// SPDX-License-Identifier: GPL-2.0-only

#include <kvm/arm_hypercalls.h>
#include <kvm/device.h>

#include <hyp/adjust_pc.h>

#include <nvhe/audit.h>
#include <nvhe/mm.h>
#include <nvhe/mem_protect.h>
#include <nvhe/pkvm.h>
#include <nvhe/serial.h>

/**
 * Example device tree node for device auditing:
 *
 *	pkvm_devices_ac {
 *		compatible = "pkvm,device-auditing";
 *		bpmp {
 *			compatible = "pkvm,mediated-device";
 *			pkvm,driver = "bpmp_hyp";
 *			memory-pools = <&cpu_bpmp_tx &cpu_bpmp_rx>;
 *		};
 *	};
 */

static LIST_HEAD(all_resources);

struct pkvm_mediated_device *mediated_devices;
unsigned long mediated_devices_nr = 0;

#define PKVM_AUDIT_MAX_DRV 8

static struct pkvm_audit_driver *audit_drivers[PKVM_AUDIT_MAX_DRV];
static unsigned long audit_drivers_nr = 0;

static struct pkvm_monitored_resource *find_resource_by_addr(u64 addr)
{
	struct pkvm_monitored_resource *res;
	list_for_each_entry(res, &all_resources, node) {
		if (addr >= res->base && addr < res->base + res->size)
			return res;
	}
	return NULL;
}

static struct pkvm_audit_driver *driver_get_by_id(unsigned short id)
{
	for (int i = 0; i < audit_drivers_nr; i++) {
		if (audit_drivers[i]->id == id)
			return audit_drivers[i];
	}
	return NULL;
}

bool pkvm_audit_handle_guest_call(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	int ret;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct pkvm_audit_driver *drv;
	u64 drvid = smccc_get_arg1(vcpu);
	u64 arg1 = smccc_get_arg2(vcpu);
	u64 arg2 = smccc_get_arg3(vcpu);
	u64 arg3 = smccc_get_arg4(vcpu);

	if (drvid >= PKVM_AUDIT_MAX_DRV) {
		ret = -ENODEV;
		goto out_ret;
	}
	drv = driver_get_by_id(drvid);
	if (!drv) {
		ret = -ENODEV;
		goto out_ret;
	}

	ret = drv->handle_guest_hcall(arg1, arg2, arg3);
	if (ret)
		goto out_ret;

	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, 0, 0, 0);
	return true;
out_ret:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static int pkvm_audit_handle_host_fault(struct user_pt_regs *regs, u64 esr,
					u64 addr)
{
	struct pkvm_mediated_device *dev;
	struct pkvm_monitored_resource *res;
	int err;
	bool is_write = !!(esr & ESR_ELx_WNR);
	u16 rt = (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;

	res = find_resource_by_addr(addr);
	if (!res)
		return -ENODEV;

	dev = res->device;
	u64 offset = addr - res->base;

	struct pkvm_dev_access a = {
		.addr = addr,
		.offset = offset,
		.hyp_addr = res->el2_map + offset,
		.reg = rt,
		.regs = regs,
		.esr = esr,
		.size = 1 << ((esr & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT),
		.value = is_write ? regs->regs[rt] : 0,
		.res = res,
	};

	if (is_write) {
		err = dev->hooks->write_cb ? dev->hooks->write_cb(dev, &a) : -EPERM;
	} else {
		err = dev->hooks->read_cb ? dev->hooks->read_cb(dev, &a) : -EPERM;
		if (!err)
			regs->regs[rt] = a.value;
	}

	/* DABT is normally handled by fixing the stage2 mappings and telling the host to retry.
	 * However in this case we want to keep the stage2 as-is, so we instead make the host
	 * skip to the next instruction. */
	kvm_skip_host_instr();
	return err;
}

/*
* Manually enumerate all known hyp auditing drivers.
* Later on, this could be replaced by a macro-based driver registration system.
*/
static struct pkvm_audit_driver *known_drivers[] = {
#ifdef CONFIG_TEGRA_BPMP_PKVM
	&bpmp_hyp,
#endif
};

static int pkvm_audit_register_drivers(void)
{
	struct pkvm_audit_driver *drv;
	int i;
	size_t drv_count = sizeof(known_drivers) / sizeof(struct pkvm_audit_driver *);

	for (i = 0; i < drv_count; i++) {
		drv = known_drivers[i];
		if (audit_drivers_nr >= PKVM_AUDIT_MAX_DRV)
			return -ENOMEM;
		audit_drivers[audit_drivers_nr] = drv;
		audit_drivers_nr++;
	}
	return 0;
}

static void pkvm_audit_host_restore_pages(struct pkvm_mediated_device *dev)
{
	struct pkvm_monitored_resource *res;
	int i, err;

	for (i = 0; i < dev->nr_resources; i++) {
		res = &dev->resources[i];

		err = module_change_host_page_prot(
			__phys_to_pfn(res->base),
			PKVM_HOST_MMIO_PROT | KVM_PGTABLE_PROT_DEVICE,
			res->size >> PAGE_SHIFT, false);
		if (err) {
			hyp_err("hyp_audit: error while restoring host ranges: %d", err);
			/* keep going regardless... */
		}
	}
}

static int pkvm_audit_init_device(struct pkvm_mediated_device *dev)
{
	struct pkvm_audit_driver *drv;
	struct pkvm_monitored_resource *res;
	int err, i;
	unsigned long el2_map;

	/*
	 * Setup device memory ranges. Do this before driver probe so that el2_map is available
	 * to the driver.
	 */
	for (i = 0; i < dev->nr_resources; i++) {
		res = &dev->resources[i];
		res->device = dev;
		INIT_LIST_HEAD(&res->node);
		list_add(&res->node, &all_resources);

		err = __pkvm_create_private_mapping(res->base, res->size,
						    PAGE_HYP_DEVICE, &el2_map);
		if (err)
			return err;
		hyp_info("mapped device in EL2 at %lx", el2_map);
		res->el2_map = el2_map;

		hyp_info("Unmapping %llx (pfn = %lx) with size %llx", res->base,
			 __phys_to_pfn(res->base), res->size);

		/* Keep the pages mapped but remove all permissions for EL1.
		 * We can then register a module callback that will be called in
		 * handle_host_mem_abort as the fault will be FSC_PERM. */
		err = module_change_host_page_prot(
			__phys_to_pfn(res->base),
			KVM_PGTABLE_PROT_DEVICE | KVM_PGTABLE_PROT_UXN,
			res->size >> PAGE_SHIFT, false);
		if (err) {
			hyp_err("hyp_audit: error during range unmapping");
			return err;
		}
	}

	/* Probe the corresponding driver */
	for (i = 0; i < audit_drivers_nr; i++) {
		drv = audit_drivers[i];
		if (strcmp(drv->name, dev->drv_name) != 0)
			continue;

		err = drv->probe(dev);
		if (err)
			return err;
		dev->drv = drv;
		break;
	}
	if (!dev->drv) {
		hyp_err("Requested device auditing but no driver found with name %s",
			dev->drv_name);
		return -ENODEV;
	}

	return 0;
}

int pkvm_audit_init(void)
{
	size_t dev_sz;
	int ret, i;

	mediated_devices = kern_hyp_va(mediated_devices);

	if (!mediated_devices_nr) {
		hyp_warn("No audited devices registered");
		return 0;
	}

	dev_sz = PAGE_ALIGN(size_mul(sizeof(struct pkvm_mediated_device),
				     mediated_devices_nr));

	ret = __pkvm_host_donate_hyp(hyp_virt_to_phys(mediated_devices) >> PAGE_SHIFT,
				     dev_sz >> PAGE_SHIFT);
	if (ret)
		goto exit;

	ret = pkvm_audit_register_drivers();
	if (ret)
		goto exit;

	for (i = 0; i < mediated_devices_nr; i++) {
		ret = pkvm_audit_init_device(&mediated_devices[i]);
		if (ret)
			goto exit;
	}

	ret = module_ops.register_host_perm_fault_handler(pkvm_audit_handle_host_fault);
	if (ret)
		goto exit;

	return 0;
exit:
	for (i = 0; i < mediated_devices_nr; i++) {
		pkvm_audit_host_restore_pages(&mediated_devices[i]);
	}
	mediated_devices_nr = 0;
	INIT_LIST_HEAD(&all_resources);
	return ret;
}
