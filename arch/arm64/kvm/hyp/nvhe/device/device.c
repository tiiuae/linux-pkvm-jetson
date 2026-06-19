// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */

#include <nvhe/iommu.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include <nvhe/pviommu-host.h>
#include <nvhe/serial.h>

#include <kvm/arm_hypercalls.h>
#include <kvm/device.h>

struct pkvm_device *registered_devices;
unsigned long registered_devices_nr;

/*
 * This lock protects all devices in registered_devices when ctxt changes,
 * this is overlocking and can be improved. However, the device context
 * only changes at boot time and at teardown and in theory there shouldn't
 * be congestion on that path.
 * All changes/checks to MMIO state or IOMMU must be atomic with the ctxt
 * of the device.
 */
static DEFINE_HYP_SPINLOCK(device_spinlock);

int pkvm_init_devices(unsigned long nr_devs, struct pkvm_device *devs)
{
	size_t dev_sz;
	int ret;

	registered_devices_nr = nr_devs;
	registered_devices = kern_hyp_va(devs);
	dev_sz = PAGE_ALIGN(size_mul(sizeof(struct pkvm_device), nr_devs));

	ret = __pkvm_host_donate_hyp(hyp_virt_to_phys(registered_devices) >> PAGE_SHIFT,
				     dev_sz >> PAGE_SHIFT);
	if (ret)
		registered_devices_nr = 0;

	return ret;
}

/*
 * Late, post-finalize device registration. The host calls this once after
 * PCI enumeration has settled. Wrapped in a one-shot guard so a compromised
 * host cannot re-register or overwrite the device table.
 */
#define PKVM_LATE_DEVICES_MAX	256

static bool late_devices_done;

int pkvm_devices_register_late(unsigned long nr_devs, struct pkvm_device *devs)
{
	int ret;

	if (late_devices_done)
		return -EBUSY;
	/* Defense in depth: never overwrite an already-populated table */
	if (registered_devices_nr)
		return -EBUSY;
	if (!nr_devs || nr_devs > PKVM_LATE_DEVICES_MAX)
		return -EINVAL;

	ret = pkvm_init_devices(nr_devs, devs);
	if (!ret)
		late_devices_done = true;
	return ret;
}

/* return device from a resource, addr and size must match. */
static struct pkvm_device *pkvm_get_device(u64 addr, size_t size)
{
	struct pkvm_device *dev;
	struct pkvm_dev_resource *res;
	int i, j;

	for (i = 0 ; i < registered_devices_nr ; ++i) {
		dev = &registered_devices[i];
		for (j = 0 ; j < dev->nr_resources; ++j) {
			res = &dev->resources[j];
			if ((addr == res->base) && (size == res->size))
				return dev;
		}
	}

	return NULL;
}

static struct pkvm_device *pkvm_get_device_by_addr(u64 addr)
{
	struct pkvm_device *dev;
	struct pkvm_dev_resource *res;
	int i, j;

	for (i = 0 ; i < registered_devices_nr ; ++i) {
		dev = &registered_devices[i];
		for (j = 0 ; j < dev->nr_resources; ++j) {
			res = &dev->resources[j];
			if ((addr >= res->base) && (addr < res->base + res->size))
				return dev;
		}
	}

	return NULL;
}

/*
 * Devices assigned to guest has to transition first to hypervisor,
 * this guarantees that there is a point of time that the device is
 * neither accessible from the host or the guest, so the hypervisor
 * can reset it and block it's IOOMU.
 * The host will donate the whole device first to the hypervisor
 * before the guest touches or requests any part of the device
 * and upon the first request or access the hypervisor will ensure
 * that the device is fully donated first.
 */
int pkvm_device_hyp_assign_mmio(u64 pfn, u64 nr_pages)
{
	struct pkvm_device *dev;
	int ret;
	size_t size = nr_pages << PAGE_SHIFT;
	u64 phys = pfn << PAGE_SHIFT;

	dev = pkvm_get_device(phys, size);
	if (!dev) {
		hyp_err("assign_mmio: no dev for phys=0x%llx size=0x%zx",
			(u64)phys, size);
		return -ENODEV;
	}

	hyp_spin_lock(&device_spinlock);
	/* A VM already have this device, no take backs. */
	if (dev->ctxt || dev->refcount) {
		hyp_err("assign_mmio EBUSY phys=0x%llx size=0x%zx idx=%ld ctxt=%p refcount=%u group_id=%u nr_res=%u",
			(u64)phys, size, (long)(dev - registered_devices),
			dev->ctxt, (unsigned int)dev->refcount,
			dev->group_id, dev->nr_resources);
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = ___pkvm_host_donate_hyp_prot(pfn, nr_pages, true, PAGE_HYP_DEVICE);
	/*
	 * No dcache flush here: hyp's mapping is PAGE_HYP_DEVICE (non-cacheable)
	 * and the host's BAR view is also Device via ioremap, so there are no
	 * cacheable writes to push out. dc cvac on a Device-mapped VA is
	 * constrained-unpredictable on some implementations and was observed
	 * to trap-loop in EL2 on Tegra234 for high MMIO (0x20a8000000).
	 */

out_unlock:
	hyp_spin_unlock(&device_spinlock);
	return ret;
}

/*
 * Reclaim of MMIO can happen in two cases:
 * - VM is dying, in that case MMIO would be eagerly reclaimed to the host
 *   from VM teardown context without host intervention.
 * - The VM was not launched or died before claiming the device, and it's is
 *   still considered as host device, but the MMIO was already donated to
 *   the hypervisor preparing for the VM to access it, in that case the host
 *   will use this function from an HVC to reclaim the MMIO from KVM/VFIO
 *   file release context or incase of failure at initialization.
 */
int pkvm_device_reclaim_mmio(u64 pfn, u64 nr_pages)
{
	struct pkvm_device *dev;
	int ret;
	size_t size = nr_pages << PAGE_SHIFT;
	u64 phys = pfn << PAGE_SHIFT;

	dev = pkvm_get_device(phys, size);
	if (!dev)
		return -ENODEV;

	hyp_spin_lock(&device_spinlock);
	if (dev->ctxt) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = __pkvm_hyp_donate_host(pfn, nr_pages);

out_unlock:
	hyp_spin_unlock(&device_spinlock);
	return ret;
}

static int pkvm_device_reset(struct pkvm_device *dev, bool host_to_guest)
{
	struct pkvm_dev_iommu *iommu;
	int ret;
	int i;

	hyp_assert_lock_held(&device_spinlock);

	/*
	 * TODO: IOMMU modules should register per-device reset handlers via
	 * pkvm_device_register_reset() to clear device state during assignment
	 * transitions. Until then, skip reset if no handler is registered.
	 */
	if (dev->reset_handler) {
		ret = dev->reset_handler(dev->cookie, host_to_guest);
		if (ret)
			return ret;
	}

	for (i = 0 ; i < dev->nr_iommus ; ++i) {
		iommu = &dev->iommus[i];
		ret = kvm_iommu_dev_block_dma(iommu->id, iommu->endpoint, host_to_guest);
		if (WARN_ON(ret))
			return ret;
	}
	return 0;
}

static int __pkvm_device_assign(struct pkvm_device *dev, struct pkvm_hyp_vm *vm)
{
	int i;
	struct pkvm_dev_resource *res;
	int ret;

	hyp_assert_lock_held(&device_spinlock);

	for (i = 0 ; i < dev->nr_resources; ++i) {
		res = &dev->resources[i];
		ret = hyp_check_range_owned(res->base, res->size);
		if (ret)
			return ret;
	}

	ret = pkvm_device_reset(dev, true);
	if (ret)
		return ret;

	dev->ctxt = vm;
	return 0;
}

/*
 * Atomically check that all the group is assigned to the hypervisor
 * and tag the devices in the group as owned by the VM.
 * This can't race with reclaim as it's protected by device_spinlock
 */
static int __pkvm_group_assign(u32 group_id, struct pkvm_hyp_vm *vm)
{
	int i;
	int ret = 0;

	hyp_assert_lock_held(&device_spinlock);

	for (i = 0 ; i < registered_devices_nr ; ++i) {
		struct pkvm_device *dev = &registered_devices[i];

		if (dev->group_id != group_id)
			continue;
		if (dev->ctxt || dev->refcount) {
			ret = -EPERM;
			break;
		}
		ret = __pkvm_device_assign(dev, vm);
		if (ret)
			break;
	}

	if (ret) {
		while (i--) {
			struct pkvm_device *dev = &registered_devices[i];

			if (dev->group_id == group_id)
				dev->ctxt = NULL;
		}
	}
	return ret;
}


int pkvm_host_map_guest_mmio(struct pkvm_hyp_vcpu *hyp_vcpu, u64 pfn, u64 gfn)
{
	int ret = 0;
	u64 phys = hyp_pfn_to_phys(pfn);
	struct pkvm_device *dev = pkvm_get_device_by_addr(phys);
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);

	if (!dev)
		return -ENODEV;

	hyp_spin_lock(&device_spinlock);

	if (dev->ctxt == NULL) {
		/*
		 * First time the device is assigned to a guest, make sure the whole
		 * group is assigned to the hypervisor.
		 */
		ret = __pkvm_group_assign(dev->group_id, vm);
		if (ret)
			goto out_ret;
	} else if (dev->ctxt != vm) {
		ret = -EBUSY; /* device owned by another VM */
		goto out_ret;
	}

	ret = __pkvm_install_guest_mmio(hyp_vcpu, pfn, gfn);

out_ret:
	hyp_spin_unlock(&device_spinlock);
	return ret;
}

bool pkvm_device_request_mmio(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	int i, j, ret;
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 ipa = smccc_get_arg1(vcpu);
	u64 token;
	s8 level;

	/* args 2..6 reserved for future use. */
	if (smccc_get_arg2(vcpu) || smccc_get_arg3(vcpu) || smccc_get_arg4(vcpu) ||
	    smccc_get_arg5(vcpu) || smccc_get_arg6(vcpu) || !PAGE_ALIGNED(ipa))
		goto out_inval;

	ret = pkvm_get_guest_pa_request(hyp_vcpu, ipa, PAGE_SIZE,
					&token, &level);
	if (ret == -ENOENT) {
		/* Repeat next time. */
		write_sysreg_el2(read_sysreg_el2(SYS_ELR) - 4, SYS_ELR);
		*exit_code = ARM_EXCEPTION_HYP_REQ;
		return false;
	}
	else if (ret) {
		goto out_inval;
	}

	/* It's expected the address is mapped as page for MMIO */
	WARN_ON(level != KVM_PGTABLE_LAST_LEVEL);

	hyp_spin_lock(&device_spinlock);
	for (i = 0 ; i < registered_devices_nr ; ++i) {
		struct pkvm_device *dev = &registered_devices[i];

		if (dev->ctxt != vm)
			continue;

		for (j = 0 ; j < dev->nr_resources; ++j) {
			struct pkvm_dev_resource *res = &dev->resources[j];

			if ((token >= res->base) && (token + PAGE_SIZE <= res->base + res->size)) {
				smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, token, 0, 0);
				goto out_ret;
			}
		}
	}

	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
out_ret:
	hyp_spin_unlock(&device_spinlock);
	return true;
out_inval:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}

static void pkvm_devices_reclaim_device(struct pkvm_device *dev)
{
	int i;

	for (i = 0 ; i < dev->nr_resources ; ++i) {
		struct pkvm_dev_resource *res = &dev->resources[i];

		hyp_spin_lock(&host_mmu.lock);
		WARN_ON(host_stage2_set_owner_locked(res->base, res->size, PKVM_ID_HOST));
		hyp_spin_unlock(&host_mmu.lock);
	}
}

void pkvm_devices_teardown(struct pkvm_hyp_vm *vm)
{
	int i;

	hyp_spin_lock(&device_spinlock);
	for (i = 0 ; i < registered_devices_nr ; ++i) {
		struct pkvm_device *dev = &registered_devices[i];

		if (dev->ctxt != vm)
			continue;
		WARN_ON(pkvm_device_reset(dev, false));
		dev->ctxt = NULL;
		pkvm_devices_reclaim_device(dev);
	}
	hyp_spin_unlock(&device_spinlock);
}

static struct pkvm_device *pkvm_get_device_by_iommu(u64 id, u32 endpoint_id)
{
	struct pkvm_device *dev = NULL;
	struct pkvm_dev_iommu *iommu;
	int i, j;

	for (i = 0 ; i < registered_devices_nr ; ++i) {
		dev = &registered_devices[i];
		for (j = 0 ; j < dev->nr_iommus; ++j) {
			iommu = &dev->iommus[j];
			if ((id == iommu->id) && (endpoint_id == iommu->endpoint))
				return dev;
		}
	}

	return NULL;
}

int pkvm_devices_get_context(u64 iommu_id, u32 endpoint_id, struct pkvm_hyp_vm *vm)
{
	struct pkvm_device *dev = pkvm_get_device_by_iommu(iommu_id, endpoint_id);
	int ret = 0;

	if (!dev)
		return 0;

	hyp_spin_lock(&device_spinlock);
	if (dev->ctxt == NULL && vm) {
		/*
		 * Device not yet assigned to any VM. Assign the whole group
		 * now, matching what pkvm_host_map_guest_mmio and
		 * pkvm_device_request_dma do on first access.
		 */
		ret = __pkvm_group_assign(dev->group_id, vm);
		if (!ret)
			hyp_refcount_inc(dev->refcount);
	} else if (dev->ctxt != vm) {
		ret = -EPERM;
	} else {
		hyp_refcount_inc(dev->refcount);
	}
	hyp_spin_unlock(&device_spinlock);
	return ret;
}

void pkvm_devices_put_context(u64 iommu_id, u32 endpoint_id)
{
	struct pkvm_device *dev = pkvm_get_device_by_iommu(iommu_id, endpoint_id);

	if (!dev)
		return;

	hyp_spin_lock(&device_spinlock);
	hyp_refcount_dec(dev->refcount);
	hyp_spin_unlock(&device_spinlock);
}

int pkvm_device_register_reset(u64 phys, void *cookie,
			       int (*cb)(void *cookie, bool host_to_guest))
{
	struct pkvm_device *dev;
	int ret = 0;

	dev = pkvm_get_device_by_addr(phys);
	if (!dev)
		return -ENODEV;

	hyp_spin_lock(&device_spinlock);
	if (!dev->reset_handler) {
		dev->reset_handler = cb;
		dev->cookie = cookie;
	} else {
		ret = -EBUSY;
	}
	hyp_spin_unlock(&device_spinlock);

	return ret;
}

/*
 * PCI MSI-X table entry layout (from PCI 3.0 spec).
 * Defined locally to avoid pulling in full PCI headers in EL2.
 */
#define MSIX_ENTRY_SIZE		16
#define MSIX_ENTRY_LOWER_ADDR	0x0
#define MSIX_ENTRY_UPPER_ADDR	0x4
#define MSIX_ENTRY_DATA		0x8
#define MSIX_ENTRY_VECTOR_CTRL	0xc
#define MSIX_ENTRY_CTRL_MASKBIT	0x1

/* Device MMIO accessors for EL2 (PAGE_HYP_DEVICE = Device-nGnRE) */
static inline u32 hyp_readl(void *addr)
{
	return *(volatile u32 *)addr;
}

static inline void hyp_writel(u32 val, void *addr)
{
	*(volatile u32 *)addr = val;
}

/*
 * Validate an MSI-X table access request from the host.
 * Returns the device pointer and computes the entry's virtual address.
 * Caller must hold device_spinlock.
 *
 * Security: The host provides indices (device_idx, entry_idx), never
 * physical addresses. EL2 computes the address from immutable boot-time
 * registration data. This prevents a compromised host from tricking
 * EL2 into arbitrary memory access.
 */
static struct pkvm_device *
pkvm_validate_msix_access(u32 device_idx, u32 entry_idx, void **entry_addr)
{
	struct pkvm_device *dev;
	u64 phys;

	hyp_assert_lock_held(&device_spinlock);

	if (device_idx >= registered_devices_nr)
		return NULL;

	dev = &registered_devices[device_idx];

	if (!dev->nr_msix_entries || entry_idx >= dev->nr_msix_entries)
		return NULL;

	/* Address computed from boot-time data, not host-provided */
	phys = dev->msix_table_phys + (u64)entry_idx * MSIX_ENTRY_SIZE;

	/* Defense in depth: verify the page is hyp-owned */
	if (hyp_check_range_owned(phys & PAGE_MASK, PAGE_SIZE))
		return NULL;

	*entry_addr = __hyp_va(phys);
	return dev;
}

/*
 * Read one MSI-X table entry.
 * Returns all 4 fields packed into two u64 return values.
 */
int pkvm_msix_read_entry(u32 device_idx, u32 entry_idx,
			 u64 *packed_addr, u64 *packed_data_ctrl)
{
	struct pkvm_device *dev;
	void *addr;
	u32 lo, hi, data, ctrl;
	int ret = -EINVAL;

	hyp_spin_lock(&device_spinlock);

	dev = pkvm_validate_msix_access(device_idx, entry_idx, &addr);
	if (!dev)
		goto out_unlock;

	lo   = hyp_readl(addr + MSIX_ENTRY_LOWER_ADDR);
	hi   = hyp_readl(addr + MSIX_ENTRY_UPPER_ADDR);
	data = hyp_readl(addr + MSIX_ENTRY_DATA);
	ctrl = hyp_readl(addr + MSIX_ENTRY_VECTOR_CTRL);

	*packed_addr = ((u64)hi << 32) | lo;
	*packed_data_ctrl = ((u64)ctrl << 32) | data;
	ret = 0;

out_unlock:
	hyp_spin_unlock(&device_spinlock);
	return ret;
}

/*
 * Write selected fields of one MSI-X table entry.
 * field_mask bits: 0=addr_lo, 1=addr_hi, 2=data, 3=vector_ctrl.
 */
int pkvm_msix_write_entry(u32 device_idx, u32 entry_idx,
			  u64 packed_addr, u64 packed_data_ctrl,
			  u32 field_mask)
{
	struct pkvm_device *dev;
	void *addr;
	int ret = -EINVAL;

	if (field_mask & ~0xFu)
		return -EINVAL;

	hyp_spin_lock(&device_spinlock);

	dev = pkvm_validate_msix_access(device_idx, entry_idx, &addr);
	if (!dev)
		goto out_unlock;

	if (field_mask & BIT(0))
		hyp_writel((u32)packed_addr, addr + MSIX_ENTRY_LOWER_ADDR);
	if (field_mask & BIT(1))
		hyp_writel((u32)(packed_addr >> 32), addr + MSIX_ENTRY_UPPER_ADDR);
	if (field_mask & BIT(2))
		hyp_writel((u32)packed_data_ctrl, addr + MSIX_ENTRY_DATA);
	if (field_mask & BIT(3))
		hyp_writel((u32)(packed_data_ctrl >> 32), addr + MSIX_ENTRY_VECTOR_CTRL);

	/* Flush: read back to ensure writes reach device */
	hyp_readl(addr + MSIX_ENTRY_DATA);
	ret = 0;

out_unlock:
	hyp_spin_unlock(&device_spinlock);
	return ret;
}

/*
 * Mask all MSI-X vectors for a device (bulk operation).
 * Avoids N individual HVCs for msix_mask_all().
 */
int pkvm_msix_mask_all(u32 device_idx)
{
	struct pkvm_device *dev;
	void *base;
	int i;

	hyp_spin_lock(&device_spinlock);

	if (device_idx >= registered_devices_nr)
		goto out_err;

	dev = &registered_devices[device_idx];
	if (!dev->nr_msix_entries)
		goto out_err;

	/* Verify the entire MSI-X table range is hyp-owned */
	if (hyp_check_range_owned(dev->msix_table_phys & PAGE_MASK,
			PAGE_ALIGN(dev->msix_table_size +
				   (dev->msix_table_phys & ~PAGE_MASK))))
		goto out_err;

	base = __hyp_va(dev->msix_table_phys);
	for (i = 0; i < dev->nr_msix_entries; i++)
		hyp_writel(MSIX_ENTRY_CTRL_MASKBIT,
			   base + i * MSIX_ENTRY_SIZE + MSIX_ENTRY_VECTOR_CTRL);

	hyp_spin_unlock(&device_spinlock);
	return 0;

out_err:
	hyp_spin_unlock(&device_spinlock);
	return -EINVAL;
}

bool pkvm_device_request_dma(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	int ret;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	u64 pviommu = smccc_get_arg1(vcpu);
	u64 vsid = smccc_get_arg2(vcpu);
	u64 token1, token2;
	struct pviommu_route route;
	struct pkvm_device *dev;

	if (smccc_get_arg3(vcpu) || smccc_get_arg4(vcpu) || smccc_get_arg5(vcpu) ||
	    smccc_get_arg6(vcpu))
		goto out_ret;

	ret = pkvm_pviommu_get_route(vm, pviommu, vsid, &route);
	if (ret)
		goto out_ret;
	token2 = route.sid;
	/*
	 * route.iommu is the host-hyp iommu ID that has no meaning for guest.
	 * It needs to be converted to IOMMU token as in the firmware(usually
	 * base MMIO address).
	 */
	ret = kvm_iommu_id_to_token(route.iommu, &token1);
	if (ret)
		goto out_ret;

	dev = pkvm_get_device_by_iommu(route.iommu, route.sid);
	if (!dev)
		goto out_ret;

	hyp_spin_lock(&device_spinlock);
	if (dev->ctxt == NULL) {
		/*
		 * First time device is assigned to guest, make sure it's resources
		 * have been donated.
		 */
		ret = __pkvm_group_assign(dev->group_id, vm);
	} else if (dev->ctxt != vm) {
		ret = -EPERM;
	}
	hyp_spin_unlock(&device_spinlock);
	if (ret)
		goto out_ret;

	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, token1, token2, 0);
	return true;
out_ret:
	smccc_set_retval(vcpu, SMCCC_RET_INVALID_PARAMETER, 0, 0, 0);
	return true;
}
