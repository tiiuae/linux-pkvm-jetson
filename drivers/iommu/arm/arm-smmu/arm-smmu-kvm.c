// SPDX-License-Identifier: GPL-2.0-only
/*
 * pKVM host stub for ARM SMMUv2 (Tegra234)
 *
 * Copyright (C) 2025 Hannu Lyytinen <hannu.lyytinen@unikie.com>
 *
 * This is a minimal EL1 stub that registers SMMU device information with
 * the EL2 hypervisor. It does NOT register as a platform driver or IOMMU
 * driver - the standard arm-smmu.c driver handles all IOMMU operations.
 *
 * EL2 traps all SMMU MMIO accesses and adds Stage-2 identity mapping on
 * top of the Stage-1 translations managed by the standard driver.
 *
 * Architecture (following SMMUv3 pKVM pattern from linux2):
 *   - This stub: core_initcall, allocates SMMU array, registers with EL2
 *   - Standard arm-smmu.c: platform driver, IOMMU ops, Stage-1 management
 *   - EL2 pkvm/arm-smmu-v2.c: MMIO trapping, Stage-2 identity mapping
 */

#include <linux/init.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm.h>

#include "arm-smmu-kvm-debugfs.h"

/* Feature flags - must match pkvm/arm-smmu-v2.h */
#define ARM_SMMU_FEAT_COHERENT_WALK	BIT(3)

/* External EL2 symbols */
extern struct kvm_iommu_ops kvm_nvhe_sym(smmu_v2_ops);
extern struct hyp_arm_smmu_v2_device *kvm_nvhe_sym(kvm_hyp_arm_smmu_v2_smmus);
#define kvm_hyp_arm_smmu_v2_smmus kvm_nvhe_sym(kvm_hyp_arm_smmu_v2_smmus)
extern size_t kvm_nvhe_sym(kvm_hyp_arm_smmu_v2_count);
#define kvm_hyp_arm_smmu_v2_count kvm_nvhe_sym(kvm_hyp_arm_smmu_v2_count)

/* Tegra234 SMMU compatible strings */
static const char * const tegra234_smmu_compat[] = {
	"nvidia,tegra234-smmu",
	"arm,mmu-500",
	NULL
};

static size_t kvm_arm_smmu_v2_count;
static struct hyp_arm_smmu_v2_device *kvm_arm_smmu_v2_array;

#define ksym_ref_addr_nvhe(x) \
	((typeof(kvm_nvhe_sym(x)) *)(kern_hyp_va(lm_alias(&kvm_nvhe_sym(x)))))

/*
 * Calculate number of pages needed for SMMU page tables.
 * Use host stage-2 page count plus extra for context banks.
 */
static size_t smmu_v2_hyp_pgt_pages(void)
{
	return host_s2_pgtable_pages() + 500;
}

/*
 * EL2 initialization callback - called by pKVM framework
 */
static int kvm_arm_smmu_v2_init(void)
{
	int ret;
	pkvm_handle_t hyp_drv_id;

	ret = kvm_iommu_register_hyp_ops(ksym_ref_addr_nvhe(smmu_v2_ops), &hyp_drv_id);

	if (ret == 0)
		kvm_smmu_host_create_debugfs(hyp_drv_id, kvm_arm_smmu_v2_array,
					     kvm_arm_smmu_v2_count);

	return ret;
}

static struct kvm_iommu_driver kvm_smmu_v2_driver = {
	.init_driver = kvm_arm_smmu_v2_init,
};

static void kvm_arm_smmu_v2_array_free(void)
{
	int order;

	if (!kvm_arm_smmu_v2_array)
		return;

	order = get_order(kvm_arm_smmu_v2_count * sizeof(*kvm_arm_smmu_v2_array));
	free_pages((unsigned long)kvm_arm_smmu_v2_array, order);
	kvm_arm_smmu_v2_array = NULL;
}

/*
 * Parse device tree to find all SMMUv2 instances and allocate the
 * hyp_arm_smmu_v2_device array that will be passed to EL2.
 *
 * This runs at core_initcall (very early) before the standard arm-smmu.c
 * driver probes. EL2 needs this information before any SMMU operations.
 */
static int kvm_arm_smmu_v2_array_alloc(void)
{
	struct device_node *np;
	int smmu_order;
	int i = 0;
	int ret;
	const char * const *compat;

	/* Count SMMUv2 nodes */
	kvm_arm_smmu_v2_count = 0;
	for (compat = tegra234_smmu_compat; *compat; compat++) {
		for_each_compatible_node(np, NULL, *compat)
			kvm_arm_smmu_v2_count++;
	}

	if (!kvm_arm_smmu_v2_count) {
		pr_info("arm-smmu-kvm: No SMMUv2 nodes found\n");
		return -ENODEV;
	}

	pr_info("arm-smmu-kvm: Found %zu SMMUv2 instances\n", kvm_arm_smmu_v2_count);

	/* Allocate array */
	smmu_order = get_order(kvm_arm_smmu_v2_count * sizeof(*kvm_arm_smmu_v2_array));
	kvm_arm_smmu_v2_array = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, smmu_order);
	if (!kvm_arm_smmu_v2_array)
		return -ENOMEM;

	/* Parse device tree for SMMU MMIO addresses */
	for (compat = tegra234_smmu_compat; *compat; compat++) {
		for_each_compatible_node(np, NULL, *compat) {
			struct resource res;

			if (i >= kvm_arm_smmu_v2_count)
				break;

			ret = of_address_to_resource(np, 0, &res);
			if (ret) {
				pr_err("arm-smmu-kvm: Failed to get resource for %pOF\n", np);
				goto out_err;
			}

			kvm_arm_smmu_v2_array[i].id = i;
			kvm_arm_smmu_v2_array[i].mmio_addr = res.start;
			kvm_arm_smmu_v2_array[i].mmio_size = resource_size(&res);

			pr_info("arm-smmu-kvm: SMMU[%d] at 0x%llx, size 0x%lx\n",
				i, (u64)res.start, (unsigned long)resource_size(&res));

			/* Check for secondary register base (Tegra234 dual-base) */
			if (of_address_to_resource(np, 1, &res) == 0) {
				kvm_arm_smmu_v2_array[i].mmio_addr_sec = res.start;
				kvm_arm_smmu_v2_array[i].has_secondary_base = true;
				pr_info("arm-smmu-kvm: SMMU[%d] secondary at 0x%llx\n",
					i, (u64)res.start);
			}

			/* Check for coherent DMA */
			if (of_dma_is_coherent(np))
				kvm_arm_smmu_v2_array[i].features |= ARM_SMMU_FEAT_COHERENT_WALK;

			i++;
		}
	}

	return 0;

out_err:
	kvm_arm_smmu_v2_array_free();
	return ret;
}

/*
 * Register SMMUv2 driver with pKVM hypervisor.
 *
 * This is called at core_initcall, before any platform drivers probe.
 * The standard arm-smmu.c driver will still probe and handle all IOMMU
 * operations - EL2 only adds Stage-2 identity mapping via MMIO trapping.
 */
static int __init kvm_arm_smmu_v2_register(void)
{
	size_t nr_pages;
	int ret;

	if (!is_protected_kvm_enabled()) {
		pr_info("arm-smmu-kvm: pKVM not enabled, skipping\n");
		return 0;
	}

	nr_pages = smmu_v2_hyp_pgt_pages();
	if (!nr_pages)
		return 0;

	ret = kvm_arm_smmu_v2_array_alloc();
	if (ret) {
		if (ret == -ENODEV)
			return 0; /* No SMMUs, not an error */
		pr_err("arm-smmu-kvm: Failed to allocate SMMU array: %d\n", ret);
		return ret;
	}

	/*
	 * Register with EL2. This passes the kvm_iommu_driver to the framework
	 * which will call init_driver() to initialize the hypervisor driver.
	 */
	ret = kvm_iommu_register_driver(&kvm_smmu_v2_driver, nr_pages);
	if (ret) {
		pr_err("arm-smmu-kvm: Failed to register with pKVM: %d\n", ret);
		goto out_err;
	}

	/*
	 * Pass SMMU array to EL2. These variables are stored in the nVHE
	 * image and will be accessed by the hypervisor after KVM init.
	 */
	kvm_hyp_arm_smmu_v2_smmus = kvm_arm_smmu_v2_array;
	kvm_hyp_arm_smmu_v2_count = kvm_arm_smmu_v2_count;

	/*
	 * Note: MC MMIO configuration is now handled by tegra-mc-kvm.c
	 * in drivers/memory/tegra/. It runs at core_initcall level and
	 * parses the MC device tree node to set hypervisor symbols.
	 */

	pr_info("arm-smmu-kvm: Registered %zu SMMUv2 instances with pKVM\n",
		kvm_arm_smmu_v2_count);

	return 0;

out_err:
	kvm_arm_smmu_v2_array_free();
	return ret;
}

/*
 * Use core_initcall to run before any platform drivers.
 * This ensures EL2 has SMMU information before the standard arm-smmu.c
 * driver probes and starts using the hardware.
 */
core_initcall(kvm_arm_smmu_v2_register);
