// SPDX-License-Identifier: GPL-2.0-only
/*
 * Tegra Memory Controller pKVM EL1 Stub Driver
 *
 * Copyright (C) 2025 Hannu Lyytinen <hannu.lyytinen@unikie.com>
 *
 * This minimal driver parses the Memory Controller device tree node and
 * provides MMIO address/size to the EL2 hypervisor for MC MMIO trapping.
 * The actual MC trapping and SID validation is performed by the EL2 code
 * in drivers/memory/tegra/pkvm/tegra234-mc.c.
 */

#include <linux/init.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_pkvm.h>

/*
 * EL2 hypervisor symbols for MC MMIO configuration.
 * These are defined in pkvm/tegra234-mc.c and populated here at EL1.
 */
extern phys_addr_t kvm_nvhe_sym(kvm_hyp_tegra_mc_mmio_addr);
#define kvm_hyp_tegra_mc_mmio_addr kvm_nvhe_sym(kvm_hyp_tegra_mc_mmio_addr)
extern size_t kvm_nvhe_sym(kvm_hyp_tegra_mc_mmio_size);
#define kvm_hyp_tegra_mc_mmio_size kvm_nvhe_sym(kvm_hyp_tegra_mc_mmio_size)

/**
 * tegra_mc_kvm_init - Initialize MC pKVM support
 *
 * Parses the Memory Controller device tree node and stores MMIO
 * address/size in hypervisor symbols for EL2 to use during initialization.
 *
 * This runs at core_initcall level, before device probing but after
 * early boot and memory initialization.
 */
static int __init tegra_mc_kvm_init(void)
{
	struct device_node *mc_np;
	struct resource mc_res;
	int ret;

	/* Only proceed if pKVM is enabled */
	if (!is_protected_kvm_enabled()) {
		pr_debug("tegra-mc-kvm: pKVM not enabled, skipping\n");
		return 0;
	}

	/* Find the Memory Controller device tree node */
	mc_np = of_find_compatible_node(NULL, NULL, "nvidia,tegra234-mc");
	if (!mc_np) {
		/*
		 * MC node not found - this is normal for non-Tegra234 platforms.
		 * Log at debug level to avoid noise on other platforms.
		 */
		pr_debug("tegra-mc-kvm: MC device tree node not found\n");
		return 0;
	}

	/* Extract MMIO resource from device tree */
	ret = of_address_to_resource(mc_np, 0, &mc_res);
	if (ret) {
		pr_warn("tegra-mc-kvm: Failed to get MC MMIO resource (ret=%d)\n", ret);
		of_node_put(mc_np);
		return 0;  /* Non-fatal - MC trapping will be disabled */
	}

	/* Store in hypervisor symbols for EL2 to use */
	kvm_hyp_tegra_mc_mmio_addr = mc_res.start;
	kvm_hyp_tegra_mc_mmio_size = resource_size(&mc_res);

	pr_info("tegra-mc-kvm: MC MMIO at 0x%llx, size 0x%lx\n",
		(u64)mc_res.start, (unsigned long)resource_size(&mc_res));

	of_node_put(mc_np);
	return 0;
}
core_initcall(tegra_mc_kvm_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hannu Lyytinen <hannu.lyytinen@unikie.com>");
MODULE_DESCRIPTION("Tegra Memory Controller pKVM EL1 Stub");
