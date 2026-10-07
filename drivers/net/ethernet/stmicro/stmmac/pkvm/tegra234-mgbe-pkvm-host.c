// SPDX-License-Identifier: GPL-2.0-only
/*
 * Host loader for the pKVM Tegra234 MGBE reset EL2 module.
 * Must be loaded before pKVM deprivileges the host, i.e. through
 * kvm-arm.protected_modules=tegra234-mgbe-pkvm.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm.h>
#include <asm/kvm_pkvm_module.h>

#include "hyp/tegra234_mgbe_reset.h"

int kvm_nvhe_sym(tegra234_mgbe_hyp_init)(const struct pkvm_module_ops *ops);
extern u64 kvm_nvhe_sym(mgbe_mac_phys)[TEGRA234_MGBE_MAX];
extern u64 kvm_nvhe_sym(mgbe_xpcs_phys)[TEGRA234_MGBE_MAX];
extern u32 kvm_nvhe_sym(mgbe_nr);

static int tegra234_mgbe_pkvm_get_reg(struct device_node *np, const char *name,
				      u64 *phys)
{
	struct resource res;
	int idx;

	idx = of_property_match_string(np, "reg-names", name);
	if (idx < 0 || of_address_to_resource(np, idx, &res)) {
		pr_warn("tegra234-mgbe-pkvm: %pOF has no %s region\n", np, name);
		return -ENOENT;
	}

	if (resource_size(&res) != TEGRA234_MGBE_REG_SIZE ||
	    !PAGE_ALIGNED(res.start)) {
		pr_warn("tegra234-mgbe-pkvm: %pOF unexpected %s region %pR\n",
			np, name, &res);
		return -EINVAL;
	}

	*phys = res.start;
	return 0;
}

static int tegra234_mgbe_pkvm_find_macs(void)
{
	struct device_node *np;
	u64 mac, xpcs;
	u32 nr = 0;

	/* Provide to the hypervisor the address of the MGBE base region from the device tree */
	for_each_compatible_node(np, NULL, "nvidia,tegra234-mgbe") {
		if (!of_device_is_available(np))
			continue;

		if (nr >= TEGRA234_MGBE_MAX) {
			pr_warn("tegra234-mgbe-pkvm: too many MGBE instances\n");
			of_node_put(np);
			break;
		}

		if (tegra234_mgbe_pkvm_get_reg(np, "mac", &mac) ||
		    tegra234_mgbe_pkvm_get_reg(np, "xpcs", &xpcs))
			continue;

		kvm_nvhe_sym(mgbe_mac_phys)[nr] = mac;
		kvm_nvhe_sym(mgbe_xpcs_phys)[nr] = xpcs;
		nr++;
	}

	kvm_nvhe_sym(mgbe_nr) = nr;
	return nr;
}

static int __init tegra234_mgbe_pkvm_init(void)
{
	int ret;

	if (!is_protected_kvm_enabled())
		return 0;

	if (!tegra234_mgbe_pkvm_find_macs()) {
		pr_info("tegra234-mgbe-pkvm: no MGBE instance found\n");
		return -ENODEV;
	}

	ret = pkvm_load_el2_module(kvm_nvhe_sym(tegra234_mgbe_hyp_init));
	if (ret)
		pr_err("tegra234-mgbe-pkvm: failed to load EL2 module: %d\n",
		       ret);
	else
		pr_info("tegra234-mgbe-pkvm: registered %u MGBE reset handler(s)\n",
			kvm_nvhe_sym(mgbe_nr));

	return ret;
}
module_init(tegra234_mgbe_pkvm_init);

MODULE_DESCRIPTION("pKVM EL2 reset handler for NVIDIA Tegra234 MGBE");
MODULE_LICENSE("GPL");
