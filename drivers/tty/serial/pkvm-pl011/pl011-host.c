#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include <asm/kvm_pkvm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm_module.h>

#include "hyp/pl011-hyp.h"

#ifndef MODULE
#define ksym_ref_addr_nvhe(x) \
	((typeof(kvm_nvhe_sym(x)) *)(kern_hyp_va(lm_alias(&kvm_nvhe_sym(x)))))

static int kvm_serial_register_hyp_ops(struct kvm_serial_ops *hyp_ops)
{
	struct arm_smccc_res res;

	if (!hyp_ops)
		return -ENODEV;

	res = kvm_call_hyp_nvhe_smccc(__pkvm_serial_register_ops, hyp_ops);
	return res.a1;
}
#endif

static bool pl011_dt_node_is_available(void)
{
	struct device_node *np;

	for_each_compatible_node(np, NULL, "arm,sbsa-uart") {
		struct resource res;

		if (of_address_to_resource(np, 0, &res)) {
			of_node_put(np);
			continue;
		}

		if (res.start == CONFIG_SERIAL_PKVM_PL011_BASE_PHYS) {
			bool available = of_device_is_available(np);
			of_node_put(np);
			return available;
		}
	}
	return false;
}

static int __init pl011_nvhe_init(void)
{
	int ret;

	if (!is_protected_kvm_enabled())
		return 0;

	if (!pl011_dt_node_is_available()) {
		pr_err("pkvm-pl011: UART at %#llx not enabled in device tree\n",
		       (u64)CONFIG_SERIAL_PKVM_PL011_BASE_PHYS);
		return -ENODEV;
	}

	pr_info("pkvm-pl011: Loading pl011 driver\n");

#ifdef MODULE
	ret = pkvm_load_el2_module(kvm_nvhe_sym(pl011_hyp_init_module));
#else
	ret = kvm_serial_register_hyp_ops(ksym_ref_addr_nvhe(pl011_ops));
#endif
	if (ret)
		pr_err("pkvm-pl011: Failed to load pl011 driver: %d\n", ret);

	return ret;
}

module_init(pl011_nvhe_init);

MODULE_DESCRIPTION("pKVM PL011 UART driver");
MODULE_LICENSE("GPL");
