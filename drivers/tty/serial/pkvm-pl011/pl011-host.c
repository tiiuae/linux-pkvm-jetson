#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

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

static int __init pl011_nvhe_init(void)
{
	int ret;

	if (!is_protected_kvm_enabled())
		return 0;

	pr_info("Loading pl011 driver\n");

#ifdef MODULE
	ret = pkvm_load_el2_module(kvm_nvhe_sym(pl011_hyp_init_module));
#else
	ret = kvm_serial_register_hyp_ops(ksym_ref_addr_nvhe(pl011_ops));
#endif
	if (ret)
		pr_err("Failed to load pl011 driver: %d\n", ret);

	return ret;
}

module_init(pl011_nvhe_init);

MODULE_DESCRIPTION("pKVM PL011 UART driver");
MODULE_LICENSE("GPL");
