#ifndef __PKVM_PL011_HYP_PL011_HYP_H_
#define __PKVM_PL011_HYP_PL011_HYP_H_

#ifdef __KVM_NVHE_HYPERVISOR__
#include <nvhe/serial.h>
#endif

#ifdef MODULE
int kvm_nvhe_sym(pl011_hyp_init_module)(const struct pkvm_module_ops *ops);
#else
extern struct kvm_serial_ops kvm_nvhe_sym(pl011_ops);
#endif

#endif /* __PKVM_PL011_HYP_PL011_HYP_H_ */