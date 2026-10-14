/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ARM64_KVM_NVHE_AUDIT_H__
#define __ARM64_KVM_NVHE_AUDIT_H__

#include <asm/kvm_asm.h>

#include <kvm/device.h>
#include <nvhe/pkvm.h>

int pkvm_audit_init(void);
int pkvm_register_audit_driver(struct pkvm_audit_driver *drv);
bool pkvm_audit_handle_guest_call(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code);

/* List of available audit drivers */
#ifdef CONFIG_TEGRA_BPMP_PKVM
extern struct pkvm_audit_driver kvm_nvhe_sym(bpmp_hyp);
#endif

#endif /* __ARM64_KVM_NVHE_AUDIT_H__ */
