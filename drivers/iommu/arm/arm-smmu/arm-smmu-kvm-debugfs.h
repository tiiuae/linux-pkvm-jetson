#ifndef _ARM_SMMU_KVM_DEBUGFS_H
#define _ARM_SMMU_KVM_DEBUGFS_H

#include <asm/kvm_host.h>

#include "pkvm/arm-smmu-v2-shared.h"

#ifdef CONFIG_ARM_SMMU_V2_PKVM_DEBUGFS
void kvm_smmu_host_create_debugfs(pkvm_handle_t hyp_drv_id, struct hyp_arm_smmu_v2_device *smmus,
				  size_t smmu_count);
#else
static inline void
kvm_smmu_host_create_debugfs(pkvm_handle_t hyp_drv_id, struct hyp_arm_smmu_v2_device *smmus,
			     size_t smmu_count) {}
#endif

#endif /* _ARM_SMMU_KVM_DEBUGFS_H */