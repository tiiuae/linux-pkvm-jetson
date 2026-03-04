/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pKVM IOMMU driver for ARM SMMUv2 (Tegra234)
 *
 * Copyright (C) 2025 Hannu Lyytinen <hannu.lyytinen@unikie.com>
 */

#ifndef __ARM_SMMU_V2_HYP_H
#define __ARM_SMMU_V2_HYP_H

#ifdef __KVM_NVHE_HYPERVISOR__
/* EL2 hypervisor includes */
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <nvhe/iommu.h>
#include <nvhe/memory.h>
#include <nvhe/spinlock.h>
#else
/* EL1 host includes */
#include <linux/types.h>
#include <asm/kvm_pkvm.h>
#endif

/* Shared EL1/EL2 data structures */
#include "arm-smmu-v2-shared.h"

/* Maximum number of SMMU instances on Tegra234 */
#define ARM_SMMU_MAX_INSTANCES		3

/* Maximum stream mapping groups */
#define ARM_SMMU_MAX_SMRS		128

/* Page shift for SMMU register pages */
#define ARM_SMMU_PGSHIFT		16

/* TLB sync timeout */
#define ARM_SMMU_POLL_TIMEOUT_US	1000000

/* Register pages */
#define ARM_SMMU_GR0			0
#define ARM_SMMU_GR1			(1 << ARM_SMMU_PGSHIFT)

/* Invalid context bank marker */
#define ARM_SMMU_INVALID_CB		0xFF

/*
 * SMMU Feature Flags
 */
#define ARM_SMMU_FEAT_TRANS_S1		BIT(0)
#define ARM_SMMU_FEAT_TRANS_S2		BIT(1)
#define ARM_SMMU_FEAT_TRANS_NESTED	BIT(2)
#define ARM_SMMU_FEAT_COHERENT_WALK	BIT(3)
#define ARM_SMMU_FEAT_VMID16		BIT(4)
#define ARM_SMMU_FEAT_STREAM_MATCH	BIT(5)

/*
 * Stream Match Register (SMR) and Stream-to-Context Register (S2CR)
 * These are shadowed by EL2 to enforce nested translation
 */
struct arm_smmu_smr {
	u16			mask;
	u16			id;
	bool			valid;
};

struct arm_smmu_s2cr {
	u8			type;
	u8			cbndx;
	u8			privcfg;
	bool			bypass;
};

/*
 * SID Assignment Tracking
 * Maps Stream IDs to domains for MC validation
 *
 * Multiple MC clients can share the same Stream ID (e.g., read/write pairs
 * like apedmar/apedmaw). We track up to MAX_CLIENTS_PER_SID clients per SID.
 */
#define MAX_CLIENTS_PER_SID	8

struct sid_assignment {
	u32			sid;		/* Stream ID (0-255) */
	u32			client_ids[MAX_CLIENTS_PER_SID];  /* MC client IDs sharing this SID */
	u8			num_clients;	/* Number of active clients (0-8) */
	pkvm_handle_t		domain_id;	/* Owning domain */
	u8			cb_idx;		/* Context bank index */
	u8			smmu_id;	/* Which SMMU instance (0-2) */
	bool			active;		/* Is this assignment active? */
};

/*
 * Note: struct hyp_arm_smmu_v2_device is now defined in arm-smmu-v2-shared.h
 * to ensure EL1/EL2 compatibility.
 */

/*
 * Tegra Memory Controller (MC) Integration
 *
 * MC structures and functions have been moved to drivers/memory/tegra/pkvm/.
 * The MC module registers with SMMU via platform hooks (smmu-platform.h).
 * See tegra234-mc.h for MC client definitions.
 */

/*
 * Global State - nVHE symbols for EL2/EL1 communication
 */

/* SMMU device array (populated by EL1, accessed by EL2) */
extern struct hyp_arm_smmu_v2_device *kvm_nvhe_sym(kvm_hyp_arm_smmu_v2_smmus);
#define kvm_hyp_arm_smmu_v2_smmus kvm_nvhe_sym(kvm_hyp_arm_smmu_v2_smmus)

extern size_t kvm_nvhe_sym(kvm_hyp_arm_smmu_v2_count);
#define kvm_hyp_arm_smmu_v2_count kvm_nvhe_sym(kvm_hyp_arm_smmu_v2_count)

/* EL2-only state */
extern struct sid_assignment sid_map[ARM_SMMU_MAX_SIDS];

/* Forward declaration of EL2 ops structure for EL1 registration */
struct kvm_iommu_ops;
extern struct kvm_iommu_ops smmu_v2_ops;

/*
 * Core Functions
 */

/* Device initialization */
int smmu_v2_init(struct hyp_arm_smmu_v2_device *smmu);
int smmu_v2_probe_device(struct hyp_arm_smmu_v2_device *smmu);
int smmu_v2_reset(struct hyp_arm_smmu_v2_device *smmu);
int smmu_v2_global_init(pkvm_handle_t drv_id);

/* MMIO emulation */
bool smmu_v2_mmio_handler(u64 addr, bool is_write, u64 *val);
int smmu_v2_handle_gr0(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		       bool is_write, u64 *val);
int smmu_v2_handle_gr1(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		       bool is_write, u64 *val);
int smmu_v2_handle_cb(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		      bool is_write, u64 *val);

/* Context bank management */
int smmu_v2_init_s2_context_bank(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx);

/* TLB operations */
void smmu_v2_tlb_inv_context(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx);
void smmu_v2_tlb_inv_range(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx,
			   unsigned long iova, size_t size, size_t granule);
int smmu_v2_tlb_sync_global(struct hyp_arm_smmu_v2_device *smmu);
int smmu_v2_tlb_sync_context(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx);

/* SID tracking */
struct sid_assignment *smmu_v2_lookup_sid(u32 sid);

/* Dual-base operations (Tegra234 niso0/niso1) */
static inline void smmu_writel(struct hyp_arm_smmu_v2_device *smmu,
			       u32 page, u32 offset, u32 val)
{
	writel_relaxed(val, smmu->base + page + offset);
	if (smmu->has_secondary_base)
		writel_relaxed(val, smmu->base_sec + page + offset);
}

static inline void smmu_writeq(struct hyp_arm_smmu_v2_device *smmu,
			       u32 page, u32 offset, u64 val)
{
	writeq_relaxed(val, smmu->base + page + offset);
	if (smmu->has_secondary_base)
		writeq_relaxed(val, smmu->base_sec + page + offset);
}

static inline u32 smmu_readl(struct hyp_arm_smmu_v2_device *smmu,
			     u32 page, u32 offset)
{
	return readl_relaxed(smmu->base + page + offset);
}

static inline u64 smmu_readq(struct hyp_arm_smmu_v2_device *smmu,
			     u32 page, u32 offset)
{
	return readq_relaxed(smmu->base + page + offset);
}
#endif /* __ARM_SMMU_V2_HYP_H */
