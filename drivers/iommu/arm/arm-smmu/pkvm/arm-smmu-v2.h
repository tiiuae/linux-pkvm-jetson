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
 */
struct sid_assignment {
	u32			sid;		/* Stream ID (0-255) */
	u32			client_id;	/* TEGRA234_MEMORY_CLIENT_* */
	pkvm_handle_t		domain_id;	/* Owning domain */
	u8			cb_idx;		/* Context bank index */
	u8			smmu_id;	/* Which SMMU instance (0-2) */
	bool			active;		/* Is this assignment active? */
};

/*
 * Domain Private State
 * Per-domain state for SMMUv2 IOMMU domains
 */
struct smmu_v2_domain {
	struct hyp_arm_smmu_v2_device	*smmu;	/* SMMU instance */
	u8				cb_idx;	/* Context bank index */
	struct io_pgtable_ops		*pgtbl_ops; /* Page table operations */
};

/*
 * Note: struct hyp_arm_smmu_v2_device is now defined in arm-smmu-v2-shared.h
 * to ensure EL1/EL2 compatibility.
 */

/*
 * Tegra Memory Controller (MC) Integration
 * Used for SID override validation
 */
struct mc_client_info {
	u32			client_id;	/* TEGRA234_MEMORY_CLIENT_* */
	const char		*name;		/* Client name (for logging) */
	u16			sid_override_offset;
	u16			sid_security_offset;
};

struct hyp_tegra_mc {
	phys_addr_t		mmio_addr;
	void __iomem		*base;
	size_t			mmio_size;
	const struct mc_client_info *clients;
	u32			num_clients;
};

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
extern struct hyp_tegra_mc tegra234_mc;

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
int smmu_v2_global_init(void);

/* MMIO emulation */
bool smmu_v2_mmio_handler(u64 addr, bool is_write, u64 *val);
int smmu_v2_handle_gr0(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		       bool is_write, u64 *val);
int smmu_v2_handle_gr1(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		       bool is_write, u64 *val);
int smmu_v2_handle_cb(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		      bool is_write, u64 *val);

/* Context bank management */
u8 smmu_v2_alloc_context_bank(struct hyp_arm_smmu_v2_device *smmu);
void smmu_v2_free_context_bank(struct hyp_arm_smmu_v2_device *smmu, u8 idx);
int smmu_v2_init_context_bank(struct hyp_arm_smmu_v2_device *smmu,
			       struct kvm_hyp_iommu_domain *domain, u8 cb_idx);

/* Stream mapping */
int smmu_v2_map_stream(struct hyp_arm_smmu_v2_device *smmu, u32 sid, u8 cb_idx);
int smmu_v2_unmap_stream(struct hyp_arm_smmu_v2_device *smmu, u32 sid);

/* Domain operations */
int smmu_v2_alloc_domain(pkvm_handle_t iommu_id, struct kvm_hyp_iommu_domain *domain, int type);
void smmu_v2_free_domain(struct kvm_hyp_iommu_domain *domain);

/* Device lifecycle */
int smmu_v2_attach_dev(pkvm_handle_t iommu_id, struct kvm_hyp_iommu_domain *domain,
		       pkvm_handle_t endpoint_id, u32 pasid, u32 pasid_bits, unsigned long flags);
int smmu_v2_detach_dev(pkvm_handle_t iommu_id, struct kvm_hyp_iommu_domain *domain,
		       pkvm_handle_t endpoint_id, u32 pasid);

/* Page table operations */
int smmu_v2_map_pages(struct kvm_hyp_iommu_domain *domain, unsigned long iova,
		      phys_addr_t paddr, size_t pgsize, size_t pgcount, int prot, size_t *total_mapped);
size_t smmu_v2_unmap_pages(struct kvm_hyp_iommu_domain *domain, unsigned long iova,
			   size_t pgsize, size_t pgcount, struct iommu_iotlb_gather *gather);
phys_addr_t smmu_v2_iova_to_phys(struct kvm_hyp_iommu_domain *domain, unsigned long iova);
void smmu_v2_iotlb_sync(struct kvm_hyp_iommu_domain *domain, struct iommu_iotlb_gather *gather);

/* TLB operations */
void smmu_v2_tlb_inv_context(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx);
void smmu_v2_tlb_inv_range(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx,
			   unsigned long iova, size_t size, size_t granule);
int smmu_v2_tlb_sync_global(struct hyp_arm_smmu_v2_device *smmu);
int smmu_v2_tlb_sync_context(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx);

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

/* Read TLB sync status from all bases (OR together for niso0/niso1) */
static inline u32 smmu_tlb_sync_status(struct hyp_arm_smmu_v2_device *smmu,
					u32 page, u32 offset)
{
	u32 val = readl_relaxed(smmu->base + page + offset);
	if (smmu->has_secondary_base)
		val |= readl_relaxed(smmu->base_sec + page + offset);
	return val;
}

/* SID tracking */
int smmu_v2_assign_sid(u32 smmu_id, u32 sid, u32 client_id, pkvm_handle_t domain_id);
int smmu_v2_release_sid(u32 smmu_id, u32 sid);
struct sid_assignment *smmu_v2_lookup_sid(u32 sid);

/* MC integration */
int mc_init(phys_addr_t mmio_addr, size_t mmio_size);
bool mc_mmio_handler(u64 addr, bool is_write, u64 *val);
int mc_validate_sid_for_client(u32 client_id, u32 sid);
const struct mc_client_info *mc_offset_to_client(u32 offset);

/* Helper functions */
static inline struct hyp_arm_smmu_v2_device *smmu_v2_find_by_mmio_addr(u64 addr)
{
	int i;
	for (i = 0; i < kvm_hyp_arm_smmu_v2_count; i++) {
		struct hyp_arm_smmu_v2_device *smmu = &kvm_hyp_arm_smmu_v2_smmus[i];

		/* Check primary base */
		if (addr >= smmu->mmio_addr && addr < smmu->mmio_addr + smmu->mmio_size)
			return smmu;

		/* Check secondary base if present */
		if (smmu->has_secondary_base &&
		    addr >= smmu->mmio_addr_sec && addr < smmu->mmio_addr_sec + smmu->mmio_size)
			return smmu;
	}
	return NULL;
}

static inline u8 smmu_v2_cb_offset_to_idx(struct hyp_arm_smmu_v2_device *smmu, u32 offset)
{
	/* CB pages start after GR0 (page 0) and GR1 (page 1) */
	return (offset >> smmu->pgshift) - 2;
}

#endif /* __ARM_SMMU_V2_HYP_H */
