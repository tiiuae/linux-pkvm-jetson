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

#include <linux/bitmap.h>
#include <linux/io.h>

/* Align @cur_size to @type and add size of @num elements of @type */
#define ALIGN_ADD(cur_size, type, num)								\
	ALIGN((cur_size), __alignof__(type)) + (num) * sizeof(type)

/**
 * Align @src_ptr to type of @dst_ptr and assign the result to @dst_ptr.
 * Return the advanced @src_ptr by the alignment performed above +
 * the size of @dst_ptr assuming it has @num elements.
 */
#define ALIGN_ASSIGN_ADV(src_ptr, dst_ptr, num)							\
	({				 							\
		(dst_ptr) = (void *)ALIGN((unsigned long)(src_ptr), __alignof__(*(dst_ptr)));	\
		(void *)((u8 *)(dst_ptr) + (num) * sizeof(*(dst_ptr)));				\
	})

/**
 * Align @dst_ptr to the type of @src_ptr and copy @num elements from @src_ptr to it.
 * Return the advanced @dst_ptr by alignment and total copied size.
 */
#define ALIGN_COPY_ADV(dst_ptr, src_ptr, num)							\
	({											\
		u8 *aligned_dst = (u8 *)ALIGN((unsigned long)dst_ptr, __alignof__(*(src_ptr)));	\
		size_t array_size = (num) * sizeof(*(src_ptr));					\
		memcpy(aligned_dst, src_ptr, array_size);					\
		(void *)(aligned_dst + array_size);						\
	})

/* Maximum number of SMMU instances on Tegra234 */
#define ARM_SMMU_MAX_INSTANCES		3

/* Invalid stream matching entry */
#define ARM_SMMU_INVALID_SME		0xFF
/* Invalid context bank marker */
#define ARM_SMMU_INVALID_CB		0xFF
/* Maximum number of stream IDs */
#define ARM_SMMU_MAX_SIDS		256
/*
 * Multiple MC clients can share the same Stream ID (e.g., read/write pairs
 * like apedmar/apedmaw). We track up to MAX_CLIENTS_PER_SID clients per SID.
 */
#define MAX_CLIENTS_PER_SID		8

/* Page shift for SMMU register pages */
#define ARM_SMMU_PGSHIFT		16

/* TLB sync timeout */
#define ARM_SMMU_POLL_TIMEOUT_US	1000000

/* Register pages */
#define ARM_SMMU_GR0			0
#define ARM_SMMU_GR1			(1 << ARM_SMMU_PGSHIFT)

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
 * Context Bank State
 *
 * Tracks per-CB translation configuration. This structure is part of
 * struct hyp_arm_smmu_v2_device and must have a fixed, known size.
 */
struct smmu_v2_cb_state {
	u32			domain_id;	/* pkvm_handle_t - owning domain */
	u32			cbar;		/* Context Bank Attribute Register */
	u32			tcr[2];		/* Translation Control Register */
	u64			ttbr[2];	/* Translation Table Base Register */
	u32			sctlr;		/* System Control Register */
	u32			mair[2];	/* Memory Attribute Indirection (Stage 1-only) */
	u16			vmid;		/* Virtual Machine ID */
	bool			reserved;	/* Is this CB in use by the hypervisor */
};

/*
 * SMMU Device Structure (EL1/EL2 shared)
 *
 * This structure is allocated by EL1 and donated to EL2. Both sides
 * must use identical definitions to ensure correct memory layout.
 *
 * Layout:
 * - Hardware configuration
 * - SMMU capabilities
 * - Context bank management
 * - Shadow arrays
 * - Lock and MC pointer
 */
struct hyp_arm_smmu_v2_device {
	/*
	 * Hardware Configuration
	 * Basic MMIO and instance information
	 */
	phys_addr_t		mmio_addr;	/* Primary register base */
	void __iomem		*base;		/* Mapped primary base */
	phys_addr_t		mmio_addr_sec;	/* Secondary register base (niso0/1) */
	void __iomem		*base_sec;	/* Mapped secondary base */
	size_t			mmio_size;
	u32			id;		/* SMMU instance ID (0-2) */
	bool			has_secondary_base;

	/*
	 * SMMU Capabilities
	 * Hardware features read from ID registers
	 */
	u32			features;	/* Feature flags */
	u32			num_mapping_groups;
	u32			num_context_banks;
	u32			num_s2_context_banks;
	u32			numpage;	/* Number of GR pages (CB pages start at numpage) */
	unsigned long		pgsize_bitmap;
	u8			pgshift;	/* Page size shift */
	u8			ias;		/* Input address size (bits) */
	u8			oas;		/* Output address size (bits) */
	u16			vmid_bits;

	/*
	 * Context Bank Management
	 * Per-CB state for all 128 context banks.
	 */
	struct smmu_v2_cb_state	*cb_state;

	/* Whether a context bank is in use or not, by anyone */
	unsigned long 		*cb_bitmap;

	/*
	 * The CB index mapping array for the host. Indexed by what the host
	 * thinks is configuring, and having values the actual CB indices.
	 * Reserved/Unused entries have a value of ARM_SMMU_INVALID_CB.
	 */
	u8 			*host_cb_map;

	/*
	 * Stream Mapping Table
	 * Pointers to arrays for SMR/S2CR registers.
	 */
	struct arm_smmu_smr 	*smrs;
	struct arm_smmu_s2cr 	*s2crs;

	/* Whether a stream matching entry is in use or not, by anyone */
	unsigned long 		*sme_bitmap;

	/*
	 * The CB index mapping array for the host. Indexed by what the host
	 * thinks is configuring, and having values the actual CB indices.
	 * Reserved/Unused entries have a value of ARM_SMMU_INVALID_SME.
	 */
	u8 			*host_sme_map;

	/*
	 * Lock and MC Reference
	 * EL2-only fields, reserved by EL1
	 *
	 * Note: hyp_spinlock_t is a union type only available at EL2.
	 * At EL1, we reserve the space as u32.
	 */
#ifdef __KVM_NVHE_HYPERVISOR__
	hyp_spinlock_t		lock;		/* EL2: actual spinlock */
	u8			_pad4[4];	/* Padding to align mc pointer */
	struct hyp_tegra_mc	*mc;		/* EL2: MC controller reference */
#else
	u32			lock;		/* EL1: reserved space for hyp_spinlock_t */
	u8			_pad4[4];	/* Padding to align mc pointer */
	void			*mc;		/* EL1: reserved space for MC pointer */
#endif
};

/*
 * SID Assignment Tracking
 * Maps Stream IDs to domains for MC validation
 */
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
int smmu_v2_probe_device(struct hyp_arm_smmu_v2_device *smmu);
int smmu_v2_reset(struct hyp_arm_smmu_v2_device *smmu);
int smmu_v2_init(struct hyp_arm_smmu_v2_device *smmu);
int smmu_v2_global_init(pkvm_handle_t drv_id);

/* MMIO emulation */
bool smmu_v2_mmio_handler(u64 addr, bool is_write, u64 *val);
int smmu_v2_handle_gr0(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		       bool is_write, u64 *val);
int smmu_v2_handle_gr1(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		       bool is_write, u64 *val);
int smmu_v2_handle_cb(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		      bool is_write, u64 *val);

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

/**
 * smmu_shadow_state_size() - Calculate size of shadow state (cbs, smrs, s2crs, etc)
 *
 * Calculates the total size of the dynamically allocated fields of
 * struct hyp_arm_smmu_v2_device (cbs, smrs, s2crs, bitmaps, host maps etc)
 */
static inline size_t smmu_shadow_state_size(struct hyp_arm_smmu_v2_device *smmu)
{
	size_t state_size = 0;

	state_size = ALIGN_ADD(state_size, *(smmu->cb_state), smmu->num_context_banks);

	state_size = ALIGN(state_size, __alignof__(*(smmu->cb_bitmap)));
	state_size += bitmap_size(smmu->num_context_banks);

	state_size = ALIGN_ADD(state_size, *(smmu->host_cb_map), smmu->num_context_banks);
	state_size = ALIGN_ADD(state_size, *(smmu->smrs), smmu->num_mapping_groups);
	state_size = ALIGN_ADD(state_size, *(smmu->s2crs), smmu->num_mapping_groups);

	state_size = ALIGN(state_size, __alignof__(*(smmu->sme_bitmap)));
	state_size += bitmap_size(smmu->num_mapping_groups);

	state_size = ALIGN_ADD(state_size, *(smmu->host_sme_map), smmu->num_mapping_groups);

	return state_size;
}

/**
 * smmu_shadow_state_from_pages() - Assign SMMU shadow fields from a contiguous buffer.
 * @smmu: The smmu structure whose shadow state fields to update
 * @pages: The contiguous source buffer that smmu structure fields should point in
 *
 * Return: The advanced @pages pointer
 */
static inline void *smmu_shadow_state_from_pages(struct hyp_arm_smmu_v2_device *smmu, void *pages)
{
	pages = ALIGN_ASSIGN_ADV(pages, smmu->cb_state, smmu->num_context_banks);

	smmu->cb_bitmap = (void *)pages;
	pages += bitmap_size(smmu->num_context_banks);

	pages = ALIGN_ASSIGN_ADV(pages, smmu->host_cb_map, smmu->num_context_banks);
	pages = ALIGN_ASSIGN_ADV(pages, smmu->smrs, smmu->num_mapping_groups);
	pages = ALIGN_ASSIGN_ADV(pages, smmu->s2crs, smmu->num_mapping_groups);

	smmu->sme_bitmap = (void *)pages;
	pages += bitmap_size(smmu->num_mapping_groups);

	pages = ALIGN_ASSIGN_ADV(pages, smmu->host_sme_map, smmu->num_mapping_groups);
	return pages;
}

/**
 * smmu_shadow_state_to_pages() - Copy SMMU shadow fields to a contiguous buffer.
 * @smmu: The smmu structure to copy shadow state fields from
 * @pages: The contiguous destination buffer to copy smmu shadow state to
 *
 * Return: The advanced @pages pointer
 */
 static inline void *smmu_shadow_state_to_pages(struct hyp_arm_smmu_v2_device *smmu, void *pages)
 {
	size_t array_size;

	pages = ALIGN_COPY_ADV(pages, smmu->cb_state, smmu->num_context_banks);

	pages = (void *)ALIGN((unsigned long)pages, __alignof__(unsigned long));
	array_size = bitmap_size(smmu->num_context_banks);
	memcpy(pages, smmu->cb_bitmap, array_size);
	pages = (void *)((u8 *)pages + array_size);

	pages = ALIGN_COPY_ADV(pages, smmu->host_cb_map, smmu->num_context_banks);
	pages = ALIGN_COPY_ADV(pages, smmu->smrs, smmu->num_mapping_groups);
	pages = ALIGN_COPY_ADV(pages, smmu->s2crs, smmu->num_mapping_groups);

	pages = (void *)ALIGN((unsigned long)pages, __alignof__(unsigned long));
	array_size = bitmap_size(smmu->num_mapping_groups);
	memcpy(pages, smmu->sme_bitmap, array_size);
	pages = (void *)((u8 *)pages + array_size);

	pages = ALIGN_COPY_ADV(pages, smmu->host_sme_map, smmu->num_mapping_groups);
	return pages;
 }
#endif /* __ARM_SMMU_V2_HYP_H */
