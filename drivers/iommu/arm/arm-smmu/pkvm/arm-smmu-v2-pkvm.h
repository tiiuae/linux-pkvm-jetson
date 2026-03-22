/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pKVM IOMMU driver for ARM SMMUv2 (Tegra234)
 *
 * Copyright (C) 2025 Hannu Lyytinen <hannu.lyytinen@unikie.com>
 */

#ifndef __ARM_SMMU_V2_PKVM_H
#define __ARM_SMMU_V2_PKVM_H

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
#include <linux/io-pgtable.h>
#include <linux/io.h>

#include "../arm-smmu.h"

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

/* Invalid stream matching entry */
#define HYP_SMMUV2_INVALID_SME		0xFF
/* Invalid context bank marker */
#define HYP_SMMUV2_INVALID_CB		0xFF
/* Maximum number of stream IDs */
#define HYP_SMMUV2_MAX_SIDS		256
/*
 * Multiple MC clients can share the same Stream ID (e.g., read/write pairs
 * like apedmar/apedmaw). We track up to HYP_SMMUV2_MAX_CLIENTS_PER_SID.
 */
#define HYP_SMMUV2_MAX_CLIENTS_PER_SID	8

/* CB 0 is used exclusively by hyp for host stage 2 translation */
#define HYP_SMMUV2_HOST_S2_CBNDX	0
/* Statically reserved CBs for the hypervisor (so far only host stage 2) */
#define HYP_SMMUV2_NUM_RSVD_CB		1
#define smmu_num_host_cbs(smmu)		((smmu)->num_context_banks - HYP_SMMUV2_NUM_RSVD_CB)

/*
 * ARM SMMUv2 Register Definitions
 * Complete set imported from arm-smmu.h for EL2 implementation
 */

/* Missing in arm-smmu.h */
#define ARM_SMMU_sCR0_SMCFCFG		BIT(21)
#define ARM_SMMU_CBAR_S1_CBNDX		GENMASK(15, 8)
#define ARM_SMMU_VTCR_TG1_4KB           BIT(31)

/* Wrong in arm-smmu.h */
#undef ARM_SMMU_SMR_MASK
#undef ARM_SMMU_SMR_ID
#define ARM_SMMU_SMR_MASK		GENMASK(30, 16)
#define ARM_SMMU_SMR_ID			GENMASK(14, 0)

/*
 * Stream Match Register (SMR) and Stream-to-Context Register (S2CR)
 * These are shadowed by EL2 to enforce nested translation
 */
struct hyp_arm_smmu_v2_smr {
	u16			mask;
	u16			id;
	bool			valid;		/* What the host thinks */
	bool			hyp_disabled; 	/* Set as invalid by hyp on hw */
};

struct hyp_arm_smmu_v2_s2cr {
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
struct hyp_arm_smmu_v2_cb {
	u16			asid;		/* Address Space ID (S1) */
	union {
		u16		vmid;		/* Virtual Machine ID (S2) */
		u16		domain_id;	/* Hyp domain id */
	};
	u32			cbar;		/* Context Bank Attribute Register */
	u32			tcr[2];		/* Translation Control Register */
	u64			ttbr[2];	/* Translation Table Base Register */
	u32			sctlr;		/* System Control Register */
	u32			mair[2];	/* Memory Attribute Indirection (Stage 1-only) */
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
	unsigned long		pgsize_bitmap;  /* Page sizes supported */
	u8			pgshift;	/* SMMU MMIO page size shift */
	u8			ubs;		/* Upstream bus size (VA, bits) */
	u8			ias;		/* IPA address size (bits) */
	u8			oas;		/* Output address size (PA, bits) */

	/* Context bank management */

	struct hyp_arm_smmu_v2_cb *cbs;		/* Array of CBs */
	unsigned long 		*cb_bitmap;	/* CB in-use bitmap */
	u8 			*host_cb_map;	/* Host CB index to hw CB index */

	/* Stream mapping entry management (SMRs + S2CRs) */

	struct hyp_arm_smmu_v2_smr *smrs;	/* Array of SMRs */
	struct hyp_arm_smmu_v2_s2cr *s2crs;	/* Array of S2CRs */
	unsigned long 		*sme_bitmap;	/* SME (SMR, S2CR) in-use bitmap */
	u8 			*host_sme_map;	/* Host SME index to hw SME index */

	/*
	 * Lock and MC Reference
	 * EL2-only fields, reserved by EL1
	 *
	 * Note: hyp_spinlock_t is a union type only available at EL2.
	 * At EL1, we reserve the space as u32.
	 */
#ifdef __KVM_NVHE_HYPERVISOR__
	hyp_spinlock_t		lock;		/* EL2: actual spinlock */
	struct hyp_tegra_mc	*mc;		/* EL2: MC controller reference */
#else
	u32			lock;		/* EL1: reserved space for hyp_spinlock_t */
	void			*mc;		/* EL1: reserved space for MC pointer */
#endif
};

/*
 * SID Assignment Tracking
 * Maps Stream IDs to domains for MC validation
 */
struct sid_assignment {
	u32			sid;		/* Stream ID (0-255) */
	/* MC client IDs sharing this SID */
	u32			client_ids[HYP_SMMUV2_MAX_CLIENTS_PER_SID];
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
extern struct sid_assignment sid_map[HYP_SMMUV2_MAX_SIDS];

/* Forward declaration of EL2 ops structure for EL1 registration */
struct kvm_iommu_ops;
extern struct kvm_iommu_ops hyp_arm_smmu_v2_ops;

/*
 * Core Functions
 */

/* SID tracking */
struct sid_assignment *smmu_lookup_sid(u32 sid);

/* Offset within a SMMU page size */
#define smmu_page_offset(smmu, offset)	((offset) & ((1 << smmu->pgshift) - 1))

/* Dual-base operations (Tegra234 niso0/niso1) */
static inline void smmu_writel(struct hyp_arm_smmu_v2_device *smmu, u32 page,
			       u32 pgoffset, u32 val)
{
	u32 pgbase = page << smmu->pgshift;

	writel_relaxed(val, smmu->base + pgbase + pgoffset);
	if (smmu->has_secondary_base)
		writel_relaxed(val, smmu->base_sec + pgbase + pgoffset);
}

static inline void smmu_writeq(struct hyp_arm_smmu_v2_device *smmu, u32 page,
			       u32 pgoffset, u64 val)
{
	u32 pgbase = page << smmu->pgshift;

	writeq_relaxed(val, smmu->base + pgbase + pgoffset);
	if (smmu->has_secondary_base)
		writeq_relaxed(val, smmu->base_sec + pgbase + pgoffset);
}

static inline u32 smmu_readl(struct hyp_arm_smmu_v2_device *smmu, u32 page,
			     u32 pgoffset)
{
	u32 pgbase = page << smmu->pgshift;
	return readl_relaxed(smmu->base + pgbase + pgoffset);
}

static inline u64 smmu_readq(struct hyp_arm_smmu_v2_device *smmu, u32 page,
			     u32 pgoffset)
{
	u32 pgbase = page << smmu->pgshift;
	return readq_relaxed(smmu->base + pgbase + pgoffset);
}

static inline u32 smmu_lpae_tcr(const struct io_pgtable_cfg *cfg)
{
	u32 tcr = FIELD_PREP(ARM_SMMU_TCR_TG0, cfg->arm_lpae_s1_cfg.tcr.tg) |
		  FIELD_PREP(ARM_SMMU_TCR_SH0, cfg->arm_lpae_s1_cfg.tcr.sh) |
		  FIELD_PREP(ARM_SMMU_TCR_ORGN0, cfg->arm_lpae_s1_cfg.tcr.orgn) |
		  FIELD_PREP(ARM_SMMU_TCR_IRGN0, cfg->arm_lpae_s1_cfg.tcr.irgn) |
		  FIELD_PREP(ARM_SMMU_TCR_T0SZ, cfg->arm_lpae_s1_cfg.tcr.tsz);

       /*
	* When TTBR1 is selected shift the TCR fields by 16 bits and disable
	* translation in TTBR0
	*/
	if (cfg->quirks & IO_PGTABLE_QUIRK_ARM_TTBR1) {
		tcr = (tcr << 16) & ~ARM_SMMU_TCR_A1;
		tcr |= ARM_SMMU_TCR_EPD0;
	} else
		tcr |= ARM_SMMU_TCR_EPD1;

	return tcr;
}

static inline u32 smmu_lpae_tcr2(const struct io_pgtable_cfg *cfg)
{
	return FIELD_PREP(ARM_SMMU_TCR2_PASIZE, cfg->arm_lpae_s1_cfg.tcr.ips) |
	       FIELD_PREP(ARM_SMMU_TCR2_SEP, ARM_SMMU_TCR2_SEP_UPSTREAM);
}

static inline u32 smmu_lpae_vtcr(const struct io_pgtable_cfg *cfg)
{
	return ARM_SMMU_VTCR_TG1_4KB |
	       FIELD_PREP(ARM_SMMU_VTCR_PS, cfg->arm_lpae_s2_cfg.vtcr.ps) |
	       FIELD_PREP(ARM_SMMU_VTCR_TG0, cfg->arm_lpae_s2_cfg.vtcr.tg) |
	       FIELD_PREP(ARM_SMMU_VTCR_SH0, cfg->arm_lpae_s2_cfg.vtcr.sh) |
	       FIELD_PREP(ARM_SMMU_VTCR_ORGN0, cfg->arm_lpae_s2_cfg.vtcr.orgn) |
	       FIELD_PREP(ARM_SMMU_VTCR_IRGN0, cfg->arm_lpae_s2_cfg.vtcr.irgn) |
	       FIELD_PREP(ARM_SMMU_VTCR_SL0, cfg->arm_lpae_s2_cfg.vtcr.sl) |
	       FIELD_PREP(ARM_SMMU_VTCR_T0SZ, cfg->arm_lpae_s2_cfg.vtcr.tsz);
}

static inline u16 smmu_guest_domain_id_to_asid(struct hyp_arm_smmu_v2_device *smmu,
					       u16 domain_id)
{
	return (u16)smmu->num_context_banks + domain_id;
}

static inline u16 smmu_asid_to_domain_id(struct hyp_arm_smmu_v2_device *smmu, u16 asid)
{
	/* host */
	if (asid < smmu->num_context_banks)
		return 0;

	/* guest */
	return asid - (u16)smmu->num_context_banks;
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

	state_size = ALIGN_ADD(state_size, *(smmu->cbs), smmu->num_context_banks);

	state_size = ALIGN(state_size, __alignof__(*(smmu->cb_bitmap)));
	state_size += bitmap_size(smmu->num_context_banks);

	state_size = ALIGN_ADD(state_size, *(smmu->host_cb_map), smmu_num_host_cbs(smmu));
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
	pages = ALIGN_ASSIGN_ADV(pages, smmu->cbs, smmu->num_context_banks);

	smmu->cb_bitmap = (void *)pages;
	pages += bitmap_size(smmu->num_context_banks);

	pages = ALIGN_ASSIGN_ADV(pages, smmu->host_cb_map, smmu_num_host_cbs(smmu));
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

	pages = ALIGN_COPY_ADV(pages, smmu->cbs, smmu->num_context_banks);

	pages = (void *)ALIGN((unsigned long)pages, __alignof__(unsigned long));
	array_size = bitmap_size(smmu->num_context_banks);
	memcpy(pages, smmu->cb_bitmap, array_size);
	pages = (void *)((u8 *)pages + array_size);

	pages = ALIGN_COPY_ADV(pages, smmu->host_cb_map, smmu_num_host_cbs(smmu));
	pages = ALIGN_COPY_ADV(pages, smmu->smrs, smmu->num_mapping_groups);
	pages = ALIGN_COPY_ADV(pages, smmu->s2crs, smmu->num_mapping_groups);

	pages = (void *)ALIGN((unsigned long)pages, __alignof__(unsigned long));
	array_size = bitmap_size(smmu->num_mapping_groups);
	memcpy(pages, smmu->sme_bitmap, array_size);
	pages = (void *)((u8 *)pages + array_size);

	pages = ALIGN_COPY_ADV(pages, smmu->host_sme_map, smmu->num_mapping_groups);
	return pages;
 }
#endif /* __ARM_SMMU_V2_PKVM_H */
