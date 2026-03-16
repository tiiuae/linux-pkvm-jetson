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
#include <linux/io-pgtable.h>
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
 * ARM SMMUv2 Register Definitions
 * Complete set imported from arm-smmu.h for EL2 implementation
 */

/* GR0 Configuration Registers */
#define ARM_SMMU_GR0_sCR0		0x0
#define ARM_SMMU_sCR0_VMID16EN		BIT(31)
#define ARM_SMMU_sCR0_SMCFCFG		BIT(21)
#define ARM_SMMU_sCR0_BSU		GENMASK(15, 14)
#define ARM_SMMU_sCR0_FB		BIT(13)
#define ARM_SMMU_sCR0_PTM		BIT(12)
#define ARM_SMMU_sCR0_VMIDPNE		BIT(11)
#define ARM_SMMU_sCR0_USFCFG		BIT(10)
#define ARM_SMMU_sCR0_GCFGFIE		BIT(5)
#define ARM_SMMU_sCR0_GCFGFRE		BIT(4)
#define ARM_SMMU_sCR0_EXIDENABLE	BIT(3)
#define ARM_SMMU_sCR0_GFIE		BIT(2)
#define ARM_SMMU_sCR0_GFRE		BIT(1)
#define ARM_SMMU_sCR0_CLIENTPD		BIT(0)

/* GR0 Identification Registers */
#define ARM_SMMU_GR0_ID0		0x20
#define ARM_SMMU_ID0_S1TS		BIT(30)
#define ARM_SMMU_ID0_S2TS		BIT(29)
#define ARM_SMMU_ID0_NTS		BIT(28)
#define ARM_SMMU_ID0_SMS		BIT(27)
#define ARM_SMMU_ID0_ATOSNS		BIT(26)
#define ARM_SMMU_ID0_PTFS_NO_AARCH32	BIT(25)
#define ARM_SMMU_ID0_PTFS_NO_AARCH32S	BIT(24)
#define ARM_SMMU_ID0_NUMIRPT		GENMASK(23, 16)
#define ARM_SMMU_ID0_CTTW		BIT(14)
#define ARM_SMMU_ID0_NUMSIDB		GENMASK(12, 9)
#define ARM_SMMU_ID0_EXIDS		BIT(8)
#define ARM_SMMU_ID0_NUMSMRG		GENMASK(7, 0)

#define ARM_SMMU_GR0_ID1		0x24
#define ARM_SMMU_ID1_PAGESIZE		BIT(31)
#define ARM_SMMU_ID1_NUMPAGENDXB	GENMASK(30, 28)
#define ARM_SMMU_ID1_NUMS2CB		GENMASK(23, 16)
#define ARM_SMMU_ID1_NUMCB		GENMASK(7, 0)

#define ARM_SMMU_GR0_ID2		0x28
#define ARM_SMMU_ID2_VMID16		BIT(15)
#define ARM_SMMU_ID2_PTFS_64K		BIT(14)
#define ARM_SMMU_ID2_PTFS_16K		BIT(13)
#define ARM_SMMU_ID2_PTFS_4K		BIT(12)
#define ARM_SMMU_ID2_UBS		GENMASK(11, 8)
#define ARM_SMMU_ID2_OAS		GENMASK(7, 4)
#define ARM_SMMU_ID2_IAS		GENMASK(3, 0)

#define ARM_SMMU_GR0_ID7		0x3c
#define ARM_SMMU_ID7_MAJOR		GENMASK(7, 4)
#define ARM_SMMU_ID7_MINOR		GENMASK(3, 0)

/* GR0 Fault Registers */
#define ARM_SMMU_GR0_sGFSR		0x48
#define ARM_SMMU_sGFSR_USF		BIT(1)

#define ARM_SMMU_GR0_sGFSYNR0		0x50
#define ARM_SMMU_GR0_sGFSYNR1		0x54
#define ARM_SMMU_GR0_sGFSYNR2		0x58

/* GR0 Global TLB Invalidation */
#define ARM_SMMU_GR0_TLBIVMID		0x64
#define ARM_SMMU_GR0_TLBIALLNSNH	0x68
#define ARM_SMMU_GR0_TLBIALLH		0x6c
#define ARM_SMMU_GR0_sTLBGSYNC		0x70

#define ARM_SMMU_GR0_sTLBGSTATUS	0x74
#define ARM_SMMU_sTLBGSTATUS_GSACTIVE	BIT(0)

/* GR0 Stream Mapping Registers */
#define ARM_SMMU_GR0_SMR(n)		(0x800 + ((n) << 2))
#define ARM_SMMU_SMR_VALID		BIT(31)
#define ARM_SMMU_SMR_MASK		GENMASK(31, 16)
#define ARM_SMMU_SMR_ID			GENMASK(15, 0)

#define ARM_SMMU_GR0_S2CR(n)		(0xc00 + ((n) << 2))
#define ARM_SMMU_S2CR_PRIVCFG		GENMASK(25, 24)
#define ARM_SMMU_S2CR_TYPE		GENMASK(17, 16)
#define ARM_SMMU_S2CR_EXIDVALID		BIT(10)
#define ARM_SMMU_S2CR_CBNDX		GENMASK(7, 0)

/* S2CR Type values */
#define S2CR_TYPE_TRANS			0
#define S2CR_TYPE_BYPASS		1
#define S2CR_TYPE_FAULT			2

/* GR1 Context Bank Attribute Registers */
#define ARM_SMMU_GR1_CBAR(n)		(0x0 + ((n) << 2))
#define ARM_SMMU_CBAR_IRPTNDX		GENMASK(31, 24)
#define ARM_SMMU_CBAR_TYPE		GENMASK(17, 16)
#define ARM_SMMU_CBAR_S1_MEMATTR	GENMASK(15, 12)
#define ARM_SMMU_CBAR_S1_MEMATTR_WB	0xf
#define ARM_SMMU_CBAR_S1_BPSHCFG	GENMASK(9, 8)
#define ARM_SMMU_CBAR_S1_BPSHCFG_NSH	3
#define ARM_SMMU_CBAR_S1_CBNDX		GENMASK(15, 8)
#define ARM_SMMU_CBAR_VMID		GENMASK(7, 0)

/* CBAR Type values */
#define CBAR_TYPE_S2_TRANS		0
#define CBAR_TYPE_S1_TRANS_S2_BYPASS	1
#define CBAR_TYPE_S1_TRANS_S2_FAULT	2
#define CBAR_TYPE_S1_TRANS_S2_TRANS	3

#define ARM_SMMU_GR1_CBFRSYNRA(n)	(0x400 + ((n) << 2))
#define ARM_SMMU_CBFRSYNRA_SID		GENMASK(15, 0)

#define ARM_SMMU_GR1_CBA2R(n)		(0x800 + ((n) << 2))
#define ARM_SMMU_CBA2R_VMID16		GENMASK(31, 16)
#define ARM_SMMU_CBA2R_VA64		BIT(0)

/* Context Bank Registers (relative to CB base) */
#define ARM_SMMU_CB_SCTLR		0x0
#define ARM_SMMU_SCTLR_S1_ASIDPNE	BIT(12)
#define ARM_SMMU_SCTLR_CFCFG		BIT(7)
#define ARM_SMMU_SCTLR_HUPCF		BIT(8)
#define ARM_SMMU_SCTLR_CFIE		BIT(6)
#define ARM_SMMU_SCTLR_CFRE		BIT(5)
#define ARM_SMMU_SCTLR_E		BIT(4)
#define ARM_SMMU_SCTLR_AFE		BIT(2)
#define ARM_SMMU_SCTLR_TRE		BIT(1)
#define ARM_SMMU_SCTLR_M		BIT(0)

#define ARM_SMMU_CB_ACTLR		0x4
#define ARM_SMMU_CB_RESUME		0x8
#define ARM_SMMU_RESUME_TERMINATE	BIT(0)

#define ARM_SMMU_CB_TCR2		0x10
#define ARM_SMMU_TCR2_SEP		GENMASK(17, 15)
#define ARM_SMMU_TCR2_SEP_UPSTREAM	0x7
#define ARM_SMMU_TCR2_AS		BIT(4)
#define ARM_SMMU_TCR2_PASIZE		GENMASK(3, 0)

#define ARM_SMMU_CB_TTBR0		0x20
#define ARM_SMMU_CB_TTBR1		0x28
#define ARM_SMMU_TTBRn_ASID		GENMASK_ULL(63, 48)

#define ARM_SMMU_CB_TCR			0x30
#define ARM_SMMU_TCR_EAE		BIT(31)
#define ARM_SMMU_TCR_EPD1		BIT(23)
#define ARM_SMMU_TCR_A1			BIT(22)
#define ARM_SMMU_TCR_TG0		GENMASK(15, 14)
#define ARM_SMMU_TCR_SH0		GENMASK(13, 12)
#define ARM_SMMU_TCR_ORGN0		GENMASK(11, 10)
#define ARM_SMMU_TCR_IRGN0		GENMASK(9, 8)
#define ARM_SMMU_TCR_EPD0		BIT(7)
#define ARM_SMMU_TCR_T0SZ		GENMASK(5, 0)

/* VTCR fields (Stage-2 translation control via TCR2 in Stage-2-only mode) */
#define ARM_SMMU_VTCR_TG1_4KB		BIT(31)
#define ARM_SMMU_VTCR_PS		GENMASK(18, 16)
#define ARM_SMMU_VTCR_TG0		ARM_SMMU_TCR_TG0
#define ARM_SMMU_VTCR_SH0		ARM_SMMU_TCR_SH0
#define ARM_SMMU_VTCR_ORGN0		ARM_SMMU_TCR_ORGN0
#define ARM_SMMU_VTCR_IRGN0		ARM_SMMU_TCR_IRGN0
#define ARM_SMMU_VTCR_SL0		GENMASK(7, 6)
#define ARM_SMMU_VTCR_T0SZ		ARM_SMMU_TCR_T0SZ

#define ARM_SMMU_CB_CONTEXTIDR		0x34
#define ARM_SMMU_CB_S1_MAIR0		0x38
#define ARM_SMMU_CB_S1_MAIR1		0x3c

#define ARM_SMMU_CB_FSR			0x58
#define ARM_SMMU_CB_FSR_MULTI		BIT(31)
#define ARM_SMMU_CB_FSR_SS		BIT(30)
#define ARM_SMMU_CB_FSR_FORMAT		GENMASK(10, 9)
#define ARM_SMMU_CB_FSR_UUT		BIT(8)
#define ARM_SMMU_CB_FSR_ASF		BIT(7)
#define ARM_SMMU_CB_FSR_TLBLKF		BIT(6)
#define ARM_SMMU_CB_FSR_TLBMCF		BIT(5)
#define ARM_SMMU_CB_FSR_EF		BIT(4)
#define ARM_SMMU_CB_FSR_PF		BIT(3)
#define ARM_SMMU_CB_FSR_AFF		BIT(2)
#define ARM_SMMU_CB_FSR_TF		BIT(1)

#define ARM_SMMU_CB_FSR_IGN		(ARM_SMMU_CB_FSR_AFF |		\
					 ARM_SMMU_CB_FSR_ASF |		\
					 ARM_SMMU_CB_FSR_TLBMCF |	\
					 ARM_SMMU_CB_FSR_TLBLKF)

#define ARM_SMMU_CB_FSR_FAULT		(ARM_SMMU_CB_FSR_MULTI |	\
					 ARM_SMMU_CB_FSR_SS |		\
					 ARM_SMMU_CB_FSR_UUT |		\
					 ARM_SMMU_CB_FSR_EF |		\
					 ARM_SMMU_CB_FSR_PF |		\
					 ARM_SMMU_CB_FSR_TF |		\
					 ARM_SMMU_CB_FSR_IGN)

#define ARM_SMMU_CB_FAR			0x60

#define ARM_SMMU_CB_FSYNR0		0x68
#define ARM_SMMU_CB_FSYNR0_PLVL		GENMASK(1, 0)
#define ARM_SMMU_CB_FSYNR0_WNR		BIT(4)
#define ARM_SMMU_CB_FSYNR0_PNU		BIT(5)
#define ARM_SMMU_CB_FSYNR0_IND		BIT(6)
#define ARM_SMMU_CB_FSYNR0_NSATTR	BIT(8)
#define ARM_SMMU_CB_FSYNR0_PTWF		BIT(10)
#define ARM_SMMU_CB_FSYNR0_AFR		BIT(11)
#define ARM_SMMU_CB_FSYNR0_S1CBNDX	GENMASK(23, 16)

/* Context Bank TLB Invalidation */
#define ARM_SMMU_CB_S1_TLBIVA		0x600
#define ARM_SMMU_CB_S1_TLBIASID		0x610
#define ARM_SMMU_CB_S1_TLBIVAL		0x620
#define ARM_SMMU_CB_S2_TLBIIPAS2	0x630
#define ARM_SMMU_CB_S2_TLBIIPAS2L	0x638
#define ARM_SMMU_CB_TLBSYNC		0x7f0
#define ARM_SMMU_CB_TLBSTATUS		0x7f4

/* Address Translation Service registers */
#define ARM_SMMU_CB_PAR			0x50
#define ARM_SMMU_CB_PAR_F		BIT(0)
#define ARM_SMMU_CB_ATS1PR		0x800
#define ARM_SMMU_CB_ATSR		0x8f0
#define ARM_SMMU_CB_ATSR_ACTIVE		BIT(0)

/* Timeouts */
#define TLB_LOOP_TIMEOUT		1000000	/* 1s */

/*
 * Stream Match Register (SMR) and Stream-to-Context Register (S2CR)
 * These are shadowed by EL2 to enforce nested translation
 */
struct smmu_v2_smr {
	u16			mask;
	u16			id;
	bool			valid;
};

struct smmu_v2_s2cr {
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
struct smmu_v2_cb {
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
	unsigned long		pgsize_bitmap;
	u8			pgshift;	/* Page size shift */
	u8			ubs;		/* Upstream bus size (VA, bits) */
	u8			ias;		/* IPA address size (bits) */
	u8			oas;		/* Output address size (PA, bits) */
	u16			sid_bits;	/* SID size (bits) */

	/*
	 * Context Bank Management
	 * Per-CB state for all 128 context banks.
	 */
	struct smmu_v2_cb	*cbs;

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
	struct smmu_v2_smr 	*smrs;
	struct smmu_v2_s2cr 	*s2crs;

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
int smmu_v2_global_init(pkvm_handle_t drv_id);

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
	pages = ALIGN_ASSIGN_ADV(pages, smmu->cbs, smmu->num_context_banks);

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

	pages = ALIGN_COPY_ADV(pages, smmu->cbs, smmu->num_context_banks);

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
