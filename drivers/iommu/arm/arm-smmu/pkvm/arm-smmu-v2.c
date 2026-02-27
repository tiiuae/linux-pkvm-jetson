// SPDX-License-Identifier: GPL-2.0-only
/*
 * pKVM IOMMU driver for ARM SMMUv2 (Tegra234)
 *
 * Copyright (C) 2025 Hannu Lyytinen <hannu.lyytinen@unikie.com>
 *
 * This driver runs at EL2 and provides IOMMU virtualization for protected
 * VMs on NVIDIA Tegra234 (Jetson AGX Orin). It manages SMMUv2 hardware,
 * enforces Stream ID assignments, and provides DMA isolation.
 */

#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/io-pgtable.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <nvhe/iommu.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/trap_handler.h>

#include "arm-smmu-v2.h"
#include "smmu-platform.h"
#include <nvhe/serial.h>
#include "../../../io-pgtable-arm.h"

/* Tegra Memory Controller integration (platform-specific) */
#ifdef CONFIG_TEGRA_MC_PKVM
#include "../../../../../drivers/memory/tegra/pkvm/tegra234-mc.h"
#endif

/*
 * Global State
 *
 * Note: MC MMIO symbols (kvm_hyp_tegra_mc_mmio_addr/size) have been moved to
 * drivers/memory/tegra/pkvm/tegra234-mc.c as part of MC/SMMU separation.
 */
struct hyp_arm_smmu_v2_device *kvm_hyp_arm_smmu_v2_smmus;
size_t kvm_hyp_arm_smmu_v2_count;
struct sid_assignment sid_map[ARM_SMMU_MAX_SIDS];

/*
 * Platform Hooks
 *
 * Platform-specific code (e.g., Tegra MC) can register hooks to handle
 * platform-specific MMIO trapping (like SID override validation).
 */
static const struct smmu_v2_platform_hooks *platform_hooks;

void smmu_v2_register_platform_hooks(const struct smmu_v2_platform_hooks *hooks)
{
	platform_hooks = hooks;
}

/*
 * Memory Donation Helpers
 */

/* Transfer ownership of memory from host to hypervisor */
static int smmu_take_pages(u64 phys, size_t size)
{
	if (!IS_ALIGNED(phys, PAGE_SIZE) || !IS_ALIGNED(size, PAGE_SIZE)) {
		hyp_err("SMMU: smmu_take_pages called with unaligned address/size: phys=%llx size=%lx",
			phys, size);
		return -EINVAL;
	}

	return __pkvm_host_donate_hyp(phys >> PAGE_SHIFT, size >> PAGE_SHIFT);
}

/*
 * Global identity-mapped page table (protected by host_mmu.lock from core code)
 * All protected domains share this single Stage-2 page table that mirrors
 * the host's CPU stage-2 mappings for DMA isolation.
 */
static struct io_pgtable *idmap_pgtable;

/*
 * ARM SMMUv2 Register Definitions
 * Complete set imported from arm-smmu.h for EL2 implementation
 */

/* GR0 Configuration Registers */
#define ARM_SMMU_GR0_sCR0		0x0
#define ARM_SMMU_sCR0_VMID16EN		BIT(31)
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
#define ARM_SMMU_VTCR_RES1		BIT(31)
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
 * Helper Functions
 */

/**
 * arm_smmu_id_size_to_bits - Convert ID register size field to actual bits
 * @size: Size field from ID register (0-7)
 *
 * Returns: Actual address size in bits
 */
static int arm_smmu_id_size_to_bits(int size)
{
	switch (size) {
	case 0:
		return 32;
	case 1:
		return 36;
	case 2:
		return 40;
	case 3:
		return 42;
	case 4:
		return 44;
	case 5:
		return 48;
	default:
		return 48;  /* Maximum supported */
	}
}

/*
 * Device Initialization
 */

/**
 * smmu_v2_probe_device - Read SMMU capabilities from hardware
 * @smmu: SMMU device to probe
 *
 * Reads IDR registers to determine capabilities (number of context banks,
 * stream mapping groups, page sizes, coherent walk support, etc.)
 *
 * Returns: 0 on success, negative error code on failure
 */
int smmu_v2_probe_device(struct hyp_arm_smmu_v2_device *smmu)
{
	u32 id0, id1, id2, id7;
	u32 size;

	/* Read capability registers */
	id0 = smmu_readl(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_ID0);
	id1 = smmu_readl(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_ID1);
	id2 = smmu_readl(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_ID2);
	id7 = smmu_readl(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_ID7);

	/* ID0: Stream mapping and translation support */
	smmu->features = 0;

	/* Check Stage-1 translation support */
	if (id0 & ARM_SMMU_ID0_S1TS)
		smmu->features |= ARM_SMMU_FEAT_TRANS_S1;

	/* Check Stage-2 translation support (required for pKVM) */
	if (id0 & ARM_SMMU_ID0_S2TS)
		smmu->features |= ARM_SMMU_FEAT_TRANS_S2;

	/* Check nested translation support */
	if (id0 & ARM_SMMU_ID0_NTS)
		smmu->features |= ARM_SMMU_FEAT_TRANS_NESTED;

	/* Check coherent table walk support */
	if (id0 & ARM_SMMU_ID0_CTTW)
		smmu->features |= ARM_SMMU_FEAT_COHERENT_WALK;

	/* Get number of stream mapping register groups */
	if (id0 & ARM_SMMU_ID0_SMS) {
		smmu->features |= ARM_SMMU_FEAT_STREAM_MATCH;
		size = FIELD_GET(ARM_SMMU_ID0_NUMSMRG, id0);
		if (size == 0) {
			/* Stream matching supported but no SMRs? Invalid! */
			return -ENODEV;
		}
		smmu->num_mapping_groups = size;
	} else {
		/* No stream matching, use direct Stream ID indexing */
		smmu->num_mapping_groups = 128;  /* Tegra234 has 128 */
	}

	/* ID1: Context banks and page size (register layout, not translation) */
	smmu->pgshift = (id1 & ARM_SMMU_ID1_PAGESIZE) ? 16 : 12;  /* 64KB or 4KB */

	/*
	 * Calculate numpage from ID1.NUMPAGENDXB.
	 * This is the number of register pages for GR0+GR1. Context banks
	 * start at page 'numpage' (not page 2 as ARM spec examples suggest).
	 * Tegra234 with 16MB MMIO and 64KB pages: numpage = 128.
	 */
	smmu->numpage = 1 << (FIELD_GET(ARM_SMMU_ID1_NUMPAGENDXB, id1) + 1);
	hyp_info("SMMU[%u]: numpage=%u (CB pages start at page %u)",
		 smmu->id, smmu->numpage, smmu->numpage);

	/*
	 * Tegra234 erratum: force 4KB translation pages due to walk cache bug.
	 * Note: This only affects the io-pgtable page size, NOT the SMMU register
	 * layout which is determined by hardware (pgshift from ID1.PAGESIZE).
	 */
	smmu->pgsize_bitmap = SZ_4K;

	/* Get number of context banks */
	smmu->num_context_banks = FIELD_GET(ARM_SMMU_ID1_NUMCB, id1);
	smmu->num_s2_context_banks = FIELD_GET(ARM_SMMU_ID1_NUMS2CB, id1);

	if (smmu->num_s2_context_banks > smmu->num_context_banks) {
		/* Impossible configuration */
		return -ENODEV;
	}

	/* ID2: Address sizes and VMID support */
	size = arm_smmu_id_size_to_bits(FIELD_GET(ARM_SMMU_ID2_IAS, id2));
	smmu->ias = size;  /* Input Address Size (IPA) */

	size = arm_smmu_id_size_to_bits(FIELD_GET(ARM_SMMU_ID2_OAS, id2));
	smmu->oas = size;  /* Output Address Size (PA) */

	/* Check for 16-bit VMID support */
	if (id2 & ARM_SMMU_ID2_VMID16) {
		smmu->features |= ARM_SMMU_FEAT_VMID16;
		smmu->vmid_bits = 16;
	} else {
		smmu->vmid_bits = 8;
	}

	/* Check page size support (used for Tegra234 quirk above) */
	if (id2 & ARM_SMMU_ID2_PTFS_4K)
		smmu->pgsize_bitmap |= SZ_4K;
	if (id2 & ARM_SMMU_ID2_PTFS_16K)
		smmu->pgsize_bitmap |= SZ_16K;
	if (id2 & ARM_SMMU_ID2_PTFS_64K)
		smmu->pgsize_bitmap |= SZ_64K;

	/* Force 4K only due to Tegra234 erratum */
	smmu->pgsize_bitmap = SZ_4K;

	/* ID7: SMMU architecture version */
	/* For Tegra234, this is SMMUv2 (ARM MMU-500) */
	/* Version info is informational only */

	return 0;
}

/**
 * smmu_v2_reset - Reset and initialize SMMU hardware
 * @smmu: SMMU device to reset
 *
 * Configures global registers and prepares hardware for operation.
 * This follows the standard ARM SMMUv2 reset sequence.
 */
int smmu_v2_reset(struct hyp_arm_smmu_v2_device *smmu)
{
	u32 scr0, reg;
	int i, ret;

	/* 1. Clear global fault status register */
	reg = smmu_readl(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sGFSR);
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sGFSR, reg);

	/*
	 * 2. Reset stream mapping groups: Initial values mark all SMRn as
	 * invalid and all S2CRn as bypass (not fault) to preserve bootloader
	 * mappings. This is critical for Tegra234 where the bootloader leaves
	 * devices like display active with ongoing DMA. Setting to FAULT mode
	 * would cause these devices to fault immediately.
	 *
	 * When devices get properly attached to domains, their S2CR entries
	 * will be updated to TRANS mode with proper context bank assignments.
	 */
	for (i = 0; i < smmu->num_mapping_groups; i++) {
		/* Clear SMR (mark as invalid) */
		smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_SMR(i), 0);

		/*
		 * Set S2CR to BYPASS type (allow unmapped streams to pass through).
		 * This matches the behavior of the standard ARM SMMU driver which
		 * preserves bootloader mappings for seamless handover (e.g., display
		 * from firmware to kernel).
		 */
		smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_S2CR(i),
			    FIELD_PREP(ARM_SMMU_S2CR_TYPE, S2CR_TYPE_BYPASS));
	}

	/* 3. Make sure all context banks are disabled and clear CB_FSR */
	for (i = 0; i < smmu->num_context_banks; i++) {
		/* Disable context bank (clear SCTLR.M) */
		smmu_writel(smmu, (i + smmu->numpage) << smmu->pgshift,
			    ARM_SMMU_CB_SCTLR, 0);

		/* Clear context bank fault status */
		smmu_writel(smmu, (i + smmu->numpage) << smmu->pgshift,
			    ARM_SMMU_CB_FSR, ARM_SMMU_CB_FSR_FAULT);
	}

	/* 4. Invalidate the TLB, just in case */
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_TLBIALLH, 0);
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_TLBIALLNSNH, 0);

	/* 5. Configure sCR0 with appropriate settings */
	scr0 = 0;

	/* Enable fault reporting */
	scr0 |= ARM_SMMU_sCR0_GFRE | ARM_SMMU_sCR0_GFIE |
		ARM_SMMU_sCR0_GCFGFRE | ARM_SMMU_sCR0_GCFGFIE;

	/* Disable TLB broadcasting, enable VMID partitioning */
	scr0 |= ARM_SMMU_sCR0_VMIDPNE | ARM_SMMU_sCR0_PTM;

	/*
	 * Handle unmatched streams: clear USFCFG to allow bypass.
	 * When USFCFG=0, undefined streams bypass the SMMU (no translation).
	 * This helps during boot when not all devices are attached to domains.
	 * Security note: attached devices still use proper translation.
	 */
	/* scr0 &= ~ARM_SMMU_sCR0_USFCFG; -- already 0, no action needed */

	/* Disable forced broadcasting */
	/* (FB bit is implicitly 0, no need to clear) */

	/* Don't upgrade barriers */
	/* (BSU bits are implicitly 0) */

	/* Enable 16-bit VMIDs if supported */
	if (smmu->features & ARM_SMMU_FEAT_VMID16)
		scr0 |= ARM_SMMU_sCR0_VMID16EN;

	/* Enable client access (clear CLIENTPD) */
	/* (CLIENTPD is bit 0, already 0 in our scr0) */

	/* 6. Perform global TLB sync before enabling */
	ret = smmu_v2_tlb_sync_global(smmu);
	if (ret)
		return ret;

	/* 7. Write final sCR0 value to enable SMMU */
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sCR0, scr0);

	return 0;
}

/*
 * TLB Operations for io-pgtable Integration
 */

/**
 * smmu_v2_tlb_flush_walk - Flush TLB after unmapping non-leaf PTEs
 * @iova: I/O virtual address
 * @size: Size of the range to invalidate
 * @granule: Page granule size
 * @cookie: SMMU device (unused - we invalidate all SMMUs)
 *
 * Called by io-pgtable when unmapping intermediate page table entries.
 */
static void smmu_v2_tlb_flush_walk(unsigned long iova, size_t size,
				   size_t granule, void *cookie)
{
	struct hyp_arm_smmu_v2_device *smmu;
	int i;

	/* Invalidate on ALL SMMU instances (global identity mapping) */
	for (i = 0; i < kvm_hyp_arm_smmu_v2_count; i++) {
		smmu = &kvm_hyp_arm_smmu_v2_smmus[i];

		/* Global TLB invalidation (all VMIDs) */
		smmu_v2_tlb_inv_context(smmu, 0);  /* CB 0 - could be any CB */
	}
}

/**
 * smmu_v2_tlb_add_page - Add page to TLB invalidation gather
 * @gather: TLB gather structure (unused for SMMUv2)
 * @iova: I/O virtual address
 * @granule: Page granule size
 * @cookie: SMMU device (unused)
 *
 * Called by io-pgtable when unmapping leaf page table entries.
 * SMMUv2 doesn't support gather/batch TLB invalidation, so we invalidate immediately.
 */
static void smmu_v2_tlb_add_page(struct iommu_iotlb_gather *gather,
				 unsigned long iova, size_t granule, void *cookie)
{
	/* For now, just do a full context invalidation */
	/* TODO: Implement range-based invalidation for better performance */
	smmu_v2_tlb_flush_walk(iova, granule, granule, cookie);
}

static const struct iommu_flush_ops smmu_v2_tlb_ops = {
	.tlb_flush_walk	= smmu_v2_tlb_flush_walk,
	.tlb_add_page	= smmu_v2_tlb_add_page,
};

/**
 * smmu_v2_init_pgt - Initialize global identity-mapped page table
 *
 * Creates a single Stage-2 page table shared by all protected domains.
 * This table mirrors the host's CPU stage-2 mappings for DMA isolation.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int smmu_v2_init_pgt(void)
{
	struct io_pgtable_cfg cfg = {
		.tlb		= &smmu_v2_tlb_ops,
		.ias		= 48,	/* Input address size */
		.oas		= 48,	/* Output address size */
		.coherent_walk	= true,
		.pgsize_bitmap	= SZ_4K,  /* Tegra234: 4K only (walk cache erratum) */
		/*
		 * IO_PGTABLE_QUIRK_IDMAP: Use atomic page allocation for idmap.
		 *   Required during early initialization before memory cache is ready.
		 * IO_PGTABLE_QUIRK_NO_WARN: Suppress warnings on conflicting mappings.
		 */
		.quirks		= IO_PGTABLE_QUIRK_NO_WARN | IO_PGTABLE_QUIRK_IDMAP,
	};
	struct hyp_arm_smmu_v2_device *smmu;
	struct io_pgtable_ops *ops;
	int i;

	/* Determine common capabilities across all SMMU instances */
	for (i = 0; i < kvm_hyp_arm_smmu_v2_count; i++) {
		smmu = &kvm_hyp_arm_smmu_v2_smmus[i];

		/* Use minimum IAS/OAS across all SMMUs */
		if (smmu->ias < cfg.ias)
			cfg.ias = smmu->ias;
		if (smmu->oas < cfg.oas)
			cfg.oas = smmu->oas;

		/* AND together page size support (most restrictive) */
		cfg.pgsize_bitmap &= smmu->pgsize_bitmap;

		/* Coherent walk only if all SMMUs support it */
		if (!(smmu->features & ARM_SMMU_FEAT_COHERENT_WALK))
			cfg.coherent_walk = false;
	}

	/* Allocate Stage-2 page table */
	hyp_info("SMMUv2: Allocating page table (ias=%u, oas=%u, pgsize=0x%lx)",
		 cfg.ias, cfg.oas, cfg.pgsize_bitmap);

	ops = kvm_alloc_io_pgtable_ops(ARM_64_LPAE_S2, &cfg, NULL);
	if (!ops) {
		hyp_err("SMMUv2: Failed to allocate page table ops");
		return -ENOMEM;
	}

	idmap_pgtable = io_pgtable_ops_to_pgtable(ops);
	if (!idmap_pgtable) {
		/* This shouldn't happen, but handle it anyway */
		return -ENOMEM;
	}

	return 0;
}

/**
 * smmu_v2_init - Initialize SMMU device at EL2
 * @smmu: SMMU device structure
 *
 * Assumes that shadow arrays have already been allocated and donated from EL1.
 * This function initializes the donated memory to a known state.
 *
 * Note: Tegra234 dual register base support (niso0/niso1 with secondary bases)
 * is handled automatically by smmu_writel/smmu_readl helper functions defined
 * in arm-smmu-v2.h. These check has_secondary_base and mirror writes to base_sec.
 */
int smmu_v2_init(struct hyp_arm_smmu_v2_device *smmu)
{
	int ret, i;
	size_t nr_pages, pg;

	/*
	 * Note: UART debugging is provided by pKVM serial framework.
	 * Ensure pkvm-pl011 module is loaded before this driver.
	 */

	hyp_info("running smmu_v2_init()");

	/*
	 * Shadow arrays are NULL initially (not allocated by EL1).
	 * We'll allocate them from hyp memory pool after probing hardware.
	 */

	/* Skip invalid SMMU instances (not populated by EL1) */
	if (!smmu->mmio_addr || !smmu->mmio_size) {
		hyp_info("SMMU[%u]: Skipping - invalid configuration (PA=0x%llx, size=0x%zx)",
			 smmu->id, smmu->mmio_addr, smmu->mmio_size);
		return -ENODEV;
	}

	/* Validate MMIO address alignment */
	if (!PAGE_ALIGNED(smmu->mmio_addr | smmu->mmio_size))
		return -EINVAL;

	/*
	 * Donate SMMU MMIO pages to hypervisor.
	 * This unmaps them from host stage-2, causing all host accesses to trap
	 * to EL2 where they are handled by smmu_v2_dabt_handler().
	 * This is the same approach used by SMMUv3 pKVM driver.
	 */
	nr_pages = smmu->mmio_size >> PAGE_SHIFT;
	for (pg = 0; pg < nr_pages; pg++) {
		u64 pfn = (smmu->mmio_addr >> PAGE_SHIFT) + pg;

		ret = ___pkvm_host_donate_hyp(pfn, 1, true);
		if (ret) {
			hyp_err("SMMU[%u]: Failed to donate MMIO page %zu at pfn 0x%llx (ret=%d)",
				smmu->id, pg, pfn, ret);
			return ret;
		}
	}

	/* Get EL2 VA from hyp linear map (pages already mapped after donation) */
	smmu->base = hyp_phys_to_virt(smmu->mmio_addr);
	hyp_info("SMMU[%u]: Donated MMIO: PA 0x%llx -> VA %p, size=0x%lx (%zu pages)",
		 smmu->id, smmu->mmio_addr, smmu->base, smmu->mmio_size, nr_pages);

	/* Donate secondary MMIO base if present (Tegra234 dual-base instances) */
	if (smmu->has_secondary_base && smmu->mmio_addr_sec) {
		nr_pages = smmu->mmio_size >> PAGE_SHIFT;
		for (pg = 0; pg < nr_pages; pg++) {
			u64 pfn = (smmu->mmio_addr_sec >> PAGE_SHIFT) + pg;

			ret = ___pkvm_host_donate_hyp(pfn, 1, true);
			if (ret) {
				hyp_err("SMMU[%u]: Failed to donate secondary MMIO page %zu at pfn 0x%llx (ret=%d)",
					smmu->id, pg, pfn, ret);
				return ret;
			}
		}

		smmu->base_sec = hyp_phys_to_virt(smmu->mmio_addr_sec);
		hyp_info("SMMU[%u]: Donated secondary MMIO: PA 0x%llx -> VA %p",
			 smmu->id, smmu->mmio_addr_sec, smmu->base_sec);
	}

	hyp_spin_lock_init(&smmu->lock);

	/* Probe hardware capabilities */
	ret = smmu_v2_probe_device(smmu);
	if (ret)
		return ret;

	/* Allocate shadow arrays from hyp memory pool (now that we know num_mapping_groups) */
	{
		size_t smr_size = smmu->num_mapping_groups * sizeof(struct arm_smmu_smr);
		size_t s2cr_size = smmu->num_mapping_groups * sizeof(struct arm_smmu_s2cr);

		smmu->smrs_shadow = kvm_iommu_donate_pages_atomic(get_order(smr_size));
		if (!smmu->smrs_shadow) {
			hyp_err("SMMU[%u]: Failed to allocate smrs_shadow (%zu bytes)",
				smmu->id, smr_size);
			return -ENOMEM;
		}

		smmu->s2crs_shadow = kvm_iommu_donate_pages_atomic(get_order(s2cr_size));
		if (!smmu->s2crs_shadow) {
			hyp_err("SMMU[%u]: Failed to allocate s2crs_shadow (%zu bytes)",
				smmu->id, s2cr_size);
			return -ENOMEM;
		}

		smmu->smrs_hw = kvm_iommu_donate_pages_atomic(get_order(smr_size));
		if (!smmu->smrs_hw) {
			hyp_err("SMMU[%u]: Failed to allocate smrs_hw (%zu bytes)",
				smmu->id, smr_size);
			return -ENOMEM;
		}

		smmu->s2crs_hw = kvm_iommu_donate_pages_atomic(get_order(s2cr_size));
		if (!smmu->s2crs_hw) {
			hyp_err("SMMU[%u]: Failed to allocate s2crs_hw (%zu bytes)",
				smmu->id, s2cr_size);
			return -ENOMEM;
		}

		hyp_info("SMMU[%u]: Allocated shadow arrays (%u entries, %zu bytes each)",
			 smmu->id, smmu->num_mapping_groups, smr_size + s2cr_size);
	}

	/* Initialize context bank bitmap (all free initially) */
	bitmap_zero(smmu->context_map, ARM_SMMU_MAX_CBS);

	/* Initialize context bank state (all inactive) */
	for (i = 0; i < ARM_SMMU_MAX_CBS; i++) {
		smmu->cb_state[i].active = false;
		smmu->cb_state[i].domain_id = 0;
	}

	/* Initialize shadow SMR arrays to invalid/fault state */
	for (i = 0; i < smmu->num_mapping_groups; i++) {
		/* Shadow state: what host thinks is programmed */
		smmu->smrs_shadow[i].valid = false;
		smmu->smrs_shadow[i].id = 0;
		smmu->smrs_shadow[i].mask = 0;

		/*
		 * S2CR shadow: bypass mode by default to preserve bootloader mappings.
		 * This allows devices initialized by firmware (display, etc.) to
		 * continue working until they get properly attached to domains.
		 */
		smmu->s2crs_shadow[i].type = S2CR_TYPE_BYPASS;
		smmu->s2crs_shadow[i].cbndx = 0;
		smmu->s2crs_shadow[i].privcfg = 0;
		smmu->s2crs_shadow[i].bypass = true;

		/* Hardware state: initially same as shadow */
		smmu->smrs_hw[i] = smmu->smrs_shadow[i];
		smmu->s2crs_hw[i] = smmu->s2crs_shadow[i];
	}

	/* Reset and configure hardware */
	ret = smmu_v2_reset(smmu);
	if (ret)
		return ret;

	return 0;
}

/*
 * MMIO Emulation
 */

/**
 * smmu_v2_handle_gr0 - Handle GR0 register access
 * @smmu: SMMU device
 * @offset: Register offset within GR0 page
 * @is_write: true for write access, false for read
 * @val: Pointer to value (read or write)
 *
 * Emulates GR0 (Global Register page 0) accesses with shadow state management.
 * Key register types:
 * - ID registers (IDR0-IDR7): Read-only capability reporting
 * - sCR0: Global control (enable/disable, fault reporting)
 * - SMR: Stream match configuration (shadowed)
 * - S2CR: Stream-to-context mapping (shadowed, enforces Stage-2)
 * - TLB operations: Wire to existing TLB implementations
 */
int smmu_v2_handle_gr0(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		       bool is_write, u64 *val)
{
	u32 val32;
	int ret = 0;

	/* ID registers - read-only capability reporting */
	if (offset >= ARM_SMMU_GR0_ID0 && offset <= ARM_SMMU_GR0_ID7) {
		if (is_write)
			return -EINVAL;  /* Read-only */

		/* Pass through hardware capabilities */
		*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
		return 0;
	}

	/* sCR0 - Global control register */
	if (offset == ARM_SMMU_GR0_sCR0) {
		if (is_write) {
			val32 = (u32)*val;

			/*
			 * Enforce USFCFG=1: unmapped streams must fault, not bypass.
			 * This is a security requirement - we cannot let the host
			 * allow arbitrary streams to bypass SMMU translation.
			 */
			val32 |= ARM_SMMU_sCR0_USFCFG;

			/* Always keep fault reporting enabled */
			val32 |= (ARM_SMMU_sCR0_GFRE | ARM_SMMU_sCR0_GFIE |
				  ARM_SMMU_sCR0_GCFGFRE | ARM_SMMU_sCR0_GCFGFIE);

			/* Always keep VMID partitioning enabled for nesting */
			if (smmu->features & ARM_SMMU_FEAT_TRANS_NESTED)
				val32 |= ARM_SMMU_sCR0_VMIDPNE;

			hyp_info("sCR0 write: 0x%x (USFCFG enforced)\n", val32);

			smmu_writel(smmu, ARM_SMMU_GR0, offset, val32);
			return 0;
		} else {
			*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
			return 0;
		}
	}

	/* Global fault status/syndrome registers - read/clear */
	if (offset == ARM_SMMU_GR0_sGFSR) {
		if (is_write) {
			/* Write-1-to-clear */
			smmu_writel(smmu, ARM_SMMU_GR0, offset, (u32)*val);
			return 0;
		} else {
			*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
			return 0;
		}
	}

	if (offset == ARM_SMMU_GR0_sGFSYNR0 || offset == ARM_SMMU_GR0_sGFSYNR1 ||
	    offset == ARM_SMMU_GR0_sGFSYNR2) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
		return 0;
	}

	/* TLB invalidation registers - write-only trigger registers */
	if (offset == ARM_SMMU_GR0_TLBIVMID) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		/* TLBIVMID: Invalidate all TLB entries for this VMID */
		smmu_writel(smmu, ARM_SMMU_GR0, offset, (u32)*val);
		ret = smmu_v2_tlb_sync_global(smmu);
		return ret;
	}

	if (offset == ARM_SMMU_GR0_TLBIALLNSNH || offset == ARM_SMMU_GR0_TLBIALLH) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		/* Global TLB invalidation */
		smmu_writel(smmu, ARM_SMMU_GR0, offset, 0);
		ret = smmu_v2_tlb_sync_global(smmu);
		return ret;
	}

	if (offset == ARM_SMMU_GR0_sTLBGSYNC) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		/* Host requested TLB sync, execute it */
		ret = smmu_v2_tlb_sync_global(smmu);
		return ret;
	}

	if (offset == ARM_SMMU_GR0_sTLBGSTATUS) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = smmu_tlb_sync_status(smmu, ARM_SMMU_GR0, offset);
		return 0;
	}

	/* SMR registers - stream match configuration (shadow state) */
	if (offset >= ARM_SMMU_GR0_SMR(0) &&
	    offset < ARM_SMMU_GR0_SMR(0) + (smmu->num_mapping_groups * 4)) {
		u32 idx = (offset - ARM_SMMU_GR0_SMR(0)) >> 2;

		if (idx >= smmu->num_mapping_groups)
			return -EINVAL;

		if (is_write) {
			val32 = (u32)*val;

			/* Update shadow state (what host thinks it programmed) */
			smmu->smrs_shadow[idx].valid = !!(val32 & ARM_SMMU_SMR_VALID);
			smmu->smrs_shadow[idx].mask = FIELD_GET(ARM_SMMU_SMR_MASK, val32);
			smmu->smrs_shadow[idx].id = FIELD_GET(ARM_SMMU_SMR_ID, val32);

			/* Write through to hardware (no modification needed for SMR) */
			smmu_writel(smmu, ARM_SMMU_GR0, offset, val32);

			/* Update hardware state tracking */
			smmu->smrs_hw[idx] = smmu->smrs_shadow[idx];
			return 0;
		} else {
			/* Return shadow state (what host thinks hardware has) */
			val32 = 0;
			if (smmu->smrs_shadow[idx].valid)
				val32 |= ARM_SMMU_SMR_VALID;
			val32 |= FIELD_PREP(ARM_SMMU_SMR_MASK, smmu->smrs_shadow[idx].mask);
			val32 |= FIELD_PREP(ARM_SMMU_SMR_ID, smmu->smrs_shadow[idx].id);
			*val = val32;
			return 0;
		}
	}

	/* S2CR registers - stream-to-context mapping (shadow + enforce Stage-2) */
	if (offset >= ARM_SMMU_GR0_S2CR(0) &&
	    offset < ARM_SMMU_GR0_S2CR(0) + (smmu->num_mapping_groups * 4)) {
		u32 idx = (offset - ARM_SMMU_GR0_S2CR(0)) >> 2;
		u8 cb_idx;
		u8 requested_type;

		if (idx >= smmu->num_mapping_groups)
			return -EINVAL;

		if (is_write) {
			val32 = (u32)*val;
			requested_type = FIELD_GET(ARM_SMMU_S2CR_TYPE, val32);

			/*
			 * Preserve BYPASS mode for unmanaged streams.
			 *
			 * When host sets TYPE=FAULT but SMR is invalid, this is the
			 * EL1 driver's reset sequence trying to set a "safe" default.
			 * However, firmware-configured devices (like GPU) use SIDs
			 * that aren't registered in the IOMMU framework, so they'd
			 * hit FAULT mode and fail.
			 *
			 * Only allow FAULT mode for explicitly managed streams
			 * (where SMR[idx].valid == true).
			 */
#if 0
			if (requested_type == S2CR_TYPE_FAULT && !smmu->smrs_shadow[idx].valid) {
				/* Keep BYPASS mode, ignore host's FAULT request */
				hyp_info("S2CR[%u]: Rejecting FAULT for unmanaged stream\n", idx);
				return 0;  /* Pretend write succeeded */
			}
#endif

			/* Update shadow state */
			smmu->s2crs_shadow[idx].type = requested_type;
			smmu->s2crs_shadow[idx].cbndx = FIELD_GET(ARM_SMMU_S2CR_CBNDX, val32);
			smmu->s2crs_shadow[idx].privcfg = FIELD_GET(ARM_SMMU_S2CR_PRIVCFG, val32);

			cb_idx = smmu->s2crs_shadow[idx].cbndx;

			/* Write through to hardware */
			smmu_writel(smmu, ARM_SMMU_GR0, offset, val32);

			/* Update hardware state tracking */
			smmu->s2crs_hw[idx] = smmu->s2crs_shadow[idx];
			return 0;
		} else {
			/* Return shadow state */
			val32 = 0;
			val32 |= FIELD_PREP(ARM_SMMU_S2CR_TYPE, smmu->s2crs_shadow[idx].type);
			val32 |= FIELD_PREP(ARM_SMMU_S2CR_CBNDX, smmu->s2crs_shadow[idx].cbndx);
			val32 |= FIELD_PREP(ARM_SMMU_S2CR_PRIVCFG, smmu->s2crs_shadow[idx].privcfg);
			*val = val32;
			return 0;
		}
	}

	/* Unknown or unsupported register */
	return -EINVAL;
}

/**
 * smmu_v2_handle_gr1 - Handle GR1 register access
 * @smmu: SMMU device
 * @offset: Register offset within GR1 page
 * @is_write: true for write access, false for read
 * @val: Pointer to value (read or write)
 *
 * Emulates GR1 (Global Register page 1) accesses for context bank attributes.
 * Key register types:
 * - CBAR: Context Bank Attribute Register (translation mode, VMID)
 * - CBA2R: Extended attributes (VMID16, 64-bit VA)
 * - CBFRSYNRA: Fault syndrome auxiliary (read-only)
 *
 * Note: CBAR.TYPE is the authority for translation mode in Stage-2-only.
 * Protected domains always use CBAR_TYPE_S2_TRANS for Stage-2 translation.
 */
int smmu_v2_handle_gr1(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		       bool is_write, u64 *val)
{
	u32 val32;
	u8 cb_idx;

	/* CBAR registers - context bank attributes */
	if (offset >= ARM_SMMU_GR1_CBAR(0) &&
	    offset < ARM_SMMU_GR1_CBAR(0) + (smmu->num_context_banks * 4)) {
		cb_idx = (offset - ARM_SMMU_GR1_CBAR(0)) >> 2;

		if (cb_idx >= smmu->num_context_banks)
			return -EINVAL;

		if (is_write) {
			val32 = (u32)*val;

			/*
			 * For protected domains (active CBs with domain_id set),
			 * enforce Stage-2 translation mode via CBAR.TYPE.
			 *
			 * If this CB is active and belongs to a protected domain,
			 * override CBAR.TYPE to CBAR_TYPE_S2_TRANS.
			 */
			if (smmu->cb_state[cb_idx].active &&
			    smmu->cb_state[cb_idx].domain_id != 0) {
				u32 __maybe_unused cbar_type = FIELD_GET(ARM_SMMU_CBAR_TYPE, val32);

				/*
				 * Force Stage-2-only translation for protected domains.
				 * This is the primary enforcement point for DMA isolation.
				 */
				val32 &= ~ARM_SMMU_CBAR_TYPE;
				val32 |= FIELD_PREP(ARM_SMMU_CBAR_TYPE, CBAR_TYPE_S2_TRANS);

				hyp_dbg("SMMU[%u]: CB%u forced Stage-2 (host requested type=%u)\n",
					smmu->id, cb_idx, cbar_type);
			}

			/* Store in CB state for tracking */
			smmu->cb_state[cb_idx].cbar = val32;

			/* Write to hardware */
			smmu_writel(smmu, ARM_SMMU_GR1, offset, val32);
			return 0;
		} else {
			/* Return current CB state */
			*val = smmu->cb_state[cb_idx].cbar;
			return 0;
		}
	}

	/* CBA2R registers - extended attributes */
	if (offset >= ARM_SMMU_GR1_CBA2R(0) &&
	    offset < ARM_SMMU_GR1_CBA2R(0) + (smmu->num_context_banks * 4)) {
		cb_idx = (offset - ARM_SMMU_GR1_CBA2R(0)) >> 2;

		if (cb_idx >= smmu->num_context_banks)
			return -EINVAL;

		if (is_write) {
			val32 = (u32)*val;

			/* Allow all CBA2R fields (VA64, VMID16) */
			smmu_writel(smmu, ARM_SMMU_GR1, offset, val32);

			/* Track VMID for this CB (needed for TLB ops) */
			if (smmu->features & ARM_SMMU_FEAT_VMID16) {
				u16 vmid = FIELD_GET(ARM_SMMU_CBA2R_VMID16, val32);
				smmu->cb_state[cb_idx].vmid = vmid;
			}
			return 0;
		} else {
			*val = smmu_readl(smmu, ARM_SMMU_GR1, offset);
			return 0;
		}
	}

	/* CBFRSYNRA registers - fault syndrome auxiliary (read-only) */
	if (offset >= ARM_SMMU_GR1_CBFRSYNRA(0) &&
	    offset < ARM_SMMU_GR1_CBFRSYNRA(0) + (smmu->num_context_banks * 4)) {
		cb_idx = (offset - ARM_SMMU_GR1_CBFRSYNRA(0)) >> 2;

		if (cb_idx >= smmu->num_context_banks)
			return -EINVAL;

		if (is_write)
			return -EINVAL;  /* Read-only */

		*val = smmu_readl(smmu, ARM_SMMU_GR1, offset);
		return 0;
	}

	/* Unknown or unsupported register */
	return -EINVAL;
}

/**
 * smmu_v2_handle_cb - Handle context bank register access
 * @smmu: SMMU device
 * @offset: Register offset (CB page + offset within CB)
 * @is_write: true for write access, false for read
 * @val: Pointer to value (read or write)
 *
 * Emulates context bank register accesses for translation control.
 * Key register types:
 * - SCTLR: System control (MMU enable, fault handling)
 * - TTBR0/TTBR1: Translation table base registers
 * - TCR/TCR2: Translation control registers
 * - MAIR: Memory attribute indirection registers
 * - FSR/FAR/FSYNR0: Fault status and address registers
 * - TLBSYNC/TLBSTATUS: Per-CB TLB synchronization
 *
 * Note: For Stage-2-only protected domains, TTBR0 points to EL2's Stage-2
 * page table. Host writes are shadowed but the actual hardware uses EL2's PT.
 */
int smmu_v2_handle_cb(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		      bool is_write, u64 *val)
{
	u32 page_offset, cb_offset;
	u8 cb_idx;
	void __iomem *cb_base;
	u32 val32;
	u64 val64;

	/* Calculate which CB this is */
	page_offset = offset >> smmu->pgshift;
	if (page_offset < smmu->numpage)
		return -EINVAL;  /* Pages 0 to numpage-1 are GR0/GR1 */

	cb_idx = page_offset - smmu->numpage;
	if (cb_idx >= smmu->num_context_banks)
		return -EINVAL;

	cb_offset = offset & ((1 << smmu->pgshift) - 1);
	cb_base = smmu->base + (page_offset << smmu->pgshift);

	/* SCTLR - System Control Register */
	if (cb_offset == ARM_SMMU_CB_SCTLR) {
		if (is_write) {
			val32 = (u32)*val;

			/* Store in shadow state */
			smmu->cb_state[cb_idx].sctlr = val32;

			/* Write to hardware */
			writel_relaxed(val32, cb_base + cb_offset);
			if (smmu->has_secondary_base) {
				void __iomem *cb_base_sec = smmu->base_sec +
					(page_offset << smmu->pgshift);
				writel_relaxed(val32, cb_base_sec + cb_offset);
			}
			return 0;
		} else {
			*val = smmu->cb_state[cb_idx].sctlr;
			return 0;
		}
	}

	/* TCR2 - Translation Control Register 2 (VTCR for Stage-2) */
	if (cb_offset == ARM_SMMU_CB_TCR2) {
		if (is_write) {
			val32 = (u32)*val;

			/* Store in shadow state */
			smmu->cb_state[cb_idx].vtcr = val32;

			/* Write to hardware */
			writel_relaxed(val32, cb_base + cb_offset);
			if (smmu->has_secondary_base) {
				void __iomem *cb_base_sec = smmu->base_sec +
					(page_offset << smmu->pgshift);
				writel_relaxed(val32, cb_base_sec + cb_offset);
			}
			return 0;
		} else {
			*val = smmu->cb_state[cb_idx].vtcr;
			return 0;
		}
	}

	/* TCR - Translation Control Register (Stage-1) */
	if (cb_offset == ARM_SMMU_CB_TCR) {
		if (is_write) {
			val32 = (u32)*val;

			/* Store in shadow state */
			smmu->cb_state[cb_idx].tcr = val32;

			/*
			 * For Stage-2-only protected domains, TCR is not used
			 * by hardware (VTCR/TCR2 controls translation).
			 * Write through for completeness but it has no effect.
			 */
			writel_relaxed(val32, cb_base + cb_offset);
			if (smmu->has_secondary_base) {
				void __iomem *cb_base_sec = smmu->base_sec +
					(page_offset << smmu->pgshift);
				writel_relaxed(val32, cb_base_sec + cb_offset);
			}
			return 0;
		} else {
			*val = smmu->cb_state[cb_idx].tcr;
			return 0;
		}
	}

	/* TTBR0 - Translation Table Base Register 0 */
	if (cb_offset == ARM_SMMU_CB_TTBR0) {
		if (is_write) {
			val64 = *val;

			/*
			 * For Stage-2-only protected domains:
			 * - Host writes TTBR0 thinking it's programming S2 PT base
			 * - We shadow host's write but use EL2's idmap_pgtable instead
			 * - Hardware actually uses ttbr0_s2 (programmed during CB init)
			 */
			if (smmu->cb_state[cb_idx].active &&
			    smmu->cb_state[cb_idx].domain_id != 0) {
				/* Shadow host's TTBR0 but don't write to hardware */
				smmu->cb_state[cb_idx].ttbr1_s1 = val64;

				/*
				 * Keep hardware TTBR0 pointing to EL2's Stage-2 PT.
				 * This was set during smmu_v2_init_context_bank().
				 * Do NOT overwrite it with host's value.
				 */
				hyp_dbg("SMMU[%u]: CB%u TTBR0 write shadowed (0x%llx), HW unchanged\n",
					smmu->id, cb_idx, val64);
				return 0;
			} else {
				/* Host/bypass domains: write through */
				writeq_relaxed(val64, cb_base + cb_offset);
				if (smmu->has_secondary_base) {
					void __iomem *cb_base_sec = smmu->base_sec +
						(page_offset << smmu->pgshift);
					writeq_relaxed(val64, cb_base_sec + cb_offset);
				}
				return 0;
			}
		} else {
			/* Return shadow state (what host thinks it programmed) */
			if (smmu->cb_state[cb_idx].active &&
			    smmu->cb_state[cb_idx].domain_id != 0) {
				*val = smmu->cb_state[cb_idx].ttbr1_s1;
			} else {
				*val = readq_relaxed(cb_base + cb_offset);
			}
			return 0;
		}
	}

	/* TTBR1 - Translation Table Base Register 1 (Stage-1 second PT) */
	if (cb_offset == ARM_SMMU_CB_TTBR1) {
		if (is_write) {
			val64 = *val;

			/*
			 * TTBR1 is only used in Stage-1 translation.
			 * For Stage-2-only domains, this is not used.
			 * Write through for host/bypass domains.
			 */
			writeq_relaxed(val64, cb_base + cb_offset);
			if (smmu->has_secondary_base) {
				void __iomem *cb_base_sec = smmu->base_sec +
					(page_offset << smmu->pgshift);
				writeq_relaxed(val64, cb_base_sec + cb_offset);
			}
			return 0;
		} else {
			*val = readq_relaxed(cb_base + cb_offset);
			return 0;
		}
	}

	/* MAIR0/MAIR1 - Memory Attribute Indirection Registers */
	if (cb_offset == ARM_SMMU_CB_S1_MAIR0) {
		if (is_write) {
			val64 = *val;

			/* Store in shadow state */
			smmu->cb_state[cb_idx].mair[0] = (u32)val64;
			smmu->cb_state[cb_idx].mair[1] = (u32)(val64 >> 32);

			/* Write to hardware */
			writeq_relaxed(val64, cb_base + cb_offset);
			if (smmu->has_secondary_base) {
				void __iomem *cb_base_sec = smmu->base_sec +
					(page_offset << smmu->pgshift);
				writeq_relaxed(val64, cb_base_sec + cb_offset);
			}
			return 0;
		} else {
			val64 = smmu->cb_state[cb_idx].mair[0] |
				((u64)smmu->cb_state[cb_idx].mair[1] << 32);
			*val = val64;
			return 0;
		}
	}

	if (cb_offset == ARM_SMMU_CB_S1_MAIR1) {
		/* MAIR1 is the high 32 bits, but typically accessed via MAIR0 as 64-bit */
		if (is_write) {
			val32 = (u32)*val;
			smmu->cb_state[cb_idx].mair[1] = val32;
			writel_relaxed(val32, cb_base + cb_offset);
			if (smmu->has_secondary_base) {
				void __iomem *cb_base_sec = smmu->base_sec +
					(page_offset << smmu->pgshift);
				writel_relaxed(val32, cb_base_sec + cb_offset);
			}
			return 0;
		} else {
			*val = smmu->cb_state[cb_idx].mair[1];
			return 0;
		}
	}

	/* FSR - Fault Status Register (write-1-to-clear) */
	if (cb_offset == ARM_SMMU_CB_FSR) {
		if (is_write) {
			val32 = (u32)*val;
			/* Write-1-to-clear fault status */
			writel_relaxed(val32, cb_base + cb_offset);
			if (smmu->has_secondary_base) {
				void __iomem *cb_base_sec = smmu->base_sec +
					(page_offset << smmu->pgshift);
				writel_relaxed(val32, cb_base_sec + cb_offset);
			}
			return 0;
		} else {
			*val = readl_relaxed(cb_base + cb_offset);
			return 0;
		}
	}

	/* FAR - Fault Address Register (read-only) */
	if (cb_offset == ARM_SMMU_CB_FAR) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = readq_relaxed(cb_base + cb_offset);
		return 0;
	}

	/* FSYNR0 - Fault Syndrome Register 0 (read-only) */
	if (cb_offset == ARM_SMMU_CB_FSYNR0) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = readl_relaxed(cb_base + cb_offset);
		return 0;
	}

	/* PAR - Physical Address Register (read-only, result of ATS operation) */
	if (cb_offset == ARM_SMMU_CB_PAR) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = readq_relaxed(cb_base + cb_offset);
		return 0;
	}

	/* TLBSYNC - Trigger CB TLB sync */
	if (cb_offset == ARM_SMMU_CB_TLBSYNC) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		return smmu_v2_tlb_sync_context(smmu, cb_idx);
	}

	/* TLBSTATUS - CB TLB sync status (read-only) */
	if (cb_offset == ARM_SMMU_CB_TLBSTATUS) {
		if (is_write)
			return -EINVAL;  /* Read-only */

		val32 = readl_relaxed(cb_base + cb_offset);
		if (smmu->has_secondary_base) {
			void __iomem *cb_base_sec = smmu->base_sec +
				(page_offset << smmu->pgshift);
			val32 |= readl_relaxed(cb_base_sec + cb_offset);
		}
		*val = val32;
		return 0;
	}

	/*
	 * Stage-1 TLB invalidation registers (0x600-0x628)
	 * These are used by the host driver for per-context TLB invalidation.
	 * Forward to hardware and sync.
	 */
	if (cb_offset == ARM_SMMU_CB_S1_TLBIVA ||
	    cb_offset == ARM_SMMU_CB_S1_TLBIASID ||
	    cb_offset == ARM_SMMU_CB_S1_TLBIVAL) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		val64 = *val;
		writeq_relaxed(val64, cb_base + cb_offset);
		if (smmu->has_secondary_base) {
			void __iomem *cb_base_sec = smmu->base_sec +
				(page_offset << smmu->pgshift);
			writeq_relaxed(val64, cb_base_sec + cb_offset);
		}
		return smmu_v2_tlb_sync_context(smmu, cb_idx);
	}

	/* S2_TLBIIPAS2 - Stage-2 TLB invalidate by IPA */
	if (cb_offset == ARM_SMMU_CB_S2_TLBIIPAS2) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		val32 = (u32)*val;
		writel_relaxed(val32, cb_base + cb_offset);
		if (smmu->has_secondary_base) {
			void __iomem *cb_base_sec = smmu->base_sec +
				(page_offset << smmu->pgshift);
			writel_relaxed(val32, cb_base_sec + cb_offset);
		}
		return smmu_v2_tlb_sync_context(smmu, cb_idx);
	}

	/* S2_TLBIIPAS2L - Stage-2 TLB invalidate by IPA (last level only) */
	if (cb_offset == ARM_SMMU_CB_S2_TLBIIPAS2L) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		val32 = (u32)*val;
		writel_relaxed(val32, cb_base + cb_offset);
		if (smmu->has_secondary_base) {
			void __iomem *cb_base_sec = smmu->base_sec +
				(page_offset << smmu->pgshift);
			writel_relaxed(val32, cb_base_sec + cb_offset);
		}
		return smmu_v2_tlb_sync_context(smmu, cb_idx);
	}

	/* CONTEXTIDR - Context ID Register */
	if (cb_offset == ARM_SMMU_CB_CONTEXTIDR) {
		if (is_write) {
			val32 = (u32)*val;
			writel_relaxed(val32, cb_base + cb_offset);
			if (smmu->has_secondary_base) {
				void __iomem *cb_base_sec = smmu->base_sec +
					(page_offset << smmu->pgshift);
				writel_relaxed(val32, cb_base_sec + cb_offset);
			}
			return 0;
		} else {
			*val = readl_relaxed(cb_base + cb_offset);
			return 0;
		}
	}

	/* RESUME - Resume processing after stall */
	if (cb_offset == ARM_SMMU_CB_RESUME) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		val32 = (u32)*val;
		writel_relaxed(val32, cb_base + cb_offset);
		if (smmu->has_secondary_base) {
			void __iomem *cb_base_sec = smmu->base_sec +
				(page_offset << smmu->pgshift);
			writel_relaxed(val32, cb_base_sec + cb_offset);
		}
		return 0;
	}

	/* ACTLR - Auxiliary Control Register */
	if (cb_offset == ARM_SMMU_CB_ACTLR) {
		if (is_write) {
			val32 = (u32)*val;
			writel_relaxed(val32, cb_base + cb_offset);
			if (smmu->has_secondary_base) {
				void __iomem *cb_base_sec = smmu->base_sec +
					(page_offset << smmu->pgshift);
				writel_relaxed(val32, cb_base_sec + cb_offset);
			}
			return 0;
		} else {
			*val = readl_relaxed(cb_base + cb_offset);
			return 0;
		}
	}

	/* ATS1PR - Address Translation Stage 1 Privileged Read (write-only) */
	if (cb_offset == ARM_SMMU_CB_ATS1PR) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		/*
		 * ATS operation: write address to translate, then poll ATSR
		 * and read result from PAR. Forward to hardware.
		 */
		val64 = *val;
		writeq_relaxed(val64, cb_base + cb_offset);
		if (smmu->has_secondary_base) {
			void __iomem *cb_base_sec = smmu->base_sec +
				(page_offset << smmu->pgshift);
			writeq_relaxed(val64, cb_base_sec + cb_offset);
		}
		return 0;
	}

	/* ATSR - Address Translation Status Register (read-only) */
	if (cb_offset == ARM_SMMU_CB_ATSR) {
		if (is_write)
			return -EINVAL;  /* Read-only */

		val32 = readl_relaxed(cb_base + cb_offset);
		if (smmu->has_secondary_base) {
			void __iomem *cb_base_sec = smmu->base_sec +
				(page_offset << smmu->pgshift);
			val32 |= readl_relaxed(cb_base_sec + cb_offset);
		}
		*val = val32;
		return 0;
	}

	/*
	 * Unknown register - log and passthrough for debugging.
	 * TODO: Audit and restrict this once all required registers are identified.
	 */
	hyp_warn("CB[%u] unknown register 0x%x access (%s)\n",
		 cb_idx, cb_offset, is_write ? "write" : "read");

	if (is_write) {
		val32 = (u32)*val;
		writel_relaxed(val32, cb_base + cb_offset);
		if (smmu->has_secondary_base) {
			void __iomem *cb_base_sec = smmu->base_sec +
				(page_offset << smmu->pgshift);
			writel_relaxed(val32, cb_base_sec + cb_offset);
		}
	} else {
		*val = readl_relaxed(cb_base + cb_offset);
	}
	return 0;
}

/**
 * smmu_v2_mmio_handler - Main MMIO trap handler
 * @addr: Physical address being accessed
 * @is_write: true for write access, false for read
 * @val: Pointer to value (read or write)
 *
 * Called by EL2 MMIO trap infrastructure when host accesses SMMU registers.
 */
bool smmu_v2_mmio_handler(u64 addr, bool is_write, u64 *val)
{
	struct hyp_arm_smmu_v2_device *smmu;
	u32 offset, page;
	int ret;

	smmu = smmu_v2_find_by_mmio_addr(addr);
	if (!smmu)
		return false;

	/* Calculate offset relative to SMMU base */
	if (addr >= smmu->mmio_addr && addr < smmu->mmio_addr + smmu->mmio_size)
		offset = addr - smmu->mmio_addr;
	else if (smmu->has_secondary_base &&
		 addr >= smmu->mmio_addr_sec && addr < smmu->mmio_addr_sec + smmu->mmio_size)
		offset = addr - smmu->mmio_addr_sec;
	else
		return false;

	page = offset & ~((1 << smmu->pgshift) - 1);

	/* Route to appropriate page handler */
	if (page == ARM_SMMU_GR0)
		ret = smmu_v2_handle_gr0(smmu, offset - ARM_SMMU_GR0, is_write, val);
	else if (page == ARM_SMMU_GR1)
		ret = smmu_v2_handle_gr1(smmu, offset - ARM_SMMU_GR1, is_write, val);
	else
		ret = smmu_v2_handle_cb(smmu, offset, is_write, val);

	return ret == 0;
}

/*
 * Context Bank Management
 */

/**
 * smmu_v2_alloc_context_bank - Allocate a free context bank
 * @smmu: SMMU device
 *
 * Returns: Context bank index, or ARM_SMMU_INVALID_CB if none available
 */
u8 smmu_v2_alloc_context_bank(struct hyp_arm_smmu_v2_device *smmu)
{
	u32 i;
	u32 word_idx, bit_idx;
	unsigned long *map = smmu->context_map;

	hyp_spin_lock(&smmu->lock);

	/* Manually search for first zero bit */
	for (i = 0; i < smmu->num_context_banks; i++) {
		word_idx = i / BITS_PER_LONG;
		bit_idx = i % BITS_PER_LONG;

		if (!(map[word_idx] & (1UL << bit_idx))) {
			/* Found free CB - mark as allocated */
			map[word_idx] |= (1UL << bit_idx);
			smmu->cb_state[i].active = true;
			hyp_spin_unlock(&smmu->lock);
			return i;
		}
	}

	hyp_spin_unlock(&smmu->lock);
	return ARM_SMMU_INVALID_CB;
}

/**
 * smmu_v2_free_context_bank - Free a context bank
 * @smmu: SMMU device
 * @idx: Context bank index
 */
void smmu_v2_free_context_bank(struct hyp_arm_smmu_v2_device *smmu, u8 idx)
{
	u32 word_idx, bit_idx;
	unsigned long *map = smmu->context_map;

	if (idx >= smmu->num_context_banks)
		return;

	word_idx = idx / BITS_PER_LONG;
	bit_idx = idx % BITS_PER_LONG;

	hyp_spin_lock(&smmu->lock);
	/* Clear the bit manually */
	map[word_idx] &= ~(1UL << bit_idx);
	smmu->cb_state[idx].active = false;
	smmu->cb_state[idx].domain_id = 0;
	hyp_spin_unlock(&smmu->lock);
}

/**
 * smmu_v2_init_context_bank - Configure a context bank for a domain
 * @smmu: SMMU device
 * @domain: IOMMU domain
 * @cb_idx: Context bank index
 *
 * Programs CBAR, TTBR, TCR, and other CB registers for Stage-2 translation.
 * Uses the global identity-mapped page table (idmap_pgtable) which mirrors
 * the host's CPU stage-2 mappings.
 */
int smmu_v2_init_context_bank(struct hyp_arm_smmu_v2_device *smmu,
			       struct kvm_hyp_iommu_domain *domain, u8 cb_idx)
{
	struct smmu_v2_cb_state *cb = &smmu->cb_state[cb_idx];
	struct io_pgtable_cfg *pgt_cfg;
	u32 cbar, vtcr, sctlr, cb_page;
	u64 ttbr0;

	if (cb_idx >= smmu->num_context_banks)
		return -EINVAL;

	if (WARN_ON(!idmap_pgtable))
		return -EINVAL;

	pgt_cfg = &idmap_pgtable->cfg;

	/* Calculate CB page offset: context banks start at page numpage */
	cb_page = (cb_idx + smmu->numpage) << smmu->pgshift;

	/* 1. Configure CBAR (Context Bank Attribute Register) for Stage-2 only */
	cbar = FIELD_PREP(ARM_SMMU_CBAR_TYPE, CBAR_TYPE_S2_TRANS);
	cbar |= FIELD_PREP(ARM_SMMU_CBAR_VMID, 0);  /* VMID = 0 (global identity mapping) */
	smmu_writel(smmu, ARM_SMMU_GR1, ARM_SMMU_GR1_CBAR(cb_idx), cbar);

	/* Configure CBA2R (extended attributes) for 64-bit addressing */
	smmu_writel(smmu, ARM_SMMU_GR1, ARM_SMMU_GR1_CBA2R(cb_idx),
		    ARM_SMMU_CBA2R_VA64);

	/* 2. Program VTCR via TCR2 register for Stage-2 translation control */
	vtcr = ARM_SMMU_VTCR_RES1;  /* Reserved bit that must be 1 */

	/* Extract configuration from global page table */
	vtcr |= (pgt_cfg->arm_lpae_s2_cfg.vtcr.ps << 16);    /* Physical address size */
	vtcr |= (pgt_cfg->arm_lpae_s2_cfg.vtcr.tg << 14);    /* Translation granule */
	vtcr |= (pgt_cfg->arm_lpae_s2_cfg.vtcr.sh << 12);    /* Shareability */
	vtcr |= (pgt_cfg->arm_lpae_s2_cfg.vtcr.orgn << 10);  /* Outer cacheability */
	vtcr |= (pgt_cfg->arm_lpae_s2_cfg.vtcr.irgn << 8);   /* Inner cacheability */
	vtcr |= (pgt_cfg->arm_lpae_s2_cfg.vtcr.sl << 6);     /* Start level */
	vtcr |= (64 - pgt_cfg->ias);                          /* T0SZ: input address size */

	smmu_writeq(smmu, cb_page, ARM_SMMU_CB_TCR2, vtcr);

	/* 3. Write TTBR0 with Stage-2 page table base address */
	ttbr0 = pgt_cfg->arm_lpae_s2_cfg.vttbr;
	smmu_writeq(smmu, cb_page, ARM_SMMU_CB_TTBR0, ttbr0);

	/* 4. Enable translation by setting SCTLR.M bit */
	sctlr = ARM_SMMU_SCTLR_M;        /* Enable MMU */
	sctlr |= ARM_SMMU_SCTLR_TRE;     /* TEX remap enable */
	sctlr |= ARM_SMMU_SCTLR_AFE;     /* Access flag enable */
	sctlr |= ARM_SMMU_SCTLR_CFIE;    /* Context fault interrupt enable */
	sctlr |= ARM_SMMU_SCTLR_CFRE;    /* Context fault report enable */
	smmu_writel(smmu, cb_page, ARM_SMMU_CB_SCTLR, sctlr);

	/* Update CB state tracking */
	cb->domain_id = domain->domain_id;
	cb->cbar = cbar;
	cb->vtcr = vtcr;
	cb->ttbr0_s2 = ttbr0;
	cb->sctlr = sctlr;
	cb->vmid = 0;  /* Global VMID for identity mapping */
	cb->active = true;

	return 0;
}

/**
 * smmu_v2_global_init - Global initialization for all SMMU instances
 *
 * Called once during hypervisor initialization to set up all SMMU devices
 * and create the global identity-mapped page table.
 *
 * This should be called from the kvm_iommu_ops->init() callback.
 *
 * Returns: 0 on success, negative error code on failure
 */
int smmu_v2_global_init(pkvm_handle_t drv_id)
{
	struct hyp_arm_smmu_v2_device *smmu;
	int i, ret;

#ifdef CONFIG_TEGRA_MC_PKVM
	/* Register Tegra MC platform hooks for SID override validation */
	tegra234_mc_register_hooks();
#endif

	hyp_info("SMMUv2: Starting global initialization");

	/*
	 * Convert array base from kernel VA to hyp VA.
	 * Then donate the memory to make it accessible to EL2.
	 */
	if (kvm_hyp_arm_smmu_v2_smmus) {
		size_t smmu_arr_size;

		kvm_hyp_arm_smmu_v2_smmus = kern_hyp_va(kvm_hyp_arm_smmu_v2_smmus);

		/* Calculate array size and donate memory to EL2 (must be page-aligned) */
		smmu_arr_size = PAGE_ALIGN(sizeof(struct hyp_arm_smmu_v2_device) * kvm_hyp_arm_smmu_v2_count);
		ret = smmu_take_pages(hyp_virt_to_phys((void *)kvm_hyp_arm_smmu_v2_smmus),
				      smmu_arr_size);
		if (ret) {
			hyp_err("SMMUv2: Failed to donate SMMU array memory (ret=%d)", ret);
			return ret;
		}

		hyp_info("SMMUv2: Donated SMMU array: %zu bytes for %zu instances",
			 smmu_arr_size, kvm_hyp_arm_smmu_v2_count);
	}

	/* Initialize each SMMU instance */
	for (i = 0; i < kvm_hyp_arm_smmu_v2_count; i++) {
		smmu = &kvm_hyp_arm_smmu_v2_smmus[i];

		hyp_info("SMMUv2: Initializing SMMU instance %u at PA 0x%llx",
			 i, smmu->mmio_addr);

		/*
		 * Shadow arrays are NULL initially (not set by EL1).
		 * smmu_v2_init() will allocate them from hyp memory pool.
		 */

		ret = smmu_v2_init(smmu);
		if (WARN_ON(ret)) {
			hyp_err("SMMUv2: Failed to init SMMU %u (ret=%d)", i, ret);
			return ret;
		}

		hyp_info("SMMUv2: SMMU %u initialization complete", i);
	}

	/* Call platform-specific initialization (e.g., Tegra MC) */
	if (platform_hooks && platform_hooks->init) {
		ret = platform_hooks->init();
		if (ret) {
			hyp_err("SMMUv2: Platform init failed (ret=%d)", ret);
			return ret;
		}
	}

	/* Initialize global identity-mapped page table (shared by all SMMUs) */
	ret = smmu_v2_init_pgt();
	if (WARN_ON(ret))
		return ret;

	hyp_info("SMMUv2: Global initialization complete");

	return 0;
}

/*
 * Stream Mapping
 */

/**
 * smmu_v2_find_free_sme - Find available Stream Mapping Entry
 * @smmu: SMMU device
 *
 * Finds an unused SMR/S2CR register pair. Each pair is called a
 * Stream Mapping Entry (SME).
 *
 * Returns: SME index (0 to num_mapping_groups-1), or negative error code
 */
static int smmu_v2_find_free_sme(struct hyp_arm_smmu_v2_device *smmu)
{
	int i;

	/* Scan hardware state array for first invalid (unused) entry */
	for (i = 0; i < smmu->num_mapping_groups; i++) {
		if (!smmu->smrs_hw[i].valid)
			return i;
	}

	/* All SMEs are allocated */
	return -ENOSPC;
}

/**
 * smmu_v2_find_sme_by_sid - Find SME that matches a Stream ID
 * @smmu: SMMU device
 * @sid: Stream ID to search for
 *
 * Returns: SME index if found, or negative error code
 */
static int smmu_v2_find_sme_by_sid(struct hyp_arm_smmu_v2_device *smmu, u32 sid)
{
	int i;

	for (i = 0; i < smmu->num_mapping_groups; i++) {
		if (smmu->smrs_hw[i].valid && smmu->smrs_hw[i].id == sid)
			return i;
	}

	return -ENOENT;
}

/**
 * smmu_v2_map_stream - Map a Stream ID to a context bank
 * @smmu: SMMU device
 * @sid: Stream ID
 * @cb_idx: Context bank index
 *
 * Configures SMR and S2CR registers to route traffic from @sid to @cb_idx.
 * This is the core operation that connects a device's DMA transactions
 * (identified by Stream ID) to an IOMMU translation context.
 *
 * Returns: 0 on success, negative error code on failure
 */
int smmu_v2_map_stream(struct hyp_arm_smmu_v2_device *smmu, u32 sid, u8 cb_idx)
{
	int sme_idx;
	u32 smr_val, s2cr_val;

	if (sid >= ARM_SMMU_MAX_SIDS) {
		hyp_err("SMMU[%u]: Invalid SID %u (max %u)\n",
			smmu->id, sid, ARM_SMMU_MAX_SIDS - 1);
		return -EINVAL;
	}

	if (cb_idx >= smmu->num_context_banks) {
		hyp_err("SMMU[%u]: Invalid CB index %u (max %u)\n",
			smmu->id, cb_idx, smmu->num_context_banks - 1);
		return -EINVAL;
	}

	/* Check if this SID is already mapped */
	sme_idx = smmu_v2_find_sme_by_sid(smmu, sid);
	if (sme_idx >= 0) {
		/* Already mapped - verify it points to the correct CB */
		if (smmu->s2crs_hw[sme_idx].cbndx == cb_idx) {
			/* Already correctly mapped, nothing to do */
			return 0;
		}

		/* Mapped to different CB - this is an error */
		hyp_err("SMMU[%u]: SID %u already mapped to CB %u (tried to map to CB %u)\n",
			smmu->id, sid, smmu->s2crs_hw[sme_idx].cbndx, cb_idx);
		return -EEXIST;
	}

	/* Find free SME (Stream Mapping Entry) */
	sme_idx = smmu_v2_find_free_sme(smmu);
	if (sme_idx < 0) {
		hyp_err("SMMU[%u]: No free stream mapping entries\n", smmu->id);
		return sme_idx;
	}

	/*
	 * Configure SMR (Stream Match Register):
	 * - Set Stream ID to match
	 * - Set mask to 0 (exact match, no masking)
	 * - Set VALID bit to enable this entry
	 */
	smr_val = FIELD_PREP(ARM_SMMU_SMR_ID, sid) | ARM_SMMU_SMR_VALID;

	/*
	 * Configure S2CR (Stream-to-Context Register):
	 * - TYPE = TRANS (translation enabled, not bypass/fault)
	 * - CBNDX = context bank index
	 * - PRIVCFG = 0 (use incoming transaction attributes)
	 */
	s2cr_val = FIELD_PREP(ARM_SMMU_S2CR_TYPE, S2CR_TYPE_TRANS) |
		   FIELD_PREP(ARM_SMMU_S2CR_CBNDX, cb_idx);

	/* Write to hardware (both primary and secondary bases if applicable) */
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_SMR(sme_idx), smr_val);
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_S2CR(sme_idx), s2cr_val);

	/* Update hardware state tracking */
	smmu->smrs_hw[sme_idx].id = (u16)sid;
	smmu->smrs_hw[sme_idx].mask = 0;
	smmu->smrs_hw[sme_idx].valid = true;

	smmu->s2crs_hw[sme_idx].type = S2CR_TYPE_TRANS;
	smmu->s2crs_hw[sme_idx].cbndx = cb_idx;
	smmu->s2crs_hw[sme_idx].privcfg = 0;
	smmu->s2crs_hw[sme_idx].bypass = false;

	/*
	 * Also update shadow state (what host thinks hardware has).
	 * This ensures that if host reads back these registers via
	 * MMIO emulation, it sees the correct values.
	 */
	smmu->smrs_shadow[sme_idx] = smmu->smrs_hw[sme_idx];
	smmu->s2crs_shadow[sme_idx] = smmu->s2crs_hw[sme_idx];

	return 0;
}

/**
 * smmu_v2_unmap_stream - Unmap a Stream ID
 * @smmu: SMMU device
 * @sid: Stream ID
 *
 * Clears the SMR/S2CR registers for this Stream ID, causing all
 * transactions from this device to fault (until remapped).
 *
 * Returns: 0 on success, negative error code on failure
 */
int smmu_v2_unmap_stream(struct hyp_arm_smmu_v2_device *smmu, u32 sid)
{
	int sme_idx;
	u32 s2cr_val;

	if (sid >= ARM_SMMU_MAX_SIDS)
		return -EINVAL;

	/* Find the SME that maps this SID */
	sme_idx = smmu_v2_find_sme_by_sid(smmu, sid);
	if (sme_idx < 0) {
		/* Not mapped - this is not an error, just a no-op */
		return 0;
	}

	/*
	 * Clear SMR (invalidate this entry).
	 * This causes transactions with this SID to no longer match.
	 */
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_SMR(sme_idx), 0);

	/*
	 * Configure S2CR to FAULT mode.
	 * This ensures any stray transactions (e.g., in-flight DMA)
	 * will generate a fault rather than accessing memory.
	 */
	s2cr_val = FIELD_PREP(ARM_SMMU_S2CR_TYPE, S2CR_TYPE_FAULT);
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_S2CR(sme_idx), s2cr_val);

	/* Update hardware state tracking */
	smmu->smrs_hw[sme_idx].id = 0;
	smmu->smrs_hw[sme_idx].mask = 0;
	smmu->smrs_hw[sme_idx].valid = false;

	smmu->s2crs_hw[sme_idx].type = S2CR_TYPE_FAULT;
	smmu->s2crs_hw[sme_idx].cbndx = 0;
	smmu->s2crs_hw[sme_idx].privcfg = 0;
	smmu->s2crs_hw[sme_idx].bypass = false;

	/* Update shadow state */
	smmu->smrs_shadow[sme_idx] = smmu->smrs_hw[sme_idx];
	smmu->s2crs_shadow[sme_idx] = smmu->s2crs_hw[sme_idx];

	return 0;
}

/*
 * TLB Operations
 */

/**
 * smmu_v2_tlb_sync_global - Wait for global TLB sync to complete
 * @smmu: SMMU device
 *
 * Returns: 0 on success, -ETIMEDOUT on timeout
 */
int smmu_v2_tlb_sync_global(struct hyp_arm_smmu_v2_device *smmu)
{
	u32 val;
	unsigned int timeout = TLB_LOOP_TIMEOUT;

	/* Trigger sync */
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sTLBGSYNC, 0);

	/* Poll for completion with timeout */
	do {
		val = smmu_tlb_sync_status(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sTLBGSTATUS);
		if (!(val & ARM_SMMU_sTLBGSTATUS_GSACTIVE))
			return 0;
		timeout--;
	} while (timeout);

	/* Timeout - hardware error */
	hyp_err("SMMU[%u]: Global TLB sync timeout (GSACTIVE still set)\n", smmu->id);
	return -ETIMEDOUT;
}

/**
 * smmu_v2_tlb_sync_context - Wait for context TLB sync to complete
 * @smmu: SMMU device
 * @cb_idx: Context bank index
 *
 * Returns: 0 on success, -ETIMEDOUT on timeout
 */
int smmu_v2_tlb_sync_context(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx)
{
	void __iomem *cb_base;
	u32 val;
	unsigned int timeout = TLB_LOOP_TIMEOUT;

	/* Calculate context bank base address */
	cb_base = smmu->base + ((cb_idx + smmu->numpage) << smmu->pgshift);

	/* Trigger sync */
	writel_relaxed(0, cb_base + ARM_SMMU_CB_TLBSYNC);
	if (smmu->has_secondary_base) {
		void __iomem *cb_base_sec = smmu->base_sec + ((cb_idx + smmu->numpage) << smmu->pgshift);
		writel_relaxed(0, cb_base_sec + ARM_SMMU_CB_TLBSYNC);
	}

	/* Poll for completion with timeout */
	do {
		val = readl_relaxed(cb_base + ARM_SMMU_CB_TLBSTATUS);
		if (smmu->has_secondary_base)
			val |= readl_relaxed(smmu->base_sec + ((cb_idx + smmu->numpage) << smmu->pgshift) + ARM_SMMU_CB_TLBSTATUS);

		if (!(val & BIT(0)))  /* SACTIVE bit */
			return 0;
		timeout--;
	} while (timeout);

	/* Timeout - hardware error */
	hyp_err("SMMU[%u]: Context bank %u TLB sync timeout (SACTIVE still set)\n",
		smmu->id, cb_idx);
	return -ETIMEDOUT;
}

/**
 * smmu_v2_tlb_inv_context - Invalidate all TLB entries for a context
 * @smmu: SMMU device
 * @cb_idx: Context bank index
 *
 * Uses TLBIVMID to invalidate all TLB entries for a given VMID.
 * This is more efficient than per-page invalidation for large ranges.
 */
void smmu_v2_tlb_inv_context(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx)
{
	struct smmu_v2_cb_state *cb = &smmu->cb_state[cb_idx];
	int ret;

	/* Invalidate all TLB entries for this VMID */
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_TLBIVMID, cb->vmid);

	/* Ensure invalidation completes */
	ret = smmu_v2_tlb_sync_global(smmu);
	if (ret)
		hyp_err("SMMU[%u]: TLB sync failed after context invalidation (CB %u, VMID %u)\n",
			smmu->id, cb_idx, cb->vmid);
}

/**
 * smmu_v2_tlb_inv_range - Invalidate TLB entries for an IOVA range
 * @smmu: SMMU device
 * @cb_idx: Context bank index
 * @iova: Starting IOVA
 * @size: Size of range
 * @granule: Invalidation granule
 *
 * For small ranges, use address-based invalidation. For large ranges,
 * fall back to full context invalidation which is more efficient.
 */
void smmu_v2_tlb_inv_range(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx,
			   unsigned long iova, size_t size, size_t granule)
{
	void __iomem *cb_base;
	unsigned long iova_start, iova_end;
	size_t num_pages;
	int ret;

	/* Calculate number of pages in range */
	num_pages = (size + granule - 1) / granule;

	/*
	 * Threshold for full context invalidation vs per-page:
	 * If more than 32 pages, invalidate entire context for efficiency.
	 * This avoids excessive register writes for large unmaps.
	 */
	if (num_pages > 32) {
		smmu_v2_tlb_inv_context(smmu, cb_idx);
		return;
	}

	/* Calculate context bank base address */
	cb_base = smmu->base + ((cb_idx + smmu->numpage) << smmu->pgshift);

	/* Invalidate each page in the range */
	iova_start = iova & ~(granule - 1);
	iova_end = iova_start + size;

	for (; iova_start < iova_end; iova_start += granule) {
		/*
		 * Use Stage-2 TLB invalidate by IPA (S2_TLBIIPAS2).
		 * For Stage-2-only translation, this is the appropriate operation.
		 * The address is shifted right by 12 bits (4K page boundary).
		 */
		u64 addr = iova_start >> 12;

		writel_relaxed((u32)addr, cb_base + ARM_SMMU_CB_S2_TLBIIPAS2);
		if (smmu->has_secondary_base) {
			void __iomem *cb_base_sec = smmu->base_sec + ((cb_idx + smmu->numpage) << smmu->pgshift);
			writel_relaxed((u32)addr, cb_base_sec + ARM_SMMU_CB_S2_TLBIIPAS2);
		}
	}

	/* Ensure TLB invalidations complete */
	ret = smmu_v2_tlb_sync_context(smmu, cb_idx);
	if (ret)
		hyp_err("SMMU[%u]: TLB sync failed after range invalidation\n", smmu->id);
}

/*
 * Stream ID Management
 */

/**
 * smmu_v2_assign_sid - Assign a Stream ID to a domain
 * @smmu_id: SMMU instance ID
 * @sid: Stream ID
 * @client_id: Memory controller client ID
 * @domain_id: Domain handle
 */
int smmu_v2_assign_sid(u32 smmu_id, u32 sid, u32 client_id, pkvm_handle_t domain_id)
{
	struct sid_assignment *entry;

	if (sid >= ARM_SMMU_MAX_SIDS)
		return -EINVAL;

	entry = &sid_map[sid];

	/*
	 * Check if already assigned to a different domain.
	 * Allow assignment if:
	 * - Not active yet (first assignment)
	 * - Same domain (idempotent)
	 * - Current domain is 0 (registered by MC but not yet attached)
	 */
	if (entry->active &&
	    entry->domain_id != 0 &&
	    entry->domain_id != domain_id)
		return -EBUSY;

	/*
	 * Update domain assignment. Note that client_ids[] are already
	 * populated by MC enumeration (mc_register_sid_mapping).
	 */
	entry->sid = sid;
	entry->domain_id = domain_id;
	entry->smmu_id = smmu_id;
	entry->active = true;

	return 0;
}

/**
 * smmu_v2_release_sid - Release a Stream ID assignment
 * @smmu_id: SMMU instance ID
 * @sid: Stream ID
 */
int smmu_v2_release_sid(u32 smmu_id, u32 sid)
{
	struct sid_assignment *entry;

	if (sid >= ARM_SMMU_MAX_SIDS)
		return -EINVAL;

	entry = &sid_map[sid];
	if (!entry->active || entry->smmu_id != smmu_id)
		return -EINVAL;

	entry->active = false;
	entry->domain_id = 0;

	return 0;
}

/**
 * smmu_v2_lookup_sid - Look up Stream ID assignment
 * @sid: Stream ID
 */
struct sid_assignment *smmu_v2_lookup_sid(u32 sid)
{
	if (sid >= ARM_SMMU_MAX_SIDS)
		return NULL;

	return sid_map[sid].active ? &sid_map[sid] : NULL;
}

/*
 * Domain Operations
 */

/**
 * smmu_v2_alloc_domain - Allocate an IOMMU domain
 * @iommu_id: SMMU instance ID (0-2 for Tegra234)
 * @domain: Generic IOMMU domain structure (to be initialized)
 * @type: Domain type (currently unused, always Stage-2)
 *
 * Allocates a context bank and creates a Stage-2 page table for the domain.
 * For SMMUv2 pKVM, we use the global identity-mapped page table created
 * during initialization (idmap_pgtable) which is shared by all domains.
 *
 * Returns: 0 on success, negative error code on failure
 */
int smmu_v2_alloc_domain(pkvm_handle_t iommu_id, struct kvm_hyp_iommu_domain *domain, int type)
{
	struct hyp_arm_smmu_v2_device *smmu;
	struct smmu_v2_domain *smmu_domain;
	u8 cb_idx;
	int ret;

	/* Validate SMMU instance ID */
	if (iommu_id >= kvm_hyp_arm_smmu_v2_count) {
		hyp_err("SMMU: Invalid iommu_id %u (max %zu)\n",
			iommu_id, kvm_hyp_arm_smmu_v2_count - 1);
		return -EINVAL;
	}

	smmu = &kvm_hyp_arm_smmu_v2_smmus[iommu_id];

	/* Allocate domain-specific state */
	smmu_domain = kvm_iommu_donate_page();
	if (!smmu_domain) {
		hyp_err("SMMU[%u]: Failed to allocate domain structure\n", smmu->id);
		return -ENOMEM;
	}

	/* Allocate a context bank */
	cb_idx = smmu_v2_alloc_context_bank(smmu);
	if (cb_idx == ARM_SMMU_INVALID_CB) {
		hyp_err("SMMU[%u]: No free context banks\n", smmu->id);
		ret = -ENOSPC;
		goto err_free_domain;
	}

	/* Initialize domain private state */
	smmu_domain->smmu = smmu;
	smmu_domain->cb_idx = cb_idx;
	smmu_domain->pgtbl_ops = &idmap_pgtable->ops;  /* Use global identity PT */

	/* Initialize context bank with Stage-2 translation */
	ret = smmu_v2_init_context_bank(smmu, domain, cb_idx);
	if (ret) {
		hyp_err("SMMU[%u]: Failed to initialize CB%u (ret=%d)\n",
			smmu->id, cb_idx, ret);
		goto err_free_cb;
	}

	/* Store domain ID in context bank state for tracking */
	smmu->cb_state[cb_idx].domain_id = domain->domain_id;
	smmu->cb_state[cb_idx].active = true;

	/* Link domain private data */
	domain->priv = smmu_domain;

	hyp_info("SMMU[%u]: Allocated domain %u with CB%u\n",
		 smmu->id, domain->domain_id, cb_idx);

	return 0;

err_free_cb:
	smmu_v2_free_context_bank(smmu, cb_idx);
err_free_domain:
	kvm_iommu_reclaim_page(smmu_domain);
	return ret;
}

/**
 * smmu_v2_free_domain - Free an IOMMU domain
 * @domain: Domain to free
 *
 * Releases the context bank and frees domain-specific state.
 * Note: We don't free the global identity-mapped page table as it's
 * shared by all domains.
 */
void smmu_v2_free_domain(struct kvm_hyp_iommu_domain *domain)
{
	struct smmu_v2_domain *smmu_domain = domain->priv;
	struct hyp_arm_smmu_v2_device *smmu;
	u8 cb_idx;

	if (!smmu_domain)
		return;

	smmu = smmu_domain->smmu;
	cb_idx = smmu_domain->cb_idx;

	/* Invalidate all TLB entries for this context bank */
	smmu_v2_tlb_inv_context(smmu, cb_idx);

	/* Mark context bank as inactive */
	smmu->cb_state[cb_idx].active = false;
	smmu->cb_state[cb_idx].domain_id = 0;

	/* Free context bank */
	smmu_v2_free_context_bank(smmu, cb_idx);

	/* Free domain structure */
	kvm_iommu_reclaim_page(smmu_domain);
	domain->priv = NULL;

	hyp_info("SMMU[%u]: Freed domain %u (CB%u)\n",
		 smmu->id, domain->domain_id, cb_idx);
}

/*
 * Device Lifecycle
 */

/**
 * smmu_v2_attach_dev - Attach a device to an IOMMU domain
 * @iommu_id: SMMU instance ID
 * @domain: Domain to attach device to
 * @endpoint_id: Stream ID (0-255)
 * @pasid: PASID (not used for SMMUv2, always 0)
 * @pasid_bits: PASID bits (not used for SMMUv2)
 * @flags: Attachment flags (reserved)
 *
 * Configures the stream mapping (SMR+S2CR) to route traffic from the
 * specified Stream ID to the domain's context bank. Also records the
 * SID assignment for Memory Controller validation.
 *
 * Returns: 0 on success, negative error code on failure
 */
int smmu_v2_attach_dev(pkvm_handle_t iommu_id, struct kvm_hyp_iommu_domain *domain,
		       pkvm_handle_t endpoint_id, u32 pasid, u32 pasid_bits, unsigned long flags)
{
	struct smmu_v2_domain *smmu_domain = domain->priv;
	struct hyp_arm_smmu_v2_device *smmu;
	u32 sid = endpoint_id;  /* For SMMUv2, endpoint_id is the Stream ID */
	u8 cb_idx;
	int ret;

	if (!smmu_domain) {
		hyp_err("SMMU: Domain %u has no private data\n", domain->domain_id);
		return -EINVAL;
	}

	smmu = smmu_domain->smmu;
	cb_idx = smmu_domain->cb_idx;

	/* Validate Stream ID */
	if (sid >= ARM_SMMU_MAX_SIDS) {
		hyp_err("SMMU[%u]: Invalid SID %u (max %u)\n",
			smmu->id, sid, ARM_SMMU_MAX_SIDS - 1);
		return -EINVAL;
	}

	/* Configure stream mapping (SMR+S2CR) */
	ret = smmu_v2_map_stream(smmu, sid, cb_idx);
	if (ret) {
		hyp_err("SMMU[%u]: Failed to map SID %u to CB%u (ret=%d)\n",
			smmu->id, sid, cb_idx, ret);
		return ret;
	}

	/* Record SID assignment (for MC validation) */
	ret = smmu_v2_assign_sid(smmu->id, sid, 0 /* client_id unknown at attach */,
				 domain->domain_id);
	if (ret) {
		hyp_err("SMMU[%u]: Failed to assign SID %u (ret=%d)\n",
			smmu->id, sid, ret);
		smmu_v2_unmap_stream(smmu, sid);  /* Undo stream mapping */
		return ret;
	}

	hyp_info("SMMU[%u]: Attached SID %u to domain %u (CB%u)\n",
		 smmu->id, sid, domain->domain_id, cb_idx);

	return 0;
}

/**
 * smmu_v2_detach_dev - Detach a device from an IOMMU domain
 * @iommu_id: SMMU instance ID
 * @domain: Domain to detach device from
 * @endpoint_id: Stream ID
 * @pasid: PASID (not used for SMMUv2)
 *
 * Clears the stream mapping and releases the SID assignment.
 * Sets the stream to FAULT mode to catch stray DMA transactions.
 *
 * Returns: 0 on success, negative error code on failure
 */
int smmu_v2_detach_dev(pkvm_handle_t iommu_id, struct kvm_hyp_iommu_domain *domain,
		       pkvm_handle_t endpoint_id, u32 pasid)
{
	struct smmu_v2_domain *smmu_domain = domain->priv;
	struct hyp_arm_smmu_v2_device *smmu;
	u32 sid = endpoint_id;
	int ret;

	if (!smmu_domain) {
		hyp_err("SMMU: Domain %u has no private data\n", domain->domain_id);
		return -EINVAL;
	}

	smmu = smmu_domain->smmu;

	/* Release SID assignment */
	ret = smmu_v2_release_sid(smmu->id, sid);
	if (ret) {
		hyp_err("SMMU[%u]: Failed to release SID %u (ret=%d)\n",
			smmu->id, sid, ret);
		/* Continue anyway - best effort cleanup */
	}

	/* Clear stream mapping (sets to FAULT mode) */
	ret = smmu_v2_unmap_stream(smmu, sid);
	if (ret) {
		hyp_err("SMMU[%u]: Failed to unmap SID %u (ret=%d)\n",
			smmu->id, sid, ret);
		return ret;
	}

	/* Invalidate TLB for this context bank */
	smmu_v2_tlb_inv_context(smmu, smmu_domain->cb_idx);

	hyp_info("SMMU[%u]: Detached SID %u from domain %u\n",
		 smmu->id, sid, domain->domain_id);

	return 0;
}

/*
 * Page Table Operations
 */

/**
 * smmu_v2_map_pages - Map IOVA range to physical addresses
 * @domain: Domain to map pages in
 * @iova: I/O virtual address to start mapping
 * @paddr: Physical address to map to
 * @pgsize: Page size (must be 4K for Tegra234)
 * @pgcount: Number of pages to map
 * @prot: Protection flags (IOMMU_READ, IOMMU_WRITE, IOMMU_CACHE, etc.)
 * @total_mapped: Output parameter for total bytes mapped
 *
 * Uses the global identity-mapped page table to map IOVA to physical addresses.
 * Note: For Tegra234, only 4K pages are supported due to walk cache erratum.
 *
 * IMPORTANT: Since we use a global identity-mapped page table, many IOVAs
 * are already mapped (IOVA=PA). If the requested mapping matches an existing
 * identity mapping, we return success (idempotent operation).
 *
 * Returns: 0 on success, negative error code on failure
 */
int smmu_v2_map_pages(struct kvm_hyp_iommu_domain *domain, unsigned long iova,
		      phys_addr_t paddr, size_t pgsize, size_t pgcount, int prot, size_t *total_mapped)
{
	struct smmu_v2_domain *smmu_domain = domain->priv;
	struct io_pgtable_ops *ops;
	size_t mapped = 0;
	size_t size;
	int ret;

	if (!smmu_domain) {
		hyp_err("SMMU: Domain %u has no private data\n", domain->domain_id);
		return -EINVAL;
	}

	ops = smmu_domain->pgtbl_ops;
	if (!ops || !ops->map_pages) {
		hyp_err("SMMU: Domain %u has no page table ops\n", domain->domain_id);
		return -ENODEV;
	}

	/* Validate page size (Tegra234: 4K only) */
	if (pgsize != SZ_4K) {
		hyp_err("SMMU: Unsupported page size %zu (only 4K supported)\n", pgsize);
		return -EINVAL;
	}

	size = pgsize * pgcount;

	/*
	 * For identity-mapped page tables, check if the mapping already exists.
	 * If IOVA == PA (identity mapping) and the region is already mapped,
	 * this is an idempotent operation - just return success.
	 *
	 * This handles the case where the global identity page table was
	 * pre-populated via host_stage2_idmap(), and DMA allocations attempt
	 * to map the same IOVAs again.
	 */
	if (iova == paddr && ops->iova_to_phys) {
		phys_addr_t existing_pa = ops->iova_to_phys(ops, iova);
		if (existing_pa == paddr) {
			/* Already identity-mapped with same PA - success */
			if (total_mapped)
				*total_mapped = size;
			return 0;
		}
	}

	/* Map pages using io-pgtable */
	ret = ops->map_pages(ops, iova, paddr, pgsize, pgcount, prot, GFP_KERNEL, &mapped);
	if (ret == -EEXIST && iova == paddr) {
		/*
		 * -EEXIST with identity mapping: the page table entry already
		 * exists. Since we're doing identity mapping (IOVA=PA), this
		 * is not an error - the mapping is already what we want.
		 */
		if (total_mapped)
			*total_mapped = size;
		return 0;
	}
	if (ret) {
		hyp_err("SMMU: Failed to map IOVA 0x%lx → PA 0x%llx (ret=%d, mapped=%zu)\n",
			iova, (unsigned long long)paddr, ret, mapped);
		if (total_mapped)
			*total_mapped = mapped;
		return ret;
	}

	if (total_mapped)
		*total_mapped = mapped;

	return 0;
}

/**
 * smmu_v2_unmap_pages - Unmap IOVA range
 * @domain: Domain to unmap pages from
 * @iova: I/O virtual address to start unmapping
 * @pgsize: Page size
 * @pgcount: Number of pages to unmap
 * @gather: TLB gather structure (for batching TLB invalidations)
 *
 * Returns: Number of bytes unmapped
 */
size_t smmu_v2_unmap_pages(struct kvm_hyp_iommu_domain *domain, unsigned long iova,
			   size_t pgsize, size_t pgcount, struct iommu_iotlb_gather *gather)
{
	struct smmu_v2_domain *smmu_domain = domain->priv;
	struct io_pgtable_ops *ops;
	size_t unmapped;

	if (!smmu_domain) {
		hyp_err("SMMU: Domain %u has no private data\n", domain->domain_id);
		return 0;
	}

	ops = smmu_domain->pgtbl_ops;
	if (!ops || !ops->unmap_pages) {
		hyp_err("SMMU: Domain %u has no page table ops\n", domain->domain_id);
		return 0;
	}

	/* Unmap pages using io-pgtable */
	unmapped = ops->unmap_pages(ops, iova, pgsize, pgcount, gather);
	if (unmapped != pgcount * pgsize) {
		hyp_err("SMMU: Partial unmap at IOVA 0x%lx (requested=%zu, unmapped=%zu)\n",
			iova, pgcount * pgsize, unmapped);
	}

	return unmapped;
}

/**
 * smmu_v2_iova_to_phys - Translate IOVA to physical address
 * @domain: Domain to perform translation in
 * @iova: I/O virtual address
 *
 * Returns: Physical address, or 0 if not mapped
 */
phys_addr_t smmu_v2_iova_to_phys(struct kvm_hyp_iommu_domain *domain, unsigned long iova)
{
	struct smmu_v2_domain *smmu_domain = domain->priv;
	struct io_pgtable_ops *ops;
	phys_addr_t paddr;

	if (!smmu_domain) {
		hyp_err("SMMU: Domain %u has no private data\n", domain->domain_id);
		return 0;
	}

	ops = smmu_domain->pgtbl_ops;
	if (!ops || !ops->iova_to_phys) {
		hyp_err("SMMU: Domain %u has no page table ops\n", domain->domain_id);
		return 0;
	}

	/* Translate using io-pgtable */
	paddr = ops->iova_to_phys(ops, iova);

	return paddr;
}

/**
 * smmu_v2_iotlb_sync - Synchronize TLB invalidations
 * @domain: Domain to sync TLB for
 * @gather: TLB gather structure (contains invalidation info)
 *
 * Performs TLB invalidation for all entries modified since the last sync.
 * For SMMUv2, we invalidate the entire context bank's TLB for simplicity.
 */
void smmu_v2_iotlb_sync(struct kvm_hyp_iommu_domain *domain, struct iommu_iotlb_gather *gather)
{
	struct smmu_v2_domain *smmu_domain = domain->priv;
	struct hyp_arm_smmu_v2_device *smmu;
	u8 cb_idx;

	if (!smmu_domain) {
		hyp_err("SMMU: Domain %u has no private data\n", domain->domain_id);
		return;
	}

	smmu = smmu_domain->smmu;
	cb_idx = smmu_domain->cb_idx;

	/* Invalidate TLB for this context bank */
	smmu_v2_tlb_inv_context(smmu, cb_idx);
}

/*
 * Host Stage-2 Identity Mapping
 */

/**
 * smmu_v2_pgsize_idmap - Select optimal page size for identity mapping
 * @size: Size of region to map
 * @paddr: Physical address to map
 * @pgsize_bitmap: Bitmap of supported page sizes
 *
 * Returns the largest page size that:
 * 1. Fits within the remaining size
 * 2. The address is aligned to
 * 3. Is supported by the page table
 */
static size_t smmu_v2_pgsize_idmap(size_t size, u64 paddr, size_t pgsize_bitmap)
{
	size_t pgsizes;

	/* Remove page sizes that are larger than the current size */
	pgsizes = pgsize_bitmap & GENMASK_ULL(__fls(size), 0);

	/* Remove page sizes that the address is not aligned to */
	if (likely(paddr))
		pgsizes &= GENMASK_ULL(__ffs(paddr), 0);

	/* Return the largest page size that fits */
	return pgsizes ? BIT(__fls(pgsizes)) : PAGE_SIZE;
}

/**
 * smmu_v2_host_stage2_idmap - Identity-map region in host stage-2 page tables
 * @start: Start physical address
 * @end: End physical address
 * @prot: Protection flags
 *
 * This is called during host stage-2 snapshot to map memory regions into
 * the global identity page table used by all SMMU domains.
 *
 * For memory regions: Uses 4K pages only (Tegra234 walk cache errata)
 * For MMIO regions: Uses largest block mappings to save page table memory
 *
 * Note: io-pgtable may return partial completions. We loop until all bytes
 * are mapped, matching the SMMUv3 pKVM implementation pattern.
 */
static void smmu_v2_host_stage2_idmap(phys_addr_t start, phys_addr_t end, int prot)
{
	struct io_pgtable_ops *ops;
	size_t size = end - start;
	size_t pgsize, pgcount;
	size_t mapped;
	int ret;

	if (!idmap_pgtable) {
		hyp_err("SMMU: Global page table not initialized\n");
		return;
	}

	ops = &idmap_pgtable->ops;

	/*
	 * Map in a loop - io-pgtable may return partial completions.
	 * This matches the SMMUv3 pKVM implementation pattern.
	 */
	while (size) {
		mapped = 0;

		/*
		 * Page size selection:
		 * - Memory: 4K pages only (Tegra234 walk cache errata)
		 * - MMIO: Largest block mappings (saves page table memory,
		 *         MMIO is never donated so no split_block issues)
		 */
		if (prot & IOMMU_MMIO)
			pgsize = smmu_v2_pgsize_idmap(size, start,
						     idmap_pgtable->cfg.pgsize_bitmap);
		else
			pgsize = SZ_4K;

		pgcount = size / pgsize;

		ret = ops->map_pages(ops, start, start, pgsize, pgcount,
				     prot, GFP_KERNEL, &mapped);
		if (ret || !mapped) {
			/*
			 * Mapping failed - this can happen if page table
			 * memory is exhausted. Silent return matches SMMUv3.
			 */
			return;
		}

		size -= mapped;
		start += mapped;
	}
}

/**
 * smmu_v2_dabt_handler - Data abort handler for SMMU MMIO accesses
 * @regs: CPU register state
 * @esr: Exception Syndrome Register value
 * @addr: Faulting address
 *
 * Wrapper around smmu_v2_mmio_handler that matches the kvm_iommu_ops signature.
 * Handles MMIO emulation for host accesses to SMMU registers.
 *
 * Returns: true if handled, false otherwise
 */
static bool smmu_v2_dabt_handler(struct user_pt_regs *regs, u64 esr, u64 addr)
{
	bool is_write = esr & ESR_ELx_WNR;
	/*
	 * Extract the source/destination register (Rt) from ESR for data aborts.
	 * Data aborts encode Rt in ESR bits [20:16] (ESR_ELx_SRT_SHIFT=16).
	 */
	u32 rt = (esr >> ESR_ELx_SRT_SHIFT) & 0x1f;
	u64 val = 0;
	bool handled;

	/* Read value from register if write */
	if (is_write)
		val = regs->regs[rt];

	/* Try SMMU MMIO handler first */
	handled = smmu_v2_mmio_handler(addr, is_write, &val);

	/* If not SMMU, try platform-specific MMIO handler (e.g., Tegra MC) */
	if (!handled && platform_hooks && platform_hooks->mmio_handler)
		handled = platform_hooks->mmio_handler(addr, is_write, &val);

	if (handled) {
		/* Write result to register if read */
		if (!is_write)
			regs->regs[rt] = val;

		/* Advance PC to next instruction */
		regs->pc += 4;
	}

	return handled;
}

#ifdef CONFIG_ARM_SMMU_V2_PKVM_DEBUGFS
static int smmu_v2_debug(pkvm_handle_t smmu_id, enum kvm_iommu_debug_ops op, void *out,
			 size_t out_sz)
{
	struct hyp_arm_smmu_v2_device *smmu;
	int ret;

	if (smmu_id >= kvm_hyp_arm_smmu_v2_count) {
		hyp_err("SMMU: Invalid smmu_id %u (max %zu)\n", smmu_id,
			kvm_hyp_arm_smmu_v2_count - 1);
		return -EINVAL;
	}

	smmu = &kvm_hyp_arm_smmu_v2_smmus[smmu_id];

	ret = hyp_pin_shared_mem(out, out + out_sz);
	if (ret) {
		hyp_err("SMMU: Failed to pin shared memory\n");
		return ret;
	}

	switch(op)
	{
	case PKVM_IOMMU_DEBUG_EXPORT_DEVICE:
		if (out_sz < sizeof(*smmu)) {
			ret = -ENOMEM;
			break;
		}

		memcpy(out, smmu, offsetof(struct hyp_arm_smmu_v2_device, smrs_shadow));
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	hyp_unpin_shared_mem(out, out + out_sz);
	return ret;
}
#endif

/*
 * IOMMU Operations Structure
 *
 * NOTE: Like SMMUv3 pKVM, we only implement init, host_stage2_idmap, and
 * dabt_handler. Per-domain page table operations (map_pages, unmap_pages,
 * alloc_domain, etc.) are NOT implemented at EL2.
 *
 * The global identity-mapped page table (idmap_pgtable) is populated during
 * host_stage2_idmap() with IOVA=PA mappings. EL2 enforces Stage-2 translation.
 */
struct kvm_iommu_ops smmu_v2_ops = {
	.init			= smmu_v2_global_init,
	.host_stage2_idmap	= smmu_v2_host_stage2_idmap,
	.dabt_handler		= smmu_v2_dabt_handler,
#ifdef CONFIG_ARM_SMMU_V2_PKVM_DEBUGFS
	.debug			= smmu_v2_debug,
#endif
};
