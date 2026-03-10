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
#include <linux/find.h>
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

#define for_each_smmu(smmu) \
	for ((smmu) = kvm_hyp_arm_smmu_v2_smmus; \
	     (smmu) != &kvm_hyp_arm_smmu_v2_smmus[kvm_hyp_arm_smmu_v2_count]; \
	     (smmu)++)

#define DRV_PREFIX "arm-smmu-v2"

#define drv_dbg(fmt, ...)  hyp_dbg(DRV_PREFIX ": " fmt, ##__VA_ARGS__)
#define drv_info(fmt, ...) hyp_info(DRV_PREFIX ": " fmt, ##__VA_ARGS__)
#define drv_err(fmt, ...)  hyp_err(DRV_PREFIX ": " fmt, ##__VA_ARGS__)
#define drv_warn(fmt, ...) hyp_warn(DRV_PREFIX ": " fmt, ##__VA_ARGS__)

#define smmu_dbg(smmu, fmt, ...) \
	hyp_dbg(DRV_PREFIX " %llx.smmu: " fmt, (smmu)->mmio_addr, ##__VA_ARGS__)
#define smmu_info(smmu, fmt, ...) \
	hyp_info(DRV_PREFIX " %llx.smmu: " fmt, (smmu)->mmio_addr, ##__VA_ARGS__)
#define smmu_err(smmu, fmt, ...) \
	hyp_err(DRV_PREFIX " %llx.smmu: " fmt, (smmu)->mmio_addr, ##__VA_ARGS__)
#define smmu_warn(smmu, fmt, ...) \
	hyp_warn(DRV_PREFIX " %llx.smmu: " fmt, (smmu)->mmio_addr, ##__VA_ARGS__)

/* CB 0 is used exclusively by hyp for host stage 2 translation */
#define HOST_S2_CBNDX 0
/* Statically reserved CBs for the hypervisor (so far only host stage 2) */
#define NUM_RESERVED_CB 1

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
		drv_err("smmu_take_pages called with unaligned address/size: phys=%llx size=%lx",
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
 * arm_smmu_id_size_to_bits() - Convert ID register size field to actual bits
 * @size: Size field from ID register (0-7)
 *
 * Return: Actual address size in bits
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
 * smmu_v2_probe_device() - Read SMMU capabilities from hardware
 * @smmu: SMMU device to probe
 *
 * Reads IDR registers to determine capabilities (number of context banks,
 * stream mapping groups, page sizes, coherent walk support, etc.)
 *
 * Return: 0 on success, negative error code on failure
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
	smmu_info(smmu, "numpage=%u (CB pages start at page %u)", smmu->numpage, smmu->numpage);

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

	if (smmu->num_context_banks < NUM_RESERVED_CB) {
		/* Shouldn't really happen but hey... */
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
 * smmu_v2_reset() - Reset and initialize SMMU hardware
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
 * smmu_v2_tlb_flush_walk() - Flush TLB after unmapping non-leaf PTEs
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

	/* Invalidate on ALL SMMU instances (global identity mapping) */
	for_each_smmu(smmu) {
		/* Global TLB invalidation (all VMIDs) */
		smmu_v2_tlb_inv_context(smmu, HOST_S2_CBNDX);
	}
}

/**
 * smmu_v2_tlb_add_page() - Add page to TLB invalidation gather
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
 * smmu_v2_init_pgt() - Initialize global identity-mapped page table
 *
 * Creates a single Stage-2 page table shared by all protected domains.
 * This table mirrors the host's CPU stage-2 mappings for DMA isolation.
 *
 * Return: 0 on success, negative error code on failure
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

	/* Determine common capabilities across all SMMU instances */
	for_each_smmu(smmu) {
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
	drv_info("Allocating page table (ias=%u, oas=%u, pgsize=0x%lx)",
		 cfg.ias, cfg.oas, cfg.pgsize_bitmap);

	ops = kvm_alloc_io_pgtable_ops(ARM_64_LPAE_S2, &cfg, NULL);
	if (!ops) {
		drv_err("Failed to allocate page table ops");
		return -ENOMEM;
	}

	idmap_pgtable = io_pgtable_ops_to_pgtable(ops);
	if (!idmap_pgtable)
		/* This shouldn't happen, but handle it anyway */
		return -ENOMEM;

	return 0;
}

/**
 * smmu_v2_init() - Initialize SMMU device at EL2
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
	size_t nr_pages, pg, state_size;
	void *state_pages;

	/*
	 * Note: UART debugging is provided by pKVM serial framework.
	 * Ensure pkvm-pl011 module is loaded before this driver.
	 */

	drv_info("running smmu_v2_init()");

	/*
	 * Shadow arrays are NULL initially (not allocated by EL1).
	 * We'll allocate them from hyp memory pool after probing hardware.
	 */

	/* Skip invalid SMMU instances (not populated by EL1) */
	if (!smmu->mmio_addr || !smmu->mmio_size) {
		smmu_info(smmu, "Skipping - invalid configuration (PA=0x%llx, size=0x%zx)",
			  smmu->mmio_addr, smmu->mmio_size);
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
			smmu_err(smmu, "Failed to donate MMIO page %zu at pfn 0x%llx (ret=%d)",
				 pg, pfn, ret);
			return ret;
		}
	}

	/* Get EL2 VA from hyp linear map (pages already mapped after donation) */
	smmu->base = hyp_phys_to_virt(smmu->mmio_addr);
	smmu_info(smmu, "Donated MMIO: PA 0x%llx -> VA 0x%p, size=0x%lx (%zu pages)",
		  smmu->mmio_addr, smmu->base, smmu->mmio_size, nr_pages);

	/* Donate secondary MMIO base if present (Tegra234 dual-base instances) */
	if (smmu->has_secondary_base && smmu->mmio_addr_sec) {
		nr_pages = smmu->mmio_size >> PAGE_SHIFT;
		for (pg = 0; pg < nr_pages; pg++) {
			u64 pfn = (smmu->mmio_addr_sec >> PAGE_SHIFT) + pg;

			ret = ___pkvm_host_donate_hyp(pfn, 1, true);
			if (ret) {
				smmu_err(smmu,
					 "Failed to donate secondary MMIO page %zu at pfn 0x%llx (ret=%d)",
					 pg, pfn, ret);
				return ret;
			}
		}

		smmu->base_sec = hyp_phys_to_virt(smmu->mmio_addr_sec);
		smmu_info(smmu, "Donated secondary MMIO: PA 0x%llx -> VA 0x%p",
			  smmu->mmio_addr_sec, smmu->base_sec);
	}

	hyp_spin_lock_init(&smmu->lock);

	/* Probe hardware capabilities */
	ret = smmu_v2_probe_device(smmu);
	if (ret)
		return ret;

	/* Now that we have num mapping groups, and CBs, calculate shadow state size */
	state_size = smmu_shadow_state_size(smmu);

	/* Allocate shadow state from hyp memory pool */
	state_pages = kvm_iommu_donate_pages_atomic(get_order(state_size));
	if (!state_pages) {
		smmu_err(smmu, "Failed to allocate structures (%zu bytes)", state_size);
		return -ENOMEM;
	}

	memset(state_pages, 0, state_size);
	smmu_shadow_state_from_pages(smmu, state_pages);

	/* Pre-allocate hyp-reserved CBs; we know for sure we'll need them */
	bitmap_set(smmu->cb_bitmap, 0, NUM_RESERVED_CB);

	/* Initialize host mappings (all inactive) */
	memset(smmu->host_cb_map, ARM_SMMU_INVALID_CB,
	       smmu->num_context_banks * sizeof(smmu->host_cb_map[0]));
	memset(smmu->host_sme_map, ARM_SMMU_INVALID_SME,
	       smmu->num_mapping_groups * sizeof(smmu->host_sme_map[0]));

	/* Initialize stream mapping arrays to invalid/fault state */
	for (i = 0; i < smmu->num_mapping_groups; i++) {
		/*
		 * Bypass mode by default to preserve bootloader mappings.
		 * This allows devices initialized by firmware (display, etc.) to
		 * continue working until they get properly attached to domains.
		 */
		smmu->s2crs[i].type = S2CR_TYPE_BYPASS;
		smmu->s2crs[i].bypass = true;
	}

	/* Reset and configure hardware */
	ret = smmu_v2_reset(smmu);
	if (ret)
		return ret;

	return 0;
}

/*
 * Context Bank Management
 */

/**
 * smmu_v2_alloc_cb() - Allocate a free context bank
 * @smmu: SMMU device
 *
 * Return: Context bank index, or ARM_SMMU_INVALID_CB if none available
 */
static u8 smmu_v2_alloc_cb(struct hyp_arm_smmu_v2_device *smmu)
{
	u32 cb_idx;

	hyp_spin_lock(&smmu->lock);

	cb_idx = find_next_zero_bit(smmu->cb_bitmap, smmu->num_context_banks, NUM_RESERVED_CB);
	if (cb_idx == smmu->num_context_banks)
		cb_idx = ARM_SMMU_INVALID_CB;
	else
		bitmap_set(smmu->cb_bitmap, cb_idx, 1);

	hyp_spin_unlock(&smmu->lock);
	return cb_idx;
}

/**
 * smmu_v2_free_cb() - Free a context bank
 * @smmu: SMMU device
 * @cb_idx: Actual hardware context bank index
 */
static void smmu_v2_free_cb(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx)
{
	if (cb_idx < NUM_RESERVED_CB || cb_idx >= smmu->num_context_banks)
		return;

	hyp_spin_lock(&smmu->lock);
	bitmap_clear(smmu->cb_bitmap, cb_idx, 1);
	hyp_spin_unlock(&smmu->lock);
}

/**
 * smmu_v2_map_host_cb() - Get or allocate a new context bank for the host
 * @smmu: SMMU device
 * @cb_idx_host: The index that the host thinks this context bank will be in.
 *
 * Return: Actual hardware context bank index, or ARM_SMMU_INVALID_CB if none available
 *         or invalid @cb_idx_host argument was provided.
 */
static u8 smmu_v2_map_host_cb(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx_host)
{
	u8 cb_idx;

	if (cb_idx_host >= smmu->num_context_banks)
		return ARM_SMMU_INVALID_CB;

	cb_idx = smmu->host_cb_map[cb_idx_host];
	if (cb_idx == ARM_SMMU_INVALID_CB) {
		cb_idx = smmu_v2_alloc_cb(smmu);
		if (cb_idx != ARM_SMMU_INVALID_CB)
			smmu->host_cb_map[cb_idx_host] = cb_idx;
	}

	return cb_idx;
}

/**
 * smmu_v2_unmap_host_cb() - Unmap and free a context bank of the host
 * @smmu: SMMU device
 * @cb_idx_host: Context bank index used by the
 */
static void smmu_v2_unmap_host_cb(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx_host)
{
	u8 cb_idx;

	if (cb_idx_host >= smmu->num_context_banks)
		return;

	cb_idx = smmu->host_cb_map[cb_idx_host];
	smmu->host_cb_map[cb_idx_host] = ARM_SMMU_INVALID_CB;
	smmu_v2_free_cb(smmu, cb_idx);
}

/**
 * smmu_v2_find_host_cb_idx() - Given a hardware CB index, find the host index
 * @smmu: SMMU device
 * @cb_idx: The index that the host thinks this context bank will be in.
 *
 * Return: Host context bank index, or ARM_SMMU_INVALID_CB if not found.
 */
static u8 smmu_v2_find_host_cb_idx(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx)
{
	u8 cb_idx_host;

	for (cb_idx_host = 0; cb_idx_host < smmu->num_context_banks; cb_idx_host++) {
		if (smmu->host_cb_map[cb_idx_host] == cb_idx)
			return cb_idx_host;
	}

	return ARM_SMMU_INVALID_CB;
}

/**
 * smmu_v2_cleanup_host_cbs() - Finds unused CBs by host, and unmaps thems
 * @smmu: SMMU device
 */
static void smmu_v2_cleanup_host_cbs(struct hyp_arm_smmu_v2_device *smmu)
{
	u8 cb_idx, cb_idx_host;

	for (cb_idx_host = 0; cb_idx_host < smmu->num_context_banks; cb_idx_host++) {
		cb_idx = smmu->host_cb_map[cb_idx_host];
		if (cb_idx == ARM_SMMU_INVALID_CB || smmu->cb_state[cb_idx].sctlr)
			continue;

		smmu_v2_unmap_host_cb(smmu, cb_idx_host);
	}
}

/**
 * smmu_v2_init_s2_cb() - Configure a stage 2 context bank for a domain
 * @smmu: SMMU device
 * @pgt: Stage-2 page table to use
 * @cb_idx: Context bank index
 *
 * Programs CBAR, TTBR, TCR, and other CB registers for Stage-2 translation.
 * Uses the specified stage 2 page table. Does not check context bank
 * availability (cb_bitmap) or reserved status; context bank should be allocated
 * before calling this function.
 */
static int smmu_v2_init_s2_cb(struct hyp_arm_smmu_v2_device *smmu, struct io_pgtable *pgt,
			      u8 cb_idx)
{
	struct smmu_v2_cb_state *cb;
	struct io_pgtable_cfg *pgt_cfg;
	u32 cbar, tcr, sctlr, cb_page;
	u64 ttbr;

	if (WARN_ON(!pgt))
		return -EINVAL;

	pgt_cfg = &pgt->cfg;

	if (cb_idx >= smmu->num_context_banks)
		return -EINVAL;

	cb = &smmu->cb_state[cb_idx];

	/* Calculate CB page offset: context banks start at page numpage */
	cb_page = (cb_idx + smmu->numpage) << smmu->pgshift;

	/* 1. Configure CBAR (Context Bank Attribute Register) for Stage-2 only */
	cbar = FIELD_PREP(ARM_SMMU_CBAR_TYPE, CBAR_TYPE_S2_TRANS);
	cbar |= FIELD_PREP(ARM_SMMU_CBAR_VMID, 0);  /* VMID = 0 (global identity mapping) */
	smmu_writel(smmu, ARM_SMMU_GR1, ARM_SMMU_GR1_CBAR(cb_idx), cbar);

	/* Configure CBA2R (extended attributes) for 64-bit addressing */
	smmu_writel(smmu, ARM_SMMU_GR1, ARM_SMMU_GR1_CBA2R(cb_idx), ARM_SMMU_CBA2R_VA64);

	/* 2. Program TCR via VTCR provided by Stage-2 page table */
	tcr = FIELD_PREP(ARM_SMMU_VTCR_PS, pgt_cfg->arm_lpae_s2_cfg.vtcr.ps) |
	      FIELD_PREP(ARM_SMMU_VTCR_TG0, pgt_cfg->arm_lpae_s2_cfg.vtcr.tg) |
	      FIELD_PREP(ARM_SMMU_VTCR_SH0, pgt_cfg->arm_lpae_s2_cfg.vtcr.sh) |
	      FIELD_PREP(ARM_SMMU_VTCR_ORGN0, pgt_cfg->arm_lpae_s2_cfg.vtcr.orgn) |
	      FIELD_PREP(ARM_SMMU_VTCR_IRGN0, pgt_cfg->arm_lpae_s2_cfg.vtcr.irgn) |
	      FIELD_PREP(ARM_SMMU_VTCR_SL0, pgt_cfg->arm_lpae_s2_cfg.vtcr.sl) |
	      FIELD_PREP(ARM_SMMU_VTCR_T0SZ, pgt_cfg->arm_lpae_s2_cfg.vtcr.tsz);
	smmu_writel(smmu, cb_page, ARM_SMMU_CB_TCR, tcr);

	/* 3. Write TTBR with Stage-2 page table base address */
	ttbr = pgt_cfg->arm_lpae_s2_cfg.vttbr;
	smmu_writeq(smmu, cb_page, ARM_SMMU_CB_TTBR0, ttbr);

	/* 4. Enable translation by setting SCTLR.M bit */
	sctlr = ARM_SMMU_SCTLR_M;        /* Enable MMU */
	sctlr |= ARM_SMMU_SCTLR_TRE;     /* TEX remap enable */
	sctlr |= ARM_SMMU_SCTLR_AFE;     /* Access flag enable */
	sctlr |= ARM_SMMU_SCTLR_CFIE;    /* Context fault interrupt enable */
	sctlr |= ARM_SMMU_SCTLR_CFRE;    /* Context fault report enable */
	smmu_writel(smmu, cb_page, ARM_SMMU_CB_SCTLR, sctlr);

	/* Update CB state tracking */
	cb->domain_id = 0; /* Not used atm */
	cb->cbar = cbar;
	cb->tcr[0] = tcr;
	cb->ttbr[0] = ttbr;
	cb->sctlr = sctlr;
	cb->vmid = 0; /* Not used atm */
	return 0;
}

/*
 * MMIO Emulation
 */

/**
 * smmu_v2_handle_gr0() - Handle GR0 register access
 * @smmu: SMMU device
 * @offset: Register offset within GR0 page
 * @is_write: true for write access, false for read
 * @val: Pointer to value (read or write)
 *
 * Emulates GR0 (Global Register page 0) accesses with shadow state management.
 * Key register types:
 * - ID registers (IDR0-IDR7): Read-only capability reporting
 * - sCR0: Global control (enable/disable, fault reporting)
 * - SMR: Stream match configuration
 * - S2CR: Stream-to-context mapping (enforces Stage-2)
 * - TLB operations: Wire to existing TLB implementations
 */
int smmu_v2_handle_gr0(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		       bool is_write, u64 *val)
{
	u32 val32;
	u8 cb_idx, cb_idx_host;

	/* ID registers - read-only capability reporting */
	if (offset >= ARM_SMMU_GR0_ID0 && offset <= ARM_SMMU_GR0_ID7) {
		if (is_write)
			return -EINVAL;  /* Read-only */

		/* Pass through most of the hardware capabilities */
		*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);

		if (offset == ARM_SMMU_GR0_ID0) {
			val32 = (u32)*val;

			/* Don't advertise stage-2 or nesting capabilities */
			val32 &= ~(ARM_SMMU_ID0_S2TS | ARM_SMMU_ID0_NTS);
			*val = val32;
		} else if (offset == ARM_SMMU_GR0_ID1) {
			val32 = (u32)*val;

			/*
			 * Subtract the reserved context banks from NUMCB.
			 * These will be owned by the hypervisor
			 */
			val32 &= ~ARM_SMMU_ID1_NUMCB;
			val32 |= FIELD_PREP(ARM_SMMU_ID1_NUMCB,
				            smmu->num_context_banks - NUM_RESERVED_CB);
			*val = val32;
		}
		return 0;
	}

	/* sCR0 - Global control register */
	if (offset == ARM_SMMU_GR0_sCR0) {
		if (is_write) {
			val32 = (u32)*val;

			if (val32 & ARM_SMMU_sCR0_CLIENTPD) {
				/* Can't let host bypass translation globally */
				val32 &= ~ARM_SMMU_sCR0_CLIENTPD;
			} else {
				/*
				 * Writing to sCR0 is the epilogue of the reset sequence. Right
				 * before that (also part of the reset sequence), the host accesses
				 * all CBs' SCTLR (writes 0). This causes our host_cb_map to be
				 * fully populated. Clean up here.
				 */
				smmu_v2_cleanup_host_cbs(smmu);
			}

			/*
			 * Enforce USFCFG=1: unmapped streams must fault, not bypass.
			 * This is a security requirement - we cannot let the host
			 * allow arbitrary streams to bypass SMMU translation.
			 */
			val32 |= ARM_SMMU_sCR0_USFCFG;

			/*
			 * Do not let conflicting matches bypass the SMMU
			 */
			val32 |= ARM_SMMU_sCR0_SMCFCFG;

			/* Always keep fault reporting enabled */
			val32 |= (ARM_SMMU_sCR0_GFRE | ARM_SMMU_sCR0_GFIE |
				  ARM_SMMU_sCR0_GCFGFRE | ARM_SMMU_sCR0_GCFGFIE);

			/* Always keep VMID partitioning enabled for nesting */
			if (smmu->features & ARM_SMMU_FEAT_TRANS_NESTED)
				val32 |= ARM_SMMU_sCR0_VMIDPNE;

			smmu_writel(smmu, ARM_SMMU_GR0, offset, val32);
		} else {
			*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
		}
		return 0;
	}

	/* Global fault status/syndrome registers - read/clear */
	if (offset == ARM_SMMU_GR0_sGFSR) {
		if (is_write) {
			/* Write-1-to-clear */
			smmu_writel(smmu, ARM_SMMU_GR0, offset, (u32)*val);
		} else {
			*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
		}
		return 0;
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
		return smmu_v2_tlb_sync_global(smmu);
	}

	if (offset == ARM_SMMU_GR0_TLBIALLNSNH || offset == ARM_SMMU_GR0_TLBIALLH) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		/* Global TLB invalidation */
		smmu_writel(smmu, ARM_SMMU_GR0, offset, 0);
		return smmu_v2_tlb_sync_global(smmu);
	}

	if (offset == ARM_SMMU_GR0_sTLBGSYNC) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		/* Host requested TLB sync, execute it */
		return smmu_v2_tlb_sync_global(smmu);
	}

	if (offset == ARM_SMMU_GR0_sTLBGSTATUS) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
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

			/* Update shadow state */
			smmu->smrs[idx].valid = !!(val32 & ARM_SMMU_SMR_VALID);
			smmu->smrs[idx].mask = FIELD_GET(ARM_SMMU_SMR_MASK, val32);
			smmu->smrs[idx].id = FIELD_GET(ARM_SMMU_SMR_ID, val32);

			/* Write through to hardware (no modification needed for SMR) */
			smmu_writel(smmu, ARM_SMMU_GR0, offset, val32);
		} else {
			/* Return shadow state */
			val32 = 0;
			if (smmu->smrs[idx].valid)
				val32 |= ARM_SMMU_SMR_VALID;
			val32 |= FIELD_PREP(ARM_SMMU_SMR_MASK, smmu->smrs[idx].mask);
			val32 |= FIELD_PREP(ARM_SMMU_SMR_ID, smmu->smrs[idx].id);
			*val = val32;
		}
		return 0;
	}

	/* S2CR registers - stream-to-context mapping (shadow + enforce Stage-2) */
	if (offset >= ARM_SMMU_GR0_S2CR(0) &&
	    offset < ARM_SMMU_GR0_S2CR(0) + (smmu->num_mapping_groups * 4)) {
		u32 idx = (offset - ARM_SMMU_GR0_S2CR(0)) >> 2;
		if (idx >= smmu->num_mapping_groups)
			return -EINVAL;

		if (is_write) {
			val32 = (u32)*val;

			/* Map the context bank index to actual hardware CB */
			cb_idx_host = FIELD_GET(ARM_SMMU_S2CR_CBNDX, val32);
			cb_idx = smmu_v2_map_host_cb(smmu, cb_idx_host);
			if (cb_idx == ARM_SMMU_INVALID_CB)
				/* Means we ran out of CBs */
				return -EINVAL;

			/* Correct it in S2CR */
			val32 &= ~ARM_SMMU_S2CR_CBNDX;
			val32 |= FIELD_PREP(ARM_SMMU_S2CR_CBNDX, cb_idx);

			/* Update shadow state */
			smmu->s2crs[idx].type = FIELD_GET(ARM_SMMU_S2CR_TYPE, val32);
			smmu->s2crs[idx].cbndx = FIELD_GET(ARM_SMMU_S2CR_CBNDX, val32);
			smmu->s2crs[idx].privcfg = FIELD_GET(ARM_SMMU_S2CR_PRIVCFG, val32);
			smmu->s2crs[idx].bypass = (smmu->s2crs[idx].type == S2CR_TYPE_BYPASS);

			/* We don't allow bypass */
			if (smmu->s2crs[idx].type == S2CR_TYPE_BYPASS) {
				val32 &= ~ARM_SMMU_S2CR_TYPE;
				val32 |= FIELD_PREP(ARM_SMMU_S2CR_TYPE, S2CR_TYPE_FAULT);

				/* And let s2crs[idx].bypass indicate that we modified this */
				smmu->s2crs[idx].type = FIELD_GET(ARM_SMMU_S2CR_TYPE, val32);
			}

			/* Write to hardware */
			smmu_writel(smmu, ARM_SMMU_GR0, offset, val32);
		} else {
			/* Return shadow state; let the host think this is set to bypass */
			if (smmu->s2crs[idx].bypass)
				val32 = FIELD_PREP(ARM_SMMU_S2CR_TYPE, S2CR_TYPE_BYPASS);
			else
				val32 = FIELD_PREP(ARM_SMMU_S2CR_TYPE, smmu->s2crs[idx].type);

			/* Map actual hardware CB index back to host index */
			cb_idx = FIELD_PREP(ARM_SMMU_S2CR_CBNDX, smmu->s2crs[idx].cbndx);
			cb_idx_host = smmu_v2_find_host_cb_idx(smmu, cb_idx);

			val32 |= FIELD_PREP(ARM_SMMU_S2CR_CBNDX, cb_idx_host);
			val32 |= FIELD_PREP(ARM_SMMU_S2CR_PRIVCFG, smmu->s2crs[idx].privcfg);
			*val = val32;
		}
		return 0;
	}

	/* Unknown or unsupported register */
	return -EINVAL;
}

/**
 * smmu_v2_handle_gr1() - Handle GR1 register access
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
	u8 cbar_type;
	u8 cb_idx_host, cb_idx;
	int cbreg_idx; /* 0: CBAR, 1: CBA2R, 2: FSYNRA */
	u32 cbreg_base[3] = {
		ARM_SMMU_GR1_CBAR(0),
		ARM_SMMU_GR1_CBA2R(0),
		ARM_SMMU_GR1_CBFRSYNRA(0)
	};

	/* Find out which CB register it's trying to access */
	for (cbreg_idx = 0; cbreg_idx < 3; cbreg_idx++) {
		if (offset < cbreg_base[cbreg_idx] ||
		    offset >= cbreg_base[cbreg_idx] + smmu->num_context_banks * 4)
			continue;

		cb_idx_host = (offset - cbreg_base[cbreg_idx]) >> 2;
		if (cb_idx_host >= smmu->num_context_banks)
			return -EINVAL;

		cb_idx = smmu_v2_map_host_cb(smmu, cb_idx_host);

		/* Ran out of CBs; not sure what's best here, -EINVAL or 0 */
		if (cb_idx == ARM_SMMU_INVALID_CB) {
			*val = 0;
			return 0;
		}

		offset = cbreg_base[cbreg_idx] + cb_idx * 4;
		break;
	}

	if (cbreg_idx == 0) {
		/* CBAR registers - context bank attributes */
		if (is_write) {
			val32 = (u32)*val;
			cbar_type = FIELD_GET(ARM_SMMU_CBAR_TYPE, val32);

			/* We don't allow or advertise support for this; bail out */
			if (cbar_type == CBAR_TYPE_S2_TRANS ||
			    cbar_type == CBAR_TYPE_S1_TRANS_S2_TRANS)
				return -EINVAL;

			/* Force it through a stage 2 translation */
			if (cbar_type == CBAR_TYPE_S1_TRANS_S2_BYPASS) {
				val32 &= ~ARM_SMMU_CBAR_TYPE;
				val32 |= FIELD_PREP(ARM_SMMU_CBAR_TYPE, CBAR_TYPE_S1_TRANS_S2_TRANS);

				/* masks the MemAttr too; should be ok */
				val32 &= ~ARM_SMMU_CBAR_S1_CBNDX;
				val32 |= FIELD_PREP(ARM_SMMU_CBAR_S1_CBNDX, HOST_S2_CBNDX);
			}

			/* Store in CB state for tracking */
			smmu->cb_state[cb_idx].cbar = val32;

			/* Write to hardware */
			smmu_writel(smmu, ARM_SMMU_GR1, offset, val32);
		} else {
			/* Return current CB state */
			val32 = smmu_readl(smmu, ARM_SMMU_GR1, offset);

			/* Undo override above during write */
			cbar_type = FIELD_GET(ARM_SMMU_CBAR_TYPE, val32);
			if (cbar_type == CBAR_TYPE_S1_TRANS_S2_TRANS) {
				val32 &= ~ARM_SMMU_CBAR_TYPE;
				val32 |= FIELD_PREP(ARM_SMMU_CBAR_TYPE, CBAR_TYPE_S1_TRANS_S2_BYPASS);
			}

			*val = val32;
		}
		return 0;
	} else if (cbreg_idx == 1) {
		/* CBA2R registers - extended attributes */
		if (is_write) {
			val32 = (u32)*val;

			/* Allow all CBA2R fields (VA64, VMID16) */
			smmu_writel(smmu, ARM_SMMU_GR1, offset, val32);

			/* Track VMID for this CB (needed for TLB ops) */
			if (smmu->features & ARM_SMMU_FEAT_VMID16) {
				u16 vmid = FIELD_GET(ARM_SMMU_CBA2R_VMID16, val32);
				smmu->cb_state[cb_idx].vmid = vmid;
			}
		} else {
			*val = smmu_readl(smmu, ARM_SMMU_GR1, offset);
		}
		return 0;
	} else if (cbreg_idx == 2) {
		/* CBFRSYNRA registers - fault syndrome auxiliary (read-only) */
		if (is_write)
			return -EINVAL;  /* Read-only */

		*val = smmu_readl(smmu, ARM_SMMU_GR1, offset);
		return 0;
	}

	/* Unknown or unsupported register */
	return -EINVAL;
}

/**
 * smmu_v2_handle_cb() - Handle context bank register access
 * @smmu: SMMU device
 * @offset: Register offset (CB page + offset within CB)
 * @is_write: true for write access, false for read
 * @val: Pointer to value (read or write)
 *
 * Emulates context bank register accesses for translation control.
 * Key register types:
 * - SCTLR: System control (MMU enable, fault handling)
 * - TTBR: Translation table base registers
 * - TCR/TCR2: Translation control registers
 * - MAIR: Memory attribute indirection registers
 * - FSR/FAR/FSYNR0: Fault status and address registers
 * - TLBSYNC/TLBSTATUS: Per-CB TLB synchronization
 */
int smmu_v2_handle_cb(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
		      bool is_write, u64 *val)
{
	u32 page_offset, cb_base, cb_offset;
	u8 cb_idx_host, cb_idx;
	u32 val32;
	u64 val64;

	/* Calculate which CB this is */
	page_offset = offset >> smmu->pgshift;
	if (page_offset < smmu->numpage)
		return -EINVAL;  /* Pages 0 to numpage-1 are GR0/GR1 */

	cb_idx_host = page_offset - smmu->numpage;
	if (cb_idx_host >= smmu->num_context_banks)
		return -EINVAL;

	cb_idx = smmu_v2_map_host_cb(smmu, cb_idx_host);

	/* Ran out of CBs; not sure what's best here, -EINVAL or 0 */
	if (cb_idx == ARM_SMMU_INVALID_CB) {
		*val = 0;
		return 0;
	}

	/* Map these back to actual hardware */
	page_offset = cb_idx + smmu->numpage;
	cb_offset = offset & ((1 << smmu->pgshift) - 1);
	cb_base = page_offset << smmu->pgshift;
	offset = cb_base | cb_offset;

	/* SCTLR - System Control Register */
	if (cb_offset == ARM_SMMU_CB_SCTLR) {
		if (is_write) {
			val32 = (u32)*val;

			if (!val32 && smmu->cb_state[cb_idx].sctlr) {
				/*
				 * Host is destroying a context; unmap it. Checking for !val32
				 * alone is not sufficient as the host writes 0 also during
				 * reset (when our shadow sctlr is also 0).
				 */
				smmu_v2_unmap_host_cb(smmu, cb_idx_host);
			}

			/* Store in shadow state */
			smmu->cb_state[cb_idx].sctlr = val32;

			/* Write to hardware */
			smmu_writel(smmu, cb_base, cb_offset, val32);
		} else {
			*val = smmu_readl(smmu, cb_base, cb_offset);
		}
		return 0;
	}

	/* TCR - Translation Control Register (Stage-1) */
	if (cb_offset == ARM_SMMU_CB_TCR) {
		if (is_write) {
			val32 = (u32)*val;

			/* Store in shadow state */
			smmu->cb_state[cb_idx].tcr[0] = val32;

			/* Write to hardware */
			smmu_writel(smmu, cb_base, cb_offset, val32);
		} else {
			*val = smmu_readl(smmu, cb_base, cb_offset);
		}
		return 0;
	}

	/* TCR2 - Translation Control Register 2 */
	if (cb_offset == ARM_SMMU_CB_TCR2) {
		if (is_write) {
			val32 = (u32)*val;

			/* Store in shadow state */
			smmu->cb_state[cb_idx].tcr[1] = val32;

			/*
			 * For Stage-2-only context banks, TCR2 is not used.
			 * Write through to hardware
			 */
			smmu_writel(smmu, cb_base, cb_offset, val32);
		} else {
			*val = smmu_readl(smmu, cb_base, cb_offset);
		}
		return 0;
	}

	/* TTBR0 - Translation Table Base Register 0 */
	if (cb_offset == ARM_SMMU_CB_TTBR0) {
		if (is_write) {
			val64 = *val;

			smmu->cb_state[cb_idx].ttbr[0] = val64;

			/* Host/bypass domains: write through */
			smmu_writeq(smmu, cb_base, cb_offset, val64);
		} else {
			*val = smmu_readq(smmu, cb_base, cb_offset);
		}
		return 0;
	}

	/* TTBR1 - Translation Table Base Register 1 (Stage-1 second PT) */
	if (cb_offset == ARM_SMMU_CB_TTBR1) {
		if (is_write) {
			val64 = *val;

			smmu->cb_state[cb_idx].ttbr[1] = val64;

			/*
			 * TTBR1 is only used in Stage-1 translation.
			 * For Stage-2-only domains, this is not used.
			 * Write through for host/bypass domains.
			 */
			smmu_writeq(smmu, cb_base, cb_offset, val64);
		} else {
			*val = smmu_readq(smmu, cb_base, cb_offset);
		}
		return 0;
	}

	/* MAIR0 - Memory Attribute Indirection Registers */
	if (cb_offset == ARM_SMMU_CB_S1_MAIR0) {
		if (is_write) {
			val32 = (u32)*val;
			smmu->cb_state[cb_idx].mair[0] = val32;
			smmu_writel(smmu, cb_base, cb_offset, val32);
		} else {
			*val = smmu_readl(smmu, cb_base, cb_offset);
		}
		return 0;
	}

	/* MAIR1 - Memory Attribute Indirection Registers */
	if (cb_offset == ARM_SMMU_CB_S1_MAIR1) {
		if (is_write) {
			val32 = (u32)*val;
			smmu->cb_state[cb_idx].mair[1] = val32;
			smmu_writel(smmu, cb_base, cb_offset, val32);
		} else {
			*val = smmu_readl(smmu, cb_base, cb_offset);
		}
		return 0;
	}

	/* FSR - Fault Status Register (write-1-to-clear) */
	if (cb_offset == ARM_SMMU_CB_FSR) {
		if (is_write) {
			val32 = (u32)*val;
			/* Write-1-to-clear fault status */
			smmu_writel(smmu, cb_base, cb_offset, val32);
		} else {
			*val = smmu_readl(smmu, cb_base, cb_offset);
		}
		return 0;
	}

	/* FAR - Fault Address Register (read-only) */
	if (cb_offset == ARM_SMMU_CB_FAR) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = smmu_readq(smmu, cb_base, cb_offset);
		return 0;
	}

	/* FSYNR0 - Fault Syndrome Register 0 (read-only) */
	if (cb_offset == ARM_SMMU_CB_FSYNR0) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = smmu_readl(smmu, cb_base, cb_offset);
		return 0;
	}

	/* PAR - Physical Address Register (read-only, result of ATS operation) */
	if (cb_offset == ARM_SMMU_CB_PAR) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = smmu_readq(smmu, cb_base, cb_offset);
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

		*val = smmu_readl(smmu, cb_base, cb_offset);
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
		smmu_writeq(smmu, cb_base, cb_offset, val64);
		return smmu_v2_tlb_sync_context(smmu, cb_idx);
	}

	/* S2_TLBIIPAS2 - Stage-2 TLB invalidate by IPA */
	if (cb_offset == ARM_SMMU_CB_S2_TLBIIPAS2) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		val32 = (u32)*val;
		smmu_writel(smmu, cb_base, cb_offset, val32);
		return smmu_v2_tlb_sync_context(smmu, cb_idx);
	}

	/* S2_TLBIIPAS2L - Stage-2 TLB invalidate by IPA (last level only) */
	if (cb_offset == ARM_SMMU_CB_S2_TLBIIPAS2L) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		val32 = (u32)*val;
		smmu_writel(smmu, cb_base, cb_offset, val32);
		return smmu_v2_tlb_sync_context(smmu, cb_idx);
	}

	/* CONTEXTIDR - Context ID Register */
	if (cb_offset == ARM_SMMU_CB_CONTEXTIDR) {
		if (is_write) {
			val32 = (u32)*val;
			smmu_writel(smmu, cb_base, cb_offset, val32);
		} else {
			*val = smmu_readl(smmu, cb_base, cb_offset);
		}
		return 0;
	}

	/* RESUME - Resume processing after stall */
	if (cb_offset == ARM_SMMU_CB_RESUME) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		val32 = (u32)*val;
		smmu_writel(smmu, cb_base, cb_offset, val32);
		return 0;
	}

	/* ACTLR - Auxiliary Control Register */
	if (cb_offset == ARM_SMMU_CB_ACTLR) {
		if (is_write) {
			val32 = (u32)*val;
			smmu_writel(smmu, cb_base, cb_offset, val32);
		} else {
			*val = smmu_readl(smmu, cb_base, cb_offset);
		}
		return 0;
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
		smmu_writeq(smmu, cb_base, cb_offset, val64);
		return 0;
	}

	/* ATSR - Address Translation Status Register (read-only) */
	if (cb_offset == ARM_SMMU_CB_ATSR) {
		if (is_write)
			return -EINVAL;  /* Read-only */

		*val = smmu_readl(smmu, cb_base, cb_offset);
		return 0;
	}

	/* Unknown register - log in case we can emulate it */
	drv_warn("CB[%u] unknown register 0x%x access (%s)",
		 cb_idx, cb_offset, is_write ? "write" : "read");
	return -EINVAL;
}

/**
 * smmu_v2_mmio_handler() - Main MMIO trap handler
 * @addr: Physical address being accessed
 * @is_write: true for write access, false for read
 * @val: Pointer to value (read or write)
 *
 * Called by EL2 MMIO trap infrastructure when host accesses SMMU registers.
 */
bool smmu_v2_mmio_handler(u64 addr, bool is_write, u64 *val)
{
	struct hyp_arm_smmu_v2_device *smmu = NULL;
	struct hyp_arm_smmu_v2_device *smmu_i;
	u32 offset, page;
	int ret;

	for_each_smmu(smmu_i) {
		/* Check primary base */
		if (addr >= smmu_i->mmio_addr && addr < smmu_i->mmio_addr + smmu_i->mmio_size) {
			smmu = smmu_i;
			break;
		}

		/* Check secondary base. Return true if match, we do all the duplication anyways */
		if (smmu_i->has_secondary_base &&
		    addr >= smmu_i->mmio_addr_sec &&
		    addr < smmu_i->mmio_addr_sec + smmu_i->mmio_size)
			return true;
	}

	if (smmu == NULL)
		return false;

	offset = addr - smmu->mmio_addr;
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

/**
 * smmu_v2_global_init() - Global initialization for all SMMU instances
 *
 * Called once during hypervisor initialization to set up all SMMU devices
 * and create the global identity-mapped page table.
 *
 * This should be called from the kvm_iommu_ops->init() callback.
 *
 * Return: 0 on success, negative error code on failure
 */
int smmu_v2_global_init(pkvm_handle_t drv_id)
{
	struct hyp_arm_smmu_v2_device *smmu;
	int ret;

#ifdef CONFIG_TEGRA_MC_PKVM
	/* Register Tegra MC platform hooks for SID override validation */
	tegra234_mc_register_hooks();
#endif

	drv_info("Starting global initialization");

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
			drv_err("Failed to donate SMMU array memory (ret=%d)", ret);
			return ret;
		}

		drv_info("Donated SMMU array: %zu bytes for %zu instances",
			 smmu_arr_size, kvm_hyp_arm_smmu_v2_count);
	}

	/* Initialize each SMMU instance */
	for_each_smmu(smmu) {
		smmu_info(smmu, "Initializing instance");

		/*
		 * Shadow arrays are NULL initially (not set by EL1).
		 * smmu_v2_init() will allocate them from hyp memory pool.
		 */

		ret = smmu_v2_init(smmu);
		if (WARN_ON(ret)) {
			smmu_err(smmu, "Failed to init (ret=%d)", ret);
			return ret;
		}

		smmu_info(smmu, "Initialization complete");
	}

	/* Call platform-specific initialization (e.g., Tegra MC) */
	if (platform_hooks && platform_hooks->init) {
		ret = platform_hooks->init();
		if (ret) {
			drv_err("Platform init failed (ret=%d)", ret);
			return ret;
		}
	}

	/* Initialize global identity-mapped page table (shared by all SMMUs) */
	ret = smmu_v2_init_pgt();
	if (WARN_ON(ret))
		return ret;

	/* Initialize our host stage 2 context bank */
	for_each_smmu(smmu) {
		ret = smmu_v2_init_s2_cb(smmu, idmap_pgtable, HOST_S2_CBNDX);
		if (WARN_ON(ret)) {
			smmu_err(smmu, "Failed to initialize stage 2 context bank (ret=%d)", ret);
			return ret;
		}
	}

	drv_info("Global initialization complete");
	return 0;
}

/*
 * TLB Operations
 */

/**
 * smmu_v2_tlb_sync_global() - Wait for global TLB sync to complete
 * @smmu: SMMU device
 *
 * Return: 0 on success, -ETIMEDOUT on timeout
 */
int smmu_v2_tlb_sync_global(struct hyp_arm_smmu_v2_device *smmu)
{
	u32 val;
	unsigned int timeout = TLB_LOOP_TIMEOUT;

	/* Trigger sync */
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sTLBGSYNC, 0);

	/* Poll for completion with timeout */
	do {
		val = smmu_readl(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sTLBGSTATUS);
		if (!(val & ARM_SMMU_sTLBGSTATUS_GSACTIVE))
			return 0;
	} while (timeout--);

	/* Timeout - hardware error */
	smmu_err(smmu, "Global TLB sync timeout (GSACTIVE still set)");
	return -ETIMEDOUT;
}

/**
 * smmu_v2_tlb_sync_context() - Wait for context TLB sync to complete
 * @smmu: SMMU device
 * @cb_idx: Context bank index
 *
 * Return: 0 on success, -ETIMEDOUT on timeout
 */
int smmu_v2_tlb_sync_context(struct hyp_arm_smmu_v2_device *smmu, u8 cb_idx)
{
	u32 cb_base;
	u32 val;
	unsigned int timeout = TLB_LOOP_TIMEOUT;

	/* Calculate context bank base address */
	cb_base = (cb_idx + smmu->numpage) << smmu->pgshift;

	/* Trigger sync */
	smmu_writel(smmu, cb_base, ARM_SMMU_CB_TLBSYNC, 0);

	/* Poll for completion with timeout */
	do {
		val = smmu_readl(smmu, cb_base, ARM_SMMU_CB_TLBSTATUS);
		if (!(val & BIT(0)))  /* SACTIVE bit */
			return 0;
	} while (timeout--);

	/* Timeout - hardware error */
	smmu_err(smmu, "Context bank %u TLB sync timeout (SACTIVE still set)", cb_idx);
	return -ETIMEDOUT;
}

/**
 * smmu_v2_tlb_inv_context() - Invalidate all TLB entries for a context
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
		smmu_err(smmu, "TLB sync failed after context invalidation (CB %u, VMID %u)",
			 cb_idx, cb->vmid);
}

/**
 * smmu_v2_tlb_inv_range() - Invalidate TLB entries for an IOVA range
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
	unsigned long iova_start, iova_end;
	u64 addr;
	size_t num_pages;
	u32 cb_base;
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
	cb_base = (cb_idx + smmu->numpage) << smmu->pgshift;

	/* Invalidate each page in the range */
	iova_start = iova & ~(granule - 1);
	iova_end = iova_start + size;

	for (; iova_start < iova_end; iova_start += granule) {
		/*
		 * Use Stage-2 TLB invalidate by IPA (S2_TLBIIPAS2).
		 * For Stage-2-only translation, this is the appropriate operation.
		 * The address is shifted right by 12 bits (4K page boundary).
		 */
		addr = iova_start >> 12;

		smmu_writeq(smmu, cb_base, ARM_SMMU_CB_S2_TLBIIPAS2, addr);
	}

	/* Ensure TLB invalidations complete */
	ret = smmu_v2_tlb_sync_context(smmu, cb_idx);
	if (ret)
		smmu_err(smmu, "TLB sync failed after range invalidation");
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
 * Host Stage-2 Identity Mapping
 */

static size_t smmu_pgsize_idmap(size_t size, u64 paddr, size_t pgsize_bitmap)
{
	size_t pgsizes;

	/* Remove page sizes that are larger than the current size */
	pgsizes = pgsize_bitmap & GENMASK_ULL(__fls(size), 0);

	/* Remove page sizes that the address is not aligned to. */
	if (likely(paddr))
		pgsizes &= GENMASK_ULL(__ffs(paddr), 0);

	WARN_ON(!pgsizes);

	/* Return the larget page size that fits. */
	return BIT(__fls(pgsizes));
}

static void smmu_v2_host_stage2_idmap(phys_addr_t start, phys_addr_t end, int prot)
{
	size_t size = end - start;
	size_t pgsize, pgcount;
	size_t mapped, unmapped;
	int ret;
	struct io_pgtable *pgtable = idmap_pgtable;
	struct iommu_iotlb_gather gather;

	end = min(end, BIT(pgtable->cfg.oas));
	if (start >= end)
		return;

	if (prot) {
		if (!(prot & IOMMU_MMIO))
			prot |= IOMMU_CACHE;

		while (size) {
			mapped = 0;

			pgsize = smmu_pgsize_idmap(size, start, pgtable->cfg.pgsize_bitmap);
			pgcount = size / pgsize;
			ret = pgtable->ops.map_pages(&pgtable->ops, start, start,
						     pgsize, pgcount, prot, 0, &mapped);
			size -= mapped;
			start += mapped;
			if (!mapped || ret) {
				return;
			}
		}
	} else {
		while (size) {
			pgsize = smmu_pgsize_idmap(size, start, pgtable->cfg.pgsize_bitmap);
			pgcount = size / pgsize;
			unmapped = pgtable->ops.unmap_pages(&pgtable->ops, start,
							    pgsize, pgcount, &gather);
			size -= unmapped;
			start += unmapped;
			if (!unmapped)
				break;
		}
		/* Some memory were not unmapped. */
		WARN_ON(size);
	}

}

/**
 * smmu_v2_dabt_handler() - Data abort handler for SMMU MMIO accesses
 * @regs: CPU register state
 * @esr: Exception Syndrome Register value
 * @addr: Faulting address
 *
 * Wrapper around smmu_v2_mmio_handler that matches the kvm_iommu_ops signature.
 * Handles MMIO emulation for host accesses to SMMU registers.
 *
 * Return: true if handled, false otherwise
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
			 size_t out_size)
{
	struct hyp_arm_smmu_v2_device *smmu;
	int ret;

	if (smmu_id >= kvm_hyp_arm_smmu_v2_count) {
		drv_err("Invalid smmu_id %u (max %zu)", smmu_id,
			kvm_hyp_arm_smmu_v2_count - 1);
		return -EINVAL;
	}

	smmu = &kvm_hyp_arm_smmu_v2_smmus[smmu_id];

	ret = hyp_pin_shared_mem(out, out + out_size);
	if (ret) {
		drv_err("Failed to pin shared memory");
		return ret;
	}

	switch(op)
	{
	case PKVM_IOMMU_DEBUG_EXPORT_DEVICE:
		if (out_size < sizeof(*smmu)) {
			ret = -ENOMEM;
			break;
		}

		memcpy(out, smmu, offsetof(struct hyp_arm_smmu_v2_device, cb_state));
		break;
	case PKVM_IOMMU_DEBUG_EXPORT_STATE:
		if (out_size < smmu_shadow_state_size(smmu)) {
			ret = -ENOMEM;
			break;
		}

		smmu_shadow_state_to_pages(smmu, out);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	hyp_unpin_shared_mem(out, out + out_size);
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
