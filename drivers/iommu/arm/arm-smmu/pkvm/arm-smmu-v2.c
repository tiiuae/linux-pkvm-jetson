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
#include <linux/find.h>
#include <linux/limits.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <nvhe/alloc.h>
#include <nvhe/iommu.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/serial.h>
#include <nvhe/trap_handler.h>

#include "arm-smmu-v2.h"
#include "smmu-platform.h"
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

enum kvm_arm_smmu_domain_type {
	KVM_ARM_SMMU_DOMAIN_S1 = KVM_IOMMU_DOMAIN_ANY_TYPE,
	KVM_ARM_SMMU_DOMAIN_S2,
	KVM_ARM_SMMU_DOMAIN_MAX,
};

/*
 * SMMUv2 domain:
 * @domain: Pointer to the IOMMU domain.
 * @smmu: SMMU owner of the domain
 * @type: Type of domain (S1, S2)
 * @pgt_lock: Lock for page table
 * @pgtable: io_pgtable instance for this domain
 */
struct hyp_arm_smmu_v2_domain {
	struct kvm_hyp_iommu_domain     *domain;
	struct hyp_arm_smmu_v2_device 	*smmu;
	u32				type;
	hyp_spinlock_t			pgt_lock;
	struct io_pgtable		*pgtable;
	u8				cbndx;
};

#define KVM_SMMU_UNMAPPED_MAX		511

struct kvm_smmu_unmapped {
	unsigned short ptr;
	u64 phys[KVM_SMMU_UNMAPPED_MAX];
	size_t size[KVM_SMMU_UNMAPPED_MAX];
};

static DEFINE_PER_CPU(struct kvm_smmu_unmapped, kvm_smmu_deferred_unuse);

/* CB 0 is used exclusively by hyp for host stage 2 translation */
#define HOST_S2_CBNDX 			0
/* Statically reserved CBs for the hypervisor (so far only host stage 2) */
#define NUM_RESERVED_CB 		1

/*
 * Logging
 */
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
static int smmu_hyp_take_pages(u64 phys, size_t size)
{
	WARN_ON(!IS_ALIGNED(phys, PAGE_SIZE) || !IS_ALIGNED(size, PAGE_SIZE));
	return __pkvm_host_donate_hyp(phys >> PAGE_SHIFT, size >> PAGE_SHIFT);
}

/* Transfer ownership of memory from hypervisor to host */
static void smmu_hyp_reclaim_pages(u64 phys, size_t size)
{
	WARN_ON(!IS_ALIGNED(phys, PAGE_SIZE) || !IS_ALIGNED(size, PAGE_SIZE));
	WARN_ON(__pkvm_hyp_donate_host(phys >> PAGE_SHIFT, size >> PAGE_SHIFT));
}

/*
 * Global identity-mapped page table (protected by host_mmu.lock from core code)
 * All protected domains share this single Stage-2 page table that mirrors
 * the host's CPU stage-2 mappings for DMA isolation.
 */
static struct io_pgtable *idmap_pgtable;

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

static struct hyp_arm_smmu_v2_device *smmu_id_to_ptr(pkvm_handle_t smmu_id)
{
	if (smmu_id >= kvm_hyp_arm_smmu_v2_count)
		return NULL;

	smmu_id = array_index_nospec(smmu_id, kvm_hyp_arm_smmu_v2_count);
	return &kvm_hyp_arm_smmu_v2_smmus[smmu_id];
}

static void smmu_flush_deferred_unuse(struct kvm_smmu_unmapped *unmapped)
{
	while (unmapped->ptr) {
		unmapped->ptr--;
		WARN_ON(iommu_pkvm_unuse_dma(unmapped->phys[unmapped->ptr],
					     unmapped->size[unmapped->ptr]));
	}
}

/*
 * TLB Operations
 */

/**
 * smmu_tlb_sync_global() - Wait for global TLB sync to complete
 * @smmu: SMMU device
 *
 * Return: 0 on success, -ETIMEDOUT on timeout
 */
static int smmu_tlb_sync_global(struct hyp_arm_smmu_v2_device *smmu)
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
 * smmu_tlb_sync_context() - Wait for context TLB sync to complete
 * @smmu: SMMU device
 * @cb_idx: Context bank index
 *
 * Return: 0 on success, -ETIMEDOUT on timeout
 */
static int smmu_tlb_sync_context(struct hyp_arm_smmu_v2_device *smmu, int cb_idx)
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
 * smmu_tlb_inv_context() - Invalidate all TLB entries for a context
 * @cookie: SMMU domain
 *
 * For S1 domains, use TLBIASID to invalidate all TLB entries for a given ASID.
 * VMID used is the one on the S1 context bank.
 *
 * For S2 domains, use TLBIVMID to invalidate all TLB entries for a given VMID.
 * This is more efficient than per-page invalidation for large ranges.
 */
static void smmu_tlb_inv_context(void *cookie)
{
	struct hyp_arm_smmu_v2_domain *smmu_domain = cookie;
	struct hyp_arm_smmu_v2_device *smmu = smmu_domain->smmu;
	int cb_idx = smmu_domain->cbndx;
	struct smmu_v2_cb *cb = &smmu->cbs[cb_idx];
	u32 cb_base;

	/*
	 * The TLBI write may be relaxed, so ensure that PTEs cleared by the
	 * current CPU are visible beforehand.
	 */
	wmb();

	hyp_spin_lock(&smmu->lock);

	if (smmu_domain->type == KVM_ARM_SMMU_DOMAIN_S1) {
		cb_base = (cb_idx + smmu->numpage) << smmu->pgshift;

		/* Invalidate all TLB entries for this ASID */
		smmu_writel(smmu, cb_base, ARM_SMMU_CB_S1_TLBIASID, cb->asid);

		/* Ensure invalidation completes */
		smmu_tlb_sync_context(smmu, cb_idx);
	} else {
		/* Invalidate all TLB entries for this VMID */
		smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_TLBIVMID, cb->vmid);

		/* Ensure invalidation completes */
		smmu_tlb_sync_global(smmu);
	}

	hyp_spin_unlock(&smmu->lock);
}

/**
 * smmu_tlb_inv_range() - Invalidate TLB entries for an IOVA range
 * @domain: The domain to invalidate on
 * @cb_idx: Context bank index
 * @iova: Starting IOVA
 * @size: Size of range
 * @granule: Invalidation granule
 * @leaf: Where this should be last-level invalidation only
 *
 * For small ranges, use address-based invalidation. For large ranges,
 * fall back to full context invalidation which is more efficient.
 */
static void smmu_tlb_inv_range(struct hyp_arm_smmu_v2_domain *smmu_domain,
			       unsigned long iova, size_t size, size_t granule,
			       bool leaf)
{
	struct hyp_arm_smmu_v2_device *smmu = smmu_domain->smmu;
	unsigned long iova_start, iova_end;
	u64 addr;
	size_t num_pages;
	u32 cb_base;
	u32 reg;
	int cb_idx = smmu_domain->cbndx;
	struct smmu_v2_cb *cb = &smmu->cbs[cb_idx];

	if (smmu->features & ARM_SMMU_FEAT_COHERENT_WALK)
		wmb();

	/* Calculate number of pages in range */
	num_pages = (size + granule - 1) / granule;

	/*
	 * Threshold for full context invalidation vs per-page:
	 * If more than 32 pages, invalidate entire context for efficiency.
	 * This avoids excessive register writes for large unmaps.
	 */
	if (num_pages > 32) {
		smmu_tlb_inv_context(smmu_domain);
		return;
	}

	hyp_spin_lock(&smmu->lock);

	/* Calculate context bank base address */
	cb_base = (cb_idx + smmu->numpage) << smmu->pgshift;

	/* Invalidate each page in the range */
	iova_start = iova & ~(granule - 1);
	iova_end = iova_start + size;

	/*
	 * There are no mappings at high addresses since we don't use TTBR1,
	 * so no overflow possible.
	 */
	BUG_ON(iova_end < iova_start);

	if (smmu_domain->type == KVM_ARM_SMMU_DOMAIN_S1) {
		reg = leaf ? ARM_SMMU_CB_S1_TLBIVAL : ARM_SMMU_CB_S1_TLBIVA;

		for (; iova_start < iova_end; iova_start += granule) {
			/*
			 * Use Stage-1 TLB invalidate by VA (S1_TLBIVA(L)).
			 * The address is shifted right by 12 bits (4K page boundary)
			 * and the ASID is or'ed at the top bits.
			 */
			addr = iova_start >> 12;
			addr |= (u64)cb->asid << 48;
			smmu_writeq(smmu, cb_base, reg, addr);
		}
	} else {
		reg = leaf ? ARM_SMMU_CB_S2_TLBIIPAS2L : ARM_SMMU_CB_S2_TLBIIPAS2;

		for (; iova_start < iova_end; iova_start += granule) {
			/*
			 * Use Stage-2 TLB invalidate by IPA (S2_TLBIIPAS2(L)).
			 * The address is shifted right by 12 bits (4K page boundary).
			 */
			addr = iova_start >> 12;
			smmu_writeq(smmu, cb_base, reg, addr);
		}
	}

	/* Ensure TLB invalidations complete, unless leaf (same as arm-smmu.c) */
	if (!leaf)
		smmu_tlb_sync_context(smmu, cb_idx);

	hyp_spin_unlock(&smmu->lock);
}

static void smmu_tlb_inv_range_idmap(unsigned long iova, size_t size,
				     size_t granule, bool leaf)
{
	struct hyp_arm_smmu_v2_domain smmu_domain;
	struct hyp_arm_smmu_v2_device *smmu;

	smmu_domain.domain = NULL;
	smmu_domain.type = KVM_ARM_SMMU_DOMAIN_S2;
	smmu_domain.pgtable = idmap_pgtable;
	smmu_domain.cbndx = HOST_S2_CBNDX;

	for_each_smmu(smmu) {
		smmu_domain.smmu = smmu;
		smmu_tlb_inv_range(&smmu_domain, iova, size, granule, leaf);
	}
}

/**
 * smmu_tlb_flush_walk() - Flush TLB after unmapping non-leaf PTEs
 * @iova: I/O virtual address
 * @size: Size of the range to invalidate
 * @granule: Page granule size
 * @cookie: SMMU domain
 *
 * Called by io-pgtable when unmapping intermediate page table entries.
 */
static void smmu_tlb_flush_walk(unsigned long iova, size_t size,
				size_t granule, void *cookie)
{
	smmu_tlb_inv_range(cookie, iova, size, granule, false);
}

/**
 * smmu_tlb_add_page() - Add page to TLB invalidation gather
 * @gather: TLB gather structure (unused for SMMUv2)
 * @iova: I/O virtual address
 * @granule: Page granule size
 * @cookie: SMMU domain
 *
 * Called by io-pgtable when unmapping leaf page table entries.
 * SMMUv2 doesn't support gather/batch TLB invalidation, so we invalidate immediately.
 */
static void smmu_tlb_add_page(struct iommu_iotlb_gather *gather, unsigned long iova,
			      size_t granule, void *cookie)
{
	smmu_tlb_inv_range(cookie, iova, granule, granule, true);
}

static const struct iommu_flush_ops smmu_tlb_ops = {
	.tlb_flush_all  = smmu_tlb_inv_context,
	.tlb_flush_walk	= smmu_tlb_flush_walk,
	.tlb_add_page	= smmu_tlb_add_page,
};

/**
 * smmu_idmap_tlb_flush_walk() - Flush TLB after unmapping non-leaf PTEs
 * @iova: I/O virtual address
 * @size: Size of the range to invalidate
 * @granule: Page granule size
 * @cookie: (unused)
 *
 * Called by io-pgtable when unmapping intermediate page table entries.
 */
static void smmu_idmap_tlb_flush_walk(unsigned long iova, size_t size,
				      size_t granule, void *cookie)
{
	smmu_tlb_inv_range_idmap(iova, size, granule, false);
}

/**
 * smmu_idmap_tlb_add_page() - Add page to TLB invalidation gather
 * @gather: TLB gather structure (unused for SMMUv2)
 * @iova: I/O virtual address
 * @granule: Page granule size
 * @cookie: (unused)
 *
 * Called by io-pgtable when unmapping leaf page table entries.
 * SMMUv2 doesn't support gather/batch TLB invalidation, so we invalidate immediately.
 */
static void smmu_idmap_tlb_add_page(struct iommu_iotlb_gather *gather, unsigned long iova,
				    size_t granule, void *cookie)
{
	smmu_tlb_inv_range_idmap(iova, granule, granule, true);
}

static const struct iommu_flush_ops smmu_idmap_tlb_ops = {
	.tlb_flush_walk = smmu_idmap_tlb_flush_walk,
	.tlb_add_page	= smmu_idmap_tlb_add_page,
};

static void smmu_iotlb_sync(struct kvm_hyp_iommu_domain *domain,
			    struct iommu_iotlb_gather *gather)
{
	struct hyp_arm_smmu_v2_domain *smmu_domain = domain->priv;
	struct hyp_arm_smmu_v2_device *smmu = smmu_domain->smmu;

	hyp_spin_lock(&smmu->lock);
	smmu_tlb_sync_context(smmu_domain->smmu, smmu_domain->cbndx);
	hyp_spin_unlock(&smmu->lock);
}

/**
 * smmu_init_idmap_pgt() - Initialize global identity-mapped page table
 *
 * Creates a single Stage-2 page table shared by all protected domains.
 * This table mirrors the host's CPU stage-2 mappings for DMA isolation.
 *
 * Return: 0 on success, negative error code on failure
 */
static int smmu_init_idmap_pgt(void)
{
	struct io_pgtable_cfg cfg = {
		.tlb		= &smmu_idmap_tlb_ops,
		.ias		= 48,	/* Input address size */
		.oas		= 48,	/* Output address size */
		.coherent_walk	= true,
		.pgsize_bitmap	= SZ_4K, /* Tegra234: 4K only (walk cache erratum) */
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
	drv_info("Allocating host s2 page table (ias=%u, oas=%u, pgsize=0x%lx)",
		 cfg.ias, cfg.oas, cfg.pgsize_bitmap);

	ops = kvm_alloc_io_pgtable_ops(ARM_64_LPAE_S2, &cfg, NULL);
	if (!ops) {
		drv_err("Failed to allocate host s2 page table ops");
		return -ENOMEM;
	}

	idmap_pgtable = io_pgtable_ops_to_pgtable(ops);
	if (!idmap_pgtable)
		/* This shouldn't happen, but handle it anyway */
		return -ENOMEM;

	return 0;
}

/*
 * This is called just before the PTE is cleared, and before any TLB invalidation.
 * So, it is not possible to decrement the page count from here as it can still
 * be accessible through DMA.
 * Doing invalidation before this defeats the point of iotlb_gather and issues
 * extra commands hurting perfromance.
 * Instead, we keep track of those pages, and unuse them once TLBs are invalidated.
 */
static void smmu_put_pages(void *cookie, u64 phys, size_t size, struct iommu_iotlb_gather *gather)
{
	struct kvm_smmu_unmapped *unmapped = this_cpu_ptr(&kvm_smmu_deferred_unuse);
	struct hyp_arm_smmu_v2_domain *smmu_domain = cookie;
	struct kvm_hyp_iommu_domain *domain = smmu_domain->domain;

	if (unmapped->ptr == KVM_SMMU_UNMAPPED_MAX) {
		/*
		 * Invalidate TLBs then flush requests.
		 * If gather is NULL that means page table is destroyed, and no devices are
		 * attached so we ignore TLB invalidation.
		 */
		if (gather) {
			smmu_iotlb_sync(domain, gather);
			iommu_iotlb_gather_init(gather);
		}
		smmu_flush_deferred_unuse(unmapped);
	}

	if (unmapped->ptr &&
	    (unmapped->phys[unmapped->ptr - 1] + unmapped->size[unmapped->ptr - 1]) == phys) {
		unmapped->size[unmapped->ptr - 1] += size;
	} else {
		unmapped->phys[unmapped->ptr] = phys;
		unmapped->size[unmapped->ptr] = size;
		unmapped->ptr++;
	}
}

static int smmu_domain_finalise(struct hyp_arm_smmu_v2_device *smmu,
				struct kvm_hyp_iommu_domain *domain)
{
	struct io_pgtable_cfg cfg;
	struct hyp_arm_smmu_v2_domain *smmu_domain = domain->priv;
	enum io_pgtable_fmt fmt;
	struct io_pgtable_ops *ops;

	if (smmu_domain->type == KVM_ARM_SMMU_DOMAIN_S1) {
		fmt = ARM_64_LPAE_S1;
		cfg = (struct io_pgtable_cfg) {
			.pgsize_bitmap = smmu->pgsize_bitmap,
			.ias = smmu->ubs,
			.oas = smmu->ias,
			.coherent_walk = smmu->features & ARM_SMMU_FEAT_COHERENT_WALK,
			.tlb = &smmu_tlb_ops,
			.put_pages = smmu_put_pages,
		};
	} else {
		fmt = ARM_64_LPAE_S2;
		cfg = (struct io_pgtable_cfg) {
			.pgsize_bitmap = smmu->pgsize_bitmap,
			.ias = smmu->ias,
			.oas = smmu->oas,
			.coherent_walk = smmu->features & ARM_SMMU_FEAT_COHERENT_WALK,
			.tlb = &smmu_tlb_ops,
			.put_pages = smmu_put_pages,
		};
	}

	ops = kvm_alloc_io_pgtable_ops(fmt, &cfg, smmu_domain);
	if (!ops)
		return -ENOMEM;
	smmu_domain->pgtable = io_pgtable_ops_to_pgtable(ops);
	return 0;
}

/*
 * Device Initialization
 */

/**
 * smmu_probe_device() - Read SMMU capabilities from hardware
 * @smmu: SMMU device to probe
 *
 * Reads IDR registers to determine capabilities (number of context banks,
 * stream mapping groups, page sizes, coherent walk support, etc.)
 *
 * Return: 0 on success, negative error code on failure
 */
static int smmu_probe_device(struct hyp_arm_smmu_v2_device *smmu)
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
		/* No stream matching, direct Stream ID indexing */
		smmu->num_mapping_groups = 128;  /* Tegra234 has 128 */
	}

	/* We will be masking extended ID support as we don't support it */
	smmu->sid_bits = FIELD_GET(ARM_SMMU_ID0_NUMSIDB, id0);

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

	/*
	 * Upstream bus size (VA, bits)
	 * Value 5 means 49-bit yet this function returns 48bits and Linux also
	 * uses that so we stick to it.
	 */
	size = arm_smmu_id_size_to_bits(FIELD_GET(ARM_SMMU_ID2_UBS, id2));
	smmu->ubs = size;

	/* IPA Address Size (IPA) */
	size = arm_smmu_id_size_to_bits(FIELD_GET(ARM_SMMU_ID2_IAS, id2));
	smmu->ias = size;

	/* Output Address Size (PA) */
	size = arm_smmu_id_size_to_bits(FIELD_GET(ARM_SMMU_ID2_OAS, id2));
	smmu->oas = size;

	/* Check for 16-bit VMID support */
	if (id2 & ARM_SMMU_ID2_VMID16)
		smmu->features |= ARM_SMMU_FEAT_VMID16;

	/* ID7: SMMU architecture version */
	/* For Tegra234, this is SMMUv2 (ARM MMU-500) */
	/* Version info is informational only */

	return 0;
}

/**
 * smmu_reset() - Reset and initialize SMMU hardware
 * @smmu: SMMU device to reset
 *
 * Configures global registers and prepares hardware for operation.
 * This follows the standard ARM SMMUv2 reset sequence.
 */
static int smmu_reset(struct hyp_arm_smmu_v2_device *smmu)
{
	u32 scr0, reg;
	int i, ret;

	/* 1. Clear global fault status register */
	reg = smmu_readl(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sGFSR);
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sGFSR, reg);

	/* 2. Reset stream mapping groups */
	for (i = 0; i < smmu->num_mapping_groups; i++) {
		/* Clear SMR (mark as invalid) */
		smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_SMR(i), 0);

		/*
		 * Set S2CR to FAULT.
		 * Warning: this is different from Linux which tries to preserve
		 *          boot mappings set by the firmware by allowing them
		 *          to bypass. It is not clear whether that is necessary.
		 *          This behaviour has not been tested with a connected
		 *          display, where presumably it could cause a (hopefully)
		 *          brief interuption. If such devices do not come back,
		 *          then a mechanism would have to be devised so that we
		 *          allow such mappings until some point in time, but not
		 *          longer. A good candidate for such point might be
		 *          host_stage2_idmap(), during which we attach the host's
		 *          stage-2 just to be safe.
		 */
		smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_S2CR(i),
			    FIELD_PREP(ARM_SMMU_S2CR_TYPE, S2CR_TYPE_FAULT));
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

	/* Do not let conflicting matches bypass the SMMU */
	scr0 |= ARM_SMMU_sCR0_SMCFCFG;

	/*
	 * Handle unmatched streams: clear USFCFG to allow bypass if you face issues.
	 * When USFCFG=0, undefined streams bypass the SMMU (no translation).
	 * This would help during boot when not all devices are attached to domains.
	 * Security note: attached devices still use proper translation.
	 */
	scr0 |= ARM_SMMU_sCR0_USFCFG;

	/* Enable 16-bit VMIDs if supported */
	if (smmu->features & ARM_SMMU_FEAT_VMID16)
		scr0 |= ARM_SMMU_sCR0_VMID16EN;

	/* Disable forced broadcasting */
	/* (FB bit is implicitly 0, no need to clear) */

	/* Don't upgrade barriers */
	/* (BSU bits are implicitly 0) */

	/* Enable client access (clear CLIENTPD) */
	/* (CLIENTPD is bit 0, already 0 in our scr0) */

	/* 6. Perform global TLB sync before enabling */
	ret = smmu_tlb_sync_global(smmu);
	if (ret)
		return ret;

	/* 7. Write final sCR0 value to enable SMMU */
	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_sCR0, scr0);
	return 0;
}

/**
 * smmu_init() - Initialize SMMU device at EL2
 * @smmu: SMMU device structure
 *
 * Assumes that shadow arrays have already been allocated and donated from EL1.
 * This function initializes the donated memory to a known state.
 *
 * Note: Tegra234 dual register base support (niso0/niso1 with secondary bases)
 * is handled automatically by smmu_writel/smmu_readl helper functions defined
 * in arm-smmu-v2.h. These check has_secondary_base and mirror writes to base_sec.
 */
static int smmu_init(struct hyp_arm_smmu_v2_device *smmu)
{
	int ret, i;
	size_t nr_pages, pg, state_size;
	void *state_pages;

	/*
	 * Shadow arrays are NULL initially (not allocated by EL1).
	 * We'll allocate them from hyp memory pool after probing hardware.
	 */

	/* Skip invalid SMMU instances (not populated by EL1) */
	if (!smmu->mmio_addr || !smmu->mmio_size)
		return -ENODEV;

	/* Validate MMIO address alignment */
	if (!PAGE_ALIGNED(smmu->mmio_addr | smmu->mmio_size))
		return -EINVAL;

	/*
	 * Donate SMMU MMIO pages to hypervisor.
	 * This unmaps them from host stage-2, causing all host accesses to trap
	 * to EL2 where they are handled by smmu_dabt_handler().
	 * This is the same approach used by SMMUv3 pKVM driver.
	 */
	nr_pages = smmu->mmio_size >> PAGE_SHIFT;
	for (pg = 0; pg < nr_pages; pg++) {
		u64 pfn = (smmu->mmio_addr >> PAGE_SHIFT) + pg;
		WARN_ON(___pkvm_host_donate_hyp(pfn, 1, true));
	}

	/* Get EL2 VA from hyp linear map (pages already mapped after donation) */
	smmu->base = hyp_phys_to_virt(smmu->mmio_addr);

	/* Donate secondary MMIO base if present (Tegra234 dual-base instances) */
	if (smmu->has_secondary_base && smmu->mmio_addr_sec) {
		nr_pages = smmu->mmio_size >> PAGE_SHIFT;
		for (pg = 0; pg < nr_pages; pg++) {
			u64 pfn = (smmu->mmio_addr_sec >> PAGE_SHIFT) + pg;
			WARN_ON(___pkvm_host_donate_hyp(pfn, 1, true));
		}

		smmu->base_sec = hyp_phys_to_virt(smmu->mmio_addr_sec);
	}

	hyp_spin_lock_init(&smmu->lock);

	/* Probe hardware capabilities */
	ret = smmu_probe_device(smmu);
	if (ret)
		return ret;

	/* Now that we have num mapping groups, and CBs, calculate shadow state size */
	state_size = smmu_shadow_state_size(smmu);

	/* Allocate shadow state from hyp memory pool */
	state_pages = kvm_iommu_donate_pages_atomic(get_order(state_size));
	if (!state_pages)
		return -ENOMEM;

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
	for (i = 0; i < smmu->num_mapping_groups; i++)
		smmu->s2crs[i].type = S2CR_TYPE_FAULT;

	/* Reset and configure hardware */
	ret = smmu_reset(smmu);
	if (ret)
		return ret;

	return 0;
}

/*
 * Context Bank Management
 */

/**
 * smmu_cb_alloc() - Allocate a free context bank
 * @smmu: SMMU device
 *
 * Return: Context bank index, or ARM_SMMU_INVALID_CB if none available
 */
static int smmu_cb_alloc(struct hyp_arm_smmu_v2_device *smmu)
{
	int cb_idx = find_next_zero_bit(smmu->cb_bitmap, smmu->num_context_banks,
					NUM_RESERVED_CB);
	if (cb_idx == smmu->num_context_banks)
		cb_idx = ARM_SMMU_INVALID_CB;
	else
		bitmap_set(smmu->cb_bitmap, cb_idx, 1);
	return cb_idx;
}

/**
 * smmu_cb_free() - Free a context bank
 * @smmu: SMMU device
 * @cb_idx: Actual hardware context bank index
 */
static void smmu_cb_free(struct hyp_arm_smmu_v2_device *smmu, int cb_idx)
{
	BUG_ON(cb_idx < NUM_RESERVED_CB || cb_idx >= smmu->num_context_banks);
	bitmap_clear(smmu->cb_bitmap, cb_idx, 1);
}

/**
 * smmu_cb_init() - Initialise a context bank
 * @smmu: SMMU device
 * @cb_idx: The hardware index of the context bank
 * @domain_type: Stage 1 or 2. One of enum kvm_arm_smmu_domain_type
 * @domain_id: 0 for host, all others for guests. Assumes < U16_MAX-num_context_banks
 * @pgtbl_cfg: The page table configuration to initialise from
 *
 * Depending on @domain_type, either sets S1-translate-S2-bypass or S2-translate.
 * * Does not support stage 1 domains for nesting (S1-translate-S2-tranlate) even
 *   though it can be used to setup a stage 2 domain for nesting with another CB.
 * * Host domain ASIDs (stage 1) are set to @cb_idx. Just as Linux does.
 * * Guest domain ASIDs (stage 1) are calculated from domain IDs mapped above
 *   `smmu.num_context_banks` to avoid collisions with the Linux host.
 * * All VMIDs (host/guest x stage 1/2) are set to @domain_id.
 */
static void smmu_cb_init(struct hyp_arm_smmu_v2_device *smmu, int cb_idx, int domain_type,
			 u16 domain_id, struct io_pgtable_cfg *pgtbl_cfg)
{
	struct smmu_v2_cb *cb = &smmu->cbs[cb_idx];
	bool stage1 = domain_type == KVM_ARM_SMMU_DOMAIN_S1;
	bool host = domain_id == 0;

	/*
	 * VMIDs are a mess...
	 *
	 * For the host:
	 *   Linux driver does not set VMID (i.e. VMID==0) for stage 1 when
	 *   8-bit VMIDs are used. Not sure if this is intended. Follow it
	 *   anyway, as according to the spec, VMIDs across S1 and S2 must
	 *   match, and we do use nesting (id mapped S2) to isolating the host.
	 *
	 *   When 16-bit VMIDs are supported, Linux sets the S1 VMID to
	 *   <cb_idx> and the S2 VMID to <cb_idx + 1>. We trap that and set
	 *   it to 0. So, all host VMIDs equal domain_id (0), regardless of
	 *   stage and size. Again this is required for nesting to work.
	 *
	 * For the guest:
	 *   We have no way to communicate VMIDs across domains unless
	 *   we are the ones to setup the nesting. Since we aren't, and this
	 *   implementation does not support nesting for guests (at least not
	 *   through the hyp iommu PV interface), set it to domain_id just to
	 *   avoid invalidating unwanted S2 entries (see smmu_tlb_inv_context()).
	 */

	/* Union'ed with domain_id */
	cb->vmid = (u16)domain_id;

	/* ASID */
	if (host && stage1)
		/* We don't ever configure host S1 but follow Linux's approach */
		cb->asid = cb_idx;
	else if (!host && stage1)
		cb->asid = smmu_guest_domain_id_to_asid(smmu, domain_id);

	/* CBAR */
	if (stage1) {
		cb->cbar = FIELD_PREP(ARM_SMMU_CBAR_TYPE, CBAR_TYPE_S1_TRANS_S2_BYPASS);
	} else {
		cb->cbar = FIELD_PREP(ARM_SMMU_CBAR_TYPE, CBAR_TYPE_S2_TRANS);
	}

	/* TCR */
	if (stage1) {
		cb->tcr[0] = smmu_lpae_tcr(pgtbl_cfg);
		cb->tcr[1] = smmu_lpae_tcr2(pgtbl_cfg);
		cb->tcr[1] |= ARM_SMMU_TCR2_AS;
	} else {
		cb->tcr[0] = smmu_lpae_vtcr(pgtbl_cfg);
	}

	/* TTBRs */
	if (stage1) {
		cb->ttbr[0] = FIELD_PREP(ARM_SMMU_TTBRn_ASID, cb->asid);
		cb->ttbr[1] = FIELD_PREP(ARM_SMMU_TTBRn_ASID, cb->asid);

		if (pgtbl_cfg->quirks & IO_PGTABLE_QUIRK_ARM_TTBR1)
			cb->ttbr[1] |= pgtbl_cfg->arm_lpae_s1_cfg.ttbr;
		else
			cb->ttbr[0] |= pgtbl_cfg->arm_lpae_s1_cfg.ttbr;
	} else {
		cb->ttbr[0] = pgtbl_cfg->arm_lpae_s2_cfg.vttbr;
	}

	/* MAIRs (stage-1 only) */
	if (stage1) {
		cb->mair[0] = pgtbl_cfg->arm_lpae_s1_cfg.mair;
		cb->mair[1] = pgtbl_cfg->arm_lpae_s1_cfg.mair >> 32;
	}
}

/**
 * smmu_cb_write() - Write context bank to hardware
 * @smmu: SMMU device
 * @cb_idx: The hardware index of the context bank to write
 *
 * All values written as specified in smmu->cbs[cb_idx] except CBAR in which
 * case only TYPE and CBNDX are respected.
 *
 * VMID is always written as 0.
 */
static void smmu_cb_write(struct hyp_arm_smmu_v2_device *smmu, int cb_idx)
{
	u32 reg, cb_base;
	bool stage1;
	struct smmu_v2_cb *cb = &smmu->cbs[cb_idx];
	u8 cbar_type;

	/* Calculate CB page offset: context banks start at page numpage */
	cb_base = (cb_idx + smmu->numpage) << smmu->pgshift;

	if (!cb->tcr[0]) {
		/* Nothing more to do */
		smmu_writel(smmu, cb_base, ARM_SMMU_CB_SCTLR, 0);
		return;
	}

	cbar_type = FIELD_GET(ARM_SMMU_CBAR_TYPE, cb->cbar);
	stage1 = cbar_type != CBAR_TYPE_S2_TRANS;

	/* CBA2R */
	reg = ARM_SMMU_CBA2R_VA64;

	/* 16-bit VMIDs live in CBA2R */
	if (smmu->features & ARM_SMMU_FEAT_VMID16)
		reg |= FIELD_PREP(ARM_SMMU_CBA2R_VMID16, cb->vmid);

	smmu_writel(smmu, ARM_SMMU_GR1, ARM_SMMU_GR1_CBA2R(cb_idx), reg);

	/* CBAR */
	reg = FIELD_PREP(ARM_SMMU_CBAR_TYPE, cbar_type);

	if (stage1) {
		/*
		 * Use the weakest shareability/memory types, so they are
		 * overridden by the ttbcr/pte.
		 */
		reg |= FIELD_PREP(ARM_SMMU_CBAR_S1_BPSHCFG,
				  ARM_SMMU_CBAR_S1_BPSHCFG_NSH) |
		       FIELD_PREP(ARM_SMMU_CBAR_S1_MEMATTR,
				  ARM_SMMU_CBAR_S1_MEMATTR_WB);

		if (cbar_type == CBAR_TYPE_S1_TRANS_S2_TRANS)
			reg |= (cb->cbar & ARM_SMMU_CBAR_S1_CBNDX);
	}

	/* 8-bit VMIDs live in CBAR */
	if (!(smmu->features & ARM_SMMU_FEAT_VMID16))
		reg |= FIELD_PREP(ARM_SMMU_CBAR_VMID, cb->vmid);

	cb->cbar = reg;
	smmu_writel(smmu, ARM_SMMU_GR1, ARM_SMMU_GR1_CBAR(cb_idx), reg);

	/*
	 * TCR
	 * We must write this before the TTBRs, since it determines the
	 * access behaviour of some fields (in particular, ASID[15:8]).
	 */
	smmu_writel(smmu, cb_base, ARM_SMMU_CB_TCR, cb->tcr[0]);
	if (stage1)
		smmu_writel(smmu, cb_base, ARM_SMMU_CB_TCR2, cb->tcr[1]);

	/* TTBRs */
	smmu_writeq(smmu, cb_base, ARM_SMMU_CB_TTBR0, cb->ttbr[0]);
	if (stage1)
		smmu_writeq(smmu, cb_base, ARM_SMMU_CB_TTBR1, cb->ttbr[1]);

	/* MAIRs (stage-1 only) */
	if (stage1) {
		smmu_writel(smmu, cb_base, ARM_SMMU_CB_S1_MAIR0, cb->mair[0]);
		smmu_writel(smmu, cb_base, ARM_SMMU_CB_S1_MAIR1, cb->mair[1]);
	}

	/* SCTLR */
	reg = ARM_SMMU_SCTLR_CFIE | ARM_SMMU_SCTLR_CFRE | ARM_SMMU_SCTLR_AFE |
	      ARM_SMMU_SCTLR_TRE | ARM_SMMU_SCTLR_M;
	if (stage1)
		reg |= ARM_SMMU_SCTLR_S1_ASIDPNE;

	cb->sctlr = reg;
	smmu_writel(smmu, cb_base, ARM_SMMU_CB_SCTLR, reg);
}

/**
 * smmu_host_cb_map() - Get or allocate a new context bank for the host
 * @smmu: SMMU device
 * @cb_idx_host: The index that the host thinks this context bank will be in.
 *
 * Return: Actual hardware context bank index, or ARM_SMMU_INVALID_CB if none available
 *         or invalid @cb_idx_host argument was provided.
 */
static int smmu_host_cb_map(struct hyp_arm_smmu_v2_device *smmu, int cb_idx_host)
{
	int cb_idx;

	if (cb_idx_host >= smmu->num_context_banks)
		return ARM_SMMU_INVALID_CB;

	cb_idx = smmu->host_cb_map[cb_idx_host];
	if (cb_idx == ARM_SMMU_INVALID_CB) {
		cb_idx = smmu_cb_alloc(smmu);
		if (cb_idx != ARM_SMMU_INVALID_CB)
			smmu->host_cb_map[cb_idx_host] = cb_idx;
	}

	return cb_idx;
}

/**
 * smmu_host_cb_unmap() - Unmap and free a context bank of the host
 * @smmu: SMMU device
 * @cb_idx_host: Context bank index used by the host
 */
static void smmu_host_cb_unmap(struct hyp_arm_smmu_v2_device *smmu, int cb_idx_host)
{
	int cb_idx;

	if (cb_idx_host >= smmu->num_context_banks)
		return;

	cb_idx = smmu->host_cb_map[cb_idx_host];
	smmu->host_cb_map[cb_idx_host] = ARM_SMMU_INVALID_CB;
	smmu_cb_free(smmu, cb_idx);
}

/**
 * smmu_host_cb_find() - Given a hardware CB index, find the host index
 * @smmu: SMMU device
 * @cb_idx: The index that the host thinks this context bank will be in.
 *
 * Return: Host context bank index, or ARM_SMMU_INVALID_CB if not found.
 */
static int smmu_host_cb_find(struct hyp_arm_smmu_v2_device *smmu, int cb_idx)
{
	int cb_idx_host;

	for (cb_idx_host = 0; cb_idx_host < smmu->num_context_banks; cb_idx_host++) {
		if (smmu->host_cb_map[cb_idx_host] == cb_idx)
			return cb_idx_host;
	}

	return ARM_SMMU_INVALID_CB;
}

/**
 * smmu_host_cb_cleanup() - Finds unused CBs by host, and unmaps them
 * @smmu: SMMU device
 */
static void smmu_host_cb_cleanup(struct hyp_arm_smmu_v2_device *smmu)
{
	int cb_idx, cb_idx_host;

	for (cb_idx_host = 0; cb_idx_host < smmu->num_context_banks; cb_idx_host++) {
		cb_idx = smmu->host_cb_map[cb_idx_host];
		if (cb_idx == ARM_SMMU_INVALID_CB || smmu->cbs[cb_idx].sctlr)
			continue;

		smmu_host_cb_unmap(smmu, cb_idx_host);
	}
}

/**
 * smmu_host_cb_init_s2() - Configure a stage 2 context bank for a domain
 * @smmu: SMMU device
 * @pgt: Stage-2 page table to use
 * @cb_idx: Context bank index
 *
 * Programs CBAR, TTBR, TCR, and other CB registers for Stage-2 translation.
 * Uses the specified stage 2 page table. Does not check context bank
 * availability (cb_bitmap) or reserved status; context bank should be allocated
 * before calling this function.
 */
static void smmu_host_cb_init_s2(struct hyp_arm_smmu_v2_device *smmu,
				 struct io_pgtable *pgt, int cb_idx)
{
	/* No need to lock; only ever called from init */
	memset(&smmu->cbs[cb_idx], 0, sizeof(struct smmu_v2_cb));
	smmu_cb_init(smmu, cb_idx, KVM_ARM_SMMU_DOMAIN_S2, 0, &pgt->cfg);
	smmu_cb_write(smmu, cb_idx);
}

/*
 * Stream matching table management
 */

/**
 * smmu_sme_alloc() - Allocate a free stream matching entry
 * @smmu: SMMU device
 *
 * Return: Stream matching index, or ARM_SMMU_INVALID_SME if none available
 */
static int smmu_sme_alloc(struct hyp_arm_smmu_v2_device *smmu)
{
	int sme_idx = find_next_zero_bit(smmu->sme_bitmap, smmu->num_mapping_groups, 0);
	if (sme_idx == smmu->num_mapping_groups)
		sme_idx = ARM_SMMU_INVALID_SME;
	else
		bitmap_set(smmu->sme_bitmap, sme_idx, 1);
	return sme_idx;
}

/**
 * smmu_sme_free() - Free a stream matching entry
 * @smmu: SMMU device
 * @sme_idx: Actual hardware stream matching entry index
 */
static void smmu_sme_free(struct hyp_arm_smmu_v2_device *smmu, int sme_idx)
{
	BUG_ON(sme_idx >= smmu->num_mapping_groups);
	bitmap_clear(smmu->sme_bitmap, sme_idx, 1);
}

static void smmu_sme_init(struct hyp_arm_smmu_v2_device *smmu, int sme_idx,
			  u32 sid, int cb_idx)
{
	struct smmu_v2_smr *smr = &smmu->smrs[sme_idx];
	struct smmu_v2_s2cr *s2cr = &smmu->s2crs[sme_idx];

	smr->mask = (1 << smmu->sid_bits) - 1;
	smr->id = (u16)sid;
	smr->valid = true;

	s2cr->type = S2CR_TYPE_TRANS;
	s2cr->cbndx = (u8)cb_idx;
	s2cr->privcfg = 0;
	s2cr->bypass = 0;
}

static void smmu_sme_disable(struct hyp_arm_smmu_v2_device *smmu, int sme_idx)
{
	struct smmu_v2_smr *smr = &smmu->smrs[sme_idx];
	struct smmu_v2_s2cr *s2cr = &smmu->s2crs[sme_idx];

	smr->mask = 0;
	smr->id = 0;
	smr->valid = false;

	s2cr->type = S2CR_TYPE_FAULT;
	s2cr->cbndx = 0;
	s2cr->privcfg = 0;
	s2cr->bypass = 0;
}

static void smmu_sme_write(struct hyp_arm_smmu_v2_device *smmu, int sme_idx)
{
	struct smmu_v2_smr *smr = &smmu->smrs[sme_idx];
	struct smmu_v2_s2cr *s2cr = &smmu->s2crs[sme_idx];
	u32 reg = FIELD_PREP(ARM_SMMU_SMR_ID, smr->id) |
		  FIELD_PREP(ARM_SMMU_SMR_MASK, smr->mask);

	if (smr->valid)
		reg |= ARM_SMMU_SMR_VALID;

	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_SMR(sme_idx), reg);

	reg = FIELD_PREP(ARM_SMMU_S2CR_TYPE, s2cr->type) |
	      FIELD_PREP(ARM_SMMU_S2CR_CBNDX, s2cr->cbndx) |
	      FIELD_PREP(ARM_SMMU_S2CR_PRIVCFG, s2cr->privcfg);

	smmu_writel(smmu, ARM_SMMU_GR0, ARM_SMMU_GR0_S2CR(sme_idx), reg);
}

static int smmu_sme_find_by_sid(struct hyp_arm_smmu_v2_device *smmu, u32 sid)
{
	int i;

	for (i = 0; i < smmu->num_mapping_groups; i++)
		if (smmu->smrs[i].id == sid)
			return i;

	return ARM_SMMU_INVALID_SME;
}

/**
 * smmu_host_sme_map() - Get or allocate a new stream matching entry for the host
 * @smmu: SMMU device
 * @sme_idx_host: The index that the host thinks this SME will be in.
 *
 * Return: Actual hardware SME index, or ARM_SMMU_INVALID_SME if none available
 *         or invalid @sme_idx_host argument was provided.
 */
static int smmu_host_sme_map(struct hyp_arm_smmu_v2_device *smmu, int sme_idx_host)
{
	int sme_idx;

	if (sme_idx_host >= smmu->num_mapping_groups)
		return ARM_SMMU_INVALID_SME;

	sme_idx = smmu->host_sme_map[sme_idx_host];
	if (sme_idx == ARM_SMMU_INVALID_SME) {
		sme_idx = smmu_sme_alloc(smmu);
		if (sme_idx != ARM_SMMU_INVALID_SME)
			smmu->host_sme_map[sme_idx_host] = sme_idx;
	}

	return sme_idx;
}

/**
 * smmu_host_sme_unmap() - Unmap and free a stream matching entry of the host
 * @smmu: SMMU device
 * @sme_idx_host: Stream matching entry index used by the host
 */
static void smmu_host_sme_unmap(struct hyp_arm_smmu_v2_device *smmu, int sme_idx_host)
{
	int sme_idx;

	if (sme_idx_host >= smmu->num_mapping_groups)
		return;

	sme_idx = smmu->host_sme_map[sme_idx_host];
	smmu->host_sme_map[sme_idx_host] = ARM_SMMU_INVALID_SME;
	smmu_sme_free(smmu, sme_idx);
}

/**
 * smmu_host_sme_cleanup() - Finds unused SMEs by host, and unmaps them
 * @smmu: SMMU device
 */
static void smmu_host_sme_cleanup(struct hyp_arm_smmu_v2_device *smmu)
{
	int sme_idx, sme_idx_host;

	for (sme_idx_host = 0; sme_idx_host < smmu->num_mapping_groups; sme_idx_host++) {
		sme_idx = smmu->host_sme_map[sme_idx_host];
		if (sme_idx == ARM_SMMU_INVALID_SME || smmu->smrs[sme_idx].valid)
			continue;

		smmu_host_sme_unmap(smmu, sme_idx_host);
	}
}

/*
 * MMIO Emulation
 */

/**
 * smmu_handle_gr0() - Handle GR0 register access
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
static int smmu_handle_gr0(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
			   bool is_write, u64 *val)
{
	u32 val32;
	int cb_idx, cb_idx_host;
	int sme_idx_host, sme_idx;
	int smereg_idx; /* 0: SMR, 1: S2CR */
	u32 smereg_base[2] = {
		ARM_SMMU_GR0_SMR(0),
		ARM_SMMU_GR0_S2CR(0)
	};

	/* Find out which stream matching register it's trying to access, if any */
	for (smereg_idx = 0; smereg_idx < 2; smereg_idx++) {
		if (offset < smereg_base[smereg_idx] ||
		    offset >= smereg_base[smereg_idx] + smmu->num_mapping_groups * 4)
			continue;

		sme_idx_host = (offset - smereg_base[smereg_idx]) >> 2;
		if (sme_idx_host >= smmu->num_mapping_groups)
			return -EINVAL;

		sme_idx = smmu_host_sme_map(smmu, sme_idx_host);

		/* Ran out of SMEss; not sure what's best here, -EINVAL or 0 */
		if (sme_idx == ARM_SMMU_INVALID_SME) {
			*val = 0;
			return 0;
		}

		offset = smereg_base[smereg_idx] + sme_idx * 4;
		break;
	}

	/* ID registers - read-only capability reporting */
	if (offset >= ARM_SMMU_GR0_ID0 && offset <= ARM_SMMU_GR0_ID7) {
		if (is_write)
			return -EINVAL;  /* Read-only */

		/* Pass through most of the hardware capabilities */
		*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
		val32 = (u32)*val;

		if (offset == ARM_SMMU_GR0_ID0) {
			/* Don't advertise stage-2 or nesting capabilities */
			val32 &= ~(ARM_SMMU_ID0_S2TS | ARM_SMMU_ID0_NTS);

			/*
			 * Don't advertise extended IDs feature; we could support it,
			 * but we would have to track the setting sCR0_EXIDENABLE too.
			 */
			val32 &= ~ARM_SMMU_ID0_EXIDS;
		} else if (offset == ARM_SMMU_GR0_ID1) {
			/*
			 * Subtract the reserved context banks from NUMCB.
			 * These will be owned by the hypervisor
			 */
			val32 &= ~ARM_SMMU_ID1_NUMCB;
			val32 |= FIELD_PREP(ARM_SMMU_ID1_NUMCB,
					    smmu->num_context_banks - NUM_RESERVED_CB);
		} else if (offset == ARM_SMMU_GR0_ID2) {
			/*
			 * Don't advertise 16-bit VMIDs feature; we could support it,
			 * but we would have to track the setting of sCR0_VMID16EN too.
			 */
			val32 &= ~ARM_SMMU_ID2_VMID16;
		}

		*val = val32;
		return 0;
	}

	/* sCR0 - Global control register */
	if (offset == ARM_SMMU_GR0_sCR0) {
		if (!is_write) {
			*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
			return 0;
		}

		/* it's a write */
		val32 = (u32)*val;
		if (val32 & ARM_SMMU_sCR0_CLIENTPD) {
			/*
			 * Can't let host bypass translation globally. This is done on 2
			 * occassions: 1) during boot, and 2) during shutdown. During
			 * boot, supposedly it is done to preserve boot mappings set by
			 * the firmware. This might break such support, though t234
			 * doesn't appear to make use of it. Regarding shutdown, masking
			 * this doesn't seem to cause any issues.
			 */
			val32 &= ~ARM_SMMU_sCR0_CLIENTPD;
		} else {
			/*
			 * Writing to sCR0 is the epilogue of the reset sequence. Right
			 * before that (also part of the reset sequence), the host accesses
			 * all CBs' SCTLR (writes 0). This causes our host_cb_map to be
			 * fully populated. Clean up here and clean up also SMEs.
			 */
			smmu_host_cb_cleanup(smmu);
			smmu_host_sme_cleanup(smmu);
		}

		/*
		 * We haven't advertised extended ID support but the host could still
		 * try to use it as part of an attack. Bail out
		 */
		if (val32 & ARM_SMMU_sCR0_EXIDENABLE)
			return -EINVAL;

		/*
		 * We haven't advertised 16-bit VMID support but the host could still
		 * try to use it as part of an attack. Bail out
		 */
		if (val32 & ARM_SMMU_sCR0_VMID16EN)
			return -EINVAL;

		/*
		 * Enforce USFCFG=1: unmapped streams must fault, not bypass.
		 * This is a security requirement - we cannot let the host
		 * allow arbitrary streams to bypass SMMU translation.
		 */
		val32 |= ARM_SMMU_sCR0_USFCFG;

		/* Do not let conflicting matches bypass the SMMU */
		val32 |= ARM_SMMU_sCR0_SMCFCFG;

		/* Always keep fault reporting enabled */
		val32 |= (ARM_SMMU_sCR0_GFRE | ARM_SMMU_sCR0_GFIE |
				ARM_SMMU_sCR0_GCFGFRE | ARM_SMMU_sCR0_GCFGFIE);

		/* Force disable TLB broadcasting */
		val32 |= (ARM_SMMU_sCR0_VMIDPNE | ARM_SMMU_sCR0_PTM);

		smmu_writel(smmu, ARM_SMMU_GR0, offset, val32);
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
		return smmu_tlb_sync_global(smmu);
	}

	if (offset == ARM_SMMU_GR0_TLBIALLNSNH || offset == ARM_SMMU_GR0_TLBIALLH) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		/* Global TLB invalidation */
		smmu_writel(smmu, ARM_SMMU_GR0, offset, 0);
		return smmu_tlb_sync_global(smmu);
	}

	if (offset == ARM_SMMU_GR0_sTLBGSYNC) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		/* Host requested TLB sync, execute it */
		return smmu_tlb_sync_global(smmu);
	}

	if (offset == ARM_SMMU_GR0_sTLBGSTATUS) {
		if (is_write)
			return -EINVAL;  /* Read-only */
		*val = smmu_readl(smmu, ARM_SMMU_GR0, offset);
		return 0;
	}

	/* SMR registers - stream match configuration (shadow state) */
	if (smereg_idx == 0) {
		if (is_write) {
			val32 = (u32)*val;

			if (!(val32 & ARM_SMMU_SMR_VALID) && smmu->smrs[sme_idx].valid) {
				/*
				 * Host is disabling this SME; unmap it; Checking val32 alone
				 * is not sufficient here as the host writes it invalid also
				 * during reset (when our shadow .valid is also 0) and we
				 * don't want to interfere with the initial reset sequence.
				 */
				smmu_host_sme_unmap(smmu, sme_idx_host);
			}

			/* Update shadow state */
			smmu->smrs[sme_idx].valid = !!(val32 & ARM_SMMU_SMR_VALID);
			smmu->smrs[sme_idx].mask = FIELD_GET(ARM_SMMU_SMR_MASK, val32);
			smmu->smrs[sme_idx].id = FIELD_GET(ARM_SMMU_SMR_ID, val32);

			/* Write through to hardware (no modification needed for SMR) */
			smmu_writel(smmu, ARM_SMMU_GR0, offset, val32);
		} else {
			/* Return shadow state */
			val32 = 0;
			if (smmu->smrs[sme_idx].valid)
				val32 |= ARM_SMMU_SMR_VALID;
			val32 |= FIELD_PREP(ARM_SMMU_SMR_MASK, smmu->smrs[sme_idx].mask);
			val32 |= FIELD_PREP(ARM_SMMU_SMR_ID, smmu->smrs[sme_idx].id);
			*val = val32;
		}
		return 0;
	}

	/* S2CR registers - stream-to-context mapping (shadow + enforce Stage-2) */
	if (smereg_idx == 1) {
		if (is_write) {
			val32 = (u32)*val;

			/* Map the context bank index to actual hardware CB */
			cb_idx_host = FIELD_GET(ARM_SMMU_S2CR_CBNDX, val32);
			cb_idx = smmu_host_cb_map(smmu, cb_idx_host);
			if (cb_idx == ARM_SMMU_INVALID_CB)
				/* We ran out of CBs or a CBNDX too large */
				return -EINVAL;

			/* Correct it in S2CR */
			val32 &= ~ARM_SMMU_S2CR_CBNDX;
			val32 |= FIELD_PREP(ARM_SMMU_S2CR_CBNDX, cb_idx);

			/* Update shadow state */
			smmu->s2crs[sme_idx].type = FIELD_GET(ARM_SMMU_S2CR_TYPE, val32);
			smmu->s2crs[sme_idx].cbndx = FIELD_GET(ARM_SMMU_S2CR_CBNDX, val32);
			smmu->s2crs[sme_idx].privcfg = FIELD_GET(ARM_SMMU_S2CR_PRIVCFG, val32);
			smmu->s2crs[sme_idx].bypass =
				(smmu->s2crs[sme_idx].type == S2CR_TYPE_BYPASS);

			/* We don't allow bypass */
			if (smmu->s2crs[sme_idx].type == S2CR_TYPE_BYPASS) {
				val32 &= ~ARM_SMMU_S2CR_TYPE;
				val32 |= FIELD_PREP(ARM_SMMU_S2CR_TYPE, S2CR_TYPE_FAULT);

				/* And let s2crs[idx].bypass indicate that we modified this */
				smmu->s2crs[sme_idx].type = FIELD_GET(ARM_SMMU_S2CR_TYPE, val32);
			}

			/* Write to hardware */
			smmu_writel(smmu, ARM_SMMU_GR0, offset, val32);
		} else {
			/* Return shadow state; let the host think this is set to bypass */
			if (smmu->s2crs[sme_idx].bypass)
				val32 = FIELD_PREP(ARM_SMMU_S2CR_TYPE, S2CR_TYPE_BYPASS);
			else
				val32 = FIELD_PREP(ARM_SMMU_S2CR_TYPE, smmu->s2crs[sme_idx].type);

			/* Map actual hardware CB index back to host index */
			cb_idx = FIELD_PREP(ARM_SMMU_S2CR_CBNDX, smmu->s2crs[sme_idx].cbndx);
			cb_idx_host = smmu_host_cb_find(smmu, cb_idx);

			val32 |= FIELD_PREP(ARM_SMMU_S2CR_CBNDX, cb_idx_host);
			val32 |= FIELD_PREP(ARM_SMMU_S2CR_PRIVCFG, smmu->s2crs[sme_idx].privcfg);
			*val = val32;
		}
		return 0;
	}

	/* Unknown or unsupported register */
	return -EINVAL;
}

/**
 * smmu_handle_gr1() - Handle GR1 register access
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
static int smmu_handle_gr1(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
			   bool is_write, u64 *val)
{
	u32 val32;
	u32 cbar_type;
	int cb_idx_host, cb_idx;
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

		cb_idx = smmu_host_cb_map(smmu, cb_idx_host);
		if (cb_idx == ARM_SMMU_INVALID_CB) {
			/* Ran out of CBs; not sure what's best here, -EINVAL or 0 */
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

			/* Force VMID = 0 for the host (it's what it uses anyway for S1) */
			val32 &= ~ARM_SMMU_CBAR_VMID;

			/* Store in CB state for tracking */
			smmu->cbs[cb_idx].cbar = val32;

			/* Write to hardware */
			smmu_writel(smmu, ARM_SMMU_GR1, offset, val32);
		} else {
			/* Return current CB state */
			val32 = smmu_readl(smmu, ARM_SMMU_GR1, offset);

			/* Undo override above during write */
			cbar_type = FIELD_GET(ARM_SMMU_CBAR_TYPE, val32);
			if (cbar_type == CBAR_TYPE_S1_TRANS_S2_TRANS) {
				val32 &= ~ARM_SMMU_CBAR_TYPE;
				val32 |= FIELD_PREP(ARM_SMMU_CBAR_TYPE,
						    CBAR_TYPE_S1_TRANS_S2_BYPASS);
			}

			*val = val32;
		}
		return 0;
	} else if (cbreg_idx == 1) {
		/* CBA2R registers - extended attributes */
		if (is_write) {
			val32 = (u32)*val;

			/*
			 * Linux sets vmid=asid here (?) force 0 on host even
			 * though we have force-disabled 16-bit VMIDs
			 */
			val32 &= ~ARM_SMMU_CBA2R_VMID16;

			/* Allow all the rest of CBA2R fields (MONC, VA64) */
			smmu_writel(smmu, ARM_SMMU_GR1, offset, val32);
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
 * smmu_handle_cb() - Handle context bank register access
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
static int smmu_handle_cb(struct hyp_arm_smmu_v2_device *smmu, u32 offset,
			  bool is_write, u64 *val)
{
	u32 page_offset, cb_base, cb_offset;
	int cb_idx_host, cb_idx;
	u32 val32;
	u64 val64;

	/* Calculate which CB this is */
	page_offset = offset >> smmu->pgshift;
	if (page_offset < smmu->numpage)
		return -EINVAL;  /* Pages 0 to numpage-1 are GR0/GR1 */

	cb_idx_host = page_offset - smmu->numpage;
	if (cb_idx_host >= smmu->num_context_banks)
		return -EINVAL;

	cb_idx = smmu_host_cb_map(smmu, cb_idx_host);
	if (cb_idx == ARM_SMMU_INVALID_CB) {
		/* Ran out of CBs; not sure what's best here, -EINVAL or 0 */
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

			if (!val32 && smmu->cbs[cb_idx].sctlr) {
				/*
				 * Host is destroying a context; unmap it. Checking for !val32
				 * alone is not sufficient as the host writes 0 also during
				 * reset (when our shadow sctlr is also 0) and we don't want
				 * to interfere with the initial reset sequence, otherwise we
				 * would have the host configuring the same index again and again
				 * instead of all of them.
				 */
				smmu_host_cb_unmap(smmu, cb_idx_host);
			} else if (val32) {
				/* Force private namespaces; we don't want clashes with VMs */
				val32 |= ARM_SMMU_SCTLR_S1_ASIDPNE;
			}

			/* Store in shadow state */
			smmu->cbs[cb_idx].sctlr = val32;

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
			smmu->cbs[cb_idx].tcr[0] = val32;

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
			smmu->cbs[cb_idx].tcr[1] = val32;

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

			smmu->cbs[cb_idx].ttbr[0] = val64;

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

			smmu->cbs[cb_idx].ttbr[1] = val64;

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
			smmu->cbs[cb_idx].mair[0] = val32;
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
			smmu->cbs[cb_idx].mair[1] = val32;
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

		return smmu_tlb_sync_context(smmu, cb_idx);
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
		return smmu_tlb_sync_context(smmu, cb_idx);
	}

	/* S2_TLBIIPAS2 - Stage-2 TLB invalidate by IPA */
	if (cb_offset == ARM_SMMU_CB_S2_TLBIIPAS2) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		val32 = (u32)*val;
		smmu_writel(smmu, cb_base, cb_offset, val32);
		return smmu_tlb_sync_context(smmu, cb_idx);
	}

	/* S2_TLBIIPAS2L - Stage-2 TLB invalidate by IPA (last level only) */
	if (cb_offset == ARM_SMMU_CB_S2_TLBIIPAS2L) {
		if (!is_write)
			return -EINVAL;  /* Write-only */

		val32 = (u32)*val;
		smmu_writel(smmu, cb_base, cb_offset, val32);
		return smmu_tlb_sync_context(smmu, cb_idx);
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
 * smmu_mmio_handler() - Main MMIO trap handler
 * @addr: Physical address being accessed
 * @is_write: true for write access, false for read
 * @val: Pointer to value (read or write)
 *
 * Called by EL2 MMIO trap infrastructure when host accesses SMMU registers.
 */
static bool smmu_mmio_handler(u64 addr, bool is_write, u64 *val)
{
	struct hyp_arm_smmu_v2_device *smmu = NULL;
	struct hyp_arm_smmu_v2_device *smmu_i;
	u32 offset, page;
	int ret;

	for_each_smmu(smmu_i) {
		/* Check primary base */
		if (addr >= smmu_i->mmio_addr &&
		    addr < smmu_i->mmio_addr + smmu_i->mmio_size) {
			smmu = smmu_i;
			break;
		}

		/* Return true if secondary base; we do all the duplication anyways */
		if (smmu_i->has_secondary_base &&
		    addr >= smmu_i->mmio_addr_sec &&
		    addr < smmu_i->mmio_addr_sec + smmu_i->mmio_size)
			return true;
	}

	if (smmu == NULL)
		return false;

	offset = addr - smmu->mmio_addr;
	page = offset & ~((1 << smmu->pgshift) - 1);

	hyp_spin_lock(&smmu->lock);

	/* Route to appropriate page handler */
	if (page == ARM_SMMU_GR0)
		ret = smmu_handle_gr0(smmu, offset - ARM_SMMU_GR0, is_write, val);
	else if (page == ARM_SMMU_GR1)
		ret = smmu_handle_gr1(smmu, offset - ARM_SMMU_GR1, is_write, val);
	else
		ret = smmu_handle_cb(smmu, offset, is_write, val);

	hyp_spin_unlock(&smmu->lock);
	return ret == 0;
}

/**
 * smmu_global_init() - Global initialization for all SMMU instances
 *
 * Called once during hypervisor initialization to set up all SMMU devices
 * and create the global identity-mapped page table.
 *
 * This should be called from the kvm_iommu_ops->init() callback.
 *
 * Return: 0 on success, negative error code on failure
 */
static int smmu_global_init(pkvm_handle_t drv_id)
{
	struct hyp_arm_smmu_v2_device *smmu;
	size_t smmu_arr_size;
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
	kvm_hyp_arm_smmu_v2_smmus = kern_hyp_va(kvm_hyp_arm_smmu_v2_smmus);

	/* Calculate array size and donate memory to EL2 (must be page-aligned) */
	smmu_arr_size = PAGE_ALIGN(sizeof(struct hyp_arm_smmu_v2_device) *
				   kvm_hyp_arm_smmu_v2_count);
	ret = smmu_hyp_take_pages(hyp_virt_to_phys(kvm_hyp_arm_smmu_v2_smmus),
				  smmu_arr_size);
	if (ret)
		return ret;

	/* Initialize each SMMU instance */
	for_each_smmu(smmu) {
		/*
		 * Shadow arrays are NULL initially (not set by EL1).
		 * smmu_init() will allocate them from hyp memory pool.
		 */
		ret = smmu_init(smmu);
		if (ret)
			goto error_with_pages;
	}

	/* Call platform-specific initialization (e.g., Tegra MC) */
	if (platform_hooks && platform_hooks->init) {
		ret = platform_hooks->init();
		if (ret)
			goto error_with_pages;
	}

	/* Initialize global identity-mapped page table (shared by all SMMUs) */
	ret = smmu_init_idmap_pgt();
	if (ret)
		goto error_with_pages;

	/* Initialize our host stage 2 context bank */
	for_each_smmu(smmu)
		smmu_host_cb_init_s2(smmu, idmap_pgtable, HOST_S2_CBNDX);

	kvm_iommu_register_pviommu_drv(drv_id);

	drv_info("Global initialization complete");
	return 0;
error_with_pages:
	smmu_hyp_reclaim_pages(hyp_virt_to_phys(kvm_hyp_arm_smmu_v2_smmus),
			       smmu_arr_size);
	return ret;
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

static void smmu_host_stage2_idmap(phys_addr_t start, phys_addr_t end, int prot)
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
			if (!mapped || ret)
				return;
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
 * smmu_domain_alloc() - Allocate a domain
 * @iommu: Handle to the smmu device instance
 * @domain: Hypervisor IOMMU domain to allocate
 * @type: Stage 1 (aka KVM_IOMMU_DOMAIN_ANY_TYPE) or stage 2 domain
 *
 * Does not reserve or allocate an SME (SMR and S2CR). This is left for
 * smmu_dev_attach().
 */
static int smmu_domain_alloc(pkvm_handle_t iommu,
			     struct kvm_hyp_iommu_domain *domain, int type)
{
	struct hyp_arm_smmu_v2_domain *smmu_domain;
	struct hyp_arm_smmu_v2_device *smmu = smmu_id_to_ptr(iommu);
	int cb_idx;
	int ret;

	/* domain 0 not used and ID reserved for the s2 vmid. */
	if (domain->domain_id == 0)
		return -EPERM;
	if (!smmu)
		return -ENODEV;

	/*
	 * U16_MAX because we'll be using it as ASID (u16).
	 * - num_context_banks because we reserve bottom <num_context_banks>
	 *   ASIDs for the host. Linux currently uses cb_idx as ASID.
	 */
	if (domain->domain_id > U16_MAX - smmu->num_context_banks)
		return -EINVAL;
	if (type >= KVM_ARM_SMMU_DOMAIN_MAX)
		return -EINVAL;

	smmu_domain = hyp_alloc(sizeof(*smmu_domain));
	if (!smmu_domain)
		return -ENOMEM;

	hyp_spin_lock(&smmu->lock);

	cb_idx = smmu_cb_alloc(smmu);
	if (cb_idx == ARM_SMMU_INVALID_CB) {
		ret = -EBUSY;
		goto error_with_lock;
	}

	smmu_domain->domain = domain;
	smmu_domain->type = type;
	smmu_domain->smmu = smmu;
	smmu_domain->cbndx = cb_idx;
	hyp_spin_lock_init(&smmu_domain->pgt_lock);

	domain->priv = (void *)smmu_domain;

	ret = smmu_domain_finalise(smmu, domain);
	if (ret)
		goto error_with_cb;

	/* Initialise our context bank and write it to hardware */
	smmu_cb_init(smmu, cb_idx, type, (u16)domain->domain_id,
		     &smmu_domain->pgtable->cfg);
	smmu_cb_write(smmu, cb_idx);

	hyp_spin_unlock(&smmu->lock);
	return 0;

error_with_cb:
	smmu_cb_free(smmu, cb_idx);
error_with_lock:
	hyp_spin_unlock(&smmu->lock);
	hyp_free(smmu_domain);
	return ret;
}

static void smmu_domain_free(struct kvm_hyp_iommu_domain *domain)
{
	struct hyp_arm_smmu_v2_domain *smmu_domain = domain->priv;
	struct hyp_arm_smmu_v2_device *smmu = smmu_domain->smmu;
	struct smmu_v2_cb *cb = &smmu->cbs[smmu_domain->cbndx];

	if (smmu_domain->pgtable)
		kvm_arm_io_pgtable_free(smmu_domain->pgtable);

	hyp_spin_lock(&smmu->lock);
	memset(cb, 0, sizeof(*cb));
	smmu_cb_write(smmu, smmu_domain->cbndx);
	smmu_cb_free(smmu, smmu_domain->cbndx);
	hyp_spin_unlock(&smmu->lock);

	smmu_flush_deferred_unuse(this_cpu_ptr(&kvm_smmu_deferred_unuse));
	hyp_free(smmu_domain);
}

static int smmu_dev_attach(pkvm_handle_t iommu, struct kvm_hyp_iommu_domain *domain,
			   u32 sid, u32 pasid, u32 pasid_bits, unsigned long flags)
{
	struct hyp_arm_smmu_v2_device *smmu = smmu_id_to_ptr(iommu);
	struct hyp_arm_smmu_v2_domain *smmu_domain = domain->priv;
	int ret = 0;
	int sme_idx;

	if (!smmu)
		return -ENODEV;
	if (smmu_domain->smmu != smmu)
		return -EBUSY;
	if (sid > U16_MAX)
		return -EINVAL;

	hyp_spin_lock(&smmu->lock);

	if (smmu_sme_find_by_sid(smmu, sid) != ARM_SMMU_INVALID_SME) {
		/* SID exists; conflicting SME would fault (sCR0_SMCFCFG) */
		ret = -EEXIST;
		goto exit_with_lock;
	}

	sme_idx = smmu_sme_alloc(smmu);
	if (sme_idx == ARM_SMMU_INVALID_SME) {
		ret = -EBUSY;
		goto exit_with_lock;
	}

	smmu_sme_init(smmu, sme_idx, sid, smmu_domain->cbndx);
	smmu_sme_write(smmu, sme_idx);

exit_with_lock:
	hyp_spin_unlock(&smmu->lock);
	return ret;
}

static int smmu_dev_detach(pkvm_handle_t iommu, struct kvm_hyp_iommu_domain *domain,
			   u32 sid, u32 pasid)
{
	struct hyp_arm_smmu_v2_device *smmu = smmu_id_to_ptr(iommu);
	struct hyp_arm_smmu_v2_domain *smmu_domain = domain->priv;
	int ret = 0;
	int sme_idx;

	if (!smmu)
		return -ENODEV;
	if (smmu_domain->smmu != smmu)
		return -EBUSY;

	hyp_spin_lock(&smmu->lock);

	sme_idx = smmu_sme_find_by_sid(smmu, sid);
	if (sme_idx == ARM_SMMU_INVALID_SME) {
		ret = -EINVAL;
		goto exit_with_lock;
	}

	smmu_sme_disable(smmu, sme_idx);
	smmu_sme_write(smmu, sme_idx);
	smmu_sme_free(smmu, sme_idx);

exit_with_lock:
	hyp_spin_unlock(&smmu->lock);
	return ret;
}

static int smmu_dev_block_dma(pkvm_handle_t iommu, u32 sid, bool is_host2guest)
{
	struct hyp_arm_smmu_v2_device *smmu = smmu_id_to_ptr(iommu);
	int ret = 0;
	int sme_idx;

	if (!smmu)
		return -ENODEV;

	hyp_spin_lock(&smmu->lock);

	sme_idx = smmu_sme_find_by_sid(smmu, sid);
	if (sme_idx == ARM_SMMU_INVALID_SME) {
		/* Nothing to do, already blocked */
		goto exit_with_lock;
	}

	smmu_sme_disable(smmu, sme_idx);
	smmu_sme_write(smmu, sme_idx);
	smmu_sme_free(smmu, sme_idx);

exit_with_lock:
	hyp_spin_unlock(&smmu->lock);
	return ret;
}

static phys_addr_t smmu_iova_to_phys(struct kvm_hyp_iommu_domain *domain,
				     unsigned long iova)
{
	phys_addr_t paddr;
	struct hyp_arm_smmu_v2_domain *smmu_domain = domain->priv;
	struct io_pgtable *pgtable = smmu_domain->pgtable;

	if (!pgtable)
		return -EINVAL;

	hyp_spin_lock(&smmu_domain->pgt_lock);
	paddr = pgtable->ops.iova_to_phys(&pgtable->ops, iova);
	hyp_spin_unlock(&smmu_domain->pgt_lock);

	return paddr;
}

static int smmu_pages_map(struct kvm_hyp_iommu_domain *domain, unsigned long iova,
			  phys_addr_t paddr, size_t pgsize, size_t pgcount, int prot,
			  size_t *total_mapped)
{
	size_t mapped;
	size_t granule;
	int ret = 0;
	struct hyp_arm_smmu_v2_domain *smmu_domain = domain->priv;
	struct io_pgtable *pgtable = smmu_domain->pgtable;
	size_t size = pgsize * pgcount;

	if (!pgtable)
		return -EINVAL;

	granule = 1UL << __ffs(smmu_domain->pgtable->cfg.pgsize_bitmap);
	if (!IS_ALIGNED(iova | paddr | pgsize, granule))
		return -EINVAL;

	ret = iommu_pkvm_use_dma(paddr, size);
	if (ret)
		return ret;

	hyp_spin_lock(&smmu_domain->pgt_lock);

	while (pgcount) {
		mapped = 0;
		ret = pgtable->ops.map_pages(&pgtable->ops, iova, paddr,
					     pgsize, pgcount, prot, 0, &mapped);
		pgcount -= mapped / pgsize;
		*total_mapped += mapped;
		iova += mapped;
		paddr += mapped;
		if (ret)
			break;
	}

	hyp_spin_unlock(&smmu_domain->pgt_lock);
	if (*total_mapped != size)
		WARN_ON(iommu_pkvm_unuse_dma(paddr, size - *total_mapped));

	return ret;
}

static size_t smmu_pages_unmap(struct kvm_hyp_iommu_domain *domain, unsigned long iova,
			       size_t pgsize, size_t pgcount, struct iommu_iotlb_gather *gather)
{
	size_t granule, unmapped, total_unmapped = 0;
	size_t size = pgsize * pgcount;
	struct hyp_arm_smmu_v2_domain *smmu_domain = domain->priv;
	struct io_pgtable *pgtable = smmu_domain->pgtable;

	if (!pgtable)
		return 0;

	granule = 1UL << __ffs(smmu_domain->pgtable->cfg.pgsize_bitmap);
	if (!IS_ALIGNED(iova | pgsize, granule))
		return 0;

	hyp_spin_lock(&smmu_domain->pgt_lock);
	while (total_unmapped < size) {
		unmapped = pgtable->ops.unmap_pages(&pgtable->ops, iova, pgsize,
						    pgcount, gather);
		if (!unmapped)
			break;
		iova += unmapped;
		total_unmapped += unmapped;
		pgcount -= unmapped / pgsize;
	}
	hyp_spin_unlock(&smmu_domain->pgt_lock);
	smmu_flush_deferred_unuse(this_cpu_ptr(&kvm_smmu_deferred_unuse));
	return total_unmapped;
}

/**
 * smmu_dabt_handler() - Data abort handler for SMMU MMIO accesses
 * @regs: CPU register state
 * @esr: Exception Syndrome Register value
 * @addr: Faulting address
 *
 * Wrapper around smmu_mmio_handler that matches the kvm_iommu_ops signature.
 * Handles MMIO emulation for host accesses to SMMU registers.
 *
 * Return: true if handled, false otherwise
 */
static bool smmu_dabt_handler(struct user_pt_regs *regs, u64 esr, u64 addr)
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
	handled = smmu_mmio_handler(addr, is_write, &val);

	/* If not SMMU, try platform-specific MMIO handler (e.g., Tegra MC) */
	if (!handled && platform_hooks && platform_hooks->mmio_handler)
		handled = platform_hooks->mmio_handler(addr, is_write, &val);

	/* Write result to register if read */
	if (handled && !is_write)
		regs->regs[rt] = val;
	return handled;
}

static int smmu_id_to_token(pkvm_handle_t smmu_id, u64 *out_token)
{
	if (smmu_id >= kvm_hyp_arm_smmu_v2_count)
		return -EINVAL;

	smmu_id = array_index_nospec(smmu_id, kvm_hyp_arm_smmu_v2_count);
	*out_token = kvm_hyp_arm_smmu_v2_smmus[smmu_id].mmio_addr;
	return 0;
}

#ifdef CONFIG_ARM_SMMU_V2_PKVM_DEBUGFS
static int smmu_debug(pkvm_handle_t smmu_id, enum kvm_iommu_debug_ops op, void *out,
			 size_t out_size)
{
	struct hyp_arm_smmu_v2_device *smmu = smmu_id_to_ptr(smmu_id);
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

		memcpy(out, smmu, offsetof(struct hyp_arm_smmu_v2_device, cbs));
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
 * The global identity-mapped page table (idmap_pgtable) is populated during
 * host_stage2_idmap() with IOVA=PA mappings. EL2 enforces Stage-2 translation.
 */
struct kvm_iommu_ops smmu_v2_ops = {
	.init			= smmu_global_init,
	.alloc_domain		= smmu_domain_alloc,
	.free_domain		= smmu_domain_free,
	.iotlb_sync		= smmu_iotlb_sync,
	.attach_dev		= smmu_dev_attach,
	.detach_dev		= smmu_dev_detach,
	.map_pages		= smmu_pages_map,
	.unmap_pages		= smmu_pages_unmap,
	.iova_to_phys		= smmu_iova_to_phys,
	.dabt_handler		= smmu_dabt_handler,
	.host_stage2_idmap	= smmu_host_stage2_idmap,
	.set_identity		= NULL,
	.dev_block_dma		= smmu_dev_block_dma,
	.get_iommu_token_by_id	= smmu_id_to_token,
#ifdef CONFIG_ARM_SMMU_V2_PKVM_DEBUGFS
	.debug			= smmu_debug,
#endif
};
