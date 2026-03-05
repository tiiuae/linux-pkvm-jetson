/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ARM SMMUv2 pKVM Shared Definitions
 *
 * Shared data structures between EL1 (host) and EL2 (hypervisor).
 * This header must be included by both arm-smmu-kvm.c (EL1) and
 * arm-smmu-v2.c (EL2) to ensure struct layout compatibility.
 *
 * CRITICAL: Any changes to struct definitions here affect memory
 * layout and must maintain compatibility between EL1 and EL2.
 */

#ifndef __ARM_SMMU_V2_SHARED_H__
#define __ARM_SMMU_V2_SHARED_H__

#include <linux/types.h>
#include <linux/io.h>

/* Maximum number of context banks and stream IDs */
#define ARM_SMMU_MAX_CBS	128
#define ARM_SMMU_MAX_SIDS	256

/* Forward declarations for types defined in arm-smmu.h */
struct arm_smmu_smr;
struct arm_smmu_s2cr;

/*
 * Context Bank State
 *
 * Tracks per-CB translation configuration. This structure is part of
 * struct hyp_arm_smmu_v2_device and must have a fixed, known size.
 */
struct smmu_v2_cb_state {
	u32		domain_id;	/* pkvm_handle_t - owning domain */
	u32		cbar;		/* Context Bank Attribute Register */
	u32		tcr[2];		/* Translation Control Register */
	u64		ttbr[2];	/* Translation Table Base Register */
	u32		sctlr;		/* System Control Register */
	u32		mair[2];	/* Memory Attribute Indirection (Stage 1-only) */
	u16		vmid;		/* Virtual Machine ID */
	bool		reserved;	/* Is this CB in use by the hypervisor */
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
	 * Per-CB state for all 128 context banks. Besides the stage-2 CBs,
	 * this is only needed for debugging purposes so far.
	 */
	struct smmu_v2_cb_state	cb_state[ARM_SMMU_MAX_CBS];

	/*
	 * Stream Mapping State
	 * Pointers to arrays for SMR/S2CR registers.
	 * Mostly needed for debugging so far.
	 */
	struct arm_smmu_smr	*smrs;
	struct arm_smmu_s2cr	*s2crs;

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

#endif /* __ARM_SMMU_V2_SHARED_H__ */
