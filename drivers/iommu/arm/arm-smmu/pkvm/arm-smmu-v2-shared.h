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
 *
 * Size: 56 bytes (verified with static_assert in users)
 */
struct smmu_v2_cb_state {
	u32		domain_id;	/* pkvm_handle_t - owning domain */
	u32		cbar;		/* Context Bank Attribute Register */
	u32		tcr;		/* Translation Control Register (S1) */
	u32		vtcr;		/* VTCR (S2) */
	u64		ttbr0_s2;	/* EL2's stage-2 PT base */
	u64		ttbr1_s1;	/* Host's stage-1 PT base (shadow) */
	u32		sctlr;		/* System Control Register */
	u32		mair[2];	/* Memory Attribute Indirection */
	u16		vmid;		/* Virtual Machine ID */
	bool		active;		/* Is this CB in use? */
	u8		_pad[5];	/* Explicit padding to 56 bytes */
} __packed __aligned(8);

/*
 * SMMU Device Structure (EL1/EL2 shared)
 *
 * This structure is allocated by EL1 and donated to EL2. Both sides
 * must use identical definitions to ensure correct memory layout.
 *
 * Layout:
 * - Hardware configuration (60 bytes)
 * - SMMU capabilities (32 bytes)
 * - Context bank management (16 + 7168 bytes)
 * - Shadow arrays (32 bytes - pointers)
 * - Lock and MC pointer (16 bytes)
 *
 * Total: ~7328 bytes (rounded to 8-byte alignment)
 *
 * IMPORTANT: Do not reorder fields. Memory layout must be identical
 * between EL1 and EL2 for memory donation to work correctly.
 */
struct hyp_arm_smmu_v2_device {
	/*
	 * Hardware Configuration (60 bytes)
	 * Basic MMIO and instance information
	 */
	u32			id;		/* SMMU instance ID (0-2) */
	phys_addr_t		mmio_addr;	/* Primary register base */
	void __iomem		*base;		/* Mapped primary base */
	phys_addr_t		mmio_addr_sec;	/* Secondary register base (niso0/1) */
	void __iomem		*base_sec;	/* Mapped secondary base */
	bool			has_secondary_base;
	u8			_pad1[7];	/* Padding to align mmio_size */
	size_t			mmio_size;

	/*
	 * SMMU Capabilities (32 bytes)
	 * Hardware features read from ID registers
	 */
	u32			features;	/* Feature flags */
	u32			num_mapping_groups;
	u32			num_context_banks;
	u32			num_s2_context_banks;
	u32			numpage;	/* Number of GR pages (CB pages start at numpage) */
	u8			pgshift;	/* Page size shift */
	u8			ias;		/* Input address size (bits) */
	u8			oas;		/* Output address size (bits) */
	u8			_pad2[1];	/* Padding to align pgsize_bitmap */
	unsigned long		pgsize_bitmap;
	u16			vmid_bits;
	u8			_pad3[6];	/* Padding to align context_map */

	/*
	 * Context Bank Management (7184 bytes)
	 * Bitmap and per-CB state for all 128 context banks
	 */
	unsigned long		context_map[2];	/* Bitmap: which CBs are allocated (16 bytes) */
	struct smmu_v2_cb_state	cb_state[ARM_SMMU_MAX_CBS]; /* 128 * 56 = 7168 bytes */

	/*
	 * Shadow Stream Mapping State (32 bytes)
	 * Pointers to shadow arrays for SMR/S2CR registers
	 */
	struct arm_smmu_smr	*smrs_shadow;	/* Host's view of SMRs */
	struct arm_smmu_s2cr	*s2crs_shadow;	/* Host's view of S2CRs */
	struct arm_smmu_smr	*smrs_hw;	/* Actual hardware state */
	struct arm_smmu_s2cr	*s2crs_hw;	/* Actual hardware state */

	/*
	 * Lock and MC Reference (16 bytes)
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
} __aligned(8);

/*
 * Compile-time size verification
 *
 * These assertions ensure struct sizes remain stable. If you change
 * struct layouts, update these values and verify both EL1 and EL2 still work.
 */
#ifdef __KERNEL__
static_assert(sizeof(struct smmu_v2_cb_state) == 56,
	      "struct smmu_v2_cb_state size changed - update EL1/EL2 code");

static_assert(sizeof(struct hyp_arm_smmu_v2_device) <= 8192,
	      "struct hyp_arm_smmu_v2_device exceeds 2 pages - check alignment");
#endif

#endif /* __ARM_SMMU_V2_SHARED_H__ */
