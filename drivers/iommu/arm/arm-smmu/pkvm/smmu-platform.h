/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pKVM SMMUv2 Platform Hook Interface
 *
 * This header defines the interface for platform-specific code to hook into
 * the generic SMMUv2 pKVM driver. This allows platform code (e.g., Tegra MC)
 * to be located outside the SMMU driver directory while still integrating
 * with the SMMU's MMIO trapping and initialization.
 *
 * Copyright (C) 2025 Hannu Lyytinen <hannu.lyytinen@unikie.com>
 */

#ifndef __SMMU_PLATFORM_H__
#define __SMMU_PLATFORM_H__

#include <linux/types.h>

/* Forward declarations */
struct sid_assignment;

/**
 * struct smmu_v2_platform_hooks - Platform-specific callbacks for SMMUv2 pKVM
 *
 * @init: Called during smmu_v2_global_init() after SMMU instances are
 *        initialized. Platform code can use this to initialize its own
 *        MMIO regions, register callbacks, etc. Return 0 on success.
 *
 * @mmio_handler: Called from smmu_v2_dabt_handler() when an MMIO access
 *                doesn't match any SMMU instance. Allows platform code
 *                to trap additional MMIO regions (e.g., MC SID overrides).
 *                Returns true if the access was handled, false otherwise.
 *                @addr: Physical address of the MMIO access
 *                @is_write: True for write, false for read
 *                @val: Pointer to value (read: output, write: input)
 */
struct smmu_v2_platform_hooks {
	int (*init)(void);
	bool (*mmio_handler)(u64 addr, bool is_write, u64 *val);
};

/**
 * smmu_v2_register_platform_hooks - Register platform-specific callbacks
 * @hooks: Pointer to hook structure (must remain valid)
 *
 * Called by platform code (e.g., Tegra MC) during EL2 initialization
 * to register its callbacks with the generic SMMU driver.
 *
 * Note: Only one platform can be registered at a time.
 */
void smmu_v2_register_platform_hooks(const struct smmu_v2_platform_hooks *hooks);

/**
 * smmu_v2_lookup_sid - Look up SID assignment information
 * @sid: Stream ID to look up
 *
 * Returns pointer to sid_assignment structure if the SID is assigned,
 * or NULL if unassigned. Used by platform code to validate SID writes.
 */
struct sid_assignment *smmu_v2_lookup_sid(u32 sid);

#endif /* __SMMU_PLATFORM_H__ */
