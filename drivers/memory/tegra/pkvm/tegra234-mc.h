/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tegra234 Memory Controller pKVM Definitions
 *
 * Copyright (C) 2025 Hannu Lyytinen <hannu.lyytinen@unikie.com>
 */

#ifndef __TEGRA234_MC_PKVM_H__
#define __TEGRA234_MC_PKVM_H__

#include <linux/types.h>
#include <linux/io.h>

/*
 * MC Client Information
 * Maps MC client IDs to SID override/security register offsets
 */
struct mc_client_info {
	u32		client_id;		/* TEGRA234_MEMORY_CLIENT_* */
	const char	*name;			/* Client name (for logging) */
	u16		sid_override_offset;	/* SID override register offset */
	u16		sid_security_offset;	/* SID security register offset */
};

/*
 * Tegra MC Controller State
 * EL2 hypervisor state for MC MMIO trapping
 */
struct hyp_tegra_mc {
	phys_addr_t		mmio_addr;
	void __iomem		*base;
	size_t			mmio_size;
	const struct mc_client_info *clients;
	u32			num_clients;
};

/* MC controller instance (defined in tegra234-mc.c) */
extern struct hyp_tegra_mc tegra234_mc;

/*
 * MC Client Table
 * Access to the static table of Tegra234 MC clients
 */
const struct mc_client_info *mc_offset_to_client(u32 offset);
int mc_validate_sid_for_client(u32 client_id, u32 sid);

/*
 * SID Registration
 * Called by MC driver hypercall to register SID→client mappings
 */
int mc_register_sid_mapping(u32 client_id, u32 sid);

/*
 * Platform Hooks Registration
 *
 * Called by SMMU driver (via CONFIG_TEGRA_MC_PKVM ifdef) during global init.
 * Registers MC MMIO handler for SID override validation.
 */
void tegra234_mc_register_hooks(void);

#endif /* __TEGRA234_MC_PKVM_H__ */
