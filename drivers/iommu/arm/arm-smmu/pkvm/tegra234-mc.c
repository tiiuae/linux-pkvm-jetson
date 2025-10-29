// SPDX-License-Identifier: GPL-2.0-only
/*
 * Tegra234 Memory Controller (MC) integration for pKVM
 *
 * Copyright (C) 2025 Hannu Lyytinen <hannu.lyytinen@unikie.com>
 *
 * This module handles MMIO trapping of the Tegra234 Memory Controller
 * and validates Stream ID override writes to enforce DMA isolation
 * for protected VMs.
 */

#include <linux/io.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <nvhe/iommu.h>
#include <nvhe/memory.h>

#include "arm-smmu-v2.h"

/* Memory Controller instance */
struct hyp_tegra_mc tegra234_mc;

/*
 * MC Client Table
 *
 * This table maps MC client IDs to their SID override/security register
 * offsets. When the host writes to these registers, EL2 validates that
 * the Stream ID being assigned matches what was previously allocated
 * to that client's owning domain.
 *
 * Extracted from drivers/memory/tegra/tegra234.c - 81 clients total
 */
static const struct mc_client_info tegra234_mc_clients[] = {
	{ .client_id = TEGRA234_MEMORY_CLIENT_HDAR, .name = "hdar", .sid_override_offset = 0xa8, .sid_security_offset = 0xac },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVENCSRD, .name = "nvencsrd", .sid_override_offset = 0xe0, .sid_security_offset = 0xe4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE6AR, .name = "pcie6ar", .sid_override_offset = 0x140, .sid_security_offset = 0x144 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE6AW, .name = "pcie6aw", .sid_override_offset = 0x148, .sid_security_offset = 0x14c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE7AR, .name = "pcie7ar", .sid_override_offset = 0x150, .sid_security_offset = 0x154 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVENCSWR, .name = "nvencswr", .sid_override_offset = 0x158, .sid_security_offset = 0x15c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA0RDB, .name = "dla0rdb", .sid_override_offset = 0x160, .sid_security_offset = 0x164 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA0RDB1, .name = "dla0rdb1", .sid_override_offset = 0x168, .sid_security_offset = 0x16c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA0WRB, .name = "dla0wrb", .sid_override_offset = 0x170, .sid_security_offset = 0x174 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA1RDB, .name = "dla1rdb", .sid_override_offset = 0x178, .sid_security_offset = 0x17c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE7AW, .name = "pcie7aw", .sid_override_offset = 0x180, .sid_security_offset = 0x184 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE8AR, .name = "pcie8ar", .sid_override_offset = 0x190, .sid_security_offset = 0x194 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_HDAW, .name = "hdaw", .sid_override_offset = 0x1a8, .sid_security_offset = 0x1ac },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE8AW, .name = "pcie8aw", .sid_override_offset = 0x1d8, .sid_security_offset = 0x1dc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE9AR, .name = "pcie9ar", .sid_override_offset = 0x1e0, .sid_security_offset = 0x1e4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE6AR1, .name = "pcie6ar1", .sid_override_offset = 0x1e8, .sid_security_offset = 0x1ec },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE9AW, .name = "pcie9aw", .sid_override_offset = 0x1f0, .sid_security_offset = 0x1f4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE10AR, .name = "pcie10ar", .sid_override_offset = 0x1f8, .sid_security_offset = 0x1fc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE10AW, .name = "pcie10aw", .sid_override_offset = 0x200, .sid_security_offset = 0x204 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE10AR1, .name = "pcie10ar1", .sid_override_offset = 0x240, .sid_security_offset = 0x244 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE7AR1, .name = "pcie7ar1", .sid_override_offset = 0x248, .sid_security_offset = 0x24c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_MGBEARD, .name = "mgbeard", .sid_override_offset = 0x2c0, .sid_security_offset = 0x2c4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_MGBEBRD, .name = "mgbebrd", .sid_override_offset = 0x2c8, .sid_security_offset = 0x2cc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_MGBECRD, .name = "mgbecrd", .sid_override_offset = 0x2d0, .sid_security_offset = 0x2d4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_MGBEDRD, .name = "mgbedrd", .sid_override_offset = 0x2d8, .sid_security_offset = 0x2dc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_MGBEBWR, .name = "mgbebwr", .sid_override_offset = 0x2f8, .sid_security_offset = 0x2fc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_MGBECWR, .name = "mgbecwr", .sid_override_offset = 0x308, .sid_security_offset = 0x30c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_SDMMCRAB, .name = "sdmmcrab", .sid_override_offset = 0x318, .sid_security_offset = 0x31c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_MGBEDWR, .name = "mgbedwr", .sid_override_offset = 0x328, .sid_security_offset = 0x32c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_SDMMCWAB, .name = "sdmmcwab", .sid_override_offset = 0x338, .sid_security_offset = 0x33c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_VICSRD, .name = "vicsrd", .sid_override_offset = 0x360, .sid_security_offset = 0x364 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_VICSWR, .name = "vicswr", .sid_override_offset = 0x368, .sid_security_offset = 0x36c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA1RDB1, .name = "dla1rdb1", .sid_override_offset = 0x370, .sid_security_offset = 0x374 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA1WRB, .name = "dla1wrb", .sid_override_offset = 0x378, .sid_security_offset = 0x37c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_VI2W, .name = "vi2w", .sid_override_offset = 0x380, .sid_security_offset = 0x384 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_VI2FALR, .name = "vi2falr", .sid_override_offset = 0x388, .sid_security_offset = 0x38c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_VIW, .name = "viw", .sid_override_offset = 0x390, .sid_security_offset = 0x394 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVDECSRD, .name = "nvdecsrd", .sid_override_offset = 0x3c0, .sid_security_offset = 0x3c4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVDECSWR, .name = "nvdecswr", .sid_override_offset = 0x3c8, .sid_security_offset = 0x3cc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_APER, .name = "aper", .sid_override_offset = 0x3d0, .sid_security_offset = 0x3d4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_APEW, .name = "apew", .sid_override_offset = 0x3d8, .sid_security_offset = 0x3dc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_VI2FALW, .name = "vi2falw", .sid_override_offset = 0x3e0, .sid_security_offset = 0x3e4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVJPGSRD, .name = "nvjpgsrd", .sid_override_offset = 0x3f0, .sid_security_offset = 0x3f4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVJPGSWR, .name = "nvjpgswr", .sid_override_offset = 0x3f8, .sid_security_offset = 0x3fc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVDISPLAYR, .name = "nvdisplayr", .sid_override_offset = 0x490, .sid_security_offset = 0x494 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_BPMPR, .name = "bpmpr", .sid_override_offset = 0x498, .sid_security_offset = 0x49c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_BPMPW, .name = "bpmpw", .sid_override_offset = 0x4a0, .sid_security_offset = 0x4a4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_BPMPDMAR, .name = "bpmpdmar", .sid_override_offset = 0x4a8, .sid_security_offset = 0x4ac },
	{ .client_id = TEGRA234_MEMORY_CLIENT_BPMPDMAW, .name = "bpmpdmaw", .sid_override_offset = 0x4b0, .sid_security_offset = 0x4b4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_APEDMAR, .name = "apedmar", .sid_override_offset = 0x4f8, .sid_security_offset = 0x4fc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_APEDMAW, .name = "apedmaw", .sid_override_offset = 0x500, .sid_security_offset = 0x504 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVDISPLAYR1, .name = "nvdisplayr1", .sid_override_offset = 0x508, .sid_security_offset = 0x50c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_VIFALR, .name = "vifalr", .sid_override_offset = 0x5e0, .sid_security_offset = 0x5e4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_VIFALW, .name = "vifalw", .sid_override_offset = 0x5e8, .sid_security_offset = 0x5ec },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA0RDA, .name = "dla0rda", .sid_override_offset = 0x5f0, .sid_security_offset = 0x5f4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA0FALRDB, .name = "dla0falrdb", .sid_override_offset = 0x5f8, .sid_security_offset = 0x5fc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA0WRA, .name = "dla0wra", .sid_override_offset = 0x600, .sid_security_offset = 0x604 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA0FALWRB, .name = "dla0falwrb", .sid_override_offset = 0x608, .sid_security_offset = 0x60c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA1RDA, .name = "dla1rda", .sid_override_offset = 0x610, .sid_security_offset = 0x614 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA1FALRDB, .name = "dla1falrdb", .sid_override_offset = 0x618, .sid_security_offset = 0x61c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA1WRA, .name = "dla1wra", .sid_override_offset = 0x620, .sid_security_offset = 0x624 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA1FALWRB, .name = "dla1falwrb", .sid_override_offset = 0x628, .sid_security_offset = 0x62c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_RCER, .name = "rcer", .sid_override_offset = 0x690, .sid_security_offset = 0x694 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_RCEW, .name = "rcew", .sid_override_offset = 0x698, .sid_security_offset = 0x69c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE0R, .name = "pcie0r", .sid_override_offset = 0x6c0, .sid_security_offset = 0x6c4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE0W, .name = "pcie0w", .sid_override_offset = 0x6c8, .sid_security_offset = 0x6cc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE1R, .name = "pcie1r", .sid_override_offset = 0x6d0, .sid_security_offset = 0x6d4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE1W, .name = "pcie1w", .sid_override_offset = 0x6d8, .sid_security_offset = 0x6dc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE2AR, .name = "pcie2ar", .sid_override_offset = 0x6e0, .sid_security_offset = 0x6e4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE2AW, .name = "pcie2aw", .sid_override_offset = 0x6e8, .sid_security_offset = 0x6ec },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE3R, .name = "pcie3r", .sid_override_offset = 0x6f0, .sid_security_offset = 0x6f4 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE3W, .name = "pcie3w", .sid_override_offset = 0x6f8, .sid_security_offset = 0x6fc },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE4R, .name = "pcie4r", .sid_override_offset = 0x700, .sid_security_offset = 0x704 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE4W, .name = "pcie4w", .sid_override_offset = 0x708, .sid_security_offset = 0x70c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE5R, .name = "pcie5r", .sid_override_offset = 0x710, .sid_security_offset = 0x714 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE5W, .name = "pcie5w", .sid_override_offset = 0x718, .sid_security_offset = 0x71c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA0RDA1, .name = "dla0rda1", .sid_override_offset = 0x748, .sid_security_offset = 0x74c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_DLA1RDA1, .name = "dla1rda1", .sid_override_offset = 0x750, .sid_security_offset = 0x754 },
	{ .client_id = TEGRA234_MEMORY_CLIENT_PCIE5R1, .name = "pcie5r1", .sid_override_offset = 0x778, .sid_security_offset = 0x77c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVJPG1SRD, .name = "nvjpg1srd", .sid_override_offset = 0x918, .sid_security_offset = 0x91c },
	{ .client_id = TEGRA234_MEMORY_CLIENT_NVJPG1SWR, .name = "nvjpg1swr", .sid_override_offset = 0x920, .sid_security_offset = 0x924 },
};

/**
 * mc_init - Initialize Memory Controller EL2 integration
 * @mmio_addr: Physical address of MC registers
 * @mmio_size: Size of MC register region
 *
 * Maps MC MMIO region and configures stage-2 page tables to trap
 * all MC register accesses.
 */
int mc_init(phys_addr_t mmio_addr, size_t mmio_size)
{
	tegra234_mc.mmio_addr = mmio_addr;
	tegra234_mc.mmio_size = mmio_size;
	tegra234_mc.clients = tegra234_mc_clients;
	tegra234_mc.num_clients = ARRAY_SIZE(tegra234_mc_clients);

	/* TODO: Map MMIO region as shared memory with EL2 */
	/* TODO: Configure stage-2 to trap all MC accesses */

	return 0;
}

/**
 * mc_offset_to_client - Find MC client by register offset
 * @offset: Register offset within MC MMIO region
 *
 * Returns: Client info if offset matches a SID override/security register,
 *          NULL otherwise
 */
const struct mc_client_info *mc_offset_to_client(u32 offset)
{
	int i;

	for (i = 0; i < tegra234_mc.num_clients; i++) {
		const struct mc_client_info *client = &tegra234_mc.clients[i];

		if (offset == client->sid_override_offset ||
		    offset == client->sid_security_offset)
			return client;
	}

	return NULL;
}

/**
 * mc_validate_sid_for_client - Validate SID assignment for a client
 * @client_id: Memory controller client ID
 * @sid: Stream ID to validate
 *
 * Checks that @sid matches the SID assigned to the client's owning domain.
 *
 * Returns: 0 if valid, -EPERM if invalid
 */
int mc_validate_sid_for_client(u32 client_id, u32 sid)
{
	struct sid_assignment *entry;

	/* Look up the assigned SID for this client */
	entry = smmu_v2_lookup_sid(sid);
	if (!entry)
		return -EPERM;  /* SID not assigned to any domain */

	if (entry->client_id != client_id)
		return -EPERM;  /* SID doesn't match this client */

	/* Valid assignment */
	return 0;
}

/**
 * mc_handle_sid_override - Handle SID override register write
 * @client: MC client info
 * @val: Value being written
 *
 * Validates that the Stream ID being written matches the client's
 * assigned SID.
 *
 * Returns: 0 if valid and write should proceed, -EPERM to block write
 */
static int mc_handle_sid_override(const struct mc_client_info *client, u32 val)
{
	u32 sid = val & 0xFF;  /* SID is typically in lower 8 bits */

	/* Validate SID assignment */
	if (mc_validate_sid_for_client(client->client_id, sid) != 0) {
		/* TODO: Log security violation */
		return -EPERM;
	}

	/* Allow write to proceed by writing to real hardware */
	writel_relaxed(val, tegra234_mc.base + client->sid_override_offset);

	return 0;
}

/**
 * mc_handle_sid_security - Handle SID security register access
 * @client: MC client info
 * @is_write: true for write, false for read
 * @val: Pointer to value
 *
 * Security registers control access protections. For now, emulate
 * them as read-only.
 */
static int mc_handle_sid_security(const struct mc_client_info *client,
				  bool is_write, u64 *val)
{
	if (is_write) {
		/* TODO: Decide policy for security register writes */
		/* For now, reject them */
		return -EPERM;
	}

	/* Read from hardware */
	*val = readl_relaxed(tegra234_mc.base + client->sid_security_offset);
	return 0;
}

/**
 * mc_mmio_handler - Main MMIO trap handler for Memory Controller
 * @addr: Physical address being accessed
 * @is_write: true for write access, false for read
 * @val: Pointer to value (read or write)
 *
 * Called by EL2 MMIO trap infrastructure when host accesses MC registers.
 *
 * Returns: true if handled, false otherwise
 */
bool mc_mmio_handler(u64 addr, bool is_write, u64 *val)
{
	const struct mc_client_info *client;
	u32 offset;
	int ret;

	/* Check if address is within MC range */
	if (addr < tegra234_mc.mmio_addr ||
	    addr >= tegra234_mc.mmio_addr + tegra234_mc.mmio_size)
		return false;

	offset = addr - tegra234_mc.mmio_addr;

	/* Find which client this register belongs to */
	client = mc_offset_to_client(offset);
	if (!client) {
		/* Not a SID-related register, pass through to hardware */
		if (is_write)
			writel_relaxed(*val, tegra234_mc.base + offset);
		else
			*val = readl_relaxed(tegra234_mc.base + offset);
		return true;
	}

	/* Handle SID override or security register */
	if (offset == client->sid_override_offset) {
		if (!is_write) {
			/* Read current value from hardware */
			*val = readl_relaxed(tegra234_mc.base + offset);
			return true;
		}

		/* Validate and handle write */
		ret = mc_handle_sid_override(client, *val);
		if (ret != 0) {
			/* TODO: Inject fault to guest? */
			/* For now, silently drop the write */
			return true;
		}

		return true;
	}

	if (offset == client->sid_security_offset) {
		ret = mc_handle_sid_security(client, is_write, val);
		return ret == 0;
	}

	/* Should not reach here */
	return false;
}

/*
 * Helper Functions
 */

/**
 * mc_get_client_name - Get human-readable name for a client
 * @client_id: MC client ID
 *
 * Returns: Client name string, or "unknown" if not found
 */
const char *mc_get_client_name(u32 client_id)
{
	int i;

	for (i = 0; i < tegra234_mc.num_clients; i++) {
		if (tegra234_mc.clients[i].client_id == client_id)
			return tegra234_mc.clients[i].name;
	}

	return "unknown";
}
