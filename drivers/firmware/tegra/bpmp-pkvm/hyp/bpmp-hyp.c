// SPDX-License-Identifier: GPL-2.0-only

#define HYP_DEBUG 0

#include "kvm/device.h"
#include <asm/kvm_pkvm_module.h>
#include <asm-generic/io.h>

#include <nvhe/audit.h>
#include <nvhe/mem_protect.h>
#include <nvhe/serial.h>

#include <soc/tegra/bpmp-abi.h>
#include <soc/tegra/bpmp.h>

#include "bpmp-hyp.h"

#define BPMP_NUM_CHANNELS 5

static const struct tegra_bpmp_soc_channels tegra186_channels = {
	.cpu_tx = {
		.offset = 3,
		.timeout = 60 * USEC_PER_SEC,
	},
	.thread = {
		.offset = 0,
		.count = 3,
		.timeout = 600 * USEC_PER_SEC,
	},
	.cpu_rx = {
		.offset = 13,
		.timeout = 0,
	},
};

static const unsigned int bpmp_frame_size = ALIGN(MSG_MIN_SZ, TEGRA_IVC_ALIGN);
/*
 * The tegra186 BPMP channels all have a predefined capacity of 1 frame, thus we can
 * compute the channel size at compile-time.
 *
 * In the general case the channel size is defined as
 * sizeof(struct tegra_ivc_header) + num_frames * frame_size
 */
static const unsigned int bpmp_channel_size =
	sizeof(struct tegra_ivc_header) + bpmp_frame_size;

static struct tegra_bpmp_shadow_channel bpmp_channels[BPMP_NUM_CHANNELS];

static inline u64 ioread_sized(void *addr, u8 size)
{
	switch (size) {
	case 1:
		return ioread8(addr);
	case 2:
		return ioread16(addr);
	case 4:
		return ioread32(addr);
	case 8:
	default:
		return ioread64(addr);
	}
}

static inline void iowrite_sized(void *addr, u8 size, u64 value)
{
	switch (size) {
	case 1:
		iowrite8(value, addr);
		break;
	case 2:
		iowrite16(value, addr);
		break;
	case 4:
		iowrite32(value, addr);
		break;
	case 8:
	default:
		iowrite64(value, addr);
		break;
	}
}

static struct tegra_bpmp_shadow_channel *
bpmp_find_channel_by_addr(unsigned long addr, enum bpmp_channel_pool_type *type)
{
	struct tegra_bpmp_shadow_channel *c;

	for (int i = 0; i < ARRAY_SIZE(bpmp_channels); i++) {
		c = &bpmp_channels[i];
		if (addr >= c->tx.phys &&
		    addr < c->tx.phys + bpmp_channel_size) {
			*type = TEGRA_BPMP_POOL_TX;
			return c;
		}
		if (addr >= c->rx.phys &&
		    addr < c->rx.phys + bpmp_channel_size) {
			*type = TEGRA_BPMP_POOL_RX;
			return c;
		}
	}
	return NULL;
}

static inline unsigned int
bpmp_get_offset_in_channel(const struct tegra_bpmp_shadow_channel *c,
			   unsigned long addr,
			   enum bpmp_channel_pool_type access_type)
{
	switch (access_type) {
	case TEGRA_BPMP_POOL_TX:
		return addr - c->tx.phys;
	case TEGRA_BPMP_POOL_RX:
		return addr - c->rx.phys;
	default: /* should never happen */
		hyp_panic();
	}
}

static struct tegra_ivc_header *
channel_header_get(const struct tegra_bpmp_shadow_channel *c,
		   enum bpmp_channel_pool_type pool_type)
{
	switch (pool_type) {
	case TEGRA_BPMP_POOL_TX:
		return (struct tegra_ivc_header *)c->tx.hdr_addr;
	case TEGRA_BPMP_POOL_RX:
		return (struct tegra_ivc_header *)c->rx.hdr_addr;
	default: /* should never happen */
		hyp_panic();
	}
}

/*
 * Implement here how hints from the guest are stored.
 */
static int bpmp_hyp_handle_guest_hcall(u64 arg1, u64 arg2, u64 arg3)
{
	hyp_debug("received guest HVC: args = %llx, %llx, %llx", arg1, arg2,
		  arg3);
	return 0;
}

static int bpmp_hyp_host_read(struct pkvm_mediated_device *dev,
			      struct pkvm_dev_access *a)
{
	a->value = ioread_sized((void *)a->hyp_addr, a->size);
	return 0;
}

/*
 * Implement here policy logic. What MRQs are allowed, which devices, etc.
 */
static void bpmp_hyp_parse_frame(const struct bpmp_access_info *a)
{
	struct tegra_bpmp_shadow_channel *c = a->channel;
	unsigned int mrq = tegra_bpmp_db_read_field((void *)c->tx_ob, code);
	hyp_debug("MRQ is %d (looking at %lx)", mrq, c->tx_ob);
}

static void bpmp_hyp_handle_header_write(const struct bpmp_access_info *a)
{
	struct tegra_ivc_header *hdr_ref =
		channel_header_get(a->channel, a->pool_type);

	switch (a->channel_offset) {
	case offsetof(struct tegra_ivc_header, tx.count):
		hyp_debug("found write to count in channel %lx",
			  a->channel->tx.phys);

		/* If count increased and state is established, infer that the host
		 * is sending a frame. */
		if (a->channel->state == 0 &&
		    a->raw_access->value > hdr_ref->tx.count) {
			bpmp_hyp_parse_frame(a);
		}
		break;

	case offsetof(struct tegra_ivc_header, tx.state):
		hyp_debug("found write to state in channel %lx",
			  a->channel->tx.phys);
		a->channel->state = a->raw_access->value;
		break;
	};
}

static int bpmp_hyp_host_write(struct pkvm_mediated_device *dev,
			       struct pkvm_dev_access *a)
{
	unsigned int offset;
	enum bpmp_channel_pool_type access_pool_type = TEGRA_BPMP_POOL_UNKNOWN;
	struct tegra_bpmp_shadow_channel *channel;

	hyp_debug("addr=%llx, el2map=%lx, offset=%llx, hyp-addr=%llx, size=%d",
		  a->addr, a->res->el2_map, a->offset, a->hyp_addr, a->size);

	/* TODO we need to remove host write access to the page before checking
	 * to prevent race conditions. */

	channel = bpmp_find_channel_by_addr(a->addr, &access_pool_type);
	if (channel) {
		offset = bpmp_get_offset_in_channel(channel, a->addr,
						    access_pool_type);
		struct bpmp_access_info access = {
			.channel = channel,
			.channel_offset = offset,
			.pool_type = access_pool_type,
			.raw_access = a,
		};
		if (offset < sizeof(struct tegra_ivc_header)) {
			// handle header r/w
			bpmp_hyp_handle_header_write(&access);
		}
	}

	iowrite_sized((void *)a->hyp_addr, a->size, a->value);
	return 0;
}

static void bpmp_shadow_channel_init(struct tegra_bpmp_shadow_channel *c,
				     unsigned long tx_phys,
				     unsigned long tx_map,
				     unsigned long rx_phys,
				     unsigned long rx_map,
				     unsigned int channel_index)
{
	unsigned long offset = bpmp_channel_size * channel_index;

	c->num_frames = 1; /* fixed argument in tegra_ivc_init */
	c->frame_size = bpmp_frame_size;

	c->tx.phys = tx_phys + offset;
	c->tx.hdr_addr = tx_map + offset;
	c->tx.position = 0;

	c->rx.phys = rx_phys + offset;
	c->rx.hdr_addr = rx_map + offset;
	c->rx.position = 0;

	c->state = -1;
	c->tx_ob = c->tx.hdr_addr + sizeof(struct tegra_ivc_header);
	c->rx_ib = c->rx.hdr_addr + sizeof(struct tegra_ivc_header);
}

static void bpmp_hyp_init_channels(const struct pkvm_monitored_resource *tx_res,
				   const struct pkvm_monitored_resource *rx_res)
{
	int i;
	unsigned long tx_phys = tx_res->base;
	unsigned long tx_map = tx_res->el2_map;
	unsigned long rx_phys = rx_res->base;
	unsigned long rx_map = rx_res->el2_map;

	bpmp_shadow_channel_init(&bpmp_channels[0], tx_phys, tx_map, rx_phys,
				 rx_map, tegra186_channels.cpu_tx.offset);
	bpmp_shadow_channel_init(&bpmp_channels[1], tx_phys, tx_map, rx_phys,
				 rx_map, tegra186_channels.cpu_rx.offset);

	for (i = 0; i < tegra186_channels.thread.count; i++) {
		bpmp_shadow_channel_init(&bpmp_channels[i + 2], tx_phys, tx_map,
					 rx_phys, rx_map,
					 tegra186_channels.thread.offset + i);
	}
}

static struct pkvm_audit_ops kvm_bpmp_audit_ops = {
	.read_cb = bpmp_hyp_host_read,
	.write_cb = bpmp_hyp_host_write,
};

static int bpmp_hyp_probe(struct pkvm_mediated_device *dev)
{
	struct pkvm_monitored_resource *tx_region, *rx_region;

	dev->hooks = &kvm_bpmp_audit_ops;

	if (dev->nr_resources < 2) {
		hyp_err("bpmp_hyp: expected at least two mem regions");
		return -EINVAL;
	}
	tx_region = &dev->resources[0];
	rx_region = &dev->resources[1];

	bpmp_hyp_init_channels(tx_region, rx_region);

	hyp_info("BPMP: Hyp driver loaded");
	return 0;
}

struct pkvm_audit_driver bpmp_hyp = {
	.id = KVM_AUDIT_OP_TARGET_BPMP,
	.name = "bpmp_hyp",
	.probe = bpmp_hyp_probe,
	.handle_guest_hcall = bpmp_hyp_handle_guest_hcall,
};
