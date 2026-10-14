/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __PKVM_BPMP_HYP_H
#define __PKVM_BPMP_HYP_H

#include <linux/types.h>

struct tegra_bpmp_soc_channels {
	struct {
		unsigned int offset;
		unsigned int count;
		unsigned int timeout;
	} cpu_tx, thread, cpu_rx;
};

#define TEGRA_IVC_ALIGN 64

struct tegra_ivc_header {
	union {
		struct {
			/* fields owned by the transmitting end */
			u32 count;
			u32 state;
		};

		u8 pad[TEGRA_IVC_ALIGN];
	} tx;

	union {
		/* fields owned by the receiving end */
		u32 count;
		u8 pad[TEGRA_IVC_ALIGN];
	} rx;
};

/*
 * Each channel contains 2 buffers: one for TX and one for RX.
 *
 * Layout of a channel TX or RX buffer in iomem:
 *
 * |		|            tx.pool          	|            rx.pool		|
 * |		|				|				|
 * | 0x0	| struct tegra_ivc_header {	|				|
 * | ..    	|	0: count (local)	|				|
 * | ..    	|	4: state		|				|
 * | ..    	|	..			|				|
 * | ..    	|	0x40: count (remote)	|				|
 * | ..    	|	..			|   ... same layout...		|
 * | 0x7f	| } 				|				|
 * | 0x80	| data buffer (1 frame) [ 	|				|
 * | ..    	|	MSG_MIN_SZ (0x80, 128) 	|				|
 * | 0xff	| ] 				|				|
 * | 0x100	| --- next channel start ---	|  --- next channel start --- 	|
 * | ...	|				|				|
 * | 0x1000	|		--- end of bpmp io memory pool ---		|
 */
struct tegra_bpmp_shadow_channel {
	/* ivc buffers */
	struct {
		unsigned long hdr_addr;
		unsigned long phys;
		unsigned int position; /* frame index in the data buffer */
	} rx, tx;

	int state;
	unsigned long rx_ib;
	unsigned long tx_ob;

	unsigned int num_frames; /* 1 for Tegra186 */
	size_t frame_size; /* 128 bytes */
};

static inline u64 ioread_sized(void *addr, u8 size);
static inline void iowrite_sized(void *addr, u8 size, u64 value);

#define io_read_field(addr__, struct_offset__, struct_type__, field__) \
	({                                                             \
		struct_type__ *s_;                                     \
		ioread_sized(addr__ + struct_offset__ +                \
				     offsetof(struct_type__, field__), \
			     sizeof(s_->field__));                     \
	})

#define tegra_bpmp_db_read_field(db, field) \
	io_read_field(db, 0, struct tegra_bpmp_mb_data, field)

enum bpmp_channel_pool_type {
	TEGRA_BPMP_POOL_TX,
	TEGRA_BPMP_POOL_RX,
	TEGRA_BPMP_POOL_UNKNOWN = -1,
};

struct bpmp_access_info {
	struct tegra_bpmp_shadow_channel *channel;
	enum bpmp_channel_pool_type pool_type;
	unsigned int channel_offset;
	struct pkvm_dev_access *raw_access;
};

#endif /* __PKVM_BPMP_HYP_H */
