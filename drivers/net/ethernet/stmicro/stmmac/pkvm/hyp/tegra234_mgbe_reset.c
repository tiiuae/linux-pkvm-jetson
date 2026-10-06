// SPDX-License-Identifier: GPL-2.0-only
/*
 * pKVM EL2 reset handler for the NVIDIA Tegra234 MGBE controller.
 * Quiesces the device when it is assigned to, or reclaimed from, a protected
 * VM. Clocks and the BPMP-controlled "mac" reset line are not reachable from
 * EL2 and remain the host's responsibility.
 *
 * Based on the vfio platform tegra234-mgbe reset module.
 * Copyright (c) 2024 Red Hat, Inc.  All rights reserved.
 *     Author: Eric Auger <eric.auger@redhat.com>
 */

#include <asm/kvm_pkvm_module.h>
#include <asm/barrier.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <linux/bits.h>

#include "tegra234_mgbe_reset.h"

#define XGMAC_TX_CONFIG                 0x00000000
#define XGMAC_CONFIG_TE                 BIT(0)
#define XGMAC_RX_CONFIG                 0x00000004
#define XGMAC_CONFIG_RE                 BIT(0)
#define XGMAC_DMA_MODE			0x00003000
#define XGMAC_SWR			BIT(0)

#define XGMAC_DMA_CH_INT_EN(x)		(0x00003138 + (0x80 * (x)))
#define XGMAC_TIE			BIT(0)
#define XGMAC_RIE			BIT(6)
#define XGMAC_RBUE			BIT(7)
#define XGMAC_DMA_INT_DEFAULT_RX	(XGMAC_RBUE | XGMAC_RIE)
#define XGMAC_DMA_INT_DEFAULT_TX	(XGMAC_TIE)

#define XGMAC_DMA_CH_STATUS(x)		(0x00003160 + (0x80 * (x)))
#define XGMAC_DMA_CH_RX_CONTROL(x)      (0x00003108 + (0x80 * (x)))
#define XGMAC_RXST                      BIT(0)
#define XGMAC_DMA_CH_TX_CONTROL(x)      (0x00003104 + (0x80 * (x)))
#define XGMAC_TXST                      BIT(0)

#define MGBE_WRAP_COMMON_INTR_ENABLE	0x8704

#define XPCS_WRAP_UPHY_HW_INIT_CTRL	0x8020
#define XPCS_WRAP_UPHY_HW_INIT_CTRL_TX_EN BIT(0)
#define XPCS_WRAP_UPHY_STATUS		0x8044
#define XPCS_WRAP_UPHY_STATUS_TX_P_UP	BIT(0)

#define MGBE_NR_DMA_CHANNELS		10
#define MGBE_SWR_TIMEOUT_US		100000
/* Same bound as tegra_mgbe_resume() in dwmac-tegra.c. */
#define MGBE_UPHY_TX_TIMEOUT_US		1000000

const struct pkvm_module_ops *pkvm_ops;

/* Physical addresses of the mac and xpcs regions, filled in by the host loader. */
u64 mgbe_mac_phys[TEGRA234_MGBE_MAX];
u64 mgbe_xpcs_phys[TEGRA234_MGBE_MAX];
u32 mgbe_nr;

/* Per-instance EL2 state; &mgbe_hyp[i] is the reset handler cookie. */
static struct tegra_mgbe_hyp {
	void __iomem *mac;	/* hyp VA of the "mac" MMIO region */
	void __iomem *xpcs;	/* hyp VA of the "xpcs" MMIO region */
} mgbe_hyp[TEGRA234_MGBE_MAX];

static void mgbe_udelay(u64 us)
{
	u64 end = pkvm_ops->get_time() + us;

	while (pkvm_ops->get_time() < end)
		cpu_relax();
}

static void stop_dma(void __iomem *mac, u32 channel)
{
	u32 value;

	/* DMA Stop RX */
	value = readl_relaxed(mac + XGMAC_DMA_CH_RX_CONTROL(channel));
	value &= ~XGMAC_RXST;
	writel_relaxed(value, mac + XGMAC_DMA_CH_RX_CONTROL(channel));

	value = readl_relaxed(mac + XGMAC_RX_CONFIG);
	value &= ~XGMAC_CONFIG_RE;
	writel_relaxed(value, mac + XGMAC_RX_CONFIG);

	mgbe_udelay(10);

	/* DMA Stop TX */
	value = readl_relaxed(mac + XGMAC_DMA_CH_TX_CONTROL(channel));
	value &= ~XGMAC_TXST;
	writel_relaxed(value, mac + XGMAC_DMA_CH_TX_CONTROL(channel));

	value = readl_relaxed(mac + XGMAC_TX_CONFIG);
	value &= ~XGMAC_CONFIG_TE;
	writel_relaxed(value, mac + XGMAC_TX_CONFIG);

	mgbe_udelay(10);
}

static int dma_sw_reset(void __iomem *mac)
{
	u64 timeout;
	u32 value;

	value = readl_relaxed(mac + XGMAC_DMA_MODE);
	writel_relaxed(value | XGMAC_SWR, mac + XGMAC_DMA_MODE);

	timeout = pkvm_ops->get_time() + MGBE_SWR_TIMEOUT_US;
	for (;;) {
		value = readl_relaxed(mac + XGMAC_DMA_MODE);
		if (!(value & XGMAC_SWR))
			return 0;
		if (pkvm_ops->get_time() >= timeout)
			return -ETIMEDOUT;
		cpu_relax();
	}
}

/*
 * The XGMAC soft reset only completes once all MAC clock domains are running,
 * and the TX PCS clock comes from the UPHY lane. Bring the TX lane up the same
 * way tegra_mgbe_resume() does before issuing the DMA SWR.
 */
static int uphy_tx_lane_up(void __iomem *xpcs)
{
	u64 timeout;
	u32 value;

	value = readl_relaxed(xpcs + XPCS_WRAP_UPHY_STATUS);
	if (value & XPCS_WRAP_UPHY_STATUS_TX_P_UP)
		return 0;

	value = readl_relaxed(xpcs + XPCS_WRAP_UPHY_HW_INIT_CTRL);
	value |= XPCS_WRAP_UPHY_HW_INIT_CTRL_TX_EN;
	writel_relaxed(value, xpcs + XPCS_WRAP_UPHY_HW_INIT_CTRL);

	timeout = pkvm_ops->get_time() + MGBE_UPHY_TX_TIMEOUT_US;
	for (;;) {
		value = readl_relaxed(xpcs + XPCS_WRAP_UPHY_HW_INIT_CTRL);
		if (!(value & XPCS_WRAP_UPHY_HW_INIT_CTRL_TX_EN))
			return 0;
		if (pkvm_ops->get_time() >= timeout)
			return -ETIMEDOUT;
		cpu_relax();
	}
}

static void disable_dma_irq(void __iomem *mac, u32 channel)
{
	u32 intr_en;

	intr_en = readl_relaxed(mac + XGMAC_DMA_CH_INT_EN(channel));
	intr_en &= ~XGMAC_DMA_INT_DEFAULT_RX;
	intr_en &= ~XGMAC_DMA_INT_DEFAULT_TX;
	writel_relaxed(intr_en, mac + XGMAC_DMA_CH_INT_EN(channel));
	mgbe_udelay(10);

	readl_relaxed(mac + XGMAC_DMA_CH_STATUS(channel));
	writel_relaxed(0, mac + XGMAC_DMA_CH_STATUS(channel));
}

static void mgbe_dump_regs(struct tegra_mgbe_hyp *mgbe, bool host_to_guest,
			   const char *msg)
{
	pkvm_ops->puts(msg);
	pkvm_ops->puts(host_to_guest ? " direction: host->guest" :
				       " direction: guest->host");
	pkvm_ops->puts(" DMA_MODE:");
	pkvm_ops->putx64(readl_relaxed(mgbe->mac + XGMAC_DMA_MODE));
	pkvm_ops->puts(" TX_CONFIG:");
	pkvm_ops->putx64(readl_relaxed(mgbe->mac + XGMAC_TX_CONFIG));
	pkvm_ops->puts(" RX_CONFIG:");
	pkvm_ops->putx64(readl_relaxed(mgbe->mac + XGMAC_RX_CONFIG));
	pkvm_ops->puts(" UPHY_STATUS:");
	pkvm_ops->putx64(readl_relaxed(mgbe->xpcs + XPCS_WRAP_UPHY_STATUS));
	pkvm_ops->puts(" UPHY_HW_INIT_CTRL:");
	pkvm_ops->putx64(readl_relaxed(mgbe->xpcs + XPCS_WRAP_UPHY_HW_INIT_CTRL));
}

/*
 * Called by the hypervisor with the device lock held, both when the device
 * is assigned to a guest (host_to_guest == true) and when it is reclaimed on
 * guest teardown (host_to_guest == false).
 */
static int mgbe_reset_cb(void *cookie, bool host_to_guest)
{
	struct tegra_mgbe_hyp *mgbe = cookie;
	int ret;
	u32 i;

	if (!mgbe || !mgbe->mac || !mgbe->xpcs)
		return -ENODEV;

	for (i = 0; i < MGBE_NR_DMA_CHANNELS; i++)
		disable_dma_irq(mgbe->mac, i);

	writel_relaxed(0, mgbe->mac + MGBE_WRAP_COMMON_INTR_ENABLE);

	for (i = 0; i < MGBE_NR_DMA_CHANNELS; i++)
		stop_dma(mgbe->mac, i);

	ret = uphy_tx_lane_up(mgbe->xpcs);
	if (ret) {
		mgbe_dump_regs(mgbe, host_to_guest,
			       "tegra234-mgbe: UPHY TX lane bring-up timed out");
		goto out;
	}

	ret = dma_sw_reset(mgbe->mac);
	if (ret)
		mgbe_dump_regs(mgbe, host_to_guest,
			       "tegra234-mgbe: DMA reset timed out");

out:
	/* Make sure the device is quiesced before the caller proceeds. */
	dsb(sy);
	return ret;
}

int tegra234_mgbe_hyp_init(const struct pkvm_module_ops *ops);

int tegra234_mgbe_hyp_init(const struct pkvm_module_ops *ops)
{
	unsigned long base;
	u32 i;
	int ret;

	pkvm_ops = ops;

	if (!mgbe_nr || mgbe_nr > TEGRA234_MGBE_MAX)
		return -EINVAL;

	for (i = 0; i < mgbe_nr; i++) {
		ret = ops->create_private_mapping(mgbe_mac_phys[i],
						  TEGRA234_MGBE_REG_SIZE,
						  PAGE_HYP_DEVICE, &base);
		if (ret)
			return ret;
		mgbe_hyp[i].mac = (void __iomem *)base;

		ret = ops->create_private_mapping(mgbe_xpcs_phys[i],
						  TEGRA234_MGBE_REG_SIZE,
						  PAGE_HYP_DEVICE, &base);
		if (ret)
			return ret;
		mgbe_hyp[i].xpcs = (void __iomem *)base;

		ret = ops->device_register_reset(mgbe_mac_phys[i], &mgbe_hyp[i],
						 mgbe_reset_cb);
		if (ret)
			return ret;
	}

	return 0;
}
