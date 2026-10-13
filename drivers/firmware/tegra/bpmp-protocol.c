// SPDX-License-Identifier: GPL-2.0-only

#include <soc/tegra/bpmp.h>

/*
 * Sender side methods
 * Request and response size are known in advance, and payload buffers are
 * already allocated
 */
int bpmp_message_req_serialize(const struct tegra_bpmp_message *msg,
			       struct tegra_bpmp_req_packed *out)
{
	if (!out || !msg)
		return -EINVAL;

	if (!tegra_bpmp_message_valid(msg))
		return -EINVAL;

	out->mrq = msg->mrq;
	out->flags = msg->flags;
	out->tx_size = msg->tx.size;
	out->rx_size = msg->rx.size;
	if (out->tx_size > 0)
		memcpy(out->tx_data, msg->tx.data, out->tx_size);
	return 0;
}

int bpmp_message_resp_deserialize(const struct tegra_bpmp_resp_packed *resp,
				  struct tegra_bpmp_message *msg)
{
	if (!resp || !msg)
		return -EINVAL;

	if (resp->rx_size > MSG_DATA_MIN_SZ)
		return -EINVAL;

	msg->rx.ret = resp->ret;
	/* message rx size is set by the caller */

	if (resp->rx_size > 0 && msg->rx.data) {
		if (resp->rx_size != msg->rx.size)
			pr_warn("bpmp: size mismatch in deserialize");
		if (resp->rx_size > msg->rx.size)
			return -EMSGSIZE;

		memcpy(msg->rx.data, resp->rx_data, resp->rx_size);
	}
	return 0;
}

/*
 * Receiver side methods.
 * Request and response size are received as input. Buffers must be allocated
 * before forwarding to firmware.
 */
int bpmp_message_req_deserialize(const struct tegra_bpmp_req_packed *req,
				 struct tegra_bpmp_message *msg)
{
	void *tx_buf;

	if (!req || !msg)
		return -EINVAL;

	memset(msg, 0, sizeof(*msg));

	if (req->tx_size > MSG_DATA_MIN_SZ || req->rx_size > MSG_DATA_MIN_SZ)
		return -EMSGSIZE;

	msg->mrq = req->mrq;
	/* explicitely disallow flags from remote sources */
	msg->flags = 0;
	msg->tx.size = req->tx_size;
	msg->rx.size = req->rx_size;
	if (req->tx_size) {
		tx_buf = kmalloc(req->tx_size, GFP_KERNEL);
		if (!tx_buf)
			return -ENOMEM;
		memcpy(tx_buf, req->tx_data, req->tx_size);
		msg->tx.data = tx_buf;
	}
	if (req->rx_size) {
		msg->rx.data = kmalloc(req->rx_size, GFP_KERNEL);
		if (!msg->rx.data)
			return -ENOMEM;
	}
	return 0;
}

int bpmp_message_resp_serialize(const struct tegra_bpmp_message *msg,
				struct tegra_bpmp_resp_packed *out)
{
	if (!out || !msg)
		return -EINVAL;

	if (!tegra_bpmp_message_valid(msg))
		return -EINVAL;

	out->ret = msg->rx.ret;
	out->rx_size = msg->rx.size;
	if (msg->rx.size)
		memcpy(out->rx_data, msg->rx.data, msg->rx.size);

	return 0;
}
