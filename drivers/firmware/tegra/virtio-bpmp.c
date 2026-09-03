// SPDX-License-Identifier: GPL-2.0
/*
 * Device driver for Tegra BPMP over virtio.
 *
 * This driver employs a single virtio queue to handle both send and recv.
 * BPMP messages are sent over virtio to the hypervisor during a BPMP transfer or
 * transfer_atomic operation. The driver then sleeps until the hypervisor notifies
 * that the command has been handled, at which point it copies the response into
 * the input message buffer and returns.
 *
 * While BPMP operation is mostly unidirectional, i.e requests from driver to BPMP,
 * a few MRQs may originate from the BPMP and expect a response from the CPU driver.
 * The `tegra_bpmp_request_mrq` API and `bpmp->mrqs` callbacks in the Tegra platform
 * driver are meant to handle this. Since this driver runs in a KVM guest, it doesn't
 * register itself to handle these MRQs, since the host will receive them first
 * and process them.
 * The MRQs that can be sent by BPMP according to bpmp-abi.h are:
 * 	- MRQ_QUERY_ABI
 * 	- MRQ_THERMAL
 * 	- MRQ_PING
 *
 * The intended hypervisor-side implementation is as follows.
 *
 *     while true:
 *         await next virtio buffer.
 *         expect first descriptor in chain to be guest-to-host.
 *         read BPMP message from that buffer.
 *         synchronously perform BPMP work determined by the command.
 *         expect second descriptor in chain to be host-to-guest.
 *         write BPMP response into that buffer.
 *         place buffer on virtio used queue indicating how many bytes written.
 */

#include <linux/arm-smccc.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/virtio_config.h>
#include <linux/iopoll.h>

#include <uapi/linux/virtio_ids.h>

#include "bpmp-private.h"

struct bpmp_virtio_device {
	/*
	 * Reference to the platform device that implements the tegra_bpmp struct.
	 */
	struct platform_device *pdev;

	/*
	 * Whether a matching DT node exists and was successfully probed.
	 */
	bool platform_probed;

	/*
	 * Virtio queue for sending and receiving BPMP messages.
	 */
	struct virtqueue *vq;

	/*
	 * Lock for writing into virtqueue.
	 */
	spinlock_t vq_lock;

	/*
	 * Completion that is notified when a virtio operation has been
	 * fulfilled by the hypervisor.
	 */
	struct completion complete;

	/*
	 * Whether driver currently holds ownership of the virtqueue buffer.
	 * When false, the hypervisor is in the process of reading or writing
	 * the buffer and the driver must not touch it.
	 */
	bool driver_has_buffer;

	/*
	 * Wait queue to wait for buffer ownership
	 */
	wait_queue_head_t wq_head;
};

struct virtio_bpmp_request {
	struct tegra_bpmp_req_packed req;
	struct tegra_bpmp_resp_packed resp;
};

static int virtio_bpmp_send(struct tegra_bpmp *bpmp,
			    struct tegra_bpmp_message *msg,
			    struct virtio_bpmp_request *req)
{
	struct bpmp_virtio_device *dev = bpmp->priv;
	struct scatterlist *sgs[2], sg_req, sg_resp;
	struct arm_smccc_res smcc_res;
	unsigned long flags;
	int rc;

	/* TODO handle disabled/missing audit driver */
	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_AUDIT_OP_FUNC_ID,
			     KVM_AUDIT_OP_TARGET_BPMP, msg->mrq, 1, 1, &smcc_res);
	if (smcc_res.a0 != SMCCC_RET_SUCCESS && smcc_res.a0 != SMCCC_RET_NOT_SUPPORTED) {
		dev_warn(bpmp->dev, "hypervisor replied with error %ld\n",
			 smcc_res.a0);
	}

	/*
	* pack the message into req struct.
	* Leave response buffer uninitialized, will be filled by virtio device.
	* Message flags (TEGRA_BPMP_MESSAGE_RESET) will be ignored by hypervisor.
	*/
	rc = bpmp_message_req_serialize(msg, &req->req);
	if (rc) {
		dev_err(bpmp->dev,
			"virtio_bpmp_transfer: invalid message. ret = %d\n",
			rc);
		return rc;
	}

	/* out: buffer for request */
	sg_init_one(&sg_req, &req->req, sizeof(req->req));
	sgs[0] = &sg_req;

	/* in: buffer for response */
	sg_init_one(&sg_resp, &req->resp, sizeof(req->resp));
	sgs[1] = &sg_resp;

	spin_lock_irqsave(&dev->vq_lock, flags);
	rc = virtqueue_add_sgs(dev->vq, sgs, 1, 1, req, GFP_ATOMIC);
	if (rc < 0) {
		goto unlock;
	}

	virtqueue_kick(dev->vq);
unlock:
	spin_unlock_irqrestore(&dev->vq_lock, flags);
	return rc;
}

static int virtio_bpmp_process_response(struct device *dev,
					struct tegra_bpmp_message *msg,
					struct virtio_bpmp_request *req,
					int len)
{
	if (!req) {
		dev_err(dev, "virtio_bpmp_send: expected a response buffer\n");
		return -ENODATA;
	}
	if (!len) {
		dev_err(dev,
			"error occurred in host device, returned 0 length buffer\n");
		return -EPROTO;
	}

	long expected = sizeof(struct tegra_bpmp_resp_packed);
	if (len != expected) {
		dev_err(dev,
			"virtio_bpmp_send: response size mismatch,"
			" got %u, expected %lu\n",
			len, expected);
		return -EMSGSIZE;
	}

	return bpmp_message_resp_deserialize(&req->resp, msg);
}

static int virtio_bpmp_transfer(struct tegra_bpmp *bpmp,
				struct tegra_bpmp_message *msg)
{
	struct bpmp_virtio_device *dev = bpmp->priv;
	struct virtio_bpmp_request *req = NULL;
	unsigned long flags;
	unsigned int len;
	int rc;

	if (WARN_ON(irqs_disabled()))
		return -EPERM;

	if (!tegra_bpmp_message_valid(msg)) {
		dev_err(bpmp->dev, "virtio_bpmp_transfer: invalid message.\n");
		return -EINVAL;
	}

	req = devm_kzalloc(bpmp->dev, sizeof(struct virtio_bpmp_request),
			   GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	if ((rc = virtio_bpmp_send(bpmp, msg, req)))
		return rc;

	/* In non-interrupt context we can use completion primitives */
	wait_for_completion(&dev->complete);

	/* Completion occurred. Expect response buffer back. */
	spin_lock_irqsave(&dev->vq_lock, flags);
	req = virtqueue_get_buf(dev->vq, &len);
	spin_unlock_irqrestore(&dev->vq_lock, flags);

	if ((rc = virtio_bpmp_process_response(bpmp->dev, msg, req, len)))
		return rc;

	return 0;
}

static int virtio_bpmp_transfer_atomic(struct tegra_bpmp *bpmp,
				       struct tegra_bpmp_message *msg)
{
	struct bpmp_virtio_device *dev = bpmp->priv;
	struct virtio_bpmp_request *req = NULL;
	unsigned int len;
	int rc;

	if (WARN_ON(!irqs_disabled()))
		return -EPERM;

	if (!tegra_bpmp_message_valid(msg)) {
		dev_err(bpmp->dev, "virtio_bpmp_transfer: invalid message.\n");
		return -EINVAL;
	}

	req = devm_kzalloc(bpmp->dev, sizeof(struct virtio_bpmp_request),
			   GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	if ((rc = virtio_bpmp_send(bpmp, msg, req)))
		return rc;

	req = NULL;
	ktime_t timeout = ktime_add_us(ktime_get(), 10 * USEC_PER_MSEC);
	/*
	 * Mirror the busy-loop from host driver transfer_atomic. This is not great performance-wise
	 * since it wastes CPU cycles, but there is not much we can do with IRQs off.
	 */
	do {
		spin_lock(&dev->vq_lock);
		req = virtqueue_get_buf(dev->vq, &len);
		spin_unlock(&dev->vq_lock);
		if (req)
			break;
		udelay(10);
	} while (ktime_before(ktime_get(), timeout));

	if ((rc = virtio_bpmp_process_response(bpmp->dev, msg, req, len)))
		return rc;

	return 0;
}

static int virtio_bpmp_ops_init(struct tegra_bpmp *bpmp)
{
	return 0;
}

static void virtio_bpmp_ops_deinit(struct tegra_bpmp *bpmp)
{
	/* noop */
}

static bool virtio_bpmp_ops_is_message_ready(struct tegra_bpmp_channel *channel)
{
	/* this should never run */
	WARN_ON_ONCE(true);
	return true;
}

static int virtio_bpmp_ops_ack_message(struct tegra_bpmp_channel *channel)
{
	/* this should never run */
	WARN_ON_ONCE(true);
	return 0;
}

static bool virtio_bpmp_ops_is_channel_free(struct tegra_bpmp_channel *channel)
{
	/* this should never run */
	WARN_ON_ONCE(true);
	return true;
}

static int virtio_bpmp_ops_post_message(struct tegra_bpmp_channel *channel)
{
	/* this should never run */
	WARN_ON_ONCE(true);
	return 0;
}

static int virtio_bpmp_ops_ring_doorbell(struct tegra_bpmp *bpmp)
{
	/* this should never run */
	WARN_ON_ONCE(true);
	return 0;
}

static int virtio_bpmp_ops_resume(struct tegra_bpmp *bpmp)
{
	/* this should never run */
	WARN_ON_ONCE(true);
	return 0;
}

#define BPMP_FW_TAG_SIZE 32

const struct tegra_bpmp_ops virtio_bpmp_ops = {
	.init = virtio_bpmp_ops_init,
	.deinit = virtio_bpmp_ops_deinit,
	.is_response_ready = virtio_bpmp_ops_is_message_ready,
	.is_request_ready = virtio_bpmp_ops_is_message_ready,
	.ack_response = virtio_bpmp_ops_ack_message,
	.ack_request = virtio_bpmp_ops_ack_message,
	.is_response_channel_free = virtio_bpmp_ops_is_channel_free,
	.is_request_channel_free = virtio_bpmp_ops_is_channel_free,
	.post_response = virtio_bpmp_ops_post_message,
	.post_request = virtio_bpmp_ops_post_message,
	.ring_doorbell = virtio_bpmp_ops_ring_doorbell,
	.resume = virtio_bpmp_ops_resume,
};

static const struct tegra_bpmp_soc virtio_soc = {
	.ops = &virtio_bpmp_ops,
	.num_resets = 193,
};

static const struct tegra_bpmp_transfer_ops virtio_bpmp_transfer_ops = {
	.transfer_atomic = virtio_bpmp_transfer_atomic,
	.transfer = virtio_bpmp_transfer,
};

static struct bpmp_virtio_device *g_bpmp_virt_dev;

static int bpmp_virt_platform_probe(struct platform_device *pdev)
{
	struct tegra_bpmp *bpmp;
	char tag[BPMP_FW_TAG_SIZE];
	int err;

	bpmp = devm_kzalloc(&pdev->dev, sizeof(*bpmp), GFP_KERNEL);
	if (!bpmp)
		return -ENOMEM;

	bpmp->soc = &virtio_soc;
	bpmp->transfer_ops = &virtio_bpmp_transfer_ops;
	bpmp->dev = &pdev->dev;
	/* init mrqs and lock because they are accessed in exported functions (although unused by our
	 * driver) */
	INIT_LIST_HEAD(&bpmp->mrqs);
	spin_lock_init(&bpmp->lock);

	/* Ugly workaround to later retrieve the virtio device from the platform device */
	bpmp->priv = g_bpmp_virt_dev;
	platform_set_drvdata(pdev, bpmp);

	err = bpmp->soc->ops->init(bpmp);
	if (err < 0)
		return err;

	err = tegra_bpmp_ping(bpmp);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to ping BPMP: %d\n", err);
		goto deinit;
	}

	err = tegra_bpmp_get_firmware_tag(bpmp, tag, sizeof(tag));
	if (err < 0) {
		dev_err(&pdev->dev, "failed to get firmware tag: %d\n", err);
		goto deinit;
	}
	dev_info(&pdev->dev, "firmware: %.*s\n", (int)sizeof(tag), tag);

	if (of_property_present(pdev->dev.of_node, "#clock-cells")) {
		err = tegra_bpmp_init_clocks(bpmp);
		if (err < 0)
			goto deinit;
	}

	if (of_property_present(pdev->dev.of_node, "#reset-cells")) {
		err = tegra_bpmp_init_resets(bpmp);
		if (err < 0)
			goto deinit;
	}

	if (of_property_present(pdev->dev.of_node, "#power-domain-cells")) {
		err = tegra_bpmp_init_powergates(bpmp);
		if (err < 0)
			goto deinit;
	}

	dev_info(&pdev->dev, "bpmp virt platform initialized\n");
	g_bpmp_virt_dev->platform_probed = true;
	return 0;

deinit:
	if (bpmp->soc->ops->deinit)
		bpmp->soc->ops->deinit(bpmp);
	dev_err(&pdev->dev,
		"failed to initialize bpmp virt platform driver: %d\n", err);
	return err;
}

static void bpmp_virt_platform_remove(struct platform_device *pdev)
{
	struct tegra_bpmp *bpmp = platform_get_drvdata(pdev);

	if (bpmp->soc->ops->deinit)
		bpmp->soc->ops->deinit(bpmp);
}

static const struct of_device_id bpmp_virt_of_match[] = {
	{ .compatible = "nvidia,tegra-bpmp-virtio" },
	{}
};

static struct platform_driver bpmp_virt_platform_driver = {
	.driver = {
		.name = "tegra-bpmp-virtio",
		.of_match_table = bpmp_virt_of_match,
	},
	.probe = bpmp_virt_platform_probe,
	.remove = bpmp_virt_platform_remove,
};

static void virtio_bpmp_recv_cb(struct virtqueue *vq)
{
	struct bpmp_virtio_device *dev = vq->vdev->priv;

	complete(&dev->complete);
}

static int virtio_bpmp_probe(struct virtio_device *vdev)
{
	int err;
	struct bpmp_virtio_device *dev;
	struct virtqueue *vq;

	dev = devm_kzalloc(&vdev->dev, sizeof(struct bpmp_virtio_device),
			   GFP_KERNEL);
	if (!dev) {
		err = -ENOMEM;
		dev_err(&vdev->dev, "failed kzalloc\n");
		goto exit;
	}

	vdev->priv = dev;
	g_bpmp_virt_dev = dev;

	vq = virtio_find_single_vq(vdev, virtio_bpmp_recv_cb, "bpmp");
	if (IS_ERR(vq)) {
		err = PTR_ERR(vq);
		dev_err(&vdev->dev, "failed virtio_find_single_vq\n");
		goto free_dev;
	}
	dev->vq = vq;
	dev->platform_probed = false;
	spin_lock_init(&dev->vq_lock);
	init_completion(&dev->complete);
	/* unused */
	init_waitqueue_head(&dev->wq_head);
	dev->driver_has_buffer = true;

	virtio_device_ready(vdev);

	/* Platform driver is probed after the virtqueue was initialized because it sends a ping MRQ */
	err = platform_driver_register(&bpmp_virt_platform_driver);
	if (err) {
		dev_err(&vdev->dev,
			"failed to register bpmp platform driver: %d\n", err);
		goto free_dev;
	}

	if (!dev->platform_probed) {
		dev_info(&vdev->dev,
			 "platform driver registered device probe failed. "
			 "This could be caused by a missing DT node\n");
		err = -ENODEV;
		goto free_dev;
	}
	dev_info(&vdev->dev, "driver initialized successfully\n");
	return 0;

free_dev:
	vdev->priv = NULL;
	g_bpmp_virt_dev = NULL;
exit:
	return err;
}

static void virtio_bpmp_remove(struct virtio_device *vdev)
{
	struct bpmp_virtio_device *dev = vdev->priv;
	void *buf;

	platform_driver_unregister(&bpmp_virt_platform_driver);

	virtio_reset_device(vdev);

	/* detach unused buffers */
	while ((buf = virtqueue_detach_unused_buf(dev->vq)) != NULL) {
		kfree(buf);
	}
	/* remove virtqueues */
	vdev->config->del_vqs(vdev);

	g_bpmp_virt_dev = NULL;
	dev_info(&vdev->dev, "driver removed successfully\n");
}

static struct virtio_device_id id_table[] = {
	{
		.device = VIRTIO_ID_BPMP,
		.vendor = VIRTIO_DEV_ANY_ID,
	},
	{},
};

static struct virtio_driver bpmp_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtio_bpmp_probe,
	.remove = virtio_bpmp_remove,
};
module_virtio_driver(bpmp_driver);

MODULE_AUTHOR("Hugo Ros <Hugo.Ros@tii.ae>");
MODULE_DESCRIPTION("Virtio BPMP Driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
