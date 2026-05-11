/* SPDX-License-Identifier: GPL-2.0 */
/*
 * To probe this driver, add a matching node to your platform device tree.
 *
	bpmp_host_proxy: bpmp_host_proxy {
		compatible = "nvidia,bpmp-host-proxy";
		nvidia,bpmp = <&bpmp>;
		allowed-clocks = <TEGRA234_CLK_UARTA>;
		allowed-resets = <TEGRA234_RESET_UARTA>;
		status = "okay";
	};
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "linux/of_platform.h"
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/platform_device.h>

#include <soc/tegra/bpmp.h>

#include "bpmp-private.h"

#define BPMP_HOST_MAX_CLOCKS_SIZE 256
#define BPMP_HOST_MAX_RESETS_SIZE 256

struct bpmp_allowed_res {
	int clocks_size;
	uint32_t clock[BPMP_HOST_MAX_CLOCKS_SIZE];
	int resets_size;
	uint32_t reset[BPMP_HOST_MAX_RESETS_SIZE];
};

#define DEVICE_NAME "bpmp_host"
#define CLASS_NAME "bpmp"

static int major_number;
static struct class *bpmp_host_proxy_class = NULL;
static struct device *bpmp_host_proxy_device = NULL;

static struct bpmp_allowed_res bpmp_ares;

static struct tegra_bpmp *bpmp = NULL;

enum transfer_status {
	TRANSFER_NONE,
	TRANSFER_PREPARE,
	TRANSFER_START,
};

struct bpmp_transaction_ctx {
	struct tegra_bpmp_message msg;
	/* Shared lock for reads and writes.
	 * We don't expect any concurrency within the same transaction. */
	struct mutex lock;
	enum transfer_status transfer_status;
	int write_status;
};

static bool check_if_allowed(struct tegra_bpmp_message *msg)
{
	struct mrq_reset_request *reset_req = NULL;
	struct mrq_clk_request *clock_req = NULL;
	struct mrq_pg_request *pg_req = NULL;
	uint32_t clk_cmd;
	int i;

	switch (msg->mrq) {
	case MRQ_PING:
	case MRQ_QUERY_TAG:
	case MRQ_THREADED_PING:
	case MRQ_QUERY_ABI:
	case MRQ_QUERY_FW_TAG:
		return true;

	case MRQ_PG:
		pg_req = (struct mrq_pg_request *)msg->tx.data;

		pr_alert("got powergate MRQ: cmd = %d, id = %d\n", pg_req->cmd,
			 pg_req->id);
		/* allow everything except SET_STATE */
		if (pg_req->cmd == CMD_PG_QUERY_ABI ||
		    pg_req->cmd == CMD_PG_GET_STATE ||
		    pg_req->cmd == CMD_PG_GET_NAME ||
		    pg_req->cmd == CMD_PG_GET_MAX_ID)
			return true;
		break;

	case MRQ_RESET:
		reset_req = (struct mrq_reset_request *)msg->tx.data;

		for (i = 0; i < bpmp_ares.resets_size; i++) {
			if (bpmp_ares.reset[i] == reset_req->reset_id) {
				return true;
			}
		}
		pr_err("Error, reset not allowed for: %d", reset_req->reset_id);
		break;

	case MRQ_CLK:
		clock_req = (struct mrq_clk_request *)msg->tx.data;

		for (i = 0; i < bpmp_ares.clocks_size; i++) {
			if (bpmp_ares.clock[i] ==
			    (clock_req->cmd_and_id & 0x0FFF)) {
				return true;
			}
		}

		clk_cmd = (clock_req->cmd_and_id >> 24) & 0x000F;

		if (clk_cmd == CMD_CLK_GET_MAX_CLK_ID ||
		    clk_cmd == CMD_CLK_GET_ALL_INFO ||
		    clk_cmd == CMD_CLK_GET_PARENT) {
			return true;
		}

		pr_err("Error, clock not allowed for: %d, with command: %d",
		       clock_req->cmd_and_id & 0x0FFF, clk_cmd);
		break;

	default:
		pr_err("Error, msg->mrq %d not allowed", msg->mrq);
		break;
	}

	return false;
}

static ssize_t write(struct file *filep, const char *buffer, size_t len,
		     loff_t *offset)
{
	struct tegra_bpmp_req_packed req;
	struct bpmp_transaction_ctx *ctx;
	int ret;

	if (!filep->private_data) {
		pr_err("failed to get fd context\n");
		return -ENOENT;
	}
	ctx = filep->private_data;

	if (mutex_lock_interruptible(&ctx->lock))
		return -EBUSY;

	ctx->transfer_status = TRANSFER_PREPARE;

	if (!bpmp) {
		pr_err("host device not initialised, can't do transfer!");
		ret = -ENODEV;
		goto unlock;
	}

	if (len != sizeof(req)) {
		pr_err("expected packed message of size %lu, got %zu",
		       sizeof(req), len);
		ret = -EINVAL;
		goto unlock;
	}

	pr_info("wants to write %zu bytes\n", len);

	ret = copy_from_user(&req, buffer, len);
	if (ret) {
		pr_err("copy_from_user(1) failed\n");
		goto unlock;
	}

	ret = bpmp_message_req_deserialize(&req, &ctx->msg);
	if (ret)
		goto unlock;

	print_hex_dump_bytes("msg: ", DUMP_PREFIX_OFFSET, &ctx->msg,
			     sizeof(ctx->msg));
	// hexDump(DEVICE_NAME ": msg", &ctx->msg, sizeof(ctx->msg));

	if (!check_if_allowed(&ctx->msg)) {
		ret = -EPERM;
		goto unlock;
	}

	ctx->transfer_status = TRANSFER_START;
	ret = tegra_bpmp_transfer(bpmp, &ctx->msg);
	if (!ret)
		ret = len;

unlock:
	pr_info("write: ret = %d\n", ret);
	ctx->write_status = ret;
	mutex_unlock(&ctx->lock);
	return ret;
}

static ssize_t read(struct file *filep, char *buffer, size_t len,
		    loff_t *offset)
{
	struct tegra_bpmp_resp_packed resp;
	struct bpmp_transaction_ctx *ctx;
	int ret;

	if (!filep->private_data) {
		pr_err("failed to get fd context\n");
		return -ENOENT;
	}
	ctx = filep->private_data;

	if (mutex_lock_interruptible(&ctx->lock))
		return -EBUSY;

	switch (ctx->transfer_status) {
	case TRANSFER_NONE:
		pr_err("tried to read before sending a command\n");
		ctx->msg.rx.ret = -BPMP_TRANSPORT_ENODATA;
		break;
	case TRANSFER_PREPARE:
		pr_err("write op returned an error: %d\n", ctx->write_status);
		ctx->msg.rx.ret = ctx->write_status - BPMP_TRANSPORT_ERRCODE_OFFSET;
		break;
	case TRANSFER_START:
		/* ctx->msg is properly setup */
		break;
	}

	if (len < ctx->msg.rx.size) {
		pr_err("read buffer is too small to copy response\n");
		/* attempt to recover by copying at least a status code. But really this is
		 * a bug in the caller */
		if (len >= sizeof(u32)) {
			s32 rc = -BPMP_TRANSPORT_EINVAL;
			ret = copy_to_user(buffer, &rc, sizeof(rc));
			if (!ret)
				ret = sizeof(rc);
			goto unlock;
		} else {
			/* can't copy anything, hard error */
			ret = -ENOBUFS;
			goto unlock;
		}
	}
	ret = bpmp_message_resp_serialize(&ctx->msg, &resp);
	if (ret) {
		resp.ret = -BPMP_TRANSPORT_EBADMSG;
		resp.rx_size = 0;
	}

	ret = copy_to_user(buffer, &resp, sizeof(resp));
	if (ret)
		goto unlock;

	if (ctx->msg.tx.data) {
		kfree(ctx->msg.tx.data);
		ctx->msg.tx.data = NULL;
	}
	if (ctx->msg.rx.data) {
		kfree(ctx->msg.rx.data);
		ctx->msg.rx.data = NULL;
	}
	ctx->transfer_status = TRANSFER_NONE;
	ctx->write_status = 0;
	ret = sizeof(resp);

unlock:
	mutex_unlock(&ctx->lock);
	return ret;
}

static int open(struct inode *inodep, struct file *filep)
{
	struct bpmp_transaction_ctx *ctx;

	if (!bpmp) {
		pr_err("host device not initialised, can't do transfer!");
		return -EFAULT;
	}
	ctx = kzalloc(sizeof(struct bpmp_transaction_ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	mutex_init(&ctx->lock);
	ctx->transfer_status = TRANSFER_NONE;

	filep->private_data = ctx;
	pr_info("device opened.\n");
	return 0;
}

static int close(struct inode *inodep, struct file *filep)
{
	if (filep->private_data)
		kfree(filep->private_data);
	filep->private_data = NULL;
	pr_info("device closed.\n");
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = open,
	.release = close,
	.read = read,
	.write = write,
};


static int bpmp_host_proxy_probe(struct platform_device *pdev)
{
	int err, i;

	dev_info(&pdev->dev, "%s, installing module.", __func__);

	/* Get a reference to the bpmp device via the device tree
		nvidia,bpmp = <&bpmp>; */
	bpmp = tegra_bpmp_get(&pdev->dev);
	err = PTR_ERR_OR_ZERO(bpmp);
	if (err) {
		pr_err("tegra_bpmp_get returned error: %d\n", err);
		return err;
	}

	bpmp_ares.clocks_size = of_property_read_variable_u32_array(
		pdev->dev.of_node, "allowed-clocks", bpmp_ares.clock, 0,
		BPMP_HOST_MAX_CLOCKS_SIZE);

	if (bpmp_ares.clocks_size <= 0) {
		dev_err(&pdev->dev, "No allowed clocks defined");
		err = -EINVAL;
		goto bpmp_put;
	}

	dev_info(&pdev->dev, "bpmp_ares.clocks_size: %d",
		 bpmp_ares.clocks_size);
	for (i = 0; i < bpmp_ares.clocks_size; i++) {
		dev_info(&pdev->dev, "bpmp_ares.clock %d", bpmp_ares.clock[i]);
	}

	bpmp_ares.resets_size = of_property_read_variable_u32_array(
		pdev->dev.of_node, "allowed-resets", bpmp_ares.reset, 0,
		BPMP_HOST_MAX_RESETS_SIZE);

	if (bpmp_ares.resets_size <= 0) {
		dev_err(&pdev->dev, "No allowed resets defined");
		err = -EINVAL;
		goto bpmp_put;
	}

	dev_info(&pdev->dev, "bpmp_ares.resets_size: %d",
		 bpmp_ares.resets_size);
	for (i = 0; i < bpmp_ares.resets_size; i++) {
		dev_info(&pdev->dev, "bpmp_ares.reset %d", bpmp_ares.reset[i]);
	}

	major_number = register_chrdev(0, DEVICE_NAME, &fops);
	if (major_number < 0) {
		dev_err(&pdev->dev, "could not register number.\n");
		err = major_number;
		goto bpmp_put;
	}
	dev_info(&pdev->dev, "registered correctly with major number %d\n",
		 major_number);

	bpmp_host_proxy_class = class_create(CLASS_NAME);
	err = PTR_ERR_OR_ZERO(bpmp_host_proxy_class);
	if (err) {
		dev_err(&pdev->dev, "Failed to register device class\n");
		goto fail_class;
	}
	dev_info(&pdev->dev, "device class registered correctly\n");

	bpmp_host_proxy_device = device_create(bpmp_host_proxy_class, NULL,
					       MKDEV(major_number, 0), NULL,
					       DEVICE_NAME);
	err = PTR_ERR_OR_ZERO(bpmp_host_proxy_device);
	if (err) {
		dev_err(&pdev->dev, "Failed to create the device\n");
		goto fail_create;
	}

	dev_info(&pdev->dev, "device created correctly\n");
	return 0;

fail_create:
	class_destroy(bpmp_host_proxy_class);
fail_class:
	unregister_chrdev(major_number, DEVICE_NAME);
bpmp_put:
	tegra_bpmp_put(bpmp);
	return err;
}

static void bpmp_host_proxy_remove(struct platform_device *pdev)
{
	dev_info(&pdev->dev, "driver unloaded.");
	device_destroy(bpmp_host_proxy_class, MKDEV(major_number, 0));
	class_unregister(bpmp_host_proxy_class);
	class_destroy(bpmp_host_proxy_class);
	unregister_chrdev(major_number, DEVICE_NAME);
	tegra_bpmp_put(bpmp);
}

static const struct of_device_id bpmp_host_proxy_ids[] = {
	{ .compatible = "nvidia,bpmp-host-proxy" },
	{},
};

static struct platform_driver bpmp_host_proxy_driver = {
	.driver = {
		.name = "bpmp_host_proxy",
		.of_match_table = bpmp_host_proxy_ids,
	},
	.probe = bpmp_host_proxy_probe,
	.remove = bpmp_host_proxy_remove,
};
builtin_platform_driver(bpmp_host_proxy_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hugo Ros");
MODULE_DESCRIPTION("BPMP host proxy");
MODULE_VERSION("0.1");
