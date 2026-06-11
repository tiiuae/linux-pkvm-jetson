/* SPDX-License-Identifier: GPL-2.0 */
/*
 * To probe this driver, add a matching node to your platform device tree.
 *
 *	bpmp_host_proxy: bpmp_host_proxy {
 *		compatible = "nvidia,bpmp-host-proxy";
 *		nvidia,bpmp = <&bpmp>;
 *		allowed-clocks = <TEGRA234_CLK_UARTA>;
 *		allowed-resets = <TEGRA234_RESET_UARTA>;
 *		allowed-power-domains = <TEGRA234_POWER_DOMAIN_DISP>;
 *		status = "okay";
 *	};
 *
 * As an alternative to listing the resource ids one by one (clocks, resets & power domains),
 * especially for devices that need access to many clocks, the `allowed-devices` property can
 * be used with a list of phandles.
 *
 *	bpmp_host_proxy: bpmp_host_proxy {
 *		compatible = "nvidia,bpmp-host-proxy";
 *		nvidia,bpmp = <&bpmp>;
 *		allowed-devices = <&ga10b &host1x_pt &vic_b &nvdec_b &nvjpg_b &nvdisplay>;
 *		status = "okay";
 *	};
 *
 * If both allowed-devices and allowed-{clocks,resets,power-domains} are specified, the resulting
 * allow list is the union of the two arrays.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "linux/of_platform.h"
#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/platform_device.h>

#include <soc/tegra/bpmp.h>

#include "bpmp-private.h"

#define BPMP_HOST_MAX_CLOCKS_SIZE 128
#define BPMP_HOST_MAX_RESETS_SIZE 64
#define BPMP_HOST_MAX_PGS_SIZE 64

struct bpmp_allowed_res {
	int clocks_size;
	uint32_t clock[BPMP_HOST_MAX_CLOCKS_SIZE];
	int clock_parents_size;
	/* Flat list of transitively allowed clocks */
	uint32_t *clock_parents;
	int resets_size;
	uint32_t reset[BPMP_HOST_MAX_RESETS_SIZE];
	int pgs_size;
	uint32_t pgs[BPMP_HOST_MAX_PGS_SIZE];
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
	/* Shared lock for reads and writes.
	 * We don't expect any concurrency within the same transaction. */
	struct mutex lock;
	struct tegra_bpmp_message msg;
	enum transfer_status transfer_status;
	int write_status;
};

/*
 * Releases memory allocated for tx and rx buffers. Should be done before a new
 * call to bpmp_message_req_deserialize, and when cleaning up a transaction.
 * This must be called with ctx->lock held.
 */
static void bpmp_transaction_free_msg_buffers(struct bpmp_transaction_ctx *ctx)
{
	if (ctx->msg.tx.data) {
		kfree(ctx->msg.tx.data);
		ctx->msg.tx.data = NULL;
	}
	if (ctx->msg.rx.data) {
		kfree(ctx->msg.rx.data);
		ctx->msg.rx.data = NULL;
	}
}

static int tegra_bpmp_clk_get_info(struct tegra_bpmp *bpmp, unsigned int id,
				   struct cmd_clk_get_all_info_response *info)
{
	struct mrq_clk_request req = {
		.cmd_and_id = ((uint32_t)CMD_CLK_GET_ALL_INFO << 24) | id,
	};
	struct tegra_bpmp_message msg = {
		.mrq = MRQ_CLK,
		.tx = { .data = &req, .size = sizeof(req) },
		.rx = { .data = info, .size = sizeof(*info) },
	};

	return tegra_bpmp_transfer(bpmp, &msg);
}

static bool check_if_allowed(struct tegra_bpmp_message *msg)
{
	struct mrq_reset_request *reset_req = NULL;
	struct mrq_clk_request *clock_req = NULL;
	struct mrq_pg_request *pg_req = NULL;
	uint32_t clk_cmd, clk_id;
	int i;

	switch (msg->mrq) {
	case MRQ_PING:
	case MRQ_THREADED_PING:
	case MRQ_QUERY_ABI:
	case MRQ_QUERY_FW_TAG:
	case MRQ_STRAP:
		return true;

	case MRQ_PG:
		pg_req = (struct mrq_pg_request *)msg->tx.data;

		pr_debug("got powergate MRQ: cmd = %d, id = %d\n", pg_req->cmd,
			 pg_req->id);
		/* allow everything except SET_STATE */
		if (pg_req->cmd == CMD_PG_QUERY_ABI ||
		    pg_req->cmd == CMD_PG_GET_STATE ||
		    pg_req->cmd == CMD_PG_GET_NAME ||
		    pg_req->cmd == CMD_PG_GET_MAX_ID)
			return true;

		/* allow SET_STATE for specific ids */
		for (i = 0; i < bpmp_ares.pgs_size; i++) {
			if (bpmp_ares.pgs[i] == pg_req->id) {
				return true;
			}
		}
		pr_warn("powergate not allowed for %d, with command %d\n",
			pg_req->id, pg_req->cmd);
		break;

	case MRQ_RESET:
		reset_req = (struct mrq_reset_request *)msg->tx.data;

		for (i = 0; i < bpmp_ares.resets_size; i++) {
			if (bpmp_ares.reset[i] == reset_req->reset_id) {
				return true;
			}
		}

		if (reset_req->cmd == CMD_RESET_GET_MAX_ID)
			return true;

		pr_warn("reset not allowed for: %d\n", reset_req->reset_id);
		break;

	case MRQ_CLK:
		clock_req = (struct mrq_clk_request *)msg->tx.data;
		clk_id = clock_req->cmd_and_id & 0x0FFF;
		clk_cmd = (clock_req->cmd_and_id >> 24) & 0x000F;

		pr_debug("Got command: %d for clock %d\n", clk_cmd, clk_id);

		for (i = 0; i < bpmp_ares.clocks_size; i++) {
			if (bpmp_ares.clock[i] == clk_id)
				return true;
		}

		if (clk_cmd == CMD_CLK_ENABLE) {
			for (i = 0; i < bpmp_ares.clock_parents_size; i++) {
				if (bpmp_ares.clock_parents[i] == clk_id)
					return true;
			}
		}

		if (clk_cmd == CMD_CLK_GET_MAX_CLK_ID ||
		    clk_cmd == CMD_CLK_GET_ALL_INFO ||
		    clk_cmd == CMD_CLK_GET_PARENT ||
		    clk_cmd == CMD_CLK_GET_RATE) {
			return true;
		}

		pr_warn("clock not allowed for: %d, with command: %d\n", clk_id,
			clk_cmd);
		break;

	default:
		pr_warn("msg->mrq %d not allowed\n", msg->mrq);
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
	/* In case userspace called write() twice in a row without reading the response. (which is
	   an incorrect but allowed use of the driver) */
	bpmp_transaction_free_msg_buffers(ctx);

	if (!bpmp) {
		pr_err("host device not initialised, can't do transfer!\n");
		ret = -ENODEV;
		goto unlock;
	}
	if (len != sizeof(req)) {
		pr_err("expected packed message of size %lu, got %zu\n",
		       sizeof(req), len);
		ret = -EINVAL;
		goto unlock;
	}

	pr_debug("wants to write %zu bytes\n", len);

	ret = copy_from_user(&req, buffer, len);
	if (ret) {
		pr_err("copy_from_user of %lu bytes failed\n", len);
		goto unlock;
	}

	ret = bpmp_message_req_deserialize(&req, &ctx->msg);
	if (ret)
		goto unlock;

	print_hex_dump_bytes("msg: ", DUMP_PREFIX_OFFSET, &ctx->msg,
			     sizeof(ctx->msg));

	if (!check_if_allowed(&ctx->msg)) {
		ret = -EPERM;
		goto unlock;
	}
	ctx->transfer_status = TRANSFER_START;
	ret = tegra_bpmp_transfer(bpmp, &ctx->msg);
	if (!ret)
		ret = len;

unlock:
	pr_debug("write: ret = %d\n", ret);
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
		pr_err_once("error: tried to read before sending a command\n");
		ctx->msg.rx.ret = -BPMP_TRANSPORT_ENODATA;
		break;
	case TRANSFER_PREPARE:
		pr_devel("write op returned an error: %d\n", ctx->write_status);
		ctx->msg.rx.ret =
			ctx->write_status - BPMP_TRANSPORT_ERRCODE_OFFSET;
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

	bpmp_transaction_free_msg_buffers(ctx);
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
		pr_err("host device not initialised, can't do transfer!\n");
		return -EFAULT;
	}
	ctx = kzalloc(sizeof(struct bpmp_transaction_ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	mutex_init(&ctx->lock);
	ctx->transfer_status = TRANSFER_NONE;

	filep->private_data = ctx;
	pr_debug("device opened\n");
	return 0;
}

static int release(struct inode *inodep, struct file *filep)
{
	struct bpmp_transaction_ctx *ctx = filep->private_data;
	filep->private_data = NULL;

	if (ctx) {
		mutex_lock(&ctx->lock);
		bpmp_transaction_free_msg_buffers(ctx);
		mutex_unlock(&ctx->lock);

		mutex_destroy(&ctx->lock);
		kfree(ctx);
	}
	pr_debug("device closed\n");
	return 0;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = open,
	.release = release,
	.read = read,
	.write = write,
};

static ssize_t allowed_clocks_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	int i;

	for (i = 0; i < bpmp_ares.clocks_size; i++)
		len += sysfs_emit_at(buf, len, "%u\n", bpmp_ares.clock[i]);
	return len;
}
static DEVICE_ATTR_RO(allowed_clocks);

static ssize_t allowed_resets_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	int i;

	for (i = 0; i < bpmp_ares.resets_size; i++)
		len += sysfs_emit_at(buf, len, "%u\n", bpmp_ares.reset[i]);
	return len;
}
static DEVICE_ATTR_RO(allowed_resets);

static ssize_t allowed_power_domains_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	ssize_t len = 0;
	int i;

	for (i = 0; i < bpmp_ares.pgs_size; i++)
		len += sysfs_emit_at(buf, len, "%u\n", bpmp_ares.pgs[i]);
	return len;
}
static DEVICE_ATTR_RO(allowed_power_domains);

static struct attribute *bpmp_host_proxy_attrs[] = {
	&dev_attr_allowed_clocks.attr,
	&dev_attr_allowed_resets.attr,
	&dev_attr_allowed_power_domains.attr,
	NULL,
};
ATTRIBUTE_GROUPS(bpmp_host_proxy);

static int bpmp_host_parse_prop_spec(const struct device_node *np,
				     const char *list_name,
				     const char *cells_name,
				     uint32_t *out_values, int *out_size,
				     int max_size)
{
	struct of_phandle_args pargs;
	int idx = 0;

	while (!of_parse_phandle_with_args(np, list_name, cells_name, idx,
					   &pargs)) {
		uint32_t bpmp_res_id = pargs.args[0];
		of_node_put(pargs.np);
		idx++;

		if (*out_size >= max_size) {
			pr_err("allow list has reached max capacity: %d\n",
			       max_size);
			return -ENOMEM;
		}

		pr_devel("device %s allowed clock: %u\n", np->name,
			 bpmp_res_id);
		out_values[*out_size] = bpmp_res_id;
		(*out_size)++;
	}

	return 0;
}

static int bpmp_host_parse_allowed_devices(struct platform_device *pdev)
{
	struct of_phandle_args args;
	int idx = 0;
	int ret;

	while (!of_parse_phandle_with_fixed_args(
		pdev->dev.of_node, "allowed-devices", 0, idx, &args)) {
		struct device_node *client_dev = args.np;
		idx++;

		ret = bpmp_host_parse_prop_spec(client_dev, "clocks",
						"#clock-cells", bpmp_ares.clock,
						&bpmp_ares.clocks_size,
						BPMP_HOST_MAX_CLOCKS_SIZE);
		if (ret) {
			of_node_put(args.np);
			return ret;
		}

		ret = bpmp_host_parse_prop_spec(client_dev, "resets",
						"#reset-cells", bpmp_ares.reset,
						&bpmp_ares.resets_size,
						BPMP_HOST_MAX_RESETS_SIZE);
		if (ret) {
			of_node_put(args.np);
			return ret;
		}

		ret = bpmp_host_parse_prop_spec(client_dev, "power-domains",
						"#power-domain-cells",
						bpmp_ares.pgs,
						&bpmp_ares.pgs_size,
						BPMP_HOST_MAX_PGS_SIZE);

		of_node_put(args.np);
		if (ret)
			return ret;
	}

	return 0;
}

static void init_array_from_property(struct device *dev, const char *propname,
				     u32 *out_values, int *out_size,
				     int max_size)
{
	*out_size = of_property_read_variable_u32_array(
		dev->of_node, propname, out_values, 0, max_size);
	if (*out_size < 0) {
		dev_err_probe(dev, *out_size, "failed to parse property %s\n",
			      propname);
		*out_size = 0;
	}
}

static int bpmp_host_proxy_probe(struct platform_device *pdev)
{
	int err, i, j;

	dev_info(&pdev->dev, "%s, installing module.\n", __func__);

	/* Get a reference to the bpmp device via the device tree
		nvidia,bpmp = <&bpmp>; */
	bpmp = tegra_bpmp_get(&pdev->dev);
	err = PTR_ERR_OR_ZERO(bpmp);
	if (err) {
		return dev_err_probe(&pdev->dev, err,
				     "tegra_bpmp_get returned error\n");
	}

	init_array_from_property(&pdev->dev, "allowed-clocks", bpmp_ares.clock,
				 &bpmp_ares.clocks_size,
				 BPMP_HOST_MAX_CLOCKS_SIZE);
	init_array_from_property(&pdev->dev, "allowed-resets", bpmp_ares.reset,
				 &bpmp_ares.resets_size,
				 BPMP_HOST_MAX_RESETS_SIZE);
	init_array_from_property(&pdev->dev, "allowed-power-domains",
				 bpmp_ares.pgs, &bpmp_ares.pgs_size,
				 BPMP_HOST_MAX_PGS_SIZE);

	err = bpmp_host_parse_allowed_devices(pdev);
	if (err) {
		dev_err(&pdev->dev,
			"Error while parsing allowed-devices property\n");
		goto bpmp_put;
	}

	/* Dynamically register clock parents */
	bpmp_ares.clock_parents_size = 0;

	unsigned int max_parents = bpmp_ares.clocks_size * MRQ_CLK_MAX_PARENTS;
	bpmp_ares.clock_parents = devm_kcalloc(&pdev->dev, max_parents,
					       sizeof(uint32_t), GFP_KERNEL);

	for (i = 0; i < bpmp_ares.clocks_size; i++) {
		struct cmd_clk_get_all_info_response info;
		uint32_t clk_id = bpmp_ares.clock[i];

		dev_dbg(&pdev->dev, "bpmp_ares.clock %d\n", clk_id);

		err = tegra_bpmp_clk_get_info(bpmp, clk_id, &info);
		if (err)
			goto bpmp_put;

		if (bpmp_ares.clock_parents_size + info.num_parents >
		    max_parents) {
			err = -ENOMEM;
			goto bpmp_put;
		}

		for (j = 0; j < info.num_parents; j++) {
			dev_dbg(&pdev->dev, "clock %u parent: %u\n", clk_id,
				info.parents[j]);
			bpmp_ares.clock_parents[bpmp_ares.clock_parents_size +
						j] = info.parents[j];
		}
		bpmp_ares.clock_parents_size += info.num_parents;
	}

	/* TODO deduplicate parent clocks */

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
	dev_dbg(&pdev->dev, "device class registered correctly\n");

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
	dev_info(&pdev->dev, "driver unloaded\n");
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
		.dev_groups = bpmp_host_proxy_groups,
	},
	.probe = bpmp_host_proxy_probe,
	.remove = bpmp_host_proxy_remove,
};
builtin_platform_driver(bpmp_host_proxy_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hugo Ros");
MODULE_DESCRIPTION("BPMP host proxy");
MODULE_VERSION("1.0");
