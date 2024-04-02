/*
 * Copyright(C) 2024, Dongsheng Yang <dongsheng.yang@easystack.cn>
 */

#include <linux/module.h>
#include <linux/io.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/blk-mq.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <net/genetlink.h>

#include <linux/types.h>
#include <linux/uuid.h>

#include "cbd_internal.h"

uuid_t cbd_uuid;
struct workqueue_struct	*cbd_wq;

enum {
	CBDT_REG_OPT_ERR		= 0,
	CBDT_REG_OPT_FORCE,
	CBDT_REG_OPT_PATH,
	CBDT_REG_OPT_HOSTNAME,
};

static const match_table_t register_opt_tokens = {
	{ CBDT_REG_OPT_FORCE,		"force=%u" },
	{ CBDT_REG_OPT_PATH,		"path=%s" },
	{ CBDT_REG_OPT_HOSTNAME,	"hostname=%s" },
	{ CBDT_REG_OPT_ERR,		NULL	}
};

static int parse_register_options(
		char *buf,
		struct cbdt_register_options *opts)
{
	substring_t args[MAX_OPT_ARGS];
	char *o, *p;
	int token, ret = 0;

	o = buf;

	while ((p = strsep(&o, ",\n")) != NULL) {
		if (!*p)
			continue;

		pr_err("p: %s\n", p);
		token = match_token(p, register_opt_tokens, args);
		switch (token) {
		case CBDT_REG_OPT_PATH:
			if (match_strlcpy(opts->path, &args[0],
			        CBD_PATH_LEN) == 0) {
			        ret = -EINVAL;
			        break;
			}
			break;
		case CBDT_REG_OPT_FORCE:
			if (match_uint(args, &token) || token != 1) {
				ret = -EINVAL;
				goto out;
			}
			opts->force = 1;
			break;
		case CBDT_REG_OPT_HOSTNAME:
			if (match_strlcpy(opts->hostname, &args[0],
			        CBD_NAME_LEN) == 0) {
			        ret = -EINVAL;
			        break;
			}
			break;
		default:
			pr_err("unknown parameter or missing value '%s'\n", p);
			ret = -EINVAL;
			goto out;
		}
	}

out:
	return ret;
}

static ssize_t transport_unregister_store(const struct bus_type *bus, const char *ubuf,
				      size_t size)
{
	int ret;
	u32 transport_id;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (sscanf(ubuf, "%u", &transport_id) != 1) {
		return -EINVAL;
	}

	ret = cbdt_unregister(transport_id);
	if (ret < 0)
		return ret;

	return size;
}

static ssize_t transport_register_store(const struct bus_type *bus, const char *ubuf,
				      size_t size)
{
	int ret;
	char *buf;
	struct cbdt_register_options opts = { 0 };

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	pr_err("ubuf: %s\n", ubuf);

	buf = kmemdup(ubuf, size + 1, GFP_KERNEL);
	if (IS_ERR(buf)) {
		pr_err("failed to dup buf for adm option: %d", (int)PTR_ERR(buf));
		return PTR_ERR(buf);
	}
	buf[size] = '\0';
	ret = parse_register_options(buf, &opts);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}
	kfree(buf);

	ret = cbdt_register(&opts);
	if (ret < 0)
		return ret;

	return size;
}

/* TODO support multi device feature */
#define RBD_FEATURES_SUPPORTED	0x0ULL

static ssize_t supported_features_show(const struct bus_type *bus, char *buf)
{
	return sprintf(buf, "0x%llx\n", RBD_FEATURES_SUPPORTED);
}

static ssize_t uuid_show(const struct bus_type *bus, char *buf)
{
	return sprintf(buf, "%pUB\n", &cbd_uuid);
}

static BUS_ATTR_WO(transport_unregister);
static BUS_ATTR_WO(transport_register);
static BUS_ATTR_RO(uuid);
static BUS_ATTR_RO(supported_features);

static struct attribute *cbd_bus_attrs[] = {
	&bus_attr_transport_unregister.attr,
	&bus_attr_transport_register.attr,
	&bus_attr_supported_features.attr,
	&bus_attr_uuid.attr,
	NULL,
};

static const struct attribute_group cbd_bus_group = {
	.attrs = cbd_bus_attrs,
};
__ATTRIBUTE_GROUPS(cbd_bus);

struct bus_type cbd_bus_type = {
	.name		= "cbd",
	.bus_groups	= cbd_bus_groups,
};

static void cbd_root_dev_release(struct device *dev)
{
}

struct device cbd_root_dev = {
	.init_name =    "cbd",
	.release =      cbd_root_dev_release,
};

static int __init cbd_init(void)
{
	int ret;
	int data;

	char zeros[4096] = {0};

	pr_err("all zero crc is : %llu\n", crc64(zeros, 4096));

	uuid_gen(&cbd_uuid);

	cbd_wq = alloc_workqueue(CBD_DRV_NAME, WQ_MEM_RECLAIM, 0);
	if (!cbd_wq) {
		return -ENOMEM;
	}

	ret = device_register(&cbd_root_dev);
	if (ret < 0) {
		put_device(&cbd_root_dev);
		goto destroy_wq;
	}

	ret = bus_register(&cbd_bus_type);
	if (ret < 0) {
		device_unregister(&cbd_root_dev);
		goto device_unregister;
	}

	cbd_blkdev_init();
	cbd_debugfs_init();

	return 0;

device_unregister:
	device_unregister(&cbd_root_dev);
destroy_wq:
	destroy_workqueue(cbd_wq);

	return ret;
}

static void cbd_exit(void)
{
	stop = 1;
	cbd_debugfs_cleanup();
	cbd_blkdev_exit();
	bus_unregister(&cbd_bus_type);
	device_unregister(&cbd_root_dev);

	destroy_workqueue(cbd_wq);

	return;
}

MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang@easystack.cn>");
MODULE_DESCRIPTION("CXL(Compute Express Link) Block Device");
MODULE_LICENSE("GPL v2");
module_init(cbd_init);
module_exit(cbd_exit);
