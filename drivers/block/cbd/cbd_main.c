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

static BUS_ATTR_RO(uuid);
static BUS_ATTR_RO(supported_features);

static struct attribute *cbd_bus_attrs[] = {
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
