// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(C) 2024, Dongsheng Yang <dongsheng.yang@linux.dev>
 */

#include <linux/kernel.h>
#include <linux/parser.h>

#include "cbd_internal.h"
#include "cbd_blkdev.h"

struct workqueue_struct	*cbd_wq;

enum {
	CBDT_REG_OPT_ERR		= 0,
	CBDT_REG_OPT_FORCE,
	CBDT_REG_OPT_FORMAT,
	CBDT_REG_OPT_PATH,
	CBDT_REG_OPT_HOSTNAME,
	CBDT_REG_OPT_HOSTID,
};

static const match_table_t register_opt_tokens = {
	{ CBDT_REG_OPT_FORCE,		"force=%u" },
	{ CBDT_REG_OPT_FORMAT,		"format=%u" },
	{ CBDT_REG_OPT_PATH,		"path=%s" },
	{ CBDT_REG_OPT_HOSTNAME,	"hostname=%s" },
	{ CBDT_REG_OPT_HOSTID,		"hostid=%u" },
	{ CBDT_REG_OPT_ERR,		NULL	}
};

/**
 * parse_register_options - Parse user-supplied options for transport registration
 * @buf: String containing the registration options, separated by commas
 * @opts: Structure to store parsed options
 *
 * This function parses the options provided in @buf and populates the
 * @opts structure. Supported options include:
 * - path: path to the device
 * - force: if non-zero, forces formatting even if data exists
 * - format: if non-zero, formats the transport
 * - hostname: host identifier string
 * - hostid: numerical identifier for the host
 *
 * Returns 0 on success, or -EINVAL if an option fails to parse or an
 * unknown option is encountered.
 */
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
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->force = (token != 0);
			break;
		case CBDT_REG_OPT_FORMAT:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->format = (token != 0);
			break;
		case CBDT_REG_OPT_HOSTNAME:
			if (match_strlcpy(opts->hostname, &args[0],
				CBD_NAME_LEN) == 0) {
				ret = -EINVAL;
				break;
			}
			break;
		case CBDT_REG_OPT_HOSTID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->host_id = token;
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
	u32 transport_id;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (sscanf(ubuf, "transport_id=%u", &transport_id) != 1)
		return -EINVAL;

	ret = cbdt_unregister(transport_id);
	if (ret < 0)
		return ret;

	return size;
}

static ssize_t transport_register_store(const struct bus_type *bus, const char *ubuf,
				      size_t size)
{
	struct cbdt_register_options opts = { 0 };
	char *buf;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	buf = kmemdup(ubuf, size + 1, GFP_KERNEL);
	if (IS_ERR(buf)) {
		pr_err("failed to dup buf for adm option: %d", (int)PTR_ERR(buf));
		return PTR_ERR(buf);
	}
	buf[size] = '\0';

	opts.host_id = UINT_MAX;
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

static BUS_ATTR_WO(transport_unregister);
static BUS_ATTR_WO(transport_register);

static struct attribute *cbd_bus_attrs[] = {
	&bus_attr_transport_unregister.attr,
	&bus_attr_transport_register.attr,
	NULL,
};

static const struct attribute_group cbd_bus_group = {
	.attrs = cbd_bus_attrs,
};
__ATTRIBUTE_GROUPS(cbd_bus);

const struct bus_type cbd_bus_type = {
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

	cbd_wq = alloc_workqueue(CBD_DRV_NAME, WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!cbd_wq)
		return -ENOMEM;

	ret = device_register(&cbd_root_dev);
	if (ret < 0) {
		put_device(&cbd_root_dev);
		goto destroy_wq;
	}

	ret = bus_register(&cbd_bus_type);
	if (ret < 0)
		goto device_unregister;

	ret = cbd_blkdev_init();
	if (ret < 0)
		goto bus_unregister;

	/*
	 * Ensures that key structures do not exceed a single page in size,
	 * using BUILD_BUG_ON checks to enforce this at compile-time.
	 */
	BUILD_BUG_ON(sizeof(struct cbd_transport_info) > PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct cbd_host_info) > PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct cbd_backend_info) > PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct cbd_blkdev_info) > PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct cbd_cache_seg_info) > PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct cbd_channel_seg_info) > PAGE_SIZE);

	return 0;

bus_unregister:
	bus_unregister(&cbd_bus_type);
device_unregister:
	device_unregister(&cbd_root_dev);
destroy_wq:
	destroy_workqueue(cbd_wq);

	return ret;
}

static void cbd_exit(void)
{
	cbd_blkdev_exit();
	bus_unregister(&cbd_bus_type);
	device_unregister(&cbd_root_dev);
	destroy_workqueue(cbd_wq);
}

MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang@linux.dev>");
MODULE_DESCRIPTION("CXL(Compute Express Link) Block Device");
MODULE_LICENSE("GPL v2");
module_init(cbd_init);
module_exit(cbd_exit);
