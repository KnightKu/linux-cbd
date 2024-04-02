#include <linux/cbd.h>
#include <linux/export.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/io.h>

#include "cbd_internal.h"

static struct cbd_region *cbd_regions[CBD_REGION_MAX];
static DEFINE_IDA(cbd_region_id_ida);

static ssize_t cbd_backend_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_region *cbdr;
	struct cbd_region_info *info;
	struct cbd_backend_info *backend_info;
	uuid_t b_uuid;
	char path[CBD_PATH_LEN];
	int ret;
	ssize_t len = 0;
	int i;

	cbdr = container_of(dev, struct cbd_region, device);

	ret = cbdr_validate(cbdr);
	if (ret < 0) {
		cbdr_err(cbdr, "not a valid cbd region: %d", ret);
		return ret;
	}

	info = cbdr->region_info;

	for (i = 0; i < readl(&info->backend_num); i++) {
		backend_info = cbdr_get_backend_info(cbdr, i);
		memcpy_fromio(&b_uuid, backend_info->owner, UUID_SIZE);
		memcpy_fromio(&path, backend_info->path, UUID_SIZE);
		len += sprintf(buf + len, "%u,owner: %pUB,path: %s\n", i, &b_uuid, path);
	}

	return len;
}

static DEVICE_ATTR(backend, 0400, cbd_backend_show, NULL);


static ssize_t cbd_myhost_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_region *cbdr;
	struct cbd_host *host;
	int ret;

	cbdr = container_of(dev, struct cbd_region, device);

	ret = cbdr_validate(cbdr);
	if (ret < 0) {
		cbdr_err(cbdr, "not a valid cbd region: %d", ret);
		return ret;
	}

	host = cbdr->host;
	if (!host)
		return 0;

	return sprintf(buf, "%d\n", host->hostid);
}


static DEVICE_ATTR(my_hostid, 0400, cbd_myhost_show, NULL);

enum {
	CBDR_ADM_OPT_ERR		= 0,
	CBDR_ADM_OPT_OP,
	CBDR_ADM_OPT_FORCE,
	CBDR_ADM_OPT_PATH,
	CBDR_ADM_OPT_BID,
	CBDR_ADM_OPT_DID,
	CBDR_ADM_OPT_HOSTNAME,
	CBDR_ADM_OPT_QUEUES,
};

enum {
	CBDR_ADM_OP_FORMAT,
	CBDR_ADM_OP_B_START,
	CBDR_ADM_OP_B_STOP,
	CBDR_ADM_OP_B_CLEAR,
	CBDR_ADM_OP_DEV_START,
	CBDR_ADM_OP_DEV_STOP,
	CBDR_ADM_OP_HOST_REG,
	CBDR_ADM_OP_HOST_UNREG,
};

static const char *const adm_op_names[] = {
	[CBDR_ADM_OP_FORMAT] = "format",
	[CBDR_ADM_OP_B_START] = "backend-start",
	[CBDR_ADM_OP_B_STOP] = "backend-stop",
	[CBDR_ADM_OP_B_CLEAR] = "backend-clear",
	[CBDR_ADM_OP_DEV_START] = "dev-start",
	[CBDR_ADM_OP_DEV_STOP] = "dev-stop",
	[CBDR_ADM_OP_HOST_REG] = "host-register",
	[CBDR_ADM_OP_HOST_UNREG] = "host-unregister",
};

static const match_table_t adm_opt_tokens = {
	{ CBDR_ADM_OPT_OP,		"op=%s"	},
	{ CBDR_ADM_OPT_FORCE,		"force=%u" },
	{ CBDR_ADM_OPT_PATH,		"path=%s" },
	{ CBDR_ADM_OPT_BID,		"bid=%u" },
	{ CBDR_ADM_OPT_DID,		"did=%u" },
	{ CBDR_ADM_OPT_HOSTNAME,	"hostname=%s" },
	{ CBDR_ADM_OPT_QUEUES,		"queues=%u" },
	{ CBDR_ADM_OPT_ERR,		NULL	}
};

static int parse_adm_options(struct cbd_region *cbdr,
		char *buf,
		struct cbd_adm_options *opts)
{
	substring_t args[MAX_OPT_ARGS];
	char *o, *p;
	int token, ret = 0;

	o = buf;

	while ((p = strsep(&o, ",\n")) != NULL) {
		if (!*p)
			continue;

		pr_err("p: %s\n", p);
		token = match_token(p, adm_opt_tokens, args);
		switch (token) {
		case CBDR_ADM_OPT_OP:
			ret = match_string(adm_op_names, ARRAY_SIZE(adm_op_names), args[0].from);
			if (ret < 0) {
				pr_err("unknown op: '%s'\n", args[0].from);
			        ret = -EINVAL;
			        break;
			}
			opts->op = ret;;
			break;
		case CBDR_ADM_OPT_PATH:
			if (match_strlcpy(opts->backend.path, &args[0],
			        CBD_PATH_LEN) == 0) {
			        ret = -EINVAL;
			        break;
			}
			break;
		case CBDR_ADM_OPT_FORCE:
			if (match_uint(args, &token) || token != 1) {
				ret = -EINVAL;
				goto out;
			}
			opts->force = 1;
			break;
		case CBDR_ADM_OPT_BID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->bid = token;
			break;
		case CBDR_ADM_OPT_DID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->blkdev.did = token;
			break;
		case CBDR_ADM_OPT_HOSTNAME:
			if (match_strlcpy(opts->host.hostname, &args[0],
			        CBD_NAME_LEN) == 0) {
			        ret = -EINVAL;
			        break;
			}
			break;
		case CBDR_ADM_OPT_QUEUES:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->blkdev.queues = token;
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

static ssize_t cbd_adm_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *ubuf,
				 size_t size)
{
	int ret;
	char *buf;
	struct cbd_adm_options opts = { 0 };
	struct cbd_region *cbdr;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	pr_err("ubuf: %s\n", ubuf);
	cbdr = container_of(dev, struct cbd_region, device);

	buf = kmemdup(ubuf, size + 1, GFP_KERNEL);
	if (IS_ERR(buf)) {
		pr_err("failed to dup buf for adm option: %d", (int)PTR_ERR(buf));
		return PTR_ERR(buf);
	}
	buf[size] = '\0';
	ret = parse_adm_options(cbdr, buf, &opts);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}
	kfree(buf);

	if (opts.op != CBDR_ADM_OP_FORMAT) {
		ret = cbdr_validate(cbdr);
		if (ret < 0) {
			cbdr_err(cbdr, "not a valid cbd region: %d", ret);
			return ret;
		}
	}

	switch (opts.op) {
	case CBDR_ADM_OP_FORMAT:
		ret = cbd_region_format(cbdr, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDR_ADM_OP_B_START:
		ret = cbd_backend_start(cbdr, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDR_ADM_OP_B_STOP:
		ret = cbd_backend_stop(cbdr, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDR_ADM_OP_B_CLEAR:
		ret = cbd_backend_clear(cbdr, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDR_ADM_OP_DEV_START:
		ret = cbd_blkdev_start(cbdr, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDR_ADM_OP_DEV_STOP:
		ret = cbd_blkdev_stop(cbdr, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDR_ADM_OP_HOST_REG:
		ret = cbd_host_register(cbdr, &opts);
		break;
	case CBDR_ADM_OP_HOST_UNREG:
		ret = cbd_host_unregister(cbdr, &opts);
		break;
	default:
		pr_err("invalid op: %d\n", opts.op);
		return -EINVAL;
	}

	if (ret < 0)
		return ret;

	return size;
}

static DEVICE_ATTR(adm, 0200, NULL, cbd_adm_store);

static ssize_t cbd_info_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_region *cbdr;
	int ret;

	cbdr = container_of(dev, struct cbd_region, device);

	ret = cbdr_validate(cbdr);
	if (ret < 0) {
		cbdr_err(cbdr, "not a valid cbd region: %d", ret);
		return ret;
	}

	return cbd_region_info(cbdr, buf);
}
static DEVICE_ATTR(info, 0400, cbd_info_show, NULL);

static struct attribute *cbd_region_attrs[] = {
	&dev_attr_backend.attr,
	&dev_attr_adm.attr,
	&dev_attr_info.attr,
	&dev_attr_my_hostid.attr,
	NULL
};

static struct attribute_group cbd_region_attr_group = {
	.attrs = cbd_region_attrs,
};

static const struct attribute_group *cbd_region_attr_groups[] = {
	&cbd_region_attr_group,
	NULL
};

static void cbd_region_release(struct device *dev)
{
}

struct device_type cbd_region_type = {
	.name		= "cbd_region",
	.groups		= cbd_region_attr_groups,
	.release	= cbd_region_release,
};

static struct cbd_region *cbd_region_alloc(struct cbd_region_param *cbd_rp)
{
	struct cbd_region *cbdr;
	struct cbd_region_info *region_info;
	struct device *dev;
	int i;

	cbdr = kzalloc(sizeof(struct cbd_region), GFP_KERNEL);
	if (!cbdr) {
		return NULL;
	}

	cbdr->id = ida_simple_get(&cbd_region_id_ida, 0, 16,
					 GFP_KERNEL);

	cbd_regions[cbdr->id] = cbdr;
	cbdr->start = cbd_rp->start;
	cbdr->size = cbd_rp->size;

	region_info = memremap(cbdr->start, cbdr->size, MEMREMAP_WB);
	if (is_vmalloc_addr(region_info))
		pr_err("is vmalloc_addr");
	cbdr->region_info = region_info;
	mutex_init(&cbdr->lock);
	INIT_LIST_HEAD(&cbdr->backends);
	INIT_LIST_HEAD(&cbdr->devices);

	dev = &cbdr->device;
	device_initialize(dev);
	device_set_pm_not_required(dev);
	dev->bus = &cbd_bus_type;
	dev->type = &cbd_region_type;
	dev->parent = &cbd_root_dev;

	dev_set_name(&cbdr->device, "region%d", cbdr->id);
	pr_err("device_add");
	device_add(&cbdr->device);

	return cbdr;

cbdr_free:
	kfree(cbdr);
	return NULL;
}

int cbd_region_create(struct cbd_region_param *cbd_rp)
{
	struct cbd_region *cbdr;
	int ret;
	int i;

	pr_err("alloc region");
	cbdr = cbd_region_alloc(cbd_rp);
	if (!cbdr) {
		return -ENOMEM;
	}

	pr_err("id: %d", cbdr->id);
	return cbdr->id;

region_free:
	kfree(cbdr);
	return ret;
}
EXPORT_SYMBOL(cbd_region_create);

int cbd_region_destroy(int rid)
{
	struct cbd_region *cbdr;

	cbdr = cbd_regions[rid];

	if (cbdr->host) {
		pr_err("region%d is busy, unregister host from regioan please.", rid);
		return -EBUSY;
	}

	ida_simple_remove(&cbd_region_id_ida, cbdr->id);

	memunmap(cbdr->region_info);

	device_unregister(&cbdr->device);
	kfree(cbdr);

	return 0;
}
EXPORT_SYMBOL(cbd_region_destroy);

int cbd_region_format(struct cbd_region *cbdr, struct cbd_adm_options *opts)
{
	struct cbd_region_info *info = cbdr->region_info;
	u64 magic;

	if (cbdr->size < (CBDR_CHANNEL_AREA_OFF + CBDR_CHANNEL_SIZE * CBDR_CHANNEL_NUM)) {
		return -EINVAL;
	}

	mutex_lock(&cbdr->lock);
	magic = readq(&info->magic);
	if (magic && !opts->force) {
		mutex_unlock(&cbdr->lock);
		return -EEXIST;
	}

	memset(info, 0, CBDR_CHANNEL_AREA_OFF + CBDR_CHANNEL_SIZE * 2);

	writeq(CBD_REGION_MAGIC, &info->magic);
	writew(CBD_REGION_VERSION, &info->version);

	writeq(CBDR_HOST_AREA_OFF, &info->host_area_off);
	writel(CBDR_HOST_INFO_SIZE, &info->host_info_size);
	writel(CBDR_HOST_NUM, &info->host_num);

	writeq(CBDR_BACKEND_AREA_OFF, &info->backend_area_off);
	writel(CBDR_BACKEND_INFO_SIZE, &info->backend_info_size);
	writel(CBDR_BACKEND_NUM, &info->backend_num);

	writeq(CBDR_BLKDEV_AREA_OFF, &info->blkdev_area_off);
	writel(CBDR_BLKDEV_INFO_SIZE, &info->blkdev_info_size);
	writel(CBDR_BLKDEV_NUM, &info->blkdev_num);

	writeq(CBDR_CHANNEL_AREA_OFF, &info->channel_area_off);
	writel(CBDR_CHANNEL_SIZE, &info->channel_size);
	writel(CBDR_CHANNEL_NUM, &info->channel_num);

	struct cbd_channel_info __iomem *channel_info;
	int i;

	for (i = 0; i < info->channel_num; i++) {
		channel_info = __get_channel_info(cbdr, i);
		memset(channel_info, 0, 4096);
	}

	mutex_unlock(&cbdr->lock);

	return 0;
}

int cbdr_validate(struct cbd_region *cbdr)
{
	struct cbd_region_info *info = cbdr->region_info;
	u64 magic;
	int ret = 0;

	mutex_lock(&cbdr->lock);
	info = cbdr->region_info;

	if (readq(&info->magic) != CBD_REGION_MAGIC) {
		ret = -EINVAL;
	}

	mutex_unlock(&cbdr->lock);

	return ret;
}

ssize_t cbd_region_info(struct cbd_region *cbdr, char *buf)
{
	struct cbd_region_info *info = cbdr->region_info;
	u64 magic;
	ssize_t ret;

	mutex_lock(&cbdr->lock);
	info = cbdr->region_info;

	magic = readq(&info->magic);
	mutex_unlock(&cbdr->lock);

	if (magic != CBD_REGION_MAGIC) {
		return sprintf(buf, "invalid magic number: 0x%llx\n", magic);
	}

	ret = sprintf(buf, "magic: 0x%llx\n"		\
			"version: %u\n"			\
			"flags: %x\n\n"			\
			"host_area_off: %llu\n"		\
			"bytes_per_host_info: %u\n"	\
			"host_num: %u\n\n"		\
			"backend_area_off: %llu\n"	\
			"bytes_per_backend_info: %u\n"	\
			"backend_num: %u\n\n"		\
			"blkdev_area_off: %llu\n"		\
			"bytes_per_blkdev_info: %u\n"	\
			"blkdev_num: %u\n\n"		\
			"channel_area_off: %llu\n"	\
			"bytes_per_channel: %u\n"	\
			"channel_num: %u\n",
			magic,
			readw(&info->version),
			readw(&info->flags),
			readq(&info->host_area_off),
			readl(&info->host_info_size),
			readl(&info->host_num),
			readq(&info->backend_area_off),
			readl(&info->backend_info_size),
			readl(&info->backend_num),
			readq(&info->blkdev_area_off),
			readl(&info->blkdev_info_size),
			readl(&info->blkdev_num),
			readq(&info->channel_area_off),
			readl(&info->channel_size),
			readl(&info->channel_num));

	return ret;
}



static int
famfs_blk_dax_notify_failure(
	struct dax_device	*dax_devp,
	u64			offset,
	u64			len,
	int			mf_flags)
{

	pr_err("%s: dax_devp %llx offset %llx len %lld mf_flags %x\n",
	       __func__, (u64)dax_devp, (u64)offset, (u64)len, mf_flags);
	return -EOPNOTSUPP;
}

const struct dax_holder_operations famfs_blk_dax_holder_ops = {
	.notify_failure		= famfs_blk_dax_notify_failure,
};

int cbdt_register(struct cbdt_register_options *opts)
{
	struct dax_device *dax_dev = NULL;
	u64 start_off = 0;
	struct bdev_handle   *handlep = NULL;
	struct cbd_transport *cbdt;

	if (!strstr(opts->path, "/dev/pmem")) {
		pr_err("%s: path (%s) is not pmem\n",
		       __func__, opts->path);
		return -EINVAL;
	}

	cbdt = kzalloc(sizeof(struct cbd_transport), GFP_KERNEL);
	if (!cbdt) {
		return -ENOMEM;
	}

	handlep = bdev_open_by_path(opts->path, BLK_OPEN_READ | BLK_OPEN_WRITE, cbdt, NULL);
	if (IS_ERR(handlep->bdev)) {
		kfree(cbdt);
		pr_err("%s: failed blkdev_get_by_path(%s)\n", __func__, opts->path);
		return PTR_ERR(handlep->bdev);
	}

	dax_dev = fs_dax_get_by_bdev(handlep->bdev, &start_off,
				      cbdt,
				      &famfs_blk_dax_holder_ops);
	if (IS_ERR(dax_dev)) {
		pr_err("%s: unable to get daxdev from handlep->bdev\n", __func__);
		bdev_release(handlep);
		kfree(cbdt);
		return -ENODEV;
	}

	pr_err("start_off: %llu\n", start_off);

	if (handlep)
		bdev_release(handlep);
	if (dax_dev)
		fs_put_dax(dax_dev, cbdt);

	kfree(cbdt);
	return 0;
}
