#include "cbd_internal.h"

#define cbdt_err(transport, fmt, ...)						\
	cbd_err("cbd_transport%u: " fmt,					\
		 transport->id, ##__VA_ARGS__)

#define cbdt_info(transport, fmt, ...)						\
	cbd_info("cbd_transport%u: " fmt,					\
		 transport->id, ##__VA_ARGS__)

#define cbdt_debug(transport, fmt, ...)						\
	cbd_debug("cbd_transport%u: " fmt,					\
		 transport->id, ##__VA_ARGS__)


static struct cbd_transport *cbd_transports[CBD_TRANSPORT_MAX];
static DEFINE_IDA(cbd_transport_id_ida);

static ssize_t cbd_myhost_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_transport *cbdt;
	struct cbd_host *host;
	int ret;

	cbdt = container_of(dev, struct cbd_transport, device);

	ret = cbdt_validate(cbdt);
	if (ret < 0) {
		cbdt_err(cbdt, "not a valid cbd transport: %d", ret);
		return ret;
	}

	host = cbdt->host;
	if (!host)
		return 0;

	return sprintf(buf, "%d\n", host->host_id);
}

static DEVICE_ATTR(my_host_id, 0400, cbd_myhost_show, NULL);

enum {
	CBDT_ADM_OPT_ERR		= 0,
	CBDT_ADM_OPT_OP,
	CBDT_ADM_OPT_FORCE,
	CBDT_ADM_OPT_PATH,
	CBDT_ADM_OPT_BID,
	CBDT_ADM_OPT_DID,
	CBDT_ADM_OPT_HOSTNAME,
	CBDT_ADM_OPT_QUEUES,
};

enum {
	CBDT_ADM_OP_FORMAT,
	CBDT_ADM_OP_B_START,
	CBDT_ADM_OP_B_STOP,
	CBDT_ADM_OP_B_CLEAR,
	CBDT_ADM_OP_DEV_START,
	CBDT_ADM_OP_DEV_STOP,
	CBDT_ADM_OP_HOST_REG,
	CBDT_ADM_OP_HOST_UNREG,
};

static const char *const adm_op_names[] = {
	[CBDT_ADM_OP_FORMAT] = "format",
	[CBDT_ADM_OP_B_START] = "backend-start",
	[CBDT_ADM_OP_B_STOP] = "backend-stop",
	[CBDT_ADM_OP_B_CLEAR] = "backend-clear",
	[CBDT_ADM_OP_DEV_START] = "dev-start",
	[CBDT_ADM_OP_DEV_STOP] = "dev-stop",
	[CBDT_ADM_OP_HOST_REG] = "host-register",
	[CBDT_ADM_OP_HOST_UNREG] = "host-unregister",
};

static const match_table_t adm_opt_tokens = {
	{ CBDT_ADM_OPT_OP,		"op=%s"	},
	{ CBDT_ADM_OPT_FORCE,		"force=%u" },
	{ CBDT_ADM_OPT_PATH,		"path=%s" },
	{ CBDT_ADM_OPT_BID,		"bid=%u" },
	{ CBDT_ADM_OPT_DID,		"did=%u" },
	{ CBDT_ADM_OPT_HOSTNAME,	"hostname=%s" },
	{ CBDT_ADM_OPT_QUEUES,		"queues=%u" },
	{ CBDT_ADM_OPT_ERR,		NULL	}
};

static int parse_adm_options(struct cbd_transport *cbdt,
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

		token = match_token(p, adm_opt_tokens, args);
		switch (token) {
		case CBDT_ADM_OPT_OP:
			ret = match_string(adm_op_names, ARRAY_SIZE(adm_op_names), args[0].from);
			if (ret < 0) {
				pr_err("unknown op: '%s'\n", args[0].from);
			        ret = -EINVAL;
			        break;
			}
			opts->op = ret;;
			break;
		case CBDT_ADM_OPT_PATH:
			if (match_strlcpy(opts->backend.path, &args[0],
			        CBD_PATH_LEN) == 0) {
			        ret = -EINVAL;
			        break;
			}
			break;
		case CBDT_ADM_OPT_FORCE:
			if (match_uint(args, &token) || token != 1) {
				ret = -EINVAL;
				goto out;
			}
			opts->force = 1;
			break;
		case CBDT_ADM_OPT_BID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->bid = token;
			break;
		case CBDT_ADM_OPT_DID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->blkdev.did = token;
			break;
		case CBDT_ADM_OPT_HOSTNAME:
			if (match_strlcpy(opts->host.hostname, &args[0],
			        CBD_NAME_LEN) == 0) {
			        ret = -EINVAL;
			        break;
			}
			break;
		case CBDT_ADM_OPT_QUEUES:
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

int cbd_transport_stop(struct cbd_transport *cbdt);
static ssize_t cbd_adm_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *ubuf,
				 size_t size)
{
	int ret;
	char *buf;
	struct cbd_adm_options opts = { 0 };
	struct cbd_transport *cbdt;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	pr_err("ubuf: %s\n", ubuf);
	cbdt = container_of(dev, struct cbd_transport, device);

	buf = kmemdup(ubuf, size + 1, GFP_KERNEL);
	if (IS_ERR(buf)) {
		pr_err("failed to dup buf for adm option: %d", (int)PTR_ERR(buf));
		return PTR_ERR(buf);
	}
	buf[size] = '\0';
	ret = parse_adm_options(cbdt, buf, &opts);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}
	kfree(buf);

	if (opts.op != CBDT_ADM_OP_FORMAT) {
		ret = cbdt_validate(cbdt);
		if (ret < 0) {
			cbdt_err(cbdt, "not a valid cbd transport: %d", ret);
			return ret;
		}
	}

	switch (opts.op) {
	case CBDT_ADM_OP_FORMAT:
		ret = cbd_transport_format(cbdt, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_B_START:
		ret = cbd_backend_start(cbdt, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_B_STOP:
		ret = cbd_backend_stop(cbdt, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_B_CLEAR:
		ret = cbd_backend_clear(cbdt, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_DEV_START:
		ret = cbd_blkdev_start(cbdt, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_DEV_STOP:
		ret = cbd_blkdev_stop(cbdt, &opts);
		if (ret < 0)
			return ret;
		break;
	case CBDT_ADM_OP_HOST_REG:
		ret = cbd_host_register(cbdt, &opts);
		break;
	case CBDT_ADM_OP_HOST_UNREG:
		ret = cbd_host_unregister(cbdt, &opts);
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
	struct cbd_transport *cbdt;
	int ret;

	cbdt = container_of(dev, struct cbd_transport, device);

	ret = cbdt_validate(cbdt);
	if (ret < 0) {
		cbdt_err(cbdt, "not a valid cbd transport: %d", ret);
		return ret;
	}

	return cbd_transport_info(cbdt, buf);
}
static DEVICE_ATTR(info, 0400, cbd_info_show, NULL);

static struct attribute *cbd_transport_attrs[] = {
	&dev_attr_adm.attr,
	&dev_attr_info.attr,
	&dev_attr_my_host_id.attr,
	NULL
};

static struct attribute_group cbd_transport_attr_group = {
	.attrs = cbd_transport_attrs,
};

static const struct attribute_group *cbd_transport_attr_groups[] = {
	&cbd_transport_attr_group,
	NULL
};

static void cbd_transport_release(struct device *dev)
{
}

struct device_type cbd_transport_type = {
	.name		= "cbd_transport",
	.groups		= cbd_transport_attr_groups,
	.release	= cbd_transport_release,
};

#define CXL_BLKDEV_TRANSPORT_PARAM_F_PMEM		1

struct cbd_transport_param {
	u64	start;
	u64	size;

	u32	flags;
};

int cbd_transport_init(struct cbd_transport *cbdt, struct dax_device *dax_dev)
{
	int ret;
	int i;
	struct device *dev;
	long access_size;
	void *kaddr;
	u64 nr_pages = 512*1024*1024 >> PAGE_SHIFT;

	cbdt->id = ida_simple_get(&cbd_transport_id_ida, 0, 16,
					 GFP_KERNEL);

	cbd_transports[cbdt->id] = cbdt;

	access_size = dax_direct_access(dax_dev, 0, nr_pages, DAX_ACCESS, &kaddr, NULL);
	if (access_size != nr_pages) {
		pr_err("dax size error: %d\n", access_size);
	}

	cbdt->transport_info = (struct cbd_transport_info *)kaddr;
	mutex_init(&cbdt->lock);
	INIT_LIST_HEAD(&cbdt->backends);
	INIT_LIST_HEAD(&cbdt->devices);

	dev = &cbdt->device;
	device_initialize(dev);
	device_set_pm_not_required(dev);
	dev->bus = &cbd_bus_type;
	dev->type = &cbd_transport_type;
	dev->parent = &cbd_root_dev;

	dev_set_name(&cbdt->device, "transport%d", cbdt->id);
	pr_err("device_add");
	device_add(&cbdt->device);

	return cbdt;
}

int cbdt_unregister(u32 tid)
{
	struct cbd_transport *cbdt;

	cbdt = cbd_transports[tid];

	if (cbdt->host) {
		pr_err("transport%d is busy, unregister host from regioan please.", tid);
		return -EBUSY;
	}

	ida_simple_remove(&cbd_transport_id_ida, cbdt->id);

	device_unregister(&cbdt->device);

	if (cbdt->bdev_handle)
		bdev_release(cbdt->bdev_handle);
	if (cbdt->dax_dev)
		fs_put_dax(cbdt->dax_dev, cbdt);

	kfree(cbdt);

	return 0;
}

static void channels_format(struct cbd_transport *cbdt)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	struct cbd_channel_info *channel_info;
	int i;

	for (i = 0; i < info->channel_num; i++) {
		channel_info = __get_channel_info(cbdt, i);
		memset(channel_info, 0, 4096);
	}
}

int cbd_transport_format(struct cbd_transport *cbdt, struct cbd_adm_options *opts)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	u64 magic;

	mutex_lock(&cbdt->lock);
	magic = info->magic;
	if (magic && !opts->force) {
		mutex_unlock(&cbdt->lock);
		return -EEXIST;
	}

	memset(info, 0, CBDT_CHANNEL_AREA_OFF + CBDT_CHANNEL_SIZE * 2);

	info->magic = CBD_TRANSPORT_MAGIC;
	info->version = CBD_TRANSPORT_VERSION;
#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __GIT_ENDIAN : defined(__BIG_ENDIAN)
	info->flags = cpu_to_le16(CBDT_INFO_F_BIGENDIAN);
#endif
	info->host_area_off = CBDT_HOST_AREA_OFF;
	info->host_info_size = CBDT_HOST_INFO_SIZE;
	info->host_num = CBDT_HOST_NUM;

	info->backend_area_off = CBDT_BACKEND_AREA_OFF;
	info->backend_info_size = CBDT_BACKEND_INFO_SIZE;
	info->backend_num = CBDT_BACKEND_NUM;

	info->blkdev_area_off = CBDT_BLKDEV_AREA_OFF;
	info->blkdev_info_size = CBDT_BLKDEV_INFO_SIZE;
	info->blkdev_num = CBDT_BLKDEV_NUM;

	info->channel_area_off = CBDT_CHANNEL_AREA_OFF;
	info->channel_size = CBDT_CHANNEL_SIZE;
	info->channel_num = CBDT_CHANNEL_NUM;

	//hosts_format(cbdt);
	//backends_format(cbdt);
	//blkdevs_format(cbdt);
	channels_format(cbdt);

	mutex_unlock(&cbdt->lock);

	return 0;
}

int cbdt_validate(struct cbd_transport *cbdt)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	u64 magic;
	u16 flags;
	int ret = 0;

	mutex_lock(&cbdt->lock);
	info = cbdt->transport_info;

	if (info->magic != CBD_TRANSPORT_MAGIC) {
		ret = -EINVAL;
		goto out;
	}

	flags = le16_to_cpu(info->flags);
#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __GIT_ENDIAN : defined(__BIG_ENDIAN)
	if (!(flags & CBDT_INFO_F_BIGENDIAN)) {
		ret = -EINVAL;
		goto out;
	}
#else
	if ((flags & CBDT_INFO_F_BIGENDIAN)) {
		ret = -EINVAL;
		goto out;
	}
#endif

out:
	mutex_unlock(&cbdt->lock);

	return ret;
}

ssize_t cbd_transport_info(struct cbd_transport *cbdt, char *buf)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	u64 magic;
	ssize_t ret;

	mutex_lock(&cbdt->lock);
	info = cbdt->transport_info;

	magic = info->magic;
	mutex_unlock(&cbdt->lock);

	if (magic != CBD_TRANSPORT_MAGIC) {
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
			info->version,
			info->flags,
			info->host_area_off,
			info->host_info_size,
			info->host_num,
			info->backend_area_off,
			info->backend_info_size,
			info->backend_num,
			info->blkdev_area_off,
			info->blkdev_info_size,
			info->blkdev_num,
			info->channel_area_off,
			info->channel_size,
			info->channel_num);

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

	cbdt->bdev_handle = handlep;
	cbdt->dax_dev = dax_dev;

	cbd_transport_init(cbdt, dax_dev);

	return 0;
}

static inline struct cbd_host_info *__get_host_info(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	void *start = cbdt->transport_info;

	return start + info->host_area_off + (info->host_info_size * id);
}

struct cbd_host_info *cbdt_get_host_info(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_host_info *host_info;

	mutex_lock(&cbdt->lock);
	host_info = __get_host_info(cbdt, id);
	mutex_unlock(&cbdt->lock);

	return host_info;
}

int cbdt_get_empty_hid(struct cbd_transport *cbdt, u32 *id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	struct cbd_host_info *host_info;
	uuid_t uuid;
	int ret = 0;
	int i;

	mutex_lock(&cbdt->lock);
	for (i = 0; i < info->host_num; i++) {
		host_info = __get_host_info(cbdt, i);
		if (host_info->status == cbd_host_status_none) {
			*id = i;
			goto out;
		}
	}

	cbdt_err(cbdt, "No available hid found.");
	ret = -ENOENT;
out:
	mutex_unlock(&cbdt->lock);

	return ret;
}
