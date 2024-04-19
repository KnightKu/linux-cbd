#include <linux/pfn_t.h>

#include "cbd_internal.h"

#define CBDT_OBJ(OBJ, OBJ_SIZE)							\
										\
static inline struct cbd_##OBJ##_info						\
*__get_##OBJ##_info(struct cbd_transport *cbdt, u32 id)				\
{										\
	struct cbd_transport_info *info = cbdt->transport_info;			\
	void *start = cbdt->transport_info;					\
										\
	start += info->OBJ##_area_off;						\
										\
	return start + (info->OBJ_SIZE * id);					\
}										\
										\
struct cbd_##OBJ##_info 							\
*cbdt_get_##OBJ##_info(struct cbd_transport *cbdt, u32 id)			\
{										\
	struct cbd_##OBJ##_info *info;						\
										\
	mutex_lock(&cbdt->lock);						\
	info = __get_##OBJ##_info(cbdt, id);					\
	mutex_unlock(&cbdt->lock);						\
										\
	return info;								\
}										\
										\
int cbdt_get_empty_##OBJ##_id(struct cbd_transport *cbdt, u32 *id)		\
{										\
	struct cbd_transport_info *info = cbdt->transport_info;			\
	struct cbd_##OBJ##_info *_info;						\
	int ret = 0;								\
	int i;									\
										\
	mutex_lock(&cbdt->lock);						\
	for (i = 0; i < info->OBJ##_num; i++) {					\
		_info = __get_##OBJ##_info(cbdt, i);				\
		cbdt_flush_range(cbdt, _info, sizeof(*_info));			\
		if (_info->state == cbd_##OBJ##_state_none) {			\
			*id = i;						\
			goto out;						\
		}								\
	}									\
										\
	cbdt_err(cbdt, "No available " #OBJ "_id found.");			\
	ret = -ENOENT;								\
out:										\
	mutex_unlock(&cbdt->lock);						\
										\
	return ret;								\
}

CBDT_OBJ(host, host_info_size);
CBDT_OBJ(backend, backend_info_size);
CBDT_OBJ(blkdev, blkdev_info_size);
CBDT_OBJ(channel, channel_size);

static struct cbd_transport *cbd_transports[CBD_TRANSPORT_MAX];
static DEFINE_IDA(cbd_transport_id_ida);
static DEFINE_MUTEX(cbd_transport_mutex);

extern struct bus_type cbd_bus_type;
extern struct device cbd_root_dev;

static ssize_t cbd_myhost_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_transport *cbdt;
	struct cbd_host *host;

	cbdt = container_of(dev, struct cbd_transport, device);

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
	CBDT_ADM_OPT_QUEUES,
};

enum {
	CBDT_ADM_OP_B_START,
	CBDT_ADM_OP_B_STOP,
	CBDT_ADM_OP_B_CLEAR,
	CBDT_ADM_OP_DEV_START,
	CBDT_ADM_OP_DEV_STOP,
};

static const char *const adm_op_names[] = {
	[CBDT_ADM_OP_B_START] = "backend-start",
	[CBDT_ADM_OP_B_STOP] = "backend-stop",
	[CBDT_ADM_OP_B_CLEAR] = "backend-clear",
	[CBDT_ADM_OP_DEV_START] = "dev-start",
	[CBDT_ADM_OP_DEV_STOP] = "dev-stop",
};

static const match_table_t adm_opt_tokens = {
	{ CBDT_ADM_OPT_OP,		"op=%s"	},
	{ CBDT_ADM_OPT_FORCE,		"force=%u" },
	{ CBDT_ADM_OPT_PATH,		"path=%s" },
	{ CBDT_ADM_OPT_BID,		"backend_id=%u" },
	{ CBDT_ADM_OPT_DID,		"devid=%u" },
	{ CBDT_ADM_OPT_QUEUES,		"queues=%u" },
	{ CBDT_ADM_OPT_ERR,		NULL	}
};


struct cbd_adm_options {
	u16 op;
	u16 force:1;
	u32 backend_id;
	union {
		struct host_options {
			u32 hid;
		} host;
		struct backend_options {
			char path[CBD_PATH_LEN];
		} backend;
		struct channel_options {
			u32 cid;
		} channel;
		struct blkdev_options {
			u32 devid;
			u32 queues;
		} blkdev;
	};
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
			opts->op = ret;
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
			opts->backend_id = token;
			break;
		case CBDT_ADM_OPT_DID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->blkdev.devid = token;
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

static void transport_zero_range(struct cbd_transport *cbdt, void *pos, u64 size)
{
	memset(pos, 0, size);
	cbdt_flush_range(cbdt, pos, size);
}

static void channels_format(struct cbd_transport *cbdt)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	struct cbd_channel_info *channel_info;
	int i;

	for (i = 0; i < info->channel_num; i++) {
		channel_info = __get_channel_info(cbdt, i);
		transport_zero_range(cbdt, channel_info, CBDC_META_SIZE);
	}
}

static int cbd_transport_format(struct cbd_transport *cbdt, bool force)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	u64 magic;

	magic = le64_to_cpu(info->magic);
	if (magic && !force) {
		return -EEXIST;
	}

	/* TODO make these configureable */
	info->magic = cpu_to_le64(CBD_TRANSPORT_MAGIC);
	info->version = cpu_to_le16(CBD_TRANSPORT_VERSION);
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

	cbdt_flush_range(cbdt, info, sizeof(*info));

	transport_zero_range(cbdt, (void *)info + info->host_area_off,
			     info->channel_area_off - info->host_area_off);

	channels_format(cbdt);

	return 0;
}



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

	switch (opts.op) {
	case CBDT_ADM_OP_B_START:
		break;
	case CBDT_ADM_OP_B_STOP:
		break;
	case CBDT_ADM_OP_B_CLEAR:
		break;
	case CBDT_ADM_OP_DEV_START:
		break;
	case CBDT_ADM_OP_DEV_STOP:
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

static ssize_t cbd_transport_info(struct cbd_transport *cbdt, char *buf)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	ssize_t ret;

	mutex_lock(&cbdt->lock);
	info = cbdt->transport_info;
	mutex_unlock(&cbdt->lock);

	ret = sprintf(buf, "magic: 0x%llx\n"		\
			"version: %u\n"			\
			"flags: %x\n\n"			\
			"host_area_off: %llu\n"		\
			"bytes_per_host_info: %u\n"	\
			"host_num: %u\n\n"		\
			"backend_area_off: %llu\n"	\
			"bytes_per_backend_info: %u\n"	\
			"backend_num: %u\n\n"		\
			"blkdev_area_off: %llu\n"	\
			"bytes_per_blkdev_info: %u\n"	\
			"blkdev_num: %u\n\n"		\
			"channel_area_off: %llu\n"	\
			"bytes_per_channel: %u\n"	\
			"channel_num: %u\n",
			le64_to_cpu(info->magic),
			le16_to_cpu(info->version),
			le16_to_cpu(info->flags),
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

static ssize_t cbd_info_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_transport *cbdt;

	cbdt = container_of(dev, struct cbd_transport, device);

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

static int
cbd_dax_notify_failure(
	struct dax_device	*dax_devp,
	u64			offset,
	u64			len,
	int			mf_flags)
{

	pr_err("%s: dax_devp %llx offset %llx len %lld mf_flags %x\n",
	       __func__, (u64)dax_devp, (u64)offset, (u64)len, mf_flags);
	return -EOPNOTSUPP;
}

const struct dax_holder_operations cbd_dax_holder_ops = {
	.notify_failure		= cbd_dax_notify_failure,
};

static struct cbd_transport *cbdt_alloc(void)
{
	struct cbd_transport *cbdt;
	int ret;

	cbdt = kzalloc(sizeof(struct cbd_transport), GFP_KERNEL);
	if (!cbdt) {
		return NULL;
	}

	ret = ida_simple_get(&cbd_transport_id_ida, 0, CBD_TRANSPORT_MAX,
				GFP_KERNEL);
	if (ret < 0) {
		goto cbdt_free;
	}

	cbdt->id = ret;
	cbd_transports[cbdt->id] = cbdt;

	return cbdt;

cbdt_free:
	kfree(cbdt);
	return NULL;
}

static void cbdt_destroy(struct cbd_transport *cbdt)
{
	cbd_transports[cbdt->id] = NULL;
	ida_simple_remove(&cbd_transport_id_ida, cbdt->id);
	kfree(cbdt);
}

static int cbdt_dax_init(struct cbd_transport *cbdt, char *path)
{
	struct dax_device *dax_dev = NULL;
	struct bdev_handle *handle = NULL;
	long access_size;
	void *kaddr;
	u64 nr_pages = CBD_TRASNPORT_SIZE >> PAGE_SHIFT;
	u64 start_off = 0;
	int ret;

	handle = bdev_open_by_path(path, BLK_OPEN_READ | BLK_OPEN_WRITE, cbdt, NULL);
	if (IS_ERR(handle)) {
		pr_err("%s: failed blkdev_get_by_path(%s)\n", __func__, path);
		ret = PTR_ERR(handle);
		goto err;
	}

	dax_dev = fs_dax_get_by_bdev(handle->bdev, &start_off,
				     cbdt,
				     &cbd_dax_holder_ops);
	if (IS_ERR(dax_dev)) {
		pr_err("%s: unable to get daxdev from handle->bdev\n", __func__);
		ret = -ENODEV;
		goto bdev_release;
	}

	access_size = dax_direct_access(dax_dev, 0, nr_pages, DAX_ACCESS, &kaddr, NULL);
	if (access_size != nr_pages) {
		ret = -EINVAL;
		goto dax_put;
	}

	cbdt->bdev_handle = handle;
	cbdt->dax_dev = dax_dev;
	cbdt->transport_info = (struct cbd_transport_info *)kaddr;

	return 0;

dax_put:
	fs_put_dax(dax_dev, cbdt);
bdev_release:
	bdev_release(handle);
err:
	return ret;
}

static void cbdt_dax_release(struct cbd_transport *cbdt)
{
	if (cbdt->dax_dev)
		fs_put_dax(cbdt->dax_dev, cbdt);

	if (cbdt->bdev_handle)
		bdev_release(cbdt->bdev_handle);
}

static int cbd_transport_init(struct cbd_transport *cbdt)
{
	struct device *dev;

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

	return device_add(&cbdt->device);
}


static int cbdt_validate(struct cbd_transport *cbdt)
{
	u16 flags;

	if (le64_to_cpu(cbdt->transport_info->magic) != CBD_TRANSPORT_MAGIC) {
		return -EINVAL;
	}

	flags = le16_to_cpu(cbdt->transport_info->flags);
#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __GIT_ENDIAN : defined(__BIG_ENDIAN)
	if (!(flags & CBDT_INFO_F_BIGENDIAN)) {
		return -EINVAL;
	}
#else
	if ((flags & CBDT_INFO_F_BIGENDIAN)) {
		return -EINVAL;
	}
#endif

	return 0;
}

int cbdt_unregister(u32 tid)
{
	struct cbd_transport *cbdt;

	cbdt = cbd_transports[tid];
	if (!cbdt) {
		pr_err("tid: %u, is not registered\n", tid);
		return -EINVAL;
	}

	mutex_lock(&cbdt->lock);
	if (!list_empty(&cbdt->backends) || !list_empty(&cbdt->devices)) {
		mutex_unlock(&cbdt->lock);
		return -EBUSY;
	}
	mutex_unlock(&cbdt->lock);

	cbd_host_unregister(cbdt);
	device_unregister(&cbdt->device);
	cbdt_dax_release(cbdt);
	cbdt_destroy(cbdt);

	return 0;
}


int cbdt_register(struct cbdt_register_options *opts)
{
	struct cbd_transport *cbdt;
	int ret;

	/* TODO support /dev/dax */
	if (!strstr(opts->path, "/dev/pmem")) {
		pr_err("%s: path (%s) is not pmem\n",
		       __func__, opts->path);
		return -EINVAL;
	}

	cbdt = cbdt_alloc();
	if (!cbdt) {
		return -ENOMEM;
	}

	ret = cbdt_dax_init(cbdt, opts->path);
	if (ret) {
		goto cbdt_destroy;
	}

	if (opts->format) {
		ret = cbd_transport_format(cbdt, opts->force);
		if (ret < 0) {
			goto dax_release;
		}
	}

	ret = cbdt_validate(cbdt);
	if (ret) {
		goto dax_release;
	}

	ret = cbd_transport_init(cbdt);
	if (ret) {
		goto dax_release;
	}

	ret = cbd_host_register(cbdt, opts->hostname);
	if (ret) {
		goto dev_unregister;
	}

	return 0;

devs_exit:
	cbd_host_unregister(cbdt);
dev_unregister:
	device_unregister(&cbdt->device);
dax_release:
	cbdt_dax_release(cbdt);
cbdt_destroy:
	cbdt_destroy(cbdt);

	return ret;
}

void cbdt_add_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb)
{
	mutex_lock(&cbdt->lock);
	list_add(&cbdb->node, &cbdt->backends);
	mutex_unlock(&cbdt->lock);
}

void cbdt_del_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb)
{
	if (list_empty(&cbdb->node))
		return;

	mutex_lock(&cbdt->lock);
	list_del_init(&cbdb->node);
	mutex_unlock(&cbdt->lock);
}

struct cbd_backend *cbdt_get_backend(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_backend *backend;

	mutex_lock(&cbdt->lock);
	list_for_each_entry(backend, &cbdt->backends, node) {
		if (backend->backend_id == id) {
			goto out;
		}
	}
	backend = NULL;
out:
	mutex_unlock(&cbdt->lock);
	return backend;
}

void cbdt_add_blkdev(struct cbd_transport *cbdt, struct cbd_blkdev *blkdev)
{
	mutex_lock(&cbdt->lock);
	list_add(&blkdev->node, &cbdt->devices);
	mutex_unlock(&cbdt->lock);
}

struct cbd_blkdev *cbdt_fetch_blkdev(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_blkdev *dev;

	mutex_lock(&cbdt->lock);
	list_for_each_entry(dev, &cbdt->devices, node) {
		if (dev->blkdev_id == id) {
			list_del(&dev->node);
			goto out;
		}
	}
	dev = NULL;
out:
	mutex_unlock(&cbdt->lock);
	return dev;
}

struct page *cbdt_page(struct cbd_transport *cbdt, u64 transport_off)
{
	long access_size;
	pfn_t pfn;

	access_size = dax_direct_access(cbdt->dax_dev, transport_off >> PAGE_SHIFT, 1, DAX_ACCESS, NULL, &pfn);

	return pfn_t_to_page(pfn);
}

void cbdt_flush_range(struct cbd_transport *cbdt, void *pos, u64 size)
{
	u64 offset = pos - (void *)cbdt->transport_info;
	u32 off_in_page = (offset & CBD_PAGE_MASK);

	offset -= off_in_page;
	size = round_up(off_in_page + size, PAGE_SIZE);

	while (size) {
		flush_dcache_page(cbdt_page(cbdt, offset));
		offset += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
}
