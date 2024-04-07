#include "cbd_internal.h"
#include <linux/delay.h>

static ssize_t cbd_backend_path_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	char path[CBD_PATH_LEN];
	struct cbd_backend_device *backend;
	struct cbd_backend_info *backend_info;
	int ret;

	backend = container_of(dev, struct cbd_backend_device, dev);
	backend_info = backend->backend_info;

	memcpy_fromio(path, backend_info->path, CBD_PATH_LEN);

	if (path[0] == 0)
		return 0;

	return sprintf(buf, "%s\n", path);
}

static DEVICE_ATTR(path, 0400, cbd_backend_path_show, NULL);

static ssize_t cbd_backend_alive_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *backend_info;
	ktime_t oldest, ts;
	int ret;

	backend = container_of(dev, struct cbd_backend_device, dev);
	backend_info = backend->backend_info;

	ts = backend_info->alive_ts;
	oldest = ktime_sub_ms(ktime_get_real(), 30 * 1000);

	if (ktime_after(ts, oldest))
		return sprintf(buf, "true\n");

	return sprintf(buf, "false\n");
}

static DEVICE_ATTR(alive, 0400, cbd_backend_alive_show, NULL);

static struct attribute *cbd_backend_attrs[] = {
	&dev_attr_path.attr,
	&dev_attr_alive.attr,
	NULL
};

static struct attribute_group cbd_backend_attr_group = {
	.attrs = cbd_backend_attrs,
};

static const struct attribute_group *cbd_backend_attr_groups[] = {
	&cbd_backend_attr_group,
	NULL
};

static void cbd_backend_release(struct device *dev)
{
}

struct device_type cbd_backend_type = {
	.name		= "cbd_backend",
	.groups		= cbd_backend_attr_groups,
	.release	= cbd_backend_release,
};

struct device_type cbd_backends_type = {
	.name		= "cbd_backends",
	.release	= cbd_backend_release,
};

int cbd_backends_init(struct cbd_transport *cbdt)
{
	struct cbd_backends_device *cbd_backends_dev;
	struct cbd_backend_device *backend;
	int i;

	cbd_backends_dev = kzalloc(sizeof(struct cbd_backends_device) + cbdt->transport_info->backend_num * sizeof(struct cbd_backend_device), GFP_KERNEL);
	if (!cbd_backends_dev) {
		return -ENOMEM;
	}

	device_initialize(&cbd_backends_dev->backends_dev);
	device_set_pm_not_required(&cbd_backends_dev->backends_dev);
	dev_set_name(&cbd_backends_dev->backends_dev, "cbd_backends");
	cbd_backends_dev->backends_dev.parent = &cbdt->device;
	cbd_backends_dev->backends_dev.type = &cbd_backends_type;
	device_add(&cbd_backends_dev->backends_dev);

	for (i = 0; i < cbdt->transport_info->backend_num; i++) {
		struct cbd_backend_device *backend = &cbd_backends_dev->backend_devs[i];
		struct device *backend_dev = &backend->dev;

		backend->backend_info = cbdt_get_backend_info(cbdt, i);
		device_initialize(backend_dev);
		device_set_pm_not_required(backend_dev);
		dev_set_name(backend_dev, "backend%u", i);
		backend_dev->parent = &cbd_backends_dev->backends_dev;
		backend_dev->type = &cbd_backend_type;

		device_add(backend_dev);
	}
	cbdt->cbd_backends_dev = cbd_backends_dev;

	return 0;
}

int cbd_backends_exit(struct cbd_transport *cbdt)
{
	struct cbd_backends_device *cbd_backends_dev = cbdt->cbd_backends_dev;
	int i;

	if (!cbd_backends_dev)
		return 0;

	for (i = 0; i < cbdt->transport_info->backend_num; i++) {
		struct cbd_backend_device *backend = &cbd_backends_dev->backend_devs[i];
		struct device *backend_dev = &backend->dev;

		device_del(backend_dev);
	}

	device_del(&cbd_backends_dev->backends_dev);

	kfree(cbd_backends_dev);
	cbdt->cbd_backends_dev = NULL;

	return 0;
}

static struct cbd_backend_io {
	struct cbd_se *se;
	u64	off;
	u32	len;
	struct bio	*bio;
	struct cbd_backend_handler *handler;
};

static void backend_bio_end(struct bio *bio)
{
	struct cbd_backend_io *backend_io = bio->bi_private;
	struct cbd_se *se = backend_io->se;
	struct cbd_backend_handler *handler = backend_io->handler;
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	u32 copied;
	u32 done = 0;
	u32 len = se->len;
	u64 data_head = se->data_off;
	void *base;

	if (bio->bi_status != 0) {
		pr_err("bio_op: %d offset: %llu, len: %llu backend bio failed: %d\n", cbd_se_hdr_get_op(se->header.len_op), se->offset, se->len, blk_status_to_errno(bio->bi_status));
	}

	//pr_err("bio: %p sector in bio_end: sector: %llu\n", bio, bio->bi_iter.bi_sector);

	if (cbd_se_hdr_get_op(se->header.len_op) == CBD_OP_READ) {
		cbdc_copy_from_bio(&handler->channel, se->data_off, se->data_len, bio);
	}

	spin_lock(&handler->channel.compr_lock);
	struct cbd_ce *ce = get_compr_head(handler);

	memset(ce, 0, sizeof(*ce));
	ce->priv_data = se->priv_data;
	ce->flags = 0;
	ce->result = 0;
	CBDC_UPDATE_COMPR_HEAD(handler->channel_info->compr_head, sizeof(struct cbd_ce), handler->channel_info->compr_size);
	spin_unlock(&handler->channel.compr_lock);

	bio_free_pages(bio);
	bio_put(bio);
	kfree(backend_io);
}

int cbd_bio_alloc_pages(struct bio *bio, size_t size, gfp_t gfp_mask)
{
        while (size) {
                struct page *page = alloc_pages(gfp_mask, 0);
                unsigned len = min_t(size_t, PAGE_SIZE, size);

                if (!page) {
			pr_err("failed to alloc page");
                        return -ENOMEM;
		}

                if (unlikely(!bio_add_page(bio, page, len, 0))) {
                        __free_page(page);
			pr_err("failed to add page");
                        break;
                }

                size -= len;
        }

        return 0;
}

static struct cbd_backend_io *backend_prepare_io(struct cbd_backend_handler *handler, struct cbd_se *se, blk_opf_t opf)
{
	struct cbd_backend_io *backend_io;
	struct cbd_backend *cbd_b = handler->cbd_b;

	backend_io = kzalloc(sizeof(struct cbd_backend_io), GFP_KERNEL);
	backend_io->se = se;

	backend_io->handler = handler;
	//pr_err("handle: priv_data: %llu, offset:%llu, sector: %llu, len: %u, data_off: %llu, data_len: %u, opf: %x\n", se->priv_data, se->offset, se->offset >> SECTOR_SHIFT, se->len, se->data_off, se->data_len, opf);
	backend_io->bio = bio_alloc_bioset(cbd_b->bdev, roundup(se->len, 4096) / 4096, opf, GFP_KERNEL, &handler->bioset);

	backend_io->bio->bi_iter.bi_sector = se->offset >> SECTOR_SHIFT;
	if (backend_io->bio->bi_iter.bi_size) {
		pr_err("bi_size is not 0");
	}
	backend_io->bio->bi_iter.bi_size = 0;
	backend_io->bio->bi_private = backend_io;
	backend_io->bio->bi_end_io = backend_bio_end;

	return backend_io;
}

static int handle_backend_cmd(struct cbd_backend_handler *handler, struct cbd_se *se)
{
	struct cbd_backend *cbd_b = handler->cbd_b;
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	uint32_t bvec_index = 0;
	void *base = handler->channel.data + se->data_off;
	u32 done = 0;
	u32 copied;
	u32 len = se->len;
	struct cbd_request *cbd_req = NULL;
	struct cbd_backend_io *backend_io;
	int ret;

	if (cbd_se_hdr_flags_test(se, CBD_SE_HDR_DONE)) {
		return 0 ;
	}

	switch (cbd_se_hdr_get_op(se->header.len_op)) {
	case CBD_OP_PAD:
		cbd_se_hdr_flags_set(se, CBD_SE_HDR_DONE);
		return 0;
	case CBD_OP_READ:
		backend_io = backend_prepare_io(handler, se, REQ_OP_READ);
		break;
	case CBD_OP_WRITE:
		backend_io = backend_prepare_io(handler, se, REQ_OP_WRITE);
		break;
	case CBD_OP_DISCARD:
		ret = blkdev_issue_discard(cbd_b->bdev, se->offset >> SECTOR_SHIFT,
				se->len, GFP_NOIO);
		return ret;
	case CBD_OP_WRITE_ZEROS:
		ret = blkdev_issue_zeroout(cbd_b->bdev, se->offset >> SECTOR_SHIFT,
				se->len, GFP_NOIO, 0);
		return ret;
	case CBD_OP_FLUSH:
		ret = blkdev_issue_flush(cbd_b->bdev);
		return ret;
	default:
		pr_err("unrecognized op: %x", cbd_se_hdr_get_op(se->header.len_op));
		return -EINVAL;
	}

	if (0) {
		spin_lock(&handler->channel.compr_lock);
		struct cbd_ce *ce = get_compr_head(handler);

		//backend_io->bio = bio_alloc_bioset(cbd_b->bdev, roundup(len, 4096) / 4096, cbd_se_hdr_get_op(se->header.len_op), GFP_KERNEL, &handler->bioset);
		//bio_put(backend_io->bio);

		memset(ce, 0, sizeof(*ce));
		ce->priv_data = se->priv_data;
		ce->flags = 0;
		ce->result = 0;
		CBDC_UPDATE_COMPR_HEAD(handler->channel_info->compr_head, sizeof(struct cbd_ce), handler->channel_info->compr_size);
		spin_unlock(&handler->channel.compr_lock);

		if (cbd_req)
			cbd_req_stats_ktime_delta(cbd_req->start_to_ack,  cbd_req->start_kt);
		kfree(backend_io);
		return 0;
	}

	//pr_err("len: %u, op: %u iovcnt: %u", len, cbd_se_hdr_get_op(se->header.len_op), roundup(len, 4097) / 4096);

	cbd_bio_alloc_pages(backend_io->bio, len, GFP_NOIO);

	if (cbd_se_hdr_get_op(se->header.len_op) == CBD_OP_WRITE) {
		//pr_err("backend write start");
		cbdc_copy_to_bio(&handler->channel, se->data_off, se->data_len, backend_io->bio, NULL);
		//pr_err("backend write finish");
	}

	//pr_err("bio: %p sector before submit: sector: %llu\n", backend_io->bio, backend_io->bio->bi_iter.bi_sector);
	submit_bio(backend_io->bio);

	return 0;
}

static u64 get_handle_work_delay(struct cbd_backend_handler *handler)
{
	if (handler->delay_cur == handler->delay_max)
		return handler->delay_cur;

	handler->delay_cur += handler->delay_cur / 10;

	if (handler->delay_cur > handler->delay_max)
		handler->delay_cur = handler->delay_max;

	return handler->delay_cur;
}

static void reset_handle_work_delay(struct cbd_backend_handler *handler)
{
	handler->delay_cur = handler->delay_min;
	return;
}

static void handle_work_fn(struct work_struct *work)
{
	struct cbd_backend_handler *handler = container_of(work, struct cbd_backend_handler, handle_work.work);
	struct cbd_backend *cbd_b = handler->cbd_b;
	struct cbd_se *se;
	struct cbd_request *cbd_req;
	struct cbd_backend_io *backend_io;
	int retry = 0;
	int ret;
again:
	spin_lock(&handler->channel.cmdr_lock);
	//pr_err("se_to_handle: %d", handler->se_to_handle);
	//pr_err("se_head: %d", handler->channel_info->cmd_head);
	se = get_se_to_handle(handler);
	if (se == get_se_head(handler)) {
		spin_unlock(&handler->channel.cmdr_lock);
		if (++retry < handler->busy_retry_count) {
			cpu_relax();
			fsleep(handler->busy_retry_interval);
			goto again;
		}

		queue_delayed_work(handler->handle_wq, &handler->handle_work, get_handle_work_delay(handler));
		return;
	}

	retry = 0;
	reset_handle_work_delay(handler);
	if (handler->channel_info->cmdr_size == 0) {
		pr_err("channel_info: %p", handler->channel_info);
		pr_err("cmdr_size is 0\n");
	}
	handler->se_to_handle = (handler->se_to_handle + cbd_se_hdr_get_len(se->header.len_op)) % handler->channel_info->cmdr_size;
	spin_unlock(&handler->channel.cmdr_lock);

	ret = handle_backend_cmd(handler, se);
	if (ret) {
		pr_err("failed to handle backend cmd\n");
	}

	goto again;
}

static ssize_t handler_cpu_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_handler *handler;
	int ret;

	handler = container_of(dev, struct cbd_backend_handler, dev);

	if (handler->cpu == -1)
		return 0;

	return sprintf(buf, "%u\n", handler->cpu);
}

static ssize_t handler_cpu_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *ubuf,
				 size_t size)
{
	struct cbd_backend_handler *handler;
	int token;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (kstrtouint(ubuf, 10, &token)) {
		return -EINVAL;
	}

	if ((token != -1) && !cpu_online(token)) {
		pr_err("cpu %u is not online.", token);
		return -EINVAL;
	}

	handler = container_of(dev, struct cbd_backend_handler, dev);

	handler->cpu = token;

	return size;
}

static DEVICE_ATTR(cpu, 0600, handler_cpu_show, handler_cpu_store);

static struct attribute *handler_attrs[] = {
	&dev_attr_cpu.attr,
	NULL
};

static struct attribute_group handler_attr_group = {
	.attrs = handler_attrs,
};

static const struct attribute_group *handler_attr_groups[] = {
	&handler_attr_group,
	NULL
};

static void handler_release(struct device *dev)
{
}

struct device_type handler_type = {
	.name		= "backend_handler",
	.groups		= handler_attr_groups,
	.release	= handler_release,
};

static int create_handler(struct cbd_backend *cbd_b, u32 channel_id)
{
	struct cbd_transport *cbdt = cbd_b->cbdt;
	struct cbd_channel_info *channel_info;
	struct cbd_backend_handler *handler;

	pr_err("channel_id: %u", channel_id);
	handler = kzalloc(sizeof(struct cbd_backend_handler), GFP_KERNEL);
	if (!handler) {
		//cbd_backend_err(cbd_b, "failed to alloc memory for handler %u.", channel_id);
		return -ENOMEM;
	}

	handler->cbd_b = cbd_b;
	channel_info = cbdt_get_channel_info(cbdt, channel_id);

	handler->channel_id = channel_id;
	handler->channel.channel_id = channel_id;
	handler->channel_info = channel_info;
	handler->channel.cmdr = (void *)channel_info + CBDC_CMDR_OFF;
	handler->channel.compr = (void *)channel_info + CBDC_COMPR_OFF;
	handler->channel.data = (void *)channel_info + CBDC_DATA_OFF;

	handler->channel_info->cmdr_off = CBDC_CMDR_OFF;
	handler->channel_info->cmdr_size = CBDC_CMDR_SIZE;
	pr_err("channel_info: %p init cmdr_size", handler->channel_info);
	handler->channel_info->compr_off = CBDC_COMPR_OFF;
	handler->channel_info->compr_size = CBDC_COMPR_SIZE;

	handler->handle_wq = alloc_workqueue("handler%u-tasks",  WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_SYSFS, 0, channel_id);
	handler->se_to_handle = channel_info->cmd_tail;
	spin_lock_init(&handler->channel.cmdr_lock);
	spin_lock_init(&handler->channel.compr_lock);
	INIT_DELAYED_WORK(&handler->handle_work, handle_work_fn);
	INIT_LIST_HEAD(&handler->handlers_node);
	bioset_init(&handler->bioset, 128, 0, BIOSET_NEED_BVECS);

	handler->delay_max = msecs_to_jiffies(1000);
	handler->delay_min = usecs_to_jiffies(100);
	handler->delay_cur = handler->delay_min;

	handler->busy_retry_count = 100;
	handler->busy_retry_interval = 1;

	struct device *dev = &handler->dev;
	int ret;
	cbd_setup_device(dev, &cbd_b->backend_device->dev, &handler_type, "handler%u", channel_id);
	handler->cpu = -1;

	list_add(&handler->handlers_node, &cbd_b->handlers);
	if (handler->cpu == -1) {
		queue_delayed_work(handler->handle_wq, &handler->handle_work, 0);
	} else {
		queue_delayed_work_on(handler->cpu, handler->handle_wq, &handler->handle_work, 0);
	}
	cbd_channel_set_backend_state(channel_info, cbdc_backend_state_running);

	return 0;
};

static void __destroy_handler(struct cbd_backend_handler *handler)
{
	cancel_delayed_work_sync(&handler->handle_work);
	drain_workqueue(handler->handle_wq);
	destroy_workqueue(handler->handle_wq);
	cbd_channel_set_backend_state(handler->channel_info, cbdc_backend_state_none);
	device_del(&handler->dev);
	bioset_exit(&handler->bioset);
	kfree(handler);
}

int destroy_handler(struct cbd_backend *cbd_b, u32 channel_id)
{
	struct cbd_backend_handler *handler, *handler_next;
	bool found = false;

	list_for_each_entry_safe(handler, handler_next, &cbd_b->handlers, handlers_node) {
		if (handler->channel_id == channel_id) {
			list_del_init(&handler->handlers_node);
			found = true;
			break;
		}
	}

	if (!found) {
		return -ENOENT;
	}

	__destroy_handler(handler);

	return 0;
}

void destroy_handlers(struct cbd_backend *cbd_b)
{
	struct cbd_backend_handler *handler, *handler_next;

	list_for_each_entry_safe(handler, handler_next, &cbd_b->handlers, handlers_node) {
		list_del_init(&handler->handlers_node);
		__destroy_handler(handler);
	}
}

void state_work_fn(struct work_struct *work)
{
	struct cbd_backend *cbd_b = container_of(work, struct cbd_backend, state_work.work);
	struct cbd_transport *cbd_r = cbd_b->cbdt;
	struct cbd_channel_info *channel_info;
	u32 blkdev_state, backend_state, backend_id;
	int i;

	for (i = 0; i < cbd_r->transport_info->channel_num; i++) {
		channel_info = cbdt_get_channel_info(cbd_r, i);
		//pr_err("channel_info: %p", channel_info);
		blkdev_state = cbd_channel_get_blkdev_state(channel_info);
		backend_state = cbd_channel_get_backend_state(channel_info);
		backend_id = cbd_channel_get_backend_id(channel_info);

		//pr_err("blkdev_state: %u, backend_State: %u, backend_id: %u", blkdev_state, backend_state, backend_id);

		if (blkdev_state == cbdc_blkdev_state_running &&
				backend_state == cbdc_backend_state_none &&
				backend_id == cbd_b->bid) {

			pr_err("someone is waiting");
			mutex_lock(&cbd_b->lock);
			create_handler(cbd_b, i);
			mutex_unlock(&cbd_b->lock);
			pr_err("backend running");
		}
		
		if (blkdev_state == cbdc_blkdev_state_stopped &&
				backend_state == cbdc_backend_state_running &&
				backend_id == cbd_b->bid) {
			mutex_lock(&cbd_b->lock);
			destroy_handler(cbd_b, i);
			mutex_unlock(&cbd_b->lock);
		}
	}

	queue_delayed_work(cbd_wq, &cbd_b->state_work, 1 * HZ);
}

static int cbd_backend_init(struct cbd_backend *cbd_b, struct cbd_adm_options *opts)
{
	int ret;
	struct cbd_backend_info *b_info;
	struct cbd_transport *cbdt = cbd_b->cbdt;

	b_info = cbdt_get_backend_info(cbdt, cbd_b->bid);
	cbd_b->backend_info = b_info;

	b_info->host_id = cbd_b->cbdt->host->host_id;

	pr_err("open %s", cbd_b->path);
	cbd_b->bdev_handle = bdev_open_by_path(cbd_b->path, BLK_OPEN_READ | BLK_OPEN_WRITE, cbd_b, NULL);
	if (IS_ERR(cbd_b->bdev_handle)) {
		pr_err("failed to open bdev: %d", PTR_ERR(cbd_b->bdev_handle));
		return PTR_ERR(cbd_b->bdev_handle);
	}
	cbd_b->bdev = cbd_b->bdev_handle->bdev;

	cbd_b->task_wq = alloc_workqueue("cbd_b-tasks", WQ_MEM_RECLAIM, 0);

	//queue_delayed_work(cbd_b->task_wq, &cbd_b->handle_work, delay);

	INIT_DELAYED_WORK(&cbd_b->state_work, state_work_fn);
	INIT_LIST_HEAD(&cbd_b->handlers);
	cbd_b->backend_device = &cbdt->cbd_backends_dev->backend_devs[cbd_b->bid];

	mutex_init(&cbd_b->lock);

	queue_delayed_work(cbd_b->task_wq, &cbd_b->state_work, 0);

	return 0;
}


int cbd_backend_start(struct cbd_transport *cbdt, struct cbd_adm_options *opts)
{
	struct cbd_backend *backend;
	struct cbd_backend_info *backend_info;
	uuid_t b_uuid;
	u32 bid;
	int ret;

	ret = cbdt_get_empty_bid(cbdt, &bid);
	if (ret) {
		pr_err("failed to find empty bid: %d\n", ret);
		return ret;
	}

	backend_info = cbdt_get_backend_info(cbdt, bid);

	if (backend_info->status != cbd_backend_status_none)
		return -EEXIST;

	backend_info->status = cbd_backend_status_running;

	backend = kzalloc(sizeof(struct cbd_backend), GFP_KERNEL);
	if (!backend) {
		return -ENOMEM;
	}

	strlcpy(backend->path, opts->backend.path, CBD_PATH_LEN);
	memcpy_toio(backend_info->path, backend->path, CBD_PATH_LEN);
	INIT_LIST_HEAD(&backend->node);
	backend->bid = bid;
	cbdt_add_backend(cbdt, backend);

	backend->cbdt = cbdt;

	cbd_backend_init(backend, opts);

	return 0;
}

int cbd_backend_stop(struct cbd_transport *cbdt, struct cbd_adm_options *opts)
{
	struct cbd_backend *cbd_b;
	struct cbd_backend_info *backend_info;

	cbd_b = cbdt_fetch_backend(cbdt, opts->bid);
	if (!cbd_b) {
		return -ENOENT;
	}

	cancel_delayed_work_sync(&cbd_b->state_work);
	destroy_handlers(cbd_b);

	backend_info = cbdt_get_backend_info(cbdt, cbd_b->bid);
	backend_info->host_id = U32_MAX;
	backend_info->status = cbd_backend_status_none;

	drain_workqueue(cbd_b->task_wq);
	destroy_workqueue(cbd_b->task_wq);
	bdev_release(cbd_b->bdev_handle);
	kfree(cbd_b);

	return 0;
}

int cbd_backend_clear(struct cbd_transport *cbdt, struct cbd_adm_options *opts)
{
	struct cbd_backend *cbd_b;
	struct cbd_backend_info *backend_info;

	backend_info = cbdt_get_backend_info(cbdt, opts->bid);
	backend_info->host_id = U32_MAX;

	return 0;
}
