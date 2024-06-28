#include "cbd_internal.h"

static ssize_t backend_host_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *backend_info;

	backend = container_of(dev, struct cbd_backend_device, dev);
	backend_info = backend->backend_info;

	if (backend_info->state == cbd_backend_state_none)
		return 0;

	return sprintf(buf, "%u\n", backend_info->host_id);
}

static DEVICE_ATTR(host_id, 0400, backend_host_id_show, NULL);

static ssize_t backend_path_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_backend_device *backend;
	struct cbd_backend_info *backend_info;

	backend = container_of(dev, struct cbd_backend_device, dev);
	backend_info = backend->backend_info;

	if (backend_info->state == cbd_backend_state_none)
		return 0;

	if (strlen(backend_info->path) == 0)
		return 0;

	return sprintf(buf, "%s\n", backend_info->path);
}

static DEVICE_ATTR(path, 0400, backend_path_show, NULL);

CBD_OBJ_HEARTBEAT(backend);

static struct attribute *cbd_backend_attrs[] = {
	&dev_attr_path.attr,
	&dev_attr_host_id.attr,
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

const struct device_type cbd_backend_type = {
	.name		= "cbd_backend",
	.groups		= cbd_backend_attr_groups,
	.release	= cbd_backend_release,
};

const struct device_type cbd_backends_type = {
	.name		= "cbd_backends",
	.release	= cbd_backend_release,
};

void cbdb_add_handler(struct cbd_backend *cbdb, struct cbd_handler *handler)
{
	mutex_lock(&cbdb->lock);
	list_add(&handler->handlers_node, &cbdb->handlers);
	mutex_unlock(&cbdb->lock);
}

void cbdb_del_handler(struct cbd_backend *cbdb, struct cbd_handler *handler)
{
	mutex_lock(&cbdb->lock);
	list_del_init(&handler->handlers_node);
	mutex_unlock(&cbdb->lock);
}

static struct cbd_handler *cbdb_get_handler(struct cbd_backend *cbdb, u32 channel_id)
{
	struct cbd_handler *handler, *handler_next;
	bool found = false;

	mutex_lock(&cbdb->lock);
	list_for_each_entry_safe(handler, handler_next, &cbdb->handlers, handlers_node) {
		if (handler->channel.channel_id == channel_id) {
			found = true;
			break;
		}
	}
	mutex_unlock(&cbdb->lock);

	if (!found)
		return ERR_PTR(-ENOENT);

	return handler;
}

static void state_work_fn(struct work_struct *work)
{
	struct cbd_backend *cbdb = container_of(work, struct cbd_backend, state_work.work);
	struct cbd_transport *cbdt = cbdb->cbdt;
	struct cbd_channel_info *channel_info;
	u32 blkdev_state, backend_state, backend_id;
	int i;

	for (i = 0; i < cbdt->transport_info->channel_num; i++) {
		channel_info = cbdt_get_channel_info(cbdt, i);

		blkdev_state = channel_info->blkdev_state;
		backend_state = channel_info->backend_state;
		backend_id = channel_info->backend_id;

		if (blkdev_state == cbdc_blkdev_state_running &&
				backend_state == cbdc_backend_state_none &&
				backend_id == cbdb->backend_id) {

			cbd_handler_create(cbdb, i);
		}

		if (blkdev_state == cbdc_blkdev_state_none &&
				backend_state == cbdc_backend_state_running &&
				backend_id == cbdb->backend_id) {
			struct cbd_handler *handler;

			handler = cbdb_get_handler(cbdb, i);
			cbd_handler_destroy(handler);
		}
	}

	queue_delayed_work(cbd_wq, &cbdb->state_work, 1 * HZ);
}

static void backend_heart_beat(void *data)
{
	struct cbd_backend *cbdb = (struct cbd_backend *)data;
	struct cbd_backend_info *info = cbdb->backend_info;
	struct cbd_handler *handler;

	info->alive_ts = ktime_get_real();

	mutex_lock(&cbdb->lock);
	list_for_each_entry(handler, &cbdb->handlers, handlers_node) {
		cbdc_hb(&handler->channel);
	}
	mutex_unlock(&cbdb->lock);
}

static struct cbd_obj_ops backend_ops = {
	.heart_beat = backend_heart_beat,
};

static int cbd_backend_init(struct cbd_backend *cbdb)
{
	struct cbd_backend_info *b_info;
	struct cbd_transport *cbdt = cbdb->cbdt;

	b_info = cbdt_get_backend_info(cbdt, cbdb->backend_id);
	cbdb->backend_info = b_info;

	b_info->host_id = cbdb->cbdt->host->host_id;

	cbdb->task_wq = alloc_workqueue("cbdt%d-b%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cbdb->backend_id);
	if (!cbdb->task_wq)
		return -ENOMEM;

	cbdb->bdev_file = bdev_file_open_by_path(cbdb->path, BLK_OPEN_READ | BLK_OPEN_WRITE, cbdb, NULL);
	if (IS_ERR(cbdb->bdev_file)) {
		cbdt_err(cbdt, "failed to open bdev: %d", (int)PTR_ERR(cbdb->bdev_file));
		destroy_workqueue(cbdb->task_wq);
		return PTR_ERR(cbdb->bdev_file);
	}
	cbdb->bdev = file_bdev(cbdb->bdev_file);
	b_info->dev_size = bdev_nr_sectors(cbdb->bdev);

	INIT_DELAYED_WORK(&cbdb->state_work, state_work_fn);
	INIT_DELAYED_WORK(&cbdb->hb_work, backend_hb_workfn);
	cbdb->ops = &backend_ops;
	INIT_LIST_HEAD(&cbdb->handlers);
	cbdb->backend_device = &cbdt->cbd_backends_dev->backend_devs[cbdb->backend_id];

	mutex_init(&cbdb->lock);

	queue_delayed_work(cbd_wq, &cbdb->state_work, 0);
	queue_delayed_work(cbd_wq, &cbdb->hb_work, 0);

	return 0;
}

int cbd_backend_start(struct cbd_transport *cbdt, char *path, u32 backend_id)
{
	struct cbd_backend *backend;
	struct cbd_backend_info *backend_info;
	int ret;

	if (backend_id == U32_MAX) {
		ret = cbdt_get_empty_backend_id(cbdt, &backend_id);
		if (ret)
			return ret;
	}

	backend_info = cbdt_get_backend_info(cbdt, backend_id);

	backend = kzalloc(sizeof(struct cbd_backend), GFP_KERNEL);
	if (!backend)
		return -ENOMEM;

	strscpy(backend->path, path, CBD_PATH_LEN);
	memcpy(backend_info->path, backend->path, CBD_PATH_LEN);
	INIT_LIST_HEAD(&backend->node);
	backend->backend_id = backend_id;
	backend->cbdt = cbdt;

	ret = cbd_backend_init(backend);
	if (ret)
		goto backend_free;

	backend_info->state = cbd_backend_state_running;

	cbdt_add_backend(cbdt, backend);

	return 0;

backend_free:
	kfree(backend);

	return ret;
}

int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id, bool force)
{
	struct cbd_backend *cbdb;
	struct cbd_backend_info *backend_info;
	struct cbd_handler *handler, *next;

	cbdb = cbdt_get_backend(cbdt, backend_id);
	if (!cbdb)
		return -ENOENT;

	mutex_lock(&cbdb->lock);
	if (!list_empty(&cbdb->handlers) && !force) {
		mutex_unlock(&cbdb->lock);
		return -EBUSY;
	}
	cbdt_del_backend(cbdt, cbdb);

	cancel_delayed_work_sync(&cbdb->hb_work);
	cancel_delayed_work_sync(&cbdb->state_work);

	mutex_unlock(&cbdb->lock);
	list_for_each_entry_safe(handler, next, &cbdb->handlers, handlers_node) {
		cbd_handler_destroy(handler);
	}
	mutex_lock(&cbdb->lock);

	backend_info = cbdt_get_backend_info(cbdt, cbdb->backend_id);
	backend_info->state = cbd_backend_state_none;
	mutex_unlock(&cbdb->lock);

	drain_workqueue(cbdb->task_wq);
	destroy_workqueue(cbdb->task_wq);

	fput(cbdb->bdev_file);
	kfree(cbdb);

	return 0;
}

int cbd_backend_clear(struct cbd_transport *cbdt, u32 backend_id)
{
	struct cbd_backend_info *backend_info;

	backend_info = cbdt_get_backend_info(cbdt, backend_id);
	if (cbd_backend_info_is_alive(backend_info)) {
		cbdt_err(cbdt, "backend %u is still alive\n", backend_id);
		return -EBUSY;
	}

	if (backend_info->state == cbd_backend_state_none)
		return 0;

	backend_info->state = cbd_backend_state_none;

	return 0;
}
