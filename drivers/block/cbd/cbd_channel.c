#include "cbd_internal.h"

static ssize_t cbd_channel_alive_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_channel_device *channel;
	struct cbd_channel_info *channel_info;
	ktime_t oldest, ts;
	int ret;

	channel = container_of(dev, struct cbd_channel_device, dev);
	channel_info = channel->channel_info;

	ts = channel_info->alive_ts;
	oldest = ktime_sub_ms(ktime_get_real(), 30 * 1000);

	if (ktime_after(ts, oldest))
		return sprintf(buf, "true\n");

	return sprintf(buf, "false\n");
}

static DEVICE_ATTR(alive, 0400, cbd_channel_alive_show, NULL);

static struct attribute *cbd_channel_attrs[] = {
	&dev_attr_alive.attr,
	NULL
};

static struct attribute_group cbd_channel_attr_group = {
	.attrs = cbd_channel_attrs,
};

static const struct attribute_group *cbd_channel_attr_groups[] = {
	&cbd_channel_attr_group,
	NULL
};

static void cbd_channel_release(struct device *dev)
{
}

struct device_type cbd_channel_type = {
	.name		= "cbd_channel",
	.groups		= cbd_channel_attr_groups,
	.release	= cbd_channel_release,
};

struct device_type cbd_channels_type = {
	.name		= "cbd_channels",
	.release	= cbd_channel_release,
};

int cbd_channels_init(struct cbd_transport *cbdt)
{
	struct cbd_channels_device *cbd_channels_dev;
	struct cbd_channel_device *channel;
	int i;

	cbd_channels_dev = kzalloc(sizeof(struct cbd_channels_device) + cbdt->transport_info->channel_num * sizeof(struct cbd_channel_device), GFP_KERNEL);
	if (!cbd_channels_dev) {
		return -ENOMEM;
	}

	device_initialize(&cbd_channels_dev->channels_dev);
	device_set_pm_not_required(&cbd_channels_dev->channels_dev);
	dev_set_name(&cbd_channels_dev->channels_dev, "cbd_channels");
	cbd_channels_dev->channels_dev.parent = &cbdt->device;
	cbd_channels_dev->channels_dev.type = &cbd_channels_type;
	device_add(&cbd_channels_dev->channels_dev);

	for (i = 0; i < cbdt->transport_info->channel_num; i++) {
		struct cbd_channel_device *channel = &cbd_channels_dev->channel_devs[i];
		struct device *channel_dev = &channel->dev;

		channel->channel_info = cbdt_get_channel_info(cbdt, i);
		device_initialize(channel_dev);
		device_set_pm_not_required(channel_dev);
		dev_set_name(channel_dev, "channel%u", i);
		channel_dev->parent = &cbd_channels_dev->channels_dev;
		channel_dev->type = &cbd_channel_type;

		device_add(channel_dev);
	}
	cbdt->cbd_channels_dev = cbd_channels_dev;

	return 0;
}

int cbd_channels_exit(struct cbd_transport *cbdt)
{
	struct cbd_channels_device *cbd_channels_dev = cbdt->cbd_channels_dev;
	int i;

	if (!cbd_channels_dev)
		return 0;

	for (i = 0; i < cbdt->transport_info->channel_num; i++) {
		struct cbd_channel_device *channel = &cbd_channels_dev->channel_devs[i];
		struct device *channel_dev = &channel->dev;

		device_del(channel_dev);
	}

	device_del(&cbd_channels_dev->channels_dev);

	kfree(cbd_channels_dev);
	cbdt->cbd_channels_dev = NULL;

	return 0;
}

void cbdc_copy_to_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, void *verify_data)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	struct page *page = NULL;
	u32 done = 0;
	u32 data_head = data_off;
	u32 to_copy, page_off = 0;
	u64 offset = bio->bi_iter.bi_sector << SECTOR_SHIFT;
next:
	bio_for_each_segment(bv, bio, iter) {
		dst = kmap_atomic(bv.bv_page);
		page_off = bv.bv_offset;
again:
		if (data_head >= CBDC_DATA_SIZE) {
			data_head %= CBDC_DATA_SIZE;
		}
		src = channel->data + data_head;

		to_copy = min(bv.bv_offset + bv.bv_len - page_off, CBDC_DATA_SIZE - data_head);
		if (data_head + to_copy > CBDC_DATA_SIZE)
			pr_err("%s %s copy overflow\n", __func__, __LINE__);
		//pr_err("copy_to_bio from %u", data_head);
		memcpy_flushcache(dst + page_off, src, to_copy);
		data_head += to_copy;
		page_off += to_copy;
		done += to_copy;
		if (page_off < bv.bv_offset + bv.bv_len) {
			goto again;
		}
		kunmap_atomic(dst);

	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next;
	}

	if (done != data_len) {
		pr_err("data copied: %u  is not data_len: %u\n", done, data_len);
	}


	if (data_off + data_len > CBDC_DATA_SIZE) {
		data_len = CBDC_DATA_SIZE - data_off;
		pr_err("truncate data_len");
	}

	return;
}

void cbdc_copy_from_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	struct page *page = NULL;
	u64 offset = (bio->bi_iter.bi_sector << SECTOR_SHIFT);
	u32 done = 0;
	u32 data_head = data_off;
	u32 to_copy, page_off = 0;

next:
	bio_for_each_segment(bv, bio, iter) {
		dst = kmap_atomic(bv.bv_page);
		page_off = bv.bv_offset;
again:
		if (data_head >= CBDC_DATA_SIZE) {
			data_head %= CBDC_DATA_SIZE;
		}
		src = channel->data + data_head;

		to_copy = min(bv.bv_offset + bv.bv_len - page_off, CBDC_DATA_SIZE - data_head);
		if (data_head + to_copy > CBDC_DATA_SIZE)
			pr_err("%s %s copy overflow\n", __func__, __LINE__);
		//pr_err("copy_to_bio to %u", data_head);
		memcpy_flushcache(src, dst + page_off, to_copy);
		data_head += to_copy;
		page_off += to_copy;
		done += to_copy;
		if (page_off < bv.bv_offset + bv.bv_len) {
			goto again;
		}
		kunmap_atomic(dst);

	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next;
	}

	if (done != data_len) {
		pr_err("data copied: %u  is not data_len: %u\n", done, data_len);
	}


	if (data_off + data_len > CBDC_DATA_SIZE) {
		data_len = CBDC_DATA_SIZE - data_off;
		pr_err("truncate data_len");
	}

	return;
}
