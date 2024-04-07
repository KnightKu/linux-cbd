#include "cbd_internal.h"
#include <linux/io.h>
#include <linux/delay.h>

#define cbd_blk_err(dev, fmt, ...)					\
	cbd_err("cbd%d: " fmt,					\
		 dev->mapped_id, ##__VA_ARGS__)

#define cbd_blk_info(dev, fmt, ...)					\
	cbd_info("cbd%d: " fmt,					\
		 dev->mapped_id, ##__VA_ARGS__)

#define cbd_blk_debug(dev, fmt, ...)					\
	cbd_debug("cbd%d: " fmt,					\
		 dev->mapped_id, ##__VA_ARGS__)

#define cbd_queue_err(queue, fmt, ...)					\
	cbd_blk_err(queue->cbd_blkdev, "queue-%d: " fmt,			\
		     queue->index, ##__VA_ARGS__)

#define cbd_queue_info(queue, fmt, ...)					\
	cbd_blk_info(queue->cbd_blkdev, "queue-%d: " fmt,			\
		     queue->index, ##__VA_ARGS__)

#define cbd_queue_debug(queue, fmt, ...)				\
	cbd_blk_debug(queue->cbd_blkdev, "queue-%d: " fmt,			\
		     queue->index, ##__VA_ARGS__)

static inline struct cbd_se *get_submit_entry(struct cbd_queue *cbd_q)
{
	struct cbd_se *se;

	se = (struct cbd_se *)(cbd_q->channel.cmdr + cbd_q->channel_info->cmd_head);

	return se;
}

static inline struct cbd_se *get_oldest_se(struct cbd_queue *cbd_q)
{
	if (cbd_q->channel_info->cmd_tail == cbd_q->channel_info->cmd_head)
		return NULL;

	return (struct cbd_se *)(cbd_q->channel.cmdr + cbd_q->channel_info->cmd_tail);
}

static inline struct cbd_ce *get_complete_entry(struct cbd_queue *cbd_q)
{
	if (cbd_q->channel_info->compr_tail == cbd_q->channel_info->compr_head)
		return NULL;

	return (struct cbd_ce *)(cbd_q->channel.compr + cbd_q->channel_info->compr_tail);
}

static bool verify = false;

static ssize_t blkdev_mapped_id_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_blkdev_device *blkdev;
	struct cbd_blkdev_info *blkdev_info;
	int ret;

	blkdev = container_of(dev, struct cbd_blkdev_device, dev);
	blkdev_info = blkdev->blkdev_info;

	return sprintf(buf, "%u\n", blkdev_info->mapped_id);
}

static DEVICE_ATTR(mapped_id, 0400, blkdev_mapped_id_show, NULL);

static ssize_t blkdev_alive_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_blkdev_device *blkdev;
	struct cbd_blkdev_info *blkdev_info;
	ktime_t oldest, ts;
	int ret;

	blkdev = container_of(dev, struct cbd_blkdev_device, dev);
	blkdev_info = blkdev->blkdev_info;

	ts = blkdev_info->alive_ts;
	oldest = ktime_sub_ms(ktime_get_real(), 30 * 1000);

	if (ktime_after(ts, oldest))
		return sprintf(buf, "true\n");

	return sprintf(buf, "false\n");
}

static DEVICE_ATTR(alive, 0400, blkdev_alive_show, NULL);

static struct attribute *cbd_blkdev_attrs[] = {
	&dev_attr_mapped_id.attr,
	&dev_attr_alive.attr,
	NULL
};

static struct attribute_group cbd_blkdev_attr_group = {
	.attrs = cbd_blkdev_attrs,
};

static const struct attribute_group *cbd_blkdev_attr_groups[] = {
	&cbd_blkdev_attr_group,
	NULL
};

static void cbd_blkdev_release(struct device *dev)
{
}

struct device_type cbd_blkdev_type = {
	.name		= "cbd_blkdev",
	.groups		= cbd_blkdev_attr_groups,
	.release	= cbd_blkdev_release,
};

struct device_type cbd_blkdevs_type = {
	.name		= "cbd_blkdevs",
	.release	= cbd_blkdev_release,
};

int cbd_blkdevs_init(struct cbd_transport *cbdt)
{
	struct cbd_blkdevs_device *cbd_blkdevs_dev;
	struct cbd_blkdev_device *blkdev;
	int i;

	cbd_blkdevs_dev = kzalloc(sizeof(struct cbd_blkdevs_device) + cbdt->transport_info->blkdev_num * sizeof(struct cbd_blkdev_device), GFP_KERNEL);
	if (!cbd_blkdevs_dev) {
		return -ENOMEM;
	}

	device_initialize(&cbd_blkdevs_dev->blkdevs_dev);
	device_set_pm_not_required(&cbd_blkdevs_dev->blkdevs_dev);
	dev_set_name(&cbd_blkdevs_dev->blkdevs_dev, "cbd_blkdevs");
	cbd_blkdevs_dev->blkdevs_dev.parent = &cbdt->device;
	cbd_blkdevs_dev->blkdevs_dev.type = &cbd_blkdevs_type;
	device_add(&cbd_blkdevs_dev->blkdevs_dev);

	for (i = 0; i < cbdt->transport_info->blkdev_num; i++) {
		struct cbd_blkdev_device *blkdev = &cbd_blkdevs_dev->blkdev_devs[i];
		struct device *blkdev_dev = &blkdev->dev;

		blkdev->blkdev_info = cbdt_get_blkdev_info(cbdt, i);
		device_initialize(blkdev_dev);
		device_set_pm_not_required(blkdev_dev);
		dev_set_name(blkdev_dev, "blkdev%u", i);
		blkdev_dev->parent = &cbd_blkdevs_dev->blkdevs_dev;
		blkdev_dev->type = &cbd_blkdev_type;

		device_add(blkdev_dev);
	}
	cbdt->cbd_blkdevs_dev = cbd_blkdevs_dev;

	return 0;
}

int cbd_blkdevs_exit(struct cbd_transport *cbdt)
{
	struct cbd_blkdevs_device *cbd_blkdevs_dev = cbdt->cbd_blkdevs_dev;
	int i;

	if (!cbd_blkdevs_dev)
		return 0;

	for (i = 0; i < cbdt->transport_info->blkdev_num; i++) {
		struct cbd_blkdev_device *blkdev = &cbd_blkdevs_dev->blkdev_devs[i];
		struct device *blkdev_dev = &blkdev->dev;

		device_del(blkdev_dev);
	}

	device_del(&cbd_blkdevs_dev->blkdevs_dev);

	kfree(cbd_blkdevs_dev);
	cbdt->cbd_blkdevs_dev = NULL;

	return 0;
}


static int cbd_major;
static DEFINE_IDA(cbd_mapped_id_ida);

static LIST_HEAD(cbd_dev_list);    /* devices */
static DEFINE_SPINLOCK(cbd_dev_list_lock);

static int cbd_mapped_id_to_minor(int mapped_id)
{
	return mapped_id << CBD_PART_SHIFT;
}

static int minor_to_cbd_mapped_id(int minor)
{
	return minor >> CBD_PART_SHIFT;
}

static void cbd_req_init(struct cbd_queue *cbd_q, enum cbd_op op, struct request *rq)
{
	struct cbd_request *cbd_req = blk_mq_rq_to_pdu(rq);

	cbd_req->req = rq;
	cbd_req->cbd_q = cbd_q;
	cbd_req->op = op;

	return;
}

static inline size_t cbd_get_cmd_size(struct cbd_request *cbd_req)
{
	u32 cmd_size = sizeof(struct cbd_se) + (sizeof(struct iovec) * cbd_req->pi_cnt);

	return round_up(cmd_size, CBD_OP_ALIGN_SIZE);
}

static bool cbd_req_nodata(struct cbd_request *cbd_req)
{
	switch (cbd_req->op) {
		case CBD_OP_WRITE:
		case CBD_OP_READ:
			return false;
		case CBD_OP_DISCARD:
		case CBD_OP_WRITE_ZEROS:
		case CBD_OP_FLUSH:
			return true;
		default:
			BUG();
	}
}

static uint32_t cbd_req_segments(struct cbd_request *cbd_req)
{
	uint32_t segs = 0;
	struct bio *bio = cbd_req->req->bio;

	if (cbd_req_nodata(cbd_req))
		return 0;

	while (bio) {
		segs += bio_segments(bio);
		bio = bio->bi_next;
	}

	return segs;
}

static int queue_req_prepare(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbd_q = cbd_req->cbd_q;
	int ret;

	cbd_req->pi_cnt = cbd_req_segments(cbd_req);

	/*
	if (cbd_req->pi_cnt > CBD_REQ_INLINE_PI_MAX) {
		ret = cbd_req_pi_alloc(cbd_req);
		if (ret) {
			cbd_blk_err(cbd_q->cbd_blkdev, "pi kcalloc failed");
			goto err;
		}

	}

	if (cbd_req->pi_cnt) {
		ret = cbd_get_data_pages(cbd_q, cbd_req);
		if (ret) {
			cbd_blk_debug(cbd_q->cbd_blkdev, "get data page failed");
			goto err_free_pi;
		}
	}

	if (req_op(cbd_req->req) == REQ_OP_WRITE) {
		copy_data_to_cbdteq(cbd_req);
	}
	*/

	return 0;

err:
	return ret;

}

static void insert_padding(struct cbd_queue *cbd_q, u32 cmd_size)
{
	struct cbd_se_hdr *header;
	u32 pad_len;

	if (cbd_q->channel_info->cmdr_size - cbd_q->channel_info->cmd_head >= cmd_size)
		return;

	pad_len = cbd_q->channel_info->cmdr_size - cbd_q->channel_info->cmd_head;
	pr_err("pad_len:%d", pad_len);

	header = (struct cbd_se_hdr *)get_submit_entry(cbd_q);
	memset(header, 0, pad_len);
	cbd_se_hdr_set_op(&header->len_op, CBD_OP_PAD);
	cbd_se_hdr_set_len(&header->len_op, pad_len);

	CBDC_UPDATE_CMDR_HEAD(cbd_q->channel_info->cmd_head, pad_len, cbd_q->channel_info->cmdr_size);
}

static void queue_req_se_init(struct cbd_request *cbd_req)
{
	struct cbd_se	*se;
	struct cbd_se_hdr *header;
	u64 offset = (u64)blk_rq_pos(cbd_req->req) << SECTOR_SHIFT;
	u64 length = blk_rq_bytes(cbd_req->req);

	se = get_submit_entry(cbd_req->cbd_q);
	memset(se, 0, cbd_get_cmd_size(cbd_req));
	header = &se->header;

	cbd_se_hdr_set_op(&header->len_op, cbd_req->op);
	cbd_se_hdr_set_len(&header->len_op, cbd_get_cmd_size(cbd_req));

	se->priv_data = cbd_req->req_tid;
	se->offset = offset;
	se->len = length;

	if (req_op(cbd_req->req) == REQ_OP_READ || req_op(cbd_req->req) == REQ_OP_WRITE) {
		se->data_off = cbd_req->cbd_q->channel.data_head;
		se->data_len = length;
	}

	//pr_err("queue: priv_data: %llu, offset:%llu, len: %u, data_off: %llu, data_len: %u\n", se->priv_data, se->offset, se->len, se->data_off, se->data_len);

	cbd_req->se = se;
}

static bool data_space_enough(struct cbd_queue *cbd_q, struct cbd_request *cbd_req)
{
	u32 space_available;
	u32 space_needed;
	u32 space_used;
	u32 space_max;

	//pr_err("data_head: %u, data_tail: %d", cbd_q->channel.data_head, cbd_q->channel.data_tail);
	space_max = cbd_q->channel.data_size - 4096;

	if (cbd_q->channel.data_head > cbd_q->channel.data_tail)
		space_used = cbd_q->channel.data_head - cbd_q->channel.data_tail;
	else if (cbd_q->channel.data_head < cbd_q->channel.data_tail)
		space_used = cbd_q->channel.data_head + (cbd_q->channel.data_size - cbd_q->channel.data_tail);
	else
		space_used = 0;

	space_available = space_max - space_used;

	space_needed = round_up(cbd_req->data_len, 4096);

	if (space_available < space_needed) {
		pr_err("data space is not enough: availaible: %u needed: %u", space_available, space_needed);
		return false;
	}

	return true;
}

static bool submit_ring_space_enough(struct cbd_queue *cbd_q, u32 cmd_size)
{
	u32 space_available;
	u32 space_needed;
	u32 space_max, space_used;

	/* There is a CMDR_RESERVED we dont use to prevent the ring to be used up */
	space_max = cbd_q->channel_info->cmdr_size - CBDC_CMDR_RESERVED;

	if (cbd_q->channel_info->cmd_head > cbd_q->channel_info->cmd_tail)
		space_used = cbd_q->channel_info->cmd_head - cbd_q->channel_info->cmd_tail;
	else if (cbd_q->channel_info->cmd_head < cbd_q->channel_info->cmd_tail)
		space_used = cbd_q->channel_info->cmd_head + (cbd_q->channel_info->cmdr_size - cbd_q->channel_info->cmd_tail);
	else
		space_used = 0;

	space_available = space_max - space_used;

	if (cbd_q->channel_info->cmdr_size - cbd_q->channel_info->cmd_head > cmd_size)
		space_needed = cmd_size;
	else
		space_needed = cmd_size + cbd_q->channel_info->cmdr_size - cbd_q->channel_info->cmd_head;

	if (space_available < space_needed)
		return false;

	return true;
}

static void queue_req_data_init(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbd_q = cbd_req->cbd_q;
	struct cbd_blkdev *cbd_blkdev = cbd_q->cbd_blkdev;
	struct bio *bio = cbd_req->req->bio;
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	u64 sector = bio->bi_iter.bi_sector;
	if (cbd_req->op == CBD_OP_READ) {
		goto advance_data_head;
	}

	void *verify_start = NULL;

	if (verify) {
		verify_start = cbd_blkdev->verify_data + (bio->bi_iter.bi_sector << SECTOR_SHIFT); 
	}

	cbdc_copy_from_bio(&cbd_q->channel, cbd_req->data_off, cbd_req->data_len, bio);

	if (verify) {
	u32 done = 0;
next:
	bio_for_each_segment(bv, bio, iter) {
		src = kmap_atomic(bv.bv_page);
		dst = verify_start + done;
		memcpy(dst, src + bv.bv_offset, bv.bv_len);
		kunmap_atomic(dst);
		done += bv.bv_len;
	}

	if (bio->bi_next) {
		bio = bio->bi_next;
		goto next;
	}

	if (done != cbd_req->data_len) {
		pr_err("done is not data_len");
	}
	}


advance_data_head:
	cbd_q->channel.data_head = round_up(cbd_q->channel.data_head + cbd_req->data_len, PAGE_SIZE);
	cbd_q->channel.data_head %= cbd_q->channel.data_size;

	return;
}

static void complete_inflight_req(struct cbd_queue *cbd_q, struct cbd_request *cbd_req, int ret);
static void cbd_queue_fn(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbd_q = cbd_req->cbd_q;
	int ret = 0;
	int status = atomic_read(&cbd_q->status);
	size_t command_size;

	cbd_req_stats_ktime_delta(cbd_req->start_to_prepare, cbd_req->start_kt);

	ret = queue_req_prepare(cbd_req);
	if (ret) {
		goto end_request;
	}

	spin_lock(&cbd_q->inflight_reqs_lock);
	list_add_tail(&cbd_req->inflight_reqs_node, &cbd_q->inflight_reqs);
	spin_unlock(&cbd_q->inflight_reqs_lock);

	command_size = cbd_get_cmd_size(cbd_req);

	spin_lock(&cbd_q->channel.cmdr_lock);
	if (req_op(cbd_req->req) == REQ_OP_WRITE || req_op(cbd_req->req) == REQ_OP_READ) {
		cbd_req->data_off = cbd_q->channel.data_head;
		cbd_req->data_len = blk_rq_bytes(cbd_req->req);
	} else {
		cbd_req->data_off = -1;
		cbd_req->data_len = 0;
	}
	//pr_err("data_off: %u, len: %u", cbd_req->data_off, cbd_req->data_len);

	if (!submit_ring_space_enough(cbd_q, command_size) ||
			!data_space_enough(cbd_q, cbd_req)) {
		spin_unlock(&cbd_q->channel.cmdr_lock);

		/* remove request from inflight_reqs */
		spin_lock(&cbd_q->inflight_reqs_lock);
		list_del_init(&cbd_req->inflight_reqs_node);
		spin_unlock(&cbd_q->inflight_reqs_lock);

		cbd_blk_debug(cbd_q->cbd_blkdev, "cmd ring space is not enough");
		ret = -ENOMEM;
		goto end_request;
	}

	insert_padding(cbd_q, command_size);

	cbd_req->req_tid = ++cbd_q->req_tid;

	queue_req_se_init(cbd_req);

	if (!cbd_req_nodata(cbd_req)) {
		queue_req_data_init(cbd_req);
	}

	queue_delayed_work(cbd_q->task_wq, &cbd_q->complete_work, 0);

	CBDC_UPDATE_CMDR_HEAD(cbd_q->channel_info->cmd_head,
			cbd_get_cmd_size(cbd_req),
			cbd_q->channel_info->cmdr_size);
	spin_unlock(&cbd_q->channel.cmdr_lock);


	cbd_req_stats_ktime_delta(cbd_req->start_to_submit, cbd_req->start_kt);

	return;

end_request:
	if (ret == -ENOMEM || ret == -EBUSY)
		blk_mq_requeue_request(cbd_req->req, true);
	else
		blk_mq_end_request(cbd_req->req, errno_to_blk_status(ret));

	return;
}

static void cbd_req_release(struct cbd_request *cbd_req)
{
	return;
}

static void advance_cmd_ring(struct cbd_queue *cbd_q)
{
       struct cbd_se *se;
again:
       se = get_oldest_se(cbd_q);
       if (!se)
               goto out;

	if (cbd_se_hdr_flags_test(se, CBD_SE_HDR_DONE)) {
		CBDC_UPDATE_CMDR_TAIL(cbd_q->channel_info->cmd_tail,
				cbd_se_hdr_get_len(se->header.len_op),
				cbd_q->channel_info->cmdr_size);
		goto again;
       }
out:
       return;
}

static bool __advance_data_tail(struct cbd_queue *cbd_q, u32 data_off, u32 data_len)
{
	if (data_off == cbd_q->channel.data_tail) {
		//pr_err("cbd%u release data_off: %u, len: %u", cbd_q->cbd_blkdev->mapped_id, data_off, data_len);
		cbd_q->released_extents[data_off / 4096] = 0;
		if (data_len % PAGE_SIZE) {
			pr_err("%u is not aligned\n", data_len);
		}
		cbd_q->channel.data_tail += data_len;
		if (cbd_q->channel.data_tail >= cbd_q->channel.data_size) {
			cbd_q->channel.data_tail %= cbd_q->channel.data_size;
		}
		return true;
	}

	return false;
}

static void advance_data_tail(struct cbd_queue *cbd_q, u32 data_off, u32 data_len)
{
	//pr_err("cbd%u, before advance %u %u, data_head: %u, %u", cbd_q->cbd_blkdev->mapped_id, data_off, data_len, cbd_q->channel.data_head, cbd_q->channel.data_tail);
	cbd_q->released_extents[data_off / 4096] = data_len;

	while (__advance_data_tail(cbd_q, data_off, data_len)) {
		data_off += data_len;
		data_len = cbd_q->released_extents[data_off / 4096];
		if (!data_len) {
			break;
		}
	}

	//pr_err("cbd%u after advance %u %u, data_head: %u, %u\n", cbd_q->cbd_blkdev->mapped_id, data_off, data_len, cbd_q->channel.data_head, cbd_q->channel.data_tail);
}

#ifdef CBD_REQUEST_STATS
static void cbd_req_stats(struct cbd_queue *cbd_q, struct cbd_request *cbd_req)
{
	if (!cbd_req->start_kt)
		return;

	cbd_q->stats_reqs++;
	cbd_q->start_to_prepare = ktime_add(cbd_q->start_to_prepare, cbd_req->start_to_prepare);
	cbd_q->start_to_submit = ktime_add(cbd_q->start_to_submit, cbd_req->start_to_submit);
	cbd_q->start_to_handle = ktime_add(cbd_q->start_to_handle, cbd_req->start_to_handle);
	cbd_q->start_to_ack = ktime_add(cbd_q->start_to_handle, cbd_req->start_to_ack);
	cbd_q->start_to_complete = ktime_add(cbd_q->start_to_complete, cbd_req->start_to_complete);
	cbd_q->start_to_release = ktime_add(cbd_q->start_to_release, cbd_req->start_to_release);
}
#endif /* CBD_REQUEST_STATS */

static inline void complete_inflight_req(struct cbd_queue *cbd_q, struct cbd_request *cbd_req, int ret)
{
	u32 data_off, data_len;
	bool advance_data = false;

	spin_lock(&cbd_q->inflight_reqs_lock);
	list_del_init(&cbd_req->inflight_reqs_node);
	spin_unlock(&cbd_q->inflight_reqs_lock);

	cbd_se_hdr_flags_set(cbd_req->se, CBD_SE_HDR_DONE);
	data_off = cbd_req->data_off;
	data_len = cbd_req->data_len;
	advance_data = (!cbd_req_nodata(cbd_req));

	blk_mq_end_request(cbd_req->req, errno_to_blk_status(ret));

	cbd_req_release(cbd_req);

	spin_lock(&cbd_q->channel.cmdr_lock);
	advance_cmd_ring(cbd_q);
	if (advance_data)
		advance_data_tail(cbd_q, data_off, round_up(data_len, PAGE_SIZE));
	spin_unlock(&cbd_q->channel.cmdr_lock);

#ifdef CBD_REQUEST_STATS
	cbd_req_stats_ktime_delta(cbd_req->start_to_release, cbd_req->start_kt);
	cbd_req_stats(cbd_q, cbd_req);
#endif /* CBD_REQUEST_STATS */
}

static struct cbd_request *fetch_inflight_req(struct cbd_queue *cbd_q, u64 req_tid)
{
	struct cbd_request *req;
	bool found = false;

	list_for_each_entry(req, &cbd_q->inflight_reqs, inflight_reqs_node) {
		if (req->req_tid == req_tid) {
			list_del_init(&req->inflight_reqs_node);
			found = true;
			break;
		}
	}

	if (found)
		return req;

	return NULL;
}

static void copy_data_from_cbdteq(struct cbd_request *cbd_req)
{
	struct bio_vec bv;
	struct bvec_iter iter;
	void *src, *dst;
	struct bio *bio = cbd_req->req->bio;
	struct page *page = NULL;
	u32 done = 0;
	struct cbd_se *se = cbd_req->se;
	struct cbd_queue *cbd_q = cbd_req->cbd_q;
	struct cbd_blkdev *cbd_blkdev = cbd_q->cbd_blkdev;
	void *base = cbd_q->channel.data + se->data_off;
	u64 data_head = se->data_off;
	u64 sector = bio->bi_iter.bi_sector;

	void *verify_start = NULL;
	
	if (verify)
		verify_start = cbd_blkdev->verify_data + (bio->bi_iter.bi_sector << SECTOR_SHIFT); 

	if (1) {
		cbdc_copy_to_bio(&cbd_q->channel, cbd_req->data_off, cbd_req->data_len, bio, cbd_blkdev->verify_data);
	} else {
next:
		bio_for_each_segment(bv, bio, iter) {
			dst = kmap_atomic(bv.bv_page);
			src = verify_start + done;
			memcpy(dst + bv.bv_offset, src, bv.bv_len);
			kunmap_atomic(dst);
			done += bv.bv_len;
		}

		if (bio->bi_next) {
			bio = bio->bi_next;
			goto next;
		}

		if (done != cbd_req->data_len) {
			pr_err("copy from done is not data_len");
		}
	}

	return;
}

static u64 get_complete_work_delay(struct cbd_queue *cbd_q)
{
	if (cbd_q->delay_cur == cbd_q->delay_max)
		return cbd_q->delay_cur;

	cbd_q->delay_cur += cbd_q->delay_cur / 10;

	if (cbd_q->delay_cur > cbd_q->delay_max)
		cbd_q->delay_cur = cbd_q->delay_max;

	return cbd_q->delay_cur;
}

static void reset_complete_work_delay(struct cbd_queue *cbd_q)
{
	cbd_q->delay_cur = cbd_q->delay_min;
	return;
}

static void complete_work_fn(struct work_struct *work)
{
	struct cbd_queue *cbd_q = container_of(work, struct cbd_queue, complete_work.work);
	struct cbd_ce *ce;
	struct cbd_request *cbd_req;
	int retry = 0;

again:
	spin_lock(&cbd_q->channel.compr_lock);
	ce = get_complete_entry(cbd_q);
	if (!ce) {
		spin_unlock(&cbd_q->channel.compr_lock);
		if (++retry < cbd_q->busy_retry_count) {
			cpu_relax();
			fsleep(cbd_q->busy_retry_interval);
			goto again;
		}

		if (1) {
			spin_lock(&cbd_q->inflight_reqs_lock);
			if (list_empty(&cbd_q->inflight_reqs)) {
				spin_unlock(&cbd_q->inflight_reqs_lock);
				return;
			}
			spin_unlock(&cbd_q->inflight_reqs_lock);
		}

		queue_delayed_work(cbd_q->task_wq, &cbd_q->complete_work, get_complete_work_delay(cbd_q));
		return;
	}
	retry = 0;
	reset_complete_work_delay(cbd_q);
	//pr_err("get ce for %lu, at %u", ce->priv_data, cbd_q->channel_info->compr_tail);
	CBDC_UPDATE_COMPR_TAIL(cbd_q->channel_info->compr_tail, sizeof(struct cbd_ce), cbd_q->channel_info->compr_size);
	spin_unlock(&cbd_q->channel.compr_lock);

	spin_lock(&cbd_q->inflight_reqs_lock);
	cbd_req = fetch_inflight_req(cbd_q, ce->priv_data);
	spin_unlock(&cbd_q->inflight_reqs_lock);
	if (!cbd_req) {
		goto again;
	}

	cbd_req_stats_ktime_delta(cbd_req->start_to_complete, cbd_req->start_kt);

	if (true && req_op(cbd_req->req) == REQ_OP_READ) {
		spin_lock(&cbd_q->channel.cmdr_lock);
		copy_data_from_cbdteq(cbd_req);
		spin_unlock(&cbd_q->channel.cmdr_lock);
	}

	complete_inflight_req(cbd_q, cbd_req, ce->result);

	goto again;
}

blk_status_t cbd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct request *req = bd->rq;
	struct cbd_queue *cbd_q = hctx->driver_data;
	struct cbd_request *cbd_req = blk_mq_rq_to_pdu(bd->rq);

	//pr_err("index: %u", cbd_q->index);

	memset(cbd_req, 0, sizeof(struct cbd_request));
	INIT_LIST_HEAD(&cbd_req->inflight_reqs_node);

	blk_mq_start_request(bd->rq);

	cbd_req_stats_ktime_get(cbd_req->start_kt);

	switch (req_op(bd->rq)) {
	case REQ_OP_FLUSH:
		cbd_req_init(cbd_q, CBD_OP_FLUSH, req);
		break;
	case REQ_OP_DISCARD:
		pr_err("discard");
		cbd_req_init(cbd_q, CBD_OP_DISCARD, req);
		break;
	case REQ_OP_WRITE_ZEROES:
		pr_err("writezeros");
		cbd_req_init(cbd_q, CBD_OP_WRITE_ZEROS, req);
		break;
	case REQ_OP_WRITE:
		cbd_req_init(cbd_q, CBD_OP_WRITE, req);
		break;
	case REQ_OP_READ:
		cbd_req_init(cbd_q, CBD_OP_READ, req);
		break;
	default:
		return BLK_STS_IOERR;
	}

	if (1)
		cbd_queue_fn(cbd_req);
	else
		blk_mq_end_request(req, errno_to_blk_status(0));

	return BLK_STS_OK;
}

static int cbd_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
			unsigned int hctx_idx)
{
	struct cbd_blkdev *cbd_blkdev = driver_data;
	struct cbd_queue *cbd_q;

	pr_err("init_hctx");
	cbd_q = &cbd_blkdev->queues[hctx_idx];
	pr_err("cbd_q: %p", cbd_q);
	cbd_q->mq_hctx = hctx;
	hctx->driver_data = cbd_q;

	return 0;
}

static const struct blk_mq_ops cbd_mq_ops = {
	.queue_rq	= cbd_queue_rq,
	.init_hctx	= cbd_init_hctx,
};

static int cbd_open(struct gendisk *disk, blk_mode_t mode)
{
	return 0;
}

static void cbd_release(struct gendisk *disk)
{
}

static const struct block_device_operations cbd_bd_ops = {
	.owner			= THIS_MODULE,
	.open			= cbd_open,
	.release		= cbd_release,
};

static void cbd_queue_destroy(struct cbd_queue *cbd_q)
{
	if (!cbd_q->inited)
		return;

	cancel_delayed_work_sync(&cbd_q->complete_work);
	if (cbd_q->task_wq) {
		drain_workqueue(cbd_q->task_wq);
		destroy_workqueue(cbd_q->task_wq);
	}

	if (cbd_q->channel_info)
		cbd_channel_set_blkdev_state(cbd_q->channel_info, cbdc_blkdev_state_stopped);

	device_del(&cbd_q->dev);
	return;
}

static int wait_for_backend_running(struct cbd_channel_info *channel_info)
{
	u32 backend_state;
	int i;

	for (i = 0; i < 100; i++) {
		backend_state = cbd_channel_get_backend_state(channel_info);
		pr_err("backend state: %u", backend_state);
		if (backend_state == cbdc_backend_state_running) {
			return 0;
		}
		msleep(1 * 1000);
	}

	return -ETIMEDOUT;
}

int cbd_queue_sb_init(struct cbd_queue *cbd_q)
{
	struct cbd_blkdev *cbd_blkdev = cbd_q->cbd_blkdev;
	struct cbd_channel_info *sb;

	sb = cbd_q->channel_info;

	cbd_q->channel.cmdr = (void *)sb + CBDC_CMDR_OFF;
	cbd_q->channel.compr = (void *)sb + CBDC_COMPR_OFF;
	cbd_q->channel.data = (void *)sb + CBDC_DATA_OFF;
	cbd_q->channel.data_head = cbd_q->channel.data_tail = 0;
	cbd_q->channel.data_size = CBDC_DATA_SIZE;
	cbd_q->channel.cbd_q = cbd_q;

	cbd_channel_set_backend_id(sb, cbd_blkdev->backend_id);
	cbd_channel_set_blkdev_state(sb, cbdc_blkdev_state_running);
	//cbd_channel_set_backend_state(sb, cbdc_backend_state_running);
	//pr_err("waiting");
	//wait_for_backend_running(channel_info);
	//pr_err("wait");
	//cbd_channel_set_blkdev_state(channel_info, cbdc_blkdev_state_running);
	//pr_err("blkdev running");

	/* Initialise the sb of the ring buffer */
	sb->cmdr_off = CBDC_CMDR_OFF;
	sb->cmdr_size = CBDC_CMDR_SIZE;
	sb->compr_off = CBDC_COMPR_OFF;
	sb->compr_size = CBDC_COMPR_SIZE;

	//sb->cmd_head = sb->cmd_tail = sb->compr_head = sb->compr_tail = 0;
	pr_err("q: %p", cbd_q);
	pr_err("channel_info: %p", cbd_q->channel_info);
	pr_err("cmdr_size: %u", cbd_q->channel_info->cmdr_size);

	return 0;
}

static ssize_t queue_cpu_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_queue *queue;
	int ret;

	queue = container_of(dev, struct cbd_queue, dev);

	if (queue->cpu == -1)
		return 0;

	return sprintf(buf, "%u\n", queue->cpu);
}

static ssize_t queue_cpu_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *ubuf,
				 size_t size)
{
	struct cbd_queue *queue;
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

	queue = container_of(dev, struct cbd_queue, dev);

	queue->cpu = token;

	return size;
}

static DEVICE_ATTR(cpu, 0600, queue_cpu_show, queue_cpu_store);

static struct attribute *queue_attrs[] = {
	&dev_attr_cpu.attr,
	NULL
};

static struct attribute_group queue_attr_group = {
	.attrs = queue_attrs,
};

static const struct attribute_group *queue_attr_groups[] = {
	&queue_attr_group,
	NULL
};

static void queue_release(struct device *dev)
{
}

struct device_type queue_type = {
	.name		= "cbd_queue",
	.groups		= queue_attr_groups,
	.release	= queue_release,
};

static int cbd_queue_create(struct cbd_queue *cbd_q)
{
	struct cbd_transport *cbd_r = cbd_q->cbd_blkdev->cbd_r;
	int ret;
	u32 channel_id;

	pr_err("cbdt_get_empty_channel_id");
	ret = cbdt_get_empty_channel_id(cbd_r, &channel_id);
	if (ret < 0) {
		pr_err("failed find empty channel_id.\n");
		return ret;
	}

	pr_err("channel_id: %u", channel_id);
	cbd_q->channel_id = channel_id;
	cbd_q->channel.channel_id = channel_id;
	cbd_q->channel_info = cbdt_get_channel_info(cbd_r, channel_id);
	cbd_q->delay_max = msecs_to_jiffies(1000);
	cbd_q->delay_min = usecs_to_jiffies(100);
	cbd_q->delay_cur = cbd_q->delay_min;

	cbd_q->busy_retry_count = 100;
	cbd_q->busy_retry_interval = 1;

	ret = cbd_queue_sb_init(cbd_q);
	if (ret) {
		cbd_blk_err(cbd_q->cbd_blkdev, "failed to init dev sb: %d.", ret);
		goto err;
	}

	mutex_init(&cbd_q->state_lock);
	INIT_LIST_HEAD(&cbd_q->inflight_reqs);
	spin_lock_init(&cbd_q->inflight_reqs_lock);
	spin_lock_init(&cbd_q->channel.cmdr_lock);
	spin_lock_init(&cbd_q->channel.compr_lock);
	cbd_q->req_tid = 0;
	INIT_DELAYED_WORK(&cbd_q->complete_work, complete_work_fn);
	//atomic_set(&cbd_q->status, CBD_QUEUE_KSTATUS_RUNNING);
	
	cbd_q->released_extents = kmalloc(sizeof(u32) * (CBDC_DATA_SIZE / 4096), GFP_KERNEL);
	if (!cbd_q->released_extents) {
		ret = -ENOMEM;
		goto err;
	}

	struct device *dev = &cbd_q->dev;
	cbd_setup_device(dev, &cbd_q->cbd_blkdev->blkdev_dev->dev, &queue_type, "cbd%u-queue%u", cbd_q->cbd_blkdev->mapped_id, cbd_q->index);

	cbd_q->cpu = -1;

	cbd_q->task_wq = alloc_workqueue("cbd%d-queue%utasks",  WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_SYSFS, 0, cbd_q->cbd_blkdev->mapped_id, cbd_q->index);
	queue_delayed_work(cbd_q->task_wq, &cbd_q->complete_work, 0);

	cbd_q->inited = 1;

	return 0;
err:
	return ret;
}


static void cbd_blkdev_destroy_queues(struct cbd_blkdev *cbd_blkdev)
{
	int i;

	for (i = 0; i < cbd_blkdev->num_queues; i++) {
		cbd_queue_destroy(&cbd_blkdev->queues[i]);
	}

	kfree(cbd_blkdev->queues);
}

static int cbd_blkdev_create_queues(struct cbd_blkdev *cbd_blkdev)
{
	int i;
	int ret;
	struct cbd_queue *cbd_q;

	cbd_blkdev->queues = kcalloc(cbd_blkdev->num_queues, sizeof(struct cbd_queue), GFP_KERNEL);
	if (!cbd_blkdev->queues) {
		return -ENOMEM;
	}

	for (i = 0; i < cbd_blkdev->num_queues; i++) {
		cbd_q = &cbd_blkdev->queues[i];
		cbd_q->cbd_blkdev = cbd_blkdev;
		cbd_q->index = i;
		ret = cbd_queue_create(cbd_q);
		if (ret)
			goto err;

	}

	return 0;
err:
	cbd_blkdev_destroy_queues(cbd_blkdev);
	return ret;
}

static int dev_init(struct cbd_blkdev *cbd_blkdev)
{
	int ret;

	if (verify) {
		cbd_blkdev->verify_data = memremap((cbd_blkdev->blkdev_id + 2)*10*1024*1024*1024ULL, 10*1024*1024*1024ULL, MEMREMAP_WT);
		if (!cbd_blkdev->verify_data) {
			pr_err("failed to remap verify data: %p\n", cbd_blkdev->verify_data);
			return -ENOMEM;
		}
		memset(cbd_blkdev->verify_data, 0, 10*1024*1024*1024ULL);
	}

	ret = cbd_blkdev_create_queues(cbd_blkdev);
	if (ret < 0) {
		return ret;
	}

	cbd_blkdev->dev_size = 8 * 1024 * 1024 * 1024ULL;

	struct gendisk *disk;

	memset(&cbd_blkdev->tag_set, 0, sizeof(cbd_blkdev->tag_set));
	cbd_blkdev->tag_set.ops = &cbd_mq_ops;
	cbd_blkdev->tag_set.queue_depth = 128;
	cbd_blkdev->tag_set.numa_node = NUMA_NO_NODE;
	cbd_blkdev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_NO_SCHED;
	cbd_blkdev->tag_set.nr_hw_queues = cbd_blkdev->num_queues;
	cbd_blkdev->tag_set.cmd_size = sizeof(struct cbd_request);
	cbd_blkdev->tag_set.timeout = cbd_blkdev->io_timeout * HZ;
	cbd_blkdev->tag_set.driver_data = cbd_blkdev;

	ret = blk_mq_alloc_tag_set(&cbd_blkdev->tag_set);
	if (ret) {
		pr_err("failed to alloc tag set %d", ret);
		goto err;
	}

	disk = blk_mq_alloc_disk(&cbd_blkdev->tag_set, cbd_blkdev);
	if (IS_ERR(disk)) {
		ret = PTR_ERR(disk);
		pr_err("failed to alloc disk");
		goto out_tag_set;
	}

	struct request_queue *q;
	q = disk->queue;

	pr_err("q: %p", q);
        snprintf(disk->disk_name, sizeof(disk->disk_name), "cbd%d",
                 cbd_blkdev->mapped_id);

	pr_err("q: %p", q);
	disk->major = cbd_major;
	disk->first_minor = cbd_blkdev->mapped_id << CBD_PART_SHIFT;
	disk->minors = (1 << CBD_PART_SHIFT);

	disk->fops = &cbd_bd_ops;
	disk->private_data = cbd_blkdev;

	pr_err("q: %p", q);
	blk_queue_flag_set(QUEUE_FLAG_NONROT, q);
	blk_queue_physical_block_size(disk->queue, PAGE_SIZE);
	
	/* Tell the block layer that this is not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, disk->queue);
	blk_queue_flag_set(QUEUE_FLAG_SYNCHRONOUS, disk->queue);
	blk_queue_flag_set(QUEUE_FLAG_NOWAIT, disk->queue);

	blk_queue_max_hw_sectors(q, 128);
	q->limits.max_sectors = queue_max_hw_sectors(q);
	blk_queue_max_segments(q, USHRT_MAX);
	blk_queue_max_segment_size(q, UINT_MAX);
	blk_queue_io_min(q, 4096);
	blk_queue_io_opt(q, 4096);

	q->limits.discard_granularity = 0;
	blk_queue_max_discard_sectors(q, 0);
	blk_queue_max_write_zeroes_sectors(q, 0);
	pr_err("====q: %p", cbd_blkdev);

	cbd_blkdev->disk = disk;

	pr_err("====q: %p", q);
	pr_err("disk is %p", cbd_blkdev->disk);
	pr_err("disk is %p", cbd_blkdev->disk);
	return 0;

out_tag_set:
	blk_mq_free_tag_set(&cbd_blkdev->tag_set);

free_cbd_blkdev:
	kfree(cbd_blkdev);

err:
	pr_err("err in init");
	return ret;
}

int cbd_blkdev_start(struct cbd_transport *cbdt, struct cbd_adm_options *opts)
{
	struct cbd_blkdev *cbd_blkdev;
	int ret;

	cbd_blkdev = kzalloc(sizeof(struct cbd_blkdev), GFP_KERNEL);
	if (!cbd_blkdev) {
		pr_err("fail to alloc cbd_blkdev");
		return -ENOMEM;
	}

	ret = cbdt_get_empty_blkdev_id(cbdt, &cbd_blkdev->blkdev_id);
	if (ret < 0) {
		goto blkdev_free;
	}

	cbd_blkdev->mapped_id = ida_simple_get(&cbd_mapped_id_ida, 0,
					 minor_to_cbd_mapped_id(1 << MINORBITS),
					 GFP_KERNEL);
	if (cbd_blkdev->mapped_id < 0) {
		ret = -ENOENT;
		goto blkdev_free;
	}

	INIT_LIST_HEAD(&cbd_blkdev->node);

	sprintf(cbd_blkdev->name, "cbd%d", cbd_blkdev->mapped_id);

	cbd_blkdev->cbd_r = cbdt;
	cbd_blkdev->backend_id = opts->bid;
	cbd_blkdev->num_queues = opts->blkdev.queues;
	cbd_blkdev->blkdev_info = cbdt_get_blkdev_info(cbdt, cbd_blkdev->blkdev_id);
	cbd_blkdev->blkdev_dev = &cbdt->cbd_blkdevs_dev->blkdev_devs[cbd_blkdev->blkdev_id];

	pr_err("blkdev_id: %u", cbd_blkdev->blkdev_id);

	pr_err("queues: %u", cbd_blkdev->num_queues);
	ret = dev_init(cbd_blkdev);
	if (ret < 0) {
		goto id_release;
	}

	spin_lock(&cbd_dev_list_lock);
	list_add(&cbd_blkdev->node, &cbd_dev_list);
	spin_unlock(&cbd_dev_list_lock);

	cbd_blkdev->blkdev_info->mapped_id = cbd_blkdev->blkdev_id;
	cbd_blkdev->blkdev_info->state = CBD_BLKDEV_STATE_RUNNING;

	set_capacity(cbd_blkdev->disk, cbd_blkdev->dev_size / SECTOR_SIZE);

	set_disk_ro(cbd_blkdev->disk, false);
	blk_queue_write_cache(cbd_blkdev->disk->queue, false, false);

	add_disk(cbd_blkdev->disk);

	sysfs_create_link(&disk_to_dev(cbd_blkdev->disk)->kobj, &cbd_blkdev->blkdev_dev->dev.kobj, "cbd_blkdev");

	cbd_debugfs_add_dev(cbd_blkdev);

	blk_put_queue(cbd_blkdev->disk->queue);

	return 0;

id_release:
	ida_simple_remove(&cbd_mapped_id_ida, cbd_blkdev->mapped_id);
blkdev_free:
	kfree(cbd_blkdev);
	return ret;
}

int cbd_blkdev_stop(struct cbd_transport *cbdt, struct cbd_adm_options *opts)
{
	struct cbd_blkdev *cbd_blkdev, *next;
	bool found = false;

	spin_lock(&cbd_dev_list_lock);
	list_for_each_entry_safe(cbd_blkdev, next, &cbd_dev_list, node) {
		if (cbd_blkdev->mapped_id == opts->blkdev.did) {
			list_del(&cbd_blkdev->node);
			found = true;
			break;
		}
	}
	spin_unlock(&cbd_dev_list_lock);

	if (!found) {
		return -EINVAL;
	}

	cbd_debugfs_remove_dev(cbd_blkdev);
	ida_simple_remove(&cbd_mapped_id_ida, cbd_blkdev->mapped_id);

	cbd_blkdev->blkdev_info->state = CBD_BLKDEV_STATE_EMPTY;

	del_gendisk(cbd_blkdev->disk);
	put_disk(cbd_blkdev->disk);
	blk_mq_free_tag_set(&cbd_blkdev->tag_set);
	cbd_blkdev_destroy_queues(cbd_blkdev);
	if (verify) {
		vfree(cbd_blkdev->verify_data);
	}
	kfree(cbd_blkdev);

	return 0;
}

int cbd_blkdev_init(void)
{
	cbd_major = register_blkdev(0, "cbd");

	return 0;
}

void cbd_blkdev_exit(void)
{
	unregister_blkdev(cbd_major, "cbd");
}
