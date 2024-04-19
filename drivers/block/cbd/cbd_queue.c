#include "cbd_internal.h"

/*
 * How do blkdev and backend interact through the channel?
 *         a) For reader side, before reading the data, if the data in this channel may
 * be modified by the other party, then I need to flush the cache before reading to ensure
 * that I get the latest data. For example, the blkdev needs to flush the cache before
 * obtaining compr_head because compr_head will be updated by the backend handler.
 *         b) For writter side, if the written information will be read by others, then
 * after writing, I need to flush the cache to let the other party see it immediately.
 * For example, after blkdev submits cbd_se, it needs to update cmd_head to let the
 * handler have a new cbd_se. Therefore, after updating cmd_head, I need to flush the
 * cache to let the backend see it.
 *
 * For the blkdev queue, I am the only one who updates the `cmd_head`, `cmd_tail`, and `compr_tail'.
 * Therefore, I don't need to flush_dcache before reading these data. However, after updating these data,
 * I need to flush_dcache so that the backend handler can see these updates.
 *
 * On the other hand, `compr_head` is updated by the backend handler. So, I need to flush_dcache before
 * reading `compr_head` to ensure that I can see the updates.
 *
 *           ┌───────────┐          ┌─────────────┐
 *           │  blkdev   │          │   backend   │
 *           │  queue    │          │   handler   │
 *           └─────┬─────┘          └──────┬──────┘
 *                 ▼                       │
 *        init data and cbd_se             │
 *                 │                       │
 *                 ▼                       │
 *            update cmd_head              │
 *                 │                       │
 *                 ▼                       │
 *            flush_cache                  │
 *                 │                       ▼
 *                 │                    flush_cache
 *                 │                       │
 *                 │                       ▼
 *                 │                   handle cmd
 *                 │                       │
 *                 │                       ▼
 *                 │                    fill cbd_ce
 *                 │                       │
 *                 │                       ▼
 *                 │                    flush_cache
 *                 ▼
 *            flush_cache
 *                 │
 *                 ▼
 *            complete_req
 */

static inline struct cbd_se *get_submit_entry(struct cbd_queue *cbdq)
{
	return (struct cbd_se *)(cbdq->channel.cmdr + cbdq->channel_info->cmd_head);
}

static inline struct cbd_se *get_oldest_se(struct cbd_queue *cbdq)
{
	if (cbdq->channel_info->cmd_tail == cbdq->channel_info->cmd_head)
		return NULL;

	return (struct cbd_se *)(cbdq->channel.cmdr + cbdq->channel_info->cmd_tail);
}

static inline struct cbd_ce *get_complete_entry(struct cbd_queue *cbdq)
{
	if (cbdq->channel_info->compr_tail == cbdq->channel_info->compr_head)
		return NULL;

	return (struct cbd_ce *)(cbdq->channel.compr + cbdq->channel_info->compr_tail);
}

static void cbd_req_init(struct cbd_queue *cbdq, enum cbd_op op, struct request *rq)
{
	struct cbd_request *cbd_req = blk_mq_rq_to_pdu(rq);

	cbd_req->req = rq;
	cbd_req->cbdq = cbdq;
	cbd_req->op = op;

	return;
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

static inline size_t cbd_get_cmd_size(struct cbd_request *cbd_req)
{
	u32 segs = cbd_req_segments(cbd_req);
	u32 cmd_size = sizeof(struct cbd_se) + (sizeof(struct iovec) * segs);

	return round_up(cmd_size, CBD_OP_ALIGN_SIZE);
}

static void insert_padding(struct cbd_queue *cbdq, u32 cmd_size)
{
	struct cbd_se_hdr *header;
	u32 pad_len;

	if (cbdq->channel_info->cmdr_size - cbdq->channel_info->cmd_head >= cmd_size)
		return;

	pad_len = cbdq->channel_info->cmdr_size - cbdq->channel_info->cmd_head;
	cbd_queue_debug(cbdq, "insert pad:%d\n", pad_len);

	header = (struct cbd_se_hdr *)get_submit_entry(cbdq);
	memset(header, 0, pad_len);
	cbd_se_hdr_set_op(&header->len_op, CBD_OP_PAD);
	cbd_se_hdr_set_len(&header->len_op, pad_len);

	cbdt_flush_range(cbdq->cbd_blkdev->cbdt, header, sizeof(*header));

	CBDC_UPDATE_CMDR_HEAD(cbdq->channel_info->cmd_head, pad_len, cbdq->channel_info->cmdr_size);
}

static void queue_req_se_init(struct cbd_request *cbd_req)
{
	struct cbd_se	*se;
	struct cbd_se_hdr *header;
	u64 offset = (u64)blk_rq_pos(cbd_req->req) << SECTOR_SHIFT;
	u64 length = blk_rq_bytes(cbd_req->req);

	se = get_submit_entry(cbd_req->cbdq);
	memset(se, 0, cbd_get_cmd_size(cbd_req));
	header = &se->header;

	cbd_se_hdr_set_op(&header->len_op, cbd_req->op);
	cbd_se_hdr_set_len(&header->len_op, cbd_get_cmd_size(cbd_req));

	se->priv_data = cbd_req->req_tid;
	se->offset = offset;
	se->len = length;

	if (req_op(cbd_req->req) == REQ_OP_READ || req_op(cbd_req->req) == REQ_OP_WRITE) {
		se->data_off = cbd_req->cbdq->channel.data_head;
		se->data_len = length;
	}

	cbd_req->se = se;
}

static bool data_space_enough(struct cbd_queue *cbdq, struct cbd_request *cbd_req)
{
	u32 space_available;
	u32 space_needed;
	u32 space_used;
	u32 space_max;

	space_max = cbdq->channel.data_size - 4096;

	if (cbdq->channel.data_head > cbdq->channel.data_tail)
		space_used = cbdq->channel.data_head - cbdq->channel.data_tail;
	else if (cbdq->channel.data_head < cbdq->channel.data_tail)
		space_used = cbdq->channel.data_head + (cbdq->channel.data_size - cbdq->channel.data_tail);
	else
		space_used = 0;

	space_available = space_max - space_used;

	space_needed = round_up(cbd_req->data_len, 4096);

	if (space_available < space_needed) {
		cbd_queue_err(cbdq, "data space is not enough: availaible: %u needed: %u",
			      space_available, space_needed);
		return false;
	}

	return true;
}

static bool submit_ring_space_enough(struct cbd_queue *cbdq, u32 cmd_size)
{
	u32 space_available;
	u32 space_needed;
	u32 space_max, space_used;

	/* There is a CMDR_RESERVED we dont use to prevent the ring to be used up */
	space_max = cbdq->channel_info->cmdr_size - CBDC_CMDR_RESERVED;

	if (cbdq->channel_info->cmd_head > cbdq->channel_info->cmd_tail)
		space_used = cbdq->channel_info->cmd_head - cbdq->channel_info->cmd_tail;
	else if (cbdq->channel_info->cmd_head < cbdq->channel_info->cmd_tail)
		space_used = cbdq->channel_info->cmd_head + (cbdq->channel_info->cmdr_size - cbdq->channel_info->cmd_tail);
	else
		space_used = 0;

	space_available = space_max - space_used;

	if (cbdq->channel_info->cmdr_size - cbdq->channel_info->cmd_head > cmd_size)
		space_needed = cmd_size;
	else
		space_needed = cmd_size + cbdq->channel_info->cmdr_size - cbdq->channel_info->cmd_head;

	if (space_available < space_needed)
		return false;

	return true;
}

static void queue_req_data_init(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbdq = cbd_req->cbdq;
	struct bio *bio = cbd_req->req->bio;

	if (cbd_req->op == CBD_OP_READ) {
		goto advance_data_head;
	}

	cbdc_copy_from_bio(&cbdq->channel, cbd_req->data_off, cbd_req->data_len, bio);

advance_data_head:
	cbdq->channel.data_head = round_up(cbdq->channel.data_head + cbd_req->data_len, PAGE_SIZE);
	cbdq->channel.data_head %= cbdq->channel.data_size;

	return;
}

static void complete_inflight_req(struct cbd_queue *cbdq, struct cbd_request *cbd_req, int ret);
static void cbd_queue_fn(struct cbd_request *cbd_req)
{
	struct cbd_queue *cbdq = cbd_req->cbdq;
	int ret = 0;
	size_t command_size;

	spin_lock(&cbdq->inflight_reqs_lock);
	list_add_tail(&cbd_req->inflight_reqs_node, &cbdq->inflight_reqs);
	spin_unlock(&cbdq->inflight_reqs_lock);

	command_size = cbd_get_cmd_size(cbd_req);

	spin_lock(&cbdq->channel.cmdr_lock);
	if (req_op(cbd_req->req) == REQ_OP_WRITE || req_op(cbd_req->req) == REQ_OP_READ) {
		cbd_req->data_off = cbdq->channel.data_head;
		cbd_req->data_len = blk_rq_bytes(cbd_req->req);
	} else {
		cbd_req->data_off = -1;
		cbd_req->data_len = 0;
	}

	if (!submit_ring_space_enough(cbdq, command_size) ||
			!data_space_enough(cbdq, cbd_req)) {
		spin_unlock(&cbdq->channel.cmdr_lock);

		/* remove request from inflight_reqs */
		spin_lock(&cbdq->inflight_reqs_lock);
		list_del_init(&cbd_req->inflight_reqs_node);
		spin_unlock(&cbdq->inflight_reqs_lock);

		cbd_blk_debug(cbdq->cbd_blkdev, "transport space is not enough");
		ret = -ENOMEM;
		goto end_request;
	}

	insert_padding(cbdq, command_size);

	cbd_req->req_tid = ++cbdq->req_tid;
	queue_req_se_init(cbd_req);
	cbdt_flush_range(cbdq->cbd_blkdev->cbdt, cbd_req->se, sizeof(struct cbd_se));

	if (!cbd_req_nodata(cbd_req)) {
		queue_req_data_init(cbd_req);
	}

	queue_delayed_work(cbdq->task_wq, &cbdq->complete_work, 0);

	CBDC_UPDATE_CMDR_HEAD(cbdq->channel_info->cmd_head,
			cbd_get_cmd_size(cbd_req),
			cbdq->channel_info->cmdr_size);
	cbdc_flush_ctrl(&cbdq->channel);
	spin_unlock(&cbdq->channel.cmdr_lock);

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

static void advance_cmd_ring(struct cbd_queue *cbdq)
{
       struct cbd_se *se;
again:
       se = get_oldest_se(cbdq);
       if (!se)
               goto out;

	if (cbd_se_hdr_flags_test(se, CBD_SE_HDR_DONE)) {
		CBDC_UPDATE_CMDR_TAIL(cbdq->channel_info->cmd_tail,
				cbd_se_hdr_get_len(se->header.len_op),
				cbdq->channel_info->cmdr_size);
		cbdc_flush_ctrl(&cbdq->channel);
		goto again;
       }
out:
       return;
}

static bool __advance_data_tail(struct cbd_queue *cbdq, u32 data_off, u32 data_len)
{
	if (data_off == cbdq->channel.data_tail) {
		cbdq->released_extents[data_off / 4096] = 0;
		cbdq->channel.data_tail += data_len;
		if (cbdq->channel.data_tail >= cbdq->channel.data_size) {
			cbdq->channel.data_tail %= cbdq->channel.data_size;
		}
		return true;
	}

	return false;
}

static void advance_data_tail(struct cbd_queue *cbdq, u32 data_off, u32 data_len)
{
	cbdq->released_extents[data_off / 4096] = data_len;

	while (__advance_data_tail(cbdq, data_off, data_len)) {
		data_off += data_len;
		data_len = cbdq->released_extents[data_off / 4096];
		if (!data_len) {
			break;
		}
	}
}

static inline void complete_inflight_req(struct cbd_queue *cbdq, struct cbd_request *cbd_req, int ret)
{
	u32 data_off, data_len;
	bool advance_data = false;

	spin_lock(&cbdq->inflight_reqs_lock);
	list_del_init(&cbd_req->inflight_reqs_node);
	spin_unlock(&cbdq->inflight_reqs_lock);

	cbd_se_hdr_flags_set(cbd_req->se, CBD_SE_HDR_DONE);
	data_off = cbd_req->data_off;
	data_len = cbd_req->data_len;
	advance_data = (!cbd_req_nodata(cbd_req));

	blk_mq_end_request(cbd_req->req, errno_to_blk_status(ret));

	cbd_req_release(cbd_req);

	spin_lock(&cbdq->channel.cmdr_lock);
	advance_cmd_ring(cbdq);
	if (advance_data)
		advance_data_tail(cbdq, data_off, round_up(data_len, PAGE_SIZE));
	spin_unlock(&cbdq->channel.cmdr_lock);
}

static struct cbd_request *fetch_inflight_req(struct cbd_queue *cbdq, u64 req_tid)
{
	struct cbd_request *req;
	bool found = false;

	list_for_each_entry(req, &cbdq->inflight_reqs, inflight_reqs_node) {
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
	struct bio *bio = cbd_req->req->bio;
	struct cbd_queue *cbdq = cbd_req->cbdq;

	cbdc_copy_to_bio(&cbdq->channel, cbd_req->data_off, cbd_req->data_len, bio);

	return;
}

static void complete_work_fn(struct work_struct *work)
{
	struct cbd_queue *cbdq = container_of(work, struct cbd_queue, complete_work.work);
	struct cbd_ce *ce;
	struct cbd_request *cbd_req;

again:
	/* compr_head would be updated by backend handler */
	cbdc_flush_ctrl(&cbdq->channel);

	spin_lock(&cbdq->channel.compr_lock);
	ce = get_complete_entry(cbdq);
	if (!ce) {
		spin_unlock(&cbdq->channel.compr_lock);
		if (cbdwc_need_retry(&cbdq->complete_worker_cfg)) {
			goto again;
		}

		spin_lock(&cbdq->inflight_reqs_lock);
		if (list_empty(&cbdq->inflight_reqs)) {
			spin_unlock(&cbdq->inflight_reqs_lock);
			cbdwc_init(&cbdq->complete_worker_cfg);
			return;
		}
		spin_unlock(&cbdq->inflight_reqs_lock);

		cbdwc_miss(&cbdq->complete_worker_cfg);

		queue_delayed_work(cbdq->task_wq, &cbdq->complete_work, 0);
		return;
	}
	cbdwc_hit(&cbdq->complete_worker_cfg);
	CBDC_UPDATE_COMPR_TAIL(cbdq->channel_info->compr_tail,
			       sizeof(struct cbd_ce),
			       cbdq->channel_info->compr_size);
	cbdc_flush_ctrl(&cbdq->channel);
	spin_unlock(&cbdq->channel.compr_lock);

	spin_lock(&cbdq->inflight_reqs_lock);
	/* flush to ensure the content of ce is uptodate */
	cbdt_flush_range(cbdq->cbd_blkdev->cbdt, ce, sizeof(*ce));
	cbd_req = fetch_inflight_req(cbdq, ce->priv_data);
	spin_unlock(&cbdq->inflight_reqs_lock);
	if (!cbd_req) {
		goto again;
	}

	if (req_op(cbd_req->req) == REQ_OP_READ) {
		spin_lock(&cbdq->channel.cmdr_lock);
		copy_data_from_cbdteq(cbd_req);
		spin_unlock(&cbdq->channel.cmdr_lock);
	}

	complete_inflight_req(cbdq, cbd_req, ce->result);

	goto again;
}

static blk_status_t cbd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct request *req = bd->rq;
	struct cbd_queue *cbdq = hctx->driver_data;
	struct cbd_request *cbd_req = blk_mq_rq_to_pdu(bd->rq);

	memset(cbd_req, 0, sizeof(struct cbd_request));
	INIT_LIST_HEAD(&cbd_req->inflight_reqs_node);

	blk_mq_start_request(bd->rq);

	switch (req_op(bd->rq)) {
	case REQ_OP_FLUSH:
		cbd_req_init(cbdq, CBD_OP_FLUSH, req);
		break;
	case REQ_OP_DISCARD:
		cbd_req_init(cbdq, CBD_OP_DISCARD, req);
		break;
	case REQ_OP_WRITE_ZEROES:
		cbd_req_init(cbdq, CBD_OP_WRITE_ZEROS, req);
		break;
	case REQ_OP_WRITE:
		cbd_req_init(cbdq, CBD_OP_WRITE, req);
		break;
	case REQ_OP_READ:
		cbd_req_init(cbdq, CBD_OP_READ, req);
		break;
	default:
		return BLK_STS_IOERR;
	}

	cbd_queue_fn(cbd_req);

	return BLK_STS_OK;
}

static int cbd_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
			unsigned int hctx_idx)
{
	struct cbd_blkdev *cbd_blkdev = driver_data;
	struct cbd_queue *cbdq;

	cbdq = &cbd_blkdev->queues[hctx_idx];
	hctx->driver_data = cbdq;

	return 0;
}

const struct blk_mq_ops cbd_mq_ops = {
	.queue_rq	= cbd_queue_rq,
	.init_hctx	= cbd_init_hctx,
};

static int cbd_queue_channel_init(struct cbd_queue *cbdq, u32 channel_id)
{
	struct cbd_blkdev *cbd_blkdev = cbdq->cbd_blkdev;
	struct cbd_transport *cbdt = cbd_blkdev->cbdt;

	cbdq->channel_id = channel_id;
	cbd_channel_init(&cbdq->channel, cbdt, channel_id);
	cbdq->channel_info = cbdq->channel.channel_info;

	cbdq->channel.data_head = cbdq->channel.data_tail = 0;

	/* Initialise the channel_info of the ring buffer */
	cbdq->channel_info->cmdr_off = CBDC_CMDR_OFF;
	cbdq->channel_info->cmdr_size = CBDC_CMDR_SIZE;
	cbdq->channel_info->compr_off = CBDC_COMPR_OFF;
	cbdq->channel_info->compr_size = CBDC_COMPR_SIZE;

	cbdq->channel_info->backend_id = cbd_blkdev->backend_id;
	cbdq->channel_info->blkdev_id = cbd_blkdev->blkdev_id;
	cbdq->channel_info->blkdev_state = cbdc_blkdev_state_running;
	cbdq->channel_info->state = cbd_channel_state_running;

	cbdc_flush_ctrl(&cbdq->channel);

	return 0;
}

int cbd_queue_start(struct cbd_queue *cbdq)
{
	struct cbd_transport *cbdt = cbdq->cbd_blkdev->cbdt;
	u32 channel_id;
	int ret;

	ret = cbdt_get_empty_channel_id(cbdt, &channel_id);
	if (ret < 0) {
		cbdt_err(cbdt, "failed find available channel_id.\n");
		goto err;
	}

	ret = cbd_queue_channel_init(cbdq, channel_id);
	if (ret) {
		cbd_queue_err(cbdq, "failed to init dev channel_info: %d.", ret);
		goto err;
	}

	INIT_LIST_HEAD(&cbdq->inflight_reqs);
	spin_lock_init(&cbdq->inflight_reqs_lock);
	cbdq->req_tid = 0;
	INIT_DELAYED_WORK(&cbdq->complete_work, complete_work_fn);
	cbdwc_init(&cbdq->complete_worker_cfg);

	cbdq->released_extents = kmalloc(sizeof(u32) * (CBDC_DATA_SIZE >> PAGE_SHIFT), GFP_KERNEL);
	if (!cbdq->released_extents) {
		ret = -ENOMEM;
		goto err;
	}

	cbdq->task_wq = alloc_workqueue("cbd%d-queue%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdq->cbd_blkdev->mapped_id, cbdq->index);
	if (!cbdq->task_wq) {
		ret = -ENOMEM;
		goto released_extents_free;
	}

	queue_delayed_work(cbdq->task_wq, &cbdq->complete_work, 0);

	atomic_set(&cbdq->state, cbd_queue_state_running);

	return 0;

released_extents_free:
	kfree(cbdq->released_extents);
err:
	return ret;
}

void cbd_queue_stop(struct cbd_queue *cbdq)
{
	if (atomic_cmpxchg(&cbdq->state,
			   cbd_queue_state_running,
			   cbd_queue_state_none) != cbd_queue_state_running)
		return;

	cancel_delayed_work_sync(&cbdq->complete_work);
	drain_workqueue(cbdq->task_wq);
	destroy_workqueue(cbdq->task_wq);

	kfree(cbdq->released_extents);
	cbdq->channel_info->blkdev_state = cbdc_blkdev_state_none;

	cbdc_flush_ctrl(&cbdq->channel);

	return;
}
