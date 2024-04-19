#include "cbd_internal.h"

static inline struct cbd_se *get_se_head(struct cbd_handler *handler)
{
	return (struct cbd_se *)(handler->channel.cmdr + handler->channel_info->cmd_head);
}

static inline struct cbd_se *get_se_to_handle(struct cbd_handler *handler)
{
	return (struct cbd_se *)(handler->channel.cmdr + handler->se_to_handle);
}

static inline struct cbd_ce *get_compr_head(struct cbd_handler *handler)
{
	return (struct cbd_ce *)(handler->channel.compr + handler->channel_info->compr_head);
}

struct cbd_backend_io {
	struct cbd_se		*se;
	u64			off;
	u32			len;
	struct bio		*bio;
	struct cbd_handler	*handler;
};

static inline void complete_cmd(struct cbd_handler *handler, u64 priv_data, int ret)
{
	struct cbd_ce *ce = get_compr_head(handler);

	memset(ce, 0, sizeof(*ce));
	ce->priv_data = priv_data;
	ce->result = ret;
	CBDC_UPDATE_COMPR_HEAD(handler->channel_info->compr_head,
			       sizeof(struct cbd_ce),
			       handler->channel_info->compr_size);

	cbdc_flush_ctrl(&handler->channel);

	return;
}

static void backend_bio_end(struct bio *bio)
{
	struct cbd_backend_io *backend_io = bio->bi_private;
	struct cbd_se *se = backend_io->se;
	struct cbd_handler *handler = backend_io->handler;

	if (bio->bi_status == 0 &&
	    cbd_se_hdr_get_op(se->header.len_op) == CBD_OP_READ) {
		cbdc_copy_from_bio(&handler->channel, se->data_off, se->data_len, bio);
	}

	complete_cmd(handler, se->priv_data, bio->bi_status);

	bio_free_pages(bio);
	bio_put(bio);
	kfree(backend_io);
}

static int cbd_bio_alloc_pages(struct bio *bio, size_t size, gfp_t gfp_mask)
{
	int ret = 0;

        while (size) {
                struct page *page = alloc_pages(gfp_mask, 0);
                unsigned len = min_t(size_t, PAGE_SIZE, size);

                if (!page) {
			pr_err("failed to alloc page");
			ret = -ENOMEM;
			break;
		}

		ret = bio_add_page(bio, page, len, 0);
                if (unlikely(ret != len)) {
                        __free_page(page);
			pr_err("failed to add page");
                        break;
                }

                size -= len;
        }

	if (size)
		bio_free_pages(bio);
	else
		ret = 0;

        return ret;
}

static struct cbd_backend_io *backend_prepare_io(struct cbd_handler *handler, struct cbd_se *se, blk_opf_t opf)
{
	struct cbd_backend_io *backend_io;
	struct cbd_backend *cbdb = handler->cbdb;

	backend_io = kzalloc(sizeof(struct cbd_backend_io), GFP_KERNEL);
	backend_io->se = se;

	backend_io->handler = handler;
	backend_io->bio = bio_alloc_bioset(cbdb->bdev, roundup(se->len, 4096) / 4096, opf, GFP_KERNEL, &handler->bioset);

	backend_io->bio->bi_iter.bi_sector = se->offset >> SECTOR_SHIFT;
	backend_io->bio->bi_iter.bi_size = 0;
	backend_io->bio->bi_private = backend_io;
	backend_io->bio->bi_end_io = backend_bio_end;

	return backend_io;
}

static int handle_backend_cmd(struct cbd_handler *handler, struct cbd_se *se)
{
	struct cbd_backend *cbdb = handler->cbdb;
	u32 len = se->len;
	struct cbd_backend_io *backend_io = NULL;
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
		ret = blkdev_issue_discard(cbdb->bdev, se->offset >> SECTOR_SHIFT,
				se->len, GFP_NOIO);
		goto complete_cmd;
	case CBD_OP_WRITE_ZEROS:
		ret = blkdev_issue_zeroout(cbdb->bdev, se->offset >> SECTOR_SHIFT,
				se->len, GFP_NOIO, 0);
		goto complete_cmd;
	case CBD_OP_FLUSH:
		ret = blkdev_issue_flush(cbdb->bdev);
		goto complete_cmd;
	default:
		pr_err("unrecognized op: %x", cbd_se_hdr_get_op(se->header.len_op));
		ret = -EIO;
		goto complete_cmd;
	}

	if (!backend_io)
		return -ENOMEM;

	ret = cbd_bio_alloc_pages(backend_io->bio, len, GFP_NOIO);
	if (ret) {
		kfree(backend_io);
		return ret;
	}

	if (cbd_se_hdr_get_op(se->header.len_op) == CBD_OP_WRITE) {
		cbdc_copy_to_bio(&handler->channel, se->data_off, se->data_len, backend_io->bio);
	}

	submit_bio(backend_io->bio);

	return 0;

complete_cmd:
	complete_cmd(handler, se->priv_data, ret);
	return 0;
}

static void handle_work_fn(struct work_struct *work)
{
	struct cbd_handler *handler = container_of(work, struct cbd_handler, handle_work.work);
	struct cbd_se *se;
	int ret;
again:
	/* channel ctrl would be updated by blkdev queue */
	cbdc_flush_ctrl(&handler->channel);
	se = get_se_to_handle(handler);
	if (se == get_se_head(handler)) {
		if (cbdwc_need_retry(&handler->handle_worker_cfg)) {
			goto again;
		}

		cbdwc_miss(&handler->handle_worker_cfg);

		queue_delayed_work(handler->handle_wq, &handler->handle_work, usecs_to_jiffies(0));
		return;
	}

	cbdwc_hit(&handler->handle_worker_cfg);
	cbdt_flush_range(handler->cbdb->cbdt, se, sizeof(*se));
	ret = handle_backend_cmd(handler, se);
	if (!ret) {
		/* this se is handled */
		handler->se_to_handle = (handler->se_to_handle + cbd_se_hdr_get_len(se->header.len_op)) % handler->channel_info->cmdr_size;
	}

	goto again;
}

int cbd_handler_create(struct cbd_backend *cbdb, u32 channel_id)
{
	struct cbd_transport *cbdt = cbdb->cbdt;
	struct cbd_handler *handler;
	int ret;

	handler = kzalloc(sizeof(struct cbd_handler), GFP_KERNEL);
	if (!handler) {
		return -ENOMEM;
	}

	handler->cbdb = cbdb;
	cbd_channel_init(&handler->channel, cbdt, channel_id);
	handler->channel_info = handler->channel.channel_info;

	handler->handle_wq = alloc_workqueue("cbdt%u-handler%u",
					     WQ_UNBOUND | WQ_MEM_RECLAIM,
					     0, cbdt->id, channel_id);
	if (!handler->handle_wq) {
		ret = -ENOMEM;
		goto free_handler;
	}

	handler->se_to_handle = handler->channel_info->cmd_tail;

	INIT_DELAYED_WORK(&handler->handle_work, handle_work_fn);
	INIT_LIST_HEAD(&handler->handlers_node);

	bioset_init(&handler->bioset, 128, 0, BIOSET_NEED_BVECS);
	cbdwc_init(&handler->handle_worker_cfg);

	cbdb_add_handler(cbdb, handler);
	handler->channel_info->backend_state = cbdc_backend_state_running;

	cbdt_flush_range(cbdt, handler->channel_info, sizeof(*handler->channel_info));

	queue_delayed_work(handler->handle_wq, &handler->handle_work, 0);

	return 0;

free_handler:
	kfree(handler);
	return ret;
};

void cbd_handler_destroy(struct cbd_handler *handler)
{
	cbdb_del_handler(handler->cbdb, handler);

	cancel_delayed_work_sync(&handler->handle_work);
	drain_workqueue(handler->handle_wq);
	destroy_workqueue(handler->handle_wq);

	handler->channel_info->backend_state = cbdc_backend_state_none;
	handler->channel_info->state = cbd_channel_state_none;
	cbdt_flush_range(handler->cbdb->cbdt, handler->channel_info, sizeof(*handler->channel_info));

	bioset_exit(&handler->bioset);
	kfree(handler);
}
