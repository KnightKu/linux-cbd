// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/blk_types.h>

#include "../cbd_backend.h"
#include "cbd_cache_internal.h"

void cbd_cache_info_init(struct cbd_cache_info *cache_info, u32 cache_segs)
{
	cache_info->n_segs = cache_segs;
	cache_info->gc_percent = CBD_CACHE_GC_PERCENT_DEFAULT;
}

static void cache_segs_destroy(struct cbd_cache *cache)
{
	u32 i;

	if (!cache->owner)
		return;

	for (i = 0; i < cache->n_segs; i++)
		cache_seg_destroy(&cache->segments[i]);
}

static void cache_info_set_seg_id(struct cbd_cache *cache, u32 seg_id)
{
	cache->cache_info->seg_id = seg_id;
	cache_info_write(cache);
}

/*
 * get_seg_id - Retrieve the segment ID for cache initialization
 * @cache: Pointer to the cache structure
 * @prev_cache_seg: Pointer to the previous cache segment in the sequence
 * @new_cache: Flag indicating if this is a new cache initialization
 * @seg_id: Pointer to store the retrieved or allocated segment ID
 *
 * For a new cache, this function allocates a new segment ID, clears the
 * corresponding segment, and links it with the previous segment in the chain.
 * If reloading an existing cache, it retrieves the segment ID based on the
 * segment chain, using the previous segment information to maintain continuity.
 *
 * Returns:
 *   0 on success,
 *   -ENOMEM if no available segment is found for a new cache,
 *   -EFAULT if there is an inconsistency in the segment chain for a reloaded cache.
 */
static int get_seg_id(struct cbd_cache *cache,
		      struct cbd_cache_segment *prev_cache_seg,
		      bool new_cache, u32 *seg_id)
{
	struct cbd_transport *cbdt = cache->cbdt;
	int ret;

	if (new_cache) {
		ret = cbdt_get_empty_segment_id(cbdt, seg_id);
		if (ret) {
			cbd_cache_err(cache, "no available segment\n");
			goto err;
		}

		/* clear the whole segment before using */
		cbd_segment_clear(cbdt, *seg_id);

		if (prev_cache_seg)
			cache_seg_set_next_seg(prev_cache_seg, *seg_id);
		else
			cache_info_set_seg_id(cache, *seg_id);
	} else {
		if (prev_cache_seg) {
			struct cbd_segment_info *prev_seg_info;

			prev_seg_info = &prev_cache_seg->cache_seg_info.segment_info;
			if (!cbd_segment_info_has_next(prev_seg_info)) {
				ret = -EFAULT;
				goto err;
			}
			*seg_id = prev_cache_seg->cache_seg_info.segment_info.next_seg;
		} else {
			*seg_id = cache->cache_info->seg_id;
		}
	}
	return 0;
err:
	return ret;
}

static int cache_segs_init(struct cbd_cache *cache, bool new_cache)
{
	struct cbd_cache_segment *prev_cache_seg = NULL;
	struct cbd_cache_info *cache_info = cache->cache_info;
	u32 seg_id;
	int ret;
	u32 i;

	for (i = 0; i < cache_info->n_segs; i++) {
		ret = get_seg_id(cache, prev_cache_seg, new_cache, &seg_id);
		if (ret)
			goto segments_destroy;

		ret = cache_seg_init(cache, seg_id, i, new_cache);
		if (ret)
			goto segments_destroy;

		prev_cache_seg = &cache->segments[i];
	}
	return 0;

segments_destroy:
	cache_segs_destroy(cache);

	return ret;
}

/**
 * cache_alloc - Allocates and initializes a cbd_cache structure with necessary resources
 * @cbdt: The transport structure associated with the cache
 * @cache_info: Information about the cache, such as the number of segments
 *
 * This function sets up the cache structure by allocating memory for
 * its segments and associated data, initializing workqueues, and setting up
 * synchronization primitives. On failure, resources are released in the
 * appropriate order before returning NULL.
 *
 * Return: Pointer to the initialized cache structure, or NULL on failure.
 */
static struct cbd_cache *cache_alloc(struct cbd_transport *cbdt, struct cbd_cache_info *cache_info)
{
	struct cbd_cache *cache;

	cache = kvzalloc(struct_size(cache, segments, cache_info->n_segs), GFP_KERNEL);
	if (!cache)
		goto err;

	cache->seg_map = bitmap_zalloc(cache_info->n_segs, GFP_KERNEL);
	if (!cache->seg_map)
		goto free_cache;

	cache->key_cache = KMEM_CACHE(cbd_cache_key, 0);
	if (!cache->key_cache)
		goto free_bitmap;

	cache->req_cache = KMEM_CACHE(cbd_request, 0);
	if (!cache->req_cache)
		goto free_key_cache;

	cache->cache_wq = alloc_workqueue("cbdt%d-c%u",  WQ_UNBOUND | WQ_MEM_RECLAIM,
					0, cbdt->id, cache->cache_id);
	if (!cache->cache_wq)
		goto free_req_cache;

	cache->cbdt = cbdt;
	cache->cache_info = cache_info;
	cache->n_segs = cache_info->n_segs;
	spin_lock_init(&cache->seg_map_lock);
	spin_lock_init(&cache->key_head_lock);
	spin_lock_init(&cache->miss_read_reqs_lock);
	INIT_LIST_HEAD(&cache->miss_read_reqs);

	mutex_init(&cache->key_tail_lock);
	mutex_init(&cache->dirty_tail_lock);

	INIT_DELAYED_WORK(&cache->writeback_work, cache_writeback_fn);
	INIT_DELAYED_WORK(&cache->gc_work, cbd_cache_gc_fn);
	INIT_WORK(&cache->clean_work, clean_fn);
	INIT_WORK(&cache->miss_read_end_work, miss_read_end_work_fn);

	return cache;

free_req_cache:
	kmem_cache_destroy(cache->req_cache);
free_key_cache:
	kmem_cache_destroy(cache->key_cache);
free_bitmap:
	bitmap_free(cache->seg_map);
free_cache:
	kvfree(cache);
err:
	return NULL;
}

static void cache_free(struct cbd_cache *cache)
{
	drain_workqueue(cache->cache_wq);
	destroy_workqueue(cache->cache_wq);
	kmem_cache_destroy(cache->req_cache);
	kmem_cache_destroy(cache->key_cache);
	bitmap_free(cache->seg_map);
	kvfree(cache);
}

/*
 * cache_init_keys - Initialize cache key-related data structures
 * @cache: Pointer to the cache structure
 * @n_paral: Number of parallel instances, usually matching the number of blkdev queues
 *
 * This function sets up the primary data structures for managing cache keys,
 * including cache trees, ksets, and data heads. It also performs a replay of
 * persisted cache keys using cache_replay().
 *
 * Returns 0 on success, or a negative error code if initialization fails.
 */
static int cache_init_keys(struct cbd_cache *cache, u32 n_paral)
{
	int ret;
	u32 i;

	/* Calculate number of cache trees based on the device size */
	cache->n_trees = DIV_ROUND_UP(cache->dev_size << SECTOR_SHIFT, CBD_CACHE_TREE_SIZE);

	/*
	 * Allocate and initialize the cache_trees array.
	 * Each element is a cache tree structure that contains
	 * an RB tree root and a spinlock for protecting its contents.
	 */
	cache->cache_trees = kvcalloc(cache->n_trees, sizeof(struct cbd_cache_tree), GFP_KERNEL);
	if (!cache->cache_trees) {
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < cache->n_trees; i++) {
		struct cbd_cache_tree *cache_tree = &cache->cache_trees[i];

		cache_tree->root = RB_ROOT;
		spin_lock_init(&cache_tree->tree_lock);
	}

	/* Set the number of ksets based on n_paral, often corresponding to blkdev multiqueue count */
	cache->n_ksets = n_paral;
	cache->ksets = kcalloc(cache->n_ksets, CBD_KSET_SIZE, GFP_KERNEL);
	if (!cache->ksets) {
		ret = -ENOMEM;
		goto free_trees;
	}

	/*
	 * Initialize each kset with a spinlock and delayed work for flushing.
	 * Each kset is associated with one queue to ensure independent handling
	 * of cache keys across multiple queues, maximizing multiqueue concurrency.
	 */
	for (i = 0; i < cache->n_ksets; i++) {
		struct cbd_cache_kset *kset = get_kset(cache, i);

		kset->cache = cache;
		spin_lock_init(&kset->kset_lock);
		INIT_DELAYED_WORK(&kset->flush_work, kset_flush_fn);
	}

	cache->n_heads = n_paral;
	cache->data_heads = kcalloc(cache->n_heads, sizeof(struct cbd_cache_data_head), GFP_KERNEL);
	if (!cache->data_heads) {
		ret = -ENOMEM;
		goto free_kset;
	}

	for (i = 0; i < cache->n_heads; i++) {
		struct cbd_cache_data_head *data_head = &cache->data_heads[i];

		spin_lock_init(&data_head->data_head_lock);
	}

	/*
	 * Replay persisted cache keys using cache_replay.
	 * This function loads and replays cache keys from previously stored
	 * ksets, allowing the cache to restore its state after a restart.
	 */
	ret = cache_replay(cache);
	if (ret) {
		cbd_cache_err(cache, "failed to replay keys\n");
		goto free_heads;
	}

	return 0;

free_heads:
	kfree(cache->data_heads);
free_kset:
	kfree(cache->ksets);
free_trees:
	kvfree(cache->cache_trees);
err:
	return ret;
}

/*
 * cache_destroy_keys - Clean up and free resources associated with cache keys
 * @cache: Pointer to the cache structure
 *
 * This function releases all resources allocated by cache_init_keys, including
 * cache trees, ksets, and data heads. It also cancels any delayed flush work
 * scheduled for each kset.
 */
static void cache_destroy_keys(struct cbd_cache *cache)
{
	u32 i;

	for (i = 0; i < cache->n_trees; i++) {
		struct cbd_cache_tree *cache_tree = &cache->cache_trees[i];
		struct rb_node *node;
		struct cbd_cache_key *key;

		spin_lock(&cache_tree->tree_lock);
		node = rb_first(&cache_tree->root);
		while (node) {
			key = CACHE_KEY(node);
			node = rb_next(node);

			cache_key_delete(key);
		}
		spin_unlock(&cache_tree->tree_lock);
	}

	for (i = 0; i < cache->n_ksets; i++) {
		struct cbd_cache_kset *kset = get_kset(cache, i);

		cancel_delayed_work_sync(&kset->flush_work);
	}

	kfree(cache->data_heads);
	kfree(cache->ksets);
	kvfree(cache->cache_trees);
}

static void __cache_info_load(struct cbd_transport *cbdt,
			      struct cbd_cache_info *cache_info,
			      u32 cache_id);
/*
 * cache_validate - Validate cache options and initialize cache information
 * @cbdt: Pointer to the transport structure
 * @opts: Pointer to the cache options structure
 *
 * This function validates the parameters specified in @opts for creating or
 * opening a cache. It checks if the parallelism level (n_paral) is within the
 * allowed range and ensures that a backend is specified for new caches. It
 * also initializes or loads cache information based on whether a new cache is
 * requested.
 *
 * Returns 0 on success, or -EINVAL if validation fails.
 */
static int cache_validate(struct cbd_transport *cbdt,
			  struct cbd_cache_opts *opts)
{
	struct cbd_cache_info *cache_info;

	if (opts->n_paral > CBD_CACHE_PARAL_MAX) {
		cbdt_err(cbdt, "n_paral too large (max %u).\n",
			 CBD_CACHE_PARAL_MAX);
		goto err;
	}

	/*
	 * For a new cache, ensure an owner backend is specified
	 * and initialize cache information with the specified number of segments.
	 */
	if (opts->new_cache) {
		if (!opts->owner) {
			cbdt_err(cbdt, "owner is needed for new cache.\n");
			goto err;
		}

		cbd_cache_info_init(opts->cache_info, opts->n_segs);
	} else {
		/* Load cache information from storage for existing cache */
		__cache_info_load(cbdt, opts->cache_info, opts->cache_id);
	}

	cache_info = opts->cache_info;

	/*
	 * Check if the number of segments required for the specified n_paral
	 * exceeds the available segments in the cache. If so, report an error.
	 */
	if (opts->n_paral * CBD_CACHE_SEGS_EACH_PARAL > cache_info->n_segs) {
		cbdt_err(cbdt, "n_paral %u requires cache size (%llu), more than current (%llu).",
				opts->n_paral, opts->n_paral * CBD_CACHE_SEGS_EACH_PARAL * (u64)CBDT_SEG_SIZE,
				cache_info->n_segs * (u64)CBDT_SEG_SIZE);
		goto err;
	}

	if (cache_info->n_segs > cbdt->transport_info->segment_num) {
		cbdt_err(cbdt, "too large cache_segs: %u, segment_num: %u\n",
				cache_info->n_segs, cbdt->transport_info->segment_num);
		goto err;
	}

	if (cache_info->n_segs > CBD_CACHE_SEGS_MAX) {
		cbdt_err(cbdt, "cache_segs: %u larger than CBD_CACHE_SEGS_MAX: %u\n",
				cache_info->n_segs, CBD_CACHE_SEGS_MAX);
		goto err;
	}

	return 0;

err:
	return -EINVAL;
}

static int cache_tail_init(struct cbd_cache *cache, bool new_cache)
{
	int ret;

	if (new_cache) {
		set_bit(0, cache->seg_map);

		cache->key_head.cache_seg = &cache->segments[0];
		cache->key_head.seg_off = 0;
		cache_pos_copy(&cache->key_tail, &cache->key_head);
		cache_pos_copy(&cache->dirty_tail, &cache->key_head);

		cache_encode_dirty_tail(cache);
		cache_encode_key_tail(cache);
	} else {
		if (cache_decode_key_tail(cache) || cache_decode_dirty_tail(cache)) {
			cbd_cache_err(cache, "Corrupted key tail or dirty tail.\n");
			ret = -EIO;
			goto err;
		}
	}
	return 0;
err:
	return ret;
}

/*
 * cbd_cache_alloc - Allocate and initialize a cache structure
 * @cbdt: Pointer to the transport structure
 * @opts: Pointer to the cache options structure
 *
 * This function allocates and initializes a cache structure based on the provided
 * options. It validates options, allocates memory, and initializes cache segments
 * and keys as specified. It also starts writeback and garbage collection (GC)
 * mechanisms if requested.
 *
 * Returns a pointer to the allocated cache structure on success, or NULL if an
 * error occurs during setup.
 */
struct cbd_cache *cbd_cache_alloc(struct cbd_transport *cbdt,
				  struct cbd_cache_opts *opts)
{
	struct cbd_cache *cache;
	int ret;

	ret = cache_validate(cbdt, opts);
	if (ret)
		return NULL;

	cache = cache_alloc(cbdt, opts->cache_info);
	if (!cache)
		return NULL;

	cache->bdev_file = opts->bdev_file;
	cache->dev_size = opts->dev_size;
	cache->cache_id = opts->cache_id;
	cache->owner = opts->owner;
	cache->state = cbd_cache_state_running;

	ret = cache_segs_init(cache, opts->new_cache);
	if (ret)
		goto free_cache;

	ret = cache_tail_init(cache, opts->new_cache);
	if (ret)
		goto segs_destroy;

	if (opts->init_keys) {
		ret = cache_init_keys(cache, opts->n_paral);
		if (ret)
			goto segs_destroy;
	}

	if (opts->start_writeback) {
		cache->start_writeback = 1;
		ret = cache_writeback_init(cache);
		if (ret)
			goto destroy_keys;
	}

	if (opts->start_gc) {
		cache->start_gc = 1;
		queue_delayed_work(cache->cache_wq, &cache->gc_work, 0);
	}

	return cache;

destroy_keys:
	cache_destroy_keys(cache);
segs_destroy:
	cache_segs_destroy(cache);
free_cache:
	cache_free(cache);

	return NULL;
}

/*
 * cbd_cache_destroy - Clean up and free cache resources
 * @cache: Pointer to the cache structure
 *
 * This function stops all ongoing cache activities, including work queues and
 * writeback. It releases allocated resources for keys and segments, then frees
 * the cache structure.
 */
void cbd_cache_destroy(struct cbd_cache *cache)
{
	cache->state = cbd_cache_state_stopping;

	flush_work(&cache->miss_read_end_work);
	cache_flush(cache);

	if (cache->start_gc) {
		cancel_delayed_work_sync(&cache->gc_work);
		flush_work(&cache->clean_work);
	}

	if (cache->start_writeback)
		cache_writeback_exit(cache);

	if (cache->n_trees)
		cache_destroy_keys(cache);

	cache_segs_destroy(cache);
	cache_free(cache);
}

/*
 * cache_info_write - Write cache information to backend
 * @cache: Pointer to the cache structure
 *
 * This function writes the cache's metadata to the backend. Only the owner
 * backend of the cache is permitted to perform this operation. It asserts
 * that the cache has an owner backend.
 */
void cache_info_write(struct cbd_cache *cache)
{
	struct cbd_backend *backend = cache->owner;

	/* Ensure only owner backend is allowed to write */
	BUG_ON(!backend);

	cbd_backend_info_write(backend);
}

/*
 * __cache_info_load - Load cache information from backend
 * @cbdt: Pointer to the transport structure
 * @cache_info: Pointer to the cache info structure to load into
 * @cache_id: Cache identifier for lookup
 *
 * This internal function reads cache information from the backend,
 * identified by the given cache_id, and copies it into the provided
 * cache_info structure. It’s primarily intended for loading cache metadata
 * from a persistent backend storage on cache initialization.
 */
static void __cache_info_load(struct cbd_transport *cbdt,
			      struct cbd_cache_info *cache_info,
			      u32 cache_id)
{
	struct cbd_backend_info *backend_info;

	backend_info = cbdt_backend_info_read(cbdt, cache_id, NULL);
	memcpy(cache_info, &backend_info->cache_info, sizeof(struct cbd_cache_info));
}

/*
 * cache_info_load - Public interface for loading cache information
 * @cache: Pointer to the cache structure
 *
 * Loads cache metadata by calling the internal function __cache_info_load,
 * passing the transport, cache information structure, and cache ID. This
 * function is designed to reload the cache’s persisted metadata on
 * initialization.
 */
void cache_info_load(struct cbd_cache *cache)
{
	__cache_info_load(cache->cbdt, cache->cache_info, cache->cache_id);
}

/*
 * cbd_cache_seg_detail_show - Display cache segment details
 * @seg_info: Pointer to the segment information structure
 * @buf: Buffer for outputting segment details
 *
 * This function formats and returns information about a cache segment's
 * backend association. Specifically, it outputs the backend ID associated
 * with the cache segment, providing insight into segment allocation and
 * ownership.
 *
 * Returns the number of characters printed into the buffer.
 */
ssize_t cbd_cache_seg_detail_show(struct cbd_segment_info *seg_info, char *buf)
{
	struct cbd_cache_seg_info *cache_info;

	cache_info = (struct cbd_cache_seg_info *)seg_info;

	return sprintf(buf, "backend id: %u\n", cache_info->backend_id);
}
