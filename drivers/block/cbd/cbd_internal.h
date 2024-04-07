#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/blk-mq.h>
#include <asm/byteorder.h>
#include <asm/types.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/parser.h>
#include <linux/idr.h>
#include <linux/workqueue.h>
#include <linux/uuid.h>
#include <linux/bitfield.h>

#define CBD_REQUEST_STATS 1
//#undef CBD_REQUEST_STATS

#define CBD_TRANSPORT_MAX	1024
#define CBD_PATH_LEN	512
#define CBD_NAME_LEN	32

/* TODO support multi queue */
#define CBD_QUEUES_MAX		1

#define CBD_PART_SHIFT 4
#define CBD_DRV_NAME "cbd"
#define CBD_DEV_NAME_LEN 32


/*   cbd_transport_info       hosts         backends                         channel0                          channel1     ...
 * |-----------------|---------------|--------------|-------------------------------------------------|----------------|------|
 * |                 | host| host|...|              | CTRL | COMPR_SIZE | CMDR_SIZE |                 |
 * |                 |               |              |         META_SIZE             |    DATA_SIZE    |
 * | CBDT_INFO_SIZE  |               |              |                CHANNEL_SIZE                     |
 */

/* cbd channel */
#define ALIGN_SIZE sizeof(__le64)
#define CBDC_META_SIZE (1024 * 4096)
#define CBDC_CMDR_RESERVED ALIGN_SIZE
#define CBDC_CMPR_RESERVED sizeof(struct cbd_ce)
/* Offset of cmd ring is size of sb */

#define CBDC_CTRL_OFF 0
#define CBDC_CTRL_SIZE 4096
#define CBDC_COMPR_OFF (CBDC_CTRL_OFF + CBDC_CTRL_SIZE)
#define CBDC_COMPR_SIZE (sizeof(struct cbd_ce) * 1024)
#define CBDC_CMDR_OFF (CBDC_COMPR_OFF + CBDC_COMPR_SIZE)
#define CBDC_CMDR_SIZE (CBDC_META_SIZE - CBDC_CMDR_OFF)

#define CBDC_DATA_OFF (CBDC_CMDR_OFF + CBDC_CMDR_SIZE)
#define CBDC_DATA_SIZE (16 * 1024 * 1024)

#define CBD_OP_ALIGN_SIZE ALIGN_SIZE

#define CBDC_UPDATE_CMDR_HEAD(head, used, size) smp_store_release(&head, ((head % size) + used) % size)
#define CBDC_UPDATE_CMDR_TAIL(tail, used, size) smp_store_release(&tail, ((tail % size) + used) % size)

#define CBDC_UPDATE_COMPR_HEAD(head, used, size) writel(((head % size) + used) % size, &head)
#define CBDC_UPDATE_COMPR_TAIL(tail, used, size) smp_store_release(&tail, ((tail % size) + used) % size)

/* cbd transport */
#define CBD_TRANSPORT_MAGIC	0x9a6c676896C596EFULL
#define CBD_TRANSPORT_VERSION	1

#define CBDT_INFO_OFF			0
#define CBDT_INFO_SIZE			4096

#define CBDT_HOST_AREA_OFF		(CBDT_INFO_OFF + CBDT_INFO_SIZE)
#define CBDT_HOST_INFO_SIZE		4096
#define CBDT_HOST_NUM			16

#define CBDT_BACKEND_AREA_OFF		(CBDT_HOST_AREA_OFF + (CBDT_HOST_INFO_SIZE * CBDT_HOST_NUM))
#define CBDT_BACKEND_INFO_SIZE		4096
#define CBDT_BACKEND_NUM		16

#define CBDT_BLKDEV_AREA_OFF		(CBDT_BACKEND_AREA_OFF + (CBDT_BACKEND_INFO_SIZE * CBDT_BACKEND_NUM))
#define CBDT_BLKDEV_INFO_SIZE		4096
#define CBDT_BLKDEV_NUM			32

#define CBDT_CHANNEL_AREA_OFF		(CBDT_BLKDEV_AREA_OFF + (CBDT_BLKDEV_INFO_SIZE * CBDT_BLKDEV_NUM))
#define CBDT_CHANNEL_SIZE		(CBDC_META_SIZE + CBDC_DATA_SIZE)
#define CBDT_CHANNEL_NUM		16

static u64 delay = HZ;

/* debug messages */
#define cbd_err(fmt, ...)						\
	pr_err("cbd: " fmt, ##__VA_ARGS__)
#define cbd_info(fmt, ...)						\
	pr_info("cbd: " fmt, ##__VA_ARGS__)
#define cbd_debug(fmt, ...)						\
	pr_debug("cbd: " fmt, ##__VA_ARGS__)

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

#define CBDT_INFO_F_BIGENDIAN		1 << 0

struct cbd_transport_info {
	__le64 magic;
	__le16 version;
	__le16 flags;

	__le64 host_area_off;
	__le32 host_info_size;
	__le32 host_num;

	__le64 backend_area_off;
	__le32 backend_info_size;
	__le32 backend_num;

	__le64 blkdev_area_off;
	__le32 blkdev_info_size;
	__le32 blkdev_num;

	__le64 channel_area_off;
	__le32 channel_size;
	__le32 channel_num;
};


struct cbd_channel_info {
	__le64	alive_ts;

	__le32	blkdev;
	__le32	backend;

	__le32 cmdr_off;
	__le32 cmdr_size;
	__le32 cmd_head;
	__le32 cmd_tail;

	__le32 compr_head;
	__le32 compr_tail;
	__le32 compr_off;
	__le32 compr_size;
};

#define CBDC_BLKDEV_STATE_MASK	GENMASK(31, 28)
#define CBDC_BLKDEV_ID_MASK	GENMASK(15, 0)

enum cbdc_blkdev_state {
	cbdc_blkdev_state_none		= 0,
	cbdc_blkdev_state_running,
	cbdc_blkdev_state_stopped,
};

#define CBDC_BACKEND_STATE_MASK	GENMASK(31, 28)
#define CBDC_BACKEND_ID_MASK	GENMASK(15, 0)

enum cbdc_backend_state {
	cbdc_backend_state_none		= 0,
	cbdc_backend_state_running,
	cbdc_backend_state_stopped,
};


#define CBD_DEVICE(OBJ)					\
static struct cbd_## OBJ ##_device {					\
	struct device dev;				\
	struct cbd_## OBJ ##_info *OBJ##_info;	\
};							\
							\
static struct cbd_## OBJ ##s_device {			\
	struct device OBJ ##s_dev;			\
	struct cbd_## OBJ ##_device OBJ ##_devs[];	\
};

CBD_DEVICE(host);
CBD_DEVICE(backend);
CBD_DEVICE(blkdev);
CBD_DEVICE(channel);

struct cbd_channel {
	struct cbd_queue *cbd_q;
	u32	channel_id;
	struct cbd_channel_deivce *dev;
	struct cbd_channel_info *channel_info;

	void *cmdr;
	void *compr;
	void *data;

	u32			data_size;
	u32			data_head;
	u32			data_tail;

	spinlock_t cmdr_lock;
	spinlock_t compr_lock;
};

enum cbd_host_status {
	cbd_host_status_none	= 0,
	cbd_host_status_running
};

struct cbd_host_info {
	u8	status;
	__le64	alive_ts;
	__u8	hostname[CBD_NAME_LEN];
};

#define CBDB_CHANNEL_NUM		128
#define CBDB_CHANNEL_STATE_MASK		GENMASK(31, 28)
#define CBDB_CHANNEL_ID_MASK		GENMASK(11, 0)

enum cbd_backend_status {
	cbd_backend_status_none	= 0,
	cbd_backend_status_running,
};

struct cbd_backend_info {
	u8	status;
	__le32	host_id;
	__le64	alive_ts;
	__u8	path[CBD_PATH_LEN];
	__le32	channels[CBDB_CHANNEL_NUM];
};

enum cbdb_channel_state {
	cbdb_channel_state_none		= 0,
	cbdb_channel_state_waiting,
	cbdb_channel_state_running,
	cbdb_channel_state_stopping,
	cbdb_channel_state_stopped,
};

struct cbd_backend_handler {
	u32 channel_id;
	struct cbd_backend *cbd_b;
	struct cbd_channel_info *channel_info;

	struct cbd_channel	channel;

	u32			se_to_handle;

	struct delayed_work	handle_work;
	struct list_head	handlers_node;
	struct bio_set		bioset;
	struct workqueue_struct *handle_wq;
	u64			delay_min;
	u64			delay_max;
	u64			delay_cur;

	u32			busy_retry_count;
	u64			busy_retry_interval;

	u32			cpu;
	struct device 		dev;
};

struct cbd_backend {
	u32 bid;
	char path[CBD_PATH_LEN];
	struct cbd_transport *cbdt;
	struct cbd_backend_info *backend_info;
	struct mutex lock;

	struct block_device	*bdev;
	struct bdev_handle	*bdev_handle;

	struct workqueue_struct	*task_wq;  /* workqueue for request work */
	struct delayed_work	state_work;

	struct list_head	node;
	struct list_head	handlers;

	struct cbd_backend_device *backend_device;
};

static inline u8 cbdb_get_channel_state(struct cbd_backend_info *backend_info,
		u32 index)
{
	u32 channel_val;

	channel_val = backend_info->channels[index];

	return FIELD_GET(CBDB_CHANNEL_STATE_MASK, channel_val);
}

static inline void cbdb_set_channel_state(struct cbd_backend_info *backend_info,
		u32 index, u8 channel_state)
{
	u32 channel_val;

	channel_val = backend_info->channels[index];

	channel_val &= ~CBDB_CHANNEL_STATE_MASK;
	channel_val |= FIELD_PREP(CBDB_CHANNEL_STATE_MASK, channel_state);

	backend_info->channels[index] = channel_val;
}

static inline u32 cbdb_get_channel_id(struct cbd_backend_info *backend_info,
		u32 index)
{
	u32 channel_val;

	channel_val = backend_info->channels[index];

	return FIELD_GET(CBDB_CHANNEL_ID_MASK, channel_val);
}

static inline void cbdb_set_channel_id(struct cbd_backend_info *backend_info,
		u32 index, u32 channel_id)
{
	u32 channel_val;

	channel_val = backend_info->channels[index];

	channel_val &= ~CBDB_CHANNEL_ID_MASK;
	channel_val |= FIELD_PREP(CBDB_CHANNEL_ID_MASK, channel_id);

	backend_info->channels[index] = channel_val;
}

#define CBD_BLKDEV_STATE_EMPTY		0
#define CBD_BLKDEV_STATE_RUNNING	1

struct cbd_blkdev_info {
	__u8	state;
	__le64	alive_ts;
	__le32	backend_id;
	__le32	host_id;
	__le32	mapped_id;
};

static struct cbd_blkdev {
	u32			blkdev_id;
	u32			backend_id;
	int			mapped_id;		/* blkdev unique id */

	int			major;		/* blkdev assigned major */
	int			minor;
	struct gendisk		*disk;		/* blkdev's gendisk and rq */
	struct work_struct	work;		/* lifecycle work such add disk */

	char			name[CBD_DEV_NAME_LEN]; /* blkdev name, e.g. cbd3 */

	spinlock_t		lock;		/* open_count */
	struct list_head	node;	/* cbd_blkdev_list */
	struct mutex		state_lock;

	/* Block layer tags. */
	struct blk_mq_tag_set	tag_set;

	unsigned long		open_count;	/* protected by lock */

	uint32_t		num_queues;
	struct cbd_queue	*queues;

	void			*verify_data;
	u64			dev_size;
	u64			dev_features;
	u32			io_timeout;

	u8			status;
	u32			status_flags;
	struct kref		kref;

	void			*cmdr;
	void			*compr;
	spinlock_t		cmdr_lock;
	spinlock_t		compr_lock;
	void			*data;

	struct cbd_blkdev_device *blkdev_dev;
	struct cbd_blkdev_info *blkdev_info;

	struct cbd_transport *cbd_r;

	struct dentry		*dev_debugfs_d;
	struct dentry		*dev_debugfs_queues_d;
};

struct cbd_host {
	u32	host_id;
	struct cbd_transport *transport;
	struct cbd_host_device *dev;
	struct cbd_host_info *host_info;
	struct delayed_work	hb_work; /* heartbeat work */
};

struct cbd_transport {
	u16	id;
	struct device device;
	struct mutex lock;

	struct cbd_transport_info *transport_info;

	struct list_head backends;
	struct list_head devices;

	struct cbd_hosts_device *cbd_hosts_dev;
	struct cbd_channels_device *cbd_channels_dev;
	struct cbd_backends_device *cbd_backends_dev;
	struct cbd_blkdevs_device *cbd_blkdevs_dev;

	struct dax_device *dax_dev;
	struct bdev_handle   *bdev_handle;

	struct cbd_host *host;
};

static inline void cbdt_add_backend(struct cbd_transport *cbdt, struct cbd_backend *cbdb)
{
	mutex_lock(&cbdt->lock);
	list_add(&cbdb->node, &cbdt->backends);
	mutex_unlock(&cbdt->lock);
}

static inline struct cbd_backend *cbdt_fetch_backend(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_backend *backend;

	mutex_lock(&cbdt->lock);
	list_for_each_entry(backend, &cbdt->backends, node) {
		if (backend->bid == id) {
			list_del(&backend->node);
			goto out;
		}
	}
	backend = NULL;
out:
	mutex_unlock(&cbdt->lock);
	return backend;
}

static inline struct cbd_blkdev *cbdt_get_device(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_blkdev *dev;

	mutex_lock(&cbdt->lock);
	list_for_each_entry(dev, &cbdt->devices, node) {
		if (dev->blkdev_id == id) {
			goto out;
		}
	}
	dev = NULL;
out:
	mutex_unlock(&cbdt->lock);
	return dev;
}



#define CBD_GETTER_AND_SETTER(OBJ, VAR, KEY, MASK)					\
static inline u32 cbd_ ## OBJ ## _get_## VAR ##_## KEY (					\
		struct cbd_## OBJ ##_info *info)			\
{											\
	u32 val;									\
											\
	val = info->VAR;					\
											\
	return FIELD_GET(MASK, val);							\
}											\
										\
static inline void cbd_ ## OBJ ## _set_ ## VAR ##_## KEY (					\
		struct cbd_## OBJ ##_info *info,	\
		u32 v)						\
{										\
	u32 val;								\
										\
	val = info->VAR;						\
										\
	val &= ~MASK;								\
	val |= FIELD_PREP(MASK, v);						\
										\
	info->VAR = val;						\
}										\

CBD_GETTER_AND_SETTER(channel, blkdev, state, CBDC_BLKDEV_STATE_MASK);
CBD_GETTER_AND_SETTER(channel, blkdev, id, CBDC_BLKDEV_ID_MASK);
CBD_GETTER_AND_SETTER(channel, backend, state, CBDC_BACKEND_STATE_MASK);
CBD_GETTER_AND_SETTER(channel, backend, id, CBDC_BACKEND_ID_MASK);


static inline void *__get_channel_info(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	void *start = cbdt->transport_info;

	return (start + info->channel_area_off + (info->channel_size * id));
}

static inline void *cbdt_get_channel_info(struct cbd_transport *cbdt, u32 id)
{
	void *addr;

	mutex_lock(&cbdt->lock);
	addr = __get_channel_info(cbdt, id);
	mutex_unlock(&cbdt->lock);

	return addr;
}

static inline int cbdt_get_empty_channel_id(struct cbd_transport *cbdt, u32 *id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	struct cbd_channel_info *channel_info;
	int ret = 0;
	int i;

	pr_err("info: %p", info);
	mutex_lock(&cbdt->lock);
	for (i = 0; i < info->channel_num; i++) {
		channel_info = __get_channel_info(cbdt, i);
		pr_err("channel_info: %p", channel_info);
		if (cbd_channel_get_blkdev_state(channel_info) != cbdc_blkdev_state_running &&
				cbd_channel_get_backend_state(channel_info) != cbdc_backend_state_running) {
			*id = i;
			goto out;
		}
	}

	ret = -ENOENT;
out:
	mutex_unlock(&cbdt->lock);

	return ret;
}

static inline void *__get_blkdev_info(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	void *start = cbdt->transport_info;

	return start + info->blkdev_area_off + (info->blkdev_info_size * id);
}

static inline void *cbdt_get_blkdev_info(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	void *start = cbdt->transport_info;
	void *addr;

	mutex_lock(&cbdt->lock);
	addr = __get_blkdev_info(cbdt, id);
	mutex_unlock(&cbdt->lock);

	return addr;
}

static inline int cbdt_get_empty_blkdev_id(struct cbd_transport *cbdt, u32 *id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	struct cbd_blkdev_info *blkdev_info;
	int ret = 0;
	int i;

	mutex_lock(&cbdt->lock);
	for (i = 0; i < info->blkdev_num; i++) {
		blkdev_info = __get_blkdev_info(cbdt, i);
		pr_err("inf: %p, i: %u", blkdev_info, i);
		if (blkdev_info->state == CBD_BLKDEV_STATE_EMPTY) {
			*id = i;
			goto out;
		}
	}

	ret = -ENOENT;
out:
	mutex_unlock(&cbdt->lock);

	return ret;
}

static inline void *__get_backend_info(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	void *start = cbdt->transport_info;

	return start + info->backend_area_off + (info->backend_info_size * id);
}

static inline void *cbdt_get_backend_info(struct cbd_transport *cbdt, u32 id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	void *start = cbdt->transport_info;
	void *addr;

	mutex_lock(&cbdt->lock);
	addr = __get_backend_info(cbdt, id);
	mutex_unlock(&cbdt->lock);

	return addr;
}

static inline int cbdt_get_empty_bid(struct cbd_transport *cbdt, u32 *id)
{
	struct cbd_transport_info *info = cbdt->transport_info;
	struct cbd_backend_info *backend_info;
	int ret = 0;
	int i;

	mutex_lock(&cbdt->lock);
	for (i = 0; i < info->backend_num; i++) {
		backend_info = __get_backend_info(cbdt, i);
		if (backend_info->status == cbd_backend_status_none) {
			*id = i;
			goto out;
		}
	}

	ret = -ENOENT;
out:
	mutex_unlock(&cbdt->lock);

	return ret;
}


struct cbd_host_info *cbdt_get_host_info(struct cbd_transport *cbdt, u32 id);
int cbdt_get_empty_hid(struct cbd_transport *cbdt, u32 *id);

/*
 * Portions Copyright (c) 1996-2001, PostgreSQL Global Development Group (Any
 * use permitted, subject to terms of PostgreSQL license; see.)

 * If we have a 64-bit integer type, then a 64-bit CRC looks just like the
 * usual sort of implementation. (See Ross Williams' excellent introduction
 * A PAINLESS GUIDE TO CRC ERROR DETECTION ALGORITHMS, available from
 * ftp://ftp.rocksoft.com/papers/crc_v3.txt or several other net sites.)
 * If we have no working 64-bit type, then fake it with two 32-bit registers.
 *
 * The present implementation is a normal (not "reflected", in Williams'
 * terms) 64-bit CRC, using initial all-ones register contents and a final
 * bit inversion. The chosen polynomial is borrowed from the DLT1 spec
 * (ECMA-182, available from http://www.ecma.ch/ecma1/STAND/ECMA-182.HTM):
 *
 * x^64 + x^62 + x^57 + x^55 + x^54 + x^53 + x^52 + x^47 + x^46 + x^45 +
 * x^40 + x^39 + x^38 + x^37 + x^35 + x^33 + x^32 + x^31 + x^29 + x^27 +
 * x^24 + x^23 + x^22 + x^21 + x^19 + x^17 + x^13 + x^12 + x^10 + x^9 +
 * x^7 + x^4 + x + 1
*/

static const uint64_t crc_table[256] = {
	0x0000000000000000ULL, 0x42F0E1EBA9EA3693ULL, 0x85E1C3D753D46D26ULL,
	0xC711223CFA3E5BB5ULL, 0x493366450E42ECDFULL, 0x0BC387AEA7A8DA4CULL,
	0xCCD2A5925D9681F9ULL, 0x8E224479F47CB76AULL, 0x9266CC8A1C85D9BEULL,
	0xD0962D61B56FEF2DULL, 0x17870F5D4F51B498ULL, 0x5577EEB6E6BB820BULL,
	0xDB55AACF12C73561ULL, 0x99A54B24BB2D03F2ULL, 0x5EB4691841135847ULL,
	0x1C4488F3E8F96ED4ULL, 0x663D78FF90E185EFULL, 0x24CD9914390BB37CULL,
	0xE3DCBB28C335E8C9ULL, 0xA12C5AC36ADFDE5AULL, 0x2F0E1EBA9EA36930ULL,
	0x6DFEFF5137495FA3ULL, 0xAAEFDD6DCD770416ULL, 0xE81F3C86649D3285ULL,
	0xF45BB4758C645C51ULL, 0xB6AB559E258E6AC2ULL, 0x71BA77A2DFB03177ULL,
	0x334A9649765A07E4ULL, 0xBD68D2308226B08EULL, 0xFF9833DB2BCC861DULL,
	0x388911E7D1F2DDA8ULL, 0x7A79F00C7818EB3BULL, 0xCC7AF1FF21C30BDEULL,
	0x8E8A101488293D4DULL, 0x499B3228721766F8ULL, 0x0B6BD3C3DBFD506BULL,
	0x854997BA2F81E701ULL, 0xC7B97651866BD192ULL, 0x00A8546D7C558A27ULL,
	0x4258B586D5BFBCB4ULL, 0x5E1C3D753D46D260ULL, 0x1CECDC9E94ACE4F3ULL,
	0xDBFDFEA26E92BF46ULL, 0x990D1F49C77889D5ULL, 0x172F5B3033043EBFULL,
	0x55DFBADB9AEE082CULL, 0x92CE98E760D05399ULL, 0xD03E790CC93A650AULL,
	0xAA478900B1228E31ULL, 0xE8B768EB18C8B8A2ULL, 0x2FA64AD7E2F6E317ULL,
	0x6D56AB3C4B1CD584ULL, 0xE374EF45BF6062EEULL, 0xA1840EAE168A547DULL,
	0x66952C92ECB40FC8ULL, 0x2465CD79455E395BULL, 0x3821458AADA7578FULL,
	0x7AD1A461044D611CULL, 0xBDC0865DFE733AA9ULL, 0xFF3067B657990C3AULL,
	0x711223CFA3E5BB50ULL, 0x33E2C2240A0F8DC3ULL, 0xF4F3E018F031D676ULL,
	0xB60301F359DBE0E5ULL, 0xDA050215EA6C212FULL, 0x98F5E3FE438617BCULL,
	0x5FE4C1C2B9B84C09ULL, 0x1D14202910527A9AULL, 0x93366450E42ECDF0ULL,
	0xD1C685BB4DC4FB63ULL, 0x16D7A787B7FAA0D6ULL, 0x5427466C1E109645ULL,
	0x4863CE9FF6E9F891ULL, 0x0A932F745F03CE02ULL, 0xCD820D48A53D95B7ULL,
	0x8F72ECA30CD7A324ULL, 0x0150A8DAF8AB144EULL, 0x43A04931514122DDULL,
	0x84B16B0DAB7F7968ULL, 0xC6418AE602954FFBULL, 0xBC387AEA7A8DA4C0ULL,
	0xFEC89B01D3679253ULL, 0x39D9B93D2959C9E6ULL, 0x7B2958D680B3FF75ULL,
	0xF50B1CAF74CF481FULL, 0xB7FBFD44DD257E8CULL, 0x70EADF78271B2539ULL,
	0x321A3E938EF113AAULL, 0x2E5EB66066087D7EULL, 0x6CAE578BCFE24BEDULL,
	0xABBF75B735DC1058ULL, 0xE94F945C9C3626CBULL, 0x676DD025684A91A1ULL,
	0x259D31CEC1A0A732ULL, 0xE28C13F23B9EFC87ULL, 0xA07CF2199274CA14ULL,
	0x167FF3EACBAF2AF1ULL, 0x548F120162451C62ULL, 0x939E303D987B47D7ULL,
	0xD16ED1D631917144ULL, 0x5F4C95AFC5EDC62EULL, 0x1DBC74446C07F0BDULL,
	0xDAAD56789639AB08ULL, 0x985DB7933FD39D9BULL, 0x84193F60D72AF34FULL,
	0xC6E9DE8B7EC0C5DCULL, 0x01F8FCB784FE9E69ULL, 0x43081D5C2D14A8FAULL,
	0xCD2A5925D9681F90ULL, 0x8FDAB8CE70822903ULL, 0x48CB9AF28ABC72B6ULL,
	0x0A3B7B1923564425ULL, 0x70428B155B4EAF1EULL, 0x32B26AFEF2A4998DULL,
	0xF5A348C2089AC238ULL, 0xB753A929A170F4ABULL, 0x3971ED50550C43C1ULL,
	0x7B810CBBFCE67552ULL, 0xBC902E8706D82EE7ULL, 0xFE60CF6CAF321874ULL,
	0xE224479F47CB76A0ULL, 0xA0D4A674EE214033ULL, 0x67C58448141F1B86ULL,
	0x253565A3BDF52D15ULL, 0xAB1721DA49899A7FULL, 0xE9E7C031E063ACECULL,
	0x2EF6E20D1A5DF759ULL, 0x6C0603E6B3B7C1CAULL, 0xF6FAE5C07D3274CDULL,
	0xB40A042BD4D8425EULL, 0x731B26172EE619EBULL, 0x31EBC7FC870C2F78ULL,
	0xBFC9838573709812ULL, 0xFD39626EDA9AAE81ULL, 0x3A28405220A4F534ULL,
	0x78D8A1B9894EC3A7ULL, 0x649C294A61B7AD73ULL, 0x266CC8A1C85D9BE0ULL,
	0xE17DEA9D3263C055ULL, 0xA38D0B769B89F6C6ULL, 0x2DAF4F0F6FF541ACULL,
	0x6F5FAEE4C61F773FULL, 0xA84E8CD83C212C8AULL, 0xEABE6D3395CB1A19ULL,
	0x90C79D3FEDD3F122ULL, 0xD2377CD44439C7B1ULL, 0x15265EE8BE079C04ULL,
	0x57D6BF0317EDAA97ULL, 0xD9F4FB7AE3911DFDULL, 0x9B041A914A7B2B6EULL,
	0x5C1538ADB04570DBULL, 0x1EE5D94619AF4648ULL, 0x02A151B5F156289CULL,
	0x4051B05E58BC1E0FULL, 0x87409262A28245BAULL, 0xC5B073890B687329ULL,
	0x4B9237F0FF14C443ULL, 0x0962D61B56FEF2D0ULL, 0xCE73F427ACC0A965ULL,
	0x8C8315CC052A9FF6ULL, 0x3A80143F5CF17F13ULL, 0x7870F5D4F51B4980ULL,
	0xBF61D7E80F251235ULL, 0xFD913603A6CF24A6ULL, 0x73B3727A52B393CCULL,
	0x31439391FB59A55FULL, 0xF652B1AD0167FEEAULL, 0xB4A25046A88DC879ULL,
	0xA8E6D8B54074A6ADULL, 0xEA16395EE99E903EULL, 0x2D071B6213A0CB8BULL,
	0x6FF7FA89BA4AFD18ULL, 0xE1D5BEF04E364A72ULL, 0xA3255F1BE7DC7CE1ULL,
	0x64347D271DE22754ULL, 0x26C49CCCB40811C7ULL, 0x5CBD6CC0CC10FAFCULL,
	0x1E4D8D2B65FACC6FULL, 0xD95CAF179FC497DAULL, 0x9BAC4EFC362EA149ULL,
	0x158E0A85C2521623ULL, 0x577EEB6E6BB820B0ULL, 0x906FC95291867B05ULL,
	0xD29F28B9386C4D96ULL, 0xCEDBA04AD0952342ULL, 0x8C2B41A1797F15D1ULL,
	0x4B3A639D83414E64ULL, 0x09CA82762AAB78F7ULL, 0x87E8C60FDED7CF9DULL,
	0xC51827E4773DF90EULL, 0x020905D88D03A2BBULL, 0x40F9E43324E99428ULL,
	0x2CFFE7D5975E55E2ULL, 0x6E0F063E3EB46371ULL, 0xA91E2402C48A38C4ULL,
	0xEBEEC5E96D600E57ULL, 0x65CC8190991CB93DULL, 0x273C607B30F68FAEULL,
	0xE02D4247CAC8D41BULL, 0xA2DDA3AC6322E288ULL, 0xBE992B5F8BDB8C5CULL,
	0xFC69CAB42231BACFULL, 0x3B78E888D80FE17AULL, 0x7988096371E5D7E9ULL,
	0xF7AA4D1A85996083ULL, 0xB55AACF12C735610ULL, 0x724B8ECDD64D0DA5ULL,
	0x30BB6F267FA73B36ULL, 0x4AC29F2A07BFD00DULL, 0x08327EC1AE55E69EULL,
	0xCF235CFD546BBD2BULL, 0x8DD3BD16FD818BB8ULL, 0x03F1F96F09FD3CD2ULL,
	0x41011884A0170A41ULL, 0x86103AB85A2951F4ULL, 0xC4E0DB53F3C36767ULL,
	0xD8A453A01B3A09B3ULL, 0x9A54B24BB2D03F20ULL, 0x5D45907748EE6495ULL,
	0x1FB5719CE1045206ULL, 0x919735E51578E56CULL, 0xD367D40EBC92D3FFULL,
	0x1476F63246AC884AULL, 0x568617D9EF46BED9ULL, 0xE085162AB69D5E3CULL,
	0xA275F7C11F7768AFULL, 0x6564D5FDE549331AULL, 0x279434164CA30589ULL,
	0xA9B6706FB8DFB2E3ULL, 0xEB46918411358470ULL, 0x2C57B3B8EB0BDFC5ULL,
	0x6EA7525342E1E956ULL, 0x72E3DAA0AA188782ULL, 0x30133B4B03F2B111ULL,
	0xF7021977F9CCEAA4ULL, 0xB5F2F89C5026DC37ULL, 0x3BD0BCE5A45A6B5DULL,
	0x79205D0E0DB05DCEULL, 0xBE317F32F78E067BULL, 0xFCC19ED95E6430E8ULL,
	0x86B86ED5267CDBD3ULL, 0xC4488F3E8F96ED40ULL, 0x0359AD0275A8B6F5ULL,
	0x41A94CE9DC428066ULL, 0xCF8B0890283E370CULL, 0x8D7BE97B81D4019FULL,
	0x4A6ACB477BEA5A2AULL, 0x089A2AACD2006CB9ULL, 0x14DEA25F3AF9026DULL,
	0x562E43B4931334FEULL, 0x913F6188692D6F4BULL, 0xD3CF8063C0C759D8ULL,
	0x5DEDC41A34BBEEB2ULL, 0x1F1D25F19D51D821ULL, 0xD80C07CD676F8394ULL,
	0x9AFCE626CE85B507ULL
};

static inline uint64_t crc64(const void *_data, size_t len)
{
	uint64_t crc = 0xFFFFFFFFFFFFFFFFULL;
	const unsigned char *data = _data;

	while (len--) {
		int i = ((int) (crc >> 56) ^ *data++) & 0xFF;
		crc = crc_table[i] ^ (crc << 8);
	}

	return crc ^ 0xFFFFFFFFFFFFFFFFULL;
}

enum cbd_op {
	CBD_OP_PAD = 0,
	CBD_OP_WRITE,
	CBD_OP_READ,
	CBD_OP_DISCARD,
	CBD_OP_WRITE_ZEROS,
	CBD_OP_FLUSH,
};

struct cbd_se_hdr {
	__le32 len_op;
	__le32 flags;

};

struct cbd_se {
	struct cbd_se_hdr	header;
	__le64			priv_data;	// pointer to cbd_request

	__le64			offset;
	__le32			len;

	__le32			data_off;
	__le32			data_len;
};


struct cbd_ce {
	__le64		priv_data;	// copied from submit entry
	__le32		result;
	__le32		flags;
};


struct cbd_request {
	struct cbd_queue	*cbd_q;

	struct cbd_se		*se;
	struct cbd_ce		*ce;
	struct request		*req;

	enum cbd_op		op;
	u64			req_tid;
	struct list_head	inflight_reqs_node;
	uint32_t		pi_cnt;

	u32			data_off;
	u32			data_len;

	struct work_struct	work;

#ifdef	CBD_REQUEST_STATS
	ktime_t			start_kt;

	ktime_t			start_to_prepare;
	ktime_t			start_to_submit;

	ktime_t			start_to_handle;
	ktime_t			start_to_ack;

	ktime_t			start_to_complete;
	ktime_t			start_to_release;
#endif
};

#define CBD_OP_MASK 0xff
#define CBD_OP_SHIFT 8

static inline enum cbd_op cbd_se_hdr_get_op(__le32 len_op)
{
       return (enum cbd_op)(len_op & CBD_OP_MASK);
}

static inline void cbd_se_hdr_set_op(__le32 *len_op, enum cbd_op op)
{
       *len_op &= ~CBD_OP_MASK;
       *len_op |= (op & CBD_OP_MASK);
}

static inline __le32 cbd_se_hdr_get_len(__le32 len_op)
{
	return len_op >> CBD_OP_SHIFT;
}

static inline void cbd_se_hdr_set_len(__le32 *len_op, __le32 len)
{
	*len_op &= CBD_OP_MASK;
	*len_op |= (len << CBD_OP_SHIFT);
}

#define CBD_SE_HDR_DONE	1

static inline bool cbd_se_hdr_flags_test(struct cbd_se *se, __le32 bit)
{
	return (se->header.flags & bit);
}

static inline void cbd_se_hdr_flags_set(struct cbd_se *se, __le32 bit)
{
	se->header.flags |= bit;
}

struct cbd_queue {
	struct cbd_blkdev	*cbd_blkdev;

	int			inited;

	int			index;
	struct list_head	inflight_reqs;
	spinlock_t		inflight_reqs_lock;
	u64			req_tid;

	u32			*released_extents;

	u32			channel_id;
	struct cbd_channel_info		*channel_info;
	struct cbd_channel		channel;
	struct workqueue_struct	*task_wq;  /* workqueue for request work */

	u32			data_pages;
	u32			data_pages_allocated;
	u32			data_pages_reserved;
	uint32_t		max_blocks;
	size_t			mmap_pages;

	struct mutex 		state_lock;
	unsigned long		flags;
	atomic_t		status;
	int			cpu;

	struct inode		*inode;
	struct delayed_work	complete_work;
	u64			delay_min;
	u64			delay_max;
	u64			delay_cur;

	u32			busy_retry_count;
	u64			busy_retry_interval;

	cpumask_t		cpumask;
	pid_t			backend_pid;
	struct blk_mq_hw_ctx	*mq_hctx;

	struct device		dev;

	struct dentry		*q_debugfs_d;
#ifdef	CBD_REQUEST_STATS
	struct dentry		*q_debugfs_req_stats_f;

	uint64_t		stats_reqs;

	ktime_t			start_to_prepare;
	ktime_t			start_to_submit;

	ktime_t			start_to_handle;
	ktime_t			start_to_ack;

	ktime_t			start_to_complete;
	ktime_t			start_to_release;
#endif /* CBD_REQUEST_STATS */
};

static inline struct cbd_se *get_submit_entry(struct cbd_queue *cbd_q)
{
	struct cbd_se *se;

	//cbd_blk_err(cbd_q->cbd_blkdev, "get submit entry: %u", cbd_q->channel_info->cmd_head);
	se = (struct cbd_se *)(cbd_q->channel.cmdr + cbd_q->channel_info->cmd_head);

	return se;
}

static inline struct cbd_se *get_oldest_se(struct cbd_queue *cbd_q)
{
	if (cbd_q->channel_info->cmd_tail == cbd_q->channel_info->cmd_head)
		return NULL;

	cbd_blk_debug(cbd_q->cbd_blkdev, "get tail se: %u", cbd_q->channel_info->cmd_tail);
	return (struct cbd_se *)(cbd_q->channel.cmdr + cbd_q->channel_info->cmd_tail);
}

static inline struct cbd_ce *get_complete_entry(struct cbd_queue *cbd_q)
{
	if (cbd_q->channel_info->compr_tail == cbd_q->channel_info->compr_head)
		return NULL;

	return (struct cbd_ce *)(cbd_q->channel.compr + cbd_q->channel_info->compr_tail);
}

static inline struct cbd_se *get_se_head(struct cbd_backend_handler *handler)
{
	return (struct cbd_se *)(handler->channel.cmdr + handler->channel_info->cmd_head);
}

static inline struct cbd_se *get_se_to_handle(struct cbd_backend_handler *handler)
{
	return (struct cbd_se *)(handler->channel.cmdr + handler->se_to_handle);
}

static inline struct cbd_ce *
get_compr_head(struct cbd_backend_handler *handler)
{
	return (struct cbd_ce *)(handler->channel.compr + handler->channel_info->compr_head);
}
int cbd_sysfs_init(void);
void cbd_sysfs_exit(void);

extern struct bus_type cbd_bus_type;
extern struct device cbd_root_dev;
extern struct device_type cbd_transport_type;
extern struct device_type cbd_host_type;

int cbd_blkdev_init(void);
void cbd_blkdev_exit(void);

struct cbd_adm_options {
	u16 op;
	u16 force:1;
	u32 bid;
	union {
		struct host_options {
			u32 hid;
			char hostname[CBD_NAME_LEN];
		} host;
		struct backend_options {
			char path[CBD_PATH_LEN];
		} backend;
		struct channel_options {
			u32 cid;
		} channel;
		struct blkdev_options {
			u32 did;
			u32 queues;
		} blkdev;
	};
};

int cbd_transport_format(struct cbd_transport *cbdt, struct cbd_adm_options *opts);
ssize_t cbd_transport_info(struct cbd_transport *cbdt, char *buf);
int cbdt_validate(struct cbd_transport *cbdt);

int cbd_backend_start(struct cbd_transport *cbdt, struct cbd_adm_options *opts);
int cbd_backend_stop(struct cbd_transport *cbdt, struct cbd_adm_options *opts);
int cbd_backend_clear(struct cbd_transport *cbdt, struct cbd_adm_options *opts);
int cbd_backends_init(struct cbd_transport *cbdt);
int cbd_backends_exit(struct cbd_transport *cbdt);

int cbd_blkdev_start(struct cbd_transport *cbdt, struct cbd_adm_options *opts);
int cbd_blkdev_stop(struct cbd_transport *cbdt, struct cbd_adm_options *opts);
int cbd_blkdevs_init(struct cbd_transport *cbdt);
int cbd_blkdevs_exit(struct cbd_transport *cbdt);

int cbd_host_register(struct cbd_transport *cbdt, struct cbd_adm_options *opts);
int cbd_host_unregister(struct cbd_transport *cbdt, struct cbd_adm_options *opts);
int cbd_hosts_init(struct cbd_transport *cbdt);
int cbd_hosts_exit(struct cbd_transport *cbdt);

int cbd_channels_init(struct cbd_transport *cbdt);
int cbd_channels_exit(struct cbd_transport *cbdt);

extern uuid_t cbd_uuid;
extern struct workqueue_struct	*cbd_wq;

#define cbd_setup_device(DEV, PARENT, TYPE, fmt, ...)		\
do {								\
	device_initialize(DEV);					\
	device_set_pm_not_required(DEV);			\
	dev_set_name(DEV, fmt, ##__VA_ARGS__);			\
	DEV->parent = PARENT;					\
	DEV->type = TYPE;					\
								\
	ret = device_add(DEV);					\
} while (0)

int cbd_debugfs_init(void);
void cbd_debugfs_cleanup(void);

void cbd_debugfs_add_dev(struct cbd_blkdev *cbd_dev);
void cbd_debugfs_remove_dev(struct cbd_blkdev *cbd_dev);

/* request stats */
#ifdef CBD_REQUEST_STATS
#define cbd_req_stats_ktime_get(V) V = ktime_get() 
#define cbd_req_stats_ktime_aggregate(T, D) T = ktime_add(T, D)
#define cbd_req_stats_ktime_delta(V, ST) V = ktime_sub(ktime_get(), ST)
#else
#define cbd_req_stats_ktime_get(V)
#define cbd_req_stats_ktime_aggregate(T, D)
#define cbd_req_stats_ktime_delta(V, ST)
#endif /* CBD_REQUEST_STATS */

void cbdc_copy_from_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio);
void cbdc_copy_to_bio(struct cbd_channel *channel,
		u32 data_off, u32 data_len, struct bio *bio, void *verify_data);

struct cbdt_register_options {
	char hostname[CBD_NAME_LEN];
	char path[CBD_PATH_LEN];
	u16 force:1;
	u16 unused:15;
};

int cbdt_register(struct cbdt_register_options *opts);
int cbdt_unregister(u32 transport_id);
