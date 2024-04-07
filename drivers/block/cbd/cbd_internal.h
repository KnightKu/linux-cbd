#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/blk-mq.h>
#include <asm/byteorder.h>
#include <asm/types.h>
#include <linux/types.h>
#include <linux/delay.h>
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


/*   cbd_transport_info       hosts      backends         blkdevs                          channel0                          channel1     ...
 * |-----------------|---------------|--------------|---------------|-------------------------------------------------|----------------|------|
 * |                 | host| host|...|              |               | CTRL | COMPR_SIZE | CMDR_SIZE |                 |
 * |                 |               |              |               |         META_SIZE             |    DATA_SIZE    |
 * | CBDT_INFO_SIZE  |               |              |               |                CHANNEL_SIZE                     |
 */

/* cbd channel */
#define CBD_OP_ALIGN_SIZE	sizeof(__le64)
#define CBDC_META_SIZE		(1024 * 4096)
#define CBDC_CMDR_RESERVED	CBD_OP_ALIGN_SIZE
#define CBDC_CMPR_RESERVED	sizeof(struct cbd_ce)

#define CBDC_CTRL_OFF		0
#define CBDC_CTRL_SIZE		4096
#define CBDC_COMPR_OFF		(CBDC_CTRL_OFF + CBDC_CTRL_SIZE)
#define CBDC_COMPR_SIZE		(sizeof(struct cbd_ce) * 1024)
#define CBDC_CMDR_OFF		(CBDC_COMPR_OFF + CBDC_COMPR_SIZE)
#define CBDC_CMDR_SIZE		(CBDC_META_SIZE - CBDC_CMDR_OFF)

#define CBDC_DATA_OFF		(CBDC_CMDR_OFF + CBDC_CMDR_SIZE)
#define CBDC_DATA_SIZE		(16 * 1024 * 1024)

#define CBDC_UPDATE_CMDR_HEAD(head, used, size) smp_store_release(&head, ((head % size) + used) % size)
#define CBDC_UPDATE_CMDR_TAIL(tail, used, size) smp_store_release(&tail, ((tail % size) + used) % size)

#define CBDC_UPDATE_COMPR_HEAD(head, used, size) smp_store_release(&head, ((head % size) + used) % size)
#define CBDC_UPDATE_COMPR_TAIL(tail, used, size) smp_store_release(&tail, ((tail % size) + used) % size)

/* cbd transport */
#define CBD_TRANSPORT_MAGIC		0x9a6c676896C596EFULL
#define CBD_TRANSPORT_VERSION		1

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
#define CBDT_BLKDEV_NUM			16

#define CBDT_CHANNEL_AREA_OFF		(CBDT_BLKDEV_AREA_OFF + (CBDT_BLKDEV_INFO_SIZE * CBDT_BLKDEV_NUM))
#define CBDT_CHANNEL_SIZE		(CBDC_META_SIZE + CBDC_DATA_SIZE)
#define CBDT_CHANNEL_NUM		16

/* debug messages */
#define cbd_err(fmt, ...)						\
	pr_err("cbd: " fmt, ##__VA_ARGS__)
#define cbd_info(fmt, ...)						\
	pr_info("cbd: " fmt, ##__VA_ARGS__)
#define cbd_debug(fmt, ...)						\
	pr_debug("cbd: " fmt, ##__VA_ARGS__)

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

enum cbd_backend_status {
	cbd_backend_status_none	= 0,
	cbd_backend_status_running,
};

struct cbd_backend_info {
	u8	status;
	__le32	host_id;
	__le64	alive_ts;
	__u8	path[CBD_PATH_LEN];
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
	u32 backend_id;
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
		if (backend->backend_id == id) {
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

struct cbd_host_info *cbdt_get_host_info(struct cbd_transport *cbdt, u32 id);
int cbdt_get_empty_host_id(struct cbd_transport *cbdt, u32 *id);
void *cbdt_get_channel_info(struct cbd_transport *cbdt, u32 id);
int cbdt_get_empty_channel_id(struct cbd_transport *cbdt, u32 *id);
void *cbdt_get_blkdev_info(struct cbd_transport *cbdt, u32 id);
int cbdt_get_empty_blkdev_id(struct cbd_transport *cbdt, u32 *id);
void *cbdt_get_backend_info(struct cbd_transport *cbdt, u32 id);
int cbdt_get_empty_backend_id(struct cbd_transport *cbdt, u32 *id);

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
	u32 backend_id;
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
			u32 devid;
			u32 queues;
		} blkdev;
	};
};

int cbd_backend_start(struct cbd_transport *cbdt, u32 backend_id, char *path);
int cbd_backend_stop(struct cbd_transport *cbdt, u32 backend_id);
int cbd_backend_clear(struct cbd_transport *cbdt, u32 backend_id);
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
