#define pr_fmt(fmt)	KBUILD_MODNAME " debugfs: " fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/jiffies.h>
#include <linux/list.h>

#include "cbd_internal.h"

static struct dentry *cbd_debugfs_root;
static struct dentry *cbd_debugfs_devices;

static void cbd_debugfs_remove(struct dentry **dp)
{
	debugfs_remove(*dp);
	*dp = NULL;
}


static int dev_attr_release(struct inode *inode, struct file *file)
{
	struct cbd_queue *cbd_q = inode->i_private;
	struct cbd_blkdev *cbd_dev = cbd_q->cbd_blkdev;

	return single_release(inode, file);
}

#define CBD_DEBUGFS_OPEN(NAME)								\
static int cbd_ ## NAME ## _open(struct inode *inode, struct file *file) 		\
{											\
	struct cbd_queue *cbd_q = inode->i_private;					\
	struct cbd_blkdev *cbd_dev = cbd_q->cbd_blkdev;				\
	struct dentry *parent;								\
	int ret = 0;								\
											\
	/* Are we still linked,								\
	 * or has debugfs_remove() already been called? */				\
	parent = file->f_path.dentry->d_parent;						\
	/* not sure if this can happen: */						\
	if (!parent || !parent->d_inode)						\
		goto out;								\
	/* serialize with d_delete() */							\
	inode_lock(d_inode(parent));							\
	/* Make sure the object is still alive */					\
	inode_unlock(d_inode(parent));							\
	if (!ret) {									\
		ret = single_open(file, cbd_ ## NAME ## _show, cbd_q);		\
	}										\
out:											\
	return ret;									\
};

#define CBD_DEBUGFS_RO_FILE(NAME)					\
CBD_DEBUGFS_OPEN(NAME)							\
static const struct file_operations cbd_ ## NAME ## _fops = {		\
	.owner		= THIS_MODULE,					\
	.open		= cbd_ ## NAME ## _open,			\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= dev_attr_release,				\
};

#define CBD_DEBUGFS_FILE(NAME)						\
CBD_DEBUGFS_OPEN(NAME)							\
static const struct file_operations cbd_ ## NAME ## _fops = {		\
	.owner		= THIS_MODULE,					\
	.open		= cbd_ ## NAME ## _open,			\
	.write		= cbd_ ## NAME ## _write,			\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= dev_attr_release,				\
};

#ifdef CBD_REQUEST_STATS
static int cbd_q_req_stats_show(struct seq_file *file, void *ignored)
{
	struct cbd_queue *cbd_q = file->private;
	uint64_t stats_reqs = cbd_q->stats_reqs;
	uint64_t start_to_prepare = cbd_q->start_to_prepare;
	uint64_t start_to_submit = cbd_q->start_to_submit;
	uint64_t start_to_complete = cbd_q->start_to_complete;
	uint64_t start_to_release = cbd_q->start_to_release;
	uint64_t start_to_handle = cbd_q->start_to_handle;
	uint64_t start_to_ack = cbd_q->start_to_ack;

	if (stats_reqs) {
		do_div(start_to_prepare, stats_reqs);
		do_div(start_to_submit, stats_reqs);
		do_div(start_to_complete, stats_reqs);
		do_div(start_to_release, stats_reqs);
		do_div(start_to_handle, stats_reqs);
		do_div(start_to_ack, stats_reqs);
	}

	seq_printf(file,
		   "request stats values are nanoseconds; write an 'r' to reset all to 0\n\n"
		   "requests:		%12llu\n"
		   "start_to_prepare:	%12lld\n"
		   "start_to_submit:	%12lld\n"
		   "start_to_handle:	%12lld\n"
		   "start_to_ack:	%12lld\n"
		   "start_to_complete:	%12lld\n"
		   "start_to_release:	%12lld\n",
		   stats_reqs, start_to_prepare, start_to_submit, start_to_handle, start_to_ack, start_to_complete, start_to_release);
	seq_puts(file, "\n");

	return 0;
}

static ssize_t cbd_q_req_stats_write(struct file *file, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	struct cbd_queue *cbd_q = file_inode(file)->i_private;
	char buffer;

	if (copy_from_user(&buffer, ubuf, 1))
		return -EFAULT;

	if (buffer == 'r' || buffer == 'R') {
		cbd_q->stats_reqs = 0;
		cbd_q->start_to_prepare = ns_to_ktime(0);
		cbd_q->start_to_submit = ns_to_ktime(0);
		cbd_q->start_to_handle = ns_to_ktime(0);
		cbd_q->start_to_ack = ns_to_ktime(0);
		cbd_q->start_to_complete = ns_to_ktime(0);
		cbd_q->start_to_release = ns_to_ktime(0);
	}

	return cnt;
}

CBD_DEBUGFS_FILE(q_req_stats);

#endif /* CBD_REQUEST_STATS */

void cbd_debugfs_add_dev(struct cbd_blkdev *cbd_dev)
{
	int i;
	struct cbd_queue *cbd_q;
	char queue_id_buf[8];

	cbd_dev->dev_debugfs_d = debugfs_create_dir(cbd_dev->name, cbd_debugfs_devices);
	cbd_dev->dev_debugfs_queues_d = debugfs_create_dir("queues", cbd_dev->dev_debugfs_d);

	for (i = 0; i < cbd_dev->num_queues; i++) {
		cbd_q = &cbd_dev->queues[i];
		snprintf(queue_id_buf, sizeof(queue_id_buf), "%u", i);
		cbd_q->q_debugfs_d = debugfs_create_dir(queue_id_buf, cbd_dev->dev_debugfs_queues_d);
#ifdef CBD_REQUEST_STATS
		cbd_q->q_debugfs_req_stats_f = debugfs_create_file("req_stats", 0600,
				cbd_q->q_debugfs_d, cbd_q, &cbd_q_req_stats_fops);
#endif /* CBD_REQUEST_STATS */
	}
}

void cbd_debugfs_remove_dev(struct cbd_blkdev *cbd_dev)
{
	int i;
	struct cbd_queue *cbd_q;

	for (i = 0; i < cbd_dev->num_queues; i++) {
		cbd_q = &cbd_dev->queues[i];
#ifdef CBD_REQUEST_STATS
		cbd_debugfs_remove(&cbd_q->q_debugfs_req_stats_f);
#endif /* CBD_REQUEST_STATS */
		cbd_debugfs_remove(&cbd_q->q_debugfs_d);
	}

	cbd_debugfs_remove(&cbd_dev->dev_debugfs_queues_d);
	cbd_debugfs_remove(&cbd_dev->dev_debugfs_d);
}

void cbd_debugfs_cleanup(void)
{
	cbd_debugfs_remove(&cbd_debugfs_devices);
	cbd_debugfs_remove(&cbd_debugfs_root);
}

void __init cbd_debugfs_init(void)
{
	struct dentry *dentry;

	dentry = debugfs_create_dir("cbd", NULL);
	cbd_debugfs_root = dentry;

	dentry = debugfs_create_dir("devices", cbd_debugfs_root);
	cbd_debugfs_devices = dentry;
}
