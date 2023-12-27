#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/parser.h>

#include "cxlv.h"

enum {
	CXLV_CREATE_OPT_ERR		= 0,
	CXLV_CREATE_OPT_CXLTYPE,
	CXLV_CREATE_OPT_PMEM,
	CXLV_CREATE_OPT_MEMSTART,
	CXLV_CREATE_OPT_MEMSIZE,
};

static const match_table_t create_opt_tokens = {
	{ CXLV_CREATE_OPT_CXLTYPE,	"cxltype=%u"	},
	{ CXLV_CREATE_OPT_PMEM,		"pmem=%u"	},
	{ CXLV_CREATE_OPT_MEMSTART,	"memstart=%s"	},
	{ CXLV_CREATE_OPT_MEMSIZE,	"memsize=%s"	},
	{ CXLV_CREATE_OPT_ERR,		NULL		}
};

static int parse_create_options(char *buf,
		struct cxlv_dev_options *opts)
{
	substring_t args[MAX_OPT_ARGS];
	char *o, *p;
	int token, ret = 0;
	u64 token64;

	o = buf;

	while ((p = strsep(&o, ",\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, create_opt_tokens, args);
		switch (token) {
		case CXLV_CREATE_OPT_PMEM:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}
			opts->pmem = token;
			break;
		case CXLV_CREATE_OPT_CXLTYPE:
			/* Only support type3 cxl device currently */
			if (match_uint(args, &token) || token != 3) {
				ret = -EINVAL;
				goto out;
			}

			opts->cxltype = token;
			break;
		case CXLV_CREATE_OPT_MEMSTART:
			if (match_u64(args, &token64)) {
				ret = -EINVAL;
				goto out;
			}
			opts->memstart = token64;
			break;
		case CXLV_CREATE_OPT_MEMSIZE:
			if (match_u64(args, &token64)) {
				ret = -EINVAL;
				goto out;
			}
			opts->memsize = token64;;
			break;
		default:
			pr_warn("unknown parameter or missing value '%s'\n", p);
			ret = -EINVAL;
			goto out;
		}
	}

out:
	return ret;
}


static struct dentry *cxlv_debugfs_root;
static struct dentry *create_f;
static struct dentry *remove_f;

static void cxlv_debugfs_remove(struct dentry **dp)
{
	debugfs_remove(*dp);
	*dp = NULL;
}

#define CXLV_DEBUGFS_WO_FILE(NAME)					\
static const struct file_operations cxlv_ ## NAME ## _fops = {		\
	.owner		= THIS_MODULE,					\
	.open		= simple_open,					\
	.write		= cxlv_ ## NAME ## _write,                      \
	.llseek		= seq_lseek,					\
};

#define CXLV_DEBUGFS_FILE(NAME)						\
static const struct file_operations cxlv_ ## NAME ## _fops = {		\
	.owner		= THIS_MODULE,					\
	.open		= simple_open,					\
	.write		= cxlv_ ## NAME ## _write,			\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
};

static ssize_t cxlv_debugfs_create_write(struct file *file, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	int ret;
	char *buf;
	struct cxlv_dev_options *opts;

	opts = kzalloc(sizeof(struct cxlv_dev_options), GFP_KERNEL);
	if (!opts) {
		pr_err("failed to alloc cxlv_dev_options.");
		return -1;
	}

	buf = memdup_user(ubuf, cnt);
	if (IS_ERR(buf)) {
		pr_err("failed to dup buf: %d", (int)PTR_ERR(buf));
		return PTR_ERR(buf);
	}

	ret = parse_create_options(buf, opts);
	if (ret) {
		kfree(buf);
		return ret;
	}
	kfree(buf);

	ret = cxlv_create_dev(opts);
	if (ret) {
		pr_err("failed to create device: %d", ret);
		return -EINVAL;
	}

	return cnt;
}

CXLV_DEBUGFS_WO_FILE(debugfs_create);

enum {
	CXLV_REMOVE_OPT_ERR		= 0,
	CXLV_REMOVE_OPT_CXLV_ID,
};

static const match_table_t remove_opt_tokens = {
	{ CXLV_REMOVE_OPT_CXLV_ID,	"cxlv_dev_id=%u"	},
	{ CXLV_REMOVE_OPT_ERR,		NULL		}
};

static int parse_remove_options(char *buf, u32 *cxlv_dev_id)
{
	substring_t args[MAX_OPT_ARGS];
	char *o, *p;
	int token, ret = 0;

	o = buf;

	while ((p = strsep(&o, ",\n")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, remove_opt_tokens, args);
		switch (token) {
		case CXLV_REMOVE_OPT_CXLV_ID:
			if (match_uint(args, &token)) {
				ret = -EINVAL;
				goto out;
			}

			*cxlv_dev_id = token;
			break;
		default:
			pr_warn("unknown parameter or missing value '%s'\n", p);
			ret = -EINVAL;
			goto out;
		}
	}

out:
	return ret;
}

static ssize_t cxlv_debugfs_remove_write(struct file *file, const char __user *ubuf,
				size_t cnt, loff_t *ppos)
{
	char *buf;
	u32 cxlv_dev_id;
	int ret;

	buf = memdup_user(ubuf, cnt);
	if (IS_ERR(buf)) {
		pr_err("failed to dup buf: %d", (int)PTR_ERR(buf));
		return PTR_ERR(buf);
	}

	ret = parse_remove_options(buf, &cxlv_dev_id);
	if (ret) {
		kfree(buf);
		return ret;
	}
	kfree(buf);

	ret = cxlv_remove_dev(cxlv_dev_id);
	if (ret < 0) {
		return ret;
	}

	return cnt;
}

CXLV_DEBUGFS_WO_FILE(debugfs_remove);

void cxlv_debugfs_cleanup(void)
{
	cxlv_debugfs_remove(&remove_f);
	cxlv_debugfs_remove(&create_f);
	cxlv_debugfs_remove(&cxlv_debugfs_root);
}

int cxlv_debugfs_init(void)
{
	struct dentry *dentry;
	int ret;

	dentry = cxl_debugfs_create_dir("cxlv");
	if (IS_ERR(dentry)) {
		ret = PTR_ERR(dentry);
		goto out;
	}

	cxlv_debugfs_root = dentry;

	create_f = debugfs_create_file("create", 0600, dentry, NULL,
			&cxlv_debugfs_create_fops);
	if (IS_ERR(create_f)) {
		ret = PTR_ERR(create_f);
		goto remove_root;
	}

	remove_f = debugfs_create_file("remove", 0600, dentry, NULL,
			&cxlv_debugfs_remove_fops);
	if (IS_ERR(remove_f)) {
		ret = PTR_ERR(remove_f);
		goto remove_create_f;
	}

	return 0;

remove_create_f:
	cxlv_debugfs_remove(&create_f);
remove_root:
	cxlv_debugfs_remove(&cxlv_debugfs_root);
out:
	return ret;
}
