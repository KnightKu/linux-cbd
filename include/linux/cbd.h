#ifndef _CXL_BLKDEV_H
#define _CXL_BLKDEV_H
#include <linux/types.h>

#define CXL_BLKDEV_REGION_PARAM_F_PMEM		1

struct cbd_region_param {
	u64	start;
	u64	size;

	u32	flags;
};

extern int cbd_region_create(struct cbd_region_param *cbd_rp);
extern int cbd_region_destroy(int id);

#endif /* _CXL_BLKDEV_H */
