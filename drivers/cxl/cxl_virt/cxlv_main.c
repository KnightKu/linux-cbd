/*
 * Copyright(C) 2024, Dongsheng Yang <dongsheng.yang@easystack.cn>
 */

#include "cxlv.h"

struct bus_type cxlv_subsys = {
	.name                           = "cxl_virt",
};

static int cxl_virt_dev_init(void)
{
	int ret;

	ret = subsys_virtual_register(&cxlv_subsys, NULL);
	if (ret) {
		pr_err("failed to register cxlv subsys");
		return ret;
	}

	return 0;
}

static void cxl_virt_dev_exit(void)
{
	bus_unregister(&cxlv_subsys);
}

static int __init cxlv_init(void)
{
	int ret;

	ret = cxl_virt_dev_init();
	if (ret)
		goto out;

	ret = cxlv_device_init();
	if (ret)
		goto cxl_virt_dev_exit;

	ret = cxlv_debugfs_init();
	if (ret)
		goto device_exit;

	return 0;

device_exit:
	cxlv_device_exit();
cxl_virt_dev_exit:
	cxl_virt_dev_exit();
out:
	return ret;
}

static void cxlv_exit(void)
{
	cxlv_debugfs_cleanup();
	cxlv_device_exit();
	cxl_virt_dev_exit();
}

MODULE_AUTHOR("Dongsheng Yang <dongsheng.yang@easystack.cn>");
MODULE_DESCRIPTION("CXL(Compute Express Link) Virtualization");
MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(CXL);
module_init(cxlv_init);
module_exit(cxlv_exit);
