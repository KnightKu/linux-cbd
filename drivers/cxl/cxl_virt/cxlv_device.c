#include <linux/delay.h>
#include <linux/kthread.h>

#include "cxlpci.h"
#include "cxlv.h"
#include "cxlv_pci.h"

#define CXLV_DEVICE_MAX_NUM	16
static struct cxlv_device *cxlv_devices[CXLV_DEVICE_MAX_NUM];
static struct mutex cxlv_devices_lock;

/* TODO faster way to find pci cfg for more devices supporting, e.g: XARRAY */
struct cxlv_pci_cfg *find_pci_cfg(struct pci_bus *bus, unsigned int devfn)
{
	int i;
	struct cxlv_device *cxlv_device;

	for (i = 0; i < CXLV_DEVICE_MAX_NUM; i++) {
		cxlv_device = cxlv_devices[i];

		if (!cxlv_device)
			continue;

		if (pci_find_host_bridge(bus)->bus->number != cxlv_device->host_bridge_busnr ||
				pci_domain_nr(bus) != cxlv_device->domain_nr)
			continue;

		if (pci_is_root_bus(bus)) {
			return &cxlv_device->bridge_cfg;
		} else {
			return &cxlv_device->dev_cfg;
		}

		continue;
	}

	return NULL;
}

static int cxlv_device_find_empty(void)
{
	int i;

	for (i = 0; i < CXLV_DEVICE_MAX_NUM; i++) {
		if (!cxlv_devices[i])
			return i;
	}

	return -1;
}

static int cxlv_device_register(struct cxlv_device *cxlv_device)
{
	int cxlv_dev_id = cxlv_device->cxlv_dev_id;

	if (cxlv_devices[cxlv_dev_id] != NULL) {
		return -EEXIST;
	}

	cxlv_devices[cxlv_dev_id] = cxlv_device;

	return 0;
}

static void cxlv_device_unregister(struct cxlv_device *cxlv_device)
{
	int cxlv_dev_id = cxlv_device->cxlv_dev_id;

	BUG_ON(cxlv_devices[cxlv_dev_id] != cxlv_device);

	cxlv_devices[cxlv_dev_id] = NULL;
}

int cxlv_device_init(void)
{
	int i;

	for (i = 0; i < CXLV_DEVICE_MAX_NUM; i++) {
		cxlv_devices[i] = NULL;
	}

	mutex_init(&cxlv_devices_lock);

	return 0;
}

void cxlv_device_exit(void)
{
	return;
}

static void cxlv_dev_release(struct device *dev)
{
}

static struct cxlv_device *cxlv_device_create(struct cxlv_dev_options *opts)
{
	struct device *cxlv_dev;
	struct cxlv_device *cxlv_device = NULL;
	int cxlv_dev_id;
	int ret;

	mutex_lock(&cxlv_devices_lock);
	cxlv_dev_id = cxlv_device_find_empty();
	if (cxlv_dev_id < 0) {
		pr_err("There is no more cxlv device can be created.");
		goto unlock;
	}

	cxlv_device = kzalloc(sizeof(struct cxlv_device), GFP_KERNEL);
	if (!cxlv_device) {
		pr_err("failed to alloc cxlv_device");
		goto unlock;
	}

	cxlv_device->opts = opts;
	cxlv_device->cxlv_dev_id = cxlv_dev_id;
	cxlv_device->aligned_start = ALIGN(opts->memstart + CXLV_RESOURCE_OFF,
					   CXLV_DEVICE_ALIGN);
	cxlv_device->aligned_end = ALIGN_DOWN(opts->memstart + opts->memsize,
					      CXLV_DEVICE_ALIGN) - 1;

	ret = cxlv_device_register(cxlv_device);
	if (ret) {
		pr_err("failed to register cxlv_device");
		goto release_device;
	}
	mutex_unlock(&cxlv_devices_lock);

	cxlv_dev = &cxlv_device->dev;
	cxlv_dev->release = cxlv_dev_release;
	cxlv_dev->bus = &cxlv_subsys;
	dev_set_name(cxlv_dev, "cxlv%d", cxlv_dev_id);
	device_set_pm_not_required(cxlv_dev);

	ret = device_register(cxlv_dev);
	if (ret < 0) {
		goto unregister;
	}

	return cxlv_device;

unregister:
        mutex_lock(&cxlv_devices_lock);
        cxlv_device_unregister(cxlv_device);
release_device:
	kfree(cxlv_device);
unlock:
	mutex_unlock(&cxlv_devices_lock);
	return NULL;
}

void cxlv_device_release(struct cxlv_device *cxlv_device)
{
	device_unregister(&cxlv_device->dev);

	mutex_lock(&cxlv_devices_lock);
	cxlv_device_unregister(cxlv_device);
	mutex_unlock(&cxlv_devices_lock);

	if (cxlv_device->opts)
		kfree(cxlv_device->opts);

	if (cxlv_device)
		kfree(cxlv_device);
}

#define CXLV_HANDLER_SLEEP_US		1000
static int cxlv_handle(void *data)
{
	while (!kthread_should_stop()) {
		process_mbox(data);
		process_decoder(data);

		/* sleep 1ms after each loop */
		schedule_timeout_interruptible(usecs_to_jiffies(10000));
	}

	return 0;
}

static void cxlv_dev_handler_init(struct cxlv_device *cxlv_device)
{
	cxlv_device->cxlv_dev_handler = kthread_create(cxlv_handle,
						       cxlv_device,
						       "cxlv%d_handler",
						       cxlv_device->cxlv_dev_id);
	wake_up_process(cxlv_device->cxlv_dev_handler);
}

static void cxlv_dev_handler_final(struct cxlv_device *cxlv_device)
{
	if (!IS_ERR_OR_NULL(cxlv_device->cxlv_dev_handler)) {
		kthread_stop(cxlv_device->cxlv_dev_handler);
		cxlv_device->cxlv_dev_handler = NULL;
	}
}

static int not_reserved(struct resource *res, void *arg)
{
	pr_err("has System RAM: %pr\n", res);

	return 1;
}

static int validate_configs(struct cxlv_dev_options *opts)
{
	u64 res_start;
	u64 res_end;
	int ret;

	if (!IS_ENABLED(CONFIG_CXL_PMEM) && opts->pmem) {
		pr_err("CONFIG_CXL_PMEM is not enabled");
		return -EINVAL;
	}

	if (!opts->memstart || !opts->memsize) {
		pr_err("[memstart] and [memsize] should be specified");
		return -EINVAL;
	}

	/* check for memory reserved */
	res_start = opts->memstart;
	res_end = res_start + opts->memsize - 1;

	ret = walk_iomem_res_desc(IORES_DESC_NONE,
				IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY,
				res_start,
				res_end, NULL,
				not_reserved);

	if (ret > 0) {
		pr_err("range [%llu, %llu] is not reserved.", res_start, res_end);
		return ret;
	}

	/* check the aligned resource */
	res_start = ALIGN(res_start + CXLV_RESOURCE_OFF, CXLV_DEVICE_ALIGN);
	if ((res_end - res_start + 1) < CXLV_DEVICE_RES_MIN) {
		pr_err("[%llu, %llu]: first %u is for metadata, \
				the rest is too small as we need %lu aligned resource range.",
				opts->memstart, res_end, CXLV_RESOURCE_OFF, CXLV_DEVICE_RES_MIN);
		return -EINVAL;
	}

	return 0;
}

int cxlv_create_dev(struct cxlv_dev_options *opts)
{
	int ret;
	struct cxlv_device *cxlv_device;

	if (validate_configs(opts)) {
		return -EINVAL;
	}

	cxlv_device = cxlv_device_create(opts);
	if (!cxlv_device) {
		return -ENOMEM;
	}

	ret = cxlv_pci_init(cxlv_device);
	if (ret) {
		goto err;
	}

	ret = cxlv_port_init(cxlv_device);
	if (ret)
		goto err;

	cxlv_dev_handler_init(cxlv_device);

	pci_bus_add_devices(cxlv_device->host_bridge->bus);

	__module_get(THIS_MODULE);
	return 0;

err:
	cxlv_device_release(cxlv_device);
	return -EIO;
}

int cxlv_remove_dev(u32 cxlv_dev_id)
{
	struct cxlv_device *cxlv_device;

	if (cxlv_dev_id >= CXLV_DEVICE_MAX_NUM)
		return -EINVAL;

	if (cxlv_devices[cxlv_dev_id] == NULL)
		return -EINVAL;

	cxlv_device = cxlv_devices[cxlv_dev_id];
	if (cxl_disable_port(cxlv_device->root_port))
		return -EBUSY;

	if (cxlv_device->host_bridge) {
		pci_stop_root_bus(cxlv_device->host_bridge->bus);
		pci_remove_root_bus(cxlv_device->host_bridge->bus);
		put_device(&cxlv_device->host_bridge->dev);
	}

	cxlv_dev_handler_final(cxlv_device);

	cxlv_device_release(cxlv_device);

	module_put(THIS_MODULE);

	return 0;
}
