#include "cbd_internal.h"

static char hostname_null[CBD_NAME_LEN] = { 0 };

static ssize_t cbd_host_name_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	char hostname[CBD_NAME_LEN];
	struct cbd_host_device *host;
	struct cbd_host_info *host_info;
	int ret;

	host = container_of(dev, struct cbd_host_device, dev);
	host_info = host->host_info;

	memcpy_fromio(hostname, host_info->hostname, CBD_NAME_LEN);

	if (hostname[0] == 0)
		return 0;

	return sprintf(buf, "%s\n", hostname);
}

static DEVICE_ATTR(hostname, 0400, cbd_host_name_show, NULL);

static ssize_t cbd_host_alive_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cbd_host_device *host;
	struct cbd_host_info *host_info;
	ktime_t oldest, ts;
	int ret;

	host = container_of(dev, struct cbd_host_device, dev);
	host_info = host->host_info;

	ts = readq(&host_info->alive_ts);
	oldest = ktime_sub_ms(ktime_get_real(), 30 * 1000);
	pr_err("ts: %llu, oldest: %llu", ts, oldest);

	if (ktime_after(ts, oldest))
		return sprintf(buf, "true\n");

	return sprintf(buf, "false\n");
}

static DEVICE_ATTR(alive, 0400, cbd_host_alive_show, NULL);

static struct attribute *cbd_host_attrs[] = {
	&dev_attr_hostname.attr,
	&dev_attr_alive.attr,
	NULL
};

static struct attribute_group cbd_host_attr_group = {
	.attrs = cbd_host_attrs,
};

static const struct attribute_group *cbd_host_attr_groups[] = {
	&cbd_host_attr_group,
	NULL
};

static void cbd_host_release(struct device *dev)
{
}

struct device_type cbd_host_type = {
	.name		= "cbd_host",
	.groups		= cbd_host_attr_groups,
	.release	= cbd_host_release,
};

struct device_type cbd_hosts_type = {
	.name		= "cbd_hosts",
	.release	= cbd_host_release,
};

int cbd_hosts_init(struct cbd_transport *cbdt)
{
	struct cbd_hosts_device *cbd_hosts_dev;
	struct cbd_host_device *host;
	struct device *dev;
	int i;
	int ret;

	cbd_hosts_dev = kzalloc(struct_size(cbd_hosts_dev, host_devs, cbdt->transport_info->host_num),
				GFP_KERNEL);
	if (!cbd_hosts_dev) {
		return -ENOMEM;
	}

	dev = &cbd_hosts_dev->hosts_dev;
	cbd_setup_device(dev,
			&cbdt->device,
			&cbd_hosts_type,
			"cbd_hosts");

	for (i = 0; i < cbdt->transport_info->host_num; i++) {
		struct cbd_host_device *host = &cbd_hosts_dev->host_devs[i];
		struct device *host_dev = &host->dev;

		host->host_info = cbdt_get_host_info(cbdt, i);
		cbd_setup_device(host_dev, &cbd_hosts_dev->hosts_dev,
				&cbd_host_type, "host%u", i);
	}
	cbdt->cbd_hosts_dev = cbd_hosts_dev;

	return 0;
}

int cbd_hosts_exit(struct cbd_transport *cbdt)
{
	struct cbd_hosts_device *cbd_hosts_dev = cbdt->cbd_hosts_dev;
	int i;

	if (!cbd_hosts_dev)
		return 0;

	for (i = 0; i < cbdt->transport_info->host_num; i++) {
		struct cbd_host_device *host = &cbd_hosts_dev->host_devs[i];
		struct device *host_dev = &host->dev;

		device_del(host_dev);
		put_device(host_dev);
	}

	device_del(&cbd_hosts_dev->hosts_dev);
	put_device(&cbd_hosts_dev->hosts_dev);

	kfree(cbd_hosts_dev);
	cbdt->cbd_hosts_dev = NULL;

	return 0;
}

static void host_hb_workfn(struct work_struct *work)
{
	struct cbd_host *host = container_of(work, struct cbd_host, hb_work.work);
	struct cbd_host_info *host_info = host->host_info;

	ktime_t now = ktime_get_real();

	writeq(now, &host_info->alive_ts);

	queue_delayed_work(cbd_wq, &host->hb_work, 5 * HZ);
}

int cbd_host_register(struct cbd_transport *cbdt, struct cbd_adm_options *opts)
{
	struct cbd_host *host;
	struct cbd_host_info *host_info;
	u32 hid;
	int ret;

	if (cbdt->host) {
		return -EEXIST;
	}

	if (opts->host.hostname[0] == 0) {
		return -EINVAL;
	}

	ret = cbdt_get_empty_hid(cbdt, &hid);
	if (ret < 0) {
		return ret;
	}

	host = kzalloc(sizeof(struct cbd_host), GFP_KERNEL);
	if (!host) {
		ret = -ENOMEM;
		goto err;
	}

	host->host_id = hid;
	INIT_DELAYED_WORK(&host->hb_work, host_hb_workfn);

	host_info = cbdt_get_host_info(cbdt, hid);
	host_info->status = cbd_host_status_running;
	memcpy_toio(&host_info->hostname, opts->host.hostname, CBD_NAME_LEN);

	host->host_info = host_info;
	cbdt->host = host;

	cbd_hosts_init(cbdt);
	cbd_backends_init(cbdt);
	cbd_channels_init(cbdt);
	cbd_blkdevs_init(cbdt);

	queue_delayed_work(cbd_wq, &host->hb_work, 0);

	return 0;

err:
	return ret;
}

int cbd_host_unregister(struct cbd_transport *cbdt, struct cbd_adm_options *opts)
{
	struct cbd_host *host = cbdt->host;
	struct cbd_host_info *host_info;

	if (!host) {
		pr_err("This host is not registered.");
		return 0;
	}

	cancel_delayed_work_sync(&host->hb_work);
	host_info = host->host_info;
	memcpy_toio(&host_info->hostname, hostname_null, CBD_NAME_LEN);
	writeq(0, &host_info->alive_ts);
	host_info->status = cbd_host_status_none;

	kfree(cbdt->host);
	cbdt->host = NULL;

	cbd_blkdevs_exit(cbdt);
	cbd_channels_exit(cbdt);
	cbd_backends_exit(cbdt);
	cbd_hosts_exit(cbdt);


	return 0;
}
