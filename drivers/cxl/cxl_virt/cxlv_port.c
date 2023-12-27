#include "cxlv.h"
#include "cxlv_pci.h"

static int cxlv_port_create_root_port(struct cxlv_device *cxlv_device)
{
	struct device *host = &cxlv_device->dev;
	struct cxl_port *root_port;

	root_port = devm_cxl_add_port(host, host, CXL_RESOURCE_NONE, NULL);
	if (IS_ERR(root_port))
		return PTR_ERR(root_port);

	cxlv_device->root_port = root_port;

	return 0;
}

static int cxlv_port_add_root_decoder(struct cxlv_device *cxlv_device, struct resource *cxlv_res)
{
	int ret;
	struct resource *res;
	struct cxl_root_decoder *cxlrd;
	struct cxl_decoder *cxld;
	int target_map[CXL_DECODER_MAX_INTERLEAVE];

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	res->name = kasprintf(GFP_KERNEL, "CXLV Window %d", cxlv_device->cxlv_dev_id);
	if (!res->name)
		goto free_res;

	res->start = cxlv_device->opts->memstart + CXLV_RESOURCE_OFF;
	res->end = cxlv_device->opts->memstart + cxlv_device->opts->memsize - 1;
	res->flags = IORESOURCE_MEM;

	ret = insert_resource(cxlv_res, res);
	if (ret)
		goto free_name;

	cxlrd = cxl_root_decoder_alloc(cxlv_device->root_port, 1, cxl_hb_modulo);
	if (IS_ERR(cxlrd)) {
		ret = PTR_ERR(cxlrd);
		goto out;
	}
	cxlrd->qos_class = 0;

	cxld = &cxlrd->cxlsd.cxld;
	cxld->flags = CXL_DECODER_F_TYPE3 | CXL_DECODER_F_RAM | CXL_DECODER_F_PMEM;
	cxld->target_type = CXL_DECODER_HOSTONLYMEM;

	cxld->hpa_range = (struct range) {
		.start = res->start,
		.end = res->end,
	};
	cxld->interleave_ways = 1;
	cxld->interleave_granularity = CXL_DECODER_MIN_GRANULARITY;

	target_map[0] = 1;

	ret = cxl_decoder_add(cxld, target_map);
	if (ret) {
		put_device(&cxld->dev);
		goto out;
	}

	ret = cxl_decoder_autoremove(&cxlv_device->host_bridge->dev, cxld);
	if (ret)
		goto out;

	return 0;

free_name:
	kfree(res->name);
free_res:
	kfree(res);
out:
	return ret;
}

int cxlv_port_init(struct cxlv_device *cxlv_device)
{
	int ret;
	struct resource *cxl_res;
	struct cxl_port *root_port, *port;
	struct cxl_dport *dport;
	u64 component_phy_addr;

	ret = cxlv_port_create_root_port(cxlv_device);
	if (ret)
		return ret;;

	root_port = cxlv_device->root_port;

	dport = devm_cxl_add_dport(root_port, &cxlv_device->host_bridge->dev, 1, CXL_RESOURCE_NONE);
	if (IS_ERR(dport)) {
		pr_err("failed to add dport: %d", (int)PTR_ERR(dport));
		return PTR_ERR(dport);
	}

	cxl_res = devm_kzalloc(&cxlv_device->host_bridge->dev, sizeof(*cxl_res), GFP_KERNEL);
	if (!cxl_res) {
		return -ENOMEM;
	}

	cxl_res->name = "CXL mem";
	cxl_res->start = 0;
	cxl_res->end = -1;
	cxl_res->flags = IORESOURCE_MEM;

	ret = devm_add_action_or_reset(&cxlv_device->host_bridge->dev, remove_cxl_resources, cxl_res);
	if (ret)
		return ret;

	ret = cxlv_port_add_root_decoder(cxlv_device, cxl_res);
	if (ret) {
		return ret;
	}

	ret = add_cxl_resources(cxl_res);
	if (ret) {
		return ret;
	}

	device_for_each_child(&root_port->dev, cxl_res, pair_cxl_resource);

	ret = devm_cxl_register_pci_bus(&root_port->dev, &cxlv_device->host_bridge->dev, cxlv_device->host_bridge->bus);
	if (ret) {
		pr_err("failed to register pci bus");
		return ret;
	}

	component_phy_addr = cxlv_device->opts->memstart + CXLV_BRIDGE_REG_OFF + CXLV_BRIDGE_BAR_COMPONENT_OFF;
	port = devm_cxl_add_port(&root_port->dev, &cxlv_device->host_bridge->dev, component_phy_addr, dport);
	if (IS_ERR(port))
		return PTR_ERR(port);

	if (IS_ENABLED(CONFIG_CXL_PMEM)) {
		ret = device_for_each_child(&root_port->dev, root_port,
					   add_root_nvdimm_bridge);
		if (ret < 0) {
			pr_err("failed add nv bridge");
			return ret;
		}
	}

	return 0;
}
