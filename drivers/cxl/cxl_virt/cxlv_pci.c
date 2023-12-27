#include "cxlv.h"
#include "cxlv_pci.h"
#include "cxlpci.h"
#include "cxlmem.h"

static struct cxl_cel_entry cel_logs[] = {
	{ .opcode = CXL_MBOX_OP_GET_SUPPORTED_LOGS, .effect = 0 },
	{ .opcode = CXL_MBOX_OP_GET_LOG, .effect = 0 },
	{ .opcode = CXL_MBOX_OP_IDENTIFY, .effect = 0 },
};

#define CXLV_CEL_SUPPORTED_NUM		3

void process_decoder(struct cxlv_device *dev)
{
	struct cxl_component *comp;
	struct cxl_decoder_cap *decoder;

	/* process device decoder */
	comp = ioremap(pci_resource_start(dev->dev_pdev, 0) + CXLV_DEV_BAR_COMPONENT_OFF,
					  CXLV_DEV_BAR_COMPONENT_LEN);

	decoder = (struct cxl_decoder_cap *)((char *)comp + CXLV_COMP_CACHEMEM_OFF + CXLV_COMP_DECODER_OFF);
	if (decoder->decoder[0].ctrl_regs & CXLV_DECODER_CTRL_COMMIT) {
		decoder->decoder[0].ctrl_regs |= CXLV_DECODER_CTRL_COMMITTED;
		decoder->decoder[0].ctrl_regs &= ~CXLV_DECODER_CTRL_COMMIT;
		decoder->decoder[0].ctrl_regs &= ~CXLV_DECODER_CTRL_COMMIT_ERR;
	}
	iounmap(comp);

	/* process bridge decoder */
	comp = ioremap(pci_resource_start(dev->bridge_pdev, 0) + CXLV_BRIDGE_BAR_COMPONENT_OFF,
					  CXLV_BRIDGE_BAR_COMPONENT_LEN);

	decoder = (struct cxl_decoder_cap *)((char *)comp + CXLV_COMP_CACHEMEM_OFF + CXLV_COMP_DECODER_OFF);
	if (decoder->decoder[0].ctrl_regs & CXLV_DECODER_CTRL_COMMIT) {
		decoder->decoder[0].ctrl_regs |= CXLV_DECODER_CTRL_COMMITTED;
		decoder->decoder[0].ctrl_regs &= ~CXLV_DECODER_CTRL_COMMIT;
		decoder->decoder[0].ctrl_regs &= ~CXLV_DECODER_CTRL_COMMIT_ERR;
	}
	iounmap(comp);

	return;
}

void process_mbox(struct cxlv_device *dev)
{
	struct pci_dev *pdev = dev->dev_pdev;
	struct cxl_bar *bar;
	struct cxlv_mbox *mbox;
	int ret;

	bar = ioremap(pci_resource_start(pdev, 0) + CXLV_DEV_BAR_DEV_REGS_OFF,
		      CXLV_DEV_BAR_DEV_REGS_LEN);

	mbox = ((void *)bar) + CXLV_DEV_CAP_MBOX_OFF;

	if (cxlv_mbox_test_doorbell(mbox)) {
		if (cxlv_mbox_get_cmd(mbox) == CXL_MBOX_OP_GET_SUPPORTED_LOGS) {
			struct cxl_mbox_get_supported_logs *supported_log;
			u32 payload_len;

			payload_len = sizeof(*supported_log) + sizeof(supported_log->entry[0]);

			supported_log = kzalloc(payload_len, GFP_KERNEL);
			if (!supported_log) {
				ret = CXL_MBOX_CMD_RC_INTERNAL;
				goto out;
			}

			supported_log->entries = cpu_to_le16(1);
			supported_log->entry[0].uuid = DEFINE_CXL_CEL_UUID;
			supported_log->entry[0].size = cpu_to_le32(sizeof(struct cxl_cel_entry) * CXLV_CEL_SUPPORTED_NUM);

			cxlv_mbox_copy_to_payload(mbox, 0, supported_log, payload_len);
			cxlv_mbox_set_cmd_payload_len(mbox, payload_len);
			ret = CXL_MBOX_CMD_RC_SUCCESS;
			kfree(supported_log);
		} else if (cxlv_mbox_get_cmd(mbox) == CXL_MBOX_OP_GET_LOG) {
			struct cxl_mbox_get_log get_log;

			cxlv_mbox_copy_from_payload(mbox, 0, &get_log, sizeof(struct cxl_mbox_get_log));

			if (!uuid_equal(&get_log.uuid, &DEFINE_CXL_CEL_UUID)) {
				ret = CXL_MBOX_CMD_RC_LOG;
				goto out;
			}

			cxlv_mbox_copy_to_payload(mbox, le32_to_cpu(get_log.offset), cel_logs, le32_to_cpu(get_log.length));
			cxlv_mbox_set_cmd_payload_len(mbox, le32_to_cpu(get_log.length));
			ret = CXL_MBOX_CMD_RC_SUCCESS;
		} else if (cxlv_mbox_get_cmd(mbox) == CXL_MBOX_OP_IDENTIFY) {
			struct cxl_mbox_identify id = { 0 };
			u64 capacity = (dev->aligned_end - dev->aligned_start + 1) / CXL_CAPACITY_MULTIPLIER;

			strcpy(id.fw_revision, CXLV_FW_VERSION);

			if (dev->opts->pmem) {
				id.total_capacity = cpu_to_le64(capacity);
				id.volatile_capacity = 0;
				id.persistent_capacity = cpu_to_le64(capacity);
				id.lsa_size = cpu_to_le64(CXLV_DEV_BAR_LSA_LEN);
			} else {
				id.total_capacity = cpu_to_le64(capacity);
				id.volatile_capacity = cpu_to_le64(capacity);
				id.persistent_capacity = 0;
			}

			cxlv_mbox_copy_to_payload(mbox, 0, &id, sizeof(id));
			cxlv_mbox_set_cmd_payload_len(mbox, sizeof(id));
			ret = CXL_MBOX_CMD_RC_SUCCESS;
		} else if (cxlv_mbox_get_cmd(mbox) == CXL_MBOX_OP_GET_LSA) {
			void *lsa;
			struct cxl_mbox_get_lsa get_lsa = { 0 };

			cxlv_mbox_copy_from_payload(mbox, 0, &get_lsa, sizeof(struct cxl_mbox_get_lsa));

			u32 offset = le32_to_cpu(get_lsa.offset);
			u32 len = le32_to_cpu(get_lsa.length);

			if (len > CXLV_DEV_CAP_MBOX_PAYLOAD) {
				ret = CXL_MBOX_CMD_RC_INPUT;
				goto out;
			}

			/* read lsa from bar */
			lsa = memremap(pci_resource_start(pdev, 0) + CXLV_DEV_BAR_LSA_OFF,
					CXLV_DEV_BAR_LSA_LEN, MEMREMAP_WB);
			cxlv_mbox_copy_to_payload(mbox, 0, lsa + offset, len);
			memunmap(lsa);

			cxlv_mbox_set_cmd_payload_len(mbox, len);
			ret = CXL_MBOX_CMD_RC_SUCCESS;
		} else if (cxlv_mbox_get_cmd(mbox) == CXL_MBOX_OP_SET_LSA) {
			void *lsa;
			struct cxl_mbox_set_lsa *set_lsa = (struct cxl_mbox_set_lsa *)mbox->payload;
			u32 offset = le32_to_cpu(set_lsa->offset);
			u32 len = FIELD_GET(CXLDEV_MBOX_CMD_PAYLOAD_LENGTH_MASK, mbox->cmd);

			/* write lsa to bar */
			lsa = memremap(pci_resource_start(pdev, 0) + CXLV_DEV_BAR_LSA_OFF,
					CXLV_DEV_BAR_LSA_LEN, MEMREMAP_WB);
			memcpy(lsa + offset, set_lsa->data, len);
			memunmap(lsa);

			ret = CXL_MBOX_CMD_RC_SUCCESS;
		} else {
			dev_err(&dev->dev, "unsupported cmd: 0x%x", cxlv_mbox_get_cmd(mbox));
			ret = CXL_MBOX_CMD_RC_UNSUPPORTED;
		}
out:
		cxlv_mbox_set_retcode(mbox, ret);
		smp_mb();
		cxlv_mbox_clear_doorbell(mbox);
		iounmap(bar);
	}

	return;
}

static int cxlv_pci_read(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *val)
{
	struct cxlv_pci_cfg *pci_cfg;

	if (devfn != 0)
		return 1;

	pci_cfg = find_pci_cfg(bus, devfn);
	if (!pci_cfg)
		return -ENXIO;

	memcpy(val, pci_cfg->cfg_data + where, size);

	pr_debug("[R] bus: %p, devfn: %u, 0x%x, size: %d, val: 0x%x\n", bus, devfn, where, size, *val);

	return 0;
};

static int cxlv_pci_write(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 _val)
{
	struct cxlv_pci_cfg *pci_cfg;
	u32 mask = ~(0U);
	u32 val = 0x00;
	int target = where;

	WARN_ON(size > sizeof(_val));

	pci_cfg = find_pci_cfg(bus, devfn);
	if (!pci_cfg)
		return -ENXIO;

	memcpy(&val, pci_cfg->cfg_data + where, size);

	if (where < CXLV_PCI_PM_CAP_OFFS) {
		if (target == PCI_STATUS) {
			mask = 0xF200;
		} else if (target == PCI_BIST) {
			mask = PCI_BIST_START;
		} else if (target == PCI_BASE_ADDRESS_0) {
			/* bar size is 1M */
			mask = 0xFFE00000;
		} else if (target == PCI_INTERRUPT_LINE) {
			mask = 0xFF;
		} else {
			mask = 0x0;
		}
	}

	val = (val & (~mask)) | (_val & mask);
	memcpy(pci_cfg->cfg_data + where, &val, size);

	pr_debug("[W] bridge 0x%x, mask: 0x%x, val: 0x%x -> 0x%x, size: %d, new: 0x%x\n", where, mask,
	    val, _val, size, (val & (~mask)) | (_val & mask));

	return 0;
};

static struct pci_ops cxlv_pci_ops = {
	.read = cxlv_pci_read,
	.write = cxlv_pci_write,
};

static struct pci_sysdata cxlv_pci_sysdata = {
	.domain = CXLV_PCI_DOMAIN_NUM,
	.node = 0,
};

static void cxlv_dev_reg_init(struct pci_dev *dev)
{
	struct cxl_bar *bar;
	struct cap_array_header *array_header;
	struct cap_header *cap_header;
	struct cxlv_mbox *mbox;
	struct cxl_dev_status *dev_status;
	struct cxl_memdev_cap *memdev;
	u16 val;
	u64 status_val;

	bar = ioremap(pci_resource_start(dev, 0) + CXLV_DEV_BAR_DEV_REGS_OFF, CXLV_DEV_BAR_DEV_REGS_LEN);

	BUG_ON(!bar);

	memset(bar, 0x0, CXLV_DEV_BAR_DEV_REGS_LEN);

	/* Initialize device cap array header */
	array_header = &bar->cap_array_header;
	array_header->cap_id = cpu_to_le16(CXLDEV_CAP_ARRAY_CAP_ID);

	val = CXLV_DEV_CAP_ARRAY_HEADER_VERS_DEFAULT;
	val |= FIELD_PREP(CXLV_DEV_CAP_ARRAY_HEADER_TYPE_MASK, CXLV_DEV_CAP_ARRAY_HEADER_TYPE_MEMDEV);
	array_header->vers_type = cpu_to_le16(val);

	array_header->cap_count = cpu_to_le16(CXLV_DEV_CAP_ARRAY_SIZE);

	/* Initialize device status cap */
	cap_header = &bar->cap_headers[0];
	cap_header->cap_id = cpu_to_le16(CXLDEV_CAP_CAP_ID_DEVICE_STATUS);
	cap_header->version = 0;
	cap_header->offset = cpu_to_le32(CXLV_DEV_CAP_STATUS_OFF);
	cap_header->len = cpu_to_le32(CXLV_DEV_CAP_STATUS_LEN);

	cap_header = &bar->cap_headers[1];
	cap_header->cap_id = cpu_to_le16(CXLDEV_CAP_CAP_ID_PRIMARY_MAILBOX);
	cap_header->version = 0;
	cap_header->offset = cpu_to_le32(CXLV_DEV_CAP_MBOX_OFF);
	cap_header->len = cpu_to_le32(CXLV_DEV_CAP_MBOX_LEN);

	cap_header = &bar->cap_headers[2];
	cap_header->cap_id = cpu_to_le16(CXLDEV_CAP_CAP_ID_MEMDEV);
	cap_header->version = 0;
	cap_header->offset = cpu_to_le32(CXLV_DEV_CAP_MEMDEV_OFF);
	cap_header->len = cpu_to_le32(CXLV_DEV_CAP_MEMDEV_LEN);

	dev_status = ((void *)bar) + CXLV_DEV_CAP_STATUS_OFF;
	dev_status->status = 0;

	mbox = ((void *)bar) + CXLV_DEV_CAP_MBOX_OFF;
	mbox->cap = cpu_to_le32(CXLV_MBOX_CAP_PAYLOAD_SIZE_DEFAULT & CXLV_MBOX_CAP_PAYLOAD_SIZE_MASK);
	mbox->control = 0;

	memdev = ((void *)bar) + CXLV_DEV_CAP_MEMDEV_OFF;
	status_val = CXLV_MEMDEV_CAP_MBXO_INTERFACE_READY;
	status_val |= FIELD_PREP(CXLV_MEMDEV_CAP_MEDIA_STATUS_MASK, CXLV_MEMDEV_CAP_MEDIA_STATUS_DEFAULT);
	status_val |= FIELD_PREP(CXLV_MEMDEV_CAP_MBOX_RESET_NEEDED_MASK, CXLV_MEMDEV_CAP_MBOX_RESET_NEEDED_DEFAULT);
	memdev->status = cpu_to_le64(status_val);

	iounmap(bar);
}

static int cxlv_component_reg_init(struct pci_dev *pdev, u32 off, u32 len)
{
	struct cxl_component *comp;
	struct cxl_decoder_cap *decoder;
	u32 val;

	comp = ioremap(pci_resource_start(pdev, 0) + off, len);

	val = CM_CAP_HDR_CAP_ID;
	val |= FIELD_PREP(CXLV_COMP_CACHEMEM_HDR_CAP_VER_MASK, 1);
	val |= FIELD_PREP(CXLV_COMP_CACHEMEM_HDR_CACHEMEM_VER_MASK, 1);
	val |= FIELD_PREP(CXLV_COMP_CACHEMEM_HDR_ARRAY_SIZE_MASK, 1);
	writel(val, &comp->cachemem_comp.header);

	val = CXL_CM_CAP_CAP_ID_HDM;
	val |= FIELD_PREP(CXLV_COMP_CACHEMEM_HDM_CAP_VER_MASK, 3);
	val |= FIELD_PREP(CXLV_COMP_CACHEMEM_HDM_DECODER_POINTER_MASK, CXLV_COMP_DECODER_OFF);
	writel(val, &comp->cachemem_comp.hdm_cap);

	decoder = (struct cxl_decoder_cap *)((char *)comp + CXLV_COMP_CACHEMEM_OFF + CXLV_COMP_DECODER_OFF);
	val = FIELD_PREP(CXLV_DECODER_CAP_DCOUNT_MASK, 0);
	val |= FIELD_PREP(CXLV_DECODER_CAP_TCOUNT_MASK, 1);
	writel(val, &decoder->cap_reg);

	decoder->decoder[0].ctrl_regs &= ~CXLV_DECODER_CTRL_COMMITTED;

	iounmap(comp);

	return 0;
}

static void cxlv_msix_table_init(struct pci_dev *dev)
{
	void *msix_table;

	msix_table = ioremap(pci_resource_start(dev, 0) + CXLV_BAR_PCI_MSIX_OFF,
			CXLV_BAR_PCI_MSIX_LEN);
	memset(msix_table, 0x00, CXLV_BAR_PCI_MSIX_LEN);
	iounmap(msix_table);
}

static struct pci_bus *cxlv_pci_bus_init(struct cxlv_device *cxlv_device)
{
	struct pci_bus *bus = cxlv_device->host_bridge->bus;
	struct pci_dev *dev, *t_dev;

	pci_scan_child_bus(bus);

	list_for_each_entry(t_dev, &bus->devices, bus_list) {
		if (!t_dev->subordinate)
			continue;

		struct pci_bus *b_bus = t_dev->subordinate;
		struct resource *res = &t_dev->resource[0];
		int i;

		cxlv_device->bridge_pdev = t_dev;

		res->parent = &iomem_resource;

		for (i = PCI_BRIDGE_RESOURCES; i <= PCI_BRIDGE_RESOURCE_END; i++) {
			res = &t_dev->resource[i];
			res->parent = &iomem_resource;
		}

		cxlv_component_reg_init(t_dev, CXLV_BRIDGE_BAR_COMPONENT_OFF, CXLV_BRIDGE_BAR_COMPONENT_LEN);
		cxlv_msix_table_init(t_dev);

		list_for_each_entry(dev, &b_bus->devices, bus_list) {
			res = &dev->resource[0];
			res->parent = &iomem_resource;

			cxlv_device->dev_pdev = dev;
			cxlv_dev_reg_init(dev);
			cxlv_component_reg_init(dev, CXLV_DEV_BAR_COMPONENT_OFF, CXLV_DEV_BAR_COMPONENT_LEN);
			cxlv_msix_table_init(dev);
		}
	}

	return bus;
};

static void pci_dev_header_init(struct cxlv_pci_cfg_header *pcihdr, unsigned long base_pa)
{
	pcihdr->vid = CXLV_VENDOR_ID;
	pcihdr->did = CXLV_DEVICE_ID;
	u32 bar = 0;

	pcihdr->status = cpu_to_le16(PCI_STATUS_CAP_LIST);

	pcihdr->rid = 0x01;

	pcihdr->class_code.bcc = PCI_BASE_CLASS_MEMORY;
	pcihdr->class_code.scc = 0x02;
	pcihdr->class_code.pi = 0x10;

	pcihdr->header_type = PCI_HEADER_TYPE_NORMAL;

	bar |= PCI_BASE_ADDRESS_MEM_TYPE_64;
	bar |= PCI_BASE_ADDRESS_MEM_PREFETCH;
	bar |= PCI_BASE_ADDRESS_SPACE_MEMORY;
	bar |= base_pa & CXLV_PCI_BASE_ADDRESS_PA_MASK;
	pcihdr->bar0 = cpu_to_le32(bar);

	pcihdr->bar1 = cpu_to_le32(base_pa >> 32);

	pcihdr->type0.subsystem_id = cpu_to_le16(CXLV_SUBSYSTEM_ID);
	pcihdr->type0.subsystem_vendor_id = cpu_to_le16(CXLV_SUBSYSTEM_VENDOR_ID);

	pcihdr->type0.expand_rom = cpu_to_le32(0);

	pcihdr->type0.cap_pointer = CXLV_PCI_PM_CAP_OFFS;
}

static void pci_pmcap_init(struct cxlv_pci_pm_cap *pmcap)
{
	pmcap->cid = PCI_CAP_ID_PM;
	pmcap->next = CXLV_PCI_MSIX_CAP_OFFS;

	/* set version of power management cap to 0x11 */
	pmcap->pm_cap = cpu_to_le16(PCI_PM_CAP_VER_MASK & 0x11);

	pmcap->pm_ctrl_status = cpu_to_le16(PCI_D0 | PCI_PM_CTRL_NO_SOFT_RESET);
}

static void pci_msixcap_init(struct cxlv_pci_msix_cap *msixcap)
{
	u16 val;
	u32 tab_val;

	msixcap->cid = PCI_CAP_ID_MSIX;
	msixcap->next = CXLV_PCIE_CAP_OFFS;

	val = PCI_MSIX_FLAGS_ENABLE;
	/* set msix table size decoded by (n + 1) */
	val |= ((CXLV_BAR_PCI_MSIX_OFF - 1) & PCI_MSIX_FLAGS_QSIZE);
	msixcap->msix_ctrl = cpu_to_le16(val);

	/* msix table at the beginning of bar0 */
	tab_val = (PCI_MSIX_TABLE_BIR & 0x0);
	tab_val |= (PCI_MSIX_TABLE_OFFSET & CXLV_BAR_PCI_MSIX_OFF);
	msixcap->msix_tab = cpu_to_le32(tab_val);
}

static void pci_pciecap_init(struct cxlv_pcie_cap *pciecap, u8 type)
{
	u32 val;
	u16 cap_val;

	pciecap->cid = PCI_CAP_ID_EXP;
	pciecap->next = 0x0;

	cap_val = CXLV_PCI_EXP_VERS_DEFAULT;
	cap_val |= FIELD_PREP(CXLV_PCI_EXP_TYPE_MASK, type);
	pciecap->pcie_cap = cpu_to_le16(cap_val);

	val = CXLV_PCI_EXP_PAYLOAD_DEFAULT;
	val |= FIELD_PREP(CXLV_PCI_EXP_DEVCAP_L0S_MASK, CXLV_PCI_EXP_DEVCAP_L0S_DEFAULT);
	val |= FIELD_PREP(CXLV_PCI_EXP_DEVCAP_L1_MASK, CXLV_PCI_EXP_DEVCAP_L1_DEFAULT);
	pciecap->pcie_dev_cap = cpu_to_le32(val);
}

static void init_pci_ext_cap(struct cxlv_pci_ext_cap *ext_cap, u16 next)
{
	u16 next_val;

	ext_cap->cid = cpu_to_le16(PCI_EXT_CAP_ID_DVSEC);
	next_val = CXLV_PCI_EXT_CAP_VERS_DEFAULT;
	next_val |= FIELD_PREP(CXLV_PCI_EXT_CAP_NEXT_MASK, next);
	ext_cap->next = cpu_to_le16(next_val);
}

static void init_cxl_dvsec_header1(__le32 *header1, u16 len)
{
	u32 header1_val;

	header1_val = PCI_DVSEC_VENDOR_ID_CXL;
	header1_val |= FIELD_PREP(CXLV_DVSEC_REVISION_MASK, CXLV_DVSEC_REVISION_DEFAULT);
	header1_val |= FIELD_PREP(CXLV_DVSEC_LEN_MASK, len);

	*header1 = cpu_to_le32(header1_val);
}

static void init_cxl_loc_low(__le32 *low, u8 bar, u8 type, u64 off)
{
	u32 val;
	u32 off_val;

	off_val = FIELD_GET(CXLV_DVSEC_LOC_LO_OFF_MASK, off);

	val = bar;
	val |= FIELD_PREP(CXLV_DVSEC_LOC_LO_TYPE_MASK, type);
	val |= FIELD_PREP(CXLV_DVSEC_LOC_LO_OFF_MASK, off_val);

	*low = cpu_to_le32(val);
}

static void init_cxl_loc_hi(__le32 *hi, u64 off)
{
	u32 off_val;

	if (!FIELD_FIT(CXLV_DVSEC_LOC_HI_OFF_MASK, off)) {
		*hi = cpu_to_le32(0);
		return;
	}

	off_val = FIELD_GET(CXLV_DVSEC_LOC_HI_OFF_MASK, off);
	*hi = cpu_to_le32(FIELD_PREP(CXLV_DVSEC_LOC_HI_OFF_MASK, off_val));
}

static void pci_dev_excap_init(struct cxlv_pci_ext_cap *ext_cap)
{
	void *ext_cap_base = ext_cap;
	struct cxlv_pci_ext_cap_id_dvsec *cap_id;
	struct cxlv_pci_ext_cap_locator *cap_loc;
	struct reg_block_loc *loc;
	u16 cap_val;

	/* Initialize the CXL_DVSEC_PCIE_DEVICE */
	cap_id = ext_cap_base;
	init_pci_ext_cap(&cap_id->header.cap_header, PCI_CFG_SPACE_SIZE + 0x3c);

	init_cxl_dvsec_header1(&cap_id->header.cxl_header1, 0x3c);

	cap_id->header.cxl_header2 = cpu_to_le16(CXL_DVSEC_PCIE_DEVICE);

	cap_val = CXLV_DVSEC_CAP_MEM;
	cap_val |= FIELD_PREP(CXLV_DVSEC_CAP_HDM_COUNT_MASK, 1);
	cap_id->cap = cpu_to_le16(cap_val);

	cap_id->size_low_1 = cpu_to_le32(CXLV_DVSEC_CAP_VALID | CXLV_DVSEC_CAP_ACTIVE);

	/* Initialize locator dvsec for memdev */
	cap_loc = ext_cap_base + 0x3c;
	init_pci_ext_cap(&cap_loc->header.cap_header, 0);

	init_cxl_dvsec_header1(&cap_loc->header.cxl_header1, 0xC + sizeof(struct reg_block_loc) * 2);

	cap_loc->header.cxl_header2 = cpu_to_le16(CXL_DVSEC_REG_LOCATOR);

	loc = &cap_loc->loc1;
	init_cxl_loc_low(&loc->reg_block_lo_off, 0, CXL_REGLOC_RBI_MEMDEV, CXLV_DEV_BAR_DEV_REGS_OFF);
	init_cxl_loc_hi(&loc->reg_block_hi_off, CXLV_DEV_BAR_DEV_REGS_OFF);

	loc = &cap_loc->loc2;
	init_cxl_loc_low(&loc->reg_block_lo_off, 0, CXL_REGLOC_RBI_COMPONENT, CXLV_DEV_BAR_COMPONENT_OFF);
	init_cxl_loc_hi(&loc->reg_block_hi_off, CXLV_DEV_BAR_COMPONENT_OFF);
}

static void pci_bridge_extcap_init(struct cxlv_pci_ext_cap *ext_cap)
{
	void *ext_cap_base = ext_cap;
	struct cxlv_pci_ext_cap_id_dvsec *cap_id;
	struct cxlv_pci_ext_cap_locator *cap_loc;
	struct reg_block_loc *loc;
	u16 cap_val;

	/* Initialize the CXL_DVSEC_PCIE_DEVICE */
	cap_id = ext_cap_base;
	init_pci_ext_cap(&cap_id->header.cap_header, PCI_CFG_SPACE_SIZE + 0x3c);

	init_cxl_dvsec_header1(&cap_id->header.cxl_header1, 0x3c);
	cap_id->header.cxl_header2 = cpu_to_le16(CXL_DVSEC_PCIE_DEVICE);

	cap_val = CXLV_DVSEC_CAP_MEM;
	cap_val |= FIELD_PREP(CXLV_DVSEC_CAP_HDM_COUNT_MASK, 1);
	cap_id->cap = cpu_to_le16(cap_val);

	cap_id->size_low_1 = cpu_to_le32(CXLV_DVSEC_CAP_VALID | CXLV_DVSEC_CAP_ACTIVE);

	/* Initialize locator dvsec for memdev */
	cap_loc = ext_cap_base + 0x3c;
	init_pci_ext_cap(&cap_loc->header.cap_header, 0);

	init_cxl_dvsec_header1(&cap_loc->header.cxl_header1, 0xC + sizeof(struct reg_block_loc) * 3);
	cap_loc->header.cxl_header2 = cpu_to_le16(CXL_DVSEC_REG_LOCATOR);

	loc = &cap_loc->loc1;
	init_cxl_loc_low(&loc->reg_block_lo_off, 0, CXL_REGLOC_RBI_COMPONENT, CXLV_BRIDGE_BAR_COMPONENT_OFF);
	init_cxl_loc_hi(&loc->reg_block_hi_off, CXLV_BRIDGE_BAR_COMPONENT_OFF);
}


static void pci_bridge_header_init(struct cxlv_pci_cfg_header *pcihdr, unsigned long base_pa)
{
	u32 bar;

	pcihdr->did = CXLV_DEVICE_ID;
	pcihdr->vid = CXLV_VENDOR_ID;
	pcihdr->status = cpu_to_le16(PCI_STATUS_CAP_LIST);

	pcihdr->header_type = PCI_HEADER_TYPE_BRIDGE;

	pcihdr->rid = 0x01;

	pcihdr->class_code.bcc = PCI_BASE_CLASS_BRIDGE;
	pcihdr->class_code.scc = 0x04;
	pcihdr->class_code.pi = 0x00;

	bar = PCI_BASE_ADDRESS_MEM_TYPE_64;
	bar |= PCI_BASE_ADDRESS_MEM_PREFETCH;
	bar |= PCI_BASE_ADDRESS_SPACE_MEMORY;
	bar |= base_pa & CXLV_PCI_BASE_ADDRESS_PA_MASK;
	pcihdr->bar0 = cpu_to_le32(bar);

	pcihdr->bar1 = cpu_to_le32(base_pa >> 32);

	pcihdr->type1.capabilities_pointer = CXLV_PCI_PM_CAP_OFFS;
}

static void pci_pointer_assign(struct cxlv_pci_cfg *cfg)
{
	cfg->pcihdr = (void *)cfg->cfg_data + CXLV_PCI_HDR_OFFS;
	cfg->pmcap = (void *)cfg->cfg_data + CXLV_PCI_PM_CAP_OFFS;
	cfg->msixcap = (void *)cfg->cfg_data + CXLV_PCI_MSIX_CAP_OFFS;
	cfg->pciecap = (void *)cfg->cfg_data + CXLV_PCIE_CAP_OFFS;
	cfg->extcap = (void *)cfg->cfg_data + CXLV_PCI_EXT_CAP_OFFS;
}

static int pci_bridge_init(struct cxlv_pci_cfg *bridge, u64 off)
{
	pci_pointer_assign(bridge);

	pci_bridge_header_init(bridge->pcihdr, off);
	pci_pmcap_init(bridge->pmcap);
	pci_msixcap_init(bridge->msixcap);
	pci_pciecap_init(bridge->pciecap, PCI_EXP_TYPE_ROOT_PORT);
	pci_bridge_extcap_init(bridge->extcap);

	return 0;
}

static void pci_dev_init(struct cxlv_pci_cfg *dev_cfg, u64 off)
{
	pci_pointer_assign(dev_cfg);

	pci_dev_header_init((struct cxlv_pci_cfg_header *)dev_cfg->pcihdr, off);
	pci_pmcap_init(dev_cfg->pmcap);
	pci_msixcap_init(dev_cfg->msixcap);
	pci_pciecap_init(dev_cfg->pciecap, PCI_EXP_TYPE_ENDPOINT);
	pci_dev_excap_init(dev_cfg->extcap);
}

static int cxlv_pci_find_busnr(int domain_start, int *domain_ret, int *bus_ret)
{
	int domain = domain_start;
	int busnr = 0;
	struct pci_bus *bus;

	for (; domain < 255; domain++) {
		for (busnr = 0; busnr < 255; busnr++) {
			bus = pci_find_bus(domain, busnr);
			if (!bus) {
				goto found;
			}
		}
	}

	pr_err("There is no available bus number found.");

	return -1;
found:
	*domain_ret = domain;
	*bus_ret = busnr;

	return 0;
}

static int cxlv_pci_create_host_bridge(struct cxlv_device *cxlv_device)
{
	LIST_HEAD(resources);
	struct pci_bus *bus;
	int domain, busnr;
	int ret;
	static struct resource busn_res = {
	        .start = 0,
	        .end = 255,
	        .flags = IORESOURCE_BUS,
	};

	ret = cxlv_pci_find_busnr(CXLV_PCI_DOMAIN_NUM, &domain, &busnr);
	if (ret) {
		return ret;
	}

	cxlv_device->domain_nr = domain;
	cxlv_device->host_bridge_busnr = busnr;

	cxlv_pci_sysdata.domain = domain;

	pci_add_resource(&resources, &ioport_resource);
	pci_add_resource(&resources, &iomem_resource);
	pci_add_resource(&resources, &busn_res);

	bus = pci_create_root_bus(NULL, busnr, &cxlv_pci_ops, &cxlv_pci_sysdata, &resources);
	if (!bus) {
		pci_free_resource_list(&resources);
		pr_err("Unable to create PCI bus\n");
		return -1;
	}

	cxlv_device->host_bridge = to_pci_host_bridge(bus->bridge);

	/* TODO to support native cxl error */
	cxlv_device->host_bridge->native_cxl_error = 0;

	return 0;
}

int cxlv_pci_init(struct cxlv_device *cxlv_device)
{
	cxlv_pci_create_host_bridge(cxlv_device);

	pci_bridge_init(&cxlv_device->bridge_cfg, cxlv_device->opts->memstart + CXLV_BRIDGE_REG_OFF);

	pci_dev_init(&cxlv_device->dev_cfg, cxlv_device->opts->memstart + CXLV_DEV_REG_OFF);

	cxlv_pci_bus_init(cxlv_device);

	return 0;
}
