#ifndef __CXLV_PCI_H__
#define __CXLV_PCI_H__
#include <linux/pci.h>

/* [PCIE 6.0] 7.5.1 PCI-Compatible Configuration Registers */
#define CXLV_PCI_BASE_ADDRESS_PA_MASK	0xFFFF8000

struct cxlv_pci_cfg_header {
	__le16 vid; /* vendor ID */
	__le16 did; /* device ID */

	__le16 command;
	__le16 status;

	u8 rid;	/* revision ID */

	struct {
		u8 pi;
		u8 scc;
		u8 bcc;
	} class_code;

	u8 cache_line_size;
	u8 latency_timer_reg;

	u8 header_type;
	u8 bist;

	__le32 bar0;
	__le32 bar1;

	union {
		struct {
			__le32 bar[4];

			__le32 cardbus_cis_pointer;

			__le16 subsystem_vendor_id;
			__le16 subsystem_id;

			__le32 expand_rom;
			u8 cap_pointer;

			u8 rsvd[7];

			u8 intr_line;
			u8 intr_pin;

			u8 min_gnt;
			u8 max_lat;
		} type0;
		struct {
			u8 primary_bus;
			u8 secondary_bus;
			u8 subordinate_bus;
			u8 secondary_latency_timer;
			u8 iobase;
			u8 iolimit;
			__le16 secondary_status;
			__le16 membase;
			__le16 memlimit;
			__le16 pref_mem_base;
			__le16 pref_mem_limit;
			__le32 prefbaseupper;
			__le32 preflimitupper;
			__le16 iobaseupper;
			__le16 iolimitupper;
			u8 capabilities_pointer;
			u8 reserve[3];
			__le32 romaddr;
			u8 intline;
			u8 intpin;
			__le16 bridgectrl;
		} type1;
	};
};

struct cxlv_pci_pm_cap {
	u8 cid;
	u8 next;

	__le16 pm_cap; /* power management capability */
	__le16 pm_ctrl_status; /* power management control status */

	u8 resv;
	u8 data;
};

struct cxlv_pci_msix_cap {
	u8 cid;
	u8 next;

	__le16 msix_ctrl;
	__le32 msix_tab;
	__le32 msix_pba; /* pending bit array */
};

/*
 * [PCIE 6.0] 7.5.3.2 PCI Express Capabilities Register
 */

/* version must be hardwired to 2h for Functions compliant */
#define CXLV_PCI_EXP_VERS_DEFAULT	2

#define CXLV_PCI_EXP_TYPE_MASK		GENMASK(7, 4)

/*
 *
 * Max payload size defined encodings are:
 *
 * 000b		128 bytes max payload size
 * 001b		256 bytes max payload size
 * 010b		512 bytes max payload size
 * 011b		1024 bytes max payload size
 * 100b		2048 bytes max payload size
 * 101b		4096 bytes max payload size
 */

/* set default max payload to 256 bytes */
#define CXLV_PCI_EXP_PAYLOAD_DEFAULT	0b001

/*
 * Endpoint L0s Acceptable Latency
 *
 * 000b		Maximum of 64 ns
 * 001b		Maximum of 128 ns
 * 010b		Maximum of 256 ns
 * 011b		Maximum of 512 ns
 * 100b		Maximum of 1 μs
 * 101b		Maximum of 2 μs
 * 110b		Maximum of 4 μs
 * 111b		No limit
 */
#define CXLV_PCI_EXP_DEVCAP_L0S_MASK	GENMASK(8, 6)
#define CXLV_PCI_EXP_DEVCAP_L0S_DEFAULT 0b110

/*
 * Endpoint L1 Acceptable Latency
 *
 * 000b		Maximum of 1 μs
 * 001b		Maximum of 2 μs
 * 010b		Maximum of 4 μs
 * 011b		Maximum of 8 μs
 * 100b		Maximum of 16 μs
 * 101b		Maximum of 32 μs
 * 110b		Maximum of 64 μs
 * 111b		No limit
 */
#define CXLV_PCI_EXP_DEVCAP_L1_MASK	GENMASK(11, 9)
#define CXLV_PCI_EXP_DEVCAP_L1_DEFAULT	0b110

struct cxlv_pcie_cap {
	u8 cid;
	u8 next;

	__le16 pcie_cap;
	__le32 pcie_dev_cap;
	__le16 pxdc;
	__le16 pxds;
	__le32 pxlcap;
	__le16 pxlc;
	__le16 pxls;

	/* not used in cxlv */
	__le32 others[10];
};

/**
 *
 * [PCIE 6.0] 7.6.3 PCI Express Extended Capability Header
 */
#define CXLV_PCI_EXT_CAP_VERS_DEFAULT	1
#define CXLV_PCI_EXT_CAP_NEXT_MASK	GENMASK(15, 4)

struct cxlv_pci_ext_cap {
	__le16 cid;
	__le16 next;
};

/*
 * cxlv memory layout
 *
 * |--dev regs (1M)---|--bridge regs (1M)---|---reserved(2M)---|----resource (rest)-----|
 */
#define CXLV_DEV_REG_OFF			0x0
#define CXLV_DEV_REG_SIZE			0x100000
#define CXLV_BRIDGE_REG_OFF			(CXLV_DEV_REG_OFF + CXLV_DEV_REG_SIZE)
#define CXLV_BRIDGE_REG_SIZE			0x100000

/* resource start from 4M offset */
#define CXLV_RESOURCE_OFF		0x400000

#define   CXLV_BAR_PCI_MSIX_OFF		0x0
#define   CXLV_MSIX_ENTRY_NUM		128
#define   CXLV_BAR_PCI_MSIX_LEN		(PCI_MSIX_ENTRY_SIZE * CXLV_MSIX_ENTRY_NUM)

#define CXLV_DEV_BAR_PCI_OFF		0x0
#define CXLV_DEV_BAR_PCI_LEN		0x10000
#define CXLV_DEV_BAR_DEV_REGS_OFF	(CXLV_DEV_BAR_PCI_OFF + CXLV_DEV_BAR_PCI_LEN)
#define CXLV_DEV_BAR_DEV_REGS_LEN	0x10000
#define CXLV_DEV_BAR_COMPONENT_OFF	(CXLV_DEV_BAR_DEV_REGS_OFF + CXLV_DEV_BAR_DEV_REGS_LEN)
#define CXLV_DEV_BAR_COMPONENT_LEN	0x10000
#define CXLV_DEV_BAR_LSA_OFF		(CXLV_DEV_BAR_COMPONENT_OFF + CXLV_DEV_BAR_COMPONENT_LEN)
#define CXLV_DEV_BAR_LSA_LEN		0x10000

#define CXLV_BRIDGE_BAR_PCI_OFF		0x0
#define CXLV_BRIDGE_BAR_PCI_LEN		0x10000
#define CXLV_BRIDGE_BAR_COMPONENT_OFF	(CXLV_BRIDGE_BAR_PCI_OFF + CXLV_BRIDGE_BAR_PCI_LEN)
#define CXLV_BRIDGE_BAR_COMPONENT_LEN	0x10000

/*
 * [CXL 3.0] 8.1.3 PCIe DVSEC for CXL Devices
 */

/*
 * DVSEC Revision ID 2h represents the structure
 * as defined in the CXL 3.0 specification.
 * */

#define CXLV_DVSEC_REVISION_MASK	GENMASK(19, 16)
#define CXLV_DVSEC_LEN_MASK		GENMASK(31, 20)

#define CXLV_DVSEC_REVISION_DEFAULT	3

struct cxlx_dvsec_header {
	struct cxlv_pci_ext_cap cap_header;
	__le32 cxl_header1;
	__le16 cxl_header2;
} __packed;

#define CXLV_DVSEC_CAP_MEM		0x4
#define CXLV_DVSEC_CAP_HDM_COUNT_MASK	GENMASK(5, 4)

#define CXLV_DVSEC_CAP_VALID		0x1
#define CXLV_DVSEC_CAP_ACTIVE		0x2
struct cxlv_pci_ext_cap_id_dvsec {
	struct cxlx_dvsec_header header;
	__le16 cap;

	__le32	skip[3];
	__le32	size_hi_1;
	__le32	size_low_1;
};

/*
 * [CXL 3.0] 8.1.9 Register Locator DVSEC
 */

#define CXLV_DVSEC_LOC_LO_TYPE_MASK	GENMASK(15, 8)
#define CXLV_DVSEC_LOC_LO_OFF_MASK	GENMASK(31, 16)
#define CXLV_DVSEC_LOC_HI_OFF_MASK	GENMASK(63, 32)
struct reg_block_loc {
	__le32 reg_block_lo_off;
	__le32 reg_block_hi_off;
};

struct cxlv_pci_ext_cap_locator {
	struct cxlx_dvsec_header header;
	struct reg_block_loc loc1;
	struct reg_block_loc loc2;
	struct reg_block_loc loc3;
};

/*
 * [CXL 3.0] 8.2.8 CXL Device Register Interface
 */

/*
 * Version: Defines the version of the capability structure present. This field shall be
 * set to 01h. Software shall check this version number during initialization to
 * determine the layout of the device capabilities, treating an unknown version number
 * as an error preventing any further access to the device by that software.
 */
#define CXLV_DEV_CAP_ARRAY_HEADER_VERS_DEFAULT	1
/*
 * Type: Identifies the type-specific capabilities in the CXL Device Capabilities Array.
 *   0h = The type is inferred from the PCI Class code. If the PCI Class code is not
 * associated with a type defined by this specification, no type-specific capabilities
 * are present.
 *   1h = Memory Device Capabilities (see Section 8.2.8.5).
 *   2h = Switch Mailbox CCI Capabilities (see Section 8.2.8.6).
 *   All other encodings are reserved.
 */
#define CXLV_DEV_CAP_ARRAY_HEADER_TYPE_MASK	GENMASK(12, 8)
#define CXLV_DEV_CAP_ARRAY_HEADER_TYPE_MEMDEV	1
#define CXLV_DEV_CAP_ARRAY_HEADER_TYPE_SWITCH	2

struct cap_array_header {
	__le16	cap_id;
	__le16	vers_type;
	__le16	cap_count;
	__le16	res[5];
} __packed;

struct cap_header {
	__le16	cap_id;
	__le16	version;
	__le32	offset;
	__le32	len;
	__le32	res2;
};

struct cxl_bar {
	struct cap_array_header cap_array_header;
	struct cap_header	cap_headers[];
};

/*
 *
 * [CXL 3.0] 8.2.8.3 Device Status Registers (Offset: Varies)
 */
struct cxl_dev_status {
	__le32	status;
	__le32	reserved;
};

/*
 * [CXL 3.0] 8.2.8.4 Mailbox Registers (Offset: Varies)
 */

/*
 * Payload Size: Size of the Command Payload registers in bytes, expressed as 2^n.
 * The minimum size is 256 bytes (n=8) and the maximum size is 1 MB (n=20).
 */
#define CXLV_MBOX_CAP_PAYLOAD_SIZE_MASK		0x1f
#define CXLV_MBOX_CAP_PAYLOAD_SIZE_DEFAULT	11	/* 2K */

struct cxlv_mbox {
	__le32 cap;
	__le32 control;
	__le64 cmd;
	__le64 status;
	__le64 bg_cmd_status;
	u8	payload[];
} __packed;

static inline bool cxlv_mbox_test_doorbell(struct cxlv_mbox *mbox)
{
	return (readl(&mbox->control) & CXLDEV_MBOX_CTRL_DOORBELL);
}

static inline void cxlv_mbox_clear_doorbell(struct cxlv_mbox *mbox)
{
	u32 val;

	val = readl(&mbox->control);
	val &= ~CXLDEV_MBOX_CTRL_DOORBELL;

	writel(val, &mbox->control);
}

static inline u16 cxlv_mbox_get_cmd(struct cxlv_mbox *mbox)
{
	return FIELD_GET(CXLDEV_MBOX_CMD_COMMAND_OPCODE_MASK, mbox->cmd);
}

static inline void cxlv_mbox_set_cmd_payload_len(struct cxlv_mbox *mbox, u16 len)
{
	u64 val;

	val = readq(&mbox->cmd);
	val |= FIELD_PREP(CXLDEV_MBOX_CMD_PAYLOAD_LENGTH_MASK, len);

	writeq(val, &mbox->cmd);
}

static inline void cxlv_mbox_set_retcode(struct cxlv_mbox *mbox, int ret)
{
	u64 val;

	val = readq(&mbox->control);
	val |= FIELD_PREP(CXLDEV_MBOX_STATUS_RET_CODE_MASK, ret);

	writeq(val, &mbox->control);
}

static inline void cxlv_mbox_copy_to_payload(struct cxlv_mbox *mbox, u32 off,
		void *p, u32 len)
{
	memcpy_toio(mbox->payload + off, p, len);
}

static inline void cxlv_mbox_copy_from_payload(struct cxlv_mbox *mbox, u32 off,
		void *p, u32 len)
{
	memcpy_fromio(p, mbox->payload + off, len);
}

/*
 * [CXL 3.0] 8.2.8.5 Memory Device Capabilities
 */

/*
 * Media Status: Describes the status of the device media.
 *  00b = Not Ready - Media training is incomplete.
 *  01b = Ready - The media trained successfully and is ready for use.
 *  10b = Error - The media failed to train or encountered an error.
 *  11b = Disabled - Access to the media is disabled.
 */
#define CXLV_MEMDEV_CAP_MEDIA_STATUS_MASK	GENMASK(3, 2)
#define CXLV_MEMDEV_CAP_MEDIA_STATUS_DEFAULT	0b01

#define CXLV_MEMDEV_CAP_MBXO_INTERFACE_READY	0x10

/*
 * Reset Needed: When nonzero, indicates the least impactful reset type needed to
 * return the device to the operational state. A cold reset is considered more impactful
 * than a warm reset. A warm reset is considered more impactful that a hot reset,
 * which is more impactful than a CXL reset. This field returns nonzero value if FW Halt
 * is set, Media Status is in the Error or Disabled state, or the Mailbox Interfaces Ready
 * does not become set.
 *  000b = Device is operational and a reset is not required
 *  001b = Cold Reset
 *  010b = Warm Reset
 *  011b = Hot Reset
 *  100b = CXL Reset (device must not report this value if it does not support CXL
 * Reset)
 * • All other encodings are reserved.
 */
#define CXLV_MEMDEV_CAP_MBOX_RESET_NEEDED_MASK		GENMASK(7, 5)
#define CXLV_MEMDEV_CAP_MBOX_RESET_NEEDED_DEFAULT	0b0

struct cxl_memdev_cap {
	__le64 status;
} __packed;

#define CXLV_DEV_CAP_MBOX_PAYLOAD	2048
#define CXLV_DEV_CAP_ARRAY_SIZE		4

#define CXLV_DEV_CAP_STATUS_OFF		(0x10 * CXLV_DEV_CAP_ARRAY_SIZE)
#define CXLV_DEV_CAP_STATUS_LEN		sizeof(struct cxl_dev_status)
#define CXLV_DEV_CAP_MEMDEV_OFF		(CXLV_DEV_CAP_STATUS_OFF + CXLV_DEV_CAP_STATUS_LEN)
#define CXLV_DEV_CAP_MEMDEV_LEN		sizeof(struct cxl_memdev_cap)
#define CXLV_DEV_CAP_MBOX_OFF		(CXLV_DEV_CAP_MEMDEV_OFF + CXLV_DEV_CAP_MEMDEV_LEN)
#define CXLV_DEV_CAP_MBOX_LEN		sizeof(struct cxlv_mbox) + CXLV_DEV_CAP_MBOX_PAYLOAD

struct cxlv_pci_ext_cap_dsn {
	struct cxlv_pci_ext_cap id;
	__le64 serial;
};

/*
 * [CXL 3.0] 8.2.3 Component Register Layout and Definition
 */

#define CXLV_COMP_CACHEMEM_OFF		4096
#define   CXLV_COMP_DECODER_OFF		1024

#define   CXLV_COMP_CACHEMEM_HDR_CAP_ID_MASK		GENMASK(15, 0)
#define   CXLV_COMP_CACHEMEM_HDR_CAP_VER_MASK		GENMASK(19, 16)
#define   CXLV_COMP_CACHEMEM_HDR_CACHEMEM_VER_MASK	GENMASK(23, 20)
#define   CXLV_COMP_CACHEMEM_HDR_ARRAY_SIZE_MASK	GENMASK(31, 24)

#define   CXLV_COMP_CACHEMEM_HDM_CAP_ID_MASK		GENMASK(15, 0)
#define   CXLV_COMP_CACHEMEM_HDM_CAP_VER_MASK		GENMASK(19, 16)
#define   CXLV_COMP_CACHEMEM_HDM_DECODER_POINTER_MASK	GENMASK(31, 20)

struct cxl_cachemem_comp {
	__le32 header;
	__le32 hdm_cap;
};

struct cxl_component {
	u8	resv1[4096];
	struct cxl_cachemem_comp	cachemem_comp;
	u8	impl_spec[49152];
	u8	arb_mux[1024];
	u8	resv2[7168];
};

/*
 * Decoder Count: Reports the number of memory address decoders
 * implemented by the component. CXL devices shall not advertise more than 10
 * decoders. CXL switches and Host Bridges may advertise up to 32 decoders.
 * 0h – 1 Decoder
 * 1h – 2 Decoders
 * 2h – 4 Decoders
 * 3h – 6 Decoders
 * 4h – 8 Decoders
 * 5h – 10 Decoders
 * 6h – 12 Decoders2
 * 7h – 14 Decoders2
 * 8h – 16 Decoders2
 * 9h – 20 Decoders2
 * Ah – 24 Decoders2
 * Bh – 28 Decoders2
 * Ch – 32 Decoders2
 * All other values are reserved
 */
#define CXLV_DECODER_CAP_DCOUNT_MASK	GENMASK(3, 0)

/*
 * Target Count: The number of target ports each decoder supports (applicable
 * only to Upstream Switch Port and CXL Host Bridge). Maximum of 8.
 * 1h – 1 target port
 * 2h – 2 target ports
 * 4h – 4 target ports
 * 8h – 8 target ports
 * All other values are reserved.
 */
#define CXLV_DECODER_CAP_TCOUNT_MASK	GENMASK(7, 4)

#define CXLV_DECODER_GLOBAL_CTRL_POISON		BIT(0)
#define CXLV_DECODER_GLOBAL_CTRL_ENABLE		BIT(1)

#define CXLV_DECODER_CTRL_IG_MASK		GENMASK(3, 0)
#define CXLV_DECODER_CTRL_IW_MASK		GENMASK(7, 4)
#define CXLV_DECODER_CTRL_COMMIT		BIT(9)
#define CXLV_DECODER_CTRL_COMMITTED		BIT(10)
#define CXLV_DECODER_CTRL_COMMIT_ERR	BIT(11)

struct cxl_decoder_regs {
	__le32	base_lo;
	__le32	base_hi;
	__le32	size_lo;
	__le32	size_hi;

	__le32 ctrl_regs;

	union {
		__le32	target_list_lo;
		__le32	dpa_skip_lo;
	};
	union {
		__le32	target_list_hi;
		__le32	dpa_skip_hi;
	};
} __packed;

struct cxl_decoder_cap {
	__le32 cap_reg;
	__le32 global_ctrl_reg;
	__le32	resv[2];
	struct cxl_decoder_regs decoder[];
} __packed;


/* use domain 0x10 instead of 0x0 to avoid race with real pci device */
#define CXLV_PCI_DOMAIN_NUM	0x10
#define CXLV_PCI_BUS_NUM	0x0

/* offset in pci configureation space */
#define CXLV_PCI_HDR_OFFS	0x0
#define CXLV_PCI_PM_CAP_OFFS	0x40
#define CXLV_PCI_MSIX_CAP_OFFS	0x50
#define CXLV_PCIE_CAP_OFFS	0x60

#define CXLV_PCI_EXT_CAP_OFFS (PCI_CFG_SPACE_SIZE)
#endif /* __CXLV_PCI_H__ */
