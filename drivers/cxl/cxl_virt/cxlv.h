#ifndef __CXLV_H__
#define __CXLV_H__
#include <linux/pci.h>
#include "cxlmem.h"
#include "core.h"

#define CXLV_FW_VERSION	"CXLV VERSION 00"

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

struct cxlv_dev_options {
	u8	cxltype;
	u64	memstart;
	u64	memsize;

	bool	pmem;
};

struct cxlv_pci_cfg {
	struct cxlv_pci_cfg_header	*pcihdr;
	struct cxlv_pci_pm_cap		*pmcap;
	struct cxlv_pci_msix_cap	*msixcap;
	struct cxlv_pcie_cap		*pciecap;
	struct cxlv_pci_ext_cap		*extcap;
	u8 cfg_data[PCI_CFG_SPACE_EXP_SIZE];
};

struct cxlv_device {
	struct device dev;
	int cxlv_dev_id;

	struct cxlv_dev_options *opts;

	/* start and end should be CXLV_DEVICE_ALIGN aligned */
	u64	aligned_start;
	u64	aligned_end;

	struct cxlv_pci_cfg dev_cfg;
	struct cxlv_pci_cfg bridge_cfg;

	struct pci_dev *bridge_pdev;
	struct pci_dev *dev_pdev;

	struct task_struct *cxlv_dev_handler;

	struct cxl_port *root_port;
	int domain_nr;
	int host_bridge_busnr;
	struct pci_host_bridge *host_bridge;
};

#define CXLV_DRV_NAME "CXLVirt"
#define CXLV_VERSION 0x0110
#define CXLV_DEVICE_ID	CXLV_VERSION
#define CXLV_VENDOR_ID 0x7c73
#define CXLV_SUBSYSTEM_ID	0x9a6c
#define CXLV_SUBSYSTEM_VENDOR_ID CXLV_VENDOR_ID

#define CXLV_DEVICE_RES_MIN		(1UL * CXL_CAPACITY_MULTIPLIER)
#define CXLV_DEVICE_ALIGN		(SZ_256M)

/* cxlv_main */
extern struct bus_type cxlv_subsys;

/* cxlv_pci */
int cxlv_pci_init(struct cxlv_device *dev);
void process_mbox(struct cxlv_device *dev);
void process_decoder(struct cxlv_device *dev);

/* cxlv_port */
int cxlv_port_init(struct cxlv_device *cxlv_device);

/* cxlv_device */
int cxlv_create_dev(struct cxlv_dev_options *opts);
int cxlv_remove_dev(u32 cxlv_dev_id);
int cxlv_device_init(void);
void cxlv_device_exit(void);
struct cxlv_pci_cfg *find_pci_cfg(struct pci_bus *bus, unsigned int devfn);

/* cxlv_debugfs */
void cxlv_debugfs_cleanup(void);
int cxlv_debugfs_init(void);
#endif /*__CXLV_H__*/
