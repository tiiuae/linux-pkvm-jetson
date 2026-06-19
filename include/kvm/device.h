// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */

#ifndef __KVM_DEVICE_H
#define __KVM_DEVICE_H

#include <asm/kvm_host.h>

/*
 * @base: physical address of MMIO resource.
 * @size: size of resource in bytes.
 */
struct pkvm_dev_resource {
	u64 base;
	u64 size;
};

/*
 * @id: hypervisor ID of the IOMMU as defined by the driver.
 * @endpoint: endpoint ID of the device.
 */
struct pkvm_dev_iommu {
	u64 id;
	u64 endpoint;
};

#define PKVM_DEVICE_MAX_RESOURCE	32
#define PKVM_DEVICE_MAX_IOMMU		32

struct pkvm_device {
	struct pkvm_dev_resource resources[PKVM_DEVICE_MAX_RESOURCE];
	struct pkvm_dev_iommu iommus[PKVM_DEVICE_MAX_IOMMU];
	u32 nr_resources;
	u32 nr_iommus;
	u32 group_id;
	void *ctxt;
	unsigned short refcount;
	int (*reset_handler)(void *cookie, bool host_to_guest);
	void *cookie; /* cookie from drivers. */

	/*
	 * MSI-X table info, populated at boot before prot_finalize.
	 * EL2 uses these to validate and perform hyp-mediated MSI-X access.
	 * nr_msix_entries == 0 means device has no MSI-X capability.
	 */
	u64 msix_table_phys;	/* BAR[bir].start + table_offset */
	u32 msix_table_size;	/* nr_entries * PCI_MSIX_ENTRY_SIZE */
	u16 nr_msix_entries;	/* (PCI_MSIX_FLAGS & 0x7FF) + 1, or 0 */
	u8  msix_bir;		/* BAR Indicator Register */
	u8  msix_pad;
};

struct pkvm_monitored_resource {
	u64 base;
	u64 size;
	/* Back pointer to get the parent device from a fault address */
	struct pkvm_mediated_device *device;
	unsigned long el2_map;
	/* Store all resources in a list for searching during abort */
	struct list_head node;
};

#define PKVM_AUDIT_MAX_RESOURCE 	8

struct pkvm_dev_access {
	u64 addr; 	/* physical faulting address */
	u64 hyp_addr; 	/* hyp VA mapping for this address */
	u8 size; 	/* 1/2/4/8 */
	u64 value; 	/* in for write, out for read */
	u64 offset; 	/* offset from dev->base */
	struct user_pt_regs *regs;
	struct pkvm_monitored_resource *res;
	u16 reg; 	/* register number of the Wt/Xt/Rt operand of the faulting instruction */
	u64 esr;
};

struct pkvm_audit_ops {
	int (*read_cb)(struct pkvm_mediated_device *dev,
		       struct pkvm_dev_access *a);
	int (*write_cb)(struct pkvm_mediated_device *dev,
			struct pkvm_dev_access *a);
};

struct pkvm_mediated_device {
	/* Filled by EL1 device tree parsing */
	struct pkvm_monitored_resource resources[PKVM_AUDIT_MAX_RESOURCE];
	u32 nr_resources;
	char drv_name[64];

	/* Filled by EL2 generic device init */
	struct pkvm_audit_driver *drv;	/* currently there can only be 1 audit driver per device */

	/* Filled by EL2 in driver probe */
	struct pkvm_audit_ops *hooks;
	void *ctxt;
};

struct pkvm_audit_driver {
	unsigned short id;
	const char *name;
	int (*probe)(struct pkvm_mediated_device *dev);
	int (*handle_guest_hcall)(u64 arg1, u64 arg2, u64 arg3);
};

#endif /* #ifndef __KVM_DEVICE_H */
