// SPDX-License-Identifier: GPL-2.0-only
/*
 * pkvm-guest-ram - map the pKVM identity guest RAM reservation for the VMM,
 * so it can load the guest kernel, FDT and initrd before first fault.
 */

#include <linux/fs.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/pkvm-guest-ram.h>

static phys_addr_t pkvm_guest_ram_base;
static u64 pkvm_guest_ram_size;

static int pkvm_guest_ram_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	u64 off = (u64)vma->vm_pgoff << PAGE_SHIFT;

	if (off >= pkvm_guest_ram_size || size > pkvm_guest_ram_size - off)
		return -EINVAL;

	/* Cacheable: the guest maps these pages cacheable too. */
	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);

	return remap_pfn_range(vma, vma->vm_start,
			       (pkvm_guest_ram_base + off) >> PAGE_SHIFT,
			       size, vma->vm_page_prot);
}

static const struct file_operations pkvm_guest_ram_fops = {
	.owner	= THIS_MODULE,
	.mmap	= pkvm_guest_ram_mmap,
	.llseek	= noop_llseek,
};

bool pkvm_guest_ram_is_vma(struct vm_area_struct *vma)
{
	return vma->vm_file && vma->vm_file->f_op == &pkvm_guest_ram_fops;
}

static struct miscdevice pkvm_guest_ram_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "pkvm-guest-ram",
	.fops	= &pkvm_guest_ram_fops,
	.mode	= 0600,
};

static int __init pkvm_guest_ram_init(void)
{
	struct device_node *np;
	struct resource res;
	int ret;

	np = of_find_compatible_node(NULL, NULL, "pkvm,identity-guest-ram");
	if (!np)
		return 0;

	ret = of_address_to_resource(np, 0, &res);
	of_node_put(np);
	if (ret) {
		pr_err("pkvm-guest-ram: node has no usable reg\n");
		return ret;
	}

	pkvm_guest_ram_base = res.start;
	pkvm_guest_ram_size = resource_size(&res);

	ret = misc_register(&pkvm_guest_ram_dev);
	if (ret) {
		pr_err("pkvm-guest-ram: failed to register: %d\n", ret);
		return ret;
	}

	pr_info("pkvm-guest-ram: 0x%llx-0x%llx available for VMM payload load\n",
		(u64)pkvm_guest_ram_base,
		(u64)(pkvm_guest_ram_base + pkvm_guest_ram_size - 1));

	return 0;
}
device_initcall(pkvm_guest_ram_init);
