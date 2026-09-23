// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Google LLC
 * Author: Mostafa Saleh <smostafa@google.com>
 */
#include <linux/of_platform.h>
#include <linux/arm-smccc.h>
#include <linux/interval_tree.h>
#include <linux/iommu.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>

#define ASSERT(cond)							\
	do {								\
		if (!(cond)) {						\
			pr_err("line %d: assertion failed: %s\n",	\
			       __LINE__, #cond);			\
			return -1;					\
		}							\
	} while (0)

static DEFINE_XARRAY(pviommu_groups);

static unsigned long pgsize_bitmap;

struct pviommu_domain {
	struct iommu_domain		domain;
	unsigned long			id; /* pKVM domain ID. */
	/*
	 * IOVA -> IPA shadow of the hypervisor's tables, needed because the
	 * hypervisor offers no way to query a translation back.
	 *
	 * The IOMMU core serialises neither ->map_pages against ->unmap_pages
	 * nor either of them against ->iova_to_phys, and the DMA API allows
	 * dma_unmap_*() and dma_sync_*() from interrupt context, so every
	 * access is taken under @lock with interrupts disabled.
	 *
	 * This deliberately is not a maple tree. Its node allocator reaches
	 * kmem_cache_prefill_sheaf() for anything but a single node, which
	 * takes the SLUB percpu sheaves local_lock unconditionally, and that
	 * lock is only preempt-disable on !PREEMPT_RT. A tree write from a
	 * NAPI poll would then corrupt the sheaves of a task it interrupted.
	 * kmalloc(GFP_ATOMIC) has no such problem: its sheaf fast paths use
	 * local_trylock() and fall back on failure.
	 */
	struct rb_root_cached		mappings;
	spinlock_t			lock;
};

/* A contiguous IOVA range backed by a contiguous IPA range. */
struct pviommu_mapping {
	struct interval_tree_node	node;	/* IOVA range, inclusive. */
	phys_addr_t			paddr;	/* IPA of node.start. */
};

struct pviommu {
	struct iommu_device		iommu;
	u32				id;
};

struct pviommu_master {
	struct device			*dev;
	struct pviommu			*iommu;
	u32				ssid_bits;
	struct pviommu_domain		*domain;
};

static int smccc_to_linux_ret(u64 smccc_ret)
{
	switch (smccc_ret) {
	case SMCCC_RET_SUCCESS:
		return 0;
	case SMCCC_RET_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case SMCCC_RET_NOT_REQUIRED:
		return -ENOENT;
	case SMCCC_RET_INVALID_PARAMETER:
		return -EINVAL;
	};

	return -ENODEV;
}

static u64 __linux_prot_smccc(int iommu_prot)
{
	int prot = 0;

	if (iommu_prot & IOMMU_READ)
		prot |= ARM_SMCCC_KVM_PVIOMMU_READ;
	if (iommu_prot & IOMMU_WRITE)
		prot |= ARM_SMCCC_KVM_PVIOMMU_WRITE;
	if (iommu_prot & IOMMU_CACHE)
		prot |= ARM_SMCCC_KVM_PVIOMMU_CACHE;
	if (iommu_prot & IOMMU_NOEXEC)
		prot |= ARM_SMCCC_KVM_PVIOMMU_NOEXEC;
	if (iommu_prot & IOMMU_MMIO)
		prot |= ARM_SMCCC_KVM_PVIOMMU_MMIO;
	if (iommu_prot & IOMMU_PRIV)
		prot |= ARM_SMCCC_KVM_PVIOMMU_PRIV;

	return prot;
}

static struct pviommu_mapping *to_pviommu_mapping(struct interval_tree_node *node)
{
	return container_of(node, struct pviommu_mapping, node);
}

static void pviommu_domain_mappings_init(struct pviommu_domain *pv_domain)
{
	spin_lock_init(&pv_domain->lock);
	pv_domain->mappings = RB_ROOT_CACHED;
}

static void pviommu_domain_mappings_destroy(struct pviommu_domain *pv_domain)
{
	struct pviommu_mapping *map, *tmp;

	rbtree_postorder_for_each_entry_safe(map, tmp,
					     &pv_domain->mappings.rb_root,
					     node.rb)
		kfree(map);

	pv_domain->mappings = RB_ROOT_CACHED;
}

/*
 * Record @map over the inclusive range [@start, @end], which must not overlap
 * an existing mapping. Caller must hold pv_domain->lock.
 */
static void __pviommu_domain_insert(struct pviommu_domain *pv_domain,
				    struct pviommu_mapping *map,
				    u64 start, u64 end, phys_addr_t paddr)
{
	map->node.start = start;
	map->node.last = end;
	map->paddr = paddr;
	interval_tree_insert(&map->node, &pv_domain->mappings);
}

/*
 * Drop the inclusive range [@start, @end] from the shadow, trimming or
 * splitting the mappings it overlaps. Caller must hold pv_domain->lock.
 */
static void __pviommu_domain_punch(struct pviommu_domain *pv_domain,
				   u64 start, u64 end)
{
	struct interval_tree_node *node;

	/* The range can cover any number of mappings. */
	while ((node = interval_tree_iter_first(&pv_domain->mappings,
						start, end))) {
		struct pviommu_mapping *map = to_pviommu_mapping(node);
		struct pviommu_mapping *head = NULL, *tail = NULL;
		u64 old_start = node->start, old_end = node->last;
		phys_addr_t old_paddr = map->paddr;

		interval_tree_remove(node, &pv_domain->mappings);

		/*
		 * Reuse the node just removed for whichever part survives, so
		 * that the common case of an exact match allocates nothing and
		 * only a mapping punched in the middle needs a second node.
		 */
		if (old_start < start) {
			head = map;
			if (old_end > end)
				tail = kzalloc(sizeof(*tail), GFP_ATOMIC);
		} else if (old_end > end) {
			tail = map;
		}

		if (head)
			__pviommu_domain_insert(pv_domain, head, old_start,
						start - 1, old_paddr);

		/*
		 * A mapping records the IPA of its first byte, so a surviving
		 * tail has to be rebased rather than merely trimmed.
		 */
		if (tail)
			__pviommu_domain_insert(pv_domain, tail, end + 1, old_end,
						old_paddr + (end + 1 - old_start));
		else if (old_end > end)
			pr_err_ratelimited("pviommu: dropping shadow of [%llx, %llx]\n",
					   end + 1, old_end);

		if (!head && !tail)
			kfree(map);
	}
}

/* Ranges are inclusive for all functions. */
static void pviommu_domain_insert_map(struct pviommu_domain *pv_domain,
				      u64 start, u64 end, phys_addr_t paddr,
				      gfp_t gfp)
{
	struct pviommu_mapping *map;
	unsigned long flags;

	if (end < start)
		return;

	/* Allocated up front, as the tree is walked with interrupts disabled. */
	map = kzalloc(sizeof(*map), gfp);
	if (!map) {
		pr_err_ratelimited("pviommu: failed to record map of [%llx, %llx]\n",
				   start, end);
		return;
	}

	spin_lock_irqsave(&pv_domain->lock, flags);
	/* A new mapping replaces whatever was recorded for the range. */
	__pviommu_domain_punch(pv_domain, start, end);
	__pviommu_domain_insert(pv_domain, map, start, end, paddr);
	spin_unlock_irqrestore(&pv_domain->lock, flags);
}

static void pviommu_domain_remove_map(struct pviommu_domain *pv_domain,
				      u64 start, u64 end)
{
	unsigned long flags;

	if (end < start)
		return;

	spin_lock_irqsave(&pv_domain->lock, flags);
	__pviommu_domain_punch(pv_domain, start, end);
	spin_unlock_irqrestore(&pv_domain->lock, flags);
}

static phys_addr_t pviommu_domain_find(struct pviommu_domain *pv_domain, u64 key)
{
	struct interval_tree_node *node;
	unsigned long flags;
	phys_addr_t phys = 0;

	spin_lock_irqsave(&pv_domain->lock, flags);
	node = interval_tree_iter_first(&pv_domain->mappings, key, key);
	/* No node means the IOVA is not mapped. */
	if (node)
		phys = to_pviommu_mapping(node)->paddr + (key - node->start);
	spin_unlock_irqrestore(&pv_domain->lock, flags);

	return phys;
}

static int pviommu_map_pages(struct iommu_domain *domain, unsigned long iova,
			     phys_addr_t paddr, size_t pgsize, size_t pgcount,
			     int prot, gfp_t gfp, size_t *mapped)
{
	struct pviommu_domain *pv_domain = container_of(domain, struct pviommu_domain, domain);
	struct arm_smccc_res res = { .a0 = SMCCC_RET_SUCCESS };
	size_t requested_size = pgsize * pgcount, cur_mapped;

	*mapped = 0;
	/*
	 * The hypervisor may return success having mapped nothing, to ask the
	 * host to refill its memcache; the HVC is simply reissued. It may also
	 * fail having mapped part of the range, so @iova and @paddr have to be
	 * advanced before the error is acted on, otherwise the range recorded
	 * below is shifted down by the amount of that last partial mapping.
	 */
	while (*mapped < requested_size) {
		arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_KVM_PVIOMMU_OP_FUNC_ID,
				  KVM_PVIOMMU_OP_MAP_PAGES, pv_domain->id, iova,
				  paddr, requested_size - *mapped, __linux_prot_smccc(prot), &res);
		cur_mapped = res.a1;
		*mapped += cur_mapped;
		iova += cur_mapped;
		paddr += cur_mapped;
		if (res.a0 != SMCCC_RET_SUCCESS)
			break;
	}

	if (*mapped)
		pviommu_domain_insert_map(pv_domain, iova - *mapped, iova - 1,
					  paddr - *mapped, gfp);

	return smccc_to_linux_ret(res.a0);
}

static size_t pviommu_unmap_pages(struct iommu_domain *domain, unsigned long iova,
				  size_t pgsize, size_t pgcount,
				  struct iommu_iotlb_gather *gather)
{
	struct pviommu_domain *pv_domain = container_of(domain, struct pviommu_domain, domain);
	struct arm_smccc_res res = { .a0 = SMCCC_RET_SUCCESS };
	size_t total_unmapped = 0, unmapped, requested_size = pgsize * pgcount;

	/* @iova is advanced before the error is acted on, as in map_pages(). */
	while (total_unmapped < requested_size) {
		arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_KVM_PVIOMMU_OP_FUNC_ID,
				  KVM_PVIOMMU_OP_UNMAP_PAGES, pv_domain->id, iova,
				  requested_size - total_unmapped, 0, 0, &res);
		unmapped = res.a1;
		total_unmapped += unmapped;
		iova += unmapped;
		if (res.a0 != SMCCC_RET_SUCCESS)
			break;
	}

	if (total_unmapped)
		pviommu_domain_remove_map(pv_domain, iova - total_unmapped, iova - 1);

	return total_unmapped;
}

static phys_addr_t pviommu_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
	struct pviommu_domain *pv_domain = container_of(domain, struct pviommu_domain, domain);

	return pviommu_domain_find(pv_domain, iova);
}

static void pviommu_domain_free(struct iommu_domain *domain)
{
	struct pviommu_domain *pv_domain = container_of(domain, struct pviommu_domain, domain);
	struct arm_smccc_res res;

	arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_KVM_PVIOMMU_OP_FUNC_ID,
			  KVM_PVIOMMU_OP_FREE_DOMAIN, pv_domain->id, 0, 0, 0, 0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		pr_err("Failed to free domain %ld\n", res.a0);

	pviommu_domain_mappings_destroy(pv_domain);
	kfree(pv_domain);
}

static void pviommu_remove_dev_pasid(struct device *dev, ioasid_t pasid,
				     struct iommu_domain *domain)
{
	struct pviommu_master *master = dev_iommu_priv_get(dev);
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	struct pviommu *pv = master->iommu;
	struct pviommu_domain *pv_domain = container_of(domain, struct pviommu_domain, domain);
	struct arm_smccc_res res;
	u32 sid;
	int i;

	if (!fwspec || !pv_domain)
		return;

	for (i = 0; i < fwspec->num_ids; i++) {
		sid = fwspec->ids[i];
		arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_KVM_PVIOMMU_OP_FUNC_ID,
				  KVM_PVIOMMU_OP_DETACH_DEV,
				  pv->id, sid, pasid, pv_domain->id, 0, &res);
		if (res.a0 != SMCCC_RET_SUCCESS)
			dev_err(dev, "Failed to detach_dev sid %d, err %ld\n", sid, res.a0);
	}
}

static void pviommu_detach_dev(struct pviommu_master *master, struct iommu_domain *domain)
{
	pviommu_remove_dev_pasid(master->dev, 0, domain);
}

static int pviommu_set_dev_pasid(struct iommu_domain *domain,
				 struct device *dev, ioasid_t pasid, struct iommu_domain *old)
{
	int ret = 0, i;
	struct arm_smccc_res res;
	u32 sid;
	struct pviommu_master *master = dev_iommu_priv_get(dev);
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);
	struct pviommu_domain *pv_domain = container_of(domain, struct pviommu_domain, domain);
	struct pviommu *pv = master->iommu;

	if (!fwspec)
		return -ENOENT;

	if (old)
		pviommu_remove_dev_pasid(dev, pasid, old);

	for (i = 0; i < fwspec->num_ids; i++) {
		sid = fwspec->ids[i];
		arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_KVM_PVIOMMU_OP_FUNC_ID,
				  KVM_PVIOMMU_OP_ATTACH_DEV,
				  pv->id, sid, pasid,
				  pv_domain->id, master->ssid_bits, &res);
		if (res.a0) {
			ret = smccc_to_linux_ret(res.a0);
			break;
		}
	}

	if (ret) {
		while (i--) {
			arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_KVM_PVIOMMU_OP_FUNC_ID,
					  KVM_PVIOMMU_OP_DETACH_DEV,
					  pv->id, sid, pasid,
					  pv_domain->id, 0, &res);
		}
	}

	return ret;
}

static int pviommu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	struct iommu_domain *old = iommu_get_domain_for_dev(dev);

	return pviommu_set_dev_pasid(domain, dev, 0, old);
}

static struct iommu_domain *pviommu_domain_alloc_paging(struct device *dev)
{
	struct pviommu_domain *pv_domain;
	struct arm_smccc_res res;

	pv_domain = kzalloc(sizeof(*pv_domain), GFP_KERNEL);
	if (!pv_domain)
		return ERR_PTR(-ENOMEM);

	pviommu_domain_mappings_init(pv_domain);

	arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_KVM_PVIOMMU_OP_FUNC_ID,
			  KVM_PVIOMMU_OP_ALLOC_DOMAIN, 0, 0, 0, 0, 0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS) {
		kfree(pv_domain);
		return ERR_PTR(smccc_to_linux_ret(res.a0));
	}

	pv_domain->id = res.a1;
	pv_domain->domain.pgsize_bitmap = pgsize_bitmap;
	return &pv_domain->domain;
}

static struct platform_driver pkvm_pviommu_driver;

static struct pviommu *pviommu_get_by_fwnode(struct fwnode_handle *fwnode)
{
	struct device *dev = bus_find_device_by_fwnode(&platform_bus_type, fwnode);

	put_device(dev);
	return dev ? dev_get_drvdata(dev) : NULL;
}

static struct iommu_ops pviommu_ops;

static bool pviommu_sids_untranslated(struct pviommu *pv,
				      struct iommu_fwspec *fwspec)
{
	struct arm_smccc_res res;
	int i;

	if (!fwspec->num_ids)
		return false;

	for (i = 0; i < fwspec->num_ids; i++) {
		arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_KVM_PVIOMMU_OP_FUNC_ID,
				  KVM_PVIOMMU_OP_SID_INFO,
				  pv->id, fwspec->ids[i], 0, 0, 0, &res);
		if (res.a0 != SMCCC_RET_SUCCESS ||
		    !(res.a1 & KVM_PVIOMMU_SID_UNTRANSLATED))
			return false;
	}

	return true;
}

static struct iommu_device *pviommu_probe_device(struct device *dev)
{
	struct pviommu_master *master;
	struct pviommu *pv = NULL;
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

	if (!fwspec)
		return ERR_PTR(-ENODEV);

	pv = pviommu_get_by_fwnode(fwspec->iommu_fwnode);
	if (!pv)
		return ERR_PTR(-ENODEV);

	/*
	 * Leave a stream the hardware never translates out of the IOMMU
	 * entirely. A domain of any type, identity included, makes the DMA API
	 * hand back an address the device does not use.
	 */
	if (pviommu_sids_untranslated(pv, fwspec))
		return ERR_PTR(-ENODEV);

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return ERR_PTR(-ENOMEM);

	master->dev = dev;
	master->iommu = pv;
	device_property_read_u32(dev, "pasid-num-bits", &master->ssid_bits);
	dev_iommu_priv_set(dev, master);

	return &pv->iommu;
}

static void pviommu_release_device(struct device *dev)
{
	struct pviommu_master *master = dev_iommu_priv_get(dev);
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);

	pviommu_detach_dev(master, domain);
}

static int pviommu_of_xlate(struct device *dev, const struct of_phandle_args *args)
{
	return iommu_fwspec_add_ids(dev, args->args, args->args_count);
}

static struct iommu_group *pviommu_group_alloc_get(struct device *dev, int group_id)
{
	struct iommu_group *group;

	group = xa_load(&pviommu_groups, (unsigned long)group_id);
	if (group)
		return group;

	group = iommu_group_alloc();
	if (!IS_ERR(group))
		return group;

	if (WARN_ON(xa_insert(&pviommu_groups, (unsigned long)group_id, group, GFP_KERNEL)))
		dev_err(dev,
			"Failed to track group %d this will lead to multiple groups instead of one\n",
			group_id);

	return group;
}

static struct iommu_group *pviommu_device_group(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev_iommu_fwspec_get(dev);

	if (!fwspec)
		return ERR_PTR(-ENODEV);

	if (dev_is_pci(dev)) {
		return pci_device_group(dev);
	} else {
		if (fwspec->num_ids == 1)
			return generic_device_group(dev);
		else
			return pviommu_group_alloc_get(dev, fwspec->ids[1]);
	}
}

static struct iommu_ops pviommu_ops = {
	.device_group		= pviommu_device_group,
	.of_xlate		= pviommu_of_xlate,
	.probe_device		= pviommu_probe_device,
	.release_device		= pviommu_release_device,
	.domain_alloc_paging		= pviommu_domain_alloc_paging,
	.owner			= THIS_MODULE,
	.msi_iova_bypass	= true,
	.default_domain_ops = &(const struct iommu_domain_ops) {
		.attach_dev	= pviommu_attach_dev,
		.map_pages	= pviommu_map_pages,
		.unmap_pages	= pviommu_unmap_pages,
		.iova_to_phys	= pviommu_iova_to_phys,
		.set_dev_pasid	= pviommu_set_dev_pasid,
		.free		= pviommu_domain_free,
	}
};

static int pviommu_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pviommu *pv = devm_kmalloc(dev, sizeof(*pv), GFP_KERNEL);
	struct device_node *np = pdev->dev.of_node;
	int ret;
	struct arm_smccc_res res;

	ret = of_property_read_u32_index(np, "id", 0, &pv->id);
	if (ret) {
		dev_err(dev, "Failed to read id from device tree node %d\n", ret);
		return ret;
	}

	arm_smccc_1_1_hvc(ARM_SMCCC_VENDOR_HYP_KVM_HYP_MEMINFO_FUNC_ID, 0, 0, 0, &res);
	if (res.a0 < 0)
		return -ENODEV;

	pgsize_bitmap = res.a0;

	platform_set_drvdata(pdev, pv);

	ret = iommu_device_sysfs_add(&pv->iommu, dev, NULL,
				     "pviommu.%pa", &pv->id);

	ret = iommu_device_register(&pv->iommu, &pviommu_ops, dev);
	if (ret) {
		dev_err(dev, "Couldn't register %d\n", ret);
		iommu_device_sysfs_remove(&pv->iommu);
	}

	return ret;
}

static const struct of_device_id pviommu_of_match[] = {
	{ .compatible = "pkvm,pviommu", },
	{ },
};

static struct platform_driver pkvm_pviommu_driver = {
	.probe = pviommu_probe,
	.driver = {
		.name = "pkvm-pviommu",
		.of_match_table = pviommu_of_match,
	},
};

#if IS_ENABLED(CONFIG_PKVM_PVIOMMU_SELFTEST) && !defined(MODULE)
/* Mainly test iova_to_phys and not hypervisor interface. */
static int __init __pviommu_selftest(void)
{
	struct pviommu_domain domain;

	pr_info("pviommu selftest starting\n");

	pviommu_domain_mappings_init(&domain);

	pviommu_domain_insert_map(&domain, 0x10000, 0xFEFFF, 0xE0000, GFP_KERNEL);
	pviommu_domain_insert_map(&domain, 0xFFF0000, 0x1EDBFFFF, 0xDEAD0000,
				  GFP_KERNEL);
	ASSERT(pviommu_domain_find(&domain, 0x10000) == 0xE0000);
	ASSERT(pviommu_domain_find(&domain, 0x10F00) == 0xE0F00);
	ASSERT(pviommu_domain_find(&domain, 0x1EDBFFFF) == 0xED89FFFF);
	ASSERT(pviommu_domain_find(&domain, 0x10000000) == 0xDEAE0000);
	ASSERT(pviommu_domain_find(&domain, 0x1FF000) == 0);
	pviommu_domain_remove_map(&domain, 0x12000, 0x19FFF);
	ASSERT(pviommu_domain_find(&domain, 0x11000) == 0xE1000);
	ASSERT(pviommu_domain_find(&domain, 0x1B000) == 0xEB000);
	ASSERT(pviommu_domain_find(&domain, 0x14000) == 0);

	pviommu_domain_insert_map(&domain, 0xC00000, 0xCFFFFF, 0xABCD000, GFP_KERNEL);
	pviommu_domain_insert_map(&domain, 0xD00000, 0xDFFFFF, 0x1000, GFP_KERNEL);
	pviommu_domain_insert_map(&domain, 0xE00000, 0xEFFFFF, 0xC0FE00000,
				  GFP_KERNEL);
	ASSERT(pviommu_domain_find(&domain, 0xD00000) == 0x1000);
	pviommu_domain_remove_map(&domain, 0xC50000, 0xE5FFFF);
	ASSERT(pviommu_domain_find(&domain, 0xC50000) == 0);
	ASSERT(pviommu_domain_find(&domain, 0xD10000) == 0);
	ASSERT(pviommu_domain_find(&domain, 0xE60000) == 0xC0FE60000);
	ASSERT(pviommu_domain_find(&domain, 0xC10000) == 0xABDD000);

	pviommu_domain_mappings_destroy(&domain);
	return 0;
}

subsys_initcall(__pviommu_selftest);
#endif

module_platform_driver(pkvm_pviommu_driver);

MODULE_DESCRIPTION("IOMMU API for pKVM paravirtualized IOMMU");
MODULE_AUTHOR("Mostafa Saleh <smostafa@google.com>");
MODULE_LICENSE("GPL");
