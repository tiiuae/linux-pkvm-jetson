// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_hypevents.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm.h>
#include <asm/stage2_pgtable.h>

#include <hyp/fault.h>

#include <nvhe/arm-smccc.h>
#include <nvhe/errno.h>
#include <nvhe/gfp.h>
#include <nvhe/iommu.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/pkvm.h>
#include <nvhe/mm.h>
#include <nvhe/modules.h>
#ifdef CONFIG_PKVM_GUEST_TO_GUEST
#include <nvhe/serial.h>
#endif

#define KVM_HOST_S2_FLAGS (KVM_PGTABLE_S2_NOFWB | KVM_PGTABLE_S2_IDMAP)

struct host_mmu host_mmu;

struct pkvm_moveable_reg pkvm_moveable_regs[PKVM_NR_MOVEABLE_REGS];
unsigned int pkvm_moveable_regs_nr;

static struct hyp_pool host_s2_pool;
static struct hyp_pool host_s2_mmio_pool;

/* Returns TRUE if a VM-owned page has a reference held for Hyp or DMA use. */
static bool hyp_page_referenced(void *addr)
{
	struct hyp_page *p = hyp_virt_to_page(addr);

	return hyp_refcount_get(p->refcount);
}

static int host_s2_pool_refill(struct kvm_hyp_memcache *host_mc)
{
	if (!host_s2_cma_size)
		return -EINVAL;

	return refill_hyp_pool(&host_s2_pool, host_mc);
}

static void host_s2_pool_reclaim(struct kvm_hyp_memcache *host_mc, int target)
{
	if (!host_s2_cma_size)
		return;

	reclaim_hyp_pool(&host_s2_pool, host_mc, target, false);
}

static int host_s2_pool_reclaimable(void)
{
	if (!host_s2_cma_size)
		return 0;

	return hyp_pool_reclaimable(&host_s2_pool, 0);
}

struct hyp_mgt_allocator_ops host_s2_pool_ops = {
	.refill		= host_s2_pool_refill,
	.reclaim	= host_s2_pool_reclaim,
	.reclaimable	= host_s2_pool_reclaimable,
};

void make_host_stage2_reclaimable(void)
{
	if (!host_s2_cma_size)
		return;

	__hyp_pool_set_range_reclaimable(&host_s2_pool);
}

static DEFINE_PER_CPU(struct pkvm_hyp_vm *, __current_vm);
#define current_vm (*this_cpu_ptr(&__current_vm))

static void pkvm_sme_dvmsync_fw_call(void)
{
	if (alternative_has_cap_unlikely(ARM64_WORKAROUND_4193714)) {
		struct arm_smccc_res res;

		/*
		 * Ignore the return value. Probing for the workaround
		 * availability took place in init_hyp_mode().
		 */
		arm_smccc_1_1_smc(ARM_SMCCC_CPU_WORKAROUND_4193714, &res);
	}
}

static struct kvm_pgtable_pte_ops host_s2_pte_ops;
static bool host_stage2_force_pte(u64 addr, u64 end, enum kvm_pgtable_prot prot);
static bool host_stage2_pte_is_counted(kvm_pte_t pte, u32 level);
static bool guest_stage2_pte_is_counted(kvm_pte_t pte, u32 level);

static struct kvm_pgtable_pte_ops guest_s2_pte_ops = {
	.pte_is_counted_cb = guest_stage2_pte_is_counted
};

/*
 * TODO(g2g): this cannot nest. current_vm is a single per-CPU slot, consumed
 * by the guest stage-2 page allocator callbacks (guest_s2_zalloc_page() and
 * friends) to find the memcache to allocate from. Locking a second guest
 * clobbers it, and the inner unlock clears it, so the outer VM's allocations
 * would then run against a NULL current_vm.
 *
 * This is why the guest-to-guest share transitions never hold two guest locks:
 * ACCEPT reads the owner's stage-2 under the owner's lock, drops it, and maps
 * into the borrower's under the borrower's (see the lock order of the
 * guest-to-guest share transitions below). Anything that needs two guests'
 * stage-2 tables locked at once needs current_vm to become a shallow stack
 * and/or the mm_ops callbacks to take the vm explicitly, which reaches into
 * guest_s2_pte_ops and the kvm_pgtable_mm_ops plumbing.
 */
static void guest_lock_component(struct pkvm_hyp_vm *vm)
{
	hyp_spin_lock(&vm->pgtable_lock);
	current_vm = vm;
}

static void guest_unlock_component(struct pkvm_hyp_vm *vm)
{
	current_vm = NULL;
	hyp_spin_unlock(&vm->pgtable_lock);
}

static void host_lock_component(void)
{
	hyp_spin_lock(&host_mmu.lock);
}

static void host_unlock_component(void)
{
	hyp_spin_unlock(&host_mmu.lock);
}

static void hyp_lock_component(void)
{
	hyp_spin_lock(&pkvm_pgd_lock);
}

static void hyp_unlock_component(void)
{
	hyp_spin_unlock(&pkvm_pgd_lock);
}

#define for_each_hyp_page(__p, __st, __sz)				\
	for (struct hyp_page *__p = hyp_phys_to_page(__st),		\
			     *__e = __p + ((__sz) >> PAGE_SHIFT);	\
	     __p < __e; __p++)

static void *host_s2_zalloc_pages_exact(size_t size)
{
	void *addr = hyp_alloc_pages(&host_s2_pool, get_order(size));

	hyp_split_page(hyp_virt_to_page(addr));

	/*
	 * The size of concatenated PGDs is always a power of two of PAGE_SIZE,
	 * so there should be no need to free any of the tail pages to make the
	 * allocation exact.
	 */
	WARN_ON(size != (PAGE_SIZE << get_order(size)));

	return addr;
}

static void *host_s2_zalloc_page(void *pool)
{
	return hyp_alloc_pages(pool, 0);
}

static struct hyp_pool *page_to_pool(void *addr)
{
	return hyp_pool_owned(&host_s2_pool, addr) ? &host_s2_pool : &host_s2_mmio_pool;
}

static struct hyp_pool *region_to_pool(bool is_memory)
{
	return is_memory ? &host_s2_pool : &host_s2_mmio_pool;
}

static void host_s2_get_page(void *addr)
{
	hyp_get_page(page_to_pool(addr), addr);
}

static void host_s2_put_page(void *addr)
{
	hyp_put_page(page_to_pool(addr), addr);
}

static void host_s2_free_unlinked_table(void *addr, s8 level)
{
	kvm_pgtable_stage2_free_unlinked(&host_mmu.mm_ops, host_mmu.pgt.pte_ops,
					 addr, level);
}

static int prepare_s2_pool(void *pgt_pool_base, void *mmio_pool_base)
{
	unsigned long nr_pages, pfn;
	int ret;

	pfn = hyp_virt_to_pfn(pgt_pool_base);
	nr_pages = host_s2_cma_size ? host_s2_cma_size >> PAGE_SHIFT : host_s2_pgtable_pages();
	ret = hyp_pool_init(&host_s2_pool, pfn, nr_pages, 0);
	if (ret)
		return ret;

	pfn = hyp_virt_to_pfn(mmio_pool_base);
	nr_pages = host_s2_mmio_pgtable_pages();
	ret = hyp_pool_init(&host_s2_mmio_pool, pfn, nr_pages, 0);
	if (ret)
		return ret;

	host_mmu.mm_ops = (struct kvm_pgtable_mm_ops) {
		.zalloc_pages_exact = host_s2_zalloc_pages_exact,
		.zalloc_page = host_s2_zalloc_page,
		.free_unlinked_table = host_s2_free_unlinked_table,
		.phys_to_virt = hyp_phys_to_virt,
		.virt_to_phys = hyp_virt_to_phys,
		.page_count = hyp_page_count,
		.get_page = host_s2_get_page,
		.put_page = host_s2_put_page,
	};

	return 0;
}

static void prepare_host_vtcr(void)
{
	u32 parange, phys_shift;

	/* The host stage 2 is id-mapped, so use parange for T0SZ */
	parange = kvm_get_parange(id_aa64mmfr0_el1_sys_val);
	phys_shift = id_aa64mmfr0_parange_to_phys_shift(parange);

	host_mmu.arch.mmu.vtcr = kvm_get_vtcr(id_aa64mmfr0_el1_sys_val,
					      id_aa64mmfr1_el1_sys_val, phys_shift);
}

static bool range_has_reclaimable_host_s2(u64 addr, u64 end)
{
	u64 cma_end = host_s2_cma_base + host_s2_cma_size;

	if (!host_s2_cma_size)
		return false;

	return addr < cma_end && end > host_s2_cma_base;
}

/* Enrolled for assignment: donated via the device path, not host RAM. */
static bool addr_in_assign_region(phys_addr_t addr)
{
	unsigned int i;

	for (i = 0; i < pkvm_moveable_regs_nr; i++) {
		struct pkvm_moveable_reg *r = &pkvm_moveable_regs[i];

		if (r->type != PKVM_MREG_ASSIGN_MMIO)
			continue;
		if (addr >= r->start && addr < r->start + r->size)
			return true;
	}
	return false;
}

static int prepopulate_host_stage2(void)
{
	struct memblock_region *reg;
	int i, ret = 0;

	for (i = 0; i < hyp_memblock_nr; i++) {
		reg = &hyp_memory[i];
		u64 base, size;

		base = reg->base;
		size = reg->size;

		if (range_has_reclaimable_host_s2(base, base + size)) {
			ret = host_stage2_idmap_locked(reg->base, host_s2_cma_base - base,
						       PKVM_HOST_MEM_PROT, true);
			if (ret)
				return ret;

			ret = host_stage2_idmap_locked(host_s2_cma_base, host_s2_cma_size,
						       PKVM_HOST_MEM_PROT, true);
			if (ret)
				return ret;

			base = host_s2_cma_base + host_s2_cma_size;
			size = reg->base + reg->size - base;
		}

		ret = host_stage2_idmap_locked(base, size, PKVM_HOST_MEM_PROT, true);
		if (ret)
			return ret;
	}

	return ret;
}

int kvm_host_prepare_stage2(void *pgt_pool_base, void *mmio_pool_base)
{
	struct kvm_s2_mmu *mmu = &host_mmu.arch.mmu;
	int ret;

	prepare_host_vtcr();
	hyp_spin_lock_init(&host_mmu.lock);
	mmu->arch = &host_mmu.arch;

	ret = prepare_s2_pool(pgt_pool_base, mmio_pool_base);
	if (ret)
		return ret;

	host_s2_pte_ops.force_pte_cb = host_stage2_force_pte;
	host_s2_pte_ops.pte_is_counted_cb = host_stage2_pte_is_counted;

	ret = __kvm_pgtable_stage2_init(&host_mmu.pgt, mmu,
					&host_mmu.mm_ops, KVM_HOST_S2_FLAGS,
					&host_s2_pte_ops);
	if (ret)
		return ret;

	mmu->pgd_phys = __hyp_pa(host_mmu.pgt.pgd);
	mmu->pgt = &host_mmu.pgt;
	atomic64_set(&mmu->vmid.id, 0);

	return prepopulate_host_stage2();
}

enum host_set_page_state_flags {
	HOST_SET_IS_MMIO                = BIT(0),
	HOST_SET_NO_IOMMU_UPDATE        = BIT(1),
	HOST_SET_NO_COMPLETE            = BIT(2), /* Skip __host_stage2_set_owner_complete() */
	HOST_SET_PSCI_MEM_PROTECT	= BIT(3),
};

static int __host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id,
					  enum pkvm_page_state nopage_state,
					  enum host_set_page_state_flags flags);


static bool guest_stage2_pte_is_counted(kvm_pte_t pte, u32 level)
{
	/*
	 * The refcount tracks valid entries as well as invalid entries if they
	 * encode ownership of a page to another entity than the page-table
	 * owner, whose id is 0.
	 */
	return !!pte;
}

static void *guest_s2_zalloc_pages_exact(size_t size)
{
	void *addr = hyp_alloc_pages(&current_vm->pool, get_order(size));

	WARN_ON(!addr || size != (PAGE_SIZE << get_order(size)));
	hyp_split_page(hyp_virt_to_page(addr));

	return addr;
}

static void guest_s2_free_pages_exact(void *addr, unsigned long size)
{
	u8 order = get_order(size);
	unsigned int i;

	for (i = 0; i < (1 << order); i++)
		hyp_put_page(&current_vm->pool, addr + (i * PAGE_SIZE));
}

static void *guest_s2_zalloc_page(void *mc)
{
	struct hyp_page *p;
	void *addr;
	unsigned long order;

	addr = hyp_alloc_pages(&current_vm->pool, 0);
	if (addr)
		return addr;

	addr = pop_hyp_memcache(mc, hyp_phys_to_virt, &order);
	if (!addr)
		return addr;

	WARN_ON(order);
	memset(addr, 0, PAGE_SIZE);
	p = hyp_virt_to_page(addr);
	hyp_set_page_refcounted(p);
	p->order = 0;

	return addr;
}

static void guest_s2_get_page(void *addr)
{
	hyp_get_page(&current_vm->pool, addr);
}

static void guest_s2_put_page(void *addr)
{
	hyp_put_page(&current_vm->pool, addr);
}

static void guest_s2_free_unlinked_table(void *addr, s8 level)
{
	/* We are trying to collapse a table into a block mapping. This is forbidden. */
	WARN_ON(1);
}

static void __apply_guest_page(void *va, size_t size,
			       void (*func)(void *addr, size_t size))
{
	size += va - PTR_ALIGN_DOWN(va, PAGE_SIZE);
	va = PTR_ALIGN_DOWN(va, PAGE_SIZE);
	size = PAGE_ALIGN(size);

	while (size) {
		size_t map_size = PAGE_SIZE;
		void *map;

		if (IS_ALIGNED((unsigned long)va, PMD_SIZE) && size >= PMD_SIZE)
			map = hyp_fixblock_map(__hyp_pa(va), &map_size);
		else
			map = hyp_fixmap_map(__hyp_pa(va));

		func(map, map_size);

		if (map_size == PMD_SIZE)
			hyp_fixblock_unmap();
		else
			hyp_fixmap_unmap();

		size -= map_size;
		va += map_size;
	}
}

static void clean_dcache_guest_page(void *va, size_t size)
{
	__apply_guest_page(va, size, __clean_dcache_guest_page);
}

static void invalidate_icache_guest_page(void *va, size_t size)
{
	__apply_guest_page(va, size, __invalidate_icache_guest_page);
}

static void __hyp_flush_page(void *addr, size_t size)
{
	/*
	 * Prefer kvm_flush_dcache_to_poc() over __clean_dcache_guest_page()
	 * here as the latter may elide the CMO under the assumption that FWB
	 * will be enabled on CPUs that support it. This is incorrect for the
	 * host stage-2 and would otherwise lead to a malicious host potentially
	 * being able to read the contents of newly reclaimed guest pages.
	 */
	kvm_flush_dcache_to_poc(addr, size);
}

static void hyp_flush_page(phys_addr_t phys, size_t size)
{
	__apply_guest_page(__hyp_va(phys), size, __hyp_flush_page);
}

int kvm_guest_prepare_stage2(struct pkvm_hyp_vm *vm, void *pgd,
			     enum kvm_pgtable_stage2_flags flags)
{
	struct kvm_s2_mmu *mmu = &vm->kvm.arch.mmu;
	unsigned long nr_pages;
	int ret;

	nr_pages = kvm_pgtable_stage2_pgd_size(mmu->vtcr) >> PAGE_SHIFT;
	ret = hyp_pool_init(&vm->pool, hyp_virt_to_pfn(pgd), nr_pages, 0);
	if (ret)
		return ret;

	hyp_spin_lock_init(&vm->pgtable_lock);
	vm->mm_ops = (struct kvm_pgtable_mm_ops) {
		.zalloc_pages_exact	= guest_s2_zalloc_pages_exact,
		.free_pages_exact	= guest_s2_free_pages_exact,
		.zalloc_page		= guest_s2_zalloc_page,
		.free_unlinked_table	= guest_s2_free_unlinked_table,
		.phys_to_virt		= hyp_phys_to_virt,
		.virt_to_phys		= hyp_virt_to_phys,
		.page_count		= hyp_page_count,
		.get_page		= guest_s2_get_page,
		.put_page		= guest_s2_put_page,
		.dcache_clean_inval_poc	= clean_dcache_guest_page,
		.icache_inval_pou	= invalidate_icache_guest_page,
	};

	guest_lock_component(vm);
	ret = __kvm_pgtable_stage2_init(mmu->pgt, mmu, &vm->mm_ops, flags,
					&guest_s2_pte_ops);
	guest_unlock_component(vm);
	if (ret)
		return ret;

	vm->kvm.arch.mmu.pgd_phys = __hyp_pa(vm->pgt.pgd);

	return 0;
}

void destroy_hyp_vm_pgt(struct pkvm_hyp_vm *vm)
{
	guest_lock_component(vm);
	kvm_pgtable_stage2_destroy(&vm->pgt);
	vm->kvm.arch.mmu.pgd_phys = 0ULL;
	guest_unlock_component(vm);
}

void drain_hyp_pool(struct hyp_pool *pool, struct kvm_hyp_memcache *mc)
{
	WARN_ON(reclaim_hyp_pool(pool, mc, INT_MAX, true) != -ENOMEM);
}

static int ___pkvm_guest_relinquish_to_module(struct pkvm_hyp_vcpu *vcpu, u64 ipa, u64 phys,
					      kvm_pte_t pte)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct hyp_page *page;

	if (pkvm_getstate(kvm_pgtable_stage2_pte_prot(pte)) != PKVM_PAGE_SHARED_BORROWED)
		return -EPERM;

	page = hyp_phys_to_page(phys);
	if (get_host_state(page) != PKVM_MODULE_SHARED_OWNED_PAGE)
		return -EPERM;

	/*
	 * We're guaranteed by the caller to be operating on existing last-level entries, so no
	 * risk of getting -ENOMEM here.
	 */
	WARN_ON(kvm_pgtable_stage2_annotate(&vm->pgt, ipa, PAGE_SIZE, &vcpu->vcpu.arch.stage2_mc,
					    KVM_ACCEPT_MODULE_PROT_NOTE));
	set_host_state(page, PKVM_MODULE_OWNED_PAGE);

	return 0;
}

static enum pkvm_page_state guest_get_page_state(kvm_pte_t pte, u64 addr);

/*
 * TODO(g2g): this path poisons a page on its way out of a guest and hands
 * ownership to the host. It requires the page to be PKVM_PAGE_OWNED, so a
 * page that VM A has offered to a peer (PKVM_PAGE_SHARED_OWNED |
 * PKVM_PAGE_G2G) is refused here with -EPERM, like any page in the wrong
 * state. That is the safe answer but not an informative one: either keep
 * refusing, with an error the caller can tell apart, or revoke the share
 * first. It must never poison while a peer still has the page mapped.
 */
int __pkvm_guest_relinquish_to_host(struct pkvm_hyp_vcpu *vcpu,
				    u64 ipa, u64 flags, u64 *ppa)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	enum pkvm_page_state state;
	u64 phys = 0, addr;
	kvm_pte_t pte;
	s8 level;
	int ret;

	if (!pkvm_hyp_vcpu_is_protected(vcpu))
		return 0;

	if (ipa & ~PAGE_MASK)
		return -EINVAL;

	host_lock_component();
	guest_lock_component(vm);

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret || !kvm_pte_valid(pte))
		goto end;

	/* We don't support splitting non-leaf mappings */
	if (level != KVM_PGTABLE_LAST_LEVEL) {
		ret = -E2BIG;
		goto end;
	}

	addr = ALIGN_DOWN(ipa, kvm_granule_size(level));
	phys = kvm_pte_to_phys(pte);
	phys += ipa - addr;
	if (!addr_is_memory(phys)) {
		ret = -EPERM;
		goto end;
	}
	/* page might be used for DMA! */
	if (hyp_page_referenced(hyp_phys_to_virt(phys))) {
		ret = -EBUSY;
		goto end;
	}

	state = guest_get_page_state(pte, addr);
	if (state != PKVM_PAGE_OWNED) {
		ret = ___pkvm_guest_relinquish_to_module(vcpu, ipa, phys, pte);
		goto end;
	}

	/* Zap the guest stage2 pte and return ownership to the host */
	WARN_ON(kvm_pgtable_stage2_unmap(&vm->pgt, ipa, PAGE_SIZE));

	if (!(flags & KVM_FUNC_MEM_RELINQUISH_NO_POISON))
		hyp_poison_page(phys, PAGE_SIZE);
	else
		hyp_flush_page(phys, PAGE_SIZE);

	ret = __host_stage2_set_owner_locked(phys, PAGE_SIZE, PKVM_ID_HOST, 0,
					     HOST_SET_PSCI_MEM_PROTECT);
	if (ret) {
		WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, phys,
					       pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED),
					       &vcpu->vcpu.arch.stage2_mc, 0));
		goto end;
	}

	if (pkvm_ipa_range_has_pvmfw(vm, ipa, ipa + PAGE_SIZE))
		vm->pvmfw_relinquished = true;
end:
	guest_unlock_component(vm);
	host_unlock_component();

	*ppa = phys;

	return ret;
}

static void pkvm_init_params_finalize(struct kvm_nvhe_init_params *params)
{
	struct kvm_s2_mmu *mmu = &host_mmu.arch.mmu;

	params->vttbr = kvm_get_vttbr(mmu);
	params->vtcr = mmu->vtcr;
	params->hcr_el2 |= HCR_VM;

	/*
	 * The CMO below not only cleans the updated params to the
	 * PoC, but also provides the DSB that ensures ongoing
	 * page-table walks that have started before we trapped to EL2
	 * have completed.
	 */
	kvm_flush_dcache_to_poc(params, sizeof(*params));
}

void __pkvm_late_cpus_finalize(void)
{
	struct kvm_nvhe_init_params *params;
	unsigned long i;

	for (i = 0; i < hyp_nr_cpus; i++) {
		if (!test_bit(KVM_HOST_DATA_FLAG_PKVM_LATE_CPU,
			      &per_cpu_ptr(&kvm_host_data, i)->flags))
			continue;

		params = per_cpu_ptr(&kvm_init_params, i);
		pkvm_init_params_finalize(params);

		/* For CPUs we've not seen before, assume the worst */
		if (!*per_cpu_ptr(&kvm_hyp_vector, i))
			__pkvm_cpu_set_vector(HYP_VECTOR_INDIRECT, i);
	}

	__pkvm_close_module_registration();
}

int __pkvm_prot_finalize(void)
{
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);

	if (read_sysreg(HCR_EL2) & HCR_VM)
		return -EINVAL;

	pkvm_init_params_finalize(params);

	write_sysreg_hcr(params->hcr_el2);
	__load_stage2(&host_mmu.arch.mmu, &host_mmu.arch);

	/*
	 * Make sure to have an ISB before the TLB maintenance below but only
	 * when __load_stage2() doesn't include one already.
	 */
	asm(ALTERNATIVE("isb", "nop", ARM64_WORKAROUND_SPECULATIVE_AT));

	/* Invalidate stale HCR bits that may be cached in TLBs */
	__tlbi(vmalls12e1);
	dsb(nsh);
	isb();

	return 0;
}

int host_stage2_unmap_reg_locked(phys_addr_t start, u64 size)
{
	hyp_assert_lock_held(&host_mmu.lock);

	return kvm_pgtable_stage2_reclaim_leaves(&host_mmu.pgt, start, size);
}

static int host_stage2_unmap_unmoveable_regs(void)
{
	struct kvm_pgtable *pgt = &host_mmu.pgt;
	struct pkvm_moveable_reg *reg;
	u64 addr = 0;
	int i, ret;

	/* Unmap all unmoveable regions to recycle the pages */
	for (i = 0; i < pkvm_moveable_regs_nr; i++) {
		reg = &pkvm_moveable_regs[i];
		if (reg->start > addr) {
			ret = host_stage2_unmap_reg_locked(addr, reg->start - addr);
			if (ret)
				return ret;
		}
		addr = max(addr, reg->start + reg->size);
	}
	return host_stage2_unmap_reg_locked(addr, BIT(pgt->ia_bits) - addr);
}

/*
 * Ensure the PFN range is contained within PA-range.
 *
 * This check is also robust to overflows and is therefore a requirement before
 * using a pfn/nr_pages pair from an untrusted source.
 */
static bool pfn_range_is_valid(u64 pfn, u64 nr_pages)
{
	u64 limit = BIT(kvm_phys_shift(&host_mmu.arch.mmu) - PAGE_SHIFT);

	return pfn < limit && ((limit - pfn) >= nr_pages);
}

struct kvm_mem_range {
	u64 start;
	u64 end;
};

static struct memblock_region *find_mem_range(phys_addr_t addr, struct kvm_mem_range *range)
{
	int cur, left = 0, right = hyp_memblock_nr;
	struct memblock_region *reg;
	phys_addr_t end;

	range->start = 0;
	range->end = ULONG_MAX;

	/* The list of memblock regions is sorted, binary search it */
	while (left < right) {
		cur = (left + right) >> 1;
		reg = &hyp_memory[cur];
		end = reg->base + reg->size;
		if (addr < reg->base) {
			right = cur;
			range->end = reg->base;
		} else if (addr >= end) {
			left = cur + 1;
			range->start = end;
		} else {
			range->start = reg->base;
			range->end = end;
			return reg;
		}
	}

	return NULL;
}

static enum kvm_pgtable_prot default_host_prot(bool is_memory)
{
	return is_memory ? PKVM_HOST_MEM_PROT : PKVM_HOST_MMIO_PROT;
}

static enum kvm_pgtable_prot default_hyp_prot(phys_addr_t phys)
{
	return addr_is_memory(phys) ? PAGE_HYP : PAGE_HYP_DEVICE;
}

bool addr_is_memory(phys_addr_t phys)
{
	struct kvm_mem_range range;

	return !!find_mem_range(phys, &range);
}

bool addr_is_hyp_text(phys_addr_t phys)
{
	phys_addr_t start = ALIGN_DOWN(__hyp_pa(__hyp_text_start), PAGE_SIZE);
	phys_addr_t end = PAGE_ALIGN(__hyp_pa(__hyp_text_end));

	return phys >= start && phys < end;
}

static bool is_in_mem_range(u64 addr, struct kvm_mem_range *range)
{
	return range->start <= addr && addr < range->end;
}

static int check_range_allowed_memory(u64 start, u64 end)
{
	struct memblock_region *reg;
	struct kvm_mem_range range;

	/*
	 * Callers can't check the state of a range that overlaps memory and
	 * MMIO regions, so ensure [start, end[ is in the same kvm_mem_range.
	 */
	reg = find_mem_range(start, &range);
	if (!is_in_mem_range(end - 1, &range))
		return -EINVAL;

	if (!reg || reg->flags & MEMBLOCK_NOMAP)
		return -EPERM;

	return 0;
}

static bool range_is_memory(u64 start, u64 end)
{
	struct kvm_mem_range r;

	if (!find_mem_range(start, &r))
		return false;

	return is_in_mem_range(end - 1, &r);
}

/*
 * The pool has been provided with enough pages to cover all of moveable regions
 * with page granularity, but it is difficult to know how much of the
 * non-moveable regions we will need to cover upfront, so we may need to
 * 'recycle' the pages if we run out.
 */
#define host_stage2_try(is_memory, fn, ...)				\
	({								\
		int __ret;						\
		hyp_assert_lock_held(&host_mmu.lock);			\
		__ret = fn(__VA_ARGS__);				\
		if (!(is_memory) && __ret == -ENOMEM) {			\
			__ret = host_stage2_unmap_unmoveable_regs();	\
			if (!__ret)					\
				__ret = fn(__VA_ARGS__);		\
		}							\
		__ret;							\
	 })

static inline bool range_included(struct kvm_mem_range *child,
				  struct kvm_mem_range *parent)
{
	return parent->start <= child->start && child->end <= parent->end;
}

static int host_stage2_adjust_range(u64 addr, struct kvm_mem_range *range)
{
	struct kvm_mem_range cur;
	kvm_pte_t pte;
	u64 granule;
	s8 level;
	int ret;

	hyp_assert_lock_held(&host_mmu.lock);
	ret = kvm_pgtable_get_leaf(&host_mmu.pgt, addr, &pte, &level);
	if (ret)
		return ret;

	if (kvm_pte_valid(pte))
		return -EAGAIN;

	if (pte)
		return -EPERM;

	for (; level <= KVM_PGTABLE_LAST_LEVEL; level++) {
		if (!kvm_level_supports_block_mapping(level))
			continue;
		granule = kvm_granule_size(level);
		cur.start = ALIGN_DOWN(addr, granule);
		cur.end = cur.start + granule;
		if (!range_included(&cur, range) && level < KVM_PGTABLE_LAST_LEVEL)
			continue;
		*range = cur;
		return 0;
	}

	WARN_ON(1);

	return -EINVAL;
}

static int __host_stage2_idmap(phys_addr_t addr, u64 size, enum kvm_pgtable_prot prot,
			       bool is_memory)
{
	struct kvm_pgtable *pgt = &host_mmu.pgt;
	void *mc = region_to_pool(is_memory);
	int ret;

	ret = host_stage2_try(is_memory, kvm_pgtable_stage2_map, pgt, addr,
			      size, addr, prot, mc, 0);
	if (is_memory && ret == -ENOMEM)
		ret = -ENOMEMHOSTS2;

	return ret;
}

static void __host_stage2_idmap_complete(enum kvm_pgtable_prot prot)
{
	if ((prot & KVM_PGTABLE_PROT_RW) != KVM_PGTABLE_PROT_RW)
		pkvm_sme_dvmsync_fw_call();
}

int host_stage2_idmap_locked(phys_addr_t addr, u64 size, enum kvm_pgtable_prot prot, bool is_memory)
{
	int ret = __host_stage2_idmap(addr, size, prot, is_memory);

	if (ret)
		return ret;

	__host_stage2_idmap_complete(prot);

	return 0;
}

static void __host_update_page_state(phys_addr_t addr, u64 size, enum pkvm_page_state state)
{
	for_each_hyp_page(page, addr, size)
		set_host_state(page, state);
}

#define KVM_MAX_OWNER_ID		PKVM_ID_MAX

static kvm_pte_t kvm_init_invalid_leaf_owner(u8 owner_id)
{
	return FIELD_PREP(KVM_INVALID_PTE_OWNER_MASK, owner_id);
}

static void __host_stage2_set_owner_complete(u8 owner_id, enum host_set_page_state_flags flags)
{
	bool is_memory = !(flags & HOST_SET_IS_MMIO);
	bool map = owner_id == PKVM_ID_HOST;

	hyp_assert_lock_held(&host_mmu.lock);

	__host_stage2_idmap_complete(map ? default_host_prot(is_memory) : 0);

	if (flags & HOST_SET_NO_IOMMU_UPDATE)
		return;

	kvm_iommu_host_stage2_idmap_complete(map);
}

static int __host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id,
					  enum pkvm_page_state nopage_state,
					  enum host_set_page_state_flags flags)
{
	bool is_memory = !(flags & HOST_SET_IS_MMIO);
	kvm_pte_t annotation;
	enum kvm_pgtable_prot prot;
	int ret;

	if (owner_id > KVM_MAX_OWNER_ID)
		return -EINVAL;

	if (owner_id == PKVM_ID_HOST) {
		prot = default_host_prot(is_memory);
		ret = __host_stage2_idmap(addr, size, prot, is_memory);
	} else {
		annotation = kvm_init_invalid_leaf_owner(owner_id);
		ret = host_stage2_try(is_memory, kvm_pgtable_stage2_annotate,
				      &host_mmu.pgt, addr, size,
				      region_to_pool(is_memory), annotation);
		if (is_memory && ret == -ENOMEM)
			ret = -ENOMEMHOSTS2;
	}

	if (ret) {
		WARN_ON(ret != -ENOMEMHOSTS2);
		return ret;
	}

	if (flags & HOST_SET_NO_IOMMU_UPDATE)
		goto psci_mem_protect;

	prot = owner_id == PKVM_ID_HOST ? PKVM_HOST_MEM_PROT : 0;
	WARN_ON(kvm_iommu_host_stage2_idmap(addr, addr + size, prot));

psci_mem_protect:
	if (flags & HOST_SET_PSCI_MEM_PROTECT) {
		if (owner_id == PKVM_ID_HOST)
			psci_mem_protect_dec(size >> PAGE_SHIFT);
		else
			psci_mem_protect_inc(size >> PAGE_SHIFT);
	}

	if (flags & HOST_SET_NO_COMPLETE)
		goto update_vmemmap;

	__host_stage2_set_owner_complete(owner_id, flags);

update_vmemmap:
	if (!is_memory)
		return 0;

	/* Don't forget to update the vmemmap tracking for the host */
	if (owner_id == PKVM_ID_HOST)
		__host_update_page_state(addr, size, PKVM_PAGE_OWNED);
	else
		__host_update_page_state(addr, size, PKVM_NOPAGE | nopage_state);

	return 0;
}

int host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id)
{
	return __host_stage2_set_owner_locked(addr, size, owner_id, 0,
					      addr_is_memory(addr) ? 0 : HOST_SET_IS_MMIO);
}

bool host_stage2_pte_is_hyp_owned(kvm_pte_t pte)
{
	if (kvm_pte_valid(pte))
		return false;

	return FIELD_GET(KVM_INVALID_PTE_OWNER_MASK, pte) == PKVM_ID_HYP;
}

static bool host_stage2_force_pte(u64 addr, u64 end, enum kvm_pgtable_prot prot)
{
	if (range_has_reclaimable_host_s2(addr, end))
		return true;

	/*
	 * Block mappings must be used with care in the host stage-2 as a
	 * kvm_pgtable_stage2_map() operation targeting a page in the range of
	 * an existing block will delete the block under the assumption that
	 * mappings in the rest of the block range can always be rebuilt lazily.
	 * That assumption is correct for the host stage-2 with RWX mappings
	 * targeting memory or RW mappings targeting MMIO ranges (see
	 * host_stage2_idmap() below which implements some of the host memory
	 * abort logic). However, this is not safe for any other mappings where
	 * the host stage-2 page-table is in fact the only place where this
	 * state is stored. In all those cases, it is safer to use page-level
	 * mappings, hence avoiding to lose the state because of side-effects in
	 * kvm_pgtable_stage2_map().
	 */
	return prot != default_host_prot(range_is_memory(addr, end));
}

static bool host_stage2_pte_is_counted(kvm_pte_t pte, u32 level)
{
	u64 phys;

	if (!kvm_pte_valid(pte))
		return !!pte;

	if (kvm_pte_table(pte, level))
		return true;

	phys = kvm_pte_to_phys(pte);
	if (addr_is_memory(phys))
		return (pte & KVM_HOST_S2_DEFAULT_MASK) !=
			KVM_HOST_S2_DEFAULT_MEM_PTE;

	return (pte & KVM_HOST_S2_DEFAULT_MASK) != KVM_HOST_S2_DEFAULT_MMIO_PTE;
}

static int host_stage2_fault(u64 addr)
{
	struct kvm_mem_range range;
	bool is_memory = !!find_mem_range(addr, &range);
	enum kvm_pgtable_prot prot = default_host_prot(is_memory);
	int ret;

	host_lock_component();
	ret = host_stage2_adjust_range(addr, &range);
	if (ret)
		goto unlock;

	/* Should never happen: host stage-2 memory region is prefaulted */
	WARN_ON(is_memory);

	ret = host_stage2_idmap_locked(range.start, range.end - range.start, prot, false);
unlock:
	host_unlock_component();

	return ret;
}

static void (*illegal_abt_notifier)(struct user_pt_regs *regs);

int __pkvm_register_illegal_abt_notifier(void (*cb)(struct user_pt_regs *))
{
	/*
	 * Paired with smp_load_acquire(&illegal_abt_notifier) in
	 * host_inject_abort(). Ensure the module's stores before registration
	 * are observed before the callback runs.
	 */
	return cmpxchg_release(&illegal_abt_notifier, NULL, cb) ? -EBUSY : 0;
}

static void host_inject_abort(struct kvm_cpu_context *host_ctxt)
{
	u64 spsr = read_sysreg_el2(SYS_SPSR);
	u64 esr = read_sysreg_el2(SYS_ESR);
	u64 ventry, ec;

	/* Acquire the callback published by __pkvm_register_illegal_abt_notifier(). */
	if (smp_load_acquire(&illegal_abt_notifier))
		illegal_abt_notifier(&host_ctxt->regs);

	/* Repaint the ESR to report a same-level fault if taken from EL1 */
	if ((spsr & PSR_MODE_MASK) != PSR_MODE_EL0t) {
		ec = ESR_ELx_EC(esr);
		if (ec == ESR_ELx_EC_DABT_LOW)
			ec = ESR_ELx_EC_DABT_CUR;
		else if (ec == ESR_ELx_EC_IABT_LOW)
			ec = ESR_ELx_EC_IABT_CUR;
		else
			WARN_ON(1);
		esr &= ~ESR_ELx_EC_MASK;
		esr |= ec << ESR_ELx_EC_SHIFT;
	}

	/*
	 * Since S1PTW should only ever be set for stage-2 faults, we're pretty
	 * much guaranteed that it won't be set in ESR_EL1 by the hardware. So,
	 * let's use that bit to allow the host abort handler to differentiate
	 * this abort from normal userspace faults.
	 *
	 * Note: although S1PTW is RES0 at EL1, it is guaranteed by the
	 * architecture to be backed by flops, so it should be safe to use.
	 */
	esr |= ESR_ELx_S1PTW;

	write_sysreg_el1(esr, SYS_ESR);
	write_sysreg_el1(spsr, SYS_SPSR);
	write_sysreg_el1(read_sysreg_el2(SYS_ELR), SYS_ELR);
	write_sysreg_el1(read_sysreg_el2(SYS_FAR), SYS_FAR);

	ventry = read_sysreg_el1(SYS_VBAR);
	ventry += get_except64_offset(spsr, PSR_MODE_EL1h, except_type_sync);
	write_sysreg_el2(ventry, SYS_ELR);

	spsr = get_except64_cpsr(spsr, system_supports_mte(),
				 read_sysreg_el1(SYS_SCTLR), PSR_MODE_EL1h);
	write_sysreg_el2(spsr, SYS_SPSR);
}


static bool is_dabt(u64 esr)
{
	return ESR_ELx_EC(esr) == ESR_ELx_EC_DABT_LOW;
}

void handle_host_mem_abort(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_vcpu_fault_info fault;
	u64 esr, addr;
	int ret = 0;

	esr = read_sysreg_el2(SYS_ESR);
	if (!__get_fault_info(esr, &fault)) {
		/* Setting the address to an invalid value for use in tracing. */
		addr = (u64)-1;
		/*
		 * We've presumably raced with a page-table change which caused
		 * AT to fail, try again.
		 */
		return;
	}


	/*
	 * Yikes, we couldn't resolve the fault IPA. This should reinject an
	 * abort into the host when we figure out how to do that.
	 */
	BUG_ON(!(fault.hpfar_el2 & HPFAR_EL2_NS));
	addr = FIELD_GET(HPFAR_EL2_FIPA, fault.hpfar_el2) << 12;
	addr |= fault.far_el2 & FAR_MASK;

	if (is_dabt(esr) && !addr_is_memory(addr) &&
	    kvm_iommu_host_dabt_handler(&host_ctxt->regs, esr, addr))
		return;


	switch (esr & ESR_ELx_FSC_TYPE) {
	case ESR_ELx_FSC_FAULT:
		ret = host_stage2_fault(addr);
		break;
	case ESR_ELx_FSC_PERM:
		ret = module_handle_host_perm_fault(&host_ctxt->regs, esr, addr);
		ret = ret ? 0 /* handled */ : -EPERM;
		break;
	default:
		ret = -EPERM;
		break;
	}

	if (ret == -EPERM)
		host_inject_abort(host_ctxt);
	else
		BUG_ON(ret && ret != -EAGAIN);

	trace_host_mem_abort(esr, addr);
}

struct check_walk_data {
	enum pkvm_page_state	desired;
	enum pkvm_page_state	(*get_page_state)(kvm_pte_t pte, u64 addr);
};

static int __check_page_state_visitor(const struct kvm_pgtable_visit_ctx *ctx,
				      enum kvm_pgtable_walk_flags visit)
{
	struct check_walk_data *d = ctx->arg;

	return d->get_page_state(ctx->old, ctx->addr) == d->desired ? 0 : -EPERM;
}

static int check_page_state_range(struct kvm_pgtable *pgt, u64 addr, u64 size,
				  struct check_walk_data *data)
{
	struct kvm_pgtable_walker walker = {
		.cb	= __check_page_state_visitor,
		.arg	= data,
		.flags	= KVM_PGTABLE_WALK_LEAF,
	};

	return kvm_pgtable_walk(pgt, addr, size, &walker);
}

static enum pkvm_page_state host_get_mmio_page_state(kvm_pte_t pte, u64 addr)
{
	enum pkvm_page_state state = 0;
	enum kvm_pgtable_prot prot;

	WARN_ON(addr_is_memory(addr));

	if (!kvm_pte_valid(pte) && pte)
		return PKVM_NOPAGE;

	prot = kvm_pgtable_stage2_pte_prot(pte);
	if (kvm_pte_valid(pte)) {
		if ((prot & KVM_PGTABLE_PROT_RWX) != PKVM_HOST_MMIO_PROT)
			state = PKVM_PAGE_RESTRICTED_PROT;
	}

	return state | pkvm_getstate(prot);
}

enum host_check_page_state_flags {
	HOST_CHECK_NULL_REFCNT		= BIT(0),
	HOST_CHECK_IS_MEMORY		= BIT(1),
	HOST_CHECK_ALLOW_NO_MAP		= BIT(2),
};

static int ___host_check_page_state_range(u64 addr, u64 size,
					  enum pkvm_page_state state,
					  enum host_check_page_state_flags flags)
{
	struct check_walk_data d = {
		.desired	= state,
		.get_page_state	= host_get_mmio_page_state,
	};
	struct memblock_region *reg;
	struct kvm_mem_range range;
	u64 end;

	if (check_add_overflow(addr, size, &end))
		return -EINVAL;

	/* Can't check the state of both MMIO and memory regions at once */
	reg = find_mem_range(addr, &range);
	if (!reg && (flags & HOST_CHECK_IS_MEMORY))
		return -EINVAL;

	if (!is_in_mem_range(end - 1, &range))
		return -EINVAL;

	hyp_assert_lock_held(&host_mmu.lock);

	/* MMIO state is still in the page-table */
	if (!reg)
		return check_page_state_range(&host_mmu.pgt, addr, size, &d);

	if (reg->flags & MEMBLOCK_NOMAP && !(flags & HOST_CHECK_ALLOW_NO_MAP))
		return -EPERM;

	for_each_hyp_page(page, addr, size) {
		if (get_host_state(page) != state)
			return -EPERM;
		if ((flags & HOST_CHECK_NULL_REFCNT) && hyp_refcount_get(page->refcount))
			return -EINVAL;
	}

	/*
	 * All memory pages with restricted permissions will already be covered
	 * by other states (e.g. PKVM_MODULE_OWNED_PAGE), so no need to retrieve
	 * the PKVM_PAGE_RESTRICTED_PROT state from the PTE.
	 */
	return 0;
}

static int __host_check_page_state_range(u64 addr, u64 size,
					 enum pkvm_page_state state)
{
	enum host_check_page_state_flags flags = HOST_CHECK_IS_MEMORY;

	if (state == PKVM_PAGE_OWNED)
		flags |= HOST_CHECK_NULL_REFCNT;

	/* Check the refcount of PAGE_OWNED pages as those may be used for DMA. */
	return ___host_check_page_state_range(addr, size, state, flags);
}


static void __hyp_set_page_state_range(phys_addr_t phys, u64 size, enum pkvm_page_state state)
{
	for_each_hyp_page(page, phys, size)
		set_hyp_state(page, state);
}

static enum pkvm_page_state hyp_get_page_state_mmio(kvm_pte_t pte, u64 addr)
{
	enum pkvm_page_state state = 0;
	enum kvm_pgtable_prot prot;

	if (!kvm_pte_valid(pte))
		return PKVM_NOPAGE;
	prot = kvm_pgtable_hyp_pte_prot(pte);
	if (kvm_pte_valid(pte) && ((prot & KVM_PGTABLE_PROT_RWX) != PAGE_HYP)) {
		state = PKVM_PAGE_RESTRICTED_PROT;
	}
	return state | pkvm_getstate(prot);
}

static int __hyp_check_page_state_range(phys_addr_t phys, u64 size,
					enum pkvm_page_state state)
{
	if (!range_is_memory(phys, phys + size)) {
		struct check_walk_data d = {
			.desired	= state,
			.get_page_state	= hyp_get_page_state_mmio,
		};

		hyp_assert_lock_held(&pkvm_pgd_lock);
		return check_page_state_range(&pkvm_pgtable, (u64)hyp_phys_to_virt(phys), size, &d);
	}

	for_each_hyp_page(page, phys, size) {
		if (get_hyp_state(page) != state)
			return -EPERM;
	}

	return 0;
}

int hyp_check_range_owned(u64 phys_addr, u64 size)
{
	int ret;

	hyp_lock_component();
	ret = __hyp_check_page_state_range(phys_addr, size, PKVM_PAGE_OWNED);
	hyp_unlock_component();

	return ret;
}

static enum pkvm_page_state guest_get_page_state(kvm_pte_t pte, u64 addr)
{
	enum pkvm_page_state state = 0;
	enum kvm_pgtable_prot prot;

	if (!kvm_pte_valid(pte)) {
		state = PKVM_NOPAGE;

		if (pte == KVM_INVALID_PTE_MMIO_NOTE)
			state |= PKVM_MMIO;
		else if (pte == KVM_ACCEPT_MODULE_PROT_NOTE)
			state |= PKVM_ACCEPT_MODULE_OWNED;

		return state;
	}

	prot = kvm_pgtable_stage2_pte_prot(pte);
	if (kvm_pte_valid(pte) && ((prot & KVM_PGTABLE_PROT_RWX) != KVM_PGTABLE_PROT_RWX))
		state = PKVM_PAGE_RESTRICTED_PROT;

#ifdef CONFIG_PKVM_GUEST_TO_GUEST
	/*
	 * Surface the guest-to-guest marker, so that every consumer of a guest
	 * page state can tell a share with a peer VM from a share with the
	 * host. Only valid PTEs can carry it; PKVM_NOPAGE returned above has
	 * no prot to read it from.
	 */
	if (pkvm_prot_is_g2g(prot))
		state |= PKVM_PAGE_G2G;
#endif

	return state | pkvm_getstate(prot);
}

static int __guest_check_page_state_range(struct pkvm_hyp_vm *vm, u64 addr,
					  u64 size, enum pkvm_page_state state)
{
	struct check_walk_data d = {
		.desired	= state,
		.get_page_state	= guest_get_page_state,
	};
	u64 end;

	if (check_add_overflow(addr, size, &end))
		return -EINVAL;

	hyp_assert_lock_held(&vm->pgtable_lock);
	return check_page_state_range(&vm->pgt, addr, size, &d);
}

struct guest_request_walker_data {
	union {
		kvm_pte_t		pte_start; /* guest_request_walker() */
		unsigned long		ipa_start; /* guest_request_ioguard_walker() */
	};
	u64			size;
	enum pkvm_page_state	desired_state;
	int			max_ptes;
};

#define GUEST_WALKER_DATA_INIT(__state)							\
{											\
	.size		= 0,								\
	.desired_state	= __state,							\
	/*										\
	 * In the very unlucky case where we have:					\
	 *   1. A block-aligned start address						\
	 *   2. An existing table							\
	 *   3. Contiguous phys for the entire table					\
	 *										\
	 * The guest stage-2 mapping of that range would try to collapse the existing	\
	 * table into a block mapping. We do not want this to happen: the		\
	 * stage-2 geometry must remain synchronized with the host's			\
	 * kvm_pinned_page tree at all time.						\
	 *										\
	 * As a mitigation, limit the number of processed PTEs to half the size		\
	 * of a table on a 4K page-size system.						\
	 */										\
	.max_ptes	= 256,								\
}

static int guest_request_walker(const struct kvm_pgtable_visit_ctx *ctx,
				enum kvm_pgtable_walk_flags visit)
{
	struct guest_request_walker_data *data = (struct guest_request_walker_data *)ctx->arg;
	enum pkvm_page_state state;
	kvm_pte_t pte = *ctx->ptep;
	phys_addr_t phys;
	u64 granule_size;

	state = guest_get_page_state(pte, 0);
	if (data->desired_state != state)
		return (state == PKVM_NOPAGE) ? -ENOENT : -EPERM;

	/* state != PKVM_NOPAGE but invalid PTE? */
	if (WARN_ON(!kvm_pte_valid(pte)))
		return -EINVAL;

	granule_size = kvm_granule_size(ctx->level);
	phys = kvm_pte_to_phys(pte);

	/* First PTE */
	if (!data->size) {
		/* Request starts in the middle of a huge-mapping */
		if (!IS_ALIGNED(ctx->start, granule_size))
			return -E2BIG;

		data->pte_start = pte;
		data->size = granule_size;

		goto end;
	}

	if (kvm_pgtable_stage2_pte_prot(pte) !=
	    kvm_pgtable_stage2_pte_prot(data->pte_start))
		return -EINVAL;

	/* Can only describe physically contiguous mappings */
	if ((phys != kvm_pte_to_phys(data->pte_start) + data->size))
		return -ERANGE;

	data->size += granule_size;

end:
	/* Request ends in the middle of a huge-mapping */
	if (ctx->start + data->size > ctx->end)
		return -E2BIG;

	return --data->max_ptes > 0 ? 0 : -ERANGE;
}

static int __guest_request_page_transition(u64 ipa, kvm_pte_t *__pte, u64 *__nr_pages,
					   struct pkvm_hyp_vm *vm,
					   enum pkvm_page_state desired)
{
	struct guest_request_walker_data data = GUEST_WALKER_DATA_INIT(desired);
	struct kvm_pgtable_walker walker = {
		.cb     = guest_request_walker,
		.flags  = KVM_PGTABLE_WALK_LEAF,
		.arg    = (void *)&data,
	};
	phys_addr_t phys;
	size_t size;
	int ret;

	if (check_mul_overflow(*__nr_pages, PAGE_SIZE, &size) ||
	    ipa >= ipa + size)
		return -EINVAL;

	ret = kvm_pgtable_walk(&vm->pgt, ipa, size, &walker);
	/*
	 * Walker reached data.max_ptes or a non-physically-contiguous mapping.
	 * Proceed with the current valid region. The guest will have to issue a new call for the
	 * leftover.
	 */
	if (ret == -ERANGE)
		ret = 0;
	else if (ret)
		return ret;

	if (WARN_ON(!kvm_pte_valid(data.pte_start)))
		return -EINVAL;

	phys = kvm_pte_to_phys(data.pte_start);
	ret = check_range_allowed_memory(phys, phys + data.size);
	if (ret)
		return ret;

	*__pte = data.pte_start;
	*__nr_pages = data.size >> PAGE_SHIFT;

	return 0;
}

int __pkvm_host_share_hyp(u64 pfn)
{
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 size = PAGE_SIZE;
	int ret;

	host_lock_component();
	hyp_lock_component();

	ret = __host_check_page_state_range(phys, size, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;
	ret = __hyp_check_page_state_range(phys, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	__hyp_set_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED);
	__host_update_page_state(phys, size, PKVM_PAGE_SHARED_OWNED);

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

int __pkvm_host_unshare_hyp(u64 pfn)
{
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 virt = (u64)__hyp_va(phys);
	u64 size = PAGE_SIZE;
	int ret;

	host_lock_component();
	hyp_lock_component();

	ret = __host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;
	ret = __hyp_check_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;
	if (hyp_page_referenced((void *)virt)) {
		ret = -EBUSY;
		goto unlock;
	}

	__hyp_set_page_state_range(phys, size, PKVM_NOPAGE);
	__host_update_page_state(phys, size, PKVM_PAGE_OWNED);

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

int __pkvm_guest_share_hyp_page(struct pkvm_hyp_vcpu *vcpu, u64 ipa, u64 *hyp_va)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	int ret;
	kvm_pte_t pte;
	u64 phys;
	enum kvm_pgtable_prot prot;
	void *virt;
	u64 nr_pages = 1;

	hyp_lock_component();
	guest_lock_component(vm);

	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vm, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	phys = kvm_pte_to_phys(pte);

	virt = __hyp_va(phys);
	ret = __hyp_check_page_state_range(phys, PAGE_SIZE, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	__hyp_set_page_state_range(phys, PAGE_SIZE, PKVM_PAGE_SHARED_BORROWED);
	prot = pkvm_mkstate(PAGE_HYP, PKVM_PAGE_SHARED_BORROWED);
	ret = pkvm_create_mappings_locked(virt, virt + PAGE_SIZE, prot);
	if (ret) {
		/*
		 * Repaint the return code as we need to distinguish between the
		 * no memory from the guest which is recoverable and no memory
		 * from the hypervisor.
		 */
		if (ret == -ENOMEM)
			ret = -EBUSY;
		goto unlock;
	}

	ret = kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, phys,
				     pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_SHARED_OWNED),
				     &vcpu->vcpu.arch.stage2_mc, 0);
	if (!ret)
		*hyp_va = (u64)virt;
unlock:
	guest_unlock_component(vm);
	hyp_unlock_component();

	return ret;
}

int __pkvm_guest_unshare_hyp_page(struct pkvm_hyp_vm *vm, u64 ipa)
{
	int ret;
	kvm_pte_t pte;
	u64 phys, virt, nr_pages = 1;

	hyp_lock_component();
	guest_lock_component(vm);

	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vm, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	phys = kvm_pte_to_phys(pte);

	virt = (u64)__hyp_va(phys);
	ret = __hyp_check_page_state_range(phys, PAGE_SIZE, PKVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;

	__hyp_set_page_state_range(phys, PAGE_SIZE, PKVM_NOPAGE);
	WARN_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, virt, PAGE_SIZE) != PAGE_SIZE);
	/*
	 * NULL memcache: this is the reverse of a prior PAGE_SIZE share, so the
	 * walker rejected any coarser leaf with -E2BIG. The map below only
	 * flips software state bits via the try_leaf fast path and never
	 * allocates. The teardown path runs without a loaded vCPU, so there is
	 * no correct memcache to pass.
	 */
	ret = kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, phys,
				     pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED),
				     NULL, 0);
unlock:
	guest_unlock_component(vm);
	hyp_unlock_component();

	return ret;
}

int __pkvm_guest_share_ffa_page(struct pkvm_hyp_vcpu *vcpu, u64 ipa, phys_addr_t *phys)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	int ret;
	kvm_pte_t pte;
	u64 nr_pages = 1;
	phys_addr_t pa;

	guest_lock_component(vm);
	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vm, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	pa = kvm_pte_to_phys(pte);
	ret = kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, pa,
				     pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_SHARED_OWNED),
				     &vcpu->vcpu.arch.stage2_mc, 0);
	if (!ret)
		*phys = pa;
unlock:
	guest_unlock_component(vm);

	return ret;
}

/*
 * The caller is responsible for tracking the FFA state and this function
 * should only be called for IPAs that have previously been shared with FFA.
 */
int __pkvm_guest_unshare_ffa_page(struct pkvm_hyp_vm *vm, u64 ipa)
{
	int ret;
	kvm_pte_t pte;
	u64 nr_pages = 1;

	guest_lock_component(vm);
	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vm, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	/* See __pkvm_guest_unshare_hyp_page() for why mc is NULL. */
	ret = kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, kvm_pte_to_phys(pte),
				     pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED),
				     NULL, 0);
unlock:
	guest_unlock_component(vm);

	return ret;
}

#ifdef CONFIG_PKVM_GUEST_TO_GUEST
/*
 * ============================================================================
 * Guest-to-guest sharing, 1 of 3: the decisions. Pure; no locks, no state.
 * ============================================================================
 *
 * Every share call is decided the way GUEST_MSG_SEND is: the handler finds out
 * a set of facts, and a pure, total function of the facts gives the verdict.
 * The transitions in section 2 only gather facts and carry verdicts out, and
 * pkvm_g2g_share_verdict_selftest() enumerates every fact set at EL2 init.
 *
 * The order of the tests in each function is the order of precedence, and it
 * is load-bearing twice over:
 *
 *  - a malformed call is refused before anything else is consulted, a caller
 *    with no identity before anything about the peer, and a call naming a dead
 *    or unknown peer before the share table or a page table is looked at, so
 *    that a refused call learns as little as possible;
 *  - every fact a transition can only find out with locks held is tested after
 *    every fact it can find out without them. A verdict reached before taking
 *    the locks therefore cannot be changed by what the locks would reveal, and
 *    the transitions return early without locking. The self-check proves this
 *    for every input (O3, A3, E1).
 *
 * NEED_MAP, NEED_SPLIT and NEED_MEMCACHE are not answers: the handler turns
 * them into a request to the host and re-executes the HVC. They are reached
 * only when nothing else stands in the way (O4, A4), so the host is never asked
 * for work that could not let the call succeed.
 */

/* OFFER: the shape of the call. */
#define PKVM_G2G_OFFER_FLAGS_BAD	BIT(9)	/* x6 has a bit other than RO */
#define PKVM_G2G_OFFER_NR_BAD		BIT(10)	/* nr_pages is 0 or > 512 */
#define PKVM_G2G_OFFER_IPA_BAD		BIT(11)	/* unaligned, or not inside the IPA space */
/* OFFER: found out with the host and owner locks held. */
#define PKVM_G2G_OFFER_STATE		BIT(12)	/* a page is not exclusively the caller's */
#define PKVM_G2G_OFFER_LIMIT		BIT(13)	/* the table or the caller's quota is full */
#define PKVM_G2G_OFFER_UNMAPPED		BIT(14)	/* a page is not mapped in yet */
#define PKVM_G2G_OFFER_STRADDLE		BIT(15)	/* a block crosses an end of the range */
#define PKVM_G2G_OFFER_LOCKED		GENMASK(15, 12)
/* Every fact an OFFER can carry. PKVM_G2G_SHARE_NO_MMIO_GUARD is not one. */
#define PKVM_G2G_OFFER_FACTS		(GENMASK(7, 0) | GENMASK(15, 9))

/* ACCEPT: the shape of the call. */
#define PKVM_G2G_ACCEPT_FLAGS_BAD	BIT(9)	/* x7 != 0 */
#define PKVM_G2G_ACCEPT_NR_BAD		BIT(10)	/* nr_pages is 0 or > 512 */
/* Unaligned, past the IPA space, or crossing a last-level table: */
#define PKVM_G2G_ACCEPT_IPA_BAD		BIT(11)
/* ACCEPT: found out with the host lock held. */
#define PKVM_G2G_ACCEPT_NO_SHARE	BIT(12)	/* no such offer, by that owner, to the caller */
#define PKVM_G2G_ACCEPT_TAKEN		BIT(13)	/* the share is already accepted */
#define PKVM_G2G_ACCEPT_OWNER_STATE	BIT(14)	/* the owner's pages are not as offered */
#define PKVM_G2G_ACCEPT_DEST_BUSY	BIT(15)	/* the destination is not all-empty */
#define PKVM_G2G_ACCEPT_MEMCACHE_LOW	BIT(16)	/* the memcache cannot cover a table path */
#define PKVM_G2G_ACCEPT_LOCKED		GENMASK(16, 12)
#define PKVM_G2G_ACCEPT_FACTS		GENMASK(16, 0)

/* REVOKE and RELEASE. */
#define PKVM_G2G_END_FLAGS_BAD		BIT(0)	/* x2 != 0 */
#define PKVM_G2G_END_NO_SHARE		BIT(1)	/* no such share for the caller in this role */
#define PKVM_G2G_END_DIVERGED		BIT(2)	/* the page tables disagree with the record */
#define PKVM_G2G_END_LOCKED		GENMASK(2, 1)
#define PKVM_G2G_END_FACTS		GENMASK(2, 0)

/* A call that names a peer is malformed if the name is not one. */
#define PKVM_G2G_SHARE_MALFORMED_PEER	(PKVM_G2G_SHARE_PEER_ID_ZERO |	\
					 PKVM_G2G_SHARE_PEER_INC_ZERO |	\
					 PKVM_G2G_SHARE_TO_SELF)
/* ...and has no peer unless a live, protected VM holds it at that incarnation. */
#define PKVM_G2G_SHARE_PEER_GONE	(PKVM_G2G_SHARE_PEER_DYING |	\
					 PKVM_G2G_SHARE_PEER_UNPROTECTED | \
					 PKVM_G2G_SHARE_PEER_STALE)

static enum pkvm_g2g_share_verdict pkvm_g2g_offer_verdict(u32 facts)
{
	/* A fact no OFFER can carry: refuse rather than guess. */
	if (facts & ~PKVM_G2G_OFFER_FACTS)
		return PKVM_G2G_SHARE_INVALID;

	if (facts & (PKVM_G2G_OFFER_FLAGS_BAD | PKVM_G2G_OFFER_NR_BAD |
		     PKVM_G2G_OFFER_IPA_BAD | PKVM_G2G_SHARE_MALFORMED_PEER))
		return PKVM_G2G_SHARE_INVALID;

	if (facts & PKVM_G2G_SHARE_UNREGISTERED)
		return PKVM_G2G_SHARE_NO_IDENTITY;

	if (!(facts & PKVM_G2G_SHARE_PEER_FOUND) ||
	    (facts & PKVM_G2G_SHARE_PEER_GONE))
		return PKVM_G2G_SHARE_NO_PEER;

	if (facts & PKVM_G2G_OFFER_STATE)
		return PKVM_G2G_SHARE_DENIED;

	if (facts & PKVM_G2G_OFFER_LIMIT)
		return PKVM_G2G_SHARE_LIMIT;

	if (facts & PKVM_G2G_OFFER_UNMAPPED)
		return PKVM_G2G_SHARE_NEED_MAP;

	if (facts & PKVM_G2G_OFFER_STRADDLE)
		return PKVM_G2G_SHARE_NEED_SPLIT;

	return PKVM_G2G_SHARE_DO;
}

static enum pkvm_g2g_share_verdict pkvm_g2g_accept_verdict(u32 facts)
{
	if (facts & ~PKVM_G2G_ACCEPT_FACTS)
		return PKVM_G2G_SHARE_INVALID;

	if (facts & (PKVM_G2G_ACCEPT_FLAGS_BAD | PKVM_G2G_ACCEPT_NR_BAD |
		     PKVM_G2G_ACCEPT_IPA_BAD | PKVM_G2G_SHARE_MALFORMED_PEER))
		return PKVM_G2G_SHARE_INVALID;

	if (facts & PKVM_G2G_SHARE_UNREGISTERED)
		return PKVM_G2G_SHARE_NO_IDENTITY;

	if (!(facts & PKVM_G2G_SHARE_PEER_FOUND) ||
	    (facts & PKVM_G2G_SHARE_PEER_GONE))
		return PKVM_G2G_SHARE_NO_PEER;

	/*
	 * Without MMIO guard, a touch of the window after the share ends would
	 * show the host the access's data register. Refused before the share is
	 * looked at, so the answer says nothing about the table.
	 */
	if (facts & PKVM_G2G_SHARE_NO_MMIO_GUARD)
		return PKVM_G2G_SHARE_DENIED;

	if (facts & PKVM_G2G_ACCEPT_NO_SHARE)
		return PKVM_G2G_SHARE_NO_SHARE;

	if (facts & (PKVM_G2G_ACCEPT_TAKEN | PKVM_G2G_ACCEPT_OWNER_STATE |
		     PKVM_G2G_ACCEPT_DEST_BUSY))
		return PKVM_G2G_SHARE_DENIED;

	if (facts & PKVM_G2G_ACCEPT_MEMCACHE_LOW)
		return PKVM_G2G_SHARE_NEED_MEMCACHE;

	return PKVM_G2G_SHARE_DO;
}

/* REVOKE (owner) and RELEASE (borrower) are decided alike. */
static enum pkvm_g2g_share_verdict pkvm_g2g_end_verdict(u32 facts)
{
	if (facts & ~PKVM_G2G_END_FACTS)
		return PKVM_G2G_SHARE_INVALID;

	if (facts & PKVM_G2G_END_FLAGS_BAD)
		return PKVM_G2G_SHARE_INVALID;

	if (facts & PKVM_G2G_END_NO_SHARE)
		return PKVM_G2G_SHARE_NO_SHARE;

	if (facts & PKVM_G2G_END_DIVERGED)
		return PKVM_G2G_SHARE_DENIED;

	return PKVM_G2G_SHARE_DO;
}

unsigned long pkvm_g2g_share_verdict_to_smccc(enum pkvm_g2g_share_verdict v)
{
	switch (v) {
	case PKVM_G2G_SHARE_DO:
		return SMCCC_RET_SUCCESS;
	case PKVM_G2G_SHARE_INVALID:
		return SMCCC_RET_INVALID_PARAMETER;
	case PKVM_G2G_SHARE_NO_IDENTITY:
		return ARM_SMCCC_KVM_G2G_MSG_NO_IDENTITY;
	case PKVM_G2G_SHARE_NO_PEER:
		return ARM_SMCCC_KVM_G2G_MSG_NO_PEER;
	case PKVM_G2G_SHARE_NO_SHARE:
		return ARM_SMCCC_KVM_G2G_SHARE_NO_SHARE;
	case PKVM_G2G_SHARE_DENIED:
		return ARM_SMCCC_KVM_G2G_SHARE_DENIED;
	case PKVM_G2G_SHARE_LIMIT:
		return ARM_SMCCC_KVM_G2G_SHARE_LIMIT;
	default:
		/* NEED_*: turned into a host request, never returned. */
		return SMCCC_RET_NOT_SUPPORTED;
	}
}

/*
 * The share self-check's verdict, read and reported by the host in
 * finalize_pkvm() like the reclaim and mailbox checks: no hyp serial driver
 * exists this early, and a hyp WARN is fatal. _inputs == 0 means the decision
 * check did not run and _steps == 0 that the lifecycle check (section 3) did
 * not. _first_bad names the first failure as (check << 16) | input, the check
 * being a PKVM_G2G_SHARE_CHK_* value.
 */
u32 pkvm_g2g_share_selftest_inputs;
u32 pkvm_g2g_share_selftest_cases;
u32 pkvm_g2g_share_selftest_steps;
u32 pkvm_g2g_share_selftest_failures;
u32 pkvm_g2g_share_selftest_first_bad;

enum {
	PKVM_G2G_SHARE_CHK_O1 = 1,	/* OFFER: DO from exactly one fact set */
	PKVM_G2G_SHARE_CHK_O2,		/* OFFER: malformed or unknown is INVALID */
	PKVM_G2G_SHARE_CHK_O3,		/* OFFER: locked facts never change an early verdict */
	PKVM_G2G_SHARE_CHK_O4,		/* OFFER: a host request only when nothing refuses */
	PKVM_G2G_SHARE_CHK_O5,		/* OFFER: only verdicts an OFFER can have */
	PKVM_G2G_SHARE_CHK_A1,		/* ACCEPT: as O1 */
	PKVM_G2G_SHARE_CHK_A2,		/* ACCEPT: as O2 */
	PKVM_G2G_SHARE_CHK_A3,		/* ACCEPT: as O3 */
	PKVM_G2G_SHARE_CHK_A4,		/* ACCEPT: as O4 */
	PKVM_G2G_SHARE_CHK_A5,		/* ACCEPT: as O5 */
	PKVM_G2G_SHARE_CHK_E1,		/* REVOKE/RELEASE: all of the above */
	PKVM_G2G_SHARE_CHK_M1,		/* the SMCCC codes */
	PKVM_G2G_SHARE_CHK_CASE,	/* a named case */
	PKVM_G2G_SHARE_CHK_STEP,	/* a lifecycle step, section 3 */
};

static void pkvm_g2g_share_check(bool ok, u32 check, u32 what)
{
	if (ok)
		return;
	if (!pkvm_g2g_share_selftest_failures)
		pkvm_g2g_share_selftest_first_bad = (check << 16) | (what & 0xffff);
	pkvm_g2g_share_selftest_failures++;
}

static bool pkvm_g2g_share_is_request(enum pkvm_g2g_share_verdict v)
{
	return v == PKVM_G2G_SHARE_NEED_MAP || v == PKVM_G2G_SHARE_NEED_SPLIT ||
	       v == PKVM_G2G_SHARE_NEED_MEMCACHE;
}

/*
 * Every OFFER fact set (2^16), every ACCEPT fact set (2^17), every REVOKE and
 * RELEASE fact set (2^3), every verdict's SMCCC code, then named cases, so that
 * a change of meaning that keeps the invariants is still caught.
 */
void pkvm_g2g_share_verdict_selftest(void)
{
	static const struct {
		u8 op;			/* 0 OFFER, 1 ACCEPT, 2 REVOKE/RELEASE */
		u32 facts;
		enum pkvm_g2g_share_verdict want;
	} cases[] = {
		/* OFFER */
		{ 0, PKVM_G2G_SHARE_PEER_FOUND, PKVM_G2G_SHARE_DO },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_SHARE_TO_SELF,
		  PKVM_G2G_SHARE_INVALID },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_SHARE_UNREGISTERED,
		  PKVM_G2G_SHARE_NO_IDENTITY },
		{ 0, 0, PKVM_G2G_SHARE_NO_PEER },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_SHARE_PEER_DYING,
		  PKVM_G2G_SHARE_NO_PEER },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_SHARE_PEER_STALE,
		  PKVM_G2G_SHARE_NO_PEER },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND |
		     PKVM_G2G_SHARE_PEER_UNPROTECTED, PKVM_G2G_SHARE_NO_PEER },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_OFFER_STATE,
		  PKVM_G2G_SHARE_DENIED },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_OFFER_LIMIT,
		  PKVM_G2G_SHARE_LIMIT },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_OFFER_UNMAPPED,
		  PKVM_G2G_SHARE_NEED_MAP },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_OFFER_STRADDLE,
		  PKVM_G2G_SHARE_NEED_SPLIT },
		/* a page in the wrong state is refused, not mapped in for nothing */
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_OFFER_STATE |
		     PKVM_G2G_OFFER_UNMAPPED, PKVM_G2G_SHARE_DENIED },
		/* a full table is refused, not split for nothing */
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_OFFER_LIMIT |
		     PKVM_G2G_OFFER_STRADDLE, PKVM_G2G_SHARE_LIMIT },
		{ 0, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_SHARE_NO_MMIO_GUARD,
		  PKVM_G2G_SHARE_INVALID },
		/* ACCEPT */
		{ 1, PKVM_G2G_SHARE_PEER_FOUND, PKVM_G2G_SHARE_DO },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_SHARE_UNREGISTERED |
		     PKVM_G2G_ACCEPT_NO_SHARE, PKVM_G2G_SHARE_NO_IDENTITY },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_SHARE_PEER_STALE |
		     PKVM_G2G_ACCEPT_NO_SHARE, PKVM_G2G_SHARE_NO_PEER },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_SHARE_NO_MMIO_GUARD |
		     PKVM_G2G_ACCEPT_NO_SHARE, PKVM_G2G_SHARE_DENIED },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_ACCEPT_NO_SHARE |
		     PKVM_G2G_ACCEPT_TAKEN, PKVM_G2G_SHARE_NO_SHARE },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_ACCEPT_TAKEN,
		  PKVM_G2G_SHARE_DENIED },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_ACCEPT_OWNER_STATE,
		  PKVM_G2G_SHARE_DENIED },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_ACCEPT_DEST_BUSY,
		  PKVM_G2G_SHARE_DENIED },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_ACCEPT_MEMCACHE_LOW,
		  PKVM_G2G_SHARE_NEED_MEMCACHE },
		/* a busy destination is refused, not topped up for nothing */
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_ACCEPT_DEST_BUSY |
		     PKVM_G2G_ACCEPT_MEMCACHE_LOW, PKVM_G2G_SHARE_DENIED },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_ACCEPT_IPA_BAD,
		  PKVM_G2G_SHARE_INVALID },
		{ 1, PKVM_G2G_SHARE_PEER_FOUND | PKVM_G2G_SHARE_TO_SELF,
		  PKVM_G2G_SHARE_INVALID },
		/* REVOKE / RELEASE */
		{ 2, 0, PKVM_G2G_SHARE_DO },
		{ 2, PKVM_G2G_END_FLAGS_BAD | PKVM_G2G_END_NO_SHARE,
		  PKVM_G2G_SHARE_INVALID },
		{ 2, PKVM_G2G_END_NO_SHARE | PKVM_G2G_END_DIVERGED,
		  PKVM_G2G_SHARE_NO_SHARE },
		{ 2, PKVM_G2G_END_DIVERGED, PKVM_G2G_SHARE_DENIED },
		/* facts no handler produces */
		{ 0, ~0U, PKVM_G2G_SHARE_INVALID },
		{ 1, BIT(17), PKVM_G2G_SHARE_INVALID },
		{ 2, BIT(3), PKVM_G2G_SHARE_INVALID },
	};
	enum pkvm_g2g_share_verdict v, early;
	u32 f, i, j, inputs = 0;

	for (f = 0; f < BIT(16); f++, inputs++) {
		v = pkvm_g2g_offer_verdict(f);
		early = pkvm_g2g_offer_verdict(f & ~PKVM_G2G_OFFER_LOCKED);

		pkvm_g2g_share_check((v == PKVM_G2G_SHARE_DO) ==
				     (f == PKVM_G2G_SHARE_PEER_FOUND),
				     PKVM_G2G_SHARE_CHK_O1, f);
		if (f & (~PKVM_G2G_OFFER_FACTS | PKVM_G2G_OFFER_FLAGS_BAD |
			 PKVM_G2G_OFFER_NR_BAD | PKVM_G2G_OFFER_IPA_BAD |
			 PKVM_G2G_SHARE_MALFORMED_PEER))
			pkvm_g2g_share_check(v == PKVM_G2G_SHARE_INVALID,
					     PKVM_G2G_SHARE_CHK_O2, f);
		if (early != PKVM_G2G_SHARE_DO)
			pkvm_g2g_share_check(v == early, PKVM_G2G_SHARE_CHK_O3, f);
		if (pkvm_g2g_share_is_request(v))
			pkvm_g2g_share_check(!(f & (PKVM_G2G_OFFER_STATE |
						    PKVM_G2G_OFFER_LIMIT)) &&
					     pkvm_g2g_offer_verdict(f &
						~(PKVM_G2G_OFFER_UNMAPPED |
						  PKVM_G2G_OFFER_STRADDLE)) ==
					     PKVM_G2G_SHARE_DO,
					     PKVM_G2G_SHARE_CHK_O4, f);
		pkvm_g2g_share_check(v < PKVM_G2G_SHARE_NR_VERDICTS &&
				     v != PKVM_G2G_SHARE_NO_SHARE &&
				     v != PKVM_G2G_SHARE_NEED_MEMCACHE,
				     PKVM_G2G_SHARE_CHK_O5, f);
	}

	for (f = 0; f < BIT(17); f++, inputs++) {
		v = pkvm_g2g_accept_verdict(f);
		early = pkvm_g2g_accept_verdict(f & ~PKVM_G2G_ACCEPT_LOCKED);

		pkvm_g2g_share_check((v == PKVM_G2G_SHARE_DO) ==
				     (f == PKVM_G2G_SHARE_PEER_FOUND),
				     PKVM_G2G_SHARE_CHK_A1, f);
		if (f & (PKVM_G2G_ACCEPT_FLAGS_BAD | PKVM_G2G_ACCEPT_NR_BAD |
			 PKVM_G2G_ACCEPT_IPA_BAD | PKVM_G2G_SHARE_MALFORMED_PEER))
			pkvm_g2g_share_check(v == PKVM_G2G_SHARE_INVALID,
					     PKVM_G2G_SHARE_CHK_A2, f);
		if (early != PKVM_G2G_SHARE_DO)
			pkvm_g2g_share_check(v == early, PKVM_G2G_SHARE_CHK_A3, f);
		if (pkvm_g2g_share_is_request(v))
			pkvm_g2g_share_check(pkvm_g2g_accept_verdict(f &
						~PKVM_G2G_ACCEPT_MEMCACHE_LOW) ==
					     PKVM_G2G_SHARE_DO,
					     PKVM_G2G_SHARE_CHK_A4, f);
		pkvm_g2g_share_check(v < PKVM_G2G_SHARE_NR_VERDICTS &&
				     v != PKVM_G2G_SHARE_LIMIT &&
				     v != PKVM_G2G_SHARE_NEED_MAP &&
				     v != PKVM_G2G_SHARE_NEED_SPLIT,
				     PKVM_G2G_SHARE_CHK_A5, f);
	}

	for (f = 0; f < BIT(3); f++, inputs++) {
		v = pkvm_g2g_end_verdict(f);
		early = pkvm_g2g_end_verdict(f & ~PKVM_G2G_END_LOCKED);

		pkvm_g2g_share_check((v == PKVM_G2G_SHARE_DO) == !f &&
				     (early == PKVM_G2G_SHARE_DO || v == early) &&
				     (v == PKVM_G2G_SHARE_DO ||
				      v == PKVM_G2G_SHARE_INVALID ||
				      v == PKVM_G2G_SHARE_NO_SHARE ||
				      v == PKVM_G2G_SHARE_DENIED),
				     PKVM_G2G_SHARE_CHK_E1, f);
	}

	for (i = 0; i < PKVM_G2G_SHARE_NR_VERDICTS; i++, inputs++) {
		unsigned long code = pkvm_g2g_share_verdict_to_smccc(i);

		if (pkvm_g2g_share_is_request(i)) {
			pkvm_g2g_share_check(code == (unsigned long)SMCCC_RET_NOT_SUPPORTED,
					     PKVM_G2G_SHARE_CHK_M1, i);
			continue;
		}
		pkvm_g2g_share_check((code == SMCCC_RET_SUCCESS) ==
				     (i == PKVM_G2G_SHARE_DO) &&
				     code != (unsigned long)SMCCC_RET_NOT_SUPPORTED,
				     PKVM_G2G_SHARE_CHK_M1, i);
		for (j = i + 1; j < PKVM_G2G_SHARE_NR_VERDICTS; j++)
			if (!pkvm_g2g_share_is_request(j))
				pkvm_g2g_share_check(code != pkvm_g2g_share_verdict_to_smccc(j),
						     PKVM_G2G_SHARE_CHK_M1, (i << 8) | j);
	}

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		v = cases[i].op == 0 ? pkvm_g2g_offer_verdict(cases[i].facts)
		  : cases[i].op == 1 ? pkvm_g2g_accept_verdict(cases[i].facts)
		  : pkvm_g2g_end_verdict(cases[i].facts);
		pkvm_g2g_share_check(v == cases[i].want, PKVM_G2G_SHARE_CHK_CASE, i);
	}

	pkvm_g2g_share_selftest_cases = ARRAY_SIZE(cases);
	/* Last: non-zero is what tells the host the check ran to the end. */
	pkvm_g2g_share_selftest_inputs = inputs;
}
#endif /* CONFIG_PKVM_GUEST_TO_GUEST: section 1 */

#ifdef CONFIG_PKVM_GUEST_TO_GUEST
/*
 * ============================================================================
 * Guest-to-guest sharing, 2 of 3: the transitions.
 * ============================================================================
 *
 * Naming: A owns the pages and offers them, B borrows them, and "host" is the
 * untrusted pKVM host. Per page:
 *
 *	situation		A's PTE			B's PTE			host state
 *	offered			SHARED_OWNED|G2G	-			NOPAGE
 *	accepted		SHARED_OWNED|G2G	SHARED_BORROWED|G2G	G2G_LENT
 *	released, B died	SHARED_OWNED|G2G	-			NOPAGE
 *	revoked			OWNED			-			NOPAGE
 *
 * pkvm_g2g_reclaim_action() already decides each of these for teardown.
 * G2G_ORPHANED is never produced: a dying owner's borrowers lose the pages
 * first (pkvm_g2g_share_vm_dying()).
 *
 * Lock order: vm_table_lock (read; the write lock in teardown) ->
 * host_mmu.lock -> one guest pgtable_lock at a time. Never two guest locks:
 * guest_lock_component() sets the single per-CPU current_vm, which cannot
 * nest. ACCEPT reads the owner's pages under the owner's lock, drops it, and
 * maps into the borrower under the borrower's. That is safe because, while
 * host_mmu.lock and the vm_table read lock are held, nothing can change an
 * owner page that is in a share: the owner's own calls (MEM_SHARE,
 * MEM_RELINQUISH, FF-A, a second OFFER) all require PKVM_PAGE_OWNED, donation
 * into and reclaim from the owner take host_mmu.lock, and teardown takes the
 * vm_table write lock.
 *
 * The share table is guarded by host_mmu.lock, which every transition holds
 * anyway because every transition changes host-side page state. A record holds
 * a VM pointer only while that VM has not started teardown:
 * pkvm_g2g_share_vm_dying() clears every reference to a VM in the same
 * vm_table write-locked step that marks it dying, and a VM is freed only after
 * that, so no pointer here can dangle.
 *
 * Nothing here WARNs (a hyp WARN is fatal on this tree), allocates outside the
 * vCPU memcache, or loops more than PKVM_G2G_SHARE_MAX records or
 * PKVM_G2G_SHARE_MAX_PAGES pages.
 */

#define PKVM_G2G_SHARE_MAX		64
#define PKVM_G2G_SHARE_MAX_PER_OWNER	16
#define PKVM_G2G_SHARE_MAX_PAGES	512

enum pkvm_g2g_share_state {
	PKVM_G2G_SHARE_FREE = 0,
	PKVM_G2G_SHARE_OFFERED,
	PKVM_G2G_SHARE_ACCEPTED,
};

struct pkvm_g2g_share {
	enum pkvm_g2g_share_state	state;
	u32				gen;		/* never 0; half the handle */
	u64				flags;		/* ARM_SMCCC_KVM_G2G_SHARE_RO */
	u64				nr_pages;
	struct pkvm_hyp_vm		*owner;
	u64				owner_ipa;
	struct pkvm_g2g_identity	to;		/* the borrower the owner named */
	struct pkvm_hyp_vm		*borrower;	/* only while ACCEPTED */
	u64				borrower_ipa;	/* only while ACCEPTED */
};

/* Guarded by host_mmu.lock. */
static struct pkvm_g2g_share pkvm_g2g_shares[PKVM_G2G_SHARE_MAX];
static u32 pkvm_g2g_share_gen;

static u64 pkvm_g2g_share_handle(const struct pkvm_g2g_share *s)
{
	return ((u64)s->gen << 32) | (u64)(s - pkvm_g2g_shares);
}

/* The live record a handle names, or NULL. Caller holds host_mmu.lock. */
static struct pkvm_g2g_share *pkvm_g2g_share_find(u64 handle)
{
	u64 slot = handle & U32_MAX;
	struct pkvm_g2g_share *s;

	hyp_assert_lock_held(&host_mmu.lock);

	if (slot >= PKVM_G2G_SHARE_MAX)
		return NULL;

	s = &pkvm_g2g_shares[slot];
	if (s->state == PKVM_G2G_SHARE_FREE || s->gen != (u32)(handle >> 32))
		return NULL;

	return s;
}

/* A free record for @owner, or NULL if the table or @owner's quota is full. */
static struct pkvm_g2g_share *pkvm_g2g_share_alloc(struct pkvm_hyp_vm *owner)
{
	struct pkvm_g2g_share *free = NULL;
	unsigned int i, mine = 0;

	hyp_assert_lock_held(&host_mmu.lock);

	for (i = 0; i < PKVM_G2G_SHARE_MAX; i++) {
		struct pkvm_g2g_share *s = &pkvm_g2g_shares[i];

		if (s->state == PKVM_G2G_SHARE_FREE) {
			if (!free)
				free = s;
		} else if (s->owner == owner) {
			mine++;
		}
	}

	return mine < PKVM_G2G_SHARE_MAX_PER_OWNER ? free : NULL;
}

/* Back to FREE. The generation is kept, so an old handle never matches again. */
static void pkvm_g2g_share_free(struct pkvm_g2g_share *s)
{
	u32 gen = s->gen;

	memset(s, 0, sizeof(*s));
	s->gen = gen;
}

/* The leaf covering @ipa in @vm's stage-2. Caller holds @vm's pgtable lock. */
static int pkvm_g2g_leaf(struct pkvm_hyp_vm *vm, u64 ipa, kvm_pte_t *pte,
			 u64 *base, u64 *gran)
{
	s8 level;
	int ret;

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, pte, &level);
	if (ret)
		return ret;

	*gran = kvm_granule_size(level);
	*base = ALIGN_DOWN(ipa, *gran);
	return 0;
}

/*
 * The OFFER facts only the owner's page table and the host vmemmap can give:
 * PKVM_G2G_OFFER_STATE, _UNMAPPED and _STRADDLE. Does not stop at the first, so
 * that the verdict sees all of them (a range with an unmapped page and a page
 * in the wrong state is refused, not mapped in for nothing). Caller holds
 * host_mmu.lock and @vm's lock.
 */
static u32 pkvm_g2g_offer_range_facts(struct pkvm_hyp_vm *vm, u64 ipa, u64 size)
{
	u64 addr = ipa, end = ipa + size;
	u32 facts = 0;

	while (addr < end) {
		u64 base, gran, next, a;
		kvm_pte_t pte;

		if (pkvm_g2g_leaf(vm, addr, &pte, &base, &gran)) {
			facts |= PKVM_G2G_OFFER_STATE;	/* past the IPA space */
			break;
		}

		if (!kvm_pte_valid(pte)) {
			/* An annotation (MMIO guard) is not a page the caller owns. */
			facts |= pte ? PKVM_G2G_OFFER_STATE : PKVM_G2G_OFFER_UNMAPPED;
			addr += PAGE_SIZE;
			continue;
		}

		if (base < ipa || base + gran > end)
			facts |= PKVM_G2G_OFFER_STRADDLE;
		if (guest_get_page_state(pte, addr) != PKVM_PAGE_OWNED)
			facts |= PKVM_G2G_OFFER_STATE;

		next = min(base + gran, end);
		for (a = addr; a < next; a += PAGE_SIZE) {
			u64 phys = kvm_pte_to_phys(pte) + (a - base);

			/* Not RAM, under DMA, or not the guest's alone. */
			if (!addr_is_memory(phys) ||
			    hyp_page_referenced(hyp_phys_to_virt(phys)) ||
			    get_host_state(hyp_phys_to_page(phys)) != PKVM_NOPAGE)
				facts |= PKVM_G2G_OFFER_STATE;
		}
		addr = next;
	}

	return facts;
}

/*
 * Re-mark every leaf of [ipa, ipa + size) in @vm with @prot. Every leaf there
 * is valid and wholly inside the range (the caller checked), and only software
 * bits change, so kvm_pgtable_stage2_map() takes its "only changing software
 * bits" path: no break-before-make, no allocation, no failure. Caller holds
 * @vm's lock.
 */
static void pkvm_g2g_mark_leaves(struct pkvm_hyp_vm *vm,
				 struct kvm_hyp_memcache *mc, u64 ipa, u64 size,
				 enum kvm_pgtable_prot prot)
{
	u64 addr = ipa, end = ipa + size;

	while (addr < end) {
		u64 base, gran;
		kvm_pte_t pte;

		if (pkvm_g2g_leaf(vm, addr, &pte, &base, &gran) ||
		    !kvm_pte_valid(pte)) {
			addr += PAGE_SIZE;
			continue;
		}

		kvm_pgtable_stage2_map(&vm->pgt, base, gran, kvm_pte_to_phys(pte),
				       prot, mc, 0);
		addr = base + gran;
	}
}

/*
 * The physical page behind @ipa in owner @vm, if it is lent out as a share
 * leaves it (SHARED_OWNED | G2G, the owner's permissions untouched). Caller
 * holds @vm's lock.
 */
static bool pkvm_g2g_owner_page(struct pkvm_hyp_vm *vm, u64 ipa, u64 *phys)
{
	u64 base, gran;
	kvm_pte_t pte;

	if (pkvm_g2g_leaf(vm, ipa, &pte, &base, &gran) || !kvm_pte_valid(pte) ||
	    guest_get_page_state(pte, ipa) !=
	    (PKVM_PAGE_SHARED_OWNED | PKVM_PAGE_G2G))
		return false;

	*phys = kvm_pte_to_phys(pte) + (ipa - base);
	return true;
}

/*
 * The physical page behind @ipa in borrower @vm, if it is a borrowed share page
 * as ACCEPT maps one: SHARED_BORROWED | G2G at PAGE_SIZE. A borrowed page is
 * never executable, so guest_get_page_state() also reports RESTRICTED_PROT.
 * Caller holds @vm's lock.
 */
static bool pkvm_g2g_borrowed_page(struct pkvm_hyp_vm *vm, u64 ipa, u64 *phys)
{
	u64 base, gran;
	kvm_pte_t pte;

	if (pkvm_g2g_leaf(vm, ipa, &pte, &base, &gran) || !kvm_pte_valid(pte) ||
	    gran != PAGE_SIZE ||
	    (guest_get_page_state(pte, ipa) & ~PKVM_PAGE_RESTRICTED_PROT) !=
	    (PKVM_PAGE_SHARED_BORROWED | PKVM_PAGE_G2G))
		return false;

	*phys = kvm_pte_to_phys(pte);
	return true;
}

/* Every page of [ipa, ipa + size) in @vm is an all-zero PTE. Caller holds @vm's lock. */
static bool pkvm_g2g_dest_empty(struct pkvm_hyp_vm *vm, u64 ipa, u64 size)
{
	u64 addr, base, gran;
	kvm_pte_t pte;

	for (addr = ipa; addr < ipa + size; addr += PAGE_SIZE)
		if (pkvm_g2g_leaf(vm, addr, &pte, &base, &gran) || pte)
			return false;

	return true;
}

/*
 * Share @s is still lent out by its owner page for page, and every page's host
 * state is @host. Caller holds host_mmu.lock; the owner's lock is taken here.
 */
static bool pkvm_g2g_owner_consistent(struct pkvm_g2g_share *s,
				      enum pkvm_page_state host)
{
	bool ok = true;
	u64 i, phys;

	hyp_assert_lock_held(&host_mmu.lock);

	guest_lock_component(s->owner);
	for (i = 0; ok && i < s->nr_pages; i++)
		ok = pkvm_g2g_owner_page(s->owner, s->owner_ipa + i * PAGE_SIZE,
					 &phys) &&
		     get_host_state(hyp_phys_to_page(phys)) == host;
	guest_unlock_component(s->owner);

	return ok;
}

/*
 * Take [ipa, ipa + nr_pages * PAGE_SIZE) out of borrower @b and mark the pages
 * no longer lent. Caller holds host_mmu.lock; @b's lock is taken here.
 *
 * Returns true if every page was a borrowed page whose host state says lent.
 * With @check_only nothing changes. Without it, every page that is as expected
 * is dropped and any other is left alone: teardown cannot refuse, and leaving a
 * page held leaks it, where dropping a page we do not understand could hand it
 * out.
 */
static bool pkvm_g2g_drop_borrowed(struct pkvm_hyp_vm *b, u64 ipa, u64 nr_pages,
				   bool check_only)
{
	bool ok = true;
	u64 i, phys;

	hyp_assert_lock_held(&host_mmu.lock);

	guest_lock_component(b);
	for (i = 0; i < nr_pages; i++) {
		u64 addr = ipa + i * PAGE_SIZE;

		if (!pkvm_g2g_borrowed_page(b, addr, &phys) ||
		    get_host_state(hyp_phys_to_page(phys)) != PKVM_PAGE_G2G_LENT) {
			ok = false;
			continue;
		}
		if (check_only)
			continue;

		/* Invalidates @b's TLB for the page, by VMID and IPA. */
		kvm_pgtable_stage2_unmap(&b->pgt, addr, PAGE_SIZE);
		__host_update_page_state(phys, PAGE_SIZE, PKVM_NOPAGE);
	}
	guest_unlock_component(b);

	return ok;
}

/*
 * Map offered share @s into @vm at @ipa, one page at a time, all or nothing.
 * The caller holds host_mmu.lock and has checked, under it, that the share is
 * offered to @vm, the owner's pages are as offered, the destination is empty
 * and @mc covers a page-table path. The owner's pages cannot have changed since,
 * but @vm's own other vCPUs can map into the destination (MMIO guard needs only
 * @vm's lock), so each page is re-checked as it is mapped and the whole share
 * is taken back if one fails.
 */
static enum pkvm_g2g_share_verdict
pkvm_g2g_borrow(struct pkvm_g2g_share *s, struct pkvm_hyp_vm *vm,
		struct kvm_hyp_memcache *mc, u64 ipa)
{
	enum kvm_pgtable_prot prot = KVM_PGTABLE_PROT_R;
	u64 i, phys = 0, dst;
	bool ok = true;
	kvm_pte_t pte;
	s8 level;

	if (!(s->flags & ARM_SMCCC_KVM_G2G_SHARE_RO))
		prot |= KVM_PGTABLE_PROT_W;
	prot = pkvm_mkprot_g2g(pkvm_mkstate(prot, PKVM_PAGE_SHARED_BORROWED));

	for (i = 0; i < s->nr_pages; i++) {
		dst = ipa + i * PAGE_SIZE;

		guest_lock_component(s->owner);
		ok = pkvm_g2g_owner_page(s->owner, s->owner_ipa + i * PAGE_SIZE,
					 &phys);
		guest_unlock_component(s->owner);
		if (!ok)
			break;

		guest_lock_component(vm);
		ok = !kvm_pgtable_get_leaf(&vm->pgt, dst, &pte, &level) && !pte &&
		     !kvm_pgtable_stage2_map(&vm->pgt, dst, PAGE_SIZE, phys, prot,
					     mc, 0);
		guest_unlock_component(vm);
		if (!ok)
			break;

		__host_update_page_state(phys, PAGE_SIZE, PKVM_PAGE_G2G_LENT);
	}

	if (!ok) {
		/* Pages 0..i-1 are mapped and marked lent: take them back. */
		pkvm_g2g_drop_borrowed(vm, ipa, i, false);
		return PKVM_G2G_SHARE_DENIED;
	}

	s->state = PKVM_G2G_SHARE_ACCEPTED;
	s->borrower = vm;
	s->borrower_ipa = ipa;

	return PKVM_G2G_SHARE_DO;
}

static enum pkvm_g2g_share_verdict
__pkvm_g2g_share_offer(struct pkvm_hyp_vm *vm, struct kvm_hyp_memcache *mc,
		       u32 facts, u64 ipa, u64 nr_pages, u64 flags,
		       const struct pkvm_g2g_identity *to, u64 *handle)
{
	enum pkvm_g2g_share_verdict v;
	struct pkvm_g2g_share *s;
	u64 limit = BIT_ULL(vm->pgt.ia_bits);
	u64 size;

	*handle = 0;
	if (flags & ~ARM_SMCCC_KVM_G2G_SHARE_RO)
		facts |= PKVM_G2G_OFFER_FLAGS_BAD;
	if (!nr_pages || nr_pages > PKVM_G2G_SHARE_MAX_PAGES)
		facts |= PKVM_G2G_OFFER_NR_BAD;
	else if (!PAGE_ALIGNED(ipa) || ipa >= limit ||
		 nr_pages * PAGE_SIZE > limit - ipa)
		facts |= PKVM_G2G_OFFER_IPA_BAD;

	v = pkvm_g2g_offer_verdict(facts);
	if (v != PKVM_G2G_SHARE_DO)
		return v;

	size = nr_pages * PAGE_SIZE;
	host_lock_component();
	guest_lock_component(vm);

	s = pkvm_g2g_share_alloc(vm);
	if (!s)
		facts |= PKVM_G2G_OFFER_LIMIT;
	facts |= pkvm_g2g_offer_range_facts(vm, ipa, size);

	v = pkvm_g2g_offer_verdict(facts);
	if (v == PKVM_G2G_SHARE_DO) {
		pkvm_g2g_mark_leaves(vm, mc, ipa, size,
				     pkvm_mkprot_g2g(pkvm_mkstate(KVM_PGTABLE_PROT_RWX,
								  PKVM_PAGE_SHARED_OWNED)));
		if (!++pkvm_g2g_share_gen)
			pkvm_g2g_share_gen = 1;
		s->state = PKVM_G2G_SHARE_OFFERED;
		s->gen = pkvm_g2g_share_gen;
		s->flags = flags;
		s->nr_pages = nr_pages;
		s->owner = vm;
		s->owner_ipa = ipa;
		s->to = *to;
		*handle = pkvm_g2g_share_handle(s);
	}

	guest_unlock_component(vm);
	host_unlock_component();

	return v;
}

static enum pkvm_g2g_share_verdict
__pkvm_g2g_share_accept(struct pkvm_hyp_vm *vm, struct kvm_hyp_memcache *mc,
			struct pkvm_hyp_vm *owner, u32 facts, u64 ipa,
			u64 nr_pages, u64 handle, u64 flags, u64 *share_flags)
{
	u64 limit = BIT_ULL(vm->pgt.ia_bits);
	enum pkvm_g2g_share_verdict v;
	struct pkvm_g2g_share *s;
	u64 size;

	*share_flags = 0;
	if (flags)
		facts |= PKVM_G2G_ACCEPT_FLAGS_BAD;
	if (!nr_pages || nr_pages > PKVM_G2G_SHARE_MAX_PAGES)
		facts |= PKVM_G2G_ACCEPT_NR_BAD;
	else if (!PAGE_ALIGNED(ipa) || ipa >= limit ||
		 nr_pages * PAGE_SIZE > limit - ipa ||
		 (ipa & (PMD_SIZE - 1)) + nr_pages * PAGE_SIZE > PMD_SIZE)
		facts |= PKVM_G2G_ACCEPT_IPA_BAD;

	v = pkvm_g2g_accept_verdict(facts);
	if (v != PKVM_G2G_SHARE_DO)
		return v;

	size = nr_pages * PAGE_SIZE;
	host_lock_component();

	s = pkvm_g2g_share_find(handle);
	if (!s || s->owner != owner || s->nr_pages != nr_pages ||
	    s->to.lo != vm->g2g_id.lo || s->to.hi != vm->g2g_id.hi ||
	    s->to.incarnation != vm->g2g_id.incarnation) {
		facts |= PKVM_G2G_ACCEPT_NO_SHARE;
	} else if (s->state == PKVM_G2G_SHARE_ACCEPTED) {
		facts |= PKVM_G2G_ACCEPT_TAKEN;
	} else {
		if (!pkvm_g2g_owner_consistent(s, PKVM_NOPAGE))
			facts |= PKVM_G2G_ACCEPT_OWNER_STATE;

		guest_lock_component(vm);
		if (!pkvm_g2g_dest_empty(vm, ipa, size))
			facts |= PKVM_G2G_ACCEPT_DEST_BUSY;
		if (mc->nr_pages < kvm_mmu_cache_min_pages(&vm->kvm.arch.mmu))
			facts |= PKVM_G2G_ACCEPT_MEMCACHE_LOW;
		guest_unlock_component(vm);
	}

	v = pkvm_g2g_accept_verdict(facts);
	if (v == PKVM_G2G_SHARE_DO) {
		v = pkvm_g2g_borrow(s, vm, mc, ipa);
		if (v == PKVM_G2G_SHARE_DO)
			*share_flags = s->flags;
	}

	host_unlock_component();

	return v;
}

static enum pkvm_g2g_share_verdict
__pkvm_g2g_share_revoke(struct pkvm_hyp_vm *vm, struct kvm_hyp_memcache *mc,
			u64 handle, u64 flags)
{
	u32 facts = flags ? PKVM_G2G_END_FLAGS_BAD : 0;
	enum pkvm_g2g_share_verdict v;
	struct pkvm_g2g_share *s;
	bool accepted = false;

	v = pkvm_g2g_end_verdict(facts);
	if (v != PKVM_G2G_SHARE_DO)
		return v;

	host_lock_component();

	s = pkvm_g2g_share_find(handle);
	if (!s || s->owner != vm) {
		facts |= PKVM_G2G_END_NO_SHARE;
	} else {
		accepted = s->state == PKVM_G2G_SHARE_ACCEPTED;
		if (!pkvm_g2g_owner_consistent(s, accepted ? PKVM_PAGE_G2G_LENT :
							     PKVM_NOPAGE) ||
		    (accepted && !pkvm_g2g_drop_borrowed(s->borrower,
							  s->borrower_ipa,
							  s->nr_pages, true)))
			facts |= PKVM_G2G_END_DIVERGED;
	}

	v = pkvm_g2g_end_verdict(facts);
	if (v == PKVM_G2G_SHARE_DO) {
		/*
		 * The borrower first: its next access faults. No poison: the
		 * pages never leave the owner.
		 */
		if (accepted)
			pkvm_g2g_drop_borrowed(s->borrower, s->borrower_ipa,
					       s->nr_pages, false);
		guest_lock_component(vm);
		pkvm_g2g_mark_leaves(vm, mc, s->owner_ipa,
				     s->nr_pages * PAGE_SIZE,
				     pkvm_mkstate(KVM_PGTABLE_PROT_RWX,
						  PKVM_PAGE_OWNED));
		guest_unlock_component(vm);
		pkvm_g2g_share_free(s);
	}

	host_unlock_component();

	return v;
}

static enum pkvm_g2g_share_verdict
__pkvm_g2g_share_release(struct pkvm_hyp_vm *vm, u64 handle, u64 flags)
{
	u32 facts = flags ? PKVM_G2G_END_FLAGS_BAD : 0;
	enum pkvm_g2g_share_verdict v;
	struct pkvm_g2g_share *s;

	v = pkvm_g2g_end_verdict(facts);
	if (v != PKVM_G2G_SHARE_DO)
		return v;

	host_lock_component();

	s = pkvm_g2g_share_find(handle);
	if (!s || s->state != PKVM_G2G_SHARE_ACCEPTED || s->borrower != vm)
		facts |= PKVM_G2G_END_NO_SHARE;
	else if (!pkvm_g2g_drop_borrowed(vm, s->borrower_ipa, s->nr_pages, true))
		facts |= PKVM_G2G_END_DIVERGED;

	v = pkvm_g2g_end_verdict(facts);
	if (v == PKVM_G2G_SHARE_DO) {
		pkvm_g2g_drop_borrowed(vm, s->borrower_ipa, s->nr_pages, false);
		s->state = PKVM_G2G_SHARE_OFFERED;
		s->borrower = NULL;
		s->borrower_ipa = 0;
	}

	host_unlock_component();

	return v;
}

/*
 * Dismantle every share @vm is part of. Called from __pkvm_start_teardown_vm()
 * with the vm_table write lock held, in the same step that marks @vm dying, so
 * no moment exists where @vm is dying and still part of a share. @vm's vCPUs
 * can no longer be loaded.
 *
 *  - Where @vm borrows, the pages leave @vm's stage-2 and stop being lent. The
 *    record goes back to OFFERED with no borrower. It named @vm's incarnation,
 *    which is never reused, so nobody can accept it again, and the owner's
 *    REVOKE gives the owner its pages back.
 *  - Where @vm owns, the borrower loses the pages first (its next access
 *    faults), then the record is freed. @vm's own PTEs keep saying
 *    SHARED_OWNED | G2G with host state NOPAGE, which pkvm_g2g_reclaim_action()
 *    decides as SOLE_OWNER when the host reclaims them: poisoned, then given
 *    back. Nothing leaks, and the host needs no knowledge of any of it.
 */
void pkvm_g2g_share_vm_dying(struct pkvm_hyp_vm *vm)
{
	unsigned int i;

	host_lock_component();
	for (i = 0; i < PKVM_G2G_SHARE_MAX; i++) {
		struct pkvm_g2g_share *s = &pkvm_g2g_shares[i];

		if (s->state == PKVM_G2G_SHARE_FREE ||
		    (s->owner != vm && s->borrower != vm))
			continue;

		if (s->state == PKVM_G2G_SHARE_ACCEPTED) {
			pkvm_g2g_drop_borrowed(s->borrower, s->borrower_ipa,
					       s->nr_pages, false);
			s->state = PKVM_G2G_SHARE_OFFERED;
			s->borrower = NULL;
			s->borrower_ipa = 0;
		}

		if (s->owner == vm)
			pkvm_g2g_share_free(s);
	}
	host_unlock_component();
}

enum pkvm_g2g_share_verdict
pkvm_g2g_share_offer(struct pkvm_hyp_vcpu *vcpu, u32 peer_facts, u64 ipa,
		     u64 nr_pages, u64 flags, const struct pkvm_g2g_identity *to,
		     u64 *handle)
{
	return __pkvm_g2g_share_offer(pkvm_hyp_vcpu_to_hyp_vm(vcpu),
				      &vcpu->vcpu.arch.stage2_mc, peer_facts,
				      ipa, nr_pages, flags, to, handle);
}

enum pkvm_g2g_share_verdict
pkvm_g2g_share_accept(struct pkvm_hyp_vcpu *vcpu, struct pkvm_hyp_vm *owner,
		      u32 peer_facts, u64 ipa, u64 nr_pages, u64 handle,
		      u64 flags, u64 *share_flags)
{
	return __pkvm_g2g_share_accept(pkvm_hyp_vcpu_to_hyp_vm(vcpu),
				       &vcpu->vcpu.arch.stage2_mc, owner,
				       peer_facts, ipa, nr_pages, handle, flags,
				       share_flags);
}

enum pkvm_g2g_share_verdict
pkvm_g2g_share_revoke(struct pkvm_hyp_vcpu *vcpu, u64 handle, u64 flags)
{
	return __pkvm_g2g_share_revoke(pkvm_hyp_vcpu_to_hyp_vm(vcpu),
				       &vcpu->vcpu.arch.stage2_mc, handle, flags);
}

enum pkvm_g2g_share_verdict
pkvm_g2g_share_release(struct pkvm_hyp_vcpu *vcpu, u64 handle, u64 flags)
{
	return __pkvm_g2g_share_release(pkvm_hyp_vcpu_to_hyp_vm(vcpu), handle,
					flags);
}
#endif /* CONFIG_PKVM_GUEST_TO_GUEST: section 2 */

#ifdef CONFIG_PKVM_GUEST_TO_GUEST
/*
 * ============================================================================
 * Guest-to-guest sharing, 3 of 3: the lifecycle self-check.
 * ============================================================================
 *
 * Section 1's check proves the decisions. This one runs section 2's real
 * transitions against real stage-2 page tables, at EL2 init, before any guest
 * exists. Two scratch VMs - not in vm_table, so no guest or host call can
 * reach them - get page tables built the way pkvm_ownership_selftest() builds
 * its one, and two real pages go hyp -> host -> A through
 * __pkvm_hyp_donate_host() and __pkvm_host_donate_guest(), as a protected VM's
 * memory does. Every step is followed by a check of A's PTEs, B's PTEs, both
 * pages' host state and the share record. At the end A is torn down through
 * pkvm_g2g_share_vm_dying() and __pkvm_host_reclaim_page_guest(), the real
 * teardown path, and the pages must reach the host poisoned.
 *
 * Failures are counted, never WARNed: a hyp WARN is fatal on this tree, and a
 * check that panics the hypervisor tells nobody which step failed. The host
 * prints the counts from finalize_pkvm(); first_bad names the step.
 */
#define PKVM_G2G_ST_PGD_MAX	16	/* concatenated pgd pages a scratch VM may need */
#define PKVM_G2G_ST_POOL	4	/* spare table pages per scratch VM */
#define PKVM_G2G_ST_MC		4	/* vCPU memcache pages per scratch VM */
#define PKVM_G2G_ST_PAGES	2	/* the pages that are shared */

static struct pkvm_hyp_vm pkvm_g2g_st_vm[2];
static struct pkvm_hyp_vcpu pkvm_g2g_st_vcpu[2];
static u64 pkvm_g2g_st_ipa_a, pkvm_g2g_st_ipa_b, pkvm_g2g_st_phys;

static bool pkvm_g2g_st_take(void **scratch, unsigned long *left,
			     unsigned long n, void **out)
{
	if (*left < n)
		return false;
	*out = *scratch;
	*scratch += n * PAGE_SIZE;
	*left -= n;
	return true;
}

/*
 * @n pages aligned to their own size, which the stage-2 pgd needs: the VM's
 * pool hands it out as one buddy block. The pages skipped to get there are
 * simply not used. Fails, rather than letting the allocator WARN (fatal), if
 * @n is not a power of two or the scratch runs out.
 */
static bool pkvm_g2g_st_take_aligned(void **scratch, unsigned long *left,
				     unsigned long n, void **out)
{
	u64 phys = hyp_virt_to_phys(*scratch);
	void *unused;

	if (!n || (n & (n - 1)))
		return false;

	return pkvm_g2g_st_take(scratch, left,
				(ALIGN(phys, n * PAGE_SIZE) - phys) >> PAGE_SHIFT,
				&unused) &&
	       pkvm_g2g_st_take(scratch, left, n, out);
}

static bool pkvm_g2g_st_init_vm(int idx, void **scratch, unsigned long *left)
{
	struct pkvm_hyp_vm *vm = &pkvm_g2g_st_vm[idx];
	struct pkvm_hyp_vcpu *vcpu = &pkvm_g2g_st_vcpu[idx];
	unsigned long pgd_pages, i;
	void *p;

	vm->kvm.arch.mmu.arch = &vm->kvm.arch;
	vm->kvm.arch.mmu.pgt = &vm->pgt;
	vm->kvm.arch.mmu.vtcr = host_mmu.arch.mmu.vtcr;
	vm->kvm.arch.pkvm.pvmfw_load_addr = PVMFW_INVALID_LOAD_ADDR;
	vcpu->vcpu.arch.hw_mmu = &vm->kvm.arch.mmu;
	vcpu->vcpu.kvm = &vm->kvm;

	pgd_pages = kvm_pgtable_stage2_pgd_size(vm->kvm.arch.mmu.vtcr) >> PAGE_SHIFT;
	if (pgd_pages > PKVM_G2G_ST_PGD_MAX ||
	    !pkvm_g2g_st_take_aligned(scratch, left, pgd_pages, &p) ||
	    kvm_guest_prepare_stage2(vm, p, 0))
		return false;

	/* Spare table pages, as init_selftest_vm() gives its VM. */
	for (i = 0; i < PKVM_G2G_ST_POOL; i++) {
		if (!pkvm_g2g_st_take(scratch, left, 1, &p))
			return false;
		hyp_set_page_refcounted(hyp_virt_to_page(p));
		hyp_put_page(&vm->pool, p);
	}

	/* And a vCPU memcache, which ACCEPT insists on. */
	for (i = 0; i < PKVM_G2G_ST_MC; i++) {
		if (!pkvm_g2g_st_take(scratch, left, 1, &p))
			return false;
		push_hyp_memcache(&vcpu->vcpu.arch.stage2_mc, p,
				  hyp_virt_to_phys, 0);
	}

	return true;
}

/* @vm's state for @ipa, and whether it maps @phys (when it maps anything). */
static bool pkvm_g2g_st_pte(struct pkvm_hyp_vm *vm, u64 ipa, u64 phys,
			    enum pkvm_page_state want)
{
	kvm_pte_t pte;
	s8 level;
	bool ok;

	guest_lock_component(vm);
	ok = !kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level) &&
	     guest_get_page_state(pte, ipa) == want &&
	     (!kvm_pte_valid(pte) || kvm_pte_to_phys(pte) +
	      (ipa - ALIGN_DOWN(ipa, kvm_granule_size(level))) == phys);
	guest_unlock_component(vm);

	return ok;
}

/* Both pages: A's state, B's state, host state. */
static bool pkvm_g2g_st_is(enum pkvm_page_state a, enum pkvm_page_state b,
			   enum pkvm_page_state host)
{
	bool ok = true;
	u64 i, phys;

	host_lock_component();
	for (i = 0; i < PKVM_G2G_ST_PAGES; i++) {
		phys = pkvm_g2g_st_phys + i * PAGE_SIZE;
		ok &= pkvm_g2g_st_pte(&pkvm_g2g_st_vm[0],
				      pkvm_g2g_st_ipa_a + i * PAGE_SIZE, phys, a);
		ok &= pkvm_g2g_st_pte(&pkvm_g2g_st_vm[1],
				      pkvm_g2g_st_ipa_b + i * PAGE_SIZE, phys, b);
		ok &= get_host_state(hyp_phys_to_page(phys)) == host;
	}
	host_unlock_component();

	return ok;
}

static enum pkvm_g2g_share_state pkvm_g2g_st_rec(u64 handle)
{
	enum pkvm_g2g_share_state state;
	struct pkvm_g2g_share *s;

	host_lock_component();
	s = pkvm_g2g_share_find(handle);
	state = s ? s->state : PKVM_G2G_SHARE_FREE;
	host_unlock_component();

	return state;
}

/* B's permissions on its first borrowed page. */
static enum kvm_pgtable_prot pkvm_g2g_st_prot_b(void)
{
	struct pkvm_hyp_vm *vm = &pkvm_g2g_st_vm[1];
	kvm_pte_t pte = 0;
	s8 level;

	host_lock_component();
	guest_lock_component(vm);
	kvm_pgtable_get_leaf(&vm->pgt, pkvm_g2g_st_ipa_b, &pte, &level);
	guest_unlock_component(vm);
	host_unlock_component();

	return kvm_pgtable_stage2_pte_prot(pte);
}

/* Write @val over the first word of a page, or test that the page is all zero. */
static void pkvm_g2g_st_fill(u64 phys, u64 val)
{
	u64 *p = hyp_fixmap_map(phys);

	*p = val;
	hyp_fixmap_unmap();
}

static bool pkvm_g2g_st_zero(u64 phys)
{
	u64 *p = hyp_fixmap_map(phys);
	bool zero = true;
	unsigned int i;

	for (i = 0; i < PAGE_SIZE / sizeof(u64); i++)
		zero &= !p[i];
	hyp_fixmap_unmap();

	return zero;
}

/*
 * REVOKE as owner A's vCPU issues it: in guest context, with A's vCPU the
 * running one and A's stage-2 loaded, so that taking the pages out of B's
 * stage-2 flushes B's VMID through enter_vmid_context()'s guest-context path -
 * the one that has to switch to another guest's stage-2, which no host-context
 * call exercises. At init no vCPU is running, so A's scratch vCPU is made the
 * running one for the call. What stage-2 is loaded does not matter yet:
 * HCR_EL2.VM is still clear, and __pkvm_prot_finalize() loads the host's.
 */
static enum pkvm_g2g_share_verdict pkvm_g2g_st_revoke_as_guest(u64 handle)
{
	struct kvm_cpu_context *host_ctxt = &this_cpu_ptr(&kvm_host_data)->host_ctxt;
	struct pkvm_hyp_vcpu *a = &pkvm_g2g_st_vcpu[0];
	enum pkvm_g2g_share_verdict v;

	host_ctxt->__hyp_running_vcpu = &a->vcpu;
	__load_stage2(a->vcpu.arch.hw_mmu, kern_hyp_va(a->vcpu.arch.hw_mmu->arch));
	v = __pkvm_g2g_share_revoke(&pkvm_g2g_st_vm[0], &a->vcpu.arch.stage2_mc,
				    handle, 0);
	host_ctxt->__hyp_running_vcpu = NULL;
	__load_host_stage2();

	return v;
}

#define PKVM_G2G_ST_SO	(PKVM_PAGE_SHARED_OWNED | PKVM_PAGE_G2G)
#define PKVM_G2G_ST_SB	(PKVM_PAGE_SHARED_BORROWED | PKVM_PAGE_G2G | \
			 PKVM_PAGE_RESTRICTED_PROT)

static void pkvm_g2g_share_lifecycle_selftest(void *scratch,
					      unsigned long nr_pages)
{
	struct pkvm_hyp_vm *a = &pkvm_g2g_st_vm[0], *b = &pkvm_g2g_st_vm[1];
	struct kvm_hyp_memcache *mca = &pkvm_g2g_st_vcpu[0].vcpu.arch.stage2_mc;
	struct kvm_hyp_memcache *mcb = &pkvm_g2g_st_vcpu[1].vcpu.arch.stage2_mc;
	const u32 found = PKVM_G2G_SHARE_PEER_FOUND;
	u32 step = 0, before = pkvm_g2g_share_selftest_failures;
	u64 h, h2, sflags, pfn, gfn, i;
	void *pages;

#define PKVM_G2G_ST_STEP(cond)						\
	do {								\
		pkvm_g2g_share_check(cond, PKVM_G2G_SHARE_CHK_STEP, step); \
		step++;							\
	} while (0)
#define PKVM_G2G_ST_OFFER(flags, hp)					\
	__pkvm_g2g_share_offer(a, mca, found, pkvm_g2g_st_ipa_a,	\
			       PKVM_G2G_ST_PAGES, flags, &b->g2g_id, hp)
#define PKVM_G2G_ST_ACCEPT(hd)						\
	__pkvm_g2g_share_accept(b, mcb, a, found, pkvm_g2g_st_ipa_b,	\
				PKVM_G2G_ST_PAGES, hd, 0, &sflags)

	if (!pkvm_g2g_st_init_vm(0, &scratch, &nr_pages) ||
	    !pkvm_g2g_st_init_vm(1, &scratch, &nr_pages) ||
	    !pkvm_g2g_st_take(&scratch, &nr_pages, PKVM_G2G_ST_PAGES, &pages)) {
		pkvm_g2g_share_check(false, PKVM_G2G_SHARE_CHK_STEP, 0xffff);
		return;
	}

	a->g2g_id = (struct pkvm_g2g_identity){ .lo = 0x7473, .hi = 0xa, .incarnation = 1 };
	b->g2g_id = (struct pkvm_g2g_identity){ .lo = 0x7473, .hi = 0xb, .incarnation = 2 };
	pkvm_g2g_st_ipa_a = BIT_ULL(a->pgt.ia_bits - 2);
	pkvm_g2g_st_ipa_b = BIT_ULL(b->pgt.ia_bits - 1) - PMD_SIZE;
	pkvm_g2g_st_phys = hyp_virt_to_phys(pages);
	pfn = hyp_phys_to_pfn(pkvm_g2g_st_phys);
	gfn = hyp_phys_to_pfn(pkvm_g2g_st_ipa_a);

	/* 0-3: hyp -> host -> A, a page at a time, as guest memory arrives. */
	PKVM_G2G_ST_STEP(!__pkvm_hyp_donate_host(pfn, PKVM_G2G_ST_PAGES));
	for (i = 0; i < PKVM_G2G_ST_PAGES; i++)
		PKVM_G2G_ST_STEP(!__pkvm_host_donate_guest(pfn + i, gfn + i, 1,
							   &pkvm_g2g_st_vcpu[0]));
	PKVM_G2G_ST_STEP(pkvm_g2g_st_is(PKVM_PAGE_OWNED, PKVM_NOPAGE, PKVM_NOPAGE));
	if (pkvm_g2g_share_selftest_failures != before)
		goto out;	/* nothing below means anything without these */
	pkvm_g2g_st_fill(pkvm_g2g_st_phys, 0x6732672d73686172ULL);

	/* 4-5: offer; the pages stay A's, the host side does not move. */
	PKVM_G2G_ST_STEP(PKVM_G2G_ST_OFFER(0, &h) == PKVM_G2G_SHARE_DO);
	PKVM_G2G_ST_STEP(pkvm_g2g_st_is(PKVM_G2G_ST_SO, PKVM_NOPAGE, PKVM_NOPAGE) &&
			 pkvm_g2g_st_rec(h) == PKVM_G2G_SHARE_OFFERED);
	/* 6: not twice */
	PKVM_G2G_ST_STEP(PKVM_G2G_ST_OFFER(0, &h2) == PKVM_G2G_SHARE_DENIED && !h2);
	/* 7: a handle of another generation names nothing */
	PKVM_G2G_ST_STEP(PKVM_G2G_ST_ACCEPT(h + BIT_ULL(32)) == PKVM_G2G_SHARE_NO_SHARE);
	/* 8-9: accept: B maps A's two pages, lent host-side */
	PKVM_G2G_ST_STEP(PKVM_G2G_ST_ACCEPT(h) == PKVM_G2G_SHARE_DO && !sflags);
	PKVM_G2G_ST_STEP(pkvm_g2g_st_is(PKVM_G2G_ST_SO, PKVM_G2G_ST_SB, PKVM_PAGE_G2G_LENT) &&
			 pkvm_g2g_st_rec(h) == PKVM_G2G_SHARE_ACCEPTED &&
			 (pkvm_g2g_st_prot_b() & KVM_PGTABLE_PROT_W) &&
			 !(pkvm_g2g_st_prot_b() & KVM_PGTABLE_PROT_X));
	/* 10: taken */
	PKVM_G2G_ST_STEP(PKVM_G2G_ST_ACCEPT(h) == PKVM_G2G_SHARE_DENIED);
	/* 11: the borrower cannot revoke, the owner cannot release */
	PKVM_G2G_ST_STEP(__pkvm_g2g_share_revoke(b, mcb, h, 0) == PKVM_G2G_SHARE_NO_SHARE &&
			 __pkvm_g2g_share_release(a, h, 0) == PKVM_G2G_SHARE_NO_SHARE);
	/* 12-13: release */
	PKVM_G2G_ST_STEP(__pkvm_g2g_share_release(b, h, 0) == PKVM_G2G_SHARE_DO);
	PKVM_G2G_ST_STEP(pkvm_g2g_st_is(PKVM_G2G_ST_SO, PKVM_NOPAGE, PKVM_NOPAGE) &&
			 pkvm_g2g_st_rec(h) == PKVM_G2G_SHARE_OFFERED);
	/* 14: twice */
	PKVM_G2G_ST_STEP(__pkvm_g2g_share_release(b, h, 0) == PKVM_G2G_SHARE_NO_SHARE);
	/* 15-16: accepted again, then revoked with the pages mapped, from guest context */
	PKVM_G2G_ST_STEP(PKVM_G2G_ST_ACCEPT(h) == PKVM_G2G_SHARE_DO);
	PKVM_G2G_ST_STEP(pkvm_g2g_st_revoke_as_guest(h) == PKVM_G2G_SHARE_DO &&
			 pkvm_g2g_st_is(PKVM_PAGE_OWNED, PKVM_NOPAGE, PKVM_NOPAGE) &&
			 pkvm_g2g_st_rec(h) == PKVM_G2G_SHARE_FREE);
	/* 17: gone for both */
	PKVM_G2G_ST_STEP(__pkvm_g2g_share_revoke(a, mca, h, 0) == PKVM_G2G_SHARE_NO_SHARE &&
			 __pkvm_g2g_share_release(b, h, 0) == PKVM_G2G_SHARE_NO_SHARE);
	/* 18: read-only */
	PKVM_G2G_ST_STEP(PKVM_G2G_ST_OFFER(ARM_SMCCC_KVM_G2G_SHARE_RO, &h) == PKVM_G2G_SHARE_DO &&
			 PKVM_G2G_ST_ACCEPT(h) == PKVM_G2G_SHARE_DO &&
			 sflags == ARM_SMCCC_KVM_G2G_SHARE_RO &&
			 !(pkvm_g2g_st_prot_b() & KVM_PGTABLE_PROT_W));
	/* 19-20: the borrower dies first; the owner revokes */
	pkvm_g2g_share_vm_dying(b);
	PKVM_G2G_ST_STEP(pkvm_g2g_st_is(PKVM_G2G_ST_SO, PKVM_NOPAGE, PKVM_NOPAGE) &&
			 pkvm_g2g_st_rec(h) == PKVM_G2G_SHARE_OFFERED);
	PKVM_G2G_ST_STEP(__pkvm_g2g_share_revoke(a, mca, h, 0) == PKVM_G2G_SHARE_DO &&
			 pkvm_g2g_st_is(PKVM_PAGE_OWNED, PKVM_NOPAGE, PKVM_NOPAGE));
	/* 21-23: the owner dies first, the borrower mapping: B loses the pages */
	PKVM_G2G_ST_STEP(PKVM_G2G_ST_OFFER(0, &h) == PKVM_G2G_SHARE_DO &&
			 PKVM_G2G_ST_ACCEPT(h) == PKVM_G2G_SHARE_DO);
	pkvm_g2g_share_vm_dying(a);
	PKVM_G2G_ST_STEP(pkvm_g2g_st_is(PKVM_G2G_ST_SO, PKVM_NOPAGE, PKVM_NOPAGE) &&
			 pkvm_g2g_st_rec(h) == PKVM_G2G_SHARE_FREE);
	PKVM_G2G_ST_STEP(__pkvm_g2g_share_release(b, h, 0) == PKVM_G2G_SHARE_NO_SHARE);
	/* 24-26: the host reclaims A's pages through the real path: poisoned, returned */
	for (i = 0; i < PKVM_G2G_ST_PAGES; i++)
		PKVM_G2G_ST_STEP(!__pkvm_host_reclaim_page_guest(gfn + i, 1, a));
	PKVM_G2G_ST_STEP(pkvm_g2g_st_is(PKVM_NOPAGE, PKVM_NOPAGE, PKVM_PAGE_OWNED) &&
			 pkvm_g2g_st_zero(pkvm_g2g_st_phys) &&
			 pkvm_g2g_st_zero(pkvm_g2g_st_phys + PAGE_SIZE));
	/* 27: back to the hypervisor, where they came from */
	PKVM_G2G_ST_STEP(!__pkvm_host_donate_hyp(pfn, PKVM_G2G_ST_PAGES));

out:
	destroy_hyp_vm_pgt(a);
	destroy_hyp_vm_pgt(b);
	pkvm_g2g_share_selftest_steps = step;

#undef PKVM_G2G_ST_ACCEPT
#undef PKVM_G2G_ST_OFFER
#undef PKVM_G2G_ST_STEP
}

/*
 * Returns true if both parts passed, by the same test the host applies when
 * it prints PASS: the decisions ran, the lifecycle ran, and nothing failed.
 * Guest-to-guest stays disabled unless it did (see pkvm_g2g_enabled).
 */
bool pkvm_g2g_share_selftest(void *scratch, unsigned long nr_pages)
{
	pkvm_g2g_share_verdict_selftest();
	pkvm_g2g_share_lifecycle_selftest(scratch, nr_pages);

	return pkvm_g2g_share_selftest_inputs && pkvm_g2g_share_selftest_steps &&
	       !pkvm_g2g_share_selftest_failures;
}
#endif /* CONFIG_PKVM_GUEST_TO_GUEST: section 3 */

static int pkvm_host_donate_hyp(u64 pfn, u64 nr_pages, enum kvm_pgtable_prot prot,
				enum host_check_page_state_flags flags)
{
	u64 size, phys;
	void *virt;
	int ret;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	phys = hyp_pfn_to_phys(pfn);
	size = nr_pages * PAGE_SIZE;
	virt = __hyp_va(phys);

	host_lock_component();
	hyp_lock_component();

	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED, flags);
	if (ret)
		goto unlock;
	ret = __hyp_check_page_state_range(phys, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	ret = host_stage2_set_owner_locked(phys, size, PKVM_ID_HYP);
	if (ret)
		goto unlock;

	ret = pkvm_create_mappings_locked(virt, virt + size, prot);
	if (ret) {
		WARN_ON(ret != -ENOMEM);
		/* We might have failed halfway through, so remove anything we've installed */
		pkvm_remove_mappings_locked(virt, virt + size);
		host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST);
		goto unlock;
	}

	/*
	 * Only allow hyp MMIO transitions to/from the host
	 */
	if (range_is_memory(phys, phys + size))
		__hyp_set_page_state_range(phys, size, PKVM_PAGE_OWNED);

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

/* The Swiss Army knife of memory donation */
int ___pkvm_host_donate_hyp_prot(u64 pfn, u64 nr_pages,
				 bool accept_mmio, enum kvm_pgtable_prot prot)
{
	enum host_check_page_state_flags flags = HOST_CHECK_NULL_REFCNT;

	if (!accept_mmio)
		flags |= HOST_CHECK_IS_MEMORY;

	return pkvm_host_donate_hyp(pfn, nr_pages, prot, flags);
}

int ___pkvm_host_donate_hyp(u64 pfn, u64 nr_pages, bool accept_mmio)
{
	return ___pkvm_host_donate_hyp_prot(pfn, nr_pages, accept_mmio,
					    default_hyp_prot(hyp_pfn_to_phys(pfn)));
}

int __pkvm_host_donate_hyp(u64 pfn, u64 nr_pages)
{
	return ___pkvm_host_donate_hyp(pfn, nr_pages, false);
}

int __pkvm_host_donate_sglist_hyp(struct pkvm_sglist_page *sglist, size_t nr_pages)
{
	enum kvm_pgtable_prot prot;
	u8 max_order;
	size_t size;
	int p, ret;
	u64 phys;

	host_lock_component();
	hyp_lock_component();

	/* Checking we are reading hyp private memory */
	WARN_ON(__hyp_check_page_state_range(hyp_virt_to_phys(sglist),
					     PAGE_ALIGN(nr_pages * sizeof(*sglist)),
					     PKVM_PAGE_OWNED));

	for (p = 0; p < nr_pages; p++) {
		max_order = get_order(PMD_SIZE);

		if (sglist[p].order > max_order) {
			ret = -EINVAL;
			goto err_page_state;
		}
		size = PAGE_SIZE << sglist[p].order;

		if (!pfn_range_is_valid(sglist[p].pfn, size >> PAGE_SHIFT)) {
			ret = -EINVAL;
			goto err_page_state;
		}
		phys = hyp_pfn_to_phys(sglist[p].pfn);

		ret = __host_check_page_state_range(phys, size, PKVM_PAGE_OWNED);
		if (ret)
			goto err_page_state;

		ret = __hyp_check_page_state_range(phys, size, PKVM_NOPAGE);
		if (ret)
			goto err_page_state;

		prot = pkvm_mkstate(PAGE_HYP, PKVM_PAGE_OWNED);
		ret = pkvm_create_mappings_locked(__hyp_va(phys), __hyp_va(phys) + size, prot);
		if (ret == -ENOMEM)
			goto err_page_state;

		WARN_ON(ret);

		ret = __host_stage2_set_owner_locked(phys, size, PKVM_ID_HYP, 0,
						     HOST_SET_NO_COMPLETE);
		if (ret) {
			pkvm_remove_mappings_locked(__hyp_va(phys), __hyp_va(phys) + size);
			goto err_page_state;
		}

		__hyp_set_page_state_range(phys, size, PKVM_PAGE_OWNED);
	}

	__host_stage2_set_owner_complete(PKVM_ID_HYP, 0);

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
err_page_state:
	/*
	 * Roll back if either hyp stage-1 -ENOMEM or host stage-2 -ENOMEMHOSTS2
	 * or if the page state doesn't match the expected state.
	 */
	if (p == 0)
		goto unlock;

	__host_stage2_set_owner_complete(PKVM_ID_HYP, 0);
	while (p-- > 0) {
		phys = hyp_pfn_to_phys(sglist[p].pfn);
		size = PAGE_SIZE << sglist[p].order;

		__hyp_set_page_state_range(phys, size, PKVM_NOPAGE);
		pkvm_remove_mappings_locked(__hyp_va(phys), __hyp_va(phys) + size);
		WARN_ON(host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST));
	}
	goto unlock;
}

static int pkvm_hyp_donate_guest(struct pkvm_hyp_vcpu *vcpu, u64 pfn, u64 gfn)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 ipa = hyp_pfn_to_phys(gfn);
	u64 hyp_addr = (u64)__hyp_va(phys);
	size_t size = PAGE_SIZE;
	enum kvm_pgtable_prot prot;
	int ret;

	if (addr_is_memory(phys))
		return -EINVAL;

	hyp_assert_lock_held(&pkvm_pgd_lock);
	hyp_assert_lock_held(&vm->pgtable_lock);

	ret = __hyp_check_page_state_range(phys, size, PKVM_PAGE_OWNED);
	if (ret)
		return ret;
	ret = __guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE);
	if (ret)
		return ret;

	WARN_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, hyp_addr, size) != size);
	prot = pkvm_mkstate(KVM_PGTABLE_PROT_RW | KVM_PGTABLE_PROT_NORMAL_NC,
			      PKVM_PAGE_OWNED);
	return WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys, prot,
					      &vcpu->vcpu.arch.stage2_mc, 0));
}

int __pkvm_hyp_donate_host(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn);
	u64 virt = (u64)__hyp_va(phys);
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size))
		return -EINVAL;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	host_lock_component();
	hyp_lock_component();

	ret = __hyp_check_page_state_range(phys, size, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;
	ret = ___host_check_page_state_range(phys, size, PKVM_NOPAGE, 0);
	if (ret)
		goto unlock;

	/* See __pkvm_host_donate_hyp_locked() */
	if (range_is_memory(phys, phys + size))
		__hyp_set_page_state_range(phys, size, PKVM_NOPAGE);
	WARN_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, virt, size) != size);
	WARN_ON(host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST));

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

/*
 * Inverse of the MMIO branch of __pkvm_host_donate_hyp_locked().
 *
 * The donate side mapped the BAR into hyp's pgtable and flipped host
 * stage-2 ownership from PKVM_ID_HOST to PKVM_ID_HYP, but skipped the
 * hyp PKVM_PAGE_OWNED bookkeeping (the "if (range_is_memory(...))"
 * guard). __pkvm_hyp_donate_host therefore cannot be used to undo MMIO
 * donations: its initial PKVM_PAGE_OWNED check fails for ranges that
 * stayed at PKVM_NOPAGE on the hyp side. This helper performs the two
 * steps that actually need reversing — drop the hyp pgtable mapping
 * and flip host stage-2 ownership back — without touching the hyp
 * page-state tracker.
 *
 * Refuses non-MMIO ranges and ranges the host can still see (i.e. not
 * currently donated): both invariants must hold for a no-op-symmetric
 * reversal of the donate-mmio path.
 */
int __pkvm_hyp_reclaim_host_mmio(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn);
	u64 virt = (u64)__hyp_va(phys);
	u64 off;
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size))
		return -EINVAL;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	if (range_is_memory(phys, phys + size))
		return -EPERM;

	host_lock_component();
	hyp_lock_component();

	ret = ___host_check_page_state_range(phys, size, PKVM_NOPAGE, 0);
	if (ret)
		goto unlock;

	/*
	 * Per-page unmap: pages of an assigned BAR can be partially
	 * unmapped from pkvm_pgtable while the guest is alive (each
	 * pkvm_hyp_donate_guest() steals one page out of the linear
	 * map). The hyp_unmap_walker bails with -EINVAL on the first
	 * invalid PTE, so a single range-unmap call would stop at the
	 * first hole and leave subsequent valid entries behind. Walking
	 * page-by-page keeps each visit isolated — valid pages get
	 * unmapped, holes return 0 without aborting the next iteration.
	 */
	for (off = 0; off < size; off += PAGE_SIZE)
		kvm_pgtable_hyp_unmap(&pkvm_pgtable, virt + off, PAGE_SIZE);
	WARN_ON(host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST));

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

/*
 * Rejects MMIO regions and is unsafe (unless "full" mode). Use with care!
 */
int __pkvm_host_donate_ffa(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn), end;
	enum host_set_page_state_flags flags;
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size) ||
	    check_add_overflow(phys, size, &end))
		return -EINVAL;

	switch (__pkvm_ffa_unmap_on_lend) {
	case PKVM_FFA_UNMAP_ON_LEND_FULL:
		flags = 0;
		break;
	case PKVM_FFA_UNMAP_ON_LEND_ON:
		/* HOST_SET_NO_COMPLETE to skip pkvm_sme_dvmsync_fw_call() */
		flags = HOST_SET_NO_IOMMU_UPDATE | HOST_SET_NO_COMPLETE;
		break;
	case PKVM_FFA_UNMAP_ON_LEND_OFF:
		return -EPERM;
	}

	host_lock_component();

	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED,
					     HOST_CHECK_IS_MEMORY |
						     HOST_CHECK_NULL_REFCNT |
						     HOST_CHECK_ALLOW_NO_MAP);
	if (ret)
		goto unlock;

	ret = __host_stage2_set_owner_locked(phys, size, PKVM_ID_FFA, 0, flags);

unlock:
	host_unlock_component();
	return ret;
}

/*
 * Just like __pkvm_donate_ffa, rejects MMIO regions.
 */
int __pkvm_host_reclaim_ffa(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn), end;
	enum host_set_page_state_flags flags;
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size) ||
	    check_add_overflow(phys, size, &end))
		return -EINVAL;

	switch (__pkvm_ffa_unmap_on_lend) {
	case PKVM_FFA_UNMAP_ON_LEND_FULL:
		flags = 0;
		break;
	case PKVM_FFA_UNMAP_ON_LEND_ON:
		flags = HOST_SET_NO_IOMMU_UPDATE;
		break;
	case PKVM_FFA_UNMAP_ON_LEND_OFF:
		return -EPERM;
	}

	host_lock_component();

	ret = ___host_check_page_state_range(phys, size, PKVM_NOPAGE,
					     HOST_CHECK_IS_MEMORY |
						     HOST_CHECK_ALLOW_NO_MAP);
	if (ret)
		goto unlock;

	WARN_ON(__host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST, 0, flags));

unlock:
	host_unlock_component();
	return ret;
}

#define MODULE_PROT_ALLOWLIST (KVM_PGTABLE_PROT_RWX |		\
			       KVM_PGTABLE_PROT_DEVICE |	\
			       KVM_PGTABLE_PROT_NORMAL_NC |	\
			       KVM_PGTABLE_PROT_PXN |		\
			       KVM_PGTABLE_PROT_UXN)

int module_change_host_page_prot(u64 pfn, enum kvm_pgtable_prot prot,
				 u64 nr_pages, bool update_iommu)
{
	u64 i, end, addr = hyp_pfn_to_phys(pfn);
	struct hyp_page *page = NULL;
	struct kvm_mem_range range;
	struct memblock_region *reg;
	int ret;

	if ((prot & MODULE_PROT_ALLOWLIST) != prot)
		return -EINVAL;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &end) ||
			check_add_overflow(addr, end, &end))
		return -EINVAL;

	reg = find_mem_range(addr, &range);
	if (end > range.end) {
		/* Specified range not in a single mmio or memory block. */
		return -EPERM;
	}

	host_lock_component();
	/*
	 * There is no hyp_vmemmap covering MMIO regions, which makes tracking
	 * of module-owned MMIO regions hard, so we trust the modules not to
	 * mess things up.
	 */
	if (!reg)
		goto update;

	/* Range is memory: we can track module ownership. */
	page = hyp_phys_to_page(addr);

	/*
	 * Modules can only modify pages they already own, and pristine host
	 * pages. The entire range must be consistently one or the other.
	 */
	if (get_host_state(page) & PKVM_MODULE_OWNED_PAGE) {
		/* The entire range must be module-owned. */
		ret = -EPERM;
		for (i = 1; i < nr_pages; i++) {
			if (!(get_host_state(&page[i]) & PKVM_MODULE_OWNED_PAGE))
				goto unlock;
		}
	} else {
		/* The entire range must be pristine. */
		ret = ___host_check_page_state_range(addr, nr_pages << PAGE_SHIFT,
						     PKVM_PAGE_OWNED, HOST_CHECK_NULL_REFCNT);
		if (ret)
			goto unlock;
	}

update:
	if (!prot) {
		enum host_set_page_state_flags flags = 0;

		if (!reg)
			flags |= HOST_SET_IS_MMIO;
		if (!update_iommu)
			flags |= HOST_SET_NO_IOMMU_UPDATE;

		ret = __host_stage2_set_owner_locked(addr, nr_pages << PAGE_SHIFT,
						     PKVM_ID_PROTECTED,
						     PKVM_MODULE_OWNED_PAGE, flags);
	} else {
		/* !update_iommu is fast but not safe. For that reason it also skips dvmsync */
		if (!update_iommu) {
			ret = __host_stage2_idmap(addr, nr_pages << PAGE_SHIFT, prot, reg);
		} else {
			ret = host_stage2_idmap_locked(addr, nr_pages << PAGE_SHIFT, prot, reg);
			if (!ret) {
				WARN_ON(kvm_iommu_host_stage2_idmap(addr, end, prot));
				kvm_iommu_host_stage2_idmap_complete(!!prot);
			}
		}
	}

	if (ret || !page || !prot)
		goto unlock;

	for (i = 0; i < nr_pages; i++) {
		if (prot != KVM_PGTABLE_PROT_RWX)
			set_host_state(&page[i], PKVM_MODULE_OWNED_PAGE);
		else
			set_host_state(&page[i], PKVM_PAGE_OWNED);
	}

unlock:
	host_unlock_component();
	return ret;
}

int module_set_host_page_owned(u64 pfn, u64 nr_pages, bool owned)
{
	u64 size, phys;
	int ret;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	phys = hyp_pfn_to_phys(pfn);
	size = nr_pages * PAGE_SIZE;

	host_lock_component();

	ret = ___host_check_page_state_range(phys, size,
					     owned ? PKVM_PAGE_OWNED : PKVM_MODULE_OWNED_PAGE,
					     HOST_CHECK_IS_MEMORY | HOST_CHECK_NULL_REFCNT);
	if (ret)
		goto unlock;

	if (owned) {
		for_each_hyp_page(page, phys, size)
			set_host_state(page, PKVM_MODULE_OWNED_PAGE);
	} else {
		for_each_hyp_page(page, phys, size)
			set_host_state(page, PKVM_PAGE_OWNED);
	}

unlock:
	host_unlock_component();
	return ret;
}

int hyp_pin_shared_mem(void *from, void *to)
{
	u64 cur, start = ALIGN_DOWN((u64)from, PAGE_SIZE);
	u64 end = PAGE_ALIGN((u64)to);
	u64 phys = __hyp_pa(start);
	u64 size = end - start;
	struct hyp_page *p;
	int ret;

	host_lock_component();
	hyp_lock_component();

	ret = __host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	ret = __hyp_check_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;

	for (cur = start; cur < end; cur += PAGE_SIZE) {
		p = hyp_virt_to_page(cur);
		if (p->refcount == 0) {
			ret = pkvm_create_mappings_locked((void *)cur,
							  (void *)cur + PAGE_SIZE,
							  PAGE_HYP);
			if (ret)
				break;
		}
		hyp_page_ref_inc(p);
	}

	if (ret) {
		WARN_ON(ret != -ENOMEM);
		/* We might have failed halfway through, so remove anything we've installed */
		end = cur;
		for (cur = start; cur < end; cur += PAGE_SIZE) {
			p = hyp_virt_to_page(cur);
			hyp_page_ref_dec(p);
			if (p->refcount == 0)
				pkvm_remove_mappings_locked((void *)cur, (void *)cur + PAGE_SIZE);
		}
	}

unlock:
	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

void hyp_unpin_shared_mem(void *from, void *to)
{
	u64 cur, start = ALIGN_DOWN((u64)from, PAGE_SIZE);
	u64 end = PAGE_ALIGN((u64)to);
	struct hyp_page *p;

	host_lock_component();
	hyp_lock_component();

	for (cur = start; cur < end; cur += PAGE_SIZE) {
		p = hyp_virt_to_page(cur);
		if (p->refcount == 1)
			WARN_ON(kvm_pgtable_hyp_unmap(&pkvm_pgtable, cur, PAGE_SIZE) != PAGE_SIZE);
		hyp_page_ref_dec(p);
	}

	hyp_unlock_component();
	host_unlock_component();
}

int __pkvm_host_share_ffa(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn);
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size))
		return -EINVAL;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	host_lock_component();
	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED,
					     HOST_CHECK_IS_MEMORY |
						     HOST_CHECK_NULL_REFCNT |
						     HOST_CHECK_ALLOW_NO_MAP);
	if (!ret)
		__host_update_page_state(phys, size, PKVM_PAGE_SHARED_OWNED);
	host_unlock_component();

	return ret;
}

int __pkvm_host_unshare_ffa(u64 pfn, u64 nr_pages)
{
	u64 size, phys = hyp_pfn_to_phys(pfn);
	int ret;

	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size))
		return -EINVAL;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	host_lock_component();
	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_OWNED,
					     HOST_CHECK_IS_MEMORY |
						     HOST_CHECK_ALLOW_NO_MAP);
	if (!ret)
		__host_update_page_state(phys, size, PKVM_PAGE_OWNED);
	host_unlock_component();

	return ret;
}

static int __guest_check_transition_size(u64 phys, u64 ipa, u64 nr_pages, u64 *size)
{
	size_t block_size;

	if (nr_pages == 1) {
		*size = PAGE_SIZE;
		return 0;
	}

	/* We solely support second to last level huge mapping */
	block_size = kvm_granule_size(KVM_PGTABLE_LAST_LEVEL - 1);

	if (nr_pages != block_size >> PAGE_SHIFT)
		return -EINVAL;

	if (!IS_ALIGNED(phys | ipa, block_size))
		return -EINVAL;

	*size = block_size;
	return 0;
}

static void __hyp_poison_page(void *addr, size_t size)
{
	memset(addr, 0, size);
	__hyp_flush_page(addr, size);
}

void hyp_poison_page(phys_addr_t phys, size_t size)
{
	__apply_guest_page(__hyp_va(phys), size, __hyp_poison_page);
}

static int get_valid_guest_pte(struct pkvm_hyp_vm *vm, u64 ipa, kvm_pte_t *ptep, u64 *physp,
			       size_t size)
{
	kvm_pte_t pte;
	s8 level;
	int ret;

	if (size != PAGE_SIZE && size != PMD_SIZE)
		return -EINVAL;

	if (ipa != ALIGN_DOWN(ipa, size))
		return -EINVAL;

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret)
		return ret;
	if (!kvm_pte_valid(pte))
		return -ENOENT;
	if (kvm_granule_size(level) != size)
		return -E2BIG;

	*ptep = pte;
	*physp = kvm_pte_to_phys(pte);

	return 0;
}

/* Return PA for an owned guest IPA or request it, and repeat the guest HVC */
/*
 * TODO(g2g): this insists on PKVM_PAGE_OWNED and returns -EPERM for anything
 * else, so a page VM A has offered to a peer is ineligible for every caller of
 * this helper - which on this tree includes the pvIOMMU DMA request path via
 * pkvm_get_guest_pa_request_use_dma(). Decide deliberately whether a
 * guest-to-guest shared page may be used for DMA by its owner. Refusing is a
 * defensible answer and is what this state check does now as a side effect;
 * it should be the answer on purpose, with an error the caller can tell
 * apart.
 *
 * Note this site does not exist on the mainline-flavoured pKVM branches - it
 * is part of the Tegra pvIOMMU work carried by this tree.
 */
int pkvm_get_guest_pa_request(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa,
			      size_t ipa_size_request, u64 *out_pa, s8 *out_level)
{
	struct kvm_hyp_req *req;
	kvm_pte_t pte;
	enum pkvm_page_state state;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	int ret;

	guest_lock_component(vm);
	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, out_level);
	guest_unlock_component(vm);

	if (ret)
		return ret;

	if (!kvm_pte_valid(pte)) {
		/* Page not mapped, create a request*/
		req = pkvm_hyp_req_reserve(hyp_vcpu, KVM_HYP_REQ_TYPE_MAP);
		if (!req)
			return -ENOMEM;

		req->map.guest_ipa = ipa;
		req->map.size = ipa_size_request;
		return -ENOENT;
	}

	state = pkvm_getstate(kvm_pgtable_stage2_pte_prot(pte));
	if (state != PKVM_PAGE_OWNED)
		return -EPERM;

	*out_pa = kvm_pte_to_phys(pte);
	*out_pa |= (ipa & (kvm_granule_size(*out_level) - 1)) & PAGE_MASK;
	return 0;
}

static int ___pkvm_module_unshare_guest(struct pkvm_hyp_vm *vm, u64 phys, u64 ipa, u64 size)
{

	if (___host_check_page_state_range(phys, size, PKVM_MODULE_SHARED_OWNED_PAGE, HOST_CHECK_IS_MEMORY))
		return -EPERM;

	if (__guest_check_page_state_range(vm, ipa, size, PKVM_PAGE_SHARED_BORROWED))
		return -EPERM;

	WARN_ON(kvm_pgtable_stage2_unmap(&vm->pgt, ipa, size));
	__host_update_page_state(phys, size, PKVM_MODULE_OWNED_PAGE);

	return 0;
}

#ifdef CONFIG_PKVM_GUEST_TO_GUEST

/*
 * ============================================================================
 * Guest-to-guest teardown.
 * ============================================================================
 *
 * The reclaim path below is a matrix over (guest PTE state, host vmemmap
 * state) written on the assumption that a page lives in exactly one guest. The
 * two guest-to-guest orderings fall into it as follows *without* this code:
 *
 *  - borrower torn down first: its PTE is PKVM_PAGE_SHARED_BORROWED but the
 *    host state is PKVM_NOPAGE rather than PKVM_PAGE_SHARED_OWNED, so the
 *    WARN_ON fires, execution CONTINUES, and the function hands the owner's
 *    live, still-mapped page to the untrusted host. A WARN and then success;
 *
 *  - owner torn down first: -EBUSY, which the host's teardown loop in
 *    arch/arm64/kvm/pkvm.c treats as "retry", so the loop never terminates.
 *
 * Rather than bolt more cases onto that switch, the decision is lifted out
 * into a pure, total function over the two states. Lifting it out is what
 * makes it testable: pkvm_g2g_reclaim_selftest() below enumerates every
 * possible (guest, host) pair and checks the safety invariants, which a switch
 * embedded in a locked mutation path cannot be made to do.
 *
 * Naming: A is the VM that owns the page and lent it; B is the peer VM that
 * borrows it. "host" is the untrusted pKVM host.
 */
enum pkvm_g2g_reclaim_action {
	/*
	 * Not a guest-to-guest page. Run the legacy switch unchanged. This is
	 * the only action that reaches the pre-existing code.
	 */
	PKVM_G2G_RECLAIM_NOT_G2G,

	/*
	 * The two sides disagree, or a state combination exists that no
	 * transition can produce. Mutate nothing and return -ENOTRECOVERABLE.
	 * Refusing loses the page; repairing a divergence we do not understand
	 * could lose a guest's confidentiality, so refusing is the only answer.
	 */
	PKVM_G2G_RECLAIM_REFUSE,

	/*
	 * B is being reclaimed while A is still alive. Unmap from B and drop
	 * the host-side borrow marker. Do NOT poison: the contents belong to A,
	 * which still owns the page. Do NOT give the page to the host: A still
	 * maps it. This is the one teardown path in the file that deliberately
	 * does not poison on the way out, and the reason is that the page is
	 * not leaving its owner.
	 */
	PKVM_G2G_RECLAIM_DROP_BORROW,

	/*
	 * B is being reclaimed and A is already gone, so B is the last holder.
	 * Poison and hand the page back to the host. The poison is NOT
	 * redundant with the poison A's teardown already did: B had a writable
	 * mapping afterwards and may have written to the page, so it must be
	 * scrubbed again before the host can see it.
	 */
	PKVM_G2G_RECLAIM_LAST_HOLDER,

	/*
	 * A is being reclaimed and its PTE still says it lent the page, but the
	 * host side says no borrower remains - B released it, leaving A's PTE
	 * stale. A owns the page exclusively, so this is the ordinary
	 * PKVM_PAGE_OWNED case: poison and hand it to the host.
	 */
	PKVM_G2G_RECLAIM_SOLE_OWNER,

	/*
	 * A is being reclaimed while B still borrows. Not reached while a VM's
	 * shares are dismantled in the step that marks it dying, and refused
	 * with a distinguishable error if it ever is; see
	 * pkvm_g2g_reclaim_page().
	 */
	PKVM_G2G_RECLAIM_REFUSE_OWNER_FIRST,
};

/*
 * pkvm_g2g_reclaim_action - decide what reclaiming one page from one guest does
 * @guest_state: guest_get_page_state() of the page in the guest being reclaimed
 * @host_state:  get_host_state() of the same physical page
 *
 * Pure and total: every one of the possible inputs maps to exactly one action,
 * with no case falling into another and no reliance on a state combination
 * being unreachable. Called with both the host and the guest component locks
 * held, but it takes no locks and touches nothing itself.
 */
static enum pkvm_g2g_reclaim_action
pkvm_g2g_reclaim_action(enum pkvm_page_state guest_state,
			enum pkvm_page_state host_state)
{
	if (!(guest_state & PKVM_PAGE_G2G)) {
		/*
		 * The guest's PTE does not claim a peer relationship. If the
		 * host side says the page is in one, the two have diverged.
		 */
		if (pkvm_host_state_is_g2g(host_state))
			return PKVM_G2G_RECLAIM_REFUSE;

		/*
		 * A guest page in PKVM_PAGE_SHARED_BORROWED was lent either by
		 * the host, which then reads PKVM_PAGE_SHARED_OWNED, or by a
		 * hyp module, which then reads PKVM_MODULE_SHARED_OWNED_PAGE and
		 * is undone by ___pkvm_module_unshare_guest() in the switch below.
		 * Any other host state means we do not know who else maps the
		 * page. Refuse rather than hand it to the host.
		 */
		if ((guest_state & PKVM_PAGE_STATE_MASK) == PKVM_PAGE_SHARED_BORROWED &&
		    host_state != PKVM_PAGE_SHARED_OWNED &&
		    host_state != PKVM_MODULE_SHARED_OWNED_PAGE)
			return PKVM_G2G_RECLAIM_REFUSE;

		return PKVM_G2G_RECLAIM_NOT_G2G;
	}

	/*
	 * A peer relationship is claimed by the guest's PTE. Only the two
	 * SHARED states can carry it - PKVM_PAGE_OWNED means no counterparty
	 * and PKVM_NOPAGE has no PTE to carry a software bit in, so either
	 * combined with PKVM_PAGE_G2G is a contradiction.
	 */
	switch (guest_state & PKVM_PAGE_STATE_MASK) {
	case PKVM_PAGE_SHARED_OWNED:
		switch (host_state) {
		case PKVM_PAGE_G2G_LENT:
			return PKVM_G2G_RECLAIM_REFUSE_OWNER_FIRST;
		case PKVM_NOPAGE:
			return PKVM_G2G_RECLAIM_SOLE_OWNER;
		default:
			return PKVM_G2G_RECLAIM_REFUSE;
		}
	case PKVM_PAGE_SHARED_BORROWED:
		switch (host_state) {
		case PKVM_PAGE_G2G_LENT:
			return PKVM_G2G_RECLAIM_DROP_BORROW;
		case PKVM_PAGE_G2G_ORPHANED:
			return PKVM_G2G_RECLAIM_LAST_HOLDER;
		default:
			return PKVM_G2G_RECLAIM_REFUSE;
		}
	default:
		return PKVM_G2G_RECLAIM_REFUSE;
	}
}

/*
 * Returns true if the page was fully handled (and sets *ret), false if it is
 * not a guest-to-guest page and the caller should run the legacy switch.
 *
 * *ret is 0, or one of two codes meaning "EL2 deliberately kept the page,
 * mutated nothing, and the host must keep its pin". Nothing else on the
 * reclaim path returns either, so the host's teardown loop can match exactly
 * these and still treat every other error, the legacy switch's -EPERM
 * included, as before:
 *
 *   -EOWNERDEAD       the owner is being reclaimed while a peer still
 *                     borrows (PKVM_G2G_RECLAIM_REFUSE_OWNER_FIRST);
 *   -ENOTRECOVERABLE  the guest and host states disagree, or describe a
 *                     state no transition produces (PKVM_G2G_RECLAIM_REFUSE).
 *
 * Called with the host component lock and @vm's guest component lock held.
 * Only ever touches @vm's own stage-2 and the host side, never a peer's
 * stage-2, so it needs no second guest lock: the peer's stale PTE is resolved
 * by the host-side state, which is the point of keeping the last-holder fact
 * there rather than in the owner's page table.
 */
static bool pkvm_g2g_reclaim_page(struct pkvm_hyp_vm *vm, u64 ipa, u64 phys,
				  u64 size, u64 nr_pages, kvm_pte_t pte,
				  int *ret)
{
	enum pkvm_page_state host_state = get_host_state(hyp_phys_to_page(phys));
	enum pkvm_page_state guest_state = guest_get_page_state(pte, ipa);

	/*
	 * Fail closed. With guest-to-guest disabled - an EL2 self-check failed,
	 * see pkvm_g2g_enabled - nothing below is used and every page takes the
	 * legacy switch, exactly as with the option off.
	 *
	 * That is safe because no guest-to-guest share can exist. The only
	 * possible writers of guest-to-guest marking - PKVM_PAGE_G2G in a guest
	 * PTE, PKVM_PAGE_G2G_LENT/_ORPHANED in the host state - are the share
	 * transitions behind calls 12-20, which are refused before dispatch
	 * while guest-to-guest is disabled, and the share self-check, which
	 * runs them on two scratch VMs in pages the host reserved for nothing
	 * else, so no guest's page is marked by it (it runs with the flag set
	 * provisionally, see __pkvm_init_finalise()). The flag is final before
	 * any guest exists and never changes after, so no marking can survive
	 * from an earlier, enabled period either. What the legacy switch gets
	 * back is only the one non-guest-to-guest case this path also
	 * intercepts (see the comment at the call site), with the default
	 * build's behaviour.
	 */
	if (!pkvm_g2g_enabled)
		return false;

	/*
	 * The action is decided from the first page's host state but applied
	 * to the whole range, which is a 2 MiB block when the host pinned at
	 * PMD level. The guest state cannot vary across the range - it is one
	 * PTE - but the host state is per page. If the pages disagree and any
	 * of them is in a guest-to-guest relationship, refuse: deciding from
	 * page 0 could hand a peer's live page to the host (I1) or send a
	 * marked page to the legacy switch (I2). A range that disagrees with no
	 * guest-to-guest marking anywhere goes to the legacy switch, as before.
	 */
	for_each_hyp_page(page, phys, size) {
		enum pkvm_page_state s = get_host_state(page);

		if (s != host_state &&
		    ((guest_state & PKVM_PAGE_G2G) ||
		     pkvm_host_state_is_g2g(host_state) ||
		     pkvm_host_state_is_g2g(s))) {
			*ret = -ENOTRECOVERABLE;
			return true;
		}
	}

	switch (pkvm_g2g_reclaim_action(guest_state, host_state)) {
	case PKVM_G2G_RECLAIM_NOT_G2G:
		return false;

	case PKVM_G2G_RECLAIM_REFUSE:
		*ret = -ENOTRECOVERABLE;
		return true;

	case PKVM_G2G_RECLAIM_REFUSE_OWNER_FIRST:
		/*
		 * The owner is being reclaimed while a peer still borrows the
		 * page. No sequence of calls reaches this: only a dying VM's
		 * pages are reclaimed, and the step that marks a VM dying,
		 * __pkvm_start_teardown_vm(), first takes its shares out of
		 * their borrowers (pkvm_g2g_share_vm_dying()). It is refused,
		 * not acted on, if it ever happens.
		 *
		 * Acting on it would mean poisoning the page (the owner is
		 * dying, so its contents must not survive), unmapping it from
		 * the owner, and marking it PKVM_PAGE_G2G_ORPHANED so that the
		 * borrower's own reclaim returns it to the host later -
		 * poison-on-last-holder, the borrower side of which is
		 * PKVM_G2G_RECLAIM_LAST_HOLDER. EL2 cannot finish that alone,
		 * because the host's teardown loop in arch/arm64/kvm/pkvm.c
		 * (__pkvm_pgtable_stage2_unmap()) would have only two outcomes
		 * for it, and neither is "keep your pin, this page is not
		 * yours yet":
		 *
		 *   -EBUSY         -> nr_busy++, "goto retry", i.e. retry
		 *                     forever. Nothing can clear this one: the
		 *                     borrower is a different struct kvm and
		 *                     is torn down by a separate sequence, so
		 *                     the loop would never terminate.
		 *   anything else  -> WARN_ON(ret), then
		 *                     unpin_user_pages_dirty_lock() and
		 *                     kvm_pinned_pages_remove(). The host drops
		 *                     its pin and forgets the page while the
		 *                     borrower's stage-2 still maps it. The
		 *                     host cannot read it - the host stage-2
		 *                     annotation is still PKVM_ID_GUEST - but
		 *                     its allocator now believes it owns a page
		 *                     it will fault on, and the borrower retains
		 *                     a mapping to memory the host may reuse.
		 *
		 * So EL2 refuses with -EOWNERDEAD, and the host loop has a
		 * third outcome for exactly this code (and for
		 * -ENOTRECOVERABLE, the other "EL2 kept the page" answer): it
		 * keeps its pin and stops tracking the page, so the page leaks
		 * and the loop terminates. Neither code is returned by anything
		 * else on this path, so the legacy switch's -EPERM keeps its
		 * legacy handling. Refusing at EL2 is not enough on its own -
		 * without that host branch the refusal would land in the second
		 * case above.
		 */
		*ret = -EOWNERDEAD;
		return true;

	case PKVM_G2G_RECLAIM_DROP_BORROW:
		__host_update_page_state(phys, size, PKVM_NOPAGE);
		/* TLB: done per VMID on the dying guest's finalize path. */
		WARN_ON(kvm_pgtable_stage2_unmap(&vm->pgt, ipa, size));
		*ret = 0;
		return true;

	case PKVM_G2G_RECLAIM_LAST_HOLDER:
	case PKVM_G2G_RECLAIM_SOLE_OWNER:
		/*
		 * The page is leaving every guest, so it is poisoned and
		 * psci_mem_protect_dec()'d exactly once here - the owner's
		 * reclaim did not decrement, because the page did not reach the
		 * host then.
		 */
		hyp_poison_page(phys, size);
		psci_mem_protect_dec(nr_pages);
		WARN_ON(kvm_pgtable_stage2_unmap(&vm->pgt, ipa, size));
		WARN_ON(host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST));
		*ret = 0;
		return true;
	}

	/* Unreachable: pkvm_g2g_reclaim_action() is total. Refuse anyway. */
	*ret = -ENOTRECOVERABLE;
	return true;
}

/*
 * Exhaustive check of pkvm_g2g_reclaim_action() over every (guest state, host
 * state) pair, run once at EL2 init.
 *
 * This is what makes the state machine above verified rather than merely
 * written. Running guests reach few of these cases: every share a VM is part
 * of is dismantled in the step that marks it dying, so the host's reclaim meets
 * a guest-to-guest page only as PKVM_G2G_RECLAIM_SOLE_OWNER. An argument that
 * the rest are correct has to come from somewhere else.
 *
 * The two invariants are the ones whose violation is a security bug rather than
 * an error:
 *
 *   I1  no input produces an action that hands the page to the host while the
 *       host side still says a peer holds it;
 *   I2  no input in which either side carries guest-to-guest marking is routed
 *       to the legacy switch, which is the code that gets I1 wrong.
 *
 * Followed by the named transitions, so that a later edit which keeps the
 * invariants but changes the meaning of a case is still caught.
 */
/*
 * The self-check's verdict, read and reported by the host in finalize_pkvm():
 * this runs before any hyp serial driver has registered, so the hyp_info() and
 * hyp_err() calls below normally print nothing. pkvm_g2g_selftest_pairs == 0
 * means it did not run.
 *
 * The verdict is also returned, and a failure turns guest-to-guest off as a
 * whole (see pkvm_g2g_enabled) instead of WARNing: a hyp WARN is fatal on this
 * tree, so it would stop the machine before the host could print the FAIL
 * line, which is the only place a failure here can be read.
 */
u32 pkvm_g2g_selftest_pairs;
u32 pkvm_g2g_selftest_cases;
u32 pkvm_g2g_selftest_failures;

bool pkvm_g2g_reclaim_selftest(void)
{
	static const struct {
		enum pkvm_page_state guest, host;
		enum pkvm_g2g_reclaim_action want;
		const char *what;
	} cases[] = {
		{ PKVM_PAGE_SHARED_OWNED | PKVM_PAGE_G2G, PKVM_PAGE_G2G_LENT,
		  PKVM_G2G_RECLAIM_REFUSE_OWNER_FIRST, "owner first, borrower live" },
		{ PKVM_PAGE_SHARED_OWNED | PKVM_PAGE_G2G, PKVM_NOPAGE,
		  PKVM_G2G_RECLAIM_SOLE_OWNER, "owner, borrower already gone" },
		{ PKVM_PAGE_SHARED_BORROWED | PKVM_PAGE_G2G, PKVM_PAGE_G2G_LENT,
		  PKVM_G2G_RECLAIM_DROP_BORROW, "borrower first, owner live" },
		{ PKVM_PAGE_SHARED_BORROWED | PKVM_PAGE_G2G, PKVM_PAGE_G2G_ORPHANED,
		  PKVM_G2G_RECLAIM_LAST_HOLDER, "borrower last, owner gone" },
		{ PKVM_PAGE_SHARED_BORROWED, PKVM_NOPAGE,
		  PKVM_G2G_RECLAIM_REFUSE, "the silently-unsafe legacy case" },
		{ PKVM_PAGE_SHARED_BORROWED, PKVM_PAGE_SHARED_OWNED,
		  PKVM_G2G_RECLAIM_NOT_G2G, "ordinary host-to-guest borrow" },
		{ PKVM_PAGE_OWNED, PKVM_NOPAGE,
		  PKVM_G2G_RECLAIM_NOT_G2G, "ordinary donated guest page" },
		{ PKVM_PAGE_SHARED_OWNED, PKVM_PAGE_SHARED_BORROWED,
		  PKVM_G2G_RECLAIM_NOT_G2G, "ordinary guest-to-host share" },
		{ PKVM_PAGE_OWNED | PKVM_PAGE_G2G, PKVM_NOPAGE,
		  PKVM_G2G_RECLAIM_REFUSE, "owned page claiming a peer" },
		{ PKVM_PAGE_SHARED_OWNED, PKVM_PAGE_G2G_LENT,
		  PKVM_G2G_RECLAIM_REFUSE, "host side says peer, guest side does not" },
	};
	unsigned int guest, host, i, pairs = 0, bad = 0;

	/*
	 * Guest states span every state/meta bit up to PKVM_PAGE_G2G;
	 * host states are whatever fits hyp_page.__host_state, which is 4 bits.
	 */
	for (guest = 0; guest < 2 * PKVM_PAGE_G2G; guest++) {
		for (host = 0; host < BIT(4); host++) {
			enum pkvm_g2g_reclaim_action act =
				pkvm_g2g_reclaim_action(guest, host);
			bool gives_to_host =
				act == PKVM_G2G_RECLAIM_LAST_HOLDER ||
				act == PKVM_G2G_RECLAIM_SOLE_OWNER;
			bool marked = (guest & PKVM_PAGE_G2G) ||
				      pkvm_host_state_is_g2g(host);

			pairs++;

			/* I1 */
			if (host == PKVM_PAGE_G2G_LENT && gives_to_host) {
				hyp_err("pkvm-g2g: I1 violated: guest=0x%x host=0x%x act=%d",
					guest, host, (int)act);
				bad++;
			}

			/* I2 */
			if (marked && act == PKVM_G2G_RECLAIM_NOT_G2G) {
				hyp_err("pkvm-g2g: I2 violated: guest=0x%x host=0x%x",
					guest, host);
				bad++;
			}
		}
	}

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		enum pkvm_g2g_reclaim_action act =
			pkvm_g2g_reclaim_action(cases[i].guest, cases[i].host);

		if (act != cases[i].want) {
			hyp_err("pkvm-g2g: case \"%s\" gave %d, wanted %d",
				cases[i].what, (int)act, (int)cases[i].want);
			bad++;
		}
	}

	pkvm_g2g_selftest_pairs = pairs;
	pkvm_g2g_selftest_cases = ARRAY_SIZE(cases);
	pkvm_g2g_selftest_failures = bad;

	hyp_info("pkvm-g2g: reclaim matrix self-check: %s (%u pairs, %u named cases, %u failures)",
		 bad ? "FAIL" : "PASS", pairs, (unsigned int)ARRAY_SIZE(cases), bad);

	return !bad;
}

#endif /* CONFIG_PKVM_GUEST_TO_GUEST */

int __pkvm_host_reclaim_page_guest(u64 gfn, u64 nr_pages, struct pkvm_hyp_vm *vm)
{
	u64 phys, size, ipa = hyp_pfn_to_phys(gfn);
	enum host_set_page_state_flags flags;
	kvm_pte_t pte;
	int ret;

	ret = __guest_check_transition_size(0, ipa, nr_pages, &size);
	if (ret)
		return ret;

	if (!pkvm_hyp_vm_is_protected(vm))
		return -EPERM;

	host_lock_component();
	guest_lock_component(vm);

	ret = get_valid_guest_pte(vm, ipa, &pte, &phys, size);
	if (ret)
		goto unlock;

#ifdef CONFIG_PKVM_GUEST_TO_GUEST
	/*
	 * Guest-to-guest pages are decided by pkvm_g2g_reclaim_action() and
	 * never reach the switch below, which assumes a page lives in exactly
	 * one guest and hands a peer's live page to the host when that
	 * assumption breaks. See the block comment above
	 * pkvm_g2g_reclaim_action().
	 *
	 * This also intercepts one combination that is not guest-to-guest at
	 * all: a PKVM_PAGE_SHARED_BORROWED guest page whose host state is not
	 * PKVM_PAGE_SHARED_OWNED. The switch below merely WARNs about that and
	 * then hands the page over; it is refused here instead. A reviewer may
	 * reasonably want that one fix unconditional rather than under this
	 * option - it is correct in every configuration. It is gated so that a
	 * kernel without CONFIG_PKVM_GUEST_TO_GUEST generates the code it
	 * always has, and because the situation it guards against requires
	 * bookkeeping that is already corrupt.
	 */
	if (pkvm_g2g_reclaim_page(vm, ipa, phys, size, nr_pages, pte, &ret))
		goto unlock;
#endif

	switch ((int)guest_get_page_state(pte, ipa)) {
	case PKVM_PAGE_OWNED:
		WARN_ON(__host_check_page_state_range(phys, size, PKVM_NOPAGE));
		hyp_poison_page(phys, size);
		flags = HOST_SET_PSCI_MEM_PROTECT;
		break;
	case PKVM_PAGE_SHARED_BORROWED:
	case PKVM_PAGE_SHARED_BORROWED | PKVM_PAGE_RESTRICTED_PROT:
		ret = ___pkvm_module_unshare_guest(vm, phys, ipa, size);
		goto unlock;
	case PKVM_PAGE_SHARED_OWNED:
		if (__host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED)) {
			/* Presumably a page shared via FF-A, will be handled separately */
			ret = -EBUSY;
			goto unlock;
		}

		/* We only need to clear PKVM_PAGE_SHARED_BORROWED from the SW-bits */
		flags = HOST_SET_NO_COMPLETE | HOST_SET_NO_IOMMU_UPDATE;
		break;
	default:
		ret = -EPERM;
		goto unlock;
	}

	/* We could avoid TLB inval, it is done per VMID on the finalize path */
	WARN_ON(kvm_pgtable_stage2_unmap(&vm->pgt, ipa, size));
	WARN_ON(__host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST, 0, flags));

unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

int __pkvm_guest_share_host(u64 gfn, struct pkvm_hyp_vcpu *vcpu, u64 nr_pages, u64 *nr_shared)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);
	enum kvm_pgtable_prot prot;
	kvm_pte_t pte;
	size_t size;
	u64 phys;
	int ret;

	host_lock_component();
	guest_lock_component(vm);
	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vm, PKVM_PAGE_OWNED);
	if (ret)
		goto unlock;

	phys = kvm_pte_to_phys(pte);
	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size)) {
		ret = -EINVAL;
		goto unlock;
	}

	ret = __host_check_page_state_range(phys, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	/*
	 * Setting PKVM_PAGE_SHARED_BORROWED ensures this mapping is refcounted
	 * which prevents stage-2 coalescing.
	 */
	prot = pkvm_mkstate(PKVM_HOST_MEM_PROT, PKVM_PAGE_SHARED_BORROWED);
	ret = host_stage2_idmap_locked(phys, size, prot, true);
	if (ret)
		goto unlock;

	WARN_ON(kvm_iommu_host_stage2_idmap(phys, phys + size, PKVM_HOST_MEM_PROT));
	kvm_iommu_host_stage2_idmap_complete(true);

	__host_update_page_state(phys, size, PKVM_PAGE_SHARED_BORROWED);

	psci_mem_protect_dec(nr_pages);
	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys,
				       pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_SHARED_OWNED),
				       &vcpu->vcpu.arch.stage2_mc, 0));
	*nr_shared = nr_pages;
unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

int __pkvm_guest_unshare_host(u64 gfn, struct pkvm_hyp_vcpu *vcpu, u64 nr_pages, u64 *nr_unshared)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);
	kvm_pte_t pte;
	size_t size;
	u64 phys;
	int ret;

	host_lock_component();
	guest_lock_component(vm);
	ret = __guest_request_page_transition(ipa, &pte, &nr_pages, vm, PKVM_PAGE_SHARED_OWNED);
	if (ret)
		goto unlock;

	phys = kvm_pte_to_phys(pte);
	if (check_shl_overflow(nr_pages, PAGE_SHIFT, &size)) {
		ret = -EINVAL;
		goto unlock;
	}

	ret = __host_check_page_state_range(phys, size, PKVM_PAGE_SHARED_BORROWED);
	if (ret)
		goto unlock;

	ret = __host_stage2_set_owner_locked(phys, size, PKVM_ID_GUEST, 0,
					     HOST_SET_PSCI_MEM_PROTECT);
	if (ret)
		goto unlock;

	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys,
				       pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED),
				       &vcpu->vcpu.arch.stage2_mc, 0));
	*nr_unshared = nr_pages;
unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

static int ___pkvm_check_module_share_guest(struct pkvm_hyp_vm *vm, u64 phys, u64 ipa, u64 size)
{
	int ret;

	ret = ___host_check_page_state_range(phys, size,
					     PKVM_NOPAGE | PKVM_MODULE_OWNED_PAGE,
					     HOST_CHECK_IS_MEMORY);
	/*
	 * module_set_host_page_owned() sets PKVM_MODULE_OWNED_PAGE without
	 * PKVM_NOPAGE.
	 */
	if (ret == -EPERM)
		ret = ___host_check_page_state_range(phys, size, PKVM_MODULE_OWNED_PAGE,
						     HOST_CHECK_IS_MEMORY);
	if (ret)
		return ret;

	ret = __guest_check_page_state_range(vm, ipa, size,
					     PKVM_NOPAGE | PKVM_ACCEPT_MODULE_OWNED);
	if (ret)
		return ret;

	return module_guest_accept_module_owned_share(phys, ipa, size, vm);
}

static int ___pkvm_module_share_guest(u64 pfn, u64 gfn, u64 nr_pages, struct pkvm_hyp_vcpu *vcpu)
{
	enum kvm_pgtable_prot prot = pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_SHARED_BORROWED);
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 size = nr_pages * PAGE_SIZE;
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 ipa = hyp_pfn_to_phys(gfn);
	int ret;

	ret = ___pkvm_check_module_share_guest(vm, phys, ipa, size);
	if (!ret) {
		__host_update_page_state(phys, size, PKVM_MODULE_SHARED_OWNED_PAGE);
		WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys, prot,
					       &vcpu->vcpu.arch.stage2_mc, 0));
	}

	return ret;
}

int __pkvm_host_donate_guest(u64 pfn, u64 gfn, u64 nr_pages, struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 ipa = hyp_pfn_to_phys(gfn);
	enum kvm_pgtable_prot prot;
	u64 size;
	int ret;

	ret = __guest_check_transition_size(phys, ipa, nr_pages, &size);
	if (ret)
		return ret;

	host_lock_component();
	guest_lock_component(vm);

	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED,
					     HOST_CHECK_NULL_REFCNT |
					     HOST_CHECK_IS_MEMORY);
	if (ret) {
		if (ret == -EPERM)
			ret = ___pkvm_module_share_guest(pfn, gfn, nr_pages, vcpu);
		goto unlock;
	}

	ret = __guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	ret = __host_stage2_set_owner_locked(phys, size, PKVM_ID_GUEST, 0,
					     HOST_SET_PSCI_MEM_PROTECT);
	if (ret)
		goto unlock;

	if (pkvm_ipa_range_has_pvmfw(vm, ipa, ipa + size))
		WARN_ON(pkvm_load_pvmfw_pages(vm, ipa, phys, size));

	prot = pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED);
	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys, prot,
		&vcpu->vcpu.arch.stage2_mc, 0));
unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

struct kvm_hyp_pinned_page *hyp_ppages;

static int __copy_hyp_ppages(struct pkvm_hyp_vcpu *vcpu)
{
	struct kvm_hyp_pinned_page *ppage, *hyp_ppage;

	WARN_ON(!hyp_ppages);

	ppage = next_kvm_hyp_pinned_page(vcpu->vcpu.arch.hyp_reqs, NULL, true);
	if (!ppage)
		return -EINVAL;

	hyp_ppage = hyp_ppages;

	do {
		memcpy(hyp_ppage, ppage, sizeof(*ppage));
		ppage = next_kvm_hyp_pinned_page(vcpu->vcpu.arch.hyp_reqs, ppage, true);
		hyp_ppage++; /* No risk to overflow hyp_ppages */
	} while (ppage);

	hyp_ppage->order = 0xFF;

	return 0;
}

#define for_each_hyp_ppage(hyp_ppage)						\
	for (hyp_ppage = hyp_ppages; (hyp_ppage)->order != 0xFF; (hyp_ppage)++)

static int ___pkvm_module_share_guest_sglist(struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct kvm_hyp_pinned_page *ppage = hyp_ppages;
	u64 phys, ipa, size;
	int ret;

	for_each_hyp_ppage(ppage) {
		phys = hyp_pfn_to_phys(ppage->pfn);
		ipa = hyp_pfn_to_phys(ppage->gfn);

		if (!pfn_range_is_valid(ppage->pfn, 1UL << ppage->order)) {
			ret = -EINVAL;
			goto fail;
		}

		ret = __guest_check_transition_size(phys, ipa, 1UL << ppage->order, &size);
		if (ret)
			goto fail;

		ret = ___pkvm_check_module_share_guest(vm, phys, ipa, size);
		if (ret)
			goto fail;

		__host_update_page_state(phys, size, PKVM_MODULE_SHARED_OWNED_PAGE);
	}

	for_each_hyp_ppage(ppage) {
		phys = hyp_pfn_to_phys(ppage->pfn);
		ipa = hyp_pfn_to_phys(ppage->gfn);
		size = PAGE_SIZE << ppage->order;
		enum kvm_pgtable_prot prot = pkvm_mkstate(
			KVM_PGTABLE_PROT_RWX, PKVM_PAGE_SHARED_BORROWED);

		WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys, prot,
					       &vcpu->vcpu.arch.stage2_mc, 0));
	}

	return 0;

fail:
	while (ppage-- != hyp_ppages) {
		u64 phys = hyp_pfn_to_phys(ppage->pfn);
		u64 size = PAGE_SIZE << ppage->order;

		__host_update_page_state(phys, size, PKVM_MODULE_OWNED_PAGE);
	}
	return ret;
}

int __pkvm_host_donate_sglist_guest(struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	struct kvm_hyp_pinned_page *ppage = hyp_ppages;
	enum kvm_pgtable_prot prot;
	u64 phys, ipa, size;
	int ret;

	host_lock_component();
	guest_lock_component(vm);

	ret = __copy_hyp_ppages(vcpu);
	if (ret)
		goto unlock;

	for_each_hyp_ppage(ppage) {
		phys = hyp_pfn_to_phys(ppage->pfn);
		ipa = hyp_pfn_to_phys(ppage->gfn);

		if (!pfn_range_is_valid(ppage->pfn, 1UL << ppage->order)) {
			ret = -EINVAL;
			goto err_rollback;
		}

		ret = __guest_check_transition_size(phys, ipa, 1UL << ppage->order, &size);
		if (ret)
			goto err_rollback;

		ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED,
						     HOST_CHECK_NULL_REFCNT |
						     HOST_CHECK_IS_MEMORY);
		if (ret)
			goto err_rollback;

		ret = __guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE);
		if (ret)
			goto err_rollback;

		ret = __host_stage2_set_owner_locked(phys, size, PKVM_ID_GUEST, 0,
						     HOST_SET_NO_COMPLETE |
						     HOST_SET_PSCI_MEM_PROTECT);
		if (ret)
			goto err_rollback;
	}
	__host_stage2_set_owner_complete(PKVM_ID_GUEST, 0);

	for_each_hyp_ppage(ppage) {
		size = PAGE_SIZE << ppage->order;
		phys = hyp_pfn_to_phys(ppage->pfn);
		ipa = hyp_pfn_to_phys(ppage->gfn);

		if (pkvm_ipa_range_has_pvmfw(vm, ipa, ipa + size))
			WARN_ON(pkvm_load_pvmfw_pages(vm, ipa, phys, size));

		prot = pkvm_mkstate(KVM_PGTABLE_PROT_RWX, PKVM_PAGE_OWNED);
		WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys, prot,
					       &vcpu->vcpu.arch.stage2_mc, 0));
	}

unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;

err_rollback:
	if (ppage == hyp_ppages) {
		if (ret == -EPERM)
			ret = ___pkvm_module_share_guest_sglist(vcpu);
		goto unlock;
	}

	__host_stage2_set_owner_complete(PKVM_ID_GUEST, 0);
	while (ppage-- != hyp_ppages) {
		size = PAGE_SIZE << ppage->order;
		phys = hyp_pfn_to_phys(ppage->pfn);
		ipa = hyp_pfn_to_phys(ppage->gfn);
		WARN_ON(__host_stage2_set_owner_locked(phys, size, PKVM_ID_HOST, 0,
						       HOST_SET_NO_COMPLETE |
						       HOST_SET_PSCI_MEM_PROTECT));
	}
	__host_stage2_set_owner_complete(PKVM_ID_HOST, 0);
	goto unlock;
}

/*
 * Share host MMIO with a non-protected guest. Unlike RAM sharing, MMIO pages
 * don't have vmemmap entries, so we validate host ownership via the host
 * stage-2 page table (___host_check_page_state_range walks host stage-2 PTEs
 * for non-memory addresses via host_get_mmio_page_state).
 */
static int __pkvm_host_share_guest_mmio(u64 pfn, u64 gfn, u64 nr_pages,
					struct pkvm_hyp_vcpu *vcpu,
					enum kvm_pgtable_prot prot)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 ipa = hyp_pfn_to_phys(gfn);
	u64 size;
	int ret;

	/* MMIO prot includes DEVICE or NORMAL_NC bits beyond RWX — allow them */
	if (prot & ~(KVM_PGTABLE_PROT_RWX | KVM_PGTABLE_PROT_DEVICE |
		     KVM_PGTABLE_PROT_NORMAL_NC))
		return -EINVAL;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	ret = __guest_check_transition_size(phys, ipa, nr_pages, &size);
	if (ret)
		return ret;

	if (phys >= phys + size || ipa >= ipa + size)
		return -EINVAL;

	host_lock_component();

	/* Verify host owns this MMIO range (checks host stage-2 PTE state) */
	ret = ___host_check_page_state_range(phys, size, PKVM_PAGE_OWNED, 0);
	if (ret)
		goto unlock;

	guest_lock_component(vm);

	ret = __guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE);
	if (ret)
		goto unlock_guest;

	/* Map MMIO into guest stage-2 — no vmemmap state tracking for MMIO */
	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys,
				       pkvm_mkstate(prot, PKVM_PAGE_SHARED_BORROWED),
				       &vcpu->vcpu.arch.stage2_mc, 0));

unlock_guest:
	guest_unlock_component(vm);
unlock:
	host_unlock_component();

	return ret;
}

int __pkvm_host_share_guest(u64 pfn, u64 gfn, u64 nr_pages, struct pkvm_hyp_vcpu *vcpu,
			    enum kvm_pgtable_prot prot)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 phys = hyp_pfn_to_phys(pfn);
	u64 ipa = hyp_pfn_to_phys(gfn);
	u64 size;
	int ret;

	if (!pfn_range_is_valid(pfn, nr_pages))
		return -EINVAL;

	ret = __guest_check_transition_size(phys, ipa, nr_pages, &size);
	if (ret)
		return ret;

	if (phys >= phys + size || ipa >= ipa + size)
		return -EINVAL;

	/*
	 * If the range is entirely non-memory (MMIO), route to the MMIO
	 * share path which validates via host stage-2 instead of vmemmap.
	 * Must be checked before the prot filter below, since MMIO mappings
	 * carry KVM_PGTABLE_PROT_DEVICE or KVM_PGTABLE_PROT_NORMAL_NC.
	 */
	if (!addr_is_memory(phys) && !addr_is_memory(phys + size - 1))
		return __pkvm_host_share_guest_mmio(pfn, gfn, nr_pages, vcpu, prot);

	if (prot & ~KVM_PGTABLE_PROT_RWX)
		return -EINVAL;

	ret = check_range_allowed_memory(phys, phys + size);
	if (ret)
		return ret;

	host_lock_component();
	guest_lock_component(vm);

	ret = __guest_check_page_state_range(vm, ipa, size, PKVM_NOPAGE);
	if (ret)
		goto unlock;

	for_each_hyp_page(page, phys, size) {
		switch (get_host_state(page)) {
		case PKVM_PAGE_OWNED:
			continue;
		case PKVM_PAGE_SHARED_OWNED:
			if (page->host_share_guest_count == U32_MAX) {
				ret = -EBUSY;
				goto unlock;
			}

			/*
			 * Only host to np-guest multi-sharing is tolerated
			 *
			 * TODO(g2g): this is the in-tree statement of the
			 * multi-sharing policy. Note what it does and does not
			 * say: it restricts multi-sharing of *host-owned*
			 * pages to *non protected* guests. A guest-to-guest
			 * share is a different thing - the page is owned by a
			 * guest, the host never regains access, and the share
			 * never comes through here (GUEST_SHARE_*, in the
			 * "Guest-to-guest sharing" sections above) - so this
			 * check continues to apply unchanged to the
			 * host-to-guest path. Do not relax it in passing.
			 */
			if (page->host_share_guest_count)
				continue;

			fallthrough;
		default:
			ret = -EPERM;
			goto unlock;
		}
	}

	for_each_hyp_page(page, phys, size) {
		set_host_state(page, PKVM_PAGE_SHARED_OWNED);
		page->host_share_guest_count++;
	}

	WARN_ON(kvm_pgtable_stage2_map(&vm->pgt, ipa, size, phys,
				       pkvm_mkstate(prot, PKVM_PAGE_SHARED_BORROWED),
				       &vcpu->vcpu.arch.stage2_mc, 0));

unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

/*
 * TODO(g2g): this asserts get_host_state(page) == PKVM_PAGE_SHARED_OWNED for
 * any guest page in PKVM_PAGE_SHARED_BORROWED, i.e. it assumes every borrowed
 * page was borrowed *from the host*. A page borrowed from a peer VM carries
 * PKVM_PAGE_G2G in its guest state (and PKVM_PAGE_G2G_LENT as its host state),
 * so it is rejected here with -EPERM, which leaks into
 * __pkvm_host_unshare_guest() and the permission/aging helpers built on it.
 * Rejecting is safe, but the callers will need a way to tell "not shared by
 * the host" from "not shared at all".
 */
static int __check_host_shared_guest(struct pkvm_hyp_vm *vm, u64 *__phys, u64 ipa, u64 size)
{
	enum pkvm_page_state state;
	kvm_pte_t pte;
	u64 phys;
	s8 level;
	int ret;

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret)
		return ret;
	if (!kvm_pte_valid(pte))
		return -ENOENT;
	if (size && kvm_granule_size(level) != size)
		return -E2BIG;

	if (!size)
		size = kvm_granule_size(level);

	state = guest_get_page_state(pte, ipa) & ~PKVM_PAGE_RESTRICTED_PROT;
	if (state != PKVM_PAGE_SHARED_BORROWED)
		return -EPERM;

	phys = kvm_pte_to_phys(pte);
	if (phys >= phys + size)
		return -EINVAL;

	ret = check_range_allowed_memory(phys, phys + size);
	if (ret)
		return ret;

	for_each_hyp_page(page, phys, size) {
		if (get_host_state(page) != PKVM_PAGE_SHARED_OWNED)
			return -EPERM;
		if (WARN_ON(!page->host_share_guest_count))
			return -EINVAL;
	}

	*__phys = phys;

	return 0;
}

int __pkvm_host_unshare_guest(u64 gfn, u64 nr_pages, struct pkvm_hyp_vm *vm)
{
	u64 ipa = hyp_pfn_to_phys(gfn);
	u64 size, phys;
	int ret;

	ret = __guest_check_transition_size(0, ipa, nr_pages, &size);
	if (ret)
		return ret;

	host_lock_component();
	guest_lock_component(vm);

	ret = __check_host_shared_guest(vm, &phys, ipa, size);
	if (ret) {
		/*
		 * RAM unshare check failed. This might be an MMIO mapping
		 * created by __pkvm_host_share_guest_mmio() which doesn't
		 * use page state tracking. Look up the guest PTE to check.
		 */
		kvm_pte_t pte;
		s8 level;

		if (!kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level) &&
		    kvm_pte_valid(pte)) {
			phys = kvm_pte_to_phys(pte);
			if (!addr_is_memory(phys)) {
				ret = kvm_pgtable_stage2_unmap(&vm->pgt,
							      ipa, size);
				goto unlock;
			}
		}
		goto unlock;
	}

	ret = kvm_pgtable_stage2_unmap(&vm->pgt, ipa, size);
	if (ret)
		goto unlock;

	for_each_hyp_page(page, phys, size) {
		/* __check_host_shared_guest() protects against underflow */
		page->host_share_guest_count--;
		if (!page->host_share_guest_count)
			set_host_state(page, PKVM_PAGE_OWNED);
	}

unlock:
	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

static void assert_host_shared_guest(struct pkvm_hyp_vm *vm, u64 ipa, u64 size)
{
	u64 phys;
	int ret;

	if (!IS_ENABLED(CONFIG_PKVM_STRICT_CHECKS))
		return;

	host_lock_component();
	guest_lock_component(vm);

	ret = __check_host_shared_guest(vm, &phys, ipa, size);

	guest_unlock_component(vm);
	host_unlock_component();

	WARN_ON(ret && ret != -ENOENT);
}

int __pkvm_host_relax_perms_guest(u64 gfn, struct pkvm_hyp_vcpu *vcpu, enum kvm_pgtable_prot prot)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);
	int ret;

	if (pkvm_hyp_vm_is_protected(vm))
		return -EPERM;

	if (prot & ~KVM_PGTABLE_PROT_RWX)
		return -EINVAL;

	assert_host_shared_guest(vm, ipa, 0);
	guest_lock_component(vm);
	ret = kvm_pgtable_stage2_relax_perms(&vm->pgt, ipa, prot, 0);
	guest_unlock_component(vm);

	return ret;
}

int __pkvm_host_wrprotect_guest(u64 gfn, u64 nr_pages, struct pkvm_hyp_vm *vm)
{
	u64 size, ipa = hyp_pfn_to_phys(gfn);
	int ret;

	if (pkvm_hyp_vm_is_protected(vm))
		return -EPERM;

	ret = __guest_check_transition_size(0, ipa, nr_pages, &size);
	if (ret)
		return ret;

	assert_host_shared_guest(vm, ipa, size);
	guest_lock_component(vm);
	ret = kvm_pgtable_stage2_wrprotect(&vm->pgt, ipa, size);
	guest_unlock_component(vm);

	return ret;
}

int __pkvm_host_test_clear_young_guest(u64 gfn, u64 nr_pages, bool mkold, struct pkvm_hyp_vm *vm)
{
	u64 size, ipa = hyp_pfn_to_phys(gfn);
	int ret;

	if (pkvm_hyp_vm_is_protected(vm))
		return -EPERM;

	ret = __guest_check_transition_size(0, ipa, nr_pages, &size);
	if (ret)
		return ret;

	assert_host_shared_guest(vm, ipa, size);
	guest_lock_component(vm);
	ret = kvm_pgtable_stage2_test_clear_young(&vm->pgt, ipa, size, mkold);
	guest_unlock_component(vm);

	return ret;
}

int __pkvm_host_mkyoung_guest(u64 gfn, struct pkvm_hyp_vcpu *vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);

	if (pkvm_hyp_vm_is_protected(vm))
		return -EPERM;

	assert_host_shared_guest(vm, ipa, 0);
	guest_lock_component(vm);
	kvm_pgtable_stage2_mkyoung(&vm->pgt, ipa, 0);
	guest_unlock_component(vm);

	return 0;
}

int __pkvm_host_split_guest(u64 gfn, u64 size, struct pkvm_hyp_vcpu *vcpu)
{
	struct kvm_hyp_memcache *mc = &vcpu->vcpu.arch.stage2_mc;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	u64 ipa = hyp_pfn_to_phys(gfn);
	int ret;

	if (size != PMD_SIZE)
		return -EINVAL;

	guest_lock_component(vm);

	/*
	 * stage2_split() already checks the existing mapping is valid and PMD-level.
	 * No other check is necessary.
	 */

	ret = kvm_pgtable_stage2_split(&vm->pgt, ipa, size, mc);

	guest_unlock_component(vm);

	return ret;
}

static bool __check_ioguard_page(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	kvm_pte_t pte;
	s8 level;
	int ret;

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret)
		return false;

	/* Must be a PAGE_SIZE mapping with our annotation */
	return (BIT(ARM64_HW_PGTABLE_LEVEL_SHIFT(level)) == PAGE_SIZE &&
		pte == KVM_INVALID_PTE_MMIO_NOTE);
}

static int guest_request_ioguard_walker(const struct kvm_pgtable_visit_ctx *ctx,
					enum kvm_pgtable_walk_flags visit)
{

	struct guest_request_walker_data *data = (struct guest_request_walker_data *)ctx->arg;
	enum pkvm_page_state state;
	kvm_pte_t pte = *ctx->ptep;
	u64 granule_size;

	state = guest_get_page_state(pte, 0) & ~PKVM_MMIO;
	if (state != PKVM_NOPAGE)
		return -EPERM;

	granule_size = kvm_granule_size(ctx->level);

	/* First PTE */
	if (!data->size)
		data->ipa_start = ctx->addr & ~(granule_size - 1);

	data->size += granule_size;

	return --data->max_ptes > 0 ? 0 : -ERANGE;
}

int __pkvm_install_ioguard_page(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa,
				u64 nr_pages, u64 *nr_guarded)
{
	struct guest_request_walker_data data = GUEST_WALKER_DATA_INIT(PKVM_NOPAGE);
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	struct kvm_pgtable_walker walker = {
		.cb     = guest_request_ioguard_walker,
		.flags  = KVM_PGTABLE_WALK_LEAF,
		.arg    = (void *)&data,
	};
	u64 end;
	int ret;

	if (!test_bit(KVM_ARCH_FLAG_MMIO_GUARD, &vm->kvm.arch.flags))
		return -EINVAL;

	if (!PAGE_ALIGNED(ipa))
		return -EINVAL;

	guest_lock_component(vm);

	ret = kvm_pgtable_walk(&vm->pgt, ipa, nr_pages << PAGE_SHIFT, &walker);
	/* Walker reached data.max_ptes */
	if (ret == -ERANGE)
		ret = 0;
	else if (ret)
		goto unlock;

	/* Intersection between the requested region and what has been verified */
	end = min(ipa + (nr_pages << PAGE_SHIFT), data.ipa_start + data.size);
	if (ipa >= end) {
		ret = -EINVAL;
		goto unlock;
	}

	*nr_guarded = (end - ipa) >> PAGE_SHIFT;
	ret = kvm_pgtable_stage2_annotate(&vm->pgt, ipa, end - ipa,
					  &hyp_vcpu->vcpu.arch.stage2_mc,
					  KVM_INVALID_PTE_MMIO_NOTE);

unlock:
	guest_unlock_component(vm);
	return ret;
}

bool __pkvm_check_ioguard_page(struct pkvm_hyp_vcpu *hyp_vcpu)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 ipa, end;
	bool ret;

	if (!kvm_vcpu_dabt_isvalid(&hyp_vcpu->vcpu))
		return false;

	if (!test_bit(KVM_ARCH_FLAG_MMIO_GUARD, &vm->kvm.arch.flags))
		return true;

	ipa  = kvm_vcpu_get_fault_ipa(&hyp_vcpu->vcpu);
	ipa |= FAR_TO_FIPA_OFFSET(kvm_vcpu_get_hfar(&hyp_vcpu->vcpu));
	end = ipa + kvm_vcpu_dabt_get_as(&hyp_vcpu->vcpu) - 1;

	guest_lock_component(vm);
	ret = __check_ioguard_page(hyp_vcpu, ipa);
	if ((end & PAGE_MASK) != (ipa & PAGE_MASK))
		ret &= __check_ioguard_page(hyp_vcpu, end);
	guest_unlock_component(vm);

	return ret;
}

static int __pkvm_remove_ioguard_page(struct pkvm_hyp_vm *vm, u64 ipa)
{
	int ret;
	kvm_pte_t pte;
	s8 level;

	hyp_assert_lock_held(&vm->pgtable_lock);

	if (!test_bit(KVM_ARCH_FLAG_MMIO_GUARD, &vm->kvm.arch.flags))
		return -EINVAL;

	if (!PAGE_ALIGNED(ipa))
		return -EINVAL;

	ret = kvm_pgtable_get_leaf(&vm->pgt, ipa, &pte, &level);
	if (ret)
		return ret;

	if (BIT(ARM64_HW_PGTABLE_LEVEL_SHIFT(level)) == PAGE_SIZE &&
	    pte == KVM_INVALID_PTE_MMIO_NOTE)
		return kvm_pgtable_stage2_unmap(&vm->pgt, ipa, PAGE_SIZE);

	return kvm_pte_valid(pte) ? -EEXIST : -EINVAL;
}

int __pkvm_install_guest_mmio(struct pkvm_hyp_vcpu *hyp_vcpu, u64 pfn, u64 gfn)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	u64 ipa = gfn << PAGE_SHIFT;
	int ret;

	hyp_lock_component();
	guest_lock_component(vm);
	/*
	 * If MMIO guard is enrolled, remove the ioguard annotation first
	 * to transition the IPA from NOPAGE|MMIO to NOPAGE before donation.
	 * Without MMIO guard, the IPA is already in NOPAGE state.
	 */
	if (test_bit(KVM_ARCH_FLAG_MMIO_GUARD, &vm->kvm.arch.flags)) {
		ret = __pkvm_remove_ioguard_page(vm, ipa);
		if (ret == -EINVAL && addr_in_assign_region(hyp_pfn_to_phys(pfn)))
			ret = 0;
		if (ret)
			goto out_unlock;
	}
	ret = pkvm_hyp_donate_guest(hyp_vcpu, pfn, gfn);
out_unlock:
	guest_unlock_component(vm);
	hyp_unlock_component();
	return ret;
}

static int guest_annot_module_prot_walker(const struct kvm_pgtable_visit_ctx *ctx,
					  enum kvm_pgtable_walk_flags visit)
{
	kvm_pte_t pte = *ctx->ptep;

	if (!pte || pte == KVM_ACCEPT_MODULE_PROT_NOTE)
		return 0;

	return -EBUSY;
}

int __pkvm_accept_module_prot_page(u64 ipa, u64 nr_pages)
{
	struct pkvm_hyp_vcpu *vcpu;
	struct pkvm_hyp_vm *vm;
	struct kvm_pgtable_walker walker = {
		.cb     = guest_annot_module_prot_walker,
		.flags  = KVM_PGTABLE_WALK_LEAF,
	};
	int ret;

	if (!PAGE_ALIGNED(ipa))
		return -EINVAL;

	vcpu = pkvm_get_loaded_hyp_vcpu();
	if (!vcpu || !pkvm_hyp_vcpu_is_protected(vcpu))
		return -EINVAL;

	vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	guest_lock_component(vm);

	ret = kvm_pgtable_walk(&vm->pgt, ipa, nr_pages << PAGE_SHIFT, &walker);
	if (ret)
		goto unlock;

	ret = kvm_pgtable_stage2_annotate(&vm->pgt, ipa, nr_pages << PAGE_SHIFT,
					  &vcpu->vcpu.arch.stage2_mc,
					  KVM_ACCEPT_MODULE_PROT_NOTE);

unlock:
	guest_unlock_component(vm);
	return ret;
}

int host_stage2_get_leaf(phys_addr_t phys, kvm_pte_t *ptep, s8 *level)
{
	int ret;

	host_lock_component();
	ret = kvm_pgtable_get_leaf(&host_mmu.pgt, phys, ptep, level);
	host_unlock_component();

	return ret;
}

#ifdef CONFIG_PKVM_SELFTESTS
struct pkvm_expected_state {
	enum pkvm_page_state host;
	enum pkvm_page_state hyp;
	enum pkvm_page_state guest[2]; /* [ gfn, gfn + 1 ] */
};

static struct pkvm_expected_state selftest_state;
static struct hyp_page *selftest_page;

static struct pkvm_hyp_vm selftest_vm = {
	.kvm = {
		.arch = {
			.mmu = {
				.arch = &selftest_vm.kvm.arch,
				.pgt = &selftest_vm.pgt,
			},
		},
	},
};

static struct pkvm_hyp_vcpu selftest_vcpu = {
	.vcpu = {
		.arch = {
			.hw_mmu = &selftest_vm.kvm.arch.mmu,
		},
		.kvm = &selftest_vm.kvm,
	},
};

static void init_selftest_vm(void *virt)
{
	struct hyp_page *p = hyp_virt_to_page(virt);
	int i;

	selftest_vm.kvm.arch.mmu.vtcr = host_mmu.arch.mmu.vtcr;
	WARN_ON(kvm_guest_prepare_stage2(&selftest_vm, virt, 0));

	for (i = 0; i < pkvm_selftest_pages(); i++) {
		if (p[i].refcount)
			continue;
		hyp_set_page_refcounted(&p[i]);
		hyp_put_page(&selftest_vm.pool, hyp_page_to_virt(&p[i]));
	}
}

static u64 selftest_ipa(void)
{
	return BIT(selftest_vm.pgt.ia_bits - 1);
}

static void assert_page_state(void)
{
	void *virt = hyp_page_to_virt(selftest_page);
	u64 size = PAGE_SIZE << selftest_page->order;
	struct pkvm_hyp_vcpu *vcpu = &selftest_vcpu;
	u64 phys = hyp_virt_to_phys(virt);
	u64 ipa[2] = { selftest_ipa(), selftest_ipa() + PAGE_SIZE };
	struct pkvm_hyp_vm *vm;

	vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);

	host_lock_component();
	WARN_ON(__host_check_page_state_range(phys, size, selftest_state.host));
	host_unlock_component();

	hyp_lock_component();
	WARN_ON(__hyp_check_page_state_range(phys, size, selftest_state.hyp));
	hyp_unlock_component();

	guest_lock_component(&selftest_vm);
	WARN_ON(__guest_check_page_state_range(vm, ipa[0], size, selftest_state.guest[0]));
	WARN_ON(__guest_check_page_state_range(vm, ipa[1], size, selftest_state.guest[1]));
	guest_unlock_component(&selftest_vm);
}

#define assert_transition_res(res, fn, ...)		\
	do {						\
		WARN_ON(fn(__VA_ARGS__) != res);	\
		assert_page_state();			\
	} while (0)

/*
 * TODO(g2g): this already models two guests (selftest_state.guest[0] and
 * guest[1]) for the host-to-np-guest multi-share case. The guest-to-guest
 * transitions and teardown orderings are checked elsewhere, at every EL2 init
 * with CONFIG_PKVM_GUEST_TO_GUEST: pkvm_g2g_reclaim_selftest() and
 * pkvm_g2g_share_selftest(), the latter on two scratch VMs of its own.
 * Extending this one with the guest-to-guest cases would hold them to the same
 * ownership assertions as every other transition, under CONFIG_NVHE_EL2_DEBUG.
 */
void pkvm_ownership_selftest(void *base)
{
	enum kvm_pgtable_prot prot = KVM_PGTABLE_PROT_RWX;
	void *virt = hyp_alloc_pages(&host_s2_pool, 0);
	struct pkvm_hyp_vcpu *vcpu = &selftest_vcpu;
	struct pkvm_hyp_vm *vm = &selftest_vm;
	u64 phys, size, pfn, gfn;
	struct hyp_page old;

	WARN_ON(!virt);
	selftest_page = hyp_virt_to_page(virt);
	old = *selftest_page;
	selftest_page->refcount = 0;
	selftest_page->tag = 0;
	init_selftest_vm(base);

	size = PAGE_SIZE << selftest_page->order;
	phys = hyp_virt_to_phys(virt);
	pfn = hyp_phys_to_pfn(phys);
	gfn = hyp_phys_to_pfn(selftest_ipa());

	selftest_state.host = PKVM_NOPAGE;
	selftest_state.hyp = PKVM_PAGE_OWNED;
	selftest_state.guest[0] = selftest_state.guest[1] = PKVM_NOPAGE;
	assert_page_state();
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_ffa, pfn, 1);
	assert_transition_res(-EPERM,	hyp_pin_shared_mem, virt, virt + size);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);

	selftest_state.host = PKVM_PAGE_OWNED;
	selftest_state.hyp = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_ffa, pfn, 1);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);
	assert_transition_res(-EPERM,	hyp_pin_shared_mem, virt, virt + size);

	selftest_state.host = PKVM_PAGE_SHARED_OWNED;
	selftest_state.hyp = PKVM_PAGE_SHARED_BORROWED;
	assert_transition_res(0,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);

	assert_transition_res(0,	hyp_pin_shared_mem, virt, virt + size);
	assert_transition_res(0,	hyp_pin_shared_mem, virt, virt + size);
	hyp_unpin_shared_mem(virt, virt + size);
	WARN_ON(!hyp_page_referenced(virt));
	assert_transition_res(-EBUSY,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);

	hyp_unpin_shared_mem(virt, virt + size);
	assert_page_state();
	WARN_ON(hyp_page_referenced(virt));

	selftest_state.host = PKVM_PAGE_OWNED;
	selftest_state.hyp = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_host_unshare_hyp, pfn);

	selftest_state.host = PKVM_PAGE_SHARED_OWNED;
	selftest_state.hyp = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-ENOENT,	__pkvm_host_unshare_guest, gfn, 1, vm);
	assert_transition_res(-EPERM,	hyp_pin_shared_mem, virt, virt + size);

	selftest_state.host = PKVM_PAGE_OWNED;
	selftest_state.hyp = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_host_unshare_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_ffa, pfn, 1);

	selftest_state.host = PKVM_PAGE_SHARED_OWNED;
	selftest_state.guest[0] = PKVM_PAGE_SHARED_BORROWED;
	assert_transition_res(0,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-EPERM,	__pkvm_host_share_guest, pfn, gfn, 1, vcpu, prot);
	assert_transition_res(-EPERM,	__pkvm_host_share_ffa, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_donate_hyp, pfn, 1);
	assert_transition_res(-EPERM,	__pkvm_host_share_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_host_unshare_hyp, pfn);
	assert_transition_res(-EPERM,	__pkvm_hyp_donate_host, pfn, 1);
	assert_transition_res(-EPERM,	hyp_pin_shared_mem, virt, virt + size);

	selftest_state.guest[1] = PKVM_PAGE_SHARED_BORROWED;
	assert_transition_res(0,	__pkvm_host_share_guest, pfn, gfn + 1, 1, vcpu, prot);
	WARN_ON(hyp_virt_to_page(virt)->host_share_guest_count != 2);

	selftest_state.guest[0] = PKVM_NOPAGE;
	assert_transition_res(0,	__pkvm_host_unshare_guest, gfn, 1, vm);

	selftest_state.guest[1] = PKVM_NOPAGE;
	selftest_state.host = PKVM_PAGE_OWNED;
	assert_transition_res(0,	__pkvm_host_unshare_guest, gfn + 1, 1, vm);

	selftest_state.host = PKVM_NOPAGE;
	selftest_state.hyp = PKVM_PAGE_OWNED;
	assert_transition_res(0,	__pkvm_host_donate_hyp, pfn, 1);

	*selftest_page = old;
	hyp_put_page(&host_s2_pool, virt);
}
#endif

static u64 __pkvm_ptdump_get_host_config(enum pkvm_ptdump_ops op)
{
	u64 ret = 0;

	host_lock_component();
	if (op == PKVM_PTDUMP_GET_LEVEL)
		ret = host_mmu.pgt.start_level;
	else
		ret = host_mmu.pgt.ia_bits;
	host_unlock_component();

	return ret;
}

static u64 __pkvm_ptdump_get_guest_config(pkvm_handle_t handle, enum pkvm_ptdump_ops op)
{
	struct pkvm_hyp_vm *vm;
	u64 ret = 0;

	vm = get_pkvm_hyp_vm(handle);
	if (!vm)
		return -EINVAL;

	if (op == PKVM_PTDUMP_GET_LEVEL)
		ret = vm->pgt.start_level;
	else
		ret = vm->pgt.ia_bits;

	put_pkvm_hyp_vm(vm);
	return ret;
}

u64 __pkvm_ptdump_get_config(pkvm_handle_t handle, enum pkvm_ptdump_ops op)
{
	if (!handle)
		return __pkvm_ptdump_get_host_config(op);

	return __pkvm_ptdump_get_guest_config(handle, op);
}

static int pkvm_ptdump_walker(const struct kvm_pgtable_visit_ctx *ctx,
			      enum kvm_pgtable_walk_flags visit)
{
	struct pkvm_ptdump_log_hdr **log_hdr = ctx->arg;
	ssize_t avail_space = PAGE_SIZE - (*log_hdr)->w_index - sizeof(struct pkvm_ptdump_log_hdr);
	struct pkvm_ptdump_log *log;

	if (avail_space < sizeof(struct pkvm_ptdump_log)) {
		if ((*log_hdr)->pfn_next == INVALID_PTDUMP_PFN)
			return -ENOMEM;

		*log_hdr = hyp_phys_to_virt(hyp_pfn_to_phys((*log_hdr)->pfn_next));
		WARN_ON((*log_hdr)->w_index);
	}

	log = (struct pkvm_ptdump_log *)((void *)*log_hdr + (*log_hdr)->w_index +
					 sizeof(struct pkvm_ptdump_log_hdr));
	log->pfn = ctx->addr >> PAGE_SHIFT;
	log->valid = ctx->old & PTE_VALID;
	log->r = FIELD_GET(KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R, ctx->old);
	log->w = FIELD_GET(KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W, ctx->old);
	log->xn = FIELD_GET(KVM_PTE_LEAF_ATTR_HI_S2_XN, ctx->old);
	log->table = FIELD_GET(KVM_PTE_TYPE, ctx->old);
	log->level = ctx->level;
	log->page_state = FIELD_GET(PKVM_PAGE_STATE_PROT_MASK, ctx->old);
	log->mmio_guard = FIELD_GET(KVM_INVALID_PTE_MMIO_NOTE, ctx->old);

	(*log_hdr)->w_index += sizeof(struct pkvm_ptdump_log);
	return 0;
}

static void pkvm_ptdump_teardown_log(struct pkvm_ptdump_log_hdr *log_hva,
				     struct pkvm_ptdump_log_hdr *cur)
{
	struct pkvm_ptdump_log_hdr *tmp, *log = (void *)kern_hyp_va(log_hva);
	bool next_log_invalid = false;

	while (log != cur && !next_log_invalid) {
		next_log_invalid = log->pfn_next == INVALID_PTDUMP_PFN;
		tmp = hyp_phys_to_virt(hyp_pfn_to_phys(log->pfn_next));
		WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(log), 1));
		log = tmp;
	}
}

static int pkvm_ptdump_setup_log(struct pkvm_ptdump_log_hdr *log_hva)
{
	int ret;
	struct pkvm_ptdump_log_hdr *log = (void *)kern_hyp_va(log_hva);

	if (!PAGE_ALIGNED(log))
		return -EINVAL;

	for (;;) {
		ret = __pkvm_host_donate_hyp(hyp_virt_to_pfn(log), 1);
		if (ret) {
			pkvm_ptdump_teardown_log(log_hva, log);
			return ret;
		}

		log->w_index = 0;
		if (log->pfn_next == INVALID_PTDUMP_PFN)
			break;

		log = hyp_phys_to_virt(hyp_pfn_to_phys(log->pfn_next));
	}

	return 0;
}

static int pkvm_ptdump_walk_host(struct kvm_pgtable_walker *walker)
{
	int ret;

	host_lock_component();
	ret = kvm_pgtable_walk(&host_mmu.pgt, 0, BIT(host_mmu.pgt.ia_bits), walker);
	host_unlock_component();

	return ret;
}

static int pkvm_ptdump_walk_guest(struct pkvm_hyp_vm *vm, struct kvm_pgtable_walker *walker)
{
	int ret;

	guest_lock_component(vm);

	ret = kvm_pgtable_walk(&vm->pgt, 0, BIT(vm->pgt.ia_bits), walker);

	guest_unlock_component(vm);

	return ret;
}

u64 __pkvm_ptdump_walk_range(pkvm_handle_t handle, struct pkvm_ptdump_log_hdr *log)
{
	struct pkvm_hyp_vm *vm;
	int ret;
	struct pkvm_ptdump_log_hdr *log_hyp = kern_hyp_va(log);
	struct kvm_pgtable_walker walker = {
		.cb     = pkvm_ptdump_walker,
		.flags  = KVM_PGTABLE_WALK_LEAF,
		.arg    = &log_hyp,
	};

	ret = pkvm_ptdump_setup_log(log);
	if (ret)
		return ret;

	if (!handle)
		ret = pkvm_ptdump_walk_host(&walker);
	else {
		vm = get_pkvm_hyp_vm(handle);
		if (!vm) {
			ret = -EINVAL;
			goto teardown;
		}

		ret = pkvm_ptdump_walk_guest(vm, &walker);
		put_pkvm_hyp_vm(vm);
	}
teardown:
	pkvm_ptdump_teardown_log(log, NULL);
	return ret;
}

static void __pkvm_use_dma_page(phys_addr_t phys)
{
	struct hyp_page *p = hyp_phys_to_page(phys);

	hyp_page_ref_inc(p);
}

static void __pkvm_unuse_dma_page(phys_addr_t phys)
{
	struct hyp_page *p = hyp_phys_to_page(phys);

	hyp_page_ref_dec(p);
}

static int __pkvm_use_dma_locked(phys_addr_t phys, size_t size, struct pkvm_hyp_vm *vm)
{
	int i;
	int ret = 0;
	struct kvm_mem_range r;
	size_t nr_pages = size >> PAGE_SHIFT;
	struct memblock_region *reg = find_mem_range(phys, &r);

	if (!pfn_range_is_valid(hyp_phys_to_pfn(phys), nr_pages) ||
	    !is_in_mem_range(phys + size - 1, &r))
		return -EINVAL;
	/*
	 * Some differences between handling of RAM and device memory:
	 * - The hyp vmemmap area for device memory is not backed by physical
	 *   pages in the hyp page tables.
	 * - However, in some cases modules can donate MMIO, as they can't be
	 *   refcounted, taint them by marking them as shared borrowed, and that
	 *   will prevent any future transition.
	 */
	if (!reg) {
		enum kvm_pgtable_prot prot;

		if (vm) {
			/*
			 * VMs generally cannot create IOMMU mappings to MMIO.
			 * Exception: the pviommu substitutes the guest's virtual
			 * ITS address with the physical ITS doorbell for MSI
			 * delivery. Verify the address matches.
			 */
			if (!vm->its_doorbell_phys_addr ||
			    phys != vm->its_doorbell_phys_addr ||
			    size != PAGE_SIZE)
				return -EINVAL;
		}
		for (i = 0; i < nr_pages; i++) {
			u64 addr = phys + i * PAGE_SIZE;

			ret = ___host_check_page_state_range(addr, PAGE_SIZE,
							     PKVM_PAGE_SHARED_BORROWED, 0);
			/* Page already borrowed */
			if (!ret)
				continue;
			ret = ___host_check_page_state_range(addr, PAGE_SIZE,
							     PKVM_PAGE_OWNED, 0);
			if (ret)
				return ret;
		}
		prot = pkvm_mkstate(PKVM_HOST_MMIO_PROT, PKVM_PAGE_SHARED_BORROWED);
		WARN_ON(host_stage2_idmap_locked(phys, size, prot, false));
	} else {

		/* For VMs, we know if we reach this point the VM has access to the page. */
		if (!vm) {
			for_each_hyp_page(page, phys, size) {
				if (get_host_state(page) != PKVM_PAGE_OWNED)
					return -EPERM;
			}
		}

		for (i = 0; i < nr_pages; i++)
			__pkvm_use_dma_page(phys + i * PAGE_SIZE);
	}

	return ret;
}

/*
 * __pkvm_use_dma - Mark memory as used for DMA
 * @phys:	physical address of the DMA region
 * @size:	size of the DMA region
 * When a page is mapped in an IOMMU page table for DMA, it must
 * not be donated to a guest or the hypervisor we ensure this with:
 * - Host can only map pages that are OWNED
 * - Any page that is mapped is refcounted
 * - Donation/Sharing is prevented if a page is refcounted.
 * - Any MMIO ever mapped in the IOMMU can't be donated/shared.
 * In case in the future shared pages are allowed to be mapped,
 * similar checks are needed in host_request_unshare() and
 * host_ack_unshare()
 */
/*
 * TODO(g2g): the comment above is the existing authors flagging this exact
 * interaction - "In case in the future shared pages are allowed to be mapped,
 * similar checks are needed". A guest-to-guest shared page is a new case: two
 * VMs can reach it, and one of them may want to DMA to it. Today it cannot:
 * an OFFER refuses a page in DMA use (its hyp_page refcount), and both DMA
 * paths require PKVM_PAGE_OWNED - the host's state here, the owner's in
 * pkvm_get_guest_pa_request() - which a shared page is not. Decide whether
 * that is the answer, and make it one on purpose rather than a side effect of
 * the state checks.
 */
int __pkvm_use_dma(phys_addr_t phys, size_t size, struct pkvm_hyp_vm *vm)
{
	int ret;

	host_lock_component();
	ret = __pkvm_use_dma_locked(phys, size, vm);
	host_unlock_component();
	return ret;
}

/*
 * Must be called after a __pkvm_host_use_dma() for the same
 * range, typically after a page was unmapped from an IOMMU.
 */
int __pkvm_unuse_dma(phys_addr_t phys, size_t size, struct pkvm_hyp_vm *vm)
{
	int i;
	size_t nr_pages = size >> PAGE_SHIFT;

	if (!pfn_range_is_valid(hyp_phys_to_pfn(phys), nr_pages))
		return -EINVAL;

	if (!range_is_memory(phys, phys + size)) {
		if (vm) {
			/* Allow ITS doorbell MMIO unuse for VMs */
			WARN_ON(!vm->its_doorbell_phys_addr ||
				phys != vm->its_doorbell_phys_addr ||
				size != PAGE_SIZE);
		}
		return 0;
	}
	host_lock_component();

	for (i = 0; i < nr_pages; i++)
		__pkvm_unuse_dma_page(phys + i * PAGE_SIZE);

	host_unlock_component();
	return 0;
}

/*
 * Get a PA of an IPA and pin the memory starting from this PA till
 *  the requested ipa_size or the end of the page boundary returned in level.
 */
int pkvm_get_guest_pa_request_use_dma(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa,
                                     size_t ipa_size, u64 *out_pa, s8 *level)
{
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	size_t off;
	int ret;

	host_lock_component();
	ret = pkvm_get_guest_pa_request(hyp_vcpu, ipa, ipa_size,
					out_pa, level);
	if (ret)
		goto out_ret;
	off = *out_pa - ALIGN_DOWN(*out_pa, kvm_granule_size(*level));
	WARN_ON(__pkvm_use_dma_locked(*out_pa,
				      min(kvm_granule_size(*level) - off, ipa_size), vm));
out_ret:
	host_unlock_component();
	return ret;
}
