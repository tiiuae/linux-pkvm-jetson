/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#ifndef __KVM_NVHE_MEM_PROTECT__
#define __KVM_NVHE_MEM_PROTECT__
#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm_module.h>
#include <asm/virt.h>
#include <nvhe/memory.h>
#include <nvhe/pkvm.h>
#include <nvhe/spinlock.h>

struct host_mmu {
	struct kvm_arch arch;
	struct kvm_pgtable pgt;
	struct kvm_pgtable_mm_ops mm_ops;
	hyp_spinlock_t lock;
};
extern struct host_mmu host_mmu;

/*
 * This corresponds to page-table locking order.
 *
 * TODO(g2g): this is a total order over component *classes*, and every
 * transition locks at most one guest - the guest-to-guest share transitions
 * included, which take one guest's pgtable lock at a time under host_mmu.lock.
 * A transition that ever needs two guests' pgtable locks at once, which sit at
 * the same level, needs an intra-GUEST ordering rule first, documented here and
 * defended: ordering by pkvm_handle_t or by struct address are both plausible.
 * Get it wrong and two CPUs locking in opposite orders deadlock at EL2, which
 * is an unrecoverable hang of the machine, not a recoverable fault.
 *
 * See also the TODO(g2g) on guest_lock_component() in mem_protect.c: the lock
 * order is not the only obstacle to holding two guest locks at once.
 */
enum pkvm_component_id {
	PKVM_ID_HOST,
	PKVM_ID_HYP,
	PKVM_ID_FFA,
	PKVM_ID_GUEST,
	PKVM_ID_PROTECTED,
	PKVM_ID_MAX = PKVM_ID_PROTECTED,
};

extern unsigned long hyp_nr_cpus;

extern struct kvm_hyp_pinned_page *hyp_ppages;

extern struct hyp_mgt_allocator_ops host_s2_pool_ops;

int __pkvm_prot_finalize(void);
void __pkvm_late_cpus_finalize(void);
int __pkvm_host_share_hyp(u64 pfn);
int __pkvm_host_unshare_hyp(u64 pfn);
int __pkvm_host_donate_hyp(u64 pfn, u64 nr_pages);
int ___pkvm_host_donate_hyp(u64 pfn, u64 nr_pages, bool accept_mmio);
int ___pkvm_host_donate_hyp_prot(u64 pfn, u64 nr_pages,
				 bool accept_mmio, enum kvm_pgtable_prot prot);
int __pkvm_host_donate_sglist_hyp(struct pkvm_sglist_page *sglist, size_t nr_pages);
int __pkvm_hyp_donate_host(u64 pfn, u64 nr_pages);
int __pkvm_hyp_reclaim_host_mmio(u64 pfn, u64 nr_pages);
int __pkvm_guest_share_hyp_page(struct pkvm_hyp_vcpu *vcpu, u64 ipa, u64 *hyp_va);
int __pkvm_guest_unshare_hyp_page(struct pkvm_hyp_vm *vm, u64 ipa);
int __pkvm_guest_share_ffa_page(struct pkvm_hyp_vcpu *vcpu, u64 ipa, phys_addr_t *phys);
int __pkvm_guest_unshare_ffa_page(struct pkvm_hyp_vm *vm, u64 ipa);
#ifdef CONFIG_PKVM_GUEST_TO_GUEST
/*
 * Exhaustive check of the guest-to-guest reclaim decision matrix. Run once from
 * __pkvm_init_finalise(); see the comment at the definition for what it proves
 * and why it exists at all. Returns true if it passed: guest-to-guest stays
 * disabled unless it did (see pkvm_g2g_enabled).
 */
bool pkvm_g2g_reclaim_selftest(void);

/*
 * Guest-to-guest page sharing: GUEST_SHARE_OFFER, _ACCEPT, _REVOKE, _RELEASE.
 * The contract is at ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_OFFER_FUNC_ID; the
 * design is in the three "Guest-to-guest sharing" sections of mem_protect.c.
 *
 * The handlers in pkvm.c find out what needs vm_table - who holds the named
 * identity, whether the caller has one, whether it is enrolled in MMIO guard -
 * and pass it in as the facts below, with vm_table_lock held for read across
 * the call. Everything else is found out in mem_protect.c.
 */
#define PKVM_G2G_SHARE_PEER_ID_ZERO	BIT(0)	/* the named identity is (0, 0) */
#define PKVM_G2G_SHARE_PEER_INC_ZERO	BIT(1)	/* the named incarnation is 0 */
#define PKVM_G2G_SHARE_TO_SELF		BIT(2)	/* the caller named itself */
#define PKVM_G2G_SHARE_UNREGISTERED	BIT(3)	/* the caller has no identity */
#define PKVM_G2G_SHARE_PEER_FOUND	BIT(4)	/* a VM holds the named identity... */
#define PKVM_G2G_SHARE_PEER_DYING	BIT(5)	/* ...and it is being torn down */
#define PKVM_G2G_SHARE_PEER_UNPROTECTED	BIT(6)	/* ...and it is not protected */
#define PKVM_G2G_SHARE_PEER_STALE	BIT(7)	/* ...at another incarnation */
#define PKVM_G2G_SHARE_NO_MMIO_GUARD	BIT(8)	/* ACCEPT: caller not enrolled */

enum pkvm_g2g_share_verdict {
	PKVM_G2G_SHARE_DO,		/* carried out */
	PKVM_G2G_SHARE_INVALID,
	PKVM_G2G_SHARE_NO_IDENTITY,
	PKVM_G2G_SHARE_NO_PEER,
	PKVM_G2G_SHARE_NO_SHARE,
	PKVM_G2G_SHARE_DENIED,
	PKVM_G2G_SHARE_LIMIT,
	/* Not answers: the handler asks the host and re-executes the HVC. */
	PKVM_G2G_SHARE_NEED_MAP,	/* map the owner's range in */
	PKVM_G2G_SHARE_NEED_SPLIT,	/* split a block at an end of it */
	PKVM_G2G_SHARE_NEED_MEMCACHE,	/* top up the vCPU memcache */
	PKVM_G2G_SHARE_NR_VERDICTS,
};

unsigned long pkvm_g2g_share_verdict_to_smccc(enum pkvm_g2g_share_verdict v);
void pkvm_g2g_share_verdict_selftest(void);

enum pkvm_g2g_share_verdict
pkvm_g2g_share_offer(struct pkvm_hyp_vcpu *vcpu, u32 peer_facts, u64 ipa,
		     u64 nr_pages, u64 flags, const struct pkvm_g2g_identity *to,
		     u64 *handle);
enum pkvm_g2g_share_verdict
pkvm_g2g_share_accept(struct pkvm_hyp_vcpu *vcpu, struct pkvm_hyp_vm *owner,
		      u32 peer_facts, u64 ipa, u64 nr_pages, u64 handle,
		      u64 flags, u64 *share_flags);
enum pkvm_g2g_share_verdict
pkvm_g2g_share_revoke(struct pkvm_hyp_vcpu *vcpu, u64 handle, u64 flags);
enum pkvm_g2g_share_verdict
pkvm_g2g_share_release(struct pkvm_hyp_vcpu *vcpu, u64 handle, u64 flags);
/* Called from __pkvm_start_teardown_vm(), vm_table write lock held. */
void pkvm_g2g_share_vm_dying(struct pkvm_hyp_vm *vm);
/*
 * Decisions, then transitions on two scratch VMs; run once from
 * __pkvm_init_finalise(). Returns true if it passed: guest-to-guest stays
 * disabled unless it did (see pkvm_g2g_enabled).
 */
bool pkvm_g2g_share_selftest(void *scratch, unsigned long nr_pages);
#endif
int __pkvm_host_share_ffa(u64 pfn, u64 nr_pages);
int __pkvm_host_unshare_ffa(u64 pfn, u64 nr_pages);
int __pkvm_host_donate_guest(u64 pfn, u64 gfn, u64 nr_pages, struct pkvm_hyp_vcpu *vcpu);
int __pkvm_host_donate_sglist_guest(struct pkvm_hyp_vcpu *vcpu);
int __pkvm_host_reclaim_page_guest(u64 gfn, u64 nr_pages, struct pkvm_hyp_vm *vm);
int __pkvm_guest_share_host(u64 gfn, struct pkvm_hyp_vcpu *vcpu, u64 nr_pages, u64 *nr_shared);
int __pkvm_guest_unshare_host(u64 gfn, struct pkvm_hyp_vcpu *vcpu, u64 nr_pages, u64 *nr_shared);
int __pkvm_host_share_guest(u64 pfn, u64 gfn, u64 nr_pages, struct pkvm_hyp_vcpu *vcpu,
			    enum kvm_pgtable_prot prot);
int __pkvm_host_unshare_guest(u64 gfn, u64 nr_pages, struct pkvm_hyp_vm *hyp_vm);
int __pkvm_host_relax_perms_guest(u64 gfn, struct pkvm_hyp_vcpu *vcpu, enum kvm_pgtable_prot prot);
int __pkvm_host_wrprotect_guest(u64 gfn, u64 nr_pages, struct pkvm_hyp_vm *hyp_vm);
int __pkvm_host_test_clear_young_guest(u64 gfn, u64 nr_pages, bool mkold, struct pkvm_hyp_vm *vm);
int __pkvm_host_mkyoung_guest(u64 gfn, struct pkvm_hyp_vcpu *vcpu);
int __pkvm_host_split_guest(u64 gfn, u64 size, struct pkvm_hyp_vcpu *vcpu);
int __pkvm_host_donate_ffa(u64 pfn, u64 nr_pages);
int __pkvm_host_reclaim_ffa(u64 pfn, u64 nr_pages);
int __pkvm_install_ioguard_page(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa,
				u64 nr_pages, u64 *nr_guarded);
bool __pkvm_check_ioguard_page(struct pkvm_hyp_vcpu *hyp_vcpu);
int __pkvm_guest_relinquish_to_host(struct pkvm_hyp_vcpu *vcpu,
				    u64 ipa, u64 flags, u64 *ppa);
u64 __pkvm_ptdump_get_config(pkvm_handle_t handle, enum pkvm_ptdump_ops op);
u64 __pkvm_ptdump_walk_range(pkvm_handle_t handle, struct pkvm_ptdump_log_hdr *log_hva);

int hyp_check_range_owned(u64 addr, u64 size);
int __pkvm_install_guest_mmio(struct pkvm_hyp_vcpu *hyp_vcpu, u64 pfn, u64 gfn);

int pkvm_get_guest_pa_request(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa,
			      size_t ipa_size_request, u64 *out_pa, s8 *out_level);
int pkvm_get_guest_pa_request_use_dma(struct pkvm_hyp_vcpu *hyp_vcpu, u64 ipa,
				      size_t ipa_size_request, u64 *out_pa, s8 *level);
void make_host_stage2_reclaimable(void);

bool addr_is_memory(phys_addr_t phys);
bool addr_is_hyp_text(phys_addr_t phys);
int host_stage2_idmap_locked(phys_addr_t addr, u64 size, enum kvm_pgtable_prot prot,
			     bool is_memory);
int host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id);
bool host_stage2_pte_is_hyp_owned(kvm_pte_t pte);
int host_stage2_unmap_reg_locked(phys_addr_t start, u64 size);
int kvm_host_prepare_stage2(void *pgt_pool_base, void *mmio_pool_base);
int kvm_guest_prepare_stage2(struct pkvm_hyp_vm *vm, void *pgd,
			     enum kvm_pgtable_stage2_flags flags);
void handle_host_mem_abort(struct kvm_cpu_context *host_ctxt);

int hyp_pin_shared_mem(void *from, void *to);
void hyp_unpin_shared_mem(void *from, void *to);
int host_stage2_get_leaf(phys_addr_t phys, kvm_pte_t *ptep, s8 *level);

int refill_hyp_pool(struct hyp_pool *pool, struct kvm_hyp_memcache *host_mc);
int reclaim_hyp_pool(struct hyp_pool *pool, struct kvm_hyp_memcache *host_mc,
		     int nr_pages, bool force);

void destroy_hyp_vm_pgt(struct pkvm_hyp_vm *vm);
void drain_hyp_pool(struct hyp_pool *pool, struct kvm_hyp_memcache *mc);
int refill_memcache(struct kvm_hyp_memcache *mc, unsigned long min_pages,
		    struct kvm_hyp_memcache *host_mc);

int module_change_host_page_prot(u64 pfn, enum kvm_pgtable_prot prot,
				 u64 nr_pages, bool update_iommu);
int module_set_host_page_owned(u64 pfn, u64 nr_pages, bool owned);

void psci_mem_protect_inc(u64 n);
void psci_mem_protect_dec(u64 n);

int __pkvm_use_dma(u64 phys_addr, size_t size, struct pkvm_hyp_vm *vm);
int __pkvm_unuse_dma(u64 phys_addr, size_t size, struct pkvm_hyp_vm *vm);

static __always_inline void __load_host_stage2(void)
{
	if (static_branch_likely(&kvm_protected_mode_initialized))
		__load_stage2(&host_mmu.arch.mmu, &host_mmu.arch);
	else
		write_sysreg(0, vttbr_el2);
}

int __pkvm_host_use_dma(phys_addr_t phys_addr, size_t size);
int __pkvm_host_unuse_dma(phys_addr_t phys_addr, size_t size);

int __pkvm_accept_module_prot_page(u64 ipa, u64 nr_pages);

#ifdef CONFIG_PKVM_SELFTESTS
void pkvm_ownership_selftest(void *base);
#else
static inline void pkvm_ownership_selftest(void *base) { }
#endif
#endif /* __KVM_NVHE_MEM_PROTECT__ */
