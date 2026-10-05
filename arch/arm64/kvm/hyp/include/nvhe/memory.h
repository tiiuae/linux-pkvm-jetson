/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_HYP_MEMORY_H
#define __KVM_HYP_MEMORY_H

#include <asm/kvm_mmu.h>
#include <asm/page.h>

#include <linux/build_bug.h>
#include <linux/types.h>
#include <nvhe/refcount.h>

/*
 * Bits 0-1 are used to encode the memory ownership state of each page from the
 * point of view of a pKVM "component" (host, hyp, guest, ... see enum
 * pkvm_component_id):
 *   00: The page is owned and exclusively accessible by the component;
 *   01: The page is owned and accessible by the component, but is also
 *       accessible by another component;
 *   10: The page is accessible but not owned by the component;
 * The storage of this state depends on the component: either in the
 * hyp_vmemmap for the host and hyp states or in PTE software bits for guests.
 */
enum pkvm_page_state {
	PKVM_PAGE_OWNED			= 0ULL,
	PKVM_PAGE_SHARED_OWNED		= BIT(0),
	PKVM_PAGE_SHARED_BORROWED	= BIT(1),

	/*
	 * 'Meta-states' are not stored directly in PTE SW bits for guest
	 * states, but inferred from the context (e.g. invalid PTE entries).
	 * For the host and hyp, meta-states are stored directly in the
	 * struct hyp_page.
	 */
	PKVM_NOPAGE			= BIT(0) | BIT(1),
	PKVM_MODULE_OWNED_PAGE		= BIT(2),
	PKVM_MODULE_SHARED_OWNED_PAGE	= BIT(3),

	/*
	 * Meta-states which aren't encoded directly in the PTE's SW bits (or
	 * the hyp_vmemmap entry for the host)
	 */
	PKVM_PAGE_RESTRICTED_PROT	= BIT(4),
	PKVM_MMIO			= BIT(5),
	PKVM_ACCEPT_MODULE_OWNED	= BIT(6),

	/*
	 * Guest-to-guest sharing. See
	 * Documentation/virt/kvm/arm/pkvm-guest-to-guest.rst.
	 *
	 * PKVM_PAGE_G2G qualifies the two SHARED states with *who the
	 * counterparty is*. Without it, PKVM_PAGE_SHARED_OWNED in a guest PTE
	 * means only "shared", not "shared with whom", and that ambiguity is
	 * precisely what makes __pkvm_host_reclaim_page_guest() hand a peer's
	 * live page to the host.
	 *
	 *   PKVM_PAGE_SHARED_OWNED    | PKVM_PAGE_G2G
	 *	this guest owns the page and has lent it to a peer VM, not to
	 *	the host.
	 *   PKVM_PAGE_SHARED_BORROWED | PKVM_PAGE_G2G
	 *	this guest borrows the page from a peer VM, not from the host.
	 *
	 * Like PKVM_MMIO it is a meta-state: it is never stored in
	 * hyp_page.__host_state (BIT(7) does not fit that 4-bit field) and it is
	 * not part of PKVM_PAGE_STATE_PROT_MASK. In a guest stage-2 PTE it is
	 * stored in KVM_PGTABLE_PROT_SW2 - see PKVM_PAGE_G2G_PROT_MASK below.
	 * SW2 and SW3 are unused by this tree (the only references to either are
	 * their own definitions in asm/kvm_pgtable.h), so this costs no memory
	 * anywhere: it is per-page state kept in the page table that already
	 * holds per-page guest state.
	 */
	PKVM_PAGE_G2G			= BIT(7),

	/*
	 * Host-side states for a page in a guest-to-guest relationship. Unlike
	 * PKVM_PAGE_G2G these ARE stored in hyp_page.__host_state, which is why
	 * their values are constrained:
	 *
	 *  - __host_state is 4 bits, so the value must be <= 15;
	 *  - BIT(2) must stay clear, because get_host_state() is tested
	 *    *bitwise* against PKVM_MODULE_OWNED_PAGE in __pkvm_use_dma()'s
	 *    neighbourhood in mem_protect.c;
	 *  - 0..3 are the four pkvm_page_state values, 4 is
	 *    PKVM_MODULE_OWNED_PAGE, 7 is PKVM_NOPAGE | PKVM_MODULE_OWNED_PAGE
	 *    and 8 is PKVM_MODULE_SHARED_OWNED_PAGE, so a new value must be
	 *    none of those.
	 *
	 * 9 and 10 are free: every __host_state test in the tree compares the
	 * whole value, except the bit test against PKVM_MODULE_OWNED_PAGE,
	 * which neither value sets. The static_asserts below check this.
	 *
	 * This is the answer to "where does the guest-to-guest borrow count
	 * live, given that struct hyp_page is exactly 8 bytes and full?". It
	 * does not need to live there. With at most one peer borrower per page
	 * (see the documentation) no count is needed at all: the last-holder
	 * question is answered by these two values plus PKVM_PAGE_G2G in the
	 * guest PTE. struct hyp_page is unchanged, and the hyp_vmemmap - one
	 * entry per physical page of RAM - does not grow.
	 *
	 * In both states the host has no access and the host stage-2 annotation
	 * still reads PKVM_ID_GUEST, because a guest still holds the page. They
	 * are deliberately NOT equal to PKVM_NOPAGE, so every existing
	 * __host_check_page_state_range(..., PKVM_NOPAGE) refuses a page in a
	 * guest-to-guest relationship rather than silently accepting it.
	 */
	PKVM_PAGE_G2G_LENT		= BIT(3) | BIT(0),	/* 9 */
	PKVM_PAGE_G2G_ORPHANED		= BIT(3) | BIT(1),	/* 10 */
};
#define PKVM_PAGE_STATE_MASK		(BIT(0) | BIT(1))

static_assert(PKVM_PAGE_G2G_LENT <= 0xf && PKVM_PAGE_G2G_ORPHANED <= 0xf,
	      "host-side g2g states must fit hyp_page.__host_state (4 bits)");
static_assert(!(PKVM_PAGE_G2G_LENT & PKVM_MODULE_OWNED_PAGE) &&
	      !(PKVM_PAGE_G2G_ORPHANED & PKVM_MODULE_OWNED_PAGE),
	      "host-side g2g states must not alias the PKVM_MODULE_OWNED_PAGE bit test");
static_assert(PKVM_PAGE_G2G_LENT != PKVM_NOPAGE &&
	      PKVM_PAGE_G2G_ORPHANED != PKVM_NOPAGE &&
	      PKVM_PAGE_G2G_LENT != PKVM_PAGE_G2G_ORPHANED,
	      "host-side g2g states must be distinct from PKVM_NOPAGE and each other");
static_assert(!(PKVM_PAGE_G2G & 0xf),
	      "PKVM_PAGE_G2G is a meta-state and must not fit __host_state");
static_assert(PKVM_PAGE_G2G_LENT != PKVM_MODULE_SHARED_OWNED_PAGE &&
	      PKVM_PAGE_G2G_ORPHANED != PKVM_MODULE_SHARED_OWNED_PAGE &&
	      PKVM_PAGE_G2G_LENT != (PKVM_NOPAGE | PKVM_MODULE_OWNED_PAGE) &&
	      PKVM_PAGE_G2G_ORPHANED != (PKVM_NOPAGE | PKVM_MODULE_OWNED_PAGE),
	      "host-side g2g states must not alias the module page states");
static_assert(!(PKVM_PAGE_G2G & (PKVM_PAGE_RESTRICTED_PROT | PKVM_MMIO |
				 PKVM_ACCEPT_MODULE_OWNED)),
	      "PKVM_PAGE_G2G must not alias another meta-state");

#define PKVM_PAGE_STATE_PROT_MASK	(KVM_PGTABLE_PROT_SW0 | KVM_PGTABLE_PROT_SW1)

/*
 * Software bit in a guest stage-2 PTE carrying PKVM_PAGE_G2G. Deliberately
 * outside PKVM_PAGE_STATE_PROT_MASK so that pkvm_mkstate()/pkvm_getstate()
 * neither clobber nor report it: the ownership state and the identity of the
 * counterparty are independent facts.
 */
#define PKVM_PAGE_G2G_PROT_MASK		KVM_PGTABLE_PROT_SW2

static inline bool pkvm_prot_is_g2g(enum kvm_pgtable_prot prot)
{
	return !!(prot & PKVM_PAGE_G2G_PROT_MASK);
}

/*
 * True for the two values of hyp_page.__host_state that mean "a peer VM holds
 * this page".
 *
 * Constant false without CONFIG_PKVM_GUEST_TO_GUEST, so that the call sites
 * outside the guest-to-guest code need no #ifdef and fold away entirely in the
 * default build. Nothing can set either state in that build, so the two are
 * equivalent; the branch keeps pkvm.nvhe.o and mem_protect.nvhe.o bit-for-bit
 * identical to their predecessors with the option off, and a runtime test here
 * would spend that.
 */
static inline bool pkvm_host_state_is_g2g(enum pkvm_page_state state)
{
#ifdef CONFIG_PKVM_GUEST_TO_GUEST
	return state == PKVM_PAGE_G2G_LENT || state == PKVM_PAGE_G2G_ORPHANED;
#else
	return false;
#endif
}

static inline enum kvm_pgtable_prot pkvm_mkstate(enum kvm_pgtable_prot prot,
						 enum pkvm_page_state state)
{
	prot &= ~PKVM_PAGE_STATE_PROT_MASK;
	prot |= FIELD_PREP(PKVM_PAGE_STATE_PROT_MASK, state);
	return prot;
}

static inline enum pkvm_page_state pkvm_getstate(enum kvm_pgtable_prot prot)
{
	return FIELD_GET(PKVM_PAGE_STATE_PROT_MASK, prot);
}

struct hyp_page {
	u16 refcount;
	u8 order;

	/* Host state. Guarded by the host stage-2 lock. */
	unsigned __host_state : 4;

	/*
	 * Complement of the hyp state. Guarded by the hyp stage-1 lock. We use
	 * the complement so that the initial 0 in __hyp_state_comp (due to the
	 * entire vmemmap starting off zeroed) encodes PKVM_NOPAGE.
	 */
	unsigned __hyp_state_comp : 4;

	union {
		u32 host_share_guest_count;

		/* When the page is hyp owned, a tag may be added */
		u32 tag;
	};

	/*
	 * RESOLVED(g2g): this struct is NOT grown for guest-to-guest sharing,
	 * and host_share_guest_count is NOT split.
	 *
	 * This struct is exactly one u64 (2 + 1 + 4 bits + 4 bits + 4 = 8), and
	 * is asserted so in hyp_phys_to_page(); growing it would double the
	 * hyp_vmemmap, which carries one entry per physical page of RAM.
	 * Guest-to-guest sharing adds nothing to it. A borrow *count* would be
	 * required only if a page could have more than one peer borrower;
	 * constraining a guest-to-guest share to a single borrower (see
	 * Documentation/virt/kvm/arm/pkvm-guest-to-guest.rst) reduces the
	 * last-holder question to a state, and two states fit in the spare
	 * encodings of the existing 4-bit __host_state field:
	 * PKVM_PAGE_G2G_LENT and PKVM_PAGE_G2G_ORPHANED above. The matching
	 * per-guest fact - whether a share's counterparty is a peer VM or the
	 * host - fits in PKVM_PAGE_G2G, an unused software bit of the guest's
	 * own stage-2 PTE.
	 *
	 * If multiple borrowers are ever wanted, a small count still fits those
	 * same spare __host_state encodings (BIT(3) | 0..3 gives four, of which
	 * two are used) without touching this struct.
	 */
};

extern u64 __hyp_vmemmap;
#define hyp_vmemmap ((struct hyp_page *)__hyp_vmemmap)

#define hyp_phys_to_pfn(phys)	((phys) >> PAGE_SHIFT)
#define hyp_pfn_to_phys(pfn)	((phys_addr_t)((pfn) << PAGE_SHIFT))

static inline struct hyp_page *hyp_phys_to_page(phys_addr_t phys)
{
	BUILD_BUG_ON(sizeof(struct hyp_page) != sizeof(u64));
	return &hyp_vmemmap[hyp_phys_to_pfn(phys)];
}

#define hyp_virt_to_page(virt)	hyp_phys_to_page(__hyp_pa(virt))
#define hyp_virt_to_pfn(virt)	hyp_phys_to_pfn(__hyp_pa(virt))

#define hyp_page_to_pfn(page)	((struct hyp_page *)(page) - hyp_vmemmap)
#define hyp_page_to_phys(page)  hyp_pfn_to_phys((hyp_page_to_pfn(page)))
#define hyp_page_to_virt(page)	__hyp_va(hyp_page_to_phys(page))
#define hyp_page_to_pool(page)	(((struct hyp_page *)page)->pool)

static inline enum pkvm_page_state get_host_state(struct hyp_page *p)
{
	return p->__host_state;
}

static inline void set_host_state(struct hyp_page *p, enum pkvm_page_state state)
{
	p->__host_state = state;
}

static inline enum pkvm_page_state get_hyp_state(struct hyp_page *p)
{
	return p->__hyp_state_comp ^ PKVM_PAGE_STATE_MASK;
}

static inline void set_hyp_state(struct hyp_page *p, enum pkvm_page_state state)
{
	p->__hyp_state_comp = state ^ PKVM_PAGE_STATE_MASK;
}

/*
 * Refcounting wrappers for 'struct hyp_page'.
 */
static inline int hyp_page_count(void *addr)
{
	struct hyp_page *p = hyp_virt_to_page(addr);

	/* Callers shouldn't see the extra reference held by page_alloc.c */
	return hyp_refcount_get(p->refcount) - 1;
}

static inline void hyp_page_ref_inc(struct hyp_page *p)
{
	hyp_refcount_inc(p->refcount);
}

static inline void hyp_page_ref_dec(struct hyp_page *p)
{
	hyp_refcount_dec(p->refcount);
}

/*
 * page_alloc.c takes an extra reference on freshly-allocated pages,
 * hence we initialise the reference count to 2.
 */
#define HYP_PAGE_INIT_REFCOUNT 2

static inline void hyp_set_page_refcounted(struct hyp_page *p)
{
	hyp_refcount_set(p->refcount, HYP_PAGE_INIT_REFCOUNT);
}
#endif /* __KVM_HYP_MEMORY_H */
