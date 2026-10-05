// SPDX-License-Identifier: GPL-2.0-only
/*
 * /dev/pkvm-g2g: guest-to-guest messages and page sharing for userspace in a
 * protected pKVM guest.
 *
 * CONFIG_PKVM_GUEST_TO_GUEST only, and registered only when the hypervisor
 * advertises every guest-to-guest call (GUEST_SHARE_* 12, 13, 19, 20,
 * GUEST_ID_* 14-16, GUEST_MSG_* 17-18). The ioctl ABI is in
 * <uapi/linux/pkvm_g2g.h>; each ioctl is one hypercall, described in
 * <linux/arm-smccc.h>. The node is root-only (0600).
 *
 * What the device holds, and the rules it keeps:
 *
 *  - An OFFER allocates zeroed pages (alloc_pages_exact(): IPA-contiguous, each
 *    page its own) and offers them. The pages go back to the page allocator
 *    only after a REVOKE that EL2 answered with SUCCESS, and only once no VMA
 *    maps them (below). Any other answer may mean a peer can still reach them,
 *    so they are kept, and on close leaked.
 *
 *  - An ACCEPT maps the share into a window: a 2 MiB slot below the top of the
 *    IPA space, slots 16..47 (the runtime self-test in arm-pkvm-guest.c uses
 *    0..7), claimed with request_mem_region() so that it overlaps nothing the
 *    kernel knows of. The kernel never maps or touches a window itself; only
 *    userspace does, through mmap(). A window is reused only after EL2 said it
 *    is empty: RELEASE returned SUCCESS, or NO_SHARE because the owner revoked
 *    or died first.
 *
 *  - Mappings are made at fault time (VM_PFNMAP, vmf_insert_pfn()), never in
 *    mmap(). The fault handler checks the share is live under the file's
 *    mutex, and REVOKE and RELEASE clear that flag and unmap_mapping_range()
 *    under the same mutex before the hypercall, so no fault maps a share after
 *    its end call starts. Installing PTEs in mmap() instead would race: the VMA
 *    is linked into the file's mapping only after ->mmap returns, so a
 *    concurrent zap could miss it. VM_PFNMAP also keeps GUP, and so any page
 *    pin, away from share pages.
 *
 *  - The zap alone does not make the pages free to reuse. munmap() clears a
 *    VMA's PTEs, unlinks the VMA from the file's mapping and only then flushes
 *    the TLB (vms_clear_ptes(): unmap_vmas(), free_pgtables(),
 *    tlb_finish_mmu()). An end call between the unlink and the flush zaps
 *    nothing, while another CPU can still store through a stale TLB entry. So
 *    every share counts the VMAs that map it (->mmap and ->open add one,
 *    ->close drops one). ->close runs from remove_vma(), after the flush. The
 *    pages or the window are given back when EL2 has ended the share AND its
 *    last VMA has closed, whichever comes second.
 *
 *  - Closing the file (its last reference; every mapping holds one) ends every
 *    share it holds, so nothing outlives it.
 *
 *  - If an owner revokes, or dies, while this guest's userspace maps the share,
 *    EL2 unmaps the window regardless. The next user access faults at EL2, and
 *    the guest gets an external abort (SIGBUS) if the host injects one as it
 *    should. An access by the kernel itself (a borrowed buffer passed to a
 *    system call) would oops, so userspace must not do that.
 *
 *  - Payload is never logged.
 *
 * Locking: a mutex per file guards its share list and each share's state; the
 * device mutex (window slots, mmap keys) nests inside it; hypercalls are made
 * under the file mutex. mmap() and the fault handler take the file mutex
 * inside mmap_lock, and REVOKE/RELEASE take i_mmap_rwsem (in the zap) inside
 * the file mutex.
 *
 * GUEST_MSG_RECV has one mailbox per VM and no demultiplexing: while the
 * runtime ping/share self-test in arm-pkvm-guest.c runs (with
 * CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST, for about 15 minutes after boot,
 * unless arm_pkvm_guest.g2g_runtime_test=0) it takes every message, including
 * ones meant for userspace here.
 *
 * Nothing here registers an identity for this VM, and MSG_SEND, OFFER and
 * ACCEPT need one: EL2 refuses them (EPERM) until something has. With
 * CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST the boot-time self-test registers a
 * predictable one; otherwise nothing in the kernel does.
 */

#include <linux/arm-smccc.h>
#include <linux/bits.h>
#include <linux/cpufeature.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pkvm_g2g.h>
#include <linux/printk.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <asm/hypervisor.h>

/*
 * Windows: 2 MiB slots counted downward from the top of the IPA space. The
 * runtime share self-test in arm-pkvm-guest.c takes slots 0..7; this device
 * takes 16..47, so the two never meet.
 */
#define PKVM_G2G_DEV_WIN_FIRST		16
#define PKVM_G2G_DEV_WIN_COUNT		32
#define PKVM_G2G_DEV_WIN_SIZE		SZ_2M

/* mmap offsets: one PKVM_G2G_MAX_PAGES-page (2 MiB) stride per share key. */
#define PKVM_G2G_DEV_KEY_SHIFT		9
#define PKVM_G2G_DEV_KEY_MAX		BIT_ULL(40)

static_assert(BIT(PKVM_G2G_DEV_KEY_SHIFT) == PKVM_G2G_MAX_PAGES);
static_assert(PKVM_G2G_MAX_PAGES * SZ_4K == PKVM_G2G_DEV_WIN_SIZE);
static_assert(PKVM_G2G_DEV_WIN_COUNT <= BITS_PER_LONG);
static_assert(PKVM_G2G_SHARE_RO == ARM_SMCCC_KVM_G2G_SHARE_RO);

enum pkvm_g2g_dev_role {
	PKVM_G2G_DEV_OWNER,
	PKVM_G2G_DEV_BORROWER,
};

/* ---- Decisions. Pure: the userspace harness compiles them verbatim. ---- */

static bool pkvm_g2g_dev_pages_ok(u64 nr_pages)
{
	return nr_pages >= 1 && nr_pages <= PKVM_G2G_MAX_PAGES;
}

static bool pkvm_g2g_dev_ident_ok(const struct pkvm_g2g_ident *id)
{
	return (id->id_lo || id->id_hi) && id->incarnation;
}

static int pkvm_g2g_dev_check_offer(const struct pkvm_g2g_offer *o)
{
	if (!pkvm_g2g_dev_pages_ok(o->nr_pages) ||
	    (o->flags & ~PKVM_G2G_SHARE_RO) ||
	    !pkvm_g2g_dev_ident_ok(&o->peer))
		return -EINVAL;

	return 0;
}

static int pkvm_g2g_dev_check_accept(const struct pkvm_g2g_accept *a)
{
	if (!pkvm_g2g_dev_pages_ok(a->nr_pages) || a->flags || !a->handle ||
	    !pkvm_g2g_dev_ident_ok(&a->owner))
		return -EINVAL;

	return 0;
}

static int pkvm_g2g_dev_check_end(const struct pkvm_g2g_end *e)
{
	return e->handle && !e->flags ? 0 : -EINVAL;
}

/* The errno for a hypercall's x0; see <uapi/linux/pkvm_g2g.h>. */
static int pkvm_g2g_dev_errno(long ret)
{
	switch (ret) {
	case SMCCC_RET_SUCCESS:			return 0;
	case SMCCC_RET_INVALID_PARAMETER:	return -EINVAL;
	case SMCCC_RET_NOT_SUPPORTED:		return -EOPNOTSUPP;
	case ARM_SMCCC_KVM_G2G_MSG_EMPTY:	return -EAGAIN;
	case ARM_SMCCC_KVM_G2G_MSG_BUSY:	return -EAGAIN;
	case ARM_SMCCC_KVM_G2G_MSG_NO_PEER:	return -ESRCH;
	case ARM_SMCCC_KVM_G2G_MSG_NO_IDENTITY:	return -EPERM;
	case ARM_SMCCC_KVM_G2G_SHARE_NO_SHARE:	return -ENOENT;
	case ARM_SMCCC_KVM_G2G_SHARE_DENIED:	return -EBUSY;
	case ARM_SMCCC_KVM_G2G_SHARE_LIMIT:	return -ENOSPC;
	default:				return -EIO;
	}
}

/*
 * After the call that ends a share (REVOKE by its owner, RELEASE by its
 * borrower) returned @ret: may the driver take back what it held for the
 * share - the owner's pages for the page allocator, the borrower's window for
 * another share? Only once EL2 has said the peer cannot reach them: the
 * owner's REVOKE succeeded, so they are its own alone again; or the
 * borrower's RELEASE succeeded, or found no share because the owner revoked
 * or died first, and EL2 unmapped the window then. Any other answer may mean
 * they are still shared. They are then kept, leaked if it comes to that,
 * rather than handed on.
 */
static bool pkvm_g2g_dev_end_frees(enum pkvm_g2g_dev_role role, long ret)
{
	if (ret == SMCCC_RET_SUCCESS)
		return true;

	return role == PKVM_G2G_DEV_BORROWER &&
	       ret == ARM_SMCCC_KVM_G2G_SHARE_NO_SHARE;
}

/* The IPA of window @slot: 2 MiB slots downward from the top of the IPA space. */
static u64 pkvm_g2g_dev_window_ipa(unsigned int ipa_bits, unsigned int slot)
{
	return BIT_ULL(ipa_bits) - (u64)(slot + 1) * PKVM_G2G_DEV_WIN_SIZE;
}

/*
 * The first of this device's slots whose bit is clear in @used, scanning
 * round from bit @from; or -ENOSPC. Next-fit rather than lowest-first, so
 * that a window EL2 refuses because it is not empty is not the first one
 * offered again every time.
 */
static int pkvm_g2g_dev_pick_slot(unsigned long used, unsigned int from)
{
	unsigned int i, bit;

	for (i = 0; i < PKVM_G2G_DEV_WIN_COUNT; i++) {
		bit = (from + i) % PKVM_G2G_DEV_WIN_COUNT;
		if (!(used & BIT(bit)))
			return PKVM_G2G_DEV_WIN_FIRST + bit;
	}

	return -ENOSPC;
}

static u64 pkvm_g2g_dev_key_offset(u64 key)
{
	return key << (PKVM_G2G_DEV_KEY_SHIFT + PAGE_SHIFT);
}

/* The share key and page that file page offset @pgoff names. 0 or -EINVAL. */
static int pkvm_g2g_dev_decode(unsigned long pgoff, u64 *key, u64 *page)
{
	*key = pgoff >> PKVM_G2G_DEV_KEY_SHIFT;
	*page = pgoff & (PKVM_G2G_MAX_PAGES - 1);

	return *key && *key < PKVM_G2G_DEV_KEY_MAX ? 0 : -EINVAL;
}

/* Do pages [@first, @first + @npages) lie inside a share of @nr_pages? */
static bool pkvm_g2g_dev_range_ok(u64 nr_pages, u64 first, u64 npages)
{
	return npages && first < nr_pages && npages <= nr_pages - first;
}

/*
 * May a mapping with @vm_flags be made of a share? It must be MAP_SHARED: a
 * private copy of memory a peer writes means nothing, and these pages cannot
 * be copied on write. That is VM_MAYSHARE: do_mmap() clears VM_SHARED, along
 * with VM_MAYWRITE, for a MAP_SHARED mapping of a read-only file, so it is
 * never a CoW mapping either. The mapping is never executable, because a
 * peer can write the memory. And it is read-only if the owner offered the
 * share so.
 */
static int pkvm_g2g_dev_check_vm_flags(unsigned long vm_flags,
				       enum pkvm_g2g_dev_role role,
				       u64 share_flags)
{
	if (!(vm_flags & VM_MAYSHARE))
		return -EINVAL;
	if (vm_flags & VM_EXEC)
		return -EACCES;
	if (role == PKVM_G2G_DEV_BORROWER &&
	    (share_flags & PKVM_G2G_SHARE_RO) && (vm_flags & VM_WRITE))
		return -EACCES;

	return 0;
}

/* What mprotect() must never add to such a mapping. */
static unsigned long pkvm_g2g_dev_vm_flags_clear(enum pkvm_g2g_dev_role role,
						 u64 share_flags)
{
	if (role == PKVM_G2G_DEV_BORROWER && (share_flags & PKVM_G2G_SHARE_RO))
		return VM_MAYEXEC | VM_MAYWRITE;

	return VM_MAYEXEC;
}

/* ---- State. ---- */

/* A share this file offered (owner) or accepted (borrower). */
struct pkvm_g2g_dev_share {
	struct list_head node;
	enum pkvm_g2g_dev_role role;
	bool live;		/* mappable; false from the first end call on */
	bool ended;		/* EL2 ended it: it waits only for its VMAs */
	unsigned int vmas;	/* VMAs mapping it: ->mmap, ->open add; ->close drops */
	u64 handle;
	u64 key;		/* the mmap offset token; never reused */
	u64 nr_pages;
	u64 flags;		/* as offered: PKVM_G2G_SHARE_RO or 0 */
	u64 ipa;		/* owner: its pages; borrower: the window */
	void *pages;		/* owner: from alloc_pages_exact() */
	unsigned int slot;	/* borrower: the window's slot */
};

struct pkvm_g2g_dev_file {
	struct mutex lock;		/* the list and every share's state */
	struct list_head shares;
	struct address_space *mapping;	/* where this file's VMAs are linked */
};

/* Device-wide, under pkvm_g2g_dev_lock, which nests inside a file's lock. */
static DEFINE_MUTEX(pkvm_g2g_dev_lock);
static struct {
	unsigned long windows;	/* bit i: slot PKVM_G2G_DEV_WIN_FIRST + i claimed */
	unsigned int next_win;	/* the bit to look at first: next-fit */
	u64 next_key;
	unsigned int ipa_bits;	/* set once, at init */
} pkvm_g2g_dev;

/* ---- Glue. ---- */

/* Issue @regs as an SMCCC 1.2 HVC; @regs then holds the results. Returns x0. */
static long pkvm_g2g_dev_hvc(struct arm_smccc_1_2_regs *regs)
{
	struct arm_smccc_1_2_regs res;

	arm_smccc_1_2_hvc(regs, &res);
	*regs = res;
	memzero_explicit(&res, sizeof(res));

	return (long)regs->a0;
}

/* A fresh mmap key, or 0 if they ran out. Under pkvm_g2g_dev_lock. */
static u64 pkvm_g2g_dev_new_key(void)
{
	if (pkvm_g2g_dev.next_key + 1 >= PKVM_G2G_DEV_KEY_MAX)
		return 0;

	return ++pkvm_g2g_dev.next_key;
}

/*
 * Claim the next free window, after the last one claimed, that nothing else
 * in the iomem tree overlaps. Its slot, or -ENOSPC. Under pkvm_g2g_dev_lock.
 */
static int pkvm_g2g_dev_claim_window(void)
{
	unsigned long tried = pkvm_g2g_dev.windows;
	unsigned int bit;
	int slot;

	while ((slot = pkvm_g2g_dev_pick_slot(tried, pkvm_g2g_dev.next_win)) >= 0) {
		bit = slot - PKVM_G2G_DEV_WIN_FIRST;
		tried |= BIT(bit);
		if (request_mem_region(pkvm_g2g_dev_window_ipa(pkvm_g2g_dev.ipa_bits, slot),
				       PKVM_G2G_DEV_WIN_SIZE, "pkvm-g2g")) {
			pkvm_g2g_dev.windows |= BIT(bit);
			pkvm_g2g_dev.next_win = (bit + 1) % PKVM_G2G_DEV_WIN_COUNT;
			return slot;
		}
	}

	return -ENOSPC;
}

static void pkvm_g2g_dev_free_window(unsigned int slot)
{
	mutex_lock(&pkvm_g2g_dev_lock);
	release_mem_region(pkvm_g2g_dev_window_ipa(pkvm_g2g_dev.ipa_bits, slot),
			   PKVM_G2G_DEV_WIN_SIZE);
	pkvm_g2g_dev.windows &= ~BIT(slot - PKVM_G2G_DEV_WIN_FIRST);
	mutex_unlock(&pkvm_g2g_dev_lock);
}

static struct pkvm_g2g_dev_share *
pkvm_g2g_dev_find(struct pkvm_g2g_dev_file *f, enum pkvm_g2g_dev_role role,
		  u64 handle)
{
	struct pkvm_g2g_dev_share *s;

	list_for_each_entry(s, &f->shares, node)
		if (s->role == role && s->handle == handle && !s->ended)
			return s;

	return NULL;
}

static struct pkvm_g2g_dev_share *
pkvm_g2g_dev_find_key(struct pkvm_g2g_dev_file *f, u64 key)
{
	struct pkvm_g2g_dev_share *s;

	list_for_each_entry(s, &f->shares, node)
		if (s->key == key)
			return s;

	return NULL;
}

/*
 * Give back @s's pages or window and free @s. With @f's lock held, once EL2
 * has ended the share and no VMA maps it any more.
 */
static void pkvm_g2g_dev_free(struct pkvm_g2g_dev_share *s)
{
	if (s->role == PKVM_G2G_DEV_OWNER)
		free_pages_exact(s->pages, s->nr_pages * PAGE_SIZE);
	else
		pkvm_g2g_dev_free_window(s->slot);
	list_del(&s->node);
	kfree(s);
}

/*
 * End @s, with @f's lock held: REVOKE if this file offered it, RELEASE if it
 * accepted it. Returns EL2's x0.
 *
 * Before the call, the share stops being mappable and every user mapping of
 * it that is still linked is zapped, so userspace never maps the pages
 * through this file again, whatever EL2 answers. After it, if
 * pkvm_g2g_dev_end_frees() allows, the share is ended: no lookup by handle
 * finds it, and it is freed now if no VMA maps it, or else by its last
 * ->close (a munmap may still be on its way to flushing the TLB). Otherwise
 * @s stays on the list, dead and still holding the pages or window, and the
 * call can be repeated.
 */
static long pkvm_g2g_dev_end(struct pkvm_g2g_dev_file *f,
			     struct pkvm_g2g_dev_share *s)
{
	struct arm_smccc_1_2_regs regs = {
		.a0 = s->role == PKVM_G2G_DEV_OWNER ?
		      ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_REVOKE_FUNC_ID :
		      ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_RELEASE_FUNC_ID,
		.a1 = s->handle,
		.a2 = 0,		/* flags: none defined */
	};
	long ret;

	s->live = false;
	unmap_mapping_range(f->mapping, pkvm_g2g_dev_key_offset(s->key),
			    pkvm_g2g_dev_key_offset(1), 1);

	ret = pkvm_g2g_dev_hvc(&regs);
	if (!pkvm_g2g_dev_end_frees(s->role, ret))
		return ret;

	s->ended = true;
	if (!s->vmas)
		pkvm_g2g_dev_free(s);

	return ret;
}

/*
 * A share was made, but its handle and offset never reached userspace (the
 * copy-out faulted): end it now rather than leave it unreachable until close.
 * Looked up again by handle, because another thread may have ended it.
 */
static void pkvm_g2g_dev_abandon(struct pkvm_g2g_dev_file *f,
				 enum pkvm_g2g_dev_role role, u64 handle)
{
	struct pkvm_g2g_dev_share *s;

	mutex_lock(&f->lock);
	s = pkvm_g2g_dev_find(f, role, handle);
	if (s)
		pkvm_g2g_dev_end(f, s);
	mutex_unlock(&f->lock);
}

static long pkvm_g2g_dev_self(void __user *uarg)
{
	struct arm_smccc_1_2_regs regs = {
		.a0 = ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_SELF_FUNC_ID,
	};
	struct pkvm_g2g_ident id;
	int err;

	err = pkvm_g2g_dev_errno(pkvm_g2g_dev_hvc(&regs));
	if (err)
		return err;

	id.id_lo = regs.a1;
	id.id_hi = regs.a2;
	id.incarnation = regs.a3;

	return copy_to_user(uarg, &id, sizeof(id)) ? -EFAULT : 0;
}

static long pkvm_g2g_dev_lookup(void __user *uarg)
{
	struct arm_smccc_1_2_regs regs = {
		.a0 = ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_PEER_LOOKUP_FUNC_ID,
	};
	struct pkvm_g2g_ident id;
	int err;

	if (copy_from_user(&id, uarg, sizeof(id)))
		return -EFAULT;

	regs.a1 = id.id_lo;
	regs.a2 = id.id_hi;
	err = pkvm_g2g_dev_errno(pkvm_g2g_dev_hvc(&regs));
	if (err)
		return err;

	id.incarnation = regs.a1;

	return copy_to_user(uarg, &id, sizeof(id)) ? -EFAULT : 0;
}

static long pkvm_g2g_dev_msg_send(void __user *uarg)
{
	struct arm_smccc_1_2_regs regs = {
		.a0 = ARM_SMCCC_VENDOR_HYP_KVM_GUEST_MSG_SEND_FUNC_ID,
	};
	struct pkvm_g2g_msg m;
	long ret;

	if (copy_from_user(&m, uarg, sizeof(m)))
		return -EFAULT;

	regs.a1 = m.peer.id_lo;
	regs.a2 = m.peer.id_hi;
	regs.a3 = m.peer.incarnation;
	regs.a4 = m.flags;
	regs.a5 = m.payload[0];
	regs.a6 = m.payload[1];
	regs.a7 = m.payload[2];
	regs.a8 = m.payload[3];
	ret = pkvm_g2g_dev_hvc(&regs);

	memzero_explicit(&m, sizeof(m));
	memzero_explicit(&regs, sizeof(regs));

	return pkvm_g2g_dev_errno(ret);
}

static long pkvm_g2g_dev_msg_recv(void __user *uarg)
{
	struct arm_smccc_1_2_regs regs = {
		.a0 = ARM_SMCCC_VENDOR_HYP_KVM_GUEST_MSG_RECV_FUNC_ID,
	};
	struct pkvm_g2g_msg m;
	int err;

	if (copy_from_user(&m, uarg, sizeof(m)))
		return -EFAULT;
	/*
	 * RECV takes the message out of the mailbox for good, so check the
	 * result can be written first. Only a racing munmap() of the buffer
	 * can still lose it.
	 */
	if (clear_user(uarg, sizeof(m)))
		return -EFAULT;

	regs.a1 = m.flags;
	err = pkvm_g2g_dev_errno(pkvm_g2g_dev_hvc(&regs));
	if (!err) {
		m.peer.id_lo = regs.a1;
		m.peer.id_hi = regs.a2;
		m.peer.incarnation = regs.a3;
		m.payload[0] = regs.a4;
		m.payload[1] = regs.a5;
		m.payload[2] = regs.a6;
		m.payload[3] = regs.a7;
		if (copy_to_user(uarg, &m, sizeof(m)))
			err = -EFAULT;	/* the message is lost */
	}

	memzero_explicit(&m, sizeof(m));
	memzero_explicit(&regs, sizeof(regs));

	return err;
}

static long pkvm_g2g_dev_offer(struct pkvm_g2g_dev_file *f, void __user *uarg)
{
	struct arm_smccc_1_2_regs regs;
	struct pkvm_g2g_dev_share *s;
	struct pkvm_g2g_offer o;
	int err;

	if (copy_from_user(&o, uarg, sizeof(o)))
		return -EFAULT;
	err = pkvm_g2g_dev_check_offer(&o);
	if (err)
		return err;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	/* Up to order 9 at userspace's request: no warning, and charged to it. */
	s->pages = alloc_pages_exact(o.nr_pages * PAGE_SIZE,
				     GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN |
				     __GFP_ACCOUNT);
	if (!s->pages) {
		kfree(s);
		return -ENOMEM;
	}
	s->role = PKVM_G2G_DEV_OWNER;
	s->nr_pages = o.nr_pages;
	s->flags = o.flags;
	s->ipa = virt_to_phys(s->pages);

	mutex_lock(&pkvm_g2g_dev_lock);
	s->key = pkvm_g2g_dev_new_key();
	mutex_unlock(&pkvm_g2g_dev_lock);
	if (!s->key) {
		err = -ENOSPC;
		goto out_free;
	}

	regs = (struct arm_smccc_1_2_regs) {
		.a0 = ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_OFFER_FUNC_ID,
		.a1 = s->ipa,
		.a2 = s->nr_pages,
		.a3 = o.peer.id_lo,
		.a4 = o.peer.id_hi,
		.a5 = o.peer.incarnation,
		.a6 = s->flags,
	};
	err = pkvm_g2g_dev_errno(pkvm_g2g_dev_hvc(&regs));
	if (err)
		goto out_free;	/* EL2 changed nothing: the pages are ours alone */

	s->handle = regs.a1;
	s->live = true;
	o.handle = s->handle;
	o.mmap_offset = pkvm_g2g_dev_key_offset(s->key);

	mutex_lock(&f->lock);
	list_add_tail(&s->node, &f->shares);
	mutex_unlock(&f->lock);

	if (copy_to_user(uarg, &o, sizeof(o))) {
		pkvm_g2g_dev_abandon(f, PKVM_G2G_DEV_OWNER, o.handle);
		return -EFAULT;
	}

	return 0;

out_free:
	free_pages_exact(s->pages, s->nr_pages * PAGE_SIZE);
	kfree(s);
	return err;
}

static long pkvm_g2g_dev_accept(struct pkvm_g2g_dev_file *f, void __user *uarg)
{
	struct arm_smccc_1_2_regs regs;
	struct pkvm_g2g_dev_share *s;
	struct pkvm_g2g_accept a;
	int err, slot;

	if (copy_from_user(&a, uarg, sizeof(a)))
		return -EFAULT;
	err = pkvm_g2g_dev_check_accept(&a);
	if (err)
		return err;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	mutex_lock(&pkvm_g2g_dev_lock);
	s->key = pkvm_g2g_dev_new_key();
	slot = s->key ? pkvm_g2g_dev_claim_window() : -ENOSPC;
	mutex_unlock(&pkvm_g2g_dev_lock);
	if (slot < 0) {
		kfree(s);
		return slot;
	}
	s->role = PKVM_G2G_DEV_BORROWER;
	s->slot = slot;
	s->handle = a.handle;
	s->nr_pages = a.nr_pages;
	s->ipa = pkvm_g2g_dev_window_ipa(pkvm_g2g_dev.ipa_bits, slot);

	regs = (struct arm_smccc_1_2_regs) {
		.a0 = ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_ACCEPT_FUNC_ID,
		.a1 = s->ipa,
		.a2 = s->nr_pages,
		.a3 = a.owner.id_lo,
		.a4 = a.owner.id_hi,
		.a5 = a.owner.incarnation,
		.a6 = s->handle,
		.a7 = 0,		/* flags: none defined */
	};
	err = pkvm_g2g_dev_errno(pkvm_g2g_dev_hvc(&regs));
	if (err) {
		/* EL2 mapped nothing, or unmapped what it had mapped. */
		pkvm_g2g_dev_free_window(slot);
		kfree(s);
		return err;
	}

	s->flags = regs.a1;
	s->live = true;
	a.flags = s->flags;
	a.mmap_offset = pkvm_g2g_dev_key_offset(s->key);

	mutex_lock(&f->lock);
	list_add_tail(&s->node, &f->shares);
	mutex_unlock(&f->lock);

	if (copy_to_user(uarg, &a, sizeof(a))) {
		pkvm_g2g_dev_abandon(f, PKVM_G2G_DEV_BORROWER, a.handle);
		return -EFAULT;
	}

	return 0;
}

static long pkvm_g2g_dev_end_ioctl(struct pkvm_g2g_dev_file *f,
				   void __user *uarg,
				   enum pkvm_g2g_dev_role role)
{
	struct pkvm_g2g_dev_share *s;
	struct pkvm_g2g_end e;
	int err;

	if (copy_from_user(&e, uarg, sizeof(e)))
		return -EFAULT;
	err = pkvm_g2g_dev_check_end(&e);
	if (err)
		return err;

	mutex_lock(&f->lock);
	s = pkvm_g2g_dev_find(f, role, e.handle);
	err = s ? pkvm_g2g_dev_errno(pkvm_g2g_dev_end(f, s)) : -EINVAL;
	mutex_unlock(&f->lock);

	return err;
}

static long pkvm_g2g_dev_ioctl(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct pkvm_g2g_dev_file *f = file->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case PKVM_G2G_IOC_SELF:
		return pkvm_g2g_dev_self(uarg);
	case PKVM_G2G_IOC_LOOKUP:
		return pkvm_g2g_dev_lookup(uarg);
	case PKVM_G2G_IOC_OFFER:
		return pkvm_g2g_dev_offer(f, uarg);
	case PKVM_G2G_IOC_ACCEPT:
		return pkvm_g2g_dev_accept(f, uarg);
	case PKVM_G2G_IOC_REVOKE:
		return pkvm_g2g_dev_end_ioctl(f, uarg, PKVM_G2G_DEV_OWNER);
	case PKVM_G2G_IOC_RELEASE:
		return pkvm_g2g_dev_end_ioctl(f, uarg, PKVM_G2G_DEV_BORROWER);
	case PKVM_G2G_IOC_MSG_SEND:
		return pkvm_g2g_dev_msg_send(uarg);
	case PKVM_G2G_IOC_MSG_RECV:
		return pkvm_g2g_dev_msg_recv(uarg);
	default:
		return -ENOTTY;
	}
}

/* A VMA's share: set by ->mmap, and kept alive by the VMA count. */
static struct pkvm_g2g_dev_share *pkvm_g2g_dev_vma_share(struct vm_area_struct *vma)
{
	return vma->vm_private_data;
}

static vm_fault_t pkvm_g2g_dev_fault(struct vm_fault *vmf)
{
	struct pkvm_g2g_dev_file *f = vmf->vma->vm_file->private_data;
	struct pkvm_g2g_dev_share *s = pkvm_g2g_dev_vma_share(vmf->vma);
	vm_fault_t ret = VM_FAULT_SIGBUS;
	u64 key, page;

	if (pkvm_g2g_dev_decode(vmf->pgoff, &key, &page))
		return VM_FAULT_SIGBUS;

	mutex_lock(&f->lock);
	if (s->live && key == s->key && page < s->nr_pages)
		ret = vmf_insert_pfn(vmf->vma, vmf->address,
				     PHYS_PFN(s->ipa) + page);
	mutex_unlock(&f->lock);

	return ret;
}

/* A VMA was split off one of ours: one more VMA maps the share. */
static void pkvm_g2g_dev_vm_open(struct vm_area_struct *vma)
{
	struct pkvm_g2g_dev_file *f = vma->vm_file->private_data;

	mutex_lock(&f->lock);
	pkvm_g2g_dev_vma_share(vma)->vmas++;
	mutex_unlock(&f->lock);
}

/*
 * A VMA is gone, and its TLB entries with it: remove_vma() calls this after
 * munmap's tlb_finish_mmu(). The last one out frees a share EL2 has ended.
 */
static void pkvm_g2g_dev_vm_close(struct vm_area_struct *vma)
{
	struct pkvm_g2g_dev_file *f = vma->vm_file->private_data;
	struct pkvm_g2g_dev_share *s = pkvm_g2g_dev_vma_share(vma);

	mutex_lock(&f->lock);
	if (!--s->vmas && s->ended)
		pkvm_g2g_dev_free(s);
	mutex_unlock(&f->lock);
}

static const struct vm_operations_struct pkvm_g2g_dev_vm_ops = {
	.open = pkvm_g2g_dev_vm_open,
	.close = pkvm_g2g_dev_vm_close,
	.fault = pkvm_g2g_dev_fault,
};

/* Check and set up the VMA; nothing is mapped until it faults. */
static int pkvm_g2g_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct pkvm_g2g_dev_file *f = file->private_data;
	struct pkvm_g2g_dev_share *s;
	u64 key, first;
	int err;

	err = pkvm_g2g_dev_decode(vma->vm_pgoff, &key, &first);
	if (err)
		return err;

	mutex_lock(&f->lock);
	s = pkvm_g2g_dev_find_key(f, key);
	if (!s || !s->live ||
	    !pkvm_g2g_dev_range_ok(s->nr_pages, first, vma_pages(vma)))
		err = -EINVAL;
	else
		err = pkvm_g2g_dev_check_vm_flags(vma->vm_flags, s->role,
						  s->flags);
	if (!err) {
		vm_flags_mod(vma, VM_PFNMAP | VM_IO | VM_DONTEXPAND |
				  VM_DONTDUMP | VM_DONTCOPY,
			     pkvm_g2g_dev_vm_flags_clear(s->role, s->flags));
		vma->vm_ops = &pkvm_g2g_dev_vm_ops;
		vma->vm_private_data = s;
		s->vmas++;	/* ->mmap succeeding is final: the VMA is inserted */
	}
	mutex_unlock(&f->lock);

	return err;
}

static int pkvm_g2g_dev_open(struct inode *inode, struct file *file)
{
	struct pkvm_g2g_dev_file *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;

	mutex_init(&f->lock);
	INIT_LIST_HEAD(&f->shares);
	f->mapping = file->f_mapping;
	file->private_data = f;

	return nonseekable_open(inode, file);
}

/* The last reference is gone, mappings included: end every share. */
static int pkvm_g2g_dev_release(struct inode *inode, struct file *file)
{
	struct pkvm_g2g_dev_file *f = file->private_data;
	struct pkvm_g2g_dev_share *s, *tmp;
	enum pkvm_g2g_dev_role role;
	u64 handle;
	long ret;

	mutex_lock(&f->lock);
	list_for_each_entry_safe(s, tmp, &f->shares, node) {
		/* No VMA is left (each held the file), so nothing waits for one. */
		if (s->ended) {
			pkvm_g2g_dev_free(s);
			continue;
		}
		role = s->role;
		handle = s->handle;
		ret = pkvm_g2g_dev_end(f, s);
		if (pkvm_g2g_dev_end_frees(role, ret))
			continue;

		/* EL2 may still share them: never free or reuse them. */
		pr_warn("pkvm-g2g: %s of share %#llx on close returned %ld; leaking its %s\n",
			role == PKVM_G2G_DEV_OWNER ? "REVOKE" : "RELEASE",
			handle, ret,
			role == PKVM_G2G_DEV_OWNER ? "pages" : "window");
		list_del(&s->node);
		kfree(s);
	}
	mutex_unlock(&f->lock);

	mutex_destroy(&f->lock);
	kfree(f);

	return 0;
}

static const struct file_operations pkvm_g2g_dev_fops = {
	.owner		= THIS_MODULE,
	.open		= pkvm_g2g_dev_open,
	.release	= pkvm_g2g_dev_release,
	.unlocked_ioctl	= pkvm_g2g_dev_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.mmap		= pkvm_g2g_dev_mmap,
};

static struct miscdevice pkvm_g2g_dev_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "pkvm-g2g",
	.fops		= &pkvm_g2g_dev_fops,
	.mode		= 0600,
};

/*
 * The IPA size, computed exactly as the runtime self-test in arm-pkvm-guest.c
 * does.
 */
static unsigned int __init pkvm_g2g_dev_ipa_bits(void)
{
	u64 mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	unsigned int parange, bits;

	parange = cpuid_feature_extract_unsigned_field(mmfr0,
						       ID_AA64MMFR0_EL1_PARANGE_SHIFT);
	bits = id_aa64mmfr0_parange_to_phys_shift(parange);

	return min_t(unsigned int, bits, PHYS_MASK_SHIFT);
}

/* Why this guest cannot have the device, or NULL. */
static const char * __init pkvm_g2g_dev_unusable(void)
{
	static const u32 fns[] = {
		ARM_SMCCC_KVM_FUNC_GUEST_SHARE_OFFER,
		ARM_SMCCC_KVM_FUNC_GUEST_SHARE_REVOKE,
		ARM_SMCCC_KVM_FUNC_GUEST_ID_REGISTER,
		ARM_SMCCC_KVM_FUNC_GUEST_ID_SELF,
		ARM_SMCCC_KVM_FUNC_GUEST_ID_PEER_LOOKUP,
		ARM_SMCCC_KVM_FUNC_GUEST_MSG_SEND,
		ARM_SMCCC_KVM_FUNC_GUEST_MSG_RECV,
		ARM_SMCCC_KVM_FUNC_GUEST_SHARE_ACCEPT,
		ARM_SMCCC_KVM_FUNC_GUEST_SHARE_RELEASE,
	};
	struct arm_smccc_1_2_regs regs = {
		.a0 = ARM_SMCCC_VENDOR_HYP_KVM_HYP_MEMINFO_FUNC_ID,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fns); i++)
		if (!kvm_arm_hyp_service_available(fns[i]))
			return "guest-to-guest hypercalls not advertised";
	if (!kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_HYP_MEMINFO))
		return "HYP_MEMINFO not advertised";
	/* arm_smccc_1_2_hvc() is an HVC whatever the conduit; check it is one. */
	if (arm_smccc_1_1_get_conduit() != SMCCC_CONDUIT_HVC)
		return "the SMCCC conduit is not HVC";
	/* nr_pages means the same pages to EL1 and EL2, and 512 fill a window. */
	pkvm_g2g_dev_hvc(&regs);
	if (regs.a0 != SZ_4K || regs.a0 != PAGE_SIZE)
		return "guest and hypervisor pages are not both 4 KiB";

	return NULL;
}

static int __init pkvm_g2g_dev_init(void)
{
	const char *why = pkvm_g2g_dev_unusable();
	int err;

	if (why) {
		pr_info("pkvm-g2g: /dev/%s not registered: %s\n",
			pkvm_g2g_dev_misc.name, why);
		return 0;
	}

	pkvm_g2g_dev.ipa_bits = pkvm_g2g_dev_ipa_bits();
	err = misc_register(&pkvm_g2g_dev_misc);
	if (err) {
		pr_err("pkvm-g2g: /dev/%s: misc_register() failed: %d\n",
		       pkvm_g2g_dev_misc.name, err);
		return err;
	}

	pr_info("pkvm-g2g: /dev/%s registered; windows are slots %u..%u below 2^%u\n",
		pkvm_g2g_dev_misc.name, PKVM_G2G_DEV_WIN_FIRST,
		PKVM_G2G_DEV_WIN_FIRST + PKVM_G2G_DEV_WIN_COUNT - 1,
		pkvm_g2g_dev.ipa_bits);

	return 0;
}
late_initcall(pkvm_g2g_dev_init);
