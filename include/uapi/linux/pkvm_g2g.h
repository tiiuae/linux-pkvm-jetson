/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * /dev/pkvm-g2g: guest-to-guest messages and page sharing for userspace in a
 * protected pKVM guest.
 *
 * Present only in a guest kernel built with CONFIG_PKVM_GUEST_TO_GUEST, and
 * registered only when the hypervisor advertises the guest-to-guest calls.
 * Each ioctl is a thin wrapper around one hypercall described in
 * <linux/arm-smccc.h> (GUEST_ID_*, GUEST_MSG_* and GUEST_SHARE_*), and keeps
 * its meaning: peers are named by the identity and incarnation the hypervisor
 * reports, never by anything the host chose.
 *
 * All structures are fixed-size and made of __u64 only, so they have no
 * padding and the same layout for 32- and 64-bit callers. Fields marked "out"
 * are ignored on input.
 *
 * Errors (ioctl returns -1 and sets errno):
 *   EINVAL      malformed arguments; a handle this file does not hold in that
 *               role; or the hypervisor answered INVALID_PARAMETER
 *   EFAULT      bad user pointer
 *   ENOMEM      the pages for an offer could not be allocated
 *   EPERM       this VM has not registered an identity (NO_IDENTITY); this
 *               device does not register one
 *   ESRCH       the named peer is not a live protected VM at that
 *               incarnation (NO_PEER)
 *   ENOENT      no such share at the hypervisor (NO_SHARE); see REVOKE and
 *               RELEASE, where it means different things
 *   EBUSY       a page or the caller is in the wrong state (DENIED)
 *   ENOSPC      OFFER: the share table or this VM's quota is full (LIMIT);
 *               ACCEPT: no free window to map the share into
 *   EAGAIN      MSG_SEND: the peer's mailbox is full (BUSY);
 *               MSG_RECV: no message (EMPTY)
 *   EOPNOTSUPP  the hypervisor does not implement the call
 *   EIO         any other hypervisor answer
 */
#ifndef _UAPI_LINUX_PKVM_G2G_H
#define _UAPI_LINUX_PKVM_G2G_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* Pages per share, at most. Pages are 4 KiB: the device requires it. */
#define PKVM_G2G_MAX_PAGES	512

/* OFFER flags: the borrower may only read (and never execute). */
#define PKVM_G2G_SHARE_RO	(1ULL << 0)

/* Words of payload a message carries. */
#define PKVM_G2G_MSG_WORDS	4

/* A VM's name: a 128-bit identity and the incarnation that holds it. */
struct pkvm_g2g_ident {
	__u64 id_lo;
	__u64 id_hi;
	__u64 incarnation;
};

/*
 * OFFER: the driver allocates nr_pages zeroed pages, IPA-contiguous, and
 * offers them to the borrower named in peer. The pages stay this VM's: the
 * owner reads and writes them through mmap() at mmap_offset, before, during
 * and after the borrower's access.
 */
struct pkvm_g2g_offer {
	struct pkvm_g2g_ident peer;	/* in: the borrower */
	__u64 nr_pages;			/* in: 1..PKVM_G2G_MAX_PAGES */
	__u64 flags;			/* in: 0 or PKVM_G2G_SHARE_RO */
	__u64 handle;			/* out: the share, as the hypervisor names it */
	__u64 mmap_offset;		/* out: pass to mmap() */
};

/*
 * ACCEPT: map the share the owner offered this VM. The driver chooses where
 * (an unused window at the top of this VM's address space); userspace reaches
 * the pages through mmap() at mmap_offset.
 */
struct pkvm_g2g_accept {
	struct pkvm_g2g_ident owner;	/* in: the owner, as it sent the handle */
	__u64 handle;			/* in: the handle the owner was given */
	__u64 nr_pages;			/* in: must equal the offer's */
	__u64 flags;			/* in: must be 0; out: the offer's flags */
	__u64 mmap_offset;		/* out: pass to mmap() */
};

/* REVOKE (owner) and RELEASE (borrower). */
struct pkvm_g2g_end {
	__u64 handle;			/* in */
	__u64 flags;			/* in: must be 0 */
};

/* MSG_SEND and MSG_RECV: a few words to or from a peer, through the hypervisor. */
struct pkvm_g2g_msg {
	struct pkvm_g2g_ident peer;	/* SEND in: the target; RECV out: the sender */
	__u64 flags;			/* in: must be 0 */
	__u64 payload[PKVM_G2G_MSG_WORDS];	/* SEND in, RECV out */
};

#define PKVM_G2G_IOC_MAGIC	0xB9

/* This VM's identity (0, 0 if it registered none) and incarnation. */
#define PKVM_G2G_IOC_SELF	_IOR(PKVM_G2G_IOC_MAGIC, 0x00, struct pkvm_g2g_ident)
/* in: id_lo, id_hi. out: incarnation, 0 if no live protected VM holds the name. */
#define PKVM_G2G_IOC_LOOKUP	_IOWR(PKVM_G2G_IOC_MAGIC, 0x01, struct pkvm_g2g_ident)
#define PKVM_G2G_IOC_OFFER	_IOWR(PKVM_G2G_IOC_MAGIC, 0x02, struct pkvm_g2g_offer)
#define PKVM_G2G_IOC_ACCEPT	_IOWR(PKVM_G2G_IOC_MAGIC, 0x03, struct pkvm_g2g_accept)
/*
 * REVOKE ends a share this file offered, whatever the borrower is doing.
 * RELEASE gives up a share this file accepted. Both first remove every
 * mapping of the share made through this file; touching one afterwards
 * raises SIGBUS, and the share can never be mapped again.
 *
 * ENOENT means different things to the two:
 *  - RELEASE: the owner had already ended the share (revoked it, or died),
 *    so it is gone from this file just as after a successful RELEASE;
 *  - REVOKE: the hypervisor did not confirm that the pages are this VM's
 *    alone again. The share stays with this file, dead and still holding
 *    its pages, as after any other failed REVOKE or RELEASE (EBUSY, EIO):
 *    the call can be repeated, and if it still fails when the file is
 *    closed, the pages (or the window) are leaked, never reused.
 *
 * Once ended, a share is no longer found by its handle. Its pages (owner)
 * or window (borrower) are given back when the hypervisor has confirmed the
 * end - for the owner, that the pages are this VM's alone again - and the
 * last mapping of the share has been munmap()ed. Until then nothing can
 * reuse memory that a stale translation might still reach, and the window
 * stays taken.
 */
#define PKVM_G2G_IOC_REVOKE	_IOW(PKVM_G2G_IOC_MAGIC, 0x04, struct pkvm_g2g_end)
#define PKVM_G2G_IOC_RELEASE	_IOW(PKVM_G2G_IOC_MAGIC, 0x05, struct pkvm_g2g_end)
#define PKVM_G2G_IOC_MSG_SEND	_IOW(PKVM_G2G_IOC_MAGIC, 0x06, struct pkvm_g2g_msg)
/*
 * MSG_RECV clears the structure before it takes a message, and an EFAULT
 * then means no message was taken; only an munmap() of the buffer racing the
 * call can lose one.
 */
#define PKVM_G2G_IOC_MSG_RECV	_IOWR(PKVM_G2G_IOC_MAGIC, 0x07, struct pkvm_g2g_msg)

/*
 * mmap(): MAP_SHARED, never PROT_EXEC, and PROT_READ only for a read-only
 * borrow. offset = mmap_offset + i * 4096 maps the share from its page i; the
 * length may not run past its last page. mmap_offset is a token the driver
 * never reuses (one 2 MiB stride per share), so an offset from a share that
 * has ended maps nothing.
 *
 * Lifetime: closing the file (the last reference, which every mapping also
 * holds) revokes every share it offered and releases every share it accepted.
 *
 * If the owner revokes, or dies, while a borrower still has the pages mapped,
 * the hypervisor removes them from the borrower at once. The borrower's next
 * access then faults in the hypervisor, and the guest sees an external abort
 * (SIGBUS) if the host injects it as it should; a hostile host can instead
 * stop running the vCPU. Do not hand a borrowed mapping to a system call: an
 * access by the kernel itself when the owner revokes is an oops, not a signal.
 */

#endif /* _UAPI_LINUX_PKVM_G2G_H */
