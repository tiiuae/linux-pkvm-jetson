// SPDX-License-Identifier: GPL-2.0-only
/*
 * Support for the hypercall interface exposed to protected guests by
 * pKVM.
 *
 * Author: Will Deacon <will@kernel.org>
 * Copyright (C) 2024 Google LLC
 */

#include <linux/arm-smccc.h>
#include <linux/array_size.h>
#include <linux/io.h>
#include <linux/linkage.h>
#include <linux/mem_encrypt.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/string.h>
#include <linux/virtio_balloon.h>

#ifdef CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST
#include <linux/bitops.h>
#include <linux/cpufeature.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/jiffies.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/workqueue.h>
#endif

#include <asm/hypervisor.h>

static size_t pkvm_granule;
static bool pkvm_func_range;

static int __arm_smccc_do(u32 func_id, phys_addr_t phys, int numgranules)
{
	while (numgranules--) {
		struct arm_smccc_res res;

		arm_smccc_1_1_invoke(func_id, phys, 0, 0, &res);
		if (res.a0 != SMCCC_RET_SUCCESS)
			return -EPERM;

		phys += pkvm_granule;
	}

	return 0;
}

static int __arm_smccc_do_range(u32 func_id, phys_addr_t phys, int numgranules)
{
	while (numgranules) {
		struct arm_smccc_res res;

		arm_smccc_1_1_invoke(func_id, phys, numgranules, 0, &res);
		if (res.a0 != SMCCC_RET_SUCCESS)
			return -EPERM;

		phys += pkvm_granule * res.a1;
		numgranules -= res.a1;
	}

	return 0;
}

/*
 * Apply func_id on the range [phys : phys + numpages * PAGE_SIZE)
 */
static int arm_smccc_do_range(u32 func_id, phys_addr_t phys, int numpages,
			      bool func_has_range)
{
	size_t size = numpages * PAGE_SIZE;
	int numgranules;

	if (!IS_ALIGNED(phys, PAGE_SIZE))
		return -EINVAL;

	if (!IS_ALIGNED(phys | size, pkvm_granule))
		return -EINVAL;

	numgranules = size / pkvm_granule;

	if (func_has_range)
		return __arm_smccc_do_range(func_id, phys, numgranules);

	return __arm_smccc_do(func_id, phys, numgranules);
}

static int pkvm_set_memory_encrypted(unsigned long addr, int numpages)
{
	return arm_smccc_do_range(ARM_SMCCC_VENDOR_HYP_KVM_MEM_UNSHARE_FUNC_ID,
				  virt_to_phys((void *)addr), numpages, pkvm_func_range);
}

static int pkvm_set_memory_decrypted(unsigned long addr, int numpages)
{
	return arm_smccc_do_range(ARM_SMCCC_VENDOR_HYP_KVM_MEM_SHARE_FUNC_ID,
				  virt_to_phys((void *)addr), numpages, pkvm_func_range);
}

static const struct arm64_mem_crypt_ops pkvm_crypt_ops = {
	.encrypt	= pkvm_set_memory_encrypted,
	.decrypt	= pkvm_set_memory_decrypted,
};

static int mmio_guard_ioremap_hook(phys_addr_t phys, size_t size,
				   pgprot_t *prot)
{
	pteval_t protval = pgprot_val(*prot);
	u32 func_id = pkvm_func_range ?
		ARM_SMCCC_VENDOR_HYP_KVM_MMIO_RGUARD_MAP_FUNC_ID :
		ARM_SMCCC_VENDOR_HYP_KVM_MMIO_GUARD_MAP_FUNC_ID;
	phys_addr_t end;

	/*
	 * We only expect MMIO emulation for regions mapped with device
	 * attributes.
	 */
	if (protval != PROT_DEVICE_nGnRE && protval != PROT_DEVICE_nGnRnE)
		return 0;

	end = ALIGN(phys + size, PAGE_SIZE);
	phys = ALIGN_DOWN(phys, PAGE_SIZE);
	size = end - phys;

	/*
	 * It is fine to overshoot MMIO guard requests. Its sole purpose is to
	 * indicate the hypervisor where are the MMIO regions and we have
	 * validated the alignment of the memory regions beforehand.
	 */
	end = ALIGN(phys + size, pkvm_granule);
	phys = ALIGN_DOWN(phys, pkvm_granule);

	pr_info("[arm-pkvm-guest] mmio_guard_ioremap_hook: func_id 0x%x, phys %pa, numpages %llu, pkvm_func_range %d",
		func_id, &phys, (end - phys) >> PAGE_SHIFT, pkvm_func_range);
	if (arm_smccc_do_range(func_id, phys, (end - phys) >> PAGE_SHIFT,
			      pkvm_func_range))
		pr_warn_once("MMIO guard map failed, not enrolled?\n");
	return 0;
}

#ifdef CONFIG_VIRTIO_BALLOON_HYP_OPS

static bool mem_relinquish_available;

static bool pkvm_page_relinquish_disallowed(void)
{
	return WARN_ON(mem_relinquish_available && (pkvm_granule > PAGE_SIZE));
}

static void pkvm_page_relinquish(struct page *page, unsigned int nr)
{
	phys_addr_t phys, end;
	u32 func_id = ARM_SMCCC_VENDOR_HYP_KVM_MEM_RELINQUISH_FUNC_ID;

	if (!mem_relinquish_available)
		return;

	phys = page_to_phys(page);
	end = phys + PAGE_SIZE * nr;

	while (phys < end) {
		struct arm_smccc_res res;

		arm_smccc_1_1_invoke(func_id, phys, 0, 0, &res);
		BUG_ON(res.a0 != SMCCC_RET_SUCCESS);

		phys += pkvm_granule;
	}
}

static struct virtio_balloon_hyp_ops pkvm_virtio_balloon_hyp_ops = {
	.page_relinquish_disallowed = pkvm_page_relinquish_disallowed,
	.page_relinquish = pkvm_page_relinquish
};

#endif

#ifdef CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST

/*
 * Boot-time exercise of guest identity: ARM_SMCCC_KVM_FUNC_GUEST_ID_REGISTER,
 * _SELF and _PEER_LOOKUP. CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST only, and the
 * only code in the kernel that registers an identity on a guest's behalf.
 *
 * This is a test of behaviour - and it is not read-only: registering an
 * identity changes hypervisor state. It is safe to do at boot because an
 * identity grants nothing (see the ABI comment in <linux/arm-smccc.h>): it is a
 * name, not a capability, and registration is once-only per VM, so there is
 * nothing to clean up and nothing to leak.
 *
 * The identity this probe registers is deliberately PREDICTABLE - a fixed magic
 * in the low half and the hypervisor-assigned incarnation in the high half -
 * for one reason: it lets two guests on the same boot find each other without
 * any out-of-band channel, which is what demonstrates cross-guest discovery on
 * real hardware.
 *
 * It is NOT a model for real use, and copying it would undo the entire point of
 * the interface. A real guest must register an identity it derives from its own
 * secret material - a key bound to its attestation, a measured-boot secret -
 * because a predictable name is one the untrusted host can also predict, and a
 * host that predicts a name can start a VM of its own that registers it first
 * and then answers to it. The hypervisor guarantees that a name maps to one VM;
 * it cannot guarantee that the VM which claimed a guessable name is the one you
 * meant.
 */
#define PKVM_G2G_PROBE_ID_LO		0x70726f62652d6964ULL	/* "probe-id" */

/* How many incarnations to sweep when looking for peers. Boot order is unknown. */
#define PKVM_G2G_PROBE_PEER_SWEEP	8

static bool pkvm_g2g_id_call(u32 func_id, u64 a1, u64 a2,
			     struct arm_smccc_res *res)
{
	memset(res, 0, sizeof(*res));
	arm_smccc_1_1_invoke(func_id, a1, a2, res);

	return (long)res->a0 == SMCCC_RET_SUCCESS;
}

static void pkvm_g2g_probe_identity(void)
{
	struct arm_smccc_res res;
	u64 incarnation, my_hi;
	unsigned int peers = 0;
	bool ok = true;
	u64 i;

	if (!kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_ID_REGISTER) ||
	    !kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_ID_SELF) ||
	    !kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_ID_PEER_LOOKUP)) {
		pr_info("pkvm-g2g: identity hypercalls not advertised, SKIP (hypervisor built without CONFIG_PKVM_GUEST_TO_GUEST, or an EL2 self-check disabled guest-to-guest?)\n");
		return;
	}

	/* 1. Before registering, this VM must have no identity but a valid incarnation. */
	if (!pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_SELF_FUNC_ID,
			      0, 0, &res)) {
		pr_err("pkvm-g2g: GUEST_ID_SELF failed with x0=%ld\n", (long)res.a0);
		return;
	}
	incarnation = res.a3;
	if (res.a1 || res.a2) {
		pr_err("pkvm-g2g: GUEST_ID_SELF reports an identity 0x%lx:0x%lx before this VM registered one\n",
		       res.a2, res.a1);
		ok = false;
	}
	if (!incarnation) {
		pr_err("pkvm-g2g: incarnation is 0, which must never be a live VM's\n");
		ok = false;
		return;
	}
	my_hi = incarnation;

	/* 2. Register. See the warning above about the predictable value. */
	if (!pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_REGISTER_FUNC_ID,
			      PKVM_G2G_PROBE_ID_LO, my_hi, &res)) {
		pr_err("pkvm-g2g: GUEST_ID_REGISTER(0x%llx:0x%llx) refused with x0=%ld\n",
		       my_hi, PKVM_G2G_PROBE_ID_LO, (long)res.a0);
		return;
	}
	if (res.a1 != incarnation) {
		pr_err("pkvm-g2g: GUEST_ID_REGISTER returned incarnation %lu, GUEST_ID_SELF said %llu\n",
		       res.a1, incarnation);
		ok = false;
	}

	/* 3. Read it back. */
	if (!pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_SELF_FUNC_ID,
			      0, 0, &res) ||
	    res.a1 != PKVM_G2G_PROBE_ID_LO || res.a2 != my_hi) {
		pr_err("pkvm-g2g: GUEST_ID_SELF read back 0x%lx:0x%lx, registered 0x%llx:0x%llx\n",
		       res.a2, res.a1, my_hi, PKVM_G2G_PROBE_ID_LO);
		ok = false;
	}

	/*
	 * 4. Immutability. A second registration must be refused whatever it
	 * asks for - this is the property that makes a name mean anything to a
	 * peer that checked it earlier.
	 */
	pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_REGISTER_FUNC_ID,
			 ~PKVM_G2G_PROBE_ID_LO, my_hi, &res);
	if ((long)res.a0 != SMCCC_RET_NOT_REQUIRED) {
		pr_err("pkvm-g2g: re-registering a different identity gave x0=%ld, wanted NOT_REQUIRED (%d): identities are not immutable\n",
		       (long)res.a0, SMCCC_RET_NOT_REQUIRED);
		ok = false;
	}

	/* 5. A VM cannot name itself as a peer, and (0, 0) is not a name. */
	pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_PEER_LOOKUP_FUNC_ID,
			 PKVM_G2G_PROBE_ID_LO, my_hi, &res);
	if ((long)res.a0 != SMCCC_RET_INVALID_PARAMETER) {
		pr_err("pkvm-g2g: PEER_LOOKUP of our own identity gave x0=%ld, wanted INVALID_PARAMETER\n",
		       (long)res.a0);
		ok = false;
	}
	pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_PEER_LOOKUP_FUNC_ID,
			 0, 0, &res);
	if ((long)res.a0 != SMCCC_RET_INVALID_PARAMETER) {
		pr_err("pkvm-g2g: PEER_LOOKUP of (0, 0) gave x0=%ld, wanted INVALID_PARAMETER\n",
		       (long)res.a0);
		ok = false;
	}

	/* 6. A name nobody holds must resolve to no peer, not to an error. */
	if (!pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_PEER_LOOKUP_FUNC_ID,
			      PKVM_G2G_PROBE_ID_LO, ~0ULL, &res) || res.a1) {
		pr_err("pkvm-g2g: PEER_LOOKUP of an unheld name gave x0=%ld x1=%lu, wanted SUCCESS with 0\n",
		       (long)res.a0, res.a1);
		ok = false;
	}

	/*
	 * 7. Cross-guest discovery. Reported rather than asserted: whether any
	 * peer is found depends on boot order and on how many protected VMs the
	 * host started, neither of which this guest controls. A peer found here
	 * was named by this guest and resolved by the hypervisor with no host
	 * involvement at any point, which is the result worth having.
	 */
	for (i = 1; i <= PKVM_G2G_PROBE_PEER_SWEEP; i++) {
		if (i == my_hi)
			continue;
		if (!pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_PEER_LOOKUP_FUNC_ID,
				      PKVM_G2G_PROBE_ID_LO, i, &res))
			continue;
		if (!res.a1)
			continue;
		pr_info("pkvm-g2g: peer found: identity 0x%llx:0x%llx is live, incarnation %lu\n",
			i, PKVM_G2G_PROBE_ID_LO, res.a1);
		peers++;
	}

	pr_info("pkvm-g2g: identity probe: %s (incarnation %llu, %u peer(s) discovered)\n",
		ok ? "PASS" : "FAIL", incarnation, peers);
}

#else /* !CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST */

static inline void pkvm_g2g_probe_identity(void) { }

#endif /* CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST */

static bool __dram_is_aligned(size_t pkvm_granule)
{
	struct memblock_region *region, *prev = NULL;

	for_each_mem_region(region) {
		phys_addr_t prev_end;

		if (!prev)
			goto discontinuous;

		prev_end = prev->base + prev->size;
		if (prev_end == region->base)
			goto contiguous;

		if (!IS_ALIGNED(prev_end, pkvm_granule))
			return false;
discontinuous:
		if (!IS_ALIGNED(region->base, pkvm_granule))
			return false;
contiguous:
		prev = region;
	}

	return IS_ALIGNED(region->base + region->size, pkvm_granule);
}

void pkvm_init_hyp_services(void)
{
	struct arm_smccc_res res;

	if (!kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_HYP_MEMINFO))
		return;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_HYP_MEMINFO_FUNC_ID,
			     0, 0, 0, &res);
	if ((long)res.a0 < 0)
		return;

	pkvm_granule = res.a0;
	pkvm_func_range = !!res.a1;
	pr_info("arm-pkvm-guest: pkvm_func_range = %d", pkvm_func_range);

	pr_info("pKVM guest: granule=%lu func_range=%d\n",
		(unsigned long)pkvm_granule, pkvm_func_range);

	if (kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_MEM_SHARE) &&
	    kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_MEM_UNSHARE))
	    arm64_mem_crypt_ops_register(&pkvm_crypt_ops);

	/* Enroll guest to MMIO guard hypervisor extension automatically */
	WARN_ON(!kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_MMIO_GUARD_ENROLL));
	memset(&res, 0, sizeof(res));
	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_KVM_MMIO_GUARD_ENROLL_FUNC_ID, &res);
	WARN_ON((long)res.a0 < 0);

	if (!kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_MMIO_GUARD_MAP)) {
		pr_warn("pKVM guest: MMIO_GUARD_MAP not available\n");
	} else if (!__dram_is_aligned(pkvm_granule)) {
		pr_warn("pKVM guest: DRAM not aligned to granule %lu, MMIO guard hook NOT registered\n",
			(unsigned long)pkvm_granule);
	} else {
		pr_info("pKVM guest: registering MMIO guard ioremap hook\n");
		arm64_ioremap_prot_hook_register(&mmio_guard_ioremap_hook);
	}

#ifdef CONFIG_VIRTIO_BALLOON_HYP_OPS
	virtio_balloon_hyp_ops = &pkvm_virtio_balloon_hyp_ops;
	if (kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_MEM_RELINQUISH))
		mem_relinquish_available = true;
#endif

	pkvm_g2g_probe_identity();
}

#ifdef CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST

/*
 * Runtime guest-to-guest ping-pong over ARM_SMCCC_KVM_FUNC_GUEST_MSG_SEND and
 * _RECV: a message from this protected VM to a peer and back, through EL2,
 * that the host never sees. CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST only, like the
 * page sharing test below that rides on it.
 *
 * Why at runtime and not in pkvm_init_hyp_services() with the probes above:
 * those run once, during setup_arch(), and whichever guest boots first finds
 * no peer at all, while one booting later finds it. An exchange that has to
 * work in both directions therefore has to keep looking. It also needs no
 * early-boot contortions: this runs from a delayed work long after the page
 * allocator, workqueues and the RNG exist.
 *
 * What it does, for about PKVM_G2G_PING_TICKS seconds after boot, once a
 * second:
 *
 *  1. drain this VM's mailbox (GUEST_MSG_RECV until EMPTY, bounded). A PING n
 *     is answered with PONG n to the sender EL2 reports; a PONG is matched
 *     against the PING this guest sent that peer;
 *  2. every PKVM_G2G_PING_LOOKUP_EVERY ticks, sweep GUEST_ID_PEER_LOOKUP over a
 *     window of incarnations for live peers, using the same predictable
 *     identity scheme as pkvm_g2g_probe_identity() - which is what registered
 *     this VM's identity, and carries the same warning: a predictable name is
 *     a demonstration convenience, not a model. A peer whose PING arrives is
 *     added too, so a peer outside the window is still answered and pinged.
 *     A peer that has died is retired, and its entry reused for a new one;
 *  3. send each newly seen live peer exactly one PING carrying a fresh random
 *     64-bit nonce, and send any PONG still owed. BUSY - the peer's one slot
 *     is full - is retried on the next tick; NO_PEER retires the peer.
 *
 * A PING from a peer the table has no room for is answered at once, and only
 * once: there is nowhere to remember a retry. If that PONG meets BUSY or
 * NO_PEER it is counted as dropped, not as an error - neither says anything
 * is wrong with EL2 or with either guest.
 *
 * Every message checks all four payload words (type, nonce, ~nonce, a fixed
 * tag), so a register that EL2 dropped or garbled on the way shows up as a
 * malformed message rather than as a quiet mismatch.
 *
 * The lines that print a nonce are KERN_DEBUG, deliberately. dmesg and
 * journalctl -k inside the guest show them, but the guest console is a
 * host-emulated device, and these images boot with loglevel=7 (or quieter),
 * which keeps KERN_DEBUG off it. At KERN_INFO the nonce would reach the host
 * on the console, and the claim the PONG line makes would be false. Anything
 * else that ships this guest's kernel log off the guest shows them to
 * whatever carries it; that is the operator's readout, not the transport.
 *
 * All state is touched only from the one delayed work, so it needs no lock.
 */

#define PKVM_G2G_PING_PERIOD_MS		1000
#define PKVM_G2G_PING_TICKS		300	/* ~5 minutes */
#define PKVM_G2G_PING_LOOKUP_EVERY	5	/* ticks between peer sweeps */
#define PKVM_G2G_PING_SWEEP		64	/* incarnations per sweep */
#define PKVM_G2G_PING_SWEEP_AHEAD	32	/* ... of which above our own */
#define PKVM_G2G_PING_MAX_PEERS		8
#define PKVM_G2G_PING_RECV_BUDGET	8	/* RECVs per tick */

/* Payload words 0 and 3. Word 1 is the nonce, word 2 its complement. */
#define PKVM_G2G_PING_TYPE_PING		0x474e49502d673267ULL	/* "g2g-PING" */
#define PKVM_G2G_PING_TYPE_PONG		0x474e4f502d673267ULL	/* "g2g-PONG" */
#define PKVM_G2G_PING_TAG		0x2164616f6c796170ULL	/* "payload!" */

/*
 * Runtime guest-to-guest page sharing test, riding on the ping's peer table,
 * tick and mailbox. With every live peer this guest is both an owner (of a
 * share it offers the peer) and a borrower (of the share the peer offers it):
 *
 *  round 1  OFFER two pages, with a fresh nonce pair written into them, and
 *           send the peer the handle. The peer ACCEPTs them into a window of
 *           its own, checks the nonce it reads there, writes a reply nonce
 *           beside it and says so; the owner finds the reply in its own pages.
 *           That is data crossing from one protected VM to another through
 *           pages the host never maps. Then the peer RELEASEs, the owner
 *           REVOKEs, OFFERs the same pages again - which works only if they
 *           came back exclusively its own - and REVOKEs that.
 *  round 2  the same exchange, then the owner REVOKEs while the peer still
 *           maps the pages, and says so; the peer's RELEASE must then answer
 *           NO_SHARE, because EL2 has already taken the pages from it.
 *  round 3  the same exchange, and the share is left in place. When the peer
 *           dies (its VM is shut down), the survivor checks both
 *           directions of EL2's cleanup: as owner, its REVOKE must succeed; as
 *           borrower, its RELEASE must answer NO_SHARE.
 *
 * Only handles and round numbers travel in messages. The nonces travel only
 * through the shared pages, and the lines that print them are KERN_DEBUG for
 * the reason the ping's are.
 *
 * A borrower maps each share into a 2 MiB window just below the top of its IPA
 * space, claimed with request_mem_region() so it cannot overlap anything the
 * kernel knows of (DT regions, PCI BARs), and mapped with memremap(MEMREMAP_WB):
 * normal memory, so the MMIO-guard ioremap hook is not involved. A window is
 * never touched after its share ends: it is unmapped before RELEASE, and before
 * acting on a message that says the owner revoked or on finding the owner gone.
 * Owner pages are freed only after a REVOKE succeeded.
 */
#define PKVM_G2G_SHARE_TICKS		900	/* ~15 minutes: past a peer's restart */
#define PKVM_G2G_SHARE_PAGES		2
#define PKVM_G2G_SHARE_SLOTS		8	/* 2 MiB windows below the top of the IPA space */
#define PKVM_G2G_SHARE_QUEUE		4	/* share messages owed to one peer */

/* Payload word 0 of a share message. Word 1 is the handle, word 2 the round. */
#define PKVM_G2G_SHARE_MSG_OFFERED	0x52464f2d53673267ULL	/* "g2gS-OFR" */
#define PKVM_G2G_SHARE_MSG_ACCEPTED	0x5043412d53673267ULL	/* "g2gS-ACP" */
#define PKVM_G2G_SHARE_MSG_FAILED	0x5252452d53673267ULL	/* "g2gS-ERR" */
#define PKVM_G2G_SHARE_MSG_RELEASE_PLS	0x514c522d53673267ULL	/* "g2gS-RLQ" */
#define PKVM_G2G_SHARE_MSG_RELEASED	0x444c522d53673267ULL	/* "g2gS-RLD" */
#define PKVM_G2G_SHARE_MSG_REVOKED	0x4b56522d53673267ULL	/* "g2gS-RVK" */
#define PKVM_G2G_SHARE_TAG		0x2167706572616873ULL	/* "sharepg!" */

/*
 * Page 0 of a share. Page 1 carries the owner's nonce ^ PKVM_G2G_SHARE_SALT in
 * word 0 and the borrower's reply ^ PKVM_G2G_SHARE_SALT in word 1, so that the
 * second page is checked as well as the first.
 */
#define PKVM_G2G_SHARE_MAGIC		0x4552414853673267ULL	/* "g2gSHARE" */
#define PKVM_G2G_SHARE_REPLY		0x594c504552673267ULL	/* "g2gREPLY" */
#define PKVM_G2G_SHARE_SALT		0x5a5a5a5a5a5a5a5aULL
struct pkvm_g2g_share_page {
	u64 magic, round, nonce, check;			/* written by the owner */
	u64 reply_magic, echo, reply, reply_check;	/* written by the borrower */
};

enum pkvm_g2g_own_phase {
	PKVM_G2G_OWN_IDLE,		/* nothing offered yet */
	PKVM_G2G_OWN_OFFERED,		/* waiting for ACCEPTED */
	PKVM_G2G_OWN_WAIT_RELEASE,	/* round 1: waiting for RELEASED */
	PKVM_G2G_OWN_HELD,		/* round 3: left in place */
	PKVM_G2G_OWN_DONE,		/* finished, or stopped by an error */
};

#define pkvm_g2g_share_payload_log(fmt, ...) \
	printk(KERN_DEBUG "pkvm-g2g: share: " fmt, ##__VA_ARGS__)

/* See the comment above for why these are KERN_DEBUG and not pr_debug(). */
#define pkvm_g2g_ping_payload_log(fmt, ...) \
	printk(KERN_DEBUG "pkvm-g2g: ping: " fmt, ##__VA_ARGS__)

struct pkvm_g2g_ping_peer {
	/* Addressing, as EL2 reported it. incarnation == 0: a free entry. */
	u64 lo, hi, incarnation;

	/* The PING this guest sends the peer. */
	u64 nonce;
	bool ping_sent;
	bool ponged;

	/* A PONG this guest owes the peer, not yet deposited. */
	bool pong_owed;
	u64 pong_nonce;

	/*
	 * That incarnation is gone - SEND said NO_PEER, or the sweep's lookup
	 * no longer finds it - and never comes back. @gone_drains is
	 * pkvm_g2g_ping.drains at the time; pkvm_g2g_ping_add() reuses the
	 * entry once the mailbox has been emptied since.
	 */
	bool gone;
	unsigned long gone_drains;

	/*
	 * A SEND to it failed with an error: never send to it again. Unlike a
	 * gone entry this one is kept, because the peer may still be alive,
	 * and the sweep would only find it, track it and fail again.
	 */
	bool stopped;

	/* Sharing, this guest as owner of pages offered to the peer. */
	enum pkvm_g2g_own_phase own_phase;
	u8 own_round;			/* 1..3; 0 before the first offer */
	struct page *own_pages;		/* order 1; freed only after a REVOKE succeeded */
	u64 own_handle, own_nonce;

	/* Sharing, this guest as borrower of the peer's pages. */
	u64 brw_handle;
	u8 brw_round;
	unsigned int brw_window;	/* 1 + window slot, or 0: nothing mapped */
	void *brw_va;

	/* Share messages owed to the peer, oldest first; BUSY is retried. */
	u64 q[PKVM_G2G_SHARE_QUEUE][3];
	u8 q_len;

	/* EL2's cleanup has been checked, once, after the peer went. */
	bool share_checked;
};

static struct {
	struct delayed_work work;
	unsigned int tick;
	u64 self_lo, self_hi, self_incarnation;
	struct pkvm_g2g_ping_peer peers[PKVM_G2G_PING_MAX_PEERS];
	bool table_full_reported;
	unsigned int seen, pinged, ponged, answered, dropped, errors;
	/* How many times RECV has found the mailbox EMPTY. */
	unsigned long drains;
	bool share_on;
	unsigned long share_windows;	/* bitmap of window slots in use */
	unsigned int sh_r1, sh_r2, sh_r3, sh_borrowed, sh_teardown, sh_errors;
} pkvm_g2g_ping;

static const char *pkvm_g2g_msg_ret_str(long ret)
{
	switch (ret) {
	case SMCCC_RET_SUCCESS:			return "SUCCESS";
	case SMCCC_RET_NOT_SUPPORTED:		return "NOT_SUPPORTED";
	case SMCCC_RET_INVALID_PARAMETER:	return "INVALID_PARAMETER";
	case ARM_SMCCC_KVM_G2G_MSG_EMPTY:	return "EMPTY";
	case ARM_SMCCC_KVM_G2G_MSG_BUSY:	return "BUSY";
	case ARM_SMCCC_KVM_G2G_MSG_NO_PEER:	return "NO_PEER";
	case ARM_SMCCC_KVM_G2G_MSG_NO_IDENTITY:	return "NO_IDENTITY";
	case ARM_SMCCC_KVM_G2G_SHARE_NO_SHARE:	return "NO_SHARE";
	case ARM_SMCCC_KVM_G2G_SHARE_DENIED:	return "DENIED";
	case ARM_SMCCC_KVM_G2G_SHARE_LIMIT:	return "LIMIT";
	default:				return "unexpected";
	}
}

static long pkvm_g2g_msg_send(const struct pkvm_g2g_ping_peer *peer, u64 type,
			      u64 nonce)
{
	struct arm_smccc_1_2_regs args = {
		.a0 = ARM_SMCCC_VENDOR_HYP_KVM_GUEST_MSG_SEND_FUNC_ID,
		.a1 = peer->lo,
		.a2 = peer->hi,
		.a3 = peer->incarnation,
		.a4 = 0,		/* flags: none defined */
		.a5 = type,
		.a6 = nonce,
		.a7 = ~nonce,
		.a8 = PKVM_G2G_PING_TAG,
	};
	struct arm_smccc_1_2_regs res;

	arm_smccc_1_2_hvc(&args, &res);

	return (long)res.a0;
}

static long pkvm_g2g_msg_recv(struct arm_smccc_1_2_regs *res)
{
	struct arm_smccc_1_2_regs args = {
		.a0 = ARM_SMCCC_VENDOR_HYP_KVM_GUEST_MSG_RECV_FUNC_ID,
		.a1 = 0,		/* flags: none defined */
	};

	arm_smccc_1_2_hvc(&args, res);

	return (long)res->a0;
}

static struct pkvm_g2g_ping_peer *pkvm_g2g_ping_find(u64 lo, u64 hi,
						     u64 incarnation)
{
	unsigned int i;

	for (i = 0; i < PKVM_G2G_PING_MAX_PEERS; i++) {
		struct pkvm_g2g_ping_peer *p = &pkvm_g2g_ping.peers[i];

		if (p->incarnation == incarnation && p->lo == lo && p->hi == hi)
			return p;
	}

	return NULL;
}

/* Returns NULL only when the table is full. */
/*
 * Whether @p's entry can be given to a new peer: its incarnation is gone, its
 * last message has been read (see the wait for a drain in
 * pkvm_g2g_ping_add()), and the share code has finished with it -
 * pkvm_g2g_share_peer_gone() has checked EL2's cleanup and given back the
 * pages and the window the entry held. Reused any sooner, the entry would
 * lose them.
 */
static bool pkvm_g2g_ping_reusable(const struct pkvm_g2g_ping_peer *p)
{
	return p->gone && pkvm_g2g_ping.drains > p->gone_drains &&
	       (!pkvm_g2g_ping.share_on || p->share_checked);
}

static struct pkvm_g2g_ping_peer *pkvm_g2g_ping_add(u64 lo, u64 hi,
						    u64 incarnation,
						    const char *how)
{
	struct pkvm_g2g_ping_peer *p = pkvm_g2g_ping_find(lo, hi, incarnation);
	unsigned int i;

	if (p)
		return p;

	for (i = 0; i < PKVM_G2G_PING_MAX_PEERS; i++) {
		p = &pkvm_g2g_ping.peers[i];

		/*
		 * Take a free entry, or one whose incarnation is gone and whose
		 * last message has been read. Incarnations are never reused, so
		 * nothing can address a gone entry again; without reusing them
		 * the table fills after PKVM_G2G_PING_MAX_PEERS incarnations of
		 * peers and stays full. The wait for a drain: a peer noticed
		 * gone can still have one message in this VM's one-message
		 * slot, and it must be matched against this entry, not against
		 * a newcomer in its place. Once RECV has found the slot EMPTY
		 * after the peer was noticed gone, that message has been read.
		 */
		if (p->incarnation && !pkvm_g2g_ping_reusable(p))
			continue;

		memset(p, 0, sizeof(*p));
		p->lo = lo;
		p->hi = hi;
		p->incarnation = incarnation;
		p->nonce = get_random_u64();
		pkvm_g2g_ping.seen++;
		pr_info("pkvm-g2g: ping: peer at incarnation %llu (identity 0x%llx:0x%llx) %s\n",
			incarnation, hi, lo, how);
		return p;
	}

	if (!pkvm_g2g_ping.table_full_reported) {
		pr_warn("pkvm-g2g: ping: peer table full (%u), not tracking incarnation %llu\n",
			PKVM_G2G_PING_MAX_PEERS, incarnation);
		pkvm_g2g_ping.table_full_reported = true;
	}
	return NULL;
}

static void pkvm_g2g_ping_gone(struct pkvm_g2g_ping_peer *p)
{
	p->gone = true;
	p->gone_drains = pkvm_g2g_ping.drains;
}

static void pkvm_g2g_ping_sweep(void)
{
	u64 top = pkvm_g2g_ping.self_incarnation + PKVM_G2G_PING_SWEEP_AHEAD;
	u64 i = top > PKVM_G2G_PING_SWEEP ? top - PKVM_G2G_PING_SWEEP + 1 : 1;
	struct arm_smccc_res res;
	unsigned int n;

	/*
	 * Retire tracked peers that died, so that one which died before it
	 * could answer is not reported as owing a PONG. A name that now
	 * resolves to a different incarnation is a different VM.
	 */
	for (n = 0; n < PKVM_G2G_PING_MAX_PEERS; n++) {
		struct pkvm_g2g_ping_peer *p = &pkvm_g2g_ping.peers[n];

		if (!p->incarnation || p->gone)
			continue;
		if (!pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_PEER_LOOKUP_FUNC_ID,
				      p->lo, p->hi, &res) ||
		    res.a1 == p->incarnation)
			continue;
		pkvm_g2g_ping_gone(p);
		pr_info("pkvm-g2g: ping: incarnation %llu is gone (lookup), dropping it\n",
			p->incarnation);
	}

	for (; i <= top; i++) {
		if (pkvm_g2g_ping.self_lo == PKVM_G2G_PROBE_ID_LO &&
		    i == pkvm_g2g_ping.self_hi)
			continue;
		if (!pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_PEER_LOOKUP_FUNC_ID,
				      PKVM_G2G_PROBE_ID_LO, i, &res) || !res.a1)
			continue;
		pkvm_g2g_ping_add(PKVM_G2G_PROBE_ID_LO, i, res.a1,
				  "found by runtime lookup");
	}
}

static void pkvm_g2g_ping_handle(const struct arm_smccc_1_2_regs *m)
{
	u64 lo = m->a1, hi = m->a2, incarnation = m->a3;
	u64 type = m->a4, nonce = m->a5, check = m->a6, tag = m->a7;
	struct pkvm_g2g_ping_peer *p;
	long ret;

	if ((!lo && !hi) || !incarnation || check != ~nonce ||
	    tag != PKVM_G2G_PING_TAG) {
		pkvm_g2g_ping_payload_log("MALFORMED message from incarnation %llu (identity 0x%llx:0x%llx): %016llx %016llx %016llx %016llx\n",
					  incarnation, hi, lo, type, nonce,
					  check, tag);
		pkvm_g2g_ping.errors++;
		return;
	}

	switch (type) {
	case PKVM_G2G_PING_TYPE_PING:
		pkvm_g2g_ping_payload_log("got PING nonce=%016llx from incarnation %llu\n",
					  nonce, incarnation);
		p = pkvm_g2g_ping_add(lo, hi, incarnation, "found by its PING");
		if (p) {
			if (p->pong_owed)
				pkvm_g2g_ping_payload_log("PING nonce=%016llx from incarnation %llu supersedes unanswered nonce=%016llx\n",
							  nonce, incarnation,
							  p->pong_nonce);
			p->pong_owed = true;
			p->pong_nonce = nonce;
			break;
		}

		/* No room to remember it: answer now, once, or not at all. */
		{
			struct pkvm_g2g_ping_peer tmp = {
				.lo = lo, .hi = hi, .incarnation = incarnation,
			};

			ret = pkvm_g2g_msg_send(&tmp, PKVM_G2G_PING_TYPE_PONG,
						nonce);
			if (ret == SMCCC_RET_SUCCESS) {
				pkvm_g2g_ping.answered++;
				pkvm_g2g_ping_payload_log("sent PONG nonce=%016llx to incarnation %llu\n",
							  nonce, incarnation);
			} else if (ret == ARM_SMCCC_KVM_G2G_MSG_BUSY ||
				   ret == ARM_SMCCC_KVM_G2G_MSG_NO_PEER) {
				/*
				 * The peer's slot is full, or the peer is
				 * gone. A tracked peer would get the PONG on a
				 * later tick; this one cannot be remembered,
				 * so the reply is dropped. Not an error.
				 */
				pr_info("pkvm-g2g: ping: PONG to untracked incarnation %llu not deposited: x0=%ld (%s), dropped\n",
					incarnation, ret,
					pkvm_g2g_msg_ret_str(ret));
				pkvm_g2g_ping.dropped++;
			} else {
				pr_err("pkvm-g2g: ping: SEND PONG to untracked incarnation %llu failed: x0=%ld (%s), dropped\n",
				       incarnation, ret,
				       pkvm_g2g_msg_ret_str(ret));
				pkvm_g2g_ping.errors++;
			}
		}
		break;

	case PKVM_G2G_PING_TYPE_PONG:
		p = pkvm_g2g_ping_find(lo, hi, incarnation);
		if (!p || !p->ping_sent) {
			pkvm_g2g_ping_payload_log("UNSOLICITED PONG nonce=%016llx from incarnation %llu: no PING was sent to it\n",
						  nonce, incarnation);
			pkvm_g2g_ping.errors++;
		} else if (p->ponged) {
			pkvm_g2g_ping_payload_log("DUPLICATE PONG nonce=%016llx from incarnation %llu\n",
						  nonce, incarnation);
			pkvm_g2g_ping.errors++;
		} else if (nonce != p->nonce) {
			pkvm_g2g_ping_payload_log("PONG nonce MISMATCH from incarnation %llu: got %016llx, sent %016llx\n",
						  incarnation, nonce, p->nonce);
			pkvm_g2g_ping.errors++;
		} else {
			p->ponged = true;
			pkvm_g2g_ping.ponged++;
			pkvm_g2g_ping_payload_log("got PONG nonce=%016llx from incarnation %llu (through EL2; the host never saw the payload)\n",
						  nonce, incarnation);
		}
		break;

	default:
		pkvm_g2g_ping_payload_log("UNKNOWN message type %016llx from incarnation %llu\n",
					  type, incarnation);
		pkvm_g2g_ping.errors++;
		break;
	}
}

/* Deposit what is owed and what is new. BUSY is retried on the next tick. */
static void pkvm_g2g_ping_flush(void)
{
	unsigned int i;
	long ret;

	for (i = 0; i < PKVM_G2G_PING_MAX_PEERS; i++) {
		struct pkvm_g2g_ping_peer *p = &pkvm_g2g_ping.peers[i];

		if (!p->incarnation || p->gone || p->stopped)
			continue;

		if (p->pong_owed) {
			ret = pkvm_g2g_msg_send(p, PKVM_G2G_PING_TYPE_PONG,
						p->pong_nonce);
			if (ret == SMCCC_RET_SUCCESS) {
				p->pong_owed = false;
				pkvm_g2g_ping.answered++;
				pkvm_g2g_ping_payload_log("sent PONG nonce=%016llx to incarnation %llu\n",
							  p->pong_nonce,
							  p->incarnation);
			} else if (ret != ARM_SMCCC_KVM_G2G_MSG_BUSY) {
				p->pong_owed = false;
				goto send_failed;
			}
		}

		/*
		 * The ping's verdict covers its first PKVM_G2G_PING_TICKS; the
		 * loop runs on for the share test. After the verdict it still
		 * answers a late peer's PING, but starts no exchange of its own,
		 * so the counters in the verdict line stay what they were.
		 */
		if (!p->ping_sent && pkvm_g2g_ping.tick < PKVM_G2G_PING_TICKS) {
			ret = pkvm_g2g_msg_send(p, PKVM_G2G_PING_TYPE_PING,
						p->nonce);
			if (ret == SMCCC_RET_SUCCESS) {
				p->ping_sent = true;
				pkvm_g2g_ping.pinged++;
				pkvm_g2g_ping_payload_log("sent PING nonce=%016llx to incarnation %llu\n",
							  p->nonce,
							  p->incarnation);
			} else if (ret != ARM_SMCCC_KVM_G2G_MSG_BUSY) {
				goto send_failed;
			}
		}
		continue;

send_failed:
		/*
		 * NO_PEER is a peer going away, which is not an error of
		 * this path; anything else is. Either way stop sending to it:
		 * no other answer gets better by repeating the call. A gone
		 * peer's entry can be reused; a stopped one's is kept.
		 */
		if (ret == ARM_SMCCC_KVM_G2G_MSG_NO_PEER) {
			pkvm_g2g_ping_gone(p);
			pr_info("pkvm-g2g: ping: incarnation %llu is gone (NO_PEER), dropping it\n",
				p->incarnation);
		} else {
			p->stopped = true;
			pr_err("pkvm-g2g: ping: SEND to incarnation %llu failed: x0=%ld (%s), dropping it\n",
			       p->incarnation, ret, pkvm_g2g_msg_ret_str(ret));
			pkvm_g2g_ping.errors++;
		}
	}
}

static void pkvm_g2g_ping_finish(const char *why)
{
	const char *verdict;
	unsigned int i, owed = 0;

	for (i = 0; i < PKVM_G2G_PING_MAX_PEERS; i++) {
		struct pkvm_g2g_ping_peer *p = &pkvm_g2g_ping.peers[i];

		if (p->incarnation && !p->gone && !p->stopped && !p->ponged)
			owed++;
	}

	if (pkvm_g2g_ping.errors)
		verdict = "FAIL";
	else if (!pkvm_g2g_ping.seen)
		verdict = "NO PEERS";
	else if (owed || !pkvm_g2g_ping.ponged)
		verdict = "INCOMPLETE";
	else
		verdict = "PASS";

	pr_info("pkvm-g2g: ping: %s after %u s: %s (%u peer(s) seen, %u PINGed, %u PONGed back, %u PING(s) answered, %u PONG(s) dropped, %u error(s))\n",
		why, pkvm_g2g_ping.tick * PKVM_G2G_PING_PERIOD_MS / 1000,
		verdict, pkvm_g2g_ping.seen, pkvm_g2g_ping.pinged,
		pkvm_g2g_ping.ponged, pkvm_g2g_ping.answered,
		pkvm_g2g_ping.dropped, pkvm_g2g_ping.errors);
}

static long pkvm_g2g_share_call(u32 fn, u64 a1, u64 a2, u64 a3, u64 a4,
				u64 a5, u64 a6, u64 a7, u64 *x1)
{
	struct arm_smccc_1_2_regs args = {
		.a0 = fn, .a1 = a1, .a2 = a2, .a3 = a3,
		.a4 = a4, .a5 = a5, .a6 = a6, .a7 = a7,
	};
	struct arm_smccc_1_2_regs res;

	arm_smccc_1_2_hvc(&args, &res);
	if (x1)
		*x1 = res.a1;

	return (long)res.a0;
}

static long pkvm_g2g_share_revoke(u64 handle)
{
	return pkvm_g2g_share_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_REVOKE_FUNC_ID,
				   handle, 0, 0, 0, 0, 0, 0, NULL);
}

static long pkvm_g2g_share_release(u64 handle)
{
	return pkvm_g2g_share_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_RELEASE_FUNC_ID,
				   handle, 0, 0, 0, 0, 0, 0, NULL);
}

static void pkvm_g2g_share_error(void)
{
	pkvm_g2g_ping.sh_errors++;
}

static void pkvm_g2g_share_send(struct pkvm_g2g_ping_peer *p, u64 type,
				u64 handle, u64 arg)
{
	if (p->q_len == PKVM_G2G_SHARE_QUEUE) {
		pr_err("pkvm-g2g: share: message queue to incarnation %llu full, dropping one\n",
		       p->incarnation);
		pkvm_g2g_share_error();
		return;
	}
	p->q[p->q_len][0] = type;
	p->q[p->q_len][1] = handle;
	p->q[p->q_len][2] = arg;
	p->q_len++;
}

/* Deposit what is owed to @p, in order; stop at the first BUSY. */
static void pkvm_g2g_share_flush(struct pkvm_g2g_ping_peer *p)
{
	struct arm_smccc_1_2_regs args, res;
	long ret;

	/* The pages are written before the message that tells the peer to look. */
	smp_mb();

	while (p->q_len && !p->gone) {
		args = (struct arm_smccc_1_2_regs) {
			.a0 = ARM_SMCCC_VENDOR_HYP_KVM_GUEST_MSG_SEND_FUNC_ID,
			.a1 = p->lo, .a2 = p->hi, .a3 = p->incarnation, .a4 = 0,
			.a5 = p->q[0][0], .a6 = p->q[0][1], .a7 = p->q[0][2],
			.a8 = PKVM_G2G_SHARE_TAG,
		};
		arm_smccc_1_2_hvc(&args, &res);
		ret = (long)res.a0;

		if (ret == ARM_SMCCC_KVM_G2G_MSG_BUSY)
			return;
		if (ret == ARM_SMCCC_KVM_G2G_MSG_NO_PEER) {
			pkvm_g2g_ping_gone(p);
			pr_info("pkvm-g2g: share: incarnation %llu is gone (NO_PEER)\n",
				p->incarnation);
			return;
		}
		if (ret != SMCCC_RET_SUCCESS) {
			pr_err("pkvm-g2g: share: SEND to incarnation %llu failed: x0=%ld (%s)\n",
			       p->incarnation, ret, pkvm_g2g_msg_ret_str(ret));
			pkvm_g2g_share_error();
		}
		memmove(p->q[0], p->q[1], sizeof(p->q[0]) * (p->q_len - 1));
		p->q_len--;
	}
}

/* The IPA of window @slot: 2 MiB windows downward from the top of the IPA space. */
static u64 pkvm_g2g_share_window(unsigned int slot)
{
	u64 mmfr0 = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	unsigned int parange, bits;

	parange = cpuid_feature_extract_unsigned_field(mmfr0,
						       ID_AA64MMFR0_EL1_PARANGE_SHIFT);
	bits = id_aa64mmfr0_parange_to_phys_shift(parange);
	bits = min_t(unsigned int, bits, PHYS_MASK_SHIFT);
	return BIT_ULL(bits) - (u64)(slot + 1) * PMD_SIZE;
}

/* Forget the window @p's share was mapped at. It is never touched again. */
static void pkvm_g2g_share_unmap(struct pkvm_g2g_ping_peer *p)
{
	unsigned int slot;

	if (!p->brw_window)
		return;

	slot = p->brw_window - 1;
	if (p->brw_va)
		memunmap(p->brw_va);
	release_mem_region(pkvm_g2g_share_window(slot),
			   PKVM_G2G_SHARE_PAGES * PAGE_SIZE);
	clear_bit(slot, &pkvm_g2g_ping.share_windows);
	p->brw_window = 0;
	p->brw_va = NULL;
}

/* Owner: write a fresh round into the pages and offer them to @p. */
static void pkvm_g2g_share_offer(struct pkvm_g2g_ping_peer *p)
{
	struct pkvm_g2g_share_page *pg = page_address(p->own_pages);
	u64 *pg1 = page_address(p->own_pages) + PAGE_SIZE;
	u64 handle = 0;
	long ret;

	p->own_nonce = get_random_u64();
	memset(pg, 0, sizeof(*pg));
	pg->magic = PKVM_G2G_SHARE_MAGIC;
	pg->round = p->own_round;
	pg->nonce = p->own_nonce;
	pg->check = ~p->own_nonce;
	pg1[0] = p->own_nonce ^ PKVM_G2G_SHARE_SALT;
	pg1[1] = 0;

	ret = pkvm_g2g_share_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_OFFER_FUNC_ID,
				  page_to_phys(p->own_pages), PKVM_G2G_SHARE_PAGES,
				  p->lo, p->hi, p->incarnation, 0, 0, &handle);
	if (ret != SMCCC_RET_SUCCESS) {
		pr_err("pkvm-g2g: share: round %u: OFFER to incarnation %llu failed: x0=%ld (%s)\n",
		       p->own_round, p->incarnation, ret,
		       pkvm_g2g_msg_ret_str(ret));
		pkvm_g2g_share_error();
		p->own_phase = PKVM_G2G_OWN_DONE;
		return;
	}

	p->own_handle = handle;
	p->own_phase = PKVM_G2G_OWN_OFFERED;
	pkvm_g2g_share_payload_log("round %u: offered %u pages at %#llx to incarnation %llu, nonce=%016llx\n",
				   p->own_round, PKVM_G2G_SHARE_PAGES,
				   (u64)page_to_phys(p->own_pages),
				   p->incarnation, p->own_nonce);
	pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_OFFERED, handle, p->own_round);
}

/* Owner: REVOKE, and free the pages only if EL2 gave them back. */
static bool pkvm_g2g_share_take_back(struct pkvm_g2g_ping_peer *p)
{
	long ret = pkvm_g2g_share_revoke(p->own_handle);

	if (ret != SMCCC_RET_SUCCESS) {
		pr_err("pkvm-g2g: share: REVOKE of the share with incarnation %llu gave x0=%ld (%s); keeping the pages\n",
		       p->incarnation, ret, pkvm_g2g_msg_ret_str(ret));
		pkvm_g2g_share_error();
		return false;
	}
	__free_pages(p->own_pages, 1);
	p->own_pages = NULL;
	return true;
}

static void pkvm_g2g_share_on_accepted(struct pkvm_g2g_ping_peer *p, u64 handle,
				       u64 round)
{
	struct pkvm_g2g_share_page *pg = page_address(p->own_pages);
	u64 *pg1 = page_address(p->own_pages) + PAGE_SIZE;
	u64 reply;
	long ret;

	if (p->own_phase != PKVM_G2G_OWN_OFFERED || handle != p->own_handle ||
	    round != p->own_round) {
		pr_err("pkvm-g2g: share: unexpected ACCEPTED (round %llu) from incarnation %llu\n",
		       round, p->incarnation);
		pkvm_g2g_share_error();
		return;
	}

	/*
	 * Read what the peer wrote only after its ACCEPTED, which it sent after
	 * writing; pairs with the smp_mb() in the peer's
	 * pkvm_g2g_share_flush().
	 */
	smp_mb();
	reply = READ_ONCE(pg->reply);
	if (READ_ONCE(pg->reply_magic) != PKVM_G2G_SHARE_REPLY ||
	    READ_ONCE(pg->echo) != p->own_nonce ||
	    READ_ONCE(pg->reply_check) != ~reply ||
	    READ_ONCE(pg1[1]) != (reply ^ PKVM_G2G_SHARE_SALT)) {
		pkvm_g2g_share_payload_log("round %u: BAD REPLY in our pages from incarnation %llu: %016llx %016llx %016llx %016llx %016llx, our nonce=%016llx\n",
					   p->own_round, p->incarnation,
					   pg->reply_magic, pg->echo, reply,
					   pg->reply_check, pg1[1], p->own_nonce);
		pkvm_g2g_share_error();
		if (pkvm_g2g_share_take_back(p))
			p->own_phase = PKVM_G2G_OWN_DONE;
		return;
	}

	pkvm_g2g_share_payload_log("round %u: incarnation %llu read nonce=%016llx in our pages and wrote reply nonce=%016llx (the host never mapped them)\n",
				   p->own_round, p->incarnation, p->own_nonce,
				   reply);
	pr_info("pkvm-g2g: share: round %u: data crossed both ways through %u shared pages with incarnation %llu\n",
		p->own_round, PKVM_G2G_SHARE_PAGES, p->incarnation);

	switch (p->own_round) {
	case 1:
		p->own_phase = PKVM_G2G_OWN_WAIT_RELEASE;
		pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_RELEASE_PLS, handle, 1);
		break;
	case 2:
		ret = pkvm_g2g_share_revoke(handle);
		if (ret != SMCCC_RET_SUCCESS) {
			pr_err("pkvm-g2g: share: round 2: REVOKE with the pages mapped by incarnation %llu gave x0=%ld (%s)\n",
			       p->incarnation, ret, pkvm_g2g_msg_ret_str(ret));
			pkvm_g2g_share_error();
			p->own_phase = PKVM_G2G_OWN_DONE;
			return;
		}
		pr_info("pkvm-g2g: share: round 2: REVOKE while incarnation %llu still mapped the pages: SUCCESS\n",
			p->incarnation);
		pkvm_g2g_ping.sh_r2++;
		pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_REVOKED, handle, 2);
		p->own_round = 3;
		pkvm_g2g_share_offer(p);
		break;
	default:
		p->own_phase = PKVM_G2G_OWN_HELD;
		pkvm_g2g_ping.sh_r3++;
		pr_info("pkvm-g2g: share: round 3: share with incarnation %llu left in place for EL2 to clean up when one of us dies\n",
			p->incarnation);
		break;
	}
}

static void pkvm_g2g_share_on_released(struct pkvm_g2g_ping_peer *p, u64 handle)
{
	u64 again = 0;
	long ret;

	if (p->own_phase != PKVM_G2G_OWN_WAIT_RELEASE || handle != p->own_handle) {
		pr_err("pkvm-g2g: share: unexpected RELEASED from incarnation %llu\n",
		       p->incarnation);
		pkvm_g2g_share_error();
		return;
	}

	ret = pkvm_g2g_share_revoke(handle);
	/* Exclusively ours again: offering them once more must work. */
	if (ret == SMCCC_RET_SUCCESS)
		ret = pkvm_g2g_share_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_OFFER_FUNC_ID,
					  page_to_phys(p->own_pages),
					  PKVM_G2G_SHARE_PAGES, p->lo, p->hi,
					  p->incarnation, 0, 0, &again);
	if (ret == SMCCC_RET_SUCCESS)
		ret = pkvm_g2g_share_revoke(again);
	if (ret != SMCCC_RET_SUCCESS) {
		pr_err("pkvm-g2g: share: round 1: REVOKE / re-OFFER / REVOKE after incarnation %llu released gave x0=%ld (%s)\n",
		       p->incarnation, ret, pkvm_g2g_msg_ret_str(ret));
		pkvm_g2g_share_error();
		p->own_phase = PKVM_G2G_OWN_DONE;
		return;
	}

	pr_info("pkvm-g2g: share: round 1: RELEASE by incarnation %llu, then REVOKE, re-OFFER, REVOKE: all SUCCESS\n",
		p->incarnation);
	pkvm_g2g_ping.sh_r1++;
	p->own_round = 2;
	pkvm_g2g_share_offer(p);
}

static void pkvm_g2g_share_on_failed(struct pkvm_g2g_ping_peer *p, u64 handle,
				     u64 arg)
{
	if (p->own_phase != PKVM_G2G_OWN_OFFERED || handle != p->own_handle) {
		pr_err("pkvm-g2g: share: unexpected FAILED from incarnation %llu\n",
		       p->incarnation);
		pkvm_g2g_share_error();
		return;
	}

	pr_err("pkvm-g2g: share: round %u: incarnation %llu could not take our pages (step %llu)\n",
	       p->own_round, p->incarnation, arg >> 8);
	pkvm_g2g_share_error();
	if (pkvm_g2g_share_take_back(p))
		p->own_phase = PKVM_G2G_OWN_DONE;
}

/* Borrower: take the pages the peer offered, check them, answer in them. */
static void pkvm_g2g_share_on_offered(struct pkvm_g2g_ping_peer *p, u64 handle,
				      u64 round)
{
	struct pkvm_g2g_share_page *pg;
	u64 ipa, flags, reply, nonce, *pg1;
	unsigned int slot;
	long ret;

	if (p->brw_window) {
		pr_err("pkvm-g2g: share: incarnation %llu offered round %llu while round %u is still mapped\n",
		       p->incarnation, round, p->brw_round);
		pkvm_g2g_share_error();
		pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_FAILED, handle, round | (1 << 8));
		return;
	}

	slot = find_first_zero_bit(&pkvm_g2g_ping.share_windows, PKVM_G2G_SHARE_SLOTS);
	ipa = slot < PKVM_G2G_SHARE_SLOTS ? pkvm_g2g_share_window(slot) : 0;
	if (!ipa || !request_mem_region(ipa, PKVM_G2G_SHARE_PAGES * PAGE_SIZE,
					"pkvm-g2g-share")) {
		pr_err("pkvm-g2g: share: no free window for incarnation %llu's pages (slot %u)\n",
		       p->incarnation, slot);
		pkvm_g2g_share_error();
		pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_FAILED, handle, round | (2 << 8));
		return;
	}

	ret = pkvm_g2g_share_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_SHARE_ACCEPT_FUNC_ID,
				  ipa, PKVM_G2G_SHARE_PAGES, p->lo, p->hi,
				  p->incarnation, handle, 0, &flags);
	if (ret != SMCCC_RET_SUCCESS) {
		release_mem_region(ipa, PKVM_G2G_SHARE_PAGES * PAGE_SIZE);
		pr_err("pkvm-g2g: share: round %llu: ACCEPT of incarnation %llu's pages at %#llx gave x0=%ld (%s)\n",
		       round, p->incarnation, ipa, ret, pkvm_g2g_msg_ret_str(ret));
		pkvm_g2g_share_error();
		pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_FAILED, handle, round | (3 << 8));
		return;
	}

	set_bit(slot, &pkvm_g2g_ping.share_windows);
	p->brw_window = slot + 1;
	p->brw_handle = handle;
	p->brw_round = round;
	p->brw_va = memremap(ipa, PKVM_G2G_SHARE_PAGES * PAGE_SIZE, MEMREMAP_WB);
	if (!p->brw_va) {
		pr_err("pkvm-g2g: share: memremap of window %#llx failed\n", ipa);
		pkvm_g2g_share_error();
		pkvm_g2g_share_unmap(p);
		pkvm_g2g_share_release(handle);
		pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_FAILED, handle, round | (4 << 8));
		return;
	}

	/*
	 * Read what the owner wrote only after its OFFERED, which it sent after
	 * writing; pairs with the smp_mb() in the owner's
	 * pkvm_g2g_share_flush().
	 */
	smp_mb();
	pg = p->brw_va;
	pg1 = p->brw_va + PAGE_SIZE;
	nonce = READ_ONCE(pg->nonce);
	if (READ_ONCE(pg->magic) != PKVM_G2G_SHARE_MAGIC ||
	    READ_ONCE(pg->round) != round || READ_ONCE(pg->check) != ~nonce ||
	    READ_ONCE(pg1[0]) != (nonce ^ PKVM_G2G_SHARE_SALT)) {
		pkvm_g2g_share_payload_log("round %llu: BAD OFFER in incarnation %llu's pages: %016llx %016llx %016llx %016llx %016llx\n",
					   round, p->incarnation, pg->magic,
					   pg->round, nonce, pg->check, pg1[0]);
		pkvm_g2g_share_error();
		pkvm_g2g_share_unmap(p);
		pkvm_g2g_share_release(handle);
		pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_FAILED, handle, round | (5 << 8));
		return;
	}

	reply = get_random_u64();
	WRITE_ONCE(pg->reply_magic, PKVM_G2G_SHARE_REPLY);
	WRITE_ONCE(pg->echo, nonce);
	WRITE_ONCE(pg->reply, reply);
	WRITE_ONCE(pg->reply_check, ~reply);
	WRITE_ONCE(pg1[1], reply ^ PKVM_G2G_SHARE_SALT);

	pkvm_g2g_share_payload_log("round %llu: borrowed %u pages from incarnation %llu at %#llx%s: read nonce=%016llx, wrote reply nonce=%016llx\n",
				   round, PKVM_G2G_SHARE_PAGES, p->incarnation,
				   ipa, flags & ARM_SMCCC_KVM_G2G_SHARE_RO ? " (read-only)" : "",
				   nonce, reply);
	pkvm_g2g_ping.sh_borrowed++;
	pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_ACCEPTED, handle, round);
}

static void pkvm_g2g_share_on_release_pls(struct pkvm_g2g_ping_peer *p, u64 handle)
{
	long ret;

	if (!p->brw_window || handle != p->brw_handle) {
		pr_err("pkvm-g2g: share: unexpected RELEASE request from incarnation %llu\n",
		       p->incarnation);
		pkvm_g2g_share_error();
		return;
	}

	pkvm_g2g_share_unmap(p);
	ret = pkvm_g2g_share_release(handle);
	if (ret != SMCCC_RET_SUCCESS) {
		pr_err("pkvm-g2g: share: RELEASE of incarnation %llu's pages gave x0=%ld (%s)\n",
		       p->incarnation, ret, pkvm_g2g_msg_ret_str(ret));
		pkvm_g2g_share_error();
		return;
	}
	pkvm_g2g_share_send(p, PKVM_G2G_SHARE_MSG_RELEASED, handle, p->brw_round);
}

static void pkvm_g2g_share_on_revoked(struct pkvm_g2g_ping_peer *p, u64 handle)
{
	long ret;

	if (!p->brw_window || handle != p->brw_handle) {
		pr_err("pkvm-g2g: share: unexpected REVOKED from incarnation %llu\n",
		       p->incarnation);
		pkvm_g2g_share_error();
		return;
	}

	pkvm_g2g_share_unmap(p);
	ret = pkvm_g2g_share_release(handle);
	if (ret != ARM_SMCCC_KVM_G2G_SHARE_NO_SHARE) {
		pr_err("pkvm-g2g: share: round 2: RELEASE after incarnation %llu revoked gave x0=%ld (%s), wanted NO_SHARE: the revoke did not take the pages\n",
		       p->incarnation, ret, pkvm_g2g_msg_ret_str(ret));
		pkvm_g2g_share_error();
		return;
	}
	pr_info("pkvm-g2g: share: round 2: incarnation %llu revoked while we mapped its pages; RELEASE says NO_SHARE, as it must\n",
		p->incarnation);
}

/*
 * The ping also gives up on a peer after an unexpected SEND error - it marks
 * it stopped - and that peer may be alive. Withdraw from the shares with it -
 * REVOKE ours, RELEASE its - without claiming anything about EL2's cleanup,
 * which has not run.
 */
static void pkvm_g2g_share_withdraw(struct pkvm_g2g_ping_peer *p)
{
	long ret;

	pr_info("pkvm-g2g: share: stopped sharing with incarnation %llu, which is still alive, after an error\n",
		p->incarnation);

	if (p->own_phase == PKVM_G2G_OWN_OFFERED ||
	    p->own_phase == PKVM_G2G_OWN_WAIT_RELEASE ||
	    p->own_phase == PKVM_G2G_OWN_HELD)
		pkvm_g2g_share_take_back(p);
	p->own_phase = PKVM_G2G_OWN_DONE;

	if (p->brw_window) {
		pkvm_g2g_share_unmap(p);
		ret = pkvm_g2g_share_release(p->brw_handle);
		/* NO_SHARE: the owner revoked first, which is fine too. */
		if (ret != SMCCC_RET_SUCCESS &&
		    ret != ARM_SMCCC_KVM_G2G_SHARE_NO_SHARE) {
			pr_err("pkvm-g2g: share: RELEASE of live incarnation %llu's pages gave x0=%ld (%s)\n",
			       p->incarnation, ret, pkvm_g2g_msg_ret_str(ret));
			pkvm_g2g_share_error();
		}
	}
}

/*
 * The peer is gone, or the ping stopped sending to it: check, once, what EL2
 * did with the shares between us, or withdraw from them if it is alive.
 */
static void pkvm_g2g_share_peer_gone(struct pkvm_g2g_ping_peer *p)
{
	enum pkvm_g2g_own_phase phase = p->own_phase;
	u8 round = p->brw_round;
	struct arm_smccc_res res;
	long ret;

	if (p->share_checked)
		return;
	p->share_checked = true;
	p->q_len = 0;

	/* Dead means EL2 no longer knows the peer at this incarnation. */
	if (pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_PEER_LOOKUP_FUNC_ID,
			     p->lo, p->hi, &res) && res.a1 == p->incarnation) {
		pkvm_g2g_share_withdraw(p);
		return;
	}

	/* As owner: the dead borrower's mapping is gone; REVOKE must work. */
	if (phase == PKVM_G2G_OWN_OFFERED || phase == PKVM_G2G_OWN_WAIT_RELEASE ||
	    phase == PKVM_G2G_OWN_HELD) {
		if (pkvm_g2g_share_take_back(p) && phase == PKVM_G2G_OWN_HELD) {
			pr_info("pkvm-g2g: share: teardown: incarnation %llu died borrowing our pages; REVOKE: SUCCESS, they are ours alone again\n",
				p->incarnation);
			pkvm_g2g_ping.sh_teardown++;
		}
		p->own_phase = PKVM_G2G_OWN_DONE;
	}

	/* As borrower: EL2 took the pages when their owner died. */
	if (p->brw_window) {
		pkvm_g2g_share_unmap(p);
		ret = pkvm_g2g_share_release(p->brw_handle);
		if (ret != ARM_SMCCC_KVM_G2G_SHARE_NO_SHARE) {
			pr_err("pkvm-g2g: share: teardown: RELEASE of dead incarnation %llu's pages gave x0=%ld (%s), wanted NO_SHARE\n",
			       p->incarnation, ret, pkvm_g2g_msg_ret_str(ret));
			pkvm_g2g_share_error();
		} else if (round == 3) {
			pr_info("pkvm-g2g: share: teardown: incarnation %llu died while we borrowed its pages; RELEASE says NO_SHARE: EL2 had already taken them\n",
				p->incarnation);
			pkvm_g2g_ping.sh_teardown++;
		}
	}
}

static bool pkvm_g2g_share_is_msg(u64 type)
{
	return type == PKVM_G2G_SHARE_MSG_OFFERED ||
	       type == PKVM_G2G_SHARE_MSG_ACCEPTED ||
	       type == PKVM_G2G_SHARE_MSG_FAILED ||
	       type == PKVM_G2G_SHARE_MSG_RELEASE_PLS ||
	       type == PKVM_G2G_SHARE_MSG_RELEASED ||
	       type == PKVM_G2G_SHARE_MSG_REVOKED;
}

static void pkvm_g2g_share_handle(const struct arm_smccc_1_2_regs *m)
{
	u64 lo = m->a1, hi = m->a2, incarnation = m->a3;
	u64 type = m->a4, handle = m->a5, arg = m->a6, tag = m->a7;
	struct pkvm_g2g_ping_peer *p;

	if (tag != PKVM_G2G_SHARE_TAG || (!lo && !hi) || !incarnation) {
		pr_err("pkvm-g2g: share: MALFORMED message from incarnation %llu\n",
		       incarnation);
		pkvm_g2g_share_error();
		return;
	}

	p = pkvm_g2g_ping_add(lo, hi, incarnation, "found by its share message");
	if (!p || !pkvm_g2g_ping.share_on || p->gone || p->stopped)
		return;

	switch (type) {
	case PKVM_G2G_SHARE_MSG_OFFERED:
		pkvm_g2g_share_on_offered(p, handle, arg);
		break;
	case PKVM_G2G_SHARE_MSG_ACCEPTED:
		pkvm_g2g_share_on_accepted(p, handle, arg);
		break;
	case PKVM_G2G_SHARE_MSG_FAILED:
		pkvm_g2g_share_on_failed(p, handle, arg);
		break;
	case PKVM_G2G_SHARE_MSG_RELEASE_PLS:
		pkvm_g2g_share_on_release_pls(p, handle);
		break;
	case PKVM_G2G_SHARE_MSG_RELEASED:
		pkvm_g2g_share_on_released(p, handle);
		break;
	case PKVM_G2G_SHARE_MSG_REVOKED:
		pkvm_g2g_share_on_revoked(p, handle);
		break;
	}
}

static void pkvm_g2g_share_tick(void)
{
	unsigned int i;

	for (i = 0; i < PKVM_G2G_PING_MAX_PEERS; i++) {
		struct pkvm_g2g_ping_peer *p = &pkvm_g2g_ping.peers[i];

		if (!p->incarnation)
			continue;
		if (p->gone || p->stopped) {
			pkvm_g2g_share_peer_gone(p);
			continue;
		}

		/* Start the owner's rounds with every live peer, once. */
		if (p->own_phase == PKVM_G2G_OWN_IDLE && !p->own_round) {
			p->own_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, 1);
			if (!p->own_pages) {
				pr_err("pkvm-g2g: share: cannot allocate %u pages\n",
				       PKVM_G2G_SHARE_PAGES);
				pkvm_g2g_share_error();
				p->own_phase = PKVM_G2G_OWN_DONE;
				continue;
			}
			p->own_round = 1;
			pkvm_g2g_share_offer(p);
		}
		pkvm_g2g_share_flush(p);
	}
}

static void pkvm_g2g_share_finish(const char *why)
{
	const char *verdict;

	if (pkvm_g2g_ping.sh_errors)
		verdict = "FAIL";
	else if (!pkvm_g2g_ping.seen)
		verdict = "NO PEERS";
	else if (!pkvm_g2g_ping.sh_r1 || !pkvm_g2g_ping.sh_r2 ||
		 !pkvm_g2g_ping.sh_r3)
		verdict = "INCOMPLETE";
	else
		verdict = "PASS";

	pr_info("pkvm-g2g: share: %s after %u s: %s (%u peer(s), round 1 passed %u, round 2 passed %u, round 3 held %u, borrowed %u, teardown checks %u, %u error(s))\n",
		why, pkvm_g2g_ping.tick * PKVM_G2G_PING_PERIOD_MS / 1000,
		verdict, pkvm_g2g_ping.seen, pkvm_g2g_ping.sh_r1,
		pkvm_g2g_ping.sh_r2, pkvm_g2g_ping.sh_r3,
		pkvm_g2g_ping.sh_borrowed, pkvm_g2g_ping.sh_teardown,
		pkvm_g2g_ping.sh_errors);
}

static void pkvm_g2g_ping_tick(struct work_struct *work)
{
	struct arm_smccc_1_2_regs m;
	unsigned int n, last;
	long ret;

	for (n = 0; n < PKVM_G2G_PING_RECV_BUDGET; n++) {
		ret = pkvm_g2g_msg_recv(&m);
		if (ret == ARM_SMCCC_KVM_G2G_MSG_EMPTY) {
			pkvm_g2g_ping.drains++;
			break;
		}
		if (ret != SMCCC_RET_SUCCESS) {
			/*
			 * RECV with no flags can only be EMPTY or SUCCESS.
			 * Anything else means the call is not reaching the
			 * handler it should, and polling on will not fix it.
			 */
			pr_err("pkvm-g2g: ping: RECV failed: x0=%ld (%s)\n",
			       ret, pkvm_g2g_msg_ret_str(ret));
			pkvm_g2g_ping.errors++;
			memzero_explicit(&m, sizeof(m));
			pkvm_g2g_ping_finish("stopped");
			if (pkvm_g2g_ping.share_on)
				pkvm_g2g_share_finish("stopped");
			return;
		}
		if (pkvm_g2g_share_is_msg(m.a4))
			pkvm_g2g_share_handle(&m);
		else
			pkvm_g2g_ping_handle(&m);
	}
	memzero_explicit(&m, sizeof(m));

	if (!(pkvm_g2g_ping.tick % PKVM_G2G_PING_LOOKUP_EVERY))
		pkvm_g2g_ping_sweep();

	pkvm_g2g_ping_flush();
	if (pkvm_g2g_ping.share_on)
		pkvm_g2g_share_tick();

	last = pkvm_g2g_ping.share_on ? PKVM_G2G_SHARE_TICKS : PKVM_G2G_PING_TICKS;
	if (++pkvm_g2g_ping.tick == PKVM_G2G_PING_TICKS)
		pkvm_g2g_ping_finish("finished");
	if (pkvm_g2g_ping.share_on && pkvm_g2g_ping.tick == PKVM_G2G_SHARE_TICKS)
		pkvm_g2g_share_finish("finished");
	if (pkvm_g2g_ping.tick < last)
		schedule_delayed_work(&pkvm_g2g_ping.work,
				      msecs_to_jiffies(PKVM_G2G_PING_PERIOD_MS));
}

/*
 * The runtime ping and share test reads this VM's one-slot mailbox for its
 * ~15 minutes, and would take the messages of any user-space protocol that
 * sets itself up through the mailbox. arm_pkvm_guest.g2g_runtime_test=0 leaves
 * the mailbox to user space. The identity is registered either way.
 */
static bool g2g_runtime_test = true;
module_param(g2g_runtime_test, bool, 0444);
MODULE_PARM_DESC(g2g_runtime_test, "run the guest-to-guest ping and share test at boot (default 1)");

static int __init pkvm_g2g_ping_init(void)
{
	struct arm_smccc_res res;

	/* Only in a guest that pkvm_init_hyp_services() set up. */
	if (!pkvm_granule)
		return 0;

	if (!g2g_runtime_test) {
		pr_info("pkvm-g2g: runtime test off (arm_pkvm_guest.g2g_runtime_test=0)\n");
		return 0;
	}

	if (!kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_MSG_SEND) ||
	    !kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_MSG_RECV) ||
	    !kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_ID_SELF) ||
	    !kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_ID_PEER_LOOKUP)) {
		pr_info("pkvm-g2g: ping: message hypercalls not advertised, SKIP (hypervisor built without CONFIG_PKVM_GUEST_TO_GUEST, an EL2 self-check disabled guest-to-guest, or not a protected guest?)\n");
		return 0;
	}

	/* arm_smccc_1_2_hvc() is an HVC whatever the conduit; check it is one. */
	if (arm_smccc_1_1_get_conduit() != SMCCC_CONDUIT_HVC) {
		pr_info("pkvm-g2g: ping: SMCCC conduit is not HVC, SKIP\n");
		return 0;
	}

	if (!pkvm_g2g_id_call(ARM_SMCCC_VENDOR_HYP_KVM_GUEST_ID_SELF_FUNC_ID,
			      0, 0, &res)) {
		pr_err("pkvm-g2g: ping: GUEST_ID_SELF failed with x0=%ld, not starting\n",
		       (long)res.a0);
		return 0;
	}
	if (!res.a1 && !res.a2) {
		/* EL2 would refuse every SEND with NO_IDENTITY. */
		pr_err("pkvm-g2g: ping: this VM has no identity (did the identity probe fail?), not starting\n");
		return 0;
	}

	pkvm_g2g_ping.self_lo = res.a1;
	pkvm_g2g_ping.self_hi = res.a2;
	pkvm_g2g_ping.self_incarnation = res.a3;

	pkvm_g2g_ping.share_on =
		kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_SHARE_OFFER) &&
		kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_SHARE_ACCEPT) &&
		kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_SHARE_REVOKE) &&
		kvm_arm_hyp_service_available(ARM_SMCCC_KVM_FUNC_GUEST_SHARE_RELEASE);
	if (pkvm_g2g_ping.share_on)
		pr_info("pkvm-g2g: share: sharing with every peer for ~%u s\n",
			PKVM_G2G_SHARE_TICKS * PKVM_G2G_PING_PERIOD_MS / 1000);
	else
		pr_info("pkvm-g2g: share: sharing hypercalls not advertised, SKIP\n");

	pr_info("pkvm-g2g: ping: polling for ~%u s as incarnation %llu (identity 0x%llx:0x%llx)\n",
		PKVM_G2G_PING_TICKS * PKVM_G2G_PING_PERIOD_MS / 1000,
		pkvm_g2g_ping.self_incarnation, pkvm_g2g_ping.self_hi,
		pkvm_g2g_ping.self_lo);

	INIT_DELAYED_WORK(&pkvm_g2g_ping.work, pkvm_g2g_ping_tick);
	schedule_delayed_work(&pkvm_g2g_ping.work,
			      msecs_to_jiffies(PKVM_G2G_PING_PERIOD_MS));

	return 0;
}
late_initcall(pkvm_g2g_ping_init);

#endif /* CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST */
