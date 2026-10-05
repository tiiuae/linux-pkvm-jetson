.. SPDX-License-Identifier: GPL-2.0

=============================================
Guest-to-guest communication in protected KVM
=============================================

Without this feature, two protected VMs cannot share memory or exchange data
except through the host: every page has one owner, and every path between two
guests is a host-emulated device. ``CONFIG_PKVM_GUEST_TO_GUEST`` adds three
things, all decided at EL2:

- **guest identity**: a protected VM registers a name it chose itself and
  learns whether a name it was given belongs to a live protected peer;
- **messages**: four 64-bit words from one protected VM to another, in
  registers, through a one-slot mailbox at EL2;
- **page sharing**: an owner offers pages to a peer it names, the peer maps
  them into its own address space, and either side ends the share.

The host never gains access to a message or a shared page, and never decides
which VMs may talk to each other. It can still refuse to run either VM.

Configuration
=============

=======================================  ======  ====================================
Option                                   Kernel  Adds
=======================================  ======  ====================================
``CONFIG_PKVM_GUEST_TO_GUEST``           host    Calls 12 to 20 for protected guests,
                                                 the page states and teardown they
                                                 need, the EL2 self-checks and the
                                                 host's report of them.
``CONFIG_PKVM_GUEST_TO_GUEST``           guest   ``/dev/pkvm-g2g``, with
                                                 ``CONFIG_ARM_PKVM_GUEST``.
``CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST``  guest   A boot-time check of the identity
                                                 calls and a runtime message and
                                                 sharing test with every peer.
=======================================  ======  ====================================

Both options default to ``n`` and live under ``CONFIG_KVM``. With
``CONFIG_PKVM_GUEST_TO_GUEST=n`` none of calls 12 to 20 exists and the
generated code is unchanged.

The self-test registers a *predictable* identity so that two guests can find
each other without a channel between them. A host that predicts a name can
start a protected VM of its own that claims it first, so the self-test is for
testing only. It is the only code in the kernel that registers an identity.
``arm_pkvm_guest.g2g_runtime_test=0`` on the guest command line skips the
runtime part and leaves the mailbox to user space.

Hypercalls
==========

The calls are SMCCC vendor-hypervisor fast calls, SMC64, using the SMCCC v1.2
register convention. Only a protected guest can reach them, and none of them
exits to the host. The register-level contract of each call is documented next
to its function ID in ``include/linux/arm-smccc.h``.

==  ==========================  ========  ==================================
ID  Call                        Caller    Effect
==  ==========================  ========  ==================================
12  ``GUEST_SHARE_OFFER``       owner     Lend 1 to 512 pages to a named peer.
13  ``GUEST_SHARE_REVOKE``      owner     End a share; the pages are the
                                          owner's alone again.
14  ``GUEST_ID_REGISTER``       any       Claim an identity, once.
15  ``GUEST_ID_SELF``           any       Read back identity and incarnation.
16  ``GUEST_ID_PEER_LOOKUP``    any       Is this name a live protected peer?
17  ``GUEST_MSG_SEND``          sender    Deposit four words in a peer's slot.
18  ``GUEST_MSG_RECV``          receiver  Take the message from its own slot.
19  ``GUEST_SHARE_ACCEPT``      borrower  Map an offer into an empty IPA range.
20  ``GUEST_SHARE_RELEASE``     borrower  Unmap an accepted share; the offer
                                          stands.
==  ==========================  ========  ==================================

``SMCCC_RET_NOT_SUPPORTED`` (-1) is what every layer returns for a function ID
it does not recognise. The function-specific results are therefore outside -1
to -3: ``ARM_SMCCC_KVM_G2G_MSG_*`` are -64 to -67 and
``ARM_SMCCC_KVM_G2G_SHARE_*`` are -68 to -70. Transient conditions are never
returned: EL2 asks the host for the work (a block to split, a page to map, a
memcache to top up) and the call is executed again.

Guest identity
==============

A guest cannot name a peer by ``pkvm_handle_t``: the host allocates handles, so
naming by handle would let the host decide which VMs may read each other. No
call returns a handle.

An identity is a 128-bit value the VM chooses inside its own protected memory
and registers once. EL2 keeps it unique among live VMs and immutable for the
VM's lifetime. A second registration and a name a live VM holds get the same
error, so ``GUEST_ID_REGISTER`` is no oracle for other VMs' names. An identity
is a name, not a capability: what authorises a share is that each side names
the other.

Uniqueness is scoped to live VMs. Every VM therefore also gets an incarnation
number when it enters the VM table, never reused within a hypervisor boot. The
message and sharing calls take identity and incarnation together, so nothing
meant for one VM reaches a later VM that registered the same name.

EL2 guarantees that a name resolves to one live VM and that the host cannot
choose it. It does not guarantee that this VM is the one a guest meant: a guest
must learn its peer's name over a channel it trusts, never from the host.

Messages
========

``GUEST_MSG_SEND`` deposits four words into the receiver's slot in its
``struct pkvm_hyp_vm``; ``GUEST_MSG_RECV`` takes them, with the sender's
identity and incarnation as EL2 holds them. Only EL2 writes a slot, and only on
behalf of a protected VM.

The guarantees are confidentiality from the host, the sender's origin, no
overwrite (a full slot answers ``MSG_BUSY``), no delivery to the caller itself
and none into a dying VM. There is no guarantee of delivery, no notification
(the receiver polls), no fairness between senders, and no attestation of what
runs behind a name. ``SEND`` holds ``vm_table_lock`` for read from the lookup to
the deposit, and the mailbox lock is a leaf.

Page sharing
============

The owner names the borrower when it offers, the borrower names the owner when
it accepts, and EL2 requires both names to match. Pages stay the owner's
throughout and are never poisoned on these paths. The borrower maps them
read-write or read-only, never executable, and must be enrolled in MMIO guard,
so that an access after the share ends faults without showing the host any
data. Each share has one borrower. Shares live in a 64-entry table at EL2, at
most 16 per owner.

===========================  ======================  =======================  ==========
State                        Owner PTE               Borrower PTE             Host
===========================  ======================  =======================  ==========
offered                      ``SHARED_OWNED|G2G``    none                     ``NOPAGE``
accepted                     ``SHARED_OWNED|G2G``    ``SHARED_BORROWED|G2G``  ``G2G_LENT``
released, or borrower died   ``SHARED_OWNED|G2G``    none                     ``NOPAGE``
revoked                      ``OWNED``               none                     ``NOPAGE``
===========================  ======================  =======================  ==========

EL2 never holds two guest page-table locks at once. Every transition holds
``vm_table_lock`` for read and ``host_mmu.lock`` and takes one guest lock at a
time; with those two held, nothing can change an owner page that is in a share.
REVOKE flushes the borrower's VMID from the owner's vCPU, so
``enter_vmid_context()`` switches to the borrower's stage-2 for that flush.

Teardown is EL2's alone. ``__pkvm_start_teardown_vm()`` dismantles a VM's
shares in the step that marks it dying: a dying borrower's pages leave its
stage-2, and a dying owner's pages leave every borrower first, so the host's
ordinary reclaim later poisons them before the host gets them back.

Reclaim
=======

Stock reclaim assumes a page lives in one guest. A shared page breaks that in
both teardown orders, so reclaim is made decidable before any share can exist.

``struct hyp_page`` is unchanged. ``PKVM_PAGE_G2G``, in the unused software bit
SW2 of a guest stage-2 PTE, says that the counterparty of a SHARED state is a
peer VM. ``PKVM_PAGE_G2G_LENT`` and ``PKVM_PAGE_G2G_ORPHANED`` take two spare
encodings of ``hyp_page.__host_state``. Neither equals ``PKVM_NOPAGE``, so every
existing check for ``NOPAGE`` refuses a page in a guest-to-guest relationship.

``pkvm_g2g_reclaim_action()`` is a pure, total function of the two states. A
borrower reclaimed while the owner lives loses its mapping and the page is not
poisoned. The last holder to go poisons the page and gives it to the host. An
owner reclaimed while a borrower still maps the page is refused with
``-EOWNERDEAD``, and two states that disagree with ``-ENOTRECOVERABLE``.

For either refusal the host does not give the page back to its allocator: it
stops tracking the page and logs ``pkvm-g2g: EL2 kept the guest page``. The
page leaks on purpose, and teardown terminates instead of retrying forever or
reusing memory a borrower still maps.

Self-checks and failing closed
==============================

Three self-checks run once at EL2 init, before any guest exists: the reclaim
decisions (all 1024 state pairs), the mailbox (every fact set of SEND and RECV
and a sequence on a real mailbox) and sharing (every fact set of the four calls
and a lifecycle of the real transitions on two scratch VMs). They cannot print
or ``WARN`` at EL2, so the host reports them at boot::

  pkvm-g2g: EL2 reclaim matrix self-check: PASS (1024 pairs, 10 named cases, 0 failures)
  pkvm-g2g: EL2 mailbox self-check: PASS (1034 inputs, 35 named cases, 0 failures)
  pkvm-g2g: EL2 share self-check: PASS (196626 inputs, 33 named cases, 28 lifecycle steps, 0 failures)

Guest-to-guest is enabled (``pkvm_g2g_enabled``) only if all three ran and
passed. Otherwise none of calls 12 to 20 is advertised, each answers
``SMCCC_RET_NOT_SUPPORTED`` before any handler runs, reclaim takes the stock
path, and the host logs ``guest-to-guest DISABLED``.

The checks cover the decisions and the helpers that change state, not the call
handlers' marshalling of registers, which is exercised only end to end.

From user space
===============

A guest kernel with ``CONFIG_PKVM_GUEST_TO_GUEST`` and
``CONFIG_ARM_PKVM_GUEST`` has ``/dev/pkvm-g2g``, a root-only misc device with
one ioctl per call: ``SELF``, ``LOOKUP``, ``OFFER``, ``ACCEPT``, ``REVOKE``,
``RELEASE``, ``MSG_SEND`` and ``MSG_RECV``. The ABI and its errors are in
``include/uapi/linux/pkvm_g2g.h``. It registers only if EL2 advertises every
call.

The driver allocates an owner's pages and picks the borrower's window, a 2 MiB
slot below the top of the IPA space. User space maps either with ``mmap()``. A
share belongs to the file that made it and ends when the file is closed.
Memory is reused only after EL2 has confirmed the end and the last VMA mapping
the share has closed; if EL2 does not confirm, the memory is leaked. A borrower
whose owner revokes or dies gets ``SIGBUS`` on its next access.

The device registers no identity: ``MSG_SEND``, ``OFFER`` and ``ACCEPT`` fail
with ``EPERM`` until the VM has one.

Trust model
===========

- Only EL2 unmaps a borrower, changes host-side state or poisons a page.
- The host can do only what it could before: start a VM's teardown and reclaim
  a dying VM's pages, in any order. EL2 decides each outcome, and no sequence
  yields a live or unscrubbed shared page to the host.
- A host that refuses EL2's requests for work only stalls the caller.
- The guarantees bind CPU access through stage-2 and DMA through the SMMU. A
  device whose stream the SMMU does not translate (on this tree, the streams
  that need 1:1 identity-mapped guest RAM) reaches physical memory directly:
  through it, its VM can write a page it borrowed read-only, reach a page after
  the share ends, and reach pages it was never lent. EL2 treats identity-mapped
  RAM as ordinary guest memory, so sharing with such a VM works, but its shares
  are only as private as that VM is trusted.

What is left
============

- A way for a guest to register an identity of its own choosing, from the
  kernel or from user space through ``/dev/pkvm-g2g``, and a consent path
  built on it. Until then only ``CONFIG_PKVM_GUEST_TO_GUEST_SELFTEST``
  registers an identity, a predictable one that a host can claim first by
  starting a protected VM of its own, so guest-to-guest is for testing only.
- Unpredictable, attested identities.
- A borrower window that the VMM reserves and advertises in the device tree.
- An access after revoke that faults inside the guest without the host, and
  that a borrower's kernel survives: today a kernel access to a revoked window
  is fatal to the borrower.
- Device DMA into shared pages through the pvIOMMU, which refuses them today.
- More than one borrower per page.
- A run on hardware of sharing with a protected VM whose RAM is 1:1
  identity-mapped. The code treats such RAM as ordinary guest memory, so it is
  expected to work, apart from what an untranslated device can reach (see
  `Trust model`_).
