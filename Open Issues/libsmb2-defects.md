# Open Issues: libsmb2 defects outside the Swift layer's control

These defects live in the vendored `libsmb2` C library (`Dependencies/libsmb2`).
The submodule now tracks the [zizicici/libsmb2](https://github.com/zizicici/libsmb2)
fork so that C-side fixes can land alongside the Swift package; issues marked
**fixed** below are already carried by the pinned submodule commit.

Related Swift-side hardening that *was* applied in this repository is listed
at the bottom.

---

## 1. ~~[P1] Compound commands share one callback state that the last callback frees~~ — FIXED in the fork

**Fix**: zizicici/libsmb2 branch `compound-cb-refcount`, carried by the pinned
submodule commit:

- `933b2a4` — every shared `*_cb_data` carries a `pending` count equal to the
  number of compound PDUs holding it; each member callback accumulates its
  status and drops one reference on **every** exit path, and the drop that
  reaches zero performs the completion (invoke the user callback, free the
  state). Any firing order — reply order, PDU timeout or context teardown —
  now completes exactly once. The symlink failure-path cleanup unlink
  transfers its reference to the cleanup continuation. `smb2_timeout_pdus()`
  (issue 3) is fixed in the same commit.
- `5789b33` — `smb2_queue_pdu()` fires every chain member before freeing on
  an encryption abort (the same invariant at queue time), and three
  allocation-failure paths release their callback state.
- `c3ea44c` — a refused connect on macOS (POLLHUP-only) now completes the
  pending connect callback with the real `SO_ERROR` errno like POLLERR does;
  `nterror_to_errno(SMB2_STATUS_SHUTDOWN)` maps to EIO instead of the
  meaningless EPERM; the notify chain is freed iteratively; and the
  encryption-abort path no longer double-frees `caller_frees_pdu` PDUs the
  synchronous wrappers own.

Regression coverage: `SMB2LifetimeTests.test{Stat,Rename,Truncate,Readlink}-
CompoundPartialReplyTimeoutAbortsAllMembersCleanly` reproduce the original
heap-use-after-free (`getinfo_cb_1` reading freed `stat_cb_data` from
`smb2_destroy_context`) on the pre-fix submodule under ASan and pass with the
fix. `SMB2RegressionTests.test_StatWithSealButNoKeyFailsFast` pins the
queue-time abort firing; `test_ConnectRefusedSurfacesConnectionRefused` pins
the refused-connect error. The compound-timeout cases only abort under ASan —
run `make asan-test`.

The original defect, kept for context:

- `lib/libsmb2.c` — `struct stat_cb_data` shared by
  `getinfo_cb_1` / `stat_attribute_tag_cb` / `getinfo_cb_2` / `getinfo_cb_3`,
  and the same pattern in `trunc_cb_1..3`, `new_name_cb_1..3`,
  `readlink_cb_1..3`, `symlink_cb_1..3`.
- Firing sites: `smb2_timeout_pdus()` (`lib/pdu.c`) and
  `smb2_destroy_context()` (`lib/init.c`).

**Mechanism**: only the final callback invoked the user callback and freed the
shared state; the earlier callbacks unconditionally read (and conditionally
wrote) `state->status`, which was only safe if the callbacks fired in chain
order. A half-received compound reply plus a PDU timeout fired the
still-queued siblings — the CLOSE callback ran, freed the shared state and
completed the Swift callback — after which teardown fired the in-flight
CREATE callback into freed memory. No server misbehavior was required, only a
stalled connection. `SMB2FileHandle.fstat()` additionally avoids the C
compound on the Swift side (see its comment in `FileHandle.swift`).

---

## 2. [P2] `smb2_destroy_context()` does not free open `smb2fh` / `smb2dir`, contradicting its documented contract

**Where**

- `include/smb2/libsmb2.h` ~193-201: "Any open *struct smb2fh* will
  automatically be freed … Any open *struct smb2dir* will automatically be
  freed."
- `lib/init.c` `smb2_destroy_context()` — no such tracking exists anywhere in
  `lib/` (no `fhs`/`dirs` lists; upstream's `smb2_free_all_fhs/dirs` were
  removed in this fork).

**Consequence**

Every successfully opened handle that outlives its context leaks: the Swift
`SMB2FileHandle.close()` nulls its Swift reference and then cannot issue the
C close (the context is gone), so the C `smb2fh` (96 bytes each; a
`smb2dir` plus all its cached entries for directories) is never freed.
Verified with a probe: 100 handles leaked 9600 bytes, all rooted at
`smb2_fh_from_file_id`. The exposure grows with every context teardown —
including the PDU-timeout teardown added on the Swift side.

**Why the Swift layer cannot fix it**

Once the context is destroyed no SMB request can be sent, and the leaked
memory belongs to C. The only correct release point is inside
`smb2_destroy_context()`.

**Suggested upstream fix**: restore per-context `fhs`/`dirs` lists (register
at allocation, remove in `free_smb2fh`/`free_smb2dir`) and sweep them in
`smb2_destroy_context()` after the PDU callbacks have drained — restoring
the documented upstream behavior.

---

## 3. ~~[P3] `smb2_timeout_pdus()` fires only the head callback of an unsent compound chain~~ — FIXED in the fork

**Fix**: same `compound-cb-refcount` branch. The timeout path now walks the
`next_compound` chain and fires every member's callback, exactly like
`smb2_destroy_context()` already did, before freeing the chain once.

The original defect, kept for context: an unsent compound was still
`next_compound`-chained; the timeout path called `pdu->cb` for the head only
and then freed the whole chain, so the shared state was leaked and the user
callback was never invoked.

---

## Swift-side hardening already applied here

- `SMB2Manager.connectShare(name:encrypted:)` no longer reuses a live
  connection that was negotiated with a different encryption mode.
- `SMB2Directory` now copies all entries under a single context lock (and
  closes the directory there), so a mid-listing disconnect throws instead
  of silently returning a partial listing. Note: the underlying C
  `smb2dir` can still leak in that failure path — that is issue 2.
- The `wait_for_reply()` PDU-timeout teardown (calling `smb2_timeout_pdus()`
  and destroying the context on completion) is safe to keep now that issues 1
  and 3 are fixed in the pinned submodule; it is what guarantees late reply
  bodies never reach Swift buffers that already left scope.
