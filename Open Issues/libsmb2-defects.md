# Open Issues: libsmb2 defects outside the Swift layer's control

These defects live in the vendored `libsmb2` C library (`Dependencies/libsmb2`).
They were verified against the commit checked out in this fork (see
`Dependencies/libsmb2` submodule state) and **cannot be fixed from the Swift
layer**; they are tracked here for a future upstream/fork patch.

Related Swift-side hardening that *was* applied in this repository is listed
at the bottom.

---

## 1. [P1] Compound commands share one callback state that the last callback frees — out-of-order firing is a heap-use-after-free

**Where**

- `lib/libsmb2.c` — `struct stat_cb_data` (~line 2415) shared by
  `getinfo_cb_1` / `stat_attribute_tag_cb` / `getinfo_cb_2` / `getinfo_cb_3`,
  and the same pattern in `trunc_cb_1..3`, `new_name_cb_1..3`,
  `readlink_cb_1..3`, `symlink_cb_1..3`.
- Firing sites: `smb2_timeout_pdus()` (`lib/pdu.c` ~1237) and
  `smb2_destroy_context()` (`lib/init.c` ~461).

**Mechanism**

The compound PDUs (CREATE → QUERY/SETINFO/IOCTL → CLOSE) each hold a pointer
to one shared `*_cb_data`. Only the final callback (e.g. `getinfo_cb_3`)
invokes the user callback and frees the shared state; the earlier callbacks
unconditionally read (and conditionally write) `state->status`. That is only
safe if the callbacks fire in chain order. Two orderings break it:

1. **Half-received reply + PDU timeout.** Once a reply header matches, the PDU
   leaves the waitqueue and becomes `smb2->pdu` (`lib/socket.c` ~854/~904).
   If the compound response stalls mid-stream past the PDU timeout,
   `smb2_timeout_pdus()` fires the *still-queued later siblings* — the CLOSE
   callback runs, frees the shared state and completes the Swift callback —
   after which teardown fires the in-flight CREATE callback into freed
   memory. No server misbehavior is required, only a stalled connection.
2. **Out-of-order reply rejected at teardown.** The order check
   (`lib/socket.c` ~894) rejects a compound reply whose predecessor is still
   queued, but only *after* `smb2->pdu` was assigned. The read failure makes
   the Swift layer destroy the context; `smb2_destroy_context()` fires
   `smb2->pdu`'s callback *before* the waitqueue's, so the trailing CLOSE
   callback frees the shared state before the queued CREATE/QUERY callbacks
   run. (Requires a protocol-violating server.)

**Why the Swift layer cannot fix it**

The allocation, the shared pointers and the firing order all live in C. The
Swift wrapper can neither prevent the timeout path from firing the queued
siblings nor change the teardown order. Avoiding the timeout teardown only
defers the same UAF to the moment the half-received reply completes or the
context is eventually destroyed.

**Swift-reachable entry points** (all call into the affected C APIs):
`stat()` / `attributes()` / `exists()` etc. (`smb2_stat_async`),
`volumeFreeCapacity()`/`volumeTotalCapacity()` (`smb2_statvfs_async`),
`readlink()` (`smb2_readlink_async`), `rename()` (`smb2_rename_async`),
resize (`smb2_truncate_async`). `SMB2FileHandle.fstat()` already avoids the
C compound for exactly this reason (see its comment in `FileHandle.swift`).

**Suggested upstream fix** (verified in a working tree, then reverted to
keep this repository's changes Swift-only): give each shared `*_cb_data` a
`pending` count equal to the number of compound PDUs holding it; every
callback drops one reference on *every* exit path and the last one frees.
This makes any firing order safe without touching the state machine. For
`symlink`, the failure-path cleanup unlink transfers its reference to the
cleanup continuation.

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

## 3. [P3] `smb2_timeout_pdus()` fires only the head callback of an unsent compound chain

**Where**: `lib/pdu.c` `smb2_timeout_pdus()`, outqueue branch (~1242).

An unsent compound is still `next_compound`-chained; the timeout path calls
`pdu->cb` for the head only and then frees the whole chain. For the compound
families above that means the shared state is leaked (the final callback
never runs) and the user callback is never invoked. The Swift wrapper's
`timeout + 2` backstop converts this into a `ETIMEDOUT` error, so the
user-visible symptom is only a slower failure plus a small C-side leak.
`smb2_destroy_context()` already walks the chain and fires every member's
callback; the timeout path should do the same.

---

## Swift-side hardening already applied here

- `SMB2Manager.connectShare(name:encrypted:)` no longer reuses a live
  connection that was negotiated with a different encryption mode.
- `SMB2Directory` now copies all entries under a single context lock (and
  closes the directory there), so a mid-listing disconnect throws instead
  of silently returning a partial listing. Note: the underlying C
  `smb2dir` can still leak in that failure path — that is issue 2.

## Exposure note

The `wait_for_reply()` PDU-timeout teardown added in this branch (calling
`smb2_timeout_pdus()` and destroying the context on completion) is what
makes issues 1 and 3 reachable in practice; before it, the client-side
event loop never invoked `smb2_timeout_pdus()`. If issue 1 needs to be
neutralized before an upstream fix lands, removing that teardown (and
keeping only the `timeout + 2` backstop) is the available Swift-side lever,
at the cost of the stricter per-PDU timeout semantics.
