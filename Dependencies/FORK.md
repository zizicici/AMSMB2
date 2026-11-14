# libsmb2 fork

`Dependencies/libsmb2` pins [zizicici/libsmb2](https://github.com/zizicici/libsmb2)
(tag `amsmb2-fork-10`), not upstream [sahlberg/libsmb2](https://github.com/sahlberg/libsmb2).
The fork carries fixes that AMSMB2's teardown and timeout handling depend on;
the regression suites assume them.

## Divergence from upstream (base a52c157)

- `933b2a4` — Compound callback state (`stat`/`statvfs`/`fstat`, `truncate`,
  `rename`/`link`, `symlink`, `readlink`, `mkdir`/`rmdir`/`unlink` families)
  is reference-counted: every member callback drops a `pending` reference on
  every exit path, so any firing order (reply order, PDU timeout, context
  teardown) completes the user callback exactly once.
  `smb2_timeout_pdus()` fires every member of an unsent compound chain
  instead of just the head.
- `5789b33` — `smb2_queue_pdu()` fires all chain members before freeing on
  an encryption abort (same invariant at queue time); three allocation-
  failure paths free their callback state.
- `c3ea44c` — A refused non-blocking connect on macOS (POLLHUP-only)
  completes the pending connect callback with the real `SO_ERROR` errno;
  `nterror_to_errno(SMB2_STATUS_SHUTDOWN)` maps to EIO instead of a bogus
  EPERM; the notify chain is freed iteratively; encryption aborts no longer
  double-free `caller_frees_pdu` PDUs.
- `fd9b7dd` — `smb2_destroy_context()` sweeps open `smb2fh`/`smb2dir` on
  per-context lists, restoring its documented contract (verified with a
  malloc-zone probe: 100 unclosed handles, 98 blocks leaked before, none
  after).
- `4086bb7` — the fstat compound applies the final attribute-tag at
  completion, so a reordered (info-first) reply still yields the right
  file type. This is what lets AMSMB2 call `smb2_fstat_async()` directly
  instead of hand-rolling two sequential queries.
- `cfa6e9d` — POLLHUP no longer discards replies already sitting in the
  socket buffer (the peer answering and hanging up in one burst reported
  the operation as failed); the connect-stage POLLHUP completion tries
  the next resolved address like POLLERR/POLLOUT; the compound writev
  aggregation caps its iovec count; and all allocation-failure paths of
  the stat/truncate/rename compounds complete the caller with -ENOMEM.
- `6c5987e`/`7c0bfcd` — commands synchronously queued from inside an
  encryption-abort callback are parked and completed iteratively (a
  bounded budget stops a pathological re-queueing callback; the parked
  error string is no longer overwritten), and the POLLHUP input drain is
  skipped while still connecting.
- `59d67cd` — the parking list honors the documented cancel-by-free
  contract (`smb2_free_pdu` unlinks parked chains; the sync wrappers'
  pending check covers them; teardown drains them inside the main queue
  loop), and directory replies whose NextEntryOffset steps overlap
  entries (min 80-byte fixed part enforced) can no longer amplify one
  heap allocation per few wire bytes.
- merge of upstream `177a9de` — pre-1970 FILETIMEs decode to negative
  seconds, matching what the Swift decode layer already assumed.
- `e49ce3b` — a forged Write reply claiming more bytes than were sent is
  rejected (the count drove the file offset and caller progress);
  negotiated MaxRead/MaxWriteSize clamp to 8 MiB (forged values became
  caller-side buffer sizes); smb2_fh_from_file_id() tolerates a NULL
  context again; notify errors convert NT statuses through errno (teardown
  reported EIO, not a bogus EPERM).
- `94b02ad` — the Write count clamp compares against the on-wire amount
  (the count after credit/size reduction), not the original request, so a
  forged reply claiming bytes in that window can no longer silently skip
  data in sequential writes. Budget-exhausted chains are dropped **without**
  firing their callbacks: the earlier fire-before-free variant recursed
  without bound on retry-style callbacks (ASan measured a 27k-frame stack
  overflow); the bounded callback loss is the documented trade-off.
- `2078fae` — `HAVE_ARC4RANDOM_BUF` is defined in the Apple config
  (platform-gated: Darwin always, glibc ≥ 2.36), so `smb2_random_bytes()`
  stops falling back to `random()` seeded with ~32 bits of guessable
  material for the NTLMv2 client challenge, SMB 3.1.1 preauth salt, client
  GUID and per-PDU nonces.
- `8262429` — the read/write count clamp is skipped when the negotiated
  size is zero ("not negotiated"): clamping to zero made the unsigned
  `(count - 1)` credit computation wrap, and an observed 64-byte write
  went on the wire as a 64 KiB payload read past the caller's buffer (the
  read path wrote past it). Reachable via a hostile server negotiating
  MaxRead/MaxWriteSize = 0.

## Syncing with upstream

Rebase/merge `upstream` (sahlberg/libsmb2) into the fork's `master`, then
re-run the guard these patches exist for, in this repository:

    make asan-test

The compound-timeout regressions only abort under AddressSanitizer. After
syncing, tag the new commit, update the pin above and the submodule pointer.

## Regression coverage in this repository

- Compound timeout firing order:
  `SMB2LifetimeTests/test{Stat,Rename,Truncate,Readlink}CompoundPartialReplyTimeoutAbortsAllMembersCleanly`
  (ASan-only — they reproduce the original heap-use-after-free on the
  pre-fix submodule).
- Queue-time abort: `SMB2RegressionTests/test_StatWithSealButNoKeyFailsFast`.
- Refused connect: `SMB2RegressionTests/test_ConnectRefusedSurfacesConnectionRefused`.
- Handle sweep: `SMB2RegressionTests/test_DestroyContextSweepsUnclosedHandles`.
- fstat compound ordering:
  `SMB2FileStatTests/testFstatCompoundAppliesLateTagWhenInfoRepliesFirst`
  (mutation-checked against `4086bb7`).
- Zero negotiated size:
  `SMB2RegressionTests/test_{Read,Write}WithZeroNegotiatedSize…`
  (mutation-checked against `8262429`: reverted, the Length field on the
  wire is 65536 instead of 64).
- Not covered by an automated test: `2078fae` (CSPRNG selection is only
  visible in the binary — `nm` shows `_arc4random_buf` and no `_random`
  reference from `smb2_random_bytes`), and the two suites noted as
  backstop-masked below.

### Known weak locks

- The compound-timeout cases pass even with `smb2_timeout_pdus()` stubbed
  out: AMSMB2's `timeout + 2` Swift backstop produces the same ETIMEDOUT.
  They guard against the use-after-free under ASan, not the C fan-out.
- `test_DestroyContextSweepsUnclosedHandles` passes with the sweep loop
  removed (macOS has no LeakSanitizer); the sweep itself was verified
  once with the malloc-zone probe described above.

## Known upstream limitations (documented, not carried as patches)

- A reply whose body never completes (half-received PDU in `smb2->pdu`)
  escapes `smb2_timeout_pdus`'s queue scan; AMSMB2's `timeout + 2`
  backstop covers its callers.
- The Apple build config has no accelerated AES backend (upstream only
  defines `HAVE_COMMONCRYPTO_COMMONCRYPTOR_H` via CMake, and that backend
  creates/releases a cryptor per 16-byte block anyway, cf. upstream issue
  #500): SMB3 encryption/signing runs the portable C AES (~52 MB/s seal,
  ~100 MB/s signing, measured on arm64). Fixing this needs CommonCrypto
  cryptor reuse or armv8 crypto intrinsics.
