# libsmb2 fork

`Dependencies/libsmb2` pins [zizicici/libsmb2](https://github.com/zizicici/libsmb2)
(tag `amsmb2-fork-12`), not upstream [sahlberg/libsmb2](https://github.com/sahlberg/libsmb2).
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
- `6c5987e`/`7c0bfcd` (revising the unbounded first cut `6576648`) —
  commands synchronously queued from inside an
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
- `2078fae` — `HAVE_ARC4RANDOM_BUF` is defined in the Apple config, so on
  Darwin `smb2_random_bytes()` stops falling back to `random()` seeded
  with ~32 bits of guessable material for the NTLMv2 client challenge,
  SMB 3.1.1 preauth salt, client GUID and per-PDU nonces. Its glibc half
  never took effect (see `bc5d2dd`).
- `8262429` — the read/write count clamp is skipped when the negotiated
  size is zero ("not negotiated"): clamping to zero made the unsigned
  `(count - 1)` credit computation wrap, and an observed 64-byte write
  went on the wire as a 64 KiB payload read past the caller's buffer (the
  read path wrote past it). Reachable via a hostile server negotiating
  MaxRead/MaxWriteSize = 0.
- `bc5d2dd` — the credit balance (an `int`) is capped at `MAX_CREDITS`
  when grants arrive, never sent on when negative, and no longer
  multiplied into the request length when non-positive. A server
  granting 65535 per reply walked it negative in ~32k replies;
  `count = credits * 65536` then produced a ~4 GiB read/write length
  that the server could answer into the caller's small buffer
  (out-of-bounds write, ASan-verified) or that shipped the caller's
  memory. A zero balance used to queue a zero-length read that looked
  like EOF once sent; it now asks for one credit's worth. The Linux
  CSPRNG is selected by compiler-predefined macros (`getrandom` +
  `/dev/urandom`): the `__GLIBC__` test `2078fae` used is always false
  because this config is the first include of every translation unit,
  and including `<features.h>` here would freeze the feature-test macros
  before the sources define `_GNU_SOURCE`. Also corrects a QUERY_INFO
  constant used in the query-directory bounds check (same value today).
- `fee8b0e` — the pwrite-side reply ceiling now applies the encoder's
  non-multi-credit 64 KiB clamp: without it a dialect-3.x connection
  without multi-credit kept the ceiling at the full request while the
  encoder truncated the payload, and a forged reply claiming the
  difference silently skipped bytes in sequential writes (the residual
  window of the `94b02ad` clamp; root cause is upstream's double clamp).
  getrandom() now uses GRND_NONBLOCK so an unseeded CRNG at early boot
  falls through to /dev/urandom instead of hanging the client (flags=0
  blocks, and blocking made the urandom fallback unreachable); a
  zero-return guard stops a broken wrapper from spinning. The BSDs
  (OpenBSD/FreeBSD/NetBSD/DragonFly) join Darwin on arc4random_buf.

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
- Credit balance: `SMB2RegressionTests/test_NegativeCreditBalanceNeverInflatesQueuedRequests`
  and `test_CreditGrantsAreCappedAtMaxCredits` (mutation-checked against
  `bc5d2dd`: clamp, send gate and cap each reverted on its own fail a
  case).
- CSPRNG: `SMB2RegressionTests/test_RandomBytesComeFromAStrongSource`
  asserts `smb2_random_bytes()` reports a strong source; it fails on
  Darwin without `2078fae` and on Linux (Docker) without `bc5d2dd`.
- Encoder-aligned write clamp:
  `SMB2RegressionTests/test_WriteClampMatchesEncodeLayerForNonMultiCredit`
  (mutation-checked: with the clamp removed the forged mid-window reply
  is accepted and the expected error never comes). The getrandom flags
  and the BSD branch have no automated test (blocking and other-BSD
  behavior are not reachable from the test hosts).

### Known weak locks

- The compound-timeout cases pass even with `smb2_timeout_pdus()` stubbed
  out: AMSMB2's `timeout + 2` Swift backstop produces the same ETIMEDOUT.
  They guard against the use-after-free under ASan, not the C fan-out.
- `test_DestroyContextSweepsUnclosedHandles` passes with the sweep loop
  removed (macOS has no LeakSanitizer); the sweep itself was verified
  once with the malloc-zone probe described above.

## Known upstream limitations (documented, not carried as patches)

- A READ issued with length 0 through the raw API skips the
  "data_length <= asked" check (`smb2-cmd-read.c`, `if (pdu->in.niov)`);
  the bytes land in an internal buffer, not the caller's. AMSMB2 never
  issues zero-length reads.
- The READ reply's DataOffset is read as 8 bits; a forged high byte is
  ignored (the data is still taken from the stream position, bounded).
- Hostile-server names: a FileName containing U+0000 is truncated by
  `String(cString:)` on the Swift side, and names containing `\` are not
  escaped when joined into paths. Both are name-confusion issues with a
  malicious server, not memory-safety ones. The same truncation applies
  to credentials taken from a URL (`smb://ad%00min:…` authenticates as
  "ad"); deserialized managers also trust user/password fields over the
  URL.
- Credits are granted into the balance before the reply is matched to a
  request and before the signature check, so a replayed or
  unknown-MessageId reply funds the balance (bounded by the MAX_CREDITS
  cap; flow-control semantics only, no memory-safety impact).
- The SMB 3.1.1 preauth-integrity chain is fail-closed, but the closure
  lands one PDU late: the final session-setup response is not verified
  even when the server signed it, so the first verified PDU is the
  tree-connect reply. Similarly, no client-side SessionId/TreeId
  consistency check exists (signed sessions are protected by the
  signature; plaintext sessions are inherently unprotected).
- Once observed (round 10; not reproduced since — four fresh Samba
  4.23.8 containers, two full suites and 60 targeted runs all pass): a
  CLOSE carrying SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB after DELETE_ON_CLOSE
  had removed the object returned STATUS_OBJECT_NAME_NOT_FOUND. If this
  recurs, that flag is the first suspect — the unlink/rmdir compound
  never consumes the attribute, so dropping it is a safe fix.

- A reply whose body never completes (half-received PDU in `smb2->pdu`)
  escapes `smb2_timeout_pdus`'s queue scan; AMSMB2's `timeout + 2`
  backstop covers its callers.
- The Apple build config has no accelerated AES backend (upstream only
  defines `HAVE_COMMONCRYPTO_COMMONCRYPTOR_H` via CMake, and that backend
  creates/releases a cryptor per 16-byte block anyway, cf. upstream issue
  #500): SMB3 encryption/signing runs the portable C AES (~52 MB/s seal,
  ~100 MB/s signing, measured on arm64). Fixing this needs CommonCrypto
  cryptor reuse or armv8 crypto intrinsics.
