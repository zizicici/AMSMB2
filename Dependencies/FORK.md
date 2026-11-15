# libsmb2 fork

`Dependencies/libsmb2` tracks the `master` branch of
[zizicici/libsmb2](https://github.com/zizicici/libsmb2) (see `branch` in
`.gitmodules`; `git submodule update --remote` follows it), not upstream
[sahlberg/libsmb2](https://github.com/sahlberg/libsmb2). `amsmb2-fork-N`
tags mark reviewed pins — currently `amsmb2-fork-13` — and master moves
only through them. The fork carries fixes that AMSMB2's teardown, timeout
and hostile-input handling depend on; the regression suites assume them.

## Divergence from upstream (base a52c157)

Compound callback lifetime (use-after-free fixes, ASan-guarded):

- `933b2a4` — compound callback state is reference-counted; every member
  callback drops a `pending` reference on every exit path, so any firing
  order completes the user callback exactly once. `smb2_timeout_pdus()`
  fires every member of an unsent chain, not just the head.
- `5789b33` — `smb2_queue_pdu()` fires all chain members before freeing on
  an encryption abort; allocation-failure paths free their callback state.
- `fd9b7dd` — `smb2_destroy_context()` sweeps open `smb2fh`/`smb2dir` from
  per-context lists, restoring its documented contract.
- `4086bb7` — the fstat compound applies the final attribute-tag at
  completion, so reordered replies still yield the right file type.
- `6c5987e`/`7c0bfcd` (revising `6576648`) — commands re-queued from inside
  an encryption-abort callback are parked and completed iteratively with a
  bounded budget (exhausted chains are dropped without firing; the earlier
  fire-before-free variant recursed without bound).
- `59d67cd` — the parking list honors the cancel-by-free contract;
  directory replies with overlapping NextEntryOffset chains can no longer
  amplify one heap allocation per few wire bytes (min 80-byte step).

Connection and socket handling:

- `c3ea44c` — a refused non-blocking connect on macOS (POLLHUP-only)
  completes with the real `SO_ERROR`; SHUTDOWN maps to EIO instead of EPERM;
  notify chains free iteratively; no `caller_frees_pdu` double-free.
- `cfa6e9d` — POLLHUP no longer discards replies already in the socket
  buffer; connect-stage POLLHUP tries the next resolved address; compound
  writev caps its iovec count; allocation failures complete the caller.

Hostile-input hardening:

- `e49ce3b` — forged Write replies claiming more bytes than sent are
  rejected; negotiated MaxRead/MaxWriteSize clamp to 8 MiB; NULL context
  tolerated in `smb2_fh_from_file_id()`; notify errors convert NT statuses.
- `94b02ad` — the Write reply clamp compares against the on-wire amount,
  not the original request.
- `8262429` — read/write count clamps are skipped when the negotiated size
  is zero; clamping to zero wrapped the unsigned `(count - 1)` credit
  computation into a multi-gigabyte request length.
- `bc5d2dd` — the credit balance is capped at `MAX_CREDITS`, never sent on
  when negative, and no longer multiplied into the request length when
  non-positive (a negative balance previously produced ~4 GiB requests:
  out-of-bounds write on read, memory disclosure on write).
- `fee8b0e` — the pwrite reply ceiling applies the encoder's
  non-multi-credit 64 KiB clamp (residual forged-reply window of
  `94b02ad`); `getrandom()` uses `GRND_NONBLOCK` so an unseeded CRNG at
  early boot falls through to `/dev/urandom` instead of hanging.
- `c2ca057` — `smb2_encode_create_request()` rejects names whose UTF-16
  form exceeds the 16-bit NameLength field (at 32,768 characters the
  wrapped length is zero and the request silently opened the share root);
  the server-side query-directory reply encoder checks its signed stride
  before the first iteration (was an unconditional do-while with a
  signed/unsigned comparison — heap over-read); two dead
  `output_buffer_length < 0` checks now test `(uint32_t)-1`; malformed
  directory replies report EIO instead of ENOMEM.

CSPRNG and platform config (`include/apple/config.h`, first include of
every translation unit — only compiler-predefined macros can be tested
here, and `<features.h>` must not be pulled in before the sources define
`_GNU_SOURCE`):

- `2078fae` — `HAVE_ARC4RANDOM_BUF` on Darwin (its glibc half never took
  effect; see `bc5d2dd`).
- `bc5d2dd` — Linux selects `getrandom` + `/dev/urandom` by predefined
  macros (`__linux__`); Android (bionic) uses `/dev/urandom` only.
- `fee8b0e` — the BSDs (OpenBSD/FreeBSD/NetBSD/DragonFly) join Darwin on
  `arc4random_buf` (FreeBSD ≥ 12).

Misc:

- merge of upstream `177a9de` — pre-1970 FILETIMEs decode to negative
  seconds.
- `bc5d2dd` — query-directory bounds check uses the correct
  `SMB2_QUERY_DIRECTORY_REPLY_SIZE` constant (same value as the
  QUERY_INFO one it used by mistake).

## Syncing with upstream

Merge `upstream` (sahlberg/libsmb2) into the fork's `master`, re-run the
guard in this repository (`make asan-test` — the compound-lifetime
regressions only abort under AddressSanitizer), then tag the new commit
and update the pin above and the submodule pointer. Upstream's
`libsmb2-6-branch` maintenance line carries client fixes that master
absorbs with different patch-ids: compare by content, not patch-id, and
if upstream ever merges our PR branches, prefer the fork's
implementations (they carry the regression tests here).

## Regression coverage in this repository

| Fix | Test |
|---|---|
| `933b2a4` compound lifetime | `SMB2LifetimeTests/test{Stat,Rename,Truncate,Readlink}CompoundPartialReplyTimeoutAbortsAllMembersCleanly` (ASan-only), `SMB2RegressionTests/test_StatWithSealButNoKeyFailsFast` |
| `c3ea44c` refused connect | `SMB2RegressionTests/test_ConnectRefusedSurfacesConnectionRefused` |
| `fd9b7dd` handle sweep | `SMB2RegressionTests/test_DestroyContextSweepsUnclosedHandles` |
| `4086bb7` fstat ordering | `SMB2FileStatTests/testFstatCompoundAppliesLateTagWhenInfoRepliesFirst` |
| `8262429` zero-size clamp | `SMB2RegressionTests/test_{Read,Write}WithZeroNegotiatedSize…` |
| `bc5d2dd` credit balance | `SMB2RegressionTests/test_NegativeCreditBalanceNeverInflatesQueuedRequests`, `test_CreditGrantsAreCappedAtMaxCredits` |
| `2078fae`/`bc5d2dd` CSPRNG | `SMB2RegressionTests/test_RandomBytesComeFromAStrongSource` |
| `fee8b0e` write clamp | `SMB2RegressionTests/test_WriteClampMatchesEncodeLayerForNonMultiCredit` |

All of the above are mutation-checked (each fix reverted on its own fails
its test). Known gaps, deliberate:

- The getrandom flags and the BSD branch have no automated test (blocking
  and other-BSD behavior are not reachable from the test hosts).
- `smb2_timeout_pdus()` fan-out: the compound-timeout cases pass with the
  function stubbed out (the Swift `timeout + 2` backstop produces the same
  ETIMEDOUT); `testFstatTagTimeoutFallsBack` does kill the stub.
- `test_DestroyContextSweepsUnclosedHandles` passes with the sweep loop
  removed (macOS has no LeakSanitizer); the sweep was verified once with a
  malloc-zone probe.
- `c2ca057`'s NameLength guard has no automated test (needs a mock that
  the suite does not carry).

## Known limitations (documented, not fixed)

Upstream behavior, unchanged in the fork:

- `nterror_to_errno()`: `STATUS_OBJECT_NAME_INVALID` → EIO (misleading for
  long-name rejections), `STATUS_LOGON_FAILURE` → ECONNREFUSED (auth
  failure misreported as connection refusal).
- The READ reply's DataOffset is read as 8 bits; a forged high byte is
  ignored (data is still bounded).
- A raw-API READ with length 0 skips the `data_length <= asked` check;
  AMSMB2 never issues one.
- `seek(.end)` uses the size snapshotted at open (no in-repo caller).
- A half-received PDU escapes `smb2_timeout_pdus()`; the Swift
  `timeout + 2` backstop covers it.
- No client-side SessionId/TreeId consistency check (signed sessions are
  covered by the signature, encrypted ones by the transform header; and
  signed sessions already verify the final session-setup response — the
  remaining gap is sessions the server leaves unsigned, where AMSMB2's
  `securityMode = [.enabled]` defers protection to the server).

Hostile-server surfaces, bounded but accepted:

- Credits are granted before the reply is matched or verified, so replays
  can fund the balance (capped at `MAX_CREDITS`; flow-control only).
- Names containing U+0000 are truncated by `String(cString:)` on the Swift
  side; `\` in server names is not escaped when joined into paths. The
  same truncation applies to URL user fields and to deserialized manager
  credentials (Codable accepts `\u0000` escapes).
- A single opendir that never returns NO_MORE_FILES accumulates pages in
  the C layer until the per-operation timeout.

AMSMB2-layer notes (recorded here for want of a better place):

- Recursive listing enforces two budgets (`recursiveListingMaxEntries` =
  1,000,000, `recursiveListingMaxPathUTF16Count` = 8,192) against
  hostile-server walk loops; the helper is unit-tested, the walk's
  invocation is not lockable without a lying-server mock.
- The full-parameter `SMB2FileHandle(path:…)` init trims before the
  separator swap (a leading `/` used to become a `\` Samba rejects); no
  automated lock.
- Paths without a leading `/` are share-root-relative; the empty path is
  the share root for reads but fails inconsistently per API. Neither is
  documented in the API doc comments.
- A change-notify reply with an empty output buffer (the "re-enumerate"
  signal) is swallowed as an empty change list.
- Once observed, never reproduced: a CLOSE with POSTQUERY_ATTRIB after
  DELETE_ON_CLOSE returned NAME_NOT_FOUND on Samba 4.23. If it recurs,
  drop that flag — the unlink/rmdir compound never consumes the attribute.
- The Apple build config has no accelerated AES backend: SMB3
  encryption/signing runs the portable C AES (~52 MB/s seal, ~100 MB/s
  signing on arm64). Fixing this needs CommonCrypto cryptor reuse or
  armv8 crypto intrinsics (cf. upstream issue #500).
