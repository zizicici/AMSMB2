# libsmb2 fork

`Dependencies/libsmb2` tracks the `watermelon` branch of
[zizicici/libsmb2](https://github.com/zizicici/libsmb2) (see `branch` in
`.gitmodules`) — upstream master plus the staged lines (pr-b, the
codex-round fixes and #521's AES). The fork repo's `master` is a plain mirror of upstream
[sahlberg/libsmb2](https://github.com/sahlberg/libsmb2) and never
carries fork work; `amsmb2-fork-N` tags on the pin line mark reviewed
pins — currently `amsmb2-fork-16`; the `watermelon` tip gets its tag
after the current round's PR split is confirmed.

## State after the November 2026 upstream sync

Upstream absorbed most of the fork's line through #510, #511, #512,
#515 (NameLength wrap + reply-encoder stride), #516 (compound
callback lifetime), #517 (CSPRNG selection) and Ronnie's own follow-ups
(non-blocking getrandom; the queue_rejected disposition for commands
queued from an abort callback — the simple variant of what this fork
had prototyped as a parking list). The fork's parking-list prototype was
dropped in favor of his direction.

The write-reply clamps went upstream as #514 (merged), together with
the notify errno conversion. The pin line (`watermelon`) carries the
staged lines on top of upstream master, each strictly ahead. A large
externally-authored batch (40+ commits as of the last review,
four-agent reviewed: core lifetime, notify/symlink, tools/crypto,
build systems — all verdicts PASS) sits on the standalone repo's local
watermelon ahead of the pushed/reviewed base `12b46cf`, NOT yet pushed
and still moving; it adds and will join the pin once pushed and
delta-reviewed: implicit-offset
I/O serialization with drain-before-close, POSIX-correct
out-of-range seek, open-cancellation detachment, server-side-copy
callback lifetime, sync connect/disconnect isolation (fixes the old
disconnect-returns-0-with-fd-open on the success path), notify
surviving interim replies (was a UAF under passthrough), directory
watch opens without host O_DIRECTORY, SET_INFO passthrough header
lengths, smb2-cp alias protection and EOF/short-write handling
(verified live: the old binary destroyed aliased sources and spun on
sysfs), an RFC 3610 + OpenSSL-compatible 64-bit AAD length encoder
(generalizing the fork's extended-encoding fix), embedded random
providers (Switch/3DS/ESP32/AmigaOS4; the weak random() fallback is
deleted), `smb2_queue_pdu_checked` with DCE/RPC propagation, native
MinGW builds, macOS cmake fixes (Kerberos link, public-header
self-containment), and Amiga/AROS SDK catch-up. The staged lines:

- `pr-b` (three commits): the zero-negotiated-size clamp skip and the
  credit balance bound (these two are the credit PR, same clamp region
  as #514), plus a separate hygiene commit fixing the query-directory
  reply overlap check constant (numerically a no-op today; submit
  separately so the credit PR stays single-purpose).
- five fixes from the codex review round: share-enum use-after-free
  when queueing fails a PDU synchronously, `rmdir()` deleting plain
  files (missing `SMB2_FILE_DIRECTORY_FILE`), the change-notify error
  branch leaking the server-side directory handle, random draws
  silently degrading to an unseeded `/dev/urandom` at early boot, and
  the DCE/RPC call tracking its pdu after a synchronously failed send.
- `pr-aes` (upstream #521, open): AES-128 on the ARMv8 crypto
  extensions — the x86 AES-NI treatment ported to arm64, with a
  runtime `getauxval`/architectural dispatch and portable stubs where
  the extension is unavailable. A single commit on top of upstream
  master.

Branch layout: `master` = upstream mirror; `pr-aes`/`pr-b`/the codex
fixes = staging commits for the open PRs (rebuild the staging branches,
not the pin line, when a PR needs changes); `watermelon` = the
assembled pin line, rebuilt as master + the staged lines after each
upstream sync. Historical lines are preserved under the
`amsmb2-fork-N` tags.

## Where libsmb2 work happens

All libsmb2 changes happen in the standalone checkout
`/Users/zici/Documents/GitHub/zizicici/libsmb2` (the review copy —
`watermelon` is checked out there and other reviewers look at it).
The `Dependencies/libsmb2` submodule directory is a read-only follower.
The local config points the submodule at the standalone repo
(`git config submodule.Dependencies/libsmb2.url <standalone path>`,
overriding the GitHub url in `.gitmodules`, which stays correct for
other clones), so `git submodule update --remote Dependencies/libsmb2`
picks up even unpushed commits from it directly; commit the moved
gitlink here afterwards. Never edit inside the submodule directory.

## Syncing with upstream

Fast-forward the fork's `master` mirror
(`git fetch upstream && git push origin upstream/master:master`),
rebuild `watermelon` as master plus the staged lines, re-run the
guard in this repository (`swift test` with a fresh `--scratch-path`,
plus `make asan-test` — the compound-lifetime regressions only abort
under AddressSanitizer), then tag the pin on `watermelon` and update the submodule
pointer. (`Dependencies/smb2-module/` resolves entirely through
symlinks into the submodule's headers — there are no copied headers
to refresh.) When testing intermediate submodule commits,
build with `swift test --scratch-path <dir>`: a shared `.build`
produces stale results and drifting sanitizer reports across
checkouts.

## Regression coverage in this repository

The compound-timeout, seal-abort, fstat-tag, refused-connect and
handle-sweep tests now guard upstream-merged code and stay as
regression walls. Fork-specific guards: `test_WriteClampMatchesEncodeLayerForNonMultiCredit`
and the zero-progress write test (upstream #514 content),
`test_NegativeCreditBalanceNeverInflatesQueuedRequests`
`test_CreditGrantsAreCappedAtMaxCredits` and the zero-negotiated-size
pair `test_ReadWithZeroNegotiatedSizeRequestsExactlyTheCallerLength` /
`test_WriteWithZeroNegotiatedSizeSendsExactlyTheCallerBytes` (pr-b
content), `test_RandomBytesComeFromAStrongSource` (upstream CSPRNG
selection — kept because it fails if a future config regression drops
the define), and `testSetAttributesMergeAndClearImmutable` /
`testStreamReadCompleteForSlowConsumer` (this round's Swift fixes:
attribute read-modify-write with flag preservation, and the pull-driven
read stream).

## Known limitations (documented, not fixed)

- The READ reply's DataOffset is read as 8 bits; a forged high byte is
  ignored (data is still bounded).
- A raw-API READ with length 0 skips the `data_length <= asked` check;
  AMSMB2 never issues one.
- `seek(.end)` uses the size snapshotted at open (no in-repo caller).
- No client-side SessionId/TreeId consistency check beyond what the
  signature and transform header already cover.
- Hostile-server names: a FileName containing U+0000 is truncated by
  `String(cString:)`; `\` in server names is not escaped when joined
  into paths; the same truncation applies to URL user fields and to
  deserialized manager credentials (Codable accepts `\u0000` escapes).
- `nterror_to_errno()`: `STATUS_OBJECT_NAME_INVALID` → EIO and
  `STATUS_LOGON_FAILURE` → ECONNREFUSED (both mislead; upstream
  mappings).
- Recursive listing budgets (`recursiveListingMaxEntries` /
  `recursiveListingMaxPathUTF16Count` in AMSMB2.swift) bound hostile
  walk loops; the helper is unit-tested, the walk's invocation is not
  lockable without a lying-server mock.
- Paths without a leading `/` are share-root-relative; the empty path
  is the share root for reads but fails inconsistently per API.
- A change-notify reply with an empty output buffer is swallowed as an
  empty change list.
- The CCM parameter domain of the portable (and, being a mirror of it,
  the ARMv8) implementation is unchecked: `nlen >= 16` overflows the
  nonce staging buffers, `mlen > 16` reads past the tag, `mlen == 0`
  produces an empty authentication field, and `plen > 2 GiB` truncates
  the BE32 length. All in-library callers stay inside the safe domain
  (nonce 11, tag 16, AAD fixed at the 32-byte transform header,
  bounded payload), so these are unreachable from AMSMB2; a future
  parameter-domain sweep for the portable path would cover both.
  (The RFC 3610 extended AAD length encoding from 65,280 bytes on was
  missing from both implementations and is fixed on the pin line —
  OpenSSL-verified across the boundary; the rest of the domain above
  is still open.)
- Task cancellation is not propagated into in-flight SMB2 commands
  (no `withTaskCancellationHandler` anywhere): a cancelled task's
  command still runs to completion or timeout, and with `timeout = 0`
  a stalled operation parks its continuation, a GCD thread and the
  open handle forever — including graceful `disconnectShare`. The
  default 60 s timeout bounds the damage everywhere else.
- Every operation holds the per-client recursive lock across its whole
  blocking poll wait, so concurrent operations on one connection occupy
  one GCD thread each (no cancellation, no priority inheritance; the
  Swift cooperative pool is never blocked). `connect(shareName:)`
  also publishes the client before the connect completes, so racing
  operations fail ENOTCONN during that window.
- Latent, unreachable-from-the-library seams, kept as notes:
  `async_await_pdu` still queues through the void `smb2_queue_pdu`
  rather than the new `smb2_queue_pdu_checked`, so a synchronously
  rejected PDU surfaces only via the timeout backstop (the C layer now
  propagates rejection; switching the Swift call site is future work);
  `monitorItem` on a symlink fails (its `.link` arm is dead, no
  open-as-reparse fallback); Codable defaults a missing `user` to ""
  where NSSecureCoding defaults to "guest"; `uploadItem` surfaces a
  CocoaError (not the documented POSIX one) for unreachable sources
  and silently ignores passwords embedded in URLs; a multi-backslash
  username like `a\b\c` silently degrades to guest;
  `AsyncThrowingStream(url:)` reads the whole local file synchronously
  in `init` (test-harness convenience; the read-side network stream
  is pull-driven since this round).
- C build surface: the CMake and SwiftPM shared libraries export the
  ARMv8 internals (like their other ~430 internal exports; autotools
  has a version script and does not), and on non-Apple non-Linux
  aarch64 targets (BSD/Windows/Android) the runtime probe returns 0,
  so those builds keep the portable path. Upstream's autotools also
  fails in libdcerpc under `--without-libkrb5` on a pristine
  checkout — pre-existing, not this fork's. Building with GCC >= 12 at
  `-O3 -Wall -Werror` trips `-Wmaybe-uninitialized` on the CMAC iov
  fast path — the same warning upstream's AES-NI twin produces, so a
  pre-existing pattern, not this fork's; AROS also has no CI job, and
  the only public AROS toolchain container cannot build the tree (its
  SDK lacks stdint.h/time.h/unistd.h entirely — broader than the old
  sys/unistd.h note).
- Destroying the context from inside a file-completion callback
  remains undefined (pre-existing class; the new implicit-offset queue
  changes the failure shape — the completion loop would walk a freed
  handle when more ops are queued — but the usage was never supported).
  Unlinking a directory symlink still returns EISDIR on stock Samba:
  the handle-based attribute-tag verification needs a tag-reporting
  server (Windows, or Samba with the smb_reparse VFS module); Samba
  answers the tag query without the REPARSE bit, so the capability is
  inert there. libsmb2 CI runs no test suite at all (no `make check`
  step), so the batch's new regression tests only run locally.
- Upstream's Apple build config has no accelerated AES backend: SMB3
  encryption/signing runs the portable C AES (~52 MB/s seal, ~100 MB/s
  signing on arm64; cf. upstream issue #500). The fork's answer is
  `pr-aes` / upstream #521 (ARMv8 crypto extensions, ~0.9 GB/s seal,
  ~2.4 GB/s signing), which the pin line already carries ahead of the
  merge.
