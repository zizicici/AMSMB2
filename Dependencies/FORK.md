# libsmb2 fork

`Dependencies/libsmb2` tracks the `watermelon` branch of
[zizicici/libsmb2](https://github.com/zizicici/libsmb2) (see `branch` in
`.gitmodules`). The fork repo's `master` is a plain mirror of upstream
[sahlberg/libsmb2](https://github.com/sahlberg/libsmb2) and never
carries fork work; `amsmb2-fork-N` tags on `watermelon` mark reviewed
pins — currently `amsmb2-fork-15`.

## State after the November 2026 upstream sync

Upstream absorbed most of the fork's line through #510, #511, #512,
#513, #515 (NameLength wrap + reply-encoder stride), #516 (compound
callback lifetime), #517 (CSPRNG selection) and Ronnie's own follow-ups
(non-blocking getrandom; the queue_rejected disposition for commands
queued from an abort callback — the simple variant of what this fork
had prototyped as a parking list). The fork's parking-list prototype was
dropped in favor of his direction.

`master..watermelon` is now just the two open PRs (6 commits, strictly
ahead — no divergence):

- `pr-a` (upstream #514, open): reject forged write replies — the
  reply-count clamp, the on-wire-amount baseline and the pwrite-side
  encoder-aligned 64 KiB clamp, plus the negotiated-size 8 MiB cap and
  the notify errno conversion.
- `pr-b` (to submit after #514 merges; same clamp region): the credit
  balance bound and the zero-negotiated-size clamp skip.

Branch layout: `master` = upstream mirror; `pr-a`/`pr-b` = staging
branches for the open PRs (rebuild them, not `watermelon`, when a PR
needs changes); `watermelon` = the assembled pin line, rebuilt as
master + the open PR branches after each upstream sync. Historical
lines are preserved under the `amsmb2-fork-N` tags.

## Syncing with upstream

Fast-forward the fork's `master` mirror
(`git fetch upstream && git push origin upstream/master:master`), merge
`master` into `watermelon`, re-run the guard in this repository
(`make asan-test` — the compound-lifetime regressions only abort under
AddressSanitizer), then tag the merge on `watermelon` and update the
submodule pointer. When testing intermediate submodule commits, build
with `swift test --scratch-path <dir>`: a shared `.build` produces
stale results and drifting sanitizer reports across checkouts.

## Regression coverage in this repository

The compound-timeout, seal-abort, fstat-tag, refused-connect and
handle-sweep tests now guard upstream-merged code and stay as
regression walls. Fork-specific guards: `test_WriteClampMatchesEncodeLayerForNonMultiCredit`
and the zero-progress write test (PR #514 content — will move to
"upstream" once merged), `test_NegativeCreditBalanceNeverInflatesQueuedRequests`
and `test_CreditGrantsAreCappedAtMaxCredits` (pr-b content),
`test_RandomBytesComeFromAStrongSource` (upstream CSPRNG selection —
kept because it fails if a future config regression drops the define).

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
- The Apple build config has no accelerated AES backend: SMB3
  encryption/signing runs the portable C AES (~52 MB/s seal, ~100 MB/s
  signing on arm64). Fixing this needs CommonCrypto cryptor reuse or
  armv8 crypto intrinsics (cf. upstream issue #500).
