# libsmb2 fork

`Dependencies/libsmb2` tracks the `watermelon-2` branch of
[zizicici/libsmb2](https://github.com/zizicici/libsmb2) (see `branch` in
`.gitmodules`) — upstream master plus both staged lines (`pr-b` and
#521's AES). The fork repo's `master` is a plain mirror of upstream
[sahlberg/libsmb2](https://github.com/sahlberg/libsmb2) and never
carries fork work; `amsmb2-fork-N` tags on the pin line mark reviewed
pins — currently `amsmb2-fork-16` (on the pre-#521 line; the
`watermelon-2` tip gets its tag after the current review round).

## State after the November 2026 upstream sync

Upstream absorbed most of the fork's line through #510, #511, #512,
#513, #515 (NameLength wrap + reply-encoder stride), #516 (compound
callback lifetime), #517 (CSPRNG selection) and Ronnie's own follow-ups
(non-blocking getrandom; the queue_rejected disposition for commands
queued from an abort callback — the simple variant of what this fork
had prototyped as a parking list). The fork's parking-list prototype was
dropped in favor of his direction.

The write-reply clamps went upstream as #514 (merged), together with
the notify errno conversion. The pin line (`watermelon-2`) carries the
two staged lines on top of upstream master, each strictly ahead:

- `pr-b`: the credit balance bound and the zero-negotiated-size clamp
  skip (same clamp region as #514; submit once its follow-up window
  opens).
- `pr-aes` (upstream #521, open): AES-128 on the ARMv8 crypto
  extensions — the x86 AES-NI treatment ported to arm64, with a
  runtime `getauxval`/architectural dispatch and portable stubs where
  the extension is unavailable. A single commit on top of upstream
  master.

Branch layout: `master` = upstream mirror; `pr-aes`/`pr-b` = staging
branches for the open PRs (rebuild them, not the pin line, when a PR
needs changes); `watermelon-2` = the assembled pin line, rebuilt as
master + the open PR branches after each upstream sync (`watermelon`
was the pre-#521 pin line and stays as the pr-b-equivalent tip).
Historical lines are preserved under the `amsmb2-fork-N` tags.

## Syncing with upstream

Fast-forward the fork's `master` mirror
(`git fetch upstream && git push origin upstream/master:master`),
rebuild `watermelon-2` as master plus the open PR branches, re-run the
guard in this repository (`swift test` with a fresh `--scratch-path`,
plus `make asan-test` — the compound-lifetime regressions only abort
under AddressSanitizer), then tag the pin on `watermelon-2` and update
the submodule pointer. When testing intermediate submodule commits,
build with `swift test --scratch-path <dir>`: a shared `.build`
produces stale results and drifting sanitizer reports across
checkouts.

## Regression coverage in this repository

The compound-timeout, seal-abort, fstat-tag, refused-connect and
handle-sweep tests now guard upstream-merged code and stay as
regression walls. Fork-specific guards: `test_WriteClampMatchesEncodeLayerForNonMultiCredit`
and the zero-progress write test (upstream #514 content),
`test_NegativeCreditBalanceNeverInflatesQueuedRequests`
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
- The CCM parameter domain of the portable (and, being a mirror of it,
  the ARMv8) implementation is unchecked: `nlen >= 16` overflows the
  nonce staging buffers, `mlen > 16` reads past the tag, `mlen == 0`
  produces an empty authentication field, an `alen >= 65536` wraps its
  BE16 encoding, and `plen > 2 GiB` truncates the BE32 length. All
  in-library callers stay inside the safe domain (nonce 11, tag 16,
  bounded AAD/payload), so these are unreachable from AMSMB2; a future
  parameter-domain sweep for the portable path would cover both.
- Upstream's Apple build config has no accelerated AES backend: SMB3
  encryption/signing runs the portable C AES (~52 MB/s seal, ~100 MB/s
  signing on arm64; cf. upstream issue #500). The fork's answer is
  `pr-aes` / upstream #521 (ARMv8 crypto extensions, ~0.9 GB/s seal,
  ~2.4 GB/s signing); `watermelon` picks it up once it merges.
