# libsmb2 fork

`Dependencies/libsmb2` pins [zizicici/libsmb2](https://github.com/zizicici/libsmb2)
(tag `amsmb2-fork-2`), not upstream [sahlberg/libsmb2](https://github.com/sahlberg/libsmb2).
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
