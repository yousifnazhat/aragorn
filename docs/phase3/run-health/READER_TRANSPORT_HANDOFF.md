# Guarded reader transport — reviewed implementation, first focused PASS

Published verified base: `95b676eca174ae5cb117fe778d3359f0e924b425` on
`codex/phase3-run-health`. Owner inspected branch/drafts, verified the checkpoint's
ED25519 signature/ancestry, fast-forwarded and read ownership-and-release-v2.md,
provider-release-v3.md, provider-release-v4.md and reader-transport-contract-v1.md.
Contract agreement was acknowledged to Root before implementation. The original
reader-response-plan.html remains untracked with unchanged SHA-256
`5d7eaf298adc1aed11434f83dbd3cb3e6506256bacfa62213035a97922830d23`.

The owner also verified and fast-forwarded its existing branch to signed correction
checkpoint `b4c0c2b411dab3d3575f05175eb04a3b58e4eee1`, then renewed-review checkpoint
`514ae19612cc30a0da786bb2bde979dcf9717d8b`, preserving every draft,
then read both reader-transport-source-review-v1.md/v2.md and amended contract Closure.
Both required corrections and Root's explicit fdinfo replay ceiling are accepted.
The first submitted implementation/test hashes and 27-method inventory remain in
that signed review; no test result existed for those bytes.

Only the three released new paths are written: the transport module, its mocked
test and this handoff. Existing response/acquisition/store/process/clock helpers,
independent reader-evidence verifier, schemas, registry, services and sources are
read-only. Root published the reviewed first schedule at verified signed checkpoint
`afb06c4eaf2074b4355fc467e052033a75a62a83`. Owner fast-forwarded its existing
branch, checked all 13 approved hashes and found the stage directory absent.
Scheduled status was NEW; the one selected execution then passed. No other stage
was executed, and no behavioral input changed after review.

## Implementation and contract boundary

ReaderListener owns the transferred notice writer and launch-target PIDFD before
metadata reads, then holds active time namespace and nofollow ancestor descriptors.
It validates pinned provisioning/epoch bytes, root real/effective/saved identity,
original main process/thread, reader accounts/capabilities/start/PIDFD, observer
umask/boot/clock, notice-pipe flags and both exact anonymous-pipe links.
The listener exists only at /run/aragorn-phase3-reader/challenge.sock. Absent-name,
parent custody, nonblocking/noninheritable mode and PASSCRED/PASSPIDFD precede bind;
only the new socket node gets chown/chmod. Named O_PATH identity is separate from
the socket descriptor's sockfs identity. No unlink, parent repair or umask/global
socket-timeout mutation exists. Unsupported protected chmod/chown/options refuse.

Every admitted request is permanently reserved in the bounded listener history,
has one next ordinal and one canonical LF-framed notice, and gets exactly one
nonblocking atomic write within PIPE_BUF and the original accept/request budgets.
Short/EAGAIN/interrupted writes terminate; there is no writer retry, accept-peer
search or failed-request recovery. The queue must be empty before admission.
Distinct successful requests may reuse one held listener and endpoint. Sequence
baselines cannot regress below the last accepted ACK.

Acceptance polls the listener and held launch PIDFD under the original BOOTTIME
deadline, then configures/checks one accepted connection and matches peer PID/UID/
GID. It rejects prequeued payload before exactly transferring to the unchanged
production acquire_owned_reader_response. That function alone owns connection
cleanup after entry. Actual returned challenge timing is checked against the
outer request budget; candidate reader records are quarantined on later refusal.
Complete TIMEOUT/cancellation and all owner-operation failures terminate the
listener and consume resources once in reverse acquisition order, preserving residue,
original owned/retention errors and every outer cleanup failure. Wrong-owner or
reentrant calls refuse without closing descriptors under an active operation.
Even known invalid requests before notice conservatively end the owner lifetime.

Ownership is recorded before metadata, and each handle's actual initial identity
is sealed independently. Cleanup detaches socket objects exactly once, validates
the returned number and current held identity, and calls raw os.close only for a
known matching handle. Unknown/read-failed/substituted handles and bad detach
results preserve cleanup failures without a close attempt or fake descriptor row.
Uncertain socket objects remain attached to the supervising exception/owner;
failed detach is an unresolved custody handoff, never permission to destroy or
retry that handle. Successfully detached objects cannot later destruct-close a
skipped replacement. PIDFD cleanup joins its target PID as well as inode metadata;
writer cleanup joins flags/noninheritability. Authorized pathname metadata pins
advance only after verified chown/chmod; sockfs identity never shares that pin.

After the initial process/namespace/pipe raw observations, each guard closes a
closing PIDFD association sample, then the final pipe bracket, and rechecks both active
held/named namespaces, directories, pathname, listener, all held descriptors,
pipe links/identities, PIDFD liveness, owner context and BOOTTIME before success.
Observations remain point samples, not a continuous-custody assertion. Final
namespace samples extend their process snapshot's actual time bracket; changed
PIDFD bytes use a partial reader snapshot. Normal ACCEPT uses 30 snapshots,
leaving space for a partial refusal within the frozen 32-entry inventory. No raw
proc sample follows that final pipe bracket: the held-handle pass reuses the acquired
PIDFD bytes. The point-sample ceiling expressly excludes recursive proc sampling or
an atomic/continuous snapshot; same-identity/flag replacement is not authenticated.

The new supplement is separate from frozen acquisition evidence. Each operation
has exact common keys, bounded raw process/boot/PIDFD observations, actual clock
brackets and structured socket/path/directory/pipe observations, with 32 snapshots,
64KiB raw budget, 128KiB record bound and 8KiB cleanup reserve. Missing observations
remain null. The existing owned evidence stays separate, never nested/base64 copied
into this record. All six authenticity/health/effect/RUN/Phase3/timing flags remain
literal false. Cleanup failures are preserved on the exception even when their
bounded metadata class-name list omits later entries and says incomplete.

Root explicitly accepted the frozen notice_pipe replay ceiling in the signed
source review: parsed full writer/reader flags and exact pipe links are retained,
but raw reader-FD3 fdinfo is absent. The code bounds/strictly parses that live raw
read without adding undeclared fields; independent replay cannot reconstruct the
original reader-FD3 fdinfo parse. Process/PIDFD/status/boot raw bytes remain retained
as specified. This agreement grants no transport authenticity or health authority.

## Actual stable closure and proposed stage

Static AST inspection parsed source/tests without importing or executing them and
traced every repository import, including the unchanged owning wrapper/store/leaf
and process/clock transitives. Exact repository closure: 13 files. No generated
source, external fixture or historical test import. Tests construct fresh fabricated
provision/epoch/socket/proc records. All socket/poll/fcntl/proc/file/clock/identity/
entropy/notice/provider primitives are mocked before invocation. No real socket,
pipe, proc read, PIDFD, protected write, subprocess, Tetragon or service is used.

```json
{
  "id": "native-run-reader-transport",
  "description": "Only mocked fixed reader listener/atomic notice/owning transfer and terminal custody; no live reader progress or authority",
  "tests": [
    "test_native_phase3_run_reader_transport"
  ],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_clock_domain.py",
    "src/aragorn/native_phase3_run_acquisition.py",
    "src/aragorn/native_phase3_run_reader_acquisition.py",
    "src/aragorn/native_phase3_run_reader_response.py",
    "src/aragorn/native_phase3_run_reader_store.py",
    "src/aragorn/native_phase3_run_reader_transport.py",
    "src/aragorn/oci_worker_protocol.py",
    "src/aragorn/runtime_action_broker.py",
    "src/aragorn/runtime_action_decision.py",
    "src/aragorn/runtime_action_observation_publisher.py",
    "src/aragorn/runtime_process_profile.py",
    "tests/test_native_phase3_run_reader_transport.py"
  ],
  "needs": [],
  "timeout_seconds": 30
}
```

Stable actual SHA-256 inventory (bare hex):

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
600d5da48f4a5b4702245936972c796162ca01b37c74f0ac46ea6c619ed82a7b  src/aragorn/native_phase3_clock_domain.py
80afdbcab0a4a076712b65db22b091b0a1276ae952ee276a76c1b83ffe06652e  src/aragorn/native_phase3_run_acquisition.py
66cce03e029441d01bd7de72f67da0bd927259a292be28e3e5555a0b0a353fe1  src/aragorn/native_phase3_run_reader_acquisition.py
769cdf49fc380f97048ebe01ca2227b71584b19e8715c76ca2629dee3037d51b  src/aragorn/native_phase3_run_reader_response.py
24dbd8cdba584a55e7a787952dfa5a12d96c8b040973537c569dd52f582aba98  src/aragorn/native_phase3_run_reader_store.py
609a5a32c33a4bb5ae0dec45eb6637b9d5b853e00797308244a92b1e86aa5fe0  src/aragorn/native_phase3_run_reader_transport.py
0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b  src/aragorn/oci_worker_protocol.py
94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21  src/aragorn/runtime_action_broker.py
3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d  src/aragorn/runtime_action_decision.py
288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90  src/aragorn/runtime_action_observation_publisher.py
a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68  src/aragorn/runtime_process_profile.py
e3528aed2fe94ceaf8b7f8bc4718aa9fce20e696fee47587031c754041b613a3  tests/test_native_phase3_run_reader_transport.py
```

Standard-library roots: __future__, base64, collections, contextlib, copy,
dataclasses, fcntl, hashlib, json, logging, math, os, pathlib, re, secrets, select,
socket, stat, struct, sys, threading, time, types, typing, unicodedata, unittest;
interpreter-owned transitives are part of the toolchain. The pipeline additionally
binds scripts/phase3_pipeline.py, requirements-worker.lock, interpreter and controlled
environment. Contract and this mutable handoff are review evidence outside the
behavioral fingerprint. No extra dependencies were inferred from reference docs.

30 focused test methods, reviewed and passed on the first scheduled execution:

- `test_open_fixed_endpoint_and_distinct_pathname_sockfs_custody`
- `test_constructor_input_pins_and_schema_refuse_before_socket_or_notice`
- `test_transferred_fd_ownership_is_recorded_once_before_validation`
- `test_platform_abi_root_and_main_thread_guards`
- `test_process_pidfd_boot_namespace_and_umask_readbacks`
- `test_notice_pipe_flags_anonymous_links_and_reader_target`
- `test_absent_socket_name_and_parent_custody_are_required`
- `test_constructor_partial_and_unsupported_syscall_cleanup_preserves_error`
- `test_pathname_and_listener_identity_substitution_during_creation`
- `test_multiple_successes_one_listener_atomic_notices_and_exact_transfer`
- `test_replayed_admission_regressed_sequence_and_capacity_do_not_write`
- `test_request_bounds_deadlines_and_pipe_buf_refuse_before_write`
- `test_unsolicited_connection_ends_lifetime_without_accept_or_notice`
- `test_notice_short_eagain_interruption_and_pipe_errors_never_retry`
- `test_notice_deadline_and_postwrite_custody_failures_are_terminal`
- `test_accept_eintr_and_eagain_stay_inside_one_notice_budget`
- `test_accept_timeout_reader_exit_poll_error_and_late_accept_refuse`
- `test_wrong_peer_or_prequeued_payload_closes_one_accepted_socket`
- `test_accepted_inherited_options_and_mode_must_read_back`
- `test_actual_late_issued_deadline_quarantines_candidate_reader`
- `test_timeout_returns_complete_record_after_terminal_cleanup`
- `test_postreturn_custody_failure_and_cleanup_failure_expose_no_reader`
- `test_cancel_and_wrong_notice_are_terminal_without_transfer`
- `test_owner_and_reentrant_cancellation_cannot_close_under_transfer`
- `test_real_owning_wrapper_issues_and_closes_with_mocked_store_leaf`
- `test_original_owned_retention_and_terminal_cleanup_failures_survive`
- `test_changed_descriptor_cleanup_skips_foreign_close_and_detaches_socket`
- `test_unknown_descriptor_and_detach_failures_preserve_unreleased_custody`
- `test_final_proc_read_mutations_quarantine_reader_and_end_lifetime`
- `test_evidence_inventory_raw_budget_and_clock_rollback`


The wiring case calls the real existing owning wrapper and its actual challenge
issuer with mocked store/leaf/OS boundaries; it checks challenge entropy, retention
capture, final store readback and exactly-once connection/store cleanup. Other cases
fabricate bounded owning returns/errors solely to isolate new transport behavior.
The reused wrapper source is fingerprinted; its historical test module is absent.
Test fixtures exercise multiple distinct admitted instances with identical request
contents, terminal timeout/notice uncertainty/cancellation, wrong credentials,
late issuance, post-return guard failures, raw budget overflow and original plus
retention/cleanup-error preservation. No fabricated fixture is runtime authority.

The correction cases exercise changed writer/socket inode and PIDFD-target cleanup,
initial/current unknown identity, wrong-number/failed detach, detached-object
finalizer safety, authorized chown/chmod pin advancement and post-transfer proc-read
mutations of writer/reader flags, pipe identities/links, namespaces, named directory,
pathname, listener, PIDFD association and clock. A specific late-reader-flags
subcase mutates FD3 flags during the second post-wrapper PIDFD fdinfo read (the
closing read); the later pipe sample must refuse. They assert terminal closure,
no second acquisition, no foreign close/fake close row, preserved partial failures,
and quarantined reader bytes. These are the necessary new correction checks;
no historical suite is included.

Actual scheduled commands in this owning worktree:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py status native-run-reader-transport
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-run-reader-transport
```

Status reported NEW with the fingerprint below; run returned PASS, exit 0.
Unittest stderr reports `Ran 30 tests in 0.880s` and `OK`.
Actual pre- and post-fingerprints match:
`sha256:b31f41624a6b096e7d009f690f26706c7531f7fd4c1a48a9eccac728ba26b97f`.
Actual result timestamps: started_at_ns=1791937161554937000,
finished_at_ns=1791937162596951000. Interpreter resolved to
`/opt/homebrew/Cellar/python@3.12/3.12.13_4/Frameworks/Python.framework/Versions/3.12/bin/python3.12`,
with `-S -B -m unittest test_native_phase3_run_reader_transport -v`.

Original evidence remains in this worktree (never copied):
`.aragorn/phase3-pipeline/native-run-reader-transport/b31f41624a6b096e7d009f690f26706c7531f7fd4c1a48a9eccac728ba26b97f/`.
Actual retained file SHA-256 values:

```text
e76b231daf6913e1917a6da1f96320f85d7b457c65fb2b5c7a7a530f9e8219e4  result.json
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  stdout.log
7adc69d524be79d8a37c4b1649b95676f05181edf609f53db1fc561840d3a926  stderr.log
9c039dd2d31058e6de33f1670dd6423f48e29470ff7cc930a2ddd658b88143fc  preflight.json
97509fcedc6b01df6943533e42645c9f0fd9aab970a6e117e70736b0caec4ab5  preflight-started.json
b4b5acd06b804a191f6ed1826a7ec2c243c609b69d14111ef9775891c45bb8ba  started.json
```

This is the first actual transport result. There is no failed attempt or retry to
hide; all prior evidence and original source-review refusals remain. Root reviewed
the exact source/closure and scheduled only this stage. The cache limitations are
DEVELOPER_SCHEDULING_CACHE_NOT_QUALIFICATION,
EXPLICIT_INPUTS_ONLY_NOT_COMPLETE_DEPENDENCY_DISCOVERY,
TRUSTED_REGISTERED_TESTS_NOT_A_SANDBOX and
NO_LIVE_CAPTURE_OR_FINAL_ACCEPTANCE_AUTOMATION. No historical rerun, broad suite,
cache copying, live effect or operational acceptance occurred.

## Out-of-scope providers and claim limits

Root owns protected provisioning/launcher/FD-copy inventory, actual admitted-request
source, real notice-consuming telemetry loop/checkpoint/loss/program/map paths,
independent transport replay and permanent supplemental retention, supervising
cancellation, IPC/broker serialization, service/staging/source identity and all
shared interfaces. No reader responder, heartbeat daemon, new sensor or alternate
service framework is added. Idle reader responsiveness does not prove upstream
bridge/sensor health. Missing/reset/lost telemetry fails closed at the later real
gates; no zero-loss, NOT_SUBMITTED, effect authority or missing-receipt inference
is manufactured here. Post-connect submitted/unknown ambiguity stays INDETERMINATE.

An actual fsync/readback/owned call can outlast policy deadlines. The outer API has
no post-transfer cancellation FD or hard-return guarantee. Only the actual challenge
deadline is joined to the outer budget; successful returned bytes cannot assert
full accepted-to-completed timing, deployed custody or meaningful loop progress.
Terminal closure preserves the socket node and permanent claims. A new admission
or constructor cannot silently recover this lifetime; root must design separately
authorized fault-scenario recovery. All operational/private-retention/cleanup holds
are unchanged. Original reader-evidence 14-check PASS855ae032 and its earlier
pre-stage refusal remain untouched, as do the original producer/store successes.
Reuse only when actual inputs/environment match; no refreshed result is claimed.

## Completed and pending checkpoint

Completed: released finite transport/notice/owning-transfer implementation, both
review corrections, exact stable closure and the first selected 30-method PASS.
The bounded transport leaf is implementation-ready at reviewed source/test bytes;
this does not close full RUN-01/RUN-02, the 15-entry RUN manifest or qualification.

Root reviewed the actual PASS, matching pre/post fingerprint, log digests and all
13 unchanged source pins, and confirmed exact three-path signed delivery. Pending:
coordinator integration, independent transport replay and the real shared providers
listed above. The owner stages exactly the three released paths, makes one
`git commit -S`, verifies with `git verify-commit HEAD` and inspects working-tree
state. The post-commit report supplies the original verified signed hash, paths,
evidence and limits for Root integration; no feature-branch push is needed. The original HTML remains outside the commit with its recorded hash.
No source/test changed after the PASS, so no check rerun is warranted.

1. Implement/integrate ready shared providers with only newly scheduled focused checks.
2. Wire full HTTP then DNS/destructive and all admission/RUN paths, cancellation,
   full timing and four actual paired tasks; real reader/loop/loss remain blockers.
3. Close the 48-entry path/consumer/source-custody ledger and publish a freeze candidate.
4. After separate operational release, collect 31 cases/100 actions/100 pairs on one
   deployment, independently replay, evaluate the existing gate and verify approved cleanup.
