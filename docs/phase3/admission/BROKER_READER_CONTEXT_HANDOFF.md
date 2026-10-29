# Protected broker reader context — reviewed first-stage PASS

## Current delivery, 28 October 2026

Under the user's explicit coordinator catch-up request, the existing Admission
branch fast-forwarded from `722c4794c349acc022dd6a751344408af82f454e` to verified
signed `fc96aed3ca6018f06a866ca50caf20409a606bc0`. All unrelated drafts survived.
The twelve behavioral inputs, runner and worker lock exactly match the published
`broker-context-review-and-scheduling-v1.md` closure. No source correction or
registry change was needed for this delivery.

The owning checkout's status was NEW. Only `native-broker-reader-context` ran,
once, with `/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py`:
**67 tests passed**, exit 0; unittest reported 0.148 seconds. Pre/post fingerprint:
`sha256:befda78d72d7a2a0c35c2c05887bcf84825cdf8ef64a8750036903e98141bd12`.
Root reviewed the actual result, all 67 outcomes and the retained log hashes.

Original evidence remains in this Admission checkout, without cache copying:
`.aragorn/phase3-pipeline/native-broker-reader-context/befda78d72d7a2a0c35c2c05887bcf84825cdf8ef64a8750036903e98141bd12/`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| result.json | 811 | a8f89a74aa5680a95037e6af5971bc3e556a09fb2dff97e632ff0c2c32a27584 |
| stderr.log | 11634 | ebe4340fc3628ebe33e56ee5acd3a4fda119aa3b22c2d3beddb679418b31b53b |
| stdout.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| preflight-started.json | 347 | 081b240694b61fd1ef6beee0a9fd1478a7bc9a28a739ff86e4b0e48834fe1e37 |
| preflight.json | 174 | 4cdf5c99a84492b10dda5a4b32d7ce04ad7e7ed159ee818b2cc51626bb7629d4 |
| started.json | 211 | ce60c25e6b29316dc7ab057abd4fd01b79caa35e6c03dea3fba5587f2b2e6a52 |

This completed source/test/handoff batch is ready for its verified signed commit
and original-ancestry integration. The coordinator integration checkpoint records
that commit hash. This removes the Admission delivery dependency of the Root
broker-reader service; that service's own first focused stage is still pending.
No historical tests, service tests, live operations or qualification ran. The
modeled-OS result does not establish Linux custody, installed sources, full RUN
health, native composition or final acceptance. All existing false flags remain.

The sections below retain the original pre-execution source submission. Statements
there describing scheduling or results as pending are superseded by this section;
their source hashes, API contract and evidence limitations are unchanged.

## Original pre-execution source submission

Base: verified signed published `722c4794c349acc022dd6a751344408af82f454e`.
Admission fast-forwarded its existing branch without conflicts and acknowledged
ownership-v2, provider-release-v9 and broker-reader-context-contract-v1.
Existing `.lavish/` and `ADM03_NATIVE_MAP.md` drafts remain preserved.
Only the three assigned paths are new. Completed replay/policy-tamper sources,
shared providers, registry and original results are unchanged.

Requirement dependency: the reserved Root broker-reader service needs actual
protected context/BOUND/pending acquisition before the first HTTP reader guard.
This leaf supplies that bounded acquisition and independent prefix replay; the
authenticated receiving caller, bootstrap and full HTTP path remain Root-owned.
This is source readiness for review, not validated acquisition or qualification.
The bounded corrections in `broker-context-source-review-v1.md` are acknowledged.
That review was read from the coordinator checkout without editing it; the lane
remains on its verified 722c479 base. No later base or execution release is inferred.

## Stable hashes and actual complete import closure

SHA-256 below omits `sha256:`. Corrected source is 35458 bytes and test is 41989 bytes.
These twelve repository paths are the complete behavioral closure:

| Path | SHA-256 |
| --- | --- |
| `src/aragorn/native_phase3_broker_reader_context.py` | `53aedfa46cd67c5febcd4f5aef3ff54d41f1227cd4a5d780b42cea2fb37e9493` |
| `tests/test_native_phase3_broker_reader_context.py` | `7a898d3fa1906ca2caac6c37683a6a567e31b9f044dc50e2643f4aea4a566fd7` |
| `src/aragorn/__init__.py` | `4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01` |
| `src/aragorn/native_phase3_broker_reader_protocol.py` | `8d17e7930d2c560ade4b5c0fb5b539e00ecbfb3fb9f40d910d271dd42eb48007` |
| `src/aragorn/native_phase3_run_submission_verify.py` | `277f090094e8335850605c5ee793042cafc831764c24a136fddb1b277cf335a7` |
| `src/aragorn/runtime_http_action.py` | `823ffdcaf114bdc8bcd7ca43009f67d6bf46969d4a27856e104ceedc979b0ac5` |
| `src/aragorn/native_phase3_http_canary_contract.py` | `bcdd7b92d3ddaddb4ab38ce5cabcdbd68c7f87c79a6251f81c1bb225313946c2` |
| `src/aragorn/runtime_process_profile.py` | `a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68` |
| `src/aragorn/runtime_action_broker.py` | `94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21` |
| `src/aragorn/runtime_action_observation_publisher.py` | `288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90` |
| `src/aragorn/runtime_action_decision.py` | `3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d` |
| `src/aragorn/oci_worker_protocol.py` | `0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b` |

The leaf directly imports only the three allowed public dependency modules:
`validate_guard_request`, `verify_submission_transcript`, and HTTP
`validate_fixture_binding`, `effect_for_attempt`, `action_digests`.
The HTTP module imports the canary contract/process profile/canonical support;
the profile imports broker and observation publisher, which import action decision
and canonical support. Static inspection found no nested/dynamic imports in this
closure. The initializer imports nothing. Remaining imports are standard library.

Tests import the new module and stdlib only. All independent canonical expectation,
measurement, fixture, context, BOUND and pending bytes, proc/stat/status data,
namespace and directory identities are authored inline. Expected HTTP effect and
wire pins are independently authored from the fixed public HTTP contract. No
producer fixture, private parser, generated module or external fixture is imported.
Every native OS/socket boundary used by the public operation is modeled; no real
proc/file/socket operation is an intended test action. Real public codec, pure HTTP
derivation and independent replay functions run only within the future scheduled
test. The journal, session, measurement producer and their tests are not imported.

Pipeline automatically binds runner, worker lock, selected stage metadata,
toolchain/interpreter and environment. This mutable handoff, contracts and stage
outputs are review references, not behavioral inputs. A generated deployed HTTP
successor will need its own source closure; these pins are not installed authority.

## Source-review corrections

The original twelve-input/55-method review covered source
`c0f16a10c1ee4760c6a01261b2c646af5eb67711e5b6d46af80f5087d51a02ee`
and test `105acb27b97a285fe990da8856e2d23f26a3cc15418b77582821413133bb904b`.
It was a pre-execution source review, not an actual stage result. Only the two
behavioral inputs above changed; all ten dependency pins remain unchanged.

`read_fd` now refreshes readonly/nonblocking/noninheritability observations after
seek and timing work, then checks original Root owner, current borrowed alias and
actual held identity immediately before every `os.read`, including EOF reads.
The same final custody check precedes seek. A prior read cannot authorize a later
read, and the original bounded prefix survives refusal.

`close_fd` now completes flag and, for the PIDFD, association/liveness work before
the final original-owner/current-borrowed-alias/held-identity check. No flag,
clock or association observation intervenes between that final check and the
single consumed `os.close`. Failed checks preserve unresolved ownership and
cleanup exceptions; there is no close-by-number fallback or retry. These are
bounded local point checks, not atomic protection against a hostile Root thread
changing the descriptor table between syscalls.

## Acquisition and failure behavior

Public API matches the contract exactly. The module takes one process-local
attempt only after checking original imported PID, Root saved accounts, native
main thread and Linux little-endian credential ABI. Foreign/fork/thread/reentrant
calls acquire no ownership; an authorized failed attempt remains consumed.
There is no factory, truth callback, alternate path or recovery API.

It checks protected canonical input pins and exact schemas, the 8192-byte HTTP
measurement binding, source-basename inventory, fixed directory expectations and
public fixture/effect/action derivations. It preserves the original receipt and
wire/session deadlines, reserves the 100 ms challenge budget, checks uint overflow
and requires nondecreasing actual BOOTTIME samples before the fixed leaf deadline.

The socket remains exclusively borrowed: only fileno, metadata, flags, timeout
and getsockopt observations occur. Existing nonblocking/CLOEXEC/PASSCRED=1/
PASSPIDFD=0/SEQPACKET profile and exact kernel peer credentials are mandatory.
The leaf acquires one peer PIDFD, checks its unique positive fdinfo association,
identity after the proc read and nonblocking liveness poll, and holds self/broker
time namespace plus broker mount namespace handles. Actual process stat/status/
stat and boot bytes are retained and independently checked at both custody edges.

Five nofollow Root-view directories and the intentional broker proc-root magic
link plus its four nofollow descendants must match the same protected ancestry.
Broker mount namespace may differ from Root's. No setns, permission widening or
Root-view substitution replaces a missing/different broker view. Shared runtime
GID is supported, with distinct non-root broker UID and exact protected accounts.

The three fixed records open once as readonly/nonblocking/CLOEXEC/nofollow FDs.
They require distinct device/inode pairs, broker ownership, exact regular 0400
mode, one link and bounded positive sizes. Full held/named metadata is joined
through both directory views before/after bounded reads. Full peer/process/
namespace/ancestry guards bracket each record read and final reread. Directory
identity deliberately excludes size/link/timestamps; file identity includes
signed 64-bit mtime/ctime and exact size. Short EOF refuses even if remaining
bytes happen to form valid JSON.

The pending record binds the actual acquired context/action request, original
accepted timestamp, measurement plan, actual broker mount string and protected
grant/deployment/source/action pins. The actual retained context and BOUND bytes
go to public independent replay with no packets and no expected terminal. The
exact OPEN_PREFIX/UNKNOWN/false-flag result is required and retained. Context
authority is joined from acquired bytes and protected expectations; the incoming
context pin is never sufficient by itself.

Every new FD is tracked before fallible metadata checks. At most 32 are owned
simultaneously. Cleanup verifies held identity, readonly/noninheritability and
PIDFD association, then rechecks final custody after all flag/association work. Each close
attempt, including an ambiguous result or failed custody check, is consumed once.
An aliased, reused, unidentified or currently borrowed descriptor is never closed
by number as a fallback. Unresolved handles/errors remain on a strong owner
reference. The borrowed socket is never closed, detached, duplicated, transferred,
reconfigured or used for IO. The broker lock is never opened or acquired.

The final Root/socket guard and BOOTTIME sample follow all successful owned closes.
Cleanup failure, lost borrowed custody or a deadline crossed during cleanup
prohibits success. `BrokerReaderContextError` preserves original failure, up to32
actual cleanup exceptions, exactly the contract's partial observation fields and
an unresolved-owner reference. Actual bounded byte prefixes survive read failures.
No acquisition record is returned on failure; no file or partial journal is
created, removed, repaired, retried or archived.

## Focused mocked cases

The new test module has 67 methods through the public API. The original 55 cover:

- Actual context/BOUND/pending bytes, independent replay invocation and all exact
  UNKNOWN/seven-false outputs; unchanged shared GID and distinct broker mount view.
- Different broker-root/control views; wrong/partial credential ABI; PIDFD wrong
  association, exit, reuse, initial borrowed alias and changed borrowed fileno at
  cleanup; no close of uncertain/borrowed descriptors.
- Process start/status-vector/duplicate account, boot, time and mount changes;
  foreign thread/fork/nonroot/reentry and consumed failed attempts.
- Missing, partial, linked, symlink, wrong owner, oversized and short-EOF control
  files; both-view named substitution, reread metadata changes, distinct-inode
  requirement, legitimate directory-time/size/link changes and original raw retention.
- Immediate ownership on metadata failure, original read interruption plus cleanup
  error, ambiguous-close consumption, socket custody loss and actual socket flags.
- Protected fixture pin, duplicate input, fixed action payload, >4096/<=8192 binding,
  pending acceptance/request/mount/plan/source joins, context grant/effect and
  post-receipt/non-BOUND prefix refusal; consumer disagreement cannot promote health.
- Expired original receipt, arithmetic overflow, cleanup crossing the unchanged
  deadline, partial observation preservation and no socket IO/lock/write operations.

The twelve added regressions are late-armed only after earlier acquisition guards
have succeeded. They assert actual modeled read/close counts, preserved partial
bytes and unresolved ownership, not merely eventual refusal:

| New method | Late mutation and required observation |
| --- | --- |
| `test_final_close_flags_replacement_prevents_foreign_close` | Context inode replaced during final F_GETFL; zero target closes. |
| `test_final_close_flags_owner_change_prevents_foreign_close` | Original owner lost during final F_GETFL; zero target closes. |
| `test_final_close_flags_new_borrowed_alias_prevents_close` | Borrowed fileno becomes context FD during final F_GETFL; zero target closes. |
| `test_final_pidfd_flags_after_association_replacement_prevents_close` | PIDFD replaced during final F_GETFD after association/liveness; zero target closes. |
| `test_final_pidfd_flags_after_association_owner_change_prevents_close` | Owner lost at that PIDFD boundary; zero target closes. |
| `test_final_pidfd_flags_after_association_new_borrowed_alias_prevents_close` | New borrowed alias at that PIDFD boundary; zero target closes. |
| `test_lseek_substitution_prevents_first_foreign_read` | Context FD replaced during seek; zero target reads/closes. |
| `test_timing_substitution_prevents_first_foreign_read` | Context FD replaced during post-seek clock sample; zero target reads/closes. |
| `test_prior_read_substitution_preserves_prefix_without_another_read` | Context FD replaced after the first authorized seven-byte read; exactly one read, retained seven-byte prefix and zero target closes. |
| `test_final_read_flags_replacement_prevents_foreign_read` | Context FD replaced during final pre-read F_GETFL; zero target reads/closes. |
| `test_final_read_flags_owner_change_prevents_foreign_read` | Owner lost during final pre-read F_GETFL; zero target reads/closes. |
| `test_final_read_flags_new_borrowed_alias_prevents_read` | Borrowed fileno becomes context FD during final pre-read F_GETFL; zero target reads/closes. |

These are prepared, unexecuted syscall-model checks. They do not establish real
Linux kernel ABI behavior, namespace/proc access or latency feasibility.

## Proposed stage — not registered or scheduled

```json
{
  "id": "native-broker-reader-context",
  "description": "67 mocked protected broker context acquisition, final descriptor custody and actual-byte independent replay cases; no native authority",
  "tests": ["test_native_phase3_broker_reader_context"],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_broker_reader_context.py",
    "src/aragorn/native_phase3_broker_reader_protocol.py",
    "src/aragorn/native_phase3_http_canary_contract.py",
    "src/aragorn/native_phase3_run_submission_verify.py",
    "src/aragorn/oci_worker_protocol.py",
    "src/aragorn/runtime_action_broker.py",
    "src/aragorn/runtime_action_decision.py",
    "src/aragorn/runtime_action_observation_publisher.py",
    "src/aragorn/runtime_http_action.py",
    "src/aragorn/runtime_process_profile.py",
    "tests/test_native_phase3_broker_reader_context.py"
  ],
  "needs": [],
  "timeout_seconds": 120
}
```

No imports, compilation, tests, pipeline execution or live acquisition occurred
before this submission. Static text/import-graph and whitespace review only.
No actual new result/fingerprint or signed batch is claimed. Root reviews the
stable closure before registration/scheduling. After release, inspect the actual
fingerprint and existing results in both checkouts; run only the scheduled stage
with `/opt/homebrew/bin/python3.12`. Retain every actual outcome, diagnose failures
before any changed retry, then sign/verify exactly these three assigned paths
after reviewed PASS. Root integrates/pushes the original commit.

## Evidence limits and remaining Root obligations

UNKNOWN is preserved. All seven acquisition authority/qualification flags and all
five independent replay flags are false. Matching acquired bytes and snapshots do
not prove uninterrupted lock/interval custody, authenticity of incoming request
bytes or receipt time, installed/loaded Python source identity, meaningful sensor
progress, zero/complete loss, authorization or final qualification.

Root must provide protected expectation/measurement/fixture origins and pins,
the actual reserved service/accepted socket, authenticated per-message receive
bytes/time, deployed process/source/clock/mount provisioning and exact inventory.
This leaf's `source_files` describes the three control records, not installed
Python. Source inventory pins remain external protected claims. Root must wire
the acquired prefix to real session/reader/loss behavior, deadline/cancellation,
broker callback intent and full REQUEST_ACCEPTED → DECISION_FINALIZED timing.
The independent replay over acquired BOUND bytes supplies no broker-lock attestation.
Actual protected policy/lifecycle, remaining admission, destructive/a100, DNS and
paired execution continue under their existing ownership and operational holds.

Completed: released three-file source/test implementation, the bounded source-review
corrections, twelve new unexecuted regressions and refreshed exact dependency
submission. Pending: coordinator review/scheduling, actual focused result and signed
handoff, then Root caller integration. No later assignment is inferred. Existing
historical evidence and the unresolved fixture-cleanup hold remain preserved.

1. Implement/integrate ready shared providers with only newly scheduled focused validation.
2. Wire full HTTP, then DNS/destructive, every admission/RUN path, real a100,
   cancellation, full timing and four actual paired tasks.
3. Close the 48-entry path/consumer/source-custody inventory and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs on
   one deployment; independently replay, evaluate the existing gate and verify approved cleanup.
