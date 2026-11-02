# Bounded broker reader protocol and submission journal handoff

Implementation base: published verified signed v4
`8ce7c8aa858f7b7b24e24bd8543e7ef7ce4406b5`.
Contract: `docs/phase3/coordinator/broker-reader-provider-contract-v1.md`.

Status: **Root reviewed the complete stable closure and the selected stage passed
all 28 tests on its first execution**. Root published the signed registry/review
checkpoint `743f9bbed27f220c5012196eccce77722f4dcaa8` before running it. The code
and test authors performed no execution; Root owns the actual result below.
No live operation, protected deployment write or lane mutation occurred.
This bounded development PASS supplies no production health gate or qualification.

## Completed source and exact ownership

Root's implementation assignment supplies:

- `src/aragorn/native_phase3_broker_reader_protocol.py`: pure canonical bounded
  request/response validation, exact echoes and artifact/loss/retention joins.
  It returns detached records and preserves structurally valid unknown/reset/lost
  counters, opaque summaries/checkpoints and partial refused evidence. All five
  authenticity/health/authority/qualification flags must remain false.
- `src/aragorn/runtime_http_run_submission.py`: original broker main-process
  ownership, actual saved IDs/process epoch, held/named protected ancestry,
  fixed borrowed lock, exact Linux fdinfo ABI, unchanged boot/time namespace,
  immutable exclusive files, ordered fsync/readback and a six-event state machine.
  Every public operation failure poisons the guard; no operation recovers or retries
  a partial journal. Only newly owned handles are closed, once. A replaced owned
  descriptor is recorded as a cleanup custody failure and is not closed as though
  still owned. The borrowed lock/control are never closed or reacquired.
- `tests/test_native_phase3_broker_reader_protocol.py`: ten new fabricated cases.
- This handoff document.

Root separately delegated only `tests/test_runtime_http_run_submission.py` to
`coverage_ledger`; this implementer has not written that file. Its coauthor
delivered the stable eighteen-method test source without execution. Admission owns
the independent transcript verifier and its tests in the separate lane. Neither
independent consumer nor frozen shared runtime sources were edited or imported
into the protocol tests.

## Stable source pins and actual dependency closure

SHA256, with no `sha256:` prefix:

| Path | Hash |
| --- | --- |
| `src/aragorn/native_phase3_broker_reader_protocol.py` | `8d17e7930d2c560ade4b5c0fb5b539e00ecbfb3fb9f40d910d271dd42eb48007` |
| `src/aragorn/runtime_http_run_submission.py` | `b80fc8b0d0d51d430d35eaf665f2535d1418a1c085a9f975b99f67c351edc51b` |
| `tests/test_native_phase3_broker_reader_protocol.py` | `8d9036337eef30bfc71a79f9d9d71f392483cd0e9ce34f881bfe2a4762463878` |
| `tests/test_runtime_http_run_submission.py` | `a8abbb484500c147b58ed69b6cd9dac2f7e3765db6fa882b0e898b06ae5c07a8` |
| `src/aragorn/__init__.py` | `4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01` |
| `src/aragorn/runtime_action_broker.py` | `94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21` |
| `src/aragorn/runtime_action_decision.py` | `3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d` |
| `src/aragorn/oci_worker_protocol.py` | `0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b` |

Protocol-test runtime repository closure is its test, codec and inert package
initializer. The journal adds only `runtime_action_broker` for the existing
`write_all` and full nine-field `_file_identity`; that broker imports
`runtime_action_decision` and `oci_worker_protocol`, and the former imports only
the latter. The combined stage closure therefore contains exactly these eight
files. All other imports are standard library.

No generated source, materialized runtime, historical test/harness, external
fixture, plugin or package dependency is used by these selected tests. Test
documents and filesystem/process/clock observations are newly fabricated in
their own modules. The contract/release are review inputs, not dynamically read
by the implementation. The existing broker helper closure remains frozen.

## Concrete source decisions and caller obligations

The current config has `expected_broker_uid`, no invented expected GID attribute.
The journal joins that UID to the independently pinned context broker UID and
uses context GID with actual real/effective/saved GIDs, lock and file GIDs. It
requires literal control `/var/lib/aragorn-runtime-action/control` and
`broker.lock`, with root-owned ancestors and broker-owned 0700 control. This
matches the existing service config (`runtime_action_service_v4.py:76`) and
root-owned parent custody (`native_phase3_denied_create_sink.py:322`). The future
caller must obtain context from protected actual accepted-grant/deployment
inputs; accepting context JSON does not establish provider provenance.

The actual boot read is the repaired fixed
`/run/aragorn-broker-boot-id`, held through root-owned nofollow `/run` ancestry,
root-owned nonwritable regular-file custody and named/held identity rereads.
There is no `/proc/sys` fallback. `runtime_http_action.py:25` and
`runtime_broker_decision_measurement.py:30` use this same bind, and
`scripts/materialize_runtime_http_credentials.py:277` preserves the broker's
exact read-only bind from the kernel boot ID. These are source-design references,
not imported/generated test dependencies. Actual mount/proc/unit provisioning
and its deployment identity remain requirements for later real wiring.

All current samples use integer BOOTTIME/MONOTONIC/BOOTTIME; both original
deadlines and rollback are checked, including the closing BOOTTIME sample.
Process/ancestry/FLOCK custody brackets retained-file and boot readbacks, and
the final time stamp follows the closing potentially blocking proc reads.
Each persisted CHECKED event validates packet chronology against its own exact
`checked_ns`, then freshness is checked again after publication. These checks
cannot promise a filesystem syscall returns within a hard time bound.

The fdinfo observations establish held-at-read state only. The future original
single-owner broker must prohibit unlock/reacquire, descriptor duplication,
transfer, close/reopen and concurrent use throughout this journal lifetime.
The root provider cannot take the broker lock. The future caller must read and
review the original finally cleanup with these obligations before release.

`SubmissionJournalError` retains bounded original/cleanup descriptions,
`last_completed_event`, `known_intent`, `intent_attempted`, `effect_possible`,
the latest bounded attempted bytes, and begin/latest fdinfo observations.
The bounded virtual reader captures the exact lock fdinfo's actual prefix
(at most 4096 bytes) before close or re-raising a read/oversize failure. It keeps
an existing begin observation and never substitutes unrelated proc-file bytes.
**The caller must propagate `effect_possible is True` when either durable intent
is known or intent publication was attempted.** Publication may have created a
durable CONNECT_INTENT even if a subsequent check prevented updating the in-memory
completed-event list. Looking only at `known_intent` would incorrectly discard
that uncertainty. Before any intent, an error/terminal remains UNKNOWN, never a
certification of NOT_SUBMITTED. Cleanup errors retain the original refusal and
must prohibit usable success. A poisoned guard cannot be resumed; close only
consumes its owned handles and retains/refuses with the original evidence.

Successful `record_check` is not permission to connect or send. Before either
intent, the real caller still needs independent reader/ACK-age/checkpoint/loss
and policy validation. Phase two retains the original immutable reader evidence,
summary, bindings, connection epoch, retention receipt and before-loss baseline;
fresh receipt/loss-after timestamps cannot manufacture a fresh ACK. A guarded
snapshot requires an actual completed binding and an active preterminal guard.
Transport bytes remain opaque canonical observations; they cannot prove
NOT_SUBMITTED. After connect intent the journal always preserves submission
through payload refusal, timeout and terminal/cleanup ambiguity.

## Proposed newly necessary focused validation

The protocol's ten methods cover detached records; opaque artifact limits;
canonical/duplicate/nonfinite/trailing refusals; exact request fields, phases,
pins and strict integers; raw/decoded bounds; response echoes and all five false
flags; error lists; base64/length/digest joins; partial REFUSED/retention joins;
loss-binding substitution; and missing/reset/increased counter preservation.

The coauthored journal's eighteen methods cover the public lifecycle with mocked OS/proc/time,
durable file-before-directory-fsync-before-readback order, unique/partial writes,
held/named substitutions, actual Linux fdinfo shape/owner/mount/flags, timing and
phase chronology, stale/REFUSED/loss refusal, retained baseline/ACK substitution,
post-connect ambiguity and original-plus-cleanup failures. The real bounded
virtual-file reader is additionally exercised against fabricated proc nodes for
multiple reads, oversize/partial read refusal and close errors. No private guard,
clock-custody, state-transition or publication method is replaced as a successful
stub. Root must review this stable closure before scheduling
`/opt/homebrew/bin/python3.12` for only these twenty-eight new test methods.

Actual result: PASS, 28 tests in 0.075 seconds, exit code 0. Stage
`native-phase3-broker-reader-submission`, fingerprint and post-fingerprint both
`sha256:d36e14e55f23068293e2159caa74311a9519b23ce61ab7816108035d58ef574b`.
Original files remain under this owning worktree's
`.aragorn/phase3-pipeline/native-phase3-broker-reader-submission/d36e14e55f23068293e2159caa74311a9519b23ce61ab7816108035d58ef574b/`:

| File | Bytes | SHA-256 |
| --- | --- | --- |
| `result.json` | 820 | `e2638524cb0496307e08f56b17236ae7332ff64afd0a8f083b4956a497a3244a` |
| `stderr.log` | 5643 | `1a9be90da9b101a94a0e7dd6f2daa6b0c2f27440d3050f9f28d91c12c5f96557` |
| `stdout.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Root read the actual result and logs and confirmed unchanged before/after input
fingerprints. No failed or repeated run exists for this stage. Independent replay
agreement remains pending Admission's separate delivery and any newly necessary
composition stage. Existing historical results and HTTP94 evidence are unchanged.

## Released assignments, blockers and remaining Phase 3 steps

Released: this bounded Root codec/journal slice and Admission's independent
transcript verifier. RUN's separately assigned transport implementation remains
independent. Reserved real IPC client/service, broker renderer, acquisition and
deployment wiring are not released by this implementation.

Concrete blockers: independent
verifier handoff; real listener/read-loop, checkpoint and
loss providers; authenticated root-to-broker IPC, actual protected context and
deployment identities; real bounded timing feasibility and finite broker hooks.
Opaque or mocked bytes cannot close those requirements.

1. Preserve this actual PASS and integrate the independent replay consumer and
   other original signed lane deliveries; schedule only newly necessary changed
   composition after review.
2. Complete the protected providers and actual broker wiring, then the remaining
   HTTP/DNS/destructive, admission/RUN and paired-task causal paths.
3. Close every real path/independent consumer/source identity in the existing
   coverage ledger before one reviewable deployment freeze candidate.
4. After separate operational release, perform the existing same-deployment
   qualification campaign and independent replay; approved cleanup is separate.
   Phase 3 is not complete from this offline slice.
