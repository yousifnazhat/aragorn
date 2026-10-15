# Root HTTP broker reader client: finite refusal-only contract v1

Effective only through provider-release-v14.md at its verified signed published
checkpoint. This is the three-path CLIENT slice. The original whole-IPC draft
remains unchanged and unreleased. Wire/context/submission journal schemas remain
unchanged. Root retains generated HTTP/measurement successor, actual launcher,
protected input origins, loaded inventories and positive health/effect paths.

## Ownership and public interfaces

Root/internal provider_path_review writes only:

- src/aragorn/native_phase3_broker_reader_client.py
- tests/test_native_phase3_broker_reader_client.py
- docs/phase3/coordinator/broker-reader-client-handoff.md

Read ownership-and-release-v2.md, provider-release-v12.md,
broker-reader-bootstrap-contract-v1.md, broker-reader-context-contract-v1.md,
broker-reader-service-contract-v1.md and this contract. Do not edit their sources,
shared journal/codec, measurement, HTTP caller, registry, unit or renderer files.

```python
def configure_broker_reader_guard(
    *, provision_raw: bytes, expected_provision_digest: str,
    source_inventory_raw: bytes, expected_source_inventory_digest: str,
    measurement_binding_raw: bytes, expected_measurement_binding_digest: str,
    fixture_binding_raw: bytes, expected_fixture_binding_digest: str,
    ipc_cancel_read_fd: int, supervisor_pidfd: int,
) -> dict: ...

def begin_http_guard_locked(control_fd: int, lock_fd: int, config, *,
                            request_raw: bytes, effect_raw: bytes,
                            deadline_monotonic: int | float) -> HttpReaderGuard: ...

class HttpReaderGuard:
    @property
    def opening_result(self) -> dict: ...
    def before_connect(self) -> dict: ...
    def before_payload_send(self) -> dict: ...
    def finish(self, *, transport_raw: bytes | None, failure_code: str | None) -> dict: ...
    def close(self) -> dict: ...

class BrokerReaderIpcError(ValueError):
    failure_code: str
    original_failure: BaseException
    cleanup_failures: tuple
    observed: dict
    unresolved_owner: object
```

Configure, opening_result, finish and close return detached exactly
{ipc_raw,observed}; before_connect returns exactly
{request_raw,response_raw,ipc_raw,observed}. No publicly usable direct guard
constructor, positive profile/switch, reset, retry or recovery API exists.
Only HTTP_REFUSAL_ONLY, one configuration and one guard per original main process/
thread. Reject fork/reentry/foreign-owner/second-entry calls without cleaning
an existing owner or taking a rejected caller's new arguments.

On an accepted first configure entry, register both distinct valid supplied FDs
before any fallible metadata, clocks or malformed-argument validation. Never hash
malformed arguments. Configuration owns cancellation read FD and supervisor PIDFD,
including failure; hold one process-lifetime configuration owner strongly. Guard
BORROWS those two handles: it never closes, duplicates or transfers them. This
also covers early policy/replay refusal that never constructs a guard. No public
configuration reset or guard-close implicit release exists. Root's fixed process
lifetime ends their ownership; native lifetime control is Root's separate launcher
obligation. Failed configuration attempts safe owned cleanup once and preserves
unknown/ambiguous custody strongly until that process exits.

Begin borrows the actual already-held broker control and lock FDs without closing,
duplicating, unlocking or reacquiring either. Record all borrowed aliases before
fallible begin work; an owned/borrowed conflict refuses without foreign close.
Guard owns only its action socket, acquired peer PIDFD, directory/namespace/file
handles and journal object. Track per-resource generations: a confirmed close
retires that generation before fallible bookkeeping, allowing legitimate later
number reuse. Ambiguous close is consumed once and quarantined, not retried.

Register all actual kernel-installed ancillary FD numbers before metadata,
including0..2, malformed/extra controls and multiple installed handles. Existing
owned/borrowed aliases are never newly adopted/closed. Mark known PIDFD roles and
any observed anon_inode:[pidfd] association UNKNOWN immediately before any later
fallible guard; unknown/changed association cannot authorize numeric close.
Recheck original process/thread, flags, held identity, borrowed aliases and PIDFD
association after preceding slow observations and before I/O/close. Detach socket
once; retain actual socket/error/unresolved owners strongly even if discarded.

## Protected inputs and actual observations

Use v12's exact provision/installed-inventory schema, constants, fixed paths and
joins; v9/v13's exact measurement/fixture schemas and bounds. Bounds before hashing:
provision16384, source65536, measurement8192, fixture16384 bytes. Require canonical
ASCII JSON, exact keys, duplicate/nonfinite rejection, strict uint excluding bool,
SHA256 pins and original cross-input joins. HTTP attempt range is p3-lab-a001..p3-lab-a025.
Input inventory remains supplied protected expectation; no client-installed or
loaded-source authenticity is inferred. Do not open inventory/packet-selected
paths. Preserve actual account/credential ABI, shared runtime GID and existing
supplementary-group policy; do not invent an empty supplementary-group requirement.

Acquire actual broker saved-account vectors and stat/status/stat, boot from the
protected /run/aragorn-broker-boot-id, held/named own mount/time namespaces, fixed
ancestry and local descriptor observations. Authenticate actual SO_PEERCRED against
protected provider PID/UID/GID and actual socket-derived PIDFD association/liveness.
Supervisor PIDFD joins the protected supervisor PID. No numeric-PID fallback.
Do not inspect inaccessible Root proc/namespace/source views. Supplied provider
start/domain remains explicitly expected; ipc_raw.peer and provider proc/namespace
observations remain null without a complete locally acquired Root process record.
Expected process values in the context do not become local raw observations.

## Existing action/pending inputs and immutable measurement accessor

Root's finite measurement successor must implement public:

```python
def current_http_guard_pending(*, expected_request_digest: str,
                               expected_grant_digest: str) -> bytes: ...
```

It returns detached original canonical Trace.pending bytes <=131072 only for the
active pre-final Trace in the original configured process/main thread. Root's
renderer must snapshot immutable canonical configuration bytes during configure
and compare both current plan and pending.binding to those original bytes.
Current _PLAN and pending.binding alias; comparing those dictionaries cannot
establish immutability. The successor's8192 binding allowance is an explicit
renderer amendment, not a capability of the current4096-byte source module.

Client uses one late PUBLIC module lookup/call; no private _CURRENT/_PLAN/Trace
access, fallback or eager import cycle. Missing accessor refuses. Retain the same
actual pending bytes through later calls; do not demand a pre-final accessor after
measurement finalization. Root's original source is an explicit pending generated-
caller dependency; unit mocks may name that unavailable boundary honestly.

Action request and effect are canonical bytes <=4096 each. Independently validate
the existing14-field action request, without importing private validators or
runtime_http_broker (the generated HTTP caller imports this client):
schema,authority,runtime_digest,session_id,run_id,tool_call_id,active_skill_digest,
operation_digest,path_digest,payload_digest,policy_digest,policy_version,
issued_at_unix,expires_at_unix. Schema is aragorn/runtime-action-request/v1;
authority RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY. Digests are SHA256;
three identifiers match [A-Za-z0-9][A-Za-z0-9._:-]{0,255}; policy_version positive
uint; times uint. This is structural input validation, never a replacement policy
ALLOW or runtime freshness decision. Preserve the owning broker's policy path.
Use public runtime_http_action.validate_effect, validate_fixture_binding,
effect_for_attempt and action_digests for exact HTTP effect/action joins.

Under the borrowed original lock, join action/effect/measurement/fixture/pending
pins and original accepted_boottime_ns. Read decision-measurement-pending.json
through held control and require byte equality to the accessor. Its actual broker
process and mount namespace must match acquired self identity; explicitly acquire
time namespace rather than compare differently shaped whole process objects.

Connect once to /run/aragorn-phase3-broker-reader/guard.sock, authenticate actual
Root peer, then mint exchange_id internally. Construct frozen context using the
original accepted time and exact clock bracket below. Invoke real PUBLIC
begin_http_submission_locked(control_fd,lock_fd,config,context_raw=...,
expected_context_digest=...). Only after it returns read the deterministic
run-reader-<requesthex>-context.json and -event-0.json through held control.
Require exact context bytes and complete BOUND event joins: sequence0, null
previous_digest, matching context_digest, phaseBOUND, original checked timestamp,
null packet/transport/failure pins, intent=false and effect_possible=false.
Require context.clock_bracket.boottime_after_ns <= BOUND.checked_ns < unchanged
wire deadline and BOUND.checked_ns <= actual completed client readback stamp.
No journal private state/helpers, missing-file waits or readback retry.

All three records are distinct device/inode, regular, single-link broker UID:GID0400,
opened nofollow/nonblocking/CLOEXEC once with bounded original prefixes. Require
held/named full identities before/after exact read and reread all three before
successful begin. Full identity is exactly device,inode,mode,uid,gid,nlink,bytes,
mtime_ns,ctime_ns; times signed64, other metadata uint. Guard actual own process,
namespace, borrowed lock/control and fixed ancestry throughout. Read sizes:
pending131072, context8192, BOUND8192. A BOUND prefix is no independent NOT_SUBMITTED
proof, policy ALLOW, loaded identity or guaranteed uninterrupted lock interval.

## Original clock budget, authenticated transport and refusal

Convert the finite supplied original HTTP deadline once using integer-ratio
arithmetic, floor to nanoseconds. Acquire BOOTTIME/MONOTONIC/BOOTTIME and require
0 < original_deadline_ns - monotonic_ns <=500000000. Frozen wire deadline equals
lower BOOTTIME plus that exact remaining budget, is <=session deadline, and closing
BOOTTIME is below it. Never clamp a context into a different formula or renew time.
Recheck both clocks/rollback, actual namespaces/boot and cancellation throughout.
Apply original250ms first-phase cap and strictly <200ms response freshness under
public journal chronology, not guessed receipt stamps.

Reuse v13 Linux little-endian64/native12-byte credentials and ordinary socket
options: PASSCRED1/PASSPIDFD0, actual nonblocking/CLOEXEC, requested buffers524320,
actual getters>=262176 and SO_SNDBUF>=2*actual_send_bytes+32. One connect attempt;
in-progress completion checks the same socket and SO_ERROR. One send attempt
DONTWAIT|NOSIGNAL; receive DONTWAIT|CMSG_CLOEXEC, bounded262144 response. Retain actual
control/flag prefixes before validation; exactly one SCM_CREDENTIALS joins provider.
Cancellation EOF/data/process-exit/custody failure wins simultaneous readiness;
spurious EAGAIN keeps the same original deadline. No retry/resend/reconnect/force-
buffer/sysctl/umask change or hard syscall-return-time guarantee.

before_connect creates/validates frozen BEFORE_CONNECT/null-predecessor request,
sends once, validates original authenticated response with public codec and
requires REFUSED. Real journal.record_check runs exactly once with original bytes.
No EVIDENCE response authorizes anything; positive intent methods are never called.
The ordinary service response is LOSS_UNAVAILABLE with null loss and actual
retained artifacts. Other valid REFUSED codes are failure evidence; never fabricate
Root response/retention from an exception. After actual response/journal check,
close the action socket once and return the completed refusal. Do NOT wait for
Root EOF/second ACK: v13 waits broker EOF. Client close does not prove Root finish.

Successful begin requires all opening guards, a final enforcing BOOTTIME/MONOTONIC
sample and finite immediate local custody checks; its connected action socket stays
owned and open for before_connect. Completed before_connect refusal additionally
requires terminal action-socket close before its final enforcing clock/custody
checks and return. Keep original acceptance/deadlines. before_payload_send refuses out of order
without new exchange/intent; no production override can synthesize positive input.

## Terminal journal and error preservation

finish calls actual journal.finish with original bounded<=32768 transport bytes or
null and an unprefixed permitted failure code, then actual final_readback. Public
record_check, finish and final_readback return no raw result; do not invent one.
Journal terminal finish/readback intentionally permits expired time. A deadline/
cancellation refusal must preserve its original failure while attempting permitted
terminal retention and independent safe cleanup under the borrowed lock; terminal
lifecycle evidence cannot become fresh usable health/refusal authority. Do not
finalize/recover a poisoned journal again. Attempt its public close once to close
its remaining known-safe owners. Guard.close closes journal and its own acquired
handles before Root releases the original broker lock; configuration FDs and
borrowed lock/control remain untouched.

Preserve actual SubmissionJournalError, available __cause__, description dictionaries,
intent_attempted,known_intent,last_completed_event,partial_bytes,custody_observations
and cleanup failures. It has no original_failure/observed attributes. Missing
records never mean NOT_SUBMITTED; submitted/attempted intent ambiguity remains
INDETERMINATE. No outer finally may weaken that claim.

## Exact bounded retained API

ipc_raw uses v13's exact <=16384 IPC observation fields with roleCLIENT, operations
OPEN/BEFORE_CONNECT/BEFORE_PAYLOAD_SEND/FINISH/CLOSE and lifecycle statuses
OPENED/REFUSED/CLOSED. Unobserved pins/marks/peer are null; observed times actual uint.
Both continuity/loss fields UNKNOWN; all five authority/qualification flags false.
Lifecycle OPENED is not provider health, effect readiness or qualification.

observed has exactly:

```text
provision_raw source_inventory_raw measurement_binding_raw fixture_binding_raw
 action_request_raw effect_raw measurement_pending_raw context_raw bound_raw
 request_raw response_raw transport_raw ipc_raw record_observations
 handle_observations transport_observations journal_error send_attempted bytes_sent
```

Raw bounds are the schemas above. Unobserved fields null; send_attempted starts false,
bytes_sent null until an actual syscall return. record_observations is at most
three actual ordered PENDING/CONTEXT/BOUND rows, each exactly role,name,identity,digest.
Identity is actual full nine-field metadata or null; digest is null until a complete
bounded read returns, never a partial prefix relabeled as complete. Actual partial
bytes remain in corresponding observed raw fields. Retain errors/original causes.

transport_observations uses v13's exact snapshot grammar, at most16 ordered rows,
initial/latest per executed edge OPEN/CONNECT/CONTEXT/RECEIVE/SEND/EOF/CLOSE. Provider
proc/namespace fields stay null as above. Keep original credential12/fdinfo4096,
six proc16384/boot64, controls<=8/4096total and socket/directory bounds unchanged.
handle_observations uses v13's row shape, first/latest for IPC_CANCEL,
SUPERVISOR_PIDFD,CONTROL_BORROWED,LOCK_BORROWED,PEER_PIDFD, at most10. The two
configuration-owned roles and borrowed control/lock remain closed=false on guard
close. Metadata/link/flags/raw are actual, not expected values copied into evidence.
IPC digest fields name only enumerated bytes; no implicit snapshot digest binding
or independent authenticity is claimed. Detached containers retain actual live
exception/unresolved owner identities rather than deepcopying ownership.

BrokerReaderIpcError.failure_code is one frozen protocol ERROR_CODES enum, set at
explicit failure sites. Retain original BaseException separately; never interpret
exception text as a reason. Local malformed framing=PROTOCOL_REFUSED,
identity=IDENTITY_CHANGED, clock=CLOCK_REFUSED, expiry=DEADLINE_EXPIRED,
retention=RETENTION_FAILED, cleanup=CLEANUP_FAILED, otherwiseINTERNAL_REFUSAL.
Renderer maps to BROKER_RUN_<code> before the first DECISION_FINALIZED and returns
False before HTTP connect. Preserve KeyboardInterrupt/SystemExit/MemoryError
identity with the same attached failure_code/evidence and bounded<=32 actual
cleanup failures plus strong local unresolved_owner. No private retention/cleanup
operation is authorized by implementing these guarded source cleanup paths.

## Review, selected validation and remaining work

Implementation may begin after signed publication. No execution is scheduled here.
Submit stable source/test/handoff hashes and actual complete import/generated/
fixture closure plus focused cases. Use /opt/homebrew/bin/python3.12 only after Root
reviews/registers/schedules the first newly necessary stage. Unit cases may mock
the unavailable PUBLIC accessor and fabricated native boundaries while using
actual codec/journal/client; declare that ceiling. Missing-accessor refusal is a
required case. No historical TestCase or fixture imports.

Cover complete REFUSED lifecycle/real journal order, original pending/context/BOUND
joins, actual receipt/freshness/clock expiry, non-root observation ceiling,
malformed-first/later-valid transfer and pre-entry rejection, all-installed
ancillary custody, late flags/PIDFD association/clock substitution, FD reuse after
confirmed close, cancellation priority, partial send/receive, terminal cleanup and
preserved ambiguity. Do not run unrelated successful stages. Preserve actual
results/fingerprints, diagnose before changed-input retries, and only after reviewed
PASS sign/verify exact assigned paths for Root integration/push.

Root must independently implement immutable measurement accessor, finite HTTP94
successor/caller wiring and actual configure call from v12 transfer; bind actual
predecessor report88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9.
Current original measurement4096 is not generated successor8192. Actual protected
launcher/input acquisition, bootstrap/service lifetime and deployed/loaded source
inventories remain Root-owned. Missing loss stays UNKNOWN -> REFUSED/LOSS_UNAVAILABLE;
full loss/program/map, policy/lifecycle, destructive observer and paired contexts
remain prerequisites to positive enforcement and implementation freeze.

1. Implement/integrate ready providers with only necessary new focused checks.
2. Wire full HTTP, DNS/destructive, all admission/RUN paths, genuine a100,
   cancellation, full timing and four actual paired tasks.
3. Close the same48-entry path/consumer/source-custody inventory and freeze.
4. Separately release the31-case/100-action/100-pair same-deployment campaign,
   independent replay, existing gate and approved cleanup. All holds remain.
