# Finite HTTP94 RUN guard successor: Root renderer contract v1

Effective only at the verified signed publication of provider-release-v15.md.
Root/internal reader_store_implementation writes exactly:

1. scripts/materialize_runtime_http_run_guard.py
2. tests/test_runtime_http_run_guard.py
3. docs/phase3/coordinator/http-run-guard-renderer-handoff.md

This is pure finite byte transformation, not a stager, installer or new framework.
No filesystem discovery/writes, old stager imports/calls, generated execution,
network/live operations, cache copy, private retention/cleanup or fabricated report
inside the renderer. Tests are prepared without execution until Root schedules.
Do not edit original source files, client/bootstrap, shared create/effective
validators, units, report, registry or existing materializers.

## Exact API, source input and generated output distinction

```python
def render(original: dict[str, bytes], *, predecessor_report_raw: bytes,
           dependency_sources: dict[str, bytes],
           expected_dependency_pins: dict[str, str]) -> dict[str, bytes]: ...
```

The exact original/output key set, using repository source names, is:

- src/aragorn/runtime_http_broker.py
- src/aragorn/runtime_broker_decision_measurement.py
- src/aragorn/runtime_broker_measurement_plan.py
- src/aragorn/runtime_broker_decision_measurement_verify.py
- src/aragorn/runtime_action_service_v5.py
- src/aragorn/runtime_http_capability.py
- src/aragorn/native_phase3_http_collection_verify.py

Require original to contain exactly those seven byte strings. Each has the exact
length/digest in actual predecessor report.source_inputs. Require report68263
bytes, SHA25688d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9;
strictly decode that pinned existing artifact. Do not change its flags or call it
a successor. Reconstruct the seven actual generated predecessors and match every
report.files source_name/path/length/digest before changing anything. Return exactly
seven generated successor byte strings; originals are never mislabeled installed.
No guessed output digest, staging report, loaded-source or qualification claim.

Original inputs currently agree with report.source_inputs:

| Basename | Bytes | SHA-256 |
| --- | --- | --- |
| runtime_http_broker.py |18373|fff489d9a315d53c79bd44f6266465788e55876d2e14e363d84713857f0b9d50|
| runtime_broker_decision_measurement.py |19164|cb374ad8d1b7dc591fa554ab0590e8c39eb3ac287589ce26da67b4d5fc0e454e|
| runtime_broker_measurement_plan.py |13206|5789d265c779ad4d5674d7dabe0cd65a289274da6663369d5d17a8557fa78c30|
| runtime_broker_decision_measurement_verify.py |21956|0354718223c4f65d2d92908817a0ac29dc3f6e5fcc873933eee8afa65672860f|
| runtime_action_service_v5.py |4146|a3e829d2e60f26dd91cbb14967ddf2a747414ce8f125b4f207dbce7a5e1e86c7|
| runtime_http_capability.py |13577|3ec5d0b7d213a0ebaf24f06c6ef94d405ba38b187ec4d1be0d1d5e1391d5391e|
| native_phase3_http_collection_verify.py |40268|d19c8042dac3d84e3f9d0cd86442093755767d74a6e368346a7311a9af53e03a|

Literal reconstruction is finite and count-checked/reversible. Read provenance
anchors but do NOT execute/import old historical materializers:

- stage_runtime_broker_measurement_receipt_profile.py:44–76
- stage_runtime_broker_effective_receipt_profile.py:163–166
- stage_runtime_phase3_http_profile.py:316–352
- materialize_runtime_http_collection.py:67–114
- materialize_runtime_broker_decision_measurement.py:162–178
- materialize_runtime_http_readiness.py:46–53

Measurement uses receipt/effective-receipt transformations, HTTP sources/8192/SENT/
profiled schemas, then readiness inventory addition. Plan/verifier use HTTP
collection transforms then readiness addition. Service uses measurement import/
three-credential/configure transforms, measurement bound8192, then startup
readiness insertion. HTTP broker and the two compatibility originals already
match their generated predecessors. A changed/missing/ambiguous literal refuses,
never falls back to a guessed source. Keep all existing input/source protections.

## Actual complete dependency inventories

Dependency_sources is a finite mapping of actual module basenames to source bytes,
with exactly matching expected_dependency_pins keys. Basenames use the v9 Python
basename grammar, no path traversal; bytes1..16777216 and total<=67108864. Validate
supplied expected pins before using them. Root must independently review/freeze
actual bytes/pins; hashing caller inputs does not create source authority.

This mapping supplies newly installed unchanged-source dependencies of generated
HTTP/service/client/bootstrap, including their complete actual transitive project
imports and existing generated dependencies. The seven rendered output names are
excluded from this unchanged mapping to avoid contradictory original/generated
hashes; use actual output bytes for those names. Keep all three generated
measurement _SOURCES sets equal to the complete reviewed final broker closure.
Do not guess that set from the old22 names or a planned client import. Root's
stable client/bootstrap closure review must settle actual names before execution.
Renderer may be implemented while they stabilize; no stage before closure.

The generated service's public read_service_credential exists only in the
repaired HTTP94 runtime_http_action successor, not the current original module.
Require that dependency to be the actual30923-byte predecessor-generated input,
sha256:c9b8ba087dd9f302c648e7b1b68ea291ff29d7df88c54ac6eb603f4b7d1b68ad,
which matches report.files. Do not substitute original21866-byte action source or
claim an unavailable public function. Other unchanged generated dependencies
must also retain actual predecessor file pins; post-predecessor signed changes
need separately reviewed Root pins/origins. Tests may reconstruct a needed exact
generated dependency from reviewed literal transforms/source constants, without
old materializer/stager imports or calls; inventory every original/constant-source
read and require the resulting exact report.files pin. No result cache copying.

No source inventory self-hash cycle: module names define the source set; final
pins are derived only after generated bytes exist by Root's actual public staging
caller. Preserve binding limit8192. Because render receives no binding argument, generated public
plan/configure guards must check the actual canonical binding fits; renderer bounds
its finite source-set inputs and never invents an actual binding. Refuse oversize rather than silently widen a frozen credential ABI. Source-only expected
inventory/byte output is not installed or loaded provenance; actual acquisition
remains Root's native launch/capture duty.

## Immutable public measurement accessor

Render current_http_guard_pending(expected_request_digest=...,expected_grant_digest=...)
as specified in v14. During successful configure capture immutable canonical plan
bytes plus original PID/main/native-thread identity, separately from aliased
_PLAN/pending.binding. Preserve original configured process identity and existing
input/source checks. Require active current Trace, final is None, actual original
owner, matching request/grant and equality of current plan AND pending binding to
the immutable original bytes. Return detached canonical original pending<=131072.
No state exposure/mutation, re-stamped acceptance, lock acquisition or private
cross-module access. Missing/stale/mutated/wrong-thread/forked states refuse.
Preserve all existing timing hooks and original8192 generated binding allowance.

## Real HTTP client wiring under the existing broker lock

Generated HTTP imports only the actual public v14 client. Preserve original
policy, revocation, health, consumed-state and deadline checks. Create guard lazily
inside the FIRST authorize_effect callback, after those latest checks still permit
proceeding, immediately before the first finalize. This avoids an idle Root
connection while HTTP constructs its own execution guard. The callback supplies
original request/effect bytes, the original already-held control/lock/config and
unchanged HTTP deadline to real begin_http_guard_locked. Retain opening_result,
then invoke actual before_connect once. Add exact mapped BROKER_RUN_<wire code>
refusal reasons before first DECISION_FINALIZED and return exactly False before
HTTP connect. Ordinary client exceptions use fixed failure_code; do not parse text.
Preserve KeyboardInterrupt/SystemExit/MemoryError identity. Save those actual
client instances before crossing the HTTP callback: current HTTP transport replaces
ordinary exceptions (including MemoryError). Restore the saved exact instance after
transport unwinds with actual transport attached, and preserve MemoryError as a
primary through generated broker lock cleanup alongside the two interrupts.
Never invoke intent
methods, forge positive evidence/transport or allow a positive response in this
refusal-only profile. An early ordinary policy/replay refusal needs no guard.

A second callback cannot become a positive route; before_payload_send is out of
order in this profile. Preserve original acceptance/finalization endpoints and
all original action/grant replay and ambiguity behavior. Client drives socket EOF;
never wait for Root close/second ACK. Root session finish success is not inferred.

In the owning exit path, while original lock remains held, finish actual journal
through client with actual bounded HTTP transport bytes or null and permitted
unprefixed failure code, then close client. Early policy refusal after guard
construction uses POLICY_REFUSED. Successful REFUSED codes map back to their
unprefixed journal enums; errors retain their fixed original codes. Prefix every
actual canonical response error code in the broker reason list; for journal's
singular failure_code select the first canonical actual code, keeping the complete
original response in retained observations. Do not finish
an already poisoned journal again; attempt the one public client.finish terminal
call, whose own poison check preserves failure without another journal finish.
Never inspect private journal state. Attempt public client.close once independently.
Attempt independent known-safe cleanup even after an earlier cleanup error.
Preserve original/cleanup exceptions and post-intent ambiguity; failed retention
or cleanup must not become a normal completed BLOCK. Original lock release runs
last. Preserve native BaseException and existing conservative effect handling.

Add one bounded public retained_http_guard_observation() getter in generated HTTP.
It returns detached exactly opening,check,finish,close,error,cleanup_errors,transport;
before an attempt return those unobserved slots as null (cleanup_errors empty
tuple). Keep the actual guard strongly in the private owning record, omit it from
public return, and retain each original client return/error before mapping. Only
actual returns/exception objects are exposed, cleanup_errors<=32, transport original bounded<=32768 canonical bytes or null.
Retain one attempt only in original process/main thread, no reset/overwrite/new
execution. Returned nested containers must keep original exception/owner identity;
never deepcopy sockets. This is source-local supplemental observation, NOT durable
external retention/authentication or health. Root's launch/capture must consume
and retain it; that later obligation is explicit rather than silently discarding
actual failures on a normal BLOCK return. No frozen broker result field is added.

## Two exact HTTP-specific reason consumers

The actual runtime_http_capability._recorded_decision and independent HTTP
collection result_record reject every new BROKER_RUN_* reason. Render these two
finite successors as well, preserving all existing result/request/policy/receipt/
transport joins and authority flags. Independently accept a canonical nonempty
subset of exact BROKER_RUN_<native protocol ERROR_CODES> only when result is
BLOCK/NOT_PERFORMED, policy decision remains ALLOW with no policy reason, payload
decision null, and unchanged transport validation passes if present. Do not
accept unknown/mixed/noncanonical broker reasons, positive verdict, SENT status,
missing policy decision or substituted identities. Preserve legacy valid paths.

Use the frozen twelve code literals independently in the HTTP consumer; do not
monkeypatch/widen shared effective/create sets or import a producer as the
independent semantic verdict. This compatibility records structurally bound
broker refusal; it does NOT independently verify the asserted underlying cause,
acquisition, blocking interval, sensor health, submission state or qualification.

## Real service bootstrap and configure call

Preserve generated service's existing THREE-argument credential ABI, User/Group,
capabilities, LoadCredential paths and original startup readiness. Retain exact
protected measurement raw bytes already read for measurement.configure and actual
capability-grant bytes. Obtain original fixture bytes only through repaired public
runtime_http_action.read_service_credential('http-fixture'). No /etc fallback or
reconstructed dictionary. Bound and pin actual bytes before public calls.

After existing expired-grant return and before startup readiness/serve, mint one
checked original BOOTTIME startup deadline within v12's4-second cap. Invoke actual
receive_broker_reader_bootstrap with credential raw bytes/pins, take_configuration
once, retain bootstrap_raw and pass exactly its other ten fields into actual
configure_broker_reader_guard. Retain configure return. Close transfer owner once
AFTER successful take, including configure failure; configuration owns transferred
FDs at that point. Receive/take failure already performs contract cleanup, so no
automatic second close/recovery. Preserve primary and actual cleanup errors.

Retain original bootstrap/configuration observations in one bounded source-local
public retained_broker_reader_bootstrap_observation() getter in generated service:
exactly bootstrap_raw,configuration_result,transfer_close_result,error,cleanup_errors.
Retain actual post-take close return/error too. Bounds and
identity rules are v12/v14, unobserved null and <=32 actual cleanup errors. No
reset or deployment/health claim. Root's future capture owns external retention.
Provider readiness, bootstrap lifecycle, HTTP startup readiness and reader
acquisition remain distinct. Do not invent boolean readiness or source identity.

## Focused source and composition review before execution

Submit exact stable source/test/handoff hashes, full actual static imports,
generated-source/fixture dependencies and focused cases. Newly authored tests may
read these seven inventoried originals and actual report; every such read is a
behavioral input. No historical TestCase imports/reruns or unstated fixtures.
All generated imports/execute/compile in tests require Root's reviewed schedule.
The renderer itself never imports/runs generated or historical sources.

Cover exact predecessor pins/reversibility, changed original/report/closure and
oversize refusals, equal actual source sets, immutable alias/current-owner accessor,
lazy guard/finalize/connect ordering, actual retained getter limits, original
BaseException/cleanup/journal ambiguity and lock-release ordering, protected raw
credential/bootstrap/take/configure/close sequence, and actual runtime PLUS
independent HTTP consumer acceptance of mapped refusal while rejecting forged
positive/unknown/mixed reasons. Declare unit boundary mocks. Generated-caller
composition with actual stable v14/v12 dependencies is a separate claim until
those actual bytes are included and exercised. No placeholder PASS.

Root owns registration/scheduling and actual result review. Only after reviewed
PASS stage exactly assigned three paths, sign/verify, push normally and verify
remote tip. No change to existing successful fingerprints or actual predecessor
report. Actual materialization/deployed inventories need a separately reviewed
public caller; neither pure bytes nor mocked tests are installed identity proof.

1. Implement/integrate released providers with only necessary focused checks.
2. Wire HTTP/DNS/destructive, all admission/RUN, a100, cancellation/full timing
   and four actual paired tasks with real protected providers.
3. Close the existing48-entry ledger/source custody and freeze.
4. Separately release same-deployment31-case/100-action/100-pair campaign, replay,
   existing gate and approved cleanup. All operational/private-retention holds stay.
