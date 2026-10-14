# HTTP94 caller successor: source review v1

Current amendment: v9 and `broker-shared-group-handoff.md` resolve the historical
journal GID incompatibility described below with four new passing checks. The
old journal pin/table remains a record of this review's predecessor; use the
handoff's actual successor pin. Bootstrap/IPC/launcher and installed capture
source release still need the remaining exact contracts; this review grants none.

Status: coordinator design review, based on published checkpoint `c0b9900` and the retained HTTP94 credential report. This document releases no implementation, stage, installation or operation. The proposed four-path source assignment must wait for the exact bootstrap/configuration decisions and the actual shared-runtime-GID incompatibility below. No project imports, tests, restaging, Git operations or live operations were used for this review; source/hash/JSON/AST reads only.

## Retained predecessor and generated source origins

Reuse `benchmark/evidence/phase3-http-credential-staged-profile-v1.json` unchanged:

- Bytes: `68263`.
- Digest: `sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9`.
- Schema: `aragorn/runtime-phase3-http-credential-staged-profile/v1`.
- Authority: `CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_DEPLOYMENT_OR_PHASE3_AUTHORITY`.
- Exact existing inventories: 94 `files`, 124 `source_inputs`, 50 `new_dependencies`, 21 `directories`, and 22 `measurement_source_names` / `binding_source_pins`.

The report's full 124 `source_inputs` records are the exact predecessor source dependency inventory, not just the five selected sources below. Its full 94 `files` records bind installed/generated paths, modes, lengths and hashes; `source_inputs` bind original source bytes. Keep these inventories distinct. Their exact enumeration and pins remain in the pinned report rather than a separately maintained duplicate manifest. Existing credential-14 and composition-7 evidence remains predecessor evidence; changing this caller does not authorize rerunning unchanged stages.

The five proposed renderer inputs, keyed by `src/aragorn/` source name, are **generated installed predecessor bytes**. Each installs at `/usr/lib/aragorn/aragorn/<name>` with mode `0644`:

| Module | Installed bytes | Full installed SHA-256 |
| --- | ---: | --- |
| `runtime_http_broker.py` | 18373 | `fff489d9a315d53c79bd44f6266465788e55876d2e14e363d84713857f0b9d50` |
| `runtime_broker_decision_measurement.py` | 20698 | `d45e313fde5021484c0e42e10f1b3336c9811a7fdf9c730e02632a368dfb5d8f` |
| `runtime_broker_measurement_plan.py` | 14096 | `ccc6229458f243ff87b033e07d64d06c4132c2bfd230c091777bda3dff516cab` |
| `runtime_broker_decision_measurement_verify.py` | 22735 | `a1af7656a1d3103c67a3ddbc33d5874231f2432231c07e565d29267b70a104e4` |
| `runtime_action_service_v5.py` | 4790 | `b802d6b797aae8f209bafdbea483384d49128b4d35cbc0de4769ab0955126dbc` |

The corresponding original repository source pins in `source_inputs` are:

| Module | Original bytes | Full original SHA-256 |
| --- | ---: | --- |
| `runtime_http_broker.py` | 18373 | `fff489d9a315d53c79bd44f6266465788e55876d2e14e363d84713857f0b9d50` |
| `runtime_broker_decision_measurement.py` | 19164 | `cb374ad8d1b7dc591fa554ab0590e8c39eb3ac287589ce26da67b4d5fc0e454e` |
| `runtime_broker_measurement_plan.py` | 13206 | `5789d265c779ad4d5674d7dabe0cd65a289274da6663369d5d17a8557fa78c30` |
| `runtime_broker_decision_measurement_verify.py` | 21956 | `0354718223c4f65d2d92908817a0ac29dc3f6e5fcc873933eee8afa65672860f` |
| `runtime_action_service_v5.py` | 4146 | `a3e829d2e60f26dd91cbb14967ddf2a747414ce8f125b4f207dbce7a5e1e86c7` |

Generation originates in `scripts/materialize_runtime_broker_decision_measurement.py`: lines 141–160 wrap the real V4 grant call in `begin`/`retain`/`close`; lines 162–184 configure measurement from the protected credential. `scripts/stage_runtime_phase3_http_profile.py:316–352` extends measurement inventories, raises only the measurement credential limit to 8192, joins HTTP profiling and preserves SENT retention ambiguity. `scripts/materialize_runtime_http_collection.py:54–124` extends the plan and independent replay sources. `scripts/stage_runtime_phase3_http_ready_profile.py:212–226` adds readiness to all three matching source sets. `scripts/materialize_runtime_http_readiness.py:46–54` inserts actual startup readiness before service entry. `scripts/materialize_runtime_http_credentials.py:252–285` repairs the HTTP credential/import-cycle boundary and service units; it does not replace the measurement caller with repository originals.

`scripts/stage_runtime_phase3_http_credential_profile.py:44–94` combines the already generated ready profile, nine credential changes and two activators. Its source is 7876 bytes, SHA-256 `c1d5c463ead4984c184ea621131a97a6d288518ce87769b2f174b63a6e56528d`. It is an additional source dependency of capture composition, not an additional `source_inputs` entry fabricated into the old report.

## Proposed finite renderer and count-one boundaries

Proposed API: `render(original: dict[str, bytes], *, predecessor_report_raw: bytes) -> dict[str, bytes]`. Freeze its exact input/output allowlist only after bootstrap selection. Verify the full predecessor report pin and each selected generated input against the matching report `files` record; reject repository-original substitutions. Return source bytes only. Do not call an old stager, evaluate generated code, mutate a predecessor or synthesize a replacement report in this renderer.

Every replacement must use one exact anchor, reject preexisting output/changed count, and reverse back to the identical input bytes. Locations below identify the reviewed source boundaries; generated inputs must still match their full hashes before searching anchors.

| Generated target | Count-one boundary / required change |
| --- | --- |
| `runtime_http_broker.py` | Import the new public client API; initialize guard state beside the existing FD/transport locals. Insert guard construction after `broker._commit_state(control_fd, config, state)` and the following initial non-ALLOW return, at repository lines 269–271. Preserve both statements. |
| `runtime_http_broker.py` | Within its single `authorize_effect` definition, join the first/second phase at the existing pre-finalization boundary at lines 328–332. Preserve actual policy rechecks and the first `finalize` call; the first reader refusal must be in `final_reasons` before that call. |
| `runtime_http_broker.py` | Retain actual transport/failure and finish/read back the journal on the owning exit path. Insert guard cleanup before its single `broker._release_lock_and_close(...)` call at lines 416–423. Preserve the original borrowed-lock owner and all exception/ambiguity behavior. |
| `runtime_broker_decision_measurement.py` | Extend its single `_SOURCES = {` inventory; add the public pending accessor before the single `def final_decision(` boundary. Add an immutable canonical configuration byte snapshot to the one successful `configure` assignment, with an explicit main-thread/original-process contract. |
| `runtime_broker_measurement_plan.py` | Extend its single `_SOURCES = {` to exactly the same final broker measurement set; preserve the current 8192-byte credential boundary unless a separately reviewed actual-size change is necessary. |
| `runtime_broker_decision_measurement_verify.py` | Extend its single `_SOURCES = {` to exactly the same set. Preserve independent timing and result joins; do not turn new IPC fields into verified acquisition evidence. |
| `runtime_action_service_v5.py` | Add one fixed configure call only after protected inputs and the selected descriptor bootstrap are available. The actual generated service already has protected measurement configuration and startup readiness. Exact bootstrap arguments, input custody, call position, and entrypoint/unit outputs remain unreleased. |

No direct edit of the five predecessor files is assigned by this proposal. Renderer-source ownership is distinct from the generated output path list.

## Public pending accessor and immutable configuration

Proposed API:

```python
def current_http_guard_pending(
    *, expected_request_digest: str, expected_grant_digest: str
) -> bytes:
    ...
```

The accessor requires a configured original broker process/main thread, a current active `Trace`, unchanged configured identity and canonical plan, matching request/grant pins, and `trace.final is None`. It returns detached canonical pending bytes bounded by the existing 128 KiB pending limit. It does not expose `_CURRENT`/`Trace`, mutate them, create another acceptance timestamp, or acquire any lock. Unconfigured/legacy calls refuse.

Concrete defect to avoid: `begin` currently places `_PLAN` itself into `Trace.pending['binding']` (`runtime_broker_decision_measurement.py:264,287`). Comparing those two dictionaries is not an unchanged-configuration check: they alias. The successor must preserve the successfully validated configuration's original canonical bytes in `configure`, then compare the current plan and pending binding to that immutable snapshot. Check the configured process and actual current main thread rather than accepting a same-shaped caller record. The original snapshot is private process state, not a new authority input.

The client acquires this pending value once before the first finalization, reads the actual protected `decision-measurement-pending.json` through the borrowed control FD, and requires byte equality. Later callbacks use retained original bytes; callback two cannot call a pre-final-only accessor. Measurement pending carries a mount-namespace spelling, not a time-namespace identity. Acquire and join both actual namespace domains separately; never rename one into the other.

## Actual caller, time, lock and ambiguity joins

The draft client APIs remain `configure_broker_reader_guard`, `begin_http_guard_locked`, and the owning guard's `before_connect`, `before_payload_send`, `finish`, and `close`. Their exact signatures and bounded raw/error schemas are in `broker-reader-ipc-next-contract-draft-v1.md`; no callback/configuration override permits positive effect authority in `HTTP_REFUSAL_ONLY`.

1. Existing service/capability execution remains the owning path. The rendered V4 measurement `begin` creates the one REQUEST_ACCEPTED stamp before claiming the grant. The HTTP broker durably consumes the request and requires its initial policy ALLOW before creating the reader guard, while holding its original serialization lock.
2. Validate actual request/effect against the protected grant and HTTP fixture. Derive context from the retained original acceptance, actual broker/provider identities and the original HTTP `deadline_monotonic`. Publish actual journal context and BOUND before the first IPC packet send; Root independently acquires those actual protected bytes without acquiring the broker lock.
3. Convert the original finite deadline exactly once through its integer ratio, rounding down to nanoseconds. Use BOOTTIME/MONOTONIC/BOOTTIME and the lower BOOTTIME sample for the deadline conversion. Preserve the original remaining budget, validate the namespace/boot domain and reject rollback/suspend/domain changes. No renewed 500 ms allowance, packet-supplied receipt stamp, narrow replacement timing pair or retry.
4. Callback one retains existing policy/clock checks. If policy has already refused, do not invent or unnecessarily acquire positive reader evidence. Otherwise the actual client sends once and passes original response/request bytes to `journal.record_check('BEFORE_CONNECT', ...)` before the first DECISION_FINALIZED. All policy and newly required reader/journal work precedes that finalization. Per-phase limits remain 250 ms before connect, 100 ms before payload and original ACK age strictly below 200 ms; the unchanged outer deadline remains binding.
5. A successful Root reader/checkpoint acquisition returns the frozen REFUSED response with exactly `LOSS_UNAVAILABLE`, null loss record, actual retained reader/checkpoint artifacts and all five authority flags false. The rendered callback merges `BROKER_RUN_LOSS_UNAVAILABLE` before finalization and returns exactly `False`. It never records connect intent. The unchanged HTTP effect's callback is before `connect`, and its second callback is before actual payload `send` (`runtime_http_action.py:413–424`). This profile cannot legitimately reach the second callback; `before_payload_send` refuses without another exchange.
6. Keep actual bounded HTTP transport bytes, not a synthesized NOT_PERFORMED record. Journal terminal codes are the unprefixed frozen codes: for example `LOSS_UNAVAILABLE`, not `BROKER_RUN_LOSS_UNAVAILABLE`; existing policy refusal uses `POLICY_REFUSED`. Mapping to broker decision reason strings is a separate step. Retain malformed/local errors and their fixed mapped codes without using exception text as a decision.
7. Journal finish, final readback and guarded client/journal close occur while the original lock is still held, before `runtime_http_broker.py:419` releases it. Neither client, service nor journal may duplicate, transfer, close, unlock or reacquire that borrowed lock. A poisoned journal is not repaired or finalized a second time. Preserve original errors and all actual retention/cleanup errors.
8. `SubmissionJournalError.intent_attempted` or `known_intent` cannot be downgraded by missing final records or NOT_PERFORMED-looking transport. Unknown exceptions after handing off to the actual HTTP effect remain indeterminate according to the existing caller. Failure does not erase durable replay consumption, clear measurement/profile/grant pending state or authorize a retry. A blocked normal result can complete the original grant/measurement retention; an interrupted path may legitimately leave only partial evidence.

Sources: `runtime_http_run_submission.py:53–86,203–254,427–554`; `runtime_http_broker.py:166–442`; `runtime_broker_decision_measurement.py:245–319,326–362,397–525`. These are source behavior references, not proof of an uninterrupted deployed custody interval.

## Shared runtime GID: concrete release blocker

Actual HTTP94 account configuration deliberately uses `User=aragorn-broker`, `Group=aragorn-runtime`, `SupplementaryGroups=aragorn-sensor`. `runtime_action_service.py:95–132` requires broker effective GID to equal the runtime group, distinct broker/runtime/sensor UIDs, and a bounded allowed supplementary-group set. `runtime_action_service_v5.py:93–95` passes that actual runtime GID into `RuntimeActionBrokerConfig`.

The frozen journal at `runtime_http_run_submission.py:217–220` loops over both `uid` and `gid` and rejects runtime equality with either broker value. Consequently it rejects the real shared runtime GID before journal initialization completes. Omitting `expected_runtime_gid`, inventing a different broker GID, changing the service account or asserting the incompatibility away is not an integration fix.

Root is considering a narrow explicit compatibility repair: preserve distinct runtime/broker UIDs and actual saved/effective identities; permit the actual shared GID only with the existing broker-owned control `0700`, lock `0600`, immutable publications `0400`, root-owned nonwritable ancestry, and the reviewed supplementary-group/access protections intact. This document does not approve or implement that change. Root must settle exact enforcement and path ownership, publish its contract, review the changed closure and schedule only newly necessary checks. Until then the four-path caller assignment is not released and the known journal hash below remains the incompatible predecessor hash.

## Exact existing repository dependency closure and its limits

The following is the complete existing **repository-source** project import closure, including inert package initialization and local imports, of the actual `ReaderCheckpointSession` and `runtime_http_run_submission` entry modules, obtained by static AST traversal. Each path is under `src/aragorn/`. No project code was imported or evaluated. All other direct imports in this closure are Python standard-library modules; the selected Python/toolchain and Linux ABI still belong in any eventual stage fingerprint.

| Existing module | Bytes | Full repository SHA-256 |
| --- | ---: | --- |
| `__init__.py` | 78 | `4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01` |
| `native_phase3_broker_reader_protocol.py` | 9400 | `8d17e7930d2c560ade4b5c0fb5b539e00ecbfb3fb9f40d910d271dd42eb48007` |
| `native_phase3_clock_domain.py` | 9543 | `600d5da48f4a5b4702245936972c796162ca01b37c74f0ac46ea6c619ed82a7b` |
| `native_phase3_run_acquisition.py` | 7939 | `80afdbcab0a4a076712b65db22b091b0a1276ae952ee276a76c1b83ffe06652e` |
| `native_phase3_run_reader_acquisition.py` | 5487 | `66cce03e029441d01bd7de72f67da0bd927259a292be28e3e5555a0b0a353fe1` |
| `native_phase3_run_reader_checkpoint_acquisition.py` | 27669 | `0fe4a8a8a1bf86839fa4a7fa1bd6ecb8b5fd56e5e3ff9a1f1ad50f8ed5889d22` |
| `native_phase3_run_reader_checkpoint_session.py` | 58910 | `dcf897c9f2b501e1c29287051812fa8969e2b7522da518270d62bb2bafdc442a` |
| `native_phase3_run_reader_checkpoint_verify.py` | 17541 | `460d25fbc8eb8cd53d2fedf7802313d7f157c22b122c0151e92e42cbd3a92cb4` |
| `native_phase3_run_reader_evidence_verify.py` | 16620 | `ee6eba09de97df0c1b2f9eeeb74e22849e56d7c876a11daf211e1d626d7abbf0` |
| `native_phase3_run_reader_response.py` | 20767 | `769cdf49fc380f97048ebe01ca2227b71584b19e8715c76ca2629dee3037d51b` |
| `native_phase3_run_reader_store.py` | 8256 | `24dbd8cdba584a55e7a787952dfa5a12d96c8b040973537c569dd52f582aba98` |
| `native_phase3_run_reader_transport.py` | 43168 | `609a5a32c33a4bb5ae0dec45eb6637b9d5b853e00797308244a92b1e86aa5fe0` |
| `oci_worker_protocol.py` | 22775 | `0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b` |
| `runtime_action_broker.py` | 79641 | `94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21` |
| `runtime_action_decision.py` | 17731 | `3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d` |
| `runtime_action_observation_publisher.py` | 21163 | `288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90` |
| `runtime_http_run_submission.py` | 30288 | `b80fc8b0d0d51d430d35eaf665f2535d1418a1c085a9f975b99f67c351edc51b` |
| `runtime_process_profile.py` | 16131 | `a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68` |

This table is not the final installed closure. In HTTP94, for example, `runtime_action_broker.py` installs as `sha256:b02b809c58a96957ccb539ad7d15fa34fe3e960c828a329fe7f3956e6ebf8354`, and `runtime_action_observation_publisher.py` installs as `sha256:48920fd3ef5e18d6535dccefb183d1c0ee34df95647dafa9a2f2054df959f409`. The generated broker imports the generated measurement module, expanding the installed import graph. The old report supplies these generated byte pins; original-source hashes must not be substituted into deployed inventories.

For the existing 22 selected HTTP measurement sources plus codec/journal, repository AST traversal reaches 34 modules before package initialization and future client code. The exact additional source-name set is `acquire.py`, `cas.py`, `native_phase3_broker_reader_protocol.py`, `native_phase3_http_fixture.py`, `oci_worker_protocol.py`, `runtime_action_decision.py`, `runtime_action_service_v2.py`, `runtime_active_skill_lineage.py`, `runtime_http_provisioning.py`, `runtime_http_run_submission.py`, `runtime_lineage_capability_issuer.py`, `runtime_process_profile.py`. Of these, codec/journal are absent from the old 94 installed files. Generated import additions must also be applied: the measurement core/grant/service imports, HTTP capability/ingress/readiness branches and worker endpoint-journal/receipt/startup imports are real dependencies. `materialize_runtime_native_tool_receipts.py:74,156–159` and `materialize_runtime_worker_ingress_measurement.py:165–167` demonstrate why original-file AST traversal alone is insufficient.

The final exact client/service/generated/test closure does not yet exist. New client/service imports, bootstrap-generated imports, any journal repair, installed writer/bridge/launcher dependencies, and locally authored test fixtures must be inventoried after stable implementation. The four paths cannot be declared closure-reviewed from the 18-module table or the old 22-entry selected inventory. No new source hash, loaded-module identity or generated-code fingerprint is invented here.

## Inventories and capture successors still unimplemented

The following work is required before installation/capture readiness can be claimed, and is not implicitly assigned by this review:

- One final installed inventory covering the actual new client/service/codec/journal and full provider/session/listener/reader/checkpoint/independent-consumer closure, both original and generated dependency origins, selected interpreter/entrypoint/units, and the actual launch/cancellation/bridge route. The proposed IPC `source_inventory_raw` remains distinct from epoch individual source pins and from measurement binding source pins. File readbacks establish byte custody, not Python loaded-code provenance.
- Three matching generated measurement inventories (`runtime_broker_decision_measurement`, plan, independent replay), the actual binding bytes and protected service credential read. Keep the 8192-byte boundary until actual final canonical length demonstrates a necessary reviewed change; do not raise limits speculatively.
- Matching generated `native_phase3_common_identity.py` and `native_phase3_common_process_verifier.py` inventories, credential/argv observations and independent replay. `materialize_native_phase3_http_identity.py:165–192` and `materialize_native_phase3_http_ready_helpers.py:140–148` currently bind the old selected source count and file count.
- A successor preparation/capture composition with its actual source-path, generated-output and report pins. `materialize_native_phase3_http_credential_helpers.py:17–38` fixes old report bytes and counts; `materialize_native_phase3_http_credential_capture.py:40–61,104–107,144–165` joins the old full source set and consumes the retained report without restaging during preparation. Leave these predecessors unchanged. A future report must identify actual changed outputs and retain the old report as predecessor, never relabel it as the new installed profile.
- Exact generated entrypoint/unit/activator changes once bootstrap is fixed. Existing capability activator `/usr/libexec/aragorn/activate-runtime-capability-host.sh` is 17054 bytes, SHA-256 `7a633393705af4c0862a957f6b9e32fef85adecbcba254ebb9e75415858e07f7`; worker activator `/usr/libexec/aragorn/activate-runtime-action-worker-host.sh` is 53551 bytes, SHA-256 `90544b98e652362d49765aec77896c622d170907f97b8d1dc23c89a7930a367a`; both mode `0755`. Preserve the predecessor's early source checks. Update the subordinate capability activator before the worker manifest pins its completed bytes; exclude activators from their own early pin set to avoid self-reference (`stage_runtime_phase3_http_credential_profile.py:67–85`).

The credential capture helper/renderers and retained report are therefore dependency inputs to any later setup/attempt successor, not a reason to run unchanged old stages now. Final staged counts and hashes must be obtained from actual new bytes after an explicit reviewed stage release, never guessed in advance.

## Pending ownership, evidence and remaining steps

The smallest proposed new source assignment remains exactly:

1. `src/aragorn/native_phase3_broker_reader_service.py`.
2. `src/aragorn/native_phase3_broker_reader_client.py`.
3. `scripts/materialize_runtime_http_run_guard.py`.
4. `tests/test_runtime_http_run_guard.py`.

These paths are **pending**, not released. A frozen-journal compatibility change and generated launch/staging/identity/capture changes need their own exact Root-owned assignments. They must not be smuggled into the four-path renderer assignment or left as runtime identity fiction.

Completed: retained report and generated input pins verified by reads; count-one owning boundaries, immutable pending requirement, original timing/lock/ambiguity joins and current dependency distinctions identified. No successor source, registry entry, focused result or installed inventory was produced by this review.

Concrete blockers: exact protected bootstrap/configure/FD contract; real shared-runtime-GID journal compatibility; final generated entrypoint/unit allowlist; actual stable client/service/generated/test closure and reviewed Linux access/credential/PIDFD/socket profile. Typed loss remains explicitly unavailable; source release of a refusal path does not close that gap.

1. Resolve and publish the bootstrap/configuration and journal compatibility contracts with exact ownership; then release the bounded four-path refusal implementation.
2. Review stable original/generated sources and complete dependency closure; register and schedule only newly necessary focused owning-call/composition cases. Preserve their actual results and fingerprints.
3. Complete the actual launch/source/identity/capture successor and protected typed loss path before separately releasing positive two-phase effect authorization. Maintain the same original acceptance, deadline, journal and submitted-ambiguity semantics.
4. Close remaining admission/RUN/workload/broker/metrics coverage and publish a reviewable implementation freeze candidate. Operational qualification, private retention and cleanup remain separately held; Phase 3 is not declared finished.
