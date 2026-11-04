# Pi-core D2 batch 8: native client and START endpoint binding

Date: 2026-11-03. Base: `849ec51fb9ce6dfd3af9ba3c012c7b43d1174a98`.
Scope: reviewed source, only new/affected offline checks, one affected isolated
compiler-only build, verified signed commit and ordinary branch push. No live
runtime operation, deployment, provider call or acceptance is authorized.

## What is connected

The request-only Pi worker now has a distinct native client factory. It reuses
the frozen legacy request codec and transport, fixing the destination to
`/run/aragorn-pi-bootstrap/requests/request.sock` with supervisor UID 0. There is
no caller-selected endpoint, alternate transport, new dependency or effect path.
The client checks Linux real/effective worker UID/GID and absence of unrelated
groups, binds session/run to the exact activation, validates and rebuilds the
canonical request, and spends its single request slot even on refusal or failure.

The client checks the fixed root-owned ancestor chain. The unchanged transport
checks the root:Pi-GID directory (`0711`) and socket (`0660`), canonical path and
identity before/after connection and result receipt. If Node exposes peer
credentials, the existing helper also checks root UID; where it does not, the
client claim stops at protected endpoint ownership. Root's independent
accepted-Pi-process/PIDFD validation remains the actual worker identity boundary.

Protected launch configuration opts in with `native_request=True`. It derives
the exact v2 START endpoint from the fixed path and configured worker identities;
it never takes a root endpoint override from the caller. Native START has one
tool-call budget and no legacy `relay` field. The distinct v2 configuration
digest also retains the legacy relay as a denied/masked path. That path cannot
equal or mask an ancestor of either protected endpoint. Default v1 START and
configuration digest retain their original byte shape and nonroot relay rule.

The supervisor requires native mode and typed request channels together before
prerequisite checks. Once the launch plan is held, its exact START bytes and
worker UID/GID must match the protected configuration before native resources
are created. The existing mount projection and dispatch/sensor/broker cleanup
ordering are reused, not replaced.

`runPreparedNativePiEntry` connects v2 START to the real pinned Pi loop using
only the fixed native factory; callers cannot inject a substitute relay. The
legacy injectable entry refuses v2. The native composition accepts an explicit
in-process provider function as a future integration seam, but the current
native bootstrap never calls it: `provider_status` remains `UNAVAILABLE`, no
request is emitted, and the worker waits for RELEASE.

## Deadlines, uncertainty and evidence ceiling

The original client deadline is captured once; the native composition caps it
to both the supplied original deadline and the START run budget. The frozen
transport's shorter **750 ms cap** remains unchanged. There is no reconnect,
automatic effect retry or timeout renewal. A later useful pilot must measure
whether that cap accommodates its real measurement/authorization path.

Cancellation is cooperative: JavaScript timers cannot preempt synchronous
filesystem metadata work inside the frozen helper. Such work may cross the
deadline before request bytes are sent. The new client rejects late completion
as `INDETERMINATE`; it does not claim a hard no-send boundary or falsely assert
`NOT_SUBMITTED`. The protected root/broker original deadline is the authoritative
effect-time boundary. Unknown post-transport or replaced-ancestor outcomes also
remain indeterminate and the client slot stays consumed.

No live Pi/Node target, native supervisor, sensor, broker, listener, provider,
effect, VM startup or capture was run. Developer Node ran only inert fixtures
with network/process entry points trapped, mocked OS identity/metadata and
in-memory root sockets. The real Pi loop used a scripted in-process provider;
its authored replies prove adapter wiring, not real effect, attribution, health,
confinement or cleanup. `PROVIDER_UNAVAILABLE`/`NO_REQUEST` is still not a useful
D2 pilot. No mapped requirement or Phase 3 gate is marked qualified.

## Focused verification and compilation

Disjoint lanes owned the Python START/supervisor boundary, TypeScript
client/entrypoint, and inert Node fixtures/checks. Cross-review and coordinator
review completed before execution. The code-review skill influenced the strict
v1/v2 separation, rejection of injected relays, and explicit cooperative-timing
claim ceiling. A bytes-versus-object fixture mistake was corrected during source
review, before any test ran.

All **83 new or affected checks passed once**, with no failed run or rerun:

| Selected stage | Checks | Exact successful fingerprint |
| --- | ---: | --- |
| `pi-core-native-start-offline` | 30 | `sha256:f0117efade7bba8fc1f7e5e00db3776707a4fe415fe24f9a21d0e852d1023aaf` |
| `pi-core-native-client-offline` | 48 | `sha256:026354cf0980b7f1ce63821b3a890f04febd73354f706bb70a8a487166207080` |
| `pipeline-capacity` | 4 | `sha256:268019741f071d5a250a03ecb7a32f1ea8b84087aa1bda4ab9360a1d9ffcce2a` |
| `pi-core-linux-compile` | 1 | `sha256:53f62a20e5eb4f70910ea3bdf34d5647a9660b87682f9b028508f77ef649c3f2` |

All ran through `scripts/phase3_pipeline.py` using reviewed explicit input
closures in `benchmark/phase3-pipeline-v1.json`. Capacity rose only 149 to 151
for the two new stages. The 30-check stage comprises 25 new checks plus exactly
five affected native-request integration checks; other imported fixture classes
were not scheduled. No broader historical stage, schema sweep or OS assembly ran.
Retained logs stay in the exact local pipeline fingerprint directories.

The one affected compiler stage first verified the already-running explicit
Colima daemon and pinned tool/archive/dependency bytes, then ran only the static
Linux compiler in a network-none, nonroot, capability-dropped owned scratch
container. Both owned container and image were verified absent afterward.
The target Node and worker were not executed. Adapter source was strictly
compiled; upstream declarations retain the existing `skipLibCheck` limitation.

The new [compiled checkpoint](../../../packaging/pi-core/compiled-artifact-v2.json)
retains the receipt, exact source/output digests and cleanup. Deployment inventory:
`dfbe1d90a12b632bca034cb6727b141a37b20fc82bdb1934ccca95fd0cd2380e` (12,694 entries).
The earlier compiled checkpoint remains untouched. Target Node bytes and static
OS/library inputs are unchanged, so `os-artifact-v1.json` is reused without
reassembly or historical recapture; this is not new ABI/kernel/installed proof.
Historical OS assembly inputs remain historical and are not relabeled as v2.
Full binaries/inventories remain local rather than published in Git.

The original 48-ID manifest, approved 29-requirement design mapping, frozen
predecessors, retained successes/failures, unrelated drafts and operational/
private-retention cleanup holds remain unchanged. The ignored
`.aragorn/pi-core-native-client-batch-8-release.json` records the resulting
signed commit, signature verification and exact remote readback after push.

## Remaining plan

1. **D2 in progress; client/START binding implemented:** connect protected
   provider/data mediation, exact service/channel provisioning and lifetime,
   consumed-code custody, and Pi-aware effective-receipt recovery/rotation.
   Then, only with separate live authorization, demonstrate a useful allowed/
   blocked task with independent health, outcome and cleanup evidence.
2. **D3:** complete managed lifecycle/admission, RUN/sensor-health, remaining
   actions/workloads and paired tasks on that same deployment.
3. **D4:** implement the approved 29-requirement mapping and complete independent
   verifier inventory, then freeze the complete deployment once.
4. **D5:** separately authorize fresh final acceptance, retain real metrics and
   cleanup, and replay evidence offline. Phase 3 remains incomplete.
