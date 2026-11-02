# Protected copy/readback context contract v1

Coordinator base: `b3fca83615cd6fd69b463ca8cebcebc660990dec`.
This supplies the concrete interface for the reviewed workload plan. It is a
design contract, not a deployed provider, execution result or qualification.
After lane agreement and publication of the containing signed checkpoint, the
coordinator may release the finite mocked leaf. Tests require a separate stable
source/closure review, registry entry and explicit scheduling.

## Ownership and call boundary

Workload owns only the new copy producer, independent consumer, focused test and
handoff named in `docs/phase3/workload-verifiers/copy-readback-plan.md`.
Coordinator owns context provisioning, protected inventory, top-level dispatch,
launch/supervision, actual paired environment selection, staging, source pins,
collector/replay composition, scheduling, retention and later cleanup.

The lane signatures are fixed:

```python
execute(request, mark, *, copy_directory_fd,
        expected_copy_directory_identity, expected_fixture) -> bytes
verify(raw, request, boundaries, *, copy_directory_fd,
       expected_copy_directory_identity, expected_fixture) -> dict
```

The coordinator's later source-pinned module exports top-level
`execute(request, mark)` and `verify(raw, request, boundaries)` functions. Each
independently resolves the protected context below and calls its corresponding
lane leaf. Existing collector/replay signatures and request schema stay intact.
No closure, partial, callback factory or global mutable FD registry substitutes.
This contract does not claim those dispatch functions already exist.

## Exact context binding

Use the existing strict eight-key request validator in
`native_phase3_workload_json_sum_contract`: kind, mode, pair_id, task_digest,
input_digest, host_profile_digest, collection_digest and deployment_digest.
The inventory key is `sha256:` plus SHA-256 of canonical request JSON. A request
is admitted only if its complete canonical bytes match the independently pinned
protected inventory entry; a receipt cannot choose its own expected context.

One immutable root-owned inventory record binds these exact fields:

- `schema`: `aragorn/native-phase3-copy-context/v1`;
- `request`: the exact validated request;
- `directory_name`: the request digest's 64 lowercase hex characters;
- `directory_identity`: device, inode, mode, uid, gid, all exact integers;
- `fixture`: the exact existing validated native HTTP fixture descriptor;
- `source_inventory_digest`: the coordinator's complete deployed source pin;
- `environment_digest`: the independently selected actual environment pin.

The record's canonical bytes are pinned by an independent protected inventory.
The root and ancestry are fixed by the source-pinned launcher, never selected by
request/receipt data. Records are read-only root-owned single-link regular files
with no-follow held ancestry and before/open/named/after identity checks. Context
records and fixture data stay under outer custody; portable receipts carry only
the existing permitted identities/digests. Reuse existing protected-reader
patterns rather than broadening path permissions.

`copy_directory_fd` is an already open, caller-owned directory descriptor.
Its independent expected identity is exactly device/inode/mode/uid/gid, with
0700 and the current root UID/GID required by the existing reference task.
FD numbers have meaning only inside that invocation. The lane snapshots expected
dictionaries, duplicates only when needed and closes only its owned descriptors.
Coordinator holds the original through the call, final guard and its own close.
The independent verification dispatch reopens and revalidates context from the
protected inventory; it does not trust the producer's FD or emitted context.

## One execution, fresh residue and interruption

Before invoking the producer, coordinator durably consumes a request-keyed
exclusive claim using O_EXCL creation, file fsync, parent fsync and protected
byte-identical readback. Occupied, partial, ambiguous or failed claims refuse.
The claim remains spent after interruption/failure. Do not use the existing
whole-commitment attempt consumer for individual paired tasks.

Provision a newly created private directory for every invocation, including both
baseline and instrumented halves. Retain prior directory handles, identities,
claims and residue mappings and reject reused device/inode identity. A different
FD number alone proves nothing. Create only the existing literal
`allowed-copy.txt` with O_EXCL; an existing entry refuses. Neither lane nor
dispatcher removes, overwrites, truncates, repairs or automatically substitutes
a new directory to retry a failed request.

The producer uses the existing reference task once between actual supplied
TASK_ACCEPTED and TASK_COMPLETED marks. Completion follows successful task and
final custody/close guards. Independent verification reads the retained file
through its own guarded descriptor and validates exact bytes and identity.
The reference task closes its file FD before returning: this proves post-task
retention identity, not uninterrupted inode continuity from creation.

Blocking write/fsync/read calls have no hard in-process deadline. The coordinator
supervises the owned guest worker/fixture using the existing bounded guest and
suspend-preserved capture boundary. Cancellation stops further sample dispatch,
retains the claim/directory/partial output and records uncertainty until the
exact guest worker is confirmed stopped. Killing a host Docker client is not
proof of guest termination. The leaf adds no timeout thread or retry. A pipeline
timeout bounds tests only; this document does not implement supervision.

## Environment and replay limits

Coordinator selects actual independently inventoried baseline and instrumented
environments, verifies their source/config/process/sensor bindings, and supplies
the environment digest. A request's mode label is not evidence of instrumentation.
The two tasks retain distinct directories and context records within one fixed
collection/deployment and pair. Missing selection/custody refuses composition.

Replay requires the original retained directory, protected mapping and still
valid fixture. Existing `owned_http_fixture` checks the original process/boot/
namespace context; receipt-only or relocated post-cleanup replay is not supplied.
Independent replay therefore precedes any separately authorized fixture cleanup.

No existing collector, replay, reference-task or frozen staging source changes
are transferred to the lane. Native execution, product cleanup, historical
reruns, cache copying and automatic unchanged retries remain prohibited.
All qualification flags remain false.
