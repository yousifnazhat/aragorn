# D2 Node source replay handoff

This batch adds an independent, bounded consumer for
`aragorn/pi-core-node-source-observation/v2`. It does not import the acquisition
producer. The v1 consumer stays frozen except for one corrected edge case:
an unsuccessful read is not a successful delivery attempt for an empty file.

## Consumer boundary

The caller supplies the observation, deployment/runtime/producer/profile and
inventory pins, worker generation, clock domain, gate identity, owned root peer
and endpoint paths, and fresh challenge. All retained inputs and file bytes join
the existing CAS and strict canonical parser; expected values are never copied
from an untrusted capture. The independent replay reconstructs:

- Leader and child TID generations, parent clone requests, actual clone event,
  initial child stop, optional first child return, terminal exit and retirement.
- Every retained resume and stop, paired syscalls, exact all-stop epochs and
  source/mapping intervals with siblings held throughout.
- Required source delivery ranges, successful empty-file reads, vector reads,
  and separately pinned ELF loader reads/mappings. Loader or IPC activity never
  fills required-source gaps; failed mappings do not count as mapped files.
- Actual declared null stdio and created internal-object identity joins, plus
  root IPC peer **and endpoint** pins. Pending, already classified owned IPC
  remains visible in accounting at a fresh all-stop boundary. Arbitrary input,
  pending source/loader/map/clone/FD-creation work, hidden tasks or missing records
  cannot produce a consistent snapshot.
- Fixed challenge budgets, fresh per-TID progress, retained loss/accounting and
  the caller's exact final challenge. This is recorded snapshot consistency,
  not continuous held effect authority.

Bounds remain 4 MiB per raw record, 4,096 events, 64 live tasks, 512 source files
of at most 16 MiB, and 512 loader files of at most 256 MiB. These limits are not
expanded to claim compatibility with an unmeasured full Node dependency tree.

## Focused checks and coordinator ownership

Only `tests/test_pi_core_node_source_replay.py` is the new consumer test target,
with 62 focused methods after the anon-inode correction. It includes two newly necessary v1 empty-file edge cases by reusing the inert
fixture helper, not by inheriting or selecting the historical v1 test suite.
The producer-to-consumer fixture must use the actual new producer's emitted raw
records with inert syscall/filesystem observations; it is not live evidence.

The coordinator owns the reviewed pipeline input closure, execution, diagnosis,
signed checkpoint, integration and push. This lane ran no tests, builds,
project imports, live tracing, services, provider calls or Git mutations. It
preserved unrelated drafts and frozen captures.

The coordinator reported that the original 60-method replay stage passed before
the anon-inode correction. The correction keys retained internal objects by
`(device/inode/mode, creation call)` because distinct eventfds can share stat
identity. The producer compares actual retained open descriptions; the consumer
checks the declared creation-record join, not a new independent kernel proof.
Only these five replay selectors are new or affected by that correction:

- `test_distinct_eventfd_births_can_share_anon_inode_identity` (new).
- `test_aliased_eventfd_identity_cannot_supply_an_unrecorded_birth` (new).
- `test_created_eventfd_has_independent_syscall_and_identity_join`.
- `test_eventfd_input_cannot_invent_creation_origin`.
- `test_eventfd_creation_cannot_substitute_output_descriptor`.

Do not rerun all 60 earlier methods for this change. This lane did not execute
the five selected checks; execution and retained results remain coordinator-owned.

Coordinator follow-up: all five selected cases passed. The complete retained
results, including the original 60 passes, are recorded in
[batch 18](pi-core-preexec-node-batch-18.md); no full replay rerun occurred.

## Evidence ceiling and remaining work

Successful replay says `CONSISTENT_REQUIRED_SOURCE_DELIVERY`, with acquisition
authenticity, active sensor health, effect authority, V8 execution and Phase 3
qualification all explicitly false. File-byte delivery does not prove arbitrary
in-memory JavaScript behavior. Deployment authentication, protected authority
consumption, complete actual loader coverage and timing feasibility still need
their own evidence; no D2 or later exit gate closes from these offline checks.

1. D2: finish the connected protected path, actual deployment identity/health,
   recovery and timing, then only the separately authorized useful pilot.
2. D3: remaining admission, RUN/health and workload producers and consumers.
3. D4: complete the 29-requirement executable inventory and independent review,
   then freeze one common deployment.
4. D5: separately authorized fresh acceptance, measurements and verified cleanup,
   followed by independent offline replay.
