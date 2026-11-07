# D2 source-observation replay handoff

Status: source implementation prepared for coordinator review; no tests, imports,
builds, live operations or Git operations were run by this lane. This is an
independent offline consumer, not a runtime-health credential or final D2 gate.

## Exact scope

`verify_pi_source_observation` consumes the additive
`aragorn/pi-core-source-observation/v1` capture produced by the bounded Linux
arm64 observer. It does not import that producer. It reuses existing CAS and
canonical JSON rules, including duplicate-key/noninteger rejection. The caller
must independently hold the observation digest, deployment/runtime/gate/Node/
producer/source-inventory pins, captured worker identity, clock domain, gate
identity, final challenge and operation-boundary time.

Raw capture and source inventory must already be retained in CAS. The source
inventory fixes path, complete digest and opened-object identity (device, inode,
mode, link count, ownership, size and modification/change times). Every raw source
must exist in CAS and match its complete pinned size/hash. Regular root-owned,
nonwritable source objects cannot be substituted or aliased by another inventory
entry. Neither pathname reporting nor `/proc` hashing alone qualifies identity.

The consumer reconstructs:

- Armed acquisition at the stopped gate before the one pinned Node exec event.
- Every retained syscall entry/exit pairing, including successful fixed exec;
  duplicate/orphan stops and missing source-read records refuse.
- Actual completed `read`/`pread64` ranges from the captured opened object, offset
  and positive return count. Short reads cover only returned bytes, EOF covers
  none, and errors cover none. Full range union is required for each source;
  empty sources still require a recorded read attempt/completion.
- All retained event, stop, read and byte counts with no pending syscall/read.
  Unknown counter fields, unknown events and unsupported access modes refuse.
- Cumulative unique challenges across repeated guards. Each challenge requires
  an actual new interrupt STOP128, exactly one acquired stop, all-stop ownership,
  no pending syscall, and a 100 ms response budget. The final challenge must
  match the caller-held nonce/interval and be less than 200 ms old at the held
  boundary. Old evidence is not erased when a new challenge is issued.

Capture bounds are 4 MiB and 4,096 events; each pinned source is at most 16 MiB.
The source inventory allows at most 512 entries. Counter/record omission cannot
be repaired by asserting zero loss or inserting a PASS receipt.

## Explicitly unsupported

The current producer is single-task Linux arm64. Its small explicit syscall
allowlist rejects unclassified calls, threads/forks, alternate read mechanisms,
file-backed mappings, process-memory access and later exec. Pre-exec execution
permits only the fixed execve transition. The replay independently applies the
same narrow ABI and bounds; it does not import producer constants as evidence.

Normal dynamically linked/threaded Node startup remains blocked. No changed
deadline, silent exclusion, fabricated event, or synthetic zero-loss report is
used to work around that. A refused or closed capture is preserved but cannot
qualify source coverage through this entrypoint.

## Meaning and non-authority

The only positive status is `CONSISTENT_SOURCE_READ_COVERAGE`: recorded complete
file delivery is internally consistent under independently held input pins. The
result explicitly keeps acquisition authenticity, sensor health, effect
authority, V8 execution and Phase 3 qualification false. A JSON record cannot
mint a live lease or prove that an arbitrary JavaScript buffer was executed.

Protected runtime gating remains the responsibility of the sealed live observer
lease, original process/unit custody, actual acquisition and safe cleanup. The
legacy reader checkpoint, transport, store and independent replay modules remain
unchanged with their UNKNOWN upstream continuity/loss state.

## Verification handoff

All 59 statically counted checks are inert. The new test module covers source/gate/process/clock
substitution, strict parsing, raw stop conservation, partial reads/EOF/errors,
range coverage, unsupported startup, exact accounting, challenge freshness and
cumulative challenge replay. The coordinator owns reviewed stage registration,
the first focused execution and any necessary diagnosis.

The producer-to-consumer check uses `build_inert_source_capture` from the new
producer test module. Expected pins/identities are prepared before capture; the
actual producer wait/read/challenge methods generate records under mocked
kernel/proc/guard boundaries, then raw records and sources pass through CAS into
the independent consumer. This is synthetic contract integration, not acquisition
authenticity. Only the helper is imported; its test cases are not added to this
consumer stage.

Consumer closure (plus producer fixture closure below):

```text
src/aragorn/__init__.py
src/aragorn/cas.py
src/aragorn/oci_worker_protocol.py
src/aragorn/phase3_exit_gate_manifest.py
src/aragorn/pi_core_source_observation_verify.py
tests/test_pi_core_source_observation_verify.py
tests/test_pi_core_source_observer.py
```

The producer-to-consumer inert integration fixture also requires
`src/aragorn/pi_core_source_observer.py` and the exact reviewed transitive closure
already registered for the producer's focused stage. It runs no live tracing or
process activation. No test execution was performed by this lane.

## Remaining work

1. Review/run only the new observer, replay and affected guard stages; retain any
   failure fingerprint and diagnose the real cause before an affected rerun.
2. Resolve the explicit dynamic-loader/threaded startup limitation with actual
   acquisition completeness, not exceptions to this contract.
3. Connect an owned pre-exec gate and continuous observation to the common native
   deployment, then retain a separately authorized useful pilot with independent
   source, health, timing and cleanup evidence.
4. Complete D3 surfaces and real independent consumers, freeze D4, then perform
   separately authorized fresh D5 qualification. This batch closes none of those
   live acceptance gates by itself.
