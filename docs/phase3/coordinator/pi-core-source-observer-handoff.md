# D2 source observation: bounded ptrace acquisition handoff

Status: source implementation only. No import execution, tests, builds, tracing,
activation, VM changes or Git operations were performed by this lane. The
coordinator owns reviewed pipeline registration, focused checks and release.

## Owned files and checks

- `src/aragorn/pi_core_source_observer.py`
- `tests/test_pi_core_source_observer.py`: **54 new focused test methods**, inert
  kernel/proc/descriptor fixtures only. Includes direct health-boundary tests
  using the actual local custody guard, activation validation, syscall/read
  acquisition and fresh challenge; substituted kernel/proc data are never live
  evidence. No subprocess or real ptrace is used by these tests.
- This handoff.

The independent consumer owns `pi_core_source_observation_verify.py` separately.
Its production imports do not include this producer. Its one synthetic
producer-to-replay test can reuse `build_inert_source_capture()` from the test
module; expected fixture pins are supplied before producing the capture.

Static import closure begins with this module, `pi_core_native_supervisor`,
`pi_core_bundle_launch`, `pi_core_confined_launch`, `pi_core_worker_identity`,
`runtime_process_profile`, and `oci_worker_protocol`, plus their actual transitive
imports. The coordinator calculates and reviews the complete registry closure.
No frozen predecessor or existing reader loss claim is changed.

## What the producer actually implements

`arm_pi_source_observer(owned, *, gate_path, gate_digest, node_path,
node_digest, sources, bindings, deadline)` explicitly opens a new observation
lifetime. It requires root on Linux arm64, the exact held native unit/plan and
prepared bundle, a live PIDFD/starttime, immutable unit/cgroup identity, and a
root-protected stopped pre-exec gate. Existing direct env-to-Node plans fail.

The fixed paths reuse `/opt/aragorn/pi-runtime`: the proposed gate is
`observer/source-gate`, Node is `node/bin/node`, and the entrypoint is
`pi-core/entrypoint.js`. The gate is **not installed or integrated by this batch**.
The gate artifact and its exact stopping/exec protocol still need implementation
and separate review; merely finding a process in stopped state is insufficient.
The factory additionally requires the pinned installed producer origin
`/opt/aragorn/src/aragorn/pi_core_source_observer.py`.

After `PTRACE_SEIZE`, an actual `PTRACE_INTERRUPT`/`waitpid` stop is acquired before
Node exec. All wait and syscall stops are retained. The fixed Node TRACEEXEC event
must follow execve entry and precede its successful exit. On each source
read/pread64 entry the producer duplicates the actual descriptor via PIDFD,
checks its immutable regular-file identity against the required inventory, and
hashes that held descriptor using pread. On completion it checks return count,
unchanged identity/bytes, exact shared offset for read, and records the returned
range. Required source paths, including empty files, need successful completed
read observations; all nonempty bytes need complete range coverage.

Files are root:root, nonwritable, single-link regular files with protected
ancestry; source files are bounded at 16 MiB. Gate/Node checks reuse the existing
256 MiB executable bound. Leaf opens are nonblocking and reject nonregular files
before hashing. Held files, retained PIDFD, exact original plan/leases and unit
generation remain guarded. The operator-provided runtime, deployment and Node
pins are joined to the actual held plan, not accepted as free JSON authority.

`guard_source_health(*, activation, deadline)` requires the exact owned activation
bytes and protected readback, expiry, context, source-manifest, PID/starttime,
UID/GID, mount/time namespace, cgroup, runtime/deployment and executable binding.
It then acquires a fresh 64-hex nonce challenge through resume/interrupt/wait,
with an exact **100 ms** challenge budget and no deadline extension. A syscall
entry racing the requested interrupt is a permanent refusal, not an automatic
retry. Every historical challenge remains retained with a unique nonce. A raw
capture never grants authority; callers must hold the exact sealed observer and
its original `_owned` object.

## Deliberate unsupported routes and remaining mandatory blockers

This backend supports **one task only** and a narrow arm64 syscall allowlist.
Fork/clone/thread inventory expansion, unsupported signals/transitions,
unclassified read descriptors, readv/preadv, legacy AIO, io_uring, process-memory
reads, FD exchange and file-backed mmap all refuse permanently. Anonymous mmap
is allowed without any JavaScript-behavior claim. No implicit fallback exists.

Consequently **ordinary dynamically linked/threaded Node startup is unsupported**.
This batch does not close independent worker-source identity, sensor health, D2,
the seven RUN event classes, or Phase 3. Before native use, engineering must:

1. Implement and bind the exact pre-exec gate and retained tracer owner lifetime
   into native launch before initial worker loading, not after HELLO.
2. Complete legitimate OS/ELF loading, known-TID all-stop acquisition, every
   permitted Node source-loading route and FD custody; refuse any remaining
   unsupported path instead of relabeling it healthy.
3. Integrate raw retention/CAS publication and independently held verifier pins
   with the existing collector and lifecycle. Observation JSON alone is not
   acquisition-authenticity evidence or active authority.
4. Establish a trusted observer interpreter/source-loader chain. This module's
   protected on-disk origin/hash check does not prove its own executed in-memory
   code, nor does worker source-read evidence prove arbitrary V8 behavior.
5. Measure actual collection/challenge/task intervals. Repeated executable hashes
   and unit readbacks are intentionally conservative and potentially expensive;
   timing feasibility is unmeasured. Do not widen the 100 ms budget to conceal it.

The inherited-descriptor/gate contract and exclusion of external untrusted shared
open descriptions remain part of native integration. The one-task restriction
prevents worker-thread offset races; it does not claim security against a hostile
root or arbitrary unsupervised FD sharers.

## Raw contract and custody-safe cleanup

`aragorn/pi-core-source-observation/v1`, architecture `linux-arm64`, contains exact
deployment/runtime/gate/Node/producer/inventory pins, worker/unit/clock identity,
immutable sources, ordered ARMED/STOP/EXEC/READ_ENTER/READ_EXIT/CHALLENGE events,
state and reconstructible counters. The canonical inventory is
`aragorn/pi-core-source-inventory/v1`. Limits are 4 MiB and 4,096 records, with
eight records reserved from normal acquisition for bounded refusal/cleanup.
There are no invented zero-loss counters. Unsupported/refused/closed captures
cannot qualify coverage; retained offline consistency is not live health.

Failure retains the observer on `PiSourceObserverError.observer`, attached trace
custody, PIDFD and owned descriptors. EXITKILL remains armed; there is no detach,
effect retry or implicit task resume. The same tracer thread must remain owned
until cleanup. After the existing supervisor initiates exact-unit cleanup,
`drain_owned_exit(deadline=...)` may release only an actual ptrace EXIT stop and
retains terminal wait records. It never signals or resumes an ordinary stop.
Expired cleanup budgets remain holds; no deadline renewal is inferred.
`close_after_exit()` requires confirmed death before closing traced-task handles.
An ambiguous close is recorded once and cannot retry a potentially recycled FD.

The independent replay result is only `CONSISTENT_SOURCE_READ_COVERAGE`; acquisition
authenticity, active runtime authority, V8 execution, and Phase 3 qualification
remain false. No native unavailable default is enabled here.

## First focused run: fixture-only correction

The coordinator's first observer fingerprint
`cea50ed4f359285fa18fe7e01018164a4d90496e445b95aedb79b56cb9128993`
is retained as failed. Its inert Linux wait-status fixture was decoded using the
macOS host's unmasked `WSTOPSIG`, which included Linux ptrace event bits. The
fixture now explicitly supplies Linux stop/signal extraction; production Linux
acquisition is unchanged. A partial frozen-plan copy is now assembled from its
explicit populated fields, and traceback formatting is isolated from fake proc
metadata. This lane did not rerun checks or alter pipeline records. The
coordinator must select only failed or unrun checks after review and preserve
already successful individual results under the reviewed recovery policy.

Primary ABI references used during design: [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html),
[pidfd_getfd](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html), and the
[pinned Node libuv read implementation](https://raw.githubusercontent.com/nodejs/node/v24.22.2/deps/uv/src/unix/fs.c).
