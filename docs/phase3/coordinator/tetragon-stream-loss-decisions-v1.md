# Tetragon stream custody and loss-accounting decisions v1

Status: coordinator decisions and source review only. This document grants no
source-path assignment, test stage, service start, sensor connection, protected
write, private retention or cleanup permission. Root must publish a separate
exact implementation contract before releasing any new slice. Existing lane
assignments remain unchanged.

Reviewed against the decisions in `reader-loop-next-release-review-v1.md`, the
published reader transport contract and broker reader/provider contract. The
selected upstream candidate is Tetragon commit
`1de2ed8ebea18e56257dc59597aa13bf8f0e471e`. The retained candidate/loss/stats-map/
program-map locks cover selected source only. They do not supply a complete
build, installed executable hash, loaded-program identity or live stream.

## Immediate bounded reader decision

Proceed toward an honest local pipe/checkpoint implementation while leaving
upstream continuity `UNKNOWN`. Its allowed claim is that the pinned reader
performed its actual bounded consuming-loop turn and retained particular raw
bytes under the reviewed local custody rules. It cannot authorize an effect or
claim subscription completeness, sensor health, complete process attribution,
RUN qualification or Phase 3 qualification. All such authority flags stay false.

The reusable pattern is the nonblocking stdout/stderr selector and 65536-byte
reads in
`benchmark/evidence/reference/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.py.txt:94`.
That historical Docker/VM acquisition is not the common native deployment.
Read-only searches across native/common modules, staging/materialization scripts
and service files found no current native `tetra`/`getevents` launcher integration.
Do not copy the smoke's orchestration, retries, single-marker filter or cleanup.

The producer may reuse the frozen single-record parser
`src/aragorn/runtime_tetragon_process.py:265` through a separately reviewed public
wrapper. It must not use `normalize_process_capture` by fabricating EOF,
quiescence or zero counters. An independent checkpoint consumer must not import
the producer or its private parser; framing, count, digest, contiguous offsets,
sequence, challenged read brackets and retained local error facts are its bounded
semantics. Full vendor execution/parent-graph attribution is a separate consumer.

Preserve the broker wire checkpoint bound of 16384 bytes. A bounded manifest pins
separately retained raw batches; Root's protected acquisition independently reads
and verifies those actual bytes before relying on the manifest. External replay
receives the same raw batches and manifest. Authentication of a small wire
envelope alone does not establish raw custody or semantic validity.

Candidate limits remain reads/records <=65536 bytes, batches <=262144 bytes and
256 records, whole stream lifetime <=4 MiB/4096 records. Batch-count and
publication policy still belong in the exact checkpoint contract. Compatibility
with the eventual campaign is unmeasured. Exhaustion, malformed/partial input,
EOF, changed identity, read/parser/publication failure or unaccounted bytes ends
the stream's eligibility; no drop, rotation, reset, restart or automatic retry may
hide it. Empty idle checkpoints contain no invented event. Only the actual
consuming loop can complete a challenged post-receipt read/EAGAIN turn and
durable checkpoint before ACK; a timer or receive callback cannot substitute.

## Selected process, descriptor and storage ownership

Root owns the supervisor, protected deployment/epoch credentials, actual
process/source acquisition, child PIDFDs, cancellation, fixed-path provisioning
and independent readback. The Tetragon sensor is the separately pinned privileged
process. The Python reader and successor `tetra` bridge use distinct dedicated
non-root UIDs/GIDs, distinct from the broker and workloads; the reader remains
capability-free with no-new-privileges under the frozen reader epoch. Account
numbers come from protected deployment bindings and actual saved/effective/real
account checks, never account-name lookup or incoming packets.

The selected future launch ABI is:

| Process | Exclusively transferred handles and purpose |
| --- | --- |
| Reader | FD 3 is the existing Root-to-reader notice pipe; FD 4 is bridge stdout read end; FD 5 is a distinct Root-to-reader checkpoint refresh command pipe; FD 6 is bridge stderr read end. FD 7 is reserved for the cancellation pipe if selected by the exact checkpoint contract. It alone consumes both bridge pipes and owns its challenge socket. |
| Bridge | stdin is `/dev/null`; FD 1 is its stdout writer and FD 2 its distinct stderr writer. For the successor only, FD 3 is one already connected, authenticated sensor socket transferred by Root. The bridge does not receive the notice pipe or reader storage handles. |
| Root supervisor | Owns notice/refresh writers, the cancellation writer if selected, child/sensor identity handles and independent acquisition handles. It closes every surplus pipe end before readiness and never writes telemetry into the bridge stdout pipe. Root PIDFD and supporting descriptor numbers come from protected provisioning, not this fixed child-FD ABI. |

These FD numbers are per-process. The bridge's FD 3 is unrelated to the reader's
FD 3. Launcher and children must mark surviving handles noninheritable after
their intentional exec transfer, check anonymous FIFO type/device/inode/access
flags and exact corresponding `/proc/<pid>/fd/<n>`/fdinfo joins, and exclude
unexpected inherited handles. Fixed commands use no shell and a pinned public
environment. The reader has no arbitrary command, endpoint, output-path or
truth-callback input. Root retains workload isolation and restrictions on ptrace,
FD transfer and subsequent child creation.

The distinct refresh pipe reserves a concrete route for second broker-phase
checkpoint acquisition while reusing the original ACK. Its command schema,
ordering, deadlines and cancellation semantics belong to the exact checkpoint
contract; neither refresh receipt nor cancellation readiness may manufacture a
new BEFORE_FIRST_EFFECT challenge or successful telemetry observation.

Sole pipe-writer custody is a reviewed launch/source obligation: create the pipes
once, transfer only the documented writer to the bridge, close all surplus copies
and prohibit duplication/transfer thereafter. Point-in-time process/FD scans are
supporting joins, not proof of every possible writer or hostile-root resistance.
The immediate leaf checks acquired local joins; it must not claim the current
unmodified bridge implements the successor's transferred-socket ABI.

Use a distinct proposed raw-spool root
`/var/lib/aragorn-phase3-reader-events`, reader-UID:reader-GID 0700, under Root-owned
non-writable ancestors. Exclusive immutable records are reader-owned 0400 with
bounded file/directory fsync and exact readback. Root independently holds and
checks named/held ancestry and file identities when acquiring those bytes. The
exact publication names, batches, failure evidence and cancellation contract must
be published before source release. Reader-owned records are trusted-reader
claims, not hostile-root-resistant storage. The existing Root-only
`/var/lib/aragorn-phase3-reader` store remains root:root 0700 and inaccessible to
the reader/bridge; its permanent consume-once claims are unchanged.

The additive stream inventory must distinguish reader, bridge and sensor, their
PID/start/accounts, executable/build/source/configuration identities, namespaces,
clock domain, child/peer PIDFD joins and pipe descriptors. The frozen two-role
epoch is not relabelled: its `stream_digest` pins this separate inventory. Static
expected deployment pins and actual observed installed bytes are distinct fields
of evidence. Unknown installed/connection facts remain unavailable; do not fill
them with the candidate source commit or historical image hash.

## Successor socket, retry, output and subscription boundaries

Root chooses a narrowly patched bridge from the same pinned upstream source,
with a separate sensor readiness patch. This successor is not released here.
Its source/build contract must include full actual module/generated-source/build
closure, patch identities and installed executable verification. The original
candidate image identity cannot attest modified bytes.

Root will connect once to the fixed protected Tetragon UNIX endpoint and bind
that actual connected socket to the expected sensor using SO_PEERCRED,
socket-derived PIDFD and fresh PID/start/account/boot/source readbacks. Pin endpoint
ancestry and named socket custody separately from its connected sockfs identity.
A separate successful probe is not this connection. Transfer this socket once
to the bridge, close Root's surplus connection copy, and require a one-use custom
dialer: no alternate target, resolver fallback or physical reconnect. The exact
descriptor conversion/duplication performed by Go must be reviewed and all
temporary copies closed; no implicit pool is permitted.

The fixed request selects PROCESS_EXEC and PROCESS_EXIT with no process/PID,
namespace, pod, policy, CEL or field filters and no aggregation. Pin all sensor
options and disable unused exporter/rate/suppression paths where supported by
reviewed source and loaded configuration. This selection still depends on
underlying clone/data/cache paths; it does not reduce loss scope to two opcodes or
close the full runtime event inventory.

Exact upstream patch/review boundaries, all at the candidate commit:

| Source | Required successor behavior and current limit |
| --- | --- |
| [`cmd/tetra/common/client.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/cmd/tetra/common/client.go) | Replace ordinary address-based client construction with the reviewed one-use transferred socket and fixed options. Current CLI retry settings are not continuity evidence. |
| [`cmd/tetra/getevents/getevents.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/cmd/tetra/getevents/getevents.go) | One fixed subscription, no reconnect loop, checked receive/encode outcome and explicit bounded readiness/failure reporting. Its streaming call uses SignalCtx, so ordinary CLI timeout is not a stream deadline. |
| [`pkg/encoder/encoder.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/encoder/encoder.go) | Account exact NDJSON bytes and reject short/failed writes. Current ProtojsonEncoder ignores its final Fprintln result. No successful encode claim may precede successful delivery of all bytes. |
| [`vendor/google.golang.org/grpc/stream.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/vendor/google.golang.org/grpc/stream.go), [`dialoptions.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/vendor/google.golang.org/grpc/dialoptions.go), [`stats/stats.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/vendor/google.golang.org/grpc/stats/stats.go) and [`stats/handlers.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/vendor/google.golang.org/grpc/stats/handlers.go) | Reviewed/build dependencies, not mandatory modification paths. Select the existing attempt-observation and committed-stream APIs described below; no vendored gRPC modification is released. |
| [`pkg/server/server.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/server/server.go) | The sensor must report bounded subscription-ready evidence after the exact listener is registered, on the same subscription. Its existing readyWG is internal, not an idle client readiness record. Freeze the additive header/receipt format and same-stream binding before patch release. |
| [`go.mod`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/go.mod), go.sum, vendor/modules.txt and actual imported/generated sources | The candidate selects grpc-go v1.80.0 and Go 1.26.0. Freeze actual build/toolchain closure; selected excerpts alone are insufficient. |

Bridge-only changes cannot manufacture idle subscription readiness. Sensor-ready
evidence still does not prove an empty upstream queue or live kernel progress.

Select the smaller same-source retry design: install a fixed `WithStatsHandler`
that observes every client `stats.Begin` for the one GetEvents call, counts all
attempts, records `IsTransparentRetryAttempt`, and permanently latches any retry,
unexpected method or terminal failure. Callback timestamps are not BOOTTIME
evidence. `WithDisableRetry` suppresses configured retries but leaves transparent
retries enabled; `WithMaxCallAttempts(1)` is not a solution because values below
two select the default of five. These options alone cannot admit an epoch.

The bridge calls `stream.Header()` and validates the exact nonempty sensor-ready
metadata bound to its fixed request and authenticated transferred connection.
Require exactly one physical dial, exactly one Begin, zero transparent attempts,
stable socket/process custody and no latched error before admitting the epoch.
The pinned implementation commits the attempt when Header succeeds; committed
streams refuse all retries and reuse that attempt. A nil header is failure even
with a nil error: this implementation can return nil/nil after a stream failure.
No internal resolver OnCommitted hook or premature Context call substitutes for
validated readiness. Prior-readiness failures/retries retain their observations
and cannot yield an admitted epoch; do not label them an exactly-one-attempt
success. The observation mechanism is not a claim that every failed setup makes
only one internal attempt.

After admission, preserve the same socket, committed stream and permanent
attempt/error latch for its whole lifetime. Any second dial/Begin, receive/output
failure, identity change or termination ends eligibility; never reconnect or
continue under a reset epoch. A source/build contract must define how bridge
status is retained and bound to the same connection; stderr text is not a
readiness API. This removes the need for a gRPC vendor fork while retaining the
separate sensor readiness and checked-output patches.

## Applicable loss and incompleteness inventory

Treat the following as the complete boundary inventory to close for the selected
path, not an assertion that existing counters completely measure those boundaries.
Preserve raw observations, exact applicability/labels, source/loaded identities,
sample brackets and independent interpretation for every entry. An unmeasured
boundary remains UNKNOWN and prevents a complete loss/health claim.

1. **Kernel output attempts.** Acquire the real `tg_stats_map` before/after with
   exact type/layout/CPU topology and program/map joins. Preserve per-CPU,
   per-opcode/error cells and detect decreases before any aggregation. The
   retained `benchmark/tetragon-stats-map-source-v1/bpf/lib/process.h` functions
   `perf_event_output_metric` and `event_output_metric` account perf and ring
   output failures. The exposed `tetragon_bpf_missed_events_total` family is sparse
   and its collector also emits nothing on acquisition failure; absence is not
   zero. The existing direct map snapshot is sequential, not atomic.
2. **Attachment and program misses.** Bind `tetragon_missed_link_probes_total` and
   `tetragon_missed_prog_probes_total` to every applicable loaded attachment and
   dependency program. The retained `benchmark/tetragon-loss-source-v1/pkg/metrics/
   kprobemetrics/{collector,missed}.go` obtains different link/recursion sources
   and omits unsupported/failed observations. The existing program-map helper
   covers selected exit linkage only; it cannot stand for exec/tail-call coverage.
3. **Sensor read/dispatch queues.** Retain
   `tetragon_observer_ringbuf_errors_total`,
   `tetragon_observer_ringbuf_events_lost_total`,
   `tetragon_observer_ringbuf_queue_events_lost_total`,
   `tetragon_handler_errors_total` and
   `tetragon_notify_overflowed_events_total` with their exact inventories. See
   [`observer_linux.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/observer/observer_linux.go)
   and [`observer.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/observer/observer.go).
   Queue drops/errors and perf lost samples are separate from kernel output
   failures. Shutdown may leave queued events; absence of drops is not drainage.
4. **Map, cache and attribution impairment.** Preserve
   `tetragon_events_missing_process_info_total`, selected PID/TID/finalization
   labels of `tetragon_errors_total`, `tetragon_event_cache_errors_total`,
   `tetragon_event_cache_fetch_failures_total`, process-cache misses/early deletions
   and available capacity-eviction evidence. Relevant source is
   [`errormetrics.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/metrics/errormetrics/errormetrics.go),
   [`eventcache/metrics.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/eventcache/metrics.go)
   and [`process/metrics.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/process/metrics.go).
   Event-cache pending/retry state is backlog, not a loss counter: the
   [`cache loop`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/eventcache/eventcache.go)
   can delay output and later emit incomplete information. A named metric or
   declaration does not prove it is registered/exposed in this build.
5. **Map/error accounting limits.**
   [`mapmetrics.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/metrics/mapmetrics/mapmetrics.go)
   defines `tetragon_map_errors_update_total` and
   `tetragon_map_errors_delete_total` as gauges, with map labels `execve_map` and
   `tg_execve_joined_info_map`. Their source-derived error values, capacity and
   pending entries require a distinct typed adapter; the frozen counter parser
   must not silently accept them. BPF helper-error accounting
   ([`pkg/errmetrics/metrics.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/errmetrics/metrics.go))
   is also sparse and acquisition failure cannot become zero.
6. **Suppression and selection.** Pin actual cgroup-rate, allow/deny/filter,
   field-filter, aggregation and exporter state. `tetragon_cgroup_rate_total`
   ([source](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/metrics/cgroupratemetrics/cgroupratemetrics.go))
   and `tetragon_export_ratelimit_events_dropped_total` are not substitutes for
   proving which paths are enabled. An inactive component is excluded with an
   explicit source-to-loaded-config argument, never a synthetic zero. Server
   aggregation has a separate full-channel discard path; the selected request
   forbids aggregation and field filters rather than guessing their losses.
7. **Connection, bridge and local reader.** Keep subscription readiness,
   reconnect/retry epochs, gRPC receive/termination, output encoding/write
   results, pipe bytes/EOF, partial records, parse errors, durable delivery and
   cancellation as separately bound facts. No current metric family closes this
   whole boundary. An actual EAGAIN read proves local pipe state at observation,
   not bridge responsiveness, upstream quiescence or sensor liveness.

There are earlier kernel omissions outside output-failure counts. Retained
`benchmark/tetragon-program-map-source-v1/bpf/process/bpf_execve_event.c:324` and
`:338` can return after an unsuccessful tail call without reaching event output.
`bpf/process/bpf_exit.h:36` and `:45` return on missing process/heap state. The
retained `process.h` no-init lookup has no compensating event-loss count.
Do not assert that aggregate SentFailed, loaded-map membership, or a bridge patch
measures these omissions. Root must close the exact applicable omission scope or
leave completeness UNKNOWN; not every early return is automatically evidence of
a lost required event.

`src/aragorn/runtime_tetragon_loss.py` remains its existing eight-family offline
adapter. Do not expand its claim by feeding it gauges, inventing absent series or
reusing it as complete protected acquisition. A future <=32-entry frozen loss
scope may aggregate only independently checked, complete typed raw components;
per-series resets, membership changes, unsupported reads and overflow refuse
before aggregation. Scope membership and ordering must be explicit and pinned.

## Remaining contracts, evidence and Phase 3 steps

Completed here: selected Root/non-root ownership, concrete future pipe/socket
transfer design, narrow immediate checkpoint claim, successor patch boundaries
and the loss/incompleteness inventory. No new implementation assignment is
released. Root can now author the bounded raw-reader/checkpoint contract while
the existing RUN transport and Admission replay assignments continue.

Pending concrete contracts: actual launcher/credential/FD provisioning; raw-spool
batch/publication/independent readback; fresh second broker-phase checkpoint while
reusing the original ACK; successor bridge plus sensor readiness/build; protected
typed loss acquisition and full loaded source/program/attachment coverage.
Installed byte hashes, actual process/namespace/peer identities, kernel support
and performance are observed deployment evidence, unavailable under the current
operational hold. Their absence must not be hidden in placeholder pins.

1. Implement and review exact protected provider contracts; schedule only newly
   necessary focused checks and integrate original signed deliveries.
2. Wire the complete admission-to-broker path, both action families, actual a100
   control, cancellation/full timing and all four genuinely paired tasks.
3. Close the existing 48-entry ledger with protected acquisition and independent
   consumers; freeze reviewed source and actual loaded/deployed identities.
4. After separate operational release, run the final same-deployment campaign,
   independently replay/evaluate the existing gate and perform only separately
   approved cleanup. Final qualification remains pending until then.

Historical-suite reruns, cache copying, unchanged retries, live operations,
private retention and cleanup remain on hold.
