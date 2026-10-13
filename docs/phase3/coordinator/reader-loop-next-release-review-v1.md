# Reader-loop next release: reviewed seam and unresolved acquisition

Review base: signed/published `8ce7c8aa858f7b7b24e24bd8543e7ef7ce4406b5`.
This source review releases no new implementation path, check or live operation.
The current RUN listener assignment remains unchanged.

## Accepted narrow direction

Use a real bounded nonblocking pipe reader with a checkpoint of the actual
consuming loop. The historical reference
`benchmark/evidence/reference/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.py.txt:94`
contains fixed `tetra getevents`, stdout/stderr selectors and 65536-byte reads.
It ran through Docker in a separate VM and is not current native stream custody.
Source search across native/common modules, staging/materialization scripts and
service files found no current native `tetra`/`getevents` launch integration.

`src/aragorn/runtime_tetragon_process.py:265` supplies the existing single-record
parser. A separately released public wrapper could reuse it under its exact
source pin. Do not call `normalize_process_capture` for an ongoing loop: that API
requires closed/quiescent capture and reported counters. Never manufacture EOF,
quiescence, events or zero loss to satisfy it.

Keep the broker contract's 16384-byte checkpoint artifact bound. A manifest can
pin separately retained raw batch bytes, exact LF-record/byte counts, contiguous
stream offsets, stream identity, prior checkpoint, sequence and BOOTTIME read /
publication brackets. Root's protected acquisition must independently verify the
actual raw readback before using that manifest. External replay receives those
same original bytes. The bounded authenticated wire envelope alone establishes
neither raw custody nor sensor health.

The independent checkpoint consumer must not import the producer or private
record parser. Its bounded claims are framing/count/digest/sequence consistency,
challenged loop progress and retained error/backlog/loss-reference joins. Full
vendor execution identity and parent-graph attribution remain separate semantics.

Candidate bounds are reads/records <=65536 bytes, batches <=262144 bytes and
256 records, session lifetime <=4 MiB/4096 records. These are proposed fail-closed
bounds, not measured campaign compatibility. Exhaustion, malformed input, EOF,
descriptor change, parser/delivery failure or unaccounted partial records poison
the stream; no silent discard, rotation, reset or automatic recovery is allowed.

Only the actual loop can ACK: receive challenge, perform a subsequent real read,
reach EAGAIN without partial/undelivered bytes, durably publish/read back its
checkpoint, then advance sequence and send the frozen response. Idle input yields
an empty checkpoint, not synthetic telemetry. A hung loop cannot ACK. Idle pipe
responsiveness cannot prove upstream subscription or sensor responsiveness.

## Decisions required before source release

1. Pin actual reader/bridge/sensor processes, accounts, installed source/builds,
   sole pipe writer, bridge socket-to-sensor join and reconnect/retry accounting.
   The candidate Tetragon source commit
   `1de2ed8ebea18e56257dc59597aa13bf8f0e471e` is not installed-binary evidence.
2. Freeze separate reader-owned raw storage and protected Root readback, proposed
   `/var/lib/aragorn-phase3-reader-events`, including batch counts, publication
   ordering and cancellation. Keep the existing root-only ReaderStore inaccessible.
3. Define fresh second-phase checkpoint acquisition while reusing the original ACK;
   never issue a second BEFORE_FIRST_EFFECT challenge after connect.
4. Bind the complete applicable loss inventory. `runtime_tetragon_loss.py:216`
   preserves unknown/reset/increased counters; sparse BPF data is not zero.
   `runtime_tetragon_stats_map.py:577` is non-atomic, and
   `runtime_tetragon_program_map.py:275` covers selected exit linkage. Upstream
   queues and ignored encoder-write errors still require explicit treatment.

All source anchors above are review evidence only. No implementation or test
stage is released until Root fixes these decisions, supplies exact paths and
publishes the contract. Root protocol/journal implementation and the existing
Admission/RUN/Workloads assignments continue independently.

Remaining Phase 3 sequence: (1) complete protected providers, (2) wire all required
admission/RUN/action and paired-task paths, (3) close the 48-entry inventory and
freeze source/loaded identity, (4) separately release the final campaign, replay,
qualification evaluation and approved cleanup. Operational holds remain.
