# Tetragon loss-accounting source slice

Retrieved 2026-10-04 from the exact `cilium/tetragon` commit
`1de2ed8ebea18e56257dc59597aa13bf8f0e471e`, already selected by the existing
[candidate source lock](../tetragon-candidate-source-v1.lock.json).
The [supplemental manifest](../tetragon-loss-source-v1.lock.json) records each
raw file's size, SHA-256 and Git blob SHA-1. The Git blob joins were checked against
the pinned GitHub tree; `eventmetrics.go` also matches the existing source lock.
This is selected source custody, not signature verification, executed-binary
identity, full build closure or live sensor attestation. Upstream Apache-2.0
copyright and SPDX notices are preserved in each source file.

## Consequence for the retained smoke

- `eventmetrics/eventmetrics.go` defines `tetragon_bpf_missed_events_total`
  for kernel perf-event send failures, labeled by opcode and error.
- `eventmetrics/bpfcollector.go` opens `tg_stats_map`, reads the per-CPU values,
  and emits only positive `SentFailed` counts. It returns without emitting data
  if map open or lookup fails. Therefore an absent family cannot distinguish
  zero counts from failed collection. Do not synthesize zero.
- `kprobemetrics/collector.go` obtains separate link misses and program recursion
  misses. `kprobemetrics/missed.go` defines their `policy`/`attach` labels. Those
  metrics cannot substitute for perf-event send-failure accounting.
- `metricsconfig/healthmetrics.go` registers the event health collectors. A
  registration path in source is not evidence that it ran successfully in the
  retained or current sensor.

The new raw-scrape adapter preserves this uncertainty and leaves the existing
restricted process profile unchanged. The next live sensor integration needs
source-bound evidence that the exact expected BPF statistics map is present,
readable, the correct type/layout and attached to the actual sensor instance,
before and after the event window. A generic `/healthz` response or process
existence is insufficient. No new live capture was performed for this source
inspection.
