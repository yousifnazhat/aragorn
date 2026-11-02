# Reader checkpoint acquisition source handoff

Implementation base: coordinator-published, verified signed checkpoint
`25ac9a8503d7ed6f66377ad6561149cea77588d7`, provider release v6 and the final
reader-checkpoint contract. Root reviewed the complete five-file closure and
published scheduling checkpoint `42f0c0d00f9b88b1eed673bf47877b48ff16e6a7`.
The selected 53-method stage passed once. No deployment or qualification is claimed.

## Ownership and concrete behavior

This owner changed only `src/aragorn/native_phase3_run_reader_checkpoint_acquisition.py`
and this handoff. The acquisition test is owned by coverage_ledger. The independent
consumer and its test are owned by provider_path_review. Root owns final contract
clarifications, registry, scheduling, integration and published checkpoints.

`acquire_reader_checkpoint` is the exact one-shot public API. It validates the
independently held provision and expectation before storage mutation, opens the
five fixed directories without following links, holds the reader PIDFD and both
active time namespaces, and reads actual stat/status/stat, PIDFD association,
boot identity and CLOCK_BOOTTIME. No supplied callback or candidate path replaces
these operations. Reader accounts/capabilities/NoNewPrivs, original root process
and thread, namespace identities, source and archive ownership are guarded.

It reads the deterministic manifest, receipt and original raw batch with bounded
nonblocking opens, full nine-field held/named identities and exact schema, pin,
sequence, byte, line, offset and timing joins. The closed trigger deadline stays
distinct from the unchanged outer acquisition deadline; REFRESH retains the
original ACK and requires a previously acquired checkpoint. Receipt preparation
must precede actual source-readback completion, and actual guards always enforce
original ACK age below 200 ms.

After source validation it exclusively creates the permanent attempt claim,
then copies the three artifacts and publishes the acquisition record. Every
publication writes fully, fsyncs its file and parent, and performs exact readback.
All five archive FDs, all three source FDs and supporting custody remain held
through final readback. Six source/copy dev+inode pairs must be distinct. Return
occurs only after owned descriptor cleanup and a final actual deadline check.
No path is repaired, overwritten, renamed, removed or retried.

Refusals retain the fixed `ReaderCheckpointAcquisitionError` attributes from the
contract: original failure, separate cleanup failures, bounded observed raw
prefixes, completed source/retention identities and conservative claim-attempt
state. Ownership is consumed before close; a descriptor whose identity changed
is never closed as though it were still owned. A transient proc read failure
remains the original error even if its close also fails. Partial files remain.

Root accepted these contract clarifications before scheduling: ancestor GID is
independently pinned rather than implicitly zero; REFRESH requires a non-null
prior checkpoint and positive previous sequence; the six source/copy identities
are distinct; cleanup capacity is 32 (actual maximum is 17 owned FDs, including
one transient proc FD). These were included in the signed scheduling update before execution.

## Stable source and complete dependency closure

| Path | SHA-256 |
| --- | --- |
| `src/aragorn/native_phase3_run_reader_checkpoint_acquisition.py` | `0fe4a8a8a1bf86839fa4a7fa1bd6ecb8b5fd56e5e3ff9a1f1ad50f8ed5889d22` |
| `src/aragorn/__init__.py` | `4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01` |

The module imports only `hashlib`, `json`, `os`, `re`, `select`, `stat`, `sys`,
`threading` and `time`. Package initialization is inert. There are no project
helper imports, dynamic/generated sources, external fixtures or historical test
imports. Suitable existing helpers were inspected, but their broader closure and
different descriptor cleanup rules did not fit this bounded owning operation.
The full stable five-file closure and 22 acquisition plus 31 independent-consumer
methods are pinned in `reader-checkpoint-review-and-scheduling-v1.md`.

All five claim flags remain false. Readback proves neither actual pipe progress
nor authenticated acquisition, upstream continuity, loss completeness, effect
authority, RUN or Phase 3 qualification. Raw records are preserved byte-for-byte;
this producer does not normalize or certify vendor execution-record semantics.

## Actual reviewed result

Root executed only `native-reader-checkpoint-acquisition` once with
`/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run` after status
reported NEW. Its actual stderr reports **53 tests, OK**; exit code 0, status PASS,
and equal pre/post fingerprint:
`sha256:091fd6c1739b55e7fae680a4612fd81bdb1d43e2007cf8ded86715855692c67e`.
No historical or unchanged stage ran. No retry or evidence copy occurred.

Original evidence remains at the coordinator checkout's
`.aragorn/phase3-pipeline/native-reader-checkpoint-acquisition/091fd6c1739b55e7fae680a4612fd81bdb1d43e2007cf8ded86715855692c67e/`:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| result.json | 819 | `02c685a43a67ccbb491f9c9d1353c1822f777e21fbb26ef403ec83000357674d` |
| stderr.log | 11178 | `0cffd7f07d5fe418cab53f5e522093dae32fc2ba5c294b32aa8d555baa70d4ee` |
| stdout.log | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Root reviewed the actual result, log counts and digest/byte matches. This closes
only the released checkpoint acquisition/archive and independent byte-consumer
implementation slice. Both APIs preserve UNKNOWN continuity/loss and false
qualification flags. Actual writer/refresh, stream identity, upstream loss,
protected invocation and broker/launch wiring remain required.

## Remaining work

1. Integrate this reviewed slice in a signed checkpoint and preserve its actual
   fingerprint; promptly review and integrate the ready lane handoffs.
2. Separately release actual reader pipe/refresh/cancellation, protected launcher
   and bridge identities, and genuine source/loss joins. They are absent here.
3. Wire the real root-to-broker acquisition/independent-consumer path, close the
   existing implementation ledger and publish a reviewable freeze candidate.
4. Keep operational observation, final qualification, private retention and
   cleanup pending their separate release. This source slice does not finish
   Phase 3.
