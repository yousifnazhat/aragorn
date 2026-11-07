# Pi-core D2 batch 15: trusted-service consumed-source startup

Date: 2026-11-06. Base: verified signed `0314633b344c7595a5f3b7c764de15dc94086ccb`.
Scope: the first dependency-ready implementation batch of the approved D2-D5
plan. Source, new/affected offline checks, one changed static image, signed main
integration and normal push only. No live operation is authorized or performed.

## Connected change and reuse

This advances the trusted-service portion of `MP1/ADM-01/exact-admitted-bytes`
and the external enforcement boundary; neither requirement is qualified here.
The existing image assembler, installed-byte holder, native lifecycle, fixed
service entrypoints, authenticated channel/PIDFD helpers and canonical receipts
are reused. No dependency, alternate runtime or general service framework is added.

Nonoverlapping internal lanes owned the source loader and its tests; service
entry/lifecycle and their tests; and independent review. Root owned fixed wrapper
successors, assembler/pins, one actual-source import check, registry, checkpoint
and publication. Existing lane worktrees/drafts were not modified. The code-review
skill and independent review drove cleanup-failure redaction, handle retirement,
bounded descriptor inventory and retained failure evidence before execution.

The three `packaging/pi-core/services-v2/` templates receive exact source pins
from the reviewed assembler. Their installed paths and isolated Python invocation
remain unchanged. Each wrapper verifies the bootstrap loader's source buffer and
compiles/executes those same bytes under a private module name, before importing
any Aragorn module. The loader then admits only pinned Aragorn modules/packages,
checks protected ownership, mode, ancestry, file identity and digest, and executes
the verified buffer. It retains handles and successful consumption records.
Preloaded/unlisted/reloaded modules, alternate paths, bytecode fallback, changed
source/module identities, expired deadlines and incomplete/failed imports refuse.
An observed loader failure cannot be repaired into authority inside that lifetime.

The existing authenticated post-exec supervisor channel now carries a one-shot
challenge, consumed-source subset and exact acknowledgement before any service
handler or action listener is released. Root validates the source-inventory/image
binding and joins the receipt to the captured PID, start time, cgroup, interpreter,
unit invocation and immutable unit properties. Missing loader successors refuse
before service startup. Invalid authenticated receipts and challenges remain
retained as INCOMPLETE, never silently retried or accepted. Legacy entry callers
without a source loader retain their old unqualified behavior.

The passive listener's finite FD-inventory bound accounts for newly held source
files/package directories; no deadline or acceptance threshold is widened.
Cleanup attempts each owned descriptor once and preserves uncertainty. Wrapper
cleanup errors produce the existing redacted refusal rather than a traceback or
an installed loader whose result was lost during cleanup.

## Evidence and authority limits

The record covers **trusted Aragorn startup imports**, not a claim that every
installed file was executed. The fixed wrapper, bootstrap loader, interpreter,
stdlib/native libraries and trusted root/manager remain the bootstrap TCB.
Independent installed-byte/process custody plus a trusted source loader are not
an independent observation of the untrusted Pi worker or arbitrary V8 memory.
Later lazy imports remain pinned by the loader but are not retroactively included
in the startup receipt. `loaded_code_verified` and `phase3_exit_eligible` remain
false. This image has not been installed or executed in the selected VM.

Read-only health review confirmed the next real gap: the current Pi sensor joins
the accepted worker/process/admitted materialization but does not observe source
reads. Existing Tetragon parsing and program-map evidence cover restricted paths;
legacy broker-reader loss remains UNKNOWN/LOSS_UNAVAILABLE. Reuse protected reader
transport/checkpoints/raw retention for a source-read and complete applicable-loss
successor; do not flip those old claims. Successful file delivery is itself
distinct from proof of arbitrary JavaScript execution or memory integrity.

## Focused checks and retained correction

**92 distinct focused checks passed.** All execution used
`scripts/phase3_pipeline.py` and the reviewed explicit registry. No historical
suite, whole-schema sweep, live capture, provider call or effect ran.

| Stage | Checks credited | Fingerprint |
| --- | ---: | --- |
| `pi-core-service-source-offline` | 32 | `647a2a07b9c8703be3486fceb7a0ffc562e4a4c5983a5931ee7d171630d6317d` |
| `pi-core-service-source-wrappers-offline` | 13 | `f3bc1c004ce3d6efdc9e1da40cc96684fdeb3feaa8d13b26c775b3dd688471f1` |
| `pi-core-service-consumption-offline` initial | 41 successful, 1 fixture error | `546fd914a01b6e4c0306cc842843c33549b21f554c101ad22b6970af8cb5c80a` |
| `pi-core-service-consumption-offline` corrected selection | 1 | `3598ad0537e867f281544445dd82c3a3fa2a792967c9b287ef3f2bd3bf69420f` |
| `pipeline-capacity` | 4 | `58e1808fc58a5f7d473c2ef20b96ce2fc046dec0b913f3da90c551d0529a7f1b` |
| `pi-core-service-source-image-assemble` | 1 | `1cb2659da04116986e9ba72c016d47eefb684bb3facb0295e448bb7ac8da28b8` |

Fingerprints are SHA-256. Exact local logs/results remain under
`.aragorn/phase3-pipeline/<stage>/<fingerprint>/`. The initial 42-check stage was
correctly retained as FAIL: its legacy-image-refusal test called a mock-only
assertion on the fixture's plain function. The source refusal had worked. The
assertion now checks the retained preparation event list. No implementation
changed after that run; the 41 other successful cases remain in its original log.
The corrected registry selection schedules **only that one test**, through the
new repaired-selector module. The unchanged failed fingerprint was never rerun.

Those retained successes include the one new connected check loading the actual
83-source pinned service closure through the loader, without invoking handlers.
The wrapper stage includes only two affected legacy assembler cases; the startup
stage includes eight selected affected entry/lifecycle cases. Four new stages
require the exact bounded registry increase from 172 to 176. Assembly reused all
three unchanged successful current prerequisites as SKIP_PASS, not execution.
Focused source results are developer evidence, never final admission/RUN proof.
Staged whitespace review found only an extra blank final line in each new wrapper
template. Those tested and artifact-pinned bytes are retained; cosmetic cleanup
does not justify rebuilding or rerunning this batch.

## Static successor

The v1/v2 input records, wrappers, artifact records and retained images remain.
New records: `packaging/pi-core/service-assembly-inputs-v3.json` and
`packaging/pi-core/service-artifact-v3.json`.

- Output: `.aragorn/pi-core-service-image/assembled-7ac1ac5e9d6946478c48e765cefc48ef/`.
- 771 files, 54 directories, 41,529,498 root bytes; 83 source modules, three
  rendered wrappers, unchanged native libraries and provenance inventory.
- Manifest: `sha256:343bf24835f170bc3578114d3d04181f250af79214b2253460a3123148563967`.
- Binding: `sha256:7fef233d03a91e9a706fff14c45bcdcd14aff3ee4f1345a8471a80d074b4cf08`.
- Receipt: `sha256:1c8bca28023edc8a7e3d69909ffcdd648ffeb226cced80caeb4cfdd9f07c7298`.
- Status: PREPARED_NOT_INSTALLED_OR_EXECUTED. No target interpreter or wrapper
  ran; the same retained archive was statically reused. Optional benchmark DSSE
  helpers remain explicitly unsupported, as before.

Publication includes only explicit batch-owned source/docs/metadata. Large images,
local evidence, unrelated drafts and all duplicate-named untracked files remain
local and untouched. Verified signed batch/merge hashes and exact remote readback
are recorded in `.aragorn/pi-core-service-source-batch-15-release.json` and the
chat milestone. Source publication is not deployment or qualification.

## Remaining plan

1. **D2:** independent worker source-read observation and complete sensor health;
   owned provider listener/dispatcher and additive enabled START; exact provider
   setup, recovery/full timing and the separately authorized calculate-and-save
   pilot in a fresh Linux arm64/systemd VM. No D2 exit claim yet.
2. **D3:** remaining managed admission, seven event classes/six responses and
   HTTP/DNS/destructive plus actual paired-workload coverage on this deployment.
3. **D4:** narrow executable `pi-core-managed-phase3/v1` acceptance, exactly 29
   MP1 requirements plus full supported/denied surface inventory and independent
   verifiers; close all prerequisites, then freeze once. Legacy 48 IDs stay intact.
4. **D5:** separately authorized fresh surface acceptance, 100 actual attempts
   and 100 real pairs, unchanged thresholds, cleanup/prior-state evidence and
   independent offline replay. No synthetic replacements or automatic retries.
