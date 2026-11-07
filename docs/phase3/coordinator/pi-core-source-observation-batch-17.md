# Pi-core batch 17: independent source acquisition and mandatory health custody

Base: signed integration `2b8c12ff6f87a7c04a37b63a25cceb096ba91818`.
Scope: reviewed offline implementation only. This is not a deployed observer,
healthy Pi startup, D2 completion, or Phase 3 qualification.

## Connected changes and evidence boundary

Three nonoverlapping lanes implement acquisition, independent replay, and the
existing native-request/provider enforcement points. The new observer reuses the
supervisor's exact unit/process/PIDFD custody, process checks, activation contract,
canonical records and existing CAS. No replacement runtime or collector is added.

The acquisition backend is Linux arm64 ptrace. It requires an independently
captured, pinned **pre-Node gate**, traces the transition to the pinned Node image,
and records actual read/pread64 entry and completion stops against held source
file identities. Only returned byte ranges contribute to coverage. A fresh
challenge must acquire another kernel stop under the original deadline; an old
stop, live PID, JSON PASS or unchanged counter is not fresh progress. Refusal and
raw observations remain retained, with owned cleanup required after worker exit.

The independent consumer reconstructs recorded source ranges and stop/read
accounting from CAS-held canonical evidence and separate caller-held pins. It
does not import the producer. Consistent offline records do **not** authenticate
their acquisition, grant active health/effect authority, prove arbitrary V8
execution, or qualify Phase 3. Those distinctions are explicit in its result.

Protected file creation and provider authorization now require the exact held
observer for the actual worker activation. Missing, stale, incomplete or refused
custody prevents protected work. The provider's authenticated terminal cleanup
does not grant new effect authority and does not request a new health challenge.
The provider-unavailable NO_REQUEST bootstrap remains unavailable and inert.

## Deliberate limits

This first acquisition backend supports one task and read/pread64 source delivery.
Thread/fork growth, file-backed mmap and unclassified reads are refused. Normal
dynamically linked/threaded Node startup therefore **cannot pass this backend**.
The protected pre-exec gate artifact, launcher integration and full actual Node
acquisition routes are still required; the factory cannot attach late to today's
ordinary Node launch and label it observed. No deadline or acceptance threshold
has been relaxed to conceal those gaps.

The legacy reader's UNKNOWN loss/health records remain unchanged. This batch is
not complete sensor-health coverage for the pilot or the seven RUN event classes.
Old static images and all retained predecessor evidence remain their exact old
bytes; no changed source is represented as already installed.

## Focused verification and delivery

**147 distinct focused checks passed:** 54 observer, 59 independent replay,
30 enforcement/caller checks (25 new and five affected), and four affected
pipeline-capacity checks. Only the reviewed pipeline executed tests.

The first observer run retained 23 passing cases but encountered fixture errors:
Darwin's wait-status macro does not mask Linux ptrace event bits; copying a
partially populated frozen fixture accessed absent slots; and mocked process
metadata interfered with traceback rendering. The replay run retained 58 passes
and failed only its cross-lane producer fixture for the same wait-status issue.
Production code was unchanged by the repair. Fixtures now decode Linux records
explicitly, build the replacement plan from its populated fields and isolate
traceback lookup from fake process metadata.

The corrected run selected only the observer's 31 failed/unrun cases and the
single replay handoff. **Five failed checks were necessarily repeated; the 85
already passing checks were not repeated.** All initial failed records remain.
The new enforcement stage ran once after positive legacy fixtures were adapted
to supply an explicit inert observer; explicit missing-observer cases still deny.
The pipeline's bounded stage capacity increased from 179 to 182, not an automatic
request to run its existing stages.

| Selection | Result | SHA-256 fingerprint |
| --- | --- | --- |
| Observer initial | FAIL retained; 23 passes, four errors, 27 unrun | `cea50ed4f359285fa18fe7e01018164a4d90496e445b95aedb79b56cb9128993` |
| Observer corrected remainder | 31 PASS | `45d06d83b87548dd869b2ecf3e2e4ae3169519c66e48522cc206417e029423aa` |
| Replay initial | FAIL retained; 58 passes, one error | `39ce2dea4a9b34be7ffda92412d49f130a183ee12a245209624bdb5d366f1591` |
| Replay corrected handoff | 1 PASS | `b18b7194bf83375ed6afb340934cdade27da16a6497ae8e76ad41e82e5263f72` |
| Health enforcement | 30 PASS | `59152a693b4551165ad6726196a1c6dd417b1cf7b93efdd0ed7d301fb56a3450` |
| Pipeline capacity | 4 PASS | `b112f2ff05aea8fa8a5708a720108a7a3d7f14b6b114f76ea05a8d9a70d13423` |

Code review aligned the independent contracts and closed deadline withdrawal,
empty-source consumption, nonblocking unsafe-file refusal, cumulative challenge
accounting, executable-object binding and ownership-safe cleanup gaps before
execution. The code-review skill guided the trust-boundary and cross-caller
review; no new acceptance authority was inferred from these unit results.

Only explicit batch-owned files are staged; unrelated drafts and duplicate-named
untracked files remain untouched. Signed source/merge
hashes, signature results and exact remote readback are retained in the local
ignored `.aragorn/pi-core-source-observation-batch-17-release.json` receipt and
the chat milestone.

## Remaining plan

1. **D2:** integrate protected pre-exec acquisition and support the actual pinned
   Node thread/read/mapping lifecycle with complete required progress/loss
   accounting. Connect the owned provider listener/native dispatcher and additive
   enabled START, provider-only credential/egress profile, recovery and full
   timing. Then obtain separate authorization and exact operator inputs for the
   calculate-and-save pilot on the fresh dedicated Linux arm64/systemd VM.
2. **D3:** complete connected managed admission, all seven RUN classes and six
   responses, HTTP/DNS/truncate/unlink paths and actual paired-task contexts.
3. **D4:** complete the real producer/evidence/independent-consumer inventory and
   source-bound surface mapping for the implemented 29-requirement contract;
   close prerequisites and freeze one common deployment once.
4. **D5:** separately authorized fresh managed-surface acceptance, 100 actual
   attempts and 100 actual pairs, unchanged thresholds, retained failures and
   ambiguity, verified cleanup/prior-state restoration and offline replay.

No live tracing, VM/service activation, provider call, credential access, target
build, broad regression or historical recapture is authorized by this batch.
