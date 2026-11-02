# Phase 3 finite admission, reader and copy/readback checkpoint

Previous published checkpoint: `55a87ea1f7ab3924ade5fa629935ffc03962ba05`.
Integration branch: `codex/phase3-runtime-prevention`.

## Original signed commits and retained checks

| Lane | Original signed implementation | Signed registration parent | Focused result |
| --- | --- | --- | --- |
| Admission | `ccf357fcdf914005503f3ad4a208977e47629865` | `d0e62576c1b6a32aead7af4b673364cfb7a95017` | `native-admission-restart`: 26 mocked tests PASS once; 9 inputs |
| RUN/health | `374541f32ddbadc6484dab583be4805002e401dd` | `1cc410760abddebc4ee4b280ea922e7b3a244c1c` | `native-run-reader-response`: 17 mocked tests PASS once; 14 inputs |
| Workloads/verifiers | `e050eb55a38105629ea56f24a1c31905368d2180` | `d69d92d800635453b1162227b630a3922a371f23` | `native-workload-copy-readback`: 12 focused tests PASS once; 13 inputs |

Each registration is a coordinator-signed one-path commit based on the previous
checkpoint. Each owner verified and fast-forwarded to its registration, ran only
its explicitly scheduled stage, then signed only its lane-owned files. The merge
preserves all original commit identities and registration ancestry. No lane
worktree was edited by the coordinator.

The implementation adds the finite native RESTART producer and independent
retained-byte consumer; one authenticated reader-response acquisition leaf; and
guarded copy/readback with an independent retained-file consumer. Existing shared
runtime modules, frozen predecessors, provider implementations and dispatch are
unchanged. See the three lane handoffs for exact interfaces, paths and limitations:

- `admission/RESTART_SOURCE_HANDOFF.md`
- `run-health/READER_RESPONSE_HANDOFF.md`
- `workload-verifiers/copy-readback-handoff.md`

Exact successful pre/post fingerprints:

- Admission: `sha256:70b1548feb59a4bd38673bb01cd9d52a78e26c31ebca95a1f5d47f7588b335b8`.
- RUN: `sha256:f1fab4f0fbe5eb90a0bdfebc731c576ba28f84db04e66d447767cf8150025e8b`.
- Copy/readback: `sha256:bc7e9c5b46f7c44569ae94dd00fcf80aafa3b51d6ff883f985b1327e5790d8db`.

Results and logs stay in their original owning worktrees. The coordinator verified
their digests, method counts, exit status, signed source bytes and exact stage
definitions. Read-only selected-stage status returned `SKIP_PASS` for all three;
no behavior reran. The combined registry contains 107 rows: all 104 historical
rows unchanged plus the three reviewed stages. Handoffs and planning references
are outside behavioral fingerprints, so recording results does not invalidate them.

## Source review corrections completed before execution

Workload tests now isolate a final fixture-guard failure after readback and the
producer-owned duplicate close after successful task completion. RUN retains the
actual send/recvmsg invocation flags before each syscall, separately from returned
flags. Admission uses a fixed reason for provider-origin ordinary exceptions while
preserving bounded partial bytes and interruption handling. Admission's stage was
reduced from 19 proposed references to its actual nine-file behavioral closure.
No failed or interrupted test attempt occurred in this batch.

## Integration boundaries and next ownership

Coordinator priority remains the offline HTTP94 protected-credential/import-cycle
repair. Its four unfinished draft files are excluded. Resolve the draft boot-ID
read under `ProcSubset=pid` using the protected boot-ID bind and corresponding
worker/sensor joins; then review and schedule only its new focused staging check.
Use that check's actual retained public report for subsequent helper/capture,
source/identity and environment composition. No HTTP repair success is claimed.

The coordinator still owns protected lifecycle acquisition and launch/source
inventory; the accepted reader transport, permanent challenge ledger, retention,
actual reader checkpoint, real loss/program/map observations and serialized broker
state; and protected workload context, fresh directories, dispatch, cancellation,
retained replay custody and actual paired environment selection.

Lane owners keep their existing worktrees and fast-forward themselves to the
published combined hash supplied after remote verification. Their next bounded
implementation needs a concrete coordinator assignment and source/closure review
before scheduling. Independent RUN custody verification, remaining admission and
workload coverage and the combined verifier inventory remain unfinished. No new
stage or live operation is released by this integration checkpoint.

The reader ACK proves neither meaningful telemetry progress nor loss completeness.
Admission lifecycle records remain runtime assertions with explicit emitter and
clock limits. Copy identity establishes post-task retention, not uninterrupted
creation-to-readback custody. No product hard return deadline or deployed provider
proof is added. All qualification flags remain false.

## Remaining Phase 3 steps

1. Finish shared runtime integration and offline HTTP repair. The recorded
   retention/cleanup hold remains unresolved and was not refreshed live.
2. Complete remaining admission, RUN acquisition/enforcement/attribution, workloads,
   actual paired environments and measurements using the real protected providers.
3. Complete independent verifier coverage and deployed source/identity custody,
   then freeze one deployment.
4. Complete the separately released same-deployment 31-case and 100-attempt/100-pair
   acceptance, independent replay and retained cleanup after prerequisites close.

Post-commit signature, ancestry, composition and remote-tip verification are
recorded separately to avoid claiming this document's own future commit hash.
There were no historical-suite reruns, cache copies, automatic unchanged retries,
live operations, private fixture retention or cleanup in this batch.
