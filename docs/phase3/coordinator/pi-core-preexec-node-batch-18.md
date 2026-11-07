# Pi-core batch 18: protected pre-exec launch and Node source observation

Base: verified signed integration `14ef5f5f72ee2f3abaef572cbcb2047a994b42e1`.
Scope: offline implementation and only new/affected focused checks. No build,
service activation, live tracing, provider call or qualification is authorized.

## Connected scope

Three nonoverlapping lanes extend the existing confined launcher, source observer
and independent replay. The coordinator owns request-custody integration, the
reviewed pipeline registry, this checkpoint and signed publication.

The additive protected launch profile selects a fixed gate before the existing
Node entrypoint. The held runtime inventory and build receipt must contain the
exact reviewed gate. The builder accepts an independently pinned static arm64
ELF and its provenance; it does not manufacture a binary or claim a compiled gate
from a source-only check. The unavailable-provider default is unchanged.

Native launch captures the owned process and unit, then arms observation before
accepting HELLO. Request custody takes the exact supervisor-held observer without
replacing authenticated service channels. Withdrawal or substitution refuses
protected work. Cleanup retains native handles until observer ownership is
resolved; no unowned process, broad kill, restart or automatic effect retry is
introduced.

The observed path alone pins and reads back `KillSignal=SIGKILL`, so exit-only
tracer cleanup does not spend its entire existing reserve waiting for a signal
that a held syscall cannot process. The legacy launch semantics are unchanged.

The additive Node observer uses a dedicated tracing owner and records bounded
thread and source-loading activity. Source byte delivery and pinned ELF loader
reads/mappings are different evidence classes; neither is proof of arbitrary V8
execution. The original single-task observation contract and retained captures
remain predecessors, not silently relabelled Node support.

Internal anonymous-inode metadata is not treated as a unique kernel object.
`KCMP_FILE` compares held local duplicates while all captured threads are stopped;
unavailable or failed comparison refuses without a metadata fallback. Creation
events remain separate in replay even when their stat identities alias. An
ambiguous descriptor close retains its ownership record and latches the existing
no-retry state, requiring a cleanup hold rather than a second close attempt.

Independent replay uses caller-pinned raw evidence, source/loader inventories and
the selected profile. It cannot mint current sensor health or effect authority
from internally consistent records. The narrow v1 correction prevents a failed
read from qualifying consumption of an empty source.

## Verification and limits

**167 distinct focused checks passed:** 54 launch/request-custody, 47 Node
acquisition, 62 independent replay (including two affected v1 cases), and four
affected pipeline-capacity checks. Only the reviewed pipeline ran tests.

The initial launch selection retained 52 passes and two fixture errors: the
existing shared digest validator raises `RuntimeActionBrokerError`, not the
fixture's expected `ValueError`. Production validation was not weakened; the
fixture now accepts the exact existing refusal types, and only those two cases
were selected again. The initial 40 acquisition and 60 replay checks passed.

Final review found the anonymous-inode alias and ambiguous-close custody issues
described above. After those actual fixes, only seven new and three affected
acquisition cases plus two new and three affected replay cases ran. In total,
eight checks were necessarily repeated (two corrected failures and six affected
passes); no unchanged unrelated passing case was repeated. Initial records,
including the failed launch fingerprint, remain intact. No cached unit result
is promoted to deployed health, useful-task or Phase 3 qualification evidence.

| Selection | Result | SHA-256 fingerprint |
| --- | --- | --- |
| Launch/custody initial | 52 PASS, two fixture errors retained | `3eed13dc493bb9a9a5bb843db505a427985a2c66d1ac0f8f93e7c989feb21b53` |
| Launch corrected cases | 2 PASS | `2f95449ae8b47d63868b87aba7a02b77a902464606d76c24455c92b03d78a17d` |
| Node acquisition initial | 40 PASS | `315a9dad560c0156de8b351942d0d16880a1e2b5f75502ad40b6211b1e2a83e1` |
| Node identity/close affected | 10 PASS | `fc81b13dd8b63b2dfb5b7df8cc93a644a490f0f63ab8d33b67f60839444e7fa5` |
| Independent replay initial | 60 PASS | `0eb490d86be4953fb20ebd478b9f8f0494730148f90ea9894619c1e9b2cabae5` |
| Replay identity affected | 5 PASS | `54f93dd4cbc5b835b41d930b9b82c04dc61aab879c600b6a21ad9573fa2b7567` |
| Pipeline capacity | 4 PASS | `e3b66b158ced3bb4079a6ff26134ff800ec1a1e2907287460c1007bdefd57972` |

The three new registry stages are `pi-core-preexec-node-launch-offline`,
`pi-core-node-source-observer-offline`, and `pi-core-node-source-replay-offline`.
Their current selectors deliberately contain only the corrected/affected final
cases; the original selections and complete results remain in retained records.
`scripts/phase3_pipeline.py run pipeline-capacity` ran the four capacity checks
once; `scripts/phase3_pipeline.py run` with only those three named stages ran
the initial and necessary changed selections. No default/all-stage run occurred.
The bounded registry capacity changed from 182 to 185.

The code-review skill guided cross-caller, trust-boundary and cleanup review;
the commit-work skill guided explicit staging and `git diff --cached` review.
The full plugin-specific C audit was not available; the fixed gate received
focused source review and inert input checks, not compiled or live validation.

Required external preparation remains the pinned compiled gate artifact and a
protected profile derived from actual installed source/loader identities. The
target must support the required `KCMP_FILE` comparison. The
bounded syscall/transport scope and observation timing require confirmation on
the exact authorized deployment. Unsupported acquisition refuses work rather
than being counted as healthy. Health challenges provide bounded freshness,
not an atomic observation-to-effect guarantee.

Only explicit batch-owned paths may be committed. Unrelated drafts, duplicate
files, predecessor artifacts and all failed pipeline records remain untouched.
Signed source/merge hashes and exact remote readback are retained after release in the
ignored `.aragorn/pi-core-preexec-node-batch-18-release.json` receipt and chat.

## Remaining plan

1. **D2:** finish installed observation preparation and any actual Node routes
   still unsupported; connect the owned provider listener/native dispatcher and
   enabled START, operator-approved provider setup, recovery and full timing.
   Then obtain separate authorization for the useful calculate-and-save pilot.
2. **D3:** complete managed admission, all seven RUN event classes and six
   responses, HTTP/DNS/truncate/unlink and real paired-task contexts.
3. **D4:** close the real producer/evidence/independent-verifier inventory for
   the 29-requirement managed contract, then freeze one complete deployment.
4. **D5:** separately authorized fresh managed acceptance, 100 actual attempts,
   100 actual pairs, unchanged thresholds, retained failures, verified cleanup
   and prior-state restoration, then independent offline replay.
