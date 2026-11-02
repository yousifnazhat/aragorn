# Reader storage and worktree scheduling checkpoint

Base: `22c05de348c1585ab9bdf17bf8cc1ba119c7f53d`, with signed registration
commits `388a552` and `3680932`. Root reviewed stable source and complete closure
before registration and executed only the two newly necessary selected stages:

| Stage | Actual result | Fingerprint |
| --- | --- | --- |
| `pipeline-selected-closure` | PASS, 6 new inert cases, first execution | `sha256:2a60c15d0dd00e688ede1be936232eb8aa07ac59435fe85b162c6b7f49535b9e` |
| `native-phase3-run-reader-store` | PASS, 16 new mocked cases, first execution | `sha256:920a28df3aa7a8f1fab8b55f6d29dea566b16bf070a44b510994e1e13d82e9e8` |

Both retained results have equal pre/post fingerprints, completed test logs and
PASS status. Actual logs/results stay in the coordinator's original
`.aragorn/phase3-pipeline/<stage>/<fingerprint>/` directories. Nothing was copied.
Their stable hashes/closures and review are recorded in coordinator
`pipeline-selection-repair.md` and `reader-storage-review-v1.md`.

The reader provider now exclusively creates permanent challenge claims and
immutable evidence under the fixed provisioned root, holds/rechecks named and
open directory/file identity, fsyncs files and directory before exact readback,
and leaves partial residue as refusal. Its owning caller mints fresh challenges
from independently pinned epochs, wires the unchanged reader leaf to real durable
callbacks, retains failure evidence and closes all owned resources before exposing
a reader result. No directory is provisioned or real socket used by these checks.

The runner now requires only the selected transitive source closure while still
validating every registry schema/path/graph. It preflights the entire selected
closure before state or execution. This repairs the recorded RUN pretest refusal
at `22c05de`; that refusal generated no stage fingerprint or behavioral result.
The changed runner is the documented changed input authorizing a new attempt.
Old unaffected evidence retains its original fingerprint and limits; the changed
runner digest is not a reason to rerun or relabel historical stages.

## Exact owner handoff after publication

Root will provide the full signed checkpoint hash and verify the remote tip.
Each owner verifies it and fast-forwards their own existing branch, preserving
all drafts. Root has not changed any active lane worktree.

Admission: the reviewed source hashes in `lane-review-and-scheduling-v3.md` remain
the release condition. With this corrected runner, execute only
`native-admission-policy-tamper` in your worktree. Preserve any actual preflight
refusal if one occurred; no product test should have run against that refusal.

RUN: verify your unchanged three reviewed hashes and execute only
`native-run-reader-evidence` once using this changed runner. Retain the earlier
pretest refusal in the handoff, separately from the actual new result/fingerprint.

Both commands use `/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run`
and the exact selected stage. After PASS, retain its actual result, sign exactly
the assigned files and verify the original commit for coordinator integration.

Workloads: DNS remains unscheduled until the 0x13/0x14 full-marker correction,
partial-prefix regression and updated hashes pass delta review. No feature
branches need pushing. Outbound bridge delivery is still unconfirmed; this is
the published copyable handoff. Earlier owner agreement is confirmed.

Completed: exact 48-entry ledger, HTTP repair/composition evidence reuse, reviewed
lane releases, selected-closure repair and durable reader provider/caller.
Released/pending: admission/RUN selected checks now have a working scheduler;
DNS correction and review pending. Later families require concrete path contracts.
Blockers: actual accepted reader/telemetry loop, protected policy/lifecycle and
loss/program/map acquisition, serialized broker submission state, owned workload
contexts, cancellation, full timing and real paired environments. Reader ACK bytes
or callback consistency cannot close these missing providers.

1. Wire the common admission/activation → request/process/capability → broker →
   protected observation → independent replay path, including real shared providers.
2. Integrate reviewed signed lane deliveries and finish remaining 31 admission,
   15 RUN and action/task implementation paths, including actual a100 control.
3. Complete the 48-entry verifier/source-custody inventory and publish a freeze
   candidate only after implementation gaps close.
4. Keep final same-deployment campaign, private retention and cleanup pending
   their separate operational release; qualify only from complete actual evidence.

No historical suites, HTTP restaging, cache copies, unchanged retries or live
operations ran. Implementation completion and final qualification remain false.
