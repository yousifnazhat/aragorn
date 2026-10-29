# Phase 3 checkpoint: independent replay, broker compatibility and context release

Starting published checkpoint was verified signed c0b99007ed9cdc43dfdf7a9f1a0b1ce4dacd42ac.
Root inspected its own branch/worktree and fast-forwarded only that branch.
All drafts and active lane worktrees remain intact. The release/schedule
checkpoint 7c505588d0fb4d37d738756f86f4e8629c0b53bb was signed, verified, normally
pushed and remote-matched before new execution. Root supplies the exact final
containing checkpoint hash after signing, pushing and remote-tip verification.

## Completed and actual evidence

Admission's original signed 5889169dad07814788508cdc377f543ed17af9ef is integrated
by fast-forward, preserving c0 and all original lane ancestry. Root verified the
signature, direct parent, exact three paths and tested pins, then inspected its
actual 33-method PASS result/logs. Evidence remains in Admission's worktree;
no cache copy or rerun occurred. Fingerprint:
`sha256:913ead583dc4eff79e8b3986d89b1d0e85e86972cb173c2771737c96a20138d9`.

Exact delivered paths:

- `src/aragorn/native_phase3_run_submission_verify.py`
- `tests/test_native_phase3_run_submission_verify.py`
- `docs/phase3/admission/SUBMISSION_REPLAY_HANDOFF.md`

Actual result.json 810 bytes hashes to
`sha256:8ae24aba65a79e7c407979116b544d8e81bcb6be9ad120f8d725861e345386f2`;
stderr 6105 bytes to
`sha256:9e3a96640e9fb1aeba1aecd4ac5d918898c5a69ec5c3e47902cfc735e7b395bc`.
Replay verifies byte consistency with conservative SUBMITTED/UNKNOWN and all
authority flags false; an open prefix is not proof of NOT_SUBMITTED.

Root fixed the real broker/shared-runtime-GID incompatibility without weakening
existing account/file protections. Only four newly scheduled delta/composition
methods ran, once, all PASS. Actual pre/post fingerprint:
`sha256:7107b9706c8e9efa605f5d39343a754e88a95fecb419f16718ea00485b1c2144`.
`coordinator/broker-shared-group-handoff.md` retains exact source, complete closure
reference and result/log pins. The new composition consumes actual journal bytes
with Admission's real independent verifier under fabricated OS primitives.

The historical 28 journal result remains attached to old bytes; no 32 aggregate
is claimed. Reader first 59 FAIL / 57 ok and writer-only 31 PASS remain separate,
including the unchanged 28 successful session method results from that failure.
Transport 30, checkpoint 53, DNS 13 and HTTP 14/7 evidence remain unaffected. Neither
unchanged staging nor a historical suite was run. This is implementation evidence,
not native health, installed custody, timing feasibility or final qualification.

## Released and pending assignments

All three external owners explicitly acknowledged c0/v7. RUN is implementing
the five DNS acquisition paths. Workloads delivered its assigned destructive/a100
design-only review; Root inspected it at SHA-256
3028a8d267d9cc6b50d354b521e881155b86693b2026a66c6cc02d843c97838a.
No destructive source or new validation is released yet.

Provider v9 and broker-reader-context-contract-v1.md release three new paths to
available Admission: protected context acquisition, its focused test file and
BROKER_READER_CONTEXT_HANDOFF.md. Acquire actual peer/proc/namespace/control
records and replay the actual BOUND prefix; trusted caller expectations and
receipt authenticity remain explicit later Root obligations. No context test is
scheduled until stable source and complete closure are reviewed.

Root's bootstrap review fixes a separate two-FD cancellation/PIDFD rendezvous,
same broker MainPID/accounts, Root-owned both-side observations, broker-local
observation limits and separate bootstrap/session readiness. The HTTP94 review
pins actual generated predecessor bytes, immutable configured measurement bytes,
original acceptance/deadline/lock ordering and full successor inventory work.
The existing HTTP94 report remains unchanged at
`sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9`.
The full IPC/launcher source assignment remains pending exact packet/API/input
origins, readiness transport and final generated closure. The draft is not a release.

Outbound delivery attempted after fresh incoming acknowledgments still failed;
no unchanged retry followed. Published v9 handoff receipt remains unconfirmed.
Use the exact copyable instructions; owners verify and fast-forward their own
branches only. No extra worktree is needed for current ready assignments.

## Concrete blockers and remaining Phase 3 steps

Actual protected bootstrap/service/reader/bridge startup, post-exec bridge
stdout/stderr CLOEXEC, authenticated stream and complete loss/program/map
observations, generated caller/deployment/capture inventories, policy/lifecycle
acquisition, destructive/a100 ingress/custody/barriers and real paired contexts
remain open. Missing loss is UNKNOWN and requires REFUSED/LOSS_UNAVAILABLE.
Post-submission ambiguity and full REQUEST_ACCEPTED -> DECISION_FINALIZED remain
mandatory. Every final qualification position in the same 48-entry ledger stays false.

1. Implement and integrate ready shared providers with only newly scheduled
   focused validation; connect each leaf to its owning caller.
2. Wire full HTTP, then DNS/destructive, every admission/RUN path, genuine a100,
   cancellation, full timing and four actual paired tasks.
3. Close the 48-entry path/consumer/source-custody inventory and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. Live operations, private retention and cleanup remain held.
