# Independent submission replay: source review and selected stage

Source base: verified signed `95b676eca174ae5cb117fe778d3359f0e924b425`.
Root release base: published `0b819f3e953aff0c879298d96d76c9d35e2f7590`.
The containing signed published checkpoint registers and schedules exactly one
new stage in the existing Admission worktree. Root does not execute it there or
mutate that worktree. Owner preserves every existing draft and fast-forwards
their own branch after verifying the supplied published hash.

Root read the complete independent verifier, reviewed the actual import closure,
and obtained separate source and all-33-case fixture reviews. No concrete blocking
defect was found against broker-reader-provider-contract-v1.md and the accepted
v5 interpretations. Canonical fields, bounds, independent expected identities,
context/packet/phase chains, full budgets, fresh phase-two observations, immutable
reader fields and conservative submission state are enforced. Null terminal pins
remain open-prefix analysis; a verified intent stays SUBMITTED. REFUSED with null
unavailable loss cannot release another intent. All five authority flags are false.

Stable complete repository behavioral closure, rechecked before registration:

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
277f090094e8335850605c5ee793042cafc831764c24a136fddb1b277cf335a7  src/aragorn/native_phase3_run_submission_verify.py
616258ca1bba22b1e9d6c7d1a619b690f46b0a9594cc1f36ad9afc40ffe1c8a1  tests/test_native_phase3_run_submission_verify.py
```

All other imports are stdlib. The initializer has no imports. Fixtures are
independently authored inline contract bytes, not producer-generated records.
There are no runtime file reads, generated sources, external fixtures, historical
TestCases or producer/parser imports. The pipeline additionally binds its runner,
worker lock, selected registry entry, interpreter/toolchain and environment.
The mutable handoff and review contracts are not behavioral inputs.

The 33 methods cover every phase/prefix/terminal position, external and packet
substitution, strict schemas/canonical bytes/false flags, unknown/reset/increased
loss, partial refusal, reader/baseline continuity, timing, aggregate bounds and
immutable caller inputs. Generic ValueError assertions in raw-bound tests do not
independently prove parser resource behavior; source inspection confirms bounds
precede parsing. No actual producer composition, kernel custody or deployed
acquisition is established by this independent fabricated-byte stage.

Only this stage is scheduled, in
`/Users/yousi/Documents/Commits/aragorn-phase3-admission`:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-run-submission-replay
```

Registry: test_native_phase3_run_submission_verify only; the three inputs above;
needs=[]; timeout 120 seconds. Existing entries are unchanged. First inspect the
actual selected fingerprint and any existing result in the owning worktree and
coordinator checkout. Hand off an existing matching actual result instead of
rerunning. Otherwise execute this selected stage once. Preserve result/log bytes
and fingerprint on success or failure; diagnose any failure before a documented
changed retry. Do not run unchanged Root broker tests or historical suites.

After reviewed PASS stage exactly the verifier, its test and
`docs/phase3/admission/SUBMISSION_REPLAY_HANDOFF.md`; sign one commit, verify it
and hand off the original hash, paths, actual result/fingerprint, limits and
blockers. No feature push is needed. Root will integrate preserving ancestry.

Completed: stable source/full closure review and one selected stage release.
Pending: actual Admission result/signed delivery; RUN transport; raw checkpoint,
real reader/loss/bridge and shared broker/deployment integration. DNS's signed
13-check result and Root's signed 28-check result remain unchanged.

1. Finish released providers, review focused results and integrate signed leaves.
2. Wire full HTTP/DNS/destructive/admission/RUN paths, real a100, cancellation,
   full timing and four actual paired tasks.
3. Close the same 48-entry source/path/consumer inventory before a freeze candidate.
4. Separately release the final 31-case/100-action/100-pair campaign, independent
   replay, existing gate evaluation and approved cleanup. Operational holds remain.
