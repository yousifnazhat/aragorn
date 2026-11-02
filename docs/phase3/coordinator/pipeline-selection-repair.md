# Selected worktree closure repair

RUN's scheduled command at `22c05de348c1585ab9bdf17bf8cc1ba119c7f53d`
refused before any test/state/fingerprint creation, exit 2, elapsed 0.247275375s:

```text
phase3 pipeline refused: [Errno 2] No such file or directory: 'native_phase3_admission_policy_tamper.py'
```

The selected RUN source was unchanged. Coordinator registry publication exposed
an existing runner bug: `load_registry` read every stage's files before selecting
a stage, and the main loop also fingerprinted unselected stages. Thus unmerged
source in another owning worktree blocked an otherwise complete selected closure.
There is no test result or fingerprint to invent for this preflight refusal; the
owner retains the actual CLI outcome in its handoff. No unchanged retry ran.

Root's correction keeps global registry schema, path syntax and dependency graph
validation. It fingerprints the entire selected transitive closure before state
creation or any launch, then visits only selected stages. The pre/post-execution
recheck also hashes only that selected closure. Missing, substituted or unsafe
selected/dependency inputs still refuse before any test. Default all-stage
selection still requires all inputs. All callers were searched; no public caller
outside the runner and inert capacity tests calls `load_registry`.

Two reviewers inspected the production diff and six new focused cases. Complete
source closure and SHA-256:

```text
46163b06a07679d157d1d37b23a8b627ea52fce1e37808753937ebbfd6edee58  scripts/phase3_pipeline.py
efb5b9ac6a090c18585e9556849806cba467cfdfa4532ea8e8b3b80c3af5d945  tests/test_phase3_pipeline_selection.py
```

The test imports only the runner and stdlib. Inline temporary files are inert
fixtures, not copied caches. `_execute` and process launching are guarded mocks.
Cases cover selected status, selected execution/current-pin checks, full closure
preflight before state, missing dependency/default-all refusal, selected symlink
refusal, and invalid unselected registry schema/path/graph. Before execution,
source review corrected the status fixture to retain BLOCKED_DEPENDENCY while
its dependency is NEW; no failed behavioral run occurred for that draft.

Root registers and schedules only `pipeline-selected-closure`, `needs: []`, 120s:

```sh
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run pipeline-selected-closure
```

After PASS, the already-reviewed root reader-storage stage can run with this
corrected runner. Publish the signed implementation checkpoint and exact hash
before releasing changed-runner execution to admission/RUN owners. DNS still
waits for corrected source review. No lane worktree is mutated by Root.

The runner digest changes prospective pipeline fingerprints. Existing unaffected
product results retain their original fingerprint, actual environment and claim
limits; do not copy or relabel those caches and do not rerun historical suites.
This coordinator scheduling repair does not invalidate their unchanged behavior
evidence or qualify Phase 3.
