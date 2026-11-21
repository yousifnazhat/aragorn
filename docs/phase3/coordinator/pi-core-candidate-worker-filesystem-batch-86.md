# D2 B86 — the fixed-view gate is in a complete offline worker filesystem

B83 staged four runtime files, but the B53 worker filesystem still contained
the old gate. The [successor packager](../../../scripts/prepare_pi_core_candidate_filesystem.py)
reads the signed B53 archive by its complete byte digest, checks the B83 gate
against the separately reviewed candidate inventory and changes only that
member. It reuses B53's archive writer and readback. It never extracts the
archive, copies a state seed, compiles code, installs a view or starts a task.
An existing or partial destination is never adopted.

The expected inventory combines the B83 manifest with the eight loader
identities for the unchanged Node executable from B37 and the pinned OS
receipt. An ordinary v2 installed source plan is **not** issued for this
candidate: B36's observer and launcher do not support the new gate.

The [signed checkpoint](../../../packaging/pi-core/worker-filesystem-b86.json)
is the exact local outcome. Its worker archive digest is
`69e4d86da0c89abfed53873ef500ff63c8e4898c369c05841206ba22e4cbb03e`.
The archive stays in `~/Library/Application Support/Aragorn-B86-Offline/`,
outside Git. Direct comparison with the original archive found the same 22
directories and 13 files; only `opt/aragorn/pi-runtime/observer/source-gate`
changed. All twelve other file payloads and all member modes were unchanged.

| Affected offline stage | Passed | Fingerprint |
|---|---:|---|
| Candidate content inventory | 5 | `c95c82c1df1aa3bb308fa4b50660ceca5786a863906cfe664fdfaa1efce4e3a7` |
| Intake and no-overwrite refusals | 3 | `d18a9fe1ce1e190eabb2d2c4aad29eaa1bdfac74d007cb0534e80ad76e5021e7` |
| Exclusive archive assembly and direct comparison | 1 | `833bce27f008e4e51ed3f1712fcf81f37c917b1cd11a90b251c65f3df2eaf6e3` |

1. D2: use this exact archive for the candidate worker view. Connect the fixed
   worker-side lookup/results to the independent observer and verifier. A
   staged gate does not prove listing denial, process-relative link identity,
   health, state isolation, recovery, timing or usefulness.
2. D3: finish admission, RUN/health and workload paths on the common deployment.
3. D4: independently verify the complete 29-requirement inventory before freeze.
4. D5: separately authorize fresh admission, 100 attempts and 100 task pairs;
   verify cleanup and replay. B49 and all live holds remain unchanged.
