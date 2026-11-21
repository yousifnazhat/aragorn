# D2 batch 62 — connect the protected caller to the stopped-worker observer

Parent: `7c9a12d0a47eea178df03915912ccbef7c1e457a`. B59 already observed
the stopped generation and retained the original mask records outside Pi;
B61 already replayed them alongside a separately supplied B58 archive.
This batch connects that path to the protected coordinator. No new worker,
evidence store, plan, approval, guest capture or B49 binding was created.

The root wrapper's separate `--capture-stopped-masks` route requires distinct
digests for the host, plan and release. It checks the installed interpreter
and consumed observer sources and holds the existing service configuration,
grant and restricted, provider-unavailable worker plan. No PID, arbitrary
command, resume request, provider credentials or fallback path is accepted.

The release must already exist at `/etc/aragorn/approvals/stopped-mask-release.json`.
It nominates one guest boot, deployment, plan, host profile, attempt and claim
directory identity. The complete original deadline must fit its short window.
The caller exclusively creates and reads back the spent marker in a separate
private durable ledger *before* calling B59. After setup and the last unit-absence
check, it rechecks the held approval bytes, original claim identity and bytes,
boot, storage paths, clock window and remaining start budget. A refusal does
not retry or refund the marker. This is a local same-boot guard, not protection
against trusted-host rollback or proof of a current off-host witness.

Capture uses B59's retained process generation, fixed masks and two private
destinations. A verified *negative* keeps its evidence but exits unsuccessfully.
The wrapper withholds both digests if custody or cleanup is uncertain; records
are not deleted. Neither a matching mask record nor verified release custody
authorizes Pi to proceed or establishes deployed isolation.

Only two affected pipeline stages ran, both passing on their first invocation:

| Stage | Checks | Retained fingerprint |
|---|---:|---|
| `pi-core-protected-mask-capture-offline` | 39 | `5070664729b7a326dde7d0d1155a8051fc14aca40c2113a73a46222629a4f227` |
| `pipeline-capacity` (292 slots) | 4 | `0cfaf26e60d806d5138b3f998efcbcd43b3aecda4484ca24ccda96587cbd9306` |

1. **D2:** pin the updated protected caller and its sources in a successor;
   acquire the full worker walk, role observations and independent current
   witness on a separately approved deployment. Installed identity, sensor
   health, recovery, full timing and the useful pilot remain open.
2. **D3:** complete connected admission, RUN/health and workload coverage.
3. **D4:** complete the independent inventory for the 29 mapped requirements,
   then freeze one deployment.
4. **D5:** after separate authorization, run fresh surface acceptance,
   100 attempts and 100 paired tasks; verify thresholds, cleanup, restoration
   and independent replay.
