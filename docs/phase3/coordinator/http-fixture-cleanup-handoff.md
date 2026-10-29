# Shared HTTP/DNS fixture cleanup: actual handoff

Released by v10 at cd38874f58d8716cd7cb4ce1320454ecd6556577. Root and an
independent reviewer approved the final stable source/complete closure before
Root published the signed selected schedule
ff1b0ee83d3459744bbdd4633e30d0d57f2cb328 and verified its remote tip.

## Exact implementation and dependency closure

- `src/aragorn/native_phase3_http_fixture.py`, 11930 bytes,
  sha256:caa7ec1bf5ff1f768fe626009fdf208472f169abca539c5374ccf69b0f144f93.
- `tests/test_native_phase3_http_fixture_cleanup.py`, 24349 bytes,
  sha256:47b0166f5b278268a33859194faad9bd10f97403915fec9ea1e598d32e8a5629.

`http-fixture-cleanup-review-and-scheduling-v1.md` retains all nine actual project
pins, standard-library/fixture/OS boundaries and the 25 selected cases. No new
source edit followed review or execution. Public context, identity and `_fds`
layout remain intact. Each persistent handle is tracked before metadata and is
closed once only after matching original owner, held identity and actual flags.
Namespace link/type/expected identity and a bounded live PID 1 fdinfo association
are required. The local fdinfo reader also owns its transient descriptor.
Changed/unknown handles are skipped; independent safe closes continue. Caller
or final-guard failure keeps precedence; otherwise the first cleanup interruption
survives. Ambiguous close is never retried.

The nested cleanup-interruption defect was found and corrected during source
review, before any execution. The actual result below is the first selected run.

## Actual retained result

Stage `native-http-fixture-cleanup`: PASS, exit 0, 25 methods in 0.088s.
Pre/post fingerprint both:
`sha256:eb00a04f5617bf8caac3b558f8e0dab0f7b7491a523409bd4b0eb6e1d18a6c37`.
Actual files remain in the owning Root checkout at
`.aragorn/phase3-pipeline/native-http-fixture-cleanup/eb00a04f5617bf8caac3b558f8e0dab0f7b7491a523409bd4b0eb6e1d18a6c37/`.

- result.json: 809 bytes,
  sha256:8fe0dcb4dff5743e30be994c7fd812f65ee06fdbf13d299bf26d3894d4142a12.
- stderr.log: 5020 bytes,
  sha256:798d7bf99b33ce7daebca96d2576be9f0074fe873bf2da9413259d01c84d03d3.
- stdout.log: 0 bytes,
  sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.

Root read the actual result and every method result. No historical suite, DNS
acquisition stage, copied cache, unchanged retry or operational action occurred.
Old HTTP and other retained evidence remain attached to their original closures;
this result creates no combined aggregate or new staged/deployed report.

## Handoff and limits

RUN fast-forwards its own existing branch to the containing signed integration
checkpoint, preserving drafts, and includes the exact new helper pin above in
its corrected DNS closure. Implement only the five paths already released by
v7 and the corrections in `dns-acquisition-source-review-v1.md`; no DNS stage is
yet scheduled. Submit stable corrected hashes, complete dependencies and focused
cases before execution. Root never changes active lane worktrees.

The fixed cleanup path has fabricated-OS evidence only. Legacy process-helper
virtual reads retain their existing ceiling; there is no global transient-FD,
atomic FD-table, hostile-root, installed-custody, loss-completeness or qualification
claim. Actual Root launch/IPC, protected acquisition and independent consumers
still need full causal wiring. Historical HTTP94 report remains unchanged at
sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9.

Completed: v10 implementation, independent review and first selected PASS.
Released: RUN corrections with integrated helper dependency; Admission v9 context.
Pending: actual corrected lane delivery, concrete bootstrap/launch release and
Workloads destructive/a100 source contract. Newer handoff receipt is unconfirmed;
outbound bridge has no listener and was not retried unchanged. No new worktree.

1. Implement/integrate ready providers using only newly scheduled focused checks.
2. Wire HTTP/DNS/destructive, all admission/RUN, real a100, cancellation, full
   timing and four actual paired tasks.
3. Close all 48 path/consumer/source-custody conditions and publish a freeze candidate.
4. Separately release 31 cases/100 actions/100 pairs on one deployment, independent
   replay, existing gate evaluation and approved cleanup. Operational holds remain.
