# Pi-core batch 21: credential, egress and approval custody

Base: signed integration `8a1424a6db14a5e9bcf17f6ed87c82c82667377d`.
Scope: additive offline implementation and focused affected checks, followed by
verified signed source/integration commits and normal remote publication. No VM,
service, credential setup/read, live socket, provider call or pilot is authorized.

## Connected change and ownership

Three parallel lanes own the new credential holder, the existing service
lifecycle successor, and the new activation-bound approval holder, with separate
focused test files. The coordinator owns managed/native caller joins, the
mediator's held-profile lookup, shared registry, review and delivery. Lanes do
not run checks or change Git. Existing worktrees and unrelated drafts remain.

The credential holder reuses protected ancestry and metadata custody. It opens
one already prepared root-owned, mode-0400, single-link regular source and keeps
its non-inheritable descriptor. It never reads, hashes, copies or deletes the
key. Systemd receives the held descriptor path for exactly `openai-api-key`;
the existing protected provider transport remains the only application consumer.
The holder joins the same exact public provider profile and CA custody.

Only the provider unit gets a credential mapping and IP-capable address family.
The requested rules deny both IP families and allow only the approved address
as a /32 or /128. Exact structured readback rejects extra credentials, imported
credentials, changed addresses, broad prefixes and unexpected hooks. Broker,
sensor and worker restrictions are not relaxed. Cleanup retains exact captured
unit/process ownership and does not require revoked request authority to stop
an owned service. Borrowed input holders remain caller-owned.
Enabled preflight requires systemd 257 or newer before preparing services, since
the exact credential-import readback uses
[the version-257 manager API](https://www.freedesktop.org/software/systemd/man/257/org.freedesktop.systemd1.html).
The exact manager credential directory must be absent before provider start and
again after the captured provider exits. Residue retains a cleanup hold; Aragorn
never deletes or adopts a manager-owned credential directory.

The root approval intent pins the route, data class, full payload digest,
one-request budget and existing policy/action fields. It does not create policy,
healthy telemetry, observations or state. Session/run/tool identifiers are
absent from the static intent; they are derived only from the authenticated
captured activation and exact prepared request, before protected START. The
existing approval validator is reused. Publication is absent-only, read back,
and one-shot; partial failures and permanent replay claims are retained, never
erased to retry. Guards accept legitimate subsequent state consumption without
treating it as new authority.

The managed caller requires both held credential and held approval when the
protected provider profile is selected. Its unavailable default rejects those
objects rather than silently enabling them. The native dispatcher binds the
approval before START and retains the existing authenticated terminal/retirement
and action ordering. Root mediation reads the same held public profile as the
provider unit, including fresh CONNECT/SEND checks; it does not read an unrelated
host `/etc` profile when service custody is present. The no-custody legacy path
keeps its existing fixed lookup.

## Deliberate evidence limits and next dependencies

Systemd credential delivery and IP rule semantics follow the upstream
[execution documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
and [resource-control documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).
The latter warns that IP filtering can be ineffective without the required
kernel support. **Matching unit properties is not effective-filter proof.**
The exact VM must demonstrate applicable cgroup filtering, provider credential
view, immutable source/loader inventories and Node execution before the pilot.
Unsupported required unit properties refuse; no compatibility fallback is added.

The existing request authority lasts at most five seconds. This batch preserves
its approved absolute times through service startup; it does not refresh them
or widen deadlines. Actual startup/timing feasibility remains unresolved. Root
readiness checks an existing observation's structure, not attribution for the
future activation. A genuine fresh observation producer and complete health
must satisfy the existing mediator before any protected provider operation.

No real model/address/CA profile, spending bound, operator key, dedicated VM or
pilot authorization is selected or supplied by these fixtures. Configuration
and bootstrap results do not become provider availability, useful-task proof,
consumed-source qualification, kernel enforcement or Phase 3 completion.

## Focused verification and delivery

Independent review caught two missing lifecycle prerequisites before execution:
the manager API version floor and explicit observation of manager credential
cleanup. Both were added before the first check. Review also kept the returned
`provider_available` flag false after cleanup, separate from
`provider_configured`, and verified approval locking does not recurse into the
mediator's held lock. Publication uses the authenticated actual activation, not
a precomputed worker identity; cleanup does not erase replay barriers.

**122 distinct new/affected checks passed once; zero reruns.** The registry
selects only four new offline modules plus four affected bounded-capacity cases
(190 to 194 stages); no old behavior or arithmetic suite ran. Input closures
include transitive local imports and actual import-time fixture resources. No
target build or executable was needed. Retained logs are under the matching
stage/fingerprint in `.aragorn/phase3-pipeline/`; no earlier record was changed.

| Selection | Checks | PASS fingerprint (SHA-256) |
| --- | ---: | --- |
| `pi-core-provider-credential-offline` | 19 | `d290ec3d4aacc096b7a532bd2c3ea7539b73399f82f73b21f3f749c9acacafee` |
| `pi-core-provider-lifecycle-offline` | 40 | `d544c2f3bb6ae5e82780ce22c2da18655874d76474741bd4be32b3484f58782a` |
| `pi-core-provider-approval-offline` | 39 | `5fa39281ddcad99ee7d66679a6b74c8b35cd1f30c840695599e23587f0f4c4e3` |
| `pi-core-provider-managed-offline` | 20 | `204cfd5c301523d7b8a73aa2d97d70fa7869b9a61bf4ffc8f55fb2850a699117` |
| `pipeline-capacity` | 4 | `c715ff4cf1890b81b3d63a12e36f211aad03a74be298b3c90c90af5123c15643` |

Only this command executed behavioral checks:

```sh
/opt/homebrew/bin/python3 -B scripts/phase3_pipeline.py run pi-core-provider-credential-offline pi-core-provider-lifecycle-offline pi-core-provider-approval-offline pi-core-provider-managed-offline pipeline-capacity
```

These authored OS/transport fixtures do not establish actual deployment,
credential delivery/erasure, kernel enforcement, consumed source, health, timing,
useful work or cleanup. D2 and managed-profile Phase 3 remain open.

Signed source/merge hashes and exact remote readback are retained in
`.aragorn/pi-core-provider-custody-batch-21-release.json` and the chat checkpoint.

## Remaining plan

1. **D2:** assemble the common changed-artifact successor; prepare/install exact
   protected inventories under separate authority; connect genuine fresh root
   observation/health and establish credential-view, Node and kernel-filter
   feasibility, recovery and full timings. Then separately authorize the useful
   calculate-and-save pilot, necessary denials and verified cleanup.
2. **D3:** finish remaining admission, seven RUN event classes/six responses,
   HTTP/DNS/truncate/unlink and real baseline/instrumented task contexts.
3. **D4:** complete the executable 29-requirement surface mapping and independent
   producer/evidence/verifier inventory; resolve prerequisites and freeze once.
4. **D5:** separately authorize fresh managed acceptance, 100 actual attempts,
   100 actual pairs, unchanged thresholds, retained failures, cleanup/prior-state
   restoration and independent offline replay. No Phase 4 release yet.
