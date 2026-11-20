# D2 batch 58 — independently corroborated worker mask records

Based on signed merge `3f3a37a`. [Decision A](pi-core-worker-mask-decision.md)
is approved for offline work only. No launcher flags, boot media, credentials,
service configuration or B49 fields changed.

Use `python -m aragorn.pi_core_state_admission CAS PROFILE_PIN LATEST_PIN --mask-witness WITNESS_PIN`
to replay an existing private, read-only store. Each expected digest must come
from the independently controlled source it represents. A hash supplied by
the worker, or one located by searching the store, is not an independent witness.
V1 retains its original three arguments, wire format and refusal of masked leaves.

| Record | What must join |
|---|---|
| V2 profile, latest head and role capture | All original B55 volume, generation, fence, subject, mount and device checks. The manager's and worker's user namespace is now also pinned and checked at both ends of the observation. |
| V2 worker walk | Complete ordinary tree, stopped process and descriptor records. A named hidden directory has a marker, **not** a successful empty worker listing. Reachability from its enumerated parent is still checked. |
| Separately pinned mask witness | Exact profile, head, capture, boot and worker-walk digests. Manager and worker subjects, named and held root-owned empty backing object under the manager's `/run/systemd/inaccessible/dir`, worker target object, raw mountinfo and per-mount read-only/noexec options must agree. |
| Bounded helper observations | The held worker and distinct probe have matching relevant discretionary-access credentials and filesystem views, including root and mount/user namespaces. The selected syscall must use the held `/dev` directory and the exact name/flags, inside the recorded interval. Its result must be `EACCES`. The permission result **alone** is insufficient. |

`/dev/pts` is mandatory. If present, `/dev/shm` and `/dev/hugepages` require
the same proof. A visible `/dev/ptmx` must be the independently corroborated
literal `pts/ptmx` symlink through the proven mask. A live character device,
an arbitrary dangling link, an unknown inaccessible path or a hidden descendant
refuses. Other possible systemd masks and process-relative links have no exemption.
The manager's successful empty-source listing and the helper's failed worker-side
lookup are different observations. Neither is used to invent worker-visible children.

**Evidence ceiling:** the output means *consistent offline records*. It does not
authenticate the observers by itself, attest their complete capture, establish
identical seccomp/LSM contexts, prove that Pi issued a syscall, or authorize
launch. The mode-0000 object and capability-free worker identity are independently
necessary to the permission argument. A source mark, fixture or old witness is
not installed isolation, sensor health, or Phase 3 qualification.

## Focused verification

| Reviewed stage | Passed once | Fingerprint |
|---|---:|---|
| `pi-core-pilot-state-mask-witness-offline` | 12 | `0089fabceb39d893fbd6e9df525aec3026d7328784c8dad4cbaf1116e12e5f41` |
| `pipeline-capacity` | 4 at the new 287-stage boundary | `50509ca68e756487c9236014e0938bcd9fd8c08b2b918ebfe7de9b14010030a1` |

The fixtures cover the V1/V2 boundary, substitutions in the raw mount stream,
untrusted/stale records and unproven access. ARM64 open flags were compared to
the pinned sysroot, not to the host's constants. No real syscall against a
worker, guest capture, or broad test suite was needed.

## Next gates

1. **D2:** implement trusted acquisition against the stopped worker and an
   independent witness custodian. Check the actual layout; do not expand the
   exceptions to get a pass. Recovery, timing and the separately authorized
   useful pilot are still outstanding.
2. **D3:** connect admission, RUN/health and four workloads on that deployment.
3. **D4:** finish independent evidence coverage for all 29 requirements before freeze.
4. **D5:** after freeze and separate approval, collect fresh admission evidence,
   100 attempts and 100 task pairs; check thresholds, cleanup and offline replay.
