# D2 batch 59 — acquire mask evidence at the stopped worker

Parent: signed merge `332d579`. This is an offline implementation, not an
authorization or a record of a worker being observed. B49 remains null.

The protected caller has one new entrypoint,
`pi_core_native_supervisor.run_native_pi_stopped_mask_capture`. It takes a
held restricted launch plan through the existing supervisor, not an arbitrary
PID. The ordinary startup path stays separate. Capture mode requires the
provider-unavailable route, an explicit attempt and private storage roots, a
pinned interpreter, and sufficient time reserved for owned cleanup.

| Boundary | What the implemented path does |
|---|---|
| Worker stopped, before readiness | Reuses the existing gate, tracer thread, pinned executable, generation, unit invocation and PID handle. Inspects a single stopped task; does not release it into Node, dispatch a request, or return a healthy RUN result. |
| Mask evidence | Holds the manager's empty mode-0000 systemd backing directory and the worker root, namespaces and private device directory. Retains both raw mount streams and opening/closing object identities. A separate child uses the pinned interpreter and fixed helper source. The parent verifies the child's dropped credentials, capabilities, namespaces, root and device handle before permitting named lookups. |
| Scope | Only `/dev/pts` and the three B58 conditional names (`shm`, `hugepages`, `ptmx`). Records actual return values, errors and times; permission denial alone does not prove a mask. An accessible object does not turn into a reported denial. |
| Custody | Five byte strings: capture bindings, worker and manager mountinfo, the held-view record and the separate probe witness. Private, root-owned pre-existing directories; writable direct ext4/xfs backing separate from service state and outside Pi's visible mount roots. No overlapping, nested or aliased store/receipt roots. A no-replace receipt outside the content store pins all five members. Publication includes readback. |
| Replay | `pi_core_stopped_mask_capture.replay_stopped_masks` requires the capture and receipt pins. It reads the local receipt and original bytes and recomputes the named-mask comparison without starting a worker or writing into the store. Matching records do not prove where a freely supplied receipt pin came from. |

The observer is single use. A complete inconsistent observation can retain a
negative finding. An unbound gate, incomplete acquisition or unsafe destination
cannot publish a successful finding; partial material must not be retried or
promoted. An uncertain worker stop/cleanup remains a hold. The helper's
lookups are its own, not Pi's; equality of filesystem and credential evidence
does not establish identical LSM/seccomp state.

These local roots need not have separate administrators or physical media.
They provide neither an off-host custodian nor a rollback fence. B59 does not
fabricate a B58 outer witness: a complete walk and separate, authenticated
current head bound to the same actual deployment are still required. The B37
host closure and all frozen predecessor artifacts were left unchanged.

## Offline verification

| Stage | Checks passed on first run | Retained fingerprint (SHA-256) |
|---|---:|---|
| `pi-core-stopped-mask-observer-offline` | 43 | `451281fef2513ca5f196afd0000007125dc61fa3276cda75421f38b5adbbf0bb` |
| `pipeline-capacity` (288-stage registry boundary) | 4 | `bbdc2cb27c58d08d5c2c5092b71e25df5546718052a193b76135c33a9a2e5c82` |

Only those two stages ran. Gate ownership, kernel reads, child startup and
privilege changes were represented by inert fixtures; the custody and replay
checks used actual private temporary files. No guest, privileged probe, system
service, provider, broad suite or historical capture ran.

## Remaining gates

1. **D2:** pin the changed observer, helper, interpreter and trusted dependency
   closure in a protected successor. Connect the complete walk and current
   witness; separately authorize installed observation, recovery/timing and
   the useful pilot. No storage admission or runtime health is claimed here.
2. **D3:** connect remaining admission, RUN/health and workload evidence on
   the common deployment.
3. **D4:** close independent verifier coverage for the 29 managed requirements
   and freeze once all prerequisites are met.
4. **D5:** only after separate authorization, collect fresh admission results,
   100 real attempts and 100 task pairs; independently replay results and verify cleanup.
