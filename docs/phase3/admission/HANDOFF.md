# Upload-disabled INSTALL consumer — reviewed and focused-check passed

Coordinator batch: 2026-10-11. Branch: `codex/phase3-admission`.
Base: `eb13d0d3eb0d7c29e613c25570cd47fafe6baffb`.

## Completed slice

The independent consumer verifies retained command/response bytes for the fixed
upload-disabled INSTALL denial, protected-boundary and admitted-byte equality,
catalog equality and target absence. Six inert test methods cover valid joins,
mutated contracts/commands, invalid raw bytes/pins and residual/discovered targets.
Static correctness, security, input-closure and test-side-effect reviews found no
blocking defect within this explicitly limited consumer contract.

## Focused verification

- Selected stage: `native-admission-install`; first execution: **PASS**, 6 tests.
- Fingerprint and post-fingerprint:
  `sha256:9f936cf6e0b82656ac1230777b99920e121b8b6f3626f199dd53779abd62e049`.
- Retained local evidence directory:
  `.aragorn/phase3-pipeline/native-admission-install/9f936cf6e0b82656ac1230777b99920e121b8b6f3626f199dd53779abd62e049/`.
- Test log digest (`stderr.log`, 1,068 bytes):
  `sha256:6d8f1d64315b13cef976fa562f6884c911263543f8526f6cf05bfd81159a5754`.
- Only the six new test methods executed. No historical test stage reran; no
  existing failed, interrupted, timed-out or successful record was altered.

Coordinator registration binds all seven repository import inputs, including the
unchanged direct-write consumer and the old test module's fixture/producer imports.
The proposed historical `native-admission-direct-write` scheduling prerequisite
was omitted after review: the selected assertions import its fixture but do not
execute its tests or producer. This does not turn old blocked prerequisites into
passing results and does not qualify direct-write behavior. `needs: []` is only
the scheduling contract for this new inert leaf; runner and lock inputs remain
automatically fingerprinted. The registry addition is coordinator-owned and travels
with this feature commit.

## Integration handoff and claim ceiling

This checked slice is ready for source integration after its signed commit is
verified. The commit contains only the consumer, its tests, its stage registration
and this checkpoint. The exact verified hash is recorded in the coordinator's
post-commit checkpoint; no self-referential commit hash is embedded here.

Native producer, retained real command bytes, common dispatcher, deployed source
custody and installed identities remain pending. Local-path, ClawHub and dependency
INSTALL are not covered. No live operation, capture, measurement or acceptance ran;
every qualification flag remains false. Frozen predecessors and the October 9
retention/cleanup hold are unchanged.

1. Shared startup/capture/listener integration and cleanup hold: unresolved.
2. This admission consumer slice: checked; broader admission/RUN/measurement: open.
3. Full independent verifier inventory and deployment freeze: pending.
4. Final acceptance: blocked until prerequisites close.
