# Upload-disabled INSTALL recording helper

The recording helper extends the checked consumer at signed commit
`52be73dcf68eaafb7ec507805524d27d33fc6501`. It performs no process launch,
filesystem mutation, service activation or shared dispatch itself.

`record_native_admission_install` accepts the verifier's five caller bindings
plus two trusted callbacks:

- `read_boundary()` returns the existing native direct-write boundary record.
- `run_command(argv)` returns a `subprocess.CompletedProcess` with matching
  arguments, an integer return code and byte stdout/stderr. The future native
  launcher owns execution limits, privilege drop, gateway liveness/namespace,
  source custody and credential handling. A bare unbounded subprocess callback
  is not an approved native integration.

The helper reads boundary/catalog state, validates the protected snapshot and
rechecks it immediately before one fixed non-force upload INSTALL attempt. It
retains actual validated denial stdout and its byte count/digest. Unexpected
install responses retain available exit/length/digest metadata without copying
arbitrary diagnostics. An interrupted or timed-out invocation remains unknown,
not a successful denial, and is never retried. Post-attempt boundary and catalog
reads are independently attempted even after an install failure. Interruptions
propagate with the partial record on `_native_install_observation`.

Only a complete record accepted by `verify_native_admission_install` becomes
`OBSERVED`. All qualification flags remain false. The existing observation
schema and limitations are unchanged: this callback helper does not close the
pending native producer/source-custody or common-dispatch integration.

## Focused checks

The existing reviewed `native-admission-install` stage already binds every
repository input, including the reused fixture's producer import. No registry
or cache coordination change was needed. The prior exact six-test result was
observed as `SKIP_PASS` before editing:
`sha256:9f936cf6e0b82656ac1230777b99920e121b8b6f3626f199dd53779abd62e049`.
The integration checkout's registry was inspected; it had no install result
directory. The prior result resides in this admission worktree's cache.

One selected pipeline invocation passed **16 tests**: six affected consumer
checks and ten new mocked recording checks. No other stage ran.

- Command: `/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-admission-install`
- Fingerprint and post-fingerprint: `sha256:0d3692546c31cc2733070f93f85a83a7ee6cd13b45f1d93b8974b53c6cd105c2`
- Result: `.aragorn/phase3-pipeline/native-admission-install/0d3692546c31cc2733070f93f85a83a7ee6cd13b45f1d93b8974b53c6cd105c2/result.json`
- Test log: 2,853 bytes; `sha256:f40530029d08038e67fd4809a5e6b8d72b04acf6687a30e34be2a5fb9b655843`

Checks cover exact command ordering/bytes, one attempt, malformed caller/result
contracts, boundary drift, unexpected diagnostics, timeout, failed readback,
independent replay rejection and interruption retention. All command and boundary
operations are mocked. Static review and whitespace checks passed.

## Coordinator handoff

Shared dispatcher, capture, installed-source identity inventory and staging remain
unchanged and deferred. Before any native execution, the coordinator must bind a
bounded command runner and the existing native boundary reader to the owned
gateway process/namespace, retain helper/verifier source identities, and compose
the outer retention/cleanup lifecycle. No callback simulation supplies that proof.
Local-path, ClawHub and dependency INSTALL coverage remain outside this branch.
The fixed exit gates and the unresolved October 9 fixture-cleanup hold are intact.

1. Shared startup/capture/listener integration: unresolved.
2. Admission and RUN/measurement implementation: current work.
3. Independent verifier inventory, then freeze: pending.
4. Final acceptance: blocked until prerequisites close.
