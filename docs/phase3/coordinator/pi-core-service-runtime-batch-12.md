# Pi-core D2 batch 12: protected service bytes and authenticated channels

Date: 2026-11-05. Base: `99cc411dec8e89703ee2962674b36c351d32c073`.
Scope: connected source implementation, reviewed new/affected offline checks,
verified signed commit and normal existing-branch push. No live operation,
credential setup, provider call, native service activation, pilot or qualification.

## Reuse and delivered behavior

Two parallel lanes owned the service-runtime provisioner and authenticated-channel
holder, with a third independent review lane. Root owned the existing native and
provider callers, integration fixtures, pipeline registration and documentation.
Existing descriptor-safe installer, canonical receipt, process-identity, packet
credential, native request and provider-v2 components are reused. No successor
broker framework or replacement service protocol was introduced.

### Protected service runtime and code provisioning

`pi_core_service_provision` accepts an independently reviewed complete runtime
manifest plus a separately pinned binding. Its fixed Linux arm64 layout contains
a regular `usr/bin/python3`, Python3.12 standard library and native extensions,
the dynamic loader/shared libraries including OpenSSL, and
`opt/aragorn/src/aragorn` Python sources. Fixed provider/action/sensor roles name
the existing handlers; callers cannot substitute arbitrary modules or functions.
Source digests cover every supplied source file. Bytecode, symlinks, hardlinks,
unexpected files, unbound empty directories and unsafe metadata refuse.

Provisioning is absent-only, with bounded file copies and per-chunk deadline
checks. It verifies both source and installed bytes, protected ownership/modes,
named parent/deployment/root/receipt identities and canonical receipt readback.
Failures retain partial output; there is no overwrite, automatic repair, rollback
or execution. The receipt status is
`PROVISIONED_SERVICE_BYTES_NOT_EXECUTED_OR_SERVICE_READY`, with credential,
activation, readiness, loaded-code and Phase 3 eligibility claims all false.

`hold_pi_service_runtime` retains protected path/file descriptors and yields a
sealed active verifier. Guards rehash the installed tree and receipt against the
independent pins, including final validation on successful scope exit. Scope exit
withdraws authority and closes only owned descriptors. Ancestors above the
deployment bind device/inode/owner/mode, allowing unrelated sibling churn; the
deployment itself retains full metadata, name and byte checks. Serialized
receipts, arbitrary callbacks, subclasses and unsealed objects are not custody.

Essential-library validation is not automatic dynamic-import discovery, ELF/ABI
compatibility proof or proof of which modules Python loaded. This batch does not
assemble or publish a real reviewed service image. The operator must supply that
complete closure independently; authored test bytes are not deployment pins.

### Authenticated channel custody connected to existing callers

`hold_pi_service_channels` accepts three caller-owned, already-connected
post-exec AF_UNIX packet channels for action, sensor and provider services. It
opens only new peer PIDFDs and binds exact kernel peer credentials, distinct
nonroot role identities, process start generations, single-member cgroups and
current interpreter hashes to the held runtime's Python pin. Kernel peer/current
interpreter checks do not independently prove a socket's creation time relative
to exec; the lifecycle caller must supply the post-exec connections.

The sealed lease creates the existing `PiNativeRequestChannels` configuration.
Native request guards and opt-in provider-v2 mediation now consume that exact
lease, rechecking deployment and service identity before request consumption and
through nested action/CONNECT/SEND guards. Optional `None` retains the prior
caller contract; native START is not activated. The sensor's existing distinct
filesystem identity remains the sensor handler's responsibility, not a generic
four-UID equality rule.

After an exact per-message-authenticated provider-v2 RESULT has been validated,
the provider is irreversibly retired. This allows the provider to exit before
later tool work while preserving action/sensor liveness and code checks. Its
socket/kernel peer remain bound; no later provider exchange or second retirement
is accepted. Retirement is not unit-exit or cleanup proof. The holder never closes
borrowed sockets, starts/stops services or releases another owner's resources.
PIDFD-close uncertainty becomes a cleanup hold without retry.

## Review and focused verification

The code-review skill and independent review drove three pre-execution fixes:
propagating each tighter caller deadline into tree/peer checks, distinguishing
ancestor sibling churn from changed deployment custody, and making provider
retirement persistent rather than a one-call liveness waiver. Held runtime seals,
failure cleanup, fixture isolation and unchanged predecessor boundaries were
also reviewed before execution.

All **120 distinct selected checks passed on their first execution**: 112 new,
four selected affected native/provider caller checks and four affected registry
capacity checks. No check was rerun.

| Selected stage | Checks | Successful fingerprint |
| --- | ---: | --- |
| `pi-core-service-runtime-offline` | 47 | `sha256:bd09e07fa439977801e4917511b680f06619995f9923004a7e109bf211a607ec` |
| `pi-core-service-channels-offline` | 48 | `sha256:f52afb2da971bf53c58c5f6b7771e220605aaea7150b2136938c4c89d06e277a` |
| `pi-core-service-integration-offline` | 21 | `sha256:f2ba33901b211abe2a24a750a18c41295af8d2e08d765e74aa6db6f2b4b49018` |
| `pipeline-capacity` | 4 | `sha256:d67e329951492faf7aeb056fbc23f024a7b1f843ad248b1197a66555ad289441` |

Only `scripts/phase3_pipeline.py` scheduled these stages using reviewed
`benchmark/phase3-pipeline-v1.json` inputs. Static import review identified
57/63/73 source/fixture inputs for the new stages. Capacity increased 161 to 164.
Results and logs remain under `.aragorn/phase3-pipeline/<stage>/<fingerprint>/`.
Historical suites were not scheduled; imported fixtures do not imply their full
suites ran. Prior PASS/failure records and frozen predecessors remain intact.

The provisioner used exclusively owned temporary authored files with modeled
Linux/root ownership. Channel and process edges were inert, and caller fixtures
reused existing modeled guards. No service process, socket, compiler, OS image
assembly, credential, paid request or live workload ran. These developer checks
do not establish Linux deployment, loaded-code, admission, RUN or timing proof.

Full-tree/interpreter rechecks may exceed the current short action/provider
permit budgets. Guards propagate the tighter original deadline and fail closed;
they neither widen the 100ms provider limit nor claim timing feasibility.
Existing bounded process readers are checked before and after calls, not made
preemptible by this batch. Concrete service-image composition and measured
feasibility remain prerequisites, not silently accepted assumptions.

The signed commit containing this checkpoint and exact remote SHA readback are
recorded in local ignored `.aragorn/pi-core-service-runtime-batch-12-release.json`
and the chat milestone. Unrelated user drafts are excluded from the commit.

## Remaining plan and evidence ceiling

Native START remains `provider_status: UNAVAILABLE`. Frozen broker/deployment
predecessors, retained evidence, the 29-requirement mapping and historical exit
manifest are unchanged. No operational hold or qualification gate is cleared.

1. **D2:** assemble the concrete reviewed Python/OpenSSL/service-source image
   and executable service wrappers. Connect protected service-unit startup,
   authenticated channel acquisition, exact process/unit lifetime and stop to
   native START, with consumed-code identity and recovery evidence. Establish
   bounded timing feasibility; select the concrete model/trust/credential
   deployment profile without activating it implicitly. Then run one useful
   controlled pilot only under separate authorization, retaining independent
   output/effect/health and verified cleanup evidence.
2. **D3:** complete remaining admission, RUN/health and workload/paired-task
   coverage on that same common deployment.
3. **D4:** complete the executable approved acceptance mapping and independent
   verifier inventory, then freeze once the prerequisites close.
4. **D5:** run required fresh final acceptance and measurements with cleanup
   evidence, followed by offline replay. Only genuine gate closure completes
   Phase 3 and permits consideration of Phase 4.
