# Pi-core D2 batch 5: protected worker identity registration

Date: 2026-11-03. Base: `96a8ca03720d35d1d752c2fffbb9ecdcda491de6`.
Release: implementation, new/affected offline checks, verified signed commit and
ordinary branch push. No live operations, deployment or acceptance is released.

## Connected scope and reuse

The root supervisor remains responsible for protected activation, process/profile
measurement, admitted-bundle custody and exact native unit ownership. The
unprivileged relay must not gain root, ptrace capabilities or access to another
user's protected process files. The old Pi guard cannot simply be run inside
that relay: its process measurement crosses this privilege boundary.

This batch adds **identity registration, not request or effect authorization**.
The supervisor supplies its protected activation and retained worker PIDFD over
an authenticated, one-use AF_UNIX/SOCK_SEQPACKET connection. The relay checks the
root peer, fresh challenge, canonical record, configured identity/digest pins,
original expiry and received PIDFD association/liveness. It inspects only its
own fdinfo, not the worker's protected process tree. The root verifies the boot
identity; the relay relies on the authenticated same-kernel channel for that
attestation instead of widening its `ProcSubset=pid` view.

Registration must be acknowledged before bootstrap START. Withdrawal must be
acknowledged before bootstrap RELEASE, while the worker still waits and remains
identifiable. Any failure preserves the native cleanup obligation and cannot
become successful bootstrap/registration evidence. Deadlines are bounded by the
original caller and activation budgets. There are no transport/effect retries.
Transferred descriptors are adopted before ancillary validation and closed on
rejection; caller-owned connections and source handles remain caller-owned.

The API consumes an explicitly supplied, already-connected channel. It does not
create a host listener, install a service or silently use the legacy UID-only
action listener. Later deployment composition must provision that channel under
the reviewed service identities and close it after its one-shot use. Inert checks
do not establish actual Linux descriptor-transfer or service compatibility.
The connection must be established under the final peer identities; a socketpair
created as root and then handed to a privilege-dropped child does not acquire
new `SO_PEERCRED` credentials and is not a substitute for that provisioning.
See the Linux [local-socket credentials and descriptor-transfer contract](https://man7.org/linux/man-pages/man7/unix.7.html).

Reused components include the existing activation validator, canonical protocol
encoding, socket peer credentials, socket-associated PIDFD and liveness helpers,
relay configuration, prepared admission/launch lease and exact native cleanup.
The compiled Linux artifact and static OS closure are unchanged; neither is
rebuilt or executed. Existing Admission/RUN/Workload lane worktrees and unrelated
drafts remain untouched. Two nonoverlapping implementation lanes supplied the
producer/supervisor and consumer; independent review covers the boundary, while
the coordinator owns registry, focused scheduling, documentation and release.

## Security and evidence limits

- No worker request is accepted or dispatched by this identity channel. No
  registration record is a portable bearer capability or an effect permission.
- Provider remains `PROVIDER_UNAVAILABLE`; the legacy action endpoint remains
  masked. No `runtime_action_worker._relay_request` call is added here.
- The existing sensor attributes its connecting relay, not the Pi worker. This
  batch does not relabel that evidence or close Pi attribution requirements.
- Request mediation must next bind bytes read from the actual authenticated Pi
  connection to one-use broker enforcement, current activation and the original
  deadline. A live PID plus relay-supplied request digest is insufficient.
- Root/system-manager integrity remains a trusted deployment assumption. A root
  channel is not independent proof against a compromised root supervisor.
- Original qualification, failure records and operational cleanup holds remain
  unchanged. No Phase 3 or Phase 4 release follows from these component checks.

## Focused verification

**85 checks passed once:** 27 new publisher/transport, 37 new relay (including
paired transcript replay), 17 new native integration/prerelease-hook, and four
directly affected finite-registry capacity checks. There were no failed attempts,
retries or reused results in this batch. Existing retained results were not rerun.
No historical Pi, native supervisor, confinement, admission or RUN suite ran.
No actual socket, PIDFD, worker, service, provider, container, VM or live effect
was created by these fixtures; kernel and transport boundaries were mocked.

The registry capacity increases from 139 to 142. The three new explicit closures
were reviewed against transitive local imports: 16, 17 and 57 inputs respectively.
They import no old test fixtures. Standard-library/interpreter/runner/requirements
and absolute-checkout identities remain covered by the existing pipeline's
fingerprint contract. No other stage ran because its runner digest changed.

| Selected stage | Cases | PASS fingerprint (`sha256:`) |
| --- | ---: | --- |
| `pi-core-identity-handoff-offline` | 27 | `0f6b27ea0a92c4a5310132cbd2db9e138f3661cf92e0fde25faeb0f555584982` |
| `pi-core-identity-relay-offline` | 37 | `c7f956fac14fd13ff8413ba03b2ecfe938259b0b60bbc47da81cc6afca4ae087` |
| `pi-core-identity-supervisor-offline` | 17 | `6701a5faa646656982b0b56aa2a07fc1bc3a5b06c4e6645f825dfa076db1abdb` |
| `pipeline-capacity` | 4 | `1b006d4260e49a81f92729163b5624ffc8a4f1a75396996199e93a1848df2ead` |

Raw results and transcripts are retained under
`.aragorn/phase3-pipeline/<stage>/<fingerprint-without-prefix>/`.
Independent source review found no remaining blocking issue within this narrow
scope. Before execution, review fixed revoke-before-release ordering, reused the
full protected worker measurement in the native guard, required nonoverlapping
relay/worker roles, and ensured malformed ancillary controls cannot skip cleanup
of already adopted handles. The fixture review also corrected missing absent-unit
metadata before any check was run. These are inert implementation results, not
deployed identity, confinement, useful-task, health, timing or qualification proof.

## Remaining plan

1. **D2:** finish exact worker-request handoff and broker-side enforcement, then
   credential-isolated provider/data mediation and controlled channel provisioning.
   Identity registration alone does not finish D2.
2. **D2 pilot, separately authorized:** install the retained pinned roots on a
   compatible controlled Linux host; demonstrate useful allowed/blocked work,
   independently observe outcome/health and verify complete owned cleanup.
3. **D3:** complete managed lifecycle/update/revocation, required RUN/sensor-health
   coverage and real workload/timing adapters on the same deployment.
4. **D4:** implement the approved 29-requirement executable contract, complete
   independent producer/verifier coverage and freeze the deployment once.
5. **D5:** separately authorized fresh acceptance, verified cleanup and offline
   evidence replay. Only then may the applicable Phase 3 result permit Phase 4.

The containing signed commit and post-push local release checkpoint identify this
batch. The original 48-ID manifest and retained historical evidence are preserved.
