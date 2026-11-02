# DNS observer provider: design findings, not an implementation release

Reviewed source base: `d87572182584f9c106393a2ca952c69703b6da6d`.
Root owns this design. It does not release source paths, registry changes, tests,
native execution, private retention or cleanup. The accepted lane contract remains
`dns-canary-contract-v1.md`, including its final coordinator decisions. That
contract's builder and retained-byte consumer do not provide a live UDP observer.

The smallest proposed provider is one fixed UDP observer, an owning execution
context and a separate acquisition-evidence consumer. Preserve the lane's exact
observation/coverage schemas and independent consumer. Do not turn its bounded
consistency result into an authenticity, prevention or qualification claim.

## Proposed ownership boundary

These are proposed **new Root-only paths**, not released implementation assignments:

- `src/aragorn/native_phase3_dns_observer.py`
- `src/aragorn/native_phase3_dns_context.py`
- `src/aragorn/native_phase3_dns_provider_verify.py`
- `scripts/runtime_native_dns_readiness.py`
- `tests/test_native_phase3_dns_provider.py`
- `docs/phase3/coordinator/dns-provider-contract-v1.md`

They do not overlap the workload lane's builder, consumer, test and handoff paths.
Publish a concrete contract with the missing decisions below before delegation.
The context must have a real owning caller in subsequent common dispatch; source
existence and a callback sketch do not complete integration.

## Existing helpers to reuse

| Existing source | Reusable mechanism | Limit that must remain explicit |
| --- | --- | --- |
| `src/aragorn/native_phase3_http_fixture.py` | `owned_http_fixture(expected_fixture)` holds fixture and PID1/network namespace identities; checks Linux root main thread, exact container cgroups, boot and loopback-only interfaces. | It does not create a fresh fixture, prove installed source, hold a UDP socket, read active time offsets or acquire loss counters. |
| `src/aragorn/runtime_process_profile.py` | Bounded `_read_virtual_file`, process start identity, PIDFD liveness; `open_peer_pidfd` for a genuinely authenticated socket peer. | A caller-supplied PID or pipe payload is not authenticated merely by parsing it. Pipe custody needs an owned child and source/descriptor provenance. |
| `src/aragorn/native_phase3_clock_domain.py` | `_snapshot`, `_live_pidfd`, `_namespace` and retained active namespace checks around BOOTTIME observations. | Current common helper does not read `timens_offsets`; boot-ID equality is insufficient for DNS's full domain. Its read brackets are not application request timestamps. |
| `src/aragorn/native_phase3_http_sink.py` | One-shot bounded observer state, immediate partial-record publication, exact fixture guards and explicit close/error retention. | It is TCP-specific, lacks independent client receive confirmation and UDP loss/queue accounting. Do not reuse its complete flag as DNS completeness. |
| `src/aragorn/native_phase3_http_collection.py` | Exact pinned child/interpreter/source invocation, owned streams, bounded reads, explicit partial outcome and child cleanup patterns. | Its HTTP READY/GO protocol does not meet DNS's separate client receipt/clock contract. Any new child cancellation must preserve actual process identity and submitted ambiguity. |
| `src/aragorn/native_phase3_workload_dns_canary.py` and `native_phase3_workload_dns_verify.py` | Lane-owned fixed wire construction and independent retained-byte verification after their reviewed implementation is integrated. | Provider calls the builder; the independent acquisition consumer may compose the lane verifier but must not reuse the provider's parser or accept its complete flags as proof. |

## Source-confirmed native mechanisms

The references below identify upstream **Linux v6.12 mechanisms**, not the deployed
kernel. This design did not inspect a live host, establish its release/config or
prove that its kernel source matches these references. Root must fix a supported
ABI/source profile and verify applicability before any native use. Unsupported or
missing fields remain unknown; no compatibility fallback invents zero.

- [`net/ipv4/udp.c`](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/udp.c):
  `udp4_format_sock` exports per-socket inode, UID, receive queue and `sk_drops` in
  the proc UDP table. `udp_recvmsg` increments namespace `UDP_MIB_INDATAGRAMS`
  after non-peeking delivery. Thus namespace totals also include the readiness
  client's received response; they are not the observer's received-row count.
- [`net/ipv4/udp_diag.c`](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/udp_diag.c),
  [`include/uapi/linux/sock_diag.h`](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/sock_diag.h)
  and [`include/uapi/linux/inet_diag.h`](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/inet_diag.h):
  socket diagnostics expose receive queue information and define socket memory
  drop accounting. This is an alternative to review, not an automatic fallback or
  a reason to add both proc and netlink implementations. The proc approach is the
  smaller initial candidate because the repository already has bounded proc reads.
- [`kernel/time/namespace.c`](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/time/namespace.c):
  `proc_timens_show_offsets` reads `time_ns_for_children`, while the active time
  namespace has its own accessor. Require active and child namespace identity
  equality before interpreting the process's offsets as its active clock domain.
- [`fs/proc/base.c`](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/proc/base.c):
  the `timens_offsets` proc reader calls that accessor and is conditional on
  `CONFIG_TIME_NS`. Absent support must refuse the full-domain acquisition claim.

## Proposed concrete context API

This is an interface sketch for agreement, not an accepted provider contract:

```python
with open_dns_context(
    *,
    expected_fixture: dict,
    expected_clock_domain: dict,
    expected_observer_process: dict,
    expected_readiness_source_digest: str,
    expected_interpreter_digest: str,
    attempt_id: str,
    readiness_nonce: str,
) as context:
    readiness = context.confirm_readiness()
    interval_start = context.begin_attempt()
    # Root dispatches the real protected action through the common runtime.
    result = context.finish_after_quiescence(quiescence_evidence_raw)
```

The context owns its UDP socket, fixed readiness child and PIDFD, exclusive child
pipes and network/time namespace descriptors. It preserves root/main-thread and
process-start identity for its lifetime. Methods are single-use and refuse
reentry, fork/thread transfer, reuse after close or use after uncertain failure.
There is no arbitrary destination, caller-provided datagram, recovered execution
context, optional retry or callback that can fabricate observation counters.

The proposed `quiescence_evidence_raw` input is **unresolved**. Accepting a caller's
success booleans would not implement quiescence. Root must bind it to the actual
serialized submission state, all relevant producers and independently retained
process/cgroup observations. If that cannot be established, finishing may return
only incomplete partial evidence, never a complete interval.

Native operations required inside the new provider are explicit:

1. `socket.socket(AF_INET, SOCK_DGRAM)` with nonblocking/CLOEXEC custody; bind only
   `127.0.0.1:47632`. Read back `SO_TYPE`, `getsockname`, socket identity and disabled
   `SO_REUSEADDR`/`SO_REUSEPORT`. Refuse endpoint conflicts instead of selecting
   another port. Retain socket inode via the held descriptor and proc fd identity.
2. Bounded reads of `/proc/self/net/udp`, matched to exactly one held socket inode,
   endpoint and UID. Retain the raw table bytes and parsed row separately. Reject
   duplicates, missing rows, unknown format, counter reset/wrap or changed socket
   identity. The proc table is namespace-scoped; netns custody is mandatory.
3. Nonblocking `recvmsg` with a bounded payload/control buffer. Record the syscall
   result, flags, peer, bytes and actual BOOTTIME receipt mark before parsing DNS.
   Every datagram is retained, including zero-byte packets and malformed/refused
   payloads. `MSG_TRUNC`, `MSG_CTRUNC`, receive failure, sixteen attempt rows or a
   document cap prevents complete coverage. EAGAIN is no available packet at that
   read, not proof of global absence. No ancillary omission becomes zero loss.
4. Send only the exact readiness response using the fixed socket. Any partial,
   uncertain or failed send refuses readiness. The independent readiness child
   sends the exact fixed query, receives and checks the exact response, and reports
   its actual receive timestamp through its exclusively owned output pipe.
5. Hold observer and child PID/process epochs and active/child time namespaces.
   Read exact `monotonic`/`boottime` offsets from bounded `timens_offsets`; require
   active namespace equals child namespace before using them. Recheck all bindings
   around the exchange and interval. Never translate unlike domains or assume zero.
6. Close only owned resources on all terminal paths. Cancellation, child timeout,
   unresolved process exit, unknown submission state, final guard or close failure
   preserves partial evidence and prohibits a complete result. Do not retry a
   potentially closed descriptor or erase retained residue.

The root-owned readiness helper must have an exact installed pathname/interpreter
and source pin before release. Actual child PID/start/UID/GID and clock identities
come from protected parent readbacks, not solely from its JSON output. Any use of
AF_UNIX instead of owned pipes needs an explicitly accepted transport and genuine
peer authentication; a pre-fork socketpair's creation credentials must not be
mistaken for the child's later sending identity.

## Mapping to the accepted coverage counters

The accepted coverage schema has six integer fields per before/after snapshot.
The provider needs a supplementary raw acquisition record because those six
integers cannot independently establish their own origins.

| Accepted field | Proposed actual source | Unknown/failure rule |
| --- | --- | --- |
| `boottime_ns` | Actual `clock_gettime_ns(CLOCK_BOOTTIME)` with held and rechecked namespace/offset identity. | Invalid/nonmonotonic sample or domain substitution refuses; never copy a requested timestamp. |
| `received_datagrams` | Counter incremented for every successful observer `recvmsg`, including readiness, zero-byte packets and later-refused packets; retained syscall journal is independently reconstructed. | Never compute from accepted rows or namespace-wide `InDatagrams`. Missing journal entries or inability to retain a consumed packet prevents complete coverage. |
| `socket_drops` | Exact held-socket `sk_drops` value from the source-matched proc UDP row. | Missing/unparseable/unmatched row is unknown. Any reset, overflow ambiguity or positive interval delta refuses. |
| `observer_drops` | Fresh one-shot observer's actual local publication/discard failure accounting. No filter or silent discard path is permitted. | Zero is justified only by the checked successful journal path; an unrecordable exception or partial publication is unknown/refusal, not zero. |
| `receive_errors` | Actual receive-call error accounting, separately retaining error class and call position. | Unhandled/interrupted/ambiguous receive prevents success; normal EAGAIN deadline/drain semantics must be fixed in the provider contract. |
| `truncated_datagrams` | Actual returned truncation flags or oversize capture events in the receive journal. | Any positive interval delta or uncertain ancillary/payload truncation refuses. |

Software counters start at zero only for a newly created one-shot observer before
its first receive; that is a measured process-local lifetime, not a synthetic
kernel-loss assumption. Independently replaying its raw journal establishes
consistency under trusted provider-source custody, not hostile-root resistance.

Coverage's received delta must still equal one readiness request plus the number
of attempt rows. The readiness response received by the **client** is retained
separately and is not counted in the observer's receive sequence. The provider
must not weaken that accepted consumer rule to accommodate a namespace counter.

Missing values may appear as explicit unknowns in a **partial acquisition record**.
They cannot be inserted as null into a successful accepted coverage envelope,
whose exact schema requires bounded integers and complete evidence. A missing
source therefore produces no verified interval and never an absence result.

## Raw acquisition and independent replay

Proposed result contains the accepted `observation_raw` and `coverage_raw` only
when every required acquisition/closure step succeeds, alongside a bounded raw
provider record. On refusal, expose available raw records through a bounded
exception/result without a complete interval. Exact result and error schemas,
bounds and retention ABI remain contract decisions before implementation.

The provider record must retain:

- caller-bound attempt/fixture/source identities and actual socket identities;
- raw before/after proc UDP rows/table snapshots, parsing/source ABI identity and
  queue/drop read brackets;
- full bounded successful/failed receive-call journal and readiness send result;
- exact readiness child output, parent-observed child identity/PIDFD custody and
  source/interpreter bytes or independently held source pins;
- raw process/time namespace/offset observations around all timing boundaries;
- actual quiescence/drain observations, cancellation, guard and close outcomes.

Define coverage's `loss_source_digest` as the digest of the separately retained
raw loss/acquisition source record, not a hash derived from coverage's own integer
claims. Keep that source record free of the coverage digest to avoid a circular
pin. The trusted caller supplies the expected source digest independently when
replaying. Actual retention/readback is required before calling it retained.

`native_phase3_dns_provider_verify.py` independently parses the raw source evidence,
reconstructs counters/identity/clock/readiness joins, and only then composes the
lane's `verify_dns_observation` with caller-held expectations. It must not import
the observer/provider implementation or accept recorded PASS/complete flags in
place of its own checks. Both layers retain the accepted six false authority flags.
This acquisition consumer does not replace the final Phase 3 semantic adapter.

## Quiescence and completeness gap

The accepted consumer checks an **application-receive timestamp interval**. It
does not by itself classify a kernel arrival that has not yet been read. A timeout,
EAGAIN or a queue snapshot followed by socket close leaves possible races between
those observations. Queue emptiness at one instant also does not establish that
all future senders are unable to produce another packet.

Root must define the real common-runtime boundary that stops new submissions,
accounts for any already submitted action and observes relevant producers as
quiescent before final draining. Retain the actual drain result and source-matched
queue/drop snapshots while the socket is still held. Late arrivals, nonempty final
queue, unresolved producer state or uncertain close must prevent complete coverage.
Do not infer NOT_SUBMITTED from missing packet/receipt or resolve a submitted
operation by merely closing the observer.

If the required claim becomes **kernel-arrival completeness**, first publish the
additional acquisition source and independent verification contract. This proposed
application receive loop cannot silently supply that stronger guarantee. Until
the quiescence semantics are fixed, `final_queue_drained=true` is not an acceptable
placeholder for an unimplemented provider.

## Decisions required before release

1. Fix supported native kernel/source/ABI applicability and exact proc table parser
   bounds, including handling of unsupported counter fields and wrap ambiguity.
2. Freeze the readiness child invocation, source/interpreter identities, exclusive
   pipe custody and its exact raw response/clock record schema.
3. Specify actual serialized quiescence/cancellation and final-drain semantics;
   resolve application-receive versus kernel-arrival scope explicitly.
4. Freeze bounded raw acquisition/result/refusal schemas, independent source-pin
   acquisition and retention/readback interfaces, then assign the exact new paths.
5. Review stable source, true imports/generated inputs and focused checks before
   Root registers and schedules a single newly necessary stage. No test is
   scheduled by this design.

No live host, packet, kernel capability, execution result or deployment state was
observed during this design review. No file other than this design note is changed
by its persistence. Root continues lane integration independently of this proposal.
