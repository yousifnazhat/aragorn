# DNS provider v1: bounded acquisition contract for coordinator review

Status: **reviewed contract; source assignment remains pending the signed DNS
builder dependency and exact owner/base release**. Root accepts its bounded
decisions in the containing signed `provider-release-v4.md` checkpoint.
This document does not authorize a new worktree, native execution, a test run,
private retention or cleanup. An operator may later create an additional worktree
against the exact signed checkpoint supplied by Root. Existing lane worktrees and
their accepted contracts remain unchanged.

Review reference: published Root checkpoint
`f080cf830d41d85421dd897a0783fe2899301645`. That checkpoint does **not** yet
contain the workload lane's DNS builder. The earliest usable implementation base
must be a subsequent signed Root checkpoint that both integrates the original
verified signed DNS delivery and publishes this reviewed contract. Root supplies
that exact hash before an owner starts; this document supplies no substitute hash.

## Ready slice and exact ownership

Implement one owning Linux UDP acquisition call and its independent raw-record
consumer. It opens the actual fixed endpoint, reads socket-loss/process/clock
evidence, records bounded received datagrams and can answer the first exact
readiness query. It **always** reports an incomplete interval and unconfirmed
client readiness. It does not emit either complete envelope accepted by
`dns-canary-contract-v1.md` and does not call its verifier as a substitute for
missing acquisition.

Only these five new paths may be assigned to the additional owner:

1. `src/aragorn/native_phase3_dns_acquisition.py` — bounded recvmsg journal and
   first exact readiness-response operation, called only by the owning context.
2. `src/aragorn/native_phase3_dns_context.py` — public owning caller; actual socket,
   fixture, cancellation, proc/clock snapshots and resource lifetime.
3. `src/aragorn/native_phase3_dns_acquisition_verify.py` — independent raw consumer.
4. `tests/test_native_phase3_dns_acquisition.py` — new focused mocked cases only.
5. `docs/phase3/dns-provider/ACQUISITION_HANDOFF.md` — exact source closure/results.

This contract and all registry, staging, dispatch, installed source inventories,
broker, workload and existing helper files remain Root-owned. The additional
owner must not edit the workload lane's DNS builder/verifier/tests. Do not add a
second DNS packet builder or a new general framework. No CLI/export, readiness
child, privileged installer, packet tap, BPF program or new dependency belongs to
this slice. The owning context is production code that calls the acquisition
module; common-runtime invocation and installation remain explicitly pending.
Its session holds the socket and journal together through both snapshots and
close; the acquisition module neither binds a second socket nor starts a second
receive loop. A future Root-owned context can reuse these same guarded snapshot,
receive-once, exact-response and journal operations while adding real client and
broker synchronization. That extension needs its own schema/contract: it cannot
relabel this v1 sample, its fixed two-second budget or its flags as a complete
attempt interval. No arbitrary provider callback supplies evidence or changes the
claim ceiling.

## Why completeness is excluded

`runtime_http_broker.mediate_observed_http` serializes one HTTP operation, retains
consume-once state and preserves ambiguity after transport handoff. It does not
provide a DNS operation or a barrier that quiesces all potential UDP producers.
`native_phase3_http_collection` coordinates an HTTP child and retains uncertain
outcomes when cleanup fails. Stopping that child does not establish DNS producer
quiescence. `scripts/runtime_native_common_attempt.py` has fixed existing workload
and source inventories; no reviewed DNS dispatcher/quiescence operation is wired.

Consequently this slice implements **application receive sampling** only. An
EAGAIN result or receive-queue snapshot describes that observation, not a complete
kernel-arrival interval. It cannot establish that a late/in-flight datagram was
absent. Closing the observer does not resolve an already submitted action.

## Public producer and consumer APIs

```python
# native_phase3_dns_context.py
capture_dns_acquisition(
    request_raw: bytes, *, expected_request_digest: str, cancel_fd: int,
) -> bytes

# native_phase3_dns_acquisition_verify.py
verify_dns_acquisition(
    acquisition_raw: bytes, *, expected_acquisition_digest: str,
    expected_request_digest: str, expected_request_raw: bytes,
) -> dict
```

The caller supplies the expected request pin from its protected plan. Neither
API derives an expected pin from the submitted evidence and calls that trust.
The consumer imports no producer, owning context or their private parsers. It may
reuse `oci_worker_protocol.canonical_json` and the existing fixture validator.
It independently reconstructs readiness bytes, proc/scalar joins and counters.
The producer imports the workload lane's public `readiness_request(nonce)` to
obtain the exact query and forms the sole fixed response by replacing the header
flags with `0x8000`; it does not implement or export another query builder. The
independent consumer reconstructs the finite bytes itself and imports neither
that builder nor the new provider/context. The existing builder is an actual
source/import dependency of the producer and belongs in the reviewed closure.

`cancel_fd` transfers exclusive ownership of one preconfigured anonymous pipe
read end to the owning call. The caller retains its write end. After the integer
descriptor is accepted, the owner closes it exactly once on every terminal path,
including invalid request, interruption and early refusal. No duplicate close or
retry follows an ambiguous close. The call accepts no path or borrowed socket.
Invalid descriptor syntax must cause refusal without closing some other resource.
The ownership transfer requires a strict nonnegative integer (never bool) and
captures its initial fstat identity before further work. If a later check shows
that its number has been replaced with another object, do not close that foreign
object: record the identity failure and CANCEL_CLOSE_FAILED, preserving the lost
ownership as unresolved. The same rule applies to a substituted socket handle.

Valid request bytes are canonical ASCII JSON, 1..16383 bytes, exact keys:

```text
schema, abi_profile, attempt_id, readiness_nonce, fixture,
observer_process, clock_domain, cancellation_identity
```

- `schema = "aragorn/native-dns-acquisition-request/v1"`.
- `abi_profile = "linux-le-proc-udp-v6.12-layout-v1"`, the offline layout profile
  below; it is not a statement that the deployed kernel is Linux v6.12.
- Attempt a026..a050 and 32-lowercase-hex readiness nonce follow the accepted DNS
  contract. Endpoint is a source constant, never a request field.
- `fixture` is exactly the existing fixture validator's four fields.
- `observer_process` has exactly `pid,start_time_ticks,uid,gid`; positive PID/start,
  UID/GID exactly zero. It must match the actual calling process and raw proc reads.
- `clock_domain` is exactly the accepted DNS six-field CLOCK_BOOTTIME domain:
  `clock_id,boot_id,time_namespace_device,time_namespace_inode,
  monotonic_offset_ns,boottime_offset_ns`.
- `cancellation_identity` has exactly `device,inode,mode,uid,gid`, matching fstat
  of the transferred pipe. Require root UID/GID, positive inode and a FIFO mode.

Except signed offsets, integers are strict nonnegative integers below 2**63,
never booleans. Signed offsets obey `-2**63 <= n < 2**63`. Digests are lowercase
`sha256:` plus 64 hex digits. Duplicate/extra JSON keys, floats, nonfinite values,
alternate encodings and noncanonical bytes refuse. All raw byte fields below use
lowercase even hex. No error message or stdout logging may contain raw bytes.

## Supported offline ABI and source mechanisms

The fixture/syscall mocks and independent parsers target 64-bit Linux, little endian,
IPv4 UDP, the proc UDP layout in upstream v6.12 and CLOCK_BOOTTIME. The production
entrypoint requires `sys.platform == "linux"`, eight-byte pointers, little endian,
root real/effective/
saved accounts with four proc UID/GID values zero, and the original main thread.
Missing PIDFD, namespace, CLOCK_BOOTTIME, socket-option or proc support refuses;
there is no reduced fallback. Record `os.uname().release` as an observation only.

Root must subsequently bind the actual supported deployed kernel/source/config
before installation/native scheduling. Matching this text format does not attest
kernel provenance or complete loss semantics. The ABI profile deliberately has no
`kernel_verified=true` field.

Reviewed mechanism references:

- [Linux v6.12 UDP](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/udp.c):
  `udp4_format_sock` emits inode/UID/receive queue and `sk_drops`; `udp_recvmsg`
  increments namespace `UDP_MIB_INDATAGRAMS` for non-peeking delivery. Therefore
  namespace datagram totals also include the readiness client's response.
- [Linux v6.12 time namespaces](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/time/namespace.c):
  `proc_timens_show_offsets` reads `time_ns_for_children`, not necessarily the
  process's active time namespace.
- [Linux v6.12 proc readers](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/proc/base.c):
  the offsets proc file requires `CONFIG_TIME_NS` and invokes that reader.
- [Linux v6.12 socket diagnostic ABI](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/sock_diag.h)
  and [UDP diagnostics](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/udp_diag.c)
  document another mechanism, but this slice does not implement netlink fallback.

Proc UDP parser: ASCII LF-terminated data, maximum 16384 bytes, no NUL; first line
split on ASCII whitespace must be exactly:

```text
sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops
```

Permit at most 64 data rows, each exactly 13 whitespace-separated fields: slot,
local endpoint, remote endpoint, state, combined tx:rx queue, combined timer:when,
retransmit, UID, timeout, inode, refcount, pointer, drops. Parse all rows enough to
reject duplicate inode matches and conflicting IPv4 wildcard/exact bindings to
the protected port. Match one row to the held socket inode, UID zero and
`0100007F:BA10` (the little-endian proc spelling of 127.0.0.1:47632), remote
`00000000:0000`, state `07`. Endpoint fields use uppercase hex widths 8:4,
queue and timer fields widths 8:8 and 2:8, state width 2 and retransmit width 8.
The pointer field is exactly 16 lowercase hex characters in this 64-bit profile;
it is retained as raw table data and never used as identity. Slot is unsigned
decimal followed by a colon; other decimal fields have no sign or leading zero
except the value zero itself. Refcount is positive; timer, retransmit and timeout
are zero in this profile. `drops` is a uint32 observation, not a uint63
lifetime-loss guarantee. Retain raw before/after values; a decrease is RESET and
has no delta. A possible undetectable full wrap remains a stated limit.

Do not read namespace `Udp InDatagrams` as the observer's packet count. Do not use
absence of SO_RXQ_OVFL ancillary data as zero drops. A missing/malformed/mismatched
proc row means unavailable/unknown, never zero. A successful snapshot preserves
the actual nonzero baseline if present.

## Owning context and native operations

Reuse `owned_http_fixture` for held fixture/PID1/network custody, and bounded
proc/process/PIDFD helpers from `runtime_process_profile` and
`native_phase3_clock_domain` where their semantics match. Do not change them or
turn their local assertions into hostile-root-resistant provenance.
For the reviewed helper version, snapshot its held network descriptors through
`session._fds[0]` and `session._fds[1]` read-only inside `owned_http_fixture`;
the helper alone owns their close. This private-layout dependency must be pinned
in the closure, not treated as a generic stable API. Preserve the helper's fixed
`HTTP_FIXTURE_FINAL_GUARD_FAILED` and `HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED`
exception notes as FINAL_GUARD_FAILED and FIXTURE_CLOSE_FAILED respectively;
do not lose those failures behind the original exception or export raw messages.

The owner validates request/cancellation custody, holds the fixture and both
active and child time namespace descriptors, creates the socket, takes a before
snapshot, performs one sample, takes an after snapshot, checks final custody and
closes owned resources before returning bytes. It rechecks original PID/start,
main thread, accounts and descriptor identities around all external reads and
operations. Root's later integration owns complete loaded-source custody.

Socket: create nonblocking CLOEXEC `AF_INET/SOCK_DGRAM/IPPROTO_UDP`; bind exactly
`127.0.0.1:47632` once. Require `SO_REUSEADDR=0`, `SO_REUSEPORT=0`,
`SO_TYPE=SOCK_DGRAM` (not IPPROTO_UDP),
unconnected remote state, getsockname equality and held socket inode stability.
No setsockopt enabling reuse, alternate bind, connect, system DNS or TCP fallback.
FD identity and `/proc/self/fd/<fd>` socket-inode readback must agree. The context
never sends a canary or launches the protected action.

Cancellation pipe: require O_RDONLY, O_NONBLOCK, FD_CLOEXEC and exact caller-held
fstat identity plus a `pipe:[inode]` proc descriptor link. Do not reconfigure it.
Poll cancellation alongside UDP, giving cancellation priority when both are ready.
On POLLIN or POLLHUP, guard identity then call `os.read(cancel_fd, 1)` exactly
once: one byte or EOF cancels; discard the byte without interpreting or retaining
it. A spurious EAGAIN/EWOULDBLOCK resumes polling; any other read error refuses
with `CANCEL_READ_FAILED`. POLLNVAL, POLLERR or pipe identity change refuses with
`CANCEL_IDENTITY_CHANGED`. Cancellation is also checked before bind, before each
receive/send and before the final snapshot. There is no application-level retry
after a cancellation event, and no datagram read/send follows an observed event.
Holding the writer open is the caller's responsibility. The later owning caller
creates the pipe before invoking this call, transfers only its read end, retains
the writer until completion and signals once or closes it to cancel; no unowned
descriptor or named FIFO may be substituted. Closing the observer is resource
release only and never cancels or resolves a producer's already submitted action.
Poll waits are at most 50ms and use the remaining BOOTTIME budget. This is a loop
responsiveness bound, not a hard return deadline for kernel/proc reads or cleanup.

Sampling: `started_ns` is sampled only after the complete before snapshot and
socket/fixture guards; `deadline_ns = started_ns + 2_000_000_000`. Stop when the
actual clock reaches/exceeds that deadline, on cancellation/failure, on 64 recvmsg
calls or after 16 received datagrams. Limits produce REFUSED, never a complete
empty interval. Successful calls count zero-length datagrams. Every recvmsg uses
4096 payload bytes, 256 control bytes and MSG_DONTWAIT, never MSG_PEEK/MSG_TRUNC as
an invocation flag. Store bounded syscall facts before interpretation; no packet
filter or malformed/refused disposition removes bytes from the journal.

EAGAIN/EWOULDBLOCK is a journaled no-data return and may resume the same sample's
bounded poll loop. EINTR or any other receive error terminates the sample, retaining
the ambiguous call. Any returned truncation flag, unknown returned flag,
oversized/unsupported ancillary
layout or non-loopback peer retains available bytes and refuses. Data from an
unavailable call stays null rather than an invented empty datagram.

Readiness: identify only the exact independently specified nonce query from the
accepted contract. On its **first** complete occurrence, send the exact fixed
response once to that row's loopback peer using nonblocking sendto. Record call
start/end and actual returned byte count. Short, EAGAIN, interrupted or ambiguous
send refuses; never repeat it. A second exact query is retained and refuses as
READINESS_REPLAY. Other packets are retained without reply. This slice never
observes the client's receipt and never emits `client_readiness_confirmed=true`.

Clock: hold `/proc/self/ns/time` and `/proc/self/ns/time_for_children` and require
their fstat/named identities equal the expected active time namespace. Retain
bounded `/proc/self/timens_offsets` bytes at both snapshots. Exactly two lines,
`monotonic` and `boottime`, each signed decimal seconds and unsigned nanoseconds
0..999999999; recompute signed nanosecond offsets and match expected values. Hold
and recheck both handles before/after reads; a difference, missing source or
changed offset refuses. Do not translate clocks or assume zero offsets. Actual
BOOTTIME readings must be monotonic across recorded calls and snapshots.

## Exact acquisition and partial schema

Successful return is canonical JSON bytes, 1..524287 bytes. Ordinary refusal
raises `DnsAcquisitionError(ValueError)` with fixed message `DNS_ACQUISITION_REFUSED`
and exact attributes `reason_code: str`, `partial_raw: bytes | None`,
`cleanup_codes: tuple[str, ...]`. Partial bytes use the **same schema** below.
KeyboardInterrupt/SystemExit preserve their original class and gain
`dns_acquisition_partial_raw` and `dns_acquisition_cleanup_codes`; never replace
the interruption with a cleanup error. Failure before a valid bounded request
exists uses `partial_raw=None`. Cleanup attempts still run for owned resources.

Top-level exact keys:

```text
schema, status, request_raw_hex, request_digest, kernel_release,
before, after, sample, receives, readiness_response, counters,
cancellation, socket_closed, errors, cleanup_codes, limitations,
interval_complete, client_readiness_confirmed, quiescence_verified,
final_queue_drained, retention_verified, submission_state, effect_disposition,
blocked_pre_effect, causal_attribution, measurement_collected,
live_deployment_attested, run_eligible, phase3_exit_eligible
```

- `schema = "aragorn/native-dns-acquisition/v1"`.
- Status is `SAMPLED_NOT_COMPLETE`, `REFUSED` or `CANCELLED`. Only the first can
  return normally; it requires deadline reached, two complete valid snapshots,
  no errors/cleanup failures and successful owned descriptor cleanup.
- Request bytes/pin are exact validated input, never re-encoded altered input.
  `kernel_release` is null before observation or ASCII printable text 1..128 bytes.
- All eleven booleans named from `interval_complete` onward (excluding the two
  state strings) are literal false. The separate `socket_closed` field reports
  actual close success and is not one of those eleven. In particular,
  `final_queue_drained` stays false even if a proc
  snapshot reports a zero queue.
- `submission_state = "UNKNOWN"`; `effect_disposition = "INDETERMINATE"` always.
  Sampling a sink cannot classify the broker's effect state.
- `errors` and `cleanup_codes` are ordered unique lists, at most 16 fixed codes
  each, no exception strings. Allowed errors: `INPUT_REFUSED`, `ABI_UNAVAILABLE`,
  `FIXTURE_CHANGED`, `PROCESS_CHANGED`, `CLOCK_CHANGED`, `CANCEL_IDENTITY_CHANGED`,
  `CANCEL_READ_FAILED`,
  `SOCKET_CHANGED`, `BIND_REFUSED`, `PROC_UDP_UNAVAILABLE`, `PROC_UDP_INVALID`,
  `SOCKET_DROP_UNKNOWN`, `SOCKET_DROP_RESET`, `SOCKET_DROP_INCREASED`,
  `POLL_FAILED`, `RECEIVE_FAILED`, `RECEIVE_FLAGS_REFUSED`, `DATAGRAM_TRUNCATED`,
  `ANCILLARY_REFUSED`,
  `PEER_REFUSED`, `READINESS_SEND_FAILED`, `READINESS_REPLAY`, `READ_LIMIT`,
  `DATAGRAM_LIMIT`, `CANCELLED`, `EVIDENCE_LIMIT`, `INTERRUPTED`, `FINAL_GUARD_FAILED`.
  Cleanup codes: `SOCKET_CLOSE_FAILED`, `CANCEL_CLOSE_FAILED`,
  `NAMESPACE_CLOSE_FAILED`, `FIXTURE_CLOSE_FAILED`.

`sample` exact keys `started_ns,deadline_ns,finished_ns,terminal`; times are null
until actually sampled. Terminal is `NOT_STARTED`, `DEADLINE`, `CANCELLED` or
`REFUSED`. A normal sample has `finished_ns >= deadline_ns`, while late-returning
reads remain observable; this does not assert a product deadline.

`cancellation` has exact keys:

```text
identity_before, identity_after, fd_link, status_flags, descriptor_flags,
event, observed_ns, read_count, read_errno, would_block_reads, closed
```

Identities are null until acquired, otherwise the actual exact
`{device,inode,mode,uid,gid}` fstat objects. Retain actual F_GETFL/F_GETFD integers
and `pipe:[inode]` ASCII link (at most 64 bytes), not requested values copied in
their place; unavailable observations are null. The last identity is sampled
immediately before close and must still match the transferred pipe for close.
`event` is `NOT_OBSERVED`, `BYTE`, `EOF`, `READ_ERROR` or `IDENTITY_CHANGE`;
`observed_ns` is the event's actual BOOTTIME mark or null if none/unavailable.
On BYTE/EOF the observed read_count is 1/0 and errno null; READ_ERROR preserves
its positive errno, or null for an interrupted/unknown call; other unavailable
read fields are null. `would_block_reads` counts actual spurious EAGAIN returns,
starting at zero; no cancelled byte is retained. `closed` is a literal bool that
becomes true only after successful owned pipe close. This record describes local
custody and a stop signal; it makes no statement about producer quiescence.
BYTE/EOF sets status CANCELLED with error CANCELLED; read/identity failure sets
REFUSED with its stated code. A cancellation result can also retain cleanup
failures, and no terminal cancellation is replaced with a normal sample.

Each `before`/`after` is null until started, otherwise an exact snapshot with:

```text
read_started_ns, read_finished_ns, observer, clock_domain,
socket, proc_udp_raw_hex, proc_udp_row, raw_process, namespace_handles
```

Unavailable fields in a partial snapshot are null; fields must never be omitted.
`observer` has exact accepted DNS `fixture,process,init_process,socket_inode` shape.
The process/init identities must independently agree with raw process data and
the caller-held fixture/process expectation. `clock_domain` has the accepted
six-field shape and is reconstructed from held namespace facts and raw offsets.

`socket` exact keys `device,inode,mode,uid,gid,fd_link,host,port,type,
reuse_address,reuse_port,nonblocking,cloexec`. Match fstat/named identity; host/port
are fixed, type is SOCK_DGRAM, reuse values are integer zero, final two booleans
true. Raw `fd_link` is ASCII `socket:[inode]`, bounded to 64 bytes.

`raw_process` exact keys and individual decoded limits:

| Key | Actual source | Bytes maximum |
| --- | --- | --- |
| `stat_hex` | `/proc/self/stat` | 4096 |
| `status_hex` | `/proc/self/status` | 16384 |
| `cgroup_hex` | `/proc/self/cgroup` | 1024 |
| `init_stat_hex` | `/proc/1/stat` | 4096 |
| `init_status_hex` | `/proc/1/status` | 16384 |
| `init_cgroup_hex` | `/proc/1/cgroup` | 1024 |
| `boot_hex` | `/proc/sys/kernel/random/boot_id` | 64 |
| `timens_offsets_hex` | `/proc/self/timens_offsets` | 512 |

Each field is null if unavailable, otherwise actual hex bytes retained before
parsing. The verifier handles the comm field's parentheses when locating proc
stat start ticks; simplistic whitespace splitting of the whole stat is invalid.
UID/GID vectors must each contain four zeros. Cgroup/init/boot joins must match
the existing owned fixture contract.

`namespace_handles` exact keys `network,init_network,time,time_for_children`.
Each value is null or exact `{held_device,held_inode,named_device,named_inode}`;
held/named values agree, network pair matches the fixture, time pair matches the
expected active domain. These are retained local syscall assertions, not external
attestation. The actual provider must hold the descriptors through both snapshots.

`proc_udp_raw_hex` has maximum 16384 decoded bytes. `proc_udp_row` is null or exact
`{socket_inode,uid,local_host,local_port,remote_host,remote_port,state,
tx_queue,rx_queue,drops}` reconstructed independently from raw bytes. Decimal state
is 7; local endpoint is fixed; remote endpoint is 0.0.0.0:0. Before/after socket
inode must match. No drop delta is substituted for either raw value.

Each receive journal row has exactly:

```text
sequence, call_started_ns, call_finished_ns, call_flags, outcome,
errno, peer_host, peer_port, raw_hex, returned_bytes, receive_flags, ancillary
```

There are at most 64 rows, consecutive zero-based sequence. Outcome is `RECEIVED`,
`WOULD_BLOCK` or `ERROR`; errno is null on success or actual positive errno below
2**31 for returned syscall errors. Pending/interrupted/unknown results use ERROR
and null errno. Start/end are null only when that actual clock sample failed;
such a row cannot occur in normal SAMPLED_NOT_COMPLETE output. Success has actual
bytes (0..4096), byte count, returned flags and IPv4 peer. WOULD_BLOCK/ERROR never
pretend a zero-byte success: unavailable peer/payload/count/flags/ancillary are
null. `call_flags` is the actual recorded MSG_DONTWAIT integer before the call.
`receive_flags` is a strict uint32. Only the Linux profile bits MSG_TRUNC=32 and
MSG_CTRUNC=8 are recognized. Either causes DATAGRAM_TRUNCATED; any other set bit
causes RECEIVE_FLAGS_REFUSED while preserving the actual flags/bytes. A normal
sample therefore has zero returned flags on every received row. Invocation
MSG_DONTWAIT is the profile constant 64; require native constant agreement before
opening the socket rather than silently interpreting another ABI.

Ancillary success is a list of at most 8 exact `{level,type,raw_hex}` entries with
total decoded control payload <=256 bytes. Retain any actual unexpected controls
within bounds and refuse; do not interpret integers in UDP ancillary data as FDs
to close. Positive returned MSG_TRUNC or MSG_CTRUNC refuses after retaining the
bounded prefix. The journal's count is copied bytes, not an invented original
wire length when truncation occurred.

`readiness_response` is null until the one send is attempted, otherwise exact
`{receive_sequence,call_started_ns,call_finished_ns,peer_host,peer_port,
response_hex,returned_bytes,errno}`. Fields without an observed value are null.
It joins the first complete exact readiness query; response bytes are the accepted
fixed QR/NOERROR question. Retained successful send count equals response length.
This object deliberately has no client receive timestamp or client identity.

`counters` exact keys `received_datagrams,observer_drops,receive_errors,
truncated_datagrams,would_block_calls,socket_drop_delta,socket_drop_state`.
Each count is null if trustworthy accounting was lost; otherwise a strict uint.
The first five are derived from actual journal/publication behavior, never from
which packets pass DNS parsing. For an intact journal: received_datagrams counts
RECEIVED rows including zero bytes; receive_errors counts ERROR rows (including
unknown/interrupted calls); truncated_datagrams counts RECEIVED rows with either
recognized truncation bit, once per row; would_block_calls counts WOULD_BLOCK
rows; observer_drops is zero only when each attempted call/result was preserved.
EAGAIN/EWOULDBLOCK does not increment receive_errors. These counters initialize
when the valid request's journal is allocated, before the first receive. A
possibly consumed but unrecorded result makes affected counts null; it never
becomes a zero-byte row. No unjournaled discarded packet is permitted. A
journal/publication failure sets observer_drops unknown and refuses.
The independent consumer recomputes every available journal-derived count.

Socket state is `UNKNOWN`, `RESET`, `UNCHANGED` or `INCREASED`. Delta is null for
unavailable/decreasing values; otherwise after minus before. UNCHANGED is an
observed equality, not proof of no full wrap or complete ingress. Increased drops
are retained and cause REFUSED with SOCKET_DROP_INCREASED; reset uses
SOCKET_DROP_RESET, and unavailable/malformed/unmatched before or after evidence
uses SOCKET_DROP_UNKNOWN (alongside the applicable proc error). A stable nonzero
baseline is preserved. No DNS accepted-coverage document is constructed from this.

The exact ordered limitations are:

```text
APPLICATION_RECVMSG_SAMPLE_NOT_KERNEL_ARRIVAL_COMPLETENESS
NO_CLIENT_READINESS_RECEIPT_OR_ACTION_START_AUTHORITY
NO_SERIALIZED_DNS_QUIESCENCE_OR_FINAL_DRAIN_PROOF
RAW_PROC_AND_NAMESPACE_JOINS_NOT_DEPLOYED_KERNEL_OR_SOURCE_ATTESTATION
UINT32_DROP_EQUALITY_CANNOT_EXCLUDE_UNOBSERVED_FULL_WRAP
RETURNED_BYTES_NOT_DURABLE_RETENTION_OR_RETENTION_READBACK
SUBMISSION_UNKNOWN_EFFECT_INDETERMINATE
NO_PREVENTION_RUN_METRICS_OR_PHASE3_QUALIFICATION
```

If the document cap would be exceeded, refuse before another receive and preserve
the already bounded document with EVIDENCE_LIMIT. Never truncate it into a normal
sample. Allocate for maximum row/snapshot sizes before entering the loop; resource
exhaustion still provides no guarantee of a recoverable partial document and must
propagate without success. No automatic file/CAS write, stdout export or deletion.

The verifier's exact result keys are `schema,status,acquisition_digest,
request_digest,record_status,received_datagrams,readiness_response_recorded,
socket_drop_state,limitations` plus all eleven false booleans and the two fixed
state strings from acquisition. Schema is
`aragorn/native-dns-acquisition-verification/v1`; status is
`CONSISTENT_BOUNDED_ACQUISITION_RECORD`. `record_status` repeats the independently
checked acquisition state; the receive count may be null for a partial failure.
`readiness_response_recorded` is a bool describing only a fully joined successful
response send. It is not client readiness. Invalid/unbound/malformed evidence
raises ValueError with fixed diagnostics and produces no verification result.

## Exact remaining caller contract before complete DNS integration

Root must publish a successor only after real code supports all of these joins:

1. Source/interpreter/kernel/profile identity and protected launch install this
   provider; a trusted collector retains actual raw output and readbacks, fixes its
   expected digest, and supplies independent replay expectations.
2. A distinct pinned readiness client actually receives the exact response and
   supplies retained client-receive bytes/timestamp, process/PIDFD/source custody
   and the same validated active time domain. Its receipt precedes actual attempt
   start. This v1 sample's send record cannot fill that field.
3. Common dispatch records the actual protected DNS request, authenticated
   process/cgroup/capability and REQUEST_ACCEPTED → DECISION_FINALIZED interval.
   Observation start/end is not decision latency or proof that an attempt ran.
4. Under the real broker serialization boundary, stop new relevant submissions,
   retain existing submitted/unknown operations and establish which actual
   processes can still emit into the sink. Observe their quiescence with protected
   identities; cancellation alone does not prove absence or rollback.
5. Define a final queue/drain and close boundary that supports the required
   application receive interval, and explicitly decide whether kernel-arrival
   completeness requires an additional observer. The proof must handle delayed
   arrivals/queueing rather than merely reading EAGAIN and setting complete=true.
6. A separate independent acquisition adapter reconstructs the exact accepted
   observation/coverage from those raw sources and caller-held expectations. Only
   then call `verify_dns_observation`; missing coverage/loss/client/quiescence stays
   refusal. Preserve all accepted false authority flags and final gate separation.

This contract intentionally defines no `finish_after_quiescence` function that
accepts an ungrounded boolean/receipt. The unresolved stronger operation is not
delegated as if it were already specified.

## Focused checks and scheduling boundary

Propose one new stage `native-dns-acquisition` with `needs: []`, timeout 120s,
selecting only `test_native_phase3_dns_acquisition`. The owner first submits stable
hashes and exact actual import/generated/fixture closure; Root authors and signs
the registry row and schedules the stage in the owning worktree. No test runs
before that. Use `/opt/homebrew/bin/python3.12`; no imported historical TestCase,
direct unittest/compile bypass, socket exchange, proc read, fixture or live native
operation in these tests. Mock syscall boundaries and use fabricated inline bytes.

Required focused cases:

- Actual owning-context call order, one fixed bind and exact option/descriptor
  checks; repeated context use and fixture/process/thread/fork substitution refuse.
- Proc table exact parser, multiple/unmatched/conflicting rows, row/drop/queue
  joins, short/oversized/unavailable data, uint32 reset and nonzero preserved base.
- Real receive-journal shape for zero-byte, malformed/refused/canary/readiness and
  unknown calls; unsupported ancillary and truncation retain bounded prefixes.
- First exact readiness response once; short/interrupted/would-block send and
  repeated readiness refuse; no path emits a client receipt or true completeness.
- Offset parsing and active-versus-child namespace mismatch, source disappearance,
  domain changes and nonmonotonic sample/call times.
- Cancellation byte/EOF/read failure, simultaneous UDP readiness priority,
  descriptor cleanup, original interruption preservation and cleanup failure.
- Fixed sample deadline, recv call/datagram/document limits and available partial
  record preservation; no effect-send retry or complete empty result on refusal.
- Independent raw consumer cannot import/call provider parsers; recompute wire,
  counters, request/raw pins, process/clock/source joins and exact claim ceiling;
  reject forged counters, canonical/duplicate/type errors and literal PASS flags.

Capacity benefit: this owner can implement and validate isolated socket/proc/clock
acquisition and independent replay while Root handles lane integration and real
broker/reader/dispatch providers. It does not remove the quiescence/readiness-client
or same-deployment source-custody blockers and does not justify an additional
worktree until the operator chooses to create one after signed release.

Checkpoint sequence: (1) Root reviews/signs this source contract; (2) an explicitly
assigned owner implements only the five new paths and returns stable closure;
(3) Root reviews/registers/schedules one new offline stage and integrates the
original verified signed handoff; (4) Root wires the remaining concrete caller
contract before any complete DNS interval or final Phase 3 claim. Existing live,
private-retention and cleanup holds remain unchanged.
