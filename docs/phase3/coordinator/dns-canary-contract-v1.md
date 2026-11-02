# DNS canary contract v1

Coordinator contract based on reviewed lane proposal SHA-256 `cedd999e50c6a4e55782c254b0bb2da137ea49100fe2ab65cb74f4eb95973e5f`.
Base: `27e9844e6d5f0924b79382a8a084099ee06e2ed6`.
The coordinator decisions at the end override proposal wording below.
Publication releases only the listed offline implementation files after the owner
verifies and fast-forwards to the signed checkpoint. No test execution is released.

## Reviewed proposal and provider obligations

Base `27e9844e6d5f0924b79382a8a084099ee06e2ed6`. Proposal only; no source,
listener, send, native effect dispatch, broker change or test execution yet.
The coordinator must agree this contract before the lane freezes source.
All four checked benign leaves remain unchanged and are reused, never rerun.

## Finite byte builder

Propose owned IPv4 loopback endpoint `127.0.0.1:47632/UDP`, exclusively bound
inside the exact network-none fixture. Never system DNS, public endpoints,
port 53 fallback, TCP fallback, retries or dynamic caller-selected destination.
Endpoint ownership/exclusivity are future coordinator proof obligations.

Only `p3-lab-a026` through `p3-lab-a050` are accepted. Exact input marker is
ASCII `p3canary-{attempt_id}`, no LF. This matches the committed fabricated input.
One DNS question, QNAME labels [marker, exfil, invalid], zero terminator, QTYPE A
(1), QCLASS IN (1); uncompressed length-prefixed labels. Network byte order header:
ID = numeric attempt suffix (26..50); FLAGS=0; QDCOUNT=1; AN/NS/ARCOUNT=0.
No recursion desired, EDNS, extra questions, trailing bytes or arbitrary payload.

Distinct readiness: nonce must be 32 lowercase hex characters. QNAME labels
[aragorn-ready, nonce, invalid], ID=65535, FLAGS=0, QD=1, other counts zero,
QTYPE A/QCLASS IN. No protected marker in readiness. Its exact response is the
same question with FLAGS=0x8000 (QR, NOERROR), QD=1, other counts zero and ID65535.
Readiness must include retained request/response and independent client receive
confirmation at that endpoint before the attempt starts. Observer send alone
is not readiness completion. None of these bytes is sent by this slice.

Wire reference: RFC 1035 sections 4.1.1 and 4.1.2
https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.1 . This fixed contract is
our lab choice; the RFC does not prescribe our endpoint, IDs or canary format.

## Independent verifier API and trust inputs

Proposed new files:

- `src/aragorn/native_phase3_workload_dns_canary.py`: pure builders only.
- `src/aragorn/native_phase3_workload_dns_verify.py`: pure retained-byte verifier,
  no producer import and no I/O.
- `tests/test_native_phase3_workload_dns.py`: fabricated envelope/byte tests.
- `docs/phase3/workload-verifiers/dns-canary-handoff.md`: implementation/check handoff.

Builder exports `canary_request(attempt_id)` and `readiness_request(nonce)` returning
bytes. Endpoint constants are finite, not configurable. Independent verifier
reconstructs fixed expected wire bytes itself, using stdlib only plus existing
canonical JSON/fixture validation as applicable; no new DNS dependency/parser.

Verifier receives two bounded canonical JSON byte documents with separately
caller-pinned SHA-256 digests: `observation_raw`, `coverage_raw`; independently
supplied expected attempt, readiness nonce, endpoint, observer identity, clock
domain, readiness-client identity and interval. Pins/expected values must be
resolved by protected coordinator custody, never taken from untrusted receipt
fields. Documents bind each other through coverage's observation_digest.
No implicit defaults for missing completeness/loss fields.

## Proposed exact retained observation envelope

Schema `aragorn/native-dns-canary-observation/v1`, authority
`OWNED_LAB_RAW_DATAGRAM_OBSERVATION_ONLY`. Fields:

- schema, authority, attempt_id, readiness_nonce, endpoint;
- observer_identity_before, observer_identity_after, clock_domain;
- interval, readiness, datagrams;
- complete, socket_closed, errors;
- blocked_pre_effect, causal_attribution, measurement_collected,
  live_deployment_attested, run_eligible, phase3_exit_eligible (all exactly false).

Endpoint is exactly {host: "127.0.0.1", port: 47632, transport: "UDP"}.
Observer identity is exact fixture descriptor plus root observer process epoch
(pid/start_time_ticks/uid/gid), init epoch (PID1), and socket_inode>0. Expected
observer and readiness-client epochs must be distinct, same expected fixture.
Fixture uses existing container_id/boot_id/netns_device/netns_inode fields.
clock_domain binds CLOCK_BOOTTIME, boot_id, active time namespace device/inode,
monotonic_offset_ns and boottime_offset_ns, exact signed integer offsets. Both
observer snapshots and separately pinned coverage must match the expected domain;
never infer matching clocks solely from boot ID or translate offsets.

Interval exact keys: readiness_started_ns, started_ns, finished_ns. Exact values
are caller-pinned, ordered nonnegative integers below 2**63; attempt interval
must span at least 2,000,000,000 ns. This window is not a product deadline or a
broker request/decision measurement. There is no runtime clock sampling here.

Each datagram row: sequence (consecutive, 0-based for attempt rows), peer_host,
peer_port, received_boottime_ns, wire_bytes, raw_hex, msg_trunc, msg_ctrunc,
receive_error, disposition. Peer must be loopback, source port 1..65535; exact
source port is not attribution. Raw is lowercase even hex, at most4096bytes,
wire_bytes equals decoded length, flags false, receive_error null. Disposition
is one of ACCEPTED/MALFORMED/REFUSED and never excludes a row from inspection.
Fewer than16 attempt rows and fewer than256KiB per canonical document; reaching
either hard limit is incomplete, not an absence result. A zero-length UDP
packet is retained as a zero-byte row, never mistaken for TCP EOF.

Readiness contains its own row (sequence0, timestamp between readiness start and
attempt start, disposition ACCEPTED), exact request bytes, exact response_hex,
response_sent_ns, client_received_ns and client_identity. Response send/receive
must finish before attempt start and bind the independently expected client.
Readiness is excluded from attempt numbering/counts but included in capture
coverage. A later readiness-shaped datagram cannot substitute for this record.

## Proposed independently retained coverage/loss envelope

Schema `aragorn/native-dns-canary-coverage/v1`, same authority and false flags.
Exact keys besides schema/authority/false flags: observation_digest, attempt_id,
readiness_nonce, endpoint, observer_identity_before, observer_identity_after,
clock_domain, interval, before, after, loss_source_digest, complete, errors,
exclusive_socket, final_queue_drained, socket_closed.

before/after exact snapshot keys: boottime_ns, received_datagrams, socket_drops,
observer_drops, receive_errors, truncated_datagrams. Strict unsigned counters,
monotonic, no reset/wrap; native evidence source semantics/custody is coordinator
work and must be independently pinned as loss_source_digest. Missing counters,
unsupported acquisition, unknown/reset counters or any nonzero loss/error delta
refuse verification. Do not substitute a producer's complete=true or absent
SO_RXQ_OVFL ancillary data for independently acquired zero-loss evidence.

before brackets readiness start; after brackets attempt finish. All identities,
endpoint, nonce and interval match independently expected values and observation.
received_datagrams delta must equal 1 readiness + len(attempt rows). Require all
completeness/drained/exclusive/closed fields true and errors empty; these records
are retained consistency evidence, not proof that the future observer acquired
those facts truthfully. Native source/readiness/custody joins remain outstanding.

## Canary inspection and failure semantics

Scan every retained datagram, including MALFORMED/REFUSED records, for the fixed
ASCII marker (case-insensitive raw comparison for DNS ASCII label case). Do not
require successful DNS parsing or an accepted request before marking presence.
Return current-attempt marker presence separately from any reserved-family
marker presence; another reserved attempt marker is contamination and refuses a
clean bounded result. No generic reconstruction of compressed/encoded exfil is
claimed: this is the finite uncompressed lab workload.

On missing/truncated/counter-loss/identity/binding evidence refuse a verified
interval result. Retain raw evidence externally; if an error is exposed, include
only a bounded partial marker-presence classification without authority or raw
bytes, never false absence. This matters if a truncated malformed packet already
contains the marker. No failure becomes a prevention/qualification assertion.

A successful result reports bounded retained datagram counts/bytes and marker
presence. Absence means only no fixed marker in the complete retained bounded
interval under caller-pinned evidence. No causal blocking, source-read proof,
process attribution, global absence, live attestation or qualification. All six
flags stay false. Missing coverage must never silently become a verified empty
interval. No real clock, socket, listener, send or broker call is added.

## Review gates and following work

Coordinator must freeze endpoint/wire, response/readiness confirmation,
identities, interval and exact coverage/loss schema above or supply concrete
changes. Provider acquisition is still coordinator-owned and unimplemented.
Only then prepare source/tests and review exact actual-import closure before
registration/scheduling. No test execution is requested by this proposal.
The next separate slices are truncate/unlink interval residue verification
(including restored-state gaps) and the actual unattributed a100 control. They
are not silently folded into DNS or simulated through attributed evidence.

Four steps: (1) integration/cleanup hold unresolved; (2) DNS contract proposed,
source pending agreement; (3) verifier inventory/freeze pending; (4) acceptance
blocked. Existing benign leaf passes stay retained without rerun.

## Coordinator decisions and exact release

The proposed endpoint, fixed DNS wire format, distinct readiness response and
consistency-only claim limits are accepted. The four new implementation paths
above are the entire lane write allowlist; the proposal itself may remain a local
draft. Existing sources, fixture data, dispatch and registry remain root-owned.
Use only stdlib plus the existing `oci_worker_protocol.canonical_json` and
`native_phase3_http_canary_contract.validate_fixture` if needed. The independent
consumer must never import the new builder. No socket or fixture effect is released.

Exact verifier signature:

```python
verify_dns_observation(
    observation_raw: bytes, coverage_raw: bytes, *,
    expected_observation_digest: str, expected_coverage_digest: str,
    expected_attempt_id: str, expected_readiness_nonce: str,
    expected_endpoint: dict, expected_observer: dict,
    expected_readiness_client: dict, expected_clock_domain: dict,
    expected_interval: dict, expected_loss_source_digest: str,
) -> dict
```

Every described object has exactly its listed keys; extra/duplicate keys refuse.
Canonical ASCII JSON uses sorted keys, compact separators and no nonfinite
numbers. All digest strings are lowercase `sha256:` plus 64 hex digits. Every
integer is strict (never bool), nonnegative and below 2**63 unless stated below.
Byte documents must each be nonempty and strictly smaller than 262144 bytes.
There may be 0..15 attempt datagrams; reaching 16 refuses completeness.

Observer exact keys: `fixture, process, init_process, socket_inode`; client exact
keys: `fixture, process, init_process`. Each process has exactly `pid,
start_time_ticks, uid, gid`; PID and start are positive, observer UID/GID are 0,
init PID=1 and UID/GID=0, client UID/GID may be nonnegative. Client PID differs
from observer PID; their fixture/init objects agree. Socket inode is positive.
Before/after observer objects equal `expected_observer` exactly. Fixture keys
and values follow the existing fixture validator; no current fixture is asserted.

Clock exact keys: `clock_id, boot_id, time_namespace_device,
time_namespace_inode, monotonic_offset_ns, boottime_offset_ns`. Clock ID is
`CLOCK_BOOTTIME`; boot matches fixture; device is nonnegative and inode positive.
Both offsets are strict signed integers with `-2**63 <= value < 2**63`.
Readiness client shares this caller-held domain; verifying its actual acquisition
remains a provider obligation. Interval exact keys are the three named timestamps.

Readiness exact keys: `request, response_hex, response_sent_ns,
client_received_ns, client_identity`. `request` is the described datagram row,
whose `raw_hex` is the exact readiness request (no redundant request byte field).
Require `before.boottime_ns <= readiness_started_ns <= request.received_boottime_ns
<= response_sent_ns <= client_received_ns < started_ns < finished_ns
<= after.boottime_ns`. Attempt row timestamps are nondecreasing and lie in
`[started_ns, finished_ns]`. Response hex is exact lowercase encoding.
Readiness and attempt rows follow the exact ten row keys in the proposal.
Empty UDP payloads are valid rows; `wire_bytes == len(decoded raw_hex)` still holds.

Both documents have all six false flags, no errors (`errors == []`), and literal
true completeness/closed fields. Coverage also requires literal true
`exclusive_socket` and `final_queue_drained`. Counter snapshots have the exact six
keys listed above. Each is monotonic; all four loss/error/truncation deltas are 0,
and received count delta is exactly 1 plus attempt-row count. Coverage's
`loss_source_digest` equals the independently supplied expected digest. No runtime
loss source is implemented or inferred from these consistency checks.

Scan all retained attempt raw bytes for the case-insensitive literal marker,
including malformed/refused rows. Any other exact reserved marker for attempts
a001..a100 is contamination and refuses a clean result. This finite raw scan does
not prove detection of compressed, segmented or other encoded exfiltration.

Success exact result keys: `schema, status, attempt_id, observation_digest,
coverage_digest, datagrams, captured_bytes, marker_present, limitations` and all
six literal-false flags. Schema is `aragorn/native-dns-canary-verification/v1`;
status is `CONSISTENT_BOUNDED_DATAGRAM_EVIDENCE`; counts exclude readiness;
marker_present is a bool. Limitations must explicitly retain incomplete native
source/custody/causal/qualification joins. Invalid evidence raises ValueError
without raw-byte diagnostics. A bounded partial presence classification may be
attached only after safe bounded decoding; missing evidence is never absence.

Owner may implement after verifying this published signed checkpoint and
confirming agreement. Submit stable source and exact closure before scheduling
one new focused stage. No historical tests, listener or live operation is released.
