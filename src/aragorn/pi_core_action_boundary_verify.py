"""Offline replay of a completed action CURRENT send summary, not authority to send.

The caller supplies ordered CHECK/attempt/summary pins from a separately bound
retained index, the actual protected activation/request and broker offer, and
independent launch/observer expectations. This reader cannot authenticate
arbitrary caller-selected pins, a sender, or the acquisition itself.

For offline export, read each original attempt by its retained digest; encode
only its source_capture member with canonical_json and copy those exact bytes,
under their SHA-256, into the replay CAS. Keep the original attempt unchanged.
Open the CAS read-only for replay. The Node verifier requires the actual
standalone blob and we compare it with the original embedded value; we neither
synthesize missing blobs nor mount a virtual CAS to satisfy its check.
"""
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_node_source_observation_verify import verify_pi_node_source_observation
from .pi_core_request_handoff import _packet, _validate_packet
from .pi_core_source_observation_verify import (
    _clock, _digest, _document, _fields, _pin, _require, _same, _uint, _worker,
)
from .pi_core_worker_identity import validate_activation
from .runtime_action_worker import _worker_request


_SOURCE_ARGS = {"expected_bindings", "expected_worker", "expected_clock", "expected_gate_identity",
                "expected_profile_raw", "source_inventory_raw", "loader_inventory_raw",
                "expected_root_peer", "expected_root_endpoints"}
_MAX_RECORD = 4 << 20


def verify_action_current_boundaries(*, evidence_cas, expected_activation, expected_request, expected_broker_nonce,
                                     expected_deadline_ns, expected_summary_digest, selections, source_expectations):
    """Verify every recorded send from sequence 1; a missing return never proves non-submission."""
    _require(type(evidence_cas) is CAS and evidence_cas.read_only is True, "ACTION_REPLAY_READ_ONLY_CAS")

    def fetch(pin, maximum):
        return _document(evidence_cas.read(_pin(pin), max_bytes=maximum))

    return _current(evidence_cas, expected_activation, expected_request, expected_broker_nonce,
                    expected_deadline_ns, expected_summary_digest, selections, source_expectations, fetch)


def _current(evidence_cas, expected_activation, expected_request, expected_broker_nonce,
             expected_deadline_ns, expected_summary_digest, selections, source_expectations, fetch):
    _require(type(selections) in (tuple, list) and 1 <= len(selections) <= 16, "ACTION_REPLAY_SEQUENCE_COUNT")
    _fields(source_expectations, _SOURCE_ARGS)
    # Validate deployment/source expectations independently of the embedded
    # capture. Activation.profile_digest describes a *process* profile, not
    # the separate Node source profile passed to the acquisition verifier.
    activation = validate_activation(expected_activation)
    request, _ = _worker_request(expected_request)
    worker, clock = _worker(source_expectations["expected_worker"]), _clock(source_expectations["expected_clock"])
    bindings = source_expectations["expected_bindings"]
    _require(type(bindings) is dict and
             all(bindings.get(k) == activation[a] for k, a in (("deployment_digest", "deployment_digest"),
                 ("runtime_digest", "runtime_digest"), ("node_digest", "executable_digest"))) and
             all(worker[k] == activation[a] for k, a in (("pid", "pid"), ("uid", "uid"), ("gid", "gid"),
                 ("start_ticks", "start_time_ticks"), ("cgroup", "cgroup"))) and clock["boot_id"] == activation["boot_id"]
             and request["session_id"] == activation["session_id"] and request["run_id"] == activation["run_id"]
             and _uint(expected_deadline_ns, 1) <= activation["expires_at_monotonic_ns"], "ACTION_REPLAY_ACTIVATION")
    fields = dict(nonce=expected_broker_nonce, activation_digest=canonical_digest(activation),
                  request_digest=canonical_digest(request), deadline_ns=expected_deadline_ns)

    summary = _fields(fetch(expected_summary_digest, 64 << 10), {"schema", "activation_digest", "rows"})
    _require(summary["schema"] == "aragorn/pi-core-action-current-sends/v1" and
             summary["activation_digest"] == fields["activation_digest"] and type(summary["rows"]) is list and
             len(summary["rows"]) == len(selections), "ACTION_REPLAY_COMPLETED_SUMMARY")
    previous_events, used_nonces, previous_return = [], set(), 0
    for sequence, (sel, row) in enumerate(zip(selections, summary["rows"]), 1):
        _fields(sel, {"check_digest", "attempt_digest", "observation_digest", "challenge"})
        _fields(row, {"sequence", "attempt_digest", "before_send_boottime_ns", "send_returned_boottime_ns"})
        _require(_uint(row["sequence"], 1, 16) == sequence and row["attempt_digest"] == _pin(sel["attempt_digest"]),
                 "ACTION_REPLAY_SEND_INTENT")
        before, returned = _uint(row["before_send_boottime_ns"], 1), _uint(row["send_returned_boottime_ns"], 1)
        check = _validate_packet(fetch(sel["check_digest"], 64 << 10), terminal_ack=True)
        _same(check, _packet("CHECK", **fields, sequence=sequence, terminal_ack=True), "ACTION_REPLAY_CHECK")
        attempt = _fields(fetch(sel["attempt_digest"], _MAX_RECORD), {
            "schema", "activation_digest", "check_digest", "sequence", "current", "source_capture", "boundary"})
        _require(attempt["schema"] == "aragorn/pi-core-action-current-attempt/v2" and
                 attempt["activation_digest"] == fields["activation_digest"] and attempt["check_digest"] == sel["check_digest"]
                 and _uint(attempt["sequence"], 1, 16) == sequence, "ACTION_REPLAY_ATTEMPT")
        _same(_validate_packet(attempt["current"], terminal_ack=True), {**check, "kind": "CURRENT"}, "ACTION_REPLAY_CURRENT")
        boundary = _fields(attempt["boundary"], {"clock", "challenge", "boundary_boottime_ns"})
        _same(boundary["clock"], clock, "ACTION_REPLAY_BOUNDARY_CLOCK")
        challenge = _fields(sel["challenge"], {"nonce", "issued_ns", "deadline_ns"})
        _same(boundary["challenge"], challenge, "ACTION_REPLAY_BOUNDARY_CHALLENGE")
        tick = _uint(boundary["boundary_boottime_ns"], 1)
        _require(previous_return <= _uint(challenge["issued_ns"], 1) <= tick <= before <= returned and
                 type(challenge["nonce"]) is str and challenge["nonce"] not in used_nonces,
                 "ACTION_REPLAY_CAUSAL_CLOCK")
        raw = canonical_json(attempt["source_capture"])
        _require(_digest(raw) == _pin(sel["observation_digest"]), "ACTION_REPLAY_EMBEDDED_CAPTURE")
        # Replay once at the later, pre-send freshness boundary. Its real CAS
        # read also binds the separately exported bytes to the original intent.
        verify_pi_node_source_observation(raw, **source_expectations, evidence_cas=evidence_cas,
            expected_observation_digest=sel["observation_digest"], expected_challenge=challenge,
            boundary_boottime_ns=before)
        events = attempt["source_capture"]["events"]
        _require(len(events) > len(previous_events) and events[-1]["boottime_ns"] <= tick, "ACTION_REPLAY_CAPTURE_TIME")
        _same(events[:len(previous_events)], previous_events, "ACTION_REPLAY_CAPTURE_FORK")
        used_nonces.add(challenge["nonce"])
        previous_events, previous_return = events, returned
    return dict(schema="aragorn/pi-core-action-current-replay/v1", status="CONSISTENT_RECORDED_LOCAL_SEND_RETURNS",
                completed_sequences=len(selections), summary_digest=expected_summary_digest,
                acquisition_authenticity_verified=False, broker_receipt_verified=False, effect_verified=False,
                sensor_health_verified=False, phase3_qualified=False)
