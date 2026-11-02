"""Independent retained DNS consistency checks; no builder import or native I/O."""

import hashlib
import json
import re

from .native_phase3_http_canary_contract import validate_fixture
from .oci_worker_protocol import canonical_json

FALSE_FLAGS = (
    "blocked_pre_effect", "causal_attribution", "measurement_collected",
    "live_deployment_attested", "run_eligible", "phase3_exit_eligible",
)
_COMMON = {
    "schema", "authority", "attempt_id", "readiness_nonce", "endpoint",
    "observer_identity_before", "observer_identity_after", "clock_domain",
    "interval", "complete", "socket_closed", "errors", *FALSE_FLAGS,
}
_ROW = {
    "sequence", "peer_host", "peer_port", "received_boottime_ns", "wire_bytes",
    "raw_hex", "msg_trunc", "msg_ctrunc", "receive_error", "disposition",
}
_COUNTERS = {
    "boottime_ns", "received_datagrams", "socket_drops", "observer_drops",
    "receive_errors", "truncated_datagrams",
}
LIMITATIONS = (
    "RETAINED_CONSISTENCY_ONLY_NATIVE_SOURCE_AND_CUSTODY_JOINS_INCOMPLETE",
    "NO_CAUSAL_ATTRIBUTION_BLOCKED_EXFILTRATION_OR_QUALIFICATION",
    "BOUNDED_INTERVAL_NOT_GLOBAL_ABSENCE_OR_PRODUCT_DEADLINE",
    "FIXED_LITERAL_SCAN_NOT_COMPRESSED_SEGMENTED_OR_ENCODED_EXFILTRATION",
    "ENDPOINT_READINESS_IDENTITY_AND_LOSS_ACQUISITION_REQUIRE_PROTECTED_PROVIDERS",
)


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _keys(value, keys):
    _require(type(value) is dict and set(value) == keys, "INVALID_DNS_OBJECT_KEYS")


def _uint(value, minimum=0):
    return type(value) is int and minimum <= value < 2**63


def _same(value, expected):
    # JSON equality must distinguish booleans from integers in nested identities.
    _require(canonical_json(value) == canonical_json(expected), "DNS_BINDING_CHANGED")


def _digest(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
             is not None, "INVALID_DNS_DIGEST")


def _document(raw, pin):
    _digest(pin)
    _require(type(raw) is bytes and 0 < len(raw) < 262144, "DNS_DOCUMENT_LIMIT")
    _require("sha256:" + hashlib.sha256(raw).hexdigest() == pin, "DNS_PIN_CHANGED")
    try:
        value = json.loads(raw)
        encoded = canonical_json(value)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("INVALID_DNS_JSON") from None
    # Duplicate keys, whitespace, non-ASCII and alternate numeric forms cannot roundtrip.
    _require(encoded == raw, "NONCANONICAL_DNS_JSON")
    return value


def _identity(value, observer=False):
    _keys(value, {"fixture", "process", "init_process"} | ({"socket_inode"} if observer else set()))
    validate_fixture(value["fixture"])
    for name in ("process", "init_process"):
        process = value[name]
        _keys(process, {"pid", "start_time_ticks", "uid", "gid"})
        _require(_uint(process["pid"], 1) and _uint(process["start_time_ticks"], 1)
                 and _uint(process["uid"]) and _uint(process["gid"]), "INVALID_DNS_PROCESS")
        if observer or name == "init_process":
            _require(process["uid"] == process["gid"] == 0, "INVALID_DNS_PROCESS_OWNER")
    _require(value["init_process"]["pid"] == 1, "INVALID_DNS_INIT")
    if observer:
        _require(_uint(value["socket_inode"], 1), "INVALID_DNS_SOCKET_IDENTITY")


def _raw(value):
    _require(type(value) is str and len(value) <= 8192
             and re.fullmatch(r"(?:[0-9a-f]{2})*", value) is not None, "INVALID_DNS_RAW")
    return bytes.fromhex(value)


def _row(value, sequence, start, end):
    _keys(value, _ROW)
    data = _raw(value["raw_hex"])
    _require(_uint(value["sequence"]) and value["sequence"] == sequence
             and value["peer_host"] == "127.0.0.1"
             and _uint(value["peer_port"], 1) and value["peer_port"] <= 65535
             and _uint(value["received_boottime_ns"])
             and start <= value["received_boottime_ns"] <= end
             and _uint(value["wire_bytes"]) and value["wire_bytes"] == len(data),
             "INVALID_DNS_DATAGRAM_BINDING")
    _require(value["msg_trunc"] is False and value["msg_ctrunc"] is False
             and value["receive_error"] is None, "INCOMPLETE_DNS_DATAGRAM")
    _require(value["disposition"] in ("ACCEPTED", "MALFORMED", "REFUSED"),
             "INVALID_DNS_DISPOSITION")
    return data


def verify_dns_observation(
    observation_raw: bytes, coverage_raw: bytes, *,
    expected_observation_digest: str, expected_coverage_digest: str,
    expected_attempt_id: str, expected_readiness_nonce: str,
    expected_endpoint: dict, expected_observer: dict,
    expected_readiness_client: dict, expected_clock_domain: dict,
    expected_interval: dict, expected_loss_source_digest: str,
) -> dict:
    """Validate externally pinned records, never infer truthful native acquisition."""
    _require(type(expected_attempt_id) is str and re.fullmatch(
        r"p3-lab-a(?:02[6-9]|0[34][0-9]|050)", expected_attempt_id
    ) is not None, "INVALID_DNS_ATTEMPT")
    _require(type(expected_readiness_nonce) is str and re.fullmatch(
        r"[0-9a-f]{32}", expected_readiness_nonce
    ) is not None, "INVALID_DNS_READINESS_NONCE")
    # Reconstruct both fixed questions independently, without the producer.
    marker = ("p3canary-" + expected_attempt_id).encode("ascii")
    question = (
        int(expected_attempt_id[-3:]).to_bytes(2, "big")
        + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x14"
        + marker + b"\x05exfil\x07invalid\x00\x00\x01\x00\x01"
    )
    probe = (b"\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0daragorn-ready\x20"
             + expected_readiness_nonce.encode("ascii") + b"\x07invalid\x00\x00\x01\x00\x01")
    response = probe[:2] + b"\x80\x00" + probe[4:]
    _same(expected_endpoint, {"host": "127.0.0.1", "port": 47632, "transport": "UDP"})
    _identity(expected_observer, observer=True)
    _identity(expected_readiness_client)
    _same(expected_observer["fixture"], expected_readiness_client["fixture"])
    _same(expected_observer["init_process"], expected_readiness_client["init_process"])
    _require(expected_observer["process"]["pid"] != expected_readiness_client["process"]["pid"],
             "DNS_CLIENT_OBSERVER_NOT_DISTINCT")
    _keys(expected_clock_domain, {"clock_id", "boot_id", "time_namespace_device",
                                 "time_namespace_inode", "monotonic_offset_ns", "boottime_offset_ns"})
    _require(expected_clock_domain["clock_id"] == "CLOCK_BOOTTIME"
             and expected_clock_domain["boot_id"] == expected_observer["fixture"]["boot_id"]
             and _uint(expected_clock_domain["time_namespace_device"])
             and _uint(expected_clock_domain["time_namespace_inode"], 1)
             and all(type(expected_clock_domain[k]) is int
                     and -2**63 <= expected_clock_domain[k] < 2**63
                     for k in ("monotonic_offset_ns", "boottime_offset_ns")), "INVALID_DNS_CLOCK")
    _keys(expected_interval, {"readiness_started_ns", "started_ns", "finished_ns"})
    _require(all(_uint(v) for v in expected_interval.values()), "INVALID_DNS_INTERVAL")
    ready, start, end = (expected_interval[k] for k in
                         ("readiness_started_ns", "started_ns", "finished_ns"))
    _require(ready <= start < end and end - start >= 2_000_000_000, "DNS_INTERVAL_TOO_SHORT")
    _digest(expected_loss_source_digest)
    observation = _document(observation_raw, expected_observation_digest)
    coverage = _document(coverage_raw, expected_coverage_digest)
    _keys(observation, _COMMON | {"readiness", "datagrams"})
    _keys(coverage, _COMMON | {"observation_digest", "before", "after", "loss_source_digest",
                               "exclusive_socket", "final_queue_drained"})
    for value, kind in ((observation, "observation"), (coverage, "coverage")):
        _require(value["schema"] == f"aragorn/native-dns-canary-{kind}/v1"
                 and value["authority"] == "OWNED_LAB_RAW_DATAGRAM_OBSERVATION_ONLY"
                 and all(value[k] is False for k in FALSE_FLAGS), "INVALID_DNS_AUTHORITY")
        for key, expected in (
            ("attempt_id", expected_attempt_id), ("readiness_nonce", expected_readiness_nonce),
            ("endpoint", expected_endpoint), ("observer_identity_before", expected_observer),
            ("observer_identity_after", expected_observer), ("clock_domain", expected_clock_domain),
            ("interval", expected_interval),
        ):
            _same(value[key], expected)
        _require(value["complete"] is True and value["socket_closed"] is True
                 and value["errors"] == [], "INCOMPLETE_DNS_EVIDENCE")
    _require(coverage["observation_digest"] == expected_observation_digest
             and coverage["loss_source_digest"] == expected_loss_source_digest
             and coverage["exclusive_socket"] is True
             and coverage["final_queue_drained"] is True, "DNS_COVERAGE_BINDING_CHANGED")
    before, after = coverage["before"], coverage["after"]
    for snapshot in (before, after):
        _keys(snapshot, _COUNTERS)
        _require(all(_uint(v) for v in snapshot.values()), "INVALID_DNS_COUNTER")
    _require(all(after[k] >= before[k] for k in _COUNTERS), "DNS_COUNTER_RESET")
    _require(all(after[k] == before[k] for k in _COUNTERS - {"boottime_ns", "received_datagrams"}),
             "DNS_LOSS_OR_RECEIVE_ERROR")
    _require(before["boottime_ns"] <= ready and end <= after["boottime_ns"], "DNS_COVERAGE_INTERVAL")
    readiness = observation["readiness"]
    _keys(readiness, {"request", "response_hex", "response_sent_ns", "client_received_ns", "client_identity"})
    _same(readiness["client_identity"], expected_readiness_client)
    _require(_row(readiness["request"], 0, ready, start) == probe
             and readiness["request"]["disposition"] == "ACCEPTED"
             and readiness["response_hex"] == response.hex()
             and _uint(readiness["response_sent_ns"]) and _uint(readiness["client_received_ns"])
             and readiness["request"]["received_boottime_ns"] <= readiness["response_sent_ns"]
             <= readiness["client_received_ns"] < start, "DNS_NOT_READY")
    rows = observation["datagrams"]
    _require(type(rows) is list and len(rows) < 16, "DNS_DATAGRAM_LIMIT")
    _require(after["received_datagrams"] - before["received_datagrams"] == 1 + len(rows),
             "DNS_COVERAGE_COUNT")
    total, present, previous = 0, False, start
    for sequence, row in enumerate(rows):
        data = _row(row, sequence, previous, end)
        previous = row["received_boottime_ns"]
        lowered = data.lower()
        present = present or lowered == question or marker in lowered
        _require(not any((f"p3canary-p3-lab-a{i:03}".encode("ascii") in lowered)
                         for i in range(1, 101) if i != int(expected_attempt_id[-3:])),
                 "DNS_OTHER_ATTEMPT_CONTAMINATION")
        total += len(data)
    return {
        "schema": "aragorn/native-dns-canary-verification/v1",
        "status": "CONSISTENT_BOUNDED_DATAGRAM_EVIDENCE",
        "attempt_id": expected_attempt_id,
        "observation_digest": expected_observation_digest,
        "coverage_digest": expected_coverage_digest,
        "datagrams": len(rows), "captured_bytes": total, "marker_present": present,
        "limitations": list(LIMITATIONS), **dict.fromkeys(FALSE_FLAGS, False),
    }
