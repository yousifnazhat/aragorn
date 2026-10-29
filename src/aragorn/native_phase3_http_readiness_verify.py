"""Independent raw readiness joins; never imports the readiness producer.

Expected process identities must come from the owning controller's independent
kernel/service observation. This consumer does not turn caller pins into live
attestation or claim the whole common deployment was installed or loaded.
"""

import json

from . import native_phase3_http_canary_contract as canary
from .oci_worker_protocol import canonical_digest, canonical_json

_AUTHORITY = "BROKER_PROCESS_BOUNDED_READINESS_ONLY_NOT_EFFECT_OR_QUALIFICATION"
_FALSE = (*canary.FALSE_FLAGS, "broker_restricted_readiness_verified")
_SECURITY = {
    "CapInh": "0000000000000000",
    "CapPrm": "0000000000000000",
    "CapEff": "0000000000000000",
    "CapBnd": "0000000000000000",
    "CapAmb": "0000000000000000",
    "NoNewPrivs": "1",
    "Seccomp": "2",
}


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _raw(raw, digest, limit=16384):
    _require(
        type(raw) is bytes and 0 < len(raw) <= limit and canary.digest(raw) == digest,
        "HTTP_READINESS_RAW_PIN_CHANGED",
    )
    value = json.loads(raw)
    _require(
        type(value) is dict and canonical_json(value) == raw,
        "HTTP_READINESS_RAW_ENCODING_CHANGED",
    )
    return value


def verify_broker_readiness(
    *,
    request_raw,
    claim_raw,
    result_raw,
    sink_raw,
    expected_digests,
    expected_fixture_binding,
    expected_broker_identity,
    expected_sink_identity,
):
    """Verify one exact broker round trip, not root-listener readiness alone."""
    _require(
        type(expected_digests) is dict
        and set(expected_digests) == {"request", "claim", "result", "sink"},
        "HTTP_READINESS_PIN_INVENTORY_CHANGED",
    )
    request = _raw(request_raw, expected_digests["request"])
    claim = _raw(claim_raw, expected_digests["claim"])
    result = _raw(result_raw, expected_digests["result"])
    sink = _raw(sink_raw, expected_digests["sink"], 65536)
    binding = expected_fixture_binding
    _require(
        type(binding) is dict
        and set(binding)
        == {"schema", "fixture", "expected_broker_uid", "expected_broker_gid"}
        and binding["schema"] == "aragorn/runtime-http-fixture-binding/v1",
        "HTTP_READINESS_BINDING_CHANGED",
    )
    canary.validate_fixture(binding["fixture"])
    _require(
        all(
            type(binding[key]) is int and 0 < binding[key] < 2**31
            for key in ("expected_broker_uid", "expected_broker_gid")
        ),
        "HTTP_READINESS_BINDING_CHANGED",
    )
    _require(
        set(request)
        == {"schema", "readiness_nonce", "fixture_binding_digest", "timeout_ms"}
        and request["schema"] == "aragorn/runtime-http-readiness-input/v1"
        and request["fixture_binding_digest"] == canonical_digest(binding)
        and type(request["timeout_ms"]) is int
        and request["timeout_ms"] == 500,
        "HTTP_READINESS_REQUEST_CHANGED",
    )
    wire = canary.readiness_request(request["readiness_nonce"])
    expected = expected_broker_identity
    _require(
        type(expected) is dict
        and set(expected) == {"fixture", "pid", "start_time_ticks", "uid", "gid"}
        and expected["fixture"] == binding["fixture"]
        and canary._integer(expected["pid"], 2)
        and canary._integer(expected["start_time_ticks"], 1)
        and type(expected["uid"]) is int
        and expected["uid"] == binding["expected_broker_uid"]
        and type(expected["gid"]) is int
        and expected["gid"] == binding["expected_broker_gid"],
        "HTTP_READINESS_BROKER_IDENTITY_CHANGED",
    )
    _require(
        set(claim)
        == {
            "schema",
            "authority",
            "request_digest",
            "fixture_binding_digest",
            "identity",
            "claimed_boottime_ns",
        }
        and claim["schema"] == "aragorn/runtime-http-readiness-claim/v1"
        and claim["authority"] == _AUTHORITY
        and claim["request_digest"] == expected_digests["request"]
        and claim["fixture_binding_digest"] == canonical_digest(binding)
        and canonical_json(claim["identity"]) == canonical_json(expected)
        and canary._integer(claim["claimed_boottime_ns"]),
        "HTTP_READINESS_CLAIM_CHANGED",
    )
    _require(
        set(result)
        == {
            "schema",
            "authority",
            "request_digest",
            "claim_digest",
            "fixture_binding_digest",
            "readiness_nonce",
            "identity",
            "security",
            "status",
            "error_code",
            "connect_attempted",
            "local_port",
            "sent_bytes",
            "response_bytes",
            "response_digest",
            "interval",
            *_FALSE,
        }
        and result["schema"] == "aragorn/runtime-http-broker-readiness/v1"
        and result["authority"] == _AUTHORITY
        and result["request_digest"] == expected_digests["request"]
        and result["claim_digest"] == expected_digests["claim"]
        and result["fixture_binding_digest"] == canonical_digest(binding)
        and result["readiness_nonce"] == request["readiness_nonce"]
        and canonical_json(result["identity"]) == canonical_json(expected)
        and result["security"] == _SECURITY
        and result["status"] == "READY"
        and result["error_code"] is None
        and result["connect_attempted"] is True
        and type(result["local_port"]) is int
        and 0 < result["local_port"] < 65536
        and type(result["sent_bytes"]) is int
        and result["sent_bytes"] == len(wire)
        and type(result["response_bytes"]) is int
        and result["response_bytes"] == len(canary.RESPONSE_BYTES)
        and result["response_digest"] == canary.digest(canary.RESPONSE_BYTES)
        and all(result[key] is False for key in _FALSE),
        "HTTP_READINESS_RESULT_CHANGED",
    )
    interval = result["interval"]
    _require(
        type(interval) is dict
        and set(interval) == {"clock_id", "started_ns", "finished_ns", "deadline_ns"}
        and interval["clock_id"] == "CLOCK_BOOTTIME"
        and all(
            canary._integer(interval[key])
            for key in ("started_ns", "finished_ns", "deadline_ns")
        )
        and claim["claimed_boottime_ns"]
        <= interval["started_ns"]
        <= interval["finished_ns"]
        <= interval["deadline_ns"]
        and interval["deadline_ns"] - interval["started_ns"] == 500_000_000,
        "HTTP_READINESS_CLOCK_CHANGED",
    )
    _require(
        set(sink)
        == {
            "schema",
            "authority",
            "identity",
            "attempt_id",
            "readiness_nonce",
            "endpoint",
            "readiness",
            "interval",
            "connections",
            "listener_closed",
            "complete",
            "errors",
            "limitations",
            *canary.FALSE_FLAGS,
        }
        and sink["schema"] == canary.SINK_SCHEMA
        and sink["authority"] == canary.SINK_AUTHORITY
        and sink["readiness_nonce"] == request["readiness_nonce"]
        and sink["endpoint"] == {"host": canary.HOST, "port": canary.PORT}
        and sink["listener_closed"] is True
        and sink["errors"] == []
        and sink["limitations"] == list(canary.LIMITATIONS)
        and all(sink[key] is False for key in canary.FALSE_FLAGS),
        "HTTP_READINESS_SINK_CHANGED",
    )
    canary.canary_bytes(sink["attempt_id"])
    canary._identity(sink["identity"], expected_sink_identity)
    _require(
        sink["identity"]["fixture"] == binding["fixture"],
        "HTTP_READINESS_SINK_FIXTURE_CHANGED",
    )
    observed = sink["interval"]
    _require(
        type(observed) is dict
        and set(observed)
        == {"clock_id", "readiness_started_ns", "started_ns", "finished_ns"}
        and observed["clock_id"] == "CLOCK_BOOTTIME"
        and canary._integer(observed["readiness_started_ns"]),
        "HTTP_READINESS_SINK_CLOCK_CHANGED",
    )
    row = sink["readiness"]
    received = canary._connection(
        row,
        observed["readiness_started_ns"],
        observed["readiness_started_ns"] + 2_000_000_000,
    )
    _require(
        received == wire
        and row["peer_port"] == result["local_port"]
        and row["eof"] is True
        and row["truncated"] is False
        and row["error_code"] is None
        and row["response_bytes"] == len(canary.RESPONSE_BYTES)
        and interval["started_ns"]
        <= row["accepted_boottime_ns"]
        <= interval["finished_ns"],
        "HTTP_READINESS_BROKER_SINK_JOIN_CHANGED",
    )
    if sink["complete"] is True:
        canary.verify_http_sink(
            sink_raw,
            expected_raw_digest=expected_digests["sink"],
            expected_identity=expected_sink_identity,
            expected_attempt_id=sink["attempt_id"],
            expected_readiness_nonce=request["readiness_nonce"],
        )
    else:
        _require(
            sink["complete"] is False
            and sink["connections"] == []
            and observed["started_ns"] is observed["finished_ns"] is None,
            "HTTP_READINESS_PARTIAL_ACTION_SINK_REFUSED",
        )
    return {
        "schema": "aragorn/runtime-http-broker-readiness-verification/v1",
        "broker_process_round_trip_verified": True,
        "request_digest": expected_digests["request"],
        "result_digest": expected_digests["result"],
        "sink_digest": expected_digests["sink"],
        "limitations": [
            "EXPECTED_PROCESS_PINS_REQUIRE_INDEPENDENT_CURRENT_SERVICE_IDENTITY",
            "NO_LOADED_SOURCE_ATTESTATION_OR_WHOLE_DEPLOYMENT_QUALIFICATION",
            "APPLICATION_INGRESS_NOT_KERNEL_PEER_PROCESS_ATTRIBUTION",
        ],
        **dict.fromkeys(_FALSE, False),
    }
