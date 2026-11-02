"""Finite HTTP successor branches for authenticated worker and sensor ingress.

The frozen relay remains responsible for peer credentials, PIDFD/profile and
lineage checks, once-only receipts, deadlines and durable ingress retention.
These helpers neither open sockets nor issue capabilities or policy decisions.
"""

from __future__ import annotations

from . import runtime_http_action as http
from . import runtime_http_broker as http_broker
from .oci_worker_protocol import canonical_digest, canonical_json

TOOL_NAME = "aragorn_runtime_http_canary"
PROFILED_SCHEMA = "aragorn/runtime-observed-http-submission/v2"
_ATTRIBUTION = (
    "runtime_digest",
    "session_id",
    "run_id",
    "tool_call_id",
    "active_skill_digest",
)
_RESULT_FIELDS = {
    "schema",
    "authority",
    "request_digest",
    "effect_digest",
    "attempt_id",
    "observation_digest",
    "verdict",
    "reason_codes",
    "effect_status",
    "decision",
    "payload_decision",
    "transport",
    "run_conformance_eligible",
    "phase3_eligible",
    "production_activation_eligible",
}


def is_http_request(value):
    return type(value) is dict and value.get("schema") == http.WORKER_SCHEMA


def is_http_envelope(value):
    return type(value) is dict and value.get("schema") == http_broker.ENVELOPE_SCHEMA


def worker_request(value):
    """Keep the frozen relay's tuple signature, with no caller-supplied bytes."""
    return http.validate_worker_request(value), b""


def tool_name(value):
    if is_http_request(value):
        http.validate_worker_request(value)
        return TOOL_NAME
    return "aragorn_runtime_create"


def action_matches(request, action):
    request = http.validate_worker_request(request)
    expected = http.action_digests(request["attempt_id"], http.load_fixture_binding())
    return all(action[key] == digest for key, digest in expected.items())


def worker_envelope(request, payload, binding, now_unix):
    """Derive all action bytes and destination pins from the protected credential."""
    request = http.validate_worker_request(request)
    if payload != b"" or type(payload) is not bytes:
        raise http.RuntimeHttpActionError("HTTP_WORKER_REQUEST_REFUSED")
    if type(now_unix) is not int or now_unix < 0:
        raise http.RuntimeHttpActionError("HTTP_WORKER_REQUEST_REFUSED")
    fixture = http.load_fixture_binding()
    value = {
        "schema": http_broker.ENVELOPE_SCHEMA,
        "request": {
            "schema": "aragorn/runtime-action-request/v1",
            "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "runtime_digest": binding.runtime_digest,
            "session_id": request["session_id"],
            "run_id": request["run_id"],
            "tool_call_id": request["tool_call_digest"],
            "active_skill_digest": binding.active_skill_digest,
            **http.action_digests(request["attempt_id"], fixture),
            "policy_digest": binding.policy_digest,
            "policy_version": binding.policy_version,
            "issued_at_unix": now_unix,
            "expires_at_unix": now_unix + 5,
        },
        "effect": http.effect_for_attempt(request["attempt_id"]),
    }
    http_broker.request_effect(value)
    return value


def observed_submission(envelope, runtime_peer, config):
    """Measure the finite action independently after authenticating worker UID/GID."""
    from . import runtime_action_observation_publisher as sensor

    sensor._validate_config(config)
    pid, uid, gid = sensor._runtime_peer(runtime_peer)
    if (uid, gid) != (config.expected_runtime_uid, config.expected_runtime_gid):
        raise sensor.RuntimeActionObservationPublisherError("HTTP worker peer refused")
    try:
        request, effect = http_broker.request_effect(envelope)
        fixture = http.load_fixture_binding()
        if (fixture["expected_broker_uid"], fixture["expected_broker_gid"]) != (
            config.expected_broker_uid,
            config.expected_broker_gid,
        ):
            raise ValueError("HTTP broker credential identity changed")
        action = http.action_digests(effect["attempt_id"], fixture)
        if (
            request["runtime_digest"] != config.expected_runtime_digest
            or request["active_skill_digest"] != config.expected_active_skill_digest
            or any(request[key] != value for key, value in action.items())
        ):
            raise ValueError("HTTP observed action changed")
        return http_broker.observed_submission(
            {
                "schema": http_broker.SUBMISSION_SCHEMA,
                "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
                "sensor_digest": config.expected_sensor_digest,
                "envelope_digest": canonical_digest(envelope),
                "request_digest": canonical_digest(request),
                "runtime_peer": {"pid": pid, "uid": uid, "gid": gid},
                "measured_action": {
                    "schema": "aragorn/measured-runtime-action/v1",
                    **{key: request[key] for key in _ATTRIBUTION},
                    **action,
                },
                "envelope": envelope,
            }
        )
    except (ValueError, TypeError, KeyError, RuntimeError) as error:
        raise sensor.RuntimeActionObservationPublisherError(
            "HTTP observation refused"
        ) from error


def broker_result(value, envelope, binding):
    """Verify complete finite results before the authenticated worker relays them."""
    from . import runtime_action_worker as worker

    result = worker._exact(value, _RESULT_FIELDS, "HTTP broker result")
    request, effect = http_broker.request_effect(envelope)
    expected = canonical_digest(request)
    if (
        result["schema"] != http_broker.RESULT_SCHEMA
        or result["authority"] != http_broker.RESULT_AUTHORITY
        or result["request_digest"] != expected
        or result["effect_digest"] != canonical_digest(effect)
        or result["attempt_id"] != effect["attempt_id"]
        or any(
            result[key] is not False
            for key in (
                "run_conformance_eligible",
                "phase3_eligible",
                "production_activation_eligible",
            )
        )
    ):
        raise worker.RuntimeActionWorkerError("HTTP broker result binding changed")
    worker._worker_digest(result["observation_digest"], "HTTP observation digest")
    reasons = worker._reason_codes(result["reason_codes"], "HTTP broker result")
    decisions = {}
    for key in ("decision", "payload_decision"):
        decisions[key] = (
            None
            if result[key] is None
            else worker._decision(
                result[key], expected_request_digest=expected, binding=binding
            )
        )
    transport = result["transport"]
    if transport is not None:
        transport = http.validate_result(
            transport, effect=effect, fixture_binding=http.load_fixture_binding()
        )
    allowed = (
        result["verdict"] == "ALLOW"
        and result["effect_status"] == "SENT"
        and not reasons
        and transport is not None
        and transport["status"] == "SENT"
        and all(
            item is not None and item["verdict"] == "ALLOW" and not item["reason_codes"]
            for item in decisions.values()
        )
    )
    blocked = (
        result["verdict"] == "BLOCK"
        and result["effect_status"] == "NOT_PERFORMED"
        and bool(reasons)
        and decisions["payload_decision"] is None
        and (transport is None or transport["status"] == "NOT_PERFORMED")
    )
    if not allowed and not blocked:
        raise worker.RuntimeActionWorkerError("HTTP broker result outcome changed")
    # The caller cannot mutate nested transport/decision metadata after validation.
    import json

    return json.loads(canonical_json(result))
