"""Finite HTTP mediation reusing the frozen broker's protected state boundary.

This is an internal successor entry point, not a listener. The common service
must still bind authenticated sensor/process attribution and a claimed one-shot
capability before calling it. It does not install or activate that integration.
"""

from __future__ import annotations

import math
import os
import sys
import time

from . import runtime_action_broker as broker
from . import runtime_broker_decision_measurement as measurement
from . import runtime_http_action as http
from .oci_worker_protocol import canonical_digest, canonical_json

ENVELOPE_SCHEMA = "aragorn/runtime-http-broker-request/v1"
SUBMISSION_SCHEMA = "aragorn/runtime-observed-http-submission/v1"
RESULT_SCHEMA = "aragorn/runtime-http-broker-result/v1"
RESULT_AUTHORITY = "BROKER_HTTP_DECISION_ONLY_NOT_SINK_OR_RUN_QUALIFICATION"


def request_effect(value):
    """Reject URL/body overrides and validate the ordinary digest-bound request."""
    envelope = broker._exact(value, broker._ENVELOPE_FIELDS, "HTTP envelope")
    if envelope["schema"] != ENVELOPE_SCHEMA:
        raise broker.RuntimeActionBrokerError("HTTP envelope schema changed")
    try:
        effect = http.validate_effect(envelope["effect"])
        broker._validate_runtime_action_request(envelope["request"])
    except (ValueError, TypeError, KeyError) as error:
        raise broker.RuntimeActionBrokerError("HTTP request refused") from error
    return envelope["request"], effect


def observed_submission(value):
    submission = broker._exact(
        value, broker._OBSERVED_SUBMISSION_FIELDS, "observed HTTP submission"
    )
    if (
        submission["schema"] != SUBMISSION_SCHEMA
        or submission["authority"]
        != "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY"
    ):
        raise broker.RuntimeActionBrokerError("observed HTTP identity changed")
    broker._require_digest(submission["sensor_digest"], "HTTP sensor digest")
    peer = broker._exact(
        submission["runtime_peer"], broker._RUNTIME_PEER_FIELDS, "HTTP peer"
    )
    broker._positive_uint(peer["pid"], "HTTP peer pid")
    broker._uint(peer["uid"], "HTTP peer uid")
    broker._uint(peer["gid"], "HTTP peer gid")
    measured = broker._exact(
        submission["measured_action"], broker._MEASURED_ACTION_FIELDS, "HTTP action"
    )
    if measured["schema"] != "aragorn/measured-runtime-action/v1":
        raise broker.RuntimeActionBrokerError("observed HTTP action schema changed")
    request, _ = request_effect(submission["envelope"])
    if submission["request_digest"] != canonical_digest(request) or submission[
        "envelope_digest"
    ] != canonical_digest(submission["envelope"]):
        raise broker.RuntimeActionBrokerError("observed HTTP digest changed")
    # Detach the complete nested document before retaining it across any I/O.
    return broker._parse_canonical_document(
        canonical_json(submission), "HTTP submission"
    )


def _publish_observation_locked(control_fd, config, request, digests, submission, now):
    """Publish one measured action without making any sensor-health assertion."""
    if config.expected_runtime_uid is None or config.expected_runtime_gid is None:
        raise broker.RuntimeActionBrokerError(
            "observed HTTP identity is not configured"
        )
    peer = submission["runtime_peer"]
    if (
        peer["uid"] != config.expected_runtime_uid
        or peer["gid"] != config.expected_runtime_gid
        or request["runtime_digest"] != config.expected_runtime_digest
    ):
        raise broker.RuntimeActionBrokerError("observed HTTP identity is unbound")
    attribution = {
        field: request[field]
        for field in (
            "runtime_digest",
            "session_id",
            "run_id",
            "tool_call_id",
            "active_skill_digest",
        )
    }
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **attribution,
        **digests,
    }
    if submission["measured_action"] != measured or any(
        request.get(field) != digest for field, digest in digests.items()
    ):
        raise broker.RuntimeActionBrokerError(
            "observed HTTP action measurement changed"
        )
    policy = broker._load_control(control_fd, config.policy_path, config, "HTTP policy")
    sensor_digest = broker._require_digest(
        policy.get("sensor_digest"), "HTTP policy sensor"
    )
    if submission["sensor_digest"] != sensor_digest:
        raise broker.RuntimeActionBrokerError("observed HTTP sensor is unbound")
    current = broker._load_control(
        control_fd, config.observation_path, config, "current HTTP observation"
    )
    current = broker._observation(
        current, broker._uint(current.get("observed_at_unix"), "HTTP observation time")
    )
    observation = {
        "schema": "aragorn/runtime-action-observation/v1",
        "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
        "sequence": current["sequence"] + 1,
        "sensor_digest": sensor_digest,
        "observed_at_unix": now,
        "expires_at_unix": now + broker._MAX_OBSERVATION_LIFETIME_SECONDS,
        "active": {"schema": "aragorn/runtime-active-context/v1", **attribution},
        "measured_action": measured,
    }
    broker._publish_control_locked(
        control_fd,
        config.observation_path,
        observation,
        canonical_json(observation),
        config,
        now,
    )


def _result(
    request,
    effect,
    observation_digest,
    decision,
    reasons,
    transport=None,
    payload_decision=None,
):
    return {
        "schema": RESULT_SCHEMA,
        "authority": RESULT_AUTHORITY,
        "request_digest": canonical_digest(request),
        "effect_digest": canonical_digest(effect),
        "attempt_id": effect["attempt_id"],
        "observation_digest": observation_digest,
        "verdict": "BLOCK" if reasons else "ALLOW",
        "reason_codes": list(reasons),
        "effect_status": "NOT_PERFORMED" if reasons else "SENT",
        "decision": decision,
        "payload_decision": payload_decision,
        "transport": transport,
        "run_conformance_eligible": False,
        "phase3_eligible": False,
        "production_activation_eligible": False,
    }


def mediate_observed_http(submission, config, *, deadline_monotonic=None, clock=None):
    """Consume once; recheck authorization immediately before connect and send.

    Reuses the ordinary broker lock, monotonic floors, health/revocation/policy
    validation and replay ledger. Network failures never erase a consumed entry.
    The enclosing capability/profile layer must retain its pending claim after
    indeterminate transport, evidence retention, or cleanup failures.
    """
    broker._validate_config(config)
    observed = observed_submission(submission)
    request, effect = request_effect(observed["envelope"])
    now_monotonic = time.monotonic()
    deadline = (
        now_monotonic + http.MAX_SECONDS
        if deadline_monotonic is None
        else deadline_monotonic
    )
    if (
        type(deadline) not in {int, float}
        or type(deadline) is float
        and not math.isfinite(deadline)
        or not now_monotonic < deadline <= now_monotonic + http.MAX_SECONDS
    ):
        raise broker.RuntimeActionBrokerError("HTTP broker deadline refused")
    trusted_clock = (lambda: int(time.time())) if clock is None else clock
    control_fd = protected_fd = staging_fd = lock_fd = -1
    locked = False
    effect_possible = False
    transport = None
    try:
        binding = http.load_fixture_binding()
        if (
            binding["expected_broker_uid"] != config.expected_broker_uid
            or binding["expected_broker_gid"] != os.getegid()
        ):
            raise broker.RuntimeActionBrokerError(
                "HTTP broker credential identity changed"
            )
        digests = http.action_digests(effect["attempt_id"], binding)
        control_fd, protected_fd, staging_fd = broker._open_broker_roots(config)
        lock_fd = broker._open_lock_file(control_fd, config)
        broker._acquire_lock(lock_fd, deadline)
        locked = True
        # A prior file-create transaction cannot be skipped by the new action.
        broker._recover_effect_journal(control_fd, protected_fd, staging_fd, config)
        now = broker._clock_value(trusted_clock)
        _publish_observation_locked(control_fd, config, request, digests, observed, now)
        state, observation_digest, decision, reasons = broker._evaluate_snapshot(
            control_fd, config, request, digests, now
        )
        request_digest = canonical_digest(request)
        finalized = False
        measured_decision = measured_observation = measured_reasons = None

        def finalize(snapshot, observed_digest, codes):
            nonlocal \
                finalized, \
                measured_decision, \
                measured_observation, \
                measured_reasons
            if finalized:
                raise broker.RuntimeActionBrokerError("HTTP decision already finalized")
            measurement.final_decision(
                request_digest, observed_digest, snapshot, not codes, codes
            )
            finalized = True
            measured_decision, measured_observation, measured_reasons = (
                snapshot,
                observed_digest,
                list(codes),
            )

        def finish_block(
            codes, snapshot=decision, observed_digest=observation_digest, record=None
        ):
            if not codes:
                raise broker.RuntimeActionBrokerError("HTTP block reason missing")
            if not finalized:
                finalize(snapshot, observed_digest, codes)
            elif (
                canonical_json(snapshot) != canonical_json(measured_decision)
                or observed_digest != measured_observation
                or codes != measured_reasons
            ):
                raise broker.RuntimeActionBrokerError("HTTP finalized block changed")
            return _result(request, effect, observed_digest, snapshot, codes, record)

        if any(
            item["request_digest"] == request_digest
            or item["observation_digest"] == observation_digest
            for item in state["consumed"]
        ):
            return finish_block(["BROKER_REPLAY_BLOCKED"], None)
        if len(state["consumed"]) >= broker._MAX_CONSUMED:
            raise broker.RuntimeActionBrokerError("HTTP broker replay state is full")
        state["consumed"].append(
            {
                "request_digest": request_digest,
                "observation_digest": observation_digest,
                "expires_at_unix": now + broker._MAX_OBSERVATION_LIFETIME_SECONDS,
            }
        )
        state["consumed"] = sorted(state["consumed"], key=canonical_json)
        broker._commit_state(control_fd, config, state)
        if decision["verdict"] != "ALLOW" or reasons:
            return finish_block(reasons or decision["reason_codes"])

        # Transport calls this only after its process/namespace/credential guards.
        # The first callback measures the decision before connect; the second
        # checks that authorization remains valid immediately before payload send.
        previous_now = now
        final_state, final_observation, final_decision = (
            state,
            observation_digest,
            decision,
        )
        final_reasons = []
        authorization_calls = 0

        def authorize_effect():
            nonlocal previous_now, final_state, final_observation, final_decision
            nonlocal final_reasons, authorization_calls
            if authorization_calls >= 2 or final_reasons:
                raise broker.RuntimeActionBrokerError(
                    "HTTP authorization callback repeated"
                )
            authorization_calls += 1
            final_reasons = []
            for _ in range(2):
                effect_now = broker._clock_value(trusted_clock)
                if effect_now < previous_now:
                    final_reasons = ["BROKER_CLOCK_ROLLBACK"]
                    break
                final_state, final_observation, final_decision, final_reasons = (
                    broker._evaluate_snapshot(
                        control_fd,
                        config,
                        request,
                        digests,
                        effect_now,
                        minimum_state=final_state,
                    )
                )
                after = broker._clock_value(trusted_clock)
                if after < effect_now:
                    final_reasons = ["BROKER_CLOCK_ROLLBACK"]
                    break
                previous_now = after
                if after == effect_now:
                    break
            else:
                final_reasons = ["BROKER_CLOCK_UNSTABLE"]
            if final_observation != observation_digest or not any(
                item["request_digest"] == request_digest
                and item["observation_digest"] == observation_digest
                for item in final_state["consumed"]
            ):
                final_reasons = final_reasons or ["BROKER_CLAIM_STATE_CHANGED"]
            if final_decision["verdict"] != "ALLOW":
                final_reasons = final_reasons or final_decision["reason_codes"]
                if not final_reasons:
                    raise broker.RuntimeActionBrokerError("HTTP final verdict invalid")
            if time.monotonic() >= deadline:
                final_reasons = final_reasons or ["BROKER_DEADLINE_EXPIRED"]
            if not finalized:
                finalize(final_decision, final_observation, final_reasons)
            return not final_reasons

        try:
            transport = http.execute_http_effect(
                effect,
                fixture_binding=binding,
                deadline_monotonic=deadline,
                authorize_effect=authorize_effect,
            )
            effect_possible = True
            transport = http.validate_result(
                transport, effect=effect, fixture_binding=binding
            )
            if (
                transport["status"] != "SENT"
                or authorization_calls != 2
                or not finalized
                or final_reasons
            ):
                raise broker.RuntimeActionEffectIndeterminate(
                    "HTTP transport did not complete"
                )
        except http.RuntimeHttpActionIndeterminate as error:
            effect_possible = True
            transport = error.observation
            failure = broker.RuntimeActionEffectIndeterminate(
                "HTTP effect outcome is indeterminate"
            )
            failure.http_action_observation = transport
            raise failure from error
        except http.RuntimeHttpActionError as error:
            transport = (
                error.observation if error.observation is not None else transport
            )
            if effect_possible:
                failure = broker.RuntimeActionEffectIndeterminate(
                    "HTTP transport result refused"
                )
                failure.http_action_observation = transport
                raise failure from error
            if (
                error.reason == "HTTP_AUTHORIZATION_REFUSED"
                and final_reasons
                and finalized
            ):
                transport = http.validate_result(
                    transport, effect=effect, fixture_binding=binding
                )
                if transport["status"] != "NOT_PERFORMED" or authorization_calls != 1:
                    raise broker.RuntimeActionEffectIndeterminate(
                        "HTTP refusal outcome changed"
                    )
                return finish_block(
                    final_reasons, final_decision, final_observation, transport
                )
            raise broker.RuntimeActionBrokerError(
                "HTTP effect refused before connect"
            ) from error
        except BaseException as error:
            # Unknown exceptions after handing off to transport cannot prove no effect.
            effect_possible = True
            transport = getattr(error, "http_action_observation", transport)
            if not isinstance(error, Exception):
                raise
            failure = broker.RuntimeActionEffectIndeterminate(
                "HTTP transport interrupted"
            )
            failure.http_action_observation = transport
            raise failure from error
        return _result(
            request,
            effect,
            measured_observation,
            measured_decision,
            [],
            transport,
            payload_decision=final_decision,
        )
    except broker.RuntimeActionBrokerError:
        raise
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise broker.RuntimeActionBrokerError(
            "HTTP broker mediation refused"
        ) from error
    finally:
        active_error = sys.exc_info()[1]
        try:
            cleanup = broker._release_lock_and_close(
                lock_fd, locked, staging_fd, protected_fd, control_fd
            )
        except BaseException as error:
            cleanup = error
        if cleanup is not None:
            if active_error is not None and not isinstance(active_error, Exception):
                if transport is not None:
                    active_error.http_action_observation = transport
                active_error.http_cleanup_failed = True
                raise active_error from cleanup
            if not isinstance(cleanup, Exception):
                if transport is not None:
                    cleanup.http_action_observation = transport
                raise cleanup
            if effect_possible:
                failure = broker.RuntimeActionEffectIndeterminate(
                    "HTTP broker cleanup failed after transport"
                )
                failure.http_action_observation = transport
                raise failure from cleanup
            raise broker.RuntimeActionBrokerError(
                "HTTP broker cleanup failed"
            ) from cleanup
