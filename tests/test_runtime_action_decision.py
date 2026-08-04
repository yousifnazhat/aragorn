from __future__ import annotations

import unittest
from copy import deepcopy

from aragorn.oci_worker_protocol import canonical_digest
from aragorn.runtime_action_decision import (
    RuntimeActionStateError,
    evaluate_runtime_action,
)

_RUNTIME = "sha256:" + "1" * 64
_SKILL = "sha256:" + "2" * 64
_OPERATION = "sha256:" + "3" * 64
_PATH = "sha256:" + "4" * 64
_PAYLOAD = "sha256:" + "5" * 64
_SENSOR = "sha256:" + "6" * 64
_REVOCATION_SOURCE = "sha256:" + "7" * 64


def _fixture() -> dict[str, object]:
    rule = {
        "runtime_digest": _RUNTIME,
        "active_skill_digest": _SKILL,
        "operation_digest": _OPERATION,
        "path_digest": _PATH,
        "payload_digest": _PAYLOAD,
    }
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-file-write-fixture",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": _SENSOR,
        "revocation_source_digest": _REVOCATION_SOURCE,
        "allow": [rule],
    }
    request = {
        "schema": "aragorn/runtime-action-request/v1",
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "runtime_digest": _RUNTIME,
        "session_id": "session-1",
        "run_id": "run-1",
        "tool_call_id": "call-1",
        "active_skill_digest": _SKILL,
        "operation_digest": _OPERATION,
        "path_digest": _PATH,
        "payload_digest": _PAYLOAD,
        "policy_digest": canonical_digest(policy),
        "policy_version": 1,
        "issued_at_unix": 98,
        "expires_at_unix": 103,
    }
    return {
        "request": request,
        "policy": policy,
        "now_unix": 100,
        "active": {
            "schema": "aragorn/runtime-active-context/v1",
            **{
                key: request[key]
                for key in (
                    "runtime_digest",
                    "session_id",
                    "run_id",
                    "tool_call_id",
                    "active_skill_digest",
                )
            },
        },
        "measured_action": {
            "schema": "aragorn/measured-runtime-action/v1",
            **{
                key: request[key]
                for key in (
                    "runtime_digest",
                    "session_id",
                    "run_id",
                    "tool_call_id",
                    "active_skill_digest",
                    "operation_digest",
                    "path_digest",
                    "payload_digest",
                )
            },
        },
        "revocations": {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": _REVOCATION_SOURCE,
            "generation": 3,
            "observed_at_unix": 95,
            "expires_at_unix": 105,
            "skill_digests": [],
        },
        "minimum_revocation_generation": 3,
        "mediator_health": {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": _RUNTIME,
            "sensor_digest": _SENSOR,
            "epoch": 1,
            "status": "healthy",
            "observed_at_unix": 95,
            "expires_at_unix": 105,
        },
        "minimum_mediator_health_epoch": 1,
    }


def _evaluate(values: dict[str, object]) -> dict[str, object]:
    return evaluate_runtime_action(
        values["request"],
        values["policy"],
        now_unix=values["now_unix"],
        active=values["active"],
        measured_action=values["measured_action"],
        revocations=values["revocations"],
        minimum_revocation_generation=values["minimum_revocation_generation"],
        mediator_health=values["mediator_health"],
        minimum_mediator_health_epoch=values["minimum_mediator_health_epoch"],
    )


class RuntimeActionDecisionTests(unittest.TestCase):
    def test_exact_binding_allows_deterministically_without_run_authority(self) -> None:
        values = _fixture()
        first = _evaluate(values)
        second = _evaluate(deepcopy(values))

        self.assertEqual(first, second)
        self.assertEqual(
            first,
            {
                "schema": "aragorn/runtime-action-decision/v1",
                "authority": (
                    "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
                ),
                "request_digest": canonical_digest(values["request"]),
                "active_context_digest": canonical_digest(values["active"]),
                "measured_action_digest": canonical_digest(values["measured_action"]),
                "policy_digest": canonical_digest(values["policy"]),
                "policy_version": 1,
                "evaluated_at_unix": 100,
                "revocation_snapshot_digest": canonical_digest(values["revocations"]),
                "revocation_generation": 3,
                "minimum_revocation_generation": 3,
                "mediator_health_digest": canonical_digest(values["mediator_health"]),
                "mediator_health_epoch": 1,
                "minimum_mediator_health_epoch": 1,
                "verdict": "ALLOW",
                "reason_codes": [],
            },
        )

        later = deepcopy(values)
        later["now_unix"] = 101
        later_decision = _evaluate(later)
        self.assertEqual(later_decision["verdict"], "ALLOW")
        self.assertEqual(later_decision["evaluated_at_unix"], 101)
        self.assertNotEqual(first, later_decision)

    def test_every_missing_or_changed_runtime_binding_blocks(self) -> None:
        cases = []

        invalid = _fixture()
        invalid["request"]["extra"] = True
        cases.append(("invalid", invalid, ["ACTION_REQUEST_INVALID"]))

        unattributed = _fixture()
        unattributed["active"] = None
        cases.append(("unattributed", unattributed, ["ACTION_UNATTRIBUTED"]))

        attribution = _fixture()
        attribution["active"]["session_id"] = "session-2"
        cases.append(("attribution", attribution, ["ACTION_ATTRIBUTION_MISMATCH"]))

        unmeasured = _fixture()
        unmeasured["measured_action"] = None
        cases.append(("unmeasured", unmeasured, ["ACTION_UNMEASURED"]))

        measurement = _fixture()
        measurement["measured_action"]["path_digest"] = "sha256:" + "7" * 64
        cases.append(("measurement", measurement, ["ACTION_MEASUREMENT_MISMATCH"]))

        measurement_lineage = _fixture()
        measurement_lineage["measured_action"]["run_id"] = "run-2"
        cases.append(
            (
                "measurement-lineage",
                measurement_lineage,
                ["ACTION_MEASUREMENT_MISMATCH"],
            )
        )

        stale = _fixture()
        stale["request"]["expires_at_unix"] = 100
        cases.append(("request-stale", stale, ["ACTION_REQUEST_STALE"]))

        policy = _fixture()
        policy["request"]["policy_digest"] = "sha256:" + "8" * 64
        cases.append(("policy", policy, ["POLICY_BINDING_MISMATCH"]))

        revoked = _fixture()
        revoked["revocations"]["skill_digests"] = [_SKILL]
        cases.append(("revoked", revoked, ["ACTIVE_SKILL_REVOKED"]))

        revocation_source = _fixture()
        revocation_source["revocations"]["source_digest"] = "sha256:" + "8" * 64
        cases.append(
            (
                "revocation-source",
                revocation_source,
                ["REVOCATION_SOURCE_BINDING_MISMATCH"],
            )
        )

        revocation_stale = _fixture()
        revocation_stale["revocations"]["expires_at_unix"] = 100
        cases.append(
            ("revocation-stale", revocation_stale, ["REVOCATION_SNAPSHOT_STALE"])
        )

        rollback = _fixture()
        rollback["revocations"]["generation"] = 2
        cases.append(("revocation-rollback", rollback, ["REVOCATION_ROLLBACK"]))

        health_binding = _fixture()
        health_binding["mediator_health"]["runtime_digest"] = "sha256:" + "9" * 64
        cases.append(
            (
                "health-binding",
                health_binding,
                ["MEDIATOR_HEALTH_BINDING_MISMATCH"],
            )
        )

        health_stale = _fixture()
        health_stale["mediator_health"]["expires_at_unix"] = 100
        cases.append(("health-stale", health_stale, ["MEDIATOR_HEALTH_STALE"]))

        sensor = _fixture()
        sensor["mediator_health"]["sensor_digest"] = "sha256:" + "a" * 64
        cases.append(("sensor", sensor, ["MEDIATOR_SENSOR_BINDING_MISMATCH"]))

        unhealthy = _fixture()
        unhealthy["mediator_health"]["status"] = "unhealthy"
        cases.append(("unhealthy", unhealthy, ["MEDIATOR_UNHEALTHY"]))

        health_rollback = _fixture()
        health_rollback["minimum_mediator_health_epoch"] = 2
        cases.append(("health-rollback", health_rollback, ["MEDIATOR_HEALTH_ROLLBACK"]))

        denied = _fixture()
        denied["policy"]["allow"] = []
        denied["request"]["policy_digest"] = canonical_digest(denied["policy"])
        cases.append(("not-allowed", denied, ["ACTION_NOT_ALLOWED"]))

        for label, values, reasons in cases:
            with self.subTest(label):
                decision = _evaluate(values)
                self.assertEqual(decision["verdict"], "BLOCK")
                self.assertEqual(decision["reason_codes"], reasons)

    def test_malformed_trusted_state_fails_closed(self) -> None:
        cases = []

        bad_now = _fixture()
        bad_now["now_unix"] = False
        cases.append(("trusted-time", bad_now))

        bad_policy = _fixture()
        bad_policy["policy"]["default"] = "ALLOW"
        cases.append(("policy-default", bad_policy))

        bad_active = _fixture()
        bad_active["active"]["extra"] = True
        cases.append(("active-context", bad_active))

        bad_measurement = _fixture()
        bad_measurement["measured_action"]["payload_digest"] = "bad"
        cases.append(("measurement", bad_measurement))

        bad_revocations = _fixture()
        bad_revocations["revocations"]["skill_digests"] = [_SKILL, _SKILL]
        cases.append(("revocations", bad_revocations))

        bad_revocation_floor = _fixture()
        bad_revocation_floor["minimum_revocation_generation"] = False
        cases.append(("revocation-floor", bad_revocation_floor))

        bad_health = _fixture()
        bad_health["mediator_health"]["epoch"] = False
        cases.append(("health", bad_health))

        bad_health_floor = _fixture()
        bad_health_floor["minimum_mediator_health_epoch"] = False
        cases.append(("health-floor", bad_health_floor))

        for label, values in cases:
            with self.subTest(label), self.assertRaises(RuntimeActionStateError):
                _evaluate(values)


if __name__ == "__main__":
    unittest.main()
