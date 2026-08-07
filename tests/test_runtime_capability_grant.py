from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_capability_grant import (
    GRANT_AUTHORITY,
    GRANT_SCHEMA,
    ISSUANCE_AUTHORITY,
    ISSUANCE_SCHEMA,
    LEASE_AUTHORITY,
    LEASE_SCHEMA,
    RuntimeCapabilityGrantError,
    issue_profiled_runtime_capability,
    parse_runtime_capability_grant,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _grant(**changes: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": GRANT_SCHEMA,
        "authority": GRANT_AUTHORITY,
        "grant_id": "1" * 64,
        "source_manifest_digest": _digest("1"),
        "install_context_digest": _digest("2"),
        "runtime_profile_digest": _digest("3"),
        "runtime_digest": _digest("4"),
        "active_skill_digest": _digest("5"),
        "sensor_digest": _digest("6"),
        "policy_digest": _digest("a"),
        "policy_version": 3,
        "operation_digest": _digest("7"),
        "issued_at_unix": 90,
        "expires_at_unix": 110,
        "max_actions": 1,
    }
    document.update(changes)
    return document


def _submission(
    *,
    issued_at_unix: int = 100,
    expires_at_unix: int = 105,
) -> dict[str, object]:
    request = {
        "schema": "aragorn/runtime-action-request/v1",
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "runtime_digest": _digest("4"),
        "session_id": "session-1",
        "run_id": "run-1",
        "tool_call_id": "call-1",
        "active_skill_digest": _digest("5"),
        "operation_digest": _digest("7"),
        "path_digest": _digest("8"),
        "payload_digest": _digest("9"),
        "policy_digest": _digest("a"),
        "policy_version": 3,
        "issued_at_unix": issued_at_unix,
        "expires_at_unix": expires_at_unix,
    }
    envelope = {
        "schema": "aragorn/runtime-action-broker-request/v1",
        "request": request,
        "effect": {
            "schema": "aragorn/runtime-create-file/v1",
            "operation": "create",
            "target_name": "result.txt",
            "payload_base64": "cGF5bG9hZA==",
        },
    }
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{
            field: request[field]
            for field in (
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
    }
    return {
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": _digest("6"),
        "envelope_digest": canonical_digest(envelope),
        "request_digest": canonical_digest(request),
        "runtime_peer": {"pid": 11, "uid": 12, "gid": 13},
        "measured_action": measured,
        "envelope": envelope,
        "runtime_attribution": {
            "schema": "aragorn/runtime-process-profile-attribution/v1",
            "authority": (
                "KERNEL_PROCESS_PROFILE_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
            ),
            "profile_digest": _digest("3"),
            "runtime_digest": _digest("4"),
            "executable_digest": _digest("b"),
            "active_skill_digest": _digest("5"),
            "skill_path": "/profile/skills/demo/SKILL.md",
            "cgroup": "/aragorn.slice/openclaw.service",
            "pid": 11,
            "uid": 12,
            "gid": 13,
            "start_time_ticks": 14,
            "mount_namespace": {"device": 15, "inode": 16},
        },
    }


def _rebind_submission(submission: dict[str, object]) -> None:
    envelope = submission["envelope"]
    assert isinstance(envelope, dict)
    request = envelope["request"]
    assert isinstance(request, dict)
    submission["request_digest"] = canonical_digest(request)
    submission["envelope_digest"] = canonical_digest(envelope)


class RuntimeCapabilityGrantTests(unittest.TestCase):
    def test_parse_and_issue_exact_profiled_capability(self) -> None:
        grant = _grant()
        grant_raw = canonical_json(grant)
        submission = _submission()

        self.assertEqual(parse_runtime_capability_grant(grant_raw), grant)
        self.assertEqual(parse_runtime_capability_grant(grant_raw, 102), grant)
        with patch(
            "aragorn.runtime_capability_grant.secrets.token_hex",
            return_value="c" * 64,
        ):
            issued = issue_profiled_runtime_capability(submission, grant_raw, 102)

        self.assertEqual(
            set(issued),
            {"schema", "authority", "grant_digest", "lease", "profiled_submission"},
        )
        self.assertEqual(issued["schema"], ISSUANCE_SCHEMA)
        self.assertEqual(issued["authority"], ISSUANCE_AUTHORITY)
        self.assertEqual(issued["grant_digest"], canonical_digest(grant))
        self.assertEqual(issued["profiled_submission"], submission)
        self.assertIsNot(issued["profiled_submission"], submission)

        lease = issued["lease"]
        self.assertEqual(
            set(lease),
            {
                "schema",
                "authority",
                "grant_digest",
                "lease_nonce",
                "submission_digest",
                "runtime_attribution_digest",
                "request_digest",
                "runtime_profile_digest",
                "runtime_digest",
                "active_skill_digest",
                "sensor_digest",
                "policy_digest",
                "policy_version",
                "operation_digest",
                "path_digest",
                "payload_digest",
                "issued_at_unix",
                "expires_at_unix",
                "max_actions",
            },
        )
        self.assertEqual(lease["schema"], LEASE_SCHEMA)
        self.assertEqual(lease["authority"], LEASE_AUTHORITY)
        self.assertEqual(lease["lease_nonce"], "c" * 64)
        self.assertEqual(lease["submission_digest"], canonical_digest(submission))
        self.assertEqual(
            lease["runtime_attribution_digest"],
            canonical_digest(submission["runtime_attribution"]),
        )
        self.assertEqual(lease["request_digest"], submission["request_digest"])
        self.assertEqual(lease["issued_at_unix"], 102)
        self.assertEqual(lease["expires_at_unix"], 105)
        self.assertIs(type(lease["max_actions"]), int)
        self.assertEqual(lease["max_actions"], 1)
        self.assertEqual(json.loads(canonical_json(issued)), issued)

        submission["sensor_digest"] = _digest("d")
        self.assertNotEqual(issued["profiled_submission"], submission)

    def test_grant_parser_rejects_noncanonical_shape_types_and_lifetime(self) -> None:
        grant = _grant()
        invalid = {
            "extra field": {**grant, "extra": True},
            "wrong schema": {**grant, "schema": "aragorn/runtime-capability-grant/v2"},
            "uppercase grant id": {**grant, "grant_id": "A" * 64},
            "bad digest": {**grant, "sensor_digest": "sha256:" + "G" * 64},
            "boolean policy version": {**grant, "policy_version": True},
            "boolean max actions": {**grant, "max_actions": True},
            "multiple actions": {**grant, "max_actions": 2},
            "empty lifetime": {**grant, "expires_at_unix": 90},
            "long lifetime": {**grant, "expires_at_unix": 391},
        }
        for label, document in invalid.items():
            with (
                self.subTest(label=label),
                self.assertRaises(RuntimeCapabilityGrantError),
            ):
                parse_runtime_capability_grant(canonical_json(document))

        with self.assertRaises(RuntimeCapabilityGrantError):
            parse_runtime_capability_grant(b'{"schema": "not-canonical"}')
        with self.assertRaises(RuntimeCapabilityGrantError):
            parse_runtime_capability_grant("not bytes")  # type: ignore[arg-type]
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "stale"):
            parse_runtime_capability_grant(canonical_json(grant), 89)
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "stale"):
            parse_runtime_capability_grant(canonical_json(grant), 110)

    def test_issuance_rejects_grant_measurement_and_attribution_mismatch(self) -> None:
        grant = _grant()
        submission = _submission()
        grant_mutations = {
            "profile": ("runtime_profile_digest", _digest("d")),
            "runtime": ("runtime_digest", _digest("d")),
            "skill": ("active_skill_digest", _digest("d")),
            "sensor": ("sensor_digest", _digest("d")),
            "policy": ("policy_digest", _digest("d")),
            "policy version": ("policy_version", 4),
            "operation": ("operation_digest", _digest("d")),
        }
        for label, (field, value) in grant_mutations.items():
            with self.subTest(label=label):
                changed = {**grant, field: value}
                with self.assertRaisesRegex(RuntimeCapabilityGrantError, "unbound"):
                    issue_profiled_runtime_capability(
                        submission,
                        canonical_json(changed),
                        102,
                    )

        changed_submission = copy.deepcopy(submission)
        changed_submission["measured_action"]["path_digest"] = _digest("d")
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "measurement"):
            issue_profiled_runtime_capability(
                changed_submission,
                canonical_json(grant),
                102,
            )

        changed_submission = copy.deepcopy(submission)
        changed_submission["runtime_attribution"]["pid"] = 99
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "attribution"):
            issue_profiled_runtime_capability(
                changed_submission,
                canonical_json(grant),
                102,
            )

        changed_submission = copy.deepcopy(submission)
        changed_submission["request_digest"] = _digest("d")
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "digest changed"):
            issue_profiled_runtime_capability(
                changed_submission,
                canonical_json(grant),
                102,
            )

    def test_dynamic_time_is_trusted_and_bounded_by_request_and_grant(self) -> None:
        grant_raw = canonical_json(_grant(expires_at_unix=104))
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "time"):
            issue_profiled_runtime_capability(_submission(), grant_raw, 102)

        before_grant = _submission(issued_at_unix=89)
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "time"):
            issue_profiled_runtime_capability(
                before_grant,
                canonical_json(_grant()),
                102,
            )

        future = _submission(issued_at_unix=103)
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "time"):
            issue_profiled_runtime_capability(
                future,
                canonical_json(_grant()),
                102,
            )

        expired = _submission(expires_at_unix=102)
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "time"):
            issue_profiled_runtime_capability(
                expired,
                canonical_json(_grant()),
                102,
            )

        with self.assertRaises(RuntimeCapabilityGrantError):
            issue_profiled_runtime_capability(
                _submission(),
                canonical_json(_grant()),
                True,  # type: ignore[arg-type]
            )

    def test_invalid_nonce_and_non_v2_submission_fail_closed(self) -> None:
        grant_raw = canonical_json(_grant())
        with (
            patch(
                "aragorn.runtime_capability_grant.secrets.token_hex",
                return_value="not-a-nonce",
            ),
            self.assertRaisesRegex(RuntimeCapabilityGrantError, "nonce"),
        ):
            issue_profiled_runtime_capability(_submission(), grant_raw, 102)

        submission = _submission()
        submission["schema"] = "aragorn/runtime-observed-create-submission/v1"
        with self.assertRaisesRegex(RuntimeCapabilityGrantError, "required"):
            issue_profiled_runtime_capability(submission, grant_raw, 102)


if __name__ == "__main__":
    unittest.main()
