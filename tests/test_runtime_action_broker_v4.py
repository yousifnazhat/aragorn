from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import (
    RuntimeActionBrokerError,
    RuntimeActionEffectIndeterminate,
)
from aragorn.runtime_action_broker_v4 import (
    RuntimeActionBrokerV4Config,
    initialize_runtime_capability_grant,
    mediate_granted_profiled_runtime_create,
    recover_runtime_capability_grant,
)
from aragorn.runtime_capability_grant import (
    GRANT_AUTHORITY,
    GRANT_SCHEMA,
    issue_profiled_runtime_capability,
)
from tests.test_runtime_action_broker_v2 import _profiled_fixture


def _fixture(
    root: Path,
) -> tuple[object, RuntimeActionBrokerV4Config, dict[str, object]]:
    fixture, broker, submission = _profiled_fixture(root)
    request = submission["envelope"]["request"]
    grant = {
        "schema": GRANT_SCHEMA,
        "authority": GRANT_AUTHORITY,
        "grant_id": "1" * 64,
        "source_manifest_digest": "sha256:" + "a" * 64,
        "install_context_digest": "sha256:" + "b" * 64,
        "runtime_profile_digest": submission["runtime_attribution"]["profile_digest"],
        "runtime_digest": request["runtime_digest"],
        "active_skill_digest": request["active_skill_digest"],
        "sensor_digest": submission["sensor_digest"],
        "policy_digest": request["policy_digest"],
        "policy_version": request["policy_version"],
        "operation_digest": request["operation_digest"],
        "issued_at_unix": 97,
        "expires_at_unix": 104,
        "max_actions": 1,
    }
    grant_raw = canonical_json(grant)
    config = RuntimeActionBrokerV4Config(
        broker=broker,
        capability_grant=grant_raw,
        grant_state_path=fixture.control / "capability-grant-state.json",
    )
    with patch(
        "aragorn.runtime_capability_grant.secrets.token_hex",
        return_value="2" * 64,
    ):
        issued = issue_profiled_runtime_capability(submission, grant_raw, 100)
    return fixture, config, issued


def _state(config: RuntimeActionBrokerV4Config) -> dict[str, object]:
    return json.loads(config.grant_state_path.read_bytes())


def _replacement(config: RuntimeActionBrokerV4Config) -> RuntimeActionBrokerV4Config:
    grant = json.loads(config.capability_grant)
    grant["grant_id"] = "4" * 64
    grant["source_manifest_digest"] = "sha256:" + "4" * 64
    return RuntimeActionBrokerV4Config(
        broker=config.broker,
        capability_grant=canonical_json(grant),
        grant_state_path=config.grant_state_path,
    )


class RuntimeActionBrokerV4Tests(unittest.TestCase):
    def test_one_root_grant_redeems_one_exact_sensor_issued_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, issued = _fixture(Path(temporary).resolve())
            initialize_runtime_capability_grant(config, now_unix=100)
            with (
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v4.time.time", return_value=100),
            ):
                result = mediate_granted_profiled_runtime_create(issued, config)

            state = _state(config)
            self.assertEqual(result["effect_status"], "CREATED")
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            self.assertEqual(state["status"], "CONSUMED")
            self.assertEqual(
                state["grant_digest"],
                issued["grant_digest"],
            )
            self.assertEqual(
                state["claim"]["lease_digest"],
                canonical_digest(issued["lease"]),
            )
            self.assertEqual(state["claim"]["lease"], issued["lease"])
            self.assertEqual(
                state["claim"]["profile_claim"]["submission_digest"],
                issued["lease"]["submission_digest"],
            )
            self.assertEqual(
                state["result"]["profile_result"]["broker_result_digest"],
                canonical_digest(result),
            )

    def test_cross_paired_and_mutated_issuance_never_claims(self) -> None:
        mutations = {
            "grant": ("grant_digest", "sha256:" + "f" * 64),
            "submission": ("submission_digest", "sha256:" + "f" * 64),
            "attribution": (
                "runtime_attribution_digest",
                "sha256:" + "f" * 64,
            ),
            "request": ("request_digest", "sha256:" + "f" * 64),
            "path": ("path_digest", "sha256:" + "f" * 64),
            "payload": ("payload_digest", "sha256:" + "f" * 64),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                _fixture_data, config, issued = _fixture(Path(temporary).resolve())
                initialize_runtime_capability_grant(config, now_unix=100)
                candidate = copy.deepcopy(issued)
                if field == "grant_digest":
                    candidate[field] = value
                else:
                    candidate["lease"][field] = value
                with (
                    patch(
                        "aragorn.runtime_action_broker_v4."
                        "mediate_profiled_runtime_create"
                    ) as mediate,
                    patch(
                        "aragorn.runtime_action_broker_v4.time.time",
                        return_value=100,
                    ),
                    self.assertRaisesRegex(RuntimeActionBrokerError, "unbound"),
                ):
                    mediate_granted_profiled_runtime_create(candidate, config)
                mediate.assert_not_called()
                self.assertEqual(_state(config)["status"], "AVAILABLE")

        with tempfile.TemporaryDirectory() as temporary:
            _fixture_data, config, issued = _fixture(Path(temporary).resolve())
            initialize_runtime_capability_grant(config, now_unix=100)
            alternate_submission = copy.deepcopy(issued["profiled_submission"])
            request = alternate_submission["envelope"]["request"]
            measured = alternate_submission["measured_action"]
            request["session_id"] = measured["session_id"] = "session-2"
            alternate_submission["request_digest"] = canonical_digest(request)
            alternate_submission["envelope_digest"] = canonical_digest(
                alternate_submission["envelope"]
            )
            candidate = {
                **issued,
                "profiled_submission": alternate_submission,
            }
            with (
                patch("aragorn.runtime_action_broker_v4.time.time", return_value=100),
                self.assertRaisesRegex(RuntimeActionBrokerError, "unbound"),
            ):
                mediate_granted_profiled_runtime_create(candidate, config)
            self.assertEqual(_state(config)["status"], "AVAILABLE")

    def test_two_sensor_nonces_under_one_grant_enter_v2_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, first = _fixture(Path(temporary).resolve())
            with patch(
                "aragorn.runtime_capability_grant.secrets.token_hex",
                return_value="3" * 64,
            ):
                second = issue_profiled_runtime_capability(
                    first["profiled_submission"],
                    config.capability_grant,
                    100,
                )
            initialize_runtime_capability_grant(config, now_unix=100)

            import aragorn.runtime_action_broker_v4 as broker_v4

            original = broker_v4.mediate_profiled_runtime_create
            entered = threading.Event()
            release = threading.Event()

            def delayed(*args: object, **kwargs: object) -> dict[str, object]:
                entered.set()
                self.assertTrue(release.wait(2))
                return original(*args, **kwargs)

            with (
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v4.time.time", return_value=100),
                patch.object(
                    broker_v4,
                    "mediate_profiled_runtime_create",
                    side_effect=delayed,
                ) as mediate,
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                winner = executor.submit(
                    mediate_granted_profiled_runtime_create,
                    first,
                    config,
                )
                self.assertTrue(entered.wait(2))
                with self.assertRaisesRegex(RuntimeActionBrokerError, "consumed"):
                    mediate_granted_profiled_runtime_create(second, config)
                release.set()
                self.assertEqual(winner.result(timeout=2)["effect_status"], "CREATED")

            self.assertEqual(mediate.call_count, 1)
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            self.assertEqual(_state(config)["status"], "CONSUMED")

    def test_lease_expiring_while_waiting_for_claim_is_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture_data, config, issued = _fixture(Path(temporary).resolve())
            initialize_runtime_capability_grant(config, now_unix=100)
            with (
                patch(
                    "aragorn.runtime_action_broker_v4.time.time",
                    side_effect=[100, issued["lease"]["expires_at_unix"]],
                ),
                patch(
                    "aragorn.runtime_action_broker_v4.mediate_profiled_runtime_create"
                ) as mediate,
                self.assertRaisesRegex(RuntimeActionBrokerError, "stale"),
            ):
                mediate_granted_profiled_runtime_create(issued, config)
            mediate.assert_not_called()
            self.assertEqual(_state(config)["status"], "AVAILABLE")

    def test_known_pre_effect_failure_is_terminal_then_rotates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture_data, config, issued = _fixture(Path(temporary).resolve())
            initialize_runtime_capability_grant(config, now_unix=100)
            with (
                patch("aragorn.runtime_action_broker_v4.time.time", return_value=100),
                patch(
                    "aragorn.runtime_action_broker_v4.mediate_profiled_runtime_create",
                    side_effect=RuntimeActionBrokerError("known pre-effect failure"),
                ) as mediate,
                self.assertRaisesRegex(RuntimeActionBrokerError, "known pre-effect"),
            ):
                mediate_granted_profiled_runtime_create(issued, config)

            abandoned = _state(config)
            self.assertEqual(abandoned["status"], "ABANDONED")
            self.assertEqual(
                abandoned["result"]["failure_code"],
                "KNOWN_NO_EFFECT_RUNTIME_BROKER_ERROR",
            )
            with (
                patch("aragorn.runtime_action_broker_v4.time.time", return_value=100),
                self.assertRaisesRegex(RuntimeActionBrokerError, "consumed"),
            ):
                mediate_granted_profiled_runtime_create(issued, config)
            self.assertEqual(mediate.call_count, 1)

            replacement = _replacement(config)
            archive = config.grant_state_path.with_name(
                "capability-grant-state-"
                f"{abandoned['grant_digest'].removeprefix('sha256:')}.json"
            )
            abandoned_stage = archive.with_name(f".{archive.name}.{'a' * 24}")
            abandoned_stage.write_bytes(canonical_json(abandoned))
            abandoned_stage.chmod(0o400)
            os.link(abandoned_stage, archive)
            self.assertEqual(archive.stat().st_nlink, 2)
            initialized = initialize_runtime_capability_grant(
                replacement,
                now_unix=100,
            )
            self.assertEqual(initialized["status"], "AVAILABLE")
            self.assertFalse(abandoned_stage.exists())
            self.assertEqual(archive.stat().st_nlink, 1)
            self.assertEqual(json.loads(archive.read_bytes()), abandoned)

            with patch(
                "aragorn.runtime_capability_grant.secrets.token_hex",
                return_value="5" * 64,
            ):
                replacement_issued = issue_profiled_runtime_capability(
                    issued["profiled_submission"],
                    replacement.capability_grant,
                    100,
                )
            with (
                patch("aragorn.runtime_action_broker_v4.time.time", return_value=100),
                patch(
                    "aragorn.runtime_action_broker_v4.mediate_profiled_runtime_create",
                    side_effect=RuntimeActionBrokerError("replacement pre-effect"),
                ),
                self.assertRaisesRegex(
                    RuntimeActionBrokerError, "replacement pre-effect"
                ),
            ):
                mediate_granted_profiled_runtime_create(
                    replacement_issued,
                    replacement,
                )
            replacement_state = _state(replacement)
            self.assertEqual(replacement_state["status"], "ABANDONED")
            with self.assertRaisesRegex(RuntimeActionBrokerError, "already terminal"):
                initialize_runtime_capability_grant(config, now_unix=100)
            self.assertEqual(_state(replacement), replacement_state)

            config.grant_state_path.unlink()
            with self.assertRaisesRegex(RuntimeActionBrokerError, "already terminal"):
                initialize_runtime_capability_grant(config, now_unix=100)
            self.assertFalse(config.grant_state_path.exists())

            config.grant_state_path.write_bytes(
                canonical_json(
                    {
                        "schema": "aragorn/runtime-capability-grant-state/v1",
                        "authority": (
                            "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_"
                            "CONFORMANCE_AUTHORITY"
                        ),
                        "grant_digest": abandoned["grant_digest"],
                        "status": "AVAILABLE",
                        "claim": None,
                        "result": None,
                    }
                )
            )
            config.grant_state_path.chmod(0o400)
            with self.assertRaisesRegex(RuntimeActionBrokerError, "already terminal"):
                initialize_runtime_capability_grant(config, now_unix=100)

    def test_indeterminate_attempt_never_rotates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture_data, config, issued = _fixture(Path(temporary).resolve())
            initialize_runtime_capability_grant(config, now_unix=100)
            with (
                patch("aragorn.runtime_action_broker_v4.time.time", return_value=100),
                patch(
                    "aragorn.runtime_action_broker_v4.mediate_profiled_runtime_create",
                    side_effect=RuntimeActionEffectIndeterminate("unknown effect"),
                ),
                self.assertRaises(RuntimeActionEffectIndeterminate),
            ):
                mediate_granted_profiled_runtime_create(issued, config)
            self.assertEqual(_state(config)["status"], "CLAIMED")
            with self.assertRaisesRegex(
                RuntimeActionBrokerError, "changed while active"
            ):
                initialize_runtime_capability_grant(
                    _replacement(config),
                    now_unix=100,
                )

    def test_exact_receipt_recovers_claim_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, issued = _fixture(Path(temporary).resolve())
            initialize_runtime_capability_grant(config, now_unix=100)
            with (
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v4.time.time", return_value=100),
                patch(
                    "aragorn.runtime_action_broker_v4._consume_grant",
                    side_effect=RuntimeActionEffectIndeterminate("crash boundary"),
                ),
                self.assertRaises(RuntimeActionEffectIndeterminate),
            ):
                mediate_granted_profiled_runtime_create(issued, config)

            self.assertEqual(_state(config)["status"], "CLAIMED")
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            with patch(
                "aragorn.runtime_action_broker_v4.mediate_profiled_runtime_create"
            ) as mediate:
                recovered = recover_runtime_capability_grant(config)
            mediate.assert_not_called()
            self.assertEqual(recovered["status"], "CONSUMED")
            self.assertEqual(_state(config)["status"], "CONSUMED")

            consumed = _state(config)
            replacement = _replacement(config)
            digest = consumed["grant_digest"].removeprefix("sha256:")
            state_archive = config.grant_state_path.with_name(
                f"capability-grant-state-{digest}.json"
            )
            receipt_archive = config.grant_state_path.with_name(
                f"capability-grant-profile-receipt-{digest}.json"
            )
            with (
                patch(
                    "aragorn.runtime_action_broker_v4._publish_state",
                    side_effect=RuntimeActionBrokerError("crash after archive"),
                ),
                self.assertRaisesRegex(RuntimeActionBrokerError, "crash after archive"),
            ):
                initialize_runtime_capability_grant(replacement, now_unix=100)
            self.assertEqual(_state(config), consumed)
            self.assertEqual(json.loads(state_archive.read_bytes()), consumed)
            self.assertEqual(
                json.loads(receipt_archive.read_bytes()),
                json.loads(config.broker.profile_receipt_path.read_bytes()),
            )
            initialized = initialize_runtime_capability_grant(
                replacement,
                now_unix=100,
            )
            self.assertEqual(initialized["status"], "AVAILABLE")

    def test_grant_change_and_state_mutation_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture_data, config, _issued = _fixture(Path(temporary).resolve())
            initialize_runtime_capability_grant(config, now_unix=100)
            grant = json.loads(config.capability_grant)
            grant["source_manifest_digest"] = "sha256:" + "f" * 64
            changed = RuntimeActionBrokerV4Config(
                broker=config.broker,
                capability_grant=canonical_json(grant),
                grant_state_path=config.grant_state_path,
            )
            with self.assertRaisesRegex(
                RuntimeActionBrokerError, "changed while active"
            ):
                initialize_runtime_capability_grant(changed, now_unix=100)

            state = _state(config)
            state["status"] = "CONSUMED"
            config.grant_state_path.chmod(0o600)
            config.grant_state_path.write_bytes(canonical_json(state))
            config.grant_state_path.chmod(0o400)
            with self.assertRaises(RuntimeActionBrokerError):
                recover_runtime_capability_grant(config)


if __name__ == "__main__":
    unittest.main()
