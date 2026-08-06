from __future__ import annotations

import copy
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import (
    RuntimeActionBrokerError,
    RuntimeActionEffectIndeterminate,
)
from aragorn.runtime_action_broker_v2 import mediate_profiled_runtime_create
from aragorn.runtime_action_broker_v3 import (
    RuntimeActionBrokerV3Config,
    initialize_runtime_capability_lease,
    mediate_leased_profiled_runtime_create,
    recover_runtime_capability_lease,
)
from tests.test_runtime_action_broker_v2 import _profiled_fixture


def _leased_fixture(
    root: Path,
) -> tuple[object, RuntimeActionBrokerV3Config, dict[str, object]]:
    fixture, broker, submission = _profiled_fixture(root)
    request = submission["envelope"]["request"]
    lease = {
        "schema": "aragorn/runtime-capability-lease/v1",
        "authority": (
            "BROKER_ENFORCED_SINGLE_CAPABILITY_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        ),
        "lease_nonce": "1" * 64,
        "runtime_profile_digest": submission["runtime_attribution"]["profile_digest"],
        "runtime_digest": request["runtime_digest"],
        "active_skill_digest": request["active_skill_digest"],
        "sensor_digest": submission["sensor_digest"],
        "request_digest": submission["request_digest"],
        "policy_digest": request["policy_digest"],
        "policy_version": request["policy_version"],
        "operation_digest": request["operation_digest"],
        "path_digest": request["path_digest"],
        "payload_digest": request["payload_digest"],
        "issued_at_unix": 97,
        "expires_at_unix": 104,
        "max_actions": 1,
    }
    config = RuntimeActionBrokerV3Config(
        broker=broker,
        capability_lease=canonical_json(lease),
        lease_state_path=fixture.control / "capability-lease-state.json",
    )
    return fixture, config, submission


def _state(config: RuntimeActionBrokerV3Config) -> dict[str, object]:
    return json.loads(config.lease_state_path.read_bytes())


class RuntimeActionBrokerV3Tests(unittest.TestCase):
    def test_one_lease_creates_once_and_replay_blocks_before_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, submission = _leased_fixture(Path(temporary).resolve())
            initialize_runtime_capability_lease(config, now_unix=100)
            with (
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
            ):
                result = mediate_leased_profiled_runtime_create(submission, config)

            state = _state(config)
            self.assertEqual(result["effect_status"], "CREATED")
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            self.assertEqual(state["status"], "CONSUMED")
            self.assertEqual(
                state["claim"]["submission_digest"],
                canonical_digest(submission),
            )
            self.assertEqual(
                state["result"]["broker_result_digest"],
                canonical_digest(result),
            )
            with (
                patch(
                    "aragorn.runtime_action_broker_v3.mediate_profiled_runtime_create"
                ) as mediate,
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
                self.assertRaisesRegex(RuntimeActionBrokerError, "consumed"),
            ):
                mediate_leased_profiled_runtime_create(submission, config)
            mediate.assert_not_called()

    def test_block_result_consumes_lease_without_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, submission = _leased_fixture(Path(temporary).resolve())
            policy = {**fixture.policy, "allow": []}
            fixture.paths["policy"].chmod(0o600)
            fixture.paths["policy"].write_bytes(canonical_json(policy))
            fixture.paths["policy"].chmod(0o400)
            request = submission["envelope"]["request"]
            request["policy_digest"] = canonical_digest(policy)
            submission["request_digest"] = canonical_digest(request)
            submission["envelope_digest"] = canonical_digest(submission["envelope"])
            lease = json.loads(config.capability_lease)
            lease["policy_digest"] = request["policy_digest"]
            lease["request_digest"] = submission["request_digest"]
            config = RuntimeActionBrokerV3Config(
                broker=config.broker,
                capability_lease=canonical_json(lease),
                lease_state_path=config.lease_state_path,
            )
            initialize_runtime_capability_lease(config, now_unix=100)
            with (
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
            ):
                result = mediate_leased_profiled_runtime_create(submission, config)

            self.assertEqual(
                (result["verdict"], result["effect_status"]),
                ("BLOCK", "NOT_PERFORMED"),
            )
            self.assertFalse(fixture.target.exists())
            self.assertEqual(_state(config)["status"], "CONSUMED")
            self.assertEqual(_state(config)["result"]["verdict"], "BLOCK")

    def test_lease_binding_changes_block_before_v2(self) -> None:
        mutations = {
            "skill": "active_skill_digest",
            "sensor": "sensor_digest",
            "request": "request_digest",
            "policy": "policy_digest",
            "operation": "operation_digest",
            "path": "path_digest",
            "payload": "payload_digest",
        }
        for label, field in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                _fixture, config, submission = _leased_fixture(
                    Path(temporary).resolve()
                )
                lease = json.loads(config.capability_lease)
                lease[field] = "sha256:" + "f" * 64
                changed = RuntimeActionBrokerV3Config(
                    broker=config.broker,
                    capability_lease=canonical_json(lease),
                    lease_state_path=config.lease_state_path,
                )
                initialize_runtime_capability_lease(changed, now_unix=100)
                with (
                    patch(
                        "aragorn.runtime_action_broker_v3."
                        "mediate_profiled_runtime_create"
                    ) as mediate,
                    patch(
                        "aragorn.runtime_action_broker_v3.time.time",
                        return_value=100,
                    ),
                    self.assertRaisesRegex(RuntimeActionBrokerError, "unbound"),
                ):
                    mediate_leased_profiled_runtime_create(submission, changed)
                mediate.assert_not_called()
                self.assertEqual(_state(changed)["status"], "ISSUED")

    def test_claim_publication_failure_never_invokes_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture, config, submission = _leased_fixture(Path(temporary).resolve())
            initialize_runtime_capability_lease(config, now_unix=100)
            with (
                patch(
                    "aragorn.runtime_action_broker_v3._atomic_publish_at",
                    side_effect=OSError("publication failed"),
                ),
                patch(
                    "aragorn.runtime_action_broker_v3.mediate_profiled_runtime_create"
                ) as mediate,
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
                self.assertRaisesRegex(RuntimeActionBrokerError, "state update failed"),
            ):
                mediate_leased_profiled_runtime_create(submission, config)
            mediate.assert_not_called()
            self.assertEqual(_state(config)["status"], "ISSUED")

    def test_alternate_lineage_cannot_steal_issued_lease(self) -> None:
        for field in ("session_id", "run_id", "tool_call_id"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                _fixture, config, submission = _leased_fixture(
                    Path(temporary).resolve()
                )
                initialize_runtime_capability_lease(config, now_unix=100)
                candidate = copy.deepcopy(submission)
                candidate["envelope"]["request"][field] = f"alternate-{field}"
                candidate["measured_action"][field] = f"alternate-{field}"
                candidate["request_digest"] = canonical_digest(
                    candidate["envelope"]["request"]
                )
                candidate["envelope_digest"] = canonical_digest(candidate["envelope"])
                with (
                    patch(
                        "aragorn.runtime_action_broker_v3."
                        "mediate_profiled_runtime_create"
                    ) as mediate,
                    patch(
                        "aragorn.runtime_action_broker_v3.time.time",
                        return_value=100,
                    ),
                    self.assertRaisesRegex(RuntimeActionBrokerError, "unbound"),
                ):
                    mediate_leased_profiled_runtime_create(candidate, config)
                mediate.assert_not_called()
                self.assertEqual(_state(config)["status"], "ISSUED")

    def test_boolean_max_actions_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture, config, _submission = _leased_fixture(Path(temporary).resolve())
            lease = json.loads(config.capability_lease)
            lease["max_actions"] = True
            changed = RuntimeActionBrokerV3Config(
                broker=config.broker,
                capability_lease=canonical_json(lease),
                lease_state_path=config.lease_state_path,
            )
            with self.assertRaisesRegex(RuntimeActionBrokerError, "max actions"):
                initialize_runtime_capability_lease(changed, now_unix=100)
            self.assertFalse(changed.lease_state_path.exists())

    def test_indeterminate_v2_leaves_claimed_and_never_reauthorizes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, submission = _leased_fixture(Path(temporary).resolve())
            initialize_runtime_capability_lease(config, now_unix=100)
            with (
                patch(
                    "aragorn.runtime_action_broker_v3.mediate_profiled_runtime_create",
                    side_effect=RuntimeActionEffectIndeterminate("uncertain"),
                ) as mediate,
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
                self.assertRaises(RuntimeActionEffectIndeterminate),
            ):
                mediate_leased_profiled_runtime_create(submission, config)

            self.assertEqual(_state(config)["status"], "CLAIMED")
            self.assertFalse(fixture.target.exists())
            with self.assertRaisesRegex(RuntimeActionBrokerError, "no durable"):
                recover_runtime_capability_lease(config)
            with (
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
                self.assertRaisesRegex(RuntimeActionBrokerError, "consumed"),
            ):
                mediate_leased_profiled_runtime_create(submission, config)
            self.assertEqual(mediate.call_count, 1)

    def test_exact_receipt_recovers_without_retrying_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, submission = _leased_fixture(Path(temporary).resolve())
            initialize_runtime_capability_lease(config, now_unix=100)

            def complete_then_crash(*args: object, **kwargs: object) -> object:
                mediate_profiled_runtime_create(*args, **kwargs)
                raise KeyboardInterrupt

            with (
                patch(
                    "aragorn.runtime_action_broker_v3.mediate_profiled_runtime_create",
                    side_effect=complete_then_crash,
                ),
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
                self.assertRaises(KeyboardInterrupt),
            ):
                mediate_leased_profiled_runtime_create(submission, config)

            self.assertEqual(_state(config)["status"], "CLAIMED")
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            with patch(
                "aragorn.runtime_action_broker_v3.mediate_profiled_runtime_create"
            ) as mediate:
                recovered = recover_runtime_capability_lease(config)
            mediate.assert_not_called()
            self.assertEqual(recovered["status"], "CONSUMED")

    def test_recovery_finishes_exact_v2_pending_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, submission = _leased_fixture(Path(temporary).resolve())
            initialize_runtime_capability_lease(config, now_unix=100)
            with (
                patch(
                    "aragorn.runtime_action_broker_v2._discard_profile_pending",
                    side_effect=KeyboardInterrupt,
                ),
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
                self.assertRaises(KeyboardInterrupt),
            ):
                mediate_leased_profiled_runtime_create(submission, config)

            self.assertTrue(config.broker.profile_pending_path.exists())
            self.assertTrue(config.broker.profile_receipt_path.exists())
            recovered = recover_runtime_capability_lease(config)
            self.assertEqual(recovered["status"], "CONSUMED")
            self.assertFalse(config.broker.profile_pending_path.exists())
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)

    def test_stale_profile_receipt_is_removed_before_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture, config, submission = _leased_fixture(Path(temporary).resolve())
            initialize_runtime_capability_lease(config, now_unix=100)
            config.broker.profile_receipt_path.write_bytes(
                canonical_json({"old": True})
            )
            config.broker.profile_receipt_path.chmod(0o400)
            real_mediate = mediate_profiled_runtime_create

            def require_fresh_receipt(*args: object, **kwargs: object) -> object:
                self.assertFalse(config.broker.profile_receipt_path.exists())
                return real_mediate(*args, **kwargs)

            with (
                patch(
                    "aragorn.runtime_action_broker_v3.mediate_profiled_runtime_create",
                    side_effect=require_fresh_receipt,
                ),
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
            ):
                mediate_leased_profiled_runtime_create(submission, config)
            self.assertEqual(_state(config)["status"], "CONSUMED")

    def test_concurrent_claims_invoke_v2_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture, config, submission = _leased_fixture(Path(temporary).resolve())
            initialize_runtime_capability_lease(config, now_unix=100)
            entered = threading.Event()
            release = threading.Event()
            failures: list[BaseException] = []
            real_mediate = mediate_profiled_runtime_create

            def delayed_mediate(*args: object, **kwargs: object) -> object:
                entered.set()
                if not release.wait(2):
                    raise AssertionError("concurrent test timed out")
                return real_mediate(*args, **kwargs)

            def first() -> None:
                try:
                    mediate_leased_profiled_runtime_create(submission, config)
                except BaseException as exc:  # noqa: BLE001 - relay thread failure
                    failures.append(exc)

            with (
                patch(
                    "aragorn.runtime_action_broker_v3.mediate_profiled_runtime_create",
                    side_effect=delayed_mediate,
                ) as mediate,
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
            ):
                worker = threading.Thread(target=first)
                worker.start()
                self.assertTrue(entered.wait(2))
                with self.assertRaisesRegex(RuntimeActionBrokerError, "consumed"):
                    mediate_leased_profiled_runtime_create(submission, config)
                release.set()
                worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(mediate.call_count, 1)
            self.assertEqual(_state(config)["status"], "CONSUMED")

    def test_mutated_recovery_receipt_cannot_consume_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _fixture, config, submission = _leased_fixture(Path(temporary).resolve())
            initialize_runtime_capability_lease(config, now_unix=100)

            def complete_then_crash(*args: object, **kwargs: object) -> object:
                mediate_profiled_runtime_create(*args, **kwargs)
                raise KeyboardInterrupt

            with (
                patch(
                    "aragorn.runtime_action_broker_v3.mediate_profiled_runtime_create",
                    side_effect=complete_then_crash,
                ),
                patch("aragorn.runtime_action_broker.time.time", return_value=100),
                patch("aragorn.runtime_action_broker_v3.time.time", return_value=100),
                self.assertRaises(KeyboardInterrupt),
            ):
                mediate_leased_profiled_runtime_create(submission, config)

            receipt = json.loads(config.broker.profile_receipt_path.read_bytes())
            changed = copy.deepcopy(receipt)
            changed["submission_digest"] = "sha256:" + "f" * 64
            config.broker.profile_receipt_path.chmod(0o600)
            config.broker.profile_receipt_path.write_bytes(canonical_json(changed))
            config.broker.profile_receipt_path.chmod(0o400)
            with self.assertRaisesRegex(RuntimeActionBrokerError, "unbound"):
                recover_runtime_capability_lease(config)
            self.assertEqual(_state(config)["status"], "CLAIMED")

    def test_mutated_durable_lineage_cannot_validate(self) -> None:
        for field in ("session_id", "run_id", "tool_call_id"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                _fixture, config, submission = _leased_fixture(
                    Path(temporary).resolve()
                )
                initialize_runtime_capability_lease(config, now_unix=100)
                with (
                    patch(
                        "aragorn.runtime_action_broker_v3."
                        "mediate_profiled_runtime_create",
                        side_effect=RuntimeActionEffectIndeterminate("uncertain"),
                    ),
                    patch(
                        "aragorn.runtime_action_broker_v3.time.time",
                        return_value=100,
                    ),
                    self.assertRaises(RuntimeActionEffectIndeterminate),
                ):
                    mediate_leased_profiled_runtime_create(submission, config)

                state = _state(config)
                state["claim"][field] = f"changed-{field}"
                config.lease_state_path.chmod(0o600)
                config.lease_state_path.write_bytes(canonical_json(state))
                config.lease_state_path.chmod(0o400)
                with self.assertRaisesRegex(RuntimeActionBrokerError, "unbound"):
                    recover_runtime_capability_lease(config)


if __name__ == "__main__":
    unittest.main()
