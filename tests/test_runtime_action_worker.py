from __future__ import annotations

import base64
import os
import socket
import stat
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import (
    RuntimeActionBrokerError,
    _read_frame,
    _send_frame,
)
from aragorn.runtime_action_worker import (
    RuntimeActionWorkerBinding,
    RuntimeActionWorkerConfig,
    RuntimeActionWorkerError,
    _broker_envelope,
    _broker_result,
    _clock_value,
    _handle_connection,
    _open_runtime_directory,
    _read_worker_binding,
    _relay_request,
)

_RUNTIME = "sha256:" + "1" * 64
_SKILL = "sha256:" + "2" * 64
_POLICY = "sha256:" + "3" * 64
_TOOL_CALL = "sha256:" + "4" * 64
_OBSERVATION = "sha256:" + "5" * 64


def _binding() -> RuntimeActionWorkerBinding:
    return RuntimeActionWorkerBinding(
        runtime_digest=_RUNTIME,
        active_skill_digest=_SKILL,
        policy_digest=_POLICY,
        policy_version=7,
    )


def _request(payload: bytes = b"bounded worker payload\n") -> dict[str, object]:
    return {
        "schema": "aragorn/runtime-action-worker-request/v1",
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "target_name": "worker-result.txt",
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "session_id": "session-1",
        "run_id": "run-1",
        "tool_call_digest": _TOOL_CALL,
    }


def _config(root: Path) -> RuntimeActionWorkerConfig:
    return RuntimeActionWorkerConfig(
        socket_path=root / "worker" / "worker.sock",
        runtime_directory=root / "worker",
        sensor_socket_path=root / "sensor" / "sensor.sock",
        protected_root=root / "protected",
        expected_worker_uid=1001,
        expected_worker_gid=2001,
        expected_gateway_uid=1002,
        expected_gateway_gid=2002,
        expected_sensor_uid=1003,
        expected_sensor_gid=2003,
        expected_broker_uid=1004,
        binding=_binding(),
    )


def _decision(envelope: dict[str, object]) -> dict[str, object]:
    request = envelope["request"]
    return {
        "schema": "aragorn/runtime-action-decision/v1",
        "authority": (
            "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        ),
        "request_digest": canonical_digest(request),
        "active_context_digest": "sha256:" + "6" * 64,
        "measured_action_digest": "sha256:" + "7" * 64,
        "policy_digest": _POLICY,
        "policy_version": 7,
        "evaluated_at_unix": 100,
        "revocation_snapshot_digest": "sha256:" + "8" * 64,
        "revocation_generation": 3,
        "minimum_revocation_generation": 2,
        "mediator_health_digest": "sha256:" + "9" * 64,
        "mediator_health_epoch": 4,
        "minimum_mediator_health_epoch": 2,
        "verdict": "ALLOW",
        "reason_codes": [],
    }


def _allowed_result(envelope: dict[str, object]) -> dict[str, object]:
    effect = envelope["effect"]
    return {
        "schema": "aragorn/runtime-action-broker-result/v1",
        "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "request_digest": canonical_digest(envelope["request"]),
        "observation_digest": _OBSERVATION,
        "target_name": effect["target_name"],
        "verdict": "ALLOW",
        "reason_codes": [],
        "effect_status": "CREATED",
        "decision": _decision(envelope),
    }


def _envelope(root: Path) -> dict[str, object]:
    request = _request()
    descriptor = os.open(root, os.O_RDONLY)
    try:
        return _broker_envelope(
            request,
            base64.b64decode(request["payload_base64"]),
            descriptor,
            _binding(),
            100,
        )
    finally:
        os.close(descriptor)


class RuntimeActionWorkerTests(unittest.TestCase):
    def test_binding_is_exact_canonical_and_five_field(self) -> None:
        document = {
            "schema": "aragorn/runtime-action-worker-binding/v1",
            "runtime_digest": _RUNTIME,
            "active_skill_digest": _SKILL,
            "policy_digest": _POLICY,
            "policy_version": 7,
        }
        with patch(
            "aragorn.runtime_action_worker._read_credential_bytes",
            return_value=canonical_json(document),
        ):
            self.assertEqual(
                _read_worker_binding(Path("/credential"), 1001), _binding()
            )

        document["extra"] = True
        with (
            patch(
                "aragorn.runtime_action_worker._read_credential_bytes",
                return_value=canonical_json(document),
            ),
            self.assertRaisesRegex(
                RuntimeActionWorkerError,
                "worker binding credential is invalid",
            ),
        ):
            _read_worker_binding(Path("/credential"), 1001)

    def test_runtime_directory_transitions_to_exact_gateway_group(self) -> None:
        config = _config(Path("/tmp/aragorn-worker-test"))

        def metadata(gid: int, ctime_ns: int) -> SimpleNamespace:
            return SimpleNamespace(
                st_dev=11,
                st_ino=12,
                st_mode=stat.S_IFDIR | 0o711,
                st_uid=config.expected_worker_uid,
                st_gid=gid,
                st_nlink=2,
                st_size=64,
                st_mtime_ns=20,
                st_ctime_ns=ctime_ns,
            )

        initial = metadata(config.expected_worker_gid, 21)
        transitioned = metadata(config.expected_gateway_gid, 22)
        with (
            patch.object(
                Path,
                "resolve",
                return_value=config.runtime_directory,
            ),
            patch("aragorn.runtime_action_worker._require_protected_ancestry"),
            patch(
                "aragorn.runtime_action_worker.os.lstat",
                side_effect=(initial, transitioned),
            ),
            patch("aragorn.runtime_action_worker.os.open", return_value=55),
            patch(
                "aragorn.runtime_action_worker.os.fstat",
                side_effect=(initial, transitioned),
            ),
            patch("aragorn.runtime_action_worker.os.fchown") as fchown,
            patch("aragorn.runtime_action_worker.os.fchmod") as fchmod,
        ):
            descriptor = _open_runtime_directory(config)

        self.assertEqual(descriptor, 55)
        fchown.assert_called_once_with(
            55,
            config.expected_worker_uid,
            config.expected_gateway_gid,
        )
        fchmod.assert_called_once_with(55, 0o711)

    def test_clock_rejects_bool_and_float_without_coercion(self) -> None:
        self.assertEqual(_clock_value(lambda: 100), 100)
        for value in (True, 100.5):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(
                    RuntimeActionWorkerError,
                    "worker clock failed",
                ),
            ):
                _clock_value(lambda value=value: value)

    def test_completed_requires_one_verified_sensor_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "protected"
            protected.mkdir()
            worker, sensor = socket.socketpair()
            request = _request()

            def sensor_round_trip() -> dict[str, object]:
                envelope = _read_frame(sensor, time.monotonic() + 1)
                _send_frame(
                    sensor,
                    canonical_json(_allowed_result(envelope)),
                    time.monotonic() + 1,
                )
                sensor.shutdown(socket.SHUT_WR)
                return envelope

            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    received = executor.submit(sensor_round_trip)
                    with (
                        patch(
                            "aragorn.runtime_action_worker._open_protected_root",
                            return_value=os.open(protected, os.O_RDONLY),
                        ),
                        patch(
                            "aragorn.runtime_action_worker._connect_sensor",
                            return_value=worker,
                        ) as connect_sensor,
                    ):
                        result = _relay_request(
                            request,
                            _config(root),
                            deadline=time.monotonic() + 1,
                            clock=lambda: 100,
                        )
                    envelope = received.result(timeout=1)
            finally:
                sensor.close()
                worker.close()

        connect_sensor.assert_called_once()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["request_digest"], canonical_digest(request))
        self.assertEqual(result["broker_result"], _allowed_result(envelope))
        self.assertEqual(envelope["request"]["tool_call_id"], _TOOL_CALL)
        self.assertEqual(envelope["request"]["issued_at_unix"], 100)
        self.assertEqual(envelope["request"]["expires_at_unix"], 105)

    def test_connect_failure_is_not_submitted_and_never_sends(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "protected"
            protected.mkdir()
            with (
                patch(
                    "aragorn.runtime_action_worker._open_protected_root",
                    return_value=os.open(protected, os.O_RDONLY),
                ),
                patch(
                    "aragorn.runtime_action_worker._connect_sensor",
                    side_effect=RuntimeActionWorkerError("sensor absent"),
                ),
                patch("aragorn.runtime_action_worker._send_frame") as send_frame,
            ):
                result = _relay_request(
                    _request(),
                    _config(root),
                    deadline=time.monotonic() + 1,
                    clock=lambda: 100,
                )

        self.assertEqual(result["status"], "NOT_SUBMITTED")
        self.assertIsNone(result["broker_result"])
        send_frame.assert_not_called()

    def test_send_failure_is_indeterminate_and_never_retried(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "protected"
            protected.mkdir()
            sensor = Mock(spec=socket.socket)
            with (
                patch(
                    "aragorn.runtime_action_worker._open_protected_root",
                    return_value=os.open(protected, os.O_RDONLY),
                ),
                patch(
                    "aragorn.runtime_action_worker._connect_sensor",
                    return_value=sensor,
                ),
                patch(
                    "aragorn.runtime_action_worker._send_frame",
                    side_effect=RuntimeActionBrokerError("partial send"),
                ) as send_frame,
                patch("aragorn.runtime_action_worker._read_frame") as read_frame,
            ):
                result = _relay_request(
                    _request(),
                    _config(root),
                    deadline=time.monotonic() + 1,
                    clock=lambda: 100,
                )

        self.assertEqual(result["status"], "INDETERMINATE")
        self.assertIsNone(result["broker_result"])
        send_frame.assert_called_once()
        sensor.shutdown.assert_not_called()
        read_frame.assert_not_called()

    def test_every_failure_after_send_is_indeterminate(self) -> None:
        failures = (
            ("shutdown", OSError("shutdown failed")),
            ("read", RuntimeActionBrokerError("response failed")),
        )
        for checkpoint, failure in failures:
            with (
                self.subTest(checkpoint=checkpoint),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                protected = root / "protected"
                protected.mkdir()
                sensor = Mock(spec=socket.socket)
                if checkpoint == "shutdown":
                    sensor.shutdown.side_effect = failure
                read_effect = failure if checkpoint == "read" else None
                with (
                    patch(
                        "aragorn.runtime_action_worker._open_protected_root",
                        return_value=os.open(protected, os.O_RDONLY),
                    ),
                    patch(
                        "aragorn.runtime_action_worker._connect_sensor",
                        return_value=sensor,
                    ),
                    patch("aragorn.runtime_action_worker._send_frame") as send_frame,
                    patch(
                        "aragorn.runtime_action_worker._read_frame",
                        side_effect=read_effect,
                    ),
                ):
                    result = _relay_request(
                        _request(),
                        _config(root),
                        deadline=time.monotonic() + 1,
                        clock=lambda: 100,
                    )
                self.assertEqual(result["status"], "INDETERMINATE")
                send_frame.assert_called_once()

    def test_broker_result_validation_rejects_unbound_or_inconsistent_outcome(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            envelope = _envelope(Path(temporary))

        for mutation in ("request_digest", "missing_decision", "block_without_reason"):
            with self.subTest(mutation=mutation):
                result = _allowed_result(envelope)
                if mutation == "request_digest":
                    result["request_digest"] = "sha256:" + "a" * 64
                elif mutation == "missing_decision":
                    result["decision"] = None
                else:
                    result.update(
                        verdict="BLOCK",
                        effect_status="NOT_PERFORMED",
                        reason_codes=[],
                    )
                with self.assertRaises(RuntimeActionWorkerError):
                    _broker_result(result, envelope, _binding())

    def test_block_accepts_null_missing_context_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            envelope = _envelope(Path(temporary))
        result = _allowed_result(envelope)
        reasons = ["ACTION_UNATTRIBUTED", "ACTION_UNMEASURED"]
        result.update(
            verdict="BLOCK",
            effect_status="NOT_PERFORMED",
            reason_codes=reasons,
        )
        result["decision"].update(
            verdict="BLOCK",
            reason_codes=reasons,
            active_context_digest=None,
            measured_action_digest=None,
        )

        self.assertEqual(_broker_result(result, envelope, _binding()), result)

    def test_invalid_request_allows_null_context_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            envelope = _envelope(Path(temporary))
        result = _allowed_result(envelope)
        reasons = ["ACTION_REQUEST_INVALID"]
        result.update(
            verdict="BLOCK",
            effect_status="NOT_PERFORMED",
            reason_codes=reasons,
        )
        result["decision"].update(
            verdict="BLOCK",
            reason_codes=reasons,
            active_context_digest=None,
            measured_action_digest=None,
        )

        self.assertEqual(_broker_result(result, envelope, _binding()), result)

    def test_allow_rejects_null_context_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            envelope = _envelope(Path(temporary))
        result = _allowed_result(envelope)
        result["decision"]["active_context_digest"] = None

        with self.assertRaisesRegex(
            RuntimeActionWorkerError,
            "decision attribution is inconsistent",
        ):
            _broker_result(result, envelope, _binding())

    def test_null_context_digest_requires_matching_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            envelope = _envelope(Path(temporary))
        result = _allowed_result(envelope)
        reasons = ["ACTION_NOT_ALLOWED"]
        result.update(
            verdict="BLOCK",
            effect_status="NOT_PERFORMED",
            reason_codes=reasons,
        )
        result["decision"].update(
            verdict="BLOCK",
            reason_codes=reasons,
            active_context_digest=None,
        )

        with self.assertRaisesRegex(
            RuntimeActionWorkerError,
            "decision attribution is inconsistent",
        ):
            _broker_result(result, envelope, _binding())

    def test_gateway_peer_is_authenticated_before_request_is_read(self) -> None:
        client, worker = socket.socketpair()
        try:
            with (
                patch(
                    "aragorn.runtime_action_worker._peer_credentials",
                    return_value=(123, 9999, 9998),
                ),
                patch("aragorn.runtime_action_worker._read_frame") as read_frame,
                self.assertRaisesRegex(
                    RuntimeActionWorkerError,
                    "unauthorized identity",
                ),
            ):
                _handle_connection(
                    worker,
                    _config(Path("/tmp/aragorn-worker-test")),
                    timeout_seconds=0.5,
                )
            read_frame.assert_not_called()
        finally:
            client.close()
            worker.close()

    def test_sensor_peer_is_authenticated_before_any_send(self) -> None:
        connection = Mock(spec=socket.socket)
        config = _config(Path("/tmp/aragorn-worker-test"))
        with (
            patch(
                "aragorn.runtime_action_worker._sensor_socket_identity",
                return_value=(1, 2, 3),
            ),
            patch(
                "aragorn.runtime_action_worker.socket.socket",
                return_value=connection,
            ),
            patch(
                "aragorn.runtime_action_worker._peer_credentials",
                return_value=(321, 9999, 9998),
            ),
            self.assertRaisesRegex(
                RuntimeActionWorkerError,
                "unauthorized identity",
            ),
        ):
            from aragorn.runtime_action_worker import _connect_sensor

            _connect_sensor(config, time.monotonic() + 1)
        connection.connect.assert_called_once_with(os.fspath(config.sensor_socket_path))
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
