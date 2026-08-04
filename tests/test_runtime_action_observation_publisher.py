from __future__ import annotations

import base64
import copy
import os
import socket
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import _action_digests, _read_frame, _send_frame
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherConfig,
    RuntimeActionObservationPublisherError,
    _handle_connection,
    build_observed_submission,
)

_RUNTIME = "sha256:" + "1" * 64
_SKILL = "sha256:" + "2" * 64
_SENSOR = "sha256:" + "3" * 64


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.protected = root / "protected"
        self.runtime = root / "runtime"
        self.protected.mkdir()
        self.runtime.mkdir()
        self.payload = b"independently measured\n"
        self.target_name = "measured.txt"
        self.protected_fd = os.open(
            self.protected,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        action = _action_digests(
            self.protected_fd,
            self.target_name,
            self.payload,
        )
        self.request = {
            "schema": "aragorn/runtime-action-request/v1",
            "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "runtime_digest": _RUNTIME,
            "session_id": "session-1",
            "run_id": "run-1",
            "tool_call_id": "call-1",
            "active_skill_digest": _SKILL,
            **action,
            "policy_digest": "sha256:" + "4" * 64,
            "policy_version": 1,
            "issued_at_unix": 98,
            "expires_at_unix": 103,
        }
        self.envelope = {
            "schema": "aragorn/runtime-action-broker-request/v1",
            "request": self.request,
            "effect": {
                "schema": "aragorn/runtime-create-file/v1",
                "operation": "create",
                "target_name": self.target_name,
                "payload_base64": base64.b64encode(self.payload).decode("ascii"),
            },
        }
        observer_uid = os.geteuid()
        observer_gid = os.getegid()
        self.runtime_uid = observer_uid + 1
        self.runtime_gid = observer_gid + 1
        self.broker_uid = observer_uid + 2
        self.broker_gid = observer_gid + 2
        self.config = RuntimeActionObservationPublisherConfig(
            frontend_socket_path=self.runtime / "sensor.sock",
            runtime_directory=self.runtime,
            instance_lock_path=self.runtime / "sensor.lock",
            backend_socket_path=root / "broker.sock",
            protected_root=self.protected,
            expected_observer_uid=observer_uid,
            expected_observer_gid=observer_gid,
            expected_runtime_uid=self.runtime_uid,
            expected_runtime_gid=self.runtime_gid,
            expected_broker_uid=self.broker_uid,
            expected_broker_gid=self.broker_gid,
            expected_runtime_digest=_RUNTIME,
            expected_active_skill_digest=_SKILL,
            expected_sensor_digest=_SENSOR,
        )
        self.runtime_peer = (101, self.runtime_uid, self.runtime_gid)

    def close(self) -> None:
        os.close(self.protected_fd)


class RuntimeActionObservationPublisherTests(unittest.TestCase):
    def test_wrapper_binds_canonical_request_peer_and_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            try:
                submission = build_observed_submission(
                    fixture.envelope,
                    fixture.runtime_peer,
                    fixture.protected_fd,
                    fixture.config,
                )
            finally:
                fixture.close()

        self.assertEqual(
            set(submission),
            {
                "schema",
                "authority",
                "sensor_digest",
                "envelope_digest",
                "request_digest",
                "runtime_peer",
                "measured_action",
                "envelope",
            },
        )
        self.assertEqual(
            submission["schema"],
            "aragorn/runtime-observed-create-submission/v1",
        )
        self.assertEqual(
            submission["authority"],
            "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        )
        self.assertEqual(submission["sensor_digest"], _SENSOR)
        self.assertEqual(
            submission["envelope_digest"], canonical_digest(submission["envelope"])
        )
        self.assertEqual(
            submission["request_digest"],
            canonical_digest(submission["envelope"]["request"]),
        )
        self.assertEqual(
            submission["runtime_peer"],
            {"pid": 101, "uid": fixture.runtime_uid, "gid": fixture.runtime_gid},
        )
        measured = submission["measured_action"]
        self.assertEqual(measured["schema"], "aragorn/measured-runtime-action/v1")
        for field in (
            "runtime_digest",
            "session_id",
            "run_id",
            "tool_call_id",
            "active_skill_digest",
            "operation_digest",
            "path_digest",
            "payload_digest",
        ):
            self.assertEqual(measured[field], submission["envelope"]["request"][field])

    def test_mutation_pin_and_peer_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            try:
                mutated = copy.deepcopy(fixture.envelope)
                mutated["effect"]["payload_base64"] = base64.b64encode(b"changed").decode(
                    "ascii"
                )
                cases = (
                    (mutated, fixture.config, fixture.runtime_peer),
                    (
                        fixture.envelope,
                        replace(
                            fixture.config,
                            expected_runtime_digest="sha256:" + "5" * 64,
                        ),
                        fixture.runtime_peer,
                    ),
                    (
                        fixture.envelope,
                        replace(
                            fixture.config,
                            expected_active_skill_digest="sha256:" + "5" * 64,
                        ),
                        fixture.runtime_peer,
                    ),
                    (
                        fixture.envelope,
                        fixture.config,
                        (101, fixture.runtime_uid + 1, fixture.runtime_gid),
                    ),
                )
                for envelope, config, peer in cases:
                    with self.subTest(config=config, peer=peer):
                        with self.assertRaises(
                            RuntimeActionObservationPublisherError
                        ):
                            build_observed_submission(
                                envelope,
                                peer,
                                fixture.protected_fd,
                                config,
                            )
            finally:
                fixture.close()

    def test_handler_authenticates_both_peers_and_relays_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            frontend_client, frontend_gateway = socket.socketpair()
            backend_gateway, backend_broker = socket.socketpair()
            result = {
                "schema": "aragorn/runtime-action-broker-result/v1",
                "verdict": "BLOCK",
                "effect_status": "NOT_PERFORMED",
            }
            deadline = time.monotonic() + 1
            _send_frame(frontend_client, canonical_json(fixture.envelope), deadline)
            frontend_client.shutdown(socket.SHUT_WR)

            def broker() -> dict[str, object]:
                submission = _read_frame(backend_broker, time.monotonic() + 1)
                _send_frame(backend_broker, canonical_json(result), time.monotonic() + 1)
                backend_broker.shutdown(socket.SHUT_WR)
                return submission

            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    broker_result = executor.submit(broker)
                    with (
                        patch(
                            "aragorn.runtime_action_observation_publisher._peer_credentials",
                            side_effect=(
                                fixture.runtime_peer,
                                (202, fixture.broker_uid, fixture.broker_gid),
                            ),
                        ) as credentials,
                        patch(
                            "aragorn.runtime_action_observation_publisher._open_protected_root",
                            return_value=os.dup(fixture.protected_fd),
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher._connect_backend",
                            return_value=backend_gateway,
                        ) as connect_backend,
                    ):
                        _handle_connection(
                            frontend_gateway,
                            fixture.config,
                            timeout_seconds=0.5,
                        )
                    frontend_gateway.shutdown(socket.SHUT_WR)
                    response = _read_frame(frontend_client, time.monotonic() + 1)
                    submission = broker_result.result(timeout=1)
                self.assertEqual(response, result)
                self.assertEqual(submission["envelope"], fixture.envelope)
                self.assertEqual(credentials.call_count, 2)
                connect_backend.assert_called_once()
            finally:
                fixture.close()
                for connection in (
                    frontend_client,
                    frontend_gateway,
                    backend_gateway,
                    backend_broker,
                ):
                    connection.close()

    def test_handler_rejects_unauthorized_runtime_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            frontend_client, frontend_gateway = socket.socketpair()
            try:
                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher._peer_credentials",
                        return_value=(101, fixture.runtime_uid + 1, fixture.runtime_gid),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher._read_frame"
                    ) as read_frame,
                    self.assertRaises(RuntimeActionObservationPublisherError),
                ):
                    _handle_connection(
                        frontend_gateway,
                        fixture.config,
                        timeout_seconds=0.5,
                    )
                read_frame.assert_not_called()
            finally:
                fixture.close()
                frontend_client.close()
                frontend_gateway.close()


if __name__ == "__main__":
    unittest.main()
