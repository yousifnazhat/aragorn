from __future__ import annotations

import base64
import copy
import os
import socket
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_json
from aragorn.runtime_action_broker import _action_digests, _read_frame, _send_frame
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from aragorn.runtime_action_observation_publisher_v2 import (
    RuntimeActionObservationPublisherV2Config,
    _handle_connection,
    build_profiled_submission,
)
from aragorn.runtime_process_profile import (
    ATTRIBUTION_AUTHORITY,
    ATTRIBUTION_SCHEMA,
    PROFILE_AUTHORITY,
    PROFILE_SCHEMA,
    runtime_process_profile,
)

_RUNTIME = "sha256:" + "1" * 64
_SKILL = "sha256:" + "2" * 64
_SENSOR = "sha256:" + "3" * 64
_EXECUTABLE = "sha256:" + "5" * 64


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.protected = root / "protected"
        self.runtime = root / "runtime"
        self.protected.mkdir()
        self.runtime.mkdir()
        self.payload = b"profile measured\n"
        self.target_name = "profiled.txt"
        self.protected_fd = os.open(self.protected, os.O_RDONLY | os.O_DIRECTORY)
        action = _action_digests(self.protected_fd, self.target_name, self.payload)
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
        observer_uid, observer_gid = os.geteuid(), os.getegid()
        self.runtime_uid, self.runtime_gid = observer_uid + 1, observer_gid + 1
        self.broker_uid, self.broker_gid = observer_uid + 2, observer_gid + 2
        self.profile = runtime_process_profile(
            {
                "schema": PROFILE_SCHEMA,
                "authority": PROFILE_AUTHORITY,
                "runtime_digest": _RUNTIME,
                "executable_digest": _EXECUTABLE,
                "cgroup": "/system.slice/aragorn-openclaw-runtime.service",
                "skill_path": "/opt/aragorn/runtime-profile/SKILL.md",
            }
        )
        self.config = RuntimeActionObservationPublisherV2Config(
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
            expected_sensor_digest=_SENSOR,
            runtime_profile=self.profile,
        )
        self.peer = (101, self.runtime_uid, self.runtime_gid)
        self.attribution = {
            "schema": ATTRIBUTION_SCHEMA,
            "authority": ATTRIBUTION_AUTHORITY,
            "profile_digest": self.profile.digest,
            "runtime_digest": _RUNTIME,
            "executable_digest": _EXECUTABLE,
            "active_skill_digest": _SKILL,
            "skill_path": str(self.profile.skill_path),
            "cgroup": self.profile.cgroup,
            "pid": 101,
            "uid": self.runtime_uid,
            "gid": self.runtime_gid,
            "start_time_ticks": 741,
            "mount_namespace": {"device": 7, "inode": 8},
        }

    def close(self) -> None:
        os.close(self.protected_fd)


class RuntimeActionObservationPublisherV2Tests(unittest.TestCase):
    def test_builder_uses_derived_skill_and_emits_profiled_wire(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            try:
                submission = build_profiled_submission(
                    fixture.envelope,
                    fixture.peer,
                    fixture.protected_fd,
                    fixture.config,
                    fixture.attribution,
                )
                mismatch = copy.deepcopy(fixture.envelope)
                mismatch["request"]["active_skill_digest"] = "sha256:" + "f" * 64
                with self.assertRaisesRegex(
                    RuntimeActionObservationPublisherError,
                    "active-skill pin",
                ):
                    build_profiled_submission(
                        mismatch,
                        fixture.peer,
                        fixture.protected_fd,
                        fixture.config,
                        fixture.attribution,
                    )
            finally:
                fixture.close()

        self.assertEqual(
            submission["schema"],
            "aragorn/runtime-observed-create-submission/v2",
        )
        self.assertEqual(submission["runtime_peer"]["pid"], 101)
        self.assertEqual(submission["measured_action"]["active_skill_digest"], _SKILL)
        self.assertEqual(submission["runtime_attribution"], fixture.attribution)

    def test_handler_measures_before_and_after_then_relays_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            frontend_client, frontend_gateway = socket.socketpair()
            backend_gateway, backend_broker = socket.socketpair()
            result = {
                "schema": "aragorn/runtime-action-broker-result/v1",
                "verdict": "BLOCK",
                "effect_status": "NOT_PERFORMED",
            }
            _send_frame(
                frontend_client,
                canonical_json(fixture.envelope),
                time.monotonic() + 1,
            )
            frontend_client.shutdown(socket.SHUT_WR)
            pidfd = os.open("/dev/null", os.O_RDONLY)

            def broker() -> dict[str, object]:
                submission = _read_frame(backend_broker, time.monotonic() + 1)
                _send_frame(
                    backend_broker, canonical_json(result), time.monotonic() + 1
                )
                backend_broker.shutdown(socket.SHUT_WR)
                return submission

            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    broker_result = executor.submit(broker)
                    with (
                        patch(
                            "aragorn.runtime_action_observation_publisher_v2._peer_credentials",
                            side_effect=(
                                fixture.peer,
                                (202, fixture.broker_uid, fixture.broker_gid),
                            ),
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v2.open_peer_pidfd",
                            return_value=pidfd,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v2.measure_runtime_process_profile",
                            side_effect=(fixture.attribution, fixture.attribution),
                        ) as measure,
                        patch(
                            "aragorn.runtime_action_observation_publisher_v2._open_protected_root",
                            return_value=os.dup(fixture.protected_fd),
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v2._connect_backend",
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
                self.assertEqual(measure.call_count, 2)
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

    def test_handler_rejects_wrong_profile_before_reading_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            client, gateway = socket.socketpair()
            pidfd = os.open("/dev/null", os.O_RDONLY)
            try:
                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher_v2._peer_credentials",
                        return_value=fixture.peer,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v2.open_peer_pidfd",
                        return_value=pidfd,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v2.measure_runtime_process_profile",
                        side_effect=RuntimeActionObservationPublisherError(
                            "runtime process cgroup does not match"
                        ),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v2._read_frame"
                    ) as read_frame,
                    patch(
                        "aragorn.runtime_action_observation_publisher_v2._connect_backend"
                    ) as connect_backend,
                    self.assertRaisesRegex(
                        RuntimeActionObservationPublisherError,
                        "cgroup does not match",
                    ),
                ):
                    _handle_connection(gateway, fixture.config, timeout_seconds=0.5)
                read_frame.assert_not_called()
                connect_backend.assert_not_called()
            finally:
                fixture.close()
                client.close()
                gateway.close()

if __name__ == "__main__":
    unittest.main()
