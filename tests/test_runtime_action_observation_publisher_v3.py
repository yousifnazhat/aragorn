from __future__ import annotations

import os
import socket
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_json
from aragorn.runtime_action_broker import _read_frame, _send_frame
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from aragorn.runtime_action_observation_publisher_v2 import (
    build_profiled_submission,
)
from aragorn.runtime_action_observation_publisher_v3 import (
    RuntimeActionObservationPublisherV3Config,
    _handle_connection,
    _validate_config,
    serve_runtime_action_observation_publisher_v3,
)
from aragorn.runtime_capability_grant import (
    GRANT_AUTHORITY,
    GRANT_SCHEMA,
    ISSUANCE_AUTHORITY,
    ISSUANCE_SCHEMA,
)
from aragorn.runtime_capability_grant import (
    issue_profiled_runtime_capability as _issue_profiled_runtime_capability,
)
from tests.test_runtime_action_observation_publisher_v2 import _Fixture


def _grant(fixture: _Fixture) -> bytes:
    return canonical_json(
        {
            "schema": GRANT_SCHEMA,
            "authority": GRANT_AUTHORITY,
            "grant_id": "6" * 64,
            "source_manifest_digest": "sha256:" + "7" * 64,
            "install_context_digest": "sha256:" + "8" * 64,
            "runtime_profile_digest": fixture.profile.digest,
            "runtime_digest": fixture.request["runtime_digest"],
            "active_skill_digest": fixture.request["active_skill_digest"],
            "sensor_digest": fixture.config.expected_sensor_digest,
            "policy_digest": fixture.request["policy_digest"],
            "policy_version": fixture.request["policy_version"],
            "operation_digest": fixture.request["operation_digest"],
            "issued_at_unix": 97,
            "expires_at_unix": 104,
            "max_actions": 1,
        }
    )


def _config(fixture: _Fixture) -> RuntimeActionObservationPublisherV3Config:
    return RuntimeActionObservationPublisherV3Config(
        publisher=fixture.config,
        capability_grant=_grant(fixture),
    )


class RuntimeActionObservationPublisherV3Tests(unittest.TestCase):
    def test_handler_issues_after_measurement_and_sends_only_wrapper_to_broker(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            config = _config(fixture)
            frontend_client, frontend_sensor = socket.socketpair()
            backend_sensor, backend_broker = socket.socketpair()
            result = {
                "schema": "aragorn/runtime-action-broker-result/v1",
                "verdict": "BLOCK",
                "effect_status": "NOT_PERFORMED",
            }
            events: list[str] = []
            _send_frame(
                frontend_client,
                canonical_json(fixture.envelope),
                time.monotonic() + 1,
            )
            frontend_client.shutdown(socket.SHUT_WR)
            pidfd = os.open("/dev/null", os.O_RDONLY)

            def broker() -> object:
                issuance = _read_frame(backend_broker, time.monotonic() + 1)
                _send_frame(
                    backend_broker,
                    canonical_json(result),
                    time.monotonic() + 1,
                )
                backend_broker.shutdown(socket.SHUT_WR)
                return issuance

            def measure(*_args: object, **_kwargs: object) -> object:
                events.append("measure")
                return fixture.attribution

            def build(*args: object, **kwargs: object) -> object:
                events.append("build")
                return build_profiled_submission(*args, **kwargs)

            def live(_descriptor: int) -> None:
                events.append("live")

            def connect(*_args: object, **_kwargs: object) -> socket.socket:
                events.append("connect")
                return backend_sensor

            def clock() -> float:
                events.append("clock")
                return 100.9

            def issue(submission: object, grant: bytes, now_unix: int) -> object:
                events.append("issue")
                self.assertEqual(grant, config.capability_grant)
                self.assertEqual(now_unix, 100)
                return _issue_profiled_runtime_capability(submission, grant, now_unix)

            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    broker_result = executor.submit(broker)
                    with (
                        patch(
                            "aragorn.runtime_action_observation_publisher_v3._peer_credentials",
                            side_effect=(
                                fixture.peer,
                                (202, fixture.broker_uid, fixture.broker_gid),
                            ),
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v3.open_peer_pidfd",
                            return_value=pidfd,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v3.measure_runtime_process_profile",
                            side_effect=measure,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v3._open_protected_root",
                            return_value=os.dup(fixture.protected_fd),
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v3.build_profiled_submission",
                            side_effect=build,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v3.require_live_pidfd",
                            side_effect=live,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v3._connect_backend",
                            side_effect=connect,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v3.time.time",
                            side_effect=clock,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v3.issue_profiled_runtime_capability",
                            side_effect=issue,
                        ),
                    ):
                        _handle_connection(
                            frontend_sensor,
                            config,
                            timeout_seconds=0.5,
                        )
                    frontend_sensor.shutdown(socket.SHUT_WR)
                    response = _read_frame(frontend_client, time.monotonic() + 1)
                    issuance = broker_result.result(timeout=1)
            finally:
                fixture.close()
                for connection in (
                    frontend_client,
                    frontend_sensor,
                    backend_sensor,
                    backend_broker,
                ):
                    connection.close()

        self.assertEqual(
            events,
            [
                "measure",
                "measure",
                "build",
                "live",
                "connect",
                "live",
                "measure",
                "clock",
                "issue",
            ],
        )
        self.assertEqual(issuance["schema"], ISSUANCE_SCHEMA)
        self.assertEqual(issuance["authority"], ISSUANCE_AUTHORITY)
        self.assertEqual(
            issuance["profiled_submission"]["schema"],
            "aragorn/runtime-observed-create-submission/v2",
        )
        self.assertNotEqual(issuance, issuance["profiled_submission"])
        self.assertEqual(response, result)
        self.assertNotIn("grant_digest", response)
        self.assertNotIn("lease", response)

    def test_wrong_runtime_peer_never_issues(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            client, sensor = socket.socketpair()
            try:
                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._peer_credentials",
                        return_value=(
                            fixture.peer[0],
                            fixture.runtime_uid + 1,
                            fixture.runtime_gid,
                        ),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.open_peer_pidfd"
                    ) as open_pidfd,
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._read_frame"
                    ) as read_frame,
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.issue_profiled_runtime_capability"
                    ) as issue,
                    self.assertRaisesRegex(
                        RuntimeActionObservationPublisherError,
                        "unauthorized identity",
                    ),
                ):
                    _handle_connection(sensor, _config(fixture), timeout_seconds=0.5)
                open_pidfd.assert_not_called()
                read_frame.assert_not_called()
                issue.assert_not_called()
            finally:
                fixture.close()
                client.close()
                sensor.close()

    def test_wrong_profile_never_reads_or_issues(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            client, sensor = socket.socketpair()
            pidfd = os.open("/dev/null", os.O_RDONLY)
            try:
                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._peer_credentials",
                        return_value=fixture.peer,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.open_peer_pidfd",
                        return_value=pidfd,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.measure_runtime_process_profile",
                        side_effect=RuntimeActionObservationPublisherError(
                            "runtime process cgroup does not match"
                        ),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._read_frame"
                    ) as read_frame,
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._connect_backend"
                    ) as connect_backend,
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.issue_profiled_runtime_capability"
                    ) as issue,
                    self.assertRaisesRegex(
                        RuntimeActionObservationPublisherError,
                        "cgroup does not match",
                    ),
                ):
                    _handle_connection(sensor, _config(fixture), timeout_seconds=0.5)
                read_frame.assert_not_called()
                connect_backend.assert_not_called()
                issue.assert_not_called()
            finally:
                fixture.close()
                client.close()
                sensor.close()

    def test_wrong_broker_peer_never_issues(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            client, sensor = socket.socketpair()
            backend_sensor, backend_peer = socket.socketpair()
            pidfd = os.open("/dev/null", os.O_RDONLY)
            try:
                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._peer_credentials",
                        side_effect=(
                            fixture.peer,
                            (202, fixture.broker_uid + 1, fixture.broker_gid),
                        ),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.open_peer_pidfd",
                        return_value=pidfd,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.measure_runtime_process_profile",
                        side_effect=(fixture.attribution, fixture.attribution),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._read_frame",
                        return_value=fixture.envelope,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._open_protected_root",
                        return_value=os.dup(fixture.protected_fd),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.require_live_pidfd"
                    ) as live,
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._connect_backend",
                        return_value=backend_sensor,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.issue_profiled_runtime_capability"
                    ) as issue,
                    self.assertRaisesRegex(
                        RuntimeActionObservationPublisherError,
                        "broker peer.*unauthorized identity",
                    ),
                ):
                    _handle_connection(sensor, _config(fixture), timeout_seconds=0.5)
                live.assert_called_once_with(pidfd)
                issue.assert_not_called()
            finally:
                fixture.close()
                client.close()
                sensor.close()
                backend_sensor.close()
                backend_peer.close()

    def test_profile_change_after_broker_authentication_never_issues(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            client, sensor = socket.socketpair()
            backend_sensor, backend_peer = socket.socketpair()
            pidfd = os.open("/dev/null", os.O_RDONLY)
            changed = {**fixture.attribution, "cgroup": "/changed"}
            try:
                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._peer_credentials",
                        side_effect=(
                            fixture.peer,
                            (202, fixture.broker_uid, fixture.broker_gid),
                        ),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.open_peer_pidfd",
                        return_value=pidfd,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.measure_runtime_process_profile",
                        side_effect=(
                            fixture.attribution,
                            fixture.attribution,
                            changed,
                        ),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._read_frame",
                        return_value=fixture.envelope,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._open_protected_root",
                        return_value=os.dup(fixture.protected_fd),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.require_live_pidfd"
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._connect_backend",
                        return_value=backend_sensor,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.issue_profiled_runtime_capability"
                    ) as issue,
                    self.assertRaisesRegex(
                        RuntimeActionObservationPublisherError,
                        "changed before capability issuance",
                    ),
                ):
                    _handle_connection(sensor, _config(fixture), timeout_seconds=0.5)
                issue.assert_not_called()
            finally:
                fixture.close()
                client.close()
                sensor.close()
                backend_sensor.close()
                backend_peer.close()

    def test_final_pidfd_failure_prevents_connection_and_issuance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            client, sensor = socket.socketpair()
            pidfd = os.open("/dev/null", os.O_RDONLY)
            try:
                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._peer_credentials",
                        return_value=fixture.peer,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.open_peer_pidfd",
                        return_value=pidfd,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.measure_runtime_process_profile",
                        side_effect=(fixture.attribution, fixture.attribution),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._read_frame",
                        return_value=fixture.envelope,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._open_protected_root",
                        return_value=os.dup(fixture.protected_fd),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.require_live_pidfd",
                        side_effect=RuntimeActionObservationPublisherError(
                            "runtime peer exited while observed"
                        ),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._connect_backend"
                    ) as connect_backend,
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3.issue_profiled_runtime_capability"
                    ) as issue,
                    self.assertRaisesRegex(
                        RuntimeActionObservationPublisherError,
                        "peer exited",
                    ),
                ):
                    _handle_connection(sensor, _config(fixture), timeout_seconds=0.5)
                connect_backend.assert_not_called()
                issue.assert_not_called()
            finally:
                fixture.close()
                client.close()
                sensor.close()

    def test_config_and_timeout_fail_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            config = _config(fixture)
            invalid = replace(config, capability_grant=b"{}")
            client, sensor = socket.socketpair()
            try:
                _validate_config(config)
                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._open_runtime_directory"
                    ) as open_runtime_directory,
                    self.assertRaisesRegex(
                        RuntimeActionObservationPublisherError,
                        "grant configuration is invalid",
                    ),
                ):
                    serve_runtime_action_observation_publisher_v3(invalid)
                open_runtime_directory.assert_not_called()

                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher_v3._peer_credentials"
                    ) as peer_credentials,
                    self.assertRaisesRegex(
                        RuntimeActionObservationPublisherError,
                        "timeout is invalid",
                    ),
                ):
                    _handle_connection(sensor, config, timeout_seconds=0)
                peer_credentials.assert_not_called()
            finally:
                fixture.close()
                client.close()
                sensor.close()


if __name__ == "__main__":
    unittest.main()
