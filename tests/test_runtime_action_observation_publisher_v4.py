from __future__ import annotations

import os
import socket
import tempfile
import time
import unittest
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_json
from aragorn.runtime_action_broker import (
    RuntimeActionBrokerError,
    _read_frame,
    _send_frame,
)
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from aragorn.runtime_action_observation_publisher_v4 import (
    RuntimeActionObservationPublisherV4Config,
    _handle_connection,
    _validate_config,
)
from aragorn.runtime_lineage_capability_issuer import (
    LINEAGE_ISSUANCE_AUTHORITY,
    LINEAGE_ISSUANCE_SCHEMA,
)
from tests.test_runtime_action_observation_publisher_v2 import _Fixture
from tests.test_runtime_action_observation_publisher_v3 import _grant


def _config(fixture: _Fixture) -> RuntimeActionObservationPublisherV4Config:
    return RuntimeActionObservationPublisherV4Config(
        publisher=fixture.config,
        capability_grant=_grant(fixture),
        protected_install_root=fixture.protected,
    )


class RuntimeActionObservationPublisherV4Tests(unittest.TestCase):
    def test_lineage_hold_covers_broker_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            config = _config(fixture)
            frontend_client, frontend_sensor = socket.socketpair()
            backend_sensor, backend_broker = socket.socketpair()
            pidfd = os.open("/dev/null", os.O_RDONLY)
            events: list[str] = []
            lineage = {
                "schema": "aragorn/verified-runtime-active-skill-lineage/v1",
                "active_record_digest": "sha256:" + "9" * 64,
            }
            wrapper = {
                "schema": LINEAGE_ISSUANCE_SCHEMA,
                "authority": LINEAGE_ISSUANCE_AUTHORITY,
                "lineage": lineage,
                "issuance": {
                    "schema": "aragorn/profiled-runtime-capability-issuance/v1"
                },
            }
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

            def broker() -> object:
                received = _read_frame(backend_broker, time.monotonic() + 1)
                events.append("broker-receive")
                _send_frame(
                    backend_broker, canonical_json(result), time.monotonic() + 1
                )
                events.append("broker-reply")
                backend_broker.shutdown(socket.SHUT_WR)
                return received

            def verify(*_args: object, **_kwargs: object) -> object:
                events.append("verify")
                return lineage

            @contextmanager
            def hold(*_args: object, **kwargs: object) -> Iterator[object]:
                self.assertEqual(kwargs["lineage_snapshot"], lineage)
                self.assertEqual(kwargs["protected_install_root"], fixture.protected)
                events.append("hold-enter")
                try:
                    yield wrapper
                finally:
                    events.append("hold-exit")

            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    broker_result = executor.submit(broker)
                    with (
                        patch(
                            "aragorn.runtime_action_observation_publisher_v4._peer_credentials",
                            side_effect=(
                                fixture.peer,
                                (202, fixture.broker_uid, fixture.broker_gid),
                            ),
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v4.open_peer_pidfd",
                            return_value=pidfd,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v4.measure_runtime_process_profile",
                            return_value=fixture.attribution,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v4.verify_runtime_active_skill_lineage",
                            side_effect=verify,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v4._open_protected_root",
                            return_value=os.dup(fixture.protected_fd),
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v4.require_live_pidfd"
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v4._connect_backend",
                            return_value=backend_sensor,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v4.time.time",
                            return_value=100.9,
                        ),
                        patch(
                            "aragorn.runtime_action_observation_publisher_v4.hold_profiled_runtime_capability_issuance",
                            side_effect=hold,
                        ),
                    ):
                        _handle_connection(
                            frontend_sensor,
                            config,
                            timeout_seconds=0.5,
                        )
                    frontend_sensor.shutdown(socket.SHUT_WR)
                    response = _read_frame(frontend_client, time.monotonic() + 1)
                    received = broker_result.result(timeout=1)
            finally:
                fixture.close()
                for connection in (
                    frontend_client,
                    frontend_sensor,
                    backend_sensor,
                    backend_broker,
                ):
                    connection.close()

        self.assertEqual(received, wrapper)
        self.assertEqual(response, result)
        self.assertEqual(
            events,
            ["verify", "hold-enter", "broker-receive", "broker-reply", "hold-exit"],
        )

    def test_lineage_failure_never_reads_or_connects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            client, sensor = socket.socketpair()
            pidfd = os.open("/dev/null", os.O_RDONLY)
            try:
                with (
                    patch(
                        "aragorn.runtime_action_observation_publisher_v4._peer_credentials",
                        return_value=fixture.peer,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v4.open_peer_pidfd",
                        return_value=pidfd,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v4.measure_runtime_process_profile",
                        return_value=fixture.attribution,
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v4.verify_runtime_active_skill_lineage",
                        side_effect=RuntimeActionBrokerError("lineage rejected"),
                    ),
                    patch(
                        "aragorn.runtime_action_observation_publisher_v4._read_frame"
                    ) as read_frame,
                    patch(
                        "aragorn.runtime_action_observation_publisher_v4._connect_backend"
                    ) as connect_backend,
                    patch(
                        "aragorn.runtime_action_observation_publisher_v4.hold_profiled_runtime_capability_issuance"
                    ) as issue,
                    self.assertRaisesRegex(
                        RuntimeActionObservationPublisherError,
                        "runtime observation relay failed",
                    ) as raised,
                ):
                    _handle_connection(sensor, _config(fixture), timeout_seconds=0.5)
                self.assertRegex(str(raised.exception.__cause__), "lineage rejected")
                read_frame.assert_not_called()
                connect_backend.assert_not_called()
                issue.assert_not_called()
            finally:
                fixture.close()
                client.close()
                sensor.close()

    def test_config_requires_a_bounded_absolute_protected_install_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            try:
                with self.assertRaisesRegex(
                    RuntimeActionObservationPublisherError,
                    "protected install root configuration is invalid",
                ):
                    _validate_config(
                        replace(
                            _config(fixture),
                            protected_install_root=Path("relative"),
                        )
                    )
                with self.assertRaisesRegex(
                    RuntimeActionObservationPublisherError,
                    "protected install root configuration is invalid",
                ):
                    _validate_config(
                        replace(
                            _config(fixture),
                            protected_install_root=Path("/"),
                        )
                    )
            finally:
                fixture.close()


if __name__ == "__main__":
    unittest.main()
