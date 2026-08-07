from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_action_service_v4 as broker_service
from aragorn import runtime_observation_service_v3 as sensor_service
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_capability_grant import GRANT_AUTHORITY, GRANT_SCHEMA
from aragorn.runtime_process_profile import PROFILE_AUTHORITY, PROFILE_SCHEMA

_RUNTIME = "sha256:" + "1" * 64
_SENSOR = "sha256:" + "3" * 64
_SKILL = "sha256:" + "4" * 64
_PROFILE_DOCUMENT = {
    "schema": PROFILE_SCHEMA,
    "authority": PROFILE_AUTHORITY,
    "runtime_digest": _RUNTIME,
    "executable_digest": "sha256:" + "5" * 64,
    "cgroup": "/system.slice/aragorn-openclaw-runtime.service",
    "skill_path": "/opt/aragorn/runtime-profile/SKILL.md",
}
_PROFILE = canonical_digest(_PROFILE_DOCUMENT)


def _credentials(root: Path) -> tuple[Path, Path, Path, bytes]:
    root = root.resolve()
    runtime = root / "runtime-binding"
    observation = root / "observation-binding"
    grant = root / "capability-grant"
    runtime.write_bytes(
        canonical_json(
            {
                "schema": "aragorn/runtime-action-runtime-binding/v2",
                "runtime_digest": _RUNTIME,
                "runtime_profile_digest": _PROFILE,
            }
        )
    )
    observation.write_bytes(
        canonical_json(
            {
                "schema": "aragorn/runtime-observation-binding/v2",
                "sensor_digest": _SENSOR,
                "runtime_profile": _PROFILE_DOCUMENT,
            }
        )
    )
    grant_bytes = canonical_json(
        {
            "schema": GRANT_SCHEMA,
            "authority": GRANT_AUTHORITY,
            "grant_id": "6" * 64,
            "source_manifest_digest": "sha256:" + "7" * 64,
            "install_context_digest": "sha256:" + "8" * 64,
            "runtime_profile_digest": _PROFILE,
            "runtime_digest": _RUNTIME,
            "active_skill_digest": _SKILL,
            "sensor_digest": _SENSOR,
            "policy_digest": "sha256:" + "9" * 64,
            "policy_version": 1,
            "operation_digest": "sha256:" + "a" * 64,
            "issued_at_unix": 1,
            "expires_at_unix": 2,
            "max_actions": 1,
        }
    )
    grant.write_bytes(grant_bytes)
    for path in (runtime, observation, grant):
        path.chmod(0o400)
    return runtime, observation, grant, grant_bytes


class RuntimeCapabilityServiceTests(unittest.TestCase):
    def test_services_receive_identical_grant_and_exact_nested_configs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime, observation, grant, grant_bytes = _credentials(Path(temporary))
            broker_identities = (
                os.geteuid(),
                os.geteuid() + 1,
                os.getegid() + 1,
                os.geteuid() + 2,
                os.getegid() + 2,
            )
            sensor_identities = (
                os.geteuid(),
                os.getegid(),
                os.geteuid() + 1,
                os.getegid() + 1,
                os.geteuid() + 2,
            )
            order: list[str] = []
            with (
                patch.object(broker_service.sys, "platform", "linux"),
                patch.object(
                    broker_service,
                    "_service_identities",
                    return_value=broker_identities,
                ),
                patch.object(sensor_service.sys, "platform", "linux"),
                patch.object(
                    sensor_service,
                    "_service_identities",
                    return_value=sensor_identities,
                ),
                patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(runtime.parent)},
                ),
                patch.object(
                    broker_service,
                    "initialize_runtime_capability_grant",
                    side_effect=lambda _config: order.append("initialize"),
                ) as initialize,
                patch.object(
                    broker_service,
                    "serve_runtime_action_broker_v4",
                    side_effect=lambda _config: order.append("serve-broker"),
                ) as serve_broker,
                patch.object(
                    sensor_service,
                    "serve_runtime_action_observation_publisher_v3",
                    side_effect=lambda _config: order.append("serve-sensor"),
                ) as serve_sensor,
            ):
                self.assertEqual(
                    broker_service.main([str(runtime), str(grant)]),
                    0,
                )
                self.assertEqual(
                    sensor_service.main([str(observation), str(grant)]),
                    0,
                )

        self.assertEqual(order, ["initialize", "serve-broker", "serve-sensor"])
        broker = serve_broker.call_args.args[0]
        sensor = serve_sensor.call_args.args[0]
        self.assertIs(broker, initialize.call_args.args[0])
        self.assertEqual(broker.capability_grant, grant_bytes)
        self.assertEqual(sensor.capability_grant, grant_bytes)
        self.assertEqual(broker.capability_grant, sensor.capability_grant)

        root = Path("/var/lib/aragorn-runtime-action")
        self.assertEqual(
            broker.grant_state_path,
            root / "control/capability-grant-state.json",
        )
        self.assertEqual(broker.broker.expected_runtime_profile_digest, _PROFILE)
        self.assertEqual(broker.broker.broker.expected_runtime_digest, _RUNTIME)
        self.assertEqual(
            broker.broker.profile_pending_path,
            root / "control/profile-pending.json",
        )
        self.assertEqual(
            broker.broker.profile_receipt_path,
            root / "control/profile-receipt.json",
        )
        self.assertEqual(
            broker.broker.broker.expected_peer_uid,
            broker_identities[3],
        )

        publisher = sensor.publisher
        self.assertEqual(publisher.expected_runtime_digest, _RUNTIME)
        self.assertEqual(publisher.expected_sensor_digest, _SENSOR)
        self.assertEqual(publisher.runtime_profile.digest, _PROFILE)
        self.assertEqual(
            publisher.frontend_socket_path,
            Path("/run/aragorn-runtime-observation/sensor.sock"),
        )
        self.assertEqual(
            publisher.backend_socket_path,
            root / "control/broker.sock",
        )
        self.assertEqual(publisher.expected_broker_uid, sensor_identities[4])

    def test_usage_platform_and_interrupt_are_bounded(self) -> None:
        cases = (
            (broker_service, "aragorn-runtime-action-service-v4"),
            (sensor_service, "aragorn-runtime-observation-service-v3"),
        )
        for service, command in cases:
            with self.subTest(service=command):
                stderr = StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(service.main([]), 64)
                self.assertIn(f"usage: {command}", stderr.getvalue())

                with (
                    patch.object(service.sys, "platform", "darwin"),
                    redirect_stderr(StringIO()),
                ):
                    self.assertEqual(service.main(["binding", "grant"]), 126)

                with (
                    patch.object(service, "_run", side_effect=KeyboardInterrupt),
                    redirect_stderr(StringIO()),
                ):
                    self.assertEqual(service.main(["binding", "grant"]), 0)

    def test_launchers_target_the_dynamic_services(self) -> None:
        root = Path(__file__).resolve().parents[1] / "packaging/libexec"
        action = (root / "aragorn-runtime-action-service-v4.py").read_text()
        observation = (root / "aragorn-runtime-observation-service-v3.py").read_text()
        self.assertIn("aragorn.runtime_action_service_v4", action)
        self.assertIn("aragorn.runtime_observation_service_v3", observation)


if __name__ == "__main__":
    unittest.main()
