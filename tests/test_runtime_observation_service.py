from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

from aragorn import runtime_observation_service as service
from aragorn.oci_worker_protocol import canonical_json

_RUNTIME = "sha256:" + "1" * 64
_SKILL = "sha256:" + "2" * 64
_SENSOR = "sha256:" + "3" * 64


def _binding(**changes: object) -> bytes:
    return canonical_json(
        {
            "schema": "aragorn/runtime-observation-binding/v1",
            "runtime_digest": _RUNTIME,
            "active_skill_digest": _SKILL,
            "sensor_digest": _SENSOR,
            **changes,
        }
    )


def _write_binding(root: Path, raw: bytes | None = None) -> Path:
    path = root.resolve() / "observation-binding"
    path.write_bytes(_binding() if raw is None else raw)
    path.chmod(0o400)
    return path


class RuntimeObservationServiceTests(unittest.TestCase):
    def test_run_resolves_fixed_identities_binding_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_binding(Path(temporary))
            observer_uid, observer_gid = os.geteuid(), os.getegid()
            runtime_uid, runtime_gid = observer_uid + 1, observer_gid + 1
            broker_uid = observer_uid + 2
            with (
                patch.object(service.sys, "platform", "linux"),
                patch.object(
                    service.pwd,
                    "getpwnam",
                    side_effect=(
                        SimpleNamespace(pw_uid=observer_uid, pw_gid=observer_gid),
                        SimpleNamespace(pw_uid=runtime_uid, pw_gid=runtime_gid),
                        SimpleNamespace(pw_uid=broker_uid),
                    ),
                ) as users,
                patch.object(
                    service.grp,
                    "getgrnam",
                    side_effect=(
                        SimpleNamespace(gr_gid=observer_gid),
                        SimpleNamespace(gr_gid=runtime_gid),
                    ),
                ) as groups,
                patch.object(service.os, "getgroups", return_value=[runtime_gid]),
                patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(path.parent)},
                ),
                patch.object(
                    service,
                    "serve_runtime_action_observation_publisher",
                ) as serve,
            ):
                self.assertEqual(service.main([str(path)]), 0)

            self.assertEqual(
                users.call_args_list,
                [
                    call("aragorn-sensor"),
                    call("aragorn-runtime"),
                    call("aragorn-broker"),
                ],
            )
            self.assertEqual(
                groups.call_args_list,
                [call("aragorn-sensor"), call("aragorn-runtime")],
            )
            config = serve.call_args.args[0]
            self.assertEqual(
                config.frontend_socket_path,
                Path("/run/aragorn-runtime-observation/sensor.sock"),
            )
            self.assertEqual(
                config.backend_socket_path,
                Path("/var/lib/aragorn-runtime-action/control/broker.sock"),
            )
            self.assertEqual(
                config.protected_root,
                Path("/var/lib/aragorn-runtime-action/protected"),
            )
            self.assertEqual(config.expected_observer_uid, observer_uid)
            self.assertEqual(config.expected_runtime_uid, runtime_uid)
            self.assertEqual(config.expected_broker_uid, broker_uid)
            self.assertEqual(config.expected_runtime_digest, _RUNTIME)
            self.assertEqual(config.expected_active_skill_digest, _SKILL)
            self.assertEqual(config.expected_sensor_digest, _SENSOR)

    def test_binding_is_exact_canonical_and_digest_pinned(self) -> None:
        invalid = (
            _binding(extra=True),
            _binding(schema="aragorn/runtime-observation-binding/v2"),
            _binding(sensor_digest="SHA256:" + "3" * 64),
            _binding() + b"\n",
        )
        for raw in invalid:
            with self.subTest(raw=raw[:80]), tempfile.TemporaryDirectory() as temporary:
                path = _write_binding(Path(temporary), raw)
                with self.assertRaisesRegex(
                    (service.RuntimeObservationServiceError, ValueError),
                    "invalid|digest",
                ):
                    service._read_binding(path, os.geteuid())

    def test_usage_platform_and_group_drift_fail_closed(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(service.main([]), 64)
        self.assertIn("usage:", stderr.getvalue())

        stderr = StringIO()
        with (
            patch.object(service.sys, "platform", "darwin"),
            redirect_stderr(stderr),
        ):
            self.assertEqual(service.main(["binding"]), 126)
        self.assertIn("Linux execution is required", stderr.getvalue())

        uid, gid = os.geteuid(), os.getegid()
        with (
            patch.object(
                service.pwd,
                "getpwnam",
                side_effect=(
                    SimpleNamespace(pw_uid=uid, pw_gid=gid),
                    SimpleNamespace(pw_uid=uid + 1, pw_gid=gid + 1),
                    SimpleNamespace(pw_uid=uid + 2),
                ),
            ),
            patch.object(
                service.grp,
                "getgrnam",
                side_effect=(
                    SimpleNamespace(gr_gid=gid),
                    SimpleNamespace(gr_gid=gid + 1),
                ),
            ),
            patch.object(service.os, "getgroups", return_value=[gid + 2]),
            self.assertRaisesRegex(
                service.RuntimeObservationServiceError,
                "supplementary groups",
            ),
        ):
            service._service_identities()


if __name__ == "__main__":
    unittest.main()
