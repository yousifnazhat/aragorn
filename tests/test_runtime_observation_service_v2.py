from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_observation_service_v2 as service
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_process_profile import PROFILE_AUTHORITY, PROFILE_SCHEMA

_RUNTIME = "sha256:" + "1" * 64
_SENSOR = "sha256:" + "3" * 64


def _binding(**changes: object) -> bytes:
    return canonical_json(
        {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": _SENSOR,
            "runtime_profile": {
                "schema": PROFILE_SCHEMA,
                "authority": PROFILE_AUTHORITY,
                "runtime_digest": _RUNTIME,
                "executable_digest": "sha256:" + "5" * 64,
                "cgroup": "/system.slice/aragorn-openclaw-runtime.service",
                "skill_path": "/opt/aragorn/runtime-profile/SKILL.md",
            },
            **changes,
        }
    )


def _write_binding(root: Path, raw: bytes | None = None) -> Path:
    path = root.resolve() / "observation-binding"
    path.write_bytes(_binding() if raw is None else raw)
    path.chmod(0o400)
    return path


class RuntimeObservationServiceV2Tests(unittest.TestCase):
    def test_binding_is_exact_and_has_no_skill_digest_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_binding(Path(temporary))
            profile, sensor_digest = service._read_binding(path, os.geteuid())

        document = json.loads(_binding())
        self.assertEqual(profile.digest, canonical_digest(document["runtime_profile"]))
        self.assertEqual(profile.runtime_digest, _RUNTIME)
        self.assertEqual(sensor_digest, _SENSOR)
        self.assertNotIn("active_skill_digest", document)
        self.assertNotIn("active_skill_digest", document["runtime_profile"])

        invalid = (
            _binding(extra=True),
            _binding(schema="aragorn/runtime-observation-binding/v1"),
            _binding(sensor_digest="SHA256:" + "3" * 64),
            _binding() + b"\n",
        )
        for raw in invalid:
            with self.subTest(raw=raw[:80]), tempfile.TemporaryDirectory() as temporary:
                path = _write_binding(Path(temporary), raw)
                with self.assertRaises((ValueError, RuntimeError)):
                    service._read_binding(path, os.geteuid())

    def test_run_requires_v2_and_configures_profile_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_binding(Path(temporary))
            observer_uid, observer_gid = os.geteuid(), os.getegid()
            identities = (
                observer_uid,
                observer_gid,
                observer_uid + 1,
                observer_gid + 1,
                observer_uid + 2,
            )
            with (
                patch.object(service.sys, "platform", "linux"),
                patch.object(service, "_service_identities", return_value=identities),
                patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(path.parent)}),
                patch.object(
                    service,
                    "serve_runtime_action_observation_publisher_v2",
                ) as serve,
            ):
                self.assertEqual(service.main([str(path)]), 0)

        config = serve.call_args.args[0]
        self.assertEqual(config.expected_runtime_digest, _RUNTIME)
        self.assertEqual(config.expected_sensor_digest, _SENSOR)
        self.assertEqual(
            config.runtime_profile.cgroup,
            "/system.slice/aragorn-openclaw-runtime.service",
        )
        self.assertEqual(
            config.frontend_socket_path,
            Path("/run/aragorn-runtime-observation/sensor.sock"),
        )


if __name__ == "__main__":
    unittest.main()
