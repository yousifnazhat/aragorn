from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_action_service_v2 as service
from aragorn.oci_worker_protocol import canonical_json

_RUNTIME = "sha256:" + "1" * 64
_PROFILE = "sha256:" + "2" * 64


def _binding(**changes: object) -> bytes:
    return canonical_json(
        {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": _RUNTIME,
            "runtime_profile_digest": _PROFILE,
            **changes,
        }
    )


def _write_binding(root: Path, raw: bytes | None = None) -> Path:
    path = root.resolve() / "runtime-binding"
    path.write_bytes(_binding() if raw is None else raw)
    path.chmod(0o400)
    return path


class RuntimeActionServiceV2Tests(unittest.TestCase):
    def test_main_serves_fixed_profile_broker_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_binding(Path(temporary))
            identities = (
                os.geteuid(),
                os.geteuid() + 1,
                os.getegid() + 1,
                os.geteuid() + 2,
                os.getegid() + 2,
            )
            with (
                patch.object(service.sys, "platform", "linux"),
                patch.object(service, "_service_identities", return_value=identities),
                patch.dict(
                    os.environ,
                    {"CREDENTIALS_DIRECTORY": str(path.parent)},
                ),
                patch.object(service, "serve_runtime_action_broker_v2") as serve,
            ):
                self.assertEqual(service.main([str(path)]), 0)

        config = serve.call_args.args[0]
        root = Path("/var/lib/aragorn-runtime-action")
        self.assertEqual(config.expected_runtime_profile_digest, _PROFILE)
        self.assertEqual(
            config.profile_pending_path, root / "control/profile-pending.json"
        )
        self.assertEqual(
            config.profile_receipt_path, root / "control/profile-receipt.json"
        )
        self.assertEqual(config.broker.expected_runtime_digest, _RUNTIME)
        self.assertEqual(config.broker.expected_broker_uid, identities[0])
        self.assertEqual(config.broker.expected_runtime_uid, identities[1])
        self.assertEqual(config.broker.expected_runtime_gid, identities[2])
        self.assertEqual(config.broker.expected_peer_uid, identities[3])
        self.assertEqual(config.broker.expected_peer_gid, identities[4])
        self.assertEqual(config.broker.control_root, root / "control")

    def test_binding_is_exact_canonical_and_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = _write_binding(Path(temporary))
            self.assertEqual(
                service._read_runtime_binding(path, os.geteuid()),
                (_RUNTIME, _PROFILE),
            )

        invalid = (
            _binding(extra=True),
            canonical_json(
                {
                    "schema": "aragorn/runtime-action-runtime-binding/v1",
                    "runtime_digest": _RUNTIME,
                    "runtime_profile_digest": _PROFILE,
                }
            ),
            _binding(runtime_profile_digest="SHA256:" + "2" * 64),
            _binding() + b"\n",
        )
        for raw in invalid:
            with self.subTest(raw=raw[:80]), tempfile.TemporaryDirectory() as temporary:
                path = _write_binding(Path(temporary), raw)
                with self.assertRaisesRegex(
                    service.RuntimeActionServiceError,
                    "runtime profile binding credential is invalid",
                ):
                    service._read_runtime_binding(path, os.geteuid())

    def test_usage_platform_and_interrupt_are_bounded(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(service.main([]), 64)
        self.assertIn("usage: aragorn-runtime-action-service-v2", stderr.getvalue())

        stderr = StringIO()
        with (
            patch.object(service.sys, "platform", "darwin"),
            patch.object(service, "serve_runtime_action_broker_v2") as serve,
            redirect_stderr(stderr),
        ):
            self.assertEqual(service.main(["binding"]), 126)
        self.assertIn("Linux execution is required", stderr.getvalue())
        serve.assert_not_called()

        with (
            patch.object(service, "_run", side_effect=KeyboardInterrupt),
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["binding"]), 0)

    def test_systemd_unit_conflicts_with_v1_and_uses_v2_launcher(self) -> None:
        unit = (
            Path(__file__).resolve().parents[1]
            / "packaging/systemd/aragorn-runtime-profile-action-broker.service"
        ).read_text(encoding="utf-8")
        self.assertIn("Conflicts=aragorn-runtime-action-broker.service", unit)
        self.assertIn(
            "ExecStart=/usr/bin/python3.12 -I -S -B "
            "/usr/libexec/aragorn/aragorn-runtime-action-service-v2.py "
            "%d/runtime-binding",
            unit,
        )
        self.assertIn("LoadCredential=runtime-binding:", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("CapabilityBoundingSet=", unit)


if __name__ == "__main__":
    unittest.main()
