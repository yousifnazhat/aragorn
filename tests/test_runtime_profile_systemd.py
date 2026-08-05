from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_UNIT = (
    _ROOT / "packaging/systemd/aragorn-runtime-profile-observation-publisher.service"
)
_BROKER_UNIT = _ROOT / "packaging/systemd/aragorn-runtime-profile-action-broker.service"
_INSTALLER = _ROOT / "packaging/install-runtime-profile-host.sh"


class RuntimeProfileSystemdTests(unittest.TestCase):
    def test_profile_sensor_drops_transient_identity_capabilities(self) -> None:
        unit = _UNIT.read_text(encoding="utf-8")
        required = {
            "User=aragorn-sensor",
            "Group=aragorn-sensor",
            "SupplementaryGroups=aragorn-runtime",
            "Conflicts=aragorn-runtime-observation-publisher.service",
            "NoNewPrivileges=yes",
            "AmbientCapabilities=CAP_SETGID CAP_SETUID CAP_SETPCAP",
            "CapabilityBoundingSet=CAP_SETGID CAP_SETUID CAP_SETPCAP",
            "ProtectProc=default",
            "ProtectControlGroups=yes",
            "ProtectSystem=strict",
            "ProcSubset=pid",
            "RestrictAddressFamilies=AF_UNIX",
        }
        self.assertTrue(required.issubset(unit.splitlines()))
        self.assertNotIn("ProtectProc=invisible", unit)
        self.assertNotIn("CAP_SYS_PTRACE", unit)
        for syscall in ("ptrace", "process_vm_readv", "process_vm_writev", "kcmp"):
            self.assertIn(syscall, unit)
        self.assertIn(
            "Requires=aragorn-runtime-profile-action-broker.service",
            unit,
        )

    def test_additive_installer_preserves_v1_and_stages_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            subprocess.run(
                ["sh", str(_INSTALLER)],
                check=True,
                cwd=_ROOT,
                env={**os.environ, "DESTDIR": temporary},
                capture_output=True,
            )
            staged = Path(temporary)
            for module in (
                "runtime_action_observation_publisher.py",
                "runtime_action_broker_v2.py",
                "runtime_process_profile.py",
                "runtime_action_observation_publisher_v2.py",
                "runtime_action_service_v2.py",
                "runtime_observation_service_v2.py",
            ):
                self.assertTrue((staged / "usr/lib/aragorn/aragorn" / module).is_file())
            launchers = {
                "aragorn-runtime-action-service-v2.py": (
                    "usage: aragorn-runtime-action-service-v2"
                ),
                "aragorn-runtime-observation-service-v2.py": (
                    "usage: aragorn-runtime-observation-service-v2"
                ),
            }
            for name, usage in launchers.items():
                launcher = staged / "usr/libexec/aragorn" / name
                result = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(launcher)],
                    check=False,
                    cwd="/",
                    env={"PATH": "/usr/bin:/bin"},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertIn(usage, result.stderr)
            self.assertTrue(
                (staged / "usr/lib/systemd/system" / _BROKER_UNIT.name).is_file()
            )


if __name__ == "__main__":
    unittest.main()
