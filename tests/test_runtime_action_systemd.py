from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SYSTEMD = _ROOT / "packaging" / "systemd"
_SERVICE = _SYSTEMD / "aragorn-runtime-action-broker.service"
_PUBLISHER_SERVICE = (
    _SYSTEMD / "aragorn-runtime-observation-publisher.service"
)
_TMPFILES = _SYSTEMD / "aragorn-runtime-action.tmpfiles"
_SYSUSERS = _SYSTEMD / "aragorn-gateway.sysusers"
_LAUNCHER = (
    _ROOT / "packaging" / "libexec" / "aragorn-runtime-action-service.py"
)
_PUBLISHER_LAUNCHER = (
    _ROOT / "packaging" / "libexec" / "aragorn-runtime-observation-service.py"
)
_INSTALLER = _ROOT / "packaging" / "install-runtime-action-host.sh"


def _section(raw: str, name: str) -> list[str]:
    lines = raw.splitlines()
    start = lines.index(f"[{name}]") + 1
    result: list[str] = []
    for line in lines[start:]:
        if line.startswith("["):
            break
        if line and not line.startswith("#"):
            result.append(line)
    return result


class RuntimeActionSystemdTests(unittest.TestCase):
    def test_service_has_fixed_credential_boundary(self) -> None:
        raw = _SERVICE.read_text(encoding="utf-8")
        unit = _section(raw, "Unit")
        service = _section(raw, "Service")

        self.assertIn(
            "ConditionPathExists=/etc/aragorn/runtime-action-runtime.json",
            unit,
        )
        for name in (
            "policy",
            "revocations",
            "health",
            "observation",
            "state",
        ):
            self.assertIn(
                "ConditionPathExists=/var/lib/aragorn-runtime-action/"
                f"control/{name}.json",
                unit,
            )
        self.assertIn("Type=simple", service)
        self.assertIn("User=aragorn-broker", service)
        self.assertIn("Group=aragorn-runtime", service)
        self.assertIn("SupplementaryGroups=aragorn-sensor", service)
        self.assertIn(
            "LoadCredential=runtime-binding:"
            "/etc/aragorn/runtime-action-runtime.json",
            service,
        )
        self.assertIn(
            "InaccessiblePaths=/etc/aragorn/runtime-action-runtime.json",
            service,
        )
        self.assertEqual(
            [line for line in service if line.startswith("ExecStart=")],
            [
                "ExecStart=/usr/bin/python3.12 -I -S -B "
                "/usr/libexec/aragorn/aragorn-runtime-action-service.py "
                "%d/runtime-binding"
            ],
        )
        self.assertIn("WantedBy=multi-user.target", _section(raw, "Install"))
        self.assertFalse(
            (_SYSTEMD / "aragorn-runtime-action-broker.socket").exists()
        )
        launcher = _LAUNCHER.read_text(encoding="utf-8")
        self.assertIn('parents[2] / "lib" / "aragorn"', launcher)
        self.assertIn("from aragorn.runtime_action_service import main", launcher)

    def test_service_preserves_unix_broker_calls_and_limits_writes(self) -> None:
        service = _section(_SERVICE.read_text(encoding="utf-8"), "Service")
        required = {
            "NoNewPrivileges=yes",
            "AmbientCapabilities=",
            "CapabilityBoundingSet=",
            "PrivateNetwork=yes",
            "ProtectSystem=strict",
            "RestrictAddressFamilies=AF_UNIX",
            "KillSignal=SIGINT",
            "TasksMax=2",
            "MemoryMax=256M",
            "MemorySwapMax=0",
            "LimitNOFILE=64",
            "SystemCallFilter=~@mount @reboot @swap @raw-io @clock",
            "ReadWritePaths=/var/lib/aragorn-runtime-action",
        }
        self.assertTrue(required.issubset(service))
        self.assertEqual(
            [
                line
                for line in service
                if line.startswith(("ReadWritePaths=", "StateDirectory="))
            ],
            ["ReadWritePaths=/var/lib/aragorn-runtime-action"],
        )
        joined = "\n".join(service)
        for incompatible in (
            "SocketBindDeny=any",
            "@network-io",
            "DynamicUser=",
            "PrivateUsers=",
            "RuntimeDirectory=",
            "CAP_CHOWN",
        ):
            self.assertNotIn(incompatible, joined)

    def test_host_installer_stages_an_importable_isolated_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = {**os.environ, "DESTDIR": temporary}
            subprocess.run(
                ["sh", str(_INSTALLER)],
                check=True,
                cwd=_ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            staged = Path(temporary)
            launcher = (
                staged
                / "usr/libexec/aragorn/aragorn-runtime-action-service.py"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(launcher)],
                cwd="/",
                env={"PATH": "/usr/bin:/bin"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 64, result.stderr)
            self.assertIn("usage: aragorn-runtime-action-service", result.stderr)
            self.assertNotIn("ModuleNotFoundError", result.stderr)
            self.assertTrue(
                (
                    staged
                    / "usr/lib/systemd/system/aragorn-runtime-action-broker.service"
                ).is_file()
            )
            self.assertTrue(
                (
                    staged
                    / "usr/lib/systemd/system"
                    / "aragorn-runtime-observation-publisher.service"
                ).is_file()
            )
            for module in (
                "runtime_action_observation_publisher.py",
                "runtime_observation_service.py",
            ):
                self.assertTrue(
                    (staged / "usr/lib/aragorn/aragorn" / module).is_file()
                )
            publisher_launcher = (
                staged
                / "usr/libexec/aragorn/aragorn-runtime-observation-service.py"
            )
            self.assertTrue(publisher_launcher.is_file())
            publisher_result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(publisher_launcher)],
                cwd="/",
                env={"PATH": "/usr/bin:/bin"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(publisher_result.returncode, 64, publisher_result.stderr)
            self.assertIn(
                "usage: aragorn-runtime-observation-service",
                publisher_result.stderr,
            )
            self.assertNotIn("ModuleNotFoundError", publisher_result.stderr)

    def test_observation_publisher_has_distinct_identity_and_fixed_paths(
        self,
    ) -> None:
        raw = _PUBLISHER_SERVICE.read_text(encoding="utf-8")
        unit = _section(raw, "Unit")
        service = _section(raw, "Service")

        self.assertIn(
            "After=local-fs.target nss-user-lookup.target "
            "aragorn-runtime-action-broker.service",
            unit,
        )
        self.assertIn(
            "Requires=aragorn-runtime-action-broker.service",
            unit,
        )
        self.assertIn(
            "RequiresMountsFor=/var/lib/aragorn-runtime-action/control "
            "/var/lib/aragorn-runtime-action/protected",
            unit,
        )
        self.assertIn(
            "ConditionPathExists=/etc/aragorn/runtime-action-observation.json",
            unit,
        )
        self.assertIn("Type=simple", service)
        self.assertIn("User=aragorn-sensor", service)
        self.assertIn("Group=aragorn-sensor", service)
        self.assertIn("SupplementaryGroups=aragorn-runtime", service)
        self.assertIn("RuntimeDirectory=aragorn-runtime-observation", service)
        self.assertIn("RuntimeDirectoryMode=0750", service)
        self.assertIn(
            "LoadCredential=observation-binding:"
            "/etc/aragorn/runtime-action-observation.json",
            service,
        )
        self.assertEqual(
            [line for line in service if line.startswith("ExecStart=")],
            [
                "ExecStart=/usr/bin/python3.12 -I -S -B "
                "/usr/libexec/aragorn/aragorn-runtime-observation-service.py "
                "%d/observation-binding"
            ],
        )
        self.assertIn(
            "ReadOnlyPaths=/var/lib/aragorn-runtime-action/control "
            "/var/lib/aragorn-runtime-action/protected",
            service,
        )
        self.assertIn(
            "InaccessiblePaths=/etc/aragorn/runtime-action-observation.json "
            "/var/lib/aragorn-runtime-action/staging",
            service,
        )
        self.assertFalse(
            any(line.startswith("ReadWritePaths=") for line in service)
        )
        self.assertIn("WantedBy=multi-user.target", _section(raw, "Install"))

        required_hardening = {
            "NoNewPrivileges=yes",
            "AmbientCapabilities=",
            "CapabilityBoundingSet=",
            "PrivateNetwork=yes",
            "ProtectSystem=strict",
            "RestrictAddressFamilies=AF_UNIX",
            "TasksMax=2",
            "MemoryMax=256M",
            "MemorySwapMax=0",
            "LimitNOFILE=64",
            "SystemCallFilter=~@mount @reboot @swap @raw-io @clock",
        }
        self.assertTrue(required_hardening.issubset(service))
        joined = "\n".join(service)
        for incompatible in (
            "SocketBindDeny=any",
            "@network-io",
            "DynamicUser=",
            "PrivateUsers=",
            "CAP_CHOWN",
        ):
            self.assertNotIn(incompatible, joined)
        launcher = _PUBLISHER_LAUNCHER.read_text(encoding="utf-8")
        self.assertIn('parents[2] / "lib" / "aragorn"', launcher)
        self.assertIn(
            "from aragorn.runtime_observation_service import main",
            launcher,
        )

    def test_sysusers_provisions_fixed_broker_and_peer_identities(self) -> None:
        lines = _SYSUSERS.read_text(encoding="utf-8").splitlines()
        expected = {
            "g aragorn-runtime -",
            "g aragorn-sensor -",
            (
                'u aragorn-runtime - "Aragorn contained agent runtime" '
                "/nonexistent /usr/sbin/nologin"
            ),
            (
                'u aragorn-broker - "Aragorn runtime action broker" '
                "/nonexistent /usr/sbin/nologin"
            ),
            (
                'u aragorn-sensor - "Aragorn runtime observation sensor" '
                "/nonexistent /usr/sbin/nologin"
            ),
        }
        self.assertTrue(expected.issubset(lines))
        for prefix in (
            "g aragorn-runtime ",
            "g aragorn-sensor ",
            "u aragorn-runtime ",
            "u aragorn-broker ",
            "u aragorn-sensor ",
        ):
            self.assertEqual(sum(line.startswith(prefix) for line in lines), 1)

    def test_tmpfiles_provisions_only_fixed_durable_paths(self) -> None:
        lines = _TMPFILES.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            lines,
            [
                "d /var/lib/aragorn-runtime-action 0755 root root -",
                (
                    "d /var/lib/aragorn-runtime-action/control 0710 "
                    "aragorn-broker aragorn-runtime -"
                ),
                (
                    "d /var/lib/aragorn-runtime-action/protected 0710 "
                    "aragorn-broker aragorn-runtime -"
                ),
                (
                    "d /var/lib/aragorn-runtime-action/staging 0700 "
                    "aragorn-broker aragorn-broker -"
                ),
                (
                    "f /var/lib/aragorn-runtime-action/control/"
                    "broker.instance.lock 0600 aragorn-broker "
                    "aragorn-runtime -"
                ),
                (
                    "f /var/lib/aragorn-runtime-action/control/broker.lock "
                    "0600 aragorn-broker aragorn-runtime -"
                ),
            ],
        )
        self.assertFalse(any(".json" in line for line in lines))
        self.assertFalse(any(" /run/" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
