from __future__ import annotations

import json
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SYSTEMD = _ROOT / "packaging" / "systemd"
_SERVICE = _SYSTEMD / "aragorn-protected-install.service"
_TMPFILES = _SYSTEMD / "aragorn-gateway.tmpfiles"
_SYSUSERS = _SYSTEMD / "aragorn-gateway.sysusers"


def _section(raw: str, name: str) -> list[str]:
    marker = f"[{name}]"
    lines = raw.splitlines()
    start = lines.index(marker) + 1
    result: list[str] = []
    for line in lines[start:]:
        if line.startswith("["):
            break
        if line and not line.startswith("#"):
            result.append(line)
    return result


class ProtectedInstallSystemdTests(unittest.TestCase):
    def test_manual_oneshot_has_fixed_request_boundary(self) -> None:
        raw = _SERVICE.read_text(encoding="utf-8")
        unit = _section(raw, "Unit")
        service = _section(raw, "Service")

        self.assertNotIn("[Install]", raw)
        self.assertIn("Type=oneshot", service)
        self.assertIn("User=root", service)
        self.assertIn("Group=root", service)
        self.assertIn("Restart=no", service)
        self.assertIn(
            "LoadCredential=install-request:"
            "/run/aragorn-protected-install/request.json",
            service,
        )
        self.assertIn(
            "ConditionPathExists="
            "/etc/aragorn/protected-broker-release.json",
            unit,
        )
        self.assertIn(
            "ConditionPathExists="
            "/etc/aragorn/protected-install-revocations.json",
            unit,
        )

        starts = [
            line.removeprefix("ExecStart=")
            for line in service
            if line.startswith("ExecStart=")
        ]
        self.assertEqual(
            starts,
            [
                (
                    "/usr/bin/python3.14 -I -S -B "
                    "/usr/libexec/aragorn/"
                    "aragorn-protected-install-launcher.py -- "
                    "--github-live "
                    "--service-request %d/install-request "
                    "--analyzer-user aragorn-analyze "
                    "--analyzer-group aragorn-analyze "
                    "--cas-root /var/lib/aragorn-quarantine "
                    "--protected-root /var/lib/aragorn-protected/skills "
                    "--expected-broker-uid 0 "
                    "--revocation-file "
                    "/etc/aragorn/protected-install-revocations.json"
                )
            ],
        )
        command = starts[0]
        for forbidden in (
            "/bin/sh",
            "/bin/bash",
            "EnvironmentFile=",
            "$",
            "--manifest-digest",
            "--expected-owner",
            "--now-unix",
        ):
            self.assertNotIn(forbidden, command)

        siblings = {
            path.name
            for path in _SYSTEMD.glob("aragorn-protected-install.*")
        }
        self.assertEqual(siblings, {"aragorn-protected-install.service"})

    def test_service_denies_network_and_limits_persistent_writes(self) -> None:
        service = _section(
            _SERVICE.read_text(encoding="utf-8"),
            "Service",
        )
        for directive in (
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=CAP_SETGID CAP_SETUID",
            "AmbientCapabilities=CAP_SETGID CAP_SETUID",
            "RestrictSUIDSGID=yes",
            "PrivateNetwork=yes",
            "IPAddressDeny=any",
            "RestrictAddressFamilies=AF_UNIX",
            "SocketBindDeny=any",
            "SystemCallFilter=~@network-io @mount @reboot @swap @raw-io @clock",
            "ProtectSystem=strict",
            "PrivateTmp=yes",
            "InaccessiblePaths=/run/aragorn-protected-install/request.json",
            "LimitNOFILE=128",
            "MemorySwapMax=0",
            (
                "ReadWritePaths="
                "/var/lib/aragorn-quarantine "
                "/var/lib/aragorn-protected/skills"
            ),
        ):
            self.assertIn(directive, service)

        write_directives = [
            line
            for line in service
            if line.startswith(("ReadWritePaths=", "StateDirectory="))
        ]
        self.assertEqual(
            write_directives,
            [
                (
                    "ReadWritePaths="
                    "/var/lib/aragorn-quarantine "
                    "/var/lib/aragorn-protected/skills"
                )
            ],
        )
        self.assertNotIn("CAP_DAC_OVERRIDE", "\n".join(service))
        self.assertNotIn("CAP_DAC_READ_SEARCH", "\n".join(service))
        self.assertNotIn("CAP_CHOWN", "\n".join(service))

    def test_sysusers_provisions_dedicated_analyzer_identity(self) -> None:
        lines = set(_SYSUSERS.read_text(encoding="utf-8").splitlines())
        self.assertIn(
            (
                'u aragorn-analyze - "Aragorn protected analyzer" '
                "/nonexistent /usr/sbin/nologin"
            ),
            lines,
        )
        self.assertEqual(
            sum(line.startswith("u aragorn-analyze ") for line in lines),
            1,
        )

    def test_tmpfiles_provisions_only_fixed_root_owned_inputs(self) -> None:
        lines = set(_TMPFILES.read_text(encoding="utf-8").splitlines())
        revocations = (
            "f /etc/aragorn/protected-install-revocations.json "
            r'0400 root root - {\"context_ids\":[],'
            r'\"schema\":\"aragorn/protected-install-revocations/v1\"}'
        )
        for required in (
            "d /etc/aragorn 0700 root root -",
            "d /run/aragorn-protected-install 0700 root root -",
            "d /var/lib/aragorn-quarantine 0700 root root -",
            "d /var/lib/aragorn-protected 0700 root root -",
            "d /var/lib/aragorn-protected/skills 0700 root root -",
            revocations,
        ):
            self.assertIn(required, lines)
        payload = revocations.split(" ", 6)[-1].replace('\\"', '"')
        self.assertEqual(
            json.loads(payload),
            {
                "context_ids": [],
                "schema": "aragorn/protected-install-revocations/v1",
            },
        )
        self.assertEqual(
            payload,
            json.dumps(
                json.loads(payload),
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
        self.assertFalse(
            any(
                line.startswith("f /run/aragorn-protected-install/")
                for line in lines
            )
        )


if __name__ == "__main__":
    unittest.main()
