from __future__ import annotations

import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SHIM = _ROOT / "packaging/libexec/aragorn-runtime-action-worker-service.py"
_UNIT = _ROOT / "packaging/systemd/aragorn-runtime-action-worker.service"
_SYSUSERS = _ROOT / "packaging/systemd/aragorn-runtime-action-worker.sysusers"


class RuntimeActionWorkerPackagingTests(unittest.TestCase):
    def test_shim_and_identity_are_additive_and_fixed(self) -> None:
        shim = _SHIM.read_text(encoding="utf-8")
        self.assertIn('import_module("aragorn.runtime_action_worker").main()', shim)
        self.assertEqual(
            _SYSUSERS.read_text(encoding="utf-8"),
            "g aragorn-agent-gateway -\n"
            'u aragorn-agent-gateway - "Aragorn agent gateway state" '
            "/nonexistent /usr/sbin/nologin\n",
        )

    def test_worker_unit_has_only_the_bounded_relay_authority(self) -> None:
        unit = _UNIT.read_text(encoding="utf-8")
        for directive in (
            (
                "After=local-fs.target nss-user-lookup.target "
                "aragorn-runtime-lineage-capability-observation-publisher.service"
            ),
            "Requires=aragorn-runtime-lineage-capability-observation-publisher.service",
            "User=aragorn-runtime",
            "Group=aragorn-runtime",
            "SupplementaryGroups=aragorn-agent-gateway",
            "RuntimeDirectory=aragorn-runtime-action-worker",
            "RuntimeDirectoryMode=0711",
            "LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json",
            (
                "ExecStart=/usr/bin/python3.12 -I -S -B "
                "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py "
                "%d/worker-binding"
            ),
            "NoNewPrivileges=yes",
            "AmbientCapabilities=\n",
            "CapabilityBoundingSet=\n",
            "PrivateNetwork=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "ProtectSystem=strict",
            "PrivateMounts=yes",
            (
                "ReadOnlyPaths=/var/lib/aragorn-runtime-action/protected "
                "/var/lib/aragorn-protected/skills"
            ),
            "/var/lib/aragorn-runtime-action/control",
            "/var/lib/aragorn-runtime-action/staging",
            "/etc/aragorn/runtime-action-observation.json",
            "/etc/aragorn/runtime-capability-grant.json",
            "/var/lib/aragorn-openclaw-profile",
            "InaccessiblePaths=-/profile/config -/profile/state -/profile/workspace",
            "ReadOnlyPaths=-/opt/aragorn/runtime-profile",
        ):
            self.assertIn(directive, unit)
        self.assertEqual(
            [line for line in unit.splitlines() if line.startswith("LoadCredential=")],
            ["LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json"],
        )
        self.assertNotIn("SupplementaryGroups=aragorn-sensor", unit)
        self.assertNotIn("LoadCredential=observation-binding:", unit)
        self.assertNotIn("LoadCredential=capability-grant:", unit)
        self.assertNotIn("ReadWritePaths=/var/lib/aragorn-runtime-action", unit)


if __name__ == "__main__":
    unittest.main()
