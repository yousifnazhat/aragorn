from __future__ import annotations

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_UNIT = _ROOT / "packaging/systemd/aragorn-agent-gateway.service"


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


class AgentGatewayPackagingTests(unittest.TestCase):
    def test_unit_is_static_and_requires_the_worker(self) -> None:
        raw = _UNIT.read_text(encoding="utf-8")
        self.assertEqual(raw.count("[Unit]"), 1)
        self.assertEqual(raw.count("[Service]"), 1)
        self.assertNotIn("[Install]", raw)
        self.assertNotIn("WantedBy=", raw)

        unit = _section(raw, "Unit")
        self.assertIn(
            "After=local-fs.target nss-user-lookup.target "
            "aragorn-runtime-action-worker.service",
            unit,
        )
        self.assertEqual(
            [line for line in unit if line.startswith("Requires=")],
            ["Requires=aragorn-runtime-action-worker.service"],
        )
        self.assertEqual(
            [line for line in unit if line.startswith("ConditionPathExists=")],
            [
                "ConditionPathExists=/usr/local/bin/node",
                "ConditionPathExists=/runtime/lib/node_modules/openclaw/openclaw.mjs",
                "ConditionPathExists=/etc/aragorn/agent-gateway/openclaw.json",
                "ConditionPathExists=/etc/aragorn/agent-gateway/environment",
                (
                    "ConditionPathExists=/usr/lib/aragorn/openclaw/"
                    "aragorn-runtime-action-worker/openclaw.plugin.json"
                ),
                (
                    "ConditionPathExists=/usr/lib/aragorn/openclaw/"
                    "aragorn-runtime-action-worker/index.js"
                ),
                "ConditionPathExists=/var/lib/aragorn-agent-gateway/home",
                "ConditionPathExists=/var/lib/aragorn-agent-gateway/state",
                "ConditionPathExists=/var/lib/aragorn-agent-gateway/workspace",
            ],
        )

    def test_gateway_identity_command_and_environment_are_declared(self) -> None:
        raw = _UNIT.read_text(encoding="utf-8")
        service = _section(raw, "Service")
        self.assertIn("User=aragorn-agent-gateway", service)
        self.assertIn("Group=aragorn-agent-gateway", service)
        self.assertIn("SupplementaryGroups=", service)
        self.assertNotIn("SupplementaryGroups=aragorn-runtime", service)
        self.assertNotIn("SupplementaryGroups=aragorn-sensor", service)
        self.assertEqual(
            [line for line in service if line.startswith("LoadCredential=")],
            [
                (
                    "LoadCredential=openclaw-config:"
                    "/etc/aragorn/agent-gateway/openclaw.json"
                )
            ],
        )
        self.assertEqual(
            [line for line in service if line.startswith("ExecStart=")],
            [
                (
                    "ExecStart=/usr/local/bin/node "
                    "/runtime/lib/node_modules/openclaw/openclaw.mjs gateway run "
                    "--auth token --bind loopback --port 18789 --tailscale off"
                )
            ],
        )
        self.assertNotIn("--allow-unconfigured", raw)
        self.assertNotIn("--ws-log", raw)
        self.assertEqual(
            [line for line in service if line.startswith("EnvironmentFile=")],
            ["EnvironmentFile=/etc/aragorn/agent-gateway/environment"],
        )
        self.assertEqual(
            [line for line in service if line.startswith("Environment=")],
            [
                (
                    "Environment=HOME=/var/lib/aragorn-agent-gateway/home LANG=C "
                    "LC_ALL=C NO_COLOR=1 NO_PROXY=127.0.0.1,localhost "
                    "OPENCLAW_CONFIG_PATH=%d/openclaw-config "
                    "OPENCLAW_STATE_DIR=/var/lib/aragorn-agent-gateway/state "
                    "PATH=/usr/local/bin:/usr/bin:/bin TZ=UTC"
                )
            ],
        )
        self.assertIn(
            "WorkingDirectory=/var/lib/aragorn-agent-gateway/workspace",
            service,
        )
        for secret_name in (
            "OPENCLAW_GATEWAY_TOKEN=",
            "OPENAI_API_KEY=",
            "ANTHROPIC_API_KEY=",
            "GOOGLE_API_KEY=",
            "AWS_SECRET_ACCESS_KEY=",
        ):
            self.assertNotIn(secret_name, raw)
        self.assertIsNone(re.search(r"Environment=.*(?:TOKEN|SECRET|API_KEY)=", raw))

    def test_gateway_sees_only_its_state_and_relay_surface(self) -> None:
        service = _section(_UNIT.read_text(encoding="utf-8"), "Service")
        self.assertEqual(
            [line for line in service if line.startswith("ReadWritePaths=")],
            ["ReadWritePaths=/var/lib/aragorn-agent-gateway"],
        )
        self.assertEqual(
            [line for line in service if line.startswith("ReadOnlyPaths=")],
            [
                (
                    "ReadOnlyPaths=/usr/lib/aragorn/openclaw/"
                    "aragorn-runtime-action-worker /runtime "
                    "/run/aragorn-runtime-action-worker"
                ),
                "ReadOnlyPaths=-/opt/aragorn/runtime-profile",
            ],
        )
        inaccessible = "\n".join(
            line for line in service if line.startswith("InaccessiblePaths=")
        )
        for path in (
            "/etc/aragorn/agent-gateway",
            "/etc/aragorn/runtime-action-worker.json",
            "/etc/aragorn/runtime-action-runtime.json",
            "/etc/aragorn/runtime-action-observation.json",
            "/etc/aragorn/runtime-capability-grant.json",
            "/etc/aragorn/runtime-action-revocation-publication.json",
            "/var/lib/aragorn-runtime-action",
            "/var/lib/aragorn-protected",
            "/run/aragorn-runtime-observation",
            "-/etc/aragorn/openclaw-profile",
            "-/var/lib/aragorn-openclaw-profile",
            "-/opt/aragorn/openclaw/aragorn-runtime-action",
        ):
            self.assertIn(path, inaccessible)
        self.assertNotIn(
            "/opt/aragorn/openclaw/aragorn-runtime-action-worker", "\n".join(service)
        )

    def test_network_default_and_node_hardening_are_explicit(self) -> None:
        raw = _UNIT.read_text(encoding="utf-8")
        service = _section(raw, "Service")
        required = {
            "NoNewPrivileges=yes",
            "AmbientCapabilities=",
            "CapabilityBoundingSet=",
            "PrivateDevices=yes",
            "PrivateIPC=yes",
            "PrivateMounts=yes",
            "PrivateTmp=yes",
            "ProtectHome=yes",
            "ProtectProc=invisible",
            "ProtectSystem=strict",
            "ProcSubset=pid",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "RestrictNamespaces=yes",
            "RestrictRealtime=yes",
            "RestrictSUIDSGID=yes",
            "IPAddressDeny=any",
            "IPAddressAllow=localhost",
        }
        self.assertTrue(required.issubset(service))
        self.assertNotIn("PrivateNetwork=", raw)
        self.assertNotIn("MemoryDenyWriteExecute=", raw)
        self.assertNotIn("Restart=", raw)
        for limit in (
            "TimeoutStartSec=30s",
            "TimeoutStopSec=10s",
            "KillSignal=SIGTERM",
            "TasksMax=128",
            "MemoryMax=1G",
            "MemorySwapMax=0",
            "LimitNOFILE=256",
        ):
            self.assertIn(limit, service)

    def test_gateway_unit_does_not_reintroduce_authority_config(self) -> None:
        raw = _UNIT.read_text(encoding="utf-8")
        for forbidden_field in (
            "activeSkillDigest",
            "expectedBrokerUid",
            "expectedRuntimeGid",
            "expectedRuntimeUid",
            "expectedSensorUid",
            "policyDigest",
            "policyVersion",
            "protectedRoot",
            "runtimeDigest",
            "sensorSocketPath",
        ):
            self.assertNotIn(forbidden_field, raw)


if __name__ == "__main__":
    unittest.main()
