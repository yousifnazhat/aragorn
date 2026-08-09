from __future__ import annotations

import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SHIM = _ROOT / "packaging/libexec/aragorn-runtime-action-worker-service.py"
_UNIT = _ROOT / "packaging/systemd/aragorn-runtime-action-worker.service"
_SYSUSERS = _ROOT / "packaging/systemd/aragorn-runtime-action-worker.sysusers"
_DRIVER = (
    _ROOT
    / "benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs"
)
_DOCKERFILE = _ROOT / "benchmark/runtime-action-worker-openclaw-systemd/Dockerfile"
_CAPTURE = _ROOT / "scripts/capture_runtime_action_worker_openclaw_systemd.sh"
_PROBE = _ROOT / "scripts/runtime_action_worker_openclaw_systemd_probe.py"


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
        self.assertEqual(
            [
                line
                for line in unit.splitlines()
                if line.startswith("InaccessiblePaths=")
            ],
            [
                (
                    "InaccessiblePaths=/etc/aragorn/runtime-action-worker.json "
                    "/etc/aragorn/runtime-action-runtime.json "
                    "/etc/aragorn/runtime-action-observation.json "
                    "/etc/aragorn/runtime-capability-grant.json "
                    "/var/lib/aragorn-runtime-action/control "
                    "/var/lib/aragorn-runtime-action/staging"
                ),
                (
                    "InaccessiblePaths=-/etc/aragorn/agent-gateway "
                    "-/etc/aragorn/openclaw-profile "
                    "-/var/lib/aragorn-agent-gateway "
                    "-/var/lib/aragorn-openclaw-profile "
                    "-/var/lib/aragorn-gateway"
                ),
                "InaccessiblePaths=-/profile/config -/profile/state -/profile/workspace",
            ],
        )
        self.assertNotIn("SupplementaryGroups=aragorn-sensor", unit)
        self.assertNotIn("LoadCredential=observation-binding:", unit)
        self.assertNotIn("LoadCredential=capability-grant:", unit)
        self.assertNotIn("ReadWritePaths=/var/lib/aragorn-runtime-action", unit)

    def test_openclaw_driver_uses_replay_stable_ids_and_nested_result_authority(
        self,
    ) -> None:
        driver = _DRIVER.read_text(encoding="utf-8")
        for claim in (
            "const value = `aragorn${digest.slice(0, 32)}`;",
            "value.length <= 40",
            "const transportToolCallId = toolCallId;",
            "exact_gateway_session_key:",
            "exact_tool_call_id_identity:",
            "exact_wait_run_id:",
            "exact_worker_request_digest:",
            "expected_nested_relay_outcome:",
            'const OPENCLAW_DETAILS_SCHEMA = "aragorn/runtime-action-worker-openclaw-details/v1";',
            "const MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024;",
            "function transcriptToolResult(sessionId, rpcToolResult)",
            '!Object.hasOwn(rpcToolResult, "details")',
            "session transcript is not one bounded regular file",
            "matches.length === 1",
            "canonicalJson(message.content) === canonicalJson(rpcToolResult.content)",
            'exactKeys(details, ["schema", "source_result", "status"]',
            "canonicalJson(details.source_result) === canonicalJson(sourceResult)",
            "exact_rpc_history_shape_without_details:",
            "exact_transcript_rpc_tool_result_join:",
            "transcript_regular_nonsymlink_bounded:",
            "exact_openclaw_history_error_classification:",
            (
                "toolResult.isError === "
                '(transcript.message.details.status !== "completed")'
            ),
        ):
            self.assertIn(claim, driver)
        self.assertNotIn('toolCallId.replaceAll("_", "")', driver)
        self.assertNotIn("expectedToolResultError", driver)
        self.assertNotIn("exact_gateway_session_run_tool_correlation", driver)
        self.assertNotIn(
            "pinned_openclaw_resolved_execute_history_is_error_false_"
            "not_nested_relay_result_authority",
            driver,
        )
        dockerfile = _DOCKERFILE.read_text(encoding="utf-8")
        for digest in (
            "e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140",
            "71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
        ):
            self.assertIn(digest, dockerfile)

    def test_capture_binds_installers_and_publishes_atomically(self) -> None:
        dockerfile = _DOCKERFILE.read_text(encoding="utf-8")
        capture = _CAPTURE.read_text(encoding="utf-8")
        probe = _PROBE.read_text(encoding="utf-8")
        for path in (
            "packaging/install-runtime-capability-host.sh",
            "packaging/install-runtime-action-worker-host.sh",
        ):
            self.assertIn(path, dockerfile)
            self.assertEqual(capture.count(path), 2)
            self.assertIn(f"/src/{path}", probe)
        self.assertIn("os.link(source, destination, follow_symlinks=False)", capture)
        self.assertIn("source_stat.st_nlink != 1", capture)
        self.assertIn("os.fchmod(descriptor, 0o644)", capture)
        self.assertNotIn("os.open(\n    destination,", capture)


if __name__ == "__main__":
    unittest.main()
