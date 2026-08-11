from __future__ import annotations

import hashlib
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
_ACTIVATOR = _ROOT / "packaging/activate-runtime-action-worker-host.sh"


class RuntimeActionWorkerPackagingTests(unittest.TestCase):
    def test_worker_activator_local_digest_pins_match_sources(self) -> None:
        source = _ACTIVATOR.read_text(encoding="utf-8")
        block = source.split("done <<'EOF'\n", 1)[1].split("\nEOF", 1)[0]
        pins = {
            installed: digest
            for _mode, digest, installed in (
                line.split(" ", 2) for line in block.splitlines()
            )
            if installed not in {"/usr/local/bin/node", "/usr/local/bin/python3.12"}
        }
        self.assertEqual(len(pins), 36)
        for installed, expected in pins.items():
            name = Path(installed).name
            if installed == "/usr/libexec/aragorn/activate-runtime-capability-host.sh":
                candidate = _ROOT / "packaging/activate-runtime-capability-host.sh"
            elif installed.startswith("/usr/libexec/aragorn/"):
                candidate = _ROOT / "packaging/libexec" / name
            elif installed.startswith("/usr/lib/aragorn/aragorn/"):
                candidate = _ROOT / "src/aragorn" / name
            else:
                candidate = (
                    _ROOT / "packaging/openclaw/aragorn-runtime-action-worker" / name
                )
            self.assertEqual(
                hashlib.sha256(candidate.read_bytes()).hexdigest(), expected
            )

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

    def test_worker_activator_reuses_capability_route_and_fails_stop(self) -> None:
        activator = _ACTIVATOR.read_text(encoding="utf-8")
        self.assertIn(
            "base_activator=/usr/libexec/aragorn/activate-runtime-capability-host.sh",
            activator,
        )
        self.assertEqual(
            activator.count('"$base_activator"'),
            2,
        )
        for required in (
            "flock -n 9",
            "aragorn-runtime-capability-activation.lock",
            "ARAGORN_RUNTIME_ACTIVATION_LOCK_HELD=1",
            "armed=1",
            "trap rollback EXIT",
            "OPENCLAW_GATEWAY_TOKEN=*)",
            "gateway environment is not one canonical ASCII assignment",
            "runtime worker NSS group membership is unsafe",
            '"$gateway_uid" -eq 0',
            "installed unit digest changed",
            "e231978207dd27b71ef43449cf603ac424f6129f64c8a03dd0851ddf32503723",
            "32dea7dfdf5ccb9914c46ea2aadfc88a491d6eadba5bdb8b4982d473af1a0ebe",
            '"$gateway_unit" "$worker_unit" "$sensor_unit" "$broker_unit"',
            "previous runtime worker route remained active",
            "previous runtime worker endpoint remained present",
            'disable "$worker_unit" "$sensor_unit" "$broker_unit"',
            'start "$worker_unit"',
            'start "$gateway_unit"',
            'worker-binding:"$worker_binding"',
            'openclaw-config:"$gateway_config"',
            "EnvironmentFiles",
            "PrivateNetwork yes",
            "PrivateNetwork no",
            "runtime worker endpoint metadata is unsafe",
            'verify_process "$worker_unit"',
            'verify_process "$gateway_unit"',
            "CapEff:",
            "NoNewPrivs:",
            "gateway listener is not owned by its MainPID",
            "gateway retained boot authority",
            "--activation-preflight",
            "config validate --json",
            "aragorn-runtime-action-worker-preflight.XXXXXX",
            'chown "0:$gateway_gid" "$preflight_root"',
            'chmod 0710 "$preflight_root"',
            'install -o 0 -g "$gateway_gid" -m 0440',
            'mask "$gateway_unit" "$worker_unit"',
            "Aragorn runtime worker fail-stop verification failed",
            "/usr/bin/setpriv",
            "--clear-groups",
            "475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c",
            "c43a81b394e0b96b0950af94b937a79e777d7e0c815a0104f1ab45871f4afa64",
            "d0f433abba94a4560c26cb99017f56543b432e2fc3aa74e3374ee4e04addeeaf",
            'wait_socket "$broker_socket"',
            'wait_socket "$sensor_socket"',
            (
                '"/usr/lib/systemd/system/$checked_unit"|'
                '"/lib/systemd/system/$checked_unit"'
            ),
            'RestrictAddressFamilies "AF_INET AF_INET6 AF_UNIX"',
        ):
            self.assertIn(required, activator)
        self.assertEqual(activator.count("\nverify_unit \\"), 2)
        stop_route = (
            "/usr/bin/systemctl stop \\\n"
            '    "$gateway_unit" "$worker_unit" "$sensor_unit" "$broker_unit"'
        )
        self.assertLess(
            activator.index(stop_route),
            activator.index('require_root_secret "$gateway_config"'),
        )
        self.assertLess(
            activator.index(stop_route),
            activator.index("--activation-preflight"),
        )
        self.assertLess(
            activator.index("--activation-preflight"),
            activator.index('ARAGORN_RUNTIME_ACTIVATION_LOCK_HELD=1 "$base_activator"'),
        )
        self.assertLess(
            activator.index('"$base_activator"'),
            activator.index('start "$worker_unit"'),
        )
        self.assertLess(
            activator.index('start "$worker_unit"'),
            activator.index('start "$gateway_unit"'),
        )
        self.assertNotIn("enable --now", activator)
        self.assertNotIn("WantedBy=", activator)


if __name__ == "__main__":
    unittest.main()
