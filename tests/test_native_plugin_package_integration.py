"""First checks for the new fixed plugin-package integration plumbing only."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import capture_runtime_native_plugin_package_check as capture
from scripts import materialize_native_plugin_package_fixture as fixture
from scripts import runtime_native_plugin_package_check as guest


class NativePluginPackageIntegrationTests(unittest.TestCase):
    def test_exact_native_version_rebinding_and_bounded_diagnostic(self):
        adapter = fixture._adapter()
        base = adapter._base()
        source = (fixture._DIRECTORY / adapter.BASE_NAME).read_bytes()
        rendered = source.split(adapter._MAIN)[0].replace(
            adapter._VERSION_ANCHOR,
            b'and version.get("stdout_excerpt", "") == '
            + repr(adapter.NATIVE_VERSION_STDOUT).encode("ascii"),
        )
        self.assertEqual(base.rendered_definitions_digest, adapter.digest(rendered))
        retained = json.loads(
            (
                capture._ROOT / adapter._VERSION_BINDING["retained_build_record"]
            ).read_bytes()
        )
        self.assertEqual(
            adapter.NATIVE_VERSION_STDOUT,
            retained["runtime_measurement"]["cli"]["stdout"],
        )
        self.assertEqual(
            guest._BUNDLE["adapter/" + guest._PROBE],
            (
                len((fixture._DIRECTORY / fixture._PROBE).read_bytes()),
                adapter.digest((fixture._DIRECTORY / fixture._PROBE).read_bytes()),
            ),
        )
        token = "c" * 64
        config = {
            "ready": True,
            "canonical_digest": base.EXPECTED_CONFIG_DIGEST,
            "file": {
                "digest": base.EXPECTED_CONFIG_DIGEST,
                "mode": "400",
                "uid": 992,
                "gid": 0,
            },
            "mount": {"ready": True},
            "install_policy": base.EXPECTED_INSTALL_POLICY,
            "plugin_policy": {
                "enabled": True,
                "target_allowlisted": False,
                "target_entry_present": False,
            },
            "must_not_escape": token,
        }
        policy_command = {
            "type": "file",
            "uid": 0,
            "gid": 0,
            "mode": "755",
            "nlink": 1,
            "size": 68480,
            "digest": base.EXPECTED_POLICY_COMMAND_DIGEST,
            "digest_error": None,
        }
        boundary = {
            "gateway_process": {
                "pid": 42,
                "cmdline": ["openclaw-gateway"],
                "effective_capabilities": "0000000000000000",
                "no_new_privileges": "1",
            },
            "config": config,
            "config_lock": {"exists": False},
            "discovery_roots": {"fixed": {"ready": True}},
            "route_input_mount": {"ready": True},
            "state_store": {"ready": True},
            "baseline_source": {"ready": True},
            "candidate_source": {"ready": True},
            "target_plugin": {
                "baseline": {"ready": True},
                "candidate": {"ready": False},
                "exact_gateway_owned_metadata": True,
                "parent_writable": True,
                "target_writable": True,
            },
            "install_policy_command": policy_command,
            "openclaw": {"digest": base.EXPECTED_OPENCLAW_DIGEST},
        }
        response = {
            "command": {"exit_code": 0, "error": None},
            "response": {"parsed": True, "value": {"pid": 42}},
        }
        plugin = {
            "command": {"exit_code": 0, "error": None},
            "response": {
                "parsed": True,
                "value": {
                    "plugin": {
                        "id": adapter.PLUGIN_ID,
                        "source": str(base.TARGET_ROOT / "index.js"),
                        "status": "disabled",
                        "version": "1.0.0",
                    }
                },
            },
        }
        version = adapter.NATIVE_VERSION_STDOUT
        calls = []

        def command(arguments):
            calls.append(arguments)
            if arguments == ["--version"]:
                return {
                    "exit_code": 0,
                    "error": None,
                    "stdout_excerpt": version,
                    "stderr_excerpt": token,
                }
            raw = (
                "blocked by install policy: " + base.EXPECTED_BLOCK_REASON + "\n"
            ).encode()
            return {
                "pid": 123,
                "error": None,
                "exit_code": 1,
                "signal": None,
                "_stderr": raw.decode(),
                "stderr_bytes": len(raw),
                "stderr_digest": adapter.digest(raw),
            }

        with (
            patch.object(base, "command", side_effect=command),
            patch.object(base, "gateway_call", return_value=response),
            patch.object(base, "plugin_inspection", return_value=plugin),
            patch.object(base, "boundary", return_value=boundary),
        ):
            observed = base.run_observation()
            self.assertIs(
                observed["observations"]["native_force_reinstall"][
                    "explicit_policy_block_observed"
                ],
                True,
            )
            self.assertIn(list(base.FORCE_ARGS), calls)
            calls.clear()
            version = "OpenClaw 2026.7.1 (7fa98d8)\n"
            refused = base.run_observation()
            self.assertEqual(refused["status"], "NOT_TESTED")
            self.assertNotIn(list(base.FORCE_ARGS), calls)
        diagnostic = adapter.diagnostic(
            "PREREQUISITES", "PREREQUISITE_MISSING", refused, base
        )
        raw = adapter.canonical(diagnostic) + b"\n"
        self.assertNotIn(token.encode(), raw)
        self.assertIs(diagnostic["checks"]["version_match"], False)
        self.assertIs(diagnostic["checks"]["config_match"], True)
        self.assertEqual(guest._decode_diagnostic(raw, token), diagnostic)
        p37b = types.SimpleNamespace(
            _GATEWAY_HOME=Path("/fixture/home"),
            _GATEWAY_STATE=Path("/fixture/state"),
            _GATEWAY_WORKSPACE=Path("/fixture/workspace"),
        )
        with (
            patch.object(
                guest.subprocess,
                "run",
                return_value=types.SimpleNamespace(
                    returncode=126, stdout=raw, stderr=b""
                ),
            ),
            self.assertRaises(guest.PluginFixtureError) as caught,
        ):
            guest._invoke(p37b, 42, token)
        self.assertEqual(
            str(caught.exception), "adapter PREREQUISITES/PREREQUISITE_MISSING"
        )
        self.assertNotIn(token, caught.exception.__notes__[0])
        for alteration in (
            {"unexpected": "raw output"},
            {"phase": "arbitrary path"},
            {"checks": {**diagnostic["checks"], "config_match": token}},
            {"exit_codes": {**diagnostic["exit_codes"], "version": True}},
        ):
            with self.assertRaises(guest.PluginFixtureError):
                guest._decode_diagnostic(
                    adapter.canonical(diagnostic | alteration) + b"\n", token
                )

    def test_bundle_matches_guest_pins_and_rejects_extra_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "route-input"
            root.mkdir()
            manifest = fixture.materialize(root / "plugin-package-skill-replacement")
            root.chmod(0o555)
            capture._audit_bundle(root, manifest)
            root.chmod(0o755)
            (root / "unexpected").mkdir()
            root.chmod(0o555)
            with self.assertRaisesRegex(RuntimeError, "inventory changed"):
                capture._audit_bundle(root, manifest)

    def test_fixed_launcher_and_secret_safe_output(self):
        document = {
            "schema": "aragorn/native-plugin-package-skill-replacement-denial/v1",
            "authority": "FIXED_INERT_PACKAGE_POLICY_DENIAL_NOT_ADMISSION_OR_CAMPAIGN_QUALIFICATION",
            "route_id": guest._ROUTE,
            "intended_inventory_route_id": "ADM-02/update/plugin-package-skill-replacement",
            "inventory_route_executed": False,
            "inventory_route_coverage": False,
            "plugin_update_lifecycle_executed": False,
            "status": "OBSERVED",
            "implementation_digest": guest._BUNDLE["adapter/" + guest._PROBE][1],
            "decision": {"run_eligible": False},
        }
        raw = (
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        token = "e" * 64
        p37b = types.SimpleNamespace(
            _GATEWAY_HOME=Path("/fixture/home"),
            _GATEWAY_STATE=Path("/fixture/state"),
            _GATEWAY_WORKSPACE=Path("/fixture/workspace"),
        )
        with patch.object(
            guest.subprocess,
            "run",
            return_value=types.SimpleNamespace(returncode=0, stdout=raw, stderr=b""),
        ) as run:
            result = guest._invoke(p37b, 42, token)
            argv = run.call_args.args[0]
            self.assertEqual(
                argv[:6],
                [
                    "/usr/bin/nsenter",
                    "--target",
                    "42",
                    "--mount",
                    "--",
                    "/usr/bin/setpriv",
                ],
            )
            self.assertEqual(argv[-1], str(guest._INPUT / "adapter" / guest._PROBE))
            self.assertIn("--reuid=992", argv)
            self.assertEqual(run.call_args.kwargs["timeout"], 120)
            self.assertNotIn(token, json.dumps(result))
            run.return_value.stdout = token.encode()
            with self.assertRaisesRegex(guest.PluginFixtureError, "output unsafe"):
                guest._invoke(p37b, 42, token)

    def test_remount_failure_unmounts_and_remains_failure(self):
        calls = []

        def command(argv):
            calls.append(argv)
            if "remount,bind,ro,nosuid,nodev,noexec" in argv:
                raise guest.PluginFixtureError("fixed input mount operation failed")

        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary).resolve() / "native-plugin-package-input"
            staged.mkdir()
            inherited = {"old-fixture": [1, 2, 3]}
            with (
                patch.object(guest, "_STAGED", staged),
                patch.object(
                    guest, "_underlying_input", return_value=inherited
                ) as underlying,
                patch.object(guest, "_mount_record", return_value=None),
                patch.object(guest, "_mount_command", side_effect=command),
                self.assertRaises(guest.PluginFixtureError),
            ):
                guest._mount_input()
            self.assertEqual(underlying.call_count, 2)
            self.assertEqual(
                calls[0], ["/usr/bin/mount", "--bind", str(staged), "/route-input"]
            )
        self.assertEqual(calls[-1], ["/usr/bin/umount", "/route-input"])

    def test_only_plugin_scenario_and_seed_before_activation(self):
        events = []
        setup = {
            "skill_digest": "skill",
            "provisioning": {"genesis_digest": "genesis"},
            "empty_store": {"receipts": []},
        }
        process = {"gateway": {"process": {"pid": 42}}}
        p37b = types.SimpleNamespace(_snapshot_effects=dict)
        cgroup = types.SimpleNamespace(observe=lambda _: {"status": "READY"})
        native = types.SimpleNamespace(
            setup_prior=types.SimpleNamespace(
                _require_fixture=lambda _: None, _installed=lambda _: {"denial": None}
            ),
            prior=types.SimpleNamespace(
                _processes=lambda _: process,
                _boot=lambda: "boot",
                _stop_fixture=lambda: events.append("stop") or {"stopped": True},
            ),
            _sources=lambda **_: {},
            _checked_startup_budget=lambda *_: {"TasksMax": 8},
            _fixture_token=lambda _: "e" * 64,
            _snapshot=lambda *_: {"receipts": []},
            _activate=lambda *_: events.append("activate"),
        )

        def prepare():
            events.append("prepare")
            native._activate(None, "e" * 64)
            return setup

        native._prepare = prepare
        mount = {"options": ["ro"]}
        with (
            patch.dict(
                sys.modules,
                {
                    "runtime_action_worker_openclaw_systemd_probe": p37b,
                    "runtime_native_cgroup_prerequisite": cgroup,
                },
            ),
            patch.object(guest, "_native", return_value=native),
            patch.object(guest, "_bundle", return_value={}),
            patch.object(
                guest,
                "_mount_input",
                side_effect=lambda: (
                    events.append("mount") or {"mounted": mount, "inherited_input": {}}
                ),
            ),
            patch.object(guest, "_underlying_input", return_value={}),
            patch.object(guest, "_mount_record", side_effect=[mount, None]),
            patch.object(
                guest, "_mount_command", side_effect=lambda _: events.append("unmount")
            ),
            patch.object(
                guest,
                "_seed_baseline",
                side_effect=lambda _: events.append("seed") or {"fixed": True},
            ),
            patch.object(
                guest, "_invoke", side_effect=lambda *_: events.append("plugin") or {}
            ) as invoke,
        ):
            result = guest._run("a" * 64, (os.geteuid(), os.getegid()))
        self.assertEqual(
            events,
            ["mount", "prepare", "seed", "activate", "plugin", "stop", "unmount"],
        )
        invoke.assert_called_once()
        self.assertIs(result["phase3_eligible"], False)
        self.assertIs(result["input_mount_removed"], True)
        self.assertEqual(result["empty_receipt_store_after"], {"receipts": []})

    def test_preflight_refusal_is_diagnosable_and_does_not_bootstrap(self):
        prepare, stop = Mock(), Mock()
        native = types.SimpleNamespace(
            setup_prior=types.SimpleNamespace(_require_fixture=lambda _: None),
            _sources=lambda **_: {},
            _prepare=prepare,
            prior=types.SimpleNamespace(_stop_fixture=stop),
        )
        cgroup = types.SimpleNamespace(
            observe=lambda _: {
                "status": "REFUSED",
                "failures": [{"reason": "PID_CONTROLLER_UNAVAILABLE"}],
            }
        )
        with (
            patch.dict(
                sys.modules,
                {
                    "runtime_action_worker_openclaw_systemd_probe": types.SimpleNamespace(),
                    "runtime_native_cgroup_prerequisite": cgroup,
                },
            ),
            patch.object(guest, "_native", return_value=native),
            self.assertRaises(guest.PluginFixtureError) as caught,
        ):
            guest._run("a" * 64, (os.geteuid(), os.getegid()))
        prepare.assert_not_called()
        stop.assert_called_once()
        self.assertEqual(guest._PHASE, "CGROUP_PREREQUISITES")
        self.assertIn("PID_CONTROLLER_UNAVAILABLE", caught.exception.__notes__[0])


if __name__ == "__main__":
    unittest.main()
