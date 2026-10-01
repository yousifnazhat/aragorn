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

        with (
            patch.object(guest, "_mount_record", return_value=None),
            patch.object(guest, "_mount_command", side_effect=command),
            self.assertRaises(guest.PluginFixtureError),
        ):
            guest._mount_input()
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
                side_effect=lambda: events.append("mount") or mount,
            ),
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
