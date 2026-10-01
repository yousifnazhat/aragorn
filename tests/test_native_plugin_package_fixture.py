from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import materialize_native_plugin_package_fixture as fixture


def _successor_fixture(adapter):
    """Inert unit input from retained predecessor shape, not a fresh observation."""
    path = (
        fixture._ROOT
        / "benchmark/evidence/runtime-action-worker-final-combined-v3-route-plugin-force-reinstall-systemd-p3-final-2026-08-28.json"
    )
    action = json.loads(path.read_bytes())["route_observation"]["document"]["action"]
    base = adapter._base()
    for location, key in (
        ("prerequisites", "plugin_before"),
        ("observations", "plugin_after"),
    ):
        plugin = action[location][key]["response"]["value"]["plugin"]
        plugin["id"] = adapter.PLUGIN_ID
        plugin["source"] = str(base.TARGET_ROOT / "index.js")
    for boundary in (
        action["prerequisites"]["boundary_before"],
        action["observations"]["boundary_after"],
    ):
        for item in (
            boundary["baseline_source"],
            boundary["candidate_source"],
            boundary["target_plugin"]["baseline"],
        ):
            item["manifest"]["skills"] = ["."]
    action["commands"][4]["argv"] = [base.NODE, base.OPENCLAW, *base.FORCE_ARGS]
    action["observations"]["native_force_reinstall"]["command"] = action["commands"][4]
    base.run_observation = lambda: action
    return action, base


class NativePluginPackageFixtureTests(unittest.TestCase):
    def test_successor_sqlite_shape_preserves_base_failure_and_rejects_mutation(self):
        adapter = fixture._adapter()
        action, base = _successor_fixture(adapter)
        original = copy.deepcopy(action)
        with (
            patch.object(adapter.sys, "platform", "linux"),
            patch.object(adapter.os, "geteuid", return_value=992),
            patch.object(adapter.os, "getegid", return_value=992),
            patch.object(adapter.os, "getgroups", return_value=[992]),
            patch.dict(os.environ, {"OPENCLAW_GATEWAY_TOKEN": "inert-test-token"}),
            patch.object(adapter, "_base", return_value=base),
        ):
            observed = adapter.observe()
        self.assertEqual(action, original)
        self.assertIs(
            observed["action"]["observations"]["native_force_reinstall"][
                "explicit_policy_block_observed"
            ],
            False,
        )
        self.assertIs(
            observed["action"]["observations"]["state_invariants"]["state_store"], False
        )
        self.assertIs(
            observed["explicit_policy_denial_observation"]["explicit_policy_denial"],
            True,
        )
        sqlite = observed["explicit_policy_denial_observation"]["sqlite_file_delta"]
        self.assertEqual(sqlite["delta_kind"], "ESTABLISHED_WAL_GROWTH_SHAPE")
        self.assertEqual(sqlite["wal_size_increase_bytes"], 32960)
        self.assertIs(sqlite["logical_database_unchanged_verified"], False)
        self.assertIs(sqlite["housekeeping_causation_verified"], False)
        self.assertIs(observed["inventory_route_coverage"], False)
        self.assertIs(observed["plugin_update_lifecycle_executed"], False)
        self.assertTrue(all(value is False for value in observed["decision"].values()))
        changed = copy.deepcopy(action)
        changed["observations"]["boundary_after"]["config"]["canonical_digest"] = (
            "sha256:" + "0" * 64
        )
        changed["observations"]["state_invariants"]["config"] = False
        with self.assertRaises(adapter.ProbeRefusal) as refusal:
            adapter._successor_denial(changed, base)
        self.assertEqual(
            refusal.exception.diagnostic["reason"], "PROTECTED_BOUNDARY_CHANGED"
        )
        self.assertIs(refusal.exception.diagnostic["invariant_checks"]["config"], False)
        for field, value in (("inode", 9), ("size", 4097)):
            changed = copy.deepcopy(action)
            state = changed["observations"]["boundary_after"]["state_store"]
            state["entries"][2][field] = value
            state["tree_digest"] = adapter.digest(adapter.canonical(state["entries"]))
            with self.assertRaises(adapter.ProbeRefusal) as refusal:
                adapter._successor_denial(changed, base)
            self.assertEqual(
                refusal.exception.diagnostic["reason"], "SQLITE_DELTA_UNRECOGNIZED"
            )

    def test_fixed_packages_declare_distinct_inert_skill_bytes_and_materialize(self):
        adapter = fixture._adapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "bundle"
            manifest = fixture.materialize(output)
            self.assertEqual(len(manifest["files"]), 10)
            self.assertTrue(
                all(value is False for value in manifest["decision"].values())
            )
            for record in manifest["files"]:
                path = output / record["name"]
                raw = path.read_bytes()
                self.assertEqual(
                    (len(raw), adapter.digest(raw)), (record["bytes"], record["digest"])
                )
                self.assertEqual(path.stat().st_mode & 0o777, 0o444)
            base = adapter._base()
            for name, version in (("baseline", "1.0.0"), ("candidate", "2.0.0")):
                package = output / (name + "-source")
                self.assertTrue(base.fixture_observation(package, name)["ready"])
                self.assertEqual(
                    json.loads((package / "openclaw.plugin.json").read_bytes())[
                        "skills"
                    ],
                    ["."],
                )
                self.assertEqual(
                    json.loads((package / "package.json").read_bytes())["version"],
                    version,
                )
            self.assertNotEqual(
                (output / "baseline-source/SKILL.md").read_bytes(),
                (output / "candidate-source/SKILL.md").read_bytes(),
            )
            with self.assertRaises(ValueError):
                fixture.materialize(output)

    def test_adapter_does_not_run_before_fixed_identity_and_requires_policy_denial(
        self,
    ):
        adapter = fixture._adapter()
        with patch.object(adapter, "_base") as load, self.assertRaises(ValueError):
            adapter.observe()
        load.assert_not_called()
        action, base = _successor_fixture(adapter)
        with (
            patch.object(adapter.sys, "platform", "linux"),
            patch.object(adapter.os, "geteuid", return_value=992),
            patch.object(adapter.os, "getegid", return_value=992),
            patch.object(adapter.os, "getgroups", return_value=[992]),
            patch.dict(os.environ, {"OPENCLAW_GATEWAY_TOKEN": "inert-test-token"}),
            patch.object(
                adapter,
                "_base",
                return_value=base,
            ),
        ):
            observed = adapter.observe()
            self.assertEqual(observed["route_id"], adapter.ROUTE)
            self.assertEqual(observed["status"], "OBSERVED")
            self.assertTrue(
                all(value is False for value in observed["decision"].values())
            )
            stderr_digest = action["commands"][4]["stderr_digest"]
            action["commands"][4]["stderr_digest"] = "sha256:" + "0" * 64
            with self.assertRaises(ValueError):
                adapter.observe()
            action["commands"][4]["stderr_digest"] = stderr_digest
            action["observations"]["state_invariants"]["config"] = False
            with self.assertRaises(ValueError):
                adapter.observe()

    def test_base_source_pin_and_fixture_variants_cannot_be_substituted(self):
        adapter = fixture._adapter()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "changed.py"
            path.write_bytes(b"raise AssertionError('must not execute')\n")
            with self.assertRaises(ValueError):
                adapter._read_base(path)
        with self.assertRaises(ValueError):
            adapter.fixture_files("3.0.0")


if __name__ == "__main__":
    unittest.main()
