from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import materialize_native_plugin_package_fixture as fixture


class NativePluginPackageFixtureTests(unittest.TestCase):
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
        item = {"manifest": {"skills": ["."]}, "ready": True}
        boundary = {
            "baseline_source": item,
            "candidate_source": item,
            "target_plugin": {"baseline": item},
        }
        action = {
            "status": "OBSERVED",
            "execution_error": None,
            "commands": [{"error": None}],
            "prerequisites": {"boundary_before": boundary},
            "observations": {
                "boundary_after": boundary,
                "native_force_reinstall": {"explicit_policy_block_observed": True},
                "state_invariants": {"catalog": True},
            },
        }
        with (
            patch.object(adapter.sys, "platform", "linux"),
            patch.object(adapter.os, "geteuid", return_value=992),
            patch.object(adapter.os, "getegid", return_value=992),
            patch.object(adapter.os, "getgroups", return_value=[992]),
            patch.dict(os.environ, {"OPENCLAW_GATEWAY_TOKEN": "inert-test-token"}),
            patch.object(
                adapter,
                "_base",
                return_value=SimpleNamespace(run_observation=lambda: action),
            ),
        ):
            observed = adapter.observe()
            self.assertEqual(observed["route_id"], adapter.ROUTE)
            self.assertEqual(observed["status"], "OBSERVED")
            self.assertTrue(
                all(value is False for value in observed["decision"].values())
            )
            action["observations"]["native_force_reinstall"][
                "explicit_policy_block_observed"
            ] = False
            with self.assertRaises(ValueError):
                adapter.observe()
            action["observations"]["native_force_reinstall"][
                "explicit_policy_block_observed"
            ] = True
            action["observations"]["state_invariants"]["catalog"] = False
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
