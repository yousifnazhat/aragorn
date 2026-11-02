"""Only the new admission seals and inert successor staging; no service launch."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import stage_runtime_native_admission_profile as stage


class NativeAdmissionProfileTests(unittest.TestCase):
    def test_only_gateway_and_activator_change(self):
        original, replacements = stage._verified_payloads()
        gateway = stage._destination(stage._GATEWAY)[0]
        activator = stage._destination(stage._ACTIVATOR)[0]
        self.assertEqual(set(replacements), {gateway, activator})
        before, after = original[gateway][2], replacements[gateway][2]
        self.assertEqual(after.replace(stage._UNIT_SEALS, b""), before)
        script = replacements[activator][2]
        self.assertEqual(
            script.replace(stage._DIRECTORIES, b"")
            .replace(stage._CHECKS, b"")
            .replace(
                stage.base.overlay._digest(after)[7:].encode(),
                stage.base.overlay._digest(before)[7:].encode(),
            ),
            original[activator][2],
        )
        self.assertLess(
            script.index(stage._DIRECTORIES), script.index(b"systemctl start")
        )
        self.assertLess(script.index(stage._CHECKS), script.index(b"systemctl start"))
        parsed = subprocess.run(
            ["/bin/sh", "-n"], input=script, capture_output=True, timeout=3, check=False
        )
        self.assertEqual(parsed.returncode, 0, parsed.stderr)

    def test_required_seals_cover_parents_without_sealing_plugin_lifecycle(self):
        paths = stage._DISCOVERY_READ_ONLY_PATHS
        self.assertEqual(len(paths), 5)
        self.assertIn("/var/lib/aragorn-agent-gateway/workspace/.agents", paths)
        self.assertIn("/var/lib/aragorn-agent-gateway/home/.agents", paths)
        self.assertNotIn(b"ReadOnlyPaths=-", stage._UNIT_SEALS)
        self.assertNotIn(b"state/extensions", stage._UNIT_SEALS)
        self.assertNotIn(b"chmod", stage._DIRECTORIES)
        self.assertNotIn(b"chown", stage._DIRECTORIES)
        for parent in (b"workspace/.agents", b"home/.agents"):
            self.assertLess(
                stage._DIRECTORIES.index(parent + b" "),
                stage._DIRECTORIES.index(parent + b"/skills"),
            )
        self.assertIn(
            b'if [ ! -e "$path" ] && [ ! -L "$path" ]; then', stage._DIRECTORIES
        )
        self.assertIn(b'require_exact_directory "$path"', stage._DIRECTORIES)

    def test_real_inert_stage_preserves_inventory_and_false_claims(self):
        original, replacements = stage._verified_payloads()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "stage"
            report = stage.stage_runtime_native_admission_profile(output)
            self.assertEqual(report["schema"], stage._SCHEMA)
            self.assertEqual(report["authority"], stage._AUTHORITY)
            self.assertEqual(
                [len(report[key]) for key in ("files", "source_inputs", "directories")],
                [70, 85, 16],
            )
            self.assertEqual(report["worker_tasks_max"], 8)
            self.assertFalse(report["admission_qualified"])
            self.assertFalse(report["watchdog_timer_enabled"])
            stage.base._audit_tree(output, original | replacements)
            for row in report["new_dependencies"]:
                raw = (original | replacements)[stage._destination(row["name"])[0]][2]
                self.assertEqual(row["bytes"], len(raw))
                self.assertEqual(row["digest"], stage.base.overlay._digest(raw))
            with self.assertRaises(stage.RuntimeNativeAdmissionStageError):
                stage.stage_runtime_native_admission_profile(output)

    def test_changed_predecessor_or_render_anchor_refuses_before_staging(self):
        with (
            patch.object(stage, "_PREDECESSOR_PIN", (1, "sha256:" + "0" * 64)),
            self.assertRaises(ValueError),
        ):
            stage._verified_payloads()
        for field in ("_UNIT_ANCHOR", "_DIRECTORY_ANCHOR", "_CHECK_ANCHOR"):
            with (
                patch.object(stage, field, b"not an existing anchor"),
                self.assertRaises(stage.RuntimeNativeAdmissionStageError),
            ):
                stage._verified_payloads()

    def test_relative_or_symlink_destination_refuses_without_touching_target(self):
        with self.assertRaises(stage.RuntimeNativeAdmissionStageError):
            stage.stage_runtime_native_admission_profile(Path("relative"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "absent"
            alias = root / "alias"
            alias.symlink_to(target)
            with self.assertRaises(stage.RuntimeNativeAdmissionStageError):
                stage.stage_runtime_native_admission_profile(alias)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
