"""Only selected worktree closure is read; no test child is launched here."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import phase3_pipeline as pipeline


class PipelineSelectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for directory in ("benchmark", "scripts", "tests"):
            (self.root / directory).mkdir()
        (self.root / ".gitignore").write_text(".aragorn/\n")
        (self.root / pipeline.RUNNER).write_text("# inert fingerprint fixture\n")
        (self.root / "requirements-worker.lock").write_text("# inert lock\n")
        for name in ("selected", "dependency"):
            (self.root / f"tests/test_{name}.py").write_text("raise AssertionError('must not execute')\n")
        self.rows = [self.row("other"), self.row("selected", ["dependency"]), self.row("dependency")]
        self.write()
        self.launch = self.enterContext(patch.object(pipeline.subprocess, "Popen", side_effect=AssertionError("no child")))
        self.addCleanup(self.launch.assert_not_called)

    @staticmethod
    def row(name, needs=()):
        return {"id": name, "description": "inert selection fixture", "tests": [f"test_{name}"],
                "inputs": [f"tests/test_{name}.py"], "needs": list(needs), "timeout_seconds": 1}

    def write(self):
        (self.root / pipeline.REGISTRY).write_text(json.dumps({"schema": "aragorn/phase3-pipeline/v1", "stages": self.rows}))

    def test_status_reads_only_selected_transitive_inputs(self):
        report = pipeline.pipeline(self.root, selected=["selected"])
        self.assertEqual(list(report["stages"]), ["dependency", "selected"])
        self.assertEqual({name: row["status"] for name, row in report["stages"].items()},
                         {"dependency": "NEW", "selected": "BLOCKED_DEPENDENCY"})
        self.assertFalse((self.root / ".aragorn").exists())

    def test_run_and_post_fingerprint_ignore_missing_other_lane_inputs(self):
        executed = []

        def execute(root, attempt, stage, pin, contract, current_pin):
            self.assertEqual(current_pin(), pin)
            self.assertEqual(set(contract["dependencies"]), set(stage["needs"]))
            executed.append(stage["id"])
            return "PASS"

        with patch.object(pipeline, "_execute", side_effect=execute):
            report = pipeline.pipeline(self.root, run=True, selected=["selected"])
        self.assertEqual(executed, ["dependency", "selected"])
        self.assertEqual(set(report["stages"]), set(executed))
        self.assertFalse((self.root / ".aragorn/phase3-pipeline/other").exists())

    def test_all_selected_files_are_preflighted_before_state_or_execution(self):
        (self.root / "tests/test_selected.py").unlink()
        with patch.object(pipeline, "_execute") as execute, self.assertRaises(FileNotFoundError):
            pipeline.pipeline(self.root, run=True, selected=["selected"])
        execute.assert_not_called()
        self.assertFalse((self.root / ".aragorn").exists())

    def test_missing_dependency_and_default_all_selection_still_refuse(self):
        with self.assertRaises(FileNotFoundError):
            pipeline.pipeline(self.root)
        (self.root / "tests/test_dependency.py").unlink()
        with self.assertRaises(FileNotFoundError):
            pipeline.pipeline(self.root, selected=["selected"])
        self.assertFalse((self.root / ".aragorn").exists())

    def test_selected_source_substitution_refuses_before_launch(self):
        target = self.root / "tests/test_selected.py"
        target.unlink()
        target.symlink_to(self.root / "tests/test_dependency.py")
        with patch.object(pipeline, "_execute") as execute, self.assertRaises(OSError):
            pipeline.pipeline(self.root, run=True, selected=["selected"])
        execute.assert_not_called()
        self.assertFalse((self.root / ".aragorn").exists())

    def test_unselected_registry_schema_paths_and_cycles_remain_validated(self):
        for mutation in ("path", "cycle", "unknown", "selection"):
            with self.subTest(mutation=mutation):
                self.rows = [self.row("other"), self.row("selected", ["dependency"]), self.row("dependency")]
                selected = ["selected"]
                if mutation == "path":
                    self.rows[0]["inputs"].append("../outside")
                elif mutation == "cycle":
                    self.rows[0]["needs"] = ["other"]
                elif mutation == "unknown":
                    self.rows[0]["needs"] = ["absent"]
                else:
                    selected = ["unknown"]
                self.write()
                with self.assertRaises(pipeline.PipelineError):
                    pipeline.pipeline(self.root, selected=selected)
