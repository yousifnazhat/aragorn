"""Bounded registry validation only; fixture test modules must never execute."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import phase3_pipeline as pipeline


class PipelineCapacityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "benchmark").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "tests/test_capacity_fixture.py").write_text(
            "raise AssertionError('registry validation executed a test module')\n"
        )
        self.launch = self.enterContext(
            mock.patch.object(
                pipeline.subprocess,
                "Popen",
                side_effect=AssertionError("registry validation launched a child"),
            )
        )
        self.addCleanup(self.launch.assert_not_called)

    @staticmethod
    def stages(count):
        return [
            {
                "id": f"stage-{index:03d}",
                "description": "Inert bounded registry validation",
                "tests": ["test_capacity_fixture"],
                "inputs": ["tests/test_capacity_fixture.py"],
                "needs": [f"stage-{index - 1:03d}"] if index else [],
                "timeout_seconds": 1,
            }
            for index in range(count)
        ]

    def write_registry(self, stages):
        (self.root / pipeline.REGISTRY).write_text(
            json.dumps({"schema": "aragorn/phase3-pipeline/v1", "stages": stages})
        )

    def test_128_stages_are_accepted_in_dependency_order_without_execution(self):
        stages = self.stages(128)
        self.write_registry(stages)
        index, ordered = pipeline.load_registry(self.root)
        expected = [stage["id"] for stage in stages]
        self.assertEqual(list(index), expected)
        self.assertEqual(ordered, expected)
        self.assertFalse((self.root / ".aragorn").exists())

    def test_129_stages_are_refused_without_execution(self):
        self.write_registry(self.stages(129))
        with self.assertRaisesRegex(pipeline.PipelineError, "invalid stage inventory"):
            pipeline.load_registry(self.root)

    def test_duplicate_stage_at_expanded_capacity_is_refused(self):
        stages = self.stages(128)
        stages[-1]["id"] = stages[0]["id"]
        self.write_registry(stages)
        with self.assertRaisesRegex(
            pipeline.PipelineError, "invalid/duplicate stage ID"
        ):
            pipeline.load_registry(self.root)

    def test_dependency_cycle_at_expanded_capacity_is_refused(self):
        stages = self.stages(128)
        stages[0]["needs"] = [stages[-1]["id"]]
        self.write_registry(stages)
        with self.assertRaisesRegex(pipeline.PipelineError, "dependency cycle"):
            pipeline.load_registry(self.root)


if __name__ == "__main__":
    unittest.main()
