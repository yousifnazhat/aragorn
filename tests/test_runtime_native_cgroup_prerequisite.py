"""Only the new read-only cgroup prerequisite behavior; no Docker execution."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import runtime_native_cgroup_prerequisite as subject
from scripts import runtime_native_receipt_systemd_check as checker

CONTAINER = "a" * 64


def _tree(root):
    owned = root / "docker" / CONTAINER
    worker = owned / "system.slice" / subject._WORKER
    worker.mkdir(parents=True)
    current = worker
    while True:
        for name, value in {
            "cgroup.controllers": "cpu memory pids\n",
            "cgroup.subtree_control": "pids\n",
            "cgroup.type": "domain\n",
            "pids.current": "1\n",
            "pids.max": "8\n" if current == worker else "max\n",
            "pids.events": "max 0\n",
        }.items():
            (current / name).write_text(value)
        if current == root:
            break
        current = current.parent
    return owned, worker


class NativeCgroupPrerequisiteTests(unittest.TestCase):
    def test_demand_driven_local_enablement_is_not_missing_host_delegation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            owned, worker = _tree(root)
            (owned / "cgroup.subtree_control").write_text("\n")
            before = subject._snapshot(root, CONTAINER, after_activation=False)
            self.assertEqual(before["status"], "READY")
            after = subject._snapshot(root, CONTAINER, after_activation=True)
            self.assertEqual(after["status"], "REFUSED")
            self.assertIn(
                {
                    "path": "/docker/" + CONTAINER,
                    "reason": "PIDS_NOT_ENABLED_FOR_CHILD",
                },
                after["failures"],
            )
            (root / "docker" / "cgroup.subtree_control").write_text("\n")
            blocked = subject._snapshot(root, CONTAINER, after_activation=False)
            self.assertEqual(blocked["status"], "REFUSED")
            self.assertFalse(blocked["controller_configuration_changed"])
            self.assertFalse(blocked["retry_performed"])
            self.assertTrue(worker.is_dir())

    def test_missing_worker_file_and_missing_directory_remain_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            _, worker = _tree(root)
            self.assertEqual(
                subject._snapshot(root, CONTAINER, after_activation=True)["status"],
                "READY",
            )
            (worker / "pids.max").unlink()
            missing = subject._snapshot(root, CONTAINER, after_activation=True)
            leaf = missing["hierarchy"][
                "/docker/" + CONTAINER + "/system.slice/" + subject._WORKER
            ]
            self.assertEqual(leaf["status"], "READ")
            self.assertEqual(leaf["unavailable"]["pids.max"], "ABSENT")
            for entry in worker.iterdir():
                entry.unlink()
            worker.rmdir()
            absent = subject._snapshot(root, CONTAINER, after_activation=True)
            self.assertEqual(absent["failures"][-1]["reason"], "CGROUP_ABSENT")

    def test_malformed_controller_data_is_bounded_and_not_printed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            owned, _ = _tree(root)
            (owned / "cgroup.controllers").write_text("pids arbitrary-secret!\n")
            report = subject._snapshot(root, CONTAINER, after_activation=False)
            self.assertEqual(report["status"], "REFUSED")
            self.assertNotIn("arbitrary-secret", str(report))
            with (
                patch.object(subject.sys, "platform", "darwin"),
                patch.object(subject, "_snapshot") as snapshot,
            ):
                with self.assertRaisesRegex(RuntimeError, "owned root Linux"):
                    subject.observe(CONTAINER)
                snapshot.assert_not_called()

    def test_post_activation_io_failure_gets_safe_diagnostics_without_retry(self):
        report = {
            "schema": "fixture",
            "status": "REFUSED",
            "failures": [{"reason": "PIDS_INTERFACE_UNAVAILABLE"}],
        }
        prerequisite = SimpleNamespace(observe=lambda container, **kwargs: report)
        with patch.object(
            checker,
            "_startup_budget",
            side_effect=FileNotFoundError("private diagnostic"),
        ) as budget:
            with self.assertRaises(checker._FixtureRefusal) as error:
                checker._checked_startup_budget(CONTAINER, prerequisite)
            budget.assert_called_once_with()
        self.assertIn("PIDS_INTERFACE_UNAVAILABLE", str(error.exception.__notes__))
        self.assertNotIn("private diagnostic", str(error.exception.__notes__))


if __name__ == "__main__":
    unittest.main()
