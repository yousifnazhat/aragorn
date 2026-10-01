"""Focused acceptance of the finite startup successor, without service activation."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import runtime_native_receipt_systemd_check as checker
from scripts import stage_runtime_native_startup_profile as stage


class NativeStartupProfileTests(unittest.TestCase):
    def test_watchdog_failure_stops_timer_before_other_fixture_services(self):
        calls = []

        def stop(label):
            calls.append(label)
            return {}

        with (
            patch.dict(
                sys.modules,
                {
                    "runtime_native_watchdog_check": SimpleNamespace(
                        stop_extra_units=lambda: stop("watchdog")
                    ),
                    "runtime_native_health_systemd_check": SimpleNamespace(
                        stop_extra_units=lambda: stop("health")
                    ),
                },
            ),
            patch.object(checker.setup_prior, "_require_fixture"),
            patch.object(checker, "_sources", return_value={}),
            patch.object(
                checker, "_prepare", side_effect=ValueError("fixture setup refused")
            ),
            patch.object(
                checker.prior, "_stop_fixture", side_effect=lambda: stop("native")
            ),
            self.assertRaises(ValueError),
        ):
            checker._run("c" * 64, health=True, startup_reserve=True, watchdog=True)
        self.assertEqual(calls, ["watchdog", "health", "native"])

    def test_only_two_payloads_change_and_keep_all_security_directives(self):
        original, replacements = stage._verified_payloads()
        self.assertEqual(len(replacements), 6)
        self.assertEqual(len(set(replacements) & set(original)), 2)
        worker = stage.health._destination(stage._WORKER)[0]
        before, after = original[worker][2], replacements[worker][2]
        self.assertEqual(after.replace(b"TasksMax=8\n", b"TasksMax=2\n"), before)
        activator = stage.health._destination(stage._ACTIVATOR)[0]
        script = replacements[activator][2]
        for name, pin in stage._ADDED_PINS.items():
            line = f"{stage._destination(name)[1]:o} {pin[1][7:]} /{stage._destination(name)[0]}\n".encode()
            self.assertEqual(script.count(line), 1)
            script = script.replace(line, b"")
        self.assertEqual(
            script.replace(stage._CHECK, b"")
            .replace(stage._POST_CHECK, b"")
            .replace(
                stage.base.overlay._digest(after)[7:].encode(),
                stage.base.overlay._digest(before)[7:].encode(),
            ),
            original[activator][2],
        )
        for name, (size, digest, mode) in checker._STARTUP_CODE.items():
            _, expected_mode, raw = replacements[name[1:]]
            self.assertEqual(
                (len(raw), stage.base.overlay._digest(raw), expected_mode),
                (size, "sha256:" + digest, mode),
            )
        result = subprocess.run(
            ["/bin/sh", "-n"], input=script, capture_output=True, check=False, timeout=3
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stage_audits_all_files_and_preserves_predecessor(self):
        original, replacements = stage._verified_payloads()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "stage"
            report = stage.stage_runtime_native_startup_profile(output)
            self.assertEqual(
                [
                    len(report[k])
                    for k in (
                        "files",
                        "source_inputs",
                        "new_dependencies",
                        "directories",
                    )
                ],
                [70, 84, 25, 16],
            )
            self.assertEqual(report["worker_tasks_max"], 8)
            stage.base._audit_tree(output, original | replacements)
            with self.assertRaises(stage.RuntimeNativeStartupStageError):
                stage.stage_runtime_native_startup_profile(output)
        with (
            patch.object(stage, "_PREDECESSOR_PIN", (1, "sha256:" + "0" * 64)),
            self.assertRaises(ValueError),
        ):
            stage._verified_payloads()

    def test_kernel_counter_binding_rejects_exhaustion_or_limit_drift(self):
        cgroup = (
            "/docker/"
            + "a" * 64
            + "/system.slice/aragorn-runtime-action-worker.service"
        )
        state = {
            "Id": checker.setup_prior._WORKER,
            "TasksMax": "8",
            "EffectiveTasksMax": "8",
            "ControlGroup": cgroup,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            leaf = root / cgroup[1:]
            leaf.mkdir(parents=True)
            current = leaf
            while current != root:
                for name, content in (
                    ("pids.current", "1\n"),
                    ("pids.max", "8\n"),
                    ("pids.events", "max 0\n"),
                ):
                    (current / name).write_text(content)
                current = current.parent

            def local(path):
                return root / path.removeprefix("/sys/fs/cgroup").lstrip("/")

            with (
                patch.object(
                    checker.response,
                    "_command",
                    side_effect=lambda *args, **kwargs: "".join(
                        f"{key}={value}\n" for key, value in state.items()
                    ).encode("ascii"),
                ),
                patch.object(checker, "Path", side_effect=local),
            ):
                result = checker._startup_budget()
                self.assertEqual(len(result["cgroup_counters"]), 4)
                for name, bad in (
                    ("pids.max", "max"),
                    ("pids.events", "max 1"),
                    ("pids.current", "9"),
                ):
                    path = leaf / name
                    before = path.read_text()
                    path.write_text(bad)
                    with self.assertRaises(checker._FixtureRefusal):
                        checker._startup_budget()
                    path.write_text(before)
                state["EffectiveTasksMax"] = "7"
                with self.assertRaises(checker._FixtureRefusal):
                    checker._startup_budget()


if __name__ == "__main__":
    unittest.main()
