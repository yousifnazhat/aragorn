"""New local scheduling-cache behavior, using inert temporary test modules."""

from __future__ import annotations

import errno
import json
import os
import signal
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import phase3_pipeline as pipeline


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        for name in ("benchmark", "scripts", "tests", "src"):
            (self.root / name).mkdir()
        (self.root / ".gitignore").write_text(".aragorn/\n")
        (self.root / "requirements-worker.lock").write_text("# inert fixture\n")
        (self.root / pipeline.RUNNER).write_bytes(Path(pipeline.__file__).read_bytes())
        (self.root / "payload").write_text("original")
        self.stages = [self.stage("one")]
        self.module("one", "self.assertTrue(True)")
        self.registry()

    def stage(self, name, *, needs=(), timeout=5):
        return {
            "id": name,
            "description": "Inert local runner check",
            "tests": ["test_" + name],
            "inputs": ["tests/test_" + name + ".py", "payload"],
            "needs": list(needs),
            "timeout_seconds": timeout,
        }

    def module(self, name, body):
        (self.root / "tests" / ("test_" + name + ".py")).write_text(
            "import unittest\nfrom pathlib import Path\nimport time\nclass Inert(unittest.TestCase):\n    def test_inert(self):\n        "
            + body
            + "\n"
        )

    def registry(self):
        (self.root / pipeline.REGISTRY).write_text(
            json.dumps({"schema": "aragorn/phase3-pipeline/v1", "stages": self.stages})
        )

    def run_stage(self):
        return pipeline.pipeline(self.root, run=True)["stages"]

    def test_pass_cache_never_launches_child_or_keys_human_description(self):
        first = self.run_stage()["one"]
        self.assertEqual(first["status"], "PASS")
        self.assertEqual(first["argv"][1:5], ["-S", "-B", "-m", "unittest"])
        self.stages[0]["description"] = "Documentation-only change"
        self.stages.append(self.stage("other"))
        self.module("other", "self.fail('unselected stage must not execute')")
        self.registry()
        with mock.patch.object(pipeline.subprocess, "Popen") as launch:
            report = pipeline.pipeline(self.root, run=True, selected=("one",))
        launch.assert_not_called()
        self.assertEqual(report["stages"]["one"]["status"], "SKIP_PASS")
        self.assertEqual(report["stages"]["one"]["fingerprint"], first["fingerprint"])
        self.assertIn(
            "DEVELOPER_SCHEDULING_CACHE_NOT_QUALIFICATION", report["limitations"]
        )
        self.assertEqual(
            (self.root / ".aragorn/phase3-pipeline").stat().st_mode & 0o777, 0o700
        )

    def test_unchanged_failure_blocks_without_retry(self):
        self.module("one", "self.fail('intentional inert fixture failure')")
        self.assertEqual(self.run_stage()["one"]["status"], "FAIL")
        with mock.patch.object(pipeline.subprocess, "Popen") as launch:
            second = self.run_stage()
        launch.assert_not_called()
        self.assertEqual(second["one"]["status"], "BLOCKED_FAIL")

    def test_network_nodename_does_not_invalidate_toolchain_fingerprint(self):
        original = os.uname()
        expected, _ = pipeline.fingerprint(self.root, self.stages[0], {})
        with mock.patch.object(pipeline.subprocess, "Popen") as launch:
            for field in range(5):
                values = list(original)
                values[field] += "-changed"
                with mock.patch.object(
                    pipeline.os, "uname", return_value=os.uname_result(values)
                ):
                    actual, _ = pipeline.fingerprint(self.root, self.stages[0], {})
                with self.subTest(field=field):
                    if field == 1:
                        self.assertEqual(actual, expected)
                    else:
                        self.assertNotEqual(actual, expected)
        launch.assert_not_called()

    def test_denied_group_control_retains_refusal_without_product_launch(self):
        helper = mock.Mock(pid=123456789, returncode=None)
        with (
            mock.patch.object(
                pipeline.os,
                "killpg",
                side_effect=PermissionError(errno.EPERM, "denied"),
            ) as group_control,
            mock.patch.object(
                pipeline.subprocess, "Popen", return_value=helper
            ) as launch,
            self.assertRaisesRegex(
                pipeline.PipelineError, "prerequisite refused before test launch"
            ),
        ):
            self.run_stage()
        group_control.assert_called_once_with(helper.pid, signal.SIGTERM)
        launch.assert_called_once()
        self.assertEqual(launch.call_args.args[0], pipeline._preflight_argv())
        helper.terminate.assert_called_once_with()
        helper.wait.assert_called_once_with(timeout=2)
        self.assertEqual(list(self.root.rglob("started.json")), [])
        retained = list(self.root.rglob("preflight.json"))
        self.assertEqual(len(retained), 1)
        self.assertEqual(json.loads(retained[0].read_bytes())["status"], "REFUSED")
        with mock.patch.object(pipeline.subprocess, "Popen") as no_retry:
            self.assertEqual(self.run_stage()["one"]["status"], "BLOCKED_PREFLIGHT")
        no_retry.assert_not_called()

    def test_zombie_group_permission_error_requires_reap_then_absence(self):
        for final_state in ("absent", "present", "denied"):
            with self.subTest(final_state=final_state):
                child = mock.Mock(pid=123456789, returncode=None)
                original = PermissionError(errno.EPERM, "zombie group")
                calls = []

                def signal_group(
                    pid,
                    sig,
                    child=child,
                    calls=calls,
                    original=original,
                    final_state=final_state,
                ):
                    self.assertEqual(pid, child.pid)
                    calls.append(sig)
                    if sig == signal.SIGKILL:
                        raise original
                    if sig == 0:
                        self.assertEqual(child.returncode, -signal.SIGTERM)
                        if final_state == "absent":
                            raise ProcessLookupError(errno.ESRCH, "gone")
                        if final_state == "denied":
                            raise PermissionError(errno.EPERM, "still denied")
                    else:
                        self.assertIsNone(child.returncode)

                def reap(*, timeout, child=child):
                    self.assertEqual(timeout, 5)
                    child.returncode = -signal.SIGTERM
                    return child.returncode

                child.wait.side_effect = reap
                with (
                    mock.patch.object(pipeline.os, "killpg", side_effect=signal_group),
                    mock.patch.object(pipeline.time, "sleep"),
                ):
                    if final_state == "absent":
                        pipeline._stop_group(child)
                    else:
                        with self.assertRaises(PermissionError) as caught:
                            pipeline._stop_group(child)
                        self.assertIs(caught.exception, original)
                self.assertEqual(calls, [signal.SIGTERM, signal.SIGKILL, 0])
                child.wait.assert_called_once_with(timeout=5)

    def test_started_marker_blocks_crash_retry_and_missing_lock_refuses(self):
        row = pipeline.pipeline(self.root)["stages"]["one"]
        state = self.root / ".aragorn/phase3-pipeline"
        attempt = state / "one" / row["fingerprint"][7:]
        attempt.mkdir(parents=True, mode=0o700)
        for directory in (state, state / "one"):
            directory.chmod(0o700)
        with self.assertRaisesRegex(pipeline.PipelineError, "lacks its lock"):
            pipeline.pipeline(self.root)
        (state / "lock").touch(mode=0o600)
        fd = os.open(attempt, os.O_RDONLY | os.O_DIRECTORY)
        try:
            start = {
                "schema": "aragorn/phase3-pipeline-preflight-start/v1",
                "stage_id": "one",
                "fingerprint": row["fingerprint"],
                "helper_argv": pipeline._preflight_argv(),
            }
            pipeline._publish(fd, "preflight-started.json", start)
            pipeline._publish(
                fd,
                "preflight.json",
                {
                    "schema": "aragorn/phase3-pipeline-preflight-result/v1",
                    "start_digest": pipeline._digest(pipeline._canonical(start)),
                    "status": "PASS",
                    "error": None,
                },
            )
            pipeline._publish(
                fd,
                "started.json",
                {
                    "schema": "aragorn/phase3-pipeline-start/v1",
                    "stage_id": "one",
                    "fingerprint": row["fingerprint"],
                    "started_at_ns": 1,
                },
            )
        finally:
            os.close(fd)
        with mock.patch.object(pipeline.subprocess, "Popen") as launch:
            result = self.run_stage()
        launch.assert_not_called()
        self.assertEqual(result["one"]["status"], "BLOCKED_INTERRUPTED")

    def test_timeout_cleans_own_child_and_does_not_retry(self):
        self.stages[0]["timeout_seconds"] = 1
        self.module("one", "time.sleep(30)")
        self.registry()
        children = []
        real_popen = pipeline.subprocess.Popen

        def launch(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        with mock.patch.object(pipeline.subprocess, "Popen", side_effect=launch):
            self.assertEqual(self.run_stage()["one"]["status"], "TIMEOUT")
        self.assertEqual(len(children), 2)  # fixed preflight, then the inert test
        for child in children:
            self.assertIsNotNone(child.returncode)
            with self.assertRaises(ProcessLookupError):
                os.kill(child.pid, 0)
        with mock.patch.object(pipeline.subprocess, "Popen") as no_retry:
            self.assertEqual(self.run_stage()["one"]["status"], "BLOCKED_TIMEOUT")
        no_retry.assert_not_called()

    def test_changed_input_refuses_pass_and_blocks_dependent(self):
        self.module("one", "Path('payload').write_text('changed')")
        self.stages.append(self.stage("two", needs=("one",)))
        self.module("two", "self.fail('dependency must block execution')")
        self.registry()
        real_popen = pipeline.subprocess.Popen
        with mock.patch.object(
            pipeline.subprocess, "Popen", wraps=real_popen
        ) as launch:
            report = self.run_stage()
        self.assertEqual(launch.call_count, 2)  # fixed preflight plus one test stage
        self.assertEqual(report["one"]["status"], "INPUT_CHANGED")
        self.assertEqual(report["two"]["status"], "BLOCKED_DEPENDENCY")

    def test_invalid_dependency_and_missing_or_symlink_input_fail_closed(self):
        for needs, expected in (
            (["unknown"], "unknown dependency"),
            (["one"], "dependency cycle"),
        ):
            self.stages[0]["needs"] = needs
            self.registry()
            with self.assertRaisesRegex(pipeline.PipelineError, expected):
                pipeline.pipeline(self.root)
        self.stages[0]["needs"] = []
        self.registry()
        (self.root / "payload").unlink()
        with self.assertRaises(FileNotFoundError):
            pipeline.pipeline(self.root)
        (self.root / "payload").symlink_to(self.root / "requirements-worker.lock")
        with self.assertRaises(OSError):
            pipeline.pipeline(self.root)
        self.assertFalse((self.root / ".aragorn").exists())

    def test_state_symlink_and_changed_retained_log_refuse(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / ".aragorn").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.run_stage()
        (self.root / ".aragorn").unlink()
        # A preexisting shared state parent remains 0755; only our subtree is private.
        (self.root / ".aragorn").mkdir(mode=0o755)
        first = self.run_stage()["one"]
        self.assertEqual(first["status"], "PASS")
        self.assertEqual((self.root / ".aragorn").stat().st_mode & 0o777, 0o755)
        attempt = self.root / ".aragorn/phase3-pipeline/one" / first["fingerprint"][7:]
        log = attempt / "stdout.log"
        log.chmod(0o600)
        log.write_bytes(b"changed")
        log.chmod(0o400)
        with (
            mock.patch.object(pipeline.subprocess, "Popen") as launch,
            self.assertRaisesRegex(pipeline.PipelineError, "retained log changed"),
        ):
            self.run_stage()
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
