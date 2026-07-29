from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import aragorn.analyze as analyze_module
from aragorn.analyze import (
    MAX_ANALYZER_OUTPUT_BYTES,
    AnalyzerResult,
    Observation,
    _parse_observations,
    run_analyzer,
)
from aragorn.policy import Policy, evaluate_policy

SUBJECT_DIGEST = "sha256:" + "a" * 64
CONFIG_DIGEST = "sha256:" + "b" * 64
EXECUTABLE_DIGEST = "sha256:" + hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
COMPLETE_CLOSURE = {"scope": "artifact_graph", "status": "complete"}


def observation(reason_code: str, severity: str) -> Observation:
    document = {
        "schema": "aragorn/observation/v1",
        "subject_digest": SUBJECT_DIGEST,
        "reason_code": reason_code,
        "severity": severity,
    }
    return Observation(
        schema=document["schema"],
        subject_digest=SUBJECT_DIGEST,
        reason_code=reason_code,
        severity=severity,
        document_json=json.dumps(document, sort_keys=True, separators=(",", ":")),
    )


def successful_result(*observations: Observation, name: str = "scanner") -> AnalyzerResult:
    return AnalyzerResult(
        name=name,
        version="1.0",
        config_digest=CONFIG_DIGEST,
        status="ok",
        observations=tuple(observations),
        returncode=0,
    )


class PolicyTests(unittest.TestCase):
    def test_clean_input_is_allowed(self) -> None:
        decision = evaluate_policy(
            Policy(required_analyzers=("scanner",)),
            closure=COMPLETE_CLOSURE,
            results=(successful_result(),),
        )

        self.assertEqual(decision.verdict, "ALLOW")
        self.assertEqual(decision.reason_codes, ())

    def test_hard_deny_has_precedence(self) -> None:
        decision = evaluate_policy(
            Policy(
                required_analyzers=("scanner",),
                hard_deny_reason_codes=frozenset({"KNOWN_BAD_DIGEST"}),
            ),
            closure=COMPLETE_CLOSURE,
            results=(
                successful_result(
                    observation("NEEDS_REVIEW", "critical"),
                    observation("KNOWN_BAD_DIGEST", "low"),
                ),
            ),
        )

        self.assertEqual(decision.verdict, "DENY")
        self.assertEqual(decision.reason_codes, ("KNOWN_BAD_DIGEST",))

    def test_review_threshold_includes_higher_severities(self) -> None:
        decision = evaluate_policy(
            Policy(required_analyzers=("scanner",), review_severities=frozenset({"high"})),
            closure=COMPLETE_CLOSURE,
            results=(successful_result(observation("CRITICAL_FINDING", "critical")),),
        )

        self.assertEqual(decision.verdict, "REVIEW")
        self.assertEqual(decision.reason_codes, ("CRITICAL_FINDING",))

    def test_required_analyzer_error_fails_closed(self) -> None:
        failed = AnalyzerResult(
            name="scanner",
            version="1.0",
            config_digest=CONFIG_DIGEST,
            status="error",
            error_code="TIMEOUT",
        )
        decision = evaluate_policy(
            Policy(required_analyzers=("scanner",)),
            closure=COMPLETE_CLOSURE,
            results=(failed,),
        )

        self.assertEqual(decision.verdict, "ERROR")
        self.assertEqual(
            decision.reason_codes,
            ("REQUIRED_ANALYZER_FAILED:scanner:TIMEOUT",),
        )

    def test_optional_configured_analyzer_error_fails_closed(self) -> None:
        failed = AnalyzerResult(
            name="extra-scanner",
            version="1.0",
            config_digest=CONFIG_DIGEST,
            status="error",
            error_code="TIMEOUT",
        )
        decision = evaluate_policy(
            Policy(required_analyzers=("scanner",)),
            closure=COMPLETE_CLOSURE,
            results=(successful_result(), failed),
        )

        self.assertEqual(decision.verdict, "ERROR")
        self.assertEqual(
            decision.reason_codes,
            ("ANALYZER_FAILED:extra-scanner:TIMEOUT",),
        )

    def test_source_tree_closure_cannot_be_allowed(self) -> None:
        decision = evaluate_policy(
            Policy(required_analyzers=("scanner",)),
            closure={"scope": "source_tree", "status": "complete"},
            results=(successful_result(),),
        )

        self.assertEqual(decision.verdict, "ERROR")
        self.assertEqual(decision.reason_codes, ("ARTIFACT_CLOSURE_INCOMPLETE",))

    def test_complete_closure_with_unresolved_artifacts_cannot_be_allowed(self) -> None:
        decision = evaluate_policy(
            Policy(required_analyzers=("scanner",)),
            closure={
                "scope": "artifact_graph",
                "status": "complete",
                "unresolved": ["https://attacker.invalid/second-stage"],
            },
            results=(successful_result(),),
        )

        self.assertEqual(decision.verdict, "ERROR")
        self.assertEqual(decision.reason_codes, ("ARTIFACT_CLOSURE_INCOMPLETE",))


class AnalyzerProcessTests(unittest.TestCase):
    def test_duplicate_observation_keys_are_rejected(self) -> None:
        raw = (
            '{"schema":"aragorn/observation/v1",'
            f'"subject_digest":"{SUBJECT_DIGEST}",'
            '"reason_code":"DUPLICATE_SEVERITY",'
            '"severity":"low","severity":"high"}\n'
        ).encode()

        observations, error = _parse_observations(raw, SUBJECT_DIGEST)

        self.assertEqual(observations, ())
        self.assertEqual(error[0] if error else None, "MALFORMED_OUTPUT")
        self.assertIn("duplicate JSON key", error[1] if error else "")

    def test_canonical_observation_size_is_bounded_before_retention(self) -> None:
        raw = json.dumps(
            {
                "schema": "aragorn/observation/v1",
                "subject_digest": SUBJECT_DIGEST,
                "reason_code": "EXPANDING_UNICODE",
                "severity": "low",
                "detail": "é" * 100,
            },
            ensure_ascii=False,
        ).encode()

        with patch.object(analyze_module, "_MAX_EVIDENCE_RECORD_BYTES", 128):
            observations, error = _parse_observations(raw, SUBJECT_DIGEST)

        self.assertEqual(observations, ())
        self.assertEqual(
            error[0] if error else None, "OBSERVATION_RECORD_LIMIT_EXCEEDED"
        )

    def test_observation_count_is_bounded_before_evidence_storage(self) -> None:
        line = json.dumps(
            {
                "schema": "aragorn/observation/v1",
                "subject_digest": SUBJECT_DIGEST,
                "reason_code": "REPEATED_FINDING",
                "severity": "low",
            }
        ).encode()
        observations, error = _parse_observations(
            b"\n".join([line] * 10_001), SUBJECT_DIGEST
        )

        self.assertEqual(observations, ())
        self.assertEqual(error[0] if error else None, "OBSERVATION_LIMIT_EXCEEDED")

    def test_json_request_jsonl_response_and_bounded_stderr(self) -> None:
        script = textwrap.dedent(
            """
            import json
            import os
            import sys

            request = json.load(sys.stdin)
            assert request["schema"] == "aragorn/analyzer-request/v1"
            assert set(request) == {"schema", "workspace", "subject_digest", "analyzer", "limits"}
            assert set(request["analyzer"]) == {
                "name", "version", "config_digest", "executable_digest"
            }
            assert request["analyzer"]["name"] == "test-scanner"
            assert request["analyzer"]["executable_digest"].startswith("sha256:")
            assert "ARAGORN_TEST_SECRET" not in os.environ
            assert os.getcwd() != request["workspace"]
            assert os.environ["HOME"] == os.getcwd()
            assert os.environ["PATH"] == os.defpath
            print(json.dumps({
                "schema": "aragorn/observation/v1",
                "subject_digest": request["subject_digest"],
                "reason_code": "OBSERVED_NETWORK",
                "severity": "high",
            }))
            print("diagnostic", file=sys.stderr)
            """
        )
        with tempfile.TemporaryDirectory() as workspace:
            with patch.dict(
                os.environ,
                {
                    "ARAGORN_TEST_SECRET": "must-not-leak",
                    "PATH": f"/tmp/aragorn-hostile-bin{os.pathsep}/usr/bin",
                },
            ):
                result = self.run_process(script, workspace=workspace)

        self.assertTrue(result.ok)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"OBSERVED_NETWORK", result.raw_stdout)
        self.assertEqual(result.raw_stderr, b"diagnostic\n")
        self.assertEqual(result.stderr, "diagnostic\n")
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].reason_code, "OBSERVED_NETWORK")

    def test_process_failures_are_explicit(self) -> None:
        mismatch = json.dumps(
            {
                "schema": "aragorn/observation/v1",
                "subject_digest": "sha256:" + "c" * 64,
                "reason_code": "WRONG_SUBJECT",
                "severity": "high",
            }
        )
        noncanonical_severity = textwrap.dedent(
            """
            import json
            import sys

            request = json.load(sys.stdin)
            print(json.dumps({
                "schema": "aragorn/observation/v1",
                "subject_digest": request["subject_digest"],
                "reason_code": "BAD_SEVERITY",
                "severity": "HIGH",
            }))
            """
        )
        noncanonical_reason = textwrap.dedent(
            """
            import json
            import sys

            request = json.load(sys.stdin)
            print(json.dumps({
                "schema": "aragorn/observation/v1",
                "subject_digest": request["subject_digest"],
                "reason_code": "not_canonical",
                "severity": "high",
            }))
            """
        )
        cases = (
            ("import sys; sys.exit(7)", 2.0, 4096, "NONZERO_EXIT"),
            ("import time; time.sleep(1)", 0.05, 4096, "TIMEOUT"),
            ("print('{')", 2.0, 4096, "MALFORMED_OUTPUT"),
            (
                "print('{\"schema\":\"aragorn/observation/v1\",\"score\":NaN}')",
                2.0,
                4096,
                "MALFORMED_OUTPUT",
            ),
            ("print('x' * 4096)", 2.0, 128, "OUTPUT_LIMIT_EXCEEDED"),
            (f"print({mismatch!r})", 2.0, 4096, "SUBJECT_DIGEST_MISMATCH"),
            (noncanonical_severity, 2.0, 4096, "MALFORMED_OUTPUT"),
            (noncanonical_reason, 2.0, 4096, "MALFORMED_OUTPUT"),
        )

        with tempfile.TemporaryDirectory() as workspace:
            for script, timeout, limit, expected_code in cases:
                with self.subTest(expected_code=expected_code):
                    result = self.run_process(
                        script,
                        workspace=workspace,
                        timeout_seconds=timeout,
                        output_limit_bytes=limit,
                    )
                    self.assertFalse(result.ok)
                    self.assertEqual(result.status, "error")
                    self.assertEqual(result.error_code, expected_code)
                    self.assertLessEqual(len(result.stderr.encode()), limit)

    def test_relative_analyzer_executable_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            result = run_analyzer(
                ("python3", "-c", "pass"),
                workspace=workspace,
                name="test-scanner",
                version="1.0",
                config_digest=CONFIG_DIGEST,
                executable_digest=EXECUTABLE_DIGEST,
                subject_digest=SUBJECT_DIGEST,
            )

        self.assertEqual(result.error_code, "INVALID_CONFIGURATION")
        self.assertIn("absolute path", result.error_message or "")

    def test_analyzer_child_uses_dedicated_identity_without_writable_scratch(
        self,
    ) -> None:
        analyzer_uid = 64001
        analyzer_gid = 64002
        observed_control: dict[str, object] = {}

        def reject_launch(*args: object, **kwargs: object) -> None:
            control_path = Path(str(kwargs["cwd"]))
            state = control_path.stat()
            observed_control["path"] = control_path
            observed_control["mode"] = stat.S_IMODE(state.st_mode)
            observed_control["uid"] = state.st_uid
            observed_control["gid"] = state.st_gid
            raise OSError("bounded launch probe")

        with (
            tempfile.TemporaryDirectory() as workspace,
            patch.object(
                analyze_module.subprocess,
                "Popen",
                side_effect=reject_launch,
            ) as popen,
        ):
            result = run_analyzer(
                (sys.executable, "-c", "pass"),
                workspace=workspace,
                name="test-scanner",
                version="1.0",
                config_digest=CONFIG_DIGEST,
                executable_digest=EXECUTABLE_DIGEST,
                subject_digest=SUBJECT_DIGEST,
                run_as_uid=analyzer_uid,
                run_as_gid=analyzer_gid,
            )

        self.assertEqual(result.error_code, "LAUNCH_FAILED")
        control_path = Path(popen.call_args.kwargs["cwd"])
        self.assertEqual(observed_control["path"], control_path)
        self.assertEqual(observed_control["mode"], 0o555)
        self.assertEqual(observed_control["uid"], os.geteuid())
        self.assertEqual(observed_control["gid"], os.getegid())
        self.assertFalse(control_path.exists())
        self.assertEqual(popen.call_args.kwargs["env"]["HOME"], "/nonexistent")
        self.assertEqual(popen.call_args.kwargs["user"], analyzer_uid)
        self.assertEqual(popen.call_args.kwargs["group"], analyzer_gid)
        self.assertEqual(popen.call_args.kwargs["extra_groups"], ())
        self.assertEqual(popen.call_args.kwargs["umask"], 0o077)

    def test_launch_interrupt_removes_uid_drop_control_directory(self) -> None:
        observed_control_path: Path | None = None

        def interrupt_launch(*args: object, **kwargs: object) -> None:
            nonlocal observed_control_path
            observed_control_path = Path(str(kwargs["cwd"]))
            raise KeyboardInterrupt

        with (
            tempfile.TemporaryDirectory() as workspace,
            patch.object(
                analyze_module.subprocess,
                "Popen",
                side_effect=interrupt_launch,
            ),
        ):
            with self.assertRaises(KeyboardInterrupt):
                run_analyzer(
                    (sys.executable, "-c", "pass"),
                    workspace=workspace,
                    name="test-scanner",
                    version="1.0",
                    config_digest=CONFIG_DIGEST,
                    executable_digest=EXECUTABLE_DIGEST,
                    subject_digest=SUBJECT_DIGEST,
                    run_as_uid=64001,
                    run_as_gid=64002,
                )

        self.assertIsNotNone(observed_control_path)
        assert observed_control_path is not None
        self.assertFalse(observed_control_path.exists())

    def test_workspace_module_is_not_imported_as_analyzer_code(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            marker = Path(workspace) / "executed"
            (Path(workspace) / "workspace_shadow.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            result = run_analyzer(
                (sys.executable, "-m", "workspace_shadow"),
                workspace=workspace,
                name="test-scanner",
                version="1.0",
                config_digest=CONFIG_DIGEST,
                executable_digest=EXECUTABLE_DIGEST,
                subject_digest=SUBJECT_DIGEST,
                timeout_seconds=2.0,
            )

            self.assertFalse(marker.exists())
            self.assertEqual(result.error_code, "NONZERO_EXIT")

    def test_oversized_identity_is_rejected_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            result = run_analyzer(
                (sys.executable, "-c", "pass"),
                workspace=workspace,
                name="x" * 257,
                version="1.0",
                config_digest=CONFIG_DIGEST,
                executable_digest=EXECUTABLE_DIGEST,
                subject_digest=SUBJECT_DIGEST,
                timeout_seconds=0.05,
            )

        self.assertEqual(result.error_code, "INVALID_CONFIGURATION")

    def test_output_limit_cannot_exceed_evidence_record_limit(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            result = run_analyzer(
                (sys.executable, "-c", "pass"),
                workspace=workspace,
                name="test-scanner",
                version="1.0",
                config_digest=CONFIG_DIGEST,
                executable_digest=EXECUTABLE_DIGEST,
                subject_digest=SUBJECT_DIGEST,
                output_limit_bytes=MAX_ANALYZER_OUTPUT_BYTES + 1,
            )

        self.assertEqual(result.error_code, "INVALID_CONFIGURATION")
        self.assertIn("between 1 and", result.error_message or "")

    def test_keyboard_interrupt_terminates_process_and_removes_control_directory(
        self,
    ) -> None:
        real_popen = subprocess.Popen
        captured: dict[str, object] = {"interrupted": False}

        def launch(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            original_wait = process.wait

            def interrupted_wait(timeout: float | None = None) -> int:
                if not captured["interrupted"]:
                    captured["interrupted"] = True
                    raise KeyboardInterrupt
                return original_wait(timeout=timeout)

            process.wait = interrupted_wait  # type: ignore[method-assign]
            captured["process"] = process
            captured["control"] = kwargs["cwd"]
            return process

        with tempfile.TemporaryDirectory() as workspace:
            with patch.object(analyze_module.subprocess, "Popen", side_effect=launch):
                with self.assertRaises(KeyboardInterrupt):
                    self.run_process(
                        "import sys, time; sys.stdin.read(); time.sleep(60)",
                        workspace=workspace,
                    )

        process = captured["process"]
        self.assertIsInstance(process, subprocess.Popen)
        self.assertIsNotNone(process.poll())  # type: ignore[union-attr]
        self.assertFalse(Path(captured["control"]).exists())

    def test_failed_post_timeout_reap_is_an_explicit_error(self) -> None:
        real_popen = subprocess.Popen
        captured: dict[str, object] = {"wait_calls": 0}

        def launch(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            original_wait = process.wait

            def delayed_reap(timeout: float | None = None) -> int:
                captured["wait_calls"] = int(captured["wait_calls"]) + 1
                if int(captured["wait_calls"]) <= 2:
                    raise subprocess.TimeoutExpired(process.args, timeout)
                return original_wait(timeout=timeout)

            process.wait = delayed_reap  # type: ignore[method-assign]
            captured["process"] = process
            return process

        with tempfile.TemporaryDirectory() as workspace:
            with patch.object(analyze_module.subprocess, "Popen", side_effect=launch):
                result = self.run_process(
                    "import sys, time; sys.stdin.read(); time.sleep(60)",
                    workspace=workspace,
                    timeout_seconds=0.01,
                )

        self.assertEqual(result.error_code, "TERMINATION_FAILED")
        process = captured["process"]
        self.assertIsInstance(process, subprocess.Popen)
        self.assertIsNotNone(process.poll())  # type: ignore[union-attr]

    @staticmethod
    def run_process(
        script: str,
        *,
        workspace: str,
        timeout_seconds: float = 2.0,
        output_limit_bytes: int = 4096,
    ) -> AnalyzerResult:
        return run_analyzer(
            (sys.executable, "-c", script),
            workspace=workspace,
            name="test-scanner",
            version="1.0",
            config_digest=CONFIG_DIGEST,
            executable_digest=EXECUTABLE_DIGEST,
            subject_digest=SUBJECT_DIGEST,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )


if __name__ == "__main__":
    unittest.main()
