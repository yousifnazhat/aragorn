from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import aragorn.cli as cli_module
from aragorn.acquire import inventory_local
from aragorn.analyzer_receipt import verify_analyzer_run
from aragorn.cas import CAS
from aragorn.cli import main
from aragorn.decision_receipt import DecisionReceiptError, verify_decision_v2
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase0_candidate import candidate_implementation_digest


ROOT = Path(__file__).parents[1]


class CLITests(unittest.TestCase):
    def test_usage_errors_have_distinct_exit_code_and_json_error(self) -> None:
        stderr = StringIO()
        with redirect_stderr(stderr):
            status = main(("unknown-command",))

        error = json.loads(stderr.getvalue())
        self.assertEqual(status, 64)
        self.assertEqual(error["schema"], "aragorn/error/v1")
        self.assertEqual(error["error"], "UsageError")

    def test_inventory_ingests_manifest_and_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("# harmless\n", encoding="utf-8")
            state = root / "state"

            stdout = StringIO()
            with redirect_stdout(stdout):
                status = main(("inventory", str(source), "--state", str(state)))

            result = json.loads(stdout.getvalue())
            manifest = json.loads(CAS(state).read(result["manifest_digest"]))
            self.assertEqual(status, 0)
            self.assertEqual(result["file_count"], 1)
            self.assertEqual(
                CAS(state).read(manifest["files"][0]["digest"]), b"# harmless\n"
            )

    def test_inspect_runs_adapters_but_source_only_closure_fails_closed(self) -> None:
        adapter = textwrap.dedent(
            """
            import json
            import os
            import sys

            request = json.load(sys.stdin)
            assert os.getcwd() != request["workspace"]
            assert os.environ["HOME"] == os.getcwd()
            run_path = os.path.join(request["workspace"], "run.sh")
            skill_path = os.path.join(request["workspace"], "SKILL.md")
            assert os.stat(run_path).st_mode & 0o111 == 0o111
            assert os.stat(skill_path).st_mode & 0o111 == 0
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("# harmless\n", encoding="utf-8")
            executable = source / "run.sh"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            config = root / "analyzers.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "aragorn/analyzers/v1",
                        "analyzers": [
                            {
                                "name": name,
                                "version": "test",
                                "argv": [sys.executable, "-c", adapter],
                            }
                            for name in ("cisco-skill-scanner", "skillspector")
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                status = main(
                    (
                        "inspect",
                        str(source),
                        "--state",
                        str(root / "state"),
                        "--analyzers",
                        str(config),
                    )
                )

            result = json.loads(stdout.getvalue())
            receipt = result["decision"]
            self.assertEqual(status, 4)
            self.assertEqual(result["schema"], "aragorn/inspect-result/v2")
            self.assertEqual(
                receipt["authority"],
                "EVIDENCE_SUMMARY_ONLY_NOT_INSTALLER_AUTHORITY",
            )
            self.assertEqual(receipt["verdict"], "ERROR")
            self.assertEqual(receipt["reason_codes"], ["ARTIFACT_CLOSURE_INCOMPLETE"])
            self.assertEqual(
                [analyzer["status"] for analyzer in receipt["analyzers"]], ["ok", "ok"]
            )
            self.assertTrue(
                all(
                    analyzer["executable_digest"].startswith("sha256:")
                    for analyzer in receipt["analyzers"]
                )
            )
            verifier_digest = candidate_implementation_digest()
            self.assertTrue(
                all(
                    verify_analyzer_run(
                        CAS(root / "state"),
                        analyzer["run_receipt_digest"],
                        expected_subject_digest=receipt["tree_digest"],
                        expected_verifier_digest=verifier_digest,
                    ).ok
                    for analyzer in receipt["analyzers"]
                )
            )
            self.assertRegex(result["decision_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(
                verify_decision_v2(
                    CAS(root / "state", read_only=True),
                    result["decision_digest"],
                    expected_manifest_digest=receipt["manifest_digest"],
                    expected_policy_digest=receipt["policy"]["digest"],
                    expected_analyzer_verifier_digest=verifier_digest,
                ),
                receipt,
            )

            changed_verdict = deepcopy(receipt)
            changed_verdict["verdict"] = "ALLOW"
            changed_artifacts = deepcopy(receipt)
            changed_artifacts["artifact_digests"] = []
            changed_analyzer = deepcopy(receipt)
            changed_analyzer["analyzers"][0]["stdout_digest"] = "sha256:" + "0" * 64
            changed_reasons = deepcopy(receipt)
            changed_reasons["reason_codes"] = []
            changed_policy = deepcopy(receipt)
            changed_policy["policy"]["digest"] = "sha256:" + "0" * 64
            cas = CAS(root / "state")
            for label, changed in (
                ("verdict", changed_verdict),
                ("artifacts", changed_artifacts),
                ("analyzer", changed_analyzer),
                ("reasons", changed_reasons),
                ("policy", changed_policy),
            ):
                with self.subTest(changed=label):
                    raw = canonical_json(changed)
                    changed_digest = cas.put(BytesIO(raw), max_bytes=len(raw))
                    with self.assertRaises(DecisionReceiptError):
                        verify_decision_v2(
                            CAS(root / "state", read_only=True),
                            changed_digest,
                            expected_manifest_digest=receipt["manifest_digest"],
                            expected_policy_digest=receipt["policy"]["digest"],
                            expected_analyzer_verifier_digest=verifier_digest,
                        )

    def test_state_inside_source_is_rejected_before_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("# harmless\n", encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                status = main(
                    (
                        "inventory",
                        str(source),
                        "--state",
                        str(source / ".aragorn"),
                    )
                )

            self.assertEqual(status, 4)
            self.assertIn("state directory must be outside", stderr.getvalue())
            self.assertFalse((source / ".aragorn").exists())

    def test_oversized_output_limit_is_rejected_before_state_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("safe\n", encoding="utf-8")
            state = root / "state"
            stdout = StringIO()
            stderr = StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    (
                        "inspect",
                        str(source),
                        "--state",
                        str(state),
                        "--output-limit",
                        str(8 * 1024 * 1024 + 1),
                    )
                )

            self.assertEqual(status, 4)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("output limit must be between", stderr.getvalue())
            self.assertFalse(state.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires POSIX")
    def test_fifo_analyzer_configuration_fails_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("safe\n", encoding="utf-8")
            fifo = root / "analyzers.json"
            os.mkfifo(fifo)
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ROOT / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "aragorn.cli",
                    "inspect",
                    str(source),
                    "--state",
                    str(root / "state"),
                    "--analyzers",
                    str(fifo),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )

        self.assertEqual(completed.returncode, 4)
        self.assertIn("regular file", completed.stderr)

    def test_source_root_symlink_is_rejected_before_cas_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir()
            (private / "credential.txt").write_text("secret\n", encoding="utf-8")
            source = root / "public-skill"
            source.symlink_to(private, target_is_directory=True)

            for command in ("inventory", "inspect"):
                with self.subTest(command=command):
                    state = root / f"state-{command}"
                    stdout = StringIO()
                    stderr = StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        status = main((command, str(source), "--state", str(state)))

                    self.assertEqual(status, 4)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn("must not be a symlink", stderr.getvalue())
                    self.assertFalse(state.exists())

    def test_source_root_swap_to_symlink_cannot_change_opened_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("public\n", encoding="utf-8")
            private = root / "private"
            private.mkdir()
            (private / "credential.txt").write_text("secret\n", encoding="utf-8")
            held = root / "held"
            state = root / "state"
            original_open = cli_module.os.open
            swapped = False

            def swap_before_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal swapped
                if not swapped and Path(path) == source:
                    swapped = True
                    source.rename(held)
                    source.symlink_to(private, target_is_directory=True)
                return original_open(path, flags, *args, **kwargs)

            stdout = StringIO()
            stderr = StringIO()
            with patch("aragorn.cli.os.open", side_effect=swap_before_open), redirect_stdout(
                stdout
            ), redirect_stderr(stderr):
                status = main(("inventory", str(source), "--state", str(state)))

            self.assertTrue(swapped)
            self.assertEqual(status, 4)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("symlink", stderr.getvalue())
            self.assertFalse(state.exists())

    def test_each_analyzer_receives_fresh_verified_workspace(self) -> None:
        mutator = textwrap.dedent(
            """
            import json
            import os
            import pathlib
            import sys

            request = json.load(sys.stdin)
            skill = pathlib.Path(request["workspace"]) / "SKILL.md"
            skill.chmod(0o600)
            skill.write_text("mutated\\n")
            """
        )
        verifier = textwrap.dedent(
            """
            import json
            import pathlib
            import sys

            request = json.load(sys.stdin)
            skill = pathlib.Path(request["workspace"]) / "SKILL.md"
            assert skill.read_text() == "original\\n"
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("original\n", encoding="utf-8")
            config = root / "analyzers.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "aragorn/analyzers/v1",
                        "analyzers": [
                            {
                                "name": "cisco-skill-scanner",
                                "version": "test",
                                "argv": [sys.executable, "-c", mutator],
                            },
                            {
                                "name": "skillspector",
                                "version": "test",
                                "argv": [sys.executable, "-c", verifier],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                status = main(
                    (
                        "inspect",
                        str(source),
                        "--state",
                        str(root / "state"),
                        "--analyzers",
                        str(config),
                    )
                )

            receipt = json.loads(stdout.getvalue())["decision"]
            self.assertEqual(status, 4)
            self.assertEqual(
                [record["status"] for record in receipt["analyzers"]],
                ["ok", "ok"],
            )

    def test_repository_executable_cannot_be_configured_as_analyzer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            marker = root / "executed"
            adapter = source / "repo-adapter"
            adapter.write_text(
                f"#!{sys.executable}\nfrom pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            adapter.chmod(0o755)
            shell_adapter = source / "repo-adapter.sh"
            shell_adapter.write_text(
                f"#!/bin/sh\nprintf bad > {marker}\n", encoding="utf-8"
            )
            shell_adapter.chmod(0o755)
            config = root / "analyzers.json"
            commands = (
                [str(adapter)],
                [sys.executable, str(adapter)],
                ["/bin/sh", str(shell_adapter)],
            )
            for command in commands:
                with self.subTest(command=command):
                    marker.unlink(missing_ok=True)
                    config.write_text(
                        json.dumps(
                            {
                                "schema": "aragorn/analyzers/v1",
                                "analyzers": [
                                    {
                                        "name": "cisco-skill-scanner",
                                        "version": "test",
                                        "argv": command,
                                    }
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )
                    stdout = StringIO()
                    stderr = StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        status = main(
                            (
                                "inspect",
                                str(source),
                                "--state",
                                str(root / "state"),
                                "--analyzers",
                                str(config),
                            )
                        )

                    self.assertEqual(status, 4)
                    self.assertFalse(marker.exists())
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertRegex(
                        stderr.getvalue(),
                        "must be outside the inspected source|filesystem path arguments are unsupported",
                    )

    def test_inventory_uses_source_opened_before_parent_link_retarget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            for parent, content in ((first, "first\n"), (second, "second\n")):
                skill = parent / "skill"
                skill.mkdir(parents=True)
                (skill / "SKILL.md").write_text(content, encoding="utf-8")
            selected = root / "selected"
            selected.symlink_to(first, target_is_directory=True)
            original_opener = cli_module._open_source_and_resolve_state

            def open_then_retarget(
                source: Path, state: Path
            ) -> tuple[int, Path, Path]:
                result = original_opener(source, state)
                selected.unlink()
                selected.symlink_to(second, target_is_directory=True)
                return result

            stdout = StringIO()
            with patch(
                "aragorn.cli._open_source_and_resolve_state",
                side_effect=open_then_retarget,
            ), redirect_stdout(stdout):
                status = main(
                    (
                        "inventory",
                        str(selected / "skill"),
                        "--state",
                        str(root / "state"),
                    )
                )

            self.assertEqual(status, 0)
            self.assertEqual(
                json.loads(stdout.getvalue())["tree_digest"],
                inventory_local(first / "skill")["tree_digest"],
            )

    def test_configuration_parent_link_retarget_cannot_change_loaded_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("safe\n", encoding="utf-8")
            marker = root / "executed"
            safe = root / "safe-config"
            safe.mkdir()
            (safe / "analyzers.json").write_text(
                json.dumps({"schema": "aragorn/analyzers/v1", "analyzers": []}),
                encoding="utf-8",
            )
            (source / "analyzers.json").write_text(
                json.dumps(
                    {
                        "schema": "aragorn/analyzers/v1",
                        "analyzers": [
                            {
                                "name": "cisco-skill-scanner",
                                "version": "bad",
                                "argv": [
                                    "/bin/sh",
                                    "-c",
                                    f"cat >/dev/null; touch {marker}",
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            selected = root / "selected-config"
            selected.symlink_to(safe, target_is_directory=True)
            original_validator = cli_module._validate_configuration_location

            def validate_then_retarget(
                path: Path | None, source_path: Path, state_path: Path
            ) -> dict[str, object] | None:
                result = original_validator(path, source_path, state_path)
                selected.unlink()
                selected.symlink_to(source, target_is_directory=True)
                return result

            stdout = StringIO()
            with patch(
                "aragorn.cli._validate_configuration_location",
                side_effect=validate_then_retarget,
            ), redirect_stdout(stdout):
                status = main(
                    (
                        "inspect",
                        str(source),
                        "--state",
                        str(root / "state"),
                        "--analyzers",
                        str(selected / "analyzers.json"),
                    )
                )

            self.assertEqual(status, 4)
            self.assertFalse(marker.exists())
            self.assertEqual(json.loads(stdout.getvalue())["decision"]["analyzers"], [])

    def test_analyzer_filesystem_path_argument_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("safe\n", encoding="utf-8")
            marker = root / "executed"
            safe = root / "safe-adapter"
            safe.mkdir()
            (safe / "adapter.py").write_text(
                "import sys\nsys.stdin.read()\n", encoding="utf-8"
            )
            (source / "adapter.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            selected = root / "selected-adapter"
            selected.symlink_to(safe, target_is_directory=True)
            config = root / "analyzers.json"
            for candidate in (
                str(selected / "adapter.py"),
                "../adapter-config.json",
                "~/adapter-config.json",
            ):
                with self.subTest(candidate=candidate):
                    config.write_text(
                        json.dumps(
                            {
                                "schema": "aragorn/analyzers/v1",
                                "analyzers": [
                                    {
                                        "name": "cisco-skill-scanner",
                                        "version": "test",
                                        "argv": [sys.executable, candidate],
                                    }
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )
                    stdout = StringIO()
                    stderr = StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        status = main(
                            (
                                "inspect",
                                str(source),
                                "--state",
                                str(root / "state"),
                                "--analyzers",
                                str(config),
                            )
                        )

                    self.assertEqual(status, 4)
                    self.assertFalse(marker.exists())
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn(
                        "filesystem path arguments are unsupported",
                        stderr.getvalue(),
                    )


if __name__ == "__main__":
    unittest.main()
