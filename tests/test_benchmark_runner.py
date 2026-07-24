from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO
import json
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from aragorn.acquire import inventory_local
from aragorn.benchmark import BenchmarkError, evaluate_files
from aragorn.benchmark_runner import RunnerError, identify_file, main, run_files
from aragorn.cas import CAS
from aragorn.cli import ConfigurationError
import aragorn.benchmark_runner as runner_module


class BenchmarkRunnerTests(unittest.TestCase):
    def test_identity_rejects_values_the_suite_contract_cannot_represent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._layout(Path(temporary), self._adapter_script())
            original = json.loads(paths["config"].read_text())
            variants = (
                ("name", "Upper Name"),
                ("version", "1\nforged"),
                ("argv", [str(paths["adapter"]), "bad\0argument"]),
            )
            for field, value in variants:
                with self.subTest(field=field):
                    document = copy.deepcopy(original)
                    document["analyzers"][0][field] = value
                    paths["config"].write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(ConfigurationError):
                        identify_file(paths["config"], state=paths["state"])

    def test_evidence_matrix_evaluates_with_retained_raw_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._layout(Path(temporary), self._adapter_script())
            identity = identify_file(paths["config"], state=paths["state"])[0]
            suite = self._write_suite(
                paths, identity, purpose="evidence_smoke", runs=5
            )

            outcomes = run_files(suite, paths["config"], state=paths["state"])
            outcome_file = paths["root"] / "outcomes.jsonl"
            outcome_file.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in outcomes),
                encoding="utf-8",
            )
            report = evaluate_files(
                suite, outcome_file, evidence_state=paths["state"]
            )

            self.assertEqual(len(outcomes), 10)
            self.assertEqual(report["purpose"], "evidence_smoke")
            summary = report["systems"][0]["overall"]
            self.assertEqual(summary["adversarial_flag_rate"], 1.0)
            self.assertEqual(summary["benign_review_rate"], 0.0)
            self.assertEqual(summary["error_rate"], 0.0)

            adversarial = next(
                item for item in outcomes if item["case_id"] == "adversarial-case"
            )
            cas = CAS(paths["state"], read_only=True)
            envelope = json.loads(cas.read(adversarial["evidence_digest"]))
            self.assertEqual(
                cas.read(envelope["executable_digest"]), paths["adapter"].read_bytes()
            )
            self.assertEqual(
                cas.read(envelope["operator_config_digest"]),
                paths["config"].read_bytes(),
            )
            self.assertIn(b"OBSERVED_CREDENTIAL_ACCESS", cas.read(envelope["stdout_digest"]))
            self.assertEqual(cas.read(envelope["stderr_digest"]), b"diagnostic\n")

            with self.assertRaisesRegex(
                BenchmarkError, "requires a retained evidence state"
            ):
                evaluate_files(suite, outcome_file)

            forged = [copy.deepcopy(item) for item in outcomes]
            benign_index = next(
                index
                for index, item in enumerate(forged)
                if item["case_id"] == "benign-case"
            )
            writable_cas = CAS(paths["state"])
            forged_envelope = json.loads(
                writable_cas.read(forged[benign_index]["evidence_digest"])
            )
            forged_envelope["verdict"] = "REVIEW"
            forged_envelope["reason_codes"] = ["FORGED_RESULT"]
            forged_bytes = json.dumps(
                forged_envelope,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            forged[benign_index]["evidence_digest"] = writable_cas.put(
                BytesIO(forged_bytes), max_bytes=len(forged_bytes)
            )
            forged[benign_index]["verdict"] = "REVIEW"
            forged[benign_index]["reason_codes"] = ["FORGED_RESULT"]
            outcome_file.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in forged),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BenchmarkError, "does not derive"):
                evaluate_files(suite, outcome_file, evidence_state=paths["state"])

            original_envelope = json.loads(
                writable_cas.read(outcomes[benign_index]["evidence_digest"])
            )
            invalid_blob = writable_cas.put(BytesIO(b"{}"), max_bytes=2)
            mutations = (
                ("manifest_digest", invalid_blob),
                ("operator_config_digest", invalid_blob),
                ("effective_config_digest", invalid_blob),
                ("executable_digest", invalid_blob),
                ("stdout_digest", invalid_blob),
                ("observation_digests", [invalid_blob]),
            )
            for field, value in mutations:
                with self.subTest(evidence_reference=field):
                    tampered = [copy.deepcopy(item) for item in outcomes]
                    envelope = copy.deepcopy(original_envelope)
                    envelope[field] = value
                    envelope_bytes = json.dumps(
                        envelope,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("ascii")
                    tampered[benign_index]["evidence_digest"] = writable_cas.put(
                        BytesIO(envelope_bytes), max_bytes=len(envelope_bytes)
                    )
                    outcome_file.write_text(
                        "".join(
                            json.dumps(item, sort_keys=True) + "\n"
                            for item in tampered
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaises(BenchmarkError):
                        evaluate_files(
                            suite, outcome_file, evidence_state=paths["state"]
                        )

            tampered = [copy.deepcopy(item) for item in outcomes]
            envelope = copy.deepcopy(original_envelope)
            operator_config = json.loads(paths["config"].read_text(encoding="utf-8"))
            operator_config["analyzers"][0]["argv"][0] = "/forged/adapter"
            operator_bytes = json.dumps(operator_config, sort_keys=True).encode()
            envelope["operator_config_digest"] = writable_cas.put(
                BytesIO(operator_bytes), max_bytes=len(operator_bytes)
            )
            envelope_bytes = json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            tampered[benign_index]["evidence_digest"] = writable_cas.put(
                BytesIO(envelope_bytes), max_bytes=len(envelope_bytes)
            )
            outcome_file.write_text(
                "".join(
                    json.dumps(item, sort_keys=True) + "\n" for item in tampered
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BenchmarkError, "not effectively bound"):
                evaluate_files(suite, outcome_file, evidence_state=paths["state"])

    def test_original_executable_mutation_cannot_change_launched_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._layout(Path(temporary), self._adapter_script())
            identity = identify_file(paths["config"], state=paths["state"])[0]
            suite = self._write_suite(paths, identity)
            original_validator = runner_module._validate_analyzer_locations

            def validate_then_mutate(*args: object, **kwargs: object):
                result = original_validator(*args, **kwargs)
                paths["adapter"].write_text(
                    f"#!{sys.executable}\nraise SystemExit(73)\n", encoding="utf-8"
                )
                paths["adapter"].chmod(0o755)
                return result

            with patch.object(
                runner_module,
                "_validate_analyzer_locations",
                side_effect=validate_then_mutate,
            ):
                outcomes = run_files(suite, paths["config"], state=paths["state"])

            self.assertEqual(
                {item["verdict"] for item in outcomes}, {"ALLOW", "DENY"}
            )

    def test_runner_rejects_state_free_contract_smoke_suite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._layout(Path(temporary), self._adapter_script())
            identity = identify_file(paths["config"], state=paths["state"])[0]
            suite = self._write_suite(paths, identity, purpose="contract_smoke")

            with self.assertRaisesRegex(
                BenchmarkError, "requires an evidence_smoke suite"
            ):
                run_files(suite, paths["config"], state=paths["state"])

    def test_identity_mismatch_launches_nothing_and_cli_emits_no_partial_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._layout(Path(temporary), self._adapter_script())
            identity = identify_file(paths["config"], state=paths["state"])[0]
            suite = self._write_suite(paths, identity)
            marker = paths["root"] / "launched"
            paths["adapter"].write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    from pathlib import Path
                    Path({str(marker)!r}).write_text("bad")
                    """
                ),
                encoding="utf-8",
            )
            paths["adapter"].chmod(0o755)

            with self.assertRaisesRegex(RunnerError, "do not match suite"):
                run_files(suite, paths["config"], state=paths["state"])
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    (
                        "run",
                        str(suite),
                        str(paths["config"]),
                        "--state",
                        str(paths["state"]),
                    )
                )
            self.assertEqual(status, 4)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("do not match suite", stderr.getvalue())
            self.assertFalse(marker.exists())

    def test_mid_matrix_infrastructure_failure_emits_no_partial_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self._layout(Path(temporary), self._adapter_script())
            identity = identify_file(paths["config"], state=paths["state"])[0]
            suite = self._write_suite(
                paths, identity, purpose="evidence_smoke", runs=2
            )
            original_workspace = runner_module._analysis_workspace
            calls = 0

            def fail_third_workspace(*args: object, **kwargs: object):
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise RuntimeError("synthetic mid-matrix failure")
                return original_workspace(*args, **kwargs)

            stdout = StringIO()
            stderr = StringIO()
            with patch.object(
                runner_module,
                "_analysis_workspace",
                side_effect=fail_third_workspace,
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(
                    (
                        "run",
                        str(suite),
                        str(paths["config"]),
                        "--state",
                        str(paths["state"]),
                    )
                )

            self.assertEqual(calls, 3)
            self.assertEqual(status, 4)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("synthetic mid-matrix failure", stderr.getvalue())

    def test_process_errors_are_outcomes_with_retained_evidence(self) -> None:
        scripts = {
            "nonzero": (
                f"#!{sys.executable}\nimport sys\nsys.stderr.buffer.write(b'raw\\xff')\nraise SystemExit(7)\n",
                120.0,
            ),
            "malformed": (
                f"#!{sys.executable}\nimport sys\nsys.stdin.read()\nprint('{{')\n",
                120.0,
            ),
            "timeout": (
                f"#!{sys.executable}\nimport sys, time\nsys.stdin.read()\ntime.sleep(1)\n",
                0.05,
            ),
        }
        for name, (script, timeout) in scripts.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                paths = self._layout(Path(temporary), script)
                identity = identify_file(
                    paths["config"], state=paths["state"], timeout_seconds=timeout
                )[0]
                suite = self._write_suite(paths, identity, purpose="evidence_smoke")
                outcomes = run_files(
                    suite,
                    paths["config"],
                    state=paths["state"],
                    timeout_seconds=timeout,
                )
                self.assertEqual({item["verdict"] for item in outcomes}, {"ERROR"})
                cas = CAS(paths["state"], read_only=True)
                envelope = json.loads(cas.read(outcomes[0]["evidence_digest"]))
                self.assertTrue(
                    cas.read(envelope["stdout_digest"])
                    or name in {"nonzero", "timeout"}
                )
                if name == "nonzero":
                    self.assertEqual(cas.read(envelope["stderr_digest"]), b"raw\xff")
                outcome_file = paths["root"] / "outcomes.jsonl"
                outcome_file.write_text(
                    "".join(
                        json.dumps(item, sort_keys=True) + "\n" for item in outcomes
                    ),
                    encoding="utf-8",
                )
                report = evaluate_files(
                    suite, outcome_file, evidence_state=paths["state"]
                )
                self.assertEqual(report["systems"][0]["overall"]["error_rate"], 1.0)
                if name == "nonzero":
                    writable_cas = CAS(paths["state"])
                    tampered = [copy.deepcopy(item) for item in outcomes]
                    envelope = json.loads(
                        writable_cas.read(tampered[0]["evidence_digest"])
                    )
                    envelope["execution"]["error_code"] = "TIMEOUT"
                    envelope_bytes = json.dumps(
                        envelope,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("ascii")
                    tampered[0]["evidence_digest"] = writable_cas.put(
                        BytesIO(envelope_bytes), max_bytes=len(envelope_bytes)
                    )
                    outcome_file.write_text(
                        "".join(
                            json.dumps(item, sort_keys=True) + "\n"
                            for item in tampered
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(
                        BenchmarkError, "timeout is inconsistent"
                    ):
                        evaluate_files(
                            suite, outcome_file, evidence_state=paths["state"]
                        )

    @staticmethod
    def _adapter_script() -> str:
        return textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json
            from pathlib import Path
            import sys

            request = json.load(sys.stdin)
            content = (Path(request["workspace"]) / "SKILL.md").read_text()
            if "inert-marker" in content:
                print(json.dumps({{
                    "schema": "aragorn/observation/v1",
                    "subject_digest": request["subject_digest"],
                    "reason_code": "OBSERVED_CREDENTIAL_ACCESS",
                    "severity": "high"
                }}))
            print("diagnostic", file=sys.stderr)
            """
        )

    @staticmethod
    def _layout(root: Path, script: str) -> dict[str, Path]:
        corpus = root / "corpus"
        tools = root / "tools"
        operator = root / "operator"
        for directory in (corpus, tools, operator):
            directory.mkdir()
        adapter = tools / "adapter"
        adapter.write_text(script, encoding="utf-8")
        adapter.chmod(0o755)
        config = operator / "analyzers.json"
        config.write_text(
            json.dumps(
                {
                    "schema": "aragorn/analyzers/v1",
                    "analyzers": [
                        {
                            "name": "synthetic-adapter",
                            "version": "1",
                            "argv": [str(adapter)],
                        }
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return {
            "root": root,
            "corpus": corpus,
            "adapter": adapter,
            "config": config,
            "state": root / "state",
        }

    @staticmethod
    def _write_suite(
        paths: dict[str, Path],
        system: dict[str, str],
        *,
        purpose: str = "evidence_smoke",
        runs: int = 1,
    ) -> Path:
        fixtures = paths["corpus"] / "fixtures"
        benign = fixtures / "benign"
        adversarial = fixtures / "adversarial"
        benign.mkdir(parents=True)
        adversarial.mkdir(parents=True)
        (benign / "SKILL.md").write_text("safe skill\n", encoding="utf-8")
        (adversarial / "SKILL.md").write_text(
            "inert-marker credential example\n", encoding="utf-8"
        )
        cases = []
        for case_id, fixture, case_class, family in (
            ("benign-case", benign, "benign", "benign"),
            (
                "adversarial-case",
                adversarial,
                "adversarial",
                "credential-access",
            ),
        ):
            cases.append(
                {
                    "schema": "aragorn/benchmark-case/v1",
                    "id": case_id,
                    "class": case_class,
                    "family": family,
                    "lineage": f"{case_id}-lineage",
                    "split": "held_out"
                    if purpose == "evidence_smoke"
                    else "development",
                    "path": fixture.relative_to(paths["corpus"]).as_posix(),
                    "tree_digest": inventory_local(fixture)["tree_digest"],
                    "inert": True,
                    "source": {
                        "kind": "synthetic",
                        "reference": "benchmark-runner-unit-test",
                        "license": "CC0-1.0",
                    },
                }
            )
        suite = paths["corpus"] / "suite.json"
        suite.write_text(
            json.dumps(
                {
                    "schema": "aragorn/benchmark-suite/v1",
                    "id": "runner-test",
                    "purpose": purpose,
                    "runs_per_case": runs,
                    "systems": [system],
                    "cases": cases,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return suite


if __name__ == "__main__":
    unittest.main()
