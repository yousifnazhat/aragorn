from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import aragorn.benchmark as benchmark_module
from aragorn.acquire import ingest_open_directory, inventory_local
from aragorn.benchmark import BenchmarkError, _digest_json, evaluate, evaluate_files


ROOT = Path(__file__).parents[1]
BENCHMARK = ROOT / "benchmark"
EMPTY_DIGEST = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
IMPLEMENTATION_DIGEST = "sha256:" + "1" * 64


class BenchmarkTests(unittest.TestCase):
    def test_checked_in_smoke_report_is_deterministic_and_marked(self) -> None:
        report = evaluate_files(BENCHMARK / "suite.json", BENCHMARK / "outcomes.jsonl")
        suite = json.loads((BENCHMARK / "suite.json").read_text(encoding="utf-8"))
        outcomes = [
            json.loads(line)
            for line in (BENCHMARK / "outcomes.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        reordered = evaluate(suite, reversed(outcomes), BENCHMARK)

        self.assertEqual(report, reordered)
        self.assertEqual(report["schema"], "aragorn/benchmark-report/v1")
        self.assertEqual(report["purpose"], "contract_smoke")
        summary = report["systems"][0]["overall"]
        self.assertEqual(summary["adversarial_flag_rate"], 1.0)
        self.assertEqual(summary["benign_review_rate"], 0.0)
        self.assertEqual(summary["benign_deny_rate"], 0.0)
        self.assertEqual(summary["benign_intervention_rate"], 0.0)
        self.assertEqual(summary["error_rate"], 0.0)
        self.assertFalse(report["systems"][0]["repeatability"]["evaluable"])
        family = report["systems"][0]["splits"][0]["families"][0]
        self.assertEqual(family["family"], "credential-exfiltration")

    def test_errors_are_separate_and_cannot_pass_repeatability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            suite = self._suite(
                root,
                benign,
                adversarial,
                runs_per_case=5,
            )
            outcomes = self._outcomes(suite)
            for outcome in outcomes:
                outcome["verdict"] = "ERROR"
                outcome["reason_codes"] = ["ANALYZER_FAILED"]

            system_report = evaluate(suite, outcomes, root)["systems"][0]

        summary = system_report["overall"]
        self.assertEqual(summary["adversarial_flag_rate"], 0.0)
        self.assertEqual(summary["benign_review_rate"], 0.0)
        self.assertEqual(summary["benign_deny_rate"], 0.0)
        self.assertEqual(summary["error_rate"], 1.0)
        repeatability = system_report["repeatability"]
        self.assertFalse(repeatability["evaluable"])
        self.assertEqual(repeatability["error_cases"], 2)
        self.assertIsNone(repeatability["verdict_agreement"])

    def test_missing_duplicate_unknown_and_unexpected_outcomes_fail_closed(self) -> None:
        suite = json.loads((BENCHMARK / "suite.json").read_text(encoding="utf-8"))
        outcomes = [
            json.loads(line)
            for line in (BENCHMARK / "outcomes.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        unknown = copy.deepcopy(outcomes)
        unknown[0]["case_id"] = "not-in-suite"
        unexpected = copy.deepcopy(outcomes)
        unexpected[0]["system"]["implementation_digest"] = "sha256:" + "9" * 64
        variants = {
            "missing": outcomes[:1],
            "duplicate": [*outcomes, copy.deepcopy(outcomes[0])],
            "unknown": unknown,
            "unexpected-system": unexpected,
        }
        for label, variant in variants.items():
            with self.subTest(label=label), self.assertRaises(BenchmarkError):
                evaluate(suite, variant, BENCHMARK)

    def test_declared_system_cannot_be_silently_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            systems = [self._system("first"), self._system("second")]
            suite = self._suite(root, benign, adversarial, systems=systems)
            outcomes = [
                outcome
                for outcome in self._outcomes(suite)
                if outcome["system"]["name"] == "first"
            ]

            with self.assertRaisesRegex(BenchmarkError, "matrix is incomplete"):
                evaluate(suite, outcomes, root)

    def test_outcomes_bind_suite_labels_and_exact_fixture_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            suite = self._suite(root, benign, adversarial)
            stale = self._outcomes(suite)

            relabeled = copy.deepcopy(suite)
            relabeled["cases"][0]["lineage"] = "changed-lineage"
            with self.assertRaisesRegex(BenchmarkError, "suite_digest"):
                evaluate(relabeled, stale, root)

            (benign / "SKILL.md").write_text("changed\n", encoding="utf-8")
            changed = copy.deepcopy(suite)
            changed["cases"][0]["tree_digest"] = inventory_local(benign)[
                "tree_digest"
            ]
            changed_suite_digest = self._suite_digest(changed)
            stale_tree = copy.deepcopy(stale)
            for outcome in stale_tree:
                outcome["suite_digest"] = changed_suite_digest
            with self.assertRaisesRegex(BenchmarkError, "tree_digest"):
                evaluate(changed, stale_tree, root)

    def test_repeated_runs_report_agreement_and_require_complete_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            suite = self._suite(
                root,
                benign,
                adversarial,
                runs_per_case=5,
            )
            outcomes = self._outcomes(suite)
            for outcome in outcomes:
                if outcome["case_id"] == "adversarial-case" and outcome["run_id"] == 5:
                    outcome["verdict"] = "DENY"

            report = evaluate(suite, outcomes, root)["systems"][0]
            self.assertEqual(report["repeatability"]["verdict_agreement"], 0.9)
            family = report["splits"][0]["families"][0]
            self.assertEqual(family["repeatability"]["verdict_agreement"], 0.8)
            self.assertEqual(report["overall"]["adversarial_flag_rate"], 1.0)

            with self.assertRaisesRegex(BenchmarkError, "matrix is incomplete"):
                evaluate(suite, outcomes[:-1], root)
            out_of_range = copy.deepcopy(outcomes)
            out_of_range[0]["run_id"] = 6
            with self.assertRaisesRegex(BenchmarkError, "run matrix"):
                evaluate(suite, out_of_range, root)

            suite["purpose"] = "efficacy"
            with self.assertRaisesRegex(BenchmarkError, "purpose is unsupported"):
                evaluate(suite, (), root)

    def test_reason_code_cross_field_contract_is_enforced(self) -> None:
        suite = json.loads((BENCHMARK / "suite.json").read_text(encoding="utf-8"))
        outcomes = [
            json.loads(line)
            for line in (BENCHMARK / "outcomes.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
        ]
        allow_with_reason = copy.deepcopy(outcomes)
        allow_with_reason[0]["reason_codes"] = ["UNEXPECTED_REASON"]
        non_allow_without_reason = copy.deepcopy(outcomes)
        non_allow_without_reason[1]["reason_codes"] = []
        malformed_reason = copy.deepcopy(outcomes)
        malformed_reason[1]["reason_codes"] = ["not-canonical"]
        for variant in (
            allow_with_reason,
            non_allow_without_reason,
            malformed_reason,
        ):
            with self.assertRaises(BenchmarkError):
                evaluate(suite, variant, BENCHMARK)

    def test_fixture_mutation_and_executable_content_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "inert marker\n")
            suite = self._suite(root, benign, adversarial)
            outcomes = self._outcomes(suite)

            (benign / "SKILL.md").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(BenchmarkError, "digest mismatch"):
                evaluate(suite, outcomes, root)

            (benign / "SKILL.md").write_text("safe\n", encoding="utf-8")
            (adversarial / "SKILL.md").chmod(0o755)
            suite = self._suite(root, benign, adversarial)
            with self.assertRaisesRegex(BenchmarkError, "executable fixture"):
                evaluate(suite, self._outcomes(suite), root)

    def test_fixture_code_nul_and_internal_links_are_never_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "executed"
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            code = adversarial / "sitecustomize.py"
            code.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            suite = self._suite(root, benign, adversarial)
            with self.assertRaisesRegex(BenchmarkError, "non-text fixture"):
                evaluate(suite, self._outcomes(suite), root)
            self.assertFalse(marker.exists())

            code.unlink()
            binary = adversarial / "payload.txt"
            binary.write_bytes(b"safe\0not-text")
            suite = self._suite(root, benign, adversarial)
            with self.assertRaisesRegex(BenchmarkError, "NUL byte"):
                evaluate(suite, self._outcomes(suite), root)

            binary.unlink()
            (adversarial / "outside-link.md").symlink_to(benign / "SKILL.md")
            suite = self._suite_without_inventory(root, benign, adversarial)
            with self.assertRaisesRegex(BenchmarkError, "unsafe fixture"):
                evaluate(suite, self._outcomes(suite), root)

    def test_intermediate_case_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "suite"
            root.mkdir()
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            outside = self._fixture(base, "outside", "outside\n")
            (root / "escape").symlink_to(base, target_is_directory=True)
            suite = self._suite(root, benign, adversarial)
            suite["cases"][0]["path"] = "escape/outside"
            suite["cases"][0]["tree_digest"] = inventory_local(outside)["tree_digest"]

            with self.assertRaisesRegex(BenchmarkError, "unsafe fixture"):
                evaluate(suite, self._outcomes(suite), root)

    def test_suite_parent_retarget_does_not_rebind_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first = base / "first"
            second = base / "second"
            first.mkdir()
            second.mkdir()
            benign = self._fixture(first, "benign", "safe\n")
            adversarial = self._fixture(first, "adversarial", "marker\n")
            self._fixture(second, "benign", "different\n")
            self._fixture(second, "adversarial", "different\n")
            suite = self._suite(first, benign, adversarial)
            (first / "suite.json").write_text(json.dumps(suite), encoding="utf-8")
            outcomes_path = base / "outcomes.jsonl"
            outcomes_path.write_text(
                "\n".join(json.dumps(item) for item in self._outcomes(suite)) + "\n",
                encoding="utf-8",
            )
            selected = base / "selected"
            selected.symlink_to(first, target_is_directory=True)
            original_decode = benchmark_module._decode_json
            retargeted = False

            def decode_and_retarget(raw: bytes, label: str) -> object:
                nonlocal retargeted
                decoded = original_decode(raw, label)
                if label == "benchmark suite" and not retargeted:
                    selected.unlink()
                    selected.symlink_to(second, target_is_directory=True)
                    retargeted = True
                return decoded

            with mock.patch.object(
                benchmark_module, "_decode_json", side_effect=decode_and_retarget
            ):
                report = evaluate_files(selected / "suite.json", outcomes_path)

        self.assertEqual(report["suite_id"], "test-suite")
        self.assertTrue(retargeted)

    def test_opened_case_survives_parent_namespace_retarget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "cases/benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            outside = root / "outside"
            outside.mkdir()
            self._fixture(outside, "benign", "different\n")
            suite = self._suite(root, benign, adversarial)
            outcomes = self._outcomes(suite)
            original_ingest = ingest_open_directory
            retargeted = False

            def ingest_after_retarget(
                display_path: Path, descriptor: int, cas: object, **limits: int
            ) -> dict[str, object]:
                nonlocal retargeted
                if not retargeted:
                    (root / "cases").rename(root / "cases-old")
                    (root / "cases").symlink_to(outside, target_is_directory=True)
                    retargeted = True
                return original_ingest(display_path, descriptor, cas, **limits)

            with mock.patch.object(
                benchmark_module,
                "ingest_open_directory",
                side_effect=ingest_after_retarget,
            ):
                report = evaluate(suite, outcomes, root)

        self.assertEqual(report["suite_id"], "test-suite")
        self.assertTrue(retargeted)

    def test_noncanonical_and_overlapping_case_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            for value in (".", "benign/.", "benign//child"):
                suite = self._suite(root, benign, adversarial)
                suite["cases"][0]["path"] = value
                with self.subTest(path=value), self.assertRaises(BenchmarkError):
                    evaluate(suite, self._outcomes(suite), root)

            parent = self._fixture(root, "container", "parent\n")
            child = self._fixture(parent, "child", "child\n")
            suite = self._suite(root, parent, child)
            with self.assertRaisesRegex(BenchmarkError, "overlaps"):
                evaluate(suite, self._outcomes(suite), root)

    def test_duplicate_digest_cross_split_lineage_and_family_mismatch_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            suite = self._suite(root, benign, adversarial)
            suite["cases"][1]["path"] = suite["cases"][0]["path"]
            suite["cases"][1]["tree_digest"] = suite["cases"][0]["tree_digest"]
            with self.assertRaisesRegex(BenchmarkError, "duplicate fixture"):
                evaluate(suite, self._outcomes(suite), root)

            suite = self._suite(root, benign, adversarial)
            suite["cases"][1]["lineage"] = suite["cases"][0]["lineage"]
            suite["cases"][1]["split"] = "held_out"
            with self.assertRaisesRegex(BenchmarkError, "crosses benchmark splits"):
                evaluate(suite, self._outcomes(suite), root)

            for index, family in ((0, "attack"), (1, "benign")):
                suite = self._suite(root, benign, adversarial)
                suite["cases"][index]["family"] = family
                with self.subTest(index=index), self.assertRaisesRegex(
                    BenchmarkError, "family"
                ):
                    evaluate(suite, self._outcomes(suite), root)

    def test_lineage_cannot_change_class_family_or_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")

            changed_class = self._suite(root, benign, adversarial)
            changed_class["cases"][1]["lineage"] = changed_class["cases"][0][
                "lineage"
            ]
            with self.assertRaisesRegex(BenchmarkError, "changes benchmark class"):
                evaluate(changed_class, self._outcomes(changed_class), root)

            changed_family = self._suite(root, benign, adversarial)
            changed_family["cases"][0]["class"] = "adversarial"
            changed_family["cases"][0]["family"] = "prompt-obfuscation"
            changed_family["cases"][1]["lineage"] = changed_family["cases"][0][
                "lineage"
            ]
            with self.assertRaisesRegex(BenchmarkError, "changes attack family"):
                evaluate(changed_family, self._outcomes(changed_family), root)

            second_attack = self._fixture(root, "second-attack", "other marker\n")
            changed_source = self._suite(root, benign, adversarial)
            extra = self._case(
                root,
                second_attack,
                "second-adversarial-case",
                "adversarial",
                "credential-exfiltration",
            )
            extra["lineage"] = changed_source["cases"][1]["lineage"]
            extra["source"] = {
                "kind": "synthetic",
                "reference": "different-provenance",
                "license": "CC0-1.0",
            }
            changed_source["cases"].append(extra)
            with self.assertRaisesRegex(BenchmarkError, "changes source provenance"):
                evaluate(changed_source, self._outcomes(changed_source), root)

    def test_benign_intervention_rate_includes_review_deny_and_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            suite = self._suite(root, benign, adversarial, runs_per_case=3)
            outcomes = self._outcomes(suite)
            benign_outcomes = [
                outcome for outcome in outcomes if outcome["case_id"] == "benign-case"
            ]
            benign_outcomes[0]["verdict"] = "REVIEW"
            benign_outcomes[0]["reason_codes"] = ["SYNTHETIC_REVIEW"]
            benign_outcomes[1]["verdict"] = "DENY"
            benign_outcomes[1]["reason_codes"] = ["SYNTHETIC_DENY"]
            benign_outcomes[2]["verdict"] = "ERROR"
            benign_outcomes[2]["reason_codes"] = ["SYNTHETIC_ERROR"]

            summary = evaluate(suite, outcomes, root)["systems"][0]["overall"]

        self.assertEqual(summary["benign_intervened"], 3)
        self.assertEqual(summary["benign_intervention_rate"], 1.0)

    def test_root_skill_and_aggregate_resource_budgets_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = root / "benign"
            benign.mkdir()
            (benign / "README.md").write_text("safe\n", encoding="utf-8")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            suite = self._suite(root, benign, adversarial)
            with self.assertRaisesRegex(BenchmarkError, "root SKILL.md"):
                evaluate(suite, self._outcomes(suite), root)

            (benign / "SKILL.md").write_text("safe\n", encoding="utf-8")
            suite = self._suite(root, benign, adversarial)
            with mock.patch.object(benchmark_module, "_MAX_SUITE_BYTES", 8):
                with self.assertRaises(BenchmarkError):
                    evaluate(suite, self._outcomes(suite), root)

            (benign / "empty-directory").mkdir()
            suite = self._suite(root, benign, adversarial)
            with mock.patch.object(benchmark_module, "_MAX_SUITE_ENTRIES", 2):
                with self.assertRaisesRegex(BenchmarkError, "file count"):
                    evaluate(suite, self._outcomes(suite), root)

    def test_malformed_container_types_return_benchmark_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            benign = self._fixture(root, "benign", "safe\n")
            adversarial = self._fixture(root, "adversarial", "marker\n")
            suite = self._suite(root, benign, adversarial)
            variants = []
            for location, value in (("purpose", []), ("class", {}), ("split", [])):
                variant = copy.deepcopy(suite)
                if location == "purpose":
                    variant["purpose"] = value
                else:
                    variant["cases"][0][location] = value
                variants.append(variant)
            for variant in variants:
                with self.assertRaises(BenchmarkError):
                    evaluate(variant, (), root)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires POSIX")
    def test_fifo_input_fails_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "suite.json"
            os.mkfifo(fifo)
            outcomes = root / "outcomes.jsonl"
            outcomes.write_text("", encoding="utf-8")
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ROOT / "src")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "aragorn.benchmark",
                    str(fifo),
                    str(outcomes),
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

    def test_generated_report_matches_declared_schema_shape(self) -> None:
        report = evaluate_files(BENCHMARK / "suite.json", BENCHMARK / "outcomes.jsonl")
        schema = json.loads(
            (ROOT / "schema/benchmark-report-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(set(report), set(schema["required"]))
        system_report = report["systems"][0]
        system_schema = schema["properties"]["systems"]["items"]
        self.assertEqual(set(system_report), set(system_schema["required"]))
        self.assertEqual(
            set(system_report["overall"]), set(schema["$defs"]["summary"]["required"])
        )
        split = system_report["splits"][0]
        split_schema = system_schema["properties"]["splits"]["items"]
        self.assertEqual(set(split), set(split_schema["required"]))
        family = split["families"][0]
        self.assertEqual(set(family), set(schema["$defs"]["family"]["required"]))

    @staticmethod
    def _fixture(root: Path, name: str, content: str) -> Path:
        fixture = root / name
        fixture.mkdir(parents=True)
        (fixture / "SKILL.md").write_text(content, encoding="utf-8")
        return fixture

    def _suite(
        self,
        root: Path,
        benign: Path,
        adversarial: Path,
        *,
        purpose: str = "contract_smoke",
        runs_per_case: int = 1,
        systems: list[dict[str, str]] | None = None,
    ) -> dict[str, object]:
        return {
            "schema": "aragorn/benchmark-suite/v1",
            "id": "test-suite",
            "purpose": purpose,
            "runs_per_case": runs_per_case,
            "systems": systems or [self._system()],
            "cases": [
                self._case(root, benign, "benign-case", "benign", "benign"),
                self._case(
                    root,
                    adversarial,
                    "adversarial-case",
                    "adversarial",
                    "credential-exfiltration",
                ),
            ],
        }

    def _suite_without_inventory(
        self, root: Path, benign: Path, adversarial: Path
    ) -> dict[str, object]:
        suite = self._suite(root, benign, benign)
        suite["cases"][1]["path"] = adversarial.relative_to(root).as_posix()
        suite["cases"][1]["tree_digest"] = "sha256:" + "0" * 64
        return suite

    @staticmethod
    def _case(
        root: Path,
        fixture: Path,
        case_id: str,
        case_class: str,
        family: str,
    ) -> dict[str, object]:
        return {
            "schema": "aragorn/benchmark-case/v1",
            "id": case_id,
            "class": case_class,
            "family": family,
            "lineage": f"{case_id}-lineage",
            "split": "development",
            "path": fixture.relative_to(root).as_posix(),
            "tree_digest": inventory_local(fixture)["tree_digest"],
            "inert": True,
            "source": {
                "kind": "synthetic",
                "reference": "unit-test",
                "license": "CC0-1.0",
            },
        }

    @staticmethod
    def _system(name: str = "synthetic-test") -> dict[str, str]:
        return {
            "name": name,
            "version": "1",
            "implementation_digest": IMPLEMENTATION_DIGEST,
            "config_digest": EMPTY_DIGEST,
        }

    @classmethod
    def _suite_digest(cls, suite: dict[str, object]) -> str:
        systems = sorted(
            suite["systems"],
            key=lambda system: (
                system["name"],
                system["version"],
                system["implementation_digest"],
                system["config_digest"],
            ),
        )
        cases = sorted(suite["cases"], key=lambda case: case["id"])
        return _digest_json(
            {
                "schema": suite["schema"],
                "id": suite["id"],
                "purpose": suite["purpose"],
                "runs_per_case": suite["runs_per_case"],
                "systems": systems,
                "cases": cases,
            }
        )

    @classmethod
    def _outcomes(cls, suite: dict[str, object]) -> list[dict[str, object]]:
        suite_digest = cls._suite_digest(suite)
        outcomes = []
        for system in suite["systems"]:
            for case in suite["cases"]:
                for run_id in range(1, suite["runs_per_case"] + 1):
                    verdict = "ALLOW" if case["class"] == "benign" else "REVIEW"
                    outcomes.append(
                        {
                            "schema": "aragorn/benchmark-outcome/v1",
                            "suite_digest": suite_digest,
                            "case_id": case["id"],
                            "tree_digest": case["tree_digest"],
                            "run_id": run_id,
                            "system": dict(system),
                            "evidence_digest": _digest_json(
                                {
                                    "case_id": case["id"],
                                    "run_id": run_id,
                                    "system": system,
                                }
                            ),
                            "verdict": verdict,
                            "reason_codes": []
                            if verdict == "ALLOW"
                            else ["SYNTHETIC_MARKER"],
                        }
                    )
        return outcomes


if __name__ == "__main__":
    unittest.main()
