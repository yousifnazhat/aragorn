from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import aragorn.benchmark as benchmark_module
from aragorn.acquire import inventory_local
from aragorn.benchmark import (
    BenchmarkError,
    _canonical_suite_document,
    _digest_json,
    _load_phase0_expansion,
    _open_directory_path,
    _phase0_hidden_gate_report,
    _validate_outcomes,
    _validate_phase0_hidden_binding,
    _validate_suite,
    evaluate,
    evaluate_phase0,
    evaluate_phase0_hidden,
)
from aragorn.benchmark import (
    main as benchmark_main,
)
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest

COMMIT = "a" * 40
COMMIT_TREE = "b" * 40
SKILL_TREE = "c" * 40
REPOSITORY_ROOT = Path(__file__).parents[1]


def _git_blob_sha1(content: bytes) -> str:
    header = b"blob " + str(len(content)).encode("ascii") + b"\0"
    return hashlib.sha1(header + content).hexdigest()


class Phase0GateTests(unittest.TestCase):
    def test_hidden_gate_scores_hidden_and_uses_v2_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, _accounting, root, _state = self._harness(
                Path(temporary),
                split="hidden",
            )
            report = self._hidden_report(suite, outcomes, root)

        self.assertEqual(report["schema"], "aragorn/benchmark-phase0-gate-report/v2")
        self.assertEqual(report["evaluation_split"], "hidden")
        self.assertNotIn("accounting", report)
        self.assertNotIn("accounting_digest", report)
        self.assertEqual(report["corpus_lock_digest"], "sha256:" + "0" * 64)
        self.assertEqual(report["public_manifest_digest"], "sha256:" + "1" * 64)
        self.assertEqual(report["hidden_suite_lock_digest"], "sha256:" + "2" * 64)
        self.assertEqual(report["candidate_policy_digest"], "sha256:" + "3" * 64)
        self.assertEqual(report["label_ledger_digest"], "sha256:" + "4" * 64)
        self.assertTrue(report["comparison"]["passed"])
        self.assertEqual(
            report["comparison"]["candidate"]["benign_intervention"],
            {"numerator": 1, "denominator": 20, "rate": 0.05},
        )
        self.assertEqual(
            report["comparison"]["attack_flag_delta"],
            {"numerator": 1, "denominator": 10, "rate": 0.1},
        )

    def test_hidden_gate_without_hidden_split_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, _accounting, root, _state = self._harness(
                Path(temporary)
            )
            report = self._hidden_report(suite, outcomes, root)

        self.assertFalse(report["comparison"]["evaluable"])
        self.assertFalse(report["comparison"]["passed"])
        self.assertEqual(report["comparison"]["reason_codes"], ["NO_HIDDEN_SPLIT"])

    def test_hidden_gate_rejects_contract_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, _state = self._harness(
                Path(temporary),
                split="hidden",
            )
            unused = root / "unused.json"
            with self.assertRaisesRegex(BenchmarkError, "requires evidence_smoke"):
                evaluate_phase0_hidden(
                    suite,
                    outcomes,
                    root,
                    corpus_lock=unused,
                    public_manifest=unused,
                    hidden_suite_lock=unused,
                    candidate_policy=unused,
                    label_ledger_digest="sha256:" + "4" * 64,
                )
            suite_path, outcomes_path, _accounting_path = self._write_cli_inputs(
                root,
                suite,
                outcomes,
                accounting,
            )
            status, stdout, stderr = self._run_cli(
                (
                    str(suite_path),
                    str(outcomes_path),
                    "--phase0-hidden-gate",
                    "--phase0-corpus-lock",
                    str(unused),
                    "--phase0-public-manifest",
                    str(unused),
                    "--phase0-hidden-suite-lock",
                    str(unused),
                    "--phase0-candidate-policy",
                    str(unused),
                    "--phase0-label-ledger-digest",
                    "sha256:" + "4" * 64,
                )
            )

        self.assertEqual(status, 4)
        self.assertEqual(stdout, "")
        self.assertIn("requires evidence_smoke", json.loads(stderr)["message"])

    def test_hidden_gate_rejects_legacy_and_v4_evidence(self) -> None:
        legacy_bindings = (
            None,
            {
                "dispatch_digest": "sha256:" + "0" * 64,
                "ledger_id": "sha256:" + "1" * 64,
                "job_id": "legacy-job",
                "nonce": "legacy-nonce",
                "request_digest": "sha256:" + "2" * 64,
                "result_digest": "sha256:" + "3" * 64,
            },
        )
        for binding in legacy_bindings:
            with (
                self.subTest(evidence="v4" if binding else "legacy"),
                tempfile.TemporaryDirectory() as temporary,
            ):
                    suite, outcomes, _accounting, root, state = self._harness(
                        Path(temporary),
                        purpose="evidence_smoke",
                        split="hidden",
                    )
                    with patch(
                        "aragorn.benchmark._verify_evidence",
                        return_value=binding,
                    ):
                        canonical_root = root.resolve(strict=True)
                        root_fd = _open_directory_path(canonical_root)
                        try:
                            (
                                _suite_id,
                                purpose,
                                runs_per_case,
                                cases,
                                normalized_cases,
                                systems,
                                manifests,
                            ) = _validate_suite(suite, canonical_root, root_fd)
                        finally:
                            os.close(root_fd)
                        suite_digest = _digest_json(
                            _canonical_suite_document(
                                suite["id"],
                                purpose,
                                runs_per_case,
                                normalized_cases,
                                systems,
                            )
                        )
                        with self.assertRaisesRegex(
                            BenchmarkError,
                            "requires candidate-composition evidence",
                        ):
                            _validate_outcomes(
                                tuple(outcomes),
                                cases,
                                systems,
                                runs_per_case,
                                suite_digest,
                                purpose=purpose,
                                manifests=manifests,
                                evidence_cas=CAS(state, read_only=True),
                                acceptance_ledger=None,
                                require_candidate_composition=True,
                                expected_candidate_policy_digest=(
                                    "sha256:" + "4" * 64
                                ),
                            )

    def test_hidden_binding_closes_exact_448_case_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._hidden_binding_fixture(Path(temporary))
            binding = self._validate_hidden_binding_fixture(fixture)

        self.assertEqual(
            binding,
            {
                "corpus_lock_digest": fixture["corpus_lock_digest"],
                "public_manifest_digest": fixture["public_manifest_digest"],
                "hidden_suite_lock_digest": fixture["hidden_suite_lock_digest"],
                "candidate_policy_digest": fixture["candidate_policy_digest"],
                "label_ledger_digest": fixture["label_ledger_digest"],
            },
        )

    def test_hidden_binding_rejects_lock_and_matrix_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            fixture = self._hidden_binding_fixture(base)

            stale_lock = base / "stale-corpus-lock.json"
            corpus_lock = json.loads(fixture["corpus_lock_path"].read_text())
            corpus_lock["case_count"] = 447
            stale_lock.write_text(json.dumps(corpus_lock), encoding="utf-8")
            with self.assertRaisesRegex(BenchmarkError, "corpus lock identity"):
                self._validate_hidden_binding_fixture(
                    fixture,
                    corpus_lock_path=stale_lock,
                )

            for field in (
                "suite_digest",
                "corpus_lock_digest",
                "evaluator_archive_digest",
            ):
                with self.subTest(lock_field=field):
                    lock = copy.deepcopy(fixture["hidden_suite_lock"])
                    lock[field] = "sha256:" + "f" * 64
                    self._write_canonical_json(fixture["hidden_suite_lock_path"], lock)
                    with self.assertRaisesRegex(BenchmarkError, "frozen inputs"):
                        self._validate_hidden_binding_fixture(fixture)
                    self._write_canonical_json(
                        fixture["hidden_suite_lock_path"],
                        fixture["hidden_suite_lock"],
                    )

            with self.assertRaisesRegex(BenchmarkError, "frozen inputs"):
                self._validate_hidden_binding_fixture(
                    fixture,
                    label_ledger_digest="sha256:" + "e" * 64,
                )
            with self.assertRaisesRegex(BenchmarkError, "public case matrix"):
                self._validate_hidden_binding_fixture(
                    fixture,
                    cases=dict(list(fixture["cases"].items())[:3]),
                )
            mixed = copy.deepcopy(fixture["cases"])
            mixed[next(iter(mixed))]["split"] = "held_out"
            with self.assertRaisesRegex(BenchmarkError, "public case matrix"):
                self._validate_hidden_binding_fixture(fixture, cases=mixed)
            with self.assertRaisesRegex(BenchmarkError, "public case matrix"):
                self._validate_hidden_binding_fixture(fixture, runs_per_case=2)
            wrong_classes = copy.deepcopy(fixture["cases"])
            wrong_classes[next(iter(wrong_classes))]["class"] = "adversarial"
            with self.assertRaisesRegex(BenchmarkError, "class accounting"):
                self._validate_hidden_binding_fixture(
                    fixture,
                    cases=wrong_classes,
                )

            lock = copy.deepcopy(fixture["hidden_suite_lock"])
            lock["systems"][0]["config_digest"] = "sha256:" + "f" * 64
            self._write_canonical_json(fixture["hidden_suite_lock_path"], lock)
            with self.assertRaisesRegex(BenchmarkError, "system identities"):
                self._validate_hidden_binding_fixture(fixture)
            fixture["hidden_suite_lock_path"].write_text(
                json.dumps(fixture["hidden_suite_lock"], indent=2),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(BenchmarkError, "canonical JSON"):
                self._validate_hidden_binding_fixture(fixture)
            with self.assertRaises(OSError):
                self._validate_hidden_binding_fixture(
                    fixture,
                    hidden_suite_lock_path=base / "missing-lock.json",
                )

    def test_hidden_binding_rejects_public_manifest_and_fixture_drift(self) -> None:
        mutations = {
            "missing": lambda manifest: manifest["entries"].pop(),
            "extra": lambda manifest: manifest["entries"].append(
                {
                    "id": "case-ffffffffffffffff",
                    "path": "cases/case-ffffffffffffffff/SKILL.md",
                    "sha256": "f" * 64,
                    "size": 1,
                }
            ),
            "duplicate": lambda manifest: manifest["entries"].__setitem__(
                -1,
                copy.deepcopy(manifest["entries"][0]),
            ),
            "path": lambda manifest: manifest["entries"][0].__setitem__(
                "path",
                "cases/wrong/SKILL.md",
            ),
            "size": lambda manifest: manifest["entries"][0].__setitem__(
                "size",
                manifest["entries"][0]["size"] + 1,
            ),
            "digest": lambda manifest: manifest["entries"][0].__setitem__(
                "sha256",
                "f" * 64,
            ),
        }
        for name, mutate in mutations.items():
            with (
                self.subTest(name=name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                    fixture = self._hidden_binding_fixture(Path(temporary))
                    manifest = copy.deepcopy(fixture["public_manifest"])
                    mutate(manifest)
                    fixture["public_manifest_path"].write_text(
                        json.dumps(manifest, sort_keys=True),
                        encoding="utf-8",
                    )
                    with self.assertRaises(BenchmarkError):
                        self._validate_hidden_binding_fixture(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._hidden_binding_fixture(Path(temporary))
            manifests = copy.deepcopy(fixture["manifests"])
            manifests[next(iter(manifests))]["files"].append(
                {
                    "path": "extra.txt",
                    "digest": "sha256:" + "f" * 64,
                    "size": 1,
                    "executable": False,
                }
            )
            with self.assertRaisesRegex(BenchmarkError, "does not match public"):
                self._validate_hidden_binding_fixture(
                    fixture,
                    manifests=manifests,
                )

    def test_v1_rejects_hidden_accounting_and_keeps_v1_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))
            report = evaluate_phase0(
                suite,
                outcomes,
                accounting,
                root,
                evidence_state=state,
            )
            hidden_base = Path(temporary) / "hidden"
            hidden_base.mkdir()
            hidden_suite, hidden_outcomes, hidden_accounting, hidden_root, hidden_state = (
                self._harness(hidden_base, split="hidden")
            )
            with self.assertRaisesRegex(BenchmarkError, "non-held-out case"):
                evaluate_phase0(
                    hidden_suite,
                    hidden_outcomes,
                    hidden_accounting,
                    hidden_root,
                    evidence_state=hidden_state,
                )

        self.assertEqual(report["schema"], "aragorn/benchmark-phase0-gate-report/v1")
        self.assertEqual(report["evaluation_split"], "held_out")
        self.assertEqual(
            _digest_json(report),
            "sha256:072fd0427f6a29af1d2d4cf90f57be432741123de0e0479a6c1d82085183cfd8",
        )
        self.assertEqual(
            set(report),
            {
                "schema",
                "assurance",
                "suite_id",
                "purpose",
                "suite_digest",
                "outcomes_digest",
                "benchmark_report_digest",
                "accounting_digest",
                "evaluation_split",
                "accounting",
                "comparison",
            },
        )

    def test_cli_phase0_gate_modes_are_mutually_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, _state = self._harness(Path(temporary))
            suite_path, outcomes_path, accounting_path = self._write_cli_inputs(
                root,
                suite,
                outcomes,
                accounting,
            )
            status, stdout, stderr = self._run_cli(
                (
                    str(suite_path),
                    str(outcomes_path),
                    "--phase0-accounting",
                    str(accounting_path),
                    "--phase0-hidden-gate",
                )
            )

        self.assertEqual(status, 4)
        self.assertEqual(stdout, "")
        self.assertIn("mutually exclusive", json.loads(stderr)["message"])

    def test_cli_runs_opt_in_phase0_gate_and_signals_pass_or_fail(self) -> None:
        for incomplete_case, expected_status in ((None, 0), ("benign-a", 2)):
            with self.subTest(incomplete_case=incomplete_case):
                with tempfile.TemporaryDirectory() as temporary:
                    base = Path(temporary)
                    suite, outcomes, accounting, root, state = self._harness(
                        base,
                        incomplete_case=incomplete_case,
                    )
                    suite_path, outcomes_path, accounting_path = self._write_cli_inputs(
                        root,
                        suite,
                        outcomes,
                        accounting,
                    )

                    status, stdout, stderr = self._run_cli(
                        (
                            str(suite_path),
                            str(outcomes_path),
                            "--state",
                            str(state),
                            "--phase0-accounting",
                            str(accounting_path),
                        )
                    )

                self.assertEqual(status, expected_status)
                self.assertEqual(stderr, "")
                report = json.loads(stdout)
                self.assertEqual(
                    report["schema"],
                    "aragorn/benchmark-phase0-gate-report/v1",
                )
                self.assertEqual(
                    report["comparison"]["passed"],
                    incomplete_case is None,
                )

    def test_cli_rejects_malformed_phase0_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            suite, outcomes, accounting, root, state = self._harness(base)
            suite_path, outcomes_path, accounting_path = self._write_cli_inputs(
                root,
                suite,
                outcomes,
                accounting,
            )
            accounting_path.write_text("{", encoding="utf-8")

            status, stdout, stderr = self._run_cli(
                (
                    str(suite_path),
                    str(outcomes_path),
                    "--state",
                    str(state),
                    "--phase0-accounting",
                    str(accounting_path),
                )
            )

        self.assertEqual(status, 4)
        self.assertEqual(stdout, "")
        error = json.loads(stderr)
        self.assertEqual(error["schema"], "aragorn/error/v1")
        self.assertIn("Phase 0 accounting sidecar", error["message"])

    def test_cli_without_accounting_keeps_the_ordinary_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            suite, outcomes, accounting, root, _state = self._harness(base)
            suite_path, outcomes_path, _accounting_path = self._write_cli_inputs(
                root,
                suite,
                outcomes,
                accounting,
            )

            status, stdout, stderr = self._run_cli(
                (str(suite_path), str(outcomes_path))
            )

        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(
            json.loads(stdout)["schema"],
            "aragorn/benchmark-report/v1",
        )

    def test_exact_thresholds_select_best_compliant_comparator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))

            report = evaluate_phase0(
                suite, outcomes, accounting, root, evidence_state=state
            )

        comparison = report["comparison"]
        self.assertEqual(report["assurance"], "comparative_metrics_only")
        self.assertTrue(comparison["evaluable"])
        self.assertTrue(comparison["passed"])
        self.assertEqual(
            comparison["selected_comparator"]["system"]["name"], "compliant"
        )
        self.assertEqual(comparison["candidate"]["benign_intervention"]["numerator"], 1)
        self.assertEqual(
            comparison["candidate"]["benign_intervention"]["denominator"], 20
        )
        self.assertEqual(comparison["attack_flag_delta"]["numerator"], 1)
        self.assertEqual(comparison["attack_flag_delta"]["denominator"], 10)
        comparators = {
            item["system"]["name"]: item for item in comparison["comparators"]
        }
        self.assertTrue(comparators["compliant"]["burden_compliant"])
        self.assertFalse(comparators["noisy"]["burden_compliant"])
        self.assertEqual(report["accounting"]["captured_references"], 3)
        self.assertEqual(report["accounting"]["source_reference_capture_rate"], 1.0)

    def test_no_burden_compliant_comparator_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))
            for outcome in outcomes:
                if (
                    outcome["system"]["name"] == "compliant"
                    and outcome["case_id"] == "benign-a"
                    and outcome["run_id"] == 2
                ):
                    outcome["verdict"] = "REVIEW"
                    outcome["reason_codes"] = ["TEST_REVIEW"]

            report = evaluate_phase0(
                suite, outcomes, accounting, root, evidence_state=state
            )
            suite_path, outcomes_path, accounting_path = self._write_cli_inputs(
                root,
                suite,
                outcomes,
                accounting,
            )
            status, stdout, stderr = self._run_cli(
                (
                    str(suite_path),
                    str(outcomes_path),
                    "--state",
                    str(state),
                    "--phase0-accounting",
                    str(accounting_path),
                )
            )

        comparison = report["comparison"]
        self.assertFalse(comparison["evaluable"])
        self.assertFalse(comparison["passed"])
        self.assertIsNone(comparison["selected_comparator"])
        self.assertIsNone(comparison["attack_flag_delta"])
        self.assertIn("NO_BURDEN_COMPLIANT_COMPARATOR", comparison["reason_codes"])
        self.assertTrue(comparison["pareto_frontier"])
        self.assertEqual(status, 2)
        self.assertEqual(stderr, "")
        self.assertFalse(json.loads(stdout)["comparison"]["evaluable"])

    def test_zero_comparators_never_becomes_a_zero_rate_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(
                Path(temporary), system_names=("aragorn",)
            )

            report = evaluate_phase0(
                suite, outcomes, accounting, root, evidence_state=state
            )

        comparison = report["comparison"]
        self.assertEqual(comparison["comparators"], [])
        self.assertEqual(comparison["pareto_frontier"], [])
        self.assertIsNone(comparison["selected_comparator"])
        self.assertIsNone(comparison["attack_flag_delta"])
        self.assertFalse(comparison["evaluable"])
        self.assertFalse(comparison["passed"])
        self.assertIn("NO_BURDEN_COMPLIANT_COMPARATOR", comparison["reason_codes"])

    def test_order_is_canonical_and_stale_or_missing_bindings_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))
            first = evaluate_phase0(
                suite, outcomes, accounting, root, evidence_state=state
            )
            reordered = copy.deepcopy(accounting)
            reordered["cases"].reverse()
            second = evaluate_phase0(
                suite, reversed(outcomes), reordered, root, evidence_state=state
            )
            self.assertEqual(first, second)

            missing = copy.deepcopy(accounting)
            missing["cases"].pop()
            with self.assertRaisesRegex(BenchmarkError, "matrix is incomplete"):
                evaluate_phase0(suite, outcomes, missing, root, evidence_state=state)

            stale = copy.deepcopy(accounting)
            stale["suite_digest"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(BenchmarkError, "suite_digest"):
                evaluate_phase0(suite, outcomes, stale, root, evidence_state=state)

            wrong_tree = copy.deepcopy(accounting)
            wrong_tree["cases"][0]["expansion_digest"] = wrong_tree["cases"][1][
                "expansion_digest"
            ]
            with self.assertRaisesRegex(BenchmarkError, "tree does not match"):
                evaluate_phase0(suite, outcomes, wrong_tree, root, evidence_state=state)

            missing_receipt = copy.deepcopy(accounting)
            missing_receipt["cases"][0]["expansion_digest"] = "sha256:" + "f" * 64
            with self.assertRaisesRegex(BenchmarkError, "unavailable or corrupt"):
                evaluate_phase0(
                    suite, outcomes, missing_receipt, root, evidence_state=state
                )

    def test_unresolved_opaque_and_budget_burden_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(
                Path(temporary), incomplete_case="benign-a"
            )

            report = evaluate_phase0(
                suite, outcomes, accounting, root, evidence_state=state
            )

        metrics = report["accounting"]
        self.assertEqual(metrics["complete_expansions"], 2)
        self.assertEqual(metrics["incomplete_expansions"], 1)
        self.assertEqual(metrics["unresolved_references"], 1)
        self.assertEqual(metrics["unresolved_expected_references"], 1)
        self.assertEqual(metrics["opaque_carriers"], 1)
        self.assertEqual(metrics["non_artifact_references"], 3)
        self.assertEqual(metrics["profile_artifact_references"], 3)
        self.assertEqual(metrics["unresolved_reference_rate"], round(1 / 3, 6))
        self.assertEqual(metrics["published_expanded_objects"], 2)
        self.assertEqual(metrics["attempted_expanded_objects"], 3)
        self.assertIn(
            {
                "reason_code": "EXPANDED_OBJECT_BUDGET_EXCEEDED",
                "cases": 1,
            },
            metrics["reason_counts"],
        )
        self.assertFalse(report["comparison"]["passed"])
        self.assertIn(
            "HELD_OUT_EXPANSION_INCOMPLETE",
            report["comparison"]["reason_codes"],
        )

    def test_candidate_allow_on_wrong_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))
            adversarial = next(
                item for item in accounting["cases"] if item["case_id"] == "adversarial"
            )
            adversarial["expected_references"][0]["target_digest"] = (
                "sha256:" + "0" * 64
            )

            with self.assertRaisesRegex(BenchmarkError, "cannot ALLOW"):
                evaluate_phase0(suite, outcomes, accounting, root, evidence_state=state)

    def test_false_root_and_expanded_git_blob_identities_are_rejected(self) -> None:
        for target in ("root", "expanded"):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as temporary,
            ):
                    suite, outcomes, accounting, root, state = self._harness(
                        Path(temporary)
                    )
                    cas = CAS(state)
                    binding = next(
                        item
                        for item in accounting["cases"]
                        if item["case_id"] == "benign-a"
                    )
                    expansion = json.loads(cas.read(binding["expansion_digest"]))
                    if target == "root":
                        root_manifest = json.loads(
                            cas.read(expansion["root_manifest_digest"])
                        )
                        root_manifest["files"][0]["git_blob_sha1"] = "0" * 40
                        expansion["root_manifest_digest"] = self._put_document(
                            cas, root_manifest
                        )
                    else:
                        expansion["objects"][0]["git_blob_sha1"] = "0" * 40
                    binding["expansion_digest"] = self._put_document(cas, expansion)

                    with self.assertRaisesRegex(
                        BenchmarkError,
                        "git_blob_sha1 does not match retained bytes",
                    ):
                        evaluate_phase0(
                            suite,
                            outcomes,
                            accounting,
                            root,
                            evidence_state=state,
                        )

    def test_root_manifest_contract_mutations_are_rejected(self) -> None:
        mutations = {
            "unknown field": (
                lambda manifest: manifest.__setitem__("unexpected", True),
                "missing or unknown fields",
            ),
            "hash algorithm": (
                lambda manifest: manifest["source"].__setitem__(
                    "repository_hash_algorithm", "sha256"
                ),
                "unsupported GitHub source metadata",
            ),
            "closure": (
                lambda manifest: manifest.__setitem__(
                    "closure", {"scope": "source_tree", "status": "incomplete"}
                ),
                "not a complete source tree",
            ),
            "root skill tree": (
                lambda manifest: manifest["source"].__setitem__("skill_path", "."),
                "skill_tree must equal commit_tree",
            ),
            "file executable": (
                lambda manifest: manifest["files"][0].__setitem__(
                    "executable", "false"
                ),
                "executable must be boolean",
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))
            cas = CAS(state)
            for name, (mutate, message) in mutations.items():
                with self.subTest(name=name):
                    bad_accounting = copy.deepcopy(accounting)
                    expansion = self._expansion(cas, bad_accounting)
                    root_manifest = json.loads(
                        cas.read(expansion["root_manifest_digest"])
                    )
                    mutate(root_manifest)
                    expansion["root_manifest_digest"] = self._put_document(
                        cas, root_manifest
                    )
                    self._replace_expansion(cas, bad_accounting, expansion)
                    with self.assertRaisesRegex(BenchmarkError, message):
                        evaluate_phase0(
                            suite,
                            outcomes,
                            bad_accounting,
                            root,
                            evidence_state=state,
                        )

    def test_expanded_object_reference_and_path_mutations_are_rejected(self) -> None:
        mutations = {
            "materialized path": (
                lambda expansion: expansion["objects"][0].__setitem__(
                    "materialized_path",
                    "__aragorn_expanded__/different/path.txt",
                ),
                "materialized_path does not match repository_path",
            ),
            "duplicate object reference": (
                lambda expansion: expansion["objects"][0]["references"].append(
                    dict(expansion["objects"][0]["references"][0])
                ),
                "duplicate identity",
            ),
            "object occurrence mismatch": (
                lambda expansion: expansion["objects"][0]["references"][0].__setitem__(
                    "literal_digest", "sha256:" + "0" * 64
                ),
                "do not exactly match top-level expanded occurrences",
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))
            cas = CAS(state)
            for name, (mutate, message) in mutations.items():
                with self.subTest(name=name):
                    bad_accounting = copy.deepcopy(accounting)
                    expansion = self._expansion(cas, bad_accounting)
                    mutate(expansion)
                    self._replace_expansion(cas, bad_accounting, expansion)
                    with self.assertRaisesRegex(BenchmarkError, message):
                        evaluate_phase0(
                            suite,
                            outcomes,
                            bad_accounting,
                            root,
                            evidence_state=state,
                        )

    def test_reference_occurrences_are_rederived_from_retained_source_bytes(
        self,
    ) -> None:
        mutations = (
            ("literal_digest", "sha256:" + "0" * 64, "literal digest"),
            ("literal_size", 1, "literal digest"),
            ("byte_offset", 0, "literal digest"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))
            cas = CAS(state)
            for field, value, message in mutations:
                with self.subTest(field=field):
                    bad_accounting = copy.deepcopy(accounting)
                    expansion = self._expansion(cas, bad_accounting)
                    identities = (
                        expansion["references"][0],
                        expansion["objects"][0]["references"][0],
                        bad_accounting["cases"][0]["expected_references"][0],
                    )
                    for identity in identities:
                        identity[field] = value
                    self._replace_expansion(cas, bad_accounting, expansion)

                    with self.assertRaisesRegex(BenchmarkError, message):
                        evaluate_phase0(
                            suite,
                            outcomes,
                            bad_accounting,
                            root,
                            evidence_state=state,
                        )

    def test_comparator_subject_rejects_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, _, accounting, _, state = self._harness(Path(temporary))
            cas = CAS(state)
            expansion = self._expansion(cas, accounting)
            subject = json.loads(
                cas.read(expansion["comparator_subject_manifest_digest"])
            )
            content = b"unbound comparator file\n"
            digest = self._put_bytes(cas, content)
            subject["files"].append(
                {
                    "path": "extra.txt",
                    "size": len(content),
                    "digest": digest,
                    "executable": False,
                }
            )
            subject["files"].sort(key=lambda item: item["path"])
            subject["tree_digest"] = canonical_digest(subject["files"])
            expansion["comparator_subject_manifest_digest"] = self._put_document(
                cas, subject
            )
            expansion["comparator_subject_tree_digest"] = subject["tree_digest"]
            expansion_digest = self._put_document(cas, expansion)

            with self.assertRaisesRegex(
                BenchmarkError,
                "file map does not exactly match the root and expanded objects",
            ):
                _load_phase0_expansion(
                    cas,
                    expansion_digest,
                    expected_tree_digest=subject["tree_digest"],
                    label="mutated comparator",
                )

    def test_complete_receipt_accounting_mutations_are_rejected(self) -> None:
        mutations = {
            "total edges": (
                lambda expansion: expansion["accounting"]["references"].__setitem__(
                    "total_edges", 2
                ),
                "total edge accounting is inconsistent",
            ),
            "reference budget": (
                lambda expansion: expansion["accounting"]["budgets"][
                    "references"
                ].__setitem__("used", 0),
                "reference budget is inconsistent",
            ),
            "retained bytes": (
                lambda expansion: expansion["accounting"]["budgets"][
                    "retained_bytes"
                ].__setitem__("used", 0),
                "retained byte accounting is inconsistent",
            ),
            "object count": (
                lambda expansion: expansion["accounting"]["budgets"][
                    "expanded_objects"
                ].__setitem__("used", 0),
                "understates objects",
            ),
            "expansion depth": (
                lambda expansion: expansion["accounting"]["budgets"][
                    "expansion_depth"
                ].__setitem__("used", 0),
                "depth accounting is inconsistent",
            ),
            "deduplication": (
                lambda expansion: expansion["accounting"]["references"].__setitem__(
                    "deduplicated", 1
                ),
                "deduplication accounting is inconsistent",
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))
            cas = CAS(state)
            for name, (mutate, message) in mutations.items():
                with self.subTest(name=name):
                    bad_accounting = copy.deepcopy(accounting)
                    expansion = self._expansion(cas, bad_accounting)
                    mutate(expansion)
                    self._replace_expansion(cas, bad_accounting, expansion)
                    with self.assertRaisesRegex(BenchmarkError, message):
                        evaluate_phase0(
                            suite,
                            outcomes,
                            bad_accounting,
                            root,
                            evidence_state=state,
                        )

    def test_scan_and_occurrence_completeness_contract_is_enforced(self) -> None:
        mutations = {
            "missing scan state": (
                lambda references: references.pop("scan_complete"),
                "missing or unknown fields",
            ),
            "complete occurrences after partial scan": (
                lambda references: references.__setitem__("scan_complete", False),
                "complete occurrences require a complete scan",
            ),
            "unknown omission after complete scan": (
                lambda references: references.update(
                    {
                        "occurrences_complete": False,
                        "occurrences_omitted": None,
                    }
                ),
                "incomplete occurrences omit no records",
            ),
            "known omission after partial scan": (
                lambda references: references.update(
                    {
                        "scan_complete": False,
                        "occurrences_complete": False,
                        "occurrences_omitted": 1,
                    }
                ),
                "incomplete scan must use an unknown omitted count",
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(Path(temporary))
            cas = CAS(state)
            for name, (mutate, message) in mutations.items():
                with self.subTest(name=name):
                    bad_accounting = copy.deepcopy(accounting)
                    expansion = self._expansion(cas, bad_accounting)
                    mutate(expansion["accounting"]["references"])
                    self._replace_expansion(cas, bad_accounting, expansion)
                    with self.assertRaisesRegex(BenchmarkError, message):
                        evaluate_phase0(
                            suite,
                            outcomes,
                            bad_accounting,
                            root,
                            evidence_state=state,
                        )

        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, accounting, root, state = self._harness(
                Path(temporary), incomplete_case="benign-a"
            )
            cas = CAS(state)
            expansion = self._expansion(cas, accounting)
            expansion["accounting"]["references"].update(
                {
                    "scan_complete": False,
                    "occurrences_complete": False,
                    "occurrences_omitted": None,
                }
            )
            self._replace_expansion(cas, accounting, expansion)

            report = evaluate_phase0(
                suite,
                outcomes,
                accounting,
                root,
                evidence_state=state,
            )

        self.assertEqual(report["accounting"]["incomplete_expansions"], 1)

    def _harness(
        self,
        base: Path,
        *,
        incomplete_case: str | None = None,
        system_names: tuple[str, ...] = ("aragorn", "compliant", "noisy"),
        split: str = "held_out",
        purpose: str = "contract_smoke",
    ) -> tuple[
        dict[str, object], list[dict[str, object]], dict[str, object], Path, Path
    ]:
        root = base / "suite"
        root.mkdir()
        state = base / "state"
        cas = CAS(state)
        systems = [self._system(name) for name in system_names]
        cases = []
        accounting_cases = []
        for case_id, case_class, family in (
            ("benign-a", "benign", "benign"),
            ("benign-b", "benign", "benign"),
            ("adversarial", "adversarial", "credential-exfiltration"),
        ):
            case, expansion_digest, expectation = self._case(
                root,
                cas,
                case_id,
                case_class,
                family,
                incomplete=case_id == incomplete_case,
                split=split,
            )
            cases.append(case)
            accounting_cases.append(
                {
                    "case_id": case_id,
                    "expansion_digest": expansion_digest,
                    "expected_references": [expectation],
                }
            )
        suite: dict[str, object] = {
            "schema": "aragorn/benchmark-suite/v1",
            "id": "phase0-test",
            "purpose": purpose,
            "runs_per_case": 10,
            "systems": systems,
            "cases": cases,
        }
        suite_digest = _digest_json(
            {
                **suite,
                "systems": sorted(
                    systems,
                    key=lambda item: (
                        item["name"],
                        item["version"],
                        item["implementation_digest"],
                        item["config_digest"],
                    ),
                ),
                "cases": sorted(cases, key=lambda item: item["id"]),
            }
        )
        outcomes = self._outcomes(
            suite,
            suite_digest,
            protected_case=incomplete_case,
        )
        accounting = {
            "schema": "aragorn/benchmark-phase0-accounting/v1",
            "suite_digest": suite_digest,
            "candidate_system": systems[0],
            "cases": accounting_cases,
        }
        return suite, outcomes, accounting, root, state

    @staticmethod
    def _hidden_binding_fixture(base: Path) -> dict[str, object]:
        corpus_lock_path = REPOSITORY_ROOT / "benchmark" / "phase0-corpus.lock.json"
        corpus_lock = json.loads(corpus_lock_path.read_text(encoding="utf-8"))
        public_manifest_digest = corpus_lock["public_manifest"]["sha256"]
        corpus_lock_digest = (
            "sha256:"
            + hashlib.sha256(corpus_lock_path.read_bytes()).hexdigest()
        )
        suite_digest = "sha256:" + "a" * 64
        candidate_policy_digest = "sha256:" + "9" * 64
        label_ledger_digest = "sha256:" + "8" * 64
        systems = [
            {
                "name": "aragorn",
                "version": "0.1.0-phase0",
                "implementation_digest": "sha256:" + "1" * 64,
                "config_digest": candidate_policy_digest,
            },
            {
                "name": "cisco-skill-scanner",
                "version": "2.0.12",
                "implementation_digest": "sha256:" + "2" * 64,
                "config_digest": "sha256:" + "3" * 64,
            },
            {
                "name": "skillspector",
                "version": "2.4.3+git.a54947c",
                "implementation_digest": "sha256:" + "4" * 64,
                "config_digest": "sha256:" + "5" * 64,
            },
        ]
        entries = []
        cases = {}
        manifests = {}
        for index in range(448):
            case_id = f"case-{index:016x}"
            content = f"# inert case {case_id}\n".encode()
            digest = hashlib.sha256(content).hexdigest()
            entries.append(
                {
                    "id": case_id,
                    "path": f"cases/{case_id}/SKILL.md",
                    "sha256": digest,
                    "size": len(content),
                }
            )
            cases[case_id] = {
                "class": "benign" if index < 336 else "adversarial",
                "split": "hidden",
            }
            manifests[case_id] = {
                "files": [
                    {
                        "path": "SKILL.md",
                        "digest": f"sha256:{digest}",
                        "size": len(content),
                        "executable": False,
                    }
                ]
            }
        public_manifest = {
            "schema_version": "1.0",
            "corpus_version": "independent-v1.0.0",
            "hash_algorithm": "sha256",
            "case_count": 448,
            "entries": entries,
        }
        public_manifest_path = base / "manifest.json"
        public_manifest_path.write_text(
            json.dumps(public_manifest, sort_keys=True),
            encoding="utf-8",
        )
        candidate_policy_path = base / "candidate-policy.json"
        candidate_policy_path.write_text("{}", encoding="utf-8")
        hidden_suite_lock = {
            "schema": "aragorn/benchmark-phase0-hidden-suite-lock/v1",
            "assurance": (
                "operator_asserted_pre_outcome_binding_"
                "not_independent_or_timestamped"
            ),
            "corpus_lock_digest": corpus_lock_digest,
            "worker_archive_digest": corpus_lock["worker_archive"]["sha256"],
            "public_manifest_digest": public_manifest_digest,
            "evaluator_archive_digest": corpus_lock["evaluator_archive"]["sha256"],
            "label_ledger_digest": label_ledger_digest,
            "candidate_policy_digest": candidate_policy_digest,
            "suite_digest": suite_digest,
            "case_count": 448,
            "class_counts": {"benign": 336, "adversarial": 112},
            "runs_per_case": 1,
            "split": "hidden",
            "systems": systems,
        }
        hidden_suite_lock_path = base / "hidden-suite-lock.json"
        Phase0GateTests._write_canonical_json(
            hidden_suite_lock_path,
            hidden_suite_lock,
        )
        return {
            "corpus_lock_path": corpus_lock_path,
            "public_manifest_path": public_manifest_path,
            "hidden_suite_lock_path": hidden_suite_lock_path,
            "candidate_policy_path": candidate_policy_path,
            "suite_digest": suite_digest,
            "runs_per_case": 1,
            "cases": cases,
            "systems": {
                (
                    system["name"],
                    system["version"],
                    system["implementation_digest"],
                    system["config_digest"],
                ): system
                for system in systems
            },
            "manifests": manifests,
            "public_manifest": public_manifest,
            "hidden_suite_lock": hidden_suite_lock,
            "candidate_policy": {
                "required_comparators": systems[1:],
            },
            "candidate_system": systems[0],
            "corpus_lock_digest": corpus_lock_digest,
            "public_manifest_digest": public_manifest_digest,
            "hidden_suite_lock_digest": (
                "sha256:"
                + hashlib.sha256(hidden_suite_lock_path.read_bytes()).hexdigest()
            ),
            "candidate_policy_digest": candidate_policy_digest,
            "label_ledger_digest": label_ledger_digest,
        }

    @staticmethod
    def _validate_hidden_binding_fixture(
        fixture: dict[str, object],
        **overrides: object,
    ) -> dict[str, str]:
        arguments = {
            key: fixture[key]
            for key in (
                "corpus_lock_path",
                "public_manifest_path",
                "hidden_suite_lock_path",
                "candidate_policy_path",
                "suite_digest",
                "runs_per_case",
                "cases",
                "systems",
                "manifests",
                "label_ledger_digest",
            )
        }
        arguments.update(overrides)
        real_digest_bytes = benchmark_module._digest_bytes

        def pinned_digest(content: bytes) -> str:
            try:
                document = json.loads(content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return real_digest_bytes(content)
            if isinstance(document, dict) and document.get("schema_version") == "1.0":
                return fixture["public_manifest_digest"]
            return real_digest_bytes(content)

        with (
            patch(
                "aragorn.benchmark._digest_bytes",
                side_effect=pinned_digest,
            ),
            patch(
                "aragorn.phase0_candidate.build_candidate_policy",
                return_value=fixture["candidate_policy"],
            ),
            patch(
                "aragorn.phase0_candidate.candidate_policy_digest",
                return_value=fixture["candidate_policy_digest"],
            ),
            patch(
                "aragorn.phase0_candidate.candidate_system_identity",
                return_value=fixture["candidate_system"],
            ),
        ):
            return _validate_phase0_hidden_binding(**arguments)

    @staticmethod
    def _write_canonical_json(path: Path, document: object) -> None:
        path.write_bytes(
            json.dumps(
                document,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        )

    @staticmethod
    def _hidden_report(
        suite: dict[str, object],
        outcomes: list[dict[str, object]],
        root: Path,
    ) -> dict[str, object]:
        benchmark_report = evaluate(suite, outcomes, root)
        benchmark_report["purpose"] = "evidence_smoke"
        systems = {
            (
                system["name"],
                system["version"],
                system["implementation_digest"],
                system["config_digest"],
            ): system
            for system in suite["systems"]
        }
        return _phase0_hidden_gate_report(
            benchmark_report=benchmark_report,
            systems=systems,
            binding={
                "corpus_lock_digest": "sha256:" + "0" * 64,
                "public_manifest_digest": "sha256:" + "1" * 64,
                "hidden_suite_lock_digest": "sha256:" + "2" * 64,
                "candidate_policy_digest": "sha256:" + "3" * 64,
                "label_ledger_digest": "sha256:" + "4" * 64,
            },
        )

    @staticmethod
    def _write_cli_inputs(
        root: Path,
        suite: object,
        outcomes: list[dict[str, object]],
        accounting: object,
    ) -> tuple[Path, Path, Path]:
        suite_path = root / "suite.json"
        outcomes_path = root / "outcomes.jsonl"
        accounting_path = root / "accounting.json"
        suite_path.write_text(
            json.dumps(suite, sort_keys=True),
            encoding="utf-8",
        )
        outcomes_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in outcomes),
            encoding="utf-8",
        )
        accounting_path.write_text(
            json.dumps(accounting, sort_keys=True),
            encoding="utf-8",
        )
        return suite_path, outcomes_path, accounting_path

    @staticmethod
    def _run_cli(arguments: tuple[str, ...]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = benchmark_main(arguments)
        return status, stdout.getvalue(), stderr.getvalue()

    def _case(
        self,
        root: Path,
        cas: CAS,
        case_id: str,
        case_class: str,
        family: str,
        *,
        incomplete: bool,
        split: str,
    ) -> tuple[dict[str, object], str, dict[str, object]]:
        source_repository_path = f"skills/{case_id}/SKILL.md"
        target_repository_path = f"payloads/{case_id}.txt"
        literal = target_repository_path.encode()
        source_content = b"# " + case_id.encode() + b"\nfetch exact " + literal + b"\n"
        payload_content = f"payload for {case_id}\n".encode()
        source_digest = self._put_bytes(cas, source_content)
        payload_digest = (
            "sha256:" + hashlib.sha256(payload_content).hexdigest()
            if incomplete
            else self._put_bytes(cas, payload_content)
        )
        literal_digest = (
            "sha256:" + hashlib.sha256(literal).hexdigest()
        )
        reference_identity = {
            "source_commit": COMMIT,
            "source_repository_path": source_repository_path,
            "source_blob_digest": source_digest,
            "byte_offset": source_content.index(literal),
            "literal_size": len(literal),
            "literal_digest": literal_digest,
        }
        root_files = [
            {
                "path": "SKILL.md",
                "size": len(source_content),
                "digest": source_digest,
                "executable": False,
            }
        ]
        root_tree_digest = canonical_digest(root_files)
        root_manifest = {
            "schema": "aragorn/github-manifest/v1",
            "source": {
                "kind": "github_commit",
                "host": "github.com",
                "owner": "example",
                "repository": "project",
                "commit": COMMIT,
                "repository_hash_algorithm": "sha1",
                "commit_tree": COMMIT_TREE,
                "skill_path": f"skills/{case_id}",
                "skill_tree": SKILL_TREE,
                "api_version": "2026-03-10",
            },
            "tree_digest": root_tree_digest,
            "files": [
                {
                    **root_files[0],
                    "git_blob_sha1": _git_blob_sha1(source_content),
                }
            ],
            "closure": {"scope": "source_tree", "status": "complete"},
        }
        root_manifest_digest = self._put_document(cas, root_manifest)

        fixture = root / case_id
        fixture.mkdir()
        (fixture / "SKILL.md").write_bytes(source_content)
        objects = []
        if incomplete:
            subject_manifest_digest = None
            subject_tree_digest = None
            reference = {
                **reference_identity,
                "target_commit": COMMIT,
                "target_repository_path": target_repository_path,
                "status": "unresolved",
                "reason_code": "EXPANDED_OBJECT_BUDGET_EXCEEDED",
            }
            reference_counts = {
                "total_edges": 4,
                "artifact_references": 1,
                "resolved_in_root": 0,
                "expanded": 0,
                "deduplicated": 0,
                "non_artifact": 3,
                "unresolved": 1,
                "opaque_carriers": 1,
                "scan_complete": True,
                "occurrences_complete": True,
                "occurrences_omitted": 0,
            }
            unresolved = [
                {
                    "reason_code": "EXPANDED_OBJECT_BUDGET_EXCEEDED",
                    "subject": target_repository_path,
                }
            ]
        else:
            materialized_path = f"__aragorn_expanded__/{target_repository_path}"
            destination = fixture / materialized_path
            destination.parent.mkdir(parents=True)
            destination.write_bytes(payload_content)
            subject_files = [
                root_files[0],
                {
                    "path": materialized_path,
                    "size": len(payload_content),
                    "digest": payload_digest,
                    "executable": False,
                },
            ]
            subject_files.sort(key=lambda item: item["path"])
            subject_manifest = {
                "schema": "aragorn/benchmark-subject-manifest/v1",
                "tree_digest": canonical_digest(subject_files),
                "files": subject_files,
            }
            subject_manifest_digest = self._put_document(cas, subject_manifest)
            subject_tree_digest = subject_manifest["tree_digest"]
            reference = {
                **reference_identity,
                "target_commit": COMMIT,
                "target_repository_path": target_repository_path,
                "status": "expanded",
                "reason_code": None,
            }
            objects = [
                {
                    "commit": COMMIT,
                    "commit_tree": COMMIT_TREE,
                    "repository_path": target_repository_path,
                    "materialized_path": materialized_path,
                    "depth": 1,
                    "size": len(payload_content),
                    "digest": payload_digest,
                    "git_blob_sha1": _git_blob_sha1(payload_content),
                    "executable": False,
                    "references": [reference_identity],
                }
            ]
            reference_counts = {
                "total_edges": 1,
                "artifact_references": 1,
                "resolved_in_root": 0,
                "expanded": 1,
                "deduplicated": 0,
                "non_artifact": 0,
                "unresolved": 0,
                "opaque_carriers": 0,
                "scan_complete": True,
                "occurrences_complete": True,
                "occurrences_omitted": 0,
            }
            unresolved = []
        tree_digest = inventory_local(fixture)["tree_digest"]
        self.assertEqual(
            tree_digest,
            subject_tree_digest if not incomplete else root_tree_digest,
        )
        budgets = {
            "api_requests": {"limit": 20, "used": 5},
            "api_bytes": {"limit": 10000, "used": 1000},
            "retained_bytes": {
                "limit": 10000,
                "used": len(source_content) + len(payload_content),
            },
            "expanded_objects": {"limit": 1, "used": 1},
            "expansion_depth": {"limit": 4, "used": 1},
            "references": {"limit": 10, "used": 1},
        }
        expansion = {
            "schema": "aragorn/github-expansion/v1",
            "profile": "phase0-exact-github-blob-expansion/v1",
            "assurance": (
                "evaluation_only_github_api_membership_asserted_"
                "blob_identity_reverified"
            ),
            "source": {
                "host": "github.com",
                "owner": "example",
                "repository": "project",
                "commit": COMMIT,
                "commit_tree": COMMIT_TREE,
                "skill_path": f"skills/{case_id}",
                "api_version": "2026-03-10",
            },
            "root_manifest_digest": root_manifest_digest,
            "root_tree_digest": root_tree_digest,
            "comparator_subject_manifest_digest": subject_manifest_digest,
            "comparator_subject_tree_digest": subject_tree_digest,
            "references": [reference],
            "objects": objects,
            "accounting": {
                "references": reference_counts,
                "budgets": budgets,
            },
            "closure": {
                "scope": "phase0_exact_github_blob_expansion",
                "status": "incomplete" if incomplete else "complete",
                "unresolved": unresolved,
            },
        }
        expansion_digest = self._put_document(cas, expansion)
        case = {
            "schema": "aragorn/benchmark-case/v1",
            "id": case_id,
            "class": case_class,
            "family": family,
            "lineage": f"{case_id}-lineage",
            "split": split,
            "path": case_id,
            "tree_digest": tree_digest,
            "inert": True,
            "source": {
                "kind": "synthetic",
                "reference": f"phase0-test/{case_id}",
                "license": "CC0-1.0",
            },
        }
        expectation = {
            **reference_identity,
            "target_commit": COMMIT,
            "target_repository_path": target_repository_path,
            "target_digest": payload_digest,
        }
        return case, expansion_digest, expectation

    def _outcomes(
        self,
        suite: dict[str, object],
        suite_digest: str,
        *,
        protected_case: str | None,
    ) -> list[dict[str, object]]:
        outcomes = []
        for system in suite["systems"]:
            for case in suite["cases"]:
                for run_id in range(1, 11):
                    if case["class"] == "benign":
                        reviews = {"aragorn": 1, "compliant": 1, "noisy": 2}[
                            system["name"]
                        ]
                        if system["name"] == "aragorn" and case["id"] == protected_case:
                            reviews = 10
                        verdict = (
                            "REVIEW"
                            if case["id"] == "benign-a" and run_id <= reviews
                            else "ALLOW"
                        )
                    else:
                        reviews = {"aragorn": 8, "compliant": 7, "noisy": 10}[
                            system["name"]
                        ]
                        verdict = "REVIEW" if run_id <= reviews else "ALLOW"
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
                                    "case": case["id"],
                                    "run": run_id,
                                    "system": system["name"],
                                }
                            ),
                            "verdict": verdict,
                            "reason_codes": (
                                ["TEST_REVIEW"] if verdict == "REVIEW" else []
                            ),
                        }
                    )
        return outcomes

    @staticmethod
    def _system(name: str) -> dict[str, str]:
        return {
            "name": name,
            "version": "1",
            "implementation_digest": _digest_json({"implementation": name}),
            "config_digest": _digest_json({"configuration": name}),
        }

    @staticmethod
    def _put_bytes(cas: CAS, content: bytes) -> str:
        return cas.put(BytesIO(content), max_bytes=len(content))

    @staticmethod
    def _put_document(cas: CAS, document: object) -> str:
        raw = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return cas.put(BytesIO(raw), max_bytes=len(raw))

    @staticmethod
    def _expansion(
        cas: CAS,
        accounting: dict[str, object],
        *,
        case_id: str = "benign-a",
    ) -> dict[str, object]:
        binding = next(
            item for item in accounting["cases"] if item["case_id"] == case_id
        )
        return json.loads(cas.read(binding["expansion_digest"]))

    def _replace_expansion(
        self,
        cas: CAS,
        accounting: dict[str, object],
        expansion: dict[str, object],
        *,
        case_id: str = "benign-a",
    ) -> None:
        binding = next(
            item for item in accounting["cases"] if item["case_id"] == case_id
        )
        binding["expansion_digest"] = self._put_document(cas, expansion)


if __name__ == "__main__":
    unittest.main()
