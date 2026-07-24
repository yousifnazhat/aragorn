from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
import unittest


import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from aragorn.acquire import inventory_local
from aragorn.benchmark import (
    BenchmarkError,
    _digest_json,
    _load_phase0_expansion,
    evaluate_phase0,
    main as benchmark_main,
)
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest


COMMIT = "a" * 40
COMMIT_TREE = "b" * 40
SKILL_TREE = "c" * 40


def _git_blob_sha1(content: bytes) -> str:
    header = b"blob " + str(len(content)).encode("ascii") + b"\0"
    return hashlib.sha1(header + content).hexdigest()


class Phase0GateTests(unittest.TestCase):
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
            with self.subTest(target=target):
                with tempfile.TemporaryDirectory() as temporary:
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
            "purpose": "contract_smoke",
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
    ) -> tuple[dict[str, object], str, dict[str, object]]:
        source_content = f"# {case_id}\nfetch exact payload\n".encode()
        payload_content = f"payload for {case_id}\n".encode()
        source_digest = self._put_bytes(cas, source_content)
        payload_digest = (
            "sha256:" + hashlib.sha256(payload_content).hexdigest()
            if incomplete
            else self._put_bytes(cas, payload_content)
        )
        source_repository_path = f"skills/{case_id}/SKILL.md"
        target_repository_path = f"payloads/{case_id}.txt"
        literal_digest = (
            "sha256:" + hashlib.sha256(target_repository_path.encode()).hexdigest()
        )
        reference_identity = {
            "source_repository_path": source_repository_path,
            "source_blob_digest": source_digest,
            "byte_offset": 0,
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
                "target_repository_path": target_repository_path,
                "status": "expanded",
                "reason_code": None,
            }
            objects = [
                {
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
            "split": "held_out",
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
