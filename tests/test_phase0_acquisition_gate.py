from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from aragorn.benchmark import _canonical_json_bytes, _digest_json, _system_key
from aragorn.cas import CAS
from aragorn.github_expand import ASSURANCE, PROFILE
from scripts.phase0_acquisition_gate import (
    AcquisitionGateError,
    EXPANSION_ASSURANCE,
    EXPANSION_PROFILE,
    ORACLE_SCHEMA,
    REPORT_SCHEMA,
    _policy,
    _require_authenticated_arm_evidence,
    build_lock,
    evaluate_pair,
    main,
)

ROOT = Path(__file__).parents[1]
POLICY = ROOT / "benchmark" / "phase0-candidate-policy-v7.json"
V7_IMPLEMENTATION_DIGEST = (
    "sha256:f42095ad5f4f66e372aceff560bd80b3"
    "abdf5e6998f8853014a45e77ebed1895"
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


class Phase0AcquisitionGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        historical_identity = patch(
            "aragorn.phase0_candidate.candidate_implementation_digest",
            return_value=V7_IMPLEMENTATION_DIGEST,
        )
        historical_identity.start()
        cls.addClassCleanup(historical_identity.stop)
        cls.policy = _policy(POLICY)

    def test_cli_requires_explicit_candidate_policy(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = main(["freeze", "oracle.json", "root.json", "expanded.json"])

        self.assertEqual(status, 4)
        self.assertIn("--candidate-policy", stderr.getvalue())

    def test_cli_requires_both_authenticated_acceptance_ledgers(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = main(
                [
                    "evaluate",
                    "oracle.json",
                    "lock.json",
                    "root.json",
                    "root.jsonl",
                    "expanded.json",
                    "expanded.jsonl",
                    "accounting.json",
                    "--state",
                    "state",
                    "--candidate-policy",
                    str(POLICY),
                ]
            )

        self.assertEqual(status, 4)
        self.assertIn("--root-acceptance-ledger", stderr.getvalue())
        self.assertIn("--expanded-acceptance-ledger", stderr.getvalue())

    def test_arm_evidence_must_use_authenticated_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cas = CAS(root / "state")
            outcome_path = root / "outcomes.jsonl"
            comparator = self.policy["comparators"][0]

            def retain(schema: str, system: dict[str, str]) -> None:
                evidence = json.dumps(
                    {"schema": schema},
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
                evidence_digest = cas.put(
                    io.BytesIO(evidence),
                    max_bytes=len(evidence),
                )
                outcome_path.write_text(
                    json.dumps(
                        {
                            "system": system,
                            "evidence_digest": evidence_digest,
                        },
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )

            retain("aragorn/benchmark-evidence/v3", comparator)
            with self.assertRaisesRegex(
                AcquisitionGateError, "authenticated worker evidence"
            ):
                _require_authenticated_arm_evidence(
                    outcome_path,
                    CAS(root / "state", read_only=True),
                    candidate_system=self.policy["candidate"],
                    expanded=False,
                )

            retain(
                "aragorn/benchmark-authenticated-worker-evidence/v1",
                comparator,
            )
            _require_authenticated_arm_evidence(
                outcome_path,
                CAS(root / "state", read_only=True),
                candidate_system=self.policy["candidate"],
                expanded=False,
            )

            retain(
                "aragorn/benchmark-candidate-evidence/v2",
                self.policy["candidate"],
            )
            _require_authenticated_arm_evidence(
                outcome_path,
                CAS(root / "state", read_only=True),
                candidate_system=self.policy["candidate"],
                expanded=True,
            )

    def test_paired_gate_uses_root_comparators_and_expanded_candidate(self) -> None:
        fixture = self._fixture()
        report = evaluate_pair(**fixture)

        self.assertEqual(report["schema"], REPORT_SCHEMA)
        self.assertTrue(report["comparison"]["passed"])
        self.assertEqual(
            report["comparison"]["attack_flag_delta"],
            {"numerator": 23, "denominator": 112, "rate": 0.205357},
        )
        self.assertEqual(
            report["comparison"]["selected_comparator"]["system"]["name"],
            "skillspector",
        )
        self.assertEqual(fixture["lock"]["case_count"], 448)
        self.assertEqual(
            fixture["lock"]["class_counts"],
            {"adversarial": 112, "benign": 336},
        )
        self.assertEqual(fixture["lock"]["lineage_count"], 448)
        self.assertEqual(sum(fixture["lock"]["family_counts"].values()), 448)
        report_schema = json.loads(
            (
                ROOT
                / "schema"
                / "benchmark-phase0-gate-report-v1.schema.json"
            ).read_bytes()
        )
        self.assertEqual(
            set(report["accounting"]),
            set(report_schema["$defs"]["accounting"]["required"]),
        )
        example = (
            ROOT / "benchmark" / "phase0-acquisition-gate-report-v1.example.json"
        ).read_bytes()
        self.assertEqual(example[-1:], b"\n")
        self.assertEqual(_canonical_json_bytes(report), example[:-1])

    def test_freeze_rejects_swapped_arms(self) -> None:
        fixture = self._fixture()
        oracle = copy.deepcopy(fixture["oracle"])
        oracle["root_suite_digest"], oracle["expanded_suite_digest"] = (
            oracle["expanded_suite_digest"],
            oracle["root_suite_digest"],
        )

        with self.assertRaisesRegex(AcquisitionGateError, "root arm"):
            build_lock(
                oracle,
                fixture["expanded_suite"],
                fixture["root_suite"],
                self.policy,
            )

    def test_evaluation_rejects_oracle_drift_after_freeze(self) -> None:
        fixture = self._fixture()
        fixture["oracle"]["cases"][0]["source"]["commit"] = "f" * 40

        with self.assertRaisesRegex(AcquisitionGateError, "not bound"):
            evaluate_pair(**fixture)

    def test_freeze_rejects_suite_mutation(self) -> None:
        fixture = self._fixture()
        fixture["root_suite"]["digest"] = _digest("f")

        with self.assertRaisesRegex(AcquisitionGateError, "root suite digest"):
            build_lock(
                fixture["oracle"],
                fixture["root_suite"],
                fixture["expanded_suite"],
                self.policy,
            )

    def test_freeze_rejects_unbound_suite_source_and_duplicate_lineage(self) -> None:
        fixture = self._fixture()
        for suite_name in ("root_suite", "expanded_suite"):
            fixture[suite_name]["cases"]["benign-000"]["source"][
                "reference"
            ] = "phase0-github-source:" + _digest("f")
        with self.assertRaisesRegex(AcquisitionGateError, "not bound"):
            build_lock(
                fixture["oracle"],
                fixture["root_suite"],
                fixture["expanded_suite"],
                self.policy,
            )

        fixture = self._fixture()
        fixture["oracle"]["cases"][1]["lineage"] = fixture["oracle"]["cases"][0][
            "lineage"
        ]
        with self.assertRaisesRegex(AcquisitionGateError, "lineages must be unique"):
            build_lock(
                fixture["oracle"],
                fixture["root_suite"],
                fixture["expanded_suite"],
                self.policy,
            )

    def test_freeze_rejects_noncanonical_github_source(self) -> None:
        for field, value in (
            ("owner", "Example"),
            ("owner", "example-"),
            ("repository", "."),
            ("repository", ".."),
            ("repository", "project.git"),
        ):
            with self.subTest(field=field, value=value):
                fixture = self._fixture()
                fixture["oracle"]["cases"][0]["source"][field] = value
                with self.assertRaisesRegex(ValueError, field):
                    build_lock(
                        fixture["oracle"],
                        fixture["root_suite"],
                        fixture["expanded_suite"],
                        self.policy,
                    )

    def test_freeze_rejects_identical_root_and_expanded_tree(self) -> None:
        fixture = self._fixture()
        fixture["oracle"]["cases"][0]["expanded_tree_digest"] = fixture[
            "oracle"
        ]["cases"][0]["root_tree_digest"]

        with self.assertRaisesRegex(AcquisitionGateError, "must differ"):
            build_lock(
                fixture["oracle"],
                fixture["root_suite"],
                fixture["expanded_suite"],
                self.policy,
            )

    def test_freeze_rejects_missing_reference_or_case_pair(self) -> None:
        fixture = self._fixture()
        missing_reference = copy.deepcopy(fixture["oracle"])
        missing_reference["cases"][0]["expected_references"] = []
        with self.assertRaisesRegex(AcquisitionGateError, "must not be empty"):
            build_lock(
                missing_reference,
                fixture["root_suite"],
                fixture["expanded_suite"],
                self.policy,
            )

        missing_case = copy.deepcopy(fixture["expanded_suite"])
        missing_case["cases"].pop("adversarial-000")
        with self.assertRaisesRegex(AcquisitionGateError, "pairing is incomplete"):
            build_lock(
                fixture["oracle"],
                fixture["root_suite"],
                missing_case,
                self.policy,
            )

    def test_evaluation_rejects_reference_source_and_budget_drift(self) -> None:
        for target, message in (
            ("reference", "oracle references changed"),
            ("source", "source changed"),
            ("budget", "resource budgets changed"),
        ):
            with self.subTest(target=target):
                fixture = self._fixture()
                if target == "reference":
                    fixture["accounting"]["cases"][0]["expected_references"][0][
                        "target_digest"
                    ] = _digest("f")
                elif target == "source":
                    fixture["expansion_records"]["benign-000"]["source"][
                        "commit"
                    ] = "f" * 40
                else:
                    fixture["expansion_records"]["benign-000"]["accounting"][
                        "budgets"
                    ]["references"]["limit"] += 1
                fixture["expanded_report"]["accounting_digest"] = _digest_json(
                    self._canonical_accounting(
                        fixture["accounting"], fixture["expanded_suite"]
                    )
                )
                with self.assertRaisesRegex(AcquisitionGateError, message):
                    evaluate_pair(**fixture)

    def test_incomplete_expansion_fails_closed(self) -> None:
        fixture = self._fixture()
        fixture["expansion_records"]["benign-000"]["closure"][
            "status"
        ] = "incomplete"

        with self.assertRaisesRegex(AcquisitionGateError, "is incomplete"):
            evaluate_pair(**fixture)

    def test_evaluation_requires_a_retained_expected_expansion(self) -> None:
        for mutation in ("root_resolved", "missing_object", "wrong_digest"):
            with self.subTest(mutation=mutation):
                fixture = self._fixture()
                record = fixture["expansion_records"]["benign-000"]
                if mutation == "root_resolved":
                    record["references"][0]["status"] = "root_resolved"
                elif mutation == "missing_object":
                    record["objects"] = []
                else:
                    record["objects"][0]["digest"] = _digest("f")

                with self.assertRaisesRegex(
                    AcquisitionGateError, "no retained expected expansion"
                ):
                    evaluate_pair(**fixture)

    def test_evaluation_rejects_nonterminal_expansion_contract(self) -> None:
        fixture = self._fixture()
        fixture["expansion_records"]["benign-000"]["profile"] = PROFILE
        fixture["expansion_records"]["benign-000"]["assurance"] = ASSURANCE

        with self.assertRaisesRegex(
            AcquisitionGateError, "expansion contract changed"
        ):
            evaluate_pair(**fixture)

        fixture = self._fixture()
        fixture["accounting"]["expansion_profile"] = PROFILE
        fixture["accounting"]["expansion_assurance"] = ASSURANCE
        with self.assertRaisesRegex(
            AcquisitionGateError, "accounting expansion contract changed"
        ):
            evaluate_pair(**fixture)

        fixture = self._fixture()
        fixture["oracle"]["budgets"]["expansion_depth"] = 2
        with self.assertRaisesRegex(
            AcquisitionGateError, "requires expansion_depth=1"
        ):
            build_lock(
                fixture["oracle"],
                fixture["root_suite"],
                fixture["expanded_suite"],
                self.policy,
            )

    def _fixture(self) -> dict[str, object]:
        root_cases = self._cases(expanded=False)
        expanded_cases = self._cases(expanded=True)
        root_suite = self._suite(root_cases, expanded=False)
        expanded_suite = self._suite(expanded_cases, expanded=True)
        case_ids = list(root_cases)
        references = {
            case_id: [self._reference(case_id)]
            for case_id in case_ids
        }
        budgets = {
            "api_requests": 20_050,
            "api_bytes": 402_653_184,
            "retained_bytes": 134_217_728,
            "expanded_objects": 256,
            "expansion_depth": 1,
            "references": 10_000,
        }
        oracle = {
            "schema": ORACLE_SCHEMA,
            "root_suite_digest": root_suite["digest"],
            "expanded_suite_digest": expanded_suite["digest"],
            "split": "held_out",
            "runs_per_case": 1,
            "candidate_system": self.policy["candidate"],
            "comparators": self.policy["comparators"],
            "expansion_profile": EXPANSION_PROFILE,
            "expansion_assurance": EXPANSION_ASSURANCE,
            "budgets": budgets,
            "cases": [
                {
                    "case_id": case_id,
                    "class": root_cases[case_id]["class"],
                    "family": root_cases[case_id]["family"],
                    "lineage": root_cases[case_id]["lineage"],
                    "root_tree_digest": root_cases[case_id]["tree_digest"],
                    "expanded_tree_digest": expanded_cases[case_id]["tree_digest"],
                    "source": self._source(case_id),
                    "expected_references": copy.deepcopy(references[case_id]),
                }
                for case_id in case_ids
            ],
        }
        lock = build_lock(oracle, root_suite, expanded_suite, self.policy)
        accounting = {
            "schema": "aragorn/benchmark-phase0-accounting/v1",
            "suite_digest": expanded_suite["digest"],
            "candidate_system": self.policy["candidate"],
            "expansion_profile": EXPANSION_PROFILE,
            "expansion_assurance": EXPANSION_ASSURANCE,
            "cases": [
                {
                    "case_id": case_id,
                    "expansion_digest": _digest_text(f"expansion:{case_id}"),
                    "expected_references": copy.deepcopy(references[case_id]),
                }
                for case_id in case_ids
            ],
        }
        expansion_records = {}
        for case_id in case_ids:
            expected_reference = references[case_id][0]
            target_path = expected_reference["target_repository_path"]
            target_digest = expected_reference["target_digest"]
            expansion_records[case_id] = {
                "profile": EXPANSION_PROFILE,
                "assurance": EXPANSION_ASSURANCE,
                "source": self._source(case_id),
                "root_tree_digest": root_cases[case_id]["tree_digest"],
                "comparator_subject_tree_digest": expanded_cases[case_id][
                    "tree_digest"
                ],
                "references": [
                    {
                        key: expected_reference[key]
                        for key in (
                            "source_commit",
                            "source_repository_path",
                            "source_blob_digest",
                            "byte_offset",
                            "literal_size",
                            "literal_digest",
                            "target_commit",
                            "target_repository_path",
                        )
                    }
                    | {"status": "expanded", "reason_code": None}
                ],
                "objects": [
                    {
                        "commit": expected_reference["target_commit"],
                        "repository_path": target_path,
                        "digest": target_digest,
                    }
                ],
                "_target_digests": {
                    (expected_reference["target_commit"], target_path): target_digest
                },
                "closure": {"status": "complete"},
                "accounting": {
                    "budgets": {
                        name: {"limit": limit, "used": 1}
                        for name, limit in budgets.items()
                    }
                },
            }
        root_report = self._root_report(root_suite["digest"])
        canonical_accounting = self._canonical_accounting(
            accounting, expanded_suite
        )
        expanded_report = {
            "suite_digest": expanded_suite["digest"],
            "outcomes_digest": _digest("6"),
            "benchmark_report_digest": _digest("7"),
            "accounting_digest": _digest_json(canonical_accounting),
            "accounting": {
                "cases": 448,
                "complete_expansions": 448,
                "incomplete_expansions": 0,
                "expansion_success_rate": 1.0,
                "incomplete_cases": 0,
                "expected_references": 448,
                "captured_references": 448,
                "missed_references": 0,
                "wrong_target_references": 0,
                "unresolved_expected_references": 0,
                "source_reference_capture_rate": 1.0,
                "profile_artifact_references": 448,
                "unresolved_references": 0,
                "non_artifact_references": 0,
                "unresolved_cases": 0,
                "unresolved_reference_rate": 0.0,
                "opaque_carriers": 0,
                "published_expanded_objects": 448,
                "attempted_expanded_objects": 448,
                "budgets": {
                    name: {
                        "limit": limit,
                        "used": 1,
                        "utilization_rate": round(1 / limit, 6),
                    }
                    for name, limit in budgets.items()
                },
                "reason_counts": [],
            },
            "comparison": {
                "candidate": {
                    "system": self.policy["candidate"],
                    "benign_intervention": {
                        "numerator": 0,
                        "denominator": 336,
                        "rate": 0.0,
                    },
                    "adversarial_flag": {
                        "numerator": 90,
                        "denominator": 112,
                        "rate": 0.803571,
                    },
                    "burden_compliant": True,
                }
            },
        }
        return {
            "oracle": oracle,
            "lock": lock,
            "root_suite": root_suite,
            "expanded_suite": expanded_suite,
            "policy": self.policy,
            "accounting": accounting,
            "expansion_records": expansion_records,
            "root_report": root_report,
            "expanded_report": expanded_report,
        }

    def _cases(self, *, expanded: bool) -> dict[str, dict[str, object]]:
        case_definitions = [
            (f"benign-{index:03d}", "benign", "benign")
            for index in range(336)
        ]
        case_definitions.extend(
            (
                f"adversarial-{index:03d}",
                "adversarial",
                f"acquisition-path-{index % 8:02d}",
            )
            for index in range(112)
        )
        return {
            case_id: {
                "id": case_id,
                "class": case_class,
                "family": family,
                "lineage": f"{case_id}-lineage",
                "split": "held_out",
                "source": {
                    "kind": "synthetic",
                    "reference": (
                        "phase0-github-source:"
                        + _digest_json(self._source(case_id))
                    ),
                    "license": "CC0-1.0",
                },
                "tree_digest": _digest_text(
                    f"{case_id}:{'expanded' if expanded else 'root'}"
                ),
            }
            for case_id, case_class, family in case_definitions
        }

    def _suite(
        self,
        cases: dict[str, dict[str, object]],
        *,
        expanded: bool,
    ) -> dict[str, object]:
        systems = [
            *self.policy["comparators"],
            *([self.policy["candidate"]] if expanded else []),
        ]
        return {
            "digest": _digest("2" if expanded else "1"),
            "purpose": "evidence_smoke",
            "runs_per_case": 1,
            "cases": cases,
            "systems": {_system_key(system): system for system in systems},
        }

    @staticmethod
    def _source(case_id: str) -> dict[str, str]:
        return {
            "host": "github.com",
            "owner": "example",
            "repository": "project",
            "commit": hashlib.sha1(f"{case_id}:commit".encode()).hexdigest(),
            "commit_tree": hashlib.sha1(
                f"{case_id}:commit-tree".encode()
            ).hexdigest(),
            "skill_path": f"skills/{case_id}",
            "api_version": "2026-03-10",
        }

    @staticmethod
    def _reference(case_id: str) -> dict[str, object]:
        literal = f"payloads/{case_id}.txt"
        commit = hashlib.sha1(f"{case_id}:commit".encode()).hexdigest()
        return {
            "source_commit": commit,
            "source_repository_path": f"skills/{case_id}/SKILL.md",
            "source_blob_digest": _digest_text(f"{case_id}:source"),
            "byte_offset": 0,
            "literal_size": len(literal.encode()),
            "literal_digest": _digest_text(literal),
            "target_commit": commit,
            "target_repository_path": literal,
            "target_digest": _digest_text(f"{case_id}:target"),
        }

    @staticmethod
    def _root_report(suite_digest: str) -> dict[str, object]:
        reports = []
        for system, flagged in zip(
            Phase0AcquisitionGateTests.policy["comparators"],
            (56, 67),
            strict=True,
        ):
            reports.append(
                {
                    "system": system,
                    "splits": [
                        {
                            "split": "held_out",
                            "summary": {
                                "class_verdicts": {
                                    "benign": {
                                        "ALLOW": 336,
                                        "REVIEW": 0,
                                        "DENY": 0,
                                        "ERROR": 0,
                                    },
                                    "adversarial": {
                                        "ALLOW": 112 - flagged,
                                        "REVIEW": flagged,
                                        "DENY": 0,
                                        "ERROR": 0,
                                    },
                                },
                                "benign_intervened": 0,
                                "adversarial_flagged": flagged,
                            },
                        }
                    ],
                }
            )
        return {
            "suite_digest": suite_digest,
            "outcomes_digest": _digest("5"),
            "systems": reports,
        }

    @staticmethod
    def _canonical_accounting(
        accounting: dict[str, object],
        expanded_suite: dict[str, object],
    ) -> dict[str, object]:
        from aragorn.benchmark import _validate_phase0_accounting

        return _validate_phase0_accounting(
            accounting,
            suite_digest=expanded_suite["digest"],
            cases=expanded_suite["cases"],
            systems=expanded_suite["systems"],
        )[2]


if __name__ == "__main__":
    unittest.main()
