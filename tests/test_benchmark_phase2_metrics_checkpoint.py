from __future__ import annotations

import copy
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn.acquire import inventory_local
from aragorn.benchmark import BenchmarkError, _digest_json, evaluate, main
from aragorn.cas import CAS

_EMPTY_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


class Phase2MetricsCheckpointTests(unittest.TestCase):
    def test_exact_attack_family_and_agreement_thresholds_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = self._harness(
                Path(temporary), benign=2, families=("family-a", "family-b")
            )
            self._verdict(outcomes, "attack-0", 5, "ALLOW")
            report = self._evaluate(suite, outcomes, root, state)

        self.assertTrue(report["decision"]["metrics_passed"])
        self.assertEqual(
            report["schema"], "aragorn/benchmark-phase2-metrics-checkpoint/v1"
        )
        self.assertEqual(
            report["assurance"],
            "declared_unfrozen_held_out_five_run_metrics_only",
        )
        self.assertFalse(report["phase2_exit_eligible"])
        self.assertEqual(
            report["missing_phase2_exit_requirements"],
            [
                "ATTRIBUTED_DETONATION_EVIDENCE_REQUIRED",
                "CAPTURE_COMPLETENESS_REQUIRED",
                "FROZEN_COVERAGE_AND_CANDIDATE_LOCK_REQUIRED",
                "QUALIFIED_ISOLATED_BACKEND_REQUIRED",
                "VARIED_SCENARIO_MATRIX_REQUIRED",
            ],
        )
        self.assertEqual(
            report["observed"]["adversarial_flag"],
            {"numerator": 9, "denominator": 10},
        )
        self.assertEqual(
            report["observed"]["families"][0]["adversarial_flag"],
            {"numerator": 4, "denominator": 5},
        )
        self.assertEqual(
            report["observed"]["verdict_agreement"],
            {"numerator": 19, "denominator": 20},
        )

    def test_exact_benign_intervention_threshold_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = self._harness(
                Path(temporary), benign=4, families=("family-a",)
            )
            self._verdict(outcomes, "benign-0", 5, "REVIEW")
            report = self._evaluate(suite, outcomes, root, state)

        self.assertTrue(report["decision"]["metrics_passed"])
        self.assertEqual(
            report["observed"]["benign_intervention"],
            {"numerator": 1, "denominator": 20},
        )

    def test_threshold_and_error_failures_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            suite, outcomes, root, state = self._harness(
                base, benign=2, families=("family-a", "family-b")
            )
            weak = copy.deepcopy(outcomes)
            self._verdict(weak, "attack-0", 4, "ALLOW")
            self._verdict(weak, "attack-0", 5, "ALLOW")
            weak_report = self._evaluate(suite, weak, root, state)
            self.assertEqual(
                weak_report["decision"]["reason_codes"],
                [
                    "ADVERSARIAL_FLAG_RATE_BELOW_90_PERCENT",
                    "ATTACK_FAMILY_FLAG_RATE_BELOW_80_PERCENT",
                    "VERDICT_AGREEMENT_BELOW_95_PERCENT",
                ],
            )

            unstable = copy.deepcopy(outcomes)
            self._verdict(unstable, "attack-0", 5, "ALLOW")
            self._verdict(unstable, "attack-1", 5, "DENY")
            unstable_report = self._evaluate(suite, unstable, root, state)
            self.assertEqual(
                unstable_report["decision"]["reason_codes"],
                ["VERDICT_AGREEMENT_BELOW_95_PERCENT"],
            )

        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = self._harness(
                Path(temporary), benign=4, families=("family-a",)
            )
            burden = copy.deepcopy(outcomes)
            self._verdict(burden, "benign-0", 4, "REVIEW")
            self._verdict(burden, "benign-0", 5, "REVIEW")
            burden_report = self._evaluate(suite, burden, root, state)
            self.assertIn(
                "BENIGN_INTERVENTION_RATE_ABOVE_5_PERCENT",
                burden_report["decision"]["reason_codes"],
            )

            errored = copy.deepcopy(outcomes)
            self._verdict(errored, "benign-0", 5, "ERROR")
            error_report = self._evaluate(suite, errored, root, state)
            self.assertEqual(
                error_report["decision"]["reason_codes"],
                ["ERROR_OUTCOMES_PRESENT", "VERDICT_AGREEMENT_NOT_EVALUABLE"],
            )
            self.assertFalse(error_report["decision"]["evaluable"])
            self.assertIsNone(error_report["observed"]["verdict_agreement"])

    def test_checkpoint_contract_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            suite, outcomes, root, state = self._harness(
                base, benign=1, families=("family-a",)
            )
            no_held_out = copy.deepcopy(suite)
            for case in no_held_out["cases"]:
                case["split"] = "development"
            self._rebind(no_held_out, outcomes)
            report = self._evaluate(no_held_out, outcomes, root, state)
            self.assertEqual(report["decision"]["reason_codes"], ["NO_HELD_OUT_SPLIT"])
            self.assertFalse(report["decision"]["metrics_passed"])

            for purpose, runs, message in (
                ("contract_smoke", 5, "requires evidence_smoke"),
                ("evidence_smoke", 4, "requires exactly five runs"),
            ):
                with self.subTest(purpose=purpose, runs=runs):
                    changed = copy.deepcopy(suite)
                    changed["purpose"] = purpose
                    changed["runs_per_case"] = runs
                    with self.assertRaisesRegex(BenchmarkError, message):
                        self._evaluate(changed, (), root, state)

            no_candidate = copy.deepcopy(suite)
            no_candidate["systems"][0]["name"] = "other"
            no_candidate_outcomes = self._outcomes(no_candidate)
            with self.assertRaisesRegex(BenchmarkError, "exactly one Aragorn"):
                self._evaluate(no_candidate, no_candidate_outcomes, root, state)

            two_candidates = copy.deepcopy(suite)
            second = copy.deepcopy(two_candidates["systems"][0])
            second["implementation_digest"] = "sha256:" + "2" * 64
            two_candidates["systems"].append(second)
            with self.assertRaisesRegex(BenchmarkError, "exactly one Aragorn"):
                self._evaluate(
                    two_candidates,
                    self._outcomes(two_candidates),
                    root,
                    state,
                )

    def test_cli_returns_metric_pass_and_failure_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = self._harness(
                Path(temporary), benign=2, families=("family-a", "family-b")
            )
            suite_path = root / "suite.json"
            outcomes_path = root / "outcomes.jsonl"
            suite_path.write_text(json.dumps(suite), encoding="utf-8")
            outcomes_path.write_text(
                "".join(json.dumps(outcome) + "\n" for outcome in outcomes),
                encoding="utf-8",
            )
            argv = (
                str(suite_path),
                str(outcomes_path),
                "--state",
                str(state),
                "--phase2-metrics-checkpoint",
            )
            with (
                patch("aragorn.benchmark._verify_evidence", return_value=None),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(main(argv), 0)

            self._verdict(outcomes, "attack-0", 4, "ALLOW")
            self._verdict(outcomes, "attack-0", 5, "ALLOW")
            outcomes_path.write_text(
                "".join(json.dumps(outcome) + "\n" for outcome in outcomes),
                encoding="utf-8",
            )
            with (
                patch("aragorn.benchmark._verify_evidence", return_value=None),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(main(argv), 2)

    @classmethod
    def _harness(
        cls,
        base: Path,
        *,
        benign: int,
        families: tuple[str, ...],
    ) -> tuple[dict[str, object], list[dict[str, object]], Path, Path]:
        root = base / "suite"
        root.mkdir()
        state = base / "state"
        CAS(state)
        system = {
            "name": "aragorn",
            "version": "1",
            "implementation_digest": "sha256:" + "1" * 64,
            "config_digest": _EMPTY_DIGEST,
        }
        cases = [
            cls._case(root, f"benign-{index}", "benign", "benign")
            for index in range(benign)
        ]
        cases.extend(
            cls._case(root, f"attack-{index}", "adversarial", family)
            for index, family in enumerate(families)
        )
        suite = {
            "schema": "aragorn/benchmark-suite/v1",
            "id": "phase2-test",
            "purpose": "evidence_smoke",
            "runs_per_case": 5,
            "systems": [system],
            "cases": cases,
        }
        return suite, cls._outcomes(suite), root, state

    @staticmethod
    def _case(
        root: Path, case_id: str, case_class: str, family: str
    ) -> dict[str, object]:
        fixture = root / case_id
        fixture.mkdir()
        (fixture / "SKILL.md").write_text(case_id + "\n", encoding="utf-8")
        return {
            "schema": "aragorn/benchmark-case/v1",
            "id": case_id,
            "class": case_class,
            "family": family,
            "lineage": case_id,
            "split": "held_out",
            "path": case_id,
            "tree_digest": inventory_local(fixture)["tree_digest"],
            "inert": True,
            "source": {
                "kind": "synthetic",
                "reference": "unit-test",
                "license": "CC0-1.0",
            },
        }

    @classmethod
    def _outcomes(cls, suite: dict[str, object]) -> list[dict[str, object]]:
        digest = cls._suite_digest(suite)
        return [
            {
                "schema": "aragorn/benchmark-outcome/v1",
                "suite_digest": digest,
                "case_id": case["id"],
                "tree_digest": case["tree_digest"],
                "run_id": run_id,
                "system": copy.deepcopy(system),
                "evidence_digest": _digest_json(
                    {"case": case["id"], "run": run_id, "system": system}
                ),
                "verdict": "ALLOW" if case["class"] == "benign" else "REVIEW",
                "reason_codes": []
                if case["class"] == "benign"
                else ["SYNTHETIC_MARKER"],
            }
            for system in suite["systems"]
            for case in suite["cases"]
            for run_id in range(1, suite["runs_per_case"] + 1)
        ]

    @staticmethod
    def _suite_digest(suite: dict[str, object]) -> str:
        return _digest_json(
            {
                **suite,
                "systems": sorted(
                    suite["systems"],
                    key=lambda system: tuple(system.values()),
                ),
                "cases": sorted(suite["cases"], key=lambda case: case["id"]),
            }
        )

    @classmethod
    def _rebind(
        cls, suite: dict[str, object], outcomes: list[dict[str, object]]
    ) -> None:
        digest = cls._suite_digest(suite)
        for outcome in outcomes:
            outcome["suite_digest"] = digest

    @staticmethod
    def _verdict(
        outcomes: list[dict[str, object]], case_id: str, run_id: int, verdict: str
    ) -> None:
        outcome = next(
            item
            for item in outcomes
            if item["case_id"] == case_id and item["run_id"] == run_id
        )
        outcome["verdict"] = verdict
        outcome["reason_codes"] = [] if verdict == "ALLOW" else [f"SYNTHETIC_{verdict}"]

    @staticmethod
    def _evaluate(
        suite: dict[str, object],
        outcomes: object,
        root: Path,
        state: Path,
    ) -> dict[str, object]:
        with patch("aragorn.benchmark._verify_evidence", return_value=None):
            return evaluate(
                suite,
                outcomes,
                root,
                evidence_state=state,
                phase2_metrics_checkpoint=True,
            )


if __name__ == "__main__":
    unittest.main()
