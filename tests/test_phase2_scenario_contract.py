from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from aragorn.phase2_scenario_contract import (
    CATALOG_ASSURANCE,
    CATALOG_SCHEMA,
    COVERAGE_LOCK_ASSURANCE,
    COVERAGE_LOCK_SCHEMA,
    PUBLIC_FIXTURE_COMMIT,
    REMOTE_CATALOG_SCHEMA,
    REMOTE_COVERAGE_LOCK_ASSURANCE,
    REMOTE_COVERAGE_LOCK_SCHEMA,
    REMOTE_TRACE_PROFILE,
    REMOTE_TRACE_RECEIPT_SCHEMA,
    RUN_SCHEDULE,
    SCENARIO_ENVIRONMENT_VARIABLE,
    SCENARIO_PROFILE,
    Phase2ScenarioContractError,
    scenario_for_run,
    validate_phase2_remote_catalog,
    validate_phase2_remote_coverage_lock,
    validate_phase2_scenario_catalog,
    validate_phase2_scenario_coverage_lock,
)

ROOT = Path(__file__).resolve().parents[1]


class Phase2ScenarioContractTests(unittest.TestCase):
    def test_exact_catalog_and_coverage_lock_bind_the_fixed_matrix(self) -> None:
        catalog = self._catalog()
        coverage = self._coverage_lock(catalog)

        self.assertEqual(validate_phase2_scenario_catalog(catalog), RUN_SCHEDULE)
        self.assertEqual(validate_phase2_scenario_coverage_lock(coverage), RUN_SCHEDULE)
        self.assertEqual(
            tuple(scenario_for_run(run_id) for run_id in range(1, 6)),
            RUN_SCHEDULE,
        )
        self.assertEqual(catalog["source"]["commit"], PUBLIC_FIXTURE_COMMIT)

    def test_schedule_source_profiles_and_case_set_fail_closed(self) -> None:
        catalog = self._catalog()
        coverage = self._coverage_lock(catalog)
        variants = []

        changed_schedule = copy.deepcopy(catalog)
        changed_schedule["scenario_matrix"]["run_schedule"][0] = "alternate"
        variants.append((validate_phase2_scenario_catalog, changed_schedule))

        old_source = copy.deepcopy(catalog)
        old_source["source"]["commit"] = "0" * 40
        variants.append((validate_phase2_scenario_catalog, old_source))

        short_catalog = copy.deepcopy(catalog)
        short_catalog["cases"].pop()
        variants.append((validate_phase2_scenario_catalog, short_catalog))

        old_runtime = copy.deepcopy(coverage)
        old_runtime["gvisor"]["receipt_schema"] = (
            "aragorn/gvisor-acquired-artifact-receipt/v4"
        )
        variants.append((validate_phase2_scenario_coverage_lock, old_runtime))

        repeated_case = copy.deepcopy(coverage)
        repeated_case["cases"][1]["case_id"] = repeated_case["cases"][0]["case_id"]
        variants.append((validate_phase2_scenario_coverage_lock, repeated_case))

        for validator, document in variants:
            with (
                self.subTest(validator=validator.__name__),
                self.assertRaises(Phase2ScenarioContractError),
            ):
                validator(document)

        for run_id in (False, 0, 6, "1"):
            with (
                self.subTest(run_id=run_id),
                self.assertRaises(Phase2ScenarioContractError),
            ):
                scenario_for_run(run_id)

    def test_v3_binds_remote_trace_without_widening_v2(self) -> None:
        catalog = self._remote_catalog()
        coverage = self._coverage_lock(catalog, remote=True)

        self.assertEqual(catalog["schema"], REMOTE_CATALOG_SCHEMA)
        self.assertEqual(validate_phase2_remote_catalog(catalog), RUN_SCHEDULE)
        self.assertEqual(validate_phase2_remote_coverage_lock(coverage), RUN_SCHEDULE)
        with self.assertRaises(Phase2ScenarioContractError):
            validate_phase2_scenario_catalog(catalog)
        with self.assertRaises(Phase2ScenarioContractError):
            validate_phase2_scenario_coverage_lock(coverage)

        variants = []
        wrong_schema = copy.deepcopy(catalog)
        wrong_schema["candidate"]["config"]["remote_trace_receipt_schema"] = (
            "aragorn/gvisor-remote-trace-capture-receipt/v1"
        )
        variants.append((validate_phase2_remote_catalog, wrong_schema))

        wrong_profile = copy.deepcopy(coverage)
        wrong_profile["gvisor"]["remote_trace_profile"] = "dynamic/v1"
        variants.append((validate_phase2_remote_coverage_lock, wrong_profile))

        missing_binding = copy.deepcopy(coverage)
        del missing_binding["gvisor"]["remote_trace_receipt_schema"]
        variants.append((validate_phase2_remote_coverage_lock, missing_binding))

        for validator, document in variants:
            with (
                self.subTest(validator=validator.__name__),
                self.assertRaises(Phase2ScenarioContractError),
            ):
                validator(document)

    def test_v1_catalog_is_rejected_without_mutation(self) -> None:
        v1 = json.loads(
            (ROOT / "benchmark" / "phase2-matrix-catalog-v1.json").read_bytes()
        )
        original = copy.deepcopy(v1)
        with self.assertRaises(Phase2ScenarioContractError):
            validate_phase2_scenario_catalog(v1)
        self.assertEqual(v1, original)

    @staticmethod
    def _scenario_matrix() -> dict[str, object]:
        return {
            "profile": SCENARIO_PROFILE,
            "environment_variable": SCENARIO_ENVIRONMENT_VARIABLE,
            "run_schedule": list(RUN_SCHEDULE),
        }

    def _catalog(self) -> dict[str, object]:
        catalog = json.loads(
            (ROOT / "benchmark" / "phase2-matrix-catalog-v1.json").read_bytes()
        )
        catalog["schema"] = CATALOG_SCHEMA
        catalog["assurance"] = CATALOG_ASSURANCE
        catalog["source"]["commit"] = PUBLIC_FIXTURE_COMMIT
        catalog["candidate"]["config"]["gvisor_receipt_schema"] = (
            "aragorn/gvisor-acquired-artifact-receipt/v5"
        )
        catalog["candidate"]["config"]["execution_profile"] = "bounded-single-script/v2"
        catalog["scenario_matrix"] = self._scenario_matrix()
        return catalog

    @staticmethod
    def _remote_catalog() -> dict[str, object]:
        return json.loads(
            (ROOT / "benchmark" / "phase2-matrix-catalog-v3.json").read_bytes()
        )

    def _coverage_lock(
        self, catalog: dict[str, object], *, remote: bool = False
    ) -> dict[str, object]:
        digest = "sha256:" + "1" * 64
        gvisor = {
            "receipt_schema": "aragorn/gvisor-acquired-artifact-receipt/v5",
            "normalization_profile": "successful-openat-execve-attributed/v1",
            "execution_profile": "bounded-single-script/v2",
            "lock_digest": "sha256:" + "4" * 64,
            "verifier_implementation_digest": "sha256:" + "5" * 64,
        }
        if remote:
            gvisor.update(
                {
                    "remote_trace_receipt_schema": REMOTE_TRACE_RECEIPT_SCHEMA,
                    "remote_trace_profile": REMOTE_TRACE_PROFILE,
                }
            )
        return {
            "schema": (REMOTE_COVERAGE_LOCK_SCHEMA if remote else COVERAGE_LOCK_SCHEMA),
            "assurance": (
                REMOTE_COVERAGE_LOCK_ASSURANCE if remote else COVERAGE_LOCK_ASSURANCE
            ),
            "suite_digest": digest,
            "evaluation_split": "held_out",
            "runs_per_case": 5,
            "candidate_system": {
                "name": "aragorn",
                "version": catalog["candidate"]["version"],
                "implementation_digest": "sha256:" + "2" * 64,
                "config_digest": "sha256:" + "3" * 64,
            },
            "verdict_profile": "undeclared-observed-review/v1",
            "gvisor": gvisor,
            "scenario_matrix": self._scenario_matrix(),
            "cases": [
                {
                    "case_id": case["case_id"],
                    "class": case["class"],
                    "family": case["family"],
                    "lineage": case["lineage"],
                    "tree_digest": digest,
                    "suite_manifest_digest": digest,
                    "source_manifest_digest": digest,
                    "quarantine_receipt_digest": digest,
                    "gateway_profile_digest": digest,
                    "entrypoint_path": "run.sh",
                    "entrypoint_digest": digest,
                    "declared_capabilities": case["declared_capabilities"],
                }
                for case in catalog["cases"]
            ],
        }


if __name__ == "__main__":
    unittest.main()
