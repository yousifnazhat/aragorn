from __future__ import annotations

import json
import unittest
from pathlib import Path

SCHEMA_DIRECTORY = Path(__file__).parents[1] / "schema"
EXPECTED_CONTRACTS = {
    "analyzer-request-v1.schema.json": "aragorn/analyzer-request/v1",
    "analyzers-v1.schema.json": "aragorn/analyzers/v1",
    "baseline-image-verification-v1.schema.json": "aragorn/baseline-image-verification/v1",
    "baseline-lock-v1.schema.json": "aragorn/baseline-lock/v1",
    "benchmark-cas-handoff-v1.schema.json": "aragorn/benchmark-cas-handoff/v1",
    "benchmark-authenticated-worker-evidence-v1.schema.json": "aragorn/benchmark-authenticated-worker-evidence/v1",
    "benchmark-candidate-composition-v1.schema.json": "aragorn/benchmark-candidate-composition/v1",
    "benchmark-candidate-composition-smoke-receipt-v1.schema.json": "aragorn/benchmark-candidate-composition-smoke-receipt/v1",
    "benchmark-candidate-evidence-v1.schema.json": "aragorn/benchmark-candidate-evidence/v1",
    "benchmark-candidate-evidence-v2.schema.json": "aragorn/benchmark-candidate-evidence/v2",
    "benchmark-candidate-policy-v1.schema.json": "aragorn/benchmark-candidate-policy/v1",
    "benchmark-candidate-policy-v2.schema.json": "aragorn/benchmark-candidate-policy/v2",
    "benchmark-collection-v1.schema.json": "aragorn/benchmark-collection/v1",
    "benchmark-collection-result-v1.schema.json": "aragorn/benchmark-collection-result/v1",
    "benchmark-corpus-provenance-lock-v1.schema.json": "aragorn/benchmark-corpus-provenance-lock/v1",
    "benchmark-e2e-smoke-receipt-v1.schema.json": "aragorn/benchmark-e2e-smoke-receipt/v1",
    "benchmark-evidence-v1.schema.json": "aragorn/benchmark-evidence/v1",
    "benchmark-evidence-v2.schema.json": "aragorn/benchmark-evidence/v2",
    "benchmark-evidence-v3.schema.json": "aragorn/benchmark-evidence/v3",
    "benchmark-evidence-v4.schema.json": "aragorn/benchmark-evidence/v4",
    "benchmark-isolated-smoke-receipt-v1.schema.json": "aragorn/benchmark-isolated-smoke-receipt/v1",
    "benchmark-oci-system-config-v1.schema.json": "aragorn/benchmark-oci-system-config/v1",
    "benchmark-oci-system-config-v2.schema.json": "aragorn/benchmark-oci-system-config/v2",
    "benchmark-outcome-v1.schema.json": "aragorn/benchmark-outcome/v1",
    "benchmark-phase0-accounting-v1.schema.json": "aragorn/benchmark-phase0-accounting/v1",
    "benchmark-phase0-gate-report-v1.schema.json": "aragorn/benchmark-phase0-gate-report/v1",
    "benchmark-phase0-gate-report-v2.schema.json": "aragorn/benchmark-phase0-gate-report/v2",
    "benchmark-phase0-hidden-suite-freeze-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v1",
    "benchmark-phase0-hidden-suite-freeze-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v2",
    "benchmark-phase0-hidden-preparation-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-preparation-receipt/v1",
    "benchmark-phase0-hidden-preparation-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-preparation-receipt/v2",
    "benchmark-phase0-hidden-worker-run-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v1",
    "benchmark-phase0-hidden-worker-run-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v2",
    "benchmark-phase0-hidden-suite-lock-v1.schema.json": "aragorn/benchmark-phase0-hidden-suite-lock/v1",
    "benchmark-portable-policy-v1.schema.json": "aragorn/benchmark-portable-policy/v1",
    "benchmark-private-dispatch-v1.schema.json": "aragorn/benchmark-private-dispatch/v1",
    "benchmark-private-dispatch-v2.schema.json": "aragorn/benchmark-private-dispatch/v2",
    "benchmark-prepare-result-v1.schema.json": "aragorn/benchmark-prepare-result/v1",
    "benchmark-prepare-result-v2.schema.json": "aragorn/benchmark-prepare-result/v2",
    "benchmark-report-v1.schema.json": "aragorn/benchmark-report/v1",
    "benchmark-subject-manifest-v1.schema.json": "aragorn/benchmark-subject-manifest/v1",
    "benchmark-suite-v1.schema.json": "aragorn/benchmark-suite/v1",
    "benchmark-system-config-v1.schema.json": "aragorn/benchmark-system-config/v1",
    "benchmark-system-identities-v1.schema.json": "aragorn/benchmark-system-identities/v1",
    "benchmark-worker-request-v1.schema.json": "aragorn/benchmark-worker-request/v1",
    "benchmark-worker-request-v2.schema.json": "aragorn/benchmark-worker-request/v2",
    "benchmark-worker-result-v1.schema.json": "aragorn/benchmark-worker-result/v1",
    "benchmark-worker-result-v2.schema.json": "aragorn/benchmark-worker-result/v2",
    "benchmark-worker-supervisor-result-v1.schema.json": "aragorn/benchmark-worker-supervisor-result/v1",
    "benchmark-worker-measurement-v1.schema.json": "aragorn/benchmark-worker-measurement/v1",
    "benchmark-worker-measurement-issuance-v1.schema.json": "aragorn/benchmark-worker-measurement-issuance/v1",
    "benchmark-worker-output-acceptance-v1.schema.json": "aragorn/benchmark-worker-output-acceptance/v1",
    "benchmark-worker-trust-store-v1.schema.json": "aragorn/benchmark-worker-trust-store/v1",
    "benchmark-worker-worklist-v1.schema.json": "aragorn/benchmark-worker-worklist/v1",
    "benchmark-worker-nonce-batch-v1.schema.json": "aragorn/benchmark-worker-nonce-batch/v1",
    "benchmark-worker-nonce-consumption-v1.schema.json": "aragorn/benchmark-worker-nonce-consumption/v1",
    "benchmark-worker-output-closure-v1.schema.json": "aragorn/benchmark-worker-output-closure/v1",
    "corpus-audit-v1.schema.json": "aragorn/corpus-audit/v1",
    "decision-v1.schema.json": "aragorn/decision/v1",
    "error-v1.schema.json": "aragorn/error/v1",
    "github-expansion-result-v1.schema.json": "aragorn/github-expansion-result/v1",
    "github-expansion-v1.schema.json": "aragorn/github-expansion/v1",
    "github-manifest-v1.schema.json": "aragorn/github-manifest/v1",
    "inspect-result-v1.schema.json": "aragorn/inspect-result/v1",
    "inventory-result-v1.schema.json": "aragorn/inventory-result/v1",
    "manifest-v1.schema.json": "aragorn/manifest/v1",
    "observation-v1.schema.json": "aragorn/observation/v1",
    "phase0-standards-gate-v1.schema.json": "aragorn/phase0-standards-gate/v1",
    "resolve-artifacts-result-v1.schema.json": "aragorn/resolve-artifacts-result/v1",
    "source-artifact-graph-v1.schema.json": "aragorn/source-artifact-graph/v1",
}


class SchemaTests(unittest.TestCase):
    def test_every_phase_zero_contract_has_a_parseable_schema(self) -> None:
        self.assertEqual(
            {path.name for path in SCHEMA_DIRECTORY.glob("*.json")},
            set(EXPECTED_CONTRACTS),
        )
        for filename, identifier in EXPECTED_CONTRACTS.items():
            with self.subTest(filename=filename):
                document = json.loads((SCHEMA_DIRECTORY / filename).read_text())
                self.assertEqual(
                    document["$schema"],
                    "https://json-schema.org/draft/2020-12/schema",
                )
                self.assertEqual(document["properties"]["schema"]["const"], identifier)

    def test_baseline_lock_binds_closure_candidates_but_not_runner_attestation(
        self,
    ) -> None:
        lock = json.loads(
            (SCHEMA_DIRECTORY.parent / "benchmark" / "baselines.lock.json").read_text()
        )
        self.assertEqual(lock["schema"], "aragorn/baseline-lock/v1")
        baselines = {item["name"]: item for item in lock["baselines"]}
        self.assertEqual(
            baselines["cisco-skill-scanner"]["commit"],
            "605afdc5c7ea887c07e2afeb0fadc1452c07bfa7",
        )
        self.assertEqual(
            baselines["skillspector"]["commit"],
            "a54947c307fe19a24a43db55f6148e181a987a67",
        )
        self.assertEqual(
            {item["attestation_status"] for item in baselines.values()},
            {"oci_closure_candidate_runner_attestation_pending"},
        )
        self.assertEqual(
            {item["profile"]["network"] for item in baselines.values()}, {"deny"}
        )
        self.assertEqual(
            {item["runtime_profile"]["network"] for item in baselines.values()},
            {"none"},
        )
        self.assertEqual(
            {
                item["runtime_profile"]["read_only_rootfs"]
                for item in baselines.values()
            },
            {True},
        )
        self.assertEqual(
            {item["image"]["architecture"] for item in baselines.values()},
            {"arm64"},
        )


if __name__ == "__main__":
    unittest.main()
