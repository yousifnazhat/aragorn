from __future__ import annotations

import hashlib
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
    "benchmark-candidate-policy-v3.schema.json": "aragorn/benchmark-candidate-policy/v3",
    "benchmark-collection-v1.schema.json": "aragorn/benchmark-collection/v1",
    "benchmark-collection-result-v1.schema.json": "aragorn/benchmark-collection-result/v1",
    "benchmark-corpus-provenance-lock-v1.schema.json": "aragorn/benchmark-corpus-provenance-lock/v1",
    "benchmark-corpus-provenance-lock-v2.schema.json": "aragorn/benchmark-corpus-provenance-lock/v2",
    "benchmark-e2e-smoke-receipt-v1.schema.json": "aragorn/benchmark-e2e-smoke-receipt/v1",
    "benchmark-evidence-v1.schema.json": "aragorn/benchmark-evidence/v1",
    "benchmark-evidence-v2.schema.json": "aragorn/benchmark-evidence/v2",
    "benchmark-evidence-v3.schema.json": "aragorn/benchmark-evidence/v3",
    "benchmark-evidence-v4.schema.json": "aragorn/benchmark-evidence/v4",
    "benchmark-isolated-smoke-receipt-v1.schema.json": "aragorn/benchmark-isolated-smoke-receipt/v1",
    "benchmark-oci-system-config-v1.schema.json": "aragorn/benchmark-oci-system-config/v1",
    "benchmark-oci-system-config-v2.schema.json": "aragorn/benchmark-oci-system-config/v2",
    "benchmark-outcome-v1.schema.json": "aragorn/benchmark-outcome/v1",
    "benchmark-phase0-acquisition-gate-report-v1.schema.json": "aragorn/benchmark-phase0-acquisition-gate-report/v1",
    "benchmark-phase0-acquisition-corpus-lock-v1.schema.json": "aragorn/benchmark-phase0-acquisition-corpus-lock/v1",
    "benchmark-phase0-acquisition-oracle-lock-v1.schema.json": "aragorn/benchmark-phase0-acquisition-oracle-lock/v1",
    "benchmark-phase0-acquisition-oracle-v1.schema.json": "aragorn/benchmark-phase0-acquisition-oracle/v1",
    "benchmark-phase0-accounting-v1.schema.json": "aragorn/benchmark-phase0-accounting/v1",
    "benchmark-phase0-gate-report-v1.schema.json": "aragorn/benchmark-phase0-gate-report/v1",
    "benchmark-phase0-gate-report-v2.schema.json": "aragorn/benchmark-phase0-gate-report/v2",
    "benchmark-phase0-hidden-calibration-result-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-calibration-result-receipt/v1",
    "benchmark-phase0-hidden-calibration-result-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-calibration-result-receipt/v2",
    "benchmark-phase0-hidden-result-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-result-receipt/v1",
    "benchmark-phase0-hidden-result-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-result-receipt/v2",
    "benchmark-phase0-hidden-suite-freeze-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v1",
    "benchmark-phase0-hidden-suite-freeze-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v2",
    "benchmark-phase0-hidden-suite-freeze-receipt-v3.schema.json": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v3",
    "benchmark-phase0-hidden-suite-freeze-receipt-v4.schema.json": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v4",
    "benchmark-phase0-hidden-suite-freeze-receipt-v5.schema.json": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v5",
    "benchmark-phase0-hidden-suite-freeze-receipt-v6.schema.json": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v6",
    "benchmark-phase0-hidden-preparation-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-preparation-receipt/v1",
    "benchmark-phase0-hidden-preparation-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-preparation-receipt/v2",
    "benchmark-phase0-hidden-preparation-receipt-v3.schema.json": "aragorn/benchmark-phase0-hidden-preparation-receipt/v3",
    "benchmark-phase0-hidden-preparation-receipt-v4.schema.json": "aragorn/benchmark-phase0-hidden-preparation-receipt/v4",
    "benchmark-phase0-hidden-preparation-receipt-v5.schema.json": "aragorn/benchmark-phase0-hidden-preparation-receipt/v5",
    "benchmark-phase0-hidden-worker-run-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v1",
    "benchmark-phase0-hidden-worker-run-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v2",
    "benchmark-phase0-hidden-worker-run-receipt-v3.schema.json": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v3",
    "benchmark-phase0-hidden-worker-run-receipt-v4.schema.json": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v4",
    "benchmark-phase0-hidden-worker-run-receipt-v5.schema.json": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v5",
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

    def test_v6_corpus_and_freeze_schema_pin_external_reference(self) -> None:
        root = SCHEMA_DIRECTORY.parent
        lock_raw = (root / "benchmark" / "phase0-corpus-v6.lock.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(lock_raw).hexdigest(),
            "12bda81360181b5c81a9483d861c681efd40083913d3e4c6c4d835814d6c192d",
        )
        lock = json.loads(lock_raw)
        self.assertEqual(
            lock["reference"],
            {
                "corpus_id": "local-v5.0.0",
                "lock_sha256": (
                    "sha256:"
                    "53ac28e5dc23e9a5a8244d58f5f12860052941d71c0c9ca3e922245c584fa697"
                ),
                "worker_sha256": (
                    "sha256:"
                    "e14b49f0f5dcce0814e853143410cd60f4a74780fc3140672823546018d73205"
                ),
            },
        )
        receipt_schema = json.loads(
            (
                SCHEMA_DIRECTORY
                / "benchmark-phase0-hidden-suite-freeze-receipt-v6.schema.json"
            ).read_text()
        )
        release = receipt_schema["properties"]["release"]["properties"]
        self.assertEqual(release["principal"]["const"], "aragorn-local-v6-author")
        self.assertEqual(release["freeze_tag"]["const"], "local-v6.0.0")
        self.assertEqual(
            receipt_schema["$defs"]["novelty"]["properties"][
                "reference_corpus_lock_digest"
            ]["const"],
            lock["reference"]["lock_sha256"],
        )

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
