from __future__ import annotations

import hashlib
import json
import re
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.admission_routes import (
    AdmissionRouteInventoryError,
    validate_openclaw_2026_7_1_route_inventory,
)

SCHEMA_DIRECTORY = Path(__file__).parents[1] / "schema"
EXPECTED_CONTRACTS = {
    "admission-artifact-graph-v1.schema.json": "aragorn/admission-artifact-graph/v1",
    "admission-artifact-graph-v2.schema.json": "aragorn/admission-artifact-graph/v2",
    "admission-artifact-graph-v4.schema.json": "aragorn/admission-artifact-graph/v4",
    "admission-artifact-graph-v5.schema.json": "aragorn/admission-artifact-graph/v5",
    "admission-artifact-graph-v6.schema.json": "aragorn/admission-artifact-graph/v6",
    "admission-conformance-result-v1.schema.json": "aragorn/admission-conformance-result/v1",
    "admission-protected-archive-route-qualification-v1.schema.json": "aragorn/admission-protected-archive-route-qualification/v1",
    "admission-protected-route-qualification-v1.schema.json": "aragorn/admission-protected-route-qualification/v1",
    "admission-runtime-candidate-lock-v1.schema.json": "aragorn/admission-runtime-candidate-lock/v1",
    "analyzer-request-v1.schema.json": "aragorn/analyzer-request/v1",
    "analyzer-request-v2.schema.json": "aragorn/analyzer-request/v2",
    "analyzer-run-receipt-v1.schema.json": "aragorn/analyzer-run-receipt/v1",
    "analyzers-v1.schema.json": "aragorn/analyzers/v1",
    "baseline-image-verification-v1.schema.json": "aragorn/baseline-image-verification/v1",
    "baseline-lock-v1.schema.json": "aragorn/baseline-lock/v1",
    "behavior-capability-diff-v1.schema.json": "aragorn/behavior-capability-diff/v1",
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
    "benchmark-phase0-acquisition-regression-result-receipt-v1.schema.json": "aragorn/benchmark-phase0-acquisition-regression-result-receipt/v1",
    "benchmark-phase0-accounting-v1.schema.json": "aragorn/benchmark-phase0-accounting/v1",
    "benchmark-phase0-gate-report-v1.schema.json": "aragorn/benchmark-phase0-gate-report/v1",
    "benchmark-phase0-gate-report-v2.schema.json": "aragorn/benchmark-phase0-gate-report/v2",
    "benchmark-phase2-coverage-lock-v1.schema.json": "aragorn/benchmark-phase2-coverage-lock/v1",
    "benchmark-phase2-coverage-lock-v2.schema.json": "aragorn/benchmark-phase2-coverage-lock/v2",
    "benchmark-phase2-coverage-lock-v3.schema.json": "aragorn/benchmark-phase2-coverage-lock/v3",
    "benchmark-phase2-gvisor-v4-evidence-v1.schema.json": "aragorn/benchmark-phase2-gvisor-v4-evidence/v1",
    "benchmark-phase2-gvisor-v5-evidence-v2.schema.json": "aragorn/benchmark-phase2-gvisor-v5-evidence/v2",
    "benchmark-phase2-gvisor-v5-remote-evidence-v3.schema.json": "aragorn/benchmark-phase2-gvisor-v5-remote-evidence/v3",
    "benchmark-phase2-metrics-checkpoint-v1.schema.json": "aragorn/benchmark-phase2-metrics-checkpoint/v1",
    "benchmark-phase2-metrics-checkpoint-v2.schema.json": "aragorn/benchmark-phase2-metrics-checkpoint/v2",
    "benchmark-phase2-metrics-checkpoint-v3.schema.json": "aragorn/benchmark-phase2-metrics-checkpoint/v3",
    "gvisor-backend-qualification-lock-v1.schema.json": "aragorn/gvisor-backend-qualification-lock/v1",
    "gvisor-backend-qualification-receipt-v1.schema.json": "aragorn/gvisor-backend-qualification-receipt/v1",
    "phase2-matrix-catalog-v1.schema.json": "aragorn/phase2-matrix-catalog/v1",
    "phase2-matrix-catalog-v2.schema.json": "aragorn/phase2-matrix-catalog/v2",
    "phase2-matrix-catalog-v3.schema.json": "aragorn/phase2-matrix-catalog/v3",
    "phase2-matrix-operator-index-v1.schema.json": "aragorn/phase2-matrix-operator-index/v1",
    "phase2-exit-gate-report-v1.schema.json": "aragorn/phase2-exit-gate-report/v1",
    "benchmark-phase0-hidden-calibration-result-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-calibration-result-receipt/v1",
    "benchmark-phase0-hidden-calibration-result-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-calibration-result-receipt/v2",
    "benchmark-phase0-hidden-calibration-result-receipt-v3.schema.json": "aragorn/benchmark-phase0-hidden-calibration-result-receipt/v3",
    "benchmark-phase0-hidden-result-receipt-v1.schema.json": "aragorn/benchmark-phase0-hidden-result-receipt/v1",
    "benchmark-phase0-hidden-result-receipt-v2.schema.json": "aragorn/benchmark-phase0-hidden-result-receipt/v2",
    "benchmark-phase0-hidden-result-receipt-v3.schema.json": "aragorn/benchmark-phase0-hidden-result-receipt/v3",
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
    "benchmark-phase0-hidden-v7-freeze-profile-v1.schema.json": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v2",
    "benchmark-phase0-hidden-v7-preparation-profile-v1.schema.json": "aragorn/benchmark-phase0-hidden-preparation-receipt/v2",
    "benchmark-phase0-hidden-v7-worker-run-profile-v1.schema.json": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v2",
    "benchmark-phase0-hidden-suite-lock-v1.schema.json": "aragorn/benchmark-phase0-hidden-suite-lock/v1",
    "benchmark-phase0-validation-milestone-receipt-v1.schema.json": "aragorn/benchmark-phase0-validation-milestone-receipt/v1",
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
    "decision-v2.schema.json": "aragorn/decision/v2",
    "decision-v3.schema.json": "aragorn/decision/v3",
    "detonation-capability-diff-receipt-v1.schema.json": "aragorn/detonation-capability-diff-receipt/v1",
    "detonation-observation-v1.schema.json": "aragorn/detonation-observation/v1",
    "detonation-source-event-v1.schema.json": "aragorn/detonation-source-event/v1",
    "error-v1.schema.json": "aragorn/error/v1",
    "gvisor-acquired-artifact-receipt-v1.schema.json": "aragorn/gvisor-acquired-artifact-receipt/v1",
    "gvisor-acquired-artifact-receipt-v2.schema.json": "aragorn/gvisor-acquired-artifact-receipt/v2",
    "gvisor-acquired-artifact-receipt-v3.schema.json": "aragorn/gvisor-acquired-artifact-receipt/v3",
    "gvisor-acquired-artifact-receipt-v4.schema.json": "aragorn/gvisor-acquired-artifact-receipt/v4",
    "gvisor-acquired-artifact-receipt-v5.schema.json": "aragorn/gvisor-acquired-artifact-receipt/v5",
    "gvisor-artifact-actor-attribution-manifest-v1.schema.json": "aragorn/gvisor-artifact-actor-attribution-manifest/v1",
    "gvisor-detonation-canary-receipt-v1.schema.json": "aragorn/gvisor-detonation-canary-receipt/v1",
    "gvisor-remote-trace-capture-receipt-v1.schema.json": "aragorn/gvisor-remote-trace-capture-receipt/v1",
    "gvisor-remote-trace-capture-receipt-v2.schema.json": "aragorn/gvisor-remote-trace-capture-receipt/v2",
    "github-expansion-result-v1.schema.json": "aragorn/github-expansion-result/v1",
    "github-expansion-v1.schema.json": "aragorn/github-expansion/v1",
    "github-gateway-request-v1.schema.json": "aragorn/github-gateway-request/v1",
    "github-gateway-result-v1.schema.json": "aragorn/github-gateway-result/v1",
    "github-gateway-result-v2.schema.json": "aragorn/github-gateway-result/v2",
    "github-manifest-v1.schema.json": "aragorn/github-manifest/v1",
    "github-quarantine-receipt-v1.schema.json": "aragorn/github-quarantine-receipt/v1",
    "github-release-asset-v1.schema.json": "aragorn/github-release-asset/v1",
    "github-release-asset-v2.schema.json": "aragorn/github-release-asset/v2",
    "github-source-proof-v1.schema.json": "aragorn/github-source-proof/v1",
    "gvisor-runtime-smoke-receipt-v1.schema.json": "aragorn/gvisor-runtime-smoke-receipt/v1",
    "inspect-result-v1.schema.json": "aragorn/inspect-result/v1",
    "inspect-result-v2.schema.json": "aragorn/inspect-result/v2",
    "inventory-result-v1.schema.json": "aragorn/inventory-result/v1",
    "manifest-v1.schema.json": "aragorn/manifest/v1",
    "observation-v1.schema.json": "aragorn/observation/v1",
    "phase0-standards-gate-v1.schema.json": "aragorn/phase0-standards-gate/v1",
    "phase1-acquisition-lock-evidence-v1.schema.json": "aragorn/phase1-acquisition-lock-evidence/v1",
    "phase1-acquisition-lock-evidence-v2.schema.json": "aragorn/phase1-acquisition-lock-evidence/v2",
    "phase1-acquisition-lock-milestone-v1.schema.json": "aragorn/phase1-acquisition-lock-milestone/v1",
    "phase1-acquisition-lock-milestone-v2.schema.json": "aragorn/phase1-acquisition-lock-milestone/v2",
    "policy-v2.schema.json": "aragorn/policy/v2",
    "protected-install-broker-request-v1.schema.json": "aragorn/protected-install-broker-request/v1",
    "protected-install-broker-request-v2.schema.json": "aragorn/protected-install-broker-request/v2",
    "protected-install-broker-request-v3.schema.json": "aragorn/protected-install-broker-request/v3",
    "protected-install-broker-request-v4.schema.json": "aragorn/protected-install-broker-request/v4",
    "protected-install-context-v1.schema.json": "aragorn/protected-install-context/v1",
    "protected-install-context-v2.schema.json": "aragorn/protected-install-context/v2",
    "protected-install-transaction-v1.schema.json": "aragorn/protected-install-transaction/v1",
    "resolve-artifacts-result-v1.schema.json": "aragorn/resolve-artifacts-result/v1",
    "runtime-acquisition-action-binding-qualification-v1.schema.json": "aragorn/runtime-acquisition-action-binding-qualification/v1",
    "runtime-action-worker-activation-expiry-systemd-qualification-v1.schema.json": "aragorn/runtime-action-worker-activation-expiry-systemd-qualification/v1",
    "runtime-action-worker-openclaw-systemd-qualification-v1.schema.json": "aragorn/runtime-action-worker-openclaw-systemd-qualification/v1",
    "source-artifact-graph-v1.schema.json": "aragorn/source-artifact-graph/v1",
    "zip-archive-inventory-v1.schema.json": "aragorn/zip-archive-inventory/v1",
}


class SchemaTests(unittest.TestCase):
    def test_every_contract_has_a_parseable_schema(self) -> None:
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

    def test_gvisor_v3_entrypoint_path_is_canonical(self) -> None:
        document = json.loads(
            (
                SCHEMA_DIRECTORY
                / "gvisor-acquired-artifact-receipt-v3.schema.json"
            ).read_text()
        )
        pattern = document["properties"]["entrypoint"]["properties"]["path"][
            "pattern"
        ]
        self.assertIsNotNone(re.fullmatch(pattern, "scripts/check.sh"))
        for path in (
            "../escape.sh",
            "/absolute.sh",
            "scripts//check.sh",
            "scripts/./check.sh",
            "scripts\\check.sh",
            " check.sh",
            "check.sh ",
            "scripts/\x00check.sh",
        ):
            with self.subTest(path=path):
                self.assertIsNone(re.fullmatch(pattern, path))

    def test_v4_release_assets_remain_unresolved_until_analyzed(self) -> None:
        document = json.loads(
            (
                SCHEMA_DIRECTORY / "admission-artifact-graph-v4.schema.json"
            ).read_text()
        )
        edge = document["$defs"]["release_asset_edge"]

        self.assertEqual(edge["properties"]["status"], {"const": "unresolved"})
        self.assertIn(
            "GITHUB_RELEASE_ASSET_NOT_ANALYZED",
            edge["properties"]["reason_code"]["enum"],
        )

    def test_v5_release_assets_remain_unresolved_until_runtime_bound(self) -> None:
        document = json.loads(
            (
                SCHEMA_DIRECTORY / "admission-artifact-graph-v5.schema.json"
            ).read_text()
        )
        edge = document["$defs"]["release_asset_edge"]

        self.assertEqual(edge["properties"]["status"], {"const": "unresolved"})
        self.assertIn(
            "GITHUB_RELEASE_ASSET_RUNTIME_BINDING_UNPROVEN",
            edge["properties"]["reason_code"]["enum"],
        )

    def test_v6_vendors_archives_but_requires_a_runtime_consumer(self) -> None:
        document = json.loads(
            (
                SCHEMA_DIRECTORY / "admission-artifact-graph-v6.schema.json"
            ).read_text()
        )
        edge = document["$defs"]["release_asset_edge"]

        self.assertEqual(edge["properties"]["status"], {"const": "unresolved"})
        self.assertEqual(
            document["properties"]["closure"]["properties"]["status"],
            {"const": "incomplete"},
        )
        self.assertEqual(
            document["properties"]["coverage"]["properties"][
                "unresolved_required"
            ]["minimum"],
            1,
        )
        self.assertIn(
            "GITHUB_RELEASE_ASSET_RUNTIME_CONSUMER_UNPROVEN",
            edge["properties"]["reason_code"]["enum"],
        )
        self.assertIn(
            "GITHUB_RELEASE_ASSET_RUNTIME_BINDING_UNPROVEN",
            edge["properties"]["reason_code"]["enum"],
        )
        self.assertTrue(
            {
                "runtime_candidate_manifest_digest",
                "runtime_candidate_tree_digest",
                "runtime_candidate_artifacts",
            }.issubset(document["required"])
        )
        self.assertEqual(
            document["$defs"]["release_asset_target"]["properties"][
                "runtime_path"
            ]["oneOf"][0]["pattern"],
            "^__aragorn_release_assets__/[1-9][0-9]*/[1-9][0-9]*/raw/"
            "[A-Za-z0-9][A-Za-z0-9._-]{0,254}$",
        )

    def test_protected_install_broker_request_separates_authority_from_mechanics(
        self,
    ) -> None:
        document = json.loads(
            (
                SCHEMA_DIRECTORY
                / "protected-install-broker-request-v1.schema.json"
            ).read_text()
        )
        properties = document["properties"]
        self.assertFalse(document["additionalProperties"])
        self.assertEqual(set(document["required"]), set(properties))
        self.assertEqual(
            properties["source_request"]["$ref"],
            "github-gateway-request-v1.schema.json",
        )
        self.assertTrue(
            {
                "path",
                "uid",
                "now_unix",
                "command",
                "environment",
                "cas_root",
                "protected_root",
                "revocation_file",
                "expected_broker_uid",
            }.isdisjoint(properties)
        )

    def test_recursive_protected_request_keeps_pins_out_of_source_intent(
        self,
    ) -> None:
        document = json.loads(
            (
                SCHEMA_DIRECTORY
                / "protected-install-broker-request-v3.schema.json"
            ).read_text()
        )
        recursive = document["$defs"]["recursive"]

        self.assertEqual(
            set(recursive["required"]),
            set(recursive["properties"]),
        )
        self.assertFalse(recursive["additionalProperties"])
        self.assertNotIn("release_asset_pins", document["properties"])
        self.assertEqual(
            recursive["properties"]["release_asset_result_digests"][
                "maxItems"
            ],
            16,
        )

    def test_v4_recursive_protected_request_binds_only_the_pin_set_digest(
        self,
    ) -> None:
        document = json.loads(
            (
                SCHEMA_DIRECTORY
                / "protected-install-broker-request-v4.schema.json"
            ).read_text()
        )
        recursive_v4 = document["$defs"]["recursiveV4"]

        self.assertEqual(
            document["properties"]["recursive"],
            {"$ref": "#/$defs/recursiveV4"},
        )
        self.assertEqual(
            set(recursive_v4["required"]),
            set(recursive_v4["properties"]),
        )
        self.assertFalse(recursive_v4["additionalProperties"])
        self.assertEqual(
            recursive_v4["properties"]["release_pin_set_digest"],
            {
                "oneOf": [
                    {"type": "null"},
                    {"$ref": "#/$defs/digest"},
                ]
            },
        )
        self.assertNotIn("release_asset_pins", document["properties"])
        self.assertNotIn("release_asset_pins", recursive_v4["properties"])
        self.assertEqual(
            {
                item["$ref"]
                for item in document["$defs"]["expectedActive"]["oneOf"]
            },
            {
                "#/$defs/expectedActiveLegacy",
                "#/$defs/expectedActiveRecursiveV3",
                "#/$defs/expectedActiveRecursiveV4",
            },
        )

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

    def test_runtime_candidate_lock_cannot_claim_dynamic_qualification(self) -> None:
        lock = json.loads(
            (
                SCHEMA_DIRECTORY.parent
                / "benchmark"
                / "admission-runtime-candidates-v1.lock.json"
            ).read_text()
        )
        self.assertEqual(lock["selection_status"], "SOURCE_SCREEN_ONLY")
        self.assertEqual(
            lock["assurance"],
            "static_source_screen_only_not_dynamic_conformance",
        )
        candidates = {item["name"]: item for item in lock["candidates"]}
        self.assertEqual(
            {
                name: (
                    item["role"],
                    item["tag_kind"],
                    item["tag_object_sha1"],
                    item["commit_sha1"],
                    item["tree_sha1"],
                )
                for name, item in candidates.items()
            },
            {
                "openclaw": (
                    "primary",
                    "annotated",
                    "842a951d5d0843aa6eb77575dc9867bf0603835c",
                    "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
                    "5e9f2135f1b2c3c14910efdedb9e60b2593f8135",
                ),
                "pi": (
                    "comparator",
                    "lightweight",
                    None,
                    "b4f293684bba718d59cc1157679bcf6157b3a7f5",
                    "33235f8a1b7a50de1dea72d39ee3f3a2adbd5806",
                ),
            },
        )
        self.assertEqual(
            {
                name: (
                    item["commit_signature_status"],
                    item["tag_signature_status"],
                )
                for name, item in candidates.items()
            },
            {
                "openclaw": (
                    "github_displayed_verified_not_aragorn_trust_verified",
                    "github_displayed_verified_not_aragorn_trust_verified",
                ),
                "pi": (
                    "absent_from_git_object",
                    "not_applicable_lightweight",
                ),
            },
        )
        for candidate in candidates.values():
            self.assertFalse(candidate["source_screen"]["runtime_executed"])
            self.assertEqual(
                candidate["dynamic_conformance"]["status"],
                "NOT_TESTED",
            )
            self.assertFalse(
                candidate["dynamic_conformance"]["installer_work_eligible"]
            )
            self.assertTrue(
                all(
                    candidate["commit_sha1"] in url
                    for url in candidate["source_screen"]["evidence_urls"]
                )
            )

    def test_update_reload_route_inventory_is_static_and_commit_bound(self) -> None:
        root = SCHEMA_DIRECTORY.parent
        lock = json.loads(
            (
                root / "benchmark" / "admission-runtime-candidates-v1.lock.json"
            ).read_text()
        )
        inventory = json.loads(
            (
                root
                / "benchmark"
                / "admission"
                / "openclaw-v2026.7.1"
                / "update-reload-route-inventory-v1.json"
            ).read_text()
        )
        validate_openclaw_2026_7_1_route_inventory(inventory, lock)

        promoted_route = deepcopy(inventory)
        promoted_route["routes"][0]["status"] = "PASS"
        promoted_decision = deepcopy(inventory)
        promoted_decision["decision"]["installer_work_eligible"] = True
        off_commit = deepcopy(inventory)
        source_urls = off_commit["routes"][0]["paths"][0]["source_urls"]
        source_urls[0] = source_urls[0].replace(
            inventory["runtime"]["commit_sha1"],
            "0" * 40,
        )
        unknown_path = deepcopy(inventory)
        unknown_path["routes"][0]["paths"][0]["source_urls"][0] = (
            "https://github.com/openclaw/openclaw/blob/"
            f"{inventory['runtime']['commit_sha1']}/src/not-real.ts#L1-L2"
        )
        reversed_range = deepcopy(inventory)
        reversed_range["routes"][1]["paths"][1]["source_urls"][0] = reversed_range[
            "routes"
        ][1]["paths"][1]["source_urls"][0].replace(
            "#L210-L290",
            "#L290-L210",
        )
        for label, changed in (
            ("promoted route", promoted_route),
            ("promoted decision", promoted_decision),
            ("off-commit source", off_commit),
            ("unknown source path", unknown_path),
            ("reversed source range", reversed_range),
        ):
            with (
                self.subTest(label=label),
                self.assertRaises(AdmissionRouteInventoryError),
            ):
                validate_openclaw_2026_7_1_route_inventory(changed, lock)


if __name__ == "__main__":
    unittest.main()
