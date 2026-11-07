"""Inert contract fixtures, not runtime observations or production verifiers.

The explicitly selected synthetic callbacks below intentionally model semantic
outcomes. Their PASS establishes only composer behavior, never D2/D3 or Phase 3.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path

from aragorn import pi_core_phase3_qualification as subject
from aragorn.cas import CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import Phase3DeploymentError
from aragorn.phase3_exit_gate_manifest import Phase3ExitGateManifestError
from aragorn.phase3_exit_qualification import Phase3ExitQualificationError, Phase3SemanticVerifier, VERIFICATION_SCHEMA
from aragorn.phase3_quantitative_metrics import Phase3QuantitativeMetricsError, build_phase3_measurement_schedule
from aragorn.phase3_reference_tasks import describe_tasks, reference_inputs
from tests import test_phase3_exit_qualification as legacy_fixture


_ROOT = Path(__file__).resolve().parents[1]
_CALLS = []
_STATUSES = {}
_METRICS = "MP1/MEASUREMENT_SEMANTICS"
_ERRORS = (Phase3ExitQualificationError, Phase3ExitGateManifestError, Phase3DeploymentError, Phase3QuantitativeMetricsError, CASError)


def synthetic_managed_consumer(raw, context, cas):
    """Test-only trusted callback: no live semantic claim is made here."""
    if not cas.read_only or cas.read(context["evidence_digest"]) != raw:
        raise ValueError("synthetic custody differs")
    key = context.get("verification_scope", context["requirement_id"])
    _CALLS.append(key)
    if key == "SOURCE_BOUND_SURFACE_COMPLETENESS":
        for pin in json.loads(raw)["evidence_by_surface"].values():
            if json.loads(cas.read(pin)) != {"synthetic_surface": True}:
                raise ValueError("a supplied PASS record is not semantic surface evidence")
    elif key != _METRICS and json.loads(raw) != {"synthetic_requirement": key}:
        raise ValueError("a supplied PASS record is not semantic requirement evidence")
    return {
        "schema": VERIFICATION_SCHEMA, "bindings": dict(context),
        "status": _STATUSES.get(key, "PASS"),
        "reason_codes": ["SYNTHETIC_CONTRACT_FIXTURE_NOT_QUALIFICATION"],
    }


def synthetic_wrong_join(raw, context, cas):
    result = synthetic_managed_consumer(raw, context, cas)
    result["bindings"]["surface_inventory_digest"] = "sha256:" + "0" * 64
    return result


class PiCorePhase3QualificationTests(unittest.TestCase):
    def setUp(self):
        _CALLS.clear()
        _STATUSES.clear()
        fixture = legacy_fixture.Phase3ExitQualificationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.cas, self.metrics = fixture.cas, deepcopy(fixture.metrics)
        self.arguments = fixture.arguments_copy()
        self.manifest_raw = (_ROOT / "benchmark/pi-core-managed-phase3-v1.json").read_bytes()
        self.manifest = json.loads(self.manifest_raw)
        self.required = subject.required_pi_core_phase3_evidence_ids(self.manifest_raw)
        self.arguments["manifest_raw"] = self.manifest_raw
        self.arguments["verifiers"] = {key: self.verifier() for key in self.required}
        self.arguments["evidence_by_requirement"] = {
            key: self.put({"synthetic_requirement": key}) for key in self.required
        }
        source_pin = self.put({"synthetic_source": "not a deployed artifact"})
        self.inventory = {
            "schema": "aragorn/pi-core-managed-surface-inventory/v1", "profile": subject.PROFILE,
            "deployment_identity_digest": self.arguments["expected_deployment_digest"],
            "sources": {"synthetic/source.py": source_pin},
            "surfaces": [
                {
                    "surface_id": f"surface-{index}", "group": group,
                    "disposition": "SUPPORTED" if index % 2 else "DENIED",
                    "entrypoint": f"synthetic.source.entrypoint_{index}",
                    "source_paths": ["synthetic/source.py"],
                    "requirements": list(self.required) if index == 0 else [self.required[index]],
                }
                for index, group in enumerate(self.manifest["surface_groups"])
            ],
        }
        inventory_pin = self.put(self.inventory)
        self.surface_evidence = {
            "schema": "aragorn/pi-core-managed-surface-evidence/v1",
            "surface_inventory_digest": inventory_pin,
            "deployment_identity_digest": self.arguments["expected_deployment_digest"],
            "evidence_by_surface": {
                row["surface_id"]: self.put({"synthetic_surface": True})
                for row in self.inventory["surfaces"]
            },
        }
        self.arguments.update(
            surface_inventory_raw=canonical_json(self.inventory),
            expected_surface_inventory_digest=inventory_pin,
            surface_evidence_digest=self.put(self.surface_evidence),
            surface_verifier=self.verifier(),
        )
        source_raw = (_ROOT / "src/aragorn/phase3_reference_tasks.py").read_bytes()
        self.arguments["expected_reference_task_source_digest"] = self.cas.put(BytesIO(source_raw), max_bytes=len(source_raw))
        for raw in reference_inputs().values():
            self.cas.put(BytesIO(raw), max_bytes=len(raw))
        descriptors = describe_tasks(source_raw)
        tasks = list(self.manifest["pairs"])
        schedule = self.arguments["measurement_schedule"]
        pair_ids = list(schedule["overhead_schedule"]["pair_bindings"])
        attempt_ids = schedule["attempt_schedule"]["attempt_ids"]
        operations = ["HTTP", "DNS", "TRUNCATE", "UNLINK"]
        self.campaign = {
            "schema": "aragorn/pi-core-managed-campaign/v1", "profile": subject.PROFILE,
            "deployment_identity_digest": self.arguments["expected_deployment_digest"],
            "surface_inventory_digest": inventory_pin,
            "attempt_operations": {key: operations[index // 25] for index, key in enumerate(attempt_ids)},
            "pair_tasks": {key: tasks[index // 25] for index, key in enumerate(pair_ids)},
            "task_descriptors": {task: self.put(descriptors[task]) for task in tasks},
            "pair_ordering": "BASELINE_FIRST",
        }
        for index, sample in enumerate(self.metrics["attempts"]):
            sample.update(
                family="EXFILTRATION" if index < 50 else "DESTRUCTIVE",
                negative_control=index == 75, attributed=index != 75,
            )
            schedule["attempt_schedule"]["attempt_families"][sample["attempt_id"]] = sample["family"]
        schedule["attempt_schedule"]["unattributed_negative_control_attempt_id"] = attempt_ids[75]
        for pair_id in pair_ids:
            task = self.campaign["pair_tasks"][pair_id]
            binding = schedule["overhead_schedule"]["pair_bindings"][pair_id]
            binding.update(task_digest=self.campaign["task_descriptors"][task], input_digest=descriptors[task]["input"]["digest"])
        for name in ("baseline_samples", "instrumented_samples"):
            for sample in self.metrics[name]:
                sample.update(schedule["overhead_schedule"]["pair_bindings"][sample["pair_id"]])
                if name == "instrumented_samples":
                    sample["started_boottime_ns"] += 2000
                    sample["completed_boottime_ns"] += 2000
        self.bind_campaign()

    def put(self, value):
        raw = canonical_json(value)
        return self.cas.put(BytesIO(raw), max_bytes=len(raw))

    def verifier(self, callback=synthetic_managed_consumer):
        pin = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        return Phase3SemanticVerifier(callback, pin)

    def bind_campaign(self):
        campaign_pin = self.put(self.campaign)
        old = self.arguments["measurement_schedule"]
        schedule = build_phase3_measurement_schedule(
            expected_attempt_ids=old["attempt_schedule"]["attempt_ids"],
            expected_attempt_families=old["attempt_schedule"]["attempt_families"],
            expected_unattributed_attempt_id=old["attempt_schedule"]["unattributed_negative_control_attempt_id"],
            expected_overhead_pair_bindings=old["overhead_schedule"]["pair_bindings"],
            expected_gate_manifest_digest=subject.MANIFEST_DIGEST,
            expected_campaign_contract_digest=campaign_pin,
            expected_runtime_identity_digest=self.arguments["expected_deployment_digest"],
        )
        self.arguments.update(
            expected_campaign_contract_digest=campaign_pin, measurement_schedule=schedule,
            expected_measurement_schedule_digest=canonical_digest(schedule),
        )
        self.metrics["bindings"].update(
            gate_manifest_digest=subject.MANIFEST_DIGEST, campaign_contract_digest=campaign_pin,
            measurement_schedule_digest=canonical_digest(schedule),
        )
        self.arguments["evidence_by_requirement"][_METRICS] = self.put(self.metrics)

    def bind_inventory(self):
        pin = self.put(self.inventory)
        self.arguments.update(surface_inventory_raw=canonical_json(self.inventory), expected_surface_inventory_digest=pin)
        self.surface_evidence["surface_inventory_digest"] = pin
        self.arguments["surface_evidence_digest"] = self.put(self.surface_evidence)
        self.campaign["surface_inventory_digest"] = pin
        self.bind_campaign()

    def qualify(self):
        return subject.qualify_pi_core_phase3_exit(**self.arguments)

    def test_fixed_29_requirement_profile_is_distinct_from_unchanged_legacy_48(self):
        self.assertEqual(len(self.required), 29)
        legacy_raw = (_ROOT / "benchmark/phase3-exit-gate-manifest-v1.json").read_bytes()
        self.assertEqual(len(legacy_fixture.subject.required_phase3_evidence_ids(legacy_raw)), 48)
        with self.assertRaises(Phase3ExitQualificationError):
            subject.required_pi_core_phase3_evidence_ids(legacy_raw)

    def test_complete_synthetic_contract_composes_without_claiming_other_profiles(self):
        result = self.qualify()
        self.assertTrue(result["decision"]["phase3_exit_eligible"])
        self.assertFalse(result["decision"]["release_eligible"])
        self.assertFalse(result["decision"]["edr_eligible"])
        self.assertEqual(result["profile"], subject.PROFILE)
        self.assertEqual(result["surface_count"], 12)
        self.assertEqual(len(result["requirements"]), 29)
        self.assertEqual(_CALLS, ["SOURCE_BOUND_SURFACE_COMPLETENESS", *self.required])
        self.assertEqual(result["quantitative_metrics"]["decision"]["status"], "PASS")

    def test_changed_missing_extra_duplicate_or_na_manifest_ids_are_rejected(self):
        for values in (self.required[:-1], (*self.required, "MP1/EXTRA"), (*self.required[:-1], self.required[0]), (*self.required[:-1], "N/A")):
            changed = {**self.manifest, "requirements": list(values)}
            with self.subTest(ids=values[-1]), self.assertRaises(Phase3ExitQualificationError):
                subject.required_pi_core_phase3_evidence_ids(canonical_json(changed) + b"\n")

    def test_missing_and_extra_requirement_or_verifier_are_rejected_before_callbacks(self):
        for label in ("verifiers", "evidence_by_requirement"):
            original = self.arguments[label]
            for kind in ("missing", "extra"):
                changed = dict(original)
                if kind == "missing":
                    del changed[self.required[0]]
                else:
                    changed["MP1/UNREVIEWED"] = changed[self.required[0]]
                self.arguments[label] = changed
                with self.subTest(label=label, kind=kind), self.assertRaises(Phase3ExitQualificationError):
                    self.qualify()
                self.assertEqual(_CALLS, [])
            self.arguments[label] = original

    def test_inventory_bytes_must_match_operator_pin(self):
        self.arguments["surface_inventory_raw"] += b" "
        with self.assertRaisesRegex(Phase3ExitQualificationError, "frozen pin"):
            self.qualify()

    def test_duplicate_json_inventory_keys_are_rejected_even_with_matching_pin(self):
        raw = b'{"schema":"x","schema":"x"}'
        self.arguments.update(surface_inventory_raw=raw, expected_surface_inventory_digest="sha256:" + hashlib.sha256(raw).hexdigest())
        with self.assertRaises(Phase3ExitGateManifestError):
            self.qualify()

    def test_inventory_missing_group_is_not_complete(self):
        self.inventory["surfaces"].pop()
        self.bind_inventory()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "incomplete source-bound"):
            self.qualify()

    def test_duplicate_surface_identity_is_rejected(self):
        self.inventory["surfaces"][1]["surface_id"] = "surface-0"
        self.bind_inventory()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "duplicate"):
            self.qualify()

    def test_na_surface_disposition_is_not_a_shortcut(self):
        self.inventory["surfaces"][0]["disposition"] = "N/A"
        self.bind_inventory()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "N/A"):
            self.qualify()

    def test_missing_source_artifact_cannot_qualify_inventory(self):
        self.inventory["sources"]["synthetic/source.py"] = "sha256:" + "0" * 64
        self.bind_inventory()
        with self.assertRaises(_ERRORS):
            self.qualify()

    def test_inventory_cannot_omit_denied_surfaces(self):
        for row in self.inventory["surfaces"]:
            row["disposition"] = "SUPPORTED"
        self.bind_inventory()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "incomplete source-bound"):
            self.qualify()

    def test_source_reference_must_be_declared(self):
        self.inventory["surfaces"][0]["source_paths"] = ["different.py"]
        self.bind_inventory()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "references"):
            self.qualify()

    def test_all_29_requirements_must_have_surface_references(self):
        self.inventory["surfaces"][0]["requirements"].remove(_METRICS)
        self.bind_inventory()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "incomplete source-bound"):
            self.qualify()

    def test_surface_evidence_requires_exact_inventory(self):
        self.surface_evidence["evidence_by_surface"].pop("surface-0")
        self.arguments["surface_evidence_digest"] = self.put(self.surface_evidence)
        with self.assertRaisesRegex(Phase3ExitQualificationError, "incomplete or unbound"):
            self.qualify()

    def test_inventory_and_surface_evidence_cannot_mix_deployments(self):
        self.surface_evidence["deployment_identity_digest"] = "sha256:" + "0" * 64
        self.arguments["surface_evidence_digest"] = self.put(self.surface_evidence)
        with self.assertRaises(Phase3ExitQualificationError):
            self.qualify()

    def test_missing_or_unpinned_surface_verifier_is_rejected(self):
        for verifier in (None, Phase3SemanticVerifier(synthetic_managed_consumer, "sha256:" + "0" * 64)):
            self.arguments["surface_verifier"] = verifier
            with self.subTest(verifier=verifier), self.assertRaises(Phase3ExitQualificationError):
                self.qualify()
            self.assertEqual(_CALLS, [])

    def test_unpinned_requirement_verifier_is_rejected(self):
        self.arguments["verifiers"][self.required[0]] = Phase3SemanticVerifier(synthetic_managed_consumer, "sha256:" + "0" * 64)
        with self.assertRaises(Phase3ExitQualificationError):
            self.qualify()
        self.assertEqual(_CALLS, [])

    def test_semantic_surface_failure_or_not_tested_prevents_numeric_upgrade(self):
        for status in ("FAIL", "NOT_TESTED"):
            _STATUSES["SOURCE_BOUND_SURFACE_COMPLETENESS"] = status
            result = self.qualify()
            self.assertFalse(result["decision"]["phase3_exit_eligible"])
            self.assertIsNone(result["quantitative_metrics"])

    def test_semantic_requirement_failure_or_not_tested_stays_ineligible(self):
        for status in ("FAIL", "NOT_TESTED"):
            _STATUSES["MP1/RUN-02"] = status
            result = self.qualify()
            self.assertFalse(result["decision"]["phase3_exit_eligible"])
            self.assertIsNone(result["quantitative_metrics"])

    def test_na_semantic_result_is_rejected(self):
        _STATUSES["SOURCE_BOUND_SURFACE_COMPLETENESS"] = "N/A"
        with self.assertRaises(Phase3ExitQualificationError):
            self.qualify()

    def test_surface_semantic_result_must_bind_exact_inventory(self):
        self.arguments["surface_verifier"] = self.verifier(synthetic_wrong_join)
        with self.assertRaisesRegex(Phase3ExitQualificationError, "unbound"):
            self.qualify()

    def test_requirement_semantic_result_must_bind_exact_inventory(self):
        self.arguments["verifiers"][self.required[0]] = self.verifier(synthetic_wrong_join)
        with self.assertRaisesRegex(Phase3ExitQualificationError, "unbound"):
            self.qualify()

    def test_forged_pass_is_not_surface_evidence(self):
        self.surface_evidence["evidence_by_surface"]["surface-0"] = self.put({"status": "PASS"})
        self.arguments["surface_evidence_digest"] = self.put(self.surface_evidence)
        with self.assertRaisesRegex(ValueError, "not semantic surface"):
            self.qualify()

    def test_forged_pass_is_not_requirement_evidence(self):
        self.arguments["evidence_by_requirement"][self.required[0]] = self.put({"status": "PASS"})
        with self.assertRaisesRegex(ValueError, "not semantic requirement"):
            self.qualify()

    def test_operation_counts_are_fixed_at_25_each(self):
        self.campaign["attempt_operations"]["attempt-000"] = "DNS"
        self.bind_campaign()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "25 attempts"):
            self.qualify()

    def test_http_cannot_be_relabelled_destructive(self):
        self.arguments["measurement_schedule"]["attempt_schedule"]["attempt_families"]["attempt-000"] = "DESTRUCTIVE"
        self.bind_campaign()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "family"):
            self.qualify()

    def test_unattributed_control_must_be_destructive(self):
        self.arguments["measurement_schedule"]["attempt_schedule"]["unattributed_negative_control_attempt_id"] = "attempt-000"
        self.bind_campaign()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "must be destructive"):
            self.qualify()

    def test_task_counts_are_fixed_at_25_each(self):
        self.campaign["pair_tasks"]["pair-000"] = "BENIGN_SHA256"
        self.bind_campaign()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "25 pairs"):
            self.qualify()

    def test_task_input_substitution_is_rejected(self):
        self.arguments["measurement_schedule"]["overhead_schedule"]["pair_bindings"]["pair-000"]["input_digest"] = "sha256:" + "0" * 64
        self.bind_campaign()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "equivalent input"):
            self.qualify()

    def test_fabricated_task_descriptor_is_rejected(self):
        task = "BENIGN_JSON_SUM"
        descriptor = json.loads(self.cas.read(self.campaign["task_descriptors"][task]))
        descriptor["output"]["expected"] = {"sum": 29}
        self.campaign["task_descriptors"][task] = self.put(descriptor)
        self.bind_campaign()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "descriptor differs"):
            self.qualify()

    def test_self_selected_task_source_cannot_impersonate_reviewed_implementation(self):
        task = "BENIGN_JSON_SUM"
        substitute = b"synthetic substituted source, not the reviewed implementation"
        self.cas.put(BytesIO(substitute), max_bytes=len(substitute))
        descriptor = describe_tasks(substitute)[task]
        self.campaign["task_descriptors"][task] = self.put(descriptor)
        self.bind_campaign()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "independently reviewed"):
            self.qualify()

    def test_core_pins_are_preflighted_before_surface_consumer(self):
        for key in ("expected_measurement_schedule_digest", "expected_metrics_implementation_digest"):
            original = self.arguments[key]
            self.arguments[key] = "sha256:" + "0" * 64
            with self.subTest(key=key), self.assertRaises(Phase3ExitQualificationError):
                self.qualify()
            self.assertEqual(_CALLS, [])
            self.arguments[key] = original
        self.arguments["deployment_raw"] += b" "
        with self.assertRaises(Phase3DeploymentError):
            self.qualify()
        self.assertEqual(_CALLS, [])

    def test_shared_composer_cannot_override_core_joins(self):
        with self.assertRaisesRegex(Phase3ExitQualificationError, "override core joins"):
            subject._qualify_phase3_requirements(
                required=(), gate_manifest_digest=subject.MANIFEST_DIGEST, measurements_id=_METRICS,
                deployment_raw=b"", expected_deployment_digest="unused", expected_campaign_contract_digest="unused",
                measurement_schedule={}, expected_measurement_schedule_digest="unused",
                expected_metrics_implementation_digest="unused", evidence_by_requirement={}, verifiers={}, evidence_cas=self.cas,
                extra_context={"deployment_identity_digest": "substituted"},
            )

    def test_mixed_campaign_deployment_is_rejected(self):
        self.campaign["deployment_identity_digest"] = "sha256:" + "0" * 64
        self.bind_campaign()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "unbound"):
            self.qualify()

    def test_baseline_first_is_enforced_on_actual_sample_intervals(self):
        self.metrics["instrumented_samples"][0]["started_boottime_ns"] -= 2000
        self.metrics["instrumented_samples"][0]["completed_boottime_ns"] -= 2000
        self.bind_campaign()
        with self.assertRaisesRegex(Phase3ExitQualificationError, "baseline first"):
            self.qualify()

    def test_strict_500ms_boundary_reuses_numeric_rejection(self):
        for sample in self.metrics["attempts"]:
            sample["decision_finalized_boottime_ns"] = sample["request_accepted_boottime_ns"] + 500_000_000
        self.bind_campaign()
        with self.assertRaises(Phase3QuantitativeMetricsError):
            self.qualify()

    def test_strict_ten_percent_overhead_boundary_reuses_numeric_rejection(self):
        for sample in self.metrics["instrumented_samples"]:
            sample["completed_boottime_ns"] = sample["started_boottime_ns"] + 1100
        self.bind_campaign()
        with self.assertRaises(Phase3QuantitativeMetricsError):
            self.qualify()

    def test_attribution_below_99_percent_is_rejected(self):
        self.metrics["attempts"][0]["attributed"] = False
        self.bind_campaign()
        with self.assertRaises(Phase3QuantitativeMetricsError):
            self.qualify()

    def test_residue_in_either_family_is_rejected(self):
        for index in (0, 50):
            self.metrics["attempts"][index]["residue_detected"] = True
            self.bind_campaign()
            with self.subTest(index=index), self.assertRaises(Phase3QuantitativeMetricsError):
                self.qualify()
            self.metrics["attempts"][index]["residue_detected"] = False

    def test_declared_control_cannot_claim_attribution(self):
        self.metrics["attempts"][75]["attributed"] = True
        self.bind_campaign()
        with self.assertRaises(Phase3QuantitativeMetricsError):
            self.qualify()


def load_tests(loader, tests, pattern):
    """Only three affected legacy composition checks, never its broad module."""
    for name in (
        "test_complete_inventory_composes_only_explicit_synthetic_verifiers",
        "test_semantic_callbacks_receive_read_only_cas_for_raw_evidence",
        "test_any_mandatory_failure_or_not_tested_remains_ineligible",
    ):
        tests.addTest(legacy_fixture.Phase3ExitQualificationTests(name))
    return tests
