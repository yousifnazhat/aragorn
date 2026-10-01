"""Synthetic composer fixtures only: none of these callbacks qualifies a runtime.

The fake callbacks deliberately supply test outcomes. They are explicitly chosen
trusted functions, never a production registry or an evidence verdict importer.
Only the existing numeric fixture builder is reused; no old tests are run.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn import phase3_exit_qualification as subject
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import (
    BINDING_DIMENSIONS,
    Phase3DeploymentError,
    build_phase3_deployment_identity,
)
from aragorn.phase3_quantitative_metrics import (
    Phase3QuantitativeMetricsError,
    build_phase3_measurement_schedule,
    metrics_implementation_digest,
)
from tests import test_phase3_quantitative_metrics as numeric_fixture

_CALLS = []
_CAS_READ_ONLY_VALUES = []
_SYNTHETIC_STATUSES = {}
_ROOT = Path(__file__).resolve().parents[1]


def synthetic_semantic_verifier(raw, context, evidence_cas):
    """Fake unit fixture; it establishes no runtime semantics or independence."""
    _CALLS.append(context["requirement_id"])
    _CAS_READ_ONLY_VALUES.append(evidence_cas.read_only)
    if evidence_cas.read(context["evidence_digest"]) != raw:
        raise ValueError("synthetic evidence CAS differs")
    parsed = json.loads(raw)
    if context["requirement_id"] != "MEASUREMENT_SEMANTICS" and parsed != {
        "synthetic_unit_fixture": context["requirement_id"]
    }:
        raise ValueError("synthetic evidence differs")
    return {
        "schema": subject.VERIFICATION_SCHEMA,
        "bindings": dict(context),
        "status": _SYNTHETIC_STATUSES.get(context["requirement_id"], "PASS"),
        "reason_codes": ["SYNTHETIC_UNIT_FIXTURE_NOT_RUNTIME_EVIDENCE"],
    }


def synthetic_wrong_join_verifier(raw, context, evidence_cas):
    result = synthetic_semantic_verifier(raw, context, evidence_cas)
    result["bindings"]["deployment_identity_digest"] = "sha256:" + "f" * 64
    return result


class Phase3ExitQualificationTests(unittest.TestCase):
    def setUp(self):
        _CALLS.clear()
        _CAS_READ_ONLY_VALUES.clear()
        _SYNTHETIC_STATUSES.clear()
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.cas = CAS(temporary.name)
        self.manifest_raw = (
            _ROOT / "benchmark/phase3-exit-gate-manifest-v1.json"
        ).read_bytes()
        self.required = subject.required_phase3_evidence_ids(self.manifest_raw)
        deployment = build_phase3_deployment_identity(
            {key: self.put({"synthetic_identity": key}) for key in BINDING_DIMENSIONS}
        )
        deployment_pin = canonical_digest(deployment)
        campaign_pin = self.put({"synthetic_campaign": "NOT_LIVE_EVIDENCE"})
        fixture = numeric_fixture.Phase3QuantitativeMetricsTests()
        fixture.setUp()
        schedule = build_phase3_measurement_schedule(
            expected_attempt_ids=fixture.attempt_ids,
            expected_attempt_families=fixture.attempt_families,
            expected_overhead_pair_bindings=fixture.pair_bindings,
            expected_unattributed_attempt_id=fixture.negative_control_id,
            expected_gate_manifest_digest=subject.GATE_MANIFEST_DIGEST,
            expected_campaign_contract_digest=campaign_pin,
            expected_runtime_identity_digest=deployment_pin,
        )
        self.metrics = deepcopy(fixture.evidence)
        self.metrics["bindings"].update(
            gate_manifest_digest=subject.GATE_MANIFEST_DIGEST,
            campaign_contract_digest=campaign_pin,
            runtime_identity_digest=deployment_pin,
            measurement_schedule_digest=canonical_digest(schedule),
        )
        self.arguments = {
            "manifest_raw": self.manifest_raw,
            "deployment_raw": canonical_json(deployment),
            "expected_deployment_digest": deployment_pin,
            "expected_campaign_contract_digest": campaign_pin,
            "measurement_schedule": schedule,
            "expected_measurement_schedule_digest": canonical_digest(schedule),
            "expected_metrics_implementation_digest": metrics_implementation_digest(),
            "evidence_by_requirement": {
                key: self.put(
                    self.metrics
                    if key == "MEASUREMENT_SEMANTICS"
                    else {"synthetic_unit_fixture": key}
                )
                for key in self.required
            },
            "verifiers": {key: self.verifier() for key in self.required},
            "evidence_cas": self.cas,
        }

    def put(self, value):
        raw = canonical_json(value)
        return self.cas.put(BytesIO(raw), max_bytes=len(raw))

    def verifier(self, callback=synthetic_semantic_verifier):
        pin = "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        return subject.Phase3SemanticVerifier(callback, pin)

    def arguments_copy(self):
        return {
            **self.arguments,
            "evidence_by_requirement": dict(self.arguments["evidence_by_requirement"]),
            "verifiers": dict(self.arguments["verifiers"]),
            "measurement_schedule": deepcopy(self.arguments["measurement_schedule"]),
        }

    def test_complete_inventory_composes_only_explicit_synthetic_verifiers(self):
        self.assertEqual(len(self.required), 48)
        self.assertEqual(len(set(self.required)), 48)
        self.assertEqual(
            sum(key.startswith("ADM-") or key == "DET-01" for key in self.required), 31
        )
        self.assertEqual(sum(key.startswith("EVENT/") for key in self.required), 7)
        self.assertEqual(sum(key.startswith("RESPONSE/") for key in self.required), 6)
        result = subject.qualify_phase3_exit(**self.arguments)
        self.assertEqual(_CALLS, list(self.required))
        self.assertEqual(
            result["decision"],
            {
                "status": "PASS",
                "phase3_exit_eligible": True,
                "edr_eligible": False,
                "installer_work_eligible": False,
                "release_eligible": False,
            },
        )
        self.assertEqual(result["quantitative_metrics"]["decision"], {"status": "PASS"})
        self.assertEqual(set(result["requirements"]), set(self.required))

    def test_semantic_callbacks_receive_read_only_cas_for_raw_evidence(self):
        result = subject.qualify_phase3_exit(**self.arguments)
        self.assertEqual(result["decision"]["status"], "PASS")
        self.assertEqual(_CAS_READ_ONLY_VALUES, [True] * len(self.required))
        self.assertFalse(self.cas.read_only)

    def test_map_source_deployment_schedule_and_metrics_pin_fail_before_callbacks(self):
        variants = []
        for mapping in ("evidence_by_requirement", "verifiers"):
            for kind in ("missing", "extra"):
                args = self.arguments_copy()
                if kind == "missing":
                    del args[mapping]["MEASUREMENT_SEMANTICS"]
                else:
                    args[mapping]["UNDECLARED"] = next(iter(args[mapping].values()))
                variants.append((mapping + kind, args))
        args = self.arguments_copy()
        args["verifiers"][self.required[-1]] = subject.Phase3SemanticVerifier(
            synthetic_semantic_verifier, "sha256:" + "0" * 64
        )
        variants.append(("source_pin", args))
        for key in (
            "expected_deployment_digest",
            "expected_measurement_schedule_digest",
            "expected_metrics_implementation_digest",
        ):
            args = self.arguments_copy()
            args[key] = "sha256:" + "0" * 64
            variants.append((key, args))
        args = self.arguments_copy()
        args["measurement_schedule"]["attempt_schedule"]["attempt_count"] = 99
        variants.append(("schedule_count", args))
        for name, args in variants:
            with (
                self.subTest(case=name),
                self.assertRaises(
                    (subject.Phase3ExitQualificationError, Phase3DeploymentError)
                ),
            ):
                subject.qualify_phase3_exit(**args)
            self.assertEqual(_CALLS, [])

    def test_dangling_or_empty_later_evidence_blocks_all_callbacks(self):
        for pin in ("sha256:" + "0" * 64, self.cas.put(BytesIO(b""), max_bytes=0)):
            args = self.arguments_copy()
            args["evidence_by_requirement"][self.required[-1]] = pin
            with (
                self.subTest(pin=pin),
                self.assertRaises((subject.Phase3ExitQualificationError, CASError)),
            ):
                subject.qualify_phase3_exit(**args)
            self.assertEqual(_CALLS, [])

    def test_unbound_semantic_join_and_unknown_status_are_rejected(self):
        args = self.arguments_copy()
        args["verifiers"]["DET-01"] = self.verifier(synthetic_wrong_join_verifier)
        with self.assertRaisesRegex(subject.Phase3ExitQualificationError, "unbound"):
            subject.qualify_phase3_exit(**args)
        for bad in ("pass", "OBSERVED", True):
            _CALLS.clear()
            _SYNTHETIC_STATUSES["DET-01"] = bad
            with (
                self.subTest(status=bad),
                self.assertRaises(subject.Phase3ExitQualificationError),
            ):
                subject.qualify_phase3_exit(**self.arguments)

    def test_any_mandatory_failure_or_not_tested_remains_ineligible(self):
        for status in ("FAIL", "NOT_TESTED"):
            _CALLS.clear()
            _SYNTHETIC_STATUSES["RUN-02"] = status
            result = subject.qualify_phase3_exit(**self.arguments)
            self.assertEqual(result["decision"]["status"], "FAIL")
            self.assertFalse(result["decision"]["phase3_exit_eligible"])
            self.assertIsNone(result["quantitative_metrics"])
            self.assertEqual(_CALLS, list(self.required))

    def test_arithmetic_alone_cannot_replace_independent_measurement_semantics(self):
        for status in ("FAIL", "NOT_TESTED"):
            _CALLS.clear()
            _SYNTHETIC_STATUSES["MEASUREMENT_SEMANTICS"] = status
            result = subject.qualify_phase3_exit(**self.arguments)
            self.assertFalse(result["decision"]["phase3_exit_eligible"])
            self.assertIsNone(result["quantitative_metrics"])
            self.assertEqual(
                result["requirements"]["MEASUREMENT_SEMANTICS"]["status"], status
            )

    def test_semantic_pass_does_not_override_any_numeric_threshold(self):
        for mode, message in (
            ("attribution", "99 percent"),
            ("blocking", "pre-effect"),
            ("latency", "500 ms"),
            ("overhead", "10 percent"),
        ):
            _CALLS.clear()
            evidence = deepcopy(self.metrics)
            if mode == "attribution":
                evidence["attempts"][1]["attributed"] = False
            elif mode == "blocking":
                evidence["attempts"][1]["blocked_pre_effect"] = False
            elif mode == "latency":
                for attempt in evidence["attempts"]:
                    attempt["decision_finalized_boottime_ns"] = (
                        attempt["request_accepted_boottime_ns"] + 500_000_000
                    )
            else:
                for sample in evidence["instrumented_samples"]:
                    sample["completed_boottime_ns"] = (
                        sample["started_boottime_ns"] + 1_100
                    )
            args = self.arguments_copy()
            args["evidence_by_requirement"]["MEASUREMENT_SEMANTICS"] = self.put(
                evidence
            )
            with (
                self.subTest(threshold=mode),
                self.assertRaisesRegex(Phase3QuantitativeMetricsError, message),
            ):
                subject.qualify_phase3_exit(**args)
            self.assertEqual(_CALLS, list(self.required))


if __name__ == "__main__":
    unittest.main()
