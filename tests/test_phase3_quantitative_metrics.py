from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_quantitative_metrics import (
    ATTRIBUTION_THRESHOLD_DENOMINATOR,
    ATTRIBUTION_THRESHOLD_NUMERATOR,
    AUTHORITY,
    CLOCK_ID,
    EXPECTED_ATTEMPTS,
    EXPECTED_OVERHEAD_PAIRS,
    INPUT_SCHEMA,
    LATENCY_THRESHOLD_NS,
    MEASUREMENT_SCHEDULE_SCHEMA,
    OVERHEAD_LIMIT,
    OVERHEAD_SCALE,
    TASK_TIMING_BOUNDARY,
    Phase3QuantitativeMetricsError,
    build_phase3_measurement_schedule,
    metrics_implementation_digest,
    qualify_phase3_quantitative_metrics,
    qualify_phase3_quantitative_metrics_bytes,
)

MANIFEST_DIGEST = "sha256:" + "a" * 64
CAMPAIGN_DIGEST = "sha256:" + "b" * 64
RUNTIME_DIGEST = "sha256:" + "c" * 64


class Phase3QuantitativeMetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.attempt_ids = [f"attempt-{index:03d}" for index in range(100)]
        self.pair_ids = [f"pair-{index:03d}" for index in range(100)]
        self.pair_bindings = {
            pair_id: {
                "host_profile_digest": "sha256:" + "d" * 64,
                "input_digest": f"sha256:{index + 1:064x}",
                "task_digest": "sha256:" + "e" * 64,
            }
            for index, pair_id in enumerate(self.pair_ids)
        }
        self.negative_control_id = self.attempt_ids[0]
        attempts = []
        self.attempt_families = {}
        for index, attempt_id in enumerate(self.attempt_ids):
            family = (
                "OTHER"
                if index == 0
                else "EXFILTRATION"
                if index < 50
                else "DESTRUCTIVE"
            )
            self.attempt_families[attempt_id] = family
            accepted = 1_000_000_000 + index * 1_000_000_000
            attempts.append(
                {
                    "attempt_id": attempt_id,
                    "attributed": index != 0,
                    "blocked_pre_effect": True,
                    "decision_finalized_boottime_ns": accepted + 100_000_000,
                    "family": family,
                    "negative_control": index == 0,
                    "request_accepted_boottime_ns": accepted,
                    "residue_detected": False,
                }
            )
        self.evidence = {
            "schema": INPUT_SCHEMA,
            "bindings": {
                "campaign_contract_digest": CAMPAIGN_DIGEST,
                "gate_manifest_digest": MANIFEST_DIGEST,
                "measurement_schedule_digest": "",
                "metrics_implementation_digest": "",
                "runtime_identity_digest": RUNTIME_DIGEST,
            },
            "clock_id": "CLOCK_BOOTTIME",
            "attempts": attempts,
            "baseline_samples": [
                {
                    **self.pair_bindings[pair_id],
                    "completed_boottime_ns": index * 10_000 + 1_000,
                    "pair_id": pair_id,
                    "started_boottime_ns": index * 10_000,
                    "status": "COMPLETED",
                    "timing_boundary": TASK_TIMING_BOUNDARY,
                }
                for index, pair_id in enumerate(self.pair_ids)
            ],
            "instrumented_samples": [
                {
                    **self.pair_bindings[pair_id],
                    "completed_boottime_ns": index * 10_000 + 1_099,
                    "pair_id": pair_id,
                    "started_boottime_ns": index * 10_000,
                    "status": "COMPLETED",
                    "timing_boundary": TASK_TIMING_BOUNDARY,
                }
                for index, pair_id in enumerate(self.pair_ids)
            ],
        }
        self.schedule = build_phase3_measurement_schedule(
            expected_attempt_ids=self.attempt_ids,
            expected_attempt_families=self.attempt_families,
            expected_overhead_pair_bindings=self.pair_bindings,
            expected_unattributed_attempt_id=self.negative_control_id,
            expected_gate_manifest_digest=MANIFEST_DIGEST,
            expected_campaign_contract_digest=CAMPAIGN_DIGEST,
            expected_runtime_identity_digest=RUNTIME_DIGEST,
        )
        self.schedule_digest = canonical_digest(self.schedule)
        self.implementation_digest = metrics_implementation_digest()
        self.evidence["bindings"]["measurement_schedule_digest"] = self.schedule_digest
        self.evidence["bindings"]["metrics_implementation_digest"] = (
            self.implementation_digest
        )

    def qualify(self, evidence: object | None = None, **overrides: object) -> dict:
        arguments = {
            "expected_attempt_ids": self.attempt_ids,
            "expected_attempt_families": self.attempt_families,
            "expected_overhead_pair_bindings": self.pair_bindings,
            "expected_unattributed_attempt_id": self.negative_control_id,
            "expected_gate_manifest_digest": MANIFEST_DIGEST,
            "expected_campaign_contract_digest": CAMPAIGN_DIGEST,
            "expected_runtime_identity_digest": RUNTIME_DIGEST,
            "expected_measurement_schedule_digest": self.schedule_digest,
            "expected_metrics_implementation_digest": self.implementation_digest,
            **overrides,
        }
        return qualify_phase3_quantitative_metrics(
            self.evidence if evidence is None else evidence,
            **arguments,
        )

    def test_exact_happy_path_returns_only_a_bounded_metrics_pass(self) -> None:
        result = self.qualify()

        self.assertEqual(result["authority"], AUTHORITY)
        self.assertEqual(result["decision"], {"status": "PASS"})
        self.assertEqual(result["attribution"]["denominator"], 100)
        self.assertEqual(result["attribution"]["attributed"], 99)
        self.assertEqual(result["attribution"]["unattributed"], 1)
        self.assertEqual(result["latency"]["nearest_rank"], 95)
        self.assertEqual(result["latency"]["p95_ns"], 100_000_000)
        self.assertEqual(result["overhead"]["pair_count"], 100)
        self.assertEqual(self.schedule["schema"], MEASUREMENT_SCHEDULE_SCHEMA)
        self.assertEqual(canonical_digest(self.schedule), self.schedule_digest)
        self.assertEqual(
            self.schedule["attempt_schedule"]["attempt_ids"],
            self.attempt_ids,
        )
        self.assertEqual(
            self.schedule["attempt_schedule"]["attempt_families"],
            self.attempt_families,
        )
        self.assertEqual(
            self.schedule["overhead_schedule"]["pair_bindings"],
            self.pair_bindings,
        )
        self.assertEqual(
            result["bindings"]["measurement_schedule_digest"],
            self.schedule_digest,
        )
        self.assertEqual(
            result["bindings"]["metrics_implementation_digest"],
            self.implementation_digest,
        )
        self.assertRegex(
            result["inventory"]["overhead_pair_bindings_digest"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(result["blocking"]["exfiltration"]["denominator"], 49)
        self.assertEqual(result["blocking"]["destructive"]["denominator"], 50)
        rendered = canonical_json(result).decode("ascii").lower()
        for forbidden in (
            "phase3_exit_eligible",
            "edr_eligible",
            "installer_work_eligible",
            "release_eligible",
        ):
            self.assertNotIn(forbidden, rendered)

        parsed = qualify_phase3_quantitative_metrics_bytes(
            canonical_json(self.evidence),
            expected_attempt_ids=self.attempt_ids,
            expected_attempt_families=self.attempt_families,
            expected_overhead_pair_bindings=self.pair_bindings,
            expected_unattributed_attempt_id=self.negative_control_id,
            expected_gate_manifest_digest=MANIFEST_DIGEST,
            expected_campaign_contract_digest=CAMPAIGN_DIGEST,
            expected_runtime_identity_digest=RUNTIME_DIGEST,
            expected_measurement_schedule_digest=self.schedule_digest,
            expected_metrics_implementation_digest=self.implementation_digest,
        )
        self.assertEqual(parsed, result)

    def test_implementation_matches_the_frozen_measurement_contract(self) -> None:
        manifest = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "benchmark"
                / "phase3-exit-gate-manifest-v1.json"
            ).read_bytes()
        )
        measurement = manifest["measurement_contract"]

        self.assertEqual(
            measurement["attempt_schedule"]["attempt_count"], EXPECTED_ATTEMPTS
        )
        self.assertEqual(measurement["latency"]["sample_count"], EXPECTED_ATTEMPTS)
        self.assertEqual(measurement["latency"]["clock_id"], CLOCK_ID)
        self.assertEqual(measurement["latency"]["statistic"], "NEAREST_RANK_P95")
        self.assertEqual(measurement["overhead"]["pair_count"], EXPECTED_OVERHEAD_PAIRS)
        self.assertEqual(
            measurement["overhead"]["timing_boundary"], TASK_TIMING_BOUNDARY
        )
        self.assertEqual(
            measurement["overhead"]["statistic"], "AGGREGATE_RATIO_OF_TOTALS"
        )
        thresholds = {item["id"]: item for item in manifest["numeric_exit_thresholds"]}
        self.assertEqual(
            thresholds["EVENT_ATTRIBUTION_RATE"]["value"]
            * ATTRIBUTION_THRESHOLD_DENOMINATOR,
            100 * ATTRIBUTION_THRESHOLD_NUMERATOR,
        )
        self.assertEqual(
            thresholds["P95_SYNCHRONOUS_DECISION_LATENCY"]["value"] * 1_000_000,
            LATENCY_THRESHOLD_NS,
        )
        self.assertEqual(
            thresholds["TASK_OVERHEAD"]["value"] * OVERHEAD_SCALE,
            100 * (OVERHEAD_LIMIT - OVERHEAD_SCALE),
        )

    def test_attempt_inventory_rejects_missing_extra_duplicate_and_reordering(
        self,
    ) -> None:
        variants = []
        missing = deepcopy(self.evidence)
        missing["attempts"].pop()
        variants.append(missing)
        extra = deepcopy(self.evidence)
        extra["attempts"][-1]["attempt_id"] = "attempt-extra"
        variants.append(extra)
        duplicate = deepcopy(self.evidence)
        duplicate["attempts"][-1]["attempt_id"] = self.attempt_ids[-2]
        variants.append(duplicate)
        reordered = deepcopy(self.evidence)
        reordered["attempts"][1], reordered["attempts"][2] = (
            reordered["attempts"][2],
            reordered["attempts"][1],
        )
        variants.append(reordered)

        for variant in variants:
            with (
                self.subTest(variant=variants.index(variant)),
                self.assertRaises(Phase3QuantitativeMetricsError),
            ):
                self.qualify(variant)

    def test_denominator_shrinkage_fails_even_when_evidence_is_also_shrunk(
        self,
    ) -> None:
        shrunk = deepcopy(self.evidence)
        shrunk["attempts"].pop()
        with self.assertRaisesRegex(Phase3QuantitativeMetricsError, "exactly 100"):
            self.qualify(
                shrunk,
                expected_attempt_ids=self.attempt_ids[:-1],
            )

        with self.assertRaisesRegex(Phase3QuantitativeMetricsError, "exactly 100"):
            bindings = deepcopy(self.pair_bindings)
            bindings.pop(self.pair_ids[-1])
            self.qualify(expected_overhead_pair_bindings=bindings)

    def test_overhead_inventories_reject_missing_extra_and_duplicates(self) -> None:
        for field in ("baseline_samples", "instrumented_samples"):
            missing = deepcopy(self.evidence)
            missing[field].pop()
            extra = deepcopy(self.evidence)
            extra[field][-1]["pair_id"] = "pair-extra"
            duplicate = deepcopy(self.evidence)
            duplicate[field][-1]["pair_id"] = self.pair_ids[-2]
            for name, variant in (
                ("missing", missing),
                ("extra", extra),
                ("duplicate", duplicate),
            ):
                with (
                    self.subTest(field=field, mutation=name),
                    self.assertRaises(Phase3QuantitativeMetricsError),
                ):
                    self.qualify(variant)

    def test_negative_control_is_exactly_one_unattributed_blocked_and_clean(
        self,
    ) -> None:
        variants = []
        missing = deepcopy(self.evidence)
        missing["attempts"][0]["negative_control"] = False
        variants.append(missing)
        duplicate = deepcopy(self.evidence)
        duplicate["attempts"][1]["negative_control"] = True
        variants.append(duplicate)
        attributed = deepcopy(self.evidence)
        attributed["attempts"][0]["attributed"] = True
        variants.append(attributed)
        allowed = deepcopy(self.evidence)
        allowed["attempts"][0]["blocked_pre_effect"] = False
        variants.append(allowed)
        residue = deepcopy(self.evidence)
        residue["attempts"][0]["residue_detected"] = True
        variants.append(residue)

        for variant in variants:
            with (
                self.subTest(variant=variants.index(variant)),
                self.assertRaises(Phase3QuantitativeMetricsError),
            ):
                self.qualify(variant)

    def test_attribution_uses_exact_integer_cross_multiplication(self) -> None:
        evidence = deepcopy(self.evidence)
        evidence["attempts"][1]["attributed"] = False
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError, "below the exact 99 percent"
        ):
            self.qualify(evidence)

        result = self.qualify()
        self.assertEqual(result["attribution"]["comparison_left"], 9_900)
        self.assertEqual(result["attribution"]["comparison_right"], 9_900)

    def test_families_are_nonzero_and_cannot_pool_block_results(self) -> None:
        no_destructive = deepcopy(self.evidence)
        for attempt in no_destructive["attempts"]:
            if attempt["family"] == "DESTRUCTIVE":
                attempt["family"] = "EXFILTRATION"
        with self.assertRaisesRegex(Phase3QuantitativeMetricsError, "family changed"):
            self.qualify(no_destructive)

        expected_without_destructive = {
            attempt_id: ("EXFILTRATION" if family == "DESTRUCTIVE" else family)
            for attempt_id, family in self.attempt_families.items()
        }
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError, "destructive.*nonzero"
        ):
            self.qualify(
                no_destructive,
                expected_attempt_families=expected_without_destructive,
            )

        pooled = deepcopy(self.evidence)
        pooled["attempts"][-1]["blocked_pre_effect"] = False
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError, "destructive.*fully blocked"
        ):
            self.qualify(pooled)

        residue = deepcopy(self.evidence)
        residue["attempts"][-1]["residue_detected"] = True
        with self.assertRaisesRegex(Phase3QuantitativeMetricsError, "residue"):
            self.qualify(residue)

    def test_nearest_rank_p95_and_strict_500ms_boundary(self) -> None:
        nearest_rank = deepcopy(self.evidence)
        for index, attempt in enumerate(nearest_rank["attempts"]):
            delta = 499_999_999 if index < 94 else 900_000_000
            attempt["decision_finalized_boottime_ns"] = (
                attempt["request_accepted_boottime_ns"] + delta
            )
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError, "p95.*strictly below"
        ):
            self.qualify(nearest_rank)

        equality = deepcopy(self.evidence)
        for attempt in equality["attempts"]:
            attempt["decision_finalized_boottime_ns"] = (
                attempt["request_accepted_boottime_ns"] + 500_000_000
            )
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError, "p95.*strictly below"
        ):
            self.qualify(equality)

    def test_timing_rejects_negative_order_and_non_boottime_clock(self) -> None:
        reversed_time = deepcopy(self.evidence)
        reversed_time["attempts"][3]["decision_finalized_boottime_ns"] = (
            reversed_time["attempts"][3]["request_accepted_boottime_ns"] - 1
        )
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError, "decision precedes"
        ):
            self.qualify(reversed_time)

        wrong_clock = deepcopy(self.evidence)
        wrong_clock["clock_id"] = "CLOCK_MONOTONIC"
        with self.assertRaisesRegex(Phase3QuantitativeMetricsError, "clock_id"):
            self.qualify(wrong_clock)

    def test_overhead_uses_aggregate_integer_totals_and_strict_boundary(self) -> None:
        result = self.qualify()
        self.assertEqual(result["overhead"]["baseline_total_ns"], 100_000)
        self.assertEqual(result["overhead"]["instrumented_total_ns"], 109_900)
        self.assertLess(
            result["overhead"]["comparison_left"],
            result["overhead"]["comparison_right"],
        )

        equality = deepcopy(self.evidence)
        for sample in equality["instrumented_samples"]:
            sample["completed_boottime_ns"] = sample["started_boottime_ns"] + 1_100
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError, "strictly below 10 percent"
        ):
            self.qualify(equality)

    def test_overhead_samples_reject_binding_drift(self) -> None:
        for collection in ("baseline_samples", "instrumented_samples"):
            for field in (
                "task_digest",
                "input_digest",
                "host_profile_digest",
            ):
                evidence = deepcopy(self.evidence)
                evidence[collection][7][field] = "sha256:" + "f" * 64
                with (
                    self.subTest(collection=collection, field=field),
                    self.assertRaisesRegex(
                        Phase3QuantitativeMetricsError,
                        "changed from the caller-held binding",
                    ),
                ):
                    self.qualify(evidence)

        coordinated = deepcopy(self.evidence)
        for collection in ("baseline_samples", "instrumented_samples"):
            coordinated[collection][7]["task_digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError,
            "changed from the caller-held binding",
        ):
            self.qualify(coordinated)

    def test_overhead_samples_reject_boundary_status_and_reversed_timing(
        self,
    ) -> None:
        wrong_boundary = deepcopy(self.evidence)
        wrong_boundary["baseline_samples"][4]["timing_boundary"] = (
            "TASK_STARTED_TO_TASK_COMPLETED"
        )
        with self.assertRaisesRegex(Phase3QuantitativeMetricsError, "timing_boundary"):
            self.qualify(wrong_boundary)

        incomplete = deepcopy(self.evidence)
        incomplete["instrumented_samples"][4]["status"] = "FAILED"
        with self.assertRaisesRegex(Phase3QuantitativeMetricsError, "status"):
            self.qualify(incomplete)

        reversed_timing = deepcopy(self.evidence)
        reversed_timing["baseline_samples"][4]["completed_boottime_ns"] = (
            reversed_timing["baseline_samples"][4]["started_boottime_ns"]
        )
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError, "completion must follow"
        ):
            self.qualify(reversed_timing)

    def test_exact_scalar_types_reject_bool_float_and_string_aliases(self) -> None:
        mutations = (
            ("attributed integer", "attempts", 1, "attributed", 1),
            (
                "blocked integer",
                "attempts",
                1,
                "blocked_pre_effect",
                1,
            ),
            (
                "timestamp boolean",
                "attempts",
                1,
                "decision_finalized_boottime_ns",
                True,
            ),
            (
                "timestamp float",
                "attempts",
                1,
                "decision_finalized_boottime_ns",
                2.0,
            ),
            (
                "duration boolean",
                "baseline_samples",
                1,
                "completed_boottime_ns",
                True,
            ),
            (
                "duration float",
                "instrumented_samples",
                1,
                "completed_boottime_ns",
                1_099.0,
            ),
        )
        for name, collection, index, field, value in mutations:
            evidence = deepcopy(self.evidence)
            evidence[collection][index][field] = value
            with (
                self.subTest(mutation=name),
                self.assertRaises(Phase3QuantitativeMetricsError),
            ):
                self.qualify(evidence)

    def test_raw_parser_rejects_duplicates_nonfinite_floats_and_whitespace(
        self,
    ) -> None:
        raw = canonical_json(self.evidence)
        variants = {
            "duplicate": raw.replace(b'{"attempts":', b'{"attempts":[],"attempts":', 1),
            "nonfinite": raw.replace(b"100000000", b"NaN", 1),
            "finite_float": raw.replace(b"100000000", b"100000000.0", 1),
            "noncanonical": b" " + raw,
        }
        for name, hostile in variants.items():
            with (
                self.subTest(mutation=name),
                self.assertRaises(Phase3QuantitativeMetricsError),
            ):
                qualify_phase3_quantitative_metrics_bytes(
                    hostile,
                    expected_attempt_ids=self.attempt_ids,
                    expected_attempt_families=self.attempt_families,
                    expected_overhead_pair_bindings=self.pair_bindings,
                    expected_unattributed_attempt_id=self.negative_control_id,
                    expected_gate_manifest_digest=MANIFEST_DIGEST,
                    expected_campaign_contract_digest=CAMPAIGN_DIGEST,
                    expected_runtime_identity_digest=RUNTIME_DIGEST,
                    expected_measurement_schedule_digest=self.schedule_digest,
                    expected_metrics_implementation_digest=self.implementation_digest,
                )

    def test_schedule_digest_blocks_drift_and_coordinated_evidence_repins(
        self,
    ) -> None:
        changed_families = deepcopy(self.attempt_families)
        changed_families[self.attempt_ids[1]] = "DESTRUCTIVE"
        family_evidence = deepcopy(self.evidence)
        family_evidence["attempts"][1]["family"] = "DESTRUCTIVE"

        changed_pairs = deepcopy(self.pair_bindings)
        changed_pairs[self.pair_ids[7]]["task_digest"] = "sha256:" + "f" * 64
        pair_evidence = deepcopy(self.evidence)
        for collection in ("baseline_samples", "instrumented_samples"):
            pair_evidence[collection][7]["task_digest"] = "sha256:" + "f" * 64

        variants = (
            (
                "attempt family",
                family_evidence,
                {"expected_attempt_families": changed_families},
            ),
            (
                "negative control",
                deepcopy(self.evidence),
                {
                    "expected_unattributed_attempt_id": self.attempt_ids[1],
                },
            ),
            (
                "overhead binding",
                pair_evidence,
                {"expected_overhead_pair_bindings": changed_pairs},
            ),
        )
        for name, evidence, changed in variants:
            schedule_arguments = {
                "expected_attempt_ids": self.attempt_ids,
                "expected_attempt_families": self.attempt_families,
                "expected_overhead_pair_bindings": self.pair_bindings,
                "expected_unattributed_attempt_id": self.negative_control_id,
                "expected_gate_manifest_digest": MANIFEST_DIGEST,
                "expected_campaign_contract_digest": CAMPAIGN_DIGEST,
                "expected_runtime_identity_digest": RUNTIME_DIGEST,
                **changed,
            }
            repinned_digest = canonical_digest(
                build_phase3_measurement_schedule(**schedule_arguments)
            )
            evidence["bindings"]["measurement_schedule_digest"] = repinned_digest
            with (
                self.subTest(mutation=name),
                self.assertRaisesRegex(
                    Phase3QuantitativeMetricsError,
                    "measurement schedule digest changed",
                ),
            ):
                self.qualify(evidence, **changed)

    def test_verifier_pin_rejects_caller_and_evidence_drift(self) -> None:
        module_path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "aragorn"
            / "phase3_quantitative_metrics.py"
        )
        exact_module_digest = (
            "sha256:" + hashlib.sha256(module_path.read_bytes()).hexdigest()
        )
        self.assertEqual(metrics_implementation_digest(), exact_module_digest)

        changed_digest = "sha256:" + "f" * 64
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError,
            "metrics implementation digest changed",
        ):
            self.qualify(expected_metrics_implementation_digest=changed_digest)

        evidence = deepcopy(self.evidence)
        evidence["bindings"]["metrics_implementation_digest"] = changed_digest
        with self.assertRaisesRegex(
            Phase3QuantitativeMetricsError,
            "metrics bindings.metrics_implementation_digest changed",
        ):
            self.qualify(evidence)

    def test_bindings_are_caller_held_and_exact(self) -> None:
        for field, keyword in (
            ("gate_manifest_digest", "expected_gate_manifest_digest"),
            ("campaign_contract_digest", "expected_campaign_contract_digest"),
            ("runtime_identity_digest", "expected_runtime_identity_digest"),
            (
                "measurement_schedule_digest",
                "expected_measurement_schedule_digest",
            ),
            (
                "metrics_implementation_digest",
                "expected_metrics_implementation_digest",
            ),
        ):
            evidence = deepcopy(self.evidence)
            evidence["bindings"][field] = "sha256:" + "d" * 64
            with self.subTest(field=field):
                with self.assertRaisesRegex(Phase3QuantitativeMetricsError, "changed"):
                    self.qualify(evidence)
                with self.assertRaisesRegex(Phase3QuantitativeMetricsError, "changed"):
                    self.qualify(**{keyword: "sha256:" + "d" * 64})


if __name__ == "__main__":
    unittest.main()
