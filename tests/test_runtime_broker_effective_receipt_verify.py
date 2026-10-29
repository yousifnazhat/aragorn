"""Inert CAS-chain checks; no broker, target action, clock or service is run."""

from __future__ import annotations

from copy import deepcopy
from itertools import combinations
import unittest
from unittest.mock import patch

from aragorn import runtime_broker_effective_receipt_verify as subject
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_runtime_broker_decision_measurement_verify as fixtures


class BrokerEffectiveReceiptVerifyTests(unittest.TestCase):
    def fixture(self):
        # Composition only: historical TestCase methods are not collected here.
        fixture = fixtures.BrokerDecisionMeasurementVerifyTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def arguments(
        self,
        fixture,
        *,
        result_update=None,
        receipt_update=None,
        state_update=None,
        final_update=None,
        evidence_update=None,
        completion_update=None,
        retain_submission=True,
    ):
        """Rebuild actual receipt -> state -> evidence -> completion CAS edges.

        No production successor record builder is used to construct expectations.
        Updates are applied before downstream hashes, so semantic tampering has
        a genuine byte-consistent closure and cannot fail only on a stale digest.
        """
        result = deepcopy(fixture.result)
        result.update(result_update or {})
        receipt = {
            **deepcopy(fixture.receipt),
            "broker_result": result,
            "broker_result_digest": canonical_digest(result),
        }
        receipt.update(receipt_update or {})
        claim = fixture.state["claim"]
        profile = claim["profile_claim"]
        state = {
            **deepcopy(fixture.state),
            "result": {
                "schema": "aragorn/runtime-capability-grant-result/v1",
                "authority": "BROKER_GRANT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                "grant_digest": claim["grant_digest"],
                "lease_digest": claim["lease_digest"],
                "profile_result": {
                    "schema": "aragorn/runtime-capability-lease-result/v1",
                    "authority": "BROKER_LEASE_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                    "lease_digest": profile["lease_digest"],
                    "submission_digest": profile["submission_digest"],
                    "profile_receipt_digest": canonical_digest(receipt),
                    "broker_result_digest": canonical_digest(result),
                    "verdict": result["verdict"],
                    "effect_status": result["effect_status"],
                },
            },
        }
        state.update(state_update or {})
        final = {
            **deepcopy(fixture.final),
            **{
                key: result[key]
                for key in ("verdict", "reason_codes", "observation_digest")
            },
            "policy_decision_digest": canonical_digest(result["decision"])
            if result["decision"] is not None
            else None,
        }
        final.update(final_update or {})
        if retain_submission:
            fixture.put(fixture.evidence, fixture.profiled)
        evidence = {
            "schema": "aragorn/runtime-broker-decision-measurement/v2",
            "authority": "VALIDATED_GRANT_REDEMPTION_TIMING_ONLY_NOT_FULL_REQUEST_LATENCY_OR_PHASE3",
            "pending": fixture.pending,
            "effective_final_decision": final,
            "consumed_grant_state_digest": fixture.put(fixture.evidence, state),
            "profile_receipt_digest": fixture.put(fixture.evidence, receipt),
            "broker_result_digest": fixture.put(fixture.evidence, result),
            "decision": {
                "phase3_exit_eligible": False,
                "run_eligible": False,
                "quantitative_metrics_eligible": False,
            },
            "limitations": subject._RETAINED_LIMITS,
        }
        evidence.update(evidence_update or {})
        completion = {
            "schema": "aragorn/runtime-broker-decision-measurement-complete/v2",
            "pending_digest": canonical_digest(fixture.pending),
            "evidence_digest": fixture.put(fixture.evidence, evidence),
        }
        completion.update(completion_update or {})
        return {
            "completion_raw": canonical_json(completion),
            "expected_completion_digest": canonical_digest(completion),
            "expected_binding_raw": canonical_json(fixture.plan),
            "expected_binding_digest": canonical_digest(fixture.plan),
            "expected_process_identity": deepcopy(fixture.process),
            "input_cas": CAS(fixture.inputs.root, read_only=True),
            "evidence_cas": CAS(fixture.evidence.root, read_only=True),
        }

    def refuse(self, fixture, **updates):
        arguments = self.arguments(fixture, **updates)
        with self.assertRaises(subject.BrokerEffectiveReceiptVerificationError):
            subject.verify_broker_effective_receipt(**arguments)

    @staticmethod
    def policy_allow(fixture):
        fixture.decision["verdict"] = "ALLOW"
        fixture.decision["reason_codes"] = []

    def test_policy_block_and_allow_have_distinct_recorded_outcomes(self):
        for allowed in (False, True):
            with self.subTest(allowed=allowed):
                fixture = self.fixture()
                if allowed:
                    self.policy_allow(fixture)
                    fixture.result.update(
                        verdict="ALLOW", reason_codes=[], effect_status="CREATED"
                    )
                arguments = self.arguments(fixture)
                with (
                    patch.object(CAS, "put", side_effect=AssertionError("CAS write")),
                    patch.object(
                        CAS, "put_expected", side_effect=AssertionError("CAS write")
                    ),
                ):
                    verified = subject.verify_broker_effective_receipt(**arguments)
                self.assertEqual(
                    verified["schema"],
                    "aragorn/runtime-broker-decision-measurement-verification/v2",
                )
                self.assertEqual(
                    verified["recorded_policy_outcome"]["verdict"],
                    fixture.decision["verdict"],
                )
                self.assertEqual(
                    verified["recorded_broker_outcome"]["verdict"],
                    fixture.result["verdict"],
                )
                self.assertEqual(verified["broker_interval"]["elapsed_ns"], 1000)
                self.assertTrue(
                    all(value is False for value in verified["decision"].values())
                )
                self.assertNotIn("semantics", verified)

    def test_each_exact_broker_reason_vector_keeps_policy_separate(self):
        mismatch = sorted(subject._MISMATCH_REASONS)
        vectors = [
            list(group)
            for size in range(1, 5)
            for group in combinations(mismatch, size)
        ]
        vectors += [[code] for code in sorted(subject._SINGLE_REASONS)]
        for allowed in (False, True):
            fixture = self.fixture()
            if allowed:
                self.policy_allow(fixture)
            for reasons in vectors:
                with self.subTest(policy_allow=allowed, reasons=reasons):
                    arguments = self.arguments(
                        fixture, result_update={"reason_codes": reasons}
                    )
                    verified = subject.verify_broker_effective_receipt(**arguments)
                    self.assertEqual(
                        verified["recorded_broker_outcome"],
                        {
                            "verdict": "BLOCK",
                            "reason_codes": reasons,
                            "effect_status": "NOT_PERFORMED",
                        },
                    )
                    self.assertEqual(
                        verified["recorded_policy_outcome"]["verdict"],
                        "ALLOW" if allowed else "BLOCK",
                    )
                    self.assertIn(
                        "RECORDED_EFFECTIVE_BLOCK_DOES_NOT_PROVE_BROKER_REASON_OR_POLICY_CAUSALITY",
                        verified["limitations"],
                    )

    def test_exact_replay_alone_permits_absent_policy_and_none_digest(self):
        fixture = self.fixture()
        arguments = self.arguments(
            fixture,
            result_update={"decision": None, "reason_codes": ["BROKER_REPLAY_BLOCKED"]},
        )
        verified = subject.verify_broker_effective_receipt(**arguments)
        self.assertIsNone(verified["recorded_policy_outcome"])
        self.assertEqual(
            verified["recorded_broker_outcome"]["effect_status"], "NOT_PERFORMED"
        )
        self.assertTrue(all(value is False for value in verified["decision"].values()))

    def test_rehashed_absent_policy_other_outcomes_are_refused(self):
        fixture = self.fixture()
        for update in (
            {"reason_codes": ["ACTION_NOT_ALLOWED"]},
            {"reason_codes": ["BROKER_CLOCK_ROLLBACK"]},
            {"reason_codes": ["BROKER_REPLAY_BLOCKED"], "effect_status": "CREATED"},
            {"reason_codes": [], "verdict": "ALLOW", "effect_status": "CREATED"},
        ):
            with self.subTest(update=update):
                self.refuse(fixture, result_update={"decision": None, **update})

    def test_rehashed_replay_cannot_have_policy_or_smuggle_broker_reasons(self):
        fixture = self.fixture()
        self.refuse(fixture, result_update={"reason_codes": ["BROKER_REPLAY_BLOCKED"]})
        for code in (
            "BROKER_REPLAY_BLOCKED",
            "BROKER_CLOCK_ROLLBACK",
            "BROKER_UNKNOWN",
        ):
            fixture.decision["reason_codes"] = [code]
            with self.subTest(code=code):
                self.refuse(fixture, result_update={"reason_codes": [code]})

    def test_rehashed_unknown_mixed_unsorted_and_duplicate_vectors_refuse(self):
        fixture = self.fixture()
        self.policy_allow(fixture)
        for reasons in (
            [],
            ["BROKER_UNKNOWN"],
            ["ACTION_NOT_ALLOWED"],
            ["BROKER_CLOCK_ROLLBACK", "BROKER_DEADLINE_EXPIRED"],
            ["ACTION_NOT_ALLOWED", "BROKER_RUNTIME_PIN_MISMATCH"],
            ["BROKER_CLOCK_ROLLBACK", "BROKER_RUNTIME_PIN_MISMATCH"],
            ["BROKER_SENSOR_PIN_MISMATCH", "BROKER_RUNTIME_PIN_MISMATCH"],
            ["BROKER_RUNTIME_PIN_MISMATCH", "BROKER_RUNTIME_PIN_MISMATCH"],
        ):
            with self.subTest(reasons=reasons):
                self.refuse(fixture, result_update={"reason_codes": reasons})

    def test_rehashed_effect_and_policy_mismatch_cannot_claim_allow(self):
        fixture = self.fixture()
        for update in (
            {"verdict": "ALLOW", "reason_codes": [], "effect_status": "CREATED"},
            {"effect_status": "CREATED"},
            {"verdict": "ALLOW", "reason_codes": [], "effect_status": "NOT_PERFORMED"},
        ):
            with self.subTest(update=update):
                self.refuse(fixture, result_update=update)
        self.policy_allow(fixture)
        fixture.decision["reason_codes"] = ["ACTION_NOT_ALLOWED"]
        self.refuse(fixture, result_update={"reason_codes": ["BROKER_CLOCK_UNSTABLE"]})

    def test_rehashed_receipt_target_request_and_attribution_joins_refuse(self):
        fixture = self.fixture()
        for update in (
            {"target_name": "other.txt"},
            {"request_digest": fixtures.PIN},
            {"observation_digest": "not-a-digest"},
            {"authority": "OTHER_AUTHORITY"},
        ):
            with self.subTest(update=update):
                self.refuse(fixture, result_update=update)
        attribution = {**fixture.attribution, "uid": fixture.attribution["uid"] + 1}
        self.refuse(
            fixture,
            receipt_update={
                "runtime_attribution": attribution,
                "runtime_attribution_digest": canonical_digest(attribution),
            },
        )
        self.refuse(fixture, receipt_update={"submission_digest": fixtures.PIN})
        self.refuse(fixture, receipt_update={"broker_result_digest": fixtures.PIN})

    def test_rehashed_final_policy_digest_and_effective_fields_must_join(self):
        fixture = self.fixture()
        for update in (
            {"verdict": "ALLOW"},
            {"reason_codes": ["OTHER_REASON"]},
            {"observation_digest": "sha256:" + "b" * 64},
            {"policy_decision_digest": None},
            {"policy_decision_digest": fixtures.PIN},
            {"finalized_boottime_ns": 1000},
        ):
            with self.subTest(update=update):
                self.refuse(fixture, final_update=update)
        self.refuse(
            fixture,
            result_update={"decision": None, "reason_codes": ["BROKER_REPLAY_BLOCKED"]},
            final_update={"policy_decision_digest": canonical_digest(None)},
        )

    def test_native_lease_grant_policy_and_process_guards_remain(self):
        fixture = self.fixture()
        fixture.plan["payload_digest"] = fixtures.PIN
        self.refuse(fixture)
        fixture.plan["payload_digest"] = fixture.request["payload_digest"]
        fixture.decision["policy_digest"] = "sha256:" + "b" * 64
        self.refuse(fixture)
        fixture.decision["policy_digest"] = fixture.request["policy_digest"]
        fixture.state["claim"]["profile_claim"]["claimed_at_unix"] = 105
        self.refuse(fixture)
        fixture = self.fixture()
        arguments = self.arguments(fixture)
        arguments["expected_process_identity"]["start_time_ticks"] += 1
        with self.assertRaises(subject.BrokerEffectiveReceiptVerificationError):
            subject.verify_broker_effective_receipt(**arguments)

    def test_operator_binding_source_pins_and_missing_submission_refuse(self):
        fixture = self.fixture()
        arguments = self.arguments(fixture)
        changed = deepcopy(fixture.plan)
        changed["source_pins"]["runtime_action_broker_v4.py"] = "sha256:" + "b" * 64
        arguments["expected_binding_raw"] = canonical_json(changed)
        with self.assertRaises(subject.BrokerEffectiveReceiptVerificationError):
            subject.verify_broker_effective_receipt(**arguments)
        self.refuse(self.fixture(), retain_submission=False)

    def test_schema_and_claim_ceiling_cannot_be_rehashed_away(self):
        fixture = self.fixture()
        self.refuse(
            fixture,
            completion_update={
                "schema": "aragorn/runtime-broker-decision-measurement-complete/v1"
            },
        )
        self.refuse(
            fixture,
            evidence_update={
                "schema": "aragorn/runtime-broker-decision-measurement/v1"
            },
        )
        self.refuse(
            fixture, evidence_update={"limitations": fixtures.subject._RETAINED_LIMITS}
        )
        self.refuse(
            fixture,
            evidence_update={
                "decision": {
                    "phase3_exit_eligible": False,
                    "run_eligible": False,
                    "quantitative_metrics_eligible": True,
                }
            },
        )

    def test_nonfinal_grant_and_writable_stores_are_refused(self):
        fixture = self.fixture()
        self.refuse(fixture, state_update={"status": "CLAIMED", "result": None})
        arguments = self.arguments(fixture)
        arguments["input_cas"] = fixture.inputs
        with self.assertRaises(subject.BrokerEffectiveReceiptVerificationError):
            subject.verify_broker_effective_receipt(**arguments)

    def test_final_readback_is_required_for_the_real_retained_submission(self):
        fixture = self.fixture()
        arguments = self.arguments(fixture)
        store, pin = arguments["evidence_cas"], canonical_digest(fixture.profiled)
        original, counts = store.read, {}

        def disappear(digest, *, max_bytes):
            counts[digest] = counts.get(digest, 0) + 1
            if digest == pin and counts[digest] > 1:
                raise CASError("inert final readback loss")
            return original(digest, max_bytes=max_bytes)

        with (
            patch.object(store, "read", side_effect=disappear),
            self.assertRaises(subject.BrokerEffectiveReceiptVerificationError),
        ):
            subject.verify_broker_effective_receipt(**arguments)


if __name__ == "__main__":
    unittest.main()
