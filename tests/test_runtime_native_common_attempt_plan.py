"""Inert original-plan composition; declared inventory is not campaign evidence."""

from contextlib import contextmanager
from copy import deepcopy
from io import BytesIO
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_native_common_attempt_plan as subject
from tests import test_native_phase3_common_preparation as common_data
from tests import test_runtime_broker_measurement_plan as plan_data
from tests import test_runtime_native_common_measurement_handoff as handoff_data


class Fixture:
    def __init__(self, test):
        self.common = common_data.NativeCommonPreparationTests()
        self.common.setUp()
        test.addCleanup(self.common.doCleanups)
        inventory = plan_data.BrokerMeasurementPlanTests()
        inventory.setUp()
        test.addCleanup(inventory.doCleanups)
        template = json.loads(
            inventory.arguments["source_cas"].read(
                inventory.arguments["expected_schedule_digest"]
            )
        )
        self.cas = self.common.cas
        self.plan = CAS(self.common.root / "private-plan")
        self.journal = []
        self.common_arguments = {
            name: value
            for name, value in self.common.arguments.items()
            if name != "provisioning_inputs"
        }
        expected = subject.common.prepare_native_common_deployment(
            **self.common.arguments
        )
        pairs = deepcopy(template["overhead_schedule"]["pair_bindings"])
        # Caller fixture declares the real rendered OS profile before planning;
        # production must reject a mismatch rather than rewrite pair bindings.
        for pair in pairs.values():
            pair["host_profile_digest"] = expected["deployment"]["bindings"][
                "os_profile"
            ]
        self.functions = subject.handoff._functions()
        self.pins = {
            role: "sha256:"
            + hashlib.sha256(
                Path(sys.modules[function.__module__].__file__).read_bytes()
            ).hexdigest()
            for role, function in self.functions.items()
        }
        attempts = template["attempt_schedule"]
        self.arguments = {
            "common_arguments": self.common_arguments,
            "provisioning_inputs": self.common.inputs,
            "expected_attempt_ids": attempts["attempt_ids"],
            "expected_attempt_families": attempts["attempt_families"],
            "expected_unattributed_attempt_id": attempts[
                "unattributed_negative_control_attempt_id"
            ],
            "expected_overhead_pair_bindings": pairs,
            "expected_gate_manifest_digest": template["bindings"][
                "gate_manifest_digest"
            ],
            "expected_campaign_contract_digest": template["bindings"][
                "campaign_contract_digest"
            ],
            "selected_attempt_id": "attempt-001",
            "expected_boot_id": common_data.BOOT,
            "protected_descriptor_raw": canonical_json(self.common.descriptor),
            "payload_raw": common_data.PAYLOAD,
            "source_pins": self.pins,
            "evidence_cas": self.cas,
            "plan_cas": self.plan,
            "public_blob_attempts": self.journal,
        }

    def build(self, **updates):
        with patch.object(subject.collector, "_boottime_ns", side_effect=[100, 200]):
            return subject.prepare_native_common_attempt_plan(
                **(self.arguments | updates)
            )


class NativeCommonAttemptPlanTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture(self)

    def test_one_original_preparation_real_closures_and_public_private_separation(self):
        calls = []
        codes = {function.__code__ for function in self.fixture.functions.values()}

        def profile(frame, event, argument):
            if event == "call" and frame.f_code in codes:
                calls.append(frame.f_code.co_name)

        previous = sys.getprofile()
        sys.setprofile(profile)
        try:
            with patch.object(
                subject.collector,
                "prepare_phase3_measurement_collection",
                wraps=subject.collector.prepare_phase3_measurement_collection,
            ) as prepare:
                result = self.fixture.build()
        finally:
            sys.setprofile(previous)
        prepare.assert_called_once()
        self.assertEqual(calls, [])
        collection = json.loads(result["collection_preparation_raw"])
        common = json.loads(result["common_preparation_raw"])
        measured = json.loads(result["measurement_prepared_raw"])
        request = json.loads(result["request_raw"])
        self.assertEqual(collection["commitment"]["prepared_boottime_ns"], 100)
        self.assertEqual(collection["commitment_readback_boottime_ns"], 200)
        self.assertEqual(
            collection["schedule"]["bindings"]["runtime_identity_digest"],
            common["deployment_digest"],
        )
        self.assertEqual(
            measured["binding"]["collection_commitment_digest"],
            collection["commitment_digest"],
        )
        self.assertEqual(
            measured["binding"]["scheduled_measurement_request_digest"],
            canonical_digest(result["scheduled_request"]),
        )
        self.assertEqual(
            request["measurement_binding_digest"], result["binding_digest"]
        )
        self.assertEqual(result["binding_raw"], canonical_json(measured["binding"]))
        self.assertEqual(len(request["expected_file_digests"]), 28)
        self.assertEqual(
            collection["schedule"]["overhead_schedule"]["pair_bindings"],
            self.fixture.arguments["expected_overhead_pair_bindings"],
        )
        self.assertTrue(
            all(value is False for value in result["report"]["decision"].values())
        )
        self.assertNotIn("input_blobs", result)
        self.assertEqual(
            result["public_blob_digests"],
            sorted(row["digest"] for row in self.fixture.journal),
        )
        grant = self.fixture.common.inputs[subject.common.old.live._GRANT]
        grant_pin = subject.common.old._digest(grant)
        self.assertEqual(self.fixture.cas.read(grant_pin), grant)
        self.assertEqual(self.fixture.plan.read(grant_pin), grant)
        self.assertNotIn(grant_pin, result["public_blob_digests"])
        private_pins = {
            subject.common.old._digest(raw)
            for raw in self.fixture.common.inputs.values()
        }
        self.assertFalse(private_pins & set(result["public_blob_digests"]))
        for pin in result["public_blob_digests"]:
            raw = self.fixture.cas.read(pin)
            self.assertNotIn(grant, raw)
        for name in (
            "common_preparation",
            "collection_preparation",
            "measurement_prepared",
            "binding",
            "request",
            "report",
        ):
            self.assertEqual(
                self.fixture.cas.read(result[name + "_digest"]), result[name + "_raw"]
            )

    def test_original_bytes_are_accepted_by_real_held_handoff_without_regeneration(
        self,
    ):
        result = self.fixture.build()
        measured = json.loads(result["measurement_prepared_raw"])
        collection = json.loads(result["collection_preparation_raw"])
        claim = (
            self.fixture.cas.root
            / subject.collector._PREPARED_CLAIMS
            / (collection["commitment_digest"][7:] + ".json")
        )
        inert = SimpleNamespace(
            claim=claim,
            measured=measured,
            measured_pin=result["measurement_prepared_digest"],
        )

        @contextmanager
        def owned(container, boot):
            self.assertEqual(
                (container, boot), (common_data.CONTAINER, common_data.BOOT)
            )
            yield lambda: None

        def provision(**arguments):
            return handoff_data.Fixture.provision(inert, **arguments)

        with (
            patch.object(subject.handoff, "_fixture", owned),
            patch.object(subject.collector, "_boottime_ns", return_value=300),
            patch.object(
                subject.collector,
                "prepare_phase3_measurement_collection",
                side_effect=AssertionError("no second collection"),
            ),
            patch.object(
                subject.handoff.provisioning,
                "provision_runtime_native_measurement",
                side_effect=provision,
            ) as invoked,
        ):
            with subject.handoff.hold_prepared_native_common_measurement(
                collection_preparation_raw=result["collection_preparation_raw"],
                expected_collection_preparation_digest=result[
                    "collection_preparation_digest"
                ],
                common_preparation_raw=result["common_preparation_raw"],
                expected_common_preparation_digest=result["common_preparation_digest"],
                measurement_prepared_raw=result["measurement_prepared_raw"],
                expected_measurement_prepared_digest=result[
                    "measurement_prepared_digest"
                ],
                expected_binding_digest=result["binding_digest"],
                scheduled_request=result["scheduled_request"],
                provisioning_inputs=self.fixture.common.inputs,
                expected_container_id=common_data.CONTAINER,
                expected_boot_id=common_data.BOOT,
                protected_descriptor_raw=canonical_json(self.fixture.common.descriptor),
                payload_raw=common_data.PAYLOAD,
                evidence_cas=self.fixture.cas,
                source_pins=self.fixture.pins,
            ) as session:
                self.assertEqual(session.request_raw, result["request_raw"])
                self.assertEqual(
                    session.report["commitment_digest"], collection["commitment_digest"]
                )
                session.guard()
        invoked.assert_called_once()

    def test_invalid_inventory_negative_control_or_fixed_action_refuses_before_clock(
        self,
    ):
        bad_pairs = deepcopy(self.fixture.arguments["expected_overhead_pair_bindings"])
        bad_pairs["pair-000"]["host_profile_digest"] = common_data.PIN
        mutations = [
            {"selected_attempt_id": "attempt-000"},
            {"selected_attempt_id": "task-001"},
            {
                "expected_attempt_ids": self.fixture.arguments["expected_attempt_ids"][
                    :-1
                ]
            },
            {"expected_overhead_pair_bindings": bad_pairs},
            {"payload_raw": b"changed payload"},
            {
                "protected_descriptor_raw": canonical_json(
                    {**self.fixture.common.descriptor, "root_inode": 655}
                )
            },
            {"source_pins": {**self.fixture.pins, "execute": common_data.PIN}},
        ]
        for mutation in mutations:
            with (
                self.subTest(mutation=tuple(mutation)),
                patch.object(
                    subject.collector,
                    "_boottime_ns",
                    side_effect=AssertionError("invalid inputs reached clock"),
                ) as clock,
                self.assertRaises(subject.NativeCommonAttemptPlanError),
            ):
                subject.prepare_native_common_attempt_plan(
                    **(self.fixture.arguments | mutation)
                )
            clock.assert_not_called()
            self.assertEqual(self.fixture.journal, [])

    def test_changed_actual_seven_writer_refuses_before_collection(self):
        inputs = {**self.fixture.common.inputs, subject.common.old.live._GRANT: b"{}"}
        with (
            patch.object(
                subject.collector,
                "prepare_phase3_measurement_collection",
                side_effect=AssertionError("invalid writer reached preparation"),
            ) as preparation,
            self.assertRaises(subject.NativeCommonAttemptPlanError),
        ):
            self.fixture.build(provisioning_inputs=inputs)
        preparation.assert_not_called()
        self.assertEqual(self.fixture.journal, [])

    def test_distinct_fresh_private_stores_required(self):
        with self.assertRaises(subject.NativeCommonAttemptPlanError):
            self.fixture.build(plan_cas=self.fixture.cas)
        self.fixture.cas.put(BytesIO(b"inert residue"), max_bytes=20)
        with (
            patch.object(
                subject.collector,
                "_boottime_ns",
                side_effect=AssertionError("residue reached clock"),
            ) as clock,
            self.assertRaises(subject.NativeCommonAttemptPlanError),
        ):
            subject.prepare_native_common_attempt_plan(**self.fixture.arguments)
        clock.assert_not_called()
        self.assertEqual(self.fixture.journal, [])

    def test_nonempty_public_journal_is_not_reused_or_exported(self):
        self.fixture.journal.append(
            {"role": "untrusted", "digest": common_data.PIN, "bytes": 1}
        )
        with self.assertRaises(subject.NativeCommonAttemptPlanError) as caught:
            self.fixture.build()
        self.assertEqual(
            caught.exception._native_common_attempt_public_blob_digests, []
        )
        self.assertEqual(
            caught.exception._native_common_attempt_plan["public_blob_attempts"], []
        )

    def test_public_candidate_is_journaled_before_failing_publication(self):
        original = CAS.put_expected

        def put(store, source, **kwargs):
            if (
                self.fixture.journal
                and self.fixture.journal[-1]["role"]
                == "original_collection_preparation"
            ):
                self.assertEqual(
                    self.fixture.journal[-1]["digest"], kwargs["expected_digest"]
                )
                raise CASError("inert failed publication")
            return original(store, source, **kwargs)

        with (
            patch.object(CAS, "put_expected", new=put),
            self.assertRaises(subject.NativeCommonAttemptPlanError) as caught,
        ):
            self.fixture.build()
        failed = self.fixture.journal[-1]
        self.assertIn(
            failed["digest"],
            caught.exception._native_common_attempt_public_blob_digests,
        )
        self.assertEqual(
            caught.exception._native_common_attempt_plan["public_blob_attempts"],
            self.fixture.journal,
        )
        with self.assertRaises(CASError):
            self.fixture.cas.read(failed["digest"])
        self.assertIn(
            "PLAN_FINAL_SOURCE_CAS_RECORD_FAILED", caught.exception.__cause__.__notes__
        )

    def test_broker_plan_failure_keeps_original_commitment_private_state_and_no_retry(
        self,
    ):
        with (
            patch.object(
                subject.broker_plan,
                "prepare_broker_decision_measurement_binding",
                side_effect=RuntimeError("inert plan failure"),
            ),
            self.assertRaises(subject.NativeCommonAttemptPlanError) as caught,
        ):
            self.fixture.build()
        journal = caught.exception._native_common_attempt_plan["public_blob_attempts"]
        self.assertIn("original_commitment", {row["role"] for row in journal})
        grant = self.fixture.common.inputs[subject.common.old.live._GRANT]
        self.assertEqual(
            self.fixture.cas.read(subject.common.old._digest(grant)), grant
        )
        self.assertNotIn(
            subject.common.old._digest(grant),
            caught.exception._native_common_attempt_public_blob_digests,
        )
        with (
            patch.object(
                subject.collector,
                "prepare_phase3_measurement_collection",
                side_effect=AssertionError("no retry"),
            ) as preparation,
            self.assertRaises(subject.NativeCommonAttemptPlanError),
        ):
            self.fixture.build(public_blob_attempts=[])
        preparation.assert_not_called()

    def test_interrupted_preparation_keeps_bounded_public_candidates_and_propagates(
        self,
    ):
        primary = KeyboardInterrupt("inert interruption")
        with (
            patch.object(
                subject.collector,
                "prepare_phase3_measurement_collection",
                side_effect=primary,
            ),
            self.assertRaises(KeyboardInterrupt) as caught,
        ):
            self.fixture.build()
        self.assertIs(caught.exception, primary)
        report = primary._native_common_attempt_plan
        self.assertEqual(report["status"], "REFUSED")
        self.assertTrue(all(value is False for value in report["decision"].values()))
        self.assertIn(
            "original_schedule", {row["role"] for row in report["public_blob_attempts"]}
        )
        self.assertNotIn(
            "original_commitment",
            {row["role"] for row in report["public_blob_attempts"]},
        )

    def test_source_recheck_happens_when_first_common_public_write_fails(self):
        source = subject.collector._source
        calls, failed = [], False

        def read_source(function, pin):
            calls.append((function.__name__, failed))
            return source(function, pin)

        def fail(*args, **kwargs):
            nonlocal failed
            failed = True
            raise CASError("inert first write failure")

        with (
            patch.object(subject.collector, "_source", side_effect=read_source),
            patch.object(CAS, "put_expected", side_effect=fail),
            self.assertRaises(subject.NativeCommonAttemptPlanError),
        ):
            self.fixture.build()
        self.assertEqual(sum(after for _, after in calls), 3)

    def test_final_private_and_target_records_checked_independently_on_failure(self):
        original_put, original_read = CAS.put_expected, CAS.read
        failed = False
        reads = []
        primary = CASError("inert report publication failure")

        def put(store, source, **kwargs):
            nonlocal failed
            if (
                self.fixture.journal
                and self.fixture.journal[-1]["role"] == "plan_report"
            ):
                failed = True
                raise primary
            return original_put(store, source, **kwargs)

        def read(store, pin, *, max_bytes=1024 * 1024):
            if failed:
                reads.append((store.root, pin))
                if store.root == self.fixture.cas.root:
                    raise CASError("inert source custody loss")
            return original_read(store, pin, max_bytes=max_bytes)

        with (
            patch.object(CAS, "put_expected", new=put),
            patch.object(CAS, "read", new=read),
            self.assertRaises(subject.NativeCommonAttemptPlanError) as caught,
        ):
            self.fixture.build()
        self.assertIs(caught.exception.__cause__, primary)
        self.assertGreater(sum(root == self.fixture.cas.root for root, _ in reads), 2)
        self.assertEqual(
            len({pin for root, pin in reads if root == self.fixture.plan.root}), 13
        )
        self.assertIn("PLAN_FINAL_SOURCE_CAS_RECORD_FAILED", primary.__notes__)

    def test_public_report_and_dictionaries_are_detached_and_final_raws_read_back(self):
        result = self.fixture.build()
        original_raw = result["report_raw"]
        result["report"]["decision"]["resumable"] = True
        result["scheduled_request"]["attempt_id"] = "changed"
        self.fixture.journal[0]["role"] = "caller-mutated-after-return"
        self.assertEqual(self.fixture.cas.read(result["report_digest"]), original_raw)
        self.assertIs(json.loads(original_raw)["decision"]["resumable"], False)


if __name__ == "__main__":
    unittest.main()
