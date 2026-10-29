"""Inert retained joins only, never a native timing or acceptance sample.

Existing data constructors are composed without inheriting or invoking any
historical test method. All three real consumers verify the resulting records.
Only temporary CAS files are created; no worker, broker, clock or workload runs.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
from io import BytesIO
import json
import unittest
from unittest.mock import patch

from aragorn import native_phase3_ingress_interval_verify as subject
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_native_phase3_clock_domain_verify as clock_data
from tests import test_runtime_broker_decision_measurement_verify as broker_data
from tests import test_runtime_broker_effective_receipt_verify as effective_data
from tests import test_runtime_worker_ingress_verify as ingress_data


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class JoinedData:
    """Explicit test-only structural composition, not a runtime execution adapter."""

    def __init__(self):
        self.broker = broker_data.BrokerDecisionMeasurementVerifyTests()
        self.broker.setUp()
        self.effective = effective_data.BrokerEffectiveReceiptVerifyTests()
        self.records, _arguments = ingress_data._fixture()
        self.before, self.after = clock_data._fixture()
        # The old broker-only data used a general identifier. Native worker
        # tool-call identity is a digest, so rebuild every dependent CAS edge.
        self.broker.request["tool_call_id"] = self.records["ingress"]["body"][
            "worker_request"
        ]["tool_call_digest"]
        self._rebuild_broker_request()
        self.worker = {
            key: self.broker.attribution[key]
            for key in ("pid", "start_time_ticks", "uid", "gid")
        }
        self.worker_binding = {
            "schema": "aragorn/runtime-action-worker-binding/v1",
            **{
                key: self.broker.request[key]
                for key in (
                    "runtime_digest",
                    "active_skill_digest",
                    "policy_digest",
                    "policy_version",
                )
            },
        }
        request = {
            "schema": "aragorn/runtime-action-worker-request/v1",
            "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "target_name": self.broker.profiled["envelope"]["effect"]["target_name"],
            "payload_base64": self.broker.profiled["envelope"]["effect"][
                "payload_base64"
            ],
            "session_id": self.broker.request["session_id"],
            "run_id": self.broker.request["run_id"],
            "tool_call_digest": self.broker.request["tool_call_id"],
        }
        self.records["ingress"]["body"]["worker_request"] = request
        self.records["action"]["body"]["action_request"] = deepcopy(self.broker.request)
        for record in self.records.values():
            record["worker_binding"] = deepcopy(self.worker_binding)
            record["worker_binding_digest"] = canonical_digest(self.worker_binding)
        self._worker_epoch(self.worker)
        namespace = deepcopy(self.records["startup"]["time_namespace"])
        self.before.update(
            boot_id=self.broker.process["boot_id"],
            read_started_boottime_ns=120,
            read_finished_boottime_ns=150,
        )
        self.after.update(
            boot_id=self.broker.process["boot_id"],
            read_started_boottime_ns=2100,
            read_finished_boottime_ns=2200,
        )
        for observation in (self.before, self.after):
            observation["processes"] = {
                "collector": {
                    "pid": 1,
                    "start_time_ticks": 1,
                    "uid": 0,
                    "gid": 0,
                    "time_namespace": deepcopy(namespace),
                },
                "worker": {**self.worker, "time_namespace": deepcopy(namespace)},
                "broker": {
                    **{key: self.broker.process[key] for key in self.worker},
                    "time_namespace": deepcopy(namespace),
                },
            }

    def _rebuild_broker_request(self):
        fixture = self.broker
        fixture.profiled["measured_action"]["tool_call_id"] = fixture.request[
            "tool_call_id"
        ]
        fixture.profiled["request_digest"] = canonical_digest(fixture.request)
        fixture.profiled["envelope_digest"] = canonical_digest(
            fixture.profiled["envelope"]
        )
        lease = deepcopy(fixture.state["claim"]["lease"])
        lease["request_digest"] = canonical_digest(fixture.request)
        lease["submission_digest"] = canonical_digest(fixture.profiled)
        # Existing pure claim constructor on actual inert data, not a renamed
        # predecessor observation or a mocked-success consumer result.
        legacy = {
            **fixture.profiled,
            "schema": "aragorn/runtime-observed-create-submission/v1",
        }
        legacy.pop("runtime_attribution")
        fixture.state["claim"] = broker_data.v4._build_claim(
            fixture.grant,
            lease,
            legacy,
            fixture.attribution,
            canonical_digest(fixture.profiled),
            101,
        )
        fixture.decision["request_digest"] = canonical_digest(fixture.request)
        fixture.decision["measured_action_digest"] = canonical_digest(
            fixture.profiled["measured_action"]
        )
        fixture.result["request_digest"] = canonical_digest(fixture.request)
        fixture.receipt["submission_digest"] = canonical_digest(fixture.profiled)
        fixture.receipt["broker_result_digest"] = canonical_digest(fixture.result)
        fixture.pending.update(
            action_request_digest=canonical_digest(fixture.request),
            submission_digest=canonical_digest(fixture.profiled),
            lease_digest=canonical_digest(lease),
        )
        fixture.final["policy_decision_digest"] = canonical_digest(fixture.decision)

    def _worker_epoch(self, worker):
        self.worker = dict(worker)
        for record in self.records.values():
            record["worker_identity"] = {
                **worker,
                "uids": [worker["uid"]] * 4,
                "gids": [worker["gid"]] * 4,
            }

    def _rechain(self):
        request = self.records["ingress"]["body"]["worker_request"]
        request_pin = canonical_digest(request)
        self.records["ingress"]["body"]["worker_request_digest"] = request_pin
        attempt = self.records["attempt"]["body"]
        attempt["worker_request_digest"] = request_pin
        attempt["attempt"]["event"].update(
            {key: request[key] for key in ("session_id", "run_id", "tool_call_digest")}
        )
        attempt["attempt"]["event"]["worker_request_digest"] = request_pin
        action = self.records["action"]["body"]
        action["worker_request_digest"] = request_pin
        action["action_request_digest"] = canonical_digest(action["action_request"])
        ingress_data._rehash_attempt(self.records)
        ingress_data._rechain(self.records)

    @staticmethod
    def retain(store, raw):
        return store.put_expected(
            BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw)
        )

    def arguments(self):
        self._rechain()
        effective = self.effective.arguments(self.broker)
        self.retain(self.broker.evidence, effective["completion_raw"])
        self.retain(self.broker.inputs, effective["expected_binding_raw"])
        records = {
            stage: canonical_json(value) for stage, value in self.records.items()
        }
        before, after = canonical_json(self.before), canonical_json(self.after)
        for raw in (*records.values(), before, after):
            self.retain(self.broker.evidence, raw)
        return {
            **{stage + "_raw": raw for stage, raw in records.items()},
            "expected_record_digests": {
                stage: _digest(raw) for stage, raw in records.items()
            },
            "clock_before_raw": before,
            "clock_after_raw": after,
            "expected_clock_before_digest": _digest(before),
            "expected_clock_after_digest": _digest(after),
            **{
                key: effective[key]
                for key in (
                    "completion_raw",
                    "expected_completion_digest",
                    "expected_binding_raw",
                    "expected_binding_digest",
                    "input_cas",
                    "evidence_cas",
                )
            },
            "expected_worker": dict(self.worker),
            "expected_broker_process": deepcopy(self.broker.process),
            "expected_worker_binding_digest": canonical_digest(self.worker_binding),
            "expected_genesis_digest": ingress_data.GENESIS,
        }

    def close(self):
        self.broker.doCleanups()


class NativeIngressIntervalTests(unittest.TestCase):
    def fixture(self):
        fixture = JoinedData()
        self.addCleanup(fixture.close)
        return fixture

    def test_real_consumers_join_one_bounded_recorded_interval_without_effect_claims(
        self,
    ):
        fixture = self.fixture()
        arguments = fixture.arguments()
        with (
            patch.object(
                CAS, "put", side_effect=AssertionError("verification wrote CAS")
            ),
            patch.object(
                CAS,
                "put_expected",
                side_effect=AssertionError("verification wrote CAS"),
            ),
            patch(
                "time.clock_gettime_ns",
                side_effect=AssertionError("verification sampled a clock"),
            ),
        ):
            result = subject.verify_native_ingress_interval(**arguments)
        self.assertEqual(
            result["status"], "RETAINED_INGRESS_TO_EFFECTIVE_FINAL_INTERVAL_VERIFIED"
        )
        self.assertEqual(
            result["retained_interval"],
            {
                "clock_id": "CLOCK_BOOTTIME",
                "start_boundary": "AUTHENTICATED_NON_RECEIPT_FRAME_BEFORE_OPEN_ATTEMPT_GATE",
                "end_boundary": "SHARED_CORE_EFFECTIVE_FINAL_VERDICT",
                "ingress_boottime_ns": 200,
                "finalized_boottime_ns": 2000,
                "elapsed_ns": 1800,
            },
        )
        self.assertEqual(result["decision"], dict.fromkeys(subject.FALSE_FLAGS, False))
        self.assertTrue(all(flag is False for flag in result["decision"].values()))
        self.assertNotIn("semantics", result)
        self.assertEqual(result["limitations"], list(subject.LIMITATIONS))
        self.assertEqual(
            result["action_request_digest"], canonical_digest(fixture.broker.request)
        )
        self.assertEqual(result["recorded_broker_outcome"]["verdict"], "BLOCK")
        self.assertEqual(
            result["input_digests"]["worker_records"],
            arguments["expected_record_digests"],
        )
        self.assertLess(
            result["chronology"]["worker_stages"]["startup"],
            result["chronology"]["external_read_brackets"]["before"][
                "started_boottime_ns"
            ],
        )
        # The old commitment clock is deliberately incomparable, not rewritten.
        commitment = json.loads(
            fixture.broker.inputs.read(
                fixture.broker.plan["collection_commitment_digest"]
            )
        )
        self.assertEqual(commitment["prepared_boottime_ns"], 100_000_000_000)

    def test_individually_valid_worker_and_clock_epochs_must_match_broker_attribution(
        self,
    ):
        fixture = self.fixture()
        changed = {**fixture.worker, "pid": 101, "start_time_ticks": 13}
        fixture._worker_epoch(changed)
        for observation in (fixture.before, fixture.after):
            observation["processes"]["worker"].update(changed)
        with self.assertRaisesRegex(
            subject.NativeIngressIntervalVerificationError, "profile attribution"
        ):
            subject.verify_native_ingress_interval(**fixture.arguments())

    def test_individually_valid_records_must_share_clock_namespace_and_broker_boot(
        self,
    ):
        for change in ("namespace", "boot"):
            with self.subTest(change=change):
                fixture = self.fixture()
                if change == "namespace":
                    for record in fixture.records.values():
                        record["time_namespace"]["inode"] += 1
                else:
                    for observation in (fixture.before, fixture.after):
                        observation["boot_id"] = "00000000-0000-0000-0000-000000000099"
                with self.assertRaisesRegex(
                    subject.NativeIngressIntervalVerificationError,
                    "namespace or broker boot",
                ):
                    subject.verify_native_ingress_interval(**fixture.arguments())

    def test_individually_valid_worker_action_cannot_join_another_broker_action(self):
        fixture = self.fixture()
        fixture.records["ingress"]["body"]["worker_request"]["session_id"] = (
            "other-inert-session"
        )
        fixture.records["action"]["body"]["action_request"]["session_id"] = (
            "other-inert-session"
        )
        with self.assertRaisesRegex(
            subject.NativeIngressIntervalVerificationError, "action digests differ"
        ):
            subject.verify_native_ingress_interval(**fixture.arguments())

    def test_external_broker_epoch_must_match_the_effective_pending_process(self):
        fixture = self.fixture()
        for observation in (fixture.before, fixture.after):
            observation["processes"]["broker"]["start_time_ticks"] += 1
        with self.assertRaises(subject.NativeIngressIntervalVerificationError):
            subject.verify_native_ingress_interval(**fixture.arguments())

    def test_all_request_events_must_fit_external_brackets_and_broker_order(self):
        for change in ("early-ingress", "late-action", "early-after"):
            with self.subTest(change=change):
                fixture = self.fixture()
                if change == "early-ingress":
                    fixture.records["ingress"]["boottime_ns"] = 140
                elif change == "late-action":
                    fixture.records["action"]["boottime_ns"] = 1100
                else:
                    fixture.after["read_started_boottime_ns"] = 1999
                with self.assertRaisesRegex(
                    subject.NativeIngressIntervalVerificationError,
                    "external brackets or causal order",
                ):
                    subject.verify_native_ingress_interval(**fixture.arguments())

    def test_touching_external_boundaries_are_allowed_but_bool_epochs_are_not(self):
        fixture = self.fixture()
        fixture.before["read_finished_boottime_ns"] = 200
        fixture.after["read_started_boottime_ns"] = 2000
        self.assertEqual(
            subject.verify_native_ingress_interval(**fixture.arguments())[
                "retained_interval"
            ]["elapsed_ns"],
            1800,
        )
        arguments = fixture.arguments()
        arguments["expected_worker"]["start_time_ticks"] = True
        with self.assertRaises(subject.NativeIngressIntervalVerificationError):
            subject.verify_native_ingress_interval(**arguments)

    def test_negative_control_plan_is_not_an_attributed_interval(self):
        fixture = self.fixture()
        fixture.broker.plan["attempt_id"] = "synthetic-000"
        scheduled = {
            "kind": "attempt",
            "attempt_id": "synthetic-000",
            "family": "EXFILTRATION",
            "negative_control": True,
            "collection_digest": fixture.broker.plan["collection_commitment_digest"],
            "deployment_digest": fixture.broker.plan["deployment_identity_digest"],
        }
        fixture.broker.plan["scheduled_measurement_request_digest"] = canonical_digest(
            scheduled
        )
        with self.assertRaisesRegex(
            subject.NativeIngressIntervalVerificationError, "attributed native attempt"
        ):
            subject.verify_native_ingress_interval(**fixture.arguments())

    def test_missing_mismatched_or_writable_inputs_refuse(self):
        fixture = self.fixture()
        arguments = fixture.arguments()
        for change in (
            {"startup_raw": arguments["startup_raw"] + b"\n"},
            {"expected_binding_digest": ingress_data.OTHER},
            {"expected_clock_before_digest": ingress_data.OTHER},
            {
                "expected_record_digests": {
                    key: value
                    for key, value in arguments["expected_record_digests"].items()
                    if key != "action"
                }
            },
            {"input_cas": fixture.broker.inputs},
            {"evidence_cas": fixture.broker.evidence},
        ):
            with self.subTest(change=tuple(change)):
                with self.assertRaises(subject.NativeIngressIntervalVerificationError):
                    subject.verify_native_ingress_interval(**(arguments | change))

    def test_caller_expectations_are_detached_before_any_cas_read(self):
        fixture = self.fixture()
        arguments = fixture.arguments()
        expected_worker = deepcopy(arguments["expected_worker"])
        expected_broker = deepcopy(arguments["expected_broker_process"])
        expected_pins = dict(arguments["expected_record_digests"])
        read = arguments["evidence_cas"].read

        def mutate_caller(pin, *, max_bytes):
            arguments["expected_worker"]["pid"] = 9999
            arguments["expected_broker_process"]["start_time_ticks"] = 9999
            arguments["expected_record_digests"]["startup"] = ingress_data.OTHER
            return read(pin, max_bytes=max_bytes)

        with patch.object(arguments["evidence_cas"], "read", side_effect=mutate_caller):
            result = subject.verify_native_ingress_interval(**arguments)
        self.assertEqual(result["worker_identity"], expected_worker)
        self.assertEqual(result["broker_process_custody_claim"], expected_broker)
        self.assertEqual(result["input_digests"]["worker_records"], expected_pins)

    def test_final_provided_record_readback_and_broker_closure_replay_are_required(
        self,
    ):
        for mode in ("clock-before", "broker-result"):
            with self.subTest(mode=mode):
                fixture = self.fixture()
                arguments = fixture.arguments()
                selected = (
                    arguments["expected_clock_before_digest"]
                    if mode == "clock-before"
                    else canonical_digest(fixture.broker.result)
                )
                trigger = 2 if mode == "clock-before" else 3
                read = arguments["evidence_cas"].read
                hits = []

                def guarded(pin, *, max_bytes):
                    if pin == selected:
                        hits.append(pin)
                        if len(hits) == trigger:
                            raise CASError("inert final custody loss")
                    return read(pin, max_bytes=max_bytes)

                with patch.object(
                    arguments["evidence_cas"], "read", side_effect=guarded
                ):
                    with self.assertRaises(
                        subject.NativeIngressIntervalVerificationError
                    ):
                        subject.verify_native_ingress_interval(**arguments)
                self.assertEqual(len(hits), trigger)


if __name__ == "__main__":
    unittest.main()
