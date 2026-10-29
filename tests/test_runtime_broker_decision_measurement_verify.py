"""New verifier checks using synthetic retained data only; no native action runs."""

from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_action_broker_v4 as v4
from aragorn import runtime_broker_decision_measurement_verify as subject
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import (
    BINDING_DIMENSIONS,
    build_phase3_deployment_identity,
)
from aragorn.phase3_quantitative_metrics import build_phase3_measurement_schedule
from aragorn.runtime_capability_grant import (
    GRANT_AUTHORITY,
    GRANT_SCHEMA,
    LEASE_AUTHORITY,
    LEASE_SCHEMA,
)
from aragorn.runtime_process_profile import ATTRIBUTION_AUTHORITY, ATTRIBUTION_SCHEMA

PIN = "sha256:" + "a" * 64
BOOT = "00000000-1111-2222-3333-444444444444"


class BrokerDecisionMeasurementVerifyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.inputs = CAS(Path(temporary.name) / "inputs")
        self.evidence = CAS(Path(temporary.name) / "evidence")
        self.path = {
            "schema": "aragorn/runtime-protected-path/v1",
            "root_device": 10,
            "root_inode": 20,
            "target_name": "inert.txt",
        }
        payload = b"inert fixture, never executed"
        self.request = {
            "schema": "aragorn/runtime-action-request/v1",
            "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "runtime_digest": PIN,
            "session_id": "synthetic-session",
            "run_id": "synthetic-run",
            "tool_call_id": "synthetic-call",
            "active_skill_digest": PIN,
            "operation_digest": canonical_digest(
                {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
            ),
            "path_digest": self.put(self.inputs, self.path),
            "payload_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "policy_digest": PIN,
            "policy_version": 1,
            "issued_at_unix": 100,
            "expires_at_unix": 105,
        }
        self.attribution = {
            "schema": ATTRIBUTION_SCHEMA,
            "authority": ATTRIBUTION_AUTHORITY,
            "profile_digest": PIN,
            "runtime_digest": PIN,
            "executable_digest": PIN,
            "active_skill_digest": PIN,
            "skill_path": "/synthetic/SKILL.md",
            "cgroup": "/synthetic",
            "pid": 100,
            "uid": 1000,
            "gid": 1000,
            "start_time_ticks": 12,
            "mount_namespace": {"device": 1, "inode": 2},
        }
        envelope = {
            "schema": "aragorn/runtime-action-broker-request/v1",
            "request": self.request,
            "effect": {
                "schema": "aragorn/runtime-create-file/v1",
                "operation": "create",
                "target_name": "inert.txt",
                "payload_base64": base64.b64encode(payload).decode(),
            },
        }
        self.profiled = {
            "schema": "aragorn/runtime-observed-create-submission/v2",
            "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
            "sensor_digest": PIN,
            "envelope_digest": canonical_digest(envelope),
            "request_digest": canonical_digest(self.request),
            "runtime_peer": {
                key: self.attribution[key] for key in ("pid", "uid", "gid")
            },
            "measured_action": {
                "schema": "aragorn/measured-runtime-action/v1",
                **{key: self.request[key] for key in subject._MEASURED},
            },
            "envelope": envelope,
            "runtime_attribution": self.attribution,
        }
        self.grant = {
            "schema": GRANT_SCHEMA,
            "authority": GRANT_AUTHORITY,
            "grant_id": "f" * 64,
            "source_manifest_digest": PIN,
            "install_context_digest": PIN,
            "runtime_profile_digest": PIN,
            "runtime_digest": PIN,
            "active_skill_digest": PIN,
            "sensor_digest": PIN,
            "policy_digest": PIN,
            "policy_version": 1,
            "operation_digest": self.request["operation_digest"],
            "issued_at_unix": 90,
            "expires_at_unix": 120,
            "max_actions": 1,
        }
        lease = {
            "schema": LEASE_SCHEMA,
            "authority": LEASE_AUTHORITY,
            "grant_digest": self.put(self.inputs, self.grant),
            "lease_nonce": "e" * 64,
            "submission_digest": canonical_digest(self.profiled),
            "runtime_attribution_digest": canonical_digest(self.attribution),
            "request_digest": canonical_digest(self.request),
            "runtime_profile_digest": PIN,
            "sensor_digest": PIN,
            **{key: self.request[key] for key in subject._MATCH},
            "policy_version": 1,
            "issued_at_unix": 100,
            "expires_at_unix": 105,
            "max_actions": 1,
        }
        legacy = {
            **self.profiled,
            "schema": "aragorn/runtime-observed-create-submission/v1",
        }
        legacy.pop("runtime_attribution")
        claim = v4._build_claim(
            self.grant,
            lease,
            legacy,
            self.attribution,
            canonical_digest(self.profiled),
            101,
        )
        self.decision = {
            "schema": "aragorn/runtime-action-decision/v1",
            "authority": "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": canonical_digest(self.request),
            "active_context_digest": PIN,
            "measured_action_digest": canonical_digest(
                self.profiled["measured_action"]
            ),
            "policy_digest": PIN,
            "policy_version": 1,
            "evaluated_at_unix": 101,
            "revocation_snapshot_digest": PIN,
            "revocation_generation": 1,
            "minimum_revocation_generation": 1,
            "mediator_health_digest": PIN,
            "mediator_health_epoch": 1,
            "minimum_mediator_health_epoch": 1,
            "verdict": "BLOCK",
            "reason_codes": ["ACTION_NOT_ALLOWED"],
        }
        self.result = {
            "schema": "aragorn/runtime-action-broker-result/v1",
            "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": canonical_digest(self.request),
            "observation_digest": PIN,
            "target_name": "inert.txt",
            "verdict": "BLOCK",
            "reason_codes": ["ACTION_NOT_ALLOWED"],
            "effect_status": "NOT_PERFORMED",
            "decision": self.decision,
        }
        self.receipt = {
            "schema": "aragorn/runtime-process-profile-receipt/v1",
            "authority": "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
            "submission_digest": canonical_digest(self.profiled),
            "runtime_attribution": self.attribution,
            "runtime_attribution_digest": canonical_digest(self.attribution),
            "broker_result": self.result,
            "broker_result_digest": canonical_digest(self.result),
        }
        self.state = {
            "schema": "aragorn/runtime-capability-grant-state/v1",
            "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": canonical_digest(self.grant),
            "status": "CONSUMED",
            "claim": claim,
            "result": v4._result_record(claim, self.receipt),
        }
        deployment = build_phase3_deployment_identity(
            {
                name: self.inputs.put(BytesIO(name.encode()), max_bytes=128)
                for name in BINDING_DIMENSIONS
            }
        )
        ids = [f"synthetic-{index:03d}" for index in range(100)]
        schedule = build_phase3_measurement_schedule(
            expected_attempt_ids=ids,
            expected_attempt_families={
                name: "EXFILTRATION" if index < 50 else "DESTRUCTIVE"
                for index, name in enumerate(ids)
            },
            expected_unattributed_attempt_id=ids[0],
            expected_overhead_pair_bindings={
                f"pair-{index:03d}": {
                    "task_digest": PIN,
                    "input_digest": PIN,
                    "host_profile_digest": PIN,
                }
                for index in range(100)
            },
            expected_gate_manifest_digest=PIN,
            expected_campaign_contract_digest=PIN,
            expected_runtime_identity_digest=canonical_digest(deployment),
        )
        commitment = {
            "schema": "aragorn/phase3-measurement-collection-commitment/v1",
            "collection_id": "b" * 64,
            "schedule_digest": self.put(self.inputs, schedule),
            "deployment": deployment,
            "sources": {
                name: {
                    "module": "synthetic_never_imported",
                    "function": name,
                    "path": "/synthetic/unused.py",
                    "bytes": 10,
                    "digest": PIN,
                }
                for name in ("execute", "verify", "identity_reader")
            },
            "collector_digest": PIN,
            "metrics_implementation_digest": PIN,
            "clock_id": "CLOCK_BOOTTIME",
            # Deliberately incomparable: collector and broker clock namespaces are not joined.
            "prepared_boottime_ns": 100_000_000_000,
        }
        self.plan = {
            "schema": "aragorn/runtime-broker-decision-measurement-binding/v1",
            "boot_id": BOOT,
            "attempt_id": ids[1],
            "deployment_identity_digest": canonical_digest(deployment),
            "measurement_schedule_digest": canonical_digest(schedule),
            "collection_commitment_digest": self.put(self.inputs, commitment),
            "scheduled_measurement_request_digest": canonical_digest(
                {
                    "kind": "attempt",
                    "attempt_id": ids[1],
                    "family": "EXFILTRATION",
                    "negative_control": False,
                    "collection_digest": canonical_digest(commitment),
                    "deployment_digest": canonical_digest(deployment),
                }
            ),
            "grant_digest": canonical_digest(self.grant),
            "runtime_profile_digest": PIN,
            "sensor_digest": PIN,
            "source_pins": {name: PIN for name in subject._SOURCES},
            **{key: self.request[key] for key in subject._MATCH},
        }
        self.process = {
            "boot_id": BOOT,
            "pid": 200,
            "uid": 1001,
            "gid": 1001,
            "start_time_ticks": 10,
            "mount_namespace": "mnt:[123]",
        }
        self.pending = {
            "schema": "aragorn/runtime-broker-decision-measurement-pending/v1",
            "binding": self.plan,
            "process": self.process,
            "clock_id": "CLOCK_BOOTTIME",
            "acceptance_boundary": subject._ACCEPTED,
            "accepted_boottime_ns": 1000,
            "action_request_digest": canonical_digest(self.request),
            "submission_digest": canonical_digest(self.profiled),
            "lease_digest": canonical_digest(lease),
            "runtime_attribution_digest": canonical_digest(self.attribution),
        }
        self.final = {
            "finalized_boottime_ns": 2000,
            "verdict": "BLOCK",
            "reason_codes": ["ACTION_NOT_ALLOWED"],
            "observation_digest": PIN,
            "policy_decision_digest": canonical_digest(self.decision),
        }

    @staticmethod
    def put(store, value):
        raw = canonical_json(value)
        return store.put(BytesIO(raw), max_bytes=1024 * 1024)

    def arguments(self, *, retain_submission=True):
        if retain_submission:
            self.put(self.evidence, self.profiled)
        evidence = {
            "schema": "aragorn/runtime-broker-decision-measurement/v1",
            "authority": "VALIDATED_GRANT_REDEMPTION_TIMING_ONLY_NOT_FULL_REQUEST_LATENCY_OR_PHASE3",
            "pending": self.pending,
            "effective_final_decision": self.final,
            "consumed_grant_state_digest": self.put(self.evidence, self.state),
            "profile_receipt_digest": self.put(self.evidence, self.receipt),
            "broker_result_digest": self.put(self.evidence, self.result),
            "decision": {
                "phase3_exit_eligible": False,
                "run_eligible": False,
                "quantitative_metrics_eligible": False,
            },
            "limitations": subject._RETAINED_LIMITS,
        }
        complete = {
            "schema": "aragorn/runtime-broker-decision-measurement-complete/v1",
            "pending_digest": canonical_digest(self.pending),
            "evidence_digest": self.put(self.evidence, evidence),
        }
        return {
            "completion_raw": canonical_json(complete),
            "expected_completion_digest": canonical_digest(complete),
            "expected_binding_raw": canonical_json(self.plan),
            "expected_binding_digest": canonical_digest(self.plan),
            "expected_process_identity": deepcopy(self.process),
            "input_cas": CAS(self.inputs.root, read_only=True),
            "evidence_cas": CAS(self.evidence.root, read_only=True),
        }

    def test_exact_retained_chain_yields_only_one_broker_interval(self):
        arguments = self.arguments()
        with (
            patch.object(CAS, "put", side_effect=AssertionError("verifier wrote CAS")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("verifier wrote CAS")
            ),
        ):
            leaf = subject.verify_broker_decision_measurement(**arguments)
        self.assertEqual(leaf["receipt_chain"], "VERIFIED")
        self.assertEqual(leaf["broker_interval"]["elapsed_ns"], 1000)
        self.assertEqual(
            leaf["recorded_broker_outcome"]["effect_status"], "NOT_PERFORMED"
        )
        self.assertTrue(all(value is False for value in leaf["decision"].values()))
        self.assertNotIn("semantics", leaf)
        self.assertIn(
            "NO_CROSS_PROCESS_CLOCK_DOMAIN_OR_CHRONOLOGY_PROOF", leaf["limitations"]
        )

    def test_frozen_profile_without_extra_profiled_submission_is_insufficient(self):
        with self.assertRaises(subject.BrokerDecisionMeasurementVerificationError):
            subject.verify_broker_decision_measurement(
                **self.arguments(retain_submission=False)
            )

    def test_rehashed_plan_cannot_hide_native_action_or_process_mismatch(self):
        self.plan["payload_digest"] = PIN
        arguments = self.arguments()
        with self.assertRaisesRegex(
            subject.BrokerDecisionMeasurementVerificationError, "native create action"
        ):
            subject.verify_broker_decision_measurement(**arguments)
        self.plan["payload_digest"] = self.request["payload_digest"]
        arguments = self.arguments()
        arguments["expected_process_identity"]["start_time_ticks"] += 1
        with self.assertRaisesRegex(
            subject.BrokerDecisionMeasurementVerificationError, "custody pins"
        ):
            subject.verify_broker_decision_measurement(**arguments)

    def test_nonfinal_grant_mixed_verdict_and_reversed_clock_are_refused(self):
        self.final["finalized_boottime_ns"] = 1000
        with self.assertRaisesRegex(
            subject.BrokerDecisionMeasurementVerificationError, "strictly increasing"
        ):
            subject.verify_broker_decision_measurement(**self.arguments())
        self.final["finalized_boottime_ns"] = 2000
        self.state["status"] = "CLAIMED"
        self.state["result"] = None
        with self.assertRaisesRegex(
            subject.BrokerDecisionMeasurementVerificationError, "incomplete grant"
        ):
            subject.verify_broker_decision_measurement(**self.arguments())
        self.state["status"] = "CONSUMED"
        self.state["result"] = v4._result_record(self.state["claim"], self.receipt)
        self.decision["verdict"] = "ALLOW"
        self.decision["reason_codes"] = []
        self.receipt["broker_result_digest"] = canonical_digest(self.result)
        self.final["policy_decision_digest"] = canonical_digest(self.decision)
        with self.assertRaises(subject.BrokerDecisionMeasurementVerificationError):
            subject.verify_broker_decision_measurement(**self.arguments())

    def test_final_custody_readback_refuses_lost_profiled_submission(self):
        arguments = self.arguments()
        store, digest = arguments["evidence_cas"], canonical_digest(self.profiled)
        original, counts = store.read, {}

        def disappear_at_readback(pin, *, max_bytes):
            counts[pin] = counts.get(pin, 0) + 1
            if pin == digest and counts[pin] > 1:
                raise CASError("synthetic custody loss")
            return original(pin, max_bytes=max_bytes)

        with (
            patch.object(store, "read", side_effect=disappear_at_readback),
            self.assertRaises(subject.BrokerDecisionMeasurementVerificationError),
        ):
            subject.verify_broker_decision_measurement(**arguments)


if __name__ == "__main__":
    unittest.main()
