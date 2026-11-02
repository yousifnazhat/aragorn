"""Inert preparation fixtures only; no clocks, runtime starts or acceptance data."""

from __future__ import annotations

import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import phase3_quantitative_metrics as metrics
from aragorn import runtime_broker_decision_measurement as helper
from aragorn import runtime_broker_measurement_plan as subject
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import (
    BINDING_DIMENSIONS,
    build_phase3_deployment_identity,
)
from aragorn.runtime_capability_grant import GRANT_AUTHORITY, GRANT_SCHEMA

PIN = "sha256:" + "a" * 64


class BrokerMeasurementPlanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        source = CAS(self.root / "source")

        def put(value):
            return source.put(BytesIO(canonical_json(value)), max_bytes=1024 * 1024)

        deployment = build_phase3_deployment_identity(
            {name: put({"inert_fixture": name}) for name in BINDING_DIMENSIONS}
        )
        identifiers = [f"attempt-{n:03d}" for n in range(100)]
        schedule = metrics.build_phase3_measurement_schedule(
            expected_attempt_ids=identifiers,
            expected_attempt_families={
                name: "EXFILTRATION" if n < 50 else "DESTRUCTIVE"
                for n, name in enumerate(identifiers)
            },
            expected_unattributed_attempt_id=identifiers[0],
            expected_overhead_pair_bindings={
                f"pair-{n:03d}": {
                    "task_digest": PIN,
                    "input_digest": f"sha256:{n + 1:064x}",
                    "host_profile_digest": deployment["bindings"]["os_profile"],
                }
                for n in range(100)
            },
            expected_gate_manifest_digest=PIN,
            expected_campaign_contract_digest=PIN,
            expected_runtime_identity_digest=canonical_digest(deployment),
        )
        schedule_digest = put(schedule)
        source_pins = {name: PIN for name in ("execute", "verify", "identity_reader")}
        commitment = {
            "schema": "aragorn/phase3-measurement-collection-commitment/v1",
            "collection_id": "1" * 64,
            "schedule_digest": schedule_digest,
            "deployment": deployment,
            "sources": {
                name: {
                    "module": name,
                    "function": name,
                    "path": "/inert/" + name + ".py",
                    "bytes": 1,
                    "digest": PIN,
                }
                for name in source_pins
            },
            "collector_digest": PIN,
            "metrics_implementation_digest": metrics.metrics_implementation_digest(),
            "clock_id": metrics.CLOCK_ID,
            "prepared_boottime_ns": 1,
        }
        commitment_digest = put(commitment)
        grant = {
            "schema": GRANT_SCHEMA,
            "authority": GRANT_AUTHORITY,
            "grant_id": "2" * 64,
            **{
                key: PIN
                for key in (
                    "source_manifest_digest",
                    "install_context_digest",
                    "runtime_profile_digest",
                    "runtime_digest",
                    "active_skill_digest",
                    "sensor_digest",
                    "policy_digest",
                )
            },
            "policy_version": 1,
            "operation_digest": canonical_digest(
                {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
            ),
            "issued_at_unix": 1,
            "expires_at_unix": 2,
            "max_actions": 1,
        }
        grant_digest = put(grant)
        path_digest = put(
            {
                "schema": "aragorn/runtime-protected-path/v1",
                "root_device": 1,
                "root_inode": 2,
                "target_name": "inert.txt",
            }
        )
        self.arguments = {
            "source_cas": CAS(source.root, read_only=True),
            "target_cas": CAS(self.root / "target"),
            "expected_commitment_digest": commitment_digest,
            "expected_schedule_digest": schedule_digest,
            "expected_deployment_digest": canonical_digest(deployment),
            "expected_grant_digest": grant_digest,
            "expected_path_digest": path_digest,
            "expected_payload_digest": PIN,
            "expected_collector_digest": PIN,
            "expected_collection_source_pins": source_pins,
            "expected_broker_source_pins": {
                name: metrics.metrics_implementation_digest()
                if name == "phase3_quantitative_metrics.py"
                else PIN
                for name in subject._SOURCES
            },
            "expected_boot_id": "00000000-0000-0000-0000-000000000001",
            "scheduled_request": {
                "kind": "attempt",
                "attempt_id": identifiers[1],
                "family": "EXFILTRATION",
                "negative_control": False,
                "collection_digest": commitment_digest,
                "deployment_digest": canonical_digest(deployment),
            },
        }

    def test_prepares_exact_helper_inputs_without_clocks_or_reusing_target(self):
        with patch(
            "time.clock_gettime_ns", side_effect=AssertionError("no clock during copy")
        ):
            result = subject.prepare_broker_decision_measurement_binding(
                **self.arguments
            )
        store = self.arguments["target_cas"]
        self.assertEqual(
            store.read(result["binding_digest"]), canonical_json(result["binding"])
        )
        self.assertTrue(all(value is False for value in result["decision"].values()))
        with patch.object(helper, "_INPUT", store.root):
            helper._inputs(result["binding"])
        for row in result["input_blobs"]:
            store.verify(row["digest"], max_bytes=row["bytes"])
        with self.assertRaises(subject.BrokerMeasurementPlanError):
            subject.prepare_broker_decision_measurement_binding(**self.arguments)

    def test_unattributed_or_rebound_plan_is_refused_before_any_copy(self):
        original = self.arguments["scheduled_request"]
        for request, pin in (
            ({**original, "attempt_id": "attempt-000", "negative_control": True}, PIN),
            ({**original, "collection_digest": PIN}, PIN),
            (original, "sha256:" + "b" * 64),
        ):
            with self.subTest(request=request["attempt_id"], collector=pin):
                with self.assertRaises(subject.BrokerMeasurementPlanError):
                    subject.prepare_broker_decision_measurement_binding(
                        **{
                            **self.arguments,
                            "scheduled_request": request,
                            "expected_collector_digest": pin,
                        }
                    )
                self.assertEqual(
                    list(
                        (self.arguments["target_cas"].root / "blobs/sha256").iterdir()
                    ),
                    [],
                )


    def test_metrics_pin_must_join_the_committed_implementation(self):
        mismatched = dict(self.arguments["expected_broker_source_pins"])
        mismatched["phase3_quantitative_metrics.py"] = PIN
        with self.assertRaises(subject.BrokerMeasurementPlanError):
            subject.prepare_broker_decision_measurement_binding(
                **{**self.arguments, "expected_broker_source_pins": mismatched}
            )
        result = subject.prepare_broker_decision_measurement_binding(**self.arguments)
        self.assertEqual(
            result["binding"]["source_pins"]["phase3_quantitative_metrics.py"],
            metrics.metrics_implementation_digest(),
        )


if __name__ == "__main__":
    unittest.main()
