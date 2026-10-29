"""Inert adapter doubles; these are not retained runtime acceptance evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import phase3_measurement_collector as collector
from aragorn import phase3_quantitative_metrics as metrics
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import (
    BINDING_DIMENSIONS,
    Phase3DeploymentError,
    build_phase3_deployment_identity,
)


def verify_test_receipt(raw, request, boundaries):
    """Independently parse the inert executor's literal deny/completion records."""
    receipt = json.loads(raw)
    if receipt["boundaries"] != boundaries:
        raise ValueError("wrong timing")
    observation = receipt["observation"]
    if request["kind"] == "attempt":
        if observation != {
            "decision": "DENY",
            "attribution": None
            if request["negative_control"]
            else request["attempt_id"],
            "sink_items": [],
        }:
            raise ValueError("unexpected inert result")
        semantics = {
            "attributed": observation["attribution"] is not None,
            "blocked_pre_effect": observation["decision"] == "DENY",
            "residue_detected": bool(observation["sink_items"]),
        }
    else:
        if observation != {
            "completed_pair": request["pair_id"],
            "mode": request["mode"],
        }:
            raise ValueError("unexpected task result")
        semantics = {"completed": True}
    return {
        "receipt_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "request_digest": canonical_digest(request),
        "deployment_digest": request["deployment_digest"],
        "semantics": semantics,
    }


_ADAPTER = """from aragorn.oci_worker_protocol import canonical_digest, canonical_json
DEPLOYMENT = None
STORE = None
CALLS = []
FAULT = None

def identity_reader():
    return DEPLOYMENT

def execute(request, mark):
    # The plan and full schedule must already exist before the first action.
    import json
    commitment = json.loads(STORE.read(request["collection_digest"]))
    STORE.verify(commitment["schedule_digest"])
    CALLS.append(request)
    names = ("REQUEST_ACCEPTED", "DECISION_FINALIZED") if request["kind"] == "attempt" else ("TASK_ACCEPTED", "TASK_COMPLETED")
    if FAULT == "boundary":
        mark(names[1])
    boundaries = {name: mark(name) for name in names}
    if request["kind"] == "attempt":
        observation = {"decision": "DENY", "attribution": None if request["negative_control"] else request["attempt_id"], "sink_items": []}
    else:
        observation = {"completed_pair": request["pair_id"], "mode": request["mode"]}
    if FAULT == "deployment":
        DEPLOYMENT["bindings"]["policy"] = "sha256:" + "f" * 64
    if FAULT == "remove-deployment" and request.get("pair_id") == "pair-099" and request.get("mode") == "instrumented":
        digest = DEPLOYMENT["bindings"]["policy"]
        (STORE.root / "blobs" / "sha256" / digest[7:9] / digest[9:]).unlink()
    raw = canonical_json({"schema": "aragorn/phase3-local-measurement-receipt/v1", "request_digest": canonical_digest(request), "deployment_digest": request["deployment_digest"], "boundaries": boundaries, "observation": observation})
    if FAULT == "oversized":
        return b"x" * 65537
    if FAULT == "replay":
        raw = raw.replace(request["deployment_digest"].encode(), ("sha256:" + "e" * 64).encode())
    return raw
"""


class Phase3MeasurementCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        self.cas = CAS(root / "evidence")
        deployment = build_phase3_deployment_identity(
            {
                name: self.cas.put(BytesIO(name.encode()), max_bytes=128)
                for name in BINDING_DIMENSIONS
            }
        )
        self.deployment = deployment
        ids = [f"attempt-{n:03d}" for n in range(100)]
        self.schedule = metrics.build_phase3_measurement_schedule(
            expected_attempt_ids=ids,
            expected_attempt_families={
                name: "EXFILTRATION" if n < 50 else "DESTRUCTIVE"
                for n, name in enumerate(ids)
            },
            expected_unattributed_attempt_id=ids[0],
            expected_overhead_pair_bindings={
                f"pair-{n:03d}": {
                    "task_digest": "sha256:" + "a" * 64,
                    "input_digest": f"sha256:{n + 1:064x}",
                    "host_profile_digest": deployment["bindings"]["os_profile"],
                }
                for n in range(100)
            },
            expected_gate_manifest_digest="sha256:" + "b" * 64,
            expected_campaign_contract_digest="sha256:" + "c" * 64,
            expected_runtime_identity_digest=canonical_digest(deployment),
        )
        path = root / "inert_measurement_adapter.py"
        path.write_text(_ADAPTER)
        name = "phase3_inert_measurement_adapter"
        spec = importlib.util.spec_from_file_location(name, path)
        self.adapter = importlib.util.module_from_spec(spec)
        sys.modules[name] = self.adapter
        self.addCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(self.adapter)
        self.adapter.DEPLOYMENT = json.loads(canonical_json(deployment))
        self.adapter.STORE = self.cas
        self.pins = {
            "execute": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            "identity_reader": "sha256:"
            + hashlib.sha256(path.read_bytes()).hexdigest(),
            "verify": "sha256:"
            + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }

    def collect(self, **overrides):
        return collector.collect_phase3_measurements(
            self.schedule,
            deployment=self.deployment,
            evidence_cas=self.cas,
            execute=self.adapter.execute,
            identity_reader=self.adapter.identity_reader,
            verify=verify_test_receipt,
            source_pins=self.pins,
            **overrides,
        )

    def test_commits_before_callbacks_retains_receipts_and_feeds_real_qualifier(self):
        # Fake clock only in this inert interface test; production has no clock parameter.
        with patch.object(
            collector, "_boottime_ns", side_effect=itertools.count(1, 100)
        ):
            result = self.collect()
        self.assertEqual(len(self.adapter.CALLS), 300)
        self.assertEqual(len(result["provenance"]), 300)
        self.assertEqual(result["metrics_qualification"]["decision"]["status"], "PASS")
        evidence = json.loads(self.cas.read(result["evidence_digest"]))
        self.assertEqual(len(evidence["attempts"]), 100)
        self.assertEqual(len(evidence["baseline_samples"]), 100)
        self.assertEqual(len(evidence["instrumented_samples"]), 100)
        self.assertEqual(evidence["clock_id"], "CLOCK_BOOTTIME")
        first = result["provenance"][0]
        self.cas.verify(first["receipt_digest"])
        self.cas.verify(first["verified_observation_digest"])
        retained = dict(result)
        retained.pop("collection_digest")
        self.assertEqual(
            self.cas.read(result["collection_digest"]), canonical_json(retained)
        )
        self.assertIn(
            "NOT_SOURCE_SEMANTIC_OR_PHASE3_QUALIFICATION", result["authority"]
        )

    def test_boundary_receipt_and_deployment_failures_abort_without_retry(self):
        for fault in ("boundary", "oversized", "replay", "deployment"):
            with self.subTest(fault=fault):
                self.adapter.CALLS.clear()
                self.adapter.DEPLOYMENT = json.loads(canonical_json(self.deployment))
                self.adapter.FAULT = fault
                with (
                    patch.object(
                        collector, "_boottime_ns", side_effect=itertools.count(1, 100)
                    ),
                    self.assertRaises(collector.Phase3MeasurementCollectionError),
                ):
                    self.collect()
                self.assertEqual(len(self.adapter.CALLS), 1)

    def test_wrong_source_pin_is_refused_before_execution(self):
        self.pins["execute"] = "sha256:" + "0" * 64
        with self.assertRaises(collector.Phase3MeasurementCollectionError):
            self.collect()
        self.assertEqual(self.adapter.CALLS, [])

    def test_end_custody_refuses_removed_deployment_artifact(self):
        self.adapter.FAULT = "remove-deployment"
        with (
            patch.object(
                collector, "_boottime_ns", side_effect=itertools.count(1, 100)
            ),
            self.assertRaisesRegex(Phase3DeploymentError, "cannot be resolved"),
        ):
            self.collect()
        self.assertEqual(len(self.adapter.CALLS), 300)

    def test_threshold_failure_is_retained_without_replacing_samples(self):
        stamp = 1

        def slow_instrumented_clock():
            nonlocal stamp
            instrumented = (
                bool(self.adapter.CALLS)
                and self.adapter.CALLS[-1].get("mode") == "instrumented"
            )
            stamp += 120 if instrumented else 100
            return stamp

        with patch.object(
            collector, "_boottime_ns", side_effect=slow_instrumented_clock
        ):
            result = self.collect()
        self.assertEqual(len(self.adapter.CALLS), 300)
        self.assertEqual(
            result["metrics_qualification"]["decision"], {"status": "FAIL"}
        )
        self.assertIn("overhead", result["metrics_qualification"]["reason"])
        evidence = json.loads(self.cas.read(result["evidence_digest"]))
        baseline = evidence["baseline_samples"][0]
        instrumented = evidence["instrumented_samples"][0]
        self.assertEqual(
            baseline["completed_boottime_ns"] - baseline["started_boottime_ns"], 100
        )
        self.assertEqual(
            instrumented["completed_boottime_ns"] - instrumented["started_boottime_ns"],
            120,
        )

    def test_no_clock_fallback(self):
        with (
            patch.object(collector.sys, "platform", "darwin"),
            self.assertRaisesRegex(
                collector.Phase3MeasurementCollectionError, "CLOCK_BOOTTIME"
            ),
        ):
            self.collect()
        self.assertEqual(self.adapter.CALLS, [])


if __name__ == "__main__":
    unittest.main()
