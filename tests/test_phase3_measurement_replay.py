"""Synthetic retained documents only; no runtime, executor, or existing tests run."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path

from aragorn import phase3_measurement_replay as subject
from aragorn import phase3_quantitative_metrics as metrics
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import (
    BINDING_DIMENSIONS,
    build_phase3_deployment_identity,
)

_CALLS = []


def synthetic_receipt_verifier(raw, request, boundaries):
    """Derive test semantics from raw observations, never the retained verdict."""
    receipt = json.loads(raw)
    if receipt["boundaries"] != boundaries:
        raise ValueError("test boundary mismatch")
    _CALLS.append(request)
    observation = receipt["observation"]
    if request["kind"] == "attempt":
        semantics = {
            "attributed": observation["subject"] == request["attempt_id"],
            "blocked_pre_effect": observation["decision"] == "DENY",
            "residue_detected": bool(observation["sink_items"]),
        }
    else:
        semantics = {
            "completed": observation
            == {"completed_pair": request["pair_id"], "mode": request["mode"]}
        }
    return {
        "receipt_digest": canonical_digest(receipt),
        "request_digest": canonical_digest(request),
        "deployment_digest": request["deployment_digest"],
        "semantics": semantics,
    }


class Phase3MeasurementReplayTests(unittest.TestCase):
    def setUp(self):
        _CALLS.clear()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.cas = CAS(temporary.name)
        self.deployment = build_phase3_deployment_identity(
            {
                key: self.cas.put(BytesIO(key.encode()), max_bytes=128)
                for key in BINDING_DIMENSIONS
            }
        )
        ids = [f"attempt-{index:03d}" for index in range(100)]
        self.schedule = metrics.build_phase3_measurement_schedule(
            expected_attempt_ids=ids,
            expected_attempt_families={
                key: "EXFILTRATION" if index < 50 else "DESTRUCTIVE"
                for index, key in enumerate(ids)
            },
            expected_overhead_pair_bindings={
                f"pair-{index:03d}": {
                    "task_digest": "sha256:" + "a" * 64,
                    "input_digest": f"sha256:{index + 1:064x}",
                    "host_profile_digest": self.deployment["bindings"]["os_profile"],
                }
                for index in range(100)
            },
            expected_unattributed_attempt_id=ids[0],
            expected_gate_manifest_digest="sha256:" + "b" * 64,
            expected_campaign_contract_digest="sha256:" + "c" * 64,
            expected_runtime_identity_digest=canonical_digest(self.deployment),
        )
        self.source_pins = {
            "execute": "sha256:" + "d" * 64,
            "identity_reader": "sha256:" + "e" * 64,
            "verify": "sha256:"
            + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }
        self.commitment = {
            "schema": "aragorn/phase3-measurement-collection-commitment/v1",
            "collection_id": "f" * 64,
            "schedule_digest": self.put(self.schedule),
            "deployment": self.deployment,
            "sources": {
                "verify": {
                    "module": __name__,
                    "function": "synthetic_receipt_verifier",
                    "path": str(Path(__file__).absolute()),
                    "bytes": Path(__file__).stat().st_size,
                    "digest": self.source_pins["verify"],
                },
                **{
                    key: {
                        "module": "never_imported_adapter",
                        "function": key,
                        "path": "/not-executed/adapter.py",
                        "bytes": 100,
                        "digest": self.source_pins[key],
                    }
                    for key in ("execute", "identity_reader")
                },
            },
            "collector_digest": "sha256:" + "1" * 64,
            "metrics_implementation_digest": metrics.metrics_implementation_digest(),
            "clock_id": "CLOCK_BOOTTIME",
            "prepared_boottime_ns": 1,
        }
        commitment_pin = self.put(self.commitment)
        self.evidence = {
            "schema": metrics.INPUT_SCHEMA,
            "bindings": {
                **self.schedule["bindings"],
                "measurement_schedule_digest": self.commitment["schedule_digest"],
                "metrics_implementation_digest": self.commitment[
                    "metrics_implementation_digest"
                ],
            },
            "clock_id": "CLOCK_BOOTTIME",
            "attempts": [],
            "baseline_samples": [],
            "instrumented_samples": [],
        }
        requests = [
            {
                "kind": "attempt",
                "attempt_id": key,
                "family": self.schedule["attempt_schedule"]["attempt_families"][key],
                "negative_control": key == ids[0],
            }
            for key in ids
        ]
        requests += [
            {"kind": "task", "mode": mode, "pair_id": pair_id, **binding}
            for pair_id, binding in self.schedule["overhead_schedule"][
                "pair_bindings"
            ].items()
            for mode in ("baseline", "instrumented")
        ]
        provenance = []
        for index, base in enumerate(requests):
            request = {
                **base,
                "collection_digest": commitment_pin,
                "deployment_digest": canonical_digest(self.deployment),
            }
            start, end = 10 + index * 1000, 110 + index * 1000
            if base["kind"] == "attempt":
                boundaries = {"REQUEST_ACCEPTED": start, "DECISION_FINALIZED": end}
                observation = {
                    "subject": None if base["negative_control"] else base["attempt_id"],
                    "decision": "DENY",
                    "sink_items": [],
                }
                semantics = {
                    "attributed": not base["negative_control"],
                    "blocked_pre_effect": True,
                    "residue_detected": False,
                }
                self.evidence["attempts"].append(
                    {key: value for key, value in base.items() if key != "kind"}
                    | semantics
                    | {
                        "request_accepted_boottime_ns": start,
                        "decision_finalized_boottime_ns": end,
                    }
                )
            else:
                boundaries = {"TASK_ACCEPTED": start, "TASK_COMPLETED": end}
                observation = {"completed_pair": base["pair_id"], "mode": base["mode"]}
                semantics = {"completed": True}
                self.evidence[base["mode"] + "_samples"].append(
                    {
                        key: value
                        for key, value in base.items()
                        if key not in {"kind", "mode"}
                    }
                    | {
                        "status": "COMPLETED",
                        "timing_boundary": metrics.TASK_TIMING_BOUNDARY,
                        "started_boottime_ns": start,
                        "completed_boottime_ns": end,
                    }
                )
            receipt = {
                "schema": "aragorn/phase3-local-measurement-receipt/v1",
                "request_digest": canonical_digest(request),
                "deployment_digest": request["deployment_digest"],
                "boundaries": boundaries,
                "observation": observation,
            }
            receipt_pin = self.put(receipt)
            verified = {
                "receipt_digest": receipt_pin,
                "request_digest": canonical_digest(request),
                "deployment_digest": request["deployment_digest"],
                "semantics": semantics,
            }
            provenance.append(
                {
                    "request": request,
                    "receipt_digest": receipt_pin,
                    "verified_observation_digest": self.put(verified),
                }
            )
        self.collection = {
            "schema": "aragorn/phase3-measurement-collection/v1",
            "authority": "SYNTHETIC_UNIT_FIXTURE_NOT_RUNTIME_EVIDENCE",
            "commitment_digest": commitment_pin,
            "commitment_readback_boottime_ns": 2,
            "evidence_digest": self.put(self.evidence),
            "provenance": provenance,
            "metrics_qualification": {"decision": {"status": "UNTRUSTED_IGNORED"}},
            "limitations": [],
        }
        self.arguments = {
            "evidence_cas": self.cas,
            "expected_collection_digest": self.put(self.collection),
            "expected_commitment_digest": commitment_pin,
            "expected_deployment_digest": canonical_digest(self.deployment),
            "expected_measurement_schedule_digest": self.commitment["schedule_digest"],
            "expected_metrics_implementation_digest": self.commitment[
                "metrics_implementation_digest"
            ],
            "expected_collector_digest": self.commitment["collector_digest"],
            "expected_source_pins": self.source_pins,
            "verify": synthetic_receipt_verifier,
        }

    def put(self, value):
        raw = canonical_json(value)
        return self.cas.put(BytesIO(raw), max_bytes=len(raw))

    def replay(self, collection=None, **overrides):
        arguments = {**self.arguments, **overrides}
        if collection is not None:
            arguments["expected_collection_digest"] = self.put(collection)
        return subject.replay_phase3_measurement_collection(**arguments)

    def test_rebuilds_all_rows_read_only_without_execution_or_recorded_arithmetic(self):
        inventory = set(self.cas.root.rglob("*"))
        result = self.replay(evidence_cas=CAS(self.cas.root, read_only=True))
        self.assertEqual(len(_CALLS), 300)
        self.assertEqual(
            result["counts"],
            {"attempts": 100, "baseline_samples": 100, "instrumented_samples": 100},
        )
        self.assertEqual(
            result["bindings"]["evidence_digest"], self.collection["evidence_digest"]
        )
        self.assertEqual(
            result["decision"],
            {
                "status": "PASS",
                "phase3_exit_eligible": False,
                "quantitative_thresholds_qualified": False,
            },
        )
        self.assertEqual(inventory, set(self.cas.root.rglob("*")))
        self.assertNotIn("never_imported_adapter", sys.modules)

    def test_forged_retained_verdict_cannot_override_raw_receipt_semantics(self):
        collection = deepcopy(self.collection)
        entry = collection["provenance"][1]
        receipt = json.loads(self.cas.read(entry["receipt_digest"]))
        receipt["observation"]["decision"] = "ALLOW"
        entry["receipt_digest"] = self.put(receipt)
        recorded = json.loads(self.cas.read(entry["verified_observation_digest"]))
        recorded["receipt_digest"] = entry["receipt_digest"]
        entry["verified_observation_digest"] = self.put(recorded)
        collection["metrics_qualification"] = {"decision": {"status": "PASS"}}
        with self.assertRaisesRegex(
            subject.Phase3MeasurementReplayError, "semantic result differs"
        ):
            self.replay(collection)
        self.assertEqual(len(_CALLS), 2)

    def test_inventory_requests_replayed_receipts_and_raw_metrics_are_exact(self):
        cases = []
        for field, value in (
            ("collection_digest", "sha256:" + "0" * 64),
            ("family", "OTHER"),
            ("negative_control", 1),
        ):
            changed = deepcopy(self.collection)
            changed["provenance"][0]["request"][field] = value
            cases.append((field, changed))
        changed = deepcopy(self.collection)
        changed["provenance"][100]["request"]["input_digest"] = "sha256:" + "0" * 64
        cases.append(("task_input", changed))
        changed = deepcopy(self.collection)
        changed["provenance"].pop()
        cases.append(("missing_sample", changed))
        changed = deepcopy(self.collection)
        changed["provenance"][1]["receipt_digest"] = changed["provenance"][0][
            "receipt_digest"
        ]
        cases.append(("receipt_replay", changed))
        changed = deepcopy(self.collection)
        evidence = deepcopy(self.evidence)
        evidence["attempts"][1]["attributed"] = False
        changed["evidence_digest"] = self.put(evidence)
        cases.append(("raw_metrics", changed))
        for name, changed in cases:
            with (
                self.subTest(case=name),
                self.assertRaises(subject.Phase3MeasurementReplayError),
            ):
                self.replay(changed)

    def test_clock_boundaries_and_global_chronology_refuse_before_semantic_replay(self):
        for value in (1, True, 110, 111):
            changed = deepcopy(self.collection)
            entry = changed["provenance"][0]
            receipt = json.loads(self.cas.read(entry["receipt_digest"]))
            receipt["boundaries"]["REQUEST_ACCEPTED"] = value
            entry["receipt_digest"] = self.put(receipt)
            with (
                self.subTest(start=value),
                self.assertRaisesRegex(
                    subject.Phase3MeasurementReplayError, "boottime"
                ),
            ):
                self.replay(changed)
        changed = deepcopy(self.collection)
        entry = changed["provenance"][1]
        receipt = json.loads(self.cas.read(entry["receipt_digest"]))
        receipt["boundaries"]["REQUEST_ACCEPTED"] = 100
        entry["receipt_digest"] = self.put(receipt)
        with self.assertRaisesRegex(subject.Phase3MeasurementReplayError, "chronology"):
            self.replay(changed)

    def test_operator_pins_separate_source_and_custody_are_required(self):
        for key in (
            "expected_commitment_digest",
            "expected_deployment_digest",
            "expected_measurement_schedule_digest",
            "expected_metrics_implementation_digest",
            "expected_collector_digest",
        ):
            with self.subTest(pin=key), self.assertRaises((ValueError, CASError)):
                self.replay(**{key: "sha256:" + "0" * 64})
        with self.assertRaisesRegex(
            subject.Phase3MeasurementReplayError, "source differs"
        ):
            self.replay(
                expected_source_pins={
                    **self.source_pins,
                    "verify": "sha256:" + "0" * 64,
                }
            )
        commitment = deepcopy(self.commitment)
        commitment["sources"]["execute"] = deepcopy(commitment["sources"]["verify"])
        changed = deepcopy(self.collection)
        changed["commitment_digest"] = self.put(commitment)
        with self.assertRaisesRegex(subject.Phase3MeasurementReplayError, "separation"):
            self.replay(
                changed,
                expected_commitment_digest=changed["commitment_digest"],
                expected_source_pins={
                    **self.source_pins,
                    "execute": self.source_pins["verify"],
                },
            )
        digest = self.collection["provenance"][-1]["receipt_digest"]
        (self.cas.root / "blobs" / "sha256" / digest[7:9] / digest[9:]).unlink()
        with self.assertRaises(CASError):
            self.replay()


if __name__ == "__main__":
    unittest.main()
