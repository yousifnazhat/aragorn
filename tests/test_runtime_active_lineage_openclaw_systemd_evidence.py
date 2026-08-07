from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn import runtime_active_lineage_openclaw_systemd_evidence as verifier
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT / "benchmark/evidence/"
    "runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json"
)
_RAW_DIGEST = "b70ca54d1efdb4b9e93ed2d3895819a2f248c132cf29d811b24635fe79517362"
_CANONICAL_DIGEST = (
    "sha256:5c48201f3273dc4597e0e387f2873d6cf93940a645d6a528344c4aa9e2f7e1bd"
)
_ZERO_DIGEST = "sha256:" + "0" * 64


def _set(*path: str, value: object):
    def mutate(document: dict) -> None:
        current = document
        for name in path[:-1]:
            current = current[name]
        current[path[-1]] = value

    return mutate


def _forge_stale_state(document: dict) -> None:
    document["cases"]["stale_active_record"]["grant_state_after"] = deepcopy(
        document["grant"]["final_state"]
    )


def _forge_source_install(document: dict) -> None:
    document["artifacts"]["installed"][0]["installed"]["digest"] = _ZERO_DIGEST


def _forge_parent_image(document: dict) -> None:
    harness = document["harness"]
    harness["document"]["parent_image_id"] = _ZERO_DIGEST
    harness["digest"] = canonical_digest(harness["document"])


class RuntimeActiveLineageOpenClawSystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = _EVIDENCE.read_bytes()
        cls.document = json.loads(cls.raw)

    def test_retained_artifact_is_pinned_canonical_and_verifies(self) -> None:
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), _RAW_DIGEST)
        self.assertEqual(self.raw, canonical_json(self.document) + b"\n")
        self.assertEqual(canonical_digest(self.document), _CANONICAL_DIGEST)
        self.assertEqual(verifier._RAW_DIGEST, _RAW_DIGEST)
        self.assertEqual(verifier._EVIDENCE_DIGEST, _CANONICAL_DIGEST)
        verifier.verify_runtime_active_lineage_openclaw_systemd_evidence(
            self.document,
            expected_digest=_CANONICAL_DIGEST,
        )

    def test_expected_digest_is_explicit_and_exact(self) -> None:
        with self.assertRaises(AdmissionEvidenceError):
            verifier.verify_runtime_active_lineage_openclaw_systemd_evidence(
                self.document
            )
        with self.assertRaises(AdmissionEvidenceError):
            verifier.verify_runtime_active_lineage_openclaw_systemd_evidence(
                self.document,
                expected_digest="sha256:" + "f" * 64,
            )

    def test_repinned_security_boundary_mutations_are_rejected(self) -> None:
        mutations = {
            "claim promotion": _set("decision", "run_02_eligible", value=True),
            "limitation removal": lambda document: document["limitations"].pop(),
            "parent evidence": _set(
                "parent_evidence", "file_digest", value=_ZERO_DIGEST
            ),
            "parent image": _forge_parent_image,
            "source install": _forge_source_install,
            "transaction tree": _set(
                "active_install", "transaction", "tree_digest", value=_ZERO_DIGEST
            ),
            "record mode": _set(
                "active_install", "record", "file", "stat", "mode", value="0644"
            ),
            "skill inode": _set(
                "active_install",
                "coherent_snapshot",
                "after",
                "skill",
                "inode",
                value=1,
            ),
            "verified lineage": _set(
                "active_install",
                "verified_lineage",
                "context_digest",
                value=_ZERO_DIGEST,
            ),
            "grant binding": _set(
                "grant", "bindings", "tree_digest", "matches", value=False
            ),
            "stale broker submission": _set(
                "cases",
                "stale_active_record",
                "checks",
                "broker_not_submitted",
                value=False,
            ),
            "stale peer": _set(
                "cases",
                "stale_active_record",
                "effects",
                "peer_trace",
                "broker",
                "peer_credentials",
                value=[{"pid": 1, "uid": 0, "gid": 0}],
            ),
            "stale grant consumption": _forge_stale_state,
            "stale target": _set(
                "cases",
                "stale_active_record",
                "effects",
                "after",
                "target_lexists",
                value=True,
            ),
            "coherent verdict": _set(
                "cases", "coherent_active_record", "result", "verdict", value="BLOCK"
            ),
            "receipt digest": _set(
                "cases",
                "coherent_active_record",
                "receipt",
                "digest",
                value=_ZERO_DIGEST,
            ),
            "target digest": _set(
                "cases",
                "coherent_active_record",
                "target",
                "digest",
                value=_ZERO_DIGEST,
            ),
            "timing": _set("timing", "sensor_deadline_ms", value=501),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = deepcopy(self.document)
                mutate(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    verifier.verify_runtime_active_lineage_openclaw_systemd_evidence(
                        changed,
                        expected_digest=canonical_digest(changed),
                    )


if __name__ == "__main__":
    unittest.main()
