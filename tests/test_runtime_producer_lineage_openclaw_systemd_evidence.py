from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn import runtime_producer_lineage_openclaw_systemd_evidence as verifier
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark/evidence/"
    "runtime-producer-lineage-openclaw-systemd-composition-p3-6b-2026-08-07.json"
)
_RAW_DIGEST = "53db78bb37550b4dde63bbc14b926a961c7d09af92f11bba74868fa917fd9589"
_CANONICAL_DIGEST = (
    "sha256:485232aa3565f056fff3a2f1e1b14e81e6dfadc175099e315eef8e9f5cabca20"
)
_ZERO_DIGEST = "sha256:" + "0" * 64


def _set(*path: str, value: object):
    def mutate(document: dict) -> None:
        current = document
        for name in path[:-1]:
            current = current[name]
        current[path[-1]] = value

    return mutate


def _forge_parent_image(document: dict) -> None:
    harness = document["harness"]
    harness["document"]["image_lineage"]["parent"]["id"] = _ZERO_DIGEST
    harness["document"]["parent_image_id"] = _ZERO_DIGEST
    harness["digest"] = canonical_digest(harness["document"])


def _forge_live_custody(document: dict) -> None:
    producer = document["producer"]
    request = producer["request"]
    live = request["quarantine_receipt"]["live"]
    live["document"]["protected_cas"]["root_inode"] = 1
    live["digest"] = canonical_digest(live["document"])
    request["document"]["quarantine_receipt_digest"] = live["digest"]
    request["digest"] = canonical_digest(request["document"])
    receipt = producer["receipt"]
    receipt["request_authority"]["request_digest"] = request["digest"]
    receipt["source"]["quarantine_receipt_digest"] = live["digest"]
    receipt["source"]["quarantine_protected_cas"] = deepcopy(
        live["document"]["protected_cas"]
    )
    producer["journal"]["message_digest"] = canonical_digest(receipt)
    producer["journal"]["message_bytes"] = len(canonical_json(receipt))


def _forge_receipt_transaction(document: dict) -> None:
    producer = document["producer"]
    producer["receipt"]["transaction"]["tree_digest"] = _ZERO_DIGEST
    producer["journal"]["message_digest"] = canonical_digest(producer["receipt"])
    producer["journal"]["message_bytes"] = len(canonical_json(producer["receipt"]))


def _forge_claim(document: dict) -> None:
    claim = document["producer"]["claim"]
    claim["document"]["tree_digest"] = _ZERO_DIGEST
    claim["digest"] = claim["raw_digest"] = canonical_digest(claim["document"])
    claim["file"]["digest"] = claim["digest"]


def _forge_producer_artifact(document: dict) -> None:
    item = document["artifacts"]["producer_installed"][0]
    item["source"]["digest"] = item["installed"]["digest"] = _ZERO_DIGEST


class RuntimeProducerLineageOpenClawSystemdEvidenceTests(unittest.TestCase):
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
        verifier.verify_runtime_producer_lineage_openclaw_systemd_evidence(
            self.document,
            expected_digest=_CANONICAL_DIGEST,
        )

    def test_expected_digest_is_explicit_and_exact(self) -> None:
        with self.assertRaises(AdmissionEvidenceError):
            verifier.verify_runtime_producer_lineage_openclaw_systemd_evidence(
                self.document
            )
        with self.assertRaises(AdmissionEvidenceError):
            verifier.verify_runtime_producer_lineage_openclaw_systemd_evidence(
                self.document,
                expected_digest="sha256:" + "f" * 64,
            )

    def test_hostile_repins_are_rejected(self) -> None:
        mutations = {
            "claim promotion": _set("decision", "run_02_eligible", value=True),
            "limitation removal": lambda document: document["limitations"].pop(),
            "parent evidence": _set(
                "parent_evidence", "canonical_digest", value=_ZERO_DIGEST
            ),
            "parent image": _forge_parent_image,
            "producer artifact": _forge_producer_artifact,
            "request release pin": _set(
                "producer", "request", "pins", "producer", value=_ZERO_DIGEST
            ),
            "live custody receipt": _forge_live_custody,
            "journal service": _set(
                "producer", "journal", "systemd_unit", value="forged.service"
            ),
            "journal executable": _set(
                "producer", "journal", "executable", value="/tmp/python"
            ),
            "service transaction": _forge_receipt_transaction,
            "protected claim": _forge_claim,
            "record restoration": _set(
                "producer", "original_record", "inode", value=1
            ),
            "runtime skill path": _set(
                "profile", "document", "skill_path", value="/tmp/SKILL.md"
            ),
            "grant tree binding": _set(
                "grant", "bindings", "tree_digest", "matches", value=False
            ),
            "stale broker submission": _set(
                "cases",
                "stale_active_record",
                "checks",
                "broker_not_submitted",
                value=False,
            ),
            "coherent receipt": _set(
                "cases", "coherent_active_record", "receipt", "digest", value=_ZERO_DIGEST
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = deepcopy(self.document)
                mutate(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    verifier.verify_runtime_producer_lineage_openclaw_systemd_evidence(
                        changed,
                        expected_digest=canonical_digest(changed),
                    )


if __name__ == "__main__":
    unittest.main()
