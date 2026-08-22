from __future__ import annotations

import base64
import hashlib
import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import (
    admission_protected_final_combined_v2_fresh_session_reset as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-fresh-session-"
    "reset-route-coverage-v1-2026-08-22.json"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _store(raw: bytes) -> tuple[TemporaryDirectory[str], CAS]:
    temporary = TemporaryDirectory()
    store = CAS(temporary.name)
    store.put_expected(BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw))
    return temporary, store


def _outer_repin(changed: dict[str, object]) -> tuple[bytes, dict[str, object]]:
    canonical = subject.legacy.parent.oci_worker_protocol.canonical_json(changed)
    raw = canonical + b"\n"
    return raw, {
        **subject._EVIDENCE,
        "bytes": len(raw),
        "canonical_bytes": len(canonical),
        "canonical_digest": _digest(canonical),
        "digest": _digest(raw),
    }


def _repin(
    changed: dict[str, object],
) -> tuple[bytes, dict[str, object], dict[str, object]]:
    document = changed["route_observation"]["document"]
    nested = (
        json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2).encode()
        + b"\n"
    )
    nested_canonical = subject.legacy.parent.oci_worker_protocol.canonical_json(
        document
    )
    changed["route_observation"]["raw"] = {
        "base64": base64.b64encode(nested).decode(),
        "bytes": len(nested),
        "canonical_digest": _digest(nested_canonical),
        "digest": _digest(nested),
        "raw_is_canonical_json_lf": False,
    }
    outer_canonical = subject.legacy.parent.oci_worker_protocol.canonical_json(changed)
    changed_raw = outer_canonical + b"\n"
    return (
        changed_raw,
        {
            **subject._EVIDENCE,
            "bytes": len(changed_raw),
            "canonical_bytes": len(outer_canonical),
            "canonical_digest": _digest(outer_canonical),
            "digest": _digest(changed_raw),
        },
        {
            "bytes": len(nested),
            "canonical_digest": _digest(nested_canonical),
            "digest": _digest(nested),
        },
    )


class FinalCombinedV2FreshSessionResetTests(unittest.TestCase):
    def test_exact_one_route_pass_and_semantic_mutation_fails_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        temporary, store = _store(raw)
        self.addCleanup(temporary.cleanup)
        result = subject.verify_openclaw_final_combined_v2_fresh_session_reset(
            evidence_cas=store
        )
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})
        statuses = {
            route["id"]: route["status"] for route in result["profile"]["routes"]
        }
        self.assertEqual(statuses[subject._ROUTE], "PASS")
        self.assertEqual(list(statuses.values()).count("PASS"), 1)
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(json.loads(raw)["decision"]["route_pass_count"], 0)
        receipt_raw = _RECEIPT.read_bytes()
        self.assertEqual(
            receipt_raw,
            subject.legacy.parent.oci_worker_protocol.canonical_json(result) + b"\n",
        )
        self.assertEqual(json.loads(receipt_raw), result)

        nested_mutations = {
            "uncleared rotation": lambda changed: changed["route_observation"][
                "document"
            ]["actions"][0]["observations"]["session_after_rotation"][
                "entry"
            ].__setitem__("snapshot_present", True),
            "retained rotated digest": lambda changed: changed["route_observation"][
                "document"
            ]["actions"][0]["observations"]["session_after_rotation"][
                "file"
            ].__setitem__(
                "digest",
                changed["route_observation"]["document"]["actions"][0]["observations"][
                    "session_before_reset"
                ]["file"]["digest"],
            ),
        }
        for label, mutate in nested_mutations.items():
            with self.subTest(label=label):
                changed = deepcopy(json.loads(raw))
                mutate(changed)
                changed_raw, evidence_identity, route_identity = _repin(changed)
                changed_temporary, changed_store = _store(changed_raw)
                self.addCleanup(changed_temporary.cleanup)
                with (
                    patch.object(subject, "_EVIDENCE", evidence_identity),
                    patch.object(subject, "_ROUTE_RAW", route_identity),
                    patch.object(
                        subject,
                        "_verify_retained_evidence",
                        return_value=changed_raw,
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.verify_openclaw_final_combined_v2_fresh_session_reset(
                        evidence_cas=changed_store
                    )

        forged_profile = deepcopy(json.loads(raw))
        for side in ("before", "after"):
            forged_profile["composition"]["profile"][side]["document"]["runtime"][
                "commit"
            ] = "0" * 40
        forged_mount = deepcopy(json.loads(raw))
        forged_mount["composition"]["action"]["harness"]["document"][
            "openclaw_runtime_mount"
        ]["source"] = "forged-volume"
        outer_mutations = {
            "forged profile runtime": forged_profile,
            "forged runtime mount": forged_mount,
        }
        for label, changed in outer_mutations.items():
            with self.subTest(label=label):
                changed_raw, evidence_identity = _outer_repin(changed)
                changed_temporary, changed_store = _store(changed_raw)
                self.addCleanup(changed_temporary.cleanup)
                with (
                    patch.object(subject, "_EVIDENCE", evidence_identity),
                    patch.object(
                        subject,
                        "_verify_retained_evidence",
                        return_value=changed_raw,
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.verify_openclaw_final_combined_v2_fresh_session_reset(
                        evidence_cas=changed_store
                    )


if __name__ == "__main__":
    unittest.main()
