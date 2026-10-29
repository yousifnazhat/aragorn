from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import (
    admission_protected_final_combined_v2_catalog_fixed_fresh_session_reset as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-catalog-"
    "fixed-fresh-session-reset-route-coverage-v1-2026-08-22.json"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _store(raw: bytes) -> tuple[tempfile.TemporaryDirectory[str], CAS]:
    temporary = tempfile.TemporaryDirectory()
    store = CAS(temporary.name)
    store.put_expected(BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw))
    return temporary, store


def _sync_harness(changed: dict[str, object]) -> None:
    harness = changed["composition"]["action"]["harness"]
    raw = canonical_json(harness["document"])
    harness["digest"] = _digest(raw)
    harness["file"]["base64"] = base64.b64encode(raw).decode()
    harness["file"]["bytes"] = len(raw)
    harness["file"]["digest"] = _digest(raw)
    harness["file"]["stat"]["size"] = len(raw)


def _sync_config_contract(changed: dict[str, object]) -> dict[str, object]:
    source = changed["composition"]["action"]["artifacts"]["final_combined_v2"]
    config = source["config"]
    config_canonical = canonical_json(config["document"])
    config_raw = config_canonical + b"\n"
    config_identity = {
        "bytes": len(config_raw),
        "canonical_bytes": len(config_canonical),
        "canonical_digest": _digest(config_canonical),
        "digest": _digest(config_raw),
    }
    config["file"]["canonical_bytes"] = config_identity["canonical_bytes"]
    config["file"]["canonical_digest"] = config_identity["canonical_digest"]
    config["file"]["source"]["bytes"] = config_identity["bytes"]
    config["file"]["source"]["digest"] = config_identity["digest"]
    config["file"]["source"]["stat"]["size"] = config_identity["bytes"]
    changed["composition"]["action"]["inputs"]["gateway_config"] = deepcopy(
        config["document"]
    )

    runtime_lock = source["runtime_lock"]
    runtime_lock["document"]["deployment_bindings"]["configuration"] = {
        **config_identity,
        "deployment_materialization": "canonical_json(config)_without_trailing_lf",
        "path": (
            "benchmark/admission/openclaw-v2026.7.1/"
            "protected-final-combined-config-v2.json"
        ),
    }
    lock_canonical = canonical_json(runtime_lock["document"])
    lock_raw = lock_canonical + b"\n"
    lock_identity = {
        "bytes": len(lock_raw),
        "canonical_bytes": len(lock_canonical),
        "canonical_digest": _digest(lock_canonical),
        "digest": _digest(lock_raw),
    }
    runtime_lock["file"]["canonical_bytes"] = lock_identity["canonical_bytes"]
    runtime_lock["file"]["canonical_digest"] = lock_identity["canonical_digest"]
    runtime_lock["file"]["source"]["bytes"] = lock_identity["bytes"]
    runtime_lock["file"]["source"]["digest"] = lock_identity["digest"]
    runtime_lock["file"]["source"]["stat"]["size"] = lock_identity["bytes"]

    boundary = changed["route_observation"]["document"]["protected_boundary"]
    boundary["configuration"]["canonical_digest"] = config_identity["canonical_digest"]
    boundary["configuration"]["expected_canonical_digest"] = config_identity[
        "canonical_digest"
    ]
    boundary["configuration"]["file"]["digest"] = config_identity["canonical_digest"]
    boundary["configuration"]["file"]["size"] = config_identity["canonical_bytes"]
    return {
        **subject.contract._SOURCES,
        "configuration": config_identity,
        "runtime_lock": lock_identity,
    }


def _repin(
    changed: dict[str, object],
) -> tuple[bytes, dict[str, object], dict[str, object], dict[str, str]]:
    document = changed["route_observation"]["document"]
    nested = (
        json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2).encode()
        + b"\n"
    )
    nested_canonical = canonical_json(document)
    changed["route_observation"]["raw"] = {
        "base64": base64.b64encode(nested).decode(),
        "bytes": len(nested),
        "canonical_digest": _digest(nested_canonical),
        "digest": _digest(nested),
        "raw_is_canonical_json_lf": False,
    }
    _sync_harness(changed)
    observation = changed["route_observation"]
    composition = changed["composition"]
    harness = composition["action"]["harness"]["document"]
    digests = {
        "action": _digest(canonical_json(document["actions"][0])),
        "composition": _digest(canonical_json(composition)),
        "composition_action": _digest(canonical_json(composition["action"])),
        "execution": _digest(canonical_json(observation["execution"])),
        "gateway_binding": _digest(canonical_json(observation["gateway_pid_binding"])),
        "harness": _digest(canonical_json(harness)),
        "host_config": _digest(canonical_json(harness["host_config"])),
        "image_lineage": _digest(canonical_json(harness["image_lineage"])),
        "protected_boundary": _digest(canonical_json(document["protected_boundary"])),
        "source_artifacts": _digest(canonical_json(changed["source_artifacts"])),
        "stack": _digest(canonical_json(observation["stack_before"])),
    }
    outer_canonical = canonical_json(changed)
    raw = outer_canonical + b"\n"
    evidence_identity = {
        **subject._EVIDENCE,
        "bytes": len(raw),
        "canonical_bytes": len(outer_canonical),
        "canonical_digest": _digest(outer_canonical),
        "digest": _digest(raw),
    }
    route_identity = {
        "bytes": len(nested),
        "canonical_digest": _digest(nested_canonical),
        "digest": _digest(nested),
    }
    return raw, evidence_identity, route_identity, digests


class CatalogFixedFreshSessionResetTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return (
            subject.verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset(
                evidence_cas=store
            )
        )

    def test_exact_one_route_pass_with_all_broad_eligibility_false(self) -> None:
        raw = _EVIDENCE.read_bytes()
        result = self.verify(raw)
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})
        statuses = {
            route["id"]: route["status"] for route in result["profile"]["routes"]
        }
        self.assertEqual(statuses[subject._ROUTE], "PASS")
        self.assertEqual(list(statuses.values()).count("PASS"), 1)
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.old.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(json.loads(raw)["decision"]["route_pass_count"], 0)
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_hostile_coordinated_repins_fail_closed(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects(
            changed: dict[str, object],
            *,
            sources: dict[str, object] | None = None,
        ) -> None:
            raw, evidence, route_raw, digests = _repin(changed)
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", evidence),
                patch.object(subject, "_ROUTE_RAW", route_raw),
                patch.object(subject, "_DIGESTS", digests),
                patch.object(
                    subject.contract,
                    "_SOURCES",
                    subject.contract._SOURCES if sources is None else sources,
                ),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset(
                    evidence_cas=store
                )

        changed = deepcopy(original)
        config = changed["composition"]["action"]["artifacts"]["final_combined_v2"][
            "config"
        ]["document"]
        config["skills"]["activation"]["authority"] = "workspace"
        sources = _sync_config_contract(changed)
        rejects(changed, sources=sources)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["actions"][0]["observations"][
            "reset_snapshot_cleared"
        ] = False
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["actions"][0]["observations"][
            "session_after_reset_check"
        ]["catalog_exact"] = 1
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["actions"][0]["observations"][
            "reset_turn"
        ]["params"]["message"] = "/reset"
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["harness"]["document"][
            "openclaw_runtime_mount"
        ]["rw"] = True
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["decision"]["edr_eligible"] = True
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["execution"]["exit_code"] = False
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["recorded_at"] = (
            "2026-08-22T09:55:11.500Z"
        )
        rejects(changed)


if __name__ == "__main__":
    unittest.main()
