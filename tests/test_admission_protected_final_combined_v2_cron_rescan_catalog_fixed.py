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
    admission_protected_final_combined_v2_cron_rescan_catalog_fixed as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-cron-"
    "rescan-catalog-fixed-route-coverage-v1-2026-08-22.json"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _store(raw: bytes) -> tuple[tempfile.TemporaryDirectory[str], CAS]:
    temporary = tempfile.TemporaryDirectory()
    store = CAS(temporary.name)
    store.put_expected(
        BytesIO(raw),
        expected_digest=_digest(raw),
        max_bytes=len(raw),
    )
    return temporary, store


def _sync_nested(changed: dict[str, object]) -> None:
    observation = changed["route_observation"]
    canonical = canonical_json(observation["document"])
    raw = canonical + b"\n"
    observation["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": _digest(canonical),
        "digest": _digest(raw),
        "raw_is_canonical_json_lf": True,
    }


def _sync_harness(changed: dict[str, object]) -> None:
    envelope = changed["composition"]["action"]["harness"]
    raw = canonical_json(envelope["document"])
    envelope["digest"] = _digest(raw)
    envelope["file"]["base64"] = base64.b64encode(raw).decode()
    envelope["file"]["bytes"] = len(raw)
    envelope["file"]["digest"] = _digest(raw)
    envelope["file"]["stat"]["size"] = len(raw)


def _repin(
    changed: dict[str, object],
) -> tuple[
    bytes,
    dict[str, object],
    dict[str, object],
    dict[str, str],
    dict[str, str],
]:
    _sync_nested(changed)
    observation = changed["route_observation"]
    document = observation["document"]
    action = document["action"]
    before = action["prerequisites"]
    nested_raw = base64.b64decode(observation["raw"]["base64"], validate=True)
    route_identity = {
        "bytes": len(nested_raw),
        "canonical_digest": _digest(canonical_json(document)),
        "digest": _digest(nested_raw),
    }
    composition = changed["composition"]
    harness = composition["action"]["harness"]["document"]
    digests = {
        "action": _digest(canonical_json(action)),
        "composition": _digest(canonical_json(composition)),
        "composition_action": _digest(canonical_json(composition["action"])),
        "execution": _digest(canonical_json(observation["execution"])),
        "gateway_binding": _digest(canonical_json(observation["gateway_pid_binding"])),
        "harness": _digest(canonical_json(harness)),
        "host_config": _digest(canonical_json(harness["host_config"])),
        "image_lineage": _digest(canonical_json(harness["image_lineage"])),
        "source_artifacts": _digest(canonical_json(changed["source_artifacts"])),
        "stack": _digest(canonical_json(observation["stack_before"])),
    }
    static = {
        "boundary": _digest(canonical_json(before["boundary_before"])),
        "config": _digest(canonical_json(before["config_before"])),
        "config_lock": _digest(canonical_json(before["config_lock_before"])),
        "config_tree": _digest(canonical_json(before["config_tree_before"])),
        "gateway": _digest(canonical_json(before["gateway_process_before"])),
        "modules": _digest(canonical_json(before["module_files_before"])),
        "openclaw": _digest(canonical_json(before["openclaw_before"])),
        "protected_roots": _digest(
            canonical_json(before["protected_root_trees_before"])
        ),
        "runtime_tree": _digest(canonical_json(before["runtime_tree_before"])),
        "session_store": _digest(canonical_json(before["session_store_before"])),
        "target": _digest(canonical_json(before["target_before"])),
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
    return raw, evidence_identity, route_identity, digests, static


class FinalCombinedV2CronRescanCatalogFixedTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v2_cron_rescan_catalog_fixed(
            evidence_cas=store
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
                for key in subject.current.base.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(json.loads(raw)["decision"]["route_pass_count"], 0)
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_coordinated_repin_hostile_semantics_fail_closed(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects(changed: dict[str, object], *, sync_harness: bool = False) -> None:
            if sync_harness:
                _sync_harness(changed)
            raw, evidence, route_raw, digests, static = _repin(changed)
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", evidence),
                patch.object(subject, "_ROUTE_RAW", route_raw),
                patch.object(subject, "_DIGESTS", digests),
                patch.object(subject, "_STATIC_DIGESTS", static),
                patch.object(subject, "_verify_dependencies", return_value=None),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v2_cron_rescan_catalog_fixed(
                    evidence_cas=store
                )

        changed = deepcopy(original)
        changed["route_observation"]["execution"]["started_at"] = (
            "2026-08-22T09:57:11.900Z"
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["execution"]["environment_names"].append(
            "NODE_OPTIONS"
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["execution"]["environment_names"].remove(
            "OPENCLAW_CONFIG_PATH"
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["harness"]["document"]["route_input_mount"][
            "destination"
        ] = "/not-route-input"
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        source = changed["composition"]["action"]["artifacts"]["final_combined_v2"]
        source["config"]["document"]["skills"]["allowBundled"] = []
        changed["composition"]["action"]["inputs"]["gateway_config"] = deepcopy(
            source["config"]["document"]
        )
        rejects(changed)

        changed = deepcopy(original)
        request = changed["route_observation"]["document"]["action"]["observations"][
            "run"
        ]["request"]
        request["params"]["mode"] = "due"
        rejects(changed)

        changed = deepcopy(original)
        snapshot = changed["route_observation"]["document"]["action"]["observations"][
            "snapshot"
        ]
        snapshot["prompt"]["storage"] = "inline"
        rejects(changed)

        changed = deepcopy(original)
        terminal = changed["route_observation"]["document"]["action"]["observations"][
            "terminal_result"
        ]
        terminal["errorReason"] = "success"
        rejects(changed)

        changed = deepcopy(original)
        cleanup = changed["route_observation"]["document"]["action"]["observations"][
            "cleanup"
        ]
        cleanup["response"]["value"]["removed"] = False
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        for target in (
            action["prerequisites"]["target_before"],
            action["observations"]["target_after"],
        ):
            target["entries"][0]["digest"] = "sha256:" + "0" * 64
        rejects(changed)

        changed = deepcopy(original)
        changed["decision"]["route_pass_count"] = 1
        rejects(changed)

        changed = deepcopy(original)
        forged = "sha256:" + "1" * 64
        changed["source_artifacts"]["probe_bundle"][1]["digest"] = forged
        changed["route_observation"]["bundle"][1]["digest"] = forged
        changed["route_observation"]["document"]["implementation_digests"]["helper"] = (
            forged
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["prerequisites"]["gateway_process_before"]["pid"] = float(
            action["prerequisites"]["gateway_process_before"]["pid"]
        )
        action["observations"]["gateway_process_after"]["pid"] = action[
            "prerequisites"
        ]["gateway_process_before"]["pid"]
        rejects(changed)

    def test_duplicate_and_nonfinite_json_fail_closed(self) -> None:
        original = _EVIDENCE.read_bytes()
        hostile = (
            original.replace(
                b'{"authority":', b'{"authority":"forged","authority":', 1
            ),
            original.replace(b'"route_pass_count":0', b'"route_pass_count":NaN', 1),
        )
        for raw in hostile:
            with self.subTest(digest=_digest(raw)):
                evidence = {
                    **subject._EVIDENCE,
                    "bytes": len(raw),
                    "digest": _digest(raw),
                }
                temporary, store = _store(raw)
                self.addCleanup(temporary.cleanup)
                with (
                    patch.object(subject, "_EVIDENCE", evidence),
                    patch.object(subject, "_verify_dependencies", return_value=None),
                    patch.object(
                        subject, "_verify_retained_evidence", return_value=raw
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.verify_openclaw_final_combined_v2_cron_rescan_catalog_fixed(
                        evidence_cas=store
                    )


if __name__ == "__main__":
    unittest.main()
