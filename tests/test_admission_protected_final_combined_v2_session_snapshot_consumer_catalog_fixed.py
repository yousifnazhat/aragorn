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
    admission_protected_final_combined_v2_session_snapshot_consumer_catalog_fixed as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-session-"
    "snapshot-consumer-catalog-fixed-route-coverage-v1-2026-08-22.json"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _store(raw: bytes) -> tuple[tempfile.TemporaryDirectory[str], CAS]:
    temporary = tempfile.TemporaryDirectory()
    store = CAS(temporary.name)
    store.put_expected(BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw))
    return temporary, store


def _sync_nested(changed: dict[str, object]) -> None:
    observation = changed["route_observation"]
    document = observation["document"]
    canonical = canonical_json(document)
    raw = (
        json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2).encode()
        + b"\n"
    )
    observation["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": _digest(canonical),
        "digest": _digest(raw),
        "raw_is_canonical_json_lf": False,
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
) -> tuple[bytes, dict[str, object], dict[str, object], dict[str, str]]:
    _sync_nested(changed)
    observation = changed["route_observation"]
    nested_raw = base64.b64decode(observation["raw"]["base64"], validate=True)
    route_identity = {
        "bytes": len(nested_raw),
        "canonical_digest": _digest(canonical_json(observation["document"])),
        "digest": _digest(nested_raw),
    }
    composition = changed["composition"]
    action = observation["document"]["action"]
    replay = action["observations"]["compiled_route_replay"]
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
        "replay": _digest(canonical_json(replay)),
        "module_files": _digest(canonical_json(replay["module_files"])),
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
    return raw, evidence_identity, route_identity, digests


class FinalCombinedV2SessionSnapshotConsumerCatalogFixedTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v2_session_snapshot_consumer_catalog_fixed(
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
        self.assertIn(
            "PRE_ROUTE_READ_ONLY_CLOSURE_ACQUISITION_BOUND_BY_RUNTIME_TREE",
            result["limitations"],
        )
        self.assertIn(
            "NO_POST_ROUTE_CLOSURE_PROVENANCE_OR_CONTINUOUS_IMMUTABILITY_CLAIM",
            result["limitations"],
        )
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_coordinated_repins_and_hostile_json_fail_closed(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects(changed: dict[str, object], *, sync_harness: bool = False) -> None:
            if sync_harness:
                _sync_harness(changed)
            raw, evidence, route_raw, digests = _repin(changed)
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", evidence),
                patch.object(subject, "_ROUTE_RAW", route_raw),
                patch.object(subject, "_DIGESTS", digests),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v2_session_snapshot_consumer_catalog_fixed(
                    evidence_cas=store
                )

        changed = deepcopy(original)
        changed["composition"]["action"]["artifacts"]["final_combined_v2"]["config"][
            "document"
        ]["skills"]["allowBundled"] = []
        rejects(changed)

        changed = deepcopy(original)
        replay = changed["route_observation"]["document"]["action"]["observations"][
            "compiled_route_replay"
        ]
        replay["native_agent_execution"] = True
        rejects(changed)

        changed = deepcopy(original)
        replay = changed["route_observation"]["document"]["action"]["observations"][
            "compiled_route_replay"
        ]
        replay["resolver"]["injected_should_refresh"] = False
        rejects(changed)

        changed = deepcopy(original)
        replay = changed["route_observation"]["document"]["action"]["observations"][
            "compiled_route_replay"
        ]
        next(iter(replay["module_files"].values()))["digest"] = "sha256:" + "0" * 64
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["harness"]["document"][
            "openclaw_runtime_mount"
        ]["rw"] = True
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        changed["decision"]["edr_eligible"] = True
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["execution"]["exit_code"] = False
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["action"]["observations"]["mutation"][
            "completed_at"
        ] = "2026-08-22T09:58:07.000Z"
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        observations = action["observations"]
        observations["mutation"]["store_before"]["digest"] = "sha256:" + "1" * 64
        observations["mutation"]["store_after_rewrite"]["digest"] = "sha256:" + "2" * 64
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        timing = action["observations"]["native_recovery_timing"]
        timing["injected_send_started_at"] -= 1
        timing["injected_wait_ended_at"] += 1
        timing["injected_wait_completed_at"] = 9_999_999_999_999
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["commands"][0]["pid"] = 0
        action["prerequisites"]["version"]["pid"] = 0
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["mutation"]["preserved_entry_without_prompt_ref"][
            "after_digest"
        ] = "sha256:" + "0" * 64
        observations["mutation"]["injected_marker"] = "FORGED"
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["mutated_snapshot"]["entry"]["runtime_ms"] += 1
        observations["attacker_blob_after"]["mode"] = "644"
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        for snapshot_name in ("baseline_snapshot", "injected_snapshot"):
            observations["compiled_route_replay"]["resolver"][snapshot_name][
                "prompt"
            ] = observations["mutated_snapshot"]["prompt"]["exact_text"]
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        for snapshot_name in ("mutated_snapshot", "pre_injected_snapshot"):
            observations[snapshot_name]["store"]["mtime_ns"] = "1"
            observations[snapshot_name]["blob"]["mtime_ns"] = "1"
        observations["mutation"]["store_after_rewrite"]["mtime_ns"] = "1"
        observations["mutation"]["blob"]["mtime_ns"] = "1"
        observations["attacker_blob_after"]["mtime_ns"] = "not-a-number"
        rejects(changed)

        changed = deepcopy(original)
        replay = changed["route_observation"]["document"]["action"]["observations"][
            "compiled_route_replay"
        ]
        for report_name in ("baseline_report", "injected_report"):
            report = replay[report_name]
            report["sessionId"] = "FORGED-SESSION"
            report["sandbox"]["sandboxed"] = True
            report["model"] = "forged-model"
            report["systemPrompt"]["chars"] = 0
            report["systemPrompt"]["nonProjectContextChars"] = 0
        rejects(changed)

        changed = deepcopy(original)
        baseline_copy = changed["route_observation"]["document"]["action"][
            "observations"
        ]["compiled_route_replay"]["baseline_store_copy"]
        baseline_copy.update(
            {
                "absent_after_replay": False,
                "digest": "sha256:" + "0" * 64,
                "gid": 0,
                "mode": "644",
                "path": "/tmp/forged-baseline.json",
                "uid": 0,
            }
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["harness"]["document"][
            "source_commit_verification"
        ]["stderr"]["extra"] = ""
        rejects(changed)

        for dependency, replacement in (
            ("parent", subject.current),
            ("session_v1", subject.current),
        ):
            with (
                patch.object(subject.semantic, dependency, replacement),
                self.assertRaises(AdmissionEvidenceError),
            ):
                self.verify()

        for raw in (
            _EVIDENCE.read_bytes().replace(
                b'{"authority":', b'{"authority":"forged","authority":', 1
            ),
            _EVIDENCE.read_bytes().replace(
                b'"route_pass_count":0', b'"route_pass_count":NaN', 1
            ),
        ):
            evidence = {
                **subject._EVIDENCE,
                "bytes": len(raw),
                "digest": _digest(raw),
            }
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", evidence),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v2_session_snapshot_consumer_catalog_fixed(
                    evidence_cas=store
                )


if __name__ == "__main__":
    unittest.main()
