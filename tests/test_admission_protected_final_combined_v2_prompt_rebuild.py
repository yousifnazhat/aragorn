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

from aragorn import admission_protected_final_combined_v2_prompt_rebuild as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-prompt-"
    "rebuild-route-coverage-v1-2026-08-22.json"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _store(*raw_values: bytes) -> tuple[TemporaryDirectory[str], CAS]:
    temporary = TemporaryDirectory()
    store = CAS(temporary.name)
    for raw in raw_values:
        store.put_expected(
            BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw)
        )
    return temporary, store


def _outer_repin(changed: dict[str, object]) -> tuple[bytes, dict[str, object]]:
    canonical = subject.parent.legacy.parent.oci_worker_protocol.canonical_json(changed)
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
    nested_canonical = subject.parent.legacy.parent.oci_worker_protocol.canonical_json(
        document
    )
    changed["route_observation"]["raw"] = {
        "base64": base64.b64encode(nested).decode(),
        "bytes": len(nested),
        "canonical_digest": _digest(nested_canonical),
        "digest": _digest(nested),
        "raw_is_canonical_json_lf": False,
    }
    outer_canonical = subject.parent.legacy.parent.oci_worker_protocol.canonical_json(
        changed
    )
    raw = outer_canonical + b"\n"
    return (
        raw,
        {
            **subject._EVIDENCE,
            "bytes": len(raw),
            "canonical_bytes": len(outer_canonical),
            "canonical_digest": _digest(outer_canonical),
            "digest": _digest(raw),
        },
        {
            "bytes": len(nested),
            "canonical_digest": _digest(nested_canonical),
            "digest": _digest(nested),
        },
    )


class FinalCombinedV2PromptRebuildTests(unittest.TestCase):
    def test_exact_two_route_passes_and_rebuild_mutation_fails_closed(self) -> None:
        fresh_raw = (_ROOT / subject.parent._EVIDENCE["path"]).read_bytes()
        prompt_raw = (_ROOT / subject._EVIDENCE["path"]).read_bytes()
        temporary, store = _store(fresh_raw, prompt_raw)
        self.addCleanup(temporary.cleanup)
        result = subject.verify_openclaw_final_combined_v2_prompt_rebuild(
            evidence_cas=store
        )
        statuses = {
            route["id"]: route["status"] for route in result["profile"]["routes"]
        }
        self.assertEqual(result["profile"]["counts"], {"PASS": 2, "NOT_TESTED": 19})
        self.assertEqual(statuses[subject._PARENT_ROUTE], "PASS")
        self.assertEqual(statuses[subject._ROUTE], "PASS")
        self.assertEqual(list(statuses.values()).count("PASS"), 2)
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.parent.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        receipt_raw = _RECEIPT.read_bytes()
        self.assertEqual(
            receipt_raw,
            subject.parent.legacy.parent.oci_worker_protocol.canonical_json(result)
            + b"\n",
        )

        invalidation = deepcopy(json.loads(prompt_raw))
        invalidation["route_observation"]["document"]["action"]["observations"][
            "invalidation"
        ]["blob_exists_after_unlink"] = True
        early_snapshot = deepcopy(json.loads(prompt_raw))
        observations = early_snapshot["route_observation"]["document"]["action"][
            "observations"
        ]
        entry = observations["initial_snapshot"]["entry"]
        entry["started_at"] = (
            subject.parent.legacy._epoch_ms(
                observations["initial_turn"]["send"]["command"]["completed_at"]
            )
            - 1
        )
        entry["runtime_ms"] = entry["ended_at"] - entry["started_at"]
        writable_root = deepcopy(json.loads(prompt_raw))
        writable_document = writable_root["route_observation"]["document"]["action"]
        for boundary in (
            writable_document["prerequisites"]["boundary_before"],
            writable_document["observations"]["boundary_after"],
        ):
            boundary["roots"]["workspace_skills"]["observation"]["mode"] = "777"
        restarted_gateway = deepcopy(json.loads(prompt_raw))
        restarted_action = restarted_gateway["route_observation"]["document"]["action"]
        restarted_action["prerequisites"]["gateway_process_before"][
            "start_time_ticks"
        ] = "1"
        restarted_action["observations"]["gateway_process_after"][
            "start_time_ticks"
        ] = "1"
        for label, changed in {
            "missing unlink": invalidation,
            "snapshot before send": early_snapshot,
            "writable protected root": writable_root,
            "unjoined gateway restart": restarted_gateway,
        }.items():
            with self.subTest(label=label):
                changed_raw, evidence_identity, route_identity = _repin(changed)
                changed_temporary, changed_store = _store(fresh_raw, changed_raw)
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
                    subject.verify_openclaw_final_combined_v2_prompt_rebuild(
                        evidence_cas=changed_store
                    )

        runtime_mount = deepcopy(json.loads(prompt_raw))
        runtime_mount["composition"]["action"]["harness"]["document"][
            "openclaw_runtime_mount"
        ]["rw"] = True
        bind_override = deepcopy(json.loads(prompt_raw))
        bind_override["composition"]["action"]["harness"]["document"]["host_config"][
            "binds"
        ].append("/tmp:/runtime:rw")
        image_lineage = deepcopy(json.loads(prompt_raw))
        image_lineage["composition"]["action"]["harness"]["document"]["image_lineage"][
            "child"
        ]["id"] = "sha256:" + "0" * 64
        substituted_layer = deepcopy(json.loads(prompt_raw))
        lineage = substituted_layer["composition"]["action"]["harness"]["document"][
            "image_lineage"
        ]
        replacement_layer = "sha256:" + "0" * 64
        lineage["added_layers"][0] = replacement_layer
        lineage["child"]["layers"][len(lineage["parent"]["layers"])] = replacement_layer
        profile_runtime = deepcopy(json.loads(prompt_raw))
        for side in ("before", "after"):
            profile_runtime["composition"]["profile"][side]["document"]["runtime"][
                "commit"
            ] = "0" * 40
        profile_runtime["composition"]["action"]["artifacts"]["final_combined_v2"][
            "profile"
        ]["document"]["runtime"]["commit"] = "0" * 40
        runtime_digest = deepcopy(json.loads(prompt_raw))
        runtime_digest["composition"]["bindings"]["runtime_digest"] = (
            "sha256:" + "0" * 64
        )
        embedded_config = deepcopy(json.loads(prompt_raw))
        for config in (
            embedded_config["composition"]["action"]["inputs"]["gateway_config"],
            embedded_config["composition"]["action"]["artifacts"]["final_combined_v2"][
                "config"
            ]["document"],
        ):
            config["tools"]["profile"] = "full"
        execution_environment = deepcopy(json.loads(prompt_raw))
        execution_environment["route_observation"]["execution"][
            "environment_names"
        ].append("OPENCLAW_TEST_FAST")
        execution_timing = deepcopy(json.loads(prompt_raw))
        execution_timing["route_observation"]["execution"]["started_at"] = (
            "2099-01-01T00:00:00Z"
        )
        forged_cgroup = deepcopy(json.loads(prompt_raw))
        forged_cgroup["route_observation"]["stack_before"]["units"][
            "aragorn-agent-gateway.service"
        ]["ControlGroup"] = "/forged"
        promoted_composition = deepcopy(json.loads(prompt_raw))
        promoted_composition["composition"]["decision"]["edr_eligible"] = True
        for label, outer_changed in {
            "writable runtime mount": runtime_mount,
            "runtime bind override": bind_override,
            "forged image lineage": image_lineage,
            "substituted image layer": substituted_layer,
            "forged embedded profile runtime": profile_runtime,
            "forged runtime digest": runtime_digest,
            "forged embedded configuration": embedded_config,
            "unexpected execution environment": execution_environment,
            "impossible execution timeline": execution_timing,
            "forged systemd cgroup": forged_cgroup,
            "promoted composition authority": promoted_composition,
        }.items():
            with self.subTest(label=label):
                outer_raw, outer_identity = _outer_repin(outer_changed)
                outer_temporary, outer_store = _store(fresh_raw, outer_raw)
                self.addCleanup(outer_temporary.cleanup)
                with (
                    patch.object(subject, "_EVIDENCE", outer_identity),
                    patch.object(
                        subject, "_verify_retained_evidence", return_value=outer_raw
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.verify_openclaw_final_combined_v2_prompt_rebuild(
                        evidence_cas=outer_store
                    )


if __name__ == "__main__":
    unittest.main()
