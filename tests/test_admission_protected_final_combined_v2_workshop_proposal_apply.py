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
    admission_protected_final_combined_v2_workshop_proposal_apply as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-workshop-"
    "proposal-apply-route-coverage-v1-2026-08-26.json"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _store(raw: bytes) -> tuple[tempfile.TemporaryDirectory[str], CAS]:
    temporary = tempfile.TemporaryDirectory()
    store = CAS(temporary.name)
    store.put_expected(BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw))
    return temporary, store


def _sync_command_json(command: dict[str, object], value: object) -> None:
    raw = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
    command["stdout_excerpt"] = raw.decode()
    command["stdout_bytes"] = len(raw)
    command["stdout_digest"] = _digest(raw)


def _sync_nested(changed: dict[str, object]) -> None:
    observation = changed["route_observation"]
    document = observation["document"]
    raw = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()
    observation["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": _digest(canonical_json(document)),
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
    nested_canonical = canonical_json(observation["document"])
    route_identity = {
        "bytes": len(nested_raw),
        "canonical_digest": _digest(nested_canonical),
        "digest": _digest(nested_raw),
    }
    digests = {
        "action": _digest(canonical_json(observation["document"]["actions"][0])),
        "composition": _digest(canonical_json(changed["composition"])),
        "composition_action": _digest(
            canonical_json(changed["composition"]["action"])
        ),
        "execution": _digest(canonical_json(observation["execution"])),
        "gateway_binding": _digest(
            canonical_json(observation["gateway_pid_binding"])
        ),
        "harness": _digest(
            canonical_json(changed["composition"]["action"]["harness"]["document"])
        ),
        "host_config": _digest(
            canonical_json(
                changed["composition"]["action"]["harness"]["document"][
                    "host_config"
                ]
            )
        ),
        "protected_boundary": _digest(
            canonical_json(observation["document"]["protected_boundary"])
        ),
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
    return raw, evidence_identity, route_identity, digests


class FinalCombinedV2WorkshopProposalApplyTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v2_workshop_proposal_apply(
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
                for key in subject.contract.base.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(json.loads(raw)["decision"]["route_pass_count"], 0)
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_coordinated_repins_fail_closed_and_summaries_are_ignored(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects(
            changed: dict[str, object], *, sync_harness: bool = False
        ) -> None:
            if sync_harness:
                _sync_harness(changed)
            raw, evidence, route_raw, digests = _repin(changed)
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", evidence),
                patch.object(subject, "_ROUTE_RAW", route_raw),
                patch.object(subject, "_DIGESTS", digests),
                patch.object(subject, "_verify_dependencies", return_value=None),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v2_workshop_proposal_apply(
                    evidence_cas=store
                )

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        denial = after["catalog_after_apply"]
        denial["response"]["value"]["error"]["message"] = "generic failure"
        _sync_command_json(denial["command"], denial["response"]["value"])
        changed["route_observation"]["document"]["actions"][0]["commands"][5] = (
            deepcopy(denial["command"])
        )
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        final = after["final_catalog"]
        final["command"]["exit_code"] = 0
        changed["route_observation"]["document"]["actions"][0]["commands"][8] = (
            deepcopy(final["command"])
        )
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        initial_value = after["catalog_before"]["response"]["value"]
        initial_value["skills"] = []
        _sync_command_json(after["catalog_before"]["command"], initial_value)
        changed["route_observation"]["document"]["actions"][0]["commands"][0] = (
            deepcopy(after["catalog_before"]["command"])
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        action["observations"]["target_after_proposal"] = deepcopy(
            action["observations"]["target_after_apply"]
        )
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        for name in ("target_after_apply", "target_final"):
            after[name]["skill"]["digest"] = "sha256:" + "1" * 64
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        after["immediate_post_apply_snapshot"]["file"]["digest"] = (
            "sha256:" + "2" * 64
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        action["commands"][3], action["commands"][4] = (
            action["commands"][4],
            action["commands"][3],
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["decision"]["route_pass_count"] = 1
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["actions"][0][
            "claimed_pass"
        ] = "forged"
        rejects(changed)

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        forged = "sha256:" + "3" * 64
        harness["image_id"] = forged
        harness["run_image_reference"] = forged
        harness["image_lineage"]["child"]["id"] = forged
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        changed["source_artifacts"]["probe_bundle"][0]["role"] = "probe"
        changed["route_observation"]["bundle"] = deepcopy(
            changed["source_artifacts"]["probe_bundle"]
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["inputs"]["gateway_config"]["skills"][
            "workshop"
        ]["restoreAuthority"] = "local"
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["execution"]["argv"][-1] = (
            "ADM-02/reload/workshop-invalidation"
        )
        rejects(changed)

        changed = deepcopy(original)
        applied = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]["native_apply_result"]
        applied["response"]["value"]["record"]["id"] = "forged"
        _sync_command_json(applied["command"], applied["response"]["value"])
        changed["route_observation"]["document"]["actions"][0]["commands"][4] = (
            deepcopy(applied["command"])
        )
        rejects(changed)

        changed = deepcopy(original)
        applied = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]["native_apply_result"]
        record = applied["response"]["value"]["record"]
        record["scan"]["scannedAt"] = "2026-08-26T14:32:37.000Z"
        record["appliedAt"] = "2026-08-26T14:32:37.001Z"
        record["updatedAt"] = record["appliedAt"]
        _sync_command_json(applied["command"], applied["response"]["value"])
        changed["route_observation"]["document"]["actions"][0]["commands"][4] = (
            deepcopy(applied["command"])
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["actions"][0]["observations"][
            "catalog_after_apply_matches_initial"
        ] = "false"
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        for name in (
            "catalog_after_apply_excludes_workshop",
            "catalog_after_apply_matches_initial",
            "final_catalog_matches_initial",
            "final_same_session_catalog_exact",
            "immediate_post_apply_same_session",
            "immediate_post_apply_store_unchanged",
        ):
            after[name] = not after[name]
        for name in (
            "initial_snapshot_check",
            "immediate_post_apply_snapshot_check",
            "final_snapshot_check",
            "final_snapshot_transition",
        ):
            for key in after[name]:
                after[name][key] = not after[name][key]
        raw, evidence, route_raw, digests = _repin(changed)
        temporary, store = _store(raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", evidence),
            patch.object(subject, "_ROUTE_RAW", route_raw),
            patch.object(subject, "_DIGESTS", digests),
            patch.object(subject, "_verify_dependencies", return_value=None),
            patch.object(subject, "_verify_retained_evidence", return_value=raw),
        ):
            result = subject.verify_openclaw_final_combined_v2_workshop_proposal_apply(
                evidence_cas=store
            )
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})

    def test_duplicate_and_nonfinite_nested_json_fail_closed(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects_nested(raw_nested: bytes) -> None:
            changed = deepcopy(original)
            observation = changed["route_observation"]
            observation["raw"] = {
                "base64": base64.b64encode(raw_nested).decode(),
                "bytes": len(raw_nested),
                "canonical_digest": subject._ROUTE_RAW["canonical_digest"],
                "digest": _digest(raw_nested),
                "raw_is_canonical_json_lf": False,
            }
            outer = canonical_json(changed)
            raw = outer + b"\n"
            evidence = {
                **subject._EVIDENCE,
                "bytes": len(raw),
                "canonical_bytes": len(outer),
                "canonical_digest": _digest(outer),
                "digest": _digest(raw),
            }
            route = {
                **subject._ROUTE_RAW,
                "bytes": len(raw_nested),
                "digest": _digest(raw_nested),
            }
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", evidence),
                patch.object(subject, "_ROUTE_RAW", route),
                patch.object(subject, "_verify_dependencies", return_value=None),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v2_workshop_proposal_apply(
                    evidence_cas=store
                )

        rejects_nested(b'{"actions":[],"actions":[]}\n')
        rejects_nested(b'{"actions":[],"value":NaN}\n')


if __name__ == "__main__":
    unittest.main()
