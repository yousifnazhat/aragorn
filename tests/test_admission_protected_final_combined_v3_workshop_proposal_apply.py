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
    admission_protected_final_combined_v3_workshop_proposal_apply as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-workshop-"
    "proposal-apply-route-coverage-v1-2026-08-28.json"
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


def _sync_command_stdout(command: dict[str, object], value: str) -> None:
    raw = value.encode()
    command["stdout_excerpt"] = value
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
    changed["harness"] = deepcopy(envelope)


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
        "composition_action": _digest(canonical_json(changed["composition"]["action"])),
        "execution": _digest(canonical_json(observation["execution"])),
        "gateway_binding": _digest(canonical_json(observation["gateway_pid_binding"])),
        "harness": _digest(
            canonical_json(changed["composition"]["action"]["harness"]["document"])
        ),
        "host_config": _digest(
            canonical_json(
                changed["composition"]["action"]["harness"]["document"]["host_config"]
            )
        ),
        "protected_boundary": _digest(
            canonical_json(observation["document"]["protected_boundary"])
        ),
        "route_observation": _digest(canonical_json(observation)),
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


class FinalCombinedV3WorkshopProposalApplyTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v3_workshop_proposal_apply(
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
                for key in subject.v3_contract.contract._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(
            result["decision"]["status"], "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE"
        )
        self.assertEqual(
            result["route_semantics"],
            {
                "activation_transition_dynamically_exercised": False,
                "dynamically_exercised_routes": [subject._ROUTE],
                "install_policy_dynamically_exercised": False,
                "pass_basis": (
                    "SIGNED_EXACT_NATIVE_PROPOSAL_APPLY_RESIDUE_WITH_POST_APPLY_"
                    "EXTERNAL_ACTIVATION_AUTHORITY_CATALOG_DENIAL"
                ),
                "post_write_catalog_denial_dynamically_exercised": True,
                "pre_effect_prevention_dynamically_exercised": False,
                "transitions_dynamically_exercised": True,
            },
        )
        self.assertIn(
            "NO_PRE_EFFECT_NO_MUTATION_CLEANUP_ROLLBACK_OR_QUARANTINE_CLAIM",
            result["limitations"],
        )
        self.assertIn(
            "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
            result["limitations"],
        )
        self.assertIn(
            "POST_WRITE_EXTERNAL_ACTIVATION_AUTHORITY_CATALOG_DENIAL_OBSERVED",
            result["limitations"],
        )
        self.assertEqual(json.loads(raw)["decision"]["route_pass_count"], 0)
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_coordinated_repins_fail_closed_and_summaries_are_ignored(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects(
            changed: dict[str, object],
            *,
            error: str = ".+",
            sync_harness: bool = False,
        ) -> None:
            if sync_harness:
                _sync_harness(changed)
            raw, evidence, route_raw, digests = _repin(changed)
            artifact = changed["composition"]["action"]["artifacts"][
                "final_combined_v3_workshop_proposal_apply"
            ]
            artifact_digests = {
                name: _digest(canonical_json(value)) for name, value in artifact.items()
            }
            type_shape_digest = _digest(
                canonical_json(subject.v3_contract._type_shape(changed))
            )
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", evidence),
                patch.object(subject, "_ROUTE_RAW", route_raw),
                patch.object(subject, "_DIGESTS", digests),
                patch.object(subject, "_ARTIFACT_DIGESTS", artifact_digests),
                patch.object(subject, "_TYPE_SHAPE_DIGEST", type_shape_digest),
                patch.object(subject, "_verify_dependencies", return_value=None),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaisesRegex(AdmissionEvidenceError, error),
            ):
                subject.verify_openclaw_final_combined_v3_workshop_proposal_apply(
                    evidence_cas=store
                )

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        denial = after["catalog_after_apply"]
        denial["response"]["value"]["error"]["message"] = "generic failure"
        _sync_command_json(denial["command"], denial["response"]["value"])
        changed["route_observation"]["document"]["actions"][0]["commands"][5] = (
            deepcopy(denial["command"])
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        initial = action["observations"]["catalog_before"]["command"]
        duplicate = initial["stdout_excerpt"].replace(
            '  "agentId": "main",\n',
            '  "agentId": "forged",\n  "agentId": "main",\n',
            1,
        )
        _sync_command_stdout(initial, duplicate)
        action["commands"][0] = deepcopy(initial)
        rejects(changed, error="duplicate .* key: agentId")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        denied = action["observations"]["catalog_after_apply"]["command"]
        boolean_alias = denied["stdout_excerpt"].replace(
            '  "ok": false,\n', '  "ok": 0,\n', 1
        )
        _sync_command_stdout(denied, boolean_alias)
        action["commands"][5] = deepcopy(denied)
        rejects(changed, error="boolean field type changed")

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        final = after["final_catalog"]
        final["command"]["exit_code"] = 0
        changed["route_observation"]["document"]["actions"][0]["commands"][8] = (
            deepcopy(final["command"])
        )
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
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
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        for name in ("target_after_apply", "target_final"):
            after[name]["skill"]["digest"] = "sha256:" + "1" * 64
        rejects(changed)

        changed = deepcopy(original)
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
        after["immediate_post_apply_snapshot"]["file"]["digest"] = "sha256:" + "2" * 64
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        action["commands"][3], action["commands"][4] = (
            action["commands"][4],
            action["commands"][3],
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        after = action["observations"]
        applied = after["native_apply_result"]
        record = applied["response"]["value"]["record"]
        applied["command"]["started_at"] = "2026-08-28T19:50:11.808Z"
        applied["command"]["completed_at"] = "2026-08-28T19:50:11.811Z"
        record["scan"]["scannedAt"] = "2026-08-28T19:50:11.809Z"
        record["appliedAt"] = "2026-08-28T19:50:11.810Z"
        record["updatedAt"] = record["appliedAt"]
        _sync_command_json(applied["command"], applied["response"]["value"])
        action["commands"][4] = deepcopy(applied["command"])
        post_apply = after["catalog_after_apply"]
        post_apply["command"]["started_at"] = "2026-08-28T19:50:11.811Z"
        action["commands"][5] = deepcopy(post_apply["command"])
        rejects(changed, error="observation-command timeline changed")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        after = action["observations"]
        initial_turn = after["initial_turn"]
        initial_wait = initial_turn["wait"]["command"]
        initial_wait["completed_at"] = "2026-08-28T19:50:10.531Z"
        initial_turn["commands"][1] = deepcopy(initial_wait)
        action["commands"][2] = deepcopy(initial_wait)
        proposal = after["native_proposal_result"]["command"]
        proposal["started_at"] = "2026-08-28T19:50:10.531Z"
        action["commands"][3] = deepcopy(proposal)
        rejects(changed, error="snapshot-observation command timeline changed")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        initial_turn = action["observations"]["initial_turn"]
        wait = initial_turn["wait"]
        wait["response"]["value"]["endedAt"] = 1
        _sync_command_json(wait["command"], wait["response"]["value"])
        initial_turn["commands"][1] = deepcopy(wait["command"])
        action["commands"][2] = deepcopy(wait["command"])
        rejects(changed, error="turn snapshot timeline changed")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        after = action["observations"]
        for name in ("initial_snapshot", "immediate_post_apply_snapshot"):
            entry = after[name]["entry"]
            entry["started_at"] = 1
            entry["runtime_ms"] = entry["ended_at"] - entry["started_at"]
        rejects(changed, error="turn snapshot timeline changed")

        changed = deepcopy(original)
        changed["decision"]["route_pass_count"] = 1
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["actions"][0]["claimed_pass"] = (
            "forged"
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["artifacts"][
            "final_combined_v3_workshop_proposal_apply"
        ]["collector"]["capture_recipe"]["digest"] = "sha256:" + "4" * 64
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["artifacts"][
            "final_combined_v3_workshop_proposal_apply"
        ]["collector"]["dockerfile"]["digest"] = "sha256:" + "5" * 64
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
        record["scan"]["scannedAt"] = "2026-08-28T19:50:12.000Z"
        record["appliedAt"] = "2026-08-28T19:50:12.001Z"
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
        after = changed["route_observation"]["document"]["actions"][0]["observations"]
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
            result = subject.verify_openclaw_final_combined_v3_workshop_proposal_apply(
                evidence_cas=store
            )
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})

    def test_duplicate_and_nonfinite_outer_and_nested_json_fail_closed(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects_outer(raw: bytes) -> None:
            identity = {
                **subject._EVIDENCE,
                "bytes": len(raw),
                "canonical_bytes": len(raw) - 1,
                "canonical_digest": _digest(raw[:-1]),
                "digest": _digest(raw),
            }
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", identity),
                patch.object(subject, "_verify_dependencies", return_value=None),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v3_workshop_proposal_apply(
                    evidence_cas=store
                )

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
                subject.verify_openclaw_final_combined_v3_workshop_proposal_apply(
                    evidence_cas=store
                )

        rejects_outer(b'{"authority":"x","authority":"x"}\n')
        rejects_outer(b'{"value":NaN}\n')
        rejects_nested(b'{"actions":[],"actions":[]}\n')
        rejects_nested(b'{"actions":[],"value":NaN}\n')


if __name__ == "__main__":
    unittest.main()
