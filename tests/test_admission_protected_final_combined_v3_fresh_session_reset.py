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

from aragorn import admission_protected_final_combined_v3_fresh_session_reset as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-fresh-"
    "session-reset-route-coverage-v1-2026-08-28.json"
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
) -> tuple[
    bytes,
    dict[str, object],
    dict[str, object],
    dict[str, str],
    str,
    str,
]:
    _sync_nested(changed)
    observation = changed["route_observation"]
    document = observation["document"]
    nested_raw = base64.b64decode(observation["raw"]["base64"], validate=True)
    route_identity = {
        "bytes": len(nested_raw),
        "canonical_digest": _digest(canonical_json(document)),
        "digest": _digest(nested_raw),
    }
    digests = {
        "action": _digest(canonical_json(document["actions"][0])),
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
        "protected_boundary": _digest(canonical_json(document["protected_boundary"])),
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
    outer_shape = _digest(canonical_json(subject.v3_contract._type_shape(changed)))
    route_shape = _digest(canonical_json(subject.v3_contract._type_shape(document)))
    return raw, evidence_identity, route_identity, digests, outer_shape, route_shape


class FinalCombinedV3FreshSessionResetTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v3_fresh_session_reset(
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
            result["route_semantics"]["pass_basis"],
            "SIGNED_EXACT_RESET_ROTATION_CLEAR_AND_REBUILD_TRANSITION",
        )
        self.assertFalse(
            result["route_semantics"]["install_policy_dynamically_exercised"]
        )
        self.assertIn(
            "RESET_REQUEST_ACCEPTANCE_IS_NOT_MODEL_OR_DELIVERY_SUCCESS",
            result["limitations"],
        )
        self.assertIn(
            "RESET_TRANSPORT_IN_PROCESS_NO_INDEPENDENT_RESET_SUBPROCESS_PID_ARGV_OR_STDOUT_RECORD",
            result["limitations"],
        )
        self.assertIn(
            "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
            result["limitations"],
        )
        self.assertIn(
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
            result["limitations"],
        )
        self.assertEqual(json.loads(raw)["decision"]["route_pass_count"], 0)
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_hostile_coordinated_repins_fail_closed(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects(
            changed: dict[str, object],
            *,
            error: str = ".+",
            sync_harness: bool = False,
        ) -> None:
            if sync_harness:
                _sync_harness(changed)
            raw, evidence, route_raw, digests, outer_shape, route_shape = _repin(
                changed
            )
            artifact = changed["composition"]["action"]["artifacts"][
                "final_combined_v3_fresh_session_reset"
            ]
            artifact_digests = {
                name: _digest(canonical_json(value)) for name, value in artifact.items()
            }
            temporary, store = _store(raw)
            self.addCleanup(temporary.cleanup)
            with (
                patch.object(subject, "_EVIDENCE", evidence),
                patch.object(subject, "_ROUTE_RAW", route_raw),
                patch.object(subject, "_DIGESTS", digests),
                patch.object(subject, "_ARTIFACT_DIGESTS", artifact_digests),
                patch.object(subject, "_TYPE_SHAPE_DIGEST", outer_shape),
                patch.object(subject, "_ROUTE_TYPE_SHAPE_DIGEST", route_shape),
                patch.object(subject, "_verify_dependencies", return_value=None),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaisesRegex(AdmissionEvidenceError, error),
            ):
                subject.verify_openclaw_final_combined_v3_fresh_session_reset(
                    evidence_cas=store
                )

        changed = deepcopy(original)
        changed["source_artifacts"]["collector"]["digest"] = "sha256:" + "1" * 64
        rejects(changed, error="source")

        changed = deepcopy(original)
        changed["composition"]["action"]["artifacts"][
            "final_combined_v3_fresh_session_reset"
        ]["collector"]["capture_recipe"]["digest"] = "sha256:" + "2" * 64
        rejects(changed, error="collector")

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        forged = "sha256:" + "3" * 64
        harness["image_id"] = forged
        harness["run_image_reference"] = forged
        harness["image_lineage"]["child"]["id"] = forged
        rejects(changed, error="harness", sync_harness=True)

        changed = deepcopy(original)
        changed["composition"]["action"]["inputs"]["gateway_config"]["security"][
            "installPolicy"
        ]["allowedPackageManagers"] = []
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["artifacts"][
            "final_combined_v3_fresh_session_reset"
        ]["fresh_session_reset_probe"]["transform"]["v2_materialization"][
            "workshop"
        ] = True
        rejects(changed, error="transform")

        changed = deepcopy(original)
        changed["route_observation"]["execution"]["argv"][-1] = (
            "ADM-02/reload/workshop-invalidation"
        )
        rejects(changed, error="execution")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        action["observations"]["reset_turn"]["accepted"] = 1
        rejects(changed, error="boolean field type changed")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        action["observations"]["reset_turn"]["params"]["message"] = "/reset"
        rejects(changed, error="semantics")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        action["observations"]["reset_turn"]["scopes"] = ["operator.write"]
        rejects(changed, error="semantics")

        changed = deepcopy(original)
        observed = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        observed["session_after_rotation"]["entry"]["session_id"] = observed[
            "session_before_reset"
        ]["entry"]["session_id"]
        rejects(changed, error="semantics")

        changed = deepcopy(original)
        observed = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        observed["session_after_rotation"]["entry"]["skill_names"] = ["template-skill"]
        rejects(changed, error="semantics")

        changed = deepcopy(original)
        observed = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        observed["session_after_reset"]["entry"]["snapshot_version"] += 1
        rejects(changed, error="snapshot custody")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        wait = action["observations"]["rebuild_turn"]["wait"]
        wait["response"]["value"]["error"] = "generic failure"
        _sync_command_json(wait["command"], wait["response"]["value"])
        action["observations"]["rebuild_turn"]["commands"][1] = deepcopy(
            wait["command"]
        )
        action["commands"][3] = deepcopy(wait["command"])
        rejects(changed, error="terminal turn")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        send = action["observations"]["initialization_turn"]["send"]["command"]
        duplicate = send["stdout_excerpt"].replace(
            '  "runId": ',
            '  "status": "forged",\n  "runId": ',
            1,
        )
        _sync_command_stdout(send, duplicate)
        action["observations"]["initialization_turn"]["commands"][0] = deepcopy(send)
        action["commands"][0] = deepcopy(send)
        rejects(changed, error="duplicate .* key: status")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        system = action["prerequisites"]["system_info"]
        value = system["response"]["value"]
        value["cpuCount"] = False
        _sync_command_json(system["command"], value)
        action["prerequisites"]["commands"][1] = deepcopy(system["command"])
        rejects(changed, error="boolean field type changed")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        initial = action["observations"]["initialization_turn"]
        rebuild = action["observations"]["rebuild_turn"]
        rebuild["send"]["command"]["pid"] = initial["send"]["command"]["pid"]
        rebuild["commands"][0] = deepcopy(rebuild["send"]["command"])
        action["commands"][2] = deepcopy(rebuild["send"]["command"])
        rejects(changed, error="command custody")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        reset = action["observations"]["reset_turn"]
        reset["completed_at"] = "2026-08-28T20:59:41.000Z"
        rejects(changed, error="snapshot custody")

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["actions"][0]
        wait = action["observations"]["initialization_turn"]["wait"]
        wait["response"]["value"]["endedAt"] = 1
        _sync_command_json(wait["command"], wait["response"]["value"])
        action["observations"]["initialization_turn"]["commands"][1] = deepcopy(
            wait["command"]
        )
        action["commands"][1] = deepcopy(wait["command"])
        rejects(changed, error="turn snapshot timeline")

        changed = deepcopy(original)
        changed["decision"]["phase3_exit_eligible"] = True
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["decision"]["edr_eligible"] = True
        rejects(changed)

    def test_probe_summaries_are_not_promoted(self) -> None:
        changed = json.loads(_EVIDENCE.read_bytes())
        observed = changed["route_observation"]["document"]["actions"][0][
            "observations"
        ]
        for name in (
            "rebuilt_snapshot_matches_baseline",
            "reset_snapshot_cleared",
            "session_id_rotated",
        ):
            observed[name] = not observed[name]
        for name in ("session_before_reset_check", "session_after_reset_check"):
            for key in observed[name]:
                observed[name][key] = not observed[name][key]
        raw, evidence, route_raw, digests, outer_shape, route_shape = _repin(changed)
        artifact = changed["composition"]["action"]["artifacts"][
            "final_combined_v3_fresh_session_reset"
        ]
        artifact_digests = {
            name: _digest(canonical_json(value)) for name, value in artifact.items()
        }
        temporary, store = _store(raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", evidence),
            patch.object(subject, "_ROUTE_RAW", route_raw),
            patch.object(subject, "_DIGESTS", digests),
            patch.object(subject, "_ARTIFACT_DIGESTS", artifact_digests),
            patch.object(subject, "_TYPE_SHAPE_DIGEST", outer_shape),
            patch.object(subject, "_ROUTE_TYPE_SHAPE_DIGEST", route_shape),
            patch.object(subject, "_verify_dependencies", return_value=None),
            patch.object(subject, "_verify_retained_evidence", return_value=raw),
        ):
            result = subject.verify_openclaw_final_combined_v3_fresh_session_reset(
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
                subject.verify_openclaw_final_combined_v3_fresh_session_reset(
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
                subject.verify_openclaw_final_combined_v3_fresh_session_reset(
                    evidence_cas=store
                )

        rejects_outer(b'{"authority":"x","authority":"x"}\n')
        rejects_outer(b'{"value":NaN}\n')
        rejects_nested(b'{"actions":[],"actions":[]}\n')
        rejects_nested(b'{"actions":[],"value":NaN}\n')


if __name__ == "__main__":
    unittest.main()
