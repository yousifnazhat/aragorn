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

from aragorn import admission_protected_final_combined_v2_archive_replacement as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-archive-"
    "source-force-replacement-route-coverage-v1-2026-08-22.json"
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


def _sync_command_stdout(command: dict[str, object], value: object) -> None:
    raw = json.dumps(value, indent=2, ensure_ascii=False).encode() + b"\n"
    command["stdout_excerpt"] = raw.decode()
    command["stdout_bytes"] = len(raw)
    command["stdout_digest"] = _digest(raw)


def _sync_command_stderr(command: dict[str, object], value: str) -> None:
    raw = value.encode()
    command["stderr_excerpt"] = value
    command["stderr_bytes"] = len(raw)
    command["stderr_digest"] = _digest(raw)


def _sync_nested(changed: dict[str, object]) -> None:
    observation = changed["route_observation"]
    document = observation["document"]
    canonical = canonical_json(document)
    raw = (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
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
    after = action["observations"]
    nested_raw = base64.b64decode(observation["raw"]["base64"], validate=True)
    route_identity = {
        "bytes": len(nested_raw),
        "canonical_digest": _digest(canonical_json(document)),
        "digest": _digest(nested_raw),
    }
    composition_action = changed["composition"]["action"]
    harness = composition_action["harness"]["document"]
    digests = {
        "action": _digest(canonical_json(action)),
        "composition": _digest(canonical_json(changed["composition"])),
        "composition_action": _digest(canonical_json(composition_action)),
        "execution": _digest(canonical_json(observation["execution"])),
        "gateway_binding": _digest(canonical_json(observation["gateway_pid_binding"])),
        "harness": _digest(canonical_json(harness)),
        "host_config": _digest(canonical_json(harness["host_config"])),
        "source_artifacts": _digest(canonical_json(changed["source_artifacts"])),
        "stack": _digest(canonical_json(observation["stack_before"])),
    }
    static = {
        "boundary_after": _digest(canonical_json(after["boundary_after"])),
        "boundary_before": _digest(canonical_json(document["protected_boundary"])),
        "discovery_after": _digest(canonical_json(after["discovery_after"])),
        "discovery_before": _digest(canonical_json(before["discovery"])),
        "gateway": _digest(canonical_json(before["gateway_process"])),
        "openclaw": _digest(canonical_json(before["openclaw"])),
        "positive_control": _digest(canonical_json(before["positive_control"])),
        "runtime_tree": _digest(canonical_json(before["runtime_tree"])),
        "source": _digest(canonical_json(before["source"])),
        "source_install": _digest(canonical_json(after["source_install"])),
        "system": _digest(canonical_json(before["system_info"])),
        "target": _digest(canonical_json(before["target_before"])),
        "upload_begin": _digest(canonical_json(after["upload_begin"])),
        "upload_install": _digest(canonical_json(after["upload_install"])),
        "version": _digest(canonical_json(before["version"])),
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


class FinalCombinedV2ArchiveReplacementTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v2_archive_replacement(
            evidence_cas=store
        )

    def test_exact_post_write_route_pass_with_broad_eligibility_false(self) -> None:
        raw = _EVIDENCE.read_bytes()
        evidence = json.loads(raw)
        action = evidence["route_observation"]["document"]["action"]
        observations = action["observations"]
        workspace = observations["boundary_after"]["roots"]["workspace_skills"]
        self.assertEqual(observations["source_install"]["command"]["exit_code"], 0)
        self.assertEqual(workspace["observation"]["entries"], ["template-skill"])

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
                for key in subject.base.base.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(evidence["decision"]["route_pass_count"], 0)
        self.assertIn(
            "DIRECTORY_INSTALL_SUCCEEDED_AND_LEFT_EXCLUDED_WORKSPACE_SKILL_RESIDUE",
            result["limitations"],
        )
        self.assertIn(
            "POST_WRITE_CATALOG_REJECTION_MAY_DENY_SKILL_DISCOVERY_AVAILABILITY",
            result["limitations"],
        )
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_coordinated_repin_hostile_post_write_semantics_fail_closed(self) -> None:
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
                subject.verify_openclaw_final_combined_v2_archive_replacement(
                    evidence_cas=store
                )

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["source_install"]["command"]["exit_code"] = 1
        action["commands"][6]["exit_code"] = 1
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["source_install"]["command"]["started_at"] = (
            "2026-08-22T10:26:14.000Z"
        )
        action["commands"][6] = deepcopy(
            action["observations"]["source_install"]["command"]
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        for target in (
            action["prerequisites"]["target_before"],
            action["observations"]["target_after"],
        ):
            target["root"]["exists"] = False
            target["entries"][0]["exists"] = False
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["action"]["observations"][
            "ignored"
        ] = "hostile"
        rejects(changed)

        changed = deepcopy(original)
        document = changed["route_observation"]["document"]
        document["action"]["observations"]["boundary_after"] = deepcopy(
            document["protected_boundary"]
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        rejection = action["observations"]["discovery_after"]["command"]
        _sync_command_stderr(rejection, "Error: generic catalog failure\n")
        action["commands"][7] = deepcopy(rejection)
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["target_after"]["tree_digest"] = "sha256:" + "0" * 64
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["source_after"]["tree_digest"] = "sha256:" + "0" * 64
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["runtime_tree_after"]["tree_digest"] = (
            "sha256:" + "0" * 64
        )
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["gateway_after"]["start_time_ticks"] = "1"
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        root = action["observations"]["boundary_after"]["roots"]["managed_skills"]
        root["observation"]["entries"] = ["unexpected"]
        root["observation"]["entry_count"] = 1
        root["observation"]["nlink"] = 3
        rejects(changed)

        for name, command_index in (("upload_begin", 4), ("upload_install", 5)):
            with self.subTest(upload=name):
                changed = deepcopy(original)
                action = changed["route_observation"]["document"]["action"]
                denial = action["observations"][name]
                response = denial["response"]["value"]
                response["error"]["retryable"] = True
                _sync_command_stdout(denial["command"], response)
                action["commands"][command_index] = deepcopy(denial["command"])
                rejects(changed)

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        fixture = harness["archive_source_fixture"]
        forged = b"forged archive fixture\n"
        fixture["base64"] = base64.b64encode(forged).decode()
        fixture["bytes"] = len(forged)
        fixture["digest"] = _digest(forged)
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        harness["archive_source_mount"]["mode"] = "rw"
        harness["archive_source_mount"]["rw"] = True
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        harness["source_commit"] = "0" * 40
        harness["source_commit_verification"]["command"][-1] = "0" * 40
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        changed["source_artifacts"]["probe_bundle"][0]["digest"] = "sha256:" + "1" * 64
        changed["route_observation"]["bundle"] = deepcopy(
            changed["source_artifacts"]["probe_bundle"]
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["decision"]["route_pass_count"] = 1
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
                    subject.verify_openclaw_final_combined_v2_archive_replacement(
                        evidence_cas=store
                    )


if __name__ == "__main__":
    unittest.main()
