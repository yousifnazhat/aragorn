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
    admission_protected_final_combined_v2_config_activation as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-config-"
    "entry-activation-route-coverage-v1-2026-08-22.json"
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


def _sync_nested(changed: dict[str, object]) -> None:
    observation = changed["route_observation"]
    document = observation["document"]
    canonical = canonical_json(document)
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


def _sync_config_contract(changed: dict[str, object]) -> dict[str, object]:
    composition = changed["composition"]
    source = composition["action"]["artifacts"]["final_combined_v2"]
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
    composition["action"]["inputs"]["gateway_config"] = deepcopy(config["document"])

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

    action = changed["route_observation"]["document"]["action"]
    before = action["prerequisites"]
    after = action["observations"]
    for value in (
        before["config_before"],
        before["boundary_before"]["configuration"],
        after["config_after"],
        after["boundary_after"]["configuration"],
    ):
        value["canonical_digest"] = config_identity["canonical_digest"]
        value["file"]["digest"] = config_identity["canonical_digest"]
        value["file"]["size"] = config_identity["canonical_bytes"]
    return {
        **subject._SOURCES,
        "configuration": config_identity,
        "runtime_lock": lock_identity,
    }


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
    action = observation["document"]["action"]
    before = action["prerequisites"]
    after = action["observations"]
    nested_raw = base64.b64decode(observation["raw"]["base64"], validate=True)
    nested_canonical = canonical_json(observation["document"])
    route_identity = {
        "bytes": len(nested_raw),
        "canonical_digest": _digest(nested_canonical),
        "digest": _digest(nested_raw),
    }
    digests = {
        "action": _digest(canonical_json(action)),
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
        "source_artifacts": _digest(canonical_json(changed["source_artifacts"])),
        "stack": _digest(canonical_json(observation["stack_before"])),
    }
    static = {
        "boundary": _digest(canonical_json(before["boundary_before"])),
        "config": _digest(canonical_json(before["config_before"])),
        "config_lock": _digest(canonical_json(before["config_lock_before"])),
        "discovery": _digest(canonical_json(before["discovery_before"])),
        "gateway": _digest(canonical_json(before["gateway_process_before"])),
        "openclaw": _digest(canonical_json(before["openclaw_before"])),
        "runtime_tree": _digest(canonical_json(before["runtime_tree_before"])),
        "target": _digest(canonical_json(before["target_before"])),
        "update": _digest(canonical_json(after["update"])),
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


class FinalCombinedV2ConfigActivationTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v2_config_activation(
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
                for key in subject.base.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(json.loads(raw)["decision"]["route_pass_count"], 0)
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_coordinated_repin_hostile_semantics_fail_closed(self) -> None:
        original = json.loads(_EVIDENCE.read_bytes())

        def rejects(
            changed: dict[str, object],
            *,
            sources: dict[str, object] | None = None,
            sync_harness: bool = False,
        ) -> None:
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
                patch.object(
                    subject,
                    "_SOURCES",
                    subject._SOURCES if sources is None else sources,
                ),
                patch.object(subject, "_verify_dependencies", return_value=None),
                patch.object(subject, "_verify_retained_evidence", return_value=raw),
                self.assertRaises(AdmissionEvidenceError),
            ):
                subject.verify_openclaw_final_combined_v2_config_activation(
                    evidence_cas=store
                )

        changed = deepcopy(original)
        source = changed["composition"]["action"]["artifacts"]["final_combined_v2"]
        source["config"]["document"]["skills"]["allowBundled"] = []
        sources = _sync_config_contract(changed)
        rejects(changed, sources=sources)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        for command in (
            action["observations"]["update"]["command"],
            action["commands"][3],
        ):
            command["argv"][4] = "skills.info"
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        response = action["observations"]["update"]["response"]["value"]
        response["error"]["message"] = "generic failure"
        _sync_command_stdout(action["observations"]["update"]["command"], response)
        action["commands"][3] = deepcopy(action["observations"]["update"]["command"])
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["observations"]["update"]["command"]["exit_code"] = 0
        action["commands"][3]["exit_code"] = 0
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["action"]["observations"][
            "config_lock_after"
        ]["exists"] = True
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        for discovery in (
            action["prerequisites"]["discovery_before"],
            action["observations"]["discovery_after"],
        ):
            discovery["response"]["value"]["source"] = "workspace"
            _sync_command_stdout(discovery["command"], discovery["response"]["value"])
        action["commands"][2] = deepcopy(
            action["prerequisites"]["discovery_before"]["command"]
        )
        action["commands"][4] = deepcopy(
            action["observations"]["discovery_after"]["command"]
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["action"]["observations"][
            "gateway_process_after"
        ]["start_time_ticks"] = "changed"
        rejects(changed)

        changed = deepcopy(original)
        commands = changed["route_observation"]["document"]["action"]["commands"]
        commands[3], commands[4] = commands[4], commands[3]
        rejects(changed)

        changed = deepcopy(original)
        changed["decision"]["route_pass_count"] = 1
        rejects(changed)

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        forged = "sha256:" + "0" * 64
        harness["image_id"] = forged
        harness["run_image_reference"] = forged
        harness["image_lineage"]["child"]["id"] = forged
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        changed["source_artifacts"]["probe_bundle"][0]["digest"] = "sha256:" + "1" * 64
        changed["route_observation"]["bundle"] = deepcopy(
            changed["source_artifacts"]["probe_bundle"]
        )
        rejects(changed)

        changed = deepcopy(original)
        binding = changed["route_observation"]["gateway_pid_binding"]
        binding["pid"] += 1
        binding["mount_namespace"] = f"/proc/{binding['pid']}/ns/mnt"
        execution = changed["route_observation"]["execution"]
        execution["argv"][2] = str(binding["pid"])
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        response = action["observations"]["update"]["response"]["value"]
        response["error"]["retryable"] = 0
        _sync_command_stdout(action["observations"]["update"]["command"], response)
        action["commands"][3] = deepcopy(action["observations"]["update"]["command"])
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
                    subject.verify_openclaw_final_combined_v2_config_activation(
                        evidence_cas=store
                    )


if __name__ == "__main__":
    unittest.main()
