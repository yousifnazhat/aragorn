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

from aragorn import admission_protected_final_combined_v2_curator_restore as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-curator-"
    "restore-route-coverage-v1-2026-08-26.json"
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


def _sync_command(command: dict[str, object], *, stream: str, value: str) -> None:
    raw = value.encode()
    command[f"{stream}_excerpt"] = value
    command[f"{stream}_bytes"] = len(raw)
    command[f"{stream}_digest"] = _digest(raw)


def _sync_command_json(command: dict[str, object], value: object) -> None:
    _sync_command(
        command,
        stream="stdout",
        value=json.dumps(value, indent=2, ensure_ascii=False) + "\n",
    )


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
        "action": _digest(canonical_json(observation["document"]["action"])),
        "composition": _digest(canonical_json(changed["composition"])),
        "composition_action": _digest(
            canonical_json(changed["composition"]["action"])
        ),
        "execution": _digest(canonical_json(observation["execution"])),
        "gateway_binding": _digest(
            canonical_json(observation["gateway_pid_binding"])
        ),
        "harness": _digest(
            canonical_json(
                changed["composition"]["action"]["harness"]["document"]
            )
        ),
        "host_config": _digest(
            canonical_json(
                changed["composition"]["action"]["harness"]["document"][
                    "host_config"
                ]
            )
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


class FinalCombinedV2CuratorRestoreTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v2_curator_restore(
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

    def test_coordinated_repin_hostile_semantics_fail_closed(self) -> None:
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
                subject.verify_openclaw_final_combined_v2_curator_restore(
                    evidence_cas=store
                )

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        gateway = action["observations"]["gateway_restore"]
        gateway["response"]["value"]["error"]["message"] = "generic failure"
        _sync_command_json(gateway["command"], gateway["response"]["value"])
        action["commands"][5] = deepcopy(gateway["command"])
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        gateway = action["observations"]["gateway_restore"]
        gateway["command"]["exit_code"] = 0
        action["commands"][5] = deepcopy(gateway["command"])
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        invalid = action["observations"]["invalid_token_gateway_control"]
        invalid["response"]["value"]["error"]["code"] = 1000
        _sync_command_json(invalid["command"], invalid["response"]["value"])
        action["commands"][6] = deepcopy(invalid["command"])
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        cli = action["observations"]["cli_fallback_restore"]["command"]
        _sync_command(cli, stream="stderr", value="restore succeeded\n")
        cli["exit_code"] = 0
        action["commands"][7] = deepcopy(cli)
        rejects(changed)

        changed = deepcopy(original)
        observations = changed["route_observation"]["document"]["action"][
            "observations"
        ]
        for name in ("database_before", "database_after_gateway", "database_after_cli"):
            observations[name]["row"]["state"] = "active"
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        for side, key in (("prerequisites", "target_before"), ("observations", "target_after")):
            action[side][key]["tree_digest"] = "sha256:" + "0" * 64
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        action["commands"][5], action["commands"][6] = (
            action["commands"][6],
            action["commands"][5],
        )
        rejects(changed)

        changed = deepcopy(original)
        changed["decision"]["route_pass_count"] = 1
        rejects(changed)

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        forged = "sha256:" + "1" * 64
        harness["image_id"] = forged
        harness["run_image_reference"] = forged
        harness["image_lineage"]["child"]["id"] = forged
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        changed["source_artifacts"]["probe_bundle"][0]["digest"] = (
            "sha256:" + "2" * 64
        )
        changed["route_observation"]["bundle"] = deepcopy(
            changed["source_artifacts"]["probe_bundle"]
        )
        rejects(changed)

        changed = deepcopy(original)
        binding = changed["route_observation"]["gateway_pid_binding"]
        binding["pid"] += 1
        binding["mount_namespace"] = f"/proc/{binding['pid']}/ns/mnt"
        changed["route_observation"]["execution"]["argv"][2] = str(binding["pid"])
        rejects(changed)

        changed = deepcopy(original)
        row = changed["route_observation"]["document"]["action"]["observations"][
            "database_before"
        ]["row"]
        row["pinned"] = "false"
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["configuration"]["document"]["skills"]["workshop"][
                "restoreAuthority"
            ] = "local"
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["authority"] = "FULL_RUN_AUTHORITY"
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["decision"]["verifier_status"] = "PASS"
        rejects(changed)

        changed = deepcopy(original)
        changed["composition"]["action"]["limitations"] = []
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["execution"]["environment_names"] = []
        rejects(changed)

        changed = deepcopy(original)
        unit = "aragorn-agent-gateway.service"
        changed["route_observation"]["stack_before"]["processes"][unit][
            "cmdline"
        ] = ["evil"]
        changed["composition"]["action"]["boundaries"]["processes"][unit][
            "cmdline"
        ] = ["evil"]
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["execution"]["forged"] = True
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        for side, key in (
            ("prerequisites", "target_before"),
            ("observations", "target_after"),
        ):
            action[side][key]["root"]["exists"] = False
            action[side][key]["entries"][0]["exists"] = False
        rejects(changed)

        changed = deepcopy(original)
        action = changed["route_observation"]["document"]["action"]
        for side, key in (
            ("prerequisites", "modules_before"),
            ("observations", "modules_after"),
        ):
            action[side][key]["curator"]["observed"]["exists"] = False
        rejects(changed)

        changed = deepcopy(original)
        changed["route_observation"]["document"]["action"]["decision"] = {
            "status": "PASS"
        }
        rejects(changed)

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        harness["authority"] = "FULL_RELEASE_AUTHORITY"
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        harness["host_config"]["runtime"] = "evil"
        rejects(changed, sync_harness=True)

        changed = deepcopy(original)
        harness = changed["composition"]["action"]["harness"]["document"]
        harness["openclaw_runtime_volume_identity"]["driver"] = "evil"
        rejects(changed, sync_harness=True)

    def test_duplicate_and_nonfinite_json_fail_closed(self) -> None:
        original = _EVIDENCE.read_bytes()
        hostile = (
            original.replace(b'{"authority":', b'{"authority":"forged","authority":', 1),
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
                    subject.verify_openclaw_final_combined_v2_curator_restore(
                        evidence_cas=store
                    )


if __name__ == "__main__":
    unittest.main()
