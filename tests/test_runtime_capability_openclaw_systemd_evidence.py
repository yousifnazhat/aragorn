from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_capability_openclaw_systemd_evidence as verifier
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "runtime-capability-openclaw-systemd-composition-p3-5a-2026-08-06.json"
)
_RAW_DIGEST = "f39d872648e5c7e84fb795f4826dc92861e79ef2287a9c6bcebbe7bbd52348d3"
_ZERO_DIGEST = "sha256:" + "0" * 64


def _set(*path: str, value: object):
    def mutate(document: dict) -> None:
        current = document
        for name in path[:-1]:
            current = current[name]
        current[path[-1]] = value

    return mutate


def _forge_source_install(document: dict) -> None:
    document["artifacts"][0]["installed_digest"] = _ZERO_DIGEST


def _append_broker_argument(document: dict) -> None:
    unit = document["deployment"]["positive"]["units"]["broker"]
    unit["ExecStart"] = unit["ExecStart"].replace(
        " ; ignore_errors=", " --forged ; ignore_errors=", 1
    )


def _forge_negative_result(document: dict) -> None:
    result = document["scenarios"]["issuer_unavailable"]["driver"]["scenario"]["proof"][
        "retained_tool_result"
    ]["result"]
    result["effect_status"] = "CREATED"


def _forge_negative_peer(document: dict) -> None:
    document["peer_trace"]["issuer_unavailable_broker"]["peer_credentials"] = [
        {"pid": 1, "uid": 0, "gid": 0}
    ]


def _forge_lease(document: dict) -> None:
    state = document["scenarios"]["one_shot_allow"]["grant_state"]["document"]
    state["claim"]["lease"]["runtime_digest"] = _ZERO_DIGEST


def _forge_attribution(document: dict) -> None:
    receipt = document["scenarios"]["one_shot_allow"]["profile_receipt"]["document"]
    receipt["runtime_attribution"]["pid"] += 1


def _forge_positive_peer(document: dict) -> None:
    document["peer_trace"]["one_shot_sensor"]["peer_credentials"][0]["pid"] += 1


class RuntimeCapabilityOpenClawSystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = _EVIDENCE.read_bytes()
        cls.document = json.loads(cls.raw)

    def test_retained_artifact_is_canonical_and_verifies(self) -> None:
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), _RAW_DIGEST)
        self.assertEqual(self.raw, canonical_json(self.document) + b"\n")
        verifier.verify_runtime_capability_openclaw_systemd_evidence(self.document)

    def test_retained_digest_is_mandatory(self) -> None:
        with (
            patch.object(verifier, "_EVIDENCE_DIGEST", None),
            self.assertRaises(AdmissionEvidenceError),
        ):
            verifier.verify_runtime_capability_openclaw_systemd_evidence(self.document)

    def test_boundary_mutations_are_rejected_after_repin(self) -> None:
        mutations = {
            "claim promotion": _set("decision", "phase3_exit_eligible", value=True),
            "collector closure": _set(
                "collector", "probe", "path", value="/src/scripts/other.py"
            ),
            "source install closure": _forge_source_install,
            "P3.4b parent lineage": _set(
                "harness", "document", "parent_image_id", value=_ZERO_DIGEST
            ),
            "runtime pin": _set("runtime", "tree", "tree_digest", value=_ZERO_DIGEST),
            "profile pin": _set("profile", "digest", value=_ZERO_DIGEST),
            "root provenance ceiling": _set(
                "inputs",
                "provenance_bindings",
                "source_manifest",
                "authority",
                value="INSTALLER_AUTHORITY",
            ),
            "dynamic unit drop-in": _set(
                "deployment",
                "positive",
                "units",
                "broker",
                "DropInPaths",
                value="/etc/systemd/system/forged.conf",
            ),
            "dynamic ExecStart": _append_broker_argument,
            "dynamic LoadCredential": _set(
                "deployment",
                "positive",
                "units",
                "sensor",
                "LoadCredential",
                value='a(ss) 1 "forged" "/tmp/forged"',
            ),
            "legacy route": _set(
                "deployment",
                "positive",
                "legacy_routes",
                "aragorn-runtime-action-broker.service",
                "enabled",
                value="enabled",
            ),
            "negative measured effect": _set(
                "scenarios",
                "issuer_unavailable",
                "effects",
                "target_exists",
                value=True,
            ),
            "negative client result": _forge_negative_result,
            "negative broker peer": _forge_negative_peer,
            "same AVAILABLE grant": _set(
                "scenarios",
                "one_shot_allow",
                "before",
                "grant_state",
                "document",
                "status",
                value="CONSUMED",
            ),
            "exact lease": _forge_lease,
            "receipt submission": _set(
                "scenarios",
                "one_shot_allow",
                "profile_receipt",
                "document",
                "submission_digest",
                value=_ZERO_DIGEST,
            ),
            "created target": _set(
                "scenarios",
                "one_shot_allow",
                "target",
                "digest",
                value=_ZERO_DIGEST,
            ),
            "runtime attribution": _forge_attribution,
            "SO_PEERCRED chain": _forge_positive_peer,
            "runtime secret absence": _set(
                "scenarios",
                "one_shot_allow",
                "runtime_facing_grant_or_lease_absent",
                value=False,
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = deepcopy(self.document)
                mutate(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    verifier.verify_runtime_capability_openclaw_systemd_evidence(
                        changed,
                        expected_digest=canonical_digest(changed),
                    )


if __name__ == "__main__":
    unittest.main()
