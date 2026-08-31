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

from aragorn import admission_protected_final_combined_v3_curator_restore as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_ORIGINAL = json.loads(_EVIDENCE.read_bytes())


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
    raw = canonical + b"\n"
    observation["raw"] = {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "canonical_digest": _digest(canonical),
        "digest": _digest(raw),
        "raw_is_canonical_json_lf": True,
    }


def _repin(
    changed: dict[str, object], *, sync_nested: bool = True
) -> tuple[object, ...]:
    if sync_nested:
        _sync_nested(changed)
    observation = changed["route_observation"]
    document = observation["document"]
    action = document["action"]
    before = action["prerequisites"]
    nested_raw = base64.b64decode(observation["raw"]["base64"], validate=True)
    route_raw = {
        "bytes": len(nested_raw),
        "canonical_digest": _digest(canonical_json(document)),
        "digest": _digest(nested_raw),
    }
    harness = changed["harness"]["document"]
    digests = {
        "action": canonical_digest(action),
        "composition": canonical_digest(changed["composition"]),
        "composition_action": canonical_digest(changed["composition"]["action"]),
        "execution": canonical_digest(observation["execution"]),
        "gateway_binding": canonical_digest(observation["gateway_pid_binding"]),
        "harness": canonical_digest(harness),
        "host_config": canonical_digest(harness["host_config"]),
        "image_lineage": canonical_digest(harness["image_lineage"]),
        "route_observation": canonical_digest(observation),
        "source_artifacts": canonical_digest(changed["source_artifacts"]),
        "stack": canonical_digest(observation["stack_before"]),
    }
    stable = {
        "boundary": before["boundary_before"],
        "config_lock": before["config_lock_before"],
        "config_tree": before["config_tree_before"],
        "gateway": before["gateway_process_before"],
        "modules": before["modules_before"],
        "openclaw": before["openclaw_before"],
        "protected_roots": before["protected_root_trees_before"],
        "runtime_tree": before["runtime_tree_before"],
        "target": before["target_before"],
    }
    static = {name: canonical_digest(value) for name, value in stable.items()}
    artifact = changed["composition"]["action"]["artifacts"][
        "final_combined_v3_curator_restore"
    ]
    artifact_digests = {
        name: canonical_digest(value) for name, value in artifact.items()
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
    return (
        raw,
        evidence,
        route_raw,
        digests,
        static,
        artifact_digests,
        canonical_digest(subject.v3_contract._type_shape(changed)),
        canonical_digest(subject.v3_contract._type_shape(document)),
    )


class FinalCombinedV3CuratorRestoreTests(unittest.TestCase):
    def verify(self, raw: bytes | None = None) -> dict[str, object]:
        evidence = _EVIDENCE.read_bytes() if raw is None else raw
        temporary, store = _store(evidence)
        self.addCleanup(temporary.cleanup)
        return subject.verify_openclaw_final_combined_v3_curator_restore(
            evidence_cas=store
        )

    def repinned(
        self, changed: dict[str, object], *, sync_nested: bool = True
    ) -> dict[str, object]:
        (
            raw,
            evidence,
            route_raw,
            digests,
            static,
            artifact_digests,
            outer_shape,
            route_shape,
        ) = _repin(changed, sync_nested=sync_nested)
        temporary, store = _store(raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", evidence),
            patch.object(subject, "_ROUTE_RAW", route_raw),
            patch.object(subject, "_DIGESTS", digests),
            patch.object(subject, "_STATIC_DIGESTS", static),
            patch.object(subject, "_ARTIFACT_DIGESTS", artifact_digests),
            patch.object(subject, "_TYPE_SHAPE_DIGEST", outer_shape),
            patch.object(subject, "_ROUTE_TYPE_SHAPE_DIGEST", route_shape),
            patch.object(subject, "_verify_dependencies", return_value=None),
            patch.object(subject, "_verify_retained_evidence", return_value=raw),
        ):
            return subject.verify_openclaw_final_combined_v3_curator_restore(
                evidence_cas=store
            )

    def test_exact_one_route_pass_with_all_broad_eligibility_false(self) -> None:
        result = self.verify()
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})
        statuses = {
            route["id"]: route["status"] for route in result["profile"]["routes"]
        }
        self.assertEqual(statuses[subject._ROUTE], "PASS")
        self.assertEqual(list(statuses.values()).count("PASS"), 1)
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.contract._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(
            json.loads(_EVIDENCE.read_bytes())["decision"]["route_pass_count"], 0
        )
        self.assertIs(
            json.loads(_EVIDENCE.read_bytes())["route_observation"]["raw"][
                "raw_is_canonical_json_lf"
            ],
            True,
        )

    def test_outer_canonical_nested_raw_cas_source_and_dependency_drift_fail(
        self,
    ) -> None:
        original_raw = _EVIDENCE.read_bytes()
        original = json.loads(original_raw)

        pretty = (json.dumps(original, indent=2) + "\n").encode()
        identity = {
            **subject._EVIDENCE,
            "bytes": len(pretty),
            "digest": _digest(pretty),
        }
        temporary, store = _store(pretty)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", identity),
            patch.object(subject, "_verify_dependencies", return_value=None),
            patch.object(subject, "_verify_retained_evidence", return_value=pretty),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v3_curator_restore(
                evidence_cas=store
            )

        changed = deepcopy(original)
        document = changed["route_observation"]["document"]
        canonical = canonical_json(document)
        changed["route_observation"]["raw"] = {
            "base64": base64.b64encode(canonical + b"\n").decode(),
            "bytes": len(canonical) + 1,
            "canonical_digest": _digest(canonical),
            "digest": _digest(canonical + b"\n"),
            "raw_is_canonical_json_lf": False,
        }
        with self.assertRaisesRegex(AdmissionEvidenceError, "raw identity"):
            self.repinned(changed, sync_nested=False)

        temporary, store = _store(original_raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_verify_dependencies", return_value=None),
            patch.object(
                subject, "_verify_retained_evidence", return_value=original_raw + b"x"
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "CAS differs"),
        ):
            subject.verify_openclaw_final_combined_v3_curator_restore(
                evidence_cas=store
            )

        changed_source = {**subject._SOURCE, "commit": "0" * 40}
        with (
            patch.object(subject, "_SOURCE", changed_source),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.verify()

        dependencies = deepcopy(subject._DEPENDENCIES)
        dependencies["curator_semantics"]["digest"] = "sha256:" + "0" * 64
        with (
            patch.object(subject, "_DEPENDENCIES", dependencies),
            self.assertRaisesRegex(AdmissionEvidenceError, "dependency changed"),
        ):
            self.verify()

        with (
            patch.object(
                subject.semantics,
                "_verify_dependencies",
                side_effect=AdmissionEvidenceError("transitive dependency changed"),
            ),
            self.assertRaisesRegex(
                AdmissionEvidenceError, "transitive dependency changed"
            ),
        ):
            self.verify()

    def test_coordinated_hostile_repins_fail_closed(self) -> None:
        mutations = []

        changed = deepcopy(_ORIGINAL)
        changed["decision"]["phase3_exit_eligible"] = True
        mutations.append(changed)

        changed = deepcopy(_ORIGINAL)
        action = changed["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["configuration"]["file"]["mode"] = "600"
        mutations.append(changed)

        changed = deepcopy(_ORIGINAL)
        action = changed["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["probe"]["read_only"] = False
        mutations.append(changed)

        changed = deepcopy(_ORIGINAL)
        action = changed["route_observation"]["document"]["action"]
        for modules in (
            action["prerequisites"]["modules_before"],
            action["observations"]["modules_after"],
        ):
            modules["cli"]["observed"]["digest"] = "sha256:" + "0" * 64
        mutations.append(changed)

        for changed in mutations:
            with (
                self.subTest(digest=canonical_digest(changed)),
                self.assertRaises(AdmissionEvidenceError),
            ):
                self.repinned(changed)

    def test_semantics_lifecycle_and_chronology_fail_after_repins(self) -> None:
        changed = deepcopy(_ORIGINAL)
        after = changed["route_observation"]["document"]["action"]["observations"]
        after["gateway_restore"]["response"]["value"]["error"]["message"] = "repinned"
        with self.assertRaisesRegex(AdmissionEvidenceError, "denial changed"):
            self.repinned(changed)

        changed = deepcopy(_ORIGINAL)
        after = changed["route_observation"]["document"]["action"]["observations"]
        after["database_after_cli"]["data_version"] = 5
        with self.assertRaisesRegex(AdmissionEvidenceError, "data version changed"):
            self.repinned(changed)

        changed = deepcopy(_ORIGINAL)
        action = changed["route_observation"]["document"]["action"]
        earlier = action["commands"][0]["started_at"]
        action["commands"][1]["started_at"] = earlier
        action["prerequisites"]["system_info_before"]["command"]["started_at"] = earlier
        with self.assertRaisesRegex(
            AdmissionEvidenceError, "command causality changed"
        ):
            self.repinned(changed)


if __name__ == "__main__":
    unittest.main()
