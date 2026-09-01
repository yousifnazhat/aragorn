from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn import (
    admission_openclaw_final_v3_workshop_invalidation_subfixture as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from scripts import (
    materialize_openclaw_final_v3_workshop_invalidation_probe as materializer,
)

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / (
    "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
    "workshop-invalidation-systemd-p3-final-2026-09-01.json"
)


def _captured_document() -> dict[str, object]:
    outer = json.loads(_EVIDENCE.read_bytes())
    document = outer["route_observation"]["document"]
    assert type(document) is dict
    return document


class WorkshopInvalidationMaterializerTests(unittest.TestCase):
    def test_exact_dedicated_read_only_bundle_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            manifest = materializer.materialize_openclaw_final_v3_workshop_invalidation(
                first
            )
            repeated = materializer.materialize_openclaw_final_v3_workshop_invalidation(
                second
            )
            self.assertEqual(manifest, repeated)
            self.assertEqual(manifest["case_id"], subject._ROUTE)
            self.assertEqual(
                manifest["files"],
                [
                    {
                        "bytes": 84,
                        "digest": subject._PROPOSAL_DIGEST,
                        "name": "PROPOSAL.md",
                        "role": "fixture",
                    },
                    {
                        "bytes": 48_609,
                        "digest": subject._PROBE_DIGEST,
                        "name": "protected-workshop-invalidation-v3-probe.mjs",
                        "role": "probe",
                    },
                ],
            )
            self.assertEqual(
                stat.S_IMODE(first.stat().st_mode),
                0o555,
            )
            for item in manifest["files"]:
                path = first / item["name"]
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
                self.assertEqual(path.read_bytes(), (second / item["name"]).read_bytes())

            probe = (first / materializer._PROBE).read_text(encoding="utf-8")
            self.assertIn(
                'const ROUTE_IDS = Object.freeze([\n  "ADM-02/reload/workshop-invalidation",\n]);',
                probe,
            )
            self.assertIn(
                '"ADM-02/reload/workshop-invalidation": "workshop-invalidation"',
                probe,
            )
            self.assertIn(subject._SCHEMA, probe)
            self.assertIn(
                '"/route-input/workshop-invalidation/PROPOSAL.md"', probe
            )
            self.assertNotIn("WORKSHOP_INVALIDATION_NOT_REACHED", probe)
            self.assertNotIn('"workshop-protected-apply"', probe)

    def test_materializer_fails_closed_on_reuse_or_parent_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary) / "existing"
            existing.mkdir()
            with self.assertRaises(
                materializer.WorkshopInvalidationMaterializationError
            ):
                materializer.materialize_openclaw_final_v3_workshop_invalidation(
                    existing
                )
            with (
                patch.object(materializer, "_V2_MATERIALIZER_BYTES", 1),
                self.assertRaises(
                    materializer.WorkshopInvalidationMaterializationError
                ),
            ):
                materializer.materialize_openclaw_final_v3_workshop_invalidation(
                    Path(temporary) / "rejected"
                )

    def test_capture_wrapper_is_a_pinned_route_only_derivative(self) -> None:
        recipe = _ROOT / (
            "scripts/capture_runtime_action_worker_final_combined_v3_"
            "workshop_invalidation_systemd.sh"
        )
        temporary_root = Path(tempfile.gettempdir())
        before = set(
            temporary_root.glob("aragorn-v3-workshop-invalidation-capture.*")
        )
        result = subprocess.run(
            ["sh", str(recipe)],
            cwd=_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        after = set(
            temporary_root.glob("aragorn-v3-workshop-invalidation-capture.*")
        )
        self.assertEqual(result.returncode, 64)
        self.assertEqual(
            result.stderr,
            "usage: capture_runtime_action_worker_final_combined_v3_"
            "workshop_invalidation_systemd.sh ABSENT_OUTPUT_PATH\n",
        )
        self.assertEqual(before, after)
        raw = recipe.read_text(encoding="utf-8")
        for binding in (
            "a4f03cf2788f097d556be2b6ef93d758d6b12622a292a530784599d20b00ae96",
            "materialize_openclaw_final_v3_workshop_invalidation_probe.py",
            "workshop-proposal-apply",
            "workshop-invalidation",
            "ADM-02/reload/workshop-invalidation",
            (
                "NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_"
                "RELEASE_AUTHORITY"
            ),
        ):
            self.assertIn(binding, raw)

        dockerfile = _ROOT / (
            "benchmark/runtime-action-worker-final-combined-v3-workshop-"
            "invalidation-systemd/Dockerfile"
        )
        docker = dockerfile.read_text(encoding="utf-8")
        for binding in (
            "sha256:601a0b582406193cf031b0f5512b564464452a60a00bc97098266182ccd13ff7",
            "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f",
            materializer._PROBE_DIGEST.removeprefix("sha256:"),
            "find /route-input -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +",
        ):
            self.assertIn(binding, docker)

        collector = (_ROOT / "scripts" / (
            "runtime_action_worker_final_combined_v3_"
            "workshop_invalidation_systemd_probe.py"
        )).read_text(encoding="utf-8")
        self.assertIn(
            'normalized["schema"] = _INHERITED_HARNESS_SCHEMA', collector
        )
        self.assertNotIn(
            'normalized["schema"] = proposal._HARNESS_SCHEMA', collector
        )
        self.assertIn('command.extend(["--route-id", _ROUTE])', collector)


class WorkshopInvalidationSemanticCompatibilityTests(unittest.TestCase):
    def verify(self, document: dict[str, object] | None = None) -> dict[str, object]:
        return subject.verify_openclaw_final_v3_workshop_invalidation_semantic_compatibility(
            _captured_document() if document is None else document
        )

    def test_retained_raw_capture_is_observation_not_pass(self) -> None:
        raw = _EVIDENCE.read_bytes()
        self.assertEqual(len(raw), 581_618)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "35c48bd6552d15682b8c500f540212d1e1deab8533edbfcc0c2188476ffff3c6",
        )
        outer = json.loads(raw)
        self.assertNotIn("failure", outer)
        self.assertEqual(outer["route_id"], subject._ROUTE)
        self.assertEqual(
            outer["harness"]["document"]["source_commit"],
            "276d5f3a6a33f4cf5ddfccaa800486d73682358a",
        )
        self.assertEqual(
            outer["decision"]["route_observation_status"], "OBSERVED"
        )
        self.assertEqual(outer["decision"]["route_pass_count"], 0)
        self.assertTrue(
            all(
                outer["decision"][key] is False
                for key in subject._ELIGIBILITY_KEYS
            )
        )

    def test_exact_semantic_compatibility_preserves_claim_ceiling(self) -> None:
        result = self.verify()
        self.assertEqual(result, self.verify())
        self.assertNotIn("outcome", result["decision"])
        self.assertEqual(
            result["decision"]["status"],
            "WORKSHOP_INVALIDATION_SEMANTIC_COMPATIBILITY_VERIFIED_"
            "NOT_OBSERVED_OR_QUALIFIED",
        )
        self.assertNotIn("PASS", result["decision"].values())
        self.assertNotIn("OBSERVED", result["decision"].values())
        self.assertFalse(
            result["route_semantics"]["native_independent_route_execution_verified"]
        )
        self.assertFalse(
            result["route_semantics"]["shared_capture_independence_verified"]
        )
        self.assertFalse(result["route_semantics"]["pass_authority"])
        self.assertTrue(
            all(result["decision"][key] is False for key in subject._ELIGIBILITY_KEYS)
        )
        for limitation in (
            "NO_DEDICATED_CAPTURE_OBSERVATION_BOUND",
            "CAPTURE_FRESHNESS_NOT_VERIFIED",
            "CAPTURE_DESTRUCTION_NOT_VERIFIED",
            "CAPTURE_INDEPENDENCE_NOT_VERIFIED",
        ):
            self.assertIn(limitation, result["limitations"])

    def test_raw_relations_not_summary_booleans_are_authority(self) -> None:
        document = _captured_document()
        after = document["actions"][0]["observations"]
        for key in (
            "catalog_after_apply_excludes_workshop",
            "catalog_after_apply_matches_initial",
            "final_catalog_matches_initial",
            "final_same_session_catalog_exact",
            "immediate_post_apply_same_session",
            "immediate_post_apply_store_unchanged",
        ):
            after[key] = not after[key]
        self.verify(document)

    def test_route_transition_and_fresh_identity_tampering_fail_closed(self) -> None:
        mutations = []

        changed = _captured_document()
        changed["routes"][0]["id"] = "ADM-02/update/workshop-proposal-apply"
        mutations.append(changed)

        changed = _captured_document()
        after = changed["actions"][0]["observations"]
        after["final_snapshot"]["entry"]["session_id"] = (
            "00000000-0000-4000-8000-000000000000"
        )
        mutations.append(changed)

        changed = _captured_document()
        after = changed["actions"][0]["observations"]
        after["final_snapshot"]["entry"]["snapshot_version"] = after[
            "initial_snapshot"
        ]["entry"]["snapshot_version"]
        mutations.append(changed)

        changed = _captured_document()
        after = changed["actions"][0]["observations"]
        after["final_snapshot"]["file"] = deepcopy(
            after["initial_snapshot"]["file"]
        )
        mutations.append(changed)

        changed = _captured_document()
        changed["actions"][0]["commands"][7:9] = reversed(
            changed["actions"][0]["commands"][7:9]
        )
        mutations.append(changed)

        for changed in mutations:
            with self.assertRaises(AdmissionEvidenceError):
                self.verify(changed)


if __name__ == "__main__":
    unittest.main()
