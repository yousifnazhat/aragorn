from __future__ import annotations

import base64
import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from aragorn import (
    admission_protected_final_combined_v2_session_snapshot_consumer as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-session-"
    "snapshot-consumer-route-coverage-v1-2026-08-22.json"
)


def _store() -> tuple[TemporaryDirectory[str], CAS]:
    temporary = TemporaryDirectory()
    store = CAS(temporary.name)
    identities = (
        subject.parent.parent.parent._EVIDENCE,
        subject.parent.parent._EVIDENCE,
        subject.parent._EVIDENCE,
        subject._EVIDENCE,
        subject._MANIFEST,
        subject._ARCHIVE,
        subject._ACQUISITION,
    )
    for identity in identities:
        raw = (_ROOT / identity["path"]).read_bytes()
        store.put_expected(
            BytesIO(raw),
            expected_digest=identity["digest"],
            max_bytes=len(raw),
        )
    return temporary, store


class FinalCombinedV2SessionSnapshotConsumerTests(unittest.TestCase):
    def test_exact_four_route_passes_and_hostile_inputs_fail_closed(self) -> None:
        temporary, store = _store()
        self.addCleanup(temporary.cleanup)
        result = subject.verify_openclaw_final_combined_v2_session_snapshot_consumer(
            evidence_cas=store
        )
        statuses = {
            route["id"]: route["status"] for route in result["profile"]["routes"]
        }
        self.assertEqual(result["profile"]["counts"], {"PASS": 4, "NOT_TESTED": 17})
        self.assertEqual(
            {route for route, status in statuses.items() if status == "PASS"},
            subject._PASS_ROUTES,
        )
        self.assertEqual(
            [route["id"] for route in result["profile"]["routes"]],
            list(subject.parent.parent.parent.legacy.parent._ROUTES),
        )
        self.assertTrue(
            all(result["decision"][key] is False for key in subject._ELIGIBILITY_KEYS)
        )
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")

        evidence = json.loads((_ROOT / subject._EVIDENCE["path"]).read_bytes())
        acquisition = json.loads(
            (_ROOT / subject._ACQUISITION["path"]).read_bytes()
        )
        manifest, closure_files = subject._verify_archive(
            (_ROOT / subject._ARCHIVE["path"]).read_bytes(),
            (_ROOT / subject._MANIFEST["path"]).read_bytes(),
        )
        trusted_stack = json.loads(
            (_ROOT / subject.parent.parent._EVIDENCE["path"]).read_bytes()
        )["route_observation"]["stack_before"]

        for raw in (b'{"x":1,"x":2}\n', b'{"x":NaN}\n'):
            with self.assertRaises(AdmissionEvidenceError):
                subject._decode_route_raw(
                    {
                        "base64": base64.b64encode(raw).decode(),
                        "bytes": len(raw),
                        "canonical_digest": subject._digest(raw.rstrip(b"\n")),
                        "digest": subject._digest(raw),
                        "raw_is_canonical_json_lf": False,
                    }
                )

        changed = deepcopy(evidence)
        changed["route_observation"]["stack_before"]["enablement"][
            "aragorn-agent-gateway.service"
        ] = "disabled"
        with self.assertRaises(AdmissionEvidenceError):
            subject._verify_evidence(changed, trusted_stack=trusted_stack)

        changed = deepcopy(evidence)
        changed["source_artifacts"]["collector"]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(AdmissionEvidenceError):
            subject._verify_evidence(changed, trusted_stack=trusted_stack)

        for mutate in (
            lambda value: value.__setitem__("authority", "FULL_EDR_RELEASE_AUTHORITY"),
            lambda value: value["composition"]["action"]["harness"][
                "document"
            ].__setitem__("image_id", "sha256:" + "0" * 64),
        ):
            changed = deepcopy(evidence)
            mutate(changed)
            with self.assertRaises(AdmissionEvidenceError):
                subject._verify_evidence(changed, trusted_stack=trusted_stack)

        document = deepcopy(evidence["route_observation"]["document"])
        document["action"]["observations"]["injected_turn"]["wait"]["response"][
            "value"
        ]["error"] = "provider succeeded"
        changed_action_digest = subject._canonical_digest(document["action"])
        with (
            patch.object(subject, "_ACTION_DIGEST", changed_action_digest),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject._verify_route_document(document, closure_files)

        document = deepcopy(evidence["route_observation"]["document"])
        final = document["action"]["observations"]["final_snapshot"]
        final["blob"]["prompt_ref"]["hash"] = (
            document["action"]["observations"]["mutated_snapshot"]["blob"][
                "prompt_ref"
            ]["hash"]
        )
        changed_action_digest = subject._canonical_digest(document["action"])
        with (
            patch.object(subject, "_ACTION_DIGEST", changed_action_digest),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject._verify_route_document(document, closure_files)

        changed_manifest = deepcopy(manifest)
        changed_manifest["entries"][0]["sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(AdmissionEvidenceError):
            subject._verify_archive(
                (_ROOT / subject._ARCHIVE["path"]).read_bytes(),
                canonical_json(changed_manifest) + b"\n",
            )

        changed_files = dict(closure_files)
        bridge_path = subject._CLOSURE_PATHS[3]
        changed_files[bridge_path] = changed_files[bridge_path].replace(
            b"skillsSnapshot: params.skillsSnapshot,",
            b"skillsSnapshot: params.changedSnapshot,",
            1,
        )
        replay = evidence["route_observation"]["document"]["action"]["observations"][
            "compiled_route_replay"
        ]
        with self.assertRaises(AdmissionEvidenceError):
            subject._verify_source_bridges(replay["handoff_statements"], changed_files)

        changed_acquisition = deepcopy(acquisition)
        changed_acquisition["acquisition"]["module_files"][0]["inode"] += 1
        with self.assertRaises(AdmissionEvidenceError):
            subject._verify_acquisition(changed_acquisition, evidence, manifest)

        for mutate in (
            lambda value: value.__setitem__("authority", "FULL_EDR_RELEASE_AUTHORITY"),
            lambda value: value["acquisition"]["acquisition_image"].__setitem__(
                "reference", "evil:latest"
            ),
            lambda value: value["acquisition"]["runtime_volume"].__setitem__(
                "created_at", "2099-01-01T00:00:00Z"
            ),
        ):
            changed_acquisition = deepcopy(acquisition)
            mutate(changed_acquisition)
            with self.assertRaises(AdmissionEvidenceError):
                subject._verify_acquisition(changed_acquisition, evidence, manifest)

        signed = subject._read_signed_sources()
        changed_signed = dict(signed)
        changed_signed["archive"] = signed["archive"][:-1] + b"0"
        with (
            patch.object(subject, "_read_signed_sources", return_value=changed_signed),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_combined_v2_session_snapshot_consumer(
                evidence_cas=store
            )
