from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn.admission_decision import AdmissionDecisionError, evaluate_admission
from aragorn.admission_retained import evaluate_retained_admission
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_VECTOR_PATH = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "deterministic-authority-vectors-v1.json"
)
_VECTOR_RAW = _VECTOR_PATH.read_bytes()
_VECTOR_SET = json.loads(_VECTOR_RAW)
_VECTORS = {
    item["request"]["case_id"]: item
    for item in _VECTOR_SET["vectors"]
}


def _request(case_id: str) -> dict[str, object]:
    return deepcopy(_VECTORS[case_id]["request"])


def _run(raw: bytes, seed: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "aragorn.admission_decision"],
        input=raw,
        capture_output=True,
        cwd=_ROOT,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": seed,
            "PYTHONPATH": str(_ROOT / "src"),
            "TZ": "UTC",
        },
        check=False,
        timeout=5,
    )


def _put(cas: CAS, raw: bytes) -> str:
    return cas.put(BytesIO(raw), max_bytes=len(raw))


class AdmissionDecisionTests(unittest.TestCase):
    def test_vector_set_is_canonical_and_complete(self) -> None:
        self.assertEqual(_VECTOR_RAW, canonical_json(_VECTOR_SET) + b"\n")
        self.assertEqual(
            list(_VECTORS),
            ["allow", "deny", "error", "review"],
        )

    def test_all_authority_exits_replay_byte_identically(self) -> None:
        for case_id, vector in _VECTORS.items():
            with self.subTest(case_id):
                raw = canonical_json(_request(case_id)) + b"\n"
                outputs = []
                for seed in ("1", "2", "3"):
                    result = _run(raw, seed)
                    self.assertEqual(
                        result.returncode,
                        0,
                        result.stderr.decode(),
                    )
                    self.assertEqual(result.stderr, b"")
                    outputs.append(result.stdout)
                self.assertEqual(len(set(outputs)), 1)
                decision = json.loads(outputs[0])
                self.assertEqual(decision["verdict"], vector["expected"]["verdict"])
                self.assertEqual(
                    decision["reason_codes"],
                    vector["expected"]["reason_codes"],
                )
                self.assertEqual(decision["case_id"], case_id)
                self.assertEqual(outputs[0], canonical_json(decision) + b"\n")

    def test_runtime_binding_changes_decision_identity_not_verdict(self) -> None:
        first = evaluate_admission(_request("allow"))
        changed = _request("allow")
        changed["target_runtime"]["adapter"]["configuration_digest"] = (
            "sha256:" + "d" * 64
        )
        second = evaluate_admission(changed)

        self.assertEqual(first["verdict"], second["verdict"])
        self.assertNotEqual(first["request_digest"], second["request_digest"])
        self.assertNotEqual(
            first["target_runtime_digest"],
            second["target_runtime_digest"],
        )

    def test_evidence_for_another_manifest_is_rejected(self) -> None:
        changed = _request("allow")
        changed["evidence"]["analyzer_results"][0]["subject_digest"] = (
            "sha256:" + "0" * 64
        )

        with self.assertRaises(AdmissionDecisionError):
            evaluate_admission(changed)

    def test_incomplete_closure_fails_closed_deterministically(self) -> None:
        changed = deepcopy(_request("allow"))
        changed["manifest"]["closure"] = {
            "scope": "artifact_graph",
            "status": "incomplete",
            "unresolved": ["MISSING:payload"],
        }

        decision = evaluate_admission(changed)
        self.assertEqual(decision["verdict"], "ERROR")
        self.assertEqual(
            decision["reason_codes"],
            ["ARTIFACT_CLOSURE_INCOMPLETE"],
        )

    def test_retained_admission_binds_source_and_evidence_without_authority(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            cas = CAS(temporary)
            request = _request("allow")
            content = b"retained conformance fixture\n"
            content_digest = _put(cas, content)
            files = [
                {
                    "path": "SKILL.md",
                    "size": len(content),
                    "digest": content_digest,
                    "executable": False,
                }
            ]
            tree_digest = canonical_digest(files)
            source_path = "/profile/state/skills/aragorn-admitted"
            request["manifest"] = {
                "schema": "aragorn/admission-manifest/v1",
                "source": {
                    "kind": "contained_conformance_fixture",
                    "path": source_path,
                },
                "tree_digest": tree_digest,
                "files": files,
                "closure": {
                    "scope": "artifact_graph",
                    "status": "complete",
                    "unresolved": [],
                },
            }
            for result in request["evidence"]["analyzer_results"]:
                result["subject_digest"] = tree_digest
            request["evidence"]["source_evidence_digests"] = sorted(
                [_put(cas, b"evidence-a"), _put(cas, b"evidence-b")]
            )
            request["evidence"]["source_receipt_digest"] = _put(
                cas,
                b"opaque-source-receipt",
            )
            retained = {
                "schema": "aragorn/manifest/v1",
                "source": {"kind": "local", "path": source_path},
                "tree_digest": tree_digest,
                "files": files,
                "closure": {"scope": "source_tree", "status": "complete"},
            }
            manifest_digest = _put(cas, canonical_json(retained))
            retained_cas = CAS(temporary, read_only=True)

            decision = evaluate_retained_admission(
                request,
                cas=retained_cas,
                source_manifest_digest=manifest_digest,
            )
            self.assertEqual(decision["verdict"], "ALLOW")
            self.assertEqual(
                decision["authority"],
                "POLICY_DECISION_ONLY_NOT_INSTALLER_AUTHORITY",
            )

            missing_evidence = deepcopy(request)
            missing_evidence["evidence"]["source_receipt_digest"] = "sha256:" + "0" * 64

            other_source = deepcopy(retained)
            other_source["source"]["path"] = "/different/source"
            other_source_digest = _put(cas, canonical_json(other_source))

            other_content = b"different retained bytes\n"
            other_files = [
                {
                    "path": "SKILL.md",
                    "size": len(other_content),
                    "digest": _put(cas, other_content),
                    "executable": False,
                }
            ]
            other_manifest = {
                **retained,
                "tree_digest": canonical_digest(other_files),
                "files": other_files,
            }
            other_manifest_digest = _put(cas, canonical_json(other_manifest))
            for label, candidate, retained_digest, message in (
                (
                    "missing evidence",
                    missing_evidence,
                    manifest_digest,
                    "cannot verify retained admission inputs",
                ),
                (
                    "source identity",
                    request,
                    other_source_digest,
                    "retained source identity",
                ),
                (
                    "source bytes",
                    request,
                    other_manifest_digest,
                    "retained source bytes",
                ),
            ):
                with self.subTest(label):
                    with self.assertRaisesRegex(AdmissionDecisionError, message):
                        evaluate_retained_admission(
                            candidate,
                            cas=retained_cas,
                            source_manifest_digest=retained_digest,
                        )

    def test_cli_rejects_noncanonical_and_duplicate_json(self) -> None:
        noncanonical = json.dumps(_request("allow")).encode() + b"\n"
        duplicate = b'{"schema":"a","schema":"b"}\n'
        unknown_severity = _request("allow")
        unknown_severity["policy"]["review_severities"] = ["unknown"]
        recursive = b"[" * 1_100 + b"0" + b"]" * 1_100

        for label, raw in (
            ("noncanonical", noncanonical),
            ("duplicate", duplicate),
            ("unknown-severity", canonical_json(unknown_severity) + b"\n"),
            ("recursive", recursive),
        ):
            with self.subTest(label):
                result = _run(raw, "1")
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr)


if __name__ == "__main__":
    unittest.main()
