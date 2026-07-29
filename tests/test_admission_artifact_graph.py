from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from aragorn.acquire import ingest_local
from aragorn.admission_artifact_graph import (
    AdmissionArtifactGraphError,
    retain_admission_artifact_graph,
    retain_github_admission_artifact_graph_v2,
    verify_admission_artifact_graph,
    verify_github_admission_artifact_graph_v2,
)
from aragorn.analyze import run_analyzer
from aragorn.analyzer_receipt import retain_analyzer_run
from aragorn.artifact_closure import canonical_json
from aragorn.benchmark_handoff_v2 import build_handoff_manifest
from aragorn.cas import CAS
from aragorn.decision_receipt import (
    DecisionReceiptError,
    retain_decision_v3,
    verify_decision_v3,
)
from aragorn.github_quarantine_receipt import (
    DARWIN_CONTAINMENT_PROFILE,
    LINUX_CONTAINMENT_PROFILE,
    github_gateway_profile_digest,
    retain_github_quarantine_receipt,
)
from aragorn.github_source_proof import retain_github_source_proof
from aragorn.policy import Policy, evaluate_policy

VERIFIER_DIGEST = "sha256:" + "1" * 64
PYTHON_DIGEST = "sha256:" + "3" * 64
PACKAGE_DIGEST = "sha256:" + "4" * 64


def _retain_manifest(cas: CAS, source: Path) -> str:
    raw = canonical_json(ingest_local(source, cas))
    return cas.put(BytesIO(raw), max_bytes=len(raw))


def _git_oid(object_type: str, payload: bytes) -> str:
    header = f"{object_type} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _tree_entry(mode: bytes, name: bytes, oid: str) -> bytes:
    return mode + b" " + name + b"\0" + bytes.fromhex(oid)


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _retain_github_quarantine(
    cas: CAS,
    content: bytes,
    *,
    containment_profile: str = LINUX_CONTAINMENT_PROFILE,
    file_name: str = "SKILL.md",
) -> tuple[str, str, str, str]:
    blob_oid = _git_oid("blob", content)
    skill_tree_payload = _tree_entry(
        b"100644",
        file_name.encode("utf-8"),
        blob_oid,
    )
    skill_tree_oid = _git_oid("tree", skill_tree_payload)
    root_tree_payload = _tree_entry(b"40000", b"demo", skill_tree_oid)
    root_tree_oid = _git_oid("tree", root_tree_payload)
    commit_payload = (
        f"tree {root_tree_oid}\n".encode("ascii")
        + b"author Fixture <fixture@example.test> 1 +0000\n"
        + b"committer Fixture <fixture@example.test> 1 +0000\n\nfixture\n"
    )
    commit_oid = _git_oid("commit", commit_payload)
    blob_digest = cas.put(BytesIO(content), max_bytes=len(content))
    tree_files = [
        {
            "path": file_name,
            "size": len(content),
            "digest": blob_digest,
            "executable": False,
        }
    ]
    manifest = {
        "schema": "aragorn/github-manifest/v1",
        "source": {
            "kind": "github_commit",
            "host": "github.com",
            "owner": "example",
            "repository": "skills",
            "commit": commit_oid,
            "repository_hash_algorithm": "sha1",
            "commit_tree": root_tree_oid,
            "skill_path": "demo",
            "skill_tree": skill_tree_oid,
            "api_version": "2026-03-10",
        },
        "tree_digest": _sha256(canonical_json(tree_files)),
        "files": [
            {
                **tree_files[0],
                "git_blob_sha1": blob_oid,
            }
        ],
        "closure": {"scope": "source_tree", "status": "complete"},
    }
    raw_manifest = canonical_json(manifest)
    manifest_digest = cas.put(BytesIO(raw_manifest), max_bytes=len(raw_manifest))
    proof_digest = retain_github_source_proof(
        cas,
        manifest,
        {
            ("commit", commit_oid): commit_payload,
            ("tree", root_tree_oid): root_tree_payload,
            ("tree", skill_tree_oid): skill_tree_payload,
        },
    )
    proof_raw = cas.read(proof_digest)
    source_closure = {
        manifest_digest: len(raw_manifest),
        blob_digest: len(content),
        proof_digest: len(proof_raw),
        _sha256(commit_payload): len(commit_payload),
        _sha256(root_tree_payload): len(root_tree_payload),
        _sha256(skill_tree_payload): len(skill_tree_payload),
    }
    handoff = build_handoff_manifest(
        kind="github_source",
        root_digest=manifest_digest,
        blobs=source_closure,
    )
    raw_handoff = canonical_json(handoff)
    handoff_digest = cas.put(BytesIO(raw_handoff), max_bytes=len(raw_handoff))
    request = {
        "schema": "aragorn/github-gateway-request/v1",
        "owner": "example",
        "repository": "skills",
        "commit": commit_oid,
        "skill_path": "demo",
    }
    receipt_digest = retain_github_quarantine_receipt(
        cas,
        request=request,
        manifest_digest=manifest_digest,
        source_proof_digest=proof_digest,
        handoff_manifest_digest=handoff_digest,
        containment_profile=containment_profile,
        python_executable_digest=PYTHON_DIGEST,
        gateway_package_tree_digest=PACKAGE_DIGEST,
    )
    gateway_profile_digest = github_gateway_profile_digest(
        containment_profile=containment_profile,
        python_executable_digest=PYTHON_DIGEST,
        gateway_package_tree_digest=PACKAGE_DIGEST,
    )
    return (
        manifest_digest,
        proof_digest,
        receipt_digest,
        gateway_profile_digest,
    )


class AdmissionArtifactGraphTests(unittest.TestCase):
    def test_self_contained_markdown_closes_and_replays(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            (source / "docs").mkdir(parents=True)
            (source / "SKILL.md").write_text(
                "[guide](docs/guide.md)\n",
                encoding="utf-8",
            )
            (source / "docs" / "guide.md").write_text("safe\n", encoding="utf-8")
            cas = CAS(root / "state")
            manifest_digest = _retain_manifest(cas, source)

            graph_digest = retain_admission_artifact_graph(
                cas,
                manifest_digest,
                verifier_implementation_digest=VERIFIER_DIGEST,
            )
            graph = verify_admission_artifact_graph(
                CAS(root / "state", read_only=True),
                graph_digest,
                expected_manifest_digest=manifest_digest,
                expected_verifier_digest=VERIFIER_DIGEST,
                expected_quarantine_receipt_digest=None,
                expected_gateway_profile_digest=None,
            )

            self.assertEqual(
                graph["closure"],
                {
                    "scope": "artifact_graph",
                    "profile": "self-contained-local-markdown/v1",
                    "status": "complete",
                    "unresolved": [],
                },
            )
            self.assertEqual(
                graph["edges"][0]["target"],
                {
                    "path": "docs/guide.md",
                    "digest": {
                        item["path"]: item["digest"] for item in graph["artifacts"]
                    }["docs/guide.md"],
                },
            )
            self.assertEqual(
                evaluate_policy(Policy(), closure=graph["closure"], results=()).verdict,
                "ALLOW",
            )
            with self.assertRaisesRegex(
                AdmissionArtifactGraphError,
                "verifier identity is untrusted",
            ):
                verify_admission_artifact_graph(
                    CAS(root / "state", read_only=True),
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_verifier_digest="sha256:" + "0" * 64,
                )
            with self.assertRaisesRegex(
                AdmissionArtifactGraphError,
                "does not accept GitHub trust identities",
            ):
                verify_admission_artifact_graph(
                    CAS(root / "state", read_only=True),
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_verifier_digest=VERIFIER_DIGEST,
                    expected_quarantine_receipt_digest="sha256:" + "2" * 64,
                    expected_gateway_profile_digest="sha256:" + "3" * 64,
                )

            changed = deepcopy(graph)
            changed["edges"][0]["target"]["digest"] = "sha256:" + "0" * 64
            raw = canonical_json(changed)
            changed_digest = cas.put(BytesIO(raw), max_bytes=len(raw))
            with self.assertRaisesRegex(
                AdmissionArtifactGraphError,
                "does not match retained source",
            ):
                verify_admission_artifact_graph(
                    CAS(root / "state", read_only=True),
                    changed_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_verifier_digest=VERIFIER_DIGEST,
                )

    def test_scripts_and_external_acquisition_remain_incomplete(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text(
                "curl https://example.com/tool.sh\n",
                encoding="utf-8",
            )
            script = source / "run.sh"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            script.chmod(0o755)
            cas = CAS(root / "state")
            manifest_digest = _retain_manifest(cas, source)

            graph = verify_admission_artifact_graph(
                CAS(root / "state", read_only=True),
                retain_admission_artifact_graph(
                    cas,
                    manifest_digest,
                    verifier_implementation_digest=VERIFIER_DIGEST,
                ),
                expected_manifest_digest=manifest_digest,
                expected_verifier_digest=VERIFIER_DIGEST,
            )

            self.assertEqual(graph["closure"]["status"], "incomplete")
            self.assertTrue(
                any(
                    item.startswith("UNSUPPORTED_ADMISSION_ARTIFACT:run.sh:")
                    for item in graph["closure"]["unresolved"]
                )
            )
            self.assertEqual(
                evaluate_policy(Policy(), closure=graph["closure"], results=()).verdict,
                "ERROR",
            )

    def test_unmodeled_markdown_and_package_acquisition_fail_closed(self) -> None:
        cases = {
            "reference definition": "[guide][g]\n[g]: missing.md\n",
            "HTML reference": '<a href="missing.md">guide</a>\n',
            "package acquisition": "pip install attacker-package\n",
        }
        for label, content in cases.items():
            with self.subTest(label=label), TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "skill"
                source.mkdir()
                (source / "SKILL.md").write_text(content, encoding="utf-8")
                cas = CAS(root / "state")
                manifest_digest = _retain_manifest(cas, source)

                graph = verify_admission_artifact_graph(
                    CAS(root / "state", read_only=True),
                    retain_admission_artifact_graph(
                        cas,
                        manifest_digest,
                        verifier_implementation_digest=VERIFIER_DIGEST,
                    ),
                    expected_manifest_digest=manifest_digest,
                    expected_verifier_digest=VERIFIER_DIGEST,
                )

                self.assertEqual(graph["closure"]["status"], "incomplete")
                self.assertTrue(graph["closure"]["unresolved"])

    @mock.patch(
        "aragorn.admission_artifact_graph._REQUIRED_BROKER_UID",
        os.geteuid(),
    )
    @mock.patch(
        "aragorn.github_quarantine_receipt.sys.platform",
        "linux",
    )
    def test_linux_github_receipt_closes_and_generic_replay_dispatches(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            cas = CAS(root / "state")
            (
                manifest_digest,
                proof_digest,
                receipt_digest,
                gateway_profile_digest,
            ) = _retain_github_quarantine(cas, b"# inert skill\n")

            graph_digest = retain_github_admission_artifact_graph_v2(
                cas,
                manifest_digest,
                expected_quarantine_receipt_digest=receipt_digest,
                expected_gateway_profile_digest=gateway_profile_digest,
                verifier_implementation_digest=VERIFIER_DIGEST,
            )
            graph = verify_github_admission_artifact_graph_v2(
                CAS(root / "state", read_only=True),
                graph_digest,
                expected_manifest_digest=manifest_digest,
                expected_quarantine_receipt_digest=receipt_digest,
                expected_gateway_profile_digest=gateway_profile_digest,
                expected_verifier_digest=VERIFIER_DIGEST,
            )

            self.assertEqual(
                graph["closure"],
                {
                    "scope": "artifact_graph",
                    "profile": "self-contained-github-markdown/v1",
                    "status": "complete",
                    "unresolved": [],
                },
            )
            self.assertEqual(graph["source_proof_digest"], proof_digest)
            self.assertEqual(graph["quarantine_receipt_digest"], receipt_digest)
            self.assertEqual(
                graph["gateway_profile_digest"],
                gateway_profile_digest,
            )
            with self.assertRaisesRegex(
                AdmissionArtifactGraphError,
                "caller-held quarantine receipt and gateway profile",
            ):
                verify_admission_artifact_graph(
                    CAS(root / "state", read_only=True),
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_verifier_digest=VERIFIER_DIGEST,
                )
            self.assertEqual(
                verify_admission_artifact_graph(
                    CAS(root / "state", read_only=True),
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_verifier_digest=VERIFIER_DIGEST,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile_digest,
                ),
                graph,
            )

            policy = {
                "schema": "aragorn/policy/v2",
                "id": "github-test",
                "version": 1,
                "required_analyzers": ["test-scanner"],
                "hard_deny_reason_codes": [],
                "review_severities": ["critical", "high", "medium"],
                "allowed_artifact_graph_profiles": [
                    "self-contained-github-markdown/v1"
                ],
            }
            raw_policy = canonical_json(policy)
            policy_digest = cas.put(
                BytesIO(raw_policy),
                max_bytes=len(raw_policy),
            )
            executable = Path(sys.executable).resolve(strict=True)
            with executable.open("rb") as stream:
                executable_digest = cas.put(
                    stream,
                    max_bytes=128 * 1024 * 1024,
                )
            script = "import json,sys;json.load(sys.stdin)"
            configuration = {
                "name": "test-scanner",
                "version": "1",
                "argv": [str(executable), "-c", script],
                "operator_argv0": str(executable),
                "executable_digest": executable_digest,
            }
            raw_configuration = canonical_json(configuration)
            config_digest = cas.put(
                BytesIO(raw_configuration),
                max_bytes=len(raw_configuration),
            )
            analyzer_result = run_analyzer(
                (str(executable), "-c", script),
                workspace=root,
                name="test-scanner",
                version="1",
                config_digest=config_digest,
                executable_digest=executable_digest,
                subject_digest=graph["tree_digest"],
                configuration_bytes=raw_configuration,
                timeout_seconds=2,
                output_limit_bytes=4096,
            )
            analyzer_receipt_digest = retain_analyzer_run(
                cas,
                analyzer_result,
                verifier_implementation_digest=VERIFIER_DIGEST,
            )
            decision_digest = retain_decision_v3(
                cas,
                manifest_digest=manifest_digest,
                artifact_graph_digest=graph_digest,
                policy_digest=policy_digest,
                analyzer_run_receipt_digests=[analyzer_receipt_digest],
                analyzer_verifier_digest=VERIFIER_DIGEST,
                artifact_graph_verifier_digest=VERIFIER_DIGEST,
                expected_quarantine_receipt_digest=receipt_digest,
                expected_gateway_profile_digest=gateway_profile_digest,
            )
            decision = verify_decision_v3(
                CAS(root / "state", read_only=True),
                decision_digest,
                expected_manifest_digest=manifest_digest,
                expected_artifact_graph_digest=graph_digest,
                expected_policy_digest=policy_digest,
                expected_analyzer_run_receipt_digests=[analyzer_receipt_digest],
                expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                expected_artifact_graph_verifier_digest=VERIFIER_DIGEST,
                expected_quarantine_receipt_digest=receipt_digest,
                expected_gateway_profile_digest=gateway_profile_digest,
            )
            self.assertEqual(decision["verdict"], "ALLOW")
            self.assertEqual(decision["artifact_graph_digest"], graph_digest)

            retained_receipt = json.loads(cas.read(receipt_digest).decode("ascii"))
            with self.assertRaisesRegex(
                ValueError,
                "cannot retain GitHub quarantine receipt",
            ):
                retain_github_quarantine_receipt(
                    cas,
                    request=retained_receipt["request"],
                    manifest_digest=manifest_digest,
                    source_proof_digest=proof_digest,
                    handoff_manifest_digest="sha256:" + "2" * 64,
                    containment_profile=LINUX_CONTAINMENT_PROFILE,
                    python_executable_digest=PYTHON_DIGEST,
                    gateway_package_tree_digest=PACKAGE_DIGEST,
                )
            another_receipt = retain_github_quarantine_receipt(
                cas,
                request=retained_receipt["request"],
                manifest_digest=manifest_digest,
                source_proof_digest=proof_digest,
                handoff_manifest_digest=retained_receipt["handoff_manifest_digest"],
                containment_profile=LINUX_CONTAINMENT_PROFILE,
                python_executable_digest=PYTHON_DIGEST,
                gateway_package_tree_digest=PACKAGE_DIGEST,
            )
            with self.assertRaisesRegex(
                AdmissionArtifactGraphError,
                "bound to another quarantine receipt",
            ):
                verify_github_admission_artifact_graph_v2(
                    CAS(root / "state", read_only=True),
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_quarantine_receipt_digest=another_receipt,
                    expected_gateway_profile_digest=gateway_profile_digest,
                    expected_verifier_digest=VERIFIER_DIGEST,
                )
            with self.assertRaisesRegex(
                AdmissionArtifactGraphError,
                "another gateway profile",
            ):
                verify_github_admission_artifact_graph_v2(
                    CAS(root / "state", read_only=True),
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest="sha256:" + "0" * 64,
                    expected_verifier_digest=VERIFIER_DIGEST,
                )
            with self.assertRaisesRegex(
                DecisionReceiptError,
                "requires caller-held quarantine receipt and gateway profile",
            ):
                verify_decision_v3(
                    CAS(root / "state", read_only=True),
                    decision_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_artifact_graph_digest=graph_digest,
                    expected_policy_digest=policy_digest,
                    expected_analyzer_run_receipt_digests=[analyzer_receipt_digest],
                    expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                    expected_artifact_graph_verifier_digest=VERIFIER_DIGEST,
                )

    @mock.patch(
        "aragorn.admission_artifact_graph._REQUIRED_BROKER_UID",
        os.geteuid(),
    )
    def test_github_admission_rejects_darwin_and_copied_custody(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            darwin_cas = CAS(root / "darwin")
            with mock.patch(
                "aragorn.github_quarantine_receipt.sys.platform",
                "darwin",
            ):
                (
                    manifest_digest,
                    _proof_digest,
                    receipt_digest,
                    gateway_profile_digest,
                ) = _retain_github_quarantine(
                    darwin_cas,
                    b"# inert skill\n",
                    containment_profile=DARWIN_CONTAINMENT_PROFILE,
                )
                with self.assertRaisesRegex(
                    AdmissionArtifactGraphError,
                    "Linux restricted-egress",
                ):
                    retain_github_admission_artifact_graph_v2(
                        darwin_cas,
                        manifest_digest,
                        expected_quarantine_receipt_digest=receipt_digest,
                        expected_gateway_profile_digest=gateway_profile_digest,
                        verifier_implementation_digest=VERIFIER_DIGEST,
                    )

            linux_cas = CAS(root / "linux")
            with mock.patch(
                "aragorn.github_quarantine_receipt.sys.platform",
                "linux",
            ):
                (
                    manifest_digest,
                    _proof_digest,
                    receipt_digest,
                    gateway_profile_digest,
                ) = _retain_github_quarantine(
                    linux_cas,
                    b"# inert skill\n",
                )
                graph_digest = retain_github_admission_artifact_graph_v2(
                    linux_cas,
                    manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile_digest,
                    verifier_implementation_digest=VERIFIER_DIGEST,
                )
            copied = root / "copied"
            shutil.copytree(root / "linux", copied)
            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt.sys.platform",
                    "linux",
                ),
                self.assertRaisesRegex(
                    AdmissionArtifactGraphError,
                    "protected CAS custody changed",
                ),
            ):
                verify_github_admission_artifact_graph_v2(
                    CAS(copied, read_only=True),
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile_digest,
                    expected_verifier_digest=VERIFIER_DIGEST,
                )

    @mock.patch(
        "aragorn.github_quarantine_receipt.sys.platform",
        "darwin",
    )
    def test_quarantine_receipt_rejects_a_linux_profile_on_darwin(self) -> None:
        with (
            TemporaryDirectory() as temporary,
            self.assertRaisesRegex(
                ValueError,
                "does not match the current host",
            ),
        ):
            _retain_github_quarantine(
                CAS(Path(temporary) / "state"),
                b"# inert skill\n",
            )

    @mock.patch(
        "aragorn.admission_artifact_graph._REQUIRED_BROKER_UID",
        os.geteuid() + 1,
    )
    @mock.patch(
        "aragorn.github_quarantine_receipt.sys.platform",
        "linux",
    )
    def test_github_admission_requires_root_broker_custody(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            cas = CAS(root / "state")
            (
                manifest_digest,
                _proof_digest,
                receipt_digest,
                gateway_profile_digest,
            ) = _retain_github_quarantine(cas, b"# inert skill\n")
            with self.assertRaisesRegex(
                AdmissionArtifactGraphError,
                "root-owned quarantine custody",
            ):
                retain_github_admission_artifact_graph_v2(
                    cas,
                    manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile_digest,
                    verifier_implementation_digest=VERIFIER_DIGEST,
                )

    @mock.patch(
        "aragorn.admission_artifact_graph._REQUIRED_BROKER_UID",
        os.geteuid(),
    )
    @mock.patch(
        "aragorn.github_quarantine_receipt.sys.platform",
        "linux",
    )
    def test_github_external_acquisition_remains_incomplete(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            cas = CAS(root / "state")
            (
                manifest_digest,
                _proof_digest,
                receipt_digest,
                gateway_profile_digest,
            ) = _retain_github_quarantine(
                cas,
                b"curl https://example.com/tool.sh\n",
            )
            graph_digest = retain_github_admission_artifact_graph_v2(
                cas,
                manifest_digest,
                expected_quarantine_receipt_digest=receipt_digest,
                expected_gateway_profile_digest=gateway_profile_digest,
                verifier_implementation_digest=VERIFIER_DIGEST,
            )
            graph = verify_github_admission_artifact_graph_v2(
                CAS(root / "state", read_only=True),
                graph_digest,
                expected_manifest_digest=manifest_digest,
                expected_quarantine_receipt_digest=receipt_digest,
                expected_gateway_profile_digest=gateway_profile_digest,
                expected_verifier_digest=VERIFIER_DIGEST,
            )
            self.assertEqual(graph["closure"]["status"], "incomplete")
            self.assertTrue(
                any(
                    item.startswith("DYNAMIC_OR_MUTABLE_ACQUISITION:")
                    for item in graph["closure"]["unresolved"]
                )
            )


if __name__ == "__main__":
    unittest.main()
