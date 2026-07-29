from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest import mock

from aragorn.admission_artifact_graph import verify_admission_artifact_graph
from aragorn.artifact_closure import canonical_json
from aragorn.benchmark_handoff_v2 import build_handoff_manifest
from aragorn.cas import CAS
from aragorn.github_expansion_proof import retain_github_expansion_proof
from aragorn.github_quarantine_receipt import (
    LINUX_CONTAINMENT_PROFILE,
    github_gateway_profile_digest,
    retain_github_quarantine_receipt,
)
from aragorn.github_recursive_artifact_graph import (
    retain_expanded_github_manifest,
    retain_recursive_github_artifact_graph,
)
from aragorn.github_source_proof import retain_github_source_proof
from aragorn.policy import Policy, evaluate_policy

_VERIFIER_DIGEST = "sha256:" + "1" * 64
_PYTHON_DIGEST = "sha256:" + "2" * 64
_PACKAGE_DIGEST = "sha256:" + "3" * 64


def _oid(kind: str, payload: bytes) -> str:
    header = f"{kind} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _tree(entries: list[tuple[str, str, bytes]]) -> tuple[str, bytes]:
    raw = b"".join(
        mode.encode("ascii") + b" " + name + b"\0" + bytes.fromhex(oid)
        for mode, oid, name in entries
    )
    return _oid("tree", raw), raw


def _commit(tree: str, message: bytes) -> tuple[str, bytes]:
    raw = (
        f"tree {tree}\n".encode("ascii")
        + b"author Fixture <fixture@example.test> 1 +0000\n"
        + b"committer Fixture <fixture@example.test> 1 +0000\n\n"
        + message
        + b"\n"
    )
    return _oid("commit", raw), raw


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class GitHubRecursiveArtifactGraphTests(unittest.TestCase):
    def test_cross_commit_markdown_closes_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            target_content = b"# target\n"
            target_blob = _oid("blob", target_content)
            payload_tree, payload_tree_raw = _tree(
                [("100644", target_blob, b"target.md")]
            )
            target_root, target_root_raw = _tree(
                [("40000", payload_tree, b"payloads")]
            )
            target_commit, target_commit_raw = _commit(target_root, b"target")

            root_content = (
                f"[target](https://raw.githubusercontent.com/example/skills/"
                f"{target_commit}/payloads/target.md)\n"
            ).encode("ascii")
            root_blob = _oid("blob", root_content)
            skill_tree, skill_tree_raw = _tree(
                [("100644", root_blob, b"SKILL.md")]
            )
            root_tree, root_tree_raw = _tree(
                [("40000", skill_tree, b"demo")]
            )
            root_commit, root_commit_raw = _commit(root_tree, b"root")

            root_blob_digest = cas.put(
                BytesIO(root_content),
                max_bytes=len(root_content),
            )
            target_digest = cas.put(
                BytesIO(target_content),
                max_bytes=len(target_content),
            )
            root_file = {
                "path": "SKILL.md",
                "size": len(root_content),
                "digest": root_blob_digest,
                "git_blob_sha1": root_blob,
                "executable": False,
            }
            root_manifest = {
                "schema": "aragorn/github-manifest/v1",
                "source": {
                    "kind": "github_commit",
                    "host": "github.com",
                    "owner": "example",
                    "repository": "skills",
                    "commit": root_commit,
                    "repository_hash_algorithm": "sha1",
                    "commit_tree": root_tree,
                    "skill_path": "demo",
                    "skill_tree": skill_tree,
                    "api_version": "2026-03-10",
                },
                "tree_digest": _sha256(
                    canonical_json(
                        [
                            {
                                key: root_file[key]
                                for key in (
                                    "path",
                                    "size",
                                    "digest",
                                    "executable",
                                )
                            }
                        ]
                    )
                ),
                "files": [root_file],
                "closure": {"scope": "source_tree", "status": "complete"},
            }
            root_raw = canonical_json(root_manifest)
            root_manifest_digest = cas.put(
                BytesIO(root_raw),
                max_bytes=len(root_raw),
            )
            source_proof_digest = retain_github_source_proof(
                cas,
                root_manifest,
                {
                    ("commit", root_commit): root_commit_raw,
                    ("tree", root_tree): root_tree_raw,
                    ("tree", skill_tree): skill_tree_raw,
                },
            )
            handoff_blobs = {
                root_manifest_digest: len(root_raw),
                root_blob_digest: len(root_content),
                source_proof_digest: len(cas.read(source_proof_digest)),
                _sha256(root_commit_raw): len(root_commit_raw),
                _sha256(root_tree_raw): len(root_tree_raw),
                _sha256(skill_tree_raw): len(skill_tree_raw),
            }
            handoff = build_handoff_manifest(
                kind="github_source",
                root_digest=root_manifest_digest,
                blobs=handoff_blobs,
            )
            handoff_raw = canonical_json(handoff)
            handoff_digest = cas.put(
                BytesIO(handoff_raw),
                max_bytes=len(handoff_raw),
            )
            request = {
                "schema": "aragorn/github-gateway-request/v1",
                "owner": "example",
                "repository": "skills",
                "commit": root_commit,
                "skill_path": "demo",
            }
            gateway_profile = github_gateway_profile_digest(
                containment_profile=LINUX_CONTAINMENT_PROFILE,
                gateway_package_tree_digest=_PACKAGE_DIGEST,
                python_executable_digest=_PYTHON_DIGEST,
            )
            with mock.patch(
                "aragorn.github_quarantine_receipt.sys.platform",
                "linux",
            ):
                receipt_digest = retain_github_quarantine_receipt(
                    cas,
                    request=request,
                    manifest_digest=root_manifest_digest,
                    source_proof_digest=source_proof_digest,
                    handoff_manifest_digest=handoff_digest,
                    containment_profile=LINUX_CONTAINMENT_PROFILE,
                    gateway_package_tree_digest=_PACKAGE_DIGEST,
                    python_executable_digest=_PYTHON_DIGEST,
                )

            materialized = (
                f"__aragorn_expanded__/{target_commit}/payloads/target.md"
            )
            expansion_object = {
                "commit": target_commit,
                "commit_tree": target_root,
                "repository_path": "payloads/target.md",
                "materialized_path": materialized,
                "depth": 1,
                "size": len(target_content),
                "digest": target_digest,
                "git_blob_sha1": target_blob,
                "executable": False,
                "references": [],
            }
            expansion = {
                "schema": "aragorn/github-expansion/v1",
                "profile": "phase0-exact-github-blob-expansion/v1",
                "assurance": (
                    "evaluation_only_github_api_membership_asserted_"
                    "blob_identity_reverified"
                ),
                "source": {
                    key: root_manifest["source"][key]
                    for key in (
                        "host",
                        "owner",
                        "repository",
                        "commit",
                        "commit_tree",
                        "skill_path",
                        "api_version",
                    )
                },
                "root_manifest_digest": root_manifest_digest,
                "root_tree_digest": root_manifest["tree_digest"],
                "comparator_subject_manifest_digest": None,
                "comparator_subject_tree_digest": None,
                "references": [],
                "objects": [expansion_object],
                "accounting": {},
                "closure": {
                    "scope": "phase0_exact_github_blob_expansion",
                    "status": "complete",
                    "unresolved": [],
                },
            }
            expansion_raw = canonical_json(expansion)
            expansion_digest = cas.put(
                BytesIO(expansion_raw),
                max_bytes=len(expansion_raw),
            )
            expansion_proof_digest = retain_github_expansion_proof(
                cas,
                expansion_digest,
                root_manifest_digest,
                {
                    ("commit", target_commit): target_commit_raw,
                    ("tree", target_root): target_root_raw,
                    ("tree", payload_tree): payload_tree_raw,
                },
            )
            manifest_digest = retain_expanded_github_manifest(
                cas,
                expansion_digest,
            )

            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt.sys.platform",
                    "linux",
                ),
                mock.patch(
                    "aragorn.github_recursive_artifact_graph._REQUIRED_BROKER_UID",
                    os.geteuid(),
                ),
            ):
                graph_digest = retain_recursive_github_artifact_graph(
                    cas,
                    manifest_digest,
                    root_manifest_digest=root_manifest_digest,
                    expansion_digest=expansion_digest,
                    expansion_proof_digest=expansion_proof_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    verifier_implementation_digest=_VERIFIER_DIGEST,
                )
                graph = verify_admission_artifact_graph(
                    cas,
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile,
                    expected_verifier_digest=_VERIFIER_DIGEST,
                )

            self.assertEqual(graph["profile"], "recursive-github-markdown/v1")
            self.assertEqual(
                graph["coverage"]["statically_resolvable"],
                {"captured": 1, "total": 1},
            )
            self.assertEqual(graph["closure"]["status"], "complete")
            self.assertEqual(
                graph["edges"][0]["target"],
                {"path": materialized, "digest": target_digest},
            )
            decision = evaluate_policy(
                Policy(),
                closure=graph["closure"],
                results=[],
            )
            self.assertNotEqual(decision.verdict, "ERROR")


if __name__ == "__main__":
    unittest.main()
