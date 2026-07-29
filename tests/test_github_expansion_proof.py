from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.github_expansion_proof import (
    GitHubExpansionProofError,
    retain_github_expansion_proof,
    verify_github_expansion_proof,
)


def _oid(kind: str, payload: bytes) -> str:
    header = f"{kind} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _tree(entries: list[tuple[str, str, bytes]]) -> tuple[str, bytes]:
    raw = b"".join(
        mode.encode("ascii") + b" " + name + b"\0" + bytes.fromhex(oid)
        for mode, oid, name in entries
    )
    return _oid("tree", raw), raw


class GitHubExpansionProofTests(unittest.TestCase):
    def test_expanded_blob_membership_replays_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            root_content = b"# root\n"
            target_content = b"# target\n"
            root_blob = _oid("blob", root_content)
            target_blob = _oid("blob", target_content)
            skill_tree, skill_tree_raw = _tree(
                [("100644", root_blob, b"SKILL.md")]
            )
            payload_tree, payload_tree_raw = _tree(
                [("100644", target_blob, b"target.md")]
            )
            root_tree, root_tree_raw = _tree(
                [
                    ("40000", payload_tree, b"payloads"),
                    ("40000", skill_tree, b"skill"),
                ]
            )
            commit_raw = (
                f"tree {root_tree}\n".encode("ascii")
                + b"author Fixture <fixture@example.test> 1 +0000\n"
                + b"committer Fixture <fixture@example.test> 1 +0000\n\nfixture\n"
            )
            commit = _oid("commit", commit_raw)
            root_digest = cas.put(
                BytesIO(root_content),
                max_bytes=len(root_content),
            )
            target_digest = cas.put(
                BytesIO(target_content),
                max_bytes=len(target_content),
            )
            root_files = [
                {
                    "path": "SKILL.md",
                    "size": len(root_content),
                    "digest": root_digest,
                    "git_blob_sha1": root_blob,
                    "executable": False,
                }
            ]
            tree_files = [
                {
                    key: entry[key]
                    for key in ("path", "size", "digest", "executable")
                }
                for entry in root_files
            ]
            manifest = {
                "schema": "aragorn/github-manifest/v1",
                "source": {
                    "kind": "github_commit",
                    "host": "github.com",
                    "owner": "example",
                    "repository": "project",
                    "commit": commit,
                    "repository_hash_algorithm": "sha1",
                    "commit_tree": root_tree,
                    "skill_path": "skill",
                    "skill_tree": skill_tree,
                    "api_version": "2026-03-10",
                },
                "tree_digest": "sha256:"
                + hashlib.sha256(canonical_json(tree_files)).hexdigest(),
                "files": root_files,
                "closure": {"scope": "source_tree", "status": "complete"},
            }
            manifest_raw = canonical_json(manifest)
            manifest_digest = cas.put(
                BytesIO(manifest_raw),
                max_bytes=len(manifest_raw),
            )
            target = {
                "commit": commit,
                "commit_tree": root_tree,
                "repository_path": "payloads/target.md",
                "materialized_path": "__expanded__/target.md",
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
                    key: manifest["source"][key]
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
                "root_manifest_digest": manifest_digest,
                "root_tree_digest": manifest["tree_digest"],
                "comparator_subject_manifest_digest": None,
                "comparator_subject_tree_digest": None,
                "references": [],
                "objects": [target],
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
            raw_objects = {
                ("commit", commit): commit_raw,
                ("tree", root_tree): root_tree_raw,
                ("tree", skill_tree): skill_tree_raw,
                ("tree", payload_tree): payload_tree_raw,
            }

            proof_digest = retain_github_expansion_proof(
                cas,
                expansion_digest,
                manifest_digest,
                raw_objects,
            )
            proof = verify_github_expansion_proof(
                cas,
                proof_digest,
                expected_expansion_digest=expansion_digest,
                expected_root_manifest_digest=manifest_digest,
            )
            self.assertEqual(
                proof["targets"],
                [
                    {
                        key: target[key]
                        for key in (
                            "commit",
                            "commit_tree",
                            "repository_path",
                            "size",
                            "digest",
                            "git_blob_sha1",
                            "executable",
                        )
                    }
                ],
            )
            self.assertNotIn(
                skill_tree,
                {item["oid"] for item in proof["objects"]},
            )

            partial = json.loads(canonical_json(expansion))
            partial["closure"] = {
                "scope": "phase0_exact_github_blob_expansion",
                "status": "incomplete",
                "unresolved": [
                    {
                        "reason_code": "RELEASE_OR_ARCHIVE_UNRESOLVED",
                        "subject": "SKILL.md",
                    }
                ],
            }
            partial_raw = canonical_json(partial)
            partial_digest = cas.put(
                BytesIO(partial_raw),
                max_bytes=len(partial_raw),
            )
            partial_proof = retain_github_expansion_proof(
                cas,
                partial_digest,
                manifest_digest,
                raw_objects,
            )
            verify_github_expansion_proof(
                cas,
                partial_proof,
                expected_expansion_digest=partial_digest,
                expected_root_manifest_digest=manifest_digest,
            )

            forged = json.loads(canonical_json(proof))
            forged["targets"][0]["digest"] = root_digest
            forged_raw = canonical_json(forged)
            forged_digest = cas.put(
                BytesIO(forged_raw),
                max_bytes=len(forged_raw),
            )
            with self.assertRaisesRegex(
                GitHubExpansionProofError,
                "targets do not match",
            ):
                verify_github_expansion_proof(
                    cas,
                    forged_digest,
                    expected_expansion_digest=expansion_digest,
                    expected_root_manifest_digest=manifest_digest,
                )


if __name__ == "__main__":
    unittest.main()
