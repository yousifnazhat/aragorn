from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest import mock

from aragorn import github_source_proof
from aragorn.artifact_closure import ArtifactClosureError, canonical_json
from aragorn.cas import CAS
from aragorn.github_source_proof import (
    retain_github_source_proof,
    verify_github_source_proof,
)


def _git_oid(object_type: str, payload: bytes) -> str:
    header = f"{object_type} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _tree_entry(mode: bytes, name: bytes, oid: str) -> bytes:
    return mode + b" " + name + b"\0" + bytes.fromhex(oid)


def _put(cas: CAS, payload: bytes) -> str:
    return cas.put(BytesIO(payload), max_bytes=len(payload))


def _retain_document(cas: CAS, document: object) -> str:
    return _put(cas, canonical_json(document))


def _tree_digest(files: list[dict[str, object]]) -> str:
    members = [
        {key: entry[key] for key in ("path", "size", "digest", "executable")}
        for entry in files
    ]
    return "sha256:" + hashlib.sha256(canonical_json(members)).hexdigest()


class Fixture:
    def __init__(self, cas: CAS) -> None:
        skill_content = b"# safe\n"
        script_content = b"#!/bin/sh\n"
        skill_blob = _git_oid("blob", skill_content)
        script_blob = _git_oid("blob", script_content)

        scripts_payload = _tree_entry(b"100755", b"run.sh", script_blob)
        scripts_oid = _git_oid("tree", scripts_payload)
        skill_payload = _tree_entry(b"100644", b"SKILL.md", skill_blob) + _tree_entry(
            b"40000", b"scripts", scripts_oid
        )
        skill_oid = _git_oid("tree", skill_payload)
        skills_payload = _tree_entry(b"40000", b"demo", skill_oid)
        skills_oid = _git_oid("tree", skills_payload)
        root_payload = _tree_entry(b"40000", b"skills", skills_oid)
        root_oid = _git_oid("tree", root_payload)
        commit_payload = (
            f"tree {root_oid}\n".encode("ascii")
            + b"author Fixture <fixture@example.test> 1 +0000\n"
            + b"committer Fixture <fixture@example.test> 1 +0000\n"
            + b"\nfixture\n"
        )
        commit_oid = _git_oid("commit", commit_payload)

        files: list[dict[str, object]] = [
            {
                "path": "SKILL.md",
                "size": len(skill_content),
                "digest": _put(cas, skill_content),
                "git_blob_sha1": skill_blob,
                "executable": False,
            },
            {
                "path": "scripts/run.sh",
                "size": len(script_content),
                "digest": _put(cas, script_content),
                "git_blob_sha1": script_blob,
                "executable": True,
            },
        ]
        self.manifest = {
            "schema": "aragorn/github-manifest/v1",
            "source": {
                "kind": "github_commit",
                "host": "github.com",
                "owner": "example",
                "repository": "skill",
                "commit": commit_oid,
                "repository_hash_algorithm": "sha1",
                "commit_tree": root_oid,
                "skill_path": "skills/demo",
                "skill_tree": skill_oid,
                "api_version": "2026-03-10",
            },
            "tree_digest": _tree_digest(files),
            "files": files,
            "closure": {"scope": "source_tree", "status": "complete"},
        }
        self.raw_objects = {
            ("commit", commit_oid): commit_payload,
            ("tree", root_oid): root_payload,
            ("tree", skills_oid): skills_payload,
            ("tree", skill_oid): skill_payload,
            ("tree", scripts_oid): scripts_payload,
        }


class GitHubSourceProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(Path(self.temporary.name) / "state")
        self.fixture = Fixture(self.cas)

    def test_good_proof_reloads_every_bound_object(self) -> None:
        proof_digest = retain_github_source_proof(
            self.cas,
            self.fixture.manifest,
            self.fixture.raw_objects,
        )
        retained = json.loads(self.cas.read(proof_digest))
        verified = verify_github_source_proof(
            self.cas,
            proof_digest,
            retained["manifest_digest"],
        )

        self.assertEqual(verified, retained)
        self.assertEqual(verified["schema"], "aragorn/github-source-proof/v1")
        self.assertEqual(verified["source"], self.fixture.manifest["source"])
        self.assertEqual(len(verified["objects"]), len(self.fixture.raw_objects))
        for record in verified["objects"]:
            self.assertEqual(
                self.cas.read(record["digest"], max_bytes=record["size"]),
                self.fixture.raw_objects[(record["type"], record["oid"])],
            )

    def test_mutated_payload_fails_git_identity_reverification(self) -> None:
        proof_digest = retain_github_source_proof(
            self.cas,
            self.fixture.manifest,
            self.fixture.raw_objects,
        )
        proof = json.loads(self.cas.read(proof_digest))
        commit = next(
            record for record in proof["objects"] if record["type"] == "commit"
        )
        mutated = self.fixture.raw_objects[("commit", commit["oid"])] + b"changed"
        commit["digest"] = _put(self.cas, mutated)
        commit["size"] = len(mutated)

        with self.assertRaisesRegex(ArtifactClosureError, "do not match OID"):
            verify_github_source_proof(
                self.cas,
                _retain_document(self.cas, proof),
                proof["manifest_digest"],
            )

    def test_missing_required_tree_is_rejected(self) -> None:
        proof_digest = retain_github_source_proof(
            self.cas,
            self.fixture.manifest,
            self.fixture.raw_objects,
        )
        proof = json.loads(self.cas.read(proof_digest))
        skill_tree = self.fixture.manifest["source"]["skill_tree"]
        proof["objects"] = [
            record
            for record in proof["objects"]
            if not (record["type"] == "tree" and record["oid"] == skill_tree)
        ]

        with self.assertRaisesRegex(ArtifactClosureError, "missing required tree"):
            verify_github_source_proof(
                self.cas,
                _retain_document(self.cas, proof),
                proof["manifest_digest"],
            )

    def test_extra_valid_tree_is_rejected(self) -> None:
        proof_digest = retain_github_source_proof(
            self.cas,
            self.fixture.manifest,
            self.fixture.raw_objects,
        )
        proof = json.loads(self.cas.read(proof_digest))
        payload = b""
        oid = _git_oid("tree", payload)
        proof["objects"].append(
            {
                "type": "tree",
                "oid": oid,
                "size": 0,
                "digest": _put(self.cas, payload),
            }
        )
        proof["objects"].sort(
            key=lambda item: (0 if item["type"] == "commit" else 1, item["oid"])
        )

        with self.assertRaisesRegex(ArtifactClosureError, "contains extra objects"):
            verify_github_source_proof(
                self.cas,
                _retain_document(self.cas, proof),
                proof["manifest_digest"],
            )

    def test_skill_path_must_resolve_from_the_commit_root(self) -> None:
        manifest = json.loads(canonical_json(self.fixture.manifest))
        manifest["source"]["skill_path"] = "skills/missing"

        with self.assertRaisesRegex(ArtifactClosureError, "skill_path"):
            retain_github_source_proof(
                self.cas,
                manifest,
                self.fixture.raw_objects,
            )

    def test_repository_path_budget_includes_skill_path_prefix(self) -> None:
        content = b"bounded"
        blob_oid = _git_oid("blob", content)
        payload = _tree_entry(b"100644", b"x", blob_oid)
        skill_tree_oid = _git_oid("tree", payload)
        raw_objects = {("tree", skill_tree_oid): payload}
        components = [
            chr(ord("a") + index).encode("ascii") * 255
            for index in range(16)
        ]
        tree_oid = skill_tree_oid
        for component in reversed(components):
            payload = _tree_entry(b"40000", component, tree_oid)
            tree_oid = _git_oid("tree", payload)
            raw_objects[("tree", tree_oid)] = payload
        commit_payload = f"tree {tree_oid}\n\nfixture\n".encode("ascii")
        commit_oid = _git_oid("commit", commit_payload)
        raw_objects[("commit", commit_oid)] = commit_payload
        files = [
            {
                "path": "x",
                "size": len(content),
                "digest": _put(self.cas, content),
                "git_blob_sha1": blob_oid,
                "executable": False,
            }
        ]
        skill_path = "/".join(component.decode("ascii") for component in components)
        manifest = {
            "schema": "aragorn/github-manifest/v1",
            "source": {
                "kind": "github_commit",
                "host": "github.com",
                "owner": "example",
                "repository": "skill",
                "commit": commit_oid,
                "repository_hash_algorithm": "sha1",
                "commit_tree": tree_oid,
                "skill_path": skill_path,
                "skill_tree": skill_tree_oid,
                "api_version": "2026-03-10",
            },
            "tree_digest": _tree_digest(files),
            "files": files,
            "closure": {"scope": "source_tree", "status": "complete"},
        }

        self.assertEqual(len(skill_path.encode("utf-8")), 4095)
        with self.assertRaisesRegex(ArtifactClosureError, "repository path"):
            retain_github_source_proof(self.cas, manifest, raw_objects)

    def test_manifest_modes_must_match_the_proved_tree(self) -> None:
        manifest = json.loads(canonical_json(self.fixture.manifest))
        manifest["files"][1]["executable"] = False
        manifest["tree_digest"] = _tree_digest(manifest["files"])

        with self.assertRaisesRegex(ArtifactClosureError, "membership, mode"):
            retain_github_source_proof(
                self.cas,
                manifest,
                self.fixture.raw_objects,
            )

    def test_skill_subtree_beyond_gateway_depth_is_rejected(self) -> None:
        content = b"deep"
        blob_oid = _git_oid("blob", content)
        payload = _tree_entry(b"100644", b"file", blob_oid)
        tree_oid = _git_oid("tree", payload)
        raw_objects = {("tree", tree_oid): payload}
        for depth in reversed(range(9)):
            payload = _tree_entry(b"40000", str(depth).encode("ascii"), tree_oid)
            tree_oid = _git_oid("tree", payload)
            raw_objects[("tree", tree_oid)] = payload
        commit_payload = f"tree {tree_oid}\n\nfixture\n".encode("ascii")
        commit_oid = _git_oid("commit", commit_payload)
        raw_objects[("commit", commit_oid)] = commit_payload
        files = [
            {
                "path": "/".join((*map(str, range(9)), "file")),
                "size": len(content),
                "digest": _put(self.cas, content),
                "git_blob_sha1": blob_oid,
                "executable": False,
            }
        ]
        manifest = {
            "schema": "aragorn/github-manifest/v1",
            "source": {
                "kind": "github_commit",
                "host": "github.com",
                "owner": "example",
                "repository": "skill",
                "commit": commit_oid,
                "repository_hash_algorithm": "sha1",
                "commit_tree": tree_oid,
                "skill_path": ".",
                "skill_tree": tree_oid,
                "api_version": "2026-03-10",
            },
            "tree_digest": _tree_digest(files),
            "files": files,
            "closure": {"scope": "source_tree", "status": "complete"},
        }

        with self.assertRaisesRegex(ArtifactClosureError, "depth 8"):
            retain_github_source_proof(self.cas, manifest, raw_objects)

    def test_tree_entry_budget_includes_root_to_skill_path(self) -> None:
        with (
            mock.patch.object(github_source_proof, "_MAX_TREE_ENTRIES", 2),
            self.assertRaisesRegex(ArtifactClosureError, "budget is exhausted"),
        ):
            retain_github_source_proof(
                self.cas,
                self.fixture.manifest,
                self.fixture.raw_objects,
            )

    def test_subtree_traversal_budget_counts_reused_trees(self) -> None:
        with (
            mock.patch.object(
                github_source_proof,
                "_MAX_TRAVERSED_TREE_ENTRIES",
                2,
            ),
            self.assertRaisesRegex(ArtifactClosureError, "subtree traversal"),
        ):
            retain_github_source_proof(
                self.cas,
                self.fixture.manifest,
                self.fixture.raw_objects,
            )


if __name__ == "__main__":
    unittest.main()
