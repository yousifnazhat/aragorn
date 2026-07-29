from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from aragorn.artifact_closure import ArtifactClosureError, canonical_json
from aragorn.cas import CAS
from aragorn.github_selected_path_proof import (
    retain_github_selected_path_proof,
    verify_github_selected_path_proof,
)


def _git_oid(object_type: str, payload: bytes) -> str:
    header = f"{object_type} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _tree_entry(mode: bytes, name: bytes, oid: str) -> bytes:
    return mode + b" " + name + b"\0" + bytes.fromhex(oid)


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _put_document(cas: CAS, document: object) -> str:
    raw = canonical_json(document)
    return cas.put(BytesIO(raw), max_bytes=len(raw))


class Fixture:
    def __init__(self) -> None:
        first_content = b"first selected payload\n"
        second_content = b"#!/bin/sh\nexit 0\n"
        ignored_content = b"not selected\n"
        first_blob = _git_oid("blob", first_content)
        second_blob = _git_oid("blob", second_content)
        ignored_blob = _git_oid("blob", ignored_content)

        assets_tree_payload = _tree_entry(
            b"100644", b"ignored.bin", ignored_blob
        ) + _tree_entry(b"100644", b"one.txt", first_blob)
        assets_tree = _git_oid("tree", assets_tree_payload)
        first_root_payload = _tree_entry(b"40000", b"assets", assets_tree)
        first_root = _git_oid("tree", first_root_payload)
        first_commit_payload = f"tree {first_root}\n\nfirst\n".encode("ascii")
        first_commit = _git_oid("commit", first_commit_payload)

        bin_tree_payload = _tree_entry(b"100755", b"run.sh", second_blob)
        bin_tree = _git_oid("tree", bin_tree_payload)
        second_root_payload = _tree_entry(b"40000", b"bin", bin_tree)
        second_root = _git_oid("tree", second_root_payload)
        second_commit_payload = f"tree {second_root}\n\nsecond\n".encode("ascii")
        second_commit = _git_oid("commit", second_commit_payload)

        self.repository = {
            "host": "github.com",
            "owner": "example",
            "repository": "project",
            "repository_hash_algorithm": "sha1",
        }
        self.targets = [
            {
                "commit": second_commit,
                "repository_path": "bin/run.sh",
                "git_blob_sha1": second_blob,
                "size": len(second_content),
                "digest": _digest(second_content),
                "executable": True,
            },
            {
                "commit": first_commit,
                "repository_path": "assets/one.txt",
                "git_blob_sha1": first_blob,
                "size": len(first_content),
                "digest": _digest(first_content),
                "executable": False,
            },
        ]
        self.raw_objects = {
            ("blob", second_blob): second_content,
            ("tree", second_root): second_root_payload,
            ("commit", first_commit): first_commit_payload,
            ("tree", assets_tree): assets_tree_payload,
            ("blob", first_blob): first_content,
            ("commit", second_commit): second_commit_payload,
            ("tree", first_root): first_root_payload,
            ("tree", bin_tree): bin_tree_payload,
        }
        self.ignored_blob = ignored_blob
        self.ignored_content = ignored_content


class GitHubSelectedPathProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(Path(self.temporary.name) / "state")
        self.fixture = Fixture()

    def retain(self) -> tuple[str, dict[str, object]]:
        proof_digest = retain_github_selected_path_proof(
            self.cas,
            self.fixture.repository,
            self.fixture.targets,
            self.fixture.raw_objects,
        )
        return proof_digest, json.loads(self.cas.read(proof_digest))

    def verify(self, proof_digest: str, **overrides: object) -> dict[str, object]:
        return verify_github_selected_path_proof(
            self.cas,
            proof_digest,
            expected_repository=overrides.get(
                "expected_repository",
                self.fixture.repository,
            ),
            expected_targets=overrides.get(
                "expected_targets",
                self.fixture.targets,
            ),
        )

    def test_replays_exact_sorted_multi_commit_target_union(self) -> None:
        proof_digest, proof = self.retain()

        verified = self.verify(proof_digest)

        self.assertEqual(verified, proof)
        self.assertEqual(
            proof["schema"],
            "aragorn/github-selected-path-proof/v1",
        )
        self.assertEqual(
            [
                (target["commit"], target["repository_path"])
                for target in proof["targets"]
            ],
            sorted(
                (target["commit"], target["repository_path"])
                for target in self.fixture.targets
            ),
        )
        self.assertEqual(
            [(record["type"], record["oid"]) for record in proof["objects"]],
            sorted(
                self.fixture.raw_objects,
                key=lambda item: (
                    {"commit": 0, "tree": 1, "blob": 2}[item[0]],
                    item[1],
                ),
            ),
        )
        for record in proof["objects"]:
            self.assertEqual(
                self.cas.read(record["digest"], max_bytes=record["size"]),
                self.fixture.raw_objects[(record["type"], record["oid"])],
            )

    def test_rejects_each_missing_object_type_and_any_extra_object(self) -> None:
        _proof_digest, proof = self.retain()
        for object_type in ("commit", "tree", "blob"):
            with self.subTest(missing=object_type):
                mutated = json.loads(canonical_json(proof))
                index = next(
                    index
                    for index, record in enumerate(mutated["objects"])
                    if record["type"] == object_type
                )
                mutated["objects"].pop(index)
                with self.assertRaisesRegex(
                    ArtifactClosureError,
                    f"missing required {object_type}",
                ):
                    self.verify(_put_document(self.cas, mutated))

        extra = json.loads(canonical_json(proof))
        extra["objects"].append(
            {
                "type": "blob",
                "oid": self.fixture.ignored_blob,
                "size": len(self.fixture.ignored_content),
                "digest": self.cas.put(
                    BytesIO(self.fixture.ignored_content),
                    max_bytes=len(self.fixture.ignored_content),
                ),
            }
        )
        extra["objects"].sort(
            key=lambda record: (
                {"commit": 0, "tree": 1, "blob": 2}[record["type"]],
                record["oid"],
            )
        )
        with self.assertRaisesRegex(ArtifactClosureError, "contains extra objects"):
            self.verify(_put_document(self.cas, extra))

        raw_with_extra = {
            **self.fixture.raw_objects,
            ("blob", self.fixture.ignored_blob): self.fixture.ignored_content,
        }
        with self.assertRaisesRegex(ArtifactClosureError, "contains extra objects"):
            retain_github_selected_path_proof(
                self.cas,
                self.fixture.repository,
                self.fixture.targets,
                raw_with_extra,
            )

    def test_rejects_changed_target_identity_bytes_mode_and_order(self) -> None:
        _proof_digest, proof = self.retain()
        mutations = (
            (0, "repository_path", "missing/file.txt", "absent from its commit"),
            (0, "digest", "sha256:" + "f" * 64, "target bytes changed"),
            (
                next(
                    index
                    for index, target in enumerate(proof["targets"])
                    if not target["executable"]
                ),
                "executable",
                True,
                "blob identity or mode changed",
            ),
        )
        for index, field, value, message in mutations:
            with self.subTest(field=field):
                mutated = json.loads(canonical_json(proof))
                mutated["targets"][index][field] = value
                with self.assertRaisesRegex(ArtifactClosureError, message):
                    self.verify(
                        _put_document(self.cas, mutated),
                        expected_targets=mutated["targets"],
                    )

        unordered = json.loads(canonical_json(proof))
        unordered["targets"].reverse()
        with self.assertRaisesRegex(
            ArtifactClosureError,
            "targets are not canonically ordered",
        ):
            self.verify(_put_document(self.cas, unordered))

    def test_rehashes_every_retained_raw_object_before_replay(self) -> None:
        _proof_digest, proof = self.retain()
        mutated = json.loads(canonical_json(proof))
        blob_record = next(
            record for record in mutated["objects"] if record["type"] == "blob"
        )
        changed = (
            self.fixture.raw_objects[("blob", blob_record["oid"])] + b"substituted"
        )
        blob_record["size"] = len(changed)
        blob_record["digest"] = self.cas.put(
            BytesIO(changed),
            max_bytes=len(changed),
        )

        with self.assertRaisesRegex(ArtifactClosureError, "do not match OID"):
            self.verify(_put_document(self.cas, mutated))

    def test_replay_requires_exact_caller_authorized_repository_and_targets(
        self,
    ) -> None:
        proof_digest, _proof = self.retain()
        repository = dict(self.fixture.repository)
        repository["repository"] = "other"
        with self.assertRaisesRegex(ArtifactClosureError, "not caller-authorized"):
            self.verify(
                proof_digest,
                expected_repository=repository,
            )

        targets = json.loads(canonical_json(self.fixture.targets))
        targets[0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ArtifactClosureError, "not caller-authorized"):
            self.verify(
                proof_digest,
                expected_targets=targets,
            )


if __name__ == "__main__":
    unittest.main()
