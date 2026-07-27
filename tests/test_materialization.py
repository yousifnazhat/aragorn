from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from aragorn.acquire import ingest_local
from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.materialization import (
    MaterializationVerificationError,
    verify_materialized_source_tree,
)


def _retain_manifest(cas: CAS, source: Path, **limits: int) -> tuple[dict, str]:
    manifest = ingest_local(source, cas, **limits)
    return manifest, _retain_document(cas, manifest)


def _retain_document(cas: CAS, document: dict) -> str:
    content = canonical_json(document)
    return cas.put(BytesIO(content), max_bytes=len(content))


def _verify(state: Path, manifest_digest: str, source: Path) -> str:
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return verify_materialized_source_tree(
            CAS(state, read_only=True),
            manifest_digest,
            descriptor,
        )
    finally:
        os.close(descriptor)


class MaterializationTests(unittest.TestCase):
    def test_open_directory_snapshot_matches_read_only_cas_after_path_retarget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            (first / "SKILL.md").write_bytes(b"expected")
            (second / "SKILL.md").write_bytes(b"replacement")
            cas = CAS(root / "state")
            manifest, manifest_digest = _retain_manifest(cas, first)
            selected = root / "selected"
            selected.symlink_to(first, target_is_directory=True)
            descriptor = os.open(first, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                selected.unlink()
                selected.symlink_to(second, target_is_directory=True)
                observed = verify_materialized_source_tree(
                    CAS(root / "state", read_only=True),
                    manifest_digest,
                    descriptor,
                )
            finally:
                os.close(descriptor)

            self.assertEqual(observed, manifest["tree_digest"])

    def test_changed_missing_extra_and_executable_files_fail_closed(self) -> None:
        mutations = {
            "changed": lambda source: (source / "SKILL.md").write_bytes(b"changed"),
            "missing": lambda source: (source / "SKILL.md").unlink(),
            "extra": lambda source: (source / "extra").write_bytes(b"extra"),
            "empty-directory": lambda source: (source / "empty").mkdir(),
            "executable": lambda source: (source / "SKILL.md").chmod(0o755),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "skill"
                (source / "nested").mkdir(parents=True)
                (source / "SKILL.md").write_bytes(b"expected")
                (source / "nested" / "content").write_bytes(b"nested")
                cas = CAS(root / "state")
                _, manifest_digest = _retain_manifest(cas, source)
                mutate(source)
                with self.assertRaisesRegex(
                    MaterializationVerificationError,
                    "does not match|cannot verify",
                ):
                    _verify(root / "state", manifest_digest, source)

    def test_missing_retained_blob_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_bytes(b"expected")
            cas = CAS(root / "state")
            manifest = ingest_local(source, cas)
            manifest["files"][0]["digest"] = "sha256:" + "f" * 64
            manifest["tree_digest"] = (
                "sha256:"
                + hashlib.sha256(canonical_json(manifest["files"])).hexdigest()
            )
            manifest_digest = _retain_document(cas, manifest)
            with self.assertRaisesRegex(
                MaterializationVerificationError,
                "cannot verify retained source blob",
            ):
                _verify(root / "state", manifest_digest, source)

    def test_github_manifest_compares_the_installation_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_bytes(b"expected")
            cas = CAS(root / "state")
            local = ingest_local(source, cas)
            entry = local["files"][0]
            content = cas.read(entry["digest"])
            manifest = {
                **local,
                "schema": "aragorn/github-manifest/v1",
                "source": {
                    "kind": "github_commit",
                    "host": "github.com",
                    "owner": "example",
                    "repository": "skill",
                    "commit": "a" * 40,
                    "repository_hash_algorithm": "sha1",
                    "commit_tree": "b" * 40,
                    "skill_path": ".",
                    "skill_tree": "c" * 40,
                    "api_version": "2026-03-10",
                },
                "files": [
                    {
                        **entry,
                        "git_blob_sha1": hashlib.sha1(
                            f"blob {len(content)}\0".encode("ascii") + content
                        ).hexdigest(),
                    }
                ],
            }
            manifest_digest = _retain_document(cas, manifest)
            observed = _verify(root / "state", manifest_digest, source)

            self.assertEqual(observed, local["tree_digest"])

    def test_retained_tree_beyond_supported_depth_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            nested = source
            for depth in range(9):
                nested /= str(depth)
            nested.mkdir(parents=True)
            (nested / "content").write_bytes(b"deep")
            cas = CAS(root / "state")
            _, manifest_digest = _retain_manifest(cas, source, max_depth=9)
            with self.assertRaisesRegex(
                MaterializationVerificationError,
                "supported depth",
            ):
                _verify(root / "state", manifest_digest, source)


if __name__ == "__main__":
    unittest.main()
