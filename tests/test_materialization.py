from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import unittest
from io import BytesIO
from pathlib import Path, PurePosixPath

from aragorn.acquire import ingest_local
from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.materialization import (
    MaterializationVerificationError,
    _publish_materialized_source_tree,
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


def _stage_manifest(cas: CAS, root: Path, name: str, manifest: dict) -> Path:
    staging = root / name
    staging.mkdir(mode=0o700)
    for entry in manifest["files"]:
        relative = PurePosixPath(entry["path"])
        parent = staging
        for part in relative.parts[:-1]:
            parent /= part
            if not parent.exists():
                parent.mkdir(mode=0o700)
        destination = staging.joinpath(*relative.parts)
        cas.materialize(entry["digest"], destination, root=staging)
        if entry["executable"]:
            destination.chmod(0o555)
    return staging


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

    def test_descriptor_relative_publication_is_fresh_verified_and_read_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "bin").mkdir(parents=True)
            (source / "SKILL.md").write_bytes(b"expected")
            executable = source / "bin" / "run.sh"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            cas = CAS(root / "state")
            manifest, manifest_digest = _retain_manifest(cas, source)
            active = root / "active"
            active.mkdir(mode=0o700)
            staging_names = [f".aragorn-stage-{index:024x}" for index in range(1, 6)]
            _stage_manifest(cas, active, staging_names[0], manifest)

            root_fd = os.open(
                active,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            try:
                self.assertEqual(
                    _publish_materialized_source_tree(
                        CAS(root / "state", read_only=True),
                        manifest_digest,
                        root_fd,
                        staging_name=staging_names[0],
                        target_name="verified-skill",
                    ),
                    manifest["tree_digest"],
                )
                target = active / "verified-skill"
                self.assertFalse((active / staging_names[0]).exists())
                self.assertEqual((target / "SKILL.md").read_bytes(), b"expected")
                self.assertEqual(
                    stat.S_IMODE(os.lstat(target).st_mode),
                    0o555,
                )
                self.assertEqual(
                    stat.S_IMODE(os.lstat(target / "bin").st_mode),
                    0o555,
                )
                self.assertEqual(
                    stat.S_IMODE(os.lstat(target / "SKILL.md").st_mode),
                    0o444,
                )
                self.assertEqual(
                    stat.S_IMODE(os.lstat(target / "bin" / "run.sh").st_mode),
                    0o555,
                )

                _stage_manifest(cas, active, staging_names[1], manifest)
                with self.assertRaisesRegex(
                    MaterializationVerificationError,
                    "already exists",
                ):
                    _publish_materialized_source_tree(
                        CAS(root / "state", read_only=True),
                        manifest_digest,
                        root_fd,
                        staging_name=staging_names[1],
                        target_name="verified-skill",
                    )
                self.assertTrue((active / staging_names[1]).is_dir())

                empty_target = active / "empty-target"
                empty_target.mkdir()
                _stage_manifest(cas, active, staging_names[2], manifest)
                with self.assertRaisesRegex(
                    MaterializationVerificationError,
                    "already exists",
                ):
                    _publish_materialized_source_tree(
                        CAS(root / "state", read_only=True),
                        manifest_digest,
                        root_fd,
                        staging_name=staging_names[2],
                        target_name="empty-target",
                    )
                self.assertTrue((active / staging_names[2]).is_dir())
                self.assertEqual(list(empty_target.iterdir()), [])

                linked_target = active / "linked-target"
                linked_target.symlink_to(source, target_is_directory=True)
                _stage_manifest(cas, active, staging_names[3], manifest)
                with self.assertRaisesRegex(
                    MaterializationVerificationError,
                    "already exists",
                ):
                    _publish_materialized_source_tree(
                        CAS(root / "state", read_only=True),
                        manifest_digest,
                        root_fd,
                        staging_name=staging_names[3],
                        target_name="linked-target",
                    )
                self.assertTrue((active / staging_names[3]).is_dir())
                self.assertTrue(linked_target.is_symlink())

                tampered = _stage_manifest(
                    cas,
                    active,
                    staging_names[4],
                    manifest,
                )
                changed = tampered / "SKILL.md"
                changed.chmod(0o644)
                changed.write_bytes(b"changed")
                changed.chmod(0o444)
                with self.assertRaisesRegex(
                    MaterializationVerificationError,
                    "does not match",
                ):
                    _publish_materialized_source_tree(
                        CAS(root / "state", read_only=True),
                        manifest_digest,
                        root_fd,
                        staging_name=staging_names[4],
                        target_name="tampered-target",
                    )
                self.assertTrue((active / staging_names[4]).is_dir())
                self.assertFalse(os.path.lexists(active / "tampered-target"))
                self.assertEqual((target / "SKILL.md").read_bytes(), b"expected")
            finally:
                os.close(root_fd)

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
