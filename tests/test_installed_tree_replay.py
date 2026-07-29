from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from io import BytesIO
from pathlib import Path

from aragorn.acquire import ingest_local
from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.installed_tree_replay import (
    ArchivedTreeMember,
    InstalledTreeInventory,
    InstalledTreeVerificationError,
    verify_installed_tree_members,
)


class InstalledTreeReplayTests(unittest.TestCase):
    def test_nested_tree_counts_and_tamper_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "nested").mkdir(parents=True)
            (source / "SKILL.md").write_bytes(b"skill")
            executable = source / "nested" / "run.sh"
            executable.write_bytes(b"#!/bin/sh\n")
            executable.chmod(0o755)

            cas = CAS(root / "cas")
            manifest = ingest_local(source, cas)
            manifest_raw = canonical_json(manifest)
            manifest_digest = cas.put(
                BytesIO(manifest_raw),
                max_bytes=len(manifest_raw),
            )
            members = (
                ArchivedTreeMember(".", "directory", 0o555, 0),
                ArchivedTreeMember(
                    "SKILL.md",
                    "file",
                    0o444,
                    5,
                    b"skill",
                ),
                ArchivedTreeMember("nested", "directory", 0o555, 0),
                ArchivedTreeMember(
                    "nested/run.sh",
                    "file",
                    0o555,
                    10,
                    b"#!/bin/sh\n",
                ),
            )

            self.assertEqual(
                verify_installed_tree_members(cas, manifest_digest, members),
                InstalledTreeInventory(
                    tree_digest=manifest["tree_digest"],
                    file_count=2,
                    directory_count=2,
                    payload_bytes=15,
                ),
            )

            tampered = {
                "missing": members[:-1],
                "extra": (
                    *members,
                    ArchivedTreeMember("extra", "file", 0o444, 0, b""),
                ),
                "symlink": (
                    members[0],
                    replace(members[1], kind="symlink"),
                    *members[2:],
                ),
                "special": (
                    members[0],
                    replace(members[1], kind="special"),
                    *members[2:],
                ),
                "mode": (
                    members[0],
                    replace(members[1], mode=0o644),
                    *members[2:],
                ),
                "size": (
                    members[0],
                    replace(members[1], size=4),
                    *members[2:],
                ),
                "content": (
                    members[0],
                    replace(members[1], content=b"other"),
                    *members[2:],
                ),
            }
            for name, changed in tampered.items():
                with (
                    self.subTest(name=name),
                    self.assertRaises(InstalledTreeVerificationError),
                ):
                    verify_installed_tree_members(cas, manifest_digest, changed)


if __name__ == "__main__":
    unittest.main()
