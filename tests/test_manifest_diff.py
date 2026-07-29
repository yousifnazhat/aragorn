from __future__ import annotations

import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn.acquire import ingest_local
from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.manifest_diff import (
    ManifestDiffError,
    diff_verified_manifests,
    diff_verified_manifests_between,
)


class ManifestDiffTests(unittest.TestCase):
    def test_verified_diff_is_canonical_and_malformed_manifest_fails_closed(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            cas = CAS(root / "state")
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            for path, content in {
                "change.md": b"old",
                "keep.md": b"same",
                "mode.sh": b"same mode-sensitive bytes",
                "remove.md": b"removed",
            }.items():
                (old / path).write_bytes(content)
            for path, content in {
                "add.md": b"added",
                "change.md": b"new",
                "keep.md": b"same",
                "mode.sh": b"same mode-sensitive bytes",
            }.items():
                (new / path).write_bytes(content)
            (new / "mode.sh").chmod(0o755)

            def retain(source: Path) -> tuple[dict, str]:
                manifest = ingest_local(source, cas)
                raw = canonical_json(manifest)
                return manifest, cas.put(BytesIO(raw), max_bytes=len(raw))

            old_manifest, old_digest = retain(old)
            new_manifest, new_digest = retain(new)
            expected = {
                "schema": "aragorn/manifest-update-diff/v1",
                "authority": "UPDATE_DIFF_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY",
                "old": {
                    "manifest_digest": old_digest,
                    "tree_digest": old_manifest["tree_digest"],
                },
                "new": {
                    "manifest_digest": new_digest,
                    "tree_digest": new_manifest["tree_digest"],
                },
                "added_paths": ["add.md"],
                "removed_paths": ["remove.md"],
                "changed_paths": ["change.md", "mode.sh"],
            }
            observed = diff_verified_manifests(cas, old_digest, new_digest)
            self.assertEqual(observed, expected)
            self.assertEqual(canonical_json(observed), canonical_json(expected))

            old_cas = CAS(root / "old-state")
            new_cas = CAS(root / "new-state")
            old_cross = ingest_local(old, old_cas)
            new_cross = ingest_local(new, new_cas)
            old_raw = canonical_json(old_cross)
            new_raw = canonical_json(new_cross)
            old_cross_digest = old_cas.put(
                BytesIO(old_raw),
                max_bytes=len(old_raw),
            )
            new_cross_digest = new_cas.put(
                BytesIO(new_raw),
                max_bytes=len(new_raw),
            )
            self.assertEqual(
                diff_verified_manifests_between(
                    old_cas,
                    old_cross_digest,
                    new_cas,
                    new_cross_digest,
                ),
                expected,
            )

            malformed = cas.put(BytesIO(b"{}"), max_bytes=2)
            with self.assertRaisesRegex(
                ManifestDiffError,
                "cannot verify update manifests",
            ):
                diff_verified_manifests(cas, malformed, new_digest)


if __name__ == "__main__":
    unittest.main()
