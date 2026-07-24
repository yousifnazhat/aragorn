from __future__ import annotations

from io import BytesIO
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts.extract_pinned_sdist import ExtractionError, extract_sdist


class PinnedSdistExtractionTests(unittest.TestCase):
    def test_extracts_regular_files_under_the_expected_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                content = b"package source"
                member = tarfile.TarInfo("package-1.0/module.py")
                member.size = len(content)
                output.addfile(member, BytesIO(content))

            destination = root / "extracted"
            extract_sdist(archive, destination, "package-1.0")

            self.assertEqual(
                (destination / "package-1.0" / "module.py").read_bytes(), content
            )

    def test_rejects_traversal_and_links(self) -> None:
        for name, member_type in (
            ("package-1.0/../escape", tarfile.REGTYPE),
            ("package-1.0/link", tarfile.SYMTYPE),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "source.tar.gz"
                with tarfile.open(archive, "w:gz") as output:
                    member = tarfile.TarInfo(name)
                    member.type = member_type
                    if member_type == tarfile.SYMTYPE:
                        member.linkname = "/etc/passwd"
                    output.addfile(member, BytesIO(b""))

                with self.assertRaises(ExtractionError):
                    extract_sdist(archive, root / "extracted", "package-1.0")


if __name__ == "__main__":
    unittest.main()
