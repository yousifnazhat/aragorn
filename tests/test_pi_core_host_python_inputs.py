"""Only new source-selection/refusal rules; no OCI extraction in this stage."""
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_host_python_inputs as host


class HostPythonRefusals(TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.release = self.root / host.RELEASE
        self.release.parent.mkdir(parents=True)
        self.archive = self.root / "input.tar"
        self.archive.write_bytes(b"good")
        self.source = self.root / "source.json"
        self.source.write_bytes(b"{\n}\n")
        self.release.write_bytes(host.image.canonical({
            "source_pin": {"path": self.source.name, "digest": host.image.pin(b"{}")},
            "archive": {"path": self.archive.name, "bytes": 4, "sha256": host.image.pin(b"good")[7:]}}))
        self.enterContext(patch.object(host, "RELEASE_PIN", host.image.pin(self.release.read_bytes())))
        self.enterContext(patch.object(host, "SOURCE_RAW_PIN", host.image.pin(self.source.read_bytes())))
        self.parse = self.enterContext(patch.object(host.image.os_root, "read_source"))

    def test_resealed_release_and_changed_oci_pin_refused_before_archive(self):
        for path in (self.release, self.source):
            before = path.read_bytes()
            path.write_bytes(before + b" ")
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, "differs from pin"):
                host.prepare_host_python_inputs(self.root)
            path.write_bytes(before)
        self.parse.assert_not_called()

    def test_raw_source_identity_does_not_replace_canonical_pin(self):
        self.source.write_bytes(b'{"different":true}')
        with patch.object(host, "SOURCE_RAW_PIN", host.image.pin(self.source.read_bytes())):
            with self.assertRaisesRegex(ValueError, "canonical OCI source differs"):
                host.prepare_host_python_inputs(self.root)
        self.parse.assert_not_called()

    def test_wrong_size_and_same_size_substitution_refused_before_parse(self):
        for raw, reason in ((b"x", "size differs"), (b"evil", "differs from pin")):
            self.archive.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, reason):
                host.prepare_host_python_inputs(self.root)
        self.parse.assert_not_called()

    def test_linked_archive_refused_even_if_bytes_match(self):
        other = self.archive.with_name("other.tar")
        self.archive.rename(other)
        self.archive.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "linked or nonregular"):
            host.prepare_host_python_inputs(self.root)
        self.parse.assert_not_called()

    def test_actual_reader_must_confirm_authenticated_archive(self):
        self.parse.return_value = None, {"archive_bytes": 4, "archive_sha256": "f" * 64}
        with self.assertRaisesRegex(ValueError, "changed during parsing"):
            host.prepare_host_python_inputs(self.root)
        self.parse.assert_called_once()

    def test_selected_member_alias_writable_source_and_unpinned_bytes_rejected(self):
        image = host.image
        tree = image.os_root.ImageTree()
        tree.entries[image.PYTHON_SOURCE] = {"kind": "file", "mode": 0o755, "raw": b"changed"}
        soname = "usr/local/lib/libpython3.12.so.1.0"
        tree.entries[soname] = {"kind": "file", "mode": 0o755, "raw": b"lib"}
        stdlib = image.STDLIB_SOURCE + "/argparse.py"
        other = image.STDLIB_SOURCE + "/other.py"
        tree.entries[other] = {"kind": "file", "mode": 0o644, "raw": b"same"}
        with patch.object(image, "selected_python_files",
                          return_value=({image.STDLIB + "/argparse.py": {"mode": 0o444}}, [])):
            for entry, reason in (({"kind": "symlink", "target": "other.py"}, "unsafe host Python"),
                                  ({"kind": "file", "mode": 0o666, "raw": b"same"}, "unsafe host Python"),
                                  (tree.entries[other], "differs from independently pinned rows")):
                tree.entries[stdlib] = entry
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    host._projection(tree)
