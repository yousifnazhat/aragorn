"""Focused assembly and refusal checks using inert temporary file trees."""
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_split_guest_payload as batch
from scripts.build_pi_core_linux import BuildError


def file(p, data):
    return dict(type="file", path=str(p), mode=0o444, uid=0, gid=0, size=len(data), sha256=batch.sha256(data))


class SplitGuestPayload(unittest.TestCase):
    def setUp(self):
        self.os_root, self.runtime = batch.WORKER_ROOTS
        self.host = {"schema": batch.SCHEMA, "entries": [batch._dir("/usr", 0o755), file("/usr/host", b"host")]}
        self.worker = {"entries": [batch._dir(self.os_root, 0o755), batch._dir(self.os_root / "dev", 0o555),
                                   batch._dir(self.runtime, 0o755), file(self.runtime / "node", b"node")]}

    def test_split_roots_and_empty_outside_mountpoints_publish_without_permissions_changing_content(self):
        point = "/var/lib/aragorn/example"
        manifest = batch.compose(self.host, self.worker, {point: 0o700})
        indexed = {r["path"]: r for r in manifest["entries"]}
        self.assertEqual(indexed[str(self.runtime)]["mode"], 0o755)
        self.assertEqual(indexed[str(self.os_root / "dev")]["mode"], 0o555)
        self.assertEqual(indexed[point], batch._dir(point, 0o700))
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "root"
            raw = {"/usr/host": b"host", str(self.runtime / "node"): b"node"}
            batch._stage(root, manifest, lambda r: raw[r["path"]])
            self.assertEqual(list((root / point[1:]).iterdir()), [])
            self.assertEqual((root / str(self.runtime / "node")[1:]).read_bytes(), b"node")

    def test_host_shadow_missing_worker_ancestor_wrong_root_mode_and_overlapping_mount_refuse(self):
        for host, rows, mounts in (
                (self.host | {"entries": [*self.host["entries"], file(self.runtime, b"other")]},
                 self.worker["entries"], {}),
                (self.host, self.worker["entries"] + [file(self.os_root / "missing/lib", b"bad")], {}),
                (self.host, [batch._dir(self.os_root, 0o555), *self.worker["entries"][1:]], {}),
                (self.host, self.worker["entries"], {"/var/lib/aragorn": 0o700}),
                (self.host, self.worker["entries"], {str(self.runtime / "writable"): 0o700})):
            with self.subTest(mounts=mounts, rows=rows), self.assertRaises(BuildError):
                batch.compose(host, {"entries": rows}, mounts)

    def test_same_path_selects_only_declared_source_generation_and_refuses_hardlink_substitution(self):
        p = "/usr/host"
        base, new = file(p, b"base"), file(p, b"new")
        with TemporaryDirectory() as tmp:
            tmp = Path(tmp).resolve()
            old, successor = tmp / "base", tmp / "successor"
            with patch.object(batch.image, "WORK", old), patch.object(batch, "PRIOR", successor):
                for parent, raw in ((old / "root", b"base"), (successor / "changed-files", b"new")):
                    target = parent / p[1:]
                    target.parent.mkdir(parents=True)
                    batch.image.new(target, raw, 0o444)
                self.assertEqual(batch._host_bytes(base, {p: base}), b"base")
                self.assertEqual(batch._host_bytes(new, {p: base}), b"new")
                os.link(target, successor / "alias")
                with self.assertRaisesRegex(BuildError, "single physical source"):
                    batch._host_bytes(new, {p: base})

    def test_partial_output_from_bad_bytes_is_preserved_without_sealing_or_reuse(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "root"
            with self.assertRaisesRegex(BuildError, "commitment"):
                batch._stage(root, self.host, lambda r: b"xxxx")
            self.assertTrue(root.is_dir())
            self.assertFalse((root / "usr/host").exists())
            self.assertEqual(stat.S_IMODE((root / "usr").stat().st_mode), 0o700)
            with self.assertRaises(FileExistsError):
                batch._stage(root, self.host, lambda r: b"host")
