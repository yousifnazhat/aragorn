"""Inert archive/ELF fixtures only; no image, target or compiler executes."""

from __future__ import annotations

import gzip
import importlib.util
import io
import json
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("pi_os_root", _ROOT / "scripts/prepare_pi_core_os_root.py")
assert _SPEC and _SPEC.loader
os_root = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(os_root)


def elf(*, needed=(), soname=None, interpreter=None, extra=(), machine=183) -> bytes:
    raw = bytearray(2048)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", raw, 16, 3, machine, 1)
    struct.pack_into("<Q", raw, 32, 64)
    count = 3 if interpreter else 2
    struct.pack_into("<HHH", raw, 52, 64, 56, count)
    table = bytearray(b"\0")
    offsets = []
    for value in (*needed, *((soname,) if soname else ())):
        offsets.append(len(table))
        table.extend(value.encode("ascii") + b"\0")
    dynamic = [(5, 0x400000 + 1024), (10, len(table))]
    dynamic.extend((1, value) for value in offsets[:len(needed)])
    if soname:
        dynamic.append((14, offsets[-1]))
    dynamic.extend(extra)
    dynamic.append((0, 0))
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 0x400000, 0, len(raw), len(raw), 4096)
    struct.pack_into("<IIQQQQQQ", raw, 120, 2, 4, 512, 0x400000 + 512, 0, len(dynamic) * 16, len(dynamic) * 16, 8)
    if interpreter:
        text = interpreter.encode("ascii") + b"\0"
        struct.pack_into("<IIQQQQQQ", raw, 176, 3, 4, 256, 0x400000 + 256, 0, len(text), len(text), 1)
        raw[256:256 + len(text)] = text
    for index, (tag, value) in enumerate(dynamic):
        struct.pack_into("<qQ", raw, 512 + 16 * index, tag, value)
    raw[1024:1024 + len(table)] = table
    return bytes(raw)


def layer(rows) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, kind, value in rows:
            item = tarfile.TarInfo(name)
            if kind == "file":
                item.size = len(value)
                item.mode = 0o755 if name.endswith(("/env", "/ld-linux-aarch64.so.1")) else 0o644
                archive.addfile(item, io.BytesIO(value))
            elif kind == "directory":
                item.type = tarfile.DIRTYPE
                item.mode = 0o755
                archive.addfile(item)
            elif kind in ("symlink", "hardlink"):
                item.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                item.linkname = value
                archive.addfile(item)
            elif kind == "device":
                item.type = tarfile.CHRTYPE
                archive.addfile(item)
            else:
                raise ValueError(kind)
    return out.getvalue()


def save_archive(layers):
    blobs = {}
    descriptors = []
    for raw in layers:
        compressed = gzip.compress(raw, mtime=0)
        digest = os_root.pin(compressed)
        blobs["blobs/sha256/" + digest[7:]] = compressed
        descriptors.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest, "size": len(compressed)})
    config = {"os": "linux", "architecture": "arm64", "variant": "v8",
              "rootfs": {"type": "layers", "diff_ids": [os_root.pin(raw) for raw in layers]}}
    config_raw = os_root.canonical(config)
    config_digest = os_root.pin(config_raw)
    blobs["blobs/sha256/" + config_digest[7:]] = config_raw
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"digest": config_digest, "size": len(config_raw)}, "layers": descriptors}
    manifest_raw = os_root.canonical(manifest)
    manifest_digest = os_root.pin(manifest_raw)
    blobs["blobs/sha256/" + manifest_digest[7:]] = manifest_raw
    platform = {"os": "linux", "architecture": "arm64", "variant": "v8"}
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{"platform": platform, "digest": manifest_digest, "size": len(manifest_raw)}]}
    index_raw = os_root.canonical(index)
    index_digest = os_root.pin(index_raw)
    blobs["blobs/sha256/" + index_digest[7:]] = index_raw
    blobs["manifest.json"] = os_root.canonical([{
        "Config": "blobs/sha256/" + config_digest[7:], "RepoTags": None,
        "Layers": ["blobs/sha256/" + item["digest"][7:] for item in descriptors]}])
    source = {"schema": "aragorn/pi-core-os-source/v1", "source_reference": "python@" + index_digest,
        "index_digest": index_digest, "platform": platform, "platform_manifest_digest": manifest_digest,
        "config_digest": config_digest, "layer_diff_ids": config["rootfs"]["diff_ids"]}
    return layer([(name, "file", raw) for name, raw in blobs.items()]), source


def closure_layer():
    interpreter = "/lib/ld-linux-aarch64.so.1"
    names = ["usr/bin/env", "usr/lib/ld-linux-aarch64.so.1", "usr/lib/aarch64-linux-gnu/libfixture.so.1",
             "usr/lib/aarch64-linux-gnu/libsecond.so.1"]
    rows = [("lib", "symlink", "usr/lib"),
        (names[0], "file", elf(interpreter=interpreter, needed=("libfixture.so.1",))),
        (names[1], "file", elf(soname="ld-linux-aarch64.so.1")),
        (names[2], "file", elf(soname="libfixture.so.1", needed=("libsecond.so.1",))),
        (names[3], "file", elf(soname="libsecond.so.1")),
        ("var/lib/dpkg/info/fixture-os.list", "file", ("\n".join("/" + name for name in names) + "\n").encode()),
        ("var/lib/dpkg/status", "file", b"Package: fixture-os\nVersion: 1.0\nArchitecture: arm64\n\n"),
        ("usr/share/doc/fixture-os/copyright", "file", b"Inert fixture license metadata; no distribution claim.\n")]
    return layer(rows)


class PiCoreOSRootTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="aragorn-os-inert-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name).resolve()
        for target in ("subprocess.Popen", "subprocess.run", "os.system", "os.execve"):
            patch = mock.patch(target, side_effect=AssertionError("target/process execution prohibited"))
            patch.start()
            self.addCleanup(patch.stop)

    def archive(self, layers=None):
        raw, source = save_archive(layers or [closure_layer()])
        path = self.path / "source.tar"
        path.write_bytes(raw)
        return path, source

    def test_exact_oci_chain_produces_verified_virtual_files(self):
        path, source = self.archive()
        tree, evidence = os_root.read_source(path, source)
        resolved, member = tree.file("lib/ld-linux-aarch64.so.1")
        self.assertEqual(resolved, "usr/lib/ld-linux-aarch64.so.1")
        self.assertEqual(os_root.elf_dependencies(member["raw"])["soname"], "ld-linux-aarch64.so.1")
        self.assertEqual(evidence["source_config_digest"], source["config_digest"])
        self.assertNotEqual(source["config_digest"], source["index_digest"])

    def test_wrong_index_pin_is_refused(self):
        path, source = self.archive()
        source["index_digest"] = "sha256:" + "a" * 64
        source["source_reference"] = "python@" + source["index_digest"]
        with self.assertRaisesRegex(os_root.OSRootError, "blob digest"):
            os_root.read_source(path, source)

    def test_wrong_platform_pin_is_refused(self):
        path, source = self.archive()
        source["platform"]["architecture"] = "amd64"
        with self.assertRaisesRegex(os_root.OSRootError, "unsupported OS source"):
            os_root.read_source(path, source)

    def test_changed_layer_diffid_is_refused(self):
        path, source = self.archive()
        source["layer_diff_ids"][0] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(os_root.OSRootError, "layer pins"):
            os_root.read_source(path, source)

    def test_traversal_in_layer_is_refused(self):
        tree = os_root.ImageTree()
        with self.assertRaisesRegex(os_root.OSRootError, "unsafe archive path"):
            tree.apply_layer(layer([("../escape", "file", b"bad")]))

    def test_image_symlink_cannot_escape_root(self):
        tree = os_root.ImageTree()
        with self.assertRaisesRegex(os_root.OSRootError, "escapes virtual root"):
            tree.apply_layer(layer([("link", "symlink", "../../host")]))

    def test_image_symlink_cycles_are_bounded(self):
        tree = os_root.ImageTree()
        tree.apply_layer(layer([("a", "symlink", "b"), ("b", "symlink", "a")]))
        with self.assertRaisesRegex(os_root.OSRootError, "cycle"):
            tree.resolve("a")

    def test_whiteout_removes_lower_file_without_touching_host(self):
        tree = os_root.ImageTree()
        tree.apply_layer(layer([("a", "file", b"lower"), ("b", "file", b"keep")]))
        tree.apply_layer(layer([(".wh.a", "file", b"")]))
        self.assertNotIn("a", tree.entries)
        self.assertEqual(tree.file("b")[1]["raw"], b"keep")

    def test_opaque_whiteout_preserves_new_same_layer_members(self):
        tree = os_root.ImageTree()
        tree.apply_layer(layer([("dir", "directory", None), ("dir/old", "file", b"old")]))
        tree.apply_layer(layer([("dir/new", "file", b"new"), ("dir/.wh..wh..opq", "file", b"")]))
        self.assertNotIn("dir/old", tree.entries)
        self.assertEqual(tree.file("dir/new")[1]["raw"], b"new")

    def test_hardlink_preserves_old_bytes_after_source_replacement(self):
        tree = os_root.ImageTree()
        tree.apply_layer(layer([("source", "file", b"old"), ("alias", "hardlink", "source")]))
        tree.apply_layer(layer([("source", "file", b"new")]))
        self.assertEqual(tree.file("alias")[1]["raw"], b"old")
        self.assertEqual(tree.file("source")[1]["raw"], b"new")

    def test_unapproved_device_is_refused(self):
        with self.assertRaisesRegex(os_root.OSRootError, "special entry"):
            os_root.ImageTree().apply_layer(layer([("device", "device", None)]))

    def test_duplicate_layer_paths_are_refused(self):
        with self.assertRaisesRegex(os_root.OSRootError, "duplicate layer path"):
            os_root.ImageTree().apply_layer(layer([("a", "file", b"1"), ("a", "file", b"2")]))

    def test_elf_interpreter_and_needed_are_read_statically(self):
        value = os_root.elf_dependencies(elf(interpreter="/lib/ld-linux-aarch64.so.1", needed=("libx.so.1",)))
        self.assertEqual(value, {"interpreter": "/lib/ld-linux-aarch64.so.1", "needed": ["libx.so.1"], "soname": None})

    def test_wrong_elf_architecture_is_refused(self):
        with self.assertRaisesRegex(os_root.OSRootError, "arm64"):
            os_root.elf_dependencies(elf(machine=62))

    def test_elf_rpath_is_refused_without_ambient_resolution(self):
        with self.assertRaisesRegex(os_root.OSRootError, "RPATH"):
            os_root.elf_dependencies(elf(extra=((15, 0),)))

    def test_out_of_bounds_program_headers_are_refused(self):
        raw = bytearray(elf())
        struct.pack_into("<Q", raw, 32, len(raw) - 4)
        with self.assertRaisesRegex(os_root.OSRootError, "program table"):
            os_root.elf_dependencies(bytes(raw))

    def test_transitive_elf_dependencies_resolve_virtual_aliases(self):
        tree = os_root.ImageTree()
        tree.apply_layer(closure_layer())
        selected, edges = os_root.closed_elf_inventory(tree, elf(interpreter="/lib/ld-linux-aarch64.so.1", needed=("libfixture.so.1",)))
        self.assertIn("lib/aarch64-linux-gnu/libsecond.so.1", selected)
        self.assertEqual(selected["lib/ld-linux-aarch64.so.1"]["source_path"], "usr/lib/ld-linux-aarch64.so.1")
        self.assertTrue(any(row["requested"] == "libsecond.so.1" for row in edges))

    def test_missing_dependency_never_becomes_a_fake_closure(self):
        tree = os_root.ImageTree()
        tree.apply_layer(closure_layer())
        with self.assertRaisesRegex(os_root.OSRootError, "unresolved ELF dependency"):
            os_root.closed_elf_inventory(tree, elf(interpreter="/lib/ld-linux-aarch64.so.1", needed=("missing.so",)))

    def test_nonexecutable_interpreter_is_refused(self):
        tree = os_root.ImageTree()
        tree.apply_layer(closure_layer())
        tree.entries["usr/lib/ld-linux-aarch64.so.1"]["mode"] = 0o644
        with self.assertRaisesRegex(os_root.OSRootError, "interpreter is not executable"):
            os_root.closed_elf_inventory(tree, elf(interpreter="/lib/ld-linux-aarch64.so.1"))

    def test_different_default_path_candidates_are_refused(self):
        tree = os_root.ImageTree()
        tree.apply_layer(closure_layer())
        tree.apply_layer(layer([("usr/lib/libfixture.so.1", "file", elf(soname="libfixture.so.1"))]))
        with self.assertRaisesRegex(os_root.OSRootError, "ambiguous library"):
            os_root.closed_elf_inventory(tree, elf(interpreter="/lib/ld-linux-aarch64.so.1", needed=("libfixture.so.1",)))

    def test_mismatched_library_soname_is_refused(self):
        tree = os_root.ImageTree()
        tree.apply_layer(closure_layer())
        tree.apply_layer(layer([("usr/lib/aarch64-linux-gnu/libfixture.so.1", "file", elf(soname="different.so"))]))
        with self.assertRaisesRegex(os_root.OSRootError, "SONAME"):
            os_root.closed_elf_inventory(tree, elf(interpreter="/lib/ld-linux-aarch64.so.1", needed=("libfixture.so.1",)))

    def test_preparation_emits_regular_aliases_bound_inventory_and_licenses(self):
        archive, source = self.archive()
        node = self.path / "node"
        raw = elf(interpreter="/lib/ld-linux-aarch64.so.1", needed=("libfixture.so.1",))
        node.write_bytes(raw)
        output = self.path / "prepared"
        receipt = os_root.prepare_os_root(archive, node, node_digest=os_root.pin(raw), output=output, source=source)
        self.assertEqual(receipt["status"], "PREPARED_NOT_INSTALLED_OR_EXECUTED")
        self.assertFalse(receipt["executed_target_code"])
        self.assertFalse(receipt["native_cleanup_verified"])
        self.assertEqual(receipt["closure_digest"], os_root.pin(os_root.canonical(receipt["protected_tree"])))
        self.assertTrue((output / "root/lib/ld-linux-aarch64.so.1").is_file())
        self.assertFalse((output / "root/lib").is_symlink())
        self.assertTrue((output / "root/var/lib/aragorn/admitted").is_dir())
        self.assertTrue((output / "root/var/tmp").is_dir())
        self.assertEqual(list((output / "root/var/tmp").iterdir()), [])
        self.assertTrue((output / "provenance/licenses/fixture-os.copyright").is_file())
        self.assertEqual((output / "root/usr/bin/env").stat().st_mode & 0o777, 0o555)
        self.assertEqual((output / "root/lib/ld-linux-aarch64.so.1").stat().st_mode & 0o777, 0o555)
        self.assertEqual(receipt["protected_tree"]["directories"], sorted(receipt["protected_tree"]["directories"]))

    def test_wrong_compiled_node_pin_prevents_staging(self):
        archive, source = self.archive()
        node = self.path / "node"
        node.write_bytes(elf())
        output = self.path / "refused"
        with self.assertRaisesRegex(os_root.OSRootError, "Node bytes differ"):
            os_root.prepare_os_root(archive, node, node_digest="sha256:" + "0" * 64, output=output, source=source)
        self.assertFalse(output.exists())

    def test_existing_output_is_never_overwritten(self):
        archive, source = self.archive()
        node = self.path / "node"
        raw = elf(interpreter="/lib/ld-linux-aarch64.so.1")
        node.write_bytes(raw)
        output = self.path / "existing"
        output.mkdir()
        marker = output / "user.txt"
        marker.write_bytes(b"preserve")
        with self.assertRaisesRegex(os_root.OSRootError, "fresh and unlinked"):
            os_root.prepare_os_root(archive, node, node_digest=os_root.pin(raw), output=output, source=source)
        self.assertEqual(marker.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
