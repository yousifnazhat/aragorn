"""Fail-closed staging and library resolution checks; no guest or target processes."""
import io
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest

from scripts import inspect_pi_core_host_clients as clients
from scripts import prepare_pi_core_host_sysroot as sysroot
from scripts.build_pi_core_linux import regular_bytes, sha256


class ClientInspection(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.stage = self.root / "stage"
        self.bin = self.stage / "usr/bin"
        self.bin.mkdir(parents=True)
        for name in clients.CLIENTS:
            # Only the installed entry/mode checks inspect these marker bytes.
            path = self.bin / name
            path.write_bytes(bytes(16) + b"\x03\x00" + name.encode())
            path.chmod(0o755)

    def test_extra_installed_artifact_is_refused(self):
        (self.bin / "systemd").touch()
        with self.assertRaisesRegex(ValueError, "exactly the three"):
            clients._clients(self.stage)

    def test_advertised_features_are_from_the_authenticated_vendor_binary(self):
        deb = regular_bytes(sysroot.WORK.parent / "libsystemd-shared.deb", 2377906)
        self.assertEqual(sha256(deb), "754ac748a6525d153f0edffb419a5b84b5c2b992812219dbe31fa705203a2bdc")
        decoder = sysroot.ZSTD.resolve(strict=True)
        self.assertEqual(sha256(regular_bytes(decoder, 8 << 20)), sysroot.ZSTD_SHA)
        with tarfile.open(fileobj=io.BytesIO(sysroot.data_tar(deb, decoder))) as archive:
            member = archive.getmember("./usr/lib/aarch64-linux-gnu/systemd/libsystemd-shared-259.so")
            self.assertTrue(member.isfile())
            raw = archive.extractfile(member).read()
        self.assertEqual(sha256(raw), "d286746d625d6c1c0160985519edb7e97cd649a61b5a94046c7096c9f39f501c")
        self.assertTrue(clients._vendor_features(raw))
        changed = raw.replace(clients.FEATURES, clients.FEATURES.replace(b"+BTF", b"-BTF"))
        self.assertFalse(clients._vendor_features(changed + b"\x00" + clients.FEATURES + b"\x00"))

    def test_linked_or_setid_clients_are_refused(self):
        entry = self.bin / "busctl"
        entry.chmod(0o4755)
        with self.assertRaisesRegex(ValueError, "mode or link"):
            clients._clients(self.stage)
        entry.unlink()
        entry.symlink_to(self.bin / "systemctl")
        with self.assertRaisesRegex(ValueError, "mode or link"):
            clients._clients(self.stage)

    def test_unreviewed_attempt_is_refused_before_loading_any_elf(self):
        with self.assertRaisesRegex(ValueError, "unreviewed build attempt"):
            clients.verify_attempt(self.root, {"fingerprint": self.root.name, "clients": {}})

    def test_staged_bytes_must_match_pins_before_host_elf_inspection(self):
        with self.assertRaisesRegex(ValueError, "differ from reviewed build"):
            clients._inspect(self.stage, self.root, {n: "0" * 64 for n in clients.CLIENTS}, {})

    def test_replacing_client_with_another_client_is_refused(self):
        (self.bin / "busctl").write_bytes((self.bin / "systemctl").read_bytes())
        with self.assertRaisesRegex(ValueError, "duplicate client bytes"):
            clients._clients(self.stage)

    def test_escape_ambiguous_and_substitute_libraries_are_refused(self):
        libdir = self.root / "usr/lib"
        multiarch = libdir / "aarch64-linux-gnu"
        multiarch.mkdir(parents=True)
        name = "libfixture.so.1"
        p = multiarch / name
        p.symlink_to(Path(__file__).resolve())
        with self.assertRaisesRegex(ValueError, "outside pinned sysroot"):
            clients._library(self.root, name)
        p.unlink()
        p.write_bytes(b"first")
        with self.assertRaisesRegex(ValueError, "differs from authenticated inventory"):
            clients._library(self.root, name, {})
        (libdir / name).write_bytes(b"second")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            clients._library(self.root, name)
        (libdir / clients.LOADER).write_bytes(b"not the pinned loader")
        with self.assertRaisesRegex(ValueError, "immutable guest library differs"):
            clients._library(self.root, clients.LOADER)
