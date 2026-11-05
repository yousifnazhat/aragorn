"""New static image/closure branches only; inert bytes, no target execution."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from tests.test_pi_core_os_root import elf

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pi_service_image_fixture", ROOT / "scripts/prepare_pi_core_service_image.py")
assert SPEC and SPEC.loader
image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(image)


def python_elf(*, rpath="$ORIGIN/../lib", needed=("libpython3.12.so.1.0", "libc.so.6"), duplicate=False):
    raw = bytearray(elf(needed=(*needed, rpath), interpreter="/lib/ld-linux-aarch64.so.1"))
    offset = 512 + 16 * (2 + len(needed))
    _, string_offset = struct.unpack_from("<qQ", raw, offset)
    struct.pack_into("<qQ", raw, offset, 29, string_offset)
    if duplicate:
        struct.pack_into("<qQ", raw, offset + 16, 15, string_offset)
        struct.pack_into("<qQ", raw, offset + 32, 0, 0)
        struct.pack_into("<Q", raw, 120 + 32, 16 * (5 + len(needed)))
        struct.pack_into("<Q", raw, 120 + 40, 16 * (5 + len(needed)))
    return bytes(raw)


def image_tree():
    tree = image.os_root.ImageTree()

    def file(name, raw, mode=0o644):
        tree.entries[name] = {"kind": "file", "raw": raw, "mode": mode}

    file(image.PYTHON_SOURCE, python_elf(), 0o755)
    file("usr/local/lib/libpython3.12.so.1.0", elf(needed=("libc.so.6",), soname="libpython3.12.so.1.0"), 0o755)
    file("lib/ld-linux-aarch64.so.1", elf(soname="ld-linux-aarch64.so.1"), 0o755)
    libraries = {"libc.so.6": ("ld-linux-aarch64.so.1",), "libssl.so.3": ("libcrypto.so.3",), "libcrypto.so.3": ("libc.so.6",), "libffi.so.8": ("libc.so.6",)}
    for name, dependencies in libraries.items():
        file("usr/lib/aarch64-linux-gnu/" + name, elf(needed=dependencies, soname=name))
    for name in ("os.py", "ssl.py", "socket.py", "encodings/__init__.py", "json/__init__.py", "ctypes/__init__.py"):
        file(image.STDLIB_SOURCE + "/" + name, b"# inert stdlib fixture\n")
    for name, dependencies in (("_ssl", ("libssl.so.3",)), ("_socket", ("libc.so.6",)), ("_ctypes", ("libffi.so.8",)),
                               ("_tkinter", ("libtk8.6.so",)), ("_testcapi", ("libmissingtest.so",))):
        file(image.STDLIB_SOURCE + "/lib-dynload/" + name + ".cpython-312-aarch64-linux-gnu.so", elf(needed=dependencies), 0o755)
    for name in ("site-packages/pip/__init__.py", "ensurepip/__init__.py", "tkinter/__init__.py", "turtle.py", "__pycache__/os.pyc", "config-3.12/Makefile"):
        file(image.STDLIB_SOURCE + "/" + name, b"excluded fixture\n")
    file(image.STDLIB_SOURCE + "/LICENSE.txt", b"CPython fixture license, no distribution claim\n")
    distro = ["lib/ld-linux-aarch64.so.1", *("usr/lib/aarch64-linux-gnu/" + name for name in libraries)]
    file("var/lib/dpkg/info/fixture-runtime:arm64.list", ("\n".join("/" + name for name in distro) + "\n").encode())
    file("var/lib/dpkg/status", b"Package: fixture-runtime\nVersion: 1.0\nArchitecture: arm64\n\n")
    file("usr/share/doc/fixture-runtime/copyright", b"Debian fixture license, no distribution claim\n")
    return tree


class PiCoreServiceImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pi-service-image-inert-")
        self.path = Path(self.temp.name).resolve()
        self.addCleanup(self._cleanup)
        self.source = self.path / "src"
        self.wrappers = self.path / "wrappers"
        self.source.mkdir()
        self.wrappers.mkdir()
        self.inventory = {}
        self.add_source("aragorn/__init__.py", b"# inert package\n")
        for module in image.SOURCE_SEEDS:
            self.add_source(module.replace(".", "/") + ".py", b"import json\nimport sys\n")
        self.wrapper_inventory = {}
        for role in image.ROLES:
            raw = b"# inert wrapper\n"
            (self.wrappers / (role + ".py")).write_bytes(raw)
            self.wrapper_inventory[role + ".py"] = image.pin(raw)
        self.tree = image_tree()
        self.output = self.path / "assembled"
        for target in ("subprocess.Popen", "subprocess.run", "os.system", "os.execve", "socket.socket", "socket.create_connection"):
            self.enterContext(mock.patch(target, side_effect=AssertionError("no execution or network")))

    def _cleanup(self):
        # Only this fixture's owned output was made readonly by assembly.
        for path, directories, _ in os.walk(self.path):
            Path(path).chmod(0o700)
            for name in directories:
                (Path(path) / name).chmod(0o700)
        self.temp.cleanup()

    def add_source(self, name, raw):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.inventory[name] = image.pin(raw)

    def closure(self):
        selected, _ = image.selected_python_files(self.tree)
        return image.source_closure(self.source, self.inventory, image.stdlib_modules(selected))

    def assemble(self):
        with mock.patch.object(image.os_root, "read_source", return_value=(self.tree, {"archive_sha256": "a" * 64})):
            return image.prepare_service_image(self.path / "inert.tar", source_pin={"fixture": True},
                source_root=self.source, wrapper_root=self.wrappers, expected_source_inventory=self.inventory,
                expected_wrapper_inventory=self.wrapper_inventory, output=self.output)

    def test_static_image_exact_layout_and_binding(self):
        receipt = self.assemble()
        manifest = json.loads((self.output / "manifest.json").read_bytes())
        binding = json.loads((self.output / "runtime-binding.json").read_bytes())
        self.assertEqual(receipt["status"], "PREPARED_NOT_INSTALLED_OR_EXECUTED")
        self.assertFalse(receipt["executed_target_code"])
        self.assertFalse(receipt["native_cleanup_verified"])
        self.assertEqual(binding["schema"], "aragorn/pi-core-service-runtime-binding/v2")
        self.assertIn(image.LIBPYTHON, binding["shared_library_paths"])
        self.assertEqual(receipt["manifest_digest"], image.pin(image.canonical(manifest)))
        self.assertEqual(receipt["runtime_binding_digest"], image.pin(image.canonical(binding)))
        self.assertEqual(binding["wrappers"]["action"]["argv"], ["/usr/bin/python3", "-I", "-S", "-B", "/opt/aragorn/bin/action.py"])
        self.assertEqual(json.loads((self.output / "service-image-receipt.json").read_bytes()), receipt)
        for row in manifest["files"]:
            path = self.output / "root" / row["path"]
            self.assertFalse(path.is_symlink())
            self.assertEqual(image.pin(path.read_bytes()), row["digest"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555 if row["executable"] else 0o444)

    def test_licenses_and_exact_exclusions_retained(self):
        receipt = self.assemble()
        self.assertTrue((self.output / receipt["python_license"]["path"]).is_file())
        self.assertTrue(receipt["packages"])
        self.assertTrue(any("_tkinter" in row["source_path"] for row in receipt["excluded_image_files"]))
        self.assertFalse(any("_tkinter" in name or "site-packages" in name for name in receipt["source_mapping"]))
        self.assertFalse(receipt["loader_cache_included"])
        self.assertFalse(receipt["site_packages_included"])
        for row in receipt["provenance_inventory"]:
            raw = (self.output / row["path"]).read_bytes()
            self.assertEqual(len(raw), row["size"])
            self.assertEqual(image.pin(raw), row["digest"])

    def test_default_elf_policy_still_rejects_python_rpath(self):
        with self.assertRaisesRegex(image.os_root.OSRootError, "RPATH"):
            image.os_root.elf_dependencies(python_elf())

    def test_explicit_python_rpath_opt_in_preserves_bytes_and_shape(self):
        raw = python_elf()
        result = image.os_root.elf_dependencies(raw, allowed_rpath=("$ORIGIN/../lib",))
        self.assertEqual(set(result), {"needed", "interpreter", "soname"})
        self.assertEqual(result["needed"], ["libpython3.12.so.1.0", "libc.so.6"])
        self.assertEqual(raw, python_elf())

    def test_alternative_relative_search_is_refused(self):
        with self.assertRaisesRegex(image.os_root.OSRootError, "search path"):
            image.os_root.elf_dependencies(python_elf(rpath="$ORIGIN/../lib:/tmp"), allowed_rpath=("$ORIGIN/../lib",))

    def test_duplicate_rpath_runpath_is_refused(self):
        with self.assertRaisesRegex(image.os_root.OSRootError, "ambiguous"):
            image.os_root.elf_dependencies(python_elf(duplicate=True), allowed_rpath=("$ORIGIN/../lib",))

    def test_other_rpath_policy_is_refused(self):
        with self.assertRaisesRegex(image.os_root.OSRootError, "policy"):
            image.os_root.elf_dependencies(elf(), allowed_rpath=("/usr/lib",))

    def test_python_must_actually_have_approved_relative_search(self):
        with self.assertRaisesRegex(image.os_root.OSRootError, "absent"):
            image.os_root.elf_dependencies(elf(), allowed_rpath=("$ORIGIN/../lib",))

    def test_audit_loading_stays_refused_with_opt_in(self):
        with self.assertRaisesRegex(image.os_root.OSRootError, "audit"):
            image.os_root.elf_dependencies(elf(extra=((0x6ffffefb, 0),)), allowed_rpath=("$ORIGIN/../lib",))

    def test_wrong_elf_architecture_refused(self):
        with self.assertRaisesRegex(image.os_root.OSRootError, "arm64"):
            image.os_root.elf_dependencies(elf(machine=62), allowed_rpath=("$ORIGIN/../lib",))

    def test_transitive_native_dependency_materialized(self):
        selected, _ = image.selected_python_files(self.tree)
        selected, edges = image.python_elf_closure(self.tree, selected)
        self.assertIn("lib/aarch64-linux-gnu/libcrypto.so.3", selected)
        self.assertIn(image.LOADER, selected)
        self.assertNotIn("lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", selected)
        self.assertTrue(any(row["requested"] == "libcrypto.so.3" for row in edges))
        self.assertEqual(selected[image.PYTHON]["raw"], self.tree.entries[image.PYTHON_SOURCE]["raw"])

    def test_unresolved_selected_native_dependency_refused(self):
        del self.tree.entries["usr/lib/aarch64-linux-gnu/libffi.so.8"]
        with self.assertRaisesRegex(image.ServiceImageError, "unresolved"):
            self.assemble()
        self.assertFalse(self.output.exists())

    def test_conflicting_library_search_candidates_refused(self):
        self.tree.entries["lib/aarch64-linux-gnu/libc.so.6"] = {"kind": "file", "mode": 0o755, "raw": elf(soname="libc.so.6") + b"different"}
        with self.assertRaisesRegex(image.ServiceImageError, "ambiguous"):
            self.assemble()

    def test_library_soname_mismatch_refused(self):
        self.tree.entries["usr/lib/aarch64-linux-gnu/libffi.so.8"]["raw"] = elf(soname="libother.so.8")
        with self.assertRaisesRegex(image.ServiceImageError, "SONAME"):
            self.assemble()

    def test_rpath_on_native_extension_refused(self):
        name = image.STDLIB_SOURCE + "/lib-dynload/_ssl.cpython-312-aarch64-linux-gnu.so"
        self.tree.entries[name]["raw"] = python_elf()
        with self.assertRaisesRegex(image.os_root.OSRootError, "RPATH"):
            self.assemble()

    def test_missing_essential_stdlib_refused(self):
        del self.tree.entries[image.STDLIB_SOURCE + "/encodings/__init__.py"]
        with self.assertRaisesRegex(image.ServiceImageError, "essentials"):
            self.assemble()

    def test_missing_essential_native_extension_refused(self):
        del self.tree.entries[image.STDLIB_SOURCE + "/lib-dynload/_ssl.cpython-312-aarch64-linux-gnu.so"]
        with self.assertRaisesRegex(image.ServiceImageError, "essentials"):
            self.assemble()

    def test_function_local_import_is_included(self):
        self.add_source("aragorn/pi_core_service_entry.py", b"def unused():\n    from . import extra\n")
        self.add_source("aragorn/extra.py", b"import json\n")
        selected, imports, unsupported = self.closure()
        self.assertIn("aragorn/extra.py", selected)
        self.assertIn("json", imports)
        self.assertEqual(unsupported, [])

    def test_pinned_target_builtin_pwd_is_available_without_host_import(self):
        self.add_source("aragorn/pi_core_service_entry.py", b"import pwd\n")
        selected, imports, unsupported = self.closure()
        self.assertIn("pwd", imports)
        self.assertIn("aragorn/pi_core_service_entry.py", selected)
        self.assertEqual(unsupported, [])
        self.assertFalse(any("pwd" in name for name in selected))

    def test_missing_pinned_sibling_is_refused(self):
        self.add_source("aragorn/pi_core_service_entry.py", b"from . import missing\n")
        with self.assertRaisesRegex(image.ServiceImageError, "missing pinned sibling"):
            self.closure()

    def test_extra_pinned_source_is_refused(self):
        self.add_source("aragorn/unreachable.py", b"pass\n")
        with self.assertRaisesRegex(image.ServiceImageError, "extra files"):
            self.closure()

    def test_external_import_is_refused(self):
        self.add_source("aragorn/pi_core_service_entry.py", b"import requests\n")
        with self.assertRaisesRegex(image.ServiceImageError, "unavailable external"):
            self.closure()

    def test_computed_dynamic_import_is_refused(self):
        self.add_source("aragorn/pi_core_service_entry.py", b"def load(name):\n    return __import__(name)\n")
        with self.assertRaisesRegex(image.ServiceImageError, "computed dynamic"):
            self.closure()

    def test_literal_dynamic_local_import_is_included(self):
        self.add_source("aragorn/pi_core_service_entry.py", b"def load():\n    return __import__('aragorn.extra')\n")
        self.add_source("aragorn/extra.py", b"pass\n")
        self.assertIn("aragorn/extra.py", self.closure()[0])

    def test_source_digest_mismatch_refused(self):
        (self.source / "aragorn/pi_core_service_entry.py").write_bytes(b"changed\n")
        with self.assertRaisesRegex(image.ServiceImageError, "digest differs"):
            self.closure()

    def test_source_symlink_refused(self):
        path = self.source / "aragorn/pi_core_service_entry.py"
        path.unlink()
        path.symlink_to(self.source / "aragorn/pi_core_request_service.py")
        with self.assertRaisesRegex(image.ServiceImageError, "linked source"):
            self.closure()

    def test_source_hardlink_refused(self):
        path = self.source / "aragorn/pi_core_service_entry.py"
        os.link(path, self.path / "alias.py")
        with self.assertRaisesRegex(image.ServiceImageError, "singly linked"):
            self.closure()

    def test_source_syntax_refused_before_output(self):
        self.add_source("aragorn/pi_core_service_entry.py", b"def broken(\n")
        with self.assertRaisesRegex(image.ServiceImageError, "Python 3.12 syntax"):
            self.assemble()
        self.assertFalse(self.output.exists())

    def _unsupported(self, raw):
        self.add_source("aragorn/pi_core_service_entry.py", b"from . import benchmark_worker_measurement\n")
        self.add_source("aragorn/benchmark_worker_measurement.py", raw)

    def test_exact_unsupported_dsse_site_is_explicit(self):
        self._unsupported(b"def verify_worker_measurement():\n    from cryptography.exceptions import InvalidSignature\n")
        rows = self.closure()[2]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function"], "verify_worker_measurement")
        self.assertEqual(rows[0]["status"], "UNSUPPORTED_BENCHMARK_DSSE_HELPER")

    def test_top_level_crypto_import_refused(self):
        self._unsupported(b"from cryptography.exceptions import InvalidSignature\n")
        with self.assertRaisesRegex(image.ServiceImageError, "unavailable external"):
            self.closure()

    def test_renamed_optional_function_refused(self):
        self._unsupported(b"def renamed():\n    from cryptography.exceptions import InvalidSignature\n")
        with self.assertRaisesRegex(image.ServiceImageError, "unavailable external"):
            self.closure()

    def test_new_optional_import_names_refused(self):
        self._unsupported(b"def verify_worker_measurement():\n    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm\n")
        with self.assertRaisesRegex(image.ServiceImageError, "unavailable external"):
            self.closure()

    def test_optional_policy_cannot_authorize_another_module(self):
        self.add_source("aragorn/pi_core_service_entry.py", b"def verify_worker_measurement():\n    from cryptography.exceptions import InvalidSignature\n")
        with self.assertRaisesRegex(image.ServiceImageError, "unavailable external"):
            self.closure()

    def test_wrapper_pin_or_extra_role_refused(self):
        self.wrapper_inventory["admin.py"] = image.pin(b"pass\n")
        with self.assertRaisesRegex(image.ServiceImageError, "wrapper inventory"):
            self.assemble()

    def test_wrapper_changed_bytes_refused(self):
        (self.wrappers / "action.py").write_bytes(b"changed\n")
        with self.assertRaisesRegex(image.ServiceImageError, "digest differs"):
            self.assemble()

    def test_existing_destination_preserved(self):
        self.output.mkdir()
        marker = self.output / "existing"
        marker.write_bytes(b"preserve")
        with self.assertRaisesRegex(image.ServiceImageError, "fresh"):
            self.assemble()
        self.assertEqual(marker.read_bytes(), b"preserve")

    def test_missing_license_fails_before_output(self):
        del self.tree.entries[image.STDLIB_SOURCE + "/LICENSE.txt"]
        with self.assertRaises(image.os_root.OSRootError):
            self.assemble()
        self.assertFalse(self.output.exists())

    def test_final_source_recheck_failure_retains_partial(self):
        original = image._input
        counts = {}
        def changed(root, name, expected):
            counts[name] = counts.get(name, 0) + 1
            if name == "aragorn/pi_core_service_entry.py" and counts[name] == 2:
                raise image.ServiceImageError("source changed during assembly")
            return original(root, name, expected)
        with mock.patch.object(image, "_input", side_effect=changed):
            with self.assertRaisesRegex(image.ServiceImageError, "changed"):
                self.assemble()
        self.assertTrue((self.output / "root/usr/bin/python3").is_file())
        self.assertFalse((self.output / "service-image-receipt.json").exists())

    def test_final_wrapper_recheck_failure_retains_partial(self):
        original = image._wrappers
        calls = 0
        def changed(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise image.ServiceImageError("wrapper changed during assembly")
            return original(*args)
        with mock.patch.object(image, "_wrappers", side_effect=changed):
            with self.assertRaisesRegex(image.ServiceImageError, "changed"):
                self.assemble()
        self.assertTrue((self.output / "root").is_dir())
        self.assertFalse((self.output / "service-image-receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
