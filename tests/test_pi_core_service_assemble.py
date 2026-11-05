"""One retained-artifact static assembly through the reviewed pipeline only.

This test executes no target interpreter, service wrapper, OpenSSL, container,
network operation or package installation. Staged bytes are not service proof.
"""

import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import unittest
from unittest import mock
import uuid

from aragorn.pi_core_service_provision import validate_service_runtime_inputs

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pi_service_real_assembly", ROOT / "scripts/prepare_pi_core_service_image.py")
assert SPEC and SPEC.loader
assembler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembler)


class PiCoreServiceAssemblyTests(unittest.TestCase):
    input_record_name = "service-assembly-inputs-v1.json"

    def test_retained_python_image_and_reviewed_sources_assemble_once(self):
        for target in ("subprocess.Popen", "subprocess.run", "os.system", "os.execve", "socket.socket", "socket.create_connection"):
            self.enterContext(mock.patch(target, side_effect=AssertionError("no process, target or network execution")))
        record_path = ROOT / "packaging/pi-core" / self.input_record_name
        record_raw = assembler._build.regular_bytes(record_path)
        record = json.loads(record_raw)
        self.assertEqual(set(record), {"schema", "purpose", "constraints", "archive", "source_pin", "source_root",
            "wrapper_root", "expected_source_inventory", "expected_wrapper_inventory", "unsupported_import_policy"})
        self.assertEqual(record["schema"], "aragorn/pi-core-service-assembly-inputs/v1")
        self.assertEqual(record["purpose"], "STATIC_SERVICE_IMAGE_ASSEMBLY_ONLY_NO_TARGET_EXECUTION")
        self.assertEqual(record["constraints"], {"network": "none", "subprocesses": False, "target_execution": False,
            "automatic_retry": False, "fresh_output_only": True})
        self.assertEqual(record["source_root"], "src")
        self.assertEqual(record["wrapper_root"], "packaging/pi-core/services")
        self.assertEqual(assembler.canonical(record["unsupported_import_policy"]), assembler.canonical(assembler.UNSUPPORTED_IMPORT_POLICY))
        self.assertEqual(set(record["archive"]), {"path", "bytes", "sha256"})
        archive = ROOT / record["archive"]["path"]
        self.assertEqual(archive.absolute(), archive.resolve(strict=True))
        self.assertTrue(archive.is_relative_to(ROOT / ".aragorn/pi-core-os-inputs"))
        archive_raw = assembler._build.regular_bytes(archive, assembler.os_root.MAX_ARCHIVE)
        self.assertEqual(len(archive_raw), record["archive"]["bytes"])
        self.assertEqual(assembler.os_root.sha256(archive_raw), record["archive"]["sha256"])
        self.assertEqual(set(record["source_pin"]), {"path", "digest"})
        self.assertEqual(record["source_pin"]["path"], "packaging/pi-core/os-source-v1.json")
        source_path = ROOT / record["source_pin"]["path"]
        source_raw = assembler._build.regular_bytes(source_path)
        source_pin = json.loads(source_raw)
        self.assertEqual(assembler.pin(assembler.canonical(source_pin)), record["source_pin"]["digest"])
        parent = ROOT / ".aragorn/pi-core-service-image"
        self.assertEqual(parent.absolute(), parent.resolve())
        if not parent.exists():
            parent.mkdir(mode=0o700)
        self.assertTrue(parent.is_dir())
        self.assertFalse(parent.is_symlink())
        output = parent / ("assembled-" + uuid.uuid4().hex)
        print(json.dumps({"static_service_image_output": str(output), "target_execution": False}), flush=True)
        receipt = assembler.prepare_service_image(archive, source_pin=source_pin,
            source_root=ROOT / record["source_root"], wrapper_root=ROOT / record["wrapper_root"],
            expected_source_inventory=record["expected_source_inventory"],
            expected_wrapper_inventory=record["expected_wrapper_inventory"], output=output)
        self.assertEqual(receipt["status"], "PREPARED_NOT_INSTALLED_OR_EXECUTED")
        self.assertFalse(receipt["executed_target_code"])
        self.assertFalse(receipt["native_cleanup_verified"])
        self.assertEqual(receipt["archive_sha256"], record["archive"]["sha256"])
        self.assertEqual(json.loads((output / "service-image-receipt.json").read_bytes()), receipt)
        manifest_raw = assembler._build.regular_bytes(output / "manifest.json")
        binding_raw = assembler._build.regular_bytes(output / "runtime-binding.json")
        manifest, binding = json.loads(manifest_raw), json.loads(binding_raw)
        self.assertEqual(manifest_raw, assembler.canonical(manifest))
        self.assertEqual(binding_raw, assembler.canonical(binding))
        self.assertEqual(assembler.pin(manifest_raw), receipt["manifest_digest"])
        self.assertEqual(assembler.pin(binding_raw), receipt["runtime_binding_digest"])
        validated = validate_service_runtime_inputs(manifest, receipt["manifest_digest"], binding, receipt["runtime_binding_digest"])
        self.assertEqual(validated, (manifest, binding))
        actual_files, actual_dirs = [], []
        self.assertEqual(stat.S_IMODE((output / "root").stat().st_mode), 0o755)
        for path in sorted((output / "root").rglob("*")):
            info = path.lstat()
            self.assertFalse(stat.S_ISLNK(info.st_mode))
            name = path.relative_to(output / "root").as_posix()
            if stat.S_ISDIR(info.st_mode):
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o555)
                actual_dirs.append(name)
            else:
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(info.st_nlink, 1)
                raw = assembler._build.regular_bytes(path, assembler.os_root.MAX_FILE)
                executable = bool(info.st_mode & 0o111)
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o555 if executable else 0o444)
                actual_files.append({"path": name, "size": len(raw), "digest": assembler.pin(raw), "executable": executable})
        self.assertEqual(actual_files, manifest["files"])
        self.assertEqual(actual_dirs, manifest["directories"])
        actual_provenance = []
        for path in sorted((output / "provenance").rglob("*")):
            self.assertFalse(path.is_symlink())
            if path.is_file():
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
                raw = assembler._build.regular_bytes(path, assembler.os_root.MAX_FILE)
                actual_provenance.append({"path": path.relative_to(output).as_posix(), "size": len(raw), "digest": assembler.pin(raw)})
        self.assertEqual(actual_provenance, receipt["provenance_inventory"])
        self.assertEqual({path.name for path in output.iterdir()}, {"root", "provenance", "manifest.json", "runtime-binding.json", "service-image-receipt.json"})
        self.assertEqual(assembler._build.regular_bytes(record_path), record_raw)
        self.assertEqual(assembler._build.regular_bytes(source_path), source_raw)
        # Re-hash the exact retained archive, not a target/runtime invocation.
        self.assertEqual(assembler._build.regular_bytes(archive, assembler.os_root.MAX_ARCHIVE), archive_raw)
        for name, digest in record["expected_source_inventory"].items():
            assembler._input(ROOT / "src", name, digest)
        for name, digest in record["expected_wrapper_inventory"].items():
            assembler._input(ROOT / "packaging/pi-core/services", name, digest)
        print(json.dumps({"receipt": str(output / "service-image-receipt.json"), "manifest_digest": receipt["manifest_digest"],
            "runtime_binding_digest": receipt["runtime_binding_digest"], "files": len(actual_files), "directories": len(actual_dirs),
            "status": receipt["status"], "unsupported_import_sites": receipt["unsupported_import_sites"]}), flush=True)


if __name__ == "__main__":
    unittest.main()
