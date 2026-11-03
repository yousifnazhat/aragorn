"""One static assembly from retained real image/Node bytes, through pipeline only.

No target ELF, Docker, service, worker or model is executed. This stage does not
install protected roots or establish Linux ABI compatibility or qualification.
"""

import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pi_os_real_assembly", ROOT / "scripts/prepare_pi_core_os_root.py")
assert SPEC and SPEC.loader
assembler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assembler)


class PiCoreOSAssemblyTests(unittest.TestCase):
    def test_retained_image_and_compiled_node_produce_static_closure_once(self):
        self.enterContext(mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no child execution")))
        record_path = ROOT / "packaging/pi-core/os-assembly-inputs-v1.json"
        record_raw = assembler._build.regular_bytes(record_path)
        record = json.loads(record_raw)
        self.assertEqual(record["schema"], "aragorn/pi-core-os-assembly-inputs/v1")
        self.assertEqual(record["purpose"], "STATIC_ARCHIVE_AND_ELF_PROCESSING_ONLY_NO_TARGET_EXECUTION")
        self.assertEqual(record["constraints"], {"network": "none", "subprocesses": False,
            "target_execution": False, "automatic_retry": False, "fresh_output_only": True})
        archive = ROOT / record["archive"]["path"]
        self.assertEqual(archive.absolute(), archive.resolve(strict=True))
        self.assertTrue(archive.is_relative_to(ROOT / ".aragorn/pi-core-os-inputs"))
        archive_raw = assembler._build.regular_bytes(archive, assembler.MAX_ARCHIVE)
        self.assertEqual(len(archive_raw), record["archive"]["bytes"])
        self.assertEqual(assembler.sha256(archive_raw), record["archive"]["sha256"])
        checkpoint = json.loads(assembler._build.regular_bytes(ROOT / record["compiled_checkpoint"]))
        receipt_path = ROOT / checkpoint["receipt_local_path"]
        self.assertEqual(receipt_path.absolute(), receipt_path.resolve(strict=True))
        self.assertTrue(receipt_path.is_relative_to(ROOT / ".aragorn/pi-core-build"))
        receipt_raw = assembler._build.regular_bytes(receipt_path)
        self.assertEqual(len(receipt_raw), checkpoint["receipt_file_bytes"])
        self.assertEqual(assembler.sha256(receipt_raw), checkpoint["receipt_file_sha256"])
        compiled = json.loads(receipt_raw)
        self.assertEqual(assembler.pin(assembler.canonical(compiled)), checkpoint["receipt_canonical_digest"])
        node_rows = [row for row in compiled["deployment_inventory"] if row["path"] == "node/bin/node"]
        self.assertEqual(len(node_rows), 1)
        node = receipt_path.parent / "deployment/node/bin/node"
        self.assertEqual(node.absolute(), node.resolve(strict=True))
        node_raw = assembler._build.regular_bytes(node, assembler.MAX_FILE)
        self.assertEqual(len(node_raw), node_rows[0]["bytes"])
        node_digest = "sha256:" + node_rows[0]["sha256"]
        self.assertEqual(assembler.pin(node_raw), node_digest)
        source_path = ROOT / record["source_pin"]
        source_raw = assembler._build.regular_bytes(source_path)
        source = assembler.document(source_raw)
        output = ROOT / ".aragorn/pi-core-os-inputs" / ("assembled-" + uuid.uuid4().hex)
        print(json.dumps({"static_os_output": str(output), "target_execution": False}), flush=True)
        receipt = assembler.prepare_os_root(archive, node, node_digest=node_digest, output=output, source=source)
        self.assertEqual(receipt["status"], "PREPARED_NOT_INSTALLED_OR_EXECUTED")
        self.assertEqual(receipt["archive_sha256"], record["archive"]["sha256"])
        self.assertFalse(receipt["executed_target_code"])
        self.assertFalse(receipt["native_cleanup_verified"])
        self.assertEqual(receipt["closure_digest"], assembler.pin(assembler.canonical(receipt["protected_tree"])))
        self.assertEqual(json.loads((output / "os-root-receipt.json").read_bytes()), receipt)
        files, directories = [], []
        for path in sorted((output / "root").rglob("*")):
            self.assertFalse(path.is_symlink())
            relative = path.relative_to(output / "root").as_posix()
            if path.is_dir():
                directories.append(relative)
            else:
                raw = assembler._build.regular_bytes(path, assembler.MAX_FILE)
                files.append({"path": relative, "size": len(raw), "digest": assembler.pin(raw),
                              "executable": bool(path.stat().st_mode & 0o111)})
        self.assertEqual(files, receipt["protected_tree"]["files"])
        self.assertEqual(directories, receipt["protected_tree"]["directories"])
        self.assertEqual(assembler._build.regular_bytes(record_path), record_raw)
        self.assertEqual(assembler._build.regular_bytes(source_path), source_raw)
        self.assertEqual(assembler._build.regular_bytes(receipt_path), receipt_raw)
        print(json.dumps({"receipt": str(output / "os-root-receipt.json"),
            "closure_digest": receipt["closure_digest"], "files": len(files),
            "directories": len(directories), "status": receipt["status"]}), flush=True)


if __name__ == "__main__":
    unittest.main()
