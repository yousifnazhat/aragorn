"""One new host cross-compile and immutable-artifact readback. Never runs an ELF."""
import json
from pathlib import Path
import stat
import unittest

from scripts import build_pi_core_source_gate as gate


class WorkerViewGateCompile(unittest.TestCase):
    def test_compile_new_fixed_view_gate_once_and_read_back_original_artifacts(self):
        root = gate.ROOT
        output = root / ".aragorn/pi-core-build/gate-batch-82"
        manifest = root / "packaging/pi-core/source-gate-toolchain-v3.json"
        self.assertFalse(output.exists() or output.is_symlink(), "prior output is evidence; do not adopt or retry")
        evidence = gate.build(root, output, manifest, gate.VIEW_TOOLCHAIN_PIN)
        self.assertEqual(gate.regular_bytes(output / "provenance.json", 65536), gate.canonical(evidence) + b"\n")
        assert_gate_readback(self, root, output, manifest, evidence)


def assert_gate_readback(self, root, output, manifest, evidence):
    self.assertEqual(evidence["schema"], "aragorn/pi-core-source-gate-provenance/v3")
    self.assertEqual(evidence["status"], "COMPILED_STATIC_GATE_NOT_EXECUTED")
    self.assertIs(evidence["runtime_executed"], False)
    self.assertEqual(evidence["toolchain_digest"], gate.VIEW_TOOLCHAIN_PIN)

    # Reopen on-disk results, not just the result object or its claim.
    read = lambda name: gate.regular_bytes(output / name, 1024 * 1024)
    recorded = json.loads(read("provenance.json"))
    self.assertEqual(gate.canonical(recorded), gate.canonical(evidence))
    source = read("source-gate.c")
    self.assertEqual(source, gate.regular_bytes(root / "packaging/pi-core/source-gate-view-v3.c", 65536))
    tools = json.loads(gate.regular_bytes(manifest, 16384))
    self.assertEqual(tools, json.loads(read("toolchain.json")))
    self.assertEqual([r["phase"] for r in recorded["commands"]], ["compile", "link"])
    self.assertEqual([r["argv"][0] for r in recorded["commands"]],
                     [tools["compiler"]["path"], tools["linker"]["path"]])
    self.assertTrue(all(r["child_reaped"] is True and r["returncode"] == 0 for r in recorded["commands"]))
    recipe = json.loads(read("commands.json"))
    self.assertEqual(recipe, recorded["recipe"])
    self.assertEqual(recipe["argv"], [r["argv"] for r in recorded["commands"]])
    self.assertEqual(recipe["node_argv"], list(gate.RESTRICTED_ARGV))
    self.assertEqual(recipe["gate_path"], gate.RESTRICTED_GATE)
    receipt = read("build-receipt.json")
    self.assertEqual(receipt, read("candidate-receipt.json"))
    self.assertEqual("sha256:" + gate.sha256(receipt), evidence["receipt_digest"])
    binary = output / "source-gate"
    self.assertEqual(stat.S_IMODE(binary.lstat().st_mode), 0o555)
    self.assertTrue(stat.S_ISREG(binary.lstat().st_mode))
    elf, claims = gate.view_gate_input(root, binary, output / "build-receipt.json", evidence["receipt_digest"])
    self.assertEqual(elf, read("source-gate"))
    self.assertEqual(claims["node_argv"], list(gate.RESTRICTED_ARGV))
    self.assertEqual(claims["source_sha256"], gate.sha256(source))
    self.assertEqual(claims["compiler_sha256"], tools["compiler"]["sha256"])
    self.assertEqual(claims["build_command_sha256"], gate.sha256(gate.canonical(recipe)))
    self.assertIs(claims["runtime_executed"], False)
    self.assertEqual(claims["elf_sha256"], gate.sha256(elf))
    self.assertEqual(recorded["artifacts"]["source-gate"], {"sha256":gate.sha256(elf),"bytes":len(elf)})
    obj = read("gate.o")
    self.assertEqual(recorded["artifacts"]["gate.o"], {"sha256":gate.sha256(obj),"bytes":len(obj)})
    for row in recorded["commands"]:
        self.assertNotEqual(Path(row["argv"][0]), binary)
