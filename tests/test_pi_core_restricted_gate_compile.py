"""Compile/link the new static gate once; no target, VM or service execution."""
import unittest

from scripts import build_pi_core_source_gate as gate


class RestrictedGateCompile(unittest.TestCase):
    def test_compile_restricted_gate_once_and_read_back_unexecuted_artifact(self):
        root = gate.ROOT
        output = root / ".aragorn/pi-core-build/gate-batch-36"
        self.assertFalse(output.exists() or output.is_symlink(), "retain previous outcome; do not rerun or adopt")
        manifest = root / "packaging/pi-core/source-gate-toolchain-v2.json"
        evidence = gate.build(root, output, manifest, gate.RESTRICTED_TOOLCHAIN_PIN)
        self.assertEqual(evidence["schema"], "aragorn/pi-core-source-gate-provenance/v2")
        self.assertEqual(evidence["status"], "COMPILED_STATIC_GATE_NOT_EXECUTED")
        self.assertIs(evidence["runtime_executed"], False)
        self.assertEqual(evidence["toolchain_digest"], gate.RESTRICTED_TOOLCHAIN_PIN)
        self.assertEqual([row["phase"] for row in evidence["commands"]], ["compile", "link"])
        self.assertTrue(all(row["child_reaped"] for row in evidence["commands"]))
        elf, record = gate.restricted_gate_input(root, output / "source-gate", output / "build-receipt.json",
                                                 evidence["receipt_digest"])
        self.assertEqual(record["elf_sha256"], gate.sha256(elf))
        self.assertEqual(record["source_sha256"], gate.RESTRICTED_SOURCE_SHA)
        self.assertEqual(record["build_command_sha256"], gate.sha256(gate.canonical(evidence["recipe"])))
        self.assertEqual(evidence["recipe"]["gate_path"], gate.RESTRICTED_GATE)
        self.assertEqual(record["node_argv"], list(gate.RESTRICTED_ARGV))
        self.assertEqual(evidence["recipe"]["node_argv"], record["node_argv"])
        self.assertEqual((output / "source-gate").stat().st_mode & 0o777, 0o555)
