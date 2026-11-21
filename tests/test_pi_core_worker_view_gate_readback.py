"""Read back only the retained B82 build. There is no build fallback."""
import json
import unittest
from unittest.mock import patch

from scripts import build_pi_core_source_gate as gate
from test_pi_core_worker_view_gate_compile import assert_gate_readback


class WorkerViewGateReadback(unittest.TestCase):
    def test_pinned_original_build_from_the_two_completed_host_commands(self):
        self.enterContext(patch.object(gate.subprocess, "Popen", side_effect=AssertionError("no child in replay")))
        root = gate.ROOT
        output = root / ".aragorn/pi-core-build/gate-batch-82"
        self.assertEqual(output.resolve(strict=True), output)
        package = root / gate.shared.PACKAGE
        pins = json.loads(gate.regular_bytes(package / "worker-view-gate-artifact-v3.json", 4096))
        self.assertEqual(set(pins["files"]), {"source-gate", "gate.o", "build-receipt.json", "provenance.json", "commands.json"})
        self.assertEqual(pins["schema"], "aragorn/pi-core-worker-view-gate-checkpoint/v1")
        self.assertEqual(output, root / pins["output"])
        self.assertIs(pins["runtime_executed"], False)
        self.assertIs(pins["phase3_exit_eligible"], False)
        self.assertEqual((pins["source_sha256"], pins["recipe_sha256"], pins["toolchain_digest"]),
                         (gate.VIEW_SOURCE_SHA, gate.VIEW_RECIPE_SHA, gate.VIEW_TOOLCHAIN_PIN))
        for name, expected in pins["files"].items():
            self.assertEqual(gate.sha256(gate.regular_bytes(output / name, 1 << 20)), expected, name)
        manifest = package / "source-gate-toolchain-v3.json"
        tools = json.loads(gate.regular_bytes(manifest, 16384))
        evidence = json.loads(gate.regular_bytes(output / "provenance.json", 65536))
        expected_argv = gate.commands(tools["compiler"]["path"], tools["linker"]["path"], output)
        self.assertEqual(gate.canonical(evidence["recipe"]["argv"]), gate.canonical(expected_argv))
        self.assertEqual(gate.sha256(gate.canonical(evidence["recipe"])), gate.VIEW_RECIPE_SHA)
        for row in evidence["commands"]:
            for name in ("stdout", "stderr"):
                relative = row["phase"] + "." + name
                raw = gate.regular_bytes(output / relative, gate.MAX_LOG)
                self.assertEqual(row[name], {"path":relative, "bytes":len(raw), "sha256":gate.sha256(raw)})
        self.assertFalse((output / "failure.json").exists())
        assert_gate_readback(self, root, output, manifest, evidence)
