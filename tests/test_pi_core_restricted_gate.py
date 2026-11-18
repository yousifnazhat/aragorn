"""Static refusal checks only. The ELF fixture is data, never an executable test."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tests import test_pi_core_source_gate_build as previous

gate = previous.gate


class RestrictedGateTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="pi-gate-v2-unit-"))).resolve()
        folder = self.root / gate.shared.PACKAGE
        folder.mkdir(parents=True)
        self.source = folder / gate.RESTRICTED_SOURCE
        self.source.write_bytes(gate.regular_bytes(previous.ROOT / gate.shared.PACKAGE / gate.RESTRICTED_SOURCE))
        self.binary = self.root / "gate.fixture"
        labels = (gate.RESTRICTED_GATE, *gate.RESTRICTED_ARGV, "HOME=/nonexistent", "PATH=/opt/aragorn/pi-runtime/node/bin")
        raw = bytearray(previous.elf() + b"".join(text.encode() + b"\0" for text in labels))
        struct.pack_into("<QQ", raw, 64 + 32, len(raw), len(raw))
        self.binary.write_bytes(raw)
        self.record = {"schema": gate.RESTRICTED_RECEIPT, "target": "linux-arm64-static",
            "source_sha256": gate.RESTRICTED_SOURCE_SHA, "elf_sha256": gate.sha256(raw),
            "compiler_sha256": "1220c0afafa12a6ae599d097ee7cf8b87c6b4d8e3fbb9783cee6b319a80683ba",
            "build_command_sha256": "d"*64, "runtime_executed": False, "node_argv": list(gate.RESTRICTED_ARGV)}
        self.receipt = self.root / "receipt.json"
        self.no_child = self.enterContext(mock.patch.object(gate.subprocess, "Popen",
                                            side_effect=AssertionError("no child in unit stage")))

    def consume(self, changed=None, pin=None):
        raw = gate.canonical(self.record if changed is None else changed) + b"\n"
        self.receipt.write_bytes(raw)
        return gate.restricted_gate_input(self.root, self.binary, self.receipt, pin or "sha256:" + gate.sha256(raw))

    def test_accepts_exact_static_receipt_without_executing_fixture(self):
        raw, row = self.consume()
        self.assertEqual(raw, self.binary.read_bytes())
        self.assertEqual(row["node_argv"], list(gate.RESTRICTED_ARGV))
        self.assertIs(row["runtime_executed"], False)
        self.no_child.assert_not_called()

    def test_full_fixed_source_argv_not_forwarded_and_only_approved_static_environment(self):
        source = self.source.read_text()
        self.assertEqual(gate.sha256(source.encode()), gate.RESTRICTED_SOURCE_SHA)
        self.assertIn("stack[0] != 4", source)
        for index, name in enumerate(("gate", "node", "restriction", "entry")):
            self.assertIn(f"!equal(argv[{index}], {name})", source)
        self.assertIn("argv[4] != 0", source)
        self.assertIn("child_argv[] = {node, restriction, entry, 0};", source)
        self.assertIn("child_env[] = {home, path, 0};", source)
        self.assertLess(source.index("call3(436"), source.index("call3(129"))
        self.assertLess(source.index("call3(129"), source.index("call3(221"))
        self.assertEqual(source.count("call3(221"), 1)
        self.assertNotIn("NODE_OPTIONS", source)

    def test_rejects_missing_extra_reordered_or_downgraded_node_argv(self):
        node, flag, entry = gate.RESTRICTED_ARGV
        for argv in ([node, entry], [node, entry, flag], [node, flag, entry, "--inspect"],
                     ["node", flag, entry], [node, flag, "entrypoint.js"]):
            with self.subTest(argv=argv), self.assertRaises(gate.BuildError):
                self.consume(self.record | {"node_argv": argv})

    def test_refuses_v1_receipt_changed_source_compiler_and_false_execution_claim(self):
        for changes in ({"schema": "aragorn/pi-core-source-gate-build/v1"}, {"runtime_executed": True},
                        {"source_sha256": "a"*64}, {"compiler_sha256": "b"*64}, {"extra": True}):
            with self.subTest(changes=changes), self.assertRaises(gate.BuildError):
                self.consume(self.record | changes)
        self.source.write_bytes(b"not approved")
        with self.assertRaises(gate.BuildError):
            self.consume(self.record | {"source_sha256": gate.sha256(self.source.read_bytes())})

    def test_refuses_changed_binary_stale_receipt_pin_and_noncanonical_record(self):
        with self.assertRaises(gate.BuildError):
            self.consume(pin="sha256:" + "e"*64)
        raw = json.dumps(self.record, indent=2).encode()
        self.receipt.write_bytes(raw)
        with self.assertRaises(gate.BuildError):
            gate.restricted_gate_input(self.root, self.binary, self.receipt, "sha256:" + gate.sha256(raw))
        self.binary.write_bytes(self.binary.read_bytes() + b"x")
        with self.assertRaises(gate.BuildError):
            self.consume()

    def test_static_strings_outside_mapped_segment_or_wx_are_not_evidence(self):
        original = self.binary.read_bytes()
        for field, value in ((64 + 4, 7), (64 + 32, 128)):
            altered = bytearray(original)
            struct.pack_into("<I", altered, field, value)
            self.binary.write_bytes(altered)
            with self.subTest(field=field), self.assertRaises(gate.BuildError):
                self.consume(self.record | {"elf_sha256": gate.sha256(altered)})

    def test_unapproved_v2_toolchain_or_source_does_not_start_compiler(self):
        path = previous.ROOT / gate.shared.PACKAGE / "source-gate-toolchain-v2.json"
        raw = path.read_bytes()
        self.assertEqual("sha256:" + gate.sha256(raw), gate.RESTRICTED_TOOLCHAIN_PIN)
        value = json.loads(raw)
        for field, candidate in (("node_argv", list(reversed(value["node_argv"]))),
                                 ("gate_path", "/tmp/gate"), ("source_sha256", "d"*64),
                                 ("unexpected_flag", "--external")):
            changed = gate.canonical(value | {field:candidate}) + b"\n"
            self.receipt.write_bytes(changed)
            with self.subTest(field=field), self.assertRaises(gate.BuildError):
                gate.load_toolchain(self.root, self.receipt, "sha256:" + gate.sha256(changed))
        self.no_child.assert_not_called()

    def test_existing_candidate_output_never_retries_or_clobbers(self):
        output = self.root / ".aragorn/pi-core-build/gate-batch-36"
        output.mkdir(parents=True)
        sentinel = output / "previous-failure"
        sentinel.write_bytes(b"retain")
        with self.assertRaises(gate.BuildError):
            gate.build(self.root, output, self.receipt, gate.RESTRICTED_TOOLCHAIN_PIN)
        self.no_child.assert_not_called()
        self.assertEqual(sentinel.read_bytes(), b"retain")


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(RestrictedGateTests)
    for name in ("test_fixed_two_command_build_emits_consumable_receipt_and_full_provenance",
                 "test_unapproved_schema_target_profile_or_flags_refuse"):
        suite.addTest(previous.GateBuildTests(name))
    return suite
