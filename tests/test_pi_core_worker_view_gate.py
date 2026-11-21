"""B82 gate source/receipt/tool contract only. Authored ELF is data, never run."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from scripts import build_pi_core_source_gate as gate
from tests.test_pi_core_source_gate_build import elf


class WorkerViewGateContract(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="pi-gate-v3-"))).resolve()
        package = self.root / gate.shared.PACKAGE
        package.mkdir(parents=True)
        self.source = package / gate.VIEW_SOURCE
        self.source.write_bytes(gate.regular_bytes(gate.ROOT / gate.shared.PACKAGE / gate.VIEW_SOURCE, 65536))
        self.manifest = gate.ROOT / gate.shared.PACKAGE / "source-gate-toolchain-v3.json"
        self.tools = json.loads(gate.regular_bytes(self.manifest, 16384))
        self.binary, self.receipt = self.root / "inert.elf", self.root / "receipt.json"
        self.names = {gate.RESTRICTED_GATE, *gate.RESTRICTED_ARGV, "HOME=/nonexistent",
                      "PATH=/opt/aragorn/pi-runtime/node/bin", *gate.VIEW_LITERALS}
        self.fixture = self.image(self.names)
        self.binary.write_bytes(self.fixture)
        self.row = {"schema":gate.VIEW_RECEIPT, "target":"linux-arm64-static", "runtime_executed":False,
                    "compiler_sha256":self.tools["compiler"]["sha256"], "build_command_sha256":gate.VIEW_RECIPE_SHA,
                    "elf_sha256":gate.sha256(self.fixture), "source_sha256":gate.VIEW_SOURCE_SHA,
                    "node_argv":list(gate.RESTRICTED_ARGV), "gate_path":gate.RESTRICTED_GATE,
                    "view_record":gate.VIEW_RECORD, "toolchain_digest":gate.VIEW_TOOLCHAIN_PIN}
        self.child = self.enterContext(mock.patch.object(gate.subprocess, "Popen",
                                              side_effect=AssertionError("unit stage cannot run a child")))
        self.addCleanup(self.child.assert_not_called)

    @staticmethod
    def image(names):
        raw = bytearray(elf() + b"".join(s.encode("ascii") + b"\0" for s in sorted(names)))
        struct.pack_into("<QQ", raw, 64 + 32, len(raw), len(raw))
        return bytes(raw)

    def consume(self, changes=None, expected=None):
        raw = gate.canonical(self.row | (changes or {})) + b"\n"
        self.receipt.write_bytes(raw)
        return gate.view_gate_input(self.root, self.binary, self.receipt, expected or "sha256:"+gate.sha256(raw))

    def test_fixed_input_contract_parses_inert_image_and_retains_no_execution_claim(self):
        value, row = self.consume()
        self.assertEqual(value,self.fixture)
        self.assertEqual(gate.sha256(self.source.read_bytes()),gate.VIEW_SOURCE_SHA)
        self.assertEqual(row["node_argv"], ["/opt/aragorn/pi-runtime/node/bin/node",
                         "--disallow-code-generation-from-strings","/opt/aragorn/pi-runtime/pi-core/entrypoint.js"])
        self.assertEqual(row["view_record"],"aragorn/pi-core-pre-exec-fixed-view/v1")
        self.assertIs(row["runtime_executed"],False)

    def test_repinning_changed_manifest_cannot_replace_tools_or_view_contract(self):
        raw = gate.regular_bytes(self.manifest,16384)
        self.assertEqual("sha256:"+gate.sha256(raw),gate.VIEW_TOOLCHAIN_PIN)
        for field, altered in (("source_sha256","9"*64), ("view_record","unrestricted"),
                               ("node_argv",list(reversed(gate.RESTRICTED_ARGV))), ("gate_path","/other"),
                               *((k,self.tools[k] | {"sha256":"9"*64}) for k in ("compiler","linker","linker_library"))):
            value = gate.canonical(self.tools | {field:altered}) + b"\n"
            self.receipt.write_bytes(value)
            with self.subTest(field=field), self.assertRaises(gate.BuildError):
                gate.load_toolchain(self.root,self.receipt,"sha256:"+gate.sha256(value))

    def test_successor_reuses_frozen_tools_and_argv_and_carries_original_fixed_paths(self):
        predecessor = gate.regular_bytes(self.manifest.with_name("source-gate-toolchain-v2.json"),16384)
        self.assertEqual("sha256:"+gate.sha256(predecessor),
                         "sha256:7fdaa9b7d5f80903b5f758458bca4457f4e8b8d025c8f113aac0f6d53f13ce5f")
        old = json.loads(predecessor)
        for field in ("target","command_profile","compiler","linker","linker_library","gate_path","node_argv"):
            self.assertEqual(self.tools[field],old[field],field)
        self.assertNotEqual(old["source_sha256"],self.tools["source_sha256"])
        self.assertTrue({"/run/aragorn-pi-bootstrap/requests", "/run/aragorn-pi-bootstrap/requests/request.sock",
                         "/run/aragorn-pi-bootstrap/provider", "/run/aragorn-pi-bootstrap/provider/provider.sock",
                         "/proc/self", "/proc/thread-self", "/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr",
                         "/proc/self/fd"} <= gate.VIEW_LITERALS)

    def test_changed_source_and_matching_locally_resealed_receipt_still_refuse(self):
        self.source.write_bytes(self.source.read_bytes()+b"\n/* changed */\n")
        with self.assertRaises(gate.BuildError):
            self.consume({"source_sha256":gate.sha256(self.source.read_bytes())})

    def test_unapproved_receipt_schema_tool_recipe_claim_or_argv_refuses(self):
        for changes in ({"schema":gate.RESTRICTED_RECEIPT}, {"runtime_executed":True},
                        {"node_argv":list(gate.RESTRICTED_ARGV)+["--inspect"]}, {"compiler_sha256":"9"*64},
                        {"toolchain_digest":"sha256:"+"9"*64}, {"build_command_sha256":"8"*64},
                        {"view_record":"observed-by-worker"}, {"gate_path":"/unowned"}, {"extra":True}):
            with self.subTest(changes=changes),self.assertRaises(gate.BuildError):
                self.consume(changes)
        with self.assertRaises(gate.BuildError):
            self.consume(expected="sha256:"+"e"*64)

    def test_lost_new_mapped_literal_or_writable_executable_segment_refuses(self):
        missing = self.image(self.names - {"/run/aragorn-pi-bootstrap/requests/request.sock"})
        # Switch every LOAD to rwx; no other mapped read-only segment supplies the contract.
        writable = bytearray(self.fixture)
        struct.pack_into("<I",writable,64+4,7)
        for raw in (missing,bytes(writable)):
            self.binary.write_bytes(raw)
            with self.subTest(length=len(raw)), self.assertRaises(gate.BuildError):
                self.consume({"elf_sha256":gate.sha256(raw)})

    def test_receipt_and_binary_are_read_under_original_byte_pins(self):
        self.binary.write_bytes(self.fixture+b"altered")
        with self.assertRaises(gate.BuildError):
            self.consume()
        self.binary.write_bytes(self.fixture)
        raw = json.dumps(self.row,indent=2).encode()
        self.receipt.write_bytes(raw)
        with self.assertRaises(gate.BuildError):
            gate.view_gate_input(self.root,self.binary,self.receipt,"sha256:"+gate.sha256(raw))

    def test_existing_output_refuses_without_child_or_replacing_failed_record(self):
        output = self.root / ".aragorn/pi-core-build/gate-batch-82"
        output.mkdir(parents=True)
        failed = output / "failure.json"
        failed.write_bytes(b"previous outcome")
        with self.assertRaises(gate.BuildError):
            gate.build(self.root,output,self.manifest,gate.VIEW_TOOLCHAIN_PIN)
        self.assertEqual(failed.read_bytes(),b"previous outcome")
