"""Fixed gate-build contracts with inert tools and authored ELF bytes only.

Every subprocess is mocked. These checks do not compile or execute the gate.
"""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pi_source_gate_build", ROOT / "scripts/build_pi_core_source_gate.py")
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def elf():
    value = bytearray(128)
    value[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", value, 16, 2, 183)
    struct.pack_into("<QQ", value, 24, 0x400078, 64)
    struct.pack_into("<HH", value, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", value, 64, 1, 5, 0, 0x400000, 0, 128, 128, 4096)
    return bytes(value)


class GateBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="aragorn-source-gate-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.output = self.root / ".aragorn/pi-core-build/new-gate"
        self.source = self.root / "packaging/pi-core/source-gate.c"
        self.write(self.source, (ROOT / "packaging/pi-core/source-gate.c").read_bytes())
        self.compiler = self.root / "host-tools/clang"
        self.linker = self.root / "host-tools/lib/rustlib/aarch64-apple-darwin/bin/rust-lld"
        self.library = self.root / "host-tools/lib/libLLVM.dylib"
        for path, raw in ((self.compiler, b"inert compiler"), (self.linker, b"inert linker"),
                          (self.library, b"inert linker library")):
            self.write(path, raw)
            path.chmod(0o755 if path != self.library else 0o644)
        self.manifest_path = self.root / "toolchain.json"
        self.manifest = {"schema": gate.SCHEMA, "target": "linux-arm64-static", "command_profile": gate.PROFILE,
            "source_sha256": gate.sha256(self.source.read_bytes()),
            **{key: {"path": str(path), "sha256": gate.sha256(path.read_bytes())}
               for key, path in (("compiler", self.compiler), ("linker", self.linker), ("linker_library", self.library))}}
        self.pin = self.save_manifest()
        self.children, self.invocations, self.codes = [], [], [0, 0]
        self.after_spawn = lambda phase: None
        self.target = elf()
        patcher = mock.patch.object(gate.subprocess, "Popen", side_effect=self.spawn)
        self.popen = patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def write(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def save_manifest(self):
        raw = gate.canonical(self.manifest) + b"\n"
        self.write(self.manifest_path, raw)
        return "sha256:" + gate.sha256(raw)

    def spawn(self, argv, **kwargs):
        index = len(self.invocations)
        self.invocations.append((argv, kwargs))
        self.assertEqual(argv[0], str(self.compiler if index == 0 else self.linker))
        self.write(self.output / ("gate.o" if index == 0 else "source-gate"),
                   b"authored object fixture" if index == 0 else self.target)
        kwargs["stdout"].write(b"inert compiler/linker output\n")
        kwargs["stdout"].flush()
        child = mock.Mock(pid=9000 + index)
        child.wait.return_value = self.codes[index]
        child.poll.return_value = self.codes[index]
        self.children.append(child)
        self.after_spawn(index)
        return child

    def build(self, **kwargs):
        return gate.build(self.root, self.output, self.manifest_path, self.pin, **kwargs)

    def test_fixed_two_command_build_emits_consumable_receipt_and_full_provenance(self):
        result = self.build()
        self.assertEqual(len(self.invocations), 2)
        self.assertEqual(result["status"], "COMPILED_STATIC_GATE_NOT_EXECUTED")
        receipt_path = self.output / "build-receipt.json"
        raw, receipt = gate.shared.source_gate_input(self.root, self.output / "source-gate", receipt_path,
                                                     result["receipt_digest"])
        self.assertEqual(raw, self.target)
        self.assertFalse(receipt["runtime_executed"])
        self.assertEqual(receipt["compiler_sha256"], self.manifest["compiler"]["sha256"])
        self.assertEqual(receipt["build_command_sha256"], gate.sha256(gate.canonical(result["recipe"])))
        self.assertEqual(result["toolchain"]["linker_library"], self.manifest["linker_library"])
        self.assertTrue(all(row["child_reaped"] and row["stdout"]["sha256"] for row in result["commands"]))
        self.assertIn("HOST_DYNAMIC_COMPILER_DEPENDENCIES_NOT_FULLY_ATTESTED", result["limitations"])
        self.assertFalse((self.output / "failure.json").exists())

    def test_fixed_commands_never_run_target_or_implicit_linker(self):
        self.build()
        compile_argv, link_argv = (row[0] for row in self.invocations)
        self.assertIn("-c", compile_argv)
        self.assertIn("-fintegrated-cc1", compile_argv)
        self.assertIn("-nostdinc", compile_argv)
        self.assertIn("--no-default-config", compile_argv)
        self.assertEqual(link_argv[1:3], ["-flavor", "gnu"])
        self.assertIn("--entry=_start", link_argv)
        self.assertNotIn(str(self.output / "source-gate"), [row[0][0] for row in self.invocations])

    def test_environment_is_fixed_without_credentials_or_tool_search_overrides(self):
        with mock.patch.dict(gate.os.environ, {"OPENAI_API_KEY": "inert-secret", "CPATH": "/unapproved", "SDKROOT": "/sdk"}):
            self.build()
        for argv, options in self.invocations:
            self.assertEqual(options["env"], gate.ENV)
            self.assertFalse(options["shell"])
            self.assertTrue(options["close_fds"])
            self.assertEqual(options["stdin"], subprocess.DEVNULL)

    def test_missing_or_changed_manifest_pin_refuses_before_output(self):
        for pin in (None, "", "sha256:" + "f" * 64):
            with self.subTest(pin=pin), self.assertRaises(gate.BuildError):
                gate.build(self.root, self.output, self.manifest_path, pin)
        self.assertFalse(self.output.exists())
        self.popen.assert_not_called()

    def test_unapproved_schema_target_profile_or_flags_refuse(self):
        original = copy.deepcopy(self.manifest)
        for key, value in (("schema", "other"), ("target", "host"), ("command_profile", "custom"), ("flags", ["-plugin"])):
            self.manifest = copy.deepcopy(original)
            self.manifest[key] = value
            self.pin = self.save_manifest()
            with self.subTest(key=key), self.assertRaises(gate.BuildError):
                self.build()
        self.popen.assert_not_called()

    def test_changed_source_or_compiler_or_linker_or_library_refuses_before_output(self):
        for path in (self.source, self.compiler, self.linker, self.library):
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(path=path), self.assertRaises(gate.BuildError):
                self.build()
            path.write_bytes(original)
        self.assertFalse(self.output.exists())
        self.popen.assert_not_called()

    def test_symlink_tool_is_not_resolved_into_unreviewed_identity(self):
        alias = self.compiler.with_name("clang-alias")
        alias.symlink_to(self.compiler)
        self.manifest["compiler"]["path"] = str(alias)
        self.pin = self.save_manifest()
        with self.assertRaisesRegex(gate.BuildError, "resolved"):
            self.build()
        self.popen.assert_not_called()

    def test_pinned_library_must_match_reviewed_linker_relative_location(self):
        elsewhere = self.root / "elsewhere/libLLVM.dylib"
        self.write(elsewhere, self.library.read_bytes())
        self.manifest["linker_library"]["path"] = str(elsewhere)
        self.pin = self.save_manifest()
        with self.assertRaisesRegex(gate.BuildError, "adjacent runtime"):
            self.build()

    def test_existing_output_is_never_overwritten_or_retried(self):
        self.output.mkdir(parents=True)
        retained = self.output / "retained.txt"
        retained.write_bytes(b"retained")
        with self.assertRaisesRegex(gate.BuildError, "new unlinked"):
            self.build()
        self.assertEqual(retained.read_bytes(), b"retained")
        self.popen.assert_not_called()

    def test_output_outside_owned_build_root_refuses(self):
        self.output = self.root / "elsewhere"
        with self.assertRaisesRegex(gate.BuildError, "new unlinked"):
            self.build()
        self.popen.assert_not_called()

    def test_compile_failure_retains_outputs_without_link_or_success_receipt(self):
        self.codes[0] = 1
        with self.assertRaisesRegex(gate.BuildError, "compile failed"):
            self.build()
        self.assertEqual(len(self.invocations), 1)
        record = json.loads((self.output / "failure.json").read_bytes())
        self.assertEqual(record["commands"][0]["returncode"], 1)
        self.assertTrue((self.output / "compile.stdout").exists())
        self.assertFalse((self.output / "build-receipt.json").exists())

    def test_link_failure_retains_both_logs_without_automatic_retry(self):
        self.codes[1] = 1
        with self.assertRaisesRegex(gate.BuildError, "link failed"):
            self.build()
        self.assertEqual(len(self.invocations), 2)
        self.assertTrue((self.output / "compile.stdout").exists() and (self.output / "link.stderr").exists())
        self.assertFalse((self.output / "build-receipt.json").exists())

    def test_invalid_elf_is_rejected_by_existing_consumer_before_final_receipt(self):
        self.target = b"not an ELF"
        with self.assertRaisesRegex(gate.BuildError, "ELF64"):
            self.build()
        self.assertTrue((self.output / "candidate-receipt.json").exists())
        self.assertTrue((self.output / "failure.json").exists())
        self.assertFalse((self.output / "build-receipt.json").exists())

    def test_source_mutation_during_build_refuses_success(self):
        self.after_spawn = lambda index: self.source.write_bytes(b"changed") if index == 1 else None
        with self.assertRaisesRegex(gate.BuildError, "source gate bytes"):
            self.build()
        self.assertFalse((self.output / "build-receipt.json").exists())

    def test_identical_byte_tool_replacement_is_still_detected(self):
        def replace(index):
            if index == 1:
                replacement = self.compiler.with_name("replacement")
                replacement.write_bytes(self.compiler.read_bytes())
                replacement.chmod(0o755)
                replacement.replace(self.compiler)
        self.after_spawn = replace
        with self.assertRaisesRegex(gate.BuildError, "changed during build"):
            self.build()

    def test_timeout_bounds_are_exact_without_boolean_or_deadline_widening(self):
        for value in (True, 0, 4, 61, float("inf")):
            with self.subTest(value=value), self.assertRaisesRegex(gate.BuildError, "5..60"):
                self.build(timeout_seconds=value)
        self.popen.assert_not_called()


class GateChildCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="aragorn-gate-child-unit-")
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.child = mock.Mock(pid=1234)
        self.child.poll.return_value = None
        self.child.wait.return_value = -9
        self.records = []

    def timeout(self, *, exhausted=False):
        with mock.patch.object(gate.subprocess, "Popen", return_value=self.child), \
             mock.patch.object(gate.time, "monotonic", side_effect=[10, 13, 16 if exhausted else 14]):
            with self.assertRaisesRegex(gate.BuildError, "original gate build deadline"):
                gate._command(["/inert/compiler"], self.output, "compile", 12, 15, self.records)

    def test_timeout_terminates_one_owned_child_and_reaps_with_original_budget(self):
        self.timeout()
        self.child.kill.assert_called_once()
        self.child.wait.assert_called_once_with(timeout=1)
        self.assertTrue(self.records[0]["child_reaped"])
        self.assertEqual(self.records[0]["stdout"]["bytes"], 0)

    def test_exit_race_during_kill_still_reaps_exact_child(self):
        self.child.kill.side_effect = ProcessLookupError("already exited")
        self.timeout()
        self.child.wait.assert_called_once_with(timeout=1)
        self.assertTrue(self.records[0]["child_reaped"])

    def test_exhausted_cleanup_budget_preserves_hold_without_extra_wait(self):
        self.timeout(exhausted=True)
        self.child.wait.assert_not_called()
        self.assertEqual(self.records[0]["status"], "CLEANUP_HOLD")
        self.assertFalse(self.records[0]["child_reaped"])

    def test_unreaped_child_is_not_reported_as_cleanup_success(self):
        self.child.wait.side_effect = subprocess.TimeoutExpired("inert compiler", 1)
        self.timeout()
        self.assertEqual(self.records[0]["status"], "CLEANUP_HOLD")
        self.child.kill.assert_called_once()

    def test_oversized_output_is_retained_and_stops_only_owned_child(self):
        def spawn(*args, **kwargs):
            kwargs["stdout"].write(b"x" * (gate.MAX_LOG + 1))
            kwargs["stdout"].flush()
            return self.child
        with mock.patch.object(gate.subprocess, "Popen", side_effect=spawn), \
             mock.patch.object(gate.time, "monotonic", return_value=10):
            with self.assertRaisesRegex(gate.BuildError, "output exceeds"):
                gate._command(["/inert/compiler"], self.output, "compile", 12, 15, self.records)
        self.child.kill.assert_called_once()
        self.assertEqual(self.records[0]["stdout"]["bytes"], gate.MAX_LOG + 1)
        self.assertIsNone(self.records[0]["stdout"]["sha256"])


if __name__ == "__main__":
    unittest.main()
