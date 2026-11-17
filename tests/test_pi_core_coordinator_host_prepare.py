"""New retained-export preparation checks; all native bytes are inert fixtures."""

import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

from tests import test_pi_core_os_root as elf_fixture
from tests import test_pi_core_service_image as image_fixture

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pi_host_prepare_fixture", ROOT / "scripts/prepare_pi_core_coordinator_host.py")
assert SPEC and SPEC.loader
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class PiCoordinatorHostPrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory(prefix="pi-host-export-inert-"))
        self.parent = Path(self.temp).resolve()
        self.export = self.parent / "export"
        self.export.mkdir()
        for owner, name in ((subprocess, "run"), (subprocess, "Popen"), (socket, "socket"),
                            (socket, "create_connection"), (os, "system")):
            self.enterContext(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        self.python = "/usr/bin/python3.12"
        self.stdlib = "/usr/lib/python3.12"
        self.loader = "/lib/ld-linux-aarch64.so.1"
        self.libc = "/lib/libc.so.6"
        self.extension = self.stdlib + "/lib-dynload/_fixture.so"
        self.raw = {
            self.python: elf_fixture.elf(interpreter=self.loader, needed=("libc.so.6",)),
            self.loader: elf_fixture.elf(soname="ld-linux-aarch64.so.1"),
            self.libc: elf_fixture.elf(soname="libc.so.6"),
            self.extension: elf_fixture.elf(needed=("libc.so.6",)),
            self.stdlib + "/os.py": b"# inert stdlib\n",
            self.stdlib + "/__pycache__/os.cpython-312.pyc": b"inert pinned bytecode",
            "/opt/aragorn/bin/coordinator.py": b"# inert coordinator\n",
            "/opt/aragorn/src/aragorn/__init__.py": b"# inert package\n",
            "/opt/aragorn/src/aragorn/pi_core_service_source.py": b"# inert loader\n",
            "/opt/aragorn/src/aragorn/pi_core_coordinator_entry.py": b"# inert managed entry\n",
            "/opt/aragorn/src/aragorn/pi_core_installed_inventory_entry.py": b"# inert preparation entry\n",
            **{str(path): elf_fixture.elf(interpreter=self.loader, needed=("libc.so.6",))
               for path in prepare.host_contract._TOOLS}}
        for name, raw in self.raw.items():
            self.write(name, raw, 0o555 if raw.startswith(b"\x7fELF") else 0o444)
        self.profile = {"schema": "aragorn/pi-core-coordinator-host/v1", "target": "linux-arm64-cpython312",
            "python_executable": self.python, "wrapper_path": "/opt/aragorn/bin/coordinator.py",
            "stdlib_roots": [self.stdlib],
            "sys_path": ["/usr/lib/python312.zip", self.stdlib, self.stdlib + "/lib-dynload"],
            "absent_sys_path": ["/usr/lib/python312.zip"], "files": self.rows()}

    def write(self, name, raw, mode=0o444):
        path = self.export / name[1:]
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def rows(self):
        return [{"path": name, "digest": prepare.host_contract._digest(raw), "size": len(raw)}
                for name, raw in sorted(self.raw.items())]

    def approved_replace(self, name, raw):
        self.raw[name] = raw
        self.write(name, raw, 0o555)
        self.profile["files"] = self.rows()

    def approved_remove(self, name):
        (self.export / name[1:]).unlink()
        self.raw.pop(name)
        self.profile["files"] = self.rows()

    def run_prepare(self):
        raw = prepare.host_contract._canonical(self.profile)
        return prepare.prepare_pi_coordinator_host_profile(raw,
            expected_profile_digest=prepare.host_contract._digest(raw), retained_root=self.export)

    def test_preparation_preserves_approved_bytes_without_qualification(self):
        before = prepare._inventory(self.export)
        result = self.run_prepare()
        self.assertEqual(result.profile_raw, prepare.host_contract._canonical(self.profile))
        receipt = json.loads(result.preparation_raw)
        self.assertEqual(receipt["host_profile_digest"], prepare.host_contract._digest(result.profile_raw))
        self.assertEqual(receipt["files"], len(self.raw))
        self.assertEqual(receipt["native_files"], 7)
        self.assertEqual(receipt["status"], "PREPARED_RETAINED_EXPORT_NOT_INSTALLED_OR_EXECUTED")
        for flag in ("phase3_exit_eligible", "executed_target_code", "installed_root_protection_verified",
                     "actual_loader_resolution_verified"):
            self.assertIs(receipt[flag], False)
        self.assertEqual(before, prepare._inventory(self.export))
        with self.assertRaises(AttributeError):
            result.profile_raw = b"replacement"

    def test_independent_pin_is_checked_before_export_reads(self):
        with mock.patch.object(prepare, "_root", side_effect=AssertionError("must not inspect export")):
            with self.assertRaisesRegex(ValueError, "independent expected"):
                prepare.prepare_pi_coordinator_host_profile(prepare.host_contract._canonical(self.profile),
                    expected_profile_digest="sha256:" + "0" * 64, retained_root=self.export)

    def test_profile_validator_is_reused_before_export_reads(self):
        self.profile["command"] = "unapproved"
        with mock.patch.object(prepare, "_root", side_effect=AssertionError("must not inspect export")):
            with self.assertRaisesRegex(ValueError, "fixed host profile"):
                self.run_prepare()

    def test_noncanonical_profile_is_not_auto_approved(self):
        raw = json.dumps(self.profile).encode()
        with mock.patch.object(prepare, "_root", side_effect=AssertionError("must not inspect export")):
            with self.assertRaisesRegex(ValueError, "canonical host"):
                prepare.prepare_pi_coordinator_host_profile(raw,
                    expected_profile_digest=prepare.host_contract._digest(raw), retained_root=self.export)

    def test_live_root_is_refused_before_inventory(self):
        self.export = Path("/")
        with mock.patch.object(prepare, "_inventory", side_effect=AssertionError("must not scan host")):
            with self.assertRaisesRegex(ValueError, "unlinked retained export"):
                self.run_prepare()

    def test_linked_root_or_ancestor_is_not_resolved_into_approval(self):
        original = self.export
        alias = self.parent / "alias"
        alias.symlink_to(original, target_is_directory=True)
        self.export = alias
        with self.assertRaisesRegex(ValueError, "unlinked retained export"):
            self.run_prepare()
        alias.unlink()
        alias.symlink_to(original.parent, target_is_directory=True)
        self.export = alias / original.name
        with self.assertRaisesRegex(ValueError, "unlinked retained export"):
            self.run_prepare()

    def test_missing_declared_file_refuses(self):
        (self.export / self.libc[1:]).unlink()
        with self.assertRaisesRegex(ValueError, "namespace differs"):
            self.run_prepare()

    def test_unlisted_file_outside_import_subtrees_refuses(self):
        self.write("/etc/unlisted", b"not approved")
        with self.assertRaisesRegex(ValueError, "namespace differs"):
            self.run_prepare()

    def test_unlisted_stdlib_bytecode_refuses(self):
        self.write(self.stdlib + "/extra.pyc", b"not approved")
        with self.assertRaisesRegex(ValueError, "namespace differs"):
            self.run_prepare()

    def test_source_bytecode_cannot_be_added_to_approved_profile(self):
        self.approved_replace("/opt/aragorn/src/aragorn/extra.pyc", b"not source")
        with self.assertRaisesRegex(ValueError, "foreign files or bytecode"):
            self.run_prepare()

    def test_symlink_file_refuses_without_following(self):
        selected = self.export / self.libc[1:]
        selected.unlink()
        selected.symlink_to(self.export / self.loader[1:])
        with self.assertRaisesRegex(ValueError, "linked or special"):
            self.run_prepare()

    def test_hardlinked_file_refuses(self):
        os.link(self.export / self.libc[1:], self.export / "duplicate")
        with self.assertRaisesRegex(ValueError, "linked or special"):
            self.run_prepare()

    def test_special_file_refuses_without_opening_it(self):
        os.mkfifo(self.export / "inert-fifo")
        with self.assertRaisesRegex(ValueError, "linked or special"):
            self.run_prepare()

    def test_changed_file_pin_refuses_without_substitution(self):
        self.write(self.stdlib + "/os.py", b"changed")
        with self.assertRaisesRegex(ValueError, "bytes or identity differ"):
            self.run_prepare()

    def test_reviewed_size_must_match_actual_bytes(self):
        self.profile["files"][0]["size"] += 1
        with self.assertRaisesRegex(ValueError, "bytes or identity differ"):
            self.run_prepare()

    def test_bootstrap_source_requires_fixed_export_mode(self):
        (self.export / "opt/aragorn/bin/coordinator.py").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "bootstrap source mode"):
            self.run_prepare()

    def test_native_entrypoint_requires_executable_mode(self):
        (self.export / self.python[1:]).chmod(0o444)
        with self.assertRaisesRegex(ValueError, "entrypoint is not executable"):
            self.run_prepare()

    def test_absent_zip_cannot_be_a_directory_either(self):
        (self.export / "usr/lib/python312.zip").mkdir()
        with self.assertRaisesRegex(ValueError, "absent Python zip is present"):
            self.run_prepare()

    def during_native(self, effect):
        original = prepare._native_inventory
        def native(*args):
            result = original(*args)
            effect()
            return result
        return mock.patch.object(prepare, "_native_inventory", side_effect=native)

    def test_changed_bytes_during_preparation_are_not_re_pinned(self):
        with self.during_native(lambda: self.write(self.stdlib + "/os.py", b"changed")):
            with self.assertRaisesRegex(ValueError, "changed before read"):
                self.run_prepare()

    def test_identical_byte_name_substitution_is_refused(self):
        def substitute():
            name = self.stdlib + "/os.py"
            replacement = self.write("/replacement", self.raw[name])
            replacement.replace(self.export / name[1:])
        with self.during_native(substitute):
            with self.assertRaisesRegex(ValueError, "changed before read"):
                self.run_prepare()

    def test_new_namespace_member_during_preparation_is_refused(self):
        with self.during_native(lambda: self.write("/unlisted", b"not approved")):
            with self.assertRaisesRegex(ValueError, "namespace or identity changed"):
                self.run_prepare()

    def test_wrong_architecture_control_tool_refuses(self):
        self.approved_replace("/usr/bin/systemctl", elf_fixture.elf(machine=62))
        with self.assertRaisesRegex(ValueError, "not little-endian Linux arm64"):
            self.run_prepare()

    def test_shared_library_named_non_elf_refuses(self):
        self.approved_replace(self.extension, b"not ELF")
        with self.assertRaisesRegex(ValueError, "not little-endian Linux arm64"):
            self.run_prepare()

    def test_missing_declared_interpreter_refuses(self):
        self.approved_remove(self.loader)
        with self.assertRaisesRegex(ValueError, "interpreter is absent"):
            self.run_prepare()

    def test_missing_declared_dependency_refuses(self):
        self.approved_remove(self.libc)
        with self.assertRaisesRegex(ValueError, "missing or ambiguous declared ELF dependency"):
            self.run_prepare()

    def test_ambiguous_declared_dependency_refuses_even_identical_bytes(self):
        self.approved_replace("/usr/lib/libc.so.6", self.raw[self.libc])
        with self.assertRaisesRegex(ValueError, "missing or ambiguous declared ELF dependency"):
            self.run_prepare()

    def test_library_basename_and_soname_both_must_match(self):
        self.approved_replace(self.libc, elf_fixture.elf(soname="different.so"))
        with self.assertRaisesRegex(ValueError, "missing or ambiguous declared ELF dependency"):
            self.run_prepare()

    def test_python_origin_policy_is_reported_not_claimed_as_runtime_resolution(self):
        self.approved_replace(self.python, image_fixture.python_elf(needed=("libc.so.6",)))
        receipt = json.loads(self.run_prepare().preparation_raw)
        self.assertEqual(receipt["declared_search_policy"][self.python], "$ORIGIN/../lib")
        self.assertFalse(receipt["actual_loader_resolution_verified"])

    def test_unapproved_python_search_policy_refuses(self):
        self.approved_replace(self.python, image_fixture.python_elf(rpath="/ambient", needed=("libc.so.6",)))
        with self.assertRaisesRegex(ValueError, "unapproved ELF relative search path"):
            self.run_prepare()

    def test_native_count_remains_bounded(self):
        with mock.patch.object(prepare, "_MAX_NATIVE", 2):
            with self.assertRaisesRegex(ValueError, "native file bound"):
                self.run_prepare()

    def test_cleanup_read_failure_returns_no_prepared_result(self):
        with mock.patch.object(prepare._build, "regular_bytes", side_effect=OSError("owned read close uncertain")):
            with self.assertRaises(OSError):
                self.run_prepare()

    def test_cli_emits_canonical_artifacts_without_writing_output(self):
        raw = prepare.host_contract._canonical(self.profile)
        profile_path = self.parent / "reviewed-profile.json"
        profile_path.write_bytes(raw)
        before = set(self.parent.iterdir())
        with mock.patch("builtins.print") as printed:
            result = prepare.main(["--profile", str(profile_path), "--profile-digest",
                prepare.host_contract._digest(raw), "--retained-root", str(self.export)])
        self.assertEqual(result, 0)
        output = printed.call_args.args[0].encode()
        self.assertEqual(prepare.host_contract._canonical(json.loads(output)), output)
        self.assertEqual(json.loads(output)["profile"], self.profile)
        self.assertEqual(set(self.parent.iterdir()), before)

    def test_cli_failure_does_not_emit_private_error_text(self):
        with mock.patch.object(prepare._build, "regular_bytes", side_effect=OSError("PRIVATE_FAILURE")), \
                mock.patch("sys.stderr") as stderr:
            with self.assertRaises(SystemExit) as error:
                prepare.main(["--profile", "/inert/missing", "--profile-digest", "sha256:" + "0" * 64,
                              "--retained-root", str(self.export)])
        self.assertEqual(error.exception.code, 1)
        self.assertNotIn("PRIVATE_FAILURE", str(stderr.write.call_args_list))
