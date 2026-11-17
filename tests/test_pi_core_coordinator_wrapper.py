"""Inert pinned-host wrapper checks; native identity and root custody are mocked.

Only exclusively owned temporary files are opened. No target interpreter,
service, process, socket, provider, credential or host profile is activated.
"""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

WRAPPER = Path(__file__).resolve().parents[1] / "packaging/pi-core/coordinator.py"


def info(value, **changes):
    fields = {key: getattr(value, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink",
        "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")}
    return types.SimpleNamespace(**(fields | changes))


class CoordinatorWrapperTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("coordinator_wrapper_fixture", WRAPPER)
        self.s = importlib.util.module_from_spec(spec)
        self.enterContext(mock.patch.dict(sys.modules, {spec.name: self.s}))
        spec.loader.exec_module(self.s)
        self.enterContext(mock.patch.dict(sys.modules, {self.s._PRIVATE: self.s}))
        for owner, name in ((subprocess, "run"), (subprocess, "Popen"), (socket, "socket"),
                            (socket, "create_connection"), (os, "system")):
            self.enterContext(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        self.temporary = self.enterContext(tempfile.TemporaryDirectory(prefix="aragorn-coordinator-inert-"))
        self.root = Path(self.temporary).resolve()
        self.python = self.root / "bin/python3.12"
        self.stdlib = self.root / "lib/python3.12"
        self.zip = self.root / "lib/python312.zip"
        self.source = self.root / "opt/aragorn/src"
        self.wrapper = self.root / "opt/aragorn/bin/coordinator.py"
        self.tools = tuple(self.root / "bin" / name for name in ("systemd-run", "systemctl", "busctl"))
        self.loader = self.source / "aragorn/pi_core_service_source.py"
        for name, value in (("_WRAPPER", self.wrapper), ("_SOURCE_ROOT", self.source),
                            ("_LOADER", self.loader), ("_TOOLS", self.tools)):
            self.enterContext(mock.patch.object(self.s, name, value))
        self.raw = {
            self.python: b"inert python", self.wrapper: b"inert wrapper",
            self.stdlib / "os.py": b"inert stdlib", self.stdlib / "__pycache__/os.cpython-312.pyc": b"inert pyc",
            self.stdlib / "lib-dynload/_fixture.so": b"inert native module",
            self.source / "aragorn/__init__.py": b"# inert package\n",
            self.source / "aragorn/pi_core_coordinator_entry.py": b"# inert fixed entry\n",
            self.loader: b"def install(root, pins, *, deadline):\n    return (root, pins, deadline)\n",
            **{path: b"inert control tool" for path in self.tools},
        }
        for path, raw in self.raw.items():
            self.write(path, raw, 0o555 if path in (*self.tools, self.python) else 0o444)
        self.profile_path = self.root / "host-profile.json"
        self.profile = {"schema": "aragorn/pi-core-coordinator-host/v1", "target": "linux-arm64-cpython312",
            "python_executable": str(self.python), "wrapper_path": str(self.wrapper),
            "stdlib_roots": [str(self.stdlib)],
            "sys_path": [str(self.zip), str(self.stdlib), str(self.stdlib / "lib-dynload")],
            "absent_sys_path": [str(self.zip)], "files": self.rows()}
        self.deadline = time.monotonic() + 20
        self.enterContext(mock.patch.object(sys, "path", list(self.profile["sys_path"])))
        self.enterContext(mock.patch.object(sys, "executable", str(self.python)))
        directory, file_guard = self.s._directory, self.s._file
        self.real_directory, self.real_file = directory, file_guard
        self.real_flags = self.s._flags
        self.flags = self.enterContext(mock.patch.object(self.s, "_flags"))
        self.real_process = self.s.PiCoordinatorHostCustody._process
        self.real_loaded = self.s.PiCoordinatorHostCustody._loaded_modules
        self.enterContext(mock.patch.object(self.s.PiCoordinatorHostCustody, "_process"))
        self.enterContext(mock.patch.object(self.s.PiCoordinatorHostCustody, "_loaded_modules"))
        self.enterContext(mock.patch.object(self.s, "_directory", side_effect=lambda value: directory(
            info(value, st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755))))
        self.enterContext(mock.patch.object(self.s, "_file", side_effect=lambda value, path:
            file_guard(info(value, st_uid=0, st_gid=0), path)))
        self.hosts = []
        self.addCleanup(self.close_hosts)

    def write(self, path, raw, mode=0o444):
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(mode)

    def rows(self):
        return [{"path": str(path), "digest": self.s._digest(raw), "size": len(raw)}
                for path, raw in sorted(self.raw.items())]

    def hold(self, pin=None):
        raw = self.s._canonical(self.profile)
        self.write(self.profile_path, raw, 0o400)
        host = self.s._hold_host(self.profile_path, pin or self.s._digest(raw), self.deadline)
        self.hosts.append(host)
        return host

    def close_hosts(self):
        for host in self.hosts:
            if not host._closed:
                host.close()

    def maps(self, path=None, *, inode=None, permissions="r-xp"):
        path = path or self.python
        metadata = path.stat()
        identity = metadata.st_ino if inode is None else inode
        return f"1000-2000 {permissions} 00000000 {os.major(metadata.st_dev):x}:{os.minor(metadata.st_dev):x} {identity} {path}\n".encode()

    def test_complete_pinned_temp_closure_and_bytecode_are_held(self):
        host = self.hold()
        self.assertEqual(host.manifest_digest, self.s._digest(self.profile_path.read_bytes()))
        self.assertEqual(host.snapshot()["files"], len(self.raw))
        self.assertFalse(host.snapshot()["phase3_exit_eligible"])
        self.assertIn(self.stdlib / "__pycache__/os.cpython-312.pyc", host._expected)

    def test_unmatched_independent_profile_pin_refuses(self):
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            self.hold("sha256:" + "0" * 64)

    def test_profile_rejects_extra_fields_wrong_target_and_entrypoint(self):
        for changes in ({"extra": "command"}, {"target": "darwin"}, {"wrapper_path": "/unapproved.py"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.s._profile(self.profile | changes)

    def test_profile_rejects_duplicate_paths_bad_pins_sizes_and_order(self):
        for mutate in (lambda rows: rows.append(rows[0]), lambda rows: rows.reverse(),
                       lambda rows: rows[0].update(size=True), lambda rows: rows[0].update(digest="self-pin"),
                       lambda rows: rows[0].update(path="/a/../b")):
            value = copy.deepcopy(self.profile)
            mutate(value["files"])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.s._profile(value)

    def test_canonical_document_rejects_duplicate_float_and_whitespace(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}', b'{ "a":1}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.s._document(raw)

    def test_full_stdlib_inventory_rejects_unpinned_bytecode(self):
        path = self.stdlib / "unapproved.pyc"
        self.write(path, b"not pinned")
        with self.assertRaisesRegex(ValueError, "subtree differs"):
            self.hold()

    def test_full_source_inventory_rejects_unpinned_python(self):
        self.write(self.source / "aragorn/extra.py", b"not pinned")
        with self.assertRaisesRegex(ValueError, "subtree differs"):
            self.hold()

    def test_source_bytecode_is_not_an_allowed_source_pin(self):
        path = self.source / "aragorn/extra.pyc"
        self.raw[path] = b"not source"
        self.profile["files"] = self.rows()
        with self.assertRaisesRegex(ValueError, "foreign files or bytecode"):
            self.s._profile(self.profile)

    def test_linked_import_subtree_is_refused(self):
        (self.stdlib / "alias.py").symlink_to(self.stdlib / "os.py")
        with self.assertRaisesRegex(ValueError, "link or special"):
            self.hold()

    def test_root_ownership_link_count_and_protected_modes_are_required(self):
        file_info = info(self.loader.stat(), st_uid=0, st_gid=0)
        self.real_file(file_info, self.loader)
        for changes in ({"st_uid": 99}, {"st_gid": 99}, {"st_nlink": 2},
                        {"st_mode": stat.S_IFREG | 0o664}, {"st_mode": stat.S_IFREG | 0o440}):
            with self.subTest(file=changes), self.assertRaises(ValueError):
                self.real_file(info(file_info, **changes), self.loader)
        directory_info = info(self.source.stat(), st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755)
        self.real_directory(directory_info)
        for changes in ({"st_uid": 99}, {"st_gid": 99}, {"st_mode": stat.S_IFDIR | 0o775}):
            with self.subTest(directory=changes), self.assertRaises(ValueError):
                self.real_directory(info(directory_info, **changes))

    def test_changed_held_bytes_poison_guard(self):
        host = self.hold()
        self.write(self.stdlib / "os.py", b"changed")
        with self.assertRaisesRegex(ValueError, "custody changed"):
            host.guard()
        with self.assertRaisesRegex(ValueError, "custody unavailable"):
            host.snapshot()

    def test_ambient_sys_path_refuses(self):
        sys.path.append("/ambient")
        with self.assertRaisesRegex(ValueError, "ambient Python search"):
            self.hold()

    def test_missing_zip_appearing_after_hold_refuses(self):
        host = self.hold()
        self.write(self.zip, b"unexpected archive")
        with self.assertRaisesRegex(ValueError, "zip appeared"):
            host.guard()

    def test_absent_search_paths_are_only_matching_zip_placeholders(self):
        value = copy.deepcopy(self.profile)
        value["sys_path"][0] = value["absent_sys_path"][0] = str(self.root / "external.zip")
        with self.assertRaisesRegex(ValueError, "outside approved stdlib"):
            self.s._profile(value)

    def test_owner_and_original_deadline_are_not_replaceable(self):
        host = self.hold()
        with self.assertRaisesRegex(ValueError, "deadline or owner"):
            host.guard(self.deadline + 1)
        host = self.hold()
        with mock.patch.object(self.s.os, "getpid", return_value=host._pid + 1):
            with self.assertRaisesRegex(ValueError, "deadline or owner"):
                host.guard()

    def test_expected_mapped_device_inode_join_is_required(self):
        host = self.hold()
        self.assertEqual(host._mapped_files(self.maps()), {self.python})
        with self.assertRaisesRegex(ValueError, "identity differs"):
            host._mapped_files(self.maps(inode=self.python.stat().st_ino + 1))

    def test_unpinned_deleted_and_anonymous_executable_maps_refuse(self):
        host = self.hold()
        for raw in (self.maps().replace(str(self.python).encode(), b"/unapproved"),
                    self.maps().rstrip() + b" (deleted)\n", b"1000-2000 r-xp 00000000 00:00 0\n",
                    self.maps(permissions="rwxp")):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                host._mapped_files(raw)

    def test_running_executable_is_joined_to_held_identity(self):
        host = self.hold()
        original = os.open
        with mock.patch.object(self.s.os, "open", side_effect=lambda path, flags, **kwargs:
                os.dup(host._files[self.python][0]) if path == "/proc/self/exe" else original(path, flags, **kwargs)), \
                mock.patch("builtins.open", return_value=io.BytesIO(self.maps())):
            self.real_process(host)
        with mock.patch.object(self.s.os, "open", side_effect=lambda path, flags, **kwargs:
                os.dup(host._files[self.tools[0]][0]) if path == "/proc/self/exe" else original(path, flags, **kwargs)):
            with self.assertRaisesRegex(ValueError, "running Python identity"):
                self.real_process(host)

    def test_loaded_module_origin_and_cached_file_must_be_pinned(self):
        host = self.hold()
        module = types.ModuleType("fixture")
        module.__file__ = str(self.stdlib / "os.py")
        module.__cached__ = str(self.stdlib / "__pycache__/os.cpython-312.pyc")
        with mock.patch.dict(sys.modules, {"fixture": module}, clear=True):
            self.real_loaded(host)
            module.__file__ = "/ambient/module.py"
            with self.assertRaisesRegex(ValueError, "outside approved host"):
                self.real_loaded(host)

    def test_typing_compatibility_alias_requires_its_pinned_parent(self):
        host = self.hold()
        typing = types.ModuleType("typing")
        typing.__file__ = str(self.stdlib / "os.py")
        typing.io = type("io", (), {"__module__": "typing"})
        with mock.patch.dict(sys.modules, {"typing": typing, "typing.io": typing.io}, clear=True):
            self.real_loaded(host)
            sys.modules["typing.io"] = type("io", (), {"__module__": "typing"})
            with self.assertRaisesRegex(ValueError, "compatibility namespace"):
                self.real_loaded(host)

    def test_bootstrap_executes_only_verified_loader_bytes(self):
        host = self.hold()
        with mock.patch.dict(sys.modules, {self.s._PRIVATE: self.s}, clear=True):
            root, pins, deadline = self.s._bootstrap(host)
        self.assertEqual(root, self.source)
        self.assertEqual(pins[str(self.loader)[1:]], self.s._digest(self.raw[self.loader]))
        self.assertEqual(deadline, self.deadline)

    def test_preimported_aragorn_refuses_before_bootstrap(self):
        host = self.hold()
        with mock.patch.dict(sys.modules, {"aragorn": types.ModuleType("aragorn")}):
            with self.assertRaisesRegex(ValueError, "before bootstrap"):
                self.s._bootstrap(host)

    def test_changed_loader_refuses_before_execution(self):
        host = self.hold()
        self.write(self.loader, b"raise AssertionError('never execute substituted source')\n")
        with self.assertRaisesRegex(ValueError, "custody changed"):
            self.s._bootstrap(host)

    def test_close_failure_attempts_each_descriptor_once_and_refuses_retry(self):
        host = self.hold()
        closed, original = [], os.close
        def close(fd):
            original(fd)
            closed.append(fd)
            if len(closed) == 1:
                raise OSError("inert uncertain close")
        with mock.patch.object(self.s.os, "close", side_effect=close):
            with self.assertRaisesRegex(ValueError, "cleanup hold"):
                host.close()
            count = len(closed)
            with self.assertRaisesRegex(ValueError, "no retry"):
                host.close()
            self.assertEqual(len(closed), count)
        self.assertEqual(len(closed), len(set(closed)))

    def flags_context(self):
        self.enterContext(mock.patch.object(sys, "platform", "linux"))
        self.enterContext(mock.patch.object(sys, "version_info", (3, 12)))
        self.enterContext(mock.patch.object(sys, "flags", types.SimpleNamespace(isolated=1, no_site=1)))
        self.enterContext(mock.patch.object(sys, "dont_write_bytecode", True))
        self.enterContext(mock.patch.object(os, "uname", return_value=types.SimpleNamespace(machine="aarch64")))
        for name in ("getuid", "geteuid", "getgid", "getegid"):
            self.enterContext(mock.patch.object(os, name, return_value=0))
        self.enterContext(mock.patch.dict(os.environ, {}, clear=True))

    def test_platform_root_isolation_and_unsafe_environment_guards(self):
        self.flags_context()
        self.real_flags()
        for name in ("OPENAI_API_KEY", "LD_PRELOAD", "PYTHONPATH", "http_proxy", "GCONV_PATH"):
            with mock.patch.dict(os.environ, {name: "private"}), self.assertRaisesRegex(ValueError, "unsafe environment"):
                self.real_flags()
        with mock.patch.object(sys, "dont_write_bytecode", False), self.assertRaisesRegex(ValueError, "protected Linux"):
            self.real_flags()

    def observation(self):
        host = self.hold()
        return {"schema": "aragorn/pi-core-coordinator-observation/v1", "phase3_exit_eligible": False,
            "status": "MANAGED_CALL_RETURNED_NOT_QUALIFIED", "managed_call_attempted": True,
            "owned_inputs_closed": True, "plan_digest": "sha256:" + "a" * 64,
            "deployment_digest": "sha256:" + "b" * 64, "host_before": host.snapshot(), "host_after": host.snapshot(),
            "source_before": [{"module": "aragorn", "path": "opt/aragorn/src/aragorn/__init__.py", "digest": "sha256:" + "c" * 64}],
            "source_after": [{"module": "aragorn", "path": "opt/aragorn/src/aragorn/__init__.py", "digest": "sha256:" + "c" * 64}],
            "managed_result": {"status": "BOOTSTRAP_COMPLETE", "private_task": "NEVER_PRINT_ME",
                "worker": {"cleanup": {"status": "VERIFIED_OWNED_CLEANUP"}},
                "services": {"cleanup": {"status": "VERIFIED_OWNED_CLEANUP"}}}}

    def test_public_report_retains_custody_but_only_digest_of_managed_content(self):
        value = self.observation()
        report = self.s._public_observation(value)
        raw = self.s._canonical(report)
        self.assertNotIn(b"NEVER_PRINT_ME", raw)
        self.assertEqual(report["source_after"], value["source_after"])
        self.assertEqual(report["host_after"], value["host_after"])
        self.assertEqual(report["managed_result_digest"], self.s._digest(self.s._canonical(value["managed_result"])))
        self.assertTrue(report["managed_cleanup_complete"])

    def test_public_report_rejects_unstructured_source_or_failure_text(self):
        value = self.observation()
        value["failure_stage"] = "PRIVATE_ERROR_BODY"
        with self.assertRaisesRegex(ValueError, "failure stage"):
            self.s._public_observation(value)
        value.pop("failure_stage")
        value["source_after"][0]["secret"] = "private"
        with self.assertRaisesRegex(ValueError, "source observation row"):
            self.s._public_observation(value)

    def invoke_main(self, observation, *, after_guard=None, cleanup_error=False, entry_error=False):
        host = types.SimpleNamespace(guard=mock.Mock(side_effect=after_guard), close=mock.Mock())
        loader = types.SimpleNamespace(close=mock.Mock(side_effect=OSError("private close detail") if cleanup_error else None))
        entry = types.ModuleType("aragorn.pi_core_coordinator_entry")
        error = ValueError("private call detail")
        error.observation = observation
        entry.run = mock.Mock(side_effect=error if entry_error else None, return_value=observation)
        package = types.ModuleType("aragorn")
        package.__path__ = []
        with mock.patch.object(self.s, "__file__", str(self.wrapper)), \
                mock.patch.object(self.s, "_hold_host", return_value=host), \
                mock.patch.object(self.s, "_bootstrap", return_value=loader), \
                mock.patch.object(sys, "argv", [str(self.wrapper), str(self.profile_path), "sha256:" + "d" * 64,
                    str(self.root / "plan.json"), "sha256:" + "e" * 64, str(int(self.deadline * 1_000_000_000))]), \
                mock.patch.dict(sys.modules, {"aragorn": package, "aragorn.pi_core_coordinator_entry": entry}), \
                mock.patch("builtins.print") as printed:
            sys.modules.pop(self.s._PRIVATE, None)
            status = self.s.main()
        host.close.assert_called_once_with()
        loader.close.assert_called_once_with()
        entry.run.assert_called_once()
        return status, json.loads(printed.call_args.args[0])

    def test_main_calls_fixed_entry_once_and_reports_only_completed_bootstrap(self):
        status, report = self.invoke_main(self.observation())
        self.assertEqual(status, 0)
        self.assertEqual(report["status"], "MANAGED_BOOTSTRAP_RETURNED_NOT_QUALIFIED")
        self.assertNotIn("NEVER_PRINT_ME", json.dumps(report))

    def test_main_does_not_promote_refusal_or_missing_cleanup(self):
        for refusal in (True, False):
            value = self.observation()
            if refusal:
                value["managed_result"]["status"] = "REFUSED"
            else:
                value["managed_result"]["worker"]["cleanup"]["status"] = "CLEANUP_HOLD"
            status, report = self.invoke_main(value)
            self.assertEqual(status, 126)
            self.assertEqual(report["managed_status"], "REFUSED" if refusal else "BOOTSTRAP_COMPLETE")

    def test_main_keeps_result_after_post_call_custody_failure(self):
        value = self.observation()
        status, report = self.invoke_main(value, after_guard=[None, ValueError("private guard detail")])
        self.assertEqual(status, 126)
        self.assertEqual(report["wrapper_stage"], "POST_CALL_CUSTODY")
        self.assertEqual(report["source_before"], value["source_before"])
        self.assertIsNotNone(report["managed_result_digest"])

    def test_main_keeps_result_and_cleanup_hold_without_retry(self):
        status, report = self.invoke_main(self.observation(), cleanup_error=True)
        self.assertEqual(status, 126)
        self.assertEqual(report["wrapper_cleanup"]["source_loader"], "CLEANUP_HOLD")
        self.assertIsNotNone(report["managed_result_digest"])

    def test_main_keeps_entry_exception_observation_and_stage(self):
        value = self.observation()
        value.update(status="REFUSED_OR_INDETERMINATE", failure_stage="MANAGED_CALL")
        status, report = self.invoke_main(value, entry_error=True)
        self.assertEqual(status, 126)
        self.assertEqual(report["entry_failure_stage"], "MANAGED_CALL")
        self.assertIsNotNone(report["managed_result_digest"])

    def test_main_report_refusal_preserves_attempted_or_unknown(self):
        for attempted in (True, "malformed"):
            value = self.observation()
            value["managed_call_attempted"] = attempted
            value["managed_result"]["private_task"] = "x" * (4 * 1024 * 1024)
            status, report = self.invoke_main(value)
            self.assertEqual(status, 126)
            self.assertEqual(report["wrapper_stage"], "REPORT_REFUSED")
            self.assertIs(report["managed_call_attempted"], True if attempted is True else None)
            self.assertTrue(report["entry_call_attempted"])
        status, report = self.invoke_main(None, entry_error=True)
        self.assertEqual(status, 126)
        self.assertIsNone(report["managed_call_attempted"])
        self.assertTrue(report["entry_call_attempted"])

    def test_partial_host_acquisition_cleanup_hold_is_reported_without_retry(self):
        original_close = self.s.PiCoordinatorHostCustody.close
        held, close_calls = [], []
        original_init = self.s.PiCoordinatorHostCustody.__init__
        def initialize(host, *args):
            original_init(host, *args)
            held.append(host)
        def close(host):
            original_close(host)
            close_calls.append(host)
            raise OSError("private ambiguous cleanup detail")
        self.write(self.profile_path, b"invalid host document", 0o400)
        sys.modules.pop(self.s._PRIVATE, None)
        with mock.patch.object(self.s, "__file__", str(self.wrapper)), \
                mock.patch.object(self.s.PiCoordinatorHostCustody, "__init__", initialize), \
                mock.patch.object(self.s.PiCoordinatorHostCustody, "close", close), \
                mock.patch.object(sys, "argv", [str(self.wrapper), str(self.profile_path),
                    self.s._digest(b"invalid host document"), str(self.root / "plan.json"),
                    "sha256:" + "e" * 64, str(int(self.deadline * 1_000_000_000))]), \
                mock.patch.object(self.s, "_bootstrap", side_effect=AssertionError("must not bootstrap")), \
                mock.patch("builtins.print") as printed:
            status = self.s.main()
        report = json.loads(printed.call_args.args[0])
        self.assertEqual(status, 126)
        self.assertEqual(report["wrapper_cleanup"]["host"], "CLEANUP_HOLD")
        self.assertFalse(report["entry_call_attempted"])
        self.assertEqual(close_calls, held)
        self.assertEqual(len(held), 1)
        self.assertTrue(held[0]._closed)
