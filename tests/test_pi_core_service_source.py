"""Tiny local source fixtures only: no service, subprocess, network or activation."""

import hashlib
import importlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

_PATH = Path(__file__).absolute().parents[1] / "src/aragorn/pi_core_service_source.py"
_PRIVATE = "_aragorn_pi_service_source"
_PREFIX = "opt/aragorn/src/"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def info(value, **changes):
    fields = {key: getattr(value, key) for key in (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
        "st_size", "st_mtime_ns", "st_ctime_ns")}
    return SimpleNamespace(**(fields | changes))


class PiServiceSourceTests(unittest.TestCase):
    def setUp(self):
        self.previous = {name: module for name, module in sys.modules.copy().items()
                         if name == "aragorn" or name.startswith("aragorn.") or name == _PRIVATE}
        for name in self.previous:
            del sys.modules[name]
        spec = importlib.util.spec_from_file_location(_PRIVATE, _PATH)
        self.subject = importlib.util.module_from_spec(spec)
        sys.modules[_PRIVATE] = self.subject
        spec.loader.exec_module(self.subject)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "source"
        (self.root / "aragorn").mkdir(parents=True)
        self.sources = {
            "aragorn/__init__.py": b'TOKEN = "package"\n',
            "aragorn/alpha.py": b"VALUE = 7\n",
            "aragorn/beta.py": b"VALUE = 11\n",
        }
        self.loader = None
        self.patches = []
        original_directory, original_file = self.subject._directory, self.subject._file
        self.original_directory, self.original_file = original_directory, original_file
        # The fixture supplies ownership only; real file type/mode/name/byte
        # and descriptor checks still run. Host ancestors are not a VM image.
        self.patch("_directory", side_effect=lambda value, final=False: original_directory(
            info(value, st_uid=0, st_gid=0,
                 st_mode=value.st_mode if final else stat.S_IFDIR | 0o755), final=final))
        self.patch("_file", side_effect=lambda value: original_file(info(value, st_uid=0, st_gid=0)))

    def patch(self, name, **kwargs):
        patcher = mock.patch.object(self.subject, name, **kwargs)
        result = patcher.start()
        self.patches.append(patcher)
        return result

    def tearDown(self):
        if self.loader is not None and not self.loader._closed:
            self.loader.close()
        for name in list(sys.modules):
            if name == "aragorn" or name.startswith("aragorn.") or name == _PRIVATE:
                del sys.modules[name]
        sys.modules.update(self.previous)
        for patcher in reversed(self.patches):
            patcher.stop()
        for path in self.root.rglob("*"):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        self.root.chmod(0o755)
        self.temporary.cleanup()

    def prepare(self):
        for name, raw in self.sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o444)
        for path in self.root.rglob("*"):
            if path.is_dir():
                path.chmod(0o555)
        self.root.chmod(0o555)
        return {_PREFIX + name: digest(raw) for name, raw in self.sources.items()}

    def install(self, pins=None, deadline=None):
        if pins is None:
            pins = self.prepare()
        self.loader = self.subject.install(self.root, pins,
            deadline=time.monotonic() + 30 if deadline is None else deadline)
        return self.loader

    def change(self, name, raw):
        path = self.root / name
        path.chmod(0o644)
        path.write_bytes(raw)
        path.chmod(0o444)

    def assert_poisoned(self):
        with self.assertRaises(self.subject.PiServiceSourceError):
            self.loader.snapshot()

    def test_import_executes_pinned_buffer_and_reports_only_consumed_sources(self):
        self.install()
        real_compile = compile
        seen = []
        def consume(raw, filename, mode, **kwargs):
            seen.append((raw, filename, mode))
            return real_compile(raw, filename, mode, **kwargs)
        self.patch("compile", create=True, side_effect=consume)
        alpha = importlib.import_module("aragorn.alpha")
        self.assertEqual(alpha.VALUE, 7)
        self.assertEqual([row["module"] for row in self.loader.snapshot()], ["aragorn", "aragorn.alpha"])
        self.assertEqual([row[0] for row in seen], [self.sources["aragorn/__init__.py"], self.sources["aragorn/alpha.py"]])
        self.assertEqual(self.loader.snapshot()[1], {"module": "aragorn.alpha",
            "path": _PREFIX + "aragorn/alpha.py", "digest": digest(self.sources["aragorn/alpha.py"])})

    def test_snapshot_and_inventory_are_defensive_copies(self):
        self.install()
        importlib.import_module("aragorn")
        report = self.loader.snapshot()
        report[0]["digest"] = "changed"
        pins = self.loader.source_digests
        pins.clear()
        self.assertEqual(len(self.loader.source_digests), 3)
        self.assertNotEqual(self.loader.snapshot()[0]["digest"], "changed")

    def test_nested_packages_and_import_cycle_use_one_execution_each(self):
        self.sources.update({"aragorn/sub/__init__.py": b"from . import child\n",
            "aragorn/sub/child.py": b"from .. import alpha\nVALUE = alpha.VALUE\n",
            "aragorn/alpha.py": b"VALUE = 7\nfrom . import beta\n",
            "aragorn/beta.py": b"from . import alpha\nVALUE = alpha.VALUE\n"})
        self.install()
        package = importlib.import_module("aragorn.sub")
        self.assertEqual(package.child.VALUE, 7)
        names = [row["module"] for row in self.loader.snapshot()]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), {"aragorn", "aragorn.alpha", "aragorn.beta", "aragorn.sub", "aragorn.sub.child"})

    def test_unrelated_imports_are_not_intercepted(self):
        self.install()
        self.assertIsNone(self.loader.find_spec("json"))
        importlib.import_module("aragorn")
        self.assertEqual(len(self.loader.snapshot()), 1)

    def test_empty_snapshot_refuses_readiness(self):
        self.install()
        self.assert_poisoned()

    def test_wrong_digest_refuses_before_source_execution(self):
        pins = self.prepare()
        pins[_PREFIX + "aragorn/alpha.py"] = "sha256:" + "0" * 64
        self.install(pins)
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.alpha")
        self.assertNotIn("aragorn.alpha", sys.modules)
        self.assert_poisoned()

    def test_changed_source_after_import_refuses_snapshot(self):
        self.install()
        importlib.import_module("aragorn.alpha")
        self.change("aragorn/alpha.py", b"VALUE = 8\n")
        self.assert_poisoned()

    def test_source_changed_after_read_is_not_reported_successful(self):
        self.install()
        importlib.import_module("aragorn")
        real_compile = compile
        def changed(raw, filename, mode, **kwargs):
            self.assertEqual(raw, self.sources["aragorn/alpha.py"])
            self.change("aragorn/alpha.py", b"VALUE = 8\n")
            return real_compile(raw, filename, mode, **kwargs)
        self.patch("compile", create=True, side_effect=changed)
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_changed_directory_identity_refuses(self):
        self.install()
        importlib.import_module("aragorn")
        (self.root / "aragorn").chmod(0o755)
        self.assert_poisoned()

    def test_unlisted_module_has_no_standard_import_fallback(self):
        self.install()
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.not_approved")
        self.assert_poisoned()

    def test_alternate_package_search_path_refuses(self):
        self.install()
        package = importlib.import_module("aragorn")
        package.__path__ = ["/tmp/untrusted"]
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_reload_refuses_without_second_execution(self):
        self.install()
        alpha = importlib.import_module("aragorn.alpha")
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.reload(alpha)
        self.assert_poisoned()

    def test_execution_failure_is_permanent_even_if_source_is_repaired(self):
        self.sources["aragorn/alpha.py"] = b"raise RuntimeError('fixture failure')\n"
        self.install()
        with self.assertRaises(RuntimeError):
            importlib.import_module("aragorn.alpha")
        self.change("aragorn/alpha.py", b"VALUE = 7\n")
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_caught_import_failure_still_blocks_readiness(self):
        self.sources["aragorn/alpha.py"] = b"try:\n    from . import missing\nexcept RuntimeError:\n    VALUE = 7\n"
        self.install()
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_module_replacement_refuses(self):
        self.install()
        importlib.import_module("aragorn.alpha")
        sys.modules["aragorn.alpha"] = SimpleNamespace(VALUE=7)
        self.assert_poisoned()

    def test_unrecorded_module_refuses(self):
        self.install()
        importlib.import_module("aragorn")
        sys.modules["aragorn.injected"] = SimpleNamespace()
        self.assert_poisoned()

    def test_removed_or_shadowed_finder_refuses(self):
        self.install()
        importlib.import_module("aragorn")
        marker = object()
        sys.meta_path.insert(0, marker)
        try:
            self.assert_poisoned()
        finally:
            sys.meta_path.remove(marker)

    def test_bootstrap_module_replacement_refuses(self):
        self.install()
        importlib.import_module("aragorn")
        sys.modules[_PRIVATE] = SimpleNamespace(PiServiceSourceLoader=object)
        self.assert_poisoned()

    def test_already_imported_aragorn_refuses_installation(self):
        pins = self.prepare()
        sys.modules["aragorn"] = SimpleNamespace()
        with self.assertRaises(self.subject.PiServiceSourceError):
            self.install(pins)

    def test_deadline_does_not_extend_during_import_or_snapshot(self):
        self.install()
        importlib.import_module("aragorn")
        with mock.patch.object(self.subject.time, "monotonic", return_value=self.loader._deadline):
            self.assert_poisoned()

    def test_invalid_or_expired_initial_deadline_refuses(self):
        pins = self.prepare()
        for deadline in (True, float("nan"), float("inf"), 0):
            with self.subTest(deadline=deadline), self.assertRaises(self.subject.PiServiceSourceError):
                self.install(pins, deadline)

    def test_symlink_source_refuses(self):
        pins = self.prepare()
        package = self.root / "aragorn"
        package.chmod(0o755)
        (package / "alpha.py").unlink()
        (package / "alpha.py").symlink_to("beta.py")
        package.chmod(0o555)
        self.install(pins)
        with self.assertRaises(OSError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_hardlink_source_refuses(self):
        pins = self.prepare()
        package = self.root / "aragorn"
        package.chmod(0o755)
        os.link(package / "alpha.py", package / "second.py")
        package.chmod(0o555)
        self.install(pins)
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_writable_source_refuses(self):
        pins = self.prepare()
        (self.root / "aragorn/alpha.py").chmod(0o644)
        self.install(pins)
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_bytecode_is_not_a_missing_source_fallback(self):
        pins = self.prepare()
        package = self.root / "aragorn"
        package.chmod(0o755)
        (package / "alpha.py").unlink()
        (package / "alpha.pyc").write_bytes(b"not admitted bytecode")
        package.chmod(0o555)
        self.install(pins)
        with self.assertRaises(FileNotFoundError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_per_file_byte_bound_refuses(self):
        self.install()
        importlib.import_module("aragorn")
        self.patch("_MAX_FILE", new=1)
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_cumulative_byte_bound_refuses(self):
        self.install()
        importlib.import_module("aragorn")
        self.patch("_MAX_BYTES", new=len(self.sources["aragorn/__init__.py"]))
        with self.assertRaises(self.subject.PiServiceSourceError):
            importlib.import_module("aragorn.alpha")
        self.assert_poisoned()

    def test_inventory_rejects_missing_package_and_ambiguous_or_invalid_sources(self):
        valid = {_PREFIX + "aragorn/__init__.py": "sha256:" + "1" * 64}
        cases = ({}, {_PREFIX + "aragorn/a.py": "sha256:" + "1" * 64},
            valid | {_PREFIX + "aragorn/sub/a.py": "sha256:" + "1" * 64},
            valid | {_PREFIX + "aragorn/sub.py": "sha256:" + "1" * 64,
                     _PREFIX + "aragorn/sub/__init__.py": "sha256:" + "1" * 64},
            valid | {_PREFIX + "aragorn/../a.py": "sha256:" + "1" * 64},
            valid | {_PREFIX + "aragorn/a.pyc": "sha256:" + "1" * 64},
            {_PREFIX + "aragorn/__init__.py": "untrusted"})
        for pins in cases:
            with self.subTest(pins=pins), self.assertRaises(self.subject.PiServiceSourceError):
                self.subject._inventory(pins)

    def test_inventory_file_limit_refuses(self):
        with mock.patch.object(self.subject, "_MAX_FILES", 1), self.assertRaises(self.subject.PiServiceSourceError):
            self.subject._inventory({_PREFIX + name: digest(raw) for name, raw in self.sources.items()})

    def test_real_metadata_checks_reject_wrong_owner_type_or_writable_mode(self):
        value = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o444,
            st_nlink=1, st_size=1)
        self.original_file(value)
        for changes in ({"st_uid": 1}, {"st_gid": 1}, {"st_mode": stat.S_IFIFO | 0o444},
                        {"st_mode": stat.S_IFREG | 0o644}, {"st_nlink": 2}, {"st_size": -1}):
            with self.subTest(changes=changes), self.assertRaises(self.subject.PiServiceSourceError):
                self.original_file(SimpleNamespace(**(vars(value) | changes)))
        directory = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o555, st_nlink=2)
        self.original_directory(directory, final=True)
        for changes in ({"st_uid": 1}, {"st_gid": 1}, {"st_mode": stat.S_IFDIR | 0o777},
                        {"st_mode": stat.S_IFREG | 0o555}, {"st_nlink": 0}):
            with self.subTest(changes=changes), self.assertRaises(self.subject.PiServiceSourceError):
                self.original_directory(SimpleNamespace(**(vars(directory) | changes)), final=True)

    def test_close_revokes_and_closes_only_owned_descriptors(self):
        self.install()
        importlib.import_module("aragorn.alpha")
        owned = {fd for fd, _ in (*self.loader._files.values(), *self.loader._directories.values())}
        real_close = os.close
        with mock.patch.object(self.subject.os, "close", wraps=real_close) as close:
            self.loader.close()
        self.assertEqual({call.args[0] for call in close.call_args_list}, owned)
        self.assertEqual(close.call_count, len(owned))
        self.assertNotIn(self.loader, sys.meta_path)
        self.assert_poisoned()

    def test_descriptor_close_failure_is_not_retried(self):
        self.install()
        importlib.import_module("aragorn")
        real_close = os.close
        first = next(iter(self.loader._files.values()))[0]
        def uncertain(fd):
            real_close(fd)
            if fd == first:
                raise OSError("fixture close uncertainty")
        with mock.patch.object(self.subject.os, "close", side_effect=uncertain) as close:
            with self.assertRaises(self.subject.PiServiceSourceError):
                self.loader.close()
            count = close.call_count
            with self.assertRaises(self.subject.PiServiceSourceError):
                self.loader.close()
            self.assertEqual(close.call_count, count)


if __name__ == "__main__":
    unittest.main()
