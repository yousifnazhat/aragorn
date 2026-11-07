"""New wrapper rendering/bootstrap checks; inert files, no service execution."""

import ast
import hashlib
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock

from tests import test_pi_core_service_image as previous


class SourceWrapperTests(previous.PiCoreServiceImageTests):
    def setUp(self):
        super().setUp()
        self.loader_raw = b"def install(root, pins, *, deadline):\n    return (root, pins, deadline)\n"
        self.add_source(previous.image.SOURCE_LOADER, self.loader_raw)
        for role in previous.image.ROLES:
            path = previous.ROOT / "packaging/pi-core/services-v2" / (role + ".py")
            raw = path.read_bytes()
            (self.wrappers / path.name).write_bytes(raw)
            self.wrapper_inventory[path.name] = previous.image.pin(raw)

    def test_rendered_wrappers_embed_exact_source_pins_without_execution(self):
        wrappers = previous.image._wrappers(self.wrappers, self.wrapper_inventory, self.inventory)
        for name, raw in wrappers.items():
            tree = ast.parse(raw)
            pins = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "_ARAGORN_SOURCE_DIGESTS"
                                for target in node.targets))
            self.assertEqual(pins, {previous.image.IMPORT_ROOT + "/" + key: value for key, value in self.inventory.items()})
            self.assertNotIn(previous.image.SOURCE_PIN_MARKER, raw)
            self.assertIn(("service_main(\"" + name[:-3] + "\", source_loader=loader)").encode(), raw)

    def test_template_requires_explicit_loader_pin(self):
        for pins in (None, {key: value for key, value in self.inventory.items() if key != previous.image.SOURCE_LOADER}):
            with self.subTest(pins=pins), self.assertRaises(previous.image.ServiceImageError):
                previous.image._wrappers(self.wrappers, self.wrapper_inventory, pins)

    def test_duplicate_pin_marker_refused(self):
        path = self.wrappers / "action.py"
        raw = path.read_bytes() + previous.image.SOURCE_PIN_MARKER
        path.write_bytes(raw)
        self.wrapper_inventory[path.name] = previous.image.pin(raw)
        with self.assertRaises(previous.image.ServiceImageError):
            previous.image._wrappers(self.wrappers, self.wrapper_inventory, self.inventory)

    def test_source_loader_is_part_of_exact_static_closure(self):
        selected, _, _ = self.closure()
        self.assertEqual(selected[previous.image.SOURCE_LOADER], self.loader_raw)

    def test_successor_image_pins_rendered_not_template_wrapper_bytes(self):
        receipt = self.assemble()
        raw = (self.output / "root/opt/aragorn/bin/action.py").read_bytes()
        self.assertNotEqual(previous.image.pin(raw), self.wrapper_inventory["action.py"])
        self.assertIn(previous.image.IMPORT_ROOT + "/" + previous.image.SOURCE_LOADER, receipt["source_mapping"])
        self.assertFalse(receipt["executed_target_code"])

    def wrapper(self):
        # Defining the fixed wrapper is inert: __main__ and service paths do not run.
        raw = previous.image._wrappers(self.wrappers, self.wrapper_inventory, self.inventory)["action.py"]
        namespace = {"__name__": "wrapper_fixture"}
        exec(compile(raw, "action.py", "exec"), namespace)
        target = self.source / previous.image.SOURCE_LOADER
        namespace["_LOADER"] = str(target)
        namespace["_ARAGORN_SOURCE_DIGESTS"] = {str(target)[1:]: previous.image.pin(self.loader_raw)}
        self.addCleanup(sys.modules.pop, namespace["_PRIVATE"], None)
        original = namespace["os"].fstat

        def metadata(fd):
            result = original(fd)
            fields = {key: getattr(result, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
            fields.update(st_uid=0, st_gid=0)
            fields["st_mode"] = stat.S_IFDIR | 0o755 if stat.S_ISDIR(result.st_mode) else stat.S_IFREG | 0o444
            return types.SimpleNamespace(**fields)

        original_stat = namespace["os"].stat

        def named(path, **kwargs):
            result = original_stat(path, **kwargs)
            return types.SimpleNamespace(**{key: 0 if key in ("st_uid", "st_gid") else
                stat.S_IFREG | 0o444 if key == "st_mode" else getattr(result, key) for key in
                ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})

        self.enterContext(mock.patch.object(namespace["os"], "fstat", side_effect=metadata))
        self.enterContext(mock.patch.object(namespace["os"], "stat", side_effect=named))
        self.enterContext(mock.patch.object(namespace["time"], "monotonic", return_value=1.0))
        return namespace, target

    def test_bootstrap_compiles_the_verified_buffer(self):
        namespace, _ = self.wrapper()
        result = namespace["_bootstrap"](10.0)
        self.assertEqual(result, (Path("/opt/aragorn/src"), namespace["_ARAGORN_SOURCE_DIGESTS"], 10.0))

    def test_changed_loader_refuses_before_compile(self):
        namespace, target = self.wrapper()
        target.write_bytes(b"raise AssertionError('unapproved loader executed')\n")
        with self.assertRaises(ValueError):
            namespace["_bootstrap"](10.0)
        self.assertNotIn(namespace["_PRIVATE"], sys.modules)

    def test_bootstrap_deadline_refuses(self):
        namespace, _ = self.wrapper()
        with self.assertRaises(ValueError):
            namespace["_bootstrap"](1.0)
        self.assertNotIn(namespace["_PRIVATE"], sys.modules)

    def test_preloaded_bootstrap_module_refuses(self):
        namespace, _ = self.wrapper()
        sys.modules[namespace["_PRIVATE"]] = types.ModuleType("unrelated")
        with self.assertRaises(ValueError):
            namespace["_bootstrap"](10.0)
        self.assertEqual(sys.modules[namespace["_PRIVATE"]].__name__, "unrelated")

    def test_bootstrap_close_failure_attempts_all_owned_handles_once(self):
        namespace, _ = self.wrapper()
        close = namespace["os"].close
        closed = []

        def fail_after_first_close(fd):
            close(fd)
            closed.append(fd)
            if len(closed) == 1:
                raise OSError("inert close uncertainty")

        with mock.patch.object(namespace["os"], "close", side_effect=fail_after_first_close):
            with self.assertRaisesRegex(ValueError, "cleanup hold"):
                namespace["_bootstrap"](10.0)
        self.assertGreater(len(closed), 2)
        self.assertEqual(len(closed), len(set(closed)))

    def test_main_redacts_loader_cleanup_failure(self):
        namespace, _ = self.wrapper()
        holder = types.SimpleNamespace(close=mock.Mock(side_effect=OSError("private detail")))
        service = types.ModuleType("aragorn.pi_core_service_entry")
        service.main = mock.Mock(return_value=0)
        package = types.ModuleType("aragorn")
        package.__path__ = []
        with mock.patch.dict(namespace, {"_bootstrap": mock.Mock(return_value=holder)}), \
                mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(sys, "flags", types.SimpleNamespace(isolated=1, no_site=1)), \
                mock.patch.object(sys, "dont_write_bytecode", True), \
                mock.patch.object(sys, "argv", ["action.py", "123", "10000000000"]), \
                mock.patch.dict(namespace["os"].environ, {}, clear=True), \
                mock.patch.dict(sys.modules, {"aragorn": package, "aragorn.pi_core_service_entry": service}), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(namespace["main"](), 126)
        holder.close.assert_called_once_with()
        self.assertEqual(printed.call_args.args, ("PI_SERVICE_ENTRY_REFUSED_OR_CLEANUP_HOLD",))


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(SourceWrapperTests(name) for name in SourceWrapperTests.__dict__ if name.startswith("test_"))
    # Only the two affected legacy branches, not the inherited historical suite.
    for name in ("test_static_image_exact_layout_and_binding", "test_licenses_and_exact_exclusions_retained"):
        suite.addTest(previous.PiCoreServiceImageTests(name))
    return suite


if __name__ == "__main__":
    unittest.main()
