"""Only new v2 image bindings and selected affected v1 contract checks.

Owned inert files exercise the real installer/holder without target execution.
Importing the earlier fixture does not schedule its historical test suite.
"""

import copy
import unittest

from aragorn import pi_core_service_provision as subject
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_service_provision as earlier


class PiServiceImageContractTests(unittest.TestCase):
    def setUp(self):
        self.fixture = earlier.PiServiceProvisionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.add_file(subject.LIBPYTHON)
        self.add_file(subject.SOURCE_ROOT + "/pi_core_service_entry.py")
        for role in subject.ROLES:
            self.add_file(subject.WRAPPER_ROOT + "/" + role + ".py", executable=True)
        self.fixture.manifest = self.fixture.inventory(self.fixture.source)
        files = {row["path"]: row for row in self.fixture.manifest["files"]}
        binding = self.fixture.binding
        binding["schema"] = subject.BINDING_SCHEMA_V2
        binding["shared_library_paths"] = sorted([*binding["shared_library_paths"], subject.LIBPYTHON])
        binding["source_digests"][subject.SOURCE_ROOT + "/pi_core_service_entry.py"] = files[
            subject.SOURCE_ROOT + "/pi_core_service_entry.py"]["digest"]
        binding["wrappers"] = {role: {
            "path": subject.WRAPPER_ROOT + "/" + role + ".py",
            "digest": files[subject.WRAPPER_ROOT + "/" + role + ".py"]["digest"],
            "argv": ["/" + subject.PYTHON, "-I", "-S", "-B", "/" + subject.WRAPPER_ROOT + "/" + role + ".py"],
        } for role in subject.ROLES}

    def add_file(self, name, executable=False):
        path = self.fixture.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(("inert service image: " + name).encode())
        path.chmod(0o755 if executable else 0o644)

    def test_exact_v2_binding_installs_and_holds_wrappers_without_execution(self):
        self.fixture.validation()
        receipt = self.fixture.install()
        with self.fixture.hold(receipt) as held:
            held.guard()
            self.assertEqual(held.binding["wrappers"], self.fixture.binding["wrappers"])
            self.assertEqual(held.receipt["binding_digest"], canonical_digest(self.fixture.binding))
            self.assertFalse(held.receipt["loaded_code_attested"])

    def test_missing_or_extra_wrapper_role_refuses(self):
        for role in ("action", "sensor", "provider", "shell"):
            binding = copy.deepcopy(self.fixture.binding)
            if role == "shell":
                binding["wrappers"][role] = binding["wrappers"]["action"]
            else:
                del binding["wrappers"][role]
            with self.subTest(role=role), self.assertRaises(subject.PiServiceProvisionError):
                self.fixture.validation(binding=binding)

    def test_wrapper_cannot_change_path_digest_flags_or_add_arguments(self):
        original = self.fixture.binding["wrappers"]["action"]
        variants = [
            {**original, "path": "opt/aragorn/bin/sensor.py"},
            {**original, "digest": "sha256:" + "0" * 64},
            {**original, "argv": original["argv"] + ["--config", "/tmp/config"]},
            {**original, "argv": [part for part in original["argv"] if part != "-I"]},
            {**original, "argv": [part for part in original["argv"] if part != "-S"]},
            {**original, "argv": [part for part in original["argv"] if part != "-B"]},
            {**original, "handler": "arbitrary"},
        ]
        for variant in variants:
            binding = copy.deepcopy(self.fixture.binding)
            binding["wrappers"]["action"] = variant
            with self.subTest(variant=variant), self.assertRaises(subject.PiServiceProvisionError):
                self.fixture.validation(binding=binding)

    def test_v1_cannot_authorize_the_expanded_image_layout(self):
        binding = copy.deepcopy(self.fixture.binding)
        binding["schema"] = subject.BINDING_SCHEMA
        del binding["wrappers"]
        with self.assertRaises(subject.PiServiceProvisionError):
            self.fixture.validation(binding=binding)

    def test_each_required_image_member_is_mandatory(self):
        for name in (subject.LIBPYTHON, subject.SOURCE_ROOT + "/pi_core_service_entry.py",
                     *(subject.WRAPPER_ROOT + "/" + role + ".py" for role in subject.ROLES)):
            manifest = copy.deepcopy(self.fixture.manifest)
            manifest["files"] = [row for row in manifest["files"] if row["path"] != name]
            manifest["directories"] = sorted(set().union(*(subject.provision._parents(row["path"]) for row in manifest["files"])))
            with self.subTest(name=name), self.assertRaises(subject.PiServiceProvisionError):
                self.fixture.validation(manifest=manifest)

    def test_wrapper_execute_mode_and_nonempty_bytes_are_bound(self):
        for update in ({"executable": False}, {"size": 0}):
            manifest = copy.deepcopy(self.fixture.manifest)
            next(row for row in manifest["files"] if row["path"] == subject.WRAPPER_ROOT + "/action.py").update(update)
            with self.subTest(update=update), self.assertRaises(subject.PiServiceProvisionError):
                self.fixture.validation(manifest=manifest)

    def test_additional_usr_lib_or_wrapper_files_are_not_admitted(self):
        for name in ("usr/lib/libother.so.1", subject.WRAPPER_ROOT + "/shell.py"):
            manifest = copy.deepcopy(self.fixture.manifest)
            manifest["files"].append({"path": name, "size": 1, "digest": "sha256:" + "a" * 64, "executable": False})
            manifest["files"].sort(key=lambda row: row["path"])
            with self.subTest(name=name), self.assertRaises(subject.PiServiceProvisionError):
                self.fixture.validation(manifest=manifest)

    def test_libpython_must_be_in_exact_library_inventory(self):
        binding = copy.deepcopy(self.fixture.binding)
        binding["shared_library_paths"].remove(subject.LIBPYTHON)
        with self.assertRaises(subject.PiServiceProvisionError):
            self.fixture.validation(binding=binding)

    def test_wrapper_byte_mutation_is_detected_by_held_guard(self):
        receipt = self.fixture.install()
        with self.assertRaises(subject.PiServiceProvisionError):
            with self.fixture.hold(receipt) as held:
                target = self.fixture.target() / "root" / subject.WRAPPER_ROOT / "action.py"
                target.chmod(0o755)
                target.write_bytes(b"changed wrapper")
                target.chmod(0o555)
                held.guard()


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(PiServiceImageContractTests)
    for name in (
        "test_exact_install_and_held_guard_bind_independent_pins_without_execution",
        "test_unknown_binding_fields_or_roles_refuse",
        "test_python_importroot_stdlib_or_loader_override_refuses",
    ):
        suite.addTest(earlier.PiServiceProvisionTests(name))
    return suite


if __name__ == "__main__":
    unittest.main()
