"""New service-byte provisioning/holding checks; no target code executes.

Authored inert bytes stand in for operator-reviewed Python, native and source
files. Linux/root ancestry is mocked; byte custody is not dynamic-load proof.
"""

from contextlib import ExitStack
import copy
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from aragorn import pi_core_os_provision as provision
from aragorn import pi_core_service_provision as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


class PiServiceProvisionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        folder = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="pi-service-bytes-inert-"))
        self.fixture = Path(folder).resolve()
        os.chown(self.fixture, -1, os.getgid(), follow_symlinks=False)
        self.source = self.fixture / "reviewed-source"
        self.parent = self.fixture / "installed"
        self.source.mkdir()
        self.parent.mkdir()
        native = [subject.STDLIB + "/lib-dynload/" + name + ".cpython-312-aarch64-linux-gnu.so"
                  for name in ("_ssl", "_socket", "_ctypes")]
        libraries = ["lib/aarch64-linux-gnu/" + name for name in ("libssl.so.3", "libcrypto.so.3", "libc.so.6")]
        sources = [subject.SOURCE_ROOT + "/__init__.py", *(row["path"] for row in subject.ROLES.values())]
        for name in [subject.PYTHON, subject.LOADER, *native, *libraries, *sources,
                     *(subject.STDLIB + "/" + name for name in subject._ESSENTIAL_STDLIB)]:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("inert reviewed fixture: " + name).encode())
            path.chmod(0o755 if name in (subject.PYTHON, subject.LOADER) else 0o644)
        self.manifest = self.inventory(self.source)
        files = {row["path"]: row for row in self.manifest["files"]}
        self.binding = {"schema": subject.BINDING_SCHEMA, "target": "linux-arm64-glibc",
            "python": {"path": subject.PYTHON, "digest": files[subject.PYTHON]["digest"]},
            "import_root": subject.IMPORT_ROOT, "stdlib_directory": subject.STDLIB,
            "loader_path": subject.LOADER, "native_extension_paths": sorted(native),
            "shared_library_paths": sorted(libraries),
            "source_digests": {name: files[name]["digest"] for name in sources}, "roles": copy.deepcopy(subject.ROLES)}
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "getaddrinfo"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        self.stack.enter_context(mock.patch.object(provision, "_ROOT_UID", os.getuid()))
        self.stack.enter_context(mock.patch.object(provision, "_ROOT_GID", os.getgid()))
        self.stack.enter_context(mock.patch.object(provision.sys, "platform", "linux"))
        self.parent_open = self.stack.enter_context(mock.patch.object(provision.lineage, "_open_protected_root",
            side_effect=lambda path, uid: os.open(path, provision._DIRECTORY)))
        # Exact outside-fixture ancestors are exempted only for this rootless
        # temporary-tree fixture. All created installed members retain checks.
        outside = {(path.stat().st_dev, path.stat().st_ino) for path in self.fixture.parents}
        original = subject._ancestor

        def ancestor(fd):
            metadata = os.fstat(fd)
            if (metadata.st_dev, metadata.st_ino) not in outside:
                original(fd)

        self.stack.enter_context(mock.patch.object(subject, "_ancestor", side_effect=ancestor))

    def inventory(self, path):
        descriptor = os.open(path, provision._DIRECTORY)
        try:
            return provision._inventory(descriptor)
        finally:
            os.close(descriptor)

    def target(self):
        return self.parent / "fixture"

    def validation(self, *, manifest=None, binding=None, **changes):
        manifest = self.manifest if manifest is None else manifest
        binding = self.binding if binding is None else binding
        options = dict(manifest=manifest, manifest_digest=canonical_digest(manifest),
                       runtime_binding=binding, runtime_binding_digest=canonical_digest(binding))
        options.update(changes)
        return subject.validate_service_runtime_inputs(**options)

    def install(self, **changes):
        options = dict(source=self.source, manifest=self.manifest, manifest_digest=canonical_digest(self.manifest),
            runtime_binding=self.binding, runtime_binding_digest=canonical_digest(self.binding),
            destination_parent=self.parent, deployment_name="fixture", deadline=time.monotonic() + 60)
        options.update(changes)
        return subject.provision_pi_service_runtime(**options)

    def hold(self, receipt, **changes):
        options = dict(receipt_digest=canonical_digest(receipt), manifest=self.manifest,
            manifest_digest=canonical_digest(self.manifest), runtime_binding=self.binding,
            runtime_binding_digest=canonical_digest(self.binding), deadline=time.monotonic() + 60)
        options.update(changes)
        return subject.hold_pi_service_runtime(self.target(), **options)

    def test_exact_install_and_held_guard_bind_independent_pins_without_execution(self):
        receipt = self.install()
        self.assertEqual(receipt["status"], subject.STATUS)
        self.assertEqual(receipt["runtime_closure_digest"], canonical_digest(self.manifest))
        self.assertEqual(receipt["binding_digest"], canonical_digest(self.binding))
        self.assertEqual((self.target() / subject.RECEIPT).read_bytes(), canonical_json(receipt))
        with self.hold(receipt) as held:
            self.assertIs(type(held), subject.PiServiceRuntime)
            held.guard()
            self.assertEqual(held.root, self.target() / "root")
            self.assertEqual(os.fstat(held.root_fd).st_ino, held.root.stat().st_ino)
            self.assertEqual(held.observation["python_digest"], self.binding["python"]["digest"])
            self.assertEqual(held.observation["authority"], subject.AUTHORITY)
            self.assertEqual(held.receipt, receipt)
        self.assertTrue(all(receipt[field] is False for field in
            ("credential_read", "activation_performed", "service_ready", "loaded_code_attested", "phase3_exit_eligible")))

    def test_installed_runtime_immutable_modes_and_root_modes_are_exact(self):
        self.install()
        self.assertEqual(stat.S_IMODE(self.target().stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.target() / "root").stat().st_mode), 0o755)
        for row in self.manifest["files"]:
            self.assertEqual(stat.S_IMODE((self.target() / "root" / row["path"]).stat().st_mode),
                             0o555 if row["executable"] else 0o444)
        for name in self.manifest["directories"]:
            self.assertEqual(stat.S_IMODE((self.target() / "root" / name).stat().st_mode), 0o555)

    def test_held_metadata_is_detached(self):
        receipt = self.install()
        with self.hold(receipt) as held:
            binding = held.binding
            binding["python"]["digest"] = "sha256:" + "0" * 64
            observation = held.observation
            observation["service_ready"] = True
            public_receipt = held.receipt
            public_receipt["runtime_root"] = "/tmp/wrong"
            self.assertEqual(held.binding, self.binding)
            self.assertFalse(held.observation["service_ready"])
            self.assertEqual(held.receipt, receipt)

    def test_context_exit_withdraws_borrowed_descriptor_and_authority(self):
        receipt = self.install()
        with self.hold(receipt) as held:
            descriptor = held.root_fd
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "no longer active"):
            held.guard()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "no longer active"):
            _ = held.binding

    def test_plain_receipt_cannot_mint_a_held_runtime(self):
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "verified installed custody"):
            subject.PiServiceRuntime(None, None, None, None, None, None, None, None, None)

    def test_unminted_exact_object_and_subclass_guard_refuse(self):
        class Counterfeit(subject.PiServiceRuntime):
            pass

        for kind in (subject.PiServiceRuntime, Counterfeit):
            with self.subTest(kind=kind):
                value = object.__new__(kind)
                with self.assertRaisesRegex(subject.PiServiceProvisionError, "not minted"):
                    value.guard()

    def test_replaced_seal_cannot_preserve_active_authority(self):
        receipt = self.install()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "not minted"):
            with self.hold(receipt) as held:
                held._seal = object()
                held.guard()

    def test_unknown_binding_fields_or_roles_refuse(self):
        for mutation in (lambda value: value.update(extra=True),
                         lambda value: value["roles"].update(shell={"path": "bin/sh"}),
                         lambda value: value["roles"]["action"].update(handler="legacy_bypass")):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(self.binding)
                mutation(value)
                with self.assertRaises(subject.PiServiceProvisionError):
                    self.validation(binding=value)

    def test_python_importroot_stdlib_or_loader_override_refuses(self):
        for field, value in (("import_root", "host/site-packages"), ("stdlib_directory", "usr/lib/python3.13"),
                             ("loader_path", "host/ld.so"), ("python", {"path": "usr/bin/python3.12", "digest": "sha256:" + "0" * 64})):
            with self.subTest(field=field), self.assertRaises(subject.PiServiceProvisionError):
                self.validation(binding={**self.binding, field: value})

    def test_independent_binding_or_manifest_pin_mismatch_refuses(self):
        for changes in ({"runtime_binding_digest": "sha256:" + "0" * 64}, {"manifest_digest": "sha256:" + "0" * 64}):
            with self.subTest(changes=changes), self.assertRaises(provision.PiOsProvisionError):
                self.validation(**changes)

    def test_node_only_tree_cannot_be_a_service_runtime(self):
        manifest = {"schema": "aragorn/pi-core-protected-tree/v1", "directories": ["usr", "usr/bin"],
                    "files": [{"path": "usr/bin/node", "size": 1, "digest": "sha256:" + "1" * 64, "executable": True}]}
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "Python or loader"):
            self.validation(manifest=manifest)

    def test_missing_essential_stdlib_file_refuses_even_when_re_pinned(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["files"] = [row for row in manifest["files"] if row["path"] != subject.STDLIB + "/ssl.py"]
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "essential Python stdlib"):
            self.validation(manifest=manifest)

    def test_missing_ssl_native_extension_identity_refuses(self):
        binding = copy.deepcopy(self.binding)
        binding["native_extension_paths"] = [name for name in binding["native_extension_paths"] if "/_ssl." not in name]
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "native extension closure"):
            self.validation(binding=binding)

    def test_missing_openssl_library_identity_refuses(self):
        binding = copy.deepcopy(self.binding)
        binding["shared_library_paths"] = [name for name in binding["shared_library_paths"] if "libssl" not in name]
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "OpenSSL/libc"):
            self.validation(binding=binding)

    def test_source_digest_map_must_cover_every_supplied_source_file(self):
        binding = copy.deepcopy(self.binding)
        binding["source_digests"].pop(subject.SOURCE_ROOT + "/__init__.py")
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "source closure"):
            self.validation(binding=binding)

    def test_source_native_code_or_bytecode_cannot_hide_in_python_source_tree(self):
        for suffix in ("native.so", "unexpected.pyc"):
            with self.subTest(suffix=suffix):
                manifest = copy.deepcopy(self.manifest)
                manifest["files"].append({"path": subject.SOURCE_ROOT + "/" + suffix, "size": 1,
                                          "digest": "sha256:" + "1" * 64, "executable": False})
                manifest["files"].sort(key=lambda row: row["path"])
                with self.assertRaises(subject.PiServiceProvisionError):
                    self.validation(manifest=manifest)

    def test_credential_or_unbound_empty_paths_are_not_runtime_closure(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["directories"].append("run")
        manifest["directories"].sort()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "unbound empty"):
            self.validation(manifest=manifest)
        manifest["files"].append({"path": "run/openai-api-key", "size": 1,
                                  "digest": "sha256:" + "1" * 64, "executable": False})
        manifest["files"].sort(key=lambda row: row["path"])
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "outside the fixed"):
            self.validation(manifest=manifest)

    def test_missing_source_or_extra_file_refuses_before_creation(self):
        extra = self.source / "extra"
        extra.write_bytes(b"not reviewed")
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "unexpected entries"):
            self.install()
        self.assertFalse(self.target().exists())
        extra.unlink()
        (self.source / subject.PYTHON).unlink()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "missing declared"):
            self.install()
        self.assertFalse(self.target().exists())

    def test_source_bytes_or_executable_mode_mutation_refuse(self):
        path = self.source / subject.PYTHON
        before = path.read_bytes()
        path.write_bytes(b"x" * len(before))
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "bytes or identity"):
            self.install()
        path.write_bytes(before)
        path.chmod(0o644)
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "executable mode"):
            self.install()

    def test_source_symlink_and_hardlink_are_refused(self):
        path = self.source / subject.PYTHON
        backup = self.fixture / "saved-python"
        path.rename(backup)
        path.symlink_to(backup)
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "type, links"):
            self.install()
        path.unlink()
        os.link(backup, path)
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "type, links"):
            self.install()

    def test_fifo_refuses_before_open_or_blocking_read(self):
        path = self.source / subject.PYTHON
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "type, links"):
            self.install()

    def test_source_ancestor_symlink_refuses(self):
        linked = self.fixture / "linked"
        linked.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(OSError):
            self.install(source=linked)

    def test_existing_destination_is_not_repaired_or_overwritten(self):
        self.target().mkdir()
        marker = self.target() / "retain"
        marker.write_bytes(b"unchanged")
        with self.assertRaises(FileExistsError):
            self.install()
        self.assertEqual(marker.read_bytes(), b"unchanged")

    def test_source_destination_overlap_or_unsafe_name_refuse(self):
        for changes in ({"destination_parent": self.source}, {"deployment_name": "../outside"}, {"source": Path("relative")}):
            with self.subTest(changes=changes), self.assertRaises(subject.PiServiceProvisionError):
                self.install(**changes)

    def test_non_linux_or_expired_deadline_refuses(self):
        with mock.patch.object(provision.sys, "platform", "darwin"):
            with self.assertRaisesRegex(provision.PiOsProvisionError, "protected Linux root"):
                self.install()
        with self.assertRaisesRegex(provision.PiOsProvisionError, "deadline"):
            self.install(deadline=time.monotonic() - 1)

    def test_partial_copy_failure_retains_evidence_and_blocks_retry(self):
        original = provision._copy_file
        count = 0

        def copy_file(*args):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("inert copy failure")
            return original(*args)

        with mock.patch.object(provision, "_copy_file", side_effect=copy_file):
            with self.assertRaises(OSError) as caught:
                self.install()
        self.assertTrue(caught.exception.pi_service_provisioning_observation["created"])
        self.assertFalse(caught.exception.pi_service_provisioning_observation["completed"])
        self.assertTrue((self.target() / "root").exists())
        with self.assertRaises(FileExistsError):
            self.install()

    def test_source_changed_after_copy_refuses_receipt(self):
        original = provision._install_tree

        def install(*args):
            original(*args)
            path = self.source / subject.PYTHON
            path.write_bytes(b"changed")

        with mock.patch.object(provision, "_install_tree", side_effect=install):
            with self.assertRaises(subject.PiServiceProvisionError):
                self.install()
        self.assertFalse((self.target() / subject.RECEIPT).exists())

    def test_installed_mode_mutation_is_rejected_before_receipt(self):
        original = provision._install_tree

        def install(*args):
            original(*args)
            (self.target() / "root" / subject.PYTHON).chmod(0o777)

        with mock.patch.object(provision, "_install_tree", side_effect=install):
            with self.assertRaisesRegex(provision.PiOsProvisionError, "exact mode"):
                self.install()

    def test_receipt_write_failure_retains_partial_bundle(self):
        original = provision._write_all

        def write(fd, raw, deadline):
            if b'"schema":"aragorn/pi-core-service-runtime/v1"' in raw:
                raise OSError("inert receipt failure")
            return original(fd, raw, deadline)

        with mock.patch.object(provision, "_write_all", side_effect=write):
            with self.assertRaises(OSError) as caught:
                self.install()
        self.assertFalse(caught.exception.pi_service_provisioning_observation["completed"])
        self.assertTrue((self.target() / subject.RECEIPT).exists())

    def test_installer_parent_name_replacement_refuses_success(self):
        count = 0

        def opened(path, uid):
            nonlocal count
            count += 1
            if count == 2:
                path.rename(self.fixture / "retained-parent")
                path.mkdir()
            return os.open(path, provision._DIRECTORY)

        self.parent_open.side_effect = opened
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "parent changed"):
            self.install()
        self.assertTrue((self.fixture / "retained-parent/fixture" / subject.RECEIPT).exists())

    def test_wrong_receipt_pin_does_not_create_held_authority(self):
        receipt = self.install()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "independent pins"):
            with self.hold(receipt, receipt_digest="sha256:" + "0" * 64):
                self.fail("incorrect pin entered a held runtime")

    def test_matching_receipt_without_actual_root_never_authorizes(self):
        receipt = self.install()
        (self.target() / "root").rename(self.target() / "retained-root")
        (self.target() / "root").mkdir()
        with self.assertRaises(subject.PiServiceProvisionError):
            with self.hold(receipt):
                self.fail("receipt alone authorized")

    def test_tampered_installed_bytes_refuse_held_entry(self):
        receipt = self.install()
        path = self.target() / "root" / subject.ROLES["action"]["path"]
        path.chmod(0o644)
        path.write_bytes(b"x" * path.stat().st_size)
        path.chmod(0o444)
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "bytes or identity"):
            with self.hold(receipt):
                self.fail("tampered bytes entered a held runtime")

    def test_held_guard_rehashes_nested_file_bytes_not_only_receipt_or_root_metadata(self):
        receipt = self.install()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "bytes or identity"):
            with self.hold(receipt) as held:
                path = held.root / subject.ROLES["sensor"]["path"]
                path.chmod(0o644)
                path.write_bytes(b"x" * path.stat().st_size)
                path.chmod(0o444)
                held.guard()

    def test_held_guard_rejects_unexpected_nested_file(self):
        receipt = self.install()
        with self.assertRaises(subject.PiServiceProvisionError):
            with self.hold(receipt) as held:
                directory = held.root / subject.SOURCE_ROOT
                directory.chmod(0o755)
                (directory / "extra.py").write_bytes(b"not reviewed")
                directory.chmod(0o555)
                held.guard()

    def test_held_guard_rejects_receipt_replacement(self):
        receipt = self.install()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "custody"):
            with self.hold(receipt) as held:
                path = self.target() / subject.RECEIPT
                path.rename(self.target() / "retained-receipt")
                path.write_bytes(canonical_json(receipt))
                path.chmod(0o444)
                held.guard()

    def test_held_guard_rejects_parent_rename_without_following_new_target(self):
        receipt = self.install()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "custody"):
            with self.hold(receipt) as held:
                self.target().rename(self.parent / "retained-deployment")
                self.target().mkdir()
                held.guard()

    def test_unrelated_ancestor_sibling_churn_does_not_change_held_bundle_custody(self):
        receipt = self.install()
        with self.hold(receipt) as held:
            sibling = self.parent / "unrelated"
            sibling.mkdir()
            (sibling / "keep").write_bytes(b"unrelated user data")
            held.guard()
            self.assertEqual((sibling / "keep").read_bytes(), b"unrelated user data")

    def test_held_guard_rejects_root_name_replacement(self):
        receipt = self.install()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "custody"):
            with self.hold(receipt) as held:
                (self.target() / "root").rename(self.target() / "retained-root")
                (self.target() / "root").mkdir()
                held.guard()

    def test_successful_context_exit_revalidates_actual_bytes(self):
        receipt = self.install()
        with self.assertRaisesRegex(subject.PiServiceProvisionError, "bytes or identity"):
            with self.hold(receipt) as held:
                path = held.root / subject.ROLES["provider"]["path"]
                path.chmod(0o644)
                path.write_bytes(b"x" * path.stat().st_size)
                path.chmod(0o444)

    def test_guard_observes_original_deadline_without_renewal(self):
        receipt = self.install()
        deadline = time.monotonic() + 30
        with self.assertRaisesRegex(provision.PiOsProvisionError, "deadline"):
            with self.hold(receipt, deadline=deadline) as held:
                with mock.patch.object(provision.time, "monotonic", return_value=deadline):
                    held.guard()

    def test_guard_tighter_deadline_reaches_tree_and_chain_without_mutating_lease(self):
        receipt = self.install()
        original_tree, original_chain = subject._tree, subject._chain_guard
        with self.hold(receipt) as held:
            original_deadline = held.deadline
            narrowed = time.monotonic() + 10
            with mock.patch.object(subject, "_tree", wraps=original_tree) as tree, \
                    mock.patch.object(subject, "_chain_guard", wraps=original_chain) as chain:
                held.guard(deadline=narrowed)
                self.assertEqual(tree.call_args.args[2], narrowed)
                self.assertTrue(all(call.args[3] == narrowed for call in chain.call_args_list))
            self.assertEqual(held.deadline, original_deadline)
            held.guard()

    def test_guard_rejects_extended_or_expired_per_call_budget_before_tree_read(self):
        receipt = self.install()
        with self.hold(receipt) as held:
            with mock.patch.object(subject, "_tree", side_effect=AssertionError("tree must not be read")) as tree:
                with self.assertRaisesRegex(subject.PiServiceProvisionError, "cannot extend"):
                    held.guard(deadline=held.deadline + 1)
                with self.assertRaisesRegex(provision.PiOsProvisionError, "deadline"):
                    held.guard(deadline=time.monotonic() - 1)
                tree.assert_not_called()

    def test_tighter_guard_budget_expires_inside_file_hashing(self):
        receipt = self.install()
        real_read, real_time = os.read, time.monotonic
        with self.hold(receipt) as held:
            narrowed = real_time() + 10
            expired = False

            def read(fd, maximum):
                nonlocal expired
                raw = real_read(fd, maximum)
                if raw.startswith(b"inert reviewed fixture:"):
                    expired = True
                return raw

            with mock.patch.object(os, "read", side_effect=read), mock.patch.object(provision.time, "monotonic",
                    side_effect=lambda: narrowed if expired else real_time()):
                with self.assertRaisesRegex(provision.PiOsProvisionError, "deadline"):
                    held.guard(deadline=narrowed)
            held.guard()

    def test_per_file_hashing_checks_deadline_inside_read_loop(self):
        original = os.read
        deadline = time.monotonic() + 60
        expired = False
        real_time = time.monotonic

        def read(fd, maximum):
            nonlocal expired
            raw = original(fd, maximum)
            expired = True
            return raw

        with mock.patch.object(os, "read", side_effect=read), mock.patch.object(provision.time, "monotonic",
                side_effect=lambda: deadline if expired else real_time()):
            with self.assertRaisesRegex(provision.PiOsProvisionError, "deadline"):
                self.install(deadline=deadline)
        self.assertFalse(self.target().exists())

    def test_cleanup_uncertainty_withdraws_held_authority_without_retry(self):
        receipt = self.install()
        original = provision._close_all
        final_count = None

        def close(fds):
            original(fds)
            if final_count is not None and len(fds) == final_count:
                raise provision.PiOsProvisionError("inert final close uncertainty")

        with mock.patch.object(provision, "_close_all", side_effect=close):
            with self.assertRaisesRegex(provision.PiOsProvisionError, "close uncertainty"):
                with self.hold(receipt) as held:
                    final_count = len(held._chain) + 2
        self.assertFalse(held._active)

    def test_body_failure_closes_held_descriptors_without_cleanup_retry(self):
        receipt = self.install()
        with self.assertRaisesRegex(RuntimeError, "inert caller failure"):
            with self.hold(receipt) as held:
                descriptor = held.root_fd
                raise RuntimeError("inert caller failure")
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertFalse(held._active)
