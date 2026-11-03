"""Inert temp-file provisioning checks; root/installed custody is mocked.

Authored tiny source bytes are not a Linux OS and are never executed. These
checks establish installer behavior only, not loader closure or deployment.
"""

from __future__ import annotations

from contextlib import ExitStack
import copy
import json
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
from aragorn.oci_worker_protocol import canonical_digest


class PiOsProvisionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="aragorn-pi-provision-inert-"))
        self.root = Path(self.temporary).resolve()
        # macOS child directories inherit the parent's group, which can differ
        # from our primary group in its temporary-directory hierarchy. Normalize
        # only this exclusively owned fixture before creating any descendants.
        os.chown(self.root, -1, os.getgid(), follow_symlinks=False)
        self.os_root = self.root / "os-source"
        self.runtime = self.root / "compiled-source"
        self.parent = self.root / "installed"
        self.parent.mkdir()
        for owner, name in ((subprocess, "Popen"), (subprocess, "run"), (socket, "socket"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        self.stack.enter_context(mock.patch.object(provision, "_ROOT_UID", os.getuid()))
        self.stack.enter_context(mock.patch.object(provision, "_ROOT_GID", os.getgid()))
        self.stack.enter_context(mock.patch.object(provision.sys, "platform", "linux"))
        # Real descriptor-safe copying/modes run only in this owned temp tree;
        # privileged root ancestry and ownership are explicitly not established.
        self.stack.enter_context(mock.patch.object(provision.lineage, "_open_protected_root",
            side_effect=lambda path, uid: os.open(path, provision._DIRECTORY)))

        def installed_tree(fd):
            tree = provision._inventory(fd)
            return {"files": tree["files"]}, tuple(tree["directories"]), canonical_digest(tree)

        self.stack.enter_context(mock.patch.object(provision.confined, "_tree", side_effect=installed_tree))
        for name in provision._EMPTY_MOUNTS:
            (self.os_root / name).mkdir(parents=True, exist_ok=True)
        self.write(self.os_root / "usr/bin/env", b"inert env", True)
        self.write(self.os_root / "lib/ld-linux-aarch64.so.1", b"inert loader", True)
        self.write(self.os_root / "lib/aarch64-linux-gnu/libc.so.6", b"inert libc", True)
        for name in ("node/bin/node", "pi-core/entrypoint.js", "pi-core/worker.js", "pi-core/package.json",
                     "pi-core/node_modules/example/cli", "openclaw/aragorn-runtime-action-worker/index.js",
                     "openclaw/aragorn-runtime-action-worker/package.json"):
            self.write(self.runtime / name, ("inert " + name).encode(), name in ("node/bin/node", "pi-core/node_modules/example/cli"))
        self.os_manifest = self.inventory(self.os_root)
        runtime_manifest = self.inventory(self.runtime)
        rows = [{"path": entry["path"], "kind": "file", "bytes": entry["size"], "sha256": entry["digest"][7:]}
                for entry in runtime_manifest["files"]]
        self.compiled = {"schema": "aragorn/pi-core-linux-build/v1", "target": "linux-arm64-glibc",
                         "status": "COMPILED_NOT_DEPLOYED_OR_OS_QUALIFIED", "node_version": "24.22.2",
                         "typescript_version": "7.0.2", "runtime_executed": False, "install_scripts_executed": False,
                         "deployment_inventory": rows, "deployment_tree_sha256": canonical_digest(rows)[7:]}

    def write(self, path: Path, raw: bytes, executable=False):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o755 if executable else 0o644)

    def inventory(self, path):
        fd = os.open(path, provision._DIRECTORY)
        try:
            return provision._inventory(fd)
        finally:
            os.close(fd)

    def install(self, **changes):
        arguments = dict(os_source=self.os_root, os_manifest=self.os_manifest,
                         os_manifest_digest=canonical_digest(self.os_manifest), runtime_source=self.runtime,
                         compiled_receipt=self.compiled, compiled_receipt_digest=canonical_digest(self.compiled),
                         destination_parent=self.parent, deployment_name="d2-fixture", deadline=time.monotonic() + 60)
        arguments.update(changes)
        return provision.provision_pi_os_runtime(**arguments)

    def test_exact_closures_are_installed_and_receipt_is_canonical(self):
        receipt = self.install()
        target = self.parent / "d2-fixture"
        self.assertEqual(receipt["os_closure_digest"], canonical_digest(self.os_manifest))
        self.assertEqual(receipt["compiled_receipt_digest"], canonical_digest(self.compiled))
        self.assertEqual(receipt["runtime_inventory_digest"], "sha256:" + self.compiled["deployment_tree_sha256"])
        self.assertEqual(json.loads((target / "provision-receipt.json").read_bytes()), receipt)
        self.assertEqual(self.inventory(target / "os"), self.os_manifest)
        self.assertFalse(receipt["activation_performed"])
        self.assertFalse(receipt["runtime_executed"])
        self.assertFalse(receipt["phase3_exit_eligible"])

    def test_modes_are_protected_roots_and_immutable_descendants(self):
        self.install()
        target = self.parent / "d2-fixture"
        for root in (target, target / "os", target / "runtime"):
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((target / "os/usr").stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((target / "os/usr/bin/env").stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((target / "runtime/pi-core/entrypoint.js").stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE((target / "provision-receipt.json").stat().st_mode), 0o444)

    def test_runtime_execution_bits_are_reduced_to_node_only(self):
        receipt = self.install()
        runtime = self.parent / "d2-fixture/runtime"
        executable = [entry["path"] for entry in self.inventory(runtime)["files"] if entry["executable"]]
        self.assertEqual(executable, ["node/bin/node"])
        self.assertIn("ONLY_NODE_BIN_NODE", receipt["runtime_executable_policy"])
        self.assertTrue((self.runtime / "pi-core/node_modules/example/cli").stat().st_mode & 0o111)

    def test_existing_destination_is_never_overwritten(self):
        target = self.parent / "d2-fixture"
        target.mkdir()
        marker = target / "user-data"
        marker.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.install()
        self.assertEqual(marker.read_bytes(), b"preserve")

    def test_existing_destination_symlink_is_never_followed(self):
        (self.parent / "d2-fixture").symlink_to(self.runtime, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.install()
        self.assertFalse((self.runtime / "provision-receipt.json").exists())

    def test_wrong_os_pin_refuses_before_creation(self):
        with self.assertRaisesRegex(provision.PiOsProvisionError, "pin mismatch"):
            self.install(os_manifest_digest="sha256:" + "0" * 64)
        self.assertFalse((self.parent / "d2-fixture").exists())

    def test_wrong_compiled_pin_refuses_before_creation(self):
        with self.assertRaisesRegex(ValueError, "receipt pin"):
            self.install(compiled_receipt_digest="sha256:" + "0" * 64)
        self.assertFalse((self.parent / "d2-fixture").exists())

    def test_source_missing_os_file_is_rejected(self):
        (self.os_root / "usr/bin/env").unlink()
        with self.assertRaisesRegex(provision.PiOsProvisionError, "source differs"):
            self.install()

    def test_source_extra_os_file_is_rejected(self):
        self.write(self.os_root / "extra", b"unreviewed")
        with self.assertRaisesRegex(provision.PiOsProvisionError, "source differs"):
            self.install()

    def test_source_changed_os_bytes_are_rejected(self):
        (self.os_root / "usr/bin/env").write_bytes(b"other bytes")
        with self.assertRaisesRegex(provision.PiOsProvisionError, "source differs"):
            self.install()

    def test_source_symlink_is_rejected(self):
        (self.os_root / "alias").symlink_to("usr/bin/env")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.install()

    def test_source_hardlink_is_rejected(self):
        os.link(self.os_root / "usr/bin/env", self.os_root / "hardlink")
        with self.assertRaisesRegex(ValueError, "hardlink"):
            self.install()

    def test_source_fifo_is_rejected_without_opening(self):
        os.mkfifo(self.os_root / "fifo")
        with self.assertRaisesRegex(ValueError, "non-regular"):
            self.install()

    def test_source_ancestor_symlink_is_rejected(self):
        (self.root / "linked").symlink_to(self.os_root, target_is_directory=True)
        with self.assertRaises(OSError):
            self.install(os_source=self.root / "linked")

    def test_manifest_missing_loader_is_rejected(self):
        manifest = copy.deepcopy(self.os_manifest)
        manifest["files"] = [row for row in manifest["files"] if row["path"] != "lib/ld-linux-aarch64.so.1"]
        with self.assertRaisesRegex(provision.PiOsProvisionError, "loader"):
            self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))

    def test_manifest_env_must_be_executable(self):
        manifest = copy.deepcopy(self.os_manifest)
        next(row for row in manifest["files"] if row["path"] == "usr/bin/env")["executable"] = False
        with self.assertRaisesRegex(provision.PiOsProvisionError, "env"):
            self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))

    def test_manifest_requires_empty_fixed_projection_mountpoints(self):
        self.write(self.os_root / "var/lib/aragorn/admitted/ambient", b"not empty")
        manifest = self.inventory(self.os_root)
        with self.assertRaisesRegex(provision.PiOsProvisionError, "mountpoints"):
            self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))

    def test_manifest_missing_mountpoint_is_rejected(self):
        manifest = copy.deepcopy(self.os_manifest)
        manifest["directories"].remove("opt/aragorn/pi-runtime")
        with self.assertRaisesRegex(provision.PiOsProvisionError, "mountpoints"):
            self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))

    def test_private_tmp_requires_both_empty_tmp_mountpoints(self):
        for name in ("tmp", "var/tmp"):
            with self.subTest(missing=name):
                manifest = copy.deepcopy(self.os_manifest)
                manifest["directories"].remove(name)
                with self.assertRaisesRegex(provision.PiOsProvisionError, "mountpoints"):
                    self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))
        self.assertFalse((self.parent / "d2-fixture").exists())

    def test_manifest_rejects_parent_traversal(self):
        manifest = copy.deepcopy(self.os_manifest)
        manifest["files"][0]["path"] = "../outside"
        with self.assertRaisesRegex(provision.PiOsProvisionError, "unsafe closure path"):
            self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))

    def test_manifest_rejects_duplicate_file_entries(self):
        manifest = copy.deepcopy(self.os_manifest)
        manifest["files"].append(manifest["files"][-1])
        with self.assertRaisesRegex(provision.PiOsProvisionError, "duplicated"):
            self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))

    def test_manifest_rejects_extra_fields(self):
        manifest = copy.deepcopy(self.os_manifest)
        manifest["owner"] = "untrusted"
        with self.assertRaisesRegex(provision.PiOsProvisionError, "unsupported"):
            self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))

    def test_manifest_rejects_unbounded_size(self):
        manifest = copy.deepcopy(self.os_manifest)
        manifest["files"][0]["size"] = 1024 ** 3
        with self.assertRaisesRegex(provision.PiOsProvisionError, "file identity"):
            self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))

    def test_manifest_rejects_missing_parent_directory(self):
        manifest = copy.deepcopy(self.os_manifest)
        manifest["directories"].remove("usr")
        with self.assertRaisesRegex(provision.PiOsProvisionError, "missing directory parents"):
            self.install(os_manifest=manifest, os_manifest_digest=canonical_digest(manifest))

    def test_runtime_extra_empty_directory_is_unbound_and_rejected(self):
        (self.runtime / "unbound-empty").mkdir()
        with self.assertRaisesRegex(provision.PiOsProvisionError, "unbound empty"):
            self.install()

    def test_runtime_byte_mutation_rejects_compiled_receipt(self):
        (self.runtime / "pi-core/worker.js").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "compiled inventory"):
            self.install()

    def test_runtime_node_must_start_executable(self):
        (self.runtime / "node/bin/node").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "layout is incomplete"):
            self.install()

    def test_platform_gate_refuses_mac_host_provisioning(self):
        with mock.patch.object(provision.sys, "platform", "darwin"):
            with self.assertRaisesRegex(provision.PiOsProvisionError, "Linux root"):
                self.install()
        self.assertFalse((self.parent / "d2-fixture").exists())

    def test_expired_original_deadline_refuses_before_write(self):
        with self.assertRaisesRegex(provision.PiOsProvisionError, "deadline"):
            self.install(deadline=time.monotonic() - 1)
        self.assertFalse((self.parent / "d2-fixture").exists())

    def test_invalid_destination_name_refuses(self):
        for name in ("../escape", "/absolute", "", "A", ".", "with space"):
            with self.subTest(name=name), self.assertRaises(provision.PiOsProvisionError):
                self.install(deployment_name=name)

    def test_overlapping_source_and_destination_refuse(self):
        with self.assertRaisesRegex(provision.PiOsProvisionError, "overlap"):
            self.install(destination_parent=self.os_root, deployment_name="inside")

    def test_write_failure_retains_partial_tree_without_receipt(self):
        with mock.patch.object(provision.os, "write", return_value=0):
            with self.assertRaisesRegex(provision.PiOsProvisionError, "short write") as caught:
                self.install()
        target = self.parent / "d2-fixture"
        self.assertTrue(target.is_dir())
        self.assertFalse((target / "provision-receipt.json").exists())
        observation = caught.exception.pi_provisioning_observation
        self.assertTrue(observation["created"])
        self.assertFalse(observation["completed"])
        self.assertFalse(observation["rollback_performed"])

    def test_partial_destination_cannot_be_automatically_retried(self):
        with mock.patch.object(provision.os, "write", return_value=0):
            with self.assertRaises(provision.PiOsProvisionError):
                self.install()
        with self.assertRaises(FileExistsError):
            self.install()

    def test_receipt_creation_failure_preserves_completed_trees(self):
        original = os.open

        def opening(path, flags, *args, **kwargs):
            if path == "provision-receipt.json":
                raise OSError("inert receipt failure")
            return original(path, flags, *args, **kwargs)

        with mock.patch.object(provision.os, "open", side_effect=opening):
            with self.assertRaisesRegex(OSError, "receipt failure"):
                self.install()
        target = self.parent / "d2-fixture"
        self.assertEqual(self.inventory(target / "os"), self.os_manifest)
        self.assertTrue((target / "runtime/node/bin/node").is_file())
        self.assertFalse((target / "provision-receipt.json").exists())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
