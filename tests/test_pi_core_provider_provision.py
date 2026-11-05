"""New public-input installer checks in exclusively owned temporary directories.

Linux/root ancestry is mocked. These authored CA bytes are not a trust store;
no credentials, service, TLS, network or target process are used or proven.
"""

from contextlib import ExitStack
import copy
import hashlib
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
from aragorn import pi_core_provider_provision as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


CA_BYTES = b"-----BEGIN CERTIFICATE-----\nINERT-PUBLIC-FIXTURE\n-----END CERTIFICATE-----\n"


class PiProviderProvisionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="pi-provider-inputs-inert-"))
        self.root = Path(directory).resolve()
        # Normalize only the owned root before children inherit macOS's group.
        os.chown(self.root, -1, os.getgid(), follow_symlinks=False)
        self.source = self.root / "public-source"
        self.parent = self.root / "destination"
        self.parent.mkdir()
        (self.source / "etc/aragorn").mkdir(parents=True)
        self.profile = {"schema": "aragorn/pi-core-openai-profile/v1", "service_uid": 8001,
                        "service_gid": 8002, "address": "8.8.8.8",
                        "ca_digest": "sha256:" + hashlib.sha256(CA_BYTES).hexdigest()}
        (self.source / subject.PROFILE).write_bytes(canonical_json(self.profile))
        (self.source / subject.CA).write_bytes(CA_BYTES)
        self.manifest = self.inventory(self.source)
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "getaddrinfo"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        self.stack.enter_context(mock.patch.object(provision, "_ROOT_UID", os.getuid()))
        self.stack.enter_context(mock.patch.object(provision, "_ROOT_GID", os.getgid()))
        self.stack.enter_context(mock.patch.object(provision.sys, "platform", "linux"))
        self.parent_open = self.stack.enter_context(mock.patch.object(provision.lineage, "_open_protected_root",
            side_effect=lambda path, uid: os.open(path, provision._DIRECTORY)))

    def inventory(self, path):
        descriptor = os.open(path, provision._DIRECTORY)
        try:
            return provision._inventory(descriptor)
        finally:
            os.close(descriptor)

    def install(self, **changes):
        arguments = dict(source=self.source, manifest=self.manifest,
                         manifest_digest=canonical_digest(self.manifest), profile=self.profile,
                         destination_parent=self.parent, deployment_name="fixture",
                         deadline=time.monotonic() + 60)
        arguments.update(changes)
        return subject.provision_pi_provider_inputs(**arguments)

    def fresh_manifest(self):
        self.manifest = self.inventory(self.source)

    def target(self):
        return self.parent / "fixture"

    def assert_no_creation(self):
        self.assertFalse(self.target().exists())

    def test_exact_public_inputs_and_canonical_receipt_are_installed(self):
        result = self.install()
        self.assertEqual(result["schema"], subject.SCHEMA)
        self.assertEqual(result["status"], subject.STATUS)
        self.assertEqual(result["input_root"], str(self.target() / "root"))
        self.assertEqual(result["input_closure_digest"], canonical_digest(self.manifest))
        self.assertEqual(result["profile_digest"], canonical_digest(self.profile))
        self.assertEqual(result["ca_digest"], self.profile["ca_digest"])
        self.assertEqual((self.target() / subject.RECEIPT).read_bytes(), canonical_json(result))
        self.assertEqual(self.inventory(self.target() / "root"), self.manifest)
        self.assertEqual(set(self.target().iterdir()), {self.target() / "root", self.target() / subject.RECEIPT})
        self.assertTrue(all(result[name] is False for name in
                            ("credential_read", "activation_performed", "service_ready", "phase3_exit_eligible")))

    def test_installed_public_files_and_directories_have_exact_protected_modes(self):
        self.install()
        expected = {"": 0o755, "root": 0o755, "root/etc": 0o555, "root/etc/aragorn": 0o555,
                    "root/" + subject.PROFILE: 0o444, "root/" + subject.CA: 0o444, subject.RECEIPT: 0o444}
        for relative, mode in expected.items():
            with self.subTest(path=relative):
                metadata = (self.target() / relative).stat()
                self.assertEqual(stat.S_IMODE(metadata.st_mode), mode)
                self.assertEqual((metadata.st_uid, metadata.st_gid), (os.getuid(), os.getgid()))

    def test_existing_destination_preserves_unrelated_data(self):
        self.target().mkdir()
        marker = self.target() / "keep"
        marker.write_bytes(b"untouched")
        with self.assertRaises(FileExistsError):
            self.install()
        self.assertEqual(marker.read_bytes(), b"untouched")

    def test_existing_destination_symlink_is_not_followed(self):
        self.target().symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.install()
        self.assertFalse((self.source / subject.RECEIPT).exists())

    def test_wrong_manifest_pin_refuses_before_creation(self):
        with self.assertRaisesRegex(provision.PiOsProvisionError, "pin mismatch"):
            self.install(manifest_digest="sha256:" + "0" * 64)
        self.assert_no_creation()

    def test_profile_bytes_must_be_canonical_not_merely_equivalent_json(self):
        (self.source / subject.PROFILE).write_text(json.dumps(self.profile, indent=2))
        self.fresh_manifest()
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "canonical approved"):
            self.install()
        self.assert_no_creation()

    def test_profile_must_match_caller_approved_identity_and_destination(self):
        approved = {**self.profile, "service_uid": 8003}
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "canonical approved"):
            self.install(profile=approved)
        self.assert_no_creation()

    def test_ca_digest_must_match_profile_even_when_manifest_is_pinned(self):
        (self.source / subject.CA).write_bytes(b"other public CA bytes")
        self.fresh_manifest()
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "CA bytes differ"):
            self.install()
        self.assert_no_creation()

    def test_non_ascii_ca_is_not_an_accepted_tls_input(self):
        raw = b"not-ascii-\xff"
        self.profile["ca_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        (self.source / subject.CA).write_bytes(raw)
        (self.source / subject.PROFILE).write_bytes(canonical_json(self.profile))
        self.fresh_manifest()
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "ASCII"):
            self.install()
        self.assert_no_creation()

    def test_root_identity_or_loopback_profile_is_rejected(self):
        for changes in ({"service_uid": 0}, {"address": "127.0.0.1"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.install(profile={**self.profile, **changes})
        self.assert_no_creation()

    def test_extra_credential_named_leaf_is_refused_before_any_public_read(self):
        (self.source / "etc/aragorn/openai-api-key").write_bytes(b"not-a-real-key")
        with mock.patch.object(subject, "_read_public", side_effect=AssertionError("no leaf may be read")) as read:
            with self.assertRaisesRegex(subject.PiProviderProvisionError, "unexpected public"):
                self.install()
        read.assert_not_called()
        self.assert_no_creation()

    def test_extra_root_or_etc_directories_are_refused_before_reads(self):
        for relative in ("run", "etc/credentials"):
            with self.subTest(path=relative):
                path = self.source / relative
                path.mkdir()
                try:
                    with mock.patch.object(subject, "_read_public", side_effect=AssertionError("no leaf reads")) as read:
                        with self.assertRaisesRegex(subject.PiProviderProvisionError, "unexpected"):
                            self.install()
                    read.assert_not_called()
                finally:
                    path.rmdir()
        self.assert_no_creation()

    def test_manifest_cannot_authorize_an_extra_file(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["files"].insert(0, {"path": "etc/aragorn/openai-api-key", "size": 1,
                                   "digest": "sha256:" + "1" * 64, "executable": False})
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "only two"):
            self.install(manifest=manifest, manifest_digest=canonical_digest(manifest))
        self.assert_no_creation()

    def test_manifest_cannot_authorize_empty_extra_directory(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["directories"].append("run")
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "only two"):
            self.install(manifest=manifest, manifest_digest=canonical_digest(manifest))
        self.assert_no_creation()

    def test_manifest_executable_public_file_is_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["files"][0]["executable"] = True
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "non-executable"):
            self.install(manifest=manifest, manifest_digest=canonical_digest(manifest))
        self.assert_no_creation()

    def test_manifest_oversized_or_empty_public_file_is_rejected(self):
        for size in (0, 1024 * 1024 + 1):
            with self.subTest(size=size):
                manifest = copy.deepcopy(self.manifest)
                manifest["files"][0]["size"] = size
                with self.assertRaisesRegex(subject.PiProviderProvisionError, "only two"):
                    self.install(manifest=manifest, manifest_digest=canonical_digest(manifest))
        self.assert_no_creation()

    def test_source_byte_mutation_is_rejected(self):
        (self.source / subject.CA).write_bytes(b"changed")
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "reviewed closure"):
            self.install()
        self.assert_no_creation()

    def test_source_executable_bit_is_rejected(self):
        (self.source / subject.CA).chmod(0o755)
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "reviewed closure"):
            self.install()
        self.assert_no_creation()

    def test_missing_source_leaf_is_rejected(self):
        (self.source / subject.CA).unlink()
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "unexpected public"):
            self.install()
        self.assert_no_creation()

    def test_symlink_public_leaf_is_refused_without_following(self):
        path = self.source / subject.CA
        path.unlink()
        path.symlink_to(self.source / subject.PROFILE)
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "unsafe"):
            self.install()
        self.assert_no_creation()

    def test_hardlinked_public_leaf_is_refused(self):
        os.link(self.source / subject.CA, self.root / "other-ca-name")
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "unsafe"):
            self.install()
        self.assert_no_creation()

    def test_fifo_public_leaf_is_refused_before_open(self):
        path = self.source / subject.CA
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "unsafe"):
            self.install()
        self.assert_no_creation()

    def test_source_ancestor_symlink_is_refused(self):
        link = self.root / "linked-source"
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(OSError):
            self.install(source=link)
        self.assert_no_creation()

    def test_symlink_intermediate_directory_is_refused(self):
        path = self.source / "etc/aragorn"
        moved = self.root / "moved-public"
        path.rename(moved)
        path.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError):
            self.install()
        self.assert_no_creation()

    def test_non_linux_provisioning_is_refused(self):
        with mock.patch.object(provision.sys, "platform", "darwin"):
            with self.assertRaisesRegex(provision.PiOsProvisionError, "protected Linux root"):
                self.install()
        self.assert_no_creation()

    def test_expired_original_deadline_is_refused(self):
        with self.assertRaisesRegex(provision.PiOsProvisionError, "deadline"):
            self.install(deadline=time.monotonic() - 1)
        self.assert_no_creation()

    def test_invalid_destination_name_or_relative_source_is_refused(self):
        for changes in ({"deployment_name": "../outside"}, {"source": Path("relative")},
                        {"destination_parent": Path("relative")}):
            with self.subTest(changes=changes), self.assertRaises(subject.PiProviderProvisionError):
                self.install(**changes)
        self.assert_no_creation()

    def test_destination_cannot_overlap_source(self):
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "overlap"):
            self.install(destination_parent=self.source)
        self.assert_no_creation()

    def test_partial_copy_failure_retains_destination_and_forbids_automatic_retry(self):
        original = provision._copy_file
        count = 0

        def copied(source, destination, entry, deadline):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("inert copy failure")
            return original(source, destination, entry, deadline)

        with mock.patch.object(provision, "_copy_file", side_effect=copied):
            with self.assertRaises(OSError) as caught:
                self.install()
        self.assertTrue(caught.exception.pi_provider_provisioning_observation["created"])
        self.assertFalse(caught.exception.pi_provider_provisioning_observation["completed"])
        self.assertTrue((self.target() / "root" / subject.CA).exists())
        self.assertFalse((self.target() / subject.RECEIPT).exists())
        with self.assertRaises(FileExistsError):
            self.install()

    def test_source_changed_after_copy_retains_unqualified_output(self):
        original = provision._install_tree

        def copied(*args):
            original(*args)
            (self.source / subject.CA).write_bytes(b"changed after copy")

        with mock.patch.object(provision, "_install_tree", side_effect=copied):
            with self.assertRaisesRegex(subject.PiProviderProvisionError, "changed during"):
                self.install()
        self.assertTrue(self.target().exists())
        self.assertFalse((self.target() / subject.RECEIPT).exists())

    def test_installed_permission_mutation_is_not_promoted_to_protected_inputs(self):
        original = provision._install_tree

        def copied(*args):
            original(*args)
            (self.target() / "root" / subject.CA).chmod(0o644)

        with mock.patch.object(provision, "_install_tree", side_effect=copied):
            with self.assertRaisesRegex(provision.PiOsProvisionError, "exact mode"):
                self.install()
        self.assertFalse((self.target() / subject.RECEIPT).exists())

    def test_receipt_write_failure_retains_partial_receipt_without_success(self):
        original = provision._write_all

        def write(fd, raw, deadline):
            if b'"schema":"aragorn/pi-core-provider-inputs/v1"' in raw:
                raise OSError("inert receipt write failure")
            return original(fd, raw, deadline)

        with mock.patch.object(provision, "_write_all", side_effect=write):
            with self.assertRaises(OSError) as caught:
                self.install()
        self.assertFalse(caught.exception.pi_provider_provisioning_observation["completed"])
        self.assertTrue((self.target() / subject.RECEIPT).exists())

    def test_receipt_readback_mismatch_refuses_completion(self):
        original = os.read

        def read(fd, maximum):
            value = original(fd, maximum)
            if b'"schema":"aragorn/pi-core-provider-inputs/v1"' in value:
                return b"changed receipt"
            return value

        with mock.patch.object(os, "read", side_effect=read):
            with self.assertRaisesRegex(subject.PiProviderProvisionError, "readback mismatch"):
                self.install()
        self.assertTrue((self.target() / subject.RECEIPT).exists())

    def test_root_name_replacement_is_not_bound_to_returned_path(self):
        original = subject._public_tree
        changed = False

        def inspect(fd, deadline, **options):
            nonlocal changed
            result = original(fd, deadline, **options)
            if options.get("protected") and not changed:
                changed = True
                (self.target() / "root").rename(self.target() / "retained-root")
                (self.target() / "root").mkdir()
            return result

        with mock.patch.object(subject, "_public_tree", side_effect=inspect):
            with self.assertRaisesRegex(subject.PiProviderProvisionError, "custody"):
                self.install()
        self.assertTrue((self.target() / "retained-root").exists())

    def test_destination_parent_replacement_is_not_promoted_to_success(self):
        count = 0

        def opened(path, uid):
            nonlocal count
            count += 1
            if count == 2:
                path.rename(self.root / "retained-destination")
                path.mkdir()
            return os.open(path, provision._DIRECTORY)

        self.parent_open.side_effect = opened
        with self.assertRaisesRegex(subject.PiProviderProvisionError, "named custody"):
            self.install()
        self.assertTrue((self.root / "retained-destination/fixture" / subject.RECEIPT).exists())

    def test_receipt_name_replacement_is_not_promoted_to_success(self):
        original = os.fsync
        changed = False

        def synced(fd):
            nonlocal changed
            original(fd)
            path = self.target() / subject.RECEIPT
            if path.exists() and not changed:
                changed = True
                path.rename(self.target() / "retained-receipt")
                path.write_bytes(b"replacement")

        with mock.patch.object(os, "fsync", side_effect=synced):
            with self.assertRaisesRegex(subject.PiProviderProvisionError, "custody"):
                self.install()
        self.assertTrue((self.target() / "retained-receipt").exists())

    def test_final_descriptor_cleanup_uncertainty_cannot_return_success(self):
        original = provision._close_all

        def closed(descriptors):
            original(descriptors)
            if len(descriptors) == 6:
                raise provision.PiOsProvisionError("inert final close uncertainty")

        with mock.patch.object(provision, "_close_all", side_effect=closed):
            with self.assertRaisesRegex(provision.PiOsProvisionError, "close uncertainty") as caught:
                self.install()
        self.assertFalse(caught.exception.pi_provider_provisioning_observation["completed"])
        self.assertTrue((self.target() / subject.RECEIPT).exists())
