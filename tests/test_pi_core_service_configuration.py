"""Focused protected configuration/public-input custody, owned inert trees only.

Linux/root ancestry is simulated. No target wrapper, service, socket, provider,
credential, runtime image or capability-state initialization executes.
"""

from contextlib import ExitStack
import copy
import hashlib
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from aragorn import pi_core_service_configuration as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests.test_runtime_capability_grant import _grant


def configurations():
    ids = {role: {"uid": 1201 + index, "gid": 1301 + index}
           for index, role in enumerate(("action", "sensor", "provider", "worker"))}
    profile = {"schema": subject.entry.process.PROFILE_SCHEMA, "authority": subject.entry.process.PROFILE_AUTHORITY,
        "runtime_digest": "sha256:" + "4" * 64, "executable_digest": "sha256:" + "b" * 64,
        "cgroup": "/system.slice/aragorn-pi-worker.service", "skill_path": "/var/lib/aragorn/admitted/.aragorn-versions/example/fixture-v1/SKILL.md"}
    grant = _grant(runtime_profile_digest=canonical_digest(profile))
    values = {role: {"schema": subject.entry.SCHEMA, "role": role, "identities": copy.deepcopy(ids)} for role in subject.ROLES}
    values["action"].update(capability_grant=copy.deepcopy(grant), runtime_binding={
        "schema": "aragorn/runtime-action-runtime-binding/v2", "runtime_digest": grant["runtime_digest"],
        "runtime_profile_digest": grant["runtime_profile_digest"]})
    values["sensor"].update(capability_grant=copy.deepcopy(grant), observation_binding={
        "schema": "aragorn/runtime-observation-binding/v2", "sensor_digest": grant["sensor_digest"], "runtime_profile": profile})
    return values


class PiServiceConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        folder = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="pi-service-config-inert-"))
        self.fixture = Path(folder).resolve()
        os.chown(self.fixture, -1, os.getgid(), follow_symlinks=False)
        self.source = self.fixture / "source"
        self.parent = self.fixture / "installed"
        self.source.mkdir()
        self.parent.mkdir()
        self.configs = configurations()
        for role, name in subject.PATHS.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(canonical_json(self.configs[role]))
            path.chmod(0o644)
        self.manifest = self.inventory(self.source)
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "getaddrinfo"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        self.stack.enter_context(mock.patch.object(subject.provision, "_ROOT_UID", os.getuid()))
        self.stack.enter_context(mock.patch.object(subject.provision, "_ROOT_GID", os.getgid()))
        self.stack.enter_context(mock.patch.object(subject.provision.sys, "platform", "linux"))
        self.stack.enter_context(mock.patch.object(subject.provision.lineage, "_open_protected_root",
            side_effect=lambda path, uid: os.open(path, subject.provision._DIRECTORY)))
        outside = {(path.stat().st_dev, path.stat().st_ino) for path in self.fixture.parents}
        original = subject.custody._ancestor
        def ancestor(fd):
            metadata = os.fstat(fd)
            if (metadata.st_dev, metadata.st_ino) not in outside:
                original(fd)
        self.stack.enter_context(mock.patch.object(subject.custody, "_ancestor", side_effect=ancestor))

    def inventory(self, root):
        descriptor = os.open(root, subject.provision._DIRECTORY)
        try:
            return subject.provision._inventory(descriptor)
        finally:
            os.close(descriptor)

    def target(self):
        return self.parent / "configuration"

    def install(self, **changes):
        options = dict(source=self.source, manifest=self.manifest, manifest_digest=canonical_digest(self.manifest),
            configurations=self.configs, configurations_digest=canonical_digest(self.configs), destination_parent=self.parent,
            deployment_name="configuration", deadline=time.monotonic() + 60)
        options.update(changes)
        return subject.provision_pi_service_configuration(**options)

    def hold(self, receipt, **changes):
        options = dict(receipt_digest=canonical_digest(receipt), manifest=self.manifest,
            manifest_digest=canonical_digest(self.manifest), configurations=self.configs,
            configurations_digest=canonical_digest(self.configs), deadline=time.monotonic() + 60)
        options.update(changes)
        return subject.hold_pi_service_configuration(self.target(), **options)

    def provider_install(self):
        source = self.fixture / "provider-source"
        directory = source / "etc/aragorn"
        directory.mkdir(parents=True)
        ca = b"INERT PUBLIC CA FIXTURE NOT TLS TRUST\n"
        self.profile = {"schema": "aragorn/pi-core-openai-profile/v1", "service_uid": 1203,
            "service_gid": 1303, "address": "1.1.1.1", "ca_digest": "sha256:" + hashlib.sha256(ca).hexdigest()}
        (source / subject.public_inputs.PROFILE).write_bytes(canonical_json(self.profile))
        (source / subject.public_inputs.CA).write_bytes(ca)
        self.provider_manifest = self.inventory(source)
        return subject.public_inputs.provision_pi_provider_inputs(source=source, manifest=self.provider_manifest,
            manifest_digest=canonical_digest(self.provider_manifest), profile=self.profile, destination_parent=self.parent,
            deployment_name="provider", deadline=time.monotonic() + 60)

    def provider_hold(self, receipt, **changes):
        options = dict(receipt_digest=canonical_digest(receipt), manifest=self.provider_manifest,
            manifest_digest=canonical_digest(self.provider_manifest), deadline=time.monotonic() + 60)
        options.update(changes)
        return subject.hold_pi_provider_inputs(self.parent / "provider", **options)

    def test_exact_three_configuration_install_and_held_custody(self):
        receipt = self.install()
        self.assertEqual(receipt["status"], subject.STATUS)
        self.assertEqual(receipt["configuration_closure_digest"], canonical_digest(self.manifest))
        self.assertEqual(receipt["configurations_digest"], canonical_digest(self.configs))
        self.assertEqual((self.target() / subject.RECEIPT).read_bytes(), canonical_json(receipt))
        with self.hold(receipt) as held:
            held.guard()
            self.assertIs(type(held), subject.PiServiceConfiguration)
            self.assertEqual(held.root, self.target() / "root")
            self.assertEqual(os.fstat(held.root_fd).st_ino, held.root.stat().st_ino)
            self.assertEqual(held.configurations, self.configs)
            self.assertEqual(held.identities, self.configs["action"]["identities"])
            self.assertEqual(held.observation["authority"], subject.AUTHORITY)
        for field in ("credential_read", "activation_performed", "current_grant_authority", "service_ready", "phase3_exit_eligible"):
            self.assertFalse(receipt[field])

    def test_config_modes_and_nonexecutability_are_exact(self):
        self.install()
        self.assertEqual(stat.S_IMODE(self.target().stat().st_mode), 0o755)
        root = self.target() / "root"
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
        for name in subject.DIRECTORIES:
            self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o555)
        for name in subject.PATHS.values():
            self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o444)

    def test_validation_and_held_metadata_are_detached(self):
        checked = subject.validate_service_configurations(self.configs)
        checked["action"]["identities"]["worker"]["uid"] = 999
        self.assertNotEqual(checked, self.configs)
        receipt = self.install()
        with self.hold(receipt) as held:
            held.configurations["action"]["role"] = "other"
            held.identities["action"]["uid"] = 999
            held.observation["service_ready"] = True
            self.assertEqual(held.configurations, self.configs)
            self.assertFalse(held.observation["service_ready"])

    def test_missing_or_unknown_role_refuses(self):
        for value in ({key: val for key, val in self.configs.items() if key != "sensor"}, {**self.configs, "shell": {}}):
            with self.subTest(value=value), self.assertRaises(subject.PiServiceConfigurationError):
                subject.validate_service_configurations(value)

    def test_unknown_endpoints_credentials_or_path_fields_refuse(self):
        for field in ("socket_path", "credential", "module", "runtime_root"):
            value = copy.deepcopy(self.configs)
            value["provider"][field] = "/unapproved"
            with self.subTest(field=field), self.assertRaises(subject.entry.PiServiceEntryError):
                subject.validate_service_configurations(value)

    def test_individually_valid_identity_maps_must_match(self):
        value = copy.deepcopy(self.configs)
        value["provider"]["identities"]["worker"]["uid"] += 100
        with self.assertRaisesRegex(subject.PiServiceConfigurationError, "identities"):
            subject.validate_service_configurations(value)

    def test_individually_valid_grants_must_be_identical(self):
        value = copy.deepcopy(self.configs)
        value["sensor"]["capability_grant"]["grant_id"] = "9" * 64
        with self.assertRaisesRegex(subject.PiServiceConfigurationError, "grant"):
            subject.validate_service_configurations(value)

    def test_sensor_runtime_profile_join_stays_enforced(self):
        value = copy.deepcopy(self.configs)
        value["sensor"]["observation_binding"]["runtime_profile"]["runtime_digest"] = "sha256:" + "f" * 64
        with self.assertRaises(subject.entry.PiServiceEntryError):
            subject.validate_service_configurations(value)

    def test_independent_configuration_or_manifest_pins_refuse(self):
        for changes in ({"configurations_digest": "sha256:" + "0" * 64}, {"manifest_digest": "sha256:" + "0" * 64}):
            with self.subTest(changes=changes), self.assertRaises(subject.provision.PiOsProvisionError):
                self.install(**changes)
        self.assertFalse(self.target().exists())

    def test_noncanonical_source_bytes_refuse_before_destination(self):
        (self.source / subject.PATHS["action"]).write_bytes(canonical_json(self.configs["action"]) + b"\n")
        manifest = self.inventory(self.source)
        with self.assertRaisesRegex(subject.PiServiceConfigurationError, "canonical"):
            self.install(manifest=manifest, manifest_digest=canonical_digest(manifest))
        self.assertFalse(self.target().exists())

    def test_extra_secret_named_leaf_is_refused_without_reading(self):
        secret = self.source / "etc/aragorn/openai-api-key"
        secret.write_bytes(b"inert forbidden fixture")
        original = os.open
        def guarded(path, *args, **kwargs):
            if str(path).endswith("openai-api-key"):
                raise AssertionError("unexpected secret read")
            return original(path, *args, **kwargs)
        with mock.patch.object(os, "open", side_effect=guarded), self.assertRaises(subject.provision.PiOsProvisionError):
            self.install()
        self.assertFalse(self.target().exists())

    def test_extra_manifest_entries_and_empty_directories_refuse(self):
        for mutate in (lambda m: m["directories"].append("extra"),
                       lambda m: m["files"].append({"path": "z", "size": 1, "digest": "sha256:" + "0" * 64, "executable": False})):
            manifest = copy.deepcopy(self.manifest)
            mutate(manifest)
            manifest["directories"].sort()
            with self.subTest(mutate=mutate), self.assertRaises(subject.provision.PiOsProvisionError):
                self.install(manifest=manifest, manifest_digest=canonical_digest(manifest))

    def test_source_symlink_and_hardlink_refuse(self):
        path = self.source / subject.PATHS["action"]
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(self.source / subject.PATHS["sensor"])
        with self.assertRaises((OSError, subject.provision.PiOsProvisionError)):
            self.install()
        path.unlink()
        path.write_bytes(original)
        os.link(path, self.fixture / "alias")
        with self.assertRaises(subject.provision.PiOsProvisionError):
            self.install()

    def test_existing_destination_is_never_overwritten(self):
        self.target().mkdir()
        marker = self.target() / "keep"
        marker.write_bytes(b"preserved")
        with self.assertRaises(OSError):
            self.install()
        self.assertEqual(marker.read_bytes(), b"preserved")

    def test_source_destination_overlap_refuses(self):
        with self.assertRaisesRegex(subject.PiServiceConfigurationError, "overlap"):
            self.install(destination_parent=self.source)

    def test_expired_deadline_refuses_before_writes(self):
        with self.assertRaises(subject.provision.PiOsProvisionError):
            self.install(deadline=time.monotonic() - 1)
        self.assertFalse(self.target().exists())

    def test_failed_install_retains_partial_and_observation(self):
        original = subject.provision._install_tree
        def failed(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("inert copy uncertainty")
        with mock.patch.object(subject.provision, "_install_tree", side_effect=failed):
            with self.assertRaises(OSError) as caught:
                self.install()
        self.assertTrue((self.target() / "root" / subject.PATHS["action"]).is_file())
        self.assertFalse((self.target() / subject.RECEIPT).exists())
        self.assertFalse(caught.exception.pi_service_configuration_observation["completed"])

    def test_installer_final_close_uncertainty_clears_completed_observation(self):
        original = subject.provision._close_all
        failures = []
        def close(descriptors):
            original(descriptors)
            if len(descriptors) == 6:
                failures.append(tuple(descriptors))
                raise subject.provision.PiOsProvisionError("inert final close uncertainty")
        with mock.patch.object(subject.provision, "_close_all", side_effect=close):
            with self.assertRaises(subject.provision.PiOsProvisionError) as caught:
                self.install()
        self.assertEqual(len(failures), 1)
        self.assertFalse(caught.exception.pi_service_configuration_observation["completed"])
        self.assertTrue((self.target() / subject.RECEIPT).is_file())

    def test_source_change_before_final_validation_refuses(self):
        original = subject.provision._install_tree
        def changed(*args, **kwargs):
            original(*args, **kwargs)
            (self.source / subject.PATHS["action"]).write_bytes(b"changed")
        with mock.patch.object(subject.provision, "_install_tree", side_effect=changed), self.assertRaises(subject.provision.PiOsProvisionError):
            self.install()
        self.assertTrue(self.target().exists())

    def test_bad_receipt_pin_cannot_mint_configuration_custody(self):
        receipt = self.install()
        with self.assertRaisesRegex(subject.PiServiceConfigurationError, "independent pins"):
            with self.hold(receipt, receipt_digest="sha256:" + "0" * 64):
                self.fail("unexpected held custody")

    def test_plain_receipt_unminted_or_subclass_cannot_mint(self):
        with self.assertRaisesRegex(subject.PiServiceConfigurationError, "verified installed"):
            subject.PiServiceConfiguration(None, None, None, None, None, None, None, None, None)
        class Counterfeit(subject.PiServiceConfiguration):
            pass
        for kind in (subject.PiServiceConfiguration, Counterfeit):
            with self.subTest(kind=kind), self.assertRaisesRegex(subject.PiServiceConfigurationError, "not minted"):
                object.__new__(kind).guard()

    def test_configuration_context_withdraws_authority_and_closes_fd(self):
        receipt = self.install()
        with self.hold(receipt) as held:
            descriptor = held.root_fd
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.assertRaisesRegex(subject.PiServiceConfigurationError, "inactive"):
            held.guard()

    def test_guard_rejects_mutated_config_bytes(self):
        receipt = self.install()
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.hold(receipt) as held:
                path = held.root / subject.PATHS["action"]
                path.chmod(0o644)
                path.write_bytes(b"changed")
                path.chmod(0o444)
                held.guard()

    def test_guard_rejects_replaced_root_name(self):
        receipt = self.install()
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.hold(receipt) as held:
                held.root.rename(self.target() / "old-root")
                held.root.mkdir()
                held.guard()

    def test_guard_rejects_receipt_replacement(self):
        receipt = self.install()
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.hold(receipt) as held:
                path = self.target() / subject.RECEIPT
                path.unlink()
                path.write_bytes(canonical_json(receipt))
                path.chmod(0o444)
                held.guard()

    def test_successful_context_exit_performs_final_guard(self):
        receipt = self.install()
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.hold(receipt) as held:
                (held.root / subject.PATHS["provider"]).chmod(0o644)

    def test_guard_tighter_deadline_propagates_without_mutating_lease(self):
        receipt = self.install()
        with self.hold(receipt) as held:
            original = held.deadline
            bounded = original - 5
            with mock.patch.object(subject.custody, "_tree", wraps=subject.custody._tree) as tree:
                held.guard(deadline=bounded)
                self.assertEqual(tree.call_args.args[2], bounded)
            self.assertEqual(held.deadline, original)

    def test_guard_cannot_extend_or_expire_budget(self):
        receipt = self.install()
        with self.hold(receipt) as held:
            for deadline in (held.deadline + 1, time.monotonic() - 1):
                with self.subTest(deadline=deadline), self.assertRaises(subject.provision.PiOsProvisionError):
                    held.guard(deadline=deadline)

    def test_unrelated_sibling_creation_does_not_invalidate_custody(self):
        receipt = self.install()
        with self.hold(receipt) as held:
            (self.parent / "unrelated").mkdir()
            held.guard()

    def test_configuration_close_uncertainty_is_not_success_or_retried(self):
        receipt = self.install()
        closed = []
        original = os.close
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.hold(receipt) as held:
                descriptor = held.root_fd
                def close(fd):
                    closed.append(fd)
                    original(fd)
                    if fd == descriptor:
                        raise OSError("inert close uncertainty")
                self.stack.enter_context(mock.patch.object(os, "close", side_effect=close))
        self.assertEqual(closed.count(descriptor), 1)
        with self.assertRaises(subject.PiServiceConfigurationError):
            held.guard()

    def test_existing_public_provider_inputs_are_held_without_keys(self):
        receipt = self.provider_install()
        with self.provider_hold(receipt) as held:
            self.assertIs(type(held), subject.PiProviderInputs)
            self.assertEqual(held.profile, self.profile)
            self.assertEqual(held.root, self.parent / "provider/root")
            self.assertEqual(held.observation["profile_digest"], canonical_digest(self.profile))
            self.assertFalse(held.observation["credential_read"])
            held.guard()

    def test_provider_profile_and_observation_are_detached(self):
        receipt = self.provider_install()
        with self.provider_hold(receipt) as held:
            held.profile["address"] = "8.8.8.8"
            held.observation["service_ready"] = True
            self.assertEqual(held.profile, self.profile)
            self.assertFalse(held.observation["service_ready"])

    def test_provider_plain_metadata_and_unminted_subclass_refuse(self):
        with self.assertRaisesRegex(subject.PiServiceConfigurationError, "verified installed"):
            subject.PiProviderInputs(None, None, None, None, None, None, None, None, None)
        class Counterfeit(subject.PiProviderInputs):
            pass
        for kind in (subject.PiProviderInputs, Counterfeit):
            with self.subTest(kind=kind), self.assertRaises(subject.PiServiceConfigurationError):
                object.__new__(kind).guard()

    def test_provider_wrong_manifest_or_receipt_pin_refuses(self):
        receipt = self.provider_install()
        for changes in ({"manifest_digest": "sha256:" + "0" * 64}, {"receipt_digest": "sha256:" + "0" * 64}):
            with self.subTest(changes=changes), self.assertRaises(subject.provision.PiOsProvisionError):
                with self.provider_hold(receipt, **changes):
                    self.fail("unexpected provider custody")

    def test_provider_extra_secret_leaf_is_not_read(self):
        receipt = self.provider_install()
        directory = self.parent / "provider/root/etc/aragorn"
        directory.chmod(0o755)
        (directory / "openai-api-key").write_bytes(b"inert forbidden fixture")
        directory.chmod(0o555)
        original = os.open
        def guarded(path, *args, **kwargs):
            if str(path).endswith("openai-api-key"):
                raise AssertionError("secret read")
            return original(path, *args, **kwargs)
        with mock.patch.object(os, "open", side_effect=guarded), self.assertRaises(subject.provision.PiOsProvisionError):
            with self.provider_hold(receipt):
                self.fail("unexpected provider custody")

    def test_provider_ca_bytes_change_is_refused(self):
        receipt = self.provider_install()
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.provider_hold(receipt) as held:
                path = held.root / subject.public_inputs.CA
                path.chmod(0o644)
                path.write_bytes(b"changed CA")
                path.chmod(0o444)
                held.guard()

    def test_provider_receipt_change_is_refused(self):
        receipt = self.provider_install()
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.provider_hold(receipt) as held:
                path = self.parent / "provider" / subject.public_inputs.RECEIPT
                path.chmod(0o644)
                path.write_bytes(b"changed receipt")
                path.chmod(0o444)
                held.guard()

    def test_provider_root_name_replacement_refuses(self):
        receipt = self.provider_install()
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.provider_hold(receipt) as held:
                held.root.rename(self.parent / "provider/old-root")
                held.root.mkdir()
                held.guard()

    def test_provider_guard_tightens_only_and_forwards_budget(self):
        receipt = self.provider_install()
        with self.provider_hold(receipt) as held:
            original = held.deadline
            with mock.patch.object(subject, "_provider_tree", wraps=subject._provider_tree) as tree:
                held.guard(deadline=original - 5)
                self.assertEqual(tree.call_args.args[2], original - 5)
            with self.assertRaises(subject.PiServiceConfigurationError):
                held.guard(deadline=original + 1)
            self.assertEqual(held.deadline, original)

    def test_provider_successful_exit_revalidates_then_closes(self):
        receipt = self.provider_install()
        with self.provider_hold(receipt) as held:
            descriptor = held.root_fd
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.assertRaises(subject.PiServiceConfigurationError):
            _ = held.profile

    def test_provider_final_guard_failure_prevents_clean_exit(self):
        receipt = self.provider_install()
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.provider_hold(receipt) as held:
                (held.root / subject.public_inputs.CA).chmod(0o644)

    def test_provider_close_uncertainty_withdraws_custody_without_retry(self):
        receipt = self.provider_install()
        closed = []
        original = os.close
        with self.assertRaises(subject.provision.PiOsProvisionError):
            with self.provider_hold(receipt) as held:
                descriptor = held.root_fd
                def close(fd):
                    closed.append(fd)
                    original(fd)
                    if fd == descriptor:
                        raise OSError("inert close uncertainty")
                self.stack.enter_context(mock.patch.object(os, "close", side_effect=close))
        self.assertEqual(closed.count(descriptor), 1)
        with self.assertRaises(subject.PiServiceConfigurationError):
            held.guard()


if __name__ == "__main__":
    unittest.main()
