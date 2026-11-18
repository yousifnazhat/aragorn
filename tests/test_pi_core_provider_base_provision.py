"""Provider-specific provisioning boundaries in a fresh, owned temporary tree."""

from dataclasses import asdict, replace
import os
from pathlib import Path
import stat
import unittest
from unittest import mock

from aragorn import pi_core_broker_base_provision as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_broker_base_provision as base


class ProviderTests(base.BaseFixture):
    def setUp(self):
        super().setUp()
        self.action_root = self.destination
        self.destination = self.base_parent / "aragorn-runtime-provider"
        self.stack.enter_context(mock.patch.object(subject, "PROVIDER_DESTINATION", self.destination))
        # The temporary filesystem uses the current account, not real Linux root.
        self.validate = self.stack.enter_context(mock.patch.object(subject.broker, "_validate_config"))
        ids = self.configs["action"]["identities"]
        control = self.destination / "control"
        self.config = subject.broker.RuntimeActionBrokerConfig(
            socket_path=control/"broker.sock", instance_lock_path=control/"instance.lock",
            lock_path=control/"broker.lock", control_root=control, protected_root=self.destination/"protected",
            staging_root=self.destination/"staging", policy_path=control/"policy.json",
            revocations_path=control/"revocations.json", health_path=control/"health.json",
            observation_path=control/"observation.json", state_path=control/"state.json", expected_broker_uid=0,
            expected_peer_uid=ids["sensor"]["uid"], expected_peer_gid=ids["sensor"]["gid"],
            expected_runtime_uid=ids["worker"]["uid"], expected_runtime_gid=ids["worker"]["gid"],
            expected_runtime_digest=self.configs["action"]["capability_grant"]["runtime_digest"])

    def install_provider(self, **changes):
        return subject.provision_pi_provider_base(**dict(configuration=self.held, provider_config=self.config,
            base_state=self.state, base_state_digest=canonical_digest(self.state), deadline=self.deadline) | changes)

    def failure_record(self, error, status):
        self.assertFalse(hasattr(error, "pi_broker_base_observation"))
        row = error.pi_provider_base_observation
        self.assertEqual((row["schema"], row["status"]), (subject.PROVIDER_SCHEMA, status))
        return row

    def test_complete_tree_matches_actual_store_and_contains_no_authority(self):
        row = self.install_provider()
        self.validate.assert_called_once_with(self.config)
        self.assertEqual((row["status"], row["schema"], row["authority"]),
                         ("INSTALLED", subject.PROVIDER_SCHEMA, subject.AUTHORITY))
        self.assertTrue(row["owned_handles_closed"])
        paths = {p.relative_to(self.destination).as_posix() for p in self.destination.rglob("*")}
        self.assertEqual(paths, {"control", "protected", "staging", "control/broker.lock", "control/state.json",
            "control/provider-evidence", "control/provider-evidence/blobs", "control/provider-evidence/blobs/sha256"})
        for leaf in ("", *paths):
            info = (self.destination / leaf).stat()
            mode = {"control/broker.lock": 0o600, "control/state.json": 0o400}.get(leaf, 0o700)
            self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid),
                             (mode, os.getuid(), os.getgid()))
        self.assertEqual(self.config.lock_path.read_bytes(), b"")
        self.assertEqual(self.config.state_path.read_bytes(), canonical_json(self.state))
        self.assertFalse(self.action_root.exists())
        for flag in ("activation_performed", "service_ready", "current_grant_authority", "phase3_exit_eligible"):
            self.assertIs(row[flag], False)
        for forbidden in self.forbidden:
            forbidden.assert_not_called()

    def test_readback_records_nested_directory_identities_and_expected_config_document(self):
        row = self.install_provider()
        wire = {key: str(value) if isinstance(value, Path) else value for key, value in asdict(self.config).items()}
        self.assertEqual(row["provider_config_digest"], canonical_digest(wire))
        self.assertEqual(row["base_state_digest"], canonical_digest(self.state))
        for leaf in ("control/provider-evidence", "control/provider-evidence/blobs", "control/provider-evidence/blobs/sha256"):
            path = self.destination / leaf
            self.assertEqual(row["readback"]["directories"][path.name], list(subject.provision._identity(path.stat())))
        self.assertEqual(row["readback"]["base_state"], self.state)

    def test_provider_path_cannot_select_action_mode_or_other_destination(self):
        for value in (None, object(), replace(self.config, expected_broker_uid=1201),
                      replace(self.config, control_root=self.action_root/"control"),
                      replace(self.config, protected_root=self.action_root/"protected"),
                      replace(self.config, staging_root=self.action_root/"staging")):
            with self.subTest(value=value), self.assertRaises(subject.PiBrokerBaseProvisionError) as caught:
                self.install_provider(provider_config=value)
            self.assertFalse(self.failure_record(caught.exception, "REFUSED")["mutation_attempted"])
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.action_root.exists())

    def test_each_control_leaf_is_fixed(self):
        for field in ("socket_path", "instance_lock_path", "lock_path", "policy_path", "revocations_path",
                      "health_path", "observation_path", "state_path"):
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "FIXED_PATHS"):
                self.install_provider(provider_config=replace(self.config, **{field:self.config.control_root/"other"}))
        self.assertFalse(self.destination.exists())

    def test_sensor_worker_and_runtime_must_match_held_configuration(self):
        for field in ("expected_peer_uid", "expected_peer_gid", "expected_runtime_uid", "expected_runtime_gid",
                      "expected_runtime_digest"):
            value = "sha256:" + "0"*64 if field.endswith("digest") else 9999
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "IDENTITY_MISMATCH"):
                self.install_provider(provider_config=replace(self.config, **{field:value}))
        self.assertFalse(self.destination.exists())

    def test_requires_real_held_service_configuration(self):
        with self.assertRaisesRegex(RuntimeError, "HELD_CONFIGURATION") as caught:
            self.install_provider(configuration=self.configs)
        self.assertFalse(self.failure_record(caught.exception, "REFUSED")["mutation_attempted"])

    def test_state_must_match_independent_pin_without_migration(self):
        with self.assertRaisesRegex(RuntimeError, "PIN_MISMATCH"):
            self.install_provider(base_state_digest="sha256:" + "0"*64)
        legacy = {k:v for k,v in self.state.items() if k != "effect_journal"}
        legacy["schema"] = "aragorn/runtime-action-broker-state/v1"
        with self.assertRaisesRegex(RuntimeError, "CURRENT_AND_EMPTY"):
            self.install_provider(base_state=legacy, base_state_digest=canonical_digest(legacy))
        self.assertFalse(self.destination.exists())

    def test_existing_base_preserves_attempts_without_reopening_any_index(self):
        self.install_provider()
        index = self.config.control_root/"provider-evidence"/"attempt-owned.jsonl"
        index.write_bytes(b"prior evidence")
        with self.assertRaisesRegex(RuntimeError, "ALREADY_EXISTS") as caught:
            self.install_provider()
        self.assertFalse(self.failure_record(caught.exception, "REFUSED")["mutation_attempted"])
        self.assertEqual(index.read_bytes(), b"prior evidence")

    def test_symlink_to_action_destination_is_never_followed(self):
        self.action_root.mkdir()
        self.destination.symlink_to(self.action_root, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "ALREADY_EXISTS"):
            self.install_provider()
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(list(self.action_root.iterdir()), [])

    def test_partial_evidence_tree_keeps_prefix_and_original_cancellation(self):
        mkdir = os.mkdir
        cancel = KeyboardInterrupt("owned fixture cancellation")
        def create(name, *args, **kwargs):
            if name == "sha256":
                raise cancel
            return mkdir(name, *args, **kwargs)
        with mock.patch.object(os, "mkdir", side_effect=create), self.assertRaises(KeyboardInterrupt) as caught:
            self.install_provider()
        self.assertIs(caught.exception, cancel)
        row = self.failure_record(cancel, "PARTIAL_OR_INDETERMINATE")
        self.assertTrue(row["owned_handles_closed"])
        self.assertIn("blobs", row["created_members"])
        self.assertNotIn("sha256", row["created_members"])
        self.assertTrue((self.config.control_root/"provider-evidence"/"blobs").is_dir())
        self.assertIsNone(row["readback"])

    def test_foreign_blob_before_readback_blocks_success_without_removal(self):
        sha = self.config.control_root/"provider-evidence"/"blobs"/"sha256"
        def changed():
            if sha.exists() and not (sha/"unrelated").exists():
                (sha/"unrelated").touch()
        with self.config_guard(changed), self.assertRaises(RuntimeError) as caught:
            self.install_provider()
        row = self.failure_record(caught.exception, "PARTIAL_OR_INDETERMINATE")
        self.assertIsNotNone(row["readback"])
        self.assertTrue((sha/"unrelated").exists())

    def test_nested_handle_close_uncertainty_retained_without_retry(self):
        opened, close_calls = [], []
        original_open, original_close = os.open, os.close
        def locate(name, *args, **kwargs):
            fd = original_open(name, *args, **kwargs)
            if name == "sha256":
                opened.append(fd)
            return fd
        def close(fd):
            original_close(fd)
            if fd in opened:
                close_calls.append(fd)
                raise OSError("uncertain fixture close")
        with mock.patch.object(os, "open", side_effect=locate), mock.patch.object(os, "close", side_effect=close), \
                self.assertRaisesRegex(OSError, "uncertain fixture close") as caught:
            self.install_provider()
        self.assertEqual(close_calls, opened)
        self.assertFalse(self.failure_record(caught.exception, "CLEANUP_HOLD")["owned_handles_closed"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(ProviderTests(name) for name in sorted(ProviderTests.__dict__) if name.startswith("test_"))
    for name in ("test_installs_exact_empty_base_and_preserves_authority_boundaries",
                 "test_exact_modes_owner_and_named_readback_identities", "test_configuration_must_be_exact_held_type",
                 "test_primary_cancellation_survives_close_failure"):
        suite.addTest(base.BaseProvisionTests(name))
    return suite
