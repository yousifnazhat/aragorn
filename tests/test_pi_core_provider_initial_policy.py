"""Pinned first publication; inert owned filesystem only, no service or health."""

from dataclasses import replace
import os
import unittest
from unittest import mock

from aragorn import pi_core_broker_base_provision as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_provider_base_provision as provider


class InitialPolicyTests(provider.ProviderTests):
    def setUp(self):
        self.policy = {"schema": "aragorn/runtime-action-policy/v1", "id": "initial-fixture", "version": 3,
            "default": "BLOCK", "sensor_digest": "sha256:" + "6" * 64,
            "revocation_source_digest": "sha256:" + "9" * 64, "allow": []}
        self.revocations = {"schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": self.policy["revocation_source_digest"], "generation": 3,
            "observed_at_unix": 95, "expires_at_unix": 105, "skill_digests": []}
        fixtures = provider.base.fixtures
        original = fixtures.configurations
        def inputs():
            docs = original()
            for role in ("action", "sensor"):
                docs[role]["capability_grant"]["policy_digest"] = canonical_digest(self.policy)
            return docs
        with mock.patch.object(fixtures, "configurations", side_effect=inputs):
            super().setUp()
        self.clock = self.stack.enter_context(mock.patch.object(subject.broker.time, "time", return_value=100))
        self.install_provider()

    def initial(self, **changes):
        values = dict(configuration=self.held, provider_config=self.config, base_state=self.state,
                      policy=self.policy, revocations=self.revocations) | changes
        for name in ("policy", "revocations", "base_state"):
            values.setdefault(name + "_digest", canonical_digest(values[name]))
        return subject.initialize_pi_provider_policy(**values, deadline=self.deadline)

    def record(self, error, status):
        row = error.pi_provider_initial_policy_observation
        self.assertEqual((row["schema"], row["authority"], row["status"]),
            (subject.PROVIDER_INITIAL_POLICY_SCHEMA, subject.PROVIDER_INITIAL_POLICY_AUTHORITY, status))
        for key in ("activation_performed", "service_ready", "current_grant_authority", "phase3_exit_eligible"):
            self.assertIs(row[key], False)
        return row

    def test_first_publication_exact_bytes_named_ids_preserved_floors_and_no_health(self):
        prior = subject.provision._identity(self.config.state_path.stat())
        row = self.initial()
        self.assertEqual(row["status"], "INSTALLED")
        self.assertTrue(row["owned_handles_closed"])
        self.assertEqual(row["cleanup_uncertainty"], [])
        self.assertEqual(set(row["created_members"]), {"control/policy.json", "control/revocations.json"})
        self.assertEqual(row["readback"]["base_state"], self.state)
        self.assertEqual(subject.provision._identity(self.config.state_path.stat()), prior)
        self.assertEqual(set(row["readback"]["directories"]), {self.destination.name, "control",
            "protected", "staging", "provider-evidence", "blobs", "sha256"})
        for name, raw, mode in (("policy.json", canonical_json(self.policy), 0o400),
                ("revocations.json", canonical_json(self.revocations), 0o400),
                ("state.json", canonical_json(self.state), 0o400), ("broker.lock", b"", 0o600)):
            path = self.config.control_root / name
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(path.stat().st_mode & 0o777, mode)
            self.assertEqual(row["readback"]["files"][name], {"digest": "sha256:" + subject.provision.hashlib.sha256(raw).hexdigest(),
                "identity": list(subject.provision._identity(path.stat()))})
        self.assertEqual({p.name for p in self.config.control_root.iterdir()},
            {"policy.json", "revocations.json", "broker.lock", "state.json", "provider-evidence"})
        for forbidden in self.forbidden:
            forbidden.assert_not_called()

    def test_requires_each_independent_document_pin_before_writing(self):
        for name in ("policy", "base_state", "revocations"):
            for wrong in (None, "sha256:" + "f" * 64):
                with self.subTest(name=name, wrong=wrong), self.assertRaises(RuntimeError) as error:
                    self.initial(**{name + "_digest": wrong})
                self.assertFalse(self.record(error.exception, "REFUSED")["mutation_attempted"])

    def test_fixed_provider_identity_and_actual_held_configuration(self):
        for changes in (dict(provider_config=replace(self.config, expected_peer_gid=9822)),
                        dict(provider_config=replace(self.config, policy_path=self.action_root/"policy.json")),
                        dict(configuration=self.configs)):
            with self.subTest(changes=changes.keys()), self.assertRaises(RuntimeError) as error:
                self.initial(**changes)
            self.assertFalse(self.record(error.exception, "REFUSED")["mutation_attempted"])

    def test_invalid_default_or_policy_not_bound_to_held_grant(self):
        for changes in ({"default": "ALLOW"}, {"sensor_digest": "sha256:" + "1"*64},
                        {"version": 5}, {"id": "other-fixture"}):
            with self.subTest(changes=changes), self.assertRaises(Exception) as error:
                self.initial(policy=self.policy | changes)
            self.assertFalse(self.record(error.exception, "REFUSED")["mutation_attempted"])

    def test_current_original_revocation_source_exact_floor_and_unrevoked_skill(self):
        skill = self.configs["action"]["capability_grant"]["active_skill_digest"]
        for changes in ({"generation": 2}, {"generation": 4}, {"source_digest": "sha256:" + "a"*64},
                {"expires_at_unix": 100}, {"observed_at_unix": 101}, {"skill_digests": [skill]},
                {"skill_digests": [skill, skill]}):
            with self.subTest(changes=changes), self.assertRaises(Exception) as error:
                self.initial(revocations=self.revocations | changes)
            self.assertFalse(self.record(error.exception, "REFUSED")["mutation_attempted"])

    def test_no_state_floor_rewrite_or_legacy_state_migration(self):
        for field, change in (("minimum_mediator_health_epoch", 88), ("schema", "aragorn/runtime-action-broker-state/v1")):
            with self.subTest(field=field), self.assertRaises(Exception) as error:
                self.initial(base_state=self.state | {field:change})
            self.assertFalse(self.record(error.exception, "REFUSED")["mutation_attempted"])
        self.assertEqual(self.config.state_path.read_bytes(), canonical_json(self.state))

    def test_existing_controls_or_effect_or_attempt_prevent_any_write(self):
        for rel in ("control/health.json", "control/observation.json", "control/policy.json", "control/revocations.json",
                    "control/provider-evidence/attempt.jsonl", "control/provider-evidence/blobs/sha256/residue",
                    "protected/retained", "staging/uncommitted"):
            path = self.destination / rel
            path.write_bytes(b"prior")
            with self.subTest(rel=rel), self.assertRaises(Exception) as error:
                self.initial()
            self.assertFalse(self.record(error.exception, "REFUSED")["mutation_attempted"])
            self.assertEqual(path.read_bytes(), b"prior")
            path.unlink()  # Remove only our inert test sentinel, not production cleanup.

    def test_repeated_call_cannot_adopt_or_publish_again(self):
        self.initial()
        prior = self.config.revocations_path.stat()
        with self.assertRaises(Exception) as error:
            self.initial()
        self.assertFalse(self.record(error.exception, "REFUSED")["mutation_attempted"])
        self.assertEqual(subject.provision._identity(prior), subject.provision._identity(self.config.revocations_path.stat()))

    def test_private_modes_and_symlink_to_foreign_storage_refuse(self):
        self.config.staging_root.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "METADATA"):
            self.initial()
        self.config.staging_root.chmod(0o700)
        foreign = self.fixture / "untouched"
        foreign.mkdir()
        self.config.staging_root.rmdir()
        self.config.staging_root.symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(OSError) as error:
            self.initial()
        self.assertFalse(self.record(error.exception, "REFUSED")["mutation_attempted"])
        self.assertEqual(list(foreign.iterdir()), [])

    def test_changed_state_or_replaced_lock_after_locking_refuses(self):
        original = subject.broker._acquire_lock
        def replace_lock(fd, deadline):
            original(fd, deadline)
            replacement = self.fixture / "new-lock"
            replacement.touch(mode=0o600)
            replacement.replace(self.config.lock_path)
        with mock.patch.object(subject.broker, "_acquire_lock", side_effect=replace_lock), self.assertRaises(Exception) as error:
            self.initial()
        self.assertFalse(self.record(error.exception, "REFUSED")["mutation_attempted"])
        self.assertFalse(self.config.policy_path.exists())

    def test_second_row_never_replaces_racing_foreign_file(self):
        original = os.open
        def race(name, flags, *args, **kwargs):
            if name == "revocations.json" and flags & os.O_EXCL:
                self.config.revocations_path.write_bytes(b"foreign")
            return original(name, flags, *args, **kwargs)
        with mock.patch.object(os, "open", side_effect=race), self.assertRaises(FileExistsError) as error:
            self.initial()
        self.assertEqual(set(self.record(error.exception, "PARTIAL_OR_INDETERMINATE")["created_members"]),
                         {"control/policy.json"})
        self.assertEqual(self.config.policy_path.read_bytes(), canonical_json(self.policy))
        self.assertEqual(self.config.revocations_path.read_bytes(), b"foreign")

    def test_expiry_at_final_readback_retains_both_rows_without_renewal(self):
        self.clock.side_effect = lambda: 105 if self.config.revocations_path.exists() else 100
        with self.assertRaisesRegex(RuntimeError, "NOT_CURRENT") as error:
            self.initial()
        row = self.record(error.exception, "PARTIAL_OR_INDETERMINATE")
        self.assertEqual(set(row["created_members"]), {"control/policy.json", "control/revocations.json"})
        self.assertEqual(row["readback"]["files"]["revocations.json"]["digest"], canonical_digest(self.revocations))

    def test_ambiguous_exclusive_create_does_not_claim_or_retry_an_inode(self):
        original = os.open
        calls = []
        def cancelled(name, flags, *args, **kwargs):
            if name == "policy.json" and flags & os.O_EXCL:
                calls.append(name)
                raise InterruptedError("unknown first publication")
            return original(name, flags, *args, **kwargs)
        with mock.patch.object(os, "open", side_effect=cancelled), self.assertRaises(InterruptedError) as error:
            self.initial()
        row = self.record(error.exception, "PARTIAL_OR_INDETERMINATE")
        self.assertEqual((calls, row["created_members"], row["uncertain_creation"]), (["policy.json"], {}, "control/policy.json"))
        self.assertFalse(self.config.revocations_path.exists())

    def test_primary_cancellation_survives_owned_close_failure_no_retry(self):
        original_open, original_close = os.open, os.close
        primary = KeyboardInterrupt("cancelled after exclusive creation")
        opened, closed = [], []
        def opening(name, flags, *args, **kwargs):
            fd = original_open(name, flags, *args, **kwargs)
            if name == "policy.json" and flags & os.O_EXCL:
                opened.append(fd)
            return fd
        def closing(fd):
            original_close(fd)
            if fd in opened:
                closed.append(fd)
                raise OSError("uncertain close")
        with mock.patch.object(os, "open", side_effect=opening), mock.patch.object(os, "close", side_effect=closing), \
             mock.patch.object(subject.provision, "_write_all", side_effect=primary), self.assertRaises(KeyboardInterrupt) as error:
            self.initial()
        self.assertIs(error.exception, primary)
        self.assertEqual(opened, closed)
        self.assertEqual(len(closed), 1)
        row = self.record(primary, "CLEANUP_HOLD")
        self.assertFalse(row["owned_handles_closed"])
        self.assertIsNone(row["uncertain_creation"])
        observed = self.config.policy_path.stat()
        self.assertEqual(row["created_members"]["control/policy.json"][:2], [observed.st_dev, observed.st_ino])
        self.assertTrue(self.config.policy_path.exists())
        self.assertFalse(self.config.revocations_path.exists())


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(InitialPolicyTests(name) for name in sorted(InitialPolicyTests.__dict__)
                               if name.startswith("test_"))
    # Only the extracted shared provider configuration join changed in the prior route.
    for name in ("test_each_control_leaf_is_fixed", "test_sensor_worker_and_runtime_must_match_held_configuration",
                 "test_readback_records_nested_directory_identities_and_expected_config_document"):
        suite.addTest(provider.ProviderTests(name))
    return suite
