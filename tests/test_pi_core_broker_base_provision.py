"""New base installer cases using only owned temporary trees and inert roles.

The existing protected-config fixture supplies real canonical files/custody.
Linux/root are simulated; action maps to the test UID for these inert writes.
No test establishes target ownership, a running service, health or permission.
"""

from contextlib import contextmanager
import copy
import os
from pathlib import Path
import stat
import time
import unittest
from unittest import mock

from aragorn import pi_core_broker_base_provision as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_service_configuration as fixtures


def base_state():
    return {"schema": "aragorn/runtime-action-broker-state/v2",
        "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "minimum_revocation_generation": 3, "minimum_mediator_health_epoch": 7,
        "consumed": [], "effect_journal": None}


class BaseFixture(fixtures.PiServiceConfigurationTests):
    def setUp(self):
        super().setUp()
        ids = self.configs["action"]["identities"]
        ids["action"] = {"uid": os.getuid() or 1201, "gid": os.getgid() or 1301}
        for role in self.configs:
            self.configs[role]["identities"] = copy.deepcopy(ids)
            (self.source / fixtures.subject.PATHS[role]).write_bytes(canonical_json(self.configs[role]))
        self.manifest = self.inventory(self.source)
        self.config_receipt = self.install()
        holder = self.hold(self.config_receipt)
        self.held = holder.__enter__()
        self.damaged_config = False
        def close_holder():
            if self.damaged_config:
                holder.__exit__(RuntimeError, RuntimeError("intentional inert fixture damage"), None)
            else:
                holder.__exit__(None, None, None)
        self.stack.callback(close_holder)
        self.base_parent = self.fixture / "var-lib"
        self.base_parent.mkdir(mode=0o755)
        self.destination = self.base_parent / "aragorn-runtime-action"
        self.stack.enter_context(mock.patch.object(subject, "DESTINATION", self.destination))
        self.state = base_state()
        self.deadline = time.monotonic() + 30
        self.forbidden = []
        for owner, name in ((subject.broker, "_load_state"), (subject.broker, "_atomic_publish_at"),
                            (subject.broker, "publish_runtime_control_document"),
                            (fixtures.subject.entry.action, "initialize_pi_broker_request_service")):
            self.forbidden.append(self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("installation must not migrate, publish, or prepare a grant"))))

    def run_base(self, **changes):
        return subject.provision_pi_broker_base(**({"configuration": self.held, "base_state": self.state,
            "base_state_digest": canonical_digest(self.state), "deadline": self.deadline} | changes))

    def record(self, error):
        result = error.pi_broker_base_observation
        self.assertEqual(result["schema"], subject.SCHEMA)
        self.assertEqual(result["authority"], subject.AUTHORITY)
        for field in ("activation_performed", "service_ready", "current_grant_authority", "phase3_exit_eligible"):
            self.assertIs(result[field], False)
        return result

    @contextmanager
    def config_guard(self, callback):
        original = fixtures.subject.PiServiceConfiguration.guard
        def guard(held, **options):
            original(held, **options)
            callback()
        with mock.patch.object(fixtures.subject.PiServiceConfiguration, "guard", guard):
            yield


class BaseProvisionTests(BaseFixture):
    def test_installs_exact_empty_base_and_preserves_authority_boundaries(self):
        result = self.run_base()
        self.assertEqual(result["status"], "INSTALLED")
        self.assertEqual(result["configuration_digest"], canonical_digest(self.configs))
        self.assertEqual(result["base_state_digest"], canonical_digest(self.state))
        self.assertEqual(result["destination"], str(self.destination))
        self.assertTrue(result["mutation_attempted"])
        self.assertTrue(result["owned_handles_closed"])
        self.assertEqual(result["cleanup_uncertainty"], [])
        self.assertEqual(result["readback"]["base_state"], self.state)
        self.assertEqual(set(result["readback"]["files"]), {"broker.lock", "state.json"})
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), ["control", "protected", "staging"])
        self.assertEqual(sorted(p.name for p in (self.destination / "control").iterdir()), ["broker.lock", "state.json"])
        self.assertEqual((self.destination / "control/state.json").read_bytes(), canonical_json(self.state))
        for field in ("activation_performed", "service_ready", "current_grant_authority", "phase3_exit_eligible"):
            self.assertIs(result[field], False)
        for forbidden in self.forbidden:
            forbidden.assert_not_called()

    def test_exact_modes_owner_and_named_readback_identities(self):
        result = self.run_base()
        for leaf, mode in (("", 0o755), ("control", 0o710), ("protected", 0o710), ("staging", 0o700),
                           ("control/broker.lock", 0o600), ("control/state.json", 0o400)):
            info = (self.destination / leaf).stat()
            owner = {"uid": os.getuid(), "gid": os.getgid()} if not leaf else self.configs["action"]["identities"]["action"]
            self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid), (mode, owner["uid"], owner["gid"]))
        for name, row in result["readback"]["files"].items():
            self.assertEqual(row["identity"], list(subject.provision._identity((self.destination / "control" / name).stat())))
        self.assertEqual((self.destination / "control/broker.lock").stat().st_size, 0)

    def test_returned_record_is_detached_from_input(self):
        original = copy.deepcopy(self.state)
        result = self.run_base()
        result["readback"]["base_state"]["minimum_mediator_health_epoch"] = 999
        self.assertEqual(self.state, original)
        self.assertEqual((self.destination / "control/state.json").read_bytes(), canonical_json(original))

    def test_configuration_must_be_exact_held_type(self):
        with self.assertRaisesRegex(subject.PiBrokerBaseProvisionError, "HELD_CONFIGURATION") as caught:
            self.run_base(configuration=object())
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.record(caught.exception)["mutation_attempted"])

    def test_inactive_configuration_refuses_before_mutation(self):
        self.held._active = False
        try:
            with self.assertRaises(fixtures.subject.PiServiceConfigurationError) as caught:
                self.run_base()
        finally:
            self.held._active = True
        self.assertEqual(self.record(caught.exception)["status"], "REFUSED")
        self.assertFalse(self.destination.exists())

    def test_changed_installed_configuration_refuses_before_mutation(self):
        path = self.held.root / fixtures.subject.PATHS["action"]
        self.damaged_config = True
        path.chmod(0o644)
        path.write_bytes(b"changed")
        path.chmod(0o444)
        with self.assertRaises(Exception) as caught:
            self.run_base()
        self.assertFalse(self.record(caught.exception)["mutation_attempted"])
        self.assertFalse(self.destination.exists())

    def test_independent_state_pin_must_match(self):
        with self.assertRaisesRegex(subject.PiBrokerBaseProvisionError, "PIN_MISMATCH") as caught:
            self.run_base(base_state_digest="sha256:" + "0" * 64)
        self.assertEqual(self.record(caught.exception)["status"], "REFUSED")
        self.assertFalse(self.destination.exists())

    def test_missing_or_malformed_pin_refuses(self):
        for pin in (None, "", "sha256:ABC", 12):
            with self.subTest(pin=pin), self.assertRaises(subject.PiBrokerBaseProvisionError):
                self.run_base(base_state_digest=pin)
        self.assertFalse(self.destination.exists())

    def test_legacy_state_is_not_migrated(self):
        self.state.pop("effect_journal")
        self.state["schema"] = "aragorn/runtime-action-broker-state/v1"
        with self.assertRaisesRegex(subject.PiBrokerBaseProvisionError, "CURRENT_AND_EMPTY"):
            self.run_base()
        self.assertFalse(self.destination.exists())

    def test_nonempty_consumed_state_refuses(self):
        self.state["consumed"] = [{"request_digest": "sha256:" + "1" * 64,
            "observation_digest": "sha256:" + "2" * 64, "expires_at_unix": 100}]
        with self.assertRaisesRegex(subject.PiBrokerBaseProvisionError, "CURRENT_AND_EMPTY"):
            self.run_base()
        self.assertFalse(self.destination.exists())

    def test_nonnull_journal_refuses_without_recovery(self):
        self.state["effect_journal"] = {"status": "PENDING"}
        with self.assertRaises(Exception):
            self.run_base()
        self.assertFalse(self.destination.exists())

    def test_positive_floor_types_and_exact_schema_are_enforced(self):
        for key, value in (("minimum_revocation_generation", 0), ("minimum_mediator_health_epoch", True),
                           ("schema", "other"), ("authority", "HEALTHY"), ("extra", 1)):
            state = base_state() | {key: value}
            with self.subTest(key=key), self.assertRaises(Exception):
                self.run_base(base_state=state, base_state_digest=canonical_digest(state))
        self.assertFalse(self.destination.exists())

    def test_oversized_base_document_refuses_before_parser_or_mutation(self):
        self.state["extra"] = "x" * (subject.broker._MAX_CONTROL_BYTES + 1)
        with self.assertRaisesRegex(subject.PiBrokerBaseProvisionError, "PIN_MISMATCH"):
            self.run_base()
        self.assertFalse(self.destination.exists())

    def test_nonroot_or_nonlinux_refuses(self):
        with mock.patch.object(subject.provision.sys, "platform", "darwin"), self.assertRaises(Exception):
            self.run_base()
        with mock.patch.object(subject.provision.os, "geteuid", return_value=99999), self.assertRaises(Exception):
            self.run_base()
        self.assertFalse(self.destination.exists())

    def test_expired_or_extended_deadline_refuses(self):
        for deadline in (time.monotonic() - 1, time.monotonic() + 1000, float("nan"), True):
            with self.subTest(deadline=deadline), self.assertRaises(Exception):
                self.run_base(deadline=deadline)
        self.assertFalse(self.destination.exists())

    def test_existing_empty_destination_is_never_adopted(self):
        self.destination.mkdir()
        before = self.destination.stat().st_ino
        with self.assertRaisesRegex(subject.PiBrokerBaseProvisionError, "ALREADY_EXISTS") as caught:
            self.run_base()
        self.assertEqual(self.destination.stat().st_ino, before)
        self.assertFalse(self.record(caught.exception)["mutation_attempted"])

    def test_existing_file_or_symlink_is_not_followed_or_removed(self):
        target = self.fixture / "unrelated"
        target.write_bytes(b"preserve")
        self.destination.symlink_to(target)
        with self.assertRaisesRegex(subject.PiBrokerBaseProvisionError, "ALREADY_EXISTS"):
            self.run_base()
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(target.read_bytes(), b"preserve")

    def test_symlink_parent_refuses_without_destination(self):
        other = self.fixture / "actual-parent"
        self.base_parent.rename(other)
        self.base_parent.symlink_to(other, target_is_directory=True)
        with self.assertRaises(Exception) as caught:
            self.run_base()
        self.assertFalse((other / self.destination.name).exists())
        self.assertEqual(self.record(caught.exception)["status"], "CLEANUP_HOLD")

    def test_parent_replacement_before_mutation_refuses(self):
        changed = False
        def replace():
            nonlocal changed
            if not changed and self.base_parent.exists():
                changed = True
                self.base_parent.rename(self.fixture / "old-parent")
                self.base_parent.mkdir()
        original = subject.custody._open_chain
        def opened(*args):
            result = original(*args)
            replace()
            return result
        with mock.patch.object(subject.custody, "_open_chain", side_effect=opened), self.assertRaisesRegex(
                subject.PiBrokerBaseProvisionError, "PARENT_CHANGED") as caught:
            self.run_base()
        self.assertFalse(self.record(caught.exception)["mutation_attempted"])

    def test_exclusive_mkdir_race_preserves_competing_destination(self):
        original = os.mkdir
        def competing(name, *args, **kwargs):
            if name == self.destination.name:
                original(name, *args, **kwargs)
            return original(name, *args, **kwargs)
        with mock.patch.object(os, "mkdir", side_effect=competing), self.assertRaises(FileExistsError) as caught:
            self.run_base()
        self.assertTrue(self.destination.is_dir())
        self.assertEqual(self.record(caught.exception)["status"], "PARTIAL_OR_INDETERMINATE")

    def test_short_writes_are_completed_without_retrying_installation(self):
        original = os.write
        def short(fd, data):
            return original(fd, data[:max(1, len(data) // 2)])
        with mock.patch.object(os, "write", side_effect=short):
            result = self.run_base()
        self.assertEqual(result["status"], "INSTALLED")
        self.assertEqual((self.destination / "control/state.json").read_bytes(), canonical_json(self.state))

    def test_zero_write_preserves_partial_destination_and_original_error(self):
        with mock.patch.object(os, "write", return_value=0), self.assertRaises(subject.provision.PiOsProvisionError) as caught:
            self.run_base()
        result = self.record(caught.exception)
        self.assertEqual(result["status"], "PARTIAL_OR_INDETERMINATE")
        self.assertTrue(result["owned_handles_closed"])
        self.assertTrue((self.destination / "control/state.json").exists())
        with self.assertRaisesRegex(subject.PiBrokerBaseProvisionError, "ALREADY_EXISTS"):
            self.run_base()

    def test_cancellation_during_write_retains_original_and_no_retry(self):
        error = KeyboardInterrupt()
        with mock.patch.object(os, "write", side_effect=error), self.assertRaises(KeyboardInterrupt) as caught:
            self.run_base()
        self.assertIs(caught.exception, error)
        self.assertEqual(self.record(error)["status"], "PARTIAL_OR_INDETERMINATE")
        self.assertTrue(self.destination.exists())

    def test_changed_config_after_creation_keeps_partial_controls(self):
        def changed():
            if self.destination.exists():
                raise RuntimeError("inert changed configuration")
        with self.config_guard(changed), self.assertRaisesRegex(RuntimeError, "inert changed") as caught:
            self.run_base()
        self.assertEqual(self.record(caught.exception)["status"], "PARTIAL_OR_INDETERMINATE")
        self.assertTrue(self.destination.exists())

    def test_readback_bytes_substitution_refuses(self):
        original = os.open
        def changed(name, flags, *args, **kwargs):
            if name == "state.json" and flags == subject.provision._FILE:
                path = self.destination / "control/state.json"
                path.chmod(0o600)
                path.write_bytes(b"changed")
                path.chmod(0o400)
            return original(name, flags, *args, **kwargs)
        with mock.patch.object(os, "open", side_effect=changed), self.assertRaisesRegex(
                subject.PiBrokerBaseProvisionError, "READBACK_CHANGED") as caught:
            self.run_base()
        self.assertIn("broker.lock", self.record(caught.exception)["readback"]["files"])
        self.assertNotIn("state.json", self.record(caught.exception)["readback"]["files"])

    def test_extra_control_or_protected_member_refuses(self):
        original = subject.custody._exact_names
        created = False
        def extra(fd, expected, deadline):
            nonlocal created
            if not created and self.destination.exists():
                created = True
                (self.destination / "control/policy.json").write_bytes(b"not authority")
            return original(fd, expected, deadline)
        with mock.patch.object(subject.custody, "_exact_names", side_effect=extra), self.assertRaises(Exception) as caught:
            self.run_base()
        self.assertEqual(self.record(caught.exception)["status"], "PARTIAL_OR_INDETERMINATE")

    def test_deadline_failure_after_mutation_does_not_remove_output(self):
        original = subject.provision._write_all
        def write(*args):
            original(*args)
            raise TimeoutError("inert deadline")
        with mock.patch.object(subject.provision, "_write_all", side_effect=write), self.assertRaises(TimeoutError) as caught:
            self.run_base()
        self.assertEqual(self.record(caught.exception)["status"], "PARTIAL_OR_INDETERMINATE")
        self.assertTrue(self.destination.exists())

    def test_owned_close_failure_is_not_retried_or_called_success(self):
        original = os.close
        closed, failed = [], False
        real_open, owned_readers = os.open, set()
        def opened(name, flags, *args, **kwargs):
            fd = real_open(name, flags, *args, **kwargs)
            if name in ("broker.lock", "state.json") and flags == subject.provision._FILE:
                owned_readers.add(fd)
            return fd
        def close(fd):
            nonlocal failed
            original(fd)
            if fd in owned_readers:
                closed.append(fd)
                if not failed:
                    failed = True
                    raise OSError("inert uncertain close")
        with mock.patch.object(os, "open", side_effect=opened), mock.patch.object(os, "close", side_effect=close), \
                self.assertRaises(OSError) as caught:
            self.run_base()
        result = self.record(caught.exception)
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertFalse(result["owned_handles_closed"])
        self.assertTrue(result["cleanup_uncertainty"])
        self.assertEqual(len(closed), len(set(closed)))

    def test_primary_cancellation_survives_close_failure(self):
        error, original = KeyboardInterrupt(), os.close
        failed = False
        def close(fd):
            nonlocal failed
            original(fd)
            if not failed and self.destination.exists():
                failed = True
                raise OSError("inert close")
        with mock.patch.object(os, "write", side_effect=error), mock.patch.object(os, "close", side_effect=close), \
                self.assertRaises(KeyboardInterrupt) as caught:
            self.run_base()
        self.assertIs(caught.exception, error)
        self.assertEqual(self.record(error)["status"], "CLEANUP_HOLD")

    def test_file_creation_is_exclusive_nofollow_and_descriptor_relative(self):
        original, seen = os.open, []
        def opening(name, flags, *args, **kwargs):
            if name in ("broker.lock", "state.json") and flags & os.O_CREAT:
                seen.append(name)
                self.assertTrue(flags & os.O_EXCL and flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC)
                self.assertIs(type(kwargs.get("dir_fd")), int)
            return original(name, flags, *args, **kwargs)
        with mock.patch.object(os, "open", side_effect=opening):
            self.run_base()
        self.assertEqual(seen, ["broker.lock", "state.json"])


def load_tests(loader, tests, pattern):
    # Inherited configuration tests are fixture code, not a redundant suite.
    return unittest.TestSuite(BaseProvisionTests(name) for name in sorted(BaseProvisionTests.__dict__)
                              if name.startswith("test_"))
