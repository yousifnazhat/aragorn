"""Explicit broker preparation only, with inert process and filesystem seams.

Existing codecs and owned lifecycle control flow are exercised without starting
units, accepting sockets, provisioning controls or executing the initializer.
Only new methods and named affected cases are selected at the end of this file.
"""

import copy
import os
import socket
import stat
import unittest
from unittest import mock

from aragorn import pi_core_service_lifecycle as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_service_consumption as sources
from tests import test_pi_core_service_lifecycle as fixtures


def base_state():
    return {"schema": "aragorn/runtime-action-broker-state/v2",
        "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "minimum_revocation_generation": 1, "minimum_mediator_health_epoch": 1,
        "consumed": [], "effect_journal": None}


def available(grant):
    return {"schema": "aragorn/runtime-capability-grant-state/v1",
        "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "grant_digest": canonical_digest(grant), "status": "AVAILABLE", "claim": None, "result": None}


class NormalSourceFixture(sources.LifecycleSourceTests):
    def setUp(self):
        super().setUp()
        self.stack.enter_context(mock.patch.object(subject.time, "monotonic_ns", return_value=100_000_000_000))

    def source_message(self, connection, message, deadline, **options):
        if message.get("schema") != subject.entry.ACTION_START_SCHEMA:
            return super().source_message(connection, message, deadline, **options)
        self.assertEqual((deadline, options), (120.0, {"max_bytes": 65536}))
        self.source_sent.append(copy.deepcopy(message))
        self.events.append(message["kind"] + "-action")


class PreparationTests(NormalSourceFixture):
    def setUp(self):
        super().setUp()
        self.preparation_result = {
            "schema": "aragorn/pi-core-request-service-preparation/v1",
            "authority": "DURABLE_GRANT_PREPARATION_NOT_ADMISSION_OR_SERVICE_READINESS",
            "status": "AVAILABLE", "grant_digest": canonical_digest(self.grant),
            "state_digest": canonical_digest(available(self.grant)), "activation_performed": False,
            "service_ready": False, "phase3_exit_eligible": False}
        self.result_change, self.snapshot_change = lambda value: value, lambda value: value
        self.owner = None
        self.stop_failure = None
        self.prepare_modes = []
        self.stack.enter_context(mock.patch.object(subject.PiServiceLifecycle, "_prepare",
            lambda held, **options: self.prepare_scope(held, **options)))
        self.snapshot = self.stack.enter_context(mock.patch.object(subject, "_broker_control_snapshot",
            side_effect=self.control_snapshot))
        self.initializer = self.stack.enter_context(mock.patch.object(subject.entry.action,
            "initialize_pi_broker_request_service", side_effect=AssertionError("root cannot initialize action authority")))
        self.stack.enter_context(mock.patch.object(subject.PiServiceLifecycle, "_stop",
            lambda held, service: self.stop_owned(held, service)))

    def stop_owned(self, held, service):
        if self.stop_failure is not None and service.start_attempted:
            raise self.stop_failure
        if service.start_attempted and not service.started:
            # Exercise the existing unknown-start refusal, not the ordinary
            # inert fixture's synthetic successful-stop observation.
            return self.real_stop(held, service)
        return self.stop_service(held, service)

    def prepare_scope(self, held, *, action_only=False):
        self.owner = held
        self.prepare_modes.append(action_only)
        self.events.append("prepare")
        held._fds[subject._ACTION] = 501
        held._identities[subject._ACTION] = (1, 500, stat.S_IFDIR | 0o750, 1201, 1301)
        for index, (role, service) in enumerate(held.services.items()):
            if action_only and role != "action":
                continue
            subject._plan(service, held)
            service.listener = fixtures.InertSocket(fd=70 + index)
            service.listener.accepted = fixtures.InertSocket((8001 + index, service.uid, service.gid), 80 + index)

    def control_snapshot(self, configs, deadline, *, require_available):
        self.assertEqual((configs, deadline), (self.config.configurations, 120.0))
        self.events.append("readback" if require_available else "preflight")
        result = {"schema": "aragorn/pi-core-broker-control-readback/v1",
            "status": "AVAILABLE_READBACK" if require_available else "PREINSTALLED_CONTROLS_ONLY",
            "grant_digest": canonical_digest(self.grant), "base_state": base_state(),
            "base_state_digest": canonical_digest(base_state()),
            "grant_state": available(self.grant) if require_available else None,
            "state_digest": canonical_digest(available(self.grant)) if require_available else None,
            "root_identities": {"control": [1, 101], "protected": [1, 102], "staging": [1, 103]},
            "read_only": True, "owned_handles_closed": True, "reader_cleanup_unknown": False}
        return self.snapshot_change(result) if require_available else result

    def source_reply(self, connection, peer, deadline, **options):
        latest = self.source_sent[-1]
        if latest.get("schema") != subject.entry.ACTION_START_SCHEMA:
            return super().source_reply(connection, peer, deadline, **options)
        self.assertEqual((connection.peer, deadline, options),
                         (peer, 120.0, {"expected_rights": 0, "max_bytes": 65536}))
        self.events.append("PREPARED-action")
        return self.result_change({**latest, "kind": "PREPARED", "result": copy.deepcopy(self.preparation_result)}), ()

    def run_preparation(self, **changes):
        return subject.prepare_native_pi_broker_control(**({"deployment": self.runtime,
            "configuration": self.config, "provider_inputs": self.public, "binding": self.binding,
            "deadline": 125.0} | changes))

    def test_only_action_starts_and_preparation_is_not_normal_readiness(self):
        result = self.run_preparation()
        self.assertEqual(self.prepare_modes, [True])
        self.assertEqual([event for event in self.events if event.startswith("capture-")], ["capture-action"])
        self.assertEqual(self.command.call_count, 1)
        self.assertIn("--unit=aragorn-pi-action.service", self.command.call_args.args[0])
        self.readiness.assert_not_called()
        self.listener.assert_not_called()
        self.channels.assert_not_called()
        self.initializer.assert_not_called()
        self.assertEqual(result["status"], "CLOSED")
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertFalse(result["units"]["sensor"]["process_exit_and_cgroup_cleanup"])
        self.assertFalse(result["units"]["provider"]["process_exit_and_cgroup_cleanup"])

    def test_source_command_result_readback_ack_and_cleanup_are_ordered(self):
        result = self.run_preparation()
        order = ["preflight", "ACCEPTED-action", "PREPARE_GRANT-action", "PREPARED-action", "readback", "ACK-action", "stop-action"]
        self.assertEqual([self.events.index(event) for event in order], sorted(self.events.index(event) for event in order))
        preparation = result["broker_preparation"]
        self.assertEqual((preparation["status"], preparation["phase"]), ("PREPARED", "COMPLETE"))
        self.assertTrue(preparation["command_attempted"])
        self.assertTrue(preparation["ack_attempted"])
        self.assertTrue(preparation["ack_sent"])
        self.assertEqual(set(result["trusted_source_startup"]), {"action"})
        self.assertFalse(result["credential_read"])
        self.assertFalse(result["provider_dispatched"])
        self.assertFalse(result["phase3_exit_eligible"])
        self.assertFalse(preparation["phase3_exit_eligible"])

    def test_exact_command_and_ack_bind_configuration_grant_result_and_budget(self):
        result = self.run_preparation()
        command = result["broker_preparation"]["command"]
        self.assertEqual(command, {"schema": subject.entry.ACTION_START_SCHEMA, "kind": "PREPARE_GRANT",
            "nonce": "a" * 64, "configuration_digest": canonical_digest(self.config.configurations["action"]),
            "grant_digest": canonical_digest(self.grant), "deadline_ns": 120_000_000_000})
        self.assertEqual(self.source_sent[-1], {**command, "kind": "ACK",
            "result_digest": canonical_digest(self.preparation_result)})
        self.assertEqual(self.owner.deadline, 125.0)
        self.assertEqual(self.owner.operation_deadline, 120.0)

    def test_result_and_actual_raw_control_readback_are_retained(self):
        result = self.run_preparation()
        record = result["broker_preparation"]
        self.assertEqual(record["result_packet"]["result"], self.preparation_result)
        self.assertEqual(record["readback"]["grant_state"], available(self.grant))
        self.assertEqual(record["preflight"]["base_state"], base_state())
        self.assertIsNone(record["preflight"]["grant_state"])
        record["readback"]["grant_state"]["status"] = "forged"
        self.assertEqual(self.owner.observation["broker_preparation"]["readback"]["grant_state"]["status"], "AVAILABLE")

    def test_existing_any_fixed_unit_refuses_before_resources(self):
        self.state.side_effect = lambda role, deadline: (
            {**self.absent(), "LoadState": "loaded", "ActiveState": "active", "MainPID": "42"}
            if role == "sensor" else self.absent())
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.run_preparation()
        self.command.assert_not_called()
        self.snapshot.assert_not_called()
        self.assertEqual(raised.exception.pi_service_lifecycle_observation["broker_preparation"]["status"], "REFUSED")

    def test_missing_preinstalled_controls_never_start_or_initialize(self):
        failure = FileNotFoundError("missing controlled root")
        self.snapshot.side_effect = failure
        with self.assertRaises(FileNotFoundError) as raised:
            self.run_preparation()
        self.assertIs(raised.exception, failure)
        self.command.assert_not_called()
        self.initializer.assert_not_called()
        self.assertEqual(raised.exception.pi_service_lifecycle_observation["broker_preparation"]["phase"], "PREINSTALLED_CONTROLS")

    def test_source_handshake_failure_never_sends_preparation_command(self):
        self.receipt_change = lambda value: {**value, "nonce": "b" * 64}
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.run_preparation()
        record = raised.exception.pi_service_lifecycle_observation["broker_preparation"]
        self.assertFalse(record["command_attempted"])
        self.assertNotIn("PREPARE_GRANT-action", self.events)
        self.assertEqual(self.source_receive.call_count, 1)

    def test_missing_source_enabled_image_or_grant_binding_refuses_before_start(self):
        del self.runtime.binding["source_digests"]
        with self.assertRaises(subject.PiServiceLifecycleError):
            self.run_preparation()
        self.command.assert_not_called()
        self.snapshot.assert_not_called()

    def test_wrong_bound_runtime_cannot_prepare_configured_grant(self):
        wrong = subject.channels.RuntimeActionWorkerBinding("sha256:" + "0" * 64,
            self.binding.active_skill_digest, self.binding.policy_digest, self.binding.policy_version)
        with self.assertRaises(subject.PiServiceLifecycleError):
            self.run_preparation(binding=wrong)
        self.command.assert_not_called()

    def test_unknown_service_start_outcome_is_not_automatically_stopped_or_retried(self):
        self.command.return_value = (1, b"")
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.run_preparation()
        self.command.assert_called_once()
        self.assertFalse(self.owner.services["action"].started)
        self.assertTrue(self.owner.services["action"].start_attempted)
        self.assertFalse(raised.exception.pi_service_lifecycle_observation["broker_preparation"]["command_attempted"])
        self.assertEqual(raised.exception.pi_service_lifecycle_observation["status"], "CLEANUP_HOLD")

    def test_uncertain_preparation_send_retains_attempt_and_original_error(self):
        failure = OSError("preparation send uncertain")
        original = self.source_send.side_effect

        def send(connection, packet, deadline, **options):
            original(connection, packet, deadline, **options)
            if packet["kind"] == "PREPARE_GRANT":
                raise failure

        self.source_send.side_effect = send
        with self.assertRaises(OSError) as raised:
            self.run_preparation()
        self.assertIs(raised.exception, failure)
        record = failure.pi_service_lifecycle_observation["broker_preparation"]
        self.assertTrue(record["command_attempted"])
        self.assertEqual(record["status"], "INDETERMINATE")
        self.assertEqual(self.events.count("PREPARE_GRANT-action"), 1)
        self.assertFalse(record["ack_attempted"])

    def test_foreign_prepared_nonce_is_retained_but_never_acknowledged(self):
        self.result_change = lambda value: {**value, "nonce": "b" * 64}
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.run_preparation()
        record = raised.exception.pi_service_lifecycle_observation["broker_preparation"]
        self.assertEqual(record["result_packet"]["nonce"], "b" * 64)
        self.assertIsNone(record["readback"])
        self.assertFalse(record["ack_attempted"])

    def test_terminal_initializer_result_is_preserved_without_availability_claim(self):
        self.preparation_result["status"] = "CONSUMED"
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.run_preparation()
        record = raised.exception.pi_service_lifecycle_observation["broker_preparation"]
        self.assertEqual(record["result_packet"]["result"]["status"], "CONSUMED")
        self.assertFalse(record["ack_attempted"])
        self.assertEqual(self.snapshot.call_count, 1)

    def test_independent_state_digest_mismatch_prevents_ack(self):
        self.snapshot_change = lambda value: {**value, "state_digest": "sha256:" + "0" * 64}
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.run_preparation()
        self.assertFalse(raised.exception.pi_service_lifecycle_observation["broker_preparation"]["ack_attempted"])
        self.assertNotIn("ACK-action", self.events)

    def test_changed_control_root_or_base_state_prevents_ack(self):
        self.snapshot_change = lambda value: {**value, "root_identities": {"control": [1, 999]}}
        with self.assertRaises(subject.PiServiceLifecycleError):
            self.run_preparation()
        self.assertNotIn("ACK-action", self.events)

    def test_changed_base_state_despite_matching_grant_is_not_preparation(self):
        self.snapshot_change = lambda value: {**value, "base_state": {**base_state(), "minimum_revocation_generation": 2}}
        with self.assertRaises(subject.PiServiceLifecycleError):
            self.run_preparation()
        self.assertNotIn("ACK-action", self.events)

    def test_uncertain_ack_send_is_once_and_not_prepared(self):
        failure = TimeoutError("ACK uncertain")
        original = self.source_send.side_effect

        def send(connection, packet, deadline, **options):
            original(connection, packet, deadline, **options)
            if packet["kind"] == "ACK":
                raise failure

        self.source_send.side_effect = send
        with self.assertRaises(TimeoutError) as raised:
            self.run_preparation()
        self.assertIs(raised.exception, failure)
        record = failure.pi_service_lifecycle_observation["broker_preparation"]
        self.assertTrue(record["ack_attempted"])
        self.assertFalse(record["ack_sent"])
        self.assertEqual(record["status"], "INDETERMINATE")
        self.assertEqual(self.events.count("ACK-action"), 1)

    def test_cancelled_result_wait_preserves_original_and_owned_cleanup(self):
        failure = KeyboardInterrupt("cancelled preparation")
        original = self.source_receive.side_effect

        def receive(*args, **options):
            if self.source_sent[-1]["kind"] == "PREPARE_GRANT":
                raise failure
            return original(*args, **options)

        self.source_receive.side_effect = receive
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.run_preparation()
        self.assertIs(raised.exception, failure)
        record = failure.pi_service_lifecycle_observation
        self.assertEqual(record["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(record["broker_preparation"]["status"], "INDETERMINATE")
        self.assertFalse(record["broker_preparation"]["ack_attempted"])

    def test_cleanup_failure_never_returns_prepared(self):
        self.stop_failure = RuntimeError("owned unit cleanup uncertain")
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.run_preparation()
        record = raised.exception.pi_service_lifecycle_observation
        self.assertEqual(record["status"], "CLEANUP_HOLD")
        self.assertEqual(record["broker_preparation"]["status"], "CLEANUP_HOLD")
        self.assertTrue(record["broker_preparation"]["ack_sent"])

    def test_original_result_error_survives_secondary_cleanup_failure(self):
        failure = OSError("result unavailable")
        original = self.source_receive.side_effect

        def receive(*args, **options):
            if self.source_sent[-1]["kind"] == "PREPARE_GRANT":
                raise failure
            return original(*args, **options)

        self.source_receive.side_effect = receive
        self.stop_failure = RuntimeError("secondary cleanup uncertainty")
        with self.assertRaises(OSError) as raised:
            self.run_preparation()
        self.assertIs(raised.exception, failure)
        self.assertEqual(failure.pi_service_lifecycle_observation["cleanup"]["status"], "CLEANUP_HOLD")

    def test_snapshot_cleanup_hold_survives_verified_service_cleanup(self):
        snapshot = self.control_snapshot(self.config.configurations, 120.0, require_available=False)
        snapshot.update(status="CLEANUP_HOLD", owned_handles_closed=False)
        failure = subject.PiServiceLifecycleError("snapshot cleanup uncertain")
        failure.pi_broker_control_snapshot = snapshot
        self.snapshot.side_effect = failure
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.run_preparation()
        self.assertIs(raised.exception, failure)
        record = failure.pi_service_lifecycle_observation
        self.assertEqual(record["status"], "CLEANUP_HOLD")
        self.assertEqual(record["cleanup"], {"status": "CLEANUP_HOLD", "scope": "BROKER_CONTROL_HANDLES",
                                           "service_resources": "VERIFIED_OWNED_CLEANUP"})
        self.assertEqual(record["broker_preparation"]["status"], "CLEANUP_HOLD")

    def test_readback_error_plus_unknown_reader_cleanup_retains_raw_result_and_hold(self):
        failure = OSError("primary readback failure")
        original = self.snapshot.side_effect

        def snapshot(*args, **options):
            value = original(*args, **options)
            if options["require_available"]:
                value.update(status="CLEANUP_HOLD", owned_handles_closed=False, reader_cleanup_unknown=True)
                failure.pi_broker_control_snapshot = value
                raise failure
            return value

        self.snapshot.side_effect = snapshot
        with self.assertRaises(OSError) as raised:
            self.run_preparation()
        self.assertIs(raised.exception, failure)
        record = failure.pi_service_lifecycle_observation
        self.assertEqual(record["broker_preparation"]["result_packet"]["result"], self.preparation_result)
        self.assertEqual(record["status"], "CLEANUP_HOLD")
        self.assertFalse(record["broker_preparation"]["ack_attempted"])

    def test_original_deadline_expiry_blocks_before_ack_and_is_not_renewed(self):
        original = self.snapshot.side_effect

        def snapshot(*args, **options):
            value = original(*args, **options)
            if options["require_available"]:
                self.stack.enter_context(mock.patch.object(subject.time, "monotonic", return_value=121.0))
            return value

        self.snapshot.side_effect = snapshot
        with self.assertRaises(RuntimeError):
            self.run_preparation()
        self.assertNotIn("ACK-action", self.events)
        self.assertEqual(self.owner.operation_deadline, 120.0)

    def test_normal_source_enabled_path_sends_run_before_action_listener(self):
        with self.hold():
            pass
        self.assertEqual(self.prepare_modes, [False])
        self.assertLess(self.events.index("ACCEPTED-action"), self.events.index("RUN_REQUEST-action"))
        self.assertLess(self.events.index("RUN_REQUEST-action"), self.events.index("action-LISTEN"))
        self.assertNotIn("PREPARE_GRANT-action", self.events)
        self.initializer.assert_not_called()
        self.assertEqual(self.readiness.call_count, 1)

    def test_action_command_is_one_shot_and_has_no_generic_selector(self):
        self.run_preparation()
        with self.assertRaises(subject.PiServiceLifecycleError):
            self.owner._action_start("RUN_REQUEST")
        with self.assertRaises(subject.PiServiceLifecycleError):
            self.owner._action_start("SHELL")
        self.assertEqual(self.events.count("PREPARE_GRANT-action"), 1)

    def test_actual_action_only_preparation_omits_other_service_skeletons(self):
        held = self.instance()
        directories, sockets = [], []

        def mkdir(owner, path, uid=0, gid=0, mode=0o755):
            directories.append(path)
            owner._fds[path] = 300 + len(directories)
            owner._created.append(path)
            owner._identities[path] = subject.broker._directory_identity(
                fixtures.metadata(300 + len(directories), stat.S_IFDIR | mode, uid, gid))

        def socket_factory(*args):
            value = fixtures.InertSocket(fd=100 + len(sockets))
            sockets.append(value)
            return value

        with mock.patch.object(subject.lineage, "_open_protected_root", return_value=200), \
             mock.patch.object(subject.PiServiceLifecycle, "_mkdir", mkdir), \
             mock.patch.object(os, "open", return_value=400), \
             mock.patch.object(os, "fstat", side_effect=lambda fd: fixtures.metadata(200) if fd == 200 else
                               fixtures.metadata(400, stat.S_IFREG | 0o444)), \
             mock.patch.object(os, "fchmod"), mock.patch.object(os, "chown"), mock.patch.object(os, "chmod"), \
             mock.patch.object(os, "stat", return_value=fixtures.metadata(900, stat.S_IFSOCK | 0o660, 0, 1301)), \
             mock.patch.object(socket, "socket", side_effect=socket_factory):
            self.real_prepare(held, action_only=True)
        self.assertEqual((len(sockets), len(held._files)), (1, 1))
        self.assertTrue(held.services["action"].argv)
        for role in ("sensor", "provider"):
            self.assertNotIn(subject._ROOT / role, directories)
            self.assertNotIn(held.services[role].root, directories)
            self.assertIsNone(held.services[role].listener)
            self.assertEqual(held.services[role].argv, ())
        self.command.assert_not_called()


class ControlSnapshotTests(fixtures.PiServiceLifecycleTests):
    def setUp(self):
        super().setUp()
        self.roots = {101: fixtures.metadata(1, stat.S_IFDIR | 0o710, 1201, 1301),
            102: fixtures.metadata(2, stat.S_IFDIR | 0o710, 1201, 1301),
            103: fixtures.metadata(3, stat.S_IFDIR | 0o700, 1201, 1301),
            104: fixtures.metadata(4, stat.S_IFREG | 0o600, 1201, 1301)}
        self.open_roots = self.stack.enter_context(mock.patch.object(subject.broker,
            "_open_protected_directory", side_effect=[101, 102, 103]))
        self.open_lock = self.stack.enter_context(mock.patch.object(os, "open", return_value=104))
        self.stack.enter_context(mock.patch.object(os, "fstat", side_effect=lambda fd: self.roots[fd]))
        self.stack.enter_context(mock.patch.object(os, "stat", return_value=self.roots[104]))
        self.named = self.stack.enter_context(mock.patch.object(os, "lstat",
            side_effect=[self.roots[101], self.roots[102], self.roots[103]]))
        self.lock = self.stack.enter_context(mock.patch.object(subject.fcntl, "flock"))
        self.read = self.stack.enter_context(mock.patch.object(subject, "_read_at",
            side_effect=[canonical_json(base_state()), canonical_json(available(self.grant))]))
        self.missing = self.stack.enter_context(mock.patch.object(subject.native, "_missing", return_value=True))
        self.close_handles = self.stack.enter_context(mock.patch.object(subject.transport, "_close_installed"))

    def snapshot(self, require_available=False):
        return subject._broker_control_snapshot(self.config.configurations, 120.0, require_available=require_available)

    def test_preflight_reads_only_existing_base_state_and_does_not_demand_grant(self):
        result = self.snapshot()
        self.assertEqual(result["status"], "PREINSTALLED_CONTROLS_ONLY")
        self.assertEqual(result["base_state"], base_state())
        self.assertIsNone(result["grant_state"])
        self.assertTrue(result["owned_handles_closed"])
        self.read.assert_called_once_with(101, "state.json", 1201, 120.0)
        self.missing.assert_not_called()
        self.close_handles.assert_called_once_with([104, 103, 102, 101])
        self.assertFalse(self.open_lock.call_args.args[1] & os.O_CREAT)

    def test_positive_readback_requires_existing_available_and_all_current_absences(self):
        result = self.snapshot(True)
        self.assertEqual(result["status"], "AVAILABLE_READBACK")
        self.assertEqual(result["grant_state"], available(self.grant))
        self.assertEqual(result["state_digest"], canonical_digest(result["grant_state"]))
        self.assertEqual(self.missing.call_count, 4)
        self.assertEqual(self.lock.call_args_list, [mock.call(104, subject.fcntl.LOCK_EX | subject.fcntl.LOCK_NB),
                                                   mock.call(104, subject.fcntl.LOCK_UN)])

    def test_pending_or_archived_authority_cannot_become_positive_readback(self):
        self.missing.return_value = False
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.snapshot(True)
        self.assertEqual(raised.exception.pi_broker_control_snapshot["grant_state"], available(self.grant))
        self.assertTrue(raised.exception.pi_broker_control_snapshot["owned_handles_closed"])

    def test_terminal_grant_state_is_retained_and_never_rewritten_available(self):
        terminal = {**available(self.grant), "status": "ABANDONED"}
        self.read.side_effect = [canonical_json(base_state()), canonical_json(terminal)]
        with self.assertRaises(RuntimeError) as raised:
            self.snapshot(True)
        self.assertEqual(raised.exception.pi_broker_control_snapshot["grant_state"], terminal)
        self.assertEqual(self.read.call_count, 2)

    def test_missing_root_refuses_without_provisioning_or_lock_creation(self):
        self.open_roots.side_effect = FileNotFoundError("missing root")
        with self.assertRaises(FileNotFoundError):
            self.snapshot()
        self.open_lock.assert_not_called()
        self.read.assert_not_called()

    def test_wrong_root_owner_mode_or_cross_device_refuses_preflight(self):
        self.roots[103] = fixtures.metadata(3, stat.S_IFDIR | 0o755, 1201, 1301)
        with self.assertRaises(subject.PiServiceLifecycleError):
            self.snapshot()
        self.open_lock.assert_not_called()

    def test_named_root_substitution_refuses_and_preserves_closed_handle_accounting(self):
        self.named.side_effect = [fixtures.metadata(99, stat.S_IFDIR | 0o710, 1201, 1301)]
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            self.snapshot()
        self.assertTrue(raised.exception.pi_broker_control_snapshot["owned_handles_closed"])

    def test_busy_existing_lock_is_not_retried(self):
        self.lock.side_effect = BlockingIOError("held by another operation")
        with self.assertRaises(BlockingIOError):
            self.snapshot()
        self.lock.assert_called_once()
        self.read.assert_not_called()
        self.close_handles.assert_called_once()

    def test_existing_reader_failure_keeps_unknown_inner_cleanup_without_retry(self):
        failure = OSError("existing reader close or read failure")
        self.read.side_effect = failure
        with self.assertRaises(OSError) as raised:
            self.snapshot()
        self.assertIs(raised.exception, failure)
        record = failure.pi_broker_control_snapshot
        self.assertTrue(record["reader_cleanup_unknown"])
        self.assertFalse(record["owned_handles_closed"])
        self.assertEqual(record["status"], "CLEANUP_HOLD")
        self.read.assert_called_once()
        self.close_handles.assert_called_once()

    def test_failed_root_acquisition_retains_unknown_inner_cleanup_without_retry(self):
        failure = OSError("existing directory acquisition or close failed")
        self.open_roots.side_effect = failure
        with self.assertRaises(OSError) as raised:
            self.snapshot()
        self.assertIs(raised.exception, failure)
        record = failure.pi_broker_control_snapshot
        self.assertTrue(record["acquisition_cleanup_unknown"])
        self.assertFalse(record["owned_handles_closed"])
        self.assertEqual(record["status"], "CLEANUP_HOLD")
        self.open_roots.assert_called_once()
        self.close_handles.assert_called_once_with([])

    def test_original_parse_error_survives_secondary_snapshot_cleanup_failure(self):
        self.read.side_effect = [b"not-json"]
        self.close_handles.side_effect = OSError("secondary close failure")
        with self.assertRaises(RuntimeError) as raised:
            self.snapshot()
        self.assertNotEqual(str(raised.exception), "readiness handle cleanup uncertain")
        record = raised.exception.pi_broker_control_snapshot
        self.assertFalse(record["owned_handles_closed"])
        self.assertFalse(record["reader_cleanup_unknown"])
        self.assertEqual(record["status"], "CLEANUP_HOLD")

    def test_snapshot_cleanup_failure_never_returns_a_successful_snapshot(self):
        self.close_handles.side_effect = OSError("owned descriptors uncertain")
        with self.assertRaisesRegex(subject.PiServiceLifecycleError, "cleanup uncertain") as raised:
            self.snapshot()
        self.assertEqual(raised.exception.pi_broker_control_snapshot["base_state"], base_state())
        self.assertFalse(raised.exception.pi_broker_control_snapshot["owned_handles_closed"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for case in (PreparationTests, ControlSnapshotTests):
        suite.addTests(case(name) for name in sorted(case.__dict__) if name.startswith("test_"))
    for name in ("test_readiness_requires_explicit_available_without_recovery_writes",
                 "test_readiness_missing_control_root_does_not_initialize_or_retry"):
        suite.addTest(fixtures.PiServiceLifecycleTests(name))
    for name in ("test_receipts_join_exact_captured_process_and_precede_readiness",
                 "test_wrong_receipt_binding_never_acks_or_starts_sensor"):
        suite.addTest(NormalSourceFixture(name))
    return suite


if __name__ == "__main__":
    unittest.main()
