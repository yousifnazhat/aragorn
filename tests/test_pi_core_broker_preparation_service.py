"""Fixed action preparation dispatch with inert service/filesystem edges only."""

import copy
import io
import math
import os
import unittest
from unittest import mock

from aragorn import pi_core_service_entry as subject
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_service_entry as fixtures


def command(configuration, *, kind="PREPARE_GRANT", deadline_ns=104_000_000_000):
    return dict(schema=subject.ACTION_START_SCHEMA, kind=kind, nonce="c" * 64,
        configuration_digest=canonical_digest(configuration),
        grant_digest=canonical_digest(configuration["capability_grant"]), deadline_ns=deadline_ns)


def preparation(configuration, *, status="AVAILABLE"):
    return dict(schema="aragorn/pi-core-request-service-preparation/v1",
        authority="DURABLE_GRANT_PREPARATION_NOT_ADMISSION_OR_SERVICE_READINESS", status=status,
        grant_digest=canonical_digest(configuration["capability_grant"]), state_digest="sha256:" + "d" * 64,
        activation_performed=False, service_ready=False, phase3_exit_eligible=False)


class PreparationServiceTests(fixtures.PiServiceEntryTests):
    def setUp(self):
        super().setUp()
        self.loader = object()
        self.command = command(self.value)
        self.preparation = preparation(self.value)
        self.acknowledgment = None
        self.sent, self.received = [], []
        self.handshake = self.stack.enter_context(mock.patch.object(subject, "_source_handshake",
            side_effect=lambda *_: self.events.append(("source_handshake",))))
        self.initialize = self.stack.enter_context(mock.patch.object(subject.action,
            "initialize_pi_broker_request_service", side_effect=self.initialize_control))
        self.receive = self.stack.enter_context(mock.patch.object(subject.channel,
            "receive_authenticated_packet", side_effect=self.receive_packet))
        self.send = self.stack.enter_context(mock.patch.object(subject.channel,
            "send_authenticated_packet", side_effect=self.send_packet))
        for name in ("setuid", "seteuid", "setgid", "setegid", "setgroups"):
            self.stack.enter_context(mock.patch.object(os, name, create=True,
                side_effect=AssertionError("service entry must not substitute its identity")))

    def initialize_control(self, config, *, deadline):
        self.events.append(("initialize",))
        self.assertEqual((os.getuid(), os.geteuid(), os.getgid(), os.getegid()), (1201, 1201, 1301, 1301))
        self.assertIs(type(config), subject.broker_v5.RuntimeActionBrokerV5Config)
        self.assertEqual(config.broker.broker.broker.expected_broker_uid, 1201)
        self.assertEqual(config.broker.capability_grant, subject.canonical_json(self.value["capability_grant"]))
        self.assertLess(deadline, self.command["deadline_ns"] / 1_000_000_000)
        self.assertEqual(deadline, math.nextafter(self.command["deadline_ns"] / 1_000_000_000, 0.0))
        return copy.deepcopy(self.preparation)

    def receive_packet(self, root, peer, deadline, **options):
        self.assertEqual(peer, (9000, 0, 0))
        self.assertEqual(options, {"expected_rights": 0, "max_bytes": subject.SOURCE_PACKET_LIMIT})
        self.received.append((root, deadline))
        self.events.append(("receive", len(self.received)))
        if len(self.received) == 1:
            return copy.deepcopy(self.command), ()
        self.assertEqual(len(self.received), 2)
        self.assertEqual(len(self.sent), 1)
        self.assertIs(root, self.sent[0][0])
        self.assertEqual(deadline, self.sent[0][2])
        if isinstance(self.acknowledgment, BaseException):
            raise self.acknowledgment
        result = self.acknowledgment if self.acknowledgment is not None else {
            **self.command, "kind": "ACK", "result_digest": canonical_digest(self.preparation)}
        return copy.deepcopy(result), ()

    def send_packet(self, root, packet, deadline, **options):
        self.assertEqual(options, {"max_bytes": subject.SOURCE_PACKET_LIMIT})
        self.events.append(("PREPARED",))
        self.sent.append((root, copy.deepcopy(packet), deadline))

    def run_preparation(self):
        return subject.run("action", ["9000", "105000000000"], source_loader=self.loader)

    def assert_no_request_dispatch(self):
        self.action.assert_not_called()
        self.sensor.assert_not_called()
        self.provider.assert_not_called()
        self.provider_profile.assert_not_called()
        self.assertFalse(any(event[0] in {"listen", "bind", "accept"} for event in self.events))
        self.assertNotIn(str(subject.ACTION_SOCKET), self.files)

    def assert_owned_cleanup(self):
        self.assertFalse(self.fds)
        self.assertTrue(all(connection.closed for connection in self.sockets))

    def test_verified_prepare_initializes_once_under_action_identity_without_listener(self):
        result = self.run_preparation()
        self.assertEqual(result, self.preparation)
        self.initialize.assert_called_once()
        self.handshake.assert_called_once()
        self.assertEqual(len(self.sockets), 1)
        self.assertEqual(len(self.received), 2)
        self.assertEqual(self.sent[0][1], {**self.command, "kind": "PREPARED", "result": self.preparation})
        self.assertLess(self.events.index(("source_handshake",)), self.events.index(("receive", 1)))
        self.assertLess(self.events.index(("receive", 1)), self.events.index(("initialize",)))
        self.assertLess(self.events.index(("initialize",)), self.events.index(("PREPARED",)))
        self.assertLess(self.events.index(("PREPARED",)), self.events.index(("receive", 2)))
        self.assert_no_request_dispatch()
        self.assert_owned_cleanup()

    def test_verified_run_command_preserves_request_handler_and_terminal_mode(self):
        self.command["kind"] = "RUN_REQUEST"
        result = self.run_preparation()
        self.assertEqual(result, {"status": "COMPLETED"})
        self.action.assert_called_once()
        self.assertIs(self.action.call_args.kwargs["terminal_ack"], True)
        self.assertLess(self.action.call_args.kwargs["deadline"], 104.0)
        self.assertEqual(len(self.received), 1)
        self.send.assert_not_called()
        self.initialize.assert_not_called()
        self.assert_owned_cleanup()

    def test_source_handshake_failure_cannot_read_command_or_prepare(self):
        self.handshake.side_effect = RuntimeError("source mismatch")
        with self.assertRaisesRegex(RuntimeError, "source mismatch"):
            self.run_preparation()
        self.receive.assert_not_called()
        self.initialize.assert_not_called()
        self.assert_no_request_dispatch()
        self.assert_owned_cleanup()

    def test_legacy_action_does_not_read_or_infer_a_startup_command(self):
        self.run_role("action")
        self.handshake.assert_not_called()
        self.receive.assert_not_called()
        self.initialize.assert_not_called()
        self.action.assert_called_once()
        self.assertNotIn("terminal_ack", self.action.call_args.kwargs)

    def test_sensor_and_provider_do_not_accept_action_commands(self):
        for role in ("sensor", "provider"):
            self.configure(role)
            with self.subTest(role=role):
                result = subject.run(role, ["9000", "105000000000"], source_loader=self.loader)
                self.assertEqual(result, {"status": "COMPLETED"})
        self.receive.assert_not_called()
        self.initialize.assert_not_called()
        self.sensor.assert_called_once()
        self.provider.assert_called_once()
        self.assert_owned_cleanup()

    def test_wrong_saved_or_effective_action_identity_refuses_before_preparation(self):
        def changed(*_):
            self.euid.return_value = 0
        self.handshake.side_effect = changed
        with self.assertRaises(subject.PiServiceEntryError):
            self.run_preparation()
        self.initialize.assert_not_called()
        self.send.assert_not_called()
        self.assert_no_request_dispatch()
        self.assert_owned_cleanup()

    def test_changed_root_peer_before_command_refuses_without_initialization(self):
        def changed(root, *_):
            root.peer = (9001, 0, 0)
        self.handshake.side_effect = changed
        with self.assertRaises(subject.PiServiceEntryError):
            self.run_preparation()
        self.receive.assert_not_called()
        self.initialize.assert_not_called()
        self.assert_owned_cleanup()

    def test_command_packet_credential_failure_is_not_retried(self):
        failure = subject.channel.PiIdentityHandoffError("wrong packet sender")
        self.receive.side_effect = failure
        with self.assertRaises(subject.channel.PiIdentityHandoffError) as caught:
            self.run_preparation()
        self.assertIs(caught.exception, failure)
        self.receive.assert_called_once()
        self.initialize.assert_not_called()
        self.assert_owned_cleanup()

    def test_configuration_and_grant_substitution_refuse_before_initializer(self):
        self.command["configuration_digest"] = "sha256:" + "f" * 64
        with self.assertRaises(subject.PiServiceEntryError):
            self.run_preparation()
        self.initialize.assert_not_called()
        self.send.assert_not_called()
        self.assert_no_request_dispatch()

    def test_initializer_exception_is_original_once_with_owned_cleanup(self):
        failure = OSError("retained controls uncertain")
        self.initialize.side_effect = failure
        with self.assertRaises(OSError) as caught:
            self.run_preparation()
        self.assertIs(caught.exception, failure)
        self.initialize.assert_called_once()
        self.send.assert_not_called()
        self.assertEqual(len(self.received), 1)
        self.assert_no_request_dispatch()
        self.assert_owned_cleanup()

    def test_cancelled_initializer_is_not_retried(self):
        failure = KeyboardInterrupt("cancelled")
        self.initialize.side_effect = failure
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_preparation()
        self.assertIs(caught.exception, failure)
        self.initialize.assert_called_once()
        self.send.assert_not_called()
        self.assert_owned_cleanup()

    def test_terminal_initializer_observation_is_retained_without_relabelling(self):
        self.preparation["status"] = "CONSUMED"
        result = self.run_preparation()
        self.assertEqual(result["status"], "CONSUMED")
        self.assertEqual(self.sent[0][1]["result"], self.preparation)
        for key in ("activation_performed", "service_ready", "phase3_exit_eligible"):
            self.assertIs(result[key], False)
        self.initialize.assert_called_once()
        self.assert_no_request_dispatch()

    def test_missing_or_forged_initializer_result_cannot_be_sent(self):
        self.initialize.return_value = None
        self.initialize.side_effect = None
        with self.assertRaises(subject.PiServiceEntryError):
            self.run_preparation()
        self.initialize.assert_called_once()
        self.send.assert_not_called()
        self.assertEqual(len(self.received), 1)
        self.assert_owned_cleanup()

    def test_prepared_send_uncertainty_does_not_retry_or_wait_for_ack(self):
        failure = OSError("partial PREPARED")
        self.send.side_effect = failure
        with self.assertRaises(OSError) as caught:
            self.run_preparation()
        self.assertIs(caught.exception, failure)
        self.initialize.assert_called_once()
        self.send.assert_called_once()
        self.assertEqual(len(self.received), 1)
        self.assert_owned_cleanup()

    def test_missing_ack_preserves_uncertainty_without_second_initializer(self):
        self.acknowledgment = TimeoutError("missing ACK")
        with self.assertRaises(TimeoutError) as caught:
            self.run_preparation()
        self.assertIs(caught.exception, self.acknowledgment)
        self.initialize.assert_called_once()
        self.send.assert_called_once()
        self.assertEqual(len(self.received), 2)
        self.assert_owned_cleanup()

    def test_cancelled_ack_wait_does_not_restart_preparation(self):
        self.acknowledgment = KeyboardInterrupt("cancelled ACK")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_preparation()
        self.assertIs(caught.exception, self.acknowledgment)
        self.initialize.assert_called_once()
        self.send.assert_called_once()
        self.assert_owned_cleanup()

    def test_ack_must_bind_actual_result_and_all_original_fields(self):
        changes = ({"result_digest": canonical_digest({})}, {"nonce": "d" * 64},
                   {"configuration_digest": "sha256:" + "f" * 64}, {"grant_digest": "sha256:" + "f" * 64},
                   {"deadline_ns": 104_000_000_001}, {"kind": "RUN_REQUEST"}, {"extra": True})
        for change in changes:
            # Each inert scope models its own one-shot channel, not a retry.
            self.received.clear()
            self.sent.clear()
            before = self.initialize.call_count
            self.acknowledgment = {**self.command, "kind": "ACK", "result_digest": canonical_digest(self.preparation), **change}
            with self.subTest(change=change), self.assertRaises(subject.PiServiceEntryError):
                self.run_preparation()
            self.assertEqual(self.initialize.call_count, before + 1)
            self.assertEqual(len(self.sent), 1)
            self.assert_owned_cleanup()

    def test_changed_connected_root_after_prepared_is_refused(self):
        send = self.send.side_effect

        def changed(root, *args, **kwargs):
            send(root, *args, **kwargs)
            root.peer = (9001, 0, 0)

        self.send.side_effect = changed
        with self.assertRaises(subject.PiServiceEntryError):
            self.run_preparation()
        self.initialize.assert_called_once()
        self.assertEqual(len(self.received), 1)
        self.assert_owned_cleanup()

    def test_original_command_deadline_expiring_in_initializer_prevents_prepared(self):
        initialize = self.initialize.side_effect

        def expired(*args, **kwargs):
            result = initialize(*args, **kwargs)
            self.clock.return_value = 104.0
            return result

        self.initialize.side_effect = expired
        with self.assertRaises(RuntimeError):
            self.run_preparation()
        self.initialize.assert_called_once()
        self.send.assert_not_called()
        self.assert_owned_cleanup()

    def test_late_ack_cannot_extend_original_command_deadline(self):
        receive = self.receive.side_effect

        def late(*args, **kwargs):
            result = receive(*args, **kwargs)
            if len(self.received) == 2:
                self.clock.return_value = 104.0
            return result

        self.receive.side_effect = late
        with self.assertRaises(RuntimeError):
            self.run_preparation()
        self.initialize.assert_called_once()
        self.assert_owned_cleanup()

    def test_owned_channel_close_failure_cannot_return_success(self):
        def acknowledged(*args, **kwargs):
            result = self.receive_packet(*args, **kwargs)
            if len(self.received) == 2:
                self.fail_socket_close.add(self.sockets[0].fd)
            return result

        self.receive.side_effect = acknowledged
        with self.assertRaises(subject.PiServiceEntryError):
            self.run_preparation()
        self.initialize.assert_called_once()
        self.assertEqual(len([event for event in self.events if event[0] == "socket_close"]), 1)
        self.assertFalse(self.fds)

    def test_main_redacts_preparation_failure_and_never_reports_success(self):
        self.initialize.side_effect = OSError("private configuration or state bytes")
        output = io.StringIO()
        with mock.patch.object(subject.sys, "stderr", output):
            status = subject.main("action", ["9000", "105000000000"], source_loader=self.loader)
        self.assertEqual(status, 126)
        self.assertEqual(output.getvalue(), "PI_SERVICE_ENTRY_REFUSED_OR_CLEANUP_HOLD\n")
        self.initialize.assert_called_once()


class ContractTests(fixtures.PiServiceEntryTests):
    def validate(self, value):
        return subject.validate_action_start(value, configuration_digest=canonical_digest(self.value),
            grant_digest=canonical_digest(self.value["capability_grant"]), deadline=105.0)

    def test_only_two_fixed_command_kinds_and_defensive_copy(self):
        for kind in ("RUN_REQUEST", "PREPARE_GRANT"):
            value = command(self.value, kind=kind)
            result = self.validate(value)
            self.assertEqual(result, value)
            self.assertIsNot(result, value)
            result["nonce"] = "changed"
            self.assertNotEqual(result, value)

    def test_command_cannot_carry_role_path_grant_bytes_credentials_or_unknown_mode(self):
        for changes in ({"kind": "SHELL"}, {"kind": []}, {"role": "provider"}, {"path": "/tmp"},
                        {"capability_grant": self.value["capability_grant"]}, {"credential": "secret"},
                        {"retry_budget": 2}, {"schema": "other/v1"}):
            with self.subTest(changes=changes), self.assertRaises(subject.PiServiceEntryError):
                self.validate({**command(self.value), **changes})

    def test_nonce_is_exact_lowercase_64_hex(self):
        for nonce in ("c" * 32, "C" * 64, "c" * 64 + "\n", True, None):
            with self.subTest(nonce=nonce), self.assertRaises(subject.PiServiceEntryError):
                self.validate({**command(self.value), "nonce": nonce})

    def test_configuration_and_grant_pins_are_independent_exact_inputs(self):
        for key in ("configuration_digest", "grant_digest"):
            for value in ("sha256:" + "f" * 64, "bad", None, True):
                with self.subTest(key=key, value=value), self.assertRaises(subject.PiServiceEntryError):
                    self.validate({**command(self.value), key: value})

    def test_original_deadline_is_integer_current_and_cannot_be_extended(self):
        for value in (True, None, 104.0, 0, 100_000_000_000, 105_000_000_001, 2**63):
            with self.subTest(value=value), self.assertRaises(subject.PiServiceEntryError):
                self.validate(command(self.value, deadline_ns=value))

    def test_result_is_exact_actual_schema_and_never_qualifies(self):
        for state in ("AVAILABLE", "CONSUMED", "ABANDONED", "EXPIRED"):
            value = preparation(self.value, status=state)
            result = subject.validate_preparation_result(value, grant_digest=value["grant_digest"])
            self.assertEqual(result, value)
            self.assertIsNot(result, value)

    def test_result_rejects_missing_extra_wrong_pin_unresolved_or_forged_success(self):
        value = preparation(self.value)
        for change in ({"status": "CLAIMED"}, {"status": "PASS"}, {"extra": True},
                       {"grant_digest": "sha256:" + "f" * 64}, {"state_digest": "bad"},
                       {"service_ready": True}, {"activation_performed": True}, {"phase3_exit_eligible": True},
                       {"service_ready": 0}, {"schema": "wrong"}, {"authority": "EFFECT_AUTHORITY"}):
            with self.subTest(change=change), self.assertRaises(subject.PiServiceEntryError):
                subject.validate_preparation_result({**value, **change}, grant_digest=value["grant_digest"])


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for case in (PreparationServiceTests, ContractTests):
        suite.addTests(case(name) for name in sorted(case.__dict__) if name.startswith("test_"))
    for name in ("test_action_dispatches_one_existing_handler_and_cleans_owned_listener",
                 "test_sensor_dispatches_real_adoption_wrapper_with_direct_stream",
                 "test_provider_dispatches_exact_handler_without_reading_credentials"):
        suite.addTest(fixtures.PiServiceEntryTests(name))
    return suite
