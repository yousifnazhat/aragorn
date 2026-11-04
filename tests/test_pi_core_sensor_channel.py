"""New inert sensor custody checks; no real sockets, processes or OS changes."""

import base64
import os
import socket
import subprocess
import unittest
from contextlib import ExitStack
from unittest import mock

from aragorn import pi_core_sensor_channel as custody
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


def request():
    return {
        "schema": "aragorn/runtime-action-worker-request/v1",
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "target_name": "result.txt", "payload_base64": "eA==",
        "session_id": "a" * 32, "run_id": "a" * 32,
        "tool_call_digest": "sha256:" + "b" * 64,
    }


def broker_result():
    return {
        "schema": "aragorn/runtime-action-broker-result/v1",
        "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "request_digest": "sha256:" + "c" * 64,
        "observation_digest": "sha256:" + "d" * 64,
        "target_name": "result.txt", "verdict": "BLOCK",
        "reason_codes": ["POLICY_BLOCKED"], "effect_status": "NOT_PERFORMED",
        "decision": None,
    }


def bound():
    return {
        "nonce": "b" * 32, "request_digest": canonical_digest(request()),
        "deadline_ns": 120_000_000_000,
    }


def offer():
    return custody._packet("OFFER", **bound(), request=request())


def done():
    return custody._packet("DONE", **bound(), broker_result_digest=canonical_digest(broker_result()))


def local_stream(descriptor=81):
    connection = mock.Mock(name="received_pi_stream")
    connection.fileno.return_value = descriptor
    connection.getsockopt.side_effect = lambda level, option: {
        custody.transport._DOMAIN: socket.AF_UNIX,
        socket.SO_TYPE: socket.SOCK_STREAM,
    }[option]
    for name in ("recv", "recvmsg", "recv_into", "send", "sendall", "sendmsg", "shutdown", "makefile"):
        getattr(connection, name).side_effect = AssertionError("Pi stream IO is forbidden in sensor custody")
    return connection


class InertTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for owner, name in (
            (socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
            (subprocess, "run"), (subprocess, "Popen"), (os, "system"), (os, "open"),
            (os, "read"), (os, "write"), (os, "dup"), (os, "readlink"),
        ):
            self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("live operation forbidden")))
        for name in ("pidfd_open", "fork", "posix_spawn", "posix_spawnp"):
            self.stack.enter_context(mock.patch.object(os, name, create=True,
                side_effect=AssertionError("process operation forbidden")))
        self.stack.enter_context(mock.patch.object(custody.time, "monotonic", return_value=100.0))
        self.stack.enter_context(mock.patch.object(custody.time, "monotonic_ns", return_value=100_000_000_000))
        self.stack.enter_context(mock.patch.object(custody.secrets, "token_hex", return_value="b" * 32))
        self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(os, "getegid", return_value=0))
        self.close = self.stack.enter_context(mock.patch.object(os, "close"))
        for name in ("open_peer_pidfd", "require_live_pidfd", "_read_virtual_file", "measure_runtime_process_profile"):
            self.stack.enter_context(mock.patch.object(custody.transport.process, name,
                side_effect=AssertionError("kernel read forbidden")))


class PacketTests(InertTests):
    def test_four_packet_shapes_have_exact_non_authorizing_schema(self):
        values = [custody._packet("CHALLENGE", nonce="b" * 32), offer(),
                  custody._packet("READY", **bound()), done()]
        for value in values:
            with self.subTest(kind=value["kind"]):
                self.assertEqual(custody._validate_packet(value), value)
                self.assertEqual(value["authority"],
                    "ROOT_READ_CANDIDATE_NOT_SENSOR_ATTRIBUTION_OR_EFFECT_AUTHORITY")

    def test_unknown_kind_extra_fields_and_forged_authority_refuse(self):
        for changes in ({"kind": "COMMIT"}, {"kind": []}, {"extra": True},
                        {"schema": "other/v1"}, {"authority": "EFFECT_AUTHORITY"}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                custody._validate_packet({**offer(), **changes})

    def test_nonce_must_be_exact_lowercase_hex(self):
        for nonce in ("B" * 32, "b" * 31, "b" * 32 + "\n", True, None):
            with self.subTest(nonce=nonce), self.assertRaises(RuntimeError):
                custody._validate_packet(custody._packet("CHALLENGE", nonce=nonce))

    def test_deadline_integer_bounds_and_request_digest_refuse(self):
        for changes in ({"deadline_ns": True}, {"deadline_ns": 0},
                        {"deadline_ns": 2**63}, {"deadline_ns": 120.0},
                        {"request_digest": "sha256:" + "f" * 64}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                custody._validate_packet({**offer(), **changes})

    def test_request_shape_and_completion_digest_are_validated(self):
        for value in ({**offer(), "request": {**request(), "extra": True}},
                      {**done(), "broker_result_digest": "bad"},
                      {**done(), "broker_result_digest": True}):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                custody._validate_packet(value)

    def test_maximum_existing_request_payload_fits_packet_budget(self):
        candidate = {**request(), "payload_base64": base64.b64encode(b"x" * 32768).decode("ascii")}
        value = {**offer(), "request": candidate, "request_digest": canonical_digest(candidate)}
        custody._validate_packet(value)
        self.assertLess(len(canonical_json(value)), custody.MAX_PACKET_BYTES)

    def test_send_passes_exact_rights_and_never_retries_failed_transfer(self):
        connection = mock.Mock()
        with mock.patch.object(custody.transport, "send_authenticated_packet",
                               side_effect=OSError("uncertain send")) as send:
            with self.assertRaises(OSError):
                custody._send(connection, offer(), 120.0, rights=(81,))
        send.assert_called_once_with(connection, offer(), 120.0, rights=(81,),
                                     max_bytes=custody.MAX_PACKET_BYTES)

    def test_send_rights_count_is_closed_by_packet_kind(self):
        with mock.patch.object(custody.transport, "send_authenticated_packet") as send:
            for value, rights in ((offer(), ()), (offer(), (81, 82)), (done(), (81,))):
                with self.subTest(kind=value["kind"], rights=rights), self.assertRaises(RuntimeError):
                    custody._send(mock.Mock(), value, 120.0, rights=rights)
        send.assert_not_called()

    def test_receive_preserves_exact_raw_authentication_and_fd_contract(self):
        connection = mock.Mock()
        with mock.patch.object(custody.transport, "receive_authenticated_packet",
                               return_value=(offer(), (81,))) as receive:
            self.assertEqual(custody._receive(connection, (200, 0, 0), 120.0, rights=1), (offer(), (81,)))
        receive.assert_called_once_with(connection, (200, 0, 0), 120.0,
                                       expected_rights=1, max_bytes=custody.MAX_PACKET_BYTES)
        self.close.assert_not_called()

    def test_receive_bad_shape_or_kind_rights_closes_installed_duplicate(self):
        for value in ({**offer(), "extra": True}, custody._packet("READY", **bound())):
            self.close.reset_mock()
            with self.subTest(value=value), mock.patch.object(custody.transport,
                    "receive_authenticated_packet", return_value=(value, (81,))):
                with self.assertRaises(RuntimeError):
                    custody._receive(mock.Mock(), (200, 0, 0), 120.0, rights=1)
            self.close.assert_called_once_with(81)


class CandidateTests(InertTests):
    def setUp(self):
        super().setUp()
        self.connection = mock.Mock(name="sensor_root_channel")
        self.connection.fileno.return_value = 10
        self.stream = local_stream()
        self.events = []
        self.offered = offer()
        self.descriptors = (81,)
        self.factory = self.stack.enter_context(mock.patch.object(socket, "socket", return_value=self.stream))
        self.guard = self.stack.enter_context(mock.patch.object(custody.transport, "guard_channel", return_value=80))
        self.live = self.stack.enter_context(mock.patch.object(custody.transport, "require_peer_live"))
        self.peer = self.stack.enter_context(mock.patch.object(custody.broker, "_peer_credentials",
                                                              return_value=(300, 1201, 1202)))
        self.send = self.stack.enter_context(mock.patch.object(custody, "_send",
            side_effect=lambda connection, value, deadline, **kw: self.events.append(value["kind"])))
        self.receive = self.stack.enter_context(mock.patch.object(custody, "_receive",
            side_effect=lambda *args, **kw: (self.offered, self.descriptors)))
        self.stream.close.side_effect = lambda: self.events.append("close_pi_duplicate")
        self.close.side_effect = lambda fd: self.events.append(("close", fd))

    def held(self, **changes):
        return custody.hold_sensor_candidate(self.connection,
            **{"expected_supervisor_pid": 200, "deadline": 120.0, **changes})

    def assert_no_pi_io(self):
        for name in ("recv", "recvmsg", "recv_into", "send", "sendall", "sendmsg", "shutdown", "makefile"):
            getattr(self.stream, name).assert_not_called()
        self.connection.close.assert_not_called()

    def test_authenticated_candidate_closes_owned_handles_before_done(self):
        with self.held() as candidate:
            self.assertIs(candidate.worker_connection, self.stream)
            self.assertEqual(candidate.request, request())
            self.assertEqual(candidate.request_digest, canonical_digest(request()))
            self.assertEqual(candidate.deadline, 120.0)
            candidate.ready()
            candidate.finish(broker_result())
        self.assertEqual(self.events, ["CHALLENGE", "READY", "close_pi_duplicate", ("close", 80), "DONE"])
        self.guard.assert_called_once_with(self.connection, (200, 0, 0), 120.0)
        self.factory.assert_called_once_with(fileno=81)
        self.assert_no_pi_io()

    def test_candidate_constructor_requires_factory_seal(self):
        with self.assertRaises(RuntimeError):
            custody.SensorCandidate(object(), self.connection, (200, 0, 0), 80,
                                    self.stream, offer(), 120.0)
        self.peer.assert_not_called()

    def test_request_property_detaches_mutable_input(self):
        with self.held() as candidate:
            candidate.request["target_name"] = "changed.txt"
            self.offered["request"]["target_name"] = "also-changed.txt"
            self.assertEqual(candidate.request, request())
            with self.assertRaises(AttributeError):
                candidate.deadline = 150.0

    def test_scope_exit_without_finish_never_sends_completion(self):
        with self.held() as candidate:
            candidate.ready()
        with self.assertRaises(RuntimeError):
            candidate.guard()
        with self.assertRaises(RuntimeError):
            _ = candidate.worker_connection
        self.assertNotIn("DONE", self.events)
        self.stream.close.assert_called_once_with()
        self.close.assert_called_once_with(80)
        self.assert_no_pi_io()

    def test_challenge_or_expired_or_extended_offer_refuses_before_socket_adoption(self):
        for changes in ({"nonce": "f" * 32}, {"deadline_ns": 100_000_000_000},
                        {"deadline_ns": 120_000_000_001}, {"kind": "READY"}):
            self.close.reset_mock()
            self.offered = {**offer(), **changes}
            with self.subTest(changes=changes), self.assertRaises(RuntimeError), self.held():
                pass
            self.assertEqual(self.close.call_args_list, [mock.call(81), mock.call(80)])
        self.factory.assert_not_called()

    def test_invalid_supervisor_pid_refuses_before_channel_handshake(self):
        for pid in (0, -1, True, 2**31):
            with self.subTest(pid=pid), self.assertRaises(RuntimeError), self.held(expected_supervisor_pid=pid):
                pass
        self.guard.assert_not_called()
        self.send.assert_not_called()

    def test_peer_authentication_failure_never_accepts_offer(self):
        self.guard.side_effect = custody.transport.PiIdentityHandoffError("wrong root peer")
        with self.assertRaises(RuntimeError), self.held():
            pass
        self.send.assert_not_called()
        self.receive.assert_not_called()
        self.factory.assert_not_called()

    def test_received_descriptor_aliases_peer_handle_is_closed_once(self):
        self.descriptors = (80,)
        with self.assertRaises(RuntimeError), self.held():
            pass
        self.close.assert_called_once_with(80)
        self.factory.assert_not_called()

    def test_non_unix_or_non_stream_received_fd_refuses_and_closes(self):
        for domain, kind in ((socket.AF_INET, socket.SOCK_STREAM), (socket.AF_UNIX, socket.SOCK_SEQPACKET)):
            self.stream.close.reset_mock()
            self.close.reset_mock()
            self.stream.getsockopt.side_effect = lambda level, option, d=domain, k=kind: {
                custody.transport._DOMAIN: d, socket.SO_TYPE: k}[option]
            with self.subTest(domain=domain, kind=kind), self.assertRaises(RuntimeError), self.held():
                pass
            self.stream.close.assert_called_once_with()
            self.close.assert_called_once_with(80)
        self.assert_no_pi_io()

    def test_socket_adoption_failure_closes_raw_fd_and_root_peer_handle(self):
        self.factory.side_effect = OSError("not a socket")
        with self.assertRaises(OSError), self.held():
            pass
        self.assertEqual(self.close.call_args_list, [mock.call(81), mock.call(80)])
        self.stream.close.assert_not_called()

    def test_peer_change_and_deadline_expiry_refuse_before_ready(self):
        with self.held() as candidate:
            self.peer.return_value = (301, 1201, 1202)
            with self.assertRaises(RuntimeError):
                candidate.ready()
            self.peer.return_value = (300, 1201, 1202)
            with self.assertRaises(RuntimeError):
                candidate.ready()
        self.assertNotIn("READY", self.events)
        self.offered = offer()
        with self.held() as candidate, mock.patch.object(custody.time, "monotonic_ns", return_value=120_000_000_000):
            with self.assertRaises(RuntimeError):
                candidate.ready()
        self.assertNotIn("READY", self.events)

    def test_ready_send_uncertainty_invalidates_without_retry_or_done(self):
        original = self.send.side_effect
        def send(connection, value, deadline, **kw):
            original(connection, value, deadline, **kw)
            if value["kind"] == "READY":
                raise OSError("READY may have arrived")
        self.send.side_effect = send
        with self.held() as candidate:
            with self.assertRaises(OSError):
                candidate.ready()
            with self.assertRaises(RuntimeError):
                candidate.ready()
            with self.assertRaises(RuntimeError):
                candidate.finish(broker_result())
        self.assertEqual(self.events.count("READY"), 1)
        self.assertNotIn("DONE", self.events)

    def test_finish_requires_ready_and_only_one_completion_attempt(self):
        with self.held() as candidate:
            with self.assertRaises(RuntimeError):
                candidate.finish(broker_result())
            candidate.ready()
            candidate.finish(broker_result())
            with self.assertRaises(RuntimeError):
                candidate.finish(broker_result())
            with self.assertRaises(RuntimeError):
                candidate.ready()
        self.assertEqual(self.events.count("DONE"), 1)
        self.stream.close.assert_called_once_with()

    def test_duplicate_close_failure_attempts_peer_close_and_prevents_done(self):
        with self.held() as candidate:
            candidate.ready()
            self.stream.close.side_effect = OSError("duplicate close uncertain")
            with self.assertRaisesRegex(RuntimeError, "cleanup"):
                candidate.finish(broker_result())
            with self.assertRaises(RuntimeError):
                candidate.finish(broker_result())
        self.stream.close.assert_called_once_with()
        self.close.assert_called_once_with(80)
        self.assertNotIn("DONE", self.events)

    def test_peer_close_failure_does_not_retry_or_send_done(self):
        with self.held() as candidate:
            candidate.ready()
            self.close.side_effect = OSError("peer close uncertain")
            with self.assertRaisesRegex(RuntimeError, "cleanup"):
                candidate.finish(broker_result())
        self.stream.close.assert_called_once_with()
        self.close.assert_called_once_with(80)
        self.assertNotIn("DONE", self.events)

    def test_done_send_failure_follows_cleanup_and_never_retries(self):
        original = self.send.side_effect
        def send(connection, value, deadline, **kw):
            original(connection, value, deadline, **kw)
            if value["kind"] == "DONE":
                raise OSError("DONE delivery uncertain")
        self.send.side_effect = send
        with self.held() as candidate:
            candidate.ready()
            with self.assertRaises(OSError):
                candidate.finish(broker_result())
            with self.assertRaises(RuntimeError):
                candidate.finish(broker_result())
        self.assertEqual(self.events, ["CHALLENGE", "READY", "close_pi_duplicate", ("close", 80), "DONE"])
        self.stream.close.assert_called_once_with()
        self.close.assert_called_once_with(80)


class TicketTests(InertTests):
    def setUp(self):
        super().setUp()
        self.connection = mock.Mock(name="root_sensor_channel")
        self.connection.fileno.return_value = 11
        self.stream = local_stream(descriptor=12)
        self.events = []
        self.messages = [custody._packet("CHALLENGE", nonce="b" * 32),
                         custody._packet("READY", **bound()), done()]
        self.guard = self.stack.enter_context(mock.patch.object(custody.transport, "guard_channel", return_value=70))
        self.live = self.stack.enter_context(mock.patch.object(custody.transport, "require_peer_live"))
        self.peer = self.stack.enter_context(mock.patch.object(custody.broker, "_peer_credentials",
                                                              return_value=(400, 1301, 1302)))
        self.send = self.stack.enter_context(mock.patch.object(custody, "_send",
            side_effect=lambda connection, value, deadline, **kw: self.events.append((value, kw))))
        self.receive = self.stack.enter_context(mock.patch.object(custody, "_receive",
            side_effect=lambda *args, **kw: (self.messages.pop(0), ())))

    def held(self, **changes):
        return custody.hold_pi_sensor_channel(self.connection, self.stream, request(),
            **{"expected_sensor_peer": (400, 1301, 1302), "deadline": 120.0, **changes})

    def assert_borrowed_connections_untouched(self):
        self.connection.close.assert_not_called()
        self.stream.close.assert_not_called()
        for name in ("recv", "recvmsg", "recv_into", "send", "sendall", "sendmsg", "shutdown", "makefile"):
            getattr(self.stream, name).assert_not_called()

    def test_root_publishes_exact_original_fd_and_receives_matching_done(self):
        with self.held() as ticket:
            ticket.finish(broker_result())
        self.assertEqual(self.events, [(offer(), {"rights": (12,)})])
        self.guard.assert_called_once_with(self.connection, (400, 1301, 1302), 120.0)
        self.close.assert_called_once_with(70)
        self.assertEqual(self.receive.call_count, 3)
        self.assert_borrowed_connections_untouched()

    def test_nonroot_publisher_or_root_sensor_peer_refuses_before_transfer(self):
        with mock.patch.object(os, "geteuid", return_value=1201):
            with self.assertRaises(RuntimeError), self.held():
                pass
        for peer in ((400, 0, 1302), (400, 1301, 0), (True, 1301, 1302)):
            with self.subTest(peer=peer), self.assertRaises(RuntimeError), self.held(expected_sensor_peer=peer):
                pass
        self.guard.assert_not_called()
        self.send.assert_not_called()

    def test_overlapping_channel_descriptor_refuses_before_handshake(self):
        self.stream.fileno.return_value = 11
        with self.assertRaises(RuntimeError), self.held():
            pass
        self.guard.assert_not_called()
        self.send.assert_not_called()

    def test_sensor_peer_authentication_failure_prevents_offer(self):
        self.guard.side_effect = custody.transport.PiIdentityHandoffError("wrong sensor peer")
        with self.assertRaises(RuntimeError), self.held():
            pass
        self.send.assert_not_called()
        self.receive.assert_not_called()
        self.close.assert_not_called()

    def test_wrong_challenge_kind_or_ready_binding_refuses_and_closes_peer(self):
        transcripts = [
            [custody._packet("READY", **bound())],
            [custody._packet("CHALLENGE", nonce="b" * 32), {**custody._packet("READY", **bound()), "nonce": "f" * 32}],
            [custody._packet("CHALLENGE", nonce="b" * 32), {**custody._packet("READY", **bound()), "deadline_ns": 121_000_000_000}],
            [custody._packet("CHALLENGE", nonce="b" * 32), {**custody._packet("READY", **bound()), "request_digest": "sha256:" + "f" * 64}],
        ]
        for messages in transcripts:
            self.messages = messages
            self.close.reset_mock()
            with self.subTest(messages=messages), self.assertRaises(RuntimeError), self.held():
                pass
            self.close.assert_called_once_with(70)
        self.assert_borrowed_connections_untouched()

    def test_offer_send_uncertainty_has_one_attempt_and_closes_only_owned_peer(self):
        self.send.side_effect = OSError("offer may have transferred FD")
        with self.assertRaises(OSError), self.held():
            pass
        self.send.assert_called_once()
        self.assertEqual(self.receive.call_count, 1)
        self.close.assert_called_once_with(70)
        self.assert_borrowed_connections_untouched()

    def test_ticket_scope_exit_is_not_success_and_cannot_finish_after_exit(self):
        with self.held() as ticket:
            pass
        with self.assertRaises(RuntimeError):
            ticket.finish(broker_result())
        self.assertEqual(self.receive.call_count, 2)
        self.close.assert_called_once_with(70)

    def test_mismatched_result_receipt_is_terminal_without_second_receive(self):
        self.messages[2] = {**done(), "broker_result_digest": "sha256:" + "f" * 64}
        with self.held() as ticket:
            with self.assertRaises(RuntimeError):
                ticket.finish(broker_result())
            with self.assertRaises(RuntimeError):
                ticket.finish(broker_result())
        self.assertEqual(self.receive.call_count, 3)
        self.close.assert_called_once_with(70)

    def test_missing_done_never_retries_or_closes_borrowed_stream(self):
        with self.held() as ticket:
            self.receive.side_effect = TimeoutError("sensor cleanup not acknowledged")
            with self.assertRaises(TimeoutError):
                ticket.finish(broker_result())
            with self.assertRaises(RuntimeError):
                ticket.finish(broker_result())
        self.assertEqual(self.receive.call_count, 3)
        self.close.assert_called_once_with(70)
        self.assert_borrowed_connections_untouched()

    def test_peer_close_failure_cannot_report_success_or_retry_close(self):
        with self.held() as ticket:
            self.close.side_effect = OSError("sensor peer handle close uncertain")
            with self.assertRaises(OSError):
                ticket.finish(broker_result())
            with self.assertRaises(RuntimeError):
                ticket.finish(broker_result())
        self.close.assert_called_once_with(70)

    def test_authenticated_terminal_done_remains_valid_after_sensor_exit(self):
        with self.held() as ticket:
            self.live.side_effect = AssertionError("terminal DONE must not depend on sender exit timing")
            ticket.finish(broker_result())
        self.assertEqual(self.receive.call_count, 3)
        self.close.assert_called_once_with(70)
        self.assertGreaterEqual(self.peer.call_count, 2)

    def test_terminal_done_with_changed_connected_peer_is_refused(self):
        with self.held() as ticket:
            self.peer.side_effect = [(400, 1301, 1302), (401, 1301, 1302)]
            with self.assertRaises(RuntimeError):
                ticket.finish(broker_result())
            with self.assertRaises(RuntimeError):
                ticket.finish(broker_result())
        self.assertEqual(self.receive.call_count, 3)
        self.close.assert_called_once_with(70)


class TranscriptTests(InertTests):
    def test_paired_sensor_and_root_transcripts_bind_same_bytes_and_cleanup(self):
        # Replay both real protocol halves against recorded mocked transport.
        # There is no concurrent thread, socketpair, service, or kernel read.
        sensor_channel, root_channel = mock.Mock(), mock.Mock()
        root_channel.fileno.return_value = 11
        duplicate, original = local_stream(81), local_stream(12)
        sensor_packets, root_packets, events = [], [], []
        duplicate.close.side_effect = lambda: events.append("sensor_duplicate_closed")
        self.close.side_effect = lambda fd: events.append(("fd_closed", fd))
        with mock.patch.object(custody.transport, "guard_channel", side_effect=[80, 70]), \
             mock.patch.object(custody.transport, "require_peer_live"), \
             mock.patch.object(custody.broker, "_peer_credentials",
                               side_effect=lambda connection: (300, 1201, 1202) if connection is duplicate else (400, 1301, 1302)), \
             mock.patch.object(socket, "socket", return_value=duplicate), \
             mock.patch.object(custody, "_receive", return_value=(offer(), (81,))), \
             mock.patch.object(custody, "_send", side_effect=lambda connection, value, deadline, **kw:
                               (sensor_packets.append(value), events.append(value["kind"]))):
            with custody.hold_sensor_candidate(sensor_channel, expected_supervisor_pid=200, deadline=120.0) as candidate:
                candidate.ready()
                candidate.finish(broker_result())
            self.assertEqual(events, ["CHALLENGE", "READY", "sensor_duplicate_closed", ("fd_closed", 80), "DONE"])
            with mock.patch.object(custody, "_receive", side_effect=lambda *args, **kw: (sensor_packets.pop(0), ())), \
                 mock.patch.object(custody, "_send", side_effect=lambda connection, value, deadline, **kw:
                                   root_packets.append((value, kw))):
                with custody.hold_pi_sensor_channel(root_channel, original, request(),
                        expected_sensor_peer=(400, 1301, 1302), deadline=120.0) as ticket:
                    ticket.finish(broker_result())
        self.assertEqual(root_packets, [(offer(), {"rights": (12,)})])
        self.assertEqual(sensor_packets, [])
        self.assertEqual(events[-1], ("fd_closed", 70))
        duplicate.close.assert_called_once_with()
        original.close.assert_not_called()
        sensor_channel.close.assert_not_called()
        root_channel.close.assert_not_called()
        self.assertEqual(self.close.call_args_list, [mock.call(80), mock.call(70)])


if __name__ == "__main__":
    unittest.main()
