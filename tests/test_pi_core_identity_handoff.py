"""Inert identity-only publisher/transport checks; no native sockets or processes."""

import array
import os
import socket
import struct
import subprocess
import unittest
from contextlib import ExitStack
from unittest import mock

from aragorn import pi_core_identity_handoff as handoff
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


def activation():
    value = {key: "sha256:" + "a" * 64 for key in (
        "profile_digest", "runtime_digest", "executable_digest", "active_skill_digest",
        "install_context_digest", "source_manifest_digest", "tree_digest", "active_record_digest",
        "deployment_digest", "policy_digest")}
    return {**value, "schema": "aragorn/pi-core-activation/v1",
        "authority": "PROTECTED_LAUNCHER_BINDING_ONLY_NOT_EFFECT_AUTHORITY",
        "activation_id": "a" * 32, "session_id": "a" * 32, "run_id": "a" * 32,
        "pid": 300, "uid": 1201, "gid": 1202, "start_time_ticks": 50,
        "mount_namespace": {"device": 1, "inode": 2}, "cgroup": "/system.slice/pi.service",
        "expires_at_monotonic_ns": 120_000_000_000,
        "boot_id": "11111111-2222-3333-4444-555555555555"}


def packet(kind, **fields):
    return {"schema": handoff.SCHEMA, "authority": handoff.AUTHORITY, "kind": kind, **fields}


def control(kind):
    return packet(kind, nonce="b" * 32, activation_digest=canonical_digest(activation()), deadline_ns=120_000_000_000)


class InertTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(handoff.time, "monotonic", return_value=100.0))
        self.stack.enter_context(mock.patch.object(handoff.time, "monotonic_ns", return_value=100_000_000_000))
        for owner, name in ((socket, "socket"), (socket, "create_connection"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("native operations forbidden")))
        for name in ("open_peer_pidfd", "require_live_pidfd", "_read_virtual_file"):
            self.stack.enter_context(mock.patch.object(handoff.process, name, side_effect=AssertionError("live kernel read forbidden")))


class PacketTransportTests(InertTests):
    def setUp(self):
        super().setUp()
        self.connection = mock.Mock()
        self.peer = (200, 0, 0)
        self.credentials = (socket.SOL_SOCKET, handoff._CREDENTIALS, handoff._CRED.pack(*self.peer))
        self.document = {**control("HANDOFF"), "activation": activation()}
        self.close = self.stack.enter_context(mock.patch.object(handoff.os, "close"))
        self.stack.enter_context(mock.patch.object(handoff.os, "get_inheritable", return_value=False))

    def receive(self, controls=None, raw=None, flags=0, expected=1):
        controls = controls if controls is not None else [self.credentials,
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [41]).tobytes())]
        self.connection.recvmsg.return_value = (canonical_json(self.document) if raw is None else raw, controls, flags, None)
        return handoff.receive_packet(self.connection, self.peer, 120, expected_rights=expected)

    def test_success_transfers_one_received_fd_and_sets_cloexec_receive(self):
        document, rights = self.receive()
        self.assertEqual(document, self.document)
        self.assertEqual(rights, (41,))
        self.assertEqual(self.connection.recvmsg.call_args.args[2], handoff._CLOEXEC)
        self.close.assert_not_called()
        self.connection.close.assert_not_called()

    def test_wrong_per_message_credentials_close_installed_fd(self):
        controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=i", 41)),
                    (socket.SOL_SOCKET, handoff._CREDENTIALS, handoff._CRED.pack(201, 0, 0))]
        with self.assertRaisesRegex(RuntimeError, "credentials differ"):
            self.receive(controls)
        self.close.assert_called_once_with(41)

    def test_missing_and_duplicate_credentials_refuse(self):
        rights = (socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=i", 41))
        for controls in ([rights], [self.credentials, self.credentials, rights]):
            self.close.reset_mock()
            with self.subTest(controls=len(controls)), self.assertRaises(RuntimeError):
                self.receive(controls)
            self.close.assert_called_once_with(41)

    def test_truncation_and_unknown_flags_close_all_installed_fds(self):
        for flags in (getattr(socket, "MSG_TRUNC", 32), getattr(socket, "MSG_CTRUNC", 8), 1):
            self.close.reset_mock()
            with self.subTest(flags=flags), self.assertRaises(RuntimeError):
                self.receive(flags=flags)
            self.close.assert_called_once_with(41)

    def test_malformed_rights_adopts_complete_integers_before_rejection(self):
        controls = [self.credentials, (socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=ii", 41, 42) + b"x")]
        with self.assertRaises(RuntimeError):
            self.receive(controls)
        self.assertEqual(self.close.call_args_list, [mock.call(41), mock.call(42)])

    def test_unexpected_scm_pidfd_is_owned_and_closed(self):
        with self.assertRaises(RuntimeError):
            self.receive([self.credentials, (socket.SOL_SOCKET, handoff._PIDFD, struct.pack("=i", 42))])
        self.close.assert_called_once_with(42)

    def test_malformed_later_control_cannot_leak_earlier_right(self):
        controls = [self.credentials, (socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=i", 41)), (1,)]
        with self.assertRaises(RuntimeError):
            self.receive(controls)
        self.close.assert_called_once_with(41)

    def test_extra_and_duplicate_descriptor_numbers_refuse(self):
        for descriptors in ((41, 42), (41, 41)):
            self.close.reset_mock()
            with self.subTest(descriptors=descriptors), self.assertRaises(RuntimeError):
                self.receive([self.credentials, (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors).tobytes())])
            self.assertEqual(self.close.call_args_list, [mock.call(fd) for fd in dict.fromkeys(descriptors)])

    def test_rejection_attempts_every_owned_close_even_if_one_fails(self):
        self.close.side_effect = [OSError("close failed"), None]
        with self.assertRaisesRegex(RuntimeError, "descriptor cleanup failed"):
            self.receive([self.credentials, (socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=ii", 41, 42))])
        self.assertEqual(self.close.call_args_list, [mock.call(41), mock.call(42)])

    def test_packet_bound_and_noncanonical_json_refuse_with_fd_cleanup(self):
        for raw in (b"x" * (handoff.MAX_PACKET_BYTES + 1), b'{"a":1,"a":1}', b'{ "a": 1 }'):
            self.close.reset_mock()
            with self.subTest(raw=raw[:20]), self.assertRaises(RuntimeError):
                self.receive(raw=raw)
            self.close.assert_called_once_with(41)

    def test_request_fields_or_effect_authority_are_not_accepted(self):
        for changed in ({**self.document, "request": {}}, {**self.document, "authority": "EFFECT_AUTHORITY"},
                        {**self.document, "kind": "COMMIT"}):
            with self.subTest(changed=changed.get("kind")), self.assertRaises(RuntimeError):
                handoff._packet(changed)

    def test_handoff_expiry_and_digest_must_match_activation(self):
        for fields in ({"deadline_ns": 120_000_000_001}, {"activation_digest": "sha256:" + "f" * 64},
                       {"deadline_ns": True}):
            with self.subTest(fields=fields), self.assertRaises(RuntimeError):
                handoff._packet({**self.document, **fields})

    def test_send_once_never_closes_borrowed_right_or_connection(self):
        self.connection.sendmsg.return_value = len(canonical_json(self.document))
        handoff.send_packet(self.connection, self.document, 120, rights=(71,))
        self.connection.sendmsg.assert_called_once()
        self.close.assert_not_called()
        self.connection.close.assert_not_called()

    def test_short_send_has_no_retry(self):
        self.connection.sendmsg.return_value = 1
        with self.assertRaisesRegex(RuntimeError, "no retry"):
            handoff.send_packet(self.connection, self.document, 120, rights=(71,))
        self.connection.sendmsg.assert_called_once()

    def test_nonhandoff_packet_cannot_transfer_rights(self):
        with self.assertRaises(RuntimeError):
            handoff.send_packet(self.connection, control("REVOKE"), 120, rights=(71,))
        self.connection.sendmsg.assert_not_called()


class ChannelAndPidfdTests(InertTests):
    def test_guard_accepts_only_actual_unix_packet_socket_and_exact_peer(self):
        connection = mock.Mock()
        options = {handoff._DOMAIN: socket.AF_UNIX, socket.SO_TYPE: socket.SOCK_SEQPACKET, handoff._PASSCRED: 1}
        connection.getsockopt.side_effect = lambda level, option: options[option]
        with mock.patch.object(handoff, "_peer_credentials", return_value=(200, 0, 0)), \
             mock.patch.object(handoff.process, "open_peer_pidfd", return_value=81), \
             mock.patch.object(handoff.process, "require_live_pidfd"):
            self.assertEqual(handoff.guard_channel(connection, (200, 0, 0), 120), 81)
            connection.setsockopt.assert_called_once_with(socket.SOL_SOCKET, handoff._PASSCRED, 1)
        connection.close.assert_not_called()

    def test_stream_or_nonunix_channel_is_refused_before_peerfd(self):
        for domain, kind in ((socket.AF_INET, socket.SOCK_SEQPACKET), (socket.AF_UNIX, socket.SOCK_STREAM)):
            connection = mock.Mock()
            connection.getsockopt.side_effect = lambda level, option: domain if option == handoff._DOMAIN else kind
            with self.subTest(domain=domain, kind=kind), mock.patch.object(handoff.process, "open_peer_pidfd") as opened:
                with self.assertRaisesRegex(RuntimeError, "AF_UNIX"):
                    handoff.guard_channel(connection, (200, 0, 0), 120)
                opened.assert_not_called()

    def test_worker_pidfd_reads_only_self_descriptor_association(self):
        with mock.patch.object(handoff.os, "get_inheritable", return_value=False), \
             mock.patch.object(handoff.os, "readlink", return_value="anon_inode:[pidfd]") as link, \
             mock.patch.object(handoff.process, "_read_virtual_file", return_value=b"Pid:\t300\n") as read, \
             mock.patch.object(handoff.process, "require_live_pidfd"):
            handoff.validate_worker_pidfd(71, 300)
            self.assertEqual(str(read.call_args.args[0]), "/proc/self/fdinfo/71")
            link.assert_called_once_with("/proc/self/fd/71")

    def test_worker_pidfd_cannot_be_inheritable_wrong_type_or_wrong_pid(self):
        for inherited, link, raw in ((True, "anon_inode:[pidfd]", b"Pid: 300\n"),
                                     (False, "pipe:[1]", b"Pid: 300\n"),
                                     (False, "anon_inode:[pidfd]", b"Pid: 301\n")):
            with self.subTest(inherited=inherited, link=link, raw=raw), \
                 mock.patch.object(handoff.os, "get_inheritable", return_value=inherited), \
                 mock.patch.object(handoff.os, "readlink", return_value=link), \
                 mock.patch.object(handoff.process, "_read_virtual_file", return_value=raw):
                with self.assertRaises(RuntimeError):
                    handoff.validate_worker_pidfd(71, 300)


class PublisherLifecycleTests(InertTests):
    def setUp(self):
        super().setUp()
        self.connection = mock.Mock()
        self.guard = mock.Mock()
        self.peer = (400, 1301, 1302)
        self.stack.enter_context(mock.patch.object(handoff.os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(handoff.os, "getegid", return_value=0))
        self.remaining = self.stack.enter_context(mock.patch.object(handoff.identity, "_remaining"))
        self.stack.enter_context(mock.patch.object(handoff, "validate_worker_pidfd"))
        self.channel = self.stack.enter_context(mock.patch.object(handoff, "guard_channel", return_value=81))
        self.stack.enter_context(mock.patch.object(handoff, "require_peer_live"))
        self.receive = self.stack.enter_context(mock.patch.object(handoff, "receive_packet", side_effect=[
            (packet("CHALLENGE", nonce="b" * 32), ()), (control("REGISTERED"), ()), (control("REVOKED"), ())]))
        self.send = self.stack.enter_context(mock.patch.object(handoff, "send_packet"))
        self.close = self.stack.enter_context(mock.patch.object(handoff.os, "close"))

    def hold(self, **options):
        return handoff.hold_pi_identity_handoff(self.connection, activation(), 71,
            **{"expected_relay_peer": self.peer, "deadline": 120, "guard": self.guard, **options})

    def test_registration_then_exact_revocation_with_only_owned_peerfd_close(self):
        with self.hold() as state:
            self.assertEqual(state["status"], "REGISTERED")
            self.assertEqual(self.send.call_count, 1)
        self.assertEqual(state["status"], "REVOKED")
        self.assertEqual([call.args[1]["kind"] for call in self.send.call_args_list], ["HANDOFF", "REVOKE"])
        self.assertEqual(self.send.call_args_list[0].kwargs, {"rights": (71,)})
        self.assertGreaterEqual(self.guard.call_count, 5)
        self.assertTrue(all(call.args[0] == 120 for call in self.remaining.call_args_list))
        self.close.assert_called_once_with(81)
        self.connection.close.assert_not_called()

    def test_nonroot_or_overlapping_relay_role_refuses_before_offer(self):
        with mock.patch.object(handoff.os, "geteuid", return_value=1):
            with self.assertRaises(RuntimeError), self.hold():
                pass
        for peer in ((300, 1301, 1302), (400, 1201, 1302), (400, 1301, 1202), (400, 0, 0)):
            with self.subTest(peer=peer), self.assertRaises(RuntimeError), self.hold(expected_relay_peer=peer):
                pass
        self.send.assert_not_called()

    def test_original_deadline_bounds_are_checked_before_channel_use(self):
        for deadline in (True, 100, 131, float("nan"), float("inf")):
            with self.subTest(deadline=deadline), self.assertRaises(RuntimeError), self.hold(deadline=deadline):
                pass
        self.channel.assert_not_called()

    def test_wrong_registration_ack_preserves_uncertainty_without_resend(self):
        self.receive.side_effect = [(packet("CHALLENGE", nonce="b" * 32), ()), ({**control("REGISTERED"), "nonce": "c" * 32}, ())]
        with self.assertRaises(handoff.PiIdentityHandoffError) as error, self.hold():
            pass
        self.assertEqual(error.exception.publication["status"], "HOLD_UNCONFIRMED")
        self.send.assert_called_once()
        self.close.assert_called_once_with(81)

    def test_revoke_failure_is_not_retried(self):
        self.receive.side_effect = [(packet("CHALLENGE", nonce="b" * 32), ()), (control("REGISTERED"), ()), TimeoutError("lost ack")]
        with self.assertRaises(handoff.PiIdentityHandoffError) as error:
            with self.hold():
                pass
        self.assertEqual(error.exception.publication["status"], "HOLD_UNCONFIRMED")
        self.assertEqual(self.send.call_count, 2)

    def test_guard_failure_before_offer_has_no_registration(self):
        self.guard.side_effect = RuntimeError("activation revoked")
        with self.assertRaises(handoff.PiIdentityHandoffError) as error, self.hold():
            pass
        self.assertEqual(error.exception.publication["status"], "REFUSED")
        self.send.assert_not_called()

    def test_guard_failure_on_exit_never_claims_revocation_ack(self):
        with self.assertRaises(handoff.PiIdentityHandoffError) as error:
            with self.hold():
                self.guard.side_effect = RuntimeError("worker identity changed")
        self.assertEqual(error.exception.publication["status"], "HOLD_UNCONFIRMED")
        self.send.assert_called_once()

    def test_peer_descriptor_cleanup_failure_overrides_completion(self):
        self.close.side_effect = OSError("close uncertain")
        with self.assertRaises(handoff.PiIdentityHandoffError) as error:
            with self.hold():
                pass
        self.assertEqual(error.exception.publication["status"], "HOLD_UNCONFIRMED")
        self.close.assert_called_once_with(81)


if __name__ == "__main__":
    unittest.main()
