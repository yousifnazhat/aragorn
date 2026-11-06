"""Inert identity-registration checks; no sockets, processes or effects run.

Transport and kernel-observation boundaries are mocked. The paired protocol
replay executes both real state machines sequentially against the same packet
transcript; it is not concurrent transport or native qualification evidence.
"""

from contextlib import ExitStack
import copy
from dataclasses import replace
import json
from pathlib import Path
import socket
import subprocess
import unittest
from unittest import mock

from aragorn import pi_core_identity_handoff as handoff
from aragorn import pi_core_identity_relay as relay
from aragorn import pi_core_worker_identity as identity
from aragorn import runtime_action_worker as worker
from aragorn.oci_worker_protocol import canonical_digest


class PiIdentityRelayTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.connection = mock.Mock(spec=socket.socket)
        for owner, name in ((socket, "socket"), (socket, "socketpair"),
                            (subprocess, "run"), (subprocess, "Popen")):
            self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("live operation forbidden")))
        self.stack.enter_context(mock.patch.object(relay.time, "monotonic", return_value=90.0))
        self.stack.enter_context(mock.patch.object(relay.time, "monotonic_ns", return_value=90_000_000_000))
        self.stack.enter_context(mock.patch.object(relay.secrets, "token_hex", return_value="1" * 32))
        self.stack.enter_context(mock.patch.object(worker.os, "geteuid", return_value=1001))
        self.stack.enter_context(mock.patch.object(worker.os, "getegid", return_value=1002))
        self.stack.enter_context(mock.patch.object(worker.os, "getgroups", return_value=[1002, 2002]))
        self.dispatch = self.stack.enter_context(mock.patch.object(worker, "_relay_request",
            side_effect=AssertionError("identity registration cannot dispatch requests")))
        for name in ("read_activation", "_boot_id", "_measured"):
            self.stack.enter_context(mock.patch.object(identity, name,
                side_effect=AssertionError("relay cannot remeasure protected activation/process/boot")))
        self.config = worker.RuntimeActionWorkerConfig(
            socket_path=Path("/run/aragorn-relay/worker.sock"),
            runtime_directory=Path("/run/aragorn-relay"),
            sensor_socket_path=Path("/run/aragorn-sensor/sensor.sock"),
            protected_root=Path("/var/lib/aragorn/protected"),
            expected_worker_uid=1001, expected_worker_gid=1002,
            expected_gateway_uid=2001, expected_gateway_gid=2002,
            expected_sensor_uid=3001, expected_sensor_gid=3002, expected_broker_uid=4001,
            binding=worker.RuntimeActionWorkerBinding("sha256:" + "b" * 64,
                "sha256:" + "c" * 64, "sha256:" + "d" * 64, 1))
        self.activation = {
            "schema": identity.ACTIVATION_SCHEMA, "authority": identity.ACTIVATION_AUTHORITY,
            "activation_id": "2" * 32, "session_id": "2" * 32, "run_id": "2" * 32,
            "pid": 5000, "uid": 2001, "gid": 2002, "start_time_ticks": 123,
            "mount_namespace": {"device": 4, "inode": 5},
            "cgroup": "/system.slice/aragorn-pi-" + "3" * 32 + ".service",
            "boot_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "expires_at_monotonic_ns": 99_000_000_000,
            **{name: "sha256:" + "a" * 64 for name in identity._PINS},
        }
        self.activation.update(runtime_digest=self.config.binding.runtime_digest,
            active_skill_digest=self.config.binding.active_skill_digest,
            policy_digest=self.config.binding.policy_digest)
        self.digest = canonical_digest(self.activation)
        self.fields = dict(nonce="1" * 32, activation_digest=self.digest, deadline_ns=99_000_000_000)
        self.packets = [(relay._packet("HANDOFF", activation=copy.deepcopy(self.activation), **self.fields), (81,)),
                        (relay._packet("REVOKE", **self.fields), ())]
        self.events = []
        self.sent = []
        self.receive_index = 0
        self.guard = self.stack.enter_context(mock.patch.object(handoff, "guard_channel", return_value=80))
        self.live = self.stack.enter_context(mock.patch.object(handoff, "require_peer_live"))
        self.pidfd = self.stack.enter_context(mock.patch.object(handoff, "validate_worker_pidfd"))
        self.sender = self.stack.enter_context(mock.patch.object(handoff, "send_packet", side_effect=self.send))
        self.receiver = self.stack.enter_context(mock.patch.object(handoff, "receive_packet", side_effect=self.receive))
        self.close = self.stack.enter_context(mock.patch.object(relay.os, "close", side_effect=self.closed))

    def send(self, connection, document, deadline, *, rights=()):
        self.assertEqual(rights, ())
        self.events.append(document["kind"])
        self.sent.append(copy.deepcopy(document))

    def receive(self, connection, peer, deadline, *, expected_rights=0):
        self.assertEqual(peer, (4000, 0, 0))
        self.assertLessEqual(deadline, 100.0)
        document, rights = self.packets[self.receive_index]
        self.receive_index += 1
        self.assertEqual(len(rights), expected_rights)
        return document, rights

    def closed(self, descriptor):
        self.events.append(("close", descriptor))

    def consume(self, **changes):
        parameters = dict(expected_supervisor_pid=4000, deadline=100.0)
        parameters.update(changes)
        return relay.consume_pi_identity_handoff(self.connection, self.config, **parameters)

    def refuse(self, **changes):
        with self.assertRaises(relay.PiIdentityRelayError) as raised:
            self.consume(**changes)
        observation = raised.exception.observation
        self.assertEqual(observation["status"], "REFUSED")
        self.assertFalse(observation["registration_active"])
        self.assertTrue(observation["registration_withdrawn"])
        self.assertFalse(observation["request_authorized"])
        self.assertFalse(observation["effect_authorized"])
        self.dispatch.assert_not_called()
        self.connection.close.assert_not_called()
        return observation

    def change_activation(self, field, value):
        self.packets[0][0]["activation"][field] = value
        self.packets[0][0]["activation_digest"] = canonical_digest(self.packets[0][0]["activation"])

    def test_registration_and_revocation_do_not_authorize_requests(self):
        result = self.consume()
        self.assertEqual(result["status"], "IDENTITY_REGISTERED_AND_REVOKED")
        self.assertEqual(result["scope"], "IDENTITY_ONLY_NOT_REQUEST_OR_EFFECT_AUTHORITY")
        self.assertTrue(result["registration_observed"] and result["registration_withdrawn"])
        self.assertFalse(result["registration_active"] or result["request_authorized"] or result["effect_authorized"])
        self.assertFalse(result["phase3_exit_eligible"])
        self.assertEqual(result["activation_digest"], self.digest)
        self.assertLess(len(json.dumps(result)), 2048)
        self.assertNotIn("activation", result)
        self.assertEqual([row["kind"] for row in self.sent], ["CHALLENGE", "REGISTERED", "REVOKED"])
        self.assertEqual(self.events, ["CHALLENGE", "REGISTERED", ("close", 81), "REVOKED", ("close", 80)])
        self.dispatch.assert_not_called()
        self.connection.close.assert_not_called()
        self.guard.assert_called_once_with(self.connection, (4000, 0, 0), 100.0)
        self.assertEqual(self.pidfd.call_args_list, [mock.call(81, 5000)] * 3)

    def test_invalid_supervisor_pid_is_rejected_before_channel(self):
        self.refuse(expected_supervisor_pid=True)
        self.guard.assert_not_called()
        self.close.assert_not_called()

    def test_expired_original_deadline_is_rejected_before_channel(self):
        self.refuse(deadline=89.0)
        self.guard.assert_not_called()

    def test_wrong_process_configuration_refuses_before_channel(self):
        with mock.patch.object(worker.os, "geteuid", return_value=9001):
            self.refuse()
        self.guard.assert_not_called()

    def test_root_consumer_is_explicitly_rejected(self):
        self.config = replace(self.config, expected_worker_uid=0)
        with mock.patch.object(worker, "_validate_config"):
            self.refuse()
        self.guard.assert_not_called()

    def test_wrong_root_peer_credentials_are_rejected(self):
        self.guard.side_effect = handoff.PiIdentityHandoffError("wrong root peer")
        self.refuse()
        self.sender.assert_not_called()

    def test_handoff_cannot_replay_a_previous_challenge(self):
        self.packets[0][0]["nonce"] = "9" * 32
        self.refuse()
        self.assertEqual(self.close.call_args_list, [mock.call(81), mock.call(80)])

    def test_handoff_wrong_phase_is_rejected(self):
        self.packets[0][0]["kind"] = "REVOKE"
        self.refuse()
        self.assertNotIn("REGISTERED", self.events)

    def test_activation_digest_mismatch_is_rejected(self):
        self.packets[0][0]["activation_digest"] = "sha256:" + "9" * 64
        self.refuse()

    def test_worker_uid_mismatch_is_rejected(self):
        self.change_activation("uid", 2099)
        self.refuse()

    def test_worker_gid_mismatch_is_rejected(self):
        self.change_activation("gid", 2099)
        self.refuse()

    def test_runtime_pin_mismatch_is_rejected(self):
        self.change_activation("runtime_digest", "sha256:" + "9" * 64)
        self.refuse()

    def test_skill_pin_mismatch_is_rejected(self):
        self.change_activation("active_skill_digest", "sha256:" + "9" * 64)
        self.refuse()

    def test_policy_pin_mismatch_is_rejected(self):
        self.change_activation("policy_digest", "sha256:" + "9" * 64)
        self.refuse()

    def test_malformed_boot_identity_is_rejected_without_proc_read(self):
        self.change_activation("boot_id", "not-a-boot-uuid")
        self.refuse()

    def test_activation_session_run_join_is_required(self):
        self.change_activation("run_id", "9" * 32)
        self.refuse()

    def test_supervisor_cannot_be_registered_as_worker(self):
        self.change_activation("pid", 4000)
        self.refuse()

    def test_handoff_cannot_extend_original_deadline(self):
        self.change_activation("expires_at_monotonic_ns", 110_000_000_000)
        self.packets[0][0]["deadline_ns"] = 101_000_000_000
        self.refuse()

    def test_handoff_cannot_extend_activation_expiry(self):
        self.packets[0][0]["deadline_ns"] = 100_000_000_000
        self.refuse()

    def test_expired_handoff_is_refused(self):
        self.packets[0][0]["deadline_ns"] = 89_000_000_000
        self.refuse()

    def test_noninteger_deadline_is_refused(self):
        self.packets[0][0]["deadline_ns"] = 99_000_000_000.0
        self.refuse()

    def test_wrong_worker_pidfd_is_refused(self):
        self.pidfd.side_effect = handoff.PiIdentityHandoffError("PIDFD association differs")
        self.refuse()
        self.assertNotIn("REGISTERED", self.events)

    def test_root_peer_exit_after_registered_withdraws(self):
        self.live.side_effect = [None, None, handoff.PiIdentityHandoffError("root exited")]
        result = self.refuse()
        self.assertTrue(result["registration_observed"])
        self.assertNotIn("REVOKED", self.events)

    def test_worker_exit_before_revoke_ack_withdraws(self):
        self.pidfd.side_effect = [None, None, handoff.PiIdentityHandoffError("worker exited")]
        result = self.refuse()
        self.assertTrue(result["worker_pidfd_closed"])
        self.assertNotIn("REVOKED", self.events)

    def test_revocation_nonce_cannot_replay_another_registration(self):
        self.packets[1][0]["nonce"] = "9" * 32
        self.refuse()

    def test_revocation_activation_digest_must_match(self):
        self.packets[1][0]["activation_digest"] = "sha256:" + "9" * 64
        self.refuse()

    def test_revocation_deadline_must_match_exactly(self):
        self.packets[1][0]["deadline_ns"] -= 1
        self.refuse()

    def test_revocation_kind_must_be_revoke(self):
        self.packets[1][0]["kind"] = "REGISTERED"
        self.refuse()

    def test_eof_before_handoff_refuses_and_closes_peer_pidfd(self):
        # The common transport exposes framing failures as its RuntimeError.
        self.receiver.side_effect = handoff.PiIdentityHandoffError("unexpected EOF")
        self.refuse()
        self.close.assert_called_once_with(80)

    def test_truncated_ancillary_rejection_does_not_create_registration(self):
        self.receiver.side_effect = handoff.PiIdentityHandoffError("ancillary truncated; installed FDs closed")
        self.refuse()
        self.assertNotIn("REGISTERED", self.events)
        self.close.assert_called_once_with(80)

    def test_eof_after_registration_withdraws_and_closes_both_fds(self):
        self.receiver.side_effect = [self.packets[0], handoff.PiIdentityHandoffError("unexpected EOF")]
        result = self.refuse()
        self.assertTrue(result["registration_observed"])
        self.assertEqual(self.close.call_args_list, [mock.call(81), mock.call(80)])

    def test_uncertain_registered_send_never_retries(self):
        self.sender.side_effect = [None, OSError("uncertain registered send")]
        self.refuse()
        self.assertEqual(self.sender.call_count, 2)

    def test_uncertain_revoked_send_never_retries(self):
        self.sender.side_effect = [None, None, OSError("uncertain revoked send")]
        result = self.refuse()
        self.assertTrue(result["worker_pidfd_closed"])
        self.assertEqual(self.sender.call_count, 3)

    def test_worker_close_failure_prevents_revoked_ack_and_closes_supervisor(self):
        self.close.side_effect = [OSError("worker close failed"), None]
        result = self.refuse()
        self.assertFalse(result["worker_pidfd_closed"])
        self.assertTrue(result["supervisor_pidfd_closed"])
        self.assertEqual(self.close.call_args_list, [mock.call(81), mock.call(80)])
        self.assertNotIn("REVOKED", self.events)

    def test_supervisor_close_failure_prevents_success_return(self):
        self.close.side_effect = [None, OSError("supervisor close failed")]
        result = self.refuse()
        self.assertTrue(result["worker_pidfd_closed"])
        self.assertFalse(result["supervisor_pidfd_closed"])

    def test_received_activation_is_detached_from_mutable_transport_input(self):
        def mutate_after_registered(connection, document, deadline, *, rights=()):
            self.send(connection, document, deadline, rights=rights)
            if document["kind"] == "REGISTERED":
                self.packets[0][0]["activation"]["pid"] = 9999
                self.packets[0][0]["activation"]["mount_namespace"]["inode"] = 9999
        self.sender.side_effect = mutate_after_registered
        result = self.consume()
        self.assertEqual(result["activation_digest"], self.digest)
        self.assertEqual(self.pidfd.call_args_list, [mock.call(81, 5000)] * 3)

    def test_real_producer_consumer_paired_offline_protocol_replay(self):
        # Both real state machines consume the same transcript. This verifies
        # their joins, not concurrent I/O, SO_PEERCRED or Linux descriptor proof.
        expected_replies = [relay._packet("CHALLENGE", nonce=self.fields["nonce"]),
                            relay._packet("REGISTERED", **self.fields),
                            relay._packet("REVOKED", **self.fields)]
        producer_packets = []
        protected_guard = mock.Mock()
        source_activation = copy.deepcopy(self.activation)

        def retain_producer(connection, packet, deadline, *, rights=()):
            producer_packets.append((copy.deepcopy(packet), rights))

        with mock.patch.object(handoff.os, "geteuid", return_value=0), \
             mock.patch.object(handoff.os, "getegid", return_value=0), \
             mock.patch.object(identity, "_remaining") as protected_measurement, \
             mock.patch.object(handoff, "send_packet", side_effect=retain_producer), \
             mock.patch.object(handoff, "receive_packet", side_effect=[(row, ()) for row in expected_replies]):
            with handoff.hold_pi_identity_handoff(self.connection, source_activation, 71,
                    expected_relay_peer=(6000, 1001, 1002), deadline=100.0,
                    guard=protected_guard) as publication:
                self.assertEqual(publication["status"], "REGISTERED")
                # Publication must retain detached protected input, not later
                # mutations to the caller-owned mapping or nested namespace.
                source_activation["pid"] = 9999
                source_activation["mount_namespace"]["inode"] = 9999
            self.assertEqual(publication["status"], "REVOKED")
            self.assertGreater(protected_guard.call_count, 0)
            self.assertGreater(protected_measurement.call_count, 0)
            for call in protected_measurement.call_args_list:
                self.assertEqual(call.args[1]["pid"], 5000)
                self.assertEqual(call.args[1]["mount_namespace"]["inode"], 5)
        self.assertGreater(self.pidfd.call_count, 0)
        self.assertEqual(self.pidfd.call_args_list, [mock.call(71, 5000)] * self.pidfd.call_count)
        self.assertEqual([row[0]["kind"] for row in producer_packets], ["HANDOFF", "REVOKE"])
        self.assertEqual([row[1] for row in producer_packets], [(71,), ()])
        self.close.assert_called_once_with(80)  # Source71 remains publisher-owned.
        self.close.reset_mock()
        self.pidfd.reset_mock()
        self.guard.reset_mock()
        self.events.clear()
        self.sent.clear()
        self.packets = [(producer_packets[0][0], (81,)), (producer_packets[1][0], ())]
        result = self.consume()
        self.assertEqual(result["status"], "IDENTITY_REGISTERED_AND_REVOKED")
        self.assertEqual(self.sent, expected_replies)
        self.assertEqual(result["activation_digest"], publication["activation_digest"])
        self.assertEqual(self.close.call_args_list, [mock.call(81), mock.call(80)])
        self.dispatch.assert_not_called()
        self.connection.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
