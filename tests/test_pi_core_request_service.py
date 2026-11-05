"""Focused connected caller checks; no live socket, process or effect is used."""

import json
import os
import socket
import subprocess
import unittest
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_request_service as service


class PiRequestServiceTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root_channel = mock.Mock(spec=socket.socket)
        self.sensor_channel = mock.Mock(spec=socket.socket)
        self.root_channel.fileno.return_value = 51
        self.sensor_channel.fileno.return_value = 52
        self.sensor_channel.getsockopt.side_effect = lambda level, option: {
            service.channel._DOMAIN: socket.AF_UNIX, socket.SO_TYPE: socket.SOCK_STREAM}[option]
        for owner, name in ((socket, "socket"), (socket, "socketpair"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("live operation forbidden in Pi caller checks")))
        self.stack.enter_context(mock.patch.object(service.channel.time, "monotonic", return_value=100.0))
        self.base = SimpleNamespace(expected_peer_uid=2101, expected_peer_gid=2102)
        self.config = SimpleNamespace(broker=SimpleNamespace(broker=SimpleNamespace(broker=self.base)))
        self.validate = self.stack.enter_context(mock.patch.object(service.v5, "_validate_config"))
        self.recover = self.stack.enter_context(mock.patch.object(service.recovery,
            "recover_pi_runtime_capability_grant", return_value={"status": "AVAILABLE"}))
        self.peer = self.stack.enter_context(mock.patch.object(service.broker, "_peer_credentials",
            return_value=(300, 2101, 2102)))
        self.pidfd = self.stack.enter_context(mock.patch.object(service.process, "open_peer_pidfd", return_value=71))
        self.live = self.stack.enter_context(mock.patch.object(service.channel, "require_peer_live"))
        self.events = []
        self.close = self.stack.enter_context(mock.patch.object(service.os, "close",
            side_effect=lambda fd: self.events.append(("close", fd))))
        self.authority = SimpleNamespace(deadline=115.0, request_digest="sha256:" + "a" * 64,
            activation={"runtime_digest": "sha256:" + "b" * 64,
                        "active_skill_digest": "sha256:" + "c" * 64,
                        "policy_digest": "sha256:" + "d" * 64},
            finish=mock.Mock(side_effect=lambda *_: self.events.append("DONE")))

        @contextmanager
        def held(connection, **options):
            self.events.append("origin_enter")
            self.assertIs(connection, self.root_channel)
            self.assertEqual(options, {"expected_supervisor_peer": (200, 0, 0), "deadline": 120.0})
            try:
                yield self.authority
            finally:
                self.events.append("origin_exit")

        self.hold = self.stack.enter_context(mock.patch.object(service.handoff,
            "hold_broker_request_authority", side_effect=held))
        self.envelope = {"request": {"policy_version": 1}, "effect": {"target_name": "output.txt"}}
        self.value = {"issuance": {"profiled_submission": {"envelope": self.envelope}}}
        self.read = self.stack.enter_context(mock.patch.object(service.broker, "_read_frame", return_value=self.value))
        self.result = {"effect_status": "CREATED", "fixture": "reviewed-broker-result"}
        self.mediate = self.stack.enter_context(mock.patch.object(service, "mediate_pi_runtime_create",
            side_effect=lambda *_args, **_kwargs: self.events.append("mediate") or self.result))
        self.result_validate = self.stack.enter_context(mock.patch.object(service.worker, "_broker_result",
            side_effect=lambda value, *_: value))
        self.send = self.stack.enter_context(mock.patch.object(service.broker, "_send_frame",
            side_effect=lambda *_: self.events.append("sensor_result")))
        self.legacy = self.stack.enter_context(mock.patch.object(service.v5,
            "mediate_lineage_granted_profiled_runtime_create",
            side_effect=AssertionError("Pi cannot fall back to legacy mediator")))

    def run_request(self, **options):
        fields = {"expected_supervisor_pid": 200, "deadline": 120.0, **options}
        return service.handle_pi_broker_request(self.root_channel, self.sensor_channel, self.config, **fields)

    def assert_borrowed_connections_open(self):
        self.root_channel.close.assert_not_called()
        self.sensor_channel.close.assert_not_called()
        self.legacy.assert_not_called()

    def test_authenticated_inputs_route_once_and_cleanup_before_success(self):
        result = self.run_request()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertTrue(result["sensor_pidfd_closed"])
        self.assertFalse(result["phase3_exit_eligible"])
        self.assertEqual(self.events, ["origin_enter", "mediate", "sensor_result", ("close", 71), "DONE", "origin_exit"])
        self.mediate.assert_called_once_with(self.value, self.config, authority=self.authority, deadline_monotonic=115.0)
        self.assertIsNot(self.mediate.call_args.args[0], self.value)
        self.close.assert_called_once_with(71)
        self.read.assert_called_once_with(self.sensor_channel, 115.0)
        self.assertEqual(json.loads(self.send.call_args.args[1]), self.result)
        envelope, response = self.authority.finish.call_args.args
        self.assertEqual(envelope, self.envelope)
        self.assertEqual(response["request_digest"], self.authority.request_digest)
        self.assertEqual(response["status"], "COMPLETED")
        self.assert_borrowed_connections_open()

    def test_malformed_supervisor_pid_refuses_before_authentication(self):
        for pid in (True, 0, -1, 2**31):
            with self.subTest(pid=pid), self.assertRaises(service.broker.RuntimeActionBrokerError):
                self.run_request(expected_supervisor_pid=pid)
        self.validate.assert_not_called()
        self.hold.assert_not_called()

    def test_expired_deadline_cannot_be_renewed(self):
        with self.assertRaises(RuntimeError):
            self.run_request(deadline=99.0)
        self.hold.assert_not_called()
        self.mediate.assert_not_called()

    def test_config_refusal_does_not_accept_either_channel(self):
        self.validate.side_effect = service.broker.RuntimeActionBrokerError("unsafe config")
        with self.assertRaises(service.broker.RuntimeActionBrokerError):
            self.run_request()
        self.hold.assert_not_called()
        self.pidfd.assert_not_called()

    def test_same_descriptor_cannot_supply_both_authorities(self):
        self.sensor_channel.fileno.return_value = 51
        with self.assertRaisesRegex(service.broker.RuntimeActionBrokerError, "distinct"):
            self.run_request()
        self.hold.assert_not_called()

    def test_nonunix_sensor_channel_is_refused(self):
        self.sensor_channel.getsockopt.return_value = socket.AF_INET
        self.sensor_channel.getsockopt.side_effect = None
        with self.assertRaises(service.broker.RuntimeActionBrokerError):
            self.run_request()
        self.pidfd.assert_not_called()

    def test_wrong_sensor_credentials_refuse_before_request_read(self):
        self.peer.return_value = (300, 9999, 2102)
        with self.assertRaises(service.broker.RuntimeActionBrokerError):
            self.run_request()
        self.read.assert_not_called()
        self.mediate.assert_not_called()

    def test_origin_custody_refusal_has_no_fallback_and_closes_sensor_fd(self):
        self.hold.side_effect = RuntimeError("root proof refused")
        with self.assertRaises(service.broker.RuntimeActionBrokerError):
            self.run_request()
        self.mediate.assert_not_called()
        self.close.assert_called_once_with(71)
        self.assert_borrowed_connections_open()

    def test_sensor_exit_before_mediation_is_a_refusal(self):
        self.live.side_effect = RuntimeError("sensor exited")
        with self.assertRaises(service.broker.RuntimeActionBrokerError) as error:
            self.run_request()
        self.assertNotIsInstance(error.exception, service.broker.RuntimeActionEffectIndeterminate)
        self.mediate.assert_not_called()
        self.close.assert_called_once_with(71)

    def test_indeterminate_mediator_never_retries_or_reports_success(self):
        self.mediate.side_effect = service.broker.RuntimeActionEffectIndeterminate("link uncertain")
        with self.assertRaises(service.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.mediate.assert_called_once()
        self.authority.finish.assert_not_called()
        self.send.assert_not_called()
        self.assert_borrowed_connections_open()

    def test_malformed_return_after_mediation_is_indeterminate(self):
        self.result_validate.side_effect = service.worker.RuntimeActionWorkerError("result changed")
        with self.assertRaises(service.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.authority.finish.assert_not_called()
        self.send.assert_not_called()

    def test_sensor_response_loss_after_mediation_is_indeterminate(self):
        self.send.side_effect = OSError("response lost")
        with self.assertRaises(service.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.send.assert_called_once()
        self.authority.finish.assert_not_called()
        self.close.assert_called_once_with(71)

    def test_sensor_close_failure_prevents_done_without_close_retry(self):
        self.close.side_effect = OSError("close uncertain")
        with self.assertRaises(service.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.authority.finish.assert_not_called()
        self.close.assert_called_once_with(71)

    def test_root_result_loss_is_indeterminate_and_not_resent(self):
        self.authority.finish.side_effect = OSError("DONE lost")
        with self.assertRaises(service.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.authority.finish.assert_called_once()
        self.close.assert_called_once_with(71)

    def test_sensor_exit_after_effect_prevents_completed_result(self):
        self.live.side_effect = [None, None, RuntimeError("sensor exited")]
        with self.assertRaises(service.broker.RuntimeActionEffectIndeterminate):
            self.run_request()
        self.authority.finish.assert_not_called()
        self.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
