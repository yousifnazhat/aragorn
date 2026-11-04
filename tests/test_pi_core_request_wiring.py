"""Only changed root/sensor join, EOF and native caller integration behavior.

Reuse fixture setup without inheriting or running historical TestCases. All
processes, sockets, identities and effects are mocked; no live operation occurs.
"""

import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_request_handoff as handoff
from aragorn import pi_core_request_service as service
from aragorn import pi_core_sensor_channel as channel
from aragorn import pi_core_native_request as native_request
from aragorn import pi_core_native_supervisor as native
from aragorn import pi_core_confined_launch as confined
from tests import test_pi_core_request_handoff as root_fixtures
from tests import test_pi_core_request_service as service_fixtures
from tests import test_pi_core_identity_supervisor as native_fixtures
from tests import test_pi_core_confined_launch as bootstrap_fixtures


class RootSensorJoinTests(unittest.TestCase):
    def setUp(self):
        self.fixture = root_fixtures.RootReaderTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        connection = mock.Mock()
        connection.fileno.return_value = 3
        self.config = channel.PiSensorChannel(connection, (500, 2201, 2202))
        self.finish = mock.Mock(side_effect=lambda result: self.fixture.events.append("sensor_done"))

        @contextmanager
        def held(custody, actual_worker, request, **options):
            self.assertIs(custody, self.config.connection)
            self.assertIs(actual_worker, self.fixture.worker)
            self.assertEqual(request, root_fixtures.request())
            self.assertEqual(options, {"expected_sensor_peer": self.config.expected_peer, "deadline": 120.0})
            self.fixture.events.append("sensor_ready")
            try:
                yield SimpleNamespace(finish=self.finish)
            finally:
                self.fixture.events.append("sensor_exit")

        self.hold = self.enterContext(mock.patch.object(channel, "hold_pi_sensor_channel", side_effect=held))

    def test_root_actual_request_sensor_ready_and_cleanup_precede_worker_response(self):
        result = self.fixture.handle(sensor_channel=self.config)
        self.assertEqual(result, root_fixtures.result())
        self.finish.assert_called_once_with(result["broker_result"])
        self.assertEqual(self.fixture.events, ["lineage_enter", "sensor_ready", "OFFER", "CURRENT",
            "sensor_done", "sensor_exit", "lineage_exit", ("close", 71), ("close", 81), "worker_response"])
        self.config.connection.close.assert_not_called()

    def test_missing_sensor_readiness_prevents_root_broker_offer(self):
        self.hold.side_effect = channel.PiSensorChannelError("measurement refused")
        result = self.fixture.handle(sensor_channel=self.config)
        self.assertEqual(result["status"], "NOT_SUBMITTED")
        self.fixture.send.assert_not_called()

    def test_sensor_cleanup_result_mismatch_cannot_report_completed(self):
        self.finish.side_effect = channel.PiSensorChannelError("DONE differs")
        result = self.fixture.handle(sensor_channel=self.config)
        self.assertEqual(result["status"], "INDETERMINATE")
        self.finish.assert_called_once()

    def test_plain_sensor_configuration_is_not_channel_authority(self):
        with self.assertRaises(handoff.PiRequestHandoffError):
            self.fixture.handle(sensor_channel={"connection": self.config.connection})
        self.fixture.read.assert_not_called()

    def test_sensor_and_broker_channel_alias_refuses_before_read(self):
        self.config.connection.fileno.return_value = 2
        with self.assertRaises(handoff.PiRequestHandoffError):
            self.fixture.handle(sensor_channel=self.config)
        self.fixture.read.assert_not_called()

    def test_native_custody_guard_rechecked_through_sensor_completion(self):
        custody = object.__new__(native_request.PiNativeRequestCustody)
        with mock.patch.object(native_request.PiNativeRequestCustody, "deadline", new_callable=mock.PropertyMock, return_value=120), \
             mock.patch.object(native_request.PiNativeRequestCustody, "guard") as guard:
            result = self.fixture.handle(sensor_channel=self.config, native_custody=custody)
            self.assertEqual(result["status"], "COMPLETED")
            self.assertGreaterEqual(guard.call_count, 7)

    def test_plain_or_renewed_native_custody_refuses_before_read(self):
        with self.assertRaises(handoff.PiRequestHandoffError):
            self.fixture.handle(native_custody={"authorized": True})
        custody = object.__new__(native_request.PiNativeRequestCustody)
        with mock.patch.object(native_request.PiNativeRequestCustody, "deadline", new_callable=mock.PropertyMock, return_value=119):
            with self.assertRaises(handoff.PiRequestHandoffError):
                self.fixture.handle(native_custody=custody)
        self.fixture.read.assert_not_called()


class BrokerResultEOFTests(unittest.TestCase):
    def setUp(self):
        self.fixture = service_fixtures.PiRequestServiceTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.sensor_channel.shutdown.side_effect = lambda how: self.fixture.events.append(("sensor_eof", how))

    def test_sensor_response_eof_precedes_root_done_and_owned_fd_close(self):
        result = self.fixture.run_request()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(self.fixture.events, ["origin_enter", "mediate", "sensor_result",
            ("sensor_eof", service.socket.SHUT_WR), ("close", 71), "DONE", "origin_exit"])
        self.fixture.sensor_channel.shutdown.assert_called_once_with(service.socket.SHUT_WR)
        self.fixture.assert_borrowed_connections_open()

    def test_uncertain_sensor_half_close_retains_indeterminate_and_no_done(self):
        self.fixture.sensor_channel.shutdown.side_effect = OSError("EOF uncertain")
        with self.assertRaises(service.broker.RuntimeActionEffectIndeterminate):
            self.fixture.run_request()
        self.fixture.authority.finish.assert_not_called()
        self.fixture.sensor_channel.shutdown.assert_called_once()
        self.fixture.close.assert_called_once_with(71)


class NativeRequestIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = native_fixtures.IdentitySupervisorTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.config = native_request.PiNativeRequestChannels(mock.Mock(), mock.Mock(),
            (500, 2201, 2202), (600, 2301, 2302), mock.sentinel.binding)
        self.observation = {"status": "NO_REQUEST", "cleanup": "NOT_ATTEMPTED", "phase3_exit_eligible": False}
        self.dispatch = SimpleNamespace(observation=self.observation, read_bootstrap_result=mock.Mock())
        self.enter_failure = self.close_failure = self.read_failure = None

        @contextmanager
        def held(owned, config, **options):
            self.assertIs(owned, self.fixture.owned)
            self.assertIs(config, self.config)
            self.assertEqual(options["deadline"], 115.0)
            self.assertEqual(options["cleanup_deadline"], 120.0)
            self.fixture.events.append("request_open")
            if self.enter_failure:
                raise self.enter_failure
            try:
                yield self.dispatch
            finally:
                self.fixture.events.append("request_close")
                if self.close_failure:
                    self.observation["cleanup"] = "CLEANUP_HOLD"
                    raise self.close_failure
                self.observation["cleanup"] = "VERIFIED_OWNED_REQUEST_CLEANUP"

        self.hold = self.enterContext(mock.patch.object(native_request, "hold_native_pi_request_dispatch", side_effect=held))

        def exchange(plan, connection, *, expected_pid, on_activation, **options):
            on_activation(self.fixture.document)
            self.fixture.events.append("START")
            self.assertIs(options["read_result"], self.dispatch.read_bootstrap_result)
            if self.read_failure:
                raise self.read_failure
            options["read_result"](connection, 115.0)
            self.fixture.events.append("RESULT")
            options["on_before_release"]()
            self.fixture.events.append("RELEASE")
            return {"status": "PROVIDER_UNAVAILABLE"}

        self.fixture.exchange.side_effect = exchange

    def run_worker(self, **kwargs):
        return self.fixture.run_worker(request_channels=self.config, **kwargs)

    def test_native_holds_original_budgets_and_closes_request_before_identity_revoke_release(self):
        result = self.run_worker()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertEqual(result["request_channel"], self.observation)
        self.assertEqual(self.fixture.events, ["lease_enter", "request_open", "capture_activation", "registered",
            "START", "RESULT", "request_close", "revoke_attempt", "revoked", "RELEASE", "cleanup", "lease_exit"])
        self.assertFalse(result["request_channel"]["phase3_exit_eligible"])
        self.config.broker_connection.close.assert_not_called()
        self.config.sensor_connection.close.assert_not_called()

    def test_request_cleanup_failure_blocks_release_and_is_top_level_hold(self):
        self.close_failure = native_request.PiNativeRequestError("custody close uncertain")
        result = self.run_worker()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["request_channel"]["cleanup"], "CLEANUP_HOLD")
        self.assertNotIn("RELEASE", self.fixture.events)
        self.assertEqual(self.fixture.events.count("request_close"), 1)
        self.assertEqual(result["identity_registration"]["status"], "REVOKED")

    def test_request_read_failure_still_closes_scope_without_release(self):
        self.read_failure = RuntimeError("request refused")
        result = self.run_worker(identity=False)
        self.assertEqual(result["status"], "REFUSED")
        self.assertNotIn("RELEASE", self.fixture.events)
        self.assertEqual(self.fixture.events.count("request_close"), 1)
        self.fixture.cleanup.assert_called_once()

    def test_partial_endpoint_acquisition_preserves_cleanup_hold(self):
        self.enter_failure = native_request.PiNativeRequestError("partial endpoint cleanup uncertain")
        self.enter_failure.observation = {"status": "NO_REQUEST", "cleanup": "CLEANUP_HOLD"}
        result = self.run_worker()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["request_channel"], self.enter_failure.observation)
        self.fixture.command.assert_not_called()

    def test_plain_request_configuration_refuses_before_prerequisites(self):
        with self.assertRaises(native.PiNativeSupervisorError):
            self.fixture.run_worker(request_channels={"authorized": True})
        self.fixture.prereq.assert_not_called()


class BootstrapResultHookTests(unittest.TestCase):
    def setUp(self):
        self.fixture = bootstrap_fixtures.BootstrapCompositionTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.reader = mock.Mock(return_value=self.fixture.result)

    def exchange(self, **options):
        return confined.exchange_prepared_pi_bootstrap(self.fixture.plan, self.fixture.connection,
            expected_pid=1234, read_result=self.reader, **options)

    def test_result_hook_only_replaces_result_read_and_preserves_release(self):
        before_release = mock.Mock()
        result = self.exchange(on_before_release=before_release)
        self.fixture.read.assert_called_once_with(self.fixture.connection, 20.0)
        self.reader.assert_called_once_with(self.fixture.connection, 20.0)
        before_release.assert_called_once()
        self.assertTrue(result["release_sent"])
        self.assertFalse(result["native_cleanup_verified"])

    def test_result_hook_failure_cannot_release_or_retry(self):
        self.reader.side_effect = RuntimeError("remote custody unresolved")
        with self.assertRaises(RuntimeError):
            self.exchange()
        self.reader.assert_called_once()
        self.assertEqual(self.fixture.send.call_count, 1)

    def test_result_hook_does_not_accept_useful_task_or_authority_claim(self):
        self.reader.return_value = {**self.fixture.result, "status": "COMPLETED"}
        with self.assertRaises(ValueError):
            self.exchange()
        self.assertEqual(self.fixture.send.call_count, 1)

    def test_noncallable_hook_refuses_before_hello(self):
        self.reader = {"read_result": True}
        with self.assertRaises(ValueError):
            self.exchange()
        self.fixture.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
