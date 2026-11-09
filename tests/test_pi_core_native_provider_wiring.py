"""New caller joins only; all operating-system and transport edges stay inert."""

import copy
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import socket
import stat
import struct
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_confined_launch as confined
from aragorn import pi_core_managed_bootstrap as managed
from aragorn import pi_core_native_provider as provider
from aragorn import pi_core_native_request as request
from aragorn import pi_core_native_supervisor as native
from aragorn import pi_core_node_source_observer as node
from aragorn import pi_core_provider_mediation as mediation
from aragorn import pi_core_service_channels as services
from aragorn import pi_core_source_observer as source
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_native_request as request_fixtures
from tests import test_pi_core_native_supervisor as native_fixtures
from tests import test_pi_core_node_source_observer as node_fixtures
from tests import test_pi_core_provider_mediation as mediation_fixtures
from tests import test_pi_core_provider_start as start_fixtures


PIN = "sha256:" + "a" * 64


def completed(tool_calls=0):
    return dict(schema="aragorn/pi-core-bootstrap-result/v2", activation_id="a" * 32,
                status="WORKER_COMPLETED", authority=confined._RESULT_AUTHORITY,
                worker=dict(status="COMPLETED", stop_reason=None, provider_calls=1,
                            tool_calls=tool_calls, agent_settled=True, transcript_complete=True))


def fixture(test, kind):
    value = kind(methodName="runTest")
    value.setUp()
    test.addCleanup(value.doCleanups)
    return value


class ProviderSelectionTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, request_fixtures.InertTests)
        self.f.owned.plan = replace(self.f.owned.plan, start_bytes=canonical_json(
            dict(schema="aragorn/pi-core-bootstrap-start/v3", provider_status="PROTECTED")))
        self.p = object.__new__(provider.PiNativeProviderDispatch)
        self.p.owned = self.f.owned
        self.p.active, self.p.closed = True, False
        self.p.listener = request_fixtures.connection(40, socket.SOCK_STREAM)
        self.p._ownership = mock.Mock()
        self.p.require_completed = mock.Mock()
        self.p.serve_once = mock.Mock()
        self.f.owned._pi_provider_dispatch = self.p
        self.f.owned.provider_dispatch_active = True
        self.select = self.f.stack.enter_context(mock.patch.object(request.select, "select"))
        self.read = self.f.stack.enter_context(mock.patch.object(confined, "_read_bootstrap", return_value=completed()))

    def read_result(self):
        return self.f.dispatch.read_bootstrap_result(self.f.bootstrap, 115)

    def test_selector_services_provider_before_simultaneously_ready_action(self):
        events = []
        self.p.serve_once.side_effect = lambda deadline: events.append("provider")
        self.p.require_completed.side_effect = lambda **kw: events.append("terminal")
        self.f.request_listener.accept.return_value = (self.f.worker, "")
        self.select.side_effect = [([self.p.listener, self.f.request_listener], [], []),
                                  ([self.f.request_listener], [], []), ([self.f.bootstrap], [], [])]
        with mock.patch.object(request, "handle_native_pi_request", side_effect=lambda *a, **kw:
                (events.append("action") or {"status": "COMPLETED"})):
            self.read_result()
        self.assertEqual(events[:3], ["provider", "terminal", "action"])
        self.p.serve_once.assert_called_once_with(115)
        self.assertIn(self.p.listener, self.select.call_args.args[0])

    def test_action_is_refused_before_accept_when_provider_not_completed(self):
        self.select.return_value = ([self.f.request_listener], [], [])
        self.p.require_completed.side_effect = RuntimeError("no authenticated terminal")
        with self.assertRaisesRegex(RuntimeError, "terminal"):
            self.read_result()
        self.f.request_listener.accept.assert_not_called()
        self.f.forward.assert_not_called()

    def test_direct_action_cannot_bypass_provider_terminal_guard(self):
        self.p.require_completed.side_effect = RuntimeError("not completed")
        with self.assertRaisesRegex(RuntimeError, "not completed"):
            self.f.handle()
        self.f.forward.assert_not_called()

    def test_nested_action_guard_rechecks_provider_retirement(self):
        self.f.forward.side_effect = lambda *a, **kw: kw["native_custody"].guard()
        self.f.handle()
        self.assertEqual(self.p.require_completed.call_count, 2)

    def test_missing_provider_owner_cannot_fall_back_to_unavailable(self):
        del self.f.owned._pi_provider_dispatch
        with self.assertRaisesRegex(RuntimeError, "exact provider custody"):
            self.read_result()
        self.select.assert_not_called()

    def test_wrong_or_closed_provider_owner_refuses(self):
        for value in (SimpleNamespace(), self.p):
            self.f.owned._pi_provider_dispatch = value
            self.p.closed = True
            with self.subTest(value=type(value)), self.assertRaisesRegex(RuntimeError, "exact provider custody"):
                self.read_result()

    def test_unavailable_start_refuses_accidental_provider_owner(self):
        self.f.owned.plan = replace(self.f.owned.plan, start_bytes=b"{}")
        with self.assertRaisesRegex(RuntimeError, "unavailable START"):
            self.read_result()

    def test_forged_worker_completion_cannot_bypass_provider_terminal(self):
        self.select.return_value = ([self.f.bootstrap], [], [])
        self.p.require_completed.side_effect = RuntimeError("no terminal")
        with self.assertRaisesRegex(RuntimeError, "no terminal"):
            self.read_result()

    def test_claimed_tool_completion_requires_native_request_result(self):
        self.select.return_value = ([self.f.bootstrap], [], [])
        self.read.return_value = completed(1)
        with self.assertRaisesRegex(RuntimeError, "native request completion"):
            self.read_result()

    def test_stopped_worker_does_not_turn_refusal_into_success(self):
        self.select.return_value = ([self.f.bootstrap], [], [])
        stopped = {"status": "WORKER_STOPPED"}
        self.read.return_value = stopped
        self.assertEqual(self.read_result(), stopped)
        self.p.require_completed.assert_not_called()

    def test_provider_listener_alias_refuses_before_effect(self):
        self.p.listener = self.f.broker
        with self.assertRaisesRegex(RuntimeError, "alias"):
            self.f.handle()
        self.f.forward.assert_not_called()


class PreparedPayloadTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, mediation_fixtures.ProviderMediationTests)

    def test_exact_prepared_payload_reaches_existing_approval_once(self):
        result = self.f.run_request(expected_request=copy.deepcopy(self.f.request))
        self.assertEqual(result["status"], "COMPLETED")
        self.f.claim.assert_called_once()
        self.f.send.assert_called_once()

    def test_changed_prepared_prompt_refuses_before_approval_and_claim(self):
        expected = copy.deepcopy(self.f.request)
        expected["payload"]["messages"][0]["content"] += " changed"
        result = self.f.run_request(expected_request=expected)
        self.assertEqual((result["status"], result["failure_stage"]), ("NOT_SUBMITTED", "REQUEST"))
        self.f.claim.assert_not_called()
        self.f.load.assert_not_called()
        self.f.send.assert_not_called()

    def test_prepared_task_and_model_substitution_refuse(self):
        expected = copy.deepcopy(self.f.request)
        expected["payload"]["messages"][1]["content"] += " changed"
        expected["payload"]["model"]["id"] += "-changed"
        self.assertEqual(self.f.run_request(expected_request=expected)["status"], "NOT_SUBMITTED")
        self.f.claim.assert_not_called()

    def test_malformed_prepared_tool_refuses_before_read(self):
        expected = copy.deepcopy(self.f.request)
        expected["payload"]["messages"][0]["toolsAdded"] = []
        with self.assertRaises(RuntimeError):
            self.f.run_request(expected_request=expected)
        self.f.read.assert_not_called()


class ProviderExchangeTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, native_fixtures.InertTests)
        self.plan = replace(native_fixtures.plan(), start_bytes=canonical_json(
            dict(schema="aragorn/pi-core-bootstrap-start/v3", provider_status="PROTECTED",
                 limits={"maxRunMs": 1000})))
        self.p = object.__new__(provider.PiNativeProviderDispatch)
        self.p.owned = SimpleNamespace(plan=self.plan)
        self.events = []
        self.p.require_start = mock.Mock(side_effect=lambda *a, **kw: self.events.append("start_guard"))
        self.f.stack.enter_context(mock.patch.object(confined.os, "geteuid", return_value=0))
        self.f.stack.enter_context(mock.patch.object(confined, "_read_bootstrap", return_value=
            {"schema": "aragorn/pi-core-bootstrap-hello/v1", "worker_nonce": "a" * 32}))
        self.f.stack.enter_context(mock.patch.object(confined, "bind_pi_worker_activation", return_value={"held": True}))
        self.send = self.f.stack.enter_context(mock.patch.object(confined, "_send_frame",
            side_effect=lambda *a: self.events.append("send")))

    def exchange(self):
        return confined.exchange_prepared_pi_bootstrap(self.plan, mock.sentinel.connection,
            expected_pid=1234, provider_dispatch=self.p,
            on_activation=lambda doc: self.events.append("activation"),
            on_before_release=lambda: self.events.append("cleanup"),
            read_result=lambda *a: {**completed(), "activation_id": self.plan.prepared.activation_id})

    def test_activation_capture_then_start_guard_then_frames_then_cleanup(self):
        result = self.exchange()
        self.assertEqual(self.events, ["activation", "start_guard", "send", "cleanup", "send"])
        self.assertTrue(result["release_sent"])
        self.assertFalse(result["native_cleanup_verified"])
        self.assertEqual(self.p.require_start.call_args.kwargs["deadline"], 101.0)
        self.assertEqual([call.args[2] for call in self.send.call_args_list], [101.0, 101.0])

    def test_failed_start_guard_sends_no_frame_and_plan_cannot_retry(self):
        self.p.require_start.side_effect = RuntimeError("observer absent")
        with self.assertRaisesRegex(RuntimeError, "observer absent"):
            self.exchange()
        self.send.assert_not_called()
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.exchange()


class ProviderNativeCallerTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, native_fixtures.NativeOrchestrationTests)
        self.config = start_fixtures.configuration()
        self.f.plan = replace(self.f.plan, worker_uid=self.config.worker_uid, worker_gid=self.config.worker_gid,
            source_observation=self.config.source_observation,
            source_observation_digest=canonical_digest(self.config.source_observation))
        self.channels = request.PiNativeRequestChannels(mock.Mock(), mock.Mock(), (4, 5, 6), (7, 8, 9), mock.Mock())
        lease = object.__new__(services.PiServiceChannels)
        lease._request_channels = self.channels
        self.provider_channels = provider.PiNativeProviderChannels(mock.Mock(), lease)
        self.r = mock.Mock(observation={"status": "NO_REQUEST", "cleanup": "VERIFIED_OWNED_REQUEST_CLEANUP"})
        self.p = mock.Mock(observation={"status": "NO_PROVIDER_REQUEST", "cleanup": "VERIFIED_OWNED_PROVIDER_CLEANUP"})
        self.f.stack.enter_context(mock.patch.object(native, "_start", return_value=self.f.plan.start_bytes))

        @contextmanager
        def hold_request(*args, **kw):
            self.f.events.append("request_open")
            try:
                yield self.r
            finally:
                self.f.events.append("request_close")

        @contextmanager
        def hold_provider(*args, **kw):
            self.f.events.append("provider_open")
            self.p.owned = args[0]
            try:
                yield self.p
            finally:
                self.f.events.append("provider_close")

        self.f.stack.enter_context(mock.patch.object(request, "hold_native_pi_request_dispatch", side_effect=hold_request))
        self.hold_provider = self.f.stack.enter_context(mock.patch.object(provider,
            "hold_native_pi_provider_dispatch", side_effect=hold_provider))

        def observer(owned, *args, **kw):
            value = object.__new__(source.PiSourceObserver)
            value._owned = owned
            return value

        self.f.stack.enter_context(mock.patch.object(node, "start_node_observer", side_effect=observer))
        self.f.stack.enter_context(mock.patch.object(source.PiSourceObserver, "observation", new_callable=mock.PropertyMock, return_value={}))
        self.f.stack.enter_context(mock.patch.object(source.PiSourceObserver, "health_observation", new_callable=mock.PropertyMock, return_value={}))

        def exchange(plan, connection, **kw):
            self.assertIs(kw["provider_dispatch"], self.p)
            self.assertEqual(kw["read_result"], self.r.read_bootstrap_result)
            kw["on_activation"]({"fixture": "activation"})
            kw["on_before_release"]()
            self.f.events.append("release")
            return {"result": completed()}

        self.f.exchange.side_effect = exchange

    def run_worker(self, **changes):
        options = dict(config=self.config, request_channels=self.channels, provider_channels=self.provider_channels)
        options.update(changes)
        return native.run_native_pi_worker(object(), {}, profile=self.f.plan.profile, grant={},
            protected_root=Path("/var/lib/aragorn/admitted"), runtime_conformance_digest=PIN,
            deployment={}, revoked_context_ids=(), now_unix=1, deadline=120, **options)

    def test_native_caller_opens_both_then_closes_before_release_and_unit_cleanup(self):
        result = self.run_worker()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertEqual(self.f.events, ["lease_enter", "request_open", "provider_open",
            "request_close", "provider_close", "release", "cleanup", "lease_exit"])
        self.assertEqual(self.hold_provider.call_args.kwargs["cleanup_deadline"], 120)

    def test_enabled_config_requires_channels_before_prerequisites(self):
        with self.assertRaisesRegex(RuntimeError, "supplied together"):
            self.run_worker(provider_channels=None)
        self.f.prereq.assert_not_called()

    def test_provider_and_action_must_share_exact_service_lease(self):
        with self.assertRaisesRegex(RuntimeError, "same service lease"):
            self.run_worker(request_channels=replace(self.channels))
        self.f.prereq.assert_not_called()

    def test_provider_cleanup_hold_is_not_promoted_by_bootstrap(self):
        self.p.observation = {"status": "PROVIDER_INDETERMINATE", "cleanup": "CLEANUP_HOLD"}
        self.assertEqual(self.run_worker()["status"], "CLEANUP_HOLD")

    def test_unavailable_managed_lifecycle_rejects_enabled_config_before_activation(self):
        with mock.patch.object(managed.lifecycle, "hold_native_pi_services") as start:
            with self.assertRaisesRegex(RuntimeError, "credential, egress and approval"):
                managed.run_native_pi_service_bootstrap(None, None, profile=None, grant=None,
                    protected_root=None, runtime_conformance_digest=None, deployment=None,
                    revoked_context_ids=(), now_unix=1, deadline=120, config=self.config,
                    service_runtime=None, service_configuration=None, provider_inputs=None, binding=None)
            start.assert_not_called()


class ObserverProviderChannelTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, node_fixtures.NodeAcquisitionTests)
        self.p = object.__new__(provider.PiNativeProviderDispatch)
        self.p.owned, self.p.active, self.p.closed = self.f.owned, True, False
        self.p._ownership = mock.Mock()
        self.f.owned._pi_provider_dispatch = self.p
        self.f.owned.provider_dispatch_active = True
        self.endpoint = "/run/aragorn-pi-bootstrap/provider/provider.sock"

    def channel(self, endpoint=None):
        target = self.endpoint if endpoint is None else endpoint
        class InertSocket:
            def __init__(self, fileno=None):
                pass
            def fileno(self):
                return 23
            def getpeername(self):
                return target
            def getsockname(inner):
                return self.endpoint
            def getsockopt(self, level, option, *args):
                if option == socket.SO_PEERCRED:
                    return struct.pack("3i", 99, 0, 0)
                return socket.AF_UNIX if option == 39 else socket.SOCK_STREAM
            def detach(self):
                return 19
        self.p.listener = InertSocket()
        with mock.patch.object(node, "_fd_identity", return_value={"device": 1, "inode": 2, "mode": stat.S_IFSOCK}), \
             mock.patch.object(node.socket, "SO_PEERCRED", 17, create=True), \
             mock.patch.object(node.os, "getpid", return_value=99), mock.patch.object(node.socket, "socket", InertSocket):
            return self.f.session._channel(8, 19)

    def test_observer_recognizes_only_actual_held_provider_listener(self):
        value, _ = self.channel()
        self.assertEqual(value["endpoint"], self.endpoint)
        self.p._ownership.assert_called_once()

    def test_observer_rejects_another_root_endpoint(self):
        with self.assertRaisesRegex(RuntimeError, "UNOWNED_ROOT_ENDPOINT"):
            self.channel("/run/unowned.sock")

    def test_observer_refuses_retired_provider_listener(self):
        self.p.active = False
        with self.assertRaisesRegex(RuntimeError, "PROVIDER_CUSTODY"):
            self.channel()


if __name__ == "__main__":
    unittest.main()
