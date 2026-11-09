"""New provider caller checks; native operations are forbidden unless mocked."""

import copy
import os
import socket
from dataclasses import replace
from pathlib import Path
from unittest import mock

from aragorn import pi_core_native_provider as subject
from aragorn import pi_core_node_source_observer as node_source
from aragorn import pi_core_service_channels as services
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests.test_pi_core_confined_launch import configuration
from tests.test_pi_core_native_request import InertTests, activation, connection, metadata


def start():
    return {"schema": "aragorn/pi-core-bootstrap-start/v3", "provider_status": "PROTECTED",
        "activation_id": "a" * 32, "model": copy.deepcopy(configuration().model),
        "system_prompt": "Calculate a public fabricated sum", "task": "Add 3 and 4",
        "limits": {"maxTurns": 1, "maxToolCalls": 1, "maxRunMs": 1000},
        "provider": {"route_digest": "sha256:" + "b" * 64, "max_requests": 1, "request_timeout_ms": 1000}}


class ProviderFixture(InertTests):
    def setUp(self):
        super().setUp()
        self.owned.plan = replace(self.owned.plan, start_bytes=canonical_json(start()))
        self.owned.provider_dispatch_active = False
        self.owned.provider_attempted = False
        self.owned.source_observer = self.source_observer
        self.source_observer._seal = subject.source._SEAL
        self.source_observer._state = "HELD"
        self.source_observer._attached = self.source_observer._executed = True
        self.source_observer._close_attempted = False
        self.source_observer._thread = 999
        self.node_session = object.__new__(node_source._NodeSession)
        self.node_session.observer, self.node_session.owned = self.source_observer, self.owned
        self.node_session.operation_deadline = 115
        self.node_session.ready, self.node_session.closed = mock.Mock(), mock.Mock()
        self.node_session.ready.is_set.return_value = True
        self.node_session.closed.is_set.return_value = False
        self.node_session.stopping, self.node_session.failure = False, None
        self.node_session.thread = mock.Mock(native_id=999)
        self.node_session.thread.is_alive.return_value = True
        self.node_session.lock = mock.Mock()
        self.node_session.lock.acquire.return_value = True
        self.source_observer._node_session = self.node_session
        self.budget = self.stack.enter_context(mock.patch.object(subject.source.PiSourceObserver, "_budget", autospec=True))
        self.provider = connection(7)
        self.provider_listener = connection(8, socket.SOCK_STREAM)
        self.provider_worker = connection(9, socket.SOCK_STREAM)
        self.provider_listener.accept.return_value = (self.provider_worker, "")
        self.services = object.__new__(services.PiServiceChannels)
        self.services._connections = (self.broker, self.sensor, self.provider)
        self.services._expected = {"provider": {"pid": 600, "uid": 1501, "gid": 1502}}
        self.services._deadline = 115
        self.services._provider_retired = False
        self.services._lifecycle = object.__new__(subject.PiServiceLifecycle)
        self.channels = replace(self.channels, service_custody=self.services)
        self.services._request_channels = self.channels
        self.dispatch.channels = self.channels
        self.guard = self.stack.enter_context(mock.patch.object(services.PiServiceChannels, "guard", autospec=True))
        self.config_check = self.stack.enter_context(mock.patch.object(subject.broker, "_validate_config"))
        root = Path("/var/lib/aragorn/provider-control")
        self.config = subject.broker.RuntimeActionBrokerConfig(root / "broker.sock", root / "instance.lock", root / "broker.lock",
            root, Path("/var/lib/aragorn/output"), Path("/var/lib/aragorn/staging"),
            *(root / (name + ".json") for name in ("policy", "revocations", "health", "observation", "state")),
            0, 1301, 1302, self.profile.runtime_digest, 1201, 1202)
        self.provider_channels = subject.PiNativeProviderChannels(self.config, self.services)
        self.pd = subject.PiNativeProviderDispatch(subject._SEAL, self.owned, self.provider_channels, {},
            Path("/var/lib/aragorn/admitted"), 115, 120)
        self.pd.listener = self.provider_listener
        self.pd.directory_fd = 14
        self.pd.directory_identity = subject.broker._directory_identity(metadata(70))
        self.pd.socket_identity = subject.broker._file_identity(metadata(71, directory=False, mode=0o660))
        self.pd.created = self.pd.active = self.owned.provider_dispatch_active = True
        self.owned._pi_provider_dispatch = self.pd
        self.provider_ownership = self.stack.enter_context(mock.patch.object(self.pd, "_ownership"))
        self.mediate = self.stack.enter_context(mock.patch.object(subject.mediation, "handle_pi_provider_connection",
            side_effect=self.complete))

    def complete(self, *args, **kwargs):
        self.services._provider_retired = True
        return {"status": "COMPLETED", "submission_attempted": True,
            "request_digest": canonical_digest(self.pd._expected), "provider_service_receipt_digest": "sha256:" + "c" * 64,
            "cleanup": "OWNED_HANDLES_CLOSED", "client_delivery": "FRAME_AND_EOF_SENT_NOT_ACKNOWLEDGED"}

    def begin(self):
        self.pd.require_start(activation(), deadline=115)

    def fs(self, name, **kwargs):
        return self.stack.enter_context(mock.patch.object(os, name, **kwargs))


class NativeProviderStartTests(ProviderFixture):
    def test_start_requires_exact_plan_transcript_model_and_fixed_tool(self):
        expected = self.pd._expected
        self.assertEqual(expected["payload"]["model"], start()["model"])
        self.assertEqual(expected["payload"]["messages"], [
            {"role": "system", "content": start()["system_prompt"], "timestamp": 0,
             "toolsAdded": [subject.mediation._TOOL]},
            {"role": "user", "content": [{"type": "text", "text": start()["task"]}], "timestamp": 0}])
        self.assertEqual(expected["activation_id"], activation()["activation_id"])

    def test_start_checks_custody_without_fabricating_full_source_coverage(self):
        self.begin()
        self.same.assert_called_once()
        self.budget.assert_not_called()
        self.node_session.lock.acquire.assert_called_once_with(timeout=15)
        self.node_session.lock.release.assert_called_once()
        self.source_health.assert_not_called()
        self.mediate.assert_not_called()

    def test_start_cannot_repeat_or_use_changed_activation(self):
        with self.assertRaisesRegex(RuntimeError, "activation differs"):
            self.pd.require_start({**activation(), "pid": 301}, deadline=115)
        self.begin()
        with self.assertRaisesRegex(RuntimeError, "already consumed"):
            self.begin()

    def test_start_tightens_provider_deadline_without_renewal(self):
        self.pd.require_start(activation(), deadline=101)
        self.assertEqual(self.pd.deadline, 101)
        with self.assertRaises(RuntimeError):
            self.pd.serve_once(102)
        self.provider_listener.accept.assert_not_called()

    def test_unavailable_start_never_creates_provider_dispatch(self):
        for version in ("v1", "v2"):
            plan = replace(self.owned.plan, start_bytes=canonical_json({**start(),
                "schema": "aragorn/pi-core-bootstrap-start/" + version, "provider_status": "UNAVAILABLE"}))
            with self.subTest(version=version), self.assertRaisesRegex(RuntimeError, "explicitly protected START"):
                subject._expected_request(plan)

    def test_provider_start_rejects_budget_override_and_extra_fields(self):
        for fields in ({"max_requests": 2}, {"request_timeout_ms": 1001}, {"endpoint": "elsewhere"},
                       {"max_requests": True}, {"request_timeout_ms": True}):
            document = start()
            document["provider"].update(fields)
            with self.subTest(fields=fields), self.assertRaises(RuntimeError):
                subject._expected_request(replace(self.owned.plan, start_bytes=canonical_json(document)))

    def test_provider_start_rejects_multiple_turn_or_tool_budgets(self):
        for name in ("maxTurns", "maxToolCalls"):
            document = start()
            document["limits"][name] = 2
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                subject._expected_request(replace(self.owned.plan, start_bytes=canonical_json(document)))

    def test_unsealed_unheld_and_swapped_observers_refuse_start(self):
        for field, value in (("_seal", object()), ("_state", "REFUSED"), ("_attached", False),
                             ("_executed", False), ("_close_attempted", True)):
            before = getattr(self.source_observer, field)
            setattr(self.source_observer, field, value)
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.begin()
            setattr(self.source_observer, field, before)
        self.owned.source_observer = None
        with self.assertRaises(RuntimeError):
            self.begin()

    def test_service_lifetime_is_required_not_arbitrary_authenticated_metadata(self):
        self.services._lifecycle = None
        with self.assertRaisesRegex(RuntimeError, "owned service lifetime"):
            self.begin()

    def test_node_owner_readiness_lifetime_and_lock_are_required(self):
        for field, value in (("stopping", True), ("failure", RuntimeError("owner failed")),
                             ("operation_deadline", 114)):
            original = getattr(self.node_session, field)
            setattr(self.node_session, field, value)
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.begin()
            setattr(self.node_session, field, original)
        self.node_session.lock.acquire.return_value = False
        with self.assertRaisesRegex(RuntimeError, "custody deadline expired"):
            self.begin()
        self.budget.assert_not_called()

    def test_changed_node_session_linkage_refuses_without_owner_calls(self):
        self.node_session.owned = object()
        with self.assertRaisesRegex(RuntimeError, "observation lifetime differs"):
            self.begin()
        self.budget.assert_not_called()
        self.source_health.assert_not_called()

    def test_service_request_custody_must_be_exact(self):
        self.services._request_channels = replace(self.channels, service_custody=None)
        with self.assertRaisesRegex(RuntimeError, "owned service lifetime"):
            self.begin()

    def test_provider_role_and_handle_aliases_are_refused(self):
        self.services._expected["provider"]["uid"] = 1401
        with self.assertRaisesRegex(RuntimeError, "roles overlap"):
            self.begin()
        self.services._expected["provider"]["uid"] = 1501
        self.services._connections = (self.broker, self.sensor, self.sensor)
        with self.assertRaisesRegex(RuntimeError, "alias"):
            self.begin()

    def test_wrong_policy_worker_or_install_root_refuses(self):
        self.pd.protected_root = Path("/tmp/unprotected")
        with self.assertRaisesRegex(RuntimeError, "policy differs"):
            self.begin()

    def test_retired_provider_and_changed_unit_refuse_start(self):
        self.services._provider_retired = True
        with self.assertRaises(RuntimeError):
            self.begin()
        self.services._provider_retired = False
        self.same.side_effect = RuntimeError("unit generation changed")
        with self.assertRaisesRegex(RuntimeError, "unit generation changed"):
            self.begin()


class NativeProviderDispatchTests(ProviderFixture):
    def test_one_native_request_reuses_exact_mediator_and_held_channels(self):
        self.begin()
        result = self.pd.serve_once(114)
        self.assertEqual(result["status"], "PROVIDER_RETURNED")
        self.assertTrue(self.owned.provider_attempted)
        args = self.mediate.call_args
        self.assertEqual(args.args, (self.provider_worker, self.provider, self.config))
        self.assertIs(args.kwargs["service_custody"], self.services)
        self.assertIs(args.kwargs["source_observer"], self.source_observer)
        self.assertEqual(args.kwargs["expected_request"], self.pd._expected)
        self.assertTrue(args.kwargs["provider_service"])
        self.assertEqual(args.kwargs["deadline"], 114)
        self.provider_worker.close.assert_called_once()
        for borrowed in (self.bootstrap, self.broker, self.sensor, self.provider):
            borrowed.close.assert_not_called()
        self.pd.require_completed(114)
        self.assertFalse(result["phase3_exit_eligible"])

    def test_attempt_requires_start_and_cannot_extend_budget(self):
        with self.assertRaisesRegex(RuntimeError, "START first"):
            self.pd.serve_once(115)
        self.begin()
        with self.assertRaises(RuntimeError):
            self.pd.serve_once(116)
        self.provider_listener.accept.assert_not_called()

    def test_failed_accept_consumes_attempt_without_retry(self):
        self.begin()
        self.provider_listener.accept.side_effect = TimeoutError("no worker")
        with self.assertRaises(TimeoutError):
            self.pd.serve_once(114)
        self.assertTrue(self.owned.provider_attempted)
        with self.assertRaisesRegex(RuntimeError, "already consumed"):
            self.pd.serve_once(114)
        self.provider_listener.accept.assert_called_once()
        self.mediate.assert_not_called()

    def test_second_request_never_reaches_provider(self):
        self.begin()
        self.pd.serve_once(114)
        with self.assertRaisesRegex(RuntimeError, "already consumed"):
            self.pd.serve_once(114)
        self.mediate.assert_called_once()

    def test_missing_health_refuses_before_mediation(self):
        self.begin()
        self.source_health.side_effect = RuntimeError("missing source progress")
        with self.assertRaisesRegex(RuntimeError, "missing source progress"):
            self.pd.serve_once(114)
        self.mediate.assert_not_called()
        self.provider_worker.close.assert_called_once()

    def test_generation_and_start_substitution_refuse(self):
        self.begin()
        self.owned.pid = 301
        with self.assertRaisesRegex(RuntimeError, "generation changed"):
            self.pd.serve_once(114)
        self.owned.pid = 300
        self.owned.plan = replace(self.owned.plan, start_bytes=canonical_json({**start(), "task": "another task"}))
        with self.assertRaisesRegex(RuntimeError, "launch or channels changed"):
            self.pd.serve_once(114)
        self.mediate.assert_not_called()

    def test_actual_worker_measurement_refusal_never_forwards(self):
        self.begin()
        self.measured.side_effect = lambda stream, *args: (_ for _ in ()).throw(RuntimeError("worker changed")) if stream is self.provider_worker else None
        with self.assertRaisesRegex(RuntimeError, "worker changed"):
            self.pd.serve_once(114)
        self.mediate.assert_not_called()

    def test_clean_not_submitted_refusal_never_allows_action(self):
        self.begin()
        self.mediate.side_effect = None
        self.mediate.return_value = {"status": "NOT_SUBMITTED", "submission_attempted": False,
            "cleanup": "OWNED_HANDLES_CLOSED", "client_delivery": "FRAME_AND_EOF_SENT_NOT_ACKNOWLEDGED"}
        self.assertEqual(self.pd.serve_once(114)["status"], "PROVIDER_RETURNED")
        self.assertFalse(self.pd._remote_custody_hold)
        self.assertFalse(self.services.provider_retired)
        with self.assertRaisesRegex(RuntimeError, "completion and retirement"):
            self.pd.require_completed(114)

    def test_submitted_without_retirement_preserves_hold(self):
        self.begin()
        def unretired(*args, **kwargs):
            value = self.complete()
            self.services._provider_retired = False
            return value
        self.mediate.side_effect = unretired
        with self.assertRaisesRegex(RuntimeError, "terminal or delivery"):
            self.pd.serve_once(114)
        self.assertTrue(self.pd._remote_custody_hold)
        self.assertEqual(self.pd.observation["status"], "PROVIDER_INDETERMINATE")

    def test_unconfirmed_delivery_or_cleanup_preserves_hold(self):
        self.begin()
        def undelivered(*args, **kwargs):
            return {**self.complete(), "client_delivery": "UNCONFIRMED"}
        self.mediate.side_effect = undelivered
        with self.assertRaises(RuntimeError):
            self.pd.serve_once(114)
        self.assertTrue(self.pd._remote_custody_hold)
        with self.assertRaises(RuntimeError):
            self.pd.require_completed(114)

    def test_ambiguous_mediator_exception_preserves_hold_no_retry(self):
        self.begin()
        self.mediate.side_effect = RuntimeError("transfer outcome unknown")
        with self.assertRaisesRegex(RuntimeError, "outcome unknown"):
            self.pd.serve_once(114)
        self.assertTrue(self.pd._remote_custody_hold)
        with self.assertRaises(RuntimeError):
            self.pd.serve_once(114)
        self.mediate.assert_called_once()

    def test_authenticated_indeterminate_terminal_is_not_completion(self):
        self.begin()
        self.mediate.side_effect = lambda *args, **kwargs: {**self.complete(), "status": "INDETERMINATE"}
        self.pd.serve_once(114)
        self.assertFalse(self.pd._remote_custody_hold)
        with self.assertRaisesRegex(RuntimeError, "completion and retirement"):
            self.pd.require_completed(114)

    def test_completion_cannot_reuse_different_request_receipt(self):
        self.begin()
        self.mediate.side_effect = lambda *args, **kwargs: {**self.complete(), "request_digest": "sha256:" + "d" * 64}
        self.pd.serve_once(114)
        with self.assertRaisesRegex(RuntimeError, "completion and retirement"):
            self.pd.require_completed(114)

    def test_completion_rechecks_action_sensor_custody_and_health(self):
        self.begin()
        self.pd.serve_once(114)
        self.guard.side_effect = RuntimeError("sensor withdrawn")
        with self.assertRaisesRegex(RuntimeError, "sensor withdrawn"):
            self.pd.require_completed(114)

    def test_observation_is_a_detached_nonqualification_copy(self):
        self.begin()
        self.pd.serve_once(114)
        observation = self.pd.observation
        observation["provider_result"]["status"] = "forged"
        self.assertEqual(self.pd.observation["provider_result"]["status"], "COMPLETED")
        self.assertFalse(self.pd.observation["phase3_exit_eligible"])


class NativeProviderOwnershipTests(ProviderFixture):
    def opener(self):
        self.owned.provider_dispatch_active = False
        del self.owned._pi_provider_dispatch
        pd = subject.PiNativeProviderDispatch(subject._SEAL, self.owned, self.provider_channels, {},
            Path("/var/lib/aragorn/admitted"), 115, 120)
        self.stack.enter_context(mock.patch.object(pd, "_ownership"))
        return pd

    def test_fixed_endpoint_is_absent_only_and_root_owned(self):
        pd = self.opener()
        mkdir = self.fs("mkdir")
        self.fs("open", return_value=14)
        self.fs("fstat", return_value=metadata(70))
        self.fs("stat", return_value=metadata(71, directory=False, mode=0o660))
        for name in ("fchown", "fchmod", "chown", "chmod", "fsync"):
            self.fs(name)
        with mock.patch.object(socket, "SOCK_CLOEXEC", 0o2000000, create=True), \
                mock.patch.object(socket, "socket", return_value=self.provider_listener):
            pd._open()
        mkdir.assert_called_once_with("provider", mode=0o711, dir_fd=11)
        self.provider_listener.bind.assert_called_once_with("/proc/self/fd/14/provider.sock")
        self.provider_listener.listen.assert_called_once_with(1)
        self.assertEqual(str(subject.PROVIDER_SOCKET), "/run/aragorn-pi-bootstrap/provider/provider.sock")
        self.assertTrue(self.owned.provider_dispatch_active)
        self.assertIs(self.owned._pi_provider_dispatch, pd)

    def test_existing_provider_directory_is_never_adopted(self):
        pd = self.opener()
        mkdir = self.fs("mkdir", side_effect=FileExistsError())
        with self.assertRaises(FileExistsError):
            pd._open()
        self.assertFalse(pd.created)
        self.assertFalse(self.owned.provider_dispatch_active)
        mkdir.assert_called_once()

    def test_directory_and_socket_identity_or_residue_fail_closed(self):
        self.fs("fstat", return_value=metadata(70))
        named = self.fs("stat", side_effect=[metadata(70), metadata(71, directory=False, mode=0o660)])
        listing = self.fs("listdir", return_value=["provider.sock"])
        subject.PiNativeProviderDispatch._ownership(self.pd)
        named.side_effect = [metadata(99)]
        with self.assertRaisesRegex(RuntimeError, "directory replaced"):
            subject.PiNativeProviderDispatch._ownership(self.pd)
        named.side_effect = [metadata(70)]
        listing.return_value = ["provider.sock", "foreign"]
        with self.assertRaisesRegex(RuntimeError, "unowned residue"):
            subject.PiNativeProviderDispatch._ownership(self.pd)

    def test_verified_cleanup_removes_only_owned_endpoint(self):
        unlink, rmdir = self.fs("unlink"), self.fs("rmdir")
        close = self.fs("close")
        self.fs("fsync")
        with mock.patch.object(subject.native, "_missing", return_value=True):
            self.pd.close()
        unlink.assert_called_once_with("provider.sock", dir_fd=14)
        rmdir.assert_called_once_with("provider", dir_fd=11)
        close.assert_called_once_with(14)
        self.provider_listener.close.assert_called_once()
        self.assertFalse(self.owned.provider_dispatch_active)
        self.assertFalse(hasattr(self.owned, "_pi_provider_dispatch"))
        self.assertEqual(self.pd.observation["cleanup"], "VERIFIED_OWNED_PROVIDER_CLEANUP")
        self.pd.close()
        self.provider_listener.close.assert_called_once()
        for borrowed in (self.bootstrap, self.broker, self.sensor, self.provider):
            borrowed.close.assert_not_called()

    def test_remote_hold_retains_namespace_and_never_retries_cleanup(self):
        self.pd._remote_custody_hold = True
        with self.assertRaisesRegex(RuntimeError, "cleanup is unconfirmed"):
            self.pd.close()
        with self.assertRaisesRegex(RuntimeError, "no automatic retry"):
            self.pd.close()
        self.provider_listener.close.assert_not_called()
        self.assertTrue(self.owned.provider_dispatch_active)
        self.assertIs(self.owned._pi_provider_dispatch, self.pd)

    def test_ambiguous_listener_close_is_not_repeated(self):
        self.provider_listener.close.side_effect = OSError("uncertain close")
        with self.assertRaises(RuntimeError):
            self.pd.close()
        with self.assertRaises(RuntimeError):
            self.pd.close()
        self.provider_listener.close.assert_called_once()
        self.assertTrue(self.owned.provider_dispatch_active)

    def test_accepted_close_failure_is_held_and_not_repeated(self):
        self.begin()
        self.provider_worker.close.side_effect = OSError("uncertain stream close")
        with self.assertRaisesRegex(OSError, "uncertain stream close"):
            self.pd.serve_once(114)
        with self.assertRaises(RuntimeError):
            self.pd.close()
        self.provider_worker.close.assert_called_once()
        self.assertTrue(self.owned.provider_dispatch_active)

    def test_cleanup_cannot_extend_original_bounded_budget(self):
        for deadline in (121, float("inf"), True):
            with self.subTest(deadline=deadline), self.assertRaises(RuntimeError):
                subject.PiNativeProviderDispatch(subject._SEAL, self.owned, self.provider_channels, {},
                    Path("/var/lib/aragorn/admitted"), 115, deadline)

    def test_constructor_requires_factory_seal(self):
        with self.assertRaisesRegex(RuntimeError, "protected factory"):
            subject.PiNativeProviderDispatch(None, self.owned, self.provider_channels, {},
                Path("/var/lib/aragorn/admitted"), 115)
