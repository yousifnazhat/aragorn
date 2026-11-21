"""Inert B81 owner transitions only: no process, file, service, socket or ptrace operations."""
from dataclasses import replace
from types import SimpleNamespace as NS
from unittest import TestCase, mock
import threading

from aragorn import pi_core_native_supervisor as native
from aragorn import pi_core_node_source_observer as node
from aragorn import pi_core_owned_socket_directories as sockets
from aragorn import pi_core_restricted_profile as restricted
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_native_provider_wiring as provider_fixtures


PIN = "sha256:" + "a" * 64
CLOCK = dict(clock_id="CLOCK_BOOTTIME", boot_id="10101010-1010-1010-1010-101010101010", time_namespace_inode=42)


class OwnerMembershipTests(TestCase):
    def setUp(self):
        profile = {"schema": restricted.PROFILE_SCHEMA}
        self.plan = plan = NS(unit_name="aragorn-pi-" + "2"*32 + ".service", worker_uid=501, worker_gid=502,
            profile=NS(cgroup="/worker"), prepared=NS(deployment_digest=PIN), source_observation=profile,
            source_observation_digest=canonical_digest(profile))
        self.owned = native._Owned(plan)
        self.request, self.provider = object(), object()
        self.owned._pi_request_dispatch = self.request
        self.owned._pi_provider_dispatch = self.provider
        self.first, self.second = [dict(boot_id=CLOCK["boot_id"], time_namespace_inode=42,
            opened_boottime_ns=n, closed_boottime_ns=n+1) for n in (10, 30)]
        self.capture = self.patch(sockets, "capture_owned_socket_directories", side_effect=[self.first, self.second])
        self.verify = self.patch(sockets, "verify_owned_socket_directories")
        self.worker_view = self.patch(sockets, "require_stopped_worker_socket_view")
        self.pidfd = self.patch(node.base.process, "require_live_pidfd")

    def patch(self, obj, name, **kw):
        p = mock.patch.object(obj, name, **kw)
        self.addCleanup(p.stop)
        return p.start()

    def begin(self):
        native._begin_socket_directories(self.owned, self.request, self.provider, deadline=90)

    def armed(self):
        o, plan = self.owned, self.plan
        o.started = o.start_attempted = True
        o.pid, o.start_ticks, o.pidfd, o.immutable_digest, o.invocation = 15, 16, 17, PIN, "1"*32
        self.worker = dict(pid=15, start_ticks=16, uid=501, gid=502, unit=plan.unit_name,
                           cgroup=plan.profile.cgroup, invocation_id=o.invocation)
        s = object.__new__(node._NodeSession)
        s.owned, s.profile, s._mask_capture, s.operation_deadline = o, plan.source_observation, None, 90
        s.gate_release_seen, s.stopping, s.failure, s.pending_events = False, False, None, []
        s.tasks = {15: dict(stopped=True, joined=True, start_ticks=16, stop_event=128, stop_seq=1)}
        s._budget, s._inventory = mock.Mock(), mock.Mock(return_value=[15])
        s.observer = NS(_thread=threading.get_native_id(), _attached=True, _executed=False, _pidfd=71, _owned=o,
            _worker=self.worker, _clock=CLOCK, _bindings=dict(profile_digest=plan.source_observation_digest,
            deployment_digest=PIN), _pins=(plan, 15, 17, 16, o.invocation, PIN),
            _events=[dict(seq=1, kind="STOP", pid=15, start_ticks=16, op="NONE", event=128, boottime_ns=20)])
        return s

    def report(self, **kw):
        args = dict(failure=None, cleanup={"status":"VERIFIED_OWNED_CLEANUP"}, status="BOOTSTRAP_COMPLETE")
        return native._native_observation(self.plan, self.owned, None, None,
            {"cleanup":"VERIFIED_OWNED_REQUEST_CLEANUP"}, {"cleanup":"VERIFIED_OWNED_PROVIDER_CLEANUP"}, None, **(args | kw))

    def test_prestart_then_actual_tracer_stop_uses_same_pair_once_and_separate_record(self):
        self.begin()
        s = self.armed()
        node._finish_socket_directories(s)
        self.assertEqual(self.capture.call_args_list, [mock.call(self.owned,self.request,self.provider,deadline=90)]*2)
        self.verify.assert_called_once_with(self.first,self.second,worker_uid=501,worker_gid=502)
        self.worker_view.assert_called_once_with(self.owned, self.second, deadline=90)
        self.assertEqual(self.pidfd.call_args_list, [mock.call(71),mock.call(17)]*3)
        self.owned.source_observer_closed = True
        result = self.report()
        r = result["owned_socket_directories"]
        self.assertEqual(r["status"], native._SOCKET_MATCHED)
        self.assertEqual((r["before_start"],r["stopped"],r["worker"],r["clock"],r["gate_stop_seq"]),
                         (self.first,self.second,self.worker,CLOCK,1))
        self.assertIsNone(result["source_observation"])
        with self.assertRaisesRegex(node.base.PiSourceObserverError,"MODE"):
            node._finish_socket_directories(s)
        self.assertEqual(self.capture.call_count,2)

    def test_start_or_first_edge_failure_never_reissues_first_capture(self):
        self.capture.side_effect = ValueError("missing endpoint")
        with self.assertRaisesRegex(ValueError,"endpoint"):
            self.begin()
        with self.assertRaises(native.PiNativeSupervisorError):
            self.begin()
        self.capture.assert_called_once()
        self.assertIsNone(self.owned.socket_directory_record["before_start"])
        self.assertEqual(self.report()["owned_socket_directories"]["status"],native._SOCKET_INCOMPLETE)

    def test_replacement_or_already_resumed_task_does_not_capture_second_edge(self):
        self.begin()
        s = self.armed()
        self.owned._pi_provider_dispatch = object()
        with self.assertRaisesRegex(node.base.PiSourceObserverError,"CUSTODY"):
            node._finish_socket_directories(s)
        self.owned._pi_provider_dispatch = self.provider
        s.tasks[15]["stopped"] = False
        with self.assertRaisesRegex(node.base.PiSourceObserverError,"INITIAL_STOP"):
            node._finish_socket_directories(s)
        self.capture.assert_called_once()
        self.verify.assert_not_called()

    def test_failed_clock_join_retains_original_edges_without_positive_result(self):
        self.begin()
        s = self.armed()
        s.observer._clock = dict(CLOCK, time_namespace_inode=91)
        with self.assertRaisesRegex(node.base.PiSourceObserverError,"CLOCK_ORDER"):
            node._finish_socket_directories(s)
        self.assertIs(self.owned.socket_directory_record["stopped"], self.second)
        self.assertEqual(self.owned.socket_directory_record["status"],native._SOCKET_INCOMPLETE)
        self.worker_view.assert_not_called()

    def test_wrong_worker_bind_prevents_release_without_recapturing_or_discarding_manager_edges(self):
        self.begin()
        self.worker_view.side_effect = ValueError("different worker socket")
        with self.assertRaisesRegex(ValueError, "worker socket"):
            node._finish_socket_directories(self.armed())
        record = self.owned.socket_directory_record
        self.assertEqual(record["status"], native._SOCKET_INCOMPLETE)
        self.assertIs(record["before_start"], self.first)
        self.assertIs(record["stopped"], self.second)
        self.assertEqual(self.capture.call_count, 2)

    def test_lost_stop_during_worker_view_refuses_before_matching(self):
        self.begin()
        s = self.armed()
        self.worker_view.side_effect = lambda *args, **kw: s.tasks[15].update(stopped=False)
        with self.assertRaisesRegex(node.base.PiSourceObserverError, "INITIAL_STOP"):
            node._finish_socket_directories(s)
        self.assertEqual(self.owned.socket_directory_record["status"], native._SOCKET_INCOMPLETE)

    def test_later_outer_cleanup_failure_retains_bytes_without_positive_status(self):
        self.begin()
        node._finish_socket_directories(self.armed())
        self.owned.source_observer_closed = True
        err = RuntimeError("late close")
        r = self.report()
        native._retain_native_failure(err,r,stage="LAUNCH_SCOPE_EXIT",terminal=True,owned=self.owned)
        failed = err.pi_native_supervisor_observation["owned_socket_directories"]
        self.assertEqual(failed,r["owned_socket_directories"] | {"status":native._SOCKET_INCOMPLETE})
        self.assertEqual(self.report(failure="refused")["owned_socket_directories"], failed)
        self.owned.source_observer_closed = False
        self.assertEqual(self.report()["owned_socket_directories"], failed)

    def test_restricted_native_caller_requires_stopped_edge_before_bootstrap_exchange(self):
        f = provider_fixtures.fixture(self, provider_fixtures.ProviderNativeCallerTests)
        new = dict(f.f.plan.source_observation, schema=restricted.PROFILE_SCHEMA)
        f.f.plan = replace(f.f.plan, source_observation=new, source_observation_digest=canonical_digest(new))
        def first(owned, request, provider, *, deadline):
            self.assertIs(request,f.r)
            self.assertIs(provider,f.p)
            self.assertFalse(owned.start_attempted)
            self.assertEqual(f.f.events[-2:],["request_open","provider_open"])
            owned.socket_directory_record = dict(status=native._SOCKET_INCOMPLETE)
        self.patch(native, "_begin_socket_directories", side_effect=first)
        result = f.run_worker()
        self.assertEqual(result["status"],"REFUSED")
        self.assertIn("stopped-gate", result["failure"])
        self.assertEqual(result["owned_socket_directories"]["status"],native._SOCKET_INCOMPLETE)
        f.f.command.assert_called_once()
        f.f.exchange.assert_not_called()
