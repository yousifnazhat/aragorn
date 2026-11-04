"""Inert native-request ownership/dispatch checks; all native operations mocked."""

import os
import socket
import stat
import subprocess
import unittest
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_native_request as route
from aragorn import pi_core_native_supervisor as native
from aragorn import pi_core_confined_launch as confined
from aragorn.oci_worker_protocol import canonical_json
from aragorn.runtime_process_profile import RuntimeProcessProfile


def activation():
    return {**{key: "sha256:" + "a" * 64 for key in route.identity._PINS},
        "schema": route.identity.ACTIVATION_SCHEMA, "authority": route.identity.ACTIVATION_AUTHORITY,
        "activation_id": "a" * 32, "session_id": "a" * 32, "run_id": "a" * 32,
        "pid": 300, "uid": 1201, "gid": 1202, "start_time_ticks": 50,
        "mount_namespace": {"device": 1, "inode": 2}, "cgroup": "/system.slice/aragorn-pi-" + "a" * 32 + ".service",
        "expires_at_monotonic_ns": 120_000_000_000,
        "boot_id": "11111111-2222-3333-4444-555555555555"}


def connection(fd, kind=socket.SOCK_SEQPACKET):
    value = mock.Mock()
    value.fileno.return_value = fd
    value.getsockopt.side_effect = lambda level, option: socket.AF_UNIX if option == route.channel._DOMAIN else kind
    return value


def metadata(inode=50, *, directory=True, mode=0o711, gid=1202):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=(stat.S_IFDIR if directory else stat.S_IFSOCK) | mode,
        st_uid=0, st_gid=gid, st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=2)


class InertTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(os, "getegid", return_value=0))
        self.stack.enter_context(mock.patch.object(os, "getpid", return_value=100))
        self.stack.enter_context(mock.patch.object(native.time, "monotonic", return_value=100.0))
        self.stack.enter_context(mock.patch.object(native.time, "monotonic_ns", return_value=100_000_000_000))
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        for name in ("open", "close", "mkdir", "rmdir", "unlink", "stat", "fstat", "fchmod", "fchown", "chmod", "chown", "listdir", "fsync"):
            self.stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("unmocked filesystem operation")))
        for name in ("pidfd_open", "fork", "posix_spawn", "posix_spawnp"):
            self.stack.enter_context(mock.patch.object(os, name, create=True, side_effect=AssertionError("process operation forbidden")))
        for name in ("_read_virtual_file", "require_live_pidfd", "measure_runtime_process_profile", "open_peer_pidfd"):
            self.stack.enter_context(mock.patch.object(native.process, name, side_effect=AssertionError("kernel read forbidden")))
        self.bootstrap = connection(1, socket.SOCK_STREAM)
        self.worker = connection(2, socket.SOCK_STREAM)
        self.broker = connection(3)
        self.sensor = connection(4)
        self.bootstrap_listener = connection(5, socket.SOCK_STREAM)
        self.request_listener = connection(6, socket.SOCK_STREAM)
        self.binding = route.worker.RuntimeActionWorkerBinding(*["sha256:" + "a" * 64] * 3, 1)
        self.channels = route.PiNativeRequestChannels(self.broker, self.sensor, (400, 1301, 1302), (500, 1401, 1402), self.binding)
        self.profile = RuntimeProcessProfile("sha256:" + "a" * 64, "sha256:" + "a" * 64,
            activation()["cgroup"], Path("/var/lib/aragorn/admitted/version/SKILL.md"), "sha256:" + "a" * 64)
        prepared = SimpleNamespace(_lease=SimpleNamespace(active=True), expires_at_monotonic_ns=120_000_000_000)
        plan = confined.PiConfinedLaunchPlan(prepared, self.profile, 1201, 1202,
            self.profile.cgroup.removeprefix("/system.slice/"), ("/usr/bin/systemd-run",),
            Path("/var/lib/aragorn/pi-activations") / ("a" * 32 + ".json"), b"{}", 115,
            "sha256:" + "a" * 64, "sha256:" + "a" * 64, confined._PlanLease())
        self.owned = native._Owned(plan, run_fd=10, directory_fd=11, directory_identity=(1, 2, 3, 0, 0),
            listener=self.bootstrap_listener, connection=self.bootstrap, socket_identity=(1, 20),
            activation_fd=20, activation_identity=(1, 30), activation_raw=canonical_json(activation()),
            start_attempted=True, started=True, pid=300, pidfd=31, start_ticks=50,
            invocation="c" * 32, immutable_digest="sha256:" + "a" * 64, cgroup_parent_fd=32, cgroup_fd=33)
        self.owned.request_attempted = False
        self.owned.request_dispatch_active = True
        self.dispatch = route.PiNativeRequestDispatch(route._SEAL, self.owned, self.channels, {},
            Path("/var/lib/aragorn/admitted"), 115, 120)
        self.dispatch.created = self.dispatch.active = True
        self.dispatch.directory_fd = 12
        self.dispatch.directory_identity = route.broker._directory_identity(metadata())
        self.dispatch.socket_identity = route.broker._file_identity(metadata(51, directory=False, mode=0o660))
        self.dispatch.listener = self.request_listener
        self.owned._pi_request_dispatch = self.dispatch
        self.ownership = self.stack.enter_context(mock.patch.object(native, "_resource_ownership"))
        self.same = self.stack.enter_context(mock.patch.object(native, "_same_generation"))
        self.state = self.stack.enter_context(mock.patch.object(native, "_unit_state", return_value={"fixture": "same-unit"}))
        self.measured = self.stack.enter_context(mock.patch.object(route.identity, "_measured"))
        self.read_activation = self.stack.enter_context(mock.patch.object(route.identity, "read_activation", return_value=activation()))
        self.peers = self.stack.enter_context(mock.patch.object(route.broker, "_peer_credentials",
            side_effect=lambda value: self.channels.broker_peer if value is self.broker else self.channels.sensor_peer))
        self.dispatch_ownership = self.stack.enter_context(mock.patch.object(self.dispatch, "_ownership"))
        self.forward = self.stack.enter_context(mock.patch.object(route.handoff, "handle_pi_request_connection",
            return_value={"status": "COMPLETED", "fixture": "unit-only"}))

    def handle(self, **changes):
        options = dict(grant={}, protected_root=Path("/var/lib/aragorn/admitted"), deadline=115)
        options.update(changes)
        return route.handle_native_pi_request(self.owned, self.worker, self.channels, **options)


class NativeCustodyTests(InertTests):
    def test_exact_held_native_custody_wraps_existing_reader_and_sensor_channel(self):
        self.assertEqual(self.handle()["status"], "COMPLETED")
        self.assertTrue(self.owned.request_attempted)
        args = self.forward.call_args
        self.assertEqual(args.args, (self.worker, self.broker))
        self.assertEqual(args.kwargs["deadline"], 115)
        self.assertEqual(args.kwargs["sensor_channel"].connection, self.sensor)
        self.assertEqual(args.kwargs["sensor_channel"].expected_peer, self.channels.sensor_peer)
        custody = args.kwargs["native_custody"]
        self.assertIs(type(custody), route.PiNativeRequestCustody)
        with self.assertRaises(RuntimeError):
            custody.guard()
        self.assertEqual(self.measured.call_args_list, [mock.call(self.bootstrap, 31, self.profile, activation(), 115),
            mock.call(self.worker, 31, self.profile, activation(), 115)])
        self.bootstrap.close.assert_not_called()
        self.worker.close.assert_not_called()
        self.sensor.close.assert_not_called()
        self.broker.close.assert_not_called()

    def test_each_nested_guard_rechecks_real_native_and_request_identity(self):
        def forward(*args, **kwargs):
            kwargs["native_custody"].guard()
            kwargs["native_custody"].guard()
            return {"status": "NOT_SUBMITTED"}
        self.forward.side_effect = forward
        self.handle()
        self.assertEqual(self.same.call_count, 3)
        self.assertEqual(self.measured.call_count, 6)
        self.assertEqual(self.dispatch_ownership.call_count, 3)

    def test_second_attempt_is_refused_even_after_failed_dispatch(self):
        self.forward.side_effect = RuntimeError("uncertain")
        with self.assertRaises(RuntimeError):
            self.handle()
        with self.assertRaisesRegex(RuntimeError, "already attempted"):
            self.handle()
        self.forward.assert_called_once()

    def test_json_or_unheld_plan_cannot_supply_native_custody(self):
        with self.assertRaises(RuntimeError):
            route.handle_native_pi_request({}, self.worker, self.channels, grant={}, protected_root=Path("/var/lib/aragorn/admitted"), deadline=115)
        self.owned.plan._lease.active = False
        with self.assertRaises(RuntimeError):
            self.handle()
        self.forward.assert_not_called()

    def test_custody_constructor_cannot_be_minted_from_caller_data(self):
        with self.assertRaises(RuntimeError):
            route.PiNativeRequestCustody()

    def test_changed_unit_activation_or_measurement_prevents_request(self):
        self.same.side_effect = RuntimeError("unit replaced")
        with self.assertRaises(RuntimeError):
            self.handle()
        self.forward.assert_not_called()

    def test_activation_change_during_dispatch_invalidates_custody(self):
        def forward(*args, **kwargs):
            self.read_activation.return_value = {**activation(), "pid": 301}
            kwargs["native_custody"].guard()
        self.forward.side_effect = forward
        with self.assertRaisesRegex(RuntimeError, "activation changed"):
            self.handle()

    def test_role_alias_or_root_service_identity_refuses(self):
        for changed in ((400, 1201, 1302), (400, 1301, 1202), (500, 1301, 1302), (400, 0, 0)):
            self.channels = replace(self.channels, broker_peer=changed)
            with self.subTest(peer=changed), self.assertRaises(RuntimeError):
                self.handle()
        self.forward.assert_not_called()

    def test_closed_or_aliased_channel_refuses(self):
        self.sensor.fileno.return_value = self.broker.fileno.return_value
        with self.assertRaises(RuntimeError):
            self.handle()
        self.forward.assert_not_called()

    def test_deadline_cannot_extend_launch_or_dispatch_budget(self):
        with self.assertRaises(RuntimeError):
            self.handle(deadline=116)
        self.forward.assert_not_called()


class SelectionTests(InertTests):
    def setUp(self):
        super().setUp()
        self.selected = self.stack.enter_context(mock.patch.object(route.select, "select"))
        self.read_result = self.stack.enter_context(mock.patch.object(confined, "_read_bootstrap",
            return_value={"status": "PROVIDER_UNAVAILABLE"}))

    def test_unavailable_bootstrap_returns_no_request_without_fabricating_work(self):
        self.selected.return_value = ([self.bootstrap], [], [])
        self.assertEqual(self.dispatch.read_bootstrap_result(self.bootstrap, 115), {"status": "PROVIDER_UNAVAILABLE"})
        self.assertEqual(self.dispatch.observation["status"], "NO_REQUEST")
        self.forward.assert_not_called()
        self.request_listener.accept.assert_not_called()

    def test_one_actual_request_is_dispatched_then_owned_stream_closed_before_result(self):
        self.selected.side_effect = [([self.request_listener], [], []), ([self.bootstrap], [], [])]
        self.request_listener.accept.return_value = (self.worker, "")
        self.dispatch.read_bootstrap_result(self.bootstrap, 115)
        self.forward.assert_called_once()
        self.worker.close.assert_called_once()
        self.worker.shutdown.assert_not_called()
        self.assertEqual(self.dispatch.observation["status"], "REQUEST_RETURNED")
        self.assertTrue(self.dispatch.observation["request_attempted"])

    def test_request_wins_when_both_streams_are_ready(self):
        self.selected.side_effect = [([self.bootstrap, self.request_listener], [], []), ([self.bootstrap], [], [])]
        self.request_listener.accept.return_value = (self.worker, "")
        self.dispatch.read_bootstrap_result(self.bootstrap, 115)
        self.forward.assert_called_once()

    def test_second_pending_request_is_refused_without_accept_or_retry(self):
        self.selected.side_effect = [([self.request_listener], [], []), ([self.request_listener], [], [])]
        self.request_listener.accept.return_value = (self.worker, "")
        with self.assertRaisesRegex(RuntimeError, "limit reached"):
            self.dispatch.read_bootstrap_result(self.bootstrap, 115)
        self.request_listener.accept.assert_called_once()
        self.forward.assert_called_once()

    def test_original_bootstrap_deadline_can_tighten_request_budget(self):
        self.selected.side_effect = [([self.request_listener], [], []), ([self.bootstrap], [], [])]
        self.request_listener.accept.return_value = (self.worker, "")
        self.dispatch.read_bootstrap_result(self.bootstrap, 110)
        self.assertEqual(self.forward.call_args.kwargs["deadline"], 110)
        self.read_result.assert_called_once_with(self.bootstrap, 110)
        with self.assertRaises(RuntimeError):
            self.dispatch.read_bootstrap_result(self.bootstrap, 115)

    def test_dispatch_failure_closes_only_accepted_stream(self):
        self.selected.return_value = ([self.request_listener], [], [])
        self.request_listener.accept.return_value = (self.worker, "")
        self.forward.side_effect = RuntimeError("request failed")
        with self.assertRaises(RuntimeError):
            self.dispatch.read_bootstrap_result(self.bootstrap, 115)
        self.worker.close.assert_called_once()
        self.read_result.assert_not_called()
        self.bootstrap.close.assert_not_called()

    def test_noncompleted_result_prevents_bootstrap_release_and_retains_remote_hold(self):
        self.selected.return_value = ([self.request_listener], [], [])
        self.request_listener.accept.return_value = (self.worker, "")
        self.forward.return_value = {"status": "INDETERMINATE"}
        with self.assertRaises(route.PiNativeRequestError) as error:
            self.dispatch.read_bootstrap_result(self.bootstrap, 115)
        self.assertEqual(error.exception.observation["cleanup"], "CLEANUP_HOLD")
        self.assertEqual(self.dispatch.observation["status"], "REQUEST_INDETERMINATE")
        self.read_result.assert_not_called()
        self.worker.close.assert_called_once()

    def test_deadline_or_wrong_bootstrap_handle_cannot_read_result(self):
        self.selected.return_value = ([], [], [])
        with self.assertRaises(RuntimeError):
            self.dispatch.read_bootstrap_result(self.bootstrap, 115)
        with self.assertRaises(RuntimeError):
            self.dispatch.read_bootstrap_result(self.worker, 115)
        self.read_result.assert_not_called()

    def test_accepted_close_failure_is_retained_as_cleanup_hold(self):
        self.selected.return_value = ([self.request_listener], [], [])
        self.request_listener.accept.return_value = (self.worker, "")
        self.worker.close.side_effect = OSError("close uncertain")
        with self.assertRaises(OSError):
            self.dispatch.read_bootstrap_result(self.bootstrap, 115)
        self.assertEqual(self.dispatch.observation["cleanup"], "CLEANUP_HOLD")
        self.assertIsNone(self.dispatch.accepted)


class ResourceTests(InertTests):
    def setUp(self):
        super().setUp()
        self.mkdir = self.stack.enter_context(mock.patch.object(os, "mkdir"))
        self.open = self.stack.enter_context(mock.patch.object(os, "open", return_value=12))
        self.close_fd = self.stack.enter_context(mock.patch.object(os, "close"))
        self.fstat = self.stack.enter_context(mock.patch.object(os, "fstat", return_value=metadata()))
        self.stat = self.stack.enter_context(mock.patch.object(os, "stat", return_value=metadata(51, directory=False, mode=0o660)))
        self.chown = self.stack.enter_context(mock.patch.object(os, "chown"))
        self.chmod = self.stack.enter_context(mock.patch.object(os, "chmod"))
        self.stack.enter_context(mock.patch.object(os, "fchown"))
        self.stack.enter_context(mock.patch.object(os, "fchmod"))
        self.fsync = self.stack.enter_context(mock.patch.object(os, "fsync"))
        self.unlink = self.stack.enter_context(mock.patch.object(os, "unlink"))
        self.rmdir = self.stack.enter_context(mock.patch.object(os, "rmdir"))
        self.stack.enter_context(mock.patch.object(os, "listdir", return_value=["request.sock"]))
        self.stack.enter_context(mock.patch.object(native, "_missing", return_value=True))

    def fresh(self):
        self.owned.request_dispatch_active = False
        del self.owned._pi_request_dispatch
        value = route.PiNativeRequestDispatch(route._SEAL, self.owned, self.channels, {},
            Path("/var/lib/aragorn/admitted"), 115, 120)
        self.stack.enter_context(mock.patch.object(value, "_ownership"))
        return value

    def test_exclusive_descriptor_relative_socket_exact_modes_and_fsync(self):
        value = self.fresh()
        with mock.patch.object(socket, "SOCK_CLOEXEC", 0x80000, create=True), \
             mock.patch.object(socket, "socket", return_value=self.request_listener) as opened:
            value._open()
        self.mkdir.assert_called_once_with("requests", mode=0o711, dir_fd=11)
        self.request_listener.bind.assert_called_once_with("/proc/self/fd/12/request.sock")
        self.chown.assert_called_once_with("request.sock", 0, 1202, dir_fd=12, follow_symlinks=False)
        self.chmod.assert_called_once_with("request.sock", 0o660, dir_fd=12, follow_symlinks=False)
        self.assertEqual(self.fsync.call_args_list, [mock.call(12), mock.call(11), mock.call(12)])
        self.assertTrue(value.active)
        self.assertTrue(self.owned.request_dispatch_active)
        opened.assert_called_once()

    def test_preexisting_request_directory_is_never_adopted_repaired_or_removed(self):
        value = self.fresh()
        self.mkdir.side_effect = FileExistsError("preexisting")
        with self.assertRaises(FileExistsError):
            value._open()
        value.close()
        self.open.assert_not_called()
        self.unlink.assert_not_called()
        self.rmdir.assert_not_called()
        self.assertFalse(self.owned.request_dispatch_active)

    def test_verified_cleanup_removes_only_owned_names_then_clears_scope(self):
        self.dispatch.close()
        self.unlink.assert_called_once_with("request.sock", dir_fd=12)
        self.rmdir.assert_called_once_with("requests", dir_fd=11)
        self.assertEqual(self.fsync.call_args_list, [mock.call(12), mock.call(11)])
        self.request_listener.close.assert_called_once()
        self.close_fd.assert_called_once_with(12)
        self.assertFalse(self.owned.request_dispatch_active)
        self.assertFalse(hasattr(self.owned, "_pi_request_dispatch"))
        self.assertEqual(self.dispatch.observation["cleanup"], "VERIFIED_OWNED_REQUEST_CLEANUP")

    def test_cleanup_uses_reserved_original_budget_not_expired_action_budget(self):
        with mock.patch.object(native.time, "monotonic", return_value=117.0):
            self.dispatch.close()
        self.assertEqual(self.dispatch.observation["cleanup"], "VERIFIED_OWNED_REQUEST_CLEANUP")

    def test_exhausted_total_budget_preserves_namespace_and_closes_handles(self):
        with mock.patch.object(native.time, "monotonic", return_value=121.0):
            with self.assertRaises(route.PiNativeRequestError):
                self.dispatch.close()
        self.unlink.assert_not_called()
        self.rmdir.assert_not_called()
        self.close_fd.assert_called_once_with(12)
        self.request_listener.close.assert_called_once()
        self.assertTrue(self.owned.request_dispatch_active)

    def test_substitution_preserves_names_and_reports_hold(self):
        self.dispatch_ownership.side_effect = RuntimeError("socket replaced")
        with self.assertRaises(route.PiNativeRequestError) as error:
            self.dispatch.close()
        self.assertEqual(error.exception.observation["cleanup"], "CLEANUP_HOLD")
        self.unlink.assert_not_called()
        self.rmdir.assert_not_called()

    def test_uncertain_close_is_never_retried(self):
        self.close_fd.side_effect = OSError("close uncertain")
        with self.assertRaises(route.PiNativeRequestError):
            self.dispatch.close()
        self.dispatch.close()
        self.close_fd.assert_called_once_with(12)
        self.assertEqual(self.dispatch.observation["cleanup"], "CLEANUP_HOLD")

    def test_namespace_fsync_failure_is_a_cleanup_hold(self):
        self.fsync.side_effect = OSError("fsync failed")
        with self.assertRaises(route.PiNativeRequestError):
            self.dispatch.close()
        self.rmdir.assert_not_called()
        self.assertEqual(self.dispatch.observation["cleanup"], "CLEANUP_HOLD")

    def test_prior_accepted_handle_failure_survives_other_cleanup_success(self):
        self.dispatch._close_failure = OSError("earlier accepted close uncertain")
        with self.assertRaises(route.PiNativeRequestError):
            self.dispatch.close()
        self.assertEqual(self.dispatch.observation["cleanup"], "CLEANUP_HOLD")

    def test_remote_custody_uncertainty_survives_local_namespace_cleanup(self):
        self.dispatch._remote_custody_hold = True
        with self.assertRaises(route.PiNativeRequestError):
            self.dispatch.close()
        self.unlink.assert_called_once_with("request.sock", dir_fd=12)
        self.rmdir.assert_called_once_with("requests", dir_fd=11)
        self.assertEqual(self.dispatch.observation["cleanup"], "CLEANUP_HOLD")

    def test_directory_socket_identity_and_unowned_residue_checks_are_substantive(self):
        self.stat.side_effect = lambda name, **kwargs: metadata() if name == "requests" else metadata(51, directory=False, mode=0o660)
        route.PiNativeRequestDispatch._ownership(self.dispatch)
        self.stat.side_effect = lambda name, **kwargs: metadata(99) if name == "requests" else metadata(51, directory=False, mode=0o660)
        with self.assertRaisesRegex(RuntimeError, "directory replaced"):
            route.PiNativeRequestDispatch._ownership(self.dispatch)
        self.stat.side_effect = lambda name, **kwargs: metadata() if name == "requests" else metadata(99, directory=False, mode=0o660)
        with self.assertRaisesRegex(RuntimeError, "socket replaced"):
            route.PiNativeRequestDispatch._ownership(self.dispatch)
        self.stat.side_effect = lambda name, **kwargs: metadata() if name == "requests" else metadata(51, directory=False, mode=0o660)
        with mock.patch.object(os, "listdir", return_value=["request.sock", "unowned"]):
            with self.assertRaisesRegex(RuntimeError, "unowned residue"):
                route.PiNativeRequestDispatch._ownership(self.dispatch)

    def test_cleanup_budget_cannot_extend_beyond_five_seconds(self):
        for deadline in (121, 114, float("inf"), True):
            with self.subTest(deadline=deadline), self.assertRaises(RuntimeError):
                route.PiNativeRequestDispatch(route._SEAL, self.owned, self.channels, {},
                    Path("/var/lib/aragorn/admitted"), 115, deadline)


if __name__ == "__main__":
    unittest.main()
