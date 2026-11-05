"""New channel-custody checks with inert sockets, process reads and deployment.

The real authentication/lease composition runs, but kernel observations and
installed-runtime custody are mocks. No actual service, socket or /proc is used.
"""

from contextlib import ExitStack
import copy
import linecache
import os
import socket
import subprocess
import unittest
from unittest import mock

from aragorn import pi_core_service_channels as subject


class InertConnection:
    def __init__(self, fd, peer):
        self.descriptor, self.peer = fd, peer
        self.domain, self.kind = socket.AF_UNIX, socket.SOCK_SEQPACKET
        self.passcred = 0
        self.timeout = None

    def fileno(self):
        return self.descriptor

    def getsockopt(self, level, name, *args):
        if level != socket.SOL_SOCKET:
            raise AssertionError("unknown socket level")
        if name == subject.transport._DOMAIN: return self.domain
        if name == socket.SO_TYPE: return self.kind
        if name == subject.transport._PASSCRED: return self.passcred
        if name == socket.SO_PEERCRED: return subject.broker._PEER_CREDENTIALS.pack(*self.peer)
        raise AssertionError("unknown socket option")

    def setsockopt(self, level, name, value):
        if (level, name) != (socket.SOL_SOCKET, subject.transport._PASSCRED):
            raise AssertionError("unknown socket mutation")
        self.passcred = value

    def settimeout(self, timeout): self.timeout = timeout
    def close(self): raise AssertionError("borrowed connection must never close")
    def shutdown(self, *args): raise AssertionError("borrowed connection must never shut down")
    def sendmsg(self, *args): raise AssertionError("no readiness protocol or application send")
    def recvmsg(self, *args): raise AssertionError("no readiness protocol or application read")


class PiServiceChannelTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(linecache, "getlines", return_value=[]))
        self.stack.enter_context(mock.patch.object(linecache, "checkcache", return_value=None))
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (socket, "getaddrinfo"), (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "scandir", "readlink", "unlink"):
            self.stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("unmocked filesystem operation")))
        self.stack.enter_context(mock.patch.object(socket, "SO_PEERCRED", 17, create=True))
        self.platform = self.stack.enter_context(mock.patch.object(subject.sys, "platform", "linux"))
        self.uid = self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
        self.gid = self.stack.enter_context(mock.patch.object(os, "getegid", return_value=0))
        self.stack.enter_context(mock.patch.object(os, "getpid", return_value=1000))
        self.clock = self.stack.enter_context(mock.patch.object(subject.transport.time, "monotonic", return_value=100.0))
        self.inheritable = self.stack.enter_context(mock.patch.object(os, "get_inheritable", return_value=False))
        self.binding = subject.RuntimeActionWorkerBinding("sha256:" + "1" * 64,
            "sha256:" + "2" * 64, "sha256:" + "3" * 64, 1)
        self.pins = {"runtime_closure_digest": "sha256:" + "a" * 64, "binding_digest": "sha256:" + "b" * 64,
                     "receipt_digest": "sha256:" + "c" * 64, "python_digest": "sha256:" + "d" * 64}
        self.expected = {role: {"pid": 401 + index, "uid": 1201 + index, "gid": 1301 + index,
            "start_ticks": 8001 + index, "cgroup": f"/system.slice/aragorn-pi-{role}.service",
            "executable_digest": self.pins["python_digest"]} for index, role in enumerate(subject._ROLES)}
        self.connections = {role: InertConnection(40 + index,
            tuple(self.expected[role][field] for field in ("pid", "uid", "gid")))
            for index, role in enumerate(subject._ROLES)}
        self.measured = copy.deepcopy(self.expected)
        self.deployment = object.__new__(subject.provision.PiServiceRuntime)
        self.deployment_guard = self.stack.enter_context(mock.patch.object(subject.provision.PiServiceRuntime, "guard"))
        self.deployment_deadline = self.stack.enter_context(mock.patch.object(subject.provision.PiServiceRuntime,
            "deadline", new_callable=mock.PropertyMock, return_value=106.0))
        self.deployment_observation = self.stack.enter_context(mock.patch.object(subject.provision.PiServiceRuntime,
            "observation", new_callable=mock.PropertyMock, side_effect=lambda: copy.deepcopy(self.pins)))
        self.closed = []
        self.close = self.stack.enter_context(mock.patch.object(os, "close", side_effect=self.closed.append))
        self.opened = []

        def acquire(connection, pid):
            self.opened.append(pid)
            return pid + 100

        self.pidfd = self.stack.enter_context(mock.patch.object(subject.process, "open_peer_pidfd", side_effect=acquire))
        self.dead = set()
        self.live_calls = []

        def live(fd):
            self.live_calls.append(fd)
            if fd in self.dead:
                raise RuntimeError("inert peer exited")

        self.live = self.stack.enter_context(mock.patch.object(subject.process, "require_live_pidfd", side_effect=live))

        def by_pid(pid, field):
            return next(value[field] for value in self.measured.values() if value["pid"] == pid)

        self.start = self.stack.enter_context(mock.patch.object(subject.process, "_process_start_time", side_effect=lambda pid: by_pid(pid, "start_ticks")))
        self.cgroup = self.stack.enter_context(mock.patch.object(subject.process, "_process_cgroup", side_effect=lambda pid: by_pid(pid, "cgroup")))
        self.members = self.stack.enter_context(mock.patch.object(subject.process, "_cgroup_processes",
            side_effect=lambda group: tuple(value["pid"] for value in self.measured.values() if value["cgroup"] == group)))
        self.executable = self.stack.enter_context(mock.patch.object(subject.process, "_executable_digest", side_effect=lambda pid: by_pid(pid, "executable_digest")))
        self.stack.enter_context(mock.patch.object(subject.process, "_require_process_status",
            side_effect=AssertionError("sensor cannot use generic all-UID-columns status check")))

    def hold(self, **changes):
        return subject.hold_pi_service_channels(self.connections, self.expected, self.binding,
            **{"deployment": self.deployment, "deadline": 105.0, **changes})

    def test_real_peer_authentication_builds_existing_request_channels_without_readiness_io(self):
        with self.hold() as held:
            self.assertIs(type(held.request_channels), subject.PiNativeRequestChannels)
            self.assertIs(held.request_channels.service_custody, held)
            self.assertIs(held.request_channels.broker_connection, self.connections["action"])
            self.assertIs(held.request_channels.sensor_connection, self.connections["sensor"])
            self.assertIs(held.provider_connection, self.connections["provider"])
            self.assertEqual(held.provider_peer, (403, 1203, 1303))
            self.assertEqual(held.deadline, 105)
            self.assertEqual(self.opened, [401, 402, 403])
            self.assertTrue(all(connection.passcred == 1 for connection in self.connections.values()))
            self.assertFalse(held.observation["service_ready"])
            self.assertFalse(held.observation["loaded_code_verified"])
        self.assertEqual(self.closed, [501, 502, 503])
        self.assertFalse(held.observation["active"])
        self.assertEqual(held.observation["cleanup"], "OWNED_PEER_PIDFDS_CLOSED_NOT_SERVICE_EXIT")

    def test_guard_remeasures_all_live_service_processes_and_installed_custody(self):
        with self.hold() as held:
            before = self.executable.call_count
            held.guard()
            self.assertEqual(self.executable.call_count, before + 3)
            self.assertGreaterEqual(self.deployment_guard.call_count, 3)

    def test_expectation_mapping_is_detached_after_factory_entry(self):
        with self.hold() as held:
            before = held.observation
            self.expected["action"]["start_ticks"] += 500
            self.connections = {}
            held.guard()
            self.assertEqual(held.observation, before)

    def test_observation_is_detached_and_has_no_qualification_or_lifetime_claim(self):
        with self.hold() as held:
            value = held.observation
            value["python_digest"] = "caller mutation"
            self.assertEqual(held.observation["python_digest"], self.pins["python_digest"])
            self.assertFalse(held.observation["phase3_exit_eligible"])
            self.assertFalse(held.observation["unit_lifetime_verified"])

    def test_lease_cannot_be_constructed_from_an_unsealed_object(self):
        with self.assertRaises(subject.PiServiceChannelsError):
            subject.PiServiceChannels(None, None, None, None, None, None, None)

    def test_uninitialized_lease_is_refused_before_attribute_access(self):
        forged = object.__new__(subject.PiServiceChannels)
        with self.assertRaises(subject.PiServiceChannelsError): forged.guard()
        with self.assertRaises(subject.PiServiceChannelsError): forged.retire_provider()

    def test_plain_deployment_metadata_is_not_held_installed_custody(self):
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(deployment=self.pins): pass
        self.pidfd.assert_not_called()

    def test_inactive_deployment_refuses_before_adopting_peer_pidfds(self):
        self.deployment_guard.side_effect = RuntimeError("inactive deployment")
        with self.assertRaises(RuntimeError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_channel_deadline_cannot_extend_held_runtime(self):
        self.deployment_deadline.return_value = 104
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_original_deadline_expiry_retires_no_authority(self):
        with self.hold() as held:
            self.clock.return_value = 105
            with self.assertRaises(RuntimeError): held.guard()
            with self.assertRaises(RuntimeError): held.retire_provider()
            self.assertFalse(held.provider_retired)

    def test_expired_unbounded_boolean_and_nonfinite_deadlines_refuse(self):
        for value in (100, 131, True, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                with self.hold(deadline=value): pass
        self.pidfd.assert_not_called()

    def test_nonroot_supervisor_is_rejected(self):
        self.uid.return_value = 1201
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_nonlinux_platform_is_rejected_before_channels(self):
        with mock.patch.object(subject.sys, "platform", "darwin"), self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_unknown_or_missing_role_is_refused(self):
        self.expected["extra"] = self.expected.pop("provider")
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_unrecognized_process_expectation_field_refuses(self):
        self.expected["sensor"]["ready"] = True
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass

    def test_root_role_and_boolean_process_identity_refuse(self):
        for value in (0, True, -1, 2**31):
            self.expected["action"]["uid"] = value
            with self.subTest(value=value), self.assertRaises(subject.PiServiceChannelsError):
                with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_duplicate_pid_uid_gid_or_cgroup_is_not_role_separation(self):
        for field in ("pid", "uid", "gid", "cgroup"):
            original = self.expected["sensor"][field]
            self.expected["sensor"][field] = self.expected["action"][field]
            with self.subTest(field=field), self.assertRaises(subject.PiServiceChannelsError):
                with self.hold(): pass
            self.expected["sensor"][field] = original
        self.pidfd.assert_not_called()

    def test_supervisor_pid_cannot_serve_as_a_nonroot_peer(self):
        self.expected["provider"]["pid"] = 1000
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass

    def test_malformed_cgroup_or_executable_digest_refuses(self):
        self.expected["provider"]["cgroup"] = "/system.slice/../provider"
        with self.assertRaises(RuntimeError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_unpinned_service_interpreter_refuses_even_if_expected_process_matches(self):
        self.expected["provider"]["executable_digest"] = "sha256:" + "e" * 64
        self.measured = copy.deepcopy(self.expected)
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_invalid_worker_binding_refuses_before_socket_adoption(self):
        self.binding = subject.RuntimeActionWorkerBinding("invalid", "invalid", "invalid", True)
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_aliasing_borrowed_socket_objects_is_refused(self):
        self.connections["sensor"] = self.connections["action"]
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.assertEqual(self.closed, [])

    def test_distinct_objects_with_aliasing_descriptors_are_refused(self):
        self.connections["sensor"].descriptor = self.connections["action"].descriptor
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_root_created_socketpair_peer_identity_cannot_substitute_service_peer(self):
        self.connections["sensor"].peer = (1000, 0, 0)
        with self.assertRaises(RuntimeError):
            with self.hold(): pass
        self.assertEqual(self.closed, [501])

    def test_stream_control_channel_is_rejected_and_prior_pidfd_closed(self):
        self.connections["sensor"].kind = socket.SOCK_STREAM
        with self.assertRaises(RuntimeError):
            with self.hold(): pass
        self.assertEqual(self.closed, [501])

    def test_missing_per_message_credentials_refuses_before_pidfd_acquisition(self):
        self.connections["action"].setsockopt = lambda *args: None
        with self.assertRaises(RuntimeError):
            with self.hold(): pass
        self.pidfd.assert_not_called()

    def test_inheritable_new_pidfd_refuses_and_closes_once(self):
        self.inheritable.return_value = True
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.assertEqual(self.closed, [501])

    def test_duplicate_new_pidfd_is_not_double_closed(self):
        self.pidfd.side_effect = [501, 501]
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.assertEqual(self.closed, [501])

    def test_returned_pidfd_aliasing_borrowed_socket_is_never_closed(self):
        self.pidfd.side_effect = [40]
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.assertEqual(self.closed, [])

    def test_wrong_start_generation_refuses_and_closes_all_acquired_pidfds(self):
        self.measured["action"]["start_ticks"] += 1
        with self.assertRaises(subject.PiServiceChannelsError) as caught:
            with self.hold(): pass
        self.assertEqual(self.closed, [501, 502, 503])
        self.assertFalse(caught.exception.pi_service_channel_observation["active"])
        self.assertEqual(caught.exception.pi_service_channel_observation["cleanup"], "OWNED_PEER_PIDFDS_CLOSED_NOT_SERVICE_EXIT")

    def test_wrong_current_cgroup_or_extra_process_refuses(self):
        self.members.side_effect = lambda group: (401, 999)
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.assertEqual(self.closed, [501, 502, 503])

    def test_actual_interpreter_bytes_must_match_protected_pin(self):
        self.measured["sensor"]["executable_digest"] = "sha256:" + "e" * 64
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.assertEqual(self.closed, [501, 502, 503])

    def test_process_generation_change_during_measurement_refuses(self):
        original = self.executable.side_effect

        def changed(pid):
            value = original(pid)
            self.measured["action"]["start_ticks"] += 1
            return value

        self.executable.side_effect = changed
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass

    def test_actual_socket_peer_replacement_is_detected_by_later_guard(self):
        with self.hold() as held:
            self.connections["action"].peer = (450, 1201, 1301)
            with self.assertRaises(subject.PiServiceChannelsError): held.guard()

    def test_installed_runtime_pin_change_is_detected_by_later_guard(self):
        with self.hold() as held:
            self.pins["runtime_closure_digest"] = "sha256:" + "e" * 64
            with self.assertRaises(subject.PiServiceChannelsError): held.guard()

    def test_retirement_accepts_authenticated_terminal_after_provider_exit(self):
        with self.hold() as held:
            self.dead.add(503)
            with self.assertRaises(RuntimeError): held.guard()
            held.retire_provider()
            self.assertTrue(held.provider_retired)
            before = len(self.live_calls)
            held.guard()
            self.assertNotIn(503, self.live_calls[before:])
            self.assertNotIn(503, self.closed)
        self.assertEqual(self.closed, [501, 502, 503])

    def test_provider_retirement_is_irreversible_and_cannot_be_repeated(self):
        with self.hold() as held:
            held.retire_provider()
            with self.assertRaises(subject.PiServiceChannelsError): held.retire_provider()
            with self.assertRaises(AttributeError): held.provider_retired = False

    def test_retired_provider_still_requires_same_connected_kernel_peer(self):
        with self.hold() as held:
            held.retire_provider()
            self.connections["provider"].peer = (404, 1203, 1303)
            with self.assertRaises(subject.PiServiceChannelsError): held.guard()

    def test_retirement_cannot_waive_sensor_or_action_liveness(self):
        with self.hold() as held:
            self.dead.add(502)
            with self.assertRaises(RuntimeError): held.retire_provider()
            self.assertFalse(held.provider_retired)

    def test_lease_exit_revokes_before_close_and_attempts_every_owned_descriptor_once(self):
        lease = None

        def closed(fd):
            self.closed.append(fd)
            self.assertFalse(lease.observation["active"])
            if fd == 502:
                raise OSError("inert close uncertainty")

        self.close.side_effect = closed
        with self.assertRaises(RuntimeError) as caught:
            with self.hold() as held:
                lease = held
        self.assertEqual(self.closed, [501, 502, 503])
        self.assertEqual(caught.exception.pi_service_channel_observation["cleanup"], "CLEANUP_HOLD")
        with self.assertRaises(RuntimeError): lease._close()
        self.assertEqual(self.closed, [501, 502, 503])

    def test_guard_and_retirement_refuse_after_scope_exit(self):
        with self.hold() as held: pass
        with self.assertRaises(subject.PiServiceChannelsError): held.guard()
        with self.assertRaises(subject.PiServiceChannelsError): held.retire_provider()

    def test_initial_channel_budget_reaches_deployment_guard(self):
        with self.hold():
            self.assertTrue(self.deployment_guard.call_args_list)
            self.assertTrue(all(call.kwargs == {"deadline": 105.0}
                                for call in self.deployment_guard.call_args_list))

    def test_invalid_channel_extension_refuses_before_heavy_deployment_guard(self):
        self.deployment_deadline.return_value = 104.0
        with self.assertRaises(subject.PiServiceChannelsError):
            with self.hold(): pass
        self.deployment_guard.assert_not_called()

    def test_tighter_guard_budget_reaches_deployment_and_every_peer_check(self):
        with self.hold() as held:
            self.deployment_guard.reset_mock()
            with mock.patch.object(subject.transport, "require_peer_live", wraps=subject.transport.require_peer_live) as peer:
                held.guard(deadline=100.5)
            self.deployment_guard.assert_called_once_with(deadline=100.5)
            self.assertEqual(peer.call_count, 6)
            self.assertTrue(all(call.args[-1] == 100.5 for call in peer.call_args_list))
            self.assertEqual(held.deadline, 105.0)
            held.guard()
            self.deployment_guard.assert_called_with(deadline=105.0)

    def test_guard_cannot_extend_lease_or_accept_invalid_budget(self):
        with self.hold() as held:
            self.deployment_guard.reset_mock()
            for value in (105.1, 100.0, True, float("nan"), float("inf"), "101"):
                with self.subTest(value=value), self.assertRaises(RuntimeError): held.guard(deadline=value)
            self.deployment_guard.assert_not_called()
            self.assertEqual(held.deadline, 105.0)

    def test_tighter_budget_expiring_in_process_read_stops_before_next_read(self):
        with self.hold() as held:
            self.cgroup.reset_mock()
            original = self.start.side_effect

            def delayed(pid):
                value = original(pid)
                self.clock.return_value = 100.5
                return value

            self.start.side_effect = delayed
            with self.assertRaises(RuntimeError): held.guard(deadline=100.5)
            self.cgroup.assert_not_called()

    def test_retirement_propagates_tighter_budget_without_extending_or_mutating_lease(self):
        with self.hold() as held:
            self.dead.add(503)
            with mock.patch.object(subject.transport, "require_peer_live", wraps=subject.transport.require_peer_live) as peer:
                held.retire_provider(deadline=100.5)
            self.assertTrue(held.provider_retired)
            self.deployment_guard.assert_called_with(deadline=100.5)
            self.assertEqual(peer.call_count, 4)
            self.assertTrue(all(call.args[-1] == 100.5 for call in peer.call_args_list))
            self.assertEqual(held.deadline, 105.0)

    def test_retirement_extension_refuses_before_work_and_cannot_latch_terminal_state(self):
        with self.hold() as held:
            self.deployment_guard.reset_mock()
            with self.assertRaises(subject.PiServiceChannelsError): held.retire_provider(deadline=105.1)
            self.deployment_guard.assert_not_called()
            self.assertFalse(held.provider_retired)


if __name__ == "__main__":
    unittest.main()
