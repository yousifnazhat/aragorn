"""Focused lifecycle/channel retirement checks over inert kernel observations.

No sockets, services, provider requests, credentials or filesystem operations
are created. These source checks are not authenticated live terminal evidence.
"""

from contextlib import ExitStack
import copy
import linecache
import os
import socket
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_service_lifecycle as subject


class Connection:
    def __init__(self, descriptor, peer):
        self.descriptor, self.peer = descriptor, peer

    def fileno(self):
        return self.descriptor

    def getsockopt(self, level, name):
        if level != socket.SOL_SOCKET:
            raise AssertionError("unexpected socket level")
        if name == subject.channels.transport._DOMAIN:
            return socket.AF_UNIX
        if name == socket.SO_TYPE:
            return socket.SOCK_SEQPACKET
        raise AssertionError("unexpected socket option")


class PiServiceRetirementTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(linecache, "getlines", return_value=[]))
        self.stack.enter_context(mock.patch.object(linecache, "checkcache", return_value=None))
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (socket, "getaddrinfo"), (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "scandir", "readlink",
                     "unlink", "mkdir", "rmdir", "chmod", "chown", "listdir", "fsync"):
            self.stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("filesystem operation forbidden")))
        self.stack.enter_context(mock.patch.object(subject.channels.sys, "platform", "linux"))
        self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(os, "getegid", return_value=0))
        self.clock = self.stack.enter_context(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.pins = {"python_digest": "sha256:" + "a" * 64}
        self.runtime = SimpleNamespace(observation=self.pins)
        identities = {role: {"uid": 1201 + index, "gid": 1301 + index}
                      for index, role in enumerate(subject.ROLES)}
        self.config = SimpleNamespace(identities=identities, deadline=125.0, guard=mock.Mock())
        self.public = SimpleNamespace(deadline=125.0, guard=mock.Mock())
        self.binding = object()
        self.owner = subject.PiServiceLifecycle(subject._SEAL, self.runtime, self.config,
                                                self.public, self.binding, 125.0, 5.0)
        self.owner._active = True
        self.connections, self.expected, self.states, self.members = {}, {}, {}, {}
        self.dead = set()
        for index, (role, service) in enumerate(self.owner.services.items()):
            service.started = service.start_attempted = True
            service.pid, service.pidfd, service.start_ticks = 401 + index, 501 + index, 801 + index
            service.invocation, service.unit_started_at = str(index + 1) * 32, "100000000"
            service.immutable_digest = "sha256:" + "b" * 64
            service.cgroup_parent_fd, service.cgroup_fd = 601 + index, 701 + index
            peer = service.pid, service.uid, service.gid
            service.connection = self.connections[role] = Connection(41 + index, peer)
            self.expected[role] = {"pid": service.pid, "uid": service.uid, "gid": service.gid,
                "start_ticks": service.start_ticks, "cgroup": service.plan.profile.cgroup,
                "executable_digest": self.pins["python_digest"]}
            self.members[service.plan.profile.cgroup] = (service.pid,)
            self.states[role] = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                "MainPID": str(service.pid), "ControlPID": "0", "InvocationID": service.invocation,
                "ExecMainPID": str(service.pid), "ExecMainStartTimestampMonotonic": service.unit_started_at,
                "ControlGroup": service.plan.profile.cgroup}
        self.lease = subject.channels.PiServiceChannels(subject.channels._SEAL, self.connections,
            copy.deepcopy(self.expected), self.binding, self.runtime, self.pins, 120.0, self.owner)
        self.lease._pidfds = [901, 902, 903]
        self.owner._attach_channels(self.lease)
        self.ownership = self.stack.enter_context(mock.patch.object(subject.PiServiceLifecycle, "_ownership"))
        self.state = self.stack.enter_context(mock.patch.object(subject, "_state",
            side_effect=lambda role, deadline: dict(self.states[role])))
        self.readback = self.stack.enter_context(mock.patch.object(subject, "_readback",
            side_effect=lambda service, state, deadline: service.immutable_digest))
        self.exited = self.stack.enter_context(mock.patch.object(subject.native, "_exited",
            side_effect=lambda fd: fd in self.dead))
        self.cgroup = self.stack.enter_context(mock.patch.object(subject.native, "_cgroup_owned", return_value=False))
        self.stack.enter_context(mock.patch.object(subject.process, "_cgroup_processes",
            side_effect=lambda path: self.members[path]))
        def observed(pid, field):
            return next(item[field] for item in self.expected.values() if item["pid"] == pid)
        for name, field in (("_process_start_time", "start_ticks"), ("_process_cgroup", "cgroup"),
                            ("_executable_digest", "executable_digest")):
            self.stack.enter_context(mock.patch.object(subject.process, name,
                side_effect=lambda pid, field=field: observed(pid, field)))
        self.stack.enter_context(mock.patch.object(subject.broker, "_peer_credentials", side_effect=lambda conn: conn.peer))
        self.stack.enter_context(mock.patch.object(subject.channels, "_deployment_pins", return_value=self.pins))
        def peer_live(conn, peer, descriptor, deadline):
            if peer[0] + 100 in self.dead:
                raise RuntimeError("captured peer exited")
        self.live = self.stack.enter_context(mock.patch.object(subject.transport, "require_peer_live", side_effect=peer_live))

    def exit(self, role="provider", *, collected=False):
        service = self.owner.services[role]
        self.dead.add(service.pidfd)
        self.members[service.plan.profile.cgroup] = ()
        self.states[role].update(ActiveState="inactive", SubState="dead", MainPID="0")
        if collected:
            self.states[role].update(LoadState="not-found", InvocationID="")

    def refused(self, operation):
        with self.assertRaises((subject.PiServiceLifecycleError, subject.channels.PiServiceChannelsError,
                                subject.native.PiNativeSupervisorError, RuntimeError)):
            operation()

    def test_unavailable_guard_requires_all_three_live_generations(self):
        self.lease.guard()
        self.assertEqual({call.args[0].role for call in self.readback.call_args_list}, set(subject.ROLES))
        self.assertFalse(self.lease.provider_retired)

    def test_provider_exit_without_terminal_retirement_refuses(self):
        self.exit()
        self.refused(self.lease.guard)

    def test_authenticated_retirement_accepts_exact_loaded_exit(self):
        self.exit()
        self.lease.retire_provider()
        self.lease.guard()
        self.assertTrue(self.lease.provider_retired)
        self.assertFalse(self.lease._provider_retiring)
        self.assertFalse(self.owner.services["provider"].terminal)

    def test_authenticated_retirement_accepts_cleared_terminal_invocation(self):
        self.exit()
        self.states["provider"]["InvocationID"] = ""
        self.lease.retire_provider()
        self.assertTrue(self.lease.provider_retired)

    def test_authenticated_retirement_accepts_collected_unit_only_with_empty_cgroup(self):
        self.exit(collected=True)
        self.lease.retire_provider()
        self.lease.guard()
        self.assertTrue(self.lease.provider_retired)

    def test_retirement_before_exit_keeps_full_live_provider_checks(self):
        self.lease.retire_provider()
        self.readback.reset_mock()
        self.lease.guard()
        self.assertEqual([call.args[0].role for call in self.readback.call_args_list], list(subject.ROLES))

    def test_exit_after_retirement_uses_same_original_generation(self):
        self.lease.retire_provider()
        self.exit()
        self.lease.guard()
        self.assertTrue(self.lease.provider_retired)

    def test_second_retirement_refuses_and_does_not_reset_state(self):
        self.lease.retire_provider()
        self.refused(self.lease.retire_provider)
        self.assertTrue(self.lease.provider_retired)
        self.assertFalse(self.lease._provider_retiring)

    def test_ordinary_check_cannot_request_provider_exit_exception(self):
        self.exit()
        self.refused(lambda: self.lease._check(allow_provider_exit=True))
        self.assertFalse(self.lease.provider_retired)

    def test_nested_retirement_refuses_without_changing_outer_transition(self):
        self.lease._provider_retiring = True
        self.refused(self.lease.retire_provider)
        self.assertTrue(self.lease._provider_retiring)
        self.assertFalse(self.lease.provider_retired)

    def test_ordinary_lifecycle_guard_cannot_request_provider_exit_exception(self):
        self.exit()
        self.refused(lambda: self.owner.guard_inputs_and_units(self.lease, deadline=110.0, allow_provider_exit=True))

    def test_action_exit_prevents_retirement(self):
        self.exit("action")
        self.exit()
        self.refused(self.lease.retire_provider)
        self.assertFalse(self.lease.provider_retired)
        self.assertFalse(self.lease._provider_retiring)

    def test_sensor_exit_prevents_retirement(self):
        self.exit("sensor")
        self.exit()
        self.refused(self.lease.retire_provider)
        self.assertFalse(self.lease.provider_retired)

    def test_action_exit_after_retirement_still_refuses(self):
        self.lease.retire_provider()
        self.exit("action")
        self.refused(self.lease.guard)

    def test_sensor_exit_after_retirement_still_refuses(self):
        self.lease.retire_provider()
        self.exit("sensor")
        self.refused(self.lease.guard)

    def test_foreign_provider_invocation_refuses(self):
        self.exit()
        self.states["provider"]["InvocationID"] = "f" * 32
        self.refused(self.lease.retire_provider)

    def test_foreign_exec_main_pid_refuses(self):
        self.exit()
        self.states["provider"]["ExecMainPID"] = "9999"
        self.refused(self.lease.retire_provider)

    def test_changed_unit_start_timestamp_refuses(self):
        self.exit()
        self.states["provider"]["ExecMainStartTimestampMonotonic"] = "100000001"
        self.refused(self.lease.retire_provider)

    def test_changed_unit_properties_refuse(self):
        self.exit()
        self.readback.side_effect = lambda service, state, deadline: "changed" if service.role == "provider" else service.immutable_digest
        self.refused(self.lease.retire_provider)

    def test_replaced_cgroup_refuses_even_after_unit_collection(self):
        self.exit(collected=True)
        def same(service, **options):
            if service.role == "provider":
                raise subject.native.PiNativeSupervisorError("owned cgroup name replaced")
            return False
        self.cgroup.side_effect = same
        self.refused(self.lease.retire_provider)

    def test_residual_cgroup_process_refuses(self):
        self.exit()
        self.members[self.owner.services["provider"].plan.profile.cgroup] = (9999,)
        self.refused(self.lease.retire_provider)

    def test_collected_unit_with_control_process_refuses(self):
        self.exit(collected=True)
        self.states["provider"]["ControlPID"] = "9999"
        self.refused(self.lease.retire_provider)

    def test_new_unit_after_collected_retirement_refuses(self):
        self.exit(collected=True)
        self.lease.retire_provider()
        self.states["provider"].update(LoadState="loaded", ActiveState="active", SubState="running",
                                       MainPID="9999", InvocationID="f" * 32)
        self.refused(self.lease.guard)

    def test_changed_provider_kernel_peer_refuses_terminal_transition(self):
        self.exit()
        self.connections["provider"].peer = (9999, 1203, 1303)
        self.refused(self.lease.retire_provider)
        self.assertFalse(self.lease.provider_retired)
        self.assertFalse(self.lease._provider_retiring)

    def test_changed_provider_capture_connection_refuses(self):
        self.exit()
        self.owner.services["provider"].connection = Connection(99, (403, 1203, 1303))
        self.refused(self.lease.retire_provider)

    def test_changed_provider_expected_generation_refuses(self):
        self.exit()
        self.lease._expected["provider"]["start_ticks"] += 1
        self.refused(self.lease.retire_provider)

    def test_held_configuration_failure_preserves_unretired_state(self):
        self.exit()
        self.config.guard.side_effect = RuntimeError("changed protected configuration")
        self.refused(self.lease.retire_provider)
        self.assertFalse(self.lease.provider_retired)
        self.assertFalse(self.lease._provider_retiring)

    def test_retirement_cannot_extend_original_deadline(self):
        self.exit()
        self.refused(lambda: self.lease.retire_provider(deadline=120.1))
        self.assertFalse(self.lease.provider_retired)
        self.assertFalse(self.lease._provider_retiring)

    def test_tightened_deadline_reaches_both_live_and_terminal_guards(self):
        self.exit()
        self.lease.retire_provider(deadline=105.0)
        self.assertTrue(all(call.args[1] == 105.0 for call in self.state.call_args_list))
        self.assertEqual(self.lease.deadline, 120.0)
        self.assertEqual(self.owner.operation_deadline, 120.0)

    def test_expired_deadline_cannot_authorize_retirement(self):
        self.exit()
        self.clock.return_value = 121.0
        self.refused(self.lease.retire_provider)
        self.assertFalse(self.lease._provider_retiring)

    def test_foreign_lease_cannot_use_captured_lifecycle(self):
        other = subject.channels.PiServiceChannels(subject.channels._SEAL, self.connections,
            self.expected, self.binding, self.runtime, self.pins, 120.0, self.owner)
        self.refused(lambda: self.owner.guard_inputs_and_units(other, deadline=110.0))

    def test_no_lifecycle_channel_retirement_remains_supported(self):
        self.lease._lifecycle = None
        self.exit()
        self.lease.retire_provider()
        self.lease.guard()
        self.assertTrue(self.lease.provider_retired)

    def test_retirement_does_not_claim_owned_cleanup_or_release_pidfds(self):
        self.exit()
        self.lease.retire_provider()
        self.assertEqual(self.lease._pidfds, [901, 902, 903])
        self.assertEqual(self.lease.observation["cleanup"], "HELD")
        self.assertEqual(self.owner.observation["cleanup"]["status"], "PENDING")
        self.assertFalse(self.owner.observation["phase3_exit_eligible"])


if __name__ == "__main__":
    unittest.main()
