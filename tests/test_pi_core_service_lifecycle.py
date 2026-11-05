"""New service lifecycle checks; all kernel/service/file effects are inert.

No executable, unit, socket, grant operation, provider call or target import is
run. Existing codecs and the fixed lifecycle state machine compose over mocks.
"""

from contextlib import ExitStack, contextmanager
import copy
from dataclasses import replace
import linecache
import os
from pathlib import Path
import socket
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_service_lifecycle as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_worker import RuntimeActionWorkerBinding
from tests import test_runtime_capability_grant as fixtures


class RuntimeHold:
    pass


class ConfigurationHold:
    pass


class PublicHold:
    pass


class ChannelHold:
    pass


def metadata(inode=1, mode=stat.S_IFDIR | 0o755, uid=0, gid=0, size=0):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid,
        st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)


class InertSocket:
    def __init__(self, peer=None, fd=77):
        self.peer, self.descriptor, self.closes = peer, fd, 0
        self.accepted = None
        self.timeout = None
        self.bound, self.backlog = None, None

    def fileno(self): return self.descriptor
    def settimeout(self, value): self.timeout = value
    def set_inheritable(self, value):
        if value: raise AssertionError("inheritable socket")
    def accept(self): return self.accepted, None
    def bind(self, path): self.bound = path
    def listen(self, backlog): self.backlog = backlog
    def close(self):
        self.closes += 1
        if self.closes > 1: raise AssertionError("close retry")


class PiServiceLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(linecache, "getlines", return_value=[]))
        self.stack.enter_context(mock.patch.object(linecache, "checkcache", return_value=None))
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (socket, "getaddrinfo"), (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "scandir", "readlink", "unlink",
                     "mkdir", "rmdir", "chmod", "chown", "fchmod", "fchown", "fsync", "listdir"):
            self.stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("unmocked filesystem operation")))
        self.close_fd = self.stack.enter_context(mock.patch.object(os, "close"))
        self.stack.enter_context(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.stack.enter_context(mock.patch.object(subject.time, "time", return_value=102.0))
        self.stack.enter_context(mock.patch.object(socket, "SOCK_CLOEXEC", 0x80000, create=True))
        self.sleep = self.stack.enter_context(mock.patch.object(subject.time, "sleep", side_effect=AssertionError("unbounded polling")))
        self.stack.enter_context(mock.patch.object(os, "getpid", return_value=9000))
        self.stack.enter_context(mock.patch.object(subject.provision, "PiServiceRuntime", RuntimeHold))
        self.stack.enter_context(mock.patch.object(subject.configuration, "PiServiceConfiguration", ConfigurationHold))
        self.stack.enter_context(mock.patch.object(subject.configuration, "PiProviderInputs", PublicHold))
        self.stack.enter_context(mock.patch.object(subject.channels, "PiServiceChannels", ChannelHold))
        self.runtime, self.config, self.public = RuntimeHold(), ConfigurationHold(), PublicHold()
        self.ids = {role: {"uid": 1201 + index, "gid": 1301 + index}
                    for index, role in enumerate((*subject.ROLES, "worker"))}
        self.grant = fixtures._grant()
        self.binding = RuntimeActionWorkerBinding(*(self.grant[key] for key in
            ("runtime_digest", "active_skill_digest", "policy_digest", "policy_version")))
        self.config.configurations = {role: {"identities": copy.deepcopy(self.ids),
            "capability_grant": copy.deepcopy(self.grant)} for role in subject.ROLES}
        self.config.identities = copy.deepcopy(self.ids)
        self.public.profile = {"service_uid": 1203, "service_gid": 1303}
        self.runtime.binding = {"schema": subject.provision.BINDING_SCHEMA_V2,
            "wrappers": {role: {"argv": ["/usr/bin/python3", "-I", "-S", "-B", "/opt/aragorn/bin/" + role + ".py"]}
                         for role in subject.ROLES}}
        self.runtime.observation = {"python_digest": "sha256:" + "f" * 64}
        for name, held in (("runtime", self.runtime), ("configuration", self.config), ("provider", self.public)):
            held.root, held.deadline = Path("/var/lib/aragorn/" + name + "/root"), 130.0
            held.guard = mock.Mock()
        self.events = []
        self.prerequisites = self.stack.enter_context(mock.patch.object(subject.native, "_prerequisites"))
        self.command = self.stack.enter_context(mock.patch.object(subject.native, "_command", return_value=(0, b"")))
        self.real_manager = subject._manager_environment
        self.manager = self.stack.enter_context(mock.patch.object(subject, "_manager_environment",
            side_effect=lambda deadline: self.events.append("manager-empty")))
        self.real_state = subject._state
        self.state = self.stack.enter_context(mock.patch.object(subject, "_state", return_value=self.absent()))
        self.real_ready = subject._readiness
        self.readiness = self.stack.enter_context(mock.patch.object(subject, "_readiness", return_value={"read_only": True}))
        self.real_generation = subject._generation
        self.generation = self.stack.enter_context(mock.patch.object(subject, "_generation",
            side_effect=lambda service, deadline, **kwargs: self.events.append("generation-" + service.role)))
        self.real_capture = subject._capture
        self.capture = self.stack.enter_context(mock.patch.object(subject, "_capture", side_effect=self.capture_service))
        self.real_listener = subject._listener_ready
        self.listener = self.stack.enter_context(mock.patch.object(subject, "_listener_ready",
            side_effect=lambda *args: self.events.append("action-LISTEN") or (1, 888)))
        self.real_prepare = subject.PiServiceLifecycle._prepare
        self.prepare = self.stack.enter_context(mock.patch.object(subject.PiServiceLifecycle, "_prepare",
            lambda held: self.prepare_service(held)))
        self.real_ownership = subject.PiServiceLifecycle._ownership
        self.ownership = self.stack.enter_context(mock.patch.object(subject.PiServiceLifecycle, "_ownership"))
        self.real_stop = subject.PiServiceLifecycle._stop
        self.stop = self.stack.enter_context(mock.patch.object(subject.PiServiceLifecycle, "_stop",
            lambda held, service: self.stop_service(held, service)))
        self.stack.enter_context(mock.patch.object(subject.broker, "_peer_credentials", side_effect=lambda connection: connection.peer))
        self.channel_lease = ChannelHold()
        self.channel_lease.request_channels = object()
        self.channel_error = None
        @contextmanager
        def channel_hold(connections, expected, binding, **kwargs):
            self.events.append("channels-held")
            self.assertEqual(set(connections), set(subject.ROLES))
            self.assertEqual(expected["action"]["executable_digest"], self.runtime.observation["python_digest"])
            self.assertEqual(kwargs["deadline"], 120.0)
            lease, owner = self.channel_lease, kwargs["lifecycle_custody"]
            lease._seal, lease._active = subject.channels._SEAL, True
            lease._lifecycle, lease._deployment, lease._binding = owner, self.runtime, binding
            lease._deadline, lease._expected = kwargs["deadline"], expected
            lease._connections = tuple(connections[role] for role in subject.ROLES)
            def guard(*, deadline):
                owner.guard_inputs_and_units(lease, deadline=deadline)
                self.runtime.guard(deadline=deadline)
            lease.guard = mock.Mock(side_effect=guard)
            owner._attach_channels(lease)
            try: yield self.channel_lease
            finally:
                self.events.append("channels-withdrawn")
                if self.channel_error: raise self.channel_error
        self.channels = self.stack.enter_context(mock.patch.object(subject.channels, "hold_pi_service_channels", side_effect=channel_hold))
        self.stack.enter_context(mock.patch.object(subject.native, "_missing", return_value=True))

    def absent(self):
        return {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0",
                "ControlPID": "0", "InvocationID": ""}

    def instance(self):
        return subject.PiServiceLifecycle(subject._SEAL, self.runtime, self.config, self.public,
            self.binding, 125.0, 5.0)

    def hold(self, **changes):
        return subject.hold_native_pi_services(**(dict(deployment=self.runtime, configuration=self.config,
            provider_inputs=self.public, binding=self.binding, deadline=125.0) | changes))

    def prepare_service(self, held):
        self.events.append("prepare")
        # No namespace creation in this orchestration test. Kernel-facing
        # preparation and ownership boundaries are mocked, not qualified.
        held._fds[subject._ACTION] = 501
        held._identities[subject._ACTION] = (1, 500, stat.S_IFDIR | 0o750, 1201, 1301)
        for index, (role, service) in enumerate(held.services.items()):
            subject._plan(service, held)
            service.listener = InertSocket(fd=70 + index)
            service.listener.accepted = InertSocket((8001 + index, service.uid, service.gid), 80 + index)

    def capture_service(self, service, deadline):
        self.events.append("capture-" + service.role)
        index = subject.ROLES.index(service.role)
        service.pid, service.pidfd, service.start_ticks = 8001 + index, 600 + index, 200 + index
        service.invocation, service.unit_started_at = str(index + 1) * 32, "100000000"
        service.immutable_digest = "sha256:" + "a" * 64
        service.cgroup_parent_fd, service.cgroup_fd = 700 + index, 800 + index

    def stop_service(self, held, service):
        self.events.append("stop-" + service.role)
        service.terminal = service.start_attempted

    def test_fixed_start_order_passive_readiness_and_owned_channel_withdrawal(self):
        with self.hold() as held:
            self.assertIs(held.channels, self.channel_lease)
            self.assertEqual(held.operation_deadline, 120.0)
            self.assertLess(self.events.index("capture-action"), self.events.index("action-LISTEN"))
            self.assertLess(self.events.index("action-LISTEN"), self.events.index("capture-sensor"))
            self.assertLess(self.events.index("capture-sensor"), self.events.index("capture-provider"))
        self.assertLess(self.events.index("channels-withdrawn"), self.events.index("stop-provider"))
        self.assertEqual([event for event in self.events if event.startswith("stop-")],
                         ["stop-provider", "stop-sensor", "stop-action"])
        self.assertEqual(held.observation["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertFalse(held.observation["provider_dispatched"])
        self.assertFalse(held.observation["phase3_exit_eligible"])

    def test_original_wrapper_lifetime_keeps_cleanup_reserve_without_extending_channels(self):
        held = self.instance()
        subject._plan(held.services["action"], held)
        self.assertEqual(held.services["action"].argv[-2:], ("9000", "125000000000"))
        self.assertEqual(held.operation_deadline, 120.0)

    def test_all_three_absence_checks_precede_first_start(self):
        with self.hold(): pass
        self.assertEqual([call.args[0] for call in self.state.call_args_list[:3]], list(subject.ROLES))

    def test_existing_unit_refuses_before_resources_or_commands(self):
        self.state.return_value = {**self.absent(), "LoadState": "loaded"}
        with self.assertRaises(subject.PiServiceLifecycleError) as raised: 
            with self.hold(): pass
        self.command.assert_not_called()
        self.assertNotIn("prepare", self.events)
        self.assertEqual(raised.exception.pi_service_lifecycle_observation["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")

    def test_readiness_refusal_has_pristine_cleanup_not_false_hold(self):
        self.readiness.side_effect = RuntimeError("inert unprepared grant")
        with self.assertRaises(RuntimeError) as raised:
            with self.hold(): pass
        self.command.assert_not_called()
        self.assertEqual(raised.exception.pi_service_lifecycle_observation["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")

    def test_partial_directory_creation_without_captured_fd_retains_hold(self):
        held = self.instance()
        held._created = [subject._ROOT]
        with self.assertRaises(subject.PiServiceLifecycleError): held.close()
        self.assertEqual(held.observation["cleanup"]["status"], "CLEANUP_HOLD")

    def test_plain_wire_objects_cannot_supply_custody(self):
        for name in ("deployment", "configuration", "provider_inputs"):
            with self.subTest(name=name), self.assertRaises(subject.PiServiceLifecycleError):
                with self.hold(**{name: {}}): pass
        self.command.assert_not_called()

    def test_invalid_deadline_or_cleanup_reserve_refuses_without_effects(self):
        for changes in ({"deadline": 100.0}, {"deadline": 131.0}, {"cleanup_timeout_seconds": 0},
                        {"cleanup_timeout_seconds": 6}, {"cleanup_timeout_seconds": True}):
            with self.subTest(changes=changes), self.assertRaises(Exception):
                with self.hold(**changes): pass
        self.command.assert_not_called()

    def test_held_input_budget_cannot_be_extended(self):
        self.public.deadline = 119.0
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.hold(): pass
        self.command.assert_not_called()

    def test_provider_profile_must_match_dedicated_nonroot_role(self):
        self.public.profile["service_uid"] = 1204
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.hold(): pass
        self.command.assert_not_called()

    def test_request_binding_must_match_current_protected_grant(self):
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.hold(binding=replace(self.binding, policy_version=4)): pass
        self.command.assert_not_called()

    def test_unwrapped_v1_image_refuses_before_start(self):
        self.runtime.binding["schema"] = subject.provision.BINDING_SCHEMA
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.hold(): pass
        self.command.assert_not_called()

    def test_manager_environment_must_be_exact_empty_typed_array(self):
        for raw in (b'as 1 "OPENSSL_CONF=/tmp/bad"', b"as 0 extra", b"s \"\"", b"as 00"):
            self.command.return_value = (0, raw)
            with self.assertRaises(subject.PiServiceLifecycleError): self.real_manager(120.0)
        self.command.return_value = (0, b"as 0\n")
        self.real_manager(120.0)

    def test_each_start_rechecks_empty_manager_before_command(self):
        with self.hold(): pass
        self.assertEqual(self.manager.call_count, 4)  # Initial plus each real start; readback is mocked.

    def test_start_error_has_no_automatic_retry(self):
        self.command.return_value = (1, b"inert failed start")
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.hold(): pass
        self.assertEqual(self.command.call_count, 1)
        self.assertNotIn("capture-action", self.events)

    def test_wrong_postexec_peer_refuses_before_sensor_start(self):
        original = self.prepare_service
        def prepare(held):
            original(held)
            held.services["action"].listener.accepted.peer = (9000, 0, 0)
        with mock.patch.object(subject.PiServiceLifecycle, "_prepare", prepare), self.assertRaises(subject.PiServiceLifecycleError):
            with self.hold(): pass
        self.assertNotIn("capture-sensor", self.events)

    def test_listener_readiness_failure_never_starts_sensor(self):
        self.listener.side_effect = RuntimeError("not listening")
        with self.assertRaises(RuntimeError):
            with self.hold(): pass
        self.assertNotIn("capture-sensor", self.events)
        self.assertNotIn("capture-provider", self.events)

    def test_plan_contains_only_fixed_isolated_credential_free_wrappers(self):
        held = self.instance()
        for role, service in held.services.items():
            subject._plan(service, held)
            self.assertEqual(service.scalar["PrivateNetwork"], "yes")
            self.assertEqual(service.scalar["RestrictAddressFamilies"], "AF_UNIX")
            self.assertEqual(service.scalar["KillSignal"], "2")
            self.assertEqual(service.scalar["PAMName"], "")
            self.assertEqual(service.argv[service.argv.index("--") + 1:][:-2], tuple(self.runtime.binding["wrappers"][role]["argv"]))
            self.assertFalse(any("LoadCredential=" in arg or "SetCredential=" in arg for arg in service.argv))
            self.assertNotIn("/usr/bin/env", service.argv)
            self.assertNotIn("/bin/sh", service.argv)

    def test_only_sensor_has_exact_adoption_capabilities_and_action_group(self):
        held = self.instance()
        for role, service in held.services.items():
            subject._plan(service, held)
            self.assertEqual(service.scalar["CapabilityBoundingSet"], subject._CAPS if role == "sensor" else "")
            self.assertEqual(service.scalar["SupplementaryGroups"], "1301" if role == "sensor" else "")

    def test_config_and_provider_mounts_are_individual_and_readonly(self):
        held = self.instance()
        for role, service in held.services.items():
            subject._plan(service, held)
            targets = [target for source, target in service.binds["BindReadOnlyPaths"]]
            self.assertIn("/etc/aragorn/pi-" + role + "-service.json", targets)
            self.assertNotIn("/etc/aragorn", targets)
            self.assertEqual("/etc/aragorn/pi-provider-ca.pem" in targets, role == "provider")

    def test_unsafe_mount_path_is_not_interpolated(self):
        held = self.instance()
        self.runtime.root = Path("/var/lib/image:override")
        with self.assertRaises(subject.PiServiceLifecycleError): subject._plan(held.services["action"], held)

    def test_readback_rejects_unexpected_credentials_before_success(self):
        service = self.instance().services["provider"]
        subject._plan(service, self.instance())
        def properties(role, name, deadline):
            if name == "LoadCredential": return ["a(ss)", "1", "key", "/secret"]
            return [subject._EMPTY[name], "0"]
        with mock.patch.object(subject, "_property", side_effect=properties), self.assertRaises(subject.PiServiceLifecycleError):
            subject._readback(service, service.scalar, 120.0)

    def test_readback_binds_full_exec_argv_mounts_and_manager_environment(self):
        held = self.instance()
        service = held.services["provider"]
        subject._plan(service, held)
        def properties(role, name, deadline):
            if name in subject._EMPTY: return [subject._EMPTY[name], "0"]
            if name in ("RuntimeMaxUSec", "TimeoutStopUSec"): return ["t", "30000000" if name == "RuntimeMaxUSec" else "5000000"]
            if name in service.binds:
                value = ["a(ssbt)", str(len(service.binds[name]))]
                for source, target in service.binds[name]: value.extend((str(source), target, "false", "16384" if name == "BindReadOnlyPaths" else "0"))
                return value
            argv = service.argv[service.argv.index("--") + 1:]
            return ["a(sasbttttuii)", "1", argv[0], str(len(argv)), *argv, "false", *(["0"] * 7)]
        with mock.patch.object(subject, "_property", side_effect=properties):
            digest = subject._readback(service, service.scalar, 120.0)
        self.assertTrue(digest.startswith("sha256:"))
        self.manager.assert_called_once_with(120.0)

    def test_guard_tightens_all_custody_and_peer_budgets(self):
        with self.hold() as held:
            self.runtime.guard.reset_mock()
            self.channel_lease.guard.reset_mock()
            held.guard(deadline=110.0)
            self.runtime.guard.assert_called_once_with(deadline=110.0)
            self.channel_lease.guard.assert_called_once_with(deadline=110.0)
            self.assertEqual(held.operation_deadline, 120.0)
            with self.assertRaises(subject.PiServiceLifecycleError): held.guard(deadline=121.0)

    def test_closed_lifecycle_cannot_supply_channels_or_new_guard(self):
        with self.hold() as held: pass
        with self.assertRaises(subject.PiServiceLifecycleError): held.guard()
        with self.assertRaises(subject.PiServiceLifecycleError): _ = held.channels

    def test_channel_attachment_is_one_shot_and_exact_process_custody(self):
        with self.hold() as held:
            with self.assertRaises(subject.PiServiceLifecycleError): held._attach_channels(self.channel_lease)
            with self.assertRaises(subject.PiServiceLifecycleError):
                held.guard_inputs_and_units(ChannelHold(), deadline=110.0)
            with self.assertRaises(subject.PiServiceLifecycleError):
                held.guard_inputs_and_units(self.channel_lease, deadline=121.0)

    def test_channel_attachment_rejects_substituted_expected_process(self):
        held = self.instance()
        self.prepare_service(held)
        held._active = True
        for item in held.services.values():
            self.capture_service(item, 120.0)
            item.started = True
            item.connection = item.listener.accepted
        lease = ChannelHold()
        lease._seal, lease._active = subject.channels._SEAL, True
        lease._lifecycle, lease._deployment, lease._binding = held, self.runtime, self.binding
        lease._deadline = 120.0
        lease._connections = tuple(item.connection for item in held.services.values())
        lease._expected = {role: {"pid": item.pid + 1, "uid": item.uid, "gid": item.gid,
            "start_ticks": item.start_ticks, "cgroup": item.plan.profile.cgroup,
            "executable_digest": self.runtime.observation["python_digest"]}
            for role, item in held.services.items()}
        with self.assertRaises(subject.PiServiceLifecycleError): held._attach_channels(lease)
        self.assertIsNone(held._channels)

    def test_service_exit_during_body_cannot_become_success_after_clean_stop(self):
        with self.assertRaisesRegex(subject.PiServiceLifecycleError, "service exited") as raised:
            with self.hold():
                self.generation.side_effect = subject.PiServiceLifecycleError("service exited during NO_REQUEST")
        self.assertEqual(raised.exception.pi_service_lifecycle_observation["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual([item for item in self.events if item.startswith("stop-")],
                         ["stop-provider", "stop-sensor", "stop-action"])

    def test_channel_withdrawal_failure_never_becomes_verified_cleanup(self):
        self.channel_error = RuntimeError("inert PIDFD close uncertainty")
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            with self.hold(): pass
        self.assertEqual(raised.exception.pi_service_lifecycle_observation["cleanup"]["status"], "CLEANUP_HOLD")
        self.assertEqual([event for event in self.events if event.startswith("stop-")], ["stop-provider", "stop-sensor", "stop-action"])

    def test_child_endpoint_is_not_removed_by_root_cleanup(self):
        held = self.instance()
        held._created = [subject._ACTION]
        held._fds = {subject._ACTION: 501}
        with mock.patch.object(subject.native, "_missing", return_value=False), self.assertRaises(subject.PiServiceLifecycleError): held.close()
        self.assertEqual(held.observation["cleanup"]["status"], "CLEANUP_HOLD")

    def test_cleanup_failure_cannot_be_retried_into_success(self):
        held = self.instance()
        held._created = [subject._ROOT]
        with self.assertRaises(subject.PiServiceLifecycleError): held.close()
        with self.assertRaises(subject.PiServiceLifecycleError): held.close()

    def test_unknown_start_outcome_never_authorizes_stop(self):
        held = self.instance()
        held.services["action"].start_attempted = True
        with self.assertRaises(subject.PiServiceLifecycleError): self.real_stop(held, held.services["action"])
        self.command.assert_not_called()

    def test_replaced_generation_refuses_stop(self):
        held = self.instance()
        item = held.services["action"]
        item.start_attempted = item.started = True
        self.capture_service(item, 120.0)
        self.state.return_value = {"LoadState": "loaded"}
        self.generation.side_effect = subject.PiServiceLifecycleError("replacement generation")
        with mock.patch.object(subject.native, "_exited", return_value=False), self.assertRaises(subject.PiServiceLifecycleError):
            self.real_stop(held, item)
        self.command.assert_not_called()

    def test_stop_is_one_attempt_and_requires_pidfd_exit_plus_cgroup_cleanup(self):
        held, item = self.instance(), self.instance().services["action"]
        item.start_attempted = item.started = True
        self.capture_service(item, 120.0)
        self.state.side_effect = [{"LoadState": "loaded"}, self.absent()]
        with mock.patch.object(subject.native, "_exited", side_effect=[False, True]), mock.patch.object(subject.native, "_cgroup_empty") as empty:
            self.real_stop(held, item)
        self.command.assert_called_once_with(("/usr/bin/systemctl", "stop", "--no-block", "aragorn-pi-action.service"), 125.0)
        empty.assert_called_once_with(item)
        self.assertTrue(item.terminal)

    def test_namespace_preparation_uses_only_owned_skeleton_and_fixed_postexec_listeners(self):
        held = self.instance()
        directories, sockets = [], []
        def mkdir(owner, path, uid=0, gid=0, mode=0o755):
            directories.append((path, uid, gid, mode))
            owner._fds[path] = 300 + len(directories)
            owner._created.append(path)
            owner._identities[path] = subject.broker._directory_identity(metadata(300 + len(directories), stat.S_IFDIR | mode, uid, gid))
        def socket_factory(*args):
            value = InertSocket(fd=100 + len(sockets))
            sockets.append((args, value))
            return value
        def endpoint(name, *, dir_fd, **kwargs):
            role = next(role for role in subject.ROLES if held._fds[subject._ROOT / role] == dir_fd)
            return metadata(900 + subject.ROLES.index(role), stat.S_IFSOCK | 0o660, 0, self.ids[role]["gid"])
        with mock.patch.object(subject.lineage, "_open_protected_root", return_value=200), \
             mock.patch.object(subject.PiServiceLifecycle, "_mkdir", mkdir), \
             mock.patch.object(os, "open", return_value=400), mock.patch.object(os, "fstat", side_effect=lambda fd:
                metadata(200) if fd == 200 else metadata(400, stat.S_IFREG | 0o444)), \
             mock.patch.object(os, "fchmod"), mock.patch.object(os, "chown"), mock.patch.object(os, "chmod"), \
             mock.patch.object(os, "stat", side_effect=endpoint), mock.patch.object(socket, "socket", side_effect=socket_factory):
            self.real_prepare(held)
        self.assertIn((subject._ACTION, 1201, 1301, 0o750), directories)
        self.assertEqual(len(sockets), 3)
        self.assertEqual(len(held._files), 5)
        for role, (_, channel) in zip(subject.ROLES, sockets):
            self.assertEqual(channel.bound, f"/proc/self/fd/{held._fds[subject._ROOT / role]}/supervisor.sock")
            self.assertEqual(channel.backlog, 1)
            self.assertIn((held.services[role].root / "var/tmp", 0, 0, 0o755), directories)
            self.assertTrue(held.services[role].socket_identity)
        self.command.assert_not_called()

    def test_owned_directory_creation_is_absent_only_and_retains_exact_descriptor(self):
        held = self.instance()
        held._fds[Path("/run")] = 200
        before = metadata(300, stat.S_IFDIR | 0o700)
        after = metadata(300, stat.S_IFDIR | 0o750, 1201, 1301)
        with mock.patch.object(os, "mkdir") as mkdir, mock.patch.object(os, "open", return_value=300), \
             mock.patch.object(os, "fstat", side_effect=[before, after]), mock.patch.object(os, "stat", return_value=after), \
             mock.patch.object(os, "fchown") as owner, mock.patch.object(os, "fchmod") as mode, mock.patch.object(os, "fsync"):
            held._mkdir(subject._ACTION, 1201, 1301, 0o750)
        mkdir.assert_called_once_with(subject._ACTION.name, 0o700, dir_fd=200)
        owner.assert_called_once_with(300, 1201, 1301)
        mode.assert_called_once_with(300, 0o750)
        self.assertEqual(held._fds[subject._ACTION], 300)
        self.assertEqual(held._identities[subject._ACTION], subject.broker._directory_identity(after))

    def test_directory_and_endpoint_substitution_refuse_owned_cleanup(self):
        held = self.instance()
        info = metadata(300)
        held._fds[subject._ROOT] = 300
        held._identities[subject._ROOT] = subject.broker._directory_identity(info)
        with mock.patch.object(os, "fstat", return_value=info), mock.patch.object(os, "lstat", return_value=metadata(301)), \
             self.assertRaises(subject.PiServiceLifecycleError): self.real_ownership(held, 120.0)
        held._identities = {}
        held._fds[subject._ROOT / "action"] = 301
        held.services["action"].socket_identity = subject.broker._file_identity(metadata(400, stat.S_IFSOCK | 0o660))
        with mock.patch.object(os, "stat", return_value=metadata(401, stat.S_IFSOCK | 0o660)), \
             self.assertRaises(subject.PiServiceLifecycleError): self.real_ownership(held, 120.0)

    def test_actual_capture_retains_pidfd_start_and_cgroup_generation(self):
        item = self.instance().services["action"]
        self.state.return_value = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
            "MainPID": "8001", "InvocationID": "a" * 32, "ControlGroup": item.plan.profile.cgroup,
            "ExecMainStartTimestampMonotonic": "100000000"}
        with mock.patch.object(subject.native, "_pidfd", return_value=600), \
             mock.patch.object(subject.process, "_process_start_time", return_value=200), \
             mock.patch.object(subject.lineage, "_open_protected_root", return_value=700), \
             mock.patch.object(os, "open", return_value=800), mock.patch.object(os, "fstat", side_effect=lambda fd: metadata(fd)), \
             mock.patch.object(subject, "_readback", return_value="sha256:" + "d" * 64):
            self.real_capture(item, 120.0)
        self.assertEqual((item.pid, item.pidfd, item.start_ticks), (8001, 600, 200))
        self.assertEqual((item.cgroup_parent_fd, item.cgroup_fd), (700, 800))
        self.assertEqual(item.cgroup_identity, subject.broker._directory_identity(metadata(800)))
        self.generation.assert_called_once_with(item, 120.0)

    def test_actual_generation_rejects_replaced_invocation_start_cgroup_or_configuration(self):
        item = self.instance().services["action"]
        self.capture_service(item, 120.0)
        state = {"LoadState": "loaded", "MainPID": "8001", "InvocationID": item.invocation,
            "ExecMainPID": "8001", "ExecMainStartTimestampMonotonic": item.unit_started_at,
            "ControlGroup": item.plan.profile.cgroup, "ActiveState": "active"}
        with mock.patch.object(subject.native, "_exited", return_value=False), \
             mock.patch.object(subject.native, "_cgroup_owned"), \
             mock.patch.object(subject.process, "_process_start_time", return_value=200), \
             mock.patch.object(subject.process, "_process_cgroup", return_value=item.plan.profile.cgroup), \
             mock.patch.object(subject.process, "_cgroup_processes", return_value=(8001,)), \
             mock.patch.object(subject, "_readback", return_value=item.immutable_digest) as readback:
            self.state.return_value = state
            self.real_generation(item, 120.0)
            for field, value in (("InvocationID", "b" * 32), ("ExecMainStartTimestampMonotonic", "2"),
                                 ("ControlGroup", "/system.slice/other.service"), ("ExecMainPID", "8002")):
                self.state.return_value = {**state, field: value}
                with self.subTest(field=field), self.assertRaises(subject.PiServiceLifecycleError): self.real_generation(item, 120.0)
            self.state.return_value = state
            readback.return_value = "sha256:" + "e" * 64
            with self.assertRaises(subject.PiServiceLifecycleError): self.real_generation(item, 120.0)
        self.command.assert_not_called()

    def test_passive_listener_requires_owned_kernel_socket_and_directory_fd(self):
        item = self.instance().services["action"]
        item.pid = 8001
        directory = metadata(500, stat.S_IFDIR | 0o750, 1201, 1301)
        endpoint = metadata(888, stat.S_IFSOCK | 0o660, 1201, 1301)
        raw = b"Num RefCount Protocol Flags Type St Inode Path\n1: 2 0 00010000 0001 01 987 /proc/self/fd/12/sensor.sock\n"
        with mock.patch.object(subject.process, "_read_virtual_file", return_value=raw), \
             mock.patch.object(os, "listdir", return_value=["12", "13"]), \
             mock.patch.object(os, "readlink", side_effect=[str(subject._ACTION), "socket:[987]"]), \
             mock.patch.object(os, "stat", side_effect=lambda path, **kwargs: directory if str(path).startswith("/proc/") else endpoint):
            value = self.real_listener(item, 501, subject.broker._directory_identity(directory), 120.0)
        self.assertEqual(value, subject.broker._file_identity(endpoint))
        self.assertEqual(self.generation.call_count, 2)
        self.command.assert_not_called()

    def test_path_presence_without_listen_cannot_release_sensor(self):
        item = self.instance().services["action"]
        item.pid = 8001
        raw = b"header\n1: 2 0 00000000 0001 01 987 /proc/self/fd/12/sensor.sock\n"
        with mock.patch.object(subject.process, "_read_virtual_file", return_value=raw), \
             mock.patch.object(os, "listdir", return_value=["13"]), mock.patch.object(os, "readlink", return_value="socket:[987]"), \
             mock.patch.object(os, "stat", return_value=metadata(888, stat.S_IFSOCK | 0o660, 1201, 1301)), \
             self.assertRaisesRegex(AssertionError, "unbounded polling"):
            self.real_listener(item, 501, (1, 500), 120.0)

    def test_listener_procfd_alias_to_unowned_directory_refuses(self):
        item = self.instance().services["action"]
        item.pid = 8001
        raw = b"header\n1: 2 0 00010000 0001 01 987 /proc/self/fd/12/sensor.sock\n"
        with mock.patch.object(subject.process, "_read_virtual_file", return_value=raw), \
             mock.patch.object(os, "listdir", return_value=["13"]), mock.patch.object(os, "readlink", return_value="socket:[987]"), \
             mock.patch.object(os, "stat", return_value=metadata(999)), self.assertRaises(subject.PiServiceLifecycleError):
            self.real_listener(item, 501, (1, 500), 120.0)

    def test_readiness_requires_explicit_available_without_recovery_writes(self):
        grant_digest = canonical_digest(self.grant)
        available = {"schema": "aragorn/runtime-capability-grant-state/v1",
            "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": grant_digest, "status": "AVAILABLE", "claim": None, "result": None}
        broker_state = {"schema": "aragorn/runtime-action-broker-state/v2",
            "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY", "minimum_revocation_generation": 1,
            "minimum_mediator_health_epoch": 1, "consumed": [], "effect_journal": None}
        roots = {101: metadata(1, stat.S_IFDIR | 0o710, 1201, 1301), 102: metadata(2, stat.S_IFDIR | 0o710, 1201, 1301),
                 103: metadata(3, stat.S_IFDIR | 0o700, 1201, 1301), 104: metadata(4, stat.S_IFREG | 0o600, 1201, 1301)}
        with mock.patch.object(subject.broker, "_open_protected_directory", side_effect=[101, 102, 103]), \
             mock.patch.object(os, "open", return_value=104), mock.patch.object(os, "fstat", side_effect=lambda fd: roots[fd]), \
             mock.patch.object(os, "stat", return_value=roots[104]), mock.patch.object(os, "lstat", side_effect=[roots[101], roots[102], roots[103]]), \
             mock.patch.object(subject.fcntl, "flock") as lock, mock.patch.object(subject, "_read_at", side_effect=[canonical_json(broker_state), canonical_json(available)]):
            value = self.real_ready(self.config.configurations, 120.0)
        self.assertEqual(value["grant_digest"], grant_digest)
        self.assertTrue(value["read_only"])
        self.assertEqual(lock.call_count, 2)

    def test_readiness_missing_control_root_does_not_initialize_or_retry(self):
        with mock.patch.object(subject.broker, "_open_protected_directory", side_effect=FileNotFoundError), \
             self.assertRaises(FileNotFoundError): self.real_ready(self.config.configurations, 120.0)
        self.command.assert_not_called()

    def test_manager_and_generation_guards_do_not_claim_loaded_code_or_egress(self):
        held = self.instance()
        self.assertFalse(held.observation["loaded_code_verified"])
        self.assertEqual(held.observation["provider_mode"], "UNAVAILABLE_NO_EGRESS_NO_CREDENTIAL")
        self.assertFalse(held.observation["credential_read"])


if __name__ == "__main__":
    unittest.main()
