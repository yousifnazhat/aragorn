"""Native supervisor contract checks with every native edge mocked.

No process, Unix socket, systemd service, kernel PIDFD, or VM is activated.
Authored observations below are not native confinement/cleanup qualification.
"""

from __future__ import annotations

import dataclasses
import os
import select
import socket
import stat
import subprocess
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_confined_launch as confined
from aragorn import pi_core_native_supervisor as native
from aragorn.oci_worker_protocol import canonical_json
from aragorn.runtime_process_profile import RuntimeProcessProfile


def plan():
    profile = RuntimeProcessProfile("sha256:" + "a" * 64, "sha256:" + "b" * 64,
        "/system.slice/aragorn-pi-" + "c" * 32 + ".service",
        Path("/var/lib/aragorn/admitted/.aragorn-versions/example/version/SKILL.md"), "sha256:" + "d" * 64)
    prepared = SimpleNamespace(activation_id="e" * 32, system_prompt="inert",
        skill_path=profile.skill_path, _lease=SimpleNamespace(active=True), expires_at_monotonic_ns=120_000_000_000)
    config = SimpleNamespace(worker_uid=1101, worker_gid=1102, root_directory=Path("/var/lib/aragorn/pi-os"),
        runtime_directory=Path("/var/lib/aragorn/pi-runtime"), relay={"workerSocketPath": "/run/aragorn-relay/worker.sock"})
    unit, argv = confined._systemd_plan(config, prepared, profile)
    return confined.PiConfinedLaunchPlan(prepared, profile, 1101, 1102, unit, argv,
        Path("/var/lib/aragorn/pi-activations") / ("e" * 32 + ".json"), b'{"fixture":"start"}',
        120.0, "sha256:" + "f" * 64, "sha256:" + "a" * 64, confined._PlanLease())


def absent(unit):
    value = {key: "" for key in native._STATE}
    value.update(Id=unit, LoadState="not-found", ActiveState="inactive", SubState="dead", MainPID="0", ControlPID="0")
    return value


def running(the_plan):
    value = {key: "" for key in native._STATE}
    value.update(native._STATIC)
    value.update(Id=the_plan.unit_name, LoadState="loaded", ActiveState="active", SubState="running",
        MainPID="1234", ExecMainPID="1234", ExecMainStartTimestampMonotonic="100000000",
        ControlGroup=the_plan.profile.cgroup, InvocationID="1" * 32, User="1101", Group="1102",
        RootDirectory="/var/lib/aragorn/pi-os", WorkingDirectory=str(the_plan.profile.skill_path.parent),
        FragmentPath="/run/systemd/transient/" + the_plan.unit_name,
        InaccessiblePaths=next(argument.split("=", 2)[2] for argument in the_plan.systemd_run_argv
                               if argument.startswith("--property=InaccessiblePaths=")))
    return value


def compound(the_plan, name):
    values = {"BindPaths": ["a(ssbt)", "0"], "EnvironmentFiles": ["a(sb)", "0"],
        "RuntimeMaxUSec": ["t", "30000000"], "TimeoutStopUSec": ["t", "5000000"],
        "TemporaryFileSystem": ["a(ss)", "1", "/var/lib/aragorn/admitted", "ro"],
        "LoadCredential": ["a(ss)", "0"], "LoadCredentialEncrypted": ["a(ss)", "0"],
        "SetCredential": ["a(say)", "0"], "SetCredentialEncrypted": ["a(say)", "0"],
        **{key: ["a(sasbttttuii)", "0"] for key in ("ExecCondition", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost")}}
    if name == "BindReadOnlyPaths":
        bind_args = [arg.split("=", 2)[2] for arg in the_plan.systemd_run_argv if arg.startswith("--property=BindReadOnlyPaths=")]
        return ["a(ssbt)", str(len(bind_args)), *[item for pair in bind_args for item in (*pair.split(":"), "false", "16384")]]
    if name == "ExecStart":
        argv = the_plan.systemd_run_argv[the_plan.systemd_run_argv.index("--") + 1:]
        return ["a(sasbttttuii)", "1", argv[0], str(len(argv)), *argv, "false", "0", "0", "0", "0", "1234", "0", "0"]
    return values[name]


def metadata(*, inode=12, mode=stat.S_IFDIR | 0o755, uid=0, gid=0):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid,
        st_nlink=1, st_size=5, st_mtime_ns=6, st_ctime_ns=7)


class InertTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(native.time, "monotonic", return_value=100.0))
        self.stack.enter_context(mock.patch.object(native.time, "monotonic_ns", return_value=100_000_000_000))
        self.stack.enter_context(mock.patch.object(native.time, "sleep"))
        for owner, name in ((subprocess, "run"), (subprocess, "Popen"), (socket, "socket"),
                            (socket, "create_connection"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("native process/socket operation forbidden in focused tests")))
        for name in ("fork", "posix_spawn", "posix_spawnp", "pidfd_open"):
            self.stack.enter_context(mock.patch.object(os, name, create=True,
                side_effect=AssertionError("native process/PIDFD operation forbidden in focused tests")))
        for name in ("_read_virtual_file", "_process_start_time", "_process_cgroup", "_cgroup_processes",
                     "require_live_pidfd", "measure_runtime_process_profile", "open_peer_pidfd"):
            self.stack.enter_context(mock.patch.object(native.process, name,
                side_effect=AssertionError("live kernel observation forbidden in focused tests")))


class NativeOrchestrationTests(InertTests):
    def setUp(self):
        super().setUp()
        self.plan = dataclasses.replace(plan(), deadline=115.0)
        self.events = []

        @contextmanager
        def held(*args, **kwargs):
            self.events.append("lease_enter")
            yield self.plan
            self.events.append("lease_exit")

        self.prereq = self.stack.enter_context(mock.patch.object(native, "_prerequisites"))
        self.hold = self.stack.enter_context(mock.patch.object(native, "hold_confined_pi_launch_plan", side_effect=held))
        self.state = self.stack.enter_context(mock.patch.object(native, "_unit_state", side_effect=[
            absent(self.plan.unit_name), absent(self.plan.unit_name), running(self.plan)]))
        self.listener = mock.Mock()
        self.connection = mock.sentinel.post_exec_connection
        self.listener.accept.return_value = (self.connection, "")

        def prepare(owned):
            owned.listener = self.listener
            self.owned = owned

        self.prepare = self.stack.enter_context(mock.patch.object(native, "_prepare_resources", side_effect=prepare))
        self.command = self.stack.enter_context(mock.patch.object(native, "_command", return_value=(0, b"")))

        def capture(owned, deadline):
            owned.pid = 1234
            owned.pidfd = 73
            owned.invocation = "1" * 32
            owned.start_ticks = 5
            owned.immutable_digest = "sha256:" + "a" * 64

        self.capture = self.stack.enter_context(mock.patch.object(native, "_capture_unit", side_effect=capture))
        self.same = self.stack.enter_context(mock.patch.object(native, "_same_generation"))
        self.activation = self.stack.enter_context(mock.patch.object(native, "_capture_activation"))

        def exchange(value, connection, *, expected_pid, on_activation):
            self.assertEqual(expected_pid, 1234)
            self.assertIs(connection, self.connection)
            on_activation({"fixture": "authenticated activation"})
            return {"status": "PROVIDER_UNAVAILABLE"}

        self.exchange = self.stack.enter_context(mock.patch.object(native, "exchange_prepared_pi_bootstrap", side_effect=exchange))

        def cleanup(owned, original_deadline, budget):
            self.events.append("cleanup")
            self.assertNotIn("lease_exit", self.events)
            self.assertEqual(original_deadline, 120.0)
            return {"status": "VERIFIED_OWNED_CLEANUP", "budget": budget}

        self.cleanup = self.stack.enter_context(mock.patch.object(native, "_cleanup", side_effect=cleanup))
        self.close = self.stack.enter_context(mock.patch.object(native, "_close_handles"))

    def run_worker(self, **kwargs):
        return native.run_native_pi_worker(object(), {}, profile=self.plan.profile, grant={},
            protected_root=Path("/var/lib/aragorn/admitted"), runtime_conformance_digest="sha256:" + "a" * 64,
            deployment={}, revoked_context_ids=(), now_unix=1, config=mock.sentinel.config,
            **{"deadline": 120.0, **kwargs})

    def test_one_start_trusted_pid_exchange_and_cleanup_inside_admission(self):
        result = self.run_worker()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertEqual(self.events, ["lease_enter", "cleanup", "lease_exit"])
        self.command.assert_called_once_with(self.plan.systemd_run_argv, 115)
        self.capture.assert_called_once_with(self.owned, 115)
        self.activation.assert_called_once_with(self.owned, {"fixture": "authenticated activation"})
        self.cleanup.assert_called_once_with(self.owned, 120.0, 5.0)
        self.assertEqual(self.listener.settimeout.call_args.args, (15.0,))
        self.assertEqual(self.hold.call_args.kwargs["deadline"], 115.0)
        self.assertIn("NOT_EFFECT_RUN_OR_PHASE3", result["authority"])

    def test_nonpositive_oversize_and_nonfinite_deadlines_refuse_before_native_prereq(self):
        for deadline in (100, 131, True, float("nan"), float("inf")):
            with self.subTest(deadline=deadline), self.assertRaises(native.PiNativeSupervisorError):
                self.run_worker(deadline=deadline)
        self.prereq.assert_not_called()

    def test_cleanup_budget_is_explicit_and_cannot_exceed_five_seconds(self):
        for budget in (0, -1, 5.1, True, float("nan")):
            with self.subTest(budget=budget), self.assertRaises(native.PiNativeSupervisorError):
                self.run_worker(cleanup_timeout_seconds=budget)
        self.prereq.assert_not_called()

    def test_original_budget_must_have_room_for_reserved_cleanup(self):
        with self.assertRaisesRegex(native.PiNativeSupervisorError, "reserve"):
            self.run_worker(deadline=104.0)
        self.prereq.assert_not_called()

    def test_prerequisite_refusal_does_not_open_admission_or_resource(self):
        self.prereq.side_effect = native.PiNativeSupervisorError("no systemd")
        with self.assertRaisesRegex(native.PiNativeSupervisorError, "no systemd"):
            self.run_worker()
        self.hold.assert_not_called()
        self.prepare.assert_not_called()

    def test_preexisting_unit_does_not_start_or_claim_owned_absence(self):
        self.state.side_effect = [running(self.plan)]
        result = self.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.prepare.assert_not_called()
        self.command.assert_not_called()
        self.assertFalse(self.cleanup.call_args.args[0].unit_absence_observed)

    def test_unit_race_before_start_is_refused_without_stop(self):
        self.state.side_effect = [absent(self.plan.unit_name), running(self.plan)]
        result = self.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.command.assert_not_called()
        self.exchange.assert_not_called()

    def test_start_failure_is_attempted_once_and_never_bootstraps(self):
        self.command.return_value = (1, b"")
        result = self.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.command.assert_called_once()
        self.capture.assert_not_called()
        self.assertTrue(self.owned.start_attempted)
        self.assertFalse(self.owned.started)

    def test_start_timeout_retains_uncertain_state_for_cleanup_hold(self):
        self.command.side_effect = subprocess.TimeoutExpired("systemd-run", 3)
        self.cleanup.side_effect = None
        self.cleanup.return_value = {"status": "CLEANUP_HOLD", "reason": "uncertain start"}
        result = self.run_worker()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.command.assert_called_once()
        self.exchange.assert_not_called()

    def test_callback_failure_prevents_bootstrap_success(self):
        self.activation.side_effect = native.PiNativeSupervisorError("activation changed")
        result = self.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.assertIsNone(result["bootstrap"])
        self.assertIn("activation changed", result["failure"])

    def test_cleanup_hold_overrides_successful_bootstrap(self):
        self.cleanup.side_effect = None
        self.cleanup.return_value = {"status": "CLEANUP_HOLD", "reason": "unit replacement"}
        result = self.run_worker()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertIsNotNone(result["bootstrap"])
        self.close.assert_called_once()

    def test_handle_close_failure_cannot_report_clean_completion(self):
        self.close.side_effect = OSError("close failed")
        result = self.run_worker()
        self.assertEqual(result["status"], "CLEANUP_HOLD")


class NativeReadbackTests(InertTests):
    def setUp(self):
        super().setUp()
        self.plan = plan()

    def test_exact_compound_and_scalar_readback_is_digest_bound(self):
        with mock.patch.object(native, "_property", side_effect=lambda unit, name, deadline: compound(self.plan, name)):
            self.assertRegex(native._readback(self.plan, running(self.plan), 120), r"^sha256:[a-f0-9]{64}$")

    def test_every_changed_scalar_property_is_rejected(self):
        for name in native._STATIC:
            state = running(self.plan)
            state[name] = "unexpected"
            with self.subTest(name=name), self.assertRaisesRegex(native.PiNativeSupervisorError, "properties differ"):
                native._readback(self.plan, state, 120)

    def test_extra_credentials_exec_hooks_and_writable_mounts_refuse(self):
        for changed in ("LoadCredential", "LoadCredentialEncrypted", "SetCredential", "SetCredentialEncrypted",
                        "EnvironmentFiles", "ExecCondition", "ExecStartPre", "ExecStop", "BindPaths"):
            def response(unit, name, deadline):
                return ["not empty"] if name == changed else compound(self.plan, name)
            with self.subTest(changed=changed), mock.patch.object(native, "_property", side_effect=response):
                with self.assertRaisesRegex(native.PiNativeSupervisorError, "unexpected privileged"):
                    native._readback(self.plan, running(self.plan), 120)

    def test_mounts_and_compiled_entrypoint_cannot_be_substituted(self):
        for changed in ("BindReadOnlyPaths", "TemporaryFileSystem", "ExecStart", "RuntimeMaxUSec", "TimeoutStopUSec"):
            def response(unit, name, deadline):
                return ["substituted"] if name == changed else compound(self.plan, name)
            with self.subTest(changed=changed), mock.patch.object(native, "_property", side_effect=response):
                with self.assertRaises(native.PiNativeSupervisorError):
                    native._readback(self.plan, running(self.plan), 120)

    def test_missing_duplicate_and_nonascii_state_refuse(self):
        good = "".join(f"{key}={value}\n" for key, value in running(self.plan).items()).encode()
        for raw in (good + b"Id=duplicate\n", b"Id=only\n", b"\xff"):
            with self.subTest(raw=raw[:20]), mock.patch.object(native, "_command", return_value=(0, raw)):
                with self.assertRaises(native.PiNativeSupervisorError):
                    native._unit_state(self.plan.unit_name, 120)

    def test_explicit_not_found_readback_is_required_for_absence(self):
        document = absent(self.plan.unit_name)
        raw = "".join(f"{key}={value}\n" for key, value in document.items()).encode()
        with mock.patch.object(native, "_command", return_value=(4, raw)) as command:
            self.assertTrue(native._absent(native._unit_state(self.plan.unit_name, 120)))
            self.assertEqual(command.call_args.args[0][0], "/usr/bin/systemctl")
        with mock.patch.object(native, "_command", return_value=(4, b"Unit not found")):
            with self.assertRaises(native.PiNativeSupervisorError):
                native._unit_state(self.plan.unit_name, 120)

    def test_compound_selector_never_accepts_arbitrary_unit_or_property(self):
        with mock.patch.object(native, "_command") as command:
            for unit, name in (("other.service", "ExecStart"), (self.plan.unit_name, "Arbitrary")):
                with self.subTest(unit=unit, name=name), self.assertRaises(native.PiNativeSupervisorError):
                    native._property(unit, name, 120)
            command.assert_not_called()

    def test_command_has_fixed_environment_bounded_timeout_no_shell(self):
        returned = SimpleNamespace(returncode=0, stdout=b"owned", stderr=b"")
        with mock.patch.object(native.subprocess, "run", return_value=returned) as execute:
            self.assertEqual(native._command(("/usr/bin/systemctl", "show"), 120), (0, b"owned"))
            options = execute.call_args.kwargs
            self.assertEqual(options["env"], native._ENV)
            self.assertEqual(options["timeout"], 3.0)
            self.assertTrue(options["close_fds"])
            self.assertNotIn("shell", options)

    def test_unapproved_command_and_oversize_output_refuse(self):
        with self.assertRaises(native.PiNativeSupervisorError):
            native._command(("/bin/sh", "-c", "anything"), 120)
        with mock.patch.object(native.subprocess, "run", return_value=SimpleNamespace(returncode=0,
                stdout=b"x" * (65536 + 1), stderr=b"")):
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "output exceeds"):
                native._command(("/usr/bin/systemctl", "show"), 120)

    def test_pidfd_open_must_match_actual_kernel_descriptor_pid(self):
        with mock.patch.object(native.os, "pidfd_open", return_value=73, create=True), \
             mock.patch.object(native.process, "_read_virtual_file", return_value=b"Pid:\t999\n"), \
             mock.patch.object(native.os, "close") as close:
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "MainPID"):
                native._pidfd(1234)
            close.assert_called_once_with(73)

    def test_pidfd_exit_requires_readability_not_just_error(self):
        for events, expected in (([], False), ([(73, select.POLLIN)], True)):
            poller = mock.Mock()
            poller.poll.return_value = events
            with mock.patch.object(native.select, "poll", return_value=poller):
                self.assertEqual(native._exited(73), expected)
        for events in ([(73, select.POLLNVAL)], [(73, select.POLLERR)], [(74, select.POLLIN)]):
            poller = mock.Mock()
            poller.poll.return_value = events
            with mock.patch.object(native.select, "poll", return_value=poller), self.assertRaises(native.PiNativeSupervisorError):
                native._exited(73)

    def test_wrong_host_or_nonroot_refuses_before_kernel_or_commands(self):
        for uid, system, machine in ((1000, "Linux", "aarch64"), (0, "Darwin", "arm64"), (0, "Linux", "x86_64")):
            with self.subTest(uid=uid, system=system, machine=machine), \
                 mock.patch.object(native.os, "geteuid", return_value=uid), \
                 mock.patch.object(native.platform, "system", return_value=system), \
                 mock.patch.object(native.platform, "machine", return_value=machine), \
                 mock.patch.object(native, "_command") as command:
                with self.assertRaisesRegex(native.PiNativeSupervisorError, "Linux arm64"):
                    native._prerequisites(120)
                command.assert_not_called()

    def test_manager_version_not_client_version_controls_logging_support(self):
        with mock.patch.object(native, "_command", return_value=(0, b's "257.1 (257.1-1)"\n')) as command:
            self.assertEqual(native._manager_version(115), 257)
            argv = command.call_args.args[0]
            self.assertEqual(argv[-2:], ("org.freedesktop.systemd1.Manager", "Version"))
            self.assertNotIn("--version", argv)

    def test_old_missing_or_malformed_manager_version_cannot_fallback(self):
        for code, raw in ((0, b's "256.9"'), (0, b's "unknown"'), (0, b'u 257'),
                          (1, b''), (0, b's "257" extra'), (0, b's "257\xff"')):
            with self.subTest(code=code, raw=raw), mock.patch.object(native, "_command", return_value=(code, raw)):
                with self.assertRaises(native.PiNativeSupervisorError):
                    native._manager_version(115)

    def test_protected_client_also_requires_property_support(self):
        with mock.patch.object(native, "_command", return_value=(0, b"systemd 257 (257.1)\n+PAM +AUDIT\n")) as command:
            self.assertEqual(native._client_version(115), 257)
            command.assert_called_once_with(("/usr/bin/systemd-run", "--version"), 115)
        for raw in (b"systemd 256\n", b"not systemd\n", b"", b"systemd 257\xff"):
            with self.subTest(raw=raw), mock.patch.object(native, "_command", return_value=(0, raw)):
                with self.assertRaises(native.PiNativeSupervisorError):
                    native._client_version(115)

    def test_changed_unit_identity_rejects_before_stop_readback(self):
        owned = native._Owned(self.plan, pid=1234, pidfd=73, invocation="1" * 32,
            unit_started_at="100000000", immutable_digest="sha256:" + "a" * 64)
        for key, value in (("InvocationID", "2" * 32), ("MainPID", "5678"), ("ExecMainPID", "5678"),
                           ("ExecMainStartTimestampMonotonic", "101"), ("ControlGroup", "/other")):
            state = {**running(self.plan), key: value}
            with self.subTest(key=key), mock.patch.object(native, "_readback") as readback:
                with self.assertRaisesRegex(native.PiNativeSupervisorError, "generation changed"):
                    native._same_generation(owned, state, 120, live=True)
                readback.assert_not_called()

    def test_same_unit_name_does_not_hide_reused_kernel_pid(self):
        owned = native._Owned(self.plan, pid=1234, pidfd=73, invocation="1" * 32, start_ticks=5,
            unit_started_at="100000000", immutable_digest="sha256:" + "a" * 64)
        with mock.patch.object(native, "_readback", return_value=owned.immutable_digest), \
             mock.patch.object(native, "_cgroup_owned"), \
             mock.patch.object(native, "_exited", return_value=False), \
             mock.patch.object(native.process, "_process_start_time", return_value=99):
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "kernel child identity"):
                native._same_generation(owned, running(self.plan), 120, live=True)


class NativeCleanupTests(InertTests):
    def setUp(self):
        super().setUp()
        self.plan = plan()
        self.owned = native._Owned(self.plan, start_attempted=True, started=True, pid=1234, pidfd=73,
            invocation="1" * 32, start_ticks=5, unit_started_at="100000000", immutable_digest="sha256:" + "a" * 64,
            unit_absence_observed=True, cgroup_fd=74, cgroup_parent_fd=75)
        self.resources = self.stack.enter_context(mock.patch.object(native, "_resource_ownership"))
        self.state = self.stack.enter_context(mock.patch.object(native, "_unit_state", side_effect=[
            running(self.plan), absent(self.plan.unit_name)]))
        self.same = self.stack.enter_context(mock.patch.object(native, "_same_generation"))
        self.exited = self.stack.enter_context(mock.patch.object(native, "_exited", side_effect=[False, True]))
        self.command = self.stack.enter_context(mock.patch.object(native, "_command", return_value=(0, b"")))
        self.unlink = self.stack.enter_context(mock.patch.object(native.os, "unlink"))
        self.rmdir = self.stack.enter_context(mock.patch.object(native.os, "rmdir"))
        self.fsync = self.stack.enter_context(mock.patch.object(native.os, "fsync"))
        self.missing = self.stack.enter_context(mock.patch.object(native, "_missing", return_value=True))
        self.cgroup = self.stack.enter_context(mock.patch.object(native, "_cgroup_empty", return_value=True))

    def cleanup(self):
        return native._cleanup(self.owned, 105, 5)

    def test_owned_stop_once_and_actual_exit_plus_absence_required(self):
        result = self.cleanup()
        self.assertEqual(result["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertTrue(result["unit_absent"] and result["process_exit_observed"])
        self.assertTrue(result["cgroup_empty_or_absent"])
        self.command.assert_called_once_with(("/usr/bin/systemctl", "stop", "--no-block", self.plan.unit_name), 105)
        self.same.assert_called_once_with(self.owned, running(self.plan), 105, live=True)

    def test_replacement_generation_cannot_be_stopped_or_deleted(self):
        self.same.side_effect = native.PiNativeSupervisorError("generation changed")
        result = self.cleanup()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.command.assert_not_called()
        self.unlink.assert_not_called()
        self.rmdir.assert_not_called()

    def test_changed_or_partial_activation_preserves_every_resource(self):
        self.resources.side_effect = native.PiNativeSupervisorError("partial activation")
        result = self.cleanup()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.command.assert_not_called()
        self.unlink.assert_not_called()

    def test_uncertain_start_never_stops_by_name_alone(self):
        self.owned.started = False
        result = self.cleanup()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.command.assert_not_called()
        self.state.assert_not_called()

    def test_missing_pidfd_or_immutable_readback_holds(self):
        for field, value in (("pidfd", -1), ("immutable_digest", ""), ("invocation", "")):
            old = getattr(self.owned, field)
            setattr(self.owned, field, value)
            with self.subTest(field=field):
                self.assertEqual(self.cleanup()["status"], "CLEANUP_HOLD")
            setattr(self.owned, field, old)
        self.command.assert_not_called()

    def test_already_absent_unit_and_observed_exit_need_no_stop(self):
        self.state.side_effect = [absent(self.plan.unit_name), absent(self.plan.unit_name)]
        self.exited.side_effect = [True]
        self.assertEqual(self.cleanup()["status"], "VERIFIED_OWNED_CLEANUP")
        self.command.assert_not_called()

    def test_absent_unit_without_process_exit_does_not_qualify_cleanup(self):
        self.state.side_effect = [absent(self.plan.unit_name), absent(self.plan.unit_name)]
        self.exited.side_effect = [False]
        with mock.patch.object(native, "_remaining", side_effect=native.PiNativeSupervisorError("cleanup deadline")):
            result = self.cleanup()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertFalse(result["process_exit_observed"])
        self.unlink.assert_not_called()

    def test_stop_failure_is_not_retried(self):
        self.command.return_value = (1, b"")
        self.assertEqual(self.cleanup()["status"], "CLEANUP_HOLD")
        self.command.assert_called_once()
        self.unlink.assert_not_called()

    def test_replacement_during_stop_preserves_activation_and_socket(self):
        replacement = running(self.plan)
        replacement["InvocationID"] = "2" * 32
        self.state.side_effect = [running(self.plan), replacement]
        result = self.cleanup()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.unlink.assert_not_called()

    def test_activation_and_socket_withdraw_only_after_observed_exit(self):
        self.owned.activation_fd = 31
        self.owned.activation_raw = b"owned activation"
        self.owned.directory_fd = 32
        self.owned.socket_identity = (1, 2)
        self.owned.listener = mock.Mock()
        result = self.cleanup()
        self.assertTrue(result["activation_withdrawn"] and result["socket_removed"])
        self.assertEqual(self.unlink.call_args_list,
            [mock.call(self.plan.activation_path.name, dir_fd=31), mock.call("bootstrap.sock", dir_fd=32)])
        self.rmdir.assert_not_called()  # a preexisting bootstrap directory is retained

    def test_ownership_recheck_failure_after_stop_retains_files(self):
        self.resources.side_effect = [None, native.PiNativeSupervisorError("socket replaced")]
        result = self.cleanup()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertTrue(result["process_exit_observed"])
        self.unlink.assert_not_called()

    def test_exhausted_original_deadline_prevents_every_cleanup_mutation(self):
        result = native._cleanup(self.owned, 100, 5)
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.resources.assert_not_called()
        self.command.assert_not_called()
        self.unlink.assert_not_called()

    def test_original_deadline_can_only_shorten_cleanup_cap(self):
        native._cleanup(self.owned, 102, 5)
        self.command.assert_called_once_with(("/usr/bin/systemctl", "stop", "--no-block", self.plan.unit_name), 102)

    def test_retained_cgroup_processes_prevent_authority_withdrawal(self):
        self.cgroup.side_effect = native.PiNativeSupervisorError("cgroup retains processes")
        self.owned.activation_raw = b"retained"
        self.owned.activation_fd = 31
        result = self.cleanup()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertFalse(result["cgroup_empty_or_absent"])
        self.unlink.assert_not_called()


class NativeProtectedResourceTests(InertTests):
    def setUp(self):
        super().setUp()
        self.plan = plan()

    def test_existing_activation_refuses_before_socket_or_directory_creation(self):
        owned = native._Owned(self.plan)
        with mock.patch.object(native.lineage, "_open_protected_root", return_value=31), \
             mock.patch.object(native.os, "fstat", return_value=metadata()), \
             mock.patch.object(native, "_missing", return_value=False), \
             mock.patch.object(native.os, "mkdir") as mkdir:
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "activation already"):
                native._prepare_resources(owned)
            mkdir.assert_not_called()

    def test_preexisting_nonempty_bootstrap_namespace_is_not_repaired(self):
        owned = native._Owned(self.plan)
        with mock.patch.object(native.lineage, "_open_protected_root", side_effect=[31, 32]), \
             mock.patch.object(native.lineage, "_open_directory_at", return_value=33), \
             mock.patch.object(native.os, "fstat", return_value=metadata()), \
             mock.patch.object(native, "_missing", return_value=True), \
             mock.patch.object(native.os, "mkdir", side_effect=FileExistsError), \
             mock.patch.object(native.os, "listdir", return_value=["existing.sock"]), \
             mock.patch.object(native.os, "chmod") as chmod:
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "existing resources"):
                native._prepare_resources(owned)
            chmod.assert_not_called()
            self.assertFalse(owned.directory_created)

    def test_socket_is_exclusive_descriptor_relative_and_exact_mode(self):
        owned = native._Owned(self.plan)
        listener = mock.Mock()
        initial = metadata(inode=90, mode=stat.S_IFSOCK | 0o755)
        final = metadata(inode=90, mode=stat.S_IFSOCK | 0o660, gid=1102)
        with mock.patch.object(native.socket, "SOCK_CLOEXEC", 0x80000, create=True), \
             mock.patch.object(native.lineage, "_open_protected_root", side_effect=[31, 32]), \
             mock.patch.object(native.lineage, "_open_directory_at", return_value=33), \
             mock.patch.object(native.os, "fstat", return_value=metadata()), \
             mock.patch.object(native, "_missing", return_value=True), \
             mock.patch.object(native.os, "mkdir", side_effect=FileExistsError), \
             mock.patch.object(native.os, "listdir", return_value=[]), \
             mock.patch.object(native.socket, "socket", return_value=listener), \
             mock.patch.object(native.os, "stat", side_effect=[initial, final]), \
             mock.patch.object(native.os, "chown") as chown, \
             mock.patch.object(native.os, "chmod") as chmod:
            native._prepare_resources(owned)
        listener.bind.assert_called_once_with("/proc/self/fd/33/bootstrap.sock")
        listener.listen.assert_called_once_with(1)
        chown.assert_called_once_with("bootstrap.sock", 0, 1102, dir_fd=33, follow_symlinks=False)
        chmod.assert_called_once_with("bootstrap.sock", 0o660, dir_fd=33, follow_symlinks=False)
        self.assertEqual(owned.socket_identity, native._file_identity(final))

    def test_partial_unrecorded_activation_forces_cleanup_hold(self):
        directory = metadata()
        owned = native._Owned(self.plan, activation_fd=31,
            activation_directory_identity=native._directory_identity(directory))
        with mock.patch.object(native.os, "fstat", return_value=directory), \
             mock.patch.object(Path, "lstat", return_value=directory), \
             mock.patch.object(native, "_missing", return_value=False):
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "partial activation"):
                native._resource_ownership(owned)

    def test_activation_capture_retains_exact_canonical_bytes_and_inode(self):
        document = {"fixture": "authenticated"}
        raw = canonical_json(document)
        value = metadata(mode=stat.S_IFREG | 0o444)
        owned = native._Owned(self.plan, activation_fd=31)
        with mock.patch.object(native, "read_activation", return_value=document), \
             mock.patch.object(native, "_read_owned_bytes_at", return_value=raw), \
             mock.patch.object(native.os, "stat", return_value=value):
            native._capture_activation(owned, document)
        self.assertEqual(owned.activation_raw, raw)
        self.assertEqual(owned.activation_identity, native._file_identity(value))

    def test_activation_capture_rejects_mismatched_protected_bytes(self):
        owned = native._Owned(self.plan, activation_fd=31)
        with mock.patch.object(native, "read_activation", return_value={"a": 1}), \
             mock.patch.object(native, "_read_owned_bytes_at", return_value=b'{"a":2}'):
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "bytes differ"):
                native._capture_activation(owned, {"a": 1})
        self.assertIsNone(owned.activation_raw)

    def test_owned_socket_inode_replacement_is_not_deleted(self):
        directory = metadata()
        original = metadata(inode=90, mode=stat.S_IFSOCK | 0o660, gid=1102)
        replacement = metadata(inode=91, mode=stat.S_IFSOCK | 0o660, gid=1102)
        owned = native._Owned(self.plan, run_fd=32, directory_fd=33,
            directory_identity=native._directory_identity(directory), socket_identity=native._file_identity(original))
        with mock.patch.object(native.os, "fstat", return_value=directory), \
             mock.patch.object(native.os, "stat", side_effect=[directory, replacement]), \
             mock.patch.object(native.os, "listdir", return_value=["bootstrap.sock"]):
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "socket replaced"):
                native._resource_ownership(owned)

    def test_cgroup_replacement_cannot_count_as_owned_cleanup(self):
        parent = metadata(inode=80)
        child = metadata(inode=81)
        replacement = metadata(inode=82)
        owned = native._Owned(self.plan, cgroup_parent_fd=75, cgroup_fd=74,
            cgroup_parent_identity=native._directory_identity(parent), cgroup_identity=native._directory_identity(child))
        with mock.patch.object(native.os, "fstat", side_effect=[parent, child]), \
             mock.patch.object(Path, "lstat", return_value=parent), \
             mock.patch.object(native.os, "stat", return_value=replacement):
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "cgroup name replaced"):
                native._cgroup_owned(owned, allow_absent=True)

    def test_cgroup_name_absence_requires_old_descriptor_removed_link(self):
        parent = metadata(inode=80)
        child = metadata(inode=81)
        owned = native._Owned(self.plan, cgroup_parent_fd=75, cgroup_fd=74,
            cgroup_parent_identity=native._directory_identity(parent), cgroup_identity=native._directory_identity(child))
        with mock.patch.object(native.os, "fstat", side_effect=[parent, child]), \
             mock.patch.object(Path, "lstat", return_value=parent), \
             mock.patch.object(native.os, "stat", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "removal proof"):
                native._cgroup_owned(owned, allow_absent=True)
        child.st_nlink = 0
        with mock.patch.object(native.os, "fstat", side_effect=[parent, child]), \
             mock.patch.object(Path, "lstat", return_value=parent), \
             mock.patch.object(native.os, "stat", side_effect=FileNotFoundError):
            self.assertTrue(native._cgroup_owned(owned, allow_absent=True))

    def test_cgroup_empty_check_refuses_processes_and_delegated_descendants(self):
        owned = native._Owned(self.plan)
        with mock.patch.object(native, "_cgroup_owned", return_value=False), \
             mock.patch.object(native.process, "_cgroup_processes", return_value=(5678,)):
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "retains processes"):
                native._cgroup_empty(owned)
        with mock.patch.object(native, "_cgroup_owned", return_value=False), \
             mock.patch.object(native.process, "_cgroup_processes", side_effect=RuntimeError("delegated descendants")):
            with self.assertRaisesRegex(RuntimeError, "descendants"):
                native._cgroup_empty(owned)

    def test_handle_failure_does_not_skip_other_owned_handle_closes(self):
        connection = mock.Mock()
        connection.close.side_effect = OSError("close failure")
        listener = mock.Mock()
        owned = native._Owned(self.plan, connection=connection, listener=listener,
            pidfd=70, cgroup_fd=71, cgroup_parent_fd=72, activation_fd=73, directory_fd=74, run_fd=75)
        with mock.patch.object(native.os, "close", side_effect=[OSError("fd failure"), None, None, None, None, None]) as close:
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "2 owned handles"):
                native._close_handles(owned)
        listener.close.assert_called_once()
        self.assertEqual(close.call_args_list, [mock.call(fd) for fd in range(70, 76)])


class BootstrapActivationCallbackTests(InertTests):
    def test_protected_callback_precedes_start_and_failure_stops_exchange(self):
        value = plan()
        hello = {"schema": "aragorn/pi-core-bootstrap-hello/v1", "worker_nonce": "a" * 32}
        calls = []
        with mock.patch.object(confined.os, "geteuid", return_value=0), \
             mock.patch.object(confined, "_read_bootstrap", return_value=hello), \
             mock.patch.object(confined, "bind_pi_worker_activation", return_value={"fixture": "activation"}), \
             mock.patch.object(confined, "_send_frame") as send:
            def callback(document):
                calls.append(document)
                raise native.PiNativeSupervisorError("protected record capture failed")
            with self.assertRaisesRegex(native.PiNativeSupervisorError, "capture failed"):
                confined.exchange_prepared_pi_bootstrap(value, mock.sentinel.connection, expected_pid=1234,
                                                        on_activation=callback)
            send.assert_not_called()
            self.assertEqual(calls, [{"fixture": "activation"}])

    def test_callback_receives_detached_document_before_start(self):
        value = plan()
        activation = {"nested": {"value": "original"}}
        reads = [{"schema": "aragorn/pi-core-bootstrap-hello/v1", "worker_nonce": "a" * 32},
                 {"schema": "aragorn/pi-core-bootstrap-result/v1", "activation_id": value.prepared.activation_id,
                  "status": "PROVIDER_UNAVAILABLE", "authority": confined._RESULT_AUTHORITY}]
        with mock.patch.object(confined.os, "geteuid", return_value=0), \
             mock.patch.object(confined, "_read_bootstrap", side_effect=reads), \
             mock.patch.object(confined, "bind_pi_worker_activation", return_value=activation), \
             mock.patch.object(confined, "_send_frame") as send:
            def callback(document):
                send.assert_not_called()
                document["nested"]["value"] = "changed callback copy"
            confined.exchange_prepared_pi_bootstrap(value, mock.sentinel.connection, expected_pid=1234,
                                                    on_activation=callback)
            self.assertEqual(activation["nested"]["value"], "original")
            self.assertEqual(send.call_count, 2)


if __name__ == "__main__":
    unittest.main()
