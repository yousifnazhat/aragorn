"""Mocked finite leaf only: no subprocess, procfs, PIDFD, signal or provider effects."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import runtime_native_admission_restart as leaf
from test_native_phase3_admission_restart import fixture, clock, SECOND, verify, denial_bytes

TOKEN = "b" * 64


@contextmanager
def leaf_environment(value):
    rows = deepcopy(value["commands_before"] + [value["restart"]] + value["commands_after"])
    snapshots = [leaf.contract.decode(row["raw_base64"], leaf.contract.MAX_ENVELOPE) for row in value["lifecycle"]]
    times = [row[key] for row in value["lifecycle"] for key in ("call_started_ns", "call_completed_ns")]
    with ExitStack() as stack:
        stack.enter_context(patch.object(leaf, "_guard", return_value=TOKEN))
        gateway = stack.enter_context(patch.object(leaf, "_gateway", return_value=value["bindings"]["gateway"]))
        boundary = stack.enter_context(patch.object(leaf, "_boundary", side_effect=lambda _: deepcopy(value["before"])))
        stack.enter_context(patch.object(leaf, "_sources", return_value=value["before"]["sources"]))
        pidfd = stack.enter_context(patch.object(leaf.os, "pidfd_open", return_value=123, create=True))
        close = stack.enter_context(patch.object(leaf.os, "close"))
        poller = Mock()
        poller.poll.return_value = []
        stack.enter_context(patch.object(leaf.select, "poll", return_value=poller, create=True))
        signals = stack.enter_context(patch.object(leaf.signal, "signal", return_value=leaf.signal.SIG_DFL))
        stack.enter_context(patch.object(leaf.time, "monotonic_ns", side_effect=times))
        command = stack.enter_context(patch.object(leaf, "_command", side_effect=rows))
        provider = Mock(side_effect=snapshots)
        yield SimpleNamespace(command=command, provider=provider, close=close, boundary=boundary,
                              rows=rows, snapshots=snapshots, gateway=gateway, poller=poller,
                              signals=signals, pidfd=pidfd)


@contextmanager
def command_environment(stdout=b"", stderr=b"", code=0):
    events, registered = [], {}
    process = Mock(pid=4321)
    process.stdout.fileno.return_value = 11
    process.stderr.fileno.return_value = 12
    process.wait.side_effect = lambda **kw: events.append("reap") or code
    process.stdout.close.side_effect = lambda: events.append("close-stdout")
    process.stderr.close.side_effect = lambda: events.append("close-stderr")
    selector = Mock()
    selector.__enter__ = Mock(return_value=selector)
    selector.__exit__ = Mock(return_value=False)
    selector.register.side_effect = lambda stream, mask, name: registered.update({
        stream.fileno(): SimpleNamespace(fileobj=stream, data=name)})
    selector.unregister.side_effect = lambda stream: registered.pop(stream.fileno())
    selector.get_map.side_effect = lambda: registered
    selector.select.side_effect = lambda timeout: [(key, 1) for key in list(registered.values())]
    remaining = {11: stdout, 12: stderr}

    def read(fd, limit):
        result, remaining[fd] = remaining[fd][:limit], remaining[fd][limit:]
        return result

    with ExitStack() as stack:
        popen = stack.enter_context(patch.object(leaf.subprocess, "Popen", return_value=process))
        stack.enter_context(patch.object(leaf.selectors, "DefaultSelector", return_value=selector))
        stack.enter_context(patch.object(leaf.os, "read", side_effect=read))
        blocking = stack.enter_context(patch.object(leaf.os, "set_blocking"))
        stack.enter_context(patch.object(leaf, "_child_start", return_value=1234))
        waitid = stack.enter_context(patch.object(leaf.os, "waitid", create=True,
            side_effect=lambda *a: events.append("observe-unreaped") or SimpleNamespace(si_pid=4321)))
        for name, number in (("P_PID", 1), ("WEXITED", 4), ("WNOHANG", 1), ("WNOWAIT", 8)):
            stack.enter_context(patch.object(leaf.os, name, number, create=True))
        kill = stack.enter_context(patch.object(leaf.os, "killpg", side_effect=lambda *a: events.append("kill-group")))
        monotonic = stack.enter_context(patch.object(leaf.time, "monotonic_ns", return_value=11 * SECOND))
        stack.enter_context(patch.object(leaf, "_clock", side_effect=[clock(10), clock(12.5)]))
        stack.enter_context(patch.object(leaf.time, "sleep"))
        stack.enter_context(patch.object(leaf.signal, "getsignal", return_value=leaf.signal.SIG_DFL))
        yield SimpleNamespace(process=process, popen=popen, kill=kill, waitid=waitid, monotonic=monotonic,
                              events=events, selector=selector, blocking=blocking)


class RestartLeafTests(unittest.TestCase):
    def test_finite_sequence_final_cursor_exact_chains_and_independent_replay(self):
        value, bindings = fixture()
        with leaf_environment(value) as env:
            result = leaf.run_restart_probe(expected_bindings=bindings, read_native_restart_lifecycle=env.provider)
        self.assertEqual(result["status"], "OBSERVED", result["refusal"])
        self.assertEqual(verify(result, bindings)["status"], "BOUNDED_RESTART_JOINS_VERIFIED")
        self.assertEqual(env.command.call_count, 11)
        self.assertEqual([call.args[0] for call in env.command.call_args_list].count(leaf.contract.ARGV), 1)
        self.assertEqual([call.kwargs["phase"] for call in env.provider.call_args_list], ["INITIAL", "BOUNDARY", "AFTER"])
        first, boundary, after = [call.kwargs for call in env.provider.call_args_list]
        self.assertIsNone(first["previous_snapshot_digest"])
        self.assertIsNone(first["after_cursor"])
        self.assertEqual(boundary["previous_snapshot_digest"], leaf.contract.digest(env.snapshots[0]))
        self.assertEqual(after["after_cursor"], "2" * 64)
        self.assertEqual(after["deadline_monotonic_ns"], 30 * SECOND)
        env.close.assert_called_once_with(123)
        self.assertEqual(env.signals.call_count, 2)

    def test_native_guard_refuses_before_provider_or_command(self):
        _, bindings = fixture()
        with patch.object(leaf.sys, "platform", "darwin"), patch.object(leaf, "_command") as command:
            provider = Mock()
            result = leaf.run_restart_probe(expected_bindings=bindings, read_native_restart_lifecycle=provider)
        self.assertEqual(result["status"], "REFUSED")
        command.assert_not_called()
        provider.assert_not_called()

    def test_gateway_namespace_and_daemon_environment_readbacks(self):
        _, bindings = fixture()
        for wrong_namespace, environment in ((False, b"TZ=UTC\0OPENCLAW_NO_RESPAWN=1\0"),
                (True, b"TZ=UTC\0OPENCLAW_NO_RESPAWN=1\0"), (False, b"TZ=UTC\0"),
                (False, b"TZ=UTC\0OPENCLAW_NO_RESPAWN=1\0OPENCLAW_NO_RESPAWN=0\0")):
            def metadata(path):
                name = path.rsplit("/", 1)[-1]
                value = bindings["namespaces"][name]
                if wrong_namespace and "/self/" in path:
                    value += 1
                return SimpleNamespace(st_ino=value)
            with patch.object(leaf.readers, "_gateway", return_value=bindings["gateway"]), \
                 patch.object(leaf.os, "stat", side_effect=metadata), \
                 patch.object(leaf.readers, "_read_proc", return_value=environment):
                if not wrong_namespace and environment == b"TZ=UTC\0OPENCLAW_NO_RESPAWN=1\0":
                    self.assertEqual(leaf._gateway(bindings), bindings["gateway"])
                else:
                    with self.assertRaises(ValueError):
                        leaf._gateway(bindings)

    def test_scheduling_failure_retains_actual_bytes_and_never_retries(self):
        value, bindings = fixture()
        value["restart"]["exit_code"] = 1
        with leaf_environment(value) as env:
            result = leaf.run_restart_probe(expected_bindings=bindings, read_native_restart_lifecycle=env.provider)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["restart"], value["restart"])
        self.assertEqual(env.command.call_count, 6)
        self.assertEqual(env.provider.call_count, 2)
        self.assertIsNotNone(result["after"])

    def test_provider_partial_and_interrupt_preserve_scheduled_effect(self):
        for error in (RuntimeError("private provider diagnostic"),
                      leaf.contract.NativeRestartError("private provider diagnostic"), KeyboardInterrupt()):
            value, bindings = fixture()
            error.partial_bytes = b'{"unfinished":'
            with leaf_environment(value) as env:
                env.provider.side_effect = env.snapshots[:2] + [error]
                if isinstance(error, Exception):
                    result = leaf.run_restart_probe(expected_bindings=bindings, read_native_restart_lifecycle=env.provider)
                else:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        leaf.run_restart_probe(expected_bindings=bindings, read_native_restart_lifecycle=env.provider)
                    result = caught.exception._native_restart_leaf
            self.assertEqual(result["status"], "REFUSED")
            self.assertIsNotNone(result["restart"])
            self.assertEqual(result["partial"][0]["raw_base64"], leaf.contract.encode(error.partial_bytes))
            self.assertEqual(env.command.call_count, 6)
            self.assertNotIn("private provider diagnostic", repr(result))
            if isinstance(error, Exception):
                self.assertEqual(result["refusal"]["reason"], "LIFECYCLE_PROVIDER_FAILED")
            env.close.assert_called_once_with(123)

    def test_sigterm_is_retained_and_handler_restored(self):
        value, bindings = fixture()
        with leaf_environment(value) as env:
            def provider(**kwargs):
                env.signals.call_args_list[0].args[1](leaf.signal.SIGTERM, None)
            env.provider.side_effect = provider
            with self.assertRaises(KeyboardInterrupt) as caught:
                leaf.run_restart_probe(expected_bindings=bindings, read_native_restart_lifecycle=env.provider)
        self.assertEqual(caught.exception._native_restart_leaf["status"], "REFUSED")
        self.assertEqual(env.command.call_count, 0)
        self.assertEqual(env.signals.call_count, 2)

    def test_initial_readiness_absence_refuses_before_any_command(self):
        value, bindings = fixture()
        with leaf_environment(value) as env:
            raw = leaf.contract.parse(env.snapshots[0])
            prefix = b'{"message":"not ready"}\n'
            raw.update(raw_base64=leaf.contract.encode(prefix), prefix_bytes=len(prefix), prefix_digest=leaf.contract.digest(prefix))
            env.provider.side_effect = [leaf.canonical_json(raw)]
            result = leaf.run_restart_probe(expected_bindings=bindings, read_native_restart_lifecycle=env.provider)
        self.assertEqual(result["status"], "REFUSED")
        env.command.assert_not_called()

    def test_source_drift_or_gateway_exit_stops_dispatch_without_pid_reopen(self):
        for drift in (False, True):
            value, bindings = fixture()
            with leaf_environment(value) as env:
                if drift:
                    env.boundary.side_effect = [deepcopy(value["before"]),
                        deepcopy(value["before"]) | {"config": {}}, deepcopy(value["before"])]
                else:
                    env.poller.poll.return_value = [(123, 1)]
                result = leaf.run_restart_probe(expected_bindings=bindings, read_native_restart_lifecycle=env.provider)
            self.assertEqual(result["status"], "REFUSED")
            self.assertNotIn(leaf.contract.ARGV, [c.args[0] for c in env.command.call_args_list])
            env.pidfd.assert_called_once()

    def test_pidfd_close_failure_cannot_leave_observed_status(self):
        value, bindings = fixture()
        with leaf_environment(value) as env:
            env.close.side_effect = OSError("close")
            result = leaf.run_restart_probe(expected_bindings=bindings, read_native_restart_lifecycle=env.provider)
        self.assertEqual(result["status"], "REFUSED")
        self.assertIn("GATEWAY_PIDFD_CLOSE_REFUSED", result["cleanup_failures"])


class RestartCommandTests(unittest.TestCase):
    def test_nonblocking_streams_fixed_environment_and_cleanup_before_reap(self):
        raw = leaf.canonical_json(leaf.contract.restart_response(42))
        with command_environment(stderr=raw) as env:
            row = leaf._command(leaf.contract.ARGV, TOKEN)
        self.assertEqual(leaf.contract.decode(row["stderr_base64"], 131072), raw)
        self.assertLess(env.events.index("observe-unreaped"), env.events.index("kill-group"))
        self.assertLess(env.events.index("kill-group"), env.events.index("reap"))
        self.assertEqual(env.events[-2:], ["close-stdout", "close-stderr"])
        self.assertEqual(env.blocking.call_count, 2)
        self.assertTrue(env.popen.call_args.kwargs["start_new_session"])
        self.assertNotIn(TOKEN, repr(env.popen.call_args.args))
        leaf.contract.command(row, leaf.contract.ARGV, 42)

    def test_denial_has_no_real_token_environment_or_catalog_exit_contract(self):
        stdout, stderr = denial_bytes()
        with command_environment(stdout=stdout, stderr=stderr, code=1) as env:
            row = leaf._command(leaf.contract.DENIAL_ARGV, TOKEN)
        self.assertNotIn("OPENCLAW_GATEWAY_TOKEN", env.popen.call_args.kwargs["env"])
        self.assertNotIn("FORCE_COLOR", env.popen.call_args.kwargs["env"])
        leaf.contract.command(row, leaf.contract.DENIAL_ARGV, 42)
        row["exit_code"] = 0
        with self.assertRaises(ValueError):
            leaf.contract.command(row, leaf.contract.DENIAL_ARGV, 42)

    def test_argv_and_sigchld_contract_fail_before_spawn(self):
        with command_environment() as env:
            with self.assertRaises(ValueError):
                leaf._command(("/bin/sh",), TOKEN)
            with patch.object(leaf.signal, "getsignal", return_value=leaf.signal.SIG_IGN):
                with self.assertRaises(ValueError):
                    leaf._command(leaf.contract.ARGV, TOKEN)
            env.popen.assert_not_called()

    def test_each_stream_cap_preserves_bounded_partial_and_kills_once(self):
        for channel in ("stdout", "stderr"):
            with command_environment(**{channel: b"x" * 131073}) as env:
                with self.assertRaisesRegex(ValueError, "OUTPUT_EXCEEDED") as caught:
                    leaf._command(leaf.contract.ARGV, TOKEN)
            row = caught.exception._native_restart_command
            self.assertEqual(len(leaf.contract.decode(row[channel + "_base64"], 131072)), 131072)
            self.assertTrue(row["group_cleanup"] and row["leader_reaped"])
            env.kill.assert_called_once()

    def test_deadline_interrupt_and_eof_leader_wait_cleanup(self):
        for mode in ("deadline", "interrupt", "eof"):
            with command_environment() as env:
                if mode == "interrupt":
                    env.selector.select.side_effect = KeyboardInterrupt()
                    error = KeyboardInterrupt
                else:
                    error = ValueError
                    if mode == "eof":
                        env.waitid.side_effect = None
                        env.waitid.return_value = None
                        env.monotonic.side_effect = [11 * SECOND, 30 * SECOND]
                    else:
                        env.monotonic.return_value = 30 * SECOND
                with self.assertRaises(error) as caught:
                    leaf._command(leaf.contract.ARGV, TOKEN)
            self.assertTrue(caught.exception._native_restart_command["leader_reaped"])
            env.kill.assert_called_once()
            env.process.stdout.close.assert_called_once()
            env.process.stderr.close.assert_called_once()

    def test_lost_child_custody_never_kills_or_reaps_reused_numeric_pid(self):
        with command_environment() as env:
            env.waitid.side_effect = ChildProcessError()
            with self.assertRaises(ChildProcessError) as caught:
                leaf._command(leaf.contract.ARGV, TOKEN)
        env.kill.assert_not_called()
        env.process.wait.assert_not_called()
        self.assertFalse(caught.exception._native_restart_command["leader_reaped"])
        env.process.stdout.close.assert_called_once()
        env.process.stderr.close.assert_called_once()

    def test_cleanup_error_preserves_original_failure_and_closes_both_streams(self):
        with command_environment(stdout=b"x" * 131073) as env:
            env.kill.side_effect = OSError("cleanup")
            with self.assertRaisesRegex(ValueError, "OUTPUT_EXCEEDED") as caught:
                leaf._command(leaf.contract.ARGV, TOKEN)
        self.assertIn("PROCESS_GROUP_CLEANUP_REFUSED", caught.exception._native_restart_command["cleanup_failures"])
        env.process.stdout.close.assert_called_once()
        env.process.stderr.close.assert_called_once()
