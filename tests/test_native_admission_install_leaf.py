"""Mocked native upload leaf only: never spawn, signal, read procfs or open PIDFDs."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
import io
from types import SimpleNamespace
import subprocess
import unittest
from unittest.mock import Mock, patch

from scripts import runtime_native_admission_install as leaf
from test_native_phase3_admission_install import fixture
from test_native_admission_direct_write import _file, _pin


TOKEN = "b" * 64


@contextmanager
def command_environment(stdout=b'{"ok":false}', stderr=b"", code=1):
    events = []
    process = Mock(pid=4321)
    process.stdout.fileno.return_value = 11
    process.stderr.fileno.return_value = 12
    process.wait.side_effect = lambda **kw: events.append("reap") or code
    process.stdout.close.side_effect = lambda: events.append("close-stdout")
    process.stderr.close.side_effect = lambda: events.append("close-stderr")
    registered = {}
    selector = Mock()
    selector.__enter__ = Mock(return_value=selector)
    selector.__exit__ = Mock(return_value=False)
    selector.register.side_effect = lambda stream, mask, name: registered.update({
        stream.fileno(): SimpleNamespace(fileobj=stream, data=name),
    })
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
        waitid = stack.enter_context(patch.object(
            leaf.os, "waitid", create=True,
            side_effect=lambda *a: events.append("observe-unreaped") or SimpleNamespace(si_pid=4321),
        ))
        for name, value in (("P_PID", 1), ("WEXITED", 4), ("WNOHANG", 1), ("WNOWAIT", 8)):
            stack.enter_context(patch.object(leaf.os, name, value, create=True))
        kill = stack.enter_context(patch.object(
            leaf.os, "killpg", side_effect=lambda *a: events.append("kill-group"),
        ))
        clock = stack.enter_context(patch.object(leaf.time, "monotonic", return_value=1))
        sleep = stack.enter_context(patch.object(leaf.time, "sleep"))
        stack.enter_context(patch.object(leaf.signal, "getsignal", return_value=leaf.signal.SIG_DFL))
        yield SimpleNamespace(process=process, popen=popen, kill=kill, waitid=waitid,
                              clock=clock, sleep=sleep, events=events, selector=selector)


class NativeInstallCommandTests(unittest.TestCase):
    def test_exit_one_install_and_group_cleanup_before_reap(self):
        with command_environment() as env:
            result = leaf._command(list(leaf.contract.ARGV), TOKEN)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(env.events, ["observe-unreaped", "kill-group", "reap",
                                          "close-stdout", "close-stderr"])
            env.kill.assert_called_once_with(4321, leaf.signal.SIGKILL)
            self.assertTrue(env.popen.call_args.kwargs["start_new_session"])
            self.assertEqual(env.popen.call_args.kwargs["env"]["OPENCLAW_GATEWAY_TOKEN"], TOKEN)
            self.assertNotIn(TOKEN, repr(env.popen.call_args.args))

    def test_catalog_zero_and_install_one_are_distinct(self):
        for argv, code, accepted in (
            (leaf.CATALOGS[0], 0, True), (leaf.CATALOGS[0], 1, False),
            (leaf.contract.ARGV, 0, False), (leaf.contract.ARGV, 1, True),
        ):
            with self.subTest(code=code, install=argv == leaf.contract.ARGV):
                with command_environment(code=code) as env:
                    if accepted:
                        self.assertEqual(leaf._command(list(argv), TOKEN).returncode, code)
                    else:
                        with self.assertRaises(leaf.contract.NativeInstallError) as caught:
                            leaf._command(list(argv), TOKEN)
                        self.assertEqual(caught.exception._native_install_command["exit_code"], code)
                    env.popen.assert_called_once()

    def test_argv_or_sigchld_refuses_before_spawn(self):
        with command_environment() as env:
            with self.assertRaises(leaf.contract.NativeInstallError):
                leaf._command(["/bin/sh"], TOKEN)
            with patch.object(leaf.signal, "getsignal", return_value=leaf.signal.SIG_IGN):
                with self.assertRaises(leaf.contract.NativeInstallError):
                    leaf._command(list(leaf.contract.ARGV), TOKEN)
            env.popen.assert_not_called()

    def test_caps_each_stream_and_redacts_partial_output(self):
        for channel in ("stdout", "stderr"):
            with self.subTest(channel=channel), command_environment(
                **{channel: b"x" * (leaf.contract.shared.MAX_COMMAND + 50)},
            ) as env:
                with self.assertRaises(leaf.contract.NativeInstallError) as caught:
                    leaf._command(list(leaf.contract.ARGV), TOKEN)
                metadata = caught.exception._native_install_command
                self.assertEqual(metadata[channel + "_bytes"], leaf.contract.shared.MAX_COMMAND + 1)
                self.assertNotIn("stdout", metadata)
                self.assertNotIn("stderr", metadata)
                self.assertTrue(metadata["group_cleanup"] and metadata["leader_reaped"])
                env.kill.assert_called_once()

    def test_timeout_and_interrupt_always_kill_reap_close(self):
        for interruption in (False, True):
            with self.subTest(interruption=interruption), command_environment() as env:
                if interruption:
                    env.selector.select.side_effect = KeyboardInterrupt()
                    error = KeyboardInterrupt
                else:
                    env.clock.side_effect = [0, 20]
                    error = leaf.contract.NativeInstallError
                with self.assertRaises(error) as caught:
                    leaf._command(list(leaf.contract.ARGV), TOKEN)
                self.assertTrue(caught.exception._native_install_command["leader_reaped"])
                self.assertEqual(env.events[-4:], ["kill-group", "reap", "close-stdout", "close-stderr"])

    def test_pipe_eof_does_not_remove_leader_deadline(self):
        with command_environment() as env:
            env.waitid.return_value = None
            env.waitid.side_effect = None
            env.clock.side_effect = [0, 1, 2, 20]
            with self.assertRaisesRegex(leaf.contract.NativeInstallError, "DEADLINE"):
                leaf._command(list(leaf.contract.ARGV), TOKEN)
            env.kill.assert_called_once()

    def test_lost_child_custody_never_signals_reused_pid(self):
        with command_environment() as env:
            env.waitid.side_effect = ChildProcessError()
            with self.assertRaises(ChildProcessError) as caught:
                leaf._command(list(leaf.contract.ARGV), TOKEN)
            env.kill.assert_not_called()
            env.process.wait.assert_not_called()
            self.assertFalse(caught.exception._native_install_command["leader_reaped"])
            env.process.stdout.close.assert_called_once()
            env.process.stderr.close.assert_called_once()

    def test_cleanup_failures_refuse_and_still_close_both_pipes(self):
        for operation in ("kill", "wait", "close"):
            with self.subTest(operation=operation), command_environment() as env:
                if operation == "kill":
                    env.kill.side_effect = PermissionError()
                elif operation == "wait":
                    env.process.wait.side_effect = subprocess.TimeoutExpired("fixed", 5)
                else:
                    env.process.stdout.close.side_effect = OSError()
                with self.assertRaises(Exception) as caught:
                    leaf._command(list(leaf.contract.ARGV), TOKEN)
                self.assertTrue(caught.exception._native_install_command["cleanup_failures"])
                env.process.stderr.close.assert_called_once()

    def test_secret_or_stderr_never_returned(self):
        for outputs in ({"stdout": TOKEN.encode()}, {"stderr": b"private diagnostic"}):
            with self.subTest(outputs=list(outputs)), command_environment(**outputs):
                with self.assertRaises(leaf.contract.NativeInstallError) as caught:
                    leaf._command(list(leaf.contract.ARGV), TOKEN)
                self.assertNotIn(TOKEN, repr(caught.exception._native_install_command))
                self.assertNotIn("private diagnostic", repr(caught.exception._native_install_command))


@contextmanager
def native_environment():
    observation, bindings = fixture()
    arguments = {**bindings, "expected_probe_digest": _pin("leaf"),
                 "expected_verifier_digest": _pin("consumer")}
    boundary = observation["before"]
    outputs = [subprocess.CompletedProcess(row["argv"], row["exit_code"],
                                           row["stdout"].encode(), b"")
               for row in [*observation["commands_before"], observation["install_command"],
                           *observation["commands_after"]]]
    with ExitStack() as stack:
        stack.enter_context(patch.object(leaf, "_guard", return_value=TOKEN))
        sources = stack.enter_context(patch.object(leaf, "_sources", return_value={"fixed": "source"}))
        stack.enter_context(patch.object(leaf.os, "pidfd_open", return_value=90, create=True))
        close = stack.enter_context(patch.object(leaf.os, "close"))
        poller = Mock()
        poller.poll.return_value = []
        stack.enter_context(patch.object(leaf.select, "poll", return_value=poller))
        gateway = stack.enter_context(patch.object(leaf.readers, "_gateway", side_effect=lambda *a: deepcopy(boundary["gateway"])))
        stack.enter_context(patch.object(leaf.readers, "_boundary", side_effect=lambda *a: deepcopy(boundary)))
        command = stack.enter_context(patch.object(leaf, "_command", side_effect=outputs))
        yield SimpleNamespace(arguments=arguments, bindings=bindings, observation=observation,
                              outputs=outputs, command=command, close=close, poller=poller,
                              sources=sources, gateway=gateway)


class NativeInstallLeafTests(unittest.TestCase):
    def test_sigterm_main_kills_group_retains_partial_output_and_restores_handler(self):
        real_command = leaf._command
        prior, handlers, children = object(), {}, []

        def set_signal(number, handler):
            previous = handlers.get(number, prior)
            handlers[number] = handler
            return previous

        with native_environment() as env:
            index = 0

            def command(argv, token):
                nonlocal index
                index += 1
                if tuple(argv) == leaf.contract.ARGV:
                    with command_environment() as child:
                        children.append(child)
                        child.selector.select.side_effect = lambda timeout: handlers[leaf.signal.SIGTERM](leaf.signal.SIGTERM, None)
                        return real_command(argv, token)
                return env.outputs[index - 1]

            env.command.side_effect = command
            output = io.BytesIO()
            argv = []
            for key, value in env.arguments.items():
                argv.extend(["--" + key.removeprefix("expected_").replace("_", "-"), str(value)])
            with patch.object(leaf.signal, "signal", side_effect=set_signal) as signals, \
                    patch.object(leaf.sys, "stdout", SimpleNamespace(buffer=output)):
                code = leaf.main(argv)
            result = leaf.contract.shared.parse(output.getvalue())
            self.assertEqual(code, 130)
            self.assertEqual(result["status"], "REFUSED")
            self.assertEqual(result["observation"]["refusal"]["phase"], "INSTALL")
            self.assertTrue(result["command_failures"][0]["leader_reaped"])
            self.assertIsNotNone(result["observation"]["after"])
            self.assertEqual(env.command.call_count, 9)
            children[0].kill.assert_called_once_with(4321, leaf.signal.SIGKILL)
            env.close.assert_called_once_with(90)
            self.assertIs(handlers[leaf.signal.SIGTERM], prior)
            self.assertEqual(signals.call_count, 2)

    def test_real_recorder_and_verifier_compose_with_mocked_native_io(self):
        with native_environment() as env:
            result = leaf.run_install_probe(**env.arguments)
            self.assertEqual(result["status"], "OBSERVED")
            self.assertEqual(result["observation"], env.observation)
            self.assertEqual(env.command.call_count, 9)
            env.close.assert_called_once_with(90)
            self.assertTrue(all(result[key] is False for key in leaf.contract.shared.FALSE_FLAGS))

    def test_gateway_death_or_identity_drift_prevents_commands(self):
        for drift in (False, True):
            with self.subTest(drift=drift), native_environment() as env:
                if drift:
                    old = env.observation["before"]["gateway"]
                    env.gateway.side_effect = [old, {**old, "start_time_ticks": 999}]
                else:
                    env.poller.poll.return_value = [(90, 1)]
                result = leaf.run_install_probe(**env.arguments)
                self.assertEqual(result["status"], "REFUSED")
                env.command.assert_not_called()
                env.close.assert_called_once()

    def test_command_partial_failure_and_interrupt_are_retained_once(self):
        for interrupt in (False, True):
            with self.subTest(interrupt=interrupt), native_environment() as env:
                error = KeyboardInterrupt() if interrupt else leaf.contract.NativeInstallError("fixed")
                error._native_install_command = {"exit_code": None, "stdout_bytes": 17}
                env.outputs[4] = error
                env.command.side_effect = env.outputs
                if interrupt:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        leaf.run_install_probe(**env.arguments)
                    result = caught.exception._native_install_leaf
                else:
                    result = leaf.run_install_probe(**env.arguments)
                self.assertEqual(result["status"], "REFUSED")
                self.assertEqual(result["command_failures"], [error._native_install_command])
                self.assertIsNotNone(result["observation"]["after"])
                self.assertEqual(env.command.call_count, 9)

    def test_source_change_and_pidfd_cleanup_cannot_be_success(self):
        for close_failure in (False, True):
            with self.subTest(close_failure=close_failure), native_environment() as env:
                if close_failure:
                    env.close.side_effect = OSError("private")
                else:
                    env.sources.side_effect = [{"fixed": "source"}, {"fixed": "changed"}]
                result = leaf.run_install_probe(**env.arguments)
                self.assertEqual(result["status"], "REFUSED")
                self.assertNotIn("private", repr(result))
                if not close_failure:
                    env.command.assert_not_called()


class NativeInstallGuardTests(unittest.TestCase):
    def test_gateway_mount_namespace_mismatch_uses_existing_reader_refusal(self):
        def proc(path):
            if path.endswith("/stat"):
                return b"42 (openclaw) S " + b"0 " * 18 + b"123"
            if path.endswith("/cmdline"):
                return b"openclaw-gateway\0"
            raise AssertionError("unexpected proc read")
        with patch.object(leaf.readers, "_status", return_value={}), \
                patch.object(leaf.readers, "_read_proc", side_effect=proc), \
                patch.object(leaf.os, "stat", side_effect=[
                    SimpleNamespace(st_ino=100), SimpleNamespace(st_ino=200),
                ]):
            with self.assertRaisesRegex(ValueError, "MOUNT_NAMESPACE_MISMATCH"):
                leaf.readers._gateway("c" * 64, 42)

    def guard_environment(self, stack):
        _, bindings = fixture()
        arguments = {**bindings, "expected_probe_digest": _pin("leaf"),
                     "expected_verifier_digest": _pin("verifier")}
        stack.enter_context(patch.object(leaf.sys, "platform", "linux"))
        uid = stack.enter_context(patch.object(leaf.os, "getresuid", return_value=(992,) * 3, create=True))
        stack.enter_context(patch.object(leaf.os, "getresgid", return_value=(992,) * 3, create=True))
        stack.enter_context(patch.object(leaf.os, "getgroups", return_value=[992]))
        for module, path in ((leaf, leaf.PROBE), (leaf.contract, leaf.VERIFIER),
                             (leaf.readers, leaf.contract.shared.PROBE),
                             (leaf.contract.shared, leaf.contract.shared.VERIFIER)):
            stack.enter_context(patch.object(module, "__file__", path))
        status = {key: "0000000000000000" for key in
                  ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
        status["NoNewPrivs"] = "1"
        stack.enter_context(patch.object(leaf.readers, "_status", return_value=status))
        proc = stack.enter_context(patch.object(leaf.readers, "_read_proc", return_value=(
            "0::/docker/" + bindings["expected_container"] + "/leaf\n").encode()))
        stack.enter_context(patch.dict(leaf.os.environ, {"OPENCLAW_GATEWAY_TOKEN": TOKEN}))
        return arguments, uid, status, proc

    def test_valid_guard_and_rejection_of_privilege_cgroup_or_source_changes(self):
        for change in (None, "uid", "cap", "nnp", "cgroup", "source", "pid"):
            with self.subTest(change=change), ExitStack() as stack:
                arguments, uid, status, proc = self.guard_environment(stack)
                if change == "uid": uid.return_value = (0, 0, 0)
                if change == "cap": status["CapBnd"] = "0000000000000001"
                if change == "nnp": status["NoNewPrivs"] = "0"
                if change == "cgroup": proc.return_value = b"0::/other\n"
                if change == "source": stack.enter_context(patch.object(leaf, "__file__", "/tmp/leaf"))
                if change == "pid": arguments["expected_gateway_pid"] = True
                if change is None:
                    self.assertEqual(leaf._guard(arguments), TOKEN)
                else:
                    with self.assertRaises(leaf.contract.NativeInstallError):
                        leaf._guard(arguments)

    def test_sources_require_exact_pin_root_ownership_and_mode(self):
        pin = _pin("source")
        for change in (None, "digest", "uid", "mode"):
            with self.subTest(change=change):
                row = _file(pin)
                if change == "digest": row["digest"] = _pin("wrong")
                if change == "uid": row["identity"][3] = 992
                if change == "mode": row["identity"][2] = 0o100644
                with patch.object(leaf.readers, "_file", return_value=row):
                    if change is None:
                        self.assertEqual(leaf._sources({leaf.PROBE: pin}), {leaf.PROBE: row})
                    else:
                        with self.assertRaises(ValueError):
                            leaf._sources({leaf.PROBE: pin})


if __name__ == "__main__":
    unittest.main()
