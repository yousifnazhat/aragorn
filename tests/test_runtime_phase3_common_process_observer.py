"""Inert second-observer checks; no services or actual process observations run."""

from contextlib import contextmanager, ExitStack
from copy import deepcopy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import runtime_phase3_common_process_observer as subject

CONTAINER = "c" * 64
BOOT = "00000000-0000-0000-0000-000000000001"
IDS = (998, 997, 997, 992, 992, 996, 996)


class Fixture:
    """Real inert fd lifetimes; kernel, account and unit reads are test doubles."""

    def __init__(self, test):
        self.test = test
        self.backing = tempfile.TemporaryFile()
        test.addCleanup(self.backing.close)
        self.states, self.processes, self.commands = {}, {}, []
        self.descriptors, self.pidfds, self.reads = [], {}, []
        self.mutate_unit = self.mutate_virtual = None
        self.fail_pidfd = self.dead_pidfd = None
        self.fail_close = False
        for index, (role, uid, gid) in enumerate(
            (
                ("gateway", IDS[3], IDS[4]),
                ("worker", IDS[1], IDS[2]),
                ("sensor", IDS[5], IDS[6]),
                ("broker", IDS[0], IDS[2]),
            )
        ):
            unit = (
                subject.native.setup_prior._GATEWAY
                if role == "gateway"
                else subject.prior._ROLES[role]
            )
            pid = 100 + index
            cgroup = f"/docker/{CONTAINER}/system.slice/{unit}"
            self.states[role] = {
                "Id": unit,
                "MainPID": str(pid),
                "ControlPID": "0",
                "ControlGroup": cgroup,
                "InvocationID": str(index + 1) * 32,
                "ActiveState": "active",
                "SubState": "running",
                "User": {
                    "gateway": "aragorn-agent-gateway",
                    "worker": "aragorn-runtime",
                    "sensor": "aragorn-sensor",
                    "broker": "aragorn-broker",
                }[role],
                "Group": "aragorn-agent-gateway"
                if role == "gateway"
                else "aragorn-sensor"
                if role == "sensor"
                else "aragorn-runtime",
                "StandardOutput": "journal",
                "DropInPaths": "",
                "FragmentPath": "/usr/lib/systemd/system/" + unit,
            }
            record = {
                "pid": pid,
                "uid": uid,
                "gid": gid,
                "start_time_ticks": 1000 + index,
                "cgroup": cgroup,
            }
            if role == "gateway":
                self.states[role].pop("StandardOutput")
                self.states[role].pop("DropInPaths")
                self.states[role].pop("FragmentPath")
                self.states[role].update(
                    LoadState="loaded",
                    KillMode="control-group",
                    Delegate="no",
                    Restart="no",
                    SendSIGKILL="yes",
                )
                record.update(cgroup_device=1, cgroup_inode=50)
            else:
                argv = subject._argv(role)
                self.states[role]["ExecStart"] = (
                    "{ path=/usr/bin/python3.12 ; argv[]="
                    + " ".join(argv)
                    + " ; ignore_errors=no ; pid=123 ; code=(null) ; status=0/0 }"
                )
                record.update(
                    uids=[uid, uid, uid, IDS[1] if role == "sensor" else uid],
                    gids=[gid, gid, gid, IDS[2] if role == "sensor" else gid],
                    executable="/usr/local/bin/python3.12",
                    command=" ".join(argv),
                )
            self.processes[role] = record

    def by_pid(self, pid):
        # Prefer the endpoint record in the deliberate gateway-PID overlap test,
        # so the distinct-PID assertion (not malformed status) is exercised.
        return next(
            (role, item)
            for role, item in reversed(tuple(self.processes.items()))
            if item["pid"] == pid
        )

    def command(self, argv, *, timeout):
        self.test.assertEqual(
            argv[:3],
            [
                "/usr/bin/systemctl",
                "show",
                "--property=" + ",".join(subject.prior._PROPERTIES),
            ],
        )
        self.test.assertEqual(timeout, 3)
        role = next(
            role for role, unit in subject.prior._ROLES.items() if argv[3] == unit
        )
        self.commands.append(role)
        state = deepcopy(self.states[role])
        if self.mutate_unit:
            self.mutate_unit(role, state, self.commands.count(role))
        return "".join(f"{key}={value}\n" for key, value in state.items()).encode()

    def virtual(self, path, limit):
        path = str(path)
        self.reads.append(path)
        if path == "/proc/sys/kernel/random/boot_id":
            raw = (BOOT + "\n").encode()
        elif path.startswith("/proc/self/fdinfo/"):
            fd = int(path.rsplit("/", 1)[1])
            raw = f"flags:\t02000002\nPid:\t{self.pidfds[fd]}\n".encode()
        else:
            role, record = self.by_pid(int(path.split("/")[2]))
            if path.endswith("/status"):
                raw = (
                    "Uid:\t"
                    + " ".join(map(str, record["uids"]))
                    + "\nGid:\t"
                    + " ".join(map(str, record["gids"]))
                    + "\n"
                ).encode()
            elif path.endswith("/cmdline"):
                raw = b"\0".join(item.encode() for item in subject._argv(role)) + b"\0"
            else:
                raise AssertionError("unexpected virtual read")
        if self.mutate_virtual:
            raw = self.mutate_virtual(path, raw, self.reads.count(path))
        self.test.assertLessEqual(len(raw), limit)
        return raw

    def pidfd(self, pid, flags):
        self.test.assertEqual(flags, 0)
        if len(self.descriptors) == self.fail_pidfd:
            raise OSError("inert PIDFD failure")
        fd = os.dup(self.backing.fileno())
        self.descriptors.append(fd)
        self.pidfds[fd] = pid
        return fd

    def live(self, fd):
        os.fstat(fd)
        if len(self.descriptors) == self.dead_pidfd:
            raise ValueError("inert exited process")

    @contextmanager
    def patched(self):
        original_close = os.close

        def close(fd):
            original_close(fd)
            if self.fail_close and fd in self.descriptors:
                raise OSError("inert close error")

        def readlink(path):
            return (
                "socket:[100]"
                if path.endswith("/fd/1")
                else self.by_pid(int(path.split("/")[2]))[1]["executable"]
            )

        def cgroup(pid):
            return (
                f"/docker/{CONTAINER}/init.scope"
                if pid == 1
                else self.by_pid(pid)[1]["cgroup"]
            )

        def resolve(path, *, strict=False):
            self.test.assertTrue(strict)
            return (
                Path("/usr/local/bin/python3.12")
                if str(path) == "/usr/bin/python3.12"
                else path
            )

        with ExitStack() as stack:
            for target, name, value in (
                (subject.sys, "platform", "linux"),
                (subject.os, "geteuid", lambda: 0),
                (subject.os, "getegid", lambda: 0),
                (subject.os, "close", close),
                (subject.os, "readlink", readlink),
                (subject.response, "_identities", lambda: IDS),
                (subject.response, "_command", self.command),
                (subject.response, "_process_cgroup", cgroup),
                (
                    subject.response,
                    "_process_start_time",
                    lambda pid: self.by_pid(pid)[1]["start_time_ticks"],
                ),
                (subject.prior, "_read_virtual_file", self.virtual),
                (subject.process, "require_live_pidfd", self.live),
                (Path, "resolve", resolve),
            ):
                stack.enter_context(patch.object(target, name, value))
            stack.enter_context(
                patch.object(subject.os, "pidfd_open", self.pidfd, create=True)
            )
            self.gateway_unit = stack.enter_context(
                patch.object(
                    subject.response,
                    "_unit_state",
                    side_effect=lambda unit: deepcopy(self.states["gateway"]),
                )
            )
            self.gateway_process = stack.enter_context(
                patch.object(
                    subject.response,
                    "_process_identity",
                    side_effect=lambda *args: deepcopy(self.processes["gateway"]),
                )
            )
            yield

    def observe(self):
        return subject.observe_common_processes(expected_container_id=CONTAINER)

    def assert_closed(self):
        for fd in self.descriptors:
            with self.test.assertRaises(OSError):
                os.fstat(fd)


class CommonProcessObserverTests(unittest.TestCase):
    def test_actual_new_endpoint_loop_and_pidfd_orchestration_with_inert_reads(self):
        fixture = Fixture(self)
        old_commands, old_roles = (
            deepcopy(subject.prior._COMMANDS),
            deepcopy(subject.prior._ROLES),
        )
        with fixture.patched():
            result = fixture.observe()
        self.assertEqual(result["schema"], subject.SCHEMA)
        self.assertEqual(result["authority"], subject.AUTHORITY)
        self.assertEqual(result["container_id"], CONTAINER)
        self.assertEqual(result["boot_id"], BOOT.replace("-", ""))
        self.assertEqual(result["limitations"], list(subject.LIMITATIONS))
        self.assertTrue(all(result[key] is False for key in subject._FALSE))
        self.assertEqual(
            set(result["processes"]), {"gateway", "worker", "sensor", "broker"}
        )
        for role, record in result["processes"].items():
            self.assertEqual(
                record,
                {"unit": fixture.states[role], "process": fixture.processes[role]},
            )
        self.assertTrue(
            result["processes"]["broker"]["process"]["command"].endswith(
                "/decision-measurement-binding"
            )
        )
        self.assertEqual(fixture.commands, ["worker", "sensor", "broker"] * 2)
        self.assertEqual(fixture.gateway_unit.call_count, 2)
        fixture.gateway_process.assert_called_with(
            subject.native.setup_prior._GATEWAY,
            fixture.states["gateway"],
            IDS[3],
            IDS[4],
        )
        self.assertEqual(len(fixture.descriptors), 4)
        self.assertEqual(subject.prior._COMMANDS, old_commands)
        self.assertEqual(subject.prior._ROLES, old_roles)
        fixture.assert_closed()

    def test_legacy_broker_argv_or_extra_argument_refused_in_unit_and_proc(self):
        for boundary in ("unit", "process"):
            for change in ("missing", "extra"):
                with self.subTest(boundary=boundary, change=change):
                    fixture = Fixture(self)
                    suffix = f"/run/credentials/{subject.prior._ROLES['broker']}/decision-measurement-binding"
                    if boundary == "unit":
                        fixture.states["broker"]["ExecStart"] = fixture.states[
                            "broker"
                        ]["ExecStart"].replace(
                            " " + suffix,
                            "" if change == "missing" else " " + suffix + " extra",
                        )
                    else:

                        def mutate(path, raw, count):
                            if path == "/proc/103/cmdline":
                                return raw.replace(
                                    suffix.encode() + b"\0",
                                    b""
                                    if change == "missing"
                                    else suffix.encode() + b"\0extra\0",
                                )
                            return raw

                        fixture.mutate_virtual = mutate
                    with (
                        fixture.patched(),
                        self.assertRaises(subject.CommonProcessObservationError),
                    ):
                        fixture.observe()
                    self.assertEqual(fixture.descriptors, [])

    def test_worker_sensor_and_gateway_guards_remain_required(self):
        for mode in (
            "worker-unit",
            "sensor-fsuid",
            "broker-fsgid",
            "gateway-cgroup",
            "gateway-epoch",
            "overlap",
            "duplicate-status",
        ):
            with self.subTest(mode=mode):
                fixture = Fixture(self)
                if mode == "worker-unit":
                    fixture.states["worker"]["DropInPaths"] = "/unexpected.conf"
                elif mode == "sensor-fsuid":
                    fixture.processes["sensor"]["uids"][-1] = IDS[5]
                elif mode == "broker-fsgid":
                    fixture.processes["broker"]["gids"][-1] = IDS[6]
                elif mode == "gateway-cgroup":
                    fixture.processes["gateway"]["cgroup"] = "/init.scope"
                elif mode == "gateway-epoch":
                    fixture.states["gateway"]["InvocationID"] = "0" * 32
                elif mode == "overlap":
                    fixture.processes["gateway"]["pid"] = 103
                else:
                    fixture.mutate_virtual = lambda path, raw, count: (
                        raw + b"Uid:\t997 997 997 997\n"
                        if path.endswith("/status")
                        else raw
                    )
                with (
                    fixture.patched(),
                    self.assertRaises(subject.CommonProcessObservationError),
                ):
                    fixture.observe()
                fixture.assert_closed()

    def test_unit_inventory_and_executable_stdout_checks_fail_closed(self):
        for mode in ("duplicate-unit", "bad-fragment", "exe", "stdout"):
            with self.subTest(mode=mode):
                fixture = Fixture(self)
                with fixture.patched(), ExitStack() as stack:
                    if mode == "duplicate-unit":
                        stack.enter_context(
                            patch.object(
                                subject.response,
                                "_command",
                                side_effect=lambda argv, **kwargs: (
                                    fixture.command(argv, **kwargs) + b"Id=duplicate\n"
                                ),
                            )
                        )
                    elif mode == "bad-fragment":
                        fixture.states["worker"]["FragmentPath"] = "/unexpected/unit"
                    else:
                        readlink = subject.os.readlink
                        stack.enter_context(
                            patch.object(
                                subject.os,
                                "readlink",
                                side_effect=lambda path: (
                                    "wrong"
                                    if path.endswith(
                                        "/exe" if mode == "exe" else "/fd/1"
                                    )
                                    else readlink(path)
                                ),
                            )
                        )
                    with self.assertRaises(subject.CommonProcessObservationError):
                        fixture.observe()
                fixture.assert_closed()

    def test_final_process_boot_account_and_fixture_rereads_are_required(self):
        for mode in ("process", "boot", "accounts", "fixture"):
            with self.subTest(mode=mode):
                fixture = Fixture(self)
                with fixture.patched(), ExitStack() as stack:
                    if mode == "process":
                        fixture.mutate_unit = lambda role, state, count: (
                            state.update(InvocationID="f" * 32)
                            if role == "broker" and count == 2
                            else None
                        )
                    elif mode == "boot":
                        fixture.mutate_virtual = lambda path, raw, count: (
                            raw.replace(b"0001", b"0002")
                            if path.endswith("boot_id") and count == 2
                            else raw
                        )
                    elif mode == "accounts":
                        stack.enter_context(
                            patch.object(
                                subject.response,
                                "_identities",
                                side_effect=[IDS, tuple(reversed(IDS))],
                            )
                        )
                    else:
                        cgroup, calls = subject.response._process_cgroup, []

                        def changed(pid):
                            if pid == 1:
                                calls.append(pid)
                                if len(calls) == 2:
                                    return "/init.scope"
                            return cgroup(pid)

                        stack.enter_context(
                            patch.object(
                                subject.response, "_process_cgroup", side_effect=changed
                            )
                        )
                    with self.assertRaises(subject.CommonProcessObservationError):
                        fixture.observe()
                self.assertEqual(len(fixture.descriptors), 4)
                fixture.assert_closed()

    def test_pidfd_open_binding_liveness_and_cleanup_failures_close_all_handles(self):
        for mode in ("partial-open", "pidfd-binding", "dead", "close"):
            with self.subTest(mode=mode):
                fixture = Fixture(self)
                if mode == "partial-open":
                    fixture.fail_pidfd = 2
                elif mode == "pidfd-binding":
                    fixture.mutate_virtual = lambda path, raw, count: (
                        b"Pid:\t9999\n" if "/fdinfo/" in path else raw
                    )
                elif mode == "dead":
                    fixture.dead_pidfd = 3
                else:
                    fixture.fail_close = True
                with (
                    fixture.patched(),
                    self.assertRaises(subject.CommonProcessObservationError),
                ):
                    fixture.observe()
                fixture.assert_closed()

    def test_environment_rejection_precedes_unit_reads(self):
        fixture = Fixture(self)
        for mode in ("platform", "uid", "gid", "container", "owned-fixture"):
            with self.subTest(mode=mode), fixture.patched(), ExitStack() as stack:
                if mode == "platform":
                    stack.enter_context(patch.object(subject.sys, "platform", "darwin"))
                elif mode in {"uid", "gid"}:
                    stack.enter_context(
                        patch.object(subject.os, "gete" + mode, return_value=1000)
                    )
                elif mode == "owned-fixture":
                    stack.enter_context(
                        patch.object(
                            subject.response,
                            "_process_cgroup",
                            return_value="/init.scope",
                        )
                    )
                with self.assertRaises(subject.CommonProcessObservationError):
                    subject.observe_common_processes(
                        expected_container_id="not-a-container"
                        if mode == "container"
                        else CONTAINER
                    )
                self.assertEqual(fixture.commands, [])


if __name__ == "__main__":
    unittest.main()
