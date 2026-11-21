"""Run the exact embedded helper with fake imports; no fork, OS call or device access."""
from collections import deque
from contextlib import nullcontext
import errno
import json
import stat
from types import SimpleNamespace as NS
import unittest
from unittest.mock import MagicMock, call, patch

from aragorn import pi_core_mask_probe as sender
from aragorn.pi_core_mask_probe import _PROGRAM


class _Exit(Exception):
    """In-memory os._exit stand-in, never exits the test process."""


class Helper:
    def __init__(self, *, replies=(b"G", b"X"), mask=15, deadline=4, uid=40, parent=600,
                 fail_drop=False):
        self.events, self.frames = [], []
        self.replies = deque(replies)
        self.results = {"pts": (-1, 13), "shm": (31, 0), "hugepages": (-1, 2), "ptmx": (0, 0)}
        self.errno, self.clock = 0, 100
        self.names = ["shm", "not-a-selected-device", "pts", "hugepages", "ptmx", "null"]

        def event(op, *args):
            self.events.append((op, *args))
        def changed(op):
            def record(*args):
                event(op, *args)
                if op == "setresuid" and fail_drop:
                    raise PermissionError("simulated refusal")
            return record
        def clock_ns(clock):
            event("clock", clock)
            self.clock += 1
            return self.clock
        def open_dev(path, flags):
            event("open", path, flags)
            if path != "/dev":
                raise AssertionError("unexpected open")
            return 19
        def scandir(fd):
            event("scandir", fd)
            if fd != 19:
                raise AssertionError("wrong listing fd")
            return nullcontext([NS(name=n) for n in self.names])
        def send(raw):
            self.frames.append(json.loads(raw))
            event("send", tuple(sorted(self.frames[-1])))
            return len(raw)
        def receive(size):
            value = self.replies.popleft()
            event("recv", size, value)
            return value
        def make_channel(*, fileno):
            event("channel", fileno)
            return NS(send=send, recv=receive, close=changed("channel.close"))
        def control(number, arg, a, b, c):
            event("prctl", number, arg, a, b, c)
            return 0
        def syscall(number, fd, name, arg, last):
            key = name.decode("ascii")
            event("syscall", number, fd, key, arg, last)
            rc, self.errno = self.results[key]
            return rc
        def set_errno(n):
            self.errno = n
        def stop(code):
            raise _Exit(code)
        libc = NS(prctl=control, syscall=syscall)
        os_stub = NS(CLONE_NEWNS=0x20000, O_RDONLY=0, O_CLOEXEC=0o2000000, O_DIRECTORY=0o40000,
                     O_NOFOLLOW=0o100000, getppid=lambda: 600, open=open_dev, scandir=scandir, _exit=stop,
                     **{k: changed(k) for k in ("setns", "chroot", "chdir", "close", "fchdir", "setgroups",
                                               "setresgid", "setresuid")})
        self.argv = ["-c", "8", "9", "10", "11", str(uid), "41", str(parent), str(mask), str(deadline * 10**9)]
        self.modules = {
            "ctypes": NS(CDLL=lambda *a, **k: libc, c_long=object(), set_errno=set_errno,
                         get_errno=lambda: self.errno, create_string_buffer=lambda n: ("buffer", n),
                         byref=lambda buf: ("byref", buf)),
            "errno": NS(EINVAL=errno.EINVAL), "json": NS(dumps=json.dumps), "os": os_stub,
            "signal": NS(SIGKILL=9, SIGALRM=14, SIG_DFL=0, ITIMER_REAL=0,
                         signal=changed("signal"), setitimer=changed("timer")),
            "socket": NS(socket=make_channel), "struct": NS(), "sys": NS(argv=self.argv),
            "time": NS(monotonic=lambda: 1, CLOCK_BOOTTIME=7, clock_gettime_ns=clock_ns),
        }

    def run(self):
        def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
            if level or name not in self.modules:
                raise AssertionError("unapproved helper import")
            return self.modules[name]
        safe = dict(__import__=restricted_import, int=int, len=len, map=map, min=min, max=max, range=range,
                    sorted=sorted, enumerate=enumerate, dict=dict, ValueError=ValueError, OSError=OSError,
                    BaseException=BaseException)
        try:
            exec(compile(_PROGRAM, "<inert exact mask helper>", "exec", dont_inherit=True), {"__builtins__": safe})
        except _Exit as final:
            return final.args[0]
        raise AssertionError("missing fake exit")

    def selected(self, operation):
        return [row[1:] for row in self.events if row[0] == operation]


class MaskProbeHelperTests(unittest.TestCase):
    def test_parent_selects_exact_pinned_interpreter_program_and_only_owned_fds(self):
        from aragorn import pi_core_node_source_observer as node

        class LaunchIntercepted(Exception):
            pass
        pin = "sha256:" + "a" * 64
        view = NS(names=("pts", "ptmx"), root_fd=8, mntns_fd=9, userns_fd=7,
                  worker={"uid": 40, "gid": 41})
        sock, peer = MagicMock(), MagicMock()
        peer.fileno.return_value = 10
        exe = "/protected/fixture/python"
        os_api = NS(uname=lambda: NS(sysname="Linux", machine="aarch64"), open=MagicMock(return_value=11),
                    close=MagicMock(), getuid=lambda: 0, geteuid=lambda: 0, getpid=lambda: 600,
                    O_RDONLY=0, O_CLOEXEC=123,
                    path=NS(samestat=lambda a, b: a == b),
                    stat=lambda name: {"/proc/self/ns/user": "userns", exe: "exe"}[name],
                    fstat=lambda fd: {7: "userns", 11: "exe"}[fd])
        factory = MagicMock(return_value=(sock, peer))
        popen = MagicMock(side_effect=LaunchIntercepted)
        with patch.object(sender, "os", os_api), patch.object(node, "_hash_readonly", return_value=(pin, None)), \
             patch.object(sender, "socket", NS(AF_UNIX=1, SOCK_SEQPACKET=5, socketpair=factory)), \
             patch.object(sender, "time", NS(monotonic=lambda: 1.0)), \
             patch.object(sender, "sys", NS(executable=exe, version_info=(3, 12))), \
             patch.object(sender, "subprocess", NS(Popen=popen, DEVNULL=-9)):
            with self.assertRaisesRegex(ValueError, "interpreter identity"):
                sender.observe_mask_denials(view, deadline=4.0, cleanup_deadline=5.0, interpreter_digest="different")
            popen.assert_not_called()
            factory.assert_not_called()
            with self.assertRaises(LaunchIntercepted):
                sender.observe_mask_denials(view, deadline=4.0, cleanup_deadline=5.0, interpreter_digest=pin)
        popen.assert_called_once_with(
            [exe, "-I", "-S", "-B", "-c", _PROGRAM, "8", "9", "10", "11", "40", "41", "600", "9", "4000000000"],
            executable="/proc/self/fd/11", pass_fds=(8, 9, 10, 11), close_fds=True, env={}, cwd="/",
            stdin=-9, stdout=-9, stderr=-9)
        self.assertEqual(os_api.close.call_args_list, [call(11), call(11)])

    def test_parent_does_not_send_go_if_either_observed_principal_or_directory_is_wrong(self):
        from aragorn import pi_core_node_source_observer as node
        from aragorn import pi_core_stopped_mask_view as view_reader
        from aragorn import runtime_process_profile as process

        subject = dict(pid=620, start_ticks=100, mount_namespace=401, user_namespace=500, uid=40, gid=41)
        root = dict(mode=stat.S_IFDIR | 0o555, dev="8:1", ino=2, rdev="0:0", mnt_id=1)
        dev = dict(mode=stat.S_IFDIR | 0o755, dev="0:21", ino=4, rdev="0:0", mnt_id=2)
        worker = dict(**subject, root=root.copy(), groups=[], no_new_privs=True, euid=40, suid=40, fsuid=40,
                      egid=41, sgid=41, fsgid=41, cap_effective=0, cap_permitted=0, cap_inheritable=0,
                      cap_ambient=0, cap_bounding=0)
        helper = worker | dict(pid=601, start_ticks=99)
        for label, who, fault in (
                ("positive", "", {}), ("other process", "probe", {"pid": 650}),
                ("other root", "probe", {"root": root | {"ino": 7}}),
                ("other mount namespace", "probe", {"mount_namespace": 403}),
                ("other user namespace", "probe", {"user_namespace": 505}),
                ("retained capabilities", "probe", {"cap_bounding": 4}), ("probe saved root", "probe", {"suid": 0}),
                ("unbounded worker", "worker", {"groups": [0]}), ("substitute /dev", "dev", {"mnt_id": 19}),
                ("probe generation drift", "after", {"start_ticks": 150}),
                ("changed device listing", "listing", {})):
            with self.subTest(label=label):
                worker_obs = worker | (fault if who == "worker" else {})
                helper_obs = helper | (fault if who == "probe" else {})
                dev_obs = dev | (fault if who == "dev" else {})
                view = NS(worker=subject, names=("pts",), root_fd=8, mntns_fd=9, userns_fd=7, dev_fd=5,
                          worker_context=lambda: worker_obs)
                sock, peer, proc = MagicMock(), MagicMock(), MagicMock()
                peer.fileno.return_value = 10
                sock.send.return_value = 1
                proc.pid, proc.wait.return_value, proc.poll.return_value = 601, 0, None if who else 0
                exe = "/protected/fixture/python"
                u = NS(st_ino=500)
                os_api = NS(uname=lambda: NS(sysname="Linux", machine="arm64"), open=lambda *_: 11,
                            close=MagicMock(), getuid=lambda: 0, geteuid=lambda: 0, getpid=lambda: 600,
                            O_RDONLY=0, O_CLOEXEC=1, pidfd_open=lambda pid, flags: 12, path=NS(samestat=lambda a,b: a == b),
                            stat=lambda name: {"/proc/self/ns/user": u, exe: "exe", "/proc/601/exe": "exe"}[name],
                            fstat=lambda fd: {7: u, 9: NS(st_ino=401), 11: "exe"}[fd])
                with patch.object(sender, "os", os_api), patch.object(node, "_hash_readonly", return_value=("pin", None)), \
                     patch.object(sender, "socket", NS(AF_UNIX=1, SOCK_SEQPACKET=5, socketpair=lambda *a: (sock, peer))), \
                     patch.object(sender, "time", NS(monotonic=lambda: 1.0, clock_gettime_ns=MagicMock(side_effect=[3,4]),
                                                    CLOCK_BOOTTIME=7)), \
                     patch.object(sender, "sys", NS(executable=exe, version_info=(3, 12))), \
                     patch.object(sender, "subprocess", NS(Popen=lambda *a, **k: proc, DEVNULL=-9)), \
                     patch.object(sender, "_recv", side_effect=[{"names":["pts"], "fd":19},
                                                               {"names":["pts","x"] if who == "listing" else ["pts"],
                                                                "calls":{"pts":{}}}]), \
                     patch.object(view_reader, "_stat", side_effect=lambda fd: {8:root, 5:dev}[fd]), \
                     patch.object(view_reader, "_probe_frame", side_effect=[
                         (helper_obs, dev_obs), (helper_obs | (fault if who == "after" else {}), dev_obs)]), \
                     patch.object(process, "require_live_pidfd"):
                    run = lambda: sender.observe_mask_denials(view, deadline=4.0, cleanup_deadline=5.0,
                                                              interpreter_digest="pin")
                    if who:
                        with self.assertRaises(ValueError):
                            run()
                        self.assertEqual(sock.send.call_args_list, [call(b"G")] if who in ("after","listing") else [])
                        proc.kill.assert_called_once_with()
                    else:
                        before, after, *_ = run()
                        self.assertEqual((before["worker"], after["probe"]), (worker, helper))
                        self.assertEqual(sock.send.call_args_list, [call(b"G"), call(b"X")])

    def test_exact_program_drops_privileges_and_waits_for_go_before_named_lookups(self):
        child = Helper()
        self.assertEqual(child.run(), 0)
        self.assertEqual(child.selected("channel"), [(10,)])
        self.assertEqual(child.selected("open"), [("/dev", 0o2140000)])
        self.assertEqual(child.selected("scandir"), [(19,), (19,)])
        rows = child.events
        def pos(*row):
            return rows.index(row)
        self.assertLess(pos("setns", 9, 0x20000), pos("fchdir", 8))
        self.assertLess(pos("chroot", "."), pos("chdir", "/"))
        self.assertLess(pos("prctl", 38, 1, 0, 0, 0), pos("setgroups", []))
        self.assertLess(pos("prctl", 47, 4, 0, 0, 0), pos("setgroups", []))
        caps = [r for r in child.selected("prctl") if r[0] == 24]
        self.assertEqual(caps, [(24, i, 0, 0, 0) for i in range(64)])
        self.assertLess(pos("prctl", 24, 63, 0, 0, 0), pos("setgroups", []))
        self.assertLess(pos("setgroups", []), pos("setresgid", 41, 41, 41))
        self.assertLess(pos("setresgid", 41, 41, 41), pos("setresuid", 40, 40, 40))
        self.assertLess(pos("setresuid", 40, 40, 40), pos("open", "/dev", 0o2140000))
        self.assertLess(pos("open", "/dev", 0o2140000), pos("send", ("fd", "names")))
        self.assertLess(pos("send", ("fd", "names")), pos("recv", 2, b"G"))
        self.assertTrue(all(i > pos("recv", 2, b"G") for i, row in enumerate(rows) if row[0] == "syscall"))
        self.assertEqual(child.frames[0], {"fd": 19, "names": sorted(child.names)})
        self.assertEqual(child.frames[1]["names"], sorted(child.names))
        self.assertEqual(child.selected("recv"), [(2, b"G"), (2, b"X")])

    def test_arm64_returns_actual_errno_success_and_clock_boundaries_without_interpretation(self):
        child = Helper()
        self.assertEqual(child.run(), 0)
        calls = child.frames[1]["calls"]
        self.assertEqual(set(calls), {"pts", "shm", "hugepages", "ptmx"})
        for i, name in enumerate(("pts", "shm", "hugepages", "ptmx")):
            link = name == "ptmx"
            rc, err = child.results[name]
            row = calls[name]
            self.assertEqual(row, dict(name=name, syscall="newfstatat" if link else "openat", dirfd=19,
                                       flags=0 if link else 0o2140000, result=rc, errno=err,
                                       started_ns=101 + 2*i, finished_ns=102 + 2*i))
            self.assertEqual(child.selected("syscall")[i], (79 if link else 56, 19, name,
                             ("byref", ("buffer", 256)) if link else 0o2140000, 0))
        self.assertIn((31,), child.selected("close"))
        self.assertNotIn((0,), child.selected("close"))

    def test_only_fixed_names_may_be_probed_and_retirement_never_starts_a_second_request(self):
        child = Helper(mask=1, replies=(b"G", b"G", b"X"))
        self.assertEqual(child.run(), 6)
        self.assertEqual([row[2] for row in child.selected("syscall")], ["pts"])
        self.assertEqual(set(child.frames[1]["calls"]), {"pts"})
        self.assertEqual(list(child.replies), [b"X"])
        for refusal in (b"", b"GO", b"X"):
            with self.subTest(refusal=refusal):
                child = Helper(replies=(refusal,))
                self.assertEqual(child.run(), 5)
                self.assertEqual(child.selected("syscall"), [])
                self.assertEqual(len(child.frames), 1)

    def test_invalid_fixed_inputs_expired_parent_or_credential_refusal_never_reaches_a_lookup(self):
        for args, index, replacement, code in [
            ({"deadline": 1}, None, None, 2), ({"deadline": 7}, None, None, 2),
            ({"parent": 601}, None, None, 2), ({"mask": 0}, None, None, 1),
            ({"mask": 3}, 8, "pts,arbitrary", 7), ({"mask": 2}, None, None, 1),
            ({"mask": 17}, None, None, 1), ({"uid": 0}, None, None, 1),
            ({}, 2, "8", 1), ({"fail_drop": True}, None, None, 7),
        ]:
            with self.subTest(args=args, index=index):
                child = Helper(**args)
                if index is not None:
                    child.argv[index] = replacement
                self.assertEqual(child.run(), code)
                self.assertFalse(child.frames)
                self.assertFalse(child.selected("open"))
                self.assertFalse(child.selected("syscall"))
        for change in (lambda argv: argv.append("extra"), lambda argv: argv.pop()):
            with self.subTest(count=change):
                child = Helper()
                change(child.argv)
                self.assertEqual(child.run(), 1)
                self.assertFalse(child.events)
