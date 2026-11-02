"""New cleanup-boundary checks; the public fixture uses fabricated native IO."""

from contextlib import ExitStack
from copy import deepcopy
import fcntl
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import native_phase3_http_fixture as fixture


CLOSE = "HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED"
FINAL = "HTTP_FIXTURE_FINAL_GUARD_FAILED"
EXPECTED = dict(container_id="a" * 64, boot_id="11111111-2222-3333-4444-555555555555",
                netns_device=7, netns_inode=55)


def metadata(device, inode, mode=stat.S_IFREG | 0o444):
    return SimpleNamespace(st_dev=device, st_ino=inode, st_mode=mode, st_uid=0, st_gid=0)


class Native:
    """No real descriptor, namespace, process, socket or proc operation escapes."""

    def __init__(self):
        self.pid = self.thread = 5000
        self.rows = {20: metadata(7, 55), 21: metadata(7, 55),
                     22: metadata(8, 66, stat.S_IFREG | 0o600)}
        self.flags = {20: os.O_RDONLY, 21: os.O_RDONLY, 22: os.O_RDWR}
        self.fdflags = {20: fcntl.FD_CLOEXEC, 21: fcntl.FD_CLOEXEC, 22: fcntl.FD_CLOEXEC}
        self.order = []
        self.next_proc = 100
        self.proc_data = {}
        self.fdinfo_raw = b"pos:\t0\nflags:\t02000002\nPid:\t1\nNSpid:\t1\n"
        self.closed = []
        self.hook = lambda *event: None
        self.live = True
        self.primary = None

    def event(self, *value):
        self.order.append(value)
        self.hook(*value)

    def open(self, path, flags):
        path = str(path)
        self.event("open", path, flags)
        if path in ("/proc/self/ns/net", "/proc/1/ns/net"):
            return 20 if path.startswith("/proc/self/") else 21
        if path != "/proc/self/fdinfo/22":
            raise AssertionError("unexpected native open")
        expected_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        if flags != expected_flags:
            raise AssertionError("unsafe proc open flags")
        fd = self.next_proc
        self.next_proc += 1
        self.rows[fd] = metadata(9, 1000 + fd)
        self.flags[fd], self.fdflags[fd] = os.O_RDONLY, fcntl.FD_CLOEXEC
        self.proc_data[fd] = self.fdinfo_raw
        self.event("proc_opened", fd)
        return fd

    def pidfd_open(self, pid, flags):
        self.event("pidfd_open", pid, flags)
        if (pid, flags) != (1, 0):
            raise AssertionError("unexpected PIDFD")
        return 22

    def fstat(self, fd):
        self.event("fstat", fd)
        value = deepcopy(self.rows[fd])
        self.event("fstat_return", fd)
        return value

    def stat(self, path):
        path = str(path)
        self.event("stat", path)
        if path not in ("/proc/self/ns/net", "/proc/1/ns/net"):
            raise AssertionError("unexpected named stat")
        return metadata(7, 55)

    def fcntl(self, fd, command):
        self.event("fcntl", fd, command)
        if command == fcntl.F_GETFL:
            value = self.flags[fd]
        elif command == fcntl.F_GETFD:
            value = self.fdflags[fd]
        else:
            raise AssertionError("unexpected descriptor mutation")
        self.event("fcntl_return", fd, command)
        return value

    def readlink(self, path):
        self.event("readlink", path)
        if path in ("/proc/self/ns/net", "/proc/1/ns/net", "/proc/self/fd/20", "/proc/self/fd/21"):
            value = "net:[55]"
        else:
            raise AssertionError("unexpected native link")
        self.event("readlink_return", path)
        return value

    def read(self, fd, count):
        self.event("read", fd, count)
        if fd < 100 or not 1 <= count <= 4097:
            raise AssertionError("unexpected native read")
        value = self.proc_data[fd][:count]
        self.proc_data[fd] = self.proc_data[fd][count:]
        self.event("read_return", fd, count)
        return value

    def close(self, fd):
        self.event("close", fd)
        if fd in self.closed:
            raise AssertionError("duplicate close")
        self.closed.append(fd)

    def live_pidfd(self, fd):
        self.event("live", fd)
        if fd != 22 or not self.live:
            raise ValueError("fabricated unavailable PIDFD")

    def virtual(self, path, maximum):
        path = str(path)
        self.event("virtual", path)
        root = ("0::/docker/" + EXPECTED["container_id"]).encode()
        values = {"/proc/1/cgroup": root + b"/init.scope\n",
                  "/proc/self/cgroup": root + b"/observer\n",
                  "/proc/sys/kernel/random/boot_id": (EXPECTED["boot_id"] + "\n").encode(),
                  "/proc/5000/status": b"Uid:\t0 0 0 0\nGid:\t0 0 0 0\n",
                  "/proc/1/status": b"Uid:\t0 0 0 0\nGid:\t0 0 0 0\n"}
        if path not in values:
            raise AssertionError("unmocked virtual dependency")
        value = values[path]
        if len(value) > maximum:
            raise AssertionError("fixture exceeds actual read bound")
        return value

    def __enter__(self):
        self.stack = ExitStack()
        patches = [(fixture.sys, "platform", "linux"),
                   (fixture.os, "getpid", Mock(side_effect=lambda: self.pid)),
                   (fixture.threading, "get_native_id", Mock(side_effect=lambda: self.thread)),
                   (fixture.os, "geteuid", Mock(return_value=0)),
                   (fixture.os, "getegid", Mock(return_value=0)),
                   (fixture.os, "open", Mock(side_effect=self.open)),
                   (fixture.os, "pidfd_open", Mock(side_effect=self.pidfd_open)),
                   (fixture.os, "fstat", Mock(side_effect=self.fstat)),
                   (fixture.os, "stat", Mock(side_effect=self.stat)),
                   (fixture.os, "readlink", Mock(side_effect=self.readlink)),
                   (fixture.os, "read", Mock(side_effect=self.read)),
                   (fixture.os, "close", Mock(side_effect=self.close)),
                   (fixture.fcntl, "fcntl", Mock(side_effect=self.fcntl)),
                   (fixture.socket, "if_nameindex", Mock(return_value=[(1, "lo")])),
                   (fixture.process, "_read_virtual_file", Mock(side_effect=self.virtual)),
                   (fixture.process, "_process_start_time", Mock(side_effect=lambda pid: {5000: 33, 1: 11}[pid])),
                   (fixture.process, "require_live_pidfd", Mock(side_effect=self.live_pidfd))]
        for module, name, value in patches:
            self.stack.enter_context(patch.object(module, name, value, create=True))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def held_closes(self):
        return [fd for fd in self.closed if fd < 100]


class FixtureCleanupTests(unittest.TestCase):
    def arm_cleanup(self, session, native, hook):
        original_guard = session.guard
        def final_guard():
            original_guard()
            native.hook = hook
        # Run the actual public final guard, then perturb only terminal cleanup.
        session.guard = final_guard

    def test_normal_public_identity_tuple_and_reverse_close_once(self):
        with Native() as native:
            with fixture.owned_http_fixture(EXPECTED) as session:
                self.assertEqual(session._fds, (20, 21, 22))
                self.assertEqual(session.identity, dict(fixture=EXPECTED,
                    process=dict(pid=5000, start_time_ticks=33, uid=0, gid=0),
                    init_process=dict(pid=1, start_time_ticks=11, uid=0, gid=0)))
                session.guard()
            self.assertEqual(native.held_closes(), [22, 21, 20])
            self.assertEqual(len(native.closed), len(set(native.closed)))
            self.assertEqual(set(native.proc_data), {fd for fd in native.closed if fd >= 100})
            with self.assertRaisesRegex(ValueError, "HTTP_FIXTURE_SESSION_CLOSED"):
                session.guard()

    def test_partial_open_failure_closes_only_acquired_namespace(self):
        with Native() as native:
            original = OSError("fabricated second open failure")
            def hook(*event):
                if event[:2] == ("open", "/proc/1/ns/net"):
                    raise original
            native.hook = hook
            with self.assertRaises(OSError) as caught:
                with fixture.owned_http_fixture(EXPECTED):
                    self.fail("must not yield")
            self.assertIs(caught.exception, original)
            self.assertEqual(native.held_closes(), [20])

    def test_unknown_initial_metadata_is_tracked_and_never_closed(self):
        for unknown_fd in (20, 21, 22):
            with self.subTest(fd=unknown_fd), Native() as native:
                original = OSError("fabricated initial metadata failure")
                def hook(*event):
                    if event == ("fstat", unknown_fd):
                        raise original
                native.hook = hook
                with self.assertRaises(OSError) as caught:
                    with fixture.owned_http_fixture(EXPECTED):
                        self.fail("must not yield")
                self.assertIs(caught.exception, original)
                self.assertIn(CLOSE, caught.exception.__notes__)
                self.assertEqual(native.held_closes(), list(reversed([fd for fd in (20, 21) if fd < unknown_fd])))

    def test_namespace_type_identity_access_and_cloexec_required_initially(self):
        for variant in ("type", "identity", "access", "cloexec"):
            with self.subTest(variant=variant), Native() as native:
                if variant == "type":
                    native.rows[20].st_mode = stat.S_IFIFO | 0o600
                elif variant == "identity":
                    native.rows[20].st_ino = 56
                elif variant == "access":
                    native.flags[20] = os.O_WRONLY
                else:
                    native.fdflags[20] = 0
                with self.assertRaisesRegex(ValueError, CLOSE):
                    with fixture.owned_http_fixture(EXPECTED):
                        self.fail("must not yield")
                self.assertEqual(native.closed, [])

    def test_substituted_namespace_is_skipped_other_owned_resources_close(self):
        with Native() as native:
            with self.assertRaises(ValueError) as caught:
                with fixture.owned_http_fixture(EXPECTED):
                    native.rows[21].st_ino = 99
            self.assertIn(CLOSE, caught.exception.__notes__)
            self.assertEqual(native.held_closes(), [22, 20])

    def test_changed_namespace_flags_are_not_treated_as_known_ownership(self):
        for field in ("flags", "fdflags"):
            with self.subTest(field=field), Native() as native:
                with self.assertRaises(ValueError):
                    with fixture.owned_http_fixture(EXPECTED):
                        getattr(native, field)[20] = os.O_WRONLY if field == "flags" else 0
                self.assertEqual(native.held_closes(), [22, 21])

    def test_pidfd_metadata_replacement_is_skipped_even_if_association_matches(self):
        with Native() as native:
            with self.assertRaises(ValueError):
                with fixture.owned_http_fixture(EXPECTED):
                    native.rows[22].st_ino = 67
            self.assertEqual(native.held_closes(), [21, 20])

    def test_dead_missing_duplicate_or_unavailable_pidfd_association_is_not_closed(self):
        for raw in (b"Pid:\t-1\n", b"Pid:\t2\n", b"pos:\t0\n", b"Pid:\t1\nPid:\t1\n", b"Pid:\t1", b"Pid:\t1\n\0"):
            with self.subTest(raw=raw), Native() as native:
                with self.assertRaises(ValueError):
                    with fixture.owned_http_fixture(EXPECTED):
                        native.fdinfo_raw = raw
                self.assertEqual(native.held_closes(), [21, 20])
        with Native() as native:
            with self.assertRaises(ValueError):
                with fixture.owned_http_fixture(EXPECTED):
                    native.live = False
            self.assertEqual(native.held_closes(), [21, 20])

    def test_initial_pidfd_association_failure_preserves_prior_known_resources(self):
        with Native() as native:
            native.fdinfo_raw = b"Pid:\t-1\n"
            with self.assertRaisesRegex(ValueError, CLOSE):
                with fixture.owned_http_fixture(EXPECTED):
                    self.fail("must not yield")
            self.assertEqual(native.held_closes(), [21, 20])
            self.assertTrue(any(fd >= 100 for fd in native.closed))

    def test_late_namespace_substitution_during_link_or_flag_readback_is_not_closed(self):
        for event_name in ("readlink_return", "fcntl_return"):
            with self.subTest(event=event_name), Native() as native:
                primary = RuntimeError("fabricated caller failure")
                def hook(*event):
                    if ((event_name == "readlink_return" and event == (event_name, "/proc/self/fd/21"))
                            or (event_name == "fcntl_return" and event[:2] == (event_name, 21))):
                        native.rows[21].st_ino = 99
                with self.assertRaises(RuntimeError) as caught:
                    with fixture.owned_http_fixture(EXPECTED) as session:
                        self.arm_cleanup(session, native, hook)
                        raise primary
                self.assertIs(caught.exception, primary)
                self.assertEqual(native.held_closes(), [22, 20])
                self.assertIn(CLOSE, primary.__notes__)
                self.assertNotIn(FINAL, primary.__notes__)

    def test_late_pidfd_substitution_during_actual_fdinfo_read_is_not_closed(self):
        with Native() as native:
            def hook(*event):
                if event[0] == "read_return":
                    native.rows[22].st_ino = 67
            with self.assertRaises(ValueError):
                with fixture.owned_http_fixture(EXPECTED) as session:
                    self.arm_cleanup(session, native, hook)
            self.assertEqual(native.held_closes(), [21, 20])

    def test_pidfd_close_has_association_then_final_fstat_order(self):
        with Native() as native:
            with fixture.owned_http_fixture(EXPECTED):
                pass
            index = native.order.index(("close", 22))
            preceding = native.order[:index]
            final_fstat = max(i for i, event in enumerate(preceding) if event == ("fstat", 22))
            last_read = max(i for i, event in enumerate(preceding) if event[0] == "read_return")
            self.assertGreater(final_fstat, last_read)
            self.assertEqual(preceding[-1], ("fstat_return", 22))

    def test_owner_pid_or_thread_change_skips_all_owned_closes(self):
        for field in ("pid", "thread"):
            with self.subTest(field=field), Native() as native:
                with self.assertRaises(ValueError):
                    with fixture.owned_http_fixture(EXPECTED):
                        setattr(native, field, 5001)
                self.assertEqual(native.held_closes(), [])

    def test_owner_change_during_cleanup_fdinfo_read_skips_all_remaining_resources(self):
        with Native() as native:
            primary = RuntimeError("fabricated caller failure")
            with self.assertRaises(RuntimeError) as caught:
                with fixture.owned_http_fixture(EXPECTED) as session:
                    def hook(*event):
                        if event[0] == "read_return":
                            native.pid = native.thread = 5001
                    self.arm_cleanup(session, native, hook)
                    raise primary
            self.assertIs(caught.exception, primary)
            self.assertEqual(native.held_closes(), [])
            self.assertIn(CLOSE, primary.__notes__)

    def test_namespace_cleanup_detects_owner_change_during_link_read(self):
        with Native() as native:
            def hook(*event):
                if event == ("readlink_return", "/proc/self/fd/21"):
                    native.thread = 5001
            with self.assertRaisesRegex(ValueError, CLOSE):
                with fixture.owned_http_fixture(EXPECTED) as session:
                    self.arm_cleanup(session, native, hook)
            self.assertEqual(native.held_closes(), [22])

    def test_pidfd_cleanup_fdinfo_unavailable_skips_pidfd_only(self):
        with Native() as native:
            def hook(*event):
                if event[:2] == ("open", "/proc/self/fdinfo/22"):
                    raise OSError("fabricated unavailable association")
            with self.assertRaisesRegex(ValueError, CLOSE):
                with fixture.owned_http_fixture(EXPECTED) as session:
                    self.arm_cleanup(session, native, hook)
            self.assertEqual(native.held_closes(), [21, 20])

    def test_cleanup_temp_close_first_interruption_preserves_original(self):
        for interruption in (KeyboardInterrupt(), SystemExit(3), MemoryError()):
            with self.subTest(kind=type(interruption).__name__), Native() as native:
                def hook(*event):
                    if event[0] == "close" and event[1] >= 100:
                        raise interruption
                with self.assertRaises(type(interruption)) as caught:
                    with fixture.owned_http_fixture(EXPECTED) as session:
                        self.arm_cleanup(session, native, hook)
                self.assertIs(caught.exception, interruption)
                self.assertIn(CLOSE, interruption.__notes__)
                self.assertEqual(native.held_closes(), [21, 20])

    def test_cleanup_dual_fault_preserves_outer_primary_or_first_interruption(self):
        for caller_failure in (False, True):
            for read_interrupted in (False, True):
                for interruption_type in (KeyboardInterrupt, SystemExit, MemoryError):
                    with self.subTest(caller=caller_failure, read_interrupted=read_interrupted,
                                      cleanup=interruption_type.__name__), Native() as native:
                        caller = RuntimeError("fabricated caller failure") if caller_failure else None
                        read_error = KeyboardInterrupt() if read_interrupted else OSError("fabricated cleanup read failure")
                        close_error = interruption_type()
                        expected = caller if caller is not None else read_error if read_interrupted else close_error
                        def hook(*event):
                            if event[0] == "read":
                                raise read_error
                            if event[0] == "close" and event[1] >= 100:
                                raise close_error
                        with self.assertRaises(type(expected)) as caught:
                            with fixture.owned_http_fixture(EXPECTED) as session:
                                self.arm_cleanup(session, native, hook)
                                if caller is not None:
                                    raise caller
                        self.assertIs(caught.exception, expected)
                        self.assertIn(CLOSE, expected.__notes__)
                        self.assertEqual(native.held_closes(), [21, 20])
                        self.assertEqual(native.order.count(("close", native.next_proc - 1)), 1)
                        self.assertNotIn(FINAL, getattr(expected, "__notes__", ()))

    def test_ambiguous_close_is_not_retried_and_remaining_resources_close(self):
        with Native() as native:
            def hook(*event):
                if event == ("close", 22):
                    raise OSError("fabricated ambiguous close")
            native.hook = hook
            with self.assertRaisesRegex(ValueError, CLOSE):
                with fixture.owned_http_fixture(EXPECTED):
                    pass
            self.assertEqual(native.order.count(("close", 22)), 1)
            self.assertEqual(native.held_closes(), [21, 20])

    def test_primary_error_survives_final_guard_and_cleanup_failures(self):
        for primary in (RuntimeError("fabricated primary"), KeyboardInterrupt(), SystemExit(9), MemoryError()):
            with self.subTest(kind=type(primary).__name__), Native() as native:
                with self.assertRaises(type(primary)) as caught:
                    with fixture.owned_http_fixture(EXPECTED):
                        native.rows[21].st_ino = 99
                        raise primary
                self.assertIs(caught.exception, primary)
                self.assertIn(FINAL, primary.__notes__)
                self.assertIn(CLOSE, primary.__notes__)
                self.assertEqual(native.held_closes(), [22, 20])

    def test_cleanup_first_interruption_survives_and_remaining_closes_continue(self):
        for primary in (KeyboardInterrupt(), SystemExit(9), MemoryError()):
            with self.subTest(kind=type(primary).__name__), Native() as native:
                def hook(*event):
                    if event == ("close", 22):
                        raise primary
                native.hook = hook
                with self.assertRaises(type(primary)) as caught:
                    with fixture.owned_http_fixture(EXPECTED):
                        pass
                self.assertIs(caught.exception, primary)
                self.assertIn(CLOSE, primary.__notes__)
                self.assertEqual(native.held_closes(), [21, 20])
                self.assertEqual(native.order.count(("close", 22)), 1)

    def test_proc_read_is_bounded_and_its_temporary_descriptors_close(self):
        with Native() as native:
            native.fdinfo_raw = b"x" * 4097
            with self.assertRaisesRegex(ValueError, CLOSE):
                with fixture.owned_http_fixture(EXPECTED):
                    self.fail("must not yield")
            self.assertEqual(native.held_closes(), [21, 20])
            self.assertEqual([event[2] for event in native.order if event[0] == "read"], [4097])
            self.assertTrue(any(fd >= 100 for fd in native.closed))

    def test_unknown_proc_descriptor_metadata_is_never_closed(self):
        with Native() as native:
            failure = OSError("fabricated temporary metadata failure")
            def hook(*event):
                if event[0] == "fstat" and event[1] >= 100:
                    raise failure
            native.hook = hook
            with self.assertRaises(OSError) as caught:
                with fixture.owned_http_fixture(EXPECTED):
                    self.fail("must not yield")
            self.assertIs(caught.exception, failure)
            self.assertEqual(native.held_closes(), [21, 20])
            self.assertFalse(any(fd >= 100 for fd in native.closed))
            self.assertIn(CLOSE, failure.__notes__)

    def test_proc_temporary_replacement_during_read_is_not_closed(self):
        with Native() as native:
            def hook(*event):
                if event[0] == "read_return":
                    native.rows[event[1]].st_ino += 1
            native.hook = hook
            with self.assertRaisesRegex(ValueError, CLOSE) as caught:
                with fixture.owned_http_fixture(EXPECTED):
                    self.fail("must not yield")
            self.assertEqual(native.held_closes(), [21, 20])
            self.assertFalse(any(fd >= 100 for fd in native.closed))
            self.assertIn(CLOSE, caught.exception.__notes__)

    def test_proc_close_failure_preserves_primary_and_does_not_retry(self):
        with Native() as native:
            original = KeyboardInterrupt()
            def hook(*event):
                if event[0] == "read":
                    raise original
                if event[0] == "close" and event[1] >= 100:
                    raise OSError("fabricated temporary close failure")
            native.hook = hook
            with self.assertRaises(KeyboardInterrupt) as caught:
                with fixture.owned_http_fixture(EXPECTED):
                    self.fail("must not yield")
            self.assertIs(caught.exception, original)
            self.assertIn(CLOSE, original.__notes__)
            temp_closes = [event for event in native.order if event[0] == "close" and event[1] >= 100]
            self.assertEqual(len(temp_closes), 1)
            self.assertEqual(native.held_closes(), [21, 20])
