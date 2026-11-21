"""Inert proc handles and admitted directories. Nothing executes, opens a device or walks a real root."""
from contextlib import ExitStack
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from aragorn import pi_core_stopped_worker_walk as spine
from tests.test_pi_core_stopped_mask_view import Kernel


VERSION = spine._VERSIONS / "sum" / ("a" * 64 + "-" + "b" * 64)


class SpineKernel(Kernel):
    def __init__(self):
        super().__init__()
        self.task_numbers, self.fd_numbers = ["73"], ["0", "1", "2"]
        self.stdio, self.cwd = dict(mode=stat.S_IFCHR | 0o666, dev="0:9", ino=11, mnt_id=6, rdev="1:3"), {}
        self.name_scans = []

    def metadata(self, fd, owner=False):
        s = super().metadata(fd, owner=owner)
        path, flags = self.fds[fd], self.flags[fd]
        if path == "/proc/73/cwd" and flags & self.O_NOFOLLOW:
            return s | {"mode":stat.S_IFLNK | 0o777}
        if path == "/proc/73/cwd" or path == self.ROOT + str(VERSION):
            return s | dict(mode=stat.S_IFDIR | 0o555, dev="8:4", ino=77, mnt_id=31) | (self.cwd if path.endswith("/cwd") else {}) | self.pinned[fd]
        if path in ("/proc/73/fd/0", "/proc/73/fd/1", "/proc/73/fd/2") and not flags & self.O_NOFOLLOW:
            return s | self.stdio | self.pinned[fd]
        return s

    def names(self, fd, deadline, limit):
        path = self.fds[fd]
        self.name_scans.append(path)
        if path not in ("/proc/73/task", "/proc/73/fd"):
            return super().names(fd, deadline, limit)
        data = self.task_numbers if path.endswith("/task") else self.fd_numbers
        if len(data) > limit:
            raise ValueError("unbounded directory")
        return data.copy()

    def install(self, scope):
        super().install(scope)
        scope.enter_context(patch.object(spine, "os", self))
        scope.enter_context(patch.object(spine, "time", spine.kernel.time))


def hold():
    return spine.kernel.hold_stopped_mask_view(pid=73, start_ticks=1173, deadline=14)


class StoppedWorkerSpineTests(unittest.TestCase):
    def test_records_only_the_two_kernel_handle_censuses_and_exact_cwd_on_its_mount(self):
        with ExitStack() as scope:
            k = SpineKernel()
            k.install(scope)
            with hold() as view:
                k.calls.clear()
                k.name_scans.clear()
                with spine.hold_worker_spine(view, admitted_path=VERSION, deadline=14) as finish:
                    probe_moment = k.clock(None)
                    doc = finish()
                self.assertEqual(set(k.name_scans), {"/proc/73/task", "/proc/73/fd"})
                for path, flags in k.calls:
                    if path.startswith(k.ROOT + "/"):
                        self.assertEqual(flags, k.O_PATH | k.O_DIRECTORY | k.O_NOFOLLOW | k.O_CLOEXEC)
                    if path in ("/proc/73/fd/0", "/proc/73/fd/1", "/proc/73/fd/2"):
                        self.assertTrue(flags & k.O_PATH)
                        self.assertFalse(flags & k.O_RDONLY)
                mask, _, _ = view.finish()
            self.assertFalse(k.fds)
            self.assertEqual(doc["schema"], "aragorn/pi-core-stopped-worker-spine/v1")
            self.assertNotIn("tree", doc)
            self.assertEqual(doc["worker"], mask["worker"])
            self.assertEqual(doc["admitted_path"], str(VERSION))
            self.assertEqual(doc["before"], doc["after"])
            self.assertEqual(doc["before"]["fd_numbers"], [0,1,2])
            self.assertEqual(doc["before"]["task_ids"], [73])
            self.assertLess(mask["opened_boottime_ns"], doc["opened_boottime_ns"])
            self.assertLess(doc["opened_boottime_ns"], probe_moment)
            self.assertLess(probe_moment, doc["closed_boottime_ns"])
            self.assertLess(doc["closed_boottime_ns"], mask["closed_boottime_ns"])
            obj = doc["objects"]["before"]
            self.assertEqual(obj, doc["objects"]["after"])
            self.assertEqual(obj["root"], mask["worker_root"])
            self.assertEqual(obj["cwd"], obj["named_cwd"])
            self.assertEqual(obj["cwd"]["mnt_id"], 31)
            self.assertEqual(obj["fds"], {str(n):k.stdio for n in range(3)})

    def test_inherited_replaced_unknown_or_unstable_objects_never_yield_a_spine(self):
        for name, change in (
                ("extra descriptor", lambda k:k.fd_numbers.append("9")),
                ("missing descriptor", lambda k:k.fd_numbers.pop(0)),
                ("other task", lambda k:k.task_numbers.__setitem__(0, "74")),
                ("stale gate", lambda k:setattr(k, "tick", 1174)),
                ("resumed", lambda k:setattr(k, "state", "S")),
                ("not null", lambda k:k.stdio.update(rdev="1:5")),
                ("swapped earlier null object", lambda k:k.renamed.update({"/proc/73/fd/0":{"ino":9}})),
                ("different cwd bind", lambda k:k.cwd.update(mnt_id=32)),
                ("replaced intermediate", lambda k:k.renamed.update({k.ROOT+str(VERSION.parent):{"ino":99}})),
                ("expired", lambda k:setattr(k, "now", 14))):
            with self.subTest(name=name), ExitStack() as scope:
                k = SpineKernel()
                k.install(scope)
                with self.assertRaises(ValueError):
                    with hold() as view, spine.hold_worker_spine(view, admitted_path=VERSION, deadline=14) as finish:
                        change(k)
                        finish()
                self.assertFalse(k.fds)

    def test_rejects_nonversion_paths_deadline_extensions_and_unfinished_or_reused_scopes(self):
        with ExitStack() as scope:
            k = SpineKernel()
            k.install(scope)
            for path in (Path("/tmp"), VERSION / "SKILL.md", VERSION.parent / "latest",
                         spine._VERSIONS / "UPPERCASE" / VERSION.name):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    with hold() as view, spine.hold_worker_spine(view, admitted_path=path, deadline=14):
                        self.fail("unexpected path accepted")
            with self.assertRaises(ValueError):
                with hold() as view, spine.hold_worker_spine(view, admitted_path=VERSION, deadline=15):
                    self.fail("extended deadline accepted")
            with self.assertRaisesRegex(ValueError, "not completed"):
                with hold() as view, spine.hold_worker_spine(view, admitted_path=VERSION, deadline=14):
                    pass
            with hold() as view:
                with spine.hold_worker_spine(view, admitted_path=VERSION, deadline=14) as finish:
                    finish()
                    with self.assertRaisesRegex(ValueError, "spent"):
                        finish()
                view.finish()
            self.assertFalse(k.fds)
