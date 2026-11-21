"""The kernel here is an inert table of fixed objects; no task or namespace is opened."""
from collections import Counter
from contextlib import ExitStack
from types import SimpleNamespace
import stat
import struct
import unittest
from unittest.mock import patch

from aragorn import pi_core_stopped_mask_view as m


class Kernel:
    O_CLOEXEC, O_NOFOLLOW, O_RDONLY, O_DIRECTORY, O_NOATIME, O_PATH = 1, 2, 4, 8, 16, 32
    ROOT = "/proc/73/root"
    MAN = "/proc/23/root"
    SOURCE = MAN + "/run/systemd/inaccessible/dir"

    def __init__(self):
        self.fds, self.flags, self.calls, self.next = {}, {}, [], 10
        # Unlike a mutable name, an already-held directory descriptor continues to
        # refer to the object pinned at open time if the path is later retargeted.
        self.renamed, self.pinned, self.missing = {}, {}, set()
        self.now, self.boot, self.tick = 10, 1000, 1173
        self.dev_names, self.source_entries, self.link = ["null", "ptmx", "pts", "shm"], [], "pts/ptmx"
        self.changed, self.state, self.cap, self.count = {}, "t", 0, 1
        self.mounts = {73: b"worker rows\n", 23: b"manager rows\n", 24: b"manager rows\n"}
        self.tid, self.thread_tgid, self.thread_mnt, self.thread_userns = 24, 23, 601, 801

    def open(self, name, flags, dir_fd=None):
        path = name if dir_fd is None else self.fds[dir_fd] + "/" + name
        self.calls.append((path, flags))
        if path in self.missing:
            raise FileNotFoundError(path)
        self.next += 1
        self.fds[self.next] = path.removesuffix("/.")
        self.flags[self.next] = flags
        self.pinned[self.next] = self.renamed.get(path, {}).copy()
        return self.next

    def close(self, fd):
        del self.fds[fd]
        del self.flags[fd]
        del self.pinned[fd]

    def getpid(self):
        return 23

    def fstat(self, fd):
        path = self.fds[fd]
        if path.startswith("/proc/23/task/24/ns/"):
            return SimpleNamespace(st_ino=self.thread_mnt if path.endswith("/mnt") else self.thread_userns)
        manager = path.startswith("/proc/23/")
        return SimpleNamespace(st_ino=(601 if manager else 602) if path.endswith("/mnt") else 801)

    def readlink(self, name, *, dir_fd):
        assert name == "" and self.fds[dir_fd] == self.ROOT + "/dev/ptmx"
        return self.link

    def metadata(self, fd, owner=False):
        path = self.fds[fd]
        result = dict(mode=stat.S_IFDIR | 0o555, dev="0:1", ino=1, rdev="0:0", mnt_id=1)
        if (path.endswith("/root") or "/ns/" in path or "/fd/" in path) and self.flags[fd] & self.O_NOFOLLOW:
            return {**result, "mode": stat.S_IFLNK | 0o777}
        if path == self.MAN + "/run" or path.startswith(self.MAN + "/run/"):
            result.update(dev="0:21", mnt_id=33)
        if path.endswith("/root"):
            result.update(dev="8:1", ino=3, mnt_id=44)
        if path.endswith("/dev") or "/fd/" in path:
            result.update(dev="0:11", ino=2, mnt_id=7)
        if path == self.SOURCE or path in (self.ROOT + "/dev/pts", self.ROOT + "/dev/shm"):
            result.update(mode=stat.S_IFDIR, dev="0:21", ino=52,
                          mnt_id=33 if path == self.SOURCE else (36 if path.endswith("/pts") else 39))
        if path.endswith("/ptmx"):
            result.update(mode=stat.S_IFLNK | 0o777, dev="0:11", ino=57, mnt_id=7)
        ids = {m.ANCHOR: (100, 70), m.ANCHOR + m.ACTION: (101, 70), m.ANCHOR + m.PROVIDER: (102, 70),
               m.ACTION: (101, 71), m.PROVIDER: (102, 72)}
        if path.removeprefix(self.MAN) in ids:
            ino, mid = ids[path.removeprefix(self.MAN)]
            result.update(mode=stat.S_IFDIR | 0o700, dev="8:2", ino=ino, mnt_id=mid)
        if owner:
            result.update(uid=0, gid=0)
        return {**result, **self.changed.get(path, {}), **self.pinned[fd]}

    def read(self, proc, name, maximum, mount, deadline):
        pid = int(self.fds[proc].split("/")[-1])
        if name == "mountinfo":
            return self.mounts[pid]
        if name == "stat":
            fields = ["S" if pid != 73 else self.state, "23", *(["0"] * 17), str(self.tick if pid == 73 else 1100 + pid)]
            return (str(pid) + " (private ) gate) " + " ".join(fields) + "\n").encode()
        assert name == "status"
        uid = 0 if pid in (23, 24) else 40
        fields = dict(Pid=pid, Tgid=self.thread_tgid if pid == 24 else pid,
                      PPid=23, Threads=self.count, Groups="", NoNewPrivs=1,
                      Uid=" ".join([str(uid)] * 4), Gid=" ".join([str(uid)] * 4),
                      State=("S" if pid != 73 else self.state) + " (state)",
                      **{key: format(self.cap if key == "CapPrm" else 0, "016x") for key in m._CAPS})
        return "".join(f"{key}:\t{value}\n" for key, value in fields.items()).encode()

    def names(self, fd, deadline, limit):
        entries = self.source_entries if self.fds[fd] == self.SOURCE else self.dev_names
        if len(entries) > limit:
            raise ValueError("unbounded directory")
        return list(entries)

    def clock(self, _):
        self.boot += 10
        return self.boot

    def install(self, s):
        for k, v in (("os", self), ("_platform", lambda: None), ("_stat", self.metadata), ("_read", self.read),
                     ("threading", SimpleNamespace(get_native_id=lambda: self.tid)),
                     ("_names", self.names), ("_filesystem", lambda fd: m._PROC if self.fds[fd] == "/proc" else
                                              m._NSFS if "/ns/" in self.fds[fd] else m._TMPFS),
                     ("time", SimpleNamespace(monotonic=lambda: self.now, clock_gettime_ns=self.clock, CLOCK_BOOTTIME=7))):
            s.enter_context(patch.object(m, k, v))


class KernelMaskViewTests(unittest.TestCase):
    def setUp(self):
        self.scope, self.k = ExitStack(), Kernel()
        self.addCleanup(self.scope.close)
        self.k.install(self.scope)

    def hold(self):
        return m.hold_stopped_mask_view(pid=73, start_ticks=1173, deadline=14)

    def test_open_and_close_same_fixed_kernel_objects_without_permission_claim(self):
        with self.hold() as v:
            self.assertEqual(v.names, ("ptmx", "pts", "shm"))
            self.assertEqual(v.worker_context()["fsuid"], 40)
            v.worker["pid"] = 99  # only a copy
            record, worker, manager = v.finish()
            self.assertEqual(record["worker"]["pid"], 73)
            with self.assertRaises(ValueError):
                v.finish()
        self.assertFalse(self.k.fds)
        self.assertEqual((worker, manager), (b"worker rows\n", b"manager rows\n"))
        self.assertEqual(record["source"]["before"], record["source"]["path_after"])
        self.assertEqual(record["schema"], "aragorn/pi-core-stopped-mask-view/v2")
        before = record["manager_state"]["before"]
        self.assertEqual(set(record["manager_state"]), {"before", "after"})
        self.assertEqual(record["manager_state"]["after"], before)
        self.assertEqual(set(before), {"sources", "targets"})
        self.assertEqual(set(before["sources"]), {m.ANCHOR, m.ACTION, m.PROVIDER})
        self.assertEqual(set(before["targets"]), {m.ACTION, m.PROVIDER})
        for side, expectations in (("sources", {m.ANCHOR: (100, 70), m.ACTION: (101, 70), m.PROVIDER: (102, 70)}),
                                   ("targets", {m.ACTION: (101, 71), m.PROVIDER: (102, 72)})):
            for name, (ino, mount_id) in expectations.items():
                self.assertEqual(before[side][name], dict(dev="8:2", ino=ino, rdev="0:0", uid=0, gid=0,
                                                          mode=stat.S_IFDIR | 0o700, mnt_id=mount_id))
                path = self.k.MAN + (m.ANCHOR if side == "sources" and name != m.ANCHOR else "") + name
                flags = [flags for n, flags in self.k.calls if n == path]
                self.assertEqual(flags, [self.k.O_NOFOLLOW | self.k.O_DIRECTORY | self.k.O_PATH | self.k.O_CLOEXEC] * 3)
        self.assertEqual(record["ptmx"]["readlink_after"], "pts/ptmx")
        self.assertEqual(set(record["directories"]["/dev/pts"]), {"before", "after"})
        self.assertEqual(record["dev_names"], ["null", "ptmx", "pts", "shm"])
        for path, flags in self.k.calls:
            if path.startswith(self.k.MAN + "/") or path.startswith(self.k.ROOT + "/"):
                self.assertTrue(flags & self.k.O_NOFOLLOW, path)
        self.assertFalse(any("/dev/pts/" in p or "/dev/null" in p for p, _ in self.k.calls))
        with self.assertRaises(ValueError):
            v.worker_context()

    def test_replaced_volume_mount_link_or_state_refuses_and_closes_all_handles(self):
        for key, change in (("directory", lambda: self.k.dev_names.remove("shm")),
                            ("source identity", lambda: self.k.changed.update({self.k.SOURCE: {"ino": 103}})),
                            ("mountinfo", lambda: self.k.mounts.update({73: b"changed\n"})),
                            ("target mount", lambda: self.k.changed.update({self.k.ROOT + "/dev/pts": {"mnt_id": 67}})),
                            ("link", lambda: setattr(self.k, "link", "other")),
                            ("generation", lambda: setattr(self.k, "tick", 1174)),
                            ("resumed", lambda: setattr(self.k, "state", "S")),
                            ("retained capabilities", lambda: setattr(self.k, "cap", 2)),
                            ("extra task", lambda: setattr(self.k, "count", 2)),
                            ("deadline", lambda: setattr(self.k, "now", 14))):
            with self.subTest(key=key), ExitStack() as inner:
                self.k = Kernel()
                self.k.install(inner)
                with self.assertRaises(ValueError):
                    with self.hold() as v:
                        change()
                        v.finish()
                self.assertFalse(self.k.fds)

    def test_no_partial_or_swallowed_failed_finish(self):
        with self.assertRaisesRegex(ValueError, "not finished"):
            with self.hold():
                pass
        with self.assertRaisesRegex(ValueError, "not finished"):
            with self.hold() as v:
                self.k.source_entries.append("unexpected")
                with self.assertRaises(ValueError):
                    v.finish()
        self.assertFalse(self.k.fds)

    def test_replaced_source_bind_or_intermediate_refuses_even_while_original_descriptors_remain_valid(self):
        for name, change in ((m.ANCHOR + m.ACTION, {"ino": 999}), (m.PROVIDER, {"mnt_id": 999}),
                             (m.ANCHOR + "/var/lib", {"ino": 999})):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "held and named manager state paths differ"):
                    with self.hold() as view:
                        self.k.renamed[self.k.MAN + name] = change
                        view.finish()
                self.assertFalse(self.k.fds)
                self.k.renamed.clear()

    def test_missing_manager_path_does_not_allow_partial_observation(self):
        self.k.missing.add(self.k.MAN + m.ANCHOR + m.PROVIDER)
        with self.assertRaises(FileNotFoundError):
            with self.hold():
                self.fail("missing source must not open a usable view")
        self.assertFalse(self.k.fds)

    def test_capture_thread_must_observe_the_manager_view_and_remain_in_its_task_group(self):
        for label, change in (("thread switched", lambda: setattr(self.k, "tid", 25)),
                              ("wrong tgid", lambda: setattr(self.k, "thread_tgid", 24)),
                              ("separate mount namespace", lambda: setattr(self.k, "thread_mnt", 888)),
                              ("separate user namespace", lambda: setattr(self.k, "thread_userns", 999)),
                              ("different root", lambda: self.k.changed.update({"/proc/23/task/24/root": {"ino": 88}})),
                              ("different mountinfo", lambda: self.k.mounts.update({24: b"other view\n"}))):
            with self.subTest(label=label), ExitStack() as local:
                self.k = Kernel()
                self.k.install(local)
                with self.assertRaises(ValueError):
                    with self.hold() as view:
                        change()
                        view.finish()
                self.assertFalse(self.k.fds)

    def test_child_context_is_read_twice_and_dev_fd_is_that_childs(self):
        ctx, dev = m._probe_frame(83, 7, 14)
        self.assertEqual((ctx["pid"], ctx["start_ticks"], ctx["uid"], dev["mnt_id"]), (83, 1183, 40, 7))
        self.assertEqual(Counter(p for p, flags in self.k.calls if not flags & self.k.O_NOFOLLOW)["/proc/83/fd/7"], 2)
        self.assertFalse(self.k.fds)
        with self.assertRaises(ValueError):
            m._probe_frame(23, 7, 14)

    def test_statx_uses_returned_mask_and_full_64bit_inode_mount_id(self):
        raw = bytearray(256)
        struct.pack_into("=I", raw, 0, 0x111b)
        struct.pack_into("=IIH", raw, 0x14, 7, 8, stat.S_IFDIR)
        struct.pack_into("=Q", raw, 0x20, 1 << 42)
        struct.pack_into("=IIIIQ", raw, 0x80, 0, 0, 0, 28, 1 << 35)
        self.assertEqual(m._decode_stat(bytes(raw), True),
                         dict(uid=7, gid=8, mode=stat.S_IFDIR, ino=1 << 42, dev="0:28", rdev="0:0", mnt_id=1 << 35))
        struct.pack_into("=I", raw, 0, 0x11b)
        with self.assertRaises(ValueError):
            m._decode_stat(bytes(raw), True)
