"""B79: fake kernel objects only. No actual proc, sysfs, block or control node."""
from contextlib import ExitStack, nullcontext
from copy import deepcopy
import errno
import hashlib
import json
import os
import stat
import unittest
from unittest.mock import patch

from aragorn import pi_core_state_backing_leaf as leaf


_TARGET = b"../../devices/platform/private-asset/block/drive"
_RAW = (b"1 99 7:0 / / ro - squashfs /dev/root ro\n"
        b"82 1 0:50 / /sys rw,nosuid,nodev,noexec - sysfs sysfs rw\n")


def sample_leaf(device="259:0", diskseq=19):
    major, minor = device.split(":")
    before = dict(dev=device+"\n", diskseq=f"{diskseq}\n",
                  uevent=f"MAJOR={major}\nMINOR={minor}\nDEVTYPE=disk\nDISKSEQ={diskseq}\n",
                  sysfs_mount_id=82, sysfs_device="0:50", inodes=list(range(11, 24)),
                  target_sha256=hashlib.sha256(_TARGET).hexdigest(), partition_errno=2, slaves_eof=True)
    return dict(schema="aragorn/pi-core-sysfs-backing-leaf/v1", before=before, after=deepcopy(before))


class Model:
    def __init__(self):
        self.at = None
        self.changed = False
        self.target = _TARGET
        self.map = {(10, "sys"): 11, (11, "dev"): 12, (12, "block"): 13, (13, "259:0"): 14,
                    (11, "devices"): 15, (15, b"platform"): 16, (16, b"private-asset"): 17,
                    (17, b"block"): 18, (18, b"drive"): 19, (19, "dev"): 20, (19, "diskseq"): 21,
                    (19, "uevent"): 22, (19, "slaves"): 23}
        self.raw, self.magic = _RAW, 0x62656572
        self.parts, self.slaves = errno.ENOENT, []
        self.stats, self.opened, self.read_at, self.masks = {}, [], {}, {}
        self.data = {20: b"259:0\n", 21: b"19\n", 22: b"MAJOR=259\nMINOR=0\nDEVNAME=private-name\n"
                     b"DEVTYPE=disk\nSERIAL=private-serial\nDISKSEQ=19\n"}
        self.ops = []
        self.root = {"root": "held", "uid": 0}
        self.vary = None

    def _pin(self, stack, parent, name, *, directory=False):
        self.ops.append(("pin", parent, name, directory))
        if name == "partition":
            if self.parts:
                raise OSError(self.parts, "not available", "private-asset")
            return 27
        return self.map[parent, name]

    def _stat(self, fd, owner=False):
        ident = self.masks.get(fd, fd)
        kind = stat.S_IFLNK if ident == 14 else (stat.S_IFREG if ident in self.data else stat.S_IFDIR)
        return dict(uid=0, gid=0, ino=ident, mnt_id=1 if ident == 10 else 82,
                    dev="7:0" if ident == 10 else "0:50", mode=kind | (0o777 if ident == 14 else 0o755),
                    rdev="0:0") | self.stats.get(ident, {})

    def _frame(self, stack, who, pm, deadline, *, kind):
        if kind == "manager":
            if self.at is not None and self.vary:
                self.vary()
            self.at = True
        return None, self.root.copy(), 10, {}

    def _open(self, stack, fds, name, flags, mount):
        ident = int(name)
        assert ident in (20, 21, 22, 23) and fds == 41 and mount == 7
        assert flags == os.O_RDONLY | os.O_NONBLOCK | (os.O_DIRECTORY if ident == 23 else 0)
        self.opened.append(ident)
        fd = 50 + len(self.opened)
        self.masks[fd], self.read_at[fd] = ident, 0
        return fd

    def _read(self, fd, bound):
        data, pos = self.data[self.masks[fd]], self.read_at[fd]
        part = data[pos:pos+bound]
        self.read_at[fd] += len(part)
        return part

    def _link(self, name, *, dir_fd):
        assert name == b"" and dir_fd == 14
        return self.target

    def enter(self, st):
        for method, cb in (("_platform", lambda: None), ("_check", lambda d: self.ops.append(("time", d))),
                           ("_proc", lambda stack: (40, 7)), ("_role", lambda stack, parent, pid, pm: (pid, 37)),
                           ("_proc_child", lambda *args: 41), ("_frame", self._frame), ("_filesystem", lambda fd: self.magic),
                           ("_read", lambda *args: self.raw), ("_pin", self._pin), ("_magic", self._open),
                           ("_stat", self._stat)):
            st.enter_context(patch.object(leaf.kernel, method, side_effect=cb))
        st.enter_context(patch.object(leaf.os, "getpid", return_value=123))
        st.enter_context(patch.object(leaf.threading, "get_native_id", return_value=124))
        st.enter_context(patch.object(leaf.os, "readlink", side_effect=self._link))
        st.enter_context(patch.object(leaf.os, "read", side_effect=self._read))
        return st.enter_context(patch.object(leaf.os, "scandir", side_effect=lambda fd: nullcontext(iter(self.slaves))))

    def run(self):
        with ExitStack() as st:
            self.enter(st)
            return leaf.capture_backing_leaf("259:0", deadline=88)


class BackingLeaf(unittest.TestCase):
    def test_complete_bounded_walk_and_public_replay(self):
        k = Model()
        record = k.run()
        self.assertEqual(record, sample_leaf())
        self.assertEqual(leaf.verify_backing_leaf(record, expected_backing_device="259:0"),
                         {"device": "259:0", "diskseq": 19})
        self.assertEqual(k.opened, [20, 21, 22, 23] * 2)
        self.assertTrue(all(x[1] == 88 for x in k.ops if x[0] == "time"))
        self.assertNotIn("private", json.dumps(record))
        self.assertNotIn("DEVNAME", json.dumps(record))

    def test_rejects_arbitrary_device_before_kernel_access(self):
        with patch.object(leaf.kernel, "_platform") as touched:
            for name in ("/dev/other", "0:0", "0259:0", "259:00", "8:1048576", "../8:0", None):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    leaf.capture_backing_leaf(name, deadline=1)
        touched.assert_not_called()

    def test_only_canonical_relative_target_under_devices(self):
        for path in (b"/sys/devices/pci", b"../../block/sda", b"../devices/a", b"../../../devices/a",
                     b"../../devices/", b"../../devices//a", b"../../devices/./a", b"../../devices/a/../b",
                     b"../../devices/a\0b", b"../../devices/a\nb", b"../../devices/"+b"/".join([b"a"]*33),
                     b"../../devices/"+b"x"*256, b"../../devices/"+b"a/"*2500):
            with self.subTest(path=path[:25]), self.assertRaises(ValueError):
                leaf._target(path)
        self.assertEqual(leaf._target(b"../../devices/platform/pci:00/other"), [b"platform", b"pci:00", b"other"])

    def test_rejects_substituted_sysfs_root_overmount_link_attribute_and_reopen(self):
        for ident, delta in ((10, {"mode": stat.S_IFDIR|0o777}), (10, {"uid": 10}), (10, {"mnt_id": 3}),
                (11, {"dev": "0:5"}), (12, {"uid": 1}), (13, {"gid": 1}), (14, {"mode": stat.S_IFREG|0o444}),
                (16, {"mnt_id": 4}), (17, {"mode": stat.S_IFLNK|0o777}), (20, {"mode": stat.S_IFBLK}),
                (21, {"mode": stat.S_IFREG|0o666}), (22, {"mode": stat.S_IFCHR}), (23, {"mode": stat.S_IFLNK})):
            k = Model()
            k.stats[ident] = delta
            with self.subTest(ident=ident, delta=delta), self.assertRaises(ValueError):
                k.run()
        for opts in ("not sysfs", "wrong magic", "shifted root", "different fd"):
            k = Model()
            if opts == "not sysfs":
                k.raw = k.raw.replace(b"- sysfs", b"- tmpfs")
            elif opts == "wrong magic":
                k.magic = 123
            elif opts == "shifted root":
                k.raw = k.raw.replace(b"0:50 / /sys", b"0:50 /sub /sys")
            else:
                k._open = lambda *a: 63
            with self.subTest(opts=opts), self.assertRaises(ValueError):
                k.run()

    def test_absence_needs_enoent_and_complete_empty_directory(self):
        for problem in (0, errno.EACCES, errno.ENOTDIR, errno.ENODEV, errno.EIO, "one slave", "unreadable slaves"):
            k = Model()
            if problem == "one slave":
                k.slaves = [object()]
            elif problem != "unreadable slaves":
                k.parts = problem
            with ExitStack() as st:
                scan = k.enter(st)
                if problem == "unreadable slaves":
                    scan.side_effect = OSError(errno.EACCES, "blocked", "private-slave")
                with self.subTest(problem=problem), self.assertRaises((OSError, ValueError)) as err:
                    leaf.capture_backing_leaf("259:0", deadline=88)
                self.assertNotIn("private", str(err.exception))

    def test_raw_attributes_must_match_complete_uevent_without_private_data(self):
        for key, data in ((20, b"259:1\n"), (20, b"259:0"), (21, b"0\n"), (21, b"019\n"),
                 (21, b"18446744073709551616\n"), (21, b"19\n20\n"), (21, b"9"*35+b"\n"),
                 (22, b"MAJOR=259\nMINOR=0\nDEVTYPE=disk\n"), (22, b"A"*4097),
                 (22, b"MAJOR=259\nMINOR=2\nDEVTYPE=disk\nDISKSEQ=19\n"),
                 (22, b"MAJOR=259\nMINOR=0\nDEVTYPE=partition\nDISKSEQ=19\n"),
                 (22, b"MAJOR=259\nMINOR=0\nDEVTYPE=disk\nDISKSEQ=18\n"),
                 (22, b"MAJOR=259\nMAJOR=259\nMINOR=0\nDEVTYPE=disk\nDISKSEQ=19\n")):
            k = Model()
            k.data[key] = data
            with self.subTest(key=key, data=data[:12]), self.assertRaises(ValueError):
                k.run()

    def test_pins_incarnation_path_and_manager_context_across_both_walks(self):
        for field in ("diskseq", "ancestor", "manager", "target", "root", "slaves now present"):
            k = Model()
            def change():
                if field == "diskseq":
                    k.data[21] = b"20\n"
                    k.data[22] = k.data[22].replace(b"19\n", b"20\n")
                elif field == "ancestor":
                    k.stats[17] = {"ino": 222}
                elif field == "manager":
                    k.root["uid"] = 99
                elif field == "target":
                    k.target = _TARGET.replace(b"private-asset", b"replacement")
                    k.map[16, b"replacement"] = 17
                elif field == "root":
                    k.stats[10] = {"ino": 42}
                else:
                    k.slaves = [object()]
            k.vary = change
            with self.subTest(field=field), self.assertRaises(ValueError):
                k.run()

    def test_replay_rejects_unbounded_extra_private_or_self_reported_fields(self):
        for changes in ({"PASS": True}, {"uevent": sample_leaf()["before"]["uevent"]+"SERIAL=private\n"},
                        {"inodes": [9]*10}, {"inodes": list(range(1, 46))}, {"inodes": [True]*10},
                        {"sysfs_mount_id": False}, {"target_sha256": "a"*65}, {"sysfs_device": "259:0"},
                        {"slaves_eof": 1}, {"partition_errno": 13}, {"diskseq": 19}, {"diskseq": "0\n"}):
            r = sample_leaf()
            for key in ("before", "after"):
                r[key].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                leaf.verify_backing_leaf(r, expected_backing_device="259:0")
        for record in ({}, sample_leaf()|{"schema": "other"}, sample_leaf()|{"after": {"pass": True}}):
            with self.assertRaises(ValueError):
                leaf.verify_backing_leaf(record, expected_backing_device="259:0")
        with self.assertRaises(ValueError):
            leaf.verify_backing_leaf(sample_leaf(), expected_backing_device="259:1")

    def test_deadline_errors_fail_without_retry_or_partial_edge(self):
        k = Model()
        with ExitStack() as st:
            k.enter(st)
            st.enter_context(patch.object(leaf.kernel, "_check", side_effect=ValueError("deadline")))
            with self.assertRaisesRegex(ValueError, "deadline"):
                leaf.capture_backing_leaf("259:0", deadline=1)
            self.assertFalse(k.opened)
