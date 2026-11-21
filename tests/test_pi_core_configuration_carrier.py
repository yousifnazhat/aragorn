"""A table of fake Linux objects only: no host /proc, /dev, mount, subprocess or service."""
from contextlib import ExitStack
import hashlib
from types import SimpleNamespace
import stat
import struct
import unittest
from unittest.mock import patch

from aragorn import pi_core_configuration_carrier as c
from tests.test_pi_core_stopped_mask_view import Kernel


RAW = (b"44 44 8:1 / / ro - squashfs /dev/nvme0n1p2 ro\n"
       b"51 44 0:11 / /run rw - tmpfs tmpfs rw\n"
       b"52 44 0:12 / /dev rw - devtmpfs devtmpfs rw\n"
       b"71 51 7:7 / /run/aragorn-pi-config ro,nosuid,nodev,noexec - squashfs /dev/loop7 ro\n")


class CarrierKernel(Kernel):
    O_NONBLOCK, O_NOCTTY = 64, 128
    P = Kernel.MAN.replace("/root", "/task/24/root")

    def __init__(self):
        super().__init__()
        self.mounts.update({23: RAW, 24: RAW})
        self.body = bytearray(1024)
        self.body[:4] = b"hsqs"
        struct.pack_into("<H", self.body, 20, 6)
        struct.pack_into("<HH", self.body, 28, 4, 0)
        struct.pack_into("<Q", self.body, 40, 117)
        self.pin = dict(device="7:7", image_sha256=hashlib.sha256(self.body[:117]).hexdigest(), image_bytes=117)
        self.geometry = {0x125e: ("=i", 1), 0x1268: ("=i", 512), 0x80081272: ("=Q", 1024)}
        self.io_calls, self.on_read = [], None
        # dev, mnt_id, ino, mode, rdev, relative to the actual caller's kernel-provided root.
        self.nodes = {"/run": ("0:11", 51, 10, stat.S_IFDIR | 0o755, "0:0"),
                      "/dev": ("0:12", 52, 11, stat.S_IFDIR | 0o755, "0:0"),
                      "/dev/loop7": ("0:12", 52, 12, stat.S_IFBLK | 0o600, "7:7"),
                      str(c.ROOT): ("7:7", 71, 1, stat.S_IFDIR | 0o700, "0:0")}
        for name, ino in (("/installed", 2), ("/installed/root", 3), ("/inputs", 4)):
            self.nodes[str(c.ROOT) + name] = ("7:7", 71, ino, stat.S_IFDIR | 0o755, "0:0")

    def open(self, name, flags, dir_fd=None):
        fd = super().open(name, flags, dir_fd)
        if dir_fd is not None and not flags & self.O_NOFOLLOW and self.fds[dir_fd].endswith("/fd"):
            self.fds[fd] = self.fds[int(name)]
        return fd

    def metadata(self, fd, owner=False):
        s = super().metadata(fd, owner=owner)
        path = self.fds[fd]
        if path.startswith(self.P + "/"):
            item = self.nodes[path[len(self.P):]]
            return s | dict(zip(("dev", "mnt_id", "ino", "mode", "rdev"), item)) | self.pinned[fd]
        return s

    def pread(self, fd, n, offset):
        assert self.fds[fd] == self.P + "/dev/loop7"
        if self.on_read:
            self.on_read()
        return bytes(self.body[offset:offset+n])

    def ioctl(self, fd, cmd, buf):
        assert self.fds[fd] == self.P + "/dev/loop7"
        fmt, want = self.geometry[cmd]
        self.io_calls.append(cmd)
        assert buf == bytes(struct.calcsize(fmt))
        return struct.pack(fmt, want)

    def install(self, s):
        super().install(s)
        def fs(fd):
            p = self.fds[fd]
            if p == "/proc":
                return c.kernel._PROC
            if "/ns/" in p:
                return c.kernel._NSFS
            return c._MAGIC if p == self.P + str(c.ROOT) else c.kernel._TMPFS
        def fstat(fd):
            meta = self.metadata(fd)
            major, minor = map(int, meta["rdev"].split(":"))
            return SimpleNamespace(st_mode=meta["mode"], st_rdev=(major, minor))
        api = SimpleNamespace(O_RDONLY=self.O_RDONLY, O_DIRECTORY=self.O_DIRECTORY, O_NOCTTY=self.O_NOCTTY,
                              O_NONBLOCK=self.O_NONBLOCK, getpid=self.getpid, fstat=fstat, pread=self.pread,
                              major=lambda n: n[0], minor=lambda n: n[1])
        for module, attr, mock in ((c.kernel, "_filesystem", fs), (c, "threading", c.kernel.threading),
                                   (c, "os", api), (c, "fcntl", SimpleNamespace(ioctl=self.ioctl))):
            s.enter_context(patch.object(module, attr, mock))


class ConfigurationCarrierTests(unittest.TestCase):
    def test_pin_requires_plain_document_canonical_nonzero_device_and_real_digest_size(self):
        good = CarrierKernel().pin
        self.assertEqual(c.validate_carrier(good), good)
        for change in ({"device": "0:7"}, {"device": "7:07"}, {"image_sha256": "0"*64},
                       {"image_sha256": "A"*64}, {"image_bytes": True}, {"image_bytes": 95},
                       {"image_bytes": (12 << 20) + 1}, {"source": "/dev/loop7"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                c.validate_carrier(good | change)

    def test_unique_private_mount_of_exact_whole_device(self):
        with ExitStack() as stack:
            k = CarrierKernel()
            k.install(stack)
            for changed in (RAW.replace(b"ro,nosuid", b"rw,nosuid"), RAW.replace(b",noexec", b""),
                            RAW.replace(b",nodev", b""), RAW.replace(b",nosuid", b""),
                            RAW.replace(b"loop7 ro", b"loop7 rw"), RAW.replace(b"noexec -", b"noexec shared:1 -"),
                            RAW.replace(b"71 51", b"71 44"), RAW.replace(b"71 51 7:7 / /run", b"71 51 7:7 /x /run"),
                            RAW.replace(b" /dev/loop7 ", b" /dev/nvme0n1p2 "), RAW.replace(b" devtmpfs devtmpfs", b" tmpfs tmpfs"),
                            RAW + b"72 71 0:22 / /run/aragorn-pi-config/shadow ro - tmpfs tmpfs ro\n",
                            RAW + b"72 44 7:7 /other /alias ro - squashfs /dev/other ro\n",
                            RAW + b"72 44 8:55 / /other ro - squashfs /dev/loop7 ro\n",
                            RAW + b"72 52 0:77 / /dev/loop7 ro - tmpfs tmpfs ro\n", RAW + RAW.splitlines(True)[-1]):
                with self.subTest(raw=changed), self.assertRaises(ValueError):
                    c._mounts(changed, "7:7", 14)
            self.assertEqual(c._mounts(RAW.replace(b"/dev/loop7", b"/dev/nvme1n1"), "7:7", 14)[1], "nvme1n1")

    def test_only_known_unrelated_systemd_helper_mounts_are_admissible(self):
        helpers = (b"82 44 0:82 / /proc rw - proc proc rw\n83 44 0:83 / /sys ro - sysfs sysfs ro\n"
                   b"84 82 0:84 / /proc/sys/fs/binfmt_misc rw - autofs systemd-1 rw,fd=33\n"
                   b"85 84 0:85 / /proc/sys/fs/binfmt_misc rw - binfmt_misc binfmt_misc rw\n"
                   b"86 83 0:86 / /sys/fs/fuse/connections rw - fusectl fusectl rw\n")
        with ExitStack() as stack:
            CarrierKernel().install(stack)
            self.assertEqual(c._mounts(RAW + helpers, "7:7", 14)[1], "loop7")
            for bad in (helpers.replace(b"0:86 / /sys", b"0:86 /else /sys"),
                        helpers.replace(b"/sys/fs/fuse/connections", b"/run/other"),
                        helpers.replace(b"systemd-1", b"other-mounter"), helpers.replace(b"85 84", b"85 82"),
                        helpers.replace(b"0:85", b"0:86"), helpers.replace(b"0:85", b"7:7"),
                        helpers + b"90 85 0:90 / /alias rw - tmpfs tmpfs rw\n",
                        helpers + b"91 83 0:91 / /sys/fs/fuse rw - tmpfs tmpfs rw\n"):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    c._mounts(RAW + bad, "7:7", 14)

    def test_hold_and_join_exact_installed_root_not_a_sibling_or_foreign_mount(self):
        with ExitStack() as outer:
            k = CarrierKernel()
            k.install(outer)
            with c.hold_configuration_carrier(k.pin, deadline=14) as held, ExitStack() as fds:
                installed = c.kernel._pin(fds, held.root_fd, "installed", directory=True)
                exact = c.kernel._pin(fds, installed, "root", directory=True)
                held.guard(deadline=13, directory_fd=exact)
                held.require_member(exact, deadline=13)
                foreign = c.kernel._own(fds, k.P + "/run", k.O_PATH)
                with self.assertRaises(ValueError):
                    held.require_member(foreign, deadline=13)
            self.assertFalse(k.fds)
            self.assertEqual(set(k.io_calls), {0x125e, 0x1268, 0x80081272})
            self.assertTrue(all(flags & k.O_PATH and flags & k.O_NOFOLLOW
                                for path, flags in k.calls if path == k.P + "/dev/loop7"))
            self.assertTrue(any(path.startswith("/proc/23/task/24/fd/") and not flags & k.O_NOFOLLOW
                                for path, flags in k.calls))
            with self.assertRaises(ValueError):
                held.guard(deadline=14)
            with self.assertRaisesRegex(ValueError, "installed configuration tree"):
                with c.hold_configuration_carrier(k.pin, deadline=14) as held, ExitStack() as fds:
                    sibling = c.kernel._pin(fds, held.root_fd, "inputs", directory=True)
                    held.guard(deadline=14, directory_fd=sibling)
            self.assertFalse(k.fds)

    def test_even_matching_digest_cannot_substitute_non_b66_superblock_or_wrong_kernel_device(self):
        for label in ("magic", "compression", "version", "used size", "rdev", "devtmpfs overmount"):
            with self.subTest(label=label), ExitStack() as outer:
                k = CarrierKernel()
                k.install(outer)
                offset = {"magic": 0, "compression": 20, "version": 28, "used size": 40}.get(label)
                if offset is not None:
                    k.body[offset] ^= 1
                    k.pin["image_sha256"] = hashlib.sha256(k.body[:117]).hexdigest()
                else:
                    dev, mid, ino, mode, rdev = k.nodes["/dev/loop7"]
                    k.nodes["/dev/loop7"] = (dev, mid if label == "rdev" else 70, ino, mode,
                                              "7:6" if label == "rdev" else rdev)
                with self.assertRaises(ValueError):
                    with c.hold_configuration_carrier(k.pin, deadline=14):
                        self.fail("unverified carrier was yielded")
                self.assertFalse(k.fds)

    def test_media_mismatch_and_changed_guard_refuse_and_close(self):
        for label, change in (
                ("bytes", lambda k: k.body.__setitem__(100, 255)),
                ("padding", lambda k: k.body.__setitem__(117, 255)),
                ("short media", lambda k: k.body.clear()),
                ("readonly", lambda k: k.geometry.update({0x125e: ("=i", 0)})),
                ("sector", lambda k: k.geometry.update({0x1268: ("=i", 4096)})),
                ("undersized final filesystem block", lambda k: k.geometry.update({0x80081272: ("=Q", 512)})),
                ("oversized carrier", lambda k: k.geometry.update({0x80081272: ("=Q", 2048)})),
                ("late nonzero filesystem padding", lambda k: k.body.__setitem__(1023, 255)),
                ("source replaced", lambda k: k.renamed.update({k.P + "/dev/loop7": {"ino": 989}})),
                ("thread namespace", lambda k: setattr(k, "thread_mnt", 992)),
                ("mountinfo changed while hashing", lambda k: setattr(k, "on_read", lambda: k.mounts.update({24: RAW+b"lost\n"}))),
                ("deadline while hashing", lambda k: setattr(k, "on_read", lambda: setattr(k, "now", 15)))):
            with self.subTest(label=label), ExitStack() as outer:
                k = CarrierKernel()
                k.install(outer)
                with self.assertRaises(ValueError):
                    with c.hold_configuration_carrier(k.pin, deadline=14):
                        change(k)
                self.assertFalse(k.fds)
