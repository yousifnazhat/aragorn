"""Read an already attached, operator-pinned configuration carrier. Never mount, write or grant.

Checks refuse on elapsed deadlines; synchronous kernel block I/O is not cancellable
by a Python clock check. A bounded external owner is required for live use. A
read-only guest device also does not attest the operator's underlying storage.
"""
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import threading

from . import pi_core_stopped_mask_view as kernel
from .pi_core_state_admission import _dev, _keys, _need, _uint
from .pi_core_state_mounts import _DEVICE, _DIRECT_FS, _ID, _options
from .runtime_tetragon_stats_map import _mount_path


ROOT = Path("/run/aragorn-pi-config")
_TARGET = bytes(ROOT)
_SOURCE = re.compile(rb"/dev/(loop(?:0|[1-9][0-9]{0,6})|nvme(?:0|[1-9][0-9]{0,5})n[1-9][0-9]{0,6})")
_MAGIC = 0x73717368
_BINFMT = b"/proc/sys/fs/binfmt_misc"
_HELPERS = {
    _BINFMT: (b"/proc", b"proc", {b"autofs": b"systemd-1", b"binfmt_misc": b"binfmt_misc"}),
    b"/sys/fs/fuse/connections": (b"/sys", b"sysfs", {b"fusectl": b"fusectl"}),
}


def validate_carrier(pin):
    _keys(pin, ("device", "image_sha256", "image_bytes"))
    _need(all(type(k) is str for k in pin), "invalid carrier fields")
    _dev(pin["device"])
    _need(type(pin["image_sha256"]) is str and re.fullmatch("[0-9a-f]{64}", pin["image_sha256"])
          and int(pin["image_sha256"], 16) != 0, "invalid configuration image pin")
    _uint(pin["image_bytes"], 96, (12 << 20) + 1)
    return dict(pin)


def _mounts(raw, device, deadline):
    _need(type(raw) is bytes and 0 < len(raw) <= 1 << 20 and raw.endswith(b"\n"), "incomplete mountinfo")
    lines = raw[:-1].split(b"\n")
    _need(0 < len(lines) <= 8192, "excessive mount inventory")
    paths, by_id, named, helpers, devices = {}, set(), {}, {}, {}
    for line in lines:
        kernel._check(deadline)
        sides = line.split(b" - ")
        _need(len(sides) == 2 and len(line) <= 16384 and not re.search(rb"[\x00-\x1f\x7f]", line),
              "malformed mountinfo")
        left, right = (s.split(b" ") for s in sides)
        _need(len(left) >= 6 and len(right) == 3 and all(left) and all(right) and
              _ID.fullmatch(left[0]) and _ID.fullmatch(left[1]) and _DEVICE.fullmatch(left[2]) and
              all(f == b"unbindable" or re.fullmatch(
                  rb"(?:shared|master|propagate_from):[1-9][0-9]{0,9}", f) for f in left[6:]),
              "ambiguous or unsupported mount row")
        ident, parent = int(left[0]), int(left[1])
        root, path = _mount_path(left[3]), _mount_path(left[4])
        _need(ident < 1 << 32 and parent < 1 << 32 and len(path) <= 4096 and len(root) <= 4096 and
              ident not in by_id and path not in paths and not path.startswith(_TARGET + b"/"),
              "stacked, shadowed or invalid mount")
        by_id.add(ident)
        devices[left[2]] = devices.get(left[2], 0) + 1
        _need(left[2] != device.encode() or path == _TARGET, "carrier device has another mount")
        if _SOURCE.fullmatch(right[1]):
            named.setdefault(right[1], []).append(path)
        flags, super_flags = _options(left[5]), _options(right[2])
        # These optional systemd helper units live outside the carrier paths.
        # Account for their identities and parents; never operate on their paths.
        if path in _HELPERS:
            observed = helpers.setdefault(path, {})
            _need(root == b"/" and left[2].startswith(b"0:") and
                  _HELPERS[path][2].get(right[0]) == right[1] and right[0] not in observed,
                  "unrecognized optional systemd helper")
            observed[right[0]] = (ident, parent, left[2])
            continue
        _need(right[0] in _DIRECT_FS, "unsupported mount filesystem")
        paths[path] = (ident, parent, left[2].decode("ascii"), root, right[0])
        if path == _TARGET:
            _need(left[2] == device.encode() and root == b"/" and right[0] == b"squashfs" and len(left) == 6
                  and {b"ro", b"nosuid", b"nodev", b"noexec"} <= flags and b"ro" in super_flags
                  and _SOURCE.fullmatch(right[1]), "configuration mount does not match the protected carrier")
            source = right[1]
    _need({b"/", b"/run", b"/dev", _TARGET} <= paths.keys(), "carrier mount topology incomplete")
    for path, observed in helpers.items():
        base, fs, _ = _HELPERS[path]
        _need(base in paths and paths[base][3:] == (b"/", fs) and paths[base][1] == paths[b"/"][0],
              "optional helper is not below the manager's kernel root")
        mids = {r[0] for r in observed.values()}
        _need(all(r[1] not in mids and not p.startswith(path + b"/") and
                  not (p.startswith(base + b"/") and path.startswith(p + b"/")) for p, r in paths.items()),
              "dependent or shadowed optional helper subtree")
        for kind, (_, parent, dev) in observed.items():
            expected = observed[b"autofs"][0] if kind == b"binfmt_misc" and b"autofs" in observed else paths[base][0]
            _need(parent == expected and devices[dev] == 1, "aliased helper or unexpected helper stack")
    rid, rp = paths[b"/"][:2]
    _need((rp == rid or rp not in by_id) and paths[b"/run"][1] == paths[b"/dev"][1] == rid and
          paths[b"/run"][3:] == (b"/", b"tmpfs") and paths[b"/dev"][3:] == (b"/", b"devtmpfs") and
          paths[_TARGET][1] == paths[b"/run"][0] and named[source] == [_TARGET] and source not in paths,
          "untrusted mount roots, block source or parentage")
    return paths, source[5:].decode("ascii")


def _geometry(fd, size, deadline):
    # Retained ARM64 Linux UAPI linux/fs.h: BLKROGET, BLKSSZGET, BLKGETSIZE64.
    # This guest's SquashFS device read granule is 1 KiB even on 512-byte logical sectors.
    for request, fmt, want in ((0x125e, "=i", 1), (0x1268, "=i", 512), (0x80081272, "=Q", (size + 1023) & ~1023)):
        kernel._check(deadline)
        buf = fcntl.ioctl(fd, request, bytes(struct.calcsize(fmt)))
        _need(struct.unpack(fmt, buf)[0] == want, "writable or unexpected carrier geometry")


def _verify_bytes(fd, pin, deadline):
    size = pin["image_bytes"]
    _geometry(fd, size, deadline)
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        kernel._check(deadline)
        n = min(size - offset, 256 << 10)
        data = os.pread(fd, n, offset)
        _need(len(data) == n, "short configuration carrier read")
        if offset == 0:
            _need(data[:4] == b"hsqs" and int.from_bytes(data[40:48], "little") == size
                  and struct.unpack_from("<HH", data, 28) == (4, 0) and struct.unpack_from("<H", data, 20)[0] == 6,
                  "unexpected configuration SquashFS superblock")
        digest.update(data)
        offset += n
    kernel._check(deadline)
    tail = -size % 1024
    _need(digest.hexdigest() == pin["image_sha256"] and (not tail or os.pread(fd, tail, size) == bytes(tail)),
          "configuration media bytes or sector padding differ")
    _geometry(fd, size, deadline)
    kernel._check(deadline)


class _Carrier:
    __slots__ = ("_pin", "_deadline", "_active", "_tid", "_pm", "_manager", "_caller", "_context_id",
                 "_raw", "_rows", "_name", "_held", "_held_stats", "_device_fd")

    def __init__(self, stack, pin, deadline):
        self._pin, self._deadline, self._active = dict(pin), deadline, True
        self._tid = threading.get_native_id()
        proc, self._pm = kernel._proc(stack)
        self._manager = kernel._role(stack, proc, os.getpid(), self._pm)
        tasks = kernel._proc_child(stack, self._manager[1], "task", os.O_RDONLY | os.O_DIRECTORY, self._pm)
        self._caller = kernel._role(stack, tasks, self._tid, self._pm)
        self._context_id, root, raw = self._context(stack, deadline)
        self._raw = raw
        self._rows, self._name = _mounts(raw, pin["device"], deadline)
        self._held = self._paths(stack, root)
        self._held_stats = self._stats(self._held)
        block = self._held["block"]
        # Open the already-checked device inode, not a second resolution of a mutable /dev name.
        fds = kernel._proc_child(stack, self._caller[1], "fd", os.O_RDONLY | os.O_DIRECTORY, self._pm)
        self._device_fd = kernel._magic(stack, fds, str(block), os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY, self._pm)
        self._device()

    def _live(self, deadline):
        _need(self._active and self._tid == threading.get_native_id(), "configuration carrier custody is inactive")
        kernel._check(deadline)
        _need(deadline <= self._deadline, "cannot extend carrier deadline")

    @property
    def root_fd(self):
        self._live(self._deadline)
        return self._held["config"]

    def _context(self, stack, deadline):
        _, manager, _, _ = kernel._frame(stack, self._manager, self._pm, deadline, kind="manager")
        _, caller, root, _ = kernel._frame(stack, self._caller, self._pm, deadline, kind="caller")
        _need(all(v == manager[k] for k, v in caller.items() if k not in ("pid", "start_ticks")),
              "caller does not share manager containment")
        raw = kernel._read(self._caller[1], "mountinfo", 1 << 20, self._pm, deadline)
        _need(raw == kernel._read(self._manager[1], "mountinfo", 1 << 20, self._pm, deadline),
              "thread and manager mountinfo differ")
        return (manager, caller), root, raw

    def _paths(self, stack, root):
        run = kernel._pin(stack, root, "run", directory=True)
        dev = kernel._pin(stack, root, "dev", directory=True)
        config = kernel._pin(stack, run, ROOT.name, directory=True)
        block = kernel._pin(stack, dev, self._name)
        return dict(root=root, run=run, dev=dev, config=config, block=block)

    def _stats(self, held):
        stats = {name: kernel._stat(fd, owner=True) for name, fd in held.items()}
        for key, name in (("root", b"/"), ("run", b"/run"), ("dev", b"/dev"), ("config", _TARGET),
                          ("block", b"/dev")):
            s, row = stats[key], self._rows[name]
            _need((s["mnt_id"], s["dev"]) == (row[0], row[2]) and s["uid"] == 0 and
                  (stat.S_ISBLK(s["mode"]) and s["rdev"] == self._pin["device"] if key == "block"
                   else stat.S_ISDIR(s["mode"]) and not s["mode"] & 0o022),
                  "held mountpoint or device node differs from manager mountinfo")
        _need(stats["config"]["mode"] == stat.S_IFDIR | 0o700 and stats["config"]["gid"] == 0 and
              kernel._filesystem(held["dev"]) in (kernel._TMPFS, 0x858458f6) and
              kernel._filesystem(held["run"]) == kernel._TMPFS and kernel._filesystem(held["config"]) == _MAGIC,
              "incorrect carrier filesystem, root protection or devtmpfs")
        return stats

    def _device(self):
        s = os.fstat(self._device_fd)
        _need(stat.S_ISBLK(s.st_mode) and f"{os.major(s.st_rdev)}:{os.minor(s.st_rdev)}" == self._pin["device"] and
              kernel._stat(self._device_fd, owner=True) == self._held_stats["block"], "opened a different block device")

    def require_member(self, fd, *, deadline):
        """Check an already-held file/directory belongs to this mount, not its name or contents."""
        self._live(deadline)
        _need(type(fd) is int and fd >= 0, "invalid member descriptor")
        s, mount = kernel._stat(fd), self._held_stats["config"]
        _need((stat.S_ISREG(s["mode"]) or stat.S_ISDIR(s["mode"])) and
              (s["dev"], s["mnt_id"]) == (mount["dev"], mount["mnt_id"]), "member is not on the held carrier")

    def _edge(self, deadline, directory_fd):
        self._live(deadline)
        with ExitStack() as edge:
            ctx, root, raw = self._context(edge, deadline)
            _need(ctx == self._context_id and raw == self._raw, "carrier namespace or manager changed")
            fresh = self._paths(edge, root)
            _need(self._stats(fresh) == self._held_stats == self._stats(self._held), "carrier path or mount replaced")
            self._device()
            if directory_fd is not None:
                self.require_member(directory_fd, deadline=deadline)
                installed = kernel._pin(edge, fresh["config"], "installed", directory=True)
                named = kernel._pin(edge, installed, "root", directory=True)
                _need(kernel._stat(named, owner=True) == kernel._stat(directory_fd, owner=True),
                      "not the held carrier's installed configuration tree")
        kernel._check(deadline)

    def guard(self, *, deadline, directory_fd=None):
        try:
            self._edge(deadline, directory_fd)
            _verify_bytes(self._device_fd, self._pin, deadline)
            self._edge(deadline, directory_fd)
        except BaseException:
            self._active = False
            raise


@contextmanager
def hold_configuration_carrier(pin, *, deadline):
    pin = validate_carrier(pin)
    kernel._check(deadline)
    kernel._platform()
    with ExitStack() as stack:
        holder = _Carrier(stack, pin, deadline)
        try:
            holder.guard(deadline=deadline)
            yield holder
            holder.guard(deadline=deadline)
        finally:
            holder._active = False
