"""Read only the manager's fixed device-mapper control, never a data disk.

This is an observation of the *live table and its dependency*, not of
a LUKS header, a physical asset, the cipher/key or exclusive attachment.
The authenticated outer observer must join it to both held state-mount edges.
"""
import fcntl
import os
import stat
import struct
import threading
from contextlib import ExitStack, contextmanager

from . import pi_core_stopped_mask_view as kernel
from .pi_core_state_admission import _dev
from .pi_core_state_mounts import ANCHOR, direct_mount_inventory


SCHEMA = "aragorn-pi-core-dm-live-mapping/v1"
# Retained ARM64 linux/dm-ioctl.h: _IOWR(0xfd, cmd, struct dm_ioctl).
# There is deliberately no interface for selecting another ioctl or flags.
_INFO, _DEPS = 0xC138FD0C, 0xC138FD0B
_ACTIVE, _NOFLUSH = 1 << 5, 1 << 11
_VERSION = (4, 50, 0)  # B44 ctl_ioctl at Image 0x15d54dc..0x15d54e8 emits all three words.
_START, _CAPACITY = 312, 512
_HEAD = struct.Struct("<6Ii3IQ")    # first 48 bytes, EXCLUDES mapper name/UUID
_TARGET = struct.Struct("<QQiI16s")
_DEPENDENCY = struct.Struct("<IIQ")
_CRYPT = b"crypt" + bytes(11)


def _need(ok, why):
    if not ok:
        raise ValueError("device-mapper observation: " + why)


def _encoded(device):
    major, minor = map(int, _dev(device).split(":"))
    return (minor & 255) | (major << 8) | ((minor & ~255) << 12)


def _devices(device, backing):
    dev, slave = _encoded(device), _encoded(backing)
    _need(dev != slave, "mapped and backing device coincide")
    return dev, slave


def _sections(header, payload, *, info, dev, slave):
    major, minor, patch, size, start, targets, opens, flags, event, pad, seen = _HEAD.unpack(header)
    _need((major, minor, patch) == _VERSION and start == _START
          and size == start + len(payload) and targets == 1 and opens > 0 and pad == 0 and seen == dev,
          "incompatible, truncated or wrong mapped device")
    _need(flags == (_ACTIVE | _NOFLUSH if info else _ACTIVE),
          "expected precisely a writable, active-only, unsuspended table")
    if info:
        sector, length, status, following, kind = _TARGET.unpack(payload[:-1])
        # In B44 retrieve_status writes the unaligned data_size but the
        # *aligned* next offset, including on the final target. crypt INFO
        # emits just NUL. No other target or nonempty status text is retained.
        _need(sector == 0 and 0 < length <= ((1 << 64) - 1) // 512 and status == 0
              and following == 48 and kind == _CRYPT and payload[-1:] == b"\0",
              "not a single complete direct crypt target")
    else:
        count, reserved, observed = _DEPENDENCY.unpack(payload)
        _need((count, reserved, observed) == (1, 0, slave), "not the one approved dependency")
        length = None
    return (major, minor, patch), event, length


def _hex(value, length):
    _need(type(value) is str and len(value) == 2 * length
          and all(c in "0123456789abcdef" for c in value), "invalid retained public bytes")
    return bytes.fromhex(value)


def _decoded(sample, *, info, dev, slave):
    _need(type(sample) is dict and set(sample) == {"header_hex", "payload_hex"}, "unexpected sample fields")
    return _sections(_hex(sample["header_hex"], _HEAD.size),
                     _hex(sample["payload_hex"], _TARGET.size + 1 if info else _DEPENDENCY.size),
                     info=info, dev=dev, slave=slave)


def verify_dm_mapping(record, *, expected_device: str, expected_backing_device: str) -> dict:
    """Replay the three strictly projected public wire samples, without I/O."""
    dev, slave = _devices(expected_device, expected_backing_device)
    _need(type(record) is dict and set(record) == {"schema", "before", "dependencies", "after"}
          and record["schema"] == SCHEMA, "invalid record")
    first, deps, last = (_decoded(record[k], info=k != "dependencies", dev=dev, slave=slave)
                         for k in ("before", "dependencies", "after"))
    _need(first == last and first[:2] == deps[:2], "table extent, ABI or event changed")
    return dict(type="dm-crypt", device=expected_device, backing_devices=[expected_backing_device],
                start_sector=0, length_sectors=first[2], event_nr=first[1])


def _query(fd, *, info, dev, slave, deadline):
    kernel._check(deadline)
    buf = bytearray(_CAPACITY)
    try:
        _HEAD.pack_into(buf, 0, *_VERSION, len(buf), _START, 0, 0, _NOFLUSH if info else 0, 0, 0, dev)
        rc = fcntl.ioctl(fd, _INFO if info else _DEPS, buf, True)
        kernel._check(deadline)
        _need(rc == 0, "read-only ioctl failed")
        # Never copy the name/UUID fields. Before copying any target bytes,
        # admit only this kernel's fixed, short, NUL-only crypt INFO layout.
        n = _TARGET.size + 1 if info else _DEPENDENCY.size
        _need(struct.unpack_from("<II", buf, 12) == (_START + n, _START), "unexpected output bounds")
        if info:
            _need(buf[_START + 24:_START + 40] == _CRYPT and buf[_START + 40] == 0,
                  "unexpected target or private parameters")
        h, p = bytes(buf[:_HEAD.size]), bytes(buf[_START:_START+n])
        _sections(h, p, info=info, dev=dev, slave=slave)
        return {"header_hex": h.hex(), "payload_hex": p.hex()}
    finally:
        buf[:] = bytes(_CAPACITY)


def _nodes(stats, rows, fs, expected):
    root, dev = rows.get("/"), rows.get("/dev")
    state = rows.get(ANCHOR)
    _need(root is not None and dev is not None and state is not None
          and state.device == expected and state.root == "/" and state.filesystem in (b"xfs", b"ext4")
          and dev.filesystem == b"devtmpfs" and dev.root == "/" and dev.parent == root.mount_id
          and "/dev/mapper" not in rows and "/dev/mapper/control" not in rows
          and fs in (kernel._TMPFS, 0x858458f6), "not the manager's state and direct devtmpfs view")
    for name, s in stats.items():
        row = root if name == "root" else dev
        _need((s["mnt_id"], s["dev"]) == (row.mount_id, row.device)
              and s["uid"] == s["gid"] == 0 and not s["mode"] & 0o022
              and (stat.S_ISCHR(s["mode"]) and s["rdev"] == "10:236" if name == "control"
                   else stat.S_ISDIR(s["mode"])), "protected path or misc control identity differs")


@contextmanager
def _control(expected, deadline):
    kernel._platform()
    kernel._check(deadline)
    # Mirrors the configuration carrier: pin leader and calling thread's
    # roots/namespaces, then follow only a kernel-fd link to the checked char
    # inode. Never open the named node as a driver or follow /dev symlinks.
    with ExitStack() as held:
        proc, pm = kernel._proc(held)
        leader = kernel._role(held, proc, os.getpid(), pm)
        tasks = kernel._proc_child(held, leader[1], "task", os.O_RDONLY | os.O_DIRECTORY, pm)
        caller = kernel._role(held, tasks, threading.get_native_id(), pm)

        def frame(stack):
            _, manager, _, _ = kernel._frame(stack, leader, pm, deadline, kind="manager")
            _, thread, root, _ = kernel._frame(stack, caller, pm, deadline, kind="caller")
            _need(all(manager[k] == v for k, v in thread.items() if k not in ("pid", "start_ticks")),
                  "manager and caller containment differ")
            raw = kernel._read(caller[1], "mountinfo", 1 << 20, pm, deadline)
            _need(raw == kernel._read(leader[1], "mountinfo", 1 << 20, pm, deadline),
                  "manager and caller mounts differ")
            dev = kernel._pin(stack, root, "dev", directory=True)
            mapper = kernel._pin(stack, dev, "mapper", directory=True)
            node = kernel._pin(stack, mapper, "control")
            stats = {k: kernel._stat(v, owner=True) for k, v in
                     (("root", root), ("dev", dev), ("mapper", mapper), ("control", node))}
            _nodes(stats, direct_mount_inventory(raw), kernel._filesystem(dev), expected)
            return (manager, thread, raw, stats), node

        before, node = frame(held)
        fds = kernel._proc_child(held, caller[1], "fd", os.O_RDONLY | os.O_DIRECTORY, pm)
        control = kernel._magic(held, fds, str(node), os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY, pm)
        _need(kernel._stat(control, owner=True) == before[3]["control"], "reopened a different node")
        yield control
        with ExitStack() as after:
            _need(before == frame(after)[0] and kernel._stat(control, owner=True) == before[3]["control"],
                  "control path or manager view changed")
        kernel._check(deadline)


def capture_dm_mapping(expected_device: str, expected_backing_device: str, *, deadline) -> dict:
    """Three fixed non-mutating ioctls under an existing owner deadline. No retries."""
    dev, slave = _devices(expected_device, expected_backing_device)
    with _control(expected_device, deadline) as fd:
        record = {"schema": SCHEMA}
        for key in ("before", "dependencies", "after"):
            record[key] = _query(fd, info=key != "dependencies", dev=dev, slave=slave, deadline=deadline)
        verify_dm_mapping(record, expected_device=expected_device, expected_backing_device=expected_backing_device)
    return record
