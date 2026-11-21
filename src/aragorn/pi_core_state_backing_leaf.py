"""Observe only sysfs: whole-disk registration, incarnation and no kernel block slaves.

No data or control node is opened. This is not a LUKS header, physical asset,
exclusive attachment, hardware type or provider-storage topology observation.
"""
from contextlib import ExitStack
import errno
import hashlib
import os
import re
import stat
import threading

from . import pi_core_stopped_mask_view as kernel
from .pi_core_state_admission import _dev
from .pi_core_state_mounts import direct_mount_inventory


SCHEMA = "aragorn/pi-core-sysfs-backing-leaf/v1"
_SYSFS = 0x62656572
_PREFIX = b"../../devices/"
_FIELDS = (b"MAJOR", b"MINOR", b"DEVTYPE", b"DISKSEQ")
_OBS = {"sysfs_mount_id", "sysfs_device", "target_sha256", "inodes", "dev", "diskseq", "uevent",
        "partition_errno", "slaves_eof"}


def _need(ok, why):
    if not ok:
        raise ValueError("backing leaf observation: " + why)


def _uint(value, upper=1 << 64):
    return type(value) is int and 0 < value < upper


def _target(raw):
    _need(type(raw) is bytes and raw.startswith(_PREFIX) and len(raw) <= 4095, "invalid sysfs index link")
    parts = raw[len(_PREFIX):].split(b"/")
    _need(1 <= len(parts) <= 32 and all(0 < len(p) <= 255 and p not in (b".", b"..")
          and all(32 <= c <= 126 for c in p) for p in parts), "unconfined or excessive index target")
    return parts


def _public(raw, *, replay=False):
    _need(type(raw) is bytes and 0 < len(raw) <= 4096 and raw.endswith(b"\n")
          and b"\r" not in raw and b"\0" not in raw, "incomplete sysfs uevent")
    seen, selected, lines = set(), [], raw[:-1].split(b"\n")
    _need(len(lines) <= 96, "excess uevent fields")
    for line in lines:
        k, sep, v = line.partition(b"=")
        _need(sep and re.fullmatch(rb"[A-Z][A-Z0-9_]{0,63}", k) and k not in seen, "ambiguous uevent")
        seen.add(k)
        if k in _FIELDS:
            _need((v == b"disk" if k == b"DEVTYPE" else re.fullmatch(rb"(?:0|[1-9][0-9]{0,19})", v)),
                  "not a complete disk registration")
            selected.append(line)
        else:
            _need(not replay, "unexpected retained uevent field")
    _need(len(selected) == len(_FIELDS), "incomplete public disk registration")
    return b"\n".join(selected) + b"\n"


def _observation(v, device):
    _need(type(v) is dict and set(v) == _OBS, "unexpected observation")
    _need(type(v["dev"]) is str and v["dev"] == device + "\n" and type(v["diskseq"]) is str
          and re.fullmatch(r"[1-9][0-9]{0,19}\n", v["diskseq"]) and _uint(int(v["diskseq"])),
          "device or disk sequence differs")
    _need(type(v["uevent"]) is str and v["uevent"].isascii() and len(v["uevent"]) <= 128,
          "not a bounded public uevent projection")
    fields = dict(vv.split(b"=", 1) for vv in _public(v["uevent"].encode(), replay=True).splitlines())
    _need(fields[b"MAJOR"] + b":" + fields[b"MINOR"] == device.encode()
          and fields[b"DISKSEQ"] + b"\n" == v["diskseq"].encode(), "uevent and attributes differ")
    _need(type(v["partition_errno"]) is int and v["partition_errno"] == errno.ENOENT and
          v["slaves_eof"] is True, "partition or lower block dependencies not excluded")
    _need(_uint(v["sysfs_mount_id"], 1 << 32) and type(v["sysfs_device"]) is str and
          re.fullmatch(r"0:[1-9][0-9]{0,6}", v["sysfs_device"]) and
          int(v["sysfs_device"][2:]) < 1 << 20 and type(v["target_sha256"]) is str and
          re.fullmatch("[a-f0-9]{64}", v["target_sha256"]), "invalid sysfs identity")
    # sys, dev, block, index link, devices, 1..32 target directories, three
    # attributes and slaves directory. Root stays in authenticated custody.
    chain = v["inodes"]
    _need(type(chain) is list and 10 <= len(chain) <= 41 and all(_uint(i) for i in chain)
          and len(set(chain)) == len(chain), "invalid held sysfs inode chain")


def verify_backing_leaf(record, *, expected_backing_device: str) -> dict:
    """Replay only this narrow, authenticated collector projection; never open sysfs."""
    device = _dev(expected_backing_device)
    _need(type(record) is dict and set(record) == {"schema", "before", "after"} and record["schema"] == SCHEMA,
          "invalid record")
    for edge in ("before", "after"):
        _observation(record[edge], device)
    _need(record["before"] == record["after"], "device incarnation, topology or observations changed")
    return {"device": device, "diskseq": int(record["before"]["diskseq"])}


def _read(fd, bound, deadline):
    data = bytearray()
    while True:
        kernel._check(deadline)
        chunk = os.read(fd, bound + 1 - len(data))
        if not chunk:
            break
        data.extend(chunk)
        _need(len(data) <= bound, "sysfs attribute exceeds bound")
    _need(data and data.endswith(b"\n"), "truncated sysfs attribute")
    return bytes(data)


def _edge(stack, leader, caller, pm, device, deadline):
    _, manager, _, _ = kernel._frame(stack, leader, pm, deadline, kind="manager")
    _, thread, root, _ = kernel._frame(stack, caller, pm, deadline, kind="caller")
    _need(all(manager[k] == v for k, v in thread.items() if k not in ("pid", "start_ticks")),
          "caller and manager containment differ")
    raw = kernel._read(caller[1], "mountinfo", 1 << 20, pm, deadline)
    _need(raw == kernel._read(leader[1], "mountinfo", 1 << 20, pm, deadline), "manager and caller mounts differ")
    rows = direct_mount_inventory(raw)
    base, sys = rows["/"], rows.get("/sys")
    root_stat = kernel._stat(root, owner=True)
    _need((root_stat["mnt_id"], root_stat["dev"]) == (base.mount_id, base.device) and
          stat.S_ISDIR(root_stat["mode"]) and root_stat["uid"] == root_stat["gid"] == 0 and
          not root_stat["mode"] & 0o022 and sys is not None and sys.filesystem == b"sysfs" and
          sys.root == "/" and sys.parent == base.mount_id, "expected managed root and direct sysfs")
    ids = []

    def pin(parent, name, kind):
        kernel._check(deadline)
        fd = kernel._pin(stack, parent, name, directory=kind == stat.S_IFDIR)
        s = kernel._stat(fd, owner=True)
        _need(stat.S_IFMT(s["mode"]) == kind and s["uid"] == s["gid"] == 0 and
              (kind == stat.S_IFLNK or not s["mode"] & 0o022) and
              (s["mnt_id"], s["dev"]) == (sys.mount_id, sys.device), "substitution in sysfs observation path")
        ids.append(s["ino"])
        return fd

    sysfd = pin(root, "sys", stat.S_IFDIR)
    _need(kernel._filesystem(sysfd) == _SYSFS, "not the kernel sysfs")
    index = pin(pin(sysfd, "dev", stat.S_IFDIR), "block", stat.S_IFDIR)
    link = pin(index, device, stat.S_IFLNK)
    # Linux readlinkat(held O_PATH|O_NOFOLLOW symlink, ""). Never let the
    # kernel follow a supplied path or arbitrary index destination.
    target = os.readlink(b"", dir_fd=link)
    parts = _target(target)
    leaf = pin(sysfd, "devices", stat.S_IFDIR)
    for part in parts:
        leaf = pin(leaf, part, stat.S_IFDIR)
    fds = kernel._proc_child(stack, caller[1], "fd", os.O_RDONLY | os.O_DIRECTORY, pm)

    def reopen(fd, flags):
        # The checked inode, not a second lookup of an ostensibly safe name.
        opened = kernel._magic(stack, fds, str(fd), os.O_RDONLY | os.O_NONBLOCK | flags, pm)
        _need(kernel._stat(opened, owner=True) == kernel._stat(fd, owner=True), "different reopened sysfs inode")
        return opened

    values = {}
    for name, bound in (("dev", 32), ("diskseq", 32), ("uevent", 4096)):
        data = _read(reopen(pin(leaf, name, stat.S_IFREG), 0), bound, deadline)
        if name == "uevent":
            data = _public(data)
        _need(data.isascii(), "malformed public attribute")
        values[name] = data.decode("ascii")
    kernel._check(deadline)
    try:
        kernel._pin(stack, leaf, "partition")
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise
    else:
        raise ValueError("backing leaf observation: not a whole-disk node")
    slaves = reopen(pin(leaf, "slaves", stat.S_IFDIR), os.O_DIRECTORY)
    with os.scandir(slaves) as entries:
        _need(next(entries, None) is None, "kernel block dependencies present")
    kernel._check(deadline)
    obs = dict(**values, sysfs_mount_id=sys.mount_id, sysfs_device=sys.device, inodes=ids,
               target_sha256=hashlib.sha256(target).hexdigest(), partition_errno=errno.ENOENT, slaves_eof=True)
    _observation(obs, device)
    return (manager, thread, raw, root_stat), obs


def capture_backing_leaf(expected_backing_device: str, *, deadline) -> dict:
    """Two fixed descriptor-bound sysfs walks under the unchanged manager deadline."""
    device = _dev(expected_backing_device)
    kernel._platform()
    kernel._check(deadline)
    try:
        with ExitStack() as held:
            proc, pm = kernel._proc(held)
            leader = kernel._role(held, proc, os.getpid(), pm)
            task = kernel._proc_child(held, leader[1], "task", os.O_RDONLY | os.O_DIRECTORY, pm)
            caller = kernel._role(held, task, threading.get_native_id(), pm)
            # Keep the first walk pinned while independently looking up the
            # path again. Never publish just one successful edge.
            a, first = _edge(held, leader, caller, pm, device, deadline)
            with ExitStack() as last:
                b, second = _edge(last, leader, caller, pm, device, deadline)
            _need(a == b, "protected root or mount context changed")
            record = {"schema": SCHEMA, "before": first, "after": second}
            verify_backing_leaf(record, expected_backing_device=device)
            kernel._check(deadline)
            return record
    except OSError as exc:
        # Never surface potentially identifying topology names from OSError.filename.
        raise OSError(exc.errno, "backing leaf: guarded sysfs observation unavailable") from None
