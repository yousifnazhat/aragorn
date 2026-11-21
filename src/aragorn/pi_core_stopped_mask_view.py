"""Read fixed guest kernel objects for an already-owned, stopped single-task gate.

Only the caller owns the stop/pidfd. No signal, namespace entry, child execution,
arbitrary lookup, or worker-side permission check is performed here. Returned
records are partial observations, never a launch decision or a mask witness.
"""
from contextlib import ExitStack, contextmanager
import ctypes
import hashlib
import math
import os
import platform
import re
import stat
import struct
import sys
import threading
import time

from .pi_core_state_mounts import ACTION, ANCHOR, PROVIDER


SCHEMA = "aragorn/pi-core-stopped-mask-view/v2"
_NAMES = frozenset(("pts", "hugepages", "shm", "ptmx"))
_SOURCE = ("run", "systemd", "inaccessible", "dir")
_CAPS = dict(CapEff="cap_effective", CapPrm="cap_permitted", CapInh="cap_inheritable",
             CapAmb="cap_ambient", CapBnd="cap_bounding")
_NS = {"mnt": "mount_namespace", "user": "user_namespace"}
_PROC = 0x9FA0
_NSFS = 0x6E736673
_TMPFS = 0x01021994


def _require(value, why):
    if not value:
        raise ValueError("stopped mask capture: " + why)


def _check(deadline):
    _require(type(deadline) in (float, int) and math.isfinite(deadline) and time.monotonic() < deadline,
             "original deadline exhausted or invalid")


def _platform():
    _require(sys.platform == "linux" and platform.machine() == "aarch64" and os.geteuid() == 0,
             "requires the protected root ARM64 Linux collector")


def _generation(pid, ticks):
    _require(type(pid) is int and 0 < pid < 1 << 31 and pid != os.getpid()
             and type(ticks) is int and 0 < ticks < 1 << 64, "invalid owned generation")


def _own(stack, name, flags, parent=None):
    fd = os.open(name, flags | os.O_CLOEXEC, dir_fd=parent)
    stack.callback(os.close, fd)
    return fd


def _error(rc):
    if rc != 0:
        n = ctypes.get_errno()
        raise OSError(n, os.strerror(n))


def _filesystem(fd):
    # Linux arm64 struct statfs: first machine word is f_type; the allocated
    # buffer is larger than the full fixed ABI. No caller-supplied pathname.
    raw = ctypes.create_string_buffer(256)
    _error(ctypes.CDLL(None, use_errno=True).fstatfs(fd, ctypes.byref(raw)))
    return struct.unpack_from("=q", raw.raw)[0]


def _decode_stat(raw, owner):
    # linux/stat.h: TYPE, MODE, UID, GID, INO, MNT_ID. Inspect the mask,
    # not default-filled compatibility values for unsupported fields.
    mask = 0x1103 | (0x18 if owner else 0)
    _require(len(raw) == 256 and struct.unpack_from("=I", raw)[0] & mask == mask, "incomplete statx")
    rmaj, rmin, maj, minor, mid = struct.unpack_from("=IIIIQ", raw, 0x80)
    ino = struct.unpack_from("=Q", raw, 0x20)[0]
    _require(mid > 0 and ino > 0, "missing held mount or inode identity")
    result = dict(mode=struct.unpack_from("=H", raw, 0x1c)[0], dev=f"{maj}:{minor}",
                  ino=ino, rdev=f"{rmaj}:{rmin}", mnt_id=mid)
    if owner:
        result["uid"], result["gid"] = struct.unpack_from("=II", raw, 0x14)
    return result


def _stat(fd, owner=False):
    raw = ctypes.create_string_buffer(256)
    # AT_EMPTY_PATH and AT_SYMLINK_NOFOLLOW: pertains to the held object,
    # including a held symlink, not a second implicit lookup of its referent.
    _error(ctypes.CDLL(None, use_errno=True).statx(fd, b"", 0x1100, 0x17ff, ctypes.byref(raw)))
    return _decode_stat(raw.raw, owner)


def _pin(stack, parent, name, *, directory=False):
    return _own(stack, name, os.O_PATH | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0), parent)


def _names(fd, deadline, limit):
    with ExitStack() as transient:
        scanfd = _own(transient, ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NOATIME, fd)
        with os.scandir(scanfd) as entries:
            names = []
            for entry in entries:
                _check(deadline)
                _require(len(names) < limit and 0 < len(entry.name) <= 255 and entry.name.isascii()
                         and entry.name.isprintable() and entry.name not in (".", ".."), "unbounded directory")
                names.append(entry.name)
    _require(len(set(names)) == len(names), "duplicate directory entry")
    return sorted(names)


def _proc_child(stack, parent, name, flags, mount):
    fd = _own(stack, name, flags | os.O_NOFOLLOW, parent)
    _require(_stat(fd)["mnt_id"] == mount, "overmounted proc object")
    return fd


def _magic(stack, parent, name, flags, mount):
    # A bind substituted for the proc link is not authority to follow it.
    before = _stat(_proc_child(stack, parent, name, os.O_PATH, mount))
    _require(stat.S_ISLNK(before["mode"]), "expected a kernel proc link")
    target = _own(stack, name, flags, parent)
    after = _stat(_proc_child(stack, parent, name, os.O_PATH, mount))
    _require(before == after, "kernel proc link changed")
    return target


def _read(proc, name, maximum, mount, deadline):
    with ExitStack() as transient:
        fd = _proc_child(transient, proc, name, os.O_RDONLY, mount)
        result = bytearray()
        while True:
            _check(deadline)
            chunk = os.read(fd, min(16384, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            _require(len(result) <= maximum, "proc record exceeds bound")
    _require(result and result.endswith(b"\n"), "incomplete proc record")
    return bytes(result)


def _parse_subject(raw_stat, raw_status, pid, tgid=None):
    start, mark, rest = raw_stat.rpartition(b") ")
    items = rest.split()
    _require(mark and start.startswith(f"{pid} (".encode()) and len(items) >= 20
             and items[1].isdigit() and items[19].isdigit(), "wrong process stat")
    wanted = set(_CAPS) | {"Uid", "Gid", "Groups", "NoNewPrivs", "Threads", "Pid", "Tgid", "PPid", "State"}
    fields = {}
    for line in raw_status.decode("ascii").splitlines():
        key, colon, tail = line.partition(":")
        if colon and key in wanted:
            _require(key not in fields, "duplicate process status field")
            fields[key] = tail.split()
    _require(fields.keys() == wanted and fields["State"] and len(fields["State"][0]) == len(items[0]) == 1,
             "incomplete process status")

    def nums(key, n=None):
        pieces = fields[key]
        _require((len(pieces) == n if n is not None else len(pieces) <= 256)
                 and all(re.fullmatch("[0-9]{1,10}", p) for p in pieces), "malformed " + key)
        return [int(p) for p in pieces]

    _require(nums("Pid", 1) == [pid] and nums("Tgid", 1) == [pid if tgid is None else tgid]
             and nums("PPid", 1) == [int(items[1])],
             "wrong process identity")
    credentials = {}
    for key in ("Uid", "Gid"):
        for prefix, value in zip(("", "e", "s", "fs"), nums(key, 4)):
            credentials[prefix + key.lower()] = value
    for key, output in _CAPS.items():
        _require(len(fields[key]) == 1 and re.fullmatch("[0-9a-fA-F]{16}", fields[key][0]), "invalid " + key)
        credentials[output] = int(fields[key][0], 16)
    nnp = nums("NoNewPrivs", 1)[0]
    _require(nnp in (0, 1) and 0 < int(items[19]) < 1 << 64, "invalid task flags/generation")
    credentials.update(groups=nums("Groups"), no_new_privs=bool(nnp))
    return (int(items[19]), nums("PPid", 1)[0], (items[0].decode("ascii"), fields["State"][0]),
            nums("Threads", 1)[0], credentials)


def _limited(credentials):
    _require(all(0 < credentials[k] < 1 << 31 and
                 all(credentials[k] == credentials[p + k] for p in ("e", "s", "fs")) for k in ("uid", "gid"))
             and not credentials["groups"] and credentials["no_new_privs"] and
             all(credentials[k] == 0 for k in _CAPS.values()), "not the bounded worker credentials")


def _role(stack, proc, pid, mount):
    pfd = _proc_child(stack, proc, str(pid), os.O_RDONLY | os.O_DIRECTORY, mount)
    return (pid, pfd)


def _frame(stack, role, mount, deadline, *, kind, ticks=None):
    pid, proc = role
    observed, parent, state, threads, creds = _parse_subject(
        _read(proc, "stat", 8192, mount, deadline), _read(proc, "status", 65536, mount, deadline),
        pid, os.getpid() if kind == "caller" else None)
    _require(ticks is None or observed == ticks, "generation changed")
    if kind in ("manager", "caller"):
        _require(pid == (threading.get_native_id() if kind == "caller" else os.getpid()) and
                 all(creds[p + k] == 0 for k in ("uid", "gid") for p in ("", "e", "s", "fs")),
                 "manager is not the root observer")
    else:
        _limited(creds)
        _require(threads == 1 and (all(s in ("T", "t") for s in state) if kind == "worker" else parent == os.getpid()),
                 "not the stopped singleton or the owned probe child")
    # Only these three fixed kernel magic links are followed. All ordinary
    # components in the target filesystem are opened without following links.
    root = _magic(stack, proc, "root", os.O_PATH | os.O_DIRECTORY, mount)
    ns = _proc_child(stack, proc, "ns", os.O_RDONLY | os.O_DIRECTORY, mount)
    held = {key: _magic(stack, ns, key, os.O_RDONLY, mount) for key in _NS}
    _require(all(_filesystem(fd) == _NSFS for fd in held.values()), "unexpected namespace handle")
    subject = dict(pid=pid, start_ticks=observed, uid=creds["uid"], gid=creds["gid"],
                   **{attr: os.fstat(held[key]).st_ino for key, attr in _NS.items()})
    return subject, {**subject, **creds, "root": _stat(root)}, root, held


def _proc(stack):
    fd = _own(stack, "/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    _require(_filesystem(fd) == _PROC, "untrusted proc filesystem")
    return fd, _stat(fd)["mnt_id"]


def _probe_frame(pid, dev_fd, deadline):
    """Inspect only the known parent-owned, held-and-ready helper, never the Pi task."""
    _check(deadline)
    _platform()
    _generation(pid, 1)
    _require(type(dev_fd) is int and 3 <= dev_fd < 1 << 31, "invalid child /dev descriptor")
    with ExitStack() as stack:
        proc, mount = _proc(stack)
        child = _role(stack, proc, pid, mount)
        fds = _proc_child(stack, child[1], "fd", os.O_RDONLY | os.O_DIRECTORY, mount)
        snapshots = []
        for _ in (0, 1):
            _, context, _, _ = _frame(stack, child, mount, deadline, kind="probe")
            fd = _magic(stack, fds, str(dev_fd), os.O_PATH | os.O_DIRECTORY, mount)
            snapshots.append((context, _stat(fd)))
        _require(snapshots[0] == snapshots[1], "probe or held /dev changed")
    _check(deadline)
    return snapshots[0]


def _source(stack, root, *, readable):
    root = _pin(stack, root, _SOURCE[0], directory=True)
    _require(_filesystem(root) == _TMPFS, "manager /run is not on tmpfs")
    run_mount = _stat(root)["mnt_id"]
    for part in _SOURCE[1:]:
        root = _pin(stack, root, part, directory=True)
        _require(_stat(root)["mnt_id"] == run_mount, "overmount in manager source path")
    if readable:
        fd = _own(stack, ".", os.O_RDONLY | os.O_NOATIME | os.O_DIRECTORY | os.O_NOFOLLOW, root)
        _require(_stat(fd, True) == _stat(root, True), "not the pinned backing object")
        return fd
    return root


def _manager_state_fds(stack, root):
    """Hold the fixed source and bind-target walks; ordinary path components are never followed."""
    fds = {"/": root}
    for path in (ANCHOR, ANCHOR + ACTION, ANCHOR + PROVIDER, ACTION, PROVIDER):
        parent = "/"
        for part in path[1:].split("/"):
            child = parent.rstrip("/") + "/" + part
            if child not in fds:
                fds[child] = _pin(stack, fds[parent], part, directory=True)
            parent = child
    return fds


def _manager_state_stats(fds):
    return {path: _stat(fd, owner=True) for path, fd in fds.items()}


class _View:
    @property
    def worker(self):
        return self._worker.copy()

    @property
    def manager(self):
        return self._manager.copy()

    @property
    def names(self):
        return tuple(n for n in self._first["dev_names"] if n in _NAMES)

    def __init__(self, stack, pid, ticks, deadline):
        self._deadline, self._ticks, self._done, self._closed, self._ok = deadline, ticks, False, False, False
        self._open_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        proc, self._mount = _proc(stack)
        self._roles = {k: _role(stack, proc, n, self._mount) for k, n in (("worker", pid), ("manager", os.getpid()))}
        w, self._ctx, self.root_fd, ns = _frame(stack, self._roles["worker"], self._mount, deadline,
                                               kind="worker", ticks=ticks)
        self._worker = w
        self.mntns_fd, self.userns_fd = ns["mnt"], ns["user"]
        self._manager, self._manager_context, self._manager_root, _ = _frame(
            stack, self._roles["manager"], self._mount, deadline, kind="manager")
        tasks = _proc_child(stack, self._roles["manager"][1], "task", os.O_RDONLY | os.O_DIRECTORY, self._mount)
        self._caller = _role(stack, tasks, threading.get_native_id(), self._mount)
        self._caller_ticks = self._caller_context()
        _require(w["mount_namespace"] != self.manager["mount_namespace"], "shared manager/worker mount view")
        self.dev_fd = _pin(stack, self.root_fd, "dev", directory=True)
        _require(_filesystem(self.dev_fd) == _TMPFS, "worker private /dev is not tmpfs")
        self._source_fd = _source(stack, self._manager_root, readable=True)
        self._state_fds = _manager_state_fds(stack, self._manager_root)
        self._first = self._sample()

    def _guard(self):
        _require(not self._done and not self._closed, "view already finished or closed")
        _require(threading.get_native_id() == self._caller[0], "ownership moved to another collector thread")
        _check(self._deadline)

    def _caller_context(self, ticks=None):
        # /proc/TGID records remain the external manager identity, but a Linux
        # thread can have its own fs root, credentials or namespace. A TID
        # obtained from the actual caller is joined through that TGID's task
        # directory; sharing a Python process alone is not evidence.
        with ExitStack() as edge:
            sub, ctx, _, _ = _frame(edge, self._caller, self._mount, self._deadline, kind="caller", ticks=ticks)
            _require(all(ctx[k] == v for k, v in self._manager_context.items() if k not in ("pid", "start_ticks")),
                     "collector thread does not share the manager root, namespaces or credentials")
        return sub["start_ticks"]

    def worker_context(self):
        self._guard()
        with ExitStack() as stack:
            _, ctx, _, _ = _frame(stack, self._roles["worker"], self._mount, self._deadline,
                                  kind="worker", ticks=self._ticks)
            _require(ctx == self._ctx, "worker context changed")
        return ctx

    def _sample(self):
        self._guard()
        with ExitStack() as s:
            ctx = self.worker_context()
            _, manager_ctx, fresh_manager_root, _ = _frame(s, self._roles["manager"], self._mount, self._deadline,
                                                          kind="manager", ticks=self.manager["start_ticks"])
            _require(manager_ctx == self._manager_context, "manager context changed")
            state = _manager_state_stats(self._state_fds)
            _require(state == _manager_state_stats(_manager_state_fds(s, fresh_manager_root)),
                     "held and named manager state paths differ")
            source = _stat(self._source_fd, True)
            named = _stat(_source(s, fresh_manager_root, readable=False), True)
            _require(source == named and source["mode"] == stat.S_IFDIR and source["uid"] == source["gid"] == 0,
                     "held and named systemd source differ or are not root-owned mode 0000")
            entries = _names(self._source_fd, self._deadline, 0)
            dev = _stat(self.dev_fd)
            _require(_stat(_pin(s, self.root_fd, "dev", directory=True)) == dev, "worker /dev changed")
            names = _names(self.dev_fd, self._deadline, 512)
            _require("pts" in names, "mandatory pts absent")
            leaves = {}
            for n in sorted(_NAMES.intersection(names)):
                fd = _pin(s, self.dev_fd, n, directory=n != "ptmx")
                metadata = _stat(fd)
                if n == "ptmx":
                    _require(stat.S_ISLNK(metadata["mode"]), "ptmx is not a symlink")
                    target = os.readlink("", dir_fd=fd)
                    _require(target == "pts/ptmx", "unexpected ptmx link")
                    leaves[n] = (metadata, target)
                else:
                    _require(metadata["mode"] == stat.S_IFDIR and all(metadata[k] == source[k]
                             for k in ("dev", "ino", "rdev")) and metadata["mnt_id"] != source["mnt_id"],
                             "target not the independently held source inode on a distinct mount")
                    leaves[n] = metadata
            mounts = {k: _read(role[1], "mountinfo", 1 << 20, self._mount, self._deadline)
                      for k, role in self._roles.items()}
            caller_raw = _read(self._caller[1], "mountinfo", 1 << 20, self._mount, self._deadline)
            _require(mounts["manager"] == caller_raw, "collector and manager mountinfo differ")
            mounts["manager"] = caller_raw
            self._caller_context(self._caller_ticks)
        _check(self._deadline)
        return dict(root=ctx["root"], dev=dev, source=source, named=named, entries=entries, state=state,
                    dev_names=names, leaves=leaves, mounts=mounts)

    def finish(self):
        self._guard()
        try:
            before, after = self._first, self._sample()
            _require(before == after, "observed roots, mounts, names or backing changed")
            result = dict(schema=SCHEMA, worker=self.worker.copy(), manager=self.manager.copy(),
                          manager_state={edge: dict(sources={ANCHOR: s["state"][ANCHOR],
                                                             ACTION: s["state"][ANCHOR + ACTION],
                                                             PROVIDER: s["state"][ANCHOR + PROVIDER]},
                                                    targets={p: s["state"][p] for p in (ACTION, PROVIDER)})
                                         for edge, s in (("before", before), ("after", after))},
                          source=dict(path="/" + "/".join(_SOURCE), fd=self._source_fd,
                                      before=before["source"], after=after["source"], path_before=before["named"],
                                      path_after=after["named"], entries_before=before["entries"], entries_after=after["entries"]),
                          directories={}, ptmx=None, dev_names=before["dev_names"], worker_root=before["root"],
                          worker_dev=before["dev"], opened_boottime_ns=self._open_ns)
            for n in self.names:
                first, last = before["leaves"][n], after["leaves"][n]
                if n == "ptmx":
                    result["ptmx"] = dict(before=first[0], after=last[0], readlink_before=first[1], readlink_after=last[1])
                else:
                    result["directories"]["/dev/" + n] = dict(before=first, after=last)
            raw = after["mounts"]
            for k, value in raw.items():
                result[k + "_mountinfo_digest"] = "sha256:" + hashlib.sha256(value).hexdigest()
            self.worker_context()
            with ExitStack() as edge:
                _, manager_ctx, _, _ = _frame(edge, self._roles["manager"], self._mount, self._deadline,
                                              kind="manager", ticks=self.manager["start_ticks"])
                _require(manager_ctx == self._manager_context, "manager changed during final read")
                self._caller_context(self._caller_ticks)
            end = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            _require(0 < end - self._open_ns <= 5_000_000_000, "capture exceeded mask window")
            result["closed_boottime_ns"] = end
            _check(self._deadline)
            self._ok = True
            return result, raw["worker"], raw["manager"]
        finally:
            self._done = True

    def guard_retained_topology(self, worker_raw, manager_raw):
        """Bounded samples of this still-held stop while publishing its new spine receipt."""
        _require(self._done and self._ok and not self._closed and threading.get_native_id() == self._caller[0],
                 "completed view no longer held by its original observer")
        _check(self._deadline)
        with ExitStack() as s:
            for key, ticks, ctx, raw in (("worker", self._ticks, self._ctx, worker_raw),
                                         ("manager", self._manager["start_ticks"], self._manager_context, manager_raw)):
                role = self._roles[key]
                _, current, _, _ = _frame(s, role, self._mount, self._deadline, kind=key, ticks=ticks)
                _require(current == ctx and raw == self._first["mounts"][key] ==
                         _read(role[1], "mountinfo", 1 << 20, self._mount, self._deadline),
                         "subject or mounting changed during evidence publication")
            self._caller_context(self._caller_ticks)
            _require(_read(self._caller[1], "mountinfo", 1 << 20, self._mount, self._deadline) == manager_raw,
                     "publishing thread no longer shares the manager mounting")
        _check(self._deadline)


@contextmanager
def hold_stopped_mask_view(*, pid, start_ticks, deadline):
    """Only while the supervisor retains the original gate stop and process generation."""
    _check(deadline)
    _generation(pid, start_ticks)
    _platform()
    with ExitStack() as stack:
        view = _View(stack, pid, start_ticks, deadline)
        try:
            yield view
            _require(view._ok, "fixed view was not finished successfully")
            _check(deadline)
        finally:
            view._closed = True
    _check(deadline)
