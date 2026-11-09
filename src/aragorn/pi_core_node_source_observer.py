"""Owned Linux arm64 Node tracing; importing this module performs no operation.

The dedicated tracer is the only thread allowed to resume or reap captured TIDs.
Mapping a pinned ELF is loader evidence, never JavaScript execution evidence.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import socket
import stat
import struct
import threading
import time

from . import pi_core_source_observer as base

SCHEMA = "aragorn/pi-core-node-source-observation/v2"
PROFILE_SCHEMA = "aragorn/pi-core-node-source-profile/v1"
SOURCE_SCHEMA = "aragorn/pi-core-node-source-inventory/v2"
LOADER_SCHEMA = "aragorn/pi-core-loader-inventory/v1"
ORIGIN = Path("/opt/aragorn/src/aragorn/pi_core_node_source_observer.py")
_PINS = {"gate_digest", "node_digest", "producer_digest", "node_observer_digest",
         "source_inventory_digest", "loader_inventory_digest"}
_THREAD_REQUIRED = 0x50F00
_THREAD_ALLOWED = _THREAD_REQUIRED | 0x40000 | 0x80000 | 0x100000 | 0x200000 | 0x1000000
_READS = {63: "read", 65: "readv", 67: "pread64", 69: "preadv"}
_CREATE = {19: "eventfd", 59: "pipe", 199: "socketpair"}
# Mutating files, FD passing, process forks, alternate execution/loading and AIO
# remain outside the fixed managed profile. Ordinary entries still pair exactly.
_ORDINARY = frozenset({20, 21, 22, 23, 24, 25, 29, 48, 56, 57, 61, 62, 64, 66,
    72, 73, 79, 80, 93, 94, 96, 98, 99, 113, 114, 115, 124, 129, 130, 131,
    132, 134, 135, 139, 160, 163, 164, 165, 166, 167, 172, 173, 174, 175,
    176, 177, 178, 198, 200, 201, 202, 203, 204, 205, 208, 209, 210,
    214, 215, 216, 226, 233, 261, 278, 283, 291, 293})
_WAIT_CALLS = {22, 72, 73, 98}
_require = base._require


def validate_node_profile(value):
    _require(type(value) is dict and set(value) == {
        "schema", "pins", "sources", "required_sources", "loader_files"} and
        value["schema"] == PROFILE_SCHEMA and type(value["pins"]) is dict and
        set(value["pins"]) == _PINS and all(type(pin) is str and base._PIN.fullmatch(pin)
        for pin in value["pins"].values()), "NODE_PROFILE")
    for field in ("sources", "loader_files"):
        rows = value[field]
        _require(type(rows) is list and 0 < len(rows) <= 512, "NODE_INVENTORY_BOUND")
        paths = []
        for row in rows:
            _require(type(row) is dict and set(row) == {"path", "digest"} and
                     type(row["path"]) is str and Path(row["path"]).is_absolute() and
                     row["path"] == os.path.normpath(row["path"]) and
                     not any(part in {"", ".", ".."} for part in row["path"].split("/")[1:]) and
                     not any(ord(char) < 32 for char in row["path"]) and len(row["path"]) <= 4096 and
                     type(row["digest"]) is str and base._PIN.fullmatch(row["digest"]), "NODE_INVENTORY_ROW")
            paths.append(row["path"])
        _require(len(set(paths)) == len(paths), "NODE_DUPLICATE_PATH")
    required = value["required_sources"]
    _require(type(required) is list and required and all(type(path) is str for path in required)
             and len(set(required)) == len(required) and set(required) <= {r["path"] for r in value["sources"]},
             "NODE_REQUIRED_SOURCES")
    _require(not ({r["path"] for r in value["sources"]} & {r["path"] for r in value["loader_files"]}),
             "NODE_SOURCE_LOADER_ALIAS")
    return json.loads(base.canonical_json(value))


def _profile_binding(owned, profile, pin):
    _require(base.canonical_json(owned.plan.source_observation) == base.canonical_json(profile) and
             base.canonical_digest(profile) == owned.plan.source_observation_digest == pin,
             "NODE_HELD_PROFILE_CHANGED")


def _readonly(fd, maximum=base.MAX_FILE):
    info = os.fstat(fd)
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             info.st_nlink == 1 and not info.st_mode & 0o7022 and 0 <= info.st_size <= maximum and
             os.fstatvfs(fd).f_flag & os.ST_RDONLY, "NODE_FILE_NOT_PROTECTED_READONLY_VIEW")
    return base._file_identity(info)


def _hash_readonly(fd, deadline, maximum=base.MAX_FILE):
    before = _readonly(fd, maximum)
    digest, offset = hashlib.sha256(), 0
    while offset < before["size"]:
        _require(time.monotonic() < deadline, "NODE_HASH_DEADLINE")
        data = os.pread(fd, min(65536, before["size"] - offset), offset)
        _require(data, "NODE_HASH_SHORT")
        digest.update(data)
        offset += len(data)
    _require(_readonly(fd, maximum) == before, "NODE_FILE_CHANGED")
    return "sha256:" + digest.hexdigest(), before


def _fd_identity(fd):
    value = os.fstat(fd)
    return {"device": value.st_dev, "inode": value.st_ino, "mode": value.st_mode}


class _NodeSession:
    def __init__(self, owned, profile, operation_deadline, cleanup_deadline):
        self.owned, self.profile = owned, validate_node_profile(profile)
        self.operation_deadline, self.cleanup_deadline = operation_deadline, cleanup_deadline
        self.commands, self.ready = queue.Queue(maxsize=1), threading.Event()
        self.thread = threading.Thread(target=self._main, name="aragorn-pi-source-owner", daemon=True)
        self.observer, self.failure = base.PiSourceObserver(base._SEAL), None
        self.observer._owned = owned
        self.observer._node_session = self
        self.tasks, self.retired, self.pending_events = {}, set(), []
        self.epoch = 0
        self.internal_fds = {}
        self.stdio = {}
        self.loaders, self.loader_fds = [], {}
        self.held_files = []
        self.gate_release_seen = False
        self.stopping = False
        self.drain_failure = None
        self.latest_health_observation = None
        self.closed = threading.Event()
        self.lock = threading.Lock()

    def _event(self, kind, **fields):
        if not self.stopping:
            _require(len(self.observer._events) < base.MAX_EVENTS - (64 * 4 + 8), "NODE_EVENT_CLEANUP_RESERVE")
        self.observer._event(kind, _cleanup=self.stopping, **fields)
        return self.observer._events[-1]

    def _budget(self, deadline=None):
        chosen = self.cleanup_deadline if self.stopping else self.operation_deadline
        if deadline is not None:
            chosen = min(chosen, deadline)
        _require(time.monotonic() < chosen, "NODE_OWNER_DEADLINE")
        return chosen

    def _peek(self, tid, address, size):
        _require(all(t["stopped"] for t in self.tasks.values()) and 0 < address < 2**63 and
                 0 <= size <= 4096 and address + size < 2**63, "NODE_MEMORY_CUSTODY")
        data = bytearray()
        start = address & ~7
        for position in range(start, (address + size + 7) & ~7, 8):
            value = self.observer._kernel.ptrace(2, tid, position, 0)
            data.extend((value & (2**64 - 1)).to_bytes(8, "little"))
        return bytes(data[address - start:address - start + size])

    def _tid_identity(self, tid):
        leader = self.owned.pid
        raw = base.process._read_virtual_file(Path(f"/proc/{leader}/task/{tid}/status"), 65536).decode("ascii")
        expected = {"Tgid": str(leader), "Pid": str(tid), "TracerPid": str(self.observer._thread)}
        for key, value in expected.items():
            _require(re.findall(r"^" + key + r":\s*(\d+)\s*$", raw, re.M) == [value], "NODE_TID_OWNERSHIP")
        for name, expected_id in (("Uid", self.owned.plan.worker_uid), ("Gid", self.owned.plan.worker_gid)):
            values = re.findall(r"^" + name + r":\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", raw, re.M)
            _require(values == [(str(expected_id),) * 4], "NODE_TID_CREDENTIALS")
        _require(base.process._process_cgroup(tid) == self.owned.plan.profile.cgroup and
                 base.process._mount_namespace(tid) == base.process._mount_namespace(leader), "NODE_TID_SCOPE")
        return base.process._process_start_time(tid)

    def _inventory(self):
        actual = sorted(int(x) for x in os.listdir(f"/proc/{self.owned.pid}/task"))
        _require(actual == sorted(self.tasks) and len(actual) <= 64, "NODE_UNACCOUNTED_TASK")
        for tid, task in self.tasks.items():
            _require(self._tid_identity(tid) == task["start_ticks"], "NODE_TID_REUSED")
        return actual

    def _resume(self, tid, request="SYSCALL"):
        task = self.tasks[tid]
        _require(task["stopped"] and task["joined"], "NODE_RESUME_CUSTODY")
        self._event("RESUME", pid=tid, start_ticks=task["start_ticks"], request=request)
        self.observer._kernel.ptrace(base._SYSCALL if request == "SYSCALL" else 7, tid)
        task["stopped"] = False

    def _wait_one(self, tid):
        task = self.tasks[tid]
        waited, status = os.waitpid(tid, os.WNOHANG | 0x40000000)
        if waited == 0:
            return False
        _require(waited == tid, "NODE_FOREIGN_WAIT")
        stopped = os.WIFSTOPPED(status)
        event = status >> 16 if stopped else 0
        sig = (status >> 8) & 255 if stopped else 0
        op, nr, args, result, error, message = "NONE", None, None, None, None, None
        if stopped and event == 0 and sig == 133:
            op, nr, args, result, error = self.observer._kernel.info(tid)
        if stopped and event in {1, 2, 3, 4, 6}:
            message = self.observer._kernel.message(tid)
        self.observer._stops += 1
        row = self._event("STOP", pid=tid, start_ticks=task["start_ticks"], status=status,
            op=op, syscall=nr, args=args, result=result, is_error=error, event=event, event_message=message)
        task.update(stopped=stopped, stop_seq=row["seq"], stop_event=event)
        if not stopped:
            _require(os.WIFEXITED(status) or os.WIFSIGNALED(status), "NODE_UNKNOWN_WAIT")
            _require(task.get("exit_seen"), "NODE_EXIT_WITHOUT_EVENT")
            self._event("THREAD_EXIT", pid=tid, start_ticks=task["start_ticks"], status=status)
            self.retired.add(tid)
            del self.tasks[tid]
            return True
        _require(event not in {1, 2}, "NODE_PROCESS_FORK_REFUSED")
        if event == 3:
            call = task["call"]
            _require(call is not None and call["nr"] in {220, 435} and "clone_seq" in call and
                     type(message) is int and message > 0 and message not in self.tasks and message not in self.retired and
                     len(self.tasks) < 64, "NODE_CLONE_UNBOUND")
            start = self._tid_identity(message)
            self.tasks[message] = dict(start_ticks=start, stopped=False, joined=False, call=None,
                                       stop_seq=None, stop_event=None, clone_parent=tid,
                                       clone_seq=call["clone_seq"], birth_exit=False, entry_seen=False)
            self._event("THREAD", pid=message, start_ticks=start, parent_pid=tid,
                        flags=call["flags"], clone_call_seq=call["clone_seq"])
        self.pending_events.append(row)
        return True

    def _barrier(self, deadline):
        for tid, task in list(self.tasks.items()):
            if not task["stopped"] and task["joined"]:
                self.observer._kernel.ptrace(base._INTERRUPT, tid)
        while not all(task["stopped"] for task in self.tasks.values()):
            self._budget(deadline)
            progressed = False
            for tid in list(self.tasks):
                if not self.tasks[tid]["stopped"]:
                    progressed |= self._wait_one(tid)
            if not progressed:
                time.sleep(min(0.001, max(0, deadline - time.monotonic())))
        self._inventory()
        self.epoch += 1
        tasks = [{"pid": tid, "start_ticks": self.tasks[tid]["start_ticks"]} for tid in sorted(self.tasks)]
        self._event("ALL_STOP", epoch=self.epoch, tasks=tasks,
                    stop_seqs=[self.tasks[t["pid"]]["stop_seq"] for t in tasks])
        return tasks

    def _duplicate(self, fd):
        _require(type(fd) is int and 0 <= fd <= 2**31 - 1, "NODE_FD_BOUND")
        duplicate = self.observer._kernel.duplicate(self.observer._pidfd, fd)
        self.observer._fds.append(duplicate)
        return duplicate

    def _close_duplicate(self, fd):
        _require(not self.observer._close_attempted and fd in self.observer._fds, "NODE_DUPLICATE_CLOSE_CUSTODY")
        try:
            os.close(fd)
        except OSError as error:
            # close(2) failure can be ambiguous. Retain the ownership record,
            # and the existing close latch prevents every later cleanup retry.
            self.observer._close_attempted = True
            raise base.PiSourceObserverError("NODE_AMBIGUOUS_FD_CLOSE_NO_RETRY", self.observer) from error
        self.observer._fds.remove(fd)

    def _read_arguments(self, tid, call):
        nr, args = call["nr"], call["args"]
        vector = None
        if nr in {65, 69}:
            _require(0 < args[2] <= 128, "NODE_IOV_BOUND")
            vector = self._peek(tid, args[1], args[2] * 16)
            count = sum(struct.unpack_from("<QQ", vector, i * 16)[1] for i in range(args[2]))
        else:
            count = args[2]
        _require(0 <= count <= base.MAX_FILE, "NODE_READ_BOUND")
        if nr == 69:
            _require(args[4] == 0, "NODE_PREADV_OFFSET_HIGH")
        return args[0], count, vector.hex() if vector is not None else None

    def _channel(self, fd, duplicate):
        identity = _fd_identity(duplicate)
        if fd in self.stdio and identity == self.stdio[fd] and os.fstat(duplicate).st_rdev == os.makedev(1, 3):
            return {"kind": "stdio-null", "fd": fd}, identity
        key = tuple(identity.values())
        if key in self.internal_fds:
            # anon_inode metadata is not a unique open-description identity.
            # Compare two held descriptors in this tracer process, never worker
            # integers that another thread can close/reuse after a stop.
            for channel, held in self.internal_fds[key]:
                if self._same_description(duplicate, held):
                    return dict(channel), identity
            raise base.PiSourceObserverError("NODE_INTERNAL_OBJECT_CHANGED", self.observer)
        _require(stat.S_ISSOCK(identity["mode"]), "NODE_UNCLASSIFIED_INPUT")
        connection = socket.socket(fileno=duplicate)
        try:
            _require(connection.getsockopt(socket.SOL_SOCKET, 39) == socket.AF_UNIX and
                     connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) in {socket.SOCK_STREAM, socket.SOCK_SEQPACKET},
                     "NODE_EXTERNAL_TRANSPORT")
            peer = list(struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)))
            _require(peer == [os.getpid(), 0, 0], "NODE_UNOWNED_ROOT_PEER")
            listeners = [self.owned.listener]
            dispatch = getattr(self.owned, "_pi_request_dispatch", None)
            if dispatch is not None:
                from .pi_core_native_request import PiNativeRequestDispatch
                _require(type(dispatch) is PiNativeRequestDispatch and dispatch.owned is self.owned and
                         dispatch.active and not dispatch.closed, "NODE_REQUEST_CUSTODY")
                dispatch._ownership()
                listeners.append(dispatch.listener)
            provider = getattr(self.owned, "_pi_provider_dispatch", None)
            if provider is not None:
                from .pi_core_native_provider import PiNativeProviderDispatch
                _require(type(provider) is PiNativeProviderDispatch and provider.owned is self.owned and
                         provider.active and not provider.closed and self.owned.provider_dispatch_active,
                         "NODE_PROVIDER_CUSTODY")
                provider._ownership()
                listeners.append(provider.listener)
            _require(any(type(listener) is socket.socket and listener.fileno() >= 0 and
                         connection.getpeername() == listener.getsockname() for listener in listeners),
                     "NODE_UNOWNED_ROOT_ENDPOINT")
            return {"kind": "root-unix", "peer": peer, "endpoint": connection.getpeername()}, identity
        finally:
            connection.detach()

    def _same_description(self, left, right):
        _require(all(task["stopped"] for task in self.tasks.values()) and
                 left in self.observer._fds and right in self.observer._fds,
                 "NODE_OPEN_DESCRIPTION_CUSTODY")
        ctypes.set_errno(0)
        # Linux arm64 __NR_kcmp=272; KCMP_FILE=0. Both descriptors are owned
        # pidfd_getfd duplicates held in this process throughout comparison.
        result = self.observer._kernel.libc.syscall(ctypes.c_long(272), ctypes.c_int(os.getpid()),
            ctypes.c_int(os.getpid()), ctypes.c_int(0), ctypes.c_ulong(left), ctypes.c_ulong(right))
        if result < 0:
            raise OSError(ctypes.get_errno(), "owned open-description comparison failed")
        return result == 0

    def _exclusive_exit(self, tid, call, deadline):
        self._resume(tid)
        while not self.tasks[tid]["stopped"]:
            self._budget(deadline)
            if not self._wait_one(tid):
                time.sleep(min(0.001, max(0, deadline - time.monotonic())))
        event = self.pending_events.pop()
        _require(event["pid"] == tid and event["op"] == "EXIT" and event["event"] == 0,
                 "NODE_EXCLUSIVE_CALL_INTERRUPTED")
        self._barrier(deadline)
        self.tasks[tid]["call"] = None
        return event

    def _file_read(self, tid, call, deadline):
        self._barrier(deadline)
        fd, count, vector = self._read_arguments(tid, call)
        duplicate = self._duplicate(fd)
        info = os.fstat(duplicate)
        if not stat.S_ISREG(info.st_mode):
            channel, identity = self._channel(fd, duplicate)
            self._event("IO_ENTER", pid=tid, call_id=call["seq"], syscall=_READS[call["nr"]],
                        fd=fd, count=count, iovecs=vector, channel=channel, identity=identity, epoch=self.epoch)
            call.update(io=True, count=count, duplicate=duplicate)
            return
        identity = _readonly(duplicate, base.process._MAX_EXECUTABLE_BYTES)
        rows = [row for row in self.observer._sources if row["identity"] == identity]
        loader_rows = [row for row in self.loaders if row["identity"] == identity]
        _require(len(rows) + len(loader_rows) == 1, "NODE_UNCLASSIFIED_REGULAR_READ")
        source = (rows or loader_rows)[0]
        offset = call["args"][3] if call["nr"] in {67, 69} else os.lseek(duplicate, 0, os.SEEK_CUR)
        _require(0 <= offset <= identity["size"] and offset + count < 2**63, "NODE_READ_RANGE")
        maximum = base.MAX_FILE if rows else base.process._MAX_EXECUTABLE_BYTES
        _require(_hash_readonly(duplicate, deadline, maximum) == (source["digest"], identity), "NODE_READ_PIN")
        kind = "READ" if rows else "LOADER_READ"
        self._event(kind + "_ENTER", pid=tid, call_id=call["seq"], syscall=_READS[call["nr"]],
                    fd=fd, offset=offset, count=count, iovecs=vector, path=source["path"], digest=source["digest"],
                    identity=identity, epoch=self.epoch)
        event = self._exclusive_exit(tid, call, deadline)
        result, error = event["result"], event["is_error"]
        _require(type(result) is int and type(error) is bool and
                 (error and -4095 <= result < 0 or not error and 0 <= result <= count and offset + result <= identity["size"]),
                 "NODE_READ_RESULT")
        _require(_hash_readonly(duplicate, deadline, maximum) == (source["digest"], identity), "NODE_READ_CHANGED")
        if not error and call["nr"] in {63, 65}:
            _require(os.lseek(duplicate, 0, os.SEEK_CUR) == offset + result, "NODE_READ_OFFSET_RACE")
        self._event(kind + "_EXIT", pid=tid, call_id=call["seq"], result=result, is_error=error,
                    identity=identity, epoch=self.epoch)
        if rows and not error:
            self.observer._read_paths.add(source["path"])
            if result:
                self.observer._ranges[source["path"]].append((offset, offset + result))
        self._close_duplicate(duplicate)

    def _mapping(self, tid, call, deadline):
        args = call["args"]
        if args[3] & 0x20:
            _require(args[4] == 2**64 - 1, "NODE_ANONYMOUS_MAPPING_FD")
            return
        self._barrier(deadline)
        duplicate = self._duplicate(args[4])
        identity = _readonly(duplicate, base.process._MAX_EXECUTABLE_BYTES)
        rows = [row for row in self.loaders if row["identity"] == identity]
        _require(len(rows) == 1 and args[3] & 3 == 2 and not args[2] & ~7 and
                 not (args[2] & 2 and args[2] & 4) and 0 < args[1] <= base.process._MAX_EXECUTABLE_BYTES and
                 args[5] % 4096 == 0 and args[5] < identity["size"], "NODE_LOADER_MAP_SCOPE")
        row = rows[0]
        _require(_hash_readonly(duplicate, deadline, base.process._MAX_EXECUTABLE_BYTES) == (row["digest"], identity)
                 and os.pread(duplicate, 4, 0) == b"\x7fELF", "NODE_LOADER_ELF")
        self._event("MAP_ENTER", pid=tid, call_id=call["seq"], fd=args[4], offset=args[5], length=args[1],
                    prot=args[2], flags=args[3], path=row["path"], digest=row["digest"], identity=identity, epoch=self.epoch)
        event = self._exclusive_exit(tid, call, deadline)
        _require(_readonly(duplicate, base.process._MAX_EXECUTABLE_BYTES) == identity, "NODE_LOADER_CHANGED")
        self._event("MAP_EXIT", pid=tid, call_id=call["seq"], result=event["result"],
                    is_error=event["is_error"], identity=identity, epoch=self.epoch)
        self._close_duplicate(duplicate)

    def _clone(self, tid, call, deadline):
        self._barrier(deadline)
        raw = None
        if call["nr"] == 435:
            _require(call["args"][1] in {64, 80, 88}, "NODE_CLONE3_SIZE")
            raw = self._peek(tid, call["args"][0], call["args"][1])
            fields = struct.unpack("<" + "Q" * (len(raw) // 8), raw)
            flags = fields[0]
            _require(fields[1] == fields[4] == 0 and fields[5] and fields[6] and
                     all(x == 0 for x in fields[8:]), "NODE_CLONE3_SCOPE")
        else:
            flags = call["args"][0]
            _require(call["args"][1] != 0, "NODE_CLONE_STACK")
        _require(flags & _THREAD_REQUIRED == _THREAD_REQUIRED and flags & ~_THREAD_ALLOWED == 0,
                 "NODE_NONTHREAD_CLONE")
        row = self._event("CLONE_REQUEST", pid=tid, call_id=call["seq"], syscall=call["nr"],
                          flags=flags, clone_args=raw.hex() if raw is not None else None, epoch=self.epoch)
        call.update(flags=flags, clone_seq=row["seq"])
        self._resume(tid)
        while True:
            self._budget(deadline)
            progressed = False
            for child in list(self.tasks):
                if child == tid or not self.tasks[child]["joined"]:
                    if not self.tasks[child]["stopped"]:
                        progressed |= self._wait_one(child)
            own = [row for row in self.pending_events if row["pid"] == tid]
            if own:
                event = own[-1]
                self.pending_events.remove(event)
                if event["event"] == 3:
                    # Parent-only progress; the automatic child stop stays held.
                    while any(not task["joined"] for task in self.tasks.values()):
                        self._budget(deadline)
                        for child in list(self.tasks):
                            if not self.tasks[child]["joined"]:
                                if not self.tasks[child]["stopped"]:
                                    self._wait_one(child)
                                if self.tasks[child]["stopped"]:
                                    initial = next(row for row in self.pending_events if row["pid"] == child)
                                    self.pending_events.remove(initial)
                                    self._handle(initial, deadline)
                        time.sleep(min(0.001, max(0, deadline - time.monotonic())))
                    self._resume(tid)
                else:
                    _require(event["op"] == "EXIT" and event["event"] == 0, "NODE_CLONE_INTERRUPTED")
                    _require((event["is_error"] and -4095 <= event["result"] < 0) or
                             (not event["is_error"] and event["result"] in self.tasks and
                              self.tasks[event["result"]].get("clone_parent") == tid), "NODE_CLONE_RESULT")
                    while any(not task["joined"] for task in self.tasks.values()):
                        self._budget(deadline)
                        for child in list(self.tasks):
                            if not self.tasks[child]["joined"]:
                                if not self.tasks[child]["stopped"]:
                                    self._wait_one(child)
                                if self.tasks[child]["stopped"]:
                                    initial = next(row for row in self.pending_events if row["pid"] == child)
                                    self.pending_events.remove(initial)
                                    self._handle(initial, deadline)
                    self._barrier(deadline)
                    self.tasks[tid]["call"] = None
                    return
            if not progressed:
                time.sleep(min(0.001, max(0, deadline - time.monotonic())))

    def _created(self, tid, call, result, error, deadline):
        if error:
            return
        self._barrier(deadline)
        if call["nr"] == 19:
            fds = [result]
        else:
            _require(result == 0, "NODE_FD_CREATE_RESULT")
            pointer = call["args"][0] if call["nr"] == 59 else call["args"][3]
            fds = list(struct.unpack("<ii", self._peek(tid, pointer, 8)))
        rows = []
        kind = _CREATE[call["nr"]]
        for fd in fds:
            duplicate = self._duplicate(fd)
            identity = _fd_identity(duplicate)
            if kind == "pipe":
                _require(stat.S_ISFIFO(identity["mode"]), "NODE_CREATED_PIPE_TYPE")
            elif kind == "socketpair":
                _require(stat.S_ISSOCK(identity["mode"]), "NODE_CREATED_SOCKET_TYPE")
            else:
                _require(os.readlink(f"/proc/{self.owned.pid}/fd/{fd}") == "anon_inode:[eventfd]", "NODE_CREATED_EVENTFD_TYPE")
            rows.append({"fd": fd, "identity": identity})
            self.internal_fds.setdefault(tuple(identity.values()), []).append(
                ({"kind": kind, "created_by": call["seq"]}, duplicate))
            # Hold the kernel object until owned teardown; inode reuse cannot
            # turn an unrelated later descriptor into an approved internal pipe.
        self._event("FD_CREATE", pid=tid, call_id=call["seq"], kind_name=kind, descriptors=rows, epoch=self.epoch)

    def _handle(self, event, deadline):
        tid = event["pid"]
        if tid not in self.tasks:
            return
        task = self.tasks[tid]
        if not task["joined"]:
            _require(event["event"] == 128 and event["op"] == "NONE", "NODE_CHILD_INITIAL_STOP")
            task["joined"] = True
            return
        if event["event"] == 6:
            task["exit_seen"] = True
            _require(self.stopping or tid != self.owned.pid, "NODE_LEADER_EXIT_DURING_OPERATION")
            self._resume(tid, "CONT")
            return
        if event["event"] in {3, 128}:
            return
        if event["event"] == 4:
            _require(tid == self.owned.pid and not self.observer._executed and task["call"] is not None and
                     task["call"]["nr"] == 221 and event["event_message"] == tid and
                     base.process._executable_digest(tid) == self.observer._bindings["node_digest"] and
                     base._file_identity(os.stat(f"/proc/{tid}/exe")) == self.observer._executable_identities["node"],
                     "NODE_EXEC_SCOPE")
            self.observer._executed = True
            self._event("EXEC", pid=tid, digest=self.observer._bindings["node_digest"])
            return
        _require(event["event"] == 0 and (event["status"] >> 8 & 255) == 133, "NODE_SIGNAL_REFUSED")
        if event["op"] == "ENTRY":
            _require(task["call"] is None, "NODE_DUPLICATE_ENTRY")
            task["entry_seen"] = True
            call = dict(nr=event["syscall"], args=event["args"], seq=event["seq"])
            task["call"] = call
            nr = call["nr"]
            _require(self.observer._executed or nr == 221, "NODE_GATE_TRANSITION_ONLY")
            if nr in _READS:
                self._file_read(tid, call, deadline)
            elif nr == 222:
                self._mapping(tid, call, deadline)
            elif nr in {220, 435}:
                self._clone(tid, call, deadline)
            elif nr == 221:
                _require(not self.observer._executed and tid == self.owned.pid, "NODE_LATER_EXEC")
            elif nr in _CREATE:
                if nr == 199:
                    _require(call["args"][0] == socket.AF_UNIX and call["args"][1] & 15 in {1, 5} and
                             call["args"][2] == 0, "NODE_SOCKETPAIR_SCOPE")
                self._barrier(deadline)
                result = self._exclusive_exit(tid, call, deadline)
                self._created(tid, call, result["result"], result["is_error"], deadline)
            else:
                _require(nr in _ORDINARY, "NODE_UNSUPPORTED_SYSCALL")
                if nr == 56:  # openat: source acquisition is never write authority.
                    _require(call["args"][2] & (3 | 0x40 | 0x200 | 0x400 | 0x410000) == 0, "NODE_WRITE_OPEN")
                if nr == 29:
                    _require(call["args"][0] in {0, 1, 2} and call["args"][1] in {0x5401, 0x5413},
                             "NODE_IOCTL_UNSUPPORTED")
        elif event["op"] == "EXIT":
            call = task["call"]
            if call is None and "clone_seq" in task and not task["birth_exit"] and not task["entry_seen"]:
                _require(event["result"] == 0 and event["is_error"] is False, "NODE_THREAD_INITIAL_EXIT")
                task["birth_exit"] = True
                self._event("THREAD_START", pid=tid, stop_seq=event["seq"], clone_call_seq=task["clone_seq"])
                return
            if call is None and not self.observer._executed and not self.gate_release_seen:
                _require(tid == self.owned.pid and event["result"] == 0 and event["is_error"] is False and
                         not any(row["kind"] == "STOP" and row["op"] == "ENTRY" for row in self.observer._events),
                         "NODE_GATE_RELEASE")
                self.gate_release_seen = True
                self._event("GATE_RELEASE", pid=tid, stop_seq=event["seq"])
                return
            _require(call is not None, "NODE_ORPHAN_EXIT")
            if call["nr"] == 221:
                _require(self.observer._executed and event["result"] == 0 and not event["is_error"], "NODE_EXEC_FAILED")
            if call.get("io"):
                _require((event["is_error"] and -4095 <= event["result"] < 0) or
                         (event["is_error"] is False and 0 <= event["result"] <= call["count"]), "NODE_IO_RESULT")
                self._event("IO_EXIT", pid=tid, call_id=call["seq"], result=event["result"],
                            is_error=event["is_error"], epoch=self.epoch)
                self._close_duplicate(call["duplicate"])
            if call["nr"] in _CREATE:
                self._created(tid, call, event["result"], event["is_error"], deadline)
            task["call"] = None
        else:
            raise base.PiSourceObserverError("NODE_UNKNOWN_STOP", self.observer)

    def _pump(self, deadline):
        while self.pending_events:
            self._handle(self.pending_events.pop(0), deadline)
        for tid in list(self.tasks):
            task = self.tasks[tid]
            if task["stopped"]:
                self._resume(tid)
        progressed = False
        for tid in list(self.tasks):
            if not self.tasks[tid]["stopped"]:
                progressed |= self._wait_one(tid)
        return progressed

    def _drain(self, deadline):
        """Only release actual EXIT stops after the native owner requests stop."""
        self._budget(deadline)
        for event in list(self.pending_events):
            self.pending_events.remove(event)
            tid = event["pid"]
            if tid in self.tasks and event["event"] == 6:
                self.tasks[tid]["exit_seen"] = True
                self._resume(tid, "CONT")
        progressed = False
        for tid in list(self.tasks):
            # SIGKILL can supersede an ordinary held ptrace stop. Do not resume
            # that stop or re-execute its pending call to make cleanup pass.
            progressed |= self._wait_one(tid)
        return progressed

    def _complete(self):
        for path in self.profile["required_sources"]:
            if path not in self.observer._read_paths:
                return False
            end = 0
            for low, high in sorted(self.observer._ranges[path]):
                if low > end:
                    return False
                end = max(end, high)
            source = next(row for row in self.observer._sources if row["path"] == path)
            if end != source["identity"]["size"]:
                return False
        return True

    def _challenge(self, nonce, issued_ns, deadline_ns):
        _require(type(nonce) is str and re.fullmatch(r"[a-f0-9]{64}", nonce) and
                 type(issued_ns) is int and type(deadline_ns) is int and
                 deadline_ns - issued_ns == base.CHALLENGE_NS and nonce not in self.observer._challenge_nonces and
                 self.observer._last_challenge_end < issued_ns <= base._tick() < deadline_ns, "NODE_CHALLENGE")
        self.observer._challenge_nonces.add(nonce)
        deadline = min(self.operation_deadline, time.monotonic() + (deadline_ns - base._tick()) / 1e9)
        self._barrier(deadline)
        while self.pending_events:
            self._handle(self.pending_events.pop(0), deadline)
        before = self.observer._stops
        for tid in list(self.tasks):
            self._resume(tid)
            self.observer._kernel.ptrace(base._INTERRUPT, tid)
        tasks = self._barrier(deadline)
        while self.pending_events:
            event = self.pending_events.pop(0)
            _require(event["event"] in {0, 128} and not (event["op"] == "ENTRY" and
                     event["syscall"] not in _ORDINARY), "NODE_CHALLENGE_SENSITIVE_PROGRESS")
            self._handle(event, deadline)
        _require(all(t["call"] is None or t["call"]["nr"] in _WAIT_CALLS or t["call"].get("io")
                     for t in self.tasks.values()),
                 "NODE_CHALLENGE_PENDING_SENSITIVE_CALL")
        _require(self._complete() and base._tick() < deadline_ns and all(
            self.observer._events[t["stop_seq"] - 1]["boottime_ns"] >= issued_ns for t in self.tasks.values()),
            "NODE_CHALLENGE_INCOMPLETE")
        self._event("CHALLENGE", nonce=nonce, issued_ns=issued_ns, deadline_ns=deadline_ns,
                    epoch=self.epoch, tasks=tasks, stops_before=before, stops_after=self.observer._stops, all_stopped=True)
        _require(self.observer._events[-1]["boottime_ns"] < deadline_ns, "NODE_CHALLENGE_EXPIRED")
        self.observer._last_challenge_end = self.observer._events[-1]["boottime_ns"]

    def _guard(self, deadline):
        observer = self.observer
        # Existing plan/unit/activation guards remain authoritative; only task
        # inventory and read-only worker-view metadata differ from v1.
        observer._budget(deadline)
        owned = self.owned
        _profile_binding(owned, self.profile, observer._bindings["profile_digest"])
        current = (owned.plan, owned.pid, owned.pidfd, owned.start_ticks, owned.invocation,
                   owned.immutable_digest, owned.cgroup_fd, owned.cgroup_identity,
                   owned.plan._lease, owned.plan.prepared, owned.plan.prepared._lease)
        _require(owned is observer._owned and current == observer._pins and
                 owned.plan._lease.active and owned.plan.prepared._lease.active and
                 owned.plan.prepared.expires_at_monotonic_ns > time.monotonic_ns() and
                 owned.started and not owned.exit_observed and observer._deadline <= owned.plan.deadline,
                 "NODE_OWNER_CUSTODY_CHANGED")
        base.process.require_live_pidfd(observer._pidfd)
        base.native._same_generation(owned, base.native._unit_state(owned.plan.unit_name, deadline), deadline, live=True)
        _require(owned.plan.profile.runtime_digest == owned.plan.runtime_inventory_digest ==
                 owned.plan.prepared.runtime_digest == observer._bindings["runtime_digest"] and
                 owned.plan.prepared.deployment_digest == observer._bindings["deployment_digest"] and
                 owned.plan.profile.executable_digest == owned.plan.prepared.executable_digest ==
                 observer._bindings["node_digest"], "NODE_DEPLOYMENT_CHANGED")
        _require(os.stat(f"/proc/{owned.pid}/ns/time").st_ino == os.stat("/proc/self/ns/time").st_ino ==
                 observer._clock["time_namespace_inode"], "NODE_CLOCK_CHANGED")
        label = "node" if observer._executed else "gate"
        _require(base.process._executable_digest(owned.pid) == observer._bindings[label + "_digest"] and
                 base._file_identity(os.stat(f"/proc/{owned.pid}/exe")) == observer._executable_identities[label],
                 "NODE_EXECUTABLE_CHANGED")
        for fd, metadata, maximum, readonly in self.held_files:
            _require((_readonly(fd, maximum) if readonly else base._protected_file(fd, maximum)) == metadata,
                     "NODE_HELD_CODE_CHANGED")
        self._inventory()
        for row in observer._sources:
            _require(_readonly(observer._source_fds[row["path"]]) == row["identity"], "NODE_HELD_SOURCE_CHANGED")
        for row in self.loaders:
            _require(_readonly(self.loader_fds[row["path"]], base.process._MAX_EXECUTABLE_BYTES) == row["identity"],
                     "NODE_HELD_LOADER_CHANGED")

    def snapshot(self):
        if threading.get_native_id() == self.observer._thread:
            return self._snapshot()
        with self.lock:
            return self._snapshot()

    def _snapshot(self):
        observer = self.observer
        events = observer._events
        enters = [x for x in events if x["kind"] == "READ_ENTER"]
        exits = [x for x in events if x["kind"] == "READ_EXIT"]
        count = lambda kind: sum(x["kind"] == kind for x in events)
        value = dict(schema=SCHEMA, architecture="linux-arm64", bindings=observer._bindings,
            worker=observer._worker, clock=observer._clock, sources=observer._sources,
            required_sources=self.profile["required_sources"], loaders=self.loaders,
            state=observer._state, events=events,
            accounting=dict(stops_acquired=observer._stops, reads_entered=len(enters), reads_exited=len(exits),
                bytes_read=sum(max(x["result"], 0) for x in exits), pending_reads=len(enters)-len(exits),
                refusals=count("REFUSED"), events_retained=len(events), threads_observed=1+count("THREAD"),
                threads_exited=count("THREAD_EXIT"), maps_entered=count("MAP_ENTER"), maps_exited=count("MAP_EXIT"),
                io_entered=count("IO_ENTER"), io_exited=count("IO_EXIT"),
                pending_syscalls=sum(t["call"] is not None for t in self.tasks.values())))
        raw = base.canonical_json(value)
        _require(len(raw) <= base.MAX_RAW, "NODE_RECORD_BOUND")
        return json.loads(raw)

    def command(self, kind, payload, deadline):
        _require(time.monotonic() < deadline <= self.cleanup_deadline and not self.closed.is_set(), "NODE_COMMAND_DEADLINE")
        done, result = threading.Event(), []
        try:
            self.commands.put_nowait((kind, payload, deadline, done, result))
        except queue.Full as error:
            raise base.PiSourceObserverError("NODE_CONCURRENT_COMMAND", self.observer) from error
        if not done.wait(max(0, deadline-time.monotonic())):
            raise base.PiSourceObserverError("NODE_COMMAND_TIMEOUT", self.observer)
        if isinstance(result[0], BaseException):
            raise result[0]
        return result[0]

    def _main(self):
        self.observer._thread = threading.get_native_id()
        try:
            _arm(self)
        except BaseException as error:
            self._refuse(error)
        self.ready.set()
        while True:
            try:
                if self.failure is not None and (not self.stopping or self.drain_failure is not None):
                    item = self.commands.get(timeout=0.1)
                else:
                    item = self.commands.get_nowait()
            except queue.Empty:
                item = None
            if item:
                with self.lock:
                    kind, payload, deadline, done, result = item
                    try:
                        if kind == "stop":
                            self.stopping = True
                            self.observer._state = "REFUSED"
                            result.append(None)
                        elif kind == "close":
                            _require(self.stopping, "NODE_STOP_NOT_BEGUN")
                            _require(self.drain_failure is None, "NODE_CLEANUP_FAILED_NO_RETRY")
                            while self.tasks:
                                self._budget(deadline)
                                self._drain(deadline)
                                time.sleep(0.001)
                            self.observer.close_after_exit()
                            result.append(None)
                            self.closed.set()
                            return
                        elif kind == "health":
                            _require(self.failure is None and not self.stopping, "NODE_OBSERVER_REFUSED")
                            self._barrier(deadline)
                            self.observer.guard_source_health(activation=payload, deadline=deadline)
                            self.latest_health_observation = self._snapshot()
                            result.append(json.loads(base.canonical_json(self.latest_health_observation)))
                        else:
                            raise base.PiSourceObserverError("NODE_COMMAND_KIND", self.observer)
                    except BaseException as error:
                        if kind == "close":
                            self.drain_failure = error
                        self._refuse(error)
                        result.append(base.PiSourceObserverError(str(error), self.observer))
                    finally:
                        done.set()
            try:
                if self.drain_failure is None and (self.failure is None or self.stopping):
                    with self.lock:
                        self._budget()
                        progress = self._drain(self.cleanup_deadline) if self.stopping else self._pump(self.operation_deadline)
                        if not progress:
                            time.sleep(0.001)
                else:
                    time.sleep(0.001)
            except BaseException as error:
                # Retain the same tracer thread and handles for the native
                # owner's cleanup; exiting here would silently arm EXITKILL.
                self._refuse(error)
                if self.stopping:
                    self.drain_failure = error
                time.sleep(0.001)

    def _refuse(self, error):
        if self.failure is None:
            self.failure = error
            try:
                self.observer._fail(error)
            except base.PiSourceObserverError:
                pass


def _arm(session):
    owned, profile = session.owned, session.profile
    _require(base.platform.system() == "Linux" and base.platform.machine() in {"arm64", "aarch64"} and
             os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0, "NODE_LINUX_ARM64_ROOT")
    _require(type(owned) is base.native._Owned and type(owned.plan) is base.confined.PiConfinedLaunchPlan and
             type(owned.plan.prepared) is base.bundle.PreparedPiBundle and owned.connection is None and
             owned.started and owned.start_attempted and owned.pid > 0 and owned.pidfd >= 0 and
             session.operation_deadline <= owned.plan.deadline and
             session.operation_deadline < session.cleanup_deadline <= session.operation_deadline+5, "NODE_PREEXEC_OWNER")
    argv = owned.plan.systemd_run_argv
    _require(argv[argv.index("--") + 1:] == ("/usr/bin/env", "-i", "HOME=/nonexistent",
             "PATH=/opt/aragorn/pi-runtime/node/bin", str(base.GATE_PATH), str(base.NODE_PATH), base.ENTRY_PATH),
             "NODE_GATE_ARGV")
    _require(type(owned.plan._lease) is base.confined._PlanLease and owned.plan._lease.active and
             type(owned.plan.prepared._lease) is base.bundle._Lease and owned.plan.prepared._lease.active and
             owned.plan.prepared.expires_at_monotonic_ns > time.monotonic_ns(), "NODE_ACTIVE_PLAN")
    _profile_binding(owned, profile, base.canonical_digest(profile))
    observer = session.observer
    observer._node_session = session
    observer._owned, observer._deadline = owned, session.operation_deadline
    observer._pins = (owned.plan, owned.pid, owned.pidfd, owned.start_ticks, owned.invocation,
                      owned.immutable_digest, owned.cgroup_fd, owned.cgroup_identity,
                      owned.plan._lease, owned.plan.prepared, owned.plan.prepared._lease)
    observer._bindings = {**profile["pins"], "runtime_digest": owned.plan.profile.runtime_digest,
        "deployment_digest": owned.plan.prepared.deployment_digest, "profile_digest": base.canonical_digest(profile)}
    observer._worker = dict(pid=owned.pid, start_ticks=owned.start_ticks, uid=owned.plan.worker_uid,
        gid=owned.plan.worker_gid, cgroup=owned.plan.profile.cgroup, unit=owned.plan.unit_name, invocation_id=owned.invocation)
    observer._clock = dict(boot_id=base.process._read_virtual_file(Path("/proc/sys/kernel/random/boot_id"),64).decode().strip(),
        clock_id="CLOCK_BOOTTIME", time_namespace_inode=os.stat(f"/proc/{owned.pid}/ns/time").st_ino)
    _require(observer._clock["time_namespace_inode"] == os.stat("/proc/self/ns/time").st_ino, "NODE_CLOCK_NAMESPACE")
    observer._pidfd = os.dup(owned.pidfd)
    observer._fds.append(observer._pidfd)
    status = base.process._read_virtual_file(Path(f"/proc/{owned.pid}/status"), 65536).decode("ascii")
    _require(re.search(r"^State:\s+T\s", status, re.M) and re.search(r"^TracerPid:\s+0$", status,re.M), "NODE_GATE_NOT_STOPPED")
    _require(Path(__file__) == ORIGIN and Path(base.__file__) == base.PRODUCER_PATH, "NODE_PRODUCER_ORIGIN")
    for path, pin in ((ORIGIN,profile["pins"]["node_observer_digest"]),(base.PRODUCER_PATH,profile["pins"]["producer_digest"])):
        fd=base._open_view(os.getpid(),path); observer._fds.append(fd)
        digest, metadata = base._hash(fd,session.operation_deadline)
        _require(digest == pin, "NODE_PRODUCER_PIN")
        session.held_files.append((fd, metadata, base.MAX_FILE, False))
    for path, pin, label in ((base.GATE_PATH,profile["pins"]["gate_digest"],"gate"),
                              (base.NODE_PATH,profile["pins"]["node_digest"],"node")):
        fd=base._open_view(owned.pid,path); observer._fds.append(fd)
        digest, metadata = _hash_readonly(fd,session.operation_deadline,base.process._MAX_EXECUTABLE_BYTES)
        _require(digest == pin, "NODE_EXECUTABLE_PIN")
        observer._executable_identities[label] = metadata
        session.held_files.append((fd, metadata, base.process._MAX_EXECUTABLE_BYTES, True))
    _require(base.process._executable_digest(owned.pid) == profile["pins"]["gate_digest"] and
             base._file_identity(os.stat(f"/proc/{owned.pid}/exe")) == observer._executable_identities["gate"],
             "NODE_GATE_EXECUTABLE")
    identities = set()
    for field, schema, output, fds, maximum in (
        ("sources",SOURCE_SCHEMA,observer._sources,observer._source_fds,base.MAX_FILE),
        ("loader_files",LOADER_SCHEMA,session.loaders,session.loader_fds,base.process._MAX_EXECUTABLE_BYTES)):
        for row in profile[field]:
            fd=base._open_view(owned.pid,Path(row["path"])); observer._fds.append(fd)
            digest, metadata = _hash_readonly(fd,session.operation_deadline,maximum)
            key=metadata["device"],metadata["inode"]
            _require(digest == row["digest"] and key not in identities,"NODE_INVENTORY_PIN_OR_ALIAS")
            identities.add(key); output.append(dict(row,identity=metadata,readonly_view=True)); fds[row["path"]]=fd
            if field=="sources": observer._ranges[row["path"]]=[]
        output.sort(key=lambda row:row["path"])
        pin="source_inventory_digest" if field=="sources" else "loader_inventory_digest"
        _require(base.canonical_digest({"schema":schema,"sources" if field=="sources" else "loaders":output})==profile["pins"][pin],"NODE_INSTALLED_INVENTORY_PIN")
    observer._kernel=base._Kernel()
    observer._kernel.ptrace(base._SEIZE,owned.pid,0,base.OPTIONS); observer._attached=True
    session.tasks[owned.pid]=dict(start_ticks=owned.start_ticks,stopped=False,joined=True,call=None,stop_seq=None,stop_event=None)
    session._event("ARMED",tasks=[owned.pid],options=base.OPTIONS,gate_identity=observer._executable_identities["gate"])
    observer._kernel.ptrace(base._INTERRUPT,owned.pid)
    while not session.tasks[owned.pid]["stopped"]:
        session._budget()
        if not session._wait_one(owned.pid): time.sleep(0.001)
    initial=session.pending_events.pop()
    _require(initial["event"]==128 and initial["op"]=="NONE" and initial["status"]>>8&255 in {5,19},"NODE_GATE_INITIAL_STOP")
    stdio = []
    session._barrier(session.operation_deadline)
    for fd in (0, 1, 2):
        duplicate = session._duplicate(fd)
        metadata = os.fstat(duplicate)
        _require(stat.S_ISCHR(metadata.st_mode) and metadata.st_rdev == os.makedev(1, 3), "NODE_STDIO_NOT_NULL")
        identity = _fd_identity(duplicate)
        session.stdio[fd] = identity
        stdio.append(dict(fd=fd, identity=identity, rdev=metadata.st_rdev))
    session._event("STDIO", descriptors=stdio, epoch=session.epoch)
    session._guard(session.operation_deadline)
    return observer


def start_node_observer(owned, profile, *, operation_deadline, cleanup_deadline):
    _require(type(operation_deadline) in (int,float) and type(cleanup_deadline) in (int,float) and
             math.isfinite(operation_deadline) and math.isfinite(cleanup_deadline) and
             time.monotonic()<operation_deadline<cleanup_deadline,"NODE_START_DEADLINE")
    session=_NodeSession(owned,profile,operation_deadline,cleanup_deadline)
    session.thread.start()
    if not session.ready.wait(max(0,operation_deadline-time.monotonic())):
        raise base.PiSourceObserverError("NODE_ARM_TIMEOUT", session.observer)
    if session.failure is not None:
        raise base.PiSourceObserverError(str(session.failure),session.observer) from session.failure
    return session.observer
