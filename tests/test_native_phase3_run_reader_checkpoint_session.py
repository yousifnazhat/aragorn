"""New session joins over fabricated syscalls; no protected or live IO.

These independent fixtures model a peer's immutable bytes. Production listener,
owning response/store, checkpoint acquisition and both independent consumers run
unchanged. No historical test module or producer/private parser builds fixtures.
"""

import base64
import copy
import fcntl
import hashlib
import json
import os
import select
import stat
import struct
import threading
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from aragorn import native_phase3_run_reader_checkpoint_session as subject
from aragorn import native_phase3_run_reader_transport as transport
from aragorn import native_phase3_run_reader_acquisition as owning
from aragorn import native_phase3_run_reader_response as response
from aragorn import native_phase3_run_reader_store as store
from aragorn import native_phase3_run_reader_checkpoint_acquisition as checkpoint
from aragorn import native_phase3_clock_domain as clock
from aragorn import runtime_process_profile as process
from aragorn import runtime_action_broker as broker


FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized",
         "run_qualified", "phase3_qualified")
PREFIX = "aragorn/native-phase3-reader-"
ROOT, READER, BRIDGE, SENSOR, SUPERVISOR = 701, 702, 703, 704, 705
NOTICE, READER_PIDFD, REFRESH, COMPLETION, CANCEL = 20, 21, 22, 23, 24
SOURCE = "/var/lib/aragorn-phase3-reader-events"
ARCHIVE = "/var/lib/aragorn-phase3-reader-checkpoints"
SOCKET_PATH = "/run/aragorn-phase3-reader/challenge.sock"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def pin(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def artifact(raw):
    return dict(base64=base64.b64encode(raw).decode("ascii"), bytes=len(raw), digest=pin(raw))


class Node:
    def __init__(self, inode, mode, uid=0, gid=0, raw=b"", kind="file", device=7):
        self.inode, self.mode, self.uid, self.gid = inode, mode, uid, gid
        self.raw, self.kind, self.device = raw, kind, device
        self.links, self.mtime, self.ctime = 1, 10, 10

    def info(self):
        return SimpleNamespace(st_dev=self.device, st_ino=self.inode, st_mode=self.mode,
                               st_uid=self.uid, st_gid=self.gid, st_nlink=self.links,
                               st_size=len(self.raw), st_mtime_ns=self.mtime, st_ctime_ns=self.ctime)


class Socket:
    """Fabricated Linux seqpacket endpoint; every method is local state only."""

    def __init__(self, kernel, accepted=False):
        self.kernel, self.family, self.accepted = kernel, 1, accepted
        self.node = kernel.node(stat.S_IFSOCK | 0o600, kind="socket")
        self.fd = kernel.descriptor(self.node, os.O_CLOEXEC | os.O_NONBLOCK)
        kernel.sockets[self.fd] = self
        self.options = {16: 1, 76: 0}
        self.path = SOCKET_PATH if accepted else ""
        self.response_raw = None
        self.pending = False
        self.closed = False

    def fileno(self):
        return self.fd

    def gettimeout(self):
        return 0.0

    def setblocking(self, value):
        if value is not False:
            raise AssertionError("unexpected blocking socket")

    def get_inheritable(self):
        return self.kernel.get_inheritable(self.fd)

    def set_inheritable(self, value):
        if value:
            raise AssertionError("unexpected inheritable socket")
        self.kernel.fds[self.fd]["flags"] |= os.O_CLOEXEC

    def getsockopt(self, level, option, size=None):
        if level != 1:
            raise AssertionError("unexpected socket level")
        if option == 3:
            return 5
        if option == 17:
            p = self.kernel.roles["reader"]
            return struct.pack("=iII", p["pid"], p["uid"], p["gid"])
        if option == 77:
            return self.kernel.pidfd_open(READER, 0)
        return self.options[option]

    def setsockopt(self, level, option, value):
        if level != 1 or option not in (16, 76):
            raise AssertionError("unexpected socket option")
        self.options[option] = value

    def getsockname(self):
        return self.path

    def bind(self, path):
        if path != SOCKET_PATH or path in self.kernel.files:
            raise AssertionError("unexpected bind")
        self.path = path
        self.kernel.files[path] = self.kernel.node(stat.S_IFSOCK | 0o700)
        self.kernel.events.append(("bind", path))

    def listen(self, backlog):
        if backlog != 1:
            raise AssertionError("unexpected backlog")
        self.kernel.listener = self

    def accept(self):
        if not self.pending:
            raise BlockingIOError()
        self.pending = False
        self.kernel.events.append(("accept", self.fd))
        return Socket(self.kernel, accepted=True), ""

    def send(self, raw, flags):
        if not self.accepted or flags != 0x4040:
            raise AssertionError("unexpected challenge send")
        challenge = json.loads(raw)
        self.kernel.challenge_raw = raw
        self.kernel.events.append(("challenge", pin(raw)))
        completion, ack = self.kernel.publish_peer("CHALLENGE", challenge, raw)
        self.kernel.completions.append(completion)
        self.response_raw = encoded(dict(schema="aragorn/native-phase3-run-reader-response/v1",
                                         epoch_digest=challenge["epoch_digest"], challenge_digest=pin(raw),
                                         request_digest=challenge["request_digest"],
                                         sequence_after=self.kernel.peer_sequence, ack_ns=ack))
        return len(raw)

    def recvmsg(self, maximum, controls_size, flags):
        if (maximum, controls_size, flags) != (4097, 4096, 0x40000040):
            raise AssertionError("unexpected receive ABI")
        if self.response_raw is None:
            raise BlockingIOError()
        raw, self.response_raw = self.response_raw, None
        p = self.kernel.roles["reader"]
        credentials = struct.pack("=iII", p["pid"], p["uid"], p["gid"])
        return raw, [(1, 2, credentials)], 0x80, ""

    def close(self):
        if self.closed:
            raise AssertionError("socket closed twice")
        self.closed = True
        self.kernel.close(self.fd)
        self.kernel.events.append(("connection-close" if self.accepted else "listener-close", self.fd))

    def detach(self):
        fd, self.fd = self.fd, -1
        return fd


class Poll:
    def __init__(self, kernel):
        self.kernel, self.registered = kernel, {}

    def register(self, fd, mask):
        self.registered[fd] = mask

    def poll(self, timeout):
        result = []
        for fd in self.registered:
            if fd not in self.kernel.fds:
                result.append((fd, select.POLLNVAL))
                continue
            row = self.kernel.fds[fd]
            if row.get("pid") in self.kernel.dead:
                result.append((fd, select.POLLIN))
            elif fd == CANCEL and self.kernel.cancel_eof:
                result.append((fd, select.POLLIN | select.POLLHUP))
            elif fd == CANCEL and self.kernel.cancel_bytes:
                result.append((fd, select.POLLIN))
            elif fd == COMPLETION and self.kernel.completions:
                result.append((fd, select.POLLIN))
            elif fd in self.kernel.sockets:
                sock = self.kernel.sockets[fd]
                if sock.pending or sock.response_raw is not None:
                    result.append((fd, select.POLLIN | (select.POLLHUP if self.kernel.peer_hup else 0)))
        if not result and timeout:
            self.kernel.now += timeout * 1000000
        if self.kernel.poll_hook is not None:
            self.kernel.poll_hook(self, result)
        return result


class Kernel:
    """Strict syscall model; unexpected paths/descriptors fail instead of escaping."""

    def __init__(self, batch=b""):
        self.now, self.next_inode, self.next_fd = 1000000000, 1000, 100
        self.files, self.fds, self.remote, self.sockets = {}, {}, {}, {}
        self.events, self.closed, self.completions = [], [], []
        self.dead, self.groups = set(), {}
        self.cancel_eof, self.cancel_bytes, self.peer_hup = False, b"", False
        self.poll_hook = self.read_hook = self.write_hook = self.fsync_hook = None
        self.close_failure, self.read_failure = None, None
        self.completion_chunk = 2049
        self.boot = "12345678-1234-1234-1234-123456789abc"
        self.clock = dict(boot_id=self.boot, clock_id="CLOCK_BOOTTIME", time_namespace=dict(device=7, inode=900))
        self.roles = {name: dict(pid=pid, start_time_ticks=pid * 2, uid=uid, gid=gid)
                      for name, pid, uid, gid in (("observer", ROOT, 0, 0), ("reader", READER, 1001, 1002),
                                                  ("bridge", BRIDGE, 1003, 1004), ("sensor", SENSOR, 0, 0),
                                                  ("supervisor", SUPERVISOR, 0, 0))}
        self.namespace = Node(900, stat.S_IFREG | 0o444)
        for path, mode, uid, gid in (("/", 0o755, 0, 0), ("/var", 0o755, 0, 0),
                                     ("/var/lib", 0o755, 0, 0), ("/run", 0o755, 0, 0),
                                     ("/run/aragorn-phase3-reader", 0o710, 0, 1002),
                                     ("/var/lib/aragorn-phase3-reader", 0o700, 0, 0),
                                     (SOURCE, 0o700, 1001, 1002), (ARCHIVE, 0o700, 0, 0)):
            self.files[path] = self.node(stat.S_IFDIR | mode, uid, gid)
        self.pipes = []
        endpoints = (("NOTICE", "OBSERVER", NOTICE, [("READER", 3)]),
                     ("TELEMETRY", "BRIDGE", 1, [("READER", 4)]),
                     ("REFRESH", "OBSERVER", REFRESH, [("READER", 5)]),
                     ("STDERR", "BRIDGE", 2, [("READER", 6)]),
                     ("CANCEL", "SUPERVISOR", 9, [("READER", 7), ("OBSERVER", CANCEL)]),
                     ("COMPLETION", "READER", 8, [("OBSERVER", COMPLETION)]))
        for name, role, fd, readers in endpoints:
            node = self.node(stat.S_IFIFO | 0o600, kind="pipe")
            self.pipes.append(dict(role=name, device=7, inode=node.inode, mode=node.mode, uid=0, gid=0,
                                   writer=dict(process=role, fd=fd),
                                   readers=[dict(process=r, fd=f) for r, f in readers]))
            for r, f, write in [(role, fd, True), *((r, f, False) for r, f in readers)]:
                row = dict(node=node, flags=os.O_CLOEXEC | os.O_NONBLOCK | (os.O_WRONLY if write else os.O_RDONLY),
                           offset=0, path=None)
                self.remote[(self.roles[r.lower()]["pid"], f)] = row
                if r == "OBSERVER":
                    self.fds[f] = row
        self.fds[READER_PIDFD] = dict(node=self.node(stat.S_IFREG | 0o600, kind="pidfd"),
                                     flags=os.O_CLOEXEC, offset=0, pid=READER, path=None)
        self.stream = dict(schema=PREFIX + "stream-inventory/v1", session_id="a" * 64, **self.roles,
                           clock=self.clock, source_inventory_digest="sha256:" + "1" * 64,
                           access_inventory_digest="sha256:" + "2" * 64, pipes=self.pipes,
                           upstream_continuity="UNKNOWN", upstream_socket_digest=None, upstream_loss_digest=None)
        self.stream_raw = encoded(self.stream)
        p = dict(boot_id=self.boot, reader_pid=READER, reader_start_ticks=READER * 2,
                 sensor_pid=SENSOR, sensor_start_ticks=SENSOR * 2, reader_uid=1001, reader_gid=1002,
                 sensor_uid=0, sensor_gid=0, reader_source_digest="sha256:" + "3" * 64,
                 sensor_source_digest="sha256:" + "4" * 64, stream_digest=pin(self.stream_raw),
                 program_map_digest="sha256:" + "5" * 64)
        self.epoch = dict(process=p, clock=dict(boot_id=self.boot, clock_id="CLOCK_BOOTTIME", time_namespace_inode=900),
                          loss_scope=["sha256:" + "6" * 64], policy=dict(timeout_ns=100000000, max_age_ns=200000000),
                          deployment_digest="sha256:" + "7" * 64)
        self.epoch_raw = encoded(self.epoch)
        self.provision = dict(schema=PREFIX + "checkpoint-provision/v1", epoch_digest=pin(self.epoch_raw),
                              session_id=self.stream["session_id"], reader=self.roles["reader"], observer=self.roles["observer"],
                              clock=self.clock, stream_digest=pin(self.stream_raw),
                              source_inventory_digest=self.stream["source_inventory_digest"],
                              access_inventory_digest=self.stream["access_inventory_digest"],
                              directories=[self.directory(path) for path in ("/", "/var", "/var/lib", SOURCE, ARCHIVE)],
                              session_deadline_ns=10000000000)
        self.provision_raw = encoded(self.provision)
        self.transport = dict(schema="aragorn/native-phase3-run-reader-transport-provision/v1",
                              epoch_digest=pin(self.epoch_raw), observer={**self.roles["observer"], "time_namespace": self.clock["time_namespace"]},
                              directories=[self.directory(path) for path in ("/", "/run", "/run/aragorn-phase3-reader")],
                              notice_pipe={**{k: self.pipes[0][k] for k in ("device", "inode", "mode", "uid", "gid")}, "reader_fd": 3},
                              session_deadline_ns=10000000000, max_requests=4,
                              access_inventory_digest=self.stream["access_inventory_digest"])
        self.transport_raw = encoded(self.transport)
        self.loop = dict(schema=PREFIX + "loop-provision/v1", epoch_digest=pin(self.epoch_raw),
                         checkpoint_provision_digest=pin(self.provision_raw), transport_provision_digest=pin(self.transport_raw),
                         stream_digest=pin(self.stream_raw), session_id=self.stream["session_id"],
                         startup_deadline_ns=1200000000, session_deadline_ns=10000000000, max_requests=4)
        self.loop_raw = encoded(self.loop)
        self.startup_raw = encoded(dict(schema=PREFIX + "loop-ready/v1", session_id=self.stream["session_id"],
                                        epoch_digest=pin(self.epoch_raw), loop_provision_digest=pin(self.loop_raw),
                                        stream_digest=pin(self.stream_raw), ready_ns=self.now)) + b"\n"
        self.completions.append(self.startup_raw)
        self.peer_sequence = self.peer_offset = self.peer_records = 0
        self.peer_manifest = self.challenge_raw = None
        self.batch = batch
        self.notice = None
        self.random_counter = 0

    def node(self, mode, uid=0, gid=0, raw=b"", kind="file"):
        self.next_inode += 1
        return Node(self.next_inode, mode, uid, gid, raw, kind)

    def descriptor(self, node, flags, path=None, pid=None):
        self.next_fd += 1
        if self.next_fd in self.fds:
            raise AssertionError("fake descriptor reused")
        self.fds[self.next_fd] = dict(node=node, flags=flags, offset=0, path=path, pid=pid)
        return self.next_fd

    def directory(self, path):
        n = self.files[path]
        return dict(path=path, device=7, inode=n.inode, mode=n.mode, uid=n.uid, gid=n.gid)

    def stamp(self, clock_id=7):
        if clock_id != 7:
            raise AssertionError("unexpected clock")
        self.now += 100
        return self.now

    def path(self, path, dir_fd=None):
        path = str(path)
        if path.startswith("/"):
            return path
        if dir_fd is None or dir_fd not in self.fds or self.fds[dir_fd]["path"] is None:
            raise AssertionError("unexpected relative path")
        return self.fds[dir_fd]["path"].rstrip("/") + "/" + path

    def fd_path(self, path):
        parts = path.split("/")
        if len(parts) == 5 and parts[1] == "proc" and parts[3] == "fd":
            pid = ROOT if parts[2] == "self" else int(parts[2])
            fd = int(parts[4])
            return self.fds[fd] if pid == ROOT else self.remote[(pid, fd)]
        return None

    def virtual(self, path):
        if path == "/proc/sys/kernel/random/boot_id":
            return (self.boot + "\n").encode()
        parts = path.split("/")
        if len(parts) == 5 and parts[1] == "proc" and parts[3] == "fdinfo":
            pid = ROOT if parts[2] == "self" else int(parts[2])
            fd = int(parts[4])
            row = self.fds[fd] if pid == ROOT else self.remote[(pid, fd)]
            return (f"pos:\t0\nflags:\t{row['flags']:o}\n" +
                    (f"Pid:\t{row['pid']}\n" if row.get("pid") is not None else "")).encode()
        if len(parts) == 4 and parts[1] == "proc":
            pid = int(parts[2])
            p = next(value for value in self.roles.values() if value["pid"] == pid)
            if parts[3] == "stat":
                return (f"{pid} (fixture) S " + "0 " * 18 + str(p["start_time_ticks"]) + " 0\n").encode()
            if parts[3] == "status":
                lines = ["Name:\tfixture", "Umask:\t0077", "NoNewPrivs:\t1",
                         "Uid:\t" + "\t".join([str(p["uid"])] * 4),
                         "Gid:\t" + "\t".join([str(p["gid"])] * 4),
                         "Groups:\t" + self.groups.get(pid, "")]
                lines += [name + ":\t0000000000000000" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")]
                return ("\n".join(lines) + "\n").encode()
        raise AssertionError("unhandled fake proc path: " + path)

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        path = self.path(path, dir_fd)
        if path.startswith("/proc/"):
            node = self.namespace if path.endswith("/ns/time") else self.node(stat.S_IFREG | 0o444, raw=self.virtual(path))
        elif flags & os.O_CREAT:
            if not flags & os.O_EXCL:
                raise AssertionError("nonexclusive protected write")
            if path in self.files:
                raise FileExistsError(path)
            node = self.files[path] = self.node(stat.S_IFREG | mode)
            self.events.append(("create", path))
        else:
            if path not in self.files:
                raise FileNotFoundError(path)
            node = self.files[path]
        self.events.append(("open", path, flags))
        return self.descriptor(node, flags, path)

    def fstat(self, fd):
        return self.fds[fd]["node"].info()

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        path = self.path(path, dir_fd)
        row = self.fd_path(path)
        if row is not None:
            return row["node"].info()
        if path.endswith("/ns/time") and path.startswith("/proc/"):
            return self.namespace.info()
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path].info()

    def readlink(self, path):
        path = str(path)
        row = self.fd_path(path)
        if row is not None and row["node"].kind == "pipe":
            return f"pipe:[{row['node'].inode}]"
        if path.endswith("/ns/time") and path.startswith("/proc/"):
            return f"time:[{self.namespace.inode}]"
        raise AssertionError("unexpected readlink: " + path)

    def read(self, fd, maximum):
        row = self.fds[fd]
        if self.read_failure is not None and self.read_failure == row["path"]:
            raise OSError("fabricated read failure")
        if fd == CANCEL:
            if self.cancel_eof:
                raw = b""
            elif self.cancel_bytes:
                raw, self.cancel_bytes = self.cancel_bytes[:maximum], self.cancel_bytes[maximum:]
            else:
                raise BlockingIOError()
        elif fd == COMPLETION:
            if not self.completions:
                raise BlockingIOError()
            count = min(maximum, self.completion_chunk)
            raw = self.completions[0][:count]
            self.completions[0] = self.completions[0][count:]
            if not self.completions[0]:
                self.completions.pop(0)
        else:
            raw = row["node"].raw[row["offset"]:row["offset"] + maximum]
            row["offset"] += len(raw)
        if self.read_hook is not None:
            self.read_hook(fd, raw)
        return raw

    def pread(self, fd, maximum, offset):
        return self.fds[fd]["node"].raw[offset:offset + maximum]

    def write(self, fd, raw):
        raw = bytes(raw)
        if self.write_hook is not None:
            result = self.write_hook(fd, raw)
            if result is not None:
                return result
        if fd == NOTICE:
            self.notice = json.loads(raw)
            self.listener.pending = True
            self.events.append(("notice", raw))
        elif fd == REFRESH:
            command = json.loads(raw)
            self.events.append(("refresh", raw))
            completion, _ = self.publish_peer("REFRESH", command, raw)
            self.completions.append(completion)
        else:
            row = self.fds[fd]
            if row["node"].kind != "file" or row["path"] is None:
                raise AssertionError("unexpected write")
            node = row["node"]
            node.raw += raw
            node.mtime += 1
            node.ctime += 1
            self.events.append(("write", row["path"], len(raw)))
        return len(raw)

    def fsync(self, fd):
        self.events.append(("fsync", self.fds[fd]["path"]))
        if self.fsync_hook is not None:
            self.fsync_hook(fd)

    def close(self, fd):
        if fd in self.closed or fd not in self.fds:
            raise AssertionError("descriptor close repeated/unknown")
        self.closed.append(fd)
        row = self.fds.pop(fd)
        if self.close_failure is not None and (self.close_failure == row["path"] or self.close_failure == fd):
            raise OSError("fabricated close failure")

    def pidfd_open(self, pid, flags):
        if flags != 0 or pid not in {READER, BRIDGE, SUPERVISOR}:
            raise AssertionError("unexpected PIDFD")
        return self.descriptor(self.node(stat.S_IFREG | 0o600, kind="pidfd"), os.O_CLOEXEC, pid=pid)

    def get_inheritable(self, fd):
        return not bool(self.fds[fd]["flags"] & os.O_CLOEXEC)

    def fcntl(self, fd, command):
        flags = self.fds[fd]["flags"]
        if command == fcntl.F_GETFL:
            return flags & ~os.O_CLOEXEC
        if command == fcntl.F_GETFD:
            return 0 if self.get_inheritable(fd) else fcntl.FD_CLOEXEC
        raise AssertionError("unexpected fcntl")

    def chmod(self, path, mode, *, dir_fd=None, follow_symlinks=True):
        node = self.files[self.path(path, dir_fd)]
        node.mode = stat.S_IFMT(node.mode) | mode

    def chown(self, path, uid, gid, *, dir_fd=None, follow_symlinks=True):
        node = self.files[self.path(path, dir_fd)]
        node.uid, node.gid = uid, gid

    def random(self, count):
        if count != 32:
            raise AssertionError("unexpected entropy size")
        self.random_counter += 1
        return bytes([self.random_counter]) * count

    def publish_peer(self, phase, trigger, trigger_raw):
        """Independent fabricated peer artifacts, never producer helper output."""
        received = self.stamp()
        reads = []
        batch = self.batch
        if batch:
            reads.append(dict(started_ns=self.stamp(), finished_ns=self.stamp(), offset=self.peer_offset,
                              bytes=len(batch), outcome="DATA"))
        reads.append(dict(started_ns=self.stamp(), finished_ns=self.stamp(), offset=self.peer_offset + len(batch),
                          bytes=0, outcome="EAGAIN"))
        manifest = dict(schema=PREFIX + "checkpoint/v1", provision_digest=pin(self.provision_raw),
                         epoch_digest=pin(self.epoch_raw), session_id=self.stream["session_id"], stream_digest=pin(self.stream_raw),
                         phase=phase, request_digest=trigger["request_digest"],
                         challenge_digest=pin(trigger_raw) if phase == "CHALLENGE" else trigger["challenge_digest"],
                         trigger_digest=pin(trigger_raw), previous_checkpoint_digest=self.peer_manifest,
                         sequence_before=self.peer_sequence, sequence_after=self.peer_sequence + 1,
                         offset_before=self.peer_offset, offset_after=self.peer_offset + len(batch),
                         records_before=self.peer_records, records_after=self.peer_records + batch.count(b"\n"),
                         clock=self.clock, trigger_received_ns=received, reads=reads, drain_finished_ns=self.stamp(),
                         raw_digest=pin(batch), raw_bytes=len(batch), raw_records=batch.count(b"\n"),
                         raw_publish_started_ns=self.stamp(), raw_readback_finished_ns=self.stamp(),
                         manifest_prepared_ns=self.stamp(), loss_scope_digest=pin(encoded(self.epoch["loss_scope"])),
                         loss_evidence_digest=None, upstream_loss_state="UNKNOWN")
        manifest_raw = encoded(manifest)
        receipt_raw = encoded(dict(schema=PREFIX + "checkpoint-publication/v1", manifest_digest=pin(manifest_raw),
                                   raw_digest=pin(batch), sequence_after=manifest["sequence_after"],
                                   manifest_publish_started_ns=self.stamp(), manifest_readback_finished_ns=self.stamp(),
                                   receipt_prepared_ns=self.stamp()))
        names = {f"batch-{self.stream['session_id']}-{manifest['sequence_after']}.ndjson": batch,
                 phase.lower() + "-" + pin(trigger_raw)[7:] + ".json": manifest_raw,
                 "receipt-" + pin(manifest_raw)[7:] + ".json": receipt_raw}
        for name, raw in names.items():
            path = SOURCE + "/" + name
            if path in self.files:
                raise AssertionError("fabricated peer overwrote immutable source")
            self.files[path] = self.node(stat.S_IFREG | 0o400, 1001, 1002, raw)
        completion = encoded(dict(schema=PREFIX + "checkpoint-ready/v1", session_id=self.stream["session_id"],
                                   epoch_digest=pin(self.epoch_raw), phase=phase,
                                   ordinal=self.notice["ordinal"] if phase == "CHALLENGE" else trigger["ordinal"],
                                   request_digest=trigger["request_digest"], challenge_digest=manifest["challenge_digest"],
                                   trigger_digest=pin(trigger_raw), sequence_after=manifest["sequence_after"],
                                   manifest_digest=pin(manifest_raw), publication_digest=pin(receipt_raw),
                                   batch_digest=pin(batch), completed_ns=self.stamp())) + b"\n"
        self.peer_sequence = manifest["sequence_after"]
        self.peer_offset, self.peer_records = manifest["offset_after"], manifest["records_after"]
        self.peer_manifest = pin(manifest_raw)
        self.events.append(("peer-publication", phase, pin(manifest_raw)))
        return completion, self.stamp()

    def arguments(self):
        return dict(epoch_raw=self.epoch_raw, expected_epoch_digest=pin(self.epoch_raw),
                    checkpoint_provision_raw=self.provision_raw, expected_checkpoint_provision_digest=pin(self.provision_raw),
                    transport_provision_raw=self.transport_raw, expected_transport_provision_digest=pin(self.transport_raw),
                    stream_inventory_raw=self.stream_raw, expected_stream_digest=pin(self.stream_raw),
                    loop_provision_raw=self.loop_raw, expected_loop_provision_digest=pin(self.loop_raw),
                    notice_write_fd=NOTICE, reader_pidfd=READER_PIDFD, refresh_write_fd=REFRESH,
                    completion_read_fd=COMPLETION, cancel_read_fd=CANCEL)

    def request(self, ordinal=1):
        received = self.stamp()
        nonce = f"{ordinal:064x}"
        context = dict(schema="aragorn/native-phase3-broker-reader-context/v1", request_digest=pin(b"request" + nonce.encode()),
                        effect_digest=pin(b"effect" + nonce.encode()), grant_digest=pin(b"grant"),
                        deployment_digest=self.epoch["deployment_digest"], epoch_digest=pin(self.epoch_raw),
                        broker=dict(pid=706, start_time_ticks=1412, uid=1005, gid=1006), provider=self.roles["observer"],
                        clock=self.clock, exchange_id=nonce, accepted_boottime_ns=received - 200,
                        deadline_boottime_ns=received - 100 + 500000000,
                        clock_bracket=dict(boottime_before_ns=received - 100, monotonic_ns=received - 100,
                                           boottime_after_ns=received, original_monotonic_deadline_ns=received - 100 + 500000000))
        context_raw = encoded(context)
        packet = dict(schema="aragorn/native-phase3-broker-reader-request/v1", phase="BEFORE_CONNECT",
                       context_digest=pin(context_raw), previous_response_digest=None,
                       **{key: context[key] for key in ("exchange_id", "epoch_digest", "request_digest", "effect_digest", "deadline_boottime_ns")})
        return dict(context_raw=context_raw, expected_context_digest=pin(context_raw), request_raw=encoded(packet),
                    admission_digest=pin(b"admission" + nonce.encode()), request_received_ns=received)

    def refresh(self, initial, result, status="EVIDENCE"):
        # This fabricated opaque loss record exercises only the frozen wire and
        # session joins. None/None is not loss evidence; a real service must
        # REFUSE/LOSS_UNAVAILABLE until protected loss acquisition/replay exists.
        original = json.loads(initial["request_raw"])
        owned = result["owned"]
        loss = encoded(dict(epoch_digest=owned["bindings"]["epoch"], challenge_digest=owned["bindings"]["challenge"],
                            request_digest=owned["bindings"]["request"], scope_digest=owned["bindings"]["loss_scope"],
                            before=None, after=None))
        response_record = dict(schema="aragorn/native-phase3-broker-reader-response/v1",
                                request_packet_digest=pin(initial["request_raw"]),
                                **{key: original[key] for key in ("exchange_id", "phase", "context_digest", "epoch_digest",
                                                                  "request_digest", "effect_digest")},
                                received_ns=initial["request_received_ns"], finished_ns=self.stamp(), status=status,
                                error_codes=[] if status == "EVIDENCE" else ["LOSS_UNAVAILABLE"],
                                reader_connection_epoch=owned["connection_epoch"], bindings=owned["bindings"],
                                reader_evidence=artifact(owned["evidence_raw"]), reader_summary=artifact(encoded(owned["reader"])),
                                reader_retention=dict(digest=owned["evidence_digest"], bytes=len(owned["evidence_raw"])),
                                loss_record=artifact(loss) if status == "EVIDENCE" else None,
                                checkpoint_record=artifact(result["checkpoint"]["acquisition_raw"]), **dict.fromkeys(FLAGS, False))
        response_raw = encoded(response_record)
        second = {**original, "phase": "BEFORE_PAYLOAD_SEND", "previous_response_digest": pin(response_raw)}
        return dict(context_raw=initial["context_raw"], expected_context_digest=initial["expected_context_digest"],
                    request_raw=encoded(second), first_response_raw=response_raw,
                    expected_first_response_digest=pin(response_raw), request_received_ns=self.stamp())

    def __enter__(self):
        self.stack = ExitStack()
        constants = {name: getattr(os, name) for name in dir(os) if name.startswith("O_")}
        constants.setdefault("O_PATH", 0x200000)
        fake_os = SimpleNamespace(**constants, open=self.open, read=self.read, pread=self.pread, write=self.write,
                                  fstat=self.fstat, stat=self.stat, readlink=self.readlink, close=self.close,
                                  fsync=self.fsync, pidfd_open=self.pidfd_open, getpid=lambda: ROOT,
                                  getresuid=lambda: (0, 0, 0), getresgid=lambda: (0, 0, 0),
                                  geteuid=lambda: 0, getegid=lambda: 0, get_inheritable=self.get_inheritable,
                                  fpathconf=lambda fd, name: 4096, chmod=self.chmod, chown=self.chown, urandom=self.random)
        fake_select = SimpleNamespace(poll=lambda: Poll(self), **{n: getattr(select, n) for n in
                                      ("POLLIN", "POLLOUT", "POLLERR", "POLLHUP", "POLLNVAL")})
        fake_socket = SimpleNamespace(AF_UNIX=1, SOL_SOCKET=1, SO_TYPE=3, SOCK_SEQPACKET=5, SCM_RIGHTS=1,
                                      MSG_DONTWAIT=0x40, MSG_EOR=0x80,
                                      socket=lambda family, flags: Socket(self))
        modules = (subject, transport, owning, response, store, checkpoint, clock, process, broker)
        for module in modules:
            for name, value in (("os", fake_os), ("select", fake_select),
                                ("time", SimpleNamespace(CLOCK_BOOTTIME=7, clock_gettime_ns=self.stamp)),
                                ("sys", SimpleNamespace(platform="linux", byteorder="little")),
                                ("threading", SimpleNamespace(get_native_id=lambda: ROOT, Lock=threading.Lock)),
                                ("socket", fake_socket), ("fcntl", SimpleNamespace(F_GETFL=fcntl.F_GETFL,
                                    F_GETFD=fcntl.F_GETFD, FD_CLOEXEC=fcntl.FD_CLOEXEC, fcntl=self.fcntl))):
                if hasattr(module, name):
                    self.stack.enter_context(patch.object(module, name, value))
        for module in (subject, checkpoint):
            self.stack.enter_context(patch.object(module, "_ORIGINAL_PID", ROOT))
        for name, value in (("_NOSIGNAL", 0x4000), ("_CLOEXEC", 0x40000000), ("_PASSCRED", 16),
                            ("_PEERCRED", 17), ("_PASSPIDFD", 76), ("_CREDENTIALS", 2), ("_PIDFD", 4)):
            self.stack.enter_context(patch.object(response, name, value))
        self.stack.enter_context(patch.object(process, "_SO_PEERPIDFD", 77))
        return self

    def __exit__(self, *args):
        self.stack.__exit__(*args)


class ReaderCheckpointSessionTests(unittest.TestCase):
    def construct(self, kernel, **changes):
        return subject.ReaderCheckpointSession(**{**kernel.arguments(), **changes})

    def rejected(self, call):
        with self.assertRaises(subject.ReaderCheckpointSessionError) as caught:
            call()
        return caught.exception

    def test_public_challenge_and_refresh_run_real_listener_acquisitions_and_independent_replay(self):
        with Kernel(b'{"unrecognized":{"payload":3}}\n') as k:
            owner = self.construct(k)
            initial = k.request()
            first = owner.acquire_challenge(**initial)
            second = owner.acquire_refresh(**k.refresh(initial, first))
            self.assertEqual(json.loads(first["reader_verification_raw"])["status"], "CONSISTENT_READER_EVIDENCE")
            self.assertEqual(json.loads(second["checkpoint_verification_raw"])["status"], "CONSISTENT_CHECKPOINT_READBACK")
            self.assertEqual(second["owned"], first["owned"])
            self.assertEqual(second["reader_verification_raw"], first["reader_verification_raw"])
            self.assertEqual(json.loads(second["expectation_raw"])["previous_checkpoint_digest"],
                             pin(first["checkpoint"]["manifest_raw"]))
            self.assertEqual(json.loads(second["checkpoint"]["manifest_raw"])["sequence_after"], 2)
            self.assertEqual(len([e for e in k.events if e[0] == "challenge"]), 1)
            self.assertEqual(len([e for e in k.events if e[0] == "accept"]), 1)
            self.assertEqual(len([e for e in k.events if e[0] == "refresh"]), 1)
            self.assertEqual(first["startup_ready_raw"], k.startup_raw)
            self.assertEqual(json.loads(first["opening_transport_raw"])["operation"], "OPEN")
            for result in (first, second):
                record = json.loads(result["session_raw"])
                self.assertTrue(all(record[f] is False for f in FLAGS))
                self.assertEqual(record["stream_continuity"], "UNKNOWN")
                self.assertEqual(record["loss_completeness"], "UNKNOWN")
                completion = json.loads(result["completion_raw"])
                acquisition = json.loads(result["checkpoint"]["acquisition_raw"])
                self.assertLessEqual(completion["completed_ns"], record["completion_received_ns"])
                self.assertLessEqual(record["completion_received_ns"], acquisition["started_ns"])
            names = [e[1] for e in k.events if e[0] == "create" and e[1].startswith(ARCHIVE + "/")]
            self.assertEqual([n.rsplit("-", 1)[1] for n in names],
                             ["claim.json", "batch.ndjson", "manifest.json", "publication.json", "acquisition.json"] * 2)
            owner.finish_request(expected_context_digest=initial["expected_context_digest"])
            owner.close()
            self.assertEqual(len(k.closed), len(set(k.closed)))
            self.assertIn(SOCKET_PATH, k.files)
            self.assertEqual(k.fds, {})

    def test_idle_checkpoint_and_next_admission_use_acquired_sequence_and_manifest(self):
        with Kernel() as k:
            owner = self.construct(k)
            first_args = k.request()
            first = owner.acquire_challenge(**first_args)
            owner.finish_request(expected_context_digest=first_args["expected_context_digest"])
            second = owner.acquire_challenge(**k.request(2))
            expectation = json.loads(second["expectation_raw"])
            self.assertEqual((expectation["sequence_before"], expectation["sequence_after"]), (1, 2))
            self.assertEqual(expectation["previous_checkpoint_digest"], pin(first["checkpoint"]["manifest_raw"]))
            self.assertEqual(second["checkpoint"]["batch_raw"], b"")
            self.assertEqual(json.loads(second["checkpoint"]["manifest_raw"])["reads"][-1]["outcome"], "EAGAIN")
            self.assertEqual(len([e for e in k.events if e[0] == "bind"]), 1)
            owner.close()

    def test_startup_is_required_before_listener_and_retained_on_open_failure(self):
        with Kernel() as k:
            k.completions.clear()
            error = self.rejected(lambda: self.construct(k))
            self.assertIsNone(error.observed["opening_transport_raw"])
            self.assertNotIn(SOCKET_PATH, k.files)
        with Kernel() as k:
            k.files[SOCKET_PATH] = k.node(stat.S_IFSOCK | 0o660, gid=1002)
            error = self.rejected(lambda: self.construct(k))
            self.assertEqual(error.observed["startup_ready_raw"], k.startup_raw)
            self.assertEqual(json.loads(error.observed["opening_transport_raw"])["status"], "REFUSED")
            self.assertIn(SOCKET_PATH, k.files)

    def test_fragmented_startup_and_completion_preserve_exact_frames(self):
        with Kernel() as k:
            k.completion_chunk = 31
            owner = self.construct(k)
            result = owner.acquire_challenge(**k.request())
            self.assertEqual(result["startup_ready_raw"], k.startup_raw)
            self.assertEqual(pin(result["completion_raw"]), json.loads(result["session_raw"])["completion_digest"])
            owner.close()

    def test_extra_or_malformed_startup_never_creates_listener(self):
        for suffix in (b"{}\n", b"x", b"\n"):
            with self.subTest(suffix=suffix), Kernel() as k:
                k.completions[0] += suffix
                error = self.rejected(lambda: self.construct(k))
                self.assertTrue(error.observed["startup_ready_raw"])
                self.assertFalse(any(e[0] == "bind" for e in k.events))

    def test_wrong_pins_and_duplicate_transfers_fail_without_creating_socket(self):
        for change in ({"expected_stream_digest": "sha256:" + "0" * 64}, {"cancel_read_fd": COMPLETION}):
            with self.subTest(change=change), Kernel() as k:
                self.rejected(lambda: self.construct(k, **change))
                self.assertEqual(len(k.closed), len(set(k.closed)))
                self.assertNotIn(SOCKET_PATH, k.files)

    def test_root_process_and_nonroot_supplementary_groups_are_observed(self):
        for pid in (READER, BRIDGE):
            with self.subTest(pid=pid), Kernel() as k:
                k.groups[pid] = "0"
                self.rejected(lambda: self.construct(k))
                self.assertNotIn(SOCKET_PATH, k.files)
        with Kernel() as k, patch.object(subject.os, "getresuid", return_value=(0, 1, 0)):
            self.rejected(lambda: self.construct(k))
            self.assertNotIn(SOCKET_PATH, k.files)

    def test_blocking_cancel_and_inheritable_bridge_stdio_refuse_before_pipe_read(self):
        for row in ("cancel", "bridge"):
            with self.subTest(row=row), Kernel() as k:
                cancel_reads = []
                k.read_hook = lambda fd, raw: cancel_reads.append(fd) if fd == CANCEL else None
                if row == "cancel":
                    k.fds[CANCEL]["flags"] &= ~os.O_NONBLOCK
                else:
                    k.remote[(BRIDGE, 1)]["flags"] &= ~os.O_CLOEXEC
                self.rejected(lambda: self.construct(k))
                if row == "cancel":
                    self.assertEqual(cancel_reads, [])
                self.assertNotIn(SOCKET_PATH, k.files)

    def test_flag_change_during_late_proc_read_refuses_before_completion_read(self):
        with Kernel() as k:
            reads = []
            def mutate(fd, raw):
                row = k.fds[fd]
                if row["path"] == f"/proc/{SUPERVISOR}/status":
                    k.fds[COMPLETION]["flags"] &= ~os.O_NONBLOCK
                if fd == COMPLETION:
                    reads.append(raw)
            k.read_hook = mutate
            self.rejected(lambda: self.construct(k))
            self.assertEqual(reads, [])

    def test_cancel_or_process_exit_wins_over_ready_startup(self):
        for event in ("EOF", "DATA", "reader", "bridge", "supervisor"):
            with self.subTest(event=event), Kernel() as k:
                if event == "EOF":
                    k.cancel_eof = True
                elif event == "DATA":
                    k.cancel_bytes = b"x"
                else:
                    k.dead.add(k.roles[event]["pid"])
                error = self.rejected(lambda: self.construct(k))
                self.assertIsNone(error.observed["startup_ready_raw"])
                self.assertNotIn(SOCKET_PATH, k.files)

    def test_precall_cancellation_does_not_issue_notice(self):
        with Kernel() as k:
            owner = self.construct(k)
            k.cancel_eof = True
            self.rejected(lambda: owner.acquire_challenge(**k.request()))
            self.assertFalse(any(e[0] == "notice" for e in k.events))

    def test_returned_records_cannot_mutate_internal_refresh_predecessor(self):
        with Kernel() as k:
            owner = self.construct(k)
            args = k.request()
            first = owner.acquire_challenge(**args)
            retained = copy.deepcopy(first)
            first["owned"]["reader"]["ack_ns"] = 0
            first["checkpoint"]["acquisition_raw"] = b"changed"
            second = owner.acquire_refresh(**k.refresh(args, retained))
            self.assertEqual(second["owned"], retained["owned"])
            owner.close()

    def test_actual_reader_verifier_rejects_changed_retained_ack(self):
        with Kernel() as k:
            owner = self.construct(k)
            real = subject.verify_reader_evidence
            def corrupt(evidence, reader, **kwargs):
                altered = json.loads(evidence)
                altered["received_ns"] = 0
                changed = encoded(altered)
                kwargs["expected_evidence_digest"] = pin(changed)
                return real(changed, reader, **kwargs)
            with patch.object(subject, "verify_reader_evidence", side_effect=corrupt):
                error = self.rejected(lambda: owner.acquire_challenge(**k.request()))
            self.assertIsNone(error.observed["owned_observed"]["reader"])
            self.assertIsNotNone(error.unaccepted_reader_raw)
            self.assertFalse(any(e[0] == "create" and e[1].startswith(ARCHIVE + "/") for e in k.events))

    def test_actual_checkpoint_verifier_rejects_changed_acquisition_record(self):
        with Kernel() as k:
            owner = self.construct(k)
            real = subject.verify_reader_checkpoint
            def corrupt(manifest, publication, batch, acquisition, **kwargs):
                altered = json.loads(acquisition)
                altered["manifest_digest"] = "sha256:" + "0" * 64
                changed = encoded(altered)
                kwargs["expected_acquisition_digest"] = pin(changed)
                return real(manifest, publication, batch, changed, **kwargs)
            with patch.object(subject, "verify_reader_checkpoint", side_effect=corrupt):
                error = self.rejected(lambda: owner.acquire_challenge(**k.request()))
            self.assertIsNotNone(error.observed["checkpoint_observed"]["acquisition_raw"])
            self.assertIsNone(error.observed["session_raw"])
            self.assertEqual(owner._sequence, 0)

    def test_completion_pin_mismatch_is_rejected_after_real_acquisition(self):
        with Kernel() as k:
            owner = self.construct(k)
            def mutate(fd, raw):
                if fd == COMPLETION and raw.endswith(b"\n"):
                    # Mutate only source bytes still independently acquired:
                    # the actual producer/readback must fail, never invent success.
                    for path, node in k.files.items():
                        if path.startswith(SOURCE + "/receipt-"):
                            document = json.loads(node.raw)
                            document["sequence_after"] += 1
                            node.raw = encoded(document)
            k.read_hook = mutate
            error = self.rejected(lambda: owner.acquire_challenge(**k.request()))
            self.assertIsNotNone(error.observed["completion_raw"])
            self.assertIsNone(error.observed["session_raw"])
            self.assertEqual(owner._sequence, 0)

    def test_source_receipt_missing_never_becomes_completed_checkpoint(self):
        with Kernel() as k:
            owner = self.construct(k)
            def remove(fd, raw):
                if fd == COMPLETION:
                    k.files = {p: n for p, n in k.files.items() if not p.startswith(SOURCE + "/receipt-")}
            k.read_hook = remove
            error = self.rejected(lambda: owner.acquire_challenge(**k.request()))
            self.assertIsNotNone(error.observed["checkpoint_observed"]["manifest_raw"])
            self.assertIsNone(error.observed["session_raw"])

    def test_late_final_cancellation_quarantines_successful_acquisitions(self):
        with Kernel() as k:
            owner = self.construct(k)
            real = subject.verify_reader_checkpoint
            def cancel(*args, **kwargs):
                result = real(*args, **kwargs)
                k.cancel_eof = True
                return result
            with patch.object(subject, "verify_reader_checkpoint", side_effect=cancel):
                error = self.rejected(lambda: owner.acquire_challenge(**k.request()))
            self.assertIsNone(error.observed["owned_observed"]["reader"])
            self.assertIsNotNone(error.observed["checkpoint_observed"]["acquisition_raw"])
            self.assertEqual(owner._sequence, 0)

    def test_refresh_loss_refusal_original_artifact_or_response_pin_change_never_writes(self):
        for change in ("LOSS_UNAVAILABLE", "pin", "artifact"):
            with self.subTest(change=change), Kernel() as k:
                owner = self.construct(k)
                initial = k.request()
                first = owner.acquire_challenge(**initial)
                args = k.refresh(initial, first, "REFUSED" if change == "LOSS_UNAVAILABLE" else "EVIDENCE")
                if change == "pin":
                    args["expected_first_response_digest"] = "sha256:" + "0" * 64
                elif change == "artifact":
                    packet = json.loads(args["first_response_raw"])
                    packet["reader_summary"] = artifact(b"{}")
                    args["first_response_raw"] = encoded(packet)
                    args["expected_first_response_digest"] = pin(args["first_response_raw"])
                    request = json.loads(args["request_raw"])
                    request["previous_response_digest"] = args["expected_first_response_digest"]
                    args["request_raw"] = encoded(request)
                error = self.rejected(lambda: owner.acquire_refresh(**args))
                self.assertIs(error.observed["command_attempted"], False)
                self.assertFalse(any(e[0] == "refresh" for e in k.events))

    def test_refresh_short_eagain_and_interrupted_writes_are_once_and_terminal(self):
        for behavior in ("short", "eagain", "eintr"):
            with self.subTest(behavior=behavior), Kernel() as k:
                owner = self.construct(k)
                initial = k.request()
                first = owner.acquire_challenge(**initial)
                args = k.refresh(initial, first)
                attempts = []
                def write(fd, raw):
                    if fd != REFRESH:
                        return None
                    attempts.append(raw)
                    if behavior == "eagain":
                        raise BlockingIOError()
                    if behavior == "eintr":
                        raise InterruptedError()
                    return len(raw) - 1
                k.write_hook = write
                error = self.rejected(lambda: owner.acquire_refresh(**args))
                self.assertTrue(error.observed["command_attempted"])
                self.assertEqual(len(attempts), 1)
                self.assertIs(self.rejected(lambda: owner.acquire_refresh(**args)), error)
                self.assertEqual(len(attempts), 1)
                self.assertEqual(owner._sequence, 1)

    def test_refresh_preserves_original_age_and_never_renews_ack(self):
        with Kernel() as k:
            owner = self.construct(k)
            args = k.request()
            first = owner.acquire_challenge(**args)
            refresh = k.refresh(args, first)
            k.now = first["owned"]["reader"]["ack_ns"] + 200000000
            self.rejected(lambda: owner.acquire_refresh(**refresh))
            self.assertEqual(len([e for e in k.events if e[0] == "challenge"]), 1)
            self.assertFalse(any(e[0] == "refresh" for e in k.events))

    def test_context_replay_and_unfinished_exchange_do_not_issue_new_notice(self):
        for finish in (False, True):
            with self.subTest(finish=finish), Kernel() as k:
                owner = self.construct(k)
                args = k.request()
                owner.acquire_challenge(**args)
                if finish:
                    owner.finish_request(expected_context_digest=args["expected_context_digest"])
                self.rejected(lambda: owner.acquire_challenge(**args))
                self.assertEqual(len([e for e in k.events if e[0] == "notice"]), 1)

    def test_archive_failure_retains_real_prefix_and_permanent_residue(self):
        with Kernel() as k:
            owner = self.construct(k)
            def fail(fd):
                path = k.fds[fd]["path"]
                if path and path.startswith(ARCHIVE + "/") and path.endswith("-manifest.json"):
                    raise OSError("fabricated archive fsync failure")
            k.fsync_hook = fail
            error = self.rejected(lambda: owner.acquire_challenge(**k.request()))
            observed = error.observed["checkpoint_observed"]
            self.assertTrue(observed["claim_attempted"])
            self.assertTrue(observed["manifest_raw"])
            self.assertTrue(any(p.startswith(ARCHIVE + "/") and p.endswith("-claim.json") for p in k.files))
            self.assertIsNone(error.observed["session_raw"])

    def test_foreign_reused_local_descriptor_is_never_closed(self):
        with Kernel() as k:
            owner = self.construct(k)
            k.fds[REFRESH]["node"] = k.node(stat.S_IFIFO | 0o600, kind="pipe")
            error = self.rejected(lambda: owner.acquire_challenge(**k.request()))
            self.assertNotIn(REFRESH, k.closed)
            self.assertTrue(error.cleanup_failures)
            count = len(k.closed)
            self.assertIs(self.rejected(owner.close), error)
            self.assertEqual(len(k.closed), count)

    def test_actual_proc_read_error_and_close_error_both_survive(self):
        with Kernel() as k:
            path = f"/proc/{SUPERVISOR}/status"
            k.read_failure = k.close_failure = path
            error = self.rejected(lambda: self.construct(k))
            self.assertIsInstance(error.original_failure, OSError)
            self.assertIn("read failure", str(error.original_failure))
            self.assertTrue(any("close failure" in str(e) for e in error.cleanup_failures))
            self.assertEqual(len(k.closed), len(set(k.closed)))

    def test_pidfd_substitution_during_cleanup_association_skips_foreign_close(self):
        with Kernel() as k:
            owner = self.construct(k)
            target = owner._pidfds["bridge"]
            changed = []
            def substitute(fd, raw):
                if (not changed and k.fds[fd]["path"] == f"/proc/self/fdinfo/{target}"
                        and owner._closed and target not in owner._owned):
                    changed.append(target)
                    k.fds[target]["node"] = k.node(stat.S_IFREG | 0o600, kind="pidfd")
            k.read_hook = substitute
            k.cancel_eof = True
            error = self.rejected(lambda: owner.acquire_challenge(**k.request()))
            self.assertEqual(changed, [target])
            self.assertNotIn(target, k.closed)
            self.assertIn("cancellation", str(error.original_failure))
            self.assertTrue(any("after cleanup observation" in str(e) for e in error.cleanup_failures))

    def test_wrong_thread_call_never_closes_descriptors_under_original_owner(self):
        with Kernel() as k:
            owner = self.construct(k)
            count = len(k.closed)
            with patch.object(subject.threading, "get_native_id", return_value=ROOT + 100):
                error = self.rejected(owner.close)
            self.assertEqual(len(k.closed), count)
            self.assertIs(self.rejected(owner.close), error)
            self.assertEqual(len(k.closed), count)

    def test_late_completion_custody_failure_preserves_received_raw_prefix(self):
        with Kernel() as k:
            def mutate(fd, raw):
                if fd == COMPLETION:
                    k.fds[COMPLETION]["flags"] &= ~os.O_NONBLOCK
            k.read_hook = mutate
            error = self.rejected(lambda: self.construct(k))
            self.assertEqual(error.observed["startup_ready_raw"], k.startup_raw)
            self.assertNotIn(SOCKET_PATH, k.files)

    def test_closed_owner_does_not_retry_descriptor_cleanup(self):
        with Kernel() as k:
            owner = self.construct(k)
            raw = owner.close()
            self.assertEqual(json.loads(raw)["operation"], "CLOSE")
            count = len(k.closed)
            self.rejected(owner.close)
            self.assertEqual(len(k.closed), count)


if __name__ == "__main__":
    unittest.main()
