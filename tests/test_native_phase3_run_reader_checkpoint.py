"""Fabricated kernel boundaries for the actual one-shot checkpoint loop."""

import errno
import hashlib
import json
import os
import posixpath
import select
import socket
import stat
import struct
import types
import unittest
from unittest.mock import patch

from aragorn import native_phase3_run_reader_checkpoint as subject


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def pin(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def document(raw):
    return json.loads(raw)


def fabricated_inputs():
    processes = {
        "reader": dict(pid=101, start_time_ticks=11, uid=501, gid=502),
        "bridge": dict(pid=102, start_time_ticks=12, uid=601, gid=602),
        "sensor": dict(pid=203, start_time_ticks=23, uid=0, gid=0),
        "observer": dict(pid=201, start_time_ticks=21, uid=0, gid=0),
        "supervisor": dict(pid=202, start_time_ticks=22, uid=0, gid=0),
    }
    clock = dict(boot_id="12345678-1234-4234-9234-123456789abc", clock_id="CLOCK_BOOTTIME",
                 time_namespace=dict(device=9, inode=700))
    session = "a" * 64
    def directory(path, inode, uid=0, gid=0, mode=0o755):
        return dict(path=path, device=1, inode=inode, uid=uid, gid=gid, mode=stat.S_IFDIR | mode)
    directories = [directory("/", 1), directory("/var", 2), directory("/var/lib", 3),
                   directory("/var/lib/aragorn-phase3-reader-events", 4, 501, 502, 0o700),
                   directory("/var/lib/aragorn-phase3-reader-checkpoints", 5, 0, 0, 0o700)]
    endpoint_dirs = [directories[0], directory("/run", 6), directory("/run/aragorn-phase3-reader", 7, 0, 502, 0o710)]
    layouts = (("NOTICE", ("OBSERVER", 30), [("READER", 3)]),
               ("TELEMETRY", ("BRIDGE", 1), [("READER", 4)]),
               ("REFRESH", ("OBSERVER", 31), [("READER", 5)]),
               ("STDERR", ("BRIDGE", 2), [("READER", 6)]),
               ("CANCEL", ("SUPERVISOR", 40), [("READER", 7), ("OBSERVER", 32)]),
               ("COMPLETION", ("READER", 8), [("OBSERVER", 33)]))
    pipes = [dict(role=role, device=1, inode=1003 + index, mode=stat.S_IFIFO | 0o600, uid=0, gid=0,
                  writer=dict(process=writer[0], fd=writer[1]),
                  readers=[dict(process=role_name, fd=fd) for role_name, fd in readers])
             for index, (role, writer, readers) in enumerate(layouts)]
    stream = dict(schema="aragorn/native-phase3-reader-stream-inventory/v1", session_id=session, **processes,
                  clock=clock, source_inventory_digest=pin(b"source inventory"), access_inventory_digest=pin(b"access inventory"),
                  pipes=pipes, upstream_continuity="UNKNOWN", upstream_socket_digest=None, upstream_loss_digest=None)
    stream_raw = encode(stream)
    process = dict(boot_id=clock["boot_id"], stream_digest=pin(stream_raw), reader_source_digest=pin(b"reader installed bytes"),
                   sensor_source_digest=pin(b"sensor installed bytes"), program_map_digest=pin(b"program map"))
    for role in ("reader", "sensor"):
        for key, suffix in (("pid", "pid"), ("start_time_ticks", "start_ticks"), ("uid", "uid"), ("gid", "gid")):
            process[role + "_" + suffix] = processes[role][key]
    epoch = dict(process=process, clock=dict(boot_id=clock["boot_id"], clock_id="CLOCK_BOOTTIME", time_namespace_inode=700),
                 loss_scope=[pin(b"unimplemented real loss scope")], policy=dict(timeout_ns=100000000, max_age_ns=200000000),
                 deployment_digest=pin(b"deployment"))
    epoch_raw = encode(epoch)
    checkpoint = dict(schema="aragorn/native-phase3-reader-checkpoint-provision/v1", epoch_digest=pin(epoch_raw),
                      session_id=session, reader=processes["reader"], observer=processes["observer"], clock=clock,
                      stream_digest=pin(stream_raw), source_inventory_digest=stream["source_inventory_digest"],
                      access_inventory_digest=stream["access_inventory_digest"], directories=directories, session_deadline_ns=900000000)
    transport = dict(schema="aragorn/native-phase3-run-reader-transport-provision/v1", epoch_digest=pin(epoch_raw),
                     observer={**processes["observer"], "time_namespace": clock["time_namespace"]}, directories=endpoint_dirs,
                     notice_pipe={**{key: pipes[0][key] for key in ("device", "inode", "mode", "uid", "gid")}, "reader_fd": 3},
                     session_deadline_ns=900000000, max_requests=8, access_inventory_digest=stream["access_inventory_digest"])
    checkpoint_raw, transport_raw = encode(checkpoint), encode(transport)
    loop = dict(schema="aragorn/native-phase3-reader-loop-provision/v1", epoch_digest=pin(epoch_raw),
                checkpoint_provision_digest=pin(checkpoint_raw), transport_provision_digest=pin(transport_raw),
                stream_digest=pin(stream_raw), session_id=session, startup_deadline_ns=50000000,
                session_deadline_ns=900000000, max_requests=8)
    arguments = dict(observer_pidfd=9, bridge_pidfd=10, supervisor_pidfd=11)
    for name, raw, pin_name in (("epoch", epoch_raw, "epoch"), ("checkpoint_provision", checkpoint_raw, "checkpoint_provision"),
                               ("transport_provision", transport_raw, "transport_provision"),
                               ("stream_inventory", stream_raw, "stream"), ("loop_provision", encode(loop), "loop_provision")):
        arguments[name + "_raw"], arguments["expected_" + pin_name + "_digest"] = raw, pin(raw)
    return arguments, stream, checkpoint, transport


class Node:
    def __init__(self, path, inode, mode, uid=0, gid=0, data=b"", device=1):
        self.path, self.inode, self.mode, self.uid, self.gid = path, inode, mode, uid, gid
        self.data, self.device, self.version, self.links = data, device, 1, 1

    def metadata(self):
        return types.SimpleNamespace(st_dev=self.device, st_ino=self.inode, st_mode=self.mode,
                                     st_uid=self.uid, st_gid=self.gid, st_nlink=self.links,
                                     st_size=len(self.data), st_mtime_ns=self.version, st_ctime_ns=self.version)


class FakeSocket:
    def __init__(self, kernel):
        self.kernel, self.detached, self.options = kernel, False, {}
        self.fd = kernel.allocate(Node("client", 8000, stat.S_IFSOCK | 0o600, 501, 502))
        self.connected = self.delivered = self.acked = self.peer_closed = False
        self.family = socket.AF_UNIX

    def fileno(self):
        return -1 if self.detached else self.fd

    def gettimeout(self):
        return 0

    def get_inheritable(self):
        return False

    def setsockopt(self, level, option, value):
        self.options[option] = value

    def getsockopt(self, level, option, size=None):
        if option == socket.SO_TYPE:
            return socket.SOCK_SEQPACKET
        if option == socket.SO_ERROR:
            return 0
        if option == 17:
            return struct.pack("=iII", 201, 0, 0)
        if option == 77:
            fd = self.kernel.allocate(Node("peerpidfd", 9000, stat.S_IFREG | 0o600))
            self.kernel.pidfds[fd] = 201
            return fd
        return self.options[option]

    def connect(self, path):
        self.kernel.log.append(("connect", path))
        if self.kernel.connect_error:
            raise OSError(self.kernel.connect_error, "fabricated connect refusal")
        self.connected = True

    def recvmsg(self, count, control_size, flags):
        self.kernel.log.append(("recvmsg", self.acked))
        if not self.delivered:
            self.delivered = True
            challenge = dict(epoch_digest=self.kernel.arguments["expected_epoch_digest"], request_digest=pin(b"request"),
                             boundary="BEFORE_FIRST_EFFECT", nonce="c" * 64, issued_ns=self.kernel.now,
                             deadline_ns=self.kernel.now + 100000000, sequence_before=0)
            if self.kernel.challenge_mutation:
                self.kernel.challenge_mutation(challenge)
            raw = self.kernel.challenge_raw = encode(challenge)
            controls = [(socket.SOL_SOCKET, 2, struct.pack("=iII", 201, 0, 0))]
            if self.kernel.unexpected_rights:
                for fd in (90, 91):
                    self.kernel.fds[fd] = Node("ancillary", fd + 10000, stat.S_IFREG | 0o600)
                controls.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=ii", 90, 91)))
            return raw, controls, 0, None
        if self.kernel.post_ack_data:
            return b"X", [], 0, None
        self.peer_closed = True
        return b"", [], 0, None

    def send(self, raw, flags):
        self.kernel.log.append(("ack", raw))
        self.kernel.ack_raw, self.acked = raw, True
        if self.kernel.ack_error:
            raise self.kernel.ack_error
        return len(raw)

    def detach(self):
        self.kernel.log.append(("detach", self.fd))
        if self.kernel.detach_error:
            raise OSError("fabricated detach refusal")
        self.detached = True
        return self.fd


class Kernel:
    """Every proc/file/socket/poll call stays in this fabricated kernel."""
    def __init__(self, chunks=(), refresh=False):
        self.arguments, self.inventory, self.provision, self.transport = fabricated_inputs()
        self.nodes, self.fds, self.positions, self.log, self.allocated_paths = {}, {}, {}, [], {}
        self.pidfds, self.next_fd, self.now = {9: 201, 10: 102, 11: 202}, 100, 1000000
        self.chunks, self.refresh = list(chunks), refresh
        self.ready = self.notice_done = self.refresh_done = self.cancel = False
        self.sock, self.ack_raw, self.challenge_raw = None, None, None
        self.completions = []
        self.notice_fragments = None
        self.refresh_raw = None
        self.connect_error = self.ack_error = self.challenge_mutation = None
        self.detach_error = self.post_ack_data = self.unexpected_rights = False
        self.supplementary = self.stderr = self.source_mutation = self.cancel_at_ready = False
        self.close_error = self.partial_write = self.fail_fsync = self.substitute_client = False
        self.never_close = False
        self.boot_reads = self.receipt_reads = 0
        self.second_completion_polls = None
        self.late_completion_flags = self.mutate_sealed = self.swap_pidfd = False
        self.swap_stderr = self.refresh_failure = False
        self.fd_flags = {}
        self.process_id = self.native_id = 101
        self.clock_step = 100
        for entry in self.provision["directories"] + self.transport["directories"][1:]:
            self.nodes[entry["path"]] = Node(entry["path"], entry["inode"], entry["mode"], entry["uid"], entry["gid"])
        self.nodes["/run/aragorn-phase3-reader/challenge.sock"] = Node("/run/aragorn-phase3-reader/challenge.sock", 800, stat.S_IFSOCK | 0o660, 0, 502)
        namespace = Node("/proc/101/ns/time", 700, stat.S_IFREG | 0o444, device=9)
        self.nodes[namespace.path] = namespace
        for fd, pipe in zip(range(3, 9), self.inventory["pipes"]):
            self.fds[fd] = Node("pipe", pipe["inode"], pipe["mode"])
        for fd in self.pidfds:
            self.fds[fd] = Node("pidfd", 2000 + fd, stat.S_IFREG | 0o600)
        self.os = types.SimpleNamespace(**{name: getattr(os, name) for name in (
            "O_RDONLY", "O_WRONLY", "O_RDWR", "O_ACCMODE", "O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC", "O_DIRECTORY", "O_EXCL", "O_CREAT")})
        for name in ("open", "read", "write", "pread", "fsync", "fstat", "stat", "close", "readlink", "get_inheritable", "fpathconf"):
            setattr(self.os, name, getattr(self, name))
        self.os.getpid = lambda: self.process_id
        self.os.getresuid = lambda: (501, 501, 501)
        self.os.getresgid = lambda: (502, 502, 502)
        self.os.getgroups = lambda: [999] if self.supplementary else []

    def allocate(self, node):
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.fds[fd], self.positions[fd] = node, 0
        self.allocated_paths[fd] = node.path
        return fd

    def path(self, path, dir_fd=None):
        return path if path.startswith("/") else posixpath.join(self.fds[dir_fd].path, path)

    def proc(self, path):
        if path == "/proc/sys/kernel/random/boot_id":
            self.boot_reads += 1
            return (self.inventory["clock"]["boot_id"] + "\n").encode()
        if path.startswith("/proc/self/fdinfo/"):
            fd = int(path.rsplit("/", 1)[1])
            return f"Pid:\t{self.pidfds[fd]}\n".encode()
        pid, leaf = int(path.split("/")[2]), path.rsplit("/", 1)[1]
        process = next(value for key, value in self.inventory.items() if key in ("reader", "bridge", "observer", "supervisor") and value["pid"] == pid)
        if leaf == "stat":
            return (f"{pid} (fabricated process) " + " ".join(["R"] + ["0"] * 18 + [str(process["start_time_ticks"])]) + "\n").encode()
        if leaf == "status":
            return ("Uid:\t" + " ".join([str(process["uid"])] * 4) + "\nGid:\t" + " ".join([str(process["gid"])] * 4)
                    + "\nGroups:\t\nNoNewPrivs:\t1\n" + "".join(key + ":\t00000000\n" for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))).encode()
        raise AssertionError("unexpected fabricated proc path " + path)

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        path = self.path(path, dir_fd)
        self.log.append(("open", path, flags))
        if flags & os.O_CREAT:
            if path in self.nodes:
                raise FileExistsError(path)
            self.nodes[path] = Node(path, 30000 + self.next_fd, stat.S_IFREG | mode, 501, 502)
        elif path.startswith("/proc/") and path not in self.nodes:
            return self.allocate(Node(path, 40000 + self.next_fd, stat.S_IFREG | 0o444, data=self.proc(path)))
        if path not in self.nodes:
            raise FileNotFoundError(path)
        return self.allocate(self.nodes[path])

    def notice(self):
        return encode(dict(schema="aragorn/native-phase3-run-reader-connect-notice/v1", listener_epoch="b" * 64,
                           ordinal=1, admission_digest=pin(b"admission"), epoch_digest=self.arguments["expected_epoch_digest"],
                           request_digest=pin(b"request"), sequence_before=0, issued_ns=1000000,
                           accept_deadline_ns=150000000, request_deadline_ns=250000000)) + b"\n"

    def command(self):
        first = self.completions[0]
        ack = document(self.ack_raw)
        return encode(dict(schema="aragorn/native-phase3-reader-checkpoint-refresh/v1", session_id=self.inventory["session_id"],
                           ordinal=1, epoch_digest=self.arguments["expected_epoch_digest"], request_digest=pin(b"request"),
                           challenge_digest=pin(self.challenge_raw), reader_evidence_digest=pin(b"root retained evidence"),
                           reader_summary_digest=pin(b"root retained summary"), reader_connection_epoch="d" * 64,
                           previous_checkpoint_digest=first["manifest_digest"], sequence_before=1,
                           second_request_digest=pin(b"second packet"), issued_ns=self.now,
                           deadline_ns=min(self.now + 100000000, ack["ack_ns"] + 200000000))) + b"\n"

    def read(self, fd, count):
        self.log.append(("read", fd, count))
        if fd == 7:
            if self.cancel:
                return b""
            raise BlockingIOError()
        if fd == 6:
            if self.stderr:
                return b"warning\n"
            raise BlockingIOError()
        if fd == 3:
            if self.ready and not self.notice_done:
                if self.notice_fragments is None:
                    self.notice_fragments = [self.notice()]
                part = self.notice_fragments.pop(0)
                if not self.notice_fragments:
                    self.notice_done = True
                return part[:count]
            raise BlockingIOError()
        if fd == 5:
            if self.refresh and self.sock and self.sock.acked and not self.refresh_done:
                self.refresh_done = True
                self.refresh_raw = self.command()
                return self.refresh_raw[:count]
            raise BlockingIOError()
        if fd == 4:
            if self.chunks:
                part = self.chunks.pop(0)
                if isinstance(part, BaseException):
                    raise part
                if len(part) > count:
                    self.chunks.insert(0, part[count:])
                return part[:count]
            raise BlockingIOError()
        node = self.fds[fd]
        offset = self.positions[fd]
        self.positions[fd] += count
        return node.data[offset:offset + count]

    def write(self, fd, raw):
        self.log.append(("write", fd, raw))
        if fd == 8:
            record = document(raw)
            if record["schema"].endswith("loop-ready/v1"):
                self.ready = True
                self.cancel = self.cancel_at_ready
                if self.swap_pidfd:
                    self.pidfds[9] = 999
            else:
                self.completions.append(record)
                if len(self.completions) == 2:
                    self.second_completion_polls = 0
            return len(raw)
        node = self.fds[fd]
        if self.partial_write and node.path.endswith(".ndjson"):
            if node.data:
                raise OSError("fabricated second file write failed")
            part = raw[:1]
        else:
            part = raw
        node.data += part
        node.version += 1
        return len(part)

    def pread(self, fd, count, offset):
        self.log.append(("pread", fd, offset))
        if "/receipt-" in self.fds[fd].path and offset == 0:
            self.receipt_reads += 1
            if self.mutate_sealed and self.receipt_reads == 2:
                next(node for node in self.nodes.values() if node.path.endswith(".ndjson")).version += 1
        return self.fds[fd].data[offset:offset + count]

    def fsync(self, fd):
        self.log.append(("fsync", fd))
        if self.fail_fsync and stat.S_ISREG(self.fds[fd].mode):
            raise OSError("fabricated durability refusal")

    def fstat(self, fd):
        return self.fds[fd].metadata()

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        return self.nodes[self.path(path, dir_fd)].metadata()

    def close(self, fd):
        self.log.append(("close", fd))
        if self.close_error and self.fds[fd].path.endswith(".ndjson"):
            raise OSError("fabricated close failed")
        del self.fds[fd]
        if self.sock and fd == self.sock.fd and not self.refresh:
            self.cancel = True
        if self.sock and fd == self.sock.fd and self.refresh_failure:
            self.chunks.append(b"")

    def readlink(self, path):
        return f"pipe:[{self.fds[int(path.rsplit('/', 1)[1])].inode}]"

    def get_inheritable(self, fd):
        return False

    def fpathconf(self, fd, name):
        return 4096

    def tick(self, clock):
        self.now += self.clock_step
        return self.now

    def poll(self):
        kernel = self
        class Poll:
            def __init__(self):
                self.registered = {}
            def register(self, fd, flags):
                self.registered[fd] = flags
            def poll(self, timeout):
                events = {}
                if kernel.second_completion_polls is not None and 8 in self.registered:
                    kernel.second_completion_polls += 1
                    if kernel.second_completion_polls >= 3:
                        kernel.cancel = True
                if kernel.late_completion_flags and not kernel.ready and kernel.boot_reads == 2 and 8 in self.registered:
                    kernel.fd_flags[8] = os.O_WRONLY
                if kernel.cancel:
                    events[7] = select.POLLHUP
                if kernel.stderr and kernel.ready:
                    events[6] = select.POLLIN
                    if kernel.swap_stderr:
                        kernel.fds[6] = Node("foreign", 98888, stat.S_IFIFO | 0o600)
                if kernel.ready and not kernel.notice_done:
                    events[3] = select.POLLIN
                if kernel.chunks:
                    events[4] = select.POLLIN
                if kernel.sock:
                    sock = kernel.sock
                    if sock.connected and not sock.delivered:
                        events[sock.fd] = select.POLLIN
                    elif sock.acked and not kernel.never_close and not sock.detached:
                        events[sock.fd] = select.POLLIN | select.POLLHUP
                    if sock.acked and kernel.refresh and not kernel.refresh_done:
                        events[5] = select.POLLIN
                    if sock.acked and kernel.substitute_client and not sock.detached:
                        kernel.fds[sock.fd] = Node("foreign", 199999, stat.S_IFREG | 0o600)
                selected = [(fd, flags) for fd, flags in events.items() if fd in self.registered]
                if kernel.never_close and timeout and not selected:
                    kernel.log.append(("poll_timeout", timeout, kernel.now))
                    kernel.now += timeout * 1000000
                return selected
        return Poll()

    def socket(self, family, kind):
        self.sock = FakeSocket(self)
        return self.sock

    def execute(self):
        fake_select = types.SimpleNamespace(poll=self.poll, **{key: getattr(select, key) for key in (
            "POLLIN", "POLLOUT", "POLLHUP", "POLLERR", "POLLNVAL")})
        fake_socket = types.SimpleNamespace(socket=self.socket, **{key: getattr(socket, key) for key in (
            "AF_UNIX", "SOCK_SEQPACKET", "SOL_SOCKET", "SO_TYPE", "SO_ERROR", "SCM_RIGHTS", "MSG_DONTWAIT", "MSG_EOR")})
        fake_socket.SOCK_NONBLOCK, fake_socket.SOCK_CLOEXEC = 0x800, 0x80000
        fake_fcntl = types.SimpleNamespace(F_GETFL=3, fcntl=lambda fd, _: self.fd_flags.get(fd, (os.O_WRONLY if fd == 8 else os.O_RDONLY) | os.O_NONBLOCK))
        with patch.multiple(subject, os=self.os, select=fake_select, socket=fake_socket, fcntl=fake_fcntl,
                            sys=types.SimpleNamespace(platform="linux", byteorder="little"),
                            threading=types.SimpleNamespace(get_native_id=lambda: self.native_id),
                            time=types.SimpleNamespace(CLOCK_BOOTTIME=7, clock_gettime_ns=self.tick), _PID=101, _STARTED=False):
            return subject.run_reader_checkpoint_loop(**self.arguments)

    def published(self, suffix):
        return [(path, node.data) for path, node in self.nodes.items() if path.startswith("/var/lib/aragorn-phase3-reader-events/") and path.endswith(suffix)]


class ReaderCheckpointTests(unittest.TestCase):
    def assert_refused(self, kernel):
        with self.assertRaises(subject.ReaderCheckpointLoopError) as caught:
            kernel.execute()
        return caught.exception

    def test_idle_actual_read_completion_ack_and_expected_peer_close(self):
        kernel = Kernel()
        result = kernel.execute()
        terminal = document(result["terminal_raw"])
        self.assertEqual((terminal["reason"], terminal["sequence_after"]), ("CANCELLED", 1))
        self.assertEqual(terminal["stream_continuity"], "UNKNOWN")
        for key in ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized", "run_qualified", "phase3_qualified"):
            self.assertIs(terminal[key], False)
        self.assertEqual(len(kernel.completions), 1)
        manifest = document(result["observed"]["manifest_raw"])
        self.assertEqual(manifest["raw_bytes"], 0)
        self.assertEqual([row["outcome"] for row in manifest["reads"]], ["EAGAIN"])
        self.assertGreaterEqual(manifest["reads"][-1]["started_ns"], manifest["trigger_received_ns"])
        completion_index = next(index for index, row in enumerate(kernel.log) if row[0] == "write" and row[1] == 8 and b"checkpoint-ready" in row[2])
        ack_index = next(index for index, row in enumerate(kernel.log) if row[0] == "ack")
        detach_index = next(index for index, row in enumerate(kernel.log) if row[0] == "detach")
        self.assertLess(completion_index, ack_index)
        self.assertLess(ack_index, detach_index)
        self.assertTrue(any(row == ("recvmsg", True) for row in kernel.log[ack_index:detach_index]))
        self.assertIsNotNone(result["observed"]["startup_ready_raw"])

    def test_unknown_variants_whitespace_numbers_and_partial_utf8_preserved(self):
        raw = b' {"unknown_variant": {"label":"\xc3\xa9","fraction":1.25}, "n":-5}\n'
        kernel = Kernel([raw[:30], raw[30:31], raw[31:]])
        result = kernel.execute()
        self.assertEqual(kernel.published(".ndjson")[0][1], raw)
        manifest = document(result["observed"]["manifest_raw"])
        self.assertEqual(manifest["raw_digest"], pin(raw))
        self.assertEqual(manifest["raw_records"], 1)
        self.assertEqual(sum(row["bytes"] for row in manifest["reads"]), len(raw))

    def test_publication_file_parent_sync_readback_close_precedes_completion(self):
        kernel = Kernel([b'{"event":"x"}\n'])
        kernel.execute()
        completion_index = next(i for i, row in enumerate(kernel.log) if row[0] == "write" and row[1] == 8 and b"checkpoint-ready" in row[2])
        create_indices = [i for i, row in enumerate(kernel.log) if row[0] == "open" and row[2] & os.O_CREAT]
        self.assertEqual(len(create_indices), 3)
        for index in create_indices:
            self.assertTrue(kernel.log[index][2] & os.O_EXCL)
            file_write = next(row for row in kernel.log[index + 1:] if row[0] == "write" and row[1] != 8)
            fd = file_write[1]
            file_sync = next(i for i, row in enumerate(kernel.log[index + 1:], index + 1) if row == ("fsync", fd))
            parent_sync = next(i for i, row in enumerate(kernel.log[file_sync + 1:], file_sync + 1) if row[0] == "fsync")
            readback = next(i for i, row in enumerate(kernel.log[parent_sync + 1:], parent_sync + 1) if row[0] == "pread" and row[1] == fd)
            closed = next(i for i, row in enumerate(kernel.log[readback + 1:], readback + 1) if row == ("close", fd))
            self.assertLess(file_sync, parent_sync)
            self.assertEqual(kernel.allocated_paths[kernel.log[parent_sync][1]], "/var/lib/aragorn-phase3-reader-events")
            self.assertLess(parent_sync, readback)
            self.assertLess(closed, completion_index)

    def test_refresh_uses_same_ack_and_chain_with_queued_control_peer_close_race(self):
        kernel = Kernel([b'{"one":1}\n'], refresh=True)
        result = kernel.execute()
        self.assertEqual(len(kernel.completions), 2)
        self.assertEqual(len([row for row in kernel.log if row[0] == "connect"]), 1)
        self.assertEqual(len([row for row in kernel.log if row[0] == "ack"]), 1)
        self.assertEqual(document(kernel.ack_raw)["sequence_after"], 1)
        manifests = [document(raw) for path, raw in kernel.published(".json") if "/refresh-" in path]
        self.assertEqual(len(manifests), 1)
        self.assertEqual(manifests[0]["previous_checkpoint_digest"], kernel.completions[0]["manifest_digest"])
        self.assertEqual(manifests[0]["trigger_digest"], pin(kernel.refresh_raw))
        self.assertEqual(manifests[0]["sequence_after"], 2)
        self.assertEqual(document(result["terminal_raw"])["sequence_after"], 2)
        self.assertGreaterEqual(kernel.second_completion_polls, 3)
        eof_index = next(i for i, row in enumerate(kernel.log) if row == ("recvmsg", True))
        close_index = next(i for i, row in enumerate(kernel.log) if row == ("close", kernel.sock.fd))
        refresh_index = next(i for i, row in enumerate(kernel.log) if row[0] == "read" and row[1] == 5)
        self.assertLess(eof_index, close_index)
        self.assertLess(close_index, refresh_index)

    def test_syntax_refusals_preserve_actual_bytes_and_no_ack(self):
        for raw in (b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'{"x":1e999}\n', b'{"x":9223372036854775808}\n',
                    b'[]\n', b'{}\r\n', b'\n', b'\xef\xbb\xbf{}\n', b'{"x":"\xff"}\n', b'{} {}\n'):
            with self.subTest(raw=raw):
                kernel = Kernel([raw])
                error = self.assert_refused(kernel)
                self.assertEqual(error.observed["batch_raw"], raw)
                self.assertIsNone(kernel.ack_raw)

    def test_incomplete_tail_never_becomes_checkpoint(self):
        kernel = Kernel([b'{"partial":'])
        kernel.never_close = True
        error = self.assert_refused(kernel)
        self.assertIsNotNone(error.observed["startup_ready_raw"])
        self.assertEqual(error.observed["challenge_raw"], kernel.challenge_raw)
        self.assertIsNotNone(kernel.challenge_raw)
        self.assertEqual(error.observed["batch_raw"], b'{"partial":')
        self.assertEqual(len([row for row in kernel.log if row[0] == "connect"]), 1)
        tail_read = next(i for i, row in enumerate(kernel.log) if row[0] == "read" and row[1] == 4)
        timeout = next(i for i, row in enumerate(kernel.log) if row[0] == "poll_timeout")
        self.assertLess(tail_read, timeout)
        deadline = document(kernel.challenge_raw)["deadline_ns"]
        self.assertGreaterEqual(kernel.now, deadline)
        self.assertLessEqual(kernel.now, deadline + 1001000)
        self.assertIsNone(error.observed["ack_raw"])
        self.assertFalse(error.observed["publication_attempted"])
        self.assertFalse(kernel.published(".json"))
        self.assertFalse(kernel.published(".ndjson"))
        self.assertFalse(kernel.completions)

    def test_data_read_cap_keeps_raw_bytes_without_ack(self):
        kernel = Kernel([b'{}\n'] * 64)
        error = self.assert_refused(kernel)
        self.assertEqual(error.observed["batch_raw"], b'{}\n' * 64)
        self.assertFalse(kernel.completions)

    def test_sixty_three_reads_can_finish_with_actual_eagain(self):
        kernel = Kernel([b'{}\n'] * 63)
        result = kernel.execute()
        manifest = document(result["observed"]["manifest_raw"])
        self.assertEqual(len(manifest["reads"]), 64)
        self.assertEqual(manifest["reads"][-1]["outcome"], "EAGAIN")

    def test_control_fragment_assembly_joins_exact_original_bytes(self):
        kernel = Kernel()
        raw = kernel.notice()
        kernel.notice_fragments = [raw[:20], raw[20:]]
        result = kernel.execute()
        self.assertEqual(result["observed"]["notice_raw"], raw)

    def test_surplus_control_refuses_before_connect(self):
        kernel = Kernel()
        kernel.notice_fragments = [kernel.notice() + b"{}\n"]
        self.assert_refused(kernel)
        self.assertFalse(any(row[0] == "connect" for row in kernel.log))

    def test_notice_pin_sequence_and_original_deadline_refuse(self):
        for key, value in (("sequence_before", 1), ("epoch_digest", pin(b"other epoch")), ("accept_deadline_ns", 1)):
            with self.subTest(key=key):
                kernel = Kernel()
                value_record = document(kernel.notice())
                value_record[key] = value
                kernel.notice_fragments = [encode(value_record) + b"\n"]
                self.assert_refused(kernel)
                self.assertIsNone(kernel.ack_raw)

    def test_one_failed_connect_attempt_no_reconnect(self):
        kernel = Kernel()
        kernel.connect_error = errno.ECONNREFUSED
        self.assert_refused(kernel)
        self.assertEqual(len([row for row in kernel.log if row[0] == "connect"]), 1)

    def test_challenge_mismatch_never_publishes(self):
        kernel = Kernel()
        kernel.challenge_mutation = lambda value: value.update(sequence_before=7)
        self.assert_refused(kernel)
        self.assertFalse(kernel.published(".json"))

    def test_unexpected_installed_ancillary_handles_all_closed(self):
        kernel = Kernel()
        kernel.unexpected_rights = True
        self.assert_refused(kernel)
        self.assertIn(("close", 90), kernel.log)
        self.assertIn(("close", 91), kernel.log)
        self.assertIsNone(kernel.ack_raw)

    def test_partial_publication_residue_and_no_completion_or_ack(self):
        kernel = Kernel([b'{"x":1}\n'])
        kernel.partial_write = True
        error = self.assert_refused(kernel)
        self.assertIs(error.observed["publication_attempted"], True)
        self.assertEqual(kernel.published(".ndjson")[0][1], b"{")
        self.assertFalse(kernel.completions)
        self.assertIsNone(kernel.ack_raw)

    def test_fsync_and_publication_close_failures_leave_residue(self):
        for field in ("fail_fsync", "close_error"):
            with self.subTest(field=field):
                kernel = Kernel([b'{}\n'])
                setattr(kernel, field, True)
                self.assert_refused(kernel)
                self.assertTrue(kernel.published(".ndjson"))
                self.assertFalse(kernel.completions)

    def test_ack_uncertainty_preserves_publication_and_attempt(self):
        kernel = Kernel()
        kernel.ack_error = BlockingIOError()
        error = self.assert_refused(kernel)
        self.assertIs(error.observed["ack_attempted"], True)
        self.assertIsNotNone(error.observed["ack_raw"])
        self.assertEqual(len(kernel.completions), 1)
        self.assertEqual(len([row for row in kernel.log if row[0] == "ack"]), 1)

    def test_post_ack_payload_refuses_and_no_second_ack(self):
        kernel = Kernel()
        kernel.post_ack_data = True
        self.assert_refused(kernel)
        self.assertEqual(len([row for row in kernel.log if row[0] == "ack"]), 1)

    def test_post_ack_close_wait_uses_outer_deadline_and_never_resets(self):
        kernel = Kernel()
        kernel.never_close = True
        error = self.assert_refused(kernel)
        self.assertIsNotNone(error.observed["ack_raw"])
        self.assertEqual(error.observed["ack_raw"], kernel.ack_raw)
        self.assertEqual(len([row for row in kernel.log if row[0] == "ack"]), 1)
        self.assertEqual(len(kernel.completions), 1)
        ack = document(kernel.ack_raw)
        deadline = min(document(kernel.notice())["request_deadline_ns"], ack["ack_ns"] + 200000000,
                       document(kernel.arguments["loop_provision_raw"])["session_deadline_ns"])
        completion = next(i for i, row in enumerate(kernel.log) if row[0] == "write" and row[1] == 8 and b"checkpoint-ready" in row[2])
        ack_index = next(i for i, row in enumerate(kernel.log) if row[0] == "ack")
        timeout = next(i for i, row in enumerate(kernel.log) if row[0] == "poll_timeout")
        self.assertLess(completion, ack_index)
        self.assertLess(ack_index, timeout)
        self.assertGreaterEqual(kernel.now, deadline)
        self.assertLessEqual(kernel.now, deadline + 1001000)

    def test_detach_failure_keeps_local_socket_owner_without_close_retry(self):
        kernel = Kernel()
        kernel.detach_error = True
        error = self.assert_refused(kernel)
        self.assertTrue(error.cleanup_failures)
        self.assertIn(kernel.sock, error.unresolved_owner.unresolved_sockets)
        self.assertEqual(len([row for row in kernel.log if row == ("detach", kernel.sock.fd)]), 1)
        self.assertNotIn(("close", kernel.sock.fd), kernel.log)

    def test_foreign_reused_socket_is_detached_and_never_closed(self):
        kernel = Kernel()
        kernel.substitute_client = True
        error = self.assert_refused(kernel)
        self.assertTrue(error.cleanup_failures)
        self.assertTrue(kernel.sock.detached)
        self.assertNotIn(("close", kernel.sock.fd), kernel.log)

    def test_cancellation_at_startup_retains_actual_ready_and_closes_once(self):
        kernel = Kernel()
        kernel.cancel_at_ready = True
        result = kernel.execute()
        self.assertEqual(document(result["terminal_raw"])["reason"], "CANCELLED")
        self.assertIsNotNone(result["observed"]["startup_ready_raw"])
        for fd in range(3, 12):
            self.assertEqual(kernel.log.count(("close", fd)), 1)

    def test_stderr_and_supplementary_groups_fail_closed(self):
        kernel = Kernel()
        kernel.stderr = True
        error = self.assert_refused(kernel)
        self.assertEqual(error.observed["stderr_raw"], b"warning\n")
        kernel = Kernel()
        kernel.supplementary = True
        self.assert_refused(kernel)
        self.assertFalse(kernel.ready)

    def test_duplicate_transferred_pidfd_does_not_close_twice(self):
        kernel = Kernel()
        kernel.arguments["bridge_pidfd"] = 9
        self.assert_refused(kernel)
        self.assertEqual(kernel.log.count(("close", 9)), 1)

    def test_independent_input_pin_refusal_occurs_before_publication(self):
        kernel = Kernel()
        kernel.arguments["expected_stream_digest"] = pin(b"other stream")
        self.assert_refused(kernel)
        self.assertFalse(kernel.ready)
        self.assertFalse(kernel.published(".json"))

    def test_trailing_poll_cannot_remove_nonblock_before_completion_write(self):
        kernel = Kernel()
        kernel.late_completion_flags = True
        self.assert_refused(kernel)
        self.assertFalse(kernel.ready)
        self.assertFalse(any(row[0] == "write" and row[1] == 8 for row in kernel.log))

    def test_sealed_batch_mutation_during_final_receipt_readback_prevents_notice(self):
        kernel = Kernel([b'{}\n'])
        kernel.mutate_sealed = True
        error = self.assert_refused(kernel)
        self.assertTrue(error.cleanup_failures)
        self.assertFalse(kernel.completions)
        self.assertIsNone(kernel.ack_raw)
        self.assertEqual(len(kernel.published(".json")), 2)

    def test_same_inode_pidfd_association_substitution_is_not_closed(self):
        kernel = Kernel()
        kernel.swap_pidfd = True
        error = self.assert_refused(kernel)
        self.assertTrue(error.cleanup_failures)
        self.assertNotIn(("close", 9), kernel.log)
        self.assertIn(9, kernel.fds)

    def test_replaced_stderr_fd_is_not_read_or_retained(self):
        kernel = Kernel()
        kernel.stderr = kernel.swap_stderr = True
        error = self.assert_refused(kernel)
        self.assertIsNone(error.observed["stderr_raw"])
        self.assertFalse(any(row[0] == "read" and row[1] == 6 for row in kernel.log))

    def test_failed_refresh_does_not_relabel_prior_publication(self):
        kernel = Kernel([b'{}\n'], refresh=True)
        kernel.refresh_failure = True
        error = self.assert_refused(kernel)
        self.assertEqual(error.observed["ack_raw"], kernel.ack_raw)
        self.assertEqual(error.observed["challenge_raw"], kernel.challenge_raw)
        self.assertEqual(error.observed["sequence_before"], 1)
        self.assertEqual(error.observed["batch_raw"], b"")
        for key in ("manifest_raw", "publication_raw", "completion_raw"):
            self.assertIsNone(error.observed[key])
        self.assertEqual(len(kernel.completions), 1)

    def test_foreign_thread_or_fork_cannot_receive_or_close_original_descriptors(self):
        for field in ("native_id", "process_id"):
            with self.subTest(field=field):
                kernel = Kernel()
                setattr(kernel, field, 999)
                error = self.assert_refused(kernel)
                self.assertFalse(error.cleanup_failures)
                self.assertFalse(kernel.log)
                self.assertTrue(all(fd in kernel.fds for fd in range(3, 12)))


if __name__ == "__main__":
    unittest.main()
