"""New client/journal integration under a fabricated Linux descriptor/filesystem model.

No host OS, socket, clock, proc, temporary file or historical fixture operation is
performed by the model. The actual public journal and codec are used. Only the
not-yet-generated public measurement accessor and native boundaries are mocked.
"""

import array
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct
import sys
import types
import unittest
from unittest.mock import patch

from aragorn import native_phase3_broker_reader_client as client
from aragorn import runtime_http_run_submission as journal
from aragorn import runtime_action_broker as broker


P = "sha256:" + "a" * 64
BOOT = "00000000-0000-0000-0000-000000000001"
CONTROL = "/var/lib/aragorn-runtime-action/control"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def metadata(inode, mode, uid=0, gid=0, device=1):
    return dict(device=device, inode=inode, mode=mode, uid=uid, gid=gid)


class Native:
    """Independent memory inodes and FD generations, including real journal writes."""
    def __init__(self):
        self.pid = client._PID
        self.broker = dict(pid=self.pid, start_time_ticks=100, uid=1001, gid=1002)
        self.provider = dict(pid=self.pid + 100, start_time_ticks=200, uid=0, gid=0)
        self.supervisor = dict(pid=self.pid + 200, start_time_ticks=300, uid=0, gid=0)
        self.namespace = dict(device=7, inode=700)
        self.now = 1000000000
        self.step = 10
        self.fds, self.files, self.calls, self.closed = {}, {}, [], []
        self.next_inode = 1000
        self.next_fd = 7
        self.free = []
        self.cancel = None
        self.peer_pid = self.provider["pid"]
        self.buffer = 524320
        self.connect_result = 0
        self.send_result = None
        self.send_error = None
        self.response_edit = None
        self.controls = None
        self.receive_flags = 0
        self.read_hook = self.stat_hook = self.close_hook = self.poll_hook = self.clock_hook = None
        self.fdinfo_hook = None
        self.accessor_calls = []
        self.accessor_present = True
        self.response = None
        self.sockets = []
        self.all_paths = []
        self.directories = []
        paths = ("/", "/run", "/run/aragorn-phase3-broker-reader", "/var", "/var/lib", "/var/lib/aragorn-runtime-action", CONTROL)
        for index, path in enumerate(paths):
            uid, gid, mode = 0, 0, stat.S_IFDIR | 0o755
            if index == 2:
                gid, mode = 1002, stat.S_IFDIR | 0o710
            elif index == 6:
                uid, gid, mode = 1001, 1002, stat.S_IFDIR | 0o700
            node = self.node(path, metadata(800 + index, mode, uid, gid))
            self.directories.append(dict(path=path, **node["meta"]))
        self.node("/run/aragorn-broker-boot-id", metadata(900, stat.S_IFREG | 0o444), (BOOT + "\n").encode())
        self.node("/run/aragorn-phase3-broker-reader/guard.sock", metadata(901, stat.S_IFSOCK | 0o660, gid=1002))
        self.node(f"/proc/{self.pid}/ns/time", metadata(700, stat.S_IFREG | 0o444, device=7))
        self.node(f"/proc/{self.pid}/ns/mnt", metadata(701, stat.S_IFREG | 0o444, device=7))
        self.node(CONTROL + "/broker.lock", metadata(902, stat.S_IFREG | 0o600, 1001, 1002))
        self.cancel_meta = metadata(500, stat.S_IFIFO | 0o600)
        self.install(3, dict(meta=self.cancel_meta, data=b"", mtime=1, ctime=1, nlink=1), os.O_RDONLY | os.O_NONBLOCK, "pipe:[500]", kind="cancel")
        self.install(4, self.new_node(stat.S_IFREG | 0o600), os.O_RDONLY, "anon_inode:[pidfd]", kind="pidfd", pid=self.supervisor["pid"])
        self.install(5, self.files[CONTROL], os.O_RDONLY | os.O_DIRECTORY, CONTROL)
        self.install(6, self.files[CONTROL + "/broker.lock"], os.O_RDWR, CONTROL + "/broker.lock")
        self.arguments, self.request_raw, self.effect_raw, self.pending_raw = self.inputs()
        self.node(CONTROL + "/decision-measurement-pending.json", metadata(903, stat.S_IFREG | 0o400, 1001, 1002), self.pending_raw)
        self.config = types.SimpleNamespace(control_root=Path(CONTROL), lock_path=Path(CONTROL + "/broker.lock"),
                                            expected_broker_uid=1001, expected_runtime_uid=1003, expected_runtime_gid=1002)

    def node(self, path, meta, data=b""):
        node = dict(meta=meta, data=data, mtime=1, ctime=1, nlink=1)
        self.files[path] = node
        return node

    def new_node(self, mode, data=b"", uid=0, gid=0):
        self.next_inode += 1
        return dict(meta=metadata(self.next_inode, mode, uid, gid), data=data, mtime=1, ctime=1, nlink=1)

    def install(self, fd, node, flags, link, *, kind="file", pid=None):
        self.fds[fd] = dict(node=node, flags=flags & ~os.O_CLOEXEC, dflags=fcntl.FD_CLOEXEC,
                            link=link, kind=kind, pid=pid, offset=0)
        return fd

    def allocate(self, node, flags, link, **kwargs):
        if self.free:
            fd = min(self.free)
            self.free.remove(fd)
        else:
            fd = self.next_fd
            self.next_fd += 1
        return self.install(fd, node, flags, link, **kwargs)

    def inputs(self):
        fixture = dict(schema="aragorn/runtime-http-fixture-binding/v1", fixture=dict(container_id="1" * 64,
            boot_id=BOOT, netns_device=2, netns_inode=201), expected_broker_uid=1001, expected_broker_gid=1002)
        fixture_raw = canonical(fixture)
        body = b"p3canary-p3-lab-a001"
        canary = ("POST /aragorn-phase3-canary HTTP/1.1\r\nHost: 127.0.0.1:47631\r\nConnection: close\r\n"
                  "Content-Type: application/octet-stream\r\nContent-Length: " + str(len(body)) + "\r\n\r\n").encode() + body
        actions = dict(operation_digest=digest(canonical(dict(schema="aragorn/runtime-http-operation/v1", operation="http_canary_post"))),
            path_digest=digest(canonical(dict(schema="aragorn/runtime-http-endpoint/v1", fixture_binding_digest=digest(fixture_raw),
                fixture=fixture["fixture"], host="127.0.0.1", port=47631, method="POST", path="/aragorn-phase3-canary"))), payload_digest=digest(canary))
        measurement = dict(schema="aragorn/runtime-broker-decision-measurement-binding/v1", boot_id=BOOT,
            attempt_id="p3-lab-a001", source_pins={"client.py": P}, **actions)
        for key in ("deployment_identity_digest", "measurement_schedule_digest", "collection_commitment_digest", "scheduled_measurement_request_digest",
                    "grant_digest", "runtime_profile_digest", "sensor_digest", "runtime_digest", "policy_digest", "active_skill_digest"):
            measurement[key] = P
        measurement_raw = canonical(measurement)
        source_raw = canonical(dict(schema="aragorn/native-phase3-broker-reader-installed-sources/v1",
            predecessor_report_digest="sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9",
            entries=[dict(path="/usr/lib/aragorn/client.py", role="BROKER", bytes=1, digest=P,
                          **metadata(910, stat.S_IFREG | 0o444))]))
        provision = dict(schema="aragorn/native-phase3-broker-reader-ipc-provision/v1", profile="HTTP_REFUSAL_ONLY",
            broker=self.broker, provider=self.provider, supervisor=self.supervisor,
            clock=dict(boot_id=BOOT, clock_id="CLOCK_BOOTTIME", time_namespace=self.namespace), epoch_digest=P,
            deployment_digest=P, grant_digest=P, measurement_binding_digest=digest(measurement_raw), fixture_binding_digest=digest(fixture_raw),
            source_inventory_digest=digest(source_raw), access_inventory_digest=P,
            reader_session={k: P for k in ("epoch_digest", "checkpoint_provision_digest", "transport_provision_digest", "stream_digest", "loop_provision_digest")},
            directories=self.directories, cancellation_pipe=dict(**self.cancel_meta, writer=dict(process="SUPERVISOR", fd=50),
                readers=[dict(process="PROVIDER", fd=51), dict(process="BROKER", fd=3)]), session_deadline_ns=2000000000, accept_deadline_ns=1800000000)
        arguments = {}
        for name, raw in (("provision", canonical(provision)), ("source_inventory", source_raw),
                          ("measurement_binding", measurement_raw), ("fixture_binding", fixture_raw)):
            arguments[name + "_raw"] = raw
            arguments["expected_" + name + "_digest"] = digest(raw)
        arguments.update(ipc_cancel_read_fd=3, supervisor_pidfd=4)
        request = dict(schema="aragorn/runtime-action-request/v1", authority="RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            runtime_digest=P, active_skill_digest=P, policy_digest=P, session_id="session", run_id="run", tool_call_id="tool",
            policy_version=1, issued_at_unix=100, expires_at_unix=105, **actions)
        request_raw = canonical(request)
        effect_raw = canonical(dict(schema="aragorn/runtime-http-canary-effect/v1", operation="http_canary_post", attempt_id="p3-lab-a001"))
        pending = canonical(dict(schema="aragorn/runtime-broker-decision-measurement-pending/v1", binding=measurement,
            process=dict(**self.broker, boot_id=BOOT, mount_namespace="mnt:[701]"), clock_id="CLOCK_BOOTTIME",
            acceptance_boundary="V4_ISSUED_SUBMISSION_VALIDATED_BEFORE_GRANT_CLAIM", accepted_boottime_ns=900000000,
            action_request_digest=digest(request_raw), submission_digest=P, lease_digest=P, runtime_attribution_digest=P))
        return arguments, request_raw, effect_raw, pending

    def path(self, path, dir_fd=None):
        path = str(path)
        if not path.startswith("/"):
            path = self.fds[dir_fd]["link"].rstrip("/") + "/" + path
        return path

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        path = self.path(path, dir_fd)
        self.all_paths.append(path)
        if path.startswith("/proc/self/fdinfo/"):
            target = int(path.rsplit("/", 1)[1])
            if self.fdinfo_hook:
                self.fdinfo_hook(target)
            row = self.fds[target]
            if row["kind"] == "pidfd":
                raw = f"Pid:\t{row['pid']}\n".encode()
            elif target == 6:
                meta = row["node"]["meta"]
                raw = (f"pos:\t0\nflags:\t{row['flags'] | os.O_CLOEXEC:o}\nmnt_id:\t1\nino:\t{meta['inode']}\n"
                       f"lock:\t1: FLOCK ADVISORY WRITE {self.pid} {os.major(meta['device']):x}:{os.minor(meta['device']):x}:{meta['inode']} 0 EOF\n").encode()
            else:
                raise AssertionError("unexpected fdinfo")
            node = self.new_node(stat.S_IFREG | 0o400, raw)
        elif path in (f"/proc/{self.pid}/stat", f"/proc/{self.pid}/status"):
            raw = (f"{self.pid} (broker) S " + "0 " * 18 + "100\n").encode() if path.endswith("/stat") else b"Uid:\t1001 1001 1001 1001\nGid:\t1002 1002 1002 1002\nGroups:\t1002\n"
            node = self.new_node(stat.S_IFREG | 0o400, raw)
        else:
            if flags & os.O_CREAT:
                if path in self.files and flags & os.O_EXCL:
                    raise FileExistsError(path)
                self.files[path] = self.new_node(stat.S_IFREG | mode, uid=1001, gid=1002)
                self.calls.append(("create", path))
            if path not in self.files:
                raise FileNotFoundError(path)
            node = self.files[path]
        link = path
        if path.endswith("/ns/time"):
            link = "time:[700]"
        elif path.endswith("/ns/mnt"):
            link = "mnt:[701]"
        return self.allocate(node, flags, link)

    def fstat(self, fd):
        if self.stat_hook:
            self.stat_hook(fd)
        node = self.fds[fd]["node"]
        m = node["meta"]
        return types.SimpleNamespace(st_dev=m["device"], st_ino=m["inode"], st_mode=m["mode"],
            st_uid=m["uid"], st_gid=m["gid"], st_nlink=node["nlink"], st_size=len(node["data"]),
            st_mtime_ns=node["mtime"], st_ctime_ns=node["ctime"])

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        path = self.path(path, dir_fd)
        node = self.files[path]
        m = node["meta"]
        return types.SimpleNamespace(st_dev=m["device"], st_ino=m["inode"], st_mode=m["mode"],
            st_uid=m["uid"], st_gid=m["gid"], st_nlink=node["nlink"], st_size=len(node["data"]),
            st_mtime_ns=node["mtime"], st_ctime_ns=node["ctime"])

    def readlink(self, path):
        path = str(path)
        if path.startswith("/proc/self/fd/"):
            return self.fds[int(path.rsplit("/", 1)[1])]["link"]
        if path == f"/proc/{self.pid}/ns/time":
            return "time:[700]"
        if path == f"/proc/{self.pid}/ns/mnt":
            return "mnt:[701]"
        raise AssertionError("unexpected proc link " + path)

    def read(self, fd, size):
        row = self.fds[fd]
        if self.read_hook:
            self.read_hook(fd, row)
        if row["kind"] == "cancel":
            if self.cancel is None:
                raise BlockingIOError(errno.EAGAIN, "model empty")
            return self.cancel
        start = row["offset"]
        result = row["node"]["data"][start:start + size]
        row["offset"] += len(result)
        return result

    def pread(self, fd, size, offset):
        row = self.fds[fd]
        if self.read_hook:
            self.read_hook(fd, row)
        return row["node"]["data"][offset:offset + size]

    def write(self, fd, data):
        row = self.fds[fd]
        node = row["node"]
        raw = bytes(data)
        node["data"] += raw
        node["mtime"] += 1
        node["ctime"] += 1
        self.calls.append(("write", row["link"], raw))
        return len(raw)

    def close(self, fd):
        if self.close_hook:
            self.close_hook(fd)
        self.calls.append(("close", fd))
        self.closed.append((fd, self.fds[fd]["node"]["meta"]["inode"]))
        del self.fds[fd]
        self.free.append(fd)

    def fcntl(self, fd, command):
        if command == fcntl.F_GETFL:
            return self.fds[fd]["flags"]
        if command == fcntl.F_GETFD:
            return self.fds[fd]["dflags"]
        raise AssertionError("unmodeled fcntl")

    def clock(self, which):
        if self.clock_hook:
            self.clock_hook(which)
        self.now += self.step
        return self.now

    def accessor(self, **kwargs):
        self.accessor_calls.append(kwargs)
        return self.pending_raw

    def import_module(self, name, package):
        if name != ".runtime_broker_decision_measurement" or package != "aragorn":
            raise AssertionError("unexpected late import")
        return types.SimpleNamespace(current_http_guard_pending=self.accessor) if self.accessor_present else types.SimpleNamespace()

    def response_for(self, request_raw):
        request = json.loads(request_raw)
        response = dict(schema="aragorn/native-phase3-broker-reader-response/v1", request_packet_digest=digest(request_raw),
            **{key: request[key] for key in ("exchange_id", "phase", "context_digest", "epoch_digest", "request_digest", "effect_digest")},
            received_ns=self.now, finished_ns=self.now + 1, status="REFUSED", error_codes=["LOSS_UNAVAILABLE"],
            reader_connection_epoch=None, bindings=None, reader_evidence=None, reader_summary=None, reader_retention=None,
            loss_record=None, checkpoint_record=None,
            acquisition_authenticity_verified=False, sensor_health_verified=False, effect_authorized=False,
            run_qualified=False, phase3_qualified=False)
        if self.response_edit:
            self.response_edit(response)
        return canonical(response)

    def socket(self, family, kind):
        if family != socket.AF_UNIX or kind & socket.SOCK_SEQPACKET != socket.SOCK_SEQPACKET:
            raise AssertionError("unexpected socket family")
        result = Socket(self)
        self.sockets.append(result)
        return result

    def poll(self):
        native = self
        class Poll:
            def __init__(self):
                self.watched = {}
            def register(self, fd, events):
                self.watched[fd] = events
            def poll(self, timeout):
                if native.poll_hook:
                    result = native.poll_hook(self.watched, timeout)
                    if result is not None:
                        return result
                if timeout == 0:
                    return []
                rows = []
                for fd, mask in self.watched.items():
                    row = native.fds[fd]
                    if row["kind"] == "socket":
                        if mask & select.POLLOUT:
                            rows.append((fd, select.POLLOUT))
                        elif native.response is not None:
                            rows.append((fd, select.POLLIN))
                if not rows:
                    native.now += timeout * 1000000
                return rows
        return Poll()

    def os_module(self):
        # Only constants and the explicitly listed native operations exist.
        values = {name: value for name, value in vars(os).items() if name.startswith("O_")}
        values.update(open=self.open, read=self.read, pread=self.pread, write=self.write, close=self.close,
            fstat=self.fstat, stat=self.stat, readlink=self.readlink, getpid=lambda: self.pid,
            getresuid=lambda: (1001, 1001, 1001), getresgid=lambda: (1002, 1002, 1002), getgroups=lambda: [1002],
            get_inheritable=lambda fd: not bool(self.fds[fd]["dflags"] & fcntl.FD_CLOEXEC),
            fsync=lambda fd: self.calls.append(("fsync", self.fds[fd]["link"])), major=os.major, minor=os.minor)
        return types.SimpleNamespace(**values)


class Socket:
    def __init__(self, native):
        self.n = native
        self.fd = native.allocate(native.new_node(stat.S_IFSOCK | 0o600, uid=1001, gid=1002),
                                  os.O_RDWR | os.O_NONBLOCK, "socket:[999]", kind="socket")
        self.options = {}
        self.detaches = 0
    def fileno(self):
        return self.fd
    def setblocking(self, value):
        if value:
            raise AssertionError("blocking requested")
    def set_inheritable(self, value):
        if value:
            raise AssertionError("inheritable requested")
    def get_inheritable(self):
        return not bool(self.n.fds[self.fd]["dflags"] & fcntl.FD_CLOEXEC)
    def gettimeout(self):
        return 0.0
    def setsockopt(self, level, option, value):
        self.options[option] = value
    def getsockopt(self, level, option, size=None):
        if option == 17:
            return struct.pack("=iII", self.n.peer_pid, 0, 0)
        if option == 77:
            return self.n.allocate(self.n.new_node(stat.S_IFREG | 0o600), os.O_RDONLY,
                                   "anon_inode:[pidfd]", kind="pidfd", pid=self.n.peer_pid)
        if option == socket.SO_TYPE:
            return socket.SOCK_SEQPACKET
        if option in (socket.SO_SNDBUF, socket.SO_RCVBUF):
            return self.n.buffer
        if option == socket.SO_ERROR:
            return 0
        return self.options[option]
    def connect_ex(self, path):
        self.n.calls.append(("connect", path))
        return self.n.connect_result
    def send(self, raw, flags):
        self.n.calls.append(("send", raw, flags))
        if self.n.send_error:
            raise self.n.send_error
        self.n.response = self.n.response_for(raw)
        return len(raw) if self.n.send_result is None else self.n.send_result
    def recvmsg(self, size, control_size, flags):
        self.n.calls.append(("recv", size, control_size, flags))
        raw, self.n.response = self.n.response, None
        controls = self.n.controls if self.n.controls is not None else [(socket.SOL_SOCKET, 2, struct.pack("=iII", self.n.peer_pid, 0, 0))]
        return raw, controls, self.n.receive_flags, None
    def detach(self):
        self.detaches += 1
        fd, self.fd = self.fd, -1
        return fd


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.n = Native()
        self.patchers = []
        self.addCleanup(self.stop_patches)
        native_os = self.n.os_module()
        native_time = types.SimpleNamespace(CLOCK_BOOTTIME=7, CLOCK_MONOTONIC=1, clock_gettime_ns=self.n.clock)
        native_fcntl = types.SimpleNamespace(F_GETFL=fcntl.F_GETFL, F_GETFD=fcntl.F_GETFD, FD_CLOEXEC=fcntl.FD_CLOEXEC, fcntl=self.n.fcntl)
        import threading
        native_threading = types.SimpleNamespace(get_ident=threading.get_ident, main_thread=threading.main_thread,
            current_thread=threading.current_thread, get_native_id=lambda: self.n.pid, Lock=threading.Lock)
        native_socket = {name: value for name, value in vars(socket).items()
                         if isinstance(value, int) and name.isupper()}
        # macOS lacks these Linux creation flags; only the model supplies them.
        native_socket.setdefault("SOCK_NONBLOCK", 0x800)
        native_socket.setdefault("SOCK_CLOEXEC", 0x80000)
        native_socket["socket"] = self.n.socket
        native_select = types.SimpleNamespace(poll=self.n.poll, POLLIN=select.POLLIN, POLLOUT=select.POLLOUT,
            POLLERR=select.POLLERR, POLLHUP=select.POLLHUP, POLLNVAL=select.POLLNVAL)
        for module in (client, journal):
            self.replace(module, "os", native_os)
            self.replace(module, "time", native_time)
            self.replace(module, "fcntl", native_fcntl)
            self.replace(module, "threading", native_threading)
            self.replace(module, "sys", types.SimpleNamespace(platform="linux", byteorder="little"))
        self.replace(broker, "os", native_os)  # actual journal public write_all uses this boundary
        self.replace(client, "socket", types.SimpleNamespace(**native_socket))
        self.replace(client, "select", native_select)
        self.replace(client, "secrets", types.SimpleNamespace(token_hex=lambda count: "b" * (count * 2)))
        self.replace(client, "importlib", types.SimpleNamespace(import_module=self.n.import_module))
        for name, value in (("_CONFIGURED", False), ("_BEGUN", False), ("_CONFIGURATION", None), ("_QUARANTINE", [])):
            self.replace(client, name, value)

    def replace(self, owner, name, value):
        patcher = patch.object(owner, name, value)
        self.patchers.append(patcher)
        return patcher.start()

    def stop_patches(self):
        for patcher in reversed(self.patchers):
            patcher.stop()

    def configure(self, **changes):
        return client.configure_broker_reader_guard(**dict(self.n.arguments, **changes))

    def begin(self, **changes):
        arguments = dict(request_raw=self.n.request_raw, effect_raw=self.n.effect_raw, deadline_monotonic=1.4)
        arguments.update(changes)
        return client.begin_http_guard_locked(5, 6, self.n.config, **arguments)

    def ready(self):
        self.configure()
        return self.begin()

    def events(self):
        return [json.loads(node["data"]) for name, node in sorted(self.n.files.items())
                if name.startswith(CONTROL + "/run-reader-") and "-event-" in name]

    def test_complete_refusal_uses_real_journal_and_preserves_borrowed_handles(self):
        configured = self.configure()
        self.assertEqual(json.loads(configured["ipc_raw"])["status"], "OPENED")
        guard = self.begin()
        self.assertEqual([v["phase"] for v in self.events()], ["BOUND"])
        self.assertEqual(self.n.sockets[0].detaches, 0)
        result = guard.before_connect()
        self.assertEqual(json.loads(result["response_raw"])["error_codes"], ["LOSS_UNAVAILABLE"])
        self.assertEqual([v["phase"] for v in self.events()], ["BOUND", "CONNECT_CHECKED"])
        self.assertEqual(self.n.sockets[0].detaches, 1)
        guard.finish(transport_raw=None, failure_code="LOSS_UNAVAILABLE")
        closed = guard.close()
        self.assertEqual([v["phase"] for v in self.events()], ["BOUND", "CONNECT_CHECKED", "TERMINAL"])
        self.assertEqual(set(self.n.fds), {3, 4, 5, 6})
        self.assertEqual(json.loads(closed["ipc_raw"])["status"], "CLOSED")
        self.assertEqual(len(self.n.accessor_calls), 1)
        self.assertFalse(any(v["intent"] for v in self.events()))

    def test_retains_complete_raw_reads_and_nonroot_observation_ceiling(self):
        guard = self.ready()
        result = guard.before_connect()
        observed = result["observed"]
        self.assertEqual(observed["measurement_pending_raw"], self.n.pending_raw)
        self.assertEqual(digest(observed["context_raw"]), json.loads(result["request_raw"])["context_digest"])
        self.assertEqual({r["role"] for r in observed["record_observations"]}, {"PENDING", "CONTEXT", "BOUND"})
        self.assertIsNone(json.loads(result["ipc_raw"])["peer"])
        for row in observed["transport_observations"]:
            self.assertIsNone(row["namespaces"]["provider"])
            self.assertIsNone(row["proc_raw"]["provider_stat_before"])
        self.assertFalse(any(f"/proc/{self.n.provider['pid']}/" in p for p in self.n.all_paths))
        guard.finish(transport_raw=None, failure_code="LOSS_UNAVAILABLE")
        guard.close()

    def test_missing_accessor_refuses_without_journal_or_send(self):
        self.configure()
        self.n.accessor_present = False
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            self.begin()
        self.assertEqual(caught.exception.failure_code, "INPUT_REFUSED")
        self.assertEqual(self.events(), [])
        self.assertFalse(self.n.sockets)
        self.assertEqual(set(self.n.fds), {3, 4, 5, 6})

    def test_configuration_reentry_does_not_take_later_handles(self):
        self.configure()
        self.n.install(60, self.n.new_node(stat.S_IFREG | 0o600), os.O_RDONLY, "new")
        with self.assertRaises(ValueError):
            self.configure(ipc_cancel_read_fd=60)
        self.assertIn(60, self.n.fds)
        self.assertIn(3, self.n.fds)

    def test_malformed_first_argument_tracks_later_valid_transfer(self):
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            self.configure(ipc_cancel_read_fd=[])
        owner = caught.exception.unresolved_owner
        self.assertIn(4, owner._owned)
        self.assertEqual(owner._owned[4]["pid"], "UNKNOWN")
        self.assertIn(4, self.n.fds)

    def test_duplicate_mixed_role_marks_unknown_pidfd(self):
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            self.configure(supervisor_pidfd=3)
        self.assertEqual(caught.exception.unresolved_owner._owned[3]["pid"], "UNKNOWN")
        self.assertIn(3, self.n.fds)

    def test_positive_profile_and_changed_input_pin_refuse(self):
        changed = json.loads(self.n.arguments["provision_raw"])
        changed["profile"] = "EVIDENCE"
        raw = canonical(changed)
        with self.assertRaises(client.BrokerReaderIpcError):
            self.configure(provision_raw=raw, expected_provision_digest=digest(raw))
        self.assertFalse(self.n.sockets)

    def test_pending_file_mismatch_refuses_before_connect(self):
        self.configure()
        self.n.files[CONTROL + "/decision-measurement-pending.json"]["data"] = b"{}"
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            self.begin()
        self.assertEqual(caught.exception.observed["measurement_pending_raw"], b"{}")
        self.assertFalse(self.n.sockets)

    def test_pending_mount_is_not_replaced_by_time_namespace(self):
        self.configure()
        value = json.loads(self.n.pending_raw)
        value["process"]["mount_namespace"] = "time:[700]"
        self.n.pending_raw = canonical(value)
        with self.assertRaises(client.BrokerReaderIpcError):
            self.begin()
        self.assertFalse(self.n.sockets)

    def test_action_boolean_policy_version_refuses(self):
        self.configure()
        value = json.loads(self.n.request_raw)
        value["policy_version"] = True
        with self.assertRaises(client.BrokerReaderIpcError):
            self.begin(request_raw=canonical(value))

    def test_foreign_provider_credentials_refuse_without_request_send(self):
        self.configure()
        self.n.peer_pid += 1
        with self.assertRaises(client.BrokerReaderIpcError):
            self.begin()
        self.assertFalse(any(c[0] == "send" for c in self.n.calls))

    def test_in_progress_connect_uses_one_socket_and_one_connect(self):
        self.n.connect_result = errno.EINPROGRESS
        guard = self.ready()
        guard.before_connect()
        self.assertEqual(len(self.n.sockets), 1)
        self.assertEqual(sum(c[0] == "connect" for c in self.n.calls), 1)
        guard.finish(transport_raw=None, failure_code="LOSS_UNAVAILABLE")
        guard.close()

    def test_short_send_retains_attempt_and_never_retries(self):
        guard = self.ready()
        self.n.send_result = 1
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            guard.before_connect()
        self.assertTrue(caught.exception.observed["send_attempted"])
        self.assertEqual(caught.exception.observed["bytes_sent"], 1)
        self.assertEqual(sum(c[0] == "send" for c in self.n.calls), 1)
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.finish(transport_raw=None, failure_code="PROTOCOL_REFUSED")
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.close()
        self.assertEqual(self.events()[-1]["phase"], "TERMINAL")

    def test_unknown_send_preserves_original_interruption(self):
        guard = self.ready()
        original = KeyboardInterrupt("model send")
        self.n.send_error = original
        with self.assertRaises(KeyboardInterrupt) as caught:
            guard.before_connect()
        self.assertIs(caught.exception, original)
        self.assertTrue(original.observed["send_attempted"])
        self.assertIsNone(original.observed["bytes_sent"])
        with self.assertRaises(KeyboardInterrupt) as closed:
            guard.close()
        self.assertIs(closed.exception, original)
        self.assertEqual(set(self.n.fds), {3, 4, 5, 6})

    def test_all_received_rights_are_registered_before_first_metadata_failure(self):
        guard = self.ready()
        for fd in (60, 61):
            self.n.install(fd, self.n.new_node(stat.S_IFREG | 0o600), os.O_RDONLY, f"rights-{fd}")
        self.n.controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [60, 61]).tobytes())]
        def fail(fd):
            if fd == 60:
                raise OSError("first rights metadata")
        self.n.stat_hook = fail
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            guard.before_connect()
        owner = caught.exception.unresolved_owner
        self.assertIn(60, owner._owned)
        self.assertNotIn(61, self.n.fds)
        self.assertTrue(caught.exception.observed["transport_observations"][-1]["controls"])

    def test_low_received_fd_is_owned_before_refusal(self):
        guard = self.ready()
        self.n.install(0, self.n.new_node(stat.S_IFREG | 0o600), os.O_RDONLY, "low-right")
        self.n.controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [0]).tobytes())]
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.before_connect()
        self.assertNotIn(0, self.n.fds)
        self.assertTrue(any(fd == 0 for fd, _ in self.n.closed))

    def test_borrowed_rights_alias_is_not_closed(self):
        guard = self.ready()
        self.n.controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [5, 6]).tobytes())]
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.before_connect()
        self.assertIn(5, self.n.fds)
        self.assertIn(6, self.n.fds)

    def test_truncated_response_retains_raw_and_flags(self):
        guard = self.ready()
        self.n.receive_flags = socket.MSG_TRUNC
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            guard.before_connect()
        self.assertIsNotNone(caught.exception.observed["response_raw"])
        self.assertTrue(any(s["receive_flags"] == socket.MSG_TRUNC for s in caught.exception.observed["transport_observations"]))

    def test_positive_wire_response_refuses_even_with_valid_frozen_shape(self):
        guard = self.ready()
        self.n.response_edit = lambda r: r.update(effect_authorized=True)
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.before_connect()
        self.assertEqual([e["phase"] for e in self.events()], ["BOUND"])

    def test_future_receipt_is_rejected_by_real_journal(self):
        guard = self.ready()
        self.n.response_edit = lambda r: r.update(received_ns=1300000000, finished_ns=1300000001)
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            guard.before_connect()
        self.assertIsInstance(caught.exception.observed["journal_error"], journal.SubmissionJournalError)
        self.assertFalse(caught.exception.observed["journal_error"].intent_attempted)

    def test_cancellation_wins_ready_response(self):
        guard = self.ready()
        def cancel(watched, timeout):
            if timeout:
                self.n.cancel = b""
            return None
        self.n.poll_hook = cancel
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.before_connect()
        self.assertFalse(any(c[0] == "recv" for c in self.n.calls))

    def test_cancel_data_refuses_before_send(self):
        guard = self.ready()
        self.n.cancel = b"x"
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.before_connect()
        self.assertFalse(any(c[0] == "send" for c in self.n.calls))

    def test_late_cancel_nonblocking_change_refuses_before_read(self):
        guard = self.ready()
        observed = []
        def change(fd, row):
            if row["link"].endswith("/status"):
                self.n.fds[3]["flags"] &= ~os.O_NONBLOCK
            if fd == 3:
                observed.append(fd)
        self.n.read_hook = change
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.before_connect()
        self.assertEqual(observed, [])

    def test_closed_generation_numbers_are_reused_normally(self):
        guard = self.ready()
        guard.before_connect()
        guard.finish(transport_raw=None, failure_code="LOSS_UNAVAILABLE")
        guard.close()
        numbers = [fd for fd, _ in self.n.closed]
        self.assertLess(len(set(numbers)), len(numbers))
        self.assertEqual(set(self.n.fds), {3, 4, 5, 6})

    def test_terminal_finish_after_original_deadline_does_not_renew_authority(self):
        guard = self.ready()
        guard.before_connect()
        self.n.now = 1500000000
        result = guard.finish(transport_raw=None, failure_code="DEADLINE_EXPIRED")
        self.assertFalse(json.loads(result["ipc_raw"])["effect_authorized"])
        self.assertEqual(self.events()[-1]["failure_code"], "DEADLINE_EXPIRED")
        guard.close()

    def test_payload_phase_never_sends_or_records_intent(self):
        guard = self.ready()
        guard.before_connect()
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.before_payload_send()
        self.assertEqual(sum(c[0] == "send" for c in self.n.calls), 1)
        self.assertFalse(any(e["intent"] for e in self.events()))

    def test_second_begin_leaves_active_owner_and_new_borrowed_handles(self):
        guard = self.ready()
        with self.assertRaises(ValueError):
            self.begin()
        self.assertIn(guard._connection.fileno(), self.n.fds)
        guard.before_connect()
        guard.finish(transport_raw=None, failure_code="LOSS_UNAVAILABLE")
        guard.close()

    def test_foreign_process_call_never_closes_existing_resources(self):
        guard = self.ready()
        before = list(self.n.closed)
        self.n.pid += 1
        with self.assertRaises(ValueError):
            guard.close()
        self.assertEqual(self.n.closed, before)

    def test_socket_close_ambiguity_is_consumed_once(self):
        guard = self.ready()
        fd = guard._connection.fileno()
        calls = []
        def fail(target):
            if target == fd:
                calls.append(target)
                raise OSError("ambiguous close")
        self.n.close_hook = fail
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.before_connect()
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.close()
        self.assertEqual(calls, [fd])
        self.assertIn(guard, client._QUARANTINE)

    def test_bound_readback_detects_tampered_temporal_join(self):
        self.configure()
        actual_begin = client.begin_http_submission_locked
        def after_real_begin(*args, **kwargs):
            actual = actual_begin(*args, **kwargs)
            name = CONTROL + "/run-reader-" + digest(self.n.request_raw)[7:] + "-event-0.json"
            node = self.n.files[name]
            value = json.loads(node["data"])
            value["checked_ns"] = 1
            node["data"] = canonical(value)
            return actual
        self.replace(client, "begin_http_submission_locked", after_real_begin)
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            self.begin()
        self.assertEqual(json.loads(caught.exception.observed["bound_raw"])["checked_ns"], 1)
        self.assertEqual(str(caught.exception.original_failure), "BOUND chronology")
        self.assertFalse(any(c[0] == "send" for c in self.n.calls))

    def test_original_failure_survives_later_terminal_error(self):
        guard = self.ready()
        self.n.send_result = 1
        with self.assertRaises(client.BrokerReaderIpcError) as first:
            guard.before_connect()
        with self.assertRaises(client.BrokerReaderIpcError) as later:
            guard.finish(transport_raw=b"not-json", failure_code="PROTOCOL_REFUSED")
        self.assertIs(first.exception, later.exception)
        self.assertTrue(later.exception.cleanup_failures)

    def test_final_clock_cannot_hide_cancel_flags_change(self):
        guard = self.ready()
        armed = [False]
        def clock(which):
            if armed[0]:
                self.n.fds[3]["flags"] &= ~os.O_NONBLOCK
                armed[0] = False
        def after_status(fd, row):
            if row["link"].endswith("/status"):
                armed[0] = True
        self.n.read_hook = after_status
        self.n.clock_hook = clock
        with self.assertRaises(client.BrokerReaderIpcError):
            guard.before_connect()
        self.assertFalse(any(c[0] == "send" for c in self.n.calls))

    def test_borrowed_lock_actual_flock_is_required_before_pending(self):
        self.configure()
        original_open = self.n.open
        def changed(path, flags, mode=0o777, *, dir_fd=None):
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            if str(path) == "/proc/self/fdinfo/6":
                self.n.fds[fd]["node"]["data"] = self.n.fds[fd]["node"]["data"].replace(b"ADVISORY WRITE", b"ADVISORY READ")
            return fd
        self.replace(client.os, "open", changed)
        with self.assertRaises(client.BrokerReaderIpcError):
            self.begin()
        self.assertEqual(self.n.accessor_calls, [])
        self.assertFalse(self.n.sockets)

    def test_named_context_replacement_retains_refusal_not_success(self):
        self.configure()
        armed = [True]
        def replace_record(fd, row):
            if armed[0] and row["link"].endswith("-context.json") and row["node"]["data"]:
                armed[0] = False
                old = self.n.files[row["link"]]
                self.n.files[row["link"]] = dict(old, meta=dict(old["meta"], inode=999999))
        actual_begin = client.begin_http_submission_locked
        def after_real_begin(*args, **kwargs):
            actual = actual_begin(*args, **kwargs)
            self.n.read_hook = replace_record
            return actual
        self.replace(client, "begin_http_submission_locked", after_real_begin)
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            self.begin()
        self.assertIsNotNone(caught.exception.observed["context_raw"])
        self.assertEqual(str(caught.exception.original_failure), "record closing identity")
        self.assertFalse(any(c[0] == "send" for c in self.n.calls))

    def test_stage_has_only_explicit_native_boundary_operations(self):
        guard = self.ready()
        guard.before_connect()
        guard.finish(transport_raw=None, failure_code="LOSS_UNAVAILABLE")
        guard.close()
        self.assertTrue(all(path.startswith(("/proc/", "/run/", "/var/")) or path in ("/", "/run", "/var")
                            for path in self.n.all_paths))
        self.assertFalse(any("/usr/lib/aragorn/client.py" == p for p in self.n.all_paths))
        self.assertFalse(any(c[0] in ("unlink", "signal", "reconnect") for c in self.n.calls))

    def test_constructor_late_deadline_retains_real_terminal_before_close(self):
        self.configure()
        actual_begin = client.begin_http_submission_locked
        bound_returns = []
        terminal_calls = []
        actual_finish = journal.SubmissionJournal.finish

        def finish_once(instance, **kwargs):
            terminal_calls.append(kwargs)
            return actual_finish(instance, **kwargs)

        def after_real_bound(*args, **kwargs):
            actual = actual_begin(*args, **kwargs)
            self.assertEqual([e["phase"] for e in self.events()], ["BOUND"])
            bound_returns.append(actual)
            # Arm only after actual context+BOUND publication/readback succeeded.
            self.n.now = 1500000000
            return actual

        self.replace(journal.SubmissionJournal, "finish", finish_once)
        self.replace(client, "begin_http_submission_locked", after_real_bound)
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            self.begin()
        self.assertEqual(len(bound_returns), 1)
        self.assertEqual(caught.exception.failure_code, "DEADLINE_EXPIRED")
        self.assertIs(caught.exception.original_failure, caught.exception.__cause__)
        self.assertEqual(terminal_calls, [dict(transport_raw=None, failure_code="DEADLINE_EXPIRED")])
        events = self.events()
        self.assertEqual([e["phase"] for e in events], ["BOUND", "TERMINAL"])
        self.assertEqual(events[-1]["failure_code"], "DEADLINE_EXPIRED")
        self.assertGreaterEqual(events[-1]["checked_ns"], 1500000000)
        self.assertFalse(events[-1]["intent"])
        self.assertIsNone(events[-1]["effect_possible"])
        self.assertEqual(set(self.n.fds), {3, 4, 5, 6})
        self.assertFalse(any(c[0] == "send" for c in self.n.calls))

    def test_constructor_late_cancel_retains_actual_terminal_publication_failure(self):
        self.configure()
        actual_begin = client.begin_http_submission_locked
        actual_finish = journal.SubmissionJournal.finish
        actual_write = self.n.write
        publication_error = OSError("model terminal publication failure")
        terminal_calls, bound_returns = [], []

        def finish_once(instance, **kwargs):
            terminal_calls.append(kwargs)
            return actual_finish(instance, **kwargs)

        def fail_terminal_write(fd, raw):
            if self.n.fds[fd]["link"].endswith("-event-1.json"):
                raise publication_error
            return actual_write(fd, raw)

        def after_real_bound(*args, **kwargs):
            actual = actual_begin(*args, **kwargs)
            self.assertEqual([e["phase"] for e in self.events()], ["BOUND"])
            bound_returns.append(actual)
            # This EOF arrives only after the real journal's successful return.
            self.n.cancel = b""
            self.replace(broker.os, "write", fail_terminal_write)
            return actual

        self.replace(journal.SubmissionJournal, "finish", finish_once)
        self.replace(client, "begin_http_submission_locked", after_real_bound)
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            self.begin()
        failure = caught.exception
        self.assertEqual(len(bound_returns), 1)
        self.assertEqual(failure.failure_code, "PROTOCOL_REFUSED")
        self.assertEqual(str(failure.original_failure), "cancellation EOF")
        self.assertIs(failure.original_failure, failure.__cause__)
        self.assertEqual(terminal_calls, [dict(transport_raw=None, failure_code="PROTOCOL_REFUSED")])
        self.assertTrue(any(isinstance(e, journal.SubmissionJournalError) and e.__cause__ is publication_error
                            for e in failure.cleanup_failures))
        retained_error = failure.observed["journal_error"]
        self.assertIsInstance(retained_error, journal.SubmissionJournalError)
        self.assertFalse(retained_error.intent_attempted)
        self.assertFalse(retained_error.known_intent)
        name = CONTROL + "/run-reader-" + digest(self.n.request_raw)[7:] + "-event-1.json"
        self.assertIn(name, self.n.files)
        self.assertEqual(self.n.files[name]["data"], b"")
        self.assertEqual(set(self.n.fds), {3, 4, 5, 6})
        self.assertFalse(any(c[0] == "send" for c in self.n.calls))

    def test_configuration_accept_expiry_during_final_view_cleanup_refuses(self):
        late_closes = []
        accept = json.loads(self.n.arguments["provision_raw"])["accept_deadline_ns"]

        def expire_after_opening_guard(fd):
            if self.n.fds[fd]["link"] == "mnt:[701]":
                late_closes.append(fd)
                # The held namespace is disposed only after OPEN guards and
                # the earlier accept-budget check. The session is still live.
                self.n.now = accept

        self.n.close_hook = expire_after_opening_guard
        with self.assertRaises(client.BrokerReaderIpcError) as caught:
            self.configure()
        self.assertEqual(len(late_closes), 1)
        self.assertEqual(caught.exception.failure_code, "DEADLINE_EXPIRED")
        self.assertEqual(str(caught.exception.original_failure), "accept budget spent at closing return")
        self.assertIsNone(caught.exception.observed["ipc_raw"])
        self.assertTrue(client._CONFIGURATION._closed)
        self.assertEqual(set(self.n.fds), {5, 6})
