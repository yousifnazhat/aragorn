"""New service cases with isolated native primitives and explicit leaf boundaries.

The public codec is real. Context acquisition/session boundaries are mocked here;
these cases do not establish their native composition or any installed identity.
All fixture bytes are authored below; no historical tests/fixtures are imported.
"""

import array
import hashlib
import json
import os
import socket
import stat
import struct
import threading
import types
import unittest
from unittest.mock import patch

from aragorn import native_phase3_broker_reader_service as service


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def pin(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


P = "sha256:" + "a" * 64
BOOT = "00000000-0000-0000-0000-000000000001"


def meta(inode, mode, uid=0, gid=0, device=1):
    return dict(device=device, inode=inode, mode=mode, uid=uid, gid=gid)


class Native:
    """Memory descriptor table: no host files, sockets, polls, time or proc reads."""
    def __init__(self):
        self.pid = service._PID
        self.provider = dict(pid=self.pid, start_time_ticks=100, uid=0, gid=0)
        self.broker = dict(pid=self.pid + 100, start_time_ticks=200, uid=1001, gid=1002)
        self.supervisor = dict(pid=self.pid + 200, start_time_ticks=300, uid=0, gid=0)
        self.reader = dict(pid=self.pid + 300, start_time_ticks=400, uid=1003, gid=1004)
        self.processes = {p["pid"]: p for p in (self.provider, self.broker, self.supervisor, self.reader)}
        self.fds, self.paths, self.calls, self.closes = {}, {}, [], []
        self.next_fd, self.now = 100, 1000000000
        self.reuse, self.free_fds = False, []
        self.cancel = None
        self.fail_write = self.fail_send = self.fail_context = self.fail_session = None
        self.short_write = self.short_send = False
        self.extra_controls = None
        self.request_flags = 0
        self.buffer = 524320
        self.fdinfo_hook = self.read_hook = self.close_hook = self.fstat_hook = None
        self.context_calls, self.session_calls = [], []
        self.session_instances = []
        self.listened = False
        self.unsafe_calls = []
        self.namespace = dict(device=7, inode=700)
        self.pending_response = False
        self.eof_extra = None
        self.eof_controls, self.eof_flags = [], 0
        self.role_pipes = {15: meta(501, stat.S_IFIFO | 0o600), 17: meta(502, stat.S_IFIFO | 0o600)}
        for fd in range(10, 18):
            if fd in (11, 16):
                pid = self.reader["pid"] if fd == 11 else self.supervisor["pid"]
                self.install(fd, meta(600 + fd, stat.S_IFREG | 0o600), os.O_RDONLY, f"anon_inode:[pidfd]", kind="pidfd", pid=pid)
            else:
                identity = self.role_pipes.get(fd, meta(500 + fd, stat.S_IFIFO | 0o600))
                direction = os.O_WRONLY if fd in (10, 12, 17) else os.O_RDONLY
                self.install(fd, identity, direction | os.O_NONBLOCK, f"pipe:[{identity['inode']}]", kind="pipe")
        paths = ("/", "/run", "/run/aragorn-phase3-broker-reader", "/var", "/var/lib",
                 "/var/lib/aragorn-runtime-action", "/var/lib/aragorn-runtime-action/control")
        self.directories = []
        for i, path in enumerate(paths):
            mode, uid, gid = stat.S_IFDIR | 0o755, 0, 0
            if i == 2:
                mode, gid = stat.S_IFDIR | 0o710, self.broker["gid"]
            if i == 6:
                mode, uid, gid = stat.S_IFDIR | 0o700, self.broker["uid"], self.broker["gid"]
            identity = meta(800 + i, mode, uid, gid)
            self.paths[path] = identity
            self.directories.append(dict(path=path, **identity))
        self.arguments = self.inputs()

    def install(self, fd, identity, flags, link, *, kind="file", data=b"", pid=None, path=None):
        self.fds[fd] = dict(identity=identity, flags=flags, descriptor_flags=1, link=link,
                            kind=kind, data=data, offset=0, pid=pid, path=path)
        return fd

    def allocate(self, identity, flags, link, **kwargs):
        if self.reuse and self.free_fds:
            fd = min(self.free_fds)
            self.free_fds.remove(fd)
        else:
            fd = self.next_fd
            self.next_fd += 1
        return self.install(fd, identity, flags, link, **kwargs)

    def inputs(self):
        clock = dict(boot_id=BOOT, clock_id="CLOCK_BOOTTIME", time_namespace=self.namespace)
        source = canonical(dict(schema="aragorn/native-phase3-broker-reader-installed-sources/v1",
                                predecessor_report_digest="sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9",
                                entries=[dict(path="/usr/lib/aragorn/service.py", role="PROVIDER", bytes=1, digest=P,
                                              **meta(900, stat.S_IFREG | 0o444))]))
        measurement = dict(schema="aragorn/runtime-broker-decision-measurement-binding/v1", boot_id=BOOT,
                           attempt_id="p3-lab-a001", source_pins={"source.py": P})
        for key in ("deployment_identity_digest", "measurement_schedule_digest", "collection_commitment_digest",
                    "scheduled_measurement_request_digest", "grant_digest", "runtime_profile_digest", "sensor_digest",
                    "runtime_digest", "policy_digest", "active_skill_digest", "operation_digest", "path_digest", "payload_digest"):
            measurement[key] = P
        measurement = canonical(measurement)
        fixture = canonical(dict(schema="aragorn/runtime-http-fixture-binding/v1", fixture=dict(
            container_id="1" * 64, boot_id=BOOT, netns_device=2, netns_inode=201),
            expected_broker_uid=self.broker["uid"], expected_broker_gid=self.broker["gid"]))
        # Reader inputs are opaque public-boundary fixtures. The session mock asserts
        # exact transfer, and does not claim to validate the frozen session schemas.
        epoch = canonical(dict(deployment_digest=P))
        checkpoint = canonical(dict(session_deadline_ns=10000000000))
        transport = canonical(dict(session_deadline_ns=10000000000))
        stream = canonical(dict(observer=self.provider, supervisor=self.supervisor, reader=self.reader,
                                clock=clock, access_inventory_digest=P,
                                pipes=[meta(number, stat.S_IFIFO | 0o600) for number in (510, 610, 512, 611, 514, 513)]))
        loop = canonical(dict(startup_deadline_ns=4000000000, session_deadline_ns=10000000000))
        sessions = dict(epoch_digest=pin(epoch), checkpoint_provision_digest=pin(checkpoint),
                        transport_provision_digest=pin(transport), stream_digest=pin(stream), loop_provision_digest=pin(loop))
        provision = dict(schema="aragorn/native-phase3-broker-reader-ipc-provision/v1", profile="HTTP_REFUSAL_ONLY",
                         broker=self.broker, provider=self.provider, supervisor=self.supervisor, clock=clock,
                         epoch_digest=pin(epoch), deployment_digest=P, grant_digest=P, measurement_binding_digest=pin(measurement),
                         fixture_binding_digest=pin(fixture), source_inventory_digest=pin(source), access_inventory_digest=P,
                         reader_session=sessions, directories=self.directories,
                         cancellation_pipe=dict(**self.role_pipes[15], writer=dict(process="SUPERVISOR", fd=50),
                                                readers=[dict(process="PROVIDER", fd=15), dict(process="BROKER", fd=51)]),
                         session_deadline_ns=10000000000, accept_deadline_ns=5000000000)
        provision = canonical(provision)
        ready = canonical(dict(schema="aragorn/native-phase3-broker-reader-bootstrap-readiness-expectation/v1",
                               provider=self.provider, supervisor=self.supervisor, pipe=self.role_pipes[17], provider_write_fd=17,
                               supervisor_read_fd=52, provision_digest=pin(provision), source_inventory_digest=pin(source)))
        result = {}
        for name, raw, digest_name in (("provision", provision, "provision"), ("source_inventory", source, "source_inventory"),
                                       ("measurement_binding", measurement, "measurement_binding"), ("fixture_binding", fixture, "fixture_binding"),
                                       ("epoch", epoch, "epoch"), ("checkpoint_provision", checkpoint, "checkpoint_provision"),
                                       ("transport_provision", transport, "transport_provision"), ("stream_inventory", stream, "stream"),
                                       ("loop_provision", loop, "loop_provision"), ("readiness_expectation", ready, "readiness_expectation")):
            result[name + "_raw"] = raw
            result["expected_" + digest_name + "_digest"] = pin(raw)
        result.update(notice_write_fd=10, reader_pidfd=11, refresh_write_fd=12, completion_read_fd=13,
                      session_cancel_read_fd=14, ipc_cancel_read_fd=15, supervisor_pidfd=16, provider_ready_write_fd=17)
        self.context_raw = canonical(dict(grant_digest=P))
        self.request = canonical(dict(schema="aragorn/native-phase3-broker-reader-request/v1", exchange_id="2" * 64,
                                      phase="BEFORE_CONNECT", context_digest=pin(self.context_raw), epoch_digest=pin(epoch),
                                      request_digest=P, effect_digest=P, deadline_boottime_ns=3000000000,
                                      previous_response_digest=None))
        return result

    def st(self, identity):
        return types.SimpleNamespace(st_dev=identity["device"], st_ino=identity["inode"], st_mode=identity["mode"],
                                     st_uid=identity["uid"], st_gid=identity["gid"])

    def fstat(self, fd):
        if self.fstat_hook:
            self.fstat_hook(fd)
        return self.st(self.fds[fd]["identity"])

    def fcntl(self, fd, operation):
        if operation == service.fcntl.F_GETFL:
            return self.fds[fd]["flags"]
        if operation == service.fcntl.F_GETFD:
            return self.fds[fd]["descriptor_flags"]
        raise AssertionError("unhandled fcntl")

    def resolve(self, path, dir_fd):
        if path.startswith("/"):
            return path
        parent = self.fds[dir_fd]["path"]
        return parent.rstrip("/") + "/" + path

    def namespace_meta(self, pid, kind):
        return meta(700 if kind == "time" else 710 + pid, stat.S_IFREG | 0o444, device=7)

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        path = self.resolve(path, dir_fd)
        if "/ns/" in path:
            _, _, pid, _, kind = path.split("/")
            return self.st(self.namespace_meta(int(pid), kind))
        if path not in self.paths:
            raise FileNotFoundError(path)
        return self.st(self.paths[path])

    def open(self, path, flags, *, dir_fd=None):
        path = self.resolve(path, dir_fd)
        self.calls.append(("open", path))
        if path in self.paths:
            return self.allocate(self.paths[path], flags, path, path=path, kind="directory")
        if "/ns/" in path:
            _, _, pid, _, kind = path.split("/")
            identity = self.namespace_meta(int(pid), kind)
            return self.allocate(identity, flags, f"{kind}:[{identity['inode']}]", path=path, kind="namespace")
        if path == "/proc/sys/kernel/random/boot_id":
            data = (BOOT + "\n").encode()
        elif path.startswith("/proc/self/fdinfo/"):
            fd = int(path.rsplit("/", 1)[1])
            if self.fdinfo_hook:
                self.fdinfo_hook(fd)
            data = f"Pid:\t{self.fds[fd]['pid']}\n".encode()
        else:
            _, _, pid, leaf = path.split("/")
            process = self.processes[int(pid)]
            if leaf == "stat":
                data = (f"{pid} (broker (unit)) S " + "0 " * 18 + str(process["start_time_ticks"]) + "\n").encode()
            elif leaf == "status":
                data = ("Uid:\t" + " ".join([str(process["uid"])] * 4) + "\nGid:\t" +
                        " ".join([str(process["gid"])] * 4) + "\n").encode()
            else:
                raise AssertionError("unhandled read " + path)
        return self.allocate(meta(10000 + self.next_fd, stat.S_IFREG | 0o400), flags, path, path=path, data=data)

    def readlink(self, path):
        if path.startswith("/proc/self/fd/"):
            return self.fds[int(path.rsplit("/", 1)[1])]["link"]
        _, _, pid, _, kind = path.split("/")
        identity = self.namespace_meta(int(pid), kind)
        return f"{kind}:[{identity['inode']}]"

    def read(self, fd, count):
        if self.read_hook:
            self.read_hook(fd)
        row = self.fds[fd]
        # A closed cancellation descriptor can be reused for a proc-file read.
        if fd == 15 and row["kind"] == "pipe":
            if self.cancel is None:
                raise BlockingIOError()
            return self.cancel
        result = row["data"][row["offset"]:row["offset"] + count]
        row["offset"] += len(result)
        return result

    def write(self, fd, raw):
        self.calls.append(("write", fd, raw))
        if self.fail_write:
            raise self.fail_write
        return len(raw) - (1 if self.short_write else 0)

    def close(self, fd):
        self.calls.append(("close", fd))
        if self.close_hook:
            self.close_hook(fd)
        self.closes.append(fd)
        del self.fds[fd]
        self.free_fds.append(fd)

    def chown(self, path, uid, gid, *, dir_fd, follow_symlinks):
        self.paths[self.resolve(path, dir_fd)].update(uid=uid, gid=gid)

    def chmod(self, path, mode, *, dir_fd, follow_symlinks):
        row = self.paths[self.resolve(path, dir_fd)]
        row["mode"] = stat.S_IFMT(row["mode"]) | mode

    def clock(self, clock):
        self.now += 100
        return self.now

    def poll(self):
        native = self
        class Poll:
            def __init__(self):
                self.fds = []
            def register(self, fd, events):
                self.fds.append(fd)
            def poll(self, timeout):
                if timeout == 0:
                    return []
                target = self.fds[0]
                if native.fds[target]["kind"] == "listener":
                    return [(target, service.select.POLLIN)]
                return [(target, service.select.POLLHUP if native.pending_response else service.select.POLLIN)]
        return Poll()

    def socket(self, family, kind):
        return FakeSocket(self, listener=True)

    def context(self, connection, **kwargs):
        self.calls.append(("context",))
        self.context_calls.append((connection, kwargs))
        if self.fail_context:
            raise self.fail_context
        return dict(context_raw=self.context_raw, context_digest=pin(self.context_raw), bound_raw=b"{}",
                    pending_raw=b"{}", submission_verification_raw=b"{}", acquisition_raw=b"{}",
                    acquisition_digest=pin(b"{}"), custody_raw=b"{}")

    def session(self, **kwargs):
        self.calls.append(("session_construct",))
        self.session_calls.append(kwargs)
        native = self
        class Session:
            def acquire_challenge(self, **arguments):
                native.calls.append(("session_acquire", arguments))
                if native.fail_session:
                    raise native.fail_session
                request = json.loads(arguments["request_raw"])
                bindings = {key: P for key in ("epoch", "challenge", "request", "process", "clock", "loss_scope", "policy")}
                bindings.update(epoch=request["epoch_digest"], request=request["request_digest"])
                owned = dict(reader={"status": "ACK"}, challenge_raw=b"{}", claim_raw=b"{}", bindings=bindings,
                             connection_epoch="3" * 64, evidence_raw=b"{}", evidence_digest=pin(b"{}"),
                             **dict.fromkeys(("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized",
                                             "run_qualified", "phase3_qualified"), False))
                return dict(owned=owned, checkpoint={"acquisition_raw": b"{}"}, session_raw=b"{}")
            def finish_request(self, **arguments):
                native.calls.append(("session_finish", arguments))
                return b'{"terminal":"FINISH"}'
            def close(self):
                native.calls.append(("session_close",))
                for name in ("notice_write_fd", "reader_pidfd", "refresh_write_fd", "completion_read_fd", "cancel_read_fd"):
                    native.close(kwargs[name])
                return b'{"terminal":"CLOSE"}'
        value = Session()
        self.session_instances.append(value)
        return value

    def patches(self):
        native_os = types.SimpleNamespace(**{name: getattr(os, name) for name in (
            "O_RDONLY", "O_WRONLY", "O_ACCMODE", "O_NONBLOCK", "O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY")})
        native_os.__dict__.update(getpid=lambda: self.pid, getresuid=lambda: (0, 0, 0), getresgid=lambda: (0, 0, 0),
                                  fstat=self.fstat, open=self.open, read=self.read, write=self.write, close=self.close,
                                  stat=self.stat, readlink=self.readlink, chown=self.chown, chmod=self.chmod,
                                  fpathconf=lambda fd, key: 4096)
        native_socket = types.SimpleNamespace(**{name: getattr(socket, name) for name in (
            "AF_UNIX", "SOCK_SEQPACKET", "SOL_SOCKET", "SO_SNDBUF", "SO_RCVBUF", "SO_TYPE", "SCM_RIGHTS", "MSG_EOR")})
        native_socket.SOCK_NONBLOCK, native_socket.SOCK_CLOEXEC = 2048, 524288
        native_socket.socket = self.socket
        return [patch.object(service, "os", native_os), patch.object(service, "socket", native_socket),
                patch.object(service, "fcntl", types.SimpleNamespace(F_GETFL=3, F_GETFD=1, FD_CLOEXEC=1, fcntl=self.fcntl)),
                patch.object(service, "select", types.SimpleNamespace(POLLIN=1, POLLERR=8, POLLHUP=16, POLLNVAL=32, poll=self.poll)),
                patch.object(service, "time", types.SimpleNamespace(CLOCK_BOOTTIME=7, clock_gettime_ns=self.clock)),
                patch.object(service, "sys", types.SimpleNamespace(platform="linux", byteorder="little")),
                patch.object(service, "ReaderCheckpointSession", self.session),
                patch.object(service, "acquire_broker_reader_context", self.context),
                patch.object(service, "_CONSTRUCTED", False), patch.object(service, "_QUARANTINE", [])]


class FakeSocket:
    def __init__(self, native, *, listener=False):
        self.native, self.listener, self.detached = native, listener, False
        self.fd = native.allocate(meta(20000 + native.next_fd, stat.S_IFSOCK | 0o777), os.O_RDWR | os.O_NONBLOCK,
                                  "socket:[owned]", kind="listener" if listener else "connection")
        self.options = {16: 1, 76: 0, socket.SO_SNDBUF: native.buffer, socket.SO_RCVBUF: native.buffer,
                        socket.SO_TYPE: socket.SOCK_SEQPACKET}
    def fileno(self):
        return -1 if self.detached else self.fd
    def setblocking(self, value):
        self.native.fds[self.fd]["flags"] |= os.O_NONBLOCK
    def set_inheritable(self, value):
        self.native.fds[self.fd]["descriptor_flags"] = 1
    def get_inheritable(self):
        return False
    def gettimeout(self):
        return 0.0
    def setsockopt(self, level, option, value):
        self.options[option] = self.native.buffer if option in (socket.SO_SNDBUF, socket.SO_RCVBUF) else value
    def getsockopt(self, level, option, size=None):
        if option == 17:
            p = self.native.broker
            return struct.pack("=iII", p["pid"], p["uid"], p["gid"])
        if option == 77:
            return self.native.allocate(meta(30000 + self.native.next_fd, stat.S_IFREG | 0o600), os.O_RDONLY,
                                        "anon_inode:[pidfd]", kind="pidfd", pid=self.native.broker["pid"])
        return self.options[option]
    def bind(self, path):
        self.native.calls.append(("bind", path))
        self.native.paths[path] = meta(999, stat.S_IFSOCK | 0o755)
    def listen(self, backlog):
        self.native.calls.append(("listen", backlog))
        self.native.listened = True
    def accept(self):
        self.native.calls.append(("accept",))
        return FakeSocket(self.native), None
    def recvmsg(self, size, ancillary, flags):
        self.native.calls.append(("recv", self.native.pending_response))
        if self.native.pending_response:
            return self.native.eof_extra or b"", self.native.eof_controls, self.native.eof_flags, None
        credentials = self.getsockopt(socket.SOL_SOCKET, 17, 12)
        controls = self.native.extra_controls
        if controls is None:
            controls = [(socket.SOL_SOCKET, 2, credentials)]
        return self.native.request, controls, self.native.request_flags, None
    def sendmsg(self, buffers, controls, flags):
        self.native.calls.append(("send", b"".join(buffers)))
        if self.native.fail_send:
            raise self.native.fail_send
        self.native.pending_response = True
        return sum(map(len, buffers)) - (1 if self.native.short_send else 0)
    def detach(self):
        self.native.calls.append(("detach", self.fd))
        self.detached = True
        return self.fd


class BrokerReaderServiceTests(unittest.TestCase):
    def setUp(self):
        self.native = Native()
        for manager in self.native.patches():
            manager.start()
            self.addCleanup(manager.stop)

    def create(self, **changes):
        return service.BrokerReaderService(**dict(self.native.arguments, **changes))

    def failure(self, action):
        with self.assertRaises(service.BrokerReaderIpcError) as caught:
            action()
        return caught.exception

    def test_ready_after_actual_constructor_and_guard_listen(self):
        owner = self.create()
        names = [call[0] for call in self.native.calls]
        self.assertLess(names.index("session_construct"), names.index("listen"))
        self.assertLess(names.index("listen"), names.index("write"))
        ready = json.loads(owner.opening_result["observed"]["provider_ready_raw"])
        self.assertEqual(ready["guard_socket"]["metadata"], self.native.paths[service._ENDPOINT])
        self.assertEqual(ready["provision_digest"], pin(self.native.arguments["provision_raw"]))
        self.assertEqual(json.loads(owner.opening_result["ipc_raw"])["status"], "OPENED")
        self.assertIn(17, self.native.fds)
        owner.close()

    def test_real_codec_refusal_context_session_and_eof_order(self):
        owner = self.create()
        result = owner.serve_one()
        response = json.loads(result["observed"]["response_raw"])
        self.assertEqual(response["status"], "REFUSED")
        self.assertEqual(response["error_codes"], ["LOSS_UNAVAILABLE"])
        self.assertIsNone(response["loss_record"])
        for flag in ("effect_authorized", "sensor_health_verified", "phase3_qualified"):
            self.assertIs(response[flag], False)
        names = [call[0] for call in self.native.calls]
        self.assertLess(names.index("context"), names.index("session_acquire"))
        self.assertLess(names.index("send"), names.index("session_finish"))
        self.assertEqual(sum(call[0] == "accept" for call in self.native.calls), 1)
        self.assertIn(17, self.native.fds)
        self.assertEqual(result["observed"]["session_finish_raw"], b'{"terminal":"FINISH"}')
        owner.close()

    def test_public_constructor_transfers_exact_original_five(self):
        owner = self.create()
        arguments = self.native.session_calls[0]
        self.assertEqual([arguments[key] for key in ("notice_write_fd", "reader_pidfd", "refresh_write_fd", "completion_read_fd", "cancel_read_fd")], list(range(10, 15)))
        self.assertEqual(arguments["epoch_raw"], self.native.arguments["epoch_raw"])
        owner.close()
        self.assertEqual([self.native.closes.count(fd) for fd in range(10, 18)], [1] * 8)

    def test_actual_received_time_and_protected_expectation_passed(self):
        owner = self.create()
        result = owner.serve_one()
        _, arguments = self.native.context_calls[0]
        expected = json.loads(arguments["expectation_raw"])
        self.assertEqual(expected["broker"], self.native.broker)
        self.assertEqual(expected["broker_source_pins"], {"source.py": P})
        self.assertEqual(arguments["expected_expectation_digest"], pin(arguments["expectation_raw"]))
        acquisition = next(call[1] for call in self.native.calls if call[0] == "session_acquire")
        self.assertEqual(acquisition["request_received_ns"], arguments["request_received_ns"])
        self.assertEqual(acquisition["admission_digest"], P)
        self.assertEqual(json.loads(result["ipc_raw"])["received_ns"], arguments["request_received_ns"])
        owner.close()

    def test_opening_result_is_detached_and_raw_handles_retained(self):
        owner = self.create()
        result = owner.opening_result
        rows = result["observed"]["handle_observations"]
        self.assertEqual({row["role"] for row in rows}, {"IPC_CANCEL", "SUPERVISOR_PIDFD", "PROVIDER_READY"})
        self.assertTrue(any(row["pidfd_info_raw"] for row in rows))
        rows.clear()
        self.assertTrue(owner.opening_result["observed"]["handle_observations"])
        owner.close()

    def test_supplied_source_path_never_opened(self):
        owner = self.create()
        self.assertNotIn(("open", "/usr/lib/aragorn/service.py"), self.native.calls)
        owner.close()

    def test_short_ready_write_is_permanent_and_retained(self):
        self.native.short_write = True
        error = self.failure(self.create)
        self.assertIs(error.observed["ready_write_attempted"], True)
        self.assertEqual(error.observed["ready_bytes_written"], len(error.observed["provider_ready_raw"]) - 1)
        self.assertEqual(sum(call[0] == "write" for call in self.native.calls), 1)
        self.assertIn(error.unresolved_owner, service._QUARANTINE)

    def test_interrupted_ready_write_preserves_same_original(self):
        original = KeyboardInterrupt("write")
        self.native.fail_write = original
        error = self.failure(self.create)
        self.assertIs(error.original_failure, original)
        self.assertIsNone(error.observed["ready_bytes_written"])

    def test_existing_endpoint_refuses_without_replacement(self):
        self.native.paths[service._ENDPOINT] = meta(4000, stat.S_IFSOCK | 0o660, gid=1002)
        self.failure(self.create)
        self.assertEqual(self.native.paths[service._ENDPOINT]["inode"], 4000)
        self.assertFalse(any(call[0] == "write" for call in self.native.calls))

    def test_bad_input_pin_closes_safe_transfers_without_session(self):
        self.failure(lambda: self.create(expected_provision_digest=P))
        self.assertFalse(self.native.session_calls)
        self.assertEqual(self.native.closes.count(15), 1)
        self.assertEqual(self.native.closes.count(16), 0)  # association still unknown

    def test_alias_transfer_is_refused_without_double_close(self):
        self.failure(lambda: self.create(provider_ready_write_fd=15))
        self.assertLessEqual(self.native.closes.count(15), 1)
        self.assertFalse(self.native.session_calls)

    def test_second_construction_never_takes_active_handles(self):
        owner = self.create()
        before = list(self.native.closes)
        with self.assertRaises(ValueError):
            self.create()
        self.assertEqual(self.native.closes, before)
        self.assertIn(17, self.native.fds)
        owner.close()

    def test_wrong_owner_call_does_not_close_existing_owner(self):
        owner = self.create()
        before = list(self.native.closes)
        self.native.pid += 1
        with self.assertRaises(ValueError):
            owner.close()
        self.assertEqual(self.native.closes, before)
        self.native.pid -= 1
        owner.close()

    def test_cancel_eof_prevents_request_and_keeps_error(self):
        owner = self.create()
        self.native.cancel = b""
        self.failure(owner.serve_one)
        self.assertFalse(self.native.context_calls)
        self.assertFalse(any(call[0] == "send" for call in self.native.calls))

    def test_cancel_data_refuses(self):
        owner = self.create()
        self.native.cancel = b"x"
        self.failure(owner.serve_one)
        self.assertFalse(self.native.context_calls)

    def test_context_failure_preserves_actual_exception_no_session_acquire(self):
        owner = self.create()
        original = ValueError("context acquisition")
        context_error = service.BrokerReaderContextError(original, [], {}, object())
        self.native.fail_context = context_error
        error = self.failure(owner.serve_one)
        self.assertIs(error.observed["context_error"], context_error)
        self.assertFalse(any(call[0] == "session_acquire" for call in self.native.calls))

    def test_context_return_then_cancellation_preserves_unaccepted_raw(self):
        owner = self.create()
        original_context = self.native.context
        def cancelled(*args, **kwargs):
            result = original_context(*args, **kwargs)
            self.native.cancel = b""
            return result
        with patch.object(service, "acquire_broker_reader_context", cancelled):
            error = self.failure(owner.serve_one)
        self.assertEqual(error.observed["context_result"]["context_raw"], self.native.context_raw)
        self.assertFalse(any(call[0] == "session_acquire" for call in self.native.calls))

    def test_session_failure_is_not_finished_or_reclosed(self):
        owner = self.create()
        original = ValueError("public session refusal")
        self.native.fail_session = original
        error = self.failure(owner.serve_one)
        self.assertIs(error.observed["session_error"], original)
        self.assertIsNone(error.observed["session_result"])
        self.assertFalse(any(call[0] in ("session_finish", "session_close", "send") for call in self.native.calls))

    def test_short_send_retains_actual_session_but_never_finishes(self):
        owner = self.create()
        self.native.short_send = True
        error = self.failure(owner.serve_one)
        self.assertIsNotNone(error.observed["session_result"])
        self.assertEqual(error.observed["bytes_sent"], len(error.observed["response_raw"]) - 1)
        self.assertFalse(any(call[0] == "session_finish" for call in self.native.calls))
        self.assertEqual(sum(call[0] == "send" for call in self.native.calls), 1)

    def test_send_interruption_has_unknown_count_and_no_retry(self):
        owner = self.create()
        original = SystemExit("send")
        self.native.fail_send = original
        error = self.failure(owner.serve_one)
        self.assertIs(error.original_failure, original)
        self.assertIs(error.observed["send_attempted"], True)
        self.assertIsNone(error.observed["bytes_sent"])
        self.assertEqual(sum(call[0] == "send" for call in self.native.calls), 1)

    def test_extra_packet_after_response_refuses_without_finish(self):
        owner = self.create()
        self.native.eof_extra = b"second phase"
        self.failure(owner.serve_one)
        self.assertFalse(any(call[0] == "session_finish" for call in self.native.calls))

    def test_unexpected_rights_handle_closed_once(self):
        owner = self.create()
        fd = self.native.allocate(meta(9999, stat.S_IFREG | 0o400), os.O_RDONLY, "/unexpected")
        self.native.extra_controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]).tobytes())]
        error = self.failure(owner.serve_one)
        self.assertEqual(self.native.closes.count(fd), 1)
        self.assertTrue(any(row["controls"] for row in error.observed["transport_observations"]))
        self.assertFalse(self.native.context_calls)

    def test_unexpected_rights_alias_never_closes_active_owner_twice(self):
        owner = self.create()
        self.native.extra_controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [17]).tobytes())]
        self.failure(owner.serve_one)
        self.assertEqual(self.native.closes.count(17), 1)  # terminal owning cleanup only
        self.assertFalse(self.native.context_calls)

    def test_receive_truncation_refuses_before_context(self):
        owner = self.create()
        self.native.request_flags = socket.MSG_TRUNC
        self.failure(owner.serve_one)
        self.assertFalse(self.native.context_calls)

    def test_kernel_nonblock_clear_prevents_cancel_read(self):
        owner = self.create()
        self.native.fds[15]["flags"] &= ~os.O_NONBLOCK
        reads = []
        self.native.read_hook = lambda fd: reads.append(fd)
        self.failure(owner.serve_one)
        self.assertNotIn(15, reads)
        self.assertNotIn(15, self.native.closes)

    def test_foreign_handle_is_quarantined_not_closed(self):
        owner = self.create()
        self.native.fds[17]["identity"] = meta(909090, stat.S_IFIFO | 0o600)
        error = self.failure(owner.close)
        self.assertNotIn(17, self.native.closes)
        self.assertIn(error.unresolved_owner, service._QUARANTINE)

    def test_pidfd_swap_during_association_read_is_never_closed(self):
        owner = self.create()
        def swap(fd):
            if fd == 16:
                self.native.fds[fd]["identity"] = meta(777777, stat.S_IFREG | 0o600)
        self.native.fdinfo_hook = swap
        self.failure(owner.close)
        self.assertNotIn(16, self.native.closes)

    def test_ordinary_clamped_buffer_accepts_small_actual_response(self):
        self.native.buffer = 262176
        owner = self.create()
        result = owner.serve_one()
        self.assertLess(2 * len(result["observed"]["response_raw"]) + 32, 262176)
        self.assertEqual(json.loads(result["ipc_raw"])["status"], "REFUSED")
        owner.close()

    def test_late_ready_completion_retains_written_frame_but_refuses(self):
        real_write = self.native.write
        def late(fd, raw):
            count = real_write(fd, raw)
            self.native.now = 4000000000
            return count
        with patch.object(service.os, "write", late):
            error = self.failure(self.create)
        self.assertIs(error.observed["ready_write_attempted"], True)
        self.assertEqual(error.observed["ready_bytes_written"], len(error.observed["provider_ready_raw"]))

    def test_primary_error_survives_cleanup_interruptions(self):
        owner = self.create()
        primary = OSError("send failure")
        self.native.fail_send = primary
        interrupt = KeyboardInterrupt("cleanup")
        def fail(fd):
            if fd == 17:
                raise interrupt
        self.native.close_hook = fail
        error = self.failure(owner.serve_one)
        self.assertIs(error.original_failure, primary)
        self.assertIn(interrupt, error.cleanup_failures)
        self.assertEqual(sum(call == ("close", 17) for call in self.native.calls), 1)

    def test_terminal_close_retains_confirmed_handle_closes(self):
        owner = self.create()
        result = owner.close()
        rows = result["observed"]["handle_observations"]
        self.assertEqual({row["role"] for row in rows if row["closed"]},
                         {"IPC_CANCEL", "SUPERVISOR_PIDFD", "PROVIDER_READY"})
        self.assertEqual(json.loads(result["ipc_raw"])["status"], "CLOSED")
        before = list(self.native.closes)
        with self.assertRaises(ValueError):
            owner.close()
        self.assertEqual(self.native.closes, before)

    def test_normal_low_number_reuse_keeps_per_generation_custody(self):
        self.native.reuse = True
        owner = self.create()
        result = owner.serve_one()
        self.assertEqual(json.loads(result["ipc_raw"])["status"], "REFUSED")
        closed = owner.close()
        self.assertTrue(any(self.native.closes.count(fd) > 1 for fd in self.native.closes if fd >= 100))
        # A temporary proc reader may reuse a closed service number during cleanup;
        # it must not be mislabeled as that old persistent pipe/PIDFD generation.
        rows = closed["observed"]["handle_observations"]
        for row in rows:
            if row["role"] in ("IPC_CANCEL", "PROVIDER_READY"):
                self.assertTrue(stat.S_ISFIFO(row["metadata"]["mode"]))

    def test_partial_process_read_is_retained_before_later_failure(self):
        owner = self.create()
        def fail_status(fd):
            if self.native.fds[fd]["path"] == f"/proc/{self.native.pid}/status":
                raise OSError("status read")
        self.native.read_hook = fail_status
        error = self.failure(owner.serve_one)
        self.assertTrue(any(row["proc_raw"]["provider_stat_before"] for row in error.observed["transport_observations"]
                            if row["edge"] == "ACCEPT"))

    def test_wrong_thread_call_leaves_owner_handles_untouched(self):
        owner = self.create()
        before = list(self.native.closes)
        with patch.object(service.threading, "get_native_id", return_value=threading.get_native_id() + 1):
            with self.assertRaises(ValueError):
                owner.serve_one()
        self.assertEqual(self.native.closes, before)
        owner.close()

    def test_service_cancel_cannot_alias_reader_channel(self):
        self.native.role_pipes[15] = meta(510, stat.S_IFIFO | 0o600)
        self.native.arguments = self.native.inputs()
        self.failure(self.create)
        self.assertFalse(self.native.session_calls)

    def test_proc_temporary_metadata_failure_keeps_unknown_fd_quarantined(self):
        original = OSError("temporary fstat")
        failed = []
        def fail(fd):
            if fd >= 100 and self.native.fds[fd]["kind"] == "file":
                failed.append(fd)
                raise original
        self.native.fstat_hook = fail
        error = self.failure(self.create)
        self.assertIs(error.original_failure, original)
        self.assertTrue(failed)
        self.assertTrue(all(fd not in self.native.closes for fd in failed))
        self.assertIn(error.unresolved_owner, service._QUARANTINE)

    def test_late_accept_clock_keeps_registered_unknown_socket_owner(self):
        owner = self.create()
        accepted = []
        actual_accept = FakeSocket.accept
        def late_accept(sock):
            result = actual_accept(sock)
            accepted.append(result[0])
            self.native.now = 5000000000
            return result
        with patch.object(FakeSocket, "accept", late_accept):
            error = self.failure(owner.serve_one)
        connection = accepted[0]
        row = error.unresolved_owner._owned[connection.fd]
        self.assertIs(row["object"], connection)
        self.assertIsNone(row["identity"])
        self.assertNotIn(connection.fd, self.native.closes)
        self.assertNotIn(("detach", connection.fd), self.native.calls)
        self.assertIn(error.unresolved_owner, service._QUARANTINE)
        self.assertFalse(self.native.context_calls)
        self.assertFalse(any(call[0] == "send" for call in self.native.calls))

    def test_unhashable_argument_still_registers_all_valid_transfers(self):
        seen = []
        self.native.fstat_hook = lambda fd: seen.append(fd)
        error = self.failure(lambda: self.create(ipc_cancel_read_fd=[]))
        valid = {10, 11, 12, 13, 14, 16, 17}
        self.assertTrue(valid.issubset(seen))
        for fd in (10, 12, 13, 14, 17):
            self.assertEqual(self.native.closes.count(fd), 1)
        for fd in (11, 16):
            self.assertEqual(error.unresolved_owner._owned[fd]["pid"], "UNKNOWN")
            self.assertNotIn(fd, self.native.closes)
        self.assertNotIn(15, self.native.closes)  # malformed argument never transferred it

    def test_confirmed_close_is_retired_before_snapshot_clock_failure(self):
        self.native.reuse = True
        owner = self.create()
        original = OSError("closed snapshot clock")
        failed = []
        original_clock = self.native.clock
        def clock(clock_id):
            if not failed and 15 in self.native.closes and 15 not in self.native.fds:
                failed.append(True)
                # Session-owned 10..14 have also closed. Select the just-retired
                # 15 for the subsequent supervisor fdinfo open, as a real kernel may.
                self.native.free_fds = [fd for fd in self.native.free_fds if fd >= 15]
                raise original
            return original_clock(clock_id)
        with patch.object(service.time, "clock_gettime_ns", clock):
            error = self.failure(owner.close)
        self.assertTrue(failed)
        self.assertIs(error.original_failure, original)
        self.assertEqual(self.native.closes.count(15), 2)  # pipe generation, then proc generation
        self.assertNotIn(15, error.unresolved_owner._owned)
        self.assertNotIn(15, self.native.fds)
        self.assertEqual(self.native.closes.count(16), 1)

    def test_post_response_rights_and_truncation_keep_actual_eof_controls(self):
        owner = self.create()
        fd = self.native.allocate(meta(90000, stat.S_IFREG | 0o400), os.O_RDONLY, "/eof-unexpected")
        raw = array.array("i", [fd]).tobytes()
        self.native.eof_controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, raw)]
        self.native.eof_flags = socket.MSG_CTRUNC
        error = self.failure(owner.serve_one)
        rows = [row for row in error.observed["transport_observations"] if row["edge"] == "EOF" and row["controls"]]
        self.assertTrue(rows)
        self.assertEqual(rows[-1]["controls"], [dict(level=socket.SOL_SOCKET, type=socket.SCM_RIGHTS, raw=raw)])
        self.assertEqual(rows[-1]["receive_flags"], socket.MSG_CTRUNC)
        self.assertEqual(self.native.closes.count(fd), 1)
        self.assertFalse(any(call[0] == "session_finish" for call in self.native.calls))

    def test_all_ancillary_numbers_registered_before_first_metadata_failure(self):
        owner = self.create()
        fds = [self.native.allocate(meta(91000 + n, stat.S_IFREG | 0o400), os.O_RDONLY, f"/unexpected-{n}") for n in range(3)]
        self.native.extra_controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds).tobytes())]
        first_failure = OSError("first ancillary metadata")
        observed = []
        def fstat(fd):
            if fd == fds[0]:
                observed.append(set(owner._owned))
                raise first_failure
        self.native.fstat_hook = fstat
        error = self.failure(owner.serve_one)
        self.assertTrue(observed)
        self.assertTrue(set(fds).issubset(observed[0]))
        self.assertIs(error.original_failure, first_failure)
        self.assertIn(fds[0], error.unresolved_owner._owned)
        self.assertNotIn(fds[0], self.native.closes)
        self.assertEqual([self.native.closes.count(fd) for fd in fds[1:]], [1, 1])

    def test_kernel_installed_low_descriptors_are_owned_and_closed_once(self):
        owner = self.create()
        for fd in (0, 1, 2):
            self.native.install(fd, meta(92000 + fd, stat.S_IFREG | 0o400), os.O_RDONLY, f"/low-{fd}")
        raw = array.array("i", [0, 1, 2]).tobytes()
        self.native.extra_controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, raw)]
        error = self.failure(owner.serve_one)
        self.assertEqual([self.native.closes.count(fd) for fd in (0, 1, 2)], [1, 1, 1])
        self.assertFalse(self.native.context_calls)
        self.assertTrue(any(row["controls"] for row in error.observed["transport_observations"]))

    def test_mixed_role_duplicate_keeps_pidfd_association_unknown(self):
        error = self.failure(lambda: self.create(reader_pidfd=10))
        self.assertEqual(error.unresolved_owner._owned[10]["pid"], "UNKNOWN")
        self.assertNotIn(10, self.native.closes)
        self.assertFalse(self.native.session_calls)
        self.assertEqual(self.native.closes.count(17), 1)

    def test_rights_pidfd_late_initial_failure_never_closes_same_inode_swap(self):
        owner = self.create()
        fd = self.native.allocate(meta(93000, stat.S_IFREG | 0o600), os.O_RDONLY,
                                  "anon_inode:[pidfd]", kind="pidfd", pid=self.native.broker["pid"])
        self.native.extra_controls = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]).tobytes())]
        seen_link, failed = [], []
        original = OSError("closing initial PIDFD fstat")
        readlink = self.native.readlink
        def observed_link(path):
            result = readlink(path)
            if path == f"/proc/self/fd/{fd}":
                seen_link.append(True)
            return result
        def late_swap(number):
            if number == fd and seen_link and not failed:
                failed.append(True)
                self.native.fds[fd]["pid"] = self.native.supervisor["pid"]
                raise original
        self.native.fstat_hook = late_swap
        with patch.object(service.os, "readlink", observed_link):
            error = self.failure(owner.serve_one)
        self.assertTrue(failed)
        self.assertIs(error.original_failure, original)
        self.assertEqual(error.unresolved_owner._owned[fd]["pid"], "UNKNOWN")
        self.assertNotIn(fd, self.native.closes)


if __name__ == "__main__":
    unittest.main()
