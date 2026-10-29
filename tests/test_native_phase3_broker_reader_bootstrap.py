"""Focused finite bootstrap checks. Every native boundary is fabricated."""

import array
import base64
from contextlib import ExitStack
from copy import deepcopy
import gc
import hashlib
import json
from pathlib import Path
import stat
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import weakref

from aragorn import native_phase3_broker_reader_bootstrap as bootstrap


PREFIX = "aragorn/native-phase3-broker-reader-bootstrap-"
ENDPOINT = "/run/aragorn-phase3-broker-reader/bootstrap.sock"
GUARD = "/run/aragorn-phase3-broker-reader/guard.sock"
BOOT = "11111111-2222-3333-4444-555555555555"
NONCE = "ab" * 32
ROOT = dict(pid=5000, start_time_ticks=10, uid=0, gid=0)
BROKER = dict(pid=6000, start_time_ticks=20, uid=501, gid=601)
PROVIDER = dict(pid=7000, start_time_ticks=30, uid=0, gid=0)
CLOCK = dict(boot_id=BOOT, clock_id="CLOCK_BOOTTIME", time_namespace=dict(device=2, inode=80))
MOUNT = dict(device=2, inode=81)
LIMITATIONS = ["NO_HEALTH_OR_EFFECT_AUTHORITY", "NO_LOSS_COMPLETENESS", "NO_LOADED_SOURCE_ATTESTATION",
              "ROOT_CALLER_OWNS_UNIT_SOURCE_AND_LAUNCH_ACQUISITION", "CLIENT_ROOT_PROC_OBSERVATIONS_UNAVAILABLE", "NO_PHASE3_QUALIFICATION"]


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def pin(char):
    return "sha256:" + char * 64


def meta(inode, mode, uid=0, gid=0, device=1):
    return dict(device=device, inode=inode, mode=mode, uid=uid, gid=gid)


def info(value):
    return SimpleNamespace(**{"st_" + ("dev" if k == "device" else "ino" if k == "inode" else k): v for k, v in value.items()})


def proc_stat(process):
    return (f"{process['pid']} (broker (reader)) " + " ".join(["S"] + ["0"] * 18 + [str(process["start_time_ticks"])]) + "\n").encode()


def proc_status(process):
    return ("Uid:\t" + " ".join([str(process["uid"])] * 4) + "\nGid:\t" + " ".join([str(process["gid"])] * 4) + "\n").encode()


def directories():
    paths = ("/", "/run", "/run/aragorn-phase3-broker-reader", "/var", "/var/lib", "/var/lib/aragorn-runtime-action", "/var/lib/aragorn-runtime-action/control")
    return [dict(path=p, **meta(200 + i, stat.S_IFDIR | (0o710 if i == 2 else 0o700 if i == 6 else 0o755), 501 if i == 6 else 0, 601 if i in (2, 6) else 0)) for i, p in enumerate(paths)]


def inputs():
    return encode({"grant": "protected"}), encode({"measurement": "protected"}), encode({"fixture": "protected"})


def hello(deadline=3000000000):
    grant, measurement, fixture = inputs()
    return dict(schema=PREFIX + "hello/v1", broker_nonce=NONCE, grant_digest=digest(grant), measurement_binding_digest=digest(measurement), fixture_binding_digest=digest(fixture), deadline_ns=deadline)


def inventory():
    return dict(schema="aragorn/native-phase3-broker-reader-installed-sources/v1", predecessor_report_digest="sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9",
                entries=[dict(path="/opt/aragorn/installed.py", role="SHARED", bytes=123, digest=pin("c"), **meta(300, stat.S_IFREG | 0o444))])


def provision(cancel_fd=60):
    h = hello()
    return dict(schema="aragorn/native-phase3-broker-reader-ipc-provision/v1", profile="HTTP_REFUSAL_ONLY", broker=deepcopy(BROKER), provider=deepcopy(PROVIDER), supervisor=deepcopy(ROOT), clock=deepcopy(CLOCK),
                epoch_digest=pin("a"), deployment_digest=pin("b"), grant_digest=h["grant_digest"], measurement_binding_digest=h["measurement_binding_digest"], fixture_binding_digest=h["fixture_binding_digest"],
                source_inventory_digest=digest(encode(inventory())), access_inventory_digest=pin("d"),
                reader_session=dict(epoch_digest=pin("a"), checkpoint_provision_digest=pin("e"), transport_provision_digest=pin("f"), stream_digest=pin("0"), loop_provision_digest=pin("1")),
                directories=directories(), cancellation_pipe=dict(**meta(90, stat.S_IFIFO | 0o600), writer=dict(process="SUPERVISOR", fd=72), readers=[dict(process="PROVIDER", fd=70), dict(process="BROKER", fd=cancel_fd)]),
                session_deadline_ns=10000000000, accept_deadline_ns=6000000000)


def expected_peer():
    h = hello()
    return dict(schema=PREFIX + "peer-expectation/v1", broker=deepcopy(BROKER), clock=deepcopy(CLOCK), mount_namespace=deepcopy(MOUNT), unit="aragorn-runtime-lineage-capability-action-broker.service", invocation_id="12" * 16,
                control_group="/system.slice/aragorn-runtime-lineage-capability-action-broker.service", command_digest=digest(b"/opt/aragorn/python\0broker.py\0a\0b\0c\0"), executable_digest=digest(b"executable"), source_inventory_digest=digest(encode(inventory())),
                grant_digest=h["grant_digest"], measurement_binding_digest=h["measurement_binding_digest"], fixture_binding_digest=h["fixture_binding_digest"], observed_before_ns=1, observed_after_ns=2)


def ready_expectation(p):
    return dict(schema=PREFIX + "readiness-expectation/v1", provider=deepcopy(PROVIDER), supervisor=deepcopy(ROOT), pipe=meta(91, stat.S_IFIFO | 0o600), provider_write_fd=71, supervisor_read_fd=42,
                provision_digest=digest(encode(p)), source_inventory_digest=p["source_inventory_digest"])


def ready_frame(p):
    return dict(schema="aragorn/native-phase3-broker-reader-provider-ready/v1", provider=deepcopy(PROVIDER), supervisor=deepcopy(ROOT), clock=deepcopy(CLOCK), provision_digest=digest(encode(p)), source_inventory_digest=p["source_inventory_digest"],
                **p["reader_session"], guard_socket=dict(path=GUARD, metadata=meta(301, stat.S_IFSOCK | 0o660, gid=601)), ready_ns=1)


class FakeSocket:
    def __init__(self, h, fd):
        self.h, self.fd, self.family = h, fd, 1
        self.options = {16: 1, 76: 0, 7: 524352, 8: 524352, 3: 5, 4: 0}
        self.bind = Mock(side_effect=self._bind)
        self.listen = Mock()
        self.connect = Mock()
        self.accept = Mock(side_effect=lambda: (h.connection, ""))
        self.sendmsg = Mock(side_effect=self._send)
        self.recvmsg = Mock(side_effect=self._receive)
        self.detach = Mock(side_effect=self._detach)
        self.close = Mock(side_effect=lambda: h.destructor_closes.append(self.fd))
        self.setblocking = Mock()
        self.set_inheritable = Mock()

    def fileno(self):
        return self.fd

    def get_inheritable(self):
        return False

    def setsockopt(self, level, key, value):
        self.options[key] = value * 2 if key in (7, 8) else value

    def getsockopt(self, level, key, *length):
        if key == 17:
            return self.h.credentials
        if key == 77:
            return 12
        return self.options[key]

    def _bind(self, path):
        self.h.endpoint_exists = True
        self.h.endpoint_meta = meta(302, stat.S_IFSOCK | 0o755)

    def _detach(self):
        value, self.fd = self.fd, -1
        return value

    def _send(self, buffers, controls, flags):
        raw = b"".join(buffers)
        self.h.sent.append((raw, controls, flags))
        if self.h.send_failure is not None:
            value = self.h.send_failure
            if isinstance(value, BaseException):
                raise value
            return value
        return len(raw)

    def _receive(self, size, control_size, flags):
        if self.h.receive_failure is not None:
            raise self.h.receive_failure
        index = self.h.received_count
        self.h.received_count += 1
        if self.h.role == "SERVER":
            if index == 0:
                raw = encode(self.h.hello_value)
            elif index == 1:
                raw = encode(dict(schema=PREFIX + "received/v1", hello_digest=digest(encode(self.h.hello_value)), handles_digest=digest(self.h.sent[0][0]), broker_nonce=NONCE, deadline_ns=self.h.hello_value["deadline_ns"], cancellation_fd=60, supervisor_pidfd=61))
            else:
                return b"", [], 0, ""
            controls = [(1, 2, self.h.credentials)]
        else:
            if index == 0:
                outgoing = json.loads(self.h.sent[0][0])
                raw = encode(dict(schema=PREFIX + "handles/v1", hello_digest=digest(self.h.sent[0][0]), broker_nonce=outgoing["broker_nonce"], deadline_ns=3000000000,
                                  supervisor=deepcopy(ROOT), clock=deepcopy(CLOCK), cancellation_pipe=meta(90, stat.S_IFIFO | 0o600), supervisor_pidfd=dict(metadata=meta(92, stat.S_IFREG | 0o700), pid=5000)))
                self.h.client_handles_raw = raw
                controls = [(1, 1, array.array("i", [60, 61]).tobytes()), (1, 2, self.h.credentials)]
            else:
                p = self.h.provision
                raw = encode(dict(schema=PREFIX + "release/v1", hello_digest=digest(self.h.sent[0][0]), handles_digest=digest(self.h.client_handles_raw), received_digest=digest(self.h.sent[1][0]), broker_nonce=NONCE, deadline_ns=3000000000,
                                  provider_ready_digest=digest(encode(ready_frame(p)) + b"\n"), provision=p, provision_digest=digest(encode(p)), source_inventory=inventory(), source_inventory_digest=digest(encode(inventory()))))
                controls = [(1, 2, self.h.credentials)]
        raw, controls, packet_flags = self.h.packet_mutation(index, raw, controls, 0)
        if self.h.role == "CLIENT" and index == 0:
            self.h.client_handles_raw = raw
        return raw, controls, packet_flags, ""


class FakePoll:
    def __init__(self, h):
        self.h, self.fds = h, {}

    def register(self, fd, flags):
        self.fds[fd] = flags

    def poll(self, timeout):
        self.h.poll_calls += 1
        if self.h.poll_mutation is not None:
            self.h.poll_mutation(self, timeout)
        result = []
        for fd in self.fds:
            if fd in self.h.exited:
                result.append((fd, 1))
            elif fd in (40, 60) and self.h.cancel_event:
                result.append((fd, 17))
            elif timeout and fd in (10, 11, 42):
                result.append((fd, 17 if fd == 11 and self.h.sent and json.loads(self.h.sent[-1][0])["schema"] == PREFIX + "release/v1" else 1 if self.fds[fd] & 1 else 4))
        if timeout and not result:
            self.h.now += 50000000
        return result


class Harness:
    def __init__(self, role="SERVER"):
        self.role = role
        self.process = deepcopy(ROOT if role == "SERVER" else BROKER)
        self.credentials = struct.pack("=iII", *(BROKER[k] if role == "SERVER" else ROOT[k] for k in ("pid", "uid", "gid")))
        self.now, self.next_fd, self.poll_calls = 100, 100, 0
        self.endpoint_exists = role == "CLIENT"
        self.endpoint_meta = meta(302, stat.S_IFSOCK | 0o660, gid=601)
        self.descriptors, self.offsets, self.closed, self.sent, self.destructor_closes = {}, {}, [], [], []
        self.received_count = 0
        self.send_failure = self.receive_failure = self.poll_mutation = None
        self.cancel_event, self.cancel_data = False, b""
        self.exited = set()
        self.packet_mutation = lambda i, raw, controls, flags: (raw, controls, flags)
        self.read_mutation = lambda path, raw: raw
        self.fstat_mutation = lambda fd, value: value
        self.link_mutation = lambda path, value: value
        self.flags_mutation = lambda fd, command, value: value
        self.provision = provision()
        self.hello_value = hello()
        self.ready_parts = [encode(ready_frame(self.provision)) + b"\n"]
        self.listener, self.connection = FakeSocket(self, 10), FakeSocket(self, 11 if role == "SERVER" else 10)
        for fd in (10, 11):
            self.install(fd, meta(400 + fd, stat.S_IFSOCK | 0o777, self.process["uid"], self.process["gid"]), 2050, f"socket:[{400 + fd}]")
        self.install(12, meta(93, stat.S_IFREG | 0o700), 2, "anon_inode:[pidfd]", BROKER["pid"] if role == "SERVER" else ROOT["pid"])
        for fd, inode in ((40, 90), (42, 91), (60, 90)):
            self.install(fd, meta(inode, stat.S_IFIFO | 0o600), 2048, f"pipe:[{inode}]")
        for fd, pid in ((41, 5000), (43, 7000), (61, 5000)):
            self.install(fd, meta(92 if pid == 5000 else 94, stat.S_IFREG | 0o700), 2, "anon_inode:[pidfd]", pid)

    def install(self, fd, metadata, flags, link, pid=None, path=None):
        self.descriptors[fd] = dict(metadata=metadata, flags=flags, fdflags=1, link=link, pid=pid, path=path)
        self.offsets[fd] = 0

    def open(self, path, flags, **kwargs):
        if kwargs.get("dir_fd") is not None:
            parent = self.descriptors[kwargs["dir_fd"]]["path"]
            path = parent.rstrip("/") + "/" + path
        if path == "/":
            normalized = path
        else:
            normalized = path.rstrip("/")
        value = self.named_meta(normalized)
        self.next_fd += 1
        fd = self.next_fd
        link = f"time:[80]" if path.endswith("/ns/time") else "mnt:[81]" if path.endswith("/ns/mnt") else normalized
        self.install(fd, value, flags & ~524288, link, path=normalized)
        return fd

    def named_meta(self, path):
        for row in directories():
            if path == row["path"]:
                return {k: v for k, v in row.items() if k != "path"}
        if path == ENDPOINT:
            if not self.endpoint_exists:
                raise FileNotFoundError()
            return self.endpoint_meta
        if path == GUARD:
            return meta(301, stat.S_IFSOCK | 0o660, gid=601)
        if path.endswith("/ns/time"):
            return meta(80, stat.S_IFREG | 0o444, device=2)
        if path.endswith("/ns/mnt"):
            return meta(81, stat.S_IFREG | 0o444, device=2)
        if re_match_fd(path):
            fd = int(path.rsplit("/", 1)[1])
            if "/7000/" in path and fd == 71:
                return meta(91, stat.S_IFIFO | 0o600)
            return self.descriptors[fd]["metadata"]
        return meta(500, stat.S_IFREG | 0o444)

    def stat(self, path, **kwargs):
        if kwargs.get("dir_fd") is not None:
            parent = self.descriptors[kwargs["dir_fd"]]["path"]
            path = parent.rstrip("/") + "/" + path
        return info(self.named_meta(path))

    def fstat(self, fd):
        if fd in self.closed:
            raise OSError(9, "closed")
        return info(self.fstat_mutation(fd, deepcopy(self.descriptors[fd]["metadata"])))

    def readlink(self, path):
        if "/fd/" in path:
            fd = int(path.rsplit("/", 1)[1])
            if "/7000/" in path and fd == 71:
                value = "pipe:[91]"
            else:
                value = self.descriptors[fd]["link"]
        else:
            value = "time:[80]" if path.endswith("/time") else "mnt:[81]"
        return self.link_mutation(path, value)

    def raw_file(self, path):
        if path.endswith("/fdinfo/71") and "/7000/" in path:
            return b"flags:\t02004001\n"
        if "/fdinfo/" in path:
            fd = int(path.rsplit("/", 1)[1])
            row = self.descriptors[fd]
            return (f"flags:\t{row['flags'] | 524288:o}\n" + (f"Pid:\t{row['pid']}\n" if row["pid"] else "")).encode()
        if path in ("/proc/sys/kernel/random/boot_id", "/run/aragorn-broker-boot-id"):
            return (BOOT + "\n").encode()
        pid = self.process["pid"] if "/self/" in path else int(path.split("/")[2])
        process = {5000: ROOT, 6000: BROKER, 7000: PROVIDER}[pid]
        if path.endswith("/stat"):
            return proc_stat(process)
        if path.endswith("/status"):
            return proc_status(process)
        if path.endswith("/cgroup"):
            return b"0::/system.slice/aragorn-runtime-lineage-capability-action-broker.service\n" if pid == 6000 else b"0::/supervisor\n"
        if path.endswith("/cmdline"):
            return b"/opt/aragorn/python\0broker.py\0a\0b\0c\0"
        if path.endswith("/exe"):
            return b"executable"
        raise AssertionError(path)

    def read(self, fd, count):
        if fd in (40, 60):
            if not self.cancel_event:
                raise BlockingIOError(11, "empty")
            return self.cancel_data
        if fd == 42:
            if not self.ready_parts:
                raise BlockingIOError(11, "writer alive")
            part = self.ready_parts.pop(0)
            if isinstance(part, BaseException):
                raise part
            result, leftover = part[:count], part[count:]
            if leftover:
                self.ready_parts.insert(0, leftover)
            return result
        path = self.descriptors[fd]["path"]
        raw = self.read_mutation(path, self.raw_file(path))
        start = self.offsets[fd]
        self.offsets[fd] += count
        return raw[start:start + count]

    def close(self, fd):
        if fd in self.closed:
            raise AssertionError("double close")
        self.closed.append(fd)

    def fcntl(self, fd, command):
        row = self.descriptors[fd]
        return self.flags_mutation(fd, command, row["flags"] if command == 3 else row["fdflags"])

    def chown(self, path, uid, gid, **kwargs):
        self.endpoint_meta = dict(self.endpoint_meta, uid=uid, gid=gid)

    def chmod(self, path, mode, **kwargs):
        self.endpoint_meta = dict(self.endpoint_meta, mode=stat.S_IFSOCK | mode)

    def __enter__(self):
        self.stack = ExitStack()
        os_fake = SimpleNamespace(O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_ACCMODE=3, O_NONBLOCK=2048, O_CLOEXEC=524288, O_NOFOLLOW=131072, O_DIRECTORY=65536, O_PATH=2097152,
                                  getpid=lambda: self.process["pid"], getresuid=lambda: (self.process["uid"],) * 3, getresgid=lambda: (self.process["gid"],) * 3,
                                  open=Mock(side_effect=self.open), read=Mock(side_effect=self.read), close=Mock(side_effect=self.close), stat=Mock(side_effect=self.stat), fstat=Mock(side_effect=self.fstat),
                                  readlink=Mock(side_effect=self.readlink), chown=Mock(side_effect=self.chown), chmod=Mock(side_effect=self.chmod), fpathconf=Mock(return_value=4096), urandom=Mock(return_value=bytes.fromhex(NONCE)))
        socket_fake = SimpleNamespace(AF_UNIX=1, SOCK_SEQPACKET=5, SOCK_NONBLOCK=2048, SOCK_CLOEXEC=524288, SOL_SOCKET=1, SCM_RIGHTS=1, SCM_CREDENTIALS=2, SO_TYPE=3, SO_ERROR=4, SO_SNDBUF=7, SO_RCVBUF=8, SO_PASSCRED=16, SO_PEERCRED=17,
                                      MSG_DONTWAIT=64, MSG_CMSG_CLOEXEC=1073741824, MSG_NOSIGNAL=16384, MSG_EOR=128, CMSG_SPACE=lambda n: (n + 7) // 8 * 8 + 16,
                                      socket=Mock(return_value=self.listener if self.role == "SERVER" else self.connection))
        replacements = dict(os=os_fake, socket=socket_fake, errno=SimpleNamespace(EAGAIN=11, EWOULDBLOCK=11, EINPROGRESS=115, EALREADY=114),
                            fcntl=SimpleNamespace(F_GETFL=3, F_GETFD=1, FD_CLOEXEC=1, fcntl=Mock(side_effect=self.fcntl)),
                            select=SimpleNamespace(POLLIN=1, POLLOUT=4, POLLERR=8, POLLHUP=16, POLLNVAL=32, poll=lambda: FakePoll(self)),
                            sys=SimpleNamespace(platform="linux", byteorder="little"), threading=SimpleNamespace(get_native_id=lambda: self.process["pid"]), time=SimpleNamespace(CLOCK_BOOTTIME=7, clock_gettime_ns=lambda _: self.now), _ATTEMPT=None, _UNRESOLVED_OWNER=None)
        for name, replacement in replacements.items():
            self.stack.enter_context(patch.object(bootstrap, name, replacement))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def server(self):
        return bootstrap.BrokerReaderBootstrapServer(broker_uid=501, broker_gid=601, startup_deadline_ns=3000000000, session_deadline_ns=10000000000)

    def offer(self, server, expected=None):
        raw = encode(expected_peer() if expected is None else expected)
        return server.offer_handles(broker_expectation_raw=raw, expected_broker_expectation_digest=digest(raw), ipc_cancel_read_fd=40, supervisor_pidfd=41)

    def release(self, server, expected=None):
        p, inv = encode(self.provision), encode(inventory())
        ready = encode(ready_expectation(self.provision) if expected is None else expected)
        return server.release(provision_raw=p, expected_provision_digest=digest(p), source_inventory_raw=inv, expected_source_inventory_digest=digest(inv), readiness_expectation_raw=ready, expected_readiness_expectation_digest=digest(ready), provider_ready_read_fd=42, provider_pidfd=43)

    def client(self):
        grant, measurement, fixture = inputs()
        return bootstrap.receive_broker_reader_bootstrap(capability_grant_raw=grant, expected_capability_grant_digest=digest(grant), measurement_binding_raw=measurement, expected_measurement_binding_digest=digest(measurement), fixture_binding_raw=fixture, expected_fixture_binding_digest=digest(fixture), startup_deadline_ns=3000000000)


def re_match_fd(path):
    return path.startswith("/proc/") and "/fd/" in path


class BootstrapTests(unittest.TestCase):
    def opened(self, h):
        server = h.server()
        server.accept_hello()
        h.offer(server)
        return server

    def artifacts(self, raw):
        value = json.loads(raw)
        self.assertEqual(value["limitations"], LIMITATIONS)
        self.assertLessEqual(len(raw), 3145728)
        self.assertLessEqual(len(value["handle_observations"]), 32)
        self.assertLessEqual(len(value["transport_observations"]), 16)
        for key, artifact in value["packet_artifacts"].items():
            if artifact is not None:
                original = base64.b64decode(artifact["base64"], validate=True)
                self.assertEqual(artifact["bytes"], len(original))
                self.assertEqual(artifact["digest"], digest(original))
                self.assertEqual(value["packet_digests"][key], artifact["digest"])
        return value

    def test_server_all_four_messages_actual_dynamic_receipt_and_ready(self):
        with Harness() as h:
            server = h.server()
            self.assertEqual(self.artifacts(server.opening_raw)["status"], "OPENED")
            accepted = server.accept_hello()
            self.assertEqual(json.loads(accepted["peer_raw"])["process"], BROKER)
            offered = h.offer(server)
            self.assertEqual(json.loads(offered["received_raw"])["cancellation_fd"], 60)
            self.assertIn(40, h.closed)
            self.assertIn(41, h.closed)
            released = h.release(server)
            result = self.artifacts(released["observation_raw"])
            self.assertEqual(result["status"], "RELEASED")
            self.assertEqual([json.loads(x[0])["schema"] for x in h.sent], [PREFIX + "handles/v1", PREFIX + "release/v1"])
            self.assertEqual(array.array("i", h.sent[0][1][0][2]).tolist(), [40, 41])
            self.assertEqual(h.sent[1][1], [])
            self.assertEqual(h.sent[0][2], 64 | 16384)
            remote = [row for row in result["handle_observations"] if row["process_role"] != "SELF"]
            self.assertTrue(any(row["fd"] == 61 and row["pidfd_info_raw"] for row in remote))
            self.assertTrue(all(row["closed"] is False for row in remote))
            self.assertNotIn(60, h.closed)
            self.assertNotIn(61, h.closed)
            self.assertNotIn(71, h.closed)
            self.assertTrue(any(s["stat_before_raw"] for s in result["transport_observations"] if s["process_role"] == "PEER"))
            server.close()
            self.assertTrue(h.endpoint_exists)
            self.assertEqual(h.destructor_closes, [])

    def test_client_actual_received_fds_one_configuration_transfer(self):
        with Harness("CLIENT") as h:
            transfer = h.client()
            result = transfer.take_configuration()
            self.assertEqual(set(result), set("provision_raw expected_provision_digest source_inventory_raw expected_source_inventory_digest measurement_binding_raw expected_measurement_binding_digest fixture_binding_raw expected_fixture_binding_digest ipc_cancel_read_fd supervisor_pidfd bootstrap_raw".split()))
            self.assertEqual((result["ipc_cancel_read_fd"], result["supervisor_pidfd"]), (60, 61))
            observed = self.artifacts(result["bootstrap_raw"])
            self.assertIsNone(observed["peer"])
            for snapshot in observed["transport_observations"]:
                if snapshot["process_role"] == "PEER":
                    self.assertIsNone(snapshot["stat_before_raw"])
                    self.assertIsNone(snapshot["namespaces"]["peer"])
                    self.assertIsNotNone(snapshot["peer_credentials_raw"])
            transfer.close()
            self.assertNotIn(60, h.closed)
            self.assertNotIn(61, h.closed)
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                transfer.take_configuration()
            self.assertNotIn(60, h.closed)
            self.assertEqual([json.loads(x[0])["schema"] for x in h.sent], [PREFIX + "hello/v1", PREFIX + "received/v1"])

    def test_client_close_without_take_releases_handles_once(self):
        with Harness("CLIENT") as h:
            transfer = h.client()
            transfer.close()
            self.assertEqual(h.closed.count(60), 1)
            self.assertEqual(h.closed.count(61), 1)

    def test_process_lifetime_attempt_and_rejected_state_preserve_owner(self):
        with Harness() as h:
            server = h.server()
            owned, closed = tuple(server.resources), list(h.closed)
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                server.offer_handles(broker_expectation_raw=b"{}", expected_broker_expectation_digest=digest(b"{}"), ipc_cancel_read_fd=40, supervisor_pidfd=41)
            self.assertEqual(tuple(server.resources), owned)
            self.assertEqual(h.closed, closed)
            self.assertEqual((server.state, server.phase, server.busy), ("OPEN", "OPEN", False))
            self.assertFalse({40, 41} & {r["fd"] for r in server.resources})
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                h.server()
            bootstrap.socket.socket.assert_called_once()

    def test_original_startup_cap_and_session_deadline(self):
        for deadline, session in ((4000000101, 10000000000), (100, 10000000000), (3000000000, 3000000000), (True, 10000000000)):
            with self.subTest(deadline=deadline, session=session), Harness():
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    bootstrap.BrokerReaderBootstrapServer(broker_uid=501, broker_gid=601, startup_deadline_ns=deadline, session_deadline_ns=session)
                bootstrap.socket.socket.assert_not_called()

    def test_platform_endian_main_thread_and_account_refusals(self):
        for case in ("platform", "endian", "thread", "account"):
            with self.subTest(case=case), Harness() as h:
                if case == "platform":
                    bootstrap.sys.platform = "darwin"
                elif case == "endian":
                    bootstrap.sys.byteorder = "big"
                elif case == "thread":
                    bootstrap.threading.get_native_id = lambda: 5001
                else:
                    bootstrap.os.getresuid = lambda: (0, 1, 0)
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.server()
                bootstrap.socket.socket.assert_not_called()

    def test_existing_endpoint_is_retained_and_never_modified(self):
        with Harness() as h:
            h.endpoint_exists = True
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                h.server()
            bootstrap.os.chown.assert_not_called()
            bootstrap.os.chmod.assert_not_called()
            bootstrap.socket.socket.assert_not_called()

    def test_native_buffer_getters_and_send_capacity_refuse(self):
        with Harness() as h:
            h.listener.setsockopt = Mock()
            h.listener.options[7] = 100
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                h.server()
            h.listener.bind.assert_not_called()
        with Harness() as h:
            server = self.opened(h)
            h.connection.options[7] = 262176
            # A later getter below the frozen capacity must stop RELEASE.
            self.assertGreaterEqual(h.connection.options[7], 262176)
            h.connection.options[7] = 262175
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                h.release(server)
            self.assertEqual(h.connection.sendmsg.call_count, 1)

    def test_kernel_socket_nonblocking_and_cloexec_override_cached_state(self):
        for command in (3, 1):
            with self.subTest(command=command), Harness() as h:
                h.flags_mutation = lambda fd, cmd, value: (value & ~(2048 if cmd == 3 else 1)) if fd == 10 and cmd == command else value
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.server()
                h.listener.bind.assert_not_called()

    def test_peer_kernel_credentials_must_match_protected_accounts(self):
        for creds in (b"short", struct.pack("=iII", 6000, 502, 601), struct.pack("=iII", 0, 501, 601)):
            with self.subTest(creds=creds), Harness() as h:
                server = h.server()
                h.credentials = creds
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    server.accept_hello()
                self.assertFalse(h.sent)
                self.assertTrue(any(s["peer_credentials_raw"] for s in caught.exception.observed["transport_observations"]))

    def test_peer_pidfd_association_missing_changed_and_exit(self):
        for case in ("missing", "changed", "exit"):
            with self.subTest(case=case), Harness() as h:
                server = h.server()
                if case == "missing":
                    h.read_mutation = lambda path, raw: b"flags: 02000002\n" if path.endswith("/fdinfo/12") else raw
                elif case == "changed":
                    h.descriptors[12]["pid"] = 6001
                else:
                    h.exited.add(12)
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    server.accept_hello()
                self.assertFalse(h.sent)

    def test_per_message_missing_duplicate_and_substituted_credentials(self):
        for controls in ([], [(1, 2, b"wrong")], [(1, 2, struct.pack("=iII", 6000, 501, 601))] * 2):
            with self.subTest(controls=controls), Harness() as h:
                server = h.server()
                h.packet_mutation = lambda i, raw, old, flags: (raw, controls, flags)
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    server.accept_hello()
                self.assertIsNotNone(caught.exception.observed["hello_raw"])
                self.assertFalse(h.sent)

    def test_canonical_duplicate_extra_nonfinite_and_oversize_packets(self):
        for raw in (b'{"schema":1,"schema":2}', encode(dict(hello(), extra=True)), b'{"a":NaN}', encode(hello()) + b"\n", b"x" * 4096, b"x" * 4097):
            with self.subTest(raw=raw[:30]), Harness() as h:
                server = h.server()
                h.packet_mutation = lambda i, old, controls, flags: (raw, controls, flags)
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    server.accept_hello()
                self.assertEqual(caught.exception.observed["hello_raw"], raw[:4096])

    def test_truncation_and_unknown_controls_refuse(self):
        for flags, extra in ((32, []), (8, []), (1, []), (0, [(99, 99, b"opaque")])):
            with self.subTest(flags=flags, extra=extra), Harness() as h:
                server = h.server()
                h.packet_mutation = lambda i, raw, controls, old: (raw, controls + extra, flags)
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    server.accept_hello()
                self.assertFalse(h.sent)

    def test_unexpected_ancillary_fds_are_owned_before_refusal_and_close_once(self):
        with Harness() as h:
            h.install(75, meta(95, stat.S_IFREG | 0o600), 0, "/unexpected")
            server = h.server()
            h.packet_mutation = lambda i, raw, controls, flags: (raw, controls + [(1, 1, array.array("i", [75]).tobytes())], flags)
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                server.accept_hello()
            self.assertEqual(h.closed.count(75), 1)
            self.assertTrue(any(row["fd"] == 75 and row["closed"] for row in caught.exception.observed["handle_observations"]))

    def test_malformed_rights_track_complete_installed_prefix_before_metadata(self):
        with Harness("CLIENT") as h:
            h.install(75, meta(95, stat.S_IFREG | 0o600), 0, "/unexpected")
            h.packet_mutation = lambda i, raw, controls, flags: (raw, [(1, 1, array.array("i", [60, 61, 75]).tobytes() + b"x"), (1, 2, h.credentials)], flags)
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                h.client()
            self.assertTrue({60, 61, 75}.issubset({row["fd"] for row in caught.exception.observed["handle_observations"]}))
            self.assertTrue({60, 61, 75}.issubset(set(h.closed)))

    def test_client_rights_inventory_order_alias_and_pidfd_controls(self):
        for fds, kind in (([60], 1), ([61, 60], 1), ([60, 60], 1), ([10, 61], 1), ([60, 61], 4)):
            with self.subTest(fds=fds, kind=kind), Harness("CLIENT") as h:
                h.packet_mutation = lambda i, raw, controls, flags: (raw, [(1, kind, array.array("i", fds).tobytes()), (1, 2, h.credentials)] if i == 0 else controls, flags)
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.client()
                self.assertEqual(len(h.closed), len(set(h.closed)))

    def test_protected_unit_source_and_credential_expectation_joins(self):
        for field, changed in (("unit", "other.service"), ("broker", dict(BROKER, pid=6001)), ("command_digest", pin("9")), ("executable_digest", pin("9")), ("control_group", "/other"), ("grant_digest", pin("9")), ("clock", dict(CLOCK, boot_id="22222222-2222-2222-2222-222222222222")), ("mount_namespace", dict(device=2, inode=82))):
            with self.subTest(field=field), Harness() as h:
                server = h.server()
                server.accept_hello()
                value = expected_peer()
                value[field] = changed
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.offer(server, value)
                h.connection.sendmsg.assert_not_called()

    def test_stale_nonce_chain_deadline_and_dynamic_receipt_substitutions(self):
        for field, changed in (("broker_nonce", "cd" * 32), ("hello_digest", pin("9")), ("handles_digest", pin("9")), ("deadline_ns", 3000000001), ("cancellation_fd", 61), ("supervisor_pidfd", 62)):
            with self.subTest(field=field), Harness() as h:
                server = h.server()
                server.accept_hello()
                def mutate(i, raw, controls, flags):
                    if i == 1:
                        value = json.loads(raw)
                        value[field] = changed
                        raw = encode(value)
                    return raw, controls, flags
                h.packet_mutation = mutate
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.offer(server)
                self.assertEqual(h.connection.sendmsg.call_count, 1)

    def test_send_short_eagain_interruption_and_memory_preserve_attempt(self):
        for failure in (1, BlockingIOError(11, "full"), KeyboardInterrupt(), SystemExit(7), MemoryError()):
            with self.subTest(kind=type(failure).__name__), Harness() as h:
                server = h.server()
                server.accept_hello()
                h.send_failure = failure
                expected_class = type(failure) if isinstance(failure, (KeyboardInterrupt, SystemExit, MemoryError)) else bootstrap.BrokerReaderBootstrapError
                with self.assertRaises(expected_class) as caught:
                    h.offer(server)
                self.assertTrue(caught.exception.observed["send_attempted"])
                self.assertIsNotNone(caught.exception.observed["handles_raw"])
                self.assertEqual(caught.exception.observed["bytes_sent"], 1 if failure == 1 else None)
                h.connection.sendmsg.assert_called_once()
                if expected_class is not bootstrap.BrokerReaderBootstrapError:
                    self.assertIs(caught.exception, failure)

    def test_provider_ready_partial_reads_and_spurious_eagain(self):
        with Harness() as h:
            server = self.opened(h)
            raw = encode(ready_frame(h.provision)) + b"\n"
            h.ready_parts = [BlockingIOError(11, "spurious"), raw[:31], raw[31:]]
            released = h.release(server)
            self.assertEqual(released["provider_ready_raw"], raw)
            self.assertEqual(self.artifacts(released["observation_raw"])["provider_ready_digest"], digest(raw))

    def test_ready_eof_extra_frame_missing_lf_and_oversize_preserve_prefix(self):
        for case in ("partial_eof", "inline_surplus", "later_surplus", "full_no_lf", "writer_eof"):
            with self.subTest(case=case), Harness() as h:
                server = self.opened(h)
                raw = encode(ready_frame(h.provision)) + b"\n"
                h.ready_parts = {"partial_eof": [b"partial", b""], "inline_surplus": [raw + b"extra"],
                                 "later_surplus": [raw, b"x"], "full_no_lf": [b"x" * 4096], "writer_eof": [raw, b""]}[case]
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    h.release(server)
                self.assertIsNotNone(caught.exception.observed["provider_ready_raw"])
                self.assertLessEqual(len(caught.exception.observed["provider_ready_raw"]), 4096)
                self.assertEqual(h.connection.sendmsg.call_count, 1)

    def test_ready_identity_clock_reader_pin_guard_and_timing_substitutions(self):
        for field, changed in (("provider", dict(PROVIDER, pid=7001)), ("supervisor", dict(ROOT, start_time_ticks=11)), ("clock", dict(CLOCK, time_namespace=dict(device=2, inode=82))), ("epoch_digest", pin("9")), ("stream_digest", pin("9")), ("ready_ns", 3000000001), ("guard_socket", dict(path=GUARD, metadata=meta(999, stat.S_IFSOCK | 0o660, gid=601)))):
            with self.subTest(field=field), Harness() as h:
                server = self.opened(h)
                frame = ready_frame(h.provision)
                frame[field] = changed
                h.ready_parts = [encode(frame) + b"\n"]
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.release(server)
                self.assertEqual(h.connection.sendmsg.call_count, 1)

    def test_readiness_expectation_endpoints_and_pipe_separation(self):
        for field, changed in (("supervisor_read_fd", 44), ("provider_write_fd", 72), ("pipe", meta(90, stat.S_IFIFO | 0o600)), ("provision_digest", pin("9"))):
            with self.subTest(field=field), Harness() as h:
                server = self.opened(h)
                expected = ready_expectation(h.provision)
                expected[field] = changed
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.release(server, expected)
                self.assertEqual(h.connection.sendmsg.call_count, 1)

    def test_provider_exit_and_deadline_win_queued_readiness(self):
        for case in ("provider_exit", "broker_exit", "deadline"):
            with self.subTest(case=case), Harness() as h:
                server = self.opened(h)
                if case == "deadline":
                    h.now = 3000000000
                else:
                    h.exited.add(43 if case == "provider_exit" else 12)
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.release(server)
                self.assertEqual(h.connection.sendmsg.call_count, 1)

    def test_cancellation_eof_data_priority_and_spurious_eagain(self):
        for data in (b"", b"x"):
            with self.subTest(data=data), Harness("CLIENT") as h:
                h.cancel_event, h.cancel_data = True, data
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.client()
                self.assertEqual(len(h.sent), 1)
        with Harness("CLIENT") as h:
            def spurious(fd, count):
                if fd == 60:
                    h.cancel_event = False
                    raise BlockingIOError(11, "spurious")
                return h.read(fd, count)
            h.cancel_event = True
            bootstrap.os.read.side_effect = spurious
            transfer = h.client()
            transfer.close()

    def test_queued_release_with_socket_hup_is_consumed_before_close(self):
        with Harness("CLIENT") as h:
            original = FakePoll.poll
            def poll(self, timeout):
                result = original(self, timeout)
                return [(fd, flags | 16 if fd == 10 else flags) for fd, flags in result]
            with patch.object(FakePoll, "poll", poll):
                transfer = h.client()
            self.assertEqual(h.received_count, 2)
            transfer.close()

    def test_final_provision_source_profile_credential_and_fd_joins(self):
        for field, changed in (("profile", "ALLOW"), ("broker", dict(BROKER, start_time_ticks=21)), ("source_inventory_digest", pin("9")), ("grant_digest", pin("9")), ("accept_deadline_ns", 50), ("session_deadline_ns", 3000000000)):
            with self.subTest(field=field), Harness("CLIENT") as h:
                h.provision[field] = changed
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.client()
                self.assertEqual(len(h.sent), 2)

    def test_remote_writer_flags_and_pidfd_readbacks_are_actual(self):
        with Harness() as h:
            server = self.opened(h)
            h.read_mutation = lambda path, raw: b"flags:\t02000001\n" if path.endswith("/7000/fdinfo/71") else raw
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                h.release(server)
            self.assertEqual(h.connection.sendmsg.call_count, 1)

    def test_late_cancel_flag_and_identity_changes_prevent_read_and_close(self):
        for case in ("flags", "inode"):
            with self.subTest(case=case), Harness("CLIENT") as h:
                link_reads = []
                def link(path, value):
                    if path == "/proc/self/fd/60":
                        link_reads.append(path)
                    if path == "/proc/self/fd/60" and len(link_reads) == 2:
                        # The first read establishes the original pin; change it
                        # only inside the following held-resource guard.
                        if case == "flags":
                            h.descriptors[60]["flags"] = 2049
                        else:
                            h.descriptors[60]["metadata"] = meta(99, stat.S_IFIFO | 0o600)
                    return value
                h.link_mutation = link
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    h.client()
                self.assertGreaterEqual(len(link_reads), 2)
                self.assertIn("late descriptor flags" if case == "flags" else "descriptor identity changed", str(caught.exception.original_failure))
                self.assertNotIn(60, h.closed)
                self.assertFalse(any(call.args[0] == 60 for call in bootstrap.os.read.call_args_list))

    def test_original_owner_change_prevents_foreign_close_and_retains_objects(self):
        with Harness() as h:
            server = self.opened(h)
            h.process["pid"] = 5001
            before = list(h.closed)
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                server.close()
            self.assertEqual(h.closed, before)
            self.assertIs(caught.exception.unresolved_owner, server)
            self.assertTrue(caught.exception.cleanup_failures)
            h.connection.detach.assert_not_called()

    def test_failed_detach_strong_quarantine_and_attempt_poison(self):
        with Harness() as h:
            server = h.server()
            def fresh_error():
                raise OSError("detach uncertain")
            h.listener.detach.side_effect = fresh_error
            reference = weakref.ref(server)
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                server.close()
            self.assertIs(caught.exception.unresolved_owner, server)
            bootstrap._ATTEMPT = True  # Keep the consumed latch without retaining its owner.
            del caught, server
            gc.collect()
            self.assertIsNotNone(reference())
            self.assertIs(bootstrap._UNRESOLVED_OWNER, reference())
            h.listener.close.assert_not_called()
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                h.server()
            bootstrap.socket.socket.assert_called_once()

    def test_take_rechecks_cancellation_pidfd_and_process_before_removing_ownership(self):
        for case in ("cancel", "exit", "owner"):
            with self.subTest(case=case), Harness("CLIENT") as h:
                transfer = h.client()
                if case == "cancel":
                    h.cancel_event = True
                elif case == "exit":
                    h.exited.add(61)
                else:
                    h.process["uid"] = 502
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    transfer.take_configuration()
                self.assertNotEqual(transfer.state, "TAKEN")

    def test_no_project_helper_import_or_historical_fixture_dependency(self):
        # A sole source read, inventoried explicitly in the selected closure.
        import ast
        tree = ast.parse(Path(bootstrap.__file__).read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and (node.level or (node.module or "").startswith("aragorn")) for node in ast.walk(tree)))
        self.assertFalse(any(isinstance(node, ast.Import) and any(alias.name.startswith("aragorn") for alias in node.names) for node in ast.walk(tree)))

    def test_connect_in_progress_is_same_single_attempt_and_so_error_checked(self):
        for error in (0, 111):
            with self.subTest(error=error), Harness("CLIENT") as h:
                h.connection.connect.side_effect = BlockingIOError(bootstrap.errno.EINPROGRESS, "progress")
                h.connection.options[4] = error
                if error:
                    with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                        h.client()
                    self.assertFalse(h.sent)
                else:
                    h.client().close()
                h.connection.connect.assert_called_once_with(ENDPOINT)
                bootstrap.socket.socket.assert_called_once()

    def test_native_peer_pidfd_failure_has_no_numeric_pid_fallback(self):
        with Harness() as h:
            server = h.server()
            original = h.connection.getsockopt
            def get(level, option, *args):
                if option == 77:
                    raise OSError(92, "unsupported")
                return original(level, option, *args)
            h.connection.getsockopt = get
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                server.accept_hello()
            self.assertIsInstance(caught.exception.original_failure, OSError)
            self.assertFalse(h.sent)
            self.assertFalse(any("/proc/6000/" in str(call) for call in bootstrap.os.open.call_args_list))

    def test_successful_raw_observations_are_actual_not_hash_only(self):
        with Harness() as h:
            server = self.opened(h)
            observed = self.artifacts(h.release(server)["observation_raw"])
            peer = [s for s in observed["transport_observations"] if s["process_role"] == "PEER" and s["stat_before_raw"]]
            self.assertTrue(peer)
            for s in peer:
                self.assertEqual(base64.b64decode(s["stat_before_raw"]["base64"]), proc_stat(BROKER))
                self.assertEqual(base64.b64decode(s["status_raw"]["base64"]), proc_status(BROKER))
                self.assertEqual(base64.b64decode(s["cmdline_raw"]["base64"]), b"/opt/aragorn/python\0broker.py\0a\0b\0c\0")
            self.assertTrue(any(r["role"] == "TRANSIENT" and r["link"] == GUARD and r["closed"] for r in observed["handle_observations"]))
            server.close()

    def test_installed_low_descriptor_is_retained_and_closed_on_inventory_refusal(self):
        with Harness("CLIENT") as h:
            h.install(0, meta(96, stat.S_IFIFO | 0o600), 2048, "pipe:[96]")
            h.packet_mutation = lambda i, raw, controls, flags: (raw, [(1, 1, array.array("i", [0, 61]).tobytes()), (1, 2, h.credentials)] if i == 0 else controls, flags)
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                h.client()
            self.assertEqual(h.closed.count(0), 1)
            self.assertTrue(any(r["fd"] == 0 for r in caught.exception.observed["handle_observations"]))

    def test_late_deadline_guard_prevents_send_and_retains_original_budget(self):
        with Harness() as h:
            server = h.server()
            server.accept_hello()
            original = h.connection.getsockopt
            def late(level, option, *args):
                result = original(level, option, *args)
                if option == 7:
                    h.now = 3000000000
                return result
            h.connection.getsockopt = late
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                h.offer(server)
            self.assertFalse(caught.exception.observed["send_attempted"])
            h.connection.sendmsg.assert_not_called()
            self.assertEqual(server.deadline, 3000000000)

    def test_late_pidfd_association_change_prevents_numeric_close(self):
        with Harness() as h:
            server = self.opened(h)
            def link(path, value):
                if path == "/proc/self/fd/12":
                    h.descriptors[12]["pid"] = 6001
                return value
            h.link_mutation = link
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                server.close()
            self.assertNotIn(12, h.closed)
            self.assertTrue(any(row["fd"] == 12 and not row["closed"] for row in server.handles))

    def test_cleanup_interruption_preserves_original_instance_and_other_close_attempts(self):
        with Harness() as h:
            server = h.server()
            original = KeyboardInterrupt()
            base_close = bootstrap.os.close.side_effect
            fired = []
            def close(fd):
                if not fired:
                    fired.append(fd)
                    raise original
                return base_close(fd)
            bootstrap.os.close.side_effect = close
            with self.assertRaises(KeyboardInterrupt) as caught:
                server.close()
            self.assertIs(caught.exception, original)
            self.assertIn(original, caught.exception.cleanup_failures)
            self.assertGreater(len(h.closed), 1)

    def test_readback_failure_keeps_actual_prefix_and_never_claims_source_digest(self):
        with Harness() as h:
            server = h.server()
            h.read_mutation = lambda path, raw: b"malformed actual status\n" if path == "/proc/6000/status" else raw
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                server.accept_hello()
            snapshots = caught.exception.observed["transport_observations"]
            self.assertTrue(any(s["status_raw"] == b"malformed actual status\n" for s in snapshots))
            self.assertTrue(all(s["executable_digest"] is None for s in snapshots))
            self.assertFalse(h.sent)

    def test_wrong_eof_payload_and_zero_packet_with_credentials_refuse(self):
        for packet in (b"extra", b""):
            with self.subTest(packet=packet), Harness() as h:
                server = self.opened(h)
                original = h.connection.recvmsg.side_effect
                def recv(*args):
                    if h.received_count >= 2:
                        return packet, [(1, 2, h.credentials)], 0, ""
                    return original(*args)
                h.connection.recvmsg.side_effect = recv
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.release(server)
                self.assertEqual(h.connection.sendmsg.call_count, 2)

    def test_namespace_boot_and_saved_account_readback_changes_refuse(self):
        for leaf in ("boot", "status", "stat"):
            with self.subTest(leaf=leaf), Harness("CLIENT") as h:
                def mutate(path, raw):
                    if leaf == "boot" and path == "/run/aragorn-broker-boot-id":
                        return b"not-uuid\n"
                    if leaf == "status" and path == "/proc/self/status":
                        return b"Uid: 501 501 0 501\nGid: 601 601 601 601\n"
                    if leaf == "stat" and path == "/proc/self/stat":
                        return proc_stat(dict(BROKER, pid=6001))
                    return raw
                h.read_mutation = mutate
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.client()
                bootstrap.socket.socket.assert_not_called()

    def test_wire_deadline_is_original_minimum_without_renewal(self):
        with Harness() as h:
            h.hello_value = hello(2500000000)
            server = self.opened(h)
            self.assertEqual(server.deadline, 2500000000)
            released = h.release(server)
            for key in ("handles_raw", "received_raw", "release_raw"):
                self.assertEqual(json.loads(released[key])["deadline_ns"], 2500000000)
            server.close()

    def test_late_named_namespace_change_prevents_release(self):
        with Harness() as h:
            server = self.opened(h)
            original = h.named_meta
            def changed(path):
                value = original(path)
                return dict(value, inode=82) if path.endswith("/ns/time") else value
            h.named_meta = changed
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                h.release(server)
            self.assertEqual(h.connection.sendmsg.call_count, 1)

    def test_protected_boot_file_cannot_be_broker_owned_or_group_writable(self):
        for changed in (meta(500, stat.S_IFREG | 0o444, uid=501), meta(500, stat.S_IFREG | 0o664)):
            with self.subTest(metadata=changed), Harness("CLIENT") as h:
                original = h.named_meta
                h.named_meta = lambda path: changed if path == "/run/aragorn-broker-boot-id" else original(path)
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                    h.client()
                bootstrap.socket.socket.assert_not_called()

    def test_late_owner_change_during_close_readlink_skips_detach_and_close(self):
        with Harness() as h:
            server = h.server()
            def link(path, value):
                if path == "/proc/self/fd/10":
                    h.process["pid"] = 5001
                return value
            h.link_mutation = link
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                server.close()
            self.assertNotIn(10, h.closed)
            h.listener.detach.assert_not_called()

    def test_timing_boundary_descriptor_substitution_prevents_actual_file_read(self):
        with Harness() as h:
            armed = []
            def link(path, value):
                if value == "/proc/self/stat":
                    armed[:] = [int(path.rsplit("/", 1)[1])]
                return value
            def now(_):
                if armed:
                    fd = armed[0]
                    h.descriptors[fd]["metadata"] = dict(h.descriptors[fd]["metadata"], inode=999)
                return h.now
            h.link_mutation = link
            bootstrap.time.clock_gettime_ns = now
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                h.server()
            self.assertTrue(armed)
            self.assertFalse(any(call.args[0] == armed[0] for call in bootstrap.os.read.call_args_list))
            self.assertNotIn(armed[0], h.closed)

    def test_failed_socket_profile_getters_remain_actual_failure_observations(self):
        with Harness() as h:
            h.listener.setsockopt = Mock()
            h.listener.options[7] = 100
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                h.server()
            snapshots = caught.exception.observed["transport_observations"]
            self.assertTrue(any(s["socket_options"] and s["socket_options"]["sndbuf"] == 100 for s in snapshots))
            h.listener.bind.assert_not_called()

    def test_unknown_oversized_and_boolean_send_returns_are_not_success(self):
        for value in (None, True, 5000):
            with self.subTest(value=value), Harness() as h:
                server = h.server()
                server.accept_hello()
                h.connection.sendmsg.side_effect = lambda *args: value
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    h.offer(server)
                self.assertTrue(caught.exception.observed["send_attempted"])
                self.assertIs(caught.exception.observed["bytes_sent"], value)
                h.connection.sendmsg.assert_called_once()

    def test_detach_wrong_return_retains_unknown_number_without_foreign_close(self):
        with Harness() as h:
            server = h.server()
            h.listener.detach.side_effect = lambda: 77
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                server.close()
            self.assertNotIn(77, h.closed)
            self.assertNotIn(10, h.closed)
            self.assertTrue(any(row["fd"] == 77 and row["metadata"] is None for row in caught.exception.observed["handle_observations"]))
            self.assertIs(caught.exception.unresolved_owner, server)

    def test_client_original_deadline_remains_below_received_session_deadline(self):
        with Harness("CLIENT") as h:
            h.provision["session_deadline_ns"] = 2700000000
            h.provision["accept_deadline_ns"] = 2600000000
            def mutate(i, raw, controls, flags):
                value = json.loads(raw)
                value["deadline_ns"] = 2500000000
                return encode(value), controls, flags
            h.packet_mutation = mutate
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                h.client()
            self.assertEqual(len(h.sent), 2)

    def test_cancel_fd_and_supervisor_pidfd_cannot_alias_same_argument(self):
        with Harness() as h:
            server = h.server()
            server.accept_hello()
            expected = encode(expected_peer())
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                server.offer_handles(broker_expectation_raw=expected, expected_broker_expectation_digest=digest(expected), ipc_cancel_read_fd=40, supervisor_pidfd=40)
            h.connection.sendmsg.assert_not_called()
            self.assertLessEqual(h.closed.count(40), 1)

    def test_unobserved_readiness_is_null_but_actual_empty_eof_is_retained(self):
        with Harness() as h:
            server = self.opened(h)
            h.exited.add(43)
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                h.release(server)
            self.assertIsNone(caught.exception.observed["provider_ready_raw"])
        with Harness() as h:
            server = self.opened(h)
            h.ready_parts = [b""]
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                h.release(server)
            self.assertEqual(caught.exception.observed["provider_ready_raw"], b"")
        with Harness() as h:
            base_open = bootstrap.os.open.side_effect
            def unavailable(path, flags, **kwargs):
                if path == "/proc/self/stat":
                    raise OSError(5, "unavailable")
                return base_open(path, flags, **kwargs)
            bootstrap.os.open.side_effect = unavailable
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                h.server()
            self.assertIsNone(caught.exception.observed["transport_observations"][0]["stat_before_raw"])

    def test_ingress_first_invalid_argument_still_retains_later_valid_transfer(self):
        for operation in ("offer", "release"):
            with self.subTest(operation=operation), Harness() as h:
                server = h.server()
                server.accept_hello()
                if operation == "offer":
                    expected = encode(expected_peer())
                    call = lambda: server.offer_handles(broker_expectation_raw=expected, expected_broker_expectation_digest=digest(expected), ipc_cancel_read_fd=True, supervisor_pidfd=41)
                    fd, role = 41, "SUPERVISOR_TRANSFER"
                else:
                    h.offer(server)
                    p, inv, ready = encode(h.provision), encode(inventory()), encode(ready_expectation(h.provision))
                    call = lambda: server.release(provision_raw=p, expected_provision_digest=digest(p), source_inventory_raw=inv, expected_source_inventory_digest=digest(inv), readiness_expectation_raw=ready, expected_readiness_expectation_digest=digest(ready), provider_ready_read_fd=True, provider_pidfd=43)
                    fd, role = 43, "PROVIDER_PIDFD"
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    call()
                rows = caught.exception.observed["handle_observations"]
                self.assertTrue(any(row["fd"] == fd and row["role"] == role and row["metadata"] is None for row in rows))
                self.assertIs(caught.exception.unresolved_owner, server)
                self.assertNotIn(fd, h.closed)
                self.assertNotIn(True, h.closed)

    def test_accepted_entry_owner_failure_retains_both_transferred_arguments(self):
        for operation in ("offer", "release"):
            with self.subTest(operation=operation), Harness() as h:
                server = h.server()
                server.accept_hello()
                if operation == "release":
                    h.offer(server)
                original = OSError(5, "owner readback unavailable")
                enter = server.enter
                def accepted(*args):
                    enter(*args)
                    bootstrap.os.getresuid = Mock(side_effect=original)
                with patch.object(server, "enter", side_effect=accepted):
                    with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                        h.offer(server) if operation == "offer" else h.release(server)
                expected = {40, 41} if operation == "offer" else {42, 43}
                observed = {row["fd"] for row in caught.exception.observed["handle_observations"]}
                self.assertTrue(expected.issubset(observed))
                self.assertIs(caught.exception.original_failure, original)
                self.assertFalse(expected & set(h.closed))

    def test_received_ancillary_owner_failure_tracks_all_installed_numbers(self):
        with Harness("CLIENT") as h:
            original = h.connection.recvmsg.side_effect
            failure = OSError(5, "owner unavailable after recvmsg")
            def received(*args):
                result = original(*args)
                bootstrap.os.getresuid = Mock(side_effect=failure)
                return result
            h.connection.recvmsg.side_effect = received
            with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                h.client()
            self.assertTrue({60, 61}.issubset({row["fd"] for row in caught.exception.observed["handle_observations"]}))
            self.assertIs(caught.exception.original_failure, failure)
            self.assertNotIn(60, h.closed)
            self.assertNotIn(61, h.closed)

    def test_take_serialization_exhausting_original_deadline_cannot_transfer(self):
        with Harness("CLIENT") as h:
            transfer = h.client()
            original = bootstrap._json
            def serialize(value):
                raw = original(value)
                if type(value) is dict and value.get("schema") == PREFIX + "observation/v1" and value.get("phase") == "RELEASE":
                    h.now = 3000000000
                return raw
            with patch.object(bootstrap, "_json", side_effect=serialize):
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    transfer.take_configuration()
            self.assertNotEqual(transfer.state, "TAKEN")
            self.assertIn("startup deadline", str(caught.exception.original_failure))
            self.assertEqual(h.closed.count(60), 1)
            self.assertEqual(h.closed.count(61), 1)

    def test_rejected_owner_state_and_reentry_leave_caller_handles_untouched(self):
        for operation in ("offer", "release"):
            for rejection in ("owner", "state", "busy"):
                with self.subTest(operation=operation, rejection=rejection), Harness() as h:
                    server = h.server()
                    server.accept_hello()
                    if operation == "release":
                        h.offer(server)
                    if rejection == "owner":
                        h.process["uid"] = 1
                    elif rejection == "state":
                        server.state = "OPEN"
                    else:
                        server.busy = True
                    before = (server.state, server.phase, server.busy, deepcopy(server.handles), tuple(server.resources), list(h.closed))
                    with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                        h.offer(server) if operation == "offer" else h.release(server)
                    after = (server.state, server.phase, server.busy, server.handles, tuple(server.resources), h.closed)
                    self.assertEqual(after, before)
                    fds = {40, 41} if operation == "offer" else {42, 43}
                    self.assertFalse(fds & {r["fd"] for r in server.resources})
                    self.assertFalse(fds & set(h.closed))

    def test_unhashable_first_argument_still_retains_valid_second_transfer(self):
        for malformed in ([], {}):
            with self.subTest(malformed=malformed), Harness() as h:
                server = h.server()
                server.accept_hello()
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    server.offer_handles(broker_expectation_raw=b"invalid", expected_broker_expectation_digest=None, ipc_cancel_read_fd=malformed, supervisor_pidfd=41)
                self.assertEqual(str(caught.exception.original_failure), "unsigned integer")
                self.assertTrue(any(r["fd"] == 41 and r["pid"] is bootstrap._PIDFD_UNKNOWN for r in server.resources))
                self.assertNotIn(41, h.closed)

    def test_accepted_entry_metadata_failure_retains_later_valid_transfer(self):
        for operation in ("offer", "release"):
            with self.subTest(operation=operation), Harness() as h:
                server = h.server()
                server.accept_hello()
                if operation == "release":
                    h.offer(server)
                first, second = (40, 41) if operation == "offer" else (42, 43)
                original = OSError(5, "first transferred metadata unavailable")
                def unavailable(fd, value):
                    if fd == first:
                        raise original
                    return value
                h.fstat_mutation = unavailable
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    h.offer(server) if operation == "offer" else h.release(server)
                self.assertIs(caught.exception.original_failure, original)
                self.assertTrue({first, second}.issubset({r["fd"] for r in server.resources}))
                self.assertIs(next(r for r in server.resources if r["fd"] == second)["pid"], bootstrap._PIDFD_UNKNOWN)
                self.assertFalse({first, second} & set(h.closed))

    def test_success_observation_deadline_seams_refuse_open_hello_offer_release(self):
        for operation, phase in (("open", "OPEN"), ("hello", "HELLO"), ("offer", "HANDLES"), ("release", "RELEASE")):
            with self.subTest(operation=operation), Harness() as h:
                server = None if operation == "open" else h.server()
                if operation in ("offer", "release"):
                    server.accept_hello()
                if operation == "release":
                    h.offer(server)
                serialize = bootstrap._json
                armed = []
                def late(value):
                    raw = serialize(value)
                    if type(value) is dict and value.get("schema") == PREFIX + "observation/v1" and value["phase"] == phase and value["status"] != "REFUSED":
                        armed.append(True)
                        h.now = 3000000000
                    return raw
                with patch.object(bootstrap, "_json", side_effect=late):
                    with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                        if operation == "open":
                            h.server()
                        elif operation == "hello":
                            server.accept_hello()
                        elif operation == "offer":
                            h.offer(server)
                        else:
                            h.release(server)
                self.assertEqual(armed, [True])
                self.assertIn("startup deadline", str(caught.exception.original_failure))
                self.assertEqual(len(h.closed), len(set(h.closed)))

    def test_late_closing_deadline_refuses_offer_release_and_client_receipt(self):
        for operation, target in (("offer", 41), ("release", 43), ("client", 12)):
            with self.subTest(operation=operation), Harness("CLIENT" if operation == "client" else "SERVER") as h:
                server = None
                if operation != "client":
                    server = h.server()
                    server.accept_hello()
                    if operation == "release":
                        h.offer(server)
                original = bootstrap._Owner.close_resource
                armed = []
                def close(owner, resource):
                    if resource["fd"] == target and not armed:
                        # The normal late close performs all actual association
                        # guards with cleanup deadlines disabled, then expires.
                        original(owner, resource)
                        armed.append(True)
                        h.now = 3000000000
                    else:
                        original(owner, resource)
                with patch.object(bootstrap._Owner, "close_resource", close):
                    with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                        if operation == "client":
                            h.client()
                        elif operation == "offer":
                            h.offer(server)
                        else:
                            h.release(server)
                self.assertEqual(armed, [True])
                self.assertIn("startup deadline", str(caught.exception.original_failure))
                self.assertEqual(h.closed.count(target), 1)

    def test_post_observation_substitution_cannot_transfer_configuration(self):
        for field, value in (("flags", 0), ("metadata", meta(999, stat.S_IFIFO | 0o600)), ("pid", 5001)):
            with self.subTest(field=field), Harness("CLIENT") as h:
                transfer = h.client()
                serialize = bootstrap._json
                fd = 61 if field == "pid" else 60
                def substitute(observation):
                    raw = serialize(observation)
                    if type(observation) is dict and observation.get("schema") == PREFIX + "observation/v1" and observation.get("status") == "RELEASED":
                        h.descriptors[fd][field] = value
                    return raw
                with patch.object(bootstrap, "_json", side_effect=substitute):
                    with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                        transfer.take_configuration()
                self.assertNotEqual(transfer.state, "TAKEN")
                self.assertNotIn(fd, h.closed)

    def test_final_clock_boundary_substitution_cannot_escape_success(self):
        for operation in ("open", "hello", "offer", "release", "client", "take"):
            with self.subTest(operation=operation), Harness("CLIENT" if operation in ("client", "take") else "SERVER") as h:
                owner = None
                if operation == "take":
                    owner = h.client()
                elif operation not in ("open", "client"):
                    owner = h.server()
                    if operation in ("offer", "release"):
                        owner.accept_hello()
                    if operation == "release":
                        h.offer(owner)
                original = bootstrap._Owner.tick
                armed = []
                def boundary(current, deadline=True):
                    now = original(current, deadline)
                    if deadline and not current.cleaning and armed == ["pending"]:
                        # Arm only after complete final slow guards, never during
                        # earlier setup. The last finite check must see this.
                        fd = current.cancel["fd"] if operation == "take" else current.directories[0]["resource"]["fd"]
                        h.descriptors[fd]["metadata"] = dict(h.descriptors[fd]["metadata"], inode=999)
                        armed.append(fd)
                    return now
                if operation == "take":
                    slow = owner.resource_guard
                    live = owner.live
                    supervisor_checked = []
                    def checked_live(resource):
                        live(resource)
                        if resource is owner.supervisor_fd and owner._final_test_observation:
                            supervisor_checked[:] = [True]
                    def guard(resource):
                        slow(resource)
                        if resource is owner.cancel and supervisor_checked and not armed:
                            armed[:] = ["pending"]
                    observe = owner.observation
                    owner._final_test_observation = False
                    def observation(status):
                        raw = observe(status)
                        owner._final_test_observation = status == "RELEASED"
                        return raw
                    context = ExitStack()
                    context.enter_context(patch.object(owner, "resource_guard", side_effect=guard))
                    context.enter_context(patch.object(owner, "live", side_effect=checked_live))
                    context.enter_context(patch.object(owner, "observation", side_effect=observation))
                else:
                    finish = bootstrap._Owner.finish_success
                    def finishing(current):
                        slow = current.guard
                        def guarded():
                            slow()
                            armed[:] = ["pending"]
                        with patch.object(current, "guard", side_effect=guarded):
                            finish(current)
                    context = patch.object(bootstrap._Owner, "finish_success", finishing)
                with context, patch.object(bootstrap._Owner, "tick", boundary):
                    with self.assertRaises(bootstrap.BrokerReaderBootstrapError):
                        if operation == "open":
                            h.server()
                        elif operation == "hello":
                            owner.accept_hello()
                        elif operation == "offer":
                            h.offer(owner)
                        elif operation == "release":
                            h.release(owner)
                        elif operation == "client":
                            h.client()
                        else:
                            owner.take_configuration()
                self.assertEqual(len(armed), 2)
                self.assertNotIn(armed[1], h.closed)

    def test_ready_timestamp_uses_lf_read_not_later_guard_work(self):
        for future in (False, True):
            with self.subTest(future=future), Harness() as h:
                server = self.opened(h)
                frame = ready_frame(h.provision)
                frame["ready_ns"] = 150 if future else 100
                h.ready_parts = [encode(frame) + b"\n"]
                original = bootstrap.os.open.side_effect
                def later(path, flags, **kwargs):
                    if path == "guard.sock":
                        h.now = 200
                    return original(path, flags, **kwargs)
                bootstrap.os.open.side_effect = later
                if future:
                    with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                        h.release(server)
                    self.assertIn("ready chronology", str(caught.exception.original_failure))
                    snapshots = caught.exception.observed["transport_observations"]
                else:
                    snapshots = json.loads(h.release(server)["observation_raw"])["transport_observations"]
                receipts = [s for s in snapshots if s["edge"] == "READY" and s["process_role"] == "SELF" and s["started_ns"] == s["finished_ns"] == 100]
                self.assertEqual(len(receipts), 1)
                self.assertEqual(h.now, 200)

    def test_pidfd_metadata_failure_before_configuration_retains_unknown(self):
        for fd in (12, 41, 43):
            with self.subTest(fd=fd), Harness() as h:
                server = h.server()
                if fd != 12:
                    server.accept_hello()
                if fd == 43:
                    h.offer(server)
                original = OSError(5, "PIDFD flags unavailable before configuration")
                def unavailable(number, command, value):
                    if number == fd:
                        raise original
                    return value
                h.flags_mutation = unavailable
                with self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    if fd == 12:
                        server.accept_hello()
                    elif fd == 41:
                        h.offer(server)
                    else:
                        h.release(server)
                resource = next(r for r in server.resources if r["fd"] == fd)
                self.assertIs(resource["pid"], bootstrap._PIDFD_UNKNOWN)
                self.assertIs(caught.exception.original_failure, original)
                self.assertIs(caught.exception.unresolved_owner, server)
                self.assertNotIn(fd, h.closed)

    def test_unexpected_pidfd_requires_actual_association_before_close(self):
        for case in ("known", "unavailable", "changed"):
            with self.subTest(case=case), Harness() as h:
                server = h.server()
                h.install(75, meta(95, stat.S_IFREG | 0o700), 2, "anon_inode:[pidfd]", 7000)
                h.install(76, meta(96, stat.S_IFREG | 0o600), 0, "/unexpected")
                h.packet_mutation = lambda i, raw, controls, flags: (raw, controls + [(1, 4, array.array("i", [75, 76]).tobytes())], flags)
                if case == "unavailable":
                    def unreadable(path, raw):
                        if path == "/proc/self/fdinfo/75":
                            raise OSError(5, "unknown PIDFD association")
                        return raw
                    h.read_mutation = unreadable
                elif case == "changed":
                    original = bootstrap._Owner.close_resource
                    def substitute(owner, resource):
                        if resource["fd"] == 75:
                            # Keep anonymous inode/link/flags unchanged; only
                            # actual association exposes the foreign handle.
                            h.descriptors[75]["pid"] = 7001
                        return original(owner, resource)
                context = patch.object(bootstrap._Owner, "close_resource", substitute) if case == "changed" else ExitStack()
                with context, self.assertRaises(bootstrap.BrokerReaderBootstrapError) as caught:
                    server.accept_hello()
                self.assertTrue({75, 76}.issubset({r["fd"] for r in server.resources}))
                if case == "known":
                    self.assertEqual(h.closed.count(75), 1)
                else:
                    self.assertNotIn(75, h.closed)
                    self.assertIs(caught.exception.unresolved_owner, server)
                if case == "unavailable":
                    self.assertIs(next(r for r in server.resources if r["fd"] == 75)["pid"], bootstrap._PIDFD_UNKNOWN)
                    self.assertNotIn(76, h.closed)  # Installed before first metadata failed.
