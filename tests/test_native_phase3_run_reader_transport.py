"""Guarded transport checks with syscall/store/leaf mocks; no live descriptors."""

import base64
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
import select
import socket
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import native_phase3_run_reader_transport as transport

_REAL_OWNED = transport.acquisition.acquire_owned_reader_response


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def info(device, inode, mode, uid=0, gid=0, nlink=1):
    return SimpleNamespace(st_dev=device, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid, st_nlink=nlink)


def proc_stat(pid, ticks):
    return (f"{pid} (read (loop) name) " + " ".join(["S"] + ["0"] * 18 + [str(ticks)]) + "\n").encode()


def proc_status(uid, gid):
    return (f"Umask:\t0077\nUid:\t{uid} {uid} {uid} {uid}\nGid:\t{gid} {gid} {gid} {gid}\n"
            "CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n").encode()


def fixture():
    pin = "sha256:" + "a" * 64
    process = dict(boot_id="11111111-2222-3333-4444-555555555555", reader_pid=101, reader_start_ticks=12,
                   sensor_pid=102, sensor_start_ticks=13, reader_uid=997, reader_gid=998, sensor_uid=0, sensor_gid=0,
                   reader_source_digest=pin, sensor_source_digest=pin, stream_digest=pin, program_map_digest=pin)
    epoch = dict(process=process, clock=dict(boot_id=process["boot_id"], clock_id="CLOCK_BOOTTIME", time_namespace_inode=99),
                 loss_scope=[pin], policy=dict(timeout_ns=1000, max_age_ns=50), deployment_digest=pin)
    directories = [dict(path=path, device=3, inode=inode, mode=stat.S_IFDIR | mode, uid=0, gid=gid)
                   for path, inode, mode, gid in (("/", 1, 0o755, 0), ("/run", 2, 0o755, 0),
                                                  ("/run/aragorn-phase3-reader", 3, 0o710, 998))]
    provision = dict(schema="aragorn/native-phase3-run-reader-transport-provision/v1", epoch_digest=digest(encode(epoch)),
                     observer=dict(pid=5000, start_time_ticks=33, uid=0, gid=0, time_namespace=dict(device=1, inode=99)),
                     directories=directories, notice_pipe=dict(device=2, inode=70, mode=stat.S_IFIFO | 0o600, uid=0, gid=0, reader_fd=3),
                     session_deadline_ns=100000, max_requests=8, access_inventory_digest=pin)
    return epoch, provision


class Harness:
    def __init__(self):
        self.epoch, self.provision = fixture()
        self.now = 1000
        self.order = []
        self.bound = False
        self.residue = False
        self.path_info = info(3, 4, stat.S_IFSOCK | 0o700)
        self.peer = (101, 997, 998)
        self.options = {transport.leaf._PASSCRED: 0, transport.leaf._PASSPIDFD: 0}
        self.queued = set()
        self.poll_actions = []
        self.accept_actions = []
        self.write_action = None
        self.writer_flags = os.O_WRONLY | os.O_NONBLOCK
        self.reader_flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
        self.pidfd_info = b"Pid:\t101\n"
        self.writer_inheritable = False
        self.writer_link = self.reader_link = "pipe:[70]"
        self.read_mutation = lambda path, raw: raw
        self.stat_mutation = lambda path, actual: actual
        self.fstat_mutation = lambda fd, actual: actual
        self.owned_status = "ACK"
        self.owned_exception = None
        self.owned_hook = lambda: None
        self.results = []
        self.connections = []
        self.random_count = 0
        self.listener = Mock()
        self.listener.family = socket.AF_UNIX
        self.listener.fileno.return_value = 300
        self.listener.gettimeout.return_value = 0.0
        self.listener.get_inheritable.return_value = False
        self.listener.getsockname.side_effect = lambda: transport._PATH if self.bound else ""
        self.listener.getsockopt.side_effect = lambda level, key: socket.SOCK_SEQPACKET if key == socket.SO_TYPE else self.options[key]
        self.listener.setsockopt.side_effect = self.option
        self.listener.bind.side_effect = self.bind
        self.listener.listen.side_effect = lambda backlog: self.order.append(("listen", backlog))
        self.listener.accept.side_effect = self.accept
        self.listener.detach.side_effect = self.detach_listener
        self.listener.close.side_effect = self.close_listener
        self.socket_destructor_closes = []

    def detach_listener(self):
        fd = self.listener.fileno.return_value
        self.listener.fileno.return_value = -1
        return fd

    def close_listener(self):
        # Model CPython's destructor close only while the object still owns an FD.
        fd = self.listener.fileno.return_value
        if fd >= 0:
            self.socket_destructor_closes.append(fd)
            self.listener.fileno.return_value = -1

    def option(self, level, key, value):
        self.order.append(("option", key, value))
        self.options[key] = value

    def bind(self, path):
        self.order.append(("bind", path))
        self.bound = True

    def stamp(self):
        self.now += 1
        return self.now

    def random(self, size):
        self.random_count += 1
        return bytes([self.random_count]) * size

    def read(self, path, maximum):
        path = str(path)
        if path == "/proc/self/fdinfo/11":
            raw = self.pidfd_info
        elif path == "/proc/101/fdinfo/3":
            raw = f"flags:\t{self.reader_flags:o}\n".encode()
        elif path == "/proc/sys/kernel/random/boot_id":
            raw = (self.epoch["clock"]["boot_id"] + "\n").encode()
        elif path in ("/proc/5000/stat", "/proc/101/stat"):
            raw = proc_stat(5000, 33) if "5000" in path else proc_stat(101, 12)
        elif path in ("/proc/5000/status", "/proc/101/status"):
            raw = proc_status(0, 0) if "5000" in path else proc_status(997, 998)
        else:
            raise AssertionError("unexpected mocked read " + path)
        return self.read_mutation(path, raw)

    def open(self, path, flags, **kwargs):
        fixed = {"/proc/5000/ns/time": 201, "/proc/101/ns/time": 202,
                 "/": 210, "run": 211, "aragorn-phase3-reader": 212, "challenge.sock": 301}
        self.order.append(("open", path, flags, kwargs))
        return fixed[path]

    def fstat(self, fd):
        if fd == 10:
            actual = info(2, 70, stat.S_IFIFO | 0o600)
        elif fd == 11:
            actual = info(4, 51, stat.S_IFREG | 0o600)
        elif fd in (201, 202):
            actual = info(1, 99, stat.S_IFREG | 0o444)
        elif fd in (210, 211, 212):
            entry = self.provision["directories"][fd - 210]
            actual = info(entry["device"], entry["inode"], entry["mode"], entry["uid"], entry["gid"])
        elif fd == 300:
            actual = info(9, 90, stat.S_IFSOCK | 0o777)
        elif fd == 301:
            actual = self.path_info
        elif 400 <= fd < 500:
            actual = info(9, fd + 1000, stat.S_IFSOCK | 0o777)
        else:
            raise AssertionError("unexpected mocked fstat " + str(fd))
        return self.fstat_mutation(fd, actual)

    def stat(self, path, **kwargs):
        if path == "challenge.sock":
            if not self.bound and not self.residue:
                raise FileNotFoundError(path)
            actual = self.path_info
        elif path in ("/", "run", "aragorn-phase3-reader"):
            actual = self.fstat({"/": 210, "run": 211, "aragorn-phase3-reader": 212}[path])
        elif path == "/proc/101/fd/3":
            actual = info(2, 70, stat.S_IFIFO | 0o600)
        else:
            raise AssertionError("unexpected mocked stat " + path)
        return self.stat_mutation(path, actual)

    def chown(self, path, uid, gid, **kwargs):
        self.order.append(("chown", path, uid, gid, kwargs))
        self.path_info = info(3, 4, self.path_info.st_mode, uid, gid)

    def chmod(self, path, mode, **kwargs):
        self.order.append(("chmod", path, mode, kwargs))
        self.path_info = info(3, 4, stat.S_IFSOCK | mode, self.path_info.st_uid, self.path_info.st_gid)

    def readlink(self, path):
        return {"/proc/self/fd/10": self.writer_link, "/proc/101/fd/3": self.reader_link}[path]

    def write(self, fd, raw):
        self.order.append(("write", fd, raw))
        if isinstance(self.write_action, BaseException):
            raise self.write_action
        return len(raw) if self.write_action is None else self.write_action

    def accept(self):
        self.order.append(("accept",))
        if self.accept_actions:
            action = self.accept_actions.pop(0)
            if isinstance(action, BaseException):
                raise action
            action()
        connection = Mock()
        connection.family = socket.AF_UNIX
        connection.fileno.return_value = 400 + len(self.connections)
        def detach():
            fd = connection.fileno.return_value
            connection.fileno.return_value = -1
            return fd
        connection.detach.side_effect = detach
        connection.close.side_effect = lambda: setattr(connection.fileno, "return_value", -1)
        connection.gettimeout.return_value = 0.0
        connection.get_inheritable.return_value = False
        connection.getsockopt.side_effect = lambda level, key, *args: (
            transport.leaf._UCREDS.pack(*self.peer) if key == transport.leaf._PEERCRED else
            socket.SOCK_SEQPACKET if key == socket.SO_TYPE else self.options[key])
        self.connections.append(connection)
        return connection, None

    def poller(self):
        harness = self
        class Poll:
            def __init__(self):
                self.registered = []
            def register(self, fd, flags):
                self.registered.append((fd, flags))
            def poll(self, timeout):
                fd = self.registered[0][0]
                if timeout == 0:
                    return [(fd, select.POLLIN)] if fd in harness.queued else []
                if harness.poll_actions:
                    action = harness.poll_actions.pop(0)
                    if isinstance(action, BaseException):
                        raise action
                    if callable(action):
                        return action()
                    return action
                return [(300, select.POLLIN)]
        return Poll()

    def owned(self, connection, *, epoch_raw, expected_epoch_digest, request_digest, sequence_before):
        try:
            self.owned_hook()
            if self.owned_exception is not None:
                raise self.owned_exception
            bindings = {key: digest(encode(self.epoch[key])) for key in ("process", "clock", "loss_scope", "policy")}
            bindings.update(epoch=expected_epoch_digest, request=request_digest)
            issued = self.stamp()
            challenge = dict(epoch_digest=expected_epoch_digest, request_digest=request_digest, boundary="BEFORE_FIRST_EFFECT",
                             nonce="e" * 64, issued_ns=issued, deadline_ns=issued + 1000, sequence_before=sequence_before)
            raw = encode(challenge)
            bindings["challenge"] = digest(raw)
            epoch = deepcopy(self.epoch)
            reader = dict(epoch_digest=expected_epoch_digest, challenge_digest=bindings["challenge"], request_digest=request_digest,
                          process_before=epoch["process"], process_after=epoch["process"], clock_before=epoch["clock"], clock_after=epoch["clock"],
                          peer=dict(pid=101, uid=997, gid=998), status=self.owned_status,
                          sequence_after=sequence_before + 1 if self.owned_status == "ACK" else sequence_before,
                          ack_ns=issued + 1 if self.owned_status == "ACK" else None,
                          received_ns=issued + 2 if self.owned_status == "ACK" else None)
            if self.owned_status == "TIMEOUT":
                self.now = challenge["deadline_ns"]
            else:
                self.now = issued + 2
            evidence_raw = b'{"mock":true}'
            result = dict(reader=reader, challenge_raw=raw, claim_raw=encode(dict(schema="aragorn/native-phase3-run-reader-claim/v1",
                          connection_epoch=f"{len(self.results)+1:064x}", challenge=challenge)), bindings=bindings,
                          connection_epoch=f"{len(self.results)+1:064x}", evidence_raw=evidence_raw, evidence_digest=digest(evidence_raw),
                          sensor_health_verified=False, acquisition_authenticity_verified=False, effect_authorized=False,
                          run_qualified=False, phase3_qualified=False)
            self.results.append(result)
            return result
        finally:
            connection.close()

    def __enter__(self):
        self.stack = ExitStack()
        patches = [(transport.sys, "platform", "linux"), (transport.sys, "byteorder", "little"),
                   (transport.os, "getpid", Mock(return_value=5000)),
                   (transport.os, "getresuid", Mock(return_value=(0, 0, 0))), (transport.os, "getresgid", Mock(return_value=(0, 0, 0))),
                   (transport.threading, "get_native_id", Mock(return_value=5000)),
                   (transport.leaf.clock, "_stamp", Mock(side_effect=self.stamp)),
                   (transport.leaf.clock, "_namespace", Mock(return_value=dict(device=1, inode=99))),
                   (transport.leaf.process, "require_live_pidfd", Mock()),
                   (transport.leaf.process, "_read_virtual_file", Mock(side_effect=self.read)),
                   (transport.os, "open", Mock(side_effect=self.open)), (transport.os, "fstat", Mock(side_effect=self.fstat)),
                   (transport.os, "stat", Mock(side_effect=self.stat)), (transport.os, "readlink", Mock(side_effect=self.readlink)),
                   (transport.os, "get_inheritable", Mock(side_effect=lambda fd: self.writer_inheritable)),
                   (transport.os, "urandom", Mock(side_effect=self.random)), (transport.os, "chown", Mock(side_effect=self.chown)),
                   (transport.os, "chmod", Mock(side_effect=self.chmod)), (transport.os, "close", Mock()),
                   (transport.os, "write", Mock(side_effect=self.write)), (transport.os, "fpathconf", Mock(return_value=4096)),
                   (transport.os, "unlink", Mock(side_effect=AssertionError("unlink forbidden"))),
                   (transport.os, "umask", Mock(side_effect=AssertionError("umask mutation forbidden"))),
                   (transport.socket, "socket", Mock(return_value=self.listener)),
                   (transport.socket, "setdefaulttimeout", Mock(side_effect=AssertionError("global timeout forbidden"))),
                   (transport.fcntl, "fcntl", Mock(side_effect=lambda fd, command: self.writer_flags)),
                   (transport.select, "poll", Mock(side_effect=self.poller)),
                   (transport.acquisition, "acquire_owned_reader_response", Mock(side_effect=self.owned))]
        for module, name, value in patches:
            self.stack.enter_context(patch.object(module, name, value, create=True))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def construct(self, **overrides):
        kwargs = dict(provision_raw=encode(self.provision), expected_provision_digest=digest(encode(self.provision)),
                      epoch_raw=encode(self.epoch), expected_epoch_digest=digest(encode(self.epoch)), notice_write_fd=10, reader_pidfd=11)
        kwargs.update(overrides)
        self.owner = transport.ReaderListener(**kwargs)
        return self.owner

    def begin(self, owner, ordinal=1, **overrides):
        kwargs = dict(admission_digest="sha256:" + f"{ordinal:064x}", request_digest="sha256:" + "a" * 64,
                      sequence_before=ordinal - 1, accept_deadline_ns=self.now + 5000, request_deadline_ns=self.now + 10000)
        kwargs.update(overrides)
        self.accept_deadline, self.request_deadline = kwargs["accept_deadline_ns"], kwargs["request_deadline_ns"]
        return owner.begin_request(**kwargs)


class ReaderTransportTests(unittest.TestCase):
    def refused(self, call):
        with self.assertRaises(transport.ReaderTransportError) as caught:
            call()
        error = caught.exception
        record = json.loads(error.partial_evidence)
        self.assertEqual(record["status"], "REFUSED")
        self.assertLessEqual(len(error.partial_evidence), 131072)
        for flag in ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized",
                     "run_qualified", "phase3_qualified", "request_timing_verified"):
            self.assertIs(record[flag], False)
        transport.os.unlink.assert_not_called()
        return error

    def test_open_fixed_endpoint_and_distinct_pathname_sockfs_custody(self):
        with Harness() as h:
            owner = h.construct()
            record = json.loads(owner.opening_evidence_raw)
            self.assertEqual(record["operation"], "OPEN")
            self.assertEqual(record["status"], "READY")
            h.listener.bind.assert_called_once_with("/run/aragorn-phase3-reader/challenge.sock")
            h.listener.listen.assert_called_once_with(1)
            self.assertLess(h.order.index(("option", transport.leaf._PASSCRED, 1)), h.order.index(("bind", transport._PATH)))
            self.assertLess(h.order.index(("option", transport.leaf._PASSPIDFD, 0)), h.order.index(("listen", 1)))
            self.assertEqual((h.path_info.st_uid, h.path_info.st_gid, h.path_info.st_mode), (0, 998, stat.S_IFSOCK | 0o660))
            nodes = [s["value"] for s in record["snapshots"] if s["name"].startswith("pathname")]
            sockets = [s["value"] for s in record["snapshots"] if s["name"].startswith("listener")]
            self.assertEqual(nodes[-1]["inode"], 4)
            self.assertEqual(sockets[-1]["inode"], 90)
            owner.close()
            self.assertEqual([c.args[0] for c in transport.os.close.call_args_list], [301, 300, 212, 211, 210, 202, 201, 11, 10])
            h.listener.detach.assert_called_once()
            transport.os.umask.assert_not_called()
            transport.socket.setdefaulttimeout.assert_not_called()

    def test_constructor_input_pins_and_schema_refuse_before_socket_or_notice(self):
        for change in (dict(expected_provision_digest="sha256:" + "f" * 64), dict(expected_epoch_digest="sha256:" + "f" * 64),
                       dict(provision_raw=b"{}"), dict(epoch_raw=b"[]"), dict(provision_raw=b" " * 8193)):
            with self.subTest(change=change), Harness() as h:
                self.refused(lambda: h.construct(**change))
                transport.socket.socket.assert_not_called()
                transport.os.write.assert_not_called()
                self.assertEqual([c.args[0] for c in transport.os.close.call_args_list], [11, 10])
        for key, value in (("max_requests", 0), ("max_requests", 4097), ("max_requests", True),
                           ("session_deadline_ns", 1), ("extra", 0)):
            with self.subTest(key=key), Harness() as h:
                h.provision[key] = value
                self.refused(h.construct)
                transport.socket.socket.assert_not_called()

    def test_transferred_fd_ownership_is_recorded_once_before_validation(self):
        for writer, pidfd, expected in ((True, 11, [11]), (2, 11, [11]), (10, -1, [10]), (10, 10, [10])):
            with self.subTest(writer=writer, pidfd=pidfd), Harness() as h:
                self.refused(lambda: h.construct(notice_write_fd=writer, reader_pidfd=pidfd))
                self.assertEqual([c.args[0] for c in transport.os.close.call_args_list], expected)
                transport.os.open.assert_not_called()

    def test_platform_abi_root_and_main_thread_guards(self):
        variants = ((transport.sys, "platform", "darwin"), (transport.sys, "byteorder", "big"),
                    (transport.os, "getresuid", Mock(return_value=(0, 1, 0))),
                    (transport.os, "getresgid", Mock(return_value=(0, 0, 1))),
                    (transport.threading, "get_native_id", Mock(return_value=5001)))
        for module, name, value in variants:
            with self.subTest(name=name), Harness() as h, patch.object(module, name, value, create=True):
                self.refused(h.construct)
                transport.socket.socket.assert_not_called()
                self.assertEqual(transport.os.close.call_count, 2)

    def test_process_pidfd_boot_namespace_and_umask_readbacks(self):
        mutations = (("/proc/self/fdinfo/11", b"Pid: 102\n"), ("/proc/101/stat", proc_stat(101, 13)),
                     ("/proc/5000/stat", proc_stat(5000, 34)), ("/proc/101/status", proc_status(0, 998)),
                     ("/proc/101/status", proc_status(997, 998).replace(b"CapEff:\t0", b"CapEff:\t1")),
                     ("/proc/101/status", proc_status(997, 998).replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0")),
                     ("/proc/5000/status", proc_status(0, 0).replace(b"0077", b"0022")),
                     ("/proc/sys/kernel/random/boot_id", b"different\n"))
        for path, raw in mutations:
            with self.subTest(path=path), Harness() as h:
                h.read_mutation = lambda p, previous: raw if p == path else previous
                error = self.refused(h.construct)
                self.assertIn(base64.b64encode(raw).decode(), error.partial_evidence.decode())
                transport.socket.socket.assert_not_called()
        with Harness() as h:
            transport.leaf.clock._namespace.return_value = dict(device=1, inode=100)
            self.refused(h.construct)
        with Harness() as h:
            transport.leaf.process.require_live_pidfd.side_effect = ValueError("reader dead")
            self.refused(h.construct)

    def test_notice_pipe_flags_anonymous_links_and_reader_target(self):
        cases = (("writer_flags", os.O_RDONLY | os.O_NONBLOCK), ("writer_flags", os.O_WRONLY),
                 ("reader_flags", os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC), ("reader_flags", os.O_RDONLY | os.O_NONBLOCK),
                 ("writer_inheritable", True), ("writer_link", "/tmp/fifo"), ("reader_link", "pipe:[71]"))
        for key, value in cases:
            with self.subTest(key=key, value=value), Harness() as h:
                setattr(h, key, value)
                self.refused(h.construct)
                transport.socket.socket.assert_not_called()
        with Harness() as h:
            h.stat_mutation = lambda path, previous: info(2, 71, stat.S_IFIFO | 0o600) if path == "/proc/101/fd/3" else previous
            self.refused(h.construct)
        with Harness() as h:
            h.provision["notice_pipe"]["reader_fd"] = 4
            self.refused(h.construct)

    def test_absent_socket_name_and_parent_custody_are_required(self):
        for mode in (stat.S_IFSOCK | 0o660, stat.S_IFLNK | 0o777, stat.S_IFREG | 0o600):
            with self.subTest(mode=mode), Harness() as h:
                h.residue = True
                h.path_info = info(3, 4, mode)
                self.refused(h.construct)
                transport.socket.socket.assert_not_called()
        for mode, uid, gid in ((stat.S_IFDIR | 0o777, 0, 998), (stat.S_IFLNK | 0o710, 0, 998),
                               (stat.S_IFDIR | 0o710, 1, 998), (stat.S_IFDIR | 0o710, 0, 999)):
            with self.subTest(mode=mode, uid=uid, gid=gid), Harness() as h:
                h.fstat_mutation = lambda fd, previous: info(3, 3, mode, uid, gid) if fd == 212 else previous
                self.refused(h.construct)
                transport.socket.socket.assert_not_called()

    def test_constructor_partial_and_unsupported_syscall_cleanup_preserves_error(self):
        with Harness() as h:
            primary = OSError("identity read unavailable")
            transport.os.getpid.side_effect = primary
            error = self.refused(h.construct)
            self.assertIs(error.original_failure, primary)
            self.assertEqual([c.args[0] for c in transport.os.close.call_args_list], [11, 10])
        with Harness() as h:
            primary = OSError("namespace unavailable")
            transport.os.open.side_effect = [201, primary]
            error = self.refused(h.construct)
            self.assertIs(error.original_failure, primary)
            self.assertEqual([c.args[0] for c in transport.os.close.call_args_list], [201, 11, 10])
        for target in ("option", "chmod"):
            with self.subTest(target=target), Harness() as h:
                primary = NotImplementedError("unsupported")
                if target == "option":
                    h.listener.setsockopt.side_effect = primary
                else:
                    transport.os.chmod.side_effect = primary
                error = self.refused(h.construct)
                self.assertIs(error.original_failure, primary)
                h.listener.detach.assert_called_once()
                transport.os.write.assert_not_called()

    def test_pathname_and_listener_identity_substitution_during_creation(self):
        with Harness() as h:
            h.stat_mutation = lambda path, previous: info(3, 55, previous.st_mode, previous.st_uid, previous.st_gid) if path == "challenge.sock" and previous.st_gid == 998 else previous
            self.refused(h.construct)
            h.listener.detach.assert_called_once()
        with Harness() as h:
            h.fstat_mutation = lambda fd, previous: info(9, 91, previous.st_mode) if fd == 300 and h.bound else previous
            self.refused(h.construct)
            h.listener.detach.assert_called_once()

    def test_multiple_successes_one_listener_atomic_notices_and_exact_transfer(self):
        with Harness() as h:
            owner = h.construct()
            notices = []
            for ordinal in (1, 2):
                raw = h.begin(owner, ordinal)
                notices.append(raw)
                notice = json.loads(raw)
                self.assertEqual(raw, encode(notice) + b"\n")
                self.assertEqual(notice["ordinal"], ordinal)
                self.assertEqual(notice["listener_epoch"], "01" * 32)
                self.assertEqual(set(notice), set("schema listener_epoch ordinal admission_digest epoch_digest request_digest sequence_before issued_ns accept_deadline_ns request_deadline_ns".split()))
                self.assertEqual(transport.os.write.call_args.args, (10, raw))
                result = owner.accept_request(raw)
                self.assertIs(result["owned"], h.results[-1])
                self.assertIs(result["listener_reusable"], True)
                self.assertEqual(result["transport_digest"], digest(result["transport_raw"]))
                call = transport.acquisition.acquire_owned_reader_response.call_args
                self.assertEqual(call.kwargs, dict(epoch_raw=encode(h.epoch), expected_epoch_digest=digest(encode(h.epoch)),
                                                  request_digest=notice["request_digest"], sequence_before=ordinal - 1))
                h.connections[-1].close.assert_called_once()
            self.assertNotEqual(notices[0], notices[1])
            self.assertNotEqual(h.results[0]["connection_epoch"], h.results[1]["connection_epoch"])
            self.assertEqual(transport.socket.socket.call_count, 1)
            self.assertEqual(h.listener.accept.call_count, 2)
            self.assertEqual(transport.os.write.call_count, 2)
            h.listener.detach.assert_not_called()
            owner.close()

    def test_replayed_admission_regressed_sequence_and_capacity_do_not_write(self):
        for variant in ("replay", "sequence", "capacity"):
            with self.subTest(variant=variant), Harness() as h:
                if variant == "capacity":
                    h.provision["max_requests"] = 1
                owner = h.construct()
                owner.accept_request(h.begin(owner))
                kwargs = dict(admission_digest="sha256:" + f"{1:064x}") if variant == "replay" else dict(sequence_before=0) if variant == "sequence" else {}
                self.refused(lambda: h.begin(owner, 2, **kwargs))
                self.assertEqual(transport.os.write.call_count, 1)
                h.listener.detach.assert_called_once()

    def test_request_bounds_deadlines_and_pipe_buf_refuse_before_write(self):
        for changes in (dict(sequence_before=True), dict(admission_digest="bad"), dict(accept_deadline_ns=1000),
                        dict(request_deadline_ns=100001), dict(accept_deadline_ns=6000, request_deadline_ns=6500),
                        dict(accept_deadline_ns=2**63), dict(sequence_before=2**63)):
            with self.subTest(changes=changes), Harness() as h:
                owner = h.construct()
                self.refused(lambda: h.begin(owner, **changes))
                transport.os.write.assert_not_called()
        with Harness() as h:
            owner = h.construct()
            transport.os.fpathconf.return_value = 8
            self.refused(lambda: h.begin(owner))
            transport.os.write.assert_not_called()

    def test_unsolicited_connection_ends_lifetime_without_accept_or_notice(self):
        with Harness() as h:
            owner = h.construct()
            h.queued.add(300)
            self.refused(lambda: h.begin(owner))
            h.listener.accept.assert_not_called()
            transport.os.write.assert_not_called()
            h.listener.detach.assert_called_once()

    def test_notice_short_eagain_interruption_and_pipe_errors_never_retry(self):
        for action in (0, 1, BlockingIOError(), InterruptedError(), BrokenPipeError(), KeyboardInterrupt()):
            with self.subTest(action=action), Harness() as h:
                owner = h.construct()
                h.write_action = action
                error = self.refused(lambda: h.begin(owner))
                transport.os.write.assert_called_once()
                self.assertIsNotNone(json.loads(error.partial_evidence)["notice_base64"])
                h.listener.detach.assert_called_once()
                self.refused(lambda: h.begin(owner, 2))
                transport.os.write.assert_called_once()

    def test_notice_deadline_and_postwrite_custody_failures_are_terminal(self):
        with Harness() as h:
            owner = h.construct()
            def delay(*args):
                h.now = h.accept_deadline
                return 4096
            transport.os.fpathconf.side_effect = delay
            self.refused(lambda: h.begin(owner))
            transport.os.write.assert_not_called()
        with Harness() as h:
            owner = h.construct()
            h.read_mutation = lambda path, raw: proc_stat(101, 13) if path == "/proc/101/stat" and transport.os.write.called else raw
            self.refused(lambda: h.begin(owner))
            transport.os.write.assert_called_once()
            h.listener.detach.assert_called_once()

    def test_accept_eintr_and_eagain_stay_inside_one_notice_budget(self):
        with Harness() as h:
            owner = h.construct()
            raw = h.begin(owner)
            h.poll_actions = [InterruptedError()]
            h.accept_actions = [BlockingIOError()]
            result = owner.accept_request(raw)
            self.assertTrue(result["listener_reusable"])
            self.assertEqual(h.listener.accept.call_count, 2)
            transport.os.write.assert_called_once()
            transport.acquisition.acquire_owned_reader_response.assert_called_once()
            owner.close()

    def test_accept_timeout_reader_exit_poll_error_and_late_accept_refuse(self):
        for event in ([(11, select.POLLIN)], [(300, select.POLLHUP)], [(300, select.POLLERR)]):
            with self.subTest(event=event), Harness() as h:
                owner = h.construct()
                raw = h.begin(owner)
                h.poll_actions = [event]
                self.refused(lambda: owner.accept_request(raw))
                transport.acquisition.acquire_owned_reader_response.assert_not_called()
        with Harness() as h:
            owner = h.construct()
            raw = h.begin(owner)
            h.poll_actions = [lambda: (setattr(h, "now", h.accept_deadline) or [])]
            self.refused(lambda: owner.accept_request(raw))
            h.listener.accept.assert_not_called()
        with Harness() as h:
            owner = h.construct()
            raw = h.begin(owner)
            h.accept_actions = [lambda: setattr(h, "now", h.accept_deadline)]
            self.refused(lambda: owner.accept_request(raw))
            h.connections[0].detach.assert_called_once()
            h.connections[0].close.assert_not_called()
            transport.os.close.assert_any_call(400)
            transport.acquisition.acquire_owned_reader_response.assert_not_called()

    def test_wrong_peer_or_prequeued_payload_closes_one_accepted_socket(self):
        for peer in ((102, 997, 998), (101, 0, 998), (101, 997, 0)):
            with self.subTest(peer=peer), Harness() as h:
                owner = h.construct()
                raw = h.begin(owner)
                h.peer = peer
                self.refused(lambda: owner.accept_request(raw))
                h.listener.accept.assert_called_once()
                h.connections[0].detach.assert_called_once()
                h.connections[0].close.assert_not_called()
                transport.os.close.assert_any_call(400)
                transport.acquisition.acquire_owned_reader_response.assert_not_called()
        with Harness() as h:
            owner = h.construct()
            raw = h.begin(owner)
            h.queued.add(400)
            self.refused(lambda: owner.accept_request(raw))
            h.connections[0].detach.assert_called_once()
            h.connections[0].close.assert_not_called()

    def test_accepted_inherited_options_and_mode_must_read_back(self):
        for key, value in ((transport.leaf._PASSCRED, 0), (transport.leaf._PASSPIDFD, 1)):
            with self.subTest(key=key), Harness() as h:
                owner = h.construct()
                raw = h.begin(owner)
                original_accept = h.accept
                def accept():
                    result = original_accept()
                    h.options[key] = value
                    return result
                h.listener.accept.side_effect = accept
                self.refused(lambda: owner.accept_request(raw))
                h.connections[0].detach.assert_called_once()
                h.connections[0].close.assert_not_called()
        for variant in ("timeout", "inheritable", "family"):
            with self.subTest(variant=variant), Harness() as h:
                owner = h.construct()
                raw = h.begin(owner)
                original_accept = h.accept
                def accept():
                    connection, address = original_accept()
                    if variant == "timeout":
                        connection.gettimeout.return_value = 0.1
                    elif variant == "inheritable":
                        connection.get_inheritable.return_value = True
                    else:
                        connection.family = socket.AF_INET
                    return connection, address
                h.listener.accept.side_effect = accept
                self.refused(lambda: owner.accept_request(raw))
                h.connections[0].setblocking.assert_called_once_with(False)
                h.connections[0].set_inheritable.assert_called_once_with(False)

    def test_actual_late_issued_deadline_quarantines_candidate_reader(self):
        with Harness() as h:
            owner = h.construct()
            raw = h.begin(owner)
            h.owned_hook = lambda: setattr(h, "now", h.request_deadline - 500)
            error = self.refused(lambda: owner.accept_request(raw))
            self.assertIn("actual issued challenge", str(error.original_failure))
            self.assertEqual(error.unaccepted_reader_raw, encode(h.results[0]["reader"]))
            self.assertIsNone(error.owned_observed["reader"])
            h.connections[0].close.assert_called_once()
            h.listener.detach.assert_called_once()

    def test_timeout_returns_complete_record_after_terminal_cleanup(self):
        with Harness() as h:
            owner = h.construct()
            raw = h.begin(owner)
            h.owned_status = "TIMEOUT"
            result = owner.accept_request(raw)
            self.assertEqual(result["owned"]["reader"]["status"], "TIMEOUT")
            self.assertFalse(result["listener_reusable"])
            record = json.loads(result["transport_raw"])
            self.assertEqual(record["status"], "TIMEOUT")
            self.assertEqual(len(record["descriptor_cleanup"]), 9)
            h.listener.detach.assert_called_once()
            h.connections[0].close.assert_called_once()
            self.refused(owner.close)
            h.listener.detach.assert_called_once()

    def test_postreturn_custody_failure_and_cleanup_failure_expose_no_reader(self):
        with Harness() as h:
            owner = h.construct()
            raw = h.begin(owner)
            h.read_mutation = lambda path, previous: proc_stat(101, 13) if path == "/proc/101/stat" and h.results else previous
            error = self.refused(lambda: owner.accept_request(raw))
            self.assertIsNone(error.owned_observed["reader"])
            self.assertEqual(error.unaccepted_reader_raw, encode(h.results[0]["reader"]))
            h.connections[0].close.assert_called_once()
        with Harness() as h:
            owner = h.construct()
            raw = h.begin(owner)
            h.owned_status = "TIMEOUT"
            transport.os.close.side_effect = OSError("close uncertain")
            error = self.refused(lambda: owner.accept_request(raw))
            self.assertEqual(len(error.cleanup_failures), 9)
            self.assertIsNone(error.owned_observed["reader"])
            self.assertEqual(transport.os.close.call_count, 9)

    def test_cancel_and_wrong_notice_are_terminal_without_transfer(self):
        with Harness() as h:
            owner = h.construct()
            notice = h.begin(owner)
            result = owner.cancel_request(notice)
            self.assertEqual(json.loads(result)["status"], "CANCELLED")
            h.listener.accept.assert_not_called()
            transport.acquisition.acquire_owned_reader_response.assert_not_called()
            self.refused(lambda: owner.accept_request(notice))
            h.listener.detach.assert_called_once()
        for operation in ("accept_request", "cancel_request"):
            with self.subTest(operation=operation), Harness() as h:
                owner = h.construct()
                notice = h.begin(owner)
                self.refused(lambda: getattr(owner, operation)(notice + b" "))
                h.listener.accept.assert_not_called()
                h.listener.detach.assert_called_once()

    def test_owner_and_reentrant_cancellation_cannot_close_under_transfer(self):
        with Harness() as h:
            owner = h.construct()
            with patch.object(transport.threading, "get_native_id", return_value=5001):
                self.refused(owner.close)
            with patch.object(transport.os, "getpid", return_value=5001):
                self.refused(owner.close)
            h.listener.detach.assert_not_called()
            transport.os.close.assert_not_called()
            owner.close()
        with Harness() as h:
            owner = h.construct()
            notice = h.begin(owner)
            def reenter():
                inner = self.refused(lambda: owner.cancel_request(notice))
                self.assertEqual(json.loads(inner.partial_evidence)["descriptor_cleanup"], [])
                h.listener.detach.assert_not_called()
                raise inner
            h.owned_hook = reenter
            self.refused(lambda: owner.accept_request(notice))
            h.listener.detach.assert_called_once()
            h.connections[0].close.assert_called_once()

    def test_real_owning_wrapper_issues_and_closes_with_mocked_store_leaf(self):
        with Harness() as h:
            owner = h.construct()
            notice = h.begin(owner)
            store = Mock()
            store.consume_once.side_effect = lambda raw: raw
            store.retain.side_effect = lambda raw, expected_digest: dict(digest=expected_digest, bytes=len(raw))
            def response(connection, **kwargs):
                challenge = json.loads(kwargs["challenge_raw"])
                claim = encode(dict(schema="aragorn/native-phase3-run-reader-claim/v1", connection_epoch=kwargs["connection_epoch"], challenge=challenge))
                self.assertEqual(kwargs["consume_once"](claim), claim)
                raw = b'{"wire":true}'
                kwargs["retain"](raw, expected_digest=digest(raw))
                return dict(epoch_digest=kwargs["bindings"]["epoch"], challenge_digest=kwargs["bindings"]["challenge"], request_digest=kwargs["bindings"]["request"],
                            process_before=h.epoch["process"], process_after=h.epoch["process"], clock_before=h.epoch["clock"], clock_after=h.epoch["clock"],
                            peer=dict(pid=101, uid=997, gid=998), status="ACK", sequence_after=1,
                            ack_ns=challenge["issued_ns"], received_ns=challenge["issued_ns"])
            transport.acquisition.acquire_owned_reader_response.side_effect = _REAL_OWNED
            with patch.object(transport.acquisition, "ReaderStore", return_value=store), patch.object(transport.leaf, "acquire_reader_response", side_effect=response):
                result = owner.accept_request(notice)
            self.assertTrue(result["listener_reusable"])
            self.assertEqual(result["owned"]["evidence_raw"], b'{"wire":true}')
            self.assertEqual(h.random_count, 3)
            store.final_readback.assert_called_once()
            store.close.assert_called_once()
            h.connections[0].close.assert_called_once()
            owner.close()

    def test_original_owned_retention_and_terminal_cleanup_failures_survive(self):
        with Harness() as h:
            owner = h.construct()
            notice = h.begin(owner)
            retention = OSError("retention uncertain")
            observed = dict(reader=None, evidence_raw=b"x" * 131072)
            primary = transport.acquisition.OwnedReaderResponseError(RuntimeError("leaf failed"), observed, [OSError("owned close")], retention)
            h.owned_exception = primary
            transport.os.close.side_effect = OSError("outer close")
            error = self.refused(lambda: owner.accept_request(notice))
            self.assertIs(error.original_failure, primary)
            self.assertIs(error.original_failure.retention_failure, retention)
            self.assertIs(error.owned_observed, observed)
            self.assertEqual(len(error.cleanup_failures), 9)
            metadata = json.loads(error.partial_evidence)
            self.assertEqual(len(metadata["cleanup_failure_types"]), 8)
            self.assertIs(metadata["cleanup_failure_types_complete"], False)
            self.assertLess(len(error.partial_evidence), 131072)
            h.connections[0].close.assert_called_once()
            h.listener.detach.assert_called_once()

    def test_changed_descriptor_cleanup_skips_foreign_close_and_detaches_socket(self):
        for fd in (10, 11, 300):
            with self.subTest(fd=fd), Harness() as h:
                owner = h.construct()
                if fd == 11:
                    # PIDFD anon-inode metadata alone cannot identify its target.
                    h.pidfd_info = b"Pid:\t102\n"
                else:
                    h.fstat_mutation = lambda target, previous: info(
                        previous.st_dev, previous.st_ino + 1, previous.st_mode,
                        previous.st_uid, previous.st_gid) if target == fd else previous
                error = self.refused(lambda: h.begin(owner))
                self.assertTrue(error.cleanup_failures)
                actual_closed = [call.args[0] for call in transport.os.close.call_args_list]
                self.assertNotIn(fd, actual_closed)
                self.assertIn(212, actual_closed)
                record = json.loads(error.partial_evidence)
                self.assertEqual([row["fd"] for row in record["descriptor_cleanup"]], actual_closed)
                h.listener.detach.assert_called_once()
                self.assertEqual(h.listener.fileno(), -1)
                # A later socket finalizer cannot close the skipped replacement.
                h.listener.close()
                self.assertEqual(h.socket_destructor_closes, [])
                before = transport.os.close.call_count
                self.refused(owner.close)
                self.assertEqual(transport.os.close.call_count, before)

    def test_unknown_descriptor_and_detach_failures_preserve_unreleased_custody(self):
        for initial in (True, False):
            with self.subTest(initial=initial), Harness() as h:
                owner = None if initial else h.construct()
                def unreadable(fd, previous):
                    if fd == 10:
                        raise OSError("descriptor identity unavailable")
                    return previous
                h.fstat_mutation = unreadable
                error = self.refused(h.construct if initial else owner.close)
                self.assertTrue(error.cleanup_failures)
                closed = [call.args[0] for call in transport.os.close.call_args_list]
                self.assertNotIn(10, closed)
                self.assertIn(11, closed)
                self.assertNotIn(10, [row["fd"] for row in json.loads(error.partial_evidence)["descriptor_cleanup"]])
        for variant in ("wrong-number", "unavailable"):
            with self.subTest(variant=variant), Harness() as h:
                owner = h.construct()
                if variant == "wrong-number":
                    def wrong_detach():
                        h.detach_listener()
                        return 999
                    h.listener.detach.side_effect = wrong_detach
                else:
                    h.listener.detach.side_effect = OSError("detach uncertain")
                error = self.refused(owner.close)
                h.listener.detach.assert_called_once()
                h.listener.close.assert_not_called()
                closed = [call.args[0] for call in transport.os.close.call_args_list]
                self.assertNotIn(300, closed)
                self.assertNotIn(999, closed)
                self.assertIn(10, closed)
                self.assertIn(h.listener, error._unreleased_sockets)
                self.assertTrue(error.cleanup_failures)
                self.assertNotIn(300, [row["fd"] for row in json.loads(error.partial_evidence)["descriptor_cleanup"]])

    def test_final_proc_read_mutations_quarantine_reader_and_end_lifetime(self):
        variants = ("writer-flags", "reader-flags", "late-reader-flags", "writer-inode", "reader-inode", "writer-link", "reader-link",
                    "namespace", "directory", "pathname", "listener", "pidfd", "clock")
        for variant in variants:
            with self.subTest(variant=variant), Harness() as h:
                owner = h.construct()
                notice = h.begin(owner)
                changed = []
                pidfd_reads = []
                def mutate(path, raw):
                    if variant == "late-reader-flags":
                        if path == "/proc/self/fdinfo/11" and h.results:
                            pidfd_reads.append(path)
                            if len(pidfd_reads) == 2:
                                changed.append(variant)
                                h.reader_flags = os.O_RDONLY | os.O_CLOEXEC
                        return raw
                    if path != "/proc/101/fdinfo/3" or not h.results or changed:
                        return raw
                    changed.append(variant)
                    if variant == "writer-flags":
                        h.writer_flags = os.O_WRONLY
                    elif variant == "reader-flags":
                        h.reader_flags = os.O_RDONLY | os.O_CLOEXEC
                    elif variant in ("writer-inode", "listener"):
                        target = 10 if variant == "writer-inode" else 300
                        h.fstat_mutation = lambda fd, previous: info(
                            previous.st_dev, previous.st_ino + 1, previous.st_mode,
                            previous.st_uid, previous.st_gid) if fd == target else previous
                    elif variant in ("reader-inode", "directory", "pathname"):
                        target = {"reader-inode": "/proc/101/fd/3", "directory": "run", "pathname": "challenge.sock"}[variant]
                        h.stat_mutation = lambda name, previous: info(
                            previous.st_dev, previous.st_ino + 1, previous.st_mode,
                            previous.st_uid, previous.st_gid) if name == target else previous
                    elif variant == "writer-link":
                        h.writer_link = "pipe:[71]"
                    elif variant == "reader-link":
                        h.reader_link = "pipe:[71]"
                    elif variant == "namespace":
                        transport.leaf.clock._namespace.return_value = dict(device=1, inode=100)
                    elif variant == "pidfd":
                        h.pidfd_info = b"Pid:\t102\n"
                    else:
                        h.now -= 1000
                    return raw
                h.read_mutation = mutate
                error = self.refused(lambda: owner.accept_request(notice))
                self.assertEqual(changed, [variant])
                self.assertIsNone(error.owned_observed["reader"])
                self.assertEqual(error.unaccepted_reader_raw, encode(h.results[0]["reader"]))
                self.assertLessEqual(len(json.loads(error.partial_evidence)["snapshots"]), 32)
                h.connections[0].close.assert_called_once()
                h.connections[0].detach.assert_not_called()
                h.listener.detach.assert_called_once()
                transport.os.write.assert_called_once()
                if variant == "late-reader-flags":
                    self.assertEqual([call.args[0] for call in transport.os.close.call_args_list],
                                     [301, 300, 212, 211, 210, 202, 201, 11, 10])
                before = transport.acquisition.acquire_owned_reader_response.call_count
                self.refused(lambda: owner.accept_request(notice))
                self.assertEqual(transport.acquisition.acquire_owned_reader_response.call_count, before)

    def test_evidence_inventory_raw_budget_and_clock_rollback(self):
        expected = set("schema operation status listener_epoch provision_digest epoch_digest admission_digest request_digest ordinal sequence_before notice_base64 started_ns finished_ns snapshots peer_credentials_base64 accepted_ns transfer_started_ns transfer_finished_ns owned_evidence_digest challenge_digest connection_epoch reader_digest descriptor_cleanup failure_type cleanup_failure_types cleanup_failure_types_complete listener_reusable acquisition_authenticity_verified sensor_health_verified effect_authorized run_qualified phase3_qualified request_timing_verified".split())
        with Harness() as h:
            owner = h.construct()
            self.assertEqual(set(json.loads(owner.opening_evidence_raw)), expected)
            owner.close()
        with Harness() as h:
            h.read_mutation = lambda path, raw: raw + b"\n" * (16384 - len(raw)) if path.endswith("/status") else raw
            error = self.refused(h.construct)
            self.assertIn("raw snapshot budget", str(error.original_failure))
            self.assertLessEqual(len(json.loads(error.partial_evidence)["snapshots"]), 32)
        with Harness() as h:
            owner = h.construct()
            h.now -= 100
            self.refused(lambda: h.begin(owner))
