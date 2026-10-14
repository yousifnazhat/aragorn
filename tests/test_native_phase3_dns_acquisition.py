"""Focused DNS acquisition/replay checks; all native boundaries are mocked."""

import ast
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import errno
import gc
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import stat
import sys
from types import SimpleNamespace
import unittest
import weakref
from unittest.mock import Mock, patch

from aragorn import native_phase3_dns_acquisition as acquisition
from aragorn import native_phase3_dns_context as context
from aragorn import native_phase3_dns_acquisition_verify as replay


FLAGS = "interval_complete client_readiness_confirmed quiescence_verified final_queue_drained retention_verified blocked_pre_effect causal_attribution measurement_collected live_deployment_attested run_eligible phase3_exit_eligible".split()
LIMITS = """APPLICATION_RECVMSG_SAMPLE_NOT_KERNEL_ARRIVAL_COMPLETENESS
NO_CLIENT_READINESS_RECEIPT_OR_ACTION_START_AUTHORITY
NO_SERIALIZED_DNS_QUIESCENCE_OR_FINAL_DRAIN_PROOF
RAW_PROC_AND_NAMESPACE_JOINS_NOT_DEPLOYED_KERNEL_OR_SOURCE_ATTESTATION
UINT32_DROP_EQUALITY_CANNOT_EXCLUDE_UNOBSERVED_FULL_WRAP
RETURNED_BYTES_NOT_DURABLE_RETENTION_OR_RETENTION_READBACK
SUBMISSION_UNKNOWN_EFFECT_INDETERMINATE
NO_PREVENTION_RUN_METRICS_OR_PHASE3_QUALIFICATION""".split()
HEADER = b"sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n"


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def process_stat(pid, ticks):
    return (f"{pid} (DNS (reader) process) " + " ".join(["S"] + ["0"] * 18 + [str(ticks)]) + "\n").encode()


def status():
    return b"Name:\tdns\nUid:\t0 0 0 0\nGid:\t0 0 0 0\n"


def udp_table(drops=7, rx=0, inode=90):
    return HEADER + f"0: 0100007F:BA10 00000000:0000 07 00000000:{rx:08X} 00:00000000 00000000 0 0 {inode} 2 0000000000000000 {drops}\n".encode()


def request():
    fixture = dict(container_id="a" * 64, boot_id="11111111-2222-3333-4444-555555555555", netns_device=1, netns_inode=55)
    return dict(schema="aragorn/native-dns-acquisition-request/v1", abi_profile="linux-le-proc-udp-v6.12-layout-v1",
                attempt_id="p3-lab-a026", readiness_nonce="ab" * 16, fixture=fixture,
                observer_process=dict(pid=5000, start_time_ticks=33, uid=0, gid=0),
                clock_domain=dict(clock_id="CLOCK_BOOTTIME", boot_id=fixture["boot_id"], time_namespace_device=2,
                                  time_namespace_inode=99, monotonic_offset_ns=-500000000, boottime_offset_ns=2000000003),
                cancellation_identity=dict(device=1, inode=70, mode=stat.S_IFIFO | 0o600, uid=0, gid=0))


def probe():
    # Authored directly from the reviewed wire contract, never builder fixtures.
    return bytes.fromhex("ffff00000001000000000000") + b"\x0daragorn-ready\x20" + b"ab" * 16 + b"\x07invalid\x00\x00\x01\x00\x01"


def raw_process(req):
    root = ("0::/docker/" + req["fixture"]["container_id"]).encode()
    return dict(stat_hex=process_stat(5000, 33).hex(), status_hex=status().hex(), cgroup_hex=(root + b"/observer\n").hex(),
                init_stat_hex=process_stat(1, 1).hex(), init_status_hex=status().hex(), init_cgroup_hex=(root + b"/init.scope\n").hex(),
                boot_hex=(req["fixture"]["boot_id"] + "\n").encode().hex(),
                timens_offsets_hex=b"monotonic -1 500000000\nboottime 2 3\n".hex())


def snapshot(req, start, finish):
    handles = {name: dict(held_device=device, named_device=device, held_inode=inode, named_inode=inode)
               for name, device, inode in (("network", 1, 55), ("init_network", 1, 55), ("time", 2, 99), ("time_for_children", 2, 99))}
    return dict(read_started_ns=start, read_finished_ns=finish,
                observer=dict(fixture=deepcopy(req["fixture"]), process=deepcopy(req["observer_process"]),
                              init_process=dict(pid=1, start_time_ticks=1, uid=0, gid=0), socket_inode=90),
                clock_domain=deepcopy(req["clock_domain"]),
                socket=dict(device=9, inode=90, mode=stat.S_IFSOCK | 0o777, uid=0, gid=0, fd_link="socket:[90]",
                            host="127.0.0.1", port=47632, type=2, reuse_address=0, reuse_port=0, nonblocking=True, cloexec=True),
                proc_udp_raw_hex=udp_table().hex(),
                proc_udp_row=dict(socket_inode=90, uid=0, local_host="127.0.0.1", local_port=47632, remote_host="0.0.0.0", remote_port=0,
                                  state=7, tx_queue=0, rx_queue=0, drops=7), raw_process=raw_process(req), namespace_handles=handles)


def fixture_record(with_query=False):
    req = request()
    record = dict(schema="aragorn/native-dns-acquisition/v1", status="SAMPLED_NOT_COMPLETE", request_raw_hex=encode(req).hex(),
                  request_digest=digest(encode(req)), kernel_release="6.12.mock", before=snapshot(req, 1, 10),
                  after=snapshot(req, 2000000040, 2000000050),
                  sample=dict(started_ns=20, deadline_ns=2000000020, finished_ns=2000000030, terminal="DEADLINE"),
                  receives=[], readiness_response=None,
                  counters=dict(received_datagrams=0, observer_drops=0, receive_errors=0, truncated_datagrams=0, would_block_calls=0,
                                socket_drop_delta=0, socket_drop_state="UNCHANGED"),
                  cancellation=dict(identity_before=deepcopy(req["cancellation_identity"]), identity_after=deepcopy(req["cancellation_identity"]),
                                    fd_link="pipe:[70]", status_flags=2048, descriptor_flags=1, event="NOT_OBSERVED", observed_ns=None,
                                    read_count=None, read_errno=None, would_block_reads=0, closed=True),
                  socket_closed=True, errors=[], cleanup_codes=[], limitations=list(LIMITS), submission_state="UNKNOWN", effect_disposition="INDETERMINATE")
    record.update(dict.fromkeys(FLAGS, False))
    if with_query:
        record["receives"] = [dict(sequence=0, call_started_ns=30, call_finished_ns=31, call_flags=64, outcome="RECEIVED", errno=None,
                                    peer_host="127.0.0.1", peer_port=53000, raw_hex=probe().hex(), returned_bytes=len(probe()), receive_flags=0, ancillary=[])]
        record["readiness_response"] = dict(receive_sequence=0, call_started_ns=32, call_finished_ns=33, peer_host="127.0.0.1", peer_port=53000,
                                            response_hex=(probe()[:2] + b"\x80\x00" + probe()[4:]).hex(), returned_bytes=len(probe()), errno=None)
        record["counters"]["received_datagrams"] = 1
    return record


def metadata(device, inode, mode, uid=0, gid=0):
    return SimpleNamespace(st_dev=device, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid)


class Harness:
    def __init__(self):
        self.request = request()
        self.now = 1000
        self.order = []
        self.bound = False
        self.receives = []
        self.poll_actions = []
        self.cancel_ready = False
        self.cancel_result = b"x"
        self.send_result = None
        self.read_mutation = lambda path, raw: raw
        self.fstat_mutation = lambda fd, value: value
        self.stat_mutation = lambda path, value: value
        self.readlink_mutation = lambda path, value: value
        self.table_count = 0
        self.before_drops = self.after_drops = 7
        self.namespace_child = 99
        self.cancel_flags, self.cancel_descriptor_flags = 2048, 1
        self.socket_flags, self.socket_descriptor_flags = 2050, 1
        self.fixture_note = None
        self.fixture = Mock()
        self.fixture._fds = (20, 21, 22)
        self.fixture.identity = dict(fixture=deepcopy(self.request["fixture"]), process=deepcopy(self.request["observer_process"]),
                                     init_process=dict(pid=1, start_time_ticks=1, uid=0, gid=0))
        self.fixture.guard.side_effect = lambda: self.order.append("fixture_guard")
        self.sock = Mock()
        self.sock.family = socket.AF_INET
        self.sock.fileno.return_value = 40
        self.sock.bind.side_effect = self.bind
        self.sock.gettimeout.return_value = 0.0
        self.sock.get_inheritable.return_value = False
        self.sock.getsockname.side_effect = lambda: ("127.0.0.1", 47632) if self.bound else ("0.0.0.0", 0)
        self.sock.getpeername.side_effect = OSError(errno.ENOTCONN, "not connected")
        self.sock.getsockopt.side_effect = lambda level, key: 2 if key == socket.SO_TYPE else 0
        self.sock.recvmsg.side_effect = self.receive
        self.sock.sendto.side_effect = self.send
        self.sock.detach.side_effect = self.detach
        self.destructor_closes = []
        self.sock.close.side_effect = lambda: self.destructor_closes.append(self.sock.fileno()) if self.sock.fileno() >= 0 else None

    @contextmanager
    def owned_fixture(self, expected):
        if expected != self.request["fixture"]:
            raise AssertionError("fixture pin")
        self.order.append("fixture_enter")
        try:
            yield self.fixture
        finally:
            self.order.append("fixture_exit")
            if self.fixture_note:
                primary = sys.exception()
                if primary is not None:
                    primary.add_note(self.fixture_note)
                else:
                    raise ValueError(self.fixture_note)

    def bind(self, endpoint):
        self.order.append(("bind", endpoint))
        self.bound = True

    def detach(self):
        fd = self.sock.fileno.return_value
        self.sock.fileno.return_value = -1
        return fd

    def close(self, fd):
        self.order.append(("close", fd))

    def stamp(self):
        self.now += 10
        return self.now

    def open(self, path, flags):
        self.order.append(("open", path, flags))
        return {"/proc/self/ns/time": 30, "/proc/self/ns/time_for_children": 31}[path]

    def fstat(self, fd):
        if fd in (10, 11):
            actual = metadata(1, 70 if fd == 10 else 71, stat.S_IFIFO | 0o600)
        elif fd in (20, 21):
            actual = metadata(1, 55, stat.S_IFREG | 0o444)
        elif fd in (30, 31):
            actual = metadata(2, 99 if fd == 30 else self.namespace_child, stat.S_IFREG | 0o444)
        elif fd == 40:
            actual = metadata(9, 90, stat.S_IFSOCK | 0o777)
        else:
            raise AssertionError("unexpected mocked descriptor")
        return self.fstat_mutation(fd, actual)

    def stat(self, path):
        fd = {"/proc/self/ns/net": 20, "/proc/1/ns/net": 21, "/proc/self/ns/time": 30,
              "/proc/self/ns/time_for_children": 31}[str(path)]
        return self.stat_mutation(str(path), self.fstat(fd))

    def readlink(self, path):
        values = {"/proc/self/fd/10": "pipe:[70]", "/proc/self/fd/11": "pipe:[71]", "/proc/self/fd/40": "socket:[90]",
                  "/proc/self/ns/net": "net:[55]", "/proc/1/ns/net": "net:[55]",
                  "/proc/self/ns/time": "time:[99]", "/proc/self/ns/time_for_children": f"time:[{self.namespace_child}]"}
        return self.readlink_mutation(path, values[path])

    def read(self, path, maximum):
        path = str(path)
        names = {"/proc/self/stat": "stat_hex", "/proc/self/status": "status_hex", "/proc/self/cgroup": "cgroup_hex",
                 "/proc/1/stat": "init_stat_hex", "/proc/1/status": "init_status_hex", "/proc/1/cgroup": "init_cgroup_hex",
                 "/proc/sys/kernel/random/boot_id": "boot_hex", "/proc/self/timens_offsets": "timens_offsets_hex"}
        self.order.append(("read", path))
        if path == "/proc/net/udp":
            self.table_count += 1
            raw = udp_table(self.before_drops if self.table_count == 1 else self.after_drops)
        else:
            raw = bytes.fromhex(raw_process(self.request)[names[path]])
        return self.read_mutation(path, raw)

    def read_cancel(self, fd, count):
        self.order.append(("cancel_read", fd, count))
        self.cancel_ready = False
        if isinstance(self.cancel_result, BaseException):
            raise self.cancel_result
        return self.cancel_result

    def receive(self, *args):
        self.order.append(("recvmsg", *args))
        result = self.receives.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def send(self, data, flags, peer):
        self.order.append(("sendto", data, flags, peer))
        if isinstance(self.send_result, BaseException):
            raise self.send_result
        return len(data) if self.send_result is None else self.send_result

    def poll(self):
        h = self
        class Poll:
            def __init__(self):
                self.fds = []
            def register(self, fd, events):
                self.fds.append(fd)
            def poll(self, timeout):
                h.order.append(("poll", tuple(self.fds), timeout))
                if timeout == 0:
                    return [(10, select.POLLIN)] if h.cancel_ready else []
                if h.poll_actions:
                    action = h.poll_actions.pop(0)
                    if isinstance(action, BaseException):
                        raise action
                    return action() if callable(action) else action
                if h.receives:
                    return [(40, select.POLLIN)]
                h.now += 2000000000
                return []
        return Poll()

    def __enter__(self):
        self.stack = ExitStack()
        patches = [(context.sys, "platform", "linux"), (context.sys, "byteorder", "little"),
                   (context, "_QUARANTINED_OWNER", None), (context, "_ACTIVE_OWNER", None),
                   (context.socket, "SOCK_NONBLOCK", 2048), (context.socket, "SOCK_CLOEXEC", 524288),
                   (context.socket, "MSG_DONTWAIT", 64), (context.errno, "EAGAIN", 11), (context.errno, "EWOULDBLOCK", 11),
                   (context.os, "O_NONBLOCK", 2048), (context.os, "O_CLOEXEC", 524288),
                   (context.os, "getpid", Mock(return_value=5000)), (context.threading, "get_native_id", Mock(return_value=5000)),
                   (context.os, "getresuid", Mock(return_value=(0, 0, 0))), (context.os, "getresgid", Mock(return_value=(0, 0, 0))),
                   (context.os, "pidfd_open", Mock(side_effect=AssertionError("fixture mock alone owns PIDFD"))),
                   (context.os, "uname", Mock(return_value=SimpleNamespace(release="6.12.mock"))),
                   (context.clock.time, "CLOCK_BOOTTIME", 7), (context.clock, "_stamp", Mock(side_effect=self.stamp)),
                   (context.clock, "_namespace", Mock(return_value=dict(device=2, inode=99))),
                   (context.process, "_process_start_time", Mock(side_effect=lambda pid: 33 if pid == 5000 else 1)),
                   (context.process, "_read_virtual_file", Mock(side_effect=self.read)),
                   (context, "owned_http_fixture", Mock(side_effect=self.owned_fixture)),
                   (context.os, "open", Mock(side_effect=self.open)), (context.os, "fstat", Mock(side_effect=self.fstat)),
                   (context.os, "stat", Mock(side_effect=self.stat)), (context.os, "readlink", Mock(side_effect=self.readlink)),
                   (context.os, "read", Mock(side_effect=self.read_cancel)), (context.os, "close", Mock(side_effect=self.close)),
                   (context.socket, "socket", Mock(return_value=self.sock)), (context.select, "poll", Mock(side_effect=self.poll)),
                   (context.fcntl, "fcntl", Mock(side_effect=lambda fd, command: (self.socket_flags if command == context.fcntl.F_GETFL else self.socket_descriptor_flags)
                    if fd == 40 else (self.cancel_flags if command == context.fcntl.F_GETFL else self.cancel_descriptor_flags)))]
        for module, name, value in patches:
            self.stack.enter_context(patch.object(module, name, value, create=True))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def capture(self, **changes):
        args = dict(request_raw=encode(self.request), expected_request_digest=digest(encode(self.request)), cancel_fd=10)
        args.update(changes)
        return context.capture_dns_acquisition(**args)


class DnsAcquisitionTests(unittest.TestCase):
    def verify(self, value, req=None):
        req_raw = encode(request() if req is None else req)
        raw = value if type(value) is bytes else encode(value)
        return replay.verify_dns_acquisition(raw, expected_acquisition_digest=digest(raw), expected_request_raw=req_raw,
                                             expected_request_digest=digest(req_raw))

    def refused(self, h, code, **changes):
        with self.assertRaises(context.DnsAcquisitionError) as caught:
            h.capture(**changes)
        error = caught.exception
        self.assertEqual(str(error), "DNS_ACQUISITION_REFUSED")
        if error.partial_raw is not None:
            value = json.loads(error.partial_raw)
            self.assertIn(code, value["errors"] + value["cleanup_codes"])
            self.assertIn(value["status"], ("REFUSED", "CANCELLED"))
            self.assertLessEqual(len(error.partial_raw), 524287)
            for flag in FLAGS:
                self.assertIs(value[flag], False)
        else:
            self.assertEqual(error.reason_code, code)
        return error

    def test_actual_context_one_fixed_bind_deadline_and_owned_cleanup(self):
        with Harness() as h:
            raw = h.capture()
            value = json.loads(raw)
            result = self.verify(raw)
            self.assertEqual(result["record_status"], "SAMPLED_NOT_COMPLETE")
            self.assertEqual(result["socket_drop_state"], "UNCHANGED")
            self.assertEqual(value["before"]["proc_udp_row"]["drops"], 7)
            self.assertEqual(value["after"]["proc_udp_row"]["drops"], 7)
            self.assertEqual(value["sample"]["deadline_ns"] - value["sample"]["started_ns"], 2000000000)
            h.sock.bind.assert_called_once_with(("127.0.0.1", 47632))
            context.socket.socket.assert_called_once_with(socket.AF_INET, 2 | 2048 | 524288, socket.IPPROTO_UDP)
            h.sock.connect.assert_not_called()
            h.sock.setsockopt.assert_not_called()
            h.sock.recvmsg.assert_not_called()
            h.sock.detach.assert_called_once()
            h.sock.close.assert_not_called()
            self.assertEqual([c.args[0] for c in context.os.close.call_args_list], [40, 31, 30, 10])
            self.assertLess(h.order.index(("close", 10)), h.order.index("fixture_exit"))
            self.assertFalse(result["retention_verified"])

    def test_invalid_request_and_descriptor_syntax_consume_only_known_owned_fd(self):
        for fd in (True, -1, "10", None, 2**63):
            with self.subTest(fd=fd), Harness() as h:
                error = self.refused(h, "INPUT_REFUSED", cancel_fd=fd)
                self.assertIsNone(error.partial_raw)
                context.os.close.assert_not_called()
        for raw in (b"{}", b"[]", b" " * 16384, b'{"schema":1,"schema":2}', encode(request()) + b"\n"):
            with self.subTest(raw_size=len(raw)), Harness() as h:
                error = self.refused(h, "INPUT_REFUSED", request_raw=raw, expected_request_digest=digest(raw))
                self.assertIsNone(error.partial_raw)
                context.os.close.assert_called_once_with(10)
                context.socket.socket.assert_not_called()
        with Harness() as h:
            self.refused(h, "INPUT_REFUSED", expected_request_digest="sha256:" + "f" * 64)
            context.os.close.assert_called_once_with(10)

    def test_request_exact_fields_types_and_caller_pins(self):
        variants = [("attempt_id", "p3-lab-a025"), ("readiness_nonce", "A" * 32), ("abi_profile", "other"), ("extra", 0)]
        for key, value in variants:
            with self.subTest(key=key), Harness() as h:
                h.request[key] = value
                self.refused(h, "INPUT_REFUSED")
        for key, value in (("pid", True), ("uid", True), ("gid", 1), ("start_time_ticks", 0)):
            with self.subTest(key=key), Harness() as h:
                h.request["observer_process"][key] = value
                self.refused(h, "INPUT_REFUSED")

    def test_platform_pointer_endian_and_missing_native_support_refuse(self):
        variants = ((context.sys, "platform", "darwin"), (context.sys, "byteorder", "big"),
                    (context.socket, "MSG_DONTWAIT", 128), (context.os, "pidfd_open", None))
        for module, name, value in variants:
            with self.subTest(name=name), Harness() as h, patch.object(module, name, value):
                error = self.refused(h, "ABI_UNAVAILABLE")
                self.verify(error.partial_raw)
                context.socket.socket.assert_not_called()
        with Harness() as h, patch.object(context.struct, "calcsize", return_value=4):
            self.refused(h, "ABI_UNAVAILABLE")

    def test_root_main_thread_process_and_fixture_substitution_refuse(self):
        variants = ((context.os, "getpid", Mock(return_value=5001)),
                    (context.threading, "get_native_id", Mock(return_value=5001)),
                    (context.os, "getresuid", Mock(return_value=(0, 1, 0))),
                    (context.os, "getresgid", Mock(return_value=(0, 0, 1))),
                    (context.process, "_process_start_time", Mock(return_value=34)))
        for module, name, value in variants:
            with self.subTest(name=name), Harness() as h, patch.object(module, name, value):
                error = self.refused(h, "PROCESS_CHANGED")
                self.verify(error.partial_raw)
                context.socket.socket.assert_not_called()
        with Harness() as h:
            h.fixture.guard.side_effect = ValueError("substituted fixture")
            error = self.refused(h, "FIXTURE_CHANGED")
            self.verify(error.partial_raw)

    def test_socket_options_name_remote_link_and_bind_failure(self):
        for variant in ("reuse_address", "reuse_port", "type", "blocking", "inheritable", "name", "remote", "link"):
            with self.subTest(variant=variant), Harness() as h:
                if variant in ("reuse_address", "reuse_port", "type"):
                    key = {"reuse_address": socket.SO_REUSEADDR, "reuse_port": socket.SO_REUSEPORT, "type": socket.SO_TYPE}[variant]
                    h.sock.getsockopt.side_effect = lambda level, option: 1 if option == key else 2 if option == socket.SO_TYPE else 0
                elif variant == "blocking":
                    h.sock.gettimeout.return_value = None
                elif variant == "inheritable":
                    h.sock.get_inheritable.return_value = True
                elif variant == "name":
                    h.sock.getsockname.side_effect = lambda: ("0.0.0.0", 47632) if h.bound else ("0.0.0.0", 0)
                elif variant == "remote":
                    h.sock.getpeername.side_effect = None
                    h.sock.getpeername.return_value = ("127.0.0.1", 53)
                else:
                    h.readlink_mutation = lambda path, old: "socket:[91]" if path.endswith("/40") else old
                self.refused(h, "SOCKET_CHANGED")
                if variant == "name":
                    h.sock.bind.assert_called_once()
                else:
                    h.sock.bind.assert_not_called()
                h.sock.recvmsg.assert_not_called()
        with Harness() as h:
            h.sock.bind.side_effect = OSError(98, "port busy")
            self.refused(h, "BIND_REFUSED")
            h.sock.bind.assert_called_once()

    def test_cancel_pipe_exact_identity_flags_and_anonymous_link(self):
        for variant in ("identity", "direction", "blocking", "cloexec", "link"):
            with self.subTest(variant=variant), Harness() as h:
                if variant == "identity":
                    h.request["cancellation_identity"]["inode"] = 71
                elif variant == "direction":
                    h.cancel_flags = 2049
                elif variant == "blocking":
                    h.cancel_flags = 0
                elif variant == "cloexec":
                    h.cancel_descriptor_flags = 0
                else:
                    h.readlink_mutation = lambda path, old: "/tmp/fifo" if path.endswith("/10") else old
                self.refused(h, "CANCEL_IDENTITY_CHANGED")
                context.socket.socket.assert_not_called()
                context.os.read.assert_not_called()

    def test_nonzero_loss_queue_reset_increase_unknown_and_malformed(self):
        for before, after, state, code in ((9, 3, "RESET", "SOCKET_DROP_RESET"), (7, 8, "INCREASED", "SOCKET_DROP_INCREASED")):
            with self.subTest(state=state), Harness() as h:
                h.before_drops, h.after_drops = before, after
                error = self.refused(h, code)
                result = self.verify(error.partial_raw)
                self.assertEqual(result["socket_drop_state"], state)
                value = json.loads(error.partial_raw)
                self.assertEqual(value["before"]["proc_udp_row"]["drops"], before)
                self.assertEqual(value["after"]["proc_udp_row"]["drops"], after)
        with Harness() as h:
            h.read_mutation = lambda path, raw: HEADER if path == "/proc/net/udp" else raw
            error = self.refused(h, "PROC_UDP_UNAVAILABLE")
            self.assertEqual(self.verify(error.partial_raw)["socket_drop_state"], "UNKNOWN")
        with Harness() as h:
            def unavailable(path, raw):
                if path == "/proc/net/udp":
                    raise OSError("unavailable")
                return raw
            h.read_mutation = unavailable
            self.refused(h, "PROC_UDP_UNAVAILABLE")

    def test_proc_udp_exact_layout_duplicate_conflict_width_and_bounds(self):
        original = udp_table()
        malformed = [b"", b"invalid\n", original[:-1], original.replace(b"07 ", b"7 "),
                     original.replace(b"0000000000000000", b"000000000000000A"),
                     original.replace(b" 7\n", b" 4294967296\n"), original.replace(b" 7\n", b" 07\n"),
                     original + original[len(HEADER):], original + original[len(HEADER):].replace(b"0100007F", b"00000000").replace(b" 90 ", b" 91 "),
                     HEADER + original[len(HEADER):] * 65, b"x" * 16385, original.replace(b" 2 ", b" 0 "), original.replace(b" 0 0 90 ", b" 0 1 90 ")]
        for raw in malformed:
            with self.subTest(size=len(raw)), Harness() as h:
                h.read_mutation = lambda path, old: raw if path == "/proc/net/udp" else old
                error = self.refused(h, "PROC_UDP_INVALID")
                self.verify(error.partial_raw)

    def test_journal_zero_byte_malformed_canary_and_would_block_are_not_filtered(self):
        packets = [b"", b"malformed DNS", b"p3canary-p3-lab-a026.exfil.invalid"]
        with Harness() as h:
            h.receives = [BlockingIOError(11, "empty")] + [(p, [], 0, ("127.0.0.2", 53000)) for p in packets]
            raw = h.capture()
            value = json.loads(raw)
            self.assertEqual([bytes.fromhex(r["raw_hex"]) for r in value["receives"][1:]], packets)
            self.assertIsNone(value["receives"][0]["raw_hex"])
            self.assertEqual(value["counters"]["received_datagrams"], 3)
            self.assertEqual(value["counters"]["would_block_calls"], 1)
            self.assertEqual(value["counters"]["receive_errors"], 0)
            self.assertEqual(self.verify(raw)["received_datagrams"], 3)
            h.sock.sendto.assert_not_called()

    def test_exact_first_readiness_response_once_without_client_authority(self):
        with Harness() as h:
            h.receives = [(probe(), [], 0, ("127.0.0.1", 53000))]
            raw = h.capture()
            result = self.verify(raw)
            self.assertTrue(result["readiness_response_recorded"])
            self.assertFalse(result["client_readiness_confirmed"])
            self.assertEqual(result["submission_state"], "UNKNOWN")
            self.assertEqual(result["effect_disposition"], "INDETERMINATE")
            h.sock.sendto.assert_called_once_with(probe()[:2] + b"\x80\x00" + probe()[4:], 64, ("127.0.0.1", 53000))
            h.sock.recvmsg.assert_called_once_with(4096, 256, 64)

    def test_readiness_wrong_nonce_and_replay_never_send_twice(self):
        with Harness() as h:
            h.receives = [(probe().replace(b"abab", b"cdcd", 1), [], 0, ("127.0.0.1", 53000))]
            self.verify(h.capture())
            h.sock.sendto.assert_not_called()
        with Harness() as h:
            h.receives = [(probe(), [], 0, ("127.0.0.1", 53000))] * 2
            error = self.refused(h, "READINESS_REPLAY")
            self.verify(error.partial_raw)
            h.sock.sendto.assert_called_once()
            self.assertEqual(len(json.loads(error.partial_raw)["receives"]), 2)

    def test_short_would_block_interrupted_and_unknown_readiness_sends_do_not_retry(self):
        for outcome in (1, BlockingIOError(11, "full"), InterruptedError(4, "signal"), OSError("unknown")):
            with self.subTest(outcome=type(outcome).__name__), Harness() as h:
                h.receives = [(probe(), [], 0, ("127.0.0.1", 53000))]
                h.send_result = outcome
                error = self.refused(h, "READINESS_SEND_FAILED")
                self.assertFalse(self.verify(error.partial_raw)["readiness_response_recorded"])
                h.sock.sendto.assert_called_once()

    def test_receive_errors_and_interrupted_unknown_calls_are_journaled(self):
        for failure in (InterruptedError(4, "signal"), OSError(5, "io"), OSError("unknown")):
            with self.subTest(kind=type(failure).__name__), Harness() as h:
                h.receives = [failure]
                error = self.refused(h, "RECEIVE_FAILED")
                self.verify(error.partial_raw)
                row = json.loads(error.partial_raw)["receives"][0]
                self.assertEqual(row["outcome"], "ERROR")
                self.assertIsNone(row["raw_hex"])
                h.sock.recvmsg.assert_called_once()

    def test_truncation_unknown_flags_and_ancillary_preserve_bounded_bytes(self):
        for flags, controls, code in ((32, [], "DATAGRAM_TRUNCATED"), (8, [], "DATAGRAM_TRUNCATED"),
                                      (1, [], "RECEIVE_FLAGS_REFUSED"), (0, [(1, 1, b"\x28\0\0\0")], "ANCILLARY_REFUSED"),
                                      (0, [(1, 9, b"x" * 300)], "ANCILLARY_REFUSED")):
            with self.subTest(flags=flags, control_size=len(controls)), Harness() as h:
                h.receives = [(b"retained prefix", controls, flags, ("127.0.0.1", 53000))]
                error = self.refused(h, code)
                self.verify(error.partial_raw)
                row = json.loads(error.partial_raw)["receives"][0]
                self.assertEqual(bytes.fromhex(row["raw_hex"]), b"retained prefix")
                self.assertEqual(row["receive_flags"], flags)
                self.assertNotIn(40, [call.args[0] for call in context.os.close.call_args_list[:-4]])
                self.assertLessEqual(sum(len(bytes.fromhex(c["raw_hex"])) for c in row["ancillary"]), 256)

    def test_nonloopback_peer_refuses_after_retaining_payload(self):
        with Harness() as h:
            h.receives = [(b"data", [], 0, ("192.0.2.1", 53000))]
            error = self.refused(h, "PEER_REFUSED")
            self.verify(error.partial_raw)
            h.sock.sendto.assert_not_called()

    def test_offsets_parentheses_cgroup_boot_and_namespace_substitutions(self):
        with Harness() as h:
            self.verify(h.capture())
        mutations = [("/proc/self/stat", process_stat(5000, 34), "PROCESS_CHANGED"),
                     ("/proc/self/status", status().replace(b"0 0 0 0", b"0 1 0 0", 1), "PROCESS_CHANGED"),
                     ("/proc/1/cgroup", b"0::/wrong/init.scope\n", "FIXTURE_CHANGED"),
                     ("/proc/sys/kernel/random/boot_id", b"changed\n", "CLOCK_CHANGED"),
                     ("/proc/self/timens_offsets", b"monotonic 0 0\nboottime 2 3\n", "CLOCK_CHANGED"),
                     ("/proc/self/timens_offsets", b"monotonic 0 1000000000\nboottime 0 0\n", "CLOCK_CHANGED")]
        for path, raw, code in mutations:
            with self.subTest(path=path), Harness() as h:
                h.read_mutation = lambda p, old: raw if p == path else old
                error = self.refused(h, code)
                self.verify(error.partial_raw)
        with Harness() as h:
            h.namespace_child = 100
            self.refused(h, "CLOCK_CHANGED")

    def test_cancellation_byte_eof_priority_and_no_receive_or_send_after_signal(self):
        for signal in (b"x", b""):
            with self.subTest(size=len(signal)), Harness() as h:
                h.cancel_result = signal
                def ready():
                    h.cancel_ready = True
                    return [(40, select.POLLIN), (10, select.POLLIN | select.POLLHUP)]
                h.poll_actions = [ready]
                error = self.refused(h, "CANCELLED")
                self.assertEqual(self.verify(error.partial_raw)["record_status"], "CANCELLED")
                context.os.read.assert_called_once_with(10, 1)
                h.sock.recvmsg.assert_not_called()
                h.sock.sendto.assert_not_called()
                self.assertNotIn('"x"', error.partial_raw.decode())

    def test_cancellation_before_bind_and_spurious_eagain_or_read_failure(self):
        with Harness() as h:
            h.cancel_ready = True
            error = self.refused(h, "CANCELLED")
            self.verify(error.partial_raw)
            context.socket.socket.assert_not_called()
        with Harness() as h:
            h.cancel_ready = True
            h.cancel_result = BlockingIOError(11, "spurious")
            raw = h.capture()
            self.assertEqual(json.loads(raw)["cancellation"]["would_block_reads"], 1)
            self.verify(raw)
        with Harness() as h:
            h.cancel_ready = True
            h.cancel_result = OSError(5, "read failure")
            error = self.refused(h, "CANCEL_READ_FAILED")
            self.verify(error.partial_raw)

    def test_poll_failure_and_cancel_error_flags_do_not_receive(self):
        for events, code in ((OSError(5, "poll"), "POLL_FAILED"), ([(40, select.POLLERR)], "POLL_FAILED"),
                             ([(10, select.POLLNVAL), (40, select.POLLIN)], "CANCEL_IDENTITY_CHANGED")):
            with self.subTest(code=code), Harness() as h:
                h.poll_actions = [events]
                self.refused(h, code)
                h.sock.recvmsg.assert_not_called()

    def test_receive_and_datagram_limits_refuse_without_extra_call(self):
        for outcomes, code in (([BlockingIOError(11, "empty")] * 64, "READ_LIMIT"),
                               ([(b"", [], 0, ("127.0.0.1", 53000))] * 16, "DATAGRAM_LIMIT")):
            with self.subTest(code=code), Harness() as h:
                h.receives = outcomes
                error = self.refused(h, code)
                self.verify(error.partial_raw)
                self.assertEqual(h.sock.recvmsg.call_count, 64 if code == "READ_LIMIT" else 16)

    def test_document_reserve_refuses_before_receive_and_preserves_partial(self):
        with Harness() as h, patch.object(acquisition, "_reserve", side_effect=acquisition._Fault("EVIDENCE_LIMIT")):
            h.receives = [(b"data", [], 0, ("127.0.0.1", 53000))]
            error = self.refused(h, "EVIDENCE_LIMIT")
            self.verify(error.partial_raw)
            h.sock.recvmsg.assert_not_called()

    def test_interruptions_preserve_original_class_and_cleanup_notes(self):
        for interrupted in (KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(kind=type(interrupted).__name__), Harness() as h:
                h.receives = [interrupted]
                h.fixture_note = "HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED"
                context.os.close.side_effect = OSError("uncertain close")
                with self.assertRaises(type(interrupted)) as caught:
                    h.capture()
                self.assertIs(caught.exception, interrupted)
                value = json.loads(interrupted.dns_acquisition_partial_raw)
                self.assertIn("INTERRUPTED", value["errors"])
                self.assertIn("FIXTURE_CLOSE_FAILED", value["cleanup_codes"])
                self.assertIn("SOCKET_CLOSE_FAILED", value["cleanup_codes"])
                self.assertEqual(context.os.close.call_count, 4)
                self.verify(interrupted.dns_acquisition_partial_raw)

    def test_substituted_or_unknown_fd_is_not_closed_and_socket_detaches(self):
        for fd in (10, 40):
            with self.subTest(fd=fd), Harness() as h:
                def mutation(path, raw):
                    if path == "/proc/net/udp":
                        h.fstat_mutation = lambda target, old: metadata(old.st_dev, old.st_ino + 1, old.st_mode) if target == fd else old
                    return raw
                h.read_mutation = mutation
                error = self.refused(h, "CANCEL_IDENTITY_CHANGED" if fd == 10 else "SOCKET_CHANGED")
                self.assertNotIn(fd, [call.args[0] for call in context.os.close.call_args_list])
                self.assertIn("CANCEL_CLOSE_FAILED" if fd == 10 else "SOCKET_CLOSE_FAILED", error.cleanup_codes)
                self.verify(error.partial_raw)
                h.sock.detach.assert_called_once()
                h.sock.close()
                self.assertEqual(h.destructor_closes, [])
        with Harness() as h:
            h.fstat_mutation = lambda fd, old: (_ for _ in ()).throw(OSError("unknown")) if fd == 10 else old
            error = self.refused(h, "INPUT_REFUSED")
            self.assertIn("CANCEL_CLOSE_FAILED", error.cleanup_codes)
            context.os.close.assert_not_called()
        with Harness() as h:
            def change_pipe_end(path, raw):
                if path == "/proc/net/udp":
                    h.cancel_flags = 2049
                return raw
            h.read_mutation = change_pipe_end
            error = self.refused(h, "CANCEL_IDENTITY_CHANGED")
            self.verify(error.partial_raw)
            self.assertNotIn(10, [call.args[0] for call in context.os.close.call_args_list])
            self.assertIn("CANCEL_CLOSE_FAILED", error.cleanup_codes)

    def test_fixture_final_guard_and_close_failure_codes_survive_primary(self):
        for note, code in (("HTTP_FIXTURE_FINAL_GUARD_FAILED", "FINAL_GUARD_FAILED"),
                           ("HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED", "FIXTURE_CLOSE_FAILED")):
            with self.subTest(note=note), Harness() as h:
                h.receives = [OSError(5, "receive")]
                h.fixture_note = note
                error = self.refused(h, "RECEIVE_FAILED")
                value = json.loads(error.partial_raw)
                self.assertIn(code, value["errors"] + value["cleanup_codes"])
                self.verify(error.partial_raw)

    def test_nonmonotonic_clock_and_late_poll_never_receive_after_deadline(self):
        with Harness() as h:
            def backwards():
                h.now -= 1000
                return [(40, select.POLLIN)]
            h.poll_actions = [backwards]
            self.refused(h, "CLOCK_CHANGED")
            h.sock.recvmsg.assert_not_called()
        with Harness() as h:
            def late():
                h.now += 2000000000
                return [(40, select.POLLIN)]
            h.poll_actions = [late]
            self.verify(h.capture())
            h.sock.recvmsg.assert_not_called()

    def test_independent_handcrafted_empty_and_readiness_records(self):
        for has_query in (False, True):
            with self.subTest(query=has_query):
                result = self.verify(fixture_record(has_query))
                self.assertEqual(result["readiness_response_recorded"], has_query)
                self.assertEqual(result["received_datagrams"], int(has_query))
                for flag in FLAGS:
                    self.assertIs(result[flag], False)

    def test_consumer_expected_pins_canonical_duplicate_extra_and_literal_flags(self):
        value = fixture_record()
        raw, req = encode(value), encode(request())
        for acquisition_pin, request_pin in (("sha256:" + "f" * 64, digest(req)), (digest(raw), "sha256:" + "f" * 64)):
            with self.subTest(pin=acquisition_pin):
                with self.assertRaises(ValueError):
                    replay.verify_dns_acquisition(raw, expected_acquisition_digest=acquisition_pin, expected_request_digest=request_pin, expected_request_raw=req)
        invalid = [raw + b"\n", b'{"schema":1,"schema":2}', encode({**value, "extra": None}), raw.replace(b'"socket_closed":true', b'"socket_closed":1')]
        for bad in invalid:
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                self.verify(bad)
        for flag in FLAGS:
            for wrong in (True, 0, "false"):
                with self.subTest(flag=flag, wrong=wrong), self.assertRaises(ValueError):
                    self.verify({**value, flag: wrong})

    def test_consumer_rejects_raw_proc_namespace_clock_counter_and_wire_substitutions(self):
        def changed(path, replacement):
            value = fixture_record(True)
            cursor = value
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = replacement
            return value
        mutations = [(("counters", "received_datagrams"), 0), (("counters", "observer_drops"), 1),
                     (("before", "proc_udp_row", "drops"), 0), (("before", "proc_udp_row", "rx_queue"), 1),
                     (("before", "raw_process", "stat_hex"), process_stat(5000, 34).hex()),
                     (("before", "namespace_handles", "time_for_children", "named_inode"), 100),
                     (("before", "clock_domain", "monotonic_offset_ns"), 0),
                     (("readiness_response", "response_hex"), probe().hex()),
                     (("readiness_response", "receive_sequence"), 1), (("readiness_response", "call_started_ns"), 29),
                     (("receives", 0, "returned_bytes"), 0), (("receives", 0, "sequence"), 1),
                     (("sample", "deadline_ns"), 21), (("cancellation", "identity_after", "inode"), 71)]
        for path, replacement in mutations:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.verify(changed(path, replacement))

    def test_consumer_independence_and_partial_refusal_reconstruction(self):
        source = Path(replay.__file__).read_text()
        tree = ast.parse(source)
        imports = [ast.unparse(node) for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any("dns_acquisition" in item or "dns_context" in item or "dns_canary" in item for item in imports))
        with patch.object(acquisition, "_udp", side_effect=AssertionError("producer parser forbidden")), patch.object(acquisition, "_proc", side_effect=AssertionError("producer parser forbidden")):
            self.verify(fixture_record(True))
        value = fixture_record()
        value["status"] = "REFUSED"
        value["sample"]["terminal"] = "REFUSED"
        value["before"]["proc_udp_raw_hex"] = b"invalid table\n".hex()
        value["before"]["proc_udp_row"] = None
        value["errors"] = ["PROC_UDP_INVALID", "SOCKET_DROP_UNKNOWN"]
        value["counters"].update(socket_drop_delta=None, socket_drop_state="UNKNOWN")
        self.assertEqual(self.verify(value)["socket_drop_state"], "UNKNOWN")
        value["before"]["proc_udp_row"] = fixture_record()["before"]["proc_udp_row"]
        with self.assertRaises(ValueError):
            self.verify(value)

    def test_retired_context_and_fork_during_sampling_cannot_be_reused(self):
        with Harness() as h:
            owners = []
            original_sample = acquisition._sample
            def sample(owner):
                owners.append(owner)
                return original_sample(owner)
            with patch.object(acquisition, "_sample", side_effect=sample):
                self.verify(h.capture())
            with self.assertRaises(ValueError):
                owners[0].guard()
            h.sock.bind.assert_called_once()
        with Harness() as h:
            def forked():
                context.os.getpid.return_value = 5001
                return [(40, select.POLLIN)]
            h.poll_actions = [forked]
            self.refused(h, "PROCESS_CHANGED")
            h.sock.recvmsg.assert_not_called()

    def test_final_table_read_mutations_are_closed_by_process_clock_and_fd_guards(self):
        for variant in ("offset", "namespace", "process", "socket"):
            with self.subTest(variant=variant), Harness() as h:
                changed = []
                def mutate(path, raw):
                    if path == "/proc/net/udp" and h.table_count == 2:
                        changed.append(variant)
                        if variant == "namespace":
                            h.namespace_child = 100
                        elif variant == "process":
                            context.process._process_start_time.return_value = 34
                            context.process._process_start_time.side_effect = None
                        elif variant == "socket":
                            h.fstat_mutation = lambda fd, old: metadata(9, 91, old.st_mode) if fd == 40 else old
                    if variant == "offset" and changed and path == "/proc/self/timens_offsets":
                        return b"monotonic 0 0\nboottime 2 3\n"
                    return raw
                h.read_mutation = mutate
                code = "CLOCK_CHANGED" if variant in ("offset", "namespace") else "PROCESS_CHANGED" if variant == "process" else "SOCKET_CHANGED"
                error = self.refused(h, code)
                self.assertEqual(changed, [variant])
                self.verify(error.partial_raw)

    def test_resource_exhaustion_and_cleanup_interruptions_never_return_success(self):
        with Harness() as h:
            exhausted = MemoryError()
            h.receives = [exhausted]
            with self.assertRaises(MemoryError) as caught:
                h.capture()
            self.assertIs(caught.exception, exhausted)
            value = json.loads(exhausted.dns_acquisition_partial_raw)
            self.assertIsNone(value["counters"]["observer_drops"])
            self.assertIsNone(value["counters"]["received_datagrams"])
            self.assertEqual(value["receives"][0]["outcome"], "ERROR")
            self.verify(exhausted.dns_acquisition_partial_raw)
        with Harness() as h:
            interrupted = KeyboardInterrupt()
            context.os.close.side_effect = [interrupted, None, None, None]
            with self.assertRaises(KeyboardInterrupt) as caught:
                h.capture()
            self.assertIs(caught.exception, interrupted)
            self.assertEqual(context.os.close.call_count, 4)
            value = json.loads(interrupted.dns_acquisition_partial_raw)
            self.assertIn("SOCKET_CLOSE_FAILED", value["cleanup_codes"])
            self.assertIn("INTERRUPTED", value["errors"])
            self.verify(interrupted.dns_acquisition_partial_raw)

    def test_detach_failure_retains_uncertain_object_and_never_closes_foreign_number(self):
        for failure in (OSError("detach unknown"), 999):
            with self.subTest(kind=type(failure).__name__), Harness() as h:
                if isinstance(failure, BaseException):
                    h.sock.detach.side_effect = failure
                else:
                    def wrong_detach():
                        h.detach()
                        return 999
                    h.sock.detach.side_effect = wrong_detach
                error = self.refused(h, "SOCKET_CLOSE_FAILED")
                self.verify(error.partial_raw)
                self.assertFalse(json.loads(error.partial_raw)["socket_closed"])
                h.sock.detach.assert_called_once()
                h.sock.close.assert_not_called()
                self.assertNotIn(40, [call.args[0] for call in context.os.close.call_args_list])
                self.assertNotIn(999, [call.args[0] for call in context.os.close.call_args_list])

    def test_replay_error_rows_require_terminal_refusal_even_with_unknown_counts(self):
        bad = dict(sequence=0, call_started_ns=30, call_finished_ns=31, call_flags=64, outcome="ERROR", errno=4,
                   peer_host=None, peer_port=None, raw_hex=None, returned_bytes=None, receive_flags=None, ancillary=None)
        normal = fixture_record()
        normal["receives"] = [bad]
        normal["counters"]["receive_errors"] = 1
        with self.assertRaises(ValueError):
            self.verify(normal)
        normal["status"] = "REFUSED"
        normal["sample"]["terminal"] = "REFUSED"
        normal["errors"] = ["RECEIVE_FAILED"]
        self.verify(normal)
        later = deepcopy(fixture_record(True)["receives"][0])
        later.update(sequence=1, call_started_ns=40, call_finished_ns=41, raw_hex=b"x".hex(), returned_bytes=1)
        normal["receives"].append(later)
        normal["counters"]["received_datagrams"] = 1
        for unknown in (False, True):
            with self.subTest(unknown=unknown):
                forged = deepcopy(normal)
                if unknown:
                    for key in ("received_datagrams", "observer_drops", "receive_errors", "truncated_datagrams", "would_block_calls"):
                        forged["counters"][key] = None
                with self.assertRaises(ValueError):
                    self.verify(forged)

    def test_replay_every_fatal_datagram_and_send_forbids_later_io(self):
        for kind, code in (("trunc", "DATAGRAM_TRUNCATED"), ("flags", "RECEIVE_FLAGS_REFUSED"),
                           ("controls", "ANCILLARY_REFUSED"), ("peer", "PEER_REFUSED"), ("replay", "READINESS_REPLAY")):
            with self.subTest(kind=kind):
                value = fixture_record(True)
                last = deepcopy(value["receives"][0])
                last.update(sequence=1, call_started_ns=40, call_finished_ns=41)
                if kind != "replay":
                    last.update(raw_hex=b"x".hex(), returned_bytes=1)
                if kind == "trunc":
                    last["receive_flags"] = 32
                    value["counters"]["truncated_datagrams"] = 1
                elif kind == "flags":
                    last["receive_flags"] = 1
                elif kind == "controls":
                    last["ancillary"] = [dict(level=1, type=9, raw_hex="00")]
                elif kind == "peer":
                    last["peer_host"] = "192.0.2.1"
                value["receives"].append(last)
                value["counters"]["received_datagrams"] = 2
                value["status"] = "REFUSED"
                value["sample"]["terminal"] = "REFUSED"
                value["errors"] = [code]
                self.assertTrue(self.verify(value)["readiness_response_recorded"])
                more = deepcopy(fixture_record(True)["receives"][0])
                more.update(sequence=2, call_started_ns=50, call_finished_ns=51, raw_hex="", returned_bytes=0)
                value["receives"].append(more)
                value["counters"]["received_datagrams"] = 3
                with self.assertRaises(ValueError):
                    self.verify(value)
        failed = fixture_record(True)
        failed.update(status="REFUSED", errors=["READINESS_SEND_FAILED"])
        failed["sample"]["terminal"] = "REFUSED"
        failed["readiness_response"]["returned_bytes"] = 1
        self.assertFalse(self.verify(failed)["readiness_response_recorded"])
        later = deepcopy(failed["receives"][0])
        later.update(sequence=1, call_started_ns=40, call_finished_ns=41, raw_hex=b"ordinary".hex(), returned_bytes=8)
        failed["receives"].append(later)
        failed["counters"]["received_datagrams"] = 2
        with self.assertRaises(ValueError):
            self.verify(failed)
        legitimate = fixture_record(True)
        legitimate.update(status="REFUSED", errors=["RECEIVE_FAILED"])
        legitimate["sample"]["terminal"] = "REFUSED"
        legitimate["receives"].append(dict(sequence=1, call_started_ns=40, call_finished_ns=41, call_flags=64,
                                             outcome="ERROR", errno=4, peer_host=None, peer_port=None, raw_hex=None,
                                             returned_bytes=None, receive_flags=None, ancillary=None))
        legitimate["counters"]["receive_errors"] = 1
        self.assertTrue(self.verify(legitimate)["readiness_response_recorded"])

    def test_partial_known_chronology_and_all_cancellation_kinds_are_joined(self):
        value = fixture_record(True)
        value.update(status="REFUSED", errors=["FINAL_GUARD_FAILED"])
        value["sample"].update(terminal="REFUSED", finished_ns=2000000060)
        self.verify(value)  # Failure completion legitimately follows after snapshot.
        for code in (None, "CLOCK_CHANGED"):
            forged = deepcopy(value)
            forged["after"]["read_started_ns"] = 30  # Before the completed send.
            if code:
                forged["errors"].append(code)
            with self.subTest(clock_code=code), self.assertRaises(ValueError):
                self.verify(forged)
        for event, code in (("READ_ERROR", "CANCEL_READ_FAILED"), ("IDENTITY_CHANGE", "CANCEL_IDENTITY_CHANGED")):
            valid = deepcopy(value)
            valid["errors"] = [code]
            valid["cancellation"].update(event=event, observed_ns=40, read_errno=5 if event == "READ_ERROR" else None)
            self.verify(valid)
            valid["cancellation"]["observed_ns"] = 30
            with self.subTest(event=event), self.assertRaises(ValueError):
                self.verify(valid)
        unknown = deepcopy(value)
        unknown["errors"] = ["CLOCK_CHANGED"]
        unknown["readiness_response"]["call_finished_ns"] = None
        self.assertFalse(self.verify(unknown)["readiness_response_recorded"])

    def test_replay_cleanup_requires_matching_actual_close_identities_and_failure_code(self):
        early = fixture_record()
        early.update(status="REFUSED", before=None, after=None, socket_closed=False,
                     errors=["CANCEL_IDENTITY_CHANGED", "SOCKET_DROP_UNKNOWN"])
        early["sample"] = dict(started_ns=None, deadline_ns=None, finished_ns=None, terminal="NOT_STARTED")
        early["counters"].update(socket_drop_delta=None, socket_drop_state="UNKNOWN")
        for edge in ("identity_before", "identity_after"):
            early["cancellation"][edge]["inode"] = 71
        early["cancellation"].update(fd_link="pipe:[71]", event="IDENTITY_CHANGE", observed_ns=100)
        self.verify(early)  # Same actually owned wrong-input pipe was closed safely.
        for after in (None, {**early["cancellation"]["identity_after"], "inode": 72}):
            forged = deepcopy(early)
            forged["cancellation"]["identity_after"] = after
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.verify(forged)
        value = fixture_record()
        value.update(status="REFUSED", socket_closed=False, errors=["FINAL_GUARD_FAILED"])
        value["sample"]["terminal"] = "REFUSED"
        with self.assertRaises(ValueError):
            self.verify(value)
        value["cleanup_codes"] = ["SOCKET_CLOSE_FAILED"]
        self.verify(value)

    def test_kernel_flags_and_exact_socket_fd_override_cached_object_state(self):
        for variant in ("blocking", "inheritable", "number"):
            with self.subTest(variant=variant), Harness() as h:
                if variant == "blocking":
                    h.socket_flags = 2
                elif variant == "inheritable":
                    h.socket_descriptor_flags = 0
                else:
                    def changed_number():
                        h.sock.fileno.return_value = 41
                        raise OSError(errno.ENOTCONN, "unconnected")
                    h.sock.getpeername.side_effect = changed_number
                self.refused(h, "SOCKET_CHANGED")
                h.sock.bind.assert_not_called()
                h.sock.recvmsg.assert_not_called()
                h.sock.sendto.assert_not_called()
                if variant == "number":
                    self.assertNotIn(41, [call.args[0] for call in context.os.close.call_args_list])

    def test_late_empty_poll_namespace_and_readlink_mutations_stop_operations(self):
        for variant in ("empty-poll", "namespace", "socket-link"):
            with self.subTest(variant=variant), Harness() as h:
                armed = []
                original_poll = h.poll
                def poll():
                    result = original_poll()
                    original = result.poll
                    def invoke(timeout):
                        events = original(timeout)
                        if timeout == 0 and not armed:
                            armed.append(True)
                            if variant == "empty-poll":
                                h.fstat_mutation = lambda fd, old: metadata(1, 71, old.st_mode) if fd == 10 else old
                        return events
                    result.poll = invoke
                    return result
                context.select.poll.side_effect = poll
                if variant == "namespace":
                    h.cancel_ready = True
                def link(path, old):
                    target = "/proc/self/ns/time_for_children" if variant == "namespace" else "/proc/self/fd/40"
                    if armed and variant != "empty-poll" and path == target:
                        h.fstat_mutation = lambda fd, value: metadata(1, 71, value.st_mode) if fd == 10 else value
                    return old
                h.readlink_mutation = link
                error = self.refused(h, "CANCEL_IDENTITY_CHANGED")
                self.verify(error.partial_raw)
                context.os.read.assert_not_called()
                h.sock.bind.assert_not_called()
                h.sock.recvmsg.assert_not_called()
                h.sock.sendto.assert_not_called()
                self.assertNotIn(10, [call.args[0] for call in context.os.close.call_args_list])

    def test_close_readlink_mutation_gets_final_identity_check_and_no_foreign_close(self):
        for fd in (10, 40):
            with self.subTest(fd=fd), Harness() as h:
                def late_link(path, old):
                    if h.sock.fileno() == -1 and path == f"/proc/self/fd/{fd}":
                        h.fstat_mutation = lambda target, value: metadata(value.st_dev, value.st_ino + 1, value.st_mode) if target == fd else value
                    return old
                h.readlink_mutation = late_link
                error = self.refused(h, "CANCEL_CLOSE_FAILED" if fd == 10 else "SOCKET_CLOSE_FAILED")
                self.verify(error.partial_raw)
                self.assertNotIn(fd, [call.args[0] for call in context.os.close.call_args_list])

    def test_failed_detach_quarantine_survives_discard_and_poison_consumes_next_pipe(self):
        with Harness() as h:
            destroyed = []
            class TrackedSocket:
                def __getattr__(self, name):
                    return getattr(h.sock, name)
                def __del__(self):
                    destroyed.append(True)
            tracked = TrackedSocket()
            socket_ref = weakref.ref(tracked)
            context.socket.socket.return_value = tracked
            def unavailable_detach():
                raise OSError("detach unavailable")  # Fresh error; Mock retains no traceback root.
            h.sock.detach.side_effect = unavailable_detach
            error = self.refused(h, "SOCKET_CLOSE_FAILED")
            self.verify(error.partial_raw)
            quarantined = weakref.ref(context._QUARANTINED_OWNER)
            context.socket.socket.return_value = None
            del tracked, error
            gc.collect()
            self.assertIsNotNone(quarantined())
            self.assertIsNotNone(socket_ref())
            self.assertEqual(destroyed, [])
            self.assertIsNone(context._ACTIVE_OWNER)
            h.request["cancellation_identity"]["inode"] = 71
            refused = self.refused(h, "SOCKET_CHANGED", cancel_fd=11)
            self.verify(refused.partial_raw, h.request)
            context.os.close.assert_any_call(11)
            context.socket.socket.assert_called_once()
            self.assertIs(context._QUARANTINED_OWNER, quarantined())
            h.sock.detach.assert_called_once()
            h.sock.close.assert_not_called()
            self.assertEqual(destroyed, [])

    def test_first_unresponded_query_is_terminal_without_inventing_send(self):
        value = fixture_record(True)
        value.update(status="REFUSED", readiness_response=None, errors=["FINAL_GUARD_FAILED"])
        value["sample"]["terminal"] = "REFUSED"
        self.assertFalse(self.verify(value)["readiness_response_recorded"])
        later = deepcopy(value["receives"][0])
        later.update(sequence=1, call_started_ns=40, call_finished_ns=41, raw_hex=b"ordinary".hex(), returned_bytes=8)
        value["receives"].append(later)
        value["counters"]["received_datagrams"] = 2
        with self.assertRaises(ValueError):
            self.verify(value)

    def test_known_partial_starts_join_sample_finish_and_empty_after_boundary(self):
        empty = fixture_record()
        empty.update(status="REFUSED", errors=["FINAL_GUARD_FAILED"])
        empty["sample"]["terminal"] = "REFUSED"
        empty["after"].update(read_started_ns=11, read_finished_ns=12)
        with self.assertRaises(ValueError):
            self.verify(empty)
        for operation in ("receive", "send"):
            value = fixture_record(True)
            value.update(status="REFUSED", errors=["CLOCK_CHANGED"])
            value["sample"]["terminal"] = "REFUSED"
            if operation == "receive":
                value["readiness_response"] = None
                value["receives"][0].update(raw_hex=b"x".hex(), returned_bytes=1, call_started_ns=50, call_finished_ns=None)
                value["sample"]["finished_ns"] = 40
            else:
                value["readiness_response"]["call_finished_ns"] = None
                value["sample"]["finished_ns"] = 31
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.verify(value)
        partial = fixture_record(True)
        partial.update(status="REFUSED", errors=["CLOCK_CHANGED"])
        partial["sample"]["terminal"] = "REFUSED"
        partial["readiness_response"]["call_started_ns"] = None
        self.assertFalse(self.verify(partial)["readiness_response_recorded"])

    def test_clock_partial_snapshot_available_boundaries_are_ordered(self):
        value = fixture_record()
        value.update(status="REFUSED", errors=["CLOCK_CHANGED"])
        value["sample"] = dict(started_ns=None, deadline_ns=None, finished_ns=None, terminal="NOT_STARTED")
        value["before"].update(read_started_ns=100, read_finished_ns=None)
        for after_finish in (120, None):
            with self.subTest(after_finish=after_finish):
                value["after"].update(read_started_ns=110, read_finished_ns=after_finish)
                self.assertEqual(self.verify(value)["record_status"], "REFUSED")
                value["after"]["read_started_ns"] = 100
                self.assertEqual(self.verify(value)["record_status"], "REFUSED")
                value["after"]["read_started_ns"] = 99
                with self.assertRaises(ValueError):
                    self.verify(value)

    def test_send_and_cancel_read_exhaustion_replay_recoverable_original_partials(self):
        for operation in ("send", "cancel"):
            with self.subTest(operation=operation), Harness() as h:
                original = MemoryError()
                if operation == "send":
                    h.receives = [(probe(), [], 0, ("127.0.0.1", 53000))]
                    h.send_result = original
                else:
                    h.cancel_ready = True
                    h.cancel_result = original
                h.fixture_note = "HTTP_FIXTURE_DESCRIPTOR_CLOSE_FAILED"
                context.os.close.side_effect = OSError("close uncertain")
                with self.assertRaises(MemoryError) as caught:
                    h.capture()
                self.assertIs(caught.exception, original)
                result = self.verify(original.dns_acquisition_partial_raw)
                self.assertEqual(result["record_status"], "REFUSED")
                self.assertFalse(result["readiness_response_recorded"])
                self.assertIn("FIXTURE_CLOSE_FAILED", original.dns_acquisition_cleanup_codes)
                value = json.loads(original.dns_acquisition_partial_raw)
                self.assertIn("EVIDENCE_LIMIT", value["errors"])
                if operation == "send":
                    h.sock.sendto.assert_called_once()
                    h.sock.recvmsg.assert_called_once()
                    self.assertIsNone(value["readiness_response"]["returned_bytes"])
                else:
                    context.os.read.assert_called_once_with(10, 1)
                    h.sock.recvmsg.assert_not_called()
                    h.sock.sendto.assert_not_called()
                    self.assertEqual(value["cancellation"]["event"], "READ_ERROR")
        bad = fixture_record(True)
        bad.update(status="REFUSED", errors=["EVIDENCE_LIMIT"])
        bad["sample"]["terminal"] = "REFUSED"
        bad["readiness_response"]["returned_bytes"] = 1
        with self.assertRaises(ValueError):
            self.verify(bad)

    def test_entry_owner_change_skips_detach_and_numeric_closes(self):
        for kind in ("pid", "thread", "uid", "gid"):
            with self.subTest(kind=kind), Harness() as h:
                def change():
                    if kind == "pid":
                        context.os.getpid.return_value = 5001
                    elif kind == "thread":
                        context.threading.get_native_id.return_value = 5001
                    elif kind == "uid":
                        context.os.getresuid.return_value = (0, 1, 0)
                    else:
                        context.os.getresgid.return_value = (0, 0, 1)
                    return [(40, select.POLLIN)]
                h.poll_actions = [change]
                error = self.refused(h, "PROCESS_CHANGED")
                self.verify(error.partial_raw)
                context.os.close.assert_not_called()
                h.sock.detach.assert_not_called()
                self.assertIs(context._QUARANTINED_OWNER.sock, h.sock)
                self.assertIn("CANCEL_CLOSE_FAILED", error.cleanup_codes)
                h.sock.recvmsg.assert_not_called()
        with Harness() as h:
            def changed_owner_link(path, value):
                if path == "/proc/self/fd/40":
                    context.os.getresgid.return_value = (0, 0, 1)
                return value
            h.readlink_mutation = changed_owner_link
            self.refused(h, "PROCESS_CHANGED")
            h.sock.bind.assert_not_called()
            h.sock.detach.assert_not_called()
            context.os.close.assert_not_called()

    def test_owner_change_during_terminal_cleanup_or_close_readback_skips_closes(self):
        for where in ("entry", "link"):
            with self.subTest(where=where), Harness() as h:
                if where == "entry":
                    original = context._Session.cleanup
                    def cleanup(owner):
                        if owner.bound and owner.active:
                            context.threading.get_native_id.return_value = 5001
                        return original(owner)
                    h.stack.enter_context(patch.object(context._Session, "cleanup", cleanup))
                else:
                    def link(path, value):
                        if h.sock.fileno() == -1 and path == "/proc/self/fd/40":
                            context.os.getresuid.return_value = (0, 1, 0)
                        return value
                    h.readlink_mutation = link
                error = self.refused(h, "PROCESS_CHANGED")
                self.verify(error.partial_raw)
                context.os.close.assert_not_called()
                if where == "entry":
                    h.sock.detach.assert_not_called()
                    self.assertIs(context._QUARANTINED_OWNER.sock, h.sock)
                else:
                    h.sock.detach.assert_called_once()
                    self.assertEqual(h.sock.fileno(), -1)

    def test_flags_changed_during_pipe_link_are_checked_before_read_and_close(self):
        for at_close in (False, True):
            with self.subTest(at_close=at_close), Harness() as h:
                if not at_close:
                    h.cancel_ready = True
                changed = []
                def link(path, value):
                    if path == "/proc/self/fd/10" and not changed and (not at_close or h.sock.fileno() == -1):
                        changed.append(True)
                        h.cancel_flags = 2049
                    return value
                h.readlink_mutation = link
                error = self.refused(h, "CANCEL_IDENTITY_CHANGED")
                self.verify(error.partial_raw)
                self.assertEqual(changed, [True])
                context.os.read.assert_not_called()
                self.assertNotIn(10, [call.args[0] for call in context.os.close.call_args_list])

    def test_operation_guard_exhausting_original_deadline_prevents_recv_and_send(self):
        for operation in ("receive", "send"):
            with self.subTest(operation=operation), Harness() as h:
                armed = []
                def ready():
                    armed.append(True)
                    return [(40, select.POLLIN)]
                h.poll_actions = [ready]
                h.receives = [(probe(), [], 0, ("127.0.0.1", 53000))]
                original = context._Session.operation_guard
                expired = []
                def guard(owner):
                    original(owner)
                    has_row = bool(owner.record["receives"])
                    if armed and not expired and (operation == "receive" and not has_row or operation == "send" and has_row):
                        expired.append(True)
                        h.now = owner.record["sample"]["deadline_ns"] + 10
                with patch.object(context._Session, "operation_guard", guard):
                    if operation == "receive":
                        raw = h.capture()
                        self.verify(raw)
                        self.assertEqual(json.loads(raw)["sample"]["terminal"], "DEADLINE")
                        h.sock.recvmsg.assert_not_called()
                    else:
                        error = self.refused(h, "READINESS_SEND_FAILED")
                        self.verify(error.partial_raw)
                        h.sock.recvmsg.assert_called_once()
                self.assertEqual(expired, [True])
                h.sock.sendto.assert_not_called()
