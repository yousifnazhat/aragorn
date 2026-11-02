"""Fabricated OS/socket model through the real public acquisition and replay APIs."""
import base64
from collections import Counter
from contextlib import ExitStack
import copy
import hashlib
import json
import posixpath
import socket
import stat
import struct
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import native_phase3_broker_reader_context as context


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def pin(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


ROOT_PID, BROKER_PID, BASE = 2000, 3000, 1000000000
PATHS = ("/", "/var", "/var/lib", "/var/lib/aragorn-runtime-action", "/var/lib/aragorn-runtime-action/control")
FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized", "run_qualified",
         "phase3_qualified", "request_receipt_authenticity_verified", "installed_sources_verified")


def info(inode, mode, uid=0, gid=0, size=0, device=1, links=1):
    return SimpleNamespace(st_dev=device, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid,
                           st_nlink=links, st_size=size, st_mtime_ns=100, st_ctime_ns=101)


class Inputs:
    def __init__(self):
        boot = "12345678-1234-1234-1234-123456789abc"
        self.broker = {"pid": BROKER_PID, "start_time_ticks": 301, "uid": 991, "gid": 992}
        self.provider = {"pid": ROOT_PID, "start_time_ticks": 201, "uid": 0, "gid": 0}
        self.clock = {"boot_id": boot, "clock_id": "CLOCK_BOOTTIME", "time_namespace": {"device": 99, "inode": 500}}
        self.fixture = {"schema": "aragorn/runtime-http-fixture-binding/v1",
                        "fixture": {"container_id": "f" * 64, "boot_id": boot, "netns_device": 99, "netns_inode": 900},
                        "expected_broker_uid": 991, "expected_broker_gid": 992}
        sources = {"runtime_http_broker.py": pin(b"inert expected broker source"),
                   "runtime_http_run_submission.py": pin(b"inert expected journal source")}
        keys = ("deployment_identity_digest", "measurement_schedule_digest", "collection_commitment_digest",
                "scheduled_measurement_request_digest", "grant_digest", "runtime_profile_digest", "sensor_digest",
                "runtime_digest", "policy_digest", "active_skill_digest")
        self.plan = {"schema": "aragorn/runtime-broker-decision-measurement-binding/v1", "boot_id": boot,
                     "attempt_id": "p3-lab-a001", "source_pins": sources,
                     **{key: pin(key.encode()) for key in keys}}
        body = b"p3canary-p3-lab-a001"
        wire = (b"POST /aragorn-phase3-canary HTTP/1.1\r\nHost: 127.0.0.1:47631\r\nConnection: close\r\n"
                b"Content-Type: application/octet-stream\r\nContent-Length: 20\r\n\r\n" + body)
        endpoint = {"schema": "aragorn/runtime-http-endpoint/v1", "fixture_binding_digest": pin(raw(self.fixture)),
                    "fixture": self.fixture["fixture"], "host": "127.0.0.1", "port": 47631,
                    "method": "POST", "path": "/aragorn-phase3-canary"}
        self.plan.update(operation_digest=pin(raw({"schema": "aragorn/runtime-http-operation/v1", "operation": "http_canary_post"})),
                         path_digest=pin(raw(endpoint)), payload_digest=pin(wire))
        self.expectation = {
            "schema": "aragorn/native-phase3-broker-reader-context-expectation/v1", "broker": self.broker,
            "provider": self.provider, "clock": self.clock, "grant_digest": self.plan["grant_digest"],
            "deployment_digest": self.plan["deployment_identity_digest"], "epoch_digest": pin(b"protected epoch"),
            "measurement_binding_digest": pin(raw(self.plan)), "fixture_binding_digest": pin(raw(self.fixture)),
            "broker_source_pins": sources,
            "directories": [{"path": path, "device": 1, "inode": i + 1,
                             "mode": stat.S_IFDIR | (0o700 if i == 4 else 0o755),
                             "uid": 991 if i == 4 else 0, "gid": 992 if i == 4 else 0}
                            for i, path in enumerate(PATHS)],
            "session_deadline_ns": BASE + 300000000,
        }
        effect = {"schema": "aragorn/runtime-http-canary-effect/v1", "operation": "http_canary_post", "attempt_id": "p3-lab-a001"}
        self.retained_context = {
            "schema": "aragorn/native-phase3-broker-reader-context/v1", "request_digest": pin(b"actual action request"),
            "effect_digest": pin(raw(effect)), "grant_digest": self.expectation["grant_digest"],
            "deployment_digest": self.expectation["deployment_digest"], "epoch_digest": self.expectation["epoch_digest"],
            "broker": self.broker, "provider": self.provider, "clock": self.clock, "exchange_id": "e" * 64,
            "accepted_boottime_ns": BASE - 100, "deadline_boottime_ns": BASE - 90 + 400000000,
            "clock_bracket": {"boottime_before_ns": BASE - 90, "boottime_after_ns": BASE - 80,
                              "monotonic_ns": 500000000, "original_monotonic_deadline_ns": 900000000},
        }
        self.bound = {"schema": "aragorn/native-phase3-broker-submission-event/v1", "context_digest": None,
                      "sequence": 0, "previous_digest": None, "phase": "BOUND", "checked_ns": BASE - 70,
                      "request_packet_digest": None, "response_packet_digest": None, "transport_digest": None,
                      "failure_code": None, "intent": False, "effect_possible": False}
        self.pending = {
            "schema": "aragorn/runtime-broker-decision-measurement-pending/v1", "binding": self.plan,
            "process": {**self.broker, "boot_id": boot, "mount_namespace": "mnt:[700]"},
            "clock_id": "CLOCK_BOOTTIME", "acceptance_boundary": "V4_ISSUED_SUBMISSION_VALIDATED_BEFORE_GRANT_CLAIM",
            "accepted_boottime_ns": BASE - 100, "action_request_digest": self.retained_context["request_digest"],
            "submission_digest": pin(b"actual submission"), "lease_digest": pin(b"actual lease"),
            "runtime_attribution_digest": pin(b"actual attribution"),
        }

    def arguments(self):
        self.expectation["measurement_binding_digest"] = pin(raw(self.plan))
        self.expectation["fixture_binding_digest"] = pin(raw(self.fixture))
        self.bound["context_digest"] = pin(raw(self.retained_context))
        request = {"schema": "aragorn/native-phase3-broker-reader-request/v1", "phase": "BEFORE_CONNECT",
                   "context_digest": pin(raw(self.retained_context)), "previous_response_digest": None,
                   **{key: self.retained_context[key] for key in ("request_digest", "effect_digest", "epoch_digest", "exchange_id", "deadline_boottime_ns")}}
        return {"expectation_raw": raw(self.expectation), "expected_expectation_digest": pin(raw(self.expectation)),
                "measurement_binding_raw": raw(self.plan), "expected_measurement_binding_digest": pin(raw(self.plan)),
                "fixture_binding_raw": raw(self.fixture), "expected_fixture_binding_digest": pin(raw(self.fixture)),
                "request_raw": raw(request), "request_received_ns": BASE - 60}


class BorrowedSocket:
    family = socket.AF_UNIX

    def __init__(self, model):
        self.model = model
        self.descriptor = 3
        self.timeout = 0.0
        self.sotype = socket.SOCK_SEQPACKET
        self.passcred, self.passpidfd = 1, 0
        self.credentials = struct.pack("=iII", BROKER_PID, 991, 992)

    def fileno(self):
        return self.descriptor

    def gettimeout(self):
        return self.timeout

    def getsockopt(self, level, option, *args):
        self.model.event("getsockopt", option)
        if option == 77:
            self.model.pidfd = self.model.allocate("pidfd", "pidfd")
            return self.model.pidfd
        return {socket.SO_TYPE: self.sotype, 16: self.passcred, 76: self.passpidfd, 17: self.credentials}[option]

    def __getattr__(self, name):
        if name in ("close", "detach", "dup", "send", "sendmsg", "recv", "recvmsg", "shutdown", "setsockopt", "settimeout", "setblocking"):
            raise AssertionError("borrowed socket operation forbidden: " + name)
        raise AttributeError(name)


class OSModel:
    def __init__(self, inputs):
        self.inputs = inputs
        self.calls = []
        self.hook = None
        self.meta = {}
        self.data = {}
        self.descriptors = {}
        self.next_fd = 20
        self.pidfd = None
        self.pidfd_raw = f"pos:\t0\nflags:\t02000002\nPid:\t{BROKER_PID}\nNSpid:\t{BROKER_PID}\n".encode()
        self.ready = []
        self.tick = BASE
        self.step = 1000
        self.chunk = 16384
        self.close_counts = Counter()
        self.read_counts = Counter()
        self.close_fail_path = None
        self.close_error = OSError("modeled ambiguous close")
        self.view_overrides = {}
        self.fd_overrides = {}
        self.record_paths = {}
        self.socket = BorrowedSocket(self)
        self.meta["socket"] = info(800, stat.S_IFSOCK | 0o600)
        self.meta["pidfd"] = info(801, 0o600)
        self.descriptors[3] = {"path": "socket", "view": "root", "offset": 0, "inheritable": False, "closed": False,
                               "flags": context.os.O_RDWR | context.os.O_NONBLOCK}
        for row in inputs.expectation["directories"]:
            self.meta[row["path"]] = info(row["inode"], row["mode"], row["uid"], row["gid"], 4096, links=2)
        for pid, namespace, inode in ((ROOT_PID, "time", 500), (BROKER_PID, "time", 500), (BROKER_PID, "mnt", 700)):
            self.meta[f"/proc/{pid}/ns/{namespace}"] = info(inode, stat.S_IFREG | 0o444, device=99)
        self.data["/proc/sys/kernel/random/boot_id"] = (inputs.clock["boot_id"] + "\n").encode()
        for process in (inputs.provider, inputs.broker):
            pid = process["pid"]
            self.data[f"/proc/{pid}/stat"] = (f"{pid} (name (nested)) S " + " ".join(["0"] * 18 + [str(process["start_time_ticks"])]) + "\n").encode()
            self.data[f"/proc/{pid}/status"] = (f"Name:\tpython\nUid:\t{process['uid']}\t{process['uid']}\t{process['uid']}\t{process['uid']}\n"
                                                 f"Gid:\t{process['gid']}\t{process['gid']}\t{process['gid']}\t{process['gid']}\nGroups:\t992 1002\n").encode()

    def install_records(self):
        self.inputs.arguments()
        request_hex = self.inputs.retained_context["request_digest"][7:]
        names = (f"run-reader-{request_hex}-context.json", f"run-reader-{request_hex}-event-0.json", "decision-measurement-pending.json")
        for index, (role, name, value) in enumerate(zip(("CONTEXT", "BOUND", "PENDING"), names,
                                                      (self.inputs.retained_context, self.inputs.bound, self.inputs.pending))):
            path = PATHS[-1] + "/" + name
            self.record_paths[role] = path
            self.data[path] = raw(value)
            self.meta[path] = info(1000 + index, stat.S_IFREG | 0o400, 991, 992, len(self.data[path]))

    def event(self, operation, path):
        self.calls.append((operation, path))
        if self.hook is not None:
            self.hook(operation, path)

    def allocate(self, path, view, flags=None):
        fd = self.next_fd; self.next_fd += 1
        self.descriptors[fd] = {"path": path, "view": view, "offset": 0, "inheritable": False, "closed": False,
                                "flags": context.os.O_RDONLY if flags is None else flags}
        return fd

    def resolve(self, path, dir_fd=None):
        if path == f"/proc/{BROKER_PID}/root":
            return "/", "broker"
        if dir_fd is not None:
            entry = self.descriptors[dir_fd]
            return posixpath.join(entry["path"], path), entry["view"]
        return path, "root"

    def open(self, path, flags, dir_fd=None):
        path, view = self.resolve(path, dir_fd)
        self.event("open", (path, view))
        if flags & (context.os.O_CREAT | context.os.O_TRUNC | context.os.O_WRONLY | context.os.O_RDWR):
            raise AssertionError("write/open effect forbidden")
        if path.endswith("broker.lock"):
            raise AssertionError("lock acquisition forbidden")
        if path not in self.meta:
            if path in self.data or path.startswith("/proc/self/fdinfo/"):
                self.meta[path] = info(5000 + len(self.meta), stat.S_IFREG | 0o444)
            else:
                raise FileNotFoundError(path)
        return self.allocate(path, view, flags)

    def fstat(self, fd):
        self.event("fstat", fd)
        entry = self.descriptors[fd]
        if entry["closed"]:
            raise OSError("closed descriptor")
        return copy.copy(self.fd_overrides.get(fd, self.view_overrides.get((entry["view"], entry["path"]), self.meta[entry["path"]])))

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        path, view = self.resolve(path, dir_fd)
        self.event("stat", (path, view))
        return copy.copy(self.view_overrides.get((view, path), self.meta[path]))

    def readlink(self, path):
        self.event("readlink", path)
        label = path.rsplit("/", 1)[-1]
        return f"{label}:[{self.meta[path].st_ino}]"

    def fcntl(self, fd, command):
        self.event("fcntl", (fd, command))
        entry = self.descriptors[fd]
        if command == context.fcntl.F_GETFD:
            return 0 if entry["inheritable"] else context.fcntl.FD_CLOEXEC
        if command == context.fcntl.F_GETFL:
            return entry["flags"]
        raise AssertionError("descriptor reconfiguration forbidden")

    def inheritable(self, fd):
        return self.descriptors[fd]["inheritable"]

    def lseek(self, fd, offset, whence):
        self.event("lseek", fd)
        if offset != 0 or whence != context.os.SEEK_SET:
            raise AssertionError("unexpected seek")
        self.descriptors[fd]["offset"] = 0
        return 0

    def read(self, fd, maximum):
        self.read_counts[fd] += 1
        entry = self.descriptors[fd]
        path = entry["path"]
        self.event("read", path)
        data = self.pidfd_raw if path.startswith("/proc/self/fdinfo/") else self.data[path]
        start = entry["offset"]
        value = data[start:start + min(maximum, self.chunk)]
        entry["offset"] += len(value)
        return value

    def close(self, fd):
        self.event("close", fd)
        if fd == 3:
            raise AssertionError("borrowed descriptor closed")
        self.close_counts[fd] += 1
        if self.close_counts[fd] != 1:
            raise AssertionError("ambiguous close retried")
        entry = self.descriptors[fd]
        entry["closed"] = True
        if entry["path"] == self.close_fail_path:
            raise self.close_error

    def poll(self):
        model = self
        class Poll:
            def register(self, fd, flags):
                model.event("poll-register", fd)
                if fd != model.pidfd:
                    raise AssertionError("wrong PIDFD")
            def poll(self, timeout):
                model.event("poll", timeout)
                if timeout != 0:
                    raise AssertionError("blocking poll")
                return list(model.ready)
        return Poll()

    def clock_ns(self, clock_id):
        self.event("clock", clock_id)
        value = self.tick; self.tick += self.step
        return value


class BrokerContextTests(unittest.TestCase):
    def setUp(self):
        self.inputs = Inputs()
        self.model = OSModel(self.inputs)
        self.model.install_records()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(context, "_IMPORT_PID", ROOT_PID))
        self.stack.enter_context(mock.patch.object(context, "_ATTEMPTED", False))
        self.stack.enter_context(mock.patch.object(context.sys, "platform", "linux"))
        self.stack.enter_context(mock.patch.object(context.sys, "byteorder", "little"))
        for target, name, value in ((context.os, "getpid", lambda: ROOT_PID),
                                     (context.os, "getresuid", lambda: (0, 0, 0)),
                                     (context.os, "getresgid", lambda: (0, 0, 0)),
                                     (context.threading, "get_native_id", lambda: ROOT_PID)):
            self.stack.enter_context(mock.patch.object(target, name, value, create=True))
        for name in ("open", "fstat", "stat", "readlink", "lseek", "read", "close"):
            self.stack.enter_context(mock.patch.object(context.os, name, getattr(self.model, name)))
        self.stack.enter_context(mock.patch.object(context.os, "get_inheritable", self.model.inheritable))
        self.stack.enter_context(mock.patch.object(context.fcntl, "fcntl", self.model.fcntl))
        self.stack.enter_context(mock.patch.object(context.select, "poll", self.model.poll, create=True))
        self.stack.enter_context(mock.patch.object(context.time, "CLOCK_BOOTTIME", 7, create=True))
        self.stack.enter_context(mock.patch.object(context.time, "clock_gettime_ns", self.model.clock_ns))

    def call(self, **changes):
        arguments = self.inputs.arguments(); arguments.update(changes)
        return context.acquire_broker_reader_context(self.model.socket, **arguments)

    def refuse(self, **changes):
        with self.assertRaises(context.BrokerReaderContextError) as caught:
            self.call(**changes)
        self.assertIsInstance(caught.exception.original_failure, BaseException)
        self.assertEqual(set(caught.exception.observed), {"request_raw", "caller_request_received_ns", "started_ns", "deadline_ns",
                                                       "context_raw", "bound_raw", "pending_raw", "submission_verification_raw", "custody_before", "custody_after"})
        self.assertFalse(self.model.descriptors[3]["closed"])
        return caught.exception

    def refresh_files(self):
        self.model.install_records()

    def test_actual_prefix_and_exact_unknown_false_results(self):
        result = self.call()
        self.assertEqual(set(result), {"context_raw", "context_digest", "bound_raw", "pending_raw", "submission_verification_raw", "acquisition_raw", "acquisition_digest", "custody_raw"})
        self.assertEqual(result["context_raw"], self.model.data[self.model.record_paths["CONTEXT"]])
        self.assertEqual(result["bound_raw"], self.model.data[self.model.record_paths["BOUND"]])
        self.assertEqual(result["pending_raw"], self.model.data[self.model.record_paths["PENDING"]])
        acquired = json.loads(result["acquisition_raw"])
        self.assertEqual(acquired["status"], "ACQUIRED_BROKER_CONTEXT_PREFIX")
        self.assertEqual(acquired["submission_state"], "UNKNOWN")
        self.assertTrue(all(acquired[key] is False for key in FLAGS))
        self.assertEqual(result["acquisition_digest"], pin(result["acquisition_raw"]))
        self.assertEqual(acquired["custody_digest"], pin(result["custody_raw"]))
        self.assertEqual(acquired["pending_digest"], pin(result["pending_raw"]))
        custody = json.loads(result["custody_raw"])
        before, after = custody["before"], custody["after"]
        self.assertLessEqual(before["finished_ns"], after["started_ns"])
        self.assertLessEqual(after["finished_ns"], acquired["finished_ns"])
        self.assertLess(acquired["finished_ns"], acquired["deadline_ns"])
        for edge in (before, after):
            self.assertEqual(edge["broker_mount_namespace"], {"device": 99, "inode": 700, "link": "mnt:[700]"})
            self.assertEqual(edge["root_directories"], edge["broker_directories"])
            self.assertEqual(struct.unpack("=iII", base64.b64decode(edge["peer_credentials_base64"])), (BROKER_PID, 991, 992))
        self.assertEqual(before["files"], after["files"])
        self.assertEqual(acquired["source_files"], after["files"])
        self.assertTrue(all(entry["closed"] for fd, entry in self.model.descriptors.items() if fd != 3))
        self.assertTrue(all(count == 1 for count in self.model.close_counts.values()))

    def test_public_replay_invoked_on_actual_read_bytes(self):
        with mock.patch.object(context, "verify_submission_transcript", wraps=context.verify_submission_transcript) as replay:
            result = self.call()
        replay.assert_called_once()
        args, kwargs = replay.call_args
        self.assertEqual(args, (result["context_raw"], [result["bound_raw"]], {}))
        self.assertEqual(kwargs["expected_context_digest"], pin(result["context_raw"]))
        self.assertIsNone(kwargs["expected_terminal_digest"])
        self.assertEqual(json.loads(result["submission_verification_raw"])["submission_state"], "UNKNOWN")

    def test_shared_runtime_gid_and_distinct_mount_view_are_supported(self):
        self.assertEqual(self.inputs.broker["gid"], 992)
        result = self.call()
        self.assertEqual(json.loads(result["acquisition_raw"])["broker"]["gid"], 992)
        self.assertTrue(any(op == "open" and value == ("/", "broker") for op, value in self.model.calls))

    def test_different_broker_control_view_refuses(self):
        self.model.view_overrides[("broker", PATHS[-1])] = info(9001, stat.S_IFDIR | 0o700, 991, 992, 4096)
        self.refuse()

    def test_different_broker_root_view_refuses_without_namespace_entry(self):
        self.model.view_overrides[("broker", "/")] = info(9002, stat.S_IFDIR | 0o755, size=4096)
        self.refuse()

    def test_wrong_peer_and_credential_abi(self):
        self.model.socket.credentials = struct.pack("=iII", BROKER_PID, 992, 992)
        self.refuse()

    def test_short_peer_credential_retains_prefix(self):
        self.model.socket.credentials = b"partial"
        error = self.refuse()
        self.assertEqual(base64.b64decode(error.observed["custody_before"]["peer_credentials_base64"]), b"partial")

    def test_pidfd_wrong_association_no_close_of_uncertain_fd(self):
        self.model.pidfd_raw = b"Pid:\t9999\n"
        error = self.refuse()
        self.assertNotIn(self.model.pidfd, self.model.close_counts)
        self.assertIn(self.model.pidfd, error.unresolved_owner.handles)

    def test_pidfd_liveness_event_refuses(self):
        self.model.ready = [(20, 1)]
        self.refuse()

    def test_pidfd_reuse_during_association_never_closes_foreign_fd(self):
        def changed(op, path):
            if op == "read" and path.startswith("/proc/self/fdinfo/"):
                self.model.fd_overrides[self.model.pidfd] = info(9900, 0o600)
        self.model.hook = changed
        error = self.refuse()
        self.assertNotIn(self.model.pidfd, self.model.close_counts)
        self.assertIn(self.model.pidfd, error.unresolved_owner.handles)

    def test_pidfd_alias_to_borrowed_descriptor_is_not_closed(self):
        original = self.model.socket.getsockopt
        with mock.patch.object(self.model.socket, "getsockopt", side_effect=lambda level, option, *args: 3 if option == 77 else original(level, option, *args)):
            self.refuse()
        self.assertEqual(self.model.close_counts[3], 0)

    def test_process_start_change_refuses_with_actual_raw(self):
        self.model.data[f"/proc/{BROKER_PID}/stat"] = (f"{BROKER_PID} (changed) S " + " ".join(["0"] * 18 + ["999"]) + "\n").encode()
        error = self.refuse()
        observed = error.observed["custody_before"]["processes"]["broker"]["stat_before_base64"]
        self.assertEqual(base64.b64decode(observed), self.model.data[f"/proc/{BROKER_PID}/stat"])

    def test_process_status_vectors_and_duplicate_accounts_refuse(self):
        self.model.data[f"/proc/{BROKER_PID}/status"] += b"Uid:\t991 991 991 991\n"
        self.refuse()

    def test_boot_change_refuses(self):
        self.model.data["/proc/sys/kernel/random/boot_id"] = b"87654321-1234-1234-1234-123456789abc\n"
        error = self.refuse()
        self.assertEqual(base64.b64decode(error.observed["custody_before"]["boot_base64"]), self.model.data["/proc/sys/kernel/random/boot_id"])

    def test_time_namespace_change_refuses(self):
        self.model.meta[f"/proc/{BROKER_PID}/ns/time"].st_ino = 501
        self.refuse()

    def test_mount_namespace_change_during_read_refuses(self):
        def changed(op, path):
            if op == "read" and path == self.model.record_paths["CONTEXT"]:
                self.model.meta[f"/proc/{BROKER_PID}/ns/mnt"].st_ino = 701
        self.model.hook = changed
        self.refuse()

    def test_foreign_thread_and_post_import_fork_reject_before_ownership(self):
        with mock.patch.object(context.threading, "get_native_id", return_value=ROOT_PID + 1):
            self.refuse()
        self.assertFalse(context._ATTEMPTED)
        with mock.patch.object(context.os, "getpid", return_value=ROOT_PID + 1):
            self.refuse()
        self.assertFalse(context._ATTEMPTED)
        self.assertFalse(self.model.calls)

    def test_nonroot_refuses_before_latch_or_descriptor_acquisition(self):
        with mock.patch.object(context.os, "getresuid", return_value=(0, 1, 0)):
            self.refuse()
        self.assertFalse(context._ATTEMPTED)
        self.assertFalse(self.model.calls)

    def test_reentry_does_not_touch_outer_owned_resources(self):
        nested = []
        def reentry(op, path):
            if op == "open" and not nested:
                nested.append(True)
                error = self.refuse()
                self.assertIsNotNone(error.original_failure)
        self.model.hook = reentry
        self.call()
        self.assertEqual(len(nested), 1)

    def test_failed_attempt_latch_forbids_recovery(self):
        self.refuse(expected_expectation_digest=pin(b"other"))
        calls = list(self.model.calls)
        self.refuse()
        self.assertEqual(self.model.calls, calls)

    def test_missing_control_record_refuses(self):
        path = self.model.record_paths["PENDING"]
        del self.model.meta[path]; del self.model.data[path]
        self.refuse()

    def test_partial_control_read_preserves_prefix_and_original_failure(self):
        self.model.chunk = 7
        failure = OSError("modeled read failure")
        path = self.model.record_paths["CONTEXT"]
        def broken(op, value):
            if op == "read" and value == path:
                if any(e["path"] == path and e["offset"] > 0 for e in self.model.descriptors.values()):
                    raise failure
        self.model.hook = broken
        error = self.refuse()
        self.assertIs(error.original_failure, failure)
        self.assertEqual(error.observed["context_raw"], self.model.data[path][:7])

    def test_linked_record_refuses(self):
        self.model.meta[self.model.record_paths["BOUND"]].st_nlink = 2
        self.refuse()

    def test_symlink_control_record_refuses(self):
        self.model.meta[self.model.record_paths["BOUND"]].st_mode = stat.S_IFLNK | 0o777
        self.refuse()

    def test_wrong_record_owner_refuses(self):
        self.model.meta[self.model.record_paths["PENDING"]].st_uid = 0
        self.refuse()

    def test_oversized_control_metadata_refuses_before_read(self):
        path = self.model.record_paths["CONTEXT"]
        self.model.meta[path].st_size = 8193
        self.refuse()
        self.assertNotIn(("read", path), self.model.calls)

    def test_short_eof_does_not_match_full_file_size(self):
        self.model.meta[self.model.record_paths["CONTEXT"]].st_size += 1
        error = self.refuse()
        self.assertIsNone(error.observed["submission_verification_raw"])

    def test_named_file_substitution_in_broker_view_refuses(self):
        path = self.model.record_paths["CONTEXT"]
        self.model.view_overrides[("broker", path)] = info(9009, stat.S_IFREG | 0o400, 991, 992, len(self.model.data[path]))
        self.refuse()

    def test_file_identity_change_during_reread_refuses_without_foreign_close(self):
        path = self.model.record_paths["CONTEXT"]
        reads = 0
        def changed(op, value):
            nonlocal reads
            if op == "lseek" and self.model.descriptors[value]["path"] == path:
                reads += 1
                if reads == 2:
                    self.model.meta[path].st_ino += 10
        self.model.hook = changed
        error = self.refuse()
        foreign = [fd for fd, e in self.model.descriptors.items() if e["path"] == path]
        self.assertTrue(foreign)
        self.assertTrue(all(fd not in self.model.close_counts for fd in foreign))
        self.assertTrue(error.cleanup_failures)

    def test_legitimate_directory_size_link_and_time_changes_are_ignored(self):
        def changed(op, path):
            if op == "read":
                value = self.model.meta[PATHS[-1]]
                value.st_mtime_ns += 1; value.st_ctime_ns += 1; value.st_size += 1; value.st_nlink += 1
        self.model.hook = changed
        result = self.call()
        custody = json.loads(result["custody_raw"])
        self.assertEqual(custody["before"]["root_directories"], custody["after"]["root_directories"])

    def test_control_files_cannot_alias_same_inode(self):
        self.model.meta[self.model.record_paths["BOUND"]].st_ino = self.model.meta[self.model.record_paths["CONTEXT"]].st_ino
        self.refuse()

    def test_acquired_metadata_failure_retains_unresolved_owner(self):
        seen = 0
        def broken(op, value):
            nonlocal seen
            if op == "fstat" and value == self.model.pidfd:
                seen += 1
                if seen == 1:
                    raise OSError("metadata unavailable after ownership")
        self.model.hook = broken
        error = self.refuse()
        self.assertIn(self.model.pidfd, error.unresolved_owner.handles)
        self.assertNotIn(self.model.pidfd, self.model.close_counts)

    def test_original_read_and_cleanup_failures_both_survive(self):
        path = self.model.record_paths["CONTEXT"]
        self.model.close_fail_path = path
        failure = KeyboardInterrupt("modeled interrupted read")
        def broken(op, value):
            if op == "read" and value == path:
                raise failure
        self.model.hook = broken
        error = self.refuse()
        self.assertIs(error.original_failure, failure)
        self.assertIn(self.model.close_error, error.cleanup_failures)

    def test_ambiguous_close_is_not_retried_and_no_success_returned(self):
        self.model.close_fail_path = self.model.record_paths["PENDING"]
        error = self.refuse()
        self.assertIn(self.model.close_error, error.cleanup_failures)
        self.assertTrue(all(count == 1 for count in self.model.close_counts.values()))
        self.assertTrue(error.unresolved_owner.handles)

    def test_borrowed_socket_replacement_is_preserved_not_closed(self):
        def changed(op, path):
            if op == "read" and path == self.model.record_paths["PENDING"]:
                self.model.meta["socket"].st_ino += 1
        self.model.hook = changed
        error = self.refuse()
        edge = error.observed["custody_after"] or error.observed["custody_before"]
        self.assertNotEqual(edge["socket"]["identity"]["inode"], 800)
        self.assertEqual(self.model.close_counts[3], 0)

    def test_socket_actual_flags_and_options_are_required(self):
        self.model.descriptors[3]["flags"] = context.os.O_RDWR
        self.refuse()

    def test_changed_borrowed_fileno_cannot_alias_owned_cleanup(self):
        def changed(op, path):
            if op == "read" and path == self.model.record_paths["PENDING"]:
                self.model.socket.descriptor = self.model.pidfd
        self.model.hook = changed
        error = self.refuse()
        self.assertNotIn(self.model.pidfd, self.model.close_counts)
        self.assertIn(self.model.pidfd, error.unresolved_owner.handles)

    def test_socket_passpidfd_must_already_be_disabled(self):
        self.model.socket.passpidfd = 1
        self.refuse()

    def test_wrong_fixture_binding_pin_refuses(self):
        self.refuse(expected_fixture_binding_digest=pin(b"other"))

    def test_duplicate_input_refuses_before_open(self):
        self.refuse(expectation_raw=b'{"x":1,"x":2}')
        self.assertFalse(any(op == "open" for op, _ in self.model.calls))

    def test_plan_payload_pin_cannot_replace_fixed_wire(self):
        self.inputs.plan["payload_digest"] = pin(b"wrong wire")
        self.refresh_files()
        self.refuse()

    def test_measurement_binding_above_predecessor_4096_is_supported(self):
        sources = {f"source_{i:03d}.py": pin(str(i).encode()) for i in range(45)}
        self.inputs.plan["source_pins"] = self.inputs.expectation["broker_source_pins"] = sources
        self.refresh_files()
        self.assertGreater(len(raw(self.inputs.plan)), 4096)
        self.assertLessEqual(len(raw(self.inputs.plan)), 8192)
        self.call()

    def test_pending_acceptance_boundary_refuses(self):
        self.inputs.pending["acceptance_boundary"] = "AFTER_GRANT_CLAIM"
        self.refresh_files(); self.refuse()

    def test_pending_request_cannot_use_scheduled_request_digest(self):
        self.inputs.pending["action_request_digest"] = self.inputs.plan["scheduled_measurement_request_digest"]
        self.refresh_files(); self.refuse()

    def test_pending_mount_process_join_refuses(self):
        self.inputs.pending["process"]["mount_namespace"] = "mnt:[999]"
        self.refresh_files(); self.refuse()

    def test_pending_plan_extra_or_changed_source_map_refuses(self):
        self.inputs.pending["binding"] = {**self.inputs.plan, "source_pins": {"other.py": pin(b"other")}}
        self.refresh_files(); self.refuse()

    def test_acquired_context_grant_cannot_replace_protected_grant(self):
        self.inputs.retained_context["grant_digest"] = pin(b"other grant")
        self.refresh_files(); self.refuse()

    def test_acquired_context_effect_cannot_replace_fixed_http_effect(self):
        self.inputs.retained_context["effect_digest"] = pin(b"other effect")
        self.refresh_files(); self.refuse()

    def test_bound_after_caller_receipt_refuses(self):
        self.inputs.bound["checked_ns"] = BASE - 59
        self.refresh_files(); self.refuse()

    def test_nonbound_prefix_refuses(self):
        self.inputs.bound["phase"] = "CONNECT_INTENT"
        self.refresh_files(); self.refuse()

    def test_actual_replay_disagreement_cannot_promote_health(self):
        promoted = {"status": "CONSISTENT_OPEN_PREFIX", "context_digest": pin(raw(self.inputs.retained_context)),
                    "last_event_digest": pin(raw(self.inputs.bound)), "submission_state": "UNKNOWN",
                    **dict.fromkeys(FLAGS[:5], False)}
        promoted["sensor_health_verified"] = True
        with mock.patch.object(context, "verify_submission_transcript", return_value=promoted):
            self.refuse()

    def test_expired_original_receipt_preserves_frozen_deadline(self):
        self.model.tick = BASE + 160000000
        error = self.refuse()
        self.assertEqual(error.observed["caller_request_received_ns"], BASE - 60)
        self.assertEqual(error.observed["deadline_ns"], BASE - 60 + 150000000)

    def test_receipt_budget_overflow_refuses_before_file_acquisition(self):
        self.model.tick = 2**63 - 100
        self.refuse(request_received_ns=2**63 - 200)
        self.assertFalse(any(op == "open" for op, _ in self.model.calls))

    def test_cleanup_crossing_deadline_cannot_return_success(self):
        def late(op, fd):
            if op == "close" and fd == self.model.pidfd:
                self.model.tick = BASE + 150000000
        self.model.hook = late
        error = self.refuse()
        self.assertIsNotNone(error.observed["custody_after"])
        self.assertTrue(all(entry["closed"] for fd, entry in self.model.descriptors.items() if fd != 3))

    def test_request_and_pending_raw_are_never_reconstructed(self):
        path = self.model.record_paths["PENDING"]
        self.model.data[path] += b"\n"
        self.model.meta[path].st_size += 1
        error = self.refuse()
        self.assertEqual(error.observed["pending_raw"], self.model.data[path])

    def late_close_change(self, change, pidfd=False):
        pending = self.model.record_paths["PENDING"]
        target_path = self.model.record_paths["CONTEXT"]
        state = {"closing": False, "polled": False, "flags": 0, "fired": False,
                 "owner_lost": False, "target": None}

        def hook(operation, value):
            if operation == "close" and self.model.descriptors[value]["path"] == pending:
                state["closing"] = True
            if operation == "poll" and state["closing"]:
                state["polled"] = True
            if operation != "fcntl" or not state["closing"] or state["fired"]:
                return
            fd, command = value
            if pidfd:
                if fd != self.model.pidfd or not state["polled"] or command != context.fcntl.F_GETFD:
                    return
                state["flags"] += 1
                if state["flags"] != 2:
                    return
            elif self.model.descriptors[fd]["path"] != target_path or command != context.fcntl.F_GETFL:
                return
            state["fired"], state["target"] = True, fd
            if change == "replace":
                old = self.model.fstat(fd)
                old.st_ino += 10000
                self.model.fd_overrides[fd] = old
            elif change == "owner":
                state["owner_lost"] = True
            else:
                self.model.socket.descriptor = fd

        self.model.hook = hook
        with mock.patch.object(context.os, "getpid", side_effect=lambda: ROOT_PID + state["owner_lost"]):
            error = self.refuse()
        self.assertTrue(state["fired"], "late final flag observation was not reached")
        self.assertEqual(self.model.close_counts[state["target"]], 0)
        self.assertIn(state["target"], error.unresolved_owner.handles)
        self.assertTrue(error.cleanup_failures)

    def test_final_close_flags_replacement_prevents_foreign_close(self):
        self.late_close_change("replace")

    def test_final_close_flags_owner_change_prevents_foreign_close(self):
        self.late_close_change("owner")

    def test_final_close_flags_new_borrowed_alias_prevents_close(self):
        self.late_close_change("borrow")

    def test_final_pidfd_flags_after_association_replacement_prevents_close(self):
        self.late_close_change("replace", pidfd=True)

    def test_final_pidfd_flags_after_association_owner_change_prevents_close(self):
        self.late_close_change("owner", pidfd=True)

    def test_final_pidfd_flags_after_association_new_borrowed_alias_prevents_close(self):
        self.late_close_change("borrow", pidfd=True)

    def late_read_change(self, boundary, change="replace"):
        path = self.model.record_paths["CONTEXT"]
        state = {"seeked": False, "fired": False, "owner_lost": False, "target": None}

        def mutate(fd):
            state["fired"], state["target"] = True, fd
            if change == "replace":
                old = self.model.fstat(fd)
                old.st_ino += 10000
                self.model.fd_overrides[fd] = old
            elif change == "owner":
                state["owner_lost"] = True
            else:
                self.model.socket.descriptor = fd

        def hook(operation, value):
            if state["fired"]:
                return
            if operation == "lseek" and self.model.descriptors[value]["path"] == path:
                state["seeked"], state["target"] = True, value
                if boundary == "seek":
                    mutate(value)
            elif operation == "clock" and state["seeked"] and boundary == "clock":
                mutate(state["target"])
            elif operation == "fcntl" and state["seeked"] and boundary == "flags":
                fd, command = value
                if fd == state["target"] and command == context.fcntl.F_GETFL:
                    mutate(fd)

        original_read = self.model.read
        def read(fd, maximum):
            value = original_read(fd, maximum)
            if boundary == "prior_read" and self.model.descriptors[fd]["path"] == path and value and not state["fired"]:
                mutate(fd)
            return value

        self.model.chunk = 7 if boundary == "prior_read" else 16384
        self.model.hook = hook
        with mock.patch.object(context.os, "read", side_effect=read), mock.patch.object(
            context.os, "getpid", side_effect=lambda: ROOT_PID + state["owner_lost"]
        ):
            error = self.refuse()
        self.assertTrue(state["fired"], "late pre-read observation was not reached")
        expected_reads = 1 if boundary == "prior_read" else 0
        self.assertEqual(self.model.read_counts[state["target"]], expected_reads)
        self.assertEqual(self.model.close_counts[state["target"]], 0)
        self.assertIn(state["target"], error.unresolved_owner.handles)
        if expected_reads:
            self.assertEqual(error.observed["context_raw"], self.model.data[path][:7])

    def test_lseek_substitution_prevents_first_foreign_read(self):
        self.late_read_change("seek")

    def test_timing_substitution_prevents_first_foreign_read(self):
        self.late_read_change("clock")

    def test_prior_read_substitution_preserves_prefix_without_another_read(self):
        self.late_read_change("prior_read")

    def test_final_read_flags_replacement_prevents_foreign_read(self):
        self.late_read_change("flags")

    def test_final_read_flags_owner_change_prevents_foreign_read(self):
        self.late_read_change("flags", "owner")

    def test_final_read_flags_new_borrowed_alias_prevents_read(self):
        self.late_read_change("flags", "borrow")


if __name__ == "__main__":
    unittest.main()
