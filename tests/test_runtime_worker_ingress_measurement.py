"""Inert filesystem/identity doubles, not native ingress or clock attestation.

Only temporary files are real. Linux, process/account/namespace readbacks and
clock readings are explicitly mocked. File ownership is a metadata double so
the same tests need neither root nor the deployed worker account.
"""

from __future__ import annotations

import base64
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import itertools
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import runtime_worker_ingress_measurement as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


PIN = "sha256:" + "1" * 64
BINDING = {
    "schema": "aragorn/runtime-action-worker-binding/v1",
    "runtime_digest": PIN,
    "active_skill_digest": PIN,
    "policy_digest": PIN,
    "policy_version": 1,
}
PEER = (77, 998, 998)


def documents():
    """Data-only exact create documents; no runtime or historical test invocation."""
    payload = b"inert test-only payload"
    request = {
        "schema": "aragorn/runtime-action-worker-request/v1",
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "target_name": "test-only.txt",
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "session_id": "inert-session",
        "run_id": "inert-run",
        "tool_call_digest": PIN,
    }
    event = {
        "schema": "aragorn/native-tool-attempt/v1",
        "authority": "AUTHENTICATED_GATEWAY_REPORT_ONLY_NOT_CAUSATION_EFFECT_OR_RUN_AUTHORITY",
        "tool_name": "aragorn_runtime_create",
        "session_id": request["session_id"],
        "run_id": request["run_id"],
        "tool_call_digest": PIN,
        "session_key_digest": PIN,
        "params_digest": PIN,
        "params_bytes": 19,
        "worker_request_digest": canonical_digest(request),
    }
    attempt = {
        "schema": "aragorn/native-tool-receipt/v1",
        "authority": "WORKER_LOCAL_DURABLE_RECEIPT_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
        "genesis_digest": PIN,
        "sequence": 1,
        "previous_digest": PIN,
        "event": event,
    }
    state = {
        "schema": "aragorn/native-tool-receipt-state/v1",
        "authority": attempt["authority"],
        "genesis_digest": PIN,
        "receipts": [canonical_digest(attempt)],
    }
    action = {
        "schema": "aragorn/runtime-action-request/v1",
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "runtime_digest": PIN,
        "session_id": request["session_id"],
        "run_id": request["run_id"],
        "tool_call_id": PIN,
        "active_skill_digest": PIN,
        "operation_digest": canonical_digest(
            {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
        ),
        "path_digest": PIN,
        "payload_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "policy_digest": PIN,
        "policy_version": 1,
        "issued_at_unix": 100,
        "expires_at_unix": 105,
    }
    return request, attempt, state, action


class InertStore:
    """Temporary data-only store with explicit fake kernel/ownership readbacks."""

    def __init__(self):
        self.stack = ExitStack()
        temporary = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.parent = Path(temporary).resolve()
        self.root = self.parent / "measurement"
        self.root.mkdir(mode=0o700)
        self.namespace_file = self.parent / "inert-namespace-fd"
        self.namespace_file.write_bytes(b"not a Linux namespace")
        self.identity = {
            "pid": 123,
            "start_time_ticks": 1234,
            "uid": 997,
            "gid": 997,
            "uids": [997] * 4,
            "gids": [997] * 4,
        }
        self.namespace = {"device": 5, "inode": 55}
        self.real_open, self.real_close = os.open, os.close
        self.real_write = os.write
        real_fstat, real_stat, real_lstat = os.fstat, os.stat, os.lstat

        def owned(info):
            values = {
                name: getattr(info, name)
                for name in dir(info)
                if name.startswith("st_")
            }
            return SimpleNamespace(**(values | {"st_uid": 997, "st_gid": 997}))

        def opened(path, flags, *args, **kwargs):
            if path == "/proc/123/ns/time":
                return self.real_open(self.namespace_file, flags)
            return self.real_open(path, flags, *args, **kwargs)

        self.patch(subject, "ROOT", self.root)
        self.patch(subject.sys, "platform", "linux")
        self.patch(subject.os, "getpid", return_value=123)
        self.patch(subject.os, "geteuid", return_value=997)
        self.patch(subject.os, "getegid", return_value=997)
        self.patch(subject.threading, "get_native_id", return_value=123)
        self.patch(subject.time, "CLOCK_BOOTTIME", 7, create=True)
        self.clock = self.patch(
            subject.time, "clock_gettime_ns", side_effect=itertools.count(1000)
        )
        self.patch(
            subject, "_self_identity", side_effect=lambda: deepcopy(self.identity)
        )
        self.patch(
            subject, "_namespace", side_effect=lambda _pid, _fd: dict(self.namespace)
        )
        self.patch(
            subject.broker,
            "_open_protected_directory",
            side_effect=lambda path, _uid, _label: self.real_open(
                path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            ),
        )
        self.patch(subject.broker, "_require_protected_ancestry", return_value=None)
        self.patch(subject.os, "open", side_effect=opened)
        self.patch(subject.os, "fstat", side_effect=lambda fd: owned(real_fstat(fd)))
        self.patch(
            subject.os,
            "stat",
            side_effect=lambda *args, **kwargs: owned(real_stat(*args, **kwargs)),
        )
        self.patch(
            subject.os,
            "lstat",
            side_effect=lambda *args, **kwargs: owned(real_lstat(*args, **kwargs)),
        )
        self.store = None

    def patch(self, owner, name, *args, **kwargs):
        return self.stack.enter_context(patch.object(owner, name, *args, **kwargs))

    def open(self, binding=None):
        value = subject.NativeWorkerIngress(
            expected_worker_uid=997,
            expected_worker_gid=997,
            binding=deepcopy(BINDING) if binding is None else binding,
        )
        self.store = value
        return value

    def read(self, stage):
        return json.loads((self.root / (stage + ".json")).read_bytes())

    def close(self):
        try:
            if self.store is not None:
                self.store.close()
        finally:
            self.stack.close()


class WorkerIngressMeasurementTests(unittest.TestCase):
    def fixture(self):
        fixture = InertStore()
        self.addCleanup(fixture.close)
        return fixture

    def test_four_records_hashlink_actual_documents_with_all_proof_flags_false(self):
        fixture = self.fixture()
        store = fixture.open()
        request, attempt, state, action = documents()
        trace = store.begin(request, PEER)
        store.bind_attempt(trace, attempt, state, PIN)
        store.bind_action(trace, action)
        previous = None
        for offset, stage in enumerate(subject.STAGES):
            raw = (fixture.root / (stage + ".json")).read_bytes()
            value = json.loads(raw)
            self.assertEqual(canonical_json(value), raw)
            self.assertEqual(value["previous_digest"], previous)
            self.assertEqual(value["boottime_ns"], 1000 + offset)
            self.assertEqual(
                value["decision"], dict.fromkeys(subject.FALSE_FLAGS, False)
            )
            self.assertTrue(all(item is False for item in value["decision"].values()))
            self.assertEqual(value["limitations"], list(subject.LIMITATIONS))
            self.assertEqual(
                stat.S_IMODE((fixture.root / (stage + ".json")).stat().st_mode), 0o400
            )
            previous = canonical_digest(value)
        self.assertEqual(fixture.read("ingress")["body"]["worker_request"], request)
        self.assertEqual(fixture.read("attempt")["body"]["attempt"], attempt)
        self.assertEqual(fixture.read("attempt")["body"]["receipt_state"], state)
        self.assertEqual(fixture.read("action")["body"]["action_request"], action)
        self.assertEqual(
            {path.name for path in fixture.root.iterdir()},
            {stage + ".json" for stage in subject.STAGES},
        )
        store.close()
        with self.assertRaises(subject.NativeWorkerIngressFatal):
            fixture.open()

    def test_startup_alone_is_permanent_and_begin_never_retries(self):
        fixture = self.fixture()
        store = fixture.open()
        request, *_ = documents()
        store.begin(request, PEER)
        with self.assertRaises(subject.NativeWorkerIngressFatal):
            store.begin(request, PEER)
        before = {path.name: path.read_bytes() for path in fixture.root.iterdir()}
        with self.assertRaises(subject.NativeWorkerIngressFatal):
            fixture.open()
        self.assertEqual(
            before, {path.name: path.read_bytes() for path in fixture.root.iterdir()}
        )

    def test_startup_claim_refuses_restart_even_without_ingress(self):
        fixture = self.fixture()
        fixture.open().close()
        raw = (fixture.root / "startup.json").read_bytes()
        with self.assertRaises(subject.NativeWorkerIngressFatal):
            fixture.open()
        self.assertEqual((fixture.root / "startup.json").read_bytes(), raw)
        self.assertEqual(
            {path.name for path in fixture.root.iterdir()}, {"startup.json"}
        )

    def test_startup_refuses_any_existing_file_without_repair(self):
        fixture = self.fixture()
        path = fixture.root / "startup.json"
        path.write_bytes(b"partial startup")
        with self.assertRaises(subject.NativeWorkerIngressFatal):
            fixture.open()
        self.assertEqual(path.read_bytes(), b"partial startup")
        self.assertEqual(
            {item.name for item in fixture.root.iterdir()}, {"startup.json"}
        )

    def test_caller_aliases_are_detached_from_all_retained_documents(self):
        fixture = self.fixture()
        binding = deepcopy(BINDING)
        store = fixture.open(binding)
        binding["policy_version"] = 99
        request, attempt, state, action = documents()
        trace = store.begin(request, PEER)
        request["session_id"] = "changed"
        store.bind_attempt(trace, attempt, state, PIN)
        attempt["event"]["session_id"] = "changed"
        state["receipts"].clear()
        store.bind_action(trace, action)
        action["policy_version"] = 99
        self.assertEqual(fixture.read("startup")["worker_binding"], BINDING)
        self.assertEqual(
            fixture.read("ingress")["body"]["worker_request"]["session_id"],
            "inert-session",
        )
        self.assertEqual(
            fixture.read("attempt")["body"]["attempt"]["event"]["session_id"],
            "inert-session",
        )
        self.assertEqual(
            fixture.read("action")["body"]["action_request"]["policy_version"], 1
        )

    def test_mismatched_attempt_and_foreign_trace_halt_before_next_record(self):
        for mode in ("event", "trace", "state", "genesis"):
            with self.subTest(mode=mode):
                fixture = InertStore()
                try:
                    store = fixture.open()
                    request, attempt, state, _action = documents()
                    trace = store.begin(request, PEER)
                    if mode == "event":
                        attempt["event"]["session_id"] = "wrong"
                        state["receipts"] = [canonical_digest(attempt)]
                    if mode == "state":
                        state["receipts"] = [PIN]
                    with self.assertRaises(subject.NativeWorkerIngressFatal):
                        store.bind_attempt(
                            object() if mode == "trace" else trace,
                            attempt,
                            state,
                            "sha256:" + "2" * 64 if mode == "genesis" else PIN,
                        )
                    self.assertFalse((fixture.root / "attempt.json").exists())
                    with self.assertRaises(subject.NativeWorkerIngressFatal):
                        store.bind_attempt(trace, *documents()[1:3], PIN)
                finally:
                    fixture.close()

    def test_action_payload_binding_and_bool_epoch_refuse(self):
        for key, value in (
            ("payload_digest", PIN),
            ("policy_version", True),
            ("issued_at_unix", True),
            ("expires_at_unix", 106),
            ("tool_call_id", "different"),
        ):
            with self.subTest(key=key):
                fixture = InertStore()
                try:
                    store = fixture.open()
                    request, attempt, state, action = documents()
                    trace = store.begin(request, PEER)
                    store.bind_attempt(trace, attempt, state, PIN)
                    action[key] = value
                    with self.assertRaises(subject.NativeWorkerIngressFatal):
                        store.bind_action(trace, action)
                    self.assertFalse((fixture.root / "action.json").exists())
                finally:
                    fixture.close()

    def test_prior_file_content_replacement_extra_entry_and_root_mode_refuse(self):
        for change in ("content", "replace", "extra", "mode"):
            with self.subTest(change=change):
                fixture = InertStore()
                try:
                    store = fixture.open()
                    path = fixture.root / "startup.json"
                    if change == "content":
                        path.chmod(0o600)
                        path.write_bytes(b"changed")
                        path.chmod(0o400)
                    elif change == "replace":
                        raw = path.read_bytes()
                        path.unlink()
                        path.write_bytes(raw)
                        path.chmod(0o400)
                    elif change == "extra":
                        (fixture.root / "unexpected").write_bytes(b"x")
                    else:
                        fixture.root.chmod(0o750)
                    with self.assertRaises(subject.NativeWorkerIngressFatal):
                        store.begin(documents()[0], PEER)
                    self.assertFalse((fixture.root / "ingress.json").exists())
                finally:
                    fixture.close()

    def test_process_and_time_namespace_changes_refuse(self):
        for change in ("start_time_ticks", "namespace"):
            with self.subTest(change=change):
                fixture = InertStore()
                try:
                    store = fixture.open()
                    if change == "namespace":
                        fixture.namespace["inode"] += 1
                    else:
                        fixture.identity[change] += 1
                    with self.assertRaises(subject.NativeWorkerIngressFatal):
                        store.begin(documents()[0], PEER)
                    self.assertFalse((fixture.root / "ingress.json").exists())
                finally:
                    fixture.close()

    def test_short_write_failure_preserves_partial_final_name_and_primary_cause(self):
        fixture = self.fixture()
        store = fixture.open()
        primary = OSError("inert write failure")
        first = True
        closed = []
        expected_closed = set(store._descriptors)

        def write(fd, raw):
            nonlocal first
            if first:
                first = False
                return fixture.real_write(fd, raw[:7])
            raise primary

        def close(fd):
            closed.append(fd)
            fixture.real_close(fd)
            if len(closed) == 1:
                raise OSError("inert secondary close failure")

        with (
            patch.object(subject.os, "write", side_effect=write),
            patch.object(subject.os, "close", side_effect=close),
        ):
            with self.assertRaises(subject.NativeWorkerIngressFatal) as caught:
                store.begin(documents()[0], PEER)
        self.assertIs(caught.exception.__cause__, primary)
        self.assertTrue(expected_closed <= set(closed))
        self.assertEqual(len(closed), len(expected_closed) + 1)
        self.assertEqual(len((fixture.root / "ingress.json").read_bytes()), 7)
        with self.assertRaises(subject.NativeWorkerIngressFatal):
            fixture.open()

    def test_close_failure_attempts_every_descriptor_and_never_erases_claim(self):
        fixture = self.fixture()
        store = fixture.open()
        expected = set(store._descriptors)
        closed = []

        def close(fd):
            closed.append(fd)
            fixture.real_close(fd)
            if len(closed) == 1:
                raise OSError("inert close failure")

        with patch.object(subject.os, "close", side_effect=close):
            with self.assertRaises(subject.NativeWorkerIngressFatal):
                store.close()
        self.assertEqual(set(closed), expected)
        self.assertTrue((fixture.root / "startup.json").is_file())
        with self.assertRaises(subject.NativeWorkerIngressFatal):
            fixture.open()

    def test_main_thread_accounts_and_bool_clock_are_enforced(self):
        fixture = self.fixture()
        with patch.object(subject.threading, "get_native_id", return_value=124):
            with self.assertRaises(subject.NativeWorkerIngressFatal):
                fixture.open()
        with patch.object(subject.os, "getegid", return_value=998):
            with self.assertRaises(subject.NativeWorkerIngressFatal):
                fixture.open()
        self.assertEqual(list(fixture.root.iterdir()), [])
        with patch.object(subject.time, "clock_gettime_ns", return_value=True):
            with self.assertRaises(subject.NativeWorkerIngressFatal):
                fixture.open()
        self.assertEqual(list(fixture.root.iterdir()), [])

    def test_ingress_clock_regression_or_bool_halts_after_startup_claim(self):
        for value in (999, 1000, True):
            with self.subTest(value=value):
                fixture = InertStore()
                try:
                    store = fixture.open()
                    with patch.object(
                        subject.time, "clock_gettime_ns", return_value=value
                    ):
                        with self.assertRaises(subject.NativeWorkerIngressFatal):
                            store.begin(documents()[0], PEER)
                    self.assertTrue((fixture.root / "startup.json").exists())
                    self.assertFalse((fixture.root / "ingress.json").exists())
                finally:
                    fixture.close()

    def test_malformed_frame_consumes_ingress_but_cannot_bind_an_attempt(self):
        fixture = self.fixture()
        store = fixture.open()
        trace = store.begin({"unrecognized": "inert frame"}, PEER)
        self.assertEqual(
            fixture.read("ingress")["body"]["worker_request"],
            {"unrecognized": "inert frame"},
        )
        _request, attempt, state, _action = documents()
        with self.assertRaises(subject.NativeWorkerIngressFatal):
            store.bind_attempt(trace, attempt, state, PIN)
        self.assertFalse((fixture.root / "attempt.json").exists())

    def test_self_identity_reads_only_own_stat_and_status_and_all_four_accounts(self):
        identity_reader = subject._self_identity
        with (
            patch.object(subject.os, "getpid", return_value=123),
            patch.object(subject.process, "_process_start_time", return_value=456),
            patch.object(
                subject.process,
                "_read_virtual_file",
                return_value=b"Uid:\t997\t997\t997\t997\nGid:\t997\t997\t997\t997\n",
            ) as read,
        ):
            self.assertEqual(identity_reader()["uids"], [997] * 4)
            read.assert_called_once_with(Path("/proc/123/status"), 16384)
        with (
            patch.object(subject.os, "getpid", return_value=123),
            patch.object(subject.process, "_process_start_time", return_value=456),
            patch.object(
                subject.process,
                "_read_virtual_file",
                return_value=b"Uid:\t997\t997\t997\t0\nGid:\t997\t997\t997\t997\n",
            ),
        ):
            with self.assertRaises(subject.NativeWorkerIngressFatal):
                identity_reader()


if __name__ == "__main__":
    unittest.main()
