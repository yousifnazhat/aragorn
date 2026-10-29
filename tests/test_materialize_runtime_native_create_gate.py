"""Synthetic temporary receipt stores and inert relay mocks; no live effects."""

from __future__ import annotations

import ast
import copy
import fcntl
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
from unittest import mock

import aragorn
from aragorn import runtime_native_tool_receipts as core
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_runtime_native_create_gate as subject
from tests import test_materialize_runtime_native_tool_receipts as predecessor
from tests import test_runtime_action_worker as old
from tests.test_runtime_native_tool_receipts import Fixture


@contextmanager
def _modules():
    rendered = subject.base._verified_inputs()
    rendered[subject._WORKER] = subject._verified_inputs()
    modules = {}
    with ExitStack() as stack:
        for source in (subject.base._JOURNAL, subject.base._STARTUP, subject._WORKER):
            name = "aragorn._native_gate_test_" + Path(source).stem
            module = types.ModuleType(name)
            module.__package__ = "aragorn"
            stack.enter_context(mock.patch.dict(sys.modules, {name: module}))
            exec(compile(rendered[source], source, "exec"), module.__dict__)  # noqa: S102 - exact pinned local source
            stack.enter_context(
                mock.patch.object(aragorn, Path(source).stem, module, create=True)
            )
            modules[source] = module
        yield (
            modules[subject._WORKER],
            modules[subject.base._STARTUP],
            modules[subject.base._JOURNAL],
        )


def _open_create(fixture, request):
    event = fixture.attempt(tool="aragorn_runtime_create")
    event.update(
        {name: request[name] for name in ("run_id", "session_id", "tool_call_digest")}
    )
    event["worker_request_digest"] = canonical_digest(request)
    return event


def _gate(worker, store, used, request, root):
    return worker._relay_native_attempt_once(
        request,
        old._config(root),
        deadline=time.monotonic() + 2,
        native_receipts=store,
        relayed_native_attempts=used,
    )


def _function(raw, name):
    source = raw.decode()
    node = next(
        n
        for n in ast.parse(source).body
        if isinstance(n, ast.FunctionDef) and n.name == name
    )
    return ast.get_source_segment(source, node)


class NativeCreateGateTests(unittest.TestCase):
    def test_exact_overlay_and_unchanged_broker_relay_source(self):
        original = subject.base._verified_inputs()[subject._WORKER]
        rendered = subject._verified_inputs()
        for name in (
            "_relay_request",
            "_worker_request",
            "_broker_envelope",
            "_broker_result",
            "_connect_sensor",
            "_open_native_receipts",
            "_run",
            "main",
        ):
            self.assertEqual(_function(original, name), _function(rendered, name))
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "source"
            manifest = subject.materialize_runtime_native_create_gate(output)
            try:
                target = output / Path(subject._WORKER).name
                self.assertEqual(target.read_bytes(), rendered)
                self.assertEqual(
                    (len(rendered), subject.overlay._digest(rendered)), subject._OUTPUT
                )
                self.assertEqual(output.stat().st_mode & 0o777, 0o555)
                self.assertEqual(target.stat().st_mode & 0o777, 0o444)
                for name in (
                    "standalone_executable",
                    "production_activation_eligible",
                    "native_hook_reachability",
                    "native_causation_verified",
                    "mandatory_capture",
                    "run_eligible",
                ):
                    self.assertIs(manifest[name], False)
                with self.assertRaises(ValueError):
                    subject.materialize_runtime_native_create_gate(output)
            finally:
                output.chmod(0o755)
            for category in ("dependency", "input", "output", "anchor"):
                with self.subTest(category=category):
                    mapping = (
                        "_DEPENDENCIES"
                        if category == "dependency"
                        else "_INPUT"
                        if category == "input"
                        else "_OUTPUT"
                        if category == "output"
                        else "_REPLACEMENTS"
                    )
                    value = copy.deepcopy(getattr(subject, mapping))
                    if category == "dependency":
                        value[next(iter(value))] = (1, "sha256:" + "0" * 64)
                    elif category == "anchor":
                        value = (("missing anchor", "replacement"),)
                    else:
                        value = (1, "sha256:" + "0" * 64)
                    with (
                        mock.patch.object(subject, mapping, value),
                        self.assertRaises(ValueError),
                    ):
                        subject._verified_inputs()
            with (
                mock.patch.object(
                    subject.overlay,
                    "_digest",
                    side_effect=AssertionError("hashed unbounded input"),
                ),
                self.assertRaises(ValueError),
            ):
                subject._transform(b"")
            with (
                mock.patch.object(
                    subject.overlay,
                    "_write_overlay",
                    side_effect=OSError("synthetic partial publication"),
                ),
                self.assertRaises(ValueError),
            ):
                subject.materialize_runtime_native_create_gate(
                    Path(temporary).resolve() / "partial"
                )

    def test_missing_read_closed_and_coherently_mismatched_reports_never_relay(self):
        with (
            _modules() as (worker, _startup, journal),
            tempfile.TemporaryDirectory() as temporary,
        ):
            for mutation in (
                "missing",
                "read",
                "closed",
                "digest",
                "run_id",
                "session_id",
                "tool_call_digest",
                "extra-request",
                "payload",
                "capacity",
            ):
                with self.subTest(mutation=mutation):
                    root = Path(temporary).resolve() / mutation
                    root.mkdir()
                    fixture = Fixture(root / "state")
                    store = fixture.open()
                    request = old._request()
                    event = _open_create(fixture, request)
                    if mutation == "read":
                        event["tool_name"] = "read"
                        event["worker_request_digest"] = None
                    elif mutation == "digest":
                        event["worker_request_digest"] = canonical_digest("other")
                    elif mutation in {"run_id", "session_id", "tool_call_digest"}:
                        event[mutation] = (
                            canonical_digest("other")
                            if mutation == "tool_call_digest"
                            else "other"
                        )
                    if mutation != "missing":
                        ack = store.retain_attempt(event)
                        if mutation == "closed":
                            store.retain_terminal(fixture.terminal(event, ack))
                    if mutation == "extra-request":
                        request["extra"] = "refuse"
                    elif mutation == "payload":
                        request["payload_base64"] = "not canonical"
                    used = (
                        {canonical_digest(i) for i in range(core._MAX_CALLS)}
                        if mutation == "capacity"
                        else set()
                    )
                    original = (fixture.root / "state.json").read_bytes()
                    with (
                        mock.patch.object(worker, "_relay_request") as relay,
                        mock.patch.object(worker, "_connect_sensor") as connect,
                        mock.patch.object(journal, "emit_journal_event"),
                        self.assertRaises(
                            (
                                core.NativeToolReceiptRejected,
                                worker.RuntimeActionWorkerError,
                            )
                        ),
                    ):
                        _gate(worker, store, used, request, root)
                    relay.assert_not_called()
                    connect.assert_not_called()
                    config = old._config(root)
                    with (
                        mock.patch.object(
                            worker,
                            "_peer_credentials",
                            return_value=(
                                111,
                                config.expected_gateway_uid,
                                config.expected_gateway_gid,
                            ),
                        ),
                        mock.patch.object(worker, "_read_frame", return_value=request),
                        mock.patch.object(worker, "_send_frame") as send,
                        mock.patch.object(worker, "_relay_request") as connection_relay,
                        mock.patch.object(
                            worker, "_connect_sensor"
                        ) as connection_connect,
                        mock.patch.object(journal, "emit_journal_event"),
                        self.assertRaises(worker.RuntimeActionWorkerError),
                    ):
                        worker._handle_connection(
                            mock.Mock(),
                            config,
                            timeout_seconds=0.5,
                            native_receipts=store,
                            relayed_native_attempts=used,
                        )
                    send.assert_not_called()
                    connection_relay.assert_not_called()
                    connection_connect.assert_not_called()
                    self.assertEqual(
                        (fixture.root / "state.json").read_bytes(), original
                    )
                    self.assertFalse(store._halted)

    def test_once_mark_precedes_relay_with_lock_held_and_status_never_retries(self):
        with (
            _modules() as (worker, _startup, _journal),
            tempfile.TemporaryDirectory() as temporary,
        ):
            for status in ("NOT_SUBMITTED", "INDETERMINATE", "COMPLETED"):
                with self.subTest(status=status):
                    root = Path(temporary).resolve() / status
                    root.mkdir()
                    fixture = Fixture(root / "state")
                    store = fixture.open()
                    request = old._request()
                    event = _open_create(fixture, request)
                    ack = store.retain_attempt(event)
                    used = set()
                    original = (fixture.root / "state.json").read_bytes()
                    result = {"synthetic_status": status}

                    def relay(
                        validated,
                        _config,
                        *,
                        deadline,
                        request=request,
                        used=used,
                        ack=ack,
                        fixture=fixture,
                        result=result,
                    ):
                        self.assertEqual(validated, request)
                        self.assertIsNot(validated, request)
                        self.assertEqual(used, {ack["receipt_digest"]})
                        self.assertGreater(deadline, time.monotonic())
                        fd = os.open(fixture.root / "receipt.lock", os.O_RDONLY)
                        try:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        finally:
                            os.close(fd)
                        return result

                    with (
                        mock.patch.object(
                            worker, "_relay_request", side_effect=relay
                        ) as call,
                        mock.patch.object(store, "_load", wraps=store._load) as load,
                    ):
                        self.assertIs(_gate(worker, store, used, request, root), result)
                        self.assertEqual(load.call_count, 2)
                        self.assertEqual(
                            load.call_args.kwargs["expected_state_digest"],
                            canonical_digest(
                                core.broker._parse_canonical_document(
                                    original, "test state"
                                )
                            ),
                        )
                        with self.assertRaises(core.NativeToolReceiptRejected):
                            _gate(worker, store, used, request, root)
                    call.assert_called_once()
                    self.assertEqual(
                        (fixture.root / "state.json").read_bytes(), original
                    )
                    with self.assertRaises(core.NativeToolReceiptFatal):
                        fixture.open()  # Worker restart cannot reset this open attempt.
                    fd = os.open(fixture.root / "receipt.lock", os.O_RDONLY)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)

    def test_cooperating_terminal_writer_cannot_close_attempt_during_relay(self):
        with (
            _modules() as (worker, _startup, _journal),
            tempfile.TemporaryDirectory() as temporary,
        ):
            root = Path(temporary).resolve()
            fixture = Fixture(root / "state")
            store = fixture.open()
            request = old._request()
            event = _open_create(fixture, request)
            ack = store.retain_attempt(event)
            terminal = fixture.terminal(event, ack)
            before = (fixture.root / "state.json").read_bytes()
            waiting, done = threading.Event(), threading.Event()
            failures = []
            real_acquire = core.broker._acquire_lock

            def close_attempt():
                try:
                    store.retain_terminal(terminal)
                except BaseException as exc:  # noqa: BLE001 - surface every background failure in the test thread
                    failures.append(exc)
                finally:
                    done.set()

            writer = threading.Thread(target=close_attempt)

            def acquire(fd, deadline):
                if threading.current_thread() is writer:
                    waiting.set()
                return real_acquire(fd, deadline)

            def relay(*_args, **_kwargs):
                writer.start()
                self.assertTrue(waiting.wait(0.2))
                self.assertFalse(done.is_set())
                self.assertEqual((fixture.root / "state.json").read_bytes(), before)
                return {"synthetic_status": "NOT_SUBMITTED"}

            with (
                mock.patch.object(core.broker, "_acquire_lock", side_effect=acquire),
                mock.patch.object(worker, "_relay_request", side_effect=relay),
            ):
                try:
                    _gate(worker, store, set(), request, root)
                finally:
                    if writer.ident is not None:
                        writer.join(2)
            self.assertTrue(done.is_set())
            self.assertEqual(failures, [])
            reopened = fixture.open()
            state = core.broker._parse_canonical_document(
                (fixture.root / "state.json").read_bytes(), "test state"
            )
            self.assertEqual(len(state["receipts"]), 2)
            self.assertEqual(reopened._state_digest, canonical_digest(state))

    def test_changed_chain_halt_unexpected_relay_and_cleanup_are_fatal(self):
        with (
            _modules() as (worker, _startup, _journal),
            tempfile.TemporaryDirectory() as temporary,
        ):
            for mutation in (
                "state",
                "halted",
                "relay-interrupt",
                "cleanup-os",
                "cleanup-interrupt",
                "rejection-cleanup",
            ):
                with self.subTest(mutation=mutation):
                    root = Path(temporary).resolve() / mutation
                    root.mkdir()
                    fixture = Fixture(root / "state")
                    store = fixture.open()
                    request = old._request()
                    if mutation != "rejection-cleanup":
                        store.retain_attempt(_open_create(fixture, request))
                    used = set()
                    real_release = core.broker._release_lock_and_close

                    def release(*args, real_release=real_release, mutation=mutation):
                        outcome = real_release(*args)
                        if mutation == "cleanup-interrupt":
                            raise KeyboardInterrupt()
                        return (
                            OSError("synthetic unlock failure")
                            if mutation in {"cleanup-os", "rejection-cleanup"}
                            else outcome
                        )

                    def relay(
                        *_args,
                        mutation=mutation,
                        fixture=fixture,
                        store=store,
                        **_kwargs,
                    ):
                        if mutation == "state":
                            fixture.write("state.json", canonical_json(fixture.state))
                        elif mutation == "halted":
                            store._halted = True
                        elif mutation == "relay-interrupt":
                            raise KeyboardInterrupt()
                        return {"synthetic_status": "INDETERMINATE"}

                    with (
                        mock.patch.object(
                            worker, "_relay_request", side_effect=relay
                        ) as call,
                        mock.patch.object(
                            core.broker, "_release_lock_and_close", side_effect=release
                        ),
                        self.assertRaises(core.NativeToolReceiptFatal),
                    ):
                        _gate(worker, store, used, request, root)
                    self.assertTrue(store._halted)
                    self.assertEqual(
                        call.call_count, 0 if mutation == "rejection-cleanup" else 1
                    )
                    with self.assertRaises(core.NativeToolReceiptFatal):
                        _gate(worker, store, used, request, root)

    def test_receipt_dispatch_and_fatal_accept_loop_propagation_are_preserved(self):
        with _modules() as (worker, startup, journal):
            original = worker._handle_connection
            used = set()

            def handle(connection, config, *, timeout_seconds, native_receipts):
                return original(
                    connection,
                    config,
                    timeout_seconds=timeout_seconds,
                    native_receipts=native_receipts,
                    relayed_native_attempts=used,
                )

            with (
                mock.patch.object(
                    predecessor,
                    "_modules",
                    side_effect=lambda: nullcontext((worker, startup, journal)),
                ),
                mock.patch.object(worker, "_handle_connection", side_effect=handle),
                mock.patch.object(
                    worker,
                    "_relay_native_attempt_once",
                    side_effect=AssertionError("receipt reached create gate"),
                ),
            ):
                case = predecessor.NativeToolReceiptTransportTests()
                case.test_real_framed_read_create_receipts_never_enter_effect_relay()
                case.test_receipt_refusals_fatal_retention_and_known_ack_delivery_are_distinct()
                case.test_required_initialization_precedes_listen_and_fatal_exits_the_accept_loop()
            self.assertEqual(used, set())


if __name__ == "__main__":
    unittest.main()
