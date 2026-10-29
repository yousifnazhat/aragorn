"""Rendered-worker seams with inert transport/clock/receipt doubles only."""

from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

import aragorn
from aragorn import runtime_native_tool_receipts as receipts
from aragorn import runtime_worker_ingress_measurement as measurement
from aragorn.oci_worker_protocol import canonical_digest
from scripts import materialize_runtime_worker_ingress_measurement as subject

PIN = "sha256:" + "1" * 64


def _request():
    return {
        "schema": "aragorn/runtime-action-worker-request/v1",
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "target_name": "inert.txt",
        "payload_base64": "aW5lcnQ=",
        "session_id": "inert-session",
        "run_id": "inert-run",
        "tool_call_digest": PIN,
    }


def _config(worker):
    return worker.RuntimeActionWorkerConfig(
        socket_path=Path("/inert/worker.sock"),
        runtime_directory=Path("/inert"),
        sensor_socket_path=Path("/inert/sensor.sock"),
        protected_root=Path("/inert/protected"),
        expected_worker_uid=997,
        expected_worker_gid=997,
        expected_gateway_uid=992,
        expected_gateway_gid=992,
        expected_sensor_uid=996,
        expected_sensor_gid=996,
        expected_broker_uid=998,
        binding=worker.RuntimeActionWorkerBinding(
            runtime_digest=PIN,
            active_skill_digest=PIN,
            policy_digest=PIN,
            policy_version=1,
        ),
    )


@contextmanager
def _worker():
    # Only this new rendered source executes. The journal is inert, and no
    # historical TestCase method or live worker/service entrypoint is invoked.
    journal = types.ModuleType("aragorn.runtime_endpoint_journal")
    journal.endpoint = lambda *_args: lambda function: function
    journal.note = mock.Mock()
    name = "aragorn._inert_worker_ingress_render_test"
    worker = types.ModuleType(name)
    worker.__package__ = "aragorn"
    with (
        mock.patch.dict(sys.modules, {name: worker, journal.__name__: journal}),
        mock.patch.object(aragorn, "runtime_endpoint_journal", journal, create=True),
    ):
        raw = subject._verified_inputs()
        exec(compile(raw, subject._WORKER, "exec"), worker.__dict__)  # noqa: S102 - pinned local source under inert boundaries
        yield worker


class _Store:
    """Inert values returned by the existing gate's lock/load interface."""

    def __init__(self, request, events):
        self.events = events
        self.held = False
        self._halted = False
        self.genesis_digest = PIN
        self.attempt = {
            "event": {
                "tool_name": "aragorn_runtime_create",
                "worker_request_digest": canonical_digest(request),
                **{
                    key: request[key]
                    for key in ("session_id", "run_id", "tool_call_digest")
                },
            }
        }
        self.state = {
            "genesis_digest": PIN,
            "receipts": [canonical_digest(self.attempt)],
        }
        self.post_error = self.exit_error = None

    @contextmanager
    def _locked(self):
        self.held = True
        self.events.append("lock")
        try:
            yield 50
        finally:
            self.held = False
            self.events.append("unlock")
            if self.exit_error:
                raise self.exit_error

    def _load(self, descriptor, *, expected_state_digest=None):
        if descriptor != 50 or not self.held:
            raise AssertionError("gate read was not under its actual lock")
        self.events.append("postload" if expected_state_digest else "load")
        if expected_state_digest is not None:
            if expected_state_digest != canonical_digest(self.state):
                raise AssertionError("gate changed the retained state join")
            if self.post_error:
                raise self.post_error
        return self.state, [self.attempt]


@contextmanager
def _service_io(worker, ingress, events):
    config = _config(worker)
    listener = mock.Mock()
    listener.bind.side_effect = lambda _path: events.append("bind")
    listener.accept.side_effect = KeyboardInterrupt("inert service stop")
    listener.close.side_effect = lambda: events.append("listener-close")
    info = types.SimpleNamespace(
        st_mode=stat.S_IFSOCK | 0o660,
        st_uid=997,
        st_gid=992,
        st_nlink=1,
        st_dev=1,
        st_ino=2,
    )
    store = mock.Mock(spec=receipts.NativeToolReceiptStore)
    with ExitStack() as stack:
        for name, value in (
            ("_validate_config", mock.Mock()),
            ("_open_runtime_directory", mock.Mock(return_value=70)),
            (
                "_prepare_socket_path",
                mock.Mock(side_effect=lambda *_a: events.append("prepare")),
            ),
        ):
            stack.enter_context(mock.patch.object(worker, name, value))
        stack.enter_context(
            mock.patch.object(worker.socket, "SO_PEERCRED", 17, create=True)
        )
        stack.enter_context(mock.patch.object(worker.os, "O_PATH", 0, create=True))
        stack.enter_context(
            mock.patch.object(worker.socket, "socket", return_value=listener)
        )
        stack.enter_context(mock.patch.object(worker.os, "stat", return_value=info))
        for name in ("chown", "chmod", "fsync", "unlink", "close"):
            stack.enter_context(mock.patch.object(worker.os, name))
        constructor = stack.enter_context(
            mock.patch.object(
                measurement,
                "NativeWorkerIngress",
                side_effect=lambda **_kwargs: (events.append("init"), ingress)[1],
            )
        )
        yield config, store, listener, constructor


@contextmanager
def _relay_io(worker, request, events):
    sensor = mock.Mock()
    sensor.close.side_effect = lambda: events.append("sensor-close")
    candidate = {"inert": "broker result"}
    reads = iter((request, candidate))

    def read(*_args):
        result = next(reads)
        events.append("frame" if result is request else "broker-result")
        return result

    with ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(worker, "_peer_credentials", return_value=(300, 992, 992))
        )
        stack.enter_context(mock.patch.object(worker, "_read_frame", side_effect=read))
        send = stack.enter_context(mock.patch.object(worker, "_send_frame"))
        stack.enter_context(
            mock.patch.object(worker, "_open_protected_root", return_value=80)
        )
        stack.enter_context(
            mock.patch.object(
                worker,
                "_action_digests",
                return_value={
                    "operation_digest": PIN,
                    "path_digest": PIN,
                    "payload_digest": PIN,
                },
            )
        )
        connect = stack.enter_context(
            mock.patch.object(
                worker,
                "_connect_sensor",
                side_effect=lambda *_a: (events.append("connect"), sensor)[1],
            )
        )
        stack.enter_context(
            mock.patch.object(
                worker, "_broker_result", side_effect=lambda value, *_a: value
            )
        )
        stack.enter_context(mock.patch.object(worker.time, "time", return_value=100))
        stack.enter_context(
            mock.patch.object(worker.time, "monotonic", return_value=10)
        )
        close = stack.enter_context(
            mock.patch.object(
                worker.os,
                "close",
                side_effect=lambda _fd: events.append("protected-close"),
            )
        )
        yield sensor, send, connect, close


class WorkerIngressRendererTests(unittest.TestCase):
    def test_exact_source_overlay_is_reversible_and_has_no_deployment_authority(self):
        original = subject.base._verified_inputs()
        raw = subject._verified_inputs()
        restored = raw
        for before, after in reversed(subject._REPLACEMENTS):
            restored = restored.replace(after.encode("ascii"), before.encode("ascii"))
        self.assertEqual(restored, original)
        self.assertEqual((len(raw), subject.overlay._digest(raw)), subject._OUTPUT)

        def functions(source):
            text = source.decode()
            return {
                node.name: ast.get_source_segment(text, node)
                for node in ast.parse(text).body
                if isinstance(node, ast.FunctionDef)
            }

        before, after = functions(original), functions(raw)
        for name in (
            "main",
            "_run",
            "_worker_request",
            "_broker_envelope",
            "_broker_result",
            "_connect_sensor",
            "_open_native_receipts",
        ):
            self.assertEqual(before[name], after[name])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "source-only"
            report = subject.materialize_runtime_worker_ingress_measurement(output)
            try:
                target = output / Path(subject._WORKER).name
                self.assertEqual(target.read_bytes(), raw)
                self.assertEqual(output.stat().st_mode & 0o777, 0o555)
                self.assertEqual(target.stat().st_mode & 0o777, 0o444)
                for key in (
                    "standalone_executable",
                    "production_activation_eligible",
                    "native_hook_reachability",
                    "measurement_collected",
                    "run_eligible",
                    "metrics_eligible",
                    "phase3_eligible",
                ):
                    self.assertIs(report[key], False)
                self.assertEqual(
                    report["predecessor_worker"]["digest"], subject._INPUT[1]
                )
                with self.assertRaises(subject.WorkerIngressOverlayError):
                    subject.materialize_runtime_worker_ingress_measurement(output)
            finally:
                output.chmod(0o755)

    def test_changed_pins_anchors_or_partial_publication_refuse(self):
        original = subject.base._verified_inputs()
        for raw in (b"", b"X" + original[1:]):
            with self.assertRaises(subject.WorkerIngressOverlayError):
                subject._transform(raw)
        for name, value in (
            ("_OUTPUT", (1, "sha256:" + "0" * 64)),
            ("_DEPENDENCIES", {subject._HELPER: (1, "sha256:" + "0" * 64)}),
            ("_REPLACEMENTS", (("missing source anchor", "replacement"),)),
        ):
            with mock.patch.object(subject, name, value), self.assertRaises(ValueError):
                subject._verified_inputs()
        with self.assertRaises(subject.WorkerIngressOverlayError):
            subject._replace(b"x x", "x", "y")
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.object(
                    subject.overlay,
                    "_write_overlay",
                    side_effect=OSError("inert publication refusal"),
                ),
                self.assertRaises(subject.WorkerIngressOverlayError),
            ):
                subject.materialize_runtime_worker_ingress_measurement(
                    Path(temporary).resolve() / "partial"
                )

    def test_startup_claim_precedes_socket_and_constructor_failure_closes_runtime_fd(
        self,
    ):
        with _worker() as worker:
            events, ingress = [], mock.Mock()
            with _service_io(worker, ingress, events) as (
                config,
                store,
                _listener,
                constructor,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    worker.serve_runtime_action_worker(config, native_receipts=store)
                self.assertEqual(events[:3], ["init", "prepare", "bind"])
                constructor.assert_called_once_with(
                    expected_worker_uid=997,
                    expected_worker_gid=997,
                    binding={
                        "schema": worker._BINDING_SCHEMA,
                        "runtime_digest": PIN,
                        "active_skill_digest": PIN,
                        "policy_digest": PIN,
                        "policy_version": 1,
                    },
                )
                ingress.close.assert_called_once_with()
                worker.os.close.assert_called_once_with(70)
            events, ingress = [], mock.Mock()
            failure = receipts.NativeToolReceiptFatal("inert startup failure")
            with _service_io(worker, ingress, events) as (
                config,
                store,
                listener,
                constructor,
            ):
                constructor.side_effect = failure
                with self.assertRaises(receipts.NativeToolReceiptFatal) as caught:
                    worker.serve_runtime_action_worker(config, native_receipts=store)
                self.assertIs(caught.exception, failure)
                listener.bind.assert_not_called()
                ingress.close.assert_not_called()
                worker.os.close.assert_called_once_with(70)

    def test_receipt_only_and_unauthorized_peers_never_begin_or_reach_gate(self):
        with _worker() as worker:
            for schema in (
                "aragorn/native-tool-attempt/v1",
                "aragorn/native-tool-terminal/v1",
                "unauthorized",
            ):
                ingress, store = mock.Mock(), mock.Mock()
                request = {"schema": schema}
                with (
                    mock.patch.object(
                        worker,
                        "_peer_credentials",
                        return_value=(300, 1 if schema == "unauthorized" else 992, 992),
                    ),
                    mock.patch.object(
                        worker, "_read_frame", return_value=request
                    ) as read,
                    mock.patch.object(worker, "_send_frame"),
                    mock.patch.object(worker, "_relay_native_attempt_once") as gate,
                    mock.patch.object(worker.time, "monotonic", return_value=10),
                ):
                    store.retain_attempt.return_value = {
                        "inert": "attempt acknowledgement"
                    }
                    store.retain_terminal.return_value = {
                        "inert": "terminal acknowledgement"
                    }
                    arguments = dict(
                        timeout_seconds=0.5,
                        native_receipts=store,
                        relayed_native_attempts=set(),
                        ingress=ingress,
                    )
                    if schema == "unauthorized":
                        with self.assertRaises(worker.RuntimeActionWorkerError):
                            worker._handle_connection(
                                mock.Mock(), _config(worker), **arguments
                            )
                        read.assert_not_called()
                    else:
                        worker._handle_connection(
                            mock.Mock(), _config(worker), **arguments
                        )
                    ingress.begin.assert_not_called()
                    ingress.bind_attempt.assert_not_called()
                    ingress.bind_action.assert_not_called()
                    gate.assert_not_called()

    def test_real_handler_gate_and_relay_pass_actual_objects_before_sensor_connect(
        self,
    ):
        with _worker() as worker:
            request, events, trace, used = _request(), [], object(), set()
            store = _Store(request, events)
            ingress = mock.Mock()
            ingress.begin.side_effect = lambda *_a: (events.append("begin"), trace)[1]

            def bind_attempt(token, attempt, state, genesis):
                self.assertIs(token, trace)
                self.assertIs(attempt, store.attempt)
                self.assertIs(state, store.state)
                self.assertEqual(genesis, store.genesis_digest)
                self.assertTrue(store.held)
                self.assertEqual(used, {canonical_digest(attempt)})
                events.append("attempt")

            ingress.bind_attempt.side_effect = bind_attempt
            ingress.bind_action.side_effect = lambda token, action: events.append(
                "action"
            )
            with _relay_io(worker, request, events) as (_sensor, send, connect, close):
                worker._handle_connection(
                    mock.Mock(),
                    _config(worker),
                    timeout_seconds=0.5,
                    native_receipts=store,
                    relayed_native_attempts=used,
                    ingress=ingress,
                )
                ingress.begin.assert_called_once_with(request, (300, 992, 992))
                action = json.loads(send.call_args_list[0].args[1])["request"]
                ingress.bind_action.assert_called_once_with(trace, action)
                connect.assert_called_once()
                close.assert_called_once_with(80)
            self.assertEqual(
                events,
                [
                    "frame",
                    "begin",
                    "lock",
                    "load",
                    "attempt",
                    "action",
                    "connect",
                    "broker-result",
                    "sensor-close",
                    "protected-close",
                    "postload",
                    "unlock",
                ],
            )
            self.assertFalse(store.held)

    def test_measurement_fatal_survives_gate_and_relay_cleanup_without_retry(self):
        for mode in (
            "begin",
            "gate-postread",
            "gate-exit",
            "relay-protected",
            "relay-sensor",
        ):
            with self.subTest(mode=mode), _worker() as worker:
                request, events, trace, used = _request(), [], object(), set()
                store, ingress = _Store(request, events), mock.Mock()
                ingress.begin.return_value = trace
                failure = receipts.NativeToolReceiptFatal(
                    "inert primary measurement failure"
                )
                if mode == "begin":
                    ingress.begin.side_effect = failure
                elif mode in ("gate-postread", "gate-exit"):
                    ingress.bind_attempt.side_effect = failure
                    if mode == "gate-postread":
                        store.post_error = KeyboardInterrupt(
                            "inert postload interruption"
                        )
                    else:
                        store.exit_error = KeyboardInterrupt(
                            "inert unlock interruption"
                        )
                elif mode == "relay-protected":
                    ingress.bind_action.side_effect = failure
                with (
                    _relay_io(worker, request, events) as (
                        sensor,
                        _send,
                        connect,
                        close,
                    ),
                    ExitStack() as changes,
                ):
                    if mode == "relay-protected":
                        close.side_effect = KeyboardInterrupt(
                            "inert protected cleanup interruption"
                        )
                    elif mode == "relay-sensor":
                        changes.enter_context(
                            mock.patch.object(
                                worker, "_broker_result", side_effect=failure
                            )
                        )
                        sensor.close.side_effect = KeyboardInterrupt(
                            "inert sensor cleanup interruption"
                        )
                    with self.assertRaises(receipts.NativeToolReceiptFatal) as caught:
                        worker._handle_connection(
                            mock.Mock(),
                            _config(worker),
                            timeout_seconds=0.5,
                            native_receipts=store,
                            relayed_native_attempts=used,
                            ingress=ingress,
                        )
                    self.assertIs(caught.exception, failure)
                    if mode != "relay-sensor":
                        connect.assert_not_called()
                    if mode.startswith("relay"):
                        close.assert_called_once_with(80)
                self.assertEqual(
                    used,
                    set() if mode == "begin" else {canonical_digest(store.attempt)},
                )
                ingress.begin.assert_called_once()
                self.assertFalse(store.held)

    def test_service_fatal_stops_accepting_and_closes_helper_despite_cleanup_errors(
        self,
    ):
        for mode in ("normal", "helper-close", "listener-close"):
            with self.subTest(mode=mode), _worker() as worker:
                events, ingress = [], mock.Mock()
                primary = receipts.NativeToolReceiptFatal("inert operation failure")
                with _service_io(worker, ingress, events) as (
                    config,
                    store,
                    listener,
                    _constructor,
                ):
                    connection = mock.MagicMock()
                    listener.accept.side_effect = [
                        (connection, None),
                        AssertionError("must not accept again"),
                    ]
                    if mode == "helper-close":
                        ingress.close.side_effect = KeyboardInterrupt(
                            "inert helper close interruption"
                        )
                    elif mode == "listener-close":
                        listener.close.side_effect = KeyboardInterrupt(
                            "inert listener close interruption"
                        )
                    with (
                        mock.patch.object(
                            worker, "_handle_connection", side_effect=primary
                        ) as handle,
                        self.assertRaises(receipts.NativeToolReceiptFatal) as caught,
                    ):
                        worker.serve_runtime_action_worker(
                            config, native_receipts=store
                        )
                    self.assertIs(caught.exception, primary)
                    self.assertIs(handle.call_args.kwargs["ingress"], ingress)
                    listener.accept.assert_called_once()
                    ingress.close.assert_called_once_with()
                    worker.os.close.assert_called_once_with(70)

    def test_ordinary_cleanup_interruption_still_closes_helper_and_keeps_original_error(
        self,
    ):
        with _worker() as worker:
            events, ingress = [], mock.Mock()
            interruption = KeyboardInterrupt("inert existing cleanup interruption")
            with _service_io(worker, ingress, events) as (
                config,
                store,
                listener,
                _constructor,
            ):
                listener.close.side_effect = interruption
                with self.assertRaises(KeyboardInterrupt) as caught:
                    worker.serve_runtime_action_worker(config, native_receipts=store)
                self.assertIs(caught.exception, interruption)
                ingress.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
