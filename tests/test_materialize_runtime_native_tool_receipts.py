from __future__ import annotations

import copy
import os
import socket
import subprocess
import sys
import tempfile
import time
import types
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

import aragorn
from aragorn import runtime_native_tool_receipts as core
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_runtime_native_tool_receipts as subject
from tests import test_materialize_runtime_endpoint_journal as predecessor_tests
from tests import test_runtime_action_worker as worker_fixture
from tests.test_runtime_native_tool_receipts import Fixture


@contextmanager
def _modules():
    with mock.patch.object(subject, "_ROOT", subject.base._ROOT):
        rendered = subject._verified_inputs()
    modules = {}
    with ExitStack() as stack:
        for source in (subject._JOURNAL, subject._STARTUP, subject._WORKER):
            name = "aragorn._receipt_test_" + Path(source).stem
            module = types.ModuleType(name)
            stack.enter_context(mock.patch.dict(sys.modules, {name: module}))
            exec(compile(rendered[source], source, "exec"), module.__dict__)  # noqa: S102 - exact pinned local source
            modules[source] = module
            stack.enter_context(
                mock.patch.object(aragorn, Path(source).stem, module, create=True)
            )
        yield (
            modules[subject._WORKER],
            modules[subject._STARTUP],
            modules[subject._JOURNAL],
        )


@contextmanager
def _records(journal):
    records = []
    with mock.patch.object(
        journal,
        "emit_journal_event",
        side_effect=lambda value: records.append(copy.deepcopy(value)),
    ):
        yield records
    assert len(records) == 2
    assert all(journal._valid_event(value) for value in records)
    assert records[0]["attempt_id"] == records[1]["attempt_id"]


@contextmanager
def _credentials(worker, credentials, root):
    fixture = Fixture(root / "state")
    binding = worker.RuntimeActionWorkerBinding(
        runtime_digest=fixture.genesis["runtime_digest"],
        active_skill_digest="sha256:" + "2" * 64,
        policy_digest=fixture.genesis["policy_digest"],
        policy_version=fixture.genesis["policy_version"],
    )
    directory = root / "credentials"
    directory.mkdir(mode=0o700)
    for name, document in (
        (
            "worker-binding",
            {
                "schema": worker._BINDING_SCHEMA,
                "runtime_digest": binding.runtime_digest,
                "active_skill_digest": binding.active_skill_digest,
                "policy_digest": binding.policy_digest,
                "policy_version": binding.policy_version,
            },
        ),
        ("openclaw-config", {}),
        ("native-tool-genesis", fixture.genesis),
    ):
        path = directory / name
        path.write_bytes(canonical_json(document))
        path.chmod(0o400)
    with (
        mock.patch.object(worker, "_NATIVE_RECEIPT_ROOT", fixture.root),
        mock.patch.object(credentials, "_CREDENTIAL_DIRECTORY", directory),
        mock.patch.object(credentials, "_EXPECTED_ROOT_UID", os.geteuid()),
        mock.patch.object(
            credentials.os,
            "fstatvfs",
            return_value=types.SimpleNamespace(f_flag=os.ST_RDONLY),
        ),
        mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(directory)}),
    ):
        yield fixture, binding, directory


class NativeToolReceiptTransportTests(unittest.TestCase):
    def test_fresh_worker_and_startup_import_orders_share_the_real_binding_class(self):
        program = """import importlib, importlib.abc, importlib.util, sys
subject = importlib.import_module(sys.argv[1])
subject._ROOT = subject.base._ROOT
raw = subject._verified_inputs()
sources = {"aragorn." + name.rsplit("/", 1)[1][:-3]: value for name, value in raw.items() if name.endswith(".py")}
class Loader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in sources:
            return importlib.util.spec_from_loader(fullname, self)
        return None
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        exec(compile(sources[module.__name__], module.__name__, "exec"), module.__dict__)
for name in list(sys.modules):
    if name == "aragorn" or name.startswith("aragorn."):
        del sys.modules[name]
sys.meta_path.insert(0, Loader())
importlib.import_module("aragorn." + sys.argv[2])
worker = importlib.import_module("aragorn.runtime_action_worker")
startup = importlib.import_module("aragorn.runtime_skill_startup_service")
assert startup.worker is worker
assert startup.startup.RuntimeActionWorkerBinding is worker.RuntimeActionWorkerBinding
assert startup._CREDENTIAL_NAMES == {"worker-binding", "openclaw-config", "native-tool-genesis"}
"""
        environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(
                (
                    str(Path(subject.__file__).parent),
                    str(subject.base._ROOT / "src"),
                    str(subject.base._ROOT),
                )
            ),
        }
        for first in ("runtime_action_worker", "runtime_skill_startup_service"):
            with self.subTest(first=first):
                result = subprocess.run(
                    [sys.executable, "-B", "-c", program, subject.__name__, first],
                    cwd=subject.base._ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_four_pinned_outputs_and_source_only_ceiling(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(subject, "_ROOT", subject.base._ROOT),
        ):
            output = Path(temporary).resolve() / "overlay"
            manifest = subject.materialize_runtime_native_tool_receipts(output)
            self.assertEqual(len(manifest["files"]), 4)
            for item in manifest["files"]:
                raw = (output / item["name"]).read_bytes()
                self.assertEqual(
                    (len(raw), subject.base.base.overlay._digest(raw)),
                    subject._OUTPUTS[item["source_name"]],
                )
                self.assertEqual((output / item["name"]).stat().st_mode & 0o777, 0o444)
            for name in (
                "standalone_executable",
                "production_activation_eligible",
                "mandatory_native_capture",
                "create_to_attempt_binding",
                "run_eligible",
            ):
                self.assertIs(manifest[name], False)
            unit = (output / Path(subject._UNIT).name).read_text()
            self.assertIn(
                "StateDirectory=aragorn-runtime-tool-receipts\nStateDirectoryMode=0700\n",
                unit,
            )
            self.assertEqual(unit.count("LoadCredential="), 3)
            self.assertIn("Restart=no\n", unit)
            self.assertIn(subject.base.base.activation._STARTUP_COMMAND, unit)
            for mutation in ("dependency", "output"):
                bad = Path(temporary).resolve() / mutation
                mapping = (
                    subject._DEPENDENCIES
                    if mutation == "dependency"
                    else subject._OUTPUTS
                )
                key = next(iter(mapping))
                with (
                    mock.patch.dict(mapping, {key: (1, "sha256:" + "0" * 64)}),
                    self.assertRaises(subject.NativeToolReceiptOverlayError),
                ):
                    subject.materialize_runtime_native_tool_receipts(bad)
                self.assertFalse(bad.exists())
            with self.assertRaises(ValueError):
                subject._render_worker(b"changed boundary")

    def test_real_framed_read_create_receipts_never_enter_effect_relay(self):
        with (
            _modules() as (worker, _credentials_module, journal),
            tempfile.TemporaryDirectory() as temporary,
        ):
            root = Path(temporary).resolve()
            fixture = Fixture(root / "state")
            store = fixture.open()
            config = worker_fixture._config(root)
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
                mock.patch.object(worker, "_relay_request") as relay,
                mock.patch.object(worker, "_connect_sensor") as connect,
            ):
                for number, tool in enumerate(("read", "aragorn_runtime_create"), 1):
                    attempt = fixture.attempt(number, tool)
                    previous = None
                    for phase in (
                        "attempt",
                        "attempt-replay",
                        "terminal",
                        "terminal-replay",
                    ):
                        request = (
                            attempt
                            if phase.startswith("attempt")
                            else fixture.terminal(attempt, previous)
                        )
                        client, server = socket.socketpair()
                        try:
                            deadline = time.monotonic() + 2
                            worker._send_frame(
                                client, canonical_json(request), deadline
                            )
                            client.shutdown(socket.SHUT_WR)
                            with _records(journal) as records:
                                worker._handle_connection(
                                    server,
                                    config,
                                    timeout_seconds=0.5,
                                    native_receipts=store,
                                )
                            server.shutdown(socket.SHUT_WR)
                            ack = worker._read_frame(client, deadline)
                            if phase == "attempt":
                                previous = ack
                            self.assertEqual(
                                ack["status"],
                                {
                                    "attempt": "ATTEMPT_RECORDED_EXECUTE_ONCE",
                                    "attempt-replay": "ALREADY_RECORDED_DO_NOT_EXECUTE",
                                    "terminal": "TERMINAL_RECORDED",
                                    "terminal-replay": "TERMINAL_ALREADY_RECORDED",
                                }[phase],
                            )
                            event = records[-1]
                            self.assertEqual(
                                event["schema"],
                                "aragorn/runtime-endpoint-journal-event/v2",
                            )
                            self.assertEqual(
                                event["outcome"], "LOCAL_RECEIPT_ACK_OBSERVED"
                            )
                            self.assertEqual(
                                event["worker_request_digest"],
                                canonical_digest(request),
                            )
                            self.assertEqual(
                                event["result_digest"], canonical_digest(ack)
                            )
                            self.assertEqual(
                                event["client_delivery"], "FRAME_SENT_NOT_ACKNOWLEDGED"
                            )
                            self.assertEqual(event["submission"], "NOT_STARTED")
                            self.assertIsNone(event["action_request_digest"])
                            self.assertIsNone(event["profile_attribution_digest"])
                            self.assertIsNone(event["verdict"])
                            self.assertIsNone(event["effect_status"])
                        finally:
                            client.close()
                            server.close()
                relay.assert_not_called()
                connect.assert_not_called()

    def test_receipt_refusals_fatal_retention_and_known_ack_delivery_are_distinct(self):
        with _modules() as (worker, _credentials_module, journal):
            for case in ("peer", "frame", "invalid", "fatal", "interrupt", "delivery"):
                with (
                    self.subTest(case=case),
                    tempfile.TemporaryDirectory() as temporary,
                    ExitStack() as stack,
                ):
                    root = Path(temporary).resolve()
                    fixture = Fixture(root / "state")
                    store = fixture.open()
                    request = fixture.attempt()
                    if case == "invalid":
                        request["params_bytes"] = True
                    config = worker_fixture._config(root)
                    stack.enter_context(
                        mock.patch.object(
                            worker,
                            "_peer_credentials",
                            return_value=(
                                111,
                                config.expected_gateway_uid + (case == "peer"),
                                config.expected_gateway_gid,
                            ),
                        )
                    )
                    read = stack.enter_context(
                        mock.patch.object(
                            worker,
                            "_read_frame",
                            side_effect=worker.RuntimeActionBrokerError("secret frame")
                            if case == "frame"
                            else None,
                            return_value=request,
                        )
                    )
                    send = stack.enter_context(
                        mock.patch.object(
                            worker,
                            "_send_frame",
                            side_effect=worker.RuntimeActionBrokerError(
                                "secret delivery"
                            )
                            if case == "delivery"
                            else None,
                        )
                    )
                    relay = stack.enter_context(
                        mock.patch.object(worker, "_relay_request")
                    )
                    if case in {"fatal", "interrupt"}:
                        stack.enter_context(
                            mock.patch.object(
                                store,
                                "retain_attempt",
                                side_effect=core.NativeToolReceiptFatal(
                                    "secret retention"
                                )
                                if case == "fatal"
                                else KeyboardInterrupt(),
                            )
                        )
                    expected = (
                        core.NativeToolReceiptFatal
                        if case in {"fatal", "interrupt"}
                        else worker.RuntimeActionWorkerError
                    )
                    with _records(journal) as records, self.assertRaises(expected):
                        worker._handle_connection(
                            mock.Mock(),
                            config,
                            timeout_seconds=0.5,
                            native_receipts=store,
                        )
                    relay.assert_not_called()
                    event = records[-1]
                    self.assertNotIn(b"secret", canonical_json(event))
                    if case == "peer":
                        read.assert_not_called()
                    if case == "delivery":
                        self.assertEqual(event["outcome"], "LOCAL_RECEIPT_ACK_OBSERVED")
                        self.assertEqual(event["client_delivery"], "SEND_ATTEMPTED")
                        self.assertEqual(
                            store.retain_attempt(request)["status"],
                            "ALREADY_RECORDED_DO_NOT_EXECUTE",
                        )
                    else:
                        send.assert_not_called()
                        self.assertIsNone(event["worker_request_digest"])
                        self.assertIsNone(event["result_digest"])
                        self.assertEqual(
                            event["outcome"],
                            "RECEIPT_REQUEST_REFUSED"
                            if case == "invalid"
                            else "RECEIPT_RETENTION_INDETERMINATE"
                            if case in {"fatal", "interrupt"}
                            else "REJECTED_BEFORE_SUBMISSION",
                        )

    def test_genesis_initialization_requires_fixed_read_only_matching_credentials(self):
        with _modules() as (worker, credentials, _journal):
            for case in (
                "valid",
                "missing",
                "environment",
                "writable",
                "binding",
                "runtime",
                "policy",
                "boolean",
                "uid",
                "unresolved",
                "recheck",
                "cleanup",
            ):
                with (
                    self.subTest(case=case),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    root = Path(temporary).resolve()
                    with (
                        _credentials(worker, credentials, root) as (
                            fixture,
                            binding,
                            directory,
                        ),
                        ExitStack() as stack,
                    ):
                        path = directory / "native-tool-genesis"
                        if case == "missing":
                            path.unlink()
                        elif case == "environment":
                            stack.enter_context(
                                mock.patch.dict(
                                    os.environ, {"CREDENTIALS_DIRECTORY": str(root)}
                                )
                            )
                        elif case == "writable":
                            stack.enter_context(
                                mock.patch.object(
                                    credentials.os,
                                    "fstatvfs",
                                    return_value=types.SimpleNamespace(f_flag=0),
                                )
                            )
                        elif case == "binding":
                            (directory / "worker-binding").chmod(0o600)
                        elif case in {"runtime", "policy", "boolean", "uid"}:
                            document = copy.deepcopy(fixture.genesis)
                            document[
                                {
                                    "runtime": "runtime_digest",
                                    "policy": "policy_digest",
                                    "boolean": "policy_version",
                                    "uid": "worker_uid",
                                }[case]
                            ] = (
                                True
                                if case == "boolean"
                                else os.geteuid() + 1
                                if case == "uid"
                                else "sha256:" + "9" * 64
                            )
                            path.chmod(0o600)
                            path.write_bytes(canonical_json(document))
                            path.chmod(0o400)
                        elif case == "unresolved":
                            fixture.open().retain_attempt(fixture.attempt())
                        elif case == "recheck":
                            original = worker._receipts.NativeToolReceiptStore

                            def changed(*args, original=original, path=path):
                                result = original(*args)
                                path.chmod(0o600)
                                return result

                            stack.enter_context(
                                mock.patch.object(
                                    worker._receipts,
                                    "NativeToolReceiptStore",
                                    side_effect=changed,
                                )
                            )
                        elif case == "cleanup":
                            original_read = credentials._read_credential
                            original_close = os.close
                            held = set()

                            def read(*args, original_read=original_read, held=held):
                                result = original_read(*args)
                                held.update(entry.fd for entry in args[3])
                                return result

                            def close(fd, original_close=original_close, held=held):
                                original_close(fd)
                                if fd in held:
                                    raise OSError("credential close failed")

                            stack.enter_context(
                                mock.patch.object(
                                    credentials, "_read_credential", side_effect=read
                                )
                            )
                            stack.enter_context(
                                mock.patch.object(os, "close", side_effect=close)
                            )
                        if case == "valid":
                            self.assertIsInstance(
                                worker._open_native_receipts(
                                    binding, os.geteuid(), os.getegid()
                                ),
                                core.NativeToolReceiptStore,
                            )
                        else:
                            with self.assertRaises(core.NativeToolReceiptFatal):
                                worker._open_native_receipts(
                                    binding, os.geteuid(), os.getegid()
                                )

    def test_required_initialization_precedes_listen_and_fatal_exits_the_accept_loop(
        self,
    ):
        with (
            _modules() as (worker, _credentials_module, _journal),
            tempfile.TemporaryDirectory() as temporary,
        ):
            root = Path(temporary).resolve()
            fixture = Fixture(root / "state")
            store = fixture.open()
            identities = (os.geteuid(), os.getegid(), 1102, 1202, 1103, 1203, 1104)
            binding = worker_fixture._binding()
            failure = core.NativeToolReceiptFatal("retention unavailable")
            with (
                mock.patch.object(worker.sys, "platform", "linux"),
                mock.patch.object(
                    worker, "_service_identities", return_value=identities
                ),
                mock.patch.object(
                    worker, "_credential_path", side_effect=lambda path, *_a, **_k: path
                ),
                mock.patch.object(worker, "_read_worker_binding", return_value=binding),
                mock.patch.object(worker, "_open_native_receipts", side_effect=failure),
                mock.patch.object(worker, "serve_runtime_action_worker") as serve,
            ):
                self.assertEqual(worker.main(["/fixed/worker-binding"]), 126)
                serve.assert_not_called()
            for close_failure in (
                "none",
                "listener-os",
                "listener-interrupt",
                "connection-interrupt",
            ):
                with self.subTest(close_failure=close_failure):
                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    fake = mock.Mock(wraps=listener)
                    connection = mock.MagicMock()
                    if close_failure == "connection-interrupt":
                        connection.__exit__.side_effect = KeyboardInterrupt()
                    fake.accept.side_effect = [
                        (connection, None),
                        AssertionError("must not accept again"),
                    ]
                    config = types.SimpleNamespace(
                        runtime_directory=root,
                        socket_path=root / "worker.sock",
                        expected_worker_uid=os.geteuid(),
                        expected_gateway_gid=os.getegid(),
                    )

                    def close(listener=listener, close_failure=close_failure):
                        listener.close()
                        if close_failure == "listener-interrupt":
                            raise KeyboardInterrupt()
                        if close_failure == "listener-os":
                            raise OSError("listener cleanup failed")

                    fake.close.side_effect = close
                    try:
                        with (
                            mock.patch.object(worker, "_validate_config"),
                            mock.patch.object(
                                worker,
                                "_open_runtime_directory",
                                side_effect=lambda _c: os.open(root, os.O_RDONLY),
                            ),
                            mock.patch.object(worker, "_prepare_socket_path"),
                            mock.patch.object(
                                worker, "_handle_connection", side_effect=failure
                            ),
                            mock.patch.object(
                                worker.socket, "socket", return_value=fake
                            ),
                            mock.patch.object(
                                worker.socket, "SO_PEERCRED", 17, create=True
                            ),
                            mock.patch.object(
                                worker.os, "O_PATH", os.O_RDONLY, create=True
                            ),
                            self.assertRaises(core.NativeToolReceiptFatal) as caught,
                        ):
                            worker.serve_runtime_action_worker(
                                config, native_receipts=store
                            )
                        self.assertIs(caught.exception, failure)
                        self.assertEqual(fake.accept.call_count, 1)
                        self.assertFalse(config.socket_path.exists())
                    finally:
                        listener.close()

    def test_existing_create_relay_and_journal_boundaries_are_preserved(self):
        with (
            _modules() as (worker, _credentials_module, journal),
            tempfile.TemporaryDirectory() as temporary,
        ):
            fixture = Fixture(Path(temporary).resolve() / "state")
            store = fixture.open()
            original = worker._handle_connection

            def handle(connection, config, *, timeout_seconds):
                return original(
                    connection,
                    config,
                    timeout_seconds=timeout_seconds,
                    native_receipts=store,
                )

            with (
                mock.patch.object(worker, "_handle_connection", handle),
                mock.patch.object(
                    predecessor_tests, "_rendered_module", return_value=worker
                ),
                mock.patch.object(predecessor_tests, "journal", journal),
            ):
                predecessor_tests.RuntimeEndpointJournalOverlayTests().test_worker_prevalidation_forward_uncertainty_and_known_result_delivery()
            self.assertEqual(
                (fixture.root / "state.json").read_bytes(),
                canonical_json(fixture.state),
            )
            for role in ("worker", "sensor", "broker"):
                event = journal._new(role)
                self.assertTrue(journal._valid_event(event))
                event["receipt_operation"] = "ATTEMPT"
                event["receipt_state"] = "ENTERED"
                self.assertEqual(journal._valid_event(event), role == "worker")


if __name__ == "__main__":
    unittest.main()
