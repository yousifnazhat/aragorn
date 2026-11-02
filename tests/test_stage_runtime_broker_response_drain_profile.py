from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

from aragorn import runtime_action_broker_v4 as v4
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import stage_runtime_broker_response_drain_profile as subject
from tests.test_runtime_action_broker_v4 import _fixture

_ROOT = subject.journal._ROOT


def _payloads():
    with mock.patch.object(subject, "_ROOT", _ROOT):
        return subject._verified_payloads()


def _module():
    _, replacements = _payloads()
    raw = replacements[subject.base._destination(subject._BROKER)[0]][2]
    name = "aragorn._broker_response_drain_test"
    module = types.ModuleType(name)
    with mock.patch.dict(sys.modules, {name: module}):
        exec(compile(raw, subject._BROKER, "exec"), module.__dict__)  # noqa: S102 - exact pinned local source
    return module


class _Clock:
    wall = 100.0
    mono = 1000.0

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono


class _Connection:
    def __init__(self, failure=None, after=None):
        self.failure = failure
        self.after = after
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True
        if self.after is not None:
            self.after()
        if self.failure is not None:
            raise self.failure
        return False


@contextmanager
def _serving(module, config, clock, calls):
    """Fake only listener/identity/transport; retain real locked v4 state/effects."""
    broker = config.broker.broker.broker
    metadata = types.SimpleNamespace(
        st_mode=stat.S_IFSOCK | 0o660,
        st_uid=broker.expected_broker_uid,
        st_gid=broker.expected_peer_gid,
        st_dev=7,
        st_ino=8,
    )
    listener = mock.MagicMock()
    iterator = iter(calls)

    def accept():
        item = next(iterator)
        if callable(item):
            item = item()
        return item, None

    listener.accept.side_effect = accept
    socket = types.SimpleNamespace(
        SO_PEERCRED=17,
        AF_UNIX=1,
        SOCK_STREAM=1,
        socket=mock.Mock(return_value=listener),
    )
    local_os = types.SimpleNamespace(**vars(os))
    for name in ("lstat", "fstat", "stat"):
        setattr(local_os, name, mock.Mock(return_value=metadata))
    for name in ("chown", "chmod", "unlink", "fsync"):
        setattr(local_os, name, mock.Mock())
    with ExitStack() as stack:
        for name, value in {
            "os": local_os,
            "socket": socket,
            "_open_protected_directory": mock.Mock(return_value=10),
            "_directory_identity": mock.Mock(return_value=(7, 8)),
            "_open_lock_file": mock.Mock(return_value=11),
            "_acquire_lock": mock.Mock(),
            "_recover_before_listen": mock.Mock(),
            "_prepare_socket_path": mock.Mock(),
            "_release_lock_and_close": mock.Mock(return_value=None),
            "_LOG": mock.Mock(),
        }.items():
            stack.enter_context(mock.patch.object(module, name, value))
        stack.enter_context(mock.patch("time.time", side_effect=clock.time))
        stack.enter_context(mock.patch("time.monotonic", side_effect=clock.monotonic))
        stack.enter_context(mock.patch.object(module._journal, "emit_journal_event"))
        yield listener, socket, local_os
    if socket.socket.called:
        listener.close.assert_called_once_with()


@contextmanager
def _action(module, config, issued, *, send_failure=None):
    broker = config.broker.broker.broker
    wrapped = {
        "schema": module.LINEAGE_ISSUANCE_SCHEMA,
        "authority": module.LINEAGE_ISSUANCE_AUTHORITY,
        "lineage": {},
        "issuance": issued,
    }
    with (
        mock.patch.object(
            module,
            "_peer_credentials",
            return_value=(22, broker.expected_peer_uid, broker.expected_peer_gid),
        ),
        mock.patch.object(module, "_read_frame", return_value=wrapped),
        mock.patch.object(
            module,
            "hold_runtime_active_skill_lineage",
            side_effect=lambda *_a, **_k: _lineage(),
        ),
        mock.patch.object(module, "_send_frame", side_effect=send_failure) as send,
    ):
        yield send


@contextmanager
def _lineage():
    yield {}


def _expire(clock):
    clock.wall = 90.0
    clock.mono = 1004.0
    raise TimeoutError


def _replace_record(path, raw):
    path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o400)


class BrokerResponseDrainTests(unittest.TestCase):
    def test_exact_55_file_stage_changes_only_broker_and_one_activator_pin(self):
        original, replacements = _payloads()
        self.assertEqual(len(original), 55)
        self.assertEqual(
            set(replacements),
            {
                subject.base._destination(name)[0]
                for name in (subject._BROKER, subject._ACTIVATOR)
            },
        )
        self.assertEqual(
            subject._OUTPUTS,
            {
                subject._BROKER: (
                    14578,
                    "sha256:cd7b85e520de7e580d74ffb66c13e67e6984c9f9513c7a7b03c5ebe5416fba6a",
                ),
                subject._ACTIVATOR: (
                    34827,
                    "sha256:5cd0c6e3729e1d6b2e35eae3cd959bb0b9d63a682606c797ddb340dcbfb1a834",
                ),
            },
        )
        final = original | replacements
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "stage"
            with mock.patch.object(subject, "_ROOT", _ROOT):
                report = subject.stage_runtime_broker_response_drain_profile(output)
            self.assertEqual(len(report["files"]), 55)
            self.assertEqual(len(report["new_dependencies"]), 10)
            for name, (_source, mode, raw) in final.items():
                self.assertEqual((output / name).read_bytes(), raw)
                self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), mode)
            for field in (
                "production_activation_eligible",
                "phase3_qualification",
                "run_qualification",
                "broker_response_drain_deployed",
                "native_terminal_retention",
                "native_turn_completion",
            ):
                self.assertIs(report[field], False)
            self.assertEqual({p.name for p in output.parent.iterdir()}, {"stage"})
        destination = subject.base._destination(subject._ACTIVATOR)[0]
        before, after = original[destination][2], replacements[destination][2]
        old = subject.journal._pin_line(
            subject._BROKER, subject._INPUTS[subject._BROKER][1]
        ).encode()
        new = subject.journal._pin_line(
            subject._BROKER, subject._OUTPUTS[subject._BROKER][1]
        ).encode()
        self.assertEqual(after.count(new), 1)
        self.assertEqual(after.replace(new, old), before)
        shell = subprocess.run(
            ["/bin/sh", "-n"], input=after, capture_output=True, timeout=3, check=False
        )
        self.assertEqual(shell.returncode, 0, shell.stderr)
        for name, (_source, _mode, raw) in original.items():
            if name not in replacements:
                self.assertEqual(final[name], original[name])
        for name in (subject._BROKER, subject._ACTIVATOR):
            render = (
                subject._render_broker
                if name == subject._BROKER
                else subject._render_activator
            )
            raw = original[subject.base._destination(name)[0]][2]
            with self.assertRaises(ValueError):
                render(raw + b"\n")

    def test_successful_consumption_keeps_listener_without_second_effect_or_renewal(
        self,
    ):
        module = _module()
        with tempfile.TemporaryDirectory() as temporary:
            fixture, config, issued = _fixture(Path(temporary).resolve())
            v4.initialize_runtime_capability_grant(config, now_unix=100)
            candidate = module.RuntimeActionBrokerV5Config(config)
            clock = _Clock()
            connections = [_Connection(), _Connection()]
            consumed = []

            def duplicate():
                self.assertTrue(connections[0].closed)
                self.assertEqual(fixture.target.read_bytes(), fixture.payload)
                consumed.append(config.grant_state_path.read_bytes())
                self.assertEqual(json.loads(consumed[0])["status"], "CONSUMED")
                clock.mono = 1001.0
                return connections[1]

            with _serving(
                module,
                candidate,
                clock,
                [connections[0], duplicate, lambda: _expire(clock)],
            ) as (listener, _, _):
                with (
                    _action(module, candidate, issued) as send,
                    mock.patch.object(
                        module,
                        "initialize_runtime_capability_grant",
                        wraps=v4.initialize_runtime_capability_grant,
                    ) as initialize,
                    mock.patch.object(
                        module,
                        "recover_runtime_capability_grant",
                        wraps=v4.recover_runtime_capability_grant,
                    ) as recover,
                ):
                    module.serve_runtime_action_broker_v5(candidate)
                self.assertEqual(listener.accept.call_count, 3)
                self.assertEqual(send.call_count, 1)
                self.assertEqual(initialize.call_count, 1)
                self.assertEqual(recover.call_count, 1)
                self.assertEqual(
                    [call.args[0] for call in listener.settimeout.call_args_list],
                    [4.0, 4.0, 3.0],
                )
            self.assertEqual(config.grant_state_path.read_bytes(), consumed[0])
            self.assertEqual(fixture.target.read_bytes(), fixture.payload)
            self.assertTrue(all(connection.closed for connection in connections))
            self.assertEqual(json.loads(config.capability_grant)["max_actions"], 1)

            # A new process sees CONSUMED at startup and never binds a socket.
            clock = _Clock()
            with _serving(module, candidate, clock, []) as (listener, socket, _):
                module.serve_runtime_action_broker_v5(candidate)
                socket.socket.assert_not_called()
                listener.accept.assert_not_called()

    def test_send_context_and_indeterminate_failures_never_enter_drain(self):
        module = _module()
        for failure in (
            "send",
            "context-os",
            "context-interrupt",
            "core-indeterminate",
        ):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture, config, issued = _fixture(Path(temporary).resolve())
                v4.initialize_runtime_capability_grant(config, now_unix=100)
                candidate = module.RuntimeActionBrokerV5Config(config)
                context_error = {
                    "context-os": OSError("close"),
                    "context-interrupt": KeyboardInterrupt(),
                }.get(failure)
                connection = _Connection(context_error)
                clock = _Clock()
                with _serving(module, candidate, clock, [connection]) as (
                    listener,
                    _,
                    _,
                ):
                    with (
                        _action(
                            module,
                            candidate,
                            issued,
                            send_failure=module.RuntimeActionBrokerError("send")
                            if failure == "send"
                            else None,
                        ),
                        mock.patch.object(
                            module,
                            "_verify_completed_consumption",
                            wraps=module._verify_completed_consumption,
                        ) as verify,
                        ExitStack() as stack,
                    ):
                        if failure == "core-indeterminate":
                            stack.enter_context(
                                mock.patch.object(
                                    module,
                                    "mediate_granted_profiled_runtime_create",
                                    side_effect=module.RuntimeActionEffectIndeterminate(
                                        "uncertain"
                                    ),
                                )
                            )
                        error = (
                            KeyboardInterrupt
                            if failure == "context-interrupt"
                            else module.RuntimeActionBrokerError
                        )
                        with self.assertRaises(error):
                            module.serve_runtime_action_broker_v5(candidate)
                        verify.assert_not_called()
                    self.assertEqual(listener.accept.call_count, 1)
                self.assertTrue(connection.closed)
                self.assertEqual(
                    fixture.target.exists(), failure != "core-indeterminate"
                )

    def test_locked_consumed_validation_never_recovers_or_repairs_changed_state(self):
        module = _module()
        for failure in (
            "initial-claimed",
            "claimed",
            "available",
            "wrong-result",
            "pending",
            "receipt",
            "lock-cleanup",
        ):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture, config, issued = _fixture(Path(temporary).resolve())
                v4.initialize_runtime_capability_grant(config, now_unix=100)
                with mock.patch("time.time", return_value=100):
                    result = v4.mediate_granted_profiled_runtime_create(issued, config)
                candidate = module.RuntimeActionBrokerV5Config(config)
                original = config.grant_state_path.read_bytes()
                expected = None if failure == "initial-claimed" else original
                clock = _Clock()

                def mutate_before_lock(
                    broker,
                    deadline,
                    operation,
                    failure=failure,
                    original=original,
                    config=config,
                ):
                    if failure in {"initial-claimed", "claimed", "available"}:
                        state = json.loads(original)
                        state["status"] = (
                            "AVAILABLE" if failure == "available" else "CLAIMED"
                        )
                        state["result"] = None
                        if failure == "available":
                            state["claim"] = None
                        _replace_record(config.grant_state_path, canonical_json(state))
                    elif failure == "pending":
                        config.broker.profile_pending_path.write_bytes(b"unresolved")
                    elif failure == "receipt":
                        _replace_record(config.broker.profile_receipt_path, b"{}")
                    v4._with_profile_lock(broker, deadline, operation)
                    if failure == "lock-cleanup":
                        raise module.RuntimeActionBrokerError("lock cleanup")

                with (
                    mock.patch("time.time", side_effect=clock.time),
                    mock.patch("time.monotonic", side_effect=clock.monotonic),
                    mock.patch.object(
                        module, "_with_profile_lock", side_effect=mutate_before_lock
                    ),
                    mock.patch.object(v4, "_publish_state") as publish,
                    mock.patch.object(v4, "_discard_exact_profile_pending") as discard,
                    mock.patch.object(
                        module, "recover_runtime_capability_grant"
                    ) as recover,
                    self.assertRaises(module.RuntimeActionBrokerError),
                ):
                    module._verify_completed_consumption(
                        candidate,
                        expected,
                        "sha256:" + "0" * 64
                        if failure == "wrong-result"
                        else canonical_digest(result),
                        deadline=1000.5,
                    )
                publish.assert_not_called()
                discard.assert_not_called()
                recover.assert_not_called()
                if failure == "pending":
                    self.assertEqual(
                        config.broker.profile_pending_path.read_bytes(), b"unresolved"
                    )
                self.assertEqual(fixture.target.read_bytes(), fixture.payload)

    def test_existing_broker_journal_known_result_and_delivery_cases_still_pass(self):
        from tests import test_materialize_runtime_endpoint_journal as previous

        case = previous.RuntimeEndpointJournalOverlayTests(
            "test_broker_core_rejection_indeterminate_and_result_delivery"
        )
        with mock.patch.object(previous, "_rendered_module", return_value=_module()):
            case.test_broker_core_rejection_indeterminate_and_result_delivery()

    def test_expiry_and_wall_clock_rollback_cannot_renew_lifetime(self):
        module = _module()
        for mode in ("monotonic", "wall-forward", "initial-lifetime-cap"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                _, config, _ = _fixture(Path(temporary).resolve())
                candidate = module.RuntimeActionBrokerV5Config(config)
                clock = _Clock()
                if mode == "initial-lifetime-cap":
                    clock.wall = 90.0

                def timeout(mode=mode, clock=clock):
                    if mode == "wall-forward":
                        clock.wall = 105.0
                        clock.mono += 1.0
                    else:
                        clock.wall = 90.0
                        clock.mono += 7.0 if mode == "initial-lifetime-cap" else 4.0
                    raise TimeoutError

                with _serving(module, candidate, clock, [timeout]) as (listener, _, _):
                    with (
                        mock.patch.object(
                            module,
                            "recover_runtime_capability_grant",
                            return_value={"status": "AVAILABLE"},
                        ),
                        mock.patch.object(
                            module,
                            "initialize_runtime_capability_grant",
                            return_value={"status": "AVAILABLE"},
                        ),
                        mock.patch.object(module, "_require_no_profile_pending"),
                    ):
                        module.serve_runtime_action_broker_v5(candidate)
                    self.assertEqual(listener.accept.call_count, 1)
                    listener.settimeout.assert_called_once_with(
                        7.0 if mode == "initial-lifetime-cap" else 4.0
                    )

    def test_stager_rejects_source_pin_partial_output_and_invalid_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for output in ("not-a-Path", Path("relative"), root):
                with (
                    mock.patch.object(subject, "_ROOT", _ROOT),
                    mock.patch.object(
                        subject.journal, "stage_runtime_endpoint_journal_profile"
                    ) as stage,
                    self.assertRaises(subject.RuntimeBrokerResponseDrainStageError),
                ):
                    subject.stage_runtime_broker_response_drain_profile(output)
                stage.assert_not_called()
            pins = copy.deepcopy(subject._SOURCE_PINS)
            name = "scripts/stage_runtime_endpoint_journal_profile.py"
            pins[name] = (pins[name][0], "sha256:" + "0" * 64)
            with (
                mock.patch.object(subject, "_ROOT", _ROOT),
                mock.patch.object(subject, "_SOURCE_PINS", pins),
                mock.patch.object(
                    subject.journal, "stage_runtime_endpoint_journal_profile"
                ) as stage,
                self.assertRaises(subject.RuntimeBrokerResponseDrainStageError),
            ):
                subject.stage_runtime_broker_response_drain_profile(root / "bad-source")
            stage.assert_not_called()
            original_apply = subject.base._apply_overrides

            def incomplete(output, replacements):
                if len(replacements) == 2:
                    original_apply(output, dict(list(replacements.items())[:1]))
                    raise OSError("partial")
                return original_apply(output, replacements)

            with (
                mock.patch.object(subject, "_ROOT", _ROOT),
                mock.patch.object(
                    subject.base, "_apply_overrides", side_effect=incomplete
                ),
                self.assertRaises(subject.RuntimeBrokerResponseDrainStageError),
            ):
                subject.stage_runtime_broker_response_drain_profile(root / "partial")
            self.assertTrue((root / "partial").is_dir())
            self.assertFalse(
                any(
                    path.name.startswith(".aragorn-runtime-stage-")
                    for path in root.iterdir()
                )
            )


if __name__ == "__main__":
    unittest.main()
