from __future__ import annotations

import copy
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock

from aragorn import runtime_endpoint_journal as journal
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import (
    RuntimeActionBrokerError,
    RuntimeActionEffectIndeterminate,
)
from scripts import materialize_runtime_endpoint_journal as subject
from tests import test_runtime_action_worker as worker_fixture
from tests.test_runtime_action_observation_publisher_v2 import _Fixture
from tests.test_runtime_action_observation_publisher_v4 import _config as sensor_config

_ROOT = subject.quarantine._ROOT


def _copy_inputs(root: Path) -> None:
    names = {
        *subject._SUPPORT_PINS,
        *subject.quarantine._SERVICES,
        *subject.quarantine._DEPENDENCIES,
        subject._WORKER,
    }
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_ROOT / name, path)
    shutil.copyfile(journal.__file__, root / subject._HELPER)


def _rendered_module(name: str):
    raw = (_ROOT / name).read_bytes()
    if name != subject._WORKER:
        raw = subject.quarantine._transform(raw)
    module_name = "aragorn._endpoint_test_" + Path(name).stem
    module = types.ModuleType(module_name)
    with mock.patch.dict(sys.modules, {module_name: module}):
        exec(compile(subject._render(name, raw), name, "exec"), module.__dict__)  # noqa: S102 - exact local pinned sources
    return module


@contextmanager
def _records():
    records = []
    with mock.patch.object(
        journal,
        "emit_journal_event",
        side_effect=lambda item: records.append(copy.deepcopy(item)),
    ):
        yield records
    assert len(records) == 2
    assert records[0]["attempt_id"] == records[1]["attempt_id"]
    assert all(journal._valid_event(item) for item in records)


class RuntimeEndpointJournalOverlayTests(unittest.TestCase):
    def test_pinned_four_file_overlay_and_required_issuer_are_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _copy_inputs(root)
            output = root / "overlay"
            with mock.patch.object(subject, "_ROOT", root):
                manifest = subject.materialize_runtime_endpoint_journal(output)
            self.assertEqual(len(manifest["files"]), 4)
            self.assertEqual(manifest["authority"], subject._AUTHORITY)
            for field in (
                "standalone_executable",
                "production_activation_eligible",
                "run_eligible",
            ):
                self.assertIs(manifest[field], False)
            self.assertEqual(
                manifest["required_companion_overrides_not_included"],
                [
                    {
                        "name": subject._ISSUER,
                        "bytes": 2180,
                        "digest": "sha256:371b0e8f54796d11aef40a0f27f72e841987f8e1a4fdd039c6a7c3ad17c16cfd",
                    }
                ],
            )
            self.assertFalse((output / subject._ISSUER).exists())
            for item in manifest["files"]:
                path = output / item["name"]
                raw = path.read_bytes()
                self.assertEqual(
                    (len(raw), subject.overlay._digest(raw)),
                    (item["bytes"], item["digest"]),
                )
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            for path in (output, output / "src", output / "src/aragorn"):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555)

    def test_source_dependency_output_and_boundary_drift_fail_before_publication(
        self,
    ) -> None:
        for name in (
            subject._WORKER,
            subject._SENSOR,
            subject._BROKER,
            subject._ISSUER,
            subject._HELPER,
            *subject._SUPPORT_PINS,
            *subject.quarantine._DEPENDENCIES,
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _copy_inputs(root)
                path = root / name
                path.write_bytes(path.read_bytes() + b"\n")
                with (
                    mock.patch.object(subject, "_ROOT", root),
                    self.assertRaises(subject.RuntimeEndpointJournalOverlayError),
                ):
                    subject.materialize_runtime_endpoint_journal(root / "overlay")
                self.assertFalse((root / "overlay").exists())
        for name in (subject._WORKER, subject._SENSOR, subject._BROKER):
            raw = (_ROOT / name).read_bytes()
            if name != subject._WORKER:
                raw = subject.quarantine._transform(raw)
            for changed in (
                raw.replace(b"def _handle_connection(", b"def changed("),
                raw + b"\ndef _handle_connection(\n",
            ):
                with self.assertRaises(subject.RuntimeEndpointJournalOverlayError):
                    subject._render(name, changed)

    def test_worker_prevalidation_forward_uncertainty_and_known_result_delivery(
        self,
    ) -> None:
        worker = _rendered_module(subject._WORKER)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = worker_fixture._config(root)
            envelope = worker_fixture._envelope(root)
            allowed = worker_fixture._allowed_result(envelope)
            for case in (
                "peer",
                "frame",
                "request",
                "connect",
                "send",
                "result",
                "delivery",
                "allow",
                "block",
                "close",
                "interrupt",
            ):
                with self.subTest(case=case), ExitStack() as stack:
                    request = worker_fixture._request()
                    if case == "request":
                        request["payload_base64"] = "!"
                    response = copy.deepcopy(allowed)
                    if case == "block":
                        response.update(
                            verdict="BLOCK",
                            effect_status="NOT_PERFORMED",
                            reason_codes=["DENIED"],
                            decision=None,
                        )
                    if case == "result":
                        response["request_digest"] = "sha256:" + "0" * 64
                    frontend = mock.Mock()
                    backend = mock.Mock()
                    if case == "close":
                        backend.close.side_effect = OSError("secret close")
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
                    stack.enter_context(
                        mock.patch.object(
                            worker,
                            "_read_frame",
                            side_effect=[
                                RuntimeActionBrokerError("secret frame")
                                if case == "frame"
                                else request,
                                response,
                            ],
                        )
                    )
                    stack.enter_context(
                        mock.patch.object(
                            worker,
                            "_open_protected_root",
                            side_effect=lambda _: os.open(root, os.O_RDONLY),
                        )
                    )
                    stack.enter_context(
                        mock.patch.object(
                            worker, "_broker_envelope", return_value=envelope
                        )
                    )
                    stack.enter_context(
                        mock.patch.object(
                            worker,
                            "_connect_sensor",
                            side_effect=OSError("secret connect")
                            if case == "connect"
                            else None,
                            return_value=backend,
                        )
                    )

                    def send(
                        connection,
                        _raw,
                        _deadline,
                        *,
                        backend=backend,
                        frontend=frontend,
                        case=case,
                    ):
                        if connection is backend and case in {"send", "interrupt"}:
                            if case == "interrupt":
                                raise KeyboardInterrupt()
                            raise RuntimeActionBrokerError("secret partial send")
                        if connection is frontend and case == "delivery":
                            raise RuntimeActionBrokerError("secret delivery")

                    stack.enter_context(
                        mock.patch.object(worker, "_send_frame", side_effect=send)
                    )
                    with _records() as records:
                        if case in {"peer", "frame", "delivery"}:
                            with self.assertRaises(worker.RuntimeActionWorkerError):
                                worker._handle_connection(
                                    frontend, config, timeout_seconds=0.5
                                )
                        elif case == "interrupt":
                            with self.assertRaises(KeyboardInterrupt):
                                worker._handle_connection(
                                    frontend, config, timeout_seconds=0.5
                                )
                        else:
                            worker._handle_connection(
                                frontend, config, timeout_seconds=0.5
                            )
                    event = records[-1]
                    self.assertNotIn(b"secret", canonical_json(event))
                    if case in {"peer", "frame", "request", "connect"}:
                        self.assertEqual(event["outcome"], "REJECTED_BEFORE_SUBMISSION")
                    elif case in {"send", "result", "interrupt"}:
                        self.assertEqual(event["outcome"], "INDETERMINATE")
                    else:
                        self.assertEqual(event["outcome"], "BROKER_RESULT_OBSERVED")
                        self.assertEqual(
                            event["effect_status"],
                            "NOT_PERFORMED" if case == "block" else "CREATED",
                        )
                    if case in {"peer", "frame", "request"}:
                        self.assertIsNone(event["worker_request_digest"])
                    else:
                        self.assertEqual(
                            event["worker_request_digest"], canonical_digest(request)
                        )
                    if case == "close":
                        self.assertEqual(event["worker_status"], "INDETERMINATE")
                    if case == "delivery":
                        self.assertEqual(event["client_delivery"], "SEND_ATTEMPTED")
                        self.assertEqual(event["handler_status"], "RAISED")

    def test_sensor_separates_pre_send_from_unverified_reply_and_cleanup(self) -> None:
        sensor = _rendered_module(subject._SENSOR)
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            try:
                config = sensor_config(fixture)
                for case in (
                    "lineage",
                    "frame",
                    "send",
                    "reply",
                    "delivery",
                    "cleanup",
                    "interrupt",
                ):
                    with self.subTest(case=case), ExitStack() as stack:
                        frontend = mock.Mock()
                        backend = mock.MagicMock()
                        backend.__enter__.return_value = backend
                        backend.__exit__.return_value = False
                        if case == "cleanup":
                            backend.__exit__.side_effect = OSError("secret cleanup")
                        pidfd = os.open("/dev/null", os.O_RDONLY)
                        stack.enter_context(
                            mock.patch.object(
                                sensor,
                                "_peer_credentials",
                                side_effect=[
                                    fixture.peer,
                                    (202, fixture.broker_uid, fixture.broker_gid),
                                ],
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                sensor, "open_peer_pidfd", return_value=pidfd
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                sensor,
                                "measure_runtime_process_profile",
                                return_value=fixture.attribution,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                sensor,
                                "verify_runtime_active_skill_lineage",
                                side_effect=RuntimeActionBrokerError("secret lineage")
                                if case == "lineage"
                                else None,
                                return_value={},
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                sensor,
                                "_read_frame",
                                side_effect=[
                                    RuntimeActionBrokerError("secret frame")
                                    if case == "frame"
                                    else fixture.envelope,
                                    {"secret": "unverified response"},
                                ],
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                sensor,
                                "_open_protected_root",
                                side_effect=lambda _: os.dup(fixture.protected_fd),
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(sensor, "require_live_pidfd")
                        )
                        stack.enter_context(
                            mock.patch.object(
                                sensor, "_connect_backend", return_value=backend
                            )
                        )

                        @contextmanager
                        def issuance(*_args, **_kwargs):
                            yield {}

                        stack.enter_context(
                            mock.patch.object(
                                sensor,
                                "hold_profiled_runtime_capability_issuance",
                                side_effect=issuance,
                            )
                        )

                        def send(
                            connection,
                            _raw,
                            _deadline,
                            *,
                            backend=backend,
                            frontend=frontend,
                            case=case,
                        ):
                            if connection is backend and case in {"send", "interrupt"}:
                                if case == "interrupt":
                                    raise KeyboardInterrupt()
                                raise RuntimeActionBrokerError("secret send")
                            if connection is frontend and case == "delivery":
                                raise RuntimeActionBrokerError("secret delivery")

                        stack.enter_context(
                            mock.patch.object(sensor, "_send_frame", side_effect=send)
                        )
                        with _records() as records:
                            if case == "reply":
                                sensor._handle_connection(
                                    frontend, config, timeout_seconds=0.5
                                )
                            else:
                                with self.assertRaises(
                                    KeyboardInterrupt
                                    if case == "interrupt"
                                    else sensor.RuntimeActionObservationPublisherError
                                ):
                                    sensor._handle_connection(
                                        frontend, config, timeout_seconds=0.5
                                    )
                        with self.assertRaises(OSError):
                            os.fstat(pidfd)
                        event = records[-1]
                        self.assertNotIn(b"secret", canonical_json(event))
                        self.assertIsNone(event["verdict"])
                        if case in {"lineage", "frame"}:
                            self.assertIsNone(event["action_request_digest"])
                            self.assertIsNone(event["profile_attribution_digest"])
                        else:
                            self.assertEqual(
                                event["action_request_digest"],
                                canonical_digest(fixture.envelope["request"]),
                            )
                            self.assertEqual(
                                event["profile_attribution_digest"],
                                canonical_digest(fixture.attribution),
                            )
                            self.assertEqual(event["request_state"], "VALIDATED")
                        if case in {"lineage", "frame"}:
                            self.assertEqual(
                                event["outcome"], "REJECTED_BEFORE_SUBMISSION"
                            )
                            self.assertIsNone(event["action_request_digest"])
                        elif case == "reply":
                            self.assertEqual(
                                event["outcome"], "REPLY_RELAYED_EFFECT_UNVERIFIED"
                            )
                        else:
                            self.assertEqual(event["outcome"], "INDETERMINATE")
            finally:
                fixture.close()

    def test_broker_core_rejection_indeterminate_and_result_delivery(self) -> None:
        broker = _rendered_module(subject._BROKER)
        peer = types.SimpleNamespace(expected_peer_uid=3, expected_peer_gid=4)
        config = types.SimpleNamespace(
            broker=types.SimpleNamespace(broker=types.SimpleNamespace(broker=peer)),
            protected_install_root=Path("/fixed"),
        )
        action_digest = "sha256:" + "a" * 64
        attribution = {"pid": 11}
        wrapped = {
            "schema": broker.LINEAGE_ISSUANCE_SCHEMA,
            "authority": broker.LINEAGE_ISSUANCE_AUTHORITY,
            "lineage": {},
            "issuance": {},
        }
        for case in (
            "frame",
            "validation",
            "lineage",
            "core",
            "indeterminate",
            "allow",
            "block",
            "delivery",
            "hold_cleanup",
            "interrupt",
        ):
            with self.subTest(case=case), ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        broker, "_peer_credentials", return_value=(22, 3, 4)
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        broker,
                        "_read_frame",
                        side_effect=RuntimeActionBrokerError("secret frame")
                        if case == "frame"
                        else None,
                        return_value=wrapped,
                    )
                )
                stack.enter_context(
                    mock.patch.object(broker, "_validate_config", return_value={})
                )
                stack.enter_context(
                    mock.patch.object(
                        broker,
                        "_issued_submission",
                        side_effect=RuntimeActionBrokerError("secret validation")
                        if case == "validation"
                        else None,
                        return_value=(
                            {},
                            {"request_digest": action_digest},
                            attribution,
                            None,
                            None,
                        ),
                    )
                )

                @contextmanager
                def lineage(*_args, case=case, **_kwargs):
                    if case == "lineage":
                        raise broker.RuntimeActionObservationPublisherError(
                            "secret lineage"
                        )
                    yield {}
                    if case == "hold_cleanup":
                        raise broker.RuntimeActionObservationPublisherError(
                            "secret cleanup"
                        )

                stack.enter_context(
                    mock.patch.object(
                        broker, "hold_runtime_active_skill_lineage", side_effect=lineage
                    )
                )
                result = {
                    "request_digest": action_digest,
                    "verdict": "BLOCK" if case == "block" else "ALLOW",
                    "effect_status": "NOT_PERFORMED" if case == "block" else "CREATED",
                }
                failure = {
                    "core": RuntimeActionBrokerError("secret core"),
                    "indeterminate": RuntimeActionEffectIndeterminate("secret effect"),
                    "interrupt": KeyboardInterrupt(),
                }.get(case)
                stack.enter_context(
                    mock.patch.object(
                        broker,
                        "mediate_granted_profiled_runtime_create",
                        side_effect=failure,
                        return_value=result,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        broker,
                        "_send_frame",
                        side_effect=RuntimeActionBrokerError("secret delivery")
                        if case == "delivery"
                        else None,
                    )
                )
                with _records() as records:
                    if case in {"allow", "block"}:
                        broker._handle_connection(
                            mock.Mock(), config, timeout_seconds=0.5
                        )
                    else:
                        error = (
                            KeyboardInterrupt
                            if case == "interrupt"
                            else RuntimeActionEffectIndeterminate
                            if case in {"indeterminate", "delivery", "hold_cleanup"}
                            else RuntimeActionBrokerError
                        )
                        with self.assertRaises(error):
                            broker._handle_connection(
                                mock.Mock(), config, timeout_seconds=0.5
                            )
                event = records[-1]
                self.assertNotIn(b"secret", canonical_json(event))
                if case in {"frame", "validation"}:
                    self.assertIsNone(event["action_request_digest"])
                    self.assertIsNone(event["profile_attribution_digest"])
                else:
                    self.assertEqual(event["action_request_digest"], action_digest)
                    self.assertEqual(
                        event["profile_attribution_digest"],
                        canonical_digest(attribution),
                    )
                    self.assertEqual(event["request_state"], "VALIDATED")
                if case in {"frame", "validation", "lineage"}:
                    self.assertEqual(event["outcome"], "REJECTED_BEFORE_SUBMISSION")
                elif case == "core":
                    self.assertEqual(event["outcome"], "REJECTED_BEFORE_EFFECT")
                elif case in {"indeterminate", "interrupt"}:
                    self.assertEqual(event["outcome"], "INDETERMINATE")
                else:
                    self.assertEqual(event["outcome"], "BROKER_RESULT_OBSERVED")
                    self.assertEqual(event["effect_status"], result["effect_status"])

    def test_complete_test_package_keeps_quarantine_issuer_and_legacy_regressions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            package_src = base / "src"
            shutil.copytree(
                _ROOT / "src/aragorn",
                package_src / "aragorn",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            shutil.copyfile(
                journal.__file__, package_src / "aragorn/runtime_endpoint_journal.py"
            )
            for name in (subject._WORKER, subject._SENSOR, subject._BROKER):
                raw = (_ROOT / name).read_bytes()
                if name != subject._WORKER:
                    raw = subject.quarantine._transform(raw)
                (base / name).write_bytes(subject._render(name, raw))
            (base / subject._ISSUER).write_bytes(
                subject.quarantine._transform((_ROOT / subject._ISSUER).read_bytes())
            )
            script = """
import sys, unittest
sys.path[:0] = [sys.argv[1], sys.argv[2]]
from aragorn import runtime_action_observation_publisher_v4 as sensor
from aragorn import runtime_lineage_capability_issuer as issuer
from aragorn import runtime_active_skill_lineage_v2 as lineage
assert sensor.hold_profiled_runtime_capability_issuance is issuer.hold_profiled_runtime_capability_issuance
assert issuer.hold_runtime_active_skill_lineage is lineage.hold_runtime_active_skill_lineage
names = ['tests.test_runtime_action_worker', 'tests.test_runtime_action_broker_v5', 'tests.test_runtime_action_observation_publisher_v4']
r = unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromNames(names))
assert r.wasSuccessful() and not r.skipped and r.testsRun >= 22
"""
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-W",
                    "error::ResourceWarning",
                    "-c",
                    script,
                    str(package_src),
                    str(_ROOT),
                ],
                cwd=base,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
