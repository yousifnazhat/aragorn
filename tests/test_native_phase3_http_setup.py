"""New eight-writer controller seams using inert writers; no native operations."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import runtime_http_action as http
from aragorn.oci_worker_protocol import canonical_json
from scripts import materialize_native_phase3_http_setup as renderer

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = {
    "container_id": "b" * 64,
    "boot_id": "00000000-0000-0000-0000-000000000001",
    "netns_device": 4,
    "netns_inode": 123,
}
BINDING = {
    "schema": http.BINDING_SCHEMA,
    "fixture": FIXTURE,
    "expected_broker_uid": 996,
    "expected_broker_gid": 997,
}


def rendered():
    return renderer.render({renderer.SOURCE: (ROOT / renderer.SOURCE).read_bytes()})[
        renderer.SOURCE
    ]


class HttpSetupTests(unittest.TestCase):
    def setUp(self):
        self.subject = ModuleType("scripts._http_setup_test")
        self.subject.__package__ = "scripts"
        exec(compile(rendered(), renderer.SOURCE, "exec"), self.subject.__dict__)
        self.events = []
        self.writer_inputs = None
        self.stage = {
            "files": [
                {
                    "path": "/inert/file-" + str(i),
                    "source_name": "inert/source-" + str(i),
                    "mode": "0644",
                    "bytes": 1,
                    "digest": "sha256:" + "a" * 64,
                }
                for i in range(93)
            ]
        }

    def test_renderer_rejects_changed_or_missing_predecessor(self):
        raw = (ROOT / renderer.SOURCE).read_bytes()
        for original in (
            {},
            {renderer.SOURCE: raw + b"\n"},
            {renderer.SOURCE: bytearray(raw)},
        ):
            with self.assertRaises(renderer.NativeHttpSetupRenderError):
                renderer.render(original)

    def test_full_runtime_inventory_and_duplicate_refusal(self):
        self.assertEqual(len(self.subject._overrides(self.stage)), 93)
        self.stage["files"][-1] = self.stage["files"][0]
        with self.assertRaises(self.subject.NativeCommonCaseSetupError):
            self.subject._overrides(self.stage)

    def test_old_inventory_refused(self):
        self.stage["files"] = self.stage["files"][:74]
        with self.assertRaises(self.subject.NativeCommonCaseSetupError):
            self.subject._overrides(self.stage)

    def test_partial_provisioning_report_is_detached_bounded_and_secret_safe(self):
        failure = OSError("secret diagnostic")
        observed = {
            "schema": "aragorn/runtime-http-provisioning/v1",
            "created": True,
            "bytes_written": None,
            "completed": False,
            "binding_digest": "sha256:" + "a" * 64,
            "cleanup_failed": True,
            "activation_performed": False,
            "phase3_exit_eligible": False,
        }
        failure.http_provisioning_observation = observed
        kept = self.subject._http_partial_observation(failure)
        self.assertEqual(kept, observed)
        self.assertIsNot(kept, observed)
        failure.http_provisioning_observation = observed | {"secret": "must not export"}
        self.assertEqual(
            self.subject._http_partial_observation(failure),
            {"status": "UNCLASSIFIED_PROVISIONING_OBSERVATION_NOT_EXPORTED"},
        )

    def test_six_helper_composition_is_exact_and_compiles_without_execution(self):
        from scripts import materialize_native_phase3_http_identity as identity
        from scripts import materialize_native_phase3_http_preparation as preparation
        from scripts import materialize_native_phase3_http_writer as writer

        names = (
            set(renderer.INPUTS)
            | set(identity.INPUTS)
            | set(preparation.INPUTS)
            | set(writer.INPUTS)
        )
        sources = {name: (ROOT / name).read_bytes() for name in names}
        outputs = renderer.compose(sources)
        self.assertEqual(len(outputs), 6)
        self.assertEqual(set(outputs), names)
        for name, raw in outputs.items():
            compile(raw, name, "exec")
        self.assertEqual(outputs[renderer.SOURCE], rendered())
        for inputs in ({}, sources | {"extra.py": b"unexpected"}):
            with self.assertRaises(renderer.NativeHttpSetupRenderError):
                renderer.compose(inputs)

    def harness(
        self,
        stack,
        *,
        duplicate=False,
        skip=False,
        fail_after_intent=False,
        post_guard=False,
        cleanup_guard=False,
    ):
        subject = self.subject
        p37b = SimpleNamespace(
            _write_document=Mock(), capability=SimpleNamespace(_write_control=Mock())
        )
        units = {
            unit: {
                "Id": unit,
                "ActiveState": "inactive",
                "MainPID": "0",
                "ControlPID": "0",
            }
            for unit in subject.measurement._UNITS
        }
        native = SimpleNamespace(
            _STARTUP_CODE={},
            provision=SimpleNamespace(_create_document=Mock()),
            _activate=Mock(side_effect=AssertionError("must not activate")),
            setup_prior=SimpleNamespace(_require_fixture=Mock()),
            prior=SimpleNamespace(_stop_fixture=Mock(return_value=units)),
            _sources=Mock(return_value={"all93": True}),
        )
        self.native = native
        self.raw_inputs = {
            path: canonical_json({"inert": path})
            for path in subject.predecessor.writer_parent.DYNAMIC_PATHS
        }

        def prepare(*, expected_http_fixture, http_attempt_id, http_binding_writer):
            self.assertEqual(expected_http_fixture, FIXTURE)
            self.assertEqual(http_attempt_id, "p3-lab-a001")
            self.events.append("intent")
            if not skip:
                http_binding_writer(canonical_json(BINDING))
            if duplicate:
                http_binding_writer(canonical_json(BINDING))
            if fail_after_intent:
                raise RuntimeError("secret diagnostic")
            self.events.append("seven-writers")
            for path, raw in self.raw_inputs.items():
                value = subject.preparation.old._parse(raw)
                if path == subject.predecessor.identity._GENESIS:
                    native.provision._create_document(1, Path(path).name, raw, [])
                elif path == subject.predecessor.identity._POLICY:
                    p37b.capability._write_control(Path(path), value)
                else:
                    p37b._write_document(Path(path), value)
            native._activate(None, "not-a-real-token")

        native._prepare = prepare
        self.prepare = prepare
        guard_calls = 0
        context_calls = 0

        @contextmanager
        def fixture(expected):
            nonlocal context_calls
            context_calls += 1
            self.assertEqual(expected, FIXTURE)
            if cleanup_guard and context_calls == 2:
                raise ValueError("fixture changed")

            def guard():
                nonlocal guard_calls
                guard_calls += 1
                if post_guard and guard_calls == 3:
                    raise ValueError("post guard")

            yield SimpleNamespace(guard=guard)

        @contextmanager
        def store():
            yield None, None, lambda: None

        def readback(_native, inputs):
            self.writer_inputs = dict(inputs)
            self.events.append("readback")
            return {
                path: {"digest": subject.preparation.old._digest(raw)}
                for path, raw in inputs.items()
            }

        self.build = Mock(return_value={"inert": "built"})
        stack.enter_context(patch.object(subject, "owned_http_fixture", fixture))
        stack.enter_context(patch.object(subject.predecessor, "_environment"))
        stack.enter_context(
            patch.object(subject.predecessor.package, "_native", return_value=native)
        )
        stack.enter_context(
            patch.object(subject.predecessor.writer_parent, "_p37b", return_value=p37b)
        )
        stack.enter_context(patch.object(subject, "_inputs", return_value=self.stage))
        stack.enter_context(
            patch.object(
                subject, "_implementation_readback", return_value={"source": True}
            )
        )
        stack.enter_context(
            patch.object(
                subject.measurement,
                "require_native_measurement_unused",
                return_value={},
            )
        )
        stack.enter_context(patch.object(subject, "_ingress_absent", return_value={}))
        stack.enter_context(patch.object(subject, "_fresh_store", store))
        stack.enter_context(patch.object(subject, "_writer_readback", readback))
        stack.enter_context(
            patch.object(
                subject.preparation, "prepare_native_common_deployment", self.build
            )
        )
        stack.enter_context(
            patch.object(
                subject, "_retain_preparation", return_value={"retained": True}
            )
        )

    def run_setup(self, **updates):
        return self.subject.prepare_common_native_setup(
            **(
                {
                    "expected_container_id": FIXTURE["container_id"],
                    "expected_setup_digest": "sha256:" + "a" * 64,
                    "expected_http_fixture": deepcopy(FIXTURE),
                    "http_attempt_id": "p3-lab-a001",
                    "case_id": "ADM-02/direct-write",
                    "nonce": "c" * 64,
                    "source_record_raw": b"{}",
                    "implementation_source_raws": {},
                    "static_pin_manifest_raw": b"{}",
                    "staged_profile_raw": b"{}",
                    "baseline_capture_raw": b"{}",
                }
                | updates
            )
        )

    def test_eight_intents_read_back_and_stop_before_activation(self):
        with ExitStack() as stack:
            self.harness(stack)
            report = self.run_setup()
        self.assertEqual(report["status"], "PREPARED_NOT_ACTIVATED", report)
        self.assertEqual(len(self.writer_inputs), 8)
        self.assertEqual(
            self.writer_inputs[str(http.BINDING_PATH)], canonical_json(BINDING)
        )
        self.assertEqual(len(report["setup_state"]["provisioning_file_digests"]), 8)
        self.assertEqual(report["setup_state"]["activation_count"], 0)
        self.assertEqual(self.events[:3], ["intent", "seven-writers", "readback"])
        self.native._activate.assert_not_called()
        self.assertIs(self.native._prepare, self.prepare)
        self.native.prior._stop_fixture.assert_called_once()
        for name in self.subject._FALSE:
            self.assertIs(report[name], False)
        self.assertNotIn("not-a-real-token", str(report))

    def test_duplicate_http_writer_intent_refuses_before_old_writers(self):
        with ExitStack() as stack:
            self.harness(stack, duplicate=True)
            report = self.run_setup()
        self.assertEqual(report["status"], "REFUSED")
        self.assertNotIn("seven-writers", self.events)
        self.build.assert_not_called()
        self.native._activate.assert_not_called()

    def test_missing_http_intent_refuses_before_preparation(self):
        with ExitStack() as stack:
            self.harness(stack, skip=True)
            report = self.run_setup()
        self.assertEqual(report["status"], "REFUSED")
        self.build.assert_not_called()
        self.native._activate.assert_not_called()

    def test_partial_writer_failure_preserves_intent_and_cleans_once(self):
        with ExitStack() as stack:
            self.harness(stack, fail_after_intent=True)
            report = self.run_setup()
        self.assertEqual(report["status"], "REFUSED")
        self.assertEqual(
            report["http_writer_intent_digest"],
            self.subject.preparation.old._digest(canonical_json(BINDING)),
        )
        self.assertNotIn("secret diagnostic", str(report))
        self.native.prior._stop_fixture.assert_called_once()
        self.assertIs(self.native._prepare, self.prepare)

    def test_changed_fixture_refuses_before_writes(self):
        with ExitStack() as stack:
            self.harness(stack)
            report = self.run_setup(
                expected_http_fixture=FIXTURE | {"container_id": "d" * 64}
            )
        self.assertEqual(report["status"], "REFUSED")
        self.assertEqual(self.events, [])
        self.native.prior._stop_fixture.assert_not_called()

    def test_postcondition_failure_is_not_prepared(self):
        with ExitStack() as stack:
            self.harness(stack, post_guard=True)
            report = self.run_setup()
        self.assertEqual(report["status"], "REFUSED")
        self.assertIn("HTTP_FIXTURE_AFTER", report["postcondition_failures"])

    def test_cleanup_identity_failure_never_stops_unowned_services(self):
        with ExitStack() as stack:
            self.harness(stack, cleanup_guard=True)
            report = self.run_setup()
        self.assertEqual(report["status"], "REFUSED")
        self.assertEqual(
            report["cleanup_failure"], "OWNED_FOUR_SERVICE_CLEANUP_UNCONFIRMED"
        )
        self.native.prior._stop_fixture.assert_not_called()
