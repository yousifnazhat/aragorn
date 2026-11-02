"""HTTP94 composition and new preactivation checks only; never activation."""

import ast
from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from aragorn import runtime_http_readiness as readiness
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import stage_runtime_phase3_http_ready_profile as subject


class HttpReadyProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original, cls.replacements, cls.inputs = subject._verified_payloads()
        cls.final = cls.original | cls.replacements

    def payload(self, source):
        return self.final[subject._destination(source)[0]][2]

    def test_exact_frozen_predecessor_and_finite_changed_inventory(self):
        self.assertEqual(len(self.original), 93)
        self.assertEqual(len(self.final), 94)
        self.assertEqual(len(subject.base._directories(self.final)), 21)
        self.assertEqual(
            set(self.final) - set(self.original),
            {
                subject.renderer.RUNTIME_DESTINATION,
            },
        )
        self.assertEqual(
            {row[0] for row in self.replacements.values()},
            {
                subject.predecessor._MEASUREMENT_SERVICE,
                subject.predecessor._BROKER_UNIT,
                subject._HELPER,
                subject._MEASUREMENT,
                subject._PLAN,
                subject._PRIOR,
                subject._CAP_ACTIVATOR,
                subject._ACTIVATOR,
            },
        )
        for name, pin in subject._SOURCE_PINS.items():
            raw = (subject._ROOT / name).read_bytes()
            self.assertEqual((len(raw), subject.base.overlay._digest(raw)), pin)
        for path in set(self.original) - set(self.replacements):
            self.assertEqual(self.final[path], self.original[path])
        self.assertNotIn(
            b"def validate_activation_readiness():", self.inputs[subject._HELPER]
        )
        self.assertEqual(self.payload(subject._HELPER).count(subject._VALIDATE), 1)

    def test_only_new_rendered_python_and_shell_syntax(self):
        for source, _mode, raw in self.replacements.values():
            if source.endswith(".py"):
                compile(raw, source, "exec")
            elif source in (subject._ACTIVATOR, subject._CAP_ACTIVATOR):
                result = subprocess.run(
                    ["/bin/sh", "-n"],
                    input=raw,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_writer_plan_and_independent_verifier_share_exact_22_sources(self):
        expected = set(subject.MEASUREMENT_SOURCE_NAMES)
        self.assertEqual(len(expected), 22)
        self.assertIn("runtime_http_readiness.py", expected)
        for source in (subject._MEASUREMENT, subject._PLAN, subject._PRIOR):
            self.assertEqual(subject._inventory(self.payload(source)), expected)
        self.assertEqual(
            self.payload(subject._EFFECTIVE),
            self.original[subject._destination(subject._EFFECTIVE)[0]][2],
        )

    def test_both_activators_check_readiness_before_mutation_and_pin_current_sources(
        self,
    ):
        cap = self.payload(subject._CAP_ACTIVATOR)
        worker = self.payload(subject._ACTIVATOR)
        for raw, mutation in (
            (cap, b"activation_lock="),
            (worker, b"trap rollback EXIT"),
            (worker, b"armed=1"),
        ):
            self.assertLess(raw.index(subject._READY_GUARD), raw.index(mutation))
            self.assertLess(
                raw.index(b"ARAGORN_READY_SOURCE_PINS"), raw.index(subject._READY_GUARD)
            )
        self.assertEqual(cap.count(subject._READY_GUARD), 1)
        self.assertEqual(worker.count(subject._READY_GUARD), 2)
        self.assertLess(
            worker.rindex(subject._READY_GUARD),
            worker.index(subject.predecessor._ACTIVATION_GUARD),
        )
        for path, (source, mode, raw) in self.replacements.items():
            if source in (subject._CAP_ACTIVATOR, subject._ACTIVATOR):
                continue
            row = f"{mode:o} {subject.base.overlay._digest(raw)[7:]} /{path}\n".encode()
            self.assertEqual(cap.count(row), 1)
            # The unit is pinned by require_unit_file later, not by the module
            # manifest; the new early read-only inventory adds its sole row.
            self.assertEqual(
                worker.count(row),
                1 if source == subject.predecessor._BROKER_UNIT else 2,
            )
            if source == subject.predecessor._BROKER_UNIT:
                self.assertIn(
                    b'"$broker_unit" \\\n    '
                    + subject.base.overlay._digest(raw)[7:].encode(),
                    worker,
                )
            if path in self.original:
                old_digest = subject.base.overlay._digest(self.original[path][2])[
                    7:
                ].encode()
                self.assertNotIn(old_digest, cap)
                self.assertNotIn(old_digest, worker)
        cap_path, mode = subject._destination(subject._CAP_ACTIVATOR)
        cap_row = (
            f"{mode:o} {subject.base.overlay._digest(cap)[7:]} /{cap_path}\n".encode()
        )
        self.assertEqual(worker.count(cap_row), 1)
        old_cap = subject.base.overlay._digest(self.original[cap_path][2])[7:].encode()
        self.assertNotIn(old_cap, worker)

    def test_real_broker_startup_seam_and_credential_are_only_staged(self):
        service = self.payload(subject.predecessor._MEASUREMENT_SERVICE)
        self.assertLess(
            service.index(b"run_startup_readiness()"),
            service.index(b"serve_runtime_action_broker_v5(config)"),
        )
        unit = self.payload(subject.predecessor._BROKER_UNIT)
        self.assertIn(b"ReadOnlyPaths=/etc/aragorn/runtime-http-readiness.json\n", unit)
        self.assertIn(b"Restart=no\n", unit)
        self.assertIn(b"CapabilityBoundingSet=\n", unit)
        self.assertIn(b"NoNewPrivileges=yes\n", unit)
        self.assertNotIn("etc/aragorn/runtime-http-readiness.json", self.final)

    def test_tampered_source_pin_refuses_before_output_mutation(self):
        name = next(iter(subject._SOURCE_PINS))
        pins = {**subject._SOURCE_PINS, name: (0, "sha256:" + "0" * 64)}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "ready"
            with (
                patch.object(subject, "_SOURCE_PINS", pins),
                patch.object(
                    subject.predecessor, "stage_runtime_phase3_http_profile"
                ) as stage,
            ):
                with self.assertRaises(ValueError):
                    subject.stage_runtime_phase3_http_ready_profile(output)
                stage.assert_not_called()
                self.assertFalse(output.exists())

    def test_fresh_inert_stage_report_binds_actual_files_and_keeps_claims_false(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "ready"
            report = subject.stage_runtime_phase3_http_ready_profile(output)
            self.assertEqual(report["schema"], subject._SCHEMA)
            self.assertTrue(report["http_readiness_paths_staged"])
            for key in (
                "http_readiness_provisioned",
                "broker_readiness_observed",
                "broker_restricted_readiness_verified",
                "http_fixture_provisioned",
                "http_runtime_activated",
                "http_collected",
                "phase3_qualification",
                "measurement_collected",
                "run_qualification",
            ):
                self.assertIs(report[key], False)
            self.assertEqual(len(report["files"]), 94)
            self.assertEqual(len(report["directories"]), 21)
            self.assertEqual(
                set(report["binding_source_pins"]),
                set(subject.MEASUREMENT_SOURCE_NAMES),
            )
            self.assertEqual(
                report["measurement_source_names"],
                list(subject.MEASUREMENT_SOURCE_NAMES),
            )
            sources = {
                row["name"]: (row["bytes"], row["digest"])
                for row in report["source_inputs"]
            }
            for name, pin in subject._SOURCE_PINS.items():
                self.assertEqual(sources[name], pin)
            for path, (source, mode, raw) in self.final.items():
                self.assertEqual((output / path).read_bytes(), raw)
                self.assertEqual((output / path).stat().st_mode & 0o777, mode)
                filename = Path(source).name
                if filename in report["binding_source_pins"]:
                    self.assertEqual(
                        report["binding_source_pins"][filename],
                        subject.base.overlay._digest(raw),
                    )
            dependency = next(
                row
                for row in report["new_dependencies"]
                if row["name"] == subject._HELPER
            )
            self.assertEqual(
                dependency["digest"],
                subject.base.overlay._digest(self.payload(subject._HELPER)),
            )
            # This single new staging check also supplies deterministic pins to
            # the next finite helper composition; it is not a second stage run.
            report_raw = canonical_json(report)
            print(
                canonical_json(
                    {
                        "http_ready_stage_metadata": {
                            "report_bytes": len(report_raw),
                            "report_digest": subject.base.overlay._digest(report_raw),
                            "counts": {
                                key: len(report[key])
                                for key in (
                                    "files",
                                    "source_inputs",
                                    "new_dependencies",
                                    "directories",
                                )
                            },
                            "changed_files": [
                                row
                                for row in report["files"]
                                if row["path"].lstrip("/") in self.replacements
                            ],
                        }
                    }
                ).decode()
            )

    def test_existing_destdir_refuses_without_invoking_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve()
            with patch.object(
                subject.predecessor, "stage_runtime_phase3_http_profile"
            ) as stage:
                with self.assertRaises(subject.Phase3HttpReadyStageError):
                    subject.stage_runtime_phase3_http_ready_profile(output)
                stage.assert_not_called()


class HttpReadyActivationGuardTests(unittest.TestCase):
    def setUp(self):
        self.binding = {
            "schema": "aragorn/runtime-http-fixture-binding/v1",
            "fixture": {
                "container_id": "a" * 64,
                "boot_id": "11111111-2222-3333-4444-555555555555",
                "netns_device": 4,
                "netns_inode": 9,
            },
            "expected_broker_uid": 996,
            "expected_broker_gid": 997,
        }
        self.request = readiness.build_readiness_input(
            fixture_binding=self.binding, readiness_nonce="b" * 32
        )
        self.raw = canonical_json(self.request)
        self.metadata = {"identity": [1, 2, 3], "bytes": len(self.raw)}
        self.held = SimpleNamespace(guard=Mock())
        self.context = MagicMock()
        self.context.__enter__.return_value = self.held
        self.context.__exit__.return_value = False
        self.read = Mock(return_value=(self.raw, self.metadata))
        self.load = Mock(return_value=deepcopy(self.binding))
        self.stopped = Mock()
        self.derive = Mock(return_value=deepcopy(self.binding))
        self.exists = Mock(return_value=False)
        self.owned = Mock(return_value=self.context)
        self.namespace = {
            "http": SimpleNamespace(load_fixture_binding=self.load),
            "provision": SimpleNamespace(
                _new_binding=self.derive, _stopped=self.stopped
            ),
            "owned_http_fixture": self.owned,
            "_read_owned": self.read,
            "_input": readiness._input,
            "_require": readiness._require,
            "os": SimpleNamespace(path=SimpleNamespace(lexists=self.exists)),
            "CREDENTIAL": readiness.CREDENTIAL,
            "CLAIM": readiness.CLAIM,
            "RESULT": readiness.RESULT,
            "canonical_digest": canonical_digest,
        }
        # Evaluate only the new function, never the staged service/module or effects.
        exec(
            compile(ast.parse(subject._VALIDATE), "<read-only-ready-guard>", "exec"),
            self.namespace,
        )
        self.guard = self.namespace["validate_activation_readiness"]

    def test_valid_bound_nonce_is_read_twice_under_held_fixture_without_any_write_api(
        self,
    ):
        self.assertEqual(self.guard(), canonical_digest(self.request))
        self.owned.assert_called_once_with(self.binding["fixture"])
        self.stopped.assert_called_once()
        self.assertEqual(self.read.call_count, 2)
        self.assertEqual(self.held.guard.call_count, 2)
        self.context.__exit__.assert_called_once()
        for call in self.read.call_args_list:
            self.assertEqual(call.args, (readiness.CREDENTIAL,))
            self.assertEqual(call.kwargs, {"uid": 0, "gid": 997, "mode": 0o440})
        self.assertNotIn("socket", self.namespace)
        self.assertNotIn("_publish_absent", self.namespace)

    def test_active_units_refuse_before_readiness_credential_read(self):
        self.stopped.side_effect = ValueError("active fixture unit")
        with self.assertRaises(ValueError):
            self.guard()
        self.read.assert_not_called()
        self.context.__exit__.assert_called_once()

    def test_changed_fixture_account_binding_refuses_before_read_or_mutation(self):
        self.derive.return_value = {**self.binding, "expected_broker_gid": 998}
        with self.assertRaises(readiness.HttpReadinessError):
            self.guard()
        self.stopped.assert_not_called()
        self.read.assert_not_called()

    def test_nonce_binding_and_noncanonical_input_each_refuse(self):
        bad_values = (
            {**self.request, "readiness_nonce": "bad"},
            {**self.request, "fixture_binding_digest": "sha256:" + "0" * 64},
            {**self.request, "timeout_ms": True},
        )
        for value in bad_values:
            with self.subTest(value=value):
                self.read.return_value = (canonical_json(value), self.metadata)
                with self.assertRaises(ValueError):
                    self.guard()
        self.read.return_value = (self.raw + b"\n", self.metadata)
        with self.assertRaises(readiness.core.RuntimeActionBrokerError):
            self.guard()

    def test_prior_claim_or_result_blocks_and_never_retries(self):
        for path in (readiness.CLAIM, readiness.RESULT):
            with self.subTest(path=path):
                self.exists.side_effect = lambda candidate: candidate == path
                self.read.reset_mock()
                with self.assertRaises(readiness.HttpReadinessError):
                    self.guard()
                self.read.assert_called_once()

    def test_changed_postread_bytes_metadata_or_fixture_refuse(self):
        for changed in (
            (self.raw + b"x", self.metadata),
            (self.raw, {**self.metadata, "identity": [9, 9, 9]}),
        ):
            with self.subTest(changed=changed):
                self.read.side_effect = [(self.raw, self.metadata), changed]
                with self.assertRaises(readiness.HttpReadinessError):
                    self.guard()
        self.read.side_effect = None
        self.load.side_effect = [deepcopy(self.binding), {}]
        with self.assertRaises(readiness.HttpReadinessError):
            self.guard()

    def test_held_fixture_or_cleanup_failure_is_not_validation_success(self):
        self.held.guard.side_effect = ValueError("fixture changed")
        with self.assertRaises(ValueError):
            self.guard()
        self.held.guard.side_effect = None
        self.context.__exit__.side_effect = OSError("fixture cleanup failure")
        with self.assertRaises(OSError):
            self.guard()


if __name__ == "__main__":
    unittest.main()
