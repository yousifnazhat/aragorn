"""Inert private-retention host gates; no guest, service, or acceptance attempt."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from io import BytesIO, StringIO
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from aragorn.cas import CAS
from aragorn import native_phase3_common_measurement_capture as measurement
from scripts import capture_native_phase3_common_attempt as subject
from scripts import retain_native_common_measurement_inputs as private_inputs
from tests import test_native_common_attempt_host as host_data


class NativeCommonAttemptPrivateHostTests(unittest.TestCase):
    def setUp(self):
        # Compose only the historical data/mocks; never inherit or invoke its tests.
        self.host = host_data.NativeCommonAttemptHostTests()
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.private = CAS(self.root / "private")
        self.store, self.pin = self.host.store, self.host.pin

    def report(self, capture):
        grant = "sha256:" + "1" * 64
        rows = [{"digest": grant, "bytes": 17}]
        fixture = {
            "container_id": capture["fixture_container"],
            "name": capture["fixture_name"],
            "owner": capture["fixture_owner"],
            "source_commit": capture["source"]["commit"],
            "image": subject.native._IMAGE,
            "network_mode": "none",
            "pid": 71,
            "started_at": "2026-10-06T00:00:00.000000000Z",
        }
        source = {
            "digest": grant,
            "bytes": 17,
            "identity": [1, 2, stat.S_IFREG | 0o444, 0, 0, 1, 17, 3, 4],
        }
        return {
            "schema": private_inputs.SCHEMA,
            "authority": private_inputs.AUTHORITY,
            "status": "PRIVATE_INPUTS_RETAINED",
            "container_id": capture["fixture_container"],
            "prepared_digest": "sha256:" + "2" * 64,
            "binding_digest": "sha256:" + "3" * 64,
            "grant_digest": grant,
            "grant_bytes": 17,
            "input_blobs": rows,
            "input_set_digest": subject._API._digest(subject.canonical_json(rows)),
            "fixture_before": deepcopy(fixture),
            "fixture_after": deepcopy(fixture),
            "grant_source_before": deepcopy(source),
            "grant_source_after": deepcopy(source),
            "scratch_directory": str(self.private.root / private_inputs.SCRATCH_NAME),
            "copy_count": 1,
            "input_validation_complete": True,
            "postcondition_failures": [],
            "refusal": None,
            **dict.fromkeys(private_inputs._FALSE, False),
        }

    def retain(self, *, capture, public_cas, private_cas):
        self.host.events.append("private-retain")
        self.assertTrue(capture["guest_publication"]["complete"])
        self.assertTrue(capture["private_input_transfer_attempted"])
        self.assertIs(type(public_cas), CAS)
        self.assertTrue(public_cas.read_only)
        self.assertEqual(public_cas.root, self.store.root)
        self.assertIs(private_cas, self.private)
        self.assertIsNone(capture["cleanup"])
        return self.report(capture)

    @contextmanager
    def lifecycle_mocks(self):
        with self.host.capture_mocks() as stack:
            # This lifecycle fixture has no genuine attempt plan. Pure consumer
            # tests exercise that join; keep the public metadata sanitizer real.
            stack.enter_context(patch.object(subject, "_validate_private_retention"))
            yield

    def capture(self, *, private_guard=None):
        return subject._capture(
            self.store,
            self.pin,
            private_store=self.private,
            private_guard=private_guard,
        )

    def assert_preserved(self, result):
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["fixture_container"], self.host.container)
        self.assertTrue(result["private_input_transfer_attempted"])
        self.assertTrue(result["fixture_preserved"])
        self.host.cleanup.assert_not_called()
        self.host.suspend.assert_called_once()
        self.host.invoke.assert_called_once()
        self.assertIsNotNone(result["runtime_after"])
        self.assertIsNotNone(result["parent_after"])
        self.assertTrue(all(result[key] is False for key in subject._FALSE))

    def test_private_retention_and_source_readback_precede_single_owned_cleanup(self):
        with (
            self.lifecycle_mocks(),
            patch.object(
                subject.private_inputs,
                "retain_native_common_measurement_inputs",
                side_effect=self.retain,
            ) as retain,
        ):
            result = self.capture()
        self.assertEqual(result["status"], "CAPTURED_BOUNDED_ATTEMPT")
        self.assertTrue(result["private_input_transfer_attempted"])
        self.assertEqual(result["private_measurement_inputs"], self.report(result))
        self.assertFalse(result["fixture_preserved"])
        retain.assert_called_once()
        self.host.cleanup.assert_called_once()
        self.host.suspend.assert_not_called()
        events = self.host.events
        position = events.index("private-retain")
        self.assertEqual(events[position - 1], "source")
        self.assertEqual(events[position + 1], "source")
        self.assertLess(position + 1, events.index("cleanup"))
        self.assertTrue(all(result[key] is False for key in subject._FALSE))

    def test_failed_transfer_retains_attached_metadata_without_retry_or_cleanup(self):
        retained = {}

        def fail(**arguments):
            report = self.retain(**arguments)
            report.update(status="REFUSED", input_validation_complete=False)
            report["refusal"] = {
                "phase": "PRIVATE_FILE_TRANSFER",
                "reason": "PRIVATE_INPUT_RETENTION_REFUSED",
            }
            retained.update(report)
            error = ValueError("PRIVATE_BYTES_MUST_NOT_ESCAPE")
            error._native_common_measurement_inputs = report
            raise error

        with (
            self.lifecycle_mocks(),
            patch.object(
                subject.private_inputs,
                "retain_native_common_measurement_inputs",
                side_effect=fail,
            ) as retain,
        ):
            result = self.capture()
        self.assert_preserved(result)
        retain.assert_called_once()
        self.assertEqual(result["private_measurement_inputs"], retained)
        self.assertNotIn("PRIVATE_BYTES_MUST_NOT_ESCAPE", json.dumps(result))
        self.assertTrue(result["guest_publication"]["complete"])

    def test_incomplete_or_rebound_private_report_cannot_unlock_cleanup(self):
        for mutation in (
            {"status": "REFUSED"},
            {"input_validation_complete": False},
            {"copy_count": 2},
            {"phase3_exit_eligible": True},
            {"container_id": "f" * 64},
            {"postcondition_failures": ["ORIGINAL_GRANT_AFTER_REFUSED"]},
        ):
            with self.subTest(mutation=mutation):

                def incomplete(**arguments):
                    return self.retain(**arguments) | mutation

                with (
                    self.lifecycle_mocks(),
                    patch.object(
                        subject.private_inputs,
                        "retain_native_common_measurement_inputs",
                        side_effect=incomplete,
                    ) as retain,
                ):
                    result = self.capture()
                self.assert_preserved(result)
                retain.assert_called_once()

    def test_private_interrupt_identity_and_metadata_survive_final_readbacks(self):
        interruption = KeyboardInterrupt("PRIVATE_INTERRUPT_MUST_NOT_ESCAPE")
        retained = {}

        def interrupt(**arguments):
            report = self.retain(**arguments)
            report.update(status="REFUSED", input_validation_complete=False)
            report["refusal"] = {
                "phase": "PRIVATE_FILE_TRANSFER",
                "reason": "PRIVATE_INPUT_RETENTION_REFUSED",
            }
            retained.update(report)
            interruption._native_common_measurement_inputs = report
            raise interruption

        with (
            self.lifecycle_mocks(),
            patch.object(
                subject.private_inputs,
                "retain_native_common_measurement_inputs",
                side_effect=interrupt,
            ) as retain,
            self.assertRaises(KeyboardInterrupt) as caught,
        ):
            self.capture()
        self.assertIs(caught.exception, interruption)
        result = interruption._native_common_attempt_host_capture
        self.assert_preserved(result)
        self.assertEqual(result["private_measurement_inputs"], retained)
        self.assertNotIn("PRIVATE_INTERRUPT_MUST_NOT_ESCAPE", json.dumps(result))
        retain.assert_called_once()

    def test_source_change_after_private_retention_still_preserves_owned_fixture(self):
        with (
            self.lifecycle_mocks(),
            patch.object(
                subject.private_inputs,
                "retain_native_common_measurement_inputs",
                side_effect=self.retain,
            ) as retain,
        ):

            def source(_):
                self.host.events.append("source")
                if "private-retain" in self.host.events:
                    raise ValueError("inert source changed after private handoff")
                return self.host.source

            self.host.source_guard.side_effect = source
            result = self.capture()
        self.assert_preserved(result)
        retain.assert_called_once()
        self.assertIn("SOURCE_READBACK_REFUSED", result["postcondition_failures"])

    def test_private_destination_guard_failure_precedes_cleanup_and_preserves_fixture(
        self,
    ):
        def guard():
            self.host.events.append("private-guard")
            if "private-retain" in self.host.events:
                raise ValueError("inert private destination custody changed")

        with (
            self.lifecycle_mocks(),
            patch.object(
                subject.private_inputs,
                "retain_native_common_measurement_inputs",
                side_effect=self.retain,
            ) as retain,
        ):
            result = self.capture(private_guard=guard)
        self.assert_preserved(result)
        retain.assert_called_once()
        events = self.host.events
        position = events.index("private-retain")
        self.assertIn("private-guard", events[:position])
        self.assertIn("private-guard", events[position + 1 :])

        # Direct API callers without an outer guard still bind the original
        # private directory inode, not a replacement at the same pathname.
        original = self.root / "retained-before-rebind"

        def rebind(**arguments):
            report = self.retain(**arguments)
            self.private.root.rename(original)
            CAS(self.private.root)
            return report

        with (
            self.lifecycle_mocks(),
            patch.object(
                subject.private_inputs,
                "retain_native_common_measurement_inputs",
                side_effect=rebind,
            ) as retain,
        ):
            result = self.capture()
        self.assert_preserved(result)
        retain.assert_called_once()
        self.assertTrue(original.is_dir())

    def test_raw_grant_in_success_or_exception_metadata_never_reaches_public_capture(
        self,
    ):
        for failed in (False, True):
            with self.subTest(failed=failed):

                def secret(**arguments):
                    report = self.retain(**arguments)
                    report["raw_grant"] = "SECRET_SENTINEL"
                    if failed:
                        report.update(status="REFUSED", input_validation_complete=False)
                        report["refusal"] = {
                            "phase": "PRIVATE_FILE_TRANSFER",
                            "reason": "PRIVATE_INPUT_RETENTION_REFUSED",
                        }
                        error = ValueError("SECRET_SENTINEL")
                        error._native_common_measurement_inputs = report
                        raise error
                    return report

                with (
                    self.lifecycle_mocks(),
                    patch.object(
                        subject.private_inputs,
                        "retain_native_common_measurement_inputs",
                        side_effect=secret,
                    ) as retain,
                ):
                    result = self.capture()
                self.assert_preserved(result)
                retain.assert_called_once()
                self.assertNotIn("SECRET_SENTINEL", json.dumps(result))
                self.assertNotIn("raw_grant", json.dumps(result))
                self.assertEqual(
                    result["private_measurement_inputs"],
                    {
                        "schema": "aragorn/native-common-measurement-input-retention-refusal/v1",
                        "status": "REFUSED",
                        "reason": "PRIVATE_INPUT_METADATA_REFUSED",
                    },
                )

    def test_private_store_aliases_and_readonly_destination_are_rejected(self):
        child = CAS(self.store.root / "nested-private")
        for public, private in (
            (self.store, self.store),
            (self.store, child),
            (child, self.store),
            (self.store, object()),
        ):
            with (
                self.subTest(
                    public=type(public).__name__, private=type(private).__name__
                ),
                self.assertRaises(Exception),
            ):
                subject._separate_stores(public, private)
        subject._separate_stores(self.store, self.private)
        subject._separate_stores(CAS(self.store.root, read_only=True), self.private)
        with patch.object(subject, "_inspect") as inspect, self.assertRaises(Exception):
            subject._capture(
                self.store,
                self.pin,
                private_store=CAS(self.private.root, read_only=True),
            )
        inspect.assert_not_called()

    def test_capture_cli_requires_private_destination_before_any_invocation(self):
        with (
            patch.object(subject, "_capture") as capture,
            redirect_stderr(StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            subject.main(
                [
                    "capture",
                    "--cas",
                    str(self.store.root),
                    "--expected-input-digest",
                    self.pin,
                    "--out",
                    str(self.root / "capture.json"),
                ]
            )
        self.assertEqual(caught.exception.code, 2)
        capture.assert_not_called()
        output = StringIO()
        with patch.object(subject, "_capture") as capture, redirect_stdout(output):
            status = subject.main(
                [
                    "capture",
                    "--cas",
                    str(self.store.root),
                    "--expected-input-digest",
                    self.pin,
                    "--private-cas",
                    str(self.private.root),
                    "--out",
                    str(self.root / "capture.json"),
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "REFUSED")
        capture.assert_not_called()
        self.assertFalse((self.root / "capture.json").exists())

    def test_measurement_cli_is_offline_and_forwards_explicit_caller_expectations(self):
        raw = b'{"inert-capture-only":true}'
        pin = self.store.put(BytesIO(raw), max_bytes=len(raw))
        expected = {
            "expected_worker": {"pid": 1, "uid": 2, "gid": 3, "start_time_ticks": 4},
            "expected_broker_process": {
                "pid": 5,
                "uid": 6,
                "gid": 7,
                "start_time_ticks": 8,
            },
            "expected_gateway": {"pid": 9, "uid": 10, "gid": 11},
            "expected_sink_accounts": {
                "broker_uid": 6,
                "broker_gid": 12,
                "runtime_gid": 3,
            },
        }
        expectations = self.root / "expectations.json"
        expectations.write_bytes(subject.canonical_json(expected))
        checked = {
            "status": "RETAINED_NATIVE_MEASUREMENT_SEMANTICS_REPLAYED",
            **dict.fromkeys(subject._FALSE, False),
        }
        output = StringIO()
        with (
            patch.object(
                subject,
                "_capture",
                side_effect=AssertionError("offline command cannot capture"),
            ),
            patch.object(
                measurement,
                "verify_native_common_measurement_capture",
                return_value=checked,
            ) as verify,
            redirect_stdout(output),
        ):
            status = subject.main(
                [
                    "verify-measurement",
                    "--cas",
                    str(self.store.root),
                    "--private-cas",
                    str(self.private.root),
                    "--expected-capture-digest",
                    pin,
                    "--measurement-expectations",
                    str(expectations),
                ]
            )
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue()), checked)
        verify.assert_called_once()
        arguments = verify.call_args
        self.assertEqual(arguments.args, (raw,))
        self.assertEqual(arguments.kwargs["expected_capture_digest"], pin)
        for name, value in expected.items():
            self.assertEqual(arguments.kwargs[name], value)
        for name, store in (
            ("public_cas", self.store),
            ("private_input_cas", self.private),
        ):
            self.assertIs(type(arguments.kwargs[name]), CAS)
            self.assertTrue(arguments.kwargs[name].read_only)
            self.assertEqual(arguments.kwargs[name].root, store.root)


if __name__ == "__main__":
    unittest.main()
