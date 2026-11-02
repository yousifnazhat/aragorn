"""Inert private-transfer tests: local CAS only; Docker/guest/validator are doubles."""

import ast
from contextlib import ExitStack
from copy import deepcopy
from io import BytesIO
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from scripts import retain_native_common_measurement_inputs as subject


CONTAINER = "c" * 64
OWNER = "a" * 64
COMMIT = "b" * 40
PIN = "sha256:" + "b" * 64
STARTED = "2026-10-06T20:10:58.131000000Z"


class NativeCommonMeasurementInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.public_writer = CAS(self.root / "public")
        self.public = CAS(self.public_writer.root, read_only=True)
        self.private = CAS(self.root / "private")
        self.grant = canonical_json({"private_grant": "SECRET_GRANT_NEVER_PUBLIC"})
        self.grant_pin = subject._digest(self.grant)
        public_raws = (canonical_json({"public": 1}), canonical_json({"public": 2}))
        self.public_blobs = {subject._digest(raw): raw for raw in public_raws}
        for pin, raw in self.public_blobs.items():
            self.public_writer.put_expected(
                BytesIO(raw), expected_digest=pin, max_bytes=1000
            )
        self.blobs = {**self.public_blobs, self.grant_pin: self.grant}
        self.plan = {
            "prepared_raw": b'{"prepared":1}',
            "prepared_digest": PIN,
            "binding_digest": PIN,
            "source_pins": {"source": PIN},
            "input_rows": [
                {"digest": pin, "bytes": len(raw)}
                for pin, raw in sorted(self.blobs.items())
            ],
            "public_blobs": self.public_blobs,
            "grant_digest": self.grant_pin,
            "grant_bytes": len(self.grant),
            "installed_sources": {
                target: {"digest": PIN, "bytes": 1}
                for target in set(subject.planning.inputs.FIXTURE_HELPERS.values())
                | set(subject.planning.inputs.HELPER_ALIASES)
            },
        }
        self.capture = {
            "fixture_container": CONTAINER,
            "fixture_name": "aragorn-native-common-attempt-" + OWNER[:16],
            "fixture_owner": OWNER,
            "source": {"commit": COMMIT},
            "fixture_image": {"Id": subject.base.native._IMAGE},
        }
        self.fixture = {
            "container_id": CONTAINER,
            "name": self.capture["fixture_name"],
            "owner": OWNER,
            "source_commit": COMMIT,
            "image": subject.base.native._IMAGE,
            "network_mode": "none",
            "pid": 81,
            "started_at": STARTED,
        }
        self.source = {
            "digest": self.grant_pin,
            "bytes": len(self.grant),
            "identity": [1, 2, stat.S_IFREG | 0o444, 0, 0, 1, len(self.grant), 3, 4],
        }
        self.events = []

    def harness(self, stack, *, copied_mode=0o444, copy_error=None):
        self.planner = stack.enter_context(
            patch.object(
                subject.planning,
                "plan_native_common_measurement_inputs",
                return_value=deepcopy(self.plan),
            )
        )
        self.fixture_read = stack.enter_context(
            patch.object(
                subject,
                "_fixture",
                side_effect=lambda *_: (
                    self.events.append("fixture") or deepcopy(self.fixture)
                ),
            )
        )
        self.source_read = stack.enter_context(
            patch.object(
                subject,
                "_guest_source",
                side_effect=lambda *_: (
                    self.events.append("source") or deepcopy(self.source)
                ),
            )
        )

        def copied(argv, *, timeout, maximum):
            self.events.append("copy")
            self.assertEqual(argv[:-2], [*subject.base._API._DOCKER, "cp"])
            self.assertEqual(
                argv[-2],
                CONTAINER
                + ":"
                + subject.CAS_ROOT
                + "/blobs/sha256/"
                + self.grant_pin[7:9]
                + "/"
                + self.grant_pin[9:],
            )
            self.assertEqual((timeout, maximum), (30, 0))
            target = Path(argv[-1])
            self.assertEqual(
                target, self.private.root / subject.SCRATCH_NAME / subject.GRANT_NAME
            )
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, copied_mode
            )
            try:
                os.write(descriptor, self.grant)
                os.fchmod(descriptor, copied_mode)
            finally:
                os.close(descriptor)
            if copy_error is not None:
                raise copy_error
            return b""

        self.copy = stack.enter_context(
            patch.object(subject, "_command", side_effect=copied)
        )

        def validated(**arguments):
            self.events.append("validate")
            self.assertEqual(arguments["prepared_raw"], self.plan["prepared_raw"])
            self.assertEqual(arguments["expected_prepared_digest"], PIN)
            self.assertEqual(arguments["expected_binding_digest"], PIN)
            self.assertEqual(
                arguments["expected_broker_source_pins"], self.plan["source_pins"]
            )
            self.assertIs(type(arguments["source_cas"]), CAS)
            self.assertTrue(arguments["source_cas"].read_only)
            for pin, raw in self.blobs.items():
                self.assertEqual(
                    arguments["source_cas"].read(pin, max_bytes=len(raw)), raw
                )
            return {"input_blobs": dict(self.blobs)}

        self.validate = stack.enter_context(
            patch.object(
                subject,
                "validate_prepared_native_measurement_inputs",
                side_effect=validated,
            )
        )

    def run_subject(self):
        return subject.retain_native_common_measurement_inputs(
            capture=self.capture, public_cas=self.public, private_cas=self.private
        )

    def assert_private(self, report):
        wire = canonical_json(report)
        self.assertNotIn(b"SECRET", wire)
        self.assertNotIn(self.grant, wire)
        self.assertTrue(all(report[key] is False for key in subject._FALSE))
        with self.assertRaises(Exception):
            self.public.read(self.grant_pin, max_bytes=65536)

    def test_one_exact_file_copy_and_private_only_finite_cas_validation(self):
        with ExitStack() as stack:
            self.harness(stack)
            result = self.run_subject()
        self.assertEqual(result["status"], "PRIVATE_INPUTS_RETAINED")
        self.assertTrue(result["input_validation_complete"])
        self.assertEqual(result["input_blobs"], self.plan["input_rows"])
        self.assertEqual(
            result["input_set_digest"],
            subject._digest(canonical_json(self.plan["input_rows"])),
        )
        self.assertEqual(result["grant_source_before"], result["grant_source_after"])
        self.assertEqual(result["fixture_before"], result["fixture_after"])
        self.assertEqual(
            self.events, ["fixture", "source", "copy", "validate", "source", "fixture"]
        )
        self.copy.assert_called_once()
        self.validate.assert_called_once()
        self.assertEqual(self.private.read(self.grant_pin, max_bytes=65536), self.grant)
        self.assertTrue(
            (self.private.root / subject.SCRATCH_NAME / subject.GRANT_NAME).exists()
        )
        self.assert_private(result)

    def test_interrupted_copy_preserves_identical_interrupt_partial_and_final_checks(
        self,
    ):
        error = KeyboardInterrupt("SECRET_INTERRUPT")
        with ExitStack() as stack:
            self.harness(stack, copy_error=error)
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.run_subject()
        self.assertIs(caught.exception, error)
        report = error._native_common_measurement_inputs
        self.assertEqual(report["copy_count"], 1)
        self.assertFalse(report["input_validation_complete"])
        self.validate.assert_not_called()
        self.assertEqual(self.source_read.call_count, 2)
        self.assertEqual(self.fixture_read.call_count, 2)
        self.assertTrue(
            (self.private.root / subject.SCRATCH_NAME / subject.GRANT_NAME).exists()
        )
        self.assert_private(report)

    def test_copy_error_never_exposes_original_details_and_never_retries(self):
        with ExitStack() as stack:
            self.harness(stack, copy_error=RuntimeError("SECRET_SOURCE_BYTES"))
            with self.assertRaises(
                subject.NativeCommonMeasurementInputRetentionError
            ) as caught:
                self.run_subject()
        self.assertEqual(str(caught.exception), "PRIVATE_INPUT_RETENTION_REFUSED")
        self.assert_private(caught.exception._native_common_measurement_inputs)
        self.copy.assert_called_once()
        self.assertTrue(
            (self.private.root / subject.SCRATCH_NAME / subject.GRANT_NAME).exists()
        )

    def test_mutable_copied_file_and_validator_failure_keep_private_scratch(self):
        with ExitStack() as stack:
            self.harness(stack, copied_mode=0o600)
            with self.assertRaises(
                subject.NativeCommonMeasurementInputRetentionError
            ) as caught:
                self.run_subject()
        self.validate.assert_not_called()
        self.assert_private(caught.exception._native_common_measurement_inputs)
        self.assertTrue(
            (self.private.root / subject.SCRATCH_NAME / subject.GRANT_NAME).exists()
        )

    def test_validation_failure_keeps_written_private_blobs(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.validate.side_effect = ValueError("SECRET_GRANT_REJECTED")
            with self.assertRaises(
                subject.NativeCommonMeasurementInputRetentionError
            ) as caught:
                self.run_subject()
        self.assertEqual(self.private.read(self.grant_pin, max_bytes=65536), self.grant)
        self.assertFalse(
            caught.exception._native_common_measurement_inputs[
                "input_validation_complete"
            ]
        )
        self.assert_private(caught.exception._native_common_measurement_inputs)

    def test_final_source_and_fixture_checks_are_independent(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.source_read.side_effect = [
                deepcopy(self.source),
                ValueError("SECRET_SOURCE_CHANGED"),
            ]
            self.fixture_read.side_effect = [
                deepcopy(self.fixture),
                {**self.fixture, "pid": 82},
            ]
            with self.assertRaises(
                subject.NativeCommonMeasurementInputRetentionError
            ) as caught:
                self.run_subject()
        result = caught.exception._native_common_measurement_inputs
        self.assertEqual(
            result["postcondition_failures"],
            ["ORIGINAL_GRANT_AFTER_REFUSED", "OWNED_FIXTURE_AFTER_REFUSED"],
        )
        self.assertEqual(self.private.read(self.grant_pin, max_bytes=65536), self.grant)
        self.assert_private(result)

    def test_later_interrupt_is_preserved_even_after_ordinary_copy_error(self):
        interrupt = SystemExit("SECRET_FINAL_INTERRUPT")
        with ExitStack() as stack:
            self.harness(stack, copy_error=ValueError("SECRET_PRIMARY"))
            self.source_read.side_effect = [deepcopy(self.source), interrupt]
            with self.assertRaises(SystemExit) as caught:
                self.run_subject()
        self.assertIs(caught.exception, interrupt)
        self.assertEqual(self.fixture_read.call_count, 2)
        self.assert_private(interrupt._native_common_measurement_inputs)

    def test_permanent_scratch_claim_and_existing_grant_refuse_before_copy(self):
        for mode in ("scratch", "grant"):
            with self.subTest(mode=mode):
                self.private = CAS(self.root / ("private-" + mode))
                if mode == "scratch":
                    (self.private.root / subject.SCRATCH_NAME).mkdir(mode=0o700)
                else:
                    self.private.put_expected(
                        BytesIO(self.grant),
                        expected_digest=self.grant_pin,
                        max_bytes=65536,
                    )
                with ExitStack() as stack:
                    self.harness(stack)
                    with self.assertRaises(
                        subject.NativeCommonMeasurementInputRetentionError
                    ) as caught:
                        self.run_subject()
                    self.copy.assert_not_called()
                    self.validate.assert_not_called()
                    self.assert_private(
                        caught.exception._native_common_measurement_inputs
                    )

    def test_bad_missing_pin_or_public_private_overlap_refuses_before_fixture(self):
        for mode in (
            "extra_missing",
            "grant_public",
            "duplicate",
            "oversize",
            "source_omission",
            "source_extra",
            "source_bad_pin",
        ):
            with self.subTest(mode=mode), ExitStack() as stack:
                self.harness(stack)
                plan = deepcopy(self.plan)
                if mode == "extra_missing":
                    plan["public_blobs"].pop(next(iter(plan["public_blobs"])))
                elif mode == "grant_public":
                    plan["public_blobs"][self.grant_pin] = self.grant
                elif mode == "duplicate":
                    plan["input_rows"].append(deepcopy(plan["input_rows"][0]))
                elif mode == "oversize":
                    plan["grant_bytes"] = 65537
                elif mode == "source_omission":
                    plan["installed_sources"].pop(next(iter(plan["installed_sources"])))
                elif mode == "source_extra":
                    plan["installed_sources"]["/tmp/arbitrary.py"] = {
                        "digest": PIN,
                        "bytes": 1,
                    }
                else:
                    plan["installed_sources"][next(iter(plan["installed_sources"]))][
                        "digest"
                    ] = "SECRET_BAD_SOURCE_PIN"
                self.planner.return_value = plan
                with self.assertRaises(
                    subject.NativeCommonMeasurementInputRetentionError
                ) as caught:
                    self.run_subject()
                self.fixture_read.assert_not_called()
                self.copy.assert_not_called()
                self.assert_private(caught.exception._native_common_measurement_inputs)

    def test_private_root_cannot_be_public_root_or_nested_in_it(self):
        for private in (self.public_writer, CAS(self.public_writer.root / "nested")):
            with self.subTest(root=private.root), ExitStack() as stack:
                self.harness(stack)
                with self.assertRaises(
                    subject.NativeCommonMeasurementInputRetentionError
                ):
                    subject.retain_native_common_measurement_inputs(
                        capture=self.capture,
                        public_cas=self.public,
                        private_cas=private,
                    )
                self.planner.assert_not_called()
                self.copy.assert_not_called()

    def test_fixture_metadata_guard_binds_exact_id_owner_commit_and_isolation(self):
        item = {
            "State": {
                "Running": True,
                "Paused": False,
                "Pid": 81,
                "StartedAt": STARTED,
            },
            "Image": subject.base.native._IMAGE,
            "HostConfig": {"NetworkMode": "none"},
        }
        with (
            patch.object(
                subject, "_command", return_value=canonical_json([item])
            ) as command,
            patch.object(subject.base.native, "_verify_fixture") as guard,
        ):
            result = subject._fixture(self.capture)
        guard.assert_called_once_with(
            item, CONTAINER, self.capture["fixture_name"], OWNER, COMMIT
        )
        self.assertEqual(
            command.call_args.args[0],
            [*subject.base._API._DOCKER, "inspect", "--type", "container", CONTAINER],
        )
        self.assertEqual(result, self.fixture)
        for changed in (
            {"Running": False},
            {"Paused": True},
            {"Pid": True},
            {"StartedAt": "SECRET_ARBITRARY_DIAGNOSTIC"},
        ):
            with (
                self.subTest(changed=changed),
                patch.object(
                    subject,
                    "_command",
                    return_value=canonical_json(
                        [{**item, "State": {**item["State"], **changed}}]
                    ),
                ),
                patch.object(subject.base.native, "_verify_fixture"),
            ):
                with self.assertRaises(
                    subject.NativeCommonMeasurementInputRetentionError
                ):
                    subject._fixture(self.capture)

    def test_metadata_only_guest_command_checks_root_readback_and_never_returns_raw(
        self,
    ):
        sources = self.plan["installed_sources"]
        source_raw = canonical_json(sources)
        response = {
            "status": "CHECKED",
            "file": self.source,
            "installed_source_expectations_digest": subject._digest(source_raw),
            "installed_source_count": len(sources),
        }
        with (
            patch.object(
                subject, "_command", return_value=canonical_json(response)
            ) as command,
            patch.object(subject.base.contract.live, "_metadata") as metadata,
        ):
            self.assertEqual(
                subject._guest_source(
                    CONTAINER, self.grant_pin, len(self.grant), sources
                ),
                self.source,
            )
        metadata.assert_called_once_with(self.source, owners={(0, 0)}, modes={0o444})
        self.assertEqual(
            command.call_args.args[0][-4:],
            [
                CONTAINER,
                self.grant_pin,
                str(len(self.grant)),
                source_raw.decode("ascii"),
            ],
        )
        self.assertEqual(command.call_args.kwargs, {"timeout": 15, "maximum": 4096})
        compile(subject._GUEST_READ, "private-measurement-input-read", "exec")
        self.assertLess(
            subject._GUEST_READ.index("source_before=source_guard()"),
            subject._GUEST_READ.index(
                "import runtime_native_common_attempt_capture as g"
            ),
        )
        self.assertIn("require(source_guard()==source_before)", subject._GUEST_READ)
        self.assertIn("os.O_NOFOLLOW", subject._GUEST_READ)
        self.assertIn("digest(raw)==expected['digest']", subject._GUEST_READ)
        self.assertIn("except BaseException:", subject._GUEST_READ)
        self.assertNotIn("write(raw", subject._GUEST_READ)
        self.assertNotIn("print(raw", subject._GUEST_READ)
        self.assertNotIn("sys.stderr", subject._GUEST_READ)
        for change in (
            {"installed_source_count": True},
            {"installed_source_count": len(sources) - 1},
            {"installed_source_expectations_digest": PIN},
            {"raw_grant": "SECRET_GRANT"},
        ):
            with (
                self.subTest(change=change),
                patch.object(
                    subject,
                    "_command",
                    return_value=canonical_json({**response, **change}),
                ),
            ):
                with self.assertRaises(
                    subject.NativeCommonMeasurementInputRetentionError
                ):
                    subject._guest_source(
                        CONTAINER, self.grant_pin, len(self.grant), sources
                    )

    def test_private_client_rejects_any_copy_output_or_diagnostic_and_closes_once(self):
        for mode in (
            "success",
            "stdout",
            "stderr",
            "timeout",
            "interrupt",
            "reap_failure",
        ):
            with self.subTest(mode=mode):
                stdout, stderr = Mock(), Mock()
                stdout.fileno.return_value, stderr.fileno.return_value = 31, 32
                child = Mock(stdout=stdout, stderr=stderr, pid=12345)
                child.poll.return_value = (
                    0 if mode in {"success", "reap_failure"} else None
                )
                child.wait.return_value = 0
                if mode == "reap_failure":
                    child.wait.side_effect = [
                        0,
                        subject.subprocess.TimeoutExpired("inert-private-client", 3),
                    ]
                selector = Mock()
                selector.__enter__ = Mock(return_value=selector)
                selector.__exit__ = Mock(return_value=False)
                selector.get_map.side_effect = [True, True, False]
                stream = stderr if mode == "stderr" else stdout
                selector.select.side_effect = [
                    [(SimpleNamespace(fileobj=stream), 1)],
                    [(SimpleNamespace(fileobj=stderr), 1)],
                ]
                if mode == "interrupt":
                    selector.select.side_effect = KeyboardInterrupt()
                chunks = (
                    [b"", b""]
                    if mode in {"success", "reap_failure"}
                    else [b"SECRET_COPY_OUTPUT"]
                )
                times = [0, 11] if mode == "timeout" else [0, 1, 2, 3]
                with (
                    patch.object(
                        subject.subprocess, "Popen", return_value=child
                    ) as popen,
                    patch.object(
                        subject.selectors, "DefaultSelector", return_value=selector
                    ),
                    patch.object(subject.os, "set_blocking"),
                    patch.object(subject.os, "read", side_effect=chunks),
                    patch.object(subject.os, "killpg") as kill,
                    patch.object(subject.time, "monotonic", side_effect=times),
                ):
                    if mode == "success":
                        self.assertEqual(
                            subject._command(["inert"], timeout=10, maximum=0), b""
                        )
                    else:
                        with self.assertRaises(
                            KeyboardInterrupt
                            if mode == "interrupt"
                            else subject.NativeCommonMeasurementInputRetentionError
                        ) as caught:
                            subject._command(["inert"], timeout=10, maximum=0)
                        self.assertNotIn("SECRET", str(caught.exception))
                popen.assert_called_once()
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                stdout.close.assert_called_once()
                stderr.close.assert_called_once()
                self.assertEqual(
                    kill.call_count, 0 if mode in {"success", "reap_failure"} else 1
                )

    def test_final_guard_client_cleanup_failure_is_retained_as_fixed_metadata(self):
        failure = subject.NativeCommonMeasurementInputRetentionError(
            "PRIVATE_CLIENT_FAILED"
        )
        failure._private_client_failures = [
            "CLIENT_CLOSE_OR_REAP_REFUSED",
            "SECRET_UNREVIEWED_DETAIL",
        ]
        with ExitStack() as stack:
            self.harness(stack)
            self.source_read.side_effect = [deepcopy(self.source), failure]
            with self.assertRaises(
                subject.NativeCommonMeasurementInputRetentionError
            ) as caught:
                self.run_subject()
        result = caught.exception._native_common_measurement_inputs
        self.assertEqual(
            result["postcondition_failures"],
            ["ORIGINAL_GRANT_AFTER_REFUSED", "CLIENT_CLOSE_OR_REAP_REFUSED"],
        )
        self.assertFalse(result["input_validation_complete"])
        self.assert_private(result)

    def test_host_private_read_rejects_symlink_hardlink_and_wrong_pin(self):
        directory = self.root / "read"
        directory.mkdir(mode=0o700)
        original = self.root / "original"
        original.write_bytes(self.grant)
        original.chmod(0o444)
        fd = os.open(directory, subject._FLAGS)
        self.addCleanup(os.close, fd)
        target = directory / subject.GRANT_NAME
        target.symlink_to(original)
        with self.assertRaises(OSError):
            subject._read_grant(fd, self.grant_pin, len(self.grant))
        target.unlink()
        os.link(original, target)
        with self.assertRaises(subject.NativeCommonMeasurementInputRetentionError):
            subject._read_grant(fd, self.grant_pin, len(self.grant))
        target.unlink()
        target.write_bytes(self.grant)
        target.chmod(0o400)
        with self.assertRaises(subject.NativeCommonMeasurementInputRetentionError):
            subject._read_grant(fd, PIN, len(self.grant))
        self.assertEqual(
            subject._read_grant(fd, self.grant_pin, len(self.grant)), self.grant
        )

    def test_source_has_no_enumeration_automatic_cleanup_tree_copy_or_host_capture_import(
        self,
    ):
        source = Path(subject.__file__).read_text()
        calls = {
            ast.unparse(node.func)
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call)
        }
        self.assertFalse(
            calls.intersection(
                {
                    "os.listdir",
                    "os.scandir",
                    "os.unlink",
                    "os.remove",
                    "shutil.rmtree",
                    "TemporaryDirectory",
                }
            )
        )
        self.assertNotIn("capture_native_phase3_common_attempt", source)
        self.assertNotIn("public_cas.put", source)
        self.assertNotIn("print(", source)

    def test_public_classifier_detaches_complete_metadata_without_private_reads(self):
        with ExitStack() as stack:
            self.harness(stack)
            report = self.run_subject()
        with (
            patch.object(
                self.private,
                "read",
                side_effect=AssertionError("private reads forbidden"),
            ),
            patch.object(
                self.private,
                "put_expected",
                side_effect=AssertionError("private writes forbidden"),
            ),
        ):
            result = subject.public_retention_metadata(
                report, capture=self.capture, private_cas=self.private
            )
        self.assertEqual(result, report)
        self.assertIsNot(result, report)
        report["grant_source_before"]["identity"][1] = 999
        self.assertEqual(result["grant_source_before"]["identity"][1], 2)
        self.assert_private(result)

    def test_public_classifier_preserves_actual_partial_refusal_and_early_refusal(self):
        for mode in ("copy", "plan"):
            with self.subTest(mode=mode), ExitStack() as stack:
                self.harness(stack, copy_error=ValueError("SECRET_COPY_DETAIL"))
                if mode == "plan":
                    self.planner.side_effect = ValueError("SECRET_PLAN_DETAIL")
                with self.assertRaises(
                    subject.NativeCommonMeasurementInputRetentionError
                ) as caught:
                    self.run_subject()
                report = caught.exception._native_common_measurement_inputs
                result = subject.public_retention_metadata(
                    report, capture=self.capture, private_cas=self.private
                )
                self.assertEqual(result, report)
                self.assertEqual(result["status"], "REFUSED")
                self.assertFalse(result["input_validation_complete"])
                self.assert_private(result)

    def test_public_classifier_refuses_unknown_private_fields_and_arbitrary_diagnostics(
        self,
    ):
        with ExitStack() as stack:
            self.harness(stack)
            good = self.run_subject()
        changes = (
            ("raw_grant",),
            ("fixture_before", "raw_grant"),
            ("grant_source_before", "raw_grant"),
            ("grant_source_before", "digest"),
            ("fixture_after", "owner"),
            ("fixture_after", "started_at"),
            ("scratch_directory",),
            ("prepared_digest",),
            ("input_set_digest",),
            ("postcondition_failures",),
            ("copy_count",),
            ("input_validation_complete",),
        )
        for path in changes:
            with self.subTest(path=path):
                report = deepcopy(good)
                value = report
                for key in path[:-1]:
                    value = value[key]
                value[path[-1]] = "SECRET_GRANT_NEVER_PUBLIC"
                with self.assertRaises(
                    subject.NativeCommonMeasurementInputRetentionError
                ) as caught:
                    subject.public_retention_metadata(
                        report, capture=self.capture, private_cas=self.private
                    )
                self.assertEqual(
                    str(caught.exception), "PRIVATE_INPUT_METADATA_REFUSED"
                )
                self.assertTrue(caught.exception.__suppress_context__)
        for change in (
            "reason",
            "phase",
            "unknown",
            "row",
            "duplicate",
            "source_boolean",
            "flag",
        ):
            with self.subTest(change=change):
                report = deepcopy(good)
                report.update(
                    status="REFUSED",
                    input_validation_complete=False,
                    refusal={
                        "phase": "FINAL_READBACKS",
                        "reason": "PRIVATE_INPUT_CUSTODY_REFUSED",
                    },
                )
                if change in {"reason", "phase"}:
                    report["refusal"][change] = "SECRET_EXCEPTION_DETAIL"
                elif change == "unknown":
                    report["refusal"]["details"] = "SECRET_EXCEPTION_DETAIL"
                elif change == "row":
                    report["input_blobs"][0]["raw_grant"] = "SECRET_GRANT"
                elif change == "duplicate":
                    report["input_blobs"].append(deepcopy(report["input_blobs"][0]))
                elif change == "source_boolean":
                    report["grant_source_after"]["identity"][0] = True
                else:
                    report[subject._FALSE[0]] = True
                with self.assertRaises(
                    subject.NativeCommonMeasurementInputRetentionError
                ) as caught:
                    subject.public_retention_metadata(
                        report, capture=self.capture, private_cas=self.private
                    )
                self.assertEqual(
                    str(caught.exception), "PRIVATE_INPUT_METADATA_REFUSED"
                )


if __name__ == "__main__":
    unittest.main()
