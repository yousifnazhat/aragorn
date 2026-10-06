"""Inert wrapper/export/claim checks; no fixture, service, clock, or historical suite."""

import ast
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import runtime_native_common_attempt_capture as subject


CONTAINER = "c" * 64
PIN = "sha256:" + "b" * 64


class NativeCommonAttemptCaptureTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.raws = {}
        self.journal = []
        self.add("clock_before", {"public": 1})
        self.add("clock_after", {"public": 2})
        handoff = {
            "status": "INPUTS_PROVISIONED_NOT_ACTIVATED",
            "request_digest": self.add("request", {"request": 1}),
            "provisioning_digest": self.add("provisioning", {"provisioning": 1}),
            "claim_digest": self.add("claim", {"claim": 1}),
        }
        self.add("handoff", handoff)
        self.sources = {name: name.encode() for name in subject._CONTROLLER_PATHS}
        self.report = {
            "schema": subject.attempt.SCHEMA,
            "authority": subject.attempt.AUTHORITY,
            "status": "BOUNDED_NATIVE_ATTEMPT_VERIFIED",
            "public_blob_attempts": self.journal,
            "public_blob_digests": sorted(self.raws),
            "plan": None,
            "handoff": handoff,
            "refusal": None,
            "fixture_stack_cleanup": {"all_stopped": True},
            **dict.fromkeys(subject._FALSE, False),
        }

    def add(self, role, value):
        raw = subject.canonical_json(value)
        pin = subject._IDENTITY._digest(raw)
        self.raws[pin] = raw
        self.journal.append({"role": role, "digest": pin, "bytes": len(raw)})
        return pin

    def preyield(self):
        commitment = self.add("original_commitment", {"commitment": 1})
        schedule = {"attempt_id": "attempt-1", "collection_digest": commitment}
        scheduled_pin = self.add("selected_request", schedule)
        binding = {
            "collection_commitment_digest": commitment,
            "scheduled_measurement_request_digest": scheduled_pin,
            "attempt_id": "attempt-1",
        }
        binding_pin = self.add("measurement_binding", binding)
        plan = {
            "schema": subject.attempt.planner.SCHEMA,
            "authority": subject.attempt.planner.AUTHORITY,
            "status": "ORIGINAL_PLAN_PREPARED_NOT_PROVISIONED",
            "container_id": CONTAINER,
            "commitment_digest": commitment,
            "common_preparation_digest": self.add("common_public_input", {"common": 1}),
            "collection_preparation_digest": self.add(
                "original_collection_preparation", {"collection": 1}
            ),
            "measurement_prepared_digest": self.add(
                "measurement_preparation", {"binding": binding}
            ),
            "binding_digest": binding_pin,
            "request_digest": self.add(
                "common_measured_request",
                {"container_id": CONTAINER, "measurement_binding_digest": binding_pin},
            ),
            "scheduled_request": schedule,
            "decision": dict.fromkeys(subject.attempt.planner.FALSE_FLAGS, False),
        }
        self.add("plan_report", plan)
        self.report.update(
            status="REFUSED",
            plan=plan,
            handoff=None,
            public_blob_digests=sorted(self.raws),
            refusal={
                "phase": "HELD_PREACTIVATION_HANDOFF",
                "reason": "FIXED_COMMON_ATTEMPT_REFUSED",
            },
        )
        self.claim = {
            "schema": "aragorn/native-common-measurement-claim/v1",
            **{
                key: plan[key]
                for key in (
                    "collection_preparation_digest",
                    "common_preparation_digest",
                    "measurement_prepared_digest",
                    "commitment_digest",
                    "binding_digest",
                )
            },
            "request_digest": scheduled_pin,
            "common_request_digest": plan["request_digest"],
            "container_id": CONTAINER,
            "state": "PERMANENT_NO_RETRY_CLAIM_NOT_COMPLETION",
            "claimed_boottime_ns": 90,
        }

    def harness(self, stack, *, missing=None, close_error=None):
        self.environment = stack.enter_context(
            patch.object(
                subject.attempt.setup.predecessor,
                "_environment",
                side_effect=lambda *_: self.events.append("environment"),
            )
        )
        self.bundle = stack.enter_context(
            patch.object(
                subject,
                "_read_bundle",
                side_effect=lambda *_: (
                    self.events.append("bundle") or (b"bundle", {"identity": [1]})
                ),
            )
        )
        self.inspected = {
            "source_raws": self.sources,
            "common_arguments": {"case_id": "case"},
            "plan_arguments": {"selected_attempt_id": "attempt-1"},
            "expected_setup_digest": PIN,
            "expected_source_digests": {"source": PIN},
        }
        stack.enter_context(
            patch.object(
                subject.contract,
                "inspect_common_attempt_inputs",
                return_value=self.inspected,
            )
        )

        def controller(name, raw):
            self.assertEqual(raw, self.sources[name])
            self.events.append("source:" + name)
            return {
                "digest": subject._IDENTITY._digest(raw),
                "bytes": len(raw),
                "identity": [1],
            }

        self.controller = stack.enter_context(
            patch.object(subject, "_read_controller", side_effect=controller)
        )
        self.run = stack.enter_context(
            patch.object(
                subject.attempt,
                "run_native_common_attempt",
                side_effect=lambda **_: (
                    self.events.append("attempt") or deepcopy(self.report)
                ),
            )
        )

        @contextmanager
        def store(**selection):
            self.events.append("store:" + str(selection))
            yield 91, lambda: self.events.append("guard")
            self.events.append("store-close")
            if close_error is not None:
                raise close_error

        self.store = stack.enter_context(
            patch.object(subject, "_evidence_store", side_effect=store)
        )

        def read(descriptor, candidate):
            self.assertEqual(descriptor, 91)
            self.events.append("read:" + candidate["digest"])
            if candidate["digest"] == missing:
                raise FileNotFoundError("SECRET_CREDENTIAL_DIAGNOSTIC")
            return self.raws[candidate["digest"]]

        self.read = stack.enter_context(
            patch.object(subject, "_read_public_blob", side_effect=read)
        )
        self.claim_read = stack.enter_context(
            patch.object(
                subject,
                "_read_claim",
                side_effect=lambda expected: (
                    subject.canonical_json(self.claim),
                    {"identity": [2], "mode": "0400"},
                ),
            )
        )

    def test_once_controller_call_and_independent_final_source_readbacks(self):
        with ExitStack() as stack:
            self.harness(stack)
            result = subject._run(CONTAINER, PIN)
        self.run.assert_called_once_with(
            common_arguments={"case_id": "case", "container_id": CONTAINER},
            plan_arguments=self.inspected["plan_arguments"],
            expected_setup_digest=PIN,
            expected_source_digests=self.inspected["expected_source_digests"],
        )
        self.assertEqual(result["status"], "EXPORTED_BOUNDED_ATTEMPT")
        self.assertEqual(self.bundle.call_count, 2)
        self.assertEqual(self.controller.call_count, 4)
        self.assertEqual(
            result["controller_sources"], result["controller_sources_after"]
        )
        self.assertEqual(self.read.call_count, len(self.raws))
        self.assertEqual(result["recovery"]["status"], "NOT_REQUIRED")
        self.assertTrue(result["public_export_complete"])
        self.assertFalse(result["preserve_fixture_for_evidence"])
        self.assertTrue(all(result[key] is False for key in subject._FALSE))
        self.assertLess(self.events.index("store-close"), len(self.events) - 5)
        self.claim_read.assert_not_called()

    def test_environment_input_or_source_guard_prevents_effects(self):
        for failure in ("environment", "bundle", "controller"):
            with self.subTest(failure=failure), ExitStack() as stack:
                self.harness(stack)
                getattr(self, failure).side_effect = ValueError("SECRET")
                result = subject._run(CONTAINER, PIN)
                self.run.assert_not_called()
                self.read.assert_not_called()
                self.assertEqual(result["status"], "REFUSED")
                self.assertNotIn(b"SECRET", subject.canonical_json(result))

    def test_same_digest_roles_deduplicate_once_and_invalid_role_blocks_all_reads(self):
        self.journal.append({**self.journal[0], "role": "identity_before"})
        with ExitStack() as stack:
            self.harness(stack)
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(len(result["public_blobs"]), len(self.raws))
        self.assertEqual(self.read.call_count, len(self.raws))
        for alteration in (
            {"bytes": 1},
            {"role": "private_grant"},
            {"private_input": "SECRET"},
        ):
            with self.subTest(alteration=alteration), ExitStack() as stack:
                self.harness(stack)
                self.report["public_blob_attempts"] = [
                    dict(self.journal[0]),
                    {**self.journal[0], **alteration},
                ]
                result = subject._run(CONTAINER, PIN)
                self.read.assert_not_called()
                self.assertTrue(result["preserve_fixture_for_evidence"])
                self.assertFalse(result["public_export_complete"])
                self.assertNotIn(b"SECRET", subject.canonical_json(result))

    def test_missing_public_candidate_keeps_siblings_and_no_secret_exception(self):
        with ExitStack() as stack:
            self.harness(stack, missing=self.journal[0]["digest"])
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(self.read.call_count, len(self.raws))
        self.assertEqual(len(result["public_blobs"]), len(self.raws) - 1)
        self.assertEqual(len(result["export_failures"]), 1)
        self.assertTrue(result["preserve_fixture_for_evidence"])
        self.assertNotIn(b"SECRET", subject.canonical_json(result))

    def test_public_digest_join_mismatch_cannot_authorize_fixture_destruction(self):
        self.report["public_blob_digests"] = []
        with ExitStack() as stack:
            self.harness(stack)
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(len(result["public_blobs"]), len(self.raws))
        self.assertFalse(result["public_export_complete"])
        self.assertTrue(result["preserve_fixture_for_evidence"])
        self.claim_read.assert_not_called()

    def test_original_interrupt_identity_retained_after_all_final_checks(self):
        error = KeyboardInterrupt("SECRET_ORIGINAL")
        error._native_common_attempt = deepcopy(self.report)
        with ExitStack() as stack:
            self.harness(stack)
            self.run.side_effect = error
            self.bundle.side_effect = [
                (b"bundle", {"identity": [1]}),
                SystemExit("SECRET_SECONDARY"),
            ]
            with self.assertRaises(KeyboardInterrupt) as caught:
                subject._run(CONTAINER, PIN)
        self.assertIs(caught.exception, error)
        result = error._native_common_attempt_capture
        self.assertEqual(result["attempt"], self.report)
        self.assertEqual(len(result["public_blobs"]), len(self.raws))
        self.assertEqual(self.controller.call_count, 4)
        self.assertTrue(result["interrupted"])
        self.assertTrue(result["preserve_fixture_for_evidence"])
        self.assertNotIn(b"SECRET", subject.canonical_json(result))

    def test_new_export_interrupt_does_not_skip_sibling_or_source_reads(self):
        error = KeyboardInterrupt("SECRET_EXPORT")
        with ExitStack() as stack:
            self.harness(stack)
            original = self.read.side_effect
            count = 0

            def read(*args):
                nonlocal count
                count += 1
                if count == 1:
                    raise error
                return original(*args)

            self.read.side_effect = read
            with self.assertRaises(KeyboardInterrupt) as caught:
                subject._run(CONTAINER, PIN)
        self.assertIs(caught.exception, error)
        result = error._native_common_attempt_capture
        self.assertEqual(len(result["public_blobs"]), len(self.raws) - 1)
        self.assertEqual(self.controller.call_count, 4)

    def test_changed_input_and_controller_custody_are_independent(self):
        with ExitStack() as stack:
            self.harness(stack, close_error=OSError("SECRET_CLOSE"))
            self.bundle.side_effect = [(b"bundle", {}), (b"bundle", {"identity": [2]})]
            self.controller.side_effect = [{}, {}, {"changed": 1}, {"changed": 2}]
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(
            result["postcondition_failures"],
            [
                "PUBLIC_CAS_CUSTODY_REFUSED",
                "BUNDLE_AFTER",
                "WRAPPER_SOURCE_AFTER",
                "CONTRACT_SOURCE_AFTER",
            ],
        )
        self.assertEqual(len(result["public_blobs"]), len(self.raws))
        self.assertTrue(result["preserve_fixture_for_evidence"])

    def test_preyield_claim_recovery_uses_only_fully_joined_original_public_roles(self):
        self.preyield()
        with ExitStack() as stack:
            self.harness(stack)
            result = subject._run(CONTAINER, PIN)
        self.claim_read.assert_called_once()
        expected = self.claim_read.call_args.args[0]
        self.assertEqual(
            expected,
            {
                key: value
                for key, value in self.claim.items()
                if key != "claimed_boottime_ns"
            },
        )
        self.assertEqual(
            result["recovery"]["status"], "CLASSIFIED_PERMANENT_CLAIM_EXPORTED"
        )
        self.assertEqual(result["recovery"]["public_blob_attempts"][0]["role"], "claim")
        self.assertEqual(result["status"], "REFUSED")
        self.assertTrue(result["public_export_complete"])
        self.assertTrue(result["preserve_fixture_for_evidence"])
        self.run.assert_called_once()

    def test_yielded_handoff_with_partial_retention_keeps_fixture(self):
        self.report.update(
            status="REFUSED",
            refusal={
                "phase": "HELD_PREACTIVATION_HANDOFF",
                "reason": "FIXED_COMMON_ATTEMPT_REFUSED",
            },
        )
        self.report["public_blob_attempts"] = [
            row for row in self.journal if row["role"] != "claim"
        ]
        self.report["public_blob_digests"] = sorted(
            {row["digest"] for row in self.report["public_blob_attempts"]}
        )
        with ExitStack() as stack:
            self.harness(stack)
            result = subject._run(CONTAINER, PIN)
        self.claim_read.assert_not_called()
        self.assertEqual(
            result["recovery"]["failures"], ["HANDOFF_PUBLIC_ROLES_INCOMPLETE"]
        )
        self.assertFalse(result["public_export_complete"])
        self.assertTrue(result["preserve_fixture_for_evidence"])

    def test_missing_partial_unclassified_claim_and_missing_plan_roles_preserve_fixture(
        self,
    ):
        self.preyield()
        for error in (
            FileNotFoundError("SECRET"),
            PermissionError("SECRET_0600"),
            ValueError("SECRET_PRIVATE_GRANT"),
        ):
            with self.subTest(error=type(error).__name__), ExitStack() as stack:
                self.harness(stack)
                self.claim_read.side_effect = error
                result = subject._run(CONTAINER, PIN)
                self.assertEqual(result["recovery"]["status"], "INCOMPLETE")
                self.assertIsNone(result["recovery"]["claim_metadata"])
                self.assertTrue(result["preserve_fixture_for_evidence"])
                self.assertNotIn(b"SECRET", subject.canonical_json(result))
        for role in (
            "original_commitment",
            "plan_report",
            "common_measured_request",
            "measurement_binding",
        ):
            with self.subTest(role=role), ExitStack() as stack:
                self.harness(
                    stack,
                    missing=next(
                        row["digest"] for row in self.journal if row["role"] == role
                    ),
                )
                result = subject._run(CONTAINER, PIN)
                self.claim_read.assert_not_called()
                self.assertTrue(result["preserve_fixture_for_evidence"])

    def test_claim_reader_exact_path_mode_and_schema_no_private_fallback(self):
        self.preyield()
        expected = {
            key: value
            for key, value in self.claim.items()
            if key != "claimed_boottime_ns"
        }

        @contextmanager
        def store(**kwargs):
            self.assertEqual(kwargs, {"claims": True})
            yield 90, lambda: None

        raw = subject.canonical_json(self.claim)
        with (
            patch.object(subject, "_evidence_store", store),
            patch.object(
                subject._IDENTITY, "_read_at", return_value=(raw, {"mode": "0400"})
            ) as read,
        ):
            self.assertEqual(subject._read_claim(expected), (raw, {"mode": "0400"}))
        read.assert_called_once_with(
            90,
            "/" + expected["commitment_digest"][7:] + ".json",
            owner=0,
            owner_gid=0,
            modes={0o400},
            limit=4096,
        )
        for raw in (
            b'{"private_grant":"SECRET"}',
            subject.canonical_json({**self.claim, "claimed_boottime_ns": True}),
            subject.canonical_json({**self.claim, "container_id": "d" * 64}),
            b'{"partial":',
        ):
            with (
                self.subTest(raw=raw),
                patch.object(subject, "_evidence_store", store),
                patch.object(subject._IDENTITY, "_read_at", return_value=(raw, {})),
            ):
                with self.assertRaises(
                    (subject.NativeCommonAttemptCaptureError, json.JSONDecodeError)
                ):
                    subject._read_claim(expected)

    def test_completed_claim_read_rejects_partial_0600_before_reading_bytes(self):
        self.preyield()
        expected = {
            key: value
            for key, value in self.claim.items()
            if key != "claimed_boottime_ns"
        }
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_nlink=1, st_size=25
        )

        @contextmanager
        def store(**_):
            yield 90, lambda: None

        with (
            patch.object(subject, "_evidence_store", store),
            patch.object(subject._IDENTITY.os, "open", return_value=91),
            patch.object(subject._IDENTITY.os, "stat", return_value=metadata),
            patch.object(subject._IDENTITY.os, "fstat", return_value=metadata),
            patch.object(subject._IDENTITY.os, "close"),
            patch.object(subject._IDENTITY.os, "read") as read,
        ):
            with self.assertRaises(ValueError):
                subject._read_claim(expected)
        read.assert_not_called()

    def test_fixed_files_and_ancestry_are_read_only_no_follow_no_enumeration(self):
        source = Path(subject.__file__).read_text()
        tree = ast.parse(source)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        names = {ast.unparse(node.func) for node in calls}
        self.assertNotIn("os.scandir", names)
        self.assertNotIn("os.listdir", names)
        self.assertNotIn("CAS", names)
        self.assertNotIn("os.mkdir", names)
        self.assertNotIn("os.unlink", names)
        self.assertNotIn("patch", names)
        self.assertEqual(
            sum(
                ast.unparse(node.func) == "attempt.run_native_common_attempt"
                for node in calls
            ),
            1,
        )
        with patch.object(
            subject, "_read_fixed", return_value=(b"expected", {})
        ) as read:
            subject._read_controller(next(iter(subject._CONTROLLER_PATHS)), b"expected")
        self.assertEqual(
            read.call_args.kwargs, {"mode": 0o444, "limit": subject._MAX_REPORT}
        )
        self.assertNotIn("/plan/", source)

    def test_store_holds_only_existing_evidence_ancestry_and_detects_replacement(self):
        identities = {}
        next_fd = 1

        def directory(fd, mode):
            return (1, fd, stat.S_IFDIR | (0o755 if mode is None else mode), 0, 0)

        def named(name, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            if name == ".":
                return identities[dir_fd]
            return directory(next_fd, None if name == "run" else 0o700)

        def opened(name, flags, *, dir_fd=None):
            nonlocal next_fd
            self.assertTrue(flags & subject.os.O_NOFOLLOW)
            self.assertTrue(flags & subject.os.O_DIRECTORY)
            fd = next_fd
            next_fd += 1
            identities[fd] = directory(fd, None if name in {"/", "run"} else 0o700)
            return fd

        # Named paths are recorded explicitly, never obtained by enumeration.
        paths = {}

        def tracked_open(name, flags, *, dir_fd=None):
            fd = opened(name, flags, dir_fd=dir_fd)
            paths[(dir_fd, name)] = identities[fd]
            return fd

        def tracked_stat(name, *, dir_fd, follow_symlinks):
            return paths.get(
                (dir_fd, name),
                named(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks),
            )

        closed = []
        with (
            patch.object(subject.os, "open", side_effect=tracked_open),
            patch.object(subject.os, "stat", side_effect=tracked_stat),
            patch.object(subject.os, "close", side_effect=closed.append),
            patch.object(
                subject, "_directory", side_effect=lambda fd, mode: identities[fd]
            ),
            patch.object(
                subject._IDENTITY.broker,
                "_directory_identity",
                side_effect=lambda value: value,
            ),
        ):
            with self.assertRaises(subject.NativeCommonAttemptCaptureError):
                with subject._evidence_store(blobs=True) as (fd, guard):
                    self.assertEqual(fd, 6)
                    paths[(4, "blobs")] = (99, 99, 99, 0, 0)
                    guard()
        self.assertEqual(closed, [6, 5, 4, 3, 2, 1])
        self.assertEqual(
            {name for _, name in paths},
            {
                "/",
                "run",
                "aragorn-native-common-attempt",
                "evidence",
                "blobs",
                "sha256",
            },
        )

    def test_main_emits_attached_interrupt_report_without_exception_text(self):
        error = KeyboardInterrupt("SECRET")
        error._native_common_attempt_capture = {
            "status": "REFUSED",
            "public_blobs": [],
            "interrupted": True,
        }
        output = SimpleNamespace(buffer=io.BytesIO())
        with (
            patch.object(subject, "_run", side_effect=error),
            patch.object(subject.sys, "stdout", output),
        ):
            self.assertEqual(subject.main([CONTAINER, PIN]), 130)
        self.assertEqual(
            json.loads(output.buffer.getvalue()), error._native_common_attempt_capture
        )
        self.assertNotIn(b"SECRET", output.buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
