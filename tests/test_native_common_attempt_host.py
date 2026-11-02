"""Inert host lifecycle checks; no VM, guest, service, attempt or acceptance run."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn.cas import CAS
from scripts import capture_native_phase3_common_attempt as subject
from tests.test_native_phase3_common_attempt_inputs import AttemptInputsData


class NativeCommonAttemptHostTests(unittest.TestCase):
    def setUp(self):
        self.data = AttemptInputsData()
        self.data.setUp()
        self.addCleanup(self.data.doCleanups)
        self.bound = self.data.bound
        self.pin = self.bound["bundle_digest"]
        self.store = self.data.fixture.cas
        for pin, raw in self.bound["input_blobs"].items():
            self.store.put_expected(
                BytesIO(raw), expected_digest=pin, max_bytes=subject._BUNDLE_LIMIT
            )
        self.source = json.loads(self.bound["source_raw"])
        self.container = "a" * 64
        self.events = []
        for target, name in (
            (subject.native.existing, "_docker"),
            (subject.subprocess, "Popen"),
        ):
            guard = patch.object(
                target, name, side_effect=AssertionError("unmocked process forbidden")
            )
            guard.start()
            self.addCleanup(guard.stop)

    def envelope(self):
        rows = []
        journal = []
        for index in range(2):
            raw = subject.canonical_json({"inert_public_lifecycle_only": index})
            pin = subject._API._digest(raw)
            rows.append({"digest": pin, "bytes": len(raw), "text": raw.decode()})
            journal.append(
                {"role": "common_public_input", "digest": pin, "bytes": len(raw)}
            )
        return {
            "schema": subject.guest.SCHEMA,
            "authority": subject.guest.AUTHORITY,
            "status": "EXPORTED_BOUNDED_ATTEMPT",
            "container_id": self.container,
            "input_bundle_digest": self.pin,
            "attempt": {
                "status": "BOUNDED_NATIVE_ATTEMPT_VERIFIED",
                "public_blob_attempts": journal,
            },
            "public_blobs": rows,
            "export_failures": [],
            "refusal": None,
            "input_bundle_readback": True,
            "controller_sources": {"inert": True},
            "controller_sources_after": {"inert": True},
            "postcondition_failures": [],
            "recovery": {
                "status": "NOT_REQUIRED",
                "claim_metadata": None,
                "public_blob_attempts": [],
                "failures": [],
            },
            "public_export_complete": True,
            "preserve_fixture_for_evidence": False,
            "interrupted": False,
            "limitations": list(subject.guest._LIMITATIONS),
            **dict.fromkeys(subject._FALSE, False),
        }

    @contextmanager
    def capture_mocks(self, *, outcome=None, cleanup_error=None, copy_error=False):
        with ExitStack() as stack:
            self.source_guard = stack.enter_context(
                patch.object(
                    subject,
                    "_source_guard",
                    side_effect=lambda _: self.events.append("source") or self.source,
                )
            )
            stack.enter_context(
                patch.object(
                    subject.native, "_build_binding", return_value={"inert": True}
                )
            )
            stack.enter_context(
                patch.object(
                    subject._API,
                    "_tree_file",
                    side_effect=lambda commit, path: {
                        "path": str(path),
                        "mode": "100644",
                        "blob": "b" * 40,
                        "bytes": len(self.bound["source_raws"][str(path)]),
                        "digest": subject._API._digest(
                            self.bound["source_raws"][str(path)]
                        ),
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    subject.native.existing.campaign,
                    "current_v3_parent_identity",
                    return_value={"inert_parent": True},
                )
            )
            self.parent = {"image_inspect": {"RootFS": {"Layers": ["parent"]}}}
            self.parent_reads = stack.enter_context(
                patch.object(
                    subject.native.snapshot,
                    "snapshot_parent",
                    side_effect=lambda _: self.events.append("parent") or self.parent,
                )
            )
            stack.enter_context(
                patch.object(
                    subject.native,
                    "_inspect",
                    side_effect=lambda kind, _: (
                        {
                            "Id": subject.native._IMAGE,
                            "RootFS": {"Type": "layers", "Layers": ["parent", "child"]},
                        }
                        if kind == "image"
                        else {"Id": self.container}
                    ),
                )
            )
            stack.enter_context(patch.object(subject.native, "_verify_fixture"))
            self.runtime_reads = stack.enter_context(
                patch.object(
                    subject.native,
                    "_snapshot_runtime",
                    side_effect=lambda: (
                        self.events.append("runtime")
                        or {"volume_inspect": {"inert": True}}
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    subject.native.previous, "_parent_unchanged", return_value=True
                )
            )
            stack.enter_context(
                patch.object(
                    subject.profile,
                    "stage_runtime_phase3_ingress_profile",
                    return_value=self.data.fixture.stage,
                )
            )
            stack.enter_context(
                patch.object(
                    subject.profile, "_verified_payloads", return_value=({}, {})
                )
            )
            stack.enter_context(patch.object(subject.profile.base, "_audit_tree"))
            stack.enter_context(
                patch.object(
                    subject,
                    "_driver",
                    return_value=(
                        {"inert_generated_source": True},
                        Path("/inert/driver.mjs"),
                        {
                            "installed_path": subject._DRIVER_PATH,
                            "installed_mode": "0444",
                            "bytes": subject.driver._OUTPUT[0],
                            "digest": subject.driver._OUTPUT[1],
                        },
                    ),
                )
            )
            stack.enter_context(patch.object(subject.pins, "_read_fixed"))

            def docker(*argv):
                if argv[0] == "cp" and copy_error:
                    raise ValueError("inert copy failure")
                return (self.container + "\n").encode() if argv[0] == "create" else b""

            self.docker = stack.enter_context(
                patch.object(subject.native.existing, "_docker", side_effect=docker)
            )

            def invoke(*_):
                self.events.append("invoke")
                if isinstance(outcome, BaseException):
                    raise outcome
                return self.envelope() if outcome is None else deepcopy(outcome)

            self.invoke = stack.enter_context(
                patch.object(subject, "_invoke", side_effect=invoke)
            )

            def cleanup(name, owner, image):
                self.events.append("cleanup")
                if cleanup_error:
                    raise cleanup_error
                return {
                    "name": name,
                    "owner": owner,
                    "image": image,
                    "removed_id": self.container,
                    "container_name_absent": True,
                    "removed_id_absent": True,
                }

            self.cleanup = stack.enter_context(
                patch.object(
                    subject.native.snapshot, "_cleanup_snapshot", side_effect=cleanup
                )
            )

            def suspend(result, interrupts):
                self.events.append("suspend")
                result["preservation_suspension"] = {
                    "attempted": True,
                    "before": {"inert": True},
                    "after": {"inert": True},
                    "paused": True,
                    "failures": [],
                }

            self.suspend = stack.enter_context(
                patch.object(subject, "_suspend_preserved", side_effect=suspend)
            )
            yield stack

    def test_prepare_inspect_actual_contract_and_signed_source_inventory(self):
        self.assertEqual(
            subject._inspect(CAS(self.store.root, read_only=True), self.pin), self.bound
        )
        self.assertEqual(subject._FILES, subject.inputs.FIXTURE_HELPERS)
        self.assertEqual(subject._ALIASES, subject.inputs.HELPER_ALIASES)
        subject._stage_guard(self.data.fixture.stage, self.bound["stage_raw"])
        sources = self.bound["source_raws"]
        real_read = subject.pins._read_fixed

        def read(path, expected):
            relative = path.relative_to(subject._ROOT).as_posix()
            if relative in sources:
                raw = sources[relative]
                self.assertEqual(expected, (len(raw), subject._API._digest(raw)))
                return raw
            return real_read(path, expected)

        with (
            patch.object(subject.base, "_current_source", return_value=self.source),
            patch.object(subject.legacy, "_source_bytes") as local,
            patch.object(
                subject._API,
                "_tree_file",
                side_effect=lambda commit, path: {
                    "bytes": len(sources[str(path)]),
                    "digest": subject._API._digest(sources[str(path)]),
                },
            ),
            patch.object(subject.pins, "_read_fixed", side_effect=read),
        ):
            result = subject._prepare(
                self.store, self.data.base_bundle["bundle_digest"], self.data.plan
            )
        self.assertEqual(result["input_bundle_digest"], self.pin)
        self.assertEqual(result["status"], "PREPARED_EXPECTATIONS_ONLY")
        self.assertTrue(all(result[key] is False for key in subject.inputs.FALSE_FLAGS))
        checked = {
            call.args[0].relative_to(subject._ROOT).as_posix()
            for call in local.call_args_list
        }
        self.assertEqual(checked, set(subject._SOURCE_PATHS))

    def test_success_copies_alias_and_generated_driver_then_invokes_and_cleans_once(
        self,
    ):
        with self.capture_mocks():
            result = subject._capture(self.store, self.pin)
        self.assertEqual(result["status"], "CAPTURED_BOUNDED_ATTEMPT")
        self.invoke.assert_called_once()
        self.cleanup.assert_called_once()
        self.assertLess(self.events.index("invoke"), self.events.index("cleanup"))
        self.assertTrue(result["guest_publication"]["complete"])
        self.assertFalse(result["fixture_preserved"])
        self.assertTrue(all(result[key] is False for key in subject._FALSE))
        create = next(
            call.args for call in self.docker.call_args_list if call.args[0] == "create"
        )
        self.assertIn("--network=none", create)
        self.assertIn("--pull=never", create)
        self.assertIn("dev.aragorn.snapshot-owner=" + result["fixture_owner"], create)
        copies = [
            call.args[2] for call in self.docker.call_args_list if call.args[0] == "cp"
        ]
        for target in [
            *subject._FILES.values(),
            *subject._ALIASES,
            subject._DRIVER_PATH,
        ]:
            self.assertEqual(copies.count(self.container + ":" + target), 1)
        audit = next(
            call.args for call in self.docker.call_args_list if call.args[0] == "exec"
        )
        inventory = json.loads(audit[8])
        self.assertEqual(inventory[subject._DRIVER_PATH]["installed_mode"], "0444")
        for target in subject._ALIASES:
            self.assertEqual(inventory[target]["installed_path"], target)
        self.assertEqual(self.runtime_reads.call_count, 2)
        self.assertEqual(self.parent_reads.call_count, 2)

    def test_uncaptured_timeout_preserves_fixture_and_runs_independent_postreads(self):
        with self.capture_mocks(outcome=TimeoutExpired("inert", subject._DEADLINE)):
            result = subject._capture(self.store, self.pin)
        self.invoke.assert_called_once()
        self.cleanup.assert_not_called()
        self.suspend.assert_called_once()
        self.assertEqual(result["status"], "REFUSED")
        self.assertTrue(result["fixture_preserved"])
        self.assertEqual(result["refusal"]["phase"], "GUEST")
        self.assertEqual(result["fixture_container"], self.container)
        self.assertIsNotNone(result["runtime_after"])
        self.assertIsNotNone(result["parent_after"])
        self.assertEqual(
            result["invocation_failure"]["reason"], "GUEST_OUTCOME_UNCAPTURED"
        )

    def test_known_complete_refusal_cleans_but_pre_yield_preservation_is_independent(
        self,
    ):
        for preserve in (False, True):
            with self.subTest(preserve=preserve):
                guest = self.envelope()
                guest.update(
                    status="REFUSED",
                    refusal={"phase": "ATTEMPT", "reason": "INERT"},
                    preserve_fixture_for_evidence=preserve,
                )
                guest["attempt"]["status"] = "REFUSED"
                with self.capture_mocks(outcome=guest):
                    result = subject._capture(self.store, self.pin)
                self.assertEqual(result["status"], "REFUSED")
                self.assertEqual(result["fixture_preserved"], preserve)
                self.assertEqual(self.cleanup.call_count, 0 if preserve else 1)
                self.assertTrue(result["guest_publication"]["complete"])

    def test_failed_publication_retains_siblings_and_never_retries_or_destroys(self):
        rows = self.envelope()["public_blobs"]
        real = self.store.put_expected
        attempted = []

        def put(stream, **kwargs):
            pin = kwargs["expected_digest"]
            attempted.append(pin)
            if pin == rows[0]["digest"]:
                raise OSError("inert public CAS failure")
            return real(stream, **kwargs)

        with (
            self.capture_mocks(),
            patch.object(self.store, "put_expected", side_effect=put),
        ):
            result = subject._capture(self.store, self.pin)
        self.assertEqual(attempted, [row["digest"] for row in rows])
        self.assertEqual(result["guest_publication"]["retained"], [rows[1]["digest"]])
        self.assertEqual(
            result["guest_publication"]["failed"][0]["digest"], rows[0]["digest"]
        )
        self.assertEqual(result["guest"]["public_blobs"], rows)
        self.assertTrue(result["fixture_preserved"])
        self.cleanup.assert_not_called()
        with patch.object(
            self.store, "put_expected", side_effect=AssertionError("no child retry")
        ):
            summary = subject._retain(self.store, result)
        self.assertEqual(summary["status"], "REFUSED")
        self.assertTrue(summary["fixture_preserved"])

    def test_pre_effect_refusals_do_not_invoke_and_copy_failure_cleans_only_owned_fixture(
        self,
    ):
        with (
            self.capture_mocks(),
            patch.object(
                subject, "_source_guard", side_effect=ValueError("inert source drift")
            ),
        ):
            with self.assertRaises(ValueError):
                subject._capture(self.store, self.pin)
        self.docker.assert_not_called()
        self.cleanup.assert_not_called()
        with self.capture_mocks(copy_error=True):
            result = subject._capture(self.store, self.pin)
        self.invoke.assert_not_called()
        self.cleanup.assert_called_once()
        self.assertFalse(result["invocation_started"])
        self.assertFalse(result["fixture_preserved"])

    def test_cleanup_failure_does_not_mask_primary_and_interrupt_preserves_report(self):
        guest = self.envelope()
        guest.update(status="REFUSED", refusal={"phase": "ATTEMPT", "reason": "INERT"})
        with self.capture_mocks(outcome=guest, cleanup_error=OSError("inert")):
            result = subject._capture(self.store, self.pin)
        self.assertEqual(result["refusal"]["phase"], "GUEST")
        self.assertEqual(result["cleanup_failure"], "OWNED_FIXTURE_CLEANUP_UNCONFIRMED")
        interruption = KeyboardInterrupt()
        with self.capture_mocks(outcome=interruption):
            with self.assertRaises(KeyboardInterrupt) as caught:
                subject._capture(self.store, self.pin)
        self.assertIs(caught.exception, interruption)
        partial = interruption._native_common_attempt_host_capture
        self.assertTrue(partial["fixture_preserved"])
        self.assertIsNotNone(partial["parent_after"])
        self.cleanup.assert_not_called()

    def test_fixed_invocation_and_seal_bounds_never_add_recovery_or_retry(self):
        envelope = self.envelope()
        wire = subject.canonical_json(envelope) + b"\n"
        with (
            patch.object(subject.native.existing, "_docker") as docker,
            patch.object(
                subject,
                "_bounded_guest",
                return_value=CompletedProcess([], 0, wire, b""),
            ) as runner,
        ):
            self.assertEqual(
                subject._invoke(self.container, self.bound["bundle_raw"], self.pin),
                envelope,
            )
        runner.assert_called_once()
        argv = runner.call_args.args[0]
        self.assertEqual(
            argv[-6:],
            [
                "-I",
                "-S",
                "-B",
                subject._FILES[subject._GUEST],
                self.container,
                self.pin,
            ],
        )
        self.assertEqual(len(docker.call_args_list), 2)
        seal = docker.call_args_list[1].args[7]
        self.assertIn(subject.guest.BUNDLE_PATH, seal)
        self.assertIn(str(subject._BUNDLE_LIMIT + 1), seal)
        self.assertNotIn("2097152", seal)
        for change in ("flag", "fields", "preserve", "limits", "interrupted"):
            bad = deepcopy(envelope)
            if change == "flag":
                bad[subject._FALSE[0]] = True
            elif change == "fields":
                bad["unreviewed"] = True
            elif change == "preserve":
                bad["preserve_fixture_for_evidence"] = True
            elif change == "limits":
                bad["limitations"] = []
            else:
                bad["interrupted"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject._guest_output(
                    CompletedProcess([], 0, subject.canonical_json(bad) + b"\n", b""),
                    self.container,
                    self.pin,
                )

    def test_bounded_process_drain_detects_stderr_overflow_deadline_and_closes_every_pipe(
        self,
    ):
        for mode in ("success", "stderr", "overflow", "timeout", "interrupt"):
            with self.subTest(mode=mode):
                stdout, stderr = Mock(), Mock()
                stdout.fileno.return_value, stderr.fileno.return_value = 31, 32
                child = Mock(stdout=stdout, stderr=stderr, pid=12345)
                child.poll.return_value = 0 if mode == "success" else None
                child.wait.return_value = 0
                selector = Mock()
                selector.__enter__ = Mock(return_value=selector)
                selector.__exit__ = Mock(return_value=False)
                selector.get_map.side_effect = [True, True, False]
                stream = stderr if mode == "stderr" else stdout
                selector.select.return_value = [(SimpleNamespace(fileobj=stream), 1)]
                if mode == "interrupt":
                    selector.select.side_effect = KeyboardInterrupt()
                chunks = [b"okay", b""] if mode == "success" else [b"too large"]
                times = [0, 301] if mode == "timeout" else [0, 1, 2, 3]
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
                    patch.object(subject, "_GUEST_LIMIT", 4),
                ):
                    if mode == "success":
                        self.assertEqual(
                            subject._bounded_guest(["inert"], maximum=4).stdout, b"okay"
                        )
                    else:
                        with self.assertRaises(
                            KeyboardInterrupt if mode == "interrupt" else ValueError
                        ):
                            subject._bounded_guest(["inert"], maximum=4)
                popen.assert_called_once()
                self.assertTrue(popen.call_args.kwargs["start_new_session"])
                stdout.close.assert_called_once()
                stderr.close.assert_called_once()
                self.assertEqual(kill.call_count, 0 if mode == "success" else 1)

    def test_preservation_pauses_only_reverified_owned_fixture_once_and_keeps_failures(
        self,
    ):
        for mode in ("success", "pause_failure", "wrong_owner", "already_paused"):
            with self.subTest(mode=mode):
                result = {
                    "fixture_container": self.container,
                    "fixture_name": "inert-owned",
                    "fixture_owner": "c" * 64,
                    "source": self.source,
                    "cleanup_failure": None,
                }
                commands = []
                reads = 0

                def invoke(argv, **bounds):
                    nonlocal reads
                    commands.append(argv)
                    self.assertEqual(bounds["timeout"], 10)
                    if "pause" in argv:
                        if mode == "pause_failure":
                            raise TimeoutExpired("inert pause", 10)
                        return CompletedProcess(
                            argv, 0, (self.container + "\n").encode(), b""
                        )
                    reads += 1
                    paused = mode == "already_paused" or (
                        reads == 2 and mode == "success"
                    )
                    return CompletedProcess(
                        argv,
                        0,
                        json.dumps(
                            [{"State": {"Running": True, "Paused": paused}}]
                        ).encode(),
                        b"",
                    )

                with (
                    patch.object(subject, "_bounded_guest", side_effect=invoke),
                    patch.object(
                        subject.native,
                        "_verify_fixture",
                        side_effect=ValueError("inert owner mismatch")
                        if mode == "wrong_owner"
                        else None,
                    ) as guard,
                ):
                    subject._suspend_preserved(result, [])
                self.assertEqual(
                    sum("pause" in argv for argv in commands),
                    0 if mode in {"wrong_owner", "already_paused"} else 1,
                )
                self.assertEqual(reads, 2)
                self.assertEqual(guard.call_count, 2)
                self.assertFalse(
                    any(
                        "stop" in argv or "rm" in argv or "unpause" in argv
                        for argv in commands
                    )
                )
                self.assertEqual(
                    result["preservation_suspension"]["paused"],
                    mode in {"success", "already_paused"},
                )
                if mode in {"pause_failure", "wrong_owner"}:
                    self.assertEqual(
                        result["cleanup_failure"],
                        "OWNED_FIXTURE_PRESERVATION_SUSPENSION_UNCONFIRMED",
                    )

    def test_generated_driver_is_fixed_source_artifact_and_semantic_refusal_keeps_capture(
        self,
    ):
        output = self.data.fixture.root / "new-blocked-driver"
        report, path, metadata = subject._driver(output)
        self.assertEqual(path.name, subject.driver._OUTPUT_NAME)
        self.assertEqual(metadata["digest"], subject.driver._OUTPUT[1])
        self.assertFalse(report["capture_performed"])
        self.assertFalse(report["phase3_eligible"])
        with self.capture_mocks():
            capture = subject._capture(self.store, self.pin)
        original = subject.canonical_json(capture) + b"\n"
        with patch.object(
            subject, "_verify", side_effect=ValueError("inert semantic refusal")
        ):
            summary = subject._retain(self.store, capture)
        self.assertEqual(summary["status"], "REFUSED")
        self.assertEqual(
            self.store.read(summary["capture_digest"], max_bytes=subject._LIMIT),
            original,
        )
        self.assertEqual(capture["status"], "CAPTURED_BOUNDED_ATTEMPT")


if __name__ == "__main__":
    unittest.main()
