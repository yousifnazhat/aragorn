"""New host composition only; Docker, subprocesses and VM effects are mocked."""

from contextlib import ExitStack, contextmanager, redirect_stdout
from copy import deepcopy
from io import BytesIO, StringIO
import json
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import capture_native_phase3_admission_case as subject
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from test_native_phase3_admission_case import builder_arguments, provisioning_inputs


class NativeAdmissionHostTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.arguments = builder_arguments()
        self.built = subject.case.build_native_admission_case_intent(**self.arguments)
        self.store = CAS(self.root / "cas")
        for pin, raw in self.built["input_blobs"].items():
            self.store.put_expected(
                BytesIO(raw), expected_digest=pin, max_bytes=len(raw)
            )
        self.intent_pin = self.built["intent_digest"]
        self.inspected = subject._inspect(
            CAS(self.store.root, read_only=True), self.intent_pin
        )
        self.source = json.loads(self.arguments["source_record_raw"])
        self.container = "d" * 64
        for guard in (
            patch.object(
                subject.native.existing,
                "_docker",
                side_effect=AssertionError("unmocked Docker forbidden"),
            ),
            patch.object(
                subject.subprocess,
                "run",
                side_effect=AssertionError("unmocked subprocess forbidden"),
            ),
        ):
            guard.start()
            self.addCleanup(guard.stop)

    def envelope(self, status="OBSERVED"):
        return {
            "schema": subject.guest.SCHEMA,
            "authority": subject.guest.AUTHORITY,
            "status": status,
            "fixture_container": self.container,
            "intent_digest": self.intent_pin,
            "input_bundle_digest": subject.case._digest(
                subject._bundle(self.inspected, self.intent_pin)
            ),
            "case_id": self.inspected["intent"]["case_id"],
            "branch": self.inspected["intent"]["branch"],
            **dict.fromkeys(subject._FALSE, False),
        }

    @contextmanager
    def offline_preparation(self):
        sources = (
            self.arguments["controller_source_raws"]
            | self.arguments["live_source_raws"]
            | self.arguments["case_source_raws"]
        )
        original_read = subject.pins._read_fixed

        def read(path, expected):
            relative = (
                path.relative_to(subject._ROOT).as_posix()
                if path.is_relative_to(subject._ROOT)
                else None
            )
            if relative in sources:
                raw = sources[relative]
                self.assertEqual(expected, (len(raw), subject.case._digest(raw)))
                return raw
            return original_read(path, expected)

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(subject, "_current_source", return_value=self.source)
            )
            stack.enter_context(
                patch.object(subject, "_source_guard", return_value=self.source)
            )
            stack.enter_context(
                patch.object(subject.pins, "_read_fixed", side_effect=read)
            )
            stack.enter_context(
                patch.object(
                    subject._API,
                    "_tree_file",
                    side_effect=lambda commit, path: {
                        "bytes": len(sources[str(path)]),
                        "digest": subject.case._digest(sources[str(path)]),
                    },
                )
            )
            stage = stack.enter_context(
                patch.object(
                    subject.profile,
                    "stage_runtime_native_admission_profile",
                    return_value=self.arguments["staged_profile"],
                )
            )
            yield stage

    def test_offline_prepare_updates_only_gateway_and_publishes_intent_last(self):
        publications = []
        original_put = CAS.put_expected

        def publish(store, stream, **kwargs):
            publications.append(kwargs["expected_digest"])
            return original_put(store, stream, **kwargs)

        with (
            self.offline_preparation() as staged,
            patch.object(CAS, "put_expected", autospec=True, side_effect=publish),
        ):
            report = subject._prepare(
                self.store, subject._DIRECT, self.arguments["nonce"]
            )
        self.assertEqual(report["status"], "PREPARED_EXPECTATIONS_ONLY")
        self.assertEqual(report["intent_digest"], publications[-1])
        self.assertEqual(len(publications), len(set(publications)))
        staged.assert_called_once()
        changed = report["successor_static_replacement"]
        self.assertEqual(
            changed["path"], "/usr/lib/systemd/system/aragorn-agent-gateway.service"
        )
        self.assertNotEqual(changed["before"], changed["after"])
        self.assertTrue(all(report[key] is False for key in subject._FALSE))
        inspected = subject._inspect(
            CAS(self.store.root, read_only=True), report["intent_digest"]
        )
        self.assertEqual(inspected["input_blobs"], self.inspected["input_blobs"])

    def test_stage_guard_rejects_changed_report_and_helper_overlap(self):
        subject._stage_guard(self.arguments["staged_profile"], self.inspected)
        bad = deepcopy(self.arguments["staged_profile"])
        bad["files"][0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            subject._stage_guard(bad, self.inspected)
        with (
            patch.object(
                subject,
                "_FILES",
                {"new": self.arguments["staged_profile"]["files"][0]["path"]},
            ),
            self.assertRaises(ValueError),
        ):
            subject._stage_guard(self.arguments["staged_profile"], self.inspected)

    def test_source_guard_checks_all_three_fixed_source_inventories(self):
        inspected = self.inspected
        expected = {
            path
            for key in (
                "controller_source_digests",
                "live_source_digests",
                "case_source_digests",
            )
            for path in inspected["intent"][key]
        }
        checked = []
        lookup = {
            path: pin
            for key in (
                "controller_source_digests",
                "live_source_digests",
                "case_source_digests",
            )
            for path, pin in inspected["intent"][key].items()
        }
        with (
            patch.object(subject, "_current_source", return_value=self.source),
            patch.object(
                subject._API,
                "_tree_file",
                side_effect=lambda commit, path: {
                    "digest": lookup[str(path)],
                    "bytes": len(inspected["input_blobs"][lookup[str(path)]]),
                },
            ),
            patch.object(
                subject.legacy,
                "_source_bytes",
                side_effect=lambda path, raw: checked.append(
                    path.relative_to(subject._ROOT).as_posix()
                ),
            ),
        ):
            self.assertEqual(subject._source_guard(inspected), self.source)
        self.assertEqual(set(checked), expected)
        with (
            patch.object(subject, "_current_source", return_value={"commit": "e" * 40}),
            self.assertRaises(ValueError),
        ):
            subject._source_guard(inspected)

    @contextmanager
    def capture_mocks(self, *, invocation_failure=False, parent_changed=False):
        with ExitStack() as stack:
            source_guard = stack.enter_context(
                patch.object(subject, "_source_guard", return_value=self.source)
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
                    return_value={"bytes": 1, "digest": "sha256:" + "1" * 64},
                )
            )
            stack.enter_context(
                patch.object(
                    subject.native.existing.campaign,
                    "current_v3_parent_identity",
                    return_value={"fixed": True},
                )
            )
            parent = {"image_inspect": {"RootFS": {"Layers": ["base"]}}}
            snapshots = stack.enter_context(
                patch.object(
                    subject.native.snapshot, "snapshot_parent", return_value=parent
                )
            )
            stack.enter_context(
                patch.object(
                    subject.native,
                    "_inspect",
                    side_effect=lambda kind, value: (
                        {
                            "Id": subject.native._IMAGE,
                            "RootFS": {"Type": "layers", "Layers": ["base", "native"]},
                        }
                        if kind == "image"
                        else {"Id": self.container}
                    ),
                )
            )
            runtime = stack.enter_context(
                patch.object(
                    subject.native,
                    "_snapshot_runtime",
                    return_value={"volume_inspect": {"fixed": True}},
                )
            )
            stack.enter_context(
                patch.object(
                    subject.native.previous,
                    "_parent_unchanged",
                    return_value=not parent_changed,
                )
            )
            stack.enter_context(
                patch.object(
                    subject.profile,
                    "stage_runtime_native_admission_profile",
                    return_value=self.arguments["staged_profile"],
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
                    subject.native,
                    "_create_arguments",
                    return_value=["create", "inert"],
                )
            )
            docker = stack.enter_context(
                patch.object(
                    subject.native.existing,
                    "_docker",
                    side_effect=lambda *args: (
                        (self.container + "\n").encode() if args[0] == "create" else b""
                    ),
                )
            )
            stack.enter_context(patch.object(subject.native, "_verify_fixture"))
            invoke = stack.enter_context(
                patch.object(
                    subject,
                    "_invoke",
                    side_effect=TimeoutExpired("fixed", 240)
                    if invocation_failure
                    else None,
                    return_value=self.envelope(),
                )
            )
            cleanup = stack.enter_context(
                patch.object(
                    subject.native.snapshot,
                    "_cleanup_snapshot",
                    return_value={
                        "container_name_absent": True,
                        "removed_id_absent": True,
                    },
                )
            )
            yield source_guard, snapshots, runtime, invoke, cleanup, docker

    def test_capture_once_and_postconditions_survive_guest_timeout(self):
        for failed, changed in ((False, False), (True, False), (False, True)):
            with (
                self.subTest(failed=failed, parent_changed=changed),
                self.capture_mocks(
                    invocation_failure=failed, parent_changed=changed
                ) as mocks,
            ):
                value = subject._capture(self.store, self.intent_pin)
                source, parent, runtime, invoke, cleanup, docker = mocks
                self.assertEqual(
                    value["status"], "REFUSED" if failed or changed else "OBSERVED"
                )
                invoke.assert_called_once()
                cleanup.assert_called_once()
                self.assertEqual(parent.call_count, 2)
                self.assertEqual(runtime.call_count, 2)
                self.assertEqual(source.call_count, 3)
                self.assertEqual(
                    sum(call.args[0] == "create" for call in docker.call_args_list), 1
                )
                self.assertEqual(
                    value["postcondition_failures"],
                    ["PARENT_READBACK_REFUSED"] if changed else [],
                )
                self.assertIsNotNone(value["runtime_after"])
                self.assertIsNotNone(value["parent_after"])
                self.assertFalse(value["independent_capture_replay_complete"])
                self.assertTrue(all(value[key] is False for key in subject._FALSE))

    def test_unknown_successor_refuses_before_source_or_docker(self):
        altered = deepcopy(self.inspected)
        altered["intent"]["case_id"] = "not-a-registered-case"
        with (
            patch.object(subject, "_inspect", return_value=altered),
            patch.object(subject, "_source_guard") as source,
            self.assertRaises(ValueError),
        ):
            subject._capture(self.store, self.intent_pin)
        source.assert_not_called()

    def test_plugin_input_bundle_is_staged_once_and_rechecked_after_timeout(self):
        self.arguments["case_id"] = subject.case.UPDATE_CASE
        self.built = subject.case.build_native_admission_case_intent(**self.arguments)
        for pin, raw in self.built["input_blobs"].items():
            self.store.put_expected(
                BytesIO(raw), expected_digest=pin, max_bytes=len(raw)
            )
        self.intent_pin = self.built["intent_digest"]
        self.inspected = subject._inspect(
            CAS(self.store.root, read_only=True), self.intent_pin
        )
        original_audit = subject._UPDATE._audit_bundle
        for timeout, changed in ((False, False), (True, False), (False, True)):
            calls = []
            audit_errors = []

            def audit(path, manifest):
                calls.append(path)
                try:
                    original_audit(path, manifest)
                except Exception as error:
                    audit_errors.append((type(error).__name__, str(error)))
                    raise
                if changed and len(calls) == 3:
                    raise ValueError("inert input replacement")

            with (
                self.subTest(timeout=timeout, changed=changed),
                self.capture_mocks(invocation_failure=timeout) as mocks,
                patch.object(subject._UPDATE, "_audit_bundle", side_effect=audit),
                patch.object(
                    subject._UPDATE.fixture,
                    "materialize",
                    wraps=subject._UPDATE.fixture.materialize,
                ) as materialize,
            ):
                value = subject._capture(self.store, self.intent_pin)
                _, _, _, invoke, cleanup, docker = mocks
                self.assertEqual(audit_errors, [], "real inert bundle audit refused")
                self.assertEqual(
                    value["status"], "REFUSED" if timeout or changed else "OBSERVED"
                )
                self.assertEqual(value["case_id"], subject.case.UPDATE_CASE)
                self.assertEqual(len(value["plugin_input_bundle"]["files"]), 13)
                self.assertEqual(len(calls), 3)
                materialize.assert_called_once()
                invoke.assert_called_once()
                cleanup.assert_called_once()
                copies = [
                    call.args
                    for call in docker.call_args_list
                    if call.args[0] == "cp"
                    and call.args[-1] == self.container + ":/opt/aragorn/"
                ]
                self.assertEqual(len(copies), 1)
                self.assertTrue(copies[0][1].endswith("/native-plugin-update-input"))
                self.assertEqual(
                    value["postcondition_failures"],
                    ["PLUGIN_INPUT_READBACK_REFUSED"] if changed else [],
                )

    def test_fixed_guest_invocation_and_proof_ceiling(self):
        envelope = self.envelope()
        for promoted in (False, True):
            value = dict(envelope)
            value["phase3_eligible"] = promoted
            raw = canonical_json(value) + b"\n"
            with (
                patch.object(subject.native.existing, "_docker") as docker,
                patch.object(
                    subject.subprocess,
                    "run",
                    return_value=CompletedProcess([], 0, raw, b""),
                ) as run,
            ):
                if promoted:
                    with self.assertRaises(ValueError):
                        subject._invoke(self.container, self.inspected, self.intent_pin)
                else:
                    self.assertEqual(
                        subject._invoke(
                            self.container, self.inspected, self.intent_pin
                        ),
                        value,
                    )
                run.assert_called_once()
                self.assertEqual(run.call_args.kwargs["timeout"], 240)
                argv = run.call_args.args[0]
                self.assertEqual(argv[-1], self.intent_pin)
                self.assertIn(subject._FILES[subject._GUEST], argv)
                self.assertEqual(docker.call_count, 2)

    def test_retention_is_child_first_and_input_loss_prevents_capture_publication(self):
        prepared = subject.case.prepare_native_admission_case(
            self.built["intent_raw"],
            expected_intent_digest=self.intent_pin,
            evidence_cas=CAS(self.store.root, read_only=True),
            provisioning_inputs=provisioning_inputs(),
        )
        value = {
            "intent_digest": self.intent_pin,
            "status": "REFUSED",
            "guest": {
                "prepared_case": {
                    "request": prepared["request"],
                    "request_digest": prepared["request_digest"],
                }
            },
            "independent_capture_replay_complete": False,
        }
        publications = []
        old_put, old_expected = CAS.put, CAS.put_expected

        def put(store, stream, **kwargs):
            publications.append("capture")
            return old_put(store, stream, **kwargs)

        def expected(store, stream, **kwargs):
            publications.append("request")
            return old_expected(store, stream, **kwargs)

        with (
            patch.object(CAS, "put", autospec=True, side_effect=put),
            patch.object(CAS, "put_expected", autospec=True, side_effect=expected),
        ):
            retained = subject._retain(self.store, value)
        self.assertEqual(publications[:2], ["request", "capture"])
        self.assertEqual(retained["status"], "REFUSED")
        self.assertFalse(retained["independent_capture_replay_complete"])
        with (
            patch.object(
                subject, "_inspect", side_effect=ValueError("input unavailable")
            ),
            patch.object(CAS, "put") as publish,
            self.assertRaises(ValueError),
        ):
            subject._retain(self.store, value)
        publish.assert_not_called()

    def test_replay_is_offline_after_capture_retention_and_failure_keeps_evidence(self):
        prepared = subject.case.prepare_native_admission_case(
            self.built["intent_raw"],
            expected_intent_digest=self.intent_pin,
            evidence_cas=CAS(self.store.root, read_only=True),
            provisioning_inputs=provisioning_inputs(),
        )
        value = {
            "intent_digest": self.intent_pin,
            "status": "OBSERVED",
            "guest": {
                "prepared_case": {
                    "request": prepared["request"],
                    "request_digest": prepared["request_digest"],
                }
            },
            "independent_capture_replay_complete": False,
        }
        raw = canonical_json(value) + b"\n"
        pin = subject.case._digest(raw)
        for failed in (False, True):

            def verify(observed, **kwargs):
                self.assertEqual(observed, raw)
                self.assertEqual(kwargs["expected_capture_digest"], pin)
                self.assertTrue(kwargs["evidence_cas"].read_only)
                self.assertEqual(kwargs["evidence_cas"].read(pin), raw)
                self.assertEqual(
                    kwargs["evidence_cas"].read(prepared["request_digest"]),
                    prepared["request_raw"],
                )
                if failed:
                    raise ValueError("inert semantic mismatch")
                return {
                    "status": "BOUNDED_CAPTURE_REPLAY_VERIFIED",
                    "independent_capture_replay_complete": True,
                    **dict.fromkeys(subject._FALSE, False),
                }

            with (
                self.subTest(failed=failed),
                patch.object(
                    subject.replay,
                    "verify_native_admission_capture",
                    side_effect=verify,
                ) as verifier,
                patch.object(subject, "_capture") as capture,
            ):
                retained = subject._retain(self.store, value)
                verifier.assert_called_once()
                capture.assert_not_called()
                self.assertEqual(
                    retained["status"], "REFUSED" if failed else "OBSERVED"
                )
                self.assertIs(
                    retained["independent_capture_replay_complete"], not failed
                )
                self.assertEqual(self.store.read(pin), raw)
                verification = json.loads(
                    self.store.read(retained["verification_digest"])
                )
                self.assertEqual(
                    verification["status"],
                    "REFUSED" if failed else "BOUNDED_CAPTURE_REPLAY_VERIFIED",
                )
                self.assertTrue(all(retained[key] is False for key in subject._FALSE))

    def test_verify_command_only_reads_caller_pinned_capture(self):
        raw = b'{"inert_cli_routing_only":true}\n'
        pin = self.store.put(BytesIO(raw), max_bytes=len(raw))
        expected = {
            "status": "BOUNDED_CAPTURE_REPLAY_VERIFIED",
            "independent_capture_replay_complete": True,
            **dict.fromkeys(subject._FALSE, False),
        }
        output = StringIO()
        with (
            patch.object(
                subject.replay, "verify_native_admission_capture", return_value=expected
            ) as verifier,
            patch.object(subject, "_capture") as capture,
            patch.object(CAS, "put") as put,
            patch.object(CAS, "put_expected") as put_expected,
            redirect_stdout(output),
        ):
            code = subject.main(
                [
                    "verify",
                    "--cas",
                    str(self.store.root),
                    "--expected-intent-digest",
                    self.intent_pin,
                    "--expected-capture-digest",
                    pin,
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue()), expected)
        verifier.assert_called_once()
        self.assertEqual(verifier.call_args.args, (raw,))
        self.assertTrue(verifier.call_args.kwargs["evidence_cas"].read_only)
        self.assertEqual(verifier.call_args.kwargs["expected_capture_digest"], pin)
        capture.assert_not_called()
        put.assert_not_called()
        put_expected.assert_not_called()

    def test_normal_verifier_return_cannot_promote_refusal_or_qualification(self):
        baseline = {
            "status": "BOUNDED_CAPTURE_REPLAY_VERIFIED",
            "independent_capture_replay_complete": True,
            **dict.fromkeys(subject._FALSE, False),
        }
        self.assertEqual(subject._verified_summary(baseline), baseline)
        for changes in (
            {"status": "REFUSED"},
            {"independent_capture_replay_complete": False},
            {"route_qualified": True},
            {"live_deployment_attested": True},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                subject._verified_summary(baseline | changes)


if __name__ == "__main__":
    unittest.main()
