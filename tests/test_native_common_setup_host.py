"""Host-only inert composition: real public inputs, mocked fixture and services.

The capture doubles below isolate host lifecycle and publication behavior. They
are deliberately not independently verified live setup records or acceptance.
"""

from contextlib import ExitStack, contextmanager, redirect_stdout
from copy import deepcopy
from io import BytesIO, StringIO
import json
from subprocess import CompletedProcess, TimeoutExpired
import unittest
from unittest.mock import patch

from aragorn.cas import CAS
from scripts import capture_native_phase3_common_setup as subject
from tests import test_native_phase3_common_preparation as data


class NativeCommonSetupHostTests(unittest.TestCase):
    def setUp(self):
        self.fixture = data.NativeCommonPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store = self.fixture.cas
        self.source = json.loads(self.fixture.arguments["source_record_raw"])
        self.sources = {
            path: ("inert host fixture source: " + path).encode()
            for path in subject._SOURCE_PATHS
        }
        self.sources.update(self.fixture.arguments["implementation_source_raws"])
        self.arguments = {
            key: value
            for key, value in self.fixture.arguments.items()
            if key not in {"container_id", "provisioning_inputs"}
        } | {
            "source_raws": self.sources,
            "setup_source_raw": self.sources[subject._SETUP],
            "wrapper_source_raw": self.sources[subject._GUEST],
            "host_source_raw": self.sources[subject._HOST],
        }
        self.built = subject.contract.prepare_common_setup_inputs(**self.arguments)
        for pin, raw in self.built["input_blobs"].items():
            self.store.put_expected(
                BytesIO(raw), expected_digest=pin, max_bytes=subject._BUNDLE_LIMIT
            )
        self.pin = self.built["bundle_digest"]
        self.bound = subject._inspect(self.fixture.reader, self.pin)
        self.container = data.CONTAINER
        self.events = []
        for target, name in (
            (subject.native.existing, "_docker"),
            (subject.subprocess, "run"),
        ):
            guard = patch.object(
                target,
                name,
                side_effect=AssertionError("unmocked native execution forbidden"),
            )
            guard.start()
            self.addCleanup(guard.stop)

    def envelope(self):
        raw = subject.canonical_json({"inert_public_host_lifecycle_only": True})
        pin = subject._API._digest(raw)
        return {
            "schema": subject.guest.SCHEMA,
            "authority": subject.guest.AUTHORITY,
            "status": "PREPARED_NOT_ACTIVATED",
            "container_id": self.container,
            "input_bundle_digest": self.pin,
            "setup": {
                "status": "PREPARED_NOT_ACTIVATED",
                "public_blob_attempts": [{"digest": pin, "bytes": len(raw)}],
                "preparation": {"retained_blob_digests": [pin]},
            },
            "public_blobs": [{"digest": pin, "bytes": len(raw), "text": raw.decode()}],
            "export_failures": [],
            "refusal": None,
            "input_bundle_readback": True,
            "controller_sources": {"inert": True},
            "controller_sources_after": {"inert": True},
            "postcondition_failures": [],
            "limitations": list(subject.guest._LIMITATIONS),
            **dict.fromkeys(subject._FALSE, False),
        }

    @contextmanager
    def capture_mocks(self, *, timeout=False, cleanup_failure=False):
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
                        "bytes": len(self.sources[str(path)]),
                        "digest": subject._API._digest(self.sources[str(path)]),
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
                    side_effect=lambda *_: self.events.append("parent") or self.parent,
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
                    return_value=self.fixture.stage,
                )
            )
            stack.enter_context(
                patch.object(
                    subject.profile, "_verified_payloads", return_value=({}, {})
                )
            )
            stack.enter_context(patch.object(subject.profile.base, "_audit_tree"))
            self.docker = stack.enter_context(
                patch.object(
                    subject.native.existing,
                    "_docker",
                    side_effect=lambda *argv: (
                        (self.container + "\n").encode() if argv[0] == "create" else b""
                    ),
                )
            )

            def invoke(*_):
                self.events.append("invoke")
                if timeout:
                    raise TimeoutExpired("inert guest", 240)
                return self.envelope()

            self.invoke = stack.enter_context(
                patch.object(subject, "_invoke", side_effect=invoke)
            )

            def cleanup(name, owner, image):
                self.events.append("cleanup")
                if cleanup_failure:
                    raise RuntimeError("inert cleanup refusal")
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
            yield stack

    def test_real_public_prepare_and_inspect_share_exact_common74_copy_inventory(self):
        self.assertEqual(subject._FILES, subject.contract.FIXTURE_HELPERS)
        self.assertEqual(subject._SOURCE_PATHS, subject.contract.SOURCE_PATHS)
        self.assertNotIn("src/aragorn/phase3_deployment.py", subject._FILES)
        self.assertEqual(
            len(
                json.loads(self.bound["setup_arguments"]["static_pin_manifest_raw"])[
                    "file_digests"
                ]
            ),
            20,
        )
        publications = []
        real_put = self.store.put_expected
        real_read = subject.pins._read_fixed

        def read(path, expected):
            relative = (
                path.relative_to(subject._ROOT).as_posix()
                if path.is_relative_to(subject._ROOT)
                else None
            )
            if relative in self.sources:
                raw = self.sources[relative]
                self.assertEqual(expected, (len(raw), subject._API._digest(raw)))
                return raw
            return real_read(path, expected)

        def put(stream, **kwargs):
            publications.append(kwargs["expected_digest"])
            return real_put(stream, **kwargs)

        with (
            patch.object(subject, "_current_source", return_value=self.source),
            patch.object(subject.legacy, "_source_bytes"),
            patch.object(
                subject._API,
                "_tree_file",
                side_effect=lambda commit, path: {
                    "bytes": len(self.sources[str(path)]),
                    "digest": subject._API._digest(self.sources[str(path)]),
                },
            ),
            patch.object(subject.pins, "_read_fixed", side_effect=read),
            patch.object(
                subject.profile,
                "stage_runtime_phase3_ingress_profile",
                return_value=self.fixture.stage,
            ) as stage,
            patch.object(self.store, "put_expected", side_effect=put),
        ):
            result = subject._prepare(
                self.store, self.arguments["case_id"], self.arguments["nonce"]
            )
        self.assertEqual(result["status"], "PREPARED_EXPECTATIONS_ONLY")
        self.assertEqual(result["input_bundle_digest"], self.pin)
        self.assertEqual(publications[-1], self.pin)
        self.assertEqual(len(publications), len(set(publications)))
        self.assertEqual(subject._inspect(self.fixture.reader, self.pin), self.bound)
        self.assertTrue(all(result[key] is False for key in subject._FALSE))
        stage.assert_called_once()

    def test_source_and_stage_guards_refuse_unsigned_drift_and_helper_overlap(self):
        checked = []
        with (
            patch.object(subject, "_current_source", return_value=self.source),
            patch.object(
                subject._API,
                "_tree_file",
                side_effect=lambda commit, path: {
                    "bytes": len(self.sources[str(path)]),
                    "digest": subject._API._digest(self.sources[str(path)]),
                },
            ),
            patch.object(
                subject.legacy,
                "_source_bytes",
                side_effect=lambda path, _: checked.append(
                    path.relative_to(subject._ROOT).as_posix()
                ),
            ),
        ):
            self.assertEqual(subject._source_guard(self.bound), self.source)
        self.assertEqual(set(checked), set(subject._SOURCE_PATHS))
        with (
            patch.object(subject, "_current_source", return_value={"commit": "e" * 40}),
            self.assertRaises(ValueError),
        ):
            subject._source_guard(self.bound)
        subject._stage_guard(self.fixture.stage, self.bound["stage_raw"])
        bad = deepcopy(self.fixture.stage)
        bad["files"][0]["mode"] = "0777"
        with self.assertRaises(ValueError):
            subject._stage_guard(bad, subject.canonical_json(bad))
        with (
            patch.dict(
                subject._FILES, {"unreviewed": self.fixture.stage["files"][0]["path"]}
            ),
            self.assertRaises(ValueError),
        ):
            subject._stage_guard(self.fixture.stage, self.bound["stage_raw"])

    def test_fixed_invocation_seal_and_strict_bounded_guest_envelope(self):
        expected = self.envelope()
        wire = subject.canonical_json(expected) + b"\n"
        with (
            patch.object(subject.native.existing, "_docker") as docker,
            patch.object(
                subject.subprocess,
                "run",
                return_value=CompletedProcess([], 0, wire, b""),
            ) as run,
        ):
            result = subject._invoke(self.container, self.built["bundle_raw"], self.pin)
        self.assertEqual(result, expected)
        self.assertEqual(docker.call_count, 2)
        seal = docker.call_args_list[1].args[7]
        self.assertEqual(seal, subject._seal_program())
        self.assertIn(subject.guest.BUNDLE_PATH, seal)
        self.assertIn("8388608", seal)
        self.assertNotIn("2097152", seal)
        self.assertEqual(
            run.call_args.args[0][-3:],
            [subject._FILES[subject._GUEST], self.container, self.pin],
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 240)
        for change in ("activation", "status", "extra"):
            value = deepcopy(expected)
            if change == "activation":
                value["activation_performed"] = True
            elif change == "status":
                value["status"] = "OBSERVED"
            else:
                value["unreviewed"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject._guest_output(
                    CompletedProcess([], 0, subject.canonical_json(value) + b"\n", b""),
                    self.container,
                    self.pin,
                )

    def test_capture_retains_public_children_before_cleanup_once(self):
        real_put = self.store.put_expected

        def put(stream, **kwargs):
            self.events.append("retain-child")
            return real_put(stream, **kwargs)

        with (
            self.capture_mocks(),
            patch.object(self.store, "put_expected", side_effect=put),
        ):
            result = subject._capture(self.store, self.pin)
        self.assertEqual(result["status"], "PREPARED_NOT_ACTIVATED")
        self.invoke.assert_called_once()
        self.cleanup.assert_called_once()
        self.assertLess(self.events.index("retain-child"), self.events.index("cleanup"))
        self.assertTrue(result["guest_publication"]["complete"])
        self.assertEqual(result["postcondition_failures"], [])
        self.assertEqual(self.runtime_reads.call_count, 2)
        self.assertEqual(self.parent_reads.call_count, 2)
        self.assertTrue(all(result[key] is False for key in subject._FALSE))

    def test_timeout_and_cleanup_failure_keep_primary_and_independent_postreads(self):
        with self.capture_mocks(timeout=True, cleanup_failure=True):
            result = subject._capture(self.store, self.pin)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["refusal"]["phase"], "GUEST")
        self.assertEqual(result["cleanup_failure"], "OWNED_FIXTURE_CLEANUP_UNCONFIRMED")
        self.invoke.assert_called_once()
        self.cleanup.assert_called_once()
        self.assertEqual(self.runtime_reads.call_count, 2)
        self.assertEqual(self.parent_reads.call_count, 2)
        self.assertIn("OWNED_CLEANUP_UNCONFIRMED", result["postcondition_failures"])

    def test_partial_export_failure_preserves_guest_and_never_retries_failed_child(
        self,
    ):
        with (
            self.capture_mocks(),
            patch.object(
                self.store,
                "put_expected",
                side_effect=OSError("inert publication failure"),
            ) as put,
        ):
            result = subject._capture(self.store, self.pin)
        self.assertEqual(result["refusal"]["phase"], "PUBLIC_EXPORT_RETENTION")
        self.assertIsNotNone(result["guest"])
        self.assertEqual(len(result["guest_publication"]["attempted"]), 1)
        self.assertEqual(result["guest_publication"]["retained"], [])
        put.assert_called_once()
        self.cleanup.assert_called_once()
        with (
            patch.object(
                subject, "_retain_guest_exports", side_effect=AssertionError("no retry")
            ),
            patch.object(
                subject.contract,
                "verify_native_common_setup_capture",
                side_effect=AssertionError("refused capture must not verify"),
            ),
        ):
            summary = subject._retain(self.store, result)
        self.assertEqual(summary["status"], "REFUSED")
        retained = json.loads(
            self.fixture.reader.read(
                summary["capture_digest"], max_bytes=subject._LIMIT
            )
        )
        self.assertEqual(retained["guest"], result["guest"])

    def test_success_cannot_omit_journaled_blobs_or_export_failures(self):
        for change in ("omitted", "failure", "unlisted", "preparation"):
            envelope = self.envelope()
            if change == "omitted":
                envelope["public_blobs"] = []
            elif change == "failure":
                envelope["export_failures"] = [
                    {"digest": self.pin, "reason": "READ_REFUSED"}
                ]
            elif change == "unlisted":
                envelope["setup"]["public_blob_attempts"] = []
            else:
                envelope["setup"]["preparation"]["retained_blob_digests"] = []
            result = {
                "guest": envelope,
                "guest_publication": {
                    "attempted": [],
                    "retained": [],
                    "complete": False,
                },
            }
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject._retain_guest_exports(self.store, result)

    def test_replay_refusal_preserves_original_capture_without_effect_retry(self):
        with self.capture_mocks():
            result = subject._capture(self.store, self.pin)
        with (
            patch.object(
                subject.contract,
                "verify_native_common_setup_capture",
                side_effect=ValueError("inert semantic refusal"),
            ),
            patch.object(
                subject, "_invoke", side_effect=AssertionError("no replay effect")
            ),
        ):
            summary = subject._retain(self.store, result)
        self.assertEqual(summary["status"], "REFUSED")
        self.assertFalse(summary["independent_capture_replay_complete"])
        self.assertEqual(
            self.fixture.reader.read(
                summary["capture_digest"], max_bytes=subject._LIMIT
            ),
            subject.canonical_json(result) + b"\n",
        )
        self.assertEqual(
            json.loads(self.fixture.reader.read(summary["verification_digest"]))[
                "reason"
            ],
            "INDEPENDENT_PUBLIC_SETUP_REPLAY_REFUSED",
        )

    def test_verify_cli_is_readonly_and_never_routes_to_capture(self):
        raw = b'{"inert_capture":true}\n'
        pin = self.store.put(BytesIO(raw), max_bytes=len(raw))
        verified = {
            "status": "BOUNDED_PUBLIC_SETUP_REPLAY_VERIFIED",
            "independent_capture_replay_complete": True,
            "private_writer_semantics_replayed": False,
            **dict.fromkeys(subject._FALSE, False),
        }
        with (
            patch.object(subject, "_capture", side_effect=AssertionError("no effect")),
            patch.object(subject, "_prepare", side_effect=AssertionError("no prepare")),
            patch.object(
                subject.contract,
                "verify_native_common_setup_capture",
                return_value=verified,
            ) as replay,
            redirect_stdout(StringIO()) as output,
        ):
            code = subject.main(
                [
                    "verify",
                    "--cas",
                    str(self.store.root),
                    "--expected-capture-digest",
                    pin,
                ]
            )
        self.assertEqual(code, 0)
        self.assertTrue(replay.call_args.kwargs["store"].read_only)
        self.assertEqual(json.loads(output.getvalue())["status"], verified["status"])


if __name__ == "__main__":
    unittest.main()
