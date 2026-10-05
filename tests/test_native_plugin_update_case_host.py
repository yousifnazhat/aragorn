"""New fixed host wiring only; all fixture execution and subprocesses are inert."""

import copy
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import capture_native_phase3_plugin_update_case as subject
from aragorn.oci_worker_protocol import canonical_json
import test_native_phase3_plugin_update_case as fixture


class NativePluginUpdateCaseHostTests(unittest.TestCase):
    def setUp(self):
        # Reuse data construction, not any pre-existing test method or suite.
        self.data = fixture.NativePluginUpdateCaseTests()
        self.addCleanup(self.data.doCleanups)
        self.data.setUp()
        self.inspected = subject._inspect(self.data.readonly, self.data.intent_pin)
        self.bundle = subject._bundle(self.inspected, self.data.intent_pin)
        self.container = self.data.capture["fixture_container"]
        self.argv = [
            "exec",
            self.container,
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            subject._FILES[subject._GUEST],
            self.container,
            str(os.geteuid()),
            str(os.getegid()),
        ]
        for guard in (
            patch.object(
                subject.prior.prior.prior.existing,
                "_docker",
                side_effect=AssertionError("live Docker forbidden"),
            ),
            patch.object(
                subject.subprocess,
                "run",
                side_effect=AssertionError("live child forbidden"),
            ),
        ):
            guard.start()
            self.addCleanup(guard.stop)

    def envelope(self, status="OBSERVED"):
        prepared = self.data.prepare()
        live = copy.deepcopy(self.data.capture["live_identity"])
        live["update_observation"] = copy.deepcopy(self.data.capture["observation"])
        return {
            "schema": subject._GUEST_SCHEMA,
            "authority": subject._GUEST_AUTHORITY,
            "status": status,
            "case_id": subject.case.ROUTE,
            "branch": subject.case.BRANCH,
            "fixture_container": self.container,
            "input_bundle_digest": subject.case._digest(self.bundle),
            "intent_digest": self.data.intent_pin,
            "identity_observation": live if status == "OBSERVED" else None,
            "prepared_case": {
                "request": prepared["request"],
                "request_digest": prepared["request_digest"],
                "local_pre_activation_readback": True,
                "authority": subject._GUEST_AUTHORITY,
                "host_ack_received": False,
                **dict.fromkeys(subject._FALSE, False),
            }
            if status == "OBSERVED"
            else None,
            "refusal": None
            if status == "OBSERVED"
            else {"phase": "INPUT_CLOSURE", "reason": "CASE_GUEST_REFUSED"},
            **dict.fromkeys(subject._FALSE, False),
        }

    def cli(self, command, *extra):
        output = io.StringIO()
        with redirect_stdout(output):
            code = subject.main(
                [
                    command,
                    "--cas",
                    str(self.data.cas.root),
                    "--expected-intent-digest",
                    self.data.intent_pin,
                    *extra,
                ]
            )
        return code, json.loads(output.getvalue())

    def test_offline_inspect_and_replay_use_caller_pins_without_capture(self):
        prepared = self.data.prepare()
        self.data.put(prepared["request_raw"])
        with patch.object(
            subject, "_capture", side_effect=AssertionError("offline command captured")
        ):
            code, inspected = self.cli("inspect")
            self.assertEqual(code, 0)
            self.assertEqual(inspected["intent"], self.data.intent)
            self.assertEqual(inspected["status"], "INPUT_CLOSURE_VERIFIED")
            code, replayed = self.cli(
                "replay",
                "--expected-request-digest",
                prepared["request_digest"],
                "--expected-collection-digest",
                self.data.retained["collection_digest"],
            )
            self.assertEqual(code, 0)
            self.assertEqual(
                replayed["status"], "BOUNDED_PREPARED_CASE_READBACK_JOINS_VERIFIED"
            )
            self.assertTrue(all(replayed[key] is False for key in subject._FALSE))

    def test_source_guard_joins_signed_record_tree_and_direct_bytes_before_capture(
        self,
    ):
        source = self.data.capture["source"]
        inventory = (
            self.data.intent["controller_source_digests"]
            | self.data.intent["live_source_digests"]
        )
        package = subject.prior.prior.prior

        def tree(commit, path):
            self.assertEqual(commit, source["commit"])
            pin = inventory[str(path)]
            return {"digest": pin, "bytes": len(self.inspected["input_blobs"][pin])}

        def source_record():
            self.assertIs(
                package._FIXTURE_SOURCES, subject.prior.prior._FIXTURE_SOURCES
            )
            return source

        with (
            patch.object(package, "_source", side_effect=source_record),
            patch.object(subject.prior._api, "_tree_file", side_effect=tree),
            patch.object(subject, "_source_bytes") as read,
        ):
            self.assertEqual(subject._source_guard(self.inspected), source)
        self.assertEqual(read.call_count, 6)
        with (
            patch.object(
                package, "_source", return_value={**source, "commit": "0" * 40}
            ),
            patch.object(subject.prior.prior, "_capture") as capture,
            self.assertRaises(subject.case.NativePluginUpdateCaseError),
        ):
            subject._capture(self.data.cas, self.data.intent_pin)
        capture.assert_not_called()
        path = Path(self.data.temporary.name).resolve() / "controller.py"
        path.write_bytes(b"bounded inert source")
        subject._source_bytes(path, b"bounded inert source")
        with self.assertRaises(subject.case.NativePluginUpdateCaseError):
            subject._source_bytes(path, b"different byte count")
        alias = path.with_name("alias.py")
        alias.symlink_to(path)
        with self.assertRaises(subject.case.NativePluginUpdateCaseError):
            subject._source_bytes(alias, b"bounded inert source")

    def test_stage_guard_uses_exact_seventy_file_profile_without_recopying_cas(self):
        manifest = self.data.capture["staged_profile"]
        subject._stage_guard(manifest, self.inspected)
        subject.prior._stage_pins(
            manifest,
            self.data.capture["live_identity"]["static_pin_manifest"]["file_digests"],
        )
        self.assertNotIn("src/aragorn/cas.py", subject._FILES)
        self.assertIn(
            "/usr/lib/aragorn/aragorn/cas.py",
            {item["path"] for item in manifest["files"]},
        )
        for kind in ("schema", "count", "duplicate", "digest", "collision"):
            changed = copy.deepcopy(manifest)
            if kind == "schema":
                changed["schema"] = "other"
            elif kind == "count":
                changed["files"].pop()
            elif kind == "duplicate":
                changed["files"][1] = changed["files"][0]
            elif kind == "digest":
                changed["files"][0]["digest"] = "sha256:" + "0" * 64
            else:
                changed["files"][0]["path"] = subject._FILES[subject._GUEST]
            with (
                self.subTest(kind=kind),
                self.assertRaises(subject.case.NativePluginUpdateCaseError),
            ):
                subject._stage_guard(changed, self.inspected)

    def test_fixed_transfer_runs_once_and_refusal_is_not_retried(self):
        for status in ("OBSERVED", "REFUSED"):
            envelope = self.envelope(status)
            completed = SimpleNamespace(
                returncode=0 if status == "OBSERVED" else 126,
                stdout=canonical_json(envelope) + b"\n",
                stderr=b"",
            )
            with (
                self.subTest(status=status),
                patch.object(subject.prior.prior.prior.existing, "_docker") as docker,
                patch.object(subject.subprocess, "run", return_value=completed) as run,
            ):
                result = subject._invoke(
                    self.argv,
                    self.container,
                    self.inspected,
                    self.data.intent_pin,
                    self.bundle,
                )
            self.assertEqual(result, envelope)
            self.assertEqual(docker.call_count, 3)
            self.assertEqual(
                [call.args[0] for call in docker.call_args_list], ["cp", "cp", "exec"]
            )
            self.assertEqual(
                docker.call_args_list[0].args[-1],
                self.container + ":" + subject.prior._MANIFEST,
            )
            self.assertEqual(
                docker.call_args_list[1].args[-1],
                self.container + ":" + subject._BUNDLE_PATH,
            )
            run.assert_called_once()
            self.assertEqual(
                run.call_args.args[0],
                [
                    *subject.prior._api._DOCKER,
                    *self.argv,
                    self.data.intent["static_pin_manifest_digest"],
                    subject.case._digest(self.bundle),
                    self.data.intent_pin,
                ],
            )
            self.assertEqual(run.call_args.kwargs["timeout"], 240)
        with (
            patch.object(subject.prior.prior.prior.existing, "_docker") as docker,
            patch.object(subject.subprocess, "run") as run,
            self.assertRaises(subject.case.NativePluginUpdateCaseError),
        ):
            subject._invoke(
                [*self.argv, "unrequested"],
                self.container,
                self.inspected,
                self.data.intent_pin,
                self.bundle,
            )
        docker.assert_not_called()
        run.assert_not_called()

    def test_guest_and_prepared_claims_cannot_promote_authority(self):
        for key, nested, value in (
            ("authority", False, "QUALIFIED"),
            ("fresh_campaign_execution", False, True),
            ("authority", True, "HOST_ACK"),
            ("preactivation_commit_verified", True, True),
            ("host_ack_received", True, True),
            ("request_digest", True, "sha256:" + "0" * 64),
        ):
            envelope = self.envelope()
            (envelope["prepared_case"] if nested else envelope)[key] = value
            completed = SimpleNamespace(
                returncode=0, stdout=canonical_json(envelope) + b"\n", stderr=b""
            )
            with (
                self.subTest(key=key, nested=nested),
                patch.object(subject.prior.prior.prior.existing, "_docker"),
                patch.object(subject.subprocess, "run", return_value=completed) as run,
                self.assertRaises(subject.case.NativePluginUpdateCaseError),
            ):
                subject._invoke(
                    self.argv,
                    self.container,
                    self.inspected,
                    self.data.intent_pin,
                    self.bundle,
                )
            run.assert_called_once()

    def test_capture_wires_only_fixed_successor_and_blocks_second_handoff(self):
        original_files = subject.prior.prior._FILES
        manifest, source = (
            self.data.capture["staged_profile"],
            self.data.capture["source"],
        )
        input_bundle = self.data.capture["input_bundle"]
        for repeated in (False, True):
            envelope = self.envelope()

            def capture():
                self.assertIs(subject.prior.prior._FILES, subject._FILES)
                self.assertEqual(subject.prior.prior._CHECKER, subject._GUEST)
                subject.prior.prior.prior.profile.stage_runtime_native_startup_profile(
                    "inert-stage"
                )
                observation = subject.prior.prior._invoke_guest(
                    self.argv, self.container
                )
                if repeated:
                    subject.prior.prior._invoke_guest(self.argv, self.container)
                return {
                    "source": source,
                    "observation": observation,
                    "input_bundle": input_bundle,
                    "invocation": {"argv": [*subject.prior._api._DOCKER, *self.argv]},
                }

            with (
                self.subTest(repeated=repeated),
                patch.object(subject, "_source_guard", return_value=source) as guard,
                patch.object(
                    subject.prior.prior, "_capture", side_effect=capture
                ) as inherited,
                patch.object(
                    subject.prior.prior.prior.profile,
                    "stage_runtime_native_startup_profile",
                    return_value=manifest,
                ),
                patch.object(
                    subject.prior._api,
                    "_tree_file",
                    side_effect=lambda commit, path: {"path": str(path)},
                ),
                patch.object(subject, "_invoke", return_value=envelope) as invoke,
            ):
                if repeated:
                    with self.assertRaises(subject.case.NativePluginUpdateCaseError):
                        subject._capture(self.data.cas, self.data.intent_pin)
                else:
                    result = subject._capture(self.data.cas, self.data.intent_pin)
                    captured = result["capture"]
                    self.assertIs(
                        captured["observation"],
                        envelope["identity_observation"]["update_observation"],
                    )
                    self.assertIs(captured["input_bundle"], input_bundle)
                    self.assertEqual(
                        set(captured["live_identity_sources"]),
                        set(subject.case.LIVE_SOURCE_PATHS),
                    )
                    self.assertNotIn("update_observation", captured["live_identity"])
                    self.assertEqual(
                        captured["invocation"]["argv"][-3:],
                        [
                            self.data.intent["static_pin_manifest_digest"],
                            subject.case._digest(self.bundle),
                            self.data.intent_pin,
                        ],
                    )
                    self.assertEqual(guard.call_count, 3)
            inherited.assert_called_once()
            invoke.assert_called_once()
            self.assertIs(subject.prior.prior._FILES, original_files)

    def test_capture_cli_preserves_one_shot_envelope_when_offline_retention_refuses(
        self,
    ):
        output = Path(self.data.temporary.name).resolve() / "capture.json"
        envelope = {
            "capture": {"status": "OBSERVED"},
            "guest": self.envelope(),
            "input_bundle_digest": subject.case._digest(self.bundle),
        }
        with (
            patch.object(subject, "_capture", return_value=envelope) as capture,
            patch.object(
                subject,
                "_retain",
                side_effect=ValueError("private diagnostic must not leak"),
            ) as retain,
        ):
            code, value = self.cli("capture", "--out", str(output))
        self.assertEqual(code, 2)
        self.assertEqual(value["status"], "REFUSED")
        self.assertNotIn("private diagnostic", json.dumps(value))
        self.assertEqual(output.read_bytes(), canonical_json(envelope) + b"\n")
        capture.assert_called_once()
        retain.assert_called_once()


if __name__ == "__main__":
    unittest.main()
