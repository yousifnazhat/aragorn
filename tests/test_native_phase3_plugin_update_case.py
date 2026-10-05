"""Fixed request joins using inert writer bytes and retained-report structure."""

import copy
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import native_phase3_plugin_update_case as subject
from aragorn import native_phase3_plugin_update_collection as collection
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase3_deployment import build_phase3_deployment_identity
import test_native_phase3_plugin_update_live_binding as fixture

_ROOT = Path(__file__).resolve().parents[1]
_CONFIG = (
    _ROOT
    / "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json"
)


class NativePluginUpdateCaseTests(unittest.TestCase):
    def setUp(self):
        old_raw = fixture._CAPTURE.read_bytes()
        self.assertEqual(subject._digest(old_raw), fixture._CAPTURE_PIN)
        capture = json.loads(old_raw)
        sources = fixture._fixture(capture)
        self.capture = capture
        capture_raw = canonical_json(capture) + b"\n"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(Path(self.temporary.name) / "cas")
        self.readonly = CAS(self.cas.root, read_only=True)
        source_raw = canonical_json(capture["source"])
        static_raw = canonical_json(capture["live_identity"]["static_pin_manifest"])
        pins = {
            "expected_capture_digest": subject._digest(capture_raw),
            "expected_source_digest": subject._digest(source_raw),
            "expected_source_commit": capture["source"]["commit"],
        }
        projected = collection.prepare_native_plugin_update_collection(
            capture_raw, **pins
        )
        self.retained = collection.collect_native_plugin_update_live_observation(
            capture_raw,
            **pins,
            deployment_raw=projected["deployment_raw"],
            expected_deployment_digest=projected["deployment_digest"],
            expected_live_identity_digest=subject._digest(
                canonical_json(capture["live_identity"])
            ),
            static_pin_manifest_raw=static_raw,
            expected_static_pin_manifest_digest=subject._digest(static_raw),
            live_source_raws=sources,
            expected_live_source_digests={
                path: subject._digest(raw) for path, raw in sources.items()
            },
            evidence_cas=self.cas,
        )
        controllers = {
            path: self.put(("inert controller source: " + path).encode())
            for path in subject.CONTROLLER_SOURCE_PATHS
        }
        self.artifacts = dict(projected["identity_artifacts"])
        case_adapter_digest = self.put(self.artifacts["adapter"])
        self.artifacts["adapter"] = subject._artifact(
            "adapter",
            {
                "controller_source_digests": controllers,
                "case_adapters": {
                    subject.ROUTE: {
                        "branch": subject.BRANCH,
                        "artifact_digest": case_adapter_digest,
                    }
                },
            },
        )
        deployment = build_phase3_deployment_identity(
            {name: self.put(raw) for name, raw in self.artifacts.items()}
        )
        self.intent = {
            "schema": subject.INTENT_SCHEMA,
            "case_id": subject.ROUTE,
            "branch": subject.BRANCH,
            "nonce": "a" * 64,
            "deployment_digest": self.put(canonical_json(deployment)),
            "case_adapter_digest": case_adapter_digest,
            "source_commit": capture["source"]["commit"],
            "source_record_digest": self.put(source_raw),
            "static_pin_manifest_digest": self.put(static_raw),
            "controller_source_digests": controllers,
            "live_source_digests": {
                path: self.put(raw) for path, raw in sources.items()
            },
        }
        self.intent_raw = canonical_json(self.intent)
        self.intent_pin = self.put(self.intent_raw)
        setup, live = capture["observation"]["setup"], subject.live
        self.inputs = {
            live._CONFIG: canonical_json(json.loads(_CONFIG.read_bytes())),
            live._WORKER: canonical_json(setup["worker_binding"]),
            live._POLICY: canonical_json(setup["policy"]),
            live._GRANT: canonical_json(setup["grant"]),
            live._GENESIS: canonical_json(setup["empty_store"]["genesis"]),
            live._RUNTIME: canonical_json(
                {
                    "schema": "aragorn/runtime-action-runtime-binding/v2",
                    "runtime_digest": setup["runtime_digest"],
                    "runtime_profile_digest": subject._digest(
                        canonical_json(setup["runtime_profile"])
                    ),
                }
            ),
            live._OBSERVATION: canonical_json(
                {
                    "schema": "aragorn/runtime-observation-binding/v2",
                    "sensor_digest": setup["policy"]["sensor_digest"],
                    "runtime_profile": setup["runtime_profile"],
                }
            ),
        }

    def put(self, raw):
        return self.cas.put(BytesIO(raw), max_bytes=len(raw))

    def prepare(self, **overrides):
        arguments = {
            "expected_intent_digest": self.intent_pin,
            "evidence_cas": self.readonly,
            "provisioning_inputs": self.inputs,
        }
        arguments.update(overrides)
        return subject.prepare_native_plugin_update_case(self.intent_raw, **arguments)

    def replay(self, prepared, **overrides):
        arguments = {
            "expected_request_digest": prepared["request_digest"],
            "expected_intent_digest": self.intent_pin,
            "expected_collection_digest": self.retained["collection_digest"],
            "evidence_cas": self.readonly,
        }
        arguments.update(overrides)
        return subject.verify_native_plugin_update_case(
            prepared["request_raw"], **arguments
        )

    def builder_arguments(self):
        source = copy.deepcopy(self.capture["source"])
        source["commit"] = (
            "c" * 40
        )  # Inert caller assertion, not a verified Git commit.
        return {
            "nonce": "d" * 64,
            "source_record_raw": canonical_json(source),
            "controller_source_raws": {
                path: self.readonly.read(pin, max_bytes=subject._MAX_ARTIFACT)
                for path, pin in self.intent["controller_source_digests"].items()
            },
            "live_source_raws": {
                path: self.readonly.read(pin, max_bytes=subject._MAX_ARTIFACT)
                for path, pin in self.intent["live_source_digests"].items()
            },
            "static_pin_manifest_raw": canonical_json(
                self.capture["live_identity"]["static_pin_manifest"]
            ),
            "staged_profile": copy.deepcopy(self.capture["staged_profile"]),
            "baseline_capture_raw": fixture._CAPTURE.read_bytes(),
        }

    def test_offline_intent_builder_returns_complete_inputs_without_writes_or_live_claims(
        self,
    ):
        arguments = self.builder_arguments()
        before = sorted(self.cas.root.rglob("*"))
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("constructor wrote CAS")
        ):
            built = subject.build_native_plugin_update_case_intent(**arguments)
            repeated = subject.build_native_plugin_update_case_intent(**arguments)
        self.assertEqual(built, repeated)
        self.assertEqual(sorted(self.cas.root.rglob("*")), before)
        self.assertEqual(set(built), {"intent_raw", "intent_digest", "input_blobs"})
        intent = json.loads(built["intent_raw"])
        self.assertEqual(subject._digest(built["intent_raw"]), built["intent_digest"])
        self.assertEqual(intent["source_commit"], "c" * 40)
        self.assertEqual(intent["nonce"], "d" * 64)
        self.assertEqual(
            intent["source_record_digest"],
            subject._digest(arguments["source_record_raw"]),
        )
        self.assertNotIn(subject._BASELINE_DIGEST, built["input_blobs"])
        deployment = json.loads(built["input_blobs"][intent["deployment_digest"]])
        for name in (
            "runtime_commit_or_image",
            "configuration",
            "worker",
            "os_profile",
            "policy",
        ):
            self.assertEqual(
                built["input_blobs"][deployment["bindings"][name]], self.artifacts[name]
            )
        common_adapter = json.loads(
            built["input_blobs"][deployment["bindings"]["adapter"]]
        )
        self.assertEqual(
            common_adapter["identity"]["case_adapters"],
            {
                subject.ROUTE: {
                    "branch": subject.BRANCH,
                    "artifact_digest": intent["case_adapter_digest"],
                },
            },
        )
        version = json.loads(
            built["input_blobs"][deployment["bindings"]["aragorn_version"]]
        )
        self.assertEqual(
            version["identity"],
            {
                "source_commit": "c" * 40,
                "source_record_digest": subject._digest(arguments["source_record_raw"]),
            },
        )
        for pin, raw in built["input_blobs"].items():
            self.assertEqual(
                self.put(raw), pin
            )  # Test-only retention, after the pure constructor.
        inspected = subject.validate_native_plugin_update_case_intent(
            built["intent_raw"],
            expected_intent_digest=built["intent_digest"],
            evidence_cas=self.readonly,
        )
        self.assertEqual(inspected["input_blobs"], built["input_blobs"])
        self.assertEqual(inspected["intent"], intent)
        self.assertNotIn("prepared_before_activation", intent)
        self.assertFalse(set(subject._FALSE_FLAGS) & set(built))

    def test_offline_intent_builder_refuses_changed_baseline_source_inventory_and_stage(
        self,
    ):
        arguments = self.builder_arguments()
        stage = arguments["staged_profile"]
        changed_files = copy.deepcopy(stage)
        changed_files["files"][0]["digest"] = "sha256:" + "0" * 64
        changed_runtime = copy.deepcopy(stage)
        changed_runtime["required_runtime_not_included"]["entrypoint_digest"] = (
            "sha256:" + "0" * 64
        )
        static = json.loads(arguments["static_pin_manifest_raw"])
        changed_static = copy.deepcopy(static)
        changed_static["file_digests"][subject.live._WORKER_CODE] = "sha256:" + "0" * 64
        missing = dict(arguments["controller_source_raws"])
        missing.pop(subject.CONTROLLER_SOURCE_PATHS[0])
        mutations = (
            {"nonce": True},
            {"baseline_capture_raw": arguments["baseline_capture_raw"] + b"\n"},
            {"baseline_capture_raw": canonical_json(self.capture) + b"\n"},
            {"source_record_raw": b'{"commit":'},
            {"source_record_raw": canonical_json({"commit": True})},
            {"source_record_raw": arguments["source_record_raw"] + b"\n"},
            {"controller_source_raws": missing},
            {
                "controller_source_raws": {
                    **arguments["controller_source_raws"],
                    "/unexpected": b"source",
                }
            },
            {"live_source_raws": {}},
            {
                "live_source_raws": {
                    **arguments["live_source_raws"],
                    subject.LIVE_SOURCE_PATHS[0]: b"\xff",
                }
            },
            {"staged_profile": {**stage, "schema": "other"}},
            {"staged_profile": changed_files},
            {"staged_profile": changed_runtime},
            {"static_pin_manifest_raw": canonical_json(changed_static)},
            {"static_pin_manifest_raw": arguments["static_pin_manifest_raw"] + b"\n"},
        )
        with patch.object(
            CAS,
            "put_expected",
            side_effect=AssertionError("refused constructor wrote CAS"),
        ):
            for mutation in mutations:
                with (
                    self.subTest(field=next(iter(mutation))),
                    self.assertRaises(subject.NativePluginUpdateCaseError),
                ):
                    subject.build_native_plugin_update_case_intent(
                        **{**arguments, **mutation}
                    )

    def test_preparation_hashes_actual_writer_inputs_without_writes_or_secret_output(
        self,
    ):
        before = sorted(self.cas.root.rglob("*"))
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("unexpected write")
        ):
            first = self.prepare()
            second = self.prepare()
        self.assertEqual(first, second)
        self.assertEqual(before, sorted(self.cas.root.rglob("*")))
        self.assertEqual(first["request_raw"], canonical_json(first["request"]))
        self.assertEqual(first["request_digest"], subject._digest(first["request_raw"]))
        self.assertEqual(
            first["provisioning_file_digests"],
            {path: subject._digest(raw) for path, raw in self.inputs.items()},
        )
        self.assertEqual(first["request"]["nonce"], self.intent["nonce"])
        self.assertNotIn(self.inputs[subject.live._CONFIG], first["request_raw"])
        self.assertNotIn(b"OPENCLAW_GATEWAY_TOKEN", first["request_raw"])
        self.assertNotIn("activation_performed", first)

    def test_public_intent_inspection_is_readonly_exact_and_fails_closed(self):
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("inspection wrote")
        ):
            inspected = subject.validate_native_plugin_update_case_intent(
                self.intent_raw,
                expected_intent_digest=self.intent_pin,
                evidence_cas=self.readonly,
            )
        self.assertEqual(set(inspected), {"intent", "input_blobs"})
        self.assertEqual(inspected["intent"], self.intent)
        self.assertEqual(inspected["input_blobs"][self.intent_pin], self.intent_raw)
        self.assertTrue(
            all(
                subject._digest(raw) == pin
                for pin, raw in inspected["input_blobs"].items()
            )
        )
        with self.assertRaises(subject.NativePluginUpdateCaseError):
            subject.validate_native_plugin_update_case_intent(
                self.intent_raw,
                expected_intent_digest=self.intent_pin,
                evidence_cas=self.cas,
            )
        for raw in (
            b'{"schema":',
            b'{"schema":NaN}',
            b'{"nested":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}",
        ):
            with (
                self.subTest(raw_size=len(raw)),
                self.assertRaises(subject.NativePluginUpdateCaseError),
            ):
                subject.validate_native_plugin_update_case_intent(
                    raw,
                    expected_intent_digest=subject._digest(raw),
                    evidence_cas=self.readonly,
                )
        original = CAS.read

        def missing_controller(store, pin, *, max_bytes=None):
            if (
                pin
                == self.intent["controller_source_digests"][
                    subject.CONTROLLER_SOURCE_PATHS[0]
                ]
            ):
                raise CASError("inert unavailable input")
            return original(store, pin, max_bytes=max_bytes)

        with (
            patch.object(CAS, "read", missing_controller),
            self.assertRaises(subject.NativePluginUpdateCaseError),
        ):
            subject.validate_native_plugin_update_case_intent(
                self.intent_raw,
                expected_intent_digest=self.intent_pin,
                evidence_cas=self.readonly,
            )

    def test_fixed_intent_and_retained_input_custody_are_required(self):
        zero = "sha256:" + "0" * 64
        for override in ({"expected_intent_digest": zero}, {"evidence_cas": self.cas}):
            with (
                self.subTest(override=override),
                self.assertRaises(subject.NativePluginUpdateCaseError),
            ):
                self.prepare(**override)
        for change in (
            {"case_id": "ADM-02/install"},
            {"branch": "NPM_UPDATE"},
            {"nonce": True},
            {"controller_source_digests": {}},
            {"live_source_digests": {}},
            {"case_adapter_digest": zero},
            {"extra": "not permitted"},
        ):
            raw = canonical_json({**self.intent, **change})
            pin = self.put(raw)
            with (
                self.subTest(change=change),
                self.assertRaises(subject.NativePluginUpdateCaseError),
            ):
                subject.prepare_native_plugin_update_case(
                    raw,
                    expected_intent_digest=pin,
                    evidence_cas=self.readonly,
                    provisioning_inputs=self.inputs,
                )
        original = CAS.read
        for denied in (
            self.intent_pin,
            *self.intent["controller_source_digests"].values(),
        ):

            def read(store, pin, *, max_bytes=None):
                if pin == denied:
                    raise CASError("inert missing child")
                return original(store, pin, max_bytes=max_bytes)

            with (
                self.subTest(denied=denied),
                patch.object(CAS, "read", read),
                self.assertRaises(subject.NativePluginUpdateCaseError),
            ):
                self.prepare()

    def test_fresh_provisioning_cannot_mix_profile_policy_worker_or_genesis(self):
        live = subject.live
        for path, change in (
            (live._CONFIG, {"secret": "must-never-be-emitted"}),
            (live._WORKER, {"policy_version": True}),
            (live._POLICY, {"version": 2}),
            (live._GRANT, {"runtime_profile_digest": "sha256:" + "0" * 64}),
            (
                live._GRANT,
                {
                    "expires_at_unix": json.loads(self.inputs[live._GRANT])[
                        "issued_at_unix"
                    ]
                    + 301
                },
            ),
            (live._GENESIS, {"worker_uid": 0}),
            (live._OBSERVATION, {"sensor_digest": "sha256:" + "0" * 64}),
            (live._RUNTIME, {"runtime_digest": "sha256:" + "0" * 64}),
        ):
            value = {**json.loads(self.inputs[path]), **change}
            inputs = {**self.inputs, path: canonical_json(value)}
            with (
                self.subTest(path=path),
                self.assertRaises(subject.NativePluginUpdateCaseError) as caught,
            ):
                self.prepare(provisioning_inputs=inputs)
            self.assertNotIn("must-never-be-emitted", str(caught.exception))
        for inputs in (
            {**self.inputs, "/unrequested": b"{}"},
            {path: raw for path, raw in self.inputs.items() if path != live._GRANT},
            {**self.inputs, live._GRANT: self.inputs[live._GRANT] + b"\n"},
        ):
            with (
                self.subTest(keys=tuple(inputs)),
                self.assertRaises(subject.NativePluginUpdateCaseError),
            ):
                self.prepare(provisioning_inputs=inputs)

    def test_replay_recomputes_live_joins_and_keeps_common_adapter_separate(self):
        prepared = self.prepare()
        self.put(prepared["request_raw"])
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("replay wrote")
        ):
            result = self.replay(prepared)
        self.assertEqual(
            result["status"], "BOUNDED_PREPARED_CASE_READBACK_JOINS_VERIFIED"
        )
        self.assertEqual(
            result["bindings"]["deployment_digest"], self.intent["deployment_digest"]
        )
        self.assertNotEqual(
            self.intent["deployment_digest"],
            self.retained["collection"]["context"]["deployment_identity_digest"],
        )
        self.assertTrue(all(result[name] is False for name in subject._FALSE_FLAGS))
        for change in (
            {"nonce": "b" * 64},
            {"prepared_before_activation": 1},
            {
                "provisioning_file_digests": {
                    **prepared["provisioning_file_digests"],
                    subject.live._GRANT: "sha256:" + "0" * 64,
                }
            },
        ):
            raw = canonical_json({**prepared["request"], **change})
            changed = {**prepared, "request_raw": raw, "request_digest": self.put(raw)}
            with (
                self.subTest(change=change),
                self.assertRaises(subject.NativePluginUpdateCaseError),
            ):
                self.replay(changed)

    def test_replay_rejects_forged_verdict_missing_request_and_end_custody_loss(self):
        prepared = self.prepare()
        with self.assertRaises(subject.NativePluginUpdateCaseError):
            self.replay(prepared)
        self.put(prepared["request_raw"])
        for override in (
            {"expected_request_digest": "sha256:" + "0" * 64},
            {"expected_intent_digest": "sha256:" + "0" * 64},
            {"expected_collection_digest": "sha256:" + "0" * 64},
            {"evidence_cas": self.cas},
        ):
            with (
                self.subTest(override=override),
                self.assertRaises(subject.NativePluginUpdateCaseError),
            ):
                self.replay(prepared, **override)
        forged = copy.deepcopy(self.retained["collection"])
        forged["phase3_eligible"] = True
        pin = self.put(canonical_json(forged))
        with self.assertRaises(subject.NativePluginUpdateCaseError):
            self.replay(prepared, expected_collection_digest=pin)
        original, reads = CAS.read, {}
        target = self.intent["controller_source_digests"][
            subject.CONTROLLER_SOURCE_PATHS[0]
        ]

        def changed_at_end(store, pin, *, max_bytes=None):
            reads[pin] = reads.get(pin, 0) + 1
            if pin == target and reads[pin] > 1:
                raise CASError("inert end custody loss")
            return original(store, pin, max_bytes=max_bytes)

        with (
            patch.object(CAS, "read", changed_at_end),
            self.assertRaises(subject.NativePluginUpdateCaseError),
        ):
            self.replay(prepared)

    def test_nested_child_loss_after_live_replay_is_rejected_without_second_replay(
        self,
    ):
        prepared = self.prepare()
        self.put(prepared["request_raw"])
        target = self.retained["collection"]["context"]["capture_digest"]
        original_read = CAS.read
        original_replay = collection.replay_native_plugin_update_live_collection
        armed = False
        child_reads = 0

        def replay_once(**arguments):
            nonlocal armed
            result = original_replay(**arguments)
            armed = True
            return result

        def lost_child(store, pin, *, max_bytes=None):
            nonlocal child_reads
            if armed and pin == target:
                child_reads += 1
                # First post-replay child read supplies the closure bytes; the
                # final case readback must still notice their later removal.
                if child_reads > 1:
                    raise CASError("inert nested capture removed after replay")
            return original_read(store, pin, max_bytes=max_bytes)

        with (
            patch.object(
                collection,
                "replay_native_plugin_update_live_collection",
                side_effect=replay_once,
            ) as replay,
            patch.object(CAS, "read", lost_child),
            self.assertRaises(subject.NativePluginUpdateCaseError),
        ):
            self.replay(prepared)
        replay.assert_called_once()
        self.assertEqual(child_reads, 2)


if __name__ == "__main__":
    unittest.main()
