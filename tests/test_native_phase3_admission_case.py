"""Inert successor expectations; these tests are never admission/live evidence."""

from copy import deepcopy
from functools import lru_cache
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aragorn import native_phase3_admission_case as subject
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_json
from scripts import stage_runtime_native_admission_profile as stager

_ROOT = Path(__file__).resolve().parents[1]
_BASELINE = (
    _ROOT
    / "benchmark/evidence/phase3-native-plugin-update-systemd-development-v2-2026-10-01.json"
)
_CONFIG = (
    _ROOT
    / "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json"
)


@lru_cache(maxsize=1)
def _fixture_data():
    # Real inert staging, once per process; no service, VM or live fixture.
    with tempfile.TemporaryDirectory() as temporary:
        stage = stager.stage_runtime_native_admission_profile(
            Path(temporary).resolve() / "stage"
        )
    baseline_raw = _BASELINE.read_bytes()
    return stage, baseline_raw, json.loads(baseline_raw)


def builder_arguments():
    """Return independent inert data for helper/host tests, never run tests."""
    stage, baseline_raw, baseline = _fixture_data()
    live = subject.old.live
    files = {row["path"]: row for row in stage["files"]}
    static = {
        "schema": "aragorn/native-plugin-update-identity-static-pins/v1",
        "file_digests": {
            **{path: files[path]["digest"] for path in live._PROFILE_PATHS},
            live._ENTRY: stage["required_runtime_not_included"]["entrypoint_digest"],
            live._PYTHON: baseline["observation"]["setup"]["runtime_profile"][
                "executable_digest"
            ],
            live._NODE: subject._NODE_PIN,
        },
    }
    return {
        "case_id": subject.DIRECT_WRITE_CASE,
        "nonce": "a" * 64,
        "source_record_raw": canonical_json({"commit": "c" * 40, "test_only": True}),
        "controller_source_raws": {
            path: ("inert controller " + path).encode()
            for path in subject.CONTROLLER_SOURCE_PATHS
        },
        "live_source_raws": {
            path: ("inert reader " + path).encode()
            for path in subject.LIVE_SOURCE_PATHS
        },
        "case_source_raws": {
            path: ("inert leaf " + path).encode() for path in subject.CASE_SOURCE_PATHS
        },
        "static_pin_manifest_raw": canonical_json(static),
        "staged_profile": deepcopy(stage),
        "baseline_capture_raw": baseline_raw,
    }


def provisioning_inputs():
    """Return seven inert canonical writer inputs without altering shared data."""
    _, _, baseline = _fixture_data()
    live = subject.old.live
    setup = baseline["observation"]["setup"]
    return {
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


class NativeAdmissionCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stage, cls.baseline_raw, cls.baseline = _fixture_data()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(Path(self.temporary.name).resolve() / "cas")
        self.readonly = CAS(self.cas.root, read_only=True)
        self.arguments = builder_arguments()
        self.inputs = provisioning_inputs()

    def build(self, **changes):
        return subject.build_native_admission_case_intent(**(self.arguments | changes))

    def retain(self, built):
        for pin, raw in built["input_blobs"].items():
            self.assertEqual(
                self.cas.put_expected(
                    BytesIO(raw), expected_digest=pin, max_bytes=len(raw)
                ),
                pin,
            )

    def inspect(self, built):
        return subject.validate_native_admission_case_intent(
            built["intent_raw"],
            expected_intent_digest=built["intent_digest"],
            evidence_cas=self.readonly,
        )

    def prepare(self, built, **changes):
        return subject.prepare_native_admission_case(
            built["intent_raw"],
            **(
                {
                    "expected_intent_digest": built["intent_digest"],
                    "evidence_cas": self.readonly,
                    "provisioning_inputs": self.inputs,
                }
                | changes
            ),
        )

    def test_both_cases_share_one_deployment_and_complete_input_closure(self):
        before = deepcopy(self.arguments)
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("builder wrote CAS")
        ):
            first = self.build()
            second = self.build(case_id=subject.UPDATE_CASE, nonce="b" * 64)
            self.assertEqual(first, self.build())
        self.assertEqual(self.arguments, before)
        self.assertEqual(set(first), {"intent_raw", "intent_digest", "input_blobs"})
        intents = [json.loads(value["intent_raw"]) for value in (first, second)]
        self.assertEqual(
            intents[0]["deployment_digest"], intents[1]["deployment_digest"]
        )
        self.assertNotEqual(
            intents[0]["case_adapter_digest"], intents[1]["case_adapter_digest"]
        )
        self.assertNotEqual(first["intent_digest"], second["intent_digest"])
        deployment = json.loads(first["input_blobs"][intents[0]["deployment_digest"]])
        adapter = json.loads(first["input_blobs"][deployment["bindings"]["adapter"]])
        self.assertEqual(
            set(adapter["identity"]["case_adapters"]), set(subject.CASE_BRANCHES)
        )
        for intent in intents:
            selected = adapter["identity"]["case_adapters"][intent["case_id"]]
            self.assertEqual(
                selected,
                {
                    "branch": intent["branch"],
                    "artifact_digest": intent["case_adapter_digest"],
                },
            )
        self.assertIn(subject.old._BASELINE_DIGEST, first["input_blobs"])
        self.assertEqual(
            first["input_blobs"][intents[0]["staged_profile_digest"]],
            canonical_json(self.stage),
        )
        for built, intent in zip((first, second), intents):
            self.retain(built)
            with patch.object(
                CAS, "put_expected", side_effect=AssertionError("validator wrote CAS")
            ):
                inspected = self.inspect(built)
            self.assertEqual(
                inspected, {"intent": intent, "input_blobs": built["input_blobs"]}
            )

    def test_path_cases_share_target_but_bind_distinct_case_and_shared_readers(self):
        all_built = [self.build(case_id=selected) for selected in subject.CASE_BRANCHES]
        intents = [json.loads(built["intent_raw"]) for built in all_built]
        self.assertEqual(len({intent["deployment_digest"] for intent in intents}), 1)
        self.assertEqual(len({intent["case_adapter_digest"] for intent in intents}), 4)
        for built, intent in zip(all_built, intents, strict=True):
            with self.subTest(case_id=intent["case_id"]):
                self.assertLessEqual(len(built["input_blobs"]), 32)
                self.retain(built)
                self.assertEqual(
                    self.prepare(built)["request"]["case_id"], intent["case_id"]
                )
                adapter = json.loads(
                    built["input_blobs"][intent["case_adapter_digest"]]
                )
                if intent["case_id"] in subject.MUTATION_CASE_BRANCHES:
                    self.assertEqual(
                        set(adapter["identity"]["probe_sources"]),
                        set(subject.CASE_SOURCE_PATHS),
                    )
                    self.assertEqual(
                        adapter["identity"]["branch"],
                        subject.MUTATION_CASE_BRANCHES[intent["case_id"]],
                    )
                elif intent["case_id"] == subject.DIRECT_WRITE_CASE:
                    self.assertEqual(
                        set(adapter["identity"]["probe_sources"]),
                        set(subject.DIRECT_SOURCE_PATHS),
                    )

    def test_exact_two_successor_outputs_and_unchanged_historical_expectations(self):
        built = self.build()
        intent = json.loads(built["intent_raw"])
        baseline, original = subject._baseline(self.baseline_raw)
        old_files = {row["path"]: row for row in baseline["staged_profile"]["files"]}
        files = {row["path"]: row for row in self.stage["files"]}
        self.assertEqual(
            {path for path in files if files[path] != old_files[path]},
            set(subject.STAGED_REPLACEMENTS),
        )
        self.assertEqual(
            (
                len(canonical_json(self.stage)),
                subject._digest(canonical_json(self.stage)),
            ),
            subject.STAGED_PROFILE_PIN,
        )
        deployment = json.loads(built["input_blobs"][intent["deployment_digest"]])
        for name in ("runtime_commit_or_image", "configuration", "worker", "policy"):
            self.assertEqual(
                built["input_blobs"][deployment["bindings"][name]], original[name]
            )
        self.assertNotEqual(
            built["input_blobs"][deployment["bindings"]["os_profile"]],
            original["os_profile"],
        )
        self.retain(built)
        with self.assertRaises(subject.old.NativePluginUpdateCaseError):
            subject.old.validate_native_plugin_update_case_intent(
                built["intent_raw"],
                expected_intent_digest=built["intent_digest"],
                evidence_cas=self.readonly,
            )

    def test_builder_refuses_profile_static_baseline_and_source_substitution(self):
        extra_file = deepcopy(self.stage)
        extra_file["files"][0]["digest"] = "sha256:" + "0" * 64
        old_gateway = json.loads(self.arguments["static_pin_manifest_raw"])
        gateway = "/usr/lib/systemd/system/aragorn-agent-gateway.service"
        old_gateway["file_digests"][gateway] = next(
            row["digest"]
            for row in self.baseline["staged_profile"]["files"]
            if row["path"] == gateway
        )
        changes = [
            {"case_id": "ADM-02/arbitrary"},
            {"case_id": True},
            {"nonce": True},
            {"baseline_capture_raw": self.baseline_raw + b"\n"},
            {"staged_profile": self.baseline["staged_profile"]},
            {"staged_profile": extra_file},
            {"staged_profile": self.stage | {"directories": []}},
            {"staged_profile": self.stage | {"source_inputs": []}},
            {"static_pin_manifest_raw": canonical_json(old_gateway)},
            {"source_record_raw": canonical_json({"commit": True})},
        ]
        for name in ("controller_source_raws", "live_source_raws", "case_source_raws"):
            changes.extend(
                ({name: {}}, {name: self.arguments[name] | {"unexpected": b"x"}})
            )
            altered = dict(self.arguments[name])
            altered[next(iter(altered))] = b"\xff"
            changes.append({name: altered})
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("refused builder wrote")
        ):
            for change in changes:
                with (
                    self.subTest(field=next(iter(change))),
                    self.assertRaises(subject.NativeAdmissionCaseError),
                ):
                    self.build(**change)

    def test_prepare_reuses_exact_writer_joins_without_writes_or_raw_secret_output(
        self,
    ):
        built = self.build()
        self.retain(built)
        original = deepcopy(self.inputs)
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("preparer wrote")
        ):
            prepared = self.prepare(built)
            self.assertEqual(prepared, self.prepare(built))
        self.assertEqual(self.inputs, original)
        self.assertEqual(prepared["request_raw"], canonical_json(prepared["request"]))
        self.assertEqual(
            prepared["request_digest"], subject._digest(prepared["request_raw"])
        )
        self.assertEqual(prepared["request"]["schema"], subject.REQUEST_SCHEMA)
        self.assertEqual(prepared["request"]["case_id"], subject.DIRECT_WRITE_CASE)
        self.assertEqual(
            prepared["provisioning_file_digests"],
            {path: subject._digest(raw) for path, raw in self.inputs.items()},
        )
        self.assertTrue(all(prepared[name] is False for name in subject._FALSE_FLAGS))
        self.assertNotIn(self.inputs[subject.old.live._CONFIG], prepared["request_raw"])
        self.assertNotIn(b"OPENCLAW_GATEWAY_TOKEN", prepared["request_raw"])
        update = self.build(case_id=subject.UPDATE_CASE)
        self.retain(update)
        self.assertEqual(
            self.prepare(update)["deployment_digest"], prepared["deployment_digest"]
        )

    def test_changed_writer_or_missing_input_refuses_without_repinning(self):
        built = self.build()
        self.retain(built)
        for path in subject.PROVISIONING_PATHS:
            changed = dict(self.inputs)
            changed[path] += b"\n"
            with (
                self.subTest(path=path),
                self.assertRaises(subject.NativeAdmissionCaseError),
            ):
                subject.prepare_native_admission_case(
                    built["intent_raw"],
                    expected_intent_digest=built["intent_digest"],
                    evidence_cas=self.readonly,
                    provisioning_inputs=changed,
                )
        with self.assertRaises(subject.NativeAdmissionCaseError):
            subject.prepare_native_admission_case(
                built["intent_raw"],
                expected_intent_digest=built["intent_digest"],
                evidence_cas=self.readonly,
                provisioning_inputs={},
            )

    def test_inspection_rejects_wrong_adapter_writable_cas_and_late_child_loss(self):
        built = self.build()
        self.retain(built)
        with self.assertRaises(subject.NativeAdmissionCaseError):
            subject.validate_native_admission_case_intent(
                built["intent_raw"],
                expected_intent_digest=built["intent_digest"],
                evidence_cas=self.cas,
            )
        intent = json.loads(built["intent_raw"])
        update = self.build(case_id=subject.UPDATE_CASE)
        intent["case_adapter_digest"] = json.loads(update["intent_raw"])[
            "case_adapter_digest"
        ]
        raw = canonical_json(intent)
        pin = self.cas.put(BytesIO(raw), max_bytes=len(raw))
        with self.assertRaises(subject.NativeAdmissionCaseError):
            subject.validate_native_admission_case_intent(
                raw, expected_intent_digest=pin, evidence_cas=self.readonly
            )
        original_read = CAS.read
        reads = 0

        def lose_baseline(store, digest, *, max_bytes):
            nonlocal reads
            if digest == subject.old._BASELINE_DIGEST:
                reads += 1
                if reads > 1:
                    raise CASError("inert late input loss")
            return original_read(store, digest, max_bytes=max_bytes)

        with (
            patch.object(CAS, "read", lose_baseline),
            self.assertRaises(subject.NativeAdmissionCaseError),
        ):
            self.inspect(built)


if __name__ == "__main__":
    unittest.main()
