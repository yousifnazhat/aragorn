"""Inert ingress74 preparation migration, not live or acceptance evidence.

The shared fixture constructs the actual reviewed stage and explicit test-only
writer/source/measurement data. No historical test method or workload is called,
and no successor worker/report pin is replaced to manufacture an acceptance.
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aragorn import native_phase3_common_preparation as subject
from aragorn.cas import CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import stage_runtime_phase3_common_profile as frozen_stage
from tests import test_native_phase3_common_preparation as data


WORKER_PIN = (
    49327,
    "sha256:1ba2bc446b0561d992ef800d324269ab6a428b2cb3449109fe771029317f850a",
)
HELPER_PIN = (
    20731,
    "sha256:aba3d6b705f9b147fdf89f083ec6edcde7d3165ba1a8008cf4bcdcaee88fe17e",
)
FROZEN_STAGE_PIN = (
    50029,
    "sha256:4c5e4f131f493d7de2a32cac5764fa7bf4ffb83fe46c4a55d600013a0ab9b65e",
)


@lru_cache(maxsize=1)
def _old_stage():
    # Actual frozen data materialization only; never a historical TestCase run.
    with tempfile.TemporaryDirectory() as temporary:
        return frozen_stage.stage_runtime_phase3_common_profile(
            Path(temporary).resolve() / "frozen-common73"
        )


class NativeCommonIngressMigrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = data.NativeCommonPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.live = subject.old.live
        self.helper = subject.common_identity.WORKER_INGRESS_SOURCES[
            "runtime_worker_ingress_measurement.py"
        ]
        self.activator = subject.common_identity.ACTIVATOR

    def inspect(self, prepared, *, raw=None, inputs=None):
        selected = prepared["preparation_raw"] if raw is None else raw
        return subject._inspect(
            selected,
            subject.old._digest(selected),
            self.fixture.reader,
            self.fixture.inputs if inputs is None else inputs,
        )

    def test_actual_ingress74_worker_helper_and_activator_close_static20(self):
        prepared = self.fixture.build()
        stage = self.fixture.stage
        stage_raw = canonical_json(stage)
        self.assertEqual(
            (len(stage_raw), subject.old._digest(stage_raw)), subject.STAGED_PROFILE_PIN
        )
        self.assertEqual(
            stage["schema"], "aragorn/runtime-phase3-ingress-staged-profile/v1"
        )
        self.assertEqual(
            tuple(
                len(stage[name])
                for name in (
                    "files",
                    "source_inputs",
                    "new_dependencies",
                    "directories",
                )
            ),
            (74, 96, 30, 16),
        )
        rows = {row["path"]: row for row in stage["files"]}
        self.assertEqual(len(rows), 74)
        self.assertEqual(
            (
                rows[self.live._WORKER_CODE]["bytes"],
                rows[self.live._WORKER_CODE]["digest"],
            ),
            WORKER_PIN,
        )
        self.assertEqual(
            (rows[self.helper]["bytes"], rows[self.helper]["digest"]), HELPER_PIN
        )
        self.assertEqual(
            rows[self.helper]["source_name"],
            "src/aragorn/runtime_worker_ingress_measurement.py",
        )
        self.assertEqual(rows[self.helper]["mode"], "0644")
        self.assertEqual(rows[self.activator]["mode"], "0755")
        self.assertEqual(
            self.fixture.static["schema"], "aragorn/native-common-static-pins/v2"
        )
        self.assertEqual(len(subject.STATIC_PATHS), 20)
        self.assertEqual(
            set(self.fixture.static["file_digests"]), set(subject.STATIC_PATHS)
        )
        for path in (self.live._WORKER_CODE, self.helper, self.activator):
            self.assertEqual(
                self.fixture.static["file_digests"][path], rows[path]["digest"]
            )
        worker = json.loads(prepared["artifacts"]["worker"])["identity"]
        self.assertEqual(
            worker,
            {
                "bytes": WORKER_PIN[0],
                "digest": WORKER_PIN[1],
                "binding": json.loads(self.fixture.inputs[self.live._WORKER]),
            },
        )
        self.assertEqual(
            prepared["preparation"]["schema"],
            "aragorn/native-common-deployment-preparation/v2",
        )
        self.assertEqual(
            prepared["preparation"]["decision"], dict.fromkeys(subject._FALSE, False)
        )
        self.assertTrue(
            all(flag is False for flag in prepared["preparation"]["decision"].values())
        )
        self.assertEqual(len(prepared["provisioning_file_digests"]), 7)
        self.assertEqual(
            prepared["provisioning_file_digests"],
            {
                path: subject.old._digest(raw)
                for path, raw in self.fixture.inputs.items()
            },
        )

    def test_frozen_common73_report_is_unchanged_but_no_longer_current(self):
        stage = _old_stage()
        raw = canonical_json(stage)
        self.assertEqual((len(raw), subject.old._digest(raw)), FROZEN_STAGE_PIN)
        self.assertEqual(len(stage["files"]), 73)
        self.assertNotEqual(FROZEN_STAGE_PIN, subject.STAGED_PROFILE_PIN)
        old_rows = {row["path"]: row for row in stage["files"]}
        self.assertNotIn(self.helper, old_rows)
        self.assertEqual(
            (
                old_rows[self.live._WORKER_CODE]["bytes"],
                old_rows[self.live._WORKER_CODE]["digest"],
            ),
            (subject.old._WORKER_BYTES, subject.old._WORKER_PIN),
        )
        with self.assertRaisesRegex(
            subject.NativeCommonPreparationError, "reviewed common stage bytes changed"
        ):
            self.fixture.build(staged_profile_raw=raw)

    def test_missing_changed_and_v1_static_pins_refuse(self):
        for path in (self.live._WORKER_CODE, self.helper, self.activator):
            for mode in ("missing", "changed"):
                with self.subTest(path=path, mode=mode):
                    value = deepcopy(self.fixture.static)
                    if mode == "missing":
                        value["file_digests"].pop(path)
                    else:
                        value["file_digests"][path] = data.PIN
                    with self.assertRaises(subject.NativeCommonPreparationError):
                        self.fixture.build(
                            static_pin_manifest_raw=canonical_json(value)
                        )
        value = deepcopy(self.fixture.static)
        value["schema"] = "aragorn/native-common-static-pins/v1"
        with self.assertRaises(subject.NativeCommonPreparationError):
            self.fixture.build(static_pin_manifest_raw=canonical_json(value))

    def test_coherently_changed_stage_and_static_cannot_bypass_full_report_pin(self):
        for path in (self.live._WORKER_CODE, self.helper, self.activator):
            with self.subTest(path=path):
                stage = deepcopy(self.fixture.stage)
                static = deepcopy(self.fixture.static)
                row = next(row for row in stage["files"] if row["path"] == path)
                row["digest"] = static["file_digests"][path] = data.PIN
                with self.assertRaisesRegex(
                    subject.NativeCommonPreparationError,
                    "reviewed common stage bytes changed",
                ):
                    self.fixture.build(
                        staged_profile_raw=canonical_json(stage),
                        static_pin_manifest_raw=canonical_json(static),
                    )

    def test_retained_v1_preparation_and_rehashed_static_downgrade_refuse_reconstruction(
        self,
    ):
        prepared = self.fixture.build()
        self.fixture.retain(prepared["input_blobs"])
        self.assertEqual(self.inspect(prepared), prepared)
        value = deepcopy(prepared["preparation"])
        value["schema"] = "aragorn/native-common-deployment-preparation/v1"
        raw = canonical_json(value)
        self.fixture.retain({subject.old._digest(raw): raw})
        with self.assertRaises(subject.NativeCommonPreparationError):
            self.inspect(prepared, raw=raw)
        for mode in ("v1", "missing-helper", "changed-activator"):
            with self.subTest(mode=mode):
                static = deepcopy(self.fixture.static)
                if mode == "v1":
                    static["schema"] = "aragorn/native-common-static-pins/v1"
                elif mode == "missing-helper":
                    static["file_digests"].pop(self.helper)
                else:
                    static["file_digests"][self.activator] = data.PIN
                static_raw = canonical_json(static)
                value = deepcopy(prepared["preparation"])
                value["static_pin_manifest_digest"] = subject.old._digest(static_raw)
                raw = canonical_json(value)
                self.fixture.retain(
                    {
                        subject.old._digest(raw): raw,
                        subject.old._digest(static_raw): static_raw,
                    }
                )
                with self.assertRaises(subject.NativeCommonPreparationError):
                    self.inspect(prepared, raw=raw)

    def test_reconstruction_requires_new_static_stage_and_worker_artifact_custody(self):
        prepared = self.fixture.build()
        self.fixture.retain(prepared["input_blobs"])
        pins = (
            prepared["preparation"]["staged_profile_digest"],
            prepared["preparation"]["static_pin_manifest_digest"],
            subject.old._digest(prepared["artifacts"]["worker"]),
        )
        original_read = self.fixture.reader.read
        for selected in pins:
            with self.subTest(selected=selected):

                def read(pin, *, max_bytes):
                    if pin == selected:
                        raise CASError("inert ingress migration retained input loss")
                    return original_read(pin, max_bytes=max_bytes)

                with patch.object(self.fixture.reader, "read", side_effect=read):
                    with self.assertRaises(CASError):
                        self.inspect(prepared)

    def test_seven_writer_raw_inputs_remain_exact_during_reconstruction(self):
        prepared = self.fixture.build()
        self.fixture.retain(prepared["input_blobs"])
        self.assertEqual(set(self.fixture.inputs), set(subject.old.PROVISIONING_PATHS))
        for path in subject.old.PROVISIONING_PATHS:
            with self.subTest(path=path):
                inputs = dict(self.fixture.inputs)
                inputs[path] += b"\n"
                with self.assertRaises(subject.NativeCommonPreparationError):
                    self.inspect(prepared, inputs=inputs)

    def test_generated_v2_request_joins_28_files_and_unchanged_seven_broker_sources(
        self,
    ):
        prepared = self.fixture.build()
        self.fixture.retain(prepared["input_blobs"])
        measured = self.fixture.measurement(prepared)
        result = subject.prepare_native_common_request(
            **self.fixture.request_arguments(prepared, measured)
        )
        request = result["request"]
        self.assertEqual(
            request["schema"], "aragorn/native-common-measured-case-request/v2"
        )
        self.assertEqual(canonical_json(request), result["request_raw"])
        self.assertEqual(canonical_digest(request), result["request_digest"])
        expected = result["expected_file_digests"]
        self.assertEqual(len(expected), 28)
        self.assertEqual(set(expected), set(subject.common_identity.FILE_PATHS))
        self.assertEqual(
            {path: expected[path] for path in subject.STATIC_PATHS},
            self.fixture.static["file_digests"],
        )
        for path in (self.live._WORKER_CODE, self.helper, self.activator):
            self.assertEqual(expected[path], self.fixture.static["file_digests"][path])
        writers = prepared["provisioning_file_digests"]
        self.assertEqual({path: expected[path] for path in writers}, writers)
        self.assertEqual(
            result["provisioning_file_digests"],
            writers
            | {subject.common_identity.MEASUREMENT_BINDING: measured["binding_digest"]},
        )
        self.assertEqual(
            expected[subject.common_identity.MEASUREMENT_BINDING],
            measured["binding_digest"],
        )
        self.assertEqual(len(subject.common_identity.MEASUREMENT_SOURCES), 7)
        broker_pins = self.fixture.stage["binding_source_pins"]
        self.assertEqual(broker_pins, _old_stage()["binding_source_pins"])
        binding = json.loads(
            self.fixture.reader.read(measured["binding_digest"], max_bytes=32768)
        )
        self.assertEqual(binding["source_pins"], broker_pins)
        self.assertEqual(
            {
                name: expected[path]
                for name, path in subject.common_identity.MEASUREMENT_SOURCES.items()
            },
            broker_pins,
        )
        self.assertEqual(request["preparation_digest"], prepared["preparation_digest"])
        self.assertEqual(
            request["staged_profile_digest"],
            prepared["preparation"]["staged_profile_digest"],
        )
        self.assertTrue(
            all(request["decision"][key] is False for key in subject._FALSE)
        )
        self.assertIs(request["decision"]["supplied_payload_bytes_verified"], True)
        for pin, raw in result["input_blobs"].items():
            self.assertEqual(
                self.fixture.reader.read(pin, max_bytes=subject.old._MAX_ARTIFACT), raw
            )


if __name__ == "__main__":
    unittest.main()
