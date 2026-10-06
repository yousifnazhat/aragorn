"""New pure common handoff checks; inert data is never live or acceptance evidence."""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aragorn import native_phase3_common_preparation as subject
from aragorn import phase3_quantitative_metrics as metrics
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import stage_runtime_phase3_ingress_profile as stager
from tests import test_native_phase3_admission_case as admission_data
from tests import test_runtime_broker_measurement_plan as measurement_data


CONTAINER = "b" * 64
BOOT = "00000000-0000-0000-0000-000000000001"
PAYLOAD = b"Aragorn P3.7b distinct worker create\n"
PIN = "sha256:" + "f" * 64


@lru_cache(maxsize=1)
def _stage_data():
    # Data construction only: no prior test method, runtime or clock is invoked.
    with tempfile.TemporaryDirectory() as temporary:
        stage = stager.stage_runtime_phase3_ingress_profile(
            Path(temporary).resolve() / "common"
        )
    raw = admission_data._BASELINE.read_bytes()
    return stage, raw, json.loads(raw)


def _provisioning(*, inode=654, container=CONTAINER):
    live = subject.old.live
    documents = {
        path: json.loads(raw)
        for path, raw in admission_data.provisioning_inputs().items()
    }
    descriptor = {
        "schema": "aragorn/runtime-protected-path/v1",
        "root_device": 321,
        "root_inode": inode,
        "target_name": "runtime-worker-qualified.txt",
    }
    profile = documents[live._OBSERVATION]["runtime_profile"]
    profile["cgroup"] = (
        f"/docker/{container}/system.slice/aragorn-runtime-action-worker.service"
    )
    profile_pin = canonical_digest(profile)
    documents[live._RUNTIME]["runtime_profile_digest"] = profile_pin
    grant = documents[live._GRANT]
    grant.update(
        runtime_profile_digest=profile_pin,
        grant_id="d" * 64,
        issued_at_unix=1,
        expires_at_unix=241,
    )
    policy = documents[live._POLICY]
    policy["allow"][0].update(
        path_digest=canonical_digest(descriptor),
        payload_digest=subject.old._digest(PAYLOAD),
    )
    policy_pin = canonical_digest(policy)
    for path in (live._WORKER, live._GRANT, live._GENESIS):
        documents[path]["policy_digest"] = policy_pin
    return {
        path: canonical_json(value) for path, value in documents.items()
    }, descriptor


class NativeCommonPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cas = CAS(self.root / "retained")
        self.reader = CAS(self.cas.root, read_only=True)
        stage, self.baseline_raw, self.baseline = _stage_data()
        self.stage = deepcopy(stage)
        self.inputs, self.descriptor = _provisioning()
        live = subject.old.live
        files = {row["path"]: row for row in stage["files"]}
        special = {
            live._ENTRY: stage["required_runtime_not_included"]["entrypoint_digest"],
            live._PYTHON: self.baseline["observation"]["setup"]["runtime_profile"][
                "executable_digest"
            ],
            live._NODE: subject.admission._NODE_PIN,
        }
        self.static = {
            "schema": subject.STATIC_SCHEMA,
            "file_digests": {
                path: special[path] if path in special else files[path]["digest"]
                for path in subject.STATIC_PATHS
            },
        }
        self.arguments = {
            "case_id": subject.admission.DIRECT_WRITE_CASE,
            "nonce": "a" * 64,
            "container_id": CONTAINER,
            "source_record_raw": canonical_json(
                {"commit": "c" * 40, "test_only": True}
            ),
            "implementation_source_raws": {
                path: ("inert common source " + path).encode()
                for path in subject.IMPLEMENTATION_SOURCE_PATHS
            },
            "static_pin_manifest_raw": canonical_json(self.static),
            "staged_profile_raw": canonical_json(self.stage),
            "baseline_capture_raw": self.baseline_raw,
            "provisioning_inputs": self.inputs,
        }

    def build(self, **updates):
        return subject.prepare_native_common_deployment(**(self.arguments | updates))

    def retain(self, blobs):
        for pin, raw in blobs.items():
            self.assertEqual(
                self.cas.put_expected(
                    BytesIO(raw), expected_digest=pin, max_bytes=len(raw)
                ),
                pin,
            )

    def measurement(self, preparation, *, change=None):
        # Compose only the old data constructor, never inherit/run its tests.
        fixture = measurement_data.BrokerMeasurementPlanTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        source = CAS(fixture.arguments["source_cas"].root)

        def put(value):
            raw = value if type(value) is bytes else canonical_json(value)
            return source.put(BytesIO(raw), max_bytes=1024 * 1024)

        for raw in preparation["input_blobs"].values():
            put(raw)
        deployment = deepcopy(preparation["deployment"])
        if change == "deployment":
            deployment["bindings"]["aragorn_version"] = put(
                {"inert_other_source": True}
            )
        deployment_pin = put(deployment)
        old_schedule = json.loads(
            source.read(fixture.arguments["expected_schedule_digest"])
        )
        attempts, overhead = (
            old_schedule["attempt_schedule"],
            old_schedule["overhead_schedule"],
        )
        pair_bindings = deepcopy(overhead["pair_bindings"])
        for item in pair_bindings.values():
            item["host_profile_digest"] = deployment["bindings"]["os_profile"]
        schedule = metrics.build_phase3_measurement_schedule(
            expected_attempt_ids=attempts["attempt_ids"],
            expected_attempt_families=attempts["attempt_families"],
            expected_unattributed_attempt_id=attempts[
                "unattributed_negative_control_attempt_id"
            ],
            expected_overhead_pair_bindings=pair_bindings,
            **{
                "expected_" + key: deployment_pin
                if key == "runtime_identity_digest"
                else value
                for key, value in old_schedule["bindings"].items()
            },
        )
        schedule_pin = put(schedule)
        commitment = json.loads(
            source.read(fixture.arguments["expected_commitment_digest"])
        )
        commitment.update(deployment=deployment, schedule_digest=schedule_pin)
        commitment_pin = put(commitment)
        grant = json.loads(self.inputs[subject.old.live._GRANT])
        descriptor = deepcopy(self.descriptor)
        sources = dict(self.stage["binding_source_pins"])
        payload_pin = subject.old._digest(PAYLOAD)
        if change == "grant":
            grant["grant_id"] = "e" * 64
        elif change == "path":
            descriptor["root_inode"] += 1
        elif change == "payload":
            payload_pin = subject.old._digest(b"other inert payload")
        elif change == "source":
            sources["runtime_action_broker.py"] = PIN
        arguments = {
            **fixture.arguments,
            "source_cas": CAS(source.root, read_only=True),
            "expected_deployment_digest": deployment_pin,
            "expected_schedule_digest": schedule_pin,
            "expected_commitment_digest": commitment_pin,
            "expected_grant_digest": put(grant),
            "expected_path_digest": put(descriptor),
            "expected_payload_digest": payload_pin,
            "expected_broker_source_pins": sources,
            "scheduled_request": {
                **fixture.arguments["scheduled_request"],
                "collection_digest": commitment_pin,
                "deployment_digest": deployment_pin,
            },
        }
        prepared = measurement_data.subject.prepare_broker_decision_measurement_binding(
            **arguments
        )
        for row in prepared["input_blobs"]:
            self.retain({row["digest"]: arguments["target_cas"].read(row["digest"])})
        self.retain({canonical_digest(prepared): canonical_json(prepared)})
        return prepared

    def request_arguments(self, preparation, measured):
        return {
            "preparation_raw": preparation["preparation_raw"],
            "expected_preparation_digest": preparation["preparation_digest"],
            "evidence_cas": self.reader,
            "provisioning_inputs": self.inputs,
            "measurement_prepared_raw": canonical_json(measured),
            "expected_measurement_prepared_digest": canonical_digest(measured),
            "expected_binding_digest": measured["binding_digest"],
            "expected_boot_id": BOOT,
            "protected_descriptor_raw": canonical_json(self.descriptor),
            "payload_raw": PAYLOAD,
        }

    def test_actual_writer_artifacts_are_pure_and_not_historical_policy_expectations(
        self,
    ):
        before = deepcopy(self.arguments)
        with (
            patch.object(
                CAS, "put", side_effect=AssertionError("pure preparation wrote CAS")
            ),
            patch.object(
                CAS,
                "put_expected",
                side_effect=AssertionError("pure preparation wrote CAS"),
            ),
            patch("time.time", side_effect=AssertionError("no grant liveness claim")),
            patch(
                "time.clock_gettime_ns", side_effect=AssertionError("no clock sampled")
            ),
        ):
            built = self.build()
            self.assertEqual(built, self.build())
        self.assertEqual(self.arguments, before)
        self.assertEqual(
            canonical_digest(built["preparation"]), built["preparation_digest"]
        )
        self.assertEqual(canonical_json(built["preparation"]), built["preparation_raw"])
        self.assertEqual(
            built["input_blobs"][built["preparation_digest"]], built["preparation_raw"]
        )
        self.assertEqual(
            built["provisioning_file_digests"],
            {path: subject.old._digest(raw) for path, raw in self.inputs.items()},
        )
        for name, raw in built["artifacts"].items():
            self.assertEqual(
                built["deployment"]["bindings"][name], subject.old._digest(raw)
            )
            self.assertEqual(built["input_blobs"][subject.old._digest(raw)], raw)
        live = subject.old.live
        policy = json.loads(built["artifacts"]["policy"])["identity"]
        worker = json.loads(built["artifacts"]["worker"])["identity"]
        self.assertEqual(
            policy["policy_digest"], subject.old._digest(self.inputs[live._POLICY])
        )
        self.assertEqual(worker["binding"], json.loads(self.inputs[live._WORKER]))
        self.assertNotEqual(
            policy["policy_digest"],
            canonical_digest(self.baseline["observation"]["setup"]["policy"]),
        )
        self.assertNotIn(self.inputs[live._CONFIG], built["input_blobs"].values())
        self.assertEqual(
            (
                len(canonical_json(self.stage)),
                subject.old._digest(canonical_json(self.stage)),
            ),
            subject.STAGED_PROFILE_PIN,
        )

    def test_cases_share_deployment_but_changed_actual_policy_changes_it(self):
        built = [self.build(case_id=selected) for selected in subject.CASE_BRANCHES]
        self.assertEqual(
            len({canonical_digest(item["deployment"]) for item in built}), 1
        )
        self.assertEqual(
            len({item["preparation_digest"] for item in built}),
            len(subject.CASE_BRANCHES),
        )
        inputs, _ = _provisioning(inode=655)
        changed = self.build(provisioning_inputs=inputs)
        self.assertNotEqual(changed["deployment"], built[0]["deployment"])
        self.assertNotEqual(
            changed["artifacts"]["policy"], built[0]["artifacts"]["policy"]
        )
        self.assertNotEqual(
            changed["artifacts"]["worker"], built[0]["artifacts"]["worker"]
        )
        for name in (
            "runtime_commit_or_image",
            "adapter",
            "configuration",
            "os_profile",
            "aragorn_version",
        ):
            self.assertEqual(changed["artifacts"][name], built[0]["artifacts"][name])

    def test_exact_stage_static_source_inventory_container_and_writer_joins_required(
        self,
    ):
        sources = dict(self.arguments["implementation_source_raws"])
        sources.pop(next(iter(sources)))
        static = deepcopy(self.static)
        static["file_digests"][subject.old.live._WORKER_CODE] = PIN
        inputs = dict(self.inputs)
        worker = json.loads(inputs[subject.old.live._WORKER])
        worker["policy_digest"] = PIN
        inputs[subject.old.live._WORKER] = canonical_json(worker)
        coherent_changes = []
        live = subject.old.live
        for mode in ("sensor", "revocation-source"):
            documents = {path: json.loads(raw) for path, raw in self.inputs.items()}
            if mode == "sensor":
                for path in (live._OBSERVATION, live._POLICY, live._GRANT):
                    documents[path]["sensor_digest"] = PIN
            else:
                documents[live._POLICY]["revocation_source_digest"] = PIN
            policy_pin = canonical_digest(documents[live._POLICY])
            for path in (live._WORKER, live._GRANT, live._GENESIS):
                documents[path]["policy_digest"] = policy_pin
            coherent_changes.append(
                {
                    "provisioning_inputs": {
                        path: canonical_json(value) for path, value in documents.items()
                    }
                }
            )
        for updates in (
            {"case_id": "unreviewed"},
            {"nonce": True},
            {"container_id": "c" * 64},
            {"implementation_source_raws": sources},
            {"static_pin_manifest_raw": canonical_json(static)},
            {"static_pin_manifest_raw": canonical_json(self.static) + b"\n"},
            {"staged_profile_raw": canonical_json({**self.stage, "schema": "other"})},
            {"baseline_capture_raw": self.baseline_raw + b"\n"},
            {"provisioning_inputs": inputs},
            *coherent_changes,
        ):
            with (
                self.subTest(fields=list(updates)),
                self.assertRaises(subject.NativeCommonPreparationError),
            ):
                self.build(**updates)

    def test_single_request_joins_real_pure_measurement_closure_and_all_28_pins(self):
        preparation = self.build()
        self.retain(preparation["input_blobs"])
        measured = self.measurement(preparation)
        arguments = self.request_arguments(preparation, measured)
        with (
            patch.object(CAS, "put", side_effect=AssertionError("request wrote CAS")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("request wrote CAS")
            ),
            patch("time.time", side_effect=AssertionError("request sampled liveness")),
            patch(
                "time.clock_gettime_ns",
                side_effect=AssertionError("request sampled clock"),
            ),
        ):
            result = subject.prepare_native_common_request(**arguments)
        self.assertEqual(canonical_json(result["request"]), result["request_raw"])
        self.assertEqual(canonical_digest(result["request"]), result["request_digest"])
        self.assertEqual(len(result["expected_file_digests"]), 28)
        self.assertEqual(len(result["provisioning_file_digests"]), 8)
        self.assertEqual(
            {
                path: result["provisioning_file_digests"][path]
                for path in preparation["provisioning_file_digests"]
            },
            preparation["provisioning_file_digests"],
        )
        self.assertEqual(
            result["expected_file_digests"][
                "/etc/aragorn/runtime-broker-decision-measurement.json"
            ],
            measured["binding_digest"],
        )
        self.assertEqual(
            {
                path: result["expected_file_digests"][path]
                for path in subject.STATIC_PATHS
            },
            self.static["file_digests"],
        )
        self.assertEqual(
            result["decision"],
            {
                **dict.fromkeys(subject._FALSE, False),
                "supplied_payload_bytes_verified": True,
            },
        )

    def test_request_requires_caller_pins_read_only_store_and_actual_input_bytes(self):
        preparation = self.build()
        self.retain(preparation["input_blobs"])
        measured = self.measurement(preparation)
        arguments = self.request_arguments(preparation, measured)
        for updates in (
            {"expected_preparation_digest": PIN},
            {"expected_measurement_prepared_digest": PIN},
            {"expected_binding_digest": PIN},
            {"preparation_raw": preparation["preparation_raw"] + b"\n"},
            {"measurement_prepared_raw": canonical_json(measured) + b"\n"},
            {"expected_boot_id": "00000000-0000-0000-0000-000000000002"},
            {"payload_raw": b"other payload"},
            {
                "protected_descriptor_raw": canonical_json(
                    {**self.descriptor, "root_inode": 655}
                )
            },
            {"evidence_cas": self.cas},
            {"provisioning_inputs": _provisioning(inode=655)[0]},
        ):
            with (
                self.subTest(fields=list(updates)),
                self.assertRaises(subject.NativeCommonPreparationError),
            ):
                subject.prepare_native_common_request(**(arguments | updates))

    def test_self_consistent_measurement_rebinding_cannot_cross_common_preparation(
        self,
    ):
        preparation = self.build()
        self.retain(preparation["input_blobs"])
        for changed in ("deployment", "grant", "path", "payload", "source"):
            with self.subTest(changed=changed):
                measured = self.measurement(preparation, change=changed)
                with self.assertRaises(subject.NativeCommonPreparationError):
                    subject.prepare_native_common_request(
                        **self.request_arguments(preparation, measured)
                    )

    def test_rehashed_preparation_and_measurement_claims_are_not_authority(self):
        preparation = self.build()
        self.retain(preparation["input_blobs"])
        measured = self.measurement(preparation)
        arguments = self.request_arguments(preparation, measured)
        for field, value in (
            ("schema", "other"),
            ("authority", "LIVE_QUALIFIED"),
            ("extra", True),
        ):
            changed = {**preparation["preparation"], field: value}
            self.retain({canonical_digest(changed): canonical_json(changed)})
            with (
                self.subTest(field=field),
                self.assertRaises(subject.NativeCommonPreparationError),
            ):
                subject.prepare_native_common_request(
                    **(
                        arguments
                        | {
                            "preparation_raw": canonical_json(changed),
                            "expected_preparation_digest": canonical_digest(changed),
                        }
                    )
                )
        altered = deepcopy(measured)
        altered["decision"]["measurement_collected"] = True
        with self.assertRaises(subject.NativeCommonPreparationError):
            subject.prepare_native_common_request(
                **(
                    arguments
                    | {
                        "measurement_prepared_raw": canonical_json(altered),
                        "expected_measurement_prepared_digest": canonical_digest(
                            altered
                        ),
                    }
                )
            )

    def test_missing_or_changed_retained_preparation_refuses(self):
        preparation = self.build()
        self.retain(preparation["input_blobs"])
        measured = self.measurement(preparation)
        arguments = self.request_arguments(preparation, measured)
        selected = subject.old._digest(self.arguments["static_pin_manifest_raw"])
        read = self.reader.read
        for mode in ("missing", "changed", "late"):
            hits = []

            def guarded(pin, *, max_bytes):
                if pin == selected:
                    hits.append(pin)
                    if mode == "missing" or (mode == "late" and len(hits) == 3):
                        raise CASError("inert retained input loss")
                    if mode == "changed":
                        return canonical_json({"wrong": "static bytes"})
                return read(pin, max_bytes=max_bytes)

            with (
                self.subTest(mode=mode),
                patch.object(self.reader, "read", side_effect=guarded),
                self.assertRaises(subject.NativeCommonPreparationError),
            ):
                subject.prepare_native_common_request(**arguments)
            self.assertEqual(hits, [selected] * (3 if mode == "late" else 1))


if __name__ == "__main__":
    unittest.main()
