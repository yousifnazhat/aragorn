"""HTTP93 preparation data only; no runtime, clock or acceptance evidence."""

from __future__ import annotations

import builtins
from copy import deepcopy
from functools import lru_cache
from io import BytesIO
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from aragorn import native_phase3_http_canary_contract as canary
from aragorn import native_phase3_http_collection_verify as http
from aragorn import phase3_quantitative_metrics as metrics
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_native_phase3_http_identity as identity_render
from scripts import materialize_native_phase3_http_preparation as renderer
from scripts import materialize_runtime_http_collection as collection_render
from scripts import stage_runtime_phase3_http_profile as stager


ROOT = Path(__file__).resolve().parents[1]
CONTAINER = "b" * 64
BOOT = "00000000-0000-0000-0000-000000000001"
ATTEMPT = "p3-lab-a001"
PIN = "sha256:" + "f" * 64
BASELINE = ROOT / (
    "benchmark/evidence/"
    "phase3-native-plugin-update-systemd-development-v2-2026-10-01.json"
)


def _module(source, name, dependencies=None):
    """Load only an inert successor namespace; never replace production globals."""
    module = types.ModuleType("aragorn._http_preparation_test_" + name)
    module.__package__ = "aragorn"
    module.__file__ = str(ROOT / "src/aragorn" / (name + ".py"))
    dependencies = dependencies or {}

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name in dependencies:
            return dependencies[name]
        if (
            level == 1
            and name == ""
            and fromlist
            and all(key in dependencies for key in fromlist)
        ):
            return types.SimpleNamespace(**{key: dependencies[key] for key in fromlist})
        return builtins.__import__(name, globals, locals, fromlist, level)

    # Module-local import wiring models the composed package, including constants
    # derived at import time. No shared package, sys.modules or builtin is patched.
    module.__dict__["__builtins__"] = vars(builtins) | {"__import__": local_import}
    exec(compile(source, module.__file__, "exec"), module.__dict__)  # noqa: S102
    return module


@lru_cache(maxsize=1)
def rendered_modules():
    originals = {
        name: (ROOT / name).read_bytes()
        for name in (
            *renderer.INPUTS,
            *identity_render.INPUTS,
            *collection_render.INPUTS,
        )
    }
    generated = (
        renderer.render(originals)
        | identity_render.render(originals)
        | collection_render.render(originals)
    )
    identity = _module(generated[identity_render.IDENTITY], "identity")
    prior = _module(generated[collection_render.PRIOR], "measurement_verify")
    inputs = _module(
        generated[renderer.MEASUREMENT_INPUTS],
        "measurement_inputs",
        {"runtime_broker_decision_measurement_verify": prior},
    )
    planner = _module(generated[collection_render.PLAN], "measurement_plan")
    subject = _module(
        generated[renderer.PREPARATION],
        "preparation",
        {
            "native_phase3_common_identity": identity,
            "runtime_native_measurement_inputs": inputs,
        },
    )
    return subject, inputs, planner, generated


@lru_cache(maxsize=1)
def _stage_data():
    # One fresh DESTDIR is data construction, not a prior test or live capture.
    with tempfile.TemporaryDirectory() as temporary:
        destination = Path(temporary).resolve() / "http"
        stage = stager.stage_runtime_phase3_http_profile(destination)
        config_raw = (
            destination / "opt/aragorn/runtime-http-gateway-template.json"
        ).read_bytes()
    baseline_raw = BASELINE.read_bytes()
    return stage, baseline_raw, json.loads(baseline_raw), config_raw


def provisioning_inputs(subject, baseline, config_raw, *, container=CONTAINER):
    live = subject.old.live
    setup = baseline["observation"]["setup"]
    profile = deepcopy(setup["runtime_profile"])
    profile["cgroup"] = (
        f"/docker/{container}/system.slice/aragorn-runtime-action-worker.service"
    )
    documents = {
        live._CONFIG: json.loads(config_raw),
        live._WORKER: deepcopy(setup["worker_binding"]),
        live._POLICY: deepcopy(setup["policy"]),
        live._GRANT: deepcopy(setup["grant"]),
        live._GENESIS: deepcopy(setup["empty_store"]["genesis"]),
        live._RUNTIME: {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": setup["runtime_digest"],
            "runtime_profile_digest": canonical_digest(profile),
        },
        live._OBSERVATION: {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": setup["policy"]["sensor_digest"],
            "runtime_profile": profile,
        },
        renderer.HTTP_FIXTURE: {
            "schema": "aragorn/runtime-http-fixture-binding/v1",
            "fixture": {
                "container_id": container,
                "boot_id": BOOT,
                "netns_device": 4,
                "netns_inode": 123456,
            },
            "expected_broker_uid": 998,
            "expected_broker_gid": 997,
        },
    }
    binding = documents[renderer.HTTP_FIXTURE]
    digests = http.action_digests(ATTEMPT, binding)
    grant = documents[live._GRANT]
    grant.update(
        runtime_profile_digest=canonical_digest(profile),
        operation_digest=digests["operation_digest"],
        grant_id="d" * 64,
        issued_at_unix=1,
        expires_at_unix=241,
    )
    policy = documents[live._POLICY]
    policy["id"] = "owned-native-receipt-http-canary"
    policy["allow"][0].update(digests)
    policy_pin = canonical_digest(policy)
    for name in (live._WORKER, live._GRANT, live._GENESIS):
        documents[name]["policy_digest"] = policy_pin
    return {name: canonical_json(value) for name, value in documents.items()}


class HttpPreparationFixture:
    """Reusable new fixture data, without inherited or invoked test methods."""

    def __init__(self, testcase):
        self.testcase = testcase
        temporary = tempfile.TemporaryDirectory()
        testcase.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cas = CAS(self.root / "retained")
        self.reader = CAS(self.cas.root, read_only=True)
        self.subject, self.input_validator, self.planner, self.generated = (
            rendered_modules()
        )
        stage, self.baseline_raw, self.baseline, self.config_raw = _stage_data()
        self.stage = deepcopy(stage)
        self.inputs = provisioning_inputs(self.subject, self.baseline, self.config_raw)
        self.fixture_binding = json.loads(self.inputs[renderer.HTTP_FIXTURE])
        self.descriptor = http.endpoint_descriptor(self.fixture_binding)
        self.payload = canary.canary_request(ATTEMPT)
        live = self.subject.old.live
        files = {row["path"]: row for row in self.stage["files"]}
        special = {
            live._ENTRY: stage["required_runtime_not_included"]["entrypoint_digest"],
            live._PYTHON: self.baseline["observation"]["setup"]["runtime_profile"][
                "executable_digest"
            ],
            live._NODE: self.subject.admission._NODE_PIN,
        }
        self.static = {
            "schema": self.subject.STATIC_SCHEMA,
            "file_digests": {
                path: special[path] if path in special else files[path]["digest"]
                for path in self.subject.STATIC_PATHS
            },
        }
        self.arguments = {
            "case_id": self.subject.admission.DIRECT_WRITE_CASE,
            "nonce": "a" * 64,
            "container_id": CONTAINER,
            "source_record_raw": canonical_json(
                {"commit": "c" * 40, "test_only": True}
            ),
            "implementation_source_raws": {
                name: self.generated[name]
                if name in self.generated
                else (ROOT / name).read_bytes()
                for name in self.subject.IMPLEMENTATION_SOURCE_PATHS
            },
            "static_pin_manifest_raw": canonical_json(self.static),
            "staged_profile_raw": canonical_json(self.stage),
            "baseline_capture_raw": self.baseline_raw,
            "provisioning_inputs": self.inputs,
        }

    def build(self, **updates):
        return self.subject.prepare_native_common_deployment(
            **(self.arguments | updates)
        )

    def retain(self, blobs):
        for pin, raw in blobs.items():
            self.testcase.assertEqual(
                self.cas.put_expected(
                    BytesIO(raw), expected_digest=pin, max_bytes=len(raw)
                ),
                pin,
            )

    def measurement(self, preparation):
        source = CAS(self.root / "measurement-source")

        def put(value):
            raw = value if type(value) is bytes else canonical_json(value)
            return source.put(BytesIO(raw), max_bytes=1024 * 1024)

        for raw in preparation["input_blobs"].values():
            put(raw)
        deployment = preparation["deployment"]
        deployment_pin = put(deployment)
        attempts = [f"p3-lab-a{n:03d}" for n in range(1, 101)]
        schedule = metrics.build_phase3_measurement_schedule(
            expected_attempt_ids=attempts,
            expected_attempt_families={
                name: "EXFILTRATION" if n < 50 else "DESTRUCTIVE"
                for n, name in enumerate(attempts)
            },
            expected_unattributed_attempt_id=attempts[-1],
            expected_overhead_pair_bindings={
                f"pair-{n:03d}": {
                    "task_digest": PIN,
                    "input_digest": f"sha256:{n + 1:064x}",
                    "host_profile_digest": deployment["bindings"]["os_profile"],
                }
                for n in range(100)
            },
            expected_gate_manifest_digest=PIN,
            expected_campaign_contract_digest=PIN,
            expected_runtime_identity_digest=deployment_pin,
        )
        schedule_pin = put(schedule)
        roles = ("execute", "verify", "identity_reader")
        commitment = {
            "schema": "aragorn/phase3-measurement-collection-commitment/v1",
            "collection_id": "1" * 64,
            "schedule_digest": schedule_pin,
            "deployment": deployment,
            "sources": {
                role: {
                    "module": role,
                    "function": role,
                    "path": "/inert/" + role + ".py",
                    "bytes": 1,
                    "digest": PIN,
                }
                for role in roles
            },
            "collector_digest": PIN,
            "metrics_implementation_digest": metrics.metrics_implementation_digest(),
            "clock_id": metrics.CLOCK_ID,
            # Explicit test data, not a sampled clock or a collection observation.
            "prepared_boottime_ns": 1,
        }
        commitment_pin = put(commitment)
        target = CAS(self.root / "measurement-target")
        arguments = {
            "source_cas": CAS(source.root, read_only=True),
            "target_cas": target,
            "expected_commitment_digest": commitment_pin,
            "expected_schedule_digest": schedule_pin,
            "expected_deployment_digest": deployment_pin,
            "expected_grant_digest": put(self.inputs[self.subject.old.live._GRANT]),
            "expected_path_digest": put(self.descriptor),
            "expected_payload_digest": canary.digest(self.payload),
            "expected_collector_digest": PIN,
            "expected_collection_source_pins": dict.fromkeys(roles, PIN),
            "expected_broker_source_pins": dict(self.stage["binding_source_pins"]),
            "expected_boot_id": BOOT,
            "scheduled_request": {
                "kind": "attempt",
                "attempt_id": ATTEMPT,
                "family": "EXFILTRATION",
                "negative_control": False,
                "collection_digest": commitment_pin,
                "deployment_digest": deployment_pin,
            },
        }
        prepared = self.planner.prepare_broker_decision_measurement_binding(**arguments)
        self.retain(
            {
                row["digest"]: target.read(row["digest"])
                for row in prepared["input_blobs"]
            }
        )
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
            "payload_raw": self.payload,
        }

    def input_arguments(self, measured):
        return {
            "prepared_raw": canonical_json(measured),
            "expected_prepared_digest": canonical_digest(measured),
            "expected_binding_digest": measured["binding_digest"],
            "expected_broker_source_pins": dict(self.stage["binding_source_pins"]),
            "source_cas": self.reader,
        }


class HttpPreparationTests(unittest.TestCase):
    def setUp(self):
        self.data = HttpPreparationFixture(self)
        self.subject = self.data.subject
        if (
            self._testMethodName
            != "test_renderer_is_exact_pinned_and_does_not_modify_predecessors"
        ):
            # A negative test must not pass because an unrelated baseline gate
            # failed before it reached the mutation under test.
            baseline = self.data.build()
            self.assertEqual(len(baseline["provisioning_file_digests"]), 8)
            self.assertFalse(
                baseline["preparation"]["decision"]["phase3_exit_eligible"]
            )

    def edit(self, path, callback):
        inputs = dict(self.data.inputs)
        value = json.loads(inputs[path])
        callback(value)
        inputs[path] = canonical_json(value)
        return inputs

    def prepared_request(self):
        prepared = self.data.build()
        self.data.retain(prepared["input_blobs"])
        measured = self.data.measurement(prepared)
        return prepared, measured, self.data.request_arguments(prepared, measured)

    def test_renderer_is_exact_pinned_and_does_not_modify_predecessors(self):
        originals = {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
        before = dict(originals)
        outputs = renderer.render(originals)
        self.assertEqual(originals, before)
        self.assertEqual(set(outputs), set(renderer.INPUTS))
        for name, raw in outputs.items():
            compile(raw, name, "exec")
            self.assertNotEqual(raw, before[name])
        for invalid in (
            {},
            outputs,
            before | {renderer.PREPARATION: before[renderer.PREPARATION] + b"\n"},
        ):
            with (
                self.subTest(inventory=list(invalid)),
                self.assertRaises(renderer.NativeHttpPreparationRenderError),
            ):
                renderer.render(invalid)

    def test_http93_preparation_is_pure_and_has_eight_writer_pins(self):
        before = deepcopy(self.data.arguments)
        with (
            patch.object(CAS, "put", side_effect=AssertionError("no CAS writes")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("no CAS writes")
            ),
            patch("time.time", side_effect=AssertionError("no liveness clock")),
            patch(
                "time.clock_gettime_ns",
                side_effect=AssertionError("no measurement clock"),
            ),
        ):
            result = self.data.build()
        self.assertEqual(self.data.arguments, before)
        self.assertEqual(
            result["preparation"]["schema"], self.subject.PREPARATION_SCHEMA
        )
        self.assertEqual(len(result["provisioning_file_digests"]), 8)
        self.assertEqual(len(self.data.static["file_digests"]), 32)
        self.assertTrue(
            all(value is False for value in result["preparation"]["decision"].values())
        )
        self.assertEqual(
            result["provisioning_file_digests"][renderer.HTTP_FIXTURE],
            canonical_digest(self.data.fixture_binding),
        )
        self.assertNotIn(
            self.data.inputs[renderer.HTTP_FIXTURE], result["input_blobs"].values()
        )
        self.assertEqual(len(self.subject.IMPLEMENTATION_SOURCE_PATHS), 10)

    def test_config_and_worker_artifacts_bind_the_actual_http_profile(self):
        built = self.data.build()
        live = self.subject.old.live
        self.assertEqual(
            built["provisioning_file_digests"][live._CONFIG], renderer.HTTP_CONFIG_PIN
        )
        worker = json.loads(built["artifacts"]["worker"])
        worker_pin = next(
            row["digest"]
            for row in self.data.stage["files"]
            if row["path"] == live._WORKER_CODE
        )
        self.assertEqual(worker["identity"]["digest"], worker_pin)
        self.assertEqual(
            self.data.stage["measurement_source_names"],
            sorted(self.subject.common_identity.MEASUREMENT_SOURCES),
        )
        self.assertEqual(len(self.data.stage["binding_source_pins"]), 21)

    def test_historical_or_mutated_stage_bytes_are_refused(self):
        stage = deepcopy(self.data.stage)
        stage["http_collected"] = True
        for raw in (
            canonical_json(self.data.baseline["staged_profile"]),
            canonical_json(stage),
        ):
            with (
                self.subTest(pin=canary.digest(raw)),
                self.assertRaises(self.subject.NativeCommonPreparationError),
            ):
                self.data.build(staged_profile_raw=raw)

    def test_noncanonical_and_historical_gateway_configuration_are_refused(self):
        live = self.subject.old.live
        altered = json.loads(self.data.inputs[live._CONFIG])
        altered["tools"]["alsoAllow"].remove("aragorn_runtime_http_canary")
        for raw in (self.data.inputs[live._CONFIG] + b"\n", canonical_json(altered)):
            with (
                self.subTest(pin=canary.digest(raw)),
                self.assertRaises(self.subject.NativeCommonPreparationError),
            ):
                self.data.build(
                    provisioning_inputs=self.data.inputs | {live._CONFIG: raw}
                )

    def test_missing_or_extra_http_writer_is_refused(self):
        for inputs in (
            {
                key: value
                for key, value in self.data.inputs.items()
                if key != renderer.HTTP_FIXTURE
            },
            self.data.inputs | {"/etc/aragorn/unreviewed.json": b"{}"},
        ):
            with (
                self.subTest(paths=sorted(inputs)),
                self.assertRaises(self.subject.NativeCommonPreparationError),
            ):
                self.data.build(provisioning_inputs=inputs)

    def test_fixture_container_or_namespace_rebinding_is_refused(self):
        for key, value in (("container_id", "e" * 64), ("netns_inode", 123457)):
            inputs = self.edit(
                renderer.HTTP_FIXTURE,
                lambda binding: binding["fixture"].update({key: value}),
            )
            with (
                self.subTest(key=key),
                self.assertRaises(self.subject.NativeCommonPreparationError),
            ):
                self.data.build(provisioning_inputs=inputs)

    def test_fixture_role_alias_or_wrong_group_is_refused(self):
        for key, value in (("expected_broker_uid", 997), ("expected_broker_gid", 996)):
            inputs = self.edit(
                renderer.HTTP_FIXTURE, lambda binding: binding.update({key: value})
            )
            with (
                self.subTest(key=key),
                self.assertRaises(self.subject.NativeCommonPreparationError),
            ):
                self.data.build(provisioning_inputs=inputs)

    def test_rehashed_policy_cannot_authorize_an_arbitrary_http_action(self):
        live = self.subject.old.live
        for key in ("operation_digest", "path_digest", "payload_digest"):
            inputs = self.edit(
                live._POLICY, lambda policy: policy["allow"][0].update({key: PIN})
            )
            documents = {path: json.loads(raw) for path, raw in inputs.items()}
            policy_pin = canonical_digest(documents[live._POLICY])
            for name in (live._WORKER, live._GRANT, live._GENESIS):
                documents[name]["policy_digest"] = policy_pin
            if key == "operation_digest":
                documents[live._GRANT][key] = PIN
            inputs = {path: canonical_json(value) for path, value in documents.items()}
            with (
                self.subTest(key=key),
                self.assertRaises(self.subject.NativeCommonPreparationError),
            ):
                self.data.build(provisioning_inputs=inputs)

    def test_case_selection_preserves_the_shared_deployment(self):
        built = [self.data.build(case_id=case) for case in self.subject.CASE_BRANCHES]
        self.assertEqual(
            len({canonical_digest(value["deployment"]) for value in built}), 1
        )
        self.assertEqual(
            len({value["preparation_digest"] for value in built}), len(built)
        )

    def test_http_measurement_input_binding_closes_over_twenty_one_sources(self):
        preparation = self.data.build()
        measured = self.data.measurement(preparation)
        with (
            patch.object(CAS, "put", side_effect=AssertionError("no input writes")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("no input writes")
            ),
        ):
            result = (
                self.data.input_validator.validate_prepared_native_measurement_inputs(
                    **self.data.input_arguments(measured)
                )
            )
        self.assertGreater(len(result["binding_raw"]), 0)
        self.assertLessEqual(len(result["binding_raw"]), 8192)
        self.assertEqual(len(result["binding"]["source_pins"]), 21)
        self.assertLessEqual(len(result["input_blobs"]), 13)
        self.assertEqual(result["path_descriptor"], self.data.descriptor)

    def test_request_has_exact_41_installed_pins_and_no_live_authority(self):
        _, _, arguments = self.prepared_request()
        with (
            patch.object(CAS, "put", side_effect=AssertionError("no request writes")),
            patch(
                "time.clock_gettime_ns", side_effect=AssertionError("no request clock")
            ),
        ):
            result = self.subject.prepare_native_common_request(**arguments)
        self.assertEqual(len(result["expected_file_digests"]), 41)
        self.assertEqual(
            set(result["expected_file_digests"]),
            set(self.subject.common_identity.FILE_PATHS),
        )
        self.assertEqual(len(result["provisioning_file_digests"]), 9)
        self.assertEqual(result["request"]["schema"], self.subject.REQUEST_SCHEMA)
        self.assertTrue(result["decision"].pop("supplied_payload_bytes_verified"))
        self.assertTrue(all(value is False for value in result["decision"].values()))

    def test_request_refuses_wrong_boot_descriptor_and_payload(self):
        _, _, arguments = self.prepared_request()
        changes = (
            {"expected_boot_id": "00000000-0000-0000-0000-000000000002"},
            {
                "protected_descriptor_raw": canonical_json(
                    self.data.descriptor | {"host": "127.0.0.2"}
                )
            },
            {"payload_raw": self.data.payload + b"x"},
        )
        for update in changes:
            with (
                self.subTest(field=next(iter(update))),
                self.assertRaises(self.subject.NativeCommonPreparationError),
            ):
                self.subject.prepare_native_common_request(**(arguments | update))

    def test_request_refuses_rebound_protected_fixture_bytes(self):
        _, _, arguments = self.prepared_request()
        inputs = self.edit(
            renderer.HTTP_FIXTURE,
            lambda binding: binding["fixture"].update(netns_inode=123457),
        )
        with self.assertRaises(self.subject.NativeCommonPreparationError):
            self.subject.prepare_native_common_request(
                **(arguments | {"provisioning_inputs": inputs})
            )

    def test_input_manifest_extras_or_missing_bytes_are_refused(self):
        measured = self.data.measurement(self.data.build())
        for rows in (
            measured["input_blobs"][:-1],
            measured["input_blobs"] + [{"digest": PIN, "bytes": 1}],
        ):
            changed = measured | {"input_blobs": rows}
            with (
                self.subTest(count=len(rows)),
                self.assertRaises(
                    self.data.input_validator.NativeMeasurementInputError
                ),
            ):
                self.data.input_validator.validate_prepared_native_measurement_inputs(
                    **self.data.input_arguments(changed)
                )


if __name__ == "__main__":
    unittest.main()
