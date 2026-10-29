"""New HTTP plan/handoff joins only; inert documents are not capture evidence."""

from __future__ import annotations

import ast
import builtins
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import native_phase3_http_canary_contract as canary
from aragorn import native_phase3_http_collection as workload
from aragorn import native_phase3_http_collection_verify as http
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.cas import CAS
from scripts import materialize_native_phase3_http_attempt_plan as renderer

ROOT = Path(__file__).resolve().parents[1]
CONTAINER = "b" * 64
BOOT = "00000000-0000-0000-0000-000000000001"
ATTEMPT = "p3-lab-a001"
NONCE = "c" * 32
PIN = "sha256:" + "d" * 64


def _load(raw, source, dependencies=None):
    """Only a private test module receives explicit composed dependencies."""
    dependencies = dependencies or {}
    package = "scripts"
    result = ModuleType("scripts._http_attempt_plan_test_" + Path(source).stem)
    result.__package__ = package
    result.__file__ = str(ROOT / source)

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in {"scripts", "aragorn"} and fromlist:
            values = {}
            for key in fromlist:
                if name + "." + key in dependencies:
                    values[key] = dependencies[name + "." + key]
                else:
                    imported = builtins.__import__(name, globals, locals, (key,), 0)
                    values[key] = getattr(imported, key)
            return SimpleNamespace(**values)
        return builtins.__import__(name, globals, locals, fromlist, level)

    result.__dict__["__builtins__"] = vars(builtins) | {"__import__": local_import}
    exec(compile(raw, result.__file__, "exec"), result.__dict__)  # noqa: S102
    return result


def _data_common():
    # This tiny data-only boundary isolates the newly added action validation;
    # the full ready preparation receives its own independent composition check.
    paths = tuple("/inert/writer-" + str(n) for n in range(6)) + (
        "/inert/policy",
        "/etc/aragorn/runtime-http-fixture.json",
        "/etc/aragorn/runtime-http-readiness.json",
    )
    return SimpleNamespace(
        PREPARATION_SCHEMA="aragorn/native-common-deployment-preparation/v4",
        PROVISIONING_PATHS=paths,
        HTTP_FIXTURE=paths[-2],
        HTTP_READINESS=paths[-1],
        old=SimpleNamespace(
            _parse=lambda raw, _limit=None: json.loads(raw),
            _digest=canary.digest,
            live=SimpleNamespace(_POLICY=paths[-3]),
        ),
    )


class HttpAttemptPlanBridgeTests(unittest.TestCase):
    def setUp(self):
        self.original = {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
        self.generated = renderer.render(self.original)
        self.common = _data_common()
        self.handoff = _load(self.generated[renderer.HANDOFF], renderer.HANDOFF)
        self.plan = _load(
            self.generated[renderer.PLAN],
            renderer.PLAN,
            {
                "aragorn.native_phase3_common_preparation": self.common,
                "scripts.runtime_native_common_measurement_handoff": self.handoff,
            },
        )
        self.binding = {
            "schema": "aragorn/runtime-http-fixture-binding/v1",
            "fixture": {
                "container_id": CONTAINER,
                "boot_id": BOOT,
                "netns_device": 4,
                "netns_inode": 123456,
            },
            "expected_broker_uid": 998,
            "expected_broker_gid": 997,
        }
        self.readiness = {
            "schema": "aragorn/runtime-http-readiness-input/v1",
            "readiness_nonce": NONCE,
            "fixture_binding_digest": canonical_digest(self.binding),
            "timeout_ms": 500,
        }
        self.inputs = {path: b"{}" for path in self.common.PROVISIONING_PATHS}
        self.inputs.update(
            {
                self.common.HTTP_FIXTURE: canonical_json(self.binding),
                self.common.HTTP_READINESS: canonical_json(self.readiness),
                self.common.old.live._POLICY: canonical_json(
                    {"allow": [http.action_digests(ATTEMPT, self.binding)]}
                ),
            }
        )
        self.arguments = {"container_id": CONTAINER, "readiness_nonce": NONCE}
        self.descriptor = canonical_json(http.endpoint_descriptor(self.binding))
        self.payload = canary.canary_request(ATTEMPT)

    def action(self, **updates):
        values = dict(
            arguments=self.arguments,
            inputs=self.inputs,
            selected=ATTEMPT,
            boot=BOOT,
            descriptor_raw=self.descriptor,
            payload_raw=self.payload,
        )
        values.update(updates)
        return self.plan._http_action(**values)

    def test_exact_sources_render_two_inert_reversible_outputs(self):
        self.assertEqual(set(self.generated), set(renderer.INPUTS))
        for name, raw in self.generated.items():
            self.assertNotEqual(raw, self.original[name])
            ast.parse(raw)
            self.assertEqual((ROOT / name).read_bytes(), self.original[name])
            self.assertEqual(
                (
                    len(self.original[name]),
                    hashlib.sha256(self.original[name]).hexdigest(),
                ),
                renderer.INPUTS[name],
            )
        for name in renderer.INPUTS:
            with self.subTest(name=name):
                changed = dict(self.original)
                changed[name] += b"\n"
                with self.assertRaisesRegex(
                    renderer.NativeHttpAttemptPlanRenderError, "pin changed"
                ):
                    renderer.render(changed)
        with self.assertRaises(renderer.NativeHttpAttemptPlanRenderError):
            renderer.render({})

    def test_http_writer_endpoint_canary_and_readiness_join(self):
        self.assertEqual(
            self.action(),
            {
                "fixture_binding_digest": canonical_digest(self.binding),
                "readiness_input_digest": canonical_digest(self.readiness),
                "readiness_nonce": NONCE,
            },
        )
        self.assertNotIn("payload", self.action())

    def test_refuses_wrong_fixture_boot_path_payload_or_selected_canary(self):
        for updates in (
            {"arguments": self.arguments | {"container_id": "f" * 64}},
            {"boot": "00000000-0000-0000-0000-000000000002"},
            {
                "descriptor_raw": canonical_json(
                    {"schema": "aragorn/runtime-protected-path/v1"}
                )
            },
            {"payload_raw": b"Aragorn P3.7b distinct worker create\n"},
            {"selected": "p3-lab-a002"},
        ):
            with self.subTest(updates=updates):
                with self.assertRaisesRegex(
                    self.plan.NativeCommonAttemptPlanError, "HTTP_ACTION_CHANGED"
                ):
                    self.action(**updates)

    def test_refuses_old_preparation_missing_writer_and_readiness_nonce(self):
        self.common.PREPARATION_SCHEMA = (
            "aragorn/native-common-deployment-preparation/v3"
        )
        with self.assertRaisesRegex(
            self.plan.NativeCommonAttemptPlanError, "NINE_WRITER"
        ):
            self.action()
        self.common.PREPARATION_SCHEMA = (
            "aragorn/native-common-deployment-preparation/v4"
        )
        missing = dict(self.inputs)
        del missing[self.common.HTTP_READINESS]
        with self.assertRaisesRegex(
            self.plan.NativeCommonAttemptPlanError, "NINE_WRITER"
        ):
            self.action(inputs=missing)
        for field, value in (
            ("readiness_nonce", "e" * 32),
            ("fixture_binding_digest", PIN),
            ("timeout_ms", 501),
            ("timeout_ms", True),
            ("extra", False),
        ):
            with self.subTest(field=field, value=value):
                changed = self.inputs | {
                    self.common.HTTP_READINESS: canonical_json(
                        self.readiness | {field: value}
                    )
                }
                with self.assertRaisesRegex(
                    self.plan.NativeCommonAttemptPlanError, "READINESS_WRITER_JOIN"
                ):
                    self.action(inputs=changed)

    def test_refuses_policy_and_noncanonical_private_writer_bytes(self):
        changed = self.inputs | {
            self.common.old.live._POLICY: canonical_json({"allow": []})
        }
        with self.assertRaisesRegex(
            self.plan.NativeCommonAttemptPlanError, "ACTUAL_HTTP_WRITER"
        ):
            self.action(inputs=changed)
        for path in (self.common.HTTP_FIXTURE, self.common.HTTP_READINESS):
            changed = self.inputs | {path: self.inputs[path] + b"\n"}
            # Fixture changes also invalidate the nonce input's declared digest.
            with (
                self.subTest(path=path),
                self.assertRaises(self.plan.NativeCommonAttemptPlanError),
            ):
                self.action(inputs=changed)

    def test_source_functions_remain_actual_http_functions_not_mark_adapters(self):
        functions = self.handoff._functions()
        self.assertIs(functions["execute"], workload.collect_native_http_attempt)
        self.assertIs(functions["verify"], http.verify_native_http_collection)
        self.assertEqual(
            functions["identity_reader"].__name__, "read_native_common_identity"
        )
        for item in (self.plan.FALSE_FLAGS, self.handoff._FALSE):
            self.assertIn("generic_collector_semantics_eligible", item)
            self.assertIn("phase3_exit_eligible", item)
        raw = self.generated[renderer.HANDOFF]
        self.assertIn(
            b"with collector._prepared_attempt_claim(evidence_cas, claim)", raw
        )
        self.assertIn(b"PERMANENT_NO_RETRY_CLAIM_NOT_COMPLETION", raw)
        self.assertNotIn(b"run_native_blocked_create_workload", raw)
        self.assertNotIn(b"verify_native_blocked_create", raw)

    def provisioning(self):
        measured = {
            "binding": {"boot_id": BOOT, "payload_digest": PIN},
            "input_blobs": [{"digest": PIN, "bytes": 1}],
            "path_descriptor": {
                "fixture_binding_digest": canonical_digest(self.binding)
            },
        }
        report = {
            "schema": "aragorn/native-http-measurement-provisioning/v1",
            "authority": "ROOT_PROVISIONED_INPUTS_ONLY_NOT_ACTIVATION_MEASUREMENT_OR_PHASE3",
            "prepared_digest": canonical_digest(measured),
            "binding_digest": PIN,
            "credential": str(self.handoff.provisioning._CREDENTIAL),
            "input_store": str(self.handoff.provisioning._STORE),
            "input_blobs": measured["input_blobs"],
            "broker_uid": 998,
            "broker_gid": 997,
            "boot_id": BOOT,
            "stopped_units": {name: {} for name in self.handoff.provisioning._UNITS},
            "payload_digest_expectation": PIN,
            "payload_bytes_verified": False,
            "activation_performed": False,
            "measurement_collected": False,
            "run_qualified": False,
            "quantitative_metrics_eligible": False,
            "phase3_exit_eligible": False,
            "limitations": [],
            "http_endpoint_bound": True,
            "http_fixture_binding_digest": canonical_digest(self.binding),
        }
        return measured, report

    def test_http_provisioner_report_custody_join_preserves_false_flags(self):
        measured, report = self.provisioning()
        self.assertEqual(
            self.handoff._provisioned(
                report, measured, PIN, canonical_digest(self.binding)
            ),
            canonical_json(report),
        )
        for updates in (
            {"schema": "aragorn/native-measurement-provisioning/v1"},
            {"http_endpoint_bound": False},
            {"http_fixture_binding_digest": PIN},
            {"payload_bytes_verified": True},
            {"phase3_exit_eligible": True},
            {"extra": None},
        ):
            with self.subTest(updates=updates):
                with self.assertRaisesRegex(
                    self.handoff.NativeCommonMeasurementHandoffError,
                    "PROVISIONING_REPORT_JOIN",
                ):
                    self.handoff._provisioned(
                        report | updates, measured, PIN, canonical_digest(self.binding)
                    )

    def test_selected_attempt_and_family_refuse_before_private_store_creation(self):
        # The public entrypoint must reject these new mismatches before it can
        # create a commitment, sample a preparation clock, or consume a claim.
        common = {name: b"inert" for name in self.plan._ARGUMENTS}
        common.update(
            implementation_source_raws={},
            http_attempt_id=ATTEMPT,
            readiness_nonce=NONCE,
            container_id=CONTAINER,
        )
        arguments = dict(
            common_arguments=common,
            provisioning_inputs=self.inputs,
            expected_attempt_ids=[],
            expected_attempt_families={ATTEMPT: "DESTRUCTIVE"},
            expected_unattributed_attempt_id="p3-lab-a100",
            expected_overhead_pair_bindings={},
            expected_gate_manifest_digest=PIN,
            expected_campaign_contract_digest=PIN,
            selected_attempt_id=ATTEMPT,
            expected_boot_id=BOOT,
            protected_descriptor_raw=self.descriptor,
            payload_raw=self.payload,
            source_pins={},
            evidence_cas=None,
            plan_cas=None,
            public_blob_attempts=[],
        )
        with self.assertRaises(self.plan.NativeCommonAttemptPlanError) as caught:
            self.plan.prepare_native_common_attempt_plan(**arguments)
        self.assertIn("HTTP_SELECTED_FAMILY", str(caught.exception.__cause__))
        self.assertEqual(
            caught.exception._native_common_attempt_public_blob_digests, []
        )
        changed = deepcopy(arguments)
        changed["common_arguments"]["http_attempt_id"] = "p3-lab-a002"
        with self.assertRaises(self.plan.NativeCommonAttemptPlanError) as caught:
            self.plan.prepare_native_common_attempt_plan(**changed)
        self.assertIn("HTTP_SELECTED_ATTEMPT", str(caught.exception.__cause__))
        self.assertEqual(
            caught.exception._native_common_attempt_public_blob_digests, []
        )

    def test_original_ready_plan_real_private_closure_and_once_handoff(self):
        from tests.test_native_phase3_http_ready_helpers import ReadyPreparationFixture

        data = ReadyPreparationFixture(self)
        common = data.subject
        prepared = common.prepare_native_common_deployment(**data.arguments)
        common_arguments = {
            key: value
            for key, value in data.arguments.items()
            if key != "provisioning_inputs"
        }
        common_arguments["http_attempt_id"] = ATTEMPT
        identity_source = "src/aragorn/native_phase3_common_identity.py"
        identity_raw = data.generated[identity_source]
        identity_path = data.root / "http-ready-identity-source.py"
        identity_path.write_bytes(identity_raw)
        identity_name = "aragorn._http_ready_attempt_identity_fixture"
        identity = ModuleType(identity_name)
        identity.__package__ = "aragorn"
        identity.__file__ = str(identity_path)
        exec(compile(identity_raw, str(identity_path), "exec"), identity.__dict__)  # noqa: S102
        dependencies = {
            "aragorn.native_phase3_common_preparation": common,
            "aragorn.native_phase3_common_identity": identity,
        }
        handoff = _load(
            self.generated[renderer.HANDOFF], renderer.HANDOFF, dependencies
        )
        plan = _load(
            self.generated[renderer.PLAN],
            renderer.PLAN,
            dependencies
            | {
                "scripts.runtime_native_common_measurement_handoff": handoff,
                "aragorn.runtime_broker_measurement_plan": data.planner,
                "aragorn.runtime_native_measurement_inputs": data.input_validator,
            },
        )
        functions = handoff._functions()
        pins = {
            role: canary.digest(
                identity_raw
                if role == "identity_reader"
                else Path(sys.modules[function.__module__].__file__).read_bytes()
            )
            for role, function in functions.items()
        }
        attempts = [f"p3-lab-a{n:03d}" for n in range(1, 101)]
        families = {
            name: "EXFILTRATION" if n < 50 else "DESTRUCTIVE"
            for n, name in enumerate(attempts)
        }
        evidence = CAS(data.root / "http-original-evidence")
        target = CAS(data.root / "http-private-plan")
        journal = []
        binding = json.loads(data.inputs[common.HTTP_FIXTURE])
        descriptor = canonical_json(http.endpoint_descriptor(binding))
        payload = canary.canary_request(ATTEMPT)
        arguments = {
            "common_arguments": common_arguments,
            "provisioning_inputs": data.inputs,
            "expected_attempt_ids": attempts,
            "expected_attempt_families": families,
            "expected_unattributed_attempt_id": attempts[-1],
            "expected_overhead_pair_bindings": {
                f"pair-{n:03d}": {
                    "task_digest": PIN,
                    "input_digest": f"sha256:{n + 1:064x}",
                    "host_profile_digest": prepared["deployment"]["bindings"][
                        "os_profile"
                    ],
                }
                for n in range(100)
            },
            "expected_gate_manifest_digest": PIN,
            "expected_campaign_contract_digest": PIN,
            "selected_attempt_id": ATTEMPT,
            "expected_boot_id": binding["fixture"]["boot_id"],
            "protected_descriptor_raw": descriptor,
            "payload_raw": payload,
            "source_pins": pins,
            "evidence_cas": evidence,
            "plan_cas": target,
            "public_blob_attempts": journal,
        }
        codes = {function.__code__ for function in functions.values()}
        observed_calls = []

        def trace(frame, event, _argument):
            if event == "call" and frame.f_code in codes:
                observed_calls.append(frame.f_code.co_name)

        previous = sys.getprofile()
        try:
            sys.setprofile(trace)
            with patch.dict(sys.modules, {identity_name: identity}):
                with patch.object(
                    plan.collector, "_boottime_ns", side_effect=[100, 200]
                ):
                    built = plan.prepare_native_common_attempt_plan(**arguments)
                measured = json.loads(built["measurement_prepared_raw"])
                request = json.loads(built["request_raw"])
                claim = (
                    evidence.root
                    / plan.collector._PREPARED_CLAIMS
                    / (built["report"]["commitment_digest"][7:] + ".json")
                )
                self.assertEqual(len(request["expected_file_digests"]), 43)
                self.assertEqual(len(measured["binding"]["source_pins"]), 22)
                self.assertEqual(
                    request["readiness_nonce"], common_arguments["readiness_nonce"]
                )
                self.assertEqual(
                    built["report"]["http_binding"]["fixture_binding_digest"],
                    canonical_digest(binding),
                )
                private_pins = {canary.digest(raw) for raw in data.inputs.values()}
                self.assertFalse(
                    private_pins.intersection(built["public_blob_digests"])
                )
                grant = data.inputs[common.old.live._GRANT]
                self.assertEqual(evidence.read(canary.digest(grant)), grant)
                self.assertEqual(target.read(canary.digest(grant)), grant)
                self.assertFalse(claim.exists())

                @contextmanager
                def owned(container, boot):
                    self.assertEqual(
                        (container, boot),
                        (
                            binding["fixture"]["container_id"],
                            binding["fixture"]["boot_id"],
                        ),
                    )
                    yield lambda: None

                def provision(**provided):
                    self.assertTrue(claim.exists())
                    self.assertEqual(
                        provided["expected_broker_source_pins"],
                        data.stage["binding_source_pins"],
                    )
                    self.assertEqual(
                        provided["prepared_raw"], built["measurement_prepared_raw"]
                    )
                    self.assertTrue(provided["source_cas"].read_only)
                    _, report = self.provisioning()
                    report.update(
                        prepared_digest=built["measurement_prepared_digest"],
                        binding_digest=built["binding_digest"],
                        input_blobs=measured["input_blobs"],
                        boot_id=binding["fixture"]["boot_id"],
                        payload_digest_expectation=measured["binding"][
                            "payload_digest"
                        ],
                        http_fixture_binding_digest=canonical_digest(binding),
                    )
                    return report

                with (
                    patch.object(handoff, "_fixture", owned),
                    patch.object(plan.collector, "_boottime_ns", return_value=300),
                    patch.object(
                        plan.collector,
                        "prepare_phase3_measurement_collection",
                        side_effect=AssertionError("no second original collection"),
                    ),
                    patch.object(
                        handoff.provisioning,
                        "provision_runtime_native_measurement",
                        side_effect=provision,
                    ) as invoked,
                ):
                    with handoff.hold_prepared_native_common_measurement(
                        collection_preparation_raw=built["collection_preparation_raw"],
                        expected_collection_preparation_digest=built[
                            "collection_preparation_digest"
                        ],
                        common_preparation_raw=built["common_preparation_raw"],
                        expected_common_preparation_digest=built[
                            "common_preparation_digest"
                        ],
                        measurement_prepared_raw=built["measurement_prepared_raw"],
                        expected_measurement_prepared_digest=built[
                            "measurement_prepared_digest"
                        ],
                        expected_binding_digest=built["binding_digest"],
                        scheduled_request=built["scheduled_request"],
                        provisioning_inputs=data.inputs,
                        expected_container_id=binding["fixture"]["container_id"],
                        expected_boot_id=binding["fixture"]["boot_id"],
                        protected_descriptor_raw=descriptor,
                        payload_raw=payload,
                        evidence_cas=evidence,
                        source_pins=pins,
                    ) as session:
                        self.assertEqual(session.request_raw, built["request_raw"])
                        self.assertEqual(
                            session.report["schema"],
                            "aragorn/native-http-measurement-handoff/v1",
                        )
                        self.assertTrue(
                            all(
                                value is False
                                for value in session.report["decision"].values()
                            )
                        )
                        session.guard()
                    invoked.assert_called_once()
                self.assertTrue(claim.exists())
                self.assertEqual(
                    json.loads(claim.read_bytes())["state"],
                    "PERMANENT_NO_RETRY_CLAIM_NOT_COMPLETION",
                )
        finally:
            sys.setprofile(previous)
        self.assertEqual(observed_calls, [])


if __name__ == "__main__":
    unittest.main()
