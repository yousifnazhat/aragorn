"""Inert native handoff composition, not live execution or acceptance evidence.

Preparation, source inspection, common request reconstruction, broker planning,
private CAS bytes and permanent claims are real. Linux fixture checks and root
provisioning effects are explicitly doubled. No historical test methods run.
"""

from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import phase3_quantitative_metrics as metrics
from aragorn import runtime_broker_measurement_plan as plan
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_native_common_measurement_handoff as subject
from tests import test_native_phase3_common_preparation as common_data
from tests import test_runtime_broker_measurement_plan as plan_data


class Fixture:
    def __init__(self, test):
        data = common_data.NativeCommonPreparationTests()
        data.setUp()
        test.addCleanup(data.doCleanups)
        self.data = data
        self.cas = data.cas
        self.root = data.root
        self.built = subject.common.prepare_native_common_deployment(**data.arguments)
        for raw in self.built["input_blobs"].values():
            self.put(raw)
        inventory = plan_data.BrokerMeasurementPlanTests()
        inventory.setUp()
        test.addCleanup(inventory.doCleanups)
        template = json.loads(
            inventory.arguments["source_cas"].read(
                inventory.arguments["expected_schedule_digest"]
            )
        )
        pairs = deepcopy(template["overhead_schedule"]["pair_bindings"])
        for pair in pairs.values():
            pair["host_profile_digest"] = self.built["deployment"]["bindings"][
                "os_profile"
            ]
        attempts = template["attempt_schedule"]
        self.schedule = metrics.build_phase3_measurement_schedule(
            expected_attempt_ids=attempts["attempt_ids"],
            expected_attempt_families=attempts["attempt_families"],
            expected_unattributed_attempt_id=attempts[
                "unattributed_negative_control_attempt_id"
            ],
            expected_overhead_pair_bindings=pairs,
            expected_gate_manifest_digest=template["bindings"]["gate_manifest_digest"],
            expected_campaign_contract_digest=template["bindings"][
                "campaign_contract_digest"
            ],
            expected_runtime_identity_digest=self.built["preparation"][
                "deployment_digest"
            ],
        )
        self.functions = subject._functions()
        self.pins = {
            name: "sha256:"
            + hashlib.sha256(
                Path(sys.modules[function.__module__].__file__).read_bytes()
            ).hexdigest()
            for name, function in self.functions.items()
        }
        with patch.object(subject.collector, "_boottime_ns", side_effect=[100, 200]):
            self.collection = subject.collector.prepare_phase3_measurement_collection(
                self.schedule,
                deployment=self.built["deployment"],
                evidence_cas=self.cas,
                **self.functions,
                source_pins=self.pins,
            )
        self.collection_raw = canonical_json(self.collection)
        self.collection_pin = self.put(self.collection_raw)
        self.grant_pin = self.put(data.inputs[subject.common.old.live._GRANT])
        self.path_pin = self.put(canonical_json(data.descriptor))
        self.measurement_count = 0
        self.rebind("attempt-001")

    def put(self, raw):
        return self.cas.put(BytesIO(raw), max_bytes=1024 * 1024)

    def rebind(self, attempt_id):
        self.measurement_count += 1
        self.scheduled = {
            "kind": "attempt",
            "attempt_id": attempt_id,
            "family": self.schedule["attempt_schedule"]["attempt_families"][attempt_id],
            "negative_control": False,
            "collection_digest": self.collection["commitment_digest"],
            "deployment_digest": canonical_digest(self.built["deployment"]),
        }
        target = CAS(self.root / f"binding-{self.measurement_count}")
        self.measured = plan.prepare_broker_decision_measurement_binding(
            source_cas=CAS(self.cas.root, read_only=True),
            target_cas=target,
            expected_commitment_digest=self.collection["commitment_digest"],
            expected_schedule_digest=self.collection["schedule_digest"],
            expected_deployment_digest=canonical_digest(self.built["deployment"]),
            expected_grant_digest=self.grant_pin,
            expected_path_digest=self.path_pin,
            expected_payload_digest=subject.common.old._digest(common_data.PAYLOAD),
            expected_collector_digest=self.collection["collector_digest"],
            expected_collection_source_pins=self.pins,
            expected_broker_source_pins=self.data.stage["binding_source_pins"],
            expected_boot_id=common_data.BOOT,
            scheduled_request=self.scheduled,
        )
        for row in self.measured["input_blobs"]:
            self.put(target.read(row["digest"]))
        self.measured_raw = canonical_json(self.measured)
        self.measured_pin = self.put(self.measured_raw)

    @property
    def claim(self):
        return (
            self.cas.root
            / subject.collector._PREPARED_CLAIMS
            / (self.collection["commitment_digest"][7:] + ".json")
        )

    def arguments(self, **updates):
        return {
            "collection_preparation_raw": self.collection_raw,
            "expected_collection_preparation_digest": self.collection_pin,
            "common_preparation_raw": self.built["preparation_raw"],
            "expected_common_preparation_digest": self.built["preparation_digest"],
            "measurement_prepared_raw": self.measured_raw,
            "expected_measurement_prepared_digest": self.measured_pin,
            "expected_binding_digest": self.measured["binding_digest"],
            "scheduled_request": deepcopy(self.scheduled),
            "provisioning_inputs": dict(self.data.inputs),
            "expected_container_id": common_data.CONTAINER,
            "expected_boot_id": common_data.BOOT,
            "protected_descriptor_raw": canonical_json(self.data.descriptor),
            "payload_raw": common_data.PAYLOAD,
            "evidence_cas": self.cas,
            "source_pins": dict(self.pins),
            **updates,
        }

    def provision(self, **arguments):
        # The OS effect is explicitly not performed. Return the exact fixed
        # public report shape, with inert stopped-unit observations.
        assert self.claim.exists(), "claim must be durable before provisioning"
        assert arguments["source_cas"].read_only is True
        return {
            "schema": "aragorn/native-measurement-provisioning/v1",
            "authority": "ROOT_PROVISIONED_INPUTS_ONLY_NOT_ACTIVATION_MEASUREMENT_OR_PHASE3",
            "prepared_digest": self.measured_pin,
            "binding_digest": self.measured["binding_digest"],
            "credential": str(subject.provisioning._CREDENTIAL),
            "input_store": str(subject.provisioning._STORE),
            "input_blobs": deepcopy(self.measured["input_blobs"]),
            "broker_uid": 1002,
            "broker_gid": 1004,
            "boot_id": common_data.BOOT,
            "stopped_units": {
                name: {
                    "unit": {
                        "Id": name,
                        "LoadState": "loaded",
                        "User": user,
                        "Group": group,
                        "KillMode": "control-group",
                        "Delegate": "no",
                        "Restart": "no",
                        "ActiveState": "inactive",
                        "SubState": "dead",
                        "MainPID": "0",
                        "ControlPID": "0",
                        "ControlGroup": "",
                    },
                    "cgroup": {
                        "path": f"/docker/{common_data.CONTAINER}/system.slice/{name}",
                        "status": "ABSENT",
                    },
                }
                for name, (user, group) in subject.provisioning._UNITS.items()
            },
            "payload_digest_expectation": self.measured["binding"]["payload_digest"],
            **dict.fromkeys(
                (
                    "payload_bytes_verified",
                    "activation_performed",
                    "measurement_collected",
                    "run_qualified",
                    "quantitative_metrics_eligible",
                    "phase3_exit_eligible",
                ),
                False,
            ),
            "limitations": [
                "CALLER_MUST_GUARD_OWNED_FIXTURE_BEFORE_LEGACY_SETUP_RESET",
                "POINT_IN_TIME_ROOT_CUSTODY_NOT_HOSTILE_ROOT_ATTESTATION",
                "NO_SERVICE_START_STOP_STATE_RESET_OR_EFFECT_RETRY",
                "PAYLOAD_DIGEST_IS_CALLER_EXPECTATION_NOT_RETAINED_PAYLOAD_BYTES",
                "NO_FULL_INGRESS_CLOCK_DOMAIN_ATTRIBUTION_OR_RESIDUE_QUALIFICATION",
            ],
        }


class NativeCommonMeasurementHandoffTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture(self)

    @contextmanager
    def harness(self, *, effect=None, stamp=300, fixture_guard=None):
        @contextmanager
        def owned(container, boot):
            self.assertEqual(container, common_data.CONTAINER)
            self.assertEqual(boot, common_data.BOOT)
            yield (lambda: None) if fixture_guard is None else fixture_guard

        with ExitStack() as stack:
            stack.enter_context(patch.object(subject, "_fixture", owned))
            stack.enter_context(
                patch.object(subject.collector, "_boottime_ns", return_value=stamp)
            )
            for name in (
                "prepare_phase3_measurement_collection",
                "collect_phase3_measurements",
                "collect_prepared_phase3_attempt",
                "_sample",
            ):
                stack.enter_context(
                    patch.object(
                        subject.collector,
                        name,
                        side_effect=AssertionError("no collection or regeneration"),
                    )
                )
            called = stack.enter_context(
                patch.object(
                    subject.provisioning,
                    "provision_runtime_native_measurement",
                    side_effect=self.fixture.provision if effect is None else effect,
                )
            )
            yield called

    def test_real_retained_composition_is_once_only_and_not_callback_execution(self):
        calls = []
        codes = {function.__code__ for function in self.fixture.functions.values()}

        def profile(frame, event, argument):
            if event == "call" and frame.f_code in codes:
                calls.append(frame.f_code.co_name)

        previous = sys.getprofile()
        sys.setprofile(profile)
        try:
            with self.harness() as provision, ExitStack() as owner:
                session = owner.enter_context(
                    subject.hold_prepared_native_common_measurement(
                        **self.fixture.arguments()
                    )
                )
                session.guard()
                report = session.report
                self.assertEqual(
                    report["commitment_digest"],
                    self.fixture.collection["commitment_digest"],
                )
                self.assertEqual(report["claimed_boottime_ns"], 300)
                self.assertEqual(report["status"], "INPUTS_PROVISIONED_NOT_ACTIVATED")
                self.assertTrue(
                    all(value is False for value in report["decision"].values())
                )
                self.assertEqual(
                    session.request["measurement_binding_digest"],
                    self.fixture.measured["binding_digest"],
                )
                for raw in (
                    session.request_raw,
                    session.provisioning_raw,
                    session.report_raw,
                    session.claim_raw,
                ):
                    self.assertEqual(
                        self.fixture.cas.read(subject.common.old._digest(raw)), raw
                    )
                    self.assertNotIn(
                        self.fixture.data.inputs[subject.common.old.live._GRANT], raw
                    )
                self.assertEqual(stat.S_IMODE(self.fixture.claim.stat().st_mode), 0o400)
                self.assertEqual(self.fixture.claim.stat().st_nlink, 1)
                session.report["decision"]["resumable"] = True
                self.assertIs(session.report["decision"]["resumable"], False)
                provision.assert_called_once()
            with self.assertRaisesRegex(
                subject.NativeCommonMeasurementHandoffError, "CLOSED"
            ):
                session.guard()
        finally:
            sys.setprofile(previous)
        self.assertEqual(calls, [])
        with (
            self.harness() as provision,
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                self.fail("claimed commitment was reused")
        provision.assert_not_called()

    def test_refuses_negative_task_changed_source_or_writer_before_claim(self):
        changes = [
            {"scheduled_request": {**self.fixture.scheduled, "negative_control": True}},
            {"scheduled_request": {**self.fixture.scheduled, "kind": "task"}},
            {"source_pins": {**self.fixture.pins, "execute": common_data.PIN}},
            {
                "provisioning_inputs": {
                    **self.fixture.data.inputs,
                    subject.common.old.live._GRANT: b"{}",
                }
            },
            {"payload_raw": b"changed"},
            {"expected_binding_digest": common_data.PIN},
            {"collection_preparation_raw": self.fixture.collection_raw + b"\n"},
        ]
        for change in changes:
            with (
                self.subTest(change=tuple(change)),
                self.harness() as provision,
                self.assertRaises(subject.NativeCommonMeasurementHandoffError),
            ):
                with subject.hold_prepared_native_common_measurement(
                    **self.fixture.arguments(**change)
                ):
                    self.fail("invalid inputs passed")
            self.assertFalse(self.fixture.claim.exists())
            provision.assert_not_called()

    def test_claim_clock_is_actual_bounded_and_not_old_preparation_stamp(self):
        for stamp in (True, 199, 2**63):
            with (
                self.subTest(stamp=stamp),
                self.harness(stamp=stamp) as provision,
                self.assertRaises(subject.NativeCommonMeasurementHandoffError),
            ):
                with subject.hold_prepared_native_common_measurement(
                    **self.fixture.arguments()
                ):
                    self.fail("invalid clock passed")
            provision.assert_not_called()
            self.assertFalse(self.fixture.claim.exists())

    def test_failed_provisioning_leaves_permanent_claim_and_no_retry(self):
        def fail(**arguments):
            self.assertTrue(self.fixture.claim.exists())
            raise RuntimeError("inert provision failure")

        with (
            self.harness(effect=fail) as provision,
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                self.fail("failed effect yielded")
        provision.assert_called_once()
        self.assertTrue(self.fixture.claim.exists())
        with (
            self.harness() as second,
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                self.fail("failed effect retried")
        second.assert_not_called()

    def test_interruption_preserves_claim_and_propagates(self):
        with self.harness(), self.assertRaises(KeyboardInterrupt):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                raise KeyboardInterrupt("inert caller interruption")
        self.assertTrue(self.fixture.claim.exists())
        with (
            self.harness() as provision,
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                self.fail("interrupted commitment retried")
        provision.assert_not_called()

    def test_provision_failure_attempts_independent_final_checks_and_keeps_primary(
        self,
    ):
        primary = RuntimeError("inert primary provisioning failure")
        failed = False
        reads_after_failure = []
        fixture_checks = []
        original_read = CAS.read

        def read(store, pin, *, max_bytes=1024 * 1024):
            if failed:
                reads_after_failure.append(pin)
                if pin == self.fixture.grant_pin:
                    raise CASError("inert independent private custody failure")
            return original_read(store, pin, max_bytes=max_bytes)

        def effect(**arguments):
            nonlocal failed
            self.fixture.provision(**arguments)
            self.fixture.claim.chmod(0o444)
            failed = True
            raise primary

        def fixture_guard():
            if failed:
                fixture_checks.append("after_failure")

        with (
            self.harness(effect=effect, fixture_guard=fixture_guard),
            patch.object(CAS, "read", new=read),
            self.assertRaises(subject.NativeCommonMeasurementHandoffError) as caught,
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                self.fail("failed provisioning yielded")
        self.assertIs(caught.exception.__cause__, primary)
        self.assertIn("HANDOFF_FINAL_CLAIM_CHECK_FAILED", primary.__notes__)
        self.assertIn("HANDOFF_FINAL_REQUEST_CHECK_FAILED", primary.__notes__)
        self.assertIn("HANDOFF_FINAL_PRIVATE_INPUT_CHECK_FAILED", primary.__notes__)
        self.assertIn(self.fixture.collection_pin, reads_after_failure)
        self.assertIn(
            subject.common.old._digest(self.fixture.claim.read_bytes()),
            reads_after_failure,
        )
        self.assertEqual(fixture_checks, ["after_failure"])
        self.assertTrue(self.fixture.claim.exists())
        with (
            self.harness() as provision,
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                self.fail("failed commitment retried")
        provision.assert_not_called()

    def test_second_valid_bound_request_cannot_bypass_commitment_claim(self):
        with (
            self.harness(),
            subject.hold_prepared_native_common_measurement(**self.fixture.arguments()),
        ):
            pass
        self.fixture.rebind("attempt-002")
        with (
            self.harness() as provision,
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                self.fail("second request bypassed commitment claim")
        provision.assert_not_called()

    def test_generic_and_native_paths_share_the_permanent_claim_namespace(self):
        claim = {
            "commitment_digest": self.fixture.collection["commitment_digest"],
            "state": "INERT_ALREADY_CLAIMED",
        }
        with subject.collector._prepared_attempt_claim(self.fixture.cas, claim):
            pass
        with (
            self.harness() as provision,
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                self.fail("existing claim bypassed")
        provision.assert_not_called()

    def test_public_output_loss_at_final_guard_refuses(self):
        with (
            self.harness(),
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ) as session:
                pin = session.report_digest
                (
                    self.fixture.cas.root / "blobs" / "sha256" / pin[7:9] / pin[9:]
                ).unlink()
        self.assertTrue(self.fixture.claim.exists())

    def test_private_input_loss_at_final_guard_refuses(self):
        with (
            self.harness(),
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                pin = self.fixture.grant_pin
                (
                    self.fixture.cas.root / "blobs" / "sha256" / pin[7:9] / pin[9:]
                ).unlink()
        self.assertTrue(self.fixture.claim.exists())

    def test_claim_replacement_during_caller_body_refuses(self):
        with (
            self.harness(),
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                raw = self.fixture.claim.read_bytes()
                self.fixture.claim.unlink()
                self.fixture.claim.write_bytes(raw)
                self.fixture.claim.chmod(0o400)

    def test_caller_pin_and_request_mutations_do_not_alias_held_state(self):
        arguments = self.fixture.arguments()
        with (
            self.harness(),
            subject.hold_prepared_native_common_measurement(**arguments) as session,
        ):
            arguments["source_pins"]["execute"] = common_data.PIN
            arguments["scheduled_request"]["attempt_id"] = "changed"
            arguments["provisioning_inputs"].clear()
            session.guard()
            self.assertEqual(
                session.report["scheduled_request"], self.fixture.scheduled
            )

    def test_source_custody_loss_after_provision_refuses_before_yield(self):
        original = subject.collector._source

        def effect(**arguments):
            result = self.fixture.provision(**arguments)
            self.source_lost = True
            return result

        self.source_lost = False

        def source(function, pin):
            if self.source_lost:
                raise subject.collector.Phase3MeasurementCollectionError(
                    "inert source loss"
                )
            return original(function, pin)

        with (
            self.harness(effect=effect),
            patch.object(subject.collector, "_source", side_effect=source),
            self.assertRaises(subject.NativeCommonMeasurementHandoffError),
        ):
            with subject.hold_prepared_native_common_measurement(
                **self.fixture.arguments()
            ):
                self.fail("source custody loss yielded")
        self.assertTrue(self.fixture.claim.exists())

    def test_exact_linux_root_container_and_boot_guard(self):
        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0)
        with ExitStack() as stack:
            stack.enter_context(patch.object(subject.sys, "platform", "linux"))
            stack.enter_context(patch.object(subject.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(subject.os, "getegid", return_value=0))
            stack.enter_context(patch.object(subject.os, "open", return_value=42))
            close = stack.enter_context(patch.object(subject.os, "close"))
            stack.enter_context(
                patch.object(subject.os, "fstat", return_value=metadata)
            )
            stack.enter_context(patch.object(Path, "lstat", return_value=metadata))
            stack.enter_context(
                patch.object(
                    subject.provisioning.broker, "_file_identity", return_value=(1, 2)
                )
            )
            raw = stack.enter_context(
                patch.object(
                    subject.os,
                    "pread",
                    return_value=f"0::/docker/{common_data.CONTAINER}/init.scope\n".encode(),
                )
            )
            boot = stack.enter_context(
                patch.object(
                    subject.provisioning, "_boot_id", return_value=common_data.BOOT
                )
            )
            with subject._fixture(common_data.CONTAINER, common_data.BOOT) as guard:
                guard()
            close.assert_called_once_with(42)
            raw.return_value = b"0::/other/init.scope\n"
            with self.assertRaises(subject.NativeCommonMeasurementHandoffError):
                with subject._fixture(common_data.CONTAINER, common_data.BOOT):
                    self.fail("wrong container passed")
            raw.return_value = (
                f"0::/docker/{common_data.CONTAINER}/init.scope\n".encode()
            )
            boot.return_value = "00000000-0000-0000-0000-000000000002"
            with self.assertRaises(subject.NativeCommonMeasurementHandoffError):
                with subject._fixture(common_data.CONTAINER, common_data.BOOT):
                    self.fail("wrong boot passed")


if __name__ == "__main__":
    unittest.main()
