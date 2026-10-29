"""Only the new profiled-raw retention branch and its two-payload stage."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aragorn import runtime_action_broker as broker
from aragorn import runtime_action_broker_v4 as v4
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import stage_runtime_broker_measurement_receipt_profile as stage

PIN = "sha256:" + "1" * 64


def rendered_helper():
    raw = stage.base.overlay._read_pinned(
        stage._HELPER, *stage.renderer._ADDED[stage._HELPER], root=stage._ROOT
    )
    module = types.ModuleType("aragorn._new_receipt_retention_test")
    module.__package__ = "aragorn"
    with patch.dict(sys.modules, {module.__name__: module}):
        exec(compile(stage._render_helper(raw), stage._HELPER, "exec"), module.__dict__)  # noqa: S102 - exact frozen-source transform; service main is never executed
    return module


class BrokerMeasurementReceiptProfileTests(unittest.TestCase):
    def test_new_branch_keeps_exact_detached_bytes_and_refuses_new_failures(self):
        for mode in ("complete", "post-effect-storage-failure"):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory() as temporary,
                ExitStack() as stack,
            ):
                subject, root = rendered_helper(), Path(temporary)
                process = {
                    "boot_id": "00000000-0000-0000-0000-000000000001",
                    "uid": os.geteuid(),
                }
                request = {key: PIN for key in subject._MATCH}
                grant = {
                    key: PIN
                    for key in subject._MATCH - {"path_digest", "payload_digest"}
                }
                grant.update(runtime_profile_digest=PIN, sensor_digest=PIN)
                plan = {
                    **request,
                    "runtime_profile_digest": PIN,
                    "sensor_digest": PIN,
                    "grant_digest": canonical_digest(grant),
                    "boot_id": process["boot_id"],
                }
                legacy = {
                    "envelope": {"request": request},
                    "request_digest": canonical_digest(request),
                    "sensor_digest": PIN,
                }
                attribution, lease = {"profile_digest": PIN}, {"fixture": "inert lease"}
                profiled = {
                    **legacy,
                    "schema": "aragorn/runtime-observed-create-submission/v2",
                    "runtime_attribution": attribution,
                }
                expected_raw, expected_digest = (
                    canonical_json(profiled),
                    canonical_digest(profiled),
                )
                config = SimpleNamespace(
                    broker=SimpleNamespace(
                        broker=SimpleNamespace(
                            control_root=root,
                            expected_runtime_digest=PIN,
                            expected_broker_uid=os.geteuid(),
                        ),
                        expected_runtime_profile_digest=PIN,
                    )
                )
                state = {"value": {"status": "AVAILABLE"}}
                for name, value in (
                    ("_ROOT", root),
                    ("_OUTPUT", root / "decision-measurement-evidence"),
                    ("_PLAN", plan),
                    ("_PROCESS", process),
                ):
                    stack.enter_context(patch.object(subject, name, value))
                stack.enter_context(
                    patch.object(subject, "_identity", return_value=process)
                )
                stack.enter_context(
                    patch.object(subject, "_sources", return_value=None)
                )
                stack.enter_context(patch.object(subject, "_inputs", return_value=None))
                stack.enter_context(
                    patch.object(subject, "_stamp", side_effect=iter((10, 20, 30)))
                )

                def locked(config, deadline, function, root=root):
                    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        function(fd)
                    finally:
                        os.close(fd)

                stack.enter_context(
                    patch.object(v4, "_with_profile_lock", side_effect=locked)
                )
                stack.enter_context(
                    patch.object(
                        v4,
                        "_load_state",
                        side_effect=lambda *args, state=state: state["value"],
                    )
                )
                # New reconstruction must fail before durable pending/claim when
                # the supplied digest is not the validated v2 submission digest.
                with self.assertRaises(broker.RuntimeActionBrokerError):
                    subject.begin(config, grant, legacy, attribution, PIN, lease, None)
                self.assertFalse((root / subject._PENDING).exists())
                trace = subject.begin(
                    config, grant, legacy, attribution, expected_digest, lease, None
                )
                stack.callback(subject.close, trace)
                self.assertEqual(trace.profiled_submission_raw, expected_raw)
                legacy["envelope"]["request"]["payload_digest"] = "sha256:" + "2" * 64
                self.assertEqual(trace.profiled_submission_raw, expected_raw)
                decision = {"verdict": "ALLOW", "reason_codes": []}
                subject.final_decision(
                    legacy["request_digest"], PIN, decision, True, []
                )
                result = {
                    "request_digest": legacy["request_digest"],
                    "verdict": "ALLOW",
                    "reason_codes": [],
                    "observation_digest": PIN,
                    "decision": decision,
                    "effect_status": "CREATED",
                }
                claim = {
                    "grant_digest": plan["grant_digest"],
                    "lease_digest": canonical_digest(lease),
                }
                receipt = {
                    "broker_result": result,
                    "runtime_attribution_digest": canonical_digest(attribution),
                    "submission_digest": expected_digest,
                }
                record = {
                    "profile_result": {"broker_result_digest": canonical_digest(result)}
                }
                state["value"] = {
                    "status": "CONSUMED",
                    "claim": claim,
                    "result": record,
                }
                stack.enter_context(
                    patch.object(v4, "_load_profile_receipt", return_value=receipt)
                )
                stack.enter_context(
                    patch.object(v4, "_result_record", return_value=record)
                )
                if mode == "post-effect-storage-failure":
                    original_put = CAS.put_expected

                    def fail_new_blob(
                        store,
                        source,
                        *,
                        expected_digest: str,
                        max_bytes: int,
                        submission_pin=expected_digest,
                        original_put=original_put,
                    ):
                        if expected_digest == submission_pin:
                            raise CASError("inert new-submission write fault")
                        return original_put(
                            store,
                            source,
                            expected_digest=expected_digest,
                            max_bytes=max_bytes,
                        )

                    with (
                        patch.object(CAS, "put_expected", new=fail_new_blob),
                        self.assertRaises(broker.RuntimeActionEffectIndeterminate),
                    ):
                        subject.retain(trace, config, claim, result, None)
                    self.assertFalse((root / subject._COMPLETE).exists())
                else:
                    subject.retain(trace, config, claim, result, None)
                    store = CAS(subject._OUTPUT, read_only=True)
                    self.assertEqual(
                        store.read(expected_digest, max_bytes=subject._LIMIT),
                        expected_raw,
                    )
                    completed = broker._parse_canonical_document(
                        (root / subject._COMPLETE).read_bytes(), "new retention index"
                    )
                    retained = broker._parse_canonical_document(
                        store.read(completed["evidence_digest"]),
                        "new retained evidence",
                    )
                    self.assertEqual(
                        retained["pending"]["submission_digest"], expected_digest
                    )
                    self.assertFalse(
                        retained["decision"]["quantitative_metrics_eligible"]
                    )
                self.assertTrue((root / subject._PENDING).exists())
                self.assertEqual(state["value"]["status"], "CONSUMED")

    def test_successor_stages_exactly_two_changed_payloads_and_new_helper_pin(self):
        frozen_names = (stage._HELPER, stage._PARENT, stage.predecessor._RENDERER)
        before = {name: (stage._ROOT / name).read_bytes() for name in frozen_names}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "receipt-profile"
            report = stage.stage_runtime_broker_measurement_receipt_profile(output)
            original, replacements = stage._verified_payloads()
            self.assertEqual(len(report["files"]), 73)
            self.assertEqual(len(replacements), 2)
            self.assertEqual(report["schema"], stage._SCHEMA)
            self.assertIs(report["profiled_submission_retention_staged"], True)
            for key in (
                "decision_measurement_deployed",
                "measurement_collected",
                "phase3_qualification",
                "run_qualification",
            ):
                self.assertIs(report[key], False)
            helper_destination, _ = stage.renderer.predecessor._destination(
                stage._HELPER
            )
            activator_destination, _ = stage.renderer.predecessor._destination(
                stage._ACTIVATOR
            )
            helper = (output / helper_destination).read_bytes()
            self.assertEqual(
                (len(helper), stage.base.overlay._digest(helper)),
                stage._OUTPUTS[stage._HELPER],
            )
            self.assertEqual(
                report["binding_source_pins"][Path(stage._HELPER).name],
                stage._OUTPUTS[stage._HELPER][1],
            )
            compile(helper, helper_destination, "exec")
            activator = (output / activator_destination).read_bytes()
            self.assertIn(stage._OUTPUTS[stage._HELPER][1][7:].encode(), activator)
            self.assertNotIn(
                stage.renderer._ADDED[stage._HELPER][1][7:].encode(), activator
            )
            checked = subprocess.run(
                ["/bin/sh", "-n", str(output / activator_destination)],
                capture_output=True,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr.decode())
            for destination, (_, _, raw) in original.items():
                if destination not in replacements:
                    self.assertEqual((output / destination).read_bytes(), raw)
        self.assertEqual(
            before, {name: (stage._ROOT / name).read_bytes() for name in frozen_names}
        )
        with self.assertRaises(stage.BrokerMeasurementReceiptStageError):
            stage._render_helper(before[stage._HELPER] + b"\n")


if __name__ == "__main__":
    unittest.main()
