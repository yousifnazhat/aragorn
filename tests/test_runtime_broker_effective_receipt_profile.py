"""Inert effective-receipt contract/retention tests; no workload or service runs."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import aragorn
from aragorn import runtime_action_broker as broker
from aragorn import runtime_action_broker_v4 as frozen_v4
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import stage_runtime_broker_effective_receipt_profile as stage

PIN = "sha256:" + "a" * 64


def rendered_modules():
    original, replacements = stage._verified_payloads()
    payloads = original | replacements
    modules = []
    for name in (stage._GRANT, stage._HELPER):
        destination, _ = stage.renderer.predecessor._destination(name)
        module = types.ModuleType("aragorn._effective_receipt_test_" + Path(name).stem)
        module.__package__ = "aragorn"
        with patch.dict(sys.modules, {module.__name__: module}):
            exec(compile(payloads[destination][2], name, "exec"), module.__dict__)  # noqa: S102 - exact-pinned definitions only, no service entrypoint
        modules.append(module)
    return tuple(modules)


def receipt_fixture(mode="mixed"):
    request = {
        key: PIN
        for key in (
            "runtime_digest",
            "policy_digest",
            "active_skill_digest",
            "operation_digest",
            "path_digest",
            "payload_digest",
        )
    }
    attribution = {"profile_digest": PIN}
    legacy = {
        "envelope": {"request": request},
        "request_digest": canonical_digest(request),
        "sensor_digest": PIN,
    }
    profiled = {
        **legacy,
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "runtime_attribution": attribution,
    }
    grant = {
        **{
            key: value
            for key, value in request.items()
            if key not in {"path_digest", "payload_digest"}
        },
        "runtime_profile_digest": PIN,
        "sensor_digest": PIN,
    }
    lease = {"inert": "single-use lease"}
    profile_claim = {
        "lease_digest": canonical_digest(lease),
        "submission_digest": canonical_digest(profiled),
        "runtime_attribution_digest": canonical_digest(attribution),
        "profile_pending": {"runtime_attribution": attribution},
        "request_digest": canonical_digest(request),
        "target_name": "inert.txt",
    }
    claim = {
        "grant_digest": canonical_digest(grant),
        "lease_digest": canonical_digest(lease),
        "profile_claim": profile_claim,
    }
    decision = {
        "schema": "aragorn/runtime-action-decision/v1",
        "authority": "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
        "request_digest": canonical_digest(request),
        "verdict": "BLOCK" if mode == "policy" else "ALLOW",
        "reason_codes": ["ACTION_NOT_ALLOWED"] if mode == "policy" else [],
    }
    reasons = {
        "mixed": ["BROKER_SENSOR_PIN_MISMATCH"],
        "policy": ["ACTION_NOT_ALLOWED"],
        "replay": ["BROKER_REPLAY_BLOCKED"],
        "allow": [],
    }[mode]
    result = {
        "schema": "aragorn/runtime-action-broker-result/v1",
        "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "request_digest": canonical_digest(request),
        "observation_digest": PIN,
        "target_name": "inert.txt",
        "verdict": "ALLOW" if mode == "allow" else "BLOCK",
        "reason_codes": reasons,
        "effect_status": "CREATED" if mode == "allow" else "NOT_PERFORMED",
        "decision": None if mode == "replay" else decision,
    }
    receipt = {
        "schema": "aragorn/runtime-process-profile-receipt/v1",
        "authority": "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
        "submission_digest": canonical_digest(profiled),
        "runtime_attribution": attribution,
        "runtime_attribution_digest": canonical_digest(attribution),
        "broker_result": result,
        "broker_result_digest": canonical_digest(result),
    }
    return SimpleNamespace(
        request=request,
        attribution=attribution,
        legacy=legacy,
        profiled=profiled,
        grant=grant,
        lease=lease,
        claim=claim,
        result=result,
        receipt=receipt,
    )


def rebind(fixture):
    fixture.receipt["broker_result_digest"] = canonical_digest(fixture.result)


class BrokerEffectiveReceiptProfileTests(unittest.TestCase):
    def test_recorded_policy_and_effective_outcomes_are_separate(self):
        grant, _ = rendered_modules()
        for mode in ("allow", "policy", "mixed", "replay"):
            with self.subTest(mode=mode):
                fixture = receipt_fixture(mode)
                record = grant._result_record(fixture.claim, fixture.receipt)
                self.assertEqual(
                    record["profile_result"]["verdict"], fixture.result["verdict"]
                )
                self.assertEqual(
                    record["profile_result"]["broker_result_digest"],
                    canonical_digest(fixture.result),
                )
                self.assertEqual(
                    record["profile_result"]["profile_receipt_digest"],
                    canonical_digest(fixture.receipt),
                )
                if mode in {"mixed", "replay"}:
                    with self.assertRaises(broker.RuntimeActionBrokerError):
                        frozen_v4._result_record(fixture.claim, fixture.receipt)
        reasons = (
            ["BROKER_RUNTIME_PIN_MISMATCH"],
            ["BROKER_SENSOR_PIN_MISMATCH"],
            ["BROKER_EFFECT_MEASUREMENT_MISMATCH"],
            ["BROKER_EFFECT_BINDING_MISMATCH"],
            ["BROKER_EFFECT_BINDING_MISMATCH", "BROKER_SENSOR_PIN_MISMATCH"],
            ["BROKER_CLOCK_ROLLBACK"],
            ["BROKER_CLOCK_UNSTABLE"],
            ["BROKER_CLAIM_STATE_CHANGED"],
            ["BROKER_DEADLINE_EXPIRED"],
        )
        for policy in ("ALLOW", "BLOCK"):
            for codes in reasons:
                with self.subTest(policy=policy, codes=codes):
                    fixture = receipt_fixture("mixed")
                    fixture.result["decision"].update(
                        verdict=policy,
                        reason_codes=[]
                        if policy == "ALLOW"
                        else ["ACTION_NOT_ALLOWED"],
                    )
                    fixture.result["reason_codes"] = codes
                    rebind(fixture)
                    self.assertEqual(
                        grant._result_record(fixture.claim, fixture.receipt)[
                            "profile_result"
                        ]["verdict"],
                        "BLOCK",
                    )

    def test_unbound_or_unsupported_effective_claims_are_refused(self):
        grant, _ = rendered_modules()
        for mode in (
            "none-non-replay",
            "none-allow",
            "dict-replay",
            "policy-broker-replay",
            "unknown",
            "mixed-reasons",
            "duplicate",
            "unsorted",
            "created-block",
            "allow-policy-block",
            "policy-reason-shape",
            "request",
            "target",
            "observation",
            "receipt-hash",
            "attribution",
            "extra-field",
        ):
            with self.subTest(mode=mode):
                fixture = receipt_fixture("mixed")
                result = fixture.result
                if mode == "none-non-replay":
                    result["decision"] = None
                elif mode == "none-allow":
                    result.update(
                        decision=None,
                        verdict="ALLOW",
                        reason_codes=[],
                        effect_status="CREATED",
                    )
                elif mode == "dict-replay":
                    result["reason_codes"] = ["BROKER_REPLAY_BLOCKED"]
                elif mode == "policy-broker-replay":
                    result["reason_codes"] = ["BROKER_REPLAY_BLOCKED"]
                    result["decision"].update(
                        verdict="BLOCK", reason_codes=result["reason_codes"]
                    )
                elif mode == "unknown":
                    result["reason_codes"] = ["BROKER_UNKNOWN"]
                elif mode == "mixed-reasons":
                    result["reason_codes"] = [
                        "BROKER_CLOCK_ROLLBACK",
                        "BROKER_SENSOR_PIN_MISMATCH",
                    ]
                elif mode == "duplicate":
                    result["reason_codes"] *= 2
                elif mode == "unsorted":
                    result["reason_codes"] = [
                        "BROKER_SENSOR_PIN_MISMATCH",
                        "BROKER_EFFECT_BINDING_MISMATCH",
                    ]
                elif mode == "created-block":
                    result["effect_status"] = "CREATED"
                elif mode == "allow-policy-block":
                    result.update(
                        verdict="ALLOW", effect_status="CREATED", reason_codes=[]
                    )
                    result["decision"].update(
                        verdict="BLOCK", reason_codes=["ACTION_NOT_ALLOWED"]
                    )
                elif mode == "policy-reason-shape":
                    result["decision"]["reason_codes"] = ["not canonical"]
                elif mode == "request":
                    result["decision"]["request_digest"] = "sha256:" + "b" * 64
                elif mode == "target":
                    result["target_name"] = "another.txt"
                elif mode == "observation":
                    result["observation_digest"] = None
                elif mode == "attribution":
                    fixture.receipt["runtime_attribution"] = {}
                elif mode == "extra-field":
                    result["run_eligible"] = True
                rebind(fixture)
                if mode == "receipt-hash":
                    fixture.receipt["broker_result_digest"] = PIN
                with self.assertRaises(broker.RuntimeActionBrokerError):
                    grant._result_record(fixture.claim, fixture.receipt)

    def _retention_fixture(self, stack, root, mode):
        grant, helper = rendered_modules()
        fixture = receipt_fixture(mode)
        process = {
            "boot_id": "00000000-0000-0000-0000-000000000001",
            "uid": os.geteuid(),
        }
        plan = {
            **fixture.request,
            "runtime_profile_digest": PIN,
            "sensor_digest": PIN,
            "grant_digest": canonical_digest(fixture.grant),
            "boot_id": process["boot_id"],
        }
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
            stack.enter_context(patch.object(helper, name, value))
        for name, value in (
            ("_identity", process),
            ("_sources", None),
            ("_inputs", None),
        ):
            stack.enter_context(patch.object(helper, name, return_value=value))
        stack.enter_context(patch.object(helper, "_stamp", side_effect=(10, 20)))
        stack.enter_context(patch.object(aragorn, "runtime_action_broker_v4", grant))

        def locked(config, deadline, function):
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                function(fd)
            finally:
                os.close(fd)

        stack.enter_context(
            patch.object(grant, "_with_profile_lock", side_effect=locked)
        )
        stack.enter_context(
            patch.object(grant, "_load_state", side_effect=lambda *args: state["value"])
        )
        stack.enter_context(
            patch.object(grant, "_load_profile_receipt", return_value=fixture.receipt)
        )
        stack.enter_context(
            patch.object(grant, "_require_no_pending_at", return_value=None)
        )
        publish = stack.enter_context(
            patch.object(
                grant,
                "_publish_state",
                side_effect=lambda fd, config, value: state.update(
                    value=deepcopy(value)
                ),
            )
        )
        trace = helper.begin(
            config,
            fixture.grant,
            fixture.legacy,
            fixture.attribution,
            canonical_digest(fixture.profiled),
            fixture.lease,
            None,
        )
        stack.callback(helper.close, trace)
        state["value"] = {"status": "CLAIMED", "claim": fixture.claim, "result": None}
        helper.final_decision(
            fixture.result["request_digest"],
            PIN,
            fixture.result["decision"],
            mode == "allow",
            fixture.result["reason_codes"],
        )
        return fixture, grant, helper, config, state, trace, publish

    def test_real_successor_consume_and_retention_complete_mixed_and_replay(self):
        for mode in ("mixed", "replay"):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory() as temporary,
                ExitStack() as stack,
            ):
                root = Path(temporary).resolve()
                fixture, grant, helper, config, state, trace, publish = (
                    self._retention_fixture(stack, root, mode)
                )
                grant._consume_grant(config, fixture.claim, fixture.result, None)
                self.assertEqual(state["value"]["status"], "CONSUMED")
                publish.assert_called_once()
                helper.retain(trace, config, fixture.claim, fixture.result, None)
                completion = broker._parse_canonical_document(
                    (root / helper._COMPLETE).read_bytes(), "inert completion"
                )
                self.assertEqual(completion["schema"], stage.COMPLETION_SCHEMA)
                store = CAS(helper._OUTPUT, read_only=True)
                evidence = broker._parse_canonical_document(
                    store.read(completion["evidence_digest"]), "inert evidence"
                )
                self.assertEqual(evidence["schema"], stage.EVIDENCE_SCHEMA)
                self.assertIn(stage.EFFECTIVE_LIMIT, evidence["limitations"])
                self.assertNotIn(stage._OLD_LIMIT, evidence["limitations"])
                self.assertTrue(
                    all(value is False for value in evidence["decision"].values())
                )
                self.assertEqual(
                    evidence["effective_final_decision"]["policy_decision_digest"],
                    None
                    if mode == "replay"
                    else canonical_digest(fixture.result["decision"]),
                )
                self.assertEqual(
                    store.read(canonical_digest(fixture.profiled)),
                    canonical_json(fixture.profiled),
                )
                self.assertTrue((root / helper._PENDING).exists())
                self.assertEqual(
                    evidence["pending"]["schema"],
                    "aragorn/runtime-broker-decision-measurement-pending/v1",
                )
                self.assertEqual(
                    evidence["pending"]["acceptance_boundary"],
                    "V4_ISSUED_SUBMISSION_VALIDATED_BEFORE_GRANT_CLAIM",
                )

    def test_failed_consumption_keeps_claim_and_pending_without_completion(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary).resolve()
            fixture, grant, helper, config, state, trace, publish = (
                self._retention_fixture(stack, root, "mixed")
            )
            fixture.result["reason_codes"] = ["BROKER_UNKNOWN"]
            rebind(fixture)
            with self.assertRaises(broker.RuntimeActionBrokerError):
                grant._consume_grant(config, fixture.claim, fixture.result, None)
            publish.assert_not_called()
            self.assertEqual(state["value"]["status"], "CLAIMED")
            self.assertTrue((root / helper._PENDING).exists())
            self.assertFalse((root / helper._COMPLETE).exists())
            self.assertFalse(helper._OUTPUT.exists())

    def test_retention_failure_never_restores_authority_or_loses_pending(self):
        for mode in ("mixed", "allow"):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory() as temporary,
                ExitStack() as stack,
            ):
                root = Path(temporary).resolve()
                fixture, grant, helper, config, state, trace, publish = (
                    self._retention_fixture(stack, root, mode)
                )
                grant._consume_grant(config, fixture.claim, fixture.result, None)
                original_put = CAS.put_expected

                def fail_profile(store, source, *, expected_digest, max_bytes):
                    if expected_digest == canonical_digest(fixture.profiled):
                        raise CASError("inert retention fault")
                    return original_put(
                        store,
                        source,
                        expected_digest=expected_digest,
                        max_bytes=max_bytes,
                    )

                with patch.object(CAS, "put_expected", new=fail_profile):
                    expected = (
                        broker.RuntimeActionEffectIndeterminate
                        if mode == "allow"
                        else broker.RuntimeActionBrokerError
                    )
                    with self.assertRaises(expected):
                        helper.retain(
                            trace, config, fixture.claim, fixture.result, None
                        )
                publish.assert_called_once()
                self.assertEqual(state["value"]["status"], "CONSUMED")
                self.assertTrue((root / helper._PENDING).exists())
                self.assertFalse((root / helper._COMPLETE).exists())
                self.assertTrue(helper._OUTPUT.exists())

    def test_exact_three_payload_stage_preserves_predecessors_and_binding_api(self):
        names = (
            stage._PROFILE,
            stage._GRANT,
            stage._HELPER,
            stage._PARENT,
            stage.renderer._PARENT,
        )
        before = {name: (stage._ROOT / name).read_bytes() for name in names}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "effective-profile"
            report = stage.stage_runtime_broker_effective_receipt_profile(output)
            original, replacements = stage._verified_payloads()
            self.assertEqual(len(report["files"]), 73)
            self.assertEqual(len(replacements), 3)
            self.assertEqual(report["schema"], stage._SCHEMA)
            self.assertIs(report["effective_block_receipt_staged"], True)
            for key in (
                "decision_measurement_deployed",
                "measurement_binding_provisioned",
                "measurement_collected",
                "phase3_qualification",
                "run_qualification",
            ):
                self.assertIs(report[key], False)
            self.assertEqual(
                set(report["binding_source_pins"]),
                {
                    "runtime_action_broker.py",
                    "runtime_action_broker_v4.py",
                    "runtime_action_broker_v5.py",
                    "runtime_action_service_v5.py",
                    "runtime_broker_decision_measurement.py",
                    "phase3_deployment.py",
                    "phase3_quantitative_metrics.py",
                },
            )
            for name in (stage._GRANT, stage._HELPER):
                self.assertEqual(
                    report["binding_source_pins"][Path(name).name],
                    stage._OUTPUTS[name][1],
                )
            for destination, (_, _, raw) in original.items():
                self.assertEqual(
                    (output / destination).read_bytes(),
                    replacements.get(destination, original[destination])[2],
                )
            activator = (
                output / stage.renderer.predecessor._destination(stage._ACTIVATOR)[0]
            )
            script = activator.read_bytes()
            for name in (stage._GRANT, stage._HELPER):
                self.assertIn(stage._OUTPUTS[name][1][7:].encode(), script)
            checked = subprocess.run(
                ["/bin/sh", "-n", str(activator)],
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr.decode())
            with self.assertRaises(stage.BrokerEffectiveReceiptStageError):
                stage.stage_runtime_broker_effective_receipt_profile(output)
        self.assertEqual(
            before, {name: (stage._ROOT / name).read_bytes() for name in names}
        )
        with self.assertRaises(stage.BrokerEffectiveReceiptStageError):
            stage._render_grant(b"changed", before[stage._PROFILE])
        with self.assertRaises(stage.BrokerEffectiveReceiptStageError):
            stage._render_helper(b"changed")


if __name__ == "__main__":
    unittest.main()
