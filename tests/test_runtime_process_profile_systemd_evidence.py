from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_process_profile_systemd_evidence as verifier
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_decision import evaluate_runtime_action

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "runtime-process-profile-systemd-composition-p3-4a-2026-08-05.json"
)
_RAW_DIGEST = "87dc7dd7efda55d6271a041726bc9f387446d5eda5ae407fbeec13bf0ef7f14d"
_ZERO_DIGEST = "sha256:" + "0" * 64


def _set(*path: str, value: object):
    def mutate(document: dict) -> None:
        current = document
        for name in path[:-1]:
            current = current[name]
        current[path[-1]] = value

    return mutate


def _remove_limitation(document: dict) -> None:
    document["limitations"].pop()


def _remove_artifact(document: dict) -> None:
    document["artifacts"].pop()


def _break_submission_binding(document: dict) -> None:
    receipt = document["scenarios"]["profiled_allow"]["receipt"]
    receipt["document"]["submission_digest"] = _ZERO_DIGEST
    receipt["digest"] = canonical_digest(receipt["document"])


def _break_broker_result_binding(document: dict) -> None:
    receipt = document["scenarios"]["profiled_allow"]["receipt"]
    result = receipt["document"]["broker_result"]
    result["target_name"] = "forged.txt"
    receipt["document"]["broker_result_digest"] = canonical_digest(result)
    receipt["digest"] = canonical_digest(receipt["document"])


def _forge_allow_decision(field: str, value: object):
    def mutate(document: dict) -> None:
        scenario = document["scenarios"]["profiled_allow"]
        response = scenario["client"]["response"]
        replacement = value(response["decision"][field]) if callable(value) else value
        response["decision"][field] = replacement
        receipt = scenario["receipt"]
        receipt["document"]["broker_result"] = deepcopy(response)
        receipt["document"]["broker_result_digest"] = canonical_digest(response)
        receipt["digest"] = canonical_digest(receipt["document"])
        raw = canonical_json(receipt["document"])
        scenario["receipt_file"]["digest"] = receipt["digest"]
        scenario["receipt_file"]["bytes"] = len(raw)
        scenario["receipt_file"]["stat"]["size"] = len(raw)
        for controls in (
            scenario["control_after"],
            document["scenarios"]["wrong_cgroup"]["control_before"],
            document["scenarios"]["wrong_cgroup"]["control_after"],
        ):
            controls["profile-receipt.json"] = receipt["digest"]

    return mutate


def _forge_initial_control(name: str, *path: str, value: object):
    def mutate(document: dict) -> None:
        control = document["inputs"]["initial_controls"][name]
        current = control
        for field in path[:-1]:
            current = current[field]
        current[path[-1]] = value
        document["inputs"]["control_baseline"][f"{name}.json"] = canonical_digest(
            control
        )

    return mutate


def _refresh_receipt(document: dict) -> None:
    scenario = document["scenarios"]["profiled_allow"]
    receipt = scenario["receipt"]
    receipt["digest"] = canonical_digest(receipt["document"])
    raw = canonical_json(receipt["document"])
    scenario["receipt_file"].update(digest=receipt["digest"], bytes=len(raw))
    scenario["receipt_file"]["stat"]["size"] = len(raw)
    for controls in (
        scenario["control_after"],
        document["scenarios"]["wrong_cgroup"]["control_before"],
        document["scenarios"]["wrong_cgroup"]["control_after"],
    ):
        controls["profile-receipt.json"] = receipt["digest"]


def _forge_profiled_client_pid(document: dict) -> None:
    scenario = document["scenarios"]["profiled_allow"]
    client = scenario["client"]["client"]
    client["pid"] = 999999
    receipt = scenario["receipt"]["document"]
    attribution = receipt["runtime_attribution"]
    attribution["pid"] = client["pid"]
    receipt["runtime_attribution_digest"] = canonical_digest(attribution)
    envelope = document["inputs"]["envelopes"]["allow"]
    request = envelope["request"]
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{
            key: request[key]
            for key in (
                "runtime_digest",
                "active_skill_digest",
                "run_id",
                "session_id",
                "tool_call_id",
            )
        },
        **document["inputs"]["actions"]["allow"],
    }
    submission = {
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": document["inputs"]["policy"]["sensor_digest"],
        "envelope_digest": canonical_digest(envelope),
        "request_digest": canonical_digest(request),
        "runtime_peer": {key: client[key] for key in ("pid", "uid", "gid")},
        "measured_action": measured,
        "envelope": envelope,
        "runtime_attribution": attribution,
    }
    receipt["submission_digest"] = canonical_digest(submission)
    _refresh_receipt(document)


def _coherent_zero_operation(document: dict) -> None:
    zero = _ZERO_DIGEST
    inputs = document["inputs"]
    for action in inputs["actions"].values():
        action["operation_digest"] = zero

    policy = inputs["policy"]
    for rule in policy["allow"]:
        rule["operation_digest"] = zero
    policy["allow"].sort(key=canonical_json)
    inputs["initial_controls"]["policy"] = deepcopy(policy)
    policy_digest = canonical_digest(policy)
    for envelope in inputs["envelopes"].values():
        envelope["request"]["operation_digest"] = zero
        envelope["request"]["policy_digest"] = policy_digest

    initial = inputs["initial_controls"]
    initial["observation"]["measured_action"]["operation_digest"] = zero
    for name, control in initial.items():
        inputs["control_baseline"][f"{name}.json"] = canonical_digest(control)

    allow = document["scenarios"]["profiled_allow"]
    wrong = document["scenarios"]["wrong_cgroup"]
    for name, scenario in (("allow", allow), ("wrong_cgroup", wrong)):
        envelope = inputs["envelopes"][name]
        raw = canonical_json(envelope)
        scenario["client"].update(
            request_bytes=len(raw),
            request_digest=canonical_digest(envelope),
            request_file_digest=canonical_digest(envelope),
        )

    response = allow["client"]["response"]
    request = inputs["envelopes"]["allow"]["request"]
    now = response["decision"]["evaluated_at_unix"]
    active = {
        "schema": "aragorn/runtime-active-context/v1",
        **{
            key: request[key]
            for key in (
                "runtime_digest",
                "session_id",
                "run_id",
                "tool_call_id",
                "active_skill_digest",
            )
        },
    }
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{key: value for key, value in active.items() if key != "schema"},
        **inputs["actions"]["allow"],
    }
    health = {
        "schema": "aragorn/runtime-mediator-health/v1",
        "runtime_digest": request["runtime_digest"],
        "sensor_digest": policy["sensor_digest"],
        "epoch": 2,
        "status": "healthy",
        "observed_at_unix": now,
        "expires_at_unix": now + 5,
    }
    observation = {
        "schema": "aragorn/runtime-action-observation/v1",
        "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
        "sequence": 2,
        "sensor_digest": policy["sensor_digest"],
        "observed_at_unix": now,
        "expires_at_unix": now + 5,
        "active": active,
        "measured_action": measured,
    }
    state = {
        "schema": "aragorn/runtime-action-broker-state/v2",
        "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
        "minimum_revocation_generation": 1,
        "minimum_mediator_health_epoch": 2,
        "consumed": [
            {
                "request_digest": canonical_digest(request),
                "observation_digest": canonical_digest(observation),
                "expires_at_unix": now + 5,
            }
        ],
        "effect_journal": None,
    }
    response.update(
        request_digest=canonical_digest(request),
        observation_digest=canonical_digest(observation),
        decision=evaluate_runtime_action(
            request,
            policy,
            now_unix=now,
            active=active,
            measured_action=measured,
            revocations=initial["revocations"],
            minimum_revocation_generation=1,
            mediator_health=health,
            minimum_mediator_health_epoch=2,
        ),
    )
    controls = {
        "policy.json": policy_digest,
        "revocations.json": canonical_digest(initial["revocations"]),
        "health.json": canonical_digest(health),
        "observation.json": canonical_digest(observation),
        "state.json": canonical_digest(state),
    }
    allow["control_after"].update(controls)
    receipt = allow["receipt"]["document"]
    receipt["broker_result"] = deepcopy(response)
    receipt["broker_result_digest"] = canonical_digest(response)
    attribution = receipt["runtime_attribution"]
    submission = {
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": policy["sensor_digest"],
        "envelope_digest": canonical_digest(inputs["envelopes"]["allow"]),
        "request_digest": canonical_digest(request),
        "runtime_peer": {
            key: allow["client"]["client"][key] for key in ("pid", "uid", "gid")
        },
        "measured_action": measured,
        "envelope": inputs["envelopes"]["allow"],
        "runtime_attribution": attribution,
    }
    receipt["submission_digest"] = canonical_digest(submission)
    _refresh_receipt(document)
    wrong["control_before"] = deepcopy(allow["control_after"])
    wrong["control_after"] = deepcopy(allow["control_after"])


class RuntimeProcessProfileSystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = _EVIDENCE.read_bytes()
        cls.document = json.loads(cls.raw)

    def test_retained_artifact_is_canonical_and_verifies(self) -> None:
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), _RAW_DIGEST)
        self.assertEqual(self.raw, canonical_json(self.document) + b"\n")
        verifier.verify_runtime_process_profile_systemd_evidence(self.document)

    def test_retained_digest_is_mandatory(self) -> None:
        with (
            patch.object(verifier, "_EVIDENCE_DIGEST", None),
            self.assertRaises(AdmissionEvidenceError),
        ):
            verifier.verify_runtime_process_profile_systemd_evidence(self.document)

    def test_semantic_mutations_are_rejected_after_repin(self) -> None:
        mutations = {
            "extra top-level field": _set("forged", value=True),
            "source closure removal": _remove_artifact,
            "source/install mismatch": _set(
                "artifacts", 0, "installed_digest", value=_ZERO_DIGEST
            ),
            "collector path": _set(
                "collector", "probe", "path", value="/src/forged.py"
            ),
            "mutable parent image": _set(
                "harness",
                "document",
                "systemd_base_image_id",
                value=_ZERO_DIGEST,
            ),
            "loaded unit drop-in": _set(
                "deployment", "units", "sensor", "DropInPaths", value="/tmp/override"
            ),
            "loaded unit fragment": _set(
                "deployment", "units", "broker", "FragmentDigest", value=_ZERO_DIGEST
            ),
            "service command": _set(
                "deployment", "processes", "sensor", "cmdline", value=["/bin/true"]
            ),
            "live capability": _set(
                "deployment",
                "security",
                "sensor",
                "capabilities",
                "CapBnd",
                "value",
                value=1,
            ),
            "profile digest": _set("profile", "digest", value=_ZERO_DIGEST),
            "coherent zero operation": _coherent_zero_operation,
            "coherent attributed client PID": _forge_profiled_client_pid,
            "protected root identity": _set(
                "deployment",
                "directories",
                "protected",
                "inode",
                value=999999,
            ),
            "derived create operation": _set(
                "inputs", "actions", "allow", "operation_digest", value=_ZERO_DIGEST
            ),
            "client systemd PID join": _set(
                "scenarios",
                "profiled_allow",
                "client",
                "client",
                "pid",
                value=999999,
            ),
            "sensor peer PID join": _set(
                "scenarios",
                "wrong_cgroup",
                "client",
                "server_peer",
                "pid",
                value=999999,
            ),
            "forged initial health epoch": _forge_initial_control(
                "health", "epoch", value=999999
            ),
            "forged initial health lifetime": _forge_initial_control(
                "health", "expires_at_unix", value=9999999999
            ),
            "forged initial observation sequence": _forge_initial_control(
                "observation", "sequence", value=999999
            ),
            "forged initial active context": _forge_initial_control(
                "observation", "active", "tool_call_id", value="forged"
            ),
            "forged initial measured action": _forge_initial_control(
                "observation", "measured_action", "path_digest", value=_ZERO_DIGEST
            ),
            "forged initial revocation generation": _forge_initial_control(
                "revocations", "generation", value=999999
            ),
            "pending effect": _set(
                "scenarios", "profiled_allow", "profile_pending_exists", value=True
            ),
            "receipt submission": _break_submission_binding,
            "receipt broker result": _break_broker_result_binding,
            "forged mediator health epoch": _forge_allow_decision(
                "mediator_health_epoch", 999999
            ),
            "forged minimum health epoch": _forge_allow_decision(
                "minimum_mediator_health_epoch", 999999
            ),
            "forged revocation generation": _forge_allow_decision(
                "revocation_generation", 999999
            ),
            "forged minimum revocation generation": _forge_allow_decision(
                "minimum_revocation_generation", 999999
            ),
            "forged active context digest": _forge_allow_decision(
                "active_context_digest", _ZERO_DIGEST
            ),
            "forged measured action digest": _forge_allow_decision(
                "measured_action_digest", _ZERO_DIGEST
            ),
            "forged evaluation time": _forge_allow_decision(
                "evaluated_at_unix", lambda value: value + 1
            ),
            "forged health snapshot": _set(
                "scenarios",
                "profiled_allow",
                "control_after",
                "health.json",
                value=_ZERO_DIGEST,
            ),
            "forged observation snapshot": _set(
                "scenarios",
                "profiled_allow",
                "control_after",
                "observation.json",
                value=_ZERO_DIGEST,
            ),
            "forged state snapshot": _set(
                "scenarios",
                "profiled_allow",
                "control_after",
                "state.json",
                value=_ZERO_DIGEST,
            ),
            "wrong-cgroup state change": _set(
                "scenarios",
                "wrong_cgroup",
                "control_after",
                "state.json",
                value=_ZERO_DIGEST,
            ),
            "wrong-cgroup effect": _set(
                "scenarios", "wrong_cgroup", "target_exists", value=True
            ),
            "limitation removal": _remove_limitation,
            "phase claim promotion": _set(
                "decision", "phase3_exit_eligible", value=True
            ),
            "EDR claim promotion": _set("decision", "edr_claim_eligible", value=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = deepcopy(self.document)
                mutate(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    verifier.verify_runtime_process_profile_systemd_evidence(
                        changed,
                        expected_digest=canonical_digest(changed),
                    )


if __name__ == "__main__":
    unittest.main()
