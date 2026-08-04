from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_openclaw_evidence import (
    verify_runtime_action_openclaw_composition_evidence,
)

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "runtime-action-openclaw-systemd-composition-p3-3c-2026-08-04.json"
)
_CASES = {
    "allow": "openclaw_allowed_create",
    "unhealthy": "openclaw_unhealthy_block",
    "sensor_unavailable": "openclaw_sensor_unavailable",
}


def _repin_probe(document: dict, scenario_id: str) -> None:
    wrapper = document["scenarios"][_CASES[scenario_id]]["openclaw"]
    raw = canonical_json(wrapper["evidence"]) + b"\n"
    wrapper.update(
        stdout_bytes=len(raw),
        stdout_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _repin_control(wrapper: dict) -> None:
    wrapper["digest"] = canonical_digest(wrapper["document"])


def _repin_provider_record(record: dict) -> None:
    raw = canonical_json(record["body"])
    record.update(
        body_raw=raw.decode("ascii"),
        body_bytes=len(raw),
        body_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _change_harness_mount(document: dict) -> None:
    harness = document["harness"]
    harness["document"]["openclaw_runtime_mount"].update(mode="rw", rw=True)
    harness["digest"] = canonical_digest(harness["document"])


def _add_conflicting_mount_option(document: dict) -> None:
    mount = document["deployment"]["mounts"]["sensor_runtime"]
    mount["raw"] = mount["raw"].replace(
        "rw,nosuid,nodev,noexec,relatime",
        "rw,nosuid,nodev,noexec,exec,relatime",
    )
    mount["mount_options"] = sorted([*mount["mount_options"], "exec"])
    mount["raw_digest"] = "sha256:" + hashlib.sha256(
        mount["raw"].encode()
    ).hexdigest()


def _invert_trace_direction(document: dict) -> None:
    trace = document["peer_trace"]["broker"]
    lines = trace["raw"].splitlines()
    index = next(i for i, line in enumerate(lines) if " accept4(" in line)
    service = lines[index].split()[0]
    descriptor = lines[index + 1].split("getsockopt(", 1)[1].split(",", 1)[0]
    lines[index] = (
        f'{service}    connect({descriptor}, {{sa_family=AF_UNIX, '
        'sun_path="/var/lib/aragorn-runtime-action/control/broker.sock"}, 54) = 0'
    )
    trace["raw"] = "\n".join(lines) + "\n"
    trace["raw_digest"] = "sha256:" + hashlib.sha256(
        trace["raw"].encode()
    ).hexdigest()


def _reuse_broker_pid_for_gateway(document: dict) -> None:
    broker_pid = document["deployment"]["processes"]["broker"]["pid"]
    evidence = document["scenarios"][_CASES["allow"]]["openclaw"]["evidence"]
    old_pid = evidence["gateway"]["process_before"]["pid"]
    for name in ("process_before", "process_after"):
        evidence["gateway"][name]["pid"] = broker_pid
    evidence["gateway"].update(spawned_pid=broker_pid, system_info={"pid": broker_pid})
    evidence["gateway"]["shutdown"]["pid"] = broker_pid
    trace = document["peer_trace"]["sensor"]
    trace["peer_credentials"][1]["pid"] = broker_pid
    trace["raw"] = trace["raw"].replace(f"pid={old_pid},", f"pid={broker_pid},", 1)
    trace["raw_digest"] = "sha256:" + hashlib.sha256(
        trace["raw"].encode()
    ).hexdigest()
    _repin_probe(document, "allow")


def _change_tool_contract(document: dict) -> None:
    evidence = document["scenarios"][_CASES["allow"]]["openclaw"]["evidence"]
    description = "forged tool contract"
    for record in evidence["provider"]["records"]:
        tool = next(
            value
            for value in record["body"]["tools"]
            if value["function"]["name"] == "aragorn_runtime_create"
        )
        tool["function"]["description"] = description
        _repin_provider_record(record)
    evidence["scenario"]["proof"]["exposed_tool_contract"]["function"][
        "description"
    ] = description
    _repin_probe(document, "allow")


def _change_plugin_source(document: dict) -> None:
    evidence = document["scenarios"][_CASES["allow"]]["openclaw"]["evidence"]
    evidence["plugin"]["inspect"]["response"]["plugin"]["source"] = "/tmp/index.js"
    _repin_probe(document, "allow")


def _add_provider_call(document: dict) -> None:
    evidence = document["scenarios"][_CASES["allow"]]["openclaw"]["evidence"]
    record = deepcopy(evidence["provider"]["records"][-1])
    record["sequence"] = 3
    evidence["provider"]["records"].append(record)
    evidence["provider"]["request_count"] = 3
    _repin_probe(document, "allow")


def _alias_target_path(document: dict) -> None:
    scenario = document["scenarios"][_CASES["allow"]]
    scenario["target"]["path"] = "/tmp/openclaw-allowed.txt"
    for when in ("target_before", "target_after"):
        scenario["openclaw"]["evidence"]["turn"][when]["path"] = (
            "/tmp/openclaw-allowed.txt"
        )
    _repin_probe(document, "allow")


def _reverse_refreshes(document: dict) -> None:
    document["scenarios"][_CASES["allow"]]["openclaw"][
        "control_refreshes"
    ].reverse()


def _change_unhealthy_status(document: dict) -> None:
    scenario = document["scenarios"][_CASES["unhealthy"]]
    scenario["openclaw"]["control_refreshes"][-1]["health"]["status"] = "healthy"
    health = scenario["control_after"]["health"]
    health["document"]["status"] = "healthy"
    _repin_control(health)


def _expire_consumed(document: dict) -> None:
    state = document["scenarios"][_CASES["allow"]]["control_after"]["state"]
    state["document"]["consumed"][0]["expires_at_unix"] = 1
    _repin_control(state)


def _forge_provider_body(document: dict) -> None:
    evidence = document["scenarios"][_CASES["allow"]]["openclaw"]["evidence"]
    evidence["provider"]["records"][0]["body"]["model"] = "forged-model"
    _repin_provider_record(evidence["provider"]["records"][0])
    _repin_probe(document, "allow")


def _zero_sensor_controls(document: dict) -> None:
    names = ("health", "observation", "policy", "revocations", "state")
    controls = {name: "sha256:" + "0" * 64 for name in names}
    document["scenarios"][_CASES["sensor_unavailable"]].update(
        control_before=controls,
        control_after=deepcopy(controls),
    )


def _change_retained_result(document: dict, mutate) -> None:
    evidence = document["scenarios"][_CASES["allow"]]["openclaw"]["evidence"]
    history = evidence["turn"]["history"]["response"]["messages"]
    tool_result = history[2]
    retained = json.loads(tool_result["content"][0]["text"])
    mutate(retained["result"])
    raw = canonical_json(retained).decode("ascii")
    tool_result["content"][0]["text"] = raw
    proof = evidence["scenario"]["proof"]
    proof["tool_result"] = deepcopy(tool_result)
    proof["retained_tool_result"] = retained
    proof["retained_tool_result_digest"] = "sha256:" + hashlib.sha256(
        raw.encode()
    ).hexdigest()
    transport = next(
        message
        for message in evidence["provider"]["records"][1]["body"]["messages"]
        if message.get("role") == "tool"
    )
    transport["content"] = raw
    _repin_provider_record(evidence["provider"]["records"][1])
    _repin_probe(document, "allow")


def _forge_request_digest(document: dict) -> None:
    def mutate(result: dict) -> None:
        forged = "sha256:" + "f" * 64
        result["request_digest"] = forged
        result["decision"]["request_digest"] = forged

    _change_retained_result(document, mutate)


def _change_decision_time(document: dict) -> None:
    _change_retained_result(
        document,
        lambda result: result["decision"].update(
            evaluated_at_unix=result["decision"]["evaluated_at_unix"] + 1
        ),
    )


class RuntimeActionOpenClawEvidenceTests(unittest.TestCase):
    def test_retained_capture_replays_and_matches_source_closure(self) -> None:
        raw = _EVIDENCE.read_bytes()
        self.assertEqual(
            "sha256:" + hashlib.sha256(raw).hexdigest(),
            "sha256:023103ddc4189da4275e4123b720e9f600d514f17734a62f1b2130e54b30488e",
        )
        document = json.loads(raw)
        self.assertEqual(raw, canonical_json(document) + b"\n")
        verify_runtime_action_openclaw_composition_evidence(document)

        retained = [*document["artifacts"], *document["collector"].values()]
        for item in retained:
            source = item.get("source_path", item.get("path"))
            payload = (_ROOT / source.removeprefix("/src/")).read_bytes()
            with self.subTest(source=source):
                self.assertEqual(
                    "sha256:" + hashlib.sha256(payload).hexdigest(),
                    item.get("source_digest", item.get("digest")),
                )
                self.assertEqual(len(payload), item["bytes"])

    def test_semantic_boundary_mutations_fail_after_repinning(self) -> None:
        document = json.loads(_EVIDENCE.read_bytes())
        mutations = {
            "authority": lambda item: item["decision"].update(edr_claim_eligible=True),
            "harness_mount": _change_harness_mount,
            "unit_dropin": lambda item: item["deployment"]["units"]["sensor"].update(
                DropInPaths="/run/systemd/system/override.conf"
            ),
            "process_command": lambda item: item["deployment"]["processes"][
                "broker"
            ].update(cmdline=["/tmp/unmeasured-broker"]),
            "mount_options": _add_conflicting_mount_option,
            "trace_direction": _invert_trace_direction,
            "gateway_pid_collision": _reuse_broker_pid_for_gateway,
            "direct_backend": lambda item: item["scenarios"][
                "runtime_direct_backend"
            ]["client"].update(outcome="RESPONSE"),
            "direct_write": lambda item: item["scenarios"]["runtime_direct_write"][
                "result"
            ].update(blocked=False),
            "tool_contract": _change_tool_contract,
            "plugin_source": _change_plugin_source,
            "provider_call_count": _add_provider_call,
            "provider_body": _forge_provider_body,
            "request_digest": _forge_request_digest,
            "decision_time": _change_decision_time,
            "target_alias": _alias_target_path,
            "refresh_order": _reverse_refreshes,
            "unhealthy_status": _change_unhealthy_status,
            "consumed_expiry": _expire_consumed,
            "sensor_controls": _zero_sensor_controls,
            "sensor_unit": lambda item: item["scenarios"][
                "openclaw_sensor_unavailable"
            ]["units"]["sensor"].update(MainPID="1"),
            "recording_time": lambda item: item.update(
                recorded_at="2000-01-01T00:00:00Z"
            ),
            "boolean_type": lambda item: item["decision"].update(
                run_01_eligible=0
            ),
            "floating_type": lambda item: item["scenarios"][
                "openclaw_allowed_create"
            ]["target"].update(bytes=38.0),
            "claim_smuggling": lambda item: item["environment"].update(attested=True),
        }
        for name, mutate in mutations.items():
            changed = deepcopy(document)
            mutate(changed)
            with self.subTest(boundary=name), self.assertRaises(AdmissionEvidenceError):
                verify_runtime_action_openclaw_composition_evidence(
                    changed, expected_digest=canonical_digest(changed)
                )


if __name__ == "__main__":
    unittest.main()
