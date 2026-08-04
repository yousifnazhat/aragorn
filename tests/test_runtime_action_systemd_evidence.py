from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn import runtime_action_systemd_evidence as evidence_verifier

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "runtime-action-systemd-composition-p3-3b-2026-08-04.json"
)


def _remove_trace_precursors(document: dict) -> None:
    trace = document["peer_trace"]["broker"]
    trace["raw"] = "\n".join(
        line
        for line in trace["raw"].splitlines()
        if " accept4(" not in line and " connect(" not in line
    ) + "\n"
    trace["raw_digest"] = "sha256:" + hashlib.sha256(
        trace["raw"].encode()
    ).hexdigest()


def _expire_consumed(document: dict) -> None:
    state = document["scenarios"]["allowed_create"]["control_after"]["state"]
    state["document"]["consumed"][0]["expires_at_unix"] = 0
    state["digest"] = canonical_digest(state["document"])


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


def _change_trace_family(document: dict) -> None:
    trace = document["peer_trace"]["broker"]
    trace["raw"] = trace["raw"].replace("AF_UNIX", "AF_INET", 1)
    trace["raw_digest"] = "sha256:" + hashlib.sha256(
        trace["raw"].encode()
    ).hexdigest()


def _reuse_broker_pid(document: dict) -> None:
    broker_pid = document["deployment"]["processes"]["broker"]["pid"]
    client = document["scenarios"]["wrong_backend_uid"]["client"]["client"]
    old_pid = client["pid"]
    client["pid"] = broker_pid
    trace = document["peer_trace"]["broker"]
    trace["peer_credentials"][0]["pid"] = broker_pid
    trace["raw"] = trace["raw"].replace(f"pid={old_pid},", f"pid={broker_pid},", 1)
    trace["raw_digest"] = "sha256:" + hashlib.sha256(
        trace["raw"].encode()
    ).hexdigest()


def _change_mount_device(document: dict) -> None:
    mount = document["deployment"]["mounts"]["broker"]["action_root"]
    mount["raw"] = mount["raw"].replace(" 0:83 ", " 0:999 ", 1)
    mount["raw_digest"] = "sha256:" + hashlib.sha256(
        mount["raw"].encode()
    ).hexdigest()


def _move_publication_after_decision(document: dict) -> None:
    unhealthy = document["scenarios"]["unhealthy_block"]
    for published in (
        unhealthy["publication"]["published"],
        unhealthy["published_health"]["document"],
    ):
        published["observed_at_unix"] += 100
        published["expires_at_unix"] += 100
    unhealthy["published_health"]["digest"] = canonical_digest(
        unhealthy["published_health"]["document"]
    )


def _alias_target_to_parent(document: dict) -> None:
    parent = document["deployment"]["directories"]["protected"]
    document["scenarios"]["allowed_create"]["target"]["stat"].update(
        device=parent["device"], inode=parent["inode"]
    )


def _alias_socket_to_parent(document: dict) -> None:
    parent = document["deployment"]["directories"]["control"]
    document["deployment"]["sockets"]["backend"].update(
        device=parent["device"], inode=parent["inode"]
    )


def _alias_installed_artifacts(document: dict) -> None:
    first, second = (item["installed_stat"] for item in document["artifacts"][:2])
    second.update(device=first["device"], inode=first["inode"])


def _change_target_size(document: dict) -> None:
    target = document["scenarios"]["allowed_create"]["target"]
    target["bytes"] = target["stat"]["size"] = 1


def _forge_observation_wrapper(document: dict) -> None:
    unhealthy = document["scenarios"]["unhealthy_block"]
    observation = unhealthy["control_after"]["observation"]
    old_digest = observation["digest"]
    observation["document"]["schema"] = "forged/v1"
    observation["digest"] = canonical_digest(observation["document"])
    response = unhealthy["client"]["response"]
    response["observation_digest"] = observation["digest"]
    state = unhealthy["control_after"]["state"]
    for consumed in state["document"]["consumed"]:
        if consumed["observation_digest"] == old_digest:
            consumed["observation_digest"] = observation["digest"]
    state["document"]["consumed"].sort(key=canonical_json)
    state["digest"] = canonical_digest(state["document"])


def _reverse_consumed(document: dict) -> None:
    state = document["scenarios"]["unhealthy_block"]["control_after"]["state"]
    state["document"]["consumed"].reverse()
    state["digest"] = canonical_digest(state["document"])


def _append_trace_syscall(document: dict) -> None:
    trace = document["peer_trace"]["broker"]
    lines = trace["raw"].splitlines()
    lines.insert(-1, f"{lines[0].split()[0]}   getpid() = 107")
    trace["raw"] = "\n".join(lines) + "\n"
    trace["raw_digest"] = "sha256:" + hashlib.sha256(
        trace["raw"].encode()
    ).hexdigest()


def _duplicate_mount_id(document: dict) -> None:
    mounts = document["deployment"]["mounts"]["broker"]
    mount = mounts["action_root"]
    duplicate = mounts["root"]["raw"].split()[0]
    fields = mount["raw"].split(" ", 1)
    mount["raw"] = f"{duplicate} {fields[1]}"
    mount["raw_digest"] = "sha256:" + hashlib.sha256(
        mount["raw"].encode()
    ).hexdigest()


def _add_conflicting_mount_option(document: dict) -> None:
    mount = document["deployment"]["mounts"]["sensor"]["runtime"]
    mount["raw"] = mount["raw"].replace(
        "rw,nosuid,nodev,noexec,relatime",
        "rw,nosuid,nodev,noexec,exec,relatime",
    )
    mount["mount_options"] = sorted([*mount["mount_options"], "exec"])
    mount["raw_digest"] = "sha256:" + hashlib.sha256(
        mount["raw"].encode()
    ).hexdigest()


def _change_shared_superblock(document: dict) -> None:
    mount = document["deployment"]["mounts"]["broker"]["action_root"]
    old = next(value for value in mount["super_options"] if value.startswith("upperdir="))
    new = "upperdir=/forged"
    mount["super_options"] = sorted(new if value == old else value for value in mount["super_options"])
    mount["raw"] = mount["raw"].replace(old, new)
    mount["raw_digest"] = "sha256:" + hashlib.sha256(
        mount["raw"].encode()
    ).hexdigest()


def _move_publisher_after_client(document: dict) -> None:
    unhealthy = document["scenarios"]["unhealthy_block"]
    unhealthy["publication"]["process"]["start_time_ticks"] = str(
        int(unhealthy["client"]["client"]["start_time_ticks"]) + 1
    )


def _change_exec_start_time(document: dict) -> None:
    unit = document["deployment"]["units"]["broker"]
    unit["ExecStartEx"] = unit["ExecStartEx"].replace("08:14:26", "08:14:27")


def _move_unit_start_after_events(document: dict) -> None:
    unit = document["deployment"]["units"]["broker"]
    for key in ("ExecStart", "ExecStartEx"):
        unit[key] = unit[key].replace("08:14:26", "08:14:28")


def _move_control_subtree(document: dict) -> None:
    document["deployment"]["directories"]["control"]["device"] = 9001
    document["deployment"]["sockets"]["backend"]["device"] = 9001


def _refresh_sensor_down_request(document: dict) -> None:
    envelope = document["inputs"]["envelopes"]["sensor_down"]
    raw = canonical_json(envelope)
    client = document["scenarios"]["sensor_unavailable"]["client"]
    client.update(
        request_bytes=len(raw),
        request_file_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _invalidate_sensor_down_time(document: dict) -> None:
    document["inputs"]["envelopes"]["sensor_down"]["request"].update(
        issued_at_unix=0, expires_at_unix=5
    )
    _refresh_sensor_down_request(document)


def _boolean_sensor_down_policy_version(document: dict) -> None:
    document["inputs"]["envelopes"]["sensor_down"]["request"][
        "policy_version"
    ] = True
    _refresh_sensor_down_request(document)


def _forge_publication_schema(document: dict) -> None:
    unhealthy = document["scenarios"]["unhealthy_block"]
    unhealthy["publication"]["published"]["schema"] = "forged/v1"
    unhealthy["published_health"]["document"]["schema"] = "forged/v1"
    unhealthy["published_health"]["digest"] = canonical_digest(
        unhealthy["published_health"]["document"]
    )


def _add_consumed_field(document: dict) -> None:
    state = document["scenarios"]["unhealthy_block"]["control_after"]["state"]
    state["document"]["consumed"][0]["claim"] = "forged"
    state["digest"] = canonical_digest(state["document"])


class RuntimeActionSystemdEvidenceTests(unittest.TestCase):
    def test_capture_replays_and_matches_the_retained_source_closure(self) -> None:
        raw = _EVIDENCE.read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "61f977d4e7264cd9d7e916a4f148e9ea8b64d2cdfd93cb4fbddc4d5341c31a3f",
        )
        document = json.loads(raw)
        self.assertEqual(raw, canonical_json(document) + b"\n")
        evidence_verifier.verify_runtime_action_systemd_composition_evidence(
            document
        )

        retained = [
            *document["artifacts"],
            *document["collector"].values(),
        ]
        for item in retained:
            source = item.get("source_path", item.get("path"))
            payload = (_ROOT / source.removeprefix("/src/")).read_bytes()
            with self.subTest(source=source):
                self.assertEqual(
                    "sha256:" + hashlib.sha256(payload).hexdigest(),
                    item.get("source_digest", item.get("digest")),
                )
                self.assertEqual(
                    len(payload), item.get("source_bytes", item.get("bytes"))
                )

    def test_semantic_boundary_mutations_fail_after_repinning(self) -> None:
        document = json.loads(_EVIDENCE.read_bytes())
        mutations = {
            "authority": lambda item: item["decision"].update(
                edr_claim_eligible=True
            ),
            "principal": lambda item: item["identities"]["runtime"].update(
                uid=item["identities"]["sensor"]["uid"]
            ),
            "process": lambda item: item["deployment"]["processes"][
                "broker"
            ].update(cmdline=["/tmp/unmeasured-broker"]),
            "unit": lambda item: item["deployment"]["units"]["sensor"].update(
                DropInPaths="/run/systemd/system/override.conf"
            ),
            "mount": lambda item: item["deployment"]["mounts"]["sensor"][
                "root"
            ].update(mount_options=["rw"]),
            "peer": lambda item: item["peer_trace"]["broker"][
                "peer_credentials"
            ][0].update(uid=item["identities"]["broker"]["uid"]),
            "trace_pair": _remove_trace_precursors,
            "trace_direction": _invert_trace_direction,
            "trace_family": _change_trace_family,
            "pid_role_collision": _reuse_broker_pid,
            "mount_device": _change_mount_device,
            "publication_order": _move_publication_after_decision,
            "recording_order": lambda item: item.update(
                recorded_at="2000-01-01T00:00:00Z"
            ),
            "recording_elapsed": lambda item: item["scenarios"][
                "sensor_unavailable"
            ]["client"].update(elapsed_ns=400_000_000),
            "request_time": _invalidate_sensor_down_time,
            "request_policy_version": _boolean_sensor_down_policy_version,
            "target_inode_alias": _alias_target_to_parent,
            "socket_inode_alias": _alias_socket_to_parent,
            "artifact_inode_alias": _alias_installed_artifacts,
            "boolean_type": lambda item: item["decision"].update(
                run_01_eligible=0
            ),
            "floating_type": lambda item: item["scenarios"]["allowed_create"][
                "target"
            ].update(bytes=29.0),
            "target_size": _change_target_size,
            "observation_wrapper": _forge_observation_wrapper,
            "consumed_order": _reverse_consumed,
            "trace_extra_syscall": _append_trace_syscall,
            "mount_id": _duplicate_mount_id,
            "mount_options": _add_conflicting_mount_option,
            "mount_superblock": _change_shared_superblock,
            "process_chronology": _move_publisher_after_client,
            "exec_start_time": _change_exec_start_time,
            "unit_start_order": _move_unit_start_after_events,
            "socket_parent_device": lambda item: item["deployment"]["sockets"][
                "backend"
            ].update(device=84),
            "directory_device": _move_control_subtree,
            "harness": lambda item: item["harness"]["document"][
                "host_config"
            ].update(privileged=False),
            "dac": lambda item: item["scenarios"]["runtime_direct_backend"][
                "client"
            ].update(outcome="RESPONSE"),
            "denial_claim": lambda item: item["scenarios"][
                "runtime_direct_backend"
            ]["client"].update(
                response={"authority": "RUN_AUTHORITY", "verdict": "ALLOW"}
            ),
            "server_peer": lambda item: item["scenarios"]["allowed_create"][
                "client"
            ].update(server_peer={"pid": 1, "uid": 0, "gid": 0}),
            "response_authority": lambda item: item["scenarios"][
                "allowed_create"
            ]["client"]["response"].update(authority="RUN_AUTHORITY"),
            "decision_floor": lambda item: item["scenarios"]["allowed_create"][
                "client"
            ]["response"]["decision"].update(minimum_mediator_health_epoch=1),
            "effect": lambda item: item["scenarios"]["allowed_create"][
                "target"
            ].update(path="/tmp/allowed.txt"),
            "effect_schema": lambda item: item["inputs"]["envelopes"][
                "allow"
            ]["effect"].update(schema="forged/v1"),
            "side_effect": lambda item: item["scenarios"]["unhealthy_block"].update(
                protected_entries=["allowed.txt", "sidecar.txt"]
            ),
            "health": lambda item: item["scenarios"]["unhealthy_block"][
                "published_health"
            ]["document"].update(status="healthy"),
            "publication_schema": _forge_publication_schema,
            "observation": lambda item: item["scenarios"]["allowed_create"][
                "control_after"
            ]["observation"]["document"].update(sequence=3),
            "state": lambda item: item["scenarios"]["allowed_create"][
                "control_after"
            ]["state"]["document"].update(schema="forged/v1"),
            "consumed_expiry": _expire_consumed,
            "consumed_fields": _add_consumed_field,
            "initial_state": lambda item: item["inputs"]["initial_controls"][
                "state"
            ].update(consumed=[{"forged": True}]),
            "policy_scope": lambda item: item["inputs"]["policy"]["allow"].append(
                {
                    "runtime_digest": "sha256:" + "9" * 64,
                    "active_skill_digest": "sha256:" + "9" * 64,
                    "operation_digest": "sha256:" + "9" * 64,
                    "path_digest": "sha256:" + "9" * 64,
                    "payload_digest": "sha256:" + "9" * 64,
                }
            ),
            "python": lambda item: item["environment"].update(python="0.0"),
            "claim_smuggling": lambda item: item["environment"].update(
                attested=True
            ),
            "snapshot_link": lambda item: item["scenarios"][
                "sensor_unavailable"
            ].update(
                control_before={
                    name: "sha256:" + "0" * 64
                    for name in item["scenarios"]["sensor_unavailable"][
                        "control_before"
                    ]
                },
                control_after={
                    name: "sha256:" + "0" * 64
                    for name in item["scenarios"]["sensor_unavailable"][
                        "control_after"
                    ]
                },
            ),
            "sensor_down_request": lambda item: item["scenarios"][
                "sensor_unavailable"
            ]["client"].update(
                request_bytes=0,
                request_file_digest="sha256:" + "0" * 64,
            ),
            "sensor_down_schema": lambda item: item["inputs"]["envelopes"][
                "sensor_down"
            ]["request"].update(schema="forged/v1"),
            "negative_schema": lambda item: item["inputs"]["envelopes"][
                "negative"
            ]["request"].update(schema="forged/v1"),
            "fail_closed": lambda item: item["scenarios"][
                "sensor_unavailable"
            ].update(target_exists=True),
        }
        for name, mutate in mutations.items():
            changed = deepcopy(document)
            mutate(changed)
            with (
                self.subTest(boundary=name),
                patch.object(
                    evidence_verifier,
                    "_EVIDENCE_DIGEST",
                    canonical_digest(changed),
                ),
                self.assertRaises(AdmissionEvidenceError),
            ):
                evidence_verifier.verify_runtime_action_systemd_composition_evidence(
                    changed
                )


if __name__ == "__main__":
    unittest.main()
