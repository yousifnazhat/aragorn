"""Checks shared by native V3 development case backends; no PASS authority."""

from __future__ import annotations

import re
from typing import Any

from aragorn import admission_openclaw_final_v3_core_updater_qualification as old
from aragorn import admission_openclaw_final_v3_det01_binding as bounded
from aragorn import admission_openclaw_final_v3_det01_qualification as det
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


def _expect(value: bool, message: str) -> None:
    if not value:
        raise AdmissionEvidenceError("V3 case " + message)


def _same(left: Any, right: Any) -> bool:
    return canonical_json(left) == canonical_json(right)


def _decision(status: str) -> dict[str, Any]:
    return {
        **{
            key: False
            for key in det.semantic._FALSE_DECISION
            if key.endswith("_eligible")
        },
        "status": status,
    }


def historical_sources(
    identity: dict[str, Any], paths: tuple[str, ...]
) -> list[dict[str, Any]]:
    old._verify_commit(identity)
    files = []
    for path in paths:
        entry = old._git(["ls-tree", "-z", identity["commit"], "--", path])
        metadata, separator, name = entry.partition(b"\t")
        fields = metadata.split()
        _expect(
            separator == b"\t"
            and name == path.encode() + b"\0"
            and len(fields) == 3
            and fields[0] in {b"100644", b"100755"}
            and fields[1] == b"blob",
            "historical source entry changed",
        )
        raw = old._git(["cat-file", "blob", fields[2].decode()], maximum=1_048_577)
        _expect(0 < len(raw) <= 1_048_576, "historical source size changed")
        digest = det._digest(raw)
        _expect(
            bounded._read_source(path, len(raw), digest) == raw,
            "historical source bytes changed",
        )
        files.append(
            {
                "path": path,
                "bytes": len(raw),
                "digest": digest,
                "mode": fields[0].decode(),
                "blob": fields[2].decode(),
            }
        )
    return files


def _record_bytes(record: dict[str, Any]) -> bytes:
    return det._decode({key: record[key] for key in ("base64", "bytes", "digest")})


def _numeric_types(value: Any) -> None:
    # Do not let Python's True == 1 turn custody/count checks into positive proof.
    if type(value) is dict:
        for key, item in value.items():
            if key in {
                "uid",
                "gid",
                "nlink",
                "bytes",
                "size",
                "pid",
                "exit_code",
                "route_pass_count",
                "route_fail_count",
                "route_not_tested_count",
            }:
                _expect(type(item) is int, "numeric custody field type changed")
            _numeric_types(item)
    elif type(value) is list:
        for item in value:
            _numeric_types(item)


def verify_source(prepared: dict[str, Any], source: dict[str, Any]) -> None:
    source_files = {item["path"]: item for item in source["files"]}
    _expect(
        len(source_files) == len(source["files"])
        and all(
            _same(source_files[item["path"]], item) for item in prepared["source_files"]
        ),
        "capture source closure changed",
    )
    _expect(
        type(source["commit"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", source["commit"]),
        "capture source commit changed",
    )


def verify_harness(
    harness: dict[str, Any],
    action: dict[str, Any],
    *,
    source: dict[str, Any],
    parent: dict[str, Any],
    stem: str,
    image_id: str,
) -> dict[str, Any]:
    host = harness["document"]
    _expect(
        _record_bytes(harness["file"]) == canonical_json(host)
        and harness["digest"] == harness["file"]["digest"] == canonical_digest(host)
        and _same(action["harness"], harness),
        "native harness raw/document join changed",
    )
    old._file_record(harness["file"], mode="0600")
    volume = host["route_input_volume_identity"]
    match = re.fullmatch(
        re.escape("aragorn-phase3-final-combined-v3-" + stem)
        + r"-route-input-([1-9][0-9]*)",
        volume["name"],
    )
    _expect(
        match is not None
        and re.fullmatch(r"[0-9a-f]{64}", host["container_id"])
        and host["source_commit"] == source["commit"]
        and host["schema"]
        == "aragorn/runtime-action-worker-final-combined-v3-"
        + stem
        + "-systemd-harness/v1"
        and host["image_id"] == host["run_image_reference"] == image_id
        and host["parent_image_id"] == parent["image_id"]
        and host["host_config"]["network_mode"] == "none"
        and host["openclaw_runtime_mount"]["source"] == parent["runtime_volume"]
        and host["openclaw_runtime_mount"]["rw"] is False
        and host["route_input_mount"]["source"] == volume["name"]
        and host["route_input_mount"]["rw"] is False,
        "native runtime/image/input binding changed",
    )
    _expect(
        volume["labels"]
        == {
            "dev.aragorn.capture-owner": source["commit"] + ":" + match[1],
            "dev.aragorn.role": "final-combined-v3-" + stem + "-route-input",
            "dev.aragorn.source-commit": source["commit"],
        },
        "native input owner changed",
    )
    lineage = host["image_lineage"]
    _expect(
        lineage["child"]["id"] == image_id
        and lineage["parent"]["id"] == parent["image_id"]
        and lineage["child"]["layers"]
        == lineage["parent"]["layers"] + lineage["added_layers"],
        "native image lineage changed",
    )
    signature = host["source_commit_verification"]
    _expect(
        signature["command"] == ["git", "verify-commit", "--raw", source["commit"]]
        and type(signature["exit_code"]) is int
        and signature["exit_code"] == 0
        and _record_bytes(signature["commit_object"])
        == old._git(["cat-file", "commit", source["commit"]]),
        "native source commit object changed",
    )
    _record_bytes(signature["stdout"])
    _record_bytes(signature["stderr"])
    return host


def verify_host(host: dict[str, Any], parent: dict[str, Any], *, stem: str) -> None:
    volume = host["route_input_volume_identity"]["name"]
    runtime = parent["runtime_volume"]
    _expect(
        set(host)
        == {
            "capture_disposition",
            "container_id",
            "host_config",
            "image_id",
            "image_lineage",
            "image_reference",
            "openclaw_runtime_mount",
            "openclaw_runtime_volume",
            "openclaw_runtime_volume_identity",
            "parent_image_id",
            "platform",
            "profile_label",
            "route_input_mount",
            "route_input_volume_identity",
            "run_image_reference",
            "schema",
            "source_commit",
            "source_commit_verification",
        }
        and set(host["source_commit_verification"])
        == {"command", "commit_object", "exit_code", "stderr", "stdout"}
        and host["capture_disposition"] == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and host["image_reference"]
        == f"aragorn-phase3-final-combined-v3-{stem}-systemd"
        and host["platform"] == "linux"
        and host["profile_label"] == f"phase3-final-combined-v3-{stem}"
        and host["openclaw_runtime_volume"] == runtime
        and _same(
            host["host_config"],
            {
                "binds": [
                    "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                    f"{runtime}:/runtime:ro",
                    f"{volume}:/route-input:ro",
                ],
                "cgroupns_mode": "host",
                "ipc_mode": "private",
                "network_mode": "none",
                "privileged": True,
                "readonly_rootfs": False,
                "runtime": "runc",
                "security_opt": ["label=disable"],
                "tmpfs": {
                    "/run": "rw,nosuid,nodev,noexec,mode=755",
                    "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
                },
                "userns_mode": "",
            },
        )
        and _same(
            host["route_input_volume_identity"],
            {
                "driver": "local",
                "labels": host["route_input_volume_identity"]["labels"],
                "name": volume,
                "options": None,
                "scope": "local",
            },
        )
        and _same(
            host["openclaw_runtime_volume_identity"],
            {
                "driver": "local",
                "labels": {
                    "io.aragorn.phase": "phase3-final",
                    "io.aragorn.role": "installed-runtime",
                    "io.aragorn.source-commit": old.custody.parent.v3_contract.contract._OPENCLAW[
                        "commit"
                    ],
                    "io.aragorn.source-tree": old.custody.parent.v3_contract.contract._OPENCLAW[
                        "source_tree"
                    ],
                },
                "name": runtime,
                "options": None,
                "scope": "local",
            },
        ),
        "native host configuration changed",
    )
    for field, name, destination in (
        ("openclaw_runtime_mount", runtime, "/runtime"),
        ("route_input_mount", volume, "/route-input"),
    ):
        _expect(
            _same(
                host[field],
                {
                    "destination": destination,
                    "driver": "local",
                    "mode": "ro",
                    "rw": False,
                    "source": name,
                    "type": "volume",
                },
            ),
            "native mount changed",
        )
    for side in ("parent", "child"):
        _expect(
            host["image_lineage"][side]["rootfs_type"] == "layers",
            "image rootfs changed",
        )


def verify_parent(
    composition: dict[str, Any],
    action: dict[str, Any],
    parent: dict[str, Any],
    *,
    artifact_key: str = "final_combined_v3_workshop_proposal_apply",
) -> dict[str, Any]:
    inherited = action["artifacts"][artifact_key]
    old.custody.parent.v3_contract.parent._verify_contract_artifacts(inherited)
    _expect(
        _same(composition["profile"]["before"], composition["profile"]["after"])
        and _same(
            composition["profile"]["before"]["document"],
            inherited["profile"]["document"],
        )
        and _same(
            composition["profile"]["before"]["outcomes"],
            {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0},
        )
        and _same(action["inputs"]["gateway_config"], inherited["config"]["document"])
        and canonical_digest(inherited["config"]["document"])
        == parent["configuration_canonical_digest"]
        and _same(
            action["runtime"]["tree"],
            old.custody.parent.v3_contract.config._RUNTIME_TREE,
        )
        and composition["bindings"]["runtime_volume"] == parent["runtime_volume"],
        "protected parent/configuration changed",
    )
    return inherited


def verify_execution(
    route: dict[str, Any],
    document: dict[str, Any],
    *,
    host: dict[str, Any],
    action: dict[str, Any],
    invocation: dict[str, Any],
    native_argv: list[str],
    recorded_at: str,
    prerequisite: dict[str, Any] | None = None,
) -> None:
    execution, stack = route["execution"], route["stack_before"]
    pid = route["gateway_pid_binding"]["pid"]
    gateway = "aragorn-agent-gateway.service"
    process = stack["processes"][gateway]
    if prerequisite is None:
        prerequisite = document["actions"][0]["prerequisites"]["gateway_process"]
    _expect(
        type(pid) is int
        and pid > 0
        and execution["exit_code"] == 0
        and execution["argv"]
        == [
            "nsenter",
            "--target",
            str(pid),
            "--mount",
            "--",
            "setpriv",
            "--reuid=992",
            "--regid=992",
            "--groups=992",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            *native_argv,
        ]
        and _same(
            execution["effective_identity"],
            {"gid": 992, "groups": [992], "uid": 992},
        )
        and _same(
            execution["stderr"],
            {"bytes": 0, "digest": det._digest(b""), "excerpt": ""},
        )
        and process["pid"] == pid == stack["pids"][gateway] == prerequisite["pid"]
        and process["uids"] == process["gids"] == [992] * 4
        and process["capabilities_effective"] == "0000000000000000"
        and process["no_new_privileges"] == 1
        and prerequisite["hostname"] == host["container_id"][:12]
        and prerequisite["start_time_ticks"] == process["start_time_ticks"],
        "actual native argv/identity changed",
    )
    legacy = old.custody.parent.contract.base.legacy
    legacy._verify_stack_boundary(
        stack,
        trusted=action["boundaries"],
        container_id=host["container_id"],
        snapshot_before=execution["started_at"],
    )
    legacy._verify_gateway_listener(stack["gateway_listener"], stack["processes"])
    _expect(
        det._timestamp(invocation["started_at"])
        < det._timestamp(execution["started_at"])
        <= det._timestamp(document["recorded_at"])
        <= det._timestamp(execution["completed_at"])
        <= det._timestamp(recorded_at)
        < det._timestamp(invocation["completed_at"]),
        "capture invocation chronology changed",
    )
