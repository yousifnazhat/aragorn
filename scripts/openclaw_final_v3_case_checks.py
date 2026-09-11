"""Checks shared by native V3 development case backends; no PASS authority."""

from __future__ import annotations

import re
from typing import Any

from aragorn import admission_openclaw_final_v3_core_updater_qualification as old
from aragorn import admission_openclaw_final_v3_det01_binding as bounded
from aragorn import admission_openclaw_final_v3_det01_qualification as det
from aragorn import admission_protected_final_combined_v3_plugin_enable as records
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
    harness_file = harness["file"]
    metadata = harness_file["stat"]
    _expect(
        set(harness_file) == {"base64", "bytes", "digest", "path", "stat"}
        and harness_file["path"] == "/run/aragorn-harness.json"
        and set(metadata)
        == {
            "ctime_ns",
            "device",
            "gid",
            "inode",
            "mode",
            "mtime_ns",
            "nlink",
            "size",
            "type",
            "uid",
        }
        and all(
            type(metadata[key]) is int and metadata[key] > 0
            for key in ("ctime_ns", "mtime_ns", "device", "inode")
        )
        and metadata["mtime_ns"] == metadata["ctime_ns"],
        "harness file custody changed",
    )
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
    frozen = old.custody.parent.v3_contract.parent
    frozen._verify_contract_artifacts(inherited)
    for name, expected in frozen._CONTRACT_FILES.items():
        bound = inherited[name]
        _expect(
            set(bound)
            == {"document", "file", *({"outcomes"} if name == "profile" else set())}
            and set(bound["file"]) == {"canonical_bytes", "canonical_digest", "source"},
            "contract file wrapper changed",
        )
        records._verify_file_record(
            bound["file"]["source"],
            path="/src/" + expected["path"],
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode="0444",
            label=name,
        )
    policy = inherited["runtime_lock"]["document"]["deployment_bindings"][
        "plugin_install_policy"
    ]["command"]
    records._verify_file_record(
        inherited["policy_command"],
        path=policy["path"],
        bytes_=policy["bytes"],
        digest=policy["digest"],
        mode=policy["mode"],
        label="policy command",
    )
    _expect(
        set(inherited["skill"]) == {"file", "parents"}
        and _same(
            inherited["skill"]["parents"],
            [
                {
                    "path": path,
                    "mode": "0755" if path == "/" else "0555",
                    "uid": 0,
                    "gid": 0,
                }
                for path in (
                    "/",
                    "/opt",
                    "/opt/aragorn",
                    "/opt/aragorn/runtime-profile",
                    "/opt/aragorn/runtime-profile/template-skill",
                )
            ],
        ),
        "skill parent custody changed",
    )
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
    pids, processes = stack["pids"], stack["processes"]
    _expect(
        set(pids) == set(processes) == set(stack["units"])
        and all(
            type(pid) is int
            and pid > 0
            and type(processes[name]["pid"]) is int
            and pid == processes[name]["pid"]
            for name, pid in pids.items()
        )
        and len(set(pids.values())) == len(pids),
        "service PID map/process join changed",
    )
    _expect(
        all(
            _same(stack[name], action["boundaries"][name])
            for name in (
                "enablement",
                "gateway_listener",
                "processes",
                "service_state",
                "sockets",
                "units",
            )
        ),
        "same-run stack/composition identity changed",
    )
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


def verify_native_artifacts(
    artifact: dict[str, Any], *, verifier: Any, probe_key: str
) -> None:
    """Use the frozen content contract, not retained inode-dependent record hashes."""
    _expect(
        set(artifact) == set(verifier._ARTIFACT_DIGESTS)
        and set(artifact["collector"]) == set(verifier._COLLECTOR_ARTIFACTS)
        and _same(
            artifact["installed_runtime"],
            artifact["runtime_lock"]["document"]["installed_runtime"],
        ),
        "artifact inventory/runtime changed",
    )
    git = old._git
    for expected in verifier.parent._CONTRACT_FILES.values():
        verifier._verify_signed_bytes(git, expected)
    activation = artifact["runtime_lock"]["document"]["deployment_bindings"][
        "activation_contract"
    ]
    for name, installed, source_path, size, source_mode, installed_mode in (
        (
            "activator",
            activation["activator"],
            "packaging/activate-runtime-action-worker-host-v3.sh",
            30504,
            "0555",
            "0755",
        ),
        (
            "preflight",
            activation["preflight"],
            "src/aragorn/runtime_action_worker.py",
            37878,
            "0444",
            "0644",
        ),
    ):
        expected = {"path": source_path, "bytes": size, "digest": installed["digest"]}
        # The activator is generated in the frozen parent, not tracked at this
        # route's source commit; the verified runtime lock pins its exact bytes.
        if name == "preflight":
            verifier._verify_signed_bytes(git, expected)
        for key, path, mode in (
            (name, installed["path"], installed_mode),
            (name + "_source", "/src/" + source_path, source_mode),
        ):
            records._verify_file_record(
                artifact[key],
                path=path,
                bytes_=size,
                digest=installed["digest"],
                mode=mode,
                label=key,
            )
    for name, expected in verifier._COLLECTOR_ARTIFACTS.items():
        records._verify_file_record(
            artifact["collector"][name],
            path="/src/" + expected["path"],
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=name,
        )
        verifier._verify_signed_bytes(git, expected)
    plugin = {
        "index.js": (
            23860,
            "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
        ),
        "openclaw.plugin.json": (
            723,
            "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036",
        ),
        "package.json": (
            134,
            "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2",
        ),
    }
    _expect(set(artifact["plugin"]) == set(plugin), "plugin inventory changed")
    for name, (size, digest) in plugin.items():
        records._verify_file_record(
            artifact["plugin"][name],
            path="/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/" + name,
            bytes_=size,
            digest=digest,
            mode="0644",
            label=name,
        )
    records._verify_file_record(
        artifact["skill"]["file"],
        path="/opt/aragorn/runtime-profile/template-skill/SKILL.md",
        bytes_=140,
        digest=verifier.config._SOURCES["skill"]["digest"],
        mode="0444",
        label="skill",
    )
    verifier._verify_artifact_probe(artifact[probe_key], git)


def verify_native_composition(
    evidence: dict[str, Any],
    parent: dict[str, Any],
    *,
    verifier: Any,
    schema: str,
    authority: str,
    artifact_key: str,
) -> dict[str, Any]:
    composition = evidence["composition"]
    action = composition["action"]
    artifact = verify_parent(
        composition,
        action,
        parent,
        artifact_key=artifact_key,
    )
    _expect(
        set(composition)
        == {
            "action",
            "authority",
            "bindings",
            "decision",
            "limitations",
            "profile",
            "recorded_at",
            "schema",
        }
        and composition["schema"] == schema
        and composition["authority"] == authority
        and composition["limitations"] == verifier._RAW_LIMITATIONS
        and _same(composition["decision"], verifier._COMPOSITION_DECISION)
        and _same(
            composition["bindings"],
            {
                "config_materialization": "canonical_json_without_trailing_lf",
                "network": "none",
                "openclaw_test_fast": "absent",
                "runtime_digest": verifier.config._RUNTIME_TREE["tree_digest"],
                "runtime_volume": parent["runtime_volume"],
                "sandbox": "off",
                "sessions": "fresh-only",
                "skill_digest": verifier.config._SOURCES["skill"]["digest"],
            },
        )
        and _same(
            action["identities"],
            {
                "broker": {"gid": 997, "uid": 995},
                "gateway": {"gid": 992, "uid": 992},
                "sensor": {"gid": 996, "uid": 996},
                "worker": {"gid": 997, "uid": 997},
            },
        )
        and _same(
            action["secret_checks"],
            {
                "forbidden_driver_fields": [],
                "gateway_environment_bytes_retained": False,
                "gateway_environment_digest_retained": False,
                "provider_and_gateway_token_values_retained": False,
            },
        )
        and _same(
            action["runtime"],
            {
                "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
                "entrypoint_digest": verifier.contract._RUNTIME["entrypoint_digest"],
                "expected_version": verifier.contract._RUNTIME["version_output"],
                "root": "/runtime",
                "tree": verifier.config._RUNTIME_TREE,
                "version_output": verifier.contract._RUNTIME["version_output"],
            },
        ),
        "composition contract changed",
    )
    verifier._verify_sources(evidence["source_artifacts"])
    return artifact
