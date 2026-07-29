"""Semantic replay for the fixed OpenClaw 2026.7.1 broker-switch probe."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest

_SCHEMA = "aragorn/openclaw-broker-symlink-live-switch-evidence/v2"
_ACTIVATION_SCHEMA = "aragorn/openclaw-broker-symlink-activation-evidence/v1"
_BASELINE_SCHEMA = "aragorn/openclaw-broker-symlink-before-state/v1"
_ASSURANCE = "SELF_REPORTED_EVIDENCE_ONLY_NOT_CONFORMANCE_AUTHORITY"
_LIMITATIONS = [
    "CONFORMANCE_FIXTURES_ONLY_NOT_PRODUCTION_ALLOW_LINEAGE",
    "BROKER_AND_DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_NOT_EXTERNAL_MODEL_PROOF",
    "NO_ADM_02_ROUTE_STATUS_IS_GRANTED",
]
_IMPLEMENTATION_DIGEST = (
    "sha256:09f96b9963507e8d37713753a6f219d23656ed29528fa62c4b45e98fa33d96b4"
)
_CONFIGURATION = {
    "canonical_document_digest": (
        "sha256:6ac6a76b495a59561e9fd92d70135f033d90d83601ced57f97f9e8dfd42a2f2a"
    ),
    "file_bytes": 1466,
    "file_digest": (
        "sha256:a00da537d7538e818b4c075b661e536e84582a79cbee1faa233c484491a5b3ea"
    ),
}
_EMPTY_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_ACTIVE_ROOT = "/profile/workspace/skills"
_VERSION_ROOT = f"{_ACTIVE_ROOT}/.aragorn-versions"
_NAME = "aragorn-admitted"
_ACTIVE_FILE = f"{_ACTIVE_ROOT}/{_NAME}/SKILL.md"
_SESSION_KEY = "agent:main:aragorn-broker-switch-v1"
_COMMIT = "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4"
_SOURCE_REVIEW = {
    "commit": _COMMIT,
    "findings": {
        "active_named_symlinks_are_bounded_and_loadable": True,
        "active_symlink_targets_are_watched": True,
        "dot_prefixed_version_storage_is_ignored_by_discovery": True,
        "root_symlink_rename_invalidates_the_workspace_snapshot": True,
    },
    "files": {
        "src/skills/loading/local-loader.ts": (
            "sha256:821c2490c5e4d0b00c7e09daef71038314d0e1ee34e888067bb5a3c0980d590f"
        ),
        "src/skills/loading/symlink-targets.ts": (
            "sha256:6fa5124aa200ff9c18ef027ed729b3f3dd9cf2b58d86d19999cb2aa57838e670"
        ),
        "src/skills/loading/workspace.ts": (
            "sha256:61720022e6f2d3b688da8ab9ee0b93eb80f12b70acec15d161c1b2116a09148a"
        ),
        "src/skills/runtime/refresh.ts": (
            "sha256:24afdf4b95d910b7cedca8415b3b93430b9417d4be2737e4eb76b2eaba8df531"
        ),
    },
    "sandbox_runtime_files": {
        "/runtime/lib/node_modules/openclaw/openclaw.mjs": {
            "digest": (
                "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
            ),
            "source": "openclaw.mjs",
        },
        "/runtime/lib/node_modules/openclaw/dist/entry.js": {
            "digest": (
                "sha256:c21dee0628985527f8a22d2fa54cfeba986479c5206339f379139464389cbf9f"
            ),
            "source": "src/entry.ts",
        },
        "/runtime/lib/node_modules/openclaw/dist/sandbox-cli-B0Is4BeU.js": {
            "digest": (
                "sha256:ba6a27d0c9ed49878a0046b7528438b1e683b21bc6dc38f2624520cd3f502fb5"
            ),
            "source": "src/commands/sandbox-explain.ts",
        },
        "/runtime/lib/node_modules/openclaw/dist/runtime-status-BRnZ3ffr.js": {
            "digest": (
                "sha256:9f5b9492c43b2c8ead57d46fb41205ac1b0e759542672ff47b9f56da3333d5d8"
            ),
            "source": "src/agents/sandbox/runtime-status.ts",
        },
        "/runtime/lib/node_modules/openclaw/dist/config-Dy4vED5-.js": {
            "digest": (
                "sha256:ce66d1255b1b66f4a0c09966fa2a8da59d42d15d8e8f578e4aae9387ac7ffb84"
            ),
            "source": "src/agents/sandbox/config.ts",
        },
        (
            "/runtime/lib/node_modules/openclaw/dist/"
            "zod-schema.agent-runtime-C02vY4RT.js"
        ): {
            "digest": (
                "sha256:84e2127660eed8573e3d486708e67884de408ed6403995f3100e42c0d4e0b0eb"
            ),
            "source": "src/config/zod-schema.agent-runtime.ts",
        },
    },
    "status": "SOURCE_REVIEWED_RUNTIME_LIVE_PROOF_PENDING",
}
_FIXTURE_TEXT = {
    version: (
        "---\n"
        f"name: {_NAME}\n"
        f"description: Inert Aragorn broker fixture aragorn-broker-{version}.\n"
        "---\n"
        f"# Aragorn broker fixture {version}\n"
        "\n"
        "This fixture is inert and performs no actions.\n"
    ).encode()
    for version in ("v1", "v2")
}
_FIXTURES = {
    version: {
        "bytes": len(raw),
        "file_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "manifest": {
            "entries": [
                {
                    "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "executable": False,
                    "mode": "444",
                    "path": "SKILL.md",
                    "size": len(raw),
                    "type": "file",
                }
            ],
            "schema": "aragorn/broker-symlink-fixture-tree/v1",
        },
        "marker": f"aragorn-broker-{version}",
        "version": version,
    }
    for version, raw in _FIXTURE_TEXT.items()
}
for _fixture in _FIXTURES.values():
    _fixture["tree_digest"] = canonical_digest(_fixture["manifest"])


def verify_openclaw_broker_symlink_evidence(document: Mapping[str, Any]) -> None:
    """Replay one evidence-only broker V1-to-V2 switch without granting authority."""

    try:
        payload = _verify_envelope(document, _SCHEMA)
        _object(
            payload,
            {
                "active_after",
                "active_before",
                "activations",
                "baseline",
                "configuration",
                "exact_old_and_new_versions_retained",
                "gateway",
                "guards",
                "implementation_digest",
                "no_gateway_restart",
                "observations",
                "observed_snapshots_only_v1_or_v2",
                "runtime",
                "runtime_boundary_after",
                "runtime_boundary_before",
                "sandbox",
                "same_session_advanced",
                "selected_attempt",
                "version_proofs",
            },
            "broker live-switch payload",
        )
        if (
            payload["implementation_digest"] != _IMPLEMENTATION_DIGEST
            or payload["configuration"] != _CONFIGURATION
            or payload["exact_old_and_new_versions_retained"] is not True
            or payload["no_gateway_restart"] is not True
            or payload["observed_snapshots_only_v1_or_v2"] is not True
            or payload["same_session_advanced"] is not True
            or payload["runtime"]
            != {
                "commit": _COMMIT,
                "name": "OpenClaw",
                "source_review": _SOURCE_REVIEW,
                "version": "2026.7.1",
            }
        ):
            raise AdmissionEvidenceError("broker implementation or claim boundary changed")

        activations = _object(
            payload["activations"], {"v1", "v2"}, "broker activation set"
        )
        activation_v1 = _verify_activation(activations["v1"], "v1", None)
        activation_v2 = _verify_activation(
            activations["v2"], "v2", activation_v1["active_after"]
        )
        baseline = _verify_baseline(payload["baseline"])
        proofs = _object(
            payload["version_proofs"], {"v1", "v2"}, "version proof set"
        )
        proof_v1 = _verify_version_proof(proofs["v1"], "v1", "installed")
        proof_v2 = _verify_version_proof(proofs["v2"], "v2", "installed")

        if (
            payload["active_before"] != baseline["link"]
            or payload["active_before"] != activation_v1["active_after"]
            or activation_v2["active_before"] != payload["active_before"]
            or payload["active_after"] != activation_v2["active_after"]
            or payload["active_before"]["resolved_target"]
            != proof_v1["directory"]["realpath"]
            or payload["active_after"]["resolved_target"]
            != proof_v2["directory"]["realpath"]
            or activation_v1["materialized"]["final"] != proof_v1
            or activation_v2["materialized"]["final"] != proof_v2
        ):
            raise AdmissionEvidenceError("broker activation and retained trees diverged")

        runtime_before = _verify_boundary(
            payload["runtime_boundary_before"], "runtime"
        )
        runtime_after = _verify_boundary(payload["runtime_boundary_after"], "runtime")
        if (
            payload["runtime_boundary_before"] != baseline["runtime_boundary"]
            or payload["runtime_boundary_before"] != payload["runtime_boundary_after"]
        ):
            raise AdmissionEvidenceError("runtime mount identity changed across switch")
        guard_boundary = _verify_guards(payload["guards"], payload["active_after"])
        if guard_boundary != payload["runtime_boundary_after"]:
            raise AdmissionEvidenceError("write guards ran outside the runtime boundary")

        broker_v1 = activation_v1["broker_boundary"]
        broker_v2 = activation_v2["broker_boundary"]
        if broker_v1 != broker_v2:
            raise AdmissionEvidenceError("broker mount identity changed across activations")
        _verify_shared_mount(broker_v1, runtime_before, runtime_after)

        gateway = _verify_gateway(payload["gateway"], baseline["gateway"])
        sandbox = _verify_sandbox(payload["sandbox"])
        observations = payload["observations"]
        if (
            not isinstance(observations, list)
            or not observations
            or len(observations) > 10
            or payload["selected_attempt"] != len(observations)
        ):
            raise AdmissionEvidenceError("broker observation selection changed")

        baseline_session = baseline["session"]
        prior_sequence = baseline["turn"]["provider"]["second_sequence"]
        prior_version = baseline_session["version"]
        for expected_attempt, observation in enumerate(observations, 1):
            item = _object(
                observation, {"attempt", "session", "turn"}, "broker observation"
            )
            if item["attempt"] != expected_attempt:
                raise AdmissionEvidenceError("broker attempts are not contiguous")
            session = _verify_session(item["session"], None)
            turn = _verify_turn(item["turn"], "v2", expected_attempt)
            if (
                session["session_id"] != baseline_session["session_id"]
                or session["version"] < prior_version
                or turn["provider"]["first_sequence"] != prior_sequence + 1
            ):
                raise AdmissionEvidenceError("broker same-session sequence changed")
            prior_version = session["version"]
            prior_sequence = turn["provider"]["second_sequence"]

        selected = observations[-1]
        selected_session = selected["session"]
        if (
            selected_session["active_marker"] != "v2"
            or selected["turn"]["provider"]["prompt_marker"] != "v2"
            or selected_session["version"] <= baseline_session["version"]
            or selected_session["prompt_digest"] == baseline_session["prompt_digest"]
        ):
            raise AdmissionEvidenceError("broker V1-to-V2 transition was not observed")

        if (
            _time(activation_v1["_recorded_at"])
            > _time(baseline["_recorded_at"])
            or _time(baseline["_recorded_at"])
            > _time(activation_v2["_recorded_at"])
            or _time(activation_v2["_recorded_at"])
            > _time(gateway["readiness_command"]["started_at"])
            or _time(activation_v2["_recorded_at"])
            > _time(sandbox["configured"]["command"]["started_at"])
            or _time(sandbox["effective"]["command"]["completed_at"])
            > _time(selected["turn"]["send"]["command"]["started_at"])
            or _time(sandbox["effective"]["command"]["completed_at"])
            > _time(document["recorded_at"])
            or _time(selected["turn"]["history_command"]["completed_at"])
            > _time(document["recorded_at"])
        ):
            raise AdmissionEvidenceError("broker evidence chronology is not causal")
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(f"invalid broker live-switch evidence: {exc}") from exc


def _verify_envelope(document: Mapping[str, Any], schema: str) -> Mapping[str, Any]:
    value = _object(
        document,
        {
            "assurance",
            "decision",
            "limitations",
            "payload",
            "recorded_at",
            "schema",
            "slice_status",
        },
        "broker evidence envelope",
    )
    if (
        value["schema"] != schema
        or value["assurance"] != _ASSURANCE
        or value["decision"]
        != {"installer_work_eligible": False, "status": "NOT_TESTED"}
        or value["limitations"] != _LIMITATIONS
        or value["slice_status"] != "PASS"
    ):
        raise AdmissionEvidenceError("broker evidence cannot grant installer authority")
    _time(value["recorded_at"])
    return _mapping(value["payload"], "broker evidence payload")


def _verify_activation(
    document: Mapping[str, Any],
    version: str,
    prior: Mapping[str, Any] | None,
) -> dict[str, Any]:
    payload = _verify_envelope(document, _ACTIVATION_SCHEMA)
    value = _object(
        payload,
        {
            "action",
            "active_after",
            "active_before",
            "atomic_relative_symlink_rename",
            "broker_boundary",
            "implementation_digest",
            "materialized",
            "native_openclaw_route_used",
            "requested_tree_digest",
            "single_volume_same_filesystem",
            "temporary_link",
        },
        f"{version} activation",
    )
    active = _verify_link(value["active_after"], version)
    boundary = _verify_boundary(value["broker_boundary"], "broker")
    materialized = _object(
        value["materialized"],
        {
            "final",
            "promoted",
            "promotion_same_filesystem",
            "source",
            "staged_device",
            "staged_inode",
        },
        f"{version} materialization",
    )
    final = _verify_version_proof(materialized["final"], version, "installed")
    source = _verify_version_proof(materialized["source"], version, "source")
    temporary = _object(
        value["temporary_link"], {"device", "inode", "target"}, "temporary link"
    )
    if (
        value["action"] != f"activate-{version}"
        or value["active_before"] != prior
        or value["atomic_relative_symlink_rename"] is not True
        or value["implementation_digest"] != _IMPLEMENTATION_DIGEST
        or value["native_openclaw_route_used"] is not False
        or value["requested_tree_digest"] != _FIXTURES[version]["tree_digest"]
        or value["single_volume_same_filesystem"] is not True
        or materialized["promoted"] is not True
        or materialized["promotion_same_filesystem"] is not True
        or materialized["staged_device"] != boundary["active_root"]["device"]
        or materialized["staged_inode"] != final["directory"]["inode"]
        or final["directory"]["device"] != boundary["active_root"]["device"]
        or active["device"] != boundary["active_root"]["device"]
        or temporary
        != {
            "device": active["device"],
            "inode": active["inode"],
            "target": active["target"],
        }
    ):
        raise AdmissionEvidenceError(f"{version} broker activation changed")
    return {
        **value,
        "broker_boundary": boundary,
        "materialized": {**materialized, "final": final, "source": source},
        "_recorded_at": document["recorded_at"],
    }


def _verify_baseline(document: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(
        document,
        {
            "configuration",
            "gateway",
            "implementation_digest",
            "link",
            "recorded_at",
            "runtime_boundary",
            "runtime_version",
            "schema",
            "session",
            "turn",
        },
        "broker baseline",
    )
    if (
        value["schema"] != _BASELINE_SCHEMA
        or value["configuration"] != _CONFIGURATION
        or value["implementation_digest"] != _IMPLEMENTATION_DIGEST
    ):
        raise AdmissionEvidenceError("broker baseline binding changed")
    _time(value["recorded_at"])
    link = _verify_link(value["link"], "v1")
    boundary = _verify_boundary(value["runtime_boundary"], "runtime")
    version = _verify_command(
        value["runtime_version"], [_NODE, _OPENCLAW, "--version"]
    )
    if (
        version["stdout_bytes"] != 28
        or version["stdout_digest"]
        != "sha256:9e98975ff3973bcd88f224e1820a177c3c881f7a46b51b7dc5ec5d050f72607f"
    ):
        raise AdmissionEvidenceError("OpenClaw 2026.7.1 runtime binding changed")
    gateway = _verify_baseline_gateway(value["gateway"])
    session = _verify_session(value["session"], "v1")
    turn = _verify_turn(value["turn"], "v1", 1)
    if (
        turn["provider"]["prompt_marker"] != "v1"
        or _time(version["completed_at"]) > _time(gateway["readiness_command"]["started_at"])
        or _time(turn["history_command"]["completed_at"]) > _time(value["recorded_at"])
    ):
        raise AdmissionEvidenceError("broker V1 baseline chronology changed")
    return {
        **value,
        "gateway": gateway,
        "link": link,
        "runtime_boundary": boundary,
        "session": session,
        "turn": turn,
        "_recorded_at": value["recorded_at"],
    }


def _verify_sandbox(document: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(
        document,
        {"configured", "effective", "runtime_files"},
        "sandbox proof",
    )
    configured = _object(
        value["configured"], {"command", "output", "stdout"}, "configured sandbox"
    )
    configured_command = _verify_command(
        configured["command"],
        [
            _NODE,
            _OPENCLAW,
            "config",
            "get",
            "agents.defaults.sandbox.mode",
            "--json",
        ],
    )
    effective = _object(
        value["effective"], {"command", "output", "stdout"}, "effective sandbox"
    )
    effective_command = _verify_command(
        effective["command"],
        [
            _NODE,
            _OPENCLAW,
            "sandbox",
            "explain",
            "--agent",
            "main",
            "--session",
            _SESSION_KEY,
            "--json",
        ],
    )
    for item, command in (
        (configured, configured_command),
        (effective, effective_command),
    ):
        stdout = item["stdout"]
        if not isinstance(stdout, str):
            raise AdmissionEvidenceError("sandbox command stdout is not text")
        raw = stdout.encode()
        if (
            command["stdout_bytes"] != len(raw)
            or command["stdout_digest"] != "sha256:" + hashlib.sha256(raw).hexdigest()
            or json.loads(stdout) != item["output"]
        ):
            raise AdmissionEvidenceError("sandbox command output binding changed")

    output = _mapping(effective["output"], "effective sandbox output")
    sandbox = _mapping(output.get("sandbox"), "effective sandbox state")
    if (
        configured["output"] != "off"
        or configured["stdout"] != '"off"\n'
        or output.get("docsUrl") != "https://docs.openclaw.ai/sandbox"
        or output.get("agentId") != "main"
        or output.get("sessionKey") != _SESSION_KEY
        or output.get("mainSessionKey") != "agent:main:main"
        or sandbox.get("mode") != "off"
        or sandbox.get("scope") != "agent"
        or sandbox.get("backend") != "docker"
        or sandbox.get("workspaceAccess") != "none"
        or sandbox.get("workspaceRoot") != "/profile/state/sandboxes"
        or sandbox.get("effectiveHostWorkspaceRoot") != "/profile/workspace"
        or sandbox.get("runtimeWorkdir") != "/profile/workspace"
        or sandbox.get("workspaceMounts") != []
        or sandbox.get("workspaceSource") != "direct"
        or sandbox.get("sessionIsSandboxed") is not False
        or _time(configured_command["completed_at"])
        > _time(effective_command["started_at"])
    ):
        raise AdmissionEvidenceError(
            "OpenClaw sandbox is not explicitly and effectively off"
        )
    runtime_files = _mapping(value["runtime_files"], "sandbox runtime files")
    expected_runtime_files = {
        path: record["digest"]
        for path, record in _SOURCE_REVIEW["sandbox_runtime_files"].items()
    }
    if runtime_files != expected_runtime_files:
        raise AdmissionEvidenceError("OpenClaw sandbox runtime files changed")
    return {
        "configured": {**configured, "command": configured_command},
        "effective": {**effective, "command": effective_command},
        "runtime_files": runtime_files,
    }


def _verify_version_proof(
    document: Mapping[str, Any], version: str, location: str
) -> Mapping[str, Any]:
    value = _object(
        document,
        {"directory", "file", "manifest", "tree_digest", "version"},
        f"{version} tree proof",
    )
    expected = _FIXTURES[version]
    directory = _object(
        value["directory"],
        {"device", "inode", "mode", "realpath", "type"},
        f"{version} directory",
    )
    file = _object(
        value["file"],
        {"device", "digest", "inode", "links", "mode", "path", "size", "type"},
        f"{version} file",
    )
    base = (
        f"{_VERSION_ROOT}/{_NAME}/{expected['tree_digest'].removeprefix('sha256:')}"
        if location == "installed"
        else f"/probe/fixtures/{version}"
    )
    if (
        value["version"] != version
        or value["manifest"] != expected["manifest"]
        or value["tree_digest"] != expected["tree_digest"]
        or canonical_digest(value["manifest"]) != value["tree_digest"]
        or directory["mode"] != "555"
        or directory["realpath"] != base
        or directory["type"] != "directory"
        or file["digest"] != expected["file_digest"]
        or file["links"] != 1
        or file["mode"] != "444"
        or file["path"] != "SKILL.md"
        or file["size"] != expected["bytes"]
        or file["type"] != "file"
        or file["device"] != directory["device"]
        or not _positive_int(directory["device"])
        or not _positive_int(directory["inode"])
        or not _positive_int(file["inode"])
    ):
        raise AdmissionEvidenceError(f"{version} exact-byte tree proof changed")
    return value


def _verify_link(document: Mapping[str, Any], version: str) -> Mapping[str, Any]:
    value = _object(
        document,
        {
            "device",
            "inode",
            "resolved_target",
            "target",
            "tree_digest",
            "type",
            "version",
        },
        f"{version} active link",
    )
    digest = _FIXTURES[version]["tree_digest"]
    suffix = digest.removeprefix("sha256:")
    target = f".aragorn-versions/{_NAME}/{suffix}"
    if (
        value["version"] != version
        or value["tree_digest"] != digest
        or value["type"] != "symlink"
        or value["target"] != target
        or value["resolved_target"] != f"{_ACTIVE_ROOT}/{target}"
        or not _positive_int(value["device"])
        or not _positive_int(value["inode"])
    ):
        raise AdmissionEvidenceError(f"{version} active-link proof changed")
    return value


def _verify_boundary(
    document: Mapping[str, Any], role: str
) -> Mapping[str, Any]:
    value = _object(
        document,
        {"active_root", "effective_identity", "mount", "role"},
        f"{role} execution boundary",
    )
    active = _object(
        value["active_root"],
        {"device", "gid", "inode", "mode", "uid"},
        "shared skill root",
    )
    identity = _object(
        value["effective_identity"], {"gid", "uid"}, f"{role} identity"
    )
    mount = _object(
        value["mount"],
        {
            "filesystem",
            "mount_options",
            "mount_point",
            "root",
            "source",
            "super_options",
        },
        f"{role} mount",
    )
    uid = 2000 if role == "broker" else 1000
    mount_mode = "rw" if role == "broker" else "ro"
    if (
        value["role"] != role
        or active["gid"] != 2000
        or active["uid"] != 2000
        or active["mode"] != "755"
        or identity != {"gid": uid, "uid": uid}
        or mount["filesystem"] != "ext4"
        or mount["mount_options"] != ["relatime", mount_mode]
        or mount["mount_point"] != _ACTIVE_ROOT
        or re.fullmatch(
            r"/docker/volumes/aragorn-openclaw-2026-7-1-broker-skills-v[0-9]+/_data",
            mount["root"],
        )
        is None
        or mount["source"] != "/dev/vdb1"
        or mount["super_options"] != ["rw"]
        or not _positive_int(active["device"])
        or not _positive_int(active["inode"])
    ):
        raise AdmissionEvidenceError(f"{role} mount boundary changed")
    return value


def _verify_shared_mount(
    broker: Mapping[str, Any],
    runtime_before: Mapping[str, Any],
    runtime_after: Mapping[str, Any],
) -> None:
    def identity(boundary: Mapping[str, Any]) -> tuple[Any, ...]:
        root = boundary["active_root"]
        mount = boundary["mount"]
        return (
            root["device"],
            root["inode"],
            root["gid"],
            root["uid"],
            mount["filesystem"],
            mount["mount_point"],
            mount["root"],
            mount["source"],
            mount["super_options"],
        )

    if (
        identity(broker) != identity(runtime_before)
        or identity(broker) != identity(runtime_after)
        or broker["mount"]["mount_options"] != ["relatime", "rw"]
        or runtime_before["mount"]["mount_options"] != ["relatime", "ro"]
        or broker["effective_identity"] == runtime_before["effective_identity"]
    ):
        raise AdmissionEvidenceError("broker RW and runtime RO views are not distinct")


def _verify_gateway(
    document: Mapping[str, Any], baseline: Mapping[str, Any]
) -> Mapping[str, Any]:
    value = _object(
        document,
        {
            "log_after",
            "log_before",
            "process_after",
            "process_before",
            "readiness_command",
        },
        "broker gateway",
    )
    before = _verify_log(value["log_before"])
    after = _verify_log(value["log_after"])
    process_before = _verify_process(value["process_before"])
    process_after = _verify_process(value["process_after"])
    readiness = _verify_gateway_readiness(value["readiness_command"])
    if (
        before != baseline["log"]
        or process_before != baseline["process"]
        or process_before != process_after
        or after["path"] != before["path"]
        or after["bytes"] <= before["bytes"]
        or after["digest"] == before["digest"]
    ):
        raise AdmissionEvidenceError("Gateway restarted or log continuity changed")
    return {**value, "readiness_command": readiness}


def _verify_baseline_gateway(document: Mapping[str, Any]) -> Mapping[str, Any]:
    value = _object(
        document,
        {"log", "process", "readiness_command", "system_info"},
        "baseline gateway",
    )
    info = _object(
        value["system_info"],
        {"arch", "node_version", "pid", "platform", "port"},
        "Gateway system info",
    )
    if info != {
        "arch": "arm64",
        "node_version": "v24.16.0",
        "pid": 1,
        "platform": "linux",
        "port": 18789,
    }:
        raise AdmissionEvidenceError("OpenClaw container runtime identity changed")
    return {
        **value,
        "log": _verify_log(value["log"]),
        "process": _verify_process(value["process"]),
        "readiness_command": _verify_gateway_readiness(value["readiness_command"]),
    }


def _verify_gateway_readiness(document: Mapping[str, Any]) -> Mapping[str, Any]:
    return _verify_command(
        document,
        [
            _NODE,
            _OPENCLAW,
            "gateway",
            "call",
            "system.info",
            "--json",
            "--timeout",
            "5000",
        ],
    )


def _verify_log(document: Mapping[str, Any]) -> Mapping[str, Any]:
    value = _object(
        document,
        {"bytes", "digest", "path", "ready_count", "restart_count"},
        "Gateway log",
    )
    if (
        not _positive_int(value["bytes"])
        or not _digest(value["digest"])
        or re.fullmatch(r"openclaw-[0-9]{4}-[0-9]{2}-[0-9]{2}\.log", value["path"])
        is None
        or value["ready_count"] != 1
        or value["restart_count"] != 0
    ):
        raise AdmissionEvidenceError("Gateway log proof changed")
    return value


def _verify_process(document: Mapping[str, Any]) -> Mapping[str, Any]:
    value = _object(
        document, {"cmdline", "pid", "start_time_ticks"}, "Gateway process"
    )
    if (
        value["cmdline"] != ["openclaw-gateway"]
        or value["pid"] != 1
        or not isinstance(value["start_time_ticks"], str)
        or not value["start_time_ticks"].isdigit()
        or int(value["start_time_ticks"]) <= 0
    ):
        raise AdmissionEvidenceError("Gateway process identity changed")
    return value


def _verify_session(
    document: Mapping[str, Any], expected_marker: str | None
) -> Mapping[str, Any]:
    value = _object(
        document,
        {
            "active_marker",
            "ended_at",
            "markers",
            "prompt_bytes",
            "prompt_digest",
            "prompt_storage",
            "run_status",
            "runtime_ms",
            "session_id",
            "skill_names",
            "started_at",
            "version",
        },
        "broker session snapshot",
    )
    marker = value["active_marker"]
    if (
        marker not in {"v1", "v2"}
        or (expected_marker is not None and marker != expected_marker)
        or value["markers"] != {"v1": marker == "v1", "v2": marker == "v2"}
        or not _positive_int(value["prompt_bytes"])
        or not _digest(value["prompt_digest"])
        or value["prompt_storage"] != "promptRef"
        or value["run_status"] != "done"
        or not isinstance(value["runtime_ms"], int)
        or isinstance(value["runtime_ms"], bool)
        or value["runtime_ms"] < 0
        or not isinstance(value["session_id"], str)
        or not value["session_id"]
        or value["skill_names"] != [_NAME]
        or not isinstance(value["started_at"], int)
        or not isinstance(value["ended_at"], int)
        or value["ended_at"] < value["started_at"]
        or not isinstance(value["version"], int)
        or value["version"] < 0
    ):
        raise AdmissionEvidenceError("broker session snapshot changed")
    return value


def _verify_turn(
    document: Mapping[str, Any], version: str, attempt: int
) -> Mapping[str, Any]:
    value = _object(
        document,
        {"consumption", "history_command", "provider", "send", "wait"},
        f"{version} broker turn",
    )
    fixture = _FIXTURES[version]
    consumption = _object(
        value["consumption"],
        {
            "final_text",
            "roles",
            "tool_content_digest",
            "tool_path",
            "valid",
        },
        "exact-byte consumption",
    )
    provider = _object(
        value["provider"],
        {
            "first_sequence",
            "prompt_digest",
            "prompt_marker",
            "record_count",
            "second_sequence",
            "tool_content_digest",
            "valid",
        },
        "provider turn",
    )
    run_id = f"aragorn-broker-switch-{version}-{attempt}"
    message = (
        "Read the active Aragorn broker skill file, then return its fixed result. "
        f"ARAGORN_BROKER_EXPECT_{version.upper()}"
    )
    send_params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": message,
        "sessionKey": _SESSION_KEY,
        "timeoutMs": 10_000,
    }
    send = _object(value["send"], {"command", "response"}, "chat.send proof")
    send_command = _verify_rpc(
        send["command"], "chat.send", send_params, command_timeout=5_000
    )
    if send["response"] != {"runId": run_id, "status": "started"}:
        raise AdmissionEvidenceError("chat.send response changed")
    wait = _object(value["wait"], {"command", "response"}, "agent.wait proof")
    wait_command = _verify_rpc(
        wait["command"],
        "agent.wait",
        {"runId": run_id, "timeoutMs": 15_000},
        command_timeout=17_000,
    )
    wait_response = _object(
        wait["response"], {"endedAt", "runId", "status"}, "agent.wait response"
    )
    history = _verify_rpc(
        value["history_command"],
        "chat.history",
        {"limit": 100, "sessionKey": _SESSION_KEY},
        command_timeout=5_000,
    )
    if (
        consumption
        != {
            "final_text": f"ARAGORN_BROKER_{version.upper()}_OK",
            "roles": ["user", "assistant", "toolResult", "assistant"],
            "tool_content_digest": fixture["file_digest"],
            "tool_path": _ACTIVE_FILE,
            "valid": True,
        }
        or provider["prompt_marker"] not in {"v1", "v2"}
        or provider["record_count"] != 2
        or provider["tool_content_digest"] != fixture["file_digest"]
        or provider["valid"] is not True
        or not _positive_int(provider["first_sequence"])
        or provider["second_sequence"] != provider["first_sequence"] + 1
        or not _digest(provider["prompt_digest"])
        or wait_response["runId"] != run_id
        or wait_response["status"] != "ok"
        or not _positive_int(wait_response["endedAt"])
        or _time(send_command["completed_at"]) > _time(wait_command["started_at"])
        or _time(wait_command["completed_at"]) > _time(history["started_at"])
    ):
        raise AdmissionEvidenceError(f"{version} exact-byte turn proof changed")
    return {
        **value,
        "history_command": history,
        "provider": provider,
        "send": {**send, "command": send_command},
        "wait": {**wait, "command": wait_command},
    }


def _verify_rpc(
    document: Mapping[str, Any],
    method: str,
    params: Mapping[str, Any],
    *,
    command_timeout: int,
) -> Mapping[str, Any]:
    argv = [
        _NODE,
        _OPENCLAW,
        "gateway",
        "call",
        method,
        "--json",
        "--timeout",
        str(command_timeout),
        "--params",
        json.dumps(params, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
    ]
    return _verify_command(document, argv)


def _verify_command(
    document: Mapping[str, Any], expected_argv: list[str]
) -> Mapping[str, Any]:
    value = _object(
        document,
        {
            "argv",
            "completed_at",
            "error",
            "exit_code",
            "pid",
            "signal",
            "started_at",
            "stderr_bytes",
            "stderr_digest",
            "stdout_bytes",
            "stdout_digest",
        },
        "OpenClaw command",
    )
    if (
        value["argv"] != expected_argv
        or value["error"] is not None
        or value["exit_code"] != 0
        or not _positive_int(value["pid"])
        or value["pid"] == 1
        or value["signal"] is not None
        or value["stderr_bytes"] != 0
        or value["stderr_digest"] != _EMPTY_DIGEST
        or not _positive_int(value["stdout_bytes"])
        or not _digest(value["stdout_digest"])
        or _time(value["started_at"]) > _time(value["completed_at"])
    ):
        raise AdmissionEvidenceError("successful OpenClaw command proof changed")
    return value


def _verify_guards(
    document: Mapping[str, Any], active: Mapping[str, Any]
) -> Mapping[str, Any]:
    value = _object(
        document,
        {"all_blocked", "direct_writes", "mountpoint", "replacements", "runtime_boundary"},
        "broker write guards",
    )
    direct_roots = [
        ("active-workspace-skills", _ACTIVE_ROOT),
        ("active-version-directory", active["resolved_target"]),
        ("project-agents", "/profile/workspace/.agents"),
        ("personal-agents", "/profile/home/.agents"),
        ("managed-skills", "/profile/state/skills"),
        ("plugin-skills", "/profile/state/plugin-skills"),
        ("extensions", "/profile/state/extensions"),
        ("configuration", "/profile/config"),
        ("bundled-runtime-skills", "/runtime/lib/node_modules/openclaw/skills"),
    ]
    replacement_roots = direct_roots[2:]
    if value["all_blocked"] is not True:
        raise AdmissionEvidenceError("broker write guards did not all block")
    _verify_guard_list(
        value["direct_writes"],
        direct_roots,
        "direct-write",
        {"EACCES", "EROFS"},
        replacement=False,
    )
    mountpoint = value["mountpoint"]
    if (
        not isinstance(mountpoint, list)
        or len(mountpoint) != 2
        or mountpoint[0]
        != {
            "blocked": True,
            "code": "EBUSY",
            "operation": "rename-skills-mountpoint",
            "root": _ACTIVE_ROOT,
        }
        or _object(
            mountpoint[1],
            {"blocked", "code", "operation", "root"},
            "unlink mount guard",
        )["code"]
        not in {"EBUSY", "EISDIR", "EPERM", "EROFS"}
        or mountpoint[1]["blocked"] is not True
        or mountpoint[1]["operation"] != "unlink-skills-mountpoint"
        or mountpoint[1]["root"] != _ACTIVE_ROOT
    ):
        raise AdmissionEvidenceError("nested mountpoint replacement guard changed")
    _verify_guard_list(
        value["replacements"],
        replacement_roots,
        "alternate-root-replacement",
        {"EACCES", "EEXIST", "ENOTEMPTY", "EPERM", "EROFS", "EXDEV"},
        replacement=True,
    )
    return _verify_boundary(value["runtime_boundary"], "runtime")


def _verify_guard_list(
    documents: Any,
    expected: list[tuple[str, str]],
    operation: str,
    codes: set[str],
    *,
    replacement: bool,
) -> None:
    if not isinstance(documents, list) or len(documents) != len(expected):
        raise AdmissionEvidenceError(f"{operation} guard count changed")
    keys = {"blocked", "code", "id", "operation", "root"}
    if replacement:
        keys.add("target")
    for document, (guard_id, root) in zip(documents, expected, strict=True):
        value = _object(document, keys, f"{operation} guard")
        if (
            value["blocked"] is not True
            or value["code"] not in codes
            or value["id"] != guard_id
            or value["operation"] != operation
            or value["root"] != root
            or (replacement and value["target"] != f"{root}/{_NAME}")
        ):
            raise AdmissionEvidenceError(f"{operation} guard semantics changed")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AdmissionEvidenceError(f"{label} is not an object")
    return value


def _object(
    value: Any, keys: set[str], label: str
) -> Mapping[str, Any]:
    result = _mapping(value, label)
    if set(result) != keys:
        raise AdmissionEvidenceError(f"{label} fields changed")
    return result


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
