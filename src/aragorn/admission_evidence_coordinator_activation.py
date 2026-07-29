"""Replay one fixed coordinator-to-OpenClaw activation slice."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json

_SCHEMA = "aragorn/openclaw-coordinator-runtime-activation-evidence/v1"
_ASSURANCE = "SELF_REPORTED_EVIDENCE_ONLY_NOT_CONFORMANCE_AUTHORITY"
_EVIDENCE_DIGEST = (
    "sha256:d56a5b6cae1fe93d448fbdbd87602be1320a86e51686984e152d43fe4bf77b3c"
)
_ARCHIVE_DIGEST = (
    "sha256:707fb29a9a22dad7ac9e9bd2c7e39a831a1e1d994ce625ef7ee8102f24b04397"
)
_IMAGE_DIGEST = (
    "sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf"
)
_CONFIG_DIGEST = (
    "sha256:47b957bbee84f3d550a4d549e7734c1aae2edf4df10c3c3351beb17bb53b6c4e"
)
_RUNTIME_TREE_DIGEST = (
    "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c"
)
_SKILL = (
    "---\n"
    "name: template-skill\n"
    "description: Replace with description of the skill and when Claude "
    "should use it.\n"
    "---\n\n"
    "# Insert instructions below\n"
)
_SKILL_DIGEST = (
    "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
)
_VERSION_PATH = (
    ".aragorn-versions/aragorn-admitted/"
    "79ebd365ace7a7d528a3e5bf50fe9ec83d93109d5c74e46f6b52f3dcd15e6655-"
    "99c08a9f18b3c4d0b7a07f058f93e69df6c1e4176ffe0f209a085ba317d6c82d"
)
_ACTIVE_FILE = "/profile/state/skills/aragorn-admitted/SKILL.md"
_RESOLVED_FILE = f"/profile/state/skills/{_VERSION_PATH}/SKILL.md"
_LIMITATIONS = [
    "OPERATOR_CONTROLLED_ARCHIVE_TO_VOLUME_IMPORT_NOT_LIVE_SHARED_FILESYSTEM",
    "CAPTURED_ROOT_MODE_0700_REEXPOSED_AS_0755_FOR_RUNTIME_TRAVERSAL",
    "DECLARED_SKILL_NAME_SELECTED_IN_DISPOSABLE_CONFIG",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_NOT_EXTERNAL_MODEL_PROOF",
    "DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
    "SINGLE_COORDINATOR_INSTALLED_ACTIVATION_SLICE_NOT_ADM_02_ROUTE_CONFORMANCE",
    "NO_INSTALLER_AUTHORITY_OR_PHASE_EXIT",
]


def verify_openclaw_coordinator_runtime_activation_evidence(
    document: Mapping[str, Any],
) -> None:
    """Verify the retained slice without granting route or installer authority."""

    try:
        _expect(
            canonical_digest(document) == _EVIDENCE_DIGEST,
            "retained evidence digest changed",
        )
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["assurance"] == _ASSURANCE, "assurance changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(document["slice_status"] == "PASS", "slice status changed")
        _expect(
            document["decision"]
            == {
                "installer_work_eligible": False,
                "phase1_exit_eligible": False,
                "status": "EVIDENCE_ONLY",
            },
            "authority boundary changed",
        )
        _time(document["recorded_at"])
        payload = document["payload"]
        _verify_source(payload["source_capture"])
        _verify_composition(payload["composition"])
        _verify_runtime_target(payload["runtime"], payload["target"])
        _verify_os_invariant(payload["os_invariant"])
        _verify_activation(payload["activation"])
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, AdmissionEvidenceError):
            raise
        raise AdmissionEvidenceError(
            f"invalid coordinator runtime activation evidence: {exc}"
        ) from exc


def _verify_source(source: Mapping[str, Any]) -> None:
    _expect(
        source["archive"]
        == {
            "digest": _ARCHIVE_DIGEST,
            "path": (
                "benchmark/evidence/"
                "phase1-protected-coordinator-live-2d29a19-2026-07-29.tar.gz"
            ),
        },
        "archive binding changed",
    )
    _expect(
        source["captured_root"] == {"gid": 0, "mode": "700", "uid": 0}
        and source["imported_root"] == {"gid": 0, "mode": "755", "uid": 0},
        "root traversal composition changed",
    )
    _expect(
        source["active_link"] == {"target": _VERSION_PATH, "type": "symlink"},
        "active link changed",
    )
    state = source["coordinator_state"]
    state_raw = canonical_json(state["document"])
    _expect(
        state["bytes"] == len(state_raw)
        and state["digest"] == _sha(state_raw)
        and state["document"]["schema"]
        == "aragorn/protected-install-coordinator-state/v1"
        and state["document"]["assurance"]
        == "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        and state["document"]["version_path"] == _VERSION_PATH
        and state["document"]["expected_active"]["source_request"]
        == {
            "commit": "2235be7c60b551f5de82ade908fd3816455afcda",
            "owner": "anthropics",
            "repository": "skills",
            "schema": "aragorn/github-gateway-request/v1",
            "skill_path": "template",
        },
        "coordinator active state changed",
    )


def _verify_composition(composition: Mapping[str, Any]) -> None:
    _expect(
        composition["docker_context"] == "colima",
        "Docker context changed from the observed colima context",
    )
    _expect(
        composition["image"]
        == {
            "architecture": "arm64",
            "digest": _IMAGE_DIGEST,
            "os": "linux",
            "reference": f"node@{_IMAGE_DIGEST}",
        },
        "container image changed",
    )
    _expect(
        composition["config"]["bytes"] == 1062
        and composition["config"]["digest"] == _CONFIG_DIGEST
        and composition["config"]["selected_skill"] == "template-skill",
        "disposable config binding changed",
    )
    container = composition["container"]
    _expect(
        re.fullmatch(r"[0-9a-f]{64}", container["id"]) is not None
        and container["user"] == "1000:1000"
        and container["read_only_rootfs"] is True
        and container["network"] == "none"
        and container["cap_drop"] == ["ALL"]
        and container["no_new_privileges"] is True,
        "container isolation profile changed",
    )
    expected_mounts = {
        "/probe": (
            "aragorn-openclaw-2026-7-1-contained-model-activation-probe-v2"
        ),
        "/profile/config": "aragorn-phase1-coordinator-config-check-v1",
        "/profile/state/skills": "aragorn-phase1-coordinator-runtime-check-v1",
        "/runtime": "aragorn-openclaw-2026-7-1-runtime-v2",
    }
    _expect(
        composition["mounts"]
        == {
            path: {"read_only": True, "source_volume": volume}
            for path, volume in expected_mounts.items()
        },
        "read-only mount composition changed",
    )


def _verify_runtime_target(
    runtime: Mapping[str, Any],
    target: Mapping[str, Any],
) -> None:
    _expect(
        runtime["commit"] == "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4"
        and runtime["version"] == "2026.7.1"
        and runtime["version_output"] == "OpenClaw 2026.7.1 (2d2ddc4)"
        and runtime["tree"]["algorithm"] == "aragorn/runtime-tree/v1"
        and runtime["tree"]["tree_digest"] == _RUNTIME_TREE_DIGEST,
        "OpenClaw runtime identity changed",
    )
    raw = target["content"].encode()
    _expect(
        target["active_path"] == _ACTIVE_FILE
        and target["resolved_path"] == _RESOLVED_FILE
        and target["alias"] == "aragorn-admitted"
        and target["declared_name"] == "template-skill"
        and target["mode"] == "444"
        and target["content"] == _SKILL
        and target["bytes"] == len(raw)
        and target["digest"] == _sha(raw) == _SKILL_DIGEST,
        "exact installed target changed",
    )


def _verify_os_invariant(invariant: Mapping[str, Any]) -> None:
    _expect(
        invariant["all_blocked"] is True
        and invariant["effective_identity"] == {"gid": 1000, "uid": 1000}
        and invariant["root"] == {"gid": 0, "mode": "755", "uid": 0}
        and invariant["mount"]["mount_point"] == "/profile/state/skills"
        and invariant["mount"]["mount_options"] == ["relatime", "ro"]
        and invariant["attempts"]
        == [
            {
                "blocked": True,
                "code": "EROFS",
                "operation": "create-in-root",
            },
            {
                "blocked": True,
                "code": "EROFS",
                "operation": "rename-active-link",
            },
            {
                "blocked": True,
                "code": "EACCES",
                "operation": "open-active-file-rw",
            },
        ],
        "runtime read-only OS invariant changed",
    )


def _verify_activation(activation: Mapping[str, Any]) -> None:
    skill = activation["skills_info"]
    _expect(
        skill["name"] == "template-skill"
        and skill["file_path"] == _RESOLVED_FILE
        and skill["eligible"] is True
        and skill["model_visible"] is True
        and skill["blocked_by_agent_filter"] is False,
        "installed skill was not model visible",
    )
    provider = activation["provider"]
    expected_prompt = (
        "<available_skills>\n"
        "  <skill>\n"
        "    <name>template-skill</name>\n"
        "    <description>Replace with description of the skill and when "
        "Claude should use it.</description>\n"
        f"    <location>{_RESOLVED_FILE}</location>\n"
        "    <version>sha256:eb685d91de039ed8</version>\n"
        "  </skill>\n"
        "</available_skills>"
    )
    _expect(
        provider["request_count"] == 2
        and [item["sequence"] for item in provider["requests"]] == [1, 2]
        and provider["prompt_block"] == expected_prompt
        and provider["prompt_block_digest"] == _sha(expected_prompt.encode()),
        "model prompt or provider sequence changed",
    )
    _verify_tool_bytes(provider, "provider tool result")
    turn = activation["turn"]
    _expect(
        turn["run_id"] == "aragorn-coordinator-activation-v1"
        and turn["send_status"] == "started"
        and turn["wait_status"] == "ok"
        and turn["session_status"] == "done"
        and turn["history_roles"]
        == ["user", "assistant", "toolResult", "assistant"]
        and turn["tool_name"] == "read"
        and turn["tool_path"] == _ACTIVE_FILE
        and turn["tool_is_error"] is False
        and turn["final_text"] == "ARAGORN_EXACT_ACTIVATION_OK"
        and activation["target_unchanged"] is True,
        "actual Gateway/model/tool turn changed",
    )
    _verify_tool_bytes(turn, "Gateway tool result")
    gateway = activation["gateway"]
    _expect(
        gateway["process"]["cmdline"] == ["openclaw-gateway"]
        and gateway["process"]["pid"] == 1
        and gateway["process"]["uid"] == 1000
        and gateway["system_info"]
        == {
            "arch": "arm64",
            "node_version": "v24.16.0",
            "pid": 1,
            "platform": "linux",
            "port": 18789,
        }
        and gateway["log"]["ready_count"] == 1
        and gateway["log"]["restart_count"] == 0
        and gateway["log"]["contains_test_token"] is False
        and gateway["log"]["contains_mock_key"] is False,
        "Gateway boundary changed",
    )


def _verify_tool_bytes(value: Mapping[str, Any], label: str) -> None:
    content = value["tool_content"]
    raw = content.encode()
    _expect(
        content == _SKILL
        and value["tool_content_bytes"] == len(raw)
        and value["tool_content_digest"] == _sha(raw) == _SKILL_DIGEST,
        f"{label} exact bytes changed",
    )


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(
            f"invalid coordinator runtime activation evidence: {message}"
        )
