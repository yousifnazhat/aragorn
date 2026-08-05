"""Semantic route closure for the narrow OpenClaw protected-consumer profile."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .admission_evidence import (
    _EMPTY_DIGEST,
    AdmissionEvidenceError,
    _read_exact,
    _time,
    verify_openclaw_restart_evidence,
)
from .admission_routes import validate_openclaw_2026_7_1_route_inventory
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_PROFILE_SCHEMA = "aragorn/admission-runtime-profile/v1"
_PROFILE_NAME = "openclaw-2026.7.1-protected-consumer"
_ASSURANCE = "DECLARED_NARROW_PROFILE_SEMANTICALLY_BOUND_TO_RETAINED_ROOT_INVARIANT"
_CONTROLS = {
    "active_skill_source": "exact-allowlisted-protected-bytes",
    "configuration": "read-only",
    "discovery_roots": "read-only",
    "network": "none",
    "plugins": "disabled",
    "runtime_tree": "read-only",
    "skill_watch": "disabled",
    "update_authority": "external-aragorn-broker-only",
}
_LIMITATIONS = [
    "BROKER_TO_RUNTIME_ACTIVATION_NOT_COMPOSED",
    "CONTAINED_PROFILE_HAS_NO_PROVIDER_NETWORK",
    "DOCKER_CONTROL_PLANE_SELF_REPORTED",
    "ROUTE_RESULTS_DERIVED_FROM_SHARED_ROOT_INVARIANT_NOT_ROUTE_BY_ROUTE_EXECUTION",
]
_ROUTE_CONTROLS = {
    "ADM-02/update/archive-source-force-replacement": (
        "discovery_roots",
        "update_authority",
    ),
    "ADM-02/update/clawhub-tracked-replacement": (
        "discovery_roots",
        "network",
        "update_authority",
    ),
    "ADM-02/update/config-entry-activation": (
        "active_skill_source",
        "configuration",
    ),
    "ADM-02/update/core-updater-plugin-replacement": (
        "plugins",
        "runtime_tree",
        "update_authority",
    ),
    "ADM-02/update/curator-restore-activation": (
        "discovery_roots",
        "update_authority",
    ),
    "ADM-02/update/plugin-enable-activation": (
        "configuration",
        "plugins",
    ),
    "ADM-02/update/plugin-force-reinstall": (
        "discovery_roots",
        "plugins",
        "update_authority",
    ),
    "ADM-02/update/plugin-package-skill-replacement": (
        "discovery_roots",
        "plugins",
        "update_authority",
    ),
    "ADM-02/update/workshop-proposal-apply": (
        "discovery_roots",
        "update_authority",
    ),
    "ADM-02/reload/chat-session-snapshot-consumer": ("active_skill_source",),
    "ADM-02/reload/config-invalidation": (
        "active_skill_source",
        "configuration",
    ),
    "ADM-02/reload/cron-rescan": ("active_skill_source",),
    "ADM-02/reload/filesystem-watch-invalidation": (
        "active_skill_source",
        "skill_watch",
    ),
    "ADM-02/reload/fresh-session-reset": ("active_skill_source",),
    "ADM-02/reload/manual-plugin-invalidation": (
        "active_skill_source",
        "plugins",
    ),
    "ADM-02/reload/missing-prompt-blob-rebuild": ("active_skill_source",),
    "ADM-02/reload/plugin-skill-dir-activation": (
        "active_skill_source",
        "plugins",
    ),
    "ADM-02/reload/remote-eligibility-invalidation": (
        "active_skill_source",
        "network",
    ),
    "ADM-02/reload/sandbox-per-run-rescan": ("active_skill_source",),
    "ADM-02/reload/session-snapshot-consumer": ("active_skill_source",),
    "ADM-02/reload/workshop-invalidation": (
        "active_skill_source",
        "discovery_roots",
    ),
}
_RESTART_EVIDENCE = sorted(
    (
        "sha256:e67b2522a705d9f9efbd447da68aae61af6964f51dd9275d2d956688389ebbfa",
        "sha256:f9b08c63b414b0f91b5cc14deeb91a86a8a0b4aa3151e52702395004dde7dcb3",
    )
)
_PROTECTED_ROUTE_SCHEMA = "aragorn/openclaw-protected-route-action-observations/v1"
_PROTECTED_ROUTE_EVIDENCE_DIGEST = (
    "sha256:1128d1b2f56dbee6a871edbdeb4c414d3f1196d8adef923005e095c6d5ec69b5"
)
_PROTECTED_ROUTE_RECEIPT_CANONICAL_DIGEST = (
    "sha256:723b4b759b3e706b4110b993275522a51f1754f4bb50a8fdca226add8fdcfc36"
)
_PROTECTED_ROUTE_PROBE_DIGEST = (
    "sha256:3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504"
)
_PROTECTED_ROUTE_CONFIG_DIGEST = (
    "sha256:ec2b2022ed27f62840583d31264826c88514a04e7e7cc94d78820b021d6288b6"
)
_PROTECTED_ROUTE_CONFIG_CANONICAL_DIGEST = (
    "sha256:6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a"
)
_PROTECTED_WORKSHOP_PROPOSAL_DIGEST = (
    "sha256:a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a"
)
_PROTECTED_WORKSHOP_ROUTE = "ADM-02/update/workshop-proposal-apply"
_PROTECTED_WORKSHOP_PROPOSAL = (
    b"# Aragorn protected workshop route fixture\n\n"
    b"This inert fixture performs no actions.\n"
)
_PROTECTED_ROOTS = {
    "extensions": (
        "/profile/state/extensions",
        "/var/lib/aragorn-protected/extensions",
    ),
    "managed_skills": (
        "/profile/state/skills",
        "/var/lib/aragorn-protected/skills",
    ),
    "personal_agents": (
        "/profile/home/.agents/skills",
        "/var/lib/aragorn-protected/home-agent-skills",
    ),
    "plugin_skills": (
        "/profile/state/plugin-skills",
        "/var/lib/aragorn-protected/plugin-skills",
    ),
    "project_agents": (
        "/profile/workspace/.agents/skills",
        "/var/lib/aragorn-protected/workspace-agent-skills",
    ),
    "workspace_skills": (
        "/profile/workspace/skills",
        "/var/lib/aragorn-protected/workspace-skills",
    ),
}
_WORKSHOP_TARGET = "/profile/workspace/skills/aragorn-protected-workshop"
_WORKSHOP_QUALIFICATION_LIMITATIONS = [
    "EXACT_PINNED_PROFILE_AND_CAPTURE_ONLY",
    "NATIVE_WORKSHOP_ROUTE_DENIED_NOT_BROKER_MEDIATED",
    "RAW_VM_ENVIRONMENT_NOT_INDEPENDENTLY_ATTESTED",
    "OTHER_ADMISSION_ROUTES_NOT_QUALIFIED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "PHASE3_RUN_AND_EDR_AUTHORITY_NOT_ESTABLISHED",
]


def validate_openclaw_protected_consumer_profile(
    profile: Mapping[str, Any],
    *,
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> None:
    """Validate the exact narrow profile without granting runtime conformance."""

    validate_openclaw_2026_7_1_route_inventory(
        route_inventory,
        runtime_candidates,
    )
    if set(profile) != {
        "assurance",
        "controls",
        "decision",
        "limitations",
        "name",
        "routes",
        "runtime",
        "schema",
    }:
        raise AdmissionEvidenceError("protected-consumer profile shape changed")
    if (
        profile["schema"] != _PROFILE_SCHEMA
        or profile["name"] != _PROFILE_NAME
        or profile["assurance"] != _ASSURANCE
        or profile["controls"] != _CONTROLS
        or profile["limitations"] != _LIMITATIONS
        or profile["decision"]
        != {"installer_work_eligible": False, "status": "NOT_TESTED"}
    ):
        raise AdmissionEvidenceError("protected-consumer profile boundary changed")

    inventory_runtime = route_inventory["runtime"]
    if profile["runtime"] != {
        "commit": inventory_runtime["commit_sha1"],
        "name": "openclaw-contained",
        "source_tree": inventory_runtime["tree_sha1"],
        "version": inventory_runtime["version"],
    }:
        raise AdmissionEvidenceError("protected-consumer runtime binding changed")

    inventory_routes = [
        f"{route['id']}/{path['id']}"
        for route in route_inventory["routes"]
        for path in route["paths"]
    ]
    expected_routes = [
        {
            "controls": list(controls),
            "id": route_id,
            "outcome": (
                "DENIED"
                if route_id.startswith("ADM-02/update/")
                else "PROTECTED_BYTES_ONLY"
            ),
        }
        for route_id, controls in _ROUTE_CONTROLS.items()
    ]
    if inventory_routes != list(_ROUTE_CONTROLS):
        raise AdmissionEvidenceError("protected-consumer inventory coverage changed")
    if profile["routes"] != expected_routes:
        raise AdmissionEvidenceError("protected-consumer route mediation changed")


def verify_openclaw_protected_consumer_routes(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Retain exact route coverage without promoting unexecuted scenarios."""

    validate_openclaw_protected_consumer_profile(
        route_profile,
        route_inventory=route_inventory,
        runtime_candidates=runtime_candidates,
    )
    verify_openclaw_restart_evidence(source_receipt, evidence_cas=evidence_cas)

    runtime = source_receipt["bindings"]["runtime"]
    profile_runtime = route_profile["runtime"]
    if (
        runtime["name"] != profile_runtime["name"]
        or runtime["version"] != profile_runtime["version"]
        or runtime["commit"] != profile_runtime["commit"]
    ):
        raise AdmissionEvidenceError(
            "protected-consumer source receipt runtime changed"
        )

    raw_profile = canonical_json(dict(route_profile)) + b"\n"
    profile_digest = "sha256:" + hashlib.sha256(raw_profile).hexdigest()
    try:
        if evidence_cas.read(profile_digest, max_bytes=128 * 1024) != raw_profile:
            raise AdmissionEvidenceError(
                "retained protected-consumer profile bytes changed"
            )
    except CASError as exc:
        raise AdmissionEvidenceError(
            "protected-consumer profile is not retained"
        ) from exc

    return {
        "evidence_digests": sorted((*_RESTART_EVIDENCE, profile_digest)),
        "installer_work_eligible": False,
        "limitations": list(_LIMITATIONS),
        "profile": _PROFILE_NAME,
        "scenario_statuses": {
            route["id"]: route["status"] for route in route_inventory["routes"]
        },
    }


def verify_openclaw_protected_workshop_route(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Qualify one exact native workshop denial without promoting the profile."""

    try:
        validate_openclaw_protected_consumer_profile(
            route_profile,
            route_inventory=route_inventory,
            runtime_candidates=runtime_candidates,
        )
        if (
            canonical_digest(source_receipt)
            != _PROTECTED_ROUTE_RECEIPT_CANONICAL_DIGEST
        ):
            raise AdmissionEvidenceError("protected-route retention receipt changed")

        evidence = _read_exact(
            evidence_cas,
            _PROTECTED_ROUTE_EVIDENCE_DIGEST,
            _PROTECTED_ROUTE_SCHEMA,
        )
        profile_raw = canonical_json(dict(route_profile)) + b"\n"
        profile_digest = "sha256:" + hashlib.sha256(profile_raw).hexdigest()
        _read_source_bytes(
            evidence_cas,
            profile_digest,
            len(profile_raw),
            "protected-consumer profile",
        )
        _read_source_bytes(
            evidence_cas,
            _PROTECTED_ROUTE_PROBE_DIGEST,
            source_receipt["inputs"]["probe"]["bytes"],
            "protected-route probe",
        )
        config_raw = _read_source_bytes(
            evidence_cas,
            _PROTECTED_ROUTE_CONFIG_DIGEST,
            source_receipt["inputs"]["configuration"]["bytes"],
            "protected-route configuration",
        )
        proposal_raw = _read_source_bytes(
            evidence_cas,
            _PROTECTED_WORKSHOP_PROPOSAL_DIGEST,
            source_receipt["inputs"]["workshop_proposal"]["bytes"],
            "protected workshop proposal",
        )
        _verify_protected_route_source_closure(
            source_receipt,
            evidence,
            config_raw=config_raw,
            proposal_raw=proposal_raw,
        )
        _verify_protected_boundary(evidence["protected_boundary"])
        _verify_protected_workshop_action(evidence, source_receipt)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid protected workshop route evidence: {exc}"
        ) from exc

    return {
        "assurance": "SEMANTICALLY_VERIFIED_EXACT_PROFILE_PRE_EFFECT_DENIAL",
        "bindings": {
            "configuration_digest": _PROTECTED_ROUTE_CONFIG_DIGEST,
            "profile_digest": profile_digest,
            "proposal_digest": _PROTECTED_WORKSHOP_PROPOSAL_DIGEST,
            "source_evidence_digest": _PROTECTED_ROUTE_EVIDENCE_DIGEST,
            "source_receipt_canonical_digest": (
                _PROTECTED_ROUTE_RECEIPT_CANONICAL_DIGEST
            ),
            "verifier_implementation_digest": (
                "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            ),
        },
        "decision": {
            "admission_profile_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "status": "ROUTE_PASS",
        },
        "limitations": list(_WORKSHOP_QUALIFICATION_LIMITATIONS),
        "profile": _PROFILE_NAME,
        "route": {
            "id": _PROTECTED_WORKSHOP_ROUTE,
            "observed_outcome": "DENIED_PRE_EFFECT",
            "status": "PASS",
        },
        "runtime": dict(route_profile["runtime"]),
        "schema": "aragorn/admission-protected-route-qualification/v1",
        "source_recorded_at": evidence["recorded_at"],
    }


def _read_source_bytes(
    evidence_cas: CAS,
    digest: str,
    expected_bytes: int,
    label: str,
) -> bytes:
    try:
        raw = evidence_cas.read(digest, max_bytes=expected_bytes)
    except CASError as exc:
        raise AdmissionEvidenceError(f"{label} is not retained") from exc
    if len(raw) != expected_bytes:
        raise AdmissionEvidenceError(f"{label} size changed")
    return raw


def _verify_protected_route_source_closure(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    config_raw: bytes,
    proposal_raw: bytes,
) -> None:
    inputs = receipt["inputs"]
    containment = receipt["containment"]
    expected_roots = sorted(
        [path for path, _ in _PROTECTED_ROOTS.values()] + ["/runtime"]
    )
    if (
        receipt["schema"]
        != "aragorn/phase1-openclaw-protected-route-action-retention/v1"
        or receipt["assurance"]
        != "OPERATOR_RETAINED_RAW_OBSERVATIONS_NOT_CONFORMANCE_AUTHORITY"
        or receipt["status"] != "RAW_OBSERVATIONS_ONLY"
        or receipt["installer_work_eligible"] is not False
        or receipt["phase1_exit_eligible"] is not False
        or receipt["evidence"]["digest"] != _PROTECTED_ROUTE_EVIDENCE_DIGEST
        or receipt["evidence"]["bytes"] != 96_420
        or receipt["evidence"]["recorded_at"] != evidence["recorded_at"]
        or receipt["evidence"]["run_nonce"] != evidence["run_nonce"]
        or inputs["probe"]["digest"] != _PROTECTED_ROUTE_PROBE_DIGEST
        or inputs["configuration"]["raw_digest"]
        != _PROTECTED_ROUTE_CONFIG_DIGEST
        or inputs["configuration"]["canonical_digest"]
        != _PROTECTED_ROUTE_CONFIG_CANONICAL_DIGEST
        or inputs["workshop_proposal"]["digest"]
        != _PROTECTED_WORKSHOP_PROPOSAL_DIGEST
        or containment["effective_user"] != "1000:1000"
        or containment["explicit_read_only_roots"] != expected_roots
        or containment["capabilities_dropped"] != ["ALL"]
        or containment["network_mode"] != "none"
        or containment["no_new_privileges"] is not True
        or containment["privileged"] is not False
        or containment["protected_boundary_ready"] is not True
        or containment["read_only_root_filesystem"] is not True
        or containment["restart_count_after"] != 0
    ):
        raise AdmissionEvidenceError("protected-route source closure changed")

    config = load_runtime_profile(config_raw)
    if (
        canonical_json(config) + b"\n" != config_raw
        or canonical_digest(config) != _PROTECTED_ROUTE_CONFIG_CANONICAL_DIGEST
        or proposal_raw != _PROTECTED_WORKSHOP_PROPOSAL
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["implementation_digest"] != _PROTECTED_ROUTE_PROBE_DIGEST
        or evidence["runtime_binding"]
        != {
            "commit": "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": (
                "sha256:"
                "f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
            ),
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "version": "2026.7.1",
        }
    ):
        raise AdmissionEvidenceError("protected-route source identity changed")


def _verify_protected_boundary(boundary: Mapping[str, Any]) -> None:
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 1000, "uid": 1000}
        or set(boundary["roots"]) != set(_PROTECTED_ROOTS)
    ):
        raise AdmissionEvidenceError("protected discovery boundary changed")

    for name, (target, source) in _PROTECTED_ROOTS.items():
        mount = boundary["roots"][name]
        _verify_exact_ro_mount(
            mount,
            target=target,
            source=source,
            entry_type="directory",
            uid=0,
            gid=982,
            mode="750",
            label=f"protected {name}",
        )
        if name != "managed_skills" and mount["entry"]["entry_count"] != 0:
            raise AdmissionEvidenceError(f"protected {name} guard is not empty")

    configuration = boundary["configuration"]
    runtime = boundary["runtime"]
    _verify_exact_ro_mount(
        configuration["mount"],
        target="/profile/config.json",
        source="/etc/aragorn/openclaw-protected-route-v1.json",
        entry_type="file",
        uid=0,
        gid=982,
        mode="440",
        label="protected configuration",
    )
    _verify_exact_ro_mount(
        runtime,
        target="/runtime",
        source=(
            "/var/lib/docker/volumes/"
            "aragorn-openclaw-2026-7-1-runtime-v2/_data"
        ),
        entry_type="directory",
        uid=0,
        gid=0,
        mode="755",
        label="protected runtime",
    )
    if (
        configuration["ready"] is not True
        or configuration["canonical_digest"]
        != _PROTECTED_ROUTE_CONFIG_CANONICAL_DIGEST
        or any(
            configuration["file"].get(key) != value
            for key, value in configuration["mount"]["entry"].items()
        )
        or configuration["file"]["digest"] != _PROTECTED_ROUTE_CONFIG_DIGEST
        or configuration["file"]["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("protected configuration or runtime changed")


def _verify_exact_ro_mount(
    mount: Mapping[str, Any],
    *,
    target: str,
    source: str,
    entry_type: str,
    uid: int,
    gid: int,
    mode: str,
    label: str,
) -> None:
    records = mount["records"]
    entry = mount["entry"]
    if (
        mount["path"] != target
        or mount["explicit"] is not True
        or mount["read_only"] is not True
        or mount["ready"] is not True
        or mount["error"] is not None
        or len(records) != 1
        or records[0]["mount_point"] != target
        or records[0]["root"] != source
        or records[0]["filesystem"] != "ext4"
        or records[0]["source"] != "/dev/vda1"
        or "ro" not in records[0]["mount_options"]
        or "rw" in records[0]["mount_options"]
        or entry["path"] != target
        or entry["exists"] is not True
        or entry["type"] != entry_type
        or entry["uid"] != uid
        or entry["gid"] != gid
        or entry["mode"] != mode
    ):
        raise AdmissionEvidenceError(f"{label} read-only mount changed")


def _verify_protected_workshop_action(
    evidence: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> None:
    routes = [
        route
        for route in evidence["routes"]
        if route["id"] == _PROTECTED_WORKSHOP_ROUTE
    ]
    actions = [
        action
        for action in evidence["actions"]
        if action["id"] == "workshop-protected-apply"
    ]
    if (
        len(routes) != 1
        or routes[0]
        != {
            "action_id": "workshop-protected-apply",
            "id": _PROTECTED_WORKSHOP_ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or len(actions) != 1
    ):
        raise AdmissionEvidenceError("protected workshop route selection changed")

    action = actions[0]
    commands = action["commands"]
    prerequisites = action["prerequisites"]
    observations = action["observations"]
    gateway = prerequisites["gateway_process"]
    system_info = prerequisites["system_info"]["response"]
    prerequisite_commands = prerequisites["commands"]
    runtime_files = prerequisites["runtime_files"]
    runtime = receipt["runtime"]
    expected_target = {
        "directory": {"exists": False, "path": _WORKSHOP_TARGET},
        "skill": {"exists": False, "path": f"{_WORKSHOP_TARGET}/SKILL.md"},
    }
    if (
        action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or len(commands) != 4
        or prerequisites["ready"] is not True
        or prerequisites["reason_codes"] != []
        or len(prerequisite_commands) != 2
        or prerequisite_commands[0]["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ]
        or prerequisite_commands[0]["exit_code"] != 0
        or prerequisite_commands[0]["stdout_digest"]
        != "sha256:9e98975ff3973bcd88f224e1820a177c3c881f7a46b51b7dc5ec5d050f72607f"
        or prerequisite_commands[1] != prerequisites["system_info"]["command"]
        or runtime_files["node"]["executable"] is not True
        or runtime_files["node"]["file"]["path"] != "/usr/local/bin/node"
        or runtime_files["openclaw"]["executable"] is not True
        or runtime_files["openclaw"]["file"]["path"]
        != "/runtime/lib/node_modules/openclaw/openclaw.mjs"
        or runtime_files["openclaw"]["file"]["digest"]
        != receipt["runtime"]["openclaw_digest"]
        or runtime_files["openclaw"]["file"]["uid"] != 0
        or runtime_files["openclaw"]["file"]["mode"] != "755"
        or gateway["cmdline"] != ["openclaw-gateway"]
        or gateway["pid"] != runtime["gateway_pid"] == 1
        or gateway["start_time_ticks"] != runtime["gateway_start_time_ticks"]
        or gateway["hostname"] != runtime["container_id"][:12]
        or system_info["parsed"] is not True
        or system_info["value"]["pid"] != gateway["pid"]
        or system_info["value"]["hostname"] != gateway["hostname"]
        or prerequisites["target_before"] != expected_target
        or observations["target_after"] != expected_target
        or observations["discovery_before"]["parsed"] is not True
        or observations["discovery_before"]["target_matches"] != []
        or observations["discovery_after"]["parsed"] is not True
        or observations["discovery_after"]["target_matches"] != []
    ):
        raise AdmissionEvidenceError("protected workshop pre-effect state changed")

    draft = prerequisites["draft"]
    _verify_exact_ro_mount(
        draft["mount"],
        target="/profile/workspace/PROPOSAL.md",
        source="/var/lib/aragorn-route-probe/PROPOSAL.md",
        entry_type="file",
        uid=0,
        gid=0,
        mode="444",
        label="protected workshop proposal",
    )
    if (
        draft["expected_digest"] != _PROTECTED_WORKSHOP_PROPOSAL_DIGEST
        or draft["observation"]["digest"] != _PROTECTED_WORKSHOP_PROPOSAL_DIGEST
        or draft["observation"]["digest_error"] is not None
        or any(
            draft["observation"].get(key) != value
            for key, value in draft["mount"]["entry"].items()
        )
    ):
        raise AdmissionEvidenceError("protected workshop proposal changed")

    proposal_id = observations["proposal_result"]["proposal_id"]
    before_command, proposal_command, action_command, after_command = commands
    apply = observations["native_apply_result"]
    command = apply["command"]
    response = apply["response"]
    proposal = json.loads(proposal_command["stdout_excerpt"])
    proposal_record = proposal["record"]
    expected_content = (
        "---\n"
        'name: "aragorn-protected-workshop"\n'
        'description: "Inert Aragorn protected workshop fixture"\n'
        "status: proposal\n"
        'version: "v1"\n'
        f'date: "{proposal_record["createdAt"]}"\n'
        "---\n\n"
    ).encode() + _PROTECTED_WORKSHOP_PROPOSAL
    status_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "skills.status",
        "--json",
        "--timeout",
        "5000",
    ]
    expected_error = {
        "code": "INVALID_REQUEST",
        "message": (
            "path is not a regular file under root | EROFS: read-only file system, "
            f"mkdir '{_WORKSHOP_TARGET}' | EROFS"
        ),
        "retryable": False,
        "type": "gateway_request_error",
    }
    if (
        observations["proposal_result"]["parsed"] is not True
        or re.fullmatch(
            r"aragorn-protected-workshop-[0-9]{8}-[0-9a-f]{10}",
            proposal_id,
        )
        is None
        or proposal_command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "skills",
            "workshop",
            "--agent",
            "main",
            "propose-create",
            "--name",
            "aragorn-protected-workshop",
            "--description",
            "Inert Aragorn protected workshop fixture",
            "--proposal",
            "/profile/workspace/PROPOSAL.md",
            "--json",
        ]
        or proposal_command["exit_code"] != 0
        or proposal_command["error"] is not None
        or proposal_command["signal"] is not None
        or not _command_output_is_exact(proposal_command)
        or proposal_record["id"] != proposal_id
        or proposal_record["kind"] != "create"
        or proposal_record["status"] != "pending"
        or proposal_record["scan"]["state"] != "clean"
        or proposal_record["target"]["skillDir"] != _WORKSHOP_TARGET
        or proposal_record["target"]["skillFile"]
        != f"{_WORKSHOP_TARGET}/SKILL.md"
        or proposal_record["target"]["source"] != "openclaw-workspace"
        or proposal["content"].encode() != expected_content
        or proposal_record["draftHash"]
        != hashlib.sha256(expected_content).hexdigest()
        or before_command != observations["discovery_before"]["command"]
        or action_command != command
        or after_command != observations["discovery_after"]["command"]
        or before_command["argv"] != status_argv
        or after_command["argv"] != status_argv
        or not _command_succeeded_clean(before_command)
        or not _command_succeeded_clean(after_command)
        or before_command["stdout_digest"] != after_command["stdout_digest"]
        or command["argv"][:-1]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "skills.proposals.apply",
            "--json",
            "--timeout",
            "5000",
            "--params",
        ]
        or json.loads(command["argv"][-1])
        != {"agentId": "main", "proposalId": proposal_id}
        or command["exit_code"] != 1
        or command["error"] is not None
        or command["signal"] is not None
        or not _command_output_is_exact(command)
        or response != {"parsed": True, "value": {"error": expected_error, "ok": False}}
        or json.loads(command["stdout_excerpt"]) != response["value"]
        or _time(before_command["completed_at"])
        > _time(proposal_command["started_at"])
        or _time(proposal_command["completed_at"]) > _time(command["started_at"])
        or _time(command["started_at"]) >= _time(command["completed_at"])
        or _time(command["completed_at"])
        > _time(after_command["started_at"])
        or _time(after_command["completed_at"]) > _time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("protected workshop denial changed")


def _command_output_is_exact(command: Mapping[str, Any]) -> bool:
    stdout = command["stdout_excerpt"].encode()
    return (
        command["stdout_bytes"] == len(stdout)
        and command["stdout_digest"]
        == "sha256:" + hashlib.sha256(stdout).hexdigest()
        and command["stderr_bytes"] == 0
        and command["stderr_excerpt"] == ""
        and command["stderr_digest"] == _EMPTY_DIGEST
    )


def _command_succeeded_clean(command: Mapping[str, Any]) -> bool:
    return (
        command["exit_code"] == 0
        and command["error"] is None
        and command["signal"] is None
        and command["stderr_bytes"] == 0
        and command["stderr_excerpt"] == ""
        and command["stderr_digest"] == _EMPTY_DIGEST
    )


def load_runtime_profile(raw: bytes) -> dict[str, Any]:
    """Load one profile while rejecting duplicate keys and non-objects."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise AdmissionEvidenceError(
                    f"duplicate protected-consumer profile key: {key}"
                )
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                AdmissionEvidenceError(
                    f"invalid protected-consumer JSON constant: {value}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(
            f"protected-consumer profile is invalid JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise AdmissionEvidenceError("protected-consumer profile must be an object")
    return value
