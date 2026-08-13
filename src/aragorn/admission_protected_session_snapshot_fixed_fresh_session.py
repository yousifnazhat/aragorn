"""Qualify one exact fresh-session reset on the private fixed runtime."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_session_snapshot_fixed as fixed
from . import admission_protected_session_snapshot_fixed_routes as parent
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/fresh-session-reset"
_EVIDENCE_DIGEST = (
    "sha256:c009f9589c7d7460a06252dd501a5f0f207ad7d786ea9f5b6d8e5da5da5d67a2"
)
_EVIDENCE_CANONICAL_DIGEST = (
    "sha256:f51c36408f0b8397cb625631bf39bef9dedaf1a4a6ec1c0e69121769c7488bed"
)
_EVIDENCE_BYTES = 25_301
_RECEIPT_DIGEST = (
    "sha256:ae3bb7b9612274db1f0a7b0d1e32743f71a431be67b3777e6a78fc0854595f4c"
)
_PARENT_DIGEST = (
    "sha256:142f760b47fc58299a30c3c1c4046767c44f9dd3e23df3b659dcbf04a7566917"
)
_IMPLEMENTATION_DIGEST = (
    "sha256:72e4ae79a6ee3370e49a465ef1ecd440f42997e4a2555bf64f461e848f5a0c4c"
)
_BOUNDARY_DIGEST = (
    "sha256:221e8a2de814e73afa38a1422877042c813a6de9a4b1cea23062b9a1df8be0c7"
)
_ACTION_DIGEST = (
    "sha256:1e0a604dab79c7d2fadb385ee664ea69e65e641be1da9677fe10878df1187054"
)
_PROMPT_DIGEST = (
    "sha256:bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c"
)
_PROMPT_PATH = "/profile/state/agents/main/sessions/skills-prompts/sha256/bb/bb2e3d95728d097c858779c1d4d8d90e00f6e14d0151ca5af56f475a6fa6301c.txt"
_SESSION_KEY = "agent:main:aragorn-protected-routes-v1"
_RECORDED_AT = "2026-08-13T06:32:30.937Z"
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_LIMITATIONS = [
    "PRIVATE_FIXED_SOURCE_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SEVEN_EXACT_PINNED_ROUTE_PASSES_ONLY",
    "FRESH_SESSION_RESET_INVALIDATION_AND_EXACT_PROTECTED_SNAPSHOT_REBUILD_ONLY",
    "RESET_REPLY_COMPLETION_NOT_RETAINED_OR_CLAIMED",
    "RESET_REPLY_DISPATCH_ERRORED_OUTSIDE_RETAINED_ROUTE_CLAIM",
    "MODEL_TURNS_FAILED_NO_SUCCESSFUL_MODEL_OR_REPLY_DELIVERY_CLAIM",
    "FULL_RUNTIME_TREE_NOT_REHASHED_BY_THIS_CAPTURE",
    "FOURTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_session_snapshot_fixed_fresh_session(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    parent_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Add the exact fresh-session reset PASS to the frozen six-route result."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        qualified = _snapshot(parent_qualification)
        if canonical_digest(profile) != fixed._PROFILE_CANONICAL_DIGEST:
            raise AdmissionEvidenceError("fixed profile changed")
        if canonical_digest(lock) != fixed._RUNTIME_LOCK_CANONICAL_DIGEST:
            raise AdmissionEvidenceError("fixed runtime lock changed")
        _verify_parent(qualified, profile)
        evidence = _read_evidence(evidence_cas)
        _verify_receipt(receipt, evidence)
        _verify_evidence(evidence)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid fixed fresh-session evidence: {exc}"
        ) from exc

    result = copy.deepcopy(qualified)
    for route in result["profile"]["routes"]:
        if route["id"] == _ROUTE:
            route["status"] = "PASS"
            break
    else:
        raise AdmissionEvidenceError("fresh-session route missing")
    result.update(
        {
            "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_FIXED_FRESH_SESSION_ROUTE_COVERAGE_ONLY",
            "bindings": {
                "fresh_session_capture_digest": _EVIDENCE_DIGEST,
                "fresh_session_receipt_canonical_digest": _RECEIPT_DIGEST,
                "parent_qualification_canonical_digest": _PARENT_DIGEST,
                "profile_digest": fixed._PROFILE_DIGEST,
                "runtime_lock_digest": fixed._RUNTIME_LOCK_DIGEST,
                "runtime_tree_digest": fixed._RUNTIME_TREE["tree_digest"],
                "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
            },
            "limitations": list(_LIMITATIONS),
            "schema": "aragorn/admission-protected-session-snapshot-fixed-fresh-session-route-coverage/v1",
            "source_recorded_at": evidence["recorded_at"],
        }
    )
    result["profile"]["counts"] = {"fail": 0, "not_tested": 14, "pass": 7}
    return result


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(canonical_json(value))


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read_evidence(cas: CAS) -> dict[str, Any]:
    raw = cas.read(_EVIDENCE_DIGEST, max_bytes=_EVIDENCE_BYTES)
    if len(raw) != _EVIDENCE_BYTES or _digest(raw) != _EVIDENCE_DIGEST:
        raise AdmissionEvidenceError("fresh-session raw identity changed")
    try:
        evidence = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid fresh-session JSON: {exc}") from exc
    if (
        not isinstance(evidence, dict)
        or canonical_json(evidence) + b"\n" != raw
        or canonical_digest(evidence) != _EVIDENCE_CANONICAL_DIGEST
    ):
        raise AdmissionEvidenceError("fresh-session parsed identity changed")
    return evidence


def _verify_parent(qualified: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    statuses = {item["id"]: item["status"] for item in qualified["profile"]["routes"]}
    if (
        canonical_digest(qualified) != _PARENT_DIGEST
        or qualified["schema"]
        != "aragorn/admission-protected-session-snapshot-fixed-route-coverage/v1"
        or qualified["profile"]["counts"] != {"fail": 0, "not_tested": 15, "pass": 6}
        or list(statuses.values()).count("PASS") != 6
        or statuses.get(_ROUTE) != "NOT_TESTED"
        or qualified["runtime"] != profile["runtime"]
        or any(
            value is not False
            for key, value in qualified["decision"].items()
            if key != "status"
        )
    ):
        raise AdmissionEvidenceError("six-route parent qualification changed")


def _verify_receipt(receipt: Mapping[str, Any], evidence: Mapping[str, Any]) -> None:
    false_fields = (
        "admission_profile_eligible",
        "aggregate_admission_eligible",
        "edr_eligible",
        "installer_work_eligible",
        "phase3_exit_eligible",
        "release_eligible",
        "run_01_eligible",
        "run_02_eligible",
        "run_eligible",
    )
    expected_evidence = {
        "bytes": _EVIDENCE_BYTES,
        "canonical_digest": _EVIDENCE_CANONICAL_DIGEST,
        "canonical_lf": True,
        "path": "benchmark/evidence/openclaw-v2026.7.1-protected-fresh-session-fixed-2026-08-13.json",
        "raw_sha256": _EVIDENCE_DIGEST.removeprefix("sha256:"),
        "run_nonce": evidence["run_nonce"],
        "schema": evidence["schema"],
    }
    if (
        canonical_digest(receipt) != _RECEIPT_DIGEST
        or receipt["schema"]
        != "aragorn/phase3-openclaw-protected-session-snapshot-fixed-fresh-session-reset-retention/v1"
        or receipt["status"] != "OBSERVED"
        or any(receipt[name] is not False for name in false_fields)
        or receipt["evidence"] != expected_evidence
        or receipt["observed_at"] != evidence["recorded_at"]
        or evidence["recorded_at"] != _RECORDED_AT
        or receipt["results"]
        != {"not_tested_count": 20, "observed": [_ROUTE], "pass": []}
        or receipt["runtime"]["commit"] != parent._RUNTIME["commit"]
        or receipt["runtime"]["lock_sha256"]
        != fixed._RUNTIME_LOCK_DIGEST.removeprefix("sha256:")
        or receipt["runtime"]["profile_sha256"]
        != fixed._PROFILE_DIGEST.removeprefix("sha256:")
        or receipt["runtime"]["tree_digest"] != fixed._RUNTIME_TREE["tree_digest"]
        or receipt["implementation"]["probe"]["sha256"]
        != _IMPLEMENTATION_DIGEST.removeprefix("sha256:")
        or receipt["implementation"]["probe"]["volume_matches_materialized_probe"]
        is not True
        or receipt["containment"]["container"]["state"]
        != {
            "dead": False,
            "exit_code": 0,
            "oom_killed": False,
            "restart_count": 0,
            "restarting": False,
            "status": "exited",
        }
    ):
        raise AdmissionEvidenceError("fresh-session retention receipt changed")


def _verify_evidence(evidence: Mapping[str, Any]) -> None:
    if (
        set(evidence)
        != {
            "actions",
            "assurance",
            "implementation_digest",
            "protected_boundary",
            "recorded_at",
            "routes",
            "run_nonce",
            "runtime_binding",
            "schema",
            "selected_route_ids",
        }
        or evidence["recorded_at"] != _RECORDED_AT
        or evidence["schema"]
        != "aragorn/openclaw-protected-route-action-observations/v1"
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["selected_route_ids"] != [_ROUTE]
        or evidence["implementation_digest"] != _IMPLEMENTATION_DIGEST
        or evidence["runtime_binding"] != parent._ROUTE_RUNTIME
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
        or evidence["routes"]
        != [
            {
                "action_id": "fresh-session-reset",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
    ):
        raise AdmissionEvidenceError("fresh-session evidence identity changed")
    boundary = evidence["protected_boundary"]
    if (
        canonical_digest(boundary) != _BOUNDARY_DIGEST
        or boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 1000, "uid": 1000}
    ):
        raise AdmissionEvidenceError("fresh-session protected boundary changed")
    parent._verify_actual_route_boundary(boundary)
    spec = {"route": _ROUTE}
    parent._verify_actual_runtime_and_probe(evidence, spec, route_style=True)

    action = evidence["actions"][0]
    before = action["prerequisites"]
    observations = action["observations"]
    gateway = before["gateway_process"]
    if (
        len(evidence["actions"]) != 1
        or canonical_digest(action) != _ACTION_DIGEST
        or action["id"] != "fresh-session-reset"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["ready"] is not True
        or before["reason_codes"] != []
        or gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "hostname": "3fd3256ebfe1",
            "pid": 1,
            "start_time_ticks": "2479518",
        }
    ):
        raise AdmissionEvidenceError("fresh-session action identity changed")

    initial = observations["initialization_turn"]
    rebuild = observations["rebuild_turn"]
    commands = [*before["commands"], *action["commands"]]
    if (
        action["commands"] != [*initial["commands"], *rebuild["commands"]]
        or initial["commands"]
        != [initial["send"]["command"], initial["wait"]["command"]]
        or rebuild["commands"]
        != [rebuild["send"]["command"], rebuild["wait"]["command"]]
        or initial["confirmed"] is not True
        or rebuild["confirmed"] is not True
        or any(
            not parent.archive.shared._command_succeeded_clean(item)
            for item in commands
        )
        or any(type(item["pid"]) is not int or item["pid"] <= 0 for item in commands)
        or len({item["pid"] for item in commands}) != len(commands)
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
    ):
        raise AdmissionEvidenceError("fresh-session command projection changed")
    _verify_turn(initial, "fresh-session-initialize", evidence["run_nonce"])
    _verify_turn(rebuild, "fresh-session-rebuild", evidence["run_nonce"])
    _verify_transition(observations, evidence["run_nonce"], evidence["recorded_at"])


def _verify_turn(turn: Mapping[str, Any], label: str, nonce: str) -> None:
    run_id = f"aragorn-protected-route-{label}-{nonce}"
    send_value = turn["send"]["response"]
    wait_value = turn["wait"]["response"]
    if (
        send_value != {"parsed": True, "value": {"runId": run_id, "status": "started"}}
        or wait_value["parsed"] is not True
        or wait_value["value"]["runId"] != run_id
        or wait_value["value"]["status"] != "ok"
        or type(wait_value["value"]["endedAt"]) is not int
    ):
        raise AdmissionEvidenceError("fresh-session turn response changed")


def _verify_transition(
    observations: Mapping[str, Any], nonce: str, recorded_at: str
) -> None:
    before = observations["session_before_reset"]
    rotated = observations["session_after_rotation"]
    after = observations["session_after_reset"]
    reset = observations["reset_turn"]
    before_id = before["entry"]["session_id"]
    after_id = after["entry"]["session_id"]
    reset_id = f"aragorn-protected-route-fresh-session-reset-{nonce}"
    if (
        observations["session_id_rotated"] is not True
        or observations["reset_snapshot_cleared"] is not True
        or observations["rebuilt_snapshot_matches_baseline"] is not True
        or observations["session_before_reset_check"] != _READY_CHECK
        or observations["session_after_reset_check"] != _READY_CHECK
        or _UUID4.fullmatch(before_id) is None
        or _UUID4.fullmatch(after_id) is None
        or before_id == after_id
        or rotated["entry"]
        != {
            "ended_at": None,
            "prompt": {"bytes": None, "digest": None, "storage": "absent-or-invalid"},
            "runtime_ms": None,
            "session_id": after_id,
            "skill_names": [],
            "snapshot_present": False,
            "snapshot_version": None,
            "started_at": None,
            "status": None,
            "updated_at": rotated["entry"]["updated_at"],
        }
        or type(rotated["entry"]["updated_at"]) is not int
        or reset
        != {
            "accepted": True,
            "completed_at": reset["completed_at"],
            "error": None,
            "method": "chat.send",
            "params": {
                "deliver": False,
                "idempotencyKey": reset_id,
                "message": "/new",
                "sessionKey": _SESSION_KEY,
                "timeoutMs": 5000,
            },
            "response": {"runId": reset_id, "status": "started"},
            "scopes": ["operator.admin", "operator.write"],
            "started_at": reset["started_at"],
            "transport": "openclaw/plugin-sdk/gateway-runtime.callGatewayFromCli",
        }
    ):
        raise AdmissionEvidenceError("fresh-session reset transition changed")
    _verify_snapshot(before, before_id)
    _verify_snapshot(after, after_id)
    if (
        before["entry"]["snapshot_version"] != after["entry"]["snapshot_version"]
        or before["entry"]["prompt"] != after["entry"]["prompt"]
        or before["entry"]["skill_names"] != after["entry"]["skill_names"]
        or len(
            {
                before["file"]["inode"],
                rotated["file"]["inode"],
                after["file"]["inode"],
            }
        )
        != 3
        or not (
            _time(reset["started_at"])
            <= _time(reset["completed_at"])
            <= _time(observations["rotation_observed_at"])
            <= _time(observations["rebuild_turn"]["send"]["command"]["started_at"])
            <= _time(recorded_at)
        )
    ):
        raise AdmissionEvidenceError("fresh-session custody or timing changed")


_READY_CHECK = {
    "catalog_exact": True,
    "prompt_exact": True,
    "ready": True,
    "session_id_valid": True,
    "snapshot_present": True,
    "snapshot_version_valid": True,
}


def _verify_snapshot(snapshot: Mapping[str, Any], session_id: str) -> None:
    entry = snapshot["entry"]
    prompt = entry["prompt"]
    file = prompt["file"]
    store = snapshot["file"]
    if (
        snapshot["present"] is not True
        or entry["session_id"] != session_id
        or entry["skill_names"] != ["requesting-code-review"]
        or type(entry["snapshot_version"]) is not int
        or entry["snapshot_version"] <= 0
        or entry["status"] != "failed"
        or prompt["storage"] != "promptRef"
        or prompt["bytes"] != 728
        or prompt["digest"] != _PROMPT_DIGEST
        or prompt["expected_digest"] != _PROMPT_DIGEST
        or file
        != {
            "device": file["device"],
            "digest": _PROMPT_DIGEST,
            "digest_error": None,
            "exists": True,
            "gid": 1000,
            "inode": file["inode"],
            "mode": "600",
            "nlink": 1,
            "path": _PROMPT_PATH,
            "size": 728,
            "type": "file",
            "uid": 1000,
        }
        or type(file["device"]) is not int
        or type(file["inode"]) is not int
        or store["path"] != "/profile/state/agents/main/sessions/sessions.json"
        or store["exists"] is not True
        or store["type"] != "file"
        or store["uid"] != 1000
        or store["gid"] != 1000
        or store["mode"] != "600"
        or store["nlink"] != 1
        or store["digest_error"] is not None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", store["digest"]) is None
    ):
        raise AdmissionEvidenceError("fresh-session protected snapshot changed")
