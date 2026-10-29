"""Qualify the V2 native chat snapshot subsequence from the shared capture."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import (
    admission_protected_final_combined_v2_session_snapshot_consumer_catalog_fixed as parent,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/reload/chat-session-snapshot-consumer"
_SOURCE_ROUTE = "ADM-02/reload/session-snapshot-consumer"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_PROTECTED_PROMPT_DIGEST = (
    "sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501"
)
_NETWORK_ERROR = (
    "⚠️ Agent failed before reply: LLM request failed: network connection error.\n"
    "Logs: openclaw logs --follow"
)
_PARENT_SOURCE = {
    "commit": "7fbb3b9d39e87f420bfa2e83281c18a5fa5fc2f8",
    "parent": "e8d03213208379adf3f87b1c0d674b683bf5ca8c",
    "tree": "e315a9dcf3578eb4c447bec28148483ed96d8d01",
}
_PARENT_MODULE = {
    "blob": "69ef81eb55b314a5bfe3501ead08fc283b134465",
    "bytes": 61_014,
    "digest": (
        "sha256:9f8c14d6c109bf0b2d686c354af64b0d65dd70ac5a34f405051f37bfa55dfcfa"
    ),
    "path": (
        "src/aragorn/admission_protected_final_combined_v2_session_snapshot_"
        "consumer_catalog_fixed.py"
    ),
}
_PARENT_RECEIPT = {
    "blob": "8261b8fe8e31440ab88d0867d05443bc204c1869",
    "bytes": 8_685,
    "digest": (
        "sha256:3bbbb88b8f69acb14f6a5c1cbcaa5b3c65d4271dc01e803d11a21b62a86e3c2e"
    ),
    "path": (
        "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-session-"
        "snapshot-consumer-catalog-fixed-route-coverage-v1-2026-08-22.json"
    ),
}
_PARENT_RESULT_DIGEST = (
    "sha256:a8b82efd6195ece5f00d2770c6778378305017318017d4d2419fd524f77d3315"
)


def verify_openclaw_final_combined_v2_chat_session_snapshot_consumer_catalog_fixed(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return only the shared-capture native chat PASS as exact 1/20 coverage."""

    try:
        signed_parent = _verify_parent_source()
        qualification = parent.verify_openclaw_final_combined_v2_session_snapshot_consumer_catalog_fixed(
            evidence_cas=evidence_cas
        )
        _verify_parent_result(qualification, signed_parent)
        raw = parent.current.base.legacy.parent._read_blob(
            evidence_cas, parent._EVIDENCE, "V2 shared chat snapshot"
        )
        evidence = parent.current.base.legacy.parent._load_canonical_json(
            raw, parent._EVIDENCE, "V2 shared chat snapshot"
        )
        _verify_chat_subsequence(evidence)
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
            f"invalid V2 catalog-fixed shared chat evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] == _ROUTE else "NOT_TESTED",
        }
        for item in qualification["profile"]["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v2-chat-session-snapshot-"
            "consumer-catalog-fixed-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_CURRENT_CONTRACT_V2_NATIVE_"
            "CHAT_ROUTE_FROM_SHARED_CAPTURE_ONLY"
        ),
        "bindings": {
            "configuration": dict(qualification["bindings"]["configuration"]),
            "image": qualification["bindings"]["image"],
            "parent_qualification_canonical_digest": _PARENT_RESULT_DIGEST,
            "parent_verifier": {
                **_PARENT_SOURCE,
                "digest": _PARENT_MODULE["digest"],
                "path": _PARENT_MODULE["path"],
            },
            "profile": dict(qualification["bindings"]["profile"]),
            "runtime": dict(qualification["bindings"]["runtime"]),
            "runtime_lock": dict(qualification["bindings"]["runtime_lock"]),
            "session_snapshot_observation": dict(
                qualification["bindings"]["session_snapshot_observation"]
            ),
            "shared_capture": {
                "capture_relationship": (
                    "SHARED_WITH_SESSION_SNAPSHOT_CONSUMER_NOT_INDEPENDENT_CAPTURE"
                ),
                "source_route": _SOURCE_ROUTE,
            },
            "skill": dict(qualification["bindings"]["skill"]),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{
                key: False
                for key in parent.current.base.legacy.parent._ELIGIBILITY_KEYS
            },
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_CHAT_SESSION_SNAPSHOT_CONSUMER_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "CHAT_ROUTE_REUSES_SHARED_SESSION_SNAPSHOT_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            "RAW_CAPTURE_ROUTE_ID_REMAINS_SESSION_SNAPSHOT_CONSUMER",
            "PARENT_SESSION_ROUTE_PASS_IS_VALIDATION_BASIS_NOT_COMPOSED_AS_SECOND_PASS",
            "BLACK_BOX_NATIVE_CHAT_PERSISTENCE_WITHOUT_DIRECT_SESSION_UPDATES_TRACE",
            "ONE_TAMPER_RECOVERY_TRIGGER_NOT_GENERAL_CHAT_ROUTE_COVERAGE",
            "MODEL_TURNS_FAILED_NO_PROVIDER_BODY_SUCCESSFUL_REPLY_OR_DELIVERY_CLAIM",
            "DETERMINISTIC_COMPILED_REPLAY_NOT_NATIVE_AGENT_EXECUTION",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "FOURTEEN_SELECTED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "COMPILED_CLOSURE_REUSED_FROM_PRIOR_CAPTURE_WITH_IDENTICAL_RUNTIME_TREE",
            "PRE_ROUTE_READ_ONLY_CLOSURE_ACQUISITION_BOUND_BY_RUNTIME_TREE",
            "NO_POST_ROUTE_CLOSURE_PROVENANCE_OR_CONTINUOUS_IMMUTABILITY_CLAIM",
            "ACQUISITION_IMAGE_DIFFERS_FROM_CURRENT_ROUTE_CAPTURE_IMAGE",
            "LOCAL_DOCKER_VOLUME_NOT_INDEPENDENTLY_ATTESTED",
            "ORIGINAL_PROVIDER_REQUEST_AND_SESSION_STORE_RAW_BYTES_NOT_RETAINED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "pass_basis": (
                "SIGNED_EXACT_NATIVE_CHAT_SEND_WAIT_SAME_SESSION_PROTECTED_PROMPT_"
                "PERSISTENCE_AFTER_ATTACKER_PROMPTREF_REPLACEMENT"
            ),
            "shared_capture_independent": False,
            "source_capture_route": _SOURCE_ROUTE,
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(qualification["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_parent_source() -> Mapping[str, Any]:
    module_path = Path(parent.__file__).resolve(strict=True)
    root = Path(__file__).resolve(strict=True).parents[2]
    git = parent.current.base.legacy._git
    if (
        module_path != (root / _PARENT_MODULE["path"]).resolve(strict=True)
        or _digest(module_path.read_bytes()) != _PARENT_MODULE["digest"]
        or Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 shared chat parent verifier changed")
    parent.current.base._verify_commit(_PARENT_SOURCE)
    signed: dict[str, bytes] = {}
    for identity in (_PARENT_MODULE, _PARENT_RECEIPT):
        entry = git(
            [
                "ls-tree",
                "-z",
                "--full-name",
                _PARENT_SOURCE["commit"],
                "--",
                identity["path"],
            ]
        )
        expected = (
            f"100644 blob {identity['blob']}\t{identity['path']}".encode() + b"\0"
        )
        if entry != expected:
            raise AdmissionEvidenceError("V2 shared chat signed parent tree changed")
        raw = git(
            ["cat-file", "blob", identity["blob"]],
            maximum=int(identity["bytes"]) + 1,
        )
        oid = hashlib.sha1(
            f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
        ).hexdigest()
        if (
            oid != identity["blob"]
            or len(raw) != identity["bytes"]
            or raw != (root / identity["path"]).read_bytes()
            or ("digest" in identity and _digest(raw) != identity["digest"])
        ):
            raise AdmissionEvidenceError("V2 shared chat signed parent blob changed")
        signed[identity["path"]] = raw
    if signed[_PARENT_MODULE["path"]] != module_path.read_bytes():
        raise AdmissionEvidenceError("V2 shared chat live parent verifier changed")
    receipt_raw = signed[_PARENT_RECEIPT["path"]]
    receipt = json.loads(
        receipt_raw,
        object_pairs_hook=parent.current.base.legacy.parent._reject_duplicates,
        parse_constant=parent.current.base.legacy.parent._reject_constant,
    )
    if (
        not isinstance(receipt, Mapping)
        or receipt_raw
        != parent.current.base.legacy.parent.oci_worker_protocol.canonical_json(receipt)
        + b"\n"
        or parent._canonical_digest(receipt) != _PARENT_RESULT_DIGEST
    ):
        raise AdmissionEvidenceError("V2 shared chat signed parent receipt changed")
    return receipt


def _verify_parent_result(
    qualification: Mapping[str, Any], signed_parent: Mapping[str, Any]
) -> None:
    counts = qualification["profile"]["counts"]
    decision = qualification["decision"]
    eligibility_keys = parent.current.base.legacy.parent._ELIGIBILITY_KEYS
    expected_routes = [
        {
            "id": route,
            "status": "PASS" if route == _SOURCE_ROUTE else "NOT_TESTED",
        }
        for route in parent.current.base.legacy.parent._ROUTES
    ]
    if (
        parent._canonical_digest(qualification) != _PARENT_RESULT_DIGEST
        or parent.current.base.legacy.parent.oci_worker_protocol.canonical_json(
            qualification
        )
        != parent.current.base.legacy.parent.oci_worker_protocol.canonical_json(
            signed_parent
        )
        or qualification["schema"]
        != (
            "aragorn/admission-protected-final-combined-v2-session-snapshot-"
            "consumer-catalog-fixed-route-coverage/v1"
        )
        or set(counts) != {"PASS", "NOT_TESTED"}
        or any(type(counts[key]) is not int for key in counts)
        or qualification["profile"]
        != {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": expected_routes,
        }
        or qualification["bindings"]["verifier_implementation_digest"]
        != _PARENT_MODULE["digest"]
        or set(decision) != {"status", *eligibility_keys}
        or decision["status"] != "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE"
        or any(decision[key] is not False for key in eligibility_keys)
    ):
        raise AdmissionEvidenceError("V2 shared chat parent result changed")


def _command_params(
    command: Mapping[str, Any], *, method: str, timeout: str
) -> Mapping[str, Any]:
    argv = command["argv"]
    expected = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        method,
        "--json",
        "--timeout",
        timeout,
        "--params",
    ]
    if len(argv) != 10 or argv[:9] != expected:
        raise AdmissionEvidenceError("V2 shared chat native command changed")
    value = json.loads(
        argv[9],
        object_pairs_hook=parent.current.base.legacy.parent._reject_duplicates,
        parse_constant=parent.current.base.legacy.parent._reject_constant,
    )
    if not isinstance(value, Mapping):
        raise AdmissionEvidenceError("V2 shared chat command params changed")
    return value


def _verify_turn(
    turn: Mapping[str, Any], *, label: str, nonce: str, session_key: str
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    run_id = f"aragorn-protected-session-snapshot-fixed-{label}-{nonce}"
    send = turn["send"]
    wait = turn["wait"]
    send_params = _command_params(send["command"], method="chat.send", timeout="5000")
    wait_params = _command_params(wait["command"], method="agent.wait", timeout="12000")
    request = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": f"Inert protected session-snapshot {label} observation.",
        "sessionKey": session_key,
        "timeoutMs": 5000,
    }
    ended_at = wait["response"]["value"]["endedAt"]
    if (
        turn["commands"] != [send["command"], wait["command"]]
        or turn["request_params"] != request
        or send_params != request
        or wait_params != {"runId": run_id, "timeoutMs": 10_000}
        or turn["tools_allow_supplied"] is not False
        or send["response"]
        != {"parsed": True, "value": {"runId": run_id, "status": "started"}}
        or type(ended_at) is not int
        or wait["response"]
        != {
            "parsed": True,
            "value": {
                "endedAt": ended_at,
                "error": _NETWORK_ERROR,
                "runId": run_id,
                "status": "error",
            },
        }
    ):
        raise AdmissionEvidenceError("V2 shared chat native turn changed")
    return send, wait


def _verify_chat_subsequence(evidence: Mapping[str, Any]) -> None:
    observation = evidence["route_observation"]
    document = observation["document"]
    action = document["action"]
    observed = action["observations"]
    initial = observed["initial_snapshot"]
    mutated = observed["mutated_snapshot"]
    final = observed["final_snapshot"]
    mutation = observed["mutation"]
    nonce = document["run_nonce"]
    session_key = f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}"
    marker = f"ARAGORN_INERT_ATTACKER_CONTROLLED_SNAPSHOT_{nonce}"
    source_route = {
        "action_id": "session-snapshot-consumer-fixed",
        "id": _SOURCE_ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }
    if (
        evidence["route_id"] != _SOURCE_ROUTE
        or observation["route"] != source_route
        or document["route"] != source_route
        or action["id"] != "session-snapshot-consumer-fixed"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
    ):
        raise AdmissionEvidenceError("V2 shared chat source route identity changed")

    initial_send, initial_wait = _verify_turn(
        observed["initial_turn"],
        label="initial",
        nonce=nonce,
        session_key=session_key,
    )
    injected_send, injected_wait = _verify_turn(
        observed["injected_turn"],
        label="injected",
        nonce=nonce,
        session_key=session_key,
    )
    commands = action["commands"]
    snapshots = [
        initial,
        mutated,
        observed["pre_injected_snapshot"],
        final,
    ]
    session_ids = {snapshot["entry"]["session_id"] for snapshot in snapshots}
    timing = observed["native_recovery_timing"]
    entry = final["entry"]
    store_mtime_ms = int(final["store"]["mtime_ns"]) // 1_000_000
    blob_mtime_ms = int(final["blob"]["mtime_ns"]) // 1_000_000
    parse = parent.current.base.legacy._parse_time
    epoch_ms = parent.current.base.legacy._epoch_ms
    pids = [command["pid"] for command in commands[2:6]]
    if (
        len(commands) != 7
        or commands[2:4] != observed["initial_turn"]["commands"]
        or commands[4:6] != observed["injected_turn"]["commands"]
        or any(type(pid) is not int or pid <= 1 for pid in pids)
        or len(set(pids)) != len(pids)
        or len(session_ids) != 1
        or any(
            session_key not in snapshot["store"]["top_level_keys"]
            for snapshot in snapshots
        )
        or observed["pre_injected_snapshot"] != mutated
        or initial["snapshot"] != final["snapshot"]
        or initial["prompt"] != final["prompt"]
        or mutated["entry"] != initial["entry"]
        or final["prompt"]["digest"] != _PROTECTED_PROMPT_DIGEST
        or final["blob"]["digest"] != _PROTECTED_PROMPT_DIGEST
        or final["prompt"]["digest"] != initial["prompt"]["digest"]
        or initial["entry"]["run_status"] != "timeout"
        or final["entry"]["run_status"] != "timeout"
        or marker not in mutated["prompt"]["exact_text"]
        or marker in final["prompt"]["exact_text"]
        or observed["attacker_blob_unreferenced_after"] is not True
        or mutation["changed_json_paths"] != [f"{session_key}.skillsSnapshot.promptRef"]
        or observed["compiled_route_replay"]["native_agent_execution"] is not False
        or any(
            report["ready"] is not False
            or report["report"] is not None
            or report["report_digest"] is not None
            or report["source_is_run"] is not False
            or report["system_prompt_hash"] is not None
            for report in (
                observed["initial_system_prompt_report"],
                observed["final_system_prompt_report"],
            )
        )
        or not (
            parse(initial_send["command"]["completed_at"])
            <= parse(initial_wait["command"]["started_at"])
            <= parse(initial_wait["command"]["completed_at"])
            < parse(mutation["started_at"])
            <= parse(mutation["completed_at"])
            < parse(injected_send["command"]["started_at"])
            <= parse(injected_send["command"]["completed_at"])
            <= parse(injected_wait["command"]["started_at"])
            <= parse(injected_wait["command"]["completed_at"])
        )
        or timing["ready"] is not True
        or timing["injected_send_started_at"]
        != epoch_ms(injected_send["command"]["started_at"])
        or timing["injected_wait_ended_at"]
        != injected_wait["response"]["value"]["endedAt"]
        or timing["injected_wait_completed_at"]
        != epoch_ms(injected_wait["command"]["completed_at"])
        or timing["final_entry_started_at"] != entry["started_at"]
        or timing["final_entry_updated_at"] != entry["updated_at"]
        or timing["final_store_mtime_ms"] != store_mtime_ms
        or not (
            epoch_ms(injected_send["command"]["completed_at"])
            <= entry["started_at"]
            <= entry["ended_at"]
            <= store_mtime_ms
            <= blob_mtime_ms
            <= entry["updated_at"]
            <= timing["injected_wait_ended_at"]
            <= timing["injected_wait_completed_at"]
        )
    ):
        raise AdmissionEvidenceError("V2 shared native chat persistence changed")
