"""Add exact fixed-runtime route PASSes to the fixed session qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterator, Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_archive as archive
from . import admission_protected_config as config
from . import admission_protected_cron as cron
from . import admission_protected_prompt as prompt
from . import admission_protected_session_snapshot_fixed as fixed
from . import admission_routes
from . import admission_runtime_profile as runtime_profile
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_SESSION_ROUTE = "ADM-02/reload/session-snapshot-consumer"
_SESSION_QUALIFICATION_DIGEST = (
    "sha256:f54c350836c69df6270c6551fb29e9a5954769a67eca633392bf36804d3da495"
)
_RECEIPT_SCHEMA = (
    "aragorn/phase3-openclaw-protected-session-snapshot-fixed-"
    "additional-routes-retention/v1"
)
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:c2c5c3901e51f2651fc2d4d252f0899a0bcc62114631067d2b0d095c402ced0b"
)
_RUNTIME = {
    "commit": "4b198dafbcca1788bfe22c0abb1f8bf16064be03",
    "node_path": "/usr/local/bin/node",
    "openclaw_digest": (
        "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
    ),
    "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
    "runtime_tree_digest": fixed._RUNTIME_TREE["tree_digest"],
    "version": "2026.7.1",
}
_ROUTE_RUNTIME = {
    key: value for key, value in _RUNTIME.items() if key != "runtime_tree_digest"
}
_FIXED_RUNTIME_SOURCE = (
    "/docker/volumes/aragorn-openclaw-2026-7-1-session-snapshot-fixed-v1/_data"
)
_VERSION_STDOUT = "OpenClaw 2026.7.1 (4b198da)\n"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_HELPER_IMPLEMENTATIONS = {
    config: "sha256:6da6bb604771530865d81b4031202bcb6a02d65e4c7f823a27112c5444b1829e",
    archive: "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f",
    prompt: "sha256:99e50bd0b18723a0bb37ca8afea04ef8b40c6fd3e159c6e17f26320f4f7c586c",
    cron: "sha256:e0cbfb701345e834bfcaa8a29e34660d90dd9a5cd1a7b45de35c6ee330465e65",
    runtime_profile: (
        "sha256:adf90754909150fba60b99b1b890e0815c2b5d081ea32dd5b5a698b1f0dfb50b"
    ),
    fixed: "sha256:70d9ad8d81f018e092aa0d6533a289b08b42326c6c1c660c7b5af8bd4f0f7481",
}
_CAPTURES: dict[str, dict[str, Any]] = {
    "config_activation": {
        "action": "config-entry-activation",
        "bytes": 32_799,
        "canonical": "sha256:e348e454c427faa9b4601d0e4fe10e132d107dc5837c7d1462207c173afda670",
        "canonical_lf": True,
        "digest": "sha256:a95353e29716f1c45729c87e58a42247f51a9a3740bed2aa14c24edf4ebb9af9",
        "gateway": ("aragorn-openclaw-fixed-config-final-v1", "1904479"),
        "implementation": "sha256:33b9da1d16f62201ee6616434008358df29c384c0e5f1af0f184493a4e7f59d1",
        "path": "benchmark/evidence/openclaw-v2026.7.1-protected-config-activation-fixed-2026-08-13.json",
        "probe": (
            "/docker/volumes/aragorn-openclaw-fixed-probe-config-b95128f/_data",
            ["protected-config-activation-probe.mjs"],
        ),
        "route": "ADM-02/update/config-entry-activation",
        "schema": "aragorn/openclaw-protected-config-activation-observation/v1",
    },
    "archive_replacement": {
        "action": "archive-source-force-replacement",
        "bytes": 36_278,
        "canonical": "sha256:a444708d93cb83636344583c3b0d52c4d082fd37295102811e654eb0703f7d71",
        "canonical_lf": False,
        "digest": "sha256:5af9cfda63a3eadd00bf847f86e2e1aac5b9cb6aa1415b888154bfeaa26c9698",
        "gateway": ("aragorn-openclaw-fixed-archive-final-v1", "1909054"),
        "implementation": "sha256:a582d06bb9872cf9d0ff09169283c18451ba9f6e9e29d6c67848a4ba9e612db1",
        "path": "benchmark/evidence/openclaw-v2026.7.1-protected-archive-replacement-fixed-2026-08-13.json",
        "probe": (
            "/docker/volumes/aragorn-openclaw-fixed-probe-archive-b95128f/_data",
            ["protected-archive-replacement-probe.mjs"],
        ),
        "route": "ADM-02/update/archive-source-force-replacement",
        "schema": "aragorn/openclaw-protected-archive-replacement-observation/v1",
    },
    "prompt_rebuild": {
        "action": "missing-prompt-blob-rebuild",
        "bytes": 51_514,
        "canonical": "sha256:8f42cd0b9afcd74621b680f72f5de383d96a10e8ce7773a177f1ed7142c2a01c",
        "canonical_lf": True,
        "digest": "sha256:803dbd8509f8e3ce4ad878a0bd79a78e10424ddbed5357793773e73550bd4f85",
        "gateway": ("aragorn-openclaw-fixed-prompt-final-v1", "1913658"),
        "implementation": {
            "helper": "sha256:90dd88392ffd88b6e9e29f682223c62a12f0c6a7c6bf9648a23d2be2dc218774",
            "probe": "sha256:a85b38660925805e5ff50c3a3a177e076f203e9c3610f62e3e732d5f198e2666",
        },
        "path": "benchmark/evidence/openclaw-v2026.7.1-protected-prompt-rebuild-fixed-2026-08-13.json",
        "probe": (
            "/docker/volumes/aragorn-openclaw-fixed-probe-prompt-b95128f/_data",
            ["protected-observation-v1.mjs", "protected-prompt-rebuild-probe.mjs"],
        ),
        "route": "ADM-02/reload/missing-prompt-blob-rebuild",
        "schema": "aragorn/openclaw-protected-prompt-rebuild-observation/v1",
    },
    "cron_rescan": {
        "action": "cron-rescan",
        "bytes": 66_346,
        "canonical": "sha256:8e36c5362243c9ee01a1f09a966fb53cccbdb54a105de624326c631f79947604",
        "canonical_lf": True,
        "digest": "sha256:ddfd445c479b9da8ebbf7eb5d2aaf953a682078e09c97953210a49f578d9107f",
        "gateway": ("aragorn-openclaw-fixed-cron-final-v1", "1918573"),
        "implementation": {
            "helper": "sha256:90dd88392ffd88b6e9e29f682223c62a12f0c6a7c6bf9648a23d2be2dc218774",
            "probe": "sha256:0620c17829f08a0257c0d6a797c4326405d4bdb00427984c978af5a39aba21d1",
        },
        "path": "benchmark/evidence/openclaw-v2026.7.1-protected-cron-rescan-fixed-2026-08-13.json",
        "probe": (
            "/docker/volumes/aragorn-openclaw-fixed-probe-cron-b95128f/_data",
            ["protected-cron-rescan-probe.mjs", "protected-observation-v1.mjs"],
        ),
        "route": "ADM-02/reload/cron-rescan",
        "schema": "aragorn/openclaw-protected-cron-rescan-observation/v1",
    },
    "workshop_proposal_apply": {
        "action": "workshop-protected-apply",
        "bytes": 27_349,
        "canonical": "sha256:ab79780c59220992f63731b31d0ede5af08ae69fda82960eba170b41a674df59",
        "canonical_lf": False,
        "digest": "sha256:c12ca22ac8d10d680cf6800c37d6d5ca84f7da5d833d9658b578b43153eab90b",
        "gateway": ("aragorn-openclaw-fixed-workshop-final-v2", "1974361"),
        "implementation": "sha256:d5f7c9c20fc2d082a53e938ae1a3e1d5eec2ff783e0f6f586b2d002db2ac13e2",
        "path": "benchmark/evidence/openclaw-v2026.7.1-protected-workshop-fixed-2026-08-13.json",
        "route": "ADM-02/update/workshop-proposal-apply",
        "schema": "aragorn/openclaw-protected-route-action-observations/v1",
    },
    "core_updater": {
        "action": "core-updater-plugin-replacement",
        "bytes": 25_248,
        "canonical": "sha256:a13df20fad0dcd153e351c8f18db36771c572ffa2c820de475bf1275e53ac3bc",
        "canonical_lf": False,
        "digest": "sha256:0c94ab5d71c7474744cc30cfda314f088b1905d38b394e7bda0a86cacb897ce6",
        "gateway": ("aragorn-openclaw-fixed-core-updater-final-v1", "1993902"),
        "implementation": "sha256:d5f7c9c20fc2d082a53e938ae1a3e1d5eec2ff783e0f6f586b2d002db2ac13e2",
        "path": "benchmark/evidence/openclaw-v2026.7.1-protected-core-updater-fixed-2026-08-13.json",
        "route": "ADM-02/update/core-updater-plugin-replacement",
        "schema": "aragorn/openclaw-protected-route-action-observations/v1",
    },
}
_PASS_ROUTES = {
    _SESSION_ROUTE,
    *(item["route"] for key, item in _CAPTURES.items() if key != "core_updater"),
}
_RECEIPT_OBSERVED_ROUTES = [
    "ADM-02/update/archive-source-force-replacement",
    "ADM-02/update/config-entry-activation",
    "ADM-02/update/core-updater-plugin-replacement",
    "ADM-02/update/workshop-proposal-apply",
    "ADM-02/reload/cron-rescan",
    "ADM-02/reload/missing-prompt-blob-rebuild",
]
_ROUTE_ROOT_SOURCES = {
    "extensions": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "managed_skills": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "personal_agents": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "plugin_skills": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "project_agents": "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
    "workspace_skills": "/docker/volumes/aragorn-openclaw-p3-archive-target-v1/_data",
}
_CRON_MODULES_DIGEST = (
    "sha256:7ef2a43f22527d4140240ede58feb0a27605fbdb0c5f2a930351fc23593a1e1a"
)
_LIMITATIONS = [
    "PRIVATE_FIXED_SOURCE_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SIX_EXACT_PINNED_ROUTE_PASSES_ONLY",
    "CORE_UPDATER_OBSERVED_WITH_NO_PLUGIN_REPLACEMENT_OUTCOME_NOT_QUALIFIED",
    "RAW_CAPTURE_RETENTION_AND_ROUTE_SEMANTICS_ONLY",
    "SIGNED_HARNESS_COMMIT_DIFFERS_FROM_TRUNCATED_DOCKER_LABEL_IDENTITY",
    "FIFTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_session_snapshot_fixed_routes(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    session_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Compose six fixed captures with the already-qualified fixed session route."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        session = _snapshot(session_qualification)
        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        fixed._verify_profile(profile, lock, inventory)
        _verify_helper_implementations()
        _verify_session_qualification(session, profile)
        evidence = {
            key: _read_capture(evidence_cas, spec) for key, spec in _CAPTURES.items()
        }
        _verify_receipt(receipt, evidence)
        for key, document in evidence.items():
            _verify_fixed_capture(key, document)
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
        raise AdmissionEvidenceError(f"invalid fixed route evidence: {exc}") from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] in _PASS_ROUTES else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    return {
        "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_FIXED_ROUTE_COVERAGE_ONLY",
        "bindings": {
            "additional_capture_digests": {
                key: spec["digest"] for key, spec in _CAPTURES.items()
            },
            "profile_digest": fixed._PROFILE_DIGEST,
            "runtime_lock_digest": fixed._RUNTIME_LOCK_DIGEST,
            "runtime_tree_digest": fixed._RUNTIME_TREE["tree_digest"],
            "session_qualification_canonical_digest": _SESSION_QUALIFICATION_DIGEST,
            "source_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "admission_profile_eligible": False,
            "aggregate_admission_eligible": False,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "status": "PARTIAL_ROUTE_COVERAGE",
        },
        "limitations": list(_LIMITATIONS),
        "profile": {
            "counts": {"fail": 0, "not_tested": 15, "pass": 6},
            "name": profile["name"],
            "routes": routes,
        },
        "runtime": dict(profile["runtime"]),
        "schema": "aragorn/admission-protected-session-snapshot-fixed-route-coverage/v1",
        "source_recorded_at": max(item["recorded_at"] for item in evidence.values()),
    }


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(canonical_json(value))


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionEvidenceError(f"duplicate fixed capture key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"invalid JSON constant: {value}")


def _read_capture(cas: CAS, spec: Mapping[str, Any]) -> dict[str, Any]:
    raw = cas.read(spec["digest"], max_bytes=spec["bytes"])
    if len(raw) != spec["bytes"] or _digest(raw) != spec["digest"]:
        raise AdmissionEvidenceError("fixed capture raw identity changed")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid fixed capture JSON: {exc}") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema") != spec["schema"]
        or canonical_digest(document) != spec["canonical"]
        or (canonical_json(document) + b"\n" == raw) is not spec["canonical_lf"]
    ):
        raise AdmissionEvidenceError("fixed capture parsed identity changed")
    return document


def _verify_helper_implementations() -> None:
    for module, expected in _HELPER_IMPLEMENTATIONS.items():
        if _digest(Path(module.__file__).read_bytes()) != expected:
            raise AdmissionEvidenceError("fixed route helper implementation changed")


def _verify_session_qualification(
    session: Mapping[str, Any], profile: Mapping[str, Any]
) -> None:
    if (
        canonical_digest(session) != _SESSION_QUALIFICATION_DIGEST
        or session["schema"]
        != "aragorn/admission-protected-session-snapshot-fixed-route-qualification/v1"
        or session["route"]["id"] != _SESSION_ROUTE
        or session["route"]["status"] != "PASS"
        or session["runtime"] != profile["runtime"]
        or session["profile"]["counts"] != {"fail": 0, "not_tested": 20, "pass": 1}
        or session["bindings"]["profile_digest"] != fixed._PROFILE_DIGEST
        or session["bindings"]["runtime_lock_digest"] != fixed._RUNTIME_LOCK_DIGEST
        or any(
            value is not False
            for key, value in session["decision"].items()
            if key != "status"
        )
    ):
        raise AdmissionEvidenceError("fixed session qualification changed")


def _verify_receipt(
    receipt: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]]
) -> None:
    false_fields = (
        "admission_profile_eligible",
        "aggregate_admission_eligible",
        "edr_eligible",
        "installer_work_eligible",
        "phase3_exit_eligible",
        "release_eligible",
        "run_eligible",
    )
    if (
        canonical_digest(receipt) != _RECEIPT_CANONICAL_DIGEST
        or receipt["schema"] != _RECEIPT_SCHEMA
        or any(receipt[name] is not False for name in false_fields)
        or set(receipt["evidence"]) != set(_CAPTURES)
        or receipt["results"]["pass"] != []
        or receipt["results"]["fail"] != []
        or receipt["results"]["observed"] != _RECEIPT_OBSERVED_ROUTES
    ):
        raise AdmissionEvidenceError("fixed additional-routes receipt changed")
    for key, spec in _CAPTURES.items():
        document = evidence[key]
        expected = {
            "bytes": spec["bytes"],
            "canonical_digest": spec["canonical"],
            "digest": spec["digest"],
            "path": spec["path"],
            "raw_is_canonical_json_lf": spec["canonical_lf"],
            "recorded_at": document["recorded_at"],
            "route_id": spec["route"],
            "run_nonce": document["run_nonce"],
            "schema": spec["schema"],
        }
        if receipt["evidence"][key] != expected:
            raise AdmissionEvidenceError("fixed capture receipt binding changed")


def _verify_fixed_capture(key: str, evidence: Mapping[str, Any]) -> None:
    spec = _CAPTURES[key]
    route_style = key in {"workshop_proposal_apply", "core_updater"}
    gateway = _gateway(evidence, route_style=route_style)
    implementation = (
        evidence["implementation_digest"]
        if "implementation_digest" in evidence
        else evidence["implementation_digests"]
    )
    routes = evidence["routes"] if route_style else [evidence["route"]]
    actions = evidence["actions"] if route_style else [evidence["action"]]
    runtime = _ROUTE_RUNTIME if route_style else _RUNTIME
    if (
        evidence["assurance"]
        not in {
            "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
            "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY",
        }
        or evidence["runtime_binding"] != runtime
        or implementation != spec["implementation"]
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
        or (route_style and evidence.get("selected_route_ids") != [spec["route"]])
        or (not route_style and "selected_route_ids" in evidence)
        or routes
        != [
            {
                "action_id": spec["action"],
                "id": spec["route"],
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        or len(actions) != 1
        or actions[0]["id"] != spec["action"]
        or actions[0]["status"] != "OBSERVED"
        or actions[0]["reason_codes"] != []
        or actions[0]["execution_error"] is not None
        or (gateway["hostname"], gateway["start_time_ticks"]) != spec["gateway"]
        or gateway["pid"] != 1
        or gateway["cmdline"] != ["openclaw-gateway"]
    ):
        raise AdmissionEvidenceError(f"fixed {key} identity changed")
    _verify_actual_runtime_and_probe(evidence, spec, route_style=route_style)
    if spec["route"] in _PASS_ROUTES:
        _verify_actual_command_projection(key, evidence)
    if route_style:
        _verify_actual_route_boundary(evidence["protected_boundary"])
        adapted = _adapt_route_capture(evidence)
        runtime_profile._verify_protected_boundary(adapted["protected_boundary"])
        if key == "workshop_proposal_apply":
            _verify_actual_workshop_proposal(actions[0]["prerequisites"]["draft"])
            _adapt_workshop(adapted)
            adapted_gateway = _gateway(adapted, route_style=True)
            runtime_profile._verify_protected_workshop_action(
                adapted,
                {
                    "runtime": {
                        "container_id": adapted_gateway["hostname"] + "0" * 64,
                        "gateway_pid": 1,
                        "gateway_start_time_ticks": adapted_gateway["start_time_ticks"],
                        "openclaw_digest": _RUNTIME["openclaw_digest"],
                    }
                },
            )
        else:
            _verify_core_updater(actions[0], evidence)
        return

    adapted = _adapt_legacy_capture(key, evidence)
    adapted_gateway = _gateway(adapted, route_style=False)
    synthetic = {
        "containment": {
            "container_id": adapted_gateway["hostname"] + "0" * 64,
            "gateway_pid": 1,
            "gateway_start_time_ticks": adapted_gateway["start_time_ticks"],
            "hostname": adapted_gateway["hostname"],
        }
    }
    if key == "archive_replacement":
        archive._verify_boundary(adapted["protected_boundary"])
    {
        "config_activation": config._verify_action,
        "archive_replacement": archive._verify_action,
        "prompt_rebuild": prompt._verify_action,
        "cron_rescan": cron._verify_action,
    }[key](adapted, synthetic)


def _gateway(evidence: Mapping[str, Any], *, route_style: bool) -> Mapping[str, Any]:
    action = evidence["actions"][0] if route_style else evidence["action"]
    before = action["prerequisites"]
    return before.get("gateway_process") or before["gateway_process_before"]


def _verify_actual_runtime_and_probe(
    evidence: Mapping[str, Any], spec: Mapping[str, Any], *, route_style: bool
) -> None:
    action = evidence["actions"][0] if route_style else evidence["action"]
    before = action["prerequisites"]
    version = before["commands"][0] if route_style else before["version"]
    boundary = (
        evidence["protected_boundary"]
        if route_style or "protected_boundary" in evidence
        else before["boundary_before"]
    )
    runtime = boundary["runtime"]
    runtime_mounts = [
        value
        for value in _walk(evidence)
        if value.get("path") == "/runtime" and isinstance(value.get("records"), list)
    ]
    if (
        version["stdout_excerpt"] != _VERSION_STDOUT
        or version["stdout_digest"] != _digest(_VERSION_STDOUT.encode())
        or version["stdout_bytes"] != len(_VERSION_STDOUT.encode())
        or version["exit_code"] != 0
        or version["stderr_digest"] != _EMPTY_DIGEST
        or not runtime_mounts
        or runtime not in runtime_mounts
    ):
        raise AdmissionEvidenceError("fixed runtime observation changed")
    for mount in runtime_mounts:
        archive._verify_ro_mount(
            mount,
            target="/runtime",
            source=_FIXED_RUNTIME_SOURCE,
            uid=0,
            gid=0,
            mode="755",
            entries=["bin", "lib"],
        )
    if not route_style:
        expected_source, expected_entries = spec["probe"]
        probe_mounts = [
            value
            for value in _walk(evidence)
            if value.get("path") == "/probe" and isinstance(value.get("records"), list)
        ]
        if not probe_mounts:
            raise AdmissionEvidenceError("fixed probe observation changed")
        for probe in probe_mounts:
            archive._verify_ro_mount(
                probe,
                target="/probe",
                source=expected_source,
                uid=0,
                gid=0,
                mode="755",
                entries=expected_entries,
            )
        trees = [
            value
            for value in _walk(evidence)
            if value.get("algorithm") == "aragorn/runtime-tree/v1"
        ]
        if not trees or any(tree != fixed._RUNTIME_TREE for tree in trees):
            raise AdmissionEvidenceError("fixed runtime tree observation changed")
    if (
        route_style
        and boundary["configuration"]["canonical_digest"]
        != archive._CONFIG_CANONICAL_DIGEST
    ):
        raise AdmissionEvidenceError("fixed route configuration changed")
    if spec["route"] == "ADM-02/reload/cron-rescan" and (
        canonical_digest(before["module_files_before"]) != _CRON_MODULES_DIGEST
        or canonical_digest(action["observations"]["module_files_after"])
        != _CRON_MODULES_DIGEST
        or action["observations"]["module_files_after"] != before["module_files_before"]
    ):
        raise AdmissionEvidenceError("fixed cron module closure changed")
    if spec["route"] == "ADM-02/reload/cron-rescan":
        _verify_actual_cron_snapshot_timing(action)


def _verify_actual_command_projection(key: str, evidence: Mapping[str, Any]) -> None:
    route_style = key == "workshop_proposal_apply"
    action = evidence["actions"][0] if route_style else evidence["action"]
    before = action["prerequisites"]
    after = action["observations"]
    commands = action["commands"]
    if key == "config_activation":
        expected = [
            before["version"],
            before["system_info_before"]["command"],
            before["discovery_before"]["command"],
            after["update"]["command"],
            after["discovery_after"]["command"],
            after["system_info_after"]["command"],
        ]
        executions = commands
    elif key == "archive_replacement":
        expected = [
            before["version"],
            before["system_info"]["command"],
            before["positive_control"]["install"],
            before["discovery"]["command"],
            after["upload_begin"]["command"],
            after["upload_install"]["command"],
            after["source_install"]["command"],
            after["discovery_after"]["command"],
        ]
        executions = commands
    elif key == "prompt_rebuild":
        initial = after["initial_turn"]
        rebuild = after["rebuild_turn"]
        initial_commands = [initial["send"]["command"], initial["wait"]["command"]]
        rebuild_commands = [rebuild["send"]["command"], rebuild["wait"]["command"]]
        if (
            initial["commands"] != initial_commands
            or rebuild["commands"] != rebuild_commands
        ):
            raise AdmissionEvidenceError("fixed prompt command projection changed")
        expected = [
            before["version"],
            before["system_info_before"]["command"],
            before["discovery_before"]["command"],
            *initial_commands,
            *rebuild_commands,
            after["discovery_after"]["command"],
            after["system_info_after"]["command"],
        ]
        executions = commands
    elif key == "cron_rescan":
        run = after["run"]
        if (
            run["poll_count"] != len(run["polls"]) == 1
            or run["terminal_poll"] != run["polls"][0]
        ):
            raise AdmissionEvidenceError("fixed cron command projection changed")
        expected = [
            before["version"],
            before["system_info_before"]["command"],
            before["discovery_before"]["command"],
            after["job"]["command"],
            run["request"]["command"],
            run["terminal_poll"]["command"],
            after["cleanup"]["command"],
            after["discovery_after"]["command"],
            after["system_info_after"]["command"],
        ]
        executions = commands
    elif key == "workshop_proposal_apply":
        preflight = before["commands"]
        if len(preflight) != 2 or preflight[1] != before["system_info"]["command"]:
            raise AdmissionEvidenceError("fixed workshop command projection changed")
        expected = [
            after["discovery_before"]["command"],
            commands[1],
            after["native_apply_result"]["command"],
            after["discovery_after"]["command"],
        ]
        executions = [*preflight, *commands]
    else:
        raise AdmissionEvidenceError("unsupported fixed PASS command projection")
    pids = [command["pid"] for command in executions]
    if (
        commands != expected
        or any(type(pid) is not int or pid <= 0 for pid in pids)
        or len(set(pids)) != len(pids)
    ):
        raise AdmissionEvidenceError(f"fixed {key} command projection changed")


def _verify_actual_cron_snapshot_timing(action: Mapping[str, Any]) -> None:
    after = action["observations"]
    snapshot = after["snapshot"]
    store_mtime_ns = snapshot["store"]["mtime_ns"]
    run_id = after["run"]["request"]["response"]["value"]["runId"]
    match = cron._RUN_ID.fullmatch(run_id)
    if (
        type(store_mtime_ns) is not str
        or re.fullmatch(r"[1-9][0-9]*", store_mtime_ns) is None
        or match is None
    ):
        raise AdmissionEvidenceError("fixed cron snapshot store timing changed")
    store_mtime_ms = int(store_mtime_ns) // 1_000_000
    run_epoch_ms = int(match.group(2))
    terminal_ms = after["terminal_result"]["ts"]
    poll_completed_ms = int(
        _time(after["run"]["terminal_poll"]["command"]["completed_at"]).timestamp()
        * 1_000
    )
    updated_at = snapshot["entry"]["updated_at"]
    if (
        type(updated_at) is not int
        or type(terminal_ms) is not int
        or not run_epoch_ms <= updated_at <= store_mtime_ms <= terminal_ms
        or terminal_ms > poll_completed_ms
    ):
        raise AdmissionEvidenceError("fixed cron snapshot store timing changed")


def _verify_actual_route_boundary(boundary: Mapping[str, Any]) -> None:
    if set(boundary["roots"]) != set(_ROUTE_ROOT_SOURCES):
        raise AdmissionEvidenceError("fixed route protected roots changed")
    for name, source in _ROUTE_ROOT_SOURCES.items():
        target = runtime_profile._PROTECTED_ROOTS[name][0]
        entries = ["requesting-code-review"] if name == "workspace_skills" else []
        archive._verify_ro_mount(
            boundary["roots"][name],
            target=target,
            source=source,
            uid=0,
            gid=982,
            mode="750",
            entries=entries,
        )
    archive._verify_ro_mount(
        boundary["configuration"]["mount"],
        target="/profile/config",
        source="/docker/volumes/aragorn-openclaw-p3-archive-config-v1/_data",
        uid=0,
        gid=982,
        mode="750",
        entries=["openclaw.json"],
    )
    configuration = boundary["configuration"]
    config_file = configuration["file"]
    if (
        configuration["ready"] is not True
        or configuration["canonical_digest"] != archive._CONFIG_CANONICAL_DIGEST
        or config_file["path"] != "/profile/config/openclaw.json"
        or config_file["exists"] is not True
        or config_file["type"] != "file"
        or config_file["uid"] != 0
        or config_file["gid"] != 982
        or config_file["mode"] != "440"
        or config_file["nlink"] != 1
        or config_file["size"] != 316
        or config_file["digest"] != archive._CONFIG_DIGEST
        or config_file["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("fixed route configuration changed")


def _verify_actual_workshop_proposal(draft: Mapping[str, Any]) -> None:
    archive._verify_ro_mount(
        draft["mount"],
        target="/proposal",
        source=(
            "/docker/volumes/aragorn-openclaw-fixed-workshop-proposal-c1164fb/_data"
        ),
        uid=0,
        gid=0,
        mode="755",
        entries=["PROPOSAL.md"],
    )
    proposal = draft["observation"]
    if (
        draft["expected_digest"] != runtime_profile._PROTECTED_WORKSHOP_PROPOSAL_DIGEST
        or proposal["path"] != "/proposal/PROPOSAL.md"
        or proposal["exists"] is not True
        or proposal["type"] != "file"
        or proposal["uid"] != 0
        or proposal["gid"] != 0
        or proposal["mode"] != "444"
        or proposal["nlink"] != 1
        or proposal["size"] != len(runtime_profile._PROTECTED_WORKSHOP_PROPOSAL)
        or proposal["digest"] != runtime_profile._PROTECTED_WORKSHOP_PROPOSAL_DIGEST
        or proposal["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("fixed workshop proposal changed")


def _walk(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _set_stdout(command: dict[str, Any], text: str) -> None:
    raw = text.encode()
    command["stdout_excerpt"] = text
    command["stdout_bytes"] = len(raw)
    command["stdout_digest"] = _digest(raw)


def _adapt_common(
    evidence: Mapping[str, Any], old_tree: Mapping[str, Any]
) -> dict[str, Any]:
    adapted = copy.deepcopy(evidence)
    for value in _walk(adapted):
        if value == fixed._RUNTIME_TREE:
            value.clear()
            value.update(old_tree)
        if value.get("stdout_excerpt") == _VERSION_STDOUT:
            _set_stdout(value, "OpenClaw 2026.7.1 (2d2ddc4)\n")
        if value.get("path") == "/runtime" and isinstance(value.get("records"), list):
            value["records"][0]["root"] = (
                "/docker/volumes/aragorn-openclaw-2026-7-1-runtime/_data"
            )
    return adapted


def _adapt_legacy_capture(key: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
    module = {
        "config_activation": config,
        "archive_replacement": archive,
        "prompt_rebuild": prompt,
        "cron_rescan": cron,
    }[key]
    adapted = _adapt_common(evidence, module._RUNTIME_TREE)
    probe_values = {
        "config_activation": (
            "/docker/volumes/aragorn-openclaw-p38-config-probe-v2/_data",
            982,
            "750",
            ["protected-config-activation-probe.mjs"],
        ),
        "archive_replacement": (
            "/docker/volumes/aragorn-openclaw-p3-archive-probe-v2/_data",
            982,
            "750",
            ["probe.mjs"],
        ),
        "prompt_rebuild": (
            "/docker/volumes/aragorn-openclaw-p40-prompt-probe-v1/_data",
            0,
            "755",
            ["protected-observation-v1.mjs", "protected-prompt-rebuild-probe.mjs"],
        ),
        "cron_rescan": (
            "/docker/volumes/aragorn-openclaw-p42-cron-probe-v7/_data",
            0,
            "755",
            ["protected-cron-rescan-probe.mjs", "protected-observation-v1.mjs"],
        ),
    }[key]
    source, gid, mode, entries = probe_values
    for value in _walk(adapted):
        if value.get("path") == "/probe" and isinstance(value.get("records"), list):
            value["records"][0]["root"] = source
            value["entry"].update(
                {
                    "entries": entries,
                    "entry_count": len(entries),
                    "gid": gid,
                    "mode": mode,
                }
            )
    if key == "archive_replacement":
        hostname = _CAPTURES[key]["gateway"][0]
        _replace_hostname(adapted, hostname, hostname[:12])
    if key == "cron_rescan":
        for value in _walk(adapted):
            if set(value) == set(cron._MODULES) and all(
                isinstance(item, dict) and set(item) == {"expected", "observed"}
                for item in value.values()
            ):
                for name, (size, digest, path) in cron._MODULES.items():
                    value[name]["expected"] = {
                        "bytes": size,
                        "digest": digest,
                        "path": path,
                    }
                    value[name]["observed"].update(
                        {"digest": digest, "path": path, "size": size}
                    )
        snapshot = adapted["action"]["observations"]["snapshot"]
        snapshot["store"]["mtime_ns"] = snapshot["blob"]["mtime_ns"]
    return adapted


def _replace_hostname(value: Any, before: str, after: str) -> None:
    for item in _walk(value):
        for key, current in list(item.items()):
            if current == before:
                item[key] = after
        excerpt = item.get("stdout_excerpt")
        if isinstance(excerpt, str) and before in excerpt:
            _set_stdout(item, excerpt.replace(before, after))


def _adapt_route_capture(evidence: Mapping[str, Any]) -> dict[str, Any]:
    adapted = copy.deepcopy(evidence)
    boundary = adapted["protected_boundary"]
    for name, (target, source) in runtime_profile._PROTECTED_ROOTS.items():
        mount = boundary["roots"][name]
        mount["records"][0].update({"root": source, "source": "/dev/vda1"})
        mount["entry"].update({"entries": [], "entry_count": 0})
    configuration = boundary["configuration"]
    entry = copy.deepcopy(configuration["file"])
    entry["path"] = "/profile/config.json"
    configuration["file"] = copy.deepcopy(entry)
    configuration["mount"].update({"path": "/profile/config.json", "entry": entry})
    configuration["mount"]["records"][0].update(
        {
            "mount_point": "/profile/config.json",
            "root": "/etc/aragorn/openclaw-protected-route-v1.json",
            "source": "/dev/vda1",
        }
    )
    boundary["runtime"]["records"][0].update(
        {
            "root": "/var/lib/docker/volumes/aragorn-openclaw-2026-7-1-runtime-v2/_data",
            "source": "/dev/vda1",
        }
    )
    return adapted


def _adapt_workshop(evidence: dict[str, Any]) -> None:
    action = evidence["actions"][0]
    before = action["prerequisites"]
    hostname = before["gateway_process"]["hostname"]
    _replace_hostname(evidence, hostname, hostname[:12])
    version = before["commands"][0]
    _set_stdout(version, "OpenClaw 2026.7.1 (2d2ddc4)\n")
    draft = before["draft"]
    entry = copy.deepcopy(draft["observation"])
    entry["path"] = "/profile/workspace/PROPOSAL.md"
    draft["observation"] = copy.deepcopy(entry)
    draft["mount"].update({"path": entry["path"], "entry": entry})
    draft["mount"]["records"][0].update(
        {
            "mount_point": entry["path"],
            "root": "/var/lib/aragorn-route-probe/PROPOSAL.md",
            "source": "/dev/vda1",
        }
    )
    proposal_command = action["commands"][1]
    proposal_command["argv"][
        proposal_command["argv"].index("/proposal/PROPOSAL.md")
    ] = "/profile/workspace/PROPOSAL.md"


def _verify_core_updater(
    action: Mapping[str, Any], evidence: Mapping[str, Any]
) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    update = after["update_repair"]
    commands = action["commands"]
    if (
        before["ready"] is not True
        or before["reason_codes"] != []
        or before["runtime_files"]["openclaw"]["file"]["digest"]
        != _RUNTIME["openclaw_digest"]
        or after["configuration_after"]
        != evidence["protected_boundary"]["configuration"]
        or after["roots_after"] != after["roots_before"]
        or after["inventory_before"]["response"]["value"]["plugins"] != []
        or after["inventory_after"]["response"]["value"]["plugins"] != []
        or update["command"]["argv"][-7:]
        != ["update", "repair", "--timeout", "10", "--yes", "--json", "--no-restart"]
        or update["command"]["exit_code"] != 0
        or update["response"]["parsed"] is not True
        or update["response"]["value"]["mode"] != "finalize"
        or update["response"]["value"]["status"] != "ok"
        or update["response"]["value"]["restart"] is not False
        or update["response"]["value"]["postUpdate"]["plugins"]["changed"] is not False
        or update["response"]["value"]["postUpdate"]["plugins"]["npm"]["outcomes"] != []
        or commands
        != [
            after["inventory_before"]["command"],
            update["command"],
            after["inventory_after"]["command"],
        ]
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or _time(commands[-1]["completed_at"]) > _time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("fixed core updater semantics changed")
