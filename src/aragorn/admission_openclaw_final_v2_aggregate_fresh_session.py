"""Qualify one route from the signed V2 aggregate admission observation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import admission_protected_final_combined_v2_fresh_session_reset as nearest
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/reload/fresh-session-reset"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_NEAREST = {
    "bytes": 36_478,
    "digest": "sha256:ce54e514bac8fa642cce4b6a24a144c8b380621fae7154de1d4fc43206e11119",
    "path": "src/aragorn/admission_protected_final_combined_v2_fresh_session_reset.py",
}
_EVIDENCE = {
    "bytes": 693_675,
    "canonical_bytes": 693_674,
    "canonical_digest": (
        "sha256:88c6bce7f2e99f00d5290b64fb661bdf82c45deeb897b8e1fd2e2bec17e9fbf3"
    ),
    "digest": (
        "sha256:9807dd26005dea8105aab48ee15eb8809bb1f5cbb544c3aa2ac0dd094e212e91"
    ),
    "path": (
        "benchmark/evidence/openclaw-final-admission-v2-systemd-p3-final-"
        "fresh-session-observed-2026-08-27.json"
    ),
}
_ROUTE_CAPTURE = {
    "bytes": 452_633,
    "canonical_bytes": 452_632,
    "canonical_digest": (
        "sha256:ab552ca9327ff1d5d2af69899451d5a17cc48c7669358cd340daeec1e98cdda2"
    ),
    "digest": (
        "sha256:1fd63ff7873f68f4300e7540a89dd6048eb7f80098dd99f643805380b8e0c76d"
    ),
}
_ACTION_RAW = {
    "bytes": 25_061,
    "canonical_bytes": 25_108,
    "canonical_digest": (
        "sha256:1e3252832b08032c36ad527aad9ada420ea43e1537be84081b81d5b74ec59c53"
    ),
    "digest": (
        "sha256:e5ca04a5d030366b560739ba6e2e12267bc76b8ed94b6e405ecf414abcb473aa"
    ),
}
_SOURCE = {
    "commit": "2a18e771d120641692284a98f3001aaee90d643a",
    "parent": "c85546eed45c14ecf678339f9d1ed11d3e038972",
    "tree": "bdf91d09c5baa0283a361c121373717788f63e6f",
}
_RETENTION = {
    "commit": "c60da240a33b451a8f7524250ebdfb4a4a2ca271",
    "parent": _SOURCE["commit"],
    "tree": "42de8ab46a13baa69659541ef9839e2aafeb0bd1",
}
_RETENTION_BLOB = "b0d2ba28d35636dacbc84ca1ae61f660f5f5ceb9"
_STATIC_OBJECTS = {
    "adm03": {
        "bytes": 3_348,
        "digest": (
            "sha256:1d61ba80a21e7ec0f335c12d8f57a5fcc2cd6271d27b59768bc33e040344621b"
        ),
    },
    "bindings": {
        "bytes": 1_784,
        "digest": (
            "sha256:50023fdb3a896188650defc26a0a8ef5686a52fe63f90845aaed8e5694f163c0"
        ),
    },
    "decision": {
        "bytes": 470,
        "digest": (
            "sha256:1631fe16b5fd6acab6f259897a58157b3482e3be9fbdace37d1e26dfcdb83a58"
        ),
    },
    "harness": {
        "bytes": 63_197,
        "digest": (
            "sha256:888a9a53a710669551e22713e28481c5b84b1b6cabcb4a20b1c764c228a56529"
        ),
    },
    "limitations": {
        "bytes": 541,
        "digest": (
            "sha256:d31399937eeaea3d2e0240046b8c0b58e120a45429ec1d9a69c0d92bfe407070"
        ),
    },
    "manifest": {
        "bytes": 6_610,
        "digest": (
            "sha256:b70f69dad88b5cdd6593d2a22bf79e2c68fd0366060bacb389e52cda6913563f"
        ),
    },
    "source_artifacts": {
        "bytes": 3_617,
        "digest": (
            "sha256:e1ae1d9980e6990123494eb2302cf1baf0a989b10eb454c0657ed57e64f55802"
        ),
    },
}
_SIGNED_SOURCE_FILES = {
    "activator": "packaging/activate-runtime-action-worker-host.sh",
    "capture": "scripts/capture_openclaw_final_admission_v2_systemd.sh",
    "configuration": (
        "benchmark/admission/openclaw-v2026.7.1/"
        "protected-final-combined-config-v2.json"
    ),
    "observation_helper": (
        "benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs"
    ),
    "preflight": "src/aragorn/runtime_action_worker.py",
    "probe": "scripts/openclaw_final_admission_v2_systemd_probe.py",
    "profile": (
        "benchmark/admission/openclaw-v2026.7.1/"
        "protected-final-combined-profile-v2.json"
    ),
    "runtime_lock": (
        "benchmark/admission/openclaw-v2026.7.1/"
        "protected-final-combined-runtime-v2.lock.json"
    ),
    "skill": "benchmark/runtime-action-worker-final-combined-systemd/SKILL.md",
    "suite": (
        "benchmark/admission/openclaw-v2026.7.1/final-admission-v2-suite.mjs"
    ),
}
_EMBEDDED_ROUTE_SOURCE_FILES = {
    "collector": (
        "scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
        "/src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
    ),
    "materializer": (
        "scripts/materialize_fixed_admission_probes.py",
        "/src/scripts/materialize_fixed_admission_probes.py",
    ),
    "v1_route_injector": (
        "scripts/runtime_action_worker_final_route_systemd_probe.py",
        "/src/scripts/runtime_action_worker_final_route_systemd_probe.py",
    ),
}
_EMBEDDED_ROUTE_PROBE_SOURCE = (
    "benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs"
)
_PROPERTY_IDS = ("DET-01", "ADM-01/exact-admitted-bytes")
_CATEGORY_IDS = (
    "ADM-02/install",
    "ADM-02/update",
    "ADM-02/direct-write",
    "ADM-02/rename",
    "ADM-02/symlink",
    "ADM-02/auto-discovery",
    "ADM-02/reload",
    "ADM-02/restart",
)
_ADM03_IDS = ("ADM-03/policy-failure", "ADM-03/policy-tampering")
_REQUIRED_ENV = (
    "ARAGORN_CONFIG_PATH",
    "ARAGORN_PROBE_ROOT",
    "ARAGORN_PROFILE_PATH",
    "ARAGORN_RUNTIME_LOCK_PATH",
    "ARAGORN_RUNTIME_ROOT",
    "ARAGORN_RUN_NONCE",
    "ARAGORN_SKILL_PATH",
)
_INTEGER_KEYS = frozenset(
    """
    FAIL NOT_TESTED OBSERVED PASS adm03_not_tested_count boottime_ns bytes
    cacheRead cacheWrite canonical_bytes claimed_at_unix completed_monotonic_ns
    contextWindow cpuCount ctime_ns device diskAvailableBytes diskTotalBytes
    elapsed_ms elapsed_ns endedAt ended_at entry_count epoch error_count
    evaluated_at_unix exit_code expectedGatewayGid expectedGatewayUid
    expectedWorkerUid expires_at_unix fd file_count formal_category_not_tested_count
    generation gid inode input issued_at_unix maxTokens max_actions
    mediator_health_epoch memoryFreeBytes memoryTotalBytes message_count
    minimum_mediator_health_epoch minimum_revocation_generation
    monitor_completed_monotonic_ns monotonic_ns mtime_ns nlink
    no_new_privileges observed_at_unix observed_monotonic_ns output pid
    policy_version port prep_container_exit_code property_not_tested_count
    raw_bytes realtime_ns request_bytes request_count revocation_generation
    root_device root_inode route_fail_count route_not_tested_count
    route_observed_count route_pass_count runtime_ms sequence service_pid size
    snapshot_version start_time_ticks started_at started_monotonic_ns stderr_bytes
    stdout_bytes symlink_count timeoutMs timeoutSeconds total_bytes uid updated_at
    uptimeMs version writable_regular_files_or_directories_for_group_or_other
    aragorn-agent-gateway.service aragorn-runtime-action-worker.service
    aragorn-runtime-lineage-capability-action-broker.service
    aragorn-runtime-lineage-capability-observation-publisher.service
    """.split()
)
_BOOLEAN_KEYS = frozenset(
    """
    accepted activation_failed_at_expired_endpoint admission_profile_eligible
    aggregate_admission_eligible aggregate_gate_eligible archive_metadata
    authorization_valid available_state_bound available_to_expired_observed
    catalog_exact clean_before_after coherent_allow_created_consumed_observed
    confirmed contract_valid covered_terminal_state deliver
    driver_completed_allow_created edr_claim_eligible edr_eligible effect_bound
    effects_unchanged enabled entries_truncated
    exact_control_inventory_no_stage_or_receipt exact_gateway_session_key
    exact_openclaw_history_error_classification exact_peer_chain
    exact_rpc_history_shape_without_details exact_tool_call_id_identity
    exact_transcript_details_schema_and_status exact_transcript_rpc_tool_result_join
    exact_wait_run_id exact_worker_request_digest executable exists
    expected_nested_relay_outcome expired_activation_fail_stop_observed
    expired_broker_stopped expired_grant_unchanged
    expired_profile_receipt_archive_present expired_services_exited_cleanly
    expired_state_archived_exactly expired_state_bound expired_state_unchanged
    explicit filesystem_workspace_only four_units_active
    four_units_active_no_boot_authority fresh_grant_distinct_and_available
    full_activation_no_boot_authority_observed gateway_environment_bytes_retained
    gateway_environment_digest_retained gateway_listener_bound_to_main_pid
    gateway_pid_present gateway_worker_masked grant_consumed_once
    idle_no_peer_or_effect installer_authority_eligible installer_work_eligible
    invocations_and_timestamps_bound json_object lease_bound
    main_removed_before_adm03 message_prefix_continuity_valid
    mutable_stacks_removed no_boot_authority one_connect_no_retry
    one_provider_driven_tool_call p3_7c_activation_action_observed
    parent_p3_7b_unchanged parsed pending_exists phase3_exit_eligible
    prep_container_oom_killed present privileged prompt_exact
    provider_and_gateway_token_values_retained provider_completed_without_error
    public_release_eligible raw_is_canonical_json_lf read_only readonly_rootfs
    ready reasoning rebuilt_snapshot_matches_baseline receipt_exists
    receipt_result_bound release_eligible reset_snapshot_cleared
    retained_evidence_eligible retained_in_repository
    rotation_changed_only_grant_state route_completion route_fail_stopped
    run_01_eligible run_02_eligible run_eligible rw semantic_pass_verified
    sensor_broker_disabled session_id_rotated session_id_valid singleton_catalog
    snapshot_present snapshot_version_valid supportsDeveloperRole supportsStore
    supportsStrictMode supportsTools supportsUsageInStreaming target_exists
    terminal_archive_rotation_observed three_sockets_present tool_contract_valid
    transcript_details_source_result_matches_public_content transcript_join
    transcript_regular_nonsymlink_bounded watch worker_attributed workspaceOnly
    writable
    """.split()
)
_NULLABLE_BOOLEAN_KEYS = frozenset({"message_prefix_continuity_valid"})
_PROMPT_DIGEST = (
    "sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501"
)
_PROMPT_PATH = (
    "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/skills-prompts/"
    f"sha256/60/{_PROMPT_DIGEST.removeprefix('sha256:')}.txt"
)
_SESSION_STORE = (
    "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json"
)
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_READY = {
    "catalog_exact",
    "prompt_exact",
    "ready",
    "session_id_valid",
    "snapshot_present",
    "snapshot_version_valid",
}
_FALSE_FLAGS = nearest.legacy.parent._ELIGIBILITY_KEYS


def verify_openclaw_final_v2_aggregate_fresh_session(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one PASS only after the signed aggregate route is verified."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = nearest.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 aggregate fresh-session"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V2 aggregate CAS differs from signed retention"
            )
        evidence = nearest.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 aggregate fresh-session"
        )
        _verify_aggregate(evidence)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid V2 aggregate fresh-session evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": route,
            "status": "PASS" if route == _ROUTE else "NOT_TESTED",
        }
        for route in nearest.legacy.parent._ROUTES
    ]
    return {
        "schema": (
            "aragorn/admission-openclaw-final-v2-aggregate-fresh-session-"
            "route-qualification/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_CURRENT_V2_ROUTE_FROM_SIGNED_"
            "AGGREGATE_EXECUTION_ONLY"
        ),
        "bindings": {
            "aggregate_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": nearest.legacy.parent._SIGNATURE["key"],
                },
                "route_action_raw": dict(_ACTION_RAW),
                "route_capture": dict(_ROUTE_CAPTURE),
                "source": {
                    **_SOURCE,
                    "signature": dict(nearest.legacy.parent._SIGNATURE),
                },
            },
            "nearest_semantic_verifier": dict(_NEAREST),
            "runtime": dict(nearest.legacy.parent._RUNTIME),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            "aggregate_execution_observed": True,
            "aggregate_semantic_admission_verified": False,
            **{key: False for key in _FALSE_FLAGS},
        },
        "formal_claims": {
            "properties": {identifier: False for identifier in _PROPERTY_IDS},
            "categories": {identifier: False for identifier in _CATEGORY_IDS},
            "adm03_scenarios": {identifier: False for identifier in _ADM03_IDS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_FRESH_SESSION_RESET_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "AGGREGATE_EXECUTION_OBSERVED_BUT_AGGREGATE_ADMISSION_NOT_ELIGIBLE",
            "DET_01_AND_ADM_01_NOT_TESTED",
            "ALL_FORMAL_ADM_02_CATEGORIES_NOT_TESTED",
            "BOTH_ADM_03_SCENARIOS_NOT_TESTED",
            "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "NO_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "pass_basis": (
                "SIGNED_AGGREGATE_BOUND_EXACT_RESET_ROTATION_CLEAR_AND_REBUILD_"
                "TRANSITION"
            ),
            "transitions_dynamically_exercised": True,
        },
        "source_recorded_at": _EVIDENCE_RECORDED_AT,
    }


_EVIDENCE_RECORDED_AT = "2026-08-27T21:18:10.340586Z"


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return nearest.legacy.parent.oci_worker_protocol.canonical_json(value)


def _verify_dependencies() -> None:
    path = Path(nearest.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_NEAREST["path"]).name
        or len(path.read_bytes()) != _NEAREST["bytes"]
        or _digest(path.read_bytes()) != _NEAREST["digest"]
    ):
        raise AdmissionEvidenceError("V2 aggregate nearest verifier changed")
    nearest._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    repository = Path(
        nearest.legacy._git(["rev-parse", "--show-toplevel"]).decode().strip()
    ).resolve(strict=True)
    if repository != root or nearest.legacy._git(
        ["rev-parse", "--show-object-format"]
    ).strip() != b"sha1":
        raise AdmissionEvidenceError("V2 aggregate signed repository changed")
    nearest._verify_commit(_SOURCE)
    nearest._verify_commit(_RETENTION)
    entry = nearest.legacy._git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = (
        f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    )
    if entry != expected:
        raise AdmissionEvidenceError("V2 aggregate signed tree entry changed")
    raw = nearest.legacy._git(
        ["cat-file", "blob", _RETENTION_BLOB], maximum=768 * 1024
    )
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 aggregate signed blob changed")
    return raw


def _verify_static(name: str, value: Any) -> None:
    canonical = _canonical(value)
    identity = _STATIC_OBJECTS[name]
    if len(canonical) != identity["bytes"] or _digest(canonical) != identity["digest"]:
        raise AdmissionEvidenceError(f"V2 aggregate {name} changed")


def _exact(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AdmissionEvidenceError(f"V2 aggregate {label} keys changed")
    return value


def _false_decision(
    value: Any,
    *,
    label: str,
    status: str,
    counts: Mapping[str, int] | None = None,
) -> None:
    keys = {*_FALSE_FLAGS, "status"}
    if counts is not None:
        keys.add("outcome_counts")
    decision = _exact(value, keys, f"{label} decision")
    if (
        decision["status"] != status
        or any(decision[key] is not False for key in _FALSE_FLAGS)
        or (
            counts is not None
            and not _exact_integer_counts(
                decision["outcome_counts"], counts
            )
        )
    ):
        raise AdmissionEvidenceError(f"V2 aggregate {label} promoted a claim")


def _exact_integer_counts(value: Any, expected: Mapping[str, int]) -> bool:
    if not isinstance(value, dict) or set(value) != set(expected):
        return False
    return all(
        type(value[key]) is int and value[key] == expected[key] for key in expected
    )


def _verify_aggregate(evidence: Mapping[str, Any]) -> None:
    _verify_scalar_types(evidence)
    if (
        set(evidence)
        != {
            "adm03",
            "authority",
            "bindings",
            "decision",
            "execution",
            "harness",
            "limitations",
            "main",
            "manifest",
            "recorded_at",
            "run_nonce",
            "schema",
            "source_artifacts",
        }
        or evidence["schema"]
        != "aragorn/openclaw-final-admission-v2-systemd-capture/v1"
        or evidence["authority"]
        != (
            "BOUND_V2_ADMISSION_RAW_OBSERVATION_AGGREGATION_ONLY_SEMANTIC_"
            "CONFORMANCE_NOT_VERIFIED_NO_INSTALLER_RUN_PHASE3_EDR_RELEASE_AUTHORITY"
        )
        or evidence["recorded_at"] != _EVIDENCE_RECORDED_AT
        or re.fullmatch(r"[0-9a-f]{64}", evidence["run_nonce"]) is None
    ):
        raise AdmissionEvidenceError("V2 aggregate outer wrapper changed")
    for name in _STATIC_OBJECTS:
        _verify_static(name, evidence[name])
    nonce = evidence["run_nonce"]
    bindings = evidence["bindings"]
    harness = _verify_harness(evidence["harness"])
    _verify_signed_source_files(evidence["source_artifacts"])
    _verify_manifest(evidence["manifest"], nonce=nonce, bindings=bindings)
    route_capture = _verify_main(
        evidence["main"], nonce=nonce, bindings=bindings, execution=evidence["execution"]
    )
    _verify_adm03(evidence["adm03"], nonce=nonce, bindings=bindings)
    _verify_execution(
        evidence["execution"],
        nonce=nonce,
        main=evidence["main"],
        adm03=evidence["adm03"],
    )
    _verify_outer_decision(evidence["decision"])
    _verify_route_capture(
        route_capture,
        outer_harness=evidence["harness"],
        outer_bindings=bindings,
        outer_recorded_at=evidence["recorded_at"],
        container_id=harness["container"]["id"],
    )


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    """Reject JSON numeric aliases and non-finite values at the boundary."""

    if type(value) is float:
        if not float_allowed or not math.isfinite(value):
            raise AdmissionEvidenceError("V2 aggregate floating-point value changed")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.endswith("_eligible") and item is not False:
                raise AdmissionEvidenceError("V2 aggregate eligibility type changed")
            if (
                key in _BOOLEAN_KEYS
                and type(item) is not bool
                and not (key in _NULLABLE_BOOLEAN_KEYS and item is None)
            ):
                raise AdmissionEvidenceError("V2 aggregate boolean type changed")
            numeric = isinstance(key, str) and (
                key in _INTEGER_KEYS
                or key.endswith(("_bytes", "_count", "_ms", "_ns"))
                or key.endswith(("Bytes", "Count", "Ms"))
                or key in {"hookCount", "httpRoutes"}
            )
            if numeric and type(item) is bool:
                raise AdmissionEvidenceError("V2 aggregate numeric type changed")
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError("V2 aggregate boolean list item changed")
            _verify_scalar_types(item, float_allowed=float_allowed)


def _raw_record(value: Any, label: str) -> bytes:
    record = _exact(value, {"base64", "bytes", "digest"}, label)
    raw = base64.b64decode(record["base64"], validate=True)
    if len(raw) != record["bytes"] or _digest(raw) != record["digest"]:
        raise AdmissionEvidenceError(f"V2 aggregate {label} identity changed")
    return raw


def _verify_harness(value: Mapping[str, Any]) -> Mapping[str, Any]:
    wrapper = _exact(value, {"digest", "document", "file"}, "harness")
    document = _exact(
        wrapper["document"],
        {
            "capture_disposition",
            "container",
            "image_lineage",
            "runtime_volume",
            "schema",
            "source",
        },
        "harness document",
    )
    file = _exact(
        wrapper["file"],
        {"base64", "bytes", "digest", "path", "stat"},
        "harness file",
    )
    file_raw = base64.b64decode(file["base64"], validate=True)
    if (
        wrapper["digest"] != _digest(_canonical(document))
        or file_raw != _canonical(document)
        or file["bytes"] != len(file_raw)
        or file["digest"] != wrapper["digest"]
        or file["path"] != "/run/aragorn-final-admission-v2-harness.json"
        or file["stat"]["size"] != len(file_raw)
        or file["stat"]["type"] != "file"
        or file["stat"]["mode"] != "0600"
        or file["stat"]["uid"] != 0
        or file["stat"]["gid"] != 0
        or file["stat"]["nlink"] != 1
    ):
        raise AdmissionEvidenceError("V2 aggregate harness digest changed")
    source = _exact(document["source"], {"commit", "tree", "verification"}, "source")
    verification = _exact(
        source["verification"],
        {"command", "commit_object", "exit_code", "stderr", "stdout"},
        "source verification",
    )
    commit_raw = _raw_record(verification["commit_object"], "source commit object")
    actual_commit = nearest.legacy._git(
        ["cat-file", "commit", _SOURCE["commit"]], maximum=64 * 1024
    )
    container = _exact(
        document["container"],
        {
            "host_profile",
            "id",
            "image_id",
            "image_reference",
            "platform",
            "profile_label",
        },
        "harness container",
    )
    host = container["host_profile"]
    lineage = document["image_lineage"]
    v1, v2, admission = lineage["v1"], lineage["v2"], lineage["admission"]
    runtime_volume = document["runtime_volume"]
    if (
        document["schema"]
        != "aragorn/openclaw-final-admission-v2-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or source["commit"] != _SOURCE["commit"]
        or source["tree"] != _SOURCE["tree"]
        or commit_raw != actual_commit
        or hashlib.sha1(
            f"commit {len(commit_raw)}\0".encode() + commit_raw,
            usedforsecurity=False,
        ).hexdigest()
        != _SOURCE["commit"]
        or verification["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or verification["exit_code"] != 0
        or _raw_record(verification["stdout"], "source verification stdout") != b""
        or not _raw_record(verification["stderr"], "source verification stderr")
        or re.fullmatch(r"[0-9a-f]{64}", container["id"]) is None
        or container["image_id"] != admission["id"]
        or container["image_reference"]
        != "aragorn-openclaw-final-admission-v2-systemd"
        or container["platform"] != "linux"
        or container["profile_label"] != "openclaw-final-admission-v2"
        or host
        != {
            "binds": [
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                (
                    "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1:"
                    "/runtime:ro"
                ),
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
        }
        or v1["id"]
        != "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
        or v2["layers"][: len(v1["layers"])] != v1["layers"]
        or admission["layers"][: len(v2["layers"])] != v2["layers"]
        or lineage["v2_added_layers"] != v2["layers"][len(v1["layers"]) :]
        or lineage["admission_added_layers"]
        != admission["layers"][len(v2["layers"]) :]
        or not lineage["v2_added_layers"]
        or not lineage["admission_added_layers"]
        or runtime_volume
        != {
            "identity": {
                "driver": "local",
                "labels": {
                    "io.aragorn.phase": "phase3-final",
                    "io.aragorn.role": "installed-runtime",
                    "io.aragorn.source-commit": nearest.legacy.parent._OPENCLAW[
                        "commit"
                    ],
                    "io.aragorn.source-tree": nearest.legacy.parent._OPENCLAW[
                        "source_tree"
                    ],
                },
                "name": nearest.legacy.parent._RUNTIME["runtime_volume"],
                "options": None,
                "scope": "local",
            },
            "mount": {
                "destination": "/runtime",
                "driver": "local",
                "mode": "ro",
                "rw": False,
                "source": nearest.legacy.parent._RUNTIME["runtime_volume"],
                "type": "volume",
            },
        }
    ):
        raise AdmissionEvidenceError("V2 aggregate signed harness changed")
    return document


def _artifact_identity(value: Mapping[str, Any], name: str) -> tuple[int, str]:
    if name in {"configuration", "profile", "runtime_lock"}:
        source = value["source"]
        return source["bytes"], source["digest"]
    if name == "skill":
        file = value["file"]
        return file["bytes"], file["digest"]
    return value["bytes"], value["digest"]


def _verify_signed_source_files(artifacts: Mapping[str, Any]) -> None:
    if set(artifacts) != set(_SIGNED_SOURCE_FILES):
        raise AdmissionEvidenceError("V2 aggregate source artifact inventory changed")
    for name, path in _SIGNED_SOURCE_FILES.items():
        raw = _signed_source_blob(path)
        size, digest = _artifact_identity(artifacts[name], name)
        if len(raw) != size or _digest(raw) != digest:
            raise AdmissionEvidenceError(
                f"V2 aggregate signed source artifact changed: {name}"
            )


def _signed_source_blob(path: str) -> bytes:
    return nearest.legacy._git(
        ["show", f"{_SOURCE['commit']}:{path}"], maximum=256 * 1024
    )


def _verify_embedded_route_sources(value: Any) -> list[Mapping[str, Any]]:
    artifacts = _exact(
        value,
        {*_EMBEDDED_ROUTE_SOURCE_FILES, "probe_bundle"},
        "embedded route source artifact inventory",
    )
    signed: dict[str, bytes] = {}
    for name, (source_path, runtime_path) in _EMBEDDED_ROUTE_SOURCE_FILES.items():
        artifact = _exact(
            artifacts[name],
            {"bytes", "digest", "path", "stat"},
            f"embedded route source artifact {name}",
        )
        stat = _exact(
            artifact["stat"],
            {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"},
            f"embedded route source artifact {name} stat",
        )
        raw = _signed_source_blob(source_path)
        signed[name] = raw
        if (
            type(artifact["bytes"]) is not int
            or artifact["bytes"] != len(raw)
            or artifact["digest"] != _digest(raw)
            or artifact["path"] != runtime_path
            or type(stat["device"]) is not int
            or stat["device"] < 0
            or type(stat["inode"]) is not int
            or stat["inode"] <= 0
            or type(stat["size"]) is not int
            or stat["size"] != len(raw)
            or type(stat["uid"]) is not int
            or stat["uid"] != 0
            or type(stat["gid"]) is not int
            or stat["gid"] != 0
            or type(stat["nlink"]) is not int
            or stat["nlink"] != 1
            or stat["mode"] != "0555"
            or stat["type"] != "file"
        ):
            raise AdmissionEvidenceError(
                f"V2 aggregate embedded route source changed: {name}"
            )

    bundle = artifacts["probe_bundle"]
    if not isinstance(bundle, list) or len(bundle) != 1:
        raise AdmissionEvidenceError("V2 aggregate embedded route probe bundle changed")
    probe = _exact(
        bundle[0], {"bytes", "digest", "name"}, "embedded generated route probe"
    )
    source_probe = _signed_source_blob(_EMBEDDED_ROUTE_PROBE_SOURCE)
    generated = _materialize_signed_route_probe(
        materializer=signed["materializer"], source_probe=source_probe
    )
    if (
        probe["name"] != "protected-route-probe.mjs"
        or type(probe["bytes"]) is not int
        or probe["bytes"] != len(generated)
        or probe["digest"] != _digest(generated)
    ):
        raise AdmissionEvidenceError("V2 aggregate generated route probe changed")
    return bundle


def _materialize_signed_route_probe(
    *, materializer: bytes, source_probe: bytes
) -> bytes:
    with TemporaryDirectory(prefix="aragorn-aggregate-route-") as temporary:
        root = Path(temporary)
        script = root / "scripts/materialize_fixed_admission_probes.py"
        source = root / _EMBEDDED_ROUTE_PROBE_SOURCE
        output = root / "generated"
        script.parent.mkdir(parents=True)
        source.parent.mkdir(parents=True)
        script.write_bytes(materializer)
        source.write_bytes(source_probe)
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(script),
                    "--final-combined-v2",
                    str(output),
                    "protected-route-probe.mjs",
                ],
                cwd=root,
                env={},
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=15,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdmissionEvidenceError(
                "V2 aggregate signed route probe materialization timed out"
            ) from exc
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise AdmissionEvidenceError(
                "V2 aggregate signed route probe materialization failed"
            )
        generated = output / "protected-route-probe.mjs"
        if not generated.is_file():
            raise AdmissionEvidenceError(
                "V2 aggregate signed route probe was not materialized"
            )
        return generated.read_bytes()


def _verify_manifest(
    manifest: Mapping[str, Any], *, nonce: str, bindings: Mapping[str, Any]
) -> None:
    contract = manifest["contract"]
    main = contract["main"]
    adm03 = contract["adm03"]
    if (
        set(manifest)
        != {
            "assurance",
            "bindings",
            "contract",
            "decision",
            "limitations",
            "mode",
            "run_nonce",
            "schema",
        }
        or manifest["schema"] != "aragorn/openclaw-final-admission-v2-manifest/v1"
        or manifest["mode"] != "manifest"
        or manifest["run_nonce"] != nonce
        or manifest["bindings"] != bindings
        or manifest["assurance"]
        != "BOUND_INPUT_CONTRACT_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or contract["bound_evidence_schema"]
        != "aragorn/openclaw-final-admission-v2-bound-evidence/v1"
        or contract["environment"] != list(_REQUIRED_ENV)
        or contract["row_statuses"] != ["FAIL", "NOT_TESTED", "OBSERVED"]
        or main["filename"] != "main-input.json"
        or main["schema"] != "aragorn/openclaw-final-admission-v2-main-input/v1"
        or main["property_ids"] != list(_PROPERTY_IDS)
        or main["category_ids"] != list(_CATEGORY_IDS)
        or main["route_ids"] != list(nearest.legacy.parent._ROUTES)
        or adm03["filename"] != "adm03-input.json"
        or adm03["schema"] != "aragorn/openclaw-final-admission-v2-adm03-input/v1"
        or adm03["scenario_ids"] != list(_ADM03_IDS)
        or not isinstance(main["allowed_probe_modules"], list)
        or not isinstance(adm03["allowed_probe_modules"], list)
        or len(main["allowed_probe_modules"]) != 19
        or adm03["allowed_probe_modules"]
        != [
            {
                "digest": (
                    "sha256:1ac42c2baf9af313c99b5327b6c075fecd10a12e06f7dfb55d15f33b40ebb77e"
                ),
                "name": "adm03-probe.mjs",
            }
        ]
    ):
        raise AdmissionEvidenceError("V2 aggregate manifest contract changed")
    _false_decision(manifest["decision"], label="manifest", status="NOT_TESTED")


def _not_tested(identifier: str) -> dict[str, Any]:
    return {
        "evidence_refs": [],
        "id": identifier,
        "reason_codes": ["SEMANTIC_EVIDENCE_NOT_PRODUCED"],
        "status": "NOT_TESTED",
    }


def _main_input(
    *, nonce: str, bindings: Mapping[str, Any], artifact: Mapping[str, Any]
) -> dict[str, Any]:
    routes = [_not_tested(route) for route in nearest.legacy.parent._ROUTES]
    routes[list(nearest.legacy.parent._ROUTES).index(_ROUTE)] = {
        "evidence_refs": [artifact["digest"]],
        "id": _ROUTE,
        "reason_codes": ["BOUND_RAW_ROUTE_EXECUTION_NOT_SEMANTICALLY_VERIFIED"],
        "status": "OBSERVED",
    }
    return {
        "artifacts": [dict(artifact)],
        "bindings": dict(bindings),
        "formal_categories": [_not_tested(item) for item in _CATEGORY_IDS],
        "mode": "main",
        "properties": [_not_tested(item) for item in _PROPERTY_IDS],
        "routes": routes,
        "run_nonce": nonce,
        "schema": "aragorn/openclaw-final-admission-v2-main-input/v1",
    }


def _verify_main(
    main: Mapping[str, Any],
    *,
    nonce: str,
    bindings: Mapping[str, Any],
    execution: Mapping[str, Any],
) -> bytes:
    if (
        set(main)
        != {
            "assurance",
            "bindings",
            "decision",
            "evidence",
            "formal_categories",
            "input",
            "limitations",
            "mode",
            "properties",
            "routes",
            "run_nonce",
            "runtime_verification",
            "schema",
        }
        or main["schema"]
        != "aragorn/openclaw-final-admission-v2-main-observation/v1"
        or main["mode"] != "main"
        or main["run_nonce"] != nonce
        or main["bindings"] != bindings
        or main["assurance"]
        != "BOUND_RAW_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or main["limitations"]
        != [
            "OBSERVED_IS_NOT_PASS",
            "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ]
        or len(main["evidence"]) != 1
    ):
        raise AdmissionEvidenceError("V2 aggregate main wrapper changed")
    bound = main["evidence"][0]
    if set(bound) != {
        "digest",
        "observation",
        "path",
        "probe_digest",
        "probe_module",
        "schema",
    }:
        raise AdmissionEvidenceError("V2 aggregate bound artifact changed")
    artifact = {
        "digest": bound["digest"],
        "path": bound["path"],
        "schema": bound["schema"],
    }
    bound_document = {
        "bindings": dict(bindings),
        "mode": "main",
        "observation": bound["observation"],
        "probe_digest": bound["probe_digest"],
        "probe_module": bound["probe_module"],
        "run_nonce": nonce,
        "schema": bound["schema"],
    }
    expected_input = _main_input(nonce=nonce, bindings=bindings, artifact=artifact)
    if (
        bound["path"] != "artifacts/fresh-session-reset.json"
        or bound["schema"]
        != "aragorn/openclaw-final-admission-v2-bound-evidence/v1"
        or bound["probe_module"] != "protected-route-probe.mjs"
        or bound["probe_digest"]
        != "sha256:65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1"
        or bound["digest"] != _digest(_canonical(bound_document) + b"\n")
        or main["properties"] != expected_input["properties"]
        or main["formal_categories"] != expected_input["formal_categories"]
        or main["routes"] != expected_input["routes"]
        or main["input"]
        != {
            "digest": _digest(_canonical(expected_input) + b"\n"),
            "path": "main-input.json",
            "schema": expected_input["schema"],
        }
        or execution["route_slice"]["artifact"] != artifact
    ):
        raise AdmissionEvidenceError("V2 aggregate main artifact join changed")
    runtime_root = f"/var/lib/aragorn-final-admission-v2/main-{nonce}/runtime"
    _verify_runtime(main["runtime_verification"], runtime_root)
    _false_decision(
        main["decision"],
        label="main",
        status="NOT_TESTED",
        counts={"FAIL": 0, "NOT_TESTED": 30, "OBSERVED": 1},
    )
    return _decode_route_capture(bound["observation"])


def _verify_adm03(
    adm03: Mapping[str, Any], *, nonce: str, bindings: Mapping[str, Any]
) -> None:
    expected_input = {
        "artifacts": [],
        "bindings": dict(bindings),
        "mode": "adm03",
        "run_nonce": nonce,
        "scenarios": [_not_tested(item) for item in _ADM03_IDS],
        "schema": "aragorn/openclaw-final-admission-v2-adm03-input/v1",
    }
    if (
        set(adm03)
        != {
            "assurance",
            "bindings",
            "decision",
            "evidence",
            "input",
            "limitations",
            "mode",
            "run_nonce",
            "runtime_verification",
            "scenarios",
            "schema",
        }
        or adm03["schema"]
        != "aragorn/openclaw-final-admission-v2-adm03-observation/v1"
        or adm03["mode"] != "adm03"
        or adm03["run_nonce"] != nonce
        or adm03["bindings"] != bindings
        or adm03["assurance"]
        != "ISOLATED_BOUND_RAW_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or adm03["evidence"] != []
        or adm03["scenarios"] != expected_input["scenarios"]
        or adm03["input"]
        != {
            "digest": _digest(_canonical(expected_input) + b"\n"),
            "path": "adm03-input.json",
            "schema": expected_input["schema"],
        }
    ):
        raise AdmissionEvidenceError("V2 aggregate ADM-03 claim ceiling changed")
    _verify_runtime(
        adm03["runtime_verification"],
        f"/var/lib/aragorn-final-admission-v2/adm03-{nonce}/runtime",
    )
    _false_decision(
        adm03["decision"],
        label="ADM-03",
        status="NOT_TESTED",
        counts={"FAIL": 0, "NOT_TESTED": 2, "OBSERVED": 0},
    )


def _verify_runtime(value: Mapping[str, Any], root: str) -> None:
    if value != {"root": root, "tree": nearest.legacy.parent._RUNTIME_TREE}:
        raise AdmissionEvidenceError("V2 aggregate isolated runtime changed")


def _verify_execution(
    execution: Mapping[str, Any],
    *,
    nonce: str,
    main: Mapping[str, Any],
    adm03: Mapping[str, Any],
) -> None:
    main_root = f"/var/lib/aragorn-final-admission-v2/main-{nonce}/runtime"
    adm03_root = f"/var/lib/aragorn-final-admission-v2/adm03-{nonce}/runtime"

    def expected_copy(destination: str) -> dict[str, Any]:
        return {
            "command": [
                "/usr/bin/cp",
                "-a",
                "--reflink=auto",
                "/runtime/.",
                destination,
            ],
            "destination": destination,
            "entrypoint_digest": nearest.legacy.parent._RUNTIME["entrypoint_digest"],
            "source": "/runtime",
        }
    if (
        set(execution)
        != {
            "adm03_runtime_copy",
            "main_removed_before_adm03",
            "main_runtime_copy",
            "mutable_stacks_removed",
            "network",
            "route_slice",
            "sequence",
            "suite_process_environment",
        }
        or execution["sequence"]
        != [
            "manifest",
            "execute-fresh-session-reset-route-probe",
            "main",
            "destroy-main-stack",
            "create-isolated-adm03-stack",
            "adm03",
            "destroy-adm03-stack",
        ]
        or execution["main_runtime_copy"] != expected_copy(main_root)
        or execution["adm03_runtime_copy"] != expected_copy(adm03_root)
        or main["runtime_verification"]["root"] != main_root
        or adm03["runtime_verification"]["root"] != adm03_root
        or main_root == adm03_root
        or execution["route_slice"]["route_id"] != _ROUTE
        or execution["route_slice"]["status"] != "OBSERVED"
        or execution["main_removed_before_adm03"] is not True
        or execution["mutable_stacks_removed"] is not True
        or execution["network"] != "none"
        or execution["suite_process_environment"]
        != "env-i-seven-exact-ARAGORN-variables"
    ):
        raise AdmissionEvidenceError("V2 aggregate execution or isolation changed")


def _verify_outer_decision(value: Mapping[str, Any]) -> None:
    counts = {
        "property_not_tested_count": 2,
        "formal_category_not_tested_count": 8,
        "route_observed_count": 1,
        "route_fail_count": 0,
        "route_not_tested_count": 20,
        "adm03_not_tested_count": 2,
    }
    decision = _exact(
        value,
        {"status", "semantic_pass_verified", *counts, *_FALSE_FLAGS},
        "outer decision",
    )
    if (
        decision["status"] != "NOT_TESTED"
        or decision["semantic_pass_verified"] is not False
        or any(decision[key] is not False for key in _FALSE_FLAGS)
        or not _exact_integer_counts(
            {key: decision[key] for key in counts}, counts
        )
    ):
        raise AdmissionEvidenceError("V2 aggregate outer claim ceiling changed")


def _strict_json(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=nearest.legacy.parent._reject_duplicates,
            parse_constant=nearest.legacy.parent._reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid V2 aggregate {label} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AdmissionEvidenceError(f"V2 aggregate {label} is not an object")
    return value


def _decode_route_capture(observation: Mapping[str, Any]) -> bytes:
    if (
        set(observation)
        != {
            "decision",
            "limitations",
            "route_capture",
            "route_capture_authority",
            "route_capture_schema",
            "route_capture_status",
            "route_id",
            "schema",
        }
        or observation["schema"]
        != "aragorn/openclaw-final-admission-v2-route-slice-observation/v1"
        or observation["route_id"] != _ROUTE
        or observation["route_capture_status"] != "OBSERVED"
        or observation["route_capture_schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-route-systemd-observation/v1"
        or observation["route_capture_authority"]
        != (
            "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_"
            "RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or observation["decision"]
        != {
            "semantic_pass_verified": False,
            "status": "OBSERVED_NOT_PASS",
            **{key: False for key in sorted(_FALSE_FLAGS)},
        }
    ):
        raise AdmissionEvidenceError("V2 aggregate opaque route wrapper changed")
    raw = _raw_record(observation["route_capture"], "opaque route capture")
    document = _strict_json(raw, "opaque route capture")
    canonical = _canonical(document)
    if (
        len(raw) != _ROUTE_CAPTURE["bytes"]
        or _digest(raw) != _ROUTE_CAPTURE["digest"]
        or len(canonical) != _ROUTE_CAPTURE["canonical_bytes"]
        or _digest(canonical) != _ROUTE_CAPTURE["canonical_digest"]
        or raw != canonical + b"\n"
    ):
        raise AdmissionEvidenceError("V2 aggregate opaque route identity changed")
    return raw


def _verify_route_capture(
    raw: bytes,
    *,
    outer_harness: Mapping[str, Any],
    outer_bindings: Mapping[str, Any],
    outer_recorded_at: str,
    container_id: str,
) -> None:
    route = _strict_json(raw, "route capture")
    _verify_scalar_types(route)
    if (
        set(route)
        != {
            "authority",
            "composition",
            "decision",
            "limitations",
            "recorded_at",
            "route_id",
            "route_observation",
            "schema",
            "source_artifacts",
        }
        or route["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-route-systemd-observation/v1"
        or route["authority"]
        != (
            "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_"
            "RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or route["route_id"] != _ROUTE
        or route["decision"]
        != {
            "status": "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED",
            "route_observation_status": "OBSERVED",
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in _FALSE_FLAGS},
        }
    ):
        raise AdmissionEvidenceError("V2 aggregate route capture wrapper changed")
    generated_probe_bundle = _verify_embedded_route_sources(route["source_artifacts"])
    composition = route["composition"]
    source = composition["action"]["artifacts"]["final_combined_v2"]
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    expected_bindings = {
        "config_materialization": "canonical_json_without_trailing_lf",
        "network": "none",
        "openclaw_test_fast": "absent",
        "runtime_digest": outer_bindings["runtime"]["tree_digest"],
        "runtime_volume": nearest.legacy.parent._RUNTIME["runtime_volume"],
        "sandbox": "off",
        "sessions": "fresh-only",
        "skill_digest": outer_bindings["skill"]["digest"],
    }
    if (
        composition["action"]["harness"] != outer_harness
        or composition["bindings"] != expected_bindings
        or profile_before != profile_after
        or profile_before != source["profile"]
        or composition["action"]["inputs"]["gateway_config"]
        != source["config"]["document"]
        or profile["name"] != _PROFILE
        or [item["id"] for item in profile["routes"]]
        != list(nearest.legacy.parent._ROUTES)
        or any(item["outcome"] != "NOT_TESTED" for item in profile["routes"])
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or source["config"]["file"]["source"]["digest"]
        != outer_bindings["configuration"]["digest"]
        or source["config"]["file"]["canonical_digest"]
        != outer_bindings["configuration"]["canonical_digest"]
        or source["profile"]["file"]["source"]["digest"]
        != outer_bindings["profile"]["digest"]
        or source["runtime_lock"]["file"]["source"]["digest"]
        != outer_bindings["runtime_lock"]["digest"]
        or composition["action"]["runtime"]
        != {
            "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "entrypoint_digest": nearest.legacy.parent._RUNTIME["entrypoint_digest"],
            "expected_version": nearest.legacy.parent._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": nearest.legacy.parent._RUNTIME_TREE,
            "version_output": nearest.legacy.parent._RUNTIME["version_output"],
        }
    ):
        raise AdmissionEvidenceError("V2 aggregate route composition changed")
    observation = route["route_observation"]
    action_document = _decode_action_raw(observation["raw"])
    if (
        action_document != observation["document"]
        or observation["route"] != action_document["routes"][0]
        or observation["bundle"] != generated_probe_bundle
        or observation["bundle"]
        != [
            {
                "bytes": 44_825,
                "digest": (
                    "sha256:65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1"
                ),
                "name": "protected-route-probe.mjs",
            }
        ]
        or any(
            unit["ControlGroup"]
            != f"/docker/{container_id}/system.slice/{name}"
            for name, unit in observation["stack_before"]["units"].items()
        )
    ):
        raise AdmissionEvidenceError("V2 aggregate route custody changed")
    _verify_route_execution(observation)
    if not (
        nearest.legacy._parse_time(observation["execution"]["started_at"])
        <= nearest.legacy._parse_time(
            action_document["actions"][0]["prerequisites"]["commands"][0][
                "started_at"
            ]
        )
        < nearest.legacy._parse_time(action_document["recorded_at"])
        <= nearest.legacy._parse_time(observation["execution"]["completed_at"])
        <= nearest.legacy._parse_time(route["recorded_at"])
        <= nearest.legacy._parse_time(outer_recorded_at)
    ):
        raise AdmissionEvidenceError("V2 aggregate route timing changed")
    _verify_transition(
        action_document,
        container_id=container_id,
        gateway_pid=observation["gateway_pid_binding"]["pid"],
        outer_recorded_at=route["recorded_at"],
        configuration_digest=outer_bindings["configuration"]["canonical_digest"],
    )


def _decode_action_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    record = _exact(
        value,
        {"base64", "bytes", "canonical_digest", "digest", "raw_is_canonical_json_lf"},
        "route action raw",
    )
    raw = base64.b64decode(record["base64"], validate=True)
    document = _strict_json(raw, "route action")
    _verify_scalar_types(document)
    canonical = _canonical(document)
    if (
        len(raw) != _ACTION_RAW["bytes"]
        or _digest(raw) != _ACTION_RAW["digest"]
        or len(canonical) != _ACTION_RAW["canonical_bytes"]
        or _digest(canonical) != _ACTION_RAW["canonical_digest"]
        or record["bytes"] != len(raw)
        or record["digest"] != _digest(raw)
        or record["canonical_digest"] != _digest(canonical)
        or record["raw_is_canonical_json_lf"] is not False
    ):
        raise AdmissionEvidenceError("V2 aggregate route action raw changed")
    return document


def _verify_route_execution(observation: Mapping[str, Any]) -> None:
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    stack = observation["stack_before"]
    pid = binding["pid"]
    process = stack["processes"]["aragorn-agent-gateway.service"]
    if (
        type(pid) is not int
        or pid <= 1
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
            "unit": "aragorn-agent-gateway.service",
        }
        or execution["argv"]
        != [
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
            "/usr/local/bin/node",
            "/route-input/fresh-session-reset/protected-route-probe.mjs",
            "--route-id",
            _ROUTE,
        ]
        or execution["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _digest(b""), "excerpt": ""}
        or stack["pids"]["aragorn-agent-gateway.service"] != pid
        or stack["gateway_listener"]["pid"] != pid
        or stack["units"]["aragorn-agent-gateway.service"]["MainPID"] != str(pid)
        or process["pid"] != pid
        or process["cmdline"] != ["openclaw-gateway"]
        or process["uids"] != [992, 992, 992, 992]
        or process["gids"] != [992, 992, 992, 992]
        or process["groups"] != [992]
        or process["capabilities_effective"] != "0000000000000000"
        or process["no_new_privileges"] != 1
        or not (
            nearest.legacy._parse_time(execution["started_at"])
            < nearest.legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V2 aggregate route execution boundary changed")


def _verify_transition(
    document: Mapping[str, Any],
    *,
    container_id: str,
    gateway_pid: int,
    outer_recorded_at: str,
    configuration_digest: str,
) -> None:
    configuration = document["protected_boundary"]["configuration"]
    config_file = configuration["file"]
    config_mount = configuration["mount"]
    protected_runtime = document["protected_boundary"]["runtime"]
    if (
        document["schema"] != "aragorn/openclaw-protected-route-action-observations/v1"
        or document["selected_route_ids"] != [_ROUTE]
        or document["implementation_digest"]
        != "sha256:65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1"
        or document["runtime_binding"]
        != {
            "commit": nearest.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": nearest.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "version": nearest.legacy.parent._OPENCLAW["version"],
        }
        or configuration["canonical_digest"] != configuration_digest
        or configuration["expected_canonical_digest"] != configuration_digest
        or configuration["json_object"] is not True
        or configuration["parse_error"] is not None
        or configuration["ready"] is not True
        or config_file["path"]
        != "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
        or config_file["exists"] is not True
        or config_file["type"] != "file"
        or config_file["digest"] != configuration_digest
        or config_file["digest_error"] is not None
        or config_file["size"] != 1_880
        or config_file["uid"] != 992
        or config_file["gid"] != 0
        or config_file["mode"] != "400"
        or config_file["nlink"] != 1
        or config_mount["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or config_mount["explicit"] is not True
        or config_mount["read_only"] is not True
        or config_mount["ready"] is not True
        or config_mount["error"] is not None
        or len(config_mount["records"]) != 1
        or config_mount["records"][0]["mount_point"]
        != "/run/credentials/aragorn-agent-gateway.service"
        or "ro" not in config_mount["records"][0]["mount_options"]
        or document["protected_boundary"]["effective_identity"]
        != {"gid": 992, "uid": 992}
        or document["protected_boundary"]["ready"] is not True
        or protected_runtime["path"] != "/runtime"
        or protected_runtime["explicit"] is not True
        or protected_runtime["read_only"] is not True
        or protected_runtime["ready"] is not True
        or protected_runtime["error"] is not None
        or len(protected_runtime["records"]) != 1
        or protected_runtime["records"][0]["mount_point"] != "/runtime"
        or "ro" not in protected_runtime["records"][0]["mount_options"]
        or nearest.legacy.parent._RUNTIME["runtime_volume"]
        not in protected_runtime["records"][0]["root"]
        or len(document["actions"]) != 1
        or document["routes"]
        != [
            {
                "action_id": "fresh-session-reset",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
    ):
        raise AdmissionEvidenceError("V2 aggregate reset selected route changed")
    action = document["actions"][0]
    observed = action["observations"]
    before = observed["session_before_reset"]
    rotated = observed["session_after_rotation"]
    after = observed["session_after_reset"]
    reset = observed["reset_turn"]
    nonce = document["run_nonce"]
    before_id = before["entry"]["session_id"]
    after_id = after["entry"]["session_id"]
    if (
        action["id"] != "fresh-session-reset"
        or action["execution_error"] is not None
        or action["reason_codes"] != []
        or action["status"] != "OBSERVED"
        or not isinstance(nonce, str)
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        or _UUID4.fullmatch(before_id) is None
        or _UUID4.fullmatch(after_id) is None
        or before_id == after_id
        or observed["session_id_rotated"] is not True
        or observed["reset_snapshot_cleared"] is not True
        or observed["rebuilt_snapshot_matches_baseline"] is not True
        or rotated["entry"]["session_id"] != after_id
        or rotated["present"] is not True
        or rotated["entry"]["snapshot_present"] is not False
        or rotated["entry"]["skill_names"] != []
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
        or set(observed["session_before_reset_check"]) != _READY
        or not all(observed["session_before_reset_check"].values())
        or set(observed["session_after_reset_check"]) != _READY
        or not all(observed["session_after_reset_check"].values())
        or reset["accepted"] is not True
        or reset["error"] is not None
        or reset["method"] != "chat.send"
        or reset["params"]
        != {
            "deliver": False,
            "idempotencyKey": f"aragorn-protected-route-fresh-session-reset-{nonce}",
            "message": "/new",
            "sessionKey": nearest.legacy._SESSION_KEY,
            "timeoutMs": 5000,
        }
        or reset["response"]
        != {
            "runId": f"aragorn-protected-route-fresh-session-reset-{nonce}",
            "status": "started",
        }
        or reset["scopes"] != ["operator.admin", "operator.write"]
        or reset["transport"]
        != "openclaw/plugin-sdk/gateway-runtime.callGatewayFromCli"
    ):
        raise AdmissionEvidenceError("V2 aggregate reset transition changed")
    initial = observed["initialization_turn"]
    rebuild = observed["rebuild_turn"]
    _verify_prerequisites(
        action["prerequisites"], container_id=container_id, gateway_pid=gateway_pid
    )
    nearest.legacy._verify_turn(
        initial,
        label="fresh-session-initialize",
        nonce=nonce,
        pids=(initial["send"]["command"]["pid"], initial["wait"]["command"]["pid"]),
    )
    nearest.legacy._verify_turn(
        rebuild,
        label="fresh-session-rebuild",
        nonce=nonce,
        pids=(rebuild["send"]["command"]["pid"], rebuild["wait"]["command"]["pid"]),
    )
    command_pids = [
        command["pid"]
        for command in (
            action["prerequisites"]["commands"]
            + initial["commands"]
            + rebuild["commands"]
        )
    ]
    if any(type(pid) is not int or pid <= 1 for pid in command_pids) or len(
        set(command_pids)
    ) != len(command_pids):
        raise AdmissionEvidenceError("V2 aggregate reset command custody changed")
    before_entry = before["entry"]
    after_entry = after["entry"]
    prompt = before_entry["prompt"]
    _verify_snapshot(before, session_id=before_id)
    _verify_snapshot(after, session_id=after_id)
    _verify_store_file(rotated["file"])
    if (
        action["commands"] != initial["commands"] + rebuild["commands"]
        or before["present"] is not True
        or after["present"] is not True
        or before_entry["snapshot_present"] is not True
        or after_entry["snapshot_present"] is not True
        or before_entry["skill_names"] != ["template-skill"]
        or before_entry["skill_names"] != after_entry["skill_names"]
        or before_entry["snapshot_version"] != after_entry["snapshot_version"]
        or before_entry["prompt"] != after_entry["prompt"]
        or prompt["storage"] != "promptRef"
        or prompt["digest"] != prompt["expected_digest"]
        or prompt["digest"] != _PROMPT_DIGEST
        or len({before["file"]["inode"], rotated["file"]["inode"], after["file"]["inode"]})
        != 3
        or len(
            {
                before["file"]["digest"],
                rotated["file"]["digest"],
                after["file"]["digest"],
            }
        )
        != 3
        or any(
            snapshot["file"]["uid"] != 992
            or snapshot["file"]["gid"] != 992
            or snapshot["file"]["mode"] != "600"
            or snapshot["file"]["nlink"] != 1
            for snapshot in (before, rotated, after)
        )
        or not (
            nearest.legacy._parse_time(initial["wait"]["command"]["completed_at"])
            <= nearest.legacy._parse_time(reset["started_at"])
            <= nearest.legacy._parse_time(reset["completed_at"])
            <= nearest.legacy._parse_time(observed["rotation_observed_at"])
            <= nearest.legacy._parse_time(rebuild["send"]["command"]["started_at"])
            < nearest.legacy._parse_time(document["recorded_at"])
            < nearest.legacy._parse_time(outer_recorded_at)
        )
        or not (
            nearest.legacy._epoch_ms(initial["send"]["command"]["completed_at"])
            <= before_entry["started_at"]
            <= before_entry["ended_at"]
            <= before_entry["updated_at"]
            <= initial["wait"]["response"]["value"]["endedAt"]
            <= nearest.legacy._epoch_ms(initial["wait"]["command"]["completed_at"])
        )
        or not (
            nearest.legacy._epoch_ms(reset["completed_at"])
            <= rotated["entry"]["updated_at"]
            <= nearest.legacy._epoch_ms(observed["rotation_observed_at"])
        )
        or not (
            nearest.legacy._epoch_ms(rebuild["send"]["command"]["completed_at"])
            <= after_entry["started_at"]
            <= after_entry["ended_at"]
            <= after_entry["updated_at"]
            <= rebuild["wait"]["response"]["value"]["endedAt"]
            <= nearest.legacy._epoch_ms(rebuild["wait"]["command"]["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V2 aggregate reset snapshot custody changed")


def _verify_prerequisites(
    value: Mapping[str, Any], *, container_id: str, gateway_pid: int
) -> None:
    commands = value["commands"]
    gateway = value["gateway_process"]
    runtime = value["runtime_files"]
    system = value["system_info"]
    if (
        value["ready"] is not True
        or value["reason_codes"] != []
        or gateway["pid"] != gateway_pid
        or gateway["hostname"] != container_id[:12]
        or gateway["cmdline"] != ["openclaw-gateway"]
        or len(commands) != 2
        or system["command"] != commands[1]
        or system["response"]["parsed"] is not True
        or system["response"]["value"]["pid"] != gateway["pid"]
        or system["response"]["value"]["hostname"] != gateway["hostname"]
        or system["response"]["value"]["machineName"] != gateway["hostname"]
        or system["response"]["value"]["diskPath"]
        != "/var/lib/aragorn-agent-gateway/state"
        or runtime["node"]["executable"] is not True
        or runtime["node"]["file"]["path"] != "/usr/local/bin/node"
        or runtime["node"]["file"]["uid"] != 0
        or runtime["node"]["file"]["gid"] != 0
        or runtime["openclaw"]["executable"] is not True
        or runtime["openclaw"]["file"]["path"]
        != "/runtime/lib/node_modules/openclaw/openclaw.mjs"
        or runtime["openclaw"]["file"]["digest"]
        != nearest.legacy.parent._RUNTIME["entrypoint_digest"]
        or runtime["openclaw"]["file"]["uid"] != 0
        or runtime["openclaw"]["file"]["gid"] != 0
    ):
        raise AdmissionEvidenceError("V2 aggregate reset prerequisites changed")
    nearest.legacy._verify_command(
        commands[0],
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ],
        expected_pid=commands[0]["pid"],
        stdout_exact=nearest.legacy.parent._RUNTIME["version_output"] + "\n",
    )
    nearest.legacy._verify_command(
        commands[1],
        nearest.legacy._gateway_argv("system.info", "5000"),
        expected_pid=commands[1]["pid"],
        stdout_value=system["response"]["value"],
    )


def _verify_snapshot(value: Mapping[str, Any], *, session_id: str) -> None:
    entry = value["entry"]
    prompt = entry["prompt"]
    prompt_file = prompt["file"]
    _verify_store_file(value["file"])
    if (
        value["present"] is not True
        or entry["session_id"] != session_id
        or entry["skill_names"] != ["template-skill"]
        or entry["snapshot_present"] is not True
        or type(entry["snapshot_version"]) is not int
        or entry["snapshot_version"] <= 0
        or entry["status"] != "timeout"
        or type(entry["runtime_ms"]) is not int
        or entry["runtime_ms"] != entry["ended_at"] - entry["started_at"]
        or not (entry["started_at"] <= entry["ended_at"] <= entry["updated_at"])
        or prompt["storage"] != "promptRef"
        or prompt["bytes"] != 737
        or prompt["digest"] != _PROMPT_DIGEST
        or prompt["expected_digest"] != _PROMPT_DIGEST
        or prompt_file["path"] != _PROMPT_PATH
        or prompt_file["exists"] is not True
        or prompt_file["type"] != "file"
        or prompt_file["digest"] != _PROMPT_DIGEST
        or prompt_file["digest_error"] is not None
        or prompt_file["uid"] != 992
        or prompt_file["gid"] != 992
        or prompt_file["mode"] != "600"
        or prompt_file["nlink"] != 1
        or prompt_file["size"] != 737
    ):
        raise AdmissionEvidenceError("V2 aggregate rebuilt snapshot changed")


def _verify_store_file(value: Mapping[str, Any]) -> None:
    if (
        value["path"] != _SESSION_STORE
        or value["exists"] is not True
        or value["type"] != "file"
        or not isinstance(value["digest"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"]) is None
        or value["digest_error"] is not None
        or value["uid"] != 992
        or value["gid"] != 992
        or value["mode"] != "600"
        or value["nlink"] != 1
        or type(value["inode"]) is not int
        or value["inode"] <= 0
        or type(value["size"]) is not int
        or value["size"] <= 0
    ):
        raise AdmissionEvidenceError("V2 aggregate session store changed")
