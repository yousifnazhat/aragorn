"""Verify the bounded P3.7b OpenClaw-to-worker systemd composition."""

from __future__ import annotations

import hashlib
import re
from base64 import b64encode
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import runtime_action_broker as broker
from . import runtime_action_broker_v3 as broker_v3
from . import runtime_action_broker_v4 as broker_v4
from . import runtime_action_decision as action_decision
from . import runtime_producer_lineage_openclaw_systemd_evidence as parent_verifier
from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import RuntimeActionBrokerError
from .runtime_active_skill_lineage import parse_active_runtime_record
from .runtime_capability_grant import parse_runtime_capability_grant
from .runtime_process_profile import runtime_process_profile

_SCHEMA = "aragorn/runtime-action-worker-openclaw-systemd-observation/v1"
_AUTHORITY = (
    "BOUNDED_DISTINCT_GATEWAY_RUNTIME_WORKER_OBSERVATION_ONLY_"
    "NOT_VERIFIED_RETAINED_EVIDENCE_OR_RUN_EDR_RELEASE_AUTHORITY"
)
_EVIDENCE_RAW_DIGEST = (
    "sha256:a4a9bbf375537713e72b9b8dda848202eedbf6ea3fd3a5bf8d3001297b5f82e6"
)
_EVIDENCE_DIGEST = (
    "sha256:4b668b1eae1875c6e129afd8fd0a56c4dc2e912179644bba22cc3e5a285b969e"
)
_EVIDENCE_BYTES = 124_214
_PARENT_RAW_DIGEST = "sha256:" + parent_verifier._RAW_DIGEST
_PARENT_DIGEST = parent_verifier._EVIDENCE_DIGEST
_PARENT_BYTES = 530_696
_PARENT_PATH = (
    "benchmark/evidence/"
    "runtime-producer-lineage-openclaw-systemd-composition-p3-6b-2026-08-07.json"
)
_RETAINED_PATH = (
    "benchmark/evidence/"
    "runtime-action-worker-openclaw-systemd-composition-p3-7b-2026-08-09.json"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_PEER_TRACE = re.compile(
    r"(?P<service>\d+)\s+getsockopt\((?P<fd>\d+), SOL_SOCKET, SO_PEERCRED, "
    r"\{pid=(?P<pid>\d+), uid=(?P<uid>\d+), gid=(?P<gid>\d+)\}, "
    r"\[12\]\) = 0"
)
_ACCEPT_TRACE = re.compile(
    r"(?P<service>\d+)\s+accept(?:4)?\((?P<listener_fd>\d+),.*\) = (?P<fd>\d+)"
)
_ACCEPT_SUCCESS_RECORD = re.compile(
    r"(?P<service>\d+)\s+accept(?:4)?\(.*\) = (?P<fd>\d+)(?:\s+.*)?"
)
_UNIX_ACCEPT_PREFIX = re.compile(
    r"(?P<service>\d+)\s+accept(?:4)?\(.*sa_family=AF_UNIX"
)
_UNSUPPORTED_RESUMED_SOCKET_SYSCALL = re.compile(
    r"(?P<service>\d+)\s+<\.\.\. "
    r"(?:accept|accept4|connect|getsockopt) resumed>.*"
)
_CONNECT_TRACE = re.compile(
    r"(?P<service>\d+)\s+connect\((?P<fd>\d+), "
    r'\{sa_family=AF_UNIX, sun_path="(?P<path>[^"]+)"\}, \d+\) = 0'
)
_CONNECT_ATTEMPT_TRACE = re.compile(
    r"(?P<service>\d+)\s+connect\((?P<fd>\d+), "
    r'\{sa_family=AF_UNIX, sun_path="(?P<path>[^"]+)"\}, \d+\) = (?P<result>.+)'
)
_UNIX_CONNECT_PREFIX = re.compile(r"(?P<service>\d+)\s+connect\(.*sa_family=AF_UNIX")
_DRIVER_FORBIDDEN_FIELDS = {
    "active_context_digest",
    "active_skill_digest",
    "decision",
    "grant",
    "grant_digest",
    "grant_id",
    "health",
    "install_context_digest",
    "lease",
    "measured_action_digest",
    "observation_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
    "policy",
    "policy_digest",
    "policy_version",
    "revocation_source_digest",
    "revocations",
    "runtime_attribution",
    "runtime_digest",
    "runtime_profile_digest",
    "sensor_digest",
    "skill_digest",
    "source_manifest_digest",
}
_TOP_LEVEL = {
    "artifacts",
    "authority",
    "boundaries",
    "cases",
    "decision",
    "harness",
    "identities",
    "inputs",
    "limitations",
    "peer_chain",
    "profiles",
    "recorded_at",
    "runtime",
    "schema",
    "secret_checks",
}
_CASES = {
    "coherent",
    "legacy_openclaw_profile",
    "stale_active_record",
    "unauthorized_worker_peer",
    "worker_binding_mismatch",
    "worker_endpoint_unavailable",
}
_NEGATIVE_CASES = _CASES - {"coherent"}
_DRIVER_CASES = _CASES - {"unauthorized_worker_peer"}
_LIMITATIONS = [
    "ONE_RETAINED_CAS_SINGLE_FILE_SKILL_AND_ONE_OPENCLAW_CREATE_ONLY",
    "LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_NOT_HOST_ATTESTATION",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "GATEWAY_ENDPOINT_METADATA_IS_PRINCIPAL_NOT_EXACT_PROCESS_IDENTITY",
    "WORKER_PROFILE_IS_POINT_IN_TIME_KERNEL_MEASUREMENT_NOT_CONTINUOUS_ATTESTATION",
    "SKILL_PROMPT_PROJECTION_MATCHES_BYTES_BUT_NOT_SEMANTIC_CAUSATION",
    "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_EXTERNAL_NETWORK_ACTION_COVERAGE",
    "NO_HOSTILE_ROOT_HOST_OR_FORCED_POWER_LOSS_QUALIFICATION",
    "VERIFIER_NOT_IMPLEMENTED",
    "RETAINED_EVIDENCE_NOT_PRODUCED",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_DECISION = {
    "aggregate_gate_eligible": False,
    "coherent_worker_allow_created_observed": True,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "legacy_openclaw_profile_rejected_observed": True,
    "one_grant_consumption_observed": True,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "retained_evidence_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "stale_active_record_indeterminate_observed": True,
    "status": "P3_7B_WORKER_TRUST_SPLIT_OBSERVED",
    "unauthorized_worker_peer_rejected_observed": True,
    "verifier_status": "NOT_TESTED",
    "worker_binding_mismatch_indeterminate_observed": True,
    "worker_endpoint_unavailable_not_submitted_observed": True,
    "worker_pid_attribution_observed": True,
}
_QUALIFICATION_LIMITATIONS = [
    "EXACT_PINNED_OPENCLAW_2026_7_1_SINGLE_CAPTURE_ONLY",
    "SOURCE_OBSERVATION_CAPTURE_TIME_NOT_TESTED_AND_FALSE_CEILINGS_PRESERVED",
    "OPENCLAW_PROVIDER_AND_SESSION_RAW_BYTES_NOT_RETAINED_CAPTURE_TIME_DRIVER_ASSERTIONS_ONLY",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "NEGATIVE_SCENARIO_CAUSE_CLASSIFICATION_RELIES_ON_PINNED_CAPTURE_SETUP_NOT_RETAINED_RUNTIME_REASON_EVIDENCE",
    "LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_NOT_INDEPENDENT_HOST_OR_CONTAINER_ATTESTATION",
    "GATEWAY_ENDPOINT_OWNERSHIP_NOT_EXACT_WORKER_SERVER_PROCESS_AUTHENTICATION",
    "POINT_IN_TIME_WORKER_PROFILE_NOT_CONTINUOUS_MEASUREMENT",
    "SKILL_PROMPT_BYTES_NOT_SEMANTIC_SKILL_CAUSATION",
    "ONE_SINGLE_FILE_CREATE_ACTION_ONLY",
    "NO_MULTI_FILE_OR_BROADER_ACTION_FAMILY_COVERAGE",
    "NO_HOSTILE_ROOT_SAME_UID_OUTPUT_DIRECTORY_OR_POWER_LOSS_QUALIFICATION",
    "PYTHON_STDLIB_AND_DYNAMIC_VERIFIER_DEPENDENCY_CLOSURE_NOT_PINNED",
    "TRACE_PROVES_SINGLE_ROUTE_CONNECT_WITHOUT_CONNECT_RETRY_NOT_SEND_SYSCALL_COUNT",
    "NO_AGGREGATE_RUN_01_RUN_02_OR_PHASE_3_EXIT_AUTHORITY",
    "NO_EDR_INSTALLER_OR_PUBLIC_RELEASE_AUTHORITY",
]
_QUALIFICATION_DECISION = {
    "aggregate_gate_eligible": False,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "qualified_pair_retained_evidence_eligible": True,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "source_observation_unchanged": True,
    "source_observation_verified": True,
    "status": "P3_7B_BOUNDED_PASS",
}
_RUNTIME = {
    "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
    "entrypoint_digest": (
        "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
    ),
    "expected_version": "OpenClaw 2026.7.1 (2d2ddc4)",
    "root": "/runtime",
    "tree": {
        "algorithm": "aragorn/runtime-tree/v1",
        "entry_count": 45_856,
        "file_count": 45_837,
        "symlink_count": 19,
        "total_bytes": 369_317_461,
        "tree_digest": (
            "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c"
        ),
    },
    "version_output": "OpenClaw 2026.7.1 (2d2ddc4)",
}
_COLLECTORS = {
    "base_installer": (
        "/src/packaging/install-runtime-capability-host.sh",
        3_252,
        "sha256:b2b52f5a1623f41e859127b65631015b15a532fc57d9a1c17f73a7bdf7f196a3",
        "0755",
    ),
    "capture_recipe": (
        "/src/scripts/capture_runtime_action_worker_openclaw_systemd.sh",
        12_637,
        "sha256:dad86ccbfee46fecb0f30c3f5bc31818d2cadd48450cd4814b2d4690d731b078",
        "0555",
    ),
    "dockerfile": (
        "/src/benchmark/runtime-action-worker-openclaw-systemd/Dockerfile",
        7_945,
        "sha256:7076f8cfdecf0f1a5f7568e830538b94f88c6117b486c58beef7a9be28a50645",
        "0444",
    ),
    "driver": (
        "/src/benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs",
        39_431,
        "sha256:e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140",
        "0555",
    ),
    "installer": (
        "/src/packaging/install-runtime-action-worker-host.sh",
        1_177,
        "sha256:bd19ce747e731d53677ebe2d135395875c5b6a0fd7d7dd1cbd95a4227632c169",
        "0555",
    ),
    "parent_probe": (
        "/src/scripts/runtime_producer_lineage_openclaw_systemd_probe.py",
        31_390,
        "sha256:9ffc9e071c045750201ccfdd4bacda86e6feaaccad6fc69fa099e33376a643aa",
        "0555",
    ),
    "probe": (
        "/src/scripts/runtime_action_worker_openclaw_systemd_probe.py",
        92_452,
        "sha256:9e36dbc38fb3fbe9244dfccab9c7a1d11db053b0746dabe37f90c20c4d419aed",
        "0555",
    ),
}
_INSTALLED_PATHS = {
    "/src/packaging/libexec/aragorn-runtime-action-worker-service.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py"
    ),
    "/src/packaging/openclaw/aragorn-runtime-action-worker/index.js": (
        "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/index.js"
    ),
    "/src/packaging/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json": (
        "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json"
    ),
    "/src/packaging/openclaw/aragorn-runtime-action-worker/package.json": (
        "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/package.json"
    ),
    "/src/packaging/systemd/aragorn-agent-gateway.service": (
        "/usr/lib/systemd/system/aragorn-agent-gateway.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-action-worker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-action-worker.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-action-worker.sysusers": (
        "/usr/lib/sysusers.d/aragorn-runtime-action-worker.conf"
    ),
    "/src/src/aragorn/runtime_action_worker.py": (
        "/usr/lib/aragorn/aragorn/runtime_action_worker.py"
    ),
}
_CASE_RESULTS = {
    "coherent": ("COMPLETED", "ALLOW", "CREATED"),
    "legacy_openclaw_profile": ("INDETERMINATE", None, None),
    "stale_active_record": ("INDETERMINATE", None, None),
    "worker_binding_mismatch": ("INDETERMINATE", None, None),
    "worker_endpoint_unavailable": ("NOT_SUBMITTED", None, None),
}
_DRIVER_CHECKS = {
    "exact_gateway_session_key",
    "exact_openclaw_history_error_classification",
    "exact_rpc_history_shape_without_details",
    "exact_tool_call_id_identity",
    "exact_transcript_details_schema_and_status",
    "exact_transcript_rpc_tool_result_join",
    "exact_wait_run_id",
    "exact_worker_request_digest",
    "expected_nested_relay_outcome",
    "gateway_pid_present",
    "one_provider_driven_tool_call",
    "provider_completed_without_error",
    "transcript_details_source_result_matches_public_content",
    "transcript_regular_nonsymlink_bounded",
}
_CASE_CHECKS = {
    "coherent": {
        "clean_after",
        "clean_before",
        "correlation_fresh",
        "driver",
        "effect_bound",
        "four_distinct_uids",
        "gateway_to_worker",
        "grant_consumed_once",
        "lease_bound",
        "nested_allow_created",
        "one_send_no_retry",
        "receipt_result_bound",
        "worker_attributed",
        "worker_to_sensor_to_broker",
    },
    "legacy_openclaw_profile": {
        "broker_not_reached",
        "driver",
        "effects_unchanged",
        "exact_connects",
        "gateway_pid",
        "grant_available",
        "sensor_received_worker",
        "worker_received_gateway",
    },
    "stale_active_record": {
        "broker_not_reached",
        "driver",
        "effects_unchanged",
        "exact_connects",
        "gateway_pid",
        "grant_available",
        "sensor_received_worker",
        "worker_received_gateway",
    },
    "unauthorized_worker_peer": {
        "broker_not_reached",
        "effects_unchanged",
        "grant_available",
        "peer_closed",
        "sensor_not_reached",
        "worker_authenticated_root",
        "worker_no_connect",
    },
    "worker_binding_mismatch": {
        "broker_not_reached",
        "driver",
        "effects_unchanged",
        "exact_connects",
        "gateway_pid",
        "grant_available",
        "sensor_received_worker",
        "worker_received_gateway",
    },
    "worker_endpoint_unavailable": {
        "broker_not_reached",
        "driver",
        "effects_unchanged",
        "gateway_pid",
        "grant_available",
        "listener_identity_restored",
        "pids_stable",
        "sensor_not_reached",
        "worker_not_reached",
    },
}
_CASE_FIELDS = {
    "coherent": {
        "broker_state",
        "checks",
        "correlation",
        "driver",
        "effects",
        "receipt",
        "receipt_file",
        "status",
        "target",
        "traces",
    },
    "legacy_openclaw_profile": {"checks", "driver", "effects", "status", "traces"},
    "stale_active_record": {"checks", "driver", "effects", "status", "traces"},
    "worker_binding_mismatch": {
        "checks",
        "driver",
        "effects",
        "status",
        "traces",
    },
    "unauthorized_worker_peer": {"checks", "client", "effects", "status", "traces"},
    "worker_endpoint_unavailable": {
        "checks",
        "driver",
        "effects",
        "endpoint_identity",
        "service_pids",
        "status",
        "traces",
    },
}
_BOUNDARY_CHECKS = {
    "covered_read_only_paths",
    "gateway_identity",
    "loaded_new_units",
    "no_effective_capabilities",
    "read_only_mounts",
    "socket_metadata",
    "unit_dependency",
    "worker_identity",
}
_LOADED_UNIT_CHECKS = {
    "credential",
    "direct_process",
    "hardening",
    "inaccessible_paths",
    "principal",
    "read_only_paths",
    "read_write_paths",
    "source_fragment",
}
_UNIT_FIELDS = {
    "ActiveState",
    "AmbientCapabilities",
    "CapabilityBoundingSet",
    "ControlGroup",
    "DropInPaths",
    "ExecMainStatus",
    "ExecStart",
    "FragmentDigest",
    "FragmentPath",
    "FragmentResolvedPath",
    "Group",
    "InaccessiblePaths",
    "LoadCredential",
    "MainPID",
    "NoNewPrivileges",
    "PrivateMounts",
    "PrivateNetwork",
    "ProtectSystem",
    "ReadOnlyPaths",
    "ReadWritePaths",
    "RestrictAddressFamilies",
    "Result",
    "SubState",
    "SupplementaryGroups",
    "User",
}
_PROCESS_FIELDS = {
    "capabilities_effective",
    "cmdline",
    "gids",
    "groups",
    "mount_namespace",
    "network_namespace",
    "no_new_privileges",
    "pid",
    "start_time_ticks",
    "uids",
}
_SOCKET_FIELDS = {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
_GATEWAY_UNIT = "aragorn-agent-gateway.service"
_WORKER_UNIT = "aragorn-runtime-action-worker.service"
_BROKER_UNIT = "aragorn-runtime-lineage-capability-action-broker.service"
_SENSOR_UNIT = "aragorn-runtime-lineage-capability-observation-publisher.service"
_INSTALLED_CLOSURE_DIGEST = (
    "sha256:ce8fc4c83eda97f83cbbd6217e097b4708ea8ade50603d1c5a5260b95fcac2f0"
)
_ACTION_PATH_DIGEST = (
    "sha256:5b28a4367dcbd67e839c5df69446b373c92fc25499e4c2757863246b7eed9c63"
)
_RECORDED_AT = "2026-08-09T12:40:08.660771Z"
_CHILD_IMAGE = "sha256:1afab032375efbe87ac938c0993880e164d6dace2e37239a27c6def8e320e1db"
_IMAGE_LINEAGE_DIGEST = (
    "sha256:f36058c956b9b6bbe58ee349023018d9f6d5f5344d9b02736564a4082507fe72"
)


def verify_runtime_action_worker_openclaw_systemd_evidence(
    document: Mapping[str, Any],
    parent: Mapping[str, Any],
    *,
    expected_digest: str | None,
) -> None:
    """Replay the exact v6 artifact without promoting aggregate authority."""

    try:
        _expect(expected_digest == _EVIDENCE_DIGEST, "retained digest pin changed")
        _expect(set(document) == _TOP_LEVEL, "top-level fields changed")
        _expect(not _contains_float(document), "floating-point evidence is invalid")
        encoded = canonical_json(document)
        _expect(canonical_digest(document) == _EVIDENCE_DIGEST, "evidence changed")
        _expect(
            _raw_digest(encoded + b"\n") == _EVIDENCE_RAW_DIGEST
            and len(encoded) + 1 == _EVIDENCE_BYTES,
            "raw evidence identity changed",
        )
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["authority"] == _AUTHORITY, "authority changed")
        _expect(document["limitations"] == _LIMITATIONS, "source ceiling changed")
        _expect(document["decision"] == _DECISION, "source decision changed")
        _expect(
            document["recorded_at"] == _RECORDED_AT
            and _time(document["recorded_at"])
            >= max(
                _time(case["driver"]["output"]["timing"]["completed_at"])
                for name, case in document["cases"].items()
                if name in _DRIVER_CASES
            ),
            "source recorded time changed",
        )
        parent_encoded = canonical_json(parent)
        _expect(
            _raw_digest(parent_encoded + b"\n") == _PARENT_RAW_DIGEST
            and len(parent_encoded) + 1 == _PARENT_BYTES,
            "parent raw evidence identity changed",
        )
        parent_verifier.verify_runtime_producer_lineage_openclaw_systemd_evidence(
            parent, expected_digest=_PARENT_DIGEST
        )
        _verify_parent_binding(document, parent)
        _verify_digest_documents(document)
        _verify_file_records(document)
        container_id, runtime_volume = _verify_harness(document["harness"])
        installed_inventory = _verify_artifacts(document["artifacts"])
        context = _verify_inputs(document["inputs"], document["profiles"])
        _verify_cases(document["cases"], context)
        _verify_boundaries(
            document["boundaries"],
            document["identities"],
            installed_inventory,
            container_id,
            runtime_volume,
        )
        _verify_peer_chain(
            document["peer_chain"],
            document["cases"],
            document["boundaries"],
            document["identities"],
            context,
        )
        _expect(document["runtime"] == _RUNTIME, "runtime identity changed")
        _verify_secrets(document["secret_checks"], document["cases"], context)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        IndexError,
        KeyError,
        RuntimeActionBrokerError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime worker OpenClaw systemd evidence: {exc}"
        ) from exc


def runtime_action_worker_openclaw_systemd_qualification(
    document: Mapping[str, Any],
    parent: Mapping[str, Any],
    *,
    expected_digest: str | None,
    implementation_digest: str | None = None,
) -> dict[str, Any]:
    """Return the deterministic qualification for the verified exact pair."""

    verify_runtime_action_worker_openclaw_systemd_evidence(
        document, parent, expected_digest=expected_digest
    )
    verifier_digest = _raw_digest(Path(__file__).read_bytes())
    _expect(
        implementation_digest is not None and implementation_digest == verifier_digest,
        "verifier implementation pin changed",
    )
    profiles = document["profiles"]
    inputs = document["inputs"]
    artifacts = document["artifacts"]["collector"]
    harness = document["harness"]
    return {
        "assurance": (
            "SEMANTICALLY_REPLAY_VERIFIED_PINNED_DISTINCT_WORKER_TRACE_AND_EFFECT_EVIDENCE"
        ),
        "bindings": {
            "harness": {
                "document_digest": harness["digest"],
                "image_id": harness["document"]["image_id"],
                "parent_image_id": harness["document"]["parent_image_id"],
            },
            "implementation": {
                "base_installer_digest": artifacts["base_installer"]["digest"],
                "capture_recipe_digest": artifacts["capture_recipe"]["digest"],
                "dockerfile_digest": artifacts["dockerfile"]["digest"],
                "driver_digest": artifacts["driver"]["digest"],
                "installer_digest": artifacts["installer"]["digest"],
                "installed_closure_digest": _INSTALLED_CLOSURE_DIGEST,
                "parent_probe_digest": artifacts["parent_probe"]["digest"],
                "plugin_digest": document["artifacts"]["plugin"]["digest"],
                "probe_digest": artifacts["probe"]["digest"],
                "verifier_implementation_digest": verifier_digest,
            },
            "parent_evidence": {
                "bytes": _PARENT_BYTES,
                "canonical_digest": _PARENT_DIGEST,
                "path": _PARENT_PATH,
                "raw_digest": _PARENT_RAW_DIGEST,
                "schema": parent_verifier._SCHEMA,
            },
            "runtime": {
                "entrypoint_digest": _RUNTIME["entrypoint_digest"],
                "tree_digest": _RUNTIME["tree"]["tree_digest"],
                "version": _RUNTIME["expected_version"],
            },
            "source_observation": {
                "authority": _AUTHORITY,
                "bytes": _EVIDENCE_BYTES,
                "canonical_digest": _EVIDENCE_DIGEST,
                "path": _RETAINED_PATH,
                "raw_digest": _EVIDENCE_RAW_DIGEST,
                "schema": _SCHEMA,
            },
            "worker": {
                "active_skill_digest": inputs["grant"]["document"][
                    "active_skill_digest"
                ],
                "grant_digest": inputs["grant"]["digest"],
                "legacy_grant_digest": inputs["legacy_grant"]["digest"],
                "legacy_profile_digest": profiles["legacy_openclaw"]["digest"],
                "policy_digest": inputs["policy_digest"],
                "profile_digest": profiles["worker"]["digest"],
            },
        },
        "cases": {
            "coherent": {
                "effect_status": "CREATED",
                "relay_status": "COMPLETED",
                "status": "PASS",
                "verdict": "ALLOW",
            },
            "legacy_openclaw_profile": {
                "relay_status": "INDETERMINATE",
                "status": "PASS",
            },
            "stale_active_record": {
                "relay_status": "INDETERMINATE",
                "status": "PASS",
            },
            "unauthorized_worker_peer": {
                "relay_status": "PEER_CLOSED",
                "status": "PASS",
            },
            "worker_binding_mismatch": {
                "relay_status": "INDETERMINATE",
                "status": "PASS",
            },
            "worker_endpoint_unavailable": {
                "relay_status": "NOT_SUBMITTED",
                "status": "PASS",
            },
        },
        "decision": dict(_QUALIFICATION_DECISION),
        "limitations": list(_QUALIFICATION_LIMITATIONS),
        "schema": "aragorn/runtime-action-worker-openclaw-systemd-qualification/v1",
        "source_recorded_at": document["recorded_at"],
    }


def _verify_parent_binding(
    document: Mapping[str, Any], parent: Mapping[str, Any]
) -> None:
    harness = document["harness"]["document"]
    _expect(
        harness["parent_image_id"] == parent_verifier._P36B_IMAGE,
        "parent image changed",
    )
    producer = document["inputs"]["producer"]
    parent_producer = parent["producer"]
    transaction = producer["transaction"]
    parent_transaction = parent_producer["transaction"]
    for field in (
        "context_id",
        "manifest_digest",
        "tree_digest",
        "version_path",
    ):
        _expect(transaction[field] == parent_transaction[field], "producer drifted")
    _expect(
        producer["skill"]["digest"] == parent_producer["tree_entry"]["digest"]
        and producer["skill"]["bytes"] == parent_producer["tree_entry"]["size"],
        "producer skill changed",
    )


def _verify_digest_documents(document: Mapping[str, Any]) -> None:
    pairs: list[Mapping[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            if "digest" in value and isinstance(value.get("document"), Mapping):
                pairs.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    _expect(len(pairs) == 22, "digest-document closure changed")
    for pair in pairs:
        _expect(
            pair["digest"] == canonical_digest(pair["document"]),
            "retained document digest changed",
        )


def _verify_file_records(document: Mapping[str, Any]) -> None:
    records: list[Mapping[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            if {"bytes", "digest", "path", "stat"}.issubset(value):
                records.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    _expect(len(records) == 38, "retained file-record closure changed")
    for record in records:
        _verify_file(record)


def _verify_file(value: Mapping[str, Any]) -> None:
    stat = value["stat"]
    _expect(
        set(value) == {"bytes", "digest", "path", "stat"}
        and set(stat)
        == {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        and isinstance(value["path"], str)
        and value["path"].startswith("/")
        and _digest(value["digest"])
        and isinstance(value["bytes"], int)
        and not isinstance(value["bytes"], bool)
        and value["bytes"] >= 0
        and stat["type"] == "file"
        and isinstance(stat["mode"], str)
        and re.fullmatch(r"[0-7]{4}", stat["mode"]) is not None
        and all(
            isinstance(stat[field], int)
            and not isinstance(stat[field], bool)
            and stat[field] >= 0
            for field in ("device", "gid", "size", "uid")
        )
        and all(
            isinstance(stat[field], int)
            and not isinstance(stat[field], bool)
            and stat[field] > 0
            for field in ("inode", "nlink")
        )
        and value["bytes"] == stat["size"],
        "retained file record changed",
    )


def _verify_harness(value: Mapping[str, Any]) -> tuple[str, str]:
    harness = value["document"]
    _expect(
        set(value) == {"digest", "document"}
        and set(harness)
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
            "run_image_reference",
            "schema",
        }
        and value["digest"] == canonical_digest(harness),
        "harness digest or shape changed",
    )
    _expect(
        harness["schema"] == "aragorn/runtime-action-worker-openclaw-systemd-harness/v1"
        and harness["capture_disposition"]
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and _HEX64.fullmatch(harness["container_id"])
        and harness["image_id"] == _CHILD_IMAGE
        and harness["run_image_reference"] == harness["image_id"]
        and harness["image_reference"]
        == "aragorn-p37b-runtime-action-worker-openclaw-systemd"
        and harness["parent_image_id"] == parent_verifier._P36B_IMAGE
        and harness["platform"] == "linux"
        and harness["profile_label"] == "p3.7b",
        "harness identity changed",
    )
    lineage = harness["image_lineage"]
    parent, child = lineage["parent"], lineage["child"]
    _expect(
        parent["id"] == parent_verifier._P36B_IMAGE
        and child["id"] == harness["image_id"]
        and canonical_digest(lineage) == _IMAGE_LINEAGE_DIGEST
        and parent["rootfs_type"] == child["rootfs_type"] == "layers"
        and child["layers"][: len(parent["layers"])] == parent["layers"]
        and lineage["added_layers"] == child["layers"][len(parent["layers"]) :]
        and len(lineage["added_layers"]) == 9,
        "child image lineage changed",
    )
    _expect(
        harness["openclaw_runtime_mount"]
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        }
        and harness["openclaw_runtime_volume"] == "aragorn-openclaw-2026-7-1-runtime"
        and harness["openclaw_runtime_volume_identity"]
        == {
            "driver": "local",
            "labels": None,
            "name": "aragorn-openclaw-2026-7-1-runtime",
            "options": None,
            "scope": "local",
        }
        and harness["host_config"]
        == {
            "binds": [
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "aragorn-openclaw-2026-7-1-runtime:/runtime:ro",
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
        "outer harness profile changed",
    )
    return harness["container_id"], harness["openclaw_runtime_volume"]


def _installed_inventory(installed: list[Mapping[str, Any]]) -> dict[str, Any]:
    files = [
        {
            "digest": item["installed"]["digest"],
            "mode": item["installed"]["stat"]["mode"],
            "path": item["installed"]["path"],
            "size": item["installed"]["bytes"],
        }
        for item in installed
    ]
    return {
        "files": sorted(files, key=lambda item: item["path"]),
        "schema": "aragorn/runtime-action-worker-installed-closure/v1",
    }


def _verify_artifacts(value: Mapping[str, Any]) -> dict[str, Any]:
    _expect(set(value) == {"collector", "installed", "plugin"}, "artifacts changed")
    collector = value["collector"]
    _expect(set(collector) == set(_COLLECTORS), "collector closure changed")
    for name, (path, size, digest, mode) in _COLLECTORS.items():
        item = collector[name]
        _expect(
            item["path"] == path
            and item["bytes"] == size
            and item["digest"] == digest
            and item["stat"]["mode"] == mode
            and item["stat"]["uid"] == 0
            and item["stat"]["gid"] == 0
            and item["stat"]["nlink"] == 1
            and item["stat"]["type"] == "file",
            f"collector changed: {name}",
        )
    installed = value["installed"]
    _expect(len(installed) == len(_INSTALLED_PATHS), "installed closure changed")
    by_source = {item["source"]["path"]: item for item in installed}
    _expect(set(by_source) == set(_INSTALLED_PATHS), "installed sources changed")
    for source_path, target_path in _INSTALLED_PATHS.items():
        pair = by_source[source_path]
        source = pair["source"]
        target = pair["installed"]
        expected_target_mode = (
            "0755"
            if target_path
            == "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py"
            else "0644"
        )
        _expect(
            set(pair) == {"installed", "source"}
            and target["path"] == target_path
            and (source["digest"], source["bytes"])
            == (target["digest"], target["bytes"])
            and source["stat"]["type"] == "file"
            and source["stat"]["uid"] == 0
            and source["stat"]["gid"] == 0
            and source["stat"]["nlink"] == 1
            and source["stat"]["mode"] == "0444"
            and target["stat"]["type"] == "file"
            and target["stat"]["uid"] == 0
            and target["stat"]["gid"] == 0
            and target["stat"]["nlink"] == 1
            and target["stat"]["mode"] == expected_target_mode,
            f"source/install binding changed: {target_path}",
        )
    plugin = value["plugin"]
    plugin_sources = [
        "/src/packaging/openclaw/aragorn-runtime-action-worker/index.js",
        "/src/packaging/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json",
        "/src/packaging/openclaw/aragorn-runtime-action-worker/package.json",
    ]
    _expect(
        set(plugin) == {"digest", "files"}
        and plugin["files"] == [by_source[path] for path in plugin_sources],
        "plugin installed-subset binding changed",
    )
    identity = []
    for item in plugin["files"]:
        source, target = item["source"], item["installed"]
        _expect(
            (source["digest"], source["bytes"]) == (target["digest"], target["bytes"]),
            "plugin source/install binding changed",
        )
        identity.append(
            {
                "digest": target["digest"],
                "executable": bool(int(target["stat"]["mode"], 8) & 0o111),
                "kind": "file",
                "links": target["stat"]["nlink"],
                "path": Path(target["path"]).name,
                "size": target["bytes"],
            }
        )
    _expect(plugin["digest"] == canonical_digest(identity), "plugin digest changed")
    inventory = _installed_inventory(installed)
    _expect(
        canonical_digest(inventory) == _INSTALLED_CLOSURE_DIGEST,
        "installed implementation closure changed",
    )
    return inventory


def _verify_inputs(
    inputs: Mapping[str, Any], profiles: Mapping[str, Any]
) -> dict[str, Any]:
    _expect(
        set(inputs)
        == {
            "action",
            "active_record",
            "control_sets",
            "driver_authority_pins_absent",
            "driver_authority_values_absent",
            "gateway_authority_pins_absent",
            "gateway_config",
            "gateway_secrets_retained",
            "grant",
            "legacy_grant",
            "policy",
            "policy_digest",
            "producer",
            "stale_active_record",
            "worker_binding",
            "worker_binding_mismatch",
        },
        "input closure changed",
    )
    _expect(
        inputs["driver_authority_pins_absent"] is True
        and inputs["driver_authority_values_absent"] is True
        and inputs["gateway_authority_pins_absent"] is True
        and inputs["gateway_secrets_retained"] is False,
        "runtime-facing authority ceiling changed",
    )
    producer = inputs["producer"]
    active_record = inputs["active_record"]
    stale_record = inputs["stale_active_record"]
    _expect(
        set(producer) == {"projected_skill", "record", "skill", "transaction"}
        and set(producer["record"]) == {"digest", "document", "file", "raw_digest"}
        and active_record
        == {key: producer["record"][key] for key in ("digest", "document", "file")}
        and producer["transaction"] == producer["record"]["document"]["transaction"]
        and producer["transaction"] == active_record["document"]["transaction"]
        and producer["record"]["raw_digest"] == producer["record"]["digest"]
        and producer["skill"]["digest"] == producer["projected_skill"]["digest"]
        and producer["skill"]["bytes"] == producer["projected_skill"]["bytes"],
        "producer fixture changed",
    )
    for name, record in (("active", active_record), ("stale", stale_record)):
        encoded = canonical_json(record["document"])
        parsed_record = parse_active_runtime_record(encoded)
        _verify_protected_file_metadata(
            record["file"], f"{name} active-record metadata changed"
        )
        _expect(
            set(record) == {"digest", "document", "file"}
            and parsed_record == record["document"]
            and record["digest"] == record["file"]["digest"] == _raw_digest(encoded)
            and record["file"]["bytes"] == len(encoded)
            and record["file"]["path"]
            == "/var/lib/aragorn-protected/skills/.aragorn-active-runtime.json",
            f"{name} active-record file binding changed",
        )
    for name, record in (
        ("producer skill", producer["skill"]),
        ("projected skill", producer["projected_skill"]),
    ):
        _verify_protected_file_metadata(record, f"{name} metadata changed")
    stale_transaction = stale_record["document"]["transaction"]
    transaction = producer["transaction"]
    expected_version_path = (
        f".aragorn-versions/{transaction['destination']['target_name']}/"
        f"{transaction['context_id'][7:]}-{transaction['manifest_digest'][7:]}"
    )
    expected_skill_path = (
        f"/var/lib/aragorn-protected/skills/{expected_version_path}/SKILL.md"
    )
    _expect(
        transaction["schema"] == "aragorn/protected-install-transaction/v1"
        and transaction["authority"]
        == "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        and transaction["context_digest"]
        == "sha256:42aa7ec326ecf17002c630f21a8975176a4008381ef9ed136bfcccee8f5f5b9a"
        and transaction["operation"] == "install"
        and transaction["expected_active"] is None
        and transaction["destination"]["target_name"] == "aragorn-admitted"
        and transaction["destination"]["root_device"]
        == producer["skill"]["stat"]["device"]
        == active_record["file"]["stat"]["device"]
        == stale_record["file"]["stat"]["device"]
        and transaction["destination"]["root_inode"] == 1_199_182
        and transaction["version_path"] == expected_version_path,
        "producer transaction contract changed",
    )
    _expect(
        producer["skill"]["path"] == expected_skill_path
        and producer["projected_skill"]["path"]
        == "/var/lib/aragorn-agent-gateway/state/skills/template-skill/SKILL.md",
        "producer skill provenance changed",
    )
    expected_stale_tree = canonical_digest(
        {
            "schema": "aragorn/p37b-stale-active-tree/v1",
            "tree_digest": transaction["tree_digest"],
        }
    )
    _expect(
        stale_record["document"]
        == {
            **active_record["document"],
            "transaction": {
                **active_record["document"]["transaction"],
                "tree_digest": expected_stale_tree,
            },
        }
        and stale_transaction["tree_digest"] != producer["transaction"]["tree_digest"],
        "stale active-record fixture changed",
    )
    action = inputs["action"]
    _expect(
        set(action) == {"operation_digest", "path_digest", "payload_digest"}
        and action["operation_digest"]
        == canonical_digest(
            {"operation": "create", "schema": "aragorn/runtime-file-operation/v1"}
        )
        and action["path_digest"] == _ACTION_PATH_DIGEST
        and action["payload_digest"]
        == _raw_digest(b"Aragorn P3.7b distinct worker create\n"),
        "action binding changed",
    )
    policy = inputs["policy"]
    _expect(
        inputs["policy_digest"] == canonical_digest(policy)
        and policy["schema"] == "aragorn/runtime-action-policy/v1"
        and policy["id"] == "p3-7b-distinct-gateway-runtime-worker"
        and policy["sensor_digest"] == "sha256:" + "3" * 64
        and policy["revocation_source_digest"] == "sha256:" + "4" * 64
        and policy["default"] == "BLOCK"
        and policy["version"] == 1
        and len(policy["allow"]) == 1
        and policy["allow"][0]
        == {
            **action,
            "active_skill_digest": producer["skill"]["digest"],
            "runtime_digest": _RUNTIME["tree"]["tree_digest"],
        },
        "worker policy changed",
    )
    gateway_config = inputs["gateway_config"]
    _expect(
        canonical_digest(gateway_config)
        == "sha256:adc853022d5ec413a614d261f92d0647bd873b4127ac471360c6d9b26f374114",
        "gateway configuration changed",
    )
    _verify_profiles(profiles, producer)
    grants = {}
    for name, profile_name in (
        ("grant", "worker"),
        ("legacy_grant", "legacy_openclaw"),
    ):
        wrapper = inputs[name]
        _expect(set(wrapper) == {"digest", "document"}, f"{name} wrapper changed")
        grant = parse_runtime_capability_grant(canonical_json(wrapper["document"]))
        _expect(
            wrapper["digest"] == canonical_digest(grant)
            and grant["runtime_profile_digest"] == profiles[profile_name]["digest"]
            and grant["runtime_digest"] == _RUNTIME["tree"]["tree_digest"]
            and grant["active_skill_digest"] == producer["skill"]["digest"]
            and grant["sensor_digest"] == policy["sensor_digest"]
            and grant["policy_digest"] == inputs["policy_digest"]
            and grant["policy_version"] == policy["version"]
            and grant["operation_digest"] == action["operation_digest"]
            and grant["source_manifest_digest"]
            == producer["transaction"]["manifest_digest"]
            and grant["install_context_digest"]
            == producer["transaction"]["context_digest"],
            f"{name} binding changed",
        )
        grants[name] = grant
    _expect(
        profiles["worker"]["digest"] != profiles["legacy_openclaw"]["digest"]
        and grants["grant"]["grant_id"] != grants["legacy_grant"]["grant_id"],
        "legacy and worker authority were not split",
    )
    binding = inputs["worker_binding"]
    mismatch = inputs["worker_binding_mismatch"]
    _expect(
        set(binding)
        == set(mismatch)
        == {
            "active_skill_digest",
            "policy_digest",
            "policy_version",
            "runtime_digest",
            "schema",
        }
        and isinstance(binding["policy_version"], int)
        and not isinstance(binding["policy_version"], bool)
        and binding["policy_version"] > 0
        and isinstance(mismatch["policy_version"], int)
        and not isinstance(mismatch["policy_version"], bool)
        and mismatch["policy_version"] > 0
        and binding
        == {
            "active_skill_digest": producer["skill"]["digest"],
            "policy_digest": inputs["policy_digest"],
            "policy_version": policy["version"],
            "runtime_digest": _RUNTIME["tree"]["tree_digest"],
            "schema": "aragorn/runtime-action-worker-binding/v1",
        }
        and {
            key: value
            for key, value in mismatch.items()
            if key != "active_skill_digest"
        }
        == {
            key: value for key, value in binding.items() if key != "active_skill_digest"
        }
        and mismatch["active_skill_digest"]
        == canonical_digest(
            {
                "active_skill_digest": producer["skill"]["digest"],
                "schema": "aragorn/p37b-worker-binding-mismatch/v1",
            }
        ),
        "worker binding cases changed",
    )
    control_sets = inputs["control_sets"]
    _verify_control_sets(control_sets, policy, action, producer["skill"]["digest"])
    for control_name, grant_name in (
        ("legacy", "legacy_grant"),
        ("worker", "grant"),
        ("stale_refresh", "grant"),
        ("coherent_refresh", "grant"),
    ):
        observed = control_sets[control_name]["observation"]["observed_at_unix"]
        grant = grants[grant_name]
        _expect(
            grant["issued_at_unix"] <= observed < grant["expires_at_unix"],
            f"{control_name} grant control window changed",
        )
    return {
        "action": action,
        "control_sets": control_sets,
        "grant": inputs["grant"],
        "gateway_config": gateway_config,
        "legacy_grant": inputs["legacy_grant"],
        "policy": policy,
        "producer": producer,
        "profiles": profiles,
        "worker_binding": binding,
        "worker_binding_mismatch": mismatch,
    }


def _verify_protected_file_metadata(record: Mapping[str, Any], message: str) -> None:
    metadata = record["stat"]
    _expect(
        metadata["type"] == "file"
        and metadata["uid"] == 0
        and metadata["gid"] == 0
        and metadata["mode"] == "0444"
        and metadata["nlink"] == 1
        and isinstance(metadata["device"], int)
        and not isinstance(metadata["device"], bool)
        and metadata["device"] >= 0
        and isinstance(metadata["inode"], int)
        and not isinstance(metadata["inode"], bool)
        and metadata["inode"] > 0
        and metadata["size"] == record["bytes"],
        message,
    )


def _verify_profiles(profiles: Mapping[str, Any], producer: Mapping[str, Any]) -> None:
    _expect(
        set(profiles) == {"executables", "legacy_openclaw", "worker"},
        "profiles changed",
    )
    for name in ("legacy_openclaw", "worker"):
        wrapper = profiles[name]
        _expect(
            set(wrapper) == {"digest", "document"}, f"{name} profile wrapper changed"
        )
        parsed = runtime_process_profile(wrapper["document"])
        _expect(parsed.digest == wrapper["digest"], f"{name} profile changed")
    executables = profiles["executables"]
    expected_executables = {
        "node": {
            "bytes": 121_333_752,
            "digest": "sha256:3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37",
            "path": "/usr/local/bin/node",
        },
        "worker_python": {
            "bytes": 67_608,
            "digest": "sha256:7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57",
            "path": "/usr/local/bin/python3.12",
        },
    }
    _expect(
        set(executables) == set(expected_executables)
        and all(
            {field: executable[field] for field in ("bytes", "digest", "path")}
            == expected_executables[name]
            for name, executable in executables.items()
        )
        and all(
            executable["stat"]["type"] == "file"
            and executable["stat"]["uid"] == 0
            and executable["stat"]["gid"] == 0
            and executable["stat"]["mode"] == "0755"
            and executable["stat"]["nlink"] == 1
            and executable["bytes"] == executable["stat"]["size"] > 0
            and _digest(executable["digest"])
            for executable in executables.values()
        ),
        "profile executable provenance changed",
    )
    _expect(
        profiles["legacy_openclaw"]["document"]["executable_digest"]
        == executables["node"]["digest"]
        and profiles["worker"]["document"]["executable_digest"]
        == executables["worker_python"]["digest"]
        and profiles["legacy_openclaw"]["document"]["runtime_digest"]
        == _RUNTIME["tree"]["tree_digest"]
        and profiles["worker"]["document"]["runtime_digest"]
        == _RUNTIME["tree"]["tree_digest"]
        and profiles["worker"]["document"]["skill_path"] == producer["skill"]["path"]
        and profiles["legacy_openclaw"]["document"]["skill_path"]
        == producer["projected_skill"]["path"],
        "profile executable or skill binding changed",
    )


def _verify_control_sets(
    control_sets: Mapping[str, Any],
    policy: Mapping[str, Any],
    action: Mapping[str, Any],
    skill_digest: str,
) -> None:
    _expect(
        set(control_sets) == {"coherent_refresh", "legacy", "stale_refresh", "worker"},
        "control epochs changed",
    )
    expected_counters = {
        "legacy": 1,
        "worker": 2,
        "stale_refresh": 3,
        "coherent_refresh": 4,
    }
    prior_time = -1
    for name in ("legacy", "worker", "stale_refresh", "coherent_refresh"):
        controls = control_sets[name]
        _expect(
            set(controls) == {"health", "observation", "policy", "revocations", "state"}
            and controls["policy"] == policy,
            f"{name} control set changed",
        )
        action_decision._policy(controls["policy"])
        action_decision._revocations(controls["revocations"])
        action_decision._health(controls["health"])
        action_decision._active(controls["observation"]["active"])
        action_decision._measured_action(controls["observation"]["measured_action"])
        broker._state(controls["state"])
        counter = expected_counters[name]
        observed = controls["observation"]["observed_at_unix"]
        _expect(
            broker._observation(controls["observation"], observed)
            == controls["observation"],
            f"{name} observation contract changed",
        )
        health = controls["health"]
        observation = controls["observation"]
        active = observation["active"]
        measured = observation["measured_action"]
        revocations = controls["revocations"]
        _expect(
            observation["sequence"] == counter
            and health["epoch"] == counter
            and revocations["generation"] == counter
            and health["observed_at_unix"] == observed
            and revocations["observed_at_unix"] == observed
            and observation["expires_at_unix"] == observed + 5
            and health["expires_at_unix"] == observed + 15
            and revocations["expires_at_unix"] == observed + 15
            and observed > prior_time,
            f"{name} control sequence changed",
        )
        _expect(
            health["status"] == "healthy"
            and health["runtime_digest"] == _RUNTIME["tree"]["tree_digest"]
            and health["sensor_digest"] == policy["sensor_digest"]
            and revocations["source_digest"] == policy["revocation_source_digest"]
            and revocations["skill_digests"] == []
            and observation["sensor_digest"] == policy["sensor_digest"]
            and active["runtime_digest"]
            == measured["runtime_digest"]
            == _RUNTIME["tree"]["tree_digest"]
            and active["active_skill_digest"]
            == measured["active_skill_digest"]
            == skill_digest
            and {
                field: active[field]
                for field in ("run_id", "session_id", "tool_call_id")
            }
            == {
                field: measured[field]
                for field in ("run_id", "session_id", "tool_call_id")
            }
            and all(measured[field] == action[field] for field in action),
            f"{name} measured action changed",
        )
        _expect(
            controls["state"]
            == {
                "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                "consumed": [],
                "effect_journal": None,
                "minimum_mediator_health_epoch": 1,
                "minimum_revocation_generation": 1,
                "schema": "aragorn/runtime-action-broker-state/v2",
            },
            f"{name} initial broker state changed",
        )
        prior_time = observed


def _verify_cases(cases: Mapping[str, Any], context: Mapping[str, Any]) -> None:
    _expect(set(cases) == _CASES, "case inventory changed")
    driver_check_count = 0
    trace_count = 0
    for name, case in cases.items():
        _expect(
            set(case) == _CASE_FIELDS[name] and case["status"] == "OBSERVED",
            f"case shape or status changed: {name}",
        )
        _expect(
            set(case["checks"]) == _CASE_CHECKS[name]
            and all(value is True for value in case["checks"].values()),
            f"case checks changed: {name}",
        )
        if name in _DRIVER_CASES:
            driver_check_count += _verify_driver(name, case["driver"])
            provider_time = int(
                _time(
                    case["driver"]["output"]["provider"]["records"][0]["received_at"]
                ).timestamp()
            )
            grant = (
                context["legacy_grant"]
                if name == "legacy_openclaw_profile"
                else context["grant"]
            )["document"]
            _expect(
                grant["issued_at_unix"] <= provider_time < grant["expires_at_unix"],
                f"driver root grant window changed: {name}",
            )
            gateway_pid = case["driver"]["output"]["gateway"]["system_info"][
                "response"
            ]["pid"]
            traced_gateway_pid = (
                case["service_pids"]["before"]["aragorn-agent-gateway.service"]
                if name == "worker_endpoint_unavailable"
                else case["traces"]["worker"]["channels"][0]["peer"]["pid"]
            )
            _expect(
                gateway_pid == traced_gateway_pid,
                f"driver gateway identity changed: {name}",
            )
        for trace_name, trace in case["traces"].items():
            _verify_trace(trace, unix_only_service=trace_name != "gateway")
            trace_count += 1
        _verify_snapshot_binding(name, case, context)
    _expect(driver_check_count == 70, "driver proof closure changed")
    _expect(trace_count == 19, "trace closure changed")
    for name in (
        "legacy_openclaw_profile",
        "stale_active_record",
        "worker_binding_mismatch",
    ):
        _verify_pre_broker_rejection_topology(cases[name])
    endpoint = cases["worker_endpoint_unavailable"]
    endpoint_identities = endpoint["endpoint_identity"]
    expected_services = {
        "aragorn-agent-gateway.service",
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    _expect(
        set(endpoint_identities) == {"before", "parked", "restored"}
        and all(
            set(identity) == {"device", "inode"}
            and all(
                isinstance(identity[field], int)
                and not isinstance(identity[field], bool)
                for field in ("device", "inode")
            )
            and identity["device"] >= 0
            and identity["inode"] > 0
            for identity in endpoint_identities.values()
        )
        and endpoint_identities["before"]
        == endpoint_identities["parked"]
        == endpoint_identities["restored"]
        == {"device": 97, "inode": 250}
        and set(endpoint["service_pids"]) == {"before", "after"}
        and set(endpoint["service_pids"]["before"]) == expected_services
        and endpoint["service_pids"]["before"] == endpoint["service_pids"]["after"]
        and all(
            isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
            for pid in endpoint["service_pids"]["before"].values()
        ),
        "endpoint restoration changed",
    )
    service_pids = endpoint["service_pids"]["before"]
    _expect(
        endpoint["traces"]["worker"]["service_pid"]
        == service_pids["aragorn-runtime-action-worker.service"]
        and endpoint["traces"]["sensor"]["service_pid"]
        == service_pids[
            "aragorn-runtime-lineage-capability-observation-publisher.service"
        ]
        and endpoint["traces"]["broker"]["service_pid"]
        == service_pids["aragorn-runtime-lineage-capability-action-broker.service"]
        and all(
            trace["channels"] == []
            and trace["successful_connects"] == []
            and _connect_attempt_paths(trace) == []
            for trace in endpoint["traces"].values()
        ),
        "endpoint-unavailable trace topology changed",
    )
    unauthorized = cases["unauthorized_worker_peer"]["client"]
    unauthorized_traces = cases["unauthorized_worker_peer"]["traces"]
    unauthorized_request = {
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "payload_base64": b64encode(b"Aragorn P3.7b distinct worker create\n").decode(
            "ascii"
        ),
        "run_id": "unauthorized-root-run",
        "schema": "aragorn/runtime-action-worker-request/v1",
        "session_id": "unauthorized-root-session",
        "target_name": "runtime-worker-qualified.txt",
        "tool_call_digest": canonical_digest(
            {"schema": "aragorn/p37b-unauthorized-tool-call/v1"}
        ),
    }
    _expect(
        set(unauthorized)
        == {"client", "errno", "error", "outcome", "request_digest", "server_peer"}
        and set(unauthorized["client"]) == {"gid", "pid", "uid"}
        and set(unauthorized["server_peer"]) == {"gid", "pid", "uid"}
        and all(
            isinstance(peer[field], int)
            and not isinstance(peer[field], bool)
            and peer[field] >= 0
            for peer in (unauthorized["client"], unauthorized["server_peer"])
            for field in ("gid", "uid")
        )
        and all(
            isinstance(peer["pid"], int)
            and not isinstance(peer["pid"], bool)
            and peer["pid"] > 0
            for peer in (unauthorized["client"], unauthorized["server_peer"])
        )
        and unauthorized["outcome"] == "PEER_CLOSED"
        and unauthorized["errno"] == 104
        and unauthorized["error"] == "ECONNRESET"
        and unauthorized["request_digest"] == canonical_digest(unauthorized_request)
        and unauthorized["client"]["uid"] == unauthorized["client"]["gid"] == 0
        and unauthorized_traces["worker"]["service_pid"]
        == service_pids["aragorn-runtime-action-worker.service"]
        and unauthorized_traces["sensor"]["service_pid"]
        == service_pids[
            "aragorn-runtime-lineage-capability-observation-publisher.service"
        ]
        and unauthorized_traces["broker"]["service_pid"]
        == service_pids["aragorn-runtime-lineage-capability-action-broker.service"]
        and unauthorized_traces["worker"]["channels"]
        == [{"kind": "accept", "path": None, "peer": unauthorized["client"]}]
        and unauthorized_traces["worker"]["successful_connects"] == []
        and _connect_attempt_paths(unauthorized_traces["worker"]) == []
        and all(
            unauthorized_traces[name]["channels"] == []
            and unauthorized_traces[name]["successful_connects"] == []
            and _connect_attempt_paths(unauthorized_traces[name]) == []
            for name in ("sensor", "broker")
        )
        and unauthorized["server_peer"]
        == {
            "gid": 997,
            "pid": cases["unauthorized_worker_peer"]["traces"]["worker"]["service_pid"],
            "uid": 997,
        },
        "unauthorized peer result changed",
    )
    _verify_coherent(cases["coherent"], context)


def _verify_pre_broker_rejection_topology(case: Mapping[str, Any]) -> None:
    traces = case["traces"]
    worker = traces["worker"]
    sensor = traces["sensor"]
    broker_trace = traces["broker"]
    gateway_pid = case["driver"]["output"]["gateway"]["system_info"]["response"]["pid"]
    _expect(
        set(traces) == {"broker", "sensor", "worker"}
        and worker["channels"]
        == [
            {
                "kind": "accept",
                "path": None,
                "peer": {"gid": 992, "pid": gateway_pid, "uid": 992},
            },
            {
                "kind": "connect",
                "path": "/run/aragorn-runtime-observation/sensor.sock",
                "peer": {
                    "gid": 996,
                    "pid": sensor["service_pid"],
                    "uid": 996,
                },
            },
        ]
        and [entry["path"] for entry in worker["successful_connects"]]
        == ["/run/aragorn-runtime-observation/sensor.sock"]
        and _connect_attempt_paths(worker)
        == ["/run/aragorn-runtime-observation/sensor.sock"]
        and sensor["channels"]
        == [
            {
                "kind": "accept",
                "path": None,
                "peer": {
                    "gid": 997,
                    "pid": worker["service_pid"],
                    "uid": 997,
                },
            }
        ]
        and sensor["successful_connects"] == []
        and _connect_attempt_paths(sensor) == []
        and broker_trace["channels"] == []
        and broker_trace["successful_connects"] == []
        and _connect_attempt_paths(broker_trace) == [],
        "pre-broker rejection topology changed",
    )


def _verify_command_summary(value: Mapping[str, Any]) -> tuple[Any, Any]:
    _expect(
        set(value)
        == {
            "completed_at",
            "error",
            "exit_code",
            "pid",
            "signal",
            "started_at",
            "stderr_bytes",
            "stdout_bytes",
        }
        and isinstance(value["exit_code"], int)
        and not isinstance(value["exit_code"], bool)
        and value["exit_code"] == 0
        and value["error"] is None
        and value["signal"] is None
        and isinstance(value["pid"], int)
        and not isinstance(value["pid"], bool)
        and value["pid"] > 0
        and all(
            isinstance(value[field], int)
            and not isinstance(value[field], bool)
            and value[field] >= 0
            for field in ("stderr_bytes", "stdout_bytes")
        )
        and value["stderr_bytes"] == 0
        and value["stdout_bytes"] > 0,
        "OpenClaw command result changed",
    )
    started = _time(value["started_at"])
    completed = _time(value["completed_at"])
    _expect(started <= completed, "OpenClaw command ordering changed")
    return started, completed


def _verify_driver(name: str, driver: Mapping[str, Any]) -> int:
    expected_status, expected_verdict, expected_effect = _CASE_RESULTS[name]
    expected_source_schema = (
        "aragorn/runtime-action-worker-client-error/v1"
        if name == "worker_endpoint_unavailable"
        else "aragorn/runtime-action-worker-result/v1"
    )
    expected_source_authority = (
        "GATEWAY_CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        if name == "worker_endpoint_unavailable"
        else "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
    )
    scenario_id = name.replace("_", "-")
    scenario = driver["input"]["scenario"]
    expected_broker_result = (
        None
        if expected_verdict is None
        else {"effect_status": expected_effect, "verdict": expected_verdict}
    )
    _expect(
        set(driver)
        == {
            "elapsed_ns",
            "exit_code",
            "input",
            "output",
            "stderr_digest",
            "stdout_digest",
        }
        and set(driver["input"]) == {"scenario", "schema"}
        and set(scenario) == {"content", "expected_result", "id", "target_name"}
        and set(scenario["expected_result"]) == {"broker_result", "schema", "status"}
        and driver["input"]["schema"] == "aragorn/openclaw-worker-driver-input/v1"
        and scenario["id"] == scenario_id
        and scenario["target_name"] == "runtime-worker-qualified.txt"
        and scenario["content"] == "Aragorn P3.7b distinct worker create\n"
        and scenario["expected_result"]
        == {
            "broker_result": expected_broker_result,
            "schema": expected_source_schema,
            "status": expected_status,
        }
        and isinstance(driver["exit_code"], int)
        and not isinstance(driver["exit_code"], bool)
        and driver["exit_code"] == 0
        and isinstance(driver["elapsed_ns"], int)
        and not isinstance(driver["elapsed_ns"], bool)
        and driver["elapsed_ns"] > 0
        and driver["stdout_digest"]
        == driver["stderr_digest"]
        == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        f"driver input changed: {name}",
    )
    output = driver["output"]
    proof = output["scenario"]["proof"]
    checks = proof["checks"]
    observed = proof["observed"]
    turn = output["turn"]
    _expect(
        set(output) == {"gateway", "provider", "scenario", "schema", "timing", "turn"}
        and set(output["gateway"]) == {"system_info"}
        and set(output["gateway"]["system_info"]) == {"command", "response"}
        and set(output["gateway"]["system_info"]["response"]) == {"pid"}
        and isinstance(output["gateway"]["system_info"]["response"]["pid"], int)
        and not isinstance(output["gateway"]["system_info"]["response"]["pid"], bool)
        and output["gateway"]["system_info"]["response"]["pid"] > 0
        and set(output["provider"]) == {"error_count", "records", "request_count"}
        and set(output["scenario"]) == {"proof", "status"}
        and set(proof) == {"checks", "expected", "observed"}
        and set(observed)
        == {
            "broker_result",
            "request_digest",
            "schema",
            "source_authority",
            "source_schema",
            "status",
        }
        and set(turn) == {"history", "identifiers", "send", "wait"}
        and set(turn["identifiers"])
        == {
            "request_digest",
            "run_id",
            "session_id",
            "tool_call_digest",
            "tool_call_id",
        }
        and set(turn["send"]) == {"command", "run_id"}
        and set(turn["wait"]) == {"command", "run_id", "status"}
        and set(turn["history"]) == {"command", "message_count", "session_id"},
        f"driver output shape changed: {name}",
    )
    commands = [
        output["gateway"]["system_info"]["command"],
        turn["send"]["command"],
        turn["wait"]["command"],
        turn["history"]["command"],
    ]
    command_windows = [_verify_command_summary(command) for command in commands]
    timing = output["timing"]
    timing_started = _time(timing["started_at"])
    timing_completed = _time(timing["completed_at"])
    _expect(
        set(timing) == {"completed_at", "elapsed_ms", "started_at"}
        and isinstance(timing["elapsed_ms"], int)
        and not isinstance(timing["elapsed_ms"], bool)
        and timing["elapsed_ms"] > 0
        and timing["elapsed_ms"]
        == int((timing_completed - timing_started).total_seconds() * 1000)
        and driver["elapsed_ns"] >= timing["elapsed_ms"] * 1_000_000
        and timing_started <= command_windows[0][0]
        and all(
            current[1] <= following[0]
            for current, following in pairwise(command_windows)
        )
        and command_windows[-1][1] <= timing_completed,
        f"driver command sequence changed: {name}",
    )
    identifiers = turn["identifiers"]
    request = {
        "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "payload_base64": b64encode(scenario["content"].encode()).decode("ascii"),
        "run_id": identifiers["run_id"],
        "schema": "aragorn/runtime-action-worker-request/v1",
        "session_id": identifiers["session_id"],
        "target_name": scenario["target_name"],
        "tool_call_digest": identifiers["tool_call_digest"],
    }
    request_digest = canonical_digest(request)
    provider_records = output["provider"]["records"]
    provider_times = [_time(record["received_at"]) for record in provider_records]
    _expect(
        output["schema"] == "aragorn/openclaw-worker-driver-output/v1"
        and output["scenario"]["status"] == "PASS"
        and proof["expected"] == scenario["expected_result"]
        and set(checks) == _DRIVER_CHECKS
        and all(value is True for value in checks.values())
        and observed["schema"] == "aragorn/openclaw-worker-driver-relay-summary/v1"
        and observed["source_schema"] == expected_source_schema
        and observed["source_authority"] == expected_source_authority
        and observed["status"] == expected_status
        and isinstance(output["provider"]["request_count"], int)
        and not isinstance(output["provider"]["request_count"], bool)
        and output["provider"]["request_count"] == 2
        and isinstance(output["provider"]["error_count"], int)
        and not isinstance(output["provider"]["error_count"], bool)
        and output["provider"]["error_count"] == 0
        and len(provider_records) == 2
        and all(
            set(record)
            == {
                "authorization_valid",
                "content_type",
                "contract_valid",
                "emitted_tool_call_id",
                "message_prefix_continuity_valid",
                "method",
                "path",
                "received_at",
                "request_bytes",
                "sequence",
                "tool_contract_valid",
                "tool_result_summary_digest",
            }
            and record["authorization_valid"] is True
            and record["contract_valid"] is True
            and record["tool_contract_valid"] is True
            and record["method"] == "POST"
            and record["path"] == "/v1/chat/completions"
            and record["content_type"] == "application/json"
            and isinstance(record["request_bytes"], int)
            and not isinstance(record["request_bytes"], bool)
            and record["request_bytes"] > 0
            and _time(record["received_at"])
            for record in provider_records
        )
        and all(
            isinstance(record["sequence"], int)
            and not isinstance(record["sequence"], bool)
            for record in provider_records
        )
        and [record["sequence"] for record in provider_records] == [1, 2]
        and [record["message_prefix_continuity_valid"] for record in provider_records]
        == [None, True]
        and command_windows[2][0]
        <= provider_times[0]
        < provider_times[1]
        <= command_windows[2][1]
        and provider_records[0]["emitted_tool_call_id"] == identifiers["tool_call_id"]
        and provider_records[1]["emitted_tool_call_id"] is None
        and provider_records[0]["tool_result_summary_digest"] is None
        and provider_records[1]["tool_result_summary_digest"]
        == canonical_digest(observed)
        and turn["wait"]["status"] == "ok"
        and identifiers["session_id"] == turn["history"]["session_id"]
        and identifiers["run_id"] == turn["send"]["run_id"] == turn["wait"]["run_id"]
        and identifiers["tool_call_digest"]
        == _raw_digest(identifiers["tool_call_id"].encode())
        and turn["history"]["message_count"] == 4,
        f"driver proof changed: {name}",
    )
    broker_result = observed["broker_result"]
    if expected_verdict is None:
        _expect(
            broker_result is None
            and (
                observed["request_digest"] is None
                if expected_source_schema
                == "aragorn/runtime-action-worker-client-error/v1"
                else observed["request_digest"] == request_digest
            )
            and identifiers["request_digest"] == observed["request_digest"],
            f"negative driver gained or changed a relay result: {name}",
        )
    else:
        _expect(
            broker_result["verdict"] == expected_verdict
            and broker_result["effect_status"] == expected_effect
            and broker_result["reason_codes"] == []
            and broker_result["source_schema"]
            == "aragorn/runtime-action-broker-result/v1"
            and broker_result["source_authority"]
            == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
            and broker_result["target_name"] == scenario["target_name"]
            and observed["request_digest"]
            == identifiers["request_digest"]
            == request_digest,
            "coherent driver result changed",
        )
    return len(checks)


def _verify_snapshot_binding(
    name: str, case: Mapping[str, Any], context: Mapping[str, Any]
) -> None:
    _expect(
        set(case["effects"]) == {"after", "before"},
        f"effect snapshot inventory changed: {name}",
    )
    before, after = case["effects"]["before"], case["effects"]["after"]
    snapshot_fields = {
        "controls",
        "grant_state",
        "pending_exists",
        "protected_entries",
        "receipt_exists",
        "staging_entries",
        "target_exists",
    }
    _expect(
        set(before) == set(after) == snapshot_fields
        and set(before["grant_state"]) == {"digest", "document"}
        and set(after["grant_state"]) == {"digest", "document"},
        f"effect snapshot shape changed: {name}",
    )
    if name in _NEGATIVE_CASES:
        _expect(before == after, f"negative effect state changed: {name}")
    control_name = {
        "legacy_openclaw_profile": "legacy",
        "worker_binding_mismatch": "worker",
        "worker_endpoint_unavailable": "worker",
        "unauthorized_worker_peer": "worker",
        "stale_active_record": "stale_refresh",
        "coherent": "coherent_refresh",
    }[name]
    _bind_controls(before, context["control_sets"][control_name])
    grant = (
        context["legacy_grant"]
        if name == "legacy_openclaw_profile"
        else context["grant"]
    )
    state = broker_v4._state(before["grant_state"]["document"], grant["digest"])
    _expect(
        before["grant_state"]["digest"] == canonical_digest(state)
        and state["status"] == "AVAILABLE",
        f"initial grant state changed: {name}",
    )
    if name in _NEGATIVE_CASES:
        _expect(
            before["protected_entries"] == []
            and before["staging_entries"] == []
            and before["pending_exists"] is False
            and before["receipt_exists"] is False
            and before["target_exists"] is False,
            f"negative case was not clean: {name}",
        )


def _bind_controls(snapshot: Mapping[str, Any], controls: Mapping[str, Any]) -> None:
    expected = {
        "health.json": canonical_digest(controls["health"]),
        "observation.json": canonical_digest(controls["observation"]),
        "policy.json": canonical_digest(controls["policy"]),
        "revocations.json": canonical_digest(controls["revocations"]),
        "state.json": canonical_digest(controls["state"]),
        "capability-grant-state.json": snapshot["grant_state"]["digest"],
    }
    _expect(snapshot["controls"] == expected, "control snapshot binding changed")


def _verify_runtime_attribution(value: Mapping[str, Any]) -> None:
    _expect(
        set(value)
        == {
            "active_skill_digest",
            "authority",
            "cgroup",
            "executable_digest",
            "gid",
            "mount_namespace",
            "pid",
            "profile_digest",
            "runtime_digest",
            "schema",
            "skill_path",
            "start_time_ticks",
            "uid",
        }
        and value["schema"] == "aragorn/runtime-process-profile-attribution/v1"
        and value["authority"]
        == "KERNEL_PROCESS_PROFILE_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
        and all(
            _digest(value[field])
            for field in (
                "active_skill_digest",
                "executable_digest",
                "profile_digest",
                "runtime_digest",
            )
        )
        and isinstance(value["cgroup"], str)
        and value["cgroup"].startswith("/")
        and isinstance(value["skill_path"], str)
        and value["skill_path"].startswith("/")
        and all(
            isinstance(value[field], int)
            and not isinstance(value[field], bool)
            and value[field] >= 0
            for field in ("gid", "uid")
        )
        and all(
            isinstance(value[field], int)
            and not isinstance(value[field], bool)
            and value[field] > 0
            for field in ("pid", "start_time_ticks")
        )
        and set(value["mount_namespace"]) == {"device", "inode"}
        and isinstance(value["mount_namespace"]["device"], int)
        and not isinstance(value["mount_namespace"]["device"], bool)
        and value["mount_namespace"]["device"] == 4
        and isinstance(value["mount_namespace"]["inode"], int)
        and not isinstance(value["mount_namespace"]["inode"], bool)
        and value["mount_namespace"]["inode"] > 0,
        "runtime attribution contract changed",
    )


def _verify_coherent(case: Mapping[str, Any], context: Mapping[str, Any]) -> None:
    before = case["effects"]["before"]
    after = case["effects"]["after"]
    _expect(
        set(case["receipt"]) == {"digest", "document"}
        and set(case["broker_state"]) == {"digest", "document"}
        and set(case["receipt"]["document"])
        == {
            "authority",
            "broker_result",
            "broker_result_digest",
            "runtime_attribution",
            "runtime_attribution_digest",
            "schema",
            "submission_digest",
        },
        "coherent receipt or broker-state shape changed",
    )
    _expect(
        before["protected_entries"] == []
        and before["staging_entries"] == []
        and before["pending_exists"] is False
        and before["receipt_exists"] is False
        and before["target_exists"] is False,
        "coherent case did not start clean",
    )
    grant = context["grant"]
    consumed = broker_v4._state(after["grant_state"]["document"], grant["digest"])
    _expect(
        consumed["status"] == "CONSUMED"
        and after["grant_state"]["digest"] == canonical_digest(consumed),
        "coherent grant was not consumed",
    )
    claim = consumed["claim"]
    lease = claim["lease"]
    root_grant = grant["document"]
    profile_claim = claim["profile_claim"]
    _expect(
        root_grant["issued_at_unix"]
        <= lease["issued_at_unix"]
        <= profile_claim["claimed_at_unix"]
        < lease["expires_at_unix"]
        <= root_grant["expires_at_unix"],
        "grant and lease temporal order changed",
    )
    _expect(
        lease["expires_at_unix"] == lease["issued_at_unix"] + 5,
        "worker request lifetime changed",
    )
    _expect(
        lease["grant_digest"] == grant["digest"]
        and lease["max_actions"] == root_grant["max_actions"]
        and lease["runtime_profile_digest"] == root_grant["runtime_profile_digest"]
        and lease["runtime_digest"] == root_grant["runtime_digest"]
        and lease["active_skill_digest"] == root_grant["active_skill_digest"]
        and lease["sensor_digest"] == root_grant["sensor_digest"]
        and lease["policy_digest"] == root_grant["policy_digest"]
        and lease["policy_version"] == root_grant["policy_version"]
        and lease["operation_digest"] == root_grant["operation_digest"]
        and lease["path_digest"] == context["action"]["path_digest"]
        and lease["payload_digest"] == context["action"]["payload_digest"],
        "grant and lease authority binding changed",
    )
    result = consumed["result"]
    receipt = case["receipt"]["document"]
    expected_profile_result = broker_v3._result_record(claim["profile_claim"], receipt)
    broker_result = receipt["broker_result"]
    decision = broker_result["decision"]
    driver_output = case["driver"]["output"]
    driver_observed = driver_output["scenario"]["proof"]["observed"]
    driver_identifiers = driver_output["turn"]["identifiers"]
    measured_action = profile_claim["profile_pending"]["measured_action"]
    action_decision._measured_action(measured_action)
    broker_summary = {
        "effect_status": broker_result["effect_status"],
        "reason_codes": broker_result["reason_codes"],
        "source_authority": broker_result["authority"],
        "source_schema": broker_result["schema"],
        "target_name": broker_result["target_name"],
        "verdict": broker_result["verdict"],
    }
    _expect(
        result["profile_result"] == expected_profile_result
        and case["receipt"]["digest"] == canonical_digest(receipt)
        and receipt["broker_result_digest"] == canonical_digest(broker_result)
        and receipt["runtime_attribution_digest"]
        == canonical_digest(receipt["runtime_attribution"])
        and broker_result["verdict"] == "ALLOW"
        and broker_result["effect_status"] == "CREATED"
        and broker_result["reason_codes"] == []
        and decision["verdict"] == "ALLOW"
        and decision["reason_codes"] == []
        and case["correlation"] == measured_action
        and {
            "run_id": measured_action["run_id"],
            "session_id": measured_action["session_id"],
            "tool_call_digest": measured_action["tool_call_id"],
        }
        == {
            key: driver_identifiers[key]
            for key in ("run_id", "session_id", "tool_call_digest")
        }
        and driver_observed["broker_result"] == broker_summary,
        "coherent receipt or result changed",
    )
    broker_state = broker._state(case["broker_state"]["document"])
    inner_request = {
        "active_skill_digest": lease["active_skill_digest"],
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "expires_at_unix": lease["expires_at_unix"],
        "issued_at_unix": lease["issued_at_unix"],
        "operation_digest": lease["operation_digest"],
        "path_digest": lease["path_digest"],
        "payload_digest": lease["payload_digest"],
        "policy_digest": lease["policy_digest"],
        "policy_version": lease["policy_version"],
        "run_id": case["correlation"]["run_id"],
        "runtime_digest": lease["runtime_digest"],
        "schema": "aragorn/runtime-action-request/v1",
        "session_id": case["correlation"]["session_id"],
        "tool_call_id": case["correlation"]["tool_call_id"],
    }
    inner_request_digest = canonical_digest(inner_request)
    inner_envelope = {
        "effect": {
            "operation": "create",
            "payload_base64": b64encode(
                b"Aragorn P3.7b distinct worker create\n"
            ).decode("ascii"),
            "schema": "aragorn/runtime-create-file/v1",
            "target_name": "runtime-worker-qualified.txt",
        },
        "request": inner_request,
        "schema": "aragorn/runtime-action-broker-request/v1",
    }
    inner_envelope_digest = canonical_digest(inner_envelope)
    attribution = profile_claim["profile_pending"]["runtime_attribution"]
    _verify_runtime_attribution(attribution)
    _expect(
        attribution == receipt["runtime_attribution"],
        "pending and receipt attribution changed",
    )
    profiled_submission = {
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "envelope": inner_envelope,
        "envelope_digest": inner_envelope_digest,
        "measured_action": case["correlation"],
        "request_digest": inner_request_digest,
        "runtime_attribution": attribution,
        "runtime_peer": {key: attribution[key] for key in ("pid", "uid", "gid")},
        "schema": "aragorn/runtime-observed-create-submission/v2",
        "sensor_digest": lease["sensor_digest"],
    }
    profiled_submission_digest = canonical_digest(profiled_submission)
    _expect(
        case["broker_state"]["digest"] == canonical_digest(broker_state)
        and broker_state["consumed"]
        == [
            {
                "expires_at_unix": lease["expires_at_unix"],
                "observation_digest": broker_result["observation_digest"],
                "request_digest": broker_result["request_digest"],
            }
        ]
        and broker_state["effect_journal"] is None,
        "coherent broker state changed",
    )
    _expect(
        {
            lease["request_digest"],
            profile_claim["request_digest"],
            profile_claim["profile_pending"]["request_digest"],
            broker_result["request_digest"],
            decision["request_digest"],
            broker_state["consumed"][0]["request_digest"],
        }
        == {inner_request_digest},
        "inner broker request binding changed",
    )
    _expect(
        {
            profile_claim["envelope_digest"],
            profile_claim["profile_pending"]["envelope_digest"],
        }
        == {inner_envelope_digest},
        "inner broker envelope binding changed",
    )
    _expect(
        {
            lease["submission_digest"],
            profile_claim["submission_digest"],
            profile_claim["profile_pending"]["submission_digest"],
            result["profile_result"]["submission_digest"],
            receipt["submission_digest"],
        }
        == {profiled_submission_digest},
        "profiled submission binding changed",
    )
    controls = after["controls"]
    _expect(
        set(controls)
        == {
            "capability-grant-state.json",
            "health.json",
            "observation.json",
            "policy.json",
            "revocations.json",
            "state.json",
        },
        "coherent post-control inventory changed",
    )
    refreshed = context["control_sets"]["coherent_refresh"]
    evaluated = decision["evaluated_at_unix"]
    wait_command = driver_output["turn"]["wait"]["command"]
    provider_records = driver_output["provider"]["records"]
    correlation = case["correlation"]
    active = {
        key: value
        for key, value in correlation.items()
        if key not in {"operation_digest", "path_digest", "payload_digest"}
    }
    active["schema"] = "aragorn/runtime-active-context/v1"
    post_health = {
        **refreshed["health"],
        "epoch": decision["mediator_health_epoch"],
        "expires_at_unix": evaluated + 5,
        "observed_at_unix": evaluated,
    }
    post_observation = {
        **refreshed["observation"],
        "active": active,
        "expires_at_unix": evaluated + 5,
        "measured_action": correlation,
        "observed_at_unix": evaluated,
        "sequence": refreshed["observation"]["sequence"] + 1,
    }
    _expect(
        set(decision)
        == {
            "active_context_digest",
            "authority",
            "evaluated_at_unix",
            "measured_action_digest",
            "mediator_health_digest",
            "mediator_health_epoch",
            "minimum_mediator_health_epoch",
            "minimum_revocation_generation",
            "policy_digest",
            "policy_version",
            "reason_codes",
            "request_digest",
            "revocation_generation",
            "revocation_snapshot_digest",
            "schema",
            "verdict",
        }
        and decision["schema"] == "aragorn/runtime-action-decision/v1"
        and decision["authority"]
        == "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        and all(
            isinstance(decision[field], int)
            and not isinstance(decision[field], bool)
            and decision[field] > 0
            for field in (
                "evaluated_at_unix",
                "mediator_health_epoch",
                "minimum_mediator_health_epoch",
                "minimum_revocation_generation",
                "policy_version",
                "revocation_generation",
            )
        )
        and profile_claim["claimed_at_unix"] <= evaluated < lease["expires_at_unix"]
        and int(_time(wait_command["started_at"]).timestamp())
        <= evaluated
        <= int(_time(wait_command["completed_at"]).timestamp())
        and int(_time(provider_records[0]["received_at"]).timestamp())
        <= evaluated
        <= int(_time(provider_records[1]["received_at"]).timestamp())
        and evaluated >= refreshed["health"]["observed_at_unix"]
        and evaluated >= refreshed["revocations"]["observed_at_unix"]
        and evaluated < refreshed["health"]["expires_at_unix"]
        and evaluated < refreshed["revocations"]["expires_at_unix"]
        and decision["policy_version"] == context["policy"]["version"]
        and decision["mediator_health_epoch"] == refreshed["health"]["epoch"] + 1
        and decision["minimum_mediator_health_epoch"]
        == decision["mediator_health_epoch"]
        == broker_state["minimum_mediator_health_epoch"]
        and decision["revocation_generation"] == refreshed["revocations"]["generation"]
        and decision["minimum_revocation_generation"]
        == decision["revocation_generation"]
        == broker_state["minimum_revocation_generation"],
        "coherent decision scalar binding changed",
    )
    _expect(
        canonical_digest(active) == decision["active_context_digest"]
        and canonical_digest(correlation) == decision["measured_action_digest"]
        and canonical_digest(post_health)
        == controls["health.json"]
        == decision["mediator_health_digest"]
        and canonical_digest(post_observation)
        == controls["observation.json"]
        == broker_result["observation_digest"]
        and canonical_digest(refreshed["policy"])
        == controls["policy.json"]
        == decision["policy_digest"]
        and canonical_digest(refreshed["revocations"])
        == controls["revocations.json"]
        == decision["revocation_snapshot_digest"]
        and canonical_digest(broker_state) == controls["state.json"]
        and canonical_digest(consumed) == controls["capability-grant-state.json"],
        "coherent post-control transition changed",
    )
    attribution = receipt["runtime_attribution"]
    worker_process = case["traces"]["worker"]["service_pid"]
    worker_profile = context["profiles"]["worker"]
    _expect(
        attribution["pid"] == worker_process
        and attribution["profile_digest"] == worker_profile["digest"]
        and attribution["runtime_digest"] == _RUNTIME["tree"]["tree_digest"]
        and attribution["active_skill_digest"]
        == context["producer"]["skill"]["digest"],
        "worker attribution changed",
    )
    target = case["target"]
    receipt_file = case["receipt_file"]
    _expect(
        target["digest"] == context["action"]["payload_digest"]
        and target["bytes"] == len(b"Aragorn P3.7b distinct worker create\n")
        and target["path"]
        == "/var/lib/aragorn-runtime-action/protected/runtime-worker-qualified.txt"
        and target["stat"]["type"] == "file"
        and target["stat"]["uid"] == 995
        and target["stat"]["gid"] == 997
        and target["stat"]["mode"] == "0400"
        and target["stat"]["nlink"] == 1
        and receipt_file["path"]
        == "/var/lib/aragorn-runtime-action/control/profile-receipt.json"
        and receipt_file["digest"] == case["receipt"]["digest"]
        and receipt_file["bytes"] == len(canonical_json(receipt))
        and receipt_file["stat"]["type"] == "file"
        and receipt_file["stat"]["uid"] == 995
        and receipt_file["stat"]["gid"] == 997
        and receipt_file["stat"]["mode"] == "0400"
        and receipt_file["stat"]["nlink"] == 1
        and after["protected_entries"] == ["runtime-worker-qualified.txt"]
        and after["target_exists"] is True
        and after["receipt_exists"] is True
        and after["pending_exists"] is False
        and after["staging_entries"] == [],
        "coherent effect changed",
    )


def _connect_attempt_paths(trace: Mapping[str, Any]) -> list[str]:
    attempts = []
    for line in trace["raw"].splitlines():
        prefix = _UNIX_CONNECT_PREFIX.match(line)
        if prefix is None:
            continue
        attempted = _CONNECT_ATTEMPT_TRACE.fullmatch(line)
        _expect(attempted is not None, "unparsed Unix connect attempt")
        _expect(
            int(attempted["service"]) == trace["service_pid"],
            "trace connect-attempt service changed",
        )
        attempts.append(attempted["path"])
    return attempts


def _verify_trace(trace: Mapping[str, Any], *, unix_only_service: bool) -> None:
    raw = trace["raw"].encode("utf-8")
    _expect(
        set(trace)
        == {
            "channels",
            "raw",
            "raw_bytes",
            "raw_digest",
            "service_pid",
            "successful_connects",
        }
        and trace["raw_bytes"] == len(raw) <= 64 * 1024
        and trace["raw_digest"] == _raw_digest(raw)
        and isinstance(trace["service_pid"], int)
        and not isinstance(trace["service_pid"], bool)
        and trace["service_pid"] > 0,
        "raw trace identity changed",
    )
    for channel in trace["channels"]:
        _expect(
            set(channel) == {"kind", "path", "peer"}
            and channel["kind"] in {"accept", "connect"}
            and (channel["path"] is None or isinstance(channel["path"], str))
            and set(channel["peer"]) == {"gid", "pid", "uid"}
            and all(
                isinstance(channel["peer"][field], int)
                and not isinstance(channel["peer"][field], bool)
                and channel["peer"][field] >= 0
                for field in ("gid", "uid")
            )
            and isinstance(channel["peer"]["pid"], int)
            and not isinstance(channel["peer"]["pid"], bool)
            and channel["peer"]["pid"] > 0,
            "trace channel identity changed",
        )
    for connection in trace["successful_connects"]:
        _expect(
            set(connection) == {"fd", "path"}
            and isinstance(connection["fd"], int)
            and not isinstance(connection["fd"], bool)
            and connection["fd"] > 0
            and isinstance(connection["path"], str),
            "trace connection identity changed",
        )
    lines = trace["raw"].splitlines()
    channels = []
    connects = []
    for line in lines:
        _expect(
            _UNSUPPORTED_RESUMED_SOCKET_SYSCALL.fullmatch(line) is None,
            "unsupported resumed socket syscall",
        )
        if _ACCEPT_SUCCESS_RECORD.fullmatch(line) is not None:
            _expect(
                _ACCEPT_TRACE.fullmatch(line) is not None,
                "unsupported accept success record",
            )
        direct_connect = re.match(r"(?P<service>\d+)\s+connect\(", line)
        if unix_only_service and direct_connect is not None:
            _expect(
                _CONNECT_ATTEMPT_TRACE.fullmatch(line) is not None,
                "unsupported Unix-only connect record",
            )
        service_prefix = re.match(
            r"(?P<service>\d+)\s+(?:accept(?:4)?|connect)\(", line
        )
        if service_prefix is not None:
            _expect(
                int(service_prefix["service"]) == trace["service_pid"],
                "trace service identity changed",
            )
        connected = _CONNECT_TRACE.fullmatch(line)
        if connected is not None:
            _expect(
                int(connected["service"]) == trace["service_pid"],
                "trace connect service changed",
            )
            connects.append({"fd": int(connected["fd"]), "path": connected["path"]})
    _connect_attempt_paths(trace)
    unix_listener_fds = set()
    for index, line in enumerate(lines):
        if _UNIX_ACCEPT_PREFIX.match(line) is None:
            continue
        accepted = _ACCEPT_TRACE.fullmatch(line)
        peer = _PEER_TRACE.fullmatch(lines[index + 1] if index + 1 < len(lines) else "")
        _expect(
            accepted is not None
            and peer is not None
            and int(accepted["service"]) == trace["service_pid"]
            and int(peer["service"]) == trace["service_pid"]
            and int(peer["fd"]) == int(accepted["fd"]),
            "unpaired Unix accept attempt",
        )
        unix_listener_fds.add(int(accepted["listener_fd"]))
    for index, line in enumerate(lines):
        accepted = _ACCEPT_TRACE.fullmatch(line)
        if accepted is None:
            continue
        peer = _PEER_TRACE.fullmatch(lines[index + 1] if index + 1 < len(lines) else "")
        if (
            peer is not None
            and int(accepted["service"]) == trace["service_pid"]
            and int(peer["service"]) == trace["service_pid"]
            and int(peer["fd"]) == int(accepted["fd"])
        ):
            unix_listener_fds.add(int(accepted["listener_fd"]))
    for index, line in enumerate(lines):
        accepted = _ACCEPT_TRACE.fullmatch(line)
        if accepted is None or (
            not unix_only_service
            and int(accepted["listener_fd"]) not in unix_listener_fds
        ):
            continue
        peer = _PEER_TRACE.fullmatch(lines[index + 1] if index + 1 < len(lines) else "")
        _expect(
            peer is not None
            and int(accepted["service"]) == trace["service_pid"]
            and int(peer["service"]) == trace["service_pid"]
            and int(peer["fd"]) == int(accepted["fd"]),
            "unpaired Unix listener accept",
        )
    for index, line in enumerate(lines):
        peer = _PEER_TRACE.fullmatch(line)
        if peer is None:
            continue
        previous = lines[index - 1] if index else ""
        accepted = _ACCEPT_TRACE.fullmatch(previous)
        connected = _CONNECT_TRACE.fullmatch(previous)
        precursor = accepted or connected
        _expect(
            precursor is not None
            and int(peer["service"]) == int(precursor["service"])
            and int(peer["service"]) == trace["service_pid"]
            and int(peer["fd"]) == int(precursor["fd"]),
            "trace channel precursor changed",
        )
        channels.append(
            {
                "kind": "accept" if accepted is not None else "connect",
                "path": None if connected is None else connected["path"],
                "peer": {key: int(peer[key]) for key in ("pid", "uid", "gid")},
            }
        )
    _expect(
        trace["channels"] == channels
        and trace["successful_connects"] == connects
        and trace["raw"].count("SO_PEERCRED") == len(channels),
        "parsed trace changed",
    )


def _verify_unit_contracts(
    units: Mapping[str, Any], processes: Mapping[str, Any]
) -> None:
    worker_command = [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py",
        "/run/credentials/aragorn-runtime-action-worker.service/worker-binding",
    ]
    contracts = {
        _GATEWAY_UNIT: {
            "address_families": {"AF_INET", "AF_INET6", "AF_UNIX"},
            "ambient_capabilities": "",
            "capability_bounding_set": "",
            "command": [
                "/usr/local/bin/node",
                "/runtime/lib/node_modules/openclaw/openclaw.mjs",
                "gateway",
                "run",
                "--auth",
                "token",
                "--bind",
                "loopback",
                "--port",
                "18789",
                "--tailscale",
                "off",
            ],
            "credential": (
                'a(ss) 1 "openclaw-config" "/etc/aragorn/agent-gateway/openclaw.json"'
            ),
            "fragment_digest": (
                "sha256:32dea7dfdf5ccb9914c46ea2aadfc88a491d6eadba5bdb8b4982d473af1a0ebe"
            ),
            "group": "aragorn-agent-gateway",
            "inaccessible": {
                "/etc/aragorn/agent-gateway",
                "/etc/aragorn/runtime-action-observation.json",
                "/etc/aragorn/runtime-action-runtime.json",
                "/etc/aragorn/runtime-action-worker.json",
                "/etc/aragorn/runtime-capability-grant.json",
                "-/etc/aragorn/openclaw-profile",
                "-/etc/aragorn/runtime-action-revocation-publication.json",
                "-/opt/aragorn/openclaw/aragorn-runtime-action",
                "-/var/lib/aragorn-openclaw-profile",
                "/run/aragorn-runtime-observation",
                "/var/lib/aragorn-protected",
                "/var/lib/aragorn-runtime-action",
            },
            "private_network": "no",
            "process_command": ["openclaw-gateway"],
            "read_only": {
                "-/opt/aragorn/runtime-profile",
                "/run/aragorn-runtime-action-worker",
                "/runtime",
                "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker",
            },
            "read_write": {"/var/lib/aragorn-agent-gateway"},
            "supplementary_groups": "",
            "user": "aragorn-agent-gateway",
        },
        _WORKER_UNIT: {
            "address_families": {"AF_UNIX"},
            "ambient_capabilities": "",
            "capability_bounding_set": "",
            "command": worker_command,
            "credential": (
                'a(ss) 1 "worker-binding" "/etc/aragorn/runtime-action-worker.json"'
            ),
            "fragment_digest": (
                "sha256:e231978207dd27b71ef43449cf603ac424f6129f64c8a03dd0851ddf32503723"
            ),
            "group": "aragorn-runtime",
            "inaccessible": {
                "/etc/aragorn/runtime-action-observation.json",
                "/etc/aragorn/runtime-action-runtime.json",
                "/etc/aragorn/runtime-action-worker.json",
                "/etc/aragorn/runtime-capability-grant.json",
                "-/etc/aragorn/agent-gateway",
                "-/etc/aragorn/openclaw-profile",
                "-/profile/config",
                "-/profile/state",
                "-/profile/workspace",
                "-/var/lib/aragorn-agent-gateway",
                "-/var/lib/aragorn-gateway",
                "-/var/lib/aragorn-openclaw-profile",
                "/var/lib/aragorn-runtime-action/control",
                "/var/lib/aragorn-runtime-action/staging",
            },
            "private_network": "yes",
            "process_command": worker_command,
            "read_only": {
                "-/opt/aragorn/runtime-profile",
                "/var/lib/aragorn-protected/skills",
                "/var/lib/aragorn-runtime-action/protected",
            },
            "read_write": set(),
            "supplementary_groups": "aragorn-agent-gateway",
            "user": "aragorn-runtime",
        },
        _BROKER_UNIT: {
            "address_families": {"AF_UNIX"},
            "ambient_capabilities": "",
            "capability_bounding_set": "",
            "command": [
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                "/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py",
                "/run/credentials/aragorn-runtime-lineage-capability-action-broker.service/runtime-binding",
                "/run/credentials/aragorn-runtime-lineage-capability-action-broker.service/capability-grant",
            ],
            "credential": (
                'a(ss) 2 "capability-grant" '
                '"/etc/aragorn/runtime-capability-grant.json" "runtime-binding" '
                '"/etc/aragorn/runtime-action-runtime.json"'
            ),
            "fragment_digest": (
                "sha256:c43a81b394e0b96b0950af94b937a79e777d7e0c815a0104f1ab45871f4afa64"
            ),
            "group": "aragorn-runtime",
            "inaccessible": {
                "/etc/aragorn/runtime-action-runtime.json",
                "/etc/aragorn/runtime-capability-grant.json",
            },
            "private_network": "yes",
            "process_command": [
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                "/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py",
                "/run/credentials/aragorn-runtime-lineage-capability-action-broker.service/runtime-binding",
                "/run/credentials/aragorn-runtime-lineage-capability-action-broker.service/capability-grant",
            ],
            "read_only": {"/var/lib/aragorn-protected/skills"},
            "read_write": {"/var/lib/aragorn-runtime-action"},
            "supplementary_groups": "aragorn-sensor",
            "user": "aragorn-broker",
        },
        _SENSOR_UNIT: {
            "address_families": {"AF_UNIX"},
            "ambient_capabilities": "cap_setgid cap_setuid cap_setpcap",
            "capability_bounding_set": "cap_setgid cap_setuid cap_setpcap",
            "command": [
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                "/usr/libexec/aragorn/aragorn-runtime-observation-service-v4.py",
                "/run/credentials/aragorn-runtime-lineage-capability-observation-publisher.service/observation-binding",
                "/run/credentials/aragorn-runtime-lineage-capability-observation-publisher.service/capability-grant",
            ],
            "credential": (
                'a(ss) 2 "capability-grant" '
                '"/etc/aragorn/runtime-capability-grant.json" '
                '"observation-binding" '
                '"/etc/aragorn/runtime-action-observation.json"'
            ),
            "fragment_digest": (
                "sha256:d0f433abba94a4560c26cb99017f56543b432e2fc3aa74e3374ee4e04addeeaf"
            ),
            "group": "aragorn-sensor",
            "inaccessible": {
                "/etc/aragorn/runtime-action-observation.json",
                "/etc/aragorn/runtime-capability-grant.json",
                "/var/lib/aragorn-runtime-action/staging",
            },
            "private_network": "yes",
            "process_command": [
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                "/usr/libexec/aragorn/aragorn-runtime-observation-service-v4.py",
                "/run/credentials/aragorn-runtime-lineage-capability-observation-publisher.service/observation-binding",
                "/run/credentials/aragorn-runtime-lineage-capability-observation-publisher.service/capability-grant",
            ],
            "read_only": {
                "/var/lib/aragorn-protected/skills",
                "/var/lib/aragorn-runtime-action/control",
                "/var/lib/aragorn-runtime-action/protected",
            },
            "read_write": set(),
            "supplementary_groups": "aragorn-runtime",
            "user": "aragorn-sensor",
        },
    }
    _expect(set(units) == set(processes) == set(contracts), "unit inventory changed")
    for name, contract in contracts.items():
        unit = units[name]
        process = processes[name]
        command = contract["command"]
        loaded_exec, separator, metadata = unit["ExecStart"].partition(
            " ; ignore_errors="
        )
        metadata_match = re.fullmatch(
            r"no ; start_time=\[[^\]\n]+\] ; stop_time=\[n/a\] ; "
            r"pid=(?P<pid>\d+) ; code=\(null\) ; status=0/0 \}",
            metadata,
        )
        _expect(
            unit["FragmentPath"] == f"/lib/systemd/system/{name}"
            and unit["FragmentResolvedPath"] == f"/usr/lib/systemd/system/{name}"
            and unit["FragmentDigest"] == contract["fragment_digest"]
            and unit["DropInPaths"] == ""
            and bool(separator)
            and loaded_exec == f"{{ path={command[0]} ; argv[]={' '.join(command)}"
            and metadata_match is not None
            and int(metadata_match["pid"]) == process["pid"]
            and process["cmdline"] == contract["process_command"]
            and unit["LoadCredential"] == contract["credential"]
            and unit["User"] == contract["user"]
            and unit["Group"] == contract["group"]
            and unit["SupplementaryGroups"] == contract["supplementary_groups"]
            and unit["ActiveState"] == "active"
            and unit["SubState"] == "running"
            and unit["Result"] == "success"
            and unit["ExecMainStatus"] == "0"
            and unit["AmbientCapabilities"] == contract["ambient_capabilities"]
            and unit["CapabilityBoundingSet"] == contract["capability_bounding_set"]
            and unit["NoNewPrivileges"] == "yes"
            and unit["PrivateMounts"] == "yes"
            and unit["PrivateNetwork"] == contract["private_network"]
            and unit["ProtectSystem"] == "strict"
            and set(unit["RestrictAddressFamilies"].split())
            == contract["address_families"]
            and set(unit["ReadOnlyPaths"].split()) == contract["read_only"]
            and set(unit["ReadWritePaths"].split()) == contract["read_write"]
            and set(unit["InaccessiblePaths"].split()) == contract["inaccessible"],
            f"loaded unit contract changed: {name}",
        )


def _verify_boundaries(
    value: Mapping[str, Any],
    identities: Mapping[str, Any],
    installed_inventory: Mapping[str, Any],
    container_id: str,
    runtime_volume: str,
) -> None:
    _expect(
        set(value)
        == {
            "checks",
            "covered_read_only_paths",
            "forbidden_reads",
            "loaded_unit_checks",
            "mounts",
            "processes",
            "sockets",
            "units",
        }
        and set(value["checks"]) == _BOUNDARY_CHECKS
        and all(flag is True for flag in value["checks"].values())
        and set(value["loaded_unit_checks"])
        == {"aragorn-agent-gateway.service", "aragorn-runtime-action-worker.service"}
        and all(
            set(checks) == _LOADED_UNIT_CHECKS
            and all(flag is True for flag in checks.values())
            for checks in value["loaded_unit_checks"].values()
        ),
        "boundary result changed",
    )
    _expect(
        set(identities) == {"broker", "gateway", "sensor", "worker"}
        and len({entry["uid"] for entry in identities.values()}) == 4,
        "principal split changed",
    )
    processes = value["processes"]
    units = value["units"]
    _expect(set(processes) == set(units) and len(processes) == 4, "process set changed")
    installed_by_path = {item["path"]: item for item in installed_inventory["files"]}
    _expect(
        units["aragorn-agent-gateway.service"]["FragmentDigest"]
        == installed_by_path["/usr/lib/systemd/system/aragorn-agent-gateway.service"][
            "digest"
        ]
        and units["aragorn-runtime-action-worker.service"]["FragmentDigest"]
        == installed_by_path[
            "/usr/lib/systemd/system/aragorn-runtime-action-worker.service"
        ]["digest"],
        "loaded unit installed-closure binding changed",
    )
    _verify_unit_contracts(units, processes)
    expected_process_identity = {
        "aragorn-agent-gateway.service": {
            "gids": [992, 992, 992, 992],
            "groups": [992],
            "uids": [992, 992, 992, 992],
        },
        "aragorn-runtime-action-worker.service": {
            "gids": [997, 997, 997, 997],
            "groups": [992, 997],
            "uids": [997, 997, 997, 997],
        },
        "aragorn-runtime-lineage-capability-action-broker.service": {
            "gids": [997, 997, 997, 997],
            "groups": [996, 997],
            "uids": [995, 995, 995, 995],
        },
        "aragorn-runtime-lineage-capability-observation-publisher.service": {
            "gids": [996, 996, 996, 997],
            "groups": [996, 997],
            "uids": [996, 996, 996, 997],
        },
    }
    _expect(
        set(processes) == set(expected_process_identity),
        "process identity inventory changed",
    )
    for name, process in processes.items():
        expected_cgroup = f"/docker/{container_id}/system.slice/{name}"
        mount_namespace = re.fullmatch(
            r"mnt:\[([1-9][0-9]*)\]", process["mount_namespace"]
        )
        network_namespace = re.fullmatch(
            r"net:\[([1-9][0-9]*)\]", process["network_namespace"]
        )
        _expect(
            set(units[name]) == _UNIT_FIELDS
            and set(process) == _PROCESS_FIELDS
            and mount_namespace is not None
            and network_namespace is not None
            and isinstance(process["pid"], int)
            and not isinstance(process["pid"], bool)
            and process["pid"] > 0
            and re.fullmatch(r"[1-9][0-9]*", units[name]["MainPID"]) is not None
            and re.fullmatch(r"[1-9][0-9]*", process["start_time_ticks"]) is not None
            and int(units[name]["MainPID"]) == process["pid"]
            and units[name]["ControlGroup"] == expected_cgroup
            and process["capabilities_effective"] == "0000000000000000"
            and isinstance(process["no_new_privileges"], int)
            and not isinstance(process["no_new_privileges"], bool)
            and process["no_new_privileges"] == 1
            and {field: process[field] for field in ("gids", "groups", "uids")}
            == expected_process_identity[name]
            and units[name]["ActiveState"] == "active"
            and units[name]["NoNewPrivileges"] == "yes",
            f"process boundary changed: {name}",
        )
    service_principals = {
        "aragorn-agent-gateway.service": "gateway",
        "aragorn-runtime-action-worker.service": "worker",
        "aragorn-runtime-lineage-capability-action-broker.service": "broker",
        "aragorn-runtime-lineage-capability-observation-publisher.service": "sensor",
    }
    _expect(
        all(
            identities[principal]
            == {
                "gid": processes[service]["gids"][0],
                "uid": processes[service]["uids"][0],
            }
            for service, principal in service_principals.items()
        ),
        "service principal identity changed",
    )
    _expect(
        len({process["mount_namespace"] for process in processes.values()}) == 4
        and len({process["network_namespace"] for process in processes.values()}) == 4,
        "namespace split changed",
    )
    sockets = value["sockets"]
    _expect(
        set(sockets) == {"broker", "sensor", "worker", "worker_directory"}
        and all(set(socket) == _SOCKET_FIELDS for socket in sockets.values())
        and all(
            isinstance(socket[field], int)
            and not isinstance(socket[field], bool)
            and socket[field] >= 0
            for socket in sockets.values()
            for field in ("device", "gid", "size", "uid")
        )
        and all(
            isinstance(socket[field], int)
            and not isinstance(socket[field], bool)
            and socket[field] > 0
            for socket in sockets.values()
            for field in ("inode", "nlink")
        )
        and sockets["worker_directory"]["type"] == "directory"
        and sockets["worker_directory"]["uid"] == identities["worker"]["uid"]
        and sockets["worker_directory"]["gid"] == identities["gateway"]["gid"]
        and sockets["worker_directory"]["mode"] == "0711"
        and sockets["worker_directory"]["nlink"] == 2
        and sockets["worker_directory"]["size"] == 60
        and sockets["worker"]["type"] == "socket"
        and sockets["worker"]["mode"] == "0660"
        and sockets["worker"]["uid"] == identities["worker"]["uid"]
        and sockets["worker"]["gid"] == identities["gateway"]["gid"]
        and sockets["worker"]["nlink"] == 1
        and sockets["worker"]["size"] == 0
        and sockets["sensor"]["type"] == "socket"
        and sockets["sensor"]["uid"] == identities["sensor"]["uid"]
        and sockets["sensor"]["gid"] == identities["worker"]["gid"]
        and sockets["sensor"]["mode"] == "0660"
        and sockets["sensor"]["nlink"] == 1
        and sockets["sensor"]["size"] == 0
        and sockets["broker"]["type"] == "socket"
        and sockets["broker"]["uid"] == identities["broker"]["uid"]
        and sockets["broker"]["gid"] == identities["sensor"]["gid"]
        and sockets["broker"]["mode"] == "0660"
        and sockets["broker"]["nlink"] == 1
        and sockets["broker"]["size"] == 0,
        "socket ownership changed",
    )
    _expect(
        value["covered_read_only_paths"]
        == {
            "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker": "gateway_root",
            "/var/lib/aragorn-protected/skills": "worker_root",
            "/var/lib/aragorn-runtime-action/protected": "worker_root",
        },
        "read-only path coverage changed",
    )
    mounts = value["mounts"]
    expected_mount_points = {
        "gateway_root": "/",
        "gateway_runtime": "/runtime",
        "gateway_worker_socket": "/run/aragorn-runtime-action-worker",
        "worker_root": "/",
    }
    expected_mount_roots = {
        "gateway_root": "/",
        "gateway_runtime": f"/docker/volumes/{runtime_volume}/_data",
        "gateway_worker_socket": "/aragorn-runtime-action-worker",
        "worker_root": "/",
    }
    _expect(
        set(mounts) == set(expected_mount_points)
        and all(
            mounts[name]["mount_point"] == mount_point
            for name, mount_point in expected_mount_points.items()
        )
        and all(
            mounts[name]["root"] == root for name, root in expected_mount_roots.items()
        )
        and set(value["covered_read_only_paths"].values()).issubset(mounts),
        "mount inventory changed",
    )
    for mount in mounts.values():
        _expect(
            set(mount)
            == {
                "filesystem",
                "mount_options",
                "mount_point",
                "raw",
                "raw_digest",
                "root",
                "source",
                "super_options",
            },
            "mount record shape changed",
        )
        raw = mount["raw"].encode("utf-8")
        sections = mount["raw"].split(" - ")
        _expect(len(sections) == 2, "mountinfo separator changed")
        left, right = sections[0].split(), sections[1].split()
        _expect(
            len(left) >= 6
            and len(right) == 3
            and mount["raw_digest"] == _raw_digest(raw)
            and mount["root"] == left[3]
            and mount["mount_point"] == left[4]
            and mount["mount_options"] == sorted(left[5].split(","))
            and mount["filesystem"] == right[0]
            and mount["source"] == right[1]
            and mount["super_options"] == sorted(right[2].split(","))
            and "ro" in mount["mount_options"],
            "read-only mount changed",
        )
    expected_forbidden = {
        "gateway": {
            "/etc/aragorn/agent-gateway/environment",
            "/etc/aragorn/agent-gateway/openclaw.json",
            "/etc/aragorn/runtime-action-observation.json",
            "/etc/aragorn/runtime-action-runtime.json",
            "/etc/aragorn/runtime-action-worker.json",
            "/etc/aragorn/runtime-capability-grant.json",
            "/run/aragorn-runtime-observation/sensor.sock",
            "/var/lib/aragorn-protected/skills",
            "/var/lib/aragorn-runtime-action/control",
            "/var/lib/aragorn-runtime-action/protected",
        },
        "worker": {
            "/etc/aragorn/agent-gateway/environment",
            "/etc/aragorn/agent-gateway/openclaw.json",
            "/etc/aragorn/runtime-action-observation.json",
            "/etc/aragorn/runtime-action-runtime.json",
            "/etc/aragorn/runtime-action-worker.json",
            "/etc/aragorn/runtime-capability-grant.json",
            "/var/lib/aragorn-agent-gateway/state",
            "/var/lib/aragorn-runtime-action/control",
            "/var/lib/aragorn-runtime-action/staging",
        },
    }
    _expect(
        set(value["forbidden_reads"]) == set(expected_forbidden)
        and all(
            set(value["forbidden_reads"][principal]) == paths
            for principal, paths in expected_forbidden.items()
        ),
        "forbidden-read inventory changed",
    )
    forbidden = [
        result
        for principal in value["forbidden_reads"].values()
        for result in principal.values()
    ]
    _expect(
        len(forbidden) == 19
        and all(
            result == {"blocked": True, "errno": 13, "error": "EACCES"}
            for result in forbidden
        ),
        "forbidden-read boundary changed",
    )


def _verify_peer_chain(
    value: Mapping[str, Any],
    cases: Mapping[str, Any],
    boundaries: Mapping[str, Any],
    identities: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    coherent = cases["coherent"]["traces"]
    _expect(
        set(value) == {"expected", "observed", "one_send_no_retry"}
        and set(value["expected"])
        == {"gateway_to_worker", "sensor_to_broker", "worker_to_sensor"}
        and set(value["observed"]) == {"broker", "gateway", "sensor", "worker"}
        and value["observed"] == coherent
        and value["one_send_no_retry"] is True,
        "peer trace projection changed",
    )
    expected = value["expected"]
    worker_channels = coherent["worker"]["channels"]
    sensor_channels = coherent["sensor"]["channels"]
    broker_channels = coherent["broker"]["channels"]
    processes = boundaries["processes"]
    service_pid = {
        "gateway": processes["aragorn-agent-gateway.service"]["pid"],
        "worker": processes["aragorn-runtime-action-worker.service"]["pid"],
        "sensor": processes[
            "aragorn-runtime-lineage-capability-observation-publisher.service"
        ]["pid"],
        "broker": processes["aragorn-runtime-lineage-capability-action-broker.service"][
            "pid"
        ],
    }
    expected_peers = {
        "gateway_to_worker": {"pid": service_pid["gateway"], **identities["gateway"]},
        "worker_to_sensor": {"pid": service_pid["worker"], **identities["worker"]},
        "sensor_to_broker": {"pid": service_pid["sensor"], **identities["sensor"]},
    }
    route_connect_attempts = {
        name: _connect_attempt_paths(coherent[name])
        for name in ("gateway", "worker", "sensor", "broker")
    }
    units = boundaries["units"]
    worker_process = processes["aragorn-runtime-action-worker.service"]
    gateway_process = processes["aragorn-agent-gateway.service"]
    worker_profile = context["profiles"]["worker"]["document"]
    legacy_profile = context["profiles"]["legacy_openclaw"]["document"]
    attribution = cases["coherent"]["receipt"]["document"]["runtime_attribution"]
    _expect(
        expected == expected_peers
        and route_connect_attempts
        == {
            "broker": [],
            "gateway": ["/run/aragorn-runtime-action-worker/worker.sock"],
            "sensor": ["/var/lib/aragorn-runtime-action/control/broker.sock"],
            "worker": ["/run/aragorn-runtime-observation/sensor.sock"],
        }
        and all(
            coherent[name]["service_pid"] == service_pid[name] for name in service_pid
        )
        and coherent["gateway"]["channels"] == []
        and worker_channels[0]
        == {"kind": "accept", "path": None, "peer": expected["gateway_to_worker"]}
        and worker_channels[1]["kind"] == "connect"
        and worker_channels[1]["path"] == "/run/aragorn-runtime-observation/sensor.sock"
        and worker_channels[1]["peer"]
        == {"pid": service_pid["sensor"], **identities["sensor"]}
        and sensor_channels[0]
        == {"kind": "accept", "path": None, "peer": expected["worker_to_sensor"]}
        and sensor_channels[1]["kind"] == "connect"
        and sensor_channels[1]["path"]
        == "/var/lib/aragorn-runtime-action/control/broker.sock"
        and sensor_channels[1]["peer"]
        == {"pid": service_pid["broker"], **identities["broker"]}
        and broker_channels
        == [{"kind": "accept", "path": None, "peer": expected["sensor_to_broker"]}]
        and [item["path"] for item in coherent["gateway"]["successful_connects"]]
        == ["/run/aragorn-runtime-action-worker/worker.sock"]
        and [item["path"] for item in coherent["worker"]["successful_connects"]]
        == ["/run/aragorn-runtime-observation/sensor.sock"]
        and [item["path"] for item in coherent["sensor"]["successful_connects"]]
        == ["/var/lib/aragorn-runtime-action/control/broker.sock"]
        and coherent["broker"]["successful_connects"] == [],
        "gateway-worker-sensor-broker chain changed",
    )
    _expect(
        worker_profile["cgroup"]
        == units["aragorn-runtime-action-worker.service"]["ControlGroup"]
        == attribution["cgroup"]
        and legacy_profile["cgroup"]
        == units["aragorn-agent-gateway.service"]["ControlGroup"]
        and attribution["uid"] == identities["worker"]["uid"]
        and attribution["gid"] == identities["worker"]["gid"]
        and attribution["executable_digest"]
        == worker_profile["executable_digest"]
        == context["profiles"]["executables"]["worker_python"]["digest"]
        and attribution["skill_path"]
        == worker_profile["skill_path"]
        == context["producer"]["skill"]["path"]
        and attribution["start_time_ticks"] == int(worker_process["start_time_ticks"])
        and worker_process["mount_namespace"]
        == f"mnt:[{attribution['mount_namespace']['inode']}]"
        and worker_process["cmdline"]
        == [
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py",
            "/run/credentials/aragorn-runtime-action-worker.service/worker-binding",
        ]
        and gateway_process["pid"] == service_pid["gateway"],
        "worker runtime attribution changed",
    )


def _forbidden_driver_fields(value: Any, path: str = "$") -> list[str]:
    matches = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in _DRIVER_FORBIDDEN_FIELDS:
                matches.append(child_path)
            matches.extend(_forbidden_driver_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(_forbidden_driver_fields(child, f"{path}[{index}]"))
    return matches


def _digest_values(value: Any) -> set[str]:
    values = set()
    if isinstance(value, Mapping):
        for child in value.values():
            values.update(_digest_values(child))
    elif isinstance(value, list):
        for child in value:
            values.update(_digest_values(child))
    elif _digest(value):
        values.add(value)
    return values


def _verify_secrets(
    value: Mapping[str, Any], cases: Mapping[str, Any], context: Mapping[str, Any]
) -> None:
    _expect(
        value
        == {
            "driver_authority_pins_absent": True,
            "driver_authority_values_absent": True,
            "forbidden_driver_fields": {
                "coherent": [],
                "legacy-openclaw-profile": [],
                "stale-active-record": [],
                "worker-binding-mismatch": [],
                "worker-endpoint-unavailable": [],
            },
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
            "runtime_facing_authority_secret_absent": True,
        },
        "secret-retention ceiling changed",
    )
    drivers = [cases[name]["driver"] for name in sorted(_DRIVER_CASES)]
    forbidden_fields = {
        driver["input"]["scenario"]["id"]: _forbidden_driver_fields(driver)
        for driver in drivers
    }
    _expect(
        forbidden_fields == value["forbidden_driver_fields"]
        and not any(forbidden_fields.values()),
        "forbidden driver authority field retained",
    )
    coherent_after = cases["coherent"]["effects"]["after"]
    lease = coherent_after["grant_state"]["document"]["claim"]["lease"]
    forbidden_values = _digest_values(
        [
            context["action"],
            context["policy"],
            context["profiles"]["legacy_openclaw"]["document"],
            context["profiles"]["worker"]["document"],
            context["worker_binding"],
            context["worker_binding_mismatch"],
            context["legacy_grant"]["document"],
            context["grant"]["document"],
            context["control_sets"]["legacy"],
            context["control_sets"]["worker"],
        ]
    )
    forbidden_values.update(coherent_after["controls"].values())
    forbidden_values.update(
        {
            context["legacy_grant"]["document"]["grant_id"],
            context["legacy_grant"]["digest"],
            context["grant"]["document"]["grant_id"],
            context["grant"]["digest"],
            context["grant"]["document"]["schema"],
            context["grant"]["document"]["authority"],
            lease["lease_nonce"],
            lease["schema"],
            lease["authority"],
            canonical_digest(context["policy"]),
        }
    )
    driver_bytes = b"\n".join(canonical_json(driver) for driver in drivers).decode(
        "ascii"
    )
    gateway_config_bytes = canonical_json(context["gateway_config"]).decode("ascii")
    _expect(
        all(
            secret not in driver_bytes and secret not in gateway_config_bytes
            for secret in forbidden_values
        ),
        "authority value leaked into a runtime-facing record",
    )


def _contains_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, Mapping):
        return any(_contains_float(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_float(child) for child in value)
    return False


def _raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _expect(condition: Any, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(message)
