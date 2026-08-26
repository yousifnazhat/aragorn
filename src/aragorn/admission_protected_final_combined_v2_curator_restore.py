"""Qualify one exact current-V2 external-authority curator restore denial."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_config_activation as contract
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/update/curator-restore-activation"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_TARGET = "template-skill"
_TARGET_ROOT = "/opt/aragorn/runtime-profile/template-skill"
_TARGET_FILE = f"{_TARGET_ROOT}/SKILL.md"
_CONFIG_PATH = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-85296"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

_BASE = {
    "bytes": 58_642,
    "digest": "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6",
    "path": "src/aragorn/admission_protected_final_combined_v2_config_activation.py",
}
_EVIDENCE = {
    "bytes": 517_713,
    "canonical_bytes": 517_712,
    "canonical_digest": "sha256:6bfc774911177c611dbb9cdf3047750c40f2fa8c7498278c28c746394603511f",
    "digest": "sha256:4dd8819dbb5dd579480d6f514366b20f1e6f81bd78d608d975c7541f3323b942",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "curator-restore-activation-systemd-p3-final-catalog-fixed-2026-08-26.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 60_026,
    "canonical_digest": "sha256:86f116d27c57cb7c5f9db40183685a07e86e07ccf2fd5b96256e38966165c76a",
    "digest": "sha256:01abe80a999ee3fb8b44aa9f34ad42737e7205ec7e574fae5ae992560b062fe7",
}
_SOURCE = {
    "commit": "223d880f07c518f7748a3605989054809d91b7a7",
    "parent": "898acaba8c3f8c8186a2f68eaff40bbfd8459c10",
    "tree": "7ceb5cb8797e357b32d322568cd2fb076f500a93",
}
_RETENTION = {
    "commit": "a86acb5e3c86d00d1d167d471c0777e8ff20e0c7",
    "parent": _SOURCE["commit"],
    "tree": "162fc9e174df1845c57d8ad4d68efdd949e4df5c",
}
_RETENTION_BLOB = "da6457ae151c7942a861a9c1f7c0eeee9890425b"
_IMAGE = "sha256:0fc8a3da376990ce24c1f976dacf2e57f10d0832903b082319d1b43f9c5d80b0"
_PARENT_IMAGE = "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
_DIGESTS = {
    "action": "sha256:72cdd3cd0383ea9ccf2808d4b7c0df33bdd4b76c3eb68de7ad98d6704dd8bfca",
    "composition": "sha256:2367e06afd32185305c58ffb57ddabb0f6f48e393a27ccbc190f4145ee6dca08",
    "composition_action": "sha256:19dab345de62b8015c336b5a810349a58a14e62ba6e75fbe06444b1dd1a6c967",
    "execution": "sha256:4ea45f8b9d26fa210d056e9830808d7cb9a1ab11cfe49397fbf1f40bc158de76",
    "gateway_binding": "sha256:e7db91e62c674d22ef22ef19f2ebad61236e915a7eb12c1e1b686cc1e6bba205",
    "harness": "sha256:71345383f25d04fad23e339ee74a5c22a4b04e2557a1daee62e1e47140323d7a",
    "host_config": "sha256:48fe0dcc4e30f4e34e3468bdc3189d490be470063a899ad3006721937172a698",
    "source_artifacts": "sha256:f75691b78a2cd0a4e22b10c857a48735ca0b11bafbd81d38820d880b2b7cf87f",
    "stack": "sha256:15b50f2d5db3ff75924c06e5553e6402b6ca34c5f70ea83a9bae4a5abbebba16",
}
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 11_402,
        "digest": "sha256:a3d274c78b7a63d81253ead94755b5e2b5506b74b51c00c0fd962b64dfd46b88",
        "path": "/src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
    },
    "materializer": {
        "bytes": 74_621,
        "digest": "sha256:7e075a5ace4bcdae87a00bbac2331fcc8a1729ce0516e42b66409dcd6b6563ba",
        "path": "/src/scripts/materialize_fixed_admission_probes.py",
    },
    "v1_route_injector": {
        "bytes": 20_729,
        "digest": "sha256:18f6fe8c98c64aaf59c6c35d4785780da2a4dc3ac2a719ac72941dd3ab1a1664",
        "path": "/src/scripts/runtime_action_worker_final_route_systemd_probe.py",
    },
}
_PROBES = [
    {
        "bytes": 26_571,
        "digest": "sha256:c43bbcc718df29114e9edcee8f8d6e8d3ad96f5c4dfc7e5b29b4743f3128f60d",
        "name": "protected-curator-restore-denial-probe.mjs",
    },
    {
        "bytes": 16_324,
        "digest": "sha256:91febf12bd6aa2e98f63b14001a74213c653c2eb9c8c7db57a55b3520fdd4f22",
        "name": "protected-observation-v1.mjs",
    },
]
_MODULES = {
    "cli": (52_200, "sha256:d88d92cfd6829a4d5204709f3ded852d8d1b0c71c94714a8e42dce8302aa7b79", "skills-cli-CNPwjJpH.js"),
    "config": (1_496, "sha256:a348e485490fbdc69d94e9254db39628147a07166e20228ff763d89838346f5f", "config-DhjFoEdz.js"),
    "curator": (45_462, "sha256:ef522ff1ee42cd11569e0dbe53d1be12bbca6ddb5024cf70f8896929d6d30bb3", "curator-rOIsv8kR.js"),
    "gateway": (46_858, "sha256:196ac4211309e82af77db50230eb3d83eb5d7a9a100bdbc50ab70018ee21868a", "skills-wlxjcAuQ.js"),
    "schema": (61_198, "sha256:42b8547c53a366ee333527117dcc12400398ec6267c84d351cbfee813ea3d95e", "zod-schema-HPCU20Az.js"),
}
_AUTHORITY_ERROR = "Skill curator restore is delegated to an external authority"
_ARCHIVED_ROW = {
    "archived_reason": "aragorn exact protected restore-authority fixture",
    "created_at_ms": 1,
    "pinned": 0,
    "skill_file": _TARGET_FILE,
    "skill_key": _TARGET,
    "skill_name": _TARGET,
    "state": "archived",
    "state_changed_at_ms": 2,
}
_STATUS_SKILL = {
    "archivedReason": _ARCHIVED_ROW["archived_reason"],
    "createdAtMs": 1,
    "lastUsedAtMs": None,
    "pinned": False,
    "skillFile": _TARGET_FILE,
    "skillKey": _TARGET,
    "skillName": _TARGET,
    "state": "archived",
    "stateChangedAtMs": 2,
    "useCount": 0,
}
_BOOLEAN_FIELDS = contract._BOOLEAN_FIELDS
_EMPTY_STATUS = {
    "counts": {"active": 0, "archived": 0, "stale": 0},
    "lastAttemptAtMs": None,
    "lastError": None,
    "lastSuccessAtMs": None,
    "overlaps": [],
    "skills": [],
}
_ARCHIVED_STATUS = {
    **_EMPTY_STATUS,
    "counts": {"active": 0, "archived": 1, "stale": 0},
    "skills": [_STATUS_SKILL],
}


def verify_openclaw_final_combined_v2_curator_restore(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact dynamic V2 curator restore denial PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract.base.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 curator restore"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V2 curator restore CAS differs from signed retention"
            )
        evidence = contract.base.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 curator restore"
        )
        profile = _verify_evidence(evidence)
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
        raise AdmissionEvidenceError(f"invalid V2 curator restore evidence: {exc}") from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED",
        }
        for route in profile["routes"]
    ]
    return {
        "schema": "aragorn/admission-protected-final-combined-v2-curator-restore-route-coverage/v1",
        "assurance": "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_CURRENT_V2_CURATOR_RESTORE_DENIAL_ROUTE_ONLY",
        "bindings": {
            "configuration": dict(contract._SOURCES["configuration"]),
            "curator_restore_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": contract.base.legacy.parent._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(contract.base.legacy.parent._SIGNATURE),
                },
            },
            "image": _IMAGE,
            "profile": dict(contract._SOURCES["profile"]),
            "runtime": dict(contract.base.legacy.parent._RUNTIME),
            "runtime_lock": dict(contract._SOURCES["runtime_lock"]),
            "skill": dict(contract._SOURCES["skill"]),
            "source_artifacts": {
                **{name: dict(value) for name, value in _SOURCE_ARTIFACTS.items()},
                "probe_bundle": [dict(value) for value in _PROBES],
            },
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in contract.base.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_CURATOR_RESTORE_ACTIVATION_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
            "EXACT_SELECTED_LIFECYCLE_ROW_ONLY_NOT_FULL_DATABASE_STATE",
            "SKILLS_STATUS_ARCHIVED_DIAGNOSTIC_NOT_ACTIVE_CONSUMER_PROOF",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
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
                "SIGNED_EXACT_CURRENT_V2_GATEWAY_AND_CLI_RESTORE_DENIAL_"
                "WITH_SYNTHETIC_ARCHIVED_ROW_PRESERVED"
            ),
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_dependencies() -> None:
    path = Path(contract.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.as_posix().endswith(_BASE["path"]) is False
        or path.stat().st_size != _BASE["bytes"]
        or _digest(path.read_bytes()) != _BASE["digest"]
    ):
        raise AdmissionEvidenceError("V2 curator restore verifier base changed")
    contract._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    if (
        Path(
            contract.base.legacy._git(["rev-parse", "--show-toplevel"])
            .decode()
            .strip()
        ).resolve(strict=True)
        != root
        or contract.base.legacy._git(["rev-parse", "--show-object-format"]).strip()
        != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 curator restore repository changed")
    contract.base._verify_commit(_SOURCE)
    contract.base._verify_commit(_RETENTION)
    entry = contract.base.legacy._git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V2 curator restore signed tree entry changed")
    raw = contract.base.legacy._git(
        ["cat-file", "blob", _RETENTION_BLOB], maximum=1024 * 1024
    )
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 curator restore signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    _verify_scalar_types(evidence)
    contract._verify_no_positive_eligibility(evidence)
    if (
        set(evidence)
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
        or evidence["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-route-systemd-observation/v1"
        or evidence["route_id"] != _ROUTE
        or evidence["recorded_at"] != "2026-08-26T13:11:40.737179Z"
        or evidence["authority"]
        != "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or evidence["decision"]
        != {
            "status": "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED",
            "route_observation_status": "OBSERVED",
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in contract.base.legacy.parent._ELIGIBILITY_KEYS},
        }
        or evidence["limitations"]
        != [
            "OBSERVED_IS_NOT_PASS",
            "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ]
        or canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
    ):
        raise AdmissionEvidenceError("V2 curator restore wrapper changed")

    profile = _verify_composition(
        evidence["composition"], evidence["source_artifacts"]
    )
    observation = evidence["route_observation"]
    document = _decode_route_raw(observation["raw"])
    if (
        set(observation)
        != {
            "bundle",
            "document",
            "execution",
            "gateway_pid_binding",
            "raw",
            "route",
            "stack_before",
        }
        or document != observation["document"]
        or observation["route"] != document["route"]
        or observation["bundle"] != _PROBES
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V2 curator restore nested custody changed")
    harness = evidence["composition"]["action"]["harness"]["document"]
    _verify_execution(
        observation,
        evidence["composition"]["action"]["boundaries"],
        harness,
    )
    _verify_action(
        document,
        config=evidence["composition"]["action"]["inputs"]["gateway_config"],
        container_id=harness["container_id"],
        execution=observation["execution"],
        outer_recorded_at=evidence["recorded_at"],
    )
    if not (
        contract.base.legacy._parse_time(document["recorded_at"])
        <= contract.base.legacy._parse_time(observation["execution"]["completed_at"])
        <= contract.base.legacy._parse_time(evidence["composition"]["recorded_at"])
        <= contract.base.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V2 curator restore execution custody changed")
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    action = composition["action"]
    source = action["artifacts"]["final_combined_v2"]
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    if (
        set(composition)
        != {
            "action",
            "authority",
            "bindings",
            "decision",
            "limitations",
            "profile",
            "recorded_at",
            "schema",
        }
        or composition["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-observation/v1"
        or composition["recorded_at"] != "2026-08-26T13:11:40.736853Z"
        or composition["authority"]
        != (
            "BOUNDED_FINAL_COMBINED_V2_P3_7C_ACTION_OBSERVATION_ONLY_PROFILE_"
            "ROUTES_REMAIN_NOT_TESTED_NOT_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or canonical_digest(action) != _DIGESTS["composition_action"]
        or profile_before != profile_after
        or profile_before != source["profile"]
        or action["inputs"]["gateway_config"] != source["config"]["document"]
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(contract.base.legacy.parent._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": contract._RUNTIME_TREE["tree_digest"],
            "runtime_volume": _RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": contract._SOURCES["skill"]["digest"],
        }
        or profile["runtime"]
        != {
            **contract.base.legacy.parent._OPENCLAW,
            "name": "openclaw-protected-final-combined-v2",
        }
        or composition["decision"]
        != {
            "admission_profile_eligible": False,
            "aggregate_admission_eligible": False,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "p3_7c_activation_action_observed": True,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            "route_pass_count": 0,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "run_eligible": False,
            "status": "FINAL_COMBINED_V2_ACTION_OBSERVED_PROFILE_NOT_TESTED",
        }
        or composition["limitations"]
        != [
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "ONE_PINNED_P3_7C_ACTIVATION_ACTION_FLOW_ONLY",
            "TWENTY_ONE_ADMISSION_ROUTES_REMAIN_NOT_TESTED",
            "ACTION_OBSERVATION_DOES_NOT_PROMOTE_ANY_ADMISSION_ROUTE",
            "FRESH_RUNTIME_PROFILE_AND_FRESH_SESSIONS_REQUIRED",
            "OPENCLAW_TEST_FAST_ABSENT",
            "PUBLIC_NETWORK_DENIED",
            "EXACT_SINGLETON_EXTERNAL_SKILL_SOURCE_ONLY",
            (
                "EXACT_PINNED_ARAGORN_TOOL_PLUGIN_READ_TOOL_WORKSPACE_AND_"
                "RESOLVED_SKILL_ROOTS_AND_LOOPBACK_PROVIDER_ONLY"
            ),
            "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        ]
        or set(action)
        != {
            "artifacts",
            "authority",
            "boundaries",
            "cases",
            "decision",
            "harness",
            "identities",
            "inputs",
            "limitations",
            "parent",
            "profiles",
            "recorded_at",
            "runtime",
            "schema",
            "secret_checks",
        }
        or action["schema"]
        != "aragorn/runtime-action-worker-activation-expiry-systemd-observation/v1"
        or action["recorded_at"] != "2026-08-26T13:11:40.268682Z"
        or action["authority"]
        != (
            "BOUNDED_ACTIVATION_EXPIRY_ROTATION_OBSERVATION_ONLY_NOT_VERIFIED_"
            "RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or action["decision"]
        != {
            "aggregate_gate_eligible": False,
            "available_to_expired_observed": True,
            "coherent_allow_created_consumed_observed": True,
            "edr_claim_eligible": False,
            "expired_activation_fail_stop_observed": True,
            "full_activation_no_boot_authority_observed": True,
            "installer_authority_eligible": False,
            "parent_p3_7b_unchanged": True,
            "phase3_exit_eligible": False,
            "public_release_eligible": False,
            "retained_evidence_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "status": "P3_7C_ACTIVATION_EXPIRY_OBSERVED",
            "terminal_archive_rotation_observed": True,
            "verifier_status": "NOT_TESTED",
        }
        or action["limitations"]
        != [
            "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "EXACT_OPENCLAW_2026_7_1_RUNTIME_VOLUME_AND_EVALUATOR_PROVIDER_ONLY",
            "ONE_AVAILABLE_TO_EXPIRED_TRANSITION_ONLY",
            "ONE_OPERATOR_UNMASK_AND_TERMINAL_ARCHIVE_ROTATION_ONLY",
            "ONE_FRESH_GRANT_AND_ONE_CREATE_ACTION_ONLY",
            "EXPIRY_USES_LOCAL_WALL_CLOCK_WITHOUT_EXTERNAL_TIME_ATTESTATION",
            "NO_CLOCK_STEP_SLEW_ROLLBACK_OR_EXPIRY_LATENCY_QUALIFICATION",
            "NO_REBOOT_SYSTEMD_REEXEC_BOOT_ACTIVATION_OR_CREDENTIAL_REPROJECTION",
            "NO_SIGKILL_POWER_LOSS_OR_FILESYSTEM_DURABILITY_FAULT_INJECTION",
            "NO_AUTOMATIC_CONTINUOUS_REPEATED_OR_OVERLAPPING_GRANT_RENEWAL",
            "NO_CONCURRENT_ACTIVATION_LOCK_CONTENTION_OR_PARTIAL_SYSTEMCTL_FAILURE",
            "NO_CLAIMED_CONNECTION_ACROSS_EXPIRY_QUALIFICATION",
            "NO_NATIVE_HOST_VM_HOSTILE_ROOT_OR_SAME_UID_DIRECTORY_ATTESTATION",
            "SOURCE_COMMIT_SIGNATURE_TRUSTS_LOCAL_GIT_CONFIGURATION_AND_KEYRING",
            "CONTAINER_BUILD_AND_CAPTURE_TOOLCHAIN_NOT_INDEPENDENTLY_ATTESTED",
            "PYTHON_NODE_SYSTEMD_KERNEL_AND_NATIVE_DEPENDENCY_CLOSURE_NOT_FULLY_PINNED",
            "PROVIDER_AND_OPENCLAW_SESSION_RAW_BYTES_NOT_RETAINED",
            "P3_7B_PARENT_REMAINS_SEPARATE_IMMUTABLE_QUALIFICATION",
            "SYSCALL_CAUSATION_IS_PINNED_IMPLEMENTATION_BOUND_NOT_INDEPENDENT_ATTESTATION",
            "TRACE_PROVES_ONE_ROUTE_CONNECT_WITHOUT_RETRY_NOT_APPLICATION_SEND_COUNT",
            "VERIFIER_NOT_IMPLEMENTED",
            "RETAINED_EVIDENCE_NOT_PRODUCED",
            "RUN_01_NOT_ESTABLISHED",
            "RUN_02_NOT_ESTABLISHED",
            "PHASE_3_EXIT_NOT_ESTABLISHED",
            "EDR_CLAIM_NOT_ESTABLISHED",
            "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
            "PUBLIC_RELEASE_NOT_AUTHORIZED",
        ]
    ):
        raise AdmissionEvidenceError("V2 curator restore composition changed")
    contract._verify_configuration(source)
    _verify_source_artifacts(source_artifacts)
    _verify_harness(action["harness"], action["identities"], action["secret_checks"])
    if action["runtime"] != {
        "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "entrypoint_digest": contract.base.legacy.parent._RUNTIME["entrypoint_digest"],
        "expected_version": contract.base.legacy.parent._RUNTIME["version_output"],
        "root": "/runtime",
        "tree": contract._RUNTIME_TREE,
        "version_output": contract.base.legacy.parent._RUNTIME["version_output"],
    }:
        raise AdmissionEvidenceError("V2 curator restore runtime binding changed")
    return profile


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V2 curator restore source bundle changed")
    for name, identity in _SOURCE_ARTIFACTS.items():
        contract._verify_bound_file(
            value[name], identity, path=identity["path"], mode="0555"
        )
    if value["probe_bundle"] != _PROBES:
        raise AdmissionEvidenceError("V2 curator restore probe bundle changed")


def _verify_harness(
    envelope: Mapping[str, Any],
    identities: Mapping[str, Any],
    secret_checks: Mapping[str, Any],
) -> None:
    document = envelope["document"]
    raw_file = envelope["file"]
    raw = base64.b64decode(raw_file["base64"], validate=True)
    parsed = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=contract.base.legacy.parent._reject_duplicates,
        parse_constant=contract.base.legacy.parent._reject_constant,
    )
    lineage = document["image_lineage"]
    if (
        set(envelope) != {"digest", "document", "file"}
        or set(document)
        != {
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
        or set(raw_file) != {"base64", "bytes", "digest", "path", "stat"}
        or parsed != document
        or raw != canonical_json(document)
        or envelope["digest"] != _DIGESTS["harness"]
        or _digest(raw) != _DIGESTS["harness"]
        or raw_file["digest"] != _DIGESTS["harness"]
        or raw_file["bytes"] != len(raw)
        or raw_file["path"] != "/run/aragorn-harness.json"
        or document["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["image_reference"]
        != "aragorn-phase3-final-combined-v2-systemd"
        or document["platform"] != "linux"
        or document["profile_label"] != "phase3-final-combined-v2"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or not lineage["added_layers"]
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or lineage["child"]["rootfs_type"] != "layers"
        or lineage["parent"]["rootfs_type"] != "layers"
        or canonical_digest(document["host_config"]) != _DIGESTS["host_config"]
        or document["host_config"]
        != {
            "binds": [
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                f"{_RUNTIME_VOLUME}:/runtime:ro",
                f"{_ROUTE_VOLUME}:/route-input:ro",
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
        or document["openclaw_runtime_volume"] != _RUNTIME_VOLUME
        or document["openclaw_runtime_mount"]
        != {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": _RUNTIME_VOLUME,
            "type": "volume",
        }
        or document["route_input_mount"]
        != {
            "destination": "/route-input",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": _ROUTE_VOLUME,
            "type": "volume",
        }
        or document["route_input_volume_identity"]
        != {
            "driver": "local",
            "labels": {
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:85296",
                "dev.aragorn.role": "final-combined-v2-route-input",
                "dev.aragorn.source-commit": _SOURCE["commit"],
            },
            "name": _ROUTE_VOLUME,
            "options": None,
            "scope": "local",
        }
        or document["openclaw_runtime_volume_identity"]
        != {
            "driver": "local",
            "labels": {
                "io.aragorn.phase": "phase3-final",
                "io.aragorn.role": "installed-runtime",
                "io.aragorn.source-commit": contract.base.legacy.parent._OPENCLAW[
                    "commit"
                ],
                "io.aragorn.source-tree": contract.base.legacy.parent._OPENCLAW[
                    "source_tree"
                ],
            },
            "name": _RUNTIME_VOLUME,
            "options": None,
            "scope": "local",
        }
        or document["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or document["source_commit_verification"]["exit_code"] != 0
        or identities
        != {
            "broker": {"gid": 997, "uid": 995},
            "gateway": {"gid": 992, "uid": 992},
            "sensor": {"gid": 996, "uid": 996},
            "worker": {"gid": 997, "uid": 997},
        }
        or secret_checks
        != {
            "forbidden_driver_fields": [],
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
            "provider_and_gateway_token_values_retained": False,
        }
    ):
        raise AdmissionEvidenceError("V2 curator restore harness changed")
    stat = raw_file["stat"]
    if (
        set(stat)
        != {
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
        or any(
            type(stat[name]) is not int
            for name in ("ctime_ns", "device", "inode", "mtime_ns", "size")
        )
        or stat["ctime_ns"] <= 0
        or stat["mtime_ns"] != stat["ctime_ns"]
        or stat["gid"] != 0
        or stat["uid"] != 0
        or stat["mode"] != "0600"
        or stat["nlink"] != 1
        or stat["size"] != len(raw)
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError("V2 curator restore harness file changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=contract.base.legacy.parent._reject_duplicates,
        parse_constant=contract.base.legacy.parent._reject_constant,
    )
    canonical = canonical_json(document)
    if (
        set(value)
        != {"base64", "bytes", "canonical_digest", "digest", "raw_is_canonical_json_lf"}
        or not isinstance(document, dict)
        or raw != canonical + b"\n"
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not True
    ):
        raise AdmissionEvidenceError("V2 curator restore raw identity changed")
    _verify_scalar_types(document)
    return document


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError(
                "V2 curator restore unexpected floating-point value"
            )
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if (
                key == "message_prefix_continuity_valid"
                and item is not None
                and type(item) is not bool
            ):
                raise AdmissionEvidenceError(
                    "V2 curator restore nullable boolean field type changed"
                )
            if key == "pinned" and type(item) not in (bool, int):
                raise AdmissionEvidenceError(
                    "V2 curator restore mixed boolean field type changed"
                )
            if (
                isinstance(key, str)
                and key not in {"message_prefix_continuity_valid", "pinned"}
                and ((key in _BOOLEAN_FIELDS) != (type(item) is bool))
            ):
                raise AdmissionEvidenceError(
                    "V2 curator restore boolean field type changed"
                )
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError(
                    "V2 curator restore boolean list item changed"
                )
            _verify_scalar_types(item, float_allowed=float_allowed)


def _verify_execution(
    observation: Mapping[str, Any],
    boundaries: Mapping[str, Any],
    harness: Mapping[str, Any],
) -> None:
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    document = observation["document"]
    stack = observation["stack_before"]
    container_id = harness["container_id"]
    pid = binding["pid"]
    gateway_unit = "aragorn-agent-gateway.service"
    units = {
        gateway_unit,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    process = stack["processes"][gateway_unit]
    nested = document["action"]["prerequisites"]["gateway_process_before"]
    commands = document["action"]["commands"]
    if (
        set(execution)
        != {
            "argv",
            "completed_at",
            "effective_identity",
            "environment_names",
            "exit_code",
            "started_at",
            "stderr",
        }
        or canonical_digest(execution) != _DIGESTS["execution"]
        or canonical_digest(binding) != _DIGESTS["gateway_binding"]
        or canonical_digest(stack) != _DIGESTS["stack"]
        or not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or type(pid) is not int
        or pid <= 0
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
            "unit": gateway_unit,
        }
        or pid != 2740
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
            "/route-input/curator-restore-activation/protected-curator-restore-denial-probe.mjs",
        ]
        or execution["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or execution["environment_names"]
        != [
            "ARAGORN_GATEWAY_PID",
            "ARAGORN_MOCK_PROVIDER_TOKEN",
            "HOME",
            "LANG",
            "LC_ALL",
            "NO_COLOR",
            "NO_PROXY",
            "OPENCLAW_CONFIG_PATH",
            "OPENCLAW_GATEWAY_TOKEN",
            "OPENCLAW_STATE_DIR",
            "PATH",
            "TZ",
        ]
        or type(execution["exit_code"]) is not int
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _EMPTY_DIGEST, "excerpt": ""}
        or set(stack["units"]) != units
        or set(stack["pids"]) != units
        or set(stack["processes"]) != units
        or stack["pids"][gateway_unit] != pid
        or stack["gateway_listener"]["pid"] != pid
        or process["pid"] != pid
        or process["cmdline"] != ["openclaw-gateway"]
        or process["uids"] != [992, 992, 992, 992]
        or process["gids"] != [992, 992, 992, 992]
        or process["groups"] != [992]
        or process["capabilities_effective"] != "0000000000000000"
        or process["no_new_privileges"] != 1
        or nested["pid"] != process["pid"]
        or nested["cmdline"] != process["cmdline"]
        or nested["start_time_ticks"] != process["start_time_ticks"]
        or nested["effective_capabilities"] != process["capabilities_effective"]
        or nested["no_new_privileges"] != str(process["no_new_privileges"])
        or any(
            boundaries[name] != stack[name]
            for name in (
                "enablement",
                "gateway_listener",
                "processes",
                "service_state",
                "sockets",
                "units",
            )
        )
        or any(
            stack["units"][name]["ControlGroup"]
            != f"/docker/{container_id}/system.slice/{name}"
            for name in units
        )
        or not (
            contract.base.legacy._parse_time(execution["started_at"])
            <= contract.base.legacy._parse_time(commands[0]["started_at"])
            <= contract.base.legacy._parse_time(commands[-1]["completed_at"])
            <= contract.base.legacy._parse_time(document["recorded_at"])
            <= contract.base.legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V2 curator restore execution boundary changed")
    contract.base.legacy._verify_stack_boundary(
        stack,
        trusted=boundaries,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    contract.base.legacy._verify_gateway_listener(
        stack["gateway_listener"], stack["processes"]
    )


def _verify_action(
    document: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    container_id: str,
    execution: Mapping[str, Any],
    outer_recorded_at: str,
) -> None:
    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        set(document)
        != {
            "action",
            "assurance",
            "implementation_digests",
            "limitations",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-curator-restore-denial-observation/v1"
        or set(action)
        != {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        or set(before)
        != {
            "boundary_before",
            "config_lock_before",
            "config_tree_before",
            "curator_status_before_seed",
            "gateway_process_before",
            "modules_before",
            "openclaw_before",
            "protected_root_trees_before",
            "runtime_tree_before",
            "system_info_before",
            "target_before",
            "version",
        }
        or set(after)
        != {
            "boundary_after",
            "cli_fallback_restore",
            "config_lock_after",
            "config_tree_after",
            "curator_status_after",
            "curator_status_before",
            "database_after_cli",
            "database_after_gateway",
            "database_before",
            "discovery_after",
            "discovery_before",
            "gateway_process_after",
            "gateway_restore",
            "invalid_token_gateway_control",
            "modules_after",
            "openclaw_after",
            "protected_root_trees_after",
            "runtime_tree_after",
            "system_info_after",
            "target_after",
        }
        or document["assurance"] != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["recorded_at"] != "2026-08-26T13:11:40.248Z"
        or document["limitations"]
        != [
            "OBSERVED_IS_NOT_PASS",
            "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
            (
                "SHARED_DATABASE_DATA_VERSION_NOT_STABLE_ONLY_EXACT_SELECTED_"
                "LIFECYCLE_ROW_BOUND"
            ),
            "SINGLE_ROUTE_SINGLE_CAPTURE",
            "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "NO_AGGREGATE_ADMISSION_INSTALLER_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ]
        or document["route"]
        != {"action_id": "curator-restore-authority-denial", "id": _ROUTE, "reason_codes": [], "status": "OBSERVED"}
        or action["id"] != "curator-restore-authority-denial"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or canonical_digest(action) != _DIGESTS["action"]
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["implementation_digests"]
        != {"helper": _PROBES[1]["digest"], "probe": _PROBES[0]["digest"]}
        or document["runtime_binding"]
        != {
            "commit": contract.base.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": contract.base.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": contract._RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
    ):
        raise AdmissionEvidenceError("V2 curator restore action identity changed")

    _verify_stable_state(before, after, config, container_id)
    _verify_semantics(action)
    commands = action["commands"]
    if (
        len(commands) != 11
        or len({command["pid"] for command in commands}) != 11
        or any(
            set(command)
            != {
                "argv",
                "completed_at",
                "error",
                "exit_code",
                "pid",
                "signal",
                "started_at",
                "stderr_bytes",
                "stderr_digest",
                "stderr_excerpt",
                "stdout_bytes",
                "stdout_digest",
                "stdout_excerpt",
            }
            or type(command["pid"]) is not int
            or command["pid"] <= 0
            or command["error"] is not None
            or command["signal"] is not None
            or not contract._command_output_is_exact(command)
            for command in commands
        )
        or any(
            contract.base.legacy._parse_time(left["completed_at"])
            > contract.base.legacy._parse_time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or not (
            contract.base.legacy._parse_time(execution["started_at"])
            <= contract.base.legacy._parse_time(commands[0]["started_at"])
            <= contract.base.legacy._parse_time(commands[-1]["completed_at"])
            <= contract.base.legacy._parse_time(document["recorded_at"])
            <= contract.base.legacy._parse_time(execution["completed_at"])
            <= contract.base.legacy._parse_time(outer_recorded_at)
        )
    ):
        raise AdmissionEvidenceError("V2 curator restore command causality changed")


def _verify_stable_state(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    config: Mapping[str, Any],
    container_id: str,
) -> None:
    if (
        after["boundary_after"] != before["boundary_before"]
        or after["config_lock_after"] != before["config_lock_before"]
        or after["config_tree_after"] != before["config_tree_before"]
        or after["gateway_process_after"] != before["gateway_process_before"]
        or after["modules_after"] != before["modules_before"]
        or after["openclaw_after"] != before["openclaw_before"]
        or after["protected_root_trees_after"] != before["protected_root_trees_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["target_after"] != before["target_before"]
    ):
        raise AdmissionEvidenceError("V2 curator restore protected state changed")
    boundary = before["boundary_before"]
    _verify_boundary(boundary, config)
    contract._verify_target(before["target_before"])
    if (
        before["target_before"]["root"]["exists"] is not True
        or before["target_before"]["entries"][0]["exists"] is not True
    ):
        raise AdmissionEvidenceError("V2 curator restore target existence changed")
    contract._verify_gateway(before["gateway_process_before"], container_id)
    contract._verify_openclaw(before["openclaw_before"])
    contract._verify_version(before["version"])
    contract._verify_system(before["system_info_before"], before["gateway_process_before"])
    contract._verify_system(after["system_info_after"], after["gateway_process_after"])
    contract._verify_system_stability(before["system_info_before"], after["system_info_after"])
    if (
        before["gateway_process_before"]["pid"] != 2740
        or before["gateway_process_before"]["start_time_ticks"] != "35947569"
        or before["runtime_tree_before"] != contract._RUNTIME_TREE
        or before["config_lock_before"]
        != {"exists": False, "path": f"{_CONFIG_PATH}.lock"}
    ):
        raise AdmissionEvidenceError("V2 curator restore exact boundary changed")
    _verify_modules(before["modules_before"])


def _verify_boundary(
    boundary: Mapping[str, Any], config: Mapping[str, Any]
) -> None:
    root_paths = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"]
        != {"gid": 992, "groups": [992], "uid": 992}
        or set(boundary["roots"]) != set(root_paths)
    ):
        raise AdmissionEvidenceError("V2 curator restore boundary changed")
    contract._verify_config(boundary["configuration"])
    if boundary["configuration"]["document"] != config:
        raise AdmissionEvidenceError("V2 curator restore configuration changed")
    contract._verify_read_only_mount(
        boundary["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{_RUNTIME_VOLUME}/_data",
    )
    contract._verify_read_only_mount(
        boundary["probe"],
        path="/route-input",
        source=f"/docker/volumes/{_ROUTE_VOLUME}/_data",
    )
    for name, path in root_paths.items():
        value = boundary["roots"][name]
        entry = value["observation"]
        if (
            value["ready"] is not True
            or value["writable"] is not True
            or entry["path"] != path
            or entry["exists"] is not True
            or entry["type"] != "directory"
            or entry["uid"] != 992
            or entry["gid"] != 992
            or entry["mode"] != "700"
            or entry["entries"] != []
            or entry["entry_count"] != 0
            or entry["entries_truncated"] is not False
        ):
            raise AdmissionEvidenceError(
                "V2 curator restore conventional root changed"
            )


def _verify_modules(value: Mapping[str, Any]) -> None:
    if set(value) != set(_MODULES):
        raise AdmissionEvidenceError("V2 curator restore module inventory changed")
    for name, (size, digest, filename) in _MODULES.items():
        item = value[name]
        expected = {
            "bytes": size,
            "digest": digest,
            "path": f"/runtime/lib/node_modules/openclaw/dist/{filename}",
        }
        observed = item["observed"]
        if (
            item["expected"] != expected
            or observed["path"] != expected["path"]
            or observed["exists"] is not True
            or observed["size"] != size
            or observed["digest"] != digest
            or observed["type"] != "file"
            or observed["uid"] != 0
            or observed["gid"] != 0
            or observed["mode"] != "644"
            or observed["nlink"] != 1
            or observed["digest_error"] is not None
        ):
            raise AdmissionEvidenceError("V2 curator restore compiled module changed")


def _verify_semantics(action: Mapping[str, Any]) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    _verify_curator_status(before["curator_status_before_seed"], _EMPTY_STATUS)
    _verify_curator_status(after["curator_status_before"], _ARCHIVED_STATUS)
    _verify_curator_status(after["curator_status_after"], _ARCHIVED_STATUS)
    _verify_discovery(after["discovery_before"])
    _verify_discovery(after["discovery_after"])
    _verify_denials(after)
    _verify_lifecycle(after)
    expected_commands = [
        before["version"],
        before["system_info_before"]["command"],
        before["curator_status_before_seed"]["command"],
        after["curator_status_before"]["command"],
        after["discovery_before"]["command"],
        after["gateway_restore"]["command"],
        after["invalid_token_gateway_control"]["command"],
        after["cli_fallback_restore"]["command"],
        after["curator_status_after"]["command"],
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    if action["commands"] != expected_commands:
        raise AdmissionEvidenceError("V2 curator restore command order changed")


def _verify_curator_status(value: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    command = value["command"]
    if (
        set(value) != {"command", "response"}
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "skills.curator.status",
            "--json",
            "--timeout",
            "5000",
        ]
        or value["response"] != {"parsed": True, "value": expected}
        or not contract._command_succeeded_clean(command)
        or not contract._command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != expected
    ):
        raise AdmissionEvidenceError("V2 curator restore status changed")


def _verify_discovery(value: Mapping[str, Any]) -> None:
    command = value["command"]
    expected = contract._EXPECTED_DISCOVERY
    response = value["response"]
    if (
        set(value) != {"command", "response", "target_matches"}
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "skills.status",
            "--json",
            "--timeout",
            "5000",
            "--params",
            '{"agentId":"main"}',
        ]
        or value["target_matches"] != [expected]
        or response["parsed"] is not True
        or response["value"]
        != {
            "agentId": "main",
            "agentSkillFilter": [_TARGET],
            "managedSkillsDir": "/var/lib/aragorn-agent-gateway/state/skills",
            "skills": [expected],
            "workspaceDir": "/var/lib/aragorn-agent-gateway/workspace",
        }
        or not contract._command_succeeded_clean(command)
        or not contract._command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != response["value"]
    ):
        raise AdmissionEvidenceError("V2 curator restore discovery changed")


def _verify_denials(after: Mapping[str, Any]) -> None:
    gateway = after["gateway_restore"]
    gateway_command = gateway["command"]
    expected_gateway = {
        "ok": False,
        "error": {
            "type": "gateway_request_error",
            "code": "INVALID_REQUEST",
            "message": _AUTHORITY_ERROR,
            "retryable": False,
        },
    }
    invalid = after["invalid_token_gateway_control"]
    invalid_command = invalid["command"]
    expected_invalid_error = {
        "type": "gateway_transport_error",
        "kind": "closed",
        "message": "gateway closed (1008): unauthorized: gateway token mismatch (set gateway.remote.token to match gateway.auth.token)",
        "code": 1008,
        "reason": "unauthorized: gateway token mismatch (set gateway.remote.token to match gateway.auth.token)",
    }
    expected_invalid = {
        "parsed": True,
        "value": {
            "error": expected_invalid_error,
            "gateway": {
                "bindDetail": "Bind: loopback",
                "url": "ws://127.0.0.1:18789",
                "urlSource": "local loopback",
            },
            "ok": False,
        },
    }
    invalid_stderr = (
        "gateway connect failed: GatewayClientRequestError: unauthorized: gateway "
        "token mismatch (set gateway.remote.token to match gateway.auth.token)\n"
    )
    cli = after["cli_fallback_restore"]["command"]
    cli_stderr = (
        "gateway connect failed: GatewayClientRequestError: unauthorized: gateway token "
        "mismatch (set gateway.remote.token to match gateway.auth.token)\n"
        f"Error: {_AUTHORITY_ERROR}\n"
    )
    if (
        set(gateway) != {"command", "response"}
        or set(invalid) != {"command", "response"}
        or set(after["cli_fallback_restore"]) != {"command"}
        or gateway["response"] != {"parsed": True, "value": expected_gateway}
        or gateway_command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "skills.curator.restore",
            "--json",
            "--timeout",
            "5000",
            "--params",
            '{"skill":"template-skill"}',
        ]
        or gateway_command["exit_code"] != 1
        or gateway_command["stderr_bytes"] != 0
        or gateway_command["stderr_digest"] != _EMPTY_DIGEST
        or gateway_command["stdout_bytes"] != 205
        or gateway_command["stdout_digest"]
        != "sha256:7857425dcee89a1d4e2269e0fa8c0f0e58a8ab15624f9301341477f0a123873c"
        or json.loads(gateway_command["stdout_excerpt"]) != expected_gateway
        or invalid["response"] != expected_invalid
        or invalid_command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "system.info",
            "--json",
            "--timeout",
            "5000",
        ]
        or invalid_command["exit_code"] != 1
        or invalid_command["stdout_bytes"] != 481
        or invalid_command["stdout_digest"]
        != "sha256:d88557eaf82b003daed20aeb2d0c1c9a6271e9c3bb95686181e9ecf19d4668ae"
        or invalid_command["stderr_bytes"] != 143
        or invalid_command["stderr_excerpt"] != invalid_stderr
        or invalid_command["stderr_digest"]
        != "sha256:25b45fe227920562cda00967eb52d40dd6380d96f3c7112b267f16fec27f7322"
        or cli["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "skills",
            "curator",
            "--json",
            "restore",
            _TARGET,
        ]
        or cli["exit_code"] != 1
        or cli["stdout_bytes"] != 0
        or cli["stdout_digest"] != _EMPTY_DIGEST
        or cli["stderr_bytes"] != 210
        or cli["stderr_excerpt"] != cli_stderr
        or cli["stderr_digest"] != _digest(cli_stderr.encode())
        or not all(
            contract._command_output_is_exact(command)
            for command in (gateway_command, invalid_command, cli)
        )
    ):
        raise AdmissionEvidenceError("V2 curator restore denial changed")


def _verify_lifecycle(after: Mapping[str, Any]) -> None:
    values = [
        after["database_before"],
        after["database_after_gateway"],
        after["database_after_cli"],
    ]
    if [value["data_version"] for value in values] != [2, 3, 4]:
        raise AdmissionEvidenceError("V2 curator restore data version changed")
    if any(value["file"] != values[0]["file"] for value in values[1:]):
        raise AdmissionEvidenceError("V2 curator restore database identity changed")
    for value in values:
        file = value["file"]
        if (
            set(value) != {"data_version", "file", "row"}
            or set(file)
            != {
                "device",
                "digest",
                "digest_error",
                "exists",
                "gid",
                "inode",
                "mode",
                "nlink",
                "path",
                "size",
                "type",
                "uid",
            }
            or value["row"] != _ARCHIVED_ROW
            or file["path"]
            != "/var/lib/aragorn-agent-gateway/state/state/openclaw.sqlite"
            or file["exists"] is not True
            or file["type"] != "file"
            or file["uid"] != 992
            or file["gid"] != 992
            or file["mode"] != "600"
            or file["nlink"] != 1
            or file["digest_error"] is not None
        ):
            raise AdmissionEvidenceError("V2 curator restore lifecycle row changed")
