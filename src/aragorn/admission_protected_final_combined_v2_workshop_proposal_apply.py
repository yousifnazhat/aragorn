"""Qualify one exact current-V2 workshop proposal apply route."""

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

_ROUTE = "ADM-02/update/workshop-proposal-apply"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_CONFIG_PATH = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-19007"
_WORKSHOP = "aragorn-protected-workshop"
_WORKSHOP_ROOT = (
    "/var/lib/aragorn-agent-gateway/workspace/skills/aragorn-protected-workshop"
)
_WORKSHOP_FILE = f"{_WORKSHOP_ROOT}/SKILL.md"
_PROPOSAL_ID = "aragorn-protected-workshop-20260826-87fafc7257"
_PROTECTED_PROMPT_DIGEST = (
    "sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501"
)
_SESSION_ID = "64cce057-e003-4465-94e2-528ff6bd391b"
_INITIAL_SNAPSHOT_VERSION = 1_787_754_737_358
_FINAL_SNAPSHOT_VERSION = 1_787_754_756_014
_INITIAL_STORE_DIGEST = (
    "sha256:0e189b02a087bdd22359407bcdbf8b4489d0734d4e4f49691e51b5c3c656626b"
)
_FINAL_STORE_DIGEST = (
    "sha256:d2784e0b0d5e7c416ec485e364952e26d9e42eae2d087672fe5057014caa2791"
)
_CATALOG_AUTHORITY_ERROR = (
    "Error: External skill activation authority rejected the catalog: "
    "selected skill set differs from the declared sources"
)
_NETWORK_ERROR = (
    "⚠️ Agent failed before reply: LLM request failed: network connection error.\n"
    "Logs: openclaw logs --follow"
)
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

_BASE = {
    "bytes": 58_642,
    "digest": "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6",
    "path": "src/aragorn/admission_protected_final_combined_v2_config_activation.py",
}
_EVIDENCE = {
    "bytes": 491_217,
    "canonical_bytes": 491_216,
    "canonical_digest": "sha256:c68338c3397fe383b27f9f74c10cda99f89e5d83cecb313e5a086a112a5f8377",
    "digest": "sha256:55a6d55988aa79a963a49eb885bb63758daa3b575ff1d16c2d901cafe281b379",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "workshop-proposal-apply-systemd-p3-final-catalog-fixed-2026-08-26.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 48_264,
    "canonical_digest": "sha256:4addbbd02a696a64271e9a3879b5a77663785662b5bc99398d5e9d2bf2c73cdf",
    "digest": "sha256:47895f2544b7b1b91c2e5daf4b32e3450dc349e5819b8eea47f944a70a215cd2",
}
_SOURCE = {
    "commit": "30df60acc9b80269530e1852c46b32a20899afba",
    "parent": "dc18f9b48f3633823d6ae8d70696fee0b0e22764",
    "tree": "eb61caabeef1f7d2b16ec9eea499132f5bb7669f",
}
_RETENTION = {
    "commit": "709910cb428008ebc53828bb2fd46ab425abf12a",
    "parent": _SOURCE["commit"],
    "tree": "edda691fc8e8e8e2b9e27206c5279517933a9664",
}
_RETENTION_BLOB = "9bfd2ec419d2beef744932f0d4b8fc9c0219e9fb"
_IMAGE = "sha256:193e2236761f8ebd93e309dc1fd2b010e24e513396a1fd08b753ad5d6d04507c"
_PARENT_IMAGE = "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
_DIGESTS = {
    "action": "sha256:64147a7ca4b0720a1abb753a2d165a556ffb2eedb31161fbcc004285a64a1281",
    "composition": "sha256:6ea30cb0667fd4a004137699c5b50a6c6b7bb1f5cf52040ad84f2fd78988cc9c",
    "composition_action": "sha256:d183e3c652d807111994ac0ebd89304656f3deee6b76e570a761cb45f4dd0f76",
    "execution": "sha256:01f06a86602f20cbbc4d4d3034f89240a1a38a448b89e4d363b00b553f5a4d41",
    "gateway_binding": "sha256:c77eee825ee61633ed7493bbef1ff9a19e5b48ea9276a439e8391591e23951da",
    "harness": "sha256:23aa209e1bd99edcc541314c80490993d7bded200afd1b4f32d57313480f23f9",
    "host_config": "sha256:cf12357295b62f09a0d34b3b9de6ff6246748bf68cebe37352380021918db6ad",
    "protected_boundary": "sha256:76979b142678cdd172b9fe3c1c68df85a3bece4ec4b86ded77e6dfbe14b7b0bd",
    "source_artifacts": "sha256:89fc3a446572319e757f52a91e3468ca61004ba010884e5d55a1b9fae8df0010",
    "stack": "sha256:dcfe6a72543dc7c5db763d9d3046c32c81f209b19db7d2aa9a0e250ba67efe1e",
}
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 12_335,
        "digest": "sha256:1797392bc6b6f0532d93e7ca46deb3cc0d1f699874871037f30cdb0caf47fc7a",
        "path": "/src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
    },
    "materializer": {
        "bytes": 87_912,
        "digest": "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
        "path": "/src/scripts/materialize_fixed_admission_probes.py",
    },
    "v1_route_injector": {
        "bytes": 20_878,
        "digest": "sha256:c6ef16317046bd5815050aaa4e24551ca62e8eb42b1997fcd7a2b8145716246c",
        "path": "/src/scripts/runtime_action_worker_final_route_systemd_probe.py",
    },
}
_PROBES = [
    {
        "bytes": 84,
        "digest": "sha256:a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a",
        "name": "PROPOSAL.md",
        "role": "fixture",
    },
    {
        "bytes": 50_175,
        "digest": "sha256:07676570b96d8c0c54f40bd44f4132a2cdb06cb36002dd6f6c406f49afc3a705",
        "name": "protected-route-probe.mjs",
        "role": "probe",
    },
]
_FIXTURE = {
    "blob": "deb44064a72852f7f963a067c0e3458180fe89ea",
    "path": "benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md",
    **_PROBES[0],
}
_BOOLEAN_FIELDS = contract._BOOLEAN_FIELDS | {
    "catalog_after_apply_excludes_workshop",
    "catalog_after_apply_matches_initial",
    "catalog_exact",
    "confirmed",
    "executable",
    "final_catalog_matches_initial",
    "final_same_session_catalog_exact",
    "immediate_post_apply_same_session",
    "immediate_post_apply_store_unchanged",
    "prompt_exact",
    "json_object",
    "same_store_device",
    "session_id_valid",
    "snapshot_present",
    "snapshot_version_advanced",
    "snapshot_version_valid",
    "store_digest_changed",
    "store_inode_changed",
    "updated_at_advanced",
}


def verify_openclaw_final_combined_v2_workshop_proposal_apply(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact dynamic current-V2 workshop proposal apply PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract.base.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 workshop proposal apply"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V2 workshop proposal apply CAS differs from signed retention"
            )
        evidence = contract.base.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 workshop proposal apply"
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
        raise AdmissionEvidenceError(
            f"invalid V2 workshop proposal apply evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED",
        }
        for route in profile["routes"]
    ]
    return {
        "schema": "aragorn/admission-protected-final-combined-v2-workshop-proposal-apply-route-coverage/v1",
        "assurance": "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_CURRENT_V2_WORKSHOP_PROPOSAL_APPLY_ROUTE_ONLY",
        "bindings": {
            "configuration": dict(contract._SOURCES["configuration"]),
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
            "workshop_proposal_apply_observation": {
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
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in contract.base.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_WORKSHOP_PROPOSAL_APPLY_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "WORKSHOP_RESIDUE_PERSISTS_THROUGH_FINAL_OBSERVATION",
            "POST_APPLY_CATALOG_REJECTED_BY_EXTERNAL_ACTIVATION_AUTHORITY",
            "NO_POST_APPLY_SKILLS_STATUS_AVAILABILITY_CLAIM",
            "NO_WORKSHOP_RESIDUE_DISCOVERY_OR_MODEL_VISIBILITY_CLAIM",
            "NO_PRE_EFFECT_NO_MUTATION_CLEANUP_ROLLBACK_OR_QUARANTINE_CLAIM",
            "APPLIED_TARGET_BYTES_NOT_RETAINED_METADATA_DIGEST_ONLY",
            "WORKSHOP_SCAN_CLEAN_IS_SELF_REPORTED_DIAGNOSTIC_ONLY",
            "FOLLOWING_SAME_SESSION_TRANSITION_NOT_PROMOTED_BY_THIS_QUALIFIER",
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
                "SIGNED_EXACT_NATIVE_PROPOSAL_APPLY_RESIDUE_WITH_POST_APPLY_"
                "EXTERNAL_ACTIVATION_AUTHORITY_CATALOG_DENIAL"
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
        raise AdmissionEvidenceError("V2 workshop proposal apply verifier base changed")
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
        raise AdmissionEvidenceError("V2 workshop proposal apply repository changed")
    contract.base._verify_commit(_SOURCE)
    contract.base._verify_commit(_RETENTION)
    entry = contract.base.legacy._git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError(
            "V2 workshop proposal apply signed tree entry changed"
        )
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
        raise AdmissionEvidenceError("V2 workshop proposal apply signed blob changed")
    fixture_entry = contract.base.legacy._git(
        ["ls-tree", "-z", "--full-name", _SOURCE["commit"], "--", _FIXTURE["path"]]
    )
    expected_fixture = (
        f"100644 blob {_FIXTURE['blob']}\t{_FIXTURE['path']}".encode() + b"\0"
    )
    fixture = contract.base.legacy._git(
        ["cat-file", "blob", _FIXTURE["blob"]], maximum=_FIXTURE["bytes"]
    )
    if (
        fixture_entry != expected_fixture
        or len(fixture) != _FIXTURE["bytes"]
        or _digest(fixture) != _FIXTURE["digest"]
    ):
        raise AdmissionEvidenceError("V2 workshop proposal source fixture changed")
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
        or evidence["recorded_at"] != "2026-08-26T14:32:40.822407Z"
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
        raise AdmissionEvidenceError("V2 workshop proposal apply wrapper changed")

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
        or observation["route"] != document["routes"][0]
        or observation["bundle"] != _PROBES
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V2 workshop proposal apply nested custody changed")
    harness = evidence["composition"]["action"]["harness"]["document"]
    _verify_execution(
        observation, evidence["composition"]["action"]["boundaries"], harness
    )
    _verify_document(
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
        raise AdmissionEvidenceError("V2 workshop proposal apply execution custody changed")
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    action = composition["action"]
    source = action["artifacts"]["final_combined_v2"]
    before = composition["profile"]["before"]
    after = composition["profile"]["after"]
    profile = after["document"]
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
        or composition["recorded_at"] != "2026-08-26T14:32:40.822093Z"
        or composition["authority"]
        != (
            "BOUNDED_FINAL_COMBINED_V2_P3_7C_ACTION_OBSERVATION_ONLY_PROFILE_"
            "ROUTES_REMAIN_NOT_TESTED_NOT_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or canonical_digest(action) != _DIGESTS["composition_action"]
        or before != after
        or before != source["profile"]
        or action["inputs"]["gateway_config"] != source["config"]["document"]
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(contract.base.legacy.parent._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
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
        or action["recorded_at"] != "2026-08-26T14:32:40.396709Z"
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
        raise AdmissionEvidenceError("V2 workshop proposal apply composition changed")
    contract._verify_configuration(source)
    _verify_source_artifacts(source_artifacts)
    _verify_harness(action["harness"], action["identities"], action["secret_checks"])
    if action["runtime"] != {
        "entrypoint": _OPENCLAW,
        "entrypoint_digest": contract.base.legacy.parent._RUNTIME["entrypoint_digest"],
        "expected_version": contract.base.legacy.parent._RUNTIME["version_output"],
        "root": "/runtime",
        "tree": contract._RUNTIME_TREE,
        "version_output": contract.base.legacy.parent._RUNTIME["version_output"],
    }:
        raise AdmissionEvidenceError("V2 workshop proposal apply runtime binding changed")
    return profile


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V2 workshop proposal apply source bundle changed")
    for name, identity in _SOURCE_ARTIFACTS.items():
        contract._verify_bound_file(
            value[name], identity, path=identity["path"], mode="0555"
        )
    if value["probe_bundle"] != _PROBES:
        raise AdmissionEvidenceError("V2 workshop proposal apply probe bundle changed")


def _verify_harness(
    envelope: Mapping[str, Any],
    identities: Mapping[str, Any],
    secret_checks: Mapping[str, Any],
) -> None:
    document = envelope["document"]
    raw_file = envelope["file"]
    raw = base64.b64decode(raw_file["base64"], validate=True)
    parsed = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=contract.base.legacy.parent._reject_duplicates,
        parse_constant=contract.base.legacy.parent._reject_constant,
    )
    lineage = document["image_lineage"]
    verification = document["source_commit_verification"]
    commit_object = verification["commit_object"]
    commit_raw = base64.b64decode(commit_object["base64"], validate=True)
    stderr = verification["stderr"]
    stderr_raw = base64.b64decode(stderr["base64"], validate=True)
    stdout = verification["stdout"]
    stdout_raw = base64.b64decode(stdout["base64"], validate=True)
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
        or document["image_reference"] != "aragorn-phase3-final-combined-v2-systemd"
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
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:19007",
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
        or set(verification)
        != {"command", "commit_object", "exit_code", "stderr", "stdout"}
        or verification["command"] != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or verification["exit_code"] != 0
        or set(commit_object) != {"base64", "bytes", "digest"}
        or commit_raw
        != contract.base.legacy._git(
            ["cat-file", "commit", _SOURCE["commit"]], maximum=4096
        )
        or commit_object["bytes"] != len(commit_raw)
        or commit_object["digest"] != _digest(commit_raw)
        or set(stderr) != {"base64", "bytes", "digest"}
        or stderr_raw
        != (
            'Good "git" signature for yousif.snazhat@gmail.com with ED25519 key '
            f'{contract.base.legacy.parent._SIGNATURE["key"]}\n'
        ).encode()
        or stderr["bytes"] != len(stderr_raw)
        or stderr["digest"] != _digest(stderr_raw)
        or set(stdout) != {"base64", "bytes", "digest"}
        or stdout_raw != b""
        or stdout["bytes"] != 0
        or stdout["digest"] != _EMPTY_DIGEST
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
        raise AdmissionEvidenceError("V2 workshop proposal apply harness changed")
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
        raise AdmissionEvidenceError("V2 workshop proposal apply harness file changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=contract.base.legacy.parent._reject_duplicates,
        parse_constant=contract.base.legacy.parent._reject_constant,
    )
    canonical = canonical_json(document)
    if (
        set(value)
        != {"base64", "bytes", "canonical_digest", "digest", "raw_is_canonical_json_lf"}
        or not isinstance(document, dict)
        or raw == canonical + b"\n"
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not False
    ):
        raise AdmissionEvidenceError("V2 workshop proposal apply raw identity changed")
    _verify_scalar_types(document)
    return document


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError(
                "V2 workshop proposal apply unexpected floating-point value"
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
                    "V2 workshop proposal apply nullable boolean field type changed"
                )
            if key == "pinned" and type(item) not in (bool, int):
                raise AdmissionEvidenceError(
                    "V2 workshop proposal apply mixed boolean field type changed"
                )
            if (
                isinstance(key, str)
                and key not in {"message_prefix_continuity_valid", "pinned"}
                and ((key in _BOOLEAN_FIELDS) != (type(item) is bool))
            ):
                raise AdmissionEvidenceError(
                    "V2 workshop proposal apply boolean field type changed"
                )
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError(
                    "V2 workshop proposal apply boolean list item changed"
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
    commands = document["actions"][0]["commands"]
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
        or pid != 2733
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
            _NODE,
            "/route-input/workshop-proposal-apply/protected-route-probe.mjs",
            "--route-id",
            _ROUTE,
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
        or document["actions"][0]["prerequisites"]["gateway_process"]["pid"] != pid
        or document["actions"][0]["prerequisites"]["gateway_process"]["cmdline"]
        != process["cmdline"]
        or document["actions"][0]["prerequisites"]["gateway_process"][
            "start_time_ticks"
        ]
        != process["start_time_ticks"]
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
        raise AdmissionEvidenceError("V2 workshop proposal apply execution boundary changed")
    contract.base.legacy._verify_stack_boundary(
        stack,
        trusted=boundaries,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    contract.base.legacy._verify_gateway_listener(
        stack["gateway_listener"], stack["processes"]
    )


def _verify_document(
    document: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    container_id: str,
    execution: Mapping[str, Any],
    outer_recorded_at: str,
) -> None:
    if (
        set(document)
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
        or document["schema"] != "aragorn/openclaw-protected-route-action-observations/v1"
        or document["recorded_at"] != "2026-08-26T14:32:40.377Z"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBES[1]["digest"]
        or document["selected_route_ids"] != [_ROUTE]
        or document["routes"]
        != [
            {
                "action_id": "workshop-protected-apply",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["run_nonce"] != "7513cbfe1b7b798354ba9aaaac0e2420"
        or document["runtime_binding"]
        != {
            "commit": contract.base.legacy.parent._OPENCLAW["commit"],
            "node_path": _NODE,
            "openclaw_digest": contract.base.legacy.parent._RUNTIME[
                "entrypoint_digest"
            ],
            "openclaw_path": _OPENCLAW,
            "version": "2026.7.1",
        }
        or canonical_digest(document["protected_boundary"])
        != _DIGESTS["protected_boundary"]
        or len(document["actions"]) != 1
    ):
        raise AdmissionEvidenceError("V2 workshop proposal apply document changed")
    _verify_boundary(document["protected_boundary"], config)
    action = document["actions"][0]
    if (
        set(action)
        != {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        or action["id"] != "workshop-protected-apply"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or canonical_digest(action) != _DIGESTS["action"]
    ):
        raise AdmissionEvidenceError("V2 workshop proposal apply action changed")
    _verify_prerequisites(action["prerequisites"], container_id)
    _verify_observations(action, document["run_nonce"])
    _verify_commands(
        action,
        execution=execution,
        recorded_at=document["recorded_at"],
        outer_recorded_at=outer_recorded_at,
    )


def _verify_boundary(boundary: Mapping[str, Any], config: Mapping[str, Any]) -> None:
    roots = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    if (
        set(boundary) != {"configuration", "effective_identity", "ready", "roots", "runtime"}
        or boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "uid": 992}
        or set(boundary["roots"]) != set(roots)
    ):
        raise AdmissionEvidenceError("V2 workshop proposal apply protected boundary changed")
    contract._verify_config(boundary["configuration"])
    if (
        config["skills"]["workshop"]["restoreAuthority"] != "external"
        or config["skills"]["activation"]["authority"] != "external"
    ):
        raise AdmissionEvidenceError("V2 workshop proposal apply configuration changed")
    contract._verify_read_only_mount(
        boundary["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{_RUNTIME_VOLUME}/_data",
    )
    for name, path in roots.items():
        value = boundary["roots"][name]
        entry = value["observation"]
        if (
            set(value) != {"observation", "ready", "writable"}
            or value["ready"] is not True
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
                "V2 workshop proposal apply conventional root changed"
            )


def _verify_prerequisites(before: Mapping[str, Any], container_id: str) -> None:
    if (
        set(before)
        != {
            "commands",
            "draft",
            "gateway_process",
            "ready",
            "reason_codes",
            "runtime_files",
            "system_info",
            "target_before",
        }
        or before["ready"] is not True
        or before["reason_codes"] != []
        or len(before["commands"]) != 2
        or before["commands"][1] != before["system_info"]["command"]
        or before["gateway_process"]
        != {
            "cmdline": ["openclaw-gateway"],
            "hostname": container_id[:12],
            "pid": 2733,
            "start_time_ticks": "36435449",
        }
        or before["target_before"] != _absent_target()
    ):
        raise AdmissionEvidenceError("V2 workshop proposal apply prerequisites changed")
    contract._verify_version(before["commands"][0])
    contract._verify_system(before["system_info"], before["gateway_process"])
    _verify_runtime_files(before["runtime_files"])
    _verify_draft(before["draft"])


def _verify_runtime_files(value: Mapping[str, Any]) -> None:
    node = value["node"]
    openclaw = value["openclaw"]
    if (
        set(value) != {"node", "openclaw"}
        or set(node) != {"executable", "file"}
        or node["executable"] is not True
        or node["file"]["path"] != _NODE
        or node["file"]["exists"] is not True
        or node["file"]["type"] != "file"
        or node["file"]["uid"] != 0
        or node["file"]["gid"] != 0
        or node["file"]["mode"] != "755"
        or node["file"]["digest"] is not None
        or node["file"]["digest_error"] != "FILE_EXCEEDS_CONTROL_LIMIT"
        or set(openclaw) != {"executable", "file"}
        or openclaw["executable"] is not True
    ):
        raise AdmissionEvidenceError("V2 workshop proposal apply runtime files changed")
    contract._verify_openclaw(openclaw["file"])


def _verify_draft(value: Mapping[str, Any]) -> None:
    file = value["observation"]
    mount = value["mount"]
    if (
        set(value) != {"expected_digest", "mount", "observation"}
        or value["expected_digest"] != _FIXTURE["digest"]
        or file["path"] != "/route-input/workshop-proposal-apply/PROPOSAL.md"
        or file["exists"] is not True
        or file["type"] != "file"
        or file["uid"] != 0
        or file["gid"] != 0
        or file["mode"] != "444"
        or file["nlink"] != 1
        or file["size"] != _FIXTURE["bytes"]
        or file["digest"] != _FIXTURE["digest"]
        or file["digest_error"] is not None
        or mount["entry"]["entries"]
        != [
            "archive-source-force-replacement",
            "config-entry-activation",
            "cron-rescan",
            "curator-restore-activation",
            "fresh-session-reset",
            "missing-prompt-blob-rebuild",
            "session-snapshot-consumer",
            "workshop-proposal-apply",
        ]
        or mount["entry"]["entry_count"] != 8
    ):
        raise AdmissionEvidenceError("V2 workshop proposal apply draft changed")
    contract._verify_read_only_mount(
        mount,
        path="/route-input",
        source=f"/docker/volumes/{_ROUTE_VOLUME}/_data",
    )


def _absent_target() -> dict[str, Any]:
    return {
        "directory": {"exists": False, "path": _WORKSHOP_ROOT},
        "skill": {"exists": False, "path": _WORKSHOP_FILE},
    }


def _verify_observations(action: Mapping[str, Any], nonce: str) -> None:
    after = action["observations"]
    expected_keys = {
        "catalog_after_apply",
        "catalog_after_apply_excludes_workshop",
        "catalog_after_apply_matches_initial",
        "catalog_before",
        "final_catalog",
        "final_catalog_matches_initial",
        "final_same_session_catalog_exact",
        "final_snapshot",
        "final_snapshot_check",
        "final_snapshot_observed_at",
        "final_snapshot_transition",
        "immediate_post_apply_same_session",
        "immediate_post_apply_snapshot",
        "immediate_post_apply_snapshot_check",
        "immediate_post_apply_snapshot_observed_at",
        "immediate_post_apply_store_unchanged",
        "initial_snapshot",
        "initial_snapshot_check",
        "initial_snapshot_observed_at",
        "initial_turn",
        "native_apply_result",
        "native_proposal_result",
        "next_same_session_turn",
        "proposal_result",
        "target_after_apply",
        "target_after_apply_observed_at",
        "target_after_proposal",
        "target_after_proposal_observed_at",
        "target_final",
    }
    if set(after) != expected_keys:
        raise AdmissionEvidenceError("V2 workshop proposal apply observations changed")

    _verify_catalog(after["catalog_before"], initial=True)
    _verify_turn(
        after["initial_turn"],
        nonce=nonce,
        label="initial-snapshot",
        message="Inert protected workshop initial snapshot observation.",
    )
    _verify_proposal(after)
    _verify_catalog(after["catalog_after_apply"], initial=False)
    _verify_turn(
        after["next_same_session_turn"],
        nonce=nonce,
        label="next-same-session",
        message="Inert protected workshop next same-session observation.",
    )
    _verify_catalog(after["final_catalog"], initial=False)

    if (
        after["target_after_proposal"] != _absent_target()
        or after["target_after_proposal_observed_at"]
        != "2026-08-26T14:32:35.173Z"
    ):
        raise AdmissionEvidenceError(
            "V2 workshop proposal created target before apply"
        )
    _verify_residue(after["target_after_apply"])
    if (
        after["target_final"] != after["target_after_apply"]
        or after["target_after_apply_observed_at"]
        != "2026-08-26T14:32:36.053Z"
    ):
        raise AdmissionEvidenceError("V2 workshop proposal residue was not preserved")

    _verify_snapshot(
        after["initial_snapshot"],
        store_digest=_INITIAL_STORE_DIGEST,
        version=_INITIAL_SNAPSHOT_VERSION,
    )
    _verify_snapshot_check(after["initial_snapshot_check"])
    if (
        after["initial_snapshot_observed_at"] != "2026-08-26T14:32:34.269Z"
        or after["immediate_post_apply_snapshot"] != after["initial_snapshot"]
        or after["immediate_post_apply_snapshot_observed_at"]
        != "2026-08-26T14:32:36.053Z"
    ):
        raise AdmissionEvidenceError(
            "V2 workshop proposal immediate protected snapshot changed"
        )
    _verify_snapshot_check(after["immediate_post_apply_snapshot_check"])
    _verify_snapshot(
        after["final_snapshot"],
        store_digest=_FINAL_STORE_DIGEST,
        version=_FINAL_SNAPSHOT_VERSION,
    )
    _verify_snapshot_check(after["final_snapshot_check"])
    if (
        after["final_snapshot_observed_at"] != "2026-08-26T14:32:39.499Z"
        or (
            after["final_snapshot"]["entry"]["session_id"]
            != after["initial_snapshot"]["entry"]["session_id"]
        )
        or after["final_snapshot"]["entry"]["snapshot_version"]
        <= after["initial_snapshot"]["entry"]["snapshot_version"]
        or after["final_snapshot"]["entry"]["updated_at"]
        <= after["initial_snapshot"]["entry"]["updated_at"]
        or after["final_snapshot"]["file"]["device"]
        != after["initial_snapshot"]["file"]["device"]
        or after["final_snapshot"]["file"]["digest"]
        == after["initial_snapshot"]["file"]["digest"]
        or after["final_snapshot"]["file"]["inode"]
        == after["initial_snapshot"]["file"]["inode"]
    ):
        raise AdmissionEvidenceError(
            "V2 workshop proposal final protected snapshot changed"
        )

    # These are probe-derived summaries. Their values are deliberately ignored;
    # the verifier recomputes every promoted predicate from the retained records.
    if (
        set(after["final_snapshot_transition"])
        != {
            "same_store_device",
            "snapshot_version_advanced",
            "store_digest_changed",
            "store_inode_changed",
            "updated_at_advanced",
        }
        or not (
            contract.base.legacy._parse_time(after["initial_snapshot_observed_at"])
            <= contract.base.legacy._parse_time(
                after["target_after_proposal_observed_at"]
            )
            <= contract.base.legacy._parse_time(after["target_after_apply_observed_at"])
            == contract.base.legacy._parse_time(
                after["immediate_post_apply_snapshot_observed_at"]
            )
            <= contract.base.legacy._parse_time(after["final_snapshot_observed_at"])
        )
    ):
        raise AdmissionEvidenceError("V2 workshop proposal observation causality changed")


def _verify_catalog(value: Mapping[str, Any], *, initial: bool) -> None:
    command = value["command"]
    if (
        set(value) != {"command", "parsed", "response", "target_matches"}
        or value["parsed"] is not True
        or value["target_matches"] != []
        or set(value["response"]) != {"parsed", "value"}
        or value["response"]["parsed"] is not True
    ):
        raise AdmissionEvidenceError("V2 workshop proposal catalog envelope changed")
    argv = _gateway_argv("skills.status")
    if initial:
        expected = {
            "agentId": "main",
            "agentSkillFilter": ["template-skill"],
            "managedSkillsDir": "/var/lib/aragorn-agent-gateway/state/skills",
            "skills": [contract._EXPECTED_DISCOVERY],
            "workspaceDir": "/var/lib/aragorn-agent-gateway/workspace",
        }
        _verify_command(command, argv)
    else:
        expected = {
            "ok": False,
            "error": {
                "type": "gateway_request_error",
                "code": "UNAVAILABLE",
                "message": _CATALOG_AUTHORITY_ERROR,
                "retryable": False,
            },
        }
        _verify_command(command, argv, exit_code=1)
    if (
        value["response"]["value"] != expected
        or json.loads(command["stdout_excerpt"]) != expected
    ):
        raise AdmissionEvidenceError("V2 workshop proposal catalog response changed")


def _verify_turn(
    value: Mapping[str, Any], *, nonce: str, label: str, message: str
) -> None:
    run_id = f"aragorn-protected-route-workshop-{label}-{nonce}"
    send_params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": message,
        "sessionKey": "agent:main:aragorn-protected-routes-v1",
        "timeoutMs": 5000,
    }
    wait_params = {"runId": run_id, "timeoutMs": 10000}
    send = value["send"]
    wait = value["wait"]
    expected_send = {"runId": run_id, "status": "started"}
    expected_wait = {
        "runId": run_id,
        "status": "error",
        "endedAt": wait["response"]["value"]["endedAt"],
        "error": _NETWORK_ERROR,
    }
    if (
        set(value) != {"commands", "confirmed", "send", "wait"}
        or set(send) != {"command", "response"}
        or set(wait) != {"command", "response"}
        or value["commands"] != [send["command"], wait["command"]]
        or send["response"] != {"parsed": True, "value": expected_send}
        or wait["response"] != {"parsed": True, "value": expected_wait}
        or type(expected_wait["endedAt"]) is not int
        or expected_wait["endedAt"] <= 0
    ):
        raise AdmissionEvidenceError("V2 workshop proposal same-session turn changed")
    _verify_command(send["command"], _gateway_argv("chat.send", params=send_params))
    _verify_command(
        wait["command"],
        _gateway_argv("agent.wait", timeout="12000", params=wait_params),
    )
    if (
        json.loads(send["command"]["stdout_excerpt"]) != expected_send
        or json.loads(wait["command"]["stdout_excerpt"]) != expected_wait
    ):
        raise AdmissionEvidenceError("V2 workshop proposal turn output changed")


def _verify_proposal(after: Mapping[str, Any]) -> None:
    proposed = after["native_proposal_result"]
    applied = after["native_apply_result"]
    if (
        set(proposed) != {"command", "response"}
        or set(applied) != {"command", "response"}
        or proposed["response"]["parsed"] is not True
        or applied["response"]["parsed"] is not True
        or set(proposed["response"]["value"]) != {"content", "record"}
        or set(applied["response"]["value"]) != {"record", "targetSkillFile"}
    ):
        raise AdmissionEvidenceError("V2 workshop proposal response envelope changed")
    proposed_value = proposed["response"]["value"]
    applied_value = applied["response"]["value"]
    pending = proposed_value["record"]
    final = applied_value["record"]
    _verify_proposal_record(pending, applied=False)
    _verify_proposal_record(final, applied=True)
    content = proposed_value["content"]
    expected_content = (
        "---\n"
        f'name: "{_WORKSHOP}"\n'
        'description: "Inert Aragorn protected workshop fixture"\n'
        "status: proposal\n"
        'version: "v1"\n'
        f'date: "{pending["createdAt"]}"\n'
        "---\n\n"
        "# Aragorn protected workshop route fixture\n\n"
        "This inert fixture performs no actions.\n"
    )
    immutable = {
        "createdAt",
        "createdBy",
        "description",
        "draftFile",
        "draftHash",
        "id",
        "kind",
        "proposedVersion",
        "schema",
        "target",
        "title",
    }
    if (
        content != expected_content
        or _digest(content.encode()) != f"sha256:{pending['draftHash']}"
        or pending["draftHash"] != final["draftHash"]
        or {key: pending[key] for key in immutable}
        != {key: final[key] for key in immutable}
        or pending["status"] != "pending"
        or final["status"] != "applied"
        or final["appliedAt"] != final["updatedAt"]
        or not (
            contract.base.legacy._parse_time(proposed["command"]["started_at"])
            <= contract.base.legacy._parse_time(pending["createdAt"])
            == contract.base.legacy._parse_time(pending["updatedAt"])
            == contract.base.legacy._parse_time(pending["scan"]["scannedAt"])
            <= contract.base.legacy._parse_time(proposed["command"]["completed_at"])
            <= contract.base.legacy._parse_time(applied["command"]["started_at"])
            < contract.base.legacy._parse_time(final["scan"]["scannedAt"])
            < contract.base.legacy._parse_time(final["appliedAt"])
            == contract.base.legacy._parse_time(final["updatedAt"])
            <= contract.base.legacy._parse_time(applied["command"]["completed_at"])
        )
        or applied_value["targetSkillFile"] != _WORKSHOP_FILE
        or after["proposal_result"]
        != {"parsed": True, "proposal_id": _PROPOSAL_ID}
        or json.loads(proposed["command"]["stdout_excerpt"]) != proposed_value
        or json.loads(applied["command"]["stdout_excerpt"]) != applied_value
    ):
        raise AdmissionEvidenceError("V2 workshop proposal/apply join changed")
    _verify_command(
        proposed["command"],
        [
            _NODE,
            _OPENCLAW,
            "skills",
            "workshop",
            "--agent",
            "main",
            "propose-create",
            "--name",
            _WORKSHOP,
            "--description",
            "Inert Aragorn protected workshop fixture",
            "--proposal",
            "/route-input/workshop-proposal-apply/PROPOSAL.md",
            "--json",
        ],
    )
    _verify_command(
        applied["command"],
        _gateway_argv(
            "skills.proposals.apply",
            params={"agentId": "main", "proposalId": _PROPOSAL_ID},
        ),
    )


def _verify_proposal_record(value: Mapping[str, Any], *, applied: bool) -> None:
    keys = {
        "createdAt",
        "createdBy",
        "description",
        "draftFile",
        "draftHash",
        "id",
        "kind",
        "proposedVersion",
        "scan",
        "schema",
        "status",
        "target",
        "title",
        "updatedAt",
    }
    if applied:
        keys.add("appliedAt")
    scan = value["scan"]
    if (
        set(value) != keys
        or value["schema"] != "openclaw.skill-workshop.proposal.v1"
        or value["id"] != _PROPOSAL_ID
        or value["kind"] != "create"
        or value["title"] != f"Create {_WORKSHOP}"
        or value["description"] != "Inert Aragorn protected workshop fixture"
        or value["createdBy"] != "cli"
        or value["proposedVersion"] != "v1"
        or value["draftFile"] != "PROPOSAL.md"
        or re.fullmatch(r"[0-9a-f]{64}", value["draftHash"]) is None
        or value["target"]
        != {
            "skillName": _WORKSHOP,
            "skillKey": _WORKSHOP,
            "skillDir": _WORKSHOP_ROOT,
            "skillFile": _WORKSHOP_FILE,
            "source": "openclaw-workspace",
        }
        or set(scan)
        != {"critical", "findings", "info", "scannedAt", "state", "warn"}
        or scan["state"] != "clean"
        or scan["critical"] != 0
        or scan["warn"] != 0
        or scan["info"] != 0
        or scan["findings"] != []
    ):
        raise AdmissionEvidenceError("V2 workshop proposal record changed")


def _verify_residue(value: Mapping[str, Any]) -> None:
    directory = value["directory"]
    skill = value["skill"]
    if (
        set(value) != {"directory", "skill"}
        or directory["path"] != _WORKSHOP_ROOT
        or directory["exists"] is not True
        or directory["type"] != "directory"
        or directory["uid"] != 992
        or directory["gid"] != 992
        or directory["mode"] != "700"
        or directory["nlink"] != 2
        or directory["entries"] != ["SKILL.md"]
        or directory["entry_count"] != 1
        or directory["entries_truncated"] is not False
        or skill["path"] != _WORKSHOP_FILE
        or skill["exists"] is not True
        or skill["type"] != "file"
        or skill["uid"] != 992
        or skill["gid"] != 992
        or skill["mode"] != "600"
        or skill["nlink"] != 1
        or skill["size"] != 184
        or skill["digest"]
        != "sha256:79f26a48b1cfb8f6a85fe7131500d6ee847884492646b80f62ca5898283a476a"
        or skill["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("V2 workshop proposal residue changed")


def _verify_snapshot(
    value: Mapping[str, Any], *, store_digest: str, version: int
) -> None:
    entry = value["entry"]
    file = value["file"]
    prompt = entry["prompt"]
    prompt_file = prompt["file"]
    if (
        set(value) != {"entry", "file", "present"}
        or value["present"] is not True
        or set(entry)
        != {
            "ended_at",
            "prompt",
            "runtime_ms",
            "session_id",
            "skill_names",
            "snapshot_present",
            "snapshot_version",
            "started_at",
            "status",
            "updated_at",
        }
        or entry["session_id"] != _SESSION_ID
        or entry["skill_names"] != ["template-skill"]
        or entry["snapshot_present"] is not True
        or entry["snapshot_version"] != version
        or entry["status"] != "timeout"
        or any(
            type(entry[name]) is not int or entry[name] <= 0
            for name in ("ended_at", "runtime_ms", "started_at", "updated_at")
        )
        or entry["started_at"] > entry["ended_at"]
        or entry["ended_at"] > entry["updated_at"]
        or set(prompt) != {"bytes", "digest", "expected_digest", "file", "storage"}
        or prompt["bytes"] != 737
        or prompt["digest"] != _PROTECTED_PROMPT_DIGEST
        or prompt["expected_digest"] != _PROTECTED_PROMPT_DIGEST
        or prompt["storage"] != "promptRef"
        or prompt_file["path"]
        != (
            "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/skills-prompts/"
            "sha256/60/60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501.txt"
        )
        or prompt_file["exists"] is not True
        or prompt_file["type"] != "file"
        or prompt_file["uid"] != 992
        or prompt_file["gid"] != 992
        or prompt_file["mode"] != "600"
        or prompt_file["nlink"] != 1
        or prompt_file["size"] != 737
        or prompt_file["digest"] != _PROTECTED_PROMPT_DIGEST
        or prompt_file["digest_error"] is not None
        or file["path"]
        != "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json"
        or file["exists"] is not True
        or file["type"] != "file"
        or file["uid"] != 992
        or file["gid"] != 992
        or file["mode"] != "600"
        or file["nlink"] != 1
        or file["size"] != 6582
        or file["digest"] != store_digest
        or file["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("V2 workshop proposal protected snapshot changed")


def _verify_snapshot_check(value: Mapping[str, Any]) -> None:
    # Values are not trusted; _verify_snapshot recomputes every predicate.
    if set(value) != {
        "catalog_exact",
        "prompt_exact",
        "ready",
        "session_id_valid",
        "snapshot_present",
        "snapshot_version_valid",
    }:
        raise AdmissionEvidenceError("V2 workshop proposal snapshot summary changed")


def _gateway_argv(
    method: str,
    *,
    timeout: str = "5000",
    params: Mapping[str, Any] | None = None,
) -> list[str]:
    argv = [_NODE, _OPENCLAW, "gateway", "call", method, "--json", "--timeout", timeout]
    if params is not None:
        argv.extend(
            ["--params", json.dumps(params, sort_keys=True, separators=(",", ":"))]
        )
    return argv


def _verify_command(
    command: Mapping[str, Any], argv: list[str], *, exit_code: int = 0
) -> None:
    if (
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
        or command["argv"] != argv
        or type(command["pid"]) is not int
        or command["pid"] <= 0
        or type(command["exit_code"]) is not int
        or command["exit_code"] != exit_code
        or command["signal"] is not None
        or command["error"] is not None
        or contract.base.legacy._parse_time(command["started_at"])
        >= contract.base.legacy._parse_time(command["completed_at"])
        or command["stderr_excerpt"] != ""
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _EMPTY_DIGEST
        or not contract._command_output_is_exact(command)
    ):
        raise AdmissionEvidenceError("V2 workshop proposal command changed")


def _verify_commands(
    action: Mapping[str, Any],
    *,
    execution: Mapping[str, Any],
    recorded_at: str,
    outer_recorded_at: str,
) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    commands = action["commands"]
    expected = [
        after["catalog_before"]["command"],
        *after["initial_turn"]["commands"],
        after["native_proposal_result"]["command"],
        after["native_apply_result"]["command"],
        after["catalog_after_apply"]["command"],
        *after["next_same_session_turn"]["commands"],
        after["final_catalog"]["command"],
    ]
    all_commands = [*before["commands"], *commands]
    if (
        len(commands) != 9
        or commands != expected
        or len({command["pid"] for command in all_commands}) != 11
        or any(
            contract.base.legacy._parse_time(left["completed_at"])
            > contract.base.legacy._parse_time(right["started_at"])
            for left, right in pairwise(all_commands)
        )
        or not (
            contract.base.legacy._parse_time(execution["started_at"])
            <= contract.base.legacy._parse_time(all_commands[0]["started_at"])
            <= contract.base.legacy._parse_time(all_commands[-1]["completed_at"])
            <= contract.base.legacy._parse_time(recorded_at)
            <= contract.base.legacy._parse_time(execution["completed_at"])
            <= contract.base.legacy._parse_time(outer_recorded_at)
        )
    ):
        raise AdmissionEvidenceError("V2 workshop proposal command causality changed")
    _verify_command(before["commands"][0], [_NODE, _OPENCLAW, "--version"])
    _verify_command(before["commands"][1], _gateway_argv("system.info"))
