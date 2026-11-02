"""Derive one V2 config-entry-activation PASS from exact retained evidence."""

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

from . import admission_protected_final_combined_v2_fresh_session_reset as base
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/update/config-entry-activation"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_CONFIG_PATH = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
_TARGET_ROOT = "/opt/aragorn/runtime-profile/template-skill"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-64335"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

_BASE = {
    "digest": (
        "sha256:ce54e514bac8fa642cce4b6a24a144c8b380621fae7154de1d4fc43206e11119"
    ),
    "path": "src/aragorn/admission_protected_final_combined_v2_fresh_session_reset.py",
}
_EVIDENCE = {
    "bytes": 445_592,
    "canonical_bytes": 445_591,
    "canonical_digest": (
        "sha256:d3a34164beb1450e301f9931ff067c78f8777997133a3902e6227c13c03e799f"
    ),
    "digest": (
        "sha256:34772c46c42541c4e76c1f9888b2ad35c8aa26d3b63746d8853ad1826a51373f"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "config-entry-activation-systemd-p3-final-catalog-fixed-2026-08-22.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 30_046,
    "canonical_digest": (
        "sha256:0bb03380db05b8a94926e5ffe463a3016b9de360ef39345cce382a0c89ff1c4b"
    ),
    "digest": (
        "sha256:4904d7312385c3914d58f4ec1112979b8ee15e14e44d1c24002f16f6af7e5e79"
    ),
}
_SOURCE = {
    "commit": "17d95091e87e9f41fdce4c096cb382fe04db4798",
    "parent": "78e9cd555f49e5eed7c6533b0bec5e420e7e3e24",
    "tree": "8e0be64c1ded065dc74d22c29ff5056ad0aca375",
}
_RETENTION = {
    "commit": "1b13a8e4ff3f66f87cd26c34987e1e845c497028",
    "parent": _SOURCE["commit"],
    "tree": "74bdab4c4e283e5c196ada2191ef7aaca724f45e",
}
_RETENTION_BLOB = "548c32492919d0368c2407151a40e01089a2748c"
_IMAGE = "sha256:700ebe792d384cce37484f1838f05622b0518984f293f4d4c0cd28c6fb60f9d4"
_PARENT_IMAGE = (
    "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
)
_DIGESTS = {
    "action": "sha256:5caad394e6bfac84e7955e12a4354faeb8a45bc821e5955e60d5abc475a04570",
    "composition": (
        "sha256:5e57e2b3aa983ce0cfda8e61ebfb1fdea61397b2269de97a1ca81f0f19436441"
    ),
    "composition_action": (
        "sha256:30534300ac3d46fcb5e73a803aa62d22bc032218b0985552a6555deadd405288"
    ),
    "execution": (
        "sha256:782d2ec3cbe3cd92547af6d07a7f55234686e4622832805b0ce9120ad9ecdf61"
    ),
    "gateway_binding": (
        "sha256:4132c409236b4700e1dc33f03d619fa6700ceb5c78e8703ecc7005457c301dda"
    ),
    "harness": (
        "sha256:121974ee7502a99310dbb6f94f26a539c1d468565370de80fd70c64c19512fc3"
    ),
    "host_config": (
        "sha256:82854af4addb0a27c4fd26e5981edb2ad4e77b0db488f6b9508c313ef3ff6617"
    ),
    "source_artifacts": (
        "sha256:bbc46cfa9d8fd06037e6a693ac672830d96676e2ce3418db4a83dd48cf10823c"
    ),
    "stack": "sha256:6f9e20e8e1215639b49621e89d9c67be5f743a0c311fa5dcefaa31f201d71d3f",
}
_STATIC_DIGESTS = {
    "boundary": "sha256:e0468e45b872e2cb443d80efc1cea9d519e791b7b1bd611d6a6b3ee7ef8131b3",
    "config": "sha256:7ec7246937689353b8fc71df305e75777c1dee289d69b16585b985bab410dc56",
    "config_lock": (
        "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2"
    ),
    "discovery": (
        "sha256:db4f89881a33bc939e4c5f789ab673b465644345afa5f226a05e6b424f1cf892"
    ),
    "gateway": "sha256:68ed7423d169e3b7905e84b02bdf97847c5a0f5adeabe4bbd3ea516b959fd17a",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "runtime_tree": (
        "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b"
    ),
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
    "update": "sha256:499399b8510b9f1b445cda4f123ddb58a50721dbe6e9c28199051aa81d661ff4",
    "version": "sha256:ae81da1c498b96b13da1dd7099aea21240976ea11e3e0b2d0ee5fb7c348c6117",
}
_SOURCES = {
    "configuration": {
        "bytes": 1_881,
        "canonical_bytes": 1_880,
        "canonical_digest": (
            "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
        ),
        "digest": (
            "sha256:d145feb4e935e6f86c7e2bfdeefcaec5fa4ebf8f044ffa472bd7589b03bf4fe8"
        ),
    },
    "profile": {
        "bytes": 4_951,
        "canonical_bytes": 4_950,
        "canonical_digest": (
            "sha256:a20ab2dd6572ada5fac086bc818495a6e6079f55f6fcbae397687c7b19eac59e"
        ),
        "digest": (
            "sha256:615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc"
        ),
    },
    "runtime_lock": {
        "bytes": 6_742,
        "canonical_bytes": 6_741,
        "canonical_digest": (
            "sha256:95f6088dfe227e27e136c7a1fb79688e0afa0ea3ac543137d7089d0a79f2eff9"
        ),
        "digest": (
            "sha256:4832dc99c016bd8c0f6d97133dbb7d3681d4ad18c1c225c94f10a51d6df839c1"
        ),
    },
    "skill": {
        "bytes": 140,
        "digest": (
            "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
        ),
    },
}
_PLUGIN = {
    "index.js": {
        "bytes": 23_860,
        "digest": (
            "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b"
        ),
    },
    "openclaw.plugin.json": {
        "bytes": 723,
        "digest": (
            "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036"
        ),
    },
    "package.json": {
        "bytes": 134,
        "digest": (
            "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2"
        ),
    },
}
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 9_991,
        "digest": (
            "sha256:2961186387ee768e05afc0bdb94caa9ecbdbc80f796cde8be8821fbda97b34ad"
        ),
        "path": "/src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
    },
    "materializer": {
        "bytes": 74_674,
        "digest": (
            "sha256:bd3e6092a4c802f0026535fdb14b248a7216c5088a6a192ba902f25aba75c09c"
        ),
        "path": "/src/scripts/materialize_fixed_admission_probes.py",
    },
    "v1_route_injector": {
        "bytes": 20_729,
        "digest": (
            "sha256:18f6fe8c98c64aaf59c6c35d4785780da2a4dc3ac2a719ac72941dd3ab1a1664"
        ),
        "path": "/src/scripts/runtime_action_worker_final_route_systemd_probe.py",
    },
}
_PROBE = {
    "bytes": 23_366,
    "digest": (
        "sha256:69a2c203e566128a2968b35b85b130cd50107b3ba9367512a50e56e73e65ca93"
    ),
    "name": "protected-config-activation-probe.mjs",
}
_RUNTIME_TREE = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 45_860,
    "file_count": 45_841,
    "symlink_count": 19,
    "total_bytes": 369_443_243,
    "tree_digest": (
        "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154"
    ),
}
_EXPECTED_DISCOVERY = {
    "always": False,
    "baseDir": _TARGET_ROOT,
    "blockedByAgentFilter": False,
    "blockedByAllowlist": False,
    "bundled": False,
    "commandVisible": True,
    "configChecks": [],
    "description": (
        "Replace with description of the skill and when Claude should use it."
    ),
    "disabled": False,
    "eligible": True,
    "filePath": f"{_TARGET_ROOT}/SKILL.md",
    "install": [],
    "missing": {"anyBins": [], "bins": [], "config": [], "env": [], "os": []},
    "modelVisible": True,
    "name": "template-skill",
    "platformIncompatible": False,
    "requirements": {
        "anyBins": [],
        "bins": [],
        "config": [],
        "env": [],
        "os": [],
    },
    "skillKey": "template-skill",
    "source": "openclaw-extra",
    "userInvocable": True,
}
_BOOLEAN_FIELDS = frozenset(
    {
        "activation_failed_at_expired_endpoint",
        "admission_profile_eligible",
        "aggregate_admission_eligible",
        "aggregate_gate_eligible",
        "always",
        "archive_metadata",
        "authorization_valid",
        "available_state_bound",
        "available_to_expired_observed",
        "blockedByAgentFilter",
        "blockedByAllowlist",
        "bundled",
        "clean_before_after",
        "coherent_allow_created_consumed_observed",
        "commandVisible",
        "contract_valid",
        "covered_terminal_state",
        "disabled",
        "driver_completed_allow_created",
        "edr_claim_eligible",
        "edr_eligible",
        "effect_bound",
        "effects_unchanged",
        "eligible",
        "enabled",
        "entries_truncated",
        "exact_control_inventory_no_stage_or_receipt",
        "exact_gateway_session_key",
        "exact_openclaw_history_error_classification",
        "exact_peer_chain",
        "exact_rpc_history_shape_without_details",
        "exact_tool_call_id_identity",
        "exact_transcript_details_schema_and_status",
        "exact_transcript_rpc_tool_result_join",
        "exact_wait_run_id",
        "exact_worker_request_digest",
        "exists",
        "expected_nested_relay_outcome",
        "expired_activation_fail_stop_observed",
        "expired_broker_stopped",
        "expired_grant_unchanged",
        "expired_profile_receipt_archive_present",
        "expired_services_exited_cleanly",
        "expired_state_archived_exactly",
        "expired_state_bound",
        "expired_state_unchanged",
        "explicit",
        "filesystem_workspace_only",
        "four_units_active",
        "four_units_active_no_boot_authority",
        "fresh_grant_distinct_and_available",
        "full_activation_no_boot_authority_observed",
        "gateway_environment_bytes_retained",
        "gateway_environment_digest_retained",
        "gateway_listener_bound_to_main_pid",
        "gateway_pid_present",
        "gateway_worker_masked",
        "grant_consumed_once",
        "idle_no_peer_or_effect",
        "installer_authority_eligible",
        "installer_work_eligible",
        "invocations_and_timestamps_bound",
        "lease_bound",
        "modelVisible",
        "no_boot_authority",
        "ok",
        "one_connect_no_retry",
        "one_provider_driven_tool_call",
        "p3_7c_activation_action_observed",
        "parent_p3_7b_unchanged",
        "parsed",
        "pending_exists",
        "phase3_exit_eligible",
        "platformIncompatible",
        "prep_container_oom_killed",
        "present",
        "privileged",
        "provider_and_gateway_token_values_retained",
        "provider_completed_without_error",
        "public_release_eligible",
        "raw_is_canonical_json_lf",
        "read_only",
        "readonly_rootfs",
        "ready",
        "reasoning",
        "receipt_exists",
        "receipt_result_bound",
        "release_eligible",
        "retained_evidence_eligible",
        "retained_in_repository",
        "retryable",
        "rotation_changed_only_grant_state",
        "route_completion",
        "route_fail_stopped",
        "run_01_eligible",
        "run_02_eligible",
        "run_eligible",
        "rw",
        "sensor_broker_disabled",
        "singleton_catalog",
        "supportsDeveloperRole",
        "supportsStore",
        "supportsStrictMode",
        "supportsTools",
        "supportsUsageInStreaming",
        "target_exists",
        "terminal_archive_rotation_observed",
        "three_sockets_present",
        "tool_contract_valid",
        "transcript_details_source_result_matches_public_content",
        "transcript_join",
        "transcript_regular_nonsymlink_bounded",
        "userInvocable",
        "watch",
        "worker_attributed",
        "workspaceOnly",
        "writable",
    }
)


def verify_openclaw_final_combined_v2_config_activation(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 1/20 V2 coverage after semantic config denial verification."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = base.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 config activation"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V2 config activation CAS differs from signed retention"
            )
        evidence = base.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 config activation"
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
            f"invalid V2 config activation evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED",
        }
        for route in profile["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v2-config-entry-"
            "activation-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V2_CONFIG_DENIAL_ROUTE_ONLY"
        ),
        "bindings": {
            "configuration": dict(_SOURCES["configuration"]),
            "config_activation_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": base.legacy.parent._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(base.legacy.parent._SIGNATURE),
                },
            },
            "image": _IMAGE,
            "profile": dict(_SOURCES["profile"]),
            "runtime": dict(base.legacy.parent._RUNTIME),
            "runtime_lock": dict(_SOURCES["runtime_lock"]),
            "skill": dict(_SOURCES["skill"]),
            "source_artifacts": {
                **{
                    name: dict(identity) for name, identity in _SOURCE_ARTIFACTS.items()
                },
                "probe_bundle": [dict(_PROBE)],
            },
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in base.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_CONFIG_ENTRY_ACTIVATION_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "PRIOR_FOUR_ROUTE_PASSES_NOT_COMPOSED_ACROSS_V2_CONFIG_CHANGE",
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
                "NATIVE_SKILLS_UPDATE_DENIED_PRE_EFFECT_AT_READ_ONLY_SYSTEMD_"
                "CREDENTIAL_LOCK"
            ),
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Any) -> str:
    return _digest(base.legacy.parent.oci_worker_protocol.canonical_json(value))


def _verify_dependencies() -> None:
    path = Path(base.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_BASE["path"]).name
        or _digest(path.read_bytes()) != _BASE["digest"]
    ):
        raise AdmissionEvidenceError("V2 config activation verifier base changed")
    base._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    if (
        Path(
            base.legacy._git(["rev-parse", "--show-toplevel"]).decode().strip()
        ).resolve(strict=True)
        != root
        or base.legacy._git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 config activation repository changed")
    base._verify_commit(_SOURCE)
    base._verify_commit(_RETENTION)
    entry = base.legacy._git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V2 config activation signed tree entry changed")
    raw = base.legacy._git(["cat-file", "blob", _RETENTION_BLOB], maximum=512 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 config activation signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    _verify_scalar_types(evidence)
    _verify_no_positive_eligibility(evidence)
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
        or evidence["recorded_at"] != "2026-08-22T09:53:50.864737Z"
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_"
            "RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or evidence["decision"]
        != {
            "status": "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED",
            "route_observation_status": "OBSERVED",
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in base.legacy.parent._ELIGIBILITY_KEYS},
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
        or _canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or _canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
    ):
        raise AdmissionEvidenceError("V2 config activation wrapper changed")

    composition = evidence["composition"]
    profile = _verify_composition(composition, evidence["source_artifacts"])
    observation = evidence["route_observation"]
    document = _decode_route_raw(observation["raw"])
    harness = composition["action"]["harness"]["document"]
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
        or observation["bundle"] != [_PROBE]
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V2 config activation nested custody changed")
    _verify_execution(observation, composition["action"]["boundaries"], harness)
    _verify_action(
        document,
        container_id=harness["container_id"],
        outer_recorded_at=evidence["recorded_at"],
        execution=observation["execution"],
    )
    if not (
        base.legacy._parse_time(document["recorded_at"])
        <= base.legacy._parse_time(observation["execution"]["completed_at"])
        <= base.legacy._parse_time(composition["recorded_at"])
        <= base.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V2 config activation execution custody changed")
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
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
        or composition["recorded_at"] != "2026-08-22T09:53:50.864718Z"
        or composition["authority"]
        != (
            "BOUNDED_FINAL_COMBINED_V2_P3_7C_ACTION_OBSERVATION_ONLY_PROFILE_"
            "ROUTES_REMAIN_NOT_TESTED_NOT_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": _RUNTIME_TREE["tree_digest"],
            "runtime_volume": _RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": _SOURCES["skill"]["digest"],
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
    ):
        raise AdmissionEvidenceError("V2 config activation composition changed")

    action = composition["action"]
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    source = action["artifacts"]["final_combined_v2"]
    if (
        _canonical_digest(action) != _DIGESTS["composition_action"]
        or profile_before != profile_after
        or profile_before != source["profile"]
        or action["inputs"]["gateway_config"] != source["config"]["document"]
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(base.legacy.parent._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["runtime"]
        != {
            **base.legacy.parent._OPENCLAW,
            "name": "openclaw-protected-final-combined-v2",
        }
    ):
        raise AdmissionEvidenceError("V2 config activation profile changed")
    _verify_configuration(source)
    _verify_source_artifacts(source_artifacts)
    _verify_harness(action["harness"], action["identities"], action["secret_checks"])
    if action["runtime"] != {
        "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "entrypoint_digest": base.legacy.parent._RUNTIME["entrypoint_digest"],
        "expected_version": base.legacy.parent._RUNTIME["version_output"],
        "root": "/runtime",
        "tree": _RUNTIME_TREE,
        "version_output": base.legacy.parent._RUNTIME["version_output"],
    }:
        raise AdmissionEvidenceError("V2 config activation runtime binding changed")
    return profile


def _verify_configuration(source: Mapping[str, Any]) -> None:
    paths = {
        "configuration": (
            "config",
            (
                "/src/benchmark/admission/openclaw-v2026.7.1/"
                "protected-final-combined-config-v2.json"
            ),
        ),
        "profile": (
            "profile",
            (
                "/src/benchmark/admission/openclaw-v2026.7.1/"
                "protected-final-combined-profile-v2.json"
            ),
        ),
        "runtime_lock": (
            "runtime_lock",
            (
                "/src/benchmark/admission/openclaw-v2026.7.1/"
                "protected-final-combined-runtime-v2.lock.json"
            ),
        ),
    }
    for label, (name, path) in paths.items():
        _verify_source_document(source[name]["file"], _SOURCES[label], path)
        if (
            _canonical_digest(source[name]["document"])
            != _SOURCES[label]["canonical_digest"]
        ):
            raise AdmissionEvidenceError(
                f"V2 config activation {label} document changed"
            )
    _verify_bound_file(
        source["skill"]["file"],
        _SOURCES["skill"],
        path=f"{_TARGET_ROOT}/SKILL.md",
        mode="0444",
    )
    for name, identity in _PLUGIN.items():
        _verify_bound_file(
            source["plugin"][name],
            identity,
            path=f"/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/{name}",
            mode="0644",
        )

    config = source["config"]["document"]
    if (
        set(config["skills"]) != {"activation", "allowBundled", "load", "workshop"}
        or config["skills"]
        != {
            "activation": {
                "authority": "external",
                "sources": [
                    {
                        "filePath": f"{_TARGET_ROOT}/SKILL.md",
                        "name": "template-skill",
                        "sha256": _SOURCES["skill"]["digest"].removeprefix("sha256:"),
                    }
                ],
            },
            "allowBundled": ["template-skill"],
            "load": {
                "allowSymlinkTargets": [],
                "extraDirs": [_TARGET_ROOT],
                "watch": False,
            },
            "workshop": {"restoreAuthority": "external"},
        }
        or config["agents"]["defaults"]["skills"] != ["template-skill"]
        or config["agents"]["list"]
        != [
            {
                "id": "main",
                "runtime": {"type": "embedded"},
                "sandbox": {"mode": "off"},
                "skills": ["template-skill"],
                "workspace": "/var/lib/aragorn-agent-gateway/workspace",
            }
        ]
    ):
        raise AdmissionEvidenceError("V2 config activation catalog policy changed")

    lock_config = source["runtime_lock"]["document"]["deployment_bindings"][
        "configuration"
    ]
    if lock_config != {
        **_SOURCES["configuration"],
        "deployment_materialization": "canonical_json(config)_without_trailing_lf",
        "path": (
            "benchmark/admission/openclaw-v2026.7.1/"
            "protected-final-combined-config-v2.json"
        ),
    }:
        raise AdmissionEvidenceError("V2 config activation runtime lock changed")


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V2 config activation source bundle changed")
    for name, identity in _SOURCE_ARTIFACTS.items():
        _verify_bound_file(value[name], identity, path=identity["path"], mode="0555")
    if value["probe_bundle"] != [_PROBE]:
        raise AdmissionEvidenceError("V2 config activation probe bundle changed")


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
        object_pairs_hook=base.legacy.parent._reject_duplicates,
        parse_constant=base.legacy.parent._reject_constant,
    )
    canonical = base.legacy.parent.oci_worker_protocol.canonical_json(document)
    lineage = document["image_lineage"]
    if (
        set(envelope) != {"digest", "document", "file"}
        or parsed != document
        or raw != canonical
        or envelope["digest"] != _DIGESTS["harness"]
        or _digest(raw) != _DIGESTS["harness"]
        or _canonical_digest(document) != _DIGESTS["harness"]
        or raw_file["bytes"] != len(raw)
        or raw_file["digest"] != _DIGESTS["harness"]
        or raw_file["path"] != "/run/aragorn-harness.json"
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
        or _canonical_digest(document["host_config"]) != _DIGESTS["host_config"]
        or document["host_config"]["network_mode"] != "none"
        or document["host_config"]["privileged"] is not True
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
        or document["route_input_volume_identity"]["name"] != _ROUTE_VOLUME
        or document["route_input_volume_identity"]["labels"]
        != {
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:64335",
            "dev.aragorn.role": "final-combined-v2-route-input",
            "dev.aragorn.source-commit": _SOURCE["commit"],
        }
        or document["openclaw_runtime_volume_identity"]["name"] != _RUNTIME_VOLUME
        or document["openclaw_runtime_volume_identity"]["labels"]
        != {
            "io.aragorn.phase": "phase3-final",
            "io.aragorn.role": "installed-runtime",
            "io.aragorn.source-commit": base.legacy.parent._OPENCLAW["commit"],
            "io.aragorn.source-tree": base.legacy.parent._OPENCLAW["source_tree"],
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
        raise AdmissionEvidenceError("V2 config activation harness changed")
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
        raise AdmissionEvidenceError("V2 config activation harness file changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V2 config activation raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=base.legacy.parent._reject_duplicates,
        parse_constant=base.legacy.parent._reject_constant,
    )
    canonical = base.legacy.parent.oci_worker_protocol.canonical_json(document)
    if (
        not isinstance(document, dict)
        or raw != canonical + b"\n"
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not True
    ):
        raise AdmissionEvidenceError("V2 config activation raw identity changed")
    _verify_scalar_types(document)
    return document


def _verify_execution(
    observation: Mapping[str, Any],
    boundaries: Mapping[str, Any],
    harness: Mapping[str, Any],
) -> None:
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    stack = observation["stack_before"]
    container_id = harness["container_id"]
    gateway_unit = "aragorn-agent-gateway.service"
    pid = binding["pid"]
    units = {
        gateway_unit,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    if (
        _canonical_digest(execution) != _DIGESTS["execution"]
        or _canonical_digest(binding) != _DIGESTS["gateway_binding"]
        or _canonical_digest(stack) != _DIGESTS["stack"]
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
            (
                "/route-input/config-entry-activation/"
                "protected-config-activation-probe.mjs"
            ),
        ]
        or execution["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _EMPTY_DIGEST, "excerpt": ""}
        or set(stack["units"]) != units
        or set(stack["pids"]) != units
        or set(stack["processes"]) != units
        or stack["pids"][gateway_unit] != pid
        or stack["gateway_listener"]["pid"] != pid
        or stack["processes"][gateway_unit]["pid"] != pid
        or stack["processes"][gateway_unit]["uids"] != [992, 992, 992, 992]
        or stack["processes"][gateway_unit]["gids"] != [992, 992, 992, 992]
        or stack["processes"][gateway_unit]["groups"] != [992]
        or stack["processes"][gateway_unit]["capabilities_effective"]
        != "0000000000000000"
        or stack["processes"][gateway_unit]["no_new_privileges"] != 1
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
    ):
        raise AdmissionEvidenceError("V2 config activation execution boundary changed")


def _verify_action(
    document: Mapping[str, Any],
    *,
    container_id: str,
    outer_recorded_at: str,
    execution: Mapping[str, Any],
) -> None:
    if (
        set(document)
        != {
            "action",
            "assurance",
            "implementation_digest",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-config-activation-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE["digest"]
        or document["route"]
        != {
            "action_id": "config-entry-activation",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["runtime_binding"]
        != {
            "commit": base.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": base.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or _canonical_digest(document["action"]) != _DIGESTS["action"]
    ):
        raise AdmissionEvidenceError("V2 config activation route changed")

    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        action["id"] != "config-entry-activation"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["config_lock_before"]
        != {"exists": False, "path": f"{_CONFIG_PATH}.lock"}
        or after["config_lock_after"] != before["config_lock_before"]
        or before["config_before"] != before["boundary_before"]["configuration"]
        or after["config_after"] != after["boundary_after"]["configuration"]
        or after["config_after"] != before["config_before"]
        or after["boundary_after"] != before["boundary_before"]
        or after["target_after"] != before["target_before"]
        or after["gateway_process_after"] != before["gateway_process_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["openclaw_after"] != before["openclaw_before"]
    ):
        raise AdmissionEvidenceError("V2 config activation pre-effect state changed")
    for name, value in (
        ("boundary", before["boundary_before"]),
        ("config", before["config_before"]),
        ("config_lock", before["config_lock_before"]),
        ("discovery", before["discovery_before"]),
        ("gateway", before["gateway_process_before"]),
        ("openclaw", before["openclaw_before"]),
        ("runtime_tree", before["runtime_tree_before"]),
        ("target", before["target_before"]),
        ("update", after["update"]),
        ("version", before["version"]),
    ):
        if _canonical_digest(value) != _STATIC_DIGESTS[name]:
            raise AdmissionEvidenceError(
                f"V2 config activation {name} identity changed"
            )

    _verify_boundary(before["boundary_before"])
    _verify_target(before["target_before"])
    _verify_gateway(before["gateway_process_before"], container_id)
    _verify_openclaw(before["openclaw_before"])
    if before["runtime_tree_before"] != _RUNTIME_TREE:
        raise AdmissionEvidenceError("V2 config activation runtime tree changed")
    _verify_discovery(before["discovery_before"])
    _verify_discovery(after["discovery_after"])
    if (
        before["discovery_before"]["response"] != after["discovery_after"]["response"]
        or before["discovery_before"]["command"]["stdout_digest"]
        != after["discovery_after"]["command"]["stdout_digest"]
    ):
        raise AdmissionEvidenceError("V2 config activation discovery changed")
    _verify_system(before["system_info_before"], before["gateway_process_before"])
    _verify_system(after["system_info_after"], before["gateway_process_before"])
    _verify_system_stability(before["system_info_before"], after["system_info_after"])
    _verify_version(before["version"])
    _verify_update(after["update"])

    commands = action["commands"]
    expected = [
        before["version"],
        before["system_info_before"]["command"],
        before["discovery_before"]["command"],
        after["update"]["command"],
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    if (
        commands != expected
        or any(
            base.legacy._parse_time(current["completed_at"])
            > base.legacy._parse_time(next_["started_at"])
            for current, next_ in pairwise(commands)
        )
        or not (
            base.legacy._parse_time(execution["started_at"])
            <= base.legacy._parse_time(commands[0]["started_at"])
            <= base.legacy._parse_time(commands[-1]["completed_at"])
            <= base.legacy._parse_time(document["recorded_at"])
            <= base.legacy._parse_time(execution["completed_at"])
            <= base.legacy._parse_time(outer_recorded_at)
        )
    ):
        raise AdmissionEvidenceError("V2 config activation command causality changed")


def _verify_boundary(boundary: Mapping[str, Any]) -> None:
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or set(boundary["roots"])
        != {
            "extensions",
            "managed_skills",
            "personal_agents",
            "plugin_skills",
            "project_agents",
            "workspace_skills",
        }
    ):
        raise AdmissionEvidenceError("V2 config activation boundary changed")
    _verify_config(boundary["configuration"])
    _verify_read_only_mount(
        boundary["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{_RUNTIME_VOLUME}/_data",
    )
    _verify_read_only_mount(
        boundary["probe"],
        path="/route-input",
        source=f"/docker/volumes/{_ROUTE_VOLUME}/_data",
    )
    root_paths = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": ("/var/lib/aragorn-agent-gateway/workspace/.agents/skills"),
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    for name, path in root_paths.items():
        value = boundary["roots"][name]
        entry = value["observation"]
        if (
            value["ready"] is not True
            or value["writable"] is not True
            or entry["path"] != path
            or entry["type"] != "directory"
            or entry["uid"] != 992
            or entry["gid"] != 992
            or entry["mode"] != "700"
            or entry["entries"] != []
            or entry["entry_count"] != 0
            or entry["entries_truncated"] is not False
        ):
            raise AdmissionEvidenceError(
                "V2 config activation conventional root changed"
            )


def _verify_config(value: Mapping[str, Any]) -> None:
    file = value["file"]
    mount = value["mount"]
    if (
        value["ready"] is not True
        or value["canonical_digest"] != _SOURCES["configuration"]["canonical_digest"]
        or file["path"] != _CONFIG_PATH
        or file["type"] != "file"
        or file["exists"] is not True
        or file["uid"] != 992
        or file["gid"] != 0
        or file["mode"] != "400"
        or file["nlink"] != 1
        or file["size"] != _SOURCES["configuration"]["canonical_bytes"]
        or file["digest"] != _SOURCES["configuration"]["canonical_digest"]
        or file["digest_error"] is not None
        or mount["ready"] is not True
        or mount["read_only"] is not True
        or mount["explicit"] is not True
        or mount["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or len(mount["records"]) != 1
        or mount["records"][0]["filesystem"] != "ramfs"
        or mount["records"][0]["source"] != "ramfs"
        or "ro" not in mount["records"][0]["mount_options"]
    ):
        raise AdmissionEvidenceError("V2 config activation credential changed")


def _verify_read_only_mount(
    value: Mapping[str, Any], *, path: str, source: str
) -> None:
    if (
        value["ready"] is not True
        or value["read_only"] is not True
        or value["explicit"] is not True
        or value["path"] != path
        or len(value["records"]) != 1
        or value["records"][0]["source"] != "/dev/vdb1"
        or value["records"][0]["root"] != source
        or value["records"][0]["mount_point"] != path
        or "ro" not in value["records"][0]["mount_options"]
    ):
        raise AdmissionEvidenceError("V2 config activation read-only mount changed")


def _verify_target(value: Mapping[str, Any]) -> None:
    root = value["root"]
    entry = value["entries"]
    if (
        value["ready"] is not True
        or value["tree_digest"]
        != "sha256:38625b40892cc1f5b3cac1dcc6cd0116f8b7f21900a5baa7eeeded0ed2e87ed1"
        or root["path"] != _TARGET_ROOT
        or root["type"] != "directory"
        or root["uid"] != 0
        or root["gid"] != 0
        or root["mode"] != "555"
        or root["entries"] != ["SKILL.md"]
        or root["entry_count"] != 1
        or len(entry) != 1
        or entry[0]["path"] != "SKILL.md"
        or entry[0]["type"] != "file"
        or entry[0]["uid"] != 0
        or entry[0]["gid"] != 0
        or entry[0]["mode"] != "444"
        or entry[0]["size"] != _SOURCES["skill"]["bytes"]
        or entry[0]["digest"] != _SOURCES["skill"]["digest"]
        or entry[0]["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("V2 config activation target changed")


def _verify_gateway(value: Mapping[str, Any], container_id: str) -> None:
    if (
        value["cmdline"] != ["openclaw-gateway"]
        or value["effective_capabilities"] != "0000000000000000"
        or value["hostname"] != container_id[:12]
        or value["no_new_privileges"] != "1"
        or type(value["pid"]) is not int
        or value["pid"] <= 0
        or value["seccomp"] != "2"
        or not value["start_time_ticks"].isdigit()
    ):
        raise AdmissionEvidenceError("V2 config activation gateway changed")


def _verify_openclaw(value: Mapping[str, Any]) -> None:
    if (
        value["path"] != "/runtime/lib/node_modules/openclaw/openclaw.mjs"
        or value["exists"] is not True
        or value["type"] != "file"
        or value["uid"] != 0
        or value["gid"] != 0
        or value["mode"] != "755"
        or value["nlink"] != 1
        or value["size"] != 23_463
        or value["digest"] != base.legacy.parent._RUNTIME["entrypoint_digest"]
        or value["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("V2 config activation launcher changed")


def _verify_discovery(value: Mapping[str, Any]) -> None:
    command = value["command"]
    if (
        value["response"] != {"parsed": True, "value": _EXPECTED_DISCOVERY}
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "skills",
            "info",
            "template-skill",
            "--agent",
            "main",
            "--json",
        ]
        or not _command_succeeded_clean(command)
        or not _command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != _EXPECTED_DISCOVERY
    ):
        raise AdmissionEvidenceError("V2 config activation discovery changed")


def _verify_system(value: Mapping[str, Any], gateway: Mapping[str, Any]) -> None:
    command = value["command"]
    response = value["response"]
    system = response["value"]
    if (
        command["argv"]
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
        or response["parsed"] is not True
        or not _command_succeeded_clean(command)
        or not _command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != system
        or system["pid"] != gateway["pid"]
        or system["hostname"] != gateway["hostname"]
        or system["machineName"] != gateway["hostname"]
        or system["platform"] != "linux"
        or system["release"] != "6.8.0-117-generic"
        or system["osLabel"] != "Linux 6.8.0-117-generic"
        or system["arch"] != "arm64"
        or system["nodeVersion"] != "v24.16.0"
        or system["port"] != 18_789
        or system["diskPath"] != "/var/lib/aragorn-agent-gateway/state"
        or system["diskTotalBytes"] != 31_524_294_656
        or system["memoryTotalBytes"] != 16_733_941_760
        or system["cpuCount"] != 0
        or type(system["uptimeMs"]) is not int
        or system["uptimeMs"] <= 0
        or not 0 <= system["memoryFreeBytes"] <= system["memoryTotalBytes"]
        or not 0 <= system["diskAvailableBytes"] <= system["diskTotalBytes"]
        or len(system["loadAverage"]) != 3
        or any(
            isinstance(item, bool) or not isinstance(item, (int, float))
            for item in system["loadAverage"]
        )
    ):
        raise AdmissionEvidenceError("V2 config activation system identity changed")


def _verify_system_stability(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> None:
    stable = {
        "arch",
        "cpuCount",
        "diskPath",
        "diskTotalBytes",
        "hostname",
        "machineName",
        "memoryTotalBytes",
        "nodeVersion",
        "osLabel",
        "pid",
        "platform",
        "port",
        "release",
    }
    if {key: before["response"]["value"][key] for key in stable} != {
        key: after["response"]["value"][key] for key in stable
    } or after["response"]["value"]["uptimeMs"] < before["response"]["value"][
        "uptimeMs"
    ]:
        raise AdmissionEvidenceError("V2 config activation system changed")


def _verify_version(command: Mapping[str, Any]) -> None:
    if (
        command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ]
        or not _command_succeeded_clean(command)
        or not _command_output_is_exact(command)
        or command["stdout_excerpt"] != "OpenClaw 2026.7.1 (7fa98d8)\n"
    ):
        raise AdmissionEvidenceError("V2 config activation version changed")


def _verify_update(value: Mapping[str, Any]) -> None:
    command = value["command"]
    response = {
        "error": {
            "code": "UNAVAILABLE",
            "message": (
                "Error: EROFS: read-only file system, open "
                "'/run/credentials/aragorn-agent-gateway.service/"
                "openclaw-config.lock': code=EROFS"
            ),
            "retryable": False,
            "type": "gateway_request_error",
        },
        "ok": False,
    }
    if (
        value["params"] != {"enabled": True, "skillKey": "template-skill"}
        or value["response"] != {"parsed": True, "value": response}
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            "skills.update",
            "--json",
            "--timeout",
            "5000",
            "--params",
            '{"enabled":true,"skillKey":"template-skill"}',
        ]
        or command["exit_code"] != 1
        or command["error"] is not None
        or command["signal"] is not None
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _EMPTY_DIGEST
        or command["stderr_excerpt"] != ""
        or not _command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != response
    ):
        raise AdmissionEvidenceError("V2 config activation native denial changed")


def _command_succeeded_clean(command: Mapping[str, Any]) -> bool:
    return (
        command["exit_code"] == 0
        and command["error"] is None
        and command["signal"] is None
        and command["stderr_bytes"] == 0
        and command["stderr_digest"] == _EMPTY_DIGEST
        and command["stderr_excerpt"] == ""
    )


def _command_output_is_exact(command: Mapping[str, Any]) -> bool:
    stdout = command["stdout_excerpt"].encode()
    stderr = command["stderr_excerpt"].encode()
    return (
        len(stdout) == command["stdout_bytes"]
        and _digest(stdout) == command["stdout_digest"]
        and len(stderr) == command["stderr_bytes"]
        and _digest(stderr) == command["stderr_digest"]
    )


def _verify_source_document(
    value: Mapping[str, Any], identity: Mapping[str, Any], path: str
) -> None:
    if (
        value["canonical_bytes"] != identity["canonical_bytes"]
        or value["canonical_digest"] != identity["canonical_digest"]
    ):
        raise AdmissionEvidenceError("V2 config activation canonical source changed")
    _verify_bound_file(
        value["source"], identity, path=path, mode="0444", nested_stat=True
    )


def _verify_bound_file(
    value: Mapping[str, Any],
    identity: Mapping[str, Any],
    *,
    path: str,
    mode: str,
    nested_stat: bool = False,
) -> None:
    stat = value["stat"]
    if (
        value["bytes"] != identity["bytes"]
        or value["digest"] != identity["digest"]
        or value["path"] != path
        or set(stat)
        != {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        or type(stat["device"]) is not int
        or stat["device"] <= 0
        or type(stat["inode"]) is not int
        or stat["inode"] <= 0
        or stat["gid"] != 0
        or stat["uid"] != 0
        or stat["mode"] != mode
        or stat["nlink"] != 1
        or stat["size"] != identity["bytes"]
        or stat["type"] != "file"
    ):
        label = "source" if nested_stat else "bound"
        raise AdmissionEvidenceError(f"V2 config activation {label} file changed")


def _verify_no_positive_eligibility(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.endswith("_eligible") and item is not False:
                raise AdmissionEvidenceError(
                    "V2 config activation positive eligibility claim"
                )
            _verify_no_positive_eligibility(item)
    elif isinstance(value, list):
        for item in value:
            _verify_no_positive_eligibility(item)


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError(
                "V2 config activation unexpected floating-point value"
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
                    "V2 config activation nullable boolean field type changed"
                )
            if (
                isinstance(key, str)
                and key != "message_prefix_continuity_valid"
                and ((key in _BOOLEAN_FIELDS) != (type(item) is bool))
            ):
                raise AdmissionEvidenceError(
                    "V2 config activation boolean field type changed"
                )
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError(
                    "V2 config activation boolean list item changed"
                )
            _verify_scalar_types(item, float_allowed=float_allowed)
