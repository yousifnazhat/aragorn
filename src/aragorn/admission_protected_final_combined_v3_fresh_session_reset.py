"""Qualify one exact current-V3 fresh-session reset route."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import runpy
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_config_activation as contract
from . import (
    admission_protected_final_combined_v3_config_entry_activation as v3_contract,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

old = contract.base

_ROUTE = "ADM-02/reload/fresh-session-reset"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_CONFIG_PATH = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v3-fresh-session-reset-route-input-90944"
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
_SESSION_KEY = "agent:main:aragorn-protected-routes-v1"
_NETWORK_ERROR = (
    "⚠️ Agent failed before reply: LLM request failed: network connection error.\n"
    "Logs: openclaw logs --follow"
)
_BASE = {
    "bytes": 57_245,
    "digest": "sha256:41a5c8e274b7f22e4cc79bde03917aea6717a83b3f810803d075e39c4b2afb5e",
    "path": "src/aragorn/admission_protected_final_combined_v3_config_entry_activation.py",
}
_SEMANTIC_BASE = {
    "bytes": 58_642,
    "digest": "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6",
    "path": "src/aragorn/admission_protected_final_combined_v2_config_activation.py",
}
_EVIDENCE = {
    "bytes": 494_420,
    "canonical_bytes": 494_419,
    "canonical_digest": "sha256:a8b62b5e9ef91e816711844c35f9b7c9e73de1f873aeddd62b2e7682c198b642",
    "digest": "sha256:e00b5dc8596f93ec1cdaa3170055e0c98915bb5c26b479e0022c471cfcca80de",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
        "fresh-session-reset-systemd-p3-final-2026-08-28.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 25_070,
    "canonical_digest": "sha256:c2d6d8a6ba27f8c042adedb5a96087b6714cea73587d895b689b838d58645d00",
    "digest": "sha256:a8d41e7963f7b94fe93cd7f64286560fab1c223cd49f444b654db6c3811636b5",
}
_SOURCE = {
    "commit": "3796e0ddbfc9c0d5ba94a994af9b7d0eb274f8b1",
    "parent": "c823ae2ae05f3b919c2e391a6852b8f8bafa1046",
    "tree": "64ac9115ca54c4625b7a5e4bf660512325cf2328",
}
_RETENTION = {
    "commit": "c2c8a8d59c0c057ea12b55ac427df9006cd16550",
    "parent": _SOURCE["commit"],
    "tree": "1af3489104ec86a609c11dacebaf9ddb4b61fb3a",
}
_RETENTION_BLOB = "faefb908f1bb4e262aeec93d2e67cc544b6fa6a5"
_IMAGE = "sha256:4ef5151083554f1e60c6c182340c7ee98f0277ea29892695949b335a2ccc459f"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_PROBE = {
    "bytes": 44_825,
    "digest": "sha256:4687054e9d7ea264c6772de4e0560fafb195ebbbfc7397333297abd6cc4347ff",
    "name": "protected-route-probe.mjs",
}
_DIGESTS = {
    "action": "sha256:ffd81a7d314dbfce8e246d5bff3acb26469aefd21e52b02a8f63aab432985aea",
    "composition": "sha256:b28d2b5a5f10abaa04f4e398c500c9c4d99b8bf8a59427327e38d17198ecd9e9",
    "composition_action": "sha256:051397ea4c737e9a87f839d32a1786ec2451c1b5654afad911043c475b985b26",
    "execution": "sha256:7052206ff8c3e9705da594e7852c6b119791a2a330d78634329792fc74fb2666",
    "gateway_binding": "sha256:29d829307f524115d24e99b81de98ddc56c1f95fc792e0558b0877b73e0c199f",
    "harness": "sha256:895f46c43a93be0abb89367f445fbe15bcc9828fb6ed4e5846e062053d75a91e",
    "host_config": "sha256:fbcd69f1c519c242263cded26407f0815b8585edef5f50b6918a4e15756b3a16",
    "protected_boundary": "sha256:5940ab40190e411a4d62bf82fc5c17ee0459102af7818befac5a46251a6e628e",
    "route_observation": "sha256:ca1ae9be42c00bee7cb128e8c0ed22406b76a7466f729a7627436420b484f2fb",
    "source_artifacts": "sha256:6cc77a64c783665db87af482c121955fa1b7844e31bffc93c580bd538e2da506",
    "stack": "sha256:b1a87c34d0e66d03ac2318150c4045dacc2f6503e85353be244a52ea8146dc18",
}
_TYPE_SHAPE_DIGEST = (
    "sha256:4f2dddead39a0220551a93eced1f46f0e2de0e4c08bdf33002df7dec3d41dff8"
)
_ROUTE_TYPE_SHAPE_DIGEST = (
    "sha256:66a053abd1630e3bdb6ca07ec29fa59b8e8e471a52c455d043a0690d758500cf"
)
_SOURCE_ARTIFACTS = {
    "checked_in_probe": {
        "bytes": 34_185,
        "digest": "sha256:3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504",
        "mode": "0444",
        "path": "benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs",
    },
    "collector": {
        "bytes": 25_532,
        "digest": "sha256:467af8df703ca43e97e8b8158f2c085ffecdc5c6e37bff4ef257095d1178fd25",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe.py",
    },
    "inherited_combined_base": {
        "bytes": 30_093,
        "digest": "sha256:03fcf63cd6f68521e261ecb8dc558c2a906b59338ce96a20688098f2066dc550",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_combined_v2_systemd_probe.py",
    },
    "inherited_route_injector": {
        "bytes": 21_470,
        "digest": "sha256:50e96d42459a40d0a87ce2cdd215bace14072a626281a3fc733efb5b22831355",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_route_systemd_probe.py",
    },
    "inherited_v3_contract_base": {
        "bytes": 28_860,
        "digest": "sha256:c9e3e43e4d122575cc362e2ec73b2fc4b57d4ad465a1d49e4b94291d935217ad",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py",
    },
    "materialized_v2_probe": {
        "bytes": 44_825,
        "digest": "sha256:65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1",
        "mode": "0444",
        "path": "benchmark/admission/openclaw-v2026.7.1/protected-route-v2-probe.mjs",
    },
    "materializer": {
        "bytes": 87_912,
        "digest": "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
        "mode": "0555",
        "path": "scripts/materialize_fixed_admission_probes.py",
    },
    "transformed_probe": {
        "bytes": 44_825,
        "digest": "sha256:4687054e9d7ea264c6772de4e0560fafb195ebbbfc7397333297abd6cc4347ff",
        "mode": "0444",
        "path": "benchmark/admission/openclaw-v2026.7.1/protected-route-v3-probe.mjs",
    },
}
_SIGNED_SOURCE_ARTIFACTS = {
    "checked_in_probe",
    "collector",
    "inherited_combined_base",
    "inherited_route_injector",
    "inherited_v3_contract_base",
    "materializer",
}
_COLLECTOR_ARTIFACTS = {
    "capture_recipe": {
        "bytes": 27_135,
        "digest": "sha256:915fb92cb74fd5b00780594a77eee357615bf264c974ebd67356ac883008d592",
        "mode": "0555",
        "path": "scripts/capture_runtime_action_worker_final_combined_v3_fresh_session_reset_systemd.sh",
    },
    "dockerfile": {
        "bytes": 6_682,
        "digest": "sha256:1d4bdf0e0ce18a6095d5a399448487031e8f1402bca6f34e487995de55aa67d2",
        "mode": "0444",
        "path": "benchmark/runtime-action-worker-final-combined-v3-fresh-session-reset-systemd/Dockerfile",
    },
    "inherited_combined_base": _SOURCE_ARTIFACTS["inherited_combined_base"],
    "inherited_route_injector": _SOURCE_ARTIFACTS["inherited_route_injector"],
    "inherited_v3_contract_helpers": _SOURCE_ARTIFACTS["inherited_v3_contract_base"],
    "probe": _SOURCE_ARTIFACTS["collector"],
}
_ARTIFACT_DIGESTS = {
    "activator": "sha256:c43b088e0560d904509da9f2177a18c201034f3373ce368126cf46ebbc0e4995",
    "activator_source": "sha256:f14374921b839ed5f7f2b9f685de38e2cde18901620bcf77b80a1095b6e65359",
    "collector": "sha256:9ad6754470007390683ad3b6a853b2cf079b78c6e46e432fe5c8152beab1b65f",
    "config": "sha256:43ce7ebe7e7f0b9c4323008fc56d5377565d43043f03837aaf49dcd5ba7bf1ec",
    "fresh_session_reset_probe": "sha256:c2cf77f2eee9176c05a075025f188ade18b9d398cd3f3a774d852fbffb392594",
    "installed_runtime": "sha256:3280849f3efd4842debc217dfc6afd03b8cc2789b89de296429fd1c2629931ab",
    "plugin": "sha256:1d51828d474068eddbe47cc8827598c78c3805bce91738727222a24fffc7a8a2",
    "policy_command": "sha256:867e114d8b428e904fdf2bc4bfc6acdae62a8b1b24d547bb469eb6633157db57",
    "preflight": "sha256:b7915d91b88aede023e00b390c34e0e9e8b6bb4b0ac15e24dac3134c03f3261b",
    "preflight_source": "sha256:7e08ff975f31bf058a7376614526a002d3945171207144a698ee16876c5fecef",
    "profile": "sha256:50c00c78419386a691350f0eb7f89b392f34f50cb4fcb2ec4cccbd937fb20b8b",
    "runtime_lock": "sha256:fa35d8380a43bf83cc26ccb3d74cd413a284457a51223f2a9992cb4c55859494",
    "skill": "sha256:c5724cccc81b23ee8f436b6c4d496871dd0342f4fc43a00f4f3ca9eea1d36ea4",
}
_RAW_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
    "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "ONLY_FRESH_SESSION_RESET_ATTEMPT_OBSERVED",
    "NO_FRESH_SESSION_RESET_SUCCESS_SESSION_CONTINUITY_OR_MODEL_SUCCESS_CLAIM",
    "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
    "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
    "FRESH_SESSION_RESET_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_SESSION_STATE_EQUIVALENCE_CLEANUP_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
_BOOLEAN_FIELDS = contract._BOOLEAN_FIELDS | {
    "accepted",
    "catalog_exact",
    "confirmed",
    "deliver",
    "executable",
    "json_object",
    "prompt_exact",
    "rebuilt_snapshot_matches_baseline",
    "reset_snapshot_cleared",
    "session_id_rotated",
    "session_id_valid",
    "snapshot_present",
    "snapshot_version_valid",
}
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_READY = old._READY
_UUID4 = old._UUID4


def verify_openclaw_final_combined_v3_fresh_session_reset(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact dynamic current-V3 fresh-session reset PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = v3_contract.contract._read_blob(
            evidence_cas, _EVIDENCE, "V3 fresh-session reset"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 fresh-session reset CAS differs from signed retention"
            )
        evidence = v3_contract.contract._load_canonical_json(
            raw, _EVIDENCE, "V3 fresh-session reset"
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
            f"invalid V3 fresh-session reset evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED",
        }
        for route in profile["routes"]
    ]
    return {
        "schema": "aragorn/admission-protected-final-combined-v3-fresh-session-reset-route-coverage/v1",
        "assurance": "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_FRESH_SESSION_RESET_ROUTE_ONLY",
        "bindings": {
            "configuration": dict(v3_contract.parent._CONTRACT_FILES["config"]),
            "fresh_session_reset_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": v3_contract.contract._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(v3_contract.contract._SIGNATURE),
                },
            },
            "image": _IMAGE,
            "profile": dict(v3_contract.parent._CONTRACT_FILES["profile"]),
            "runtime_lock": dict(v3_contract.parent._CONTRACT_FILES["runtime_lock"]),
            "skill": dict(v3_contract.config._SOURCES["skill"]),
            "source_artifacts": {
                **{name: dict(value) for name, value in _SOURCE_ARTIFACTS.items()},
                "collector_dependencies": {
                    name: dict(value) for name, value in _COLLECTOR_ARTIFACTS.items()
                },
                "probe_bundle": [dict(_PROBE)],
            },
            "semantic_verifier_base": dict(_SEMANTIC_BASE),
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE",
            **{key: False for key in v3_contract.contract._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_FRESH_SESSION_RESET_PASS_ONLY",
            "TWENTY_OTHER_V3_PROFILE_ROUTES_NOT_TESTED",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
            "RESET_REQUEST_ACCEPTANCE_IS_NOT_MODEL_OR_DELIVERY_SUCCESS",
            "RESET_TRANSPORT_IN_PROCESS_NO_INDEPENDENT_RESET_SUBPROCESS_PID_ARGV_OR_STDOUT_RECORD",
            "NETWORK_DENIAL_ERRORS_EXPECTED_NO_PROVIDER_MODEL_REPLY_OR_DELIVERY_SUCCESS",
            "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
            "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
            "NO_CLEANUP_ROLLBACK_QUARANTINE_OR_STATE_EQUIVALENCE_CLAIM",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "SOURCE_TO_BINARY_BUILD_NOT_INDEPENDENTLY_ATTESTED_OR_REPRODUCED",
            "PUBLIC_NETWORK_DENIED",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "activation_transition_dynamically_exercised": False,
            "dynamically_exercised_routes": [_ROUTE],
            "install_policy_dynamically_exercised": False,
            "pass_basis": "SIGNED_EXACT_RESET_ROTATION_CLEAR_AND_REBUILD_TRANSITION",
            "pre_effect_prevention_dynamically_exercised": False,
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load_strict_json_stdout(command: Mapping[str, Any]) -> Any:
    value = json.loads(
        command["stdout_excerpt"],
        object_pairs_hook=contract.base.legacy.parent._reject_duplicates,
        parse_constant=contract.base.legacy.parent._reject_constant,
    )
    _verify_scalar_types(value)
    return value


def _verify_dependencies() -> None:
    path = Path(v3_contract.__file__).resolve(strict=True)
    semantic_path = Path(contract.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.as_posix().endswith(_BASE["path"]) is False
        or path.stat().st_size != _BASE["bytes"]
        or _digest(path.read_bytes()) != _BASE["digest"]
        or semantic_path
        != (Path(__file__).resolve(strict=True).parent / semantic_path.name).resolve(
            strict=True
        )
        or semantic_path.as_posix().endswith(_SEMANTIC_BASE["path"]) is False
        or semantic_path.stat().st_size != _SEMANTIC_BASE["bytes"]
        or _digest(semantic_path.read_bytes()) != _SEMANTIC_BASE["digest"]
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset verifier base changed")
    v3_contract._verify_dependencies()
    contract._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    if (
        Path(
            v3_contract.config.base.legacy._git(["rev-parse", "--show-toplevel"])
            .decode()
            .strip()
        ).resolve(strict=True)
        != root
        or v3_contract.config.base.legacy._git(
            ["rev-parse", "--show-object-format"]
        ).strip()
        != b"sha1"
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset repository changed")
    v3_contract.config.base._verify_commit(_SOURCE)
    v3_contract.config.base._verify_commit(_RETENTION)
    entry = v3_contract.config.base.legacy._git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V3 fresh-session reset signed tree changed")
    raw = v3_contract.config.base.legacy._git(
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
        raise AdmissionEvidenceError("V3 fresh-session reset signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    if canonical_digest(v3_contract._type_shape(evidence)) != _TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError("V3 fresh-session reset JSON type changed")
    v3_contract.enable._verify_scalar_types(evidence)
    v3_contract.config._verify_no_positive_eligibility(evidence)
    if (
        set(evidence)
        != {
            "authority",
            "composition",
            "decision",
            "harness",
            "limitations",
            "recorded_at",
            "route_id",
            "route_observation",
            "schema",
            "source_artifacts",
        }
        or evidence["schema"]
        != "aragorn/runtime-action-worker-final-combined-v3-fresh-session-reset-systemd-observation/v1"
        or evidence["route_id"] != _ROUTE
        or evidence["recorded_at"] != "2026-08-28T20:59:42.734344Z"
        or evidence["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_FRESH_SESSION_RESET_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or evidence["decision"]
        != {
            "status": "FINAL_COMBINED_V3_FRESH_SESSION_RESET_OBSERVED_PROFILE_NOT_TESTED",
            "route_observation_status": "OBSERVED",
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in v3_contract.contract._ELIGIBILITY_KEYS},
        }
        or evidence["limitations"] != _RAW_LIMITATIONS
        or canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
        or canonical_digest(evidence["harness"]["document"]) != _DIGESTS["harness"]
        or canonical_digest(evidence["route_observation"])
        != _DIGESTS["route_observation"]
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset wrapper changed")

    profile = _verify_composition(evidence["composition"], evidence["source_artifacts"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError("V3 fresh-session reset harness copies differ")
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
        or observation["bundle"] != [_PROBE]
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset nested custody changed")
    _verify_harness(evidence["harness"], evidence["source_artifacts"])
    harness = evidence["harness"]["document"]
    _verify_execution(
        observation, evidence["composition"]["action"]["boundaries"], harness
    )
    _verify_transition(
        document,
        container_id=harness["container_id"],
        execution=observation["execution"],
        gateway_pid=observation["gateway_pid_binding"]["pid"],
        outer_recorded_at=evidence["recorded_at"],
    )
    if not (
        contract.base.legacy._parse_time(document["recorded_at"])
        <= contract.base.legacy._parse_time(observation["execution"]["completed_at"])
        <= contract.base.legacy._parse_time(evidence["composition"]["recorded_at"])
        <= contract.base.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset execution custody changed")
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    action = composition["action"]
    artifact = action["artifacts"]["final_combined_v3_fresh_session_reset"]
    profile = artifact["profile"]["document"]
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
        != "aragorn/runtime-action-worker-final-combined-v3-fresh-session-reset-systemd-observation/v1"
        or composition["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_FRESH_SESSION_RESET_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or composition["recorded_at"] != "2026-08-28T20:59:42.734304Z"
        or composition["limitations"] != _RAW_LIMITATIONS
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
            "status": "FINAL_COMBINED_V3_ACTION_OBSERVED_PROFILE_NOT_TESTED",
        }
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": v3_contract.config._RUNTIME_TREE["tree_digest"],
            "runtime_volume": _RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": v3_contract.config._SOURCES["skill"]["digest"],
        }
        or canonical_digest(action) != _DIGESTS["composition_action"]
        or set(artifact) != set(_ARTIFACT_DIGESTS)
        or any(
            canonical_digest(artifact[name]) != digest
            for name, digest in _ARTIFACT_DIGESTS.items()
        )
        or composition["profile"]["before"] != composition["profile"]["after"]
        or composition["profile"]["before"]["document"] != profile
        or composition["profile"]["before"]["outcomes"]
        != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or action["inputs"]["gateway_config"] != artifact["config"]["document"]
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(v3_contract.contract._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile["runtime"]
        != {
            **v3_contract.contract._OPENCLAW,
            "name": "openclaw-protected-final-combined-v3",
        }
        or action["identities"]
        != {
            "broker": {"gid": 997, "uid": 995},
            "gateway": {"gid": 992, "uid": 992},
            "sensor": {"gid": 996, "uid": 996},
            "worker": {"gid": 997, "uid": 997},
        }
        or action["secret_checks"]
        != {
            "forbidden_driver_fields": [],
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
            "provider_and_gateway_token_values_retained": False,
        }
        or action["runtime"]
        != {
            "entrypoint": _OPENCLAW,
            "entrypoint_digest": v3_contract.contract._RUNTIME["entrypoint_digest"],
            "expected_version": v3_contract.contract._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": v3_contract.config._RUNTIME_TREE,
            "version_output": v3_contract.contract._RUNTIME["version_output"],
        }
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset composition changed")
    v3_contract.parent._verify_contract_artifacts(artifact)
    _verify_source_artifacts(source_artifacts)
    _verify_collector_artifacts(artifact["collector"])
    _verify_probe_artifact(artifact["fresh_session_reset_probe"])
    return profile


def _verify_signed_bytes(expected: Mapping[str, Any]) -> bytes:
    raw = v3_contract.config.base.legacy._git(
        ["show", f"{_SOURCE['commit']}:{expected['path']}"],
        maximum=expected["bytes"],
    )
    if len(raw) != expected["bytes"] or _digest(raw) != expected["digest"]:
        raise AdmissionEvidenceError("V3 fresh-session reset signed source changed")
    return raw


def _verify_collector_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != set(_COLLECTOR_ARTIFACTS):
        raise AdmissionEvidenceError("V3 fresh-session reset collector changed")
    for name, expected in _COLLECTOR_ARTIFACTS.items():
        v3_contract.enable_route._verify_file_record(
            value[name],
            path=f"/src/{expected['path']}",
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=f"fresh-session reset collector {name}",
        )
        _verify_signed_bytes(expected)


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V3 fresh-session reset source bundle changed")
    for name, expected in _SOURCE_ARTIFACTS.items():
        v3_contract.enable_route._verify_file_record(
            value[name],
            path=f"/src/{expected['path']}",
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=f"fresh-session reset {name} source",
        )
        if name in _SIGNED_SOURCE_ARTIFACTS:
            _verify_signed_bytes(expected)
    if value["probe_bundle"] != [_PROBE]:
        raise AdmissionEvidenceError("V3 fresh-session reset probe bundle changed")
    _verify_materialization()


def _verify_materialization() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    materializer = _verify_signed_bytes(_SOURCE_ARTIFACTS["materializer"])
    path = (root / _SOURCE_ARTIFACTS["materializer"]["path"]).resolve(strict=True)
    if path.read_bytes() != materializer:
        raise AdmissionEvidenceError("V3 fresh-session reset materializer changed")
    namespace = runpy.run_path(str(path))
    materialize = namespace.get("transformed_final_combined_v2_probe")
    if not callable(materialize):
        raise AdmissionEvidenceError(
            "V3 fresh-session reset materializer entry changed"
        )
    v2 = materialize("protected-route-probe.mjs", workshop=False)
    expected_v2 = _SOURCE_ARTIFACTS["materialized_v2_probe"]
    if (
        type(v2) is not bytes
        or len(v2) != expected_v2["bytes"]
        or _digest(v2) != expected_v2["digest"]
    ):
        raise AdmissionEvidenceError(
            "V3 fresh-session reset V2 materialization changed"
        )
    old_digest = (
        b"sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
    )
    new_digest = v3_contract.parent._CONTRACT_FILES["config"][
        "canonical_digest"
    ].encode()
    old_size = b"configuration.file?.size === 1880"
    new_size = b"configuration.file?.size === 2159"
    if (
        v2.count(old_digest) != 2
        or v2.count(new_digest) != 0
        or v2.count(old_size) != 1
        or v2.count(new_size) != 0
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset transform input changed")
    transformed = v2.replace(old_digest, new_digest).replace(old_size, new_size)
    expected_v3 = _SOURCE_ARTIFACTS["transformed_probe"]
    if (
        len(transformed) != expected_v3["bytes"]
        or _digest(transformed) != expected_v3["digest"]
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset transformed probe changed")
    return transformed


def _verify_probe_artifact(value: Mapping[str, Any]) -> None:
    expected_transform = {
        "configuration_bytes": {"from": 1_880, "occurrences": 1, "to": 2_159},
        "configuration_digest": {
            "from": "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
            "occurrences": 2,
            "to": v3_contract.parent._CONTRACT_FILES["config"]["canonical_digest"],
        },
        "v2_materialization": {
            "mode": "final-combined-v2",
            "result_digest": _SOURCE_ARTIFACTS["materialized_v2_probe"]["digest"],
            "source_digest": _SOURCE_ARTIFACTS["checked_in_probe"]["digest"],
            "workshop": False,
        },
    }
    if (
        set(value)
        != {
            "checked_in_source",
            "materialized_v2_source",
            "materializer",
            "runtime",
            "transform",
            "transformed_source",
        }
        or value["transform"] != expected_transform
    ):
        raise AdmissionEvidenceError(
            "V3 fresh-session reset transform artifact changed"
        )
    for name, expected, path, mode in (
        (
            "checked_in_source",
            _SOURCE_ARTIFACTS["checked_in_probe"],
            "/src/benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs",
            "0444",
        ),
        (
            "materialized_v2_source",
            _SOURCE_ARTIFACTS["materialized_v2_probe"],
            "/src/benchmark/admission/openclaw-v2026.7.1/protected-route-v2-probe.mjs",
            "0444",
        ),
        (
            "materializer",
            _SOURCE_ARTIFACTS["materializer"],
            "/src/scripts/materialize_fixed_admission_probes.py",
            "0555",
        ),
        (
            "transformed_source",
            _SOURCE_ARTIFACTS["transformed_probe"],
            "/src/benchmark/admission/openclaw-v2026.7.1/protected-route-v3-probe.mjs",
            "0444",
        ),
        (
            "runtime",
            _SOURCE_ARTIFACTS["transformed_probe"],
            "/route-input/fresh-session-reset/protected-route-probe.mjs",
            "0444",
        ),
    ):
        v3_contract.enable_route._verify_file_record(
            value[name],
            path=path,
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=mode,
            label=f"fresh-session reset {name}",
        )
    _verify_materialization()


def _verify_harness(
    envelope: Mapping[str, Any],
    _source_artifacts: Mapping[str, Any],
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
        != "aragorn/runtime-action-worker-final-combined-v3-fresh-session-reset-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["image_reference"]
        != "aragorn-phase3-final-combined-v3-fresh-session-reset-systemd"
        or document["platform"] != "linux"
        or document["profile_label"] != "phase3-final-combined-v3-fresh-session-reset"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or lineage["added_layers"]
        != [
            "sha256:2c69b4c9a8898fe909c33f04b930f03452963bf7a66fba1886e445f88cccd8dc",
            "sha256:366852cc8def63aa5e41176666b3e01b1aa64f38e5d291c03448f3fa4da363bd",
            "sha256:023e360bb5bcacbaf6cfd388f7671420c33f12b6df6de0436cb4f1539a05b0b2",
            "sha256:8026d12536c151c474cfdb78bf251d4979b9004cc585e305db3389e019827f0d",
        ]
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
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:90944",
                "dev.aragorn.role": (
                    "final-combined-v3-fresh-session-reset-route-input"
                ),
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
                "io.aragorn.source-commit": v3_contract.contract._OPENCLAW["commit"],
                "io.aragorn.source-tree": v3_contract.contract._OPENCLAW["source_tree"],
            },
            "name": _RUNTIME_VOLUME,
            "options": None,
            "scope": "local",
        }
        or set(verification)
        != {"command", "commit_object", "exit_code", "stderr", "stdout"}
        or verification["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or type(verification["exit_code"]) is not int
        or verification["exit_code"] != 0
        or set(commit_object) != {"base64", "bytes", "digest"}
        or commit_raw
        != v3_contract.config.base.legacy._git(
            ["cat-file", "commit", _SOURCE["commit"]], maximum=4096
        )
        or commit_object["bytes"] != len(commit_raw)
        or commit_object["digest"] != _digest(commit_raw)
        or set(stderr) != {"base64", "bytes", "digest"}
        or stderr_raw
        != (
            'Good "git" signature for yousif.snazhat@gmail.com with ED25519 key '
            f"{v3_contract.contract._SIGNATURE['key']}\n"
        ).encode()
        or stderr["bytes"] != len(stderr_raw)
        or stderr["digest"] != _digest(stderr_raw)
        or set(stdout) != {"base64", "bytes", "digest"}
        or stdout_raw != b""
        or stdout["bytes"] != 0
        or stdout["digest"] != _EMPTY_DIGEST
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset harness changed")
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
        raise AdmissionEvidenceError("V3 fresh-session reset harness file changed")


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
        raise AdmissionEvidenceError("V3 fresh-session reset raw identity changed")
    if canonical_digest(v3_contract._type_shape(document)) != _ROUTE_TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError("V3 fresh-session reset route JSON type changed")
    _verify_scalar_types(document)
    return document


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError(
                "V3 fresh-session reset unexpected floating-point value"
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
                    "V3 fresh-session reset nullable boolean field type changed"
                )
            if key == "pinned" and type(item) not in (bool, int):
                raise AdmissionEvidenceError(
                    "V3 fresh-session reset mixed boolean field type changed"
                )
            if (
                isinstance(key, str)
                and key not in {"message_prefix_continuity_valid", "pinned"}
                and ((key in _BOOLEAN_FIELDS) != (type(item) is bool))
            ):
                raise AdmissionEvidenceError(
                    "V3 fresh-session reset boolean field type changed"
                )
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError(
                    "V3 fresh-session reset boolean list item changed"
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
    action = document["actions"][0]
    commands = action["commands"]
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
            "/route-input/fresh-session-reset/protected-route-probe.mjs",
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
        or action["prerequisites"]["gateway_process"]["pid"] != pid
        or action["prerequisites"]["gateway_process"]["cmdline"] != process["cmdline"]
        or action["prerequisites"]["gateway_process"]["start_time_ticks"]
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
            <= contract.base.legacy._parse_time(
                action["prerequisites"]["commands"][0]["started_at"]
            )
            <= contract.base.legacy._parse_time(commands[0]["started_at"])
            <= contract.base.legacy._parse_time(commands[-1]["completed_at"])
            <= contract.base.legacy._parse_time(document["recorded_at"])
            <= contract.base.legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError(
            "V3 fresh-session reset execution boundary changed"
        )
    contract.base.legacy._verify_stack_boundary(
        stack,
        trusted=boundaries,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    contract.base.legacy._verify_gateway_listener(
        stack["gateway_listener"], stack["processes"]
    )


def _verify_transition(
    document: Mapping[str, Any],
    *,
    container_id: str,
    execution: Mapping[str, Any],
    gateway_pid: int,
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
        or document["schema"]
        != "aragorn/openclaw-protected-route-action-observations/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["selected_route_ids"] != [_ROUTE]
        or document["implementation_digest"] != _PROBE["digest"]
        or document["runtime_binding"]
        != {
            "commit": v3_contract.contract._OPENCLAW["commit"],
            "node_path": _NODE,
            "openclaw_digest": v3_contract.contract._RUNTIME["entrypoint_digest"],
            "openclaw_path": _OPENCLAW,
            "version": v3_contract.contract._OPENCLAW["version"],
        }
        or document["routes"]
        != [
            {
                "action_id": "fresh-session-reset",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        or len(document["actions"]) != 1
        or canonical_digest(document["actions"][0]) != _DIGESTS["action"]
        or not isinstance(document["run_nonce"], str)
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset route changed")
    _verify_protected_boundary(document["protected_boundary"])

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
        or set(observed)
        != {
            "initialization_turn",
            "rebuild_turn",
            "rebuilt_snapshot_matches_baseline",
            "reset_snapshot_cleared",
            "reset_turn",
            "rotation_observed_at",
            "session_after_reset",
            "session_after_reset_check",
            "session_after_rotation",
            "session_before_reset",
            "session_before_reset_check",
            "session_id_rotated",
        }
        or action["id"] != "fresh-session-reset"
        or action["execution_error"] is not None
        or action["reason_codes"] != []
        or action["status"] != "OBSERVED"
        or _UUID4.fullmatch(before_id) is None
        or _UUID4.fullmatch(after_id) is None
        or before_id == after_id
        or rotated["entry"]["session_id"] != after_id
        or rotated["present"] is not True
        or rotated["entry"]["snapshot_present"] is not False
        or rotated["entry"]["skill_names"] != []
        or rotated["entry"]
        != {
            "ended_at": None,
            "prompt": {
                "bytes": None,
                "digest": None,
                "storage": "absent-or-invalid",
            },
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
        or rotated["entry"]["updated_at"] <= 0
        or set(observed["session_before_reset_check"]) != _READY
        or set(observed["session_after_reset_check"]) != _READY
        or set(reset)
        != {
            "accepted",
            "completed_at",
            "error",
            "method",
            "params",
            "response",
            "scopes",
            "started_at",
            "transport",
        }
        or reset["accepted"] is not True
        or reset["error"] is not None
        or reset["method"] != "chat.send"
        or reset["params"]
        != {
            "deliver": False,
            "idempotencyKey": f"aragorn-protected-route-fresh-session-reset-{nonce}",
            "message": "/new",
            "sessionKey": _SESSION_KEY,
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
        raise AdmissionEvidenceError("V3 fresh-session reset semantics changed")

    # Probe summaries are not authority; all promoted predicates are recomputed below.
    initial = observed["initialization_turn"]
    rebuild = observed["rebuild_turn"]
    _verify_prerequisites(
        action["prerequisites"], container_id=container_id, gateway_pid=gateway_pid
    )
    _verify_turn(
        initial,
        label="fresh-session-initialize",
        nonce=nonce,
        snapshot=before,
    )
    _verify_turn(
        rebuild,
        label="fresh-session-rebuild",
        nonce=nonce,
        snapshot=after,
    )
    commands = [
        *action["prerequisites"]["commands"],
        *initial["commands"],
        *rebuild["commands"],
    ]
    if (
        action["commands"] != initial["commands"] + rebuild["commands"]
        or any(
            type(command["pid"]) is not int or command["pid"] <= 1
            for command in commands
        )
        or len({command["pid"] for command in commands}) != len(commands)
        or gateway_pid in {command["pid"] for command in commands}
        or any(
            contract.base.legacy._parse_time(left["completed_at"])
            > contract.base.legacy._parse_time(right["started_at"])
            for left, right in pairwise(commands)
        )
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset command custody changed")

    before_entry = before["entry"]
    after_entry = after["entry"]
    prompt = before_entry["prompt"]
    _verify_snapshot(before, session_id=before_id)
    _verify_snapshot(after, session_id=after_id)
    _verify_store_file(rotated["file"])
    if (
        before_entry["skill_names"] != after_entry["skill_names"]
        or before_entry["snapshot_version"] != after_entry["snapshot_version"]
        or before_entry["prompt"] != after_entry["prompt"]
        or prompt["storage"] != "promptRef"
        or prompt["digest"] != prompt["expected_digest"]
        or prompt["digest"] != _PROMPT_DIGEST
        or len(
            {before["file"]["inode"], rotated["file"]["inode"], after["file"]["inode"]}
        )
        != 3
        or len(
            {
                before["file"]["digest"],
                rotated["file"]["digest"],
                after["file"]["digest"],
            }
        )
        != 3
        or len(
            {
                before["file"]["device"],
                rotated["file"]["device"],
                after["file"]["device"],
            }
        )
        != 1
        or not (
            contract.base.legacy._parse_time(execution["started_at"])
            <= contract.base.legacy._parse_time(
                action["prerequisites"]["commands"][0]["started_at"]
            )
            <= contract.base.legacy._parse_time(
                initial["wait"]["command"]["completed_at"]
            )
            <= contract.base.legacy._parse_time(reset["started_at"])
            <= contract.base.legacy._parse_time(reset["completed_at"])
            <= contract.base.legacy._parse_time(observed["rotation_observed_at"])
            <= contract.base.legacy._parse_time(
                rebuild["send"]["command"]["started_at"]
            )
            < contract.base.legacy._parse_time(
                rebuild["wait"]["command"]["completed_at"]
            )
            <= contract.base.legacy._parse_time(document["recorded_at"])
            <= contract.base.legacy._parse_time(execution["completed_at"])
            < contract.base.legacy._parse_time(outer_recorded_at)
        )
        or not (
            old.legacy._epoch_ms(reset["completed_at"])
            <= rotated["entry"]["updated_at"]
            <= old.legacy._epoch_ms(observed["rotation_observed_at"])
        )
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset snapshot custody changed")


def _verify_protected_boundary(value: Mapping[str, Any]) -> None:
    roots = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    if (
        canonical_digest(value) != _DIGESTS["protected_boundary"]
        or set(value)
        != {"configuration", "effective_identity", "ready", "roots", "runtime"}
        or value["ready"] is not True
        or value["effective_identity"] != {"gid": 992, "uid": 992}
        or set(value["roots"]) != set(roots)
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset boundary changed")
    v3_contract._verify_config(value["configuration"])
    v3_contract._verify_read_only_mount(
        value["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{_RUNTIME_VOLUME}/_data",
    )
    for name, path in roots.items():
        root = value["roots"][name]
        entry = root["observation"]
        if (
            set(root) != {"observation", "ready", "writable"}
            or root["ready"] is not True
            or root["writable"] is not True
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
                "V3 fresh-session reset conventional root changed"
            )


def _verify_prerequisites(
    value: Mapping[str, Any], *, container_id: str, gateway_pid: int
) -> None:
    commands = value["commands"]
    gateway = value["gateway_process"]
    runtime = value["runtime_files"]
    system = value["system_info"]
    if (
        set(value)
        != {
            "commands",
            "gateway_process",
            "ready",
            "reason_codes",
            "runtime_files",
            "system_info",
        }
        or value["ready"] is not True
        or value["reason_codes"] != []
        or gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "hostname": container_id[:12],
            "pid": gateway_pid,
            "start_time_ticks": gateway["start_time_ticks"],
        }
        or re.fullmatch(r"[1-9][0-9]*", gateway["start_time_ticks"]) is None
        or len(commands) != 2
        or system["command"] != commands[1]
        or system["response"]["parsed"] is not True
        or _load_strict_json_stdout(commands[1]) != system["response"]["value"]
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset prerequisites changed")
    _verify_runtime_files(runtime)
    contract._verify_version(commands[0])
    contract._verify_system(system, gateway)
    _verify_command(
        commands[0],
        [_NODE, _OPENCLAW, "--version"],
        stdout_exact=v3_contract.contract._RUNTIME["version_output"] + "\n",
    )
    _verify_command(
        commands[1],
        _gateway_argv("system.info"),
        stdout_value=system["response"]["value"],
    )


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
        raise AdmissionEvidenceError("V3 fresh-session reset runtime files changed")
    contract._verify_openclaw(openclaw["file"])


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
    command: Mapping[str, Any],
    argv: list[str],
    *,
    stdout_value: Any | None = None,
    stdout_exact: str | None = None,
) -> None:
    stdout = command["stdout_excerpt"]
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
        or command["exit_code"] != 0
        or command["signal"] is not None
        or command["error"] is not None
        or contract.base.legacy._parse_time(command["started_at"])
        >= contract.base.legacy._parse_time(command["completed_at"])
        or command["stderr_excerpt"] != ""
        or type(command["stderr_bytes"]) is not int
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _EMPTY_DIGEST
        or type(command["stdout_bytes"]) is not int
        or command["stdout_bytes"] != len(stdout.encode())
        or command["stdout_digest"] != _digest(stdout.encode())
        or (stdout_exact is not None and stdout != stdout_exact)
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset command changed")
    if stdout_value is not None and _load_strict_json_stdout(command) != stdout_value:
        raise AdmissionEvidenceError("V3 fresh-session reset command output changed")


def _verify_turn(
    turn: Mapping[str, Any],
    *,
    label: str,
    nonce: str,
    snapshot: Mapping[str, Any],
) -> None:
    run_id = f"aragorn-protected-route-{label}-{nonce}"
    message = {
        "fresh-session-initialize": "Inert protected-route session initialization.",
        "fresh-session-rebuild": "Inert protected-route post-reset snapshot rebuild.",
    }[label]
    send_params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": message,
        "sessionKey": _SESSION_KEY,
        "timeoutMs": 5000,
    }
    wait_params = {"runId": run_id, "timeoutMs": 10_000}
    send_value = {"runId": run_id, "status": "started"}
    wait_value = {
        "runId": run_id,
        "status": "error",
        "endedAt": turn["wait"]["response"]["value"]["endedAt"],
        "error": _NETWORK_ERROR,
    }
    send = turn["send"]
    wait = turn["wait"]
    if (
        set(turn) != {"commands", "confirmed", "send", "wait"}
        or turn["confirmed"] is not True
        or set(send) != {"command", "response"}
        or set(wait) != {"command", "response"}
        or turn["commands"] != [send["command"], wait["command"]]
        or send["response"] != {"parsed": True, "value": send_value}
        or wait["response"] != {"parsed": True, "value": wait_value}
        or type(wait_value["endedAt"]) is not int
        or wait_value["endedAt"] <= 0
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset terminal turn changed")
    _verify_command(
        send["command"],
        _gateway_argv("chat.send", params=send_params),
        stdout_value=send_value,
    )
    _verify_command(
        wait["command"],
        _gateway_argv("agent.wait", timeout="12000", params=wait_params),
        stdout_value=wait_value,
    )
    entry = snapshot["entry"]
    if not (
        entry["runtime_ms"] == entry["ended_at"] - entry["started_at"]
        and old.legacy._epoch_ms(wait["command"]["started_at"])
        <= entry["started_at"]
        <= entry["ended_at"]
        <= entry["updated_at"]
        <= wait_value["endedAt"]
        <= old.legacy._epoch_ms(wait["command"]["completed_at"])
    ):
        raise AdmissionEvidenceError(
            "V3 fresh-session reset turn snapshot timeline changed"
        )


def _verify_snapshot(value: Mapping[str, Any], *, session_id: str) -> None:
    entry = value["entry"]
    prompt = entry["prompt"]
    prompt_file = prompt["file"]
    _verify_store_file(value["file"])
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
        or entry["session_id"] != session_id
        or entry["skill_names"] != ["template-skill"]
        or entry["snapshot_present"] is not True
        or type(entry["snapshot_version"]) is not int
        or entry["snapshot_version"] <= 0
        or entry["status"] != "timeout"
        or any(
            type(entry[name]) is not int or entry[name] <= 0
            for name in ("ended_at", "runtime_ms", "started_at", "updated_at")
        )
        or entry["runtime_ms"] != entry["ended_at"] - entry["started_at"]
        or not (entry["started_at"] <= entry["ended_at"] <= entry["updated_at"])
        or set(prompt) != {"bytes", "digest", "expected_digest", "file", "storage"}
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
        raise AdmissionEvidenceError("V3 fresh-session reset rebuilt snapshot changed")


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
        or any(
            type(value[name]) is not int or value[name] <= 0
            for name in ("device", "inode", "size")
        )
    ):
        raise AdmissionEvidenceError("V3 fresh-session reset session store changed")
