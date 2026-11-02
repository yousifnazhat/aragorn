"""Qualify one exact V3 archive-source post-write activation rejection."""

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

from . import admission_protected_final_combined_v2_archive_replacement as semantics
from . import admission_protected_final_combined_v3_config_entry_activation as v3_contract
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

contract = v3_contract.contract
current = v3_contract.config

_ROUTE = "ADM-02/update/archive-source-force-replacement"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = (
    "aragorn-phase3-final-combined-v3-archive-source-force-replacement-"
    "route-input-84294"
)
_ARCHIVE_VOLUME = (
    "aragorn-phase3-final-combined-v3-archive-source-force-replacement-"
    "archive-source-84294"
)
_IMAGE = "sha256:7273f24c1a819548f352ca07383f3da61749d8b2ff0dc3338a3b3ad86014fd13"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_PROBE_BUNDLE = [
    {
        "bytes": 25_498,
        "digest": "sha256:c89af8975bcdc8963659b39b354fc8b754d4805f7249a1cc766458cdad891328",
        "name": "protected-archive-replacement-probe.mjs",
    }
]
_DEPENDENCIES = {
    "archive_semantics": {
        "bytes": 52_608,
        "digest": "sha256:c31d209c5ea7af4181396bcdeb8a4e54d965ed793ba4fc4be489cd69e460602e",
        "path": "admission_protected_final_combined_v2_archive_replacement.py",
    },
    "v3_contract": {
        "bytes": 57_245,
        "digest": "sha256:41a5c8e274b7f22e4cc79bde03917aea6717a83b3f810803d075e39c4b2afb5e",
        "path": "admission_protected_final_combined_v3_config_entry_activation.py",
    },
}
_EVIDENCE = {
    "bytes": 511_551,
    "canonical_bytes": 511_550,
    "canonical_digest": "sha256:3af77488516bb851c85ba79144c88eab234f9c4e5fad68376c9a35d04ed00c47",
    "digest": "sha256:95192b887bbc2978db2817f753ce65f5e3f8e5da1889eae355d1f3110f234b37",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
        "archive-source-force-replacement-systemd-p3-final-2026-08-31.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 31_023,
    "canonical_bytes": 31_034,
    "canonical_digest": "sha256:0faeaef09b6560c84ff6d6601fc139c831b0ac4e45bf22917872684041e57c65",
    "digest": "sha256:1673a719d8f52012b6d5201bb930cc04196741db947344b20a7fa64d575fbc09",
}
_SOURCE = {
    "commit": "fea1cdcee40aa1ddb74aea19e9f20e7bca740598",
    "parent": "7aca6574b6d2a1123a508588acc18eebaaad8f20",
    "tree": "1b2f6116db2c5e47362ea952721b997a7094a3cb",
}
_RETENTION = {
    "commit": "9cebb30283877b6e369cc70c92faa1d260802c75",
    "parent": _SOURCE["commit"],
    "tree": "64611119a747a9886f58d7866c1ea86e5765f90c",
}
_RETENTION_BLOB = "2e679718d6a5a54c807b595a357bdb76e8104b0a"
_TYPE_SHAPE_DIGEST = "sha256:04f75cfec0e68b6587672776569183fa99b4ff44fbe9b6b7f5b92d06ac65a485"
_ROUTE_TYPE_SHAPE_DIGEST = "sha256:4b9dd986853ab5a246e46ef4c217b59a7ba6daf667841f9c4a322aa844139cf4"
_DIGESTS = {
    "action": "sha256:43db7b231d4e6312d448f09fcecfc5132d6817c162fe425da6d9ef30349f58f9",
    "composition": "sha256:c5b64f4ff0a97220d5b06f3b99cee4d942f1f492b7b774d2d77df086c40915f5",
    "execution": "sha256:f558271078cd52f624a49af27a6715f3d6d429d52748e4f344e58c2739283beb",
    "gateway_binding": "sha256:4ed9d5fafd91b07fb03087250eb7d0a5ba2e1750b4d5aa2e4f83151bcd99f372",
    "harness": "sha256:0aeb614dfc13d79ccc77fe1164a707ad9e5305e8f2e3f0e6bd6d03bc4e62137a",
    "host_config": "sha256:2e0ad0e9ce445367c793fdbe666a9e5ce6fa4913eca7101b1f9539f5825069ea",
    "image_lineage": "sha256:ffc6b782f9aa293c91d8a7225996b1fa5e75899d4961fdd6ecaeb65bdde77e6a",
    "route_observation": "sha256:8b887b8cfd04562b095d093e6eea541c99f6e26068c8d6d07ab0e62929477677",
    "source_artifacts": "sha256:405843c3aa60a517c6bb08a25b6bd3a0e52f4a61afe5e6975be4133e5b8bdcc4",
    "stack": "sha256:9233f737bbb701bce3972cfe064e5301880cdb3db6d8b293841025dd235eb2f1",
}
_STATIC_DIGESTS = {
    "boundary_after": "sha256:09e85890eec3ae2eeded08baa5665fc7bfe805d5fafa1d519625fd2a02bddef8",
    "boundary_before": "sha256:c712101902d121e1093b7e7597abbd8645e0111e98ac6e46274256d418439871",
    "discovery_after": "sha256:9966c129036bdfe868f2c01b11027cab17ea4afa1d5a8f606a8304279274e5b7",
    "discovery_before": "sha256:77cd9c8ae7cf78e6623ec29badfbef79a793ea0108c4c721200f9d4899ece7e8",
    "gateway": "sha256:577780d17ded404414d7b404d9a674a4aa63c1eed5d443411033d3080d1a48bf",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "positive_control": "sha256:bada9f03c1c821b9d75bbeb2c27ea6c472c60a2b8070951c030e9b138b1b9c5c",
    "runtime_tree": "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b",
    "source": "sha256:3358bfe4ecafca756b9a5fc2129dfb008abd3075c82b9a0cdace1975445082d7",
    "source_install": "sha256:c31f817188f6b7d81765ecf52edd4c83e42a9678baf4386456cbd64bc04004c2",
    "stack_boundaries": "sha256:48b6cfac8e6cc055c60f1911adf605215c71ae5b9650a6d1fde0c7247ac5fb8c",
    "system": "sha256:99f65cb80ebe121df5198aa55d34bf5adbacc6b75e4ee5a3ba5565edde0354b2",
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
    "upload_begin": "sha256:e0d63988aabf9971f5817dd6b2a17c099b3cc4ba410c8e9f12aaf5cfbcc40414",
    "upload_install": "sha256:a365c1d420940c145d65e22d3681e0ac5605ce6ca16b51b10dec99f2cc06007d",
    "version": "sha256:d56135c69c02cc6e0feb388b4078bc18d122f6b191b407701de097db8659b501",
}
_SOURCE_ARTIFACTS = {
    "checked_in_probe": (
        22_549,
        "sha256:90bf211226365ede1cf781fa3faa45217b1ed72fd636cc48824c4b39e5ac7c22",
        "benchmark/admission/openclaw-v2026.7.1/protected-archive-replacement-probe.mjs",
        "0444",
    ),
    "collector": (
        17_373,
        "sha256:4fb753ff7e83ca381d3ce04957e190e38c920309a805099f03684810521c5dee",
        "scripts/runtime_action_worker_final_combined_v3_archive_source_force_replacement_systemd_probe.py",
        "0555",
    ),
    "fixed_materializer": (
        87_912,
        "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
        "scripts/materialize_fixed_admission_probes.py",
        "0555",
    ),
    "inherited_v2_route_injector": (
        17_073,
        "sha256:48c4a6d269f29080cf88d750205d40731f66fc13415aa76f6afeff0f8259e809",
        "scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
        "0555",
    ),
    "inherited_v3_contract_base": (
        28_860,
        "sha256:c9e3e43e4d122575cc362e2ec73b2fc4b57d4ad465a1d49e4b94291d935217ad",
        "scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py",
        "0555",
    ),
    "inherited_v3_stack_helper": (
        25_532,
        "sha256:467af8df703ca43e97e8b8158f2c085ffecdc5c6e37bff4ef257095d1178fd25",
        "scripts/runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe.py",
        "0555",
    ),
    "rebound_materializer": (
        7_691,
        "sha256:8321a6c423b03c283d175185de6886ca12aaa08c244f81b67be3a73a47279a1c",
        "scripts/materialize_openclaw_final_v3_rebound_probes.py",
        "0555",
    ),
}
_COLLECTOR_ARTIFACTS = {
    "capture_recipe": (
        35_063,
        "sha256:7f921ef370f78dd3277c5a33681545ac81047799a4f631c51b041f06e31237d8",
        "scripts/capture_runtime_action_worker_final_combined_v3_archive_source_force_replacement_systemd.sh",
        "0555",
    ),
    "dockerfile": (
        6_223,
        "sha256:797f5ffa7cbb3d44fb928bb48138852da68855623b622f075e6804940cbfec4a",
        "benchmark/runtime-action-worker-final-combined-v3-archive-source-force-replacement-systemd/Dockerfile",
        "0444",
    ),
    "inherited_v2_route_injector": _SOURCE_ARTIFACTS["inherited_v2_route_injector"],
    "inherited_v3_contract_base": _SOURCE_ARTIFACTS["inherited_v3_contract_base"],
    "inherited_v3_stack_helper": _SOURCE_ARTIFACTS["inherited_v3_stack_helper"],
    "probe": _SOURCE_ARTIFACTS["collector"],
}
_RAW_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
    "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "ONLY_ARCHIVE_SOURCE_FORCE_REPLACEMENT_ATTEMPT_OBSERVED",
    "NO_ARCHIVE_SOURCE_FORCE_REPLACEMENT_CONFORMANCE_OR_REPLACEMENT_SUCCESS_CLAIM",
    "EXACT_READ_ONLY_ARCHIVE_SOURCE_FIXTURE_CUSTODY_BOUND",
    "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
    "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
    "ARCHIVE_SOURCE_FORCE_REPLACEMENT_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_ARCHIVE_STATE_EQUIVALENCE_CLEANUP_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def verify_openclaw_final_combined_v3_archive_replacement(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact V3 post-write activation-prevention PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract._read_blob(evidence_cas, _EVIDENCE, "V3 archive replacement")
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 archive replacement CAS differs from signed retention"
            )
        evidence = contract._load_canonical_json(
            raw, _EVIDENCE, "V3 archive replacement"
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
        raise AdmissionEvidenceError(f"invalid V3 archive replacement evidence: {exc}") from exc

    routes = [
        {"id": route["id"], "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED"}
        for route in profile["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v3-archive-source-force-"
            "replacement-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_POST_WRITE_"
            "ACTIVATION_REJECTION_ROUTE_ONLY"
        ),
        "bindings": {
            "archive_source_observation": {
                **_EVIDENCE,
                "retention": {**_RETENTION, "signing_key": contract._SIGNATURE["key"]},
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {**_SOURCE, "signature": dict(contract._SIGNATURE)},
            },
            "configuration": dict(v3_contract.parent._CONTRACT_FILES["config"]),
            "image": _IMAGE,
            "profile": dict(v3_contract.parent._CONTRACT_FILES["profile"]),
            "runtime_lock": dict(v3_contract.parent._CONTRACT_FILES["runtime_lock"]),
            "source_artifacts": {
                name: {"bytes": value[0], "digest": value[1], "path": value[2]}
                for name, value in _SOURCE_ARTIFACTS.items()
            },
            "verifier_dependencies": {
                name: dict(value) for name, value in _DEPENDENCIES.items()
            },
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE",
            **{key: False for key in contract._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_POST_WRITE_ACTIVATION_REJECTION_PASS_ONLY",
            "TWENTY_OTHER_V3_PROFILE_ROUTES_NOT_TESTED",
            "DIRECTORY_SOURCE_NOT_ARCHIVE_INGESTION_OR_REPLACEMENT",
            "UPLOAD_PATHS_DENIED_BEFORE_ARCHIVE_INGESTION",
            "EXCLUDED_WORKSPACE_RESIDUE_CONTENT_NOT_HASHED_AFTER_INSTALL",
            "ONE_IMMEDIATE_CLI_DISCOVERY_REJECTION_NOT_CONTINUOUS_PREVENTION",
            "NO_NATIVE_AGENT_OR_MODEL_CONSUMER_ATTEMPT",
            "NO_CLEANUP_ROLLBACK_STATE_EQUIVALENCE_OR_BROAD_CAUSALITY_CLAIM",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "SOURCE_TO_BINARY_BUILD_NOT_INDEPENDENTLY_ATTESTED_OR_REPRODUCED",
            "PUBLIC_NETWORK_DENIED",
            "INERT_READ_ONLY_SOURCE_FIXTURE_ONLY",
            "PLUGIN_ONLY_INSTALL_POLICY_PRESENT_BUT_NOT_CAUSAL",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "pass_basis": (
                "SIGNED_EXACT_UPLOAD_DENIAL_AND_EXCLUDED_WORKSPACE_WRITE_FOLLOWED_"
                "BY_EXTERNAL_SINGLETON_CATALOG_REJECTION_WITH_PROTECTED_TARGET_"
                "PRESERVED"
            ),
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_dependencies() -> None:
    directory = Path(__file__).resolve(strict=True).parent
    modules = {"archive_semantics": semantics, "v3_contract": v3_contract}
    for name, module in modules.items():
        expected = _DEPENDENCIES[name]
        path = Path(module.__file__).resolve(strict=True)
        if (
            path != (directory / expected["path"]).resolve(strict=True)
            or path.stat().st_size != expected["bytes"]
            or _digest(path.read_bytes()) != expected["digest"]
        ):
            raise AdmissionEvidenceError(f"V3 archive replacement dependency changed: {name}")
    semantics._verify_dependencies()
    v3_contract._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = current.base.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(strict=True)
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V3 archive replacement repository changed")
    current.base._verify_commit(_SOURCE)
    current.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V3 archive replacement signed tree changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=600 * 1024)
    oid = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False).hexdigest()
    if oid != _RETENTION_BLOB or len(raw) != _EVIDENCE["bytes"] or _digest(raw) != _EVIDENCE["digest"]:
        raise AdmissionEvidenceError("V3 archive replacement signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    if canonical_digest(v3_contract._type_shape(evidence)) != _TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError("V3 archive replacement JSON type changed")
    semantics.base._verify_scalar_types(evidence)
    current._verify_no_positive_eligibility(evidence)
    decision = {
        "admission_profile_eligible": False,
        "aggregate_admission_eligible": False,
        "edr_eligible": False,
        "installer_work_eligible": False,
        "phase3_exit_eligible": False,
        "release_eligible": False,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        "route_observation_status": "OBSERVED",
        "route_pass_count": 0,
        "run_01_eligible": False,
        "run_02_eligible": False,
        "run_eligible": False,
        "status": "FINAL_COMBINED_V3_ARCHIVE_SOURCE_FORCE_REPLACEMENT_OBSERVED_PROFILE_NOT_TESTED",
    }
    if (
        set(evidence) != {"authority", "composition", "decision", "harness", "limitations", "recorded_at", "route_id", "route_observation", "schema", "source_artifacts"}
        or evidence["schema"] != "aragorn/runtime-action-worker-final-combined-v3-archive-source-force-replacement-systemd-observation/v1"
        or evidence["authority"] != "BOUND_FINAL_COMBINED_V3_RAW_ARCHIVE_SOURCE_FORCE_REPLACEMENT_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or evidence["recorded_at"] != "2026-08-31T18:15:23.811507Z"
        or evidence["route_id"] != _ROUTE
        or evidence["decision"] != decision
        or any(type(evidence["decision"][name]) is not int for name in ("route_fail_count", "route_not_tested_count", "route_pass_count"))
        or evidence["limitations"] != _RAW_LIMITATIONS
        or canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or canonical_digest(evidence["source_artifacts"]) != _DIGESTS["source_artifacts"]
        or canonical_digest(evidence["harness"]["document"]) != _DIGESTS["harness"]
        or canonical_digest(evidence["route_observation"]) != _DIGESTS["route_observation"]
    ):
        raise AdmissionEvidenceError("V3 archive replacement wrapper changed")
    profile = _verify_composition(evidence["composition"], evidence["source_artifacts"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError("V3 archive replacement harness copies differ")
    harness = _verify_harness(evidence["harness"])
    observation = evidence["route_observation"]
    document = _decode_route_raw(observation["raw"])
    if (
        set(observation) != {"bundle", "document", "execution", "gateway_pid_binding", "raw", "route", "stack_before"}
        or document != observation["document"]
        or observation["route"] != document["route"]
        or observation["bundle"] != _PROBE_BUNDLE
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V3 archive replacement nested custody changed")
    _verify_execution(
        observation, evidence["composition"]["action"]["boundaries"], harness
    )
    _verify_document(
        document,
        harness=harness,
        execution=observation["execution"],
        composition_recorded_at=evidence["composition"]["recorded_at"],
        outer_recorded_at=evidence["recorded_at"],
    )
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    artifact = composition["action"]["artifacts"][
        "final_combined_v3_archive_source_force_replacement"
    ]
    profile = composition["profile"]["before"]["document"]
    if (
        composition["schema"] != "aragorn/runtime-action-worker-final-combined-v3-archive-source-force-replacement-systemd-observation/v1"
        or composition["authority"] != "BOUND_FINAL_COMBINED_V3_RAW_ARCHIVE_SOURCE_FORCE_REPLACEMENT_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or composition["recorded_at"] != "2026-08-31T18:15:23.810977Z"
        or composition["limitations"] != _RAW_LIMITATIONS
        or composition["decision"] != {
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
        or composition["bindings"]["network"] != "none"
        or set(artifact)
        != {
            "activator",
            "activator_source",
            "archive_source_force_replacement_probe",
            "collector",
            "config",
            "plugin",
            "policy_command",
            "preflight",
            "profile",
            "runtime_lock",
            "skill",
        }
        or composition["profile"]["before"] != composition["profile"]["after"]
        or composition["profile"]["before"]["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]] != list(contract._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile["runtime"] != {**contract._OPENCLAW, "name": "openclaw-protected-final-combined-v3"}
    ):
        raise AdmissionEvidenceError("V3 archive replacement composition changed")
    v3_contract.parent._verify_contract_artifacts(artifact)
    _verify_source_artifacts(source_artifacts)
    _verify_collector_artifacts(artifact["collector"])
    _verify_probe_artifact(artifact["archive_source_force_replacement_probe"])
    return profile


def _identity(value: tuple[int, str, str, str]) -> dict[str, Any]:
    return {"bytes": value[0], "digest": value[1], "path": value[2], "mode": value[3]}


def _verify_signed_record(
    value: Mapping[str, Any], expected: tuple[int, str, str, str], label: str
) -> None:
    identity = _identity(expected)
    v3_contract.enable_route._verify_file_record(
        value,
        path=f"/src/{identity['path']}",
        bytes_=identity["bytes"],
        digest=identity["digest"],
        mode=identity["mode"],
        label=label,
    )
    raw = current.base.legacy._git(
        ["show", f"{_SOURCE['commit']}:{identity['path']}"],
        maximum=identity["bytes"],
    )
    if len(raw) != identity["bytes"] or _digest(raw) != identity["digest"]:
        raise AdmissionEvidenceError(
            f"V3 archive replacement signed source changed: {label}"
        )


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V3 archive replacement source inventory changed")
    for name, expected in _SOURCE_ARTIFACTS.items():
        _verify_signed_record(value[name], expected, f"source {name}")
    if value["probe_bundle"] != _PROBE_BUNDLE:
        raise AdmissionEvidenceError("V3 archive replacement probe bundle changed")


def _verify_collector_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != set(_COLLECTOR_ARTIFACTS):
        raise AdmissionEvidenceError("V3 archive replacement collector inventory changed")
    for name, expected in _COLLECTOR_ARTIFACTS.items():
        _verify_signed_record(value[name], expected, f"collector {name}")


def _verify_probe_artifact(value: Mapping[str, Any]) -> None:
    if (
        set(value)
        != {
            "checked_in_probe",
            "fixed_materializer",
            "probe_bundle",
            "rebound_materializer",
            "runtime_probe",
        }
        or value["probe_bundle"] != _PROBE_BUNDLE
    ):
        raise AdmissionEvidenceError("V3 archive replacement probe artifact changed")
    for name in ("checked_in_probe", "fixed_materializer", "rebound_materializer"):
        expected = _SOURCE_ARTIFACTS[name]
        v3_contract.enable_route._verify_file_record(
            value[name],
            path=f"/src/{expected[2]}",
            bytes_=expected[0],
            digest=expected[1],
            mode=expected[3],
            label=f"probe {name}",
        )
    bundle = _PROBE_BUNDLE[0]
    v3_contract.enable_route._verify_file_record(
        value["runtime_probe"],
        path=f"/route-input/archive-source-force-replacement/{bundle['name']}",
        bytes_=bundle["bytes"],
        digest=bundle["digest"],
        mode="0444",
        label="runtime probe",
    )


def _verify_harness(envelope: Mapping[str, Any]) -> Mapping[str, Any]:
    document = envelope["document"]
    file = envelope["file"]
    raw = base64.b64decode(file["base64"], validate=True)
    parsed = json.loads(raw.decode(), object_pairs_hook=contract._reject_duplicates, parse_constant=contract._reject_constant)
    archive_fixture = document["archive_source_fixture"]
    archive_raw = base64.b64decode(archive_fixture["base64"], validate=True)
    lineage = document["image_lineage"]
    route_identity = document["route_input_volume_identity"]
    archive_identity = document["archive_source_volume_identity"]
    if (
        set(envelope) != {"digest", "document", "file"}
        or parsed != document
        or raw != canonical_json(document)
        or envelope["digest"] != _DIGESTS["harness"]
        or file["digest"] != _DIGESTS["harness"]
        or file["bytes"] != len(raw)
        or file["path"] != "/run/aragorn-harness.json"
        or document["schema"] != "aragorn/runtime-action-worker-final-combined-v3-archive-source-force-replacement-systemd-harness/v1"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["profile_label"] != "phase3-final-combined-v3-archive-source-force-replacement"
        or document["platform"] != "linux"
        or canonical_digest(document["host_config"]) != _DIGESTS["host_config"]
        or document["host_config"]["network_mode"] != "none"
        or sorted(document["host_config"]["binds"]) != sorted([
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            f"{_RUNTIME_VOLUME}:/runtime:ro",
            f"{_ROUTE_VOLUME}:/route-input:ro",
            f"{_ARCHIVE_VOLUME}:/sources:ro",
        ])
        or document["route_input_mount"] != {"destination": "/route-input", "driver": "local", "mode": "ro", "rw": False, "source": _ROUTE_VOLUME, "type": "volume"}
        or document["archive_source_mount"] != {"destination": "/sources", "driver": "local", "mode": "ro", "rw": False, "source": _ARCHIVE_VOLUME, "type": "volume"}
        or document["openclaw_runtime_mount"] != {"destination": "/runtime", "driver": "local", "mode": "ro", "rw": False, "source": _RUNTIME_VOLUME, "type": "volume"}
        or document["openclaw_runtime_volume"] != _RUNTIME_VOLUME
        or route_identity["name"] != _ROUTE_VOLUME
        or route_identity["labels"] != {
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:84294",
            "dev.aragorn.role": "final-combined-v3-archive-source-force-replacement-route-input",
            "dev.aragorn.source-commit": _SOURCE["commit"],
        }
        or archive_identity["name"] != _ARCHIVE_VOLUME
        or archive_identity["labels"] != {
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:84294",
            "dev.aragorn.role": "final-combined-v3-archive-source-force-replacement-archive-source",
            "dev.aragorn.route": _ROUTE,
            "dev.aragorn.source-commit": _SOURCE["commit"],
        }
        or archive_fixture["path"] != "benchmark/fixtures/phase3-protected-archive-replacement/SKILL.md"
        or archive_fixture["bytes"] != 144
        or archive_fixture["digest"] != "sha256:d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1"
        or len(archive_raw) != 144
        or _digest(archive_raw) != archive_fixture["digest"]
        or document["source_commit_verification"]["command"] != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or document["source_commit_verification"]["exit_code"] != 0
        or canonical_digest(document["image_lineage"]) != _DIGESTS["image_lineage"]
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or lineage["child"]["id"] != _IMAGE
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or re.fullmatch(r"[0-9a-f]{64}", document["container_id"]) is None
    ):
        raise AdmissionEvidenceError("V3 archive replacement harness changed")
    return document


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(raw.decode(), object_pairs_hook=contract._reject_duplicates, parse_constant=contract._reject_constant)
    canonical = canonical_json(document)
    if (
        raw == canonical + b"\n"
        or len(raw) != _ROUTE_RAW["bytes"]
        or len(canonical) != _ROUTE_RAW["canonical_bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not False
        or canonical_digest(v3_contract._type_shape(document)) != _ROUTE_TYPE_SHAPE_DIGEST
    ):
        raise AdmissionEvidenceError("V3 archive replacement raw identity changed")
    semantics.base._verify_scalar_types(document)
    return document


def _verify_execution(
    observation: Mapping[str, Any],
    boundaries: Mapping[str, Any],
    harness: Mapping[str, Any],
) -> None:
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    stack = observation["stack_before"]
    pid = binding["pid"]
    gateway = "aragorn-agent-gateway.service"
    units = {
        gateway,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    process = stack["processes"][gateway]
    unit = stack["units"][gateway]
    if (
        canonical_digest(execution) != _DIGESTS["execution"]
        or canonical_digest(binding) != _DIGESTS["gateway_binding"]
        or canonical_digest(stack) != _DIGESTS["stack"]
        or canonical_digest(boundaries) != _STATIC_DIGESTS["stack_boundaries"]
        or type(pid) is not int
        or pid <= 0
        or binding != {"environment_name": "ARAGORN_GATEWAY_PID", "mount_namespace": f"/proc/{pid}/ns/mnt", "pid": pid, "unit": gateway}
        or execution["argv"] != ["nsenter", "--target", str(pid), "--mount", "--", "setpriv", "--reuid=992", "--regid=992", "--groups=992", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "/usr/local/bin/node", "/route-input/archive-source-force-replacement/protected-archive-replacement-probe.mjs"]
        or execution["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or execution["environment_names"] != [
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
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _EMPTY_DIGEST, "excerpt": ""}
        or set(stack) != {"enablement", "gateway_listener", "pids", "processes", "service_state", "sockets", "units"}
        or set(stack["pids"]) != units
        or set(stack["processes"]) != units
        or set(stack["units"]) != units
        or stack["pids"][gateway] != pid
        or stack["gateway_listener"]["pid"] != pid
        or process["pid"] != pid
        or process["uids"] != [992, 992, 992, 992]
        or process["gids"] != [992, 992, 992, 992]
        or process["groups"] != [992]
        or process["capabilities_effective"] != "0000000000000000"
        or process["no_new_privileges"] != 1
        or unit["User"] != "aragorn-agent-gateway"
        or unit["Group"] != "aragorn-agent-gateway"
        or unit["AmbientCapabilities"] != ""
        or unit["CapabilityBoundingSet"] != ""
        or unit["NoNewPrivileges"] != "yes"
        or unit["SupplementaryGroups"] != ""
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
            != f"/docker/{harness['container_id']}/system.slice/{name}"
            for name in units
        )
    ):
        raise AdmissionEvidenceError("V3 archive replacement execution boundary changed")
    current.base.legacy._verify_stack_boundary(
        stack,
        trusted=boundaries,
        container_id=harness["container_id"],
        snapshot_before=execution["started_at"],
    )
    current.base.legacy._verify_gateway_listener(
        stack["gateway_listener"], stack["processes"]
    )


def _verify_document(
    document: Mapping[str, Any],
    *,
    harness: Mapping[str, Any],
    execution: Mapping[str, Any],
    composition_recorded_at: str,
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
            "implementation_digest",
            "protected_boundary",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
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
            "discovery",
            "gateway_process",
            "openclaw",
            "positive_control",
            "ready",
            "reason_codes",
            "runtime_tree",
            "source",
            "system_info",
            "target_before",
            "version",
        }
        or set(after)
        != {
            "boundary_after",
            "discovery_after",
            "gateway_after",
            "runtime_tree_after",
            "source_after",
            "source_install",
            "staging_after",
            "staging_before",
            "target_after",
            "upload_begin",
            "upload_install",
        }
        or document["schema"] != "aragorn/openclaw-protected-archive-replacement-observation/v1"
        or document["assurance"] != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE_BUNDLE[0]["digest"]
        or document["recorded_at"] != "2026-08-31T18:15:23.489Z"
        or document["route"] != {"action_id": "archive-source-force-replacement", "id": _ROUTE, "reason_codes": [], "status": "OBSERVED"}
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["runtime_binding"]
        != {
            "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188",
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
            "version": "2026.7.1",
        }
        or canonical_digest(action) != _DIGESTS["action"]
        or action["id"] != "archive-source-force-replacement"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["ready"] is not True
        or before["reason_codes"] != []
        or after["staging_before"] != []
        or after["staging_after"] != []
        or after["source_after"] != before["source"]
        or after["target_after"] != before["target_before"]
        or after["runtime_tree_after"] != before["runtime_tree"]
        or after["gateway_after"] != before["gateway_process"]
    ):
        raise AdmissionEvidenceError("V3 archive replacement route changed")
    for name, value in (
        ("boundary_before", document["protected_boundary"]),
        ("boundary_after", after["boundary_after"]),
        ("discovery_before", before["discovery"]),
        ("discovery_after", after["discovery_after"]),
        ("gateway", before["gateway_process"]),
        ("openclaw", before["openclaw"]),
        ("positive_control", before["positive_control"]),
        ("runtime_tree", before["runtime_tree"]),
        ("source", before["source"]),
        ("source_install", after["source_install"]),
        ("system", before["system_info"]),
        ("target", before["target_before"]),
        ("upload_begin", after["upload_begin"]),
        ("upload_install", after["upload_install"]),
        ("version", before["version"]),
    ):
        if canonical_digest(value) != _STATIC_DIGESTS[name]:
            raise AdmissionEvidenceError(
                f"V3 archive replacement {name} identity changed"
            )
    root_paths = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    for boundary, workspace_residue in (
        (document["protected_boundary"], False),
        (after["boundary_after"], True),
    ):
        if (
            boundary["ready"] is not True
            or boundary["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
            or boundary["inputs"]["probe"]["read_only"] is not True
            or boundary["inputs"]["probe"]["path"] != "/route-input"
            or boundary["inputs"]["source"]["read_only"] is not True
            or boundary["inputs"]["source"]["path"] != "/sources"
            or boundary["runtime"]["read_only"] is not True
            or boundary["runtime"]["path"] != "/runtime"
        ):
            raise AdmissionEvidenceError("V3 archive replacement protected boundary changed")
        v3_contract._verify_config(boundary["configuration"])
        for name, path in root_paths.items():
            root = boundary["roots"][name]
            entry = root["observation"]
            entries = (
                ["template-skill"]
                if workspace_residue and name == "workspace_skills"
                else []
            )
            if (
                root["ready"] is not True
                or root["writable"] is not True
                or entry["path"] != path
                or entry["exists"] is not True
                or entry["type"] != "directory"
                or entry["uid"] != 992
                or entry["gid"] != 992
                or entry["mode"] != "700"
                or entry["entries"] != entries
                or entry["entry_count"] != len(entries)
                or entry["entries_truncated"] is not False
                or entry["nlink"] != 2 + len(entries)
            ):
                raise AdmissionEvidenceError(
                    f"V3 archive replacement conventional root changed: {name}"
                )
    semantics._verify_boundary_delta(document["protected_boundary"], after["boundary_after"])
    _verify_source_tree(before["source"])
    semantics.base._verify_target(before["target_before"])
    if (
        before["target_before"]["root"]["exists"] is not True
        or before["target_before"]["entries"][0]["exists"] is not True
    ):
        raise AdmissionEvidenceError("V3 archive replacement target absent")
    _verify_positive_control(before["positive_control"])
    semantics._verify_gateway_process(before["gateway_process"], harness["container_id"])
    semantics.base._verify_openclaw(before["openclaw"])
    if before["runtime_tree"] != current._RUNTIME_TREE:
        raise AdmissionEvidenceError("V3 archive replacement runtime tree changed")
    _verify_system(before["system_info"], before["gateway_process"])
    semantics.base._verify_version(before["version"])
    semantics.base._verify_discovery(before["discovery"])
    semantics._verify_upload_denial(after["upload_begin"], method="skills.upload.begin")
    semantics._verify_upload_denial(after["upload_install"], method="skills.install")
    semantics._verify_source_install(after["source_install"])
    semantics._verify_catalog_rejection(after["discovery_after"])
    commands = action["commands"]
    expected = [before["version"], before["system_info"]["command"], before["positive_control"]["install"], before["discovery"]["command"], after["upload_begin"]["command"], after["upload_install"]["command"], after["source_install"]["command"], after["discovery_after"]["command"]]
    parse = current.base.legacy._parse_time
    pids = [command["pid"] for command in commands]
    if (
        commands != expected
        or len(commands) != 8
        or len(set(pids)) != 8
        or any(type(pid) is not int or pid <= 1 for pid in pids)
        or any(parse(command["started_at"]) > parse(command["completed_at"]) for command in commands)
        or any(parse(left["completed_at"]) > parse(right["started_at"]) for left, right in pairwise(commands))
        or not (parse(execution["started_at"]) <= parse(commands[0]["started_at"]) <= parse(commands[-1]["completed_at"]) <= parse(document["recorded_at"]) <= parse(execution["completed_at"]) <= parse(composition_recorded_at) <= parse(outer_recorded_at))
    ):
        raise AdmissionEvidenceError("V3 archive replacement command causality changed")


def _verify_source_tree(value: Mapping[str, Any]) -> None:
    root = value["root"]
    skill = value["entries"][0]
    if (
        set(value) != {"entries", "ready", "root", "tree_digest"}
        or value["ready"] is not True
        or value["tree_digest"] != "sha256:5804c949da172dd474fd8c3c0c75a299364abec3e9e3ce362e48df50791a874d"
        or len(value["entries"]) != 1
        or root["path"] != "/sources/replacement"
        or root["exists"] is not True
        or root["type"] != "directory"
        or root["uid"] != 0 or root["gid"] != 992 or root["mode"] != "750"
        or root["nlink"] != 2
        or root["entries"] != ["SKILL.md"]
        or root["entry_count"] != 1
        or root["entries_truncated"] is not False
        or skill["path"] != "SKILL.md" or skill["uid"] != 0 or skill["gid"] != 992
        or skill["exists"] is not True
        or skill["type"] != "file"
        or skill["mode"] != "440" or skill["size"] != 144
        or skill["nlink"] != 1
        or skill["digest"] != "sha256:d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1"
        or skill["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("V3 archive replacement source tree changed")


def _verify_system(value: Mapping[str, Any], gateway: Mapping[str, Any]) -> None:
    command = value["command"]
    response = value["response"]
    system = response["value"]
    if (
        set(value) != {"command", "response"}
        or command["argv"]
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
        or not semantics.base._command_succeeded_clean(command)
        or not semantics.base._command_output_is_exact(command)
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
        or any(
            type(system[name]) is not int or system[name] <= 0
            for name in ("diskTotalBytes", "memoryTotalBytes", "uptimeMs")
        )
        or type(system["cpuCount"]) is not int
        or system["cpuCount"] < 0
        or not 0 <= system["memoryFreeBytes"] <= system["memoryTotalBytes"]
        or not 0 <= system["diskAvailableBytes"] <= system["diskTotalBytes"]
        or len(system["loadAverage"]) != 3
        or any(
            isinstance(item, bool) or not isinstance(item, (int, float))
            for item in system["loadAverage"]
        )
    ):
        raise AdmissionEvidenceError("V3 archive replacement system identity changed")


def _verify_positive_control(value: Mapping[str, Any]) -> None:
    target = value["target_after"]
    entries = {entry["path"]: entry for entry in target["entries"]}
    if (
        value["ready"] is not True
        or value["configuration_digest"]
        != "sha256:9b584ae1e25f46b4708aa135fe896f67358ef0229f4263d42dbf4a60af343d87"
        or value["target_before"] != {"exists": False, "path": "/tmp/aragorn-final-archive-control/workspace/skills/template-skill"}
        or value["install"]["argv"] != semantics._INSTALL_ARGV
        or not semantics.base._command_succeeded_clean(value["install"])
        or not semantics.base._command_output_is_exact(value["install"])
        or value["install"]["stdout_excerpt"]
        != (
            "Installing to /tmp/aragorn-final-archive-control/workspace/skills/"
            "template-skill…\nInstalled template-skill from path -> /tmp/aragorn-"
            "final-archive-control/workspace/skills/template-skill\n"
        )
        or target["tree_digest"] != "sha256:be494d7b06ff375ba9cc91e26f9ed8e6f3bf8679288d72fbd4cf8e95dd6a360f"
        or set(entries) != {".openclaw", "SKILL.md", ".openclaw/source-origin.json"}
        or entries["SKILL.md"]["digest"] != "sha256:d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1"
        or entries[".openclaw/source-origin.json"]["digest"] != "sha256:815deeb3fedc791f517d5ce69f6c609e3c67306eeed877eabc902435820e52c4"
    ):
        raise AdmissionEvidenceError("V3 archive replacement positive control changed")
