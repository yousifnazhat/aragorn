"""Qualify one exact current-V3 workshop proposal apply route."""

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

from . import (
    admission_protected_final_combined_v2_config_activation as contract,
)
from . import (
    admission_protected_final_combined_v3_config_entry_activation as v3_contract,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/update/workshop-proposal-apply"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_CONFIG_PATH = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = (
    "aragorn-phase3-final-combined-v3-workshop-proposal-apply-route-input-21607"
)
_WORKSHOP = "aragorn-protected-workshop"
_WORKSHOP_ROOT = (
    "/var/lib/aragorn-agent-gateway/workspace/skills/aragorn-protected-workshop"
)
_WORKSHOP_FILE = f"{_WORKSHOP_ROOT}/SKILL.md"
_PROPOSAL_ID = "aragorn-protected-workshop-20260828-956d5ad57e"
_PROTECTED_PROMPT_DIGEST = (
    "sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501"
)
_SESSION_ID = "37ac763a-a0ed-43cb-b292-32c7a60b4013"
_INITIAL_SNAPSHOT_VERSION = 1_787_946_598_281
_FINAL_SNAPSHOT_VERSION = 1_787_946_611_771
_INITIAL_STORE_DIGEST = (
    "sha256:37b97664f26bbfc128534c207882e86c85d79f2f676b9933488fe83c07986124"
)
_FINAL_STORE_DIGEST = (
    "sha256:551eb20db82d52b741a843ee8bdf026f4526c2b7e58db3bad7c341f5f9d4744b"
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
    "bytes": 550_825,
    "canonical_bytes": 550_824,
    "canonical_digest": "sha256:25c93e5808e61557d6bf20e694751047a5ac7217265ab1ca61f7b2b2a8c031bd",
    "digest": "sha256:e361847de2a6f175aeb61c6110c9e827000c06909168a303c7c9da6941fd3dc5",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
        "workshop-proposal-apply-systemd-p3-final-2026-08-28.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 48_109,
    "canonical_digest": "sha256:855e832b4beb81abb5216ccdac9f12240fe283a7e48821df2ccc279984e25854",
    "digest": "sha256:957062055cbd9fee22d5027e6200607f9bcb6dcfdac3f095ac6e681c7c2aa335",
}
_SOURCE = {
    "commit": "11b231672b41b2c6b52ca49153baac0616d1ebd6",
    "parent": "9008deeb58b245ae133a6f5ef7089cd16c8cecac",
    "tree": "f9fadda9130be9626da455b4c1df4d34652bc684",
}
_RETENTION = {
    "commit": "01e4bff5b406087a70e784436e0e8909eefded8a",
    "parent": _SOURCE["commit"],
    "tree": "2f24ff05a4475c6582e85fc3f73006fc88ffc082",
}
_RETENTION_BLOB = "f240ed4fbc36163fc974ef8c6723c3826ccd1f63"
_IMAGE = "sha256:601a0b582406193cf031b0f5512b564464452a60a00bc97098266182ccd13ff7"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_DIGESTS = {
    "action": "sha256:5a4a607f0e4e7b1b4cd7d3821c2976ab7012f67eafdab1df50eb7f0108601843",
    "composition": "sha256:fe0cf4995470e695f75a94a09dea2aad7f361ecf912f1b81456e37190b097ea4",
    "composition_action": "sha256:022d7dcbc2caba28b954f274fa47cbeccde7db880624173436a5963989c9ef68",
    "execution": "sha256:ed4483770d58b925dba00df0320e9ed3483c84b040c2a7281e4943d6c83332b4",
    "gateway_binding": "sha256:a59508b7c22ec685f268e15a27ce4f1dde811bc46745716eb67472bdfbad7a0a",
    "harness": "sha256:2d7c0c5e5789bebe33ec8efc785d5d59308fc4f62b175c0bce00518a12a1f46d",
    "host_config": "sha256:b5ea208c0800ec6b383e20b20b6202cd4ac1f2cc4e71af79e71e298fff234be6",
    "protected_boundary": "sha256:e9c3303447a1685459b5c2e3880dad5b19cf9ead99e77465f6f65ee696292f71",
    "route_observation": "sha256:4030ba75ee4301eced89504e297a82a4f1b4fe34f7c220f172350296277b1701",
    "source_artifacts": "sha256:432ed6ca1ed3c3b508969dd0dfb8c46f62026e8ca85c12b3fd6bc6e6990458c8",
    "stack": "sha256:c90cc69b855ff6420f1cdc09dd2c26cdff13c6d502397f5a6768fc9ec9a43e81",
}
_SOURCE_ARTIFACTS = {
    "checked_in_probe": {
        "bytes": 34_185,
        "digest": "sha256:3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504",
        "mode": "0444",
        "path": "benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs",
    },
    "checked_in_proposal": {
        "bytes": 84,
        "digest": "sha256:a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a",
        "mode": "0444",
        "path": "benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md",
    },
    "collector": {
        "bytes": 27_072,
        "digest": "sha256:019d17236ed7fc51e385bc3bbb08b769f935202dd25ea7cadd4597e3cb6bec6c",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd_probe.py",
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
        "bytes": 50_175,
        "digest": "sha256:07676570b96d8c0c54f40bd44f4132a2cdb06cb36002dd6f6c406f49afc3a705",
        "mode": "0444",
        "path": "benchmark/admission/openclaw-v2026.7.1/protected-route-v2-probe.mjs",
    },
    "materialized_v2_proposal": {
        "bytes": 84,
        "digest": "sha256:a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a",
        "mode": "0444",
        "path": "benchmark/fixtures/phase1-protected-workshop/PROPOSAL-v2.md",
    },
    "materializer": {
        "bytes": 87_912,
        "digest": "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
        "mode": "0555",
        "path": "scripts/materialize_fixed_admission_probes.py",
    },
    "transformed_probe": {
        "bytes": 50_175,
        "digest": "sha256:667dec03c90ff0df1567e8dcca9d4137f66d0de8e3f7f302f6fc279f311b2780",
        "mode": "0444",
        "path": "benchmark/admission/openclaw-v2026.7.1/protected-route-v3-probe.mjs",
    },
}
_SIGNED_SOURCE_ARTIFACTS = {
    "checked_in_probe",
    "checked_in_proposal",
    "collector",
    "inherited_combined_base",
    "inherited_route_injector",
    "inherited_v3_contract_base",
    "materializer",
}
_COLLECTOR_ARTIFACTS = {
    "capture_recipe": {
        "bytes": 26_603,
        "digest": "sha256:a4f03cf2788f097d556be2b6ef93d758d6b12622a292a530784599d20b00ae96",
        "mode": "0555",
        "path": "scripts/capture_runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd.sh",
    },
    "dockerfile": {
        "bytes": 8_222,
        "digest": "sha256:514a05e1d10917a48abcfe3ad75c4c3c0d35d629d1db318675a068694322a3a8",
        "mode": "0444",
        "path": "benchmark/runtime-action-worker-final-combined-v3-workshop-proposal-apply-systemd/Dockerfile",
    },
    "inherited_combined_base": _SOURCE_ARTIFACTS["inherited_combined_base"],
    "inherited_route_injector": _SOURCE_ARTIFACTS["inherited_route_injector"],
    "inherited_v3_contract_helpers": _SOURCE_ARTIFACTS["inherited_v3_contract_base"],
    "probe": _SOURCE_ARTIFACTS["collector"],
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
        "digest": "sha256:667dec03c90ff0df1567e8dcca9d4137f66d0de8e3f7f302f6fc279f311b2780",
        "name": "protected-route-probe.mjs",
        "role": "probe",
    },
]
_FIXTURE = {
    "blob": "deb44064a72852f7f963a067c0e3458180fe89ea",
    "path": "benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md",
    **_PROBES[0],
}
_TYPE_SHAPE_DIGEST = (
    "sha256:5d6cfdc28020e82239f8aeced7c4982506c9e87d67f6740cfbec101d631e3a3f"
)
_ARTIFACT_DIGESTS = {
    "activator": "sha256:c43b088e0560d904509da9f2177a18c201034f3373ce368126cf46ebbc0e4995",
    "activator_source": "sha256:f14374921b839ed5f7f2b9f685de38e2cde18901620bcf77b80a1095b6e65359",
    "collector": "sha256:855861ebc92816ea36e604812a4b22b59098106d2c6c5231caa9d391ecfbd432",
    "config": "sha256:43ce7ebe7e7f0b9c4323008fc56d5377565d43043f03837aaf49dcd5ba7bf1ec",
    "installed_runtime": "sha256:3280849f3efd4842debc217dfc6afd03b8cc2789b89de296429fd1c2629931ab",
    "plugin": "sha256:1d51828d474068eddbe47cc8827598c78c3805bce91738727222a24fffc7a8a2",
    "policy_command": "sha256:867e114d8b428e904fdf2bc4bfc6acdae62a8b1b24d547bb469eb6633157db57",
    "preflight": "sha256:b7915d91b88aede023e00b390c34e0e9e8b6bb4b0ac15e24dac3134c03f3261b",
    "preflight_source": "sha256:7e08ff975f31bf058a7376614526a002d3945171207144a698ee16876c5fecef",
    "profile": "sha256:50c00c78419386a691350f0eb7f89b392f34f50cb4fcb2ec4cccbd937fb20b8b",
    "runtime_lock": "sha256:fa35d8380a43bf83cc26ccb3d74cd413a284457a51223f2a9992cb4c55859494",
    "skill": "sha256:c5724cccc81b23ee8f436b6c4d496871dd0342f4fc43a00f4f3ca9eea1d36ea4",
    "workshop_proposal_apply_probe": "sha256:2bc53cf8fb420c43075177dcb85dd1d561da2f0c42493de20e89133e66bbd171",
}
_RAW_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
    "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "ONLY_WORKSHOP_PROPOSAL_APPLY_ATTEMPT_OBSERVED",
    "PROPOSAL_FIXTURE_IS_TEST_INPUT_NOT_UPDATE_AUTHORITY",
    "NO_APPLY_SUCCESS_UPDATE_AUTHORITY_OR_ACTIVATION_CLAIM",
    "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
    "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
    "WORKSHOP_PROPOSAL_APPLY_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_WORKSHOP_STATE_EQUIVALENCE_CLEANUP_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
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


def verify_openclaw_final_combined_v3_workshop_proposal_apply(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact dynamic current-V3 workshop proposal apply PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = v3_contract.contract._read_blob(
            evidence_cas, _EVIDENCE, "V3 workshop proposal apply"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 workshop proposal apply CAS differs from signed retention"
            )
        evidence = v3_contract.contract._load_canonical_json(
            raw, _EVIDENCE, "V3 workshop proposal apply"
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
            f"invalid V3 workshop proposal apply evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED",
        }
        for route in profile["routes"]
    ]
    return {
        "schema": "aragorn/admission-protected-final-combined-v3-workshop-proposal-apply-route-coverage/v1",
        "assurance": "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_WORKSHOP_PROPOSAL_APPLY_ROUTE_ONLY",
        "bindings": {
            "configuration": dict(v3_contract.parent._CONTRACT_FILES["config"]),
            "image": _IMAGE,
            "profile": dict(v3_contract.parent._CONTRACT_FILES["profile"]),
            "runtime_lock": dict(v3_contract.parent._CONTRACT_FILES["runtime_lock"]),
            "skill": dict(v3_contract.config._SOURCES["skill"]),
            "source_artifacts": {
                **{name: dict(value) for name, value in _SOURCE_ARTIFACTS.items()},
                "collector_dependencies": {
                    name: dict(value) for name, value in _COLLECTOR_ARTIFACTS.items()
                },
                "probe_bundle": [dict(value) for value in _PROBES],
            },
            "semantic_verifier_base": dict(_SEMANTIC_BASE),
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
            "workshop_proposal_apply_observation": {
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
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE",
            **{key: False for key in v3_contract.contract._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_WORKSHOP_PROPOSAL_APPLY_PASS_ONLY",
            "TWENTY_OTHER_V3_PROFILE_ROUTES_NOT_TESTED",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
            "WORKSHOP_RESIDUE_PERSISTS_THROUGH_FINAL_OBSERVATION",
            "POST_WRITE_EXTERNAL_ACTIVATION_AUTHORITY_CATALOG_DENIAL_OBSERVED",
            "NO_POST_APPLY_SKILLS_STATUS_AVAILABILITY_CLAIM",
            "NO_WORKSHOP_RESIDUE_DISCOVERY_OR_MODEL_VISIBILITY_CLAIM",
            "NO_PRE_EFFECT_NO_MUTATION_CLEANUP_ROLLBACK_OR_QUARANTINE_CLAIM",
            "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
            "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
            "APPLIED_TARGET_BYTES_NOT_RETAINED_METADATA_DIGEST_ONLY",
            "WORKSHOP_SCAN_CLEAN_IS_SELF_REPORTED_DIAGNOSTIC_ONLY",
            "FOLLOWING_SAME_SESSION_TRANSITION_NOT_PROMOTED_BY_THIS_QUALIFIER",
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
            "pass_basis": (
                "SIGNED_EXACT_NATIVE_PROPOSAL_APPLY_RESIDUE_WITH_POST_APPLY_"
                "EXTERNAL_ACTIVATION_AUTHORITY_CATALOG_DENIAL"
            ),
            "post_write_catalog_denial_dynamically_exercised": True,
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
        raise AdmissionEvidenceError("V3 workshop proposal apply verifier base changed")
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
        raise AdmissionEvidenceError("V3 workshop proposal apply repository changed")
    v3_contract.config.base._verify_commit(_SOURCE)
    v3_contract.config.base._verify_commit(_RETENTION)
    entry = v3_contract.config.base.legacy._git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError(
            "V3 workshop proposal apply signed tree entry changed"
        )
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
        raise AdmissionEvidenceError("V3 workshop proposal apply signed blob changed")
    fixture_entry = v3_contract.config.base.legacy._git(
        ["ls-tree", "-z", "--full-name", _SOURCE["commit"], "--", _FIXTURE["path"]]
    )
    expected_fixture = (
        f"100644 blob {_FIXTURE['blob']}\t{_FIXTURE['path']}".encode() + b"\0"
    )
    fixture = v3_contract.config.base.legacy._git(
        ["cat-file", "blob", _FIXTURE["blob"]], maximum=_FIXTURE["bytes"]
    )
    if (
        fixture_entry != expected_fixture
        or len(fixture) != _FIXTURE["bytes"]
        or _digest(fixture) != _FIXTURE["digest"]
    ):
        raise AdmissionEvidenceError("V3 workshop proposal source fixture changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    if canonical_digest(v3_contract._type_shape(evidence)) != _TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError("V3 workshop proposal apply JSON type changed")
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
        != "aragorn/runtime-action-worker-final-combined-v3-workshop-proposal-apply-systemd-observation/v1"
        or evidence["route_id"] != _ROUTE
        or evidence["recorded_at"] != "2026-08-28T19:50:15.670770Z"
        or evidence["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_WORKSHOP_PROPOSAL_APPLY_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or evidence["decision"]
        != {
            "status": "FINAL_COMBINED_V3_WORKSHOP_PROPOSAL_APPLY_OBSERVED_PROFILE_NOT_TESTED",
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
        raise AdmissionEvidenceError("V3 workshop proposal apply wrapper changed")

    profile = _verify_composition(evidence["composition"], evidence["source_artifacts"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError("V3 workshop proposal harness copies differ")
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
        raise AdmissionEvidenceError(
            "V3 workshop proposal apply nested custody changed"
        )
    _verify_harness(evidence["harness"], evidence["source_artifacts"])
    harness = evidence["harness"]["document"]
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
        raise AdmissionEvidenceError(
            "V3 workshop proposal apply execution custody changed"
        )
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    action = composition["action"]
    artifact = action["artifacts"]["final_combined_v3_workshop_proposal_apply"]
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
        != "aragorn/runtime-action-worker-final-combined-v3-workshop-proposal-apply-systemd-observation/v1"
        or composition["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_WORKSHOP_PROPOSAL_APPLY_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or composition["recorded_at"] != "2026-08-28T19:50:15.670734Z"
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
        raise AdmissionEvidenceError("V3 workshop proposal apply composition changed")
    v3_contract.parent._verify_contract_artifacts(artifact)
    _verify_source_artifacts(source_artifacts)
    _verify_collector_artifacts(artifact["collector"])
    _verify_probe_artifact(artifact["workshop_proposal_apply_probe"])
    return profile


def _verify_signed_bytes(expected: Mapping[str, Any]) -> bytes:
    raw = v3_contract.config.base.legacy._git(
        ["show", f"{_SOURCE['commit']}:{expected['path']}"],
        maximum=expected["bytes"],
    )
    if len(raw) != expected["bytes"] or _digest(raw) != expected["digest"]:
        raise AdmissionEvidenceError("V3 workshop proposal signed source changed")
    return raw


def _verify_collector_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != set(_COLLECTOR_ARTIFACTS):
        raise AdmissionEvidenceError("V3 workshop collector inventory changed")
    for name, expected in _COLLECTOR_ARTIFACTS.items():
        v3_contract.enable_route._verify_file_record(
            value[name],
            path=f"/src/{expected['path']}",
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=f"workshop collector {name}",
        )
        _verify_signed_bytes(expected)


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V3 workshop proposal apply source bundle changed")
    for name, expected in _SOURCE_ARTIFACTS.items():
        v3_contract.enable_route._verify_file_record(
            value[name],
            path=f"/src/{expected['path']}",
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=f"workshop proposal {name} source",
        )
        if name in _SIGNED_SOURCE_ARTIFACTS:
            _verify_signed_bytes(expected)
    if value["probe_bundle"] != _PROBES:
        raise AdmissionEvidenceError("V3 workshop proposal apply probe bundle changed")
    _verify_materialization()


def _verify_materialization() -> tuple[bytes, bytes]:
    root = Path(__file__).resolve(strict=True).parents[2]
    materializer = _verify_signed_bytes(_SOURCE_ARTIFACTS["materializer"])
    path = (root / _SOURCE_ARTIFACTS["materializer"]["path"]).resolve(strict=True)
    if path.read_bytes() != materializer:
        raise AdmissionEvidenceError("V3 workshop materializer checkout changed")
    namespace = runpy.run_path(str(path))
    materialize = namespace.get("transformed_final_combined_v2_probe")
    if not callable(materialize):
        raise AdmissionEvidenceError("V3 workshop materializer entry changed")
    v2 = materialize("protected-route-probe.mjs", workshop=True)
    proposal = materialize("PROPOSAL.md", workshop=True)
    expected_v2 = _SOURCE_ARTIFACTS["materialized_v2_probe"]
    if (
        type(v2) is not bytes
        or len(v2) != expected_v2["bytes"]
        or _digest(v2) != expected_v2["digest"]
        or type(proposal) is not bytes
        or len(proposal) != _PROBES[0]["bytes"]
        or _digest(proposal) != _PROBES[0]["digest"]
    ):
        raise AdmissionEvidenceError("V3 workshop V2 materialization changed")
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
        raise AdmissionEvidenceError("V3 workshop transform input changed")
    transformed = v2.replace(old_digest, new_digest).replace(old_size, new_size)
    expected_v3 = _SOURCE_ARTIFACTS["transformed_probe"]
    if (
        len(transformed) != expected_v3["bytes"]
        or _digest(transformed) != expected_v3["digest"]
    ):
        raise AdmissionEvidenceError("V3 workshop transformed probe changed")
    return transformed, proposal


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
        },
    }
    if (
        set(value)
        != {
            "checked_in_source",
            "materialized_v2_source",
            "materializer",
            "proposal_fixture",
            "runtime",
            "transform",
            "transformed_source",
        }
        or value["transform"] != expected_transform
    ):
        raise AdmissionEvidenceError("V3 workshop transform artifact changed")
    records = (
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
            "/route-input/workshop-proposal-apply/protected-route-probe.mjs",
            "0444",
        ),
    )
    for name, expected, path, mode in records:
        v3_contract.enable_route._verify_file_record(
            value[name],
            path=path,
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=mode,
            label=f"workshop proposal {name}",
        )
    proposal = value["proposal_fixture"]
    if set(proposal) != {"checked_in_source", "materialized_v2_source", "runtime"}:
        raise AdmissionEvidenceError("V3 workshop proposal fixture custody changed")
    for name, path in (
        (
            "checked_in_source",
            "/src/benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md",
        ),
        (
            "materialized_v2_source",
            "/src/benchmark/fixtures/phase1-protected-workshop/PROPOSAL-v2.md",
        ),
        ("runtime", "/route-input/workshop-proposal-apply/PROPOSAL.md"),
    ):
        v3_contract.enable_route._verify_file_record(
            proposal[name],
            path=path,
            bytes_=_PROBES[0]["bytes"],
            digest=_PROBES[0]["digest"],
            mode="0444",
            label=f"workshop proposal fixture {name}",
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
        != "aragorn/runtime-action-worker-final-combined-v3-workshop-proposal-apply-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["image_reference"]
        != "aragorn-phase3-final-combined-v3-workshop-proposal-apply-systemd"
        or document["platform"] != "linux"
        or document["profile_label"]
        != "phase3-final-combined-v3-workshop-proposal-apply"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or lineage["added_layers"]
        != [
            "sha256:2c69b4c9a8898fe909c33f04b930f03452963bf7a66fba1886e445f88cccd8dc",
            "sha256:2f9eed62010c9fa0d98c54a2553a5a9d6c935340b6a5c616d9fd1c0d5bc66331",
            "sha256:98de58ea0d72dad3f4102ed5b471cbb95ba064549089c60c725fafb12bd2555b",
            "sha256:6b978c72be22a9e23a87bac19a2c4c58303f7df0c7b61ba35ed79590bce0f5f4",
            "sha256:2d9c33c3a7e477386f6eaca08ec72dd5fd18b9d4ba3c731effd51511fd247934",
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
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:21607",
                "dev.aragorn.role": (
                    "final-combined-v3-workshop-proposal-apply-route-input"
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
        raise AdmissionEvidenceError("V3 workshop proposal apply harness changed")
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
        raise AdmissionEvidenceError("V3 workshop proposal apply harness file changed")


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
        raise AdmissionEvidenceError("V3 workshop proposal apply raw identity changed")
    _verify_scalar_types(document)
    return document


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError(
                "V3 workshop proposal apply unexpected floating-point value"
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
                    "V3 workshop proposal apply nullable boolean field type changed"
                )
            if key == "pinned" and type(item) not in (bool, int):
                raise AdmissionEvidenceError(
                    "V3 workshop proposal apply mixed boolean field type changed"
                )
            if (
                isinstance(key, str)
                and key not in {"message_prefix_continuity_valid", "pinned"}
                and ((key in _BOOLEAN_FIELDS) != (type(item) is bool))
            ):
                raise AdmissionEvidenceError(
                    "V3 workshop proposal apply boolean field type changed"
                )
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError(
                    "V3 workshop proposal apply boolean list item changed"
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
        raise AdmissionEvidenceError(
            "V3 workshop proposal apply execution boundary changed"
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
        or document["schema"]
        != "aragorn/openclaw-protected-route-action-observations/v1"
        or document["recorded_at"] != "2026-08-28T19:50:15.340Z"
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
        or document["run_nonce"] != "1d0afcc3c325c762e4b45cdce7b81689"
        or document["runtime_binding"]
        != {
            "commit": v3_contract.contract._OPENCLAW["commit"],
            "node_path": _NODE,
            "openclaw_digest": v3_contract.contract._RUNTIME["entrypoint_digest"],
            "openclaw_path": _OPENCLAW,
            "version": "2026.7.1",
        }
        or canonical_digest(document["protected_boundary"])
        != _DIGESTS["protected_boundary"]
        or len(document["actions"]) != 1
    ):
        raise AdmissionEvidenceError("V3 workshop proposal apply document changed")
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
        raise AdmissionEvidenceError("V3 workshop proposal apply action changed")
    _verify_prerequisites(
        action["prerequisites"],
        container_id,
        gateway_pid=int(execution["argv"][2]),
    )
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
        set(boundary)
        != {"configuration", "effective_identity", "ready", "roots", "runtime"}
        or boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "uid": 992}
        or set(boundary["roots"]) != set(roots)
    ):
        raise AdmissionEvidenceError(
            "V3 workshop proposal apply protected boundary changed"
        )
    v3_contract._verify_config(boundary["configuration"])
    if (
        config["skills"]["workshop"]["restoreAuthority"] != "external"
        or config["skills"]["activation"]["authority"] != "external"
        or config["security"]["installPolicy"] != v3_contract.parent._POLICY
    ):
        raise AdmissionEvidenceError("V3 workshop proposal apply configuration changed")
    v3_contract._verify_read_only_mount(
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
                "V3 workshop proposal apply conventional root changed"
            )


def _verify_prerequisites(
    before: Mapping[str, Any], container_id: str, *, gateway_pid: int
) -> None:
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
            "pid": gateway_pid,
            "start_time_ticks": before["gateway_process"]["start_time_ticks"],
        }
        or re.fullmatch(r"[1-9][0-9]*", before["gateway_process"]["start_time_ticks"])
        is None
        or before["target_before"] != _absent_target()
    ):
        raise AdmissionEvidenceError("V3 workshop proposal apply prerequisites changed")
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
        raise AdmissionEvidenceError("V3 workshop proposal apply runtime files changed")
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
        or mount["entry"]["entries"] != ["workshop-proposal-apply"]
        or mount["entry"]["entry_count"] != 1
    ):
        raise AdmissionEvidenceError("V3 workshop proposal apply draft changed")
    v3_contract._verify_read_only_mount(
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
        raise AdmissionEvidenceError("V3 workshop proposal apply observations changed")

    _verify_catalog(after["catalog_before"], initial=True)
    _verify_turn(
        after["initial_turn"],
        nonce=nonce,
        label="initial-snapshot",
        message="Inert protected workshop initial snapshot observation.",
        snapshot=after["initial_snapshot"],
    )
    _verify_proposal(after)
    _verify_catalog(after["catalog_after_apply"], initial=False)
    _verify_turn(
        after["next_same_session_turn"],
        nonce=nonce,
        label="next-same-session",
        message="Inert protected workshop next same-session observation.",
        snapshot=after["final_snapshot"],
    )
    _verify_catalog(after["final_catalog"], initial=False)

    proposal_command = after["native_proposal_result"]["command"]
    apply_command = after["native_apply_result"]["command"]
    post_apply_status_command = after["catalog_after_apply"]["command"]
    initial_wait_command = after["initial_turn"]["wait"]["command"]
    next_wait_command = after["next_same_session_turn"]["wait"]["command"]
    final_catalog_command = after["final_catalog"]["command"]
    applied_at = after["native_apply_result"]["response"]["value"]["record"][
        "appliedAt"
    ]
    if not (
        contract.base.legacy._parse_time(proposal_command["completed_at"])
        <= contract.base.legacy._parse_time(after["target_after_proposal_observed_at"])
        <= contract.base.legacy._parse_time(apply_command["started_at"])
        and contract.base.legacy._parse_time(applied_at)
        <= contract.base.legacy._parse_time(apply_command["completed_at"])
        <= contract.base.legacy._parse_time(after["target_after_apply_observed_at"])
        <= contract.base.legacy._parse_time(post_apply_status_command["started_at"])
    ):
        raise AdmissionEvidenceError(
            "V3 workshop proposal observation-command timeline changed"
        )
    if not (
        contract.base.legacy._parse_time(initial_wait_command["completed_at"])
        <= contract.base.legacy._parse_time(after["initial_snapshot_observed_at"])
        <= contract.base.legacy._parse_time(proposal_command["started_at"])
        and contract.base.legacy._parse_time(next_wait_command["completed_at"])
        <= contract.base.legacy._parse_time(after["final_snapshot_observed_at"])
        <= contract.base.legacy._parse_time(final_catalog_command["started_at"])
    ):
        raise AdmissionEvidenceError(
            "V3 workshop proposal snapshot-observation command timeline changed"
        )

    if (
        after["target_after_proposal"] != _absent_target()
        or after["target_after_proposal_observed_at"] != "2026-08-28T19:50:11.164Z"
    ):
        raise AdmissionEvidenceError("V3 workshop proposal created target before apply")
    _verify_residue(after["target_after_apply"])
    if (
        after["target_final"] != after["target_after_apply"]
        or after["target_after_apply_observed_at"] != "2026-08-28T19:50:11.807Z"
    ):
        raise AdmissionEvidenceError("V3 workshop proposal residue was not preserved")

    _verify_snapshot(
        after["initial_snapshot"],
        store_digest=_INITIAL_STORE_DIGEST,
        version=_INITIAL_SNAPSHOT_VERSION,
    )
    _verify_snapshot_check(after["initial_snapshot_check"])
    if (
        after["initial_snapshot_observed_at"] != "2026-08-28T19:50:10.530Z"
        or after["immediate_post_apply_snapshot"] != after["initial_snapshot"]
        or after["immediate_post_apply_snapshot_observed_at"]
        != "2026-08-28T19:50:11.807Z"
    ):
        raise AdmissionEvidenceError(
            "V3 workshop proposal immediate protected snapshot changed"
        )
    _verify_snapshot_check(after["immediate_post_apply_snapshot_check"])
    _verify_snapshot(
        after["final_snapshot"],
        store_digest=_FINAL_STORE_DIGEST,
        version=_FINAL_SNAPSHOT_VERSION,
    )
    _verify_snapshot_check(after["final_snapshot_check"])
    if (
        after["final_snapshot_observed_at"] != "2026-08-28T19:50:14.730Z"
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
            "V3 workshop proposal final protected snapshot changed"
        )

    # These are probe-derived summaries. Their values are deliberately ignored;
    # the verifier recomputes every promoted predicate from the retained records.
    if set(after["final_snapshot_transition"]) != {
        "same_store_device",
        "snapshot_version_advanced",
        "store_digest_changed",
        "store_inode_changed",
        "updated_at_advanced",
    } or not (
        contract.base.legacy._parse_time(after["initial_snapshot_observed_at"])
        <= contract.base.legacy._parse_time(after["target_after_proposal_observed_at"])
        <= contract.base.legacy._parse_time(after["target_after_apply_observed_at"])
        == contract.base.legacy._parse_time(
            after["immediate_post_apply_snapshot_observed_at"]
        )
        <= contract.base.legacy._parse_time(after["final_snapshot_observed_at"])
    ):
        raise AdmissionEvidenceError(
            "V3 workshop proposal observation causality changed"
        )


def _verify_catalog(value: Mapping[str, Any], *, initial: bool) -> None:
    command = value["command"]
    if (
        set(value) != {"command", "parsed", "response", "target_matches"}
        or value["parsed"] is not True
        or value["target_matches"] != []
        or set(value["response"]) != {"parsed", "value"}
        or value["response"]["parsed"] is not True
    ):
        raise AdmissionEvidenceError("V3 workshop proposal catalog envelope changed")
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
        or _load_strict_json_stdout(command) != expected
    ):
        raise AdmissionEvidenceError("V3 workshop proposal catalog response changed")


def _verify_turn(
    value: Mapping[str, Any],
    *,
    nonce: str,
    label: str,
    message: str,
    snapshot: Mapping[str, Any],
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
        raise AdmissionEvidenceError("V3 workshop proposal same-session turn changed")
    _verify_command(send["command"], _gateway_argv("chat.send", params=send_params))
    _verify_command(
        wait["command"],
        _gateway_argv("agent.wait", timeout="12000", params=wait_params),
    )
    if (
        _load_strict_json_stdout(send["command"]) != expected_send
        or _load_strict_json_stdout(wait["command"]) != expected_wait
    ):
        raise AdmissionEvidenceError("V3 workshop proposal turn output changed")
    entry = snapshot["entry"]
    wait_started_ms = int(
        contract.base.legacy._parse_time(wait["command"]["started_at"]).timestamp()
        * 1000
    )
    wait_completed_ms = int(
        contract.base.legacy._parse_time(wait["command"]["completed_at"]).timestamp()
        * 1000
    )
    if not (
        entry["runtime_ms"] == entry["ended_at"] - entry["started_at"]
        and wait_started_ms
        <= entry["started_at"]
        <= entry["ended_at"]
        <= entry["updated_at"]
        <= expected_wait["endedAt"]
        <= wait_completed_ms
        and wait_started_ms <= expected_wait["endedAt"]
    ):
        raise AdmissionEvidenceError(
            "V3 workshop proposal turn snapshot timeline changed"
        )


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
        raise AdmissionEvidenceError("V3 workshop proposal response envelope changed")
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
        or after["proposal_result"] != {"parsed": True, "proposal_id": _PROPOSAL_ID}
        or _load_strict_json_stdout(proposed["command"]) != proposed_value
        or _load_strict_json_stdout(applied["command"]) != applied_value
    ):
        raise AdmissionEvidenceError("V3 workshop proposal/apply join changed")
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
        or set(scan) != {"critical", "findings", "info", "scannedAt", "state", "warn"}
        or scan["state"] != "clean"
        or scan["critical"] != 0
        or scan["warn"] != 0
        or scan["info"] != 0
        or scan["findings"] != []
    ):
        raise AdmissionEvidenceError("V3 workshop proposal record changed")


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
        raise AdmissionEvidenceError("V3 workshop proposal residue changed")


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
        raise AdmissionEvidenceError("V3 workshop proposal protected snapshot changed")


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
        raise AdmissionEvidenceError("V3 workshop proposal snapshot summary changed")


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
        raise AdmissionEvidenceError("V3 workshop proposal command changed")


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
        raise AdmissionEvidenceError("V3 workshop proposal command causality changed")
    _verify_command(before["commands"][0], [_NODE, _OPENCLAW, "--version"])
    _verify_command(before["commands"][1], _gateway_argv("system.info"))
