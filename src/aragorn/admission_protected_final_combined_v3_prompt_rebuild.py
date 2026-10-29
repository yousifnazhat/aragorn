"""Qualify one exact current-V3 missing-prompt-blob rebuild route."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import (
    admission_protected_final_combined_v2_prompt_rebuild_catalog_fixed as semantics,
)
from . import (
    admission_protected_final_combined_v3_config_entry_activation as v3_contract,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

contract = v3_contract.contract
current = v3_contract.config

_ROUTE = "ADM-02/reload/missing-prompt-blob-rebuild"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v3-prompt-rebuild-route-input-93201"
_IMAGE = "sha256:69b63e03736a1bd22e13713094cb3d56343db488eba4b0c2c400f4808145fe60"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_PROBE_BUNDLE = [
    {
        "bytes": 16_464,
        "digest": "sha256:9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7",
        "name": "protected-prompt-rebuild-probe.mjs",
    },
    {
        "bytes": 16_324,
        "digest": "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        "name": "protected-observation-v1.mjs",
    },
]
_DEPENDENCIES = {
    "prompt_semantics": {
        "bytes": 48_056,
        "digest": "sha256:df9623c4ff226b070f7cfed903a79d86a4eef0ad757114e61847709485b3ac2e",
        "path": "admission_protected_final_combined_v2_prompt_rebuild_catalog_fixed.py",
    },
    "v3_contract": {
        "bytes": 57_245,
        "digest": "sha256:41a5c8e274b7f22e4cc79bde03917aea6717a83b3f810803d075e39c4b2afb5e",
        "path": "admission_protected_final_combined_v3_config_entry_activation.py",
    },
}
_EVIDENCE = {
    "bytes": 541_797,
    "canonical_bytes": 541_796,
    "canonical_digest": "sha256:99222acd19a19e626ee0154817e434d5fa86e6c63b2c1d24fca4d430adb5f26b",
    "digest": "sha256:533b9e0a905a2fe2314cb2f0a505618397975059080f77413af69fe776b0e5a5",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
        "missing-prompt-blob-rebuild-systemd-p3-final-2026-08-30.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 45_257,
    "canonical_digest": "sha256:6749aba2b933ed711d5923da052cdcb098b7750d8341521129da860620b338bd",
    "digest": "sha256:64db8f1e36876c7987317f3d68121a1643c3cb12f4e45e6986ae6892dd282d4f",
}
_SOURCE = {
    "commit": "78ee56edcc1da8140f943aaf401bf5d2ffaafb33",
    "parent": "342015b721661477c25105afb8ca299621071398",
    "tree": "096ab7544bbba822ca5769007b7cceb1a99f6919",
}
_RETENTION = {
    "commit": "e28f00aac697369ac3606be99f2657fb30e07136",
    "parent": _SOURCE["commit"],
    "tree": "b8711e6b00ce6df6dd48075a6b9c55218d118545",
}
_RETENTION_BLOB = "f4398c28c86969047b192dd3ac4ce8861ee97617"
_TYPE_SHAPE_DIGEST = (
    "sha256:a1f282bde8c6ad956e82d834f9045a711639ee3732d45d3e681c0d03af869358"
)
_ROUTE_TYPE_SHAPE_DIGEST = (
    "sha256:7f1223c2ee9fcf4d8d294074765f0cb7537fb13930b25146a0c1e13412531989"
)
_DIGESTS = {
    "action": "sha256:f5c3c1f2c152779b34d9c15049ea007834112652ac66afe3e95a6a82057571cd",
    "composition": "sha256:8c776ac6636f81c6bd87afe990429770576b5c2929fb94500ccca26bccff60f7",
    "composition_action": "sha256:dd67d97f99ccea291240a7592a088aa0f560c901a8cfe74f8341b1ecd3c132af",
    "execution": "sha256:df2bcfe364aaf0fa8bed1cbf0e12364156ccab05f588f31b9afbb5e8bb778c4b",
    "gateway_binding": "sha256:f778f523c28b96e85f1b9d80b5969ea8373996c5c2ea065cbc5f92bd5ccff2c0",
    "harness": "sha256:09bb5da73c092031a0050611eb6e8d64ff56ec8de4b8437a2c5180ea5cf27c0f",
    "host_config": "sha256:9580c42ba4f9b4056aa6088f9cce65ecce06ae253fc815d7228adc0ee549729f",
    "image_lineage": "sha256:99bb5cc91d262119980bf11368675f537a2e46751f051397b4a4af02f1a09d97",
    "route_observation": "sha256:53a7014660f7ef6e4f5dc54c7d63fd22b34f4fda2b308b800a87c38f4ab1b126",
    "source_artifacts": "sha256:fef8ba9acdb08baa1e2f5a0ec0c81853f6e16fb25b0a0c5a65b490a937298a7c",
    "stack": "sha256:65314396197bf6fd0d45fd9caf194b2a5e60fe5205acd490dd287adbdb0ffa53",
}
_STATIC_DIGESTS = {
    "boundary": "sha256:a18b263d6e1d5c6da0633e1e9cf2559a52759fe5b7df08a60c63b6b0af22cb31",
    "config_lock": "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2",
    "config_tree": "sha256:a8dd27e6b50c4937472da0edf1838af3d214140ee8a6822242e02a8a8f280041",
    "gateway": "sha256:45ff1ebe427944eafa50b8dd39e5256516a33b8609007a07d0b8e16cab342cf1",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "protected_roots": "sha256:20499490eb55be8194459099257531e46e3016ad978b9d645dfac07acc8aa43b",
    "runtime_tree": "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b",
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
}
_ARTIFACT_DIGESTS = {
    "activator": "sha256:c43b088e0560d904509da9f2177a18c201034f3373ce368126cf46ebbc0e4995",
    "activator_source": "sha256:f14374921b839ed5f7f2b9f685de38e2cde18901620bcf77b80a1095b6e65359",
    "collector": "sha256:8a3a8e453898c2211862a517f3999132f8606e2d9f46da394f7157ea20e64d8d",
    "config": "sha256:43ce7ebe7e7f0b9c4323008fc56d5377565d43043f03837aaf49dcd5ba7bf1ec",
    "plugin": "sha256:1d51828d474068eddbe47cc8827598c78c3805bce91738727222a24fffc7a8a2",
    "policy_command": "sha256:867e114d8b428e904fdf2bc4bfc6acdae62a8b1b24d547bb469eb6633157db57",
    "preflight": "sha256:b7915d91b88aede023e00b390c34e0e9e8b6bb4b0ac15e24dac3134c03f3261b",
    "profile": "sha256:50c00c78419386a691350f0eb7f89b392f34f50cb4fcb2ec4cccbd937fb20b8b",
    "prompt_rebuild_probe": "sha256:b9eb702495ece98e44fbeb3e448629d0e6656f4ba37209f54eeb99799e74b540",
    "runtime_lock": "sha256:fa35d8380a43bf83cc26ccb3d74cd413a284457a51223f2a9992cb4c55859494",
    "skill": "sha256:c5724cccc81b23ee8f436b6c4d496871dd0342f4fc43a00f4f3ca9eea1d36ea4",
}
_SOURCE_ARTIFACTS = {
    "checked_in_observation_helper": (
        13_609,
        "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b",
        "benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs",
        "0444",
    ),
    "checked_in_probe": (
        15_501,
        "sha256:f8fcfe8af1243c558ad071f7a001f84dca5cd219cdb069e64af6d48aac32d7eb",
        "benchmark/admission/openclaw-v2026.7.1/protected-prompt-rebuild-probe.mjs",
        "0444",
    ),
    "collector": (
        15_880,
        "sha256:bbee3b1ade76da1b4b4aa310231a5b856571a43e4f6543ec0e125eef1dd62280",
        "scripts/runtime_action_worker_final_combined_v3_prompt_rebuild_systemd_probe.py",
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
        27_082,
        "sha256:62023216d35e7e8d04296b9c05ca01588267933fab2720f80ad1c25a00fffd47",
        "scripts/capture_runtime_action_worker_final_combined_v3_prompt_rebuild_systemd.sh",
        "0555",
    ),
    "dockerfile": (
        7_002,
        "sha256:6bee0d3e9824e0e84d3259f5621d72d6eb4797e60323049280d0349984ff0c84",
        "benchmark/runtime-action-worker-final-combined-v3-prompt-rebuild-systemd/Dockerfile",
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
    "ONLY_MISSING_PROMPT_BLOB_REBUILD_ATTEMPT_OBSERVED",
    "NO_PROMPT_REBUILD_SUCCESS_PROMPT_RECONSTRUCTION_OR_MODEL_SUCCESS_CLAIM",
    "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
    "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
    "PROMPT_REBUILD_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_PROMPT_STATE_EQUIVALENCE_CLEANUP_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def verify_openclaw_final_combined_v3_prompt_rebuild(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact dynamic current-V3 prompt-rebuild PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract._read_blob(evidence_cas, _EVIDENCE, "V3 prompt rebuild")
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 prompt-rebuild CAS differs from signed retention"
            )
        evidence = contract._load_canonical_json(raw, _EVIDENCE, "V3 prompt rebuild")
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
            f"invalid V3 prompt-rebuild evidence: {exc}"
        ) from exc

    routes = [
        {"id": route["id"], "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED"}
        for route in profile["routes"]
    ]
    return {
        "schema": "aragorn/admission-protected-final-combined-v3-prompt-rebuild-route-coverage/v1",
        "assurance": "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_PROMPT_REBUILD_ROUTE_ONLY",
        "bindings": {
            "configuration": dict(v3_contract.parent._CONTRACT_FILES["config"]),
            "image": _IMAGE,
            "profile": dict(v3_contract.parent._CONTRACT_FILES["profile"]),
            "prompt_rebuild_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": contract._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(contract._SIGNATURE),
                },
            },
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
            "ONE_EXACT_DYNAMIC_PROMPT_REBUILD_PASS_ONLY",
            "TWENTY_OTHER_V3_PROFILE_ROUTES_NOT_TESTED",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
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
            "dynamically_exercised_routes": [_ROUTE],
            "pass_basis": "SIGNED_EXACT_PROMPT_BLOB_UNLINK_AND_RECONSTRUCTION_TRANSITION",
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_dependencies() -> None:
    directory = Path(__file__).resolve(strict=True).parent
    for name, module in (("prompt_semantics", semantics), ("v3_contract", v3_contract)):
        expected = _DEPENDENCIES[name]
        path = Path(module.__file__).resolve(strict=True)
        if (
            path != (directory / expected["path"]).resolve(strict=True)
            or path.stat().st_size != expected["bytes"]
            or _digest(path.read_bytes()) != expected["digest"]
        ):
            raise AdmissionEvidenceError(
                f"V3 prompt-rebuild dependency changed: {name}"
            )
    semantics._verify_dependencies()
    v3_contract._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = current.base.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild repository changed")
    current.base._verify_commit(_SOURCE)
    current.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V3 prompt-rebuild signed tree changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=600 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    if canonical_digest(v3_contract._type_shape(evidence)) != _TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError("V3 prompt-rebuild JSON type changed")
    semantics._verify_scalar_types(evidence)
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
        "status": "FINAL_COMBINED_V3_PROMPT_REBUILD_OBSERVED_PROFILE_NOT_TESTED",
    }
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
        != "aragorn/runtime-action-worker-final-combined-v3-prompt-rebuild-systemd-observation/v1"
        or evidence["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_PROMPT_REBUILD_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or evidence["recorded_at"] != "2026-08-30T17:36:09.870417Z"
        or evidence["route_id"] != _ROUTE
        or evidence["decision"] != decision
        or any(
            type(evidence["decision"][name]) is not int
            for name in ("route_fail_count", "route_not_tested_count", "route_pass_count")
        )
        or evidence["limitations"] != _RAW_LIMITATIONS
        or canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
        or canonical_digest(evidence["harness"]["document"])
        != _DIGESTS["harness"]
        or canonical_digest(evidence["route_observation"])
        != _DIGESTS["route_observation"]
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild wrapper changed")
    profile = _verify_composition(evidence["composition"], evidence["source_artifacts"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError("V3 prompt-rebuild harness copies differ")
    _verify_harness(evidence["harness"])
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
        or observation["bundle"] != _PROBE_BUNDLE
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild nested custody changed")
    harness = evidence["harness"]["document"]
    _verify_execution(
        observation, evidence["composition"]["action"]["boundaries"], harness
    )
    _verify_route_contract(document, harness["container_id"])
    if not (
        current.base.legacy._parse_time(document["recorded_at"])
        <= current.base.legacy._parse_time(observation["execution"]["completed_at"])
        <= current.base.legacy._parse_time(evidence["composition"]["action"]["recorded_at"])
        <= current.base.legacy._parse_time(evidence["composition"]["recorded_at"])
        <= current.base.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild execution custody changed")
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    action = composition["action"]
    artifact = action["artifacts"]["final_combined_v3_prompt_rebuild"]
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
        != "aragorn/runtime-action-worker-final-combined-v3-prompt-rebuild-systemd-observation/v1"
        or composition["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_PROMPT_REBUILD_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or composition["recorded_at"] != "2026-08-30T17:36:09.870382Z"
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
            "runtime_digest": current._RUNTIME_TREE["tree_digest"],
            "runtime_volume": _RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": current._SOURCES["skill"]["digest"],
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
        or [route["id"] for route in profile["routes"]] != list(contract._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile["runtime"]
        != {**contract._OPENCLAW, "name": "openclaw-protected-final-combined-v3"}
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild composition changed")
    v3_contract.parent._verify_contract_artifacts(artifact)
    _verify_source_artifacts(source_artifacts)
    _verify_collector_artifacts(artifact["collector"])
    _verify_probe_artifact(artifact["prompt_rebuild_probe"])
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
        ["show", f"{_SOURCE['commit']}:{identity['path']}"], maximum=identity["bytes"]
    )
    if len(raw) != identity["bytes"] or _digest(raw) != identity["digest"]:
        raise AdmissionEvidenceError(f"V3 prompt-rebuild signed source changed: {label}")


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V3 prompt-rebuild source inventory changed")
    for name, expected in _SOURCE_ARTIFACTS.items():
        _verify_signed_record(value[name], expected, f"source {name}")
    if value["probe_bundle"] != _PROBE_BUNDLE:
        raise AdmissionEvidenceError("V3 prompt-rebuild probe bundle changed")


def _verify_collector_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != set(_COLLECTOR_ARTIFACTS):
        raise AdmissionEvidenceError("V3 prompt-rebuild collector inventory changed")
    for name, expected in _COLLECTOR_ARTIFACTS.items():
        _verify_signed_record(value[name], expected, f"collector {name}")


def _verify_probe_artifact(value: Mapping[str, Any]) -> None:
    if (
        set(value)
        != {
            "checked_in_observation_helper",
            "checked_in_probe",
            "fixed_materializer",
            "probe_bundle",
            "rebound_materializer",
            "runtime_observation_helper",
            "runtime_probe",
        }
        or value["probe_bundle"] != _PROBE_BUNDLE
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild probe artifact changed")
    for name in (
        "checked_in_observation_helper",
        "checked_in_probe",
        "fixed_materializer",
        "rebound_materializer",
    ):
        expected = _SOURCE_ARTIFACTS[name]
        v3_contract.enable_route._verify_file_record(
            value[name],
            path=f"/src/{expected[2]}",
            bytes_=expected[0],
            digest=expected[1],
            mode=expected[3],
            label=f"probe {name}",
        )
    for name, bundle in (
        ("runtime_probe", _PROBE_BUNDLE[0]),
        ("runtime_observation_helper", _PROBE_BUNDLE[1]),
    ):
        v3_contract.enable_route._verify_file_record(
            value[name],
            path=f"/route-input/missing-prompt-blob-rebuild/{bundle['name']}",
            bytes_=bundle["bytes"],
            digest=bundle["digest"],
            mode="0444",
            label=name,
        )


def _verify_harness(envelope: Mapping[str, Any]) -> None:
    document = envelope["document"]
    file = envelope["file"]
    raw = base64.b64decode(file["base64"], validate=True)
    parsed = json.loads(
        raw.decode(),
        object_pairs_hook=contract._reject_duplicates,
        parse_constant=contract._reject_constant,
    )
    lineage = document["image_lineage"]
    if (
        set(envelope) != {"digest", "document", "file"}
        or parsed != document
        or raw != canonical_json(document)
        or envelope["digest"] != _DIGESTS["harness"]
        or file["digest"] != _DIGESTS["harness"]
        or file["bytes"] != len(raw)
        or file["path"] != "/run/aragorn-harness.json"
        or document["schema"]
        != "aragorn/runtime-action-worker-final-combined-v3-prompt-rebuild-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["image_reference"]
        != "aragorn-phase3-final-combined-v3-prompt-rebuild-systemd"
        or document["profile_label"] != "phase3-final-combined-v3-prompt-rebuild"
        or document["platform"] != "linux"
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
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:93201",
            "dev.aragorn.role": "final-combined-v3-prompt-rebuild-route-input",
            "dev.aragorn.source-commit": _SOURCE["commit"],
        }
        or document["openclaw_runtime_volume"] != _RUNTIME_VOLUME
        or document["openclaw_runtime_volume_identity"]["name"] != _RUNTIME_VOLUME
        or canonical_digest(lineage) != _DIGESTS["image_lineage"]
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or document["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or document["source_commit_verification"]["exit_code"] != 0
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild harness changed")
    stat = file["stat"]
    if (
        stat["uid"] != 0
        or stat["gid"] != 0
        or stat["mode"] != "0600"
        or stat["nlink"] != 1
        or stat["size"] != len(raw)
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild harness file changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V3 prompt-rebuild raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode(),
        object_pairs_hook=contract._reject_duplicates,
        parse_constant=contract._reject_constant,
    )
    canonical = canonical_json(document)
    if (
        not isinstance(document, dict)
        or raw == canonical + b"\n"
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not False
        or canonical_digest(v3_contract._type_shape(document))
        != _ROUTE_TYPE_SHAPE_DIGEST
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild raw identity changed")
    semantics._verify_scalar_types(document)
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
    container_id = harness["container_id"]
    gateway = "aragorn-agent-gateway.service"
    units = {
        gateway,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    if (
        canonical_digest(execution) != _DIGESTS["execution"]
        or canonical_digest(binding) != _DIGESTS["gateway_binding"]
        or canonical_digest(stack) != _DIGESTS["stack"]
        or type(pid) is not int
        or pid <= 0
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
            "unit": gateway,
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
            "/route-input/missing-prompt-blob-rebuild/protected-prompt-rebuild-probe.mjs",
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
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _EMPTY_DIGEST, "excerpt": ""}
        or set(stack["units"]) != units
        or set(stack["pids"]) != units
        or set(stack["processes"]) != units
        or stack["pids"][gateway] != pid
        or stack["gateway_listener"]["pid"] != pid
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
            current.base.legacy._parse_time(execution["started_at"])
            <= current.base.legacy._parse_time(
                observation["document"]["action"]["commands"][0]["started_at"]
            )
            <= current.base.legacy._parse_time(
                observation["document"]["action"]["commands"][-1]["completed_at"]
            )
            <= current.base.legacy._parse_time(observation["document"]["recorded_at"])
            <= current.base.legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild execution boundary changed")
    current.base.legacy._verify_stack_boundary(
        stack,
        trusted=boundaries,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    current.base.legacy._verify_gateway_listener(
        stack["gateway_listener"], stack["processes"]
    )


def _verify_route_contract(document: Mapping[str, Any], container_id: str) -> None:
    if (
        set(document)
        != {
            "action",
            "assurance",
            "implementation_digests",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-prompt-rebuild-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digests"]
        != {"helper": _PROBE_BUNDLE[1]["digest"], "probe": _PROBE_BUNDLE[0]["digest"]}
        or document["route"]
        != {
            "action_id": "missing-prompt-blob-rebuild",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["runtime_binding"]
        != {
            "commit": contract._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": contract._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": current._RUNTIME_TREE["tree_digest"],
            "version": contract._OPENCLAW["version"],
        }
        or canonical_digest(document["action"]) != _DIGESTS["action"]
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild route changed")
    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    stable = {
        "boundary": (before["boundary_before"], after["boundary_after"]),
        "config_lock": (before["config_lock_before"], after["config_lock_after"]),
        "config_tree": (before["config_tree_before"], after["config_tree_after"]),
        "gateway": (before["gateway_process_before"], after["gateway_process_after"]),
        "openclaw": (before["openclaw_before"], after["openclaw_after"]),
        "protected_roots": (
            before["protected_root_trees_before"],
            after["protected_root_trees_after"],
        ),
        "runtime_tree": (before["runtime_tree_before"], after["runtime_tree_after"]),
        "target": (before["target_before"], after["target_after"]),
    }
    if (
        action["id"] != "missing-prompt-blob-rebuild"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["session_entry_absent_before"] is not True
        or any(left != right for left, right in stable.values())
        or any(
            canonical_digest(left) != _STATIC_DIGESTS[name]
            for name, (left, _right) in stable.items()
        )
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild protected state changed")
    _verify_current_boundary(before, container_id)
    semantics._verify_commands(action, document["run_nonce"], document["recorded_at"])
    semantics.semantic._verify_rebuild(after)
    semantics._verify_rebuild_chronology(after, document["recorded_at"])


def _verify_current_boundary(before: Mapping[str, Any], container_id: str) -> None:
    boundary = before["boundary_before"]
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or before["runtime_tree_before"] != current._RUNTIME_TREE
        or before["config_lock_before"]
        != {
            "exists": False,
            "path": "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock",
        }
    ):
        raise AdmissionEvidenceError("V3 prompt-rebuild current contract changed")
    v3_contract._verify_config(boundary["configuration"])
    current._verify_target(before["target_before"])
    current._verify_gateway(before["gateway_process_before"], container_id)
    current._verify_openclaw(before["openclaw_before"])
    v3_contract._verify_read_only_mount(
        boundary["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{_RUNTIME_VOLUME}/_data",
    )
    v3_contract._verify_read_only_mount(
        boundary["probe"],
        path="/route-input",
        source=f"/docker/volumes/{_ROUTE_VOLUME}/_data",
    )
    root_paths = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    if set(boundary["roots"]) != set(root_paths):
        raise AdmissionEvidenceError("V3 prompt-rebuild protected roots changed")
    for name, path in root_paths.items():
        value = boundary["roots"][name]
        entry = value["observation"]
        if (
            value["ready"] is not True
            or value["writable"] is not True
            or entry["exists"] is not True
            or entry["path"] != path
            or entry["type"] != "directory"
            or entry["uid"] != 992
            or entry["gid"] != 992
            or entry["mode"] != "700"
            or entry["entries"] != []
            or entry["entry_count"] != 0
            or entry["entries_truncated"] is not False
        ):
            raise AdmissionEvidenceError("V3 prompt-rebuild protected roots changed")
