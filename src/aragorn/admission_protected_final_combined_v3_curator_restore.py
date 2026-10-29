"""Qualify one exact current-V3 curator restore denial route."""

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

from . import (
    admission_protected_final_combined_v2_curator_restore as semantics,
)
from . import (
    admission_protected_final_combined_v3_config_entry_activation as v3_contract,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

contract = v3_contract.contract
current = v3_contract.config

_ROUTE = "ADM-02/update/curator-restore-activation"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v3-curator-restore-route-input-30420"
_IMAGE = "sha256:a804840dd279ed38a3214d9a9153e2bacc29db563350496e5fbdcb178613c320"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_PROBE_BUNDLE = [
    {
        "bytes": 26_571,
        "digest": "sha256:fd3fa9ec7dce5b626eb1243c3391279093d08555e7c81f67d1b4549160fca089",
        "name": "protected-curator-restore-denial-probe.mjs",
    },
    {
        "bytes": 16_324,
        "digest": "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        "name": "protected-observation-v1.mjs",
    },
]
_DEPENDENCIES = {
    "curator_semantics": {
        "bytes": 58_492,
        "digest": "sha256:f03ae87ea84a8dc7af9596e79db7cc573b8ac1027949bf6e914674251008eaa6",
        "path": "admission_protected_final_combined_v2_curator_restore.py",
    },
    "curator_semantics_contract": {
        "bytes": 58_642,
        "digest": "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6",
        "path": "admission_protected_final_combined_v2_config_activation.py",
    },
    "v3_contract": {
        "bytes": 57_245,
        "digest": "sha256:41a5c8e274b7f22e4cc79bde03917aea6717a83b3f810803d075e39c4b2afb5e",
        "path": "admission_protected_final_combined_v3_config_entry_activation.py",
    },
}
_EVIDENCE = {
    "bytes": 575_266,
    "canonical_bytes": 575_265,
    "canonical_digest": "sha256:2aaa6ad9fa08305177a3276670fa79d89b56ab3a48da45458ea43f2ec1691113",
    "digest": "sha256:52188c09dbb0a114d1fee48b4e85b42e201ab0463e813e4365e49c0cb8e78c05",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
        "curator-restore-activation-systemd-p3-final-2026-08-30.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 60_323,
    "canonical_digest": "sha256:6ec53e7c1faa68ae682da0c08fcf3376d906c49b1da350d9129676c3d118d467",
    "digest": "sha256:cabed81080c914d6ef937008045854b140ef9baad25cc7e8fb1d01beac6e0f58",
}
_SOURCE = {
    "commit": "7177974fef382fda095e3e9aa25eee08dea86074",
    "parent": "a3f4affb84d0da40c69e91995ad678ec824b7f82",
    "tree": "600937bfb5f34292e9da7ffbbaf197fa027ea8cb",
}
_RETENTION = {
    "commit": "83da88245bc677f7a04111c8fd23cdff1051fd3a",
    "parent": _SOURCE["commit"],
    "tree": "5d40db9a3ec425e5b1c88d7859295bd66d0f1eca",
}
_RETENTION_BLOB = "1f09e8a0563f67cdcc1edd13a6a3f47a12bd5150"
_TYPE_SHAPE_DIGEST = (
    "sha256:9ed6ab569c6d729e141f4fd564ec97f5a2a15aa615ab05a060de4cabbec62f3c"
)
_ROUTE_TYPE_SHAPE_DIGEST = (
    "sha256:61b0019119507295523ed70475327e81e510bf3ca9c778171e9174088d5e9799"
)
_DIGESTS = {
    "action": "sha256:1f07e58ea085f0d490f9ecaca783fde20d2e2962671cd130ea048f17ad5b41c3",
    "composition": "sha256:ee0fd5a0885f82f19f99396c54f1ed8e7b5f8e5cc03ac80debbc94ae7088f8e8",
    "composition_action": "sha256:eb860f52d9c1d3c4844a300841b03947bc046402840812c9c59f11ec4c36b4f8",
    "execution": "sha256:89431d438d904caeaf2deb0d41db86fdaaa2588740db340a0524521a3799fcb6",
    "gateway_binding": "sha256:8d60494d20918096d7667a7b22005ad9a615f24955d38623dae3c82511f2e0f4",
    "harness": "sha256:89892281139b71baef568e85bdad66f31a8b40cc9f86e1fc5fb4d5080755fd2b",
    "host_config": "sha256:122f1f5330270f4d3141ca73d3f0807641626f7de8566df4fbb34068c224fc2f",
    "image_lineage": "sha256:5bc636d0db5cf51c5ef9dbffe16a5dd18d5003c766a88c22d6ff26dbf3ceb24f",
    "route_observation": "sha256:c613df420f58ace23cdb5859439ada51c19b81a7783e789c2297b61afcf77327",
    "source_artifacts": "sha256:3bf4150dd8589038f6bbeb894743277eca71cf55db40601427d2403d16fad1c6",
    "stack": "sha256:617ba1c446fb1f0726d6459f9dfe08ab15c9e9098ed4382cb13e0bfc212fdac4",
}
_STATIC_DIGESTS = {
    "boundary": "sha256:774cd363c6f141ec1c70ca4561b353c4d32b61c578e09a585a39409df5126a66",
    "config_lock": "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2",
    "config_tree": "sha256:a62dd188176f864a44160b6a241580c50621ba1e81fb9e55e34ed248f0fc91bb",
    "gateway": "sha256:245af7e7676ccbfc85412d5e8abeea5edc2ef92eca56d38ecbd90faa812cb91e",
    "modules": "sha256:3ef18a07efd8f4c52c9bba0e4d512d23357fa0ce3b7b7afd5c033b33a2aba25f",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "protected_roots": "sha256:d89847615795fb2fbae6068b7b7a38188ed91405bbab1433e26538f7e567b165",
    "runtime_tree": "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b",
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
}
_ARTIFACT_DIGESTS = {
    "activator": "sha256:c43b088e0560d904509da9f2177a18c201034f3373ce368126cf46ebbc0e4995",
    "activator_source": "sha256:f14374921b839ed5f7f2b9f685de38e2cde18901620bcf77b80a1095b6e65359",
    "collector": "sha256:4c54420a69a9e1e27055e0ce788ce18123ed3135b9ad875fda3d5a03d3a52097",
    "config": "sha256:43ce7ebe7e7f0b9c4323008fc56d5377565d43043f03837aaf49dcd5ba7bf1ec",
    "curator_restore_probe": "sha256:7972a2bc1c3da77001fb4da2e85a1fc3962f26dd0e87d72df80487faee20feb0",
    "plugin": "sha256:1d51828d474068eddbe47cc8827598c78c3805bce91738727222a24fffc7a8a2",
    "policy_command": "sha256:867e114d8b428e904fdf2bc4bfc6acdae62a8b1b24d547bb469eb6633157db57",
    "preflight": "sha256:b7915d91b88aede023e00b390c34e0e9e8b6bb4b0ac15e24dac3134c03f3261b",
    "profile": "sha256:50c00c78419386a691350f0eb7f89b392f34f50cb4fcb2ec4cccbd937fb20b8b",
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
        24_502,
        "sha256:ecc2649b40cc9e6106181a12a31b12999a596d634f7a1ee9cc658adc70c9192a",
        "benchmark/admission/openclaw-v2026.7.1/protected-curator-restore-denial-probe.mjs",
        "0444",
    ),
    "collector": (
        15_941,
        "sha256:e629878f8afebc96d329410ffa8d06bc7c58b0994e6a13eba6933c5f243a1e36",
        "scripts/runtime_action_worker_final_combined_v3_curator_restore_systemd_probe.py",
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
        27_150,
        "sha256:190ae493be8969e9645b0a32581240ed9fe2749fb2bc573ddef2c871a49c98a2",
        "scripts/capture_runtime_action_worker_final_combined_v3_curator_restore_systemd.sh",
        "0555",
    ),
    "dockerfile": (
        7_062,
        "sha256:c38a1d33c384ec322844d1e8f8569742c077465f411f6bb1296dfdd2425bb953",
        "benchmark/runtime-action-worker-final-combined-v3-curator-restore-systemd/Dockerfile",
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
    "ONLY_CURATOR_RESTORE_ACTIVATION_ATTEMPT_OBSERVED",
    "NO_CURATOR_RESTORE_DENIAL_CONFORMANCE_OR_SKILL_ACTIVATION_CLAIM",
    "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
    "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
    "CURATOR_RESTORE_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_CURATOR_STATE_EQUIVALENCE_CLEANUP_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def verify_openclaw_final_combined_v3_curator_restore(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact dynamic current-V3 curator-restore PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract._read_blob(evidence_cas, _EVIDENCE, "V3 curator restore")
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 curator-restore CAS differs from signed retention"
            )
        evidence = contract._load_canonical_json(raw, _EVIDENCE, "V3 curator restore")
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
            f"invalid V3 curator-restore evidence: {exc}"
        ) from exc

    routes = [
        {"id": route["id"], "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED"}
        for route in profile["routes"]
    ]
    return {
        "schema": "aragorn/admission-protected-final-combined-v3-curator-restore-route-coverage/v1",
        "assurance": "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_CURATOR_RESTORE_ROUTE_ONLY",
        "bindings": {
            "configuration": dict(v3_contract.parent._CONTRACT_FILES["config"]),
            "image": _IMAGE,
            "profile": dict(v3_contract.parent._CONTRACT_FILES["profile"]),
            "curator_restore_observation": {
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
            "ONE_EXACT_DYNAMIC_CURATOR_RESTORE_DENIAL_PASS_ONLY",
            "TWENTY_OTHER_V3_PROFILE_ROUTES_NOT_TESTED",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
            "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
            "EXACT_SELECTED_LIFECYCLE_ROW_ONLY_NOT_FULL_DATABASE_STATE",
            "SKILLS_STATUS_ARCHIVED_DIAGNOSTIC_NOT_ACTIVE_CONSUMER_PROOF",
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
            "pass_basis": (
                "SIGNED_EXACT_EXTERNAL_AUTHORITY_AND_INVALID_TOKEN_CURATOR_RESTORE_"
                "DENIAL_LIFECYCLE_WITH_SYNTHETIC_ARCHIVED_ROW_PRESERVED"
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
    modules = {
        "curator_semantics": semantics,
        "curator_semantics_contract": semantics.contract,
        "v3_contract": v3_contract,
    }
    for name, module in modules.items():
        expected = _DEPENDENCIES[name]
        path = Path(module.__file__).resolve(strict=True)
        if (
            path != (directory / expected["path"]).resolve(strict=True)
            or path.stat().st_size != expected["bytes"]
            or _digest(path.read_bytes()) != expected["digest"]
        ):
            raise AdmissionEvidenceError(
                f"V3 curator-restore dependency changed: {name}"
            )
    if semantics.contract is not current:
        raise AdmissionEvidenceError("V3 curator-restore contract identity changed")
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
        raise AdmissionEvidenceError("V3 curator-restore repository changed")
    current.base._verify_commit(_SOURCE)
    current.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V3 curator-restore signed tree changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=600 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V3 curator-restore signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    if canonical_digest(v3_contract._type_shape(evidence)) != _TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError("V3 curator-restore JSON type changed")
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
        "status": "FINAL_COMBINED_V3_CURATOR_RESTORE_OBSERVED_PROFILE_NOT_TESTED",
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
        != "aragorn/runtime-action-worker-final-combined-v3-curator-restore-systemd-observation/v1"
        or evidence["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_CURATOR_RESTORE_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or evidence["recorded_at"] != "2026-08-31T00:13:45.597255Z"
        or evidence["route_id"] != _ROUTE
        or evidence["decision"] != decision
        or any(
            type(evidence["decision"][name]) is not int
            for name in (
                "route_fail_count",
                "route_not_tested_count",
                "route_pass_count",
            )
        )
        or evidence["limitations"] != _RAW_LIMITATIONS
        or canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
        or canonical_digest(evidence["harness"]["document"]) != _DIGESTS["harness"]
        or canonical_digest(evidence["route_observation"])
        != _DIGESTS["route_observation"]
    ):
        raise AdmissionEvidenceError("V3 curator-restore wrapper changed")
    profile = _verify_composition(evidence["composition"], evidence["source_artifacts"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError("V3 curator-restore harness copies differ")
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
        raise AdmissionEvidenceError("V3 curator-restore nested custody changed")
    harness = evidence["harness"]["document"]
    _verify_execution(
        observation, evidence["composition"]["action"]["boundaries"], harness
    )
    _verify_route_contract(
        document,
        container_id=harness["container_id"],
        execution=observation["execution"],
        outer_recorded_at=evidence["recorded_at"],
    )
    if not (
        current.base.legacy._parse_time(document["recorded_at"])
        <= current.base.legacy._parse_time(observation["execution"]["completed_at"])
        <= current.base.legacy._parse_time(
            evidence["composition"]["action"]["recorded_at"]
        )
        <= current.base.legacy._parse_time(evidence["composition"]["recorded_at"])
        <= current.base.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V3 curator-restore execution custody changed")
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    action = composition["action"]
    artifact = action["artifacts"]["final_combined_v3_curator_restore"]
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
        != "aragorn/runtime-action-worker-final-combined-v3-curator-restore-systemd-observation/v1"
        or composition["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_CURATOR_RESTORE_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or composition["recorded_at"] != "2026-08-31T00:13:45.597201Z"
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
        raise AdmissionEvidenceError("V3 curator-restore composition changed")
    v3_contract.parent._verify_contract_artifacts(artifact)
    _verify_source_artifacts(source_artifacts)
    _verify_collector_artifacts(artifact["collector"])
    _verify_probe_artifact(artifact["curator_restore_probe"])
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
        raise AdmissionEvidenceError(
            f"V3 curator-restore signed source changed: {label}"
        )


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V3 curator-restore source inventory changed")
    for name, expected in _SOURCE_ARTIFACTS.items():
        _verify_signed_record(value[name], expected, f"source {name}")
    if value["probe_bundle"] != _PROBE_BUNDLE:
        raise AdmissionEvidenceError("V3 curator-restore probe bundle changed")


def _verify_collector_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != set(_COLLECTOR_ARTIFACTS):
        raise AdmissionEvidenceError("V3 curator-restore collector inventory changed")
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
        raise AdmissionEvidenceError("V3 curator-restore probe artifact changed")
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
            path=f"/route-input/curator-restore-activation/{bundle['name']}",
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
        != "aragorn/runtime-action-worker-final-combined-v3-curator-restore-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["image_reference"]
        != "aragorn-phase3-final-combined-v3-curator-restore-systemd"
        or document["profile_label"] != "phase3-final-combined-v3-curator-restore"
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
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:30420",
            "dev.aragorn.role": "final-combined-v3-curator-restore-route-input",
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
        raise AdmissionEvidenceError("V3 curator-restore harness changed")
    stat = file["stat"]
    if (
        stat["uid"] != 0
        or stat["gid"] != 0
        or stat["mode"] != "0600"
        or stat["nlink"] != 1
        or stat["size"] != len(raw)
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError("V3 curator-restore harness file changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V3 curator-restore raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode(),
        object_pairs_hook=contract._reject_duplicates,
        parse_constant=contract._reject_constant,
    )
    canonical = canonical_json(document)
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
        or canonical_digest(v3_contract._type_shape(document))
        != _ROUTE_TYPE_SHAPE_DIGEST
    ):
        raise AdmissionEvidenceError("V3 curator-restore raw identity changed")
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
        raise AdmissionEvidenceError("V3 curator-restore execution boundary changed")
    current.base.legacy._verify_stack_boundary(
        stack,
        trusted=boundaries,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    current.base.legacy._verify_gateway_listener(
        stack["gateway_listener"], stack["processes"]
    )


def _verify_route_contract(
    document: Mapping[str, Any],
    *,
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
        or document["schema"]
        != "aragorn/openclaw-protected-curator-restore-denial-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["limitations"]
        != [
            "OBSERVED_IS_NOT_PASS",
            "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
            "SHARED_DATABASE_DATA_VERSION_NOT_STABLE_ONLY_EXACT_SELECTED_LIFECYCLE_ROW_BOUND",
            "SINGLE_ROUTE_SINGLE_CAPTURE",
            "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "NO_AGGREGATE_ADMISSION_INSTALLER_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ]
        or document["implementation_digests"]
        != {"helper": _PROBE_BUNDLE[1]["digest"], "probe": _PROBE_BUNDLE[0]["digest"]}
        or document["route"]
        != {
            "action_id": "curator-restore-authority-denial",
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
        or canonical_digest(action) != _DIGESTS["action"]
        or action["id"] != "curator-restore-authority-denial"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("V3 curator-restore route changed")

    stable = {
        "boundary": (before["boundary_before"], after["boundary_after"]),
        "config_lock": (before["config_lock_before"], after["config_lock_after"]),
        "config_tree": (before["config_tree_before"], after["config_tree_after"]),
        "gateway": (before["gateway_process_before"], after["gateway_process_after"]),
        "modules": (before["modules_before"], after["modules_after"]),
        "openclaw": (before["openclaw_before"], after["openclaw_after"]),
        "protected_roots": (
            before["protected_root_trees_before"],
            after["protected_root_trees_after"],
        ),
        "runtime_tree": (before["runtime_tree_before"], after["runtime_tree_after"]),
        "target": (before["target_before"], after["target_after"]),
    }
    if any(left != right for left, right in stable.values()) or any(
        canonical_digest(left) != _STATIC_DIGESTS[name]
        for name, (left, _right) in stable.items()
    ):
        raise AdmissionEvidenceError("V3 curator-restore protected state changed")

    _verify_current_boundary(before, after, container_id)
    semantics._verify_modules(before["modules_before"])
    semantics._verify_semantics(action)
    _verify_command_causality(
        action["commands"],
        document_recorded_at=document["recorded_at"],
        execution=execution,
        outer_recorded_at=outer_recorded_at,
    )


def _verify_current_boundary(
    before: Mapping[str, Any], after: Mapping[str, Any], container_id: str
) -> None:
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
        or before["target_before"]["root"]["exists"] is not True
        or before["target_before"]["entries"][0]["exists"] is not True
    ):
        raise AdmissionEvidenceError("V3 curator-restore current contract changed")
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
        raise AdmissionEvidenceError("V3 curator-restore protected roots changed")
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
            raise AdmissionEvidenceError("V3 curator-restore protected roots changed")
    _verify_version(before["version"])
    _verify_system_snapshot(
        before["system_info_before"], before["gateway_process_before"]
    )
    _verify_system_snapshot(after["system_info_after"], after["gateway_process_after"])
    _verify_system_stability(before["system_info_before"], after["system_info_after"])


def _command_output_is_exact(command: Mapping[str, Any]) -> bool:
    stdout = command["stdout_excerpt"].encode()
    stderr = command["stderr_excerpt"].encode()
    return (
        command["stdout_bytes"] == len(stdout)
        and command["stdout_digest"] == _digest(stdout)
        and command["stderr_bytes"] == len(stderr)
        and command["stderr_digest"] == _digest(stderr)
    )


def _command_succeeded_clean(command: Mapping[str, Any]) -> bool:
    return (
        command["exit_code"] == 0
        and command["error"] is None
        and command["signal"] is None
        and command["stderr_bytes"] == 0
        and command["stderr_digest"] == _EMPTY_DIGEST
        and command["stderr_excerpt"] == ""
        and _command_output_is_exact(command)
    )


def _verify_version(command: Mapping[str, Any]) -> None:
    if (
        command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ]
        or not _command_succeeded_clean(command)
        or command["stdout_excerpt"] != "OpenClaw 2026.7.1 (7fa98d8)\n"
    ):
        raise AdmissionEvidenceError("V3 curator-restore version changed")


def _verify_system_snapshot(
    value: Mapping[str, Any], gateway: Mapping[str, Any]
) -> None:
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
        or not _command_succeeded_clean(command)
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
        or type(system["diskTotalBytes"]) is not int
        or system["diskTotalBytes"] <= 0
        or type(system["memoryTotalBytes"]) is not int
        or system["memoryTotalBytes"] <= 0
        or type(system["cpuCount"]) is not int
        or system["cpuCount"] < 0
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
        raise AdmissionEvidenceError("V3 curator-restore system identity changed")


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
    left = before["response"]["value"]
    right = after["response"]["value"]
    if {key: left[key] for key in stable} != {
        key: right[key] for key in stable
    } or right["uptimeMs"] < left["uptimeMs"]:
        raise AdmissionEvidenceError("V3 curator-restore system changed")


def _verify_command_causality(
    commands: list[Mapping[str, Any]],
    *,
    document_recorded_at: str,
    execution: Mapping[str, Any],
    outer_recorded_at: str,
) -> None:
    parse_time = current.base.legacy._parse_time
    expected_keys = {
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
    if (
        len(commands) != 11
        or len({command["pid"] for command in commands}) != 11
        or any(
            set(command) != expected_keys
            or type(command["pid"]) is not int
            or command["pid"] <= 0
            or command["error"] is not None
            or command["signal"] is not None
            or not _command_output_is_exact(command)
            or parse_time(command["started_at"]) > parse_time(command["completed_at"])
            for command in commands
        )
        or any(
            parse_time(left["completed_at"]) > parse_time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or not (
            parse_time(execution["started_at"])
            <= parse_time(commands[0]["started_at"])
            <= parse_time(commands[-1]["completed_at"])
            <= parse_time(document_recorded_at)
            <= parse_time(execution["completed_at"])
            <= parse_time(outer_recorded_at)
        )
    ):
        raise AdmissionEvidenceError("V3 curator-restore command causality changed")
