"""Qualify one exact current-V3 cron-rescan route."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_cron_rescan as semantics
from . import (
    admission_protected_final_combined_v3_config_entry_activation as v3_contract,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

contract = v3_contract.contract
current = v3_contract.config

_ROUTE = "ADM-02/reload/cron-rescan"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v3-cron-rescan-route-input-74427"
_IMAGE = "sha256:f235e4b9b9e39cebe25d29e8b548de34da1cbdc39e186e52735b27d2abf2dc28"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_PROBE_BUNDLE = [
    {
        "bytes": 35_318,
        "digest": "sha256:94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0",
        "name": "protected-cron-rescan-probe.mjs",
    },
    {
        "bytes": 16_324,
        "digest": "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        "name": "protected-observation-v1.mjs",
    },
]
_DEPENDENCIES = {
    "cron_semantics": {
        "bytes": 96_240,
        "digest": "sha256:180a1c2757c5bbfaa44c2eb05c8f1aa522ac2c4327df2d8447a384fb076a2e04",
        "path": "admission_protected_final_combined_v2_cron_rescan.py",
    },
    "v3_contract": {
        "bytes": 57_245,
        "digest": "sha256:41a5c8e274b7f22e4cc79bde03917aea6717a83b3f810803d075e39c4b2afb5e",
        "path": "admission_protected_final_combined_v3_config_entry_activation.py",
    },
}
_EVIDENCE = {
    "bytes": 652_492,
    "canonical_bytes": 652_491,
    "canonical_digest": "sha256:79d9c18051b62f901702889775022fb15a0c2cb492a9c8fd614b0c6ae67f1e04",
    "digest": "sha256:0760e58a014965fb960d6e15fe3af5909ea0e672c1f6ec4a6c8be4822b69e2b6",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
        "cron-rescan-systemd-p3-final-2026-08-30.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 94_717,
    "canonical_digest": "sha256:699b9a0039b4ffd69399ccaa5bbfda78dd05f0887e9251049e6008a29f166be5",
    "digest": "sha256:e66866bfe091b2f2d6754bf6ab0d8b5e776c1ac68f3cd9293274eba1eaa55c5a",
}
_SOURCE = {
    "commit": "af2d41d3dc89444c1c064fef0969b3a9a246dcf9",
    "parent": "72518183e83937eb3f958c648909c4a26a788c35",
    "tree": "709e39768875640430e04890110e15bb28d3b16d",
}
_RETENTION = {
    "commit": "342015b721661477c25105afb8ca299621071398",
    "parent": _SOURCE["commit"],
    "tree": "88c69c0669ce3d71fd070526b4a5aa7a9c6bbd0a",
}
_RETENTION_BLOB = "4b524b589fb0b1291d906b4c72e5e08c3d16da5f"
_TYPE_SHAPE_DIGEST = (
    "sha256:d0693933f1a11c4cb24af894b2fc41858b49504fabc024d07e53c45ecb0ed588"
)
_ROUTE_TYPE_SHAPE_DIGEST = (
    "sha256:b7be6b0ade9040ad5f4fd1501205277fe18c227d3fa804ee0256987152a55e3a"
)
_DIGESTS = {
    "action": "sha256:68d879f6a85995058cd37a51eeec50c9a31e2ad07a850100b1329e9ed6033573",
    "composition": "sha256:edb490579619545f3ef8a89c781beaebae818271624784ea3487447ecf526f02",
    "composition_action": "sha256:20dc747dfadbf990c926d948b49246a3534dbaa2e02ad64fe1fded97533409c6",
    "execution": "sha256:b948a3e4bffd1a3378642728976075bdf7a5bfa383d21c20a80fa3d998ae6fee",
    "gateway_binding": "sha256:3b7d5d89df8549ea6cf93e83fc8566ff3ab2488b47c032ac2d20458247a45c59",
    "harness": "sha256:86dc5d33202b93c634d888cbe0b4ba20f2635c1432a8abdbc6fcf77af46da31a",
    "host_config": "sha256:6592a7682fcb3ff4b6cc3042678c8d89ec4327386ec4203cff97ab261890dc50",
    "image_lineage": "sha256:b6f5adfd743c03f0c1812e7c62a4a3c8e4d6e96d4440cdc815a221e13b6b17e2",
    "route_observation": "sha256:41e51f24f57060f4ae056713de8be91d24a6e531c7052e832a7b3a547ba9677f",
    "source_artifacts": "sha256:26b5ab7c716cab4659c330f83d21e087979093173f4adfcd54be40e6b1849e55",
    "stack": "sha256:b3a8cbb9bf43815a47d87e3db9f4d8e777be4c65bcec1c101e51cd0a3c7ab272",
}
_STATIC_DIGESTS = {
    "boundary": "sha256:e480284419e19e578771c25ad93cd72606fd57cc7a77ac1c471c7311b88ca754",
    "config": "sha256:d2f943ecc4ecfb50e4e73968dbe66093fd729f75cc37a9721f3e366d5d6d1733",
    "config_lock": "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2",
    "config_tree": "sha256:c5fe0ce8ad7bbb08de401a4d759a9e5bf3c8e45ce182e6f8ae57eda511707000",
    "gateway": "sha256:e3ed6ad40d5fa69595a587eae8c6abab5f1d978f150c1e07910e0df411eda939",
    "modules": "sha256:b624f9ba14df4da2b769b886a6675a646b29c0c430832b8b88ace6a118a1e1ac",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "protected_roots": "sha256:d638e9118082db3e6e7728d9f7a2d126e4647b6ec70482fd7a318b982d063a51",
    "runtime_tree": "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b",
    "session_store": "sha256:e017d695c9041131fecd05f246e657bd0a7678559fb1db82140dd67038999111",
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
}
_ARTIFACT_DIGESTS = {
    "activator": "sha256:c43b088e0560d904509da9f2177a18c201034f3373ce368126cf46ebbc0e4995",
    "activator_source": "sha256:f14374921b839ed5f7f2b9f685de38e2cde18901620bcf77b80a1095b6e65359",
    "collector": "sha256:3096a57f7c47d3bc775dcb3162bae3134031c9f60f315f3f42cd66d47a29fd15",
    "config": "sha256:43ce7ebe7e7f0b9c4323008fc56d5377565d43043f03837aaf49dcd5ba7bf1ec",
    "cron_rescan_probe": "sha256:20646b9dc7923caa6525d9f21a6e0608d28a5717bde4b503da37f0f95c0b9f3c",
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
    "checked_in_v2_probe": (
        36_202,
        "sha256:3733b27d34e692271b0ac7c93956017d55b318fef1dcabc27e3478531c0e47b3",
        "benchmark/admission/openclaw-v2026.7.1/protected-cron-rescan-v2-probe.mjs",
        "0444",
    ),
    "collector": (
        15_710,
        "sha256:1ebdc953442c8682f624eb909a524cb2dd96ca9f66aabb04e6b49570fb082993",
        "scripts/runtime_action_worker_final_combined_v3_cron_rescan_systemd_probe.py",
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
        26_875,
        "sha256:898a53ebe5d3b0c07092085931de9121c908e0767be68285c4214637092cb763",
        "scripts/capture_runtime_action_worker_final_combined_v3_cron_rescan_systemd.sh",
        "0555",
    ),
    "dockerfile": (
        6_757,
        "sha256:48f38a827bc20d6a4588d1c39343b1aef25e6dbb169433351597da2d1aebd273",
        "benchmark/runtime-action-worker-final-combined-v3-cron-rescan-systemd/Dockerfile",
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
    "ONLY_CRON_RESCAN_ATTEMPT_OBSERVED",
    "NO_CRON_RESCAN_SUCCESS_SKILL_ACTIVATION_OR_MODEL_SUCCESS_CLAIM",
    "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
    "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
    "CRON_RESCAN_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_RUNTIME_STATE_EQUIVALENCE_CLEANUP_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def verify_openclaw_final_combined_v3_cron_rescan(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact dynamic current-V3 cron-rescan PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract._read_blob(evidence_cas, _EVIDENCE, "V3 cron rescan")
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 cron-rescan CAS differs from signed retention"
            )
        evidence = contract._load_canonical_json(raw, _EVIDENCE, "V3 cron rescan")
        profile, run_at_delta = _verify_evidence(evidence)
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
        raise AdmissionEvidenceError(f"invalid V3 cron-rescan evidence: {exc}") from exc

    routes = [
        {"id": route["id"], "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED"}
        for route in profile["routes"]
    ]
    return {
        "schema": "aragorn/admission-protected-final-combined-v3-cron-rescan-route-coverage/v1",
        "assurance": "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_CRON_RESCAN_ROUTE_ONLY",
        "bindings": {
            "configuration": dict(v3_contract.parent._CONTRACT_FILES["config"]),
            "cron_rescan_observation": {
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
            "ONE_EXACT_DYNAMIC_CRON_RESCAN_PASS_ONLY",
            "TWENTY_OTHER_V3_PROFILE_ROUTES_NOT_TESTED",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
            "MODEL_NOT_FOUND_IS_EXPECTED_TERMINAL_PROOF_NOT_MODEL_SUCCESS",
            "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
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
            "observed_run_at_delta_ms": run_at_delta,
            "pass_basis": "SIGNED_EXACT_CRON_FORCE_RUN_SNAPSHOT_AND_MODEL_NOT_FOUND_TRANSITION",
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_dependencies() -> None:
    directory = Path(__file__).resolve(strict=True).parent
    for name, module in (("cron_semantics", semantics), ("v3_contract", v3_contract)):
        expected = _DEPENDENCIES[name]
        path = Path(module.__file__).resolve(strict=True)
        if (
            path != (directory / expected["path"]).resolve(strict=True)
            or path.stat().st_size != expected["bytes"]
            or _digest(path.read_bytes()) != expected["digest"]
        ):
            raise AdmissionEvidenceError(f"V3 cron-rescan dependency changed: {name}")
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
        raise AdmissionEvidenceError("V3 cron-rescan repository changed")
    current.base._verify_commit(_SOURCE)
    current.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V3 cron-rescan signed tree changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=700 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V3 cron-rescan signed blob changed")
    return raw


def _verify_evidence(
    evidence: Mapping[str, Any],
) -> tuple[Mapping[str, Any], int]:
    if canonical_digest(v3_contract._type_shape(evidence)) != _TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError("V3 cron-rescan JSON type changed")
    semantics._verify_no_unexpected_floats(evidence)
    semantics._verify_no_positive_eligibility(evidence)
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
        "status": "FINAL_COMBINED_V3_CRON_RESCAN_OBSERVED_PROFILE_NOT_TESTED",
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
        != "aragorn/runtime-action-worker-final-combined-v3-cron-rescan-systemd-observation/v1"
        or evidence["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_CRON_RESCAN_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or evidence["recorded_at"] != "2026-08-30T17:03:28.198842Z"
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
        raise AdmissionEvidenceError("V3 cron-rescan wrapper changed")
    profile = _verify_composition(evidence["composition"], evidence["source_artifacts"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError("V3 cron-rescan harness copies differ")
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
        raise AdmissionEvidenceError("V3 cron-rescan nested custody changed")
    harness = evidence["harness"]["document"]
    _verify_execution(
        observation, evidence["composition"]["action"]["boundaries"], harness
    )
    run_at_delta = _verify_route_contract(document, harness["container_id"])
    if not (
        current.base.legacy._parse_time(document["recorded_at"])
        <= current.base.legacy._parse_time(observation["execution"]["completed_at"])
        <= current.base.legacy._parse_time(evidence["composition"]["recorded_at"])
        <= current.base.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V3 cron-rescan execution custody changed")
    return profile, run_at_delta


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    action = composition["action"]
    artifact = action["artifacts"]["final_combined_v3_cron_rescan"]
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
        != "aragorn/runtime-action-worker-final-combined-v3-cron-rescan-systemd-observation/v1"
        or composition["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_CRON_RESCAN_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or composition["recorded_at"] != "2026-08-30T17:03:28.198811Z"
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
        raise AdmissionEvidenceError("V3 cron-rescan composition changed")
    v3_contract.parent._verify_contract_artifacts(artifact)
    _verify_source_artifacts(source_artifacts)
    _verify_collector_artifacts(artifact["collector"])
    _verify_probe_artifact(artifact["cron_rescan_probe"])
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
        raise AdmissionEvidenceError(f"V3 cron-rescan signed source changed: {label}")


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V3 cron-rescan source inventory changed")
    for name, expected in _SOURCE_ARTIFACTS.items():
        _verify_signed_record(value[name], expected, f"source {name}")
    if value["probe_bundle"] != _PROBE_BUNDLE:
        raise AdmissionEvidenceError("V3 cron-rescan probe bundle changed")


def _verify_collector_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != set(_COLLECTOR_ARTIFACTS):
        raise AdmissionEvidenceError("V3 cron-rescan collector inventory changed")
    for name, expected in _COLLECTOR_ARTIFACTS.items():
        _verify_signed_record(value[name], expected, f"collector {name}")


def _verify_probe_artifact(value: Mapping[str, Any]) -> None:
    if (
        set(value)
        != {
            "checked_in_observation_helper",
            "checked_in_v2_probe",
            "fixed_materializer",
            "probe_bundle",
            "rebound_materializer",
            "runtime_observation_helper",
            "runtime_probe",
        }
        or value["probe_bundle"] != _PROBE_BUNDLE
    ):
        raise AdmissionEvidenceError("V3 cron-rescan probe artifact changed")
    for name in (
        "checked_in_observation_helper",
        "checked_in_v2_probe",
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
            path=f"/route-input/cron-rescan/{bundle['name']}",
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
        != "aragorn/runtime-action-worker-final-combined-v3-cron-rescan-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["image_reference"]
        != "aragorn-phase3-final-combined-v3-cron-rescan-systemd"
        or document["profile_label"] != "phase3-final-combined-v3-cron-rescan"
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
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:74427",
            "dev.aragorn.role": "final-combined-v3-cron-rescan-route-input",
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
        raise AdmissionEvidenceError("V3 cron-rescan harness changed")
    stat = file["stat"]
    if (
        stat["uid"] != 0
        or stat["gid"] != 0
        or stat["mode"] != "0600"
        or stat["nlink"] != 1
        or stat["size"] != len(raw)
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError("V3 cron-rescan harness file changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V3 cron-rescan raw envelope changed")
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
        raise AdmissionEvidenceError("V3 cron-rescan raw identity changed")
    semantics._verify_route_scalar_types(document)
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
            "/route-input/cron-rescan/protected-cron-rescan-probe.mjs",
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
        raise AdmissionEvidenceError("V3 cron-rescan execution boundary changed")
    current.base.legacy._verify_stack_boundary(
        stack,
        trusted=boundaries,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    current.base.legacy._verify_gateway_listener(
        stack["gateway_listener"], stack["processes"]
    )


def _verify_route_contract(document: Mapping[str, Any], container_id: str) -> int:
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
        or document["schema"] != "aragorn/openclaw-protected-cron-rescan-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digests"]
        != {"helper": _PROBE_BUNDLE[1]["digest"], "probe": _PROBE_BUNDLE[0]["digest"]}
        or document["route"]
        != {
            "action_id": "cron-rescan",
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
        raise AdmissionEvidenceError("V3 cron-rescan route changed")
    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    stable = {
        "boundary": (before["boundary_before"], after["boundary_after"]),
        "config": (before["config_before"], after["config_after"]),
        "config_lock": (before["config_lock_before"], after["config_lock_after"]),
        "config_tree": (before["config_tree_before"], after["config_tree_after"]),
        "gateway": (before["gateway_process_before"], after["gateway_process_after"]),
        "modules": (before["module_files_before"], after["module_files_after"]),
        "openclaw": (before["openclaw_before"], after["openclaw_after"]),
        "protected_roots": (
            before["protected_root_trees_before"],
            after["protected_root_trees_after"],
        ),
        "runtime_tree": (before["runtime_tree_before"], after["runtime_tree_after"]),
        "target": (before["target_before"], after["target_after"]),
    }
    if (
        action["id"] != "cron-rescan"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or any(left != right for left, right in stable.values())
        or any(
            canonical_digest(left) != _STATIC_DIGESTS[name]
            for name, (left, _right) in stable.items()
        )
        or canonical_digest(before["session_store_before"])
        != _STATIC_DIGESTS["session_store"]
    ):
        raise AdmissionEvidenceError("V3 cron-rescan protected state changed")
    boundary = before["boundary_before"]
    if (
        boundary["ready"] is not True
        or before["config_before"] != boundary["configuration"]
        or before["runtime_tree_before"] != current._RUNTIME_TREE
        or before["config_lock_before"]
        != {
            "exists": False,
            "path": "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock",
        }
    ):
        raise AdmissionEvidenceError("V3 cron-rescan current contract changed")
    v3_contract._verify_config(before["config_before"])
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
    return _verify_route(
        action,
        document["recorded_at"],
        expected_gateway_pid=before["gateway_process_before"]["pid"],
        expected_hostname=before["gateway_process_before"]["hostname"],
    )


def _verify_route(
    action: Mapping[str, Any],
    recorded_at: str,
    *,
    expected_gateway_pid: int,
    expected_hostname: str,
) -> int:
    before = action["prerequisites"]
    after = action["observations"]
    semantics._verify_version(before["version"])
    semantics._verify_system(
        before["system_info_before"], expected_gateway_pid, expected_hostname
    )
    semantics._verify_system(
        after["system_info_after"], expected_gateway_pid, expected_hostname
    )
    system_before = before["system_info_before"]["response"]["value"]
    system_after = after["system_info_after"]["response"]["value"]
    stable = (
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
    )
    if (
        any(system_before[name] != system_after[name] for name in stable)
        or system_after["uptimeMs"] < system_before["uptimeMs"]
    ):
        raise AdmissionEvidenceError("V3 cron-rescan system identity drifted")
    inventory_before = semantics._verify_cron_inventory(
        before["cron_inventory_before"],
        mtime_not_after=after["job"]["command"]["started_at"],
    )
    job_id = semantics._verify_job(after["job"])
    job = after["job"]["response"]["value"]
    inventory_after_add = semantics._verify_cron_inventory(
        after["cron_inventory_after_add"],
        job=job,
        mtime_not_before=after["job"]["command"]["started_at"],
        mtime_not_after=after["session_state_before_forced_run"]["started_at"],
    )
    pre_store = semantics._verify_pre_run(
        after["session_state_before_forced_run"], before["session_store_before"], job_id
    )
    request = after["run"]["request"]
    semantics._verify_native_call(
        request, method="cron.run", params={"id": job_id, "mode": "force"}
    )
    run_id = request["response"]["value"].get("runId")
    if (
        request["response"]["value"] != {"enqueued": True, "ok": True, "runId": run_id}
        or not isinstance(run_id, str)
        or semantics.cron._RUN_ID.fullmatch(run_id) is None
        or type(after["run"]["poll_count"]) is not int
        or after["run"]["poll_count"] != 1
        or after["run"]["polls"] != [after["run"]["terminal_poll"]]
    ):
        raise AdmissionEvidenceError("V3 cron-rescan forced run changed")
    poll = after["run"]["terminal_poll"]
    semantics._verify_native_call(
        poll, method="cron.runs", params={"id": job_id, "limit": 10}
    )
    terminal = after["terminal_result"]
    if poll["response"]["value"] != {
        "entries": [terminal],
        "hasMore": False,
        "limit": 10,
        "nextOffset": None,
        "offset": 0,
        "total": 1,
    }:
        raise AdmissionEvidenceError("V3 cron-rescan terminal history changed")
    semantics._verify_snapshot(after["snapshot"], job_id, pre_store)
    run_at_delta = _verify_terminal(
        terminal,
        job=after["job"],
        request=request,
        poll=poll,
        snapshot=after["snapshot"],
        job_id=job_id,
        run_id=run_id,
    )
    semantics._verify_store(
        after["session_store_after"],
        after["snapshot"]["store"],
        before["session_store_before"],
    )
    semantics._verify_native_call(
        after["cleanup"], method="cron.remove", params={"id": job_id}
    )
    if after["cleanup"]["response"]["value"] != {"ok": True, "removed": True}:
        raise AdmissionEvidenceError("V3 cron-rescan cleanup changed")
    inventory_after_remove = semantics._verify_cron_inventory(
        after["cron_inventory_after_remove"],
        mtime_not_before=after["cleanup"]["command"]["started_at"],
        mtime_not_after=after["system_info_after"]["command"]["started_at"],
    )
    semantics._verify_cron_store_transition(
        inventory_before, inventory_after_add, inventory_after_remove
    )
    sqlite_inodes = {
        snapshot[name]["inode"]
        for snapshot in (inventory_before, inventory_after_add, inventory_after_remove)
        for name in ("database", "shared_memory", "write_ahead_log")
    }
    if sqlite_inodes & {
        after["snapshot"]["blob"]["inode"],
        after["snapshot"]["store"]["inode"],
    }:
        raise AdmissionEvidenceError("V3 cron-rescan state-file inode reused")
    semantics._verify_commands(action, recorded_at)
    return run_at_delta


def _verify_terminal(
    result: Mapping[str, Any],
    *,
    job: Mapping[str, Any],
    request: Mapping[str, Any],
    poll: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    job_id: str,
    run_id: str,
) -> int:
    match = semantics.cron._RUN_ID.fullmatch(run_id)
    run_epoch = int(match.group(2)) if match is not None else -1
    diagnostic = result["diagnostics"]["entries"][0]
    session_id = result["sessionId"]
    if (
        set(result)
        != {
            "action",
            "deliveryStatus",
            "diagnostics",
            "durationMs",
            "error",
            "errorReason",
            "jobId",
            "jobName",
            "model",
            "nextRunAtMs",
            "provider",
            "runAtMs",
            "runId",
            "sessionId",
            "sessionKey",
            "status",
            "ts",
        }
        or set(result["diagnostics"]) != {"entries", "summary"}
        or set(diagnostic) != {"message", "severity", "source", "ts"}
        or match is None
        or match.group(1) != job_id
        or result["action"] != "finished"
        or result["status"] != "error"
        or result["errorReason"] != "model_not_found"
        or result["error"] != "FailoverError: Unknown model: openai/gpt-5.5"
        or result["provider"] != "openai"
        or result["model"] != "gpt-5.5"
        or result["jobId"] != job_id
        or result["jobName"] != semantics.cron._CRON_NAME
        or result["runId"] != run_id
        or semantics.cron._UUID4.fullmatch(session_id) is None
        or result["sessionKey"] != f"agent:main:cron:{job_id}:run:{session_id}"
        or result["deliveryStatus"] != "not-requested"
        or result["diagnostics"]["summary"] != "Unknown model: openai/gpt-5.5"
        or len(result["diagnostics"]["entries"]) != 1
        or diagnostic
        != {
            "message": "Unknown model: openai/gpt-5.5",
            "severity": "error",
            "source": "agent-run",
            "ts": diagnostic["ts"],
        }
        or result["nextRunAtMs"] != job["response"]["value"]["nextRunAtMs"]
        or type(result["durationMs"]) is not int
        or result["durationMs"] < 0
        or result["durationMs"] > result["ts"] - result["runAtMs"]
        or any(
            type(value) is not int or value <= 0
            for value in (
                result["nextRunAtMs"],
                result["runAtMs"],
                result["ts"],
                diagnostic["ts"],
            )
        )
        or not (
            current.base.legacy._epoch_ms(request["command"]["started_at"])
            <= run_epoch
            <= result["runAtMs"]
            <= current.base.legacy._epoch_ms(request["command"]["completed_at"])
            <= snapshot["entry"]["updated_at"]
            <= int(snapshot["store"]["mtime_ns"]) // 1_000_000
            <= int(snapshot["blob"]["mtime_ns"]) // 1_000_000
            <= diagnostic["ts"]
            <= result["ts"]
            <= current.base.legacy._epoch_ms(poll["command"]["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V3 cron-rescan terminal causality changed")
    return result["runAtMs"] - run_epoch
