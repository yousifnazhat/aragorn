"""Qualify one exact V3 plugin-enable credential-lock denial."""

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

from . import admission_protected_final_combined_v3_plugin_force_reinstall as parent
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

contract = parent.contract
enable = parent.parent.parent
config = enable.base

_ROUTE = "ADM-02/update/plugin-enable-activation"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_PLUGIN_ID = "tts-local-cli"
_PLUGIN_ROOT = "/runtime/lib/node_modules/openclaw/dist/extensions/tts-local-cli"
_CONFIG_PATH = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
_ROUTE_PROBE = (
    "/route-input/plugin-enable-activation/protected-plugin-enable-v3-probe.mjs"
)
_VERIFIER_PATH = "src/aragorn/admission_protected_final_combined_v3_plugin_enable.py"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

_BASE = {
    "digest": "sha256:4e8087e56a72332d974d142936e6250d4eba626e8b719df01d4c2257fac1ed4f",
    "path": "src/aragorn/admission_protected_final_combined_v3_plugin_force_reinstall.py",
}
_EVIDENCE = {
    "bytes": 525_899,
    "canonical_bytes": 525_898,
    "canonical_digest": (
        "sha256:8bff7f4a330b73d6d8aba0f1594306cd7e2587b623e6ab99bf29e8e4c76f62e9"
    ),
    "digest": (
        "sha256:005e757a8a59a677c62ff409cec424fa0e25320bbd183fc3b26bdb63582c0780"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-plugin-"
        "enable-activation-systemd-p3-final-2026-08-28.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 38_290,
    "canonical_digest": (
        "sha256:b9c8a36e11c12f26a759de8e6df669df2acfb66e4f069bfec0245898ebe6ce69"
    ),
    "digest": (
        "sha256:aadd270b67c58bfb7d749adfdcf8d436d84b582a93cd75cdab6525678bb91d05"
    ),
}
_SOURCE = {
    "commit": "d1c7684e4acbdbe35abd891a1e80b586fdc85e8b",
    "parent": "95ebf1b845409b93cabf463e966effa33558a0e1",
    "tree": "7b3f9195888fd83ba108d05cb2a0621f23c4a63f",
}
_RETENTION = {
    "commit": "98a8e799ad7f3dbac9eecad2baf962a6bb9356ef",
    "parent": _SOURCE["commit"],
    "tree": "2a78b825f81597b16d7d5ee7786c4ac575a94bc5",
}
_RETENTION_BLOB = "18d6ff80a89243981e7cae41c1d3df39b582403c"
_IMAGE = "sha256:98d8bc660d756d43c4b03a3a7377324b4f5e224605bcad82e022bc1a45fb2f46"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)

_PROBE = {
    "bytes": 23_594,
    "digest": "sha256:5b4f38b55770f51071f467072f186a316feb8ea0373c5621a6ceb3e7edb4489a",
    "name": "protected-plugin-enable-v3-probe.mjs",
}
_SOURCE_PROBE = {
    "bytes": 23_594,
    "digest": "sha256:b31dc052d9eaffb4712de2a716f958afeb54399452aaaf47a714ee216da1ed92",
    "path": "benchmark/admission/openclaw-v2026.7.1/protected-plugin-enable-probe.mjs",
}
_TRANSFORMED_PROBE_PATH = (
    "benchmark/admission/openclaw-v2026.7.1/protected-plugin-enable-v3-probe.mjs"
)
_TRANSFORM = {
    "configuration_bytes": {"from": 1_880, "occurrences": 1, "to": 2_159},
    "configuration_digest": {
        "from": "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
        "occurrences": 2,
        "to": parent._CONTRACT_FILES["config"]["canonical_digest"],
    },
    "self_check_key": {
        "from": "current_v2_configuration_pinned",
        "occurrences": 1,
        "to": "current_v3_configuration_pinned",
    },
}

_SOURCE_ARTIFACTS = {
    "checked_in_probe": {**_SOURCE_PROBE, "mode": "0444"},
    "collector": {
        "bytes": 23_811,
        "digest": "sha256:653baa6bc273b8ddf7e121b03fe84bd131f2fc066dddbbbaba0aecf172c40143",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_combined_v3_plugin_enable_systemd_probe.py",
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
    "transformed_probe": {
        **_PROBE,
        "mode": "0444",
        "path": _TRANSFORMED_PROBE_PATH,
    },
}
_SIGNED_SOURCE_ARTIFACTS = {
    name for name in _SOURCE_ARTIFACTS if name != "transformed_probe"
}
_COLLECTOR_ARTIFACTS = {
    "capture_recipe": {
        "bytes": 23_635,
        "digest": "sha256:1b5b52425df7b047c1103587603016044b3a026f8780ab89fec06c116e4a1b23",
        "mode": "0555",
        "path": "scripts/capture_runtime_action_worker_final_combined_v3_plugin_enable_systemd.sh",
    },
    "dockerfile": {
        "bytes": 6_269,
        "digest": "sha256:9f5e6f4342a457589d50281a3b70113e8bbafd9b0d5220c8a214f1d8a6bbae69",
        "mode": "0444",
        "path": "benchmark/runtime-action-worker-final-combined-v3-plugin-enable-systemd/Dockerfile",
    },
    "inherited_combined_base": _SOURCE_ARTIFACTS["inherited_combined_base"],
    "inherited_route_injector": _SOURCE_ARTIFACTS["inherited_route_injector"],
    "inherited_v3_contract_helpers": _SOURCE_ARTIFACTS["inherited_v3_contract_base"],
    "probe": _SOURCE_ARTIFACTS["collector"],
}

_DIGESTS = {
    "composition": "sha256:551bde5c482a6dcfb508c2875909e4697d9f22cdff84b53dcae9e4ed0ea99752",
    "source_artifacts": "sha256:e624e903ac4674d3ef8aabd4ab2500ee9592a7f2caedec8060f0c2fb2627aead",
    "harness": "sha256:80b84cfc52b8e60603a284923933d32b2a7aca6713611b69febea68be3c795f1",
    "route_observation": "sha256:a66ef9e4f0090c11bce265f58a1778f34169893cc5695139087be0ab5185c986",
    "execution": "sha256:8ca5be07273f1465498bb8f801c0ccae893c9793e31a2bb4fc564841ba8b2ac2",
    "gateway": "sha256:ba2e4b138ed55128ff8bdb296613e8d3d63df04e3686a0ad3367d981059ff158",
    "stack": "sha256:6ecbe8585bf26be43f33357dcabe17096cfe904db45bfae71b704aaebdcf9c11",
    "document": _ROUTE_RAW["canonical_digest"],
    "action": "sha256:ba00b4676151401e370a9c6dec130393861e2d85132108bd6afe49819e934829",
    "v3_artifact": "sha256:05ee5d431107ed257c27038ecff03210a7eb89c7640a17af621bea301332c421",
}
_TYPE_SHAPE_DIGEST = (
    "sha256:f85d4f94189fddbd3c8c8eb96ed4481a39287c3d3f9fcd8e2ea7fc7914d922e5"
)
# These semantic projections are deliberately independent of repinnable envelopes.
_SEMANTIC_DIGESTS = {
    "boundary": "sha256:75071e1d07b9787f563fcb737c3d24302236288454ae6ff01a31d6031b2f18e0",
    "config": "sha256:815b1da91a2e8084944904f19b9bcd65aced5c4bab137407e0a1a913c0abcedf",
    "config_lock": "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2",
    "gateway_process": "sha256:e996704c741795b14812c1dbc5f1f3a76a783d4bee132e5c58206f54b75f60da",
    "harness_document": "sha256:9354d0d0cc4d019f4bceb7d9563a8d2b787021340eff6c1cc4deaab40785b611",
    "native_enable": "sha256:8a587353122fbe3664123c2642037fa1ff2cb2c3f5e4ceabdd346475594a92e5",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "plugin_response": "sha256:683dcaeffe72d29b2011fd9fee7ff1c30717640e8be87963dc2b1dfbb12f1234",
    "plugin_tree": "sha256:ec751dc1b1856a74291079ce2e7a3c754975d2e9d8bd9d61431d83dff45312be",
    "runtime_tree": "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b",
    "stack": "sha256:6ecbe8585bf26be43f33357dcabe17096cfe904db45bfae71b704aaebdcf9c11",
}
_ARTIFACT_DIGESTS = {
    "activator": "sha256:c43b088e0560d904509da9f2177a18c201034f3373ce368126cf46ebbc0e4995",
    "activator_source": "sha256:f14374921b839ed5f7f2b9f685de38e2cde18901620bcf77b80a1095b6e65359",
    "collector": "sha256:df7f3faccf8c67d886dbc9f25b4f6e65fd85edfd67af4ddfa55dc68fef01733c",
    "config": "sha256:43ce7ebe7e7f0b9c4323008fc56d5377565d43043f03837aaf49dcd5ba7bf1ec",
    "installed_runtime": "sha256:3280849f3efd4842debc217dfc6afd03b8cc2789b89de296429fd1c2629931ab",
    "plugin": "sha256:1d51828d474068eddbe47cc8827598c78c3805bce91738727222a24fffc7a8a2",
    "plugin_enable_probe": "sha256:eed103649d5740dc3cc8f7bf35c523d436898c4fb853030aa659b20577e6d028",
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
    "INSTALL_POLICY_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_SQLITE_LOGICAL_STATE_STORE_EQUIVALENCE_NO_WRITE_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
_OUTER_DECISION = {
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
    "status": "FINAL_COMBINED_V3_PLUGIN_ENABLE_OBSERVED_PROFILE_NOT_TESTED",
}
_COMPOSITION_DECISION = {
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
_STDERR = (
    "[openclaw] Could not start the CLI.\n"
    "[openclaw] Reason: EROFS: read-only file system, open "
    f"'{_CONFIG_PATH}.lock'\n"
    "[openclaw] Debug: set OPENCLAW_DEBUG=1 to include the stack trace.\n"
    "[openclaw] Try: openclaw doctor\n"
    "[openclaw] Help: openclaw --help\n"
)


def verify_openclaw_final_combined_v3_plugin_enable(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one narrowly qualified V3 PASS and twenty NOT_TESTED routes."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract._read_blob(evidence_cas, _EVIDENCE, "V3 plugin enable")
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 plugin-enable CAS differs from signed retention"
            )
        evidence = contract._load_canonical_json(raw, _EVIDENCE, "V3 plugin enable")
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
            f"invalid V3 plugin-enable evidence: {exc}"
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
            "aragorn/admission-protected-final-combined-v3-plugin-enable-"
            "activation-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_PLUGIN_ENABLE_"
            "PRE_EFFECT_CREDENTIAL_LOCK_DENIAL_ROUTE_ONLY"
        ),
        "bindings": {
            "configuration": dict(parent._CONTRACT_FILES["config"]),
            "image": _IMAGE,
            "plugin_enable_observation": {
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
            "profile": dict(parent._CONTRACT_FILES["profile"]),
            "runtime_lock": dict(parent._CONTRACT_FILES["runtime_lock"]),
            "source_artifacts": {
                name: {key: value[key] for key in ("bytes", "digest", "path")}
                for name, value in _SOURCE_ARTIFACTS.items()
            },
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE",
            **{key: False for key in contract._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_PLUGIN_ENABLE_ACTIVATION_ROUTE_ONLY",
            "TWENTY_OTHER_V3_ROUTES_NOT_TESTED",
            "NATIVE_PLUGIN_ENABLE_FAILED_PRE_EFFECT_AT_READ_ONLY_SYSTEMD_CREDENTIAL_LOCK",
            "PLUGIN_REMAINED_DISABLED_NOT_ALLOWLISTED_UNACTIVATED_AND_UNIMPORTED",
            "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_NOT_CAUSAL_FOR_THIS_ENABLE_DENIAL",
            "NO_SQLITE_LOGICAL_STATE_STORE_EQUIVALENCE_NO_WRITE_ROLLBACK_OR_CAUSALITY_CLAIM",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "SOURCE_TO_BINARY_BUILD_NOT_INDEPENDENTLY_ATTESTED_OR_REPRODUCED",
            "PUBLIC_NETWORK_DENIED",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"NOT_TESTED": 20, "PASS": 1},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "pass_basis": (
                "NATIVE_PLUGIN_ENABLE_DENIED_PRE_EFFECT_AT_READ_ONLY_"
                "SYSTEMD_CREDENTIAL_LOCK"
            ),
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _type_shape(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _type_shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_type_shape(item) for item in value]
    if value is None:
        return "null"
    for type_, name in ((bool, "bool"), (int, "int"), (float, "float"), (str, "str")):
        if type(value) is type_:
            return name
    raise AdmissionEvidenceError("V3 plugin-enable JSON type changed")


def _verify_dependencies() -> None:
    path = Path(parent.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_BASE["path"]).name
        or _digest(path.read_bytes()) != _BASE["digest"]
    ):
        raise AdmissionEvidenceError("V3 plugin-enable verifier base changed")
    parent._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = config.base.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V3 plugin-enable repository changed")
    config.base._verify_commit(_SOURCE)
    config.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V3 plugin-enable signed tree entry changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=640 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V3 plugin-enable signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    if canonical_digest(_type_shape(evidence)) != _TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError("V3 plugin-enable JSON type shape changed")
    enable._verify_scalar_types(evidence)
    config._verify_no_positive_eligibility(evidence)
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
        != "aragorn/runtime-action-worker-final-combined-v3-plugin-enable-systemd-observation/v1"
        or evidence["recorded_at"] != "2026-08-28T18:09:33.087163Z"
        or evidence["route_id"] != _ROUTE
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V3_RAW_PLUGIN_ENABLE_OBSERVATION_ONLY_"
            "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or evidence["decision"] != _OUTER_DECISION
        or evidence["limitations"] != _RAW_LIMITATIONS
        or canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
        or canonical_digest(evidence["harness"]) != _DIGESTS["harness"]
        or canonical_digest(evidence["route_observation"])
        != _DIGESTS["route_observation"]
    ):
        raise AdmissionEvidenceError("V3 plugin-enable outer observation changed")
    _verify_sources(evidence["source_artifacts"])
    profile = _verify_composition(evidence["composition"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError("V3 plugin-enable harness copies differ")
    _verify_harness(evidence["harness"])
    if (
        evidence["route_observation"]["bundle"]
        != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V3 plugin-enable route bundle changed")
    _verify_route_observation(
        evidence["route_observation"],
        evidence["recorded_at"],
        boundaries=evidence["composition"]["action"]["boundaries"],
        container_id=evidence["harness"]["document"]["container_id"],
    )
    return profile


def _verify_sources(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V3 plugin-enable source inventory changed")
    git = config.base.legacy._git
    for name, expected in _SOURCE_ARTIFACTS.items():
        _verify_file_record(
            value[name],
            path=f"/src/{expected['path']}",
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=f"{name} source",
        )
        if name in _SIGNED_SOURCE_ARTIFACTS:
            _verify_signed_bytes(git, expected)
    if value["probe_bundle"] != [_PROBE]:
        raise AdmissionEvidenceError("V3 plugin-enable probe bundle changed")
    _verify_probe_transform(git)


def _verify_signed_bytes(git: Any, expected: Mapping[str, Any]) -> bytes:
    raw = git(
        ["show", f"{_SOURCE['commit']}:{expected['path']}"],
        maximum=expected["bytes"],
    )
    if len(raw) != expected["bytes"] or _digest(raw) != expected["digest"]:
        raise AdmissionEvidenceError("V3 plugin-enable signed source changed")
    return raw


def _verify_probe_transform(git: Any) -> bytes:
    raw = _verify_signed_bytes(git, _SOURCE_PROBE)
    replacements = (
        (
            _TRANSFORM["configuration_digest"]["from"].encode(),
            _TRANSFORM["configuration_digest"]["to"].encode(),
            2,
        ),
        (b"file.size === 1880", b"file.size === 2159", 1),
        (
            _TRANSFORM["self_check_key"]["from"].encode(),
            _TRANSFORM["self_check_key"]["to"].encode(),
            1,
        ),
    )
    transformed = raw
    for old, new, count in replacements:
        if transformed.count(old) != count or transformed.count(new) != 0:
            raise AdmissionEvidenceError("V3 plugin-enable transform input changed")
        transformed = transformed.replace(old, new)
    if len(transformed) != _PROBE["bytes"] or _digest(transformed) != _PROBE["digest"]:
        raise AdmissionEvidenceError("V3 plugin-enable transformed probe changed")
    return transformed


def _verify_composition(composition: Mapping[str, Any]) -> Mapping[str, Any]:
    action = composition["action"]
    artifact = action["artifacts"]["final_combined_v3_plugin_enable"]
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
        != "aragorn/runtime-action-worker-final-combined-v3-plugin-enable-systemd-observation/v1"
        or composition["authority"]
        != (
            "BOUND_FINAL_COMBINED_V3_RAW_PLUGIN_ENABLE_OBSERVATION_ONLY_"
            "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or composition["recorded_at"] != "2026-08-28T18:09:33.087116Z"
        or composition["decision"] != _COMPOSITION_DECISION
        or composition["limitations"] != _RAW_LIMITATIONS
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": config._RUNTIME_TREE["tree_digest"],
            "runtime_volume": config._RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": config._SOURCES["skill"]["digest"],
        }
        or canonical_digest(artifact) != _DIGESTS["v3_artifact"]
    ):
        raise AdmissionEvidenceError("V3 plugin-enable composition changed")
    _verify_artifact(artifact)
    profile = artifact["profile"]["document"]
    if (
        composition["profile"]["before"] != composition["profile"]["after"]
        or composition["profile"]["before"]["document"] != profile
        or composition["profile"]["before"]["outcomes"]
        != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]] != list(contract._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile["runtime"]
        != {**contract._OPENCLAW, "name": "openclaw-protected-final-combined-v3"}
    ):
        raise AdmissionEvidenceError("V3 plugin-enable profile changed")
    if (
        action["identities"]
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
            "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "entrypoint_digest": contract._RUNTIME["entrypoint_digest"],
            "expected_version": contract._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": config._RUNTIME_TREE,
            "version_output": contract._RUNTIME["version_output"],
        }
    ):
        raise AdmissionEvidenceError("V3 plugin-enable composition boundary changed")
    return profile


def _verify_artifact(artifact: Mapping[str, Any]) -> None:
    if set(artifact) != set(_ARTIFACT_DIGESTS):
        raise AdmissionEvidenceError("V3 plugin-enable artifact inventory changed")
    for name, digest in _ARTIFACT_DIGESTS.items():
        if canonical_digest(artifact[name]) != digest:
            raise AdmissionEvidenceError(f"V3 plugin-enable {name} artifact changed")

    parent._verify_contract_artifacts(artifact)
    git = config.base.legacy._git
    for expected in parent._CONTRACT_FILES.values():
        _verify_signed_bytes(git, expected)

    _verify_file_record(
        artifact["activator_source"],
        path="/src/packaging/activate-runtime-action-worker-host-v3.sh",
        bytes_=30_504,
        digest="sha256:3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c",
        mode="0555",
        label="activator source",
    )
    _verify_file_record(
        artifact["activator"],
        path="/usr/libexec/aragorn/activate-runtime-action-worker-host.sh",
        bytes_=30_504,
        digest=artifact["activator_source"]["digest"],
        mode="0755",
        label="activator install",
    )
    _verify_file_record(
        artifact["preflight_source"],
        path="/src/src/aragorn/runtime_action_worker.py",
        bytes_=37_878,
        digest="sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873",
        mode="0444",
        label="preflight source",
    )
    _verify_file_record(
        artifact["preflight"],
        path="/usr/lib/aragorn/aragorn/runtime_action_worker.py",
        bytes_=37_878,
        digest=artifact["preflight_source"]["digest"],
        mode="0644",
        label="preflight install",
    )
    _verify_signed_bytes(
        git,
        {
            "bytes": 37_878,
            "digest": artifact["preflight_source"]["digest"],
            "path": "src/aragorn/runtime_action_worker.py",
        },
    )
    if (
        artifact["installed_runtime"]
        != artifact["runtime_lock"]["document"]["installed_runtime"]
    ):
        raise AdmissionEvidenceError("V3 plugin-enable installed runtime changed")

    for name, expected in _COLLECTOR_ARTIFACTS.items():
        _verify_file_record(
            artifact["collector"][name],
            path=f"/src/{expected['path']}",
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=f"collector {name}",
        )
        _verify_signed_bytes(git, expected)

    plugin = artifact["plugin"]
    expected_plugin = {
        "index.js": (
            23_860,
            "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
        ),
        "openclaw.plugin.json": (
            723,
            "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036",
        ),
        "package.json": (
            134,
            "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2",
        ),
    }
    if set(plugin) != set(expected_plugin):
        raise AdmissionEvidenceError("V3 plugin-enable Aragorn plugin changed")
    for name, (bytes_, digest) in expected_plugin.items():
        _verify_file_record(
            plugin[name],
            path=f"/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/{name}",
            bytes_=bytes_,
            digest=digest,
            mode="0644",
            label=f"Aragorn plugin {name}",
        )
    _verify_file_record(
        artifact["skill"]["file"],
        path="/opt/aragorn/runtime-profile/template-skill/SKILL.md",
        bytes_=140,
        digest=config._SOURCES["skill"]["digest"],
        mode="0444",
        label="skill",
    )
    _verify_artifact_probe(artifact["plugin_enable_probe"], git)


def _verify_artifact_probe(value: Mapping[str, Any], git: Any) -> None:
    if set(value) != {
        "checked_in_source",
        "runtime",
        "transform",
        "transformed_source",
    }:
        raise AdmissionEvidenceError("V3 plugin-enable transform artifact changed")
    if value["transform"] != _TRANSFORM:
        raise AdmissionEvidenceError("V3 plugin-enable transform metadata changed")
    _verify_file_record(
        value["checked_in_source"],
        path=f"/src/{_SOURCE_PROBE['path']}",
        bytes_=_SOURCE_PROBE["bytes"],
        digest=_SOURCE_PROBE["digest"],
        mode="0444",
        label="checked-in enable probe",
    )
    _verify_file_record(
        value["transformed_source"],
        path=f"/src/{_TRANSFORMED_PROBE_PATH}",
        bytes_=_PROBE["bytes"],
        digest=_PROBE["digest"],
        mode="0444",
        label="transformed enable probe",
    )
    _verify_file_record(
        value["runtime"],
        path=_ROUTE_PROBE,
        bytes_=_PROBE["bytes"],
        digest=_PROBE["digest"],
        mode="0444",
        label="runtime enable probe",
    )
    _verify_probe_transform(git)


def _verify_file_record(
    value: Mapping[str, Any],
    *,
    path: str,
    bytes_: int,
    digest: str,
    mode: str,
    label: str,
) -> None:
    stat = value["stat"]
    if (
        set(value) != {"bytes", "digest", "path", "stat"}
        or value["path"] != path
        or value["bytes"] != bytes_
        or value["digest"] != digest
        or set(stat)
        != {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
        or type(stat["device"]) is not int
        or stat["device"] <= 0
        or type(stat["inode"]) is not int
        or stat["inode"] <= 0
        or stat["uid"] != 0
        or stat["gid"] != 0
        or stat["mode"] != mode
        or stat["nlink"] != 1
        or stat["size"] != bytes_
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError(f"V3 plugin-enable {label} changed")


def _verify_harness(value: Mapping[str, Any]) -> None:
    document = value["document"]
    file = value["file"]
    stat = file["stat"]
    raw = base64.b64decode(file["base64"], validate=True)
    parsed = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=contract._reject_duplicates,
        parse_constant=contract._reject_constant,
    )
    host = document["host_config"]
    runtime_mount = document["openclaw_runtime_mount"]
    route_mount = document["route_input_mount"]
    if (
        set(value) != {"digest", "document", "file"}
        or parsed != document
        or raw != canonical_json(document)
        or canonical_digest(document) != _SEMANTIC_DIGESTS["harness_document"]
        or value["digest"] != _SEMANTIC_DIGESTS["harness_document"]
        or file["bytes"] != 20_653
        or len(raw) != 20_653
        or file["digest"] != _SEMANTIC_DIGESTS["harness_document"]
        or file["path"] != "/run/aragorn-harness.json"
        or document["schema"]
        != "aragorn/runtime-action-worker-final-combined-v3-plugin-enable-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["platform"] != "linux"
        or document["profile_label"] != "phase3-final-combined-v3-plugin-enable"
        or document["image_reference"]
        != "aragorn-phase3-final-combined-v3-plugin-enable-systemd"
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["source_commit"] != _SOURCE["commit"]
        or document["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or document["source_commit_verification"]["exit_code"] != 0
        or re.fullmatch(r"[0-9a-f]{64}", document["container_id"]) is None
        or host["network_mode"] != "none"
        or host["privileged"] is not True
        or host["readonly_rootfs"] is not False
        or host["cgroupns_mode"] != "host"
        or host["runtime"] != "runc"
        or runtime_mount
        != {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": config._RUNTIME_VOLUME,
            "type": "volume",
        }
        or route_mount
        != {
            "destination": "/route-input",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-phase3-final-combined-v3-plugin-enable-route-input-55143",
            "type": "volume",
        }
        or f"{config._RUNTIME_VOLUME}:/runtime:ro" not in host["binds"]
        or f"{route_mount['source']}:/route-input:ro" not in host["binds"]
        or document["openclaw_runtime_volume"] != config._RUNTIME_VOLUME
        or document["route_input_volume_identity"]["labels"]
        != {
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:55143",
            "dev.aragorn.role": "final-combined-v3-plugin-enable-route-input",
            "dev.aragorn.source-commit": _SOURCE["commit"],
        }
        or set(stat)
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
        or stat["device"] <= 0
        or stat["inode"] <= 0
        or stat["mtime_ns"] != stat["ctime_ns"]
        or stat["gid"] != 0
        or stat["uid"] != 0
        or stat["mode"] != "0600"
        or stat["nlink"] != 1
        or stat["size"] != len(raw)
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError("V3 plugin-enable harness changed")


def _verify_route_observation(
    value: Mapping[str, Any],
    recorded_at: str,
    *,
    boundaries: Mapping[str, Any],
    container_id: str,
) -> None:
    gateway = value["gateway_pid_binding"]
    if (
        set(value)
        != {
            "bundle",
            "document",
            "execution",
            "gateway_pid_binding",
            "raw",
            "route",
            "stack_before",
        }
        or value["bundle"] != [_PROBE]
        or canonical_digest(value["execution"]) != _DIGESTS["execution"]
        or canonical_digest(gateway) != _DIGESTS["gateway"]
        or canonical_digest(value["stack_before"]) != _DIGESTS["stack"]
        or gateway
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": "/proc/2673/ns/mnt",
            "pid": 2673,
            "unit": "aragorn-agent-gateway.service",
        }
        or value["route"] != value_route()
    ):
        raise AdmissionEvidenceError("V3 plugin-enable route envelope changed")
    _verify_execution(value["execution"], gateway)
    _verify_stack(
        value["stack_before"],
        boundaries=boundaries,
        container_id=container_id,
        gateway=gateway,
    )
    document = _verify_document_raw(value["raw"], value["document"])
    _verify_document(document, recorded_at, container_id=container_id)
    commands = document["action"]["commands"]
    if not (
        parent._time(value["execution"]["started_at"])
        <= parent._time(commands[0]["started_at"])
        <= parent._time(commands[-1]["completed_at"])
        <= parent._time(document["recorded_at"])
        <= parent._time(value["execution"]["completed_at"])
        <= parent._time(recorded_at)
    ):
        raise AdmissionEvidenceError("V3 plugin-enable outer execution time changed")


def _verify_execution(value: Mapping[str, Any], gateway: Mapping[str, Any]) -> None:
    expected_argv = [
        "nsenter",
        "--target",
        str(gateway["pid"]),
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
        _ROUTE_PROBE,
    ]
    if (
        set(value)
        != {
            "argv",
            "completed_at",
            "effective_identity",
            "environment_names",
            "exit_code",
            "started_at",
            "stderr",
        }
        or value["argv"] != expected_argv
        or value["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or value["environment_names"]
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
        or type(value["exit_code"]) is not int
        or value["exit_code"] != 0
        or value["stderr"] != {"bytes": 0, "digest": _EMPTY_DIGEST, "excerpt": ""}
    ):
        raise AdmissionEvidenceError("V3 plugin-enable execution changed")


def _verify_stack(
    stack: Mapping[str, Any],
    *,
    boundaries: Mapping[str, Any],
    container_id: str,
    gateway: Mapping[str, Any],
) -> None:
    gateway_unit = gateway["unit"]
    units = {
        gateway_unit,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    process = stack["processes"][gateway_unit]
    if (
        canonical_digest(stack) != _SEMANTIC_DIGESTS["stack"]
        or set(stack)
        != {
            "enablement",
            "gateway_listener",
            "pids",
            "processes",
            "service_state",
            "sockets",
            "units",
        }
        or set(stack["units"]) != units
        or set(stack["pids"]) != units
        or set(stack["processes"]) != units
        or stack["pids"][gateway_unit] != gateway["pid"]
        or stack["gateway_listener"]["pid"] != gateway["pid"]
        or process["pid"] != gateway["pid"]
        or process["uids"] != [992, 992, 992, 992]
        or process["gids"] != [992, 992, 992, 992]
        or process["groups"] != [992]
        or process["capabilities_effective"] != "0000000000000000"
        or process["no_new_privileges"] != 1
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
        raise AdmissionEvidenceError("V3 plugin-enable stack binding changed")


def _verify_document_raw(
    raw_value: Mapping[str, Any], document: Mapping[str, Any]
) -> Mapping[str, Any]:
    raw = base64.b64decode(raw_value["base64"], validate=True)
    parsed = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=contract._reject_duplicates,
        parse_constant=contract._reject_constant,
    )
    if (
        {key: raw_value[key] for key in ("bytes", "canonical_digest", "digest")}
        != _ROUTE_RAW
        or raw_value["raw_is_canonical_json_lf"] is not True
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or raw != canonical_json(document) + b"\n"
        or canonical_digest(document) != _DIGESTS["document"]
        or parsed != document
    ):
        raise AdmissionEvidenceError("V3 plugin-enable raw document changed")
    return document


def _verify_document(
    document: Mapping[str, Any], outer_recorded_at: str, *, container_id: str
) -> None:
    action = document["action"]
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
        or set(action["prerequisites"])
        != {
            "boundary_before",
            "config_before",
            "config_lock_before",
            "gateway_process_before",
            "openclaw_before",
            "plugin_before",
            "plugin_tree_before",
            "runtime_tree_before",
            "system_info_before",
            "version",
        }
        or set(action["observations"])
        != {
            "boundary_after",
            "config_after",
            "config_lock_after",
            "gateway_process_after",
            "native_enable",
            "openclaw_after",
            "plugin_after",
            "plugin_tree_after",
            "runtime_tree_after",
            "system_info_after",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-plugin-enable-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE["digest"]
        or document["recorded_at"] != "2026-08-28T18:09:32.719Z"
        or len(document["run_nonce"]) != 32
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["runtime_binding"]
        != {
            "commit": contract._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": contract._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": config._RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or document["route"] != value_route()
        or canonical_digest(action) != _DIGESTS["action"]
        or action["id"] != "plugin-enable-activation"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("V3 plugin-enable document changed")
    _verify_commands(action, document["recorded_at"], outer_recorded_at)
    _verify_semantics(action, container_id=container_id)


def _verify_commands(
    action: Mapping[str, Any], document_recorded_at: str, outer_recorded_at: str
) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    aliases = [
        before["version"],
        before["system_info_before"]["command"],
        before["plugin_before"]["command"],
        after["native_enable"]["command"],
        after["plugin_after"]["command"],
        after["system_info_after"]["command"],
    ]
    commands = action["commands"]
    if commands != aliases or len(commands) != 6:
        raise AdmissionEvidenceError("V3 plugin-enable command aliases changed")
    pids = [command["pid"] for command in commands]
    if len(set(pids)) != len(pids) or any(
        type(pid) is not int or pid <= 0 or pid == 2673 for pid in pids
    ):
        raise AdmissionEvidenceError("V3 plugin-enable command PIDs changed")
    for command in commands:
        if parent._time(command["started_at"]) > parent._time(command["completed_at"]):
            raise AdmissionEvidenceError("V3 plugin-enable command time changed")
    for left, right in pairwise(commands):
        if parent._time(left["completed_at"]) > parent._time(right["started_at"]):
            raise AdmissionEvidenceError("V3 plugin-enable commands overlapped")
    if not (
        parent._time(commands[-1]["completed_at"])
        <= parent._time(document_recorded_at)
        <= parent._time(outer_recorded_at)
    ):
        raise AdmissionEvidenceError("V3 plugin-enable recording time changed")


def _verify_semantics(action: Mapping[str, Any], *, container_id: str) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    pairs = {
        "boundary": (before["boundary_before"], after["boundary_after"]),
        "config": (before["config_before"], after["config_after"]),
        "config_lock": (before["config_lock_before"], after["config_lock_after"]),
        "gateway_process": (
            before["gateway_process_before"],
            after["gateway_process_after"],
        ),
        "openclaw": (before["openclaw_before"], after["openclaw_after"]),
        "plugin_tree": (before["plugin_tree_before"], after["plugin_tree_after"]),
        "runtime_tree": (before["runtime_tree_before"], after["runtime_tree_after"]),
    }
    for name, (left, right) in pairs.items():
        if left != right or canonical_digest(left) != _SEMANTIC_DIGESTS[name]:
            raise AdmissionEvidenceError(f"V3 plugin-enable {name} snapshots changed")
    if (
        before["config_before"] != before["boundary_before"]["configuration"]
        or after["config_after"] != after["boundary_after"]["configuration"]
        or before["plugin_before"]["response"] != after["plugin_after"]["response"]
        or canonical_digest(before["plugin_before"]["response"])
        != _SEMANTIC_DIGESTS["plugin_response"]
        or before["plugin_before"]["command"]["stdout_digest"]
        != after["plugin_after"]["command"]["stdout_digest"]
    ):
        raise AdmissionEvidenceError("V3 plugin-enable pre-effect state changed")
    _verify_boundary(before["boundary_before"])
    _verify_config(before["config_before"])
    if before["config_lock_before"] != {
        "exists": False,
        "path": f"{_CONFIG_PATH}.lock",
    }:
        raise AdmissionEvidenceError("V3 plugin-enable config lock changed")
    gateway = before["gateway_process_before"]
    config._verify_gateway(gateway, container_id)
    if gateway["pid"] != 2673:
        raise AdmissionEvidenceError("V3 plugin-enable gateway PID changed")
    config._verify_openclaw(before["openclaw_before"])
    if before["runtime_tree_before"] != config._RUNTIME_TREE:
        raise AdmissionEvidenceError("V3 plugin-enable runtime tree changed")
    _verify_native_enable(after["native_enable"])
    _verify_plugin_observation(before["plugin_before"])
    _verify_plugin_observation(after["plugin_after"])
    config._verify_version(before["version"])
    for observation in (before["system_info_before"], after["system_info_after"]):
        parent._verify_json_command(
            observation,
            [
                "/usr/local/bin/node",
                "/runtime/lib/node_modules/openclaw/openclaw.mjs",
                "gateway",
                "call",
                "system.info",
                "--json",
                "--timeout",
                "5000",
            ],
        )
        config._verify_system(observation, gateway)
    config._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )


def _verify_boundary(value: Mapping[str, Any]) -> None:
    if value["ready"] is not True or value["effective_identity"] != {
        "gid": 992,
        "groups": [992],
        "uid": 992,
    }:
        raise AdmissionEvidenceError("V3 plugin-enable boundary changed")
    _verify_read_only_mount(
        value["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{config._RUNTIME_VOLUME}/_data",
    )
    _verify_read_only_mount(
        value["route_input"],
        path="/route-input",
        source=(
            "/docker/volumes/aragorn-phase3-final-combined-v3-plugin-enable-"
            "route-input-55143/_data"
        ),
    )


def _verify_read_only_mount(
    value: Mapping[str, Any], *, path: str, source: str
) -> None:
    if (
        value["ready"] is not True
        or value["read_only"] is not True
        or value["explicit"] is not True
        or value["path"] != path
        or value["error"] is not None
        or len(value["records"]) != 1
        or value["records"][0]["source"] != "/dev/vdb1"
        or value["records"][0]["root"] != source
        or value["records"][0]["mount_point"] != path
        or "ro" not in value["records"][0]["mount_options"]
    ):
        raise AdmissionEvidenceError("V3 plugin-enable read-only mount changed")


def _verify_config(value: Mapping[str, Any]) -> None:
    file = value["file"]
    mount = value["mount"]
    identity = parent._CONTRACT_FILES["config"]
    if (
        value["ready"] is not True
        or value["canonical_digest"] != identity["canonical_digest"]
        or value["plugin_policy"]
        != {
            "allow": ["aragorn-runtime-action-worker"],
            "enabled": True,
            "target_allowlisted": False,
            "target_entry": None,
            "target_entry_present": False,
        }
        or file["path"] != _CONFIG_PATH
        or file["type"] != "file"
        or file["exists"] is not True
        or file["uid"] != 992
        or file["gid"] != 0
        or file["mode"] != "400"
        or file["nlink"] != 1
        or file["size"] != identity["canonical_bytes"]
        or file["digest"] != identity["canonical_digest"]
        or file["digest_error"] is not None
        or mount["ready"] is not True
        or mount["read_only"] is not True
        or mount["explicit"] is not True
        or mount["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or mount["error"] is not None
        or len(mount["records"]) != 1
        or mount["records"][0]["filesystem"] != "ramfs"
        or mount["records"][0]["source"] != "ramfs"
        or "ro" not in mount["records"][0]["mount_options"]
    ):
        raise AdmissionEvidenceError("V3 plugin-enable credential changed")


def _verify_native_enable(value: Mapping[str, Any]) -> None:
    command = value["command"]
    if (
        canonical_digest(value) != _SEMANTIC_DIGESTS["native_enable"]
        or set(value) != {"command", "process_started", "target_plugin_id"}
        or value["process_started"] is not True
        or value["target_plugin_id"] != _PLUGIN_ID
        or set(command)
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
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "plugins",
            "enable",
            _PLUGIN_ID,
        ]
        or type(command["exit_code"]) is not int
        or command["exit_code"] != 1
        or command["error"] is not None
        or command["signal"] is not None
        or command["stdout_bytes"] != 0
        or command["stdout_digest"] != _EMPTY_DIGEST
        or command["stdout_excerpt"] != ""
        or command["stderr_bytes"] != len(_STDERR.encode())
        or command["stderr_digest"] != _digest(_STDERR.encode())
        or command["stderr_excerpt"] != _STDERR
    ):
        raise AdmissionEvidenceError("V3 plugin-enable native denial changed")


def _verify_plugin_observation(value: Mapping[str, Any]) -> None:
    enable._verify_plugin_inspection(value)
    enable._verify_plugin(value["response"])
    plugin_value = value["response"]["value"]
    plugin = plugin_value["plugin"]
    if (
        plugin_value["capabilityCount"] != 1
        or type(plugin_value["capabilityCount"]) is not int
        or plugin["id"] != _PLUGIN_ID
        or plugin["source"] != f"{_PLUGIN_ROOT}/index.js"
        or plugin["rootDir"] != _PLUGIN_ROOT
        or plugin["enabled"] is not False
        or plugin["explicitlyEnabled"] is not False
        or plugin["activated"] is not False
        or plugin["imported"] is not False
    ):
        raise AdmissionEvidenceError("V3 plugin-enable plugin state changed")


def value_route() -> dict[str, Any]:
    """Expose the exact route identifier for schema tooling."""

    return {
        "action_id": "plugin-enable-activation",
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }
