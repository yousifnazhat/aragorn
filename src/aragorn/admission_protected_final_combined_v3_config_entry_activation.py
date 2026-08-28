"""Qualify one exact V3 enabled=true config-entry persistence denial."""

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

from . import admission_protected_final_combined_v3_plugin_enable as enable_route
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

parent = enable_route.parent
contract = parent.contract
enable = parent.parent.parent
config = enable.base

_ROUTE = "ADM-02/update/config-entry-activation"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_CONFIG_PATH = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
_TARGET_ROOT = "/opt/aragorn/runtime-profile/template-skill"
_ROUTE_VOLUME = (
    "aragorn-phase3-final-combined-v3-config-entry-activation-route-input-90778"
)
_ROUTE_PROBE = (
    "/route-input/config-entry-activation/protected-config-activation-v3-probe.mjs"
)
_VERIFIER_PATH = (
    "src/aragorn/admission_protected_final_combined_v3_config_entry_activation.py"
)
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

_BASE = {
    "digest": "sha256:91af7f107f0315ce622b3f5447b1da6d388a663ace1d3aec3d7b0a4c80c5c906",
    "path": "src/aragorn/admission_protected_final_combined_v3_plugin_enable.py",
}
_EVIDENCE = {
    "bytes": 504_137,
    "canonical_bytes": 504_136,
    "canonical_digest": "sha256:845ac848b9aeb76a314c13a3eb90f29bce18362be7917acdbb8fab47b9346fae",
    "digest": "sha256:6e1606766e97c5bcb6fcfc3d5da5e52bd5f6bd1aadc548ce7ea2aaa59348a37e",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-config-"
        "entry-activation-systemd-p3-final-2026-08-28.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 29_906,
    "canonical_digest": "sha256:716fc6119e6527e78de1a8d2689460e598207dad57cabf0043e87f04b278fb2e",
    "digest": "sha256:1c5ba0629ddde350a64d1735f0eb1a4be25140819d5f7be9a1a294dadc9c1174",
}
_SOURCE = {
    "commit": "c168317bad852c01ea0e16aa5044464a5626dfe9",
    "parent": "b45a4e0dd9ec447409dcb16aaca6c2a568b0ffb9",
    "tree": "50a57fc309576b24fb8140e33ff2ea48dfd36df4",
}
_RETENTION = {
    "commit": "ab9de09d2735ff379e176b6069211dcdf4309620",
    "parent": _SOURCE["commit"],
    "tree": "db62ff08e855aee7ff36e934973c24b9d2baf560",
}
_RETENTION_BLOB = "f8f4999b260ab9db4e5ab9993e82f139fc13ca0f"
_IMAGE = "sha256:bd2b00e7362a039bb7d8399822f5a837b0b0ddadc0c57973a5b78820160b52b6"
_PARENT_IMAGE = "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
_ADDED_LAYERS = [
    "sha256:be894a22b461814c051d1e44f6c2ddbc076cdf2ba14ea4cd0c5377a13c626c6d",
    "sha256:41c4cb15e85b7bcadc3ea43a30e969a4d837669092e7536685e48f38712a5bb1",
    "sha256:765e5d9b955e03ec1f889cc9fa18877845174f586d277a76c1957c4ac4b063fc",
    "sha256:26982427f74fca49183f64ae0366fa146f840d51d4c74556a8741cfda749f2eb",
]

_PROBE = {
    "bytes": 23_366,
    "digest": "sha256:e577e5e6cd769bc24886b976792499f06fd6c279f3df24b7f17b652a08e66db5",
    "name": "protected-config-activation-v3-probe.mjs",
}
_SOURCE_PROBE = {
    "bytes": 20_622,
    "digest": "sha256:49c9c173cf6214a16e77e6cf5084c7cb91f8fd5c2e0b8555612d8c1174de2234",
    "path": "benchmark/admission/openclaw-v2026.7.1/protected-config-activation-probe.mjs",
}
_V2_PROBE = {
    "bytes": 23_366,
    "digest": "sha256:69a2c203e566128a2968b35b85b130cd50107b3ba9367512a50e56e73e65ca93",
    "path": "benchmark/admission/openclaw-v2026.7.1/protected-config-activation-v2-probe.mjs",
}
_TRANSFORMED_PROBE_PATH = (
    "benchmark/admission/openclaw-v2026.7.1/protected-config-activation-v3-probe.mjs"
)
_MATERIALIZER = {
    "bytes": 87_912,
    "digest": "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
    "path": "scripts/materialize_fixed_admission_probes.py",
}
_TRANSFORM = {
    "configuration_bytes": {"from": 1_880, "occurrences": 1, "to": 2_159},
    "configuration_digest": {
        "from": "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
        "occurrences": 3,
        "to": parent._CONTRACT_FILES["config"]["canonical_digest"],
    },
    "v2_materialization": {
        "mode": "final-combined-v2",
        "result_digest": _V2_PROBE["digest"],
        "source_digest": _SOURCE_PROBE["digest"],
    },
}

_SOURCE_ARTIFACTS = {
    "checked_in_probe": {**_SOURCE_PROBE, "mode": "0444"},
    "collector": {
        "bytes": 25_606,
        "digest": "sha256:7068d97d634af33e5f15e577e3ab96db81d74d40d2a79294dd8c0adead160fa7",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_combined_v3_config_entry_activation_systemd_probe.py",
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
    "materialized_v2_probe": {**_V2_PROBE, "mode": "0444"},
    "materializer": {**_MATERIALIZER, "mode": "0555"},
    "transformed_probe": {
        **_PROBE,
        "mode": "0444",
        "path": _TRANSFORMED_PROBE_PATH,
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
        "bytes": 24_405,
        "digest": "sha256:3f5bbe56783983e87027b005902ac3267306de5b286e5c28a7a5d96dadadf1d6",
        "mode": "0555",
        "path": "scripts/capture_runtime_action_worker_final_combined_v3_config_entry_activation_systemd.sh",
    },
    "dockerfile": {
        "bytes": 6_882,
        "digest": "sha256:e786c1b1332fa6d427d3f6249fbfefeacffd81c6ed1b339d13fb58b334f1d0d0",
        "mode": "0444",
        "path": "benchmark/runtime-action-worker-final-combined-v3-config-entry-activation-systemd/Dockerfile",
    },
    "inherited_combined_base": _SOURCE_ARTIFACTS["inherited_combined_base"],
    "inherited_route_injector": _SOURCE_ARTIFACTS["inherited_route_injector"],
    "inherited_v3_contract_helpers": _SOURCE_ARTIFACTS["inherited_v3_contract_base"],
    "probe": _SOURCE_ARTIFACTS["collector"],
}

_DIGESTS = {
    "composition": "sha256:66b936ad977c70e3be93b47f304964d1b9fed0aca7ca4e99df296870f78d59b3",
    "composition_action": "sha256:2758aee2ca7b2d22a01c39c9f4bfa4d9aeed7ecdf828e560845cf11a4d66791d",
    "source_artifacts": "sha256:7822ddacc00f9b39039f721793a575a95692609c3b1bea5c5d97a75012ba491a",
    "harness": "sha256:42c9e0efea14e20eeca947e542bbd631793e61673a54882c8d7396e7b9c2b67d",
    "route_observation": "sha256:1286acbd353c8a576dbd8e13c7cbfdb9b2878c234c0b214b8c24431c67913f74",
    "execution": "sha256:e8b5aef69f0183e56d9461a6487043da4bddca975cb390de97e3a93bb5d84099",
    "gateway": "sha256:3e5eeb941a08f0ba70dede13410dd2f87738b9b84075e8eb345d9de2be14d16b",
    "stack": "sha256:81ddf55ce7a82cb270bc19fc1c910afd90d9f57ae020d22ab0f5e167ae7a7871",
    "document": _ROUTE_RAW["canonical_digest"],
    "action": "sha256:b294139d77758379d6b57f217c8d9b5f6116e851130c832da6c30613f14ffddf",
    "v3_artifact": "sha256:3937b9f0bbcd0d44195b173cd4030e65b7e3957d689d3889980358dc6dd6d29c",
}
_TYPE_SHAPE_DIGEST = "sha256:fe103b5fdda9d409533b00abdd350b6787f8fa006e226fde03603916f35c6b08"
_SEMANTIC_DIGESTS = {
    "boundary": "sha256:84a74ef05c949c0a41ea17a03bb593450fe3de5f9b11137d74478e5b43c2f79b",
    "config": "sha256:f3de9ce437991e8bedde1f918ccfba7d8d078daf523322850e74389b5af68b9e",
    "config_lock": "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2",
    "discovery_before": "sha256:e18e5f05f4c3e5fe76f3f40fea1ea465494b7d3a9496e5ad0d736b5f05ca7b4c",
    "discovery_after": "sha256:1cf8d5c28dd399173e1c4adf4009419f26848d707d042e89616ad4dc5be3af07",
    "discovery_response": "sha256:a7af181736e784ad9f6232c25eb2b4c373b98f81c098613d5375e94401f9f159",
    "gateway_process": "sha256:f327d2d64665517134ac1fe4214cb4162b57f5d90a314f82595a4fda0cda0893",
    "harness_document": "sha256:ca79f050a3af17b1c96aa8cf65224c5fa31faed3c3df524a49c33f17f75dffb4",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "runtime_tree": "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b",
    "stack": _DIGESTS["stack"],
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
    "update": "sha256:4893a0845a0c517c9eefd7abb75e2bf69ba7d07a3b47342bf87435187c1ee3d1",
    "update_response": "sha256:e86e3ce32c27eb3b9fd4ad5bfea64dbe63c66a69d46fed8c81cf3990e61547d4",
    "system_stable": "sha256:a7a411ef5a231d4315f26285e08a50e0f3504795625ef5c967e8428cfedae53c",
    "version": "sha256:4898e8cf0172b75c4a971fb5648220223bd5b9c846c82111dbac36f134b8ea91",
}
_ARTIFACT_DIGESTS = {
    "activator": "sha256:c43b088e0560d904509da9f2177a18c201034f3373ce368126cf46ebbc0e4995",
    "activator_source": "sha256:f14374921b839ed5f7f2b9f685de38e2cde18901620bcf77b80a1095b6e65359",
    "collector": "sha256:34f5d049c0a69d05a6358bab27275742fc675055723ffeb363e264164298ab38",
    "config": "sha256:43ce7ebe7e7f0b9c4323008fc56d5377565d43043f03837aaf49dcd5ba7bf1ec",
    "config_entry_activation_probe": "sha256:d44470e646a23a54b458a6b66db0746af1c2abd32efe107642685e52b36accde",
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
    "TEMPLATE_SKILL_ALREADY_AVAILABLE_AND_ELIGIBLE_BEFORE_ACTION",
    "ONLY_ENABLED_TRUE_CONFIG_ENTRY_PERSISTENCE_ATTEMPT_OBSERVED",
    "NO_DISABLED_TO_ENABLED_ACTIVATION_TRANSITION_CLAIM",
    "NO_INSTALL_POLICY_CAUSALITY_CLAIM",
    "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
    "CONFIG_ENTRY_ACTIVATION_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_CONFIG_LOGICAL_STATE_EQUIVALENCE_ROLLBACK_OR_CAUSALITY_CLAIM",
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
    "status": "FINAL_COMBINED_V3_CONFIG_ENTRY_PERSISTENCE_ATTEMPT_OBSERVED_PROFILE_NOT_TESTED",
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


def verify_openclaw_final_combined_v3_config_entry_activation(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one narrow config-persistence PASS and twenty NOT_TESTED routes."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract._read_blob(evidence_cas, _EVIDENCE, "V3 config entry")
        if raw != retained:
            raise AdmissionEvidenceError("V3 config-entry CAS differs from signed retention")
        evidence = contract._load_canonical_json(raw, _EVIDENCE, "V3 config entry")
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
        raise AdmissionEvidenceError(f"invalid V3 config-entry evidence: {exc}") from exc

    routes = [
        {"id": route["id"], "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED"}
        for route in profile["routes"]
    ]
    return {
        "schema": "aragorn/admission-protected-final-combined-v3-config-entry-persistence-route-coverage/v1",
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_ENABLED_TRUE_CONFIG_ENTRY_"
            "PERSISTENCE_DENIAL_ROUTE_ONLY"
        ),
        "bindings": {
            "configuration": dict(parent._CONTRACT_FILES["config"]),
            "config_entry_observation": {
                **_EVIDENCE,
                "retention": {**_RETENTION, "signing_key": contract._SIGNATURE["key"]},
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {**_SOURCE, "signature": dict(contract._SIGNATURE)},
            },
            "image": _IMAGE,
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
            "ONE_EXACT_ENABLED_TRUE_CONFIG_ENTRY_PERSISTENCE_ATTEMPT_ROUTE_ONLY",
            "TWENTY_OTHER_V3_ROUTES_NOT_TESTED",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
            "TEMPLATE_SKILL_ALREADY_AVAILABLE_AND_ELIGIBLE_BEFORE_ACTION",
            "NO_DISABLED_TO_ENABLED_ACTIVATION_TRANSITION_CLAIM",
            "PERSISTENCE_ATTEMPT_DENIED_BEFORE_CONFIG_MUTATION_CALLBACK_AT_READ_ONLY_SYSTEMD_CREDENTIAL_LOCK",
            "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_NOT_CAUSAL_FOR_THIS_DENIAL",
            "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
            "NO_CONFIG_LOGICAL_STATE_EQUIVALENCE_ROLLBACK_OR_CAUSALITY_CLAIM",
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
            "availability_transition_dynamically_exercised": False,
            "dynamically_exercised_routes": [_ROUTE],
            "install_policy_dynamically_exercised": False,
            "pass_basis": (
                "NATIVE_SKILLS_UPDATE_ENABLED_TRUE_CONFIG_ENTRY_PERSISTENCE_ATTEMPT_"
                "DENIED_BEFORE_CONFIG_MUTATION_CALLBACK_AT_READ_ONLY_SYSTEMD_"
                "CREDENTIAL_LOCK"
            ),
            "transitions_dynamically_exercised": False,
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
    raise AdmissionEvidenceError("V3 config-entry JSON type changed")


def _verify_dependencies() -> None:
    path = Path(enable_route.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_BASE["path"]).name
        or _digest(path.read_bytes()) != _BASE["digest"]
    ):
        raise AdmissionEvidenceError("V3 config-entry verifier base changed")
    enable_route._verify_dependencies()


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
        raise AdmissionEvidenceError("V3 config-entry repository changed")
    config.base._verify_commit(_SOURCE)
    config.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V3 config-entry signed tree entry changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=640 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V3 config-entry signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    if canonical_digest(_type_shape(evidence)) != _TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError("V3 config-entry JSON type shape changed")
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
        != "aragorn/runtime-action-worker-final-combined-v3-config-entry-activation-systemd-observation/v1"
        or evidence["recorded_at"] != "2026-08-28T19:03:06.552531Z"
        or evidence["route_id"] != _ROUTE
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V3_RAW_CONFIG_ENTRY_ENABLED_TRUE_PERSISTENCE_"
            "ATTEMPT_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_"
            "RELEASE_AUTHORITY"
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
        raise AdmissionEvidenceError("V3 config-entry outer observation changed")
    _verify_sources(evidence["source_artifacts"])
    profile = _verify_composition(evidence["composition"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError("V3 config-entry harness copies differ")
    _verify_harness(evidence["harness"])
    if (
        evidence["route_observation"]["bundle"]
        != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V3 config-entry route bundle changed")
    _verify_route_observation(
        evidence["route_observation"],
        evidence["recorded_at"],
        composition_recorded_at=evidence["composition"]["recorded_at"],
        boundaries=evidence["composition"]["action"]["boundaries"],
        container_id=evidence["harness"]["document"]["container_id"],
    )
    return profile


def _verify_sources(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V3 config-entry source inventory changed")
    git = config.base.legacy._git
    for name, expected in _SOURCE_ARTIFACTS.items():
        enable_route._verify_file_record(
            value[name],
            path=f"/src/{expected['path']}",
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=f"config-entry {name} source",
        )
        if name in _SIGNED_SOURCE_ARTIFACTS:
            _verify_signed_bytes(git, expected)
    if value["probe_bundle"] != [_PROBE]:
        raise AdmissionEvidenceError("V3 config-entry probe bundle changed")
    _verify_probe_transform(git)


def _verify_signed_bytes(git: Any, expected: Mapping[str, Any]) -> bytes:
    raw = git(
        ["show", f"{_SOURCE['commit']}:{expected['path']}"],
        maximum=expected["bytes"],
    )
    if len(raw) != expected["bytes"] or _digest(raw) != expected["digest"]:
        raise AdmissionEvidenceError("V3 config-entry signed source changed")
    return raw


def _verify_probe_transform(git: Any) -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    signed_source = _verify_signed_bytes(git, _SOURCE_PROBE)
    signed_materializer = _verify_signed_bytes(git, _MATERIALIZER)
    source_path = (root / _SOURCE_PROBE["path"]).resolve(strict=True)
    materializer_path = (root / _MATERIALIZER["path"]).resolve(strict=True)
    if (
        source_path.read_bytes() != signed_source
        or materializer_path.read_bytes() != signed_materializer
    ):
        raise AdmissionEvidenceError("V3 config-entry materializer checkout changed")
    namespace = runpy.run_path(str(materializer_path))
    materialize = namespace.get("transformed_final_combined_v2_probe")
    if not callable(materialize):
        raise AdmissionEvidenceError("V3 config-entry materializer entry changed")
    v2 = materialize(Path(_SOURCE_PROBE["path"]).name)
    if (
        type(v2) is not bytes
        or len(v2) != _V2_PROBE["bytes"]
        or _digest(v2) != _V2_PROBE["digest"]
    ):
        raise AdmissionEvidenceError("V3 config-entry V2 materialization changed")
    old_digest = _TRANSFORM["configuration_digest"]["from"].encode()
    new_digest = _TRANSFORM["configuration_digest"]["to"].encode()
    old_size = b"configuration.file?.size === 1880"
    new_size = b"configuration.file?.size === 2159"
    if (
        v2.count(old_digest) != 3
        or v2.count(new_digest) != 0
        or v2.count(old_size) != 1
        or v2.count(new_size) != 0
    ):
        raise AdmissionEvidenceError("V3 config-entry transform input changed")
    transformed = v2.replace(old_digest, new_digest).replace(old_size, new_size)
    if (
        len(transformed) != _PROBE["bytes"]
        or _digest(transformed) != _PROBE["digest"]
    ):
        raise AdmissionEvidenceError("V3 config-entry transformed probe changed")
    return transformed


def _verify_composition(composition: Mapping[str, Any]) -> Mapping[str, Any]:
    action = composition["action"]
    artifact = action["artifacts"]["final_combined_v3_config_entry_activation"]
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
        != "aragorn/runtime-action-worker-final-combined-v3-config-entry-activation-systemd-observation/v1"
        or composition["authority"]
        != (
            "BOUND_FINAL_COMBINED_V3_RAW_CONFIG_ENTRY_ENABLED_TRUE_PERSISTENCE_"
            "ATTEMPT_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_"
            "RELEASE_AUTHORITY"
        )
        or composition["recorded_at"] != "2026-08-28T19:03:06.552471Z"
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
        or canonical_digest(action) != _DIGESTS["composition_action"]
        or canonical_digest(artifact) != _DIGESTS["v3_artifact"]
    ):
        raise AdmissionEvidenceError("V3 config-entry composition changed")
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
        raise AdmissionEvidenceError("V3 config-entry profile changed")
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
        raise AdmissionEvidenceError("V3 config-entry composition boundary changed")
    return profile


def _verify_artifact(artifact: Mapping[str, Any]) -> None:
    if set(artifact) != set(_ARTIFACT_DIGESTS):
        raise AdmissionEvidenceError("V3 config-entry artifact inventory changed")
    for name, digest in _ARTIFACT_DIGESTS.items():
        if canonical_digest(artifact[name]) != digest:
            raise AdmissionEvidenceError(f"V3 config-entry {name} artifact changed")
    parent._verify_contract_artifacts(artifact)
    git = config.base.legacy._git
    for expected in parent._CONTRACT_FILES.values():
        _verify_signed_bytes(git, expected)

    for name, path, bytes_, digest, mode in (
        (
            "activator_source",
            "/src/packaging/activate-runtime-action-worker-host-v3.sh",
            30_504,
            "sha256:3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c",
            "0555",
        ),
        (
            "activator",
            "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh",
            30_504,
            "sha256:3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c",
            "0755",
        ),
        (
            "preflight_source",
            "/src/src/aragorn/runtime_action_worker.py",
            37_878,
            "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873",
            "0444",
        ),
        (
            "preflight",
            "/usr/lib/aragorn/aragorn/runtime_action_worker.py",
            37_878,
            "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873",
            "0644",
        ),
    ):
        enable_route._verify_file_record(
            artifact[name],
            path=path,
            bytes_=bytes_,
            digest=digest,
            mode=mode,
            label=f"config-entry {name}",
        )
    _verify_signed_bytes(
        git,
        {
            "bytes": 37_878,
            "digest": "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873",
            "path": "src/aragorn/runtime_action_worker.py",
        },
    )
    if artifact["installed_runtime"] != artifact["runtime_lock"]["document"]["installed_runtime"]:
        raise AdmissionEvidenceError("V3 config-entry installed runtime changed")
    for name, expected in _COLLECTOR_ARTIFACTS.items():
        enable_route._verify_file_record(
            artifact["collector"][name],
            path=f"/src/{expected['path']}",
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=f"config-entry collector {name}",
        )
        _verify_signed_bytes(git, expected)
    plugin = artifact["plugin"]
    expected_plugin = {
        "index.js": (23_860, "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b"),
        "openclaw.plugin.json": (723, "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036"),
        "package.json": (134, "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2"),
    }
    if set(plugin) != set(expected_plugin):
        raise AdmissionEvidenceError("V3 config-entry Aragorn plugin changed")
    for name, (bytes_, digest) in expected_plugin.items():
        enable_route._verify_file_record(
            plugin[name],
            path=f"/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/{name}",
            bytes_=bytes_,
            digest=digest,
            mode="0644",
            label=f"config-entry Aragorn plugin {name}",
        )
    enable_route._verify_file_record(
        artifact["skill"]["file"],
        path=f"{_TARGET_ROOT}/SKILL.md",
        bytes_=140,
        digest=config._SOURCES["skill"]["digest"],
        mode="0444",
        label="config-entry skill",
    )
    _verify_artifact_probe(artifact["config_entry_activation_probe"], git)


def _verify_artifact_probe(value: Mapping[str, Any], git: Any) -> None:
    if set(value) != {
        "checked_in_source",
        "materialized_v2_source",
        "materializer",
        "runtime",
        "transform",
        "transformed_source",
    } or value["transform"] != _TRANSFORM:
        raise AdmissionEvidenceError("V3 config-entry transform artifact changed")
    records = (
        ("checked_in_source", _SOURCE_PROBE, f"/src/{_SOURCE_PROBE['path']}", "0444"),
        ("materialized_v2_source", _V2_PROBE, f"/src/{_V2_PROBE['path']}", "0444"),
        ("materializer", _MATERIALIZER, f"/src/{_MATERIALIZER['path']}", "0555"),
        ("transformed_source", _PROBE, f"/src/{_TRANSFORMED_PROBE_PATH}", "0444"),
        ("runtime", _PROBE, _ROUTE_PROBE, "0444"),
    )
    for name, expected, path, mode in records:
        enable_route._verify_file_record(
            value[name],
            path=path,
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=mode,
            label=f"config-entry {name}",
        )
    _verify_probe_transform(git)


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
    lineage = document["image_lineage"]
    parent_layers = lineage["parent"]["layers"]
    child_layers = lineage["child"]["layers"]
    if (
        set(value) != {"digest", "document", "file"}
        or parsed != document
        or raw != canonical_json(document)
        or canonical_digest(document) != _SEMANTIC_DIGESTS["harness_document"]
        or value["digest"] != _SEMANTIC_DIGESTS["harness_document"]
        or file["bytes"] != 20_719
        or len(raw) != 20_719
        or file["digest"] != _SEMANTIC_DIGESTS["harness_document"]
        or file["path"] != "/run/aragorn-harness.json"
        or document["schema"]
        != "aragorn/runtime-action-worker-final-combined-v3-config-entry-activation-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["platform"] != "linux"
        or document["profile_label"]
        != "phase3-final-combined-v3-config-entry-activation"
        or document["image_reference"]
        != "aragorn-phase3-final-combined-v3-config-entry-activation-systemd"
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["rootfs_type"] != "layers"
        or lineage["child"]["rootfs_type"] != "layers"
        or len(parent_layers) != 108
        or len(child_layers) != 112
        or child_layers[: len(parent_layers)] != parent_layers
        or child_layers[len(parent_layers) :] != _ADDED_LAYERS
        or lineage["added_layers"] != _ADDED_LAYERS
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
            "source": _ROUTE_VOLUME,
            "type": "volume",
        }
        or f"{config._RUNTIME_VOLUME}:/runtime:ro" not in host["binds"]
        or f"{_ROUTE_VOLUME}:/route-input:ro" not in host["binds"]
        or document["openclaw_runtime_volume"] != config._RUNTIME_VOLUME
        or document["route_input_volume_identity"]["name"] != _ROUTE_VOLUME
        or document["route_input_volume_identity"]["labels"]
        != {
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:90778",
            "dev.aragorn.role": "final-combined-v3-config-entry-activation-route-input",
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
        raise AdmissionEvidenceError("V3 config-entry harness changed")


def _verify_route_observation(
    value: Mapping[str, Any],
    recorded_at: str,
    *,
    composition_recorded_at: str,
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
            "mount_namespace": "/proc/2665/ns/mnt",
            "pid": 2665,
            "unit": "aragorn-agent-gateway.service",
        }
        or value["route"] != value_route()
    ):
        raise AdmissionEvidenceError("V3 config-entry route envelope changed")
    _verify_execution(value["execution"], gateway)
    service_pids = _verify_stack(
        value["stack_before"],
        boundaries=boundaries,
        container_id=container_id,
        gateway=gateway,
    )
    document = _verify_document_raw(value["raw"], value["document"])
    _verify_document(
        document,
        recorded_at,
        container_id=container_id,
        execution=value["execution"],
        service_pids=service_pids,
    )
    commands = document["action"]["commands"]
    if not (
        parent._time(value["execution"]["started_at"])
        <= parent._time(commands[0]["started_at"])
        <= parent._time(commands[-1]["completed_at"])
        <= parent._time(document["recorded_at"])
        <= parent._time(value["execution"]["completed_at"])
        <= parent._time(composition_recorded_at)
        <= parent._time(recorded_at)
    ):
        raise AdmissionEvidenceError("V3 config-entry outer execution time changed")


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
        or parent._time(value["started_at"]) > parent._time(value["completed_at"])
    ):
        raise AdmissionEvidenceError("V3 config-entry execution changed")


def _verify_stack(
    stack: Mapping[str, Any],
    *,
    boundaries: Mapping[str, Any],
    container_id: str,
    gateway: Mapping[str, Any],
) -> set[int]:
    gateway_unit = gateway["unit"]
    units = {
        gateway_unit,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    process = stack["processes"][gateway_unit]
    pids = set(stack["pids"].values())
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
        or len(pids) != 4
        or any(type(pid) is not int or pid <= 0 for pid in pids)
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
        raise AdmissionEvidenceError("V3 config-entry stack binding changed")
    return pids


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
        raise AdmissionEvidenceError("V3 config-entry raw document changed")
    return document


def _verify_document(
    document: Mapping[str, Any],
    outer_recorded_at: str,
    *,
    container_id: str,
    execution: Mapping[str, Any],
    service_pids: set[int],
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
            "discovery_before",
            "gateway_process_before",
            "openclaw_before",
            "runtime_tree_before",
            "system_info_before",
            "target_before",
            "version",
        }
        or set(action["observations"])
        != {
            "boundary_after",
            "config_after",
            "config_lock_after",
            "discovery_after",
            "gateway_process_after",
            "openclaw_after",
            "runtime_tree_after",
            "system_info_after",
            "target_after",
            "update",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-config-activation-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE["digest"]
        or document["recorded_at"] != "2026-08-28T19:03:06.193Z"
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
        or action["id"] != "config-entry-activation"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("V3 config-entry document changed")
    _verify_commands(
        action,
        document["recorded_at"],
        outer_recorded_at,
        execution=execution,
        service_pids=service_pids,
    )
    _verify_semantics(action, container_id=container_id)


def _verify_commands(
    action: Mapping[str, Any],
    document_recorded_at: str,
    outer_recorded_at: str,
    *,
    execution: Mapping[str, Any],
    service_pids: set[int],
) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    aliases = [
        before["version"],
        before["system_info_before"]["command"],
        before["discovery_before"]["command"],
        after["update"]["command"],
        after["discovery_after"]["command"],
        after["system_info_after"]["command"],
    ]
    commands = action["commands"]
    if commands != aliases or len(commands) != 6:
        raise AdmissionEvidenceError("V3 config-entry command aliases changed")
    pids = [command["pid"] for command in commands]
    if (
        len(set(pids)) != 6
        or any(type(pid) is not int or pid <= 0 for pid in pids)
        or not set(pids).isdisjoint(service_pids)
    ):
        raise AdmissionEvidenceError("V3 config-entry command PIDs changed")
    for command in commands:
        if parent._time(command["started_at"]) > parent._time(command["completed_at"]):
            raise AdmissionEvidenceError("V3 config-entry command time changed")
    for left, right in pairwise(commands):
        if parent._time(left["completed_at"]) > parent._time(right["started_at"]):
            raise AdmissionEvidenceError("V3 config-entry commands overlapped")
    if not (
        parent._time(execution["started_at"])
        <= parent._time(commands[0]["started_at"])
        <= parent._time(commands[-1]["completed_at"])
        <= parent._time(document_recorded_at)
        <= parent._time(execution["completed_at"])
        <= parent._time(outer_recorded_at)
    ):
        raise AdmissionEvidenceError("V3 config-entry recording time changed")


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
        "runtime_tree": (before["runtime_tree_before"], after["runtime_tree_after"]),
        "target": (before["target_before"], after["target_after"]),
    }
    for name, (left, right) in pairs.items():
        if left != right or canonical_digest(left) != _SEMANTIC_DIGESTS[name]:
            raise AdmissionEvidenceError(f"V3 config-entry {name} snapshots changed")
    if (
        before["config_before"] != before["boundary_before"]["configuration"]
        or after["config_after"] != after["boundary_after"]["configuration"]
        or before["discovery_before"]["response"]
        != after["discovery_after"]["response"]
        or canonical_digest(before["discovery_before"])
        != _SEMANTIC_DIGESTS["discovery_before"]
        or canonical_digest(after["discovery_after"])
        != _SEMANTIC_DIGESTS["discovery_after"]
        or canonical_digest(before["discovery_before"]["response"])
        != _SEMANTIC_DIGESTS["discovery_response"]
        or before["discovery_before"]["command"]["stdout_digest"]
        != after["discovery_after"]["command"]["stdout_digest"]
        or canonical_digest(after["update"]) != _SEMANTIC_DIGESTS["update"]
        or canonical_digest(after["update"]["response"])
        != _SEMANTIC_DIGESTS["update_response"]
        or canonical_digest(before["version"]) != _SEMANTIC_DIGESTS["version"]
    ):
        raise AdmissionEvidenceError("V3 config-entry pre-effect state changed")
    _verify_boundary(before["boundary_before"])
    _verify_config(before["config_before"])
    if before["config_lock_before"] != {
        "exists": False,
        "path": f"{_CONFIG_PATH}.lock",
    }:
        raise AdmissionEvidenceError("V3 config-entry config lock changed")
    gateway = before["gateway_process_before"]
    config._verify_gateway(gateway, container_id)
    if gateway["pid"] != 2665:
        raise AdmissionEvidenceError("V3 config-entry gateway PID changed")
    config._verify_openclaw(before["openclaw_before"])
    if before["runtime_tree_before"] != config._RUNTIME_TREE:
        raise AdmissionEvidenceError("V3 config-entry runtime tree changed")
    config._verify_target(before["target_before"])
    for observation in (before["discovery_before"], after["discovery_after"]):
        config._verify_discovery(observation)
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
        projection = {key: observation["response"]["value"][key] for key in stable}
        if canonical_digest(projection) != _SEMANTIC_DIGESTS["system_stable"]:
            raise AdmissionEvidenceError("V3 config-entry system identity changed")
    config._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )
    config._verify_version(before["version"])
    config._verify_update(after["update"])


def _verify_boundary(value: Mapping[str, Any]) -> None:
    if (
        value["ready"] is not True
        or value["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or set(value["roots"])
        != {
            "extensions",
            "managed_skills",
            "personal_agents",
            "plugin_skills",
            "project_agents",
            "workspace_skills",
        }
    ):
        raise AdmissionEvidenceError("V3 config-entry boundary changed")
    _verify_config(value["configuration"])
    _verify_read_only_mount(
        value["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{config._RUNTIME_VOLUME}/_data",
    )
    _verify_read_only_mount(
        value["probe"],
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
    for name, path in root_paths.items():
        boundary = value["roots"][name]
        entry = boundary["observation"]
        if (
            boundary["ready"] is not True
            or boundary["writable"] is not True
            or entry["path"] != path
            or entry["type"] != "directory"
            or entry["uid"] != 992
            or entry["gid"] != 992
            or entry["mode"] != "700"
            or entry["entries"] != []
            or entry["entry_count"] != 0
            or entry["entries_truncated"] is not False
        ):
            raise AdmissionEvidenceError("V3 config-entry conventional root changed")


def _verify_config(value: Mapping[str, Any]) -> None:
    file = value["file"]
    mount = value["mount"]
    identity = parent._CONTRACT_FILES["config"]
    if (
        value["ready"] is not True
        or value["canonical_digest"] != identity["canonical_digest"]
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
        raise AdmissionEvidenceError("V3 config-entry credential changed")


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
        raise AdmissionEvidenceError("V3 config-entry read-only mount changed")


def value_route() -> dict[str, Any]:
    """Expose the exact route identifier for schema tooling."""

    return {
        "action_id": "config-entry-activation",
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }
