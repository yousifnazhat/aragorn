"""Qualify one exact current-V3 native chat snapshot-consumer route."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import tarfile
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import (
    admission_protected_final_combined_v2_chat_session_snapshot_consumer_catalog_fixed as chat_semantics,
)
from . import (
    admission_protected_final_combined_v3_session_snapshot_consumer as session,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

contract = session.contract
current = session.current
v3_contract = session.v3_contract

_ROUTE = "ADM-02/reload/chat-session-snapshot-consumer"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = (
    "aragorn-phase3-final-combined-v3-chat-session-snapshot-consumer-route-input-45618"
)
_IMAGE = "sha256:207cefad579f11815d0f7299104bd8ab65b37933bc74b66f5652bafebad9a9bb"
_PARENT_IMAGE = session._PARENT_IMAGE
_EMPTY_DIGEST = session._EMPTY_DIGEST
_PROTECTED_PROMPT_DIGEST = chat_semantics._PROTECTED_PROMPT_DIGEST
_PROBE_BUNDLE = [
    {
        "bytes": 42_287,
        "digest": "sha256:9a091bd617bf2e78d436218098f2c2b9ca616815ec1a1598afe42b28a263aaa7",
        "name": "protected-chat-session-snapshot-consumer-v3-probe.mjs",
    },
    {
        "bytes": 16_324,
        "digest": "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        "name": "protected-observation-v1.mjs",
    },
]
_DEPENDENCIES = {
    "v2_chat_semantics": {
        "bytes": 19_357,
        "digest": "sha256:f14ab10c8f005cc678a97a082666f66f886e4f3543a06426e53923f5f947a4d5",
        "path": (
            "admission_protected_final_combined_v2_"
            "chat_session_snapshot_consumer_catalog_fixed.py"
        ),
    },
    "v3_session": {
        "bytes": 70_767,
        "digest": "sha256:490ab2967e7b5fd9f9005cf75f953742e91a377cfedfb5f0bb20efa7d1c82ebd",
        "path": ("admission_protected_final_combined_v3_session_snapshot_consumer.py"),
    },
}
_EVIDENCE = {
    "bytes": 662_917,
    "canonical_bytes": 662_916,
    "canonical_digest": "sha256:11d5292dfc01dac929b62476ce4d9d78caaa66722fe72da82dcfaca58ce59de4",
    "digest": "sha256:a8cec570e1460dd67ab254ab88f70d74e93804dbebc3f23c02eb755823b5c11a",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
        "chat-session-snapshot-consumer-systemd-p3-final-2026-09-01.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 97_371,
    "canonical_bytes": 97_482,
    "canonical_digest": "sha256:50c3375d42800d836aa7c9ac0140354bdd4f855505c537bfb829d89f80f4f291",
    "digest": "sha256:6a07afe243f52a8d037747f70943d5a15d433133c3807465acc4b7cf956a5d72",
}
_SOURCE = {
    "commit": "07ee36d9292861b4c2dcc3866f133e68af2cf433",
    "parent": "88151ae0611a95cb00767acbb416983c9540eeeb",
    "tree": "2e78d16eb35f39416e97cee0e4e40bb5d09a5c4e",
}
_RETENTION = {
    "commit": "fe06369463cc4593f75031618b67a04865d5fb7d",
    "parent": _SOURCE["commit"],
    "tree": "d54149d8f8447062a884c4d5bc2381b6522f7e36",
}
_RETENTION_BLOB = "7003e43d7c46f7cd320c17ce57a8ede73d42bade"
_TYPE_SHAPE_DIGEST = (
    "sha256:1c0f35aee3f3a6a4583c6d47c20291b271baf7ec90b2463da8193efacef2ba9e"
)
_ROUTE_TYPE_SHAPE_DIGEST = (
    "sha256:52f20967af56a9a27d4c1efdee12bd54d2339607bffc34444cb6fc4da298fabb"
)
_DIGESTS = {
    "action": "sha256:e0178c990c059642c4c25f65f48ed41d76fd8ba4ce903062741f9c2729356ea9",
    "composition": "sha256:f33436f8b05fb7e95c4a1cc9fe0785bc042444ec93e349225897316528e5c8fe",
    "composition_action": "sha256:5223a856a044fcc54954d57980ef93733727e61106fd9e846d314f52f2db4d1a",
    "execution": "sha256:25a7842f76fcd0351564b977016536bb96c2bc13552270ef28526148b620287a",
    "gateway_binding": "sha256:d6d6a8d74acd6d938b8fcebf5a1502608d00136cb27fea5506ce861b9355ec04",
    "harness": "sha256:5d3d68ed12dcd8c08d3a5a3cbb10ddeb827a224fdd0923f5e66c22d948ab729a",
    "host_config": "sha256:a5cb63eae9e17254d00133d138758ec47f15aa776ff3cb479fb1d48bdc46c5fd",
    "image_lineage": "sha256:3ebc2ce001d77ae51d4a221b2ed10c93b047ad2de94a2b5654b7d203bb5a7aa1",
    "module_files": "sha256:9846dfc18ae93d3c216a6e87ba89b811b7d260b52a264ee1551cf1638cc6abad",
    "replay": "sha256:f085a9ba0ad2b0b2310f571722b17cd10d8c2adee8552c38e1474581afbbbfd1",
    "route_observation": "sha256:5638a83c682e61b49da971520fa62da37d5f1f4bb74272053f030ae789bdf115",
    "source_artifacts": "sha256:ba023c3876a48aa29906e616c29e54e9d681823f00a243eaa787bf9a21c1cb29",
    "stack": "sha256:2723c0bac75906bfda1a5e0d48c86ef8d651f3582ba884c907c8d4910ecb1dc3",
}
_STATIC_DIGESTS = {
    "boundary": "sha256:025a43d438f7d17dd00328d2e5d8eaad45f35a535988a9f5d1e5d722f117407e",
    "config": "sha256:b2d66901244dbb3d3a263ec623c85ebab527ad169c914296498c3ce1157e3967",
    "config_lock": "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2",
    "config_tree": "sha256:d34ea13730fd5105ace3e218970c22deee710f987becf3366a0916a933fe2ed6",
    "gateway": "sha256:d59d07a803b472fd9f16af6e31c93fe2a06dfc61511370742141ccba6886d97c",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "protected_roots": "sha256:7fd6168fdbb95d3424b5c9553b0b93bc18401abb4351527a062a912d6cad6309",
    "runtime_tree": "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b",
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
}
_ARTIFACT_DIGESTS = {
    "activator": "sha256:c43b088e0560d904509da9f2177a18c201034f3373ce368126cf46ebbc0e4995",
    "activator_source": "sha256:f14374921b839ed5f7f2b9f685de38e2cde18901620bcf77b80a1095b6e65359",
    "chat_session_snapshot_consumer_probe": "sha256:2af6716ad4e029f323b0551217aff47434c62b3c2264a38d0faa664d737d4bf5",
    "collector": "sha256:8b7c9d0f61e9e5a5d95b8cc38a7abc2117252c891816b89f7bcdb9b31e1ed4ec",
    "config": "sha256:43ce7ebe7e7f0b9c4323008fc56d5377565d43043f03837aaf49dcd5ba7bf1ec",
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
        41_345,
        "sha256:1efe13c3beb3ac2ff6fc1293aa64875c95424f1576a10b12943f0b875af223e2",
        "benchmark/admission/openclaw-v2026.7.1/protected-session-snapshot-fixed-probe.mjs",
        "0444",
    ),
    "collector": (
        16_474,
        "sha256:99674a26ce2c5dd91abbc253b43eadf18c3b616f3e35cba668ff6b6a7d08331b",
        "scripts/runtime_action_worker_final_combined_v3_chat_session_snapshot_consumer_systemd_probe.py",
        "0555",
    ),
    "fixed_materializer": session._SOURCE_ARTIFACTS["fixed_materializer"],
    "inherited_v2_route_injector": session._SOURCE_ARTIFACTS[
        "inherited_v2_route_injector"
    ],
    "inherited_v3_contract_base": session._SOURCE_ARTIFACTS[
        "inherited_v3_contract_base"
    ],
    "inherited_v3_stack_helper": session._SOURCE_ARTIFACTS["inherited_v3_stack_helper"],
    "rebound_materializer": session._SOURCE_ARTIFACTS["rebound_materializer"],
}
_COLLECTOR_ARTIFACTS = {
    "capture_recipe": (
        28_069,
        "sha256:9fdfe3019432f508b949af4c86623d05a447c29e184907c6986377f4ecc795fe",
        "scripts/capture_runtime_action_worker_final_combined_v3_chat_session_snapshot_consumer_systemd.sh",
        "0555",
    ),
    "dockerfile": (
        7_274,
        "sha256:fee3d896e8f43f8552735e17ca1eb19862e6c806ccf4197e4b9b6c12ae42a5f1",
        "benchmark/runtime-action-worker-final-combined-v3-chat-session-snapshot-consumer-systemd/Dockerfile",
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
    "ONLY_CHAT_SESSION_SNAPSHOT_CONSUMER_ATTEMPT_OBSERVED",
    "NO_CHAT_SESSION_SNAPSHOT_CONSUMER_CONFORMANCE_OR_PROTECTED_PROMPT_REFRESH_CLAIM",
    "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
    "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
    "CHAT_SESSION_SNAPSHOT_CONSUMER_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_SESSION_STATE_EQUIVALENCE_CLEANUP_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def verify_openclaw_final_combined_v3_chat_session_snapshot_consumer(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact dynamic current-V3 native chat consumer PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract._read_blob(
            evidence_cas, _EVIDENCE, "V3 chat session snapshot consumer"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 chat-session-snapshot-consumer CAS differs from signed retention"
            )
        evidence = contract._load_canonical_json(
            raw, _EVIDENCE, "V3 chat session snapshot consumer"
        )
        closure_files = _verify_compiled_closure()
        profile = _verify_evidence(evidence, closure_files=closure_files)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        CASError,
        EOFError,
        IndexError,
        KeyError,
        OSError,
        tarfile.TarError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 chat-session-snapshot-consumer evidence: {exc}"
        ) from exc

    routes = [
        {"id": route["id"], "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED"}
        for route in profile["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v3-chat-session-"
            "snapshot-consumer-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_CHAT_SESSION_"
            "SNAPSHOT_CONSUMER_ROUTE_ONLY"
        ),
        "bindings": {
            "compiled_closure": {
                "acquisition": dict(session._CLOSURE["acquisition"]),
                "archive": dict(session._CLOSURE["archive"]),
                "manifest": dict(session._CLOSURE["manifest"]),
                "module_files_canonical_digest": session._CLOSURE[
                    "module_files_canonical_digest"
                ],
                "scope": "fourteen_selected_compiled_route_modules",
            },
            "configuration": dict(v3_contract.parent._CONTRACT_FILES["config"]),
            "image": _IMAGE,
            "profile": dict(v3_contract.parent._CONTRACT_FILES["profile"]),
            "chat_session_snapshot_consumer_observation": {
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
                **{name: dict(value) for name, value in session._DEPENDENCIES.items()},
                **{name: dict(value) for name, value in _DEPENDENCIES.items()},
            },
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE",
            **{key: False for key in contract._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_CHAT_SESSION_SNAPSHOT_CONSUMER_PASS_ONLY",
            "TWENTY_OTHER_V3_PROFILE_ROUTES_NOT_TESTED",
            "PRIOR_V3_ROUTE_PASSES_NOT_COMPOSED_ACROSS_FRESH_SESSIONS",
            "INDEPENDENT_CHAT_ROUTE_CAPTURE_USES_SESSION_SNAPSHOT_DERIVED_PROBE",
            "RETAINED_ACTION_ID_AND_SESSION_IDEMPOTENCY_PREFIXES_ARE_LEGACY_SESSION_NAMES",
            "BLACK_BOX_NATIVE_CHAT_PERSISTENCE_WITHOUT_DIRECT_SESSION_UPDATES_TRACE",
            "ONE_TAMPER_RECOVERY_TRIGGER_NOT_GENERAL_CHAT_ROUTE_COVERAGE",
            "MODEL_TURNS_FAILED_NO_PROVIDER_BODY_SUCCESSFUL_REPLY_OR_DELIVERY_CLAIM",
            "DETERMINISTIC_COMPILED_REPLAY_NOT_NATIVE_AGENT_EXECUTION",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "SOURCE_TO_BINARY_BUILD_NOT_INDEPENDENTLY_ATTESTED_OR_REPRODUCED",
            "PUBLIC_NETWORK_DENIED",
            "FOURTEEN_SELECTED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "COMPILED_CLOSURE_REUSED_FROM_PRIOR_CAPTURE_WITH_IDENTICAL_RUNTIME_TREE",
            "PRE_ROUTE_READ_ONLY_CLOSURE_ACQUISITION_BOUND_BY_RUNTIME_TREE",
            "NO_POST_ROUTE_CLOSURE_PROVENANCE_OR_CONTINUOUS_IMMUTABILITY_CLAIM",
            "ACQUISITION_IMAGE_DIFFERS_FROM_CURRENT_ROUTE_CAPTURE_IMAGE",
            "LOCAL_DOCKER_VOLUME_NOT_INDEPENDENTLY_ATTESTED",
            "ORIGINAL_PROVIDER_REQUEST_AND_SESSION_STORE_RAW_BYTES_NOT_RETAINED",
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
                "SIGNED_EXACT_NATIVE_CHAT_SEND_WAIT_SAME_SESSION_"
                "PROTECTED_PROMPT_PERSISTENCE_AFTER_ATTACKER_PROMPTREF_REPLACEMENT"
            ),
            "independent_capture": True,
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_dependencies() -> None:
    directory = Path(__file__).resolve(strict=True).parent
    modules = {"v2_chat_semantics": chat_semantics, "v3_session": session}
    for name, module in modules.items():
        expected = _DEPENDENCIES[name]
        path = Path(module.__file__).resolve(strict=True)
        if (
            path != (directory / expected["path"]).resolve(strict=True)
            or path.stat().st_size != expected["bytes"]
            or _digest(path.read_bytes()) != expected["digest"]
        ):
            raise AdmissionEvidenceError(
                f"V3 chat-session-snapshot-consumer dependency changed: {name}"
            )
    if chat_semantics.parent is not session.semantics:
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer semantic dependency identity changed"
        )
    session._verify_dependencies()


def _verify_compiled_closure() -> dict[str, bytes]:
    closure_files = session._verify_compiled_closure()
    current.base.legacy._git(
        [
            "merge-base",
            "--is-ancestor",
            session.semantics.semantic._ACQUISITION_RETENTION["commit"],
            _SOURCE["commit"],
        ]
    )
    return closure_files


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
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer repository changed"
        )
    current.base._verify_commit(_SOURCE)
    current.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer signed tree changed"
        )
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=700 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer signed blob changed"
        )
    return raw


def _verify_evidence(
    evidence: Mapping[str, Any], *, closure_files: Mapping[str, bytes]
) -> Mapping[str, Any]:
    if canonical_digest(v3_contract._type_shape(evidence)) != _TYPE_SHAPE_DIGEST:
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer JSON type changed"
        )
    session.semantics._verify_scalar_types(evidence)
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
        "status": "FINAL_COMBINED_V3_CHAT_SESSION_SNAPSHOT_CONSUMER_OBSERVED_PROFILE_NOT_TESTED",
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
        != "aragorn/runtime-action-worker-final-combined-v3-chat-session-snapshot-consumer-systemd-observation/v1"
        or evidence["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_CHAT_SESSION_SNAPSHOT_CONSUMER_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or evidence["recorded_at"] != "2026-09-01T14:16:47.108885Z"
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
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer wrapper changed"
        )
    profile = _verify_composition(evidence["composition"], evidence["source_artifacts"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer harness copies differ"
        )
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
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer nested custody changed"
        )
    harness = evidence["harness"]["document"]
    _verify_execution(
        observation, evidence["composition"]["action"]["boundaries"], harness
    )
    _verify_route_contract(
        document,
        container_id=harness["container_id"],
        closure_files=closure_files,
        execution=observation["execution"],
        outer_recorded_at=evidence["recorded_at"],
    )
    parse = current.base.legacy._parse_time
    if not (
        parse(document["recorded_at"])
        <= parse(observation["execution"]["completed_at"])
        <= parse(evidence["composition"]["action"]["recorded_at"])
        <= parse(evidence["composition"]["recorded_at"])
        <= parse(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer execution custody changed"
        )
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    action = composition["action"]
    artifact = action["artifacts"]["final_combined_v3_chat_session_snapshot_consumer"]
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
        != "aragorn/runtime-action-worker-final-combined-v3-chat-session-snapshot-consumer-systemd-observation/v1"
        or composition["authority"]
        != "BOUND_FINAL_COMBINED_V3_RAW_CHAT_SESSION_SNAPSHOT_CONSUMER_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        or composition["recorded_at"] != "2026-09-01T14:16:47.108852Z"
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
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer composition changed"
        )
    v3_contract.parent._verify_contract_artifacts(artifact)
    _verify_source_artifacts(source_artifacts)
    _verify_collector_artifacts(artifact["collector"])
    _verify_probe_artifact(artifact["chat_session_snapshot_consumer_probe"])
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
            f"V3 chat-session-snapshot-consumer signed source changed: {label}"
        )


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer source inventory changed"
        )
    for name, expected in _SOURCE_ARTIFACTS.items():
        _verify_signed_record(value[name], expected, f"source {name}")
    if value["probe_bundle"] != _PROBE_BUNDLE:
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer probe bundle changed"
        )


def _verify_collector_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != set(_COLLECTOR_ARTIFACTS):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer collector inventory changed"
        )
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
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer probe artifact changed"
        )
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
            path=f"/route-input/chat-session-snapshot-consumer/{bundle['name']}",
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
        != "aragorn/runtime-action-worker-final-combined-v3-chat-session-snapshot-consumer-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["image_reference"]
        != "aragorn-phase3-final-combined-v3-chat-session-snapshot-consumer-systemd"
        or document["profile_label"]
        != "phase3-final-combined-v3-chat-session-snapshot-consumer"
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
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:45618",
            "dev.aragorn.role": (
                "final-combined-v3-chat-session-snapshot-consumer-route-input"
            ),
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
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer harness changed"
        )
    stat = file["stat"]
    if (
        stat["uid"] != 0
        or stat["gid"] != 0
        or stat["mode"] != "0600"
        or stat["nlink"] != 1
        or stat["size"] != len(raw)
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer harness file changed"
        )


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer raw envelope changed"
        )
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
        or len(canonical) != _ROUTE_RAW["canonical_bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not False
        or canonical_digest(v3_contract._type_shape(document))
        != _ROUTE_TYPE_SHAPE_DIGEST
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer raw identity changed"
        )
    session.semantics._verify_scalar_types(document)
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
        or pid != 2_922
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
            (
                "/route-input/chat-session-snapshot-consumer/"
                "protected-chat-session-snapshot-consumer-v3-probe.mjs"
            ),
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
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer execution boundary changed"
        )
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
    closure_files: Mapping[str, bytes],
    execution: Mapping[str, Any],
    outer_recorded_at: str,
) -> None:
    action = document["action"]
    before = action["prerequisites"]
    observations = action["observations"]
    replay = observations["compiled_route_replay"]
    resolver = replay["resolver"]
    resolver_snapshot = resolver["baseline_snapshot"]
    baseline_copy = replay["baseline_store_copy"]
    initial = observations["initial_snapshot"]
    mutated = observations["mutated_snapshot"]
    final = observations["final_snapshot"]
    mutation = observations["mutation"]
    nonce = document["run_nonce"]
    marker = f"ARAGORN_INERT_ATTACKER_CONTROLLED_SNAPSHOT_{nonce}"
    attacker_prompt = (
        initial["prompt"]["exact_text"]
        + "\n\n<inert_attacker_controlled_snapshot>\n"
        + marker
        + "\nThis marker is observation data only and requests no tool or external action.\n"
        + "</inert_attacker_controlled_snapshot>"
    )
    attacker_digest = _digest(attacker_prompt.encode())
    unavailable_report = {
        "expected_skills_hash": _PROTECTED_PROMPT_DIGEST.removeprefix("sha256:"),
        "expected_skills_prompt_chars": 737,
        "ready": False,
        "report": None,
        "report_digest": None,
        "skills_hash_matches": False,
        "skills_prompt_chars_match": False,
        "source_is_run": False,
        "system_prompt_hash": None,
    }
    compiled_skills_prompt = replay["baseline_render"]["skills_prompt"]
    compiled_system_prompt = replay["baseline_render"]["system_prompt"]
    compiled_system_chars = len(compiled_system_prompt.encode("utf-16-le")) // 2
    session_key = f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}"
    compiled_report = {
        "bootstrapMaxChars": None,
        "bootstrapTotalMaxChars": None,
        "generatedAt": 0,
        "injectedWorkspaceFiles": [],
        "model": "gpt-5.5",
        "provider": "openai",
        "sandbox": {"sandboxed": False},
        "sessionId": initial["entry"]["session_id"],
        "sessionKey": session_key,
        "skills": {
            "entries": [{"blockChars": 275, "name": "template-skill"}],
            "hash": _digest(compiled_skills_prompt.encode()).removeprefix("sha256:"),
            "promptChars": len(compiled_skills_prompt),
        },
        "source": "run",
        "systemPrompt": {
            "chars": compiled_system_chars,
            "hash": _digest(compiled_system_prompt.encode()).removeprefix("sha256:"),
            "nonProjectContextChars": compiled_system_chars,
            "projectContextChars": 0,
        },
        "tools": {"entries": [], "listChars": 0, "schemaChars": 0},
        "workspaceDir": "/var/lib/aragorn-agent-gateway/workspace",
    }

    session.semantics.semantic._verify_snapshot(
        initial,
        _PROTECTED_PROMPT_DIGEST,
        entry_digest=(
            "sha256:624f7dc254b406d9338418e2f2bc58cb7f1e160d6df0c6d59c2dda72526af949"
        ),
        store_digest=(
            "sha256:d2be5ffbe888cf20a0a1917e094bea0654286bbdd5fe68e35204e67ab51eada1"
        ),
        store_bytes=6_628,
        store_inode=1_224_613,
        nonce=nonce,
    )
    session.semantics.semantic._verify_snapshot(
        mutated,
        attacker_digest,
        entry_digest=(
            "sha256:0890b9658d180158da355817ea26ac2f2e32d1bd24ed9c111d65a745b519da96"
        ),
        store_digest=(
            "sha256:554128f41b79eddcff3b27db73e5e53a9778b8037b3e0fe6090b23c7000e9116"
        ),
        store_bytes=6_629,
        store_inode=1_224_616,
        nonce=nonce,
    )
    session.semantics.semantic._verify_snapshot(
        final,
        _PROTECTED_PROMPT_DIGEST,
        entry_digest=(
            "sha256:8353639a836393a6c7006b51a24ef477c905f86b99bc662fef735296f0a92c32"
        ),
        store_digest=(
            "sha256:2ccb19bf97894aa33b1bf58b21b6ccaeae39c029c91aab123a3c5e748473196b"
        ),
        store_bytes=6_628,
        store_inode=1_224_611,
        nonce=nonce,
    )

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
            "config_before",
            "config_lock_before",
            "config_tree_before",
            "gateway_process_before",
            "openclaw_before",
            "protected_root_trees_before",
            "runtime_tree_before",
            "session_entry_absent_before",
            "system_info_before",
            "target_before",
            "version",
        }
        or set(observations)
        != {
            "attacker_blob_after",
            "attacker_blob_unreferenced_after",
            "boundary_after",
            "compiled_protected_prompt_boundary_observed",
            "compiled_route_replay",
            "config_after",
            "config_lock_after",
            "config_tree_after",
            "final_snapshot",
            "final_system_prompt_report",
            "gateway_process_after",
            "initial_snapshot",
            "initial_system_prompt_report",
            "initial_turn",
            "injected_turn",
            "mutated_snapshot",
            "mutation",
            "native_recovery_timing",
            "openclaw_after",
            "pre_injected_snapshot",
            "protected_root_trees_after",
            "runtime_tree_after",
            "system_info_after",
            "target_after",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-chat-session-snapshot-consumer-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["recorded_at"] != "2026-09-01T14:16:46.756Z"
        or document["implementation_digests"]
        != {"helper": _PROBE_BUNDLE[1]["digest"], "probe": _PROBE_BUNDLE[0]["digest"]}
        or document["route"]
        != {
            "action_id": "session-snapshot-consumer-fixed",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
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
        or action["id"] != "session-snapshot-consumer-fixed"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["session_entry_absent_before"] is not True
        or observations["compiled_protected_prompt_boundary_observed"] is not True
        or canonical_digest(replay) != _DIGESTS["replay"]
        or canonical_digest(replay["module_files"]) != _DIGESTS["module_files"]
        or replay["assurance"]
        != "DETERMINISTIC_PINNED_COMPILED_ROUTE_REPLAY_NOT_NATIVE_AGENT_EXECUTION"
        or replay["ready"] is not True
        or replay["native_agent_execution"] is not False
        or replay["consumer_chain"]
        != session.semantics.semantic.session_v1._CONSUMER_CHAIN
        or replay["baseline_loaded_entry_digest"]
        != "sha256:cdde172602315858dd58ff1b512105a4d06ec06b98bd94f2549dff5292e7a1fe"
        or replay["mutated_loaded_entry_digest"]
        != "sha256:de99c5d7eb6e987914481c954be0c76e931a81f217bf26b4c823d63cc1899f40"
        or replay["non_skill_render_inputs_digest"]
        != "sha256:268b3ef369b481edd277a877b2814be5f7049e8e3ce83ad2f25e1f6eed3cd7d4"
        or canonical_digest(replay["non_skill_render_inputs"])
        != replay["non_skill_render_inputs_digest"]
        or replay["baseline_report"] != compiled_report
        or replay["injected_report"] != compiled_report
        or resolver["baseline_should_refresh"] is not False
        or resolver["injected_should_refresh"] is not True
        or resolver["watch"] is not False
        or resolver_snapshot != resolver["injected_snapshot"]
        or resolver["baseline_snapshot_digest"]
        != "sha256:128c221b6c1a76a7c443c79be91732671b03111d9d03fa31560a49d7b6349b83"
        or canonical_digest(resolver_snapshot) != resolver["baseline_snapshot_digest"]
        or resolver["injected_snapshot_digest"] != resolver["baseline_snapshot_digest"]
        or resolver["injected_snapshot_version"]
        != resolver["baseline_snapshot_version"]
        or resolver["persisted_snapshot_version"]
        != resolver["baseline_snapshot_version"]
        or resolver["persisted_snapshot_version"]
        != initial["snapshot"]["metadata"]["version"]
        or resolver["baseline_prompt_digest"] != _PROTECTED_PROMPT_DIGEST
        or resolver["injected_prompt_digest"] != _PROTECTED_PROMPT_DIGEST
        or resolver_snapshot["prompt"] != initial["prompt"]["exact_text"]
        or resolver_snapshot["skills"] != initial["snapshot"]["metadata"]["skills"]
        or resolver_snapshot["skillFilter"]
        != initial["snapshot"]["metadata"]["skillFilter"]
        or resolver_snapshot["promptFormatVersion"]
        != initial["snapshot"]["metadata"]["promptFormatVersion"]
        or resolver_snapshot["version"] != initial["snapshot"]["metadata"]["version"]
        or len(resolver_snapshot["resolvedSkills"]) != 1
        or resolver_snapshot["resolvedSkills"][0]["name"] != "template-skill"
        or resolver_snapshot["resolvedSkills"][0]["filePath"]
        != "/opt/aragorn/runtime-profile/template-skill/SKILL.md"
        or resolver_snapshot["resolvedSkills"][0]["promptVersion"]
        != "sha256:eb685d91de039ed8"
        or replay["hydrated_inputs"]
        != {
            "baseline_prompt_digest": _PROTECTED_PROMPT_DIGEST,
            "injected_marker_count": 1,
            "injected_prompt_digest": attacker_digest,
        }
        or replay["baseline_render"] != replay["injected_render"]
        or replay["baseline_render"]["marker_count_in_skills_prompt"] != 0
        or replay["baseline_render"]["marker_count_in_system_prompt"] != 0
        or compiled_skills_prompt != initial["prompt"]["exact_text"]
        or _digest(compiled_skills_prompt.encode()) != _PROTECTED_PROMPT_DIGEST
        or _digest(compiled_system_prompt.encode())
        != "sha256:44813d1ef762eb51385d7406a6f2c8e5ce8a8291bf1af95c024cae13edc51d82"
        or marker in compiled_skills_prompt
        or marker in compiled_system_prompt
        or mutated["prompt"]["exact_text"] != attacker_prompt
        or observations["pre_injected_snapshot"] != mutated
        or final["snapshot"] != initial["snapshot"]
        or mutated["snapshot"] != initial["snapshot"]
        or mutated["entry"] != initial["entry"]
        or final["entry"]["session_id"] != initial["entry"]["session_id"]
        or observations["attacker_blob_after"]["digest"] != attacker_digest
        or {
            key: value
            for key, value in observations["attacker_blob_after"].items()
            if key != "mtime_ns"
        }
        != {
            key: value
            for key, value in mutated["blob"].items()
            if key not in {"mtime_ns", "prompt_ref"}
        }
        or observations["attacker_blob_unreferenced_after"] is not True
        or mutation["changed_json_paths"] != [f"{session_key}.skillsSnapshot.promptRef"]
        or mutation["entry_before_digest"] != initial["entry_digest"]
        or mutation["entry_after_digest"] != mutated["entry_digest"]
        or mutation["injected_marker"] != marker
        or mutation["store_before"] != initial["store"]
        or mutation["store_after_rewrite"]
        != {
            key: value
            for key, value in mutated["store"].items()
            if key != "top_level_keys"
        }
        or mutation["preserved_entry_without_prompt_ref"]
        != {
            "after_digest": "sha256:4090e4972583029f93860cc09170c3ea9ef955869298a78e9cced8d88cdb0a7a",
            "before_digest": "sha256:4090e4972583029f93860cc09170c3ea9ef955869298a78e9cced8d88cdb0a7a",
            "exact_equal": True,
        }
        or mutation["blob"] != {**mutated["blob"], "exact_text": attacker_prompt}
        or mutation["atomic_store_replacement"]
        != {
            "directory_fsync": True,
            "rename_completed": True,
            "same_directory": True,
            "temporary_path": (
                "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/"
                f"sessions.json.aragorn-{nonce}.tmp"
            ),
            "temporary_path_absent_after": True,
        }
        or observations["initial_system_prompt_report"] != unavailable_report
        or observations["final_system_prompt_report"] != unavailable_report
    ):
        raise AdmissionEvidenceError("V3 chat-session-snapshot-consumer route changed")

    epoch_ms = current.base.legacy._epoch_ms
    if (
        baseline_copy
        != {
            "absent_after_replay": True,
            "bytes": initial["store"]["bytes"],
            "digest": initial["store"]["digest"],
            "gid": initial["store"]["gid"],
            "inode": baseline_copy["inode"],
            "mode": initial["store"]["mode"],
            "mtime_ns": baseline_copy["mtime_ns"],
            "nlink": initial["store"]["nlink"],
            "path": f"{initial['store']['path']}.aragorn-{nonce}.baseline.json",
            "uid": initial["store"]["uid"],
        }
        or type(baseline_copy["inode"]) is not int
        or baseline_copy["inode"] <= 1
        or re.fullmatch(r"[1-9][0-9]*", baseline_copy["mtime_ns"]) is None
        or not (
            epoch_ms(mutation["completed_at"])
            <= int(baseline_copy["mtime_ns"]) // 1_000_000
            <= epoch_ms(observations["injected_turn"]["send"]["command"]["started_at"])
        )
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer compiled baseline copy changed"
        )

    stable = {
        "boundary": (before["boundary_before"], observations["boundary_after"]),
        "config": (before["config_before"], observations["config_after"]),
        "config_lock": (
            before["config_lock_before"],
            observations["config_lock_after"],
        ),
        "config_tree": (
            before["config_tree_before"],
            observations["config_tree_after"],
        ),
        "gateway": (
            before["gateway_process_before"],
            observations["gateway_process_after"],
        ),
        "openclaw": (before["openclaw_before"], observations["openclaw_after"]),
        "protected_roots": (
            before["protected_root_trees_before"],
            observations["protected_root_trees_after"],
        ),
        "runtime_tree": (
            before["runtime_tree_before"],
            observations["runtime_tree_after"],
        ),
        "target": (before["target_before"], observations["target_after"]),
    }
    if any(left != right for left, right in stable.values()) or any(
        canonical_digest(left) != _STATIC_DIGESTS[name]
        for name, (left, _right) in stable.items()
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer protected state changed"
        )

    _verify_current_boundary(before, observations, container_id)
    session.semantics.semantic._verify_module_files(
        replay["module_files"], closure_files
    )
    if tuple(closure_files) != (
        "manifest.json",
        *session.semantics.semantic._CLOSURE_PATHS,
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer closure paths changed"
        )
    session.semantics.semantic._verify_source_bridges(
        replay["handoff_statements"], closure_files
    )
    _verify_chat_persistence(document)

    expected_commands = [
        before["version"],
        before["system_info_before"]["command"],
        *observations["initial_turn"]["commands"],
        *observations["injected_turn"]["commands"],
        observations["system_info_after"]["command"],
    ]
    if (
        action["commands"] != expected_commands
        or [command["pid"] for command in action["commands"]]
        != [3_264, 3_271, 3_283, 3_295, 3_308, 3_320, 3_332]
        or not (
            current.base.legacy._parse_time(document["recorded_at"])
            <= current.base.legacy._parse_time(execution["completed_at"])
            <= current.base.legacy._parse_time(outer_recorded_at)
        )
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer native command custody changed"
        )
    _verify_route_chronology(action, document["recorded_at"])


def _verify_current_boundary(
    before: Mapping[str, Any], after: Mapping[str, Any], container_id: str
) -> None:
    boundary = before["boundary_before"]
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or before["config_before"] != boundary["configuration"]
        or before["runtime_tree_before"] != current._RUNTIME_TREE
        or before["config_lock_before"]
        != {
            "exists": False,
            "path": "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock",
        }
        or before["target_before"]["root"]["exists"] is not True
        or before["target_before"]["entries"][0]["exists"] is not True
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer current contract changed"
        )
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
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer protected roots changed"
        )
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
            raise AdmissionEvidenceError(
                "V3 chat-session-snapshot-consumer protected roots changed"
            )
    session._verify_version(before["version"])
    session._verify_system_snapshot(
        before["system_info_before"], before["gateway_process_before"]
    )
    session._verify_system_snapshot(
        after["system_info_after"], after["gateway_process_after"]
    )
    session._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )


def _verify_chat_persistence(document: Mapping[str, Any]) -> None:
    action = document["action"]
    observed = action["observations"]
    initial = observed["initial_snapshot"]
    mutated = observed["mutated_snapshot"]
    final = observed["final_snapshot"]
    mutation = observed["mutation"]
    replay = observed["compiled_route_replay"]
    nonce = document["run_nonce"]
    session_key = f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}"
    marker = f"ARAGORN_INERT_ATTACKER_CONTROLLED_SNAPSHOT_{nonce}"
    initial_send, initial_wait = chat_semantics._verify_turn(
        observed["initial_turn"],
        label="initial",
        nonce=nonce,
        session_key=session_key,
    )
    injected_send, injected_wait = chat_semantics._verify_turn(
        observed["injected_turn"],
        label="injected",
        nonce=nonce,
        session_key=session_key,
    )
    snapshots = [initial, mutated, observed["pre_injected_snapshot"], final]
    session_ids = {snapshot["entry"]["session_id"] for snapshot in snapshots}
    timing = observed["native_recovery_timing"]
    entry = final["entry"]
    store_mtime_ms = int(final["store"]["mtime_ns"]) // 1_000_000
    blob_mtime_ms = int(final["blob"]["mtime_ns"]) // 1_000_000
    parse = current.base.legacy._parse_time
    epoch_ms = current.base.legacy._epoch_ms
    if (
        len(action["commands"]) != 7
        or action["commands"][2:4] != observed["initial_turn"]["commands"]
        or action["commands"][4:6] != observed["injected_turn"]["commands"]
        or len(session_ids) != 1
        or any(
            session_key not in snapshot["store"]["top_level_keys"]
            for snapshot in snapshots
        )
        or observed["pre_injected_snapshot"] != mutated
        or initial["snapshot"] != final["snapshot"]
        or initial["prompt"] != final["prompt"]
        or mutated["entry"] != initial["entry"]
        or final["prompt"]["digest"] != _PROTECTED_PROMPT_DIGEST
        or final["blob"]["digest"] != _PROTECTED_PROMPT_DIGEST
        or final["prompt"]["digest"] != initial["prompt"]["digest"]
        or initial["entry"]["run_status"] != "timeout"
        or final["entry"]["run_status"] != "timeout"
        or marker not in mutated["prompt"]["exact_text"]
        or marker in final["prompt"]["exact_text"]
        or observed["attacker_blob_unreferenced_after"] is not True
        or mutation["changed_json_paths"] != [f"{session_key}.skillsSnapshot.promptRef"]
        or replay["native_agent_execution"] is not False
        or not (
            parse(initial_send["command"]["completed_at"])
            <= parse(initial_wait["command"]["started_at"])
            <= parse(initial_wait["command"]["completed_at"])
            <= parse(mutation["started_at"])
            <= parse(mutation["completed_at"])
            < parse(injected_send["command"]["started_at"])
            <= parse(injected_send["command"]["completed_at"])
            <= parse(injected_wait["command"]["started_at"])
            <= parse(injected_wait["command"]["completed_at"])
        )
        or timing["ready"] is not True
        or any(type(timing[key]) is not int for key in timing if key != "ready")
        or timing["injected_send_started_at"]
        != epoch_ms(injected_send["command"]["started_at"])
        or timing["injected_wait_ended_at"]
        != injected_wait["response"]["value"]["endedAt"]
        or timing["injected_wait_completed_at"]
        != epoch_ms(injected_wait["command"]["completed_at"])
        or timing["final_entry_started_at"] != entry["started_at"]
        or timing["final_entry_updated_at"] != entry["updated_at"]
        or timing["final_store_mtime_ms"] != store_mtime_ms
        or not (
            epoch_ms(injected_send["command"]["completed_at"])
            <= entry["started_at"]
            <= entry["ended_at"]
            <= store_mtime_ms
            <= blob_mtime_ms
            <= entry["updated_at"]
            <= timing["injected_wait_ended_at"]
            <= timing["injected_wait_completed_at"]
        )
    ):
        raise AdmissionEvidenceError(
            "V3 native chat-session-snapshot-consumer persistence changed"
        )


def _verify_route_chronology(action: Mapping[str, Any], recorded_at: str) -> None:
    observations = action["observations"]
    commands = action["commands"]
    initial = observations["initial_snapshot"]
    mutated = observations["mutated_snapshot"]
    final = observations["final_snapshot"]
    initial_turn = observations["initial_turn"]
    injected_turn = observations["injected_turn"]
    mutation = observations["mutation"]
    parse = current.base.legacy._parse_time
    epoch_ms = current.base.legacy._epoch_ms
    mutated_store_mtime = mutated["store"]["mtime_ns"]
    mutated_blob_mtime = mutated["blob"]["mtime_ns"]
    attacker_blob_mtime = observations["attacker_blob_after"]["mtime_ns"]
    pids = [command["pid"] for command in commands]
    if (
        len(commands) != 7
        or any(type(pid) is not int or pid <= 1 for pid in pids)
        or len(set(pids)) != len(pids)
        or any(
            parse(command["started_at"]) > parse(command["completed_at"])
            for command in commands
        )
        or any(
            parse(left["completed_at"]) > parse(right["started_at"])
            for left, right in pairwise(commands)
        )
        or re.fullmatch(r"[1-9][0-9]*", mutated_store_mtime) is None
        or re.fullmatch(r"[1-9][0-9]*", mutated_blob_mtime) is None
        or int(mutated_blob_mtime) > int(mutated_store_mtime)
        or re.fullmatch(r"[1-9][0-9]*", attacker_blob_mtime) is None
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer command process sequence changed"
        )
    if not (
        parse(initial_turn["send"]["command"]["completed_at"])
        <= parse(initial_turn["wait"]["command"]["started_at"])
        <= parse(initial_turn["wait"]["command"]["completed_at"])
        <= parse(mutation["started_at"])
        <= parse(mutation["completed_at"])
        < parse(injected_turn["send"]["command"]["started_at"])
        <= parse(injected_turn["send"]["command"]["completed_at"])
        <= parse(injected_turn["wait"]["command"]["started_at"])
        <= parse(injected_turn["wait"]["command"]["completed_at"])
        <= parse(observations["system_info_after"]["command"]["started_at"])
        <= parse(observations["system_info_after"]["command"]["completed_at"])
        <= parse(recorded_at)
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer command chronology changed"
        )
    mutated_store_ms = int(mutated_store_mtime) // 1_000_000
    mutated_blob_ms = int(mutated_blob_mtime) // 1_000_000
    if not (
        epoch_ms(initial_turn["send"]["command"]["completed_at"])
        <= initial["entry"]["started_at"]
        <= initial["entry"]["ended_at"]
        <= int(initial["store"]["mtime_ns"]) // 1_000_000
        <= initial["entry"]["updated_at"]
        <= int(initial["blob"]["mtime_ns"]) // 1_000_000
        <= initial_turn["wait"]["response"]["value"]["endedAt"]
        <= mutated_blob_ms
        <= mutated_store_ms
        <= epoch_ms(mutation["completed_at"])
        < epoch_ms(injected_turn["send"]["command"]["started_at"])
        <= int(attacker_blob_mtime) // 1_000_000
        <= epoch_ms(injected_turn["send"]["command"]["completed_at"])
        <= final["entry"]["started_at"]
        <= final["entry"]["ended_at"]
        <= int(final["store"]["mtime_ns"]) // 1_000_000
        <= final["entry"]["updated_at"]
        <= int(final["blob"]["mtime_ns"]) // 1_000_000
        <= injected_turn["wait"]["response"]["value"]["endedAt"]
        <= epoch_ms(injected_turn["wait"]["command"]["completed_at"])
        <= epoch_ms(recorded_at)
    ):
        raise AdmissionEvidenceError(
            "V3 chat-session-snapshot-consumer document chronology changed"
        )
