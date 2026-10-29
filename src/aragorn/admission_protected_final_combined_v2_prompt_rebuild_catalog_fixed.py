"""Derive one prompt-rebuild PASS from the corrected current V2 contract."""

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
    admission_protected_final_combined_v2_catalog_fixed_fresh_session_reset as fresh,
)
from . import admission_protected_final_combined_v2_prompt_rebuild as semantic
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

current = fresh.contract
base = fresh.old

_ROUTE = "ADM-02/reload/missing-prompt-blob-rebuild"
_PROFILE = fresh._PROFILE
_DEPENDENCIES = {
    "current_contract": {
        "digest": "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6",
        "path": "admission_protected_final_combined_v2_config_activation.py",
    },
    "current_fresh_session": {
        "digest": "sha256:dfea26baa270b7b1aecfa1e40838618d9ab4aa7f6e1d5ef006e5dfee1533b1dd",
        "path": "admission_protected_final_combined_v2_catalog_fixed_fresh_session_reset.py",
    },
    "prompt_semantics": {
        "digest": "sha256:6518ada93011ed91bd5a5d3a7d53a599603be863d9dea1427441628bab08a3ee",
        "path": "admission_protected_final_combined_v2_prompt_rebuild.py",
    },
}
_EVIDENCE = {
    "bytes": 483_212,
    "canonical_bytes": 483_211,
    "canonical_digest": (
        "sha256:aa7942c3ea1251258a2e959b804ce3a6de799b07b8be47a3647ae9e6774dc98d"
    ),
    "digest": (
        "sha256:5ba5f02971788a9320f0de8a5ca4bbbdface6f216bafd3510fa42615d670cbb3"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "missing-prompt-blob-rebuild-systemd-p3-final-catalog-fixed-2026-08-22.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 44_847,
    "canonical_digest": (
        "sha256:a7e5952423428c7c75cb71c820bc584efc83344b60802f6644b9754ffd3c6786"
    ),
    "digest": (
        "sha256:3f353461dffe96c5c8bf866ae6ca1cfbbbdb7115afe059ac909a9c42daeaed69"
    ),
}
_SOURCE = {
    "commit": "9bc13769a9b71faf23012be993e615474934618d",
    "parent": "1b13a8e4ff3f66f87cd26c34987e1e845c497028",
    "tree": "1d1d15c686098613dd38ab58204ed3916605b0ee",
}
_RETENTION = {
    "commit": "8e19944e294486509f60e4d34f5efdc0ee771974",
    "parent": _SOURCE["commit"],
    "tree": "e0c54ffd6644cf07c65f1d0f924a424fc80855e3",
}
_RETENTION_BLOB = "41e66e0dcab7c1ce7643de79273795653a3ffdd9"
_IMAGE = fresh._IMAGE
_PARENT_IMAGE = fresh._PARENT_IMAGE
_RUNTIME_VOLUME = fresh._RUNTIME_VOLUME
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-64757"
_DIGESTS = {
    "action": "sha256:ca6114c8a69463b317580d2fa0d228249ee4b9535916c494600ecc8f80301ebb",
    "composition": "sha256:40bc601f0c81c083f891378e5034b69982317af89ec03911f2c669ea1a4932cc",
    "composition_action": "sha256:914890d38176308859ab077102458f1261ee9bac31f669310b4795597702bb47",
    "execution": "sha256:f82ea898f33404e03713ac23ac1121096e27e4d275912d096c280acb609f425f",
    "gateway_binding": "sha256:2f50432dab329084b39f0c58a07c6615bea67009ad00dffe7eb878ebe943d8a8",
    "harness": "sha256:4b0c0bd8a8f27c7734ea5eb65d448549d47c066af0dbbdbd9a88797753b764f8",
    "host_config": "sha256:16ea2400dec57b4b176463b312ed7167cab12519e7541310174cf2a1949e7060",
    "image_lineage": "sha256:a2d5cfc19644d5285878238bd22fc338ccef61df23c6d168e48c754790b5475f",
    "source_artifacts": "sha256:71a2749bef1f4939433adb2344cc682258e70272ac86ce3c21da68d646de716d",
    "stack": "sha256:b5200ebd19c80b0f45880a29884668b1506a7e4764e8f0ed7eff113b2b70ce59",
}
_STATIC_DIGESTS = {
    "boundary": "sha256:977fccbfa186c3c9ad847f8a05c177cddc55bf5013c23e733b852348dc05d2c0",
    "config_lock": "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2",
    "config_tree": "sha256:5c53385f14f86845475e47f0f07aa6b9b877bbe55fe63f6ecca60fc93d373de1",
    "gateway": "sha256:71bb487be61e6529010fce570ff794697b8ee57a43012c8634d056e21b966f61",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "protected_roots": "sha256:45c9d950cfd98b36370a47e2b46c2236f46b1a8f4b92d087731b638639370b83",
    "runtime_tree": "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b",
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
}
_SHAPE_DIGEST = (
    "sha256:d3543fe6a91f9d436fcd3af47b5dcbc5827c397372b3de109178b31037cd4f40"
)
_SOURCE_ARTIFACTS = {
    "collector": dict(current._SOURCE_ARTIFACTS["collector"]),
    "helper": {
        "bytes": 16_324,
        "digest": "sha256:91febf12bd6aa2e98f63b14001a74213c653c2eb9c8c7db57a55b3520fdd4f22",
        "name": "protected-observation-v1.mjs",
    },
    "materializer": dict(current._SOURCE_ARTIFACTS["materializer"]),
    "probe": {
        "bytes": 16_464,
        "digest": "sha256:9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7",
        "name": "protected-prompt-rebuild-probe.mjs",
    },
    "v1_route_injector": dict(current._SOURCE_ARTIFACTS["v1_route_injector"]),
}
_PROMPT = semantic._PROMPT
_PROMPT_DIGEST = semantic._PROMPT_DIGEST
_PROMPT_PATH = semantic._PROMPT_PATH
_SESSION_STORE = semantic._SESSION_STORE
_UUID4 = semantic._UUID4
_EMPTY_DIGEST = fresh._EMPTY_DIGEST
_BOOLEAN_FIELDS = current._BOOLEAN_FIELDS | {
    "blob_exists_after_unlink",
    "confirmed",
    "session_entry_absent_before",
}


def verify_openclaw_final_combined_v2_prompt_rebuild_catalog_fixed(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 1/20 coverage without composing any other route PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = base.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "catalog-fixed V2 prompt rebuild"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "catalog-fixed V2 prompt CAS differs from signed retention"
            )
        evidence = base.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "catalog-fixed V2 prompt rebuild"
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
            f"invalid catalog-fixed V2 prompt evidence: {exc}"
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
            "aragorn/admission-protected-final-combined-v2-prompt-rebuild-"
            "catalog-fixed-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_CURRENT_CONTRACT_V2_PROMPT_"
            "REBUILD_ROUTE_ONLY"
        ),
        "bindings": {
            "configuration": dict(current._SOURCES["configuration"]),
            "image": _IMAGE,
            "profile": dict(current._SOURCES["profile"]),
            "prompt_rebuild_observation": {
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
            "runtime": dict(base.legacy.parent._RUNTIME),
            "runtime_lock": dict(current._SOURCES["runtime_lock"]),
            "skill": dict(current._SOURCES["skill"]),
            "source_artifacts": {
                name: dict(identity) for name, identity in _SOURCE_ARTIFACTS.items()
            },
            "verifier_dependencies": {
                name: dict(identity) for name, identity in _DEPENDENCIES.items()
            },
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in base.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_PROMPT_REBUILD_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "PRIOR_ROUTE_PASSES_NOT_COMPOSED_ACROSS_V2_CONFIG_CHANGE",
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
                "SIGNED_EXACT_CURRENT_CATALOG_PROMPT_BLOB_UNLINK_AND_"
                "RECONSTRUCTION_TRANSITION"
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


def _shape(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_shape(item) for item in value]
    return type(value).__name__


def _verify_dependencies() -> None:
    directory = Path(__file__).resolve(strict=True).parent
    modules = {
        "current_contract": current,
        "current_fresh_session": fresh,
        "prompt_semantics": semantic,
    }
    for name, module in modules.items():
        identity = _DEPENDENCIES[name]
        path = Path(module.__file__).resolve(strict=True)
        if (
            path != (directory / identity["path"]).resolve(strict=True)
            or _digest(path.read_bytes()) != identity["digest"]
        ):
            raise AdmissionEvidenceError(
                f"catalog-fixed V2 prompt dependency changed: {name}"
            )
    if (
        fresh.contract is not current
        or fresh.old is not base
        or semantic.parent is not base
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt dependency graph changed")
    fresh._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = base.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt repository changed")
    base._verify_commit(_SOURCE)
    base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError(
            "catalog-fixed V2 prompt signed tree entry changed"
        )
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=512 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    _verify_scalar_types(evidence)
    current._verify_no_positive_eligibility(evidence)
    if (
        _canonical_digest(_shape(evidence)) != _SHAPE_DIGEST
        or set(evidence)
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
        or evidence["recorded_at"] != "2026-08-22T09:56:15.880185Z"
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
        raise AdmissionEvidenceError("catalog-fixed V2 prompt wrapper changed")

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
        or observation["bundle"]
        != [_SOURCE_ARTIFACTS["helper"], _SOURCE_ARTIFACTS["probe"]]
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt nested custody changed")
    _verify_execution(observation, composition["action"]["boundaries"], harness)
    _verify_prompt(document, harness["container_id"], evidence["recorded_at"])
    if not (
        base.legacy._parse_time(document["recorded_at"])
        <= base.legacy._parse_time(observation["execution"]["completed_at"])
        <= base.legacy._parse_time(composition["action"]["recorded_at"])
        <= base.legacy._parse_time(composition["recorded_at"])
        <= base.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError(
            "catalog-fixed V2 prompt execution custody changed"
        )
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
        or composition["recorded_at"] != "2026-08-22T09:56:15.880162Z"
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
            "runtime_digest": current._RUNTIME_TREE["tree_digest"],
            "runtime_volume": _RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": current._SOURCES["skill"]["digest"],
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
        or composition["limitations"]
        != [
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "ONE_PINNED_P3_7C_ACTIVATION_ACTION_FLOW_ONLY",
            "TWENTY_ONE_ADMISSION_ROUTES_REMAIN_NOT_TESTED",
            "ACTION_OBSERVATION_DOES_NOT_PROMOTE_ANY_ADMISSION_ROUTE",
            "FRESH_RUNTIME_PROFILE_AND_FRESH_SESSIONS_REQUIRED",
            "OPENCLAW_TEST_FAST_ABSENT",
            "PUBLIC_NETWORK_DENIED",
            "EXACT_SINGLETON_EXTERNAL_SKILL_SOURCE_ONLY",
            (
                "EXACT_PINNED_ARAGORN_TOOL_PLUGIN_READ_TOOL_WORKSPACE_AND_"
                "RESOLVED_SKILL_ROOTS_AND_LOOPBACK_PROVIDER_ONLY"
            ),
            "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        ]
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt composition changed")

    action = composition["action"]
    source = action["artifacts"]["final_combined_v2"]
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    if (
        _canonical_digest(action) != _DIGESTS["composition_action"]
        or set(action)
        != {
            "artifacts",
            "authority",
            "boundaries",
            "cases",
            "decision",
            "harness",
            "identities",
            "inputs",
            "limitations",
            "parent",
            "profiles",
            "recorded_at",
            "runtime",
            "schema",
            "secret_checks",
        }
        or action["schema"]
        != "aragorn/runtime-action-worker-activation-expiry-systemd-observation/v1"
        or action["recorded_at"] != "2026-08-22T09:56:15.473819Z"
        or action["authority"]
        != (
            "BOUNDED_ACTIVATION_EXPIRY_ROTATION_OBSERVATION_ONLY_NOT_VERIFIED_"
            "RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or action["decision"]
        != {
            "aggregate_gate_eligible": False,
            "available_to_expired_observed": True,
            "coherent_allow_created_consumed_observed": True,
            "edr_claim_eligible": False,
            "expired_activation_fail_stop_observed": True,
            "full_activation_no_boot_authority_observed": True,
            "installer_authority_eligible": False,
            "parent_p3_7b_unchanged": True,
            "phase3_exit_eligible": False,
            "public_release_eligible": False,
            "retained_evidence_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "status": "P3_7C_ACTIVATION_EXPIRY_OBSERVED",
            "terminal_archive_rotation_observed": True,
            "verifier_status": "NOT_TESTED",
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
        or action["runtime"]
        != {
            "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "entrypoint_digest": base.legacy.parent._RUNTIME["entrypoint_digest"],
            "expected_version": base.legacy.parent._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": current._RUNTIME_TREE,
            "version_output": base.legacy.parent._RUNTIME["version_output"],
        }
    ):
        raise AdmissionEvidenceError(
            "catalog-fixed V2 prompt profile or action changed"
        )
    current._verify_configuration(source)
    _verify_source_artifacts(source_artifacts)
    _verify_harness(action["harness"])
    return profile


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {"collector", "materializer", "probe_bundle", "v1_route_injector"}:
        raise AdmissionEvidenceError("catalog-fixed V2 prompt source bundle changed")
    for name in ("collector", "materializer", "v1_route_injector"):
        identity = _SOURCE_ARTIFACTS[name]
        current._verify_bound_file(
            value[name], identity, path=identity["path"], mode="0555"
        )
    if value["probe_bundle"] != [
        _SOURCE_ARTIFACTS["helper"],
        _SOURCE_ARTIFACTS["probe"],
    ]:
        raise AdmissionEvidenceError("catalog-fixed V2 prompt probe bundle changed")


def _verify_harness(envelope: Mapping[str, Any]) -> None:
    document = envelope["document"]
    file = envelope["file"]
    stat = file["stat"]
    raw = base64.b64decode(file["base64"], validate=True)
    parsed = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=base.legacy.parent._reject_duplicates,
        parse_constant=base.legacy.parent._reject_constant,
    )
    canonical = base.legacy.parent.oci_worker_protocol.canonical_json(document)
    lineage = document["image_lineage"]
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
        or set(file) != {"base64", "bytes", "digest", "path", "stat"}
        or parsed != document
        or raw != canonical
        or _digest(raw) != _DIGESTS["harness"]
        or envelope["digest"] != _DIGESTS["harness"]
        or file["bytes"] != len(raw)
        or file["digest"] != _DIGESTS["harness"]
        or file["path"] != "/run/aragorn-harness.json"
        or stat["size"] != len(raw)
        or stat["type"] != "file"
        or stat["uid"] != 0
        or stat["gid"] != 0
        or stat["mode"] != "0600"
        or stat["nlink"] != 1
        or any(
            type(stat[field]) is not int or stat[field] <= 0
            for field in ("ctime_ns", "device", "inode", "mtime_ns")
        )
        or not isinstance(document["container_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", document["container_id"]) is None
        or document["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["image_reference"] != "aragorn-phase3-final-combined-v2-systemd"
        or document["platform"] != "linux"
        or document["profile_label"] != "phase3-final-combined-v2"
        or _canonical_digest(lineage) != _DIGESTS["image_lineage"]
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or not lineage["added_layers"]
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or lineage["child"]["rootfs_type"] != "layers"
        or lineage["parent"]["rootfs_type"] != "layers"
        or _canonical_digest(document["host_config"]) != _DIGESTS["host_config"]
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
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:64757",
                "dev.aragorn.role": "final-combined-v2-route-input",
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
                "io.aragorn.source-commit": base.legacy.parent._OPENCLAW["commit"],
                "io.aragorn.source-tree": base.legacy.parent._OPENCLAW["source_tree"],
            },
            "name": _RUNTIME_VOLUME,
            "options": None,
            "scope": "local",
        }
        or document["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or type(document["source_commit_verification"]["exit_code"]) is not int
        or document["source_commit_verification"]["exit_code"] != 0
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt harness changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("catalog-fixed V2 prompt raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=base.legacy.parent._reject_duplicates,
        parse_constant=base.legacy.parent._reject_constant,
    )
    canonical = base.legacy.parent.oci_worker_protocol.canonical_json(document)
    if (
        not isinstance(document, dict)
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not False
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt raw identity changed")
    _verify_scalar_types(document)
    return document


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
    gateway_unit = "aragorn-agent-gateway.service"
    pid = binding["pid"]
    units = {
        gateway_unit,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    process = stack["processes"][gateway_unit]
    nested = document["action"]["prerequisites"]["gateway_process_before"]
    commands = document["action"]["commands"]
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
        or _canonical_digest(execution) != _DIGESTS["execution"]
        or _canonical_digest(binding) != _DIGESTS["gateway_binding"]
        or _canonical_digest(stack) != _DIGESTS["stack"]
        or type(pid) is not int
        or pid <= 1
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
        or nested["pid"] != process["pid"]
        or nested["cmdline"] != process["cmdline"]
        or nested["start_time_ticks"] != process["start_time_ticks"]
        or nested["effective_capabilities"] != process["capabilities_effective"]
        or nested["no_new_privileges"] != str(process["no_new_privileges"])
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
            base.legacy._parse_time(execution["started_at"])
            <= base.legacy._parse_time(commands[0]["started_at"])
            <= base.legacy._parse_time(commands[-1]["completed_at"])
            <= base.legacy._parse_time(document["recorded_at"])
            <= base.legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError(
            "catalog-fixed V2 prompt execution boundary changed"
        )
    base.legacy._verify_stack_boundary(
        stack,
        trusted=boundaries,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    base.legacy._verify_gateway_listener(stack["gateway_listener"], stack["processes"])


def _verify_prompt(
    document: Mapping[str, Any], container_id: str, outer_recorded_at: str
) -> None:
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
        != {
            "helper": _SOURCE_ARTIFACTS["helper"]["digest"],
            "probe": _SOURCE_ARTIFACTS["probe"]["digest"],
        }
        or document["runtime_binding"]
        != {
            "commit": base.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": base.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": current._RUNTIME_TREE["tree_digest"],
            "version": base.legacy.parent._OPENCLAW["version"],
        }
        or document["route"]
        != {
            "action_id": "missing-prompt-blob-rebuild",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or not isinstance(document["run_nonce"], str)
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or _canonical_digest(document["action"]) != _DIGESTS["action"]
    ):
        raise AdmissionEvidenceError(
            "catalog-fixed V2 prompt observation identity changed"
        )

    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    stable = {
        "boundary": (before["boundary_before"], after["boundary_after"]),
        "config_lock": (
            before["config_lock_before"],
            after["config_lock_after"],
        ),
        "config_tree": (
            before["config_tree_before"],
            after["config_tree_after"],
        ),
        "gateway": (
            before["gateway_process_before"],
            after["gateway_process_after"],
        ),
        "openclaw": (before["openclaw_before"], after["openclaw_after"]),
        "protected_roots": (
            before["protected_root_trees_before"],
            after["protected_root_trees_after"],
        ),
        "runtime_tree": (
            before["runtime_tree_before"],
            after["runtime_tree_after"],
        ),
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
            _canonical_digest(left) != _STATIC_DIGESTS[name]
            for name, (left, _right) in stable.items()
        )
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt protected state changed")

    _verify_static(before, container_id)
    _verify_commands(action, document["run_nonce"], document["recorded_at"])
    semantic._verify_rebuild(after)
    _verify_rebuild_chronology(after, document["recorded_at"])
    if base.legacy._parse_time(document["recorded_at"]) >= base.legacy._parse_time(
        outer_recorded_at
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt recording order changed")


def _verify_static(before: Mapping[str, Any], container_id: str) -> None:
    boundary = before["boundary_before"]
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or _canonical_digest(boundary) != _STATIC_DIGESTS["boundary"]
        or before["runtime_tree_before"] != current._RUNTIME_TREE
        or before["config_lock_before"]
        != {
            "exists": False,
            "path": (
                "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock"
            ),
        }
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt current contract changed")
    current._verify_config(boundary["configuration"])
    current._verify_target(before["target_before"])
    if (
        before["target_before"]["root"]["exists"] is not True
        or before["target_before"]["entries"][0]["exists"] is not True
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt target absent")
    current._verify_gateway(before["gateway_process_before"], container_id)
    current._verify_openclaw(before["openclaw_before"])
    current._verify_read_only_mount(
        boundary["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{_RUNTIME_VOLUME}/_data",
    )
    current._verify_read_only_mount(
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
        raise AdmissionEvidenceError("catalog-fixed V2 prompt protected roots changed")
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
                "catalog-fixed V2 prompt protected roots changed"
            )


def _verify_commands(action: Mapping[str, Any], nonce: str, recorded_at: str) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    commands = action["commands"]
    expected = [
        before["version"],
        before["system_info_before"]["command"],
        *after["initial_turn"]["commands"],
        *after["rebuild_turn"]["commands"],
        after["system_info_after"]["command"],
    ]
    if (
        commands != expected
        or len(commands) != 7
        or any(
            type(command["pid"]) is not int or command["pid"] <= 1
            for command in commands
        )
        or len({command["pid"] for command in commands}) != 7
        or any(
            not (
                base.legacy._parse_time(command["started_at"])
                <= base.legacy._parse_time(command["completed_at"])
            )
            for command in commands
        )
        or any(
            base.legacy._parse_time(left["completed_at"])
            > base.legacy._parse_time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or base.legacy._parse_time(commands[-1]["completed_at"])
        > base.legacy._parse_time(recorded_at)
    ):
        raise AdmissionEvidenceError(
            "catalog-fixed V2 prompt command causality changed"
        )
    base.legacy._verify_command(
        before["version"],
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ],
        expected_pid=before["version"]["pid"],
        stdout_exact=base.legacy.parent._RUNTIME["version_output"] + "\n",
    )
    gateway = before["gateway_process_before"]
    _verify_system(before["system_info_before"], gateway)
    _verify_system(after["system_info_after"], gateway)
    current._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )
    semantic._verify_turn(after["initial_turn"], "initial", nonce)
    semantic._verify_turn(after["rebuild_turn"], "rebuild", nonce)


def _verify_system(value: Mapping[str, Any], gateway: Mapping[str, Any]) -> None:
    response = value["response"]
    system = response["value"]
    if (
        response["parsed"] is not True
        or system["pid"] != gateway["pid"]
        or system["hostname"] != gateway["hostname"]
        or system["machineName"] != gateway["hostname"]
        or system["diskPath"] != "/var/lib/aragorn-agent-gateway/state"
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 prompt system identity changed")
    base.legacy._verify_command(
        value["command"],
        base.legacy._gateway_argv("system.info", "5000"),
        expected_pid=value["command"]["pid"],
        stdout_value=system,
    )


def _verify_rebuild_chronology(after: Mapping[str, Any], recorded_at: str) -> None:
    initial = after["initial_snapshot"]
    rebuilt = after["rebuilt_snapshot"]
    initial_turn = after["initial_turn"]
    rebuild_turn = after["rebuild_turn"]
    invalidation = after["invalidation"]
    initial_blob_ms = int(initial["blob"]["mtime_ns"]) // 1_000_000
    rebuilt_blob_ms = int(rebuilt["blob"]["mtime_ns"]) // 1_000_000
    store_before_ms = int(invalidation["store_before"]["mtime_ns"]) // 1_000_000
    store_after_ms = int(invalidation["store_after_rewrite"]["mtime_ns"]) // 1_000_000
    if not (
        base.legacy._parse_time(initial_turn["send"]["command"]["completed_at"])
        <= base.legacy._parse_time(initial_turn["wait"]["command"]["started_at"])
        <= base.legacy._parse_time(initial_turn["wait"]["command"]["completed_at"])
        <= base.legacy._parse_time(invalidation["started_at"])
        < base.legacy._parse_time(invalidation["completed_at"])
        <= base.legacy._parse_time(rebuild_turn["send"]["command"]["started_at"])
        <= base.legacy._parse_time(rebuild_turn["send"]["command"]["completed_at"])
        <= base.legacy._parse_time(rebuild_turn["wait"]["command"]["started_at"])
        <= base.legacy._parse_time(rebuild_turn["wait"]["command"]["completed_at"])
        <= base.legacy._parse_time(after["system_info_after"]["command"]["started_at"])
        <= base.legacy._parse_time(
            after["system_info_after"]["command"]["completed_at"]
        )
        <= base.legacy._parse_time(recorded_at)
    ):
        raise AdmissionEvidenceError(
            "catalog-fixed V2 prompt command chronology changed"
        )
    if not (
        initial["entry"]["started_at"]
        <= initial["entry"]["ended_at"]
        <= store_before_ms
        <= initial["entry"]["updated_at"]
        <= initial_blob_ms
        <= initial_turn["wait"]["response"]["value"]["endedAt"]
        <= base.legacy._epoch_ms(initial_turn["wait"]["command"]["completed_at"])
        <= base.legacy._epoch_ms(invalidation["started_at"])
        <= store_after_ms
        <= base.legacy._epoch_ms(invalidation["completed_at"])
        <= base.legacy._epoch_ms(rebuild_turn["send"]["command"]["started_at"])
        <= rebuilt["entry"]["started_at"]
        <= rebuilt["entry"]["ended_at"]
        <= rebuilt["entry"]["updated_at"]
        <= rebuilt_blob_ms
        <= rebuild_turn["wait"]["response"]["value"]["endedAt"]
        <= base.legacy._epoch_ms(rebuild_turn["wait"]["command"]["completed_at"])
        <= base.legacy._epoch_ms(recorded_at)
    ):
        raise AdmissionEvidenceError(
            "catalog-fixed V2 prompt document chronology changed"
        )


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError(
                "catalog-fixed V2 prompt unexpected floating-point value"
            )
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key == "message_prefix_continuity_valid":
                if item is not None and type(item) is not bool:
                    raise AdmissionEvidenceError(
                        "catalog-fixed V2 prompt nullable boolean changed"
                    )
            elif isinstance(key, str) and (
                (key in _BOOLEAN_FIELDS) != (type(item) is bool)
            ):
                raise AdmissionEvidenceError(
                    "catalog-fixed V2 prompt boolean field type changed"
                )
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError(
                    "catalog-fixed V2 prompt boolean list item changed"
                )
            _verify_scalar_types(item, float_allowed=float_allowed)
