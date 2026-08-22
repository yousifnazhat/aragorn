"""Derive one V2 cron-rescan PASS from the catalog-fixed retained evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_config_activation as current
from . import admission_protected_final_combined_v2_cron_rescan as semantic
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/reload/cron-rescan"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-64902"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

_DEPENDENCIES = {
    "current_contract": {
        "digest": (
            "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6"
        ),
        "path": "admission_protected_final_combined_v2_config_activation.py",
    },
    "cron_semantics": {
        "digest": (
            "sha256:180a1c2757c5bbfaa44c2eb05c8f1aa522ac2c4327df2d8447a384fb076a2e04"
        ),
        "path": "admission_protected_final_combined_v2_cron_rescan.py",
    },
    "prompt_contract": {
        "digest": (
            "sha256:6518ada93011ed91bd5a5d3a7d53a599603be863d9dea1427441628bab08a3ee"
        ),
        "path": "admission_protected_final_combined_v2_prompt_rebuild.py",
    },
    "cron_patterns": {
        "digest": (
            "sha256:e0cbfb701345e834bfcaa8a29e34660d90dd9a5cd1a7b45de35c6ee330465e65"
        ),
        "path": "admission_protected_cron.py",
    },
}
_EVIDENCE = {
    "bytes": 598_239,
    "canonical_bytes": 598_238,
    "canonical_digest": (
        "sha256:5ab21441deecc03ecb277ddd1064bf7fc3037523cf5f4d1362f4025dfefe144e"
    ),
    "digest": (
        "sha256:7914578bfadc88a33e0f2ea0ee97350de7be8881e852326a07294b74c5f3e003"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "cron-rescan-systemd-p3-final-catalog-fixed-2026-08-22.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 93_788,
    "canonical_digest": (
        "sha256:4fa1219c9c087eed76419013b66fd2f2a90b963d7ab0f73129fdbb4be9122a1f"
    ),
    "digest": (
        "sha256:eb0dfff60628318eed0bd47553c2cdb912d88938ff590495f58ca7fd2258b02e"
    ),
}
_SOURCE = {
    "commit": "8e19944e294486509f60e4d34f5efdc0ee771974",
    "parent": "9bc13769a9b71faf23012be993e615474934618d",
    "tree": "e0c54ffd6644cf07c65f1d0f924a424fc80855e3",
}
_RETENTION = {
    "commit": "b583862c5738631442dc972474490ee4cb6a9f0e",
    "parent": _SOURCE["commit"],
    "tree": "fce9214a2560a20cbfdc3d5929e00d20b6abcb5f",
}
_RETENTION_BLOB = "8a67a487fa025548627602d776ef7285b29abcf1"
_IMAGE = "sha256:700ebe792d384cce37484f1838f05622b0518984f293f4d4c0cd28c6fb60f9d4"
_PARENT_IMAGE = (
    "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
)
_DIGESTS = {
    "action": "sha256:b194d8085d2cf69b690d2071fb6a552985549b1154a0f33b86ef92f4b23d0744",
    "composition": (
        "sha256:cd8009bd19d15918f30231214f3d3ac09f69f51dad363674f4cb2e243cbd1c5b"
    ),
    "composition_action": (
        "sha256:d81e8fedb38dd6092df281aa383f6c61f858276013e1ec5ee29bb8bac4010644"
    ),
    "execution": (
        "sha256:8541378a2412a55c3702e1b40ed14a52d8494c3cf289c61d4d614c6b9147e917"
    ),
    "gateway_binding": (
        "sha256:0482662a733d8ba40bb119e342e63765e7053b413e7d98640737f5fb561bf28a"
    ),
    "harness": (
        "sha256:0bf68b94d5c3b954c94885ed48a8269da966c5a683254378cb72eeb02692627a"
    ),
    "host_config": (
        "sha256:4f779eff27c672db391f7d6dda1d33b12a711ce0d69ae2c7cadf7c6afb49c8c5"
    ),
    "image_lineage": (
        "sha256:a2d5cfc19644d5285878238bd22fc338ccef61df23c6d168e48c754790b5475f"
    ),
    "source_artifacts": (
        "sha256:2db37a2d915cc9b52adf4b00017823b8ad54baea3016c589db94f60d51451dbf"
    ),
    "stack": "sha256:82bcf87ce106c19f91d2269161c9309fcd3275d09d1eabcf061dc20de4b3dbe9",
}
_STATIC_DIGESTS = {
    "boundary": "sha256:913ad80055afb7460aa81baa3df55bf0a94805d709ee31d0d75469144f21ffb4",
    "config": "sha256:56a0c576151193cac46ffa0e98f36bf4cac2758775c87afd9c3df89f4f53f28b",
    "config_lock": (
        "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2"
    ),
    "config_tree": (
        "sha256:131fc3a0a815069a67baf2f1261db988d417887afab107bc6d3a3325c22bf877"
    ),
    "gateway": "sha256:e4b9f52acc0617a3c9aa5122b02e95f55b6a21bebeb8704e05a31bc225df1a82",
    "modules": "sha256:b624f9ba14df4da2b769b886a6675a646b29c0c430832b8b88ace6a118a1e1ac",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "protected_roots": (
        "sha256:45c9d950cfd98b36370a47e2b46c2236f46b1a8f4b92d087731b638639370b83"
    ),
    "runtime_tree": (
        "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b"
    ),
    "session_store": (
        "sha256:23c269084385ce8948bd27ca430538fb9b85fd118c7aa268de660b64dd3ef3e8"
    ),
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
}
_SOURCE_ARTIFACTS = {
    "collector": dict(current._SOURCE_ARTIFACTS["collector"]),
    "helper": {
        "bytes": 16_324,
        "digest": (
            "sha256:91febf12bd6aa2e98f63b14001a74213c653c2eb9c8c7db57a55b3520fdd4f22"
        ),
        "name": "protected-observation-v1.mjs",
    },
    "materializer": dict(current._SOURCE_ARTIFACTS["materializer"]),
    "probe": {
        "bytes": 35_318,
        "digest": (
            "sha256:94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0"
        ),
        "name": "protected-cron-rescan-probe.mjs",
    },
    "v1_route_injector": dict(current._SOURCE_ARTIFACTS["v1_route_injector"]),
}
_BOOLEAN_FIELDS = current._BOOLEAN_FIELDS | semantic._ROUTE_BOOLEAN_FIELDS


def verify_openclaw_final_combined_v2_cron_rescan_catalog_fixed(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 1/20 V2 coverage after current-contract cron verification."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = current.base.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 catalog-fixed cron rescan"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V2 catalog-fixed cron CAS differs from signed retention"
            )
        evidence = current.base.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 catalog-fixed cron rescan"
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
            f"invalid V2 catalog-fixed cron evidence: {exc}"
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
            "aragorn/admission-protected-final-combined-v2-cron-rescan-"
            "catalog-fixed-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_CURRENT_CONTRACT_V2_"
            "CRON_ROUTE_ONLY"
        ),
        "bindings": {
            "configuration": dict(current._SOURCES["configuration"]),
            "cron_rescan_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": current.base.legacy.parent._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(current.base.legacy.parent._SIGNATURE),
                },
            },
            "image": _IMAGE,
            "profile": dict(current._SOURCES["profile"]),
            "runtime": dict(current.base.legacy.parent._RUNTIME),
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
            **{key: False for key in current.base.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_CRON_RESCAN_PASS_ONLY",
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
                "SIGNED_EXACT_CURRENT_CATALOG_CRON_FORCE_RUN_SNAPSHOT_AND_"
                "MODEL_NOT_FOUND_TRANSITION"
            ),
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Any) -> str:
    return _digest(current.base.legacy.parent.oci_worker_protocol.canonical_json(value))


def _verify_dependencies() -> None:
    directory = Path(__file__).resolve(strict=True).parent
    modules = {
        "current_contract": current,
        "cron_semantics": semantic,
        "prompt_contract": semantic.parent,
        "cron_patterns": semantic.cron,
    }
    for name, module in modules.items():
        identity = _DEPENDENCIES[name]
        path = Path(module.__file__).resolve(strict=True)
        if (
            path != (directory / identity["path"]).resolve(strict=True)
            or _digest(path.read_bytes()) != identity["digest"]
        ):
            raise AdmissionEvidenceError(
                f"V2 catalog-fixed cron dependency changed: {name}"
            )
    if semantic.parent.parent is not current.base:
        raise AdmissionEvidenceError("V2 catalog-fixed cron dependency graph changed")
    current._verify_dependencies()


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
        raise AdmissionEvidenceError("V2 catalog-fixed cron repository changed")
    current.base._verify_commit(_SOURCE)
    current.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V2 catalog-fixed cron signed tree entry changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=640 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    _verify_scalar_types(evidence)
    current._verify_no_positive_eligibility(evidence)
    if (
        set(evidence)
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
        or evidence["recorded_at"] != "2026-08-22T09:57:12.460477Z"
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
            **{key: False for key in current.base.legacy.parent._ELIGIBILITY_KEYS},
        }
        or evidence["limitations"] != semantic._LIMITATIONS["outer"]
        or _canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or _canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron wrapper changed")

    profile = _verify_composition(evidence["composition"], evidence["source_artifacts"])
    observation = evidence["route_observation"]
    document = _decode_route_raw(observation["raw"])
    harness = evidence["composition"]["action"]["harness"]["document"]
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
        != [_SOURCE_ARTIFACTS["probe"], _SOURCE_ARTIFACTS["helper"]]
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron nested custody changed")
    _verify_execution(
        observation,
        evidence["composition"]["action"]["boundaries"],
        harness,
    )
    _verify_route_contract(document, harness["container_id"])
    if not (
        current.base.legacy._parse_time(document["recorded_at"])
        <= current.base.legacy._parse_time(observation["execution"]["completed_at"])
        <= current.base.legacy._parse_time(evidence["composition"]["recorded_at"])
        <= current.base.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron execution custody changed")
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
        or composition["recorded_at"] != "2026-08-22T09:57:12.460455Z"
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
        or composition["limitations"] != semantic._LIMITATIONS["composition"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron composition changed")

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
        or action["recorded_at"] != "2026-08-22T09:57:12.086894Z"
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
        or action["limitations"] != semantic._LIMITATIONS["action"]
        or profile_before != profile_after
        or profile_before != source["profile"]
        or action["inputs"]["gateway_config"] != source["config"]["document"]
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(current.base.legacy.parent._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["runtime"]
        != {
            **current.base.legacy.parent._OPENCLAW,
            "name": "openclaw-protected-final-combined-v2",
        }
        or action["runtime"]
        != {
            "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "entrypoint_digest": current.base.legacy.parent._RUNTIME[
                "entrypoint_digest"
            ],
            "expected_version": current.base.legacy.parent._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": current._RUNTIME_TREE,
            "version_output": current.base.legacy.parent._RUNTIME["version_output"],
        }
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron profile or action changed")
    current._verify_configuration(source)
    _verify_source_artifacts(source_artifacts)
    _verify_harness(action["harness"])
    return profile


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {"collector", "materializer", "probe_bundle", "v1_route_injector"}:
        raise AdmissionEvidenceError("V2 catalog-fixed cron source bundle changed")
    for name in ("collector", "materializer", "v1_route_injector"):
        identity = _SOURCE_ARTIFACTS[name]
        current._verify_bound_file(
            value[name], identity, path=identity["path"], mode="0555"
        )
    if value["probe_bundle"] != [
        _SOURCE_ARTIFACTS["probe"],
        _SOURCE_ARTIFACTS["helper"],
    ]:
        raise AdmissionEvidenceError("V2 catalog-fixed cron probe bundle changed")


def _verify_harness(envelope: Mapping[str, Any]) -> None:
    document = envelope["document"]
    file = envelope["file"]
    raw = base64.b64decode(file["base64"], validate=True)
    parsed = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=current.base.legacy.parent._reject_duplicates,
        parse_constant=current.base.legacy.parent._reject_constant,
    )
    canonical = current.base.legacy.parent.oci_worker_protocol.canonical_json(document)
    lineage = document["image_lineage"]
    stat = file["stat"]
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
        or _canonical_digest(document["host_config"]) != _DIGESTS["host_config"]
        or _canonical_digest(lineage) != _DIGESTS["image_lineage"]
        or not isinstance(document["container_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", document["container_id"]) is None
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["image_reference"] != "aragorn-phase3-final-combined-v2-systemd"
        or document["platform"] != "linux"
        or document["profile_label"] != "phase3-final-combined-v2"
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or not lineage["added_layers"]
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or lineage["child"]["rootfs_type"] != "layers"
        or lineage["parent"]["rootfs_type"] != "layers"
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
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:64902",
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
                "io.aragorn.source-commit": current.base.legacy.parent._OPENCLAW[
                    "commit"
                ],
                "io.aragorn.source-tree": current.base.legacy.parent._OPENCLAW[
                    "source_tree"
                ],
            },
            "name": _RUNTIME_VOLUME,
            "options": None,
            "scope": "local",
        }
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
        or set(document["source_commit_verification"])
        != {"command", "commit_object", "exit_code", "stderr", "stdout"}
        or document["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or document["source_commit_verification"]["exit_code"] != 0
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron harness changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V2 catalog-fixed cron raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode(),
        object_pairs_hook=current.base.legacy.parent._reject_duplicates,
        parse_constant=current.base.legacy.parent._reject_constant,
    )
    canonical = current.base.legacy.parent.oci_worker_protocol.canonical_json(document)
    if (
        raw != canonical + b"\n"
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not True
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron raw identity changed")
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
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
            "unit": gateway_unit,
        }
        or type(pid) is not int
        or pid <= 0
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
        or any(
            type(identity) is not int
            for identity in (
                execution["effective_identity"]["gid"],
                execution["effective_identity"]["uid"],
                *execution["effective_identity"]["groups"],
            )
        )
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
        or stack["processes"][gateway_unit]["pid"] != pid
        or stack["processes"][gateway_unit]["uids"] != [992, 992, 992, 992]
        or stack["processes"][gateway_unit]["gids"] != [992, 992, 992, 992]
        or stack["processes"][gateway_unit]["groups"] != [992]
        or stack["processes"][gateway_unit]["capabilities_effective"]
        != "0000000000000000"
        or stack["processes"][gateway_unit]["no_new_privileges"] != 1
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
                document["action"]["commands"][0]["started_at"]
            )
            <= current.base.legacy._parse_time(
                document["action"]["commands"][-1]["completed_at"]
            )
            <= current.base.legacy._parse_time(document["recorded_at"])
            <= current.base.legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron execution boundary changed")
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
        or document["schema"] != "aragorn/openclaw-protected-cron-rescan-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digests"]
        != {
            "helper": _SOURCE_ARTIFACTS["helper"]["digest"],
            "probe": _SOURCE_ARTIFACTS["probe"]["digest"],
        }
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
            "commit": current.base.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": current.base.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": current._RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or _canonical_digest(document["action"]) != _DIGESTS["action"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron route changed")

    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
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
        or set(before)
        != {
            "boundary_before",
            "config_before",
            "config_lock_before",
            "config_tree_before",
            "cron_inventory_before",
            "gateway_process_before",
            "module_files_before",
            "openclaw_before",
            "protected_root_trees_before",
            "runtime_tree_before",
            "session_store_before",
            "system_info_before",
            "target_before",
            "version",
        }
        or set(after)
        != {
            "boundary_after",
            "cleanup",
            "config_after",
            "config_lock_after",
            "config_tree_after",
            "cron_inventory_after_add",
            "cron_inventory_after_remove",
            "gateway_process_after",
            "job",
            "module_files_after",
            "openclaw_after",
            "protected_root_trees_after",
            "run",
            "runtime_tree_after",
            "session_state_before_forced_run",
            "session_store_after",
            "snapshot",
            "system_info_after",
            "target_after",
            "terminal_result",
        }
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron action shape changed")
    stable = {
        "boundary": (before["boundary_before"], after["boundary_after"]),
        "config": (before["config_before"], after["config_after"]),
        "config_lock": (before["config_lock_before"], after["config_lock_after"]),
        "config_tree": (before["config_tree_before"], after["config_tree_after"]),
        "gateway": (
            before["gateway_process_before"],
            after["gateway_process_after"],
        ),
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
            _canonical_digest(left) != _STATIC_DIGESTS[name]
            for name, (left, _right) in stable.items()
        )
        or _canonical_digest(before["session_store_before"])
        != _STATIC_DIGESTS["session_store"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron protected state changed")
    boundary = before["boundary_before"]
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or before["config_before"] != boundary["configuration"]
        or _canonical_digest(before["config_before"]["document"])
        != current._SOURCES["configuration"]["canonical_digest"]
        or before["runtime_tree_before"] != current._RUNTIME_TREE
        or before["config_lock_before"]
        != {
            "exists": False,
            "path": (
                "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock"
            ),
        }
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed cron current contract changed")
    current._verify_config(before["config_before"])
    current._verify_target(before["target_before"])
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
    semantic._verify_route(
        action,
        document["recorded_at"],
        expected_gateway_pid=before["gateway_process_before"]["pid"],
        expected_hostname=before["gateway_process_before"]["hostname"],
    )


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError(
                "V2 catalog-fixed cron unexpected floating-point value"
            )
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key == "message_prefix_continuity_valid":
                if item is not None and type(item) is not bool:
                    raise AdmissionEvidenceError(
                        "V2 catalog-fixed cron nullable boolean changed"
                    )
            elif isinstance(key, str) and (
                (key in _BOOLEAN_FIELDS) != (type(item) is bool)
            ):
                raise AdmissionEvidenceError(
                    "V2 catalog-fixed cron boolean field type changed"
                )
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError(
                    "V2 catalog-fixed cron boolean list item changed"
                )
            _verify_scalar_types(item, float_allowed=float_allowed)
