"""Derive one V2 session-snapshot-consumer PASS from the catalog-fixed retained evidence."""

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

from . import admission_protected_final_combined_v2_config_activation as current
from . import (
    admission_protected_final_combined_v2_session_snapshot_consumer as semantic,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/reload/session-snapshot-consumer"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-65090"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

_DEPENDENCIES = {
    "current_contract": {
        "digest": (
            "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6"
        ),
        "path": "admission_protected_final_combined_v2_config_activation.py",
    },
    "session_semantics": {
        "digest": (
            "sha256:689cd095b38b6ce70e94dd4741c6000355420644060660c4bdc90db262e481c8"
        ),
        "path": "admission_protected_final_combined_v2_session_snapshot_consumer.py",
    },
    "session_semantics_parent": {
        "digest": (
            "sha256:180a1c2757c5bbfaa44c2eb05c8f1aa522ac2c4327df2d8447a384fb076a2e04"
        ),
        "path": "admission_protected_final_combined_v2_cron_rescan.py",
    },
    "session_v1": {
        "digest": (
            "sha256:dbbded9573031e791e9382398d87a0c8c3753822dc68e473221df8883b79b7ed"
        ),
        "path": "admission_protected_session_snapshot.py",
    },
}
_EVIDENCE = {
    "bytes": 603_610,
    "canonical_bytes": 603_609,
    "canonical_digest": (
        "sha256:35012e1048d5b17d01d1d62796311e351bbb2e93d87d74667f31a3070618216a"
    ),
    "digest": (
        "sha256:f4745ede0f7b4ed044df709ec8fa560dfa5ac98ce5139d766e01fa9f50f22c0f"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "session-snapshot-consumer-systemd-p3-final-catalog-fixed-2026-08-22.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 96_072,
    "canonical_digest": (
        "sha256:4ee6b4fe878dd287302d203679084a1427e31dfb5d791702b1cdf3e7a4874bb2"
    ),
    "digest": (
        "sha256:51f3c395a813813732b1941b2ee0b5b50d1f76e559ca871de21dfefc659cbaf5"
    ),
}
_SOURCE = {
    "commit": "b583862c5738631442dc972474490ee4cb6a9f0e",
    "parent": "8e19944e294486509f60e4d34f5efdc0ee771974",
    "tree": "fce9214a2560a20cbfdc3d5929e00d20b6abcb5f",
}
_RETENTION = {
    "commit": "5025f00fccbce6a8b7dacfa787a699276f8f4310",
    "parent": _SOURCE["commit"],
    "tree": "5b0f4a0381fd676e51d065a852c8ae3a5829f6fb",
}
_RETENTION_BLOB = "cc5503cbfa0a72d423396d43fdc0ddbb5b143a9a"
_IMAGE = "sha256:700ebe792d384cce37484f1838f05622b0518984f293f4d4c0cd28c6fb60f9d4"
_PARENT_IMAGE = (
    "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
)
_DIGESTS = {
    "action": "sha256:3e4ba6637cdbefb4652b836645b147f6573f4ec2e2aba21648bb0c9d19276ca0",
    "composition": (
        "sha256:c1b243ce869bc20e37534f720b64f7eec82bf6cfcad3241edf1b0226be84561e"
    ),
    "composition_action": (
        "sha256:cede1aa26ec7b5e62ee5fa080bdf6fb29b445e5db70638a6462f7c15600e5892"
    ),
    "execution": (
        "sha256:ddfb9be3c1cc3cb9fa422daa1b7e79da3e885114c38aeb758637439b3bcc5721"
    ),
    "gateway_binding": (
        "sha256:fcd88400787187b5b06617b15c92e2cfb130067beff97408fe3910f25843f0f3"
    ),
    "harness": (
        "sha256:073dc36bc5d97f046687af8c07b1fb8d4e9be82a6eadcc0d0c77ec2be8ba6967"
    ),
    "host_config": (
        "sha256:917e4e33c430689b86b800499d41dc3b1638937132c788c92e5a2f8b786406c2"
    ),
    "image_lineage": (
        "sha256:a2d5cfc19644d5285878238bd22fc338ccef61df23c6d168e48c754790b5475f"
    ),
    "source_artifacts": (
        "sha256:c7b50601165a53692a0076937e3298a35dba09984f620070fc6a39d8ffe0e3ad"
    ),
    "stack": "sha256:0e9e9ca93b626d6d25723cd92b78fc1e6f58da2d17bee8f7b03a9739fd247360",
    "replay": "sha256:757c8160d48a6cfa6db240d94b67a5f534e3b0e9fcc9d8c3128dc1922d5f26b3",
    "module_files": (
        "sha256:9846dfc18ae93d3c216a6e87ba89b811b7d260b52a264ee1551cf1638cc6abad"
    ),
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
        "bytes": 42_266,
        "digest": (
            "sha256:9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11"
        ),
        "name": "protected-session-snapshot-fixed-probe.mjs",
    },
    "v1_route_injector": dict(current._SOURCE_ARTIFACTS["v1_route_injector"]),
}
_BOOLEAN_FIELDS = current._BOOLEAN_FIELDS | semantic._ROUTE_BOOLEAN_FIELDS
_SHAPE_DIGEST = (
    "sha256:74ebe5d340f78bcb3a49e2342b275d9fb625589c14101349c77734f96f788808"
)


def verify_openclaw_final_combined_v2_session_snapshot_consumer_catalog_fixed(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 1/20 V2 coverage after current-contract session verification."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = current.base.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 catalog-fixed session snapshot"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V2 catalog-fixed session CAS differs from signed retention"
            )
        evidence = current.base.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 catalog-fixed session snapshot"
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
            f"invalid V2 catalog-fixed session evidence: {exc}"
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
            "aragorn/admission-protected-final-combined-v2-session-snapshot-consumer-"
            "catalog-fixed-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_CURRENT_CONTRACT_V2_"
            "SESSION_SNAPSHOT_ROUTE_ONLY"
        ),
        "bindings": {
            "configuration": dict(current._SOURCES["configuration"]),
            "session_snapshot_observation": {
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
            "compiled_closure": {
                "acquisition": {
                    key: semantic._ACQUISITION[key]
                    for key in ("bytes", "digest", "path")
                },
                "archive": {
                    key: semantic._ARCHIVE[key] for key in ("bytes", "digest", "path")
                },
                "manifest": {
                    key: semantic._MANIFEST[key] for key in ("bytes", "digest", "path")
                },
                "module_files_canonical_digest": _DIGESTS["module_files"],
                "scope": "fourteen_selected_compiled_route_modules",
            },
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
            "ONE_EXACT_DYNAMIC_SESSION_SNAPSHOT_CONSUMER_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "PRIOR_ROUTE_PASSES_NOT_COMPOSED_ACROSS_V2_CONFIG_CHANGE",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "DETERMINISTIC_COMPILED_REPLAY_NOT_NATIVE_AGENT_EXECUTION",
            "NATIVE_MODEL_ATTEMPTS_ENDED_IN_EXPECTED_NETWORK_ERROR",
            "NATIVE_PROVIDER_REQUEST_BODY_AND_SYSTEM_PROMPT_REPORT_NOT_OBSERVED",
            "FOURTEEN_SELECTED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "COMPILED_CLOSURE_REUSED_FROM_PRIOR_CAPTURE_WITH_IDENTICAL_RUNTIME_TREE",
            "PRE_ROUTE_READ_ONLY_CLOSURE_ACQUISITION_BOUND_BY_RUNTIME_TREE",
            "NO_POST_ROUTE_CLOSURE_PROVENANCE_OR_CONTINUOUS_IMMUTABILITY_CLAIM",
            "ACQUISITION_IMAGE_DIFFERS_FROM_CURRENT_ROUTE_CAPTURE_IMAGE",
            "LOCAL_DOCKER_VOLUME_NOT_INDEPENDENTLY_ATTESTED",
            "ORIGINAL_PROVIDER_REQUEST_AND_SESSION_STORE_RAW_BYTES_NOT_RETAINED",
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
                "SIGNED_EXACT_CURRENT_CATALOG_SESSION_SNAPSHOT_REFRESH_TO_"
                "PROTECTED_PROMPT_AFTER_ATTACKER_PROMPTREF_REPLACEMENT"
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
        "session_semantics": semantic,
        "session_semantics_parent": semantic.parent,
        "session_v1": semantic.session_v1,
    }
    for name, module in modules.items():
        identity = _DEPENDENCIES[name]
        path = Path(module.__file__).resolve(strict=True)
        if (
            path != (directory / identity["path"]).resolve(strict=True)
            or _digest(path.read_bytes()) != identity["digest"]
        ):
            raise AdmissionEvidenceError(
                f"V2 catalog-fixed session dependency changed: {name}"
            )
    current._verify_dependencies()


def _verify_compiled_closure() -> dict[str, bytes]:
    signed = semantic._read_signed_sources()
    evidence = semantic._load_canonical_json(
        signed["evidence"], semantic._EVIDENCE, "prior route evidence"
    )
    acquisition = semantic._load_canonical_json(
        signed["acquisition"], semantic._ACQUISITION, "closure acquisition"
    )
    manifest, closure_files = semantic._verify_archive(
        signed["archive"], signed["manifest"]
    )
    semantic._verify_acquisition(acquisition, evidence, manifest)
    current.base.legacy._git(
        [
            "merge-base",
            "--is-ancestor",
            semantic._ACQUISITION_RETENTION["commit"],
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
        raise AdmissionEvidenceError("V2 catalog-fixed session repository changed")
    current.base._verify_commit(_SOURCE)
    current.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError(
            "V2 catalog-fixed session signed tree entry changed"
        )
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=640 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed session signed blob changed")
    return raw


def _verify_evidence(
    evidence: Mapping[str, Any], *, closure_files: Mapping[str, bytes]
) -> Mapping[str, Any]:
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
        or evidence["recorded_at"] != "2026-08-22T09:58:09.826661Z"
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
        or evidence["limitations"] != semantic.parent._LIMITATIONS["outer"]
        or _canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or _canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed session wrapper changed")

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
        != [_SOURCE_ARTIFACTS["helper"], _SOURCE_ARTIFACTS["probe"]]
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed session nested custody changed")
    _verify_execution(
        observation,
        evidence["composition"]["action"]["boundaries"],
        harness,
    )
    _verify_route_contract(document, harness["container_id"], closure_files)
    if not (
        current.base.legacy._parse_time(document["recorded_at"])
        <= current.base.legacy._parse_time(observation["execution"]["completed_at"])
        <= current.base.legacy._parse_time(evidence["composition"]["recorded_at"])
        <= current.base.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError(
            "V2 catalog-fixed session execution custody changed"
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
        or composition["recorded_at"] != "2026-08-22T09:58:09.826641Z"
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
        or composition["limitations"] != semantic.parent._LIMITATIONS["composition"]
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed session composition changed")

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
        or action["recorded_at"] != "2026-08-22T09:58:09.451349Z"
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
        or action["limitations"] != semantic.parent._LIMITATIONS["action"]
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
        raise AdmissionEvidenceError(
            "V2 catalog-fixed session profile or action changed"
        )
    current._verify_configuration(source)
    _verify_source_artifacts(source_artifacts)
    _verify_harness(action["harness"])
    return profile


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {"collector", "materializer", "probe_bundle", "v1_route_injector"}:
        raise AdmissionEvidenceError("V2 catalog-fixed session source bundle changed")
    for name in ("collector", "materializer", "v1_route_injector"):
        identity = _SOURCE_ARTIFACTS[name]
        current._verify_bound_file(
            value[name], identity, path=identity["path"], mode="0555"
        )
    if value["probe_bundle"] != [
        _SOURCE_ARTIFACTS["helper"],
        _SOURCE_ARTIFACTS["probe"],
    ]:
        raise AdmissionEvidenceError("V2 catalog-fixed session probe bundle changed")


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
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:65090",
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
        raise AdmissionEvidenceError("V2 catalog-fixed session harness changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V2 catalog-fixed session raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode(),
        object_pairs_hook=current.base.legacy.parent._reject_duplicates,
        parse_constant=current.base.legacy.parent._reject_constant,
    )
    canonical = current.base.legacy.parent.oci_worker_protocol.canonical_json(document)
    if (
        not raw.endswith(b"\n")
        or raw == canonical + b"\n"
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not False
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed session raw identity changed")
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
            "/route-input/session-snapshot-consumer/protected-session-snapshot-fixed-probe.mjs",
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
        raise AdmissionEvidenceError(
            "V2 catalog-fixed session execution boundary changed"
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
    container_id: str,
    closure_files: Mapping[str, bytes],
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
    protected_digest = (
        "sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501"
    )
    attacker_digest = (
        "sha256:b682f676ab2b736daa8f87f83017c5202dc547964583a51cd52ce5e461e73bac"
    )
    reports = {
        "expected_skills_hash": protected_digest.removeprefix("sha256:"),
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
    compiled_report = {
        "bootstrapMaxChars": None,
        "bootstrapTotalMaxChars": None,
        "generatedAt": 0,
        "injectedWorkspaceFiles": [],
        "model": "gpt-5.5",
        "provider": "openai",
        "sandbox": {"sandboxed": False},
        "sessionId": initial["entry"]["session_id"],
        "sessionKey": (f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}"),
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
    semantic._verify_snapshot(
        initial,
        protected_digest,
        entry_digest=(
            "sha256:8c3bad6173b33e53ad1fbfb1510ab94ab64ae2752fc9a0fc0f8d821a0ad6d1c6"
        ),
        store_digest=(
            "sha256:2ce6c24a36e5f4aa0a8322f7a462c2641076ea64fa08f7bb55eced46580af33d"
        ),
        store_bytes=6_628,
        store_inode=1_116_358,
        nonce=nonce,
    )
    semantic._verify_snapshot(
        mutated,
        attacker_digest,
        entry_digest=(
            "sha256:cdc938b47517c8181fe5a5dc0117d431043fa94d2683220fc2d2fd9ac9c5fd1f"
        ),
        store_digest=(
            "sha256:e8fec7b40be1dcd1ef3f0039f8e28e9f3aa137f8ef7253073ae038f353441359"
        ),
        store_bytes=6_629,
        store_inode=1_116_361,
        nonce=nonce,
    )
    semantic._verify_snapshot(
        final,
        protected_digest,
        entry_digest=(
            "sha256:60d66bb5f50265f081f27127f132867826dabd759ff96699deebceba891d3506"
        ),
        store_digest=(
            "sha256:ed786311f5084244d1e038781e24f265a577f3c79dc63dd2fcab74fc723f55bb"
        ),
        store_bytes=6_628,
        store_inode=1_116_356,
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
        or document["schema"]
        != "aragorn/openclaw-protected-session-snapshot-fixed-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["recorded_at"] != "2026-08-22T09:58:09.418Z"
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        or document["implementation_digests"]
        != {
            "helper": _SOURCE_ARTIFACTS["helper"]["digest"],
            "probe": _SOURCE_ARTIFACTS["probe"]["digest"],
        }
        or document["route"]
        != {
            "action_id": "session-snapshot-consumer-fixed",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or document["runtime_binding"]
        != {
            "commit": current.base.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": current.base.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": current._RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or _canonical_digest(action) != _DIGESTS["action"]
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
        or action["id"] != "session-snapshot-consumer-fixed"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
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
        or before["session_entry_absent_before"] is not True
        or observations["compiled_protected_prompt_boundary_observed"] is not True
        or _canonical_digest(replay) != _DIGESTS["replay"]
        or _canonical_digest(replay["module_files"]) != _DIGESTS["module_files"]
        or replay["assurance"]
        != "DETERMINISTIC_PINNED_COMPILED_ROUTE_REPLAY_NOT_NATIVE_AGENT_EXECUTION"
        or replay["ready"] is not True
        or replay["native_agent_execution"] is not False
        or replay["consumer_chain"] != semantic.session_v1._CONSUMER_CHAIN
        or replay["baseline_loaded_entry_digest"]
        != "sha256:f66e8654ff8f917ef54c1cfd1297cc12a65d15461e58e9fbe90123d1f17c67b0"
        or replay["mutated_loaded_entry_digest"]
        != "sha256:8fb027d6063158ed3b761a11bf9c79bcd1372781af8dc4217960a93fb2fcac6e"
        or replay["non_skill_render_inputs_digest"]
        != "sha256:039ba750215bedd4a4663d67459c15649f30c4a12cd677aad13b28144d284c22"
        or _canonical_digest(replay["non_skill_render_inputs"])
        != replay["non_skill_render_inputs_digest"]
        or replay["baseline_report"] != compiled_report
        or replay["injected_report"] != compiled_report
        or resolver["baseline_should_refresh"] is not False
        or resolver["injected_should_refresh"] is not True
        or resolver["watch"] is not False
        or resolver_snapshot != resolver["injected_snapshot"]
        or resolver["baseline_snapshot_digest"]
        != "sha256:d885af2b80cd0426f882ae1b91225d51812c642b66bb0a48f145395e8294b46f"
        or _canonical_digest(resolver_snapshot) != resolver["baseline_snapshot_digest"]
        or resolver["injected_snapshot_digest"] != resolver["baseline_snapshot_digest"]
        or _canonical_digest(resolver["injected_snapshot"])
        != resolver["injected_snapshot_digest"]
        or resolver["baseline_prompt_digest"] != protected_digest
        or resolver["injected_prompt_digest"] != protected_digest
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
        or resolver_snapshot["version"] != resolver["baseline_snapshot_version"]
        or resolver["injected_snapshot"]["version"]
        != resolver["injected_snapshot_version"]
        or resolver["persisted_snapshot_version"]
        != resolver["baseline_snapshot_version"]
        or resolver["persisted_snapshot_version"]
        != initial["snapshot"]["metadata"]["version"]
        or replay["hydrated_inputs"]
        != {
            "baseline_prompt_digest": protected_digest,
            "injected_marker_count": 1,
            "injected_prompt_digest": attacker_digest,
        }
        or replay["baseline_render"] != replay["injected_render"]
        or replay["baseline_render"]["marker_count_in_skills_prompt"] != 0
        or replay["baseline_render"]["marker_count_in_system_prompt"] != 0
        or replay["baseline_render"]["skills_prompt"] != initial["prompt"]["exact_text"]
        or _digest(replay["baseline_render"]["skills_prompt"].encode())
        != protected_digest
        or _digest(replay["baseline_render"]["system_prompt"].encode())
        != "sha256:8d43c4a9b201ca59cc9fb6ef26a5684b42a88fe60c3e0f9a245924602f0b37d3"
        or marker in replay["baseline_render"]["skills_prompt"]
        or marker in replay["baseline_render"]["system_prompt"]
        or initial["prompt"]["digest"] != protected_digest
        or initial["entry"]["run_status"] != "timeout"
        or mutated["prompt"]["digest"] != attacker_digest
        or mutated["entry"]["run_status"] != "timeout"
        or marker not in mutated["prompt"]["exact_text"]
        or final["prompt"]["digest"] != protected_digest
        or final["entry"]["run_status"] != "timeout"
        or final["prompt"]["exact_text"] != initial["prompt"]["exact_text"]
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
        or mutation["changed_json_paths"]
        != [
            (
                "agent:main:aragorn-protected-session-snapshot-fixed-"
                f"{nonce}.skillsSnapshot.promptRef"
            )
        ]
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
            "after_digest": (
                "sha256:2636b5d2d0aaa88347affbbf67d82097912df96029818bd10fe3e28f7f68cd74"
            ),
            "before_digest": (
                "sha256:2636b5d2d0aaa88347affbbf67d82097912df96029818bd10fe3e28f7f68cd74"
            ),
            "exact_equal": True,
        }
        or mutation["blob"]
        != {**mutated["blob"], "exact_text": mutated["prompt"]["exact_text"]}
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
        or observations["initial_system_prompt_report"] != reports
        or observations["final_system_prompt_report"] != reports
    ):
        raise AdmissionEvidenceError(
            "V2 catalog-fixed session recovery semantics changed"
        )

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
            current.base.legacy._epoch_ms(mutation["completed_at"])
            <= int(baseline_copy["mtime_ns"]) // 1_000_000
            <= current.base.legacy._epoch_ms(
                observations["injected_turn"]["send"]["command"]["started_at"]
            )
        )
    ):
        raise AdmissionEvidenceError(
            "V2 catalog-fixed session compiled baseline copy changed"
        )

    for after_name, before_name in (
        ("boundary_after", "boundary_before"),
        ("config_after", "config_before"),
        ("config_lock_after", "config_lock_before"),
        ("config_tree_after", "config_tree_before"),
        ("gateway_process_after", "gateway_process_before"),
        ("openclaw_after", "openclaw_before"),
        ("protected_root_trees_after", "protected_root_trees_before"),
        ("runtime_tree_after", "runtime_tree_before"),
        ("target_after", "target_before"),
    ):
        if observations[after_name] != before[before_name]:
            raise AdmissionEvidenceError(
                "V2 catalog-fixed session protected state changed"
            )

    boundary = before["boundary_before"]
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or before["config_before"] != boundary["configuration"]
        or before["runtime_tree_before"] != current._RUNTIME_TREE
        or before["config_lock_before"]
        != {
            "exists": False,
            "path": (
                "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock"
            ),
        }
    ):
        raise AdmissionEvidenceError(
            "V2 catalog-fixed session current contract changed"
        )
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
    current._verify_version(before["version"])
    current._verify_system(
        before["system_info_before"], before["gateway_process_before"]
    )
    current._verify_system(
        observations["system_info_after"], observations["gateway_process_after"]
    )
    current._verify_system_stability(
        before["system_info_before"], observations["system_info_after"]
    )

    semantic._verify_module_files(replay["module_files"], closure_files)
    if tuple(closure_files) != ("manifest.json", *semantic._CLOSURE_PATHS):
        raise AdmissionEvidenceError("V2 catalog-fixed session closure paths changed")
    semantic._verify_source_bridges(replay["handoff_statements"], closure_files)
    semantic._verify_turn(observations["initial_turn"], "initial", nonce)
    semantic._verify_turn(observations["injected_turn"], "injected", nonce)

    expected_commands = [
        before["version"],
        before["system_info_before"]["command"],
        *observations["initial_turn"]["commands"],
        *observations["injected_turn"]["commands"],
        observations["system_info_after"]["command"],
    ]
    timing = observations["native_recovery_timing"]
    entry = final["entry"]
    if (
        action["commands"] != expected_commands
        or timing["ready"] is not True
        or not all(type(timing[key]) is int for key in timing if key != "ready")
        or timing["injected_send_started_at"]
        != current.base.legacy._epoch_ms(
            observations["injected_turn"]["send"]["command"]["started_at"]
        )
        or timing["injected_wait_ended_at"]
        != observations["injected_turn"]["wait"]["response"]["value"]["endedAt"]
        or timing["injected_wait_completed_at"]
        != current.base.legacy._epoch_ms(
            observations["injected_turn"]["wait"]["command"]["completed_at"]
        )
        or not (
            timing["injected_send_started_at"]
            <= entry["started_at"]
            <= entry["ended_at"]
            <= entry["updated_at"]
            <= timing["injected_wait_ended_at"]
            <= timing["injected_wait_completed_at"]
        )
        or timing["final_entry_started_at"] != entry["started_at"]
        or timing["final_entry_updated_at"] != entry["updated_at"]
        or timing["final_store_mtime_ms"]
        != int(final["store"]["mtime_ns"]) // 1_000_000
    ):
        raise AdmissionEvidenceError("V2 catalog-fixed session native timing changed")
    _verify_route_chronology(action, document["recorded_at"])


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
        or mutated_blob_mtime != mutated_store_mtime
        or re.fullmatch(r"[1-9][0-9]*", attacker_blob_mtime) is None
    ):
        raise AdmissionEvidenceError(
            "V2 catalog-fixed session command process sequence changed"
        )
    if not (
        parse(initial_turn["send"]["command"]["completed_at"])
        <= parse(initial_turn["wait"]["command"]["started_at"])
        <= parse(initial_turn["wait"]["command"]["completed_at"])
        < parse(mutation["started_at"])
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
            "V2 catalog-fixed session command chronology changed"
        )
    if not (
        epoch_ms(initial_turn["send"]["command"]["completed_at"])
        <= initial["entry"]["started_at"]
        <= initial["entry"]["ended_at"]
        <= int(initial["store"]["mtime_ns"]) // 1_000_000
        <= initial["entry"]["updated_at"]
        <= int(initial["blob"]["mtime_ns"]) // 1_000_000
        <= initial_turn["wait"]["response"]["value"]["endedAt"]
        <= epoch_ms(initial_turn["wait"]["command"]["completed_at"])
        <= int(mutated_store_mtime) // 1_000_000
        <= epoch_ms(mutation["completed_at"])
        < epoch_ms(injected_turn["send"]["command"]["started_at"])
        <= int(attacker_blob_mtime) // 1_000_000
        <= epoch_ms(injected_turn["send"]["command"]["completed_at"])
        <= final["entry"]["started_at"]
        <= final["entry"]["ended_at"]
        <= int(final["store"]["mtime_ns"]) // 1_000_000
        <= int(final["blob"]["mtime_ns"]) // 1_000_000
        <= final["entry"]["updated_at"]
        <= injected_turn["wait"]["response"]["value"]["endedAt"]
        <= epoch_ms(injected_turn["wait"]["command"]["completed_at"])
        <= epoch_ms(recorded_at)
    ):
        raise AdmissionEvidenceError(
            "V2 catalog-fixed session document chronology changed"
        )


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError(
                "V2 catalog-fixed session unexpected floating-point value"
            )
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key == "message_prefix_continuity_valid":
                if item is not None and type(item) is not bool:
                    raise AdmissionEvidenceError(
                        "V2 catalog-fixed session nullable boolean changed"
                    )
            elif isinstance(key, str) and (
                (key in _BOOLEAN_FIELDS) != (type(item) is bool)
            ):
                raise AdmissionEvidenceError(
                    "V2 catalog-fixed session boolean field type changed"
                )
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError(
                    "V2 catalog-fixed session boolean list item changed"
                )
            _verify_scalar_types(item, float_allowed=float_allowed)
