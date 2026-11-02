"""Derive one fresh-session PASS from the corrected current V2 contract."""

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

from . import admission_protected_final_combined_v2_config_activation as contract
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

old = contract.base

_ROUTE = "ADM-02/reload/fresh-session-reset"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_BASE = {
    "digest": "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6",
    "path": "src/aragorn/admission_protected_final_combined_v2_config_activation.py",
}
_EVIDENCE = {
    "bytes": 435_899,
    "canonical_bytes": 435_898,
    "canonical_digest": (
        "sha256:ca17e4d43d8ebb3ab6370fc08b95d470e6230f26c31204f8a10105840c6072bb"
    ),
    "digest": (
        "sha256:f804ea2ce5162e5b9317d544a0363d0b247844d6cfb07e4804cd0dc230986982"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "fresh-session-reset-systemd-p3-final-catalog-fixed-2026-08-22.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 25_070,
    "canonical_digest": (
        "sha256:bd1b8a0b72ad5fe697170a079365c6b0ee2f45967feeaf29aa34d78ac74463a2"
    ),
    "digest": (
        "sha256:5cd8a0622fb96bc7c1017360d07f1076b96c9a4a94a5d60e0f50a28c4bfcd219"
    ),
}
_SOURCE = {
    "commit": "1b13a8e4ff3f66f87cd26c34987e1e845c497028",
    "parent": "17d95091e87e9f41fdce4c096cb382fe04db4798",
    "tree": "74bdab4c4e283e5c196ada2191ef7aaca724f45e",
}
_RETENTION = {
    "commit": "9bc13769a9b71faf23012be993e615474934618d",
    "parent": _SOURCE["commit"],
    "tree": "1d1d15c686098613dd38ab58204ed3916605b0ee",
}
_RETENTION_BLOB = "7416b7ac60ea51487aa55f9c4b4207d637533f2c"
_IMAGE = "sha256:700ebe792d384cce37484f1838f05622b0518984f293f4d4c0cd28c6fb60f9d4"
_PARENT_IMAGE = contract._PARENT_IMAGE
_RUNTIME_VOLUME = contract._RUNTIME_VOLUME
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-64580"
_PROBE = {
    "bytes": 44_825,
    "digest": (
        "sha256:65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1"
    ),
    "name": "protected-route-probe.mjs",
}
_DIGESTS = {
    "action": "sha256:8c128b45276515e70b0cfce9bb0a34edc8b6cab02ec93d900eda1e1126fd9a4e",
    "composition": (
        "sha256:4b893e4de1121e37c5cd8ca4d8d1bb3626c310016bb1975270c75626e2d0bfbf"
    ),
    "composition_action": (
        "sha256:95feb17ad1ccce40be404b58d9d7989ce4f5bab66058b11fe6b6d933ff7f3ef4"
    ),
    "execution": (
        "sha256:06be09a2afa5e773b7cd891647d2015dcfd9caef4b8fd802585ffb0fba306230"
    ),
    "gateway_binding": (
        "sha256:566016753656e131c3c33219304613d5eb22e9c1ef1c1e425d1cfaf14f64b33d"
    ),
    "harness": (
        "sha256:3b0e7df044c630d1b3e775f62721126e10ea1ab82a93c39bda788ce615b13698"
    ),
    "host_config": (
        "sha256:e9c19a6a162ce95370a59ea442b7a3bb5c6205dff6701736734affe48a87699a"
    ),
    "image_lineage": (
        "sha256:a2d5cfc19644d5285878238bd22fc338ccef61df23c6d168e48c754790b5475f"
    ),
    "protected_boundary": (
        "sha256:f742d077218c5fd71a91b7a43db14799f819003c82f88098aa7c25e8c099aafd"
    ),
    "source_artifacts": (
        "sha256:39cec4e36e8518cac7007bd27c0d264d601033062fe57242528f37af65082473"
    ),
    "stack": "sha256:8af3d384e037bbde305c7979a40984d590cf82a440d1279f3fe3830603303eb3",
}
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_READY = old._READY
_UUID4 = old._UUID4


def verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 1/20 coverage without composing any other route PASS."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = old.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "catalog-fixed V2 fresh-session reset"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "catalog-fixed V2 reset CAS differs from signed retention"
            )
        evidence = old.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "catalog-fixed V2 fresh-session reset"
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
            f"invalid catalog-fixed V2 fresh-session evidence: {exc}"
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
            "aragorn/admission-protected-final-combined-v2-catalog-fixed-fresh-"
            "session-reset-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_CURRENT_CONTRACT_V2_RESET_ROUTE_ONLY"
        ),
        "bindings": {
            "configuration": dict(contract._SOURCES["configuration"]),
            "fresh_session_reset_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": old.legacy.parent._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(old.legacy.parent._SIGNATURE),
                },
            },
            "image": _IMAGE,
            "profile": dict(contract._SOURCES["profile"]),
            "runtime": dict(old.legacy.parent._RUNTIME),
            "runtime_lock": dict(contract._SOURCES["runtime_lock"]),
            "skill": dict(contract._SOURCES["skill"]),
            "source_artifacts": {
                **{
                    name: dict(identity)
                    for name, identity in contract._SOURCE_ARTIFACTS.items()
                },
                "probe_bundle": [dict(_PROBE)],
            },
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in old.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_FRESH_SESSION_RESET_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "CONFIG_ENTRY_ACTIVATION_PASS_NOT_COMPOSED",
            "PRIOR_FOUR_ROUTE_PASSES_NOT_COMPOSED_ACROSS_V2_CONFIG_CHANGE",
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
            "pass_basis": "SIGNED_EXACT_RESET_ROTATION_CLEAR_AND_REBUILD_TRANSITION",
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Any) -> str:
    return _digest(old.legacy.parent.oci_worker_protocol.canonical_json(value))


def _verify_dependencies() -> None:
    path = Path(contract.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_BASE["path"]).name
        or _digest(path.read_bytes()) != _BASE["digest"]
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset verifier base changed")
    contract._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    if (
        Path(
            old.legacy._git(["rev-parse", "--show-toplevel"]).decode().strip()
        ).resolve(strict=True)
        != root
        or old.legacy._git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset repository changed")
    old._verify_commit(_SOURCE)
    old._verify_commit(_RETENTION)
    entry = old.legacy._git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("catalog-fixed V2 reset signed tree changed")
    raw = old.legacy._git(["cat-file", "blob", _RETENTION_BLOB], maximum=512 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    contract._verify_scalar_types(
        {key: value for key, value in evidence.items() if key != "route_observation"}
    )
    contract._verify_no_positive_eligibility(evidence)
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
        or evidence["recorded_at"] != "2026-08-22T09:55:13.914185Z"
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
            **{key: False for key in old.legacy.parent._ELIGIBILITY_KEYS},
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
        raise AdmissionEvidenceError("catalog-fixed V2 reset wrapper changed")

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
        or observation["route"] != document["routes"][0]
        or observation["bundle"] != [_PROBE]
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset route custody changed")
    _verify_execution(
        observation,
        evidence["composition"]["action"]["boundaries"],
        harness,
    )
    _verify_transition(
        document,
        container_id=harness["container_id"],
        gateway_pid=observation["gateway_pid_binding"]["pid"],
        outer_recorded_at=evidence["recorded_at"],
    )
    if not (
        old.legacy._parse_time(document["recorded_at"])
        <= old.legacy._parse_time(observation["execution"]["completed_at"])
        <= old.legacy._parse_time(evidence["composition"]["recorded_at"])
        <= old.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset custody timing changed")
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
        or composition["recorded_at"] != "2026-08-22T09:55:13.914162Z"
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
            "runtime_digest": contract._RUNTIME_TREE["tree_digest"],
            "runtime_volume": _RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": contract._SOURCES["skill"]["digest"],
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
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset composition changed")

    action = composition["action"]
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    source = action["artifacts"]["final_combined_v2"]
    if (
        _canonical_digest(action) != _DIGESTS["composition_action"]
        or profile_before != profile_after
        or profile_before != source["profile"]
        or action["inputs"]["gateway_config"] != source["config"]["document"]
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(old.legacy.parent._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["runtime"]
        != {
            **old.legacy.parent._OPENCLAW,
            "name": "openclaw-protected-final-combined-v2",
        }
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset profile changed")
    contract._verify_configuration(source)
    _verify_source_artifacts(source_artifacts)
    _verify_harness(action["harness"], action["identities"], action["secret_checks"])
    if action["runtime"] != {
        "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "entrypoint_digest": old.legacy.parent._RUNTIME["entrypoint_digest"],
        "expected_version": old.legacy.parent._RUNTIME["version_output"],
        "root": "/runtime",
        "tree": contract._RUNTIME_TREE,
        "version_output": old.legacy.parent._RUNTIME["version_output"],
    }:
        raise AdmissionEvidenceError("catalog-fixed V2 reset runtime changed")
    return profile


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*contract._SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("catalog-fixed V2 reset source bundle changed")
    for name, identity in contract._SOURCE_ARTIFACTS.items():
        contract._verify_bound_file(
            value[name], identity, path=identity["path"], mode="0555"
        )
    if value["probe_bundle"] != [_PROBE]:
        raise AdmissionEvidenceError("catalog-fixed V2 reset probe changed")


def _verify_harness(
    envelope: Mapping[str, Any],
    identities: Mapping[str, Any],
    secret_checks: Mapping[str, Any],
) -> None:
    document = envelope["document"]
    raw_file = envelope["file"]
    raw = base64.b64decode(raw_file["base64"], validate=True)
    parsed = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=old.legacy.parent._reject_duplicates,
        parse_constant=old.legacy.parent._reject_constant,
    )
    canonical = old.legacy.parent.oci_worker_protocol.canonical_json(document)
    lineage = document["image_lineage"]
    host_config = document["host_config"]
    if (
        set(envelope) != {"digest", "document", "file"}
        or parsed != document
        or raw != canonical
        or envelope["digest"] != _DIGESTS["harness"]
        or _digest(raw) != _DIGESTS["harness"]
        or raw_file["bytes"] != len(raw)
        or raw_file["digest"] != _DIGESTS["harness"]
        or raw_file["path"] != "/run/aragorn-harness.json"
        or document["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or _canonical_digest(lineage) != _DIGESTS["image_lineage"]
        or not lineage["added_layers"]
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or lineage["child"]["rootfs_type"] != "layers"
        or lineage["parent"]["rootfs_type"] != "layers"
        or _canonical_digest(host_config) != _DIGESTS["host_config"]
        or host_config
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
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:64580",
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
                "io.aragorn.source-commit": old.legacy.parent._OPENCLAW["commit"],
                "io.aragorn.source-tree": old.legacy.parent._OPENCLAW["source_tree"],
            },
            "name": _RUNTIME_VOLUME,
            "options": None,
            "scope": "local",
        }
        or document["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or document["source_commit_verification"]["exit_code"] != 0
        or identities
        != {
            "broker": {"gid": 997, "uid": 995},
            "gateway": {"gid": 992, "uid": 992},
            "sensor": {"gid": 996, "uid": 996},
            "worker": {"gid": 997, "uid": 997},
        }
        or secret_checks
        != {
            "forbidden_driver_fields": [],
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
            "provider_and_gateway_token_values_retained": False,
        }
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset harness changed")
    stat = raw_file["stat"]
    if (
        stat["ctime_ns"] != stat["mtime_ns"]
        or stat["gid"] != 0
        or stat["uid"] != 0
        or stat["mode"] != "0600"
        or stat["nlink"] != 1
        or stat["size"] != len(raw)
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset harness file changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("catalog-fixed V2 reset raw wrapper changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=old.legacy.parent._reject_duplicates,
        parse_constant=old.legacy.parent._reject_constant,
    )
    canonical = old.legacy.parent.oci_worker_protocol.canonical_json(document)
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
        raise AdmissionEvidenceError("catalog-fixed V2 reset raw identity changed")
    return document


def _verify_execution(
    observation: Mapping[str, Any],
    boundaries: Mapping[str, Any],
    harness: Mapping[str, Any],
) -> None:
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
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
        _canonical_digest(execution) != _DIGESTS["execution"]
        or _canonical_digest(binding) != _DIGESTS["gateway_binding"]
        or _canonical_digest(stack) != _DIGESTS["stack"]
        or not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
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
            "/route-input/fresh-session-reset/protected-route-probe.mjs",
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
        or stack["processes"][gateway_unit]["pid"] != pid
        or stack["processes"][gateway_unit]["cmdline"] != ["openclaw-gateway"]
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
            old.legacy._parse_time(execution["started_at"])
            < old.legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset execution changed")


def _verify_transition(
    document: Mapping[str, Any],
    *,
    container_id: str,
    gateway_pid: int,
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
        or document["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["selected_route_ids"] != [_ROUTE]
        or document["implementation_digest"] != _PROBE["digest"]
        or document["runtime_binding"]
        != {
            "commit": old.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": old.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "version": old.legacy.parent._OPENCLAW["version"],
        }
        or document["routes"]
        != [
            {
                "action_id": "fresh-session-reset",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        or len(document["actions"]) != 1
        or _canonical_digest(document["actions"][0]) != _DIGESTS["action"]
        or not isinstance(document["run_nonce"], str)
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset route changed")
    _verify_protected_boundary(document["protected_boundary"])

    action = document["actions"][0]
    observed = action["observations"]
    before = observed["session_before_reset"]
    rotated = observed["session_after_rotation"]
    after = observed["session_after_reset"]
    reset = observed["reset_turn"]
    nonce = document["run_nonce"]
    before_id = before["entry"]["session_id"]
    after_id = after["entry"]["session_id"]
    if (
        action["id"] != "fresh-session-reset"
        or action["execution_error"] is not None
        or action["reason_codes"] != []
        or action["status"] != "OBSERVED"
        or _UUID4.fullmatch(before_id) is None
        or _UUID4.fullmatch(after_id) is None
        or before_id == after_id
        or observed["session_id_rotated"] is not True
        or observed["reset_snapshot_cleared"] is not True
        or observed["rebuilt_snapshot_matches_baseline"] is not True
        or rotated["entry"]["session_id"] != after_id
        or rotated["present"] is not True
        or rotated["entry"]["snapshot_present"] is not False
        or rotated["entry"]["skill_names"] != []
        or rotated["entry"]
        != {
            "ended_at": None,
            "prompt": {
                "bytes": None,
                "digest": None,
                "storage": "absent-or-invalid",
            },
            "runtime_ms": None,
            "session_id": after_id,
            "skill_names": [],
            "snapshot_present": False,
            "snapshot_version": None,
            "started_at": None,
            "status": None,
            "updated_at": rotated["entry"]["updated_at"],
        }
        or set(observed["session_before_reset_check"]) != _READY
        or any(
            item is not True for item in observed["session_before_reset_check"].values()
        )
        or set(observed["session_after_reset_check"]) != _READY
        or any(
            item is not True for item in observed["session_after_reset_check"].values()
        )
        or reset["accepted"] is not True
        or reset["error"] is not None
        or reset["method"] != "chat.send"
        or reset["params"]
        != {
            "deliver": False,
            "idempotencyKey": f"aragorn-protected-route-fresh-session-reset-{nonce}",
            "message": "/new",
            "sessionKey": old.legacy._SESSION_KEY,
            "timeoutMs": 5000,
        }
        or reset["response"]
        != {
            "runId": f"aragorn-protected-route-fresh-session-reset-{nonce}",
            "status": "started",
        }
        or reset["scopes"] != ["operator.admin", "operator.write"]
        or reset["transport"]
        != "openclaw/plugin-sdk/gateway-runtime.callGatewayFromCli"
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset semantics changed")

    initial = observed["initialization_turn"]
    rebuild = observed["rebuild_turn"]
    _verify_prerequisites(
        action["prerequisites"], container_id=container_id, gateway_pid=gateway_pid
    )
    old.legacy._verify_turn(
        initial,
        label="fresh-session-initialize",
        nonce=nonce,
        pids=(initial["send"]["command"]["pid"], initial["wait"]["command"]["pid"]),
    )
    old.legacy._verify_turn(
        rebuild,
        label="fresh-session-rebuild",
        nonce=nonce,
        pids=(rebuild["send"]["command"]["pid"], rebuild["wait"]["command"]["pid"]),
    )
    commands = (
        action["prerequisites"]["commands"] + initial["commands"] + rebuild["commands"]
    )
    if (
        action["commands"] != initial["commands"] + rebuild["commands"]
        or any(
            type(command["pid"]) is not int or command["pid"] <= 1
            for command in commands
        )
        or len({command["pid"] for command in commands}) != len(commands)
        or any(
            old.legacy._parse_time(left["completed_at"])
            > old.legacy._parse_time(right["started_at"])
            for left, right in pairwise(commands)
        )
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset command custody changed")

    before_entry = before["entry"]
    after_entry = after["entry"]
    prompt = before_entry["prompt"]
    old._verify_snapshot(before, session_id=before_id)
    old._verify_snapshot(after, session_id=after_id)
    old._verify_store_file(rotated["file"])
    if (
        before["present"] is not True
        or after["present"] is not True
        or before_entry["snapshot_present"] is not True
        or after_entry["snapshot_present"] is not True
        or before_entry["skill_names"] != ["template-skill"]
        or before_entry["skill_names"] != after_entry["skill_names"]
        or before_entry["snapshot_version"] != after_entry["snapshot_version"]
        or before_entry["prompt"] != after_entry["prompt"]
        or prompt["storage"] != "promptRef"
        or prompt["digest"] != prompt["expected_digest"]
        or prompt["digest"] != old._PROMPT_DIGEST
        or len(
            {before["file"]["inode"], rotated["file"]["inode"], after["file"]["inode"]}
        )
        != 3
        or len(
            {
                before["file"]["digest"],
                rotated["file"]["digest"],
                after["file"]["digest"],
            }
        )
        != 3
        or not (
            old.legacy._parse_time(initial["wait"]["command"]["completed_at"])
            <= old.legacy._parse_time(reset["started_at"])
            <= old.legacy._parse_time(reset["completed_at"])
            <= old.legacy._parse_time(observed["rotation_observed_at"])
            <= old.legacy._parse_time(rebuild["send"]["command"]["started_at"])
            < old.legacy._parse_time(rebuild["wait"]["command"]["completed_at"])
            <= old.legacy._parse_time(document["recorded_at"])
            < old.legacy._parse_time(outer_recorded_at)
        )
        or not (
            old.legacy._epoch_ms(initial["send"]["command"]["completed_at"])
            <= before_entry["started_at"]
            <= before_entry["ended_at"]
            <= before_entry["updated_at"]
            <= initial["wait"]["response"]["value"]["endedAt"]
            <= old.legacy._epoch_ms(initial["wait"]["command"]["completed_at"])
        )
        or not (
            old.legacy._epoch_ms(reset["completed_at"])
            <= rotated["entry"]["updated_at"]
            <= old.legacy._epoch_ms(observed["rotation_observed_at"])
        )
        or not (
            old.legacy._epoch_ms(rebuild["send"]["command"]["completed_at"])
            <= after_entry["started_at"]
            <= after_entry["ended_at"]
            <= after_entry["updated_at"]
            <= rebuild["wait"]["response"]["value"]["endedAt"]
            <= old.legacy._epoch_ms(rebuild["wait"]["command"]["completed_at"])
            <= old.legacy._epoch_ms(document["recorded_at"])
        )
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset snapshot custody changed")


def _verify_protected_boundary(value: Mapping[str, Any]) -> None:
    configuration = value["configuration"]
    config_file = configuration["file"]
    config_mount = configuration["mount"]
    runtime = value["runtime"]
    if (
        _canonical_digest(value) != _DIGESTS["protected_boundary"]
        or value["effective_identity"] != {"gid": 992, "uid": 992}
        or value["ready"] is not True
        or configuration["canonical_digest"]
        != contract._SOURCES["configuration"]["canonical_digest"]
        or configuration["expected_canonical_digest"]
        != contract._SOURCES["configuration"]["canonical_digest"]
        or configuration["json_object"] is not True
        or configuration["parse_error"] is not None
        or configuration["ready"] is not True
        or config_file["path"] != contract._CONFIG_PATH
        or config_file["exists"] is not True
        or config_file["type"] != "file"
        or config_file["digest"]
        != contract._SOURCES["configuration"]["canonical_digest"]
        or config_file["size"] != contract._SOURCES["configuration"]["canonical_bytes"]
        or config_file["uid"] != 992
        or config_file["gid"] != 0
        or config_file["mode"] != "400"
        or config_file["nlink"] != 1
        or config_mount["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or config_mount["explicit"] is not True
        or config_mount["read_only"] is not True
        or config_mount["ready"] is not True
        or len(config_mount["records"]) != 1
        or "ro" not in config_mount["records"][0]["mount_options"]
        or runtime["path"] != "/runtime"
        or runtime["explicit"] is not True
        or runtime["read_only"] is not True
        or runtime["ready"] is not True
        or len(runtime["records"]) != 1
        or runtime["records"][0]["mount_point"] != "/runtime"
        or _RUNTIME_VOLUME not in runtime["records"][0]["root"]
        or "ro" not in runtime["records"][0]["mount_options"]
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset boundary changed")
    root_paths = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    if set(value["roots"]) != set(root_paths):
        raise AdmissionEvidenceError("catalog-fixed V2 reset roots changed")
    for name, path in root_paths.items():
        root = value["roots"][name]
        entry = root["observation"]
        if (
            root["ready"] is not True
            or root["writable"] is not True
            or entry["path"] != path
            or entry["type"] != "directory"
            or entry["uid"] != 992
            or entry["gid"] != 992
            or entry["mode"] != "700"
            or entry["entries"] != []
            or entry["entry_count"] != 0
            or entry["entries_truncated"] is not False
        ):
            raise AdmissionEvidenceError("catalog-fixed V2 reset root changed")


def _verify_prerequisites(
    value: Mapping[str, Any], *, container_id: str, gateway_pid: int
) -> None:
    commands = value["commands"]
    gateway = value["gateway_process"]
    runtime = value["runtime_files"]
    system = value["system_info"]
    if (
        value["ready"] is not True
        or value["reason_codes"] != []
        or gateway["pid"] != gateway_pid
        or gateway["hostname"] != container_id[:12]
        or gateway["cmdline"] != ["openclaw-gateway"]
        or len(commands) != 2
        or system["command"] != commands[1]
        or system["response"]["parsed"] is not True
        or system["response"]["value"]["pid"] != gateway_pid
        or system["response"]["value"]["hostname"] != gateway["hostname"]
        or system["response"]["value"]["machineName"] != gateway["hostname"]
        or system["response"]["value"]["diskPath"]
        != "/var/lib/aragorn-agent-gateway/state"
        or runtime["node"]["executable"] is not True
        or runtime["node"]["file"]["path"] != "/usr/local/bin/node"
        or runtime["node"]["file"]["uid"] != 0
        or runtime["node"]["file"]["gid"] != 0
        or runtime["openclaw"]["executable"] is not True
        or runtime["openclaw"]["file"]["path"]
        != "/runtime/lib/node_modules/openclaw/openclaw.mjs"
        or runtime["openclaw"]["file"]["digest"]
        != old.legacy.parent._RUNTIME["entrypoint_digest"]
        or runtime["openclaw"]["file"]["uid"] != 0
        or runtime["openclaw"]["file"]["gid"] != 0
    ):
        raise AdmissionEvidenceError("catalog-fixed V2 reset prerequisites changed")
    old.legacy._verify_command(
        commands[0],
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ],
        expected_pid=commands[0]["pid"],
        stdout_exact=old.legacy.parent._RUNTIME["version_output"] + "\n",
    )
    old.legacy._verify_command(
        commands[1],
        old.legacy._gateway_argv("system.info", "5000"),
        expected_pid=commands[1]["pid"],
        stdout_value=system["response"]["value"],
    )
