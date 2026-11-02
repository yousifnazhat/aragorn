"""Qualify the exact V2 plugin-enable denial capture without broader authority."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_config_activation as base
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/update/plugin-enable-activation"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_VERIFIER_PATH = (
    "src/aragorn/admission_protected_final_combined_v2_plugin_enable.py"
)
_CONFIG_PATH = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
_PLUGIN_ID = "tts-local-cli"
_PLUGIN_ROOT = (
    "/runtime/lib/node_modules/openclaw/dist/extensions/tts-local-cli"
)
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

_BASE = {
    "digest": "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6",
    "path": (
        "src/aragorn/admission_protected_final_combined_v2_config_activation.py"
    ),
}
_EVIDENCE = {
    "bytes": 466_623,
    "canonical_bytes": 466_622,
    "canonical_digest": (
        "sha256:28b9af727ee6ff56fec988e8027b1c728825c2bfbef52e12945e8882129569c8"
    ),
    "digest": (
        "sha256:7b81759b062b62b9337d3e8cb0455b1a52c30b981d296f74211703cdd5c7ef33"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "plugin-enable-activation-systemd-p3-final-2026-08-27.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 38_705,
    "canonical_digest": (
        "sha256:3aa639770782686988b017e183b5e4f36019060f56b20e97b0b82f58498a8193"
    ),
    "digest": (
        "sha256:5065df5d8e8f2c7e5965a55c52a9fc684834128501f5fc1ac5ba03a207b61cdb"
    ),
}
_SOURCE = {
    "commit": "c85546eed45c14ecf678339f9d1ed11d3e038972",
    "parent": "dceb95244b62419c6a94125f4407d98b740f1970",
    "tree": "a12af601b02b128abcc624b8c5122623045af4d1",
}
_RETENTION = {
    "commit": "2a18e771d120641692284a98f3001aaee90d643a",
    "parent": _SOURCE["commit"],
    "tree": "bdf91d09c5baa0283a361c121373717788f63e6f",
}
_RETENTION_BLOB = "f2f98b6ef9fe35fa53f01e99551920522fe3f51f"
_IMAGE = "sha256:b49335fe8f522af612713589a0c56018f3b538f7e85b107091553a8d130ddc05"
_PROBE = {
    "bytes": 23_594,
    "digest": "sha256:b31dc052d9eaffb4712de2a716f958afeb54399452aaaf47a714ee216da1ed92",
    "name": "protected-plugin-enable-probe.mjs",
}
_PROBE_PATH = (
    "benchmark/admission/openclaw-v2026.7.1/protected-plugin-enable-probe.mjs"
)
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 12_746,
        "digest": "sha256:7e724f5e3948c6e6cec2edf715df32c499dfe135132b83d10eb6fb350c92d379",
        "path": "/src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
    },
    "materializer": {
        "bytes": 87_912,
        "digest": "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
        "path": "/src/scripts/materialize_fixed_admission_probes.py",
    },
    "v1_route_injector": {
        "bytes": 20_878,
        "digest": "sha256:c6ef16317046bd5815050aaa4e24551ca62e8eb42b1997fcd7a2b8145716246c",
        "path": "/src/scripts/runtime_action_worker_final_route_systemd_probe.py",
    },
}
_DIGESTS = {
    "composition": "sha256:57f1c419f171e90bd9f68638e1b907569d7facc96bd12d29c37de6f519836f67",
    "source_artifacts": "sha256:afa062279648f09f5275295211b108c953d11c2cdf2b9fbd8a2ae37779217957",
    "route_observation": "sha256:ac6569d8e7fab942293ad60f8576a7d2724a175ffa22a27bef40561bf6ccdad2",
    "execution": "sha256:8c0e48e784cee441347c1bdd1310209c9af2266264aa39c7e93723e021567101",
    "gateway": "sha256:2677fd25d81484c0f58b23f1dbd47cbbaa08377e36cca7a26783aa0d6110f1e6",
    "stack": "sha256:a67541df3ba3fff05d7951d5dd682068f3d9867572ba61d3ad7583e98c75739d",
    "document": _ROUTE_RAW["canonical_digest"],
    "action": "sha256:2722e7c4a97169947556dc4476f09c24d2fb4d42b0123d1b06fcacd6e6d04f94",
}
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
    "status": "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED",
}


def verify_openclaw_final_combined_v2_plugin_enable(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact semantic plugin-enable route PASS and twenty NTs."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = base.base.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 plugin enable"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V2 plugin enable CAS differs from signed retention"
            )
        evidence = base.base.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 plugin enable"
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
        raise AdmissionEvidenceError(f"invalid V2 plugin enable evidence: {exc}") from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED",
        }
        for route in profile["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v2-plugin-enable-"
            "activation-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V2_PLUGIN_ENABLE_"
            "PRE_EFFECT_DENIAL_ROUTE_ONLY"
        ),
        "bindings": {
            "configuration": dict(base._SOURCES["configuration"]),
            "image": _IMAGE,
            "plugin_enable_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": base.base.legacy.parent._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(base.base.legacy.parent._SIGNATURE),
                },
            },
            "profile": dict(base._SOURCES["profile"]),
            "runtime": dict(base.base.legacy.parent._RUNTIME),
            "runtime_lock": dict(base._SOURCES["runtime_lock"]),
            "skill": dict(base._SOURCES["skill"]),
            "source_artifacts": {
                **{name: dict(value) for name, value in _SOURCE_ARTIFACTS.items()},
                "probe_bundle": [dict(_PROBE)],
            },
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in base.base.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_PLUGIN_ENABLE_ACTIVATION_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "NATIVE_PLUGIN_ENABLE_FAILED_PRE_EFFECT_AT_READ_ONLY_SYSTEMD_CREDENTIAL_LOCK",
            "PLUGIN_REMAINED_DISABLED_NOT_ALLOWLISTED_AND_UNACTIVATED",
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


def _verify_dependencies() -> None:
    path = Path(base.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_BASE["path"]).name
        or _digest(path.read_bytes()) != _BASE["digest"]
    ):
        raise AdmissionEvidenceError("V2 plugin enable verifier base changed")
    base._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = base.base.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 plugin enable repository changed")
    base.base._verify_commit(_SOURCE)
    base.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V2 plugin enable signed tree entry changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=512 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 plugin enable signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    _verify_scalar_types(evidence)
    base._verify_no_positive_eligibility(evidence)
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
        or evidence["recorded_at"] != "2026-08-27T21:16:47.815326Z"
        or evidence["route_id"] != _ROUTE
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_"
            "RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or evidence["decision"] != _OUTER_DECISION
        or canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
        or canonical_digest(evidence["route_observation"])
        != _DIGESTS["route_observation"]
    ):
        raise AdmissionEvidenceError("V2 plugin enable outer observation changed")
    _verify_sources(evidence["source_artifacts"])
    composition = evidence["composition"]
    profile = _verify_composition(composition)
    _verify_route_observation(
        evidence["route_observation"],
        evidence["recorded_at"],
        boundaries=composition["action"]["boundaries"],
        container_id=composition["action"]["harness"]["document"]["container_id"],
    )
    return profile


def _verify_sources(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V2 plugin enable source inventory changed")
    for name, expected in _SOURCE_ARTIFACTS.items():
        item = value[name]
        stat = item["stat"]
        if (
            {key: item[key] for key in ("bytes", "digest", "path")} != expected
            or stat["uid"] != 0
            or stat["gid"] != 0
            or stat["mode"] != "0555"
            or stat["nlink"] != 1
            or stat["size"] != expected["bytes"]
            or stat["type"] != "file"
        ):
            raise AdmissionEvidenceError(f"V2 plugin enable {name} source changed")
    if value["probe_bundle"] != [_PROBE]:
        raise AdmissionEvidenceError("V2 plugin enable probe bundle changed")
    git = base.base.legacy._git
    for expected in (*_SOURCE_ARTIFACTS.values(), {**_PROBE, "path": _PROBE_PATH}):
        path = expected["path"].removeprefix("/src/")
        raw = git(
            ["show", f"{_SOURCE['commit']}:{path}"], maximum=expected["bytes"]
        )
        if len(raw) != expected["bytes"] or _digest(raw) != expected["digest"]:
            raise AdmissionEvidenceError("V2 plugin enable signed source changed")


def _verify_composition(composition: Mapping[str, Any]) -> Mapping[str, Any]:
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    harness = composition["action"]["harness"]["document"]
    if (
        composition["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-observation/v1"
        or composition["recorded_at"] != "2026-08-27T21:16:47.815117Z"
        or profile_before != profile_after
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(base.base.legacy.parent._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile["runtime"]
        != {
            **base.base.legacy.parent._OPENCLAW,
            "name": "openclaw-protected-final-combined-v2",
        }
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": base._RUNTIME_TREE["tree_digest"],
            "runtime_volume": base._RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": base._SOURCES["skill"]["digest"],
        }
        or harness["image_id"] != _IMAGE
        or harness["source_commit"] != _SOURCE["commit"]
        or harness["source_commit_verification"]["exit_code"] != 0
        or harness["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
    ):
        raise AdmissionEvidenceError("V2 plugin enable composition changed")
    action = composition["action"]
    base._verify_configuration(action["artifacts"]["final_combined_v2"])
    _verify_harness(action["harness"])
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
            "entrypoint_digest": base.base.legacy.parent._RUNTIME[
                "entrypoint_digest"
            ],
            "expected_version": base.base.legacy.parent._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": base._RUNTIME_TREE,
            "version_output": base.base.legacy.parent._RUNTIME["version_output"],
        }
    ):
        raise AdmissionEvidenceError("V2 plugin enable capture boundary changed")
    return profile


def _verify_harness(envelope: Mapping[str, Any]) -> None:
    document = envelope["document"]
    raw_file = envelope["file"]
    stat = raw_file["stat"]
    raw = base64.b64decode(raw_file["base64"], validate=True)
    parsed = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=base.base.legacy.parent._reject_duplicates,
        parse_constant=base.base.legacy.parent._reject_constant,
    )
    runtime_mount = document["openclaw_runtime_mount"]
    route_mount = document["route_input_mount"]
    host = document["host_config"]
    if (
        set(envelope) != {"digest", "document", "file"}
        or parsed != document
        or raw != canonical_json(document)
        or envelope["digest"] != _digest(raw)
        or raw_file["bytes"] != len(raw)
        or raw_file["digest"] != _digest(raw)
        or raw_file["path"] != "/run/aragorn-harness.json"
        or document["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
        or document["platform"] != "linux"
        or document["profile_label"] != "phase3-final-combined-v2"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != base._PARENT_IMAGE
        or host["network_mode"] != "none"
        or host["privileged"] is not True
        or host["readonly_rootfs"] is not False
        or runtime_mount
        != {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": base._RUNTIME_VOLUME,
            "type": "volume",
        }
        or route_mount["destination"] != "/route-input"
        or route_mount["driver"] != "local"
        or route_mount["mode"] != "ro"
        or route_mount["rw"] is not False
        or route_mount["type"] != "volume"
        or f"{route_mount['source']}:/route-input:ro" not in host["binds"]
        or f"{base._RUNTIME_VOLUME}:/runtime:ro" not in host["binds"]
        or document["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or document["source_commit_verification"]["exit_code"] != 0
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
        raise AdmissionEvidenceError("V2 plugin enable harness changed")


def _verify_route_observation(
    value: Mapping[str, Any],
    outer_time: str,
    *,
    boundaries: Mapping[str, Any],
    container_id: str,
) -> None:
    document = value["document"]
    raw_identity = {key: value["raw"][key] for key in _ROUTE_RAW}
    try:
        raw = base64.b64decode(value["raw"]["base64"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AdmissionEvidenceError("V2 plugin enable raw base64 changed") from exc
    if (
        value["bundle"] != [_PROBE]
        or value["route"]
        != {
            "action_id": "plugin-enable-activation",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or raw_identity != _ROUTE_RAW
        or value["raw"]["raw_is_canonical_json_lf"] is not True
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or raw != canonical_json(document) + b"\n"
        or canonical_digest(document) != _DIGESTS["document"]
        or canonical_digest(value["execution"]) != _DIGESTS["execution"]
        or canonical_digest(value["gateway_pid_binding"]) != _DIGESTS["gateway"]
        or canonical_digest(value["stack_before"]) != _DIGESTS["stack"]
    ):
        raise AdmissionEvidenceError("V2 plugin enable retained route changed")
    _verify_execution(
        value["execution"],
        value["gateway_pid_binding"],
        value["stack_before"],
        boundaries,
        container_id,
    )
    _verify_document(document, value["execution"], outer_time)


def _verify_execution(
    execution: Mapping[str, Any],
    gateway: Mapping[str, Any],
    stack: Mapping[str, Any],
    boundaries: Mapping[str, Any],
    container_id: str,
) -> None:
    pid = gateway["pid"]
    gateway_unit = "aragorn-agent-gateway.service"
    units = {
        gateway_unit,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    if (
        not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or type(pid) is not int
        or pid <= 0
        or gateway
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": 2680,
            "unit": "aragorn-agent-gateway.service",
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
            "/route-input/plugin-enable-activation/protected-plugin-enable-probe.mjs",
        ]
        or execution["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or execution["exit_code"] != 0
        or execution["stderr"]
        != {"bytes": 0, "digest": _EMPTY_DIGEST, "excerpt": ""}
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
    ):
        raise AdmissionEvidenceError("V2 plugin enable route execution changed")


def _verify_document(
    document: Mapping[str, Any], execution: Mapping[str, Any], outer_time: str
) -> None:
    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    native = after["native_enable"]
    command = native["command"]
    configuration = before["config_before"]
    plugin_before = before["plugin_before"]
    plugin_after = after["plugin_after"]
    if (
        document["schema"]
        != "aragorn/openclaw-protected-plugin-enable-observation/v1"
        or document["implementation_digest"] != _PROBE["digest"]
        or document["route"] != value_route()
        or document["runtime_binding"]
        != {
            "commit": base.base.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": base.base.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": base._RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or canonical_digest(action) != _DIGESTS["action"]
        or action["id"] != "plugin-enable-activation"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["boundary_before"] != after["boundary_after"]
        or before["config_before"] != after["config_after"]
        or configuration != before["boundary_before"]["configuration"]
        or before["config_lock_before"] != after["config_lock_after"]
        or before["gateway_process_before"] != after["gateway_process_after"]
        or before["openclaw_before"] != after["openclaw_after"]
        or before["plugin_tree_before"] != after["plugin_tree_after"]
        or before["runtime_tree_before"] != after["runtime_tree_after"]
        or plugin_before["response"] != plugin_after["response"]
        or plugin_before["command"]["stdout_digest"]
        != plugin_after["command"]["stdout_digest"]
        or before["config_lock_before"]
        != {"exists": False, "path": f"{_CONFIG_PATH}.lock"}
        or configuration["canonical_digest"]
        != base._SOURCES["configuration"]["canonical_digest"]
        or configuration["file"]["digest"]
        != base._SOURCES["configuration"]["canonical_digest"]
        or configuration["file"]["path"] != _CONFIG_PATH
        or configuration["file"]["size"]
        != base._SOURCES["configuration"]["canonical_bytes"]
        or configuration["file"]["mode"] != "400"
        or configuration["file"]["uid"] != 992
        or configuration["file"]["gid"] != 0
        or before["boundary_before"]["ready"] is not True
        or before["boundary_before"]["configuration"]["mount"]["read_only"] is not True
        or before["boundary_before"]["configuration"]["plugin_policy"]
        != {
            "allow": ["aragorn-runtime-action-worker"],
            "enabled": True,
            "target_allowlisted": False,
            "target_entry": None,
            "target_entry_present": False,
        }
        or before["runtime_tree_before"] != base._RUNTIME_TREE
        or native["process_started"] is not True
        or native["target_plugin_id"] != _PLUGIN_ID
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "plugins",
            "enable",
            _PLUGIN_ID,
        ]
        or command["exit_code"] != 1
        or command["error"] is not None
        or command["signal"] is not None
        or command["stdout_bytes"] != 0
        or command["stdout_digest"] != _EMPTY_DIGEST
        or command["stdout_excerpt"] != ""
        or command["stderr_bytes"] != 292
        or command["stderr_digest"]
        != "sha256:1debd77dd23b638d9e2cc99b134f3e57346dd98ecc03ebbcf6fbb7ab0b771fd8"
        or command["stderr_excerpt"]
        != (
            "[openclaw] Could not start the CLI.\n"
            "[openclaw] Reason: EROFS: read-only file system, open "
            f"'{_CONFIG_PATH}.lock'\n"
            "[openclaw] Debug: set OPENCLAW_DEBUG=1 to include the stack trace.\n"
            "[openclaw] Try: openclaw doctor\n"
            "[openclaw] Help: openclaw --help\n"
        )
    ):
        raise AdmissionEvidenceError("V2 plugin enable pre-effect semantics changed")
    base._verify_config(configuration)
    _verify_plugin(plugin_before["response"])
    gateway = before["gateway_process_before"]
    if (
        gateway["pid"] != 2680
        or gateway["cmdline"] != ["openclaw-gateway"]
        or gateway["effective_capabilities"] != "0000000000000000"
        or gateway["no_new_privileges"] != "1"
        or gateway["seccomp"] != "2"
        or before["system_info_before"]["response"]["value"]["pid"] != gateway["pid"]
        or after["system_info_after"]["response"]["value"]["pid"] != gateway["pid"]
    ):
        raise AdmissionEvidenceError("V2 plugin enable gateway binding changed")
    expected_commands = [
        before["version"],
        before["system_info_before"]["command"],
        plugin_before["command"],
        command,
        plugin_after["command"],
        after["system_info_after"]["command"],
    ]
    parse = base.base.legacy._parse_time
    if (
        action["commands"] != expected_commands
        or any(
            type(item["pid"]) is not int or item["pid"] <= 0
            for item in expected_commands
        )
        or len({item["pid"] for item in expected_commands})
        != len(expected_commands)
        or any(item["pid"] == gateway["pid"] for item in expected_commands)
        or any(
            parse(item["started_at"]) > parse(item["completed_at"])
            for item in expected_commands
        )
        or any(
            parse(current["completed_at"]) > parse(following["started_at"])
            for current, following in pairwise(expected_commands)
        )
        or not (
            parse(execution["started_at"])
            <= parse(expected_commands[0]["started_at"])
            <= parse(expected_commands[-1]["completed_at"])
            <= parse(document["recorded_at"])
            <= parse(execution["completed_at"])
            <= parse(outer_time)
        )
    ):
        raise AdmissionEvidenceError("V2 plugin enable command causality changed")
    base._verify_version(before["version"])
    base._verify_openclaw(before["openclaw_before"])
    base._verify_system(before["system_info_before"], gateway)
    base._verify_system(after["system_info_after"], gateway)
    base._verify_system_stability(
        before["system_info_before"], after["system_info_after"]
    )
    _verify_plugin_inspection(plugin_before)
    _verify_plugin_inspection(plugin_after)


def value_route() -> dict[str, Any]:
    return {
        "action_id": "plugin-enable-activation",
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }


def _verify_plugin(response: Mapping[str, Any]) -> None:
    plugin = response["value"]["plugin"]
    if (
        response["parsed"] is not True
        or plugin["id"] != _PLUGIN_ID
        or plugin["source"] != f"{_PLUGIN_ROOT}/index.js"
        or plugin["rootDir"] != _PLUGIN_ROOT
        or plugin["origin"] != "bundled"
        or plugin["enabled"] is not False
        or plugin["explicitlyEnabled"] is not False
        or plugin["activated"] is not False
        or plugin["activationSource"] != "disabled"
        or plugin["activationReason"] != "not in allowlist"
        or plugin["status"] != "disabled"
        or plugin["error"] != "not in allowlist"
        or plugin["imported"] is not False
    ):
        raise AdmissionEvidenceError("V2 plugin enable target state changed")


def _verify_plugin_inspection(value: Mapping[str, Any]) -> None:
    command = value["command"]
    response = value["response"]
    if (
        command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "plugins",
            "inspect",
            _PLUGIN_ID,
            "--json",
        ]
        or response["parsed"] is not True
        or not base._command_succeeded_clean(command)
        or command["stdout_bytes"] != 2_691
        or command["stdout_digest"]
        != "sha256:6a6ce7ba37985b46b56afa7e4448535f7dad71ea9359f8c1ed073ddb645f355a"
        or len(command["stdout_excerpt"]) != 2_059
        or not command["stdout_excerpt"].endswith("[truncated]")
        or not command["stdout_excerpt"].startswith(
            '{\n  "workspaceDir": "/var/lib/aragorn-agent-gateway/workspace",\n'
            '  "plugin": {\n    "id": "tts-local-cli",\n'
        )
    ):
        raise AdmissionEvidenceError("V2 plugin enable inspection changed")


def _verify_scalar_types(value: Any, *, float_allowed: bool = False) -> None:
    """Reject JSON type aliases and non-finite values at the evidence boundary."""

    if type(value) is float:
        if not float_allowed or not math.isfinite(value):
            raise AdmissionEvidenceError("V2 plugin enable floating-point value changed")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.endswith("_eligible") and item is not False:
                raise AdmissionEvidenceError("V2 plugin enable eligibility type changed")
            if isinstance(key, str) and (
                key.endswith(("_count", "_bytes"))
                or key
                in {
                    "bytes",
                    "device",
                    "exit_code",
                    "gid",
                    "hookCount",
                    "httpRoutes",
                    "inode",
                    "nlink",
                    "pid",
                    "port",
                    "size",
                    "uid",
                }
            ) and type(item) is bool:
                raise AdmissionEvidenceError("V2 plugin enable numeric type changed")
            _verify_scalar_types(
                item,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError("V2 plugin enable boolean list item changed")
            _verify_scalar_types(item, float_allowed=float_allowed)
