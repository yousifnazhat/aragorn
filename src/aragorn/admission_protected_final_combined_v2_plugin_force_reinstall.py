"""Qualify one exact V2 plugin force-reinstall route failure."""

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

from . import admission_protected_final_combined_v2_plugin_enable as parent
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

config = parent.base
contract = config.base.legacy.parent

_ROUTE = "ADM-02/update/plugin-force-reinstall"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_PLUGIN_ID = "aragorn-force-reinstall-fixture"
_TARGET = f"/var/lib/aragorn-agent-gateway/state/extensions/{_PLUGIN_ID}"
_SOURCE_ROOT = "/route-input/plugin-force-reinstall/candidate-source"
_CONFIG = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_VERIFIER_PATH = (
    "src/aragorn/admission_protected_final_combined_v2_plugin_force_reinstall.py"
)

_BASE = {
    "digest": "sha256:4992378c9ed3d538b82a1e8e836eb45cf2b931b067069a0c04a2c7c76206ef4d",
    "path": "src/aragorn/admission_protected_final_combined_v2_plugin_enable.py",
}
_EVIDENCE = {
    "bytes": 515_143,
    "canonical_bytes": 515_142,
    "canonical_digest": (
        "sha256:34414a8d14a37efaa1cba0f0e977fcc8f68e4fc00ddc3896a705ea46299a9af2"
    ),
    "digest": (
        "sha256:b0d0679c4738ecdb317ec644124b4829d276c1f2a25ef8fec04633764c8ca4e4"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-plugin-"
        "force-reinstall-systemd-p3-final-2026-08-28.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 59_388,
    "canonical_digest": (
        "sha256:0b8729b22556cae3e13276f0cda5591214ef5d148db73174c79dd5f146410880"
    ),
    "digest": (
        "sha256:35d54fe148d8a81659c8478f63247cda7645c0a64d418e13fdfad121d0e5b99b"
    ),
}
_SOURCE = {
    "commit": "ab0efc995baf1fc43a951b3939496f387532fcf6",
    "parent": "a4e66d837460e556097103ebba37ab4d5850ce64",
    "tree": "9458326ea0fbcdb512f7355a20c51115e2b9d9d7",
}
_RETENTION = {
    "commit": "e4e487c77117bfd00e4b45648631c686c2a3c52c",
    "parent": _SOURCE["commit"],
    "tree": "f208dbd5a22faa653ccaffd6d299ca1ea8dc3185",
}
_RETENTION_BLOB = "9aefd82f5623014cd556085592235052f2882d3e"
_IMAGE = "sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b"
_PROBE = {
    "bytes": 26_836,
    "digest": "sha256:6b4adf647cef823f5cfee73d0130c06ab4612e37fb704246a56fe4dca03c0bbe",
    "name": "protected-plugin-force-reinstall-probe.py",
    "role": "probe",
}
_FIXTURES = (
    {
        "bytes": 122,
        "digest": "sha256:631cc6f036f3cdf2f8fa6c814a27da075bf8c37fd2fe3681a55f7f5e593dd4ea",
        "name": "baseline-source/index.js",
        "role": "fixture",
    },
    {
        "bytes": 179,
        "digest": "sha256:9b93a70d606ec63c32d15dd9021dc603df9bdf680b74789c675f5227c1c6b077",
        "name": "baseline-source/openclaw.plugin.json",
        "role": "fixture",
    },
    {
        "bytes": 141,
        "digest": "sha256:cf817f208ceb1f4bb211d5cc97b190f6ba54cb27f34d7864b9fea5adc74a679e",
        "name": "baseline-source/package.json",
        "role": "fixture",
    },
    {
        "bytes": 125,
        "digest": "sha256:0d4abd050921ecb1c29c8c97457654184137c65644ca9b3e21a920284ce5178b",
        "name": "candidate-source/index.js",
        "role": "fixture",
    },
    {
        "bytes": 182,
        "digest": "sha256:5579b471618e53e8fd72df36ad0128bb6310c0fc8111be6db31a18c672b5053c",
        "name": "candidate-source/openclaw.plugin.json",
        "role": "fixture",
    },
    {
        "bytes": 141,
        "digest": "sha256:7e73514c5369d1d90524663baff896f41f71e21540d1b0a311a73aaf456ee8de",
        "name": "candidate-source/package.json",
        "role": "fixture",
    },
)
_BUNDLE = [*map(dict, _FIXTURES), dict(_PROBE)]
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 17_073,
        "digest": "sha256:48c4a6d269f29080cf88d750205d40731f66fc13415aa76f6afeff0f8259e809",
        "path": "/src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
    },
    "materializer": {
        "bytes": 87_912,
        "digest": "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
        "path": "/src/scripts/materialize_fixed_admission_probes.py",
    },
    "v1_route_injector": {
        "bytes": 21_470,
        "digest": "sha256:50e96d42459a40d0a87ce2cdd215bace14072a626281a3fc733efb5b22831355",
        "path": "/src/scripts/runtime_action_worker_final_route_systemd_probe.py",
    },
}
_BUNDLE_SOURCE_PATHS = (
    "benchmark/admission/openclaw-v2026.7.1/plugin-force-reinstall-baseline-index.js",
    "benchmark/admission/openclaw-v2026.7.1/plugin-force-reinstall-baseline-openclaw.plugin.json",
    "benchmark/admission/openclaw-v2026.7.1/plugin-force-reinstall-baseline-package.json",
    "benchmark/admission/openclaw-v2026.7.1/plugin-force-reinstall-replacement-index.js",
    "benchmark/admission/openclaw-v2026.7.1/plugin-force-reinstall-replacement-openclaw.plugin.json",
    "benchmark/admission/openclaw-v2026.7.1/plugin-force-reinstall-replacement-package.json",
    "benchmark/admission/openclaw-v2026.7.1/protected-plugin-force-reinstall-probe.py",
)
_DIGESTS = {
    "composition": "sha256:fdbe735345fe7e9e249a868a6459bf2f75cf3106105a4401f17319e5b82cc551",
    "source_artifacts": "sha256:ae43bc4bbb759eaa14aa0999594e45715ca6587bf7e727cc4be906bc55bc255b",
    "route_observation": "sha256:39047f2a59d83f0b2ca8d5c47d30da9bd7b80ff723efe85a145f700b4cf21fb6",
    "execution": "sha256:017108089d0e25a9b499fd79c2d6408c67fb235c717662343a3ccfdd89f9ba23",
    "gateway": "sha256:35a7832bce8cb3e5570639c7265da78652927bd4f7bff9d17c1c09c8629ac7ed",
    "stack": "sha256:e14641e88067690f07c75969b0639926755462042ee5a3bac9c70a68465c0e0f",
    "document": _ROUTE_RAW["canonical_digest"],
    "action": "sha256:1ac005689de326dbf98bed8d47a7591cea1196721a0b161c1b1adb1cc58a8dd5",
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


def verify_openclaw_final_combined_v2_plugin_force_reinstall(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact force-reinstall FAIL and twenty NOT_TESTED routes."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract._read_blob(evidence_cas, _EVIDENCE, "V2 plugin force reinstall")
        if raw != retained:
            raise AdmissionEvidenceError(
                "V2 plugin force-reinstall CAS differs from signed retention"
            )
        evidence = contract._load_canonical_json(
            raw, _EVIDENCE, "V2 plugin force reinstall"
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
            f"invalid V2 plugin force-reinstall evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": route["id"],
            "status": "FAIL" if route["id"] == _ROUTE else "NOT_TESTED",
        }
        for route in profile["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v2-plugin-force-"
            "reinstall-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V2_PLUGIN_FORCE_REINSTALL_"
            "ROUTE_FAILURE_ONLY"
        ),
        "bindings": {
            "configuration": dict(config._SOURCES["configuration"]),
            "image": _IMAGE,
            "plugin_force_reinstall_observation": {
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
            "profile": dict(config._SOURCES["profile"]),
            "runtime": dict(contract._RUNTIME),
            "runtime_lock": dict(config._SOURCES["runtime_lock"]),
            "skill": dict(config._SOURCES["skill"]),
            "source_artifacts": {
                **{name: dict(value) for name, value in _SOURCE_ARTIFACTS.items()},
                "probe_bundle": [dict(value) for value in _BUNDLE],
            },
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "FAIL",
            **{key: False for key in contract._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_PLUGIN_FORCE_REINSTALL_FAILURE_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "UNBROKERED_FORCE_REINSTALL_PERSISTED_CANDIDATE_PLUGIN_BYTES",
            "COMMAND_FAILED_ON_READ_ONLY_CONFIG_LOCK_AND_TARGET_REPLACEMENT_PERSISTED",
            "EMPTY_OPENCLAW_INSTALL_BACKUPS_DIRECTORY_RESIDUE_PERSISTED",
            "SQLITE_MAIN_FILE_UNCHANGED_BUT_WAL_AND_SHM_BYTES_CHANGED",
            "NO_TABLE_LEVEL_SQLITE_DIFF_OR_LOGICAL_TRANSACTION_ATTESTATION",
            "REPLACEMENT_REMAINED_DISABLED_UNALLOWLISTED_UNACTIVATED_AND_UNIMPORTED",
            "NO_PRE_EFFECT_DENIAL_ROLLBACK_CLEANUP_QUARANTINE_OR_TARGET_INTEGRITY_CLAIM",
            "NO_POST_RESTART_FRESH_SESSION_OR_MODEL_EXECUTION",
            "INERT_NO_DEPENDENCY_NO_HOOK_LOCAL_PLUGIN_FIXTURE_ONLY",
            "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "SOURCE_TO_BINARY_BUILD_NOT_INDEPENDENTLY_ATTESTED_OR_REPRODUCED",
            "PUBLIC_NETWORK_DENIED",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"FAIL": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "containment_observed": {
                "configuration_unchanged": True,
                "external_skill_catalog_unchanged": True,
                "gateway_process_unchanged": True,
                "replacement_activated": False,
            },
            "dynamically_exercised_routes": [_ROUTE],
            "failure_basis": (
                "FAIL_UNBROKERED_FORCE_REINSTALL_PERSISTED_PLUGIN_TARGET_AND_"
                "FAILED_ON_CONFIG_LOCK"
            ),
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


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
        raise AdmissionEvidenceError("V2 plugin force-reinstall verifier base changed")
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
        raise AdmissionEvidenceError("V2 plugin force-reinstall repository changed")
    config.base._verify_commit(_SOURCE)
    config.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall signed tree entry changed"
        )
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=576 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 plugin force-reinstall signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    parent._verify_scalar_types(evidence)
    config._verify_no_positive_eligibility(evidence)
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
        or evidence["recorded_at"] != "2026-08-28T14:54:35.875071Z"
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
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall outer observation changed"
        )
    _verify_sources(evidence["source_artifacts"])
    profile = _verify_composition(evidence["composition"])
    _verify_route_observation(
        evidence["route_observation"],
        evidence["recorded_at"],
        boundaries=evidence["composition"]["action"]["boundaries"],
        container_id=evidence["composition"]["action"]["harness"]["document"][
            "container_id"
        ],
    )
    return profile


def _verify_sources(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall source inventory changed"
        )
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
            raise AdmissionEvidenceError(
                f"V2 plugin force-reinstall {name} source changed"
            )
    if value["probe_bundle"] != _BUNDLE:
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall probe bundle changed"
        )
    git = config.base.legacy._git
    signed = [
        ({**item}, item["path"].removeprefix("/src/"))
        for item in _SOURCE_ARTIFACTS.values()
    ] + list(zip(_BUNDLE, _BUNDLE_SOURCE_PATHS, strict=True))
    for expected, path in signed:
        raw = git(["show", f"{_SOURCE['commit']}:{path}"], maximum=expected["bytes"])
        if len(raw) != expected["bytes"] or _digest(raw) != expected["digest"]:
            raise AdmissionEvidenceError(
                "V2 plugin force-reinstall signed source changed"
            )


def _verify_composition(composition: Mapping[str, Any]) -> Mapping[str, Any]:
    before = composition["profile"]["before"]
    after = composition["profile"]["after"]
    profile = after["document"]
    action = composition["action"]
    harness = action["harness"]["document"]
    if (
        composition["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-observation/v1"
        or composition["recorded_at"] != "2026-08-28T14:54:35.874870Z"
        or before != after
        or after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(contract._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile["runtime"]
        != {**contract._OPENCLAW, "name": "openclaw-protected-final-combined-v2"}
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
        or harness["source_commit"] != _SOURCE["commit"]
        or harness["image_id"] != _IMAGE
        or harness["run_image_reference"] != _IMAGE
        or harness["source_commit_verification"]["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or harness["source_commit_verification"]["exit_code"] != 0
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall composition changed"
        )
    config._verify_configuration(action["artifacts"]["final_combined_v2"])
    _verify_harness(action["harness"])
    return profile


def _verify_harness(envelope: Mapping[str, Any]) -> None:
    document = envelope["document"]
    raw_file = envelope["file"]
    raw = base64.b64decode(raw_file["base64"], validate=True)
    parsed = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=contract._reject_duplicates,
        parse_constant=contract._reject_constant,
    )
    runtime_mount = document["openclaw_runtime_mount"]
    route_mount = document["route_input_mount"]
    host = document["host_config"]
    if (
        parsed != document
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
        or document["parent_image_id"] != config._PARENT_IMAGE
        or host["network_mode"] != "none"
        or host["privileged"] is not True
        or host["readonly_rootfs"] is not False
        or runtime_mount
        != {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": config._RUNTIME_VOLUME,
            "type": "volume",
        }
        or route_mount["destination"] != "/route-input"
        or route_mount["driver"] != "local"
        or route_mount["mode"] != "ro"
        or route_mount["rw"] is not False
        or route_mount["type"] != "volume"
        or f"{route_mount['source']}:/route-input:ro" not in host["binds"]
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall harness changed"
        )


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
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall raw base64 changed"
        ) from exc
    if (
        value["bundle"] != _BUNDLE
        or value["route"] != value_route()
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
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall retained route changed"
        )
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
        re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or gateway
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": "/proc/2759/ns/mnt",
            "pid": 2759,
            "unit": gateway_unit,
        }
        or execution["argv"]
        != [
            "nsenter",
            "--target",
            "2759",
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
            "/usr/local/bin/python3.12",
            "/route-input/plugin-force-reinstall/protected-plugin-force-reinstall-probe.py",
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
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall route execution changed"
        )


def _verify_document(
    document: Mapping[str, Any], execution: Mapping[str, Any], outer_time: str
) -> None:
    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    boundary_before = before["boundary_before"]
    boundary_after = after["boundary_after"]
    native = after["native_force_reinstall"]
    command = native["command"]
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
            "plugin_before",
            "skills_status_before",
            "system_info_before",
            "version",
        }
        or set(after)
        != {
            "boundary_after",
            "native_force_reinstall",
            "plugin_after",
            "post_write_containment",
            "skills_status_after",
            "state_invariants",
            "system_info_after",
        }
        or set(document)
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
        or document["schema"]
        != "aragorn/openclaw-protected-plugin-force-reinstall-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE["digest"]
        or document["route"] != value_route()
        or document["runtime_binding"]
        != {
            "commit": contract._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": contract._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "version": "2026.7.1",
        }
        or canonical_digest(action) != _DIGESTS["action"]
        or action["id"] != "plugin-force-reinstall"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or boundary_before["baseline_source"] != boundary_after["baseline_source"]
        or boundary_before["candidate_source"] != boundary_after["candidate_source"]
        or boundary_before["config"] != boundary_after["config"]
        or boundary_before["config_lock"] != boundary_after["config_lock"]
        or boundary_before["gateway_process"] != boundary_after["gateway_process"]
        or boundary_before["openclaw"] != boundary_after["openclaw"]
        or boundary_before["route_input_mount"] != boundary_after["route_input_mount"]
        or boundary_before["config_lock"]
        != {"exists": False, "path": f"{_CONFIG}.lock"}
        or before["skills_status_before"]["response"]
        != after["skills_status_after"]["response"]
        or after["state_invariants"]
        != {
            "baseline_source": True,
            "candidate_source": True,
            "config": True,
            "config_lock": True,
            "discovery_roots": False,
            "gateway_process": True,
            "openclaw": True,
            "plugin_inspection": False,
            "route_input_mount": True,
            "skills_status": True,
            "state_store": False,
            "target_plugin": False,
        }
        or after["post_write_containment"]
        != {
            "configuration_unchanged": True,
            "external_skill_catalog_unchanged": True,
            "gateway_process_unchanged": True,
            "installed_record_absent": True,
            "replacement_disabled": True,
            "state_store_unchanged": False,
            "target_transition": {
                "after_is_baseline": False,
                "after_is_candidate": True,
                "before_is_baseline": True,
                "candidate_differs_from_baseline": True,
            },
        }
        or native["process_started"] is not True
        or native["same_id_existing_target"] is not True
        or native["source_path"] != _SOURCE_ROOT
        or native["target_path"] != _TARGET
        or native["target_plugin_id"] != _PLUGIN_ID
        or native["effective_update_basis"]
        != {
            "candidate_manifest_id": _PLUGIN_ID,
            "existing_target_manifest_id": _PLUGIN_ID,
            "force_requested": True,
            "target_existed_before": True,
        }
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "plugins",
            "install",
            _SOURCE_ROOT,
            "--force",
        ]
        or command["exit_code"] != 1
        or command["error"] is not None
        or command["signal"] is not None
        or command["stderr_bytes"] != 292
        or command["stderr_digest"]
        != "sha256:1debd77dd23b638d9e2cc99b134f3e57346dd98ecc03ebbcf6fbb7ab0b771fd8"
        or f"open '{_CONFIG}.lock'" not in command["stderr_excerpt"]
        or command["stdout_bytes"] != 260
        or command["stdout_digest"]
        != "sha256:0ca16742cf756b8aa9c6f75206ed3680e52c9e1878ab11e8f3ff319aa229cd3a"
        or f"Installing to {_TARGET}" not in command["stdout_excerpt"]
        or not config._command_output_is_exact(command)
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall failure semantics changed"
        )
    _verify_config(boundary_before["config"])
    config._verify_version(before["version"])
    config._verify_openclaw(boundary_before["openclaw"])
    _verify_source_fixture(
        boundary_before["baseline_source"], fixture="baseline", version="1.0.0"
    )
    _verify_source_fixture(
        boundary_before["candidate_source"], fixture="candidate", version="2.0.0"
    )
    _verify_route_input(boundary_before["route_input_mount"])
    _verify_skills_status(
        before["skills_status_before"], after["skills_status_after"]
    )
    _verify_plugins(before["plugin_before"], after["plugin_after"])
    _verify_target_transition(
        boundary_before["target_plugin"], boundary_after["target_plugin"]
    )
    _verify_discovery_residue(
        boundary_before["discovery_roots"], boundary_after["discovery_roots"]
    )
    _verify_state_store_delta(
        boundary_before["state_store"], boundary_after["state_store"]
    )
    gateway = boundary_before["gateway_process"]
    if (
        gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "effective_capabilities": "0000000000000000",
            "no_new_privileges": "1",
            "pid": 2759,
            "seccomp": "2",
            "start_time_ticks": "44681061",
        }
        or before["system_info_before"]["response"]["value"]["pid"] != 2759
        or after["system_info_after"]["response"]["value"]["pid"] != 2759
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall gateway binding changed"
        )
    _verify_systems(
        before["system_info_before"], after["system_info_after"]
    )
    commands = [
        before["version"],
        before["system_info_before"]["command"],
        before["skills_status_before"]["command"],
        before["plugin_before"]["command"],
        command,
        after["plugin_after"]["command"],
        after["skills_status_after"]["command"],
        after["system_info_after"]["command"],
    ]
    parse = config.base.legacy._parse_time
    if (
        action["commands"] != commands
        or any(type(item["pid"]) is not int or item["pid"] <= 0 for item in commands)
        or len({item["pid"] for item in commands}) != len(commands)
        or any(item["pid"] == gateway["pid"] for item in commands)
        or any(parse(item["started_at"]) > parse(item["completed_at"]) for item in commands)
        or any(
            parse(current["completed_at"]) > parse(following["started_at"])
            for current, following in pairwise(commands)
        )
        or not (
            parse(execution["started_at"])
            <= parse(commands[0]["started_at"])
            <= parse(commands[-1]["completed_at"])
            <= parse(document["recorded_at"])
            <= parse(execution["completed_at"])
            <= parse(outer_time)
        )
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall command causality changed"
        )


def _verify_plugins(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    expected = (
        (
            before,
            "Aragorn force reinstall baseline",
            "1.0.0",
            2_516,
            "sha256:743580ca707f52fbdaece81c69dc2bf0856c6f4381d73af55a202b9302eedb85",
        ),
        (
            after,
            "Aragorn force reinstall replacement",
            "2.0.0",
            2_519,
            "sha256:95c6e607e24a8ce22c8b62993476569e68ac97169664a28591221b5659745eb7",
        ),
    )
    for observation, name, version, stdout_bytes, stdout_digest in expected:
        command = observation["command"]
        response = observation["response"]
        value = response["value"]
        plugin = value["plugin"]
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
            or command["stdout_bytes"] != stdout_bytes
            or command["stdout_digest"] != stdout_digest
            or not command["stdout_excerpt"].startswith(
                '{\n  "workspaceDir": "/var/lib/aragorn-agent-gateway/workspace",\n'
                f'  "plugin": {{\n    "id": "{_PLUGIN_ID}",\n'
                f'    "name": "{name}",\n    "version": "{version}",\n'
            )
            or response["parsed"] is not True
            or "install" in value
            or plugin["id"] != _PLUGIN_ID
            or plugin["name"] != name
            or plugin["version"] != version
            or plugin["source"] != f"{_TARGET}/index.js"
            or plugin["rootDir"] != _TARGET
            or plugin["origin"] != "global"
            or plugin["enabled"] is not False
            or plugin["explicitlyEnabled"] is not False
            or plugin["activated"] is not False
            or plugin["activationSource"] != "disabled"
            or plugin["activationReason"] != "not in allowlist"
            or plugin["status"] != "disabled"
            or plugin["error"] != "not in allowlist"
            or plugin["imported"] is not False
            or value["shape"] != "non-capability"
            or type(value["capabilityCount"]) is not int
            or value["capabilityCount"] != 0
            or any(
                value[key] != []
                for key in ("capabilities", "tools", "services", "typedHooks")
            )
            or not config._command_succeeded_clean(command)
        ):
            raise AdmissionEvidenceError(
                "V2 plugin force-reinstall plugin containment changed"
            )


def _verify_config(value: Mapping[str, Any]) -> None:
    file = value["file"]
    mount = value["mount"]
    if (
        value["ready"] is not True
        or value["canonical_digest"]
        != config._SOURCES["configuration"]["canonical_digest"]
        or file["digest"] != value["canonical_digest"]
        or file["path"] != _CONFIG
        or file["exists"] is not True
        or file["type"] != "file"
        or file["size"] != config._SOURCES["configuration"]["canonical_bytes"]
        or file["mode"] != "400"
        or file["uid"] != 992
        or file["gid"] != 0
        or file["nlink"] != 1
        or file["digest_error"] is not None
        or mount["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or mount["ready"] is not True
        or mount["read_only"] is not True
        or len(mount["records"]) != 1
        or mount["records"][0]["filesystem"] != "ramfs"
        or mount["records"][0]["source"] != "ramfs"
        or mount["records"][0]["root"] != "/"
        or mount["records"][0]["mount_point"]
        != "/run/credentials/aragorn-agent-gateway.service"
        or mount["records"][0]["mount_options"]
        != ["nodev", "noexec", "nosuid", "relatime", "ro"]
        or value["plugin_policy"]
        != {
            "allow": ["aragorn-runtime-action-worker"],
            "enabled": True,
            "target_allowlisted": False,
            "target_entry": None,
            "target_entry_present": False,
        }
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall configuration changed"
        )


def _verify_source_fixture(
    value: Mapping[str, Any], *, fixture: str, version: str
) -> None:
    _verify_fixture(
        value,
        fixture=fixture,
        version=version,
        root_path=f"/route-input/plugin-force-reinstall/{fixture}-source",
        uid=0,
        gid=0,
        root_mode="555",
        file_mode="444",
        tree_digest={
            "baseline": (
                "sha256:f696fe71e9394a97f3a9c328b6eac7319791bb435bc74cfb991a2f3919ae8e2d"
            ),
            "candidate": (
                "sha256:86a805724c85e1357c881af756cdcbdfb7caa703e8664101b2a4e0eac61839cf"
            ),
        }[fixture],
    )


def _verify_fixture(
    value: Mapping[str, Any],
    *,
    fixture: str,
    version: str,
    root_path: str,
    uid: int,
    gid: int,
    root_mode: str,
    file_mode: str,
    tree_digest: str,
) -> None:
    tree = value["tree"]
    root = tree["root"]
    entries = {item["path"]: item for item in tree["entries"]}
    expected = {
        item["name"].split("/", 1)[1]: item
        for item in _FIXTURES
        if item["name"].startswith(f"{fixture}-source/")
    }
    if (
        value["ready"] is not True
        or value["expected_fixture"] != fixture
        or value["manifest"]
        != {
            "configSchema": {
                "additionalProperties": False,
                "properties": {},
                "type": "object",
            },
            "id": _PLUGIN_ID,
            "name": (
                "Aragorn force reinstall baseline"
                if fixture == "baseline"
                else "Aragorn force reinstall replacement"
            ),
            "version": version,
        }
        or value["package"]
        != {
            "name": "@aragorn/plugin-force-reinstall-fixture",
            "openclaw": {"extensions": ["./index.js"]},
            "private": True,
            "type": "module",
            "version": version,
        }
        or tree["ready"] is not True
        or tree["tree_digest"] != tree_digest
        or root["path"] != root_path
        or root["exists"] is not True
        or root["type"] != "directory"
        or root["uid"] != uid
        or root["gid"] != gid
        or root["mode"] != root_mode
        or len(tree["entries"]) != 3
        or set(entries) != set(expected)
        or any(
            entry["exists"] is not True
            or entry["type"] != "file"
            or entry["uid"] != uid
            or entry["gid"] != gid
            or entry["mode"] != file_mode
            or entry["size"] != expected[path]["bytes"]
            or entry["digest"] != expected[path]["digest"]
            or entry["digest_error"] is not None
            for path, entry in entries.items()
        )
    ):
        raise AdmissionEvidenceError(
            f"V2 plugin force-reinstall {fixture} source fixture changed"
        )


def _verify_route_input(value: Mapping[str, Any]) -> None:
    if (
        value["path"] != "/route-input"
        or value["ready"] is not True
        or value["read_only"] is not True
        or len(value["records"]) != 1
        or value["records"][0]["source"] != "/dev/vdb1"
        or value["records"][0]["mount_point"] != "/route-input"
        or value["records"][0]["root"]
        != "/docker/volumes/aragorn-phase3-final-combined-v2-route-input-51477/_data"
        or value["records"][0]["mount_options"]
        != ["nosuid", "relatime", "ro"]
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall route-input mount changed"
        )


def _verify_systems(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "system.info",
        "--json",
        "--timeout",
        "5000",
    ]
    _verify_json_probe(
        before,
        argv=argv,
        stdout_bytes=549,
        stdout_digest=(
            "sha256:cd37095c158524a1fd816212bd19030c85e25b8fb33a0771989a4b72cc1a3f51"
        ),
        label="system.info before",
    )
    _verify_json_probe(
        after,
        argv=argv,
        stdout_bytes=552,
        stdout_digest=(
            "sha256:9c54a1729ed7785599d1d587971bbdd6d5e91cf2d65f7c6f92e7595ea396de71"
        ),
        label="system.info after",
    )
    first = before["response"]
    second = after["response"]
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
    if (
        first["parsed"] is not True
        or second["parsed"] is not True
        or not config._command_succeeded_clean(before["command"])
        or not config._command_succeeded_clean(after["command"])
        or any(first["value"][key] != second["value"][key] for key in stable)
        or first["value"]["pid"] != 2759
        or second["value"]["uptimeMs"] <= first["value"]["uptimeMs"]
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall system stability changed"
        )


def _verify_skills_status(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "skills.status",
        "--json",
        "--timeout",
        "5000",
    ]
    for label, observation in (("before", before), ("after", after)):
        _verify_json_probe(
            observation,
            argv=argv,
            stdout_bytes=1_170,
            stdout_digest=(
                "sha256:479c998f7111d3342f25b644ababf9dd6b6b36aee879876d82f9caa31db9b597"
            ),
            label=f"skills.status {label}",
        )


def _verify_json_probe(
    observation: Mapping[str, Any],
    *,
    argv: list[str],
    stdout_bytes: int,
    stdout_digest: str,
    label: str,
) -> None:
    command = observation["command"]
    response = observation["response"]
    parsed = json.loads(
        command["stdout_excerpt"],
        object_pairs_hook=contract._reject_duplicates,
        parse_constant=contract._reject_constant,
    )
    if (
        command["argv"] != argv
        or command["stdout_bytes"] != stdout_bytes
        or command["stdout_digest"] != stdout_digest
        or not config._command_succeeded_clean(command)
        or not config._command_output_is_exact(command)
        or response["parsed"] is not True
        or parsed != response["value"]
    ):
        raise AdmissionEvidenceError(
            f"V2 plugin force-reinstall {label} observation changed"
        )


def _verify_target_transition(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    if (
        before["baseline"]["ready"] is not True
        or before["candidate"]["ready"] is not False
        or after["baseline"]["ready"] is not False
        or after["candidate"]["ready"] is not True
        or before["exact_gateway_owned_metadata"] is not True
        or after["exact_gateway_owned_metadata"] is not False
        or before["parent_writable"] is not True
        or before["target_writable"] is not True
        or after["parent_writable"] is not True
        or after["target_writable"] is not True
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall persisted target transition changed"
        )
    _verify_fixture(
        before["baseline"],
        fixture="baseline",
        version="1.0.0",
        root_path=_TARGET,
        uid=992,
        gid=992,
        root_mode="700",
        file_mode="600",
        tree_digest=(
            "sha256:f50fedfe6fc7a17bcdb3211bb24a02d3bab3afe595ce44f5805d8651e650e1db"
        ),
    )
    _verify_fixture(
        after["candidate"],
        fixture="candidate",
        version="2.0.0",
        root_path=_TARGET,
        uid=992,
        gid=992,
        root_mode="700",
        file_mode="444",
        tree_digest=(
            "sha256:98bb4053ece75b0eaf3ba4ad6988e434e680951e09a05c30dc0f58432d16f50f"
        ),
    )


def _verify_discovery_residue(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    root = "/var/lib/aragorn-agent-gateway/state/extensions"
    if (
        before[root]["ready"] is not True
        or after[root]["ready"] is not True
        or before[root]["tree_digest"]
        != "sha256:8f5d5a9810fc3ca0784d50b5498ccad87bcb704b8e93f97fd916721617fd6634"
        or after[root]["tree_digest"]
        != "sha256:b63babdbfc174d5fd16ff752d43f2f5edac9b8220249f5c7f5865c0dd4014c5c"
        or any(
            value[root]["root"]["path"] != root
            or value[root]["root"]["exists"] is not True
            or value[root]["root"]["type"] != "directory"
            or value[root]["root"]["uid"] != 992
            or value[root]["root"]["gid"] != 992
            or value[root]["root"]["mode"] != "700"
            or any(
                item["exists"] is not True
                or item.get("digest_error") is not None
                for item in value[root]["entries"]
            )
            for value in (before, after)
        )
        or any(before[path] != after[path] for path in before if path != root)
        or set(before) != set(after)
        or [item["path"] for item in before[root]["entries"]]
        != [
            _PLUGIN_ID,
            f"{_PLUGIN_ID}/index.js",
            f"{_PLUGIN_ID}/openclaw.plugin.json",
            f"{_PLUGIN_ID}/package.json",
        ]
        or [item["path"] for item in after[root]["entries"]]
        != [
            ".openclaw-install-backups",
            _PLUGIN_ID,
            f"{_PLUGIN_ID}/index.js",
            f"{_PLUGIN_ID}/openclaw.plugin.json",
            f"{_PLUGIN_ID}/package.json",
        ]
        or after[root]["entries"][0]["type"] != "directory"
        or after[root]["entries"][0]["uid"] != 992
        or after[root]["entries"][0]["gid"] != 992
        or after[root]["entries"][0]["mode"] != "755"
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall discovery-root residue changed"
        )


def _verify_state_store_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    first = {item["path"]: item for item in before["entries"]}
    second = {item["path"]: item for item in after["entries"]}
    if (
        before["ready"] is not True
        or after["ready"] is not True
        or before["tree_digest"]
        != "sha256:e23bba81d17f8fab2f803fb82b60f73da943b0953190888a558b6018196255a5"
        or after["tree_digest"]
        != "sha256:e04028c03d48bd5c83a841772aec741853411f8b3cde27633a80e34f682b6e8c"
        or before["root"] != after["root"]
        or before["root"]["path"]
        != "/var/lib/aragorn-agent-gateway/state/state"
        or before["root"]["exists"] is not True
        or before["root"]["type"] != "directory"
        or before["root"]["uid"] != 992
        or before["root"]["gid"] != 992
        or before["root"]["mode"] != "700"
        or len(before["entries"]) != 3
        or len(after["entries"]) != 3
        or any(
            item["exists"] is not True
            or item["type"] != "file"
            or item["uid"] != 992
            or item["gid"] != 992
            or item["mode"] != "600"
            or item["digest_error"] is not None
            for item in (*before["entries"], *after["entries"])
        )
        or set(first)
        != {"openclaw.sqlite", "openclaw.sqlite-shm", "openclaw.sqlite-wal"}
        or set(second) != set(first)
        or first["openclaw.sqlite"] != second["openclaw.sqlite"]
        or first["openclaw.sqlite"]["digest"]
        != "sha256:40cf07c52bfaa52b334ef341456f970787f6dc701ffe18ad3c572cb5056dbd70"
        or first["openclaw.sqlite-shm"]["digest"]
        != "sha256:9565db8e62001bd55c64addb009ef5e69ae5c08eb0bf7fd9e3f24b3acb814f3f"
        or second["openclaw.sqlite-shm"]["digest"]
        != "sha256:82a0e771094ef4bfd33bca4782466a5a2174b5bd6d122ac5ac6cee762bd25a47"
        or first["openclaw.sqlite-wal"]["digest"]
        != "sha256:51734585f841f319de3d29d89b4a3f58116c1eb956c1538f44f41efdcd16fd46"
        or second["openclaw.sqlite-wal"]["digest"]
        != "sha256:2e8e08217d5583711005cf878153f690beb33d900be741f46baa5df43e9868f4"
        or first["openclaw.sqlite-wal"]["size"] != 3_073_552
        or second["openclaw.sqlite-wal"]["size"] != 3_304_272
        or second["openclaw.sqlite-wal"]["size"] <= first["openclaw.sqlite-wal"]["size"]
    ):
        raise AdmissionEvidenceError(
            "V2 plugin force-reinstall state-store residue changed"
        )


def value_route() -> dict[str, Any]:
    return {
        "action_id": "plugin-force-reinstall",
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }
