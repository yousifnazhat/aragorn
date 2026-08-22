"""Derive one V2 route PASS from the signed fresh-session reset observation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import admission_protected_final_fresh_session_reset as legacy
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/reload/fresh-session-reset"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_LEGACY = {
    "digest": "sha256:0194290d96b384d0b16528a0c5715675b226c1c494dbc11c69f1c774c082e2c1",
    "path": "src/aragorn/admission_protected_final_fresh_session_reset.py",
}
_EVIDENCE = {
    "bytes": 433_597,
    "canonical_bytes": 433_596,
    "canonical_digest": (
        "sha256:2cd64814b3d33bcb2d34594e8c5ed4ff091d66e6331a2b479e9158cd03997269"
    ),
    "digest": (
        "sha256:d3d3280fc0273a5b87d026c18729244adfc29d17cf4deb486e6d15cb9b7c9794"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "fresh-session-reset-systemd-p3-final-2026-08-22.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 25_070,
    "canonical_digest": (
        "sha256:01f3e3dfe44f5514e50ecd7830b850c2bb320e40f95abc374a5e01ef1f345362"
    ),
    "digest": (
        "sha256:61b309dbaf7c4e31d285e04cff2c63b6a432f00668f1a5b26177946786c05d5d"
    ),
}
_SOURCE = {
    "commit": "37be5944d6e307b6f042ef4412c51166dd7f515f",
    "parent": "7ea8ade2c1342a9393622c1ed8eae8625f55dcb2",
    "tree": "182d6ccd6c61ea0d7b9dcf8b9be1576a06665c0c",
}
_RETENTION = {
    "commit": "51c2186c72d8b47260dbacabf34062c543944892",
    "parent": _SOURCE["commit"],
    "tree": "80fb5cc8771c1d8af4607e754e7e202707891fd9",
}
_RETENTION_BLOB = "bbc66ca7bd06512b72efa75e2c7d07aa21a54249"
_IMAGE = "sha256:9e8342fcb279ce57d02e591e6a521496fd180625605d070d22f0abc0493274d4"
_PARENT_IMAGE = (
    "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
)
_PROMPT_DIGEST = (
    "sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501"
)
_PROMPT_PATH = (
    "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/skills-prompts/"
    f"sha256/60/{_PROMPT_DIGEST.removeprefix('sha256:')}.txt"
)
_SESSION_STORE = (
    "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json"
)
_SOURCES = {
    "configuration": {
        "bytes": 1_847,
        "canonical_bytes": 1_846,
        "canonical_digest": (
            "sha256:93bbb9107c8ed72ef5cd919888306119016ce4c5843e7d61ebb1580b9ae67645"
        ),
        "digest": (
            "sha256:2772bca6629607247e2a5c056282b4748ab5bb6d024fd742c9755fb915281ddb"
        ),
    },
    "profile": {
        "bytes": 4_951,
        "canonical_bytes": 4_950,
        "canonical_digest": (
            "sha256:a20ab2dd6572ada5fac086bc818495a6e6079f55f6fcbae397687c7b19eac59e"
        ),
        "digest": (
            "sha256:615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc"
        ),
    },
    "runtime_lock": {
        "bytes": 6_742,
        "canonical_bytes": 6_741,
        "canonical_digest": (
            "sha256:ceb60c00c806858caaa155b1778e09c5df28117109dfc021076f934f134f3f3d"
        ),
        "digest": (
            "sha256:c5773a0b8829d1dbdd9fa89d7dc93e995ee54ea723208daa59b0951d50e76fd5"
        ),
    },
    "skill": {
        "bytes": 140,
        "digest": (
            "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
        ),
    },
}
_PLUGIN = {
    "index.js": {
        "bytes": 23_860,
        "digest": (
            "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b"
        ),
    },
    "openclaw.plugin.json": {
        "bytes": 723,
        "digest": (
            "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036"
        ),
    },
    "package.json": {
        "bytes": 134,
        "digest": (
            "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2"
        ),
    },
}
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 7_953,
        "digest": (
            "sha256:d0e630ee2bf33c160bb76150f82634ef200f8e9e5a8a6ad97ebd32ba4e48c73c"
        ),
    },
    "materializer": {
        "bytes": 73_058,
        "digest": (
            "sha256:04818e44f7529457784e059edec44a441ffb00e980202fd9016fdbb8ad54e442"
        ),
    },
    "probe": {
        "bytes": 44_825,
        "digest": (
            "sha256:ac23d68064c1a904649c6c1064f8c7729768fe516eef1e6d7c2bdc6b4e12d299"
        ),
    },
    "v1_route_injector": {
        "bytes": 20_729,
        "digest": (
            "sha256:18f6fe8c98c64aaf59c6c35d4785780da2a4dc3ac2a719ac72941dd3ab1a1664"
        ),
    },
}
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_READY = {
    "catalog_exact",
    "prompt_exact",
    "ready",
    "session_id_valid",
    "snapshot_present",
    "snapshot_version_valid",
}


def verify_openclaw_final_combined_v2_fresh_session_reset(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 1/20 V2 route coverage after semantic verification."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = legacy.parent._read_blob(evidence_cas, _EVIDENCE, "V2 reset")
        if raw != retained:
            raise AdmissionEvidenceError("V2 reset CAS differs from signed retention")
        evidence = legacy.parent._load_canonical_json(raw, _EVIDENCE, "V2 reset")
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
            f"invalid V2 fresh-session evidence: {exc}"
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
            "aragorn/admission-protected-final-combined-v2-fresh-session-reset-"
            "route-coverage/v1"
        ),
        "assurance": "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V2_RESET_ROUTE_ONLY",
        "bindings": {
            "configuration": dict(_SOURCES["configuration"]),
            "fresh_session_reset_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": legacy.parent._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(legacy.parent._SIGNATURE),
                },
            },
            "image": _IMAGE,
            "legacy_verifier": dict(_LEGACY),
            "plugin": {name: dict(identity) for name, identity in _PLUGIN.items()},
            "profile": dict(_SOURCES["profile"]),
            "runtime": dict(legacy.parent._RUNTIME),
            "runtime_lock": dict(_SOURCES["runtime_lock"]),
            "skill": dict(_SOURCES["skill"]),
            "source_artifacts": {
                name: dict(identity) for name, identity in _SOURCE_ARTIFACTS.items()
            },
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_FRESH_SESSION_RESET_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
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


def _verify_dependencies() -> None:
    path = Path(legacy.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_LEGACY["path"]).name
        or _digest(path.read_bytes()) != _LEGACY["digest"]
    ):
        raise AdmissionEvidenceError("V2 reset legacy verifier changed")
    legacy._verify_parent_dependency()
    legacy.parent._verify_dependencies()


def _verify_commit(identity: Mapping[str, str]) -> None:
    commit = identity["commit"]
    with tempfile.TemporaryDirectory(prefix="aragorn-v2-reset-signer-") as temporary:
        allowed = Path(temporary) / "allowed_signers"
        allowed.write_bytes(legacy._ALLOWED_SIGNER)
        legacy._git_with_signer(["verify-commit", "--raw", commit], allowed)
        metadata = legacy._git_with_signer(
            [
                "show",
                "-s",
                "--format=%H%x00%T%x00%P%x00%G?%x00%GF%x00%GS%x00%GT",
                commit,
            ],
            allowed,
        ).rstrip(b"\n")
    fields = [field.decode("ascii") for field in metadata.split(b"\0")]
    if fields != [
        commit,
        identity["tree"],
        identity["parent"],
        "G",
        legacy.parent._SIGNATURE["key"],
        legacy.parent._SIGNATURE["signer"],
        "fully",
    ]:
        raise AdmissionEvidenceError("V2 reset signed commit identity changed")


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    if (
        Path(legacy._git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or legacy._git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 reset signed repository changed")
    _verify_commit(_SOURCE)
    _verify_commit(_RETENTION)
    entry = legacy._git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V2 reset signed tree entry changed")
    raw = legacy._git(["cat-file", "blob", _RETENTION_BLOB], maximum=512 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 reset signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
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
        or evidence["recorded_at"] != "2026-08-22T04:50:49.672305Z"
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
            **{key: False for key in legacy.parent._ELIGIBILITY_KEYS},
        }
    ):
        raise AdmissionEvidenceError("V2 reset wrapper changed")

    composition = evidence["composition"]
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    source = composition["action"]["artifacts"]["final_combined_v2"]
    harness = composition["action"]["harness"]["document"]
    lineage = harness["image_lineage"]
    runtime_volume = legacy.parent._RUNTIME["runtime_volume"]
    if (
        profile_before != profile_after
        or profile_before != source["profile"]
        or composition["action"]["inputs"]["gateway_config"]
        != source["config"]["document"]
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]] != list(legacy.parent._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or harness["image_id"] != _IMAGE
        or harness["run_image_reference"] != _IMAGE
        or harness["parent_image_id"] != _PARENT_IMAGE
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or not lineage["added_layers"]
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or lineage["child"]["rootfs_type"] != "layers"
        or lineage["parent"]["rootfs_type"] != "layers"
        or harness["source_commit"] != _SOURCE["commit"]
        or harness["host_config"]["network_mode"] != "none"
        or harness["host_config"]["privileged"] is not True
        or harness["openclaw_runtime_mount"]
        != {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": runtime_volume,
            "type": "volume",
        }
        or harness["openclaw_runtime_volume"] != runtime_volume
        or harness["openclaw_runtime_volume_identity"]
        != {
            "driver": "local",
            "labels": {
                "io.aragorn.phase": "phase3-final",
                "io.aragorn.role": "installed-runtime",
                "io.aragorn.source-commit": legacy.parent._OPENCLAW["commit"],
                "io.aragorn.source-tree": legacy.parent._OPENCLAW["source_tree"],
            },
            "name": runtime_volume,
            "options": None,
            "scope": "local",
        }
        or composition["action"]["runtime"]
        != {
            "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "entrypoint_digest": legacy.parent._RUNTIME["entrypoint_digest"],
            "expected_version": legacy.parent._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": legacy.parent._RUNTIME_TREE,
            "version_output": legacy.parent._RUNTIME["version_output"],
        }
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": legacy.parent._RUNTIME["runtime_digest"],
            "runtime_volume": legacy.parent._RUNTIME["runtime_volume"],
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": _SOURCES["skill"]["digest"],
        }
    ):
        raise AdmissionEvidenceError("V2 reset profile or bindings changed")
    _verify_source_file(source["config"]["file"], _SOURCES["configuration"])
    _verify_source_file(source["profile"]["file"], _SOURCES["profile"])
    _verify_source_file(source["runtime_lock"]["file"], _SOURCES["runtime_lock"])
    _verify_file(source["skill"]["file"], _SOURCES["skill"])
    if any(
        legacy._canonical_digest(source[name]["document"])
        != _SOURCES[label]["canonical_digest"]
        for name, label in (
            ("config", "configuration"),
            ("profile", "profile"),
            ("runtime_lock", "runtime_lock"),
        )
    ):
        raise AdmissionEvidenceError("V2 reset embedded source document changed")
    for name, identity in _PLUGIN.items():
        _verify_file(source["plugin"][name], identity)
    for name, identity in _SOURCE_ARTIFACTS.items():
        _verify_file(evidence["source_artifacts"][name], identity)

    observation = evidence["route_observation"]
    document = _decode_route_raw(observation["raw"])
    container_id = harness["container_id"]
    if (
        document != observation["document"]
        or observation["route"] != document["routes"][0]
        or observation["bundle"]
        != [
            {
                **_SOURCE_ARTIFACTS["probe"],
                "name": "protected-route-probe.mjs",
            }
        ]
        or observation["bundle"] != [evidence["source_artifacts"]["probe"]]
        or not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or any(
            unit["ControlGroup"] != f"/docker/{container_id}/system.slice/{name}"
            for name, unit in observation["stack_before"]["units"].items()
        )
    ):
        raise AdmissionEvidenceError("V2 reset nested route custody changed")
    _verify_execution(observation)
    if not (
        legacy._parse_time(document["recorded_at"])
        <= legacy._parse_time(observation["execution"]["completed_at"])
        <= legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V2 reset execution custody changed")
    _verify_transition(
        document,
        container_id=container_id,
        outer_recorded_at=evidence["recorded_at"],
    )
    return profile


def _verify_file(value: Mapping[str, Any], identity: Mapping[str, Any]) -> None:
    if value["bytes"] != identity["bytes"] or value["digest"] != identity["digest"]:
        raise AdmissionEvidenceError("V2 reset bound file changed")


def _verify_source_file(value: Mapping[str, Any], identity: Mapping[str, Any]) -> None:
    source = value["source"]
    if (
        value["canonical_bytes"] != identity["canonical_bytes"]
        or value["canonical_digest"] != identity["canonical_digest"]
        or source["bytes"] != identity["bytes"]
        or source["digest"] != identity["digest"]
    ):
        raise AdmissionEvidenceError("V2 reset canonical source changed")


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V2 reset raw wrapper changed")
    raw = base64.b64decode(value["base64"], validate=True)
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=legacy.parent._reject_duplicates,
            parse_constant=legacy.parent._reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid V2 reset nested JSON: {exc}") from exc
    canonical = legacy.parent.oci_worker_protocol.canonical_json(document)
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
        raise AdmissionEvidenceError("V2 reset raw identity changed")
    return document


def _verify_execution(observation: Mapping[str, Any]) -> None:
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    stack = observation["stack_before"]
    pid = 2737
    expected_argv = [
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
        "/route-input/probe/protected-route-probe.mjs",
        "--route-id",
        _ROUTE,
    ]
    process = stack["processes"]["aragorn-agent-gateway.service"]
    if (
        binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
            "unit": "aragorn-agent-gateway.service",
        }
        or execution["argv"] != expected_argv
        or execution["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _digest(b""), "excerpt": ""}
        or stack["pids"]["aragorn-agent-gateway.service"] != pid
        or stack["gateway_listener"]["pid"] != pid
        or stack["units"]["aragorn-agent-gateway.service"]["MainPID"] != str(pid)
        or process["pid"] != pid
        or process["cmdline"] != ["openclaw-gateway"]
        or process["uids"] != [992, 992, 992, 992]
        or process["gids"] != [992, 992, 992, 992]
        or process["groups"] != [992]
        or process["capabilities_effective"] != "0000000000000000"
        or process["no_new_privileges"] != 1
        or not (
            legacy._parse_time(execution["started_at"])
            < legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V2 reset execution boundary changed")


def _verify_transition(
    document: Mapping[str, Any], *, container_id: str, outer_recorded_at: str
) -> None:
    configuration = document["protected_boundary"]["configuration"]
    config_file = configuration["file"]
    config_mount = configuration["mount"]
    protected_runtime = document["protected_boundary"]["runtime"]
    if (
        document["schema"] != "aragorn/openclaw-protected-route-action-observations/v1"
        or document["selected_route_ids"] != [_ROUTE]
        or document["implementation_digest"] != _SOURCE_ARTIFACTS["probe"]["digest"]
        or document["runtime_binding"]
        != {
            "commit": legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "version": legacy.parent._OPENCLAW["version"],
        }
        or configuration["canonical_digest"]
        != _SOURCES["configuration"]["canonical_digest"]
        or configuration["expected_canonical_digest"]
        != _SOURCES["configuration"]["canonical_digest"]
        or configuration["json_object"] is not True
        or configuration["parse_error"] is not None
        or configuration["ready"] is not True
        or config_file["path"]
        != "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
        or config_file["exists"] is not True
        or config_file["type"] != "file"
        or config_file["digest"] != _SOURCES["configuration"]["canonical_digest"]
        or config_file["digest_error"] is not None
        or config_file["size"] != _SOURCES["configuration"]["canonical_bytes"]
        or config_file["uid"] != 992
        or config_file["gid"] != 0
        or config_file["mode"] != "400"
        or config_file["nlink"] != 1
        or config_mount["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or config_mount["explicit"] is not True
        or config_mount["read_only"] is not True
        or config_mount["ready"] is not True
        or config_mount["error"] is not None
        or len(config_mount["records"]) != 1
        or config_mount["records"][0]["mount_point"]
        != "/run/credentials/aragorn-agent-gateway.service"
        or "ro" not in config_mount["records"][0]["mount_options"]
        or document["protected_boundary"]["effective_identity"]
        != {"gid": 992, "uid": 992}
        or document["protected_boundary"]["ready"] is not True
        or protected_runtime["path"] != "/runtime"
        or protected_runtime["explicit"] is not True
        or protected_runtime["read_only"] is not True
        or protected_runtime["ready"] is not True
        or protected_runtime["error"] is not None
        or len(protected_runtime["records"]) != 1
        or protected_runtime["records"][0]["mount_point"] != "/runtime"
        or "ro" not in protected_runtime["records"][0]["mount_options"]
        or legacy.parent._RUNTIME["runtime_volume"]
        not in protected_runtime["records"][0]["root"]
        or len(document["actions"]) != 1
        or document["routes"]
        != [
            {
                "action_id": "fresh-session-reset",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
    ):
        raise AdmissionEvidenceError("V2 reset selected route changed")
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
        or not isinstance(nonce, str)
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
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
        or not all(observed["session_before_reset_check"].values())
        or set(observed["session_after_reset_check"]) != _READY
        or not all(observed["session_after_reset_check"].values())
        or reset["accepted"] is not True
        or reset["error"] is not None
        or reset["method"] != "chat.send"
        or reset["params"]
        != {
            "deliver": False,
            "idempotencyKey": f"aragorn-protected-route-fresh-session-reset-{nonce}",
            "message": "/new",
            "sessionKey": legacy._SESSION_KEY,
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
        raise AdmissionEvidenceError("V2 reset transition changed")

    initial = observed["initialization_turn"]
    rebuild = observed["rebuild_turn"]
    _verify_prerequisites(action["prerequisites"], container_id=container_id)
    legacy._verify_turn(
        initial,
        label="fresh-session-initialize",
        nonce=nonce,
        pids=(initial["send"]["command"]["pid"], initial["wait"]["command"]["pid"]),
    )
    legacy._verify_turn(
        rebuild,
        label="fresh-session-rebuild",
        nonce=nonce,
        pids=(rebuild["send"]["command"]["pid"], rebuild["wait"]["command"]["pid"]),
    )
    command_pids = [
        command["pid"]
        for command in (
            action["prerequisites"]["commands"]
            + initial["commands"]
            + rebuild["commands"]
        )
    ]
    if any(type(pid) is not int or pid <= 1 for pid in command_pids) or len(
        set(command_pids)
    ) != len(command_pids):
        raise AdmissionEvidenceError("V2 reset command process custody changed")
    before_entry = before["entry"]
    after_entry = after["entry"]
    prompt = before_entry["prompt"]
    _verify_snapshot(before, session_id=before_id)
    _verify_snapshot(after, session_id=after_id)
    _verify_store_file(rotated["file"])
    if (
        action["commands"] != initial["commands"] + rebuild["commands"]
        or before["present"] is not True
        or after["present"] is not True
        or before_entry["snapshot_present"] is not True
        or after_entry["snapshot_present"] is not True
        or before_entry["skill_names"] != ["template-skill"]
        or before_entry["skill_names"] != after_entry["skill_names"]
        or before_entry["snapshot_version"] != after_entry["snapshot_version"]
        or before_entry["prompt"] != after_entry["prompt"]
        or prompt["storage"] != "promptRef"
        or prompt["digest"] != prompt["expected_digest"]
        or prompt["digest"] != _PROMPT_DIGEST
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
        or any(
            snapshot["file"]["uid"] != 992
            or snapshot["file"]["gid"] != 992
            or snapshot["file"]["mode"] != "600"
            or snapshot["file"]["nlink"] != 1
            for snapshot in (before, rotated, after)
        )
        or not (
            legacy._parse_time(initial["wait"]["command"]["completed_at"])
            <= legacy._parse_time(reset["started_at"])
            <= legacy._parse_time(reset["completed_at"])
            <= legacy._parse_time(observed["rotation_observed_at"])
            <= legacy._parse_time(rebuild["send"]["command"]["started_at"])
            < legacy._parse_time(document["recorded_at"])
            < legacy._parse_time(outer_recorded_at)
        )
        or not (
            legacy._epoch_ms(initial["send"]["command"]["completed_at"])
            <= before_entry["started_at"]
            <= before_entry["ended_at"]
            <= before_entry["updated_at"]
            <= initial["wait"]["response"]["value"]["endedAt"]
            <= legacy._epoch_ms(initial["wait"]["command"]["completed_at"])
        )
        or not (
            legacy._epoch_ms(reset["completed_at"])
            <= rotated["entry"]["updated_at"]
            <= legacy._epoch_ms(observed["rotation_observed_at"])
        )
        or not (
            legacy._epoch_ms(rebuild["send"]["command"]["completed_at"])
            <= after_entry["started_at"]
            <= after_entry["ended_at"]
            <= after_entry["updated_at"]
            <= rebuild["wait"]["response"]["value"]["endedAt"]
            <= legacy._epoch_ms(rebuild["wait"]["command"]["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V2 reset snapshot custody or timing changed")


def _verify_prerequisites(value: Mapping[str, Any], *, container_id: str) -> None:
    commands = value["commands"]
    gateway = value["gateway_process"]
    runtime = value["runtime_files"]
    system = value["system_info"]
    if (
        value["ready"] is not True
        or value["reason_codes"] != []
        or gateway["pid"] != 2737
        or gateway["hostname"] != container_id[:12]
        or gateway["cmdline"] != ["openclaw-gateway"]
        or len(commands) != 2
        or system["command"] != commands[1]
        or system["response"]["parsed"] is not True
        or system["response"]["value"]["pid"] != gateway["pid"]
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
        != legacy.parent._RUNTIME["entrypoint_digest"]
        or runtime["openclaw"]["file"]["uid"] != 0
        or runtime["openclaw"]["file"]["gid"] != 0
    ):
        raise AdmissionEvidenceError("V2 reset prerequisites changed")
    legacy._verify_command(
        commands[0],
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ],
        expected_pid=commands[0]["pid"],
        stdout_exact=legacy.parent._RUNTIME["version_output"] + "\n",
    )
    legacy._verify_command(
        commands[1],
        legacy._gateway_argv("system.info", "5000"),
        expected_pid=commands[1]["pid"],
        stdout_value=system["response"]["value"],
    )


def _verify_snapshot(value: Mapping[str, Any], *, session_id: str) -> None:
    entry = value["entry"]
    prompt = entry["prompt"]
    prompt_file = prompt["file"]
    _verify_store_file(value["file"])
    if (
        value["present"] is not True
        or entry["session_id"] != session_id
        or entry["skill_names"] != ["template-skill"]
        or entry["snapshot_present"] is not True
        or type(entry["snapshot_version"]) is not int
        or entry["snapshot_version"] <= 0
        or entry["status"] != "timeout"
        or type(entry["runtime_ms"]) is not int
        or entry["runtime_ms"] != entry["ended_at"] - entry["started_at"]
        or not (entry["started_at"] <= entry["ended_at"] <= entry["updated_at"])
        or prompt["storage"] != "promptRef"
        or prompt["bytes"] != 737
        or prompt["digest"] != _PROMPT_DIGEST
        or prompt["expected_digest"] != _PROMPT_DIGEST
        or prompt_file["path"] != _PROMPT_PATH
        or prompt_file["exists"] is not True
        or prompt_file["type"] != "file"
        or prompt_file["digest"] != _PROMPT_DIGEST
        or prompt_file["digest_error"] is not None
        or prompt_file["uid"] != 992
        or prompt_file["gid"] != 992
        or prompt_file["mode"] != "600"
        or prompt_file["nlink"] != 1
        or prompt_file["size"] != 737
    ):
        raise AdmissionEvidenceError("V2 reset rebuilt snapshot changed")


def _verify_store_file(value: Mapping[str, Any]) -> None:
    if (
        value["path"] != _SESSION_STORE
        or value["exists"] is not True
        or value["type"] != "file"
        or not isinstance(value["digest"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value["digest"]) is None
        or value["digest_error"] is not None
        or value["uid"] != 992
        or value["gid"] != 992
        or value["mode"] != "600"
        or value["nlink"] != 1
        or type(value["inode"]) is not int
        or value["inode"] <= 0
        or type(value["size"]) is not int
        or value["size"] <= 0
    ):
        raise AdmissionEvidenceError("V2 reset session store changed")
