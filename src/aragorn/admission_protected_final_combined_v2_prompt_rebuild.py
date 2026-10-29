"""Add one prompt-rebuild PASS to the verified V2 fresh-session route."""

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

from . import admission_protected_final_combined_v2_fresh_session_reset as parent
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/reload/missing-prompt-blob-rebuild"
_PARENT_ROUTE = "ADM-02/reload/fresh-session-reset"
_PARENT_DIGEST = (
    "sha256:f626a85b45c7cbd6650c1b8218ffccbc795887e02774cd5de1eef2e85ef0364d"
)
_PARENT_VERIFIER = (
    "sha256:ce54e514bac8fa642cce4b6a24a144c8b380621fae7154de1d4fc43206e11119"
)
_EVIDENCE = {
    "bytes": 481_904,
    "canonical_bytes": 481_903,
    "canonical_digest": (
        "sha256:45b3511aa5d7c51792cd814a8d18595186d95e4fc43cb072ca2ac77a562f4869"
    ),
    "digest": (
        "sha256:20de45e1e21796b10de08c181e503e705c500c07f161ea2a519184742c4cdfe0"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "missing-prompt-blob-rebuild-systemd-p3-final-mounted-2026-08-22.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 44_721,
    "canonical_digest": (
        "sha256:f865b3c8a4198eae8795ecd8b5a3d3906c0289caef2171b6a0bc1476b2fcea82"
    ),
    "digest": (
        "sha256:4a90dc587e29b134899427fa5664bea15fc1d6aafbe8bd1b8ef2bad4648b743a"
    ),
}
_SOURCE = {
    "commit": "b134447599766b237a5f7f0b8b77cc2543f98c23",
    "parent": "2d59385a291273e515e013751429d93c3af7c31d",
    "tree": "67f1cf1757b7f57efadece05142b1ba1304d6754",
}
_RETENTION = {
    "commit": "e6e3ba9b880363926486f1207303193b7ae20ecc",
    "parent": _SOURCE["commit"],
    "tree": "b719949c8eab3fa655e943d6b20672b3d078576e",
}
_RETENTION_BLOB = "97a39613ce729f56815aa04652f55ed469996065"
_IMAGE = "sha256:293a3407dee23bb7e4f8bcd2aa885c78558fb27293ecd8c8bb06429972a89561"
_IMAGE_LINEAGE_DIGEST = (
    "sha256:d4ee3db6ffbc12dc385fc9c4f5b76d3fe595a58f097dee35f4b25393bf44cd51"
)
_HOST_CONFIG_DIGEST = (
    "sha256:6dff5d0a4e8d47a0e853d11bdeb5d931d07d9f2d353761c8715413c44fe56c3e"
)
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-45367"
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 9_473,
        "digest": (
            "sha256:9f113dc9477fb691b29e8f57491bfaa051cd52c8b174a9fcfe7b12e3fea9725c"
        ),
    },
    "helper": {
        "bytes": 16_324,
        "digest": (
            "sha256:13baaac69f323603f2029eb1dc675f7438d51e0b9440befe775758a38c09a321"
        ),
    },
    "materializer": dict(parent._SOURCE_ARTIFACTS["materializer"]),
    "probe": {
        "bytes": 16_464,
        "digest": (
            "sha256:9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7"
        ),
    },
    "v1_route_injector": dict(parent._SOURCE_ARTIFACTS["v1_route_injector"]),
}
_PROMPT = (
    b"\n\nThe following skills provide specialized instructions for specific tasks.\n"
    b"Use the read tool to load a skill's file when the task matches its description.\n"
    b"If a skill's <version> differs from a previous turn, re-read its SKILL.md before using it.\n"
    b"When a skill file references a relative path, resolve it against the skill directory "
    b"(parent of SKILL.md / dirname of the path) and use that absolute path in tool commands.\n\n"
    b"<available_skills>\n"
    b"  <skill>\n"
    b"    <name>template-skill</name>\n"
    b"    <description>Replace with description of the skill and when Claude should use it.</description>\n"
    b"    <location>/opt/aragorn/runtime-profile/template-skill/SKILL.md</location>\n"
    b"    <version>sha256:eb685d91de039ed8</version>\n"
    b"  </skill>\n"
    b"</available_skills>"
)
_PROMPT_DIGEST = "sha256:" + hashlib.sha256(_PROMPT).hexdigest()
_PROMPT_PATH = (
    "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/skills-prompts/"
    f"sha256/60/{_PROMPT_DIGEST.removeprefix('sha256:')}.txt"
)
_SESSION_STORE = (
    "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json"
)
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


def verify_openclaw_final_combined_v2_prompt_rebuild(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 2/21 V2 route coverage after both semantic checks."""

    try:
        if _digest(Path(parent.__file__).read_bytes()) != _PARENT_VERIFIER:
            raise AdmissionEvidenceError("V2 prompt parent verifier changed")
        parent_result = parent.verify_openclaw_final_combined_v2_fresh_session_reset(
            evidence_cas=evidence_cas
        )
        if _canonical_digest(parent_result) != _PARENT_DIGEST:
            raise AdmissionEvidenceError("V2 prompt parent qualification changed")
        retained = _verify_retained_evidence()
        raw = parent.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 prompt rebuild"
        )
        if raw != retained:
            raise AdmissionEvidenceError("V2 prompt CAS differs from signed retention")
        evidence = parent.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 prompt rebuild"
        )
        _verify_evidence(evidence)
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
        raise AdmissionEvidenceError(f"invalid V2 prompt evidence: {exc}") from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS"
            if route["id"] in {_PARENT_ROUTE, _ROUTE}
            else "NOT_TESTED",
        }
        for route in parent_result["profile"]["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v2-prompt-rebuild-"
            "route-coverage/v1"
        ),
        "assurance": "TWO_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V2_ROUTES_ONLY",
        "bindings": {
            "parent_qualification_canonical_digest": _PARENT_DIGEST,
            "parent_verifier_implementation_digest": _PARENT_VERIFIER,
            "prompt_rebuild_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": parent.legacy.parent._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(parent.legacy.parent._SIGNATURE),
                },
            },
            "image": _IMAGE,
            "source_artifacts": {
                name: dict(identity) for name, identity in _SOURCE_ARTIFACTS.items()
            },
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in parent.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "TWO_EXACT_DYNAMIC_ROUTE_PASSES_ONLY",
            "NINETEEN_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "TWO_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURES_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 2, "NOT_TESTED": 19},
            "name": parent_result["profile"]["name"],
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_PARENT_ROUTE, _ROUTE],
            "pass_basis": [
                "SIGNED_EXACT_RESET_ROTATION_CLEAR_AND_REBUILD_TRANSITION",
                "SIGNED_EXACT_PROMPT_BLOB_UNLINK_AND_RECONSTRUCTION_TRANSITION",
            ],
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(parent_result["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Mapping[str, Any]) -> str:
    return _digest(parent.legacy.parent.oci_worker_protocol.canonical_json(value))


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    if (
        Path(
            parent.legacy._git(["rev-parse", "--show-toplevel"]).decode().strip()
        ).resolve(strict=True)
        != root
        or parent.legacy._git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 prompt signed repository changed")
    parent._verify_commit(_SOURCE)
    parent._verify_commit(_RETENTION)
    entry = parent.legacy._git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V2 prompt signed tree entry changed")
    raw = parent.legacy._git(["cat-file", "blob", _RETENTION_BLOB], maximum=512 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 prompt signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> None:
    expected_decision = {
        "status": "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED",
        "route_observation_status": "OBSERVED",
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in parent.legacy.parent._ELIGIBILITY_KEYS},
    }
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
        or evidence["recorded_at"] != "2026-08-22T05:39:54.869437Z"
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_"
            "RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or evidence["decision"] != expected_decision
    ):
        raise AdmissionEvidenceError("V2 prompt wrapper changed")

    composition = evidence["composition"]
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    source = composition["action"]["artifacts"]["final_combined_v2"]
    harness = composition["action"]["harness"]["document"]
    lineage = harness["image_lineage"]
    runtime_volume = parent.legacy.parent._RUNTIME["runtime_volume"]
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
        or composition["recorded_at"] != "2026-08-22T05:39:54.869418Z"
        or composition["authority"]
        != (
            "BOUNDED_FINAL_COMBINED_V2_P3_7C_ACTION_OBSERVATION_ONLY_PROFILE_"
            "ROUTES_REMAIN_NOT_TESTED_NOT_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
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
        or profile_before != profile_after
        or profile_before != source["profile"]
        or composition["action"]["inputs"]["gateway_config"]
        != source["config"]["document"]
        or profile["name"] != parent._PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(parent.legacy.parent._ROUTES)
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or harness["source_commit"] != _SOURCE["commit"]
        or harness["image_id"] != _IMAGE
        or harness["run_image_reference"] != _IMAGE
        or harness["parent_image_id"] != parent._PARENT_IMAGE
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != parent._PARENT_IMAGE
        or _canonical_digest(lineage) != _IMAGE_LINEAGE_DIGEST
        or not lineage["added_layers"]
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or lineage["child"]["rootfs_type"] != "layers"
        or lineage["parent"]["rootfs_type"] != "layers"
        or _canonical_digest(harness["host_config"]) != _HOST_CONFIG_DIGEST
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
                "io.aragorn.source-commit": parent.legacy.parent._OPENCLAW["commit"],
                "io.aragorn.source-tree": parent.legacy.parent._OPENCLAW["source_tree"],
            },
            "name": runtime_volume,
            "options": None,
            "scope": "local",
        }
        or harness["route_input_mount"]
        != {
            "destination": "/route-input",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": _ROUTE_VOLUME,
            "type": "volume",
        }
        or harness["route_input_volume_identity"]
        != {
            "driver": "local",
            "labels": {
                "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:45367",
                "dev.aragorn.role": "final-combined-v2-route-input",
                "dev.aragorn.source-commit": _SOURCE["commit"],
            },
            "name": _ROUTE_VOLUME,
            "options": None,
            "scope": "local",
        }
        or composition["action"]["runtime"]
        != {
            "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "entrypoint_digest": parent.legacy.parent._RUNTIME["entrypoint_digest"],
            "expected_version": parent.legacy.parent._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": parent.legacy.parent._RUNTIME_TREE,
            "version_output": parent.legacy.parent._RUNTIME["version_output"],
        }
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": parent.legacy.parent._RUNTIME["runtime_digest"],
            "runtime_volume": runtime_volume,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": parent._SOURCES["skill"]["digest"],
        }
    ):
        raise AdmissionEvidenceError("V2 prompt profile or harness changed")
    parent._verify_source_file(
        source["config"]["file"], parent._SOURCES["configuration"]
    )
    parent._verify_source_file(source["profile"]["file"], parent._SOURCES["profile"])
    parent._verify_source_file(
        source["runtime_lock"]["file"], parent._SOURCES["runtime_lock"]
    )
    parent._verify_file(source["skill"]["file"], parent._SOURCES["skill"])
    if any(
        parent.legacy._canonical_digest(source[name]["document"])
        != parent._SOURCES[label]["canonical_digest"]
        for name, label in (
            ("config", "configuration"),
            ("profile", "profile"),
            ("runtime_lock", "runtime_lock"),
        )
    ):
        raise AdmissionEvidenceError("V2 prompt embedded source document changed")
    for name, identity in parent._PLUGIN.items():
        parent._verify_file(source["plugin"][name], identity)
    for name in ("collector", "materializer", "v1_route_injector"):
        parent._verify_file(evidence["source_artifacts"][name], _SOURCE_ARTIFACTS[name])
    bundle = evidence["source_artifacts"]["probe_bundle"]
    if bundle != [
        {**_SOURCE_ARTIFACTS["helper"], "name": "protected-observation-v1.mjs"},
        {**_SOURCE_ARTIFACTS["probe"], "name": "protected-prompt-rebuild-probe.mjs"},
    ]:
        raise AdmissionEvidenceError("V2 prompt probe bundle changed")

    observation = evidence["route_observation"]
    document = _decode_route_raw(observation["raw"])
    if (
        document != observation["document"]
        or observation["route"] != document["route"]
        or observation["bundle"] != bundle
    ):
        raise AdmissionEvidenceError("V2 prompt nested custody changed")
    _verify_execution(observation, harness["container_id"])
    if not (
        parent.legacy._parse_time(document["recorded_at"])
        <= parent.legacy._parse_time(observation["execution"]["completed_at"])
        <= parent.legacy._parse_time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("V2 prompt execution custody changed")
    _verify_prompt(document, harness["container_id"], evidence["recorded_at"])


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode(),
        object_pairs_hook=parent.legacy.parent._reject_duplicates,
        parse_constant=parent.legacy.parent._reject_constant,
    )
    canonical = parent.legacy.parent.oci_worker_protocol.canonical_json(document)
    if (
        len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not False
    ):
        raise AdmissionEvidenceError("V2 prompt raw identity changed")
    return document


def _verify_execution(observation: Mapping[str, Any], container_id: str) -> None:
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    document = observation["document"]
    stack = observation["stack_before"]
    units = stack["units"]
    pid = 2696
    unit_names = {
        "aragorn-agent-gateway.service",
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    process = stack["processes"]["aragorn-agent-gateway.service"]
    nested_process = document["action"]["prerequisites"]["gateway_process_before"]
    if (
        not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
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
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _digest(b""), "excerpt": ""}
        or set(units) != unit_names
        or any(
            unit["ControlGroup"] != f"/docker/{container_id}/system.slice/{name}"
            for name, unit in units.items()
        )
        or stack["pids"]["aragorn-agent-gateway.service"] != pid
        or stack["gateway_listener"]["pid"] != pid
        or units["aragorn-agent-gateway.service"]["MainPID"] != str(pid)
        or process["pid"] != pid
        or process["cmdline"] != ["openclaw-gateway"]
        or process["uids"] != [992, 992, 992, 992]
        or process["gids"] != [992, 992, 992, 992]
        or process["groups"] != [992]
        or process["capabilities_effective"] != "0000000000000000"
        or process["no_new_privileges"] != 1
        or nested_process["pid"] != process["pid"]
        or nested_process["cmdline"] != process["cmdline"]
        or nested_process["start_time_ticks"] != process["start_time_ticks"]
        or nested_process["effective_capabilities"] != process["capabilities_effective"]
        or nested_process["no_new_privileges"] != str(process["no_new_privileges"])
        or not (
            parent.legacy._parse_time(execution["started_at"])
            <= parent.legacy._parse_time(
                document["action"]["commands"][0]["started_at"]
            )
            <= parent.legacy._parse_time(document["recorded_at"])
            <= parent.legacy._parse_time(execution["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("V2 prompt execution boundary changed")


def _verify_prompt(
    document: Mapping[str, Any], container_id: str, outer_recorded_at: str
) -> None:
    if (
        document["schema"] != "aragorn/openclaw-protected-prompt-rebuild-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digests"]
        != {
            "helper": _SOURCE_ARTIFACTS["helper"]["digest"],
            "probe": _SOURCE_ARTIFACTS["probe"]["digest"],
        }
        or document["runtime_binding"]
        != {
            "commit": parent.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": parent.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": parent.legacy.parent._RUNTIME_TREE["tree_digest"],
            "version": parent.legacy.parent._OPENCLAW["version"],
        }
        or document["route"]
        != {
            "action_id": "missing-prompt-blob-rebuild",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
    ):
        raise AdmissionEvidenceError("V2 prompt observation identity changed")
    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        action["id"] != "missing-prompt-blob-rebuild"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["session_entry_absent_before"] is not True
        or after["boundary_after"] != before["boundary_before"]
        or after["config_lock_after"] != before["config_lock_before"]
        or after["config_tree_after"] != before["config_tree_before"]
        or after["gateway_process_after"] != before["gateway_process_before"]
        or after["openclaw_after"] != before["openclaw_before"]
        or after["protected_root_trees_after"] != before["protected_root_trees_before"]
        or after["runtime_tree_after"] != before["runtime_tree_before"]
        or after["target_after"] != before["target_before"]
    ):
        raise AdmissionEvidenceError("V2 prompt protected state changed")
    _verify_static(before, container_id)
    _verify_commands(action, document["run_nonce"], document["recorded_at"])
    _verify_rebuild(after)
    if parent.legacy._parse_time(document["recorded_at"]) >= parent.legacy._parse_time(
        outer_recorded_at
    ):
        raise AdmissionEvidenceError("V2 prompt recording order changed")


def _verify_static(before: Mapping[str, Any], container_id: str) -> None:
    boundary = before["boundary_before"]
    config = boundary["configuration"]
    gateway = before["gateway_process_before"]
    target = before["target_before"]
    _verify_read_only_mount(
        boundary["runtime"],
        target="/runtime",
        root=(
            f"/docker/volumes/{parent.legacy.parent._RUNTIME['runtime_volume']}/_data"
        ),
        entries=["bin", "lib"],
        mode="755",
        nlink=4,
    )
    _verify_read_only_mount(
        boundary["probe"],
        target="/route-input",
        root=f"/docker/volumes/{_ROUTE_VOLUME}/_data",
        entries=[
            "cron-rescan",
            "fresh-session-reset",
            "missing-prompt-blob-rebuild",
            "session-snapshot-consumer",
        ],
        mode="555",
        nlink=6,
    )
    root_paths = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": ("/var/lib/aragorn-agent-gateway/workspace/.agents/skills"),
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    if set(boundary["roots"]) != set(root_paths):
        raise AdmissionEvidenceError("V2 prompt protected roots changed")
    for name, path in root_paths.items():
        value = boundary["roots"][name]
        observation = value["observation"]
        if (
            value["ready"] is not True
            or value["writable"] is not True
            or observation["path"] != path
            or observation["exists"] is not True
            or observation["type"] != "directory"
            or observation["uid"] != 992
            or observation["gid"] != 992
            or observation["mode"] != "700"
            or observation["nlink"] != 2
            or observation["entries"] != []
            or observation["entry_count"] != 0
            or observation["entries_truncated"] is not False
        ):
            raise AdmissionEvidenceError("V2 prompt protected roots changed")
    config_mount = config["mount"]
    config_entry = config_mount["entry"]
    config_file = config["file"]
    target_root = target["root"]
    target_file = target["entries"][0]
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or config["canonical_digest"]
        != parent._SOURCES["configuration"]["canonical_digest"]
        or parent.legacy._canonical_digest(config["document"])
        != parent._SOURCES["configuration"]["canonical_digest"]
        or config_file["digest"] != parent._SOURCES["configuration"]["canonical_digest"]
        or config_file["path"]
        != "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
        or config_file["exists"] is not True
        or config_file["type"] != "file"
        or config_file["digest_error"] is not None
        or config_file["size"] != parent._SOURCES["configuration"]["canonical_bytes"]
        or config_file["uid"] != 992
        or config_file["gid"] != 0
        or config_file["mode"] != "400"
        or config_file["nlink"] != 1
        or config_mount["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or config_mount["explicit"] is not True
        or config_mount["read_only"] is not True
        or config_mount["ready"] is not True
        or config_mount["error"] is not None
        or config_mount["records"]
        != [
            {
                "filesystem": "ramfs",
                "mount_options": ["nodev", "noexec", "nosuid", "relatime", "ro"],
                "mount_point": "/run/credentials/aragorn-agent-gateway.service",
                "root": "/",
                "source": "ramfs",
                "super_options": ["mode=700", "rw"],
            }
        ]
        or config_entry["path"] != "/run/credentials/aragorn-agent-gateway.service"
        or config_entry["exists"] is not True
        or config_entry["type"] != "directory"
        or config_entry["uid"] != 992
        or config_entry["gid"] != 0
        or config_entry["mode"] != "500"
        or config_entry["nlink"] != 2
        or config_entry["entries"] != ["openclaw-config"]
        or config_entry["entry_count"] != 1
        or config_entry["entries_truncated"] is not False
        or before["runtime_tree_before"] != parent.legacy.parent._RUNTIME_TREE
        or before["config_lock_before"]
        != {
            "exists": False,
            "path": "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock",
        }
        or target["tree_digest"]
        != "sha256:38625b40892cc1f5b3cac1dcc6cd0116f8b7f21900a5baa7eeeded0ed2e87ed1"
        or target["ready"] is not True
        or len(target["entries"]) != 1
        or target_root["path"] != "/opt/aragorn/runtime-profile/template-skill"
        or target_root["exists"] is not True
        or target_root["type"] != "directory"
        or target_root["uid"] != 0
        or target_root["gid"] != 0
        or target_root["mode"] != "555"
        or target_root["nlink"] != 2
        or target_root["entries"] != ["SKILL.md"]
        or target_root["entry_count"] != 1
        or target_root["entries_truncated"] is not False
        or target_file["path"] != "SKILL.md"
        or target_file["exists"] is not True
        or target_file["type"] != "file"
        or target_file["digest"] != parent._SOURCES["skill"]["digest"]
        or target_file["digest_error"] is not None
        or target_file["size"] != parent._SOURCES["skill"]["bytes"]
        or target_file["uid"] != 0
        or target_file["gid"] != 0
        or target_file["mode"] != "444"
        or target_file["nlink"] != 1
        or gateway["pid"] != 2696
        or gateway["hostname"] != container_id[:12]
        or gateway["cmdline"] != ["openclaw-gateway"]
        or gateway["effective_capabilities"] != "0000000000000000"
        or gateway["no_new_privileges"] != "1"
        or gateway["seccomp"] != "2"
        or before["openclaw_before"]["digest"]
        != parent.legacy.parent._RUNTIME["entrypoint_digest"]
    ):
        raise AdmissionEvidenceError("V2 prompt static boundary changed")


def _verify_read_only_mount(
    value: Mapping[str, Any],
    *,
    target: str,
    root: str,
    entries: list[str],
    mode: str,
    nlink: int,
) -> None:
    entry = value["entry"]
    if (
        value["path"] != target
        or value["explicit"] is not True
        or value["read_only"] is not True
        or value["ready"] is not True
        or value["error"] is not None
        or value["records"]
        != [
            {
                "filesystem": "ext4",
                "mount_options": ["nosuid", "relatime", "ro"],
                "mount_point": target,
                "root": root,
                "source": "/dev/vdb1",
                "super_options": ["rw"],
            }
        ]
        or entry["path"] != target
        or entry["exists"] is not True
        or entry["type"] != "directory"
        or entry["uid"] != 0
        or entry["gid"] != 0
        or entry["mode"] != mode
        or entry["nlink"] != nlink
        or entry["entries"] != entries
        or entry["entry_count"] != len(entries)
        or entry["entries_truncated"] is not False
    ):
        raise AdmissionEvidenceError(f"V2 prompt read-only mount changed: {target}")


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
        or len({command["pid"] for command in commands}) != 7
        or any(
            parent.legacy._parse_time(left["completed_at"])
            > parent.legacy._parse_time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or parent.legacy._parse_time(commands[-1]["completed_at"])
        > parent.legacy._parse_time(recorded_at)
    ):
        raise AdmissionEvidenceError("V2 prompt command causality changed")
    parent.legacy._verify_command(
        before["version"],
        [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ],
        expected_pid=before["version"]["pid"],
        stdout_exact=parent.legacy.parent._RUNTIME["version_output"] + "\n",
    )
    for value in (before["system_info_before"], after["system_info_after"]):
        _verify_system(value)
    _verify_turn(after["initial_turn"], "initial", nonce)
    _verify_turn(after["rebuild_turn"], "rebuild", nonce)


def _verify_system(value: Mapping[str, Any]) -> None:
    response = value["response"]
    system = response["value"]
    if (
        response["parsed"] is not True
        or system["pid"] != 2696
        or system["hostname"] != system["machineName"]
        or system["diskPath"] != "/var/lib/aragorn-agent-gateway/state"
    ):
        raise AdmissionEvidenceError("V2 prompt system identity changed")
    parent.legacy._verify_command(
        value["command"],
        parent.legacy._gateway_argv("system.info", "5000"),
        expected_pid=value["command"]["pid"],
        stdout_value=system,
    )


def _verify_turn(turn: Mapping[str, Any], label: str, nonce: str) -> None:
    run_id = f"aragorn-protected-prompt-rebuild-{label}-{nonce}"
    session_key = f"agent:main:aragorn-protected-prompt-rebuild-{nonce}"
    send_value = {"runId": run_id, "status": "started"}
    wait_value = {
        "runId": run_id,
        "status": "error",
        "endedAt": turn["wait"]["response"]["value"]["endedAt"],
        "error": parent.legacy._NETWORK_ERROR,
    }
    if (
        turn["confirmed"] is not True
        or turn["commands"] != [turn["send"]["command"], turn["wait"]["command"]]
        or turn["send"]["response"] != {"parsed": True, "value": send_value}
        or turn["wait"]["response"] != {"parsed": True, "value": wait_value}
        or type(wait_value["endedAt"]) is not int
    ):
        raise AdmissionEvidenceError("V2 prompt terminal turn changed")
    parent.legacy._verify_command(
        turn["send"]["command"],
        parent.legacy._gateway_argv(
            "chat.send",
            "5000",
            {
                "deliver": False,
                "idempotencyKey": run_id,
                "message": f"Inert protected prompt rebuild {label}.",
                "sessionKey": session_key,
                "timeoutMs": 5000,
            },
        ),
        expected_pid=turn["send"]["command"]["pid"],
        stdout_value=send_value,
    )
    parent.legacy._verify_command(
        turn["wait"]["command"],
        parent.legacy._gateway_argv(
            "agent.wait", "12000", {"runId": run_id, "timeoutMs": 10_000}
        ),
        expected_pid=turn["wait"]["command"]["pid"],
        stdout_value=wait_value,
    )


def _verify_snapshot(value: Mapping[str, Any]) -> None:
    blob = value["blob"]
    entry = value["entry"]
    prompt = value["prompt"]
    if (
        _UUID4.fullmatch(entry["session_id"]) is None
        or entry["run_status"] != "timeout"
        or entry["runtime_ms"] != entry["ended_at"] - entry["started_at"]
        or not entry["started_at"] <= entry["ended_at"] <= entry["updated_at"]
        or entry["skill_filter"] != ["template-skill"]
        or entry["skill_names"] != ["template-skill"]
        or type(entry["snapshot_version"]) is not int
        or prompt
        != {
            "bytes": len(_PROMPT),
            "digest": _PROMPT_DIGEST,
            "exact_text": _PROMPT.decode(),
            "storage": "promptRef",
        }
        or blob["bytes"] != len(_PROMPT)
        or blob["digest"] != _PROMPT_DIGEST
        or blob["mode"] != "600"
        or blob["nlink"] != 1
        or blob["path"] != _PROMPT_PATH
        or blob["prompt_ref"]
        != {
            "algorithm": "sha256",
            "bytes": len(_PROMPT),
            "hash": _PROMPT_DIGEST.removeprefix("sha256:"),
            "version": 1,
        }
        or re.fullmatch(r"[1-9][0-9]*", blob["mtime_ns"]) is None
    ):
        raise AdmissionEvidenceError("V2 prompt snapshot changed")


def _verify_snapshot_timing(value: Mapping[str, Any], turn: Mapping[str, Any]) -> None:
    entry = value["entry"]
    blob_ms = int(value["blob"]["mtime_ns"]) // 1_000_000
    wait_ended_ms = turn["wait"]["response"]["value"]["endedAt"]
    send_completed_ms = parent.legacy._epoch_ms(turn["send"]["command"]["completed_at"])
    wait_started_ms = parent.legacy._epoch_ms(turn["wait"]["command"]["started_at"])
    wait_completed_ms = parent.legacy._epoch_ms(turn["wait"]["command"]["completed_at"])
    if not (
        send_completed_ms
        <= entry["started_at"]
        <= entry["ended_at"]
        <= entry["updated_at"]
        <= blob_ms
        <= wait_ended_ms
        <= wait_completed_ms
        and wait_started_ms <= wait_ended_ms
    ):
        raise AdmissionEvidenceError("V2 prompt snapshot timing changed")


def _verify_rebuild(after: Mapping[str, Any]) -> None:
    initial = after["initial_snapshot"]
    rebuilt = after["rebuilt_snapshot"]
    invalidation = after["invalidation"]
    before_store = invalidation["store_before"]
    after_store = invalidation["store_after_rewrite"]
    _verify_snapshot(initial)
    _verify_snapshot(rebuilt)
    _verify_snapshot_timing(initial, after["initial_turn"])
    _verify_snapshot_timing(rebuilt, after["rebuild_turn"])
    initial_blob_ms = int(initial["blob"]["mtime_ns"]) // 1_000_000
    rebuilt_blob_ms = int(rebuilt["blob"]["mtime_ns"]) // 1_000_000
    initial_wait_ms = after["initial_turn"]["wait"]["response"]["value"]["endedAt"]
    rebuild_wait_ms = after["rebuild_turn"]["wait"]["response"]["value"]["endedAt"]
    rebuild_send_ms = parent.legacy._epoch_ms(
        after["rebuild_turn"]["send"]["command"]["started_at"]
    )
    invalidation_started_ms = parent.legacy._epoch_ms(invalidation["started_at"])
    invalidation_completed_ms = parent.legacy._epoch_ms(invalidation["completed_at"])
    store_after_ms = int(after_store["mtime_ns"]) // 1_000_000
    if (
        rebuilt["entry"]["session_id"] != initial["entry"]["session_id"]
        or rebuilt["entry"]["snapshot_version"] != initial["entry"]["snapshot_version"]
        or rebuilt["entry"]["started_at"] <= initial["entry"]["ended_at"]
        or rebuilt["blob"]["prompt_ref"] != initial["blob"]["prompt_ref"]
        or rebuilt["prompt"] != initial["prompt"]
        or not initial["entry"]["ended_at"] <= initial_blob_ms <= initial_wait_ms
        or not rebuild_send_ms <= rebuilt["entry"]["ended_at"]
        or not rebuilt["entry"]["ended_at"] <= rebuilt_blob_ms <= rebuild_wait_ms
        or invalidation["blob_exists_after_unlink"] is not False
        or invalidation["blob_path"] != _PROMPT_PATH
        or before_store["path"] != _SESSION_STORE
        or after_store["path"] != _SESSION_STORE
        or before_store["mode"] != "600"
        or after_store["mode"] != "600"
        or before_store["nlink"] != 1
        or after_store["nlink"] != 1
        or before_store["digest"] != after_store["digest"]
        or before_store["bytes"] != after_store["bytes"]
        or int(after_store["mtime_ns"]) <= int(before_store["mtime_ns"])
        or not invalidation_started_ms <= store_after_ms <= invalidation_completed_ms
        or int(rebuilt["blob"]["mtime_ns"]) <= int(after_store["mtime_ns"])
        or int(after_store["mtime_ns"]) <= int(initial["blob"]["mtime_ns"])
        or parent.legacy._parse_time(
            after["initial_turn"]["wait"]["command"]["completed_at"]
        )
        > parent.legacy._parse_time(invalidation["started_at"])
        or parent.legacy._parse_time(invalidation["started_at"])
        >= parent.legacy._parse_time(invalidation["completed_at"])
        or parent.legacy._parse_time(invalidation["completed_at"])
        > parent.legacy._parse_time(
            after["rebuild_turn"]["send"]["command"]["started_at"]
        )
    ):
        raise AdmissionEvidenceError("V2 prompt reconstruction changed")
