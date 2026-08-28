#!/usr/bin/env python3
"""Observe native plugin enable once under the exact V3 protected profile."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe as v3_base

combined = v3_base.combined
p37c = v3_base.p37c
v1_route = v3_base.v1_route

_HARNESS = Path("/run/aragorn-harness.json")
_OUTPUT = Path(
    "/evidence/runtime-action-worker-final-combined-v3-plugin-enable-systemd.json"
)
_ADMISSION = Path("/src/benchmark/admission/openclaw-v2026.7.1")
_SOURCE_PROBE = _ADMISSION / "protected-plugin-enable-probe.mjs"
_TRANSFORMED_PROBE = _ADMISSION / "protected-plugin-enable-v3-probe.mjs"
_ROUTE = "ADM-02/update/plugin-enable-activation"
_ROUTE_ROOT = Path("/route-input/plugin-enable-activation")
_ROUTE_PROBE = _ROUTE_ROOT / "protected-plugin-enable-v3-probe.mjs"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_SOURCE_PROBE_DIGEST = (
    "sha256:b31dc052d9eaffb4712de2a716f958afeb54399452aaaf47a714ee216da1ed92"
)
_TRANSFORMED_PROBE_DIGEST = (
    "sha256:5b4f38b55770f51071f467072f186a316feb8ea0373c5621a6ceb3e7edb4489a"
)
_ROUTES = {
    _ROUTE: {
        "files": ("protected-plugin-enable-v3-probe.mjs",),
        "probe": "protected-plugin-enable-v3-probe.mjs",
        "schema": "aragorn/openclaw-protected-plugin-enable-observation/v1",
    }
}
_EXPECTED_BUNDLE = {
    "protected-plugin-enable-v3-probe.mjs": {
        "bytes": 23_594,
        "digest": _TRANSFORMED_PROBE_DIGEST,
    }
}
_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-"
    "plugin-enable-systemd-observation/v1"
)
_HARNESS_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-plugin-enable-systemd-harness/v1"
)
_AUTHORITY = (
    "BOUND_FINAL_COMBINED_V3_RAW_PLUGIN_ENABLE_OBSERVATION_ONLY_"
    "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
    "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "INSTALL_POLICY_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_SQLITE_LOGICAL_STATE_STORE_EQUIVALENCE_NO_WRITE_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
_ELIGIBILITY_KEYS = v3_base._ELIGIBILITY_KEYS
_ORIGINAL_HARNESS = v3_base._ORIGINAL_HARNESS
_ORIGINAL_PREPARE_GATEWAY = v3_base._ORIGINAL_PREPARE_GATEWAY
_ORIGINAL_COHERENT_CASE = v3_base._ORIGINAL_COHERENT_CASE
_STAGE = "BOOTSTRAP"
_ROUTE_OBSERVATION: dict[str, Any] | None = None


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    combined._expect(condition, message)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _custody(record: dict[str, Any]) -> dict[str, Any]:
    return {key: record["stat"][key] for key in ("gid", "mode", "nlink", "type", "uid")}


def _route_input_volume_name(
    document: dict[str, Any], source_commit: str
) -> str | None:
    return combined._ephemeral_input_volume_name(
        document,
        source_commit,
        stem="route_input",
        destination="/route-input",
        name_pattern=(
            r"aragorn-phase3-final-combined-v3-plugin-enable-"
            r"route-input-([1-9][0-9]*)"
        ),
        role="final-combined-v3-plugin-enable-route-input",
    )


def _harness() -> dict[str, Any]:
    retained = p37c._stable_document_snapshot(_HARNESS)
    document = retained["document"]
    _expect(
        document.get("schema") == _HARNESS_SCHEMA
        and document.get("image_reference")
        == "aragorn-phase3-final-combined-v3-plugin-enable-systemd"
        and document.get("profile_label") == "phase3-final-combined-v3-plugin-enable",
        "outer V3 plugin-enable harness identity changed",
    )
    normalized = json.loads(p37c.canonical_json(document))
    normalized["schema"] = (
        "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
    )
    normalized["image_reference"] = "aragorn-phase3-final-combined-v2-systemd"
    normalized["profile_label"] = "phase3-final-combined-v2"
    descriptor, name = tempfile.mkstemp(prefix="aragorn-v3-enable-harness-", dir="/run")
    path = Path(name)
    try:
        remaining = memoryview(p37c.canonical_json(normalized))
        while remaining:
            written = os.write(descriptor, remaining)
            _expect(written > 0, "normalized V3 harness write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        with (
            mock.patch.object(combined, "_HARNESS", path),
            mock.patch.object(combined, "_PARENT_IMAGE", _PARENT_IMAGE),
            mock.patch.object(
                combined, "_route_input_volume_name", _route_input_volume_name
            ),
        ):
            base = _ORIGINAL_HARNESS()
    finally:
        path.unlink(missing_ok=True)
    _expect(base["document"] == normalized, "normalized V3 harness changed")
    return retained


def _artifacts() -> dict[str, Any]:
    parent = v3_base._PARENT_ARTIFACTS()
    config, config_file = combined._canonical_source(v3_base._CONFIG)
    profile = v3_base._profile_snapshot()
    lock, lock_file = combined._canonical_source(v3_base._LOCK)
    skill = combined._skill_snapshot()
    activator_source = p37c._file(v3_base._ACTIVATOR_SOURCE)
    activator = p37c._file(v3_base._ACTIVATOR)
    preflight_source = p37c._file(Path("/src/src/aragorn/runtime_action_worker.py"))
    preflight = p37c._file(v3_base._PREFLIGHT)
    policy_command = v3_base._policy_command()
    source = p37c._file(_SOURCE_PROBE)
    transformed = p37c._file(_TRANSFORMED_PROBE)
    runtime = p37c._file(_ROUTE_PROBE)
    _expect(
        activator_source["digest"] == activator["digest"] == v3_base._ACTIVATOR_DIGEST
        and activator_source["bytes"] == activator["bytes"] == 30_504
        and _custody(activator_source)
        == {"gid": 0, "mode": "0555", "nlink": 1, "type": "file", "uid": 0}
        and _custody(activator)
        == {"gid": 0, "mode": "0755", "nlink": 1, "type": "file", "uid": 0}
        and preflight_source["digest"]
        == preflight["digest"]
        == v3_base._PREFLIGHT_DIGEST
        and preflight_source["bytes"] == preflight["bytes"] == 37_878
        and _custody(preflight_source)
        == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0}
        and _custody(preflight)
        == {"gid": 0, "mode": "0644", "nlink": 1, "type": "file", "uid": 0},
        "V3 activator or preflight source/install custody changed",
    )

    plugin = {}
    for name, digest in v3_base._PLUGIN_DIGESTS.items():
        item = p37c._file(p37c.p37b._PLUGIN / name)
        _expect(
            item["digest"] == digest
            and _custody(item)
            == {"gid": 0, "mode": "0644", "nlink": 1, "type": "file", "uid": 0},
            f"V3 Aragorn plugin changed: {name}",
        )
        plugin[name] = item

    configuration = lock["deployment_bindings"]["configuration"]
    activation = lock["deployment_bindings"]["activation_contract"]
    policy = lock["deployment_bindings"]["plugin_install_policy"]
    installed_runtime = lock["installed_runtime"]
    _expect(
        config_file["source"]["digest"] == v3_base._CONFIG_DIGEST
        and config_file["source"]["bytes"] == 2_160
        and config_file["canonical_digest"] == v3_base._CONFIG_CANONICAL_DIGEST
        and config_file["canonical_bytes"] == 2_159
        and profile["file"]["source"]["digest"] == v3_base._PROFILE_DIGEST
        and profile["file"]["source"]["bytes"] == 5_302
        and profile["file"]["canonical_digest"] == v3_base._PROFILE_CANONICAL_DIGEST
        and profile["file"]["canonical_bytes"] == 5_301
        and lock_file["source"]["digest"] == v3_base._LOCK_DIGEST
        and lock_file["source"]["bytes"] == 7_620
        and lock_file["canonical_digest"] == v3_base._LOCK_CANONICAL_DIGEST
        and lock_file["canonical_bytes"] == 7_619
        and config["skills"]["activation"]["authority"] == "external"
        and config["skills"]["activation"]["sources"]
        == [
            {
                "filePath": str(v3_base._SKILL),
                "name": "template-skill",
                "sha256": v3_base._SKILL_DIGEST.removeprefix("sha256:"),
            }
        ]
        and config["agents"]["defaults"]["sandbox"]["mode"] == "off"
        and config["skills"]["load"]["watch"] is False
        and config["tools"]
        == {
            "alsoAllow": ["aragorn_runtime_create", "read"],
            "deny": ["session_status"],
            "fs": {"workspaceOnly": True},
            "profile": "minimal",
        }
        and config["security"]["installPolicy"] == v3_base._EXPECTED_INSTALL_POLICY
        and activation
        == {
            "activator": {
                "digest": v3_base._ACTIVATOR_DIGEST,
                "path": str(v3_base._ACTIVATOR),
            },
            "preflight": {
                "digest": v3_base._PREFLIGHT_DIGEST,
                "path": str(v3_base._PREFLIGHT),
            },
            "tool_policy": {
                "also_allow": ["aragorn_runtime_create", "read"],
                "deny": ["session_status"],
                "filesystem_workspace_only": True,
                "profile": "minimal",
            },
        }
        and configuration
        == {
            "bytes": 2_160,
            "canonical_bytes": 2_159,
            "canonical_digest": v3_base._CONFIG_CANONICAL_DIGEST,
            "deployment_materialization": "canonical_json(config)_without_trailing_lf",
            "digest": v3_base._CONFIG_DIGEST,
            "path": (
                "benchmark/admission/openclaw-v2026.7.1/"
                "protected-final-combined-config-v3.json"
            ),
        }
        and policy
        == {
            "command": {
                "bytes": policy_command["bytes"],
                "digest": policy_command["digest"],
                "gid": policy_command["stat"]["gid"],
                "mode": policy_command["stat"]["mode"],
                "nlink": policy_command["stat"]["nlink"],
                "path": str(v3_base._POLICY_COMMAND),
                "type": policy_command["stat"]["type"],
                "uid": policy_command["stat"]["uid"],
            },
            "decision": {
                "decision": "block",
                "protocolVersion": 1,
                "reason": "plugin installs disabled by Aragorn protected profile",
            },
            "enabled": True,
            "exec": v3_base._EXPECTED_INSTALL_POLICY["exec"],
            "targets": ["plugin"],
        }
        and installed_runtime["volume"] == v3_base._RUNTIME_VOLUME
        and installed_runtime["runtime_tree"]["tree_digest"] == v3_base._RUNTIME_DIGEST
        and installed_runtime["openclaw_digest"] == v3_base._ENTRYPOINT_DIGEST
        and installed_runtime["version_output"] == "OpenClaw 2026.7.1 (7fa98d8)",
        "V3 configuration, profile, lock, policy, or runtime binding changed",
    )

    _expect(
        source["bytes"] == 23_594
        and source["digest"] == _SOURCE_PROBE_DIGEST
        and transformed["bytes"] == runtime["bytes"] == 23_594
        and transformed["digest"] == runtime["digest"] == _TRANSFORMED_PROBE_DIGEST
        and _custody(source)
        == _custody(transformed)
        == _custody(runtime)
        == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0},
        "V3 plugin-enable source/transform/runtime custody changed",
    )
    return {
        **parent,
        "final_combined_v3_plugin_enable": {
            "activator": activator,
            "activator_source": activator_source,
            "preflight": preflight,
            "preflight_source": preflight_source,
            "policy_command": policy_command,
            "config": {"document": config, "file": config_file},
            "profile": profile,
            "runtime_lock": {"document": lock, "file": lock_file},
            "installed_runtime": installed_runtime,
            "skill": skill,
            "plugin": plugin,
            "plugin_enable_probe": {
                "checked_in_source": source,
                "transformed_source": transformed,
                "runtime": runtime,
                "transform": {
                    "configuration_digest": {
                        "from": (
                            "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
                        ),
                        "to": v3_base._CONFIG_CANONICAL_DIGEST,
                        "occurrences": 2,
                    },
                    "configuration_bytes": {
                        "from": 1_880,
                        "to": 2_159,
                        "occurrences": 1,
                    },
                    "self_check_key": {
                        "from": "current_v2_configuration_pinned",
                        "to": "current_v3_configuration_pinned",
                        "occurrences": 1,
                    },
                },
            },
            "collector": {
                "capture_recipe": p37c._file(
                    Path(
                        "/src/scripts/capture_runtime_action_worker_final_combined_v3_"
                        "plugin_enable_systemd.sh"
                    )
                ),
                "dockerfile": p37c._file(
                    Path(
                        "/src/benchmark/runtime-action-worker-final-combined-v3-"
                        "plugin-enable-systemd/Dockerfile"
                    )
                ),
                "probe": p37c._file(Path(__file__).resolve()),
                "inherited_v3_contract_helpers": p37c._file(
                    Path(v3_base.__file__).resolve()
                ),
                "inherited_combined_base": p37c._file(
                    Path(
                        "/src/scripts/"
                        "runtime_action_worker_final_combined_v2_systemd_probe.py"
                    )
                ),
                "inherited_route_injector": p37c._file(
                    Path(
                        "/src/scripts/"
                        "runtime_action_worker_final_route_systemd_probe.py"
                    )
                ),
            },
        },
    }


def _probe_bundle() -> list[dict[str, Any]]:
    specification = _ROUTES[_ROUTE]
    actual_files = []
    actual_directories = []
    for path in _ROUTE_ROOT.rglob("*"):
        metadata = path.lstat()
        relative = str(path.relative_to(_ROUTE_ROOT))
        _expect(not stat.S_ISLNK(metadata.st_mode), "V3 enable route bundle symlink")
        if stat.S_ISREG(metadata.st_mode):
            actual_files.append(relative)
        elif stat.S_ISDIR(metadata.st_mode):
            actual_directories.append(relative)
        else:
            _expect(False, "V3 enable route bundle special file")
    _expect(
        tuple(sorted(actual_files)) == tuple(sorted(specification["files"]))
        and actual_directories == [],
        "V3 plugin-enable route bundle inventory changed",
    )
    record = p37c._file(_ROUTE_PROBE)
    _expect(
        _custody(record)
        == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0}
        and {key: record[key] for key in ("bytes", "digest")}
        == _EXPECTED_BUNDLE[_ROUTE_PROBE.name],
        "V3 plugin-enable route input changed",
    )
    return [
        {
            "name": _ROUTE_PROBE.name,
            "bytes": record["bytes"],
            "digest": record["digest"],
        }
    ]


def _prepare_gateway(
    gateway_uid: int,
    gateway_gid: int,
    worker_uid: int,
    skill_name: str,
    skill_raw: bytes,
) -> tuple[dict[str, Any], dict[str, str], Path, str]:
    prepared = _ORIGINAL_PREPARE_GATEWAY(
        gateway_uid, gateway_gid, worker_uid, skill_name, skill_raw
    )
    _expect(
        (gateway_uid, gateway_gid, worker_uid, skill_name)
        == (992, 992, 997, "template-skill"),
        "V3 plugin-enable gateway identity changed",
    )
    for path in (
        p37c.p37b._GATEWAY_STATE / "extensions",
        p37c.p37b._GATEWAY_STATE / "skills",
        p37c.p37b._GATEWAY_STATE / "plugin-skills",
        p37c.p37b._GATEWAY_HOME / ".agents" / "skills",
        p37c.p37b._GATEWAY_WORKSPACE / ".agents" / "skills",
        p37c.p37b._GATEWAY_WORKSPACE / "skills",
    ):
        p37c.p37b._mkdir(path, gateway_uid, gateway_gid, 0o700)
    return prepared


def _run_route(tokens: dict[str, str], gateway_pid: int) -> dict[str, Any]:
    harness = {"document": {"probe_bundle": _probe_bundle()}}
    with (
        mock.patch.object(v1_route, "_ROUTES", _ROUTES),
        mock.patch.object(v1_route, "_PROBE_ROOT", _ROUTE_ROOT),
        mock.patch.object(v1_route, "_SELECTED_ROUTE", _ROUTE),
    ):
        return v1_route._run_route(tokens, harness, gateway_pid)


def _coherent_case(**kwargs: Any) -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _set_stage("P3_7C_COHERENT_ACTION")
    coherent = _ORIGINAL_COHERENT_CASE(**kwargs)
    _set_stage("ADM_02_PLUGIN_ENABLE_ACTIVATION")
    gateway_pid = kwargs["stack"]["pids"][p37c._GATEWAY_UNIT]
    _ROUTE_OBSERVATION = {
        **_run_route(kwargs["tokens"], gateway_pid),
        "gateway_pid_binding": {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{gateway_pid}/ns/mnt",
            "pid": gateway_pid,
            "unit": p37c._GATEWAY_UNIT,
        },
        "stack_before": kwargs["stack"],
    }
    return coherent


def _observation_decision(observed: bool) -> dict[str, Any]:
    return {
        "status": (
            "FINAL_COMBINED_V3_ACTION_OBSERVED_PROFILE_NOT_TESTED"
            if observed
            else "FINAL_COMBINED_V3_ACTION_NOT_OBSERVED_PROFILE_NOT_TESTED"
        ),
        "p3_7c_activation_action_observed": observed,
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in sorted(_ELIGIBILITY_KEYS)},
    }


def _decision(status: str) -> dict[str, Any]:
    _expect(status in {"NOT_TESTED", "OBSERVED"}, "V3 enable route status changed")
    return {
        "status": (
            "FINAL_COMBINED_V3_PLUGIN_ENABLE_OBSERVED_PROFILE_NOT_TESTED"
            if status == "OBSERVED"
            else "FINAL_COMBINED_V3_PLUGIN_ENABLE_NOT_TESTED_PROFILE_NOT_TESTED"
        ),
        "route_observation_status": status,
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in sorted(_ELIGIBILITY_KEYS)},
    }


def _collect() -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _ROUTE_OBSERVATION = None
    if os.environ.get("OPENCLAW_TEST_FAST") is not None:
        raise combined.openclaw.ProbeError("OPENCLAW_TEST_FAST must be absent")
    _set_stage("FINAL_COMBINED_V3")
    with (
        mock.patch.object(combined, "_HARNESS", _HARNESS),
        mock.patch.object(combined, "_CONFIG", v3_base._CONFIG),
        mock.patch.object(combined, "_PROFILE", v3_base._PROFILE),
        mock.patch.object(combined, "_LOCK", v3_base._LOCK),
        mock.patch.object(combined, "_PARENT_IMAGE", _PARENT_IMAGE),
        mock.patch.object(combined, "_CONFIG_DIGEST", v3_base._CONFIG_DIGEST),
        mock.patch.object(combined, "_PROFILE_DIGEST", v3_base._PROFILE_DIGEST),
        mock.patch.object(combined, "_LOCK_DIGEST", v3_base._LOCK_DIGEST),
        mock.patch.object(combined, "_ACTIVATOR_DIGEST", v3_base._ACTIVATOR_DIGEST),
        mock.patch.object(combined, "_SCHEMA", _SCHEMA),
        mock.patch.object(combined, "_AUTHORITY", _AUTHORITY),
        mock.patch.object(combined, "_LIMITATIONS", _LIMITATIONS),
        mock.patch.object(combined, "_harness", _harness),
        mock.patch.object(combined, "_profile_snapshot", v3_base._profile_snapshot),
        mock.patch.object(combined, "_artifacts", _artifacts),
        mock.patch.object(combined, "_prepare_gateway", _prepare_gateway),
        mock.patch.object(combined, "_observation_decision", _observation_decision),
        mock.patch.object(combined, "_set_stage", _set_stage),
        mock.patch.object(p37c, "_INSTALLED", v3_base._v3_installed()),
        mock.patch.object(p37c, "_coherent_case", _coherent_case),
    ):
        composition = combined._collect()
    _expect(_ROUTE_OBSERVATION is not None, "V3 plugin-enable route did not execute")
    status = _ROUTE_OBSERVATION["route"]["status"]
    _expect(
        composition["decision"]["status"]
        == "FINAL_COMBINED_V3_ACTION_OBSERVED_PROFILE_NOT_TESTED"
        and composition["decision"]["route_pass_count"] == 0
        and composition["decision"]["route_fail_count"] == 0
        and composition["decision"]["route_not_tested_count"] == 21
        and all(composition["decision"][key] is False for key in _ELIGIBILITY_KEYS),
        "V3 plugin-enable composition claim ceiling changed",
    )
    _set_stage("OBSERVATION_ASSEMBLY")
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "route_id": _ROUTE,
        "route_observation": _ROUTE_OBSERVATION,
        "composition": composition,
        "harness": _harness(),
        "source_artifacts": {
            "collector": p37c._file(Path(__file__).resolve()),
            "checked_in_probe": p37c._file(_SOURCE_PROBE),
            "transformed_probe": p37c._file(_TRANSFORMED_PROBE),
            "probe_bundle": _probe_bundle(),
            "inherited_v3_contract_base": p37c._file(Path(v3_base.__file__).resolve()),
            "inherited_combined_base": p37c._file(
                Path(
                    "/src/scripts/runtime_action_worker_final_combined_v2_systemd_probe.py"
                )
            ),
            "inherited_route_injector": p37c._file(
                Path("/src/scripts/runtime_action_worker_final_route_systemd_probe.py")
            ),
        },
        "decision": _decision(status),
        "limitations": _LIMITATIONS,
    }


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "route_id": _ROUTE,
        "decision": _decision("NOT_TESTED"),
        "failure": {
            "code": "LIVE_CAPTURE_FAILED_CLOSED",
            "stage": _STAGE,
            "type": type(exc).__name__,
            "message": str(exc),
        },
        "limitations": ["NO_ROUTE_OR_ADMISSION_AUTHORITY_FROM_FAILED_CAPTURE"],
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print(
            "usage: runtime_action_worker_final_combined_v3_"
            "plugin_enable_systemd_probe.py",
            file=sys.stderr,
        )
        return 64
    try:
        result = _collect()
        status = 0
    except Exception as exc:  # noqa: BLE001 - failed captures self-describe
        result = _failure(exc)
        status = 2
    p37c._publish(_OUTPUT, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
