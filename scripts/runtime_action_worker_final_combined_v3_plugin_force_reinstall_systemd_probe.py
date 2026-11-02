#!/usr/bin/env python3
"""Observe the exact V3 native plugin force-reinstall block in the final stack."""

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

import runtime_action_worker_final_combined_v2_systemd_probe as combined
import runtime_action_worker_final_route_systemd_probe as v1_route

p37c = combined.p37c

_HARNESS = Path("/run/aragorn-harness.json")
_OUTPUT = Path(
    "/evidence/runtime-action-worker-final-combined-v3-"
    "plugin-force-reinstall-systemd.json"
)
_ADMISSION = Path("/src/benchmark/admission/openclaw-v2026.7.1")
_CONFIG = _ADMISSION / "protected-final-combined-config-v3.json"
_PROFILE = _ADMISSION / "protected-final-combined-profile-v3.json"
_LOCK = _ADMISSION / "protected-final-combined-runtime-v3.lock.json"
_FORCE_PROBE_SOURCE = _ADMISSION / "protected-plugin-force-reinstall-v3-probe.py"
_FORCE_ROUTE = "ADM-02/update/plugin-force-reinstall"
_FORCE_ID = "aragorn-force-reinstall-fixture"
_ROUTE_ROOT = Path("/route-input/plugin-force-reinstall")
_ACTIVATOR = Path("/usr/libexec/aragorn/activate-runtime-action-worker-host.sh")
_ACTIVATOR_SOURCE = Path(
    "/src/packaging/activate-runtime-action-worker-host-v3.sh"
)
_PREFLIGHT = Path("/usr/lib/aragorn/aragorn/runtime_action_worker.py")
_POLICY_COMMAND = Path("/usr/bin/printf")
_SKILL = Path("/opt/aragorn/runtime-profile/template-skill/SKILL.md")
_PARENT_IMAGE = (
    "sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b"
)
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_RUNTIME_DIGEST = (
    "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154"
)
_ENTRYPOINT_DIGEST = (
    "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
)
_SKILL_DIGEST = (
    "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
)
_ACTIVATOR_DIGEST = (
    "sha256:3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c"
)
_PREFLIGHT_DIGEST = (
    "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873"
)
_POLICY_COMMAND_DIGEST = (
    "sha256:2c7b0151ee3c1ba4e829209f2ff4336de9d97143e22bf87c7448539112139957"
)
_CONFIG_DIGEST = (
    "sha256:2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab"
)
_PROFILE_DIGEST = (
    "sha256:3229bd747088199d8bae074bbc27a415169fa21f86462408434ecdb43c5b2a6c"
)
_LOCK_DIGEST = (
    "sha256:3bbcc6568cf713f9e534f84f7a92e313b5aa357065759bd01b5f24a594fb5822"
)
_CONFIG_CANONICAL_DIGEST = (
    "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
)
_PROFILE_CANONICAL_DIGEST = (
    "sha256:9e73029de2f4e26b8dea9c8ac8bc5bc182c9669b01fb20657ec6177d99d31532"
)
_LOCK_CANONICAL_DIGEST = (
    "sha256:4b58803f600def6a63737e68882cff0de09e3c1780b417c9f93caa8a9d37d43c"
)
_PLUGIN_DIGESTS = {
    "index.js": "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
    "openclaw.plugin.json": (
        "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036"
    ),
    "package.json": (
        "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2"
    ),
}
_EXPECTED_INSTALL_POLICY = {
    "enabled": True,
    "exec": {
        "args": [
            "%s",
            (
                '{"protocolVersion":1,"decision":"block","reason":'
                '"plugin installs disabled by Aragorn protected profile"}'
            ),
        ],
        "command": "/usr/bin/printf",
        "source": "exec",
        "trustedDirs": ["/usr/bin"],
    },
    "targets": ["plugin"],
}
_ROUTES = {
    _FORCE_ROUTE: {
        "directories": ("baseline-source", "candidate-source"),
        "files": (
            "baseline-source/index.js",
            "baseline-source/openclaw.plugin.json",
            "baseline-source/package.json",
            "candidate-source/index.js",
            "candidate-source/openclaw.plugin.json",
            "candidate-source/package.json",
            "protected-plugin-force-reinstall-v3-probe.py",
        ),
        "fixtures": (
            "baseline-source/index.js",
            "baseline-source/openclaw.plugin.json",
            "baseline-source/package.json",
            "candidate-source/index.js",
            "candidate-source/openclaw.plugin.json",
            "candidate-source/package.json",
        ),
        "interpreter": "/usr/local/bin/python3.12",
        "probe": "protected-plugin-force-reinstall-v3-probe.py",
        "schema": (
            "aragorn/openclaw-protected-plugin-force-reinstall-v3-observation/v1"
        ),
    }
}
_EXPECTED_BUNDLE = {
    "baseline-source/index.js": {
        "bytes": 122,
        "digest": (
            "sha256:631cc6f036f3cdf2f8fa6c814a27da075bf8c37fd2fe3681a55f7f5e593dd4ea"
        ),
    },
    "baseline-source/openclaw.plugin.json": {
        "bytes": 179,
        "digest": (
            "sha256:9b93a70d606ec63c32d15dd9021dc603df9bdf680b74789c675f5227c1c6b077"
        ),
    },
    "baseline-source/package.json": {
        "bytes": 141,
        "digest": (
            "sha256:cf817f208ceb1f4bb211d5cc97b190f6ba54cb27f34d7864b9fea5adc74a679e"
        ),
    },
    "candidate-source/index.js": {
        "bytes": 125,
        "digest": (
            "sha256:0d4abd050921ecb1c29c8c97457654184137c65644ca9b3e21a920284ce5178b"
        ),
    },
    "candidate-source/openclaw.plugin.json": {
        "bytes": 182,
        "digest": (
            "sha256:5579b471618e53e8fd72df36ad0128bb6310c0fc8111be6db31a18c672b5053c"
        ),
    },
    "candidate-source/package.json": {
        "bytes": 141,
        "digest": (
            "sha256:7e73514c5369d1d90524663baff896f41f71e21540d1b0a311a73aaf456ee8de"
        ),
    },
    # Filled by the exact child Dockerfile assertion as well. This source digest
    # deliberately has no semantic authority; it only binds the executing bytes.
    "protected-plugin-force-reinstall-v3-probe.py": {
        "bytes": 30_362,
        "digest": (
            "sha256:58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a"
        ),
    },
}
_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-"
    "plugin-force-reinstall-systemd-observation/v1"
)
_HARNESS_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-"
    "plugin-force-reinstall-systemd-harness/v1"
)
_AUTHORITY = (
    "BOUND_FINAL_COMBINED_V3_RAW_PLUGIN_FORCE_REINSTALL_OBSERVATION_ONLY_"
    "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
    "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "NATIVE_INSTALL_POLICY_COVERS_PLUGIN_TARGETS_ONLY",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
_ELIGIBILITY_KEYS = combined._ELIGIBILITY_KEYS
_STAGE = "BOOTSTRAP"
_ROUTE_OBSERVATION: dict[str, Any] | None = None
_ORIGINAL_HARNESS = combined._harness
_ORIGINAL_PREPARE_GATEWAY = combined._prepare_gateway
_ORIGINAL_COHERENT_CASE = combined.p37c._coherent_case
_PARENT_ARTIFACTS = combined._PARENT_ARTIFACTS
_BASE_INSTALLED = dict(p37c._INSTALLED)


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    combined._expect(condition, message)


def _custody(record: dict[str, Any]) -> dict[str, Any]:
    metadata = record["stat"]
    return {
        key: metadata[key] for key in ("gid", "mode", "nlink", "type", "uid")
    }


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _route_input_volume_name(
    document: dict[str, Any], source_commit: str
) -> str | None:
    return combined._ephemeral_input_volume_name(
        document,
        source_commit,
        stem="route_input",
        destination="/route-input",
        name_pattern=(
            r"aragorn-phase3-final-combined-v3-plugin-force-reinstall-"
            r"route-input-([1-9][0-9]*)"
        ),
        role="final-combined-v3-plugin-force-reinstall-route-input",
    )


def _harness() -> dict[str, Any]:
    retained = p37c._stable_document_snapshot(_HARNESS)
    document = retained["document"]
    _expect(
        document.get("schema") == _HARNESS_SCHEMA
        and document.get("image_reference")
        == "aragorn-phase3-final-combined-v3-plugin-force-reinstall-systemd"
        and document.get("profile_label")
        == "phase3-final-combined-v3-plugin-force-reinstall",
        "outer V3 force-reinstall harness identity changed",
    )
    normalized = json.loads(p37c.canonical_json(document))
    normalized["schema"] = (
        "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
    )
    normalized["image_reference"] = "aragorn-phase3-final-combined-v2-systemd"
    normalized["profile_label"] = "phase3-final-combined-v2"
    descriptor, name = tempfile.mkstemp(prefix="aragorn-v3-force-harness-", dir="/run")
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


def _profile_snapshot() -> dict[str, Any]:
    profile, source = combined._canonical_source(_PROFILE)
    routes = profile.get("routes", [])
    outcomes = {name: 0 for name in ("PASS", "FAIL", "NOT_TESTED")}
    for route in routes:
        _expect(route.get("outcome") in outcomes, "V3 route outcome is invalid")
        outcomes[route["outcome"]] += 1
    decision = profile.get("decision", {})
    eligible = {key for key in decision if key.endswith("_eligible")}
    _expect(
        profile.get("name") == "openclaw-2026.7.1-protected-final-combined-v3"
        and len(routes) == 21
        and tuple(route.get("id") for route in routes) == combined._ROUTE_IDS
        and outcomes == {"PASS": 0, "FAIL": 0, "NOT_TESTED": 21}
        and set(decision) == {*_ELIGIBILITY_KEYS, "status"}
        and decision.get("status") == "NOT_TESTED"
        and eligible == _ELIGIBILITY_KEYS
        and all(decision[key] is False for key in eligible),
        "V3 profile is not the fresh 0 PASS / 0 FAIL / 21 NOT_TESTED ledger",
    )
    return {"document": profile, "file": source, "outcomes": outcomes}


def _policy_command() -> dict[str, Any]:
    command = p37c._file(_POLICY_COMMAND)
    _expect(
        command["bytes"] == 68_480
        and command["digest"] == _POLICY_COMMAND_DIGEST
        and _custody(command)
        == {
            "gid": 0,
            "mode": "0755",
            "nlink": 1,
            "type": "file",
            "uid": 0,
        },
        "V3 install-policy command custody changed",
    )
    return command


def _artifacts() -> dict[str, Any]:
    parent = _PARENT_ARTIFACTS()
    config, config_file = combined._canonical_source(_CONFIG)
    profile = _profile_snapshot()
    lock, lock_file = combined._canonical_source(_LOCK)
    skill = combined._skill_snapshot()
    activator_source = p37c._file(_ACTIVATOR_SOURCE)
    activator = p37c._file(_ACTIVATOR)
    preflight = p37c._file(_PREFLIGHT)
    policy_command = _policy_command()
    force_probe_source = p37c._file(_FORCE_PROBE_SOURCE)
    force_probe_runtime = p37c._file(_ROUTE_ROOT / _ROUTES[_FORCE_ROUTE]["probe"])
    _expect(
        activator_source["digest"] == activator["digest"] == _ACTIVATOR_DIGEST
        and activator_source["bytes"] == activator["bytes"] == 30_504
        and _custody(activator_source)
        == {"gid": 0, "mode": "0555", "nlink": 1, "type": "file", "uid": 0}
        and _custody(activator)
        == {"gid": 0, "mode": "0755", "nlink": 1, "type": "file", "uid": 0}
        and preflight["digest"] == _PREFLIGHT_DIGEST
        and force_probe_source["digest"] == force_probe_runtime["digest"]
        and force_probe_source["bytes"] == force_probe_runtime["bytes"],
        "V3 source/install or force-probe binding changed",
    )
    plugin = {}
    for name, digest in _PLUGIN_DIGESTS.items():
        item = p37c._file(p37c.p37b._PLUGIN / name)
        _expect(item["digest"] == digest, f"V3 Aragorn plugin changed: {name}")
        plugin[name] = item
    configuration = lock["deployment_bindings"]["configuration"]
    activation = lock["deployment_bindings"]["activation_contract"]
    policy = lock["deployment_bindings"]["plugin_install_policy"]
    installed_runtime = lock["installed_runtime"]
    _expect(
        config_file["source"]["digest"] == _CONFIG_DIGEST
        and config_file["source"]["bytes"] == 2_160
        and config_file["canonical_digest"] == _CONFIG_CANONICAL_DIGEST
        and config_file["canonical_bytes"] == 2_159
        and profile["file"]["source"]["digest"] == _PROFILE_DIGEST
        and profile["file"]["source"]["bytes"] == 5_302
        and profile["file"]["canonical_digest"] == _PROFILE_CANONICAL_DIGEST
        and profile["file"]["canonical_bytes"] == 5_301
        and lock_file["source"]["digest"] == _LOCK_DIGEST
        and lock_file["source"]["bytes"] == 7_620
        and lock_file["canonical_digest"] == _LOCK_CANONICAL_DIGEST
        and lock_file["canonical_bytes"] == 7_619
        and config["security"]["installPolicy"] == _EXPECTED_INSTALL_POLICY
        and activation
        == {
            "activator": {"digest": _ACTIVATOR_DIGEST, "path": str(_ACTIVATOR)},
            "preflight": {"digest": _PREFLIGHT_DIGEST, "path": str(_PREFLIGHT)},
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
            "canonical_digest": _CONFIG_CANONICAL_DIGEST,
            "deployment_materialization": "canonical_json(config)_without_trailing_lf",
            "digest": _CONFIG_DIGEST,
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
                "path": str(_POLICY_COMMAND),
                "type": policy_command["stat"]["type"],
                "uid": policy_command["stat"]["uid"],
            },
            "decision": {
                "decision": "block",
                "protocolVersion": 1,
                "reason": "plugin installs disabled by Aragorn protected profile",
            },
            "enabled": True,
            "exec": _EXPECTED_INSTALL_POLICY["exec"],
            "targets": ["plugin"],
        }
        and installed_runtime["volume"] == _RUNTIME_VOLUME
        and installed_runtime["runtime_tree"]["tree_digest"] == _RUNTIME_DIGEST
        and installed_runtime["openclaw_digest"] == _ENTRYPOINT_DIGEST
        and installed_runtime["version_output"] == "OpenClaw 2026.7.1 (7fa98d8)",
        "V3 configuration, profile, lock, policy, or runtime binding changed",
    )
    return {
        **parent,
        "final_combined_v3_plugin_force_reinstall": {
            "activator": activator,
            "activator_source": activator_source,
            "preflight": preflight,
            "policy_command": policy_command,
            "config": {"document": config, "file": config_file},
            "profile": profile,
            "runtime_lock": {"document": lock, "file": lock_file},
            "skill": skill,
            "plugin": plugin,
            "force_probe": {
                "source": force_probe_source,
                "runtime": force_probe_runtime,
            },
            "collector": {
                "capture_recipe": p37c._file(
                    Path(
                        "/src/scripts/capture_runtime_action_worker_final_combined_"
                        "v3_plugin_force_reinstall_systemd.sh"
                    )
                ),
                "dockerfile": p37c._file(
                    Path(
                        "/src/benchmark/runtime-action-worker-final-combined-v3-"
                        "plugin-force-reinstall-systemd/Dockerfile"
                    )
                ),
                "probe": p37c._file(Path(__file__).resolve()),
                "inherited_combined_base": p37c._file(
                    Path(
                        "/src/scripts/"
                        "runtime_action_worker_final_combined_v2_systemd_probe.py"
                    )
                ),
                "inherited_route_injector": p37c._file(
                    Path(
                        "/src/scripts/runtime_action_worker_final_route_"
                        "systemd_probe.py"
                    )
                ),
            },
        },
    }


def _probe_bundle() -> list[dict[str, Any]]:
    specification = _ROUTES[_FORCE_ROUTE]
    actual_files = []
    actual_directories = []
    for path in _ROUTE_ROOT.rglob("*"):
        metadata = path.lstat()
        relative = str(path.relative_to(_ROUTE_ROOT))
        _expect(not stat.S_ISLNK(metadata.st_mode), "V3 route bundle symlink")
        if stat.S_ISREG(metadata.st_mode):
            actual_files.append(relative)
        elif stat.S_ISDIR(metadata.st_mode):
            actual_directories.append(relative)
        else:
            _expect(False, "V3 route bundle special file")
    _expect(
        tuple(sorted(actual_files)) == tuple(sorted(specification["files"]))
        and tuple(sorted(actual_directories))
        == tuple(sorted(specification["directories"])),
        "V3 force-reinstall route bundle inventory changed",
    )
    bundle = []
    for name in specification["files"]:
        record = p37c._file(_ROUTE_ROOT / name)
        _expect(
            _custody(record)
            == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0}
            and {key: record[key] for key in ("bytes", "digest")}
            == _EXPECTED_BUNDLE[name],
            f"V3 force-reinstall route input changed: {name}",
        )
        bundle.append(
            {
                "name": name,
                "bytes": record["bytes"],
                "digest": record["digest"],
                "role": "fixture" if name in specification["fixtures"] else "probe",
            }
        )
    return bundle


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
        "V3 gateway identity changed",
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
    bundle = {item["name"]: item for item in _probe_bundle()}
    source = _ROUTE_ROOT / "baseline-source"
    target = p37c.p37b._GATEWAY_STATE / "extensions" / _FORCE_ID
    _expect(not target.exists(), "V3 force-reinstall target was not fresh")
    p37c.p37b._mkdir(target, gateway_uid, gateway_gid, 0o700)
    for name in ("index.js", "openclaw.plugin.json", "package.json"):
        source_record = p37c._file(source / name)
        _expect(
            {key: source_record[key] for key in ("bytes", "digest")}
            == {key: bundle[f"baseline-source/{name}"][key] for key in ("bytes", "digest")},
            f"V3 force-reinstall baseline source changed: {name}",
        )
        destination = target / name
        destination.write_bytes((source / name).read_bytes())
        os.chown(destination, gateway_uid, gateway_gid)
        os.chmod(destination, 0o600)
        target_record = p37c._file(destination)
        _expect(
            target_record["digest"] == source_record["digest"]
            and _custody(target_record)
            == {
                "gid": gateway_gid,
                "mode": "0600",
                "nlink": 1,
                "type": "file",
                "uid": gateway_uid,
            },
            f"V3 force-reinstall baseline target changed: {name}",
        )
    return prepared


def _run_route(tokens: dict[str, str], gateway_pid: int) -> dict[str, Any]:
    harness = {"document": {"probe_bundle": _probe_bundle()}}
    with (
        mock.patch.object(v1_route, "_ROUTES", _ROUTES),
        mock.patch.object(v1_route, "_PROBE_ROOT", _ROUTE_ROOT),
        mock.patch.object(v1_route, "_SELECTED_ROUTE", _FORCE_ROUTE),
    ):
        return v1_route._run_route(tokens, harness, gateway_pid)


def _coherent_case(**kwargs: Any) -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _set_stage("P3_7C_COHERENT_ACTION")
    coherent = _ORIGINAL_COHERENT_CASE(**kwargs)
    _set_stage("ADM_02_PLUGIN_FORCE_REINSTALL")
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
    _expect(status in {"NOT_TESTED", "OBSERVED"}, "V3 route status changed")
    return {
        "status": (
            "FINAL_COMBINED_V3_PLUGIN_FORCE_REINSTALL_OBSERVED_PROFILE_NOT_TESTED"
            if status == "OBSERVED"
            else (
                "FINAL_COMBINED_V3_PLUGIN_FORCE_REINSTALL_NOT_TESTED_"
                "PROFILE_NOT_TESTED"
            )
        ),
        "route_observation_status": status,
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in sorted(_ELIGIBILITY_KEYS)},
    }


def _v3_installed() -> dict[str, str]:
    installed = dict(_BASE_INSTALLED)
    target = installed.pop("/src/packaging/activate-runtime-action-worker-host.sh")
    _expect(
        target == str(_ACTIVATOR)
        and str(_ACTIVATOR_SOURCE) not in installed,
        "inherited activator source/install map changed",
    )
    installed[str(_ACTIVATOR_SOURCE)] = target
    return installed


def _collect() -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _ROUTE_OBSERVATION = None
    if os.environ.get("OPENCLAW_TEST_FAST") is not None:
        raise combined.openclaw.ProbeError("OPENCLAW_TEST_FAST must be absent")
    _set_stage("FINAL_COMBINED_V3")
    with (
        mock.patch.object(combined, "_HARNESS", _HARNESS),
        mock.patch.object(combined, "_CONFIG", _CONFIG),
        mock.patch.object(combined, "_PROFILE", _PROFILE),
        mock.patch.object(combined, "_LOCK", _LOCK),
        mock.patch.object(combined, "_PARENT_IMAGE", _PARENT_IMAGE),
        mock.patch.object(combined, "_CONFIG_DIGEST", _CONFIG_DIGEST),
        mock.patch.object(combined, "_PROFILE_DIGEST", _PROFILE_DIGEST),
        mock.patch.object(combined, "_LOCK_DIGEST", _LOCK_DIGEST),
        mock.patch.object(combined, "_ACTIVATOR_DIGEST", _ACTIVATOR_DIGEST),
        mock.patch.object(combined, "_SCHEMA", _SCHEMA),
        mock.patch.object(combined, "_AUTHORITY", _AUTHORITY),
        mock.patch.object(combined, "_LIMITATIONS", _LIMITATIONS),
        mock.patch.object(combined, "_harness", _harness),
        mock.patch.object(combined, "_profile_snapshot", _profile_snapshot),
        mock.patch.object(combined, "_artifacts", _artifacts),
        mock.patch.object(combined, "_prepare_gateway", _prepare_gateway),
        mock.patch.object(combined, "_observation_decision", _observation_decision),
        mock.patch.object(combined, "_set_stage", _set_stage),
        mock.patch.object(p37c, "_INSTALLED", _v3_installed()),
        mock.patch.object(p37c, "_coherent_case", _coherent_case),
    ):
        composition = combined._collect()
    _expect(_ROUTE_OBSERVATION is not None, "V3 force-reinstall route did not execute")
    status = _ROUTE_OBSERVATION["route"]["status"]
    _expect(
        composition["decision"]["status"]
        == "FINAL_COMBINED_V3_ACTION_OBSERVED_PROFILE_NOT_TESTED"
        and composition["decision"]["route_pass_count"] == 0
        and composition["decision"]["route_fail_count"] == 0
        and composition["decision"]["route_not_tested_count"] == 21
        and all(
            composition["decision"][key] is False for key in _ELIGIBILITY_KEYS
        ),
        "V3 composition claim ceiling changed",
    )
    _set_stage("OBSERVATION_ASSEMBLY")
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "route_id": _FORCE_ROUTE,
        "route_observation": _ROUTE_OBSERVATION,
        "composition": composition,
        "harness": _harness(),
        "source_artifacts": {
            "collector": p37c._file(Path(__file__).resolve()),
            "force_probe": p37c._file(_FORCE_PROBE_SOURCE),
            "probe_bundle": _probe_bundle(),
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
        "decision": _decision(status),
        "limitations": _LIMITATIONS,
    }


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "route_id": _FORCE_ROUTE,
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
            "plugin_force_reinstall_systemd_probe.py",
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
