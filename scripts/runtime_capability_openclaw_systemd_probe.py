#!/usr/bin/env python3
"""Collect one bounded dynamic-capability OpenClaw/systemd slice for P3.5a."""

from __future__ import annotations

import os
import platform
import re
import secrets
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_process_profile_openclaw_systemd_probe as prior
import runtime_process_profile_systemd_probe as profile_prior

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import _action_digests, write_all
from aragorn.runtime_capability_grant import (
    GRANT_AUTHORITY,
    GRANT_SCHEMA,
    parse_runtime_capability_grant,
)
from aragorn.runtime_process_profile import (
    PROFILE_AUTHORITY,
    PROFILE_SCHEMA,
    runtime_process_profile,
)

_ROOT = Path("/var/lib/aragorn-runtime-action")
_CONTROL = _ROOT / "control"
_PROTECTED = _ROOT / "protected"
_STAGING = _ROOT / "staging"
_FRONTEND = Path("/run/aragorn-runtime-observation/sensor.sock")
_BACKEND = _CONTROL / "broker.sock"
_PENDING = _CONTROL / "profile-pending.json"
_RECEIPT = _CONTROL / "profile-receipt.json"
_GRANT_STATE = _CONTROL / "capability-grant-state.json"
_GRANT_SOURCE = Path("/etc/aragorn/runtime-capability-grant.json")
_RUNTIME_BINDING = Path("/etc/aragorn/runtime-action-runtime.json")
_OBSERVATION_BINDING = Path("/etc/aragorn/runtime-action-observation.json")
_HARNESS = Path("/run/aragorn-harness.json")
_DRIVER = prior._DRIVER
_DRIVER_ROOT = Path("/run/aragorn-p35a-driver")
_GATEWAY_UNIT = prior._GATEWAY_UNIT
_BROKER_UNIT = "aragorn-runtime-capability-action-broker.service"
_SENSOR_UNIT = "aragorn-runtime-capability-observation-publisher.service"
_LEGACY_UNITS = (
    "aragorn-runtime-action-broker.service",
    "aragorn-runtime-profile-action-broker.service",
    "aragorn-runtime-observation-publisher.service",
    "aragorn-runtime-profile-observation-publisher.service",
)
_P34B_IMAGE = "sha256:9a3fad8e3b336799fda105d4dc598ae65445058539934a756b8d65e8f5a125ce"
_TARGET = "openclaw-capability-allowed.txt"
_PAYLOAD = b"Aragorn P3.5a dynamic one-shot OpenClaw create\n"
_AUTHORITY = (
    "BOUNDED_PINNED_OPENCLAW_DYNAMIC_CAPABILITY_SYSTEMD_COMPOSITION_ONLY_"
    "NOT_RUN_OR_EDR_AUTHORITY"
)
_LIMITATIONS = [
    "ONE_PINNED_OPENCLAW_CREATE_AND_ONE_ROOT_GRANT_ONLY",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "SKILL_PROMPT_PROJECTION_IS_CONSUMPTION_EVIDENCE_NOT_SEMANTIC_CAUSATION",
    "ROOT_SUPPLIED_SOURCE_AND_INSTALL_DIGESTS_NOT_INDEPENDENT_PROVENANCE",
    "PROFILE_RECEIPT_IS_LATEST_ONLY_NOT_APPEND_ONLY_ACTION_HISTORY",
    "PROCESS_PROFILE_SNAPSHOTS_NOT_CONTINUOUS_EXEC_OR_WRITER_ATTESTATION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "NO_HOSTILE_ROOT_HOST_OR_FORCED_POWER_LOSS_QUALIFICATION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]

_expect = prior._expect
_run = prior._run
_systemctl = prior._systemctl
_user = prior._user
_group = prior._group
_metadata = prior._metadata
_file = prior._file
_document = prior._document
_process = prior._process
_wait_path = prior._wait_path
_write_control = prior._write_control
_unit = prior._unit
_wait_active = prior._wait_active
_security_status = prior._security_status

_PYTHON_MODULES = (
    "__init__.py",
    "oci_worker_protocol.py",
    "runtime_action_decision.py",
    "runtime_action_broker.py",
    "runtime_action_observation_publisher.py",
    "runtime_action_service.py",
    "runtime_observation_service.py",
    "runtime_process_profile.py",
    "runtime_action_broker_v2.py",
    "runtime_action_observation_publisher_v2.py",
    "runtime_action_service_v2.py",
    "runtime_observation_service_v2.py",
    "runtime_action_broker_v3.py",
    "runtime_capability_grant.py",
    "runtime_action_observation_publisher_v3.py",
    "runtime_action_broker_v4.py",
    "runtime_action_service_v4.py",
    "runtime_observation_service_v3.py",
)
_ARTIFACTS = {
    **{
        f"/src/src/aragorn/{name}": f"/usr/lib/aragorn/aragorn/{name}"
        for name in _PYTHON_MODULES
    },
    "/src/packaging/activate-runtime-capability-host.sh": (
        "/usr/libexec/aragorn/activate-runtime-capability-host.sh"
    ),
    "/src/packaging/libexec/aragorn-runtime-action-service-v4.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-service-v4.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-observation-service-v3.py": (
        "/usr/libexec/aragorn/aragorn-runtime-observation-service-v3.py"
    ),
    "/src/packaging/systemd/aragorn-gateway.sysusers": (
        "/usr/lib/sysusers.d/aragorn-gateway.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action.tmpfiles": (
        "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-capability-action-broker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-capability-action-broker.service"
    ),
    (
        "/src/packaging/systemd/"
        "aragorn-runtime-capability-observation-publisher.service"
    ): (
        "/usr/lib/systemd/system/"
        "aragorn-runtime-capability-observation-publisher.service"
    ),
}
_UNIT_OBJECTS = {
    _BROKER_UNIT: (
        "/org/freedesktop/systemd1/unit/"
        "aragorn_2druntime_2dcapability_2daction_2dbroker_2eservice"
    ),
    _SENSOR_UNIT: (
        "/org/freedesktop/systemd1/unit/"
        "aragorn_2druntime_2dcapability_2dobservation_2dpublisher_2eservice"
    ),
}


def _harness() -> dict[str, Any]:
    retained = _document(_HARNESS)
    document = retained["document"]
    expected = {
        "schema",
        "container_id",
        "image_id",
        "image_reference",
        "run_image_reference",
        "parent_image_id",
        "systemd_base_image_id",
        "node_image",
        "image_lineage",
        "platform",
        "profile_label",
        "openclaw_runtime_volume",
        "openclaw_runtime_volume_identity",
        "openclaw_runtime_mount",
        "host_config",
    }
    _expect(
        isinstance(document, dict)
        and set(document) == expected
        and document["schema"]
        == "aragorn/runtime-capability-openclaw-systemd-harness/v1"
        and isinstance(document["container_id"], str)
        and re.fullmatch(r"[0-9a-f]{64}", document["container_id"])
        and document["container_id"].startswith(platform.node())
        and isinstance(document["image_id"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document["image_id"])
        and document["image_reference"]
        == "aragorn-p35a-runtime-capability-openclaw-systemd"
        and document["run_image_reference"] == document["image_id"]
        and document["parent_image_id"] == _P34B_IMAGE
        and document["platform"] == "linux"
        and document["profile_label"] == "p3.5a",
        "outer P3.5a harness identity changed",
    )
    lineage = document["image_lineage"]
    _expect(
        lineage["parent"]["id"] == _P34B_IMAGE
        and lineage["child"]["id"] == document["image_id"]
        and lineage["child"]["layers"][: len(lineage["parent"]["layers"])]
        == lineage["parent"]["layers"]
        and lineage["added_layers"]
        == lineage["child"]["layers"][len(lineage["parent"]["layers"]) :]
        and bool(lineage["added_layers"]),
        "P3.5a image lineage changed",
    )
    return retained


def _stop_units() -> None:
    _systemctl(
        "stop",
        _GATEWAY_UNIT,
        _SENSOR_UNIT,
        _BROKER_UNIT,
        *_LEGACY_UNITS,
        check=False,
    )


def _reset() -> None:
    _stop_units()
    _systemctl(
        "reset-failed",
        _GATEWAY_UNIT,
        _SENSOR_UNIT,
        _BROKER_UNIT,
        *_LEGACY_UNITS,
        check=False,
    )
    _systemctl("unmask", _BROKER_UNIT, _SENSOR_UNIT, *_LEGACY_UNITS, check=False)
    _run(
        [
            "systemd-tmpfiles",
            "--create",
            "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf",
        ]
    )
    for directory in (_PROTECTED, _STAGING):
        for child in directory.iterdir():
            _expect(not child.is_dir(), f"unexpected fixture directory: {child}")
            child.unlink()
    for path in _CONTROL.iterdir():
        if path.name.endswith(".json"):
            path.unlink()
    for path in (
        _GRANT_SOURCE,
        _RUNTIME_BINDING,
        _OBSERVATION_BINDING,
        prior._CONFIG,
    ):
        path.unlink(missing_ok=True)
    if _DRIVER_ROOT.exists():
        for child in _DRIVER_ROOT.iterdir():
            child.unlink()
        _DRIVER_ROOT.rmdir()


def _capability_unit(name: str) -> dict[str, Any]:
    unit = _unit(name)
    unit["LoadCredential"] = (
        _run(
            [
                "busctl",
                "get-property",
                "org.freedesktop.systemd1",
                _UNIT_OBJECTS[name],
                "org.freedesktop.systemd1.Service",
                "LoadCredential",
            ]
        )
        .stdout.decode()
        .strip()
    )
    return unit


def _control_snapshot() -> dict[str, str]:
    return {
        path.name: prior._sha256(path)
        for path in (
            *(
                _CONTROL / f"{name}.json"
                for name in ("policy", "revocations", "health", "observation", "state")
            ),
            _GRANT_STATE,
        )
        if path.exists()
    }


def _controls(
    policy: dict[str, Any],
    action: dict[str, str],
    now: int,
    *,
    counter: int,
) -> dict[str, Any]:
    seed = {
        "runtime_digest": prior._RUNTIME_DIGEST,
        "session_id": f"seed-p3-5a-{counter}",
        "run_id": f"seed-p3-5a-{counter}",
        "tool_call_id": f"seed-p3-5a-{counter}",
        "active_skill_digest": prior._SKILL_DIGEST,
    }
    return {
        "policy": policy,
        "revocations": {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": prior._REVOCATION_SOURCE,
            "generation": counter,
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
            "skill_digests": [],
        },
        "health": {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": prior._RUNTIME_DIGEST,
            "sensor_digest": prior._SENSOR_DIGEST,
            "epoch": counter,
            "status": "healthy",
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
        },
        "observation": {
            "schema": "aragorn/runtime-action-observation/v1",
            "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
            "sequence": counter,
            "sensor_digest": prior._SENSOR_DIGEST,
            "observed_at_unix": now,
            "expires_at_unix": now + 5,
            "active": {"schema": "aragorn/runtime-active-context/v1", **seed},
            "measured_action": {
                "schema": "aragorn/measured-runtime-action/v1",
                **seed,
                **action,
            },
        },
        "state": {
            "schema": "aragorn/runtime-action-broker-state/v2",
            "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "minimum_revocation_generation": 1,
            "minimum_mediator_health_epoch": 1,
            "consumed": [],
            "effect_journal": None,
        },
    }


def _run_driver(
    scenario_id: str,
    expected_verdict: str,
    expected_effect_status: str,
    runtime_uid: int,
    runtime_gid: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    input_path = _DRIVER_ROOT / f"{scenario_id}.input.json"
    output_path = _DRIVER_ROOT / f"{scenario_id}.output.json"
    driver_input = {
        "schema": "aragorn/openclaw-profile-driver-input/v1",
        "scenario": {
            "id": scenario_id,
            "target_name": _TARGET,
            "content": _PAYLOAD.decode(),
            "expected_verdict": expected_verdict,
            "expected_effect_status": expected_effect_status,
        },
    }
    profile_prior._write_file(
        input_path,
        canonical_json(driver_input) + b"\n",
        0,
        runtime_gid,
        0o440,
    )
    started = time.monotonic_ns()
    process = subprocess.run(
        [
            "setpriv",
            f"--reuid={runtime_uid}",
            f"--regid={runtime_gid}",
            "--clear-groups",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            str(prior._NODE),
            str(_DRIVER),
            str(input_path),
            str(output_path),
        ],
        capture_output=True,
        env={
            "HOME": str(prior._HOME),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "OPENCLAW_CONFIG_PATH": str(prior._CONFIG),
            "OPENCLAW_GATEWAY_TOKEN": "aragorn-p34b-gateway-token-v1",
            "OPENCLAW_STATE_DIR": str(prior._STATE),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TZ": "UTC",
        },
        timeout=45,
        check=False,
    )
    elapsed = time.monotonic_ns() - started
    driver = _document(output_path)["document"] if output_path.exists() else {}
    proof = driver.get("scenario", {}).get("proof", {})
    checks = proof.get("checks", {})
    if expected_verdict == "CLIENT_ERROR":
        passed = (
            process.returncode == 1
            and driver.get("scenario", {}).get("status") == "FAIL"
            and proof.get("passed") is False
            and checks
            == {
                "action_result_bound": False,
                "gateway_pid_present": True,
                "history_lineage": True,
                "one_provider_driven_tool_call": True,
                "provider_completed_without_error": True,
            }
        )
    else:
        passed = (
            process.returncode == 0
            and driver.get("scenario", {}).get("status") == "PASS"
        )
    return driver_input, {
        "status": "PASS" if passed else "FAIL",
        "driver_exit_code": process.returncode,
        "driver_stdout": process.stdout.decode(errors="replace"),
        "driver_stderr": process.stderr.decode(errors="replace"),
        "driver_elapsed_ns": elapsed,
        "driver": driver,
    }


def _trace(
    process: subprocess.Popen[bytes],
    path: Path,
    pid: int,
    expected: list[str],
) -> dict[str, Any]:
    try:
        return profile_prior.prior._trace(process, path, pid, expected)
    except prior.ProbeError as exc:
        raw = path.read_text(errors="replace") if path.exists() else "<absent>"
        raise prior.ProbeError(f"{exc}; raw trace={raw!r}") from exc


def _stop_trace(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def _legacy_routes() -> dict[str, dict[str, Any]]:
    result = {}
    for name in _LEGACY_UNITS:
        enabled = _systemctl("is-enabled", name, check=False)
        active = _systemctl("is-active", name, check=False)
        result[name] = {
            "enabled_exit_code": enabled.returncode,
            "enabled": enabled.stdout.decode().strip(),
            "active_exit_code": active.returncode,
            "active": active.stdout.decode().strip(),
        }
    return result


def _credential_file(unit: str, name: str) -> dict[str, Any]:
    return _file(Path("/run/credentials") / unit / name)


def _gateway_state(
    runtime_uid: int,
    runtime_gid: int,
    *,
    expected_cgroup: str | None = None,
) -> dict[str, Any]:
    _wait_active(_GATEWAY_UNIT)
    time.sleep(0.25)
    unit = _unit(_GATEWAY_UNIT)
    pid = int(unit["MainPID"])
    cgroup = prior._cgroup(pid)
    process = _process(pid)
    security = _security_status(pid)
    checks = {
        "active": unit["ActiveState"] == "active",
        "main_pid": pid > 0,
        "cgroup": unit["ControlGroup"] == cgroup,
        "expected_cgroup": expected_cgroup is None or cgroup == expected_cgroup,
        "singleton": prior._cgroup_processes(cgroup) == [pid],
        "uids": process["uids"] == [runtime_uid] * 4,
        "gids": process["gids"] == [runtime_gid] * 4,
        "no_new_privileges": security["no_new_privileges"] == 1,
        "capabilities": all(
            item["value"] == 0 for item in security["capabilities"].values()
        ),
    }
    _expect(
        all(checks.values()),
        "gateway process profile changed: "
        + ",".join(name for name, passed in checks.items() if not passed),
    )
    return {
        "unit": unit,
        "pid": pid,
        "cgroup": cgroup,
        "process": process,
        "mount_namespace": prior._mount_namespace(pid),
        "security": security,
    }


def _runtime_facing_secret_absence(
    drivers: tuple[dict[str, Any], ...],
    grant: dict[str, Any],
    grant_digest: str,
    lease: dict[str, Any],
) -> bool:
    raw = b"\n".join(canonical_json(driver) for driver in drivers)
    forbidden = (
        grant["grant_id"],
        grant_digest,
        lease["lease_nonce"],
        lease["authority"],
        lease["schema"],
    )
    return all(value.encode() not in raw for value in forbidden)


def _collect_live(harness: dict[str, Any]) -> dict[str, Any]:
    broker = _user("aragorn-broker")
    runtime = _user("aragorn-runtime")
    sensor = _user("aragorn-sensor")
    runtime_gid = _group("aragorn-runtime").gr_gid
    sensor_gid = _group("aragorn-sensor").gr_gid
    identities = {
        "broker_uid": broker.pw_uid,
        "runtime_uid": runtime.pw_uid,
        "runtime_gid": runtime_gid,
        "sensor_uid": sensor.pw_uid,
        "sensor_gid": sensor_gid,
    }
    _expect(
        len({broker.pw_uid, runtime.pw_uid, sensor.pw_uid}) == 3,
        "service UIDs overlap",
    )

    artifacts = []
    for source, installed in sorted(_ARTIFACTS.items()):
        source_file = _file(Path(source))
        installed_file = _file(Path(installed))
        _expect(
            source_file["digest"] == installed_file["digest"]
            and source_file["bytes"] == installed_file["bytes"],
            f"installed artifact differs from source: {installed}",
        )
        artifacts.append(
            {
                "source_path": source,
                "installed_path": installed,
                "source_digest": source_file["digest"],
                "installed_digest": installed_file["digest"],
                "source_bytes": source_file["bytes"],
                "installed_bytes": installed_file["bytes"],
                "installed_stat": installed_file["stat"],
            }
        )

    node = _file(prior._NODE)
    _expect(node["digest"] == prior._NODE_DIGEST, "pinned Node changed")
    runtime_snapshot = prior._runtime_snapshot()
    skill = _file(prior._SKILL)
    _expect(skill["digest"] == prior._SKILL_DIGEST, "pinned skill changed")
    _, plugin_digest = prior.openclaw_prior._plugin_artifacts()
    _expect(plugin_digest == prior._PLUGIN_DIGEST, "pinned plugin changed")

    protected_fd = os.open(_PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        action = _action_digests(protected_fd, _TARGET, _PAYLOAD)
    finally:
        os.close(protected_fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-5a-pinned-openclaw-dynamic-capability",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": prior._SENSOR_DIGEST,
        "revocation_source_digest": prior._REVOCATION_SOURCE,
        "allow": [
            {
                "runtime_digest": prior._RUNTIME_DIGEST,
                "active_skill_digest": prior._SKILL_DIGEST,
                **action,
            }
        ],
    }
    config = prior._gateway_config(policy, plugin_digest, identities)
    prior._CONFIG.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    prior._write_document(prior._CONFIG, config, 0, 0, 0o444)

    verification = _run(
        [
            "systemd-analyze",
            "verify",
            f"/usr/lib/systemd/system/{_BROKER_UNIT}",
            f"/usr/lib/systemd/system/{_SENSOR_UNIT}",
            f"/usr/lib/systemd/system/{_GATEWAY_UNIT}",
        ]
    )
    _systemctl("daemon-reload")
    _systemctl("start", _GATEWAY_UNIT)
    negative_gateway = _gateway_state(runtime.pw_uid, runtime_gid)
    profile_document = {
        "schema": PROFILE_SCHEMA,
        "authority": PROFILE_AUTHORITY,
        "runtime_digest": prior._RUNTIME_DIGEST,
        "executable_digest": node["digest"],
        "cgroup": negative_gateway["cgroup"],
        "skill_path": str(prior._SKILL),
    }
    profile = runtime_process_profile(profile_document)

    now = int(time.time())
    initial_controls = _controls(policy, action, now, counter=1)
    for name, document in initial_controls.items():
        _write_control(_CONTROL / f"{name}.json", document, broker.pw_uid, runtime_gid)
    prior._write_document(
        _RUNTIME_BINDING,
        {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": prior._RUNTIME_DIGEST,
            "runtime_profile_digest": profile.digest,
        },
        0,
        0,
        0o400,
    )
    prior._write_document(
        _OBSERVATION_BINDING,
        {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": prior._SENSOR_DIGEST,
            "runtime_profile": profile_document,
        },
        0,
        0,
        0o400,
    )
    provenance_bindings = {
        "source_manifest": {
            "schema": "aragorn/evaluator-root-source-binding/v1",
            "authority": "ROOT_SUPPLIED_DIGEST_ONLY_NOT_INSTALLER_AUTHORITY",
            "fixture": "p3.5a-pinned-openclaw-source",
        },
        "install_context": {
            "schema": "aragorn/evaluator-root-install-binding/v1",
            "authority": "ROOT_SUPPLIED_DIGEST_ONLY_NOT_INSTALLER_AUTHORITY",
            "fixture": "p3.5a-pinned-openclaw-install",
        },
    }
    grant = {
        "schema": GRANT_SCHEMA,
        "authority": GRANT_AUTHORITY,
        "grant_id": secrets.token_hex(32),
        "source_manifest_digest": canonical_digest(
            provenance_bindings["source_manifest"]
        ),
        "install_context_digest": canonical_digest(
            provenance_bindings["install_context"]
        ),
        "runtime_profile_digest": profile.digest,
        "runtime_digest": prior._RUNTIME_DIGEST,
        "active_skill_digest": prior._SKILL_DIGEST,
        "sensor_digest": prior._SENSOR_DIGEST,
        "policy_digest": canonical_digest(policy),
        "policy_version": policy["version"],
        "operation_digest": action["operation_digest"],
        "issued_at_unix": now - 1,
        "expires_at_unix": now + 240,
        "max_actions": 1,
    }
    grant_raw = canonical_json(grant)
    _expect(
        parse_runtime_capability_grant(grant_raw, now) == grant,
        "root grant validation changed",
    )
    prior._write_document(_GRANT_SOURCE, grant, 0, 0, 0o400)
    grant_digest = canonical_digest(grant)
    grant_source_file = _file(_GRANT_SOURCE)
    _expect(
        grant_source_file["stat"]["uid"] == 0
        and grant_source_file["stat"]["gid"] == 0
        and grant_source_file["stat"]["mode"] == "0400"
        and grant_source_file["stat"]["nlink"] == 1,
        "root grant source metadata changed",
    )

    _DRIVER_ROOT.mkdir(mode=0o700)
    os.chown(_DRIVER_ROOT, runtime.pw_uid, runtime_gid)
    _systemctl("start", _BROKER_UNIT)
    _wait_path(_BACKEND)
    negative_broker_unit = _wait_active(_BROKER_UNIT)
    negative_broker_pid = int(negative_broker_unit["MainPID"])
    negative_broker_process = _process(negative_broker_pid)
    available_before = _document(_GRANT_STATE)
    _expect(
        available_before["document"]["status"] == "AVAILABLE"
        and available_before["document"]["grant_digest"] == grant_digest
        and available_before["document"]["claim"] is None
        and available_before["document"]["result"] is None,
        "grant did not initialize as AVAILABLE",
    )
    negative_before = _control_snapshot()
    negative_trace_path = _DRIVER_ROOT / "negative-broker.trace"
    negative_trace_process = profile_prior.prior._start_trace(
        negative_broker_pid, negative_trace_path
    )
    try:
        negative_input, negative = _run_driver(
            "issuer-unavailable",
            "CLIENT_ERROR",
            "NOT_SUBMITTED",
            runtime.pw_uid,
            runtime_gid,
        )
        negative_trace = _trace(
            negative_trace_process,
            negative_trace_path,
            negative_broker_pid,
            [],
        )
    finally:
        _stop_trace(negative_trace_process)
    available_after = _document(_GRANT_STATE)
    negative_after = _control_snapshot()
    negative_sensor_unit = _capability_unit(_SENSOR_UNIT)
    negative_result = prior._driver_result(negative["driver"])
    negative_effects = {
        "frontend_exists": _FRONTEND.exists(),
        "target_exists": (_PROTECTED / _TARGET).exists(),
        "profile_pending_exists": _PENDING.exists(),
        "profile_receipt_exists": _RECEIPT.exists(),
        "protected_entries": sorted(path.name for path in _PROTECTED.iterdir()),
        "staging_entries": sorted(path.name for path in _STAGING.iterdir()),
    }
    negative_checks = {
        "driver": negative["status"] == "PASS",
        "result": negative_result is not None,
        "schema": negative_result is not None
        and negative_result.get("schema") == "aragorn/runtime-action-client-error/v1",
        "authority": negative_result is not None
        and negative_result.get("authority")
        == "CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
        "effect": negative_result is not None
        and negative_result.get("effect_status") == "NOT_SUBMITTED",
        "message": negative_result is not None
        and negative_result.get("message")
        == "sensor runtime directory is unavailable: ENOENT",
        "controls": negative_before == negative_after,
        "grant": available_before == available_after,
        "frontend": not negative_effects["frontend_exists"],
        "sensor_state": negative_sensor_unit["ActiveState"] != "active",
        "sensor_pid": negative_sensor_unit["MainPID"] == "0",
        "target": not negative_effects["target_exists"],
        "pending": not negative_effects["profile_pending_exists"],
        "receipt": not negative_effects["profile_receipt_exists"],
        "protected": not negative_effects["protected_entries"],
        "staging": not negative_effects["staging_entries"],
        "broker_trace": not negative_trace["peer_credentials"],
    }
    _expect(
        all(negative_checks.values()),
        "issuer-unavailable scenario changed: "
        + ",".join(name for name, passed in negative_checks.items() if not passed)
        + f";result={negative_result};proof="
        + repr(negative["driver"].get("scenario", {}).get("proof")),
    )

    negative_gateway["process_after"] = _process(negative_gateway["pid"])
    _systemctl("stop", _BROKER_UNIT, _GATEWAY_UNIT)
    _systemctl("start", _GATEWAY_UNIT)
    gateway = _gateway_state(
        runtime.pw_uid,
        runtime_gid,
        expected_cgroup=profile_document["cgroup"],
    )
    gateway_unit = gateway["unit"]
    gateway_pid = gateway["pid"]
    gateway_cgroup = gateway["cgroup"]
    gateway_before = gateway["process"]
    gateway_namespace = gateway["mount_namespace"]
    gateway_security = gateway["security"]
    refreshed_controls = _controls(policy, action, int(time.time()), counter=2)
    for name in ("revocations", "health", "observation"):
        _write_control(
            _CONTROL / f"{name}.json",
            refreshed_controls[name],
            broker.pw_uid,
            runtime_gid,
        )
    activation = _run(["/usr/libexec/aragorn/activate-runtime-capability-host.sh"])
    _wait_path(_BACKEND)
    _wait_path(_FRONTEND)
    broker_unit = _capability_unit(_BROKER_UNIT)
    sensor_unit = _capability_unit(_SENSOR_UNIT)
    broker_pid = int(broker_unit["MainPID"])
    sensor_pid = int(sensor_unit["MainPID"])
    _expect(
        broker_unit["ActiveState"] == sensor_unit["ActiveState"] == "active"
        and broker_unit["DropInPaths"] == sensor_unit["DropInPaths"] == "",
        "dynamic capability units are not exact and active",
    )
    legacy_routes = _legacy_routes()
    _expect(
        all(
            route["enabled"] == "masked" and route["active"] != "active"
            for route in legacy_routes.values()
        ),
        "legacy runtime route remained usable",
    )
    positive_before = {
        "controls": _control_snapshot(),
        "grant_state": _document(_GRANT_STATE),
        "protected_entries": sorted(path.name for path in _PROTECTED.iterdir()),
        "staging_entries": sorted(path.name for path in _STAGING.iterdir()),
        "profile_pending_exists": _PENDING.exists(),
        "profile_receipt_exists": _RECEIPT.exists(),
    }
    _expect(
        positive_before["grant_state"]["document"]["status"] == "AVAILABLE"
        and not positive_before["protected_entries"]
        and not positive_before["staging_entries"]
        and not positive_before["profile_pending_exists"]
        and not positive_before["profile_receipt_exists"],
        "positive scenario did not begin from the same clean AVAILABLE grant",
    )

    sensor_trace_path = _DRIVER_ROOT / "positive-sensor.trace"
    broker_trace_path = _DRIVER_ROOT / "positive-broker.trace"
    sensor_trace_process = profile_prior.prior._start_trace(
        sensor_pid, sensor_trace_path
    )
    broker_trace_process = profile_prior.prior._start_trace(
        broker_pid, broker_trace_path
    )
    try:
        positive_input, positive = _run_driver(
            "one-shot-allow",
            "ALLOW",
            "CREATED",
            runtime.pw_uid,
            runtime_gid,
        )
        _expect(
            positive["status"] == "PASS",
            "positive OpenClaw driver changed: "
            + repr(
                {
                    "exit": positive["driver_exit_code"],
                    "stderr": positive["driver_stderr"],
                    "scenario": positive["driver"].get("scenario"),
                    "grant_state": _document(_GRANT_STATE),
                    "broker_journal": _run(
                        [
                            "journalctl",
                            "--no-pager",
                            "--output=cat",
                            "--unit",
                            _BROKER_UNIT,
                            "--lines=40",
                        ],
                        check=False,
                    ).stdout.decode(errors="replace"),
                    "sensor_journal": _run(
                        [
                            "journalctl",
                            "--no-pager",
                            "--output=cat",
                            "--unit",
                            _SENSOR_UNIT,
                            "--lines=40",
                        ],
                        check=False,
                    ).stdout.decode(errors="replace"),
                }
            ),
        )
        sensor_trace = _trace(
            sensor_trace_process,
            sensor_trace_path,
            sensor_pid,
            ["accept", "connect"],
        )
        broker_trace = _trace(
            broker_trace_process,
            broker_trace_path,
            broker_pid,
            ["accept"],
        )
    finally:
        _stop_trace(sensor_trace_process)
        _stop_trace(broker_trace_process)

    positive_result = prior._driver_result(positive["driver"])
    grant_state = _document(_GRANT_STATE)
    grant_state_file = _file(_GRANT_STATE)
    receipt = _document(_RECEIPT) if _RECEIPT.exists() else None
    receipt_file = _file(_RECEIPT) if _RECEIPT.exists() else None
    target = _file(_PROTECTED / _TARGET) if (_PROTECTED / _TARGET).exists() else None
    broker_state = _document(_CONTROL / "state.json")
    gateway_after = _process(gateway_pid)
    claim = grant_state["document"].get("claim") or {}
    lease = claim.get("lease") or {}
    result_record = grant_state["document"].get("result") or {}
    profile_result = result_record.get("profile_result") or {}
    receipt_document = receipt["document"] if receipt else {}
    attribution = receipt_document.get("runtime_attribution") or {}
    positive_passed = (
        positive["status"] == "PASS"
        and positive_result is not None
        and positive_result.get("verdict") == "ALLOW"
        and positive_result.get("effect_status") == "CREATED"
        and grant_state["document"].get("status") == "CONSUMED"
        and grant_state["document"].get("grant_digest") == grant_digest
        and claim.get("grant_digest") == grant_digest
        and claim.get("lease_digest") == canonical_digest(lease)
        and lease.get("grant_digest") == grant_digest
        and lease.get("max_actions") == 1
        and lease.get("runtime_profile_digest") == profile.digest
        and lease.get("runtime_digest") == prior._RUNTIME_DIGEST
        and lease.get("active_skill_digest") == prior._SKILL_DIGEST
        and lease.get("sensor_digest") == prior._SENSOR_DIGEST
        and lease.get("policy_digest") == canonical_digest(policy)
        and lease.get("operation_digest") == action["operation_digest"]
        and lease.get("path_digest") == action["path_digest"]
        and lease.get("payload_digest") == action["payload_digest"]
        and claim.get("profile_claim", {}).get("submission_digest")
        == lease.get("submission_digest")
        and claim.get("profile_claim", {}).get("request_digest")
        == lease.get("request_digest")
        and receipt_document.get("submission_digest") == lease.get("submission_digest")
        and receipt_document.get("runtime_attribution_digest")
        == lease.get("runtime_attribution_digest")
        and receipt_document.get("broker_result") == positive_result
        and receipt_document.get("broker_result_digest")
        == canonical_digest(positive_result)
        and profile_result.get("lease_digest") == claim.get("lease_digest")
        and profile_result.get("submission_digest") == lease.get("submission_digest")
        and profile_result.get("profile_receipt_digest")
        == canonical_digest(receipt_document)
        and profile_result.get("broker_result_digest")
        == canonical_digest(positive_result)
        and attribution.get("profile_digest") == profile.digest
        and attribution.get("pid") == gateway_pid
        and attribution.get("uid") == runtime.pw_uid
        and attribution.get("gid") == runtime_gid
        and attribution.get("start_time_ticks")
        == int(gateway_before["start_time_ticks"])
        and attribution.get("mount_namespace") == gateway_namespace
        and target is not None
        and target["digest"] == action["payload_digest"]
        and target["stat"]["uid"] == broker.pw_uid
        and target["stat"]["gid"] == runtime_gid
        and target["stat"]["mode"] == "0400"
        and target["stat"]["nlink"] == 1
        and not _PENDING.exists()
        and not list(_STAGING.iterdir())
        and len(broker_state["document"]["consumed"]) == 1
        and broker_state["document"]["effect_journal"] is None
        and sensor_trace["peer_credentials"]
        == [
            {"pid": gateway_pid, "uid": runtime.pw_uid, "gid": runtime_gid},
            {"pid": broker_pid, "uid": broker.pw_uid, "gid": runtime_gid},
        ]
        and broker_trace["peer_credentials"]
        == [{"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid}]
        and gateway_after["start_time_ticks"] == gateway_before["start_time_ticks"]
        and gateway_after["mount_namespace"] == gateway_before["mount_namespace"]
        and prior._cgroup_processes(gateway_cgroup) == [gateway_pid]
    )
    _expect(positive_passed, "dynamic one-shot scenario changed")
    secret_absent = _runtime_facing_secret_absence(
        (negative["driver"], positive["driver"]), grant, grant_digest, lease
    )
    _expect(secret_absent, "runtime-facing output exposed grant or lease authority")

    credentials = {
        "root_grant": grant_source_file,
        "broker": {
            "runtime_binding": _credential_file(_BROKER_UNIT, "runtime-binding"),
            "capability_grant": _credential_file(_BROKER_UNIT, "capability-grant"),
        },
        "sensor": {
            "observation_binding": _credential_file(
                _SENSOR_UNIT, "observation-binding"
            ),
            "capability_grant": _credential_file(_SENSOR_UNIT, "capability-grant"),
        },
    }
    for copy in (
        credentials["broker"]["capability_grant"],
        credentials["sensor"]["capability_grant"],
    ):
        _expect(
            copy["digest"] == grant_digest and copy["bytes"] == len(grant_raw),
            "systemd grant credential changed",
        )

    return {
        "schema": "aragorn/runtime-capability-openclaw-systemd-evidence/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_5A_DYNAMIC_CAPABILITY_OBSERVED",
            "issuer_unavailable_not_submitted_no_effect_observed": True,
            "one_grant_available_to_consumed_observed": True,
            "exact_profile_receipt_bound": True,
            "gateway_main_pid_peer_bound": True,
            "semantic_causation_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "installer_authority_eligible": False,
            "public_release_eligible": False,
        },
        "harness": harness,
        "environment": {
            "platform": sys.platform,
            "architecture": platform.machine(),
            "kernel_release": platform.release(),
            "python": platform.python_version(),
            "node": node,
            "capture_identity": profile_prior._identity(),
            "systemd_verify": {
                "exit_code": verification.returncode,
                "stdout": verification.stdout.decode(),
                "stderr": verification.stderr.decode(),
            },
            "activation": {
                "exit_code": activation.returncode,
                "stdout": activation.stdout.decode(),
                "stderr": activation.stderr.decode(),
            },
        },
        "artifacts": artifacts,
        "collector": {
            "probe": _file(Path(__file__).resolve()),
            "dockerfile": _file(
                Path("/src/benchmark/runtime-capability-openclaw-systemd/Dockerfile")
            ),
            "recipe": _file(
                Path("/src/scripts/capture_runtime_capability_openclaw_systemd.sh")
            ),
            "driver": _file(_DRIVER),
            "profile_helper": _file(
                Path("/src/scripts/runtime_process_profile_openclaw_systemd_probe.py")
            ),
        },
        "runtime": runtime_snapshot,
        "profile": {
            "digest": profile.digest,
            "document": profile_document,
            "skill": skill,
            "executable": node,
        },
        "identities": {
            "broker": {"uid": broker.pw_uid, "gid": runtime_gid},
            "runtime": {"uid": runtime.pw_uid, "gid": runtime_gid},
            "sensor": {"uid": sensor.pw_uid, "gid": sensor_gid},
        },
        "credentials": credentials,
        "inputs": {
            "action": action,
            "policy": policy,
            "gateway_config": config,
            "gateway_config_digest": canonical_digest(config),
            "initial_controls": initial_controls,
            "refreshed_controls": {
                name: refreshed_controls[name]
                for name in ("revocations", "health", "observation")
            },
            "provenance_bindings": provenance_bindings,
            "grant": {"digest": grant_digest, "document": grant},
            "negative_driver": negative_input,
            "positive_driver": positive_input,
        },
        "deployment": {
            "directories": {
                "root": _metadata(_ROOT),
                "control": _metadata(_CONTROL),
                "protected": _metadata(_PROTECTED),
                "staging": _metadata(_STAGING),
                "runtime": _metadata(_FRONTEND.parent),
            },
            "gateway": {
                "negative": negative_gateway,
                "positive": {
                    "unit": gateway_unit,
                    "process_before": gateway_before,
                    "process_after": gateway_after,
                    "security": gateway_security,
                    "cgroup_processes": prior._cgroup_processes(gateway_cgroup),
                },
            },
            "negative": {
                "broker_unit": negative_broker_unit,
                "broker_process": negative_broker_process,
                "sensor_unit": negative_sensor_unit,
                "effects": negative_effects,
            },
            "positive": {
                "units": {"broker": broker_unit, "sensor": sensor_unit},
                "processes": {
                    "broker": _process(broker_pid),
                    "sensor": _process(sensor_pid),
                },
                "security": {
                    "broker": _security_status(broker_pid),
                    "sensor": _security_status(sensor_pid),
                },
                "sockets": {
                    "backend": _metadata(_BACKEND),
                    "frontend": _metadata(_FRONTEND),
                },
                "legacy_routes": legacy_routes,
            },
        },
        "scenarios": {
            "issuer_unavailable": {
                **negative,
                "control_before": negative_before,
                "control_after": negative_after,
                "grant_state_before": available_before,
                "grant_state_after": available_after,
                "effects": negative_effects,
            },
            "one_shot_allow": {
                **positive,
                "before": positive_before,
                "control_after": _control_snapshot(),
                "grant_state": grant_state,
                "grant_state_file": grant_state_file,
                "profile_receipt": receipt,
                "profile_receipt_file": receipt_file,
                "broker_state": broker_state,
                "target": target,
                "protected_entries": sorted(path.name for path in _PROTECTED.iterdir()),
                "staging_entries": sorted(path.name for path in _STAGING.iterdir()),
                "profile_pending_exists": _PENDING.exists(),
                "runtime_facing_grant_or_lease_absent": secret_absent,
            },
        },
        "peer_trace": {
            "issuer_unavailable_broker": negative_trace,
            "one_shot_sensor": sensor_trace,
            "one_shot_broker": broker_trace,
        },
        "timing": {
            "grant_lifetime_seconds": grant["expires_at_unix"]
            - grant["issued_at_unix"],
            "sensor_deadline_ms": 500,
            "client_deadline_ms": 750,
            "negative_driver_elapsed_ns": negative["driver_elapsed_ns"],
            "positive_driver_elapsed_ns": positive["driver_elapsed_ns"],
        },
    }


def _collect() -> dict[str, Any]:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text().strip() != "systemd"
    ):
        raise prior.ProbeError("collector requires root in the fixed systemd container")
    harness = _harness()
    _reset()
    try:
        return _collect_live(harness)
    finally:
        _stop_units()


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    output_path: Path | None = None
    if len(arguments) == 2 and arguments[0] == "--output":
        output_path = Path(arguments[1])
        result = _collect()
    elif not arguments:
        result = _collect()
    else:
        print(
            "usage: runtime_capability_openclaw_systemd_probe.py "
            "[--output ABSENT_PATH]",
            file=sys.stderr,
        )
        return 64
    raw = canonical_json(result) + b"\n"
    if output_path is None:
        sys.stdout.buffer.write(raw)
    else:
        descriptor = os.open(
            output_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            write_all(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
