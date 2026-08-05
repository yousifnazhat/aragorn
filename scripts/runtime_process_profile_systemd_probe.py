#!/usr/bin/env python3
"""Collect one bounded live systemd process-profile slice for P3.4a."""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import platform
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_systemd_probe as prior  # noqa: E402
from aragorn.oci_worker_protocol import canonical_digest, canonical_json  # noqa: E402
from aragorn.runtime_action_broker import _action_digests, write_all  # noqa: E402
from aragorn.runtime_process_profile import (  # noqa: E402
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
_HARNESS = Path("/run/aragorn-harness.json")
_REQUEST = Path("/run/aragorn-runtime-profile-request.json")
_WRONG_REQUEST = Path("/run/aragorn-runtime-profile-wrong-request.json")
_GO = Path("/run/aragorn-runtime-profile-go")
_SKILL = Path("/opt/aragorn/runtime-profile/SKILL.md")
_EXECUTABLE = Path("/usr/local/bin/python3.12")
_BROKER_UNIT = "aragorn-runtime-profile-action-broker.service"
_SENSOR_UNIT = "aragorn-runtime-profile-observation-publisher.service"
_CLIENT_UNIT = "aragorn-runtime-profile-client.service"
_V1_UNITS = (
    "aragorn-runtime-observation-publisher.service",
    "aragorn-runtime-action-broker.service",
)
_RUNTIME_DIGEST = "sha256:" + "1" * 64
_SENSOR_DIGEST = "sha256:" + "3" * 64
_REVOCATION_SOURCE = "sha256:" + "4" * 64
_SYSTEMD_BASE_IMAGE = (
    "sha256:1a4fe98562882fca13e0349f84d9eb4c38b5361a1289da2a0bfa8852ccfdbc56"
)
_AUTHORITY = (
    "BOUNDED_SYNTHETIC_LINUX_SYSTEMD_PROCESS_PROFILE_ONLY_"
    "NOT_SEMANTIC_CAUSATION_AUTHORITY"
)
_LIMITATIONS = [
    "SINGLE_SYNTHETIC_CREATE_PROFILE_ONLY",
    "ROOT_PROVISIONED_SKILL_PATH_NOT_OPENCLAW_CONSUMPTION_PROOF",
    "RUNTIME_DIGEST_IS_POLICY_IDENTITY_NOT_EXECUTABLE_IDENTITY",
    "SENSOR_ADOPTS_RUNTIME_FS_CREDENTIALS_FOR_CROSS_UID_PROC_MEASUREMENT",
    "SENSOR_BOOTSTRAP_IDENTITY_CAPABILITIES_ARE_DROPPED_BEFORE_ACCEPT",
    "PROFILE_RECEIPT_IS_LATEST_ONLY_NOT_APPEND_ONLY_ACTION_HISTORY",
    "BEFORE_AFTER_PROCESS_SNAPSHOTS_NOT_CONTINUOUS_EXEC_OR_PER_MESSAGE_WRITER_ATTESTATION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "NO_PINNED_OPENCLAW_RUNTIME_COMPOSITION",
    "NO_SEMANTIC_OR_CAUSAL_SKILL_ATTRIBUTION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_ARTIFACTS = {
    **prior._ARTIFACTS,  # noqa: SLF001
    "/src/benchmark/runtime-process-profile-systemd/SKILL.md": (
        "/opt/aragorn/runtime-profile/SKILL.md"
    ),
    (
        "/src/benchmark/runtime-process-profile-systemd/"
        "aragorn-runtime-profile-client.service"
    ): (
        "/usr/lib/systemd/system/aragorn-runtime-profile-client.service"
    ),
    "/src/packaging/libexec/aragorn-runtime-action-service-v2.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-service-v2.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-observation-service-v2.py": (
        "/usr/libexec/aragorn/aragorn-runtime-observation-service-v2.py"
    ),
    "/src/packaging/systemd/aragorn-runtime-profile-action-broker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-profile-action-broker.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-profile-observation-publisher.service": (
        "/usr/lib/systemd/system/aragorn-runtime-profile-observation-publisher.service"
    ),
    **{
        f"/src/src/aragorn/{name}": f"/usr/lib/aragorn/aragorn/{name}"
        for name in (
            "runtime_action_broker_v2.py",
            "runtime_action_observation_publisher_v2.py",
            "runtime_action_service_v2.py",
            "runtime_observation_service_v2.py",
            "runtime_process_profile.py",
        )
    },
}

ProbeError = prior.ProbeError
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
_read_exact = prior._read_exact


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _cgroup(pid: int) -> str:
    lines = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines()
    _expect(len(lines) == 1 and lines[0].startswith("0::/"), "cgroup v2 is required")
    return lines[0][3:]


def _identity() -> dict[str, Any]:
    value = prior._identity()
    value["start_time_ticks"] = int(value["start_time_ticks"])
    value["cgroup"] = _cgroup(os.getpid())
    namespace = os.stat("/proc/self/ns/mnt")
    value["mount_namespace"] = {
        "device": namespace.st_dev,
        "inode": namespace.st_ino,
    }
    return value


def _security_status(pid: int) -> dict[str, Any]:
    wanted = {
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
    }
    values = {
        key: value.strip()
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
        for key, separator, value in (line.partition(":"),)
        if separator and key in wanted
    }
    _expect(set(values) == wanted, f"process security status is incomplete: {pid}")
    return {
        "capabilities": {
            key: {"hex": values[key], "value": int(values[key], 16)}
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        },
        "no_new_privileges": int(values["NoNewPrivs"]),
    }


def _client(request_path: Path) -> dict[str, Any]:
    raw = request_path.read_bytes()
    try:
        request = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProbeError("client request is not JSON") from exc
    _expect(canonical_json(request) == raw, "client request is not canonical")
    started = time.monotonic_ns()
    record: dict[str, Any] = {
        "client": _identity(),
        "request_path": str(request_path),
        "request_bytes": len(raw),
        "request_digest": canonical_digest(request),
        "request_file_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(2)
    try:
        try:
            connection.connect(os.fspath(_FRONTEND))
        except OSError as exc:
            record.update(
                outcome="CONNECT_ERROR",
                errno=exc.errno,
                error=errno.errorcode.get(exc.errno, "UNKNOWN"),
            )
            return record
        peer = prior._PEER.unpack(
            connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                prior._PEER.size,
            )
        )
        record["server_peer"] = {"pid": peer[0], "uid": peer[1], "gid": peer[2]}
        try:
            connection.sendall(prior._FRAME.pack(len(raw)) + raw)
            connection.shutdown(socket.SHUT_WR)
            header = _read_exact(connection, prior._FRAME.size)
        except OSError as exc:
            if exc.errno not in {errno.ECONNRESET, errno.EPIPE}:
                raise
            record.update(
                outcome="PEER_CLOSED",
                errno=exc.errno,
                error=errno.errorcode.get(exc.errno, "UNKNOWN"),
            )
            return record
        if not header:
            record["outcome"] = "PEER_CLOSED"
            return record
        _expect(len(header) == prior._FRAME.size, "response header was truncated")
        size = prior._FRAME.unpack(header)[0]
        response = _read_exact(connection, size)
        _expect(
            len(response) == size and not connection.recv(1),
            "response frame was invalid",
        )
        document = json.loads(response)
        _expect(canonical_json(document) == response, "response was not canonical")
        record.update(outcome="RESPONSE", response=document)
        return record
    finally:
        record["elapsed_ns"] = time.monotonic_ns() - started
        connection.close()


def _run_client_as(uid: int, gid: int, request_path: Path) -> dict[str, Any]:
    result = _run(
        [
            "setpriv",
            "--no-new-privs",
            f"--reuid={uid}",
            f"--regid={gid}",
            "--clear-groups",
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(__file__).resolve()),
            "client",
            str(request_path),
        ]
    )
    return json.loads(result.stdout)


def _write_file(path: Path, raw: bytes, uid: int, gid: int, mode: int) -> None:
    path.write_bytes(raw)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _write_document(
    path: Path,
    document: object,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    _write_file(path, canonical_json(document), uid, gid, mode)


def _harness() -> dict[str, Any]:
    retained = _document(_HARNESS)
    document = retained["document"]
    expected_host = {
        "binds": ["/sys/fs/cgroup:/sys/fs/cgroup:rw"],
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
    _expect(
        isinstance(document, dict)
        and set(document)
        == {
            "schema",
            "container_id",
            "image_id",
            "image_reference",
            "systemd_base_image_id",
            "platform",
            "profile_label",
            "host_config",
        }
        and document["schema"]
        == "aragorn/runtime-process-profile-systemd-harness/v1"
        and isinstance(document["container_id"], str)
        and re.fullmatch(r"[0-9a-f]{64}", document["container_id"])
        and document["container_id"].startswith(platform.node())
        and isinstance(document["image_id"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document["image_id"])
        and document["systemd_base_image_id"] == _SYSTEMD_BASE_IMAGE
        and document["image_reference"] == "aragorn-p34a-runtime-profile-systemd"
        and document["platform"] == "linux"
        and document["profile_label"] == "p3.4a"
        and document["host_config"] == expected_host,
        "outer harness descriptor changed",
    )
    return retained


def _unit(name: str) -> dict[str, Any]:
    properties = (
        "ActiveState",
        "AmbientCapabilities",
        "CapabilityBoundingSet",
        "ControlGroup",
        "ExecMainStatus",
        "ExecStart",
        "DropInPaths",
        "FragmentPath",
        "Group",
        "InvocationID",
        "MainPID",
        "NoNewPrivileges",
        "Result",
        "SubState",
        "SupplementaryGroups",
        "User",
    )
    raw = _systemctl("show", name, *[f"-p{item}" for item in properties]).stdout
    values = {
        key: value
        for line in raw.decode().splitlines()
        for key, separator, value in (line.partition("="),)
        if separator
    }
    _expect(set(values) == set(properties), f"unit properties are incomplete: {name}")
    fragment = Path(values["FragmentPath"])
    values["FragmentResolvedPath"] = str(fragment.resolve(strict=True))
    values["FragmentDigest"] = _sha256(fragment)
    return values


def _wait_active(name: str) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        unit = _unit(name)
        if unit["ActiveState"] == "active" and int(unit["MainPID"]) > 0:
            return unit
        if unit["ActiveState"] == "failed":
            break
        time.sleep(0.02)
    raise ProbeError(f"unit did not become active: {name}")


def _wait_complete(name: str) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        unit = _unit(name)
        if unit["ActiveState"] in {"inactive", "failed"}:
            _expect(
                unit["Result"] == "success" and unit["ExecMainStatus"] == "0",
                f"unit failed: {name}",
            )
            return unit
        time.sleep(0.02)
    raise ProbeError(f"unit did not complete: {name}")


def _journal_record(invocation_id: str) -> dict[str, Any]:
    _expect(
        re.fullmatch(r"[0-9a-f]{32}", invocation_id) is not None,
        "client invocation ID is invalid",
    )
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        raw = _run(
            [
                "journalctl",
                f"_SYSTEMD_INVOCATION_ID={invocation_id}",
                "--output=cat",
                "--no-pager",
            ]
        ).stdout
        lines = [line for line in raw.splitlines() if line]
        if lines:
            _expect(len(lines) == 1, "client journal output was ambiguous")
            document = json.loads(lines[0])
            _expect(canonical_json(document) == lines[0], "client output changed")
            return document
        time.sleep(0.02)
    raise ProbeError("client journal record was not retained")


def _request(
    action: dict[str, str],
    policy: dict[str, Any],
    skill_digest: str,
    suffix: str,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "schema": "aragorn/runtime-action-request/v1",
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": "session-p3-4a",
        "run_id": "run-p3-4a",
        "tool_call_id": f"call-{suffix}",
        "active_skill_digest": skill_digest,
        **action,
        "policy_digest": canonical_digest(policy),
        "policy_version": policy["version"],
        "issued_at_unix": now,
        "expires_at_unix": now + 5,
    }


def _envelope(
    action: dict[str, str],
    policy: dict[str, Any],
    skill_digest: str,
    suffix: str,
    target: str,
    payload: bytes,
) -> dict[str, Any]:
    return {
        "schema": "aragorn/runtime-action-broker-request/v1",
        "request": _request(action, policy, skill_digest, suffix),
        "effect": {
            "schema": "aragorn/runtime-create-file/v1",
            "operation": "create",
            "target_name": target,
            "payload_base64": base64.b64encode(payload).decode("ascii"),
        },
    }


def _control_snapshot() -> dict[str, str]:
    names = ("health", "observation", "policy", "revocations", "state")
    paths = [_CONTROL / f"{name}.json" for name in names]
    paths.extend(path for path in (_PENDING, _RECEIPT) if path.exists())
    return {path.name: _sha256(path) for path in paths}


def _stop_units() -> None:
    _systemctl(
        "stop",
        _CLIENT_UNIT,
        _SENSOR_UNIT,
        _BROKER_UNIT,
        *_V1_UNITS,
        check=False,
    )


def _reset() -> None:
    _stop_units()
    _systemctl("reset-failed", _CLIENT_UNIT, _SENSOR_UNIT, _BROKER_UNIT, check=False)
    _run(
        [
            "systemd-tmpfiles",
            "--create",
            "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf",
        ]
    )
    for directory in (_PROTECTED, _STAGING):
        for child in directory.iterdir():
            _expect(not child.is_dir(), f"unexpected directory in fixture: {child}")
            child.unlink()
    for name in (
        "health.json",
        "observation.json",
        "policy.json",
        "profile-pending.json",
        "profile-receipt.json",
        "revocations.json",
        "state.json",
    ):
        (_CONTROL / name).unlink(missing_ok=True)
    for path in (_REQUEST, _WRONG_REQUEST, _GO):
        path.unlink(missing_ok=True)
    for path in (
        Path("/etc/aragorn/runtime-action-runtime.json"),
        Path("/etc/aragorn/runtime-action-observation.json"),
    ):
        path.unlink(missing_ok=True)


def _collect_live(harness: dict[str, Any]) -> dict[str, Any]:
    broker = _user("aragorn-broker")
    runtime = _user("aragorn-runtime")
    sensor = _user("aragorn-sensor")
    runtime_gid = _group("aragorn-runtime").gr_gid
    sensor_gid = _group("aragorn-sensor").gr_gid
    _expect(
        len({broker.pw_uid, runtime.pw_uid, sensor.pw_uid}) == 3,
        "service UIDs overlap",
    )

    verification = _run(
        [
            "systemd-analyze",
            "verify",
            f"/usr/lib/systemd/system/{_BROKER_UNIT}",
            f"/usr/lib/systemd/system/{_SENSOR_UNIT}",
            f"/usr/lib/systemd/system/{_CLIENT_UNIT}",
        ]
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
    _systemctl("daemon-reload")

    # The inactive profile services are condition-skipped while this one client
    # waits, letting the collector obtain systemd's exact host-cgroup path.
    _write_document(_REQUEST, {"waiting": True}, 0, 0, 0o444)
    _systemctl("start", _CLIENT_UNIT)
    client_unit = _wait_active(_CLIENT_UNIT)
    client_pid = int(client_unit["MainPID"])
    profile_cgroup = _cgroup(client_pid)
    _expect(
        client_unit["ControlGroup"] == profile_cgroup,
        "systemd and proc cgroup identities disagree",
    )

    skill_digest = _sha256(_SKILL)
    executable_digest = _sha256(_EXECUTABLE)
    profile_document = {
        "schema": PROFILE_SCHEMA,
        "authority": PROFILE_AUTHORITY,
        "runtime_digest": _RUNTIME_DIGEST,
        "executable_digest": executable_digest,
        "cgroup": profile_cgroup,
        "skill_path": str(_SKILL),
    }
    profile = runtime_process_profile(profile_document)

    protected_fd = os.open(_PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    payloads = {
        "allow": ("profile-allowed.txt", b"Aragorn P3.4a profiled create\n"),
        "wrong_cgroup": (
            "profile-wrong-cgroup.txt",
            b"Aragorn P3.4a wrong-cgroup block\n",
        ),
    }
    try:
        actions = {
            name: _action_digests(protected_fd, target, payload)
            for name, (target, payload) in payloads.items()
        }
    finally:
        os.close(protected_fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-4a-systemd-process-profile",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": _SENSOR_DIGEST,
        "revocation_source_digest": _REVOCATION_SOURCE,
        "allow": sorted(
            (
                {
                    "runtime_digest": _RUNTIME_DIGEST,
                    "active_skill_digest": skill_digest,
                    **action,
                }
                for action in actions.values()
            ),
            key=canonical_json,
        ),
    }
    initial_request = _request(actions["allow"], policy, skill_digest, "initial")
    attribution = {
        key: initial_request[key]
        for key in (
            "runtime_digest",
            "session_id",
            "run_id",
            "tool_call_id",
            "active_skill_digest",
        )
    }
    now = int(time.time())
    controls = {
        "policy": policy,
        "revocations": {
            "schema": "aragorn/runtime-action-revocations/v1",
            "source_digest": _REVOCATION_SOURCE,
            "generation": 1,
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
            "skill_digests": [],
        },
        "health": {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": _RUNTIME_DIGEST,
            "sensor_digest": _SENSOR_DIGEST,
            "epoch": 1,
            "status": "healthy",
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
        },
        "observation": {
            "schema": "aragorn/runtime-action-observation/v1",
            "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY",
            "sequence": 1,
            "sensor_digest": _SENSOR_DIGEST,
            "observed_at_unix": now,
            "expires_at_unix": now + 5,
            "active": {
                "schema": "aragorn/runtime-active-context/v1",
                **attribution,
            },
            "measured_action": {
                "schema": "aragorn/measured-runtime-action/v1",
                **attribution,
                **actions["allow"],
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
    for name, document in controls.items():
        _write_control(_CONTROL / f"{name}.json", document, broker.pw_uid, runtime_gid)

    etc = Path("/etc/aragorn")
    etc.mkdir(mode=0o755, exist_ok=True)
    _write_document(
        etc / "runtime-action-runtime.json",
        {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": _RUNTIME_DIGEST,
            "runtime_profile_digest": profile.digest,
        },
        0,
        0,
        0o400,
    )
    _write_document(
        etc / "runtime-action-observation.json",
        {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": _SENSOR_DIGEST,
            "runtime_profile": profile_document,
        },
        0,
        0,
        0o400,
    )

    _systemctl("start", _BROKER_UNIT)
    _systemctl("start", _SENSOR_UNIT)
    _wait_path(_BACKEND)
    _wait_path(_FRONTEND)
    broker_unit = _wait_active(_BROKER_UNIT)
    sensor_unit = _wait_active(_SENSOR_UNIT)
    broker_pid = int(broker_unit["MainPID"])
    sensor_pid = int(sensor_unit["MainPID"])
    broker_process = _process(broker_pid)
    sensor_process = _process(sensor_pid)
    broker_security = _security_status(broker_pid)
    sensor_security = _security_status(sensor_pid)
    _expect(
        sensor_process["uids"]
        == [sensor.pw_uid, sensor.pw_uid, sensor.pw_uid, runtime.pw_uid]
        and sensor_process["gids"]
        == [sensor_gid, sensor_gid, sensor_gid, runtime_gid]
        and all(
            value["value"] == 0
            for value in sensor_security["capabilities"].values()
        )
        and sensor_security["no_new_privileges"] == 1,
        "sensor did not adopt runtime FS credentials and drop all capabilities",
    )
    _expect(
        all(
            value["value"] == 0
            for value in broker_security["capabilities"].values()
        )
        and broker_security["no_new_privileges"] == 1,
        "broker privilege state changed",
    )
    units = {
        "broker": (
            broker_unit,
            "/src/packaging/systemd/aragorn-runtime-profile-action-broker.service",
            "/usr/lib/systemd/system/aragorn-runtime-profile-action-broker.service",
        ),
        "sensor": (
            sensor_unit,
            "/src/packaging/systemd/"
            "aragorn-runtime-profile-observation-publisher.service",
            "/usr/lib/systemd/system/"
            "aragorn-runtime-profile-observation-publisher.service",
        ),
        "client": (
            client_unit,
            "/src/benchmark/runtime-process-profile-systemd/"
            "aragorn-runtime-profile-client.service",
            "/usr/lib/systemd/system/aragorn-runtime-profile-client.service",
        ),
    }
    for name, (unit, source, installed) in units.items():
        _expect(
            unit["FragmentResolvedPath"] == installed
            and unit["FragmentDigest"] == _file(Path(source))["digest"]
            and unit["DropInPaths"] == "",
            f"loaded {name} unit differs from its pinned source",
        )
    _expect(
        broker_process["cmdline"]
        == [
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-action-service-v2.py",
            f"/run/credentials/{_BROKER_UNIT}/runtime-binding",
        ]
        and sensor_process["cmdline"]
        == [
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-runtime-observation-service-v2.py",
            f"/run/credentials/{_SENSOR_UNIT}/observation-binding",
        ],
        "service process command changed",
    )

    allowed_envelope = _envelope(
        actions["allow"],
        policy,
        skill_digest,
        "allow",
        *payloads["allow"],
    )
    _write_document(_REQUEST, allowed_envelope, 0, 0, 0o444)
    baseline = _control_snapshot()
    before_protected = sorted(path.name for path in _PROTECTED.iterdir())
    before_staging = sorted(path.name for path in _STAGING.iterdir())
    _GO.touch(mode=0o600)
    completed_client_unit = _wait_complete(_CLIENT_UNIT)
    allow = _journal_record(client_unit["InvocationID"])
    allowed_path = _PROTECTED / payloads["allow"][0]
    _wait_path(allowed_path)
    _wait_path(_RECEIPT)
    allowed_target = _file(allowed_path)
    receipt = _document(_RECEIPT)
    receipt_file = _file(_RECEIPT)
    after_allow = _control_snapshot()
    after_allow_state = _document(_CONTROL / "state.json")
    runtime_attribution = receipt["document"].get("runtime_attribution", {})
    response = allow.get("response", {})
    _expect(
        allow.get("outcome") == "RESPONSE"
        and allow["client"]["pid"] == client_pid
        and allow["client"]["cgroup"] == profile_cgroup
        and allow["client"]["euid"] == runtime.pw_uid
        and allow["client"]["egid"] == runtime_gid
        and response.get("verdict") == "ALLOW"
        and response.get("effect_status") == "CREATED"
        and response.get("reason_codes") == [],
        "profiled create did not return ALLOW/CREATED",
    )
    _expect(
        allowed_target["digest"] == actions["allow"]["payload_digest"]
        and allowed_target["stat"]["uid"] == broker.pw_uid
        and allowed_target["stat"]["gid"] == runtime_gid
        and allowed_target["stat"]["mode"] == "0400"
        and before_protected == []
        and before_staging == []
        and sorted(path.name for path in _PROTECTED.iterdir())
        == [payloads["allow"][0]]
        and sorted(path.name for path in _STAGING.iterdir()) == [],
        "profiled create effect metadata changed",
    )
    _expect(
        receipt["document"].get("schema")
        == "aragorn/runtime-process-profile-receipt/v1"
        and receipt["document"].get("broker_result") == response
        and receipt["document"].get("broker_result_digest")
        == canonical_digest(response)
        and receipt["document"].get("runtime_attribution_digest")
        == canonical_digest(runtime_attribution)
        and runtime_attribution.get("profile_digest") == profile.digest
        and runtime_attribution.get("runtime_digest") == _RUNTIME_DIGEST
        and runtime_attribution.get("executable_digest") == executable_digest
        and runtime_attribution.get("active_skill_digest") == skill_digest
        and runtime_attribution.get("skill_path") == str(_SKILL)
        and runtime_attribution.get("cgroup") == profile_cgroup
        and runtime_attribution.get("pid") == client_pid
        and runtime_attribution.get("uid") == runtime.pw_uid
        and runtime_attribution.get("gid") == runtime_gid
        and runtime_attribution.get("start_time_ticks")
        == allow["client"]["start_time_ticks"]
        and runtime_attribution.get("mount_namespace")
        == allow["client"]["mount_namespace"]
        and not _PENDING.exists()
        and receipt_file["stat"]["uid"] == broker.pw_uid
        and receipt_file["stat"]["gid"] == runtime_gid
        and receipt_file["stat"]["mode"] == "0400",
        "broker profile receipt is not bound to the live client",
    )
    _expect(
        len(after_allow_state["document"]["consumed"]) == 1
        and after_allow_state["document"]["effect_journal"] is None,
        "allowed broker state transition changed",
    )

    wrong_envelope = _envelope(
        actions["wrong_cgroup"],
        policy,
        skill_digest,
        "wrong-cgroup",
        *payloads["wrong_cgroup"],
    )
    _write_document(_WRONG_REQUEST, wrong_envelope, 0, 0, 0o444)
    before_wrong = _control_snapshot()
    wrong = _run_client_as(runtime.pw_uid, runtime_gid, _WRONG_REQUEST)
    wrong_path = _PROTECTED / payloads["wrong_cgroup"][0]
    after_wrong = _control_snapshot()
    _expect(
        wrong.get("outcome") == "PEER_CLOSED"
        and wrong.get("server_peer")
        == {"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid}
        and wrong["client"]["euid"] == runtime.pw_uid
        and wrong["client"]["egid"] == runtime_gid
        and wrong["client"]["cgroup"] != profile_cgroup
        and not wrong_path.exists()
        and not _PENDING.exists()
        and before_wrong == after_wrong
        and sorted(path.name for path in _PROTECTED.iterdir())
        == [payloads["allow"][0]]
        and sorted(path.name for path in _STAGING.iterdir()) == [],
        "wrong-cgroup client did not fail before broker effect",
    )

    credentials = {
        "broker": _document(etc / "runtime-action-runtime.json"),
        "sensor": _document(etc / "runtime-action-observation.json"),
    }
    return {
        "schema": "aragorn/runtime-process-profile-systemd-evidence/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_4A_SYNTHETIC_SYSTEMD_OBSERVED",
            "profiled_allow_created_observed": True,
            "broker_profile_receipt_observed": True,
            "wrong_cgroup_no_effect_observed": True,
            "openclaw_consumption_observed": False,
            "semantic_causation_observed": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "public_release_eligible": False,
        },
        "environment": {
            "platform": sys.platform,
            "architecture": platform.machine(),
            "kernel_release": platform.release(),
            "python": platform.python_version(),
            "systemd": _run(["systemd", "--version"]).stdout.decode().splitlines()[0],
            "container_id": platform.node(),
            "capture_identity": _identity(),
            "systemd_verify": {
                "exit_code": verification.returncode,
                "stdout": verification.stdout.decode(),
                "stderr": verification.stderr.decode(),
            },
        },
        "harness": harness,
        "artifacts": artifacts,
        "collector": {
            "probe": _file(Path(__file__).resolve()),
            "base_probe": _file(Path("/src/scripts/runtime_action_systemd_probe.py")),
            "dockerfile": _file(
                Path("/src/benchmark/runtime-process-profile-systemd/Dockerfile")
            ),
            "installer": _file(
                Path("/src/packaging/install-runtime-profile-host.sh")
            ),
            "base_installer": _file(
                Path("/src/packaging/install-runtime-action-host.sh")
            ),
            "recipe": _file(
                Path("/src/scripts/capture_runtime_process_profile_systemd.sh")
            ),
        },
        "profile": {
            "digest": profile.digest,
            "document": profile_document,
            "skill": _file(_SKILL),
            "executable": _file(_EXECUTABLE),
        },
        "credentials": credentials,
        "identities": {
            "broker": {"uid": broker.pw_uid, "gid": runtime_gid},
            "runtime": {"uid": runtime.pw_uid, "gid": runtime_gid},
            "sensor": {"uid": sensor.pw_uid, "gid": sensor_gid},
        },
        "deployment": {
            "directories": {
                "root": _metadata(_ROOT),
                "control": _metadata(_CONTROL),
                "protected": _metadata(_PROTECTED),
                "staging": _metadata(_STAGING),
                "runtime": _metadata(_FRONTEND.parent),
            },
            "units": {
                "broker": broker_unit,
                "sensor": sensor_unit,
                "client_started": client_unit,
                "client_completed": completed_client_unit,
            },
            "processes": {
                "broker": broker_process,
                "sensor": sensor_process,
            },
            "security": {
                "broker": broker_security,
                "sensor": sensor_security,
                "sensor_filesystem_identity": {
                    "real_uid": sensor_process["uids"][0],
                    "effective_uid": sensor_process["uids"][1],
                    "saved_uid": sensor_process["uids"][2],
                    "filesystem_uid": sensor_process["uids"][3],
                    "real_gid": sensor_process["gids"][0],
                    "effective_gid": sensor_process["gids"][1],
                    "saved_gid": sensor_process["gids"][2],
                    "filesystem_gid": sensor_process["gids"][3],
                },
                "sensor_bootstrap_capabilities": {
                    "names": ["CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP"],
                    "purpose": (
                        "adopt runtime FS credentials then irreversibly drop all caps"
                    ),
                    "live_after_start": [],
                },
            },
            "sockets": {
                "backend": _metadata(_BACKEND),
                "frontend": _metadata(_FRONTEND),
            },
        },
        "inputs": {
            "initial_controls": controls,
            "policy": policy,
            "actions": actions,
            "envelopes": {
                "allow": allowed_envelope,
                "wrong_cgroup": wrong_envelope,
            },
            "control_baseline": baseline,
        },
        "scenarios": {
            "profiled_allow": {
                "status": "PASS",
                "client": allow,
                "target": allowed_target,
                "receipt": receipt,
                "receipt_file": receipt_file,
                "profile_pending_exists": _PENDING.exists(),
                "control_after": after_allow,
            },
            "wrong_cgroup": {
                "status": "PASS",
                "client": wrong,
                "expected_cgroup": profile_cgroup,
                "actual_cgroup": wrong["client"]["cgroup"],
                "target_exists": wrong_path.exists(),
                "control_before": before_wrong,
                "control_after": after_wrong,
                "protected_entries": sorted(
                    path.name for path in _PROTECTED.iterdir()
                ),
                "staging_entries": sorted(path.name for path in _STAGING.iterdir()),
            },
        },
    }


def _collect() -> dict[str, Any]:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text().strip() != "systemd"
    ):
        raise ProbeError("collector requires root in the fixed systemd container")
    harness = _harness()
    _reset()
    try:
        return _collect_live(harness)
    finally:
        _stop_units()


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    output_path: Path | None = None
    if len(arguments) == 2 and arguments[0] == "client":
        result = _client(Path(arguments[1]))
    elif len(arguments) == 2 and arguments[0] == "--output":
        output_path = Path(arguments[1])
        result = _collect()
    elif not arguments:
        result = _collect()
    else:
        print(
            "usage: runtime_process_profile_systemd_probe.py "
            "[client REQUEST_JSON | --output ABSENT_PATH]",
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
