#!/usr/bin/env python3
"""Collect one bounded live systemd composition slice for P3.3b."""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import platform
import pwd
import grp
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")

from aragorn.oci_worker_protocol import canonical_digest, canonical_json  # noqa: E402
from aragorn.runtime_action_broker import (  # noqa: E402
    RuntimeActionBrokerConfig,
    _action_digests,
    publish_runtime_control_document,
    write_all,
)

_ROOT = Path("/var/lib/aragorn-runtime-action")
_CONTROL = _ROOT / "control"
_PROTECTED = _ROOT / "protected"
_STAGING = _ROOT / "staging"
_FRONTEND = Path("/run/aragorn-runtime-observation/sensor.sock")
_BACKEND = _CONTROL / "broker.sock"
_HARNESS = Path("/run/aragorn-harness.json")
_BROKER_UNIT = "aragorn-runtime-action-broker.service"
_SENSOR_UNIT = "aragorn-runtime-observation-publisher.service"
_UNIT_OBJECTS = {
    _BROKER_UNIT: (
        "/org/freedesktop/systemd1/unit/"
        "aragorn_2druntime_2daction_2dbroker_2eservice"
    ),
    _SENSOR_UNIT: (
        "/org/freedesktop/systemd1/unit/"
        "aragorn_2druntime_2dobservation_2dpublisher_2eservice"
    ),
}
_BASE_IMAGE = (
    "python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b"
)
_RUNTIME_DIGEST = "sha256:" + "1" * 64
_SKILL_DIGEST = "sha256:" + "2" * 64
_SENSOR_DIGEST = "sha256:" + "3" * 64
_REVOCATION_SOURCE = "sha256:" + "4" * 64
_FRAME = struct.Struct(">I")
_PEER = struct.Struct("3i")
_PEER_TRACE = re.compile(
    r"(?P<service>\d+)\s+getsockopt\((?P<fd>\d+), SOL_SOCKET, SO_PEERCRED, "
    r"\{pid=(?P<pid>\d+), uid=(?P<uid>\d+), gid=(?P<gid>\d+)\}, "
    r"\[12\]\) = 0"
)
_ACCEPT_TRACE = re.compile(
    r"(?P<service>\d+)\s+accept4\(.*\) = (?P<fd>\d+)"
)
_CONNECT_TRACE = re.compile(
    r'(?P<service>\d+)\s+connect\((?P<fd>\d+), '
    r'\{sa_family=AF_UNIX, sun_path="(?P<path>[^"]+)"\}, \d+\) = 0'
)
_AUTHORITY = "BOUNDED_LINUX_SYSTEMD_COMPOSITION_ONLY_NOT_RUN_OR_EDR_AUTHORITY"
_LIMITATIONS = [
    "SINGLE_SYNTHETIC_CREATE_PROFILE_ONLY",
    "OPAQUE_SESSION_RUN_AND_TOOL_IDS_NOT_CAUSAL_ATTRIBUTION",
    "ACTIVE_SKILL_DIGEST_IS_DEPLOYMENT_PIN_NOT_CAUSAL_ATTRIBUTION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "SYSTEMD_PACKAGE_INSTALLED_FROM_NETWORKED_DEBIAN_REPOSITORY",
    "NO_PINNED_OPENCLAW_RUNTIME_COMPOSITION",
    "NO_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "NO_FORCED_RESET_FILESYSTEM_OR_POWER_LOSS_QUALIFICATION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_ARTIFACTS = {
    "/src/packaging/libexec/aragorn-runtime-action-service.py": (
        "/usr/libexec/aragorn/aragorn-runtime-action-service.py"
    ),
    "/src/packaging/libexec/aragorn-runtime-observation-service.py": (
        "/usr/libexec/aragorn/aragorn-runtime-observation-service.py"
    ),
    "/src/packaging/systemd/aragorn-gateway.sysusers": (
        "/usr/lib/sysusers.d/aragorn-gateway.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action.tmpfiles": (
        "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"
    ),
    "/src/packaging/systemd/aragorn-runtime-action-broker.service": (
        "/usr/lib/systemd/system/aragorn-runtime-action-broker.service"
    ),
    "/src/packaging/systemd/aragorn-runtime-observation-publisher.service": (
        "/usr/lib/systemd/system/aragorn-runtime-observation-publisher.service"
    ),
    **{
        f"/src/src/aragorn/{name}": f"/usr/lib/aragorn/aragorn/{name}"
        for name in (
            "__init__.py",
            "oci_worker_protocol.py",
            "runtime_action_broker.py",
            "runtime_action_decision.py",
            "runtime_action_observation_publisher.py",
            "runtime_action_service.py",
            "runtime_observation_service.py",
        )
    },
}


class ProbeError(RuntimeError):
    """The live composition did not satisfy its bounded contract."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def _run(
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        arguments,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if check and result.returncode != 0:
        raise ProbeError(
            f"command failed ({result.returncode}): {' '.join(arguments)}: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result


def _systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return _run(["systemctl", *arguments], check=check)


def _user(name: str) -> pwd.struct_passwd:
    return pwd.getpwnam(name)


def _group(name: str) -> grp.struct_group:
    return grp.getgrnam(name)


def _metadata(path: Path) -> dict[str, Any]:
    value = os.lstat(path)
    kind = (
        "directory"
        if stat.S_ISDIR(value.st_mode)
        else "socket"
        if stat.S_ISSOCK(value.st_mode)
        else "file"
        if stat.S_ISREG(value.st_mode)
        else "other"
    )
    return {
        "type": kind,
        "device": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": f"{stat.S_IMODE(value.st_mode):04o}",
        "nlink": value.st_nlink,
        "size": value.st_size,
    }


def _file(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {
        "path": str(path),
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "stat": _metadata(path),
    }


def _document(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    document = json.loads(raw)
    if canonical_json(document) != raw:
        raise ProbeError(f"control document is not canonical: {path}")
    return {"digest": canonical_digest(document), "document": document}


def _control_snapshot() -> dict[str, str]:
    return {
        name: "sha256:" + hashlib.sha256((_CONTROL / f"{name}.json").read_bytes()).hexdigest()
        for name in ("health", "observation", "policy", "revocations", "state")
    }


def _harness() -> dict[str, Any]:
    retained = _document(_HARNESS)
    document = retained["document"]
    _expect(
        document["schema"] == "aragorn/runtime-action-systemd-harness/v1"
        and re.fullmatch(r"[0-9a-f]{64}", document["container_id"])
        and document["container_id"].startswith(platform.node())
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document["image_id"])
        and document["image_reference"] == "aragorn-p33b-systemd"
        and document["platform"] == "linux"
        and document["profile_label"] == "p3.3b"
        and document["host_config"]
        == {
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
        },
        "outer harness descriptor changed",
    )
    return retained


def _process(pid: int) -> dict[str, Any]:
    status_fields: dict[str, str] = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status_fields[key] = value.strip()
    stat_fields = Path(f"/proc/{pid}/stat").read_text().split()
    return {
        "pid": pid,
        "start_time_ticks": stat_fields[21],
        "cmdline": [
            item.decode(errors="strict")
            for item in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if item
        ],
        "uids": [int(item) for item in status_fields["Uid"].split()],
        "gids": [int(item) for item in status_fields["Gid"].split()],
        "groups": sorted(int(item) for item in status_fields["Groups"].split()),
        "capabilities_effective": status_fields["CapEff"],
        "no_new_privileges": int(status_fields["NoNewPrivs"]),
        "mount_namespace": os.readlink(f"/proc/{pid}/ns/mnt"),
        "network_namespace": os.readlink(f"/proc/{pid}/ns/net"),
    }


def _mount(pid: int, mount_point: str) -> dict[str, Any]:
    for raw in Path(f"/proc/{pid}/mountinfo").read_text().splitlines():
        left, right = raw.split(" - ", 1)
        fields = left.split()
        if fields[4] != mount_point:
            continue
        filesystem, source, super_options = right.split(" ", 2)
        return {
            "raw": raw,
            "mount_point": fields[4],
            "root": fields[3],
            "mount_options": sorted(fields[5].split(",")),
            "filesystem": filesystem,
            "source": source,
            "super_options": sorted(super_options.split(",")),
            "raw_digest": "sha256:" + hashlib.sha256(raw.encode()).hexdigest(),
        }
    raise ProbeError(f"mount point is absent for pid {pid}: {mount_point}")


def _unit(name: str) -> dict[str, Any]:
    properties = (
        "ActiveState",
        "DropInPaths",
        "ExecStart",
        "ExecStartEx",
        "FragmentPath",
        "Group",
        "InaccessiblePaths",
        "MainPID",
        "NoNewPrivileges",
        "PrivateMounts",
        "PrivateNetwork",
        "ProtectSystem",
        "ReadOnlyPaths",
        "ReadWritePaths",
        "RestrictAddressFamilies",
        "SubState",
        "SupplementaryGroups",
        "User",
    )
    output = _systemctl("show", name, *[f"-p{item}" for item in properties]).stdout
    values = {}
    for line in output.decode().splitlines():
        key, value = line.split("=", 1)
        values[key] = value
    if set(values) != set(properties):
        raise ProbeError(f"systemd property output is incomplete for {name}")
    fragment = Path(values["FragmentPath"])
    values["FragmentResolvedPath"] = str(fragment.resolve(strict=True))
    values["FragmentDigest"] = "sha256:" + hashlib.sha256(
        fragment.read_bytes()
    ).hexdigest()
    values["LoadCredential"] = _run(
        [
            "busctl",
            "get-property",
            "org.freedesktop.systemd1",
            _UNIT_OBJECTS[name],
            "org.freedesktop.systemd1.Service",
            "LoadCredential",
        ]
    ).stdout.decode().strip()
    return values


def _identity() -> dict[str, Any]:
    return {
        "pid": os.getpid(),
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "gid": os.getgid(),
        "egid": os.getegid(),
        "groups": sorted(os.getgroups()),
        "start_time_ticks": Path(f"/proc/{os.getpid()}/stat").read_text().split()[21],
    }


def _read_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            break
        result.extend(chunk)
    return bytes(result)


def _client(socket_path: Path) -> dict[str, Any]:
    raw = sys.stdin.buffer.read()
    started = time.monotonic_ns()
    record: dict[str, Any] = {
        "client": _identity(),
        "request_bytes": len(raw),
        "request_file_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(1)
    try:
        try:
            connection.connect(os.fspath(socket_path))
        except OSError as exc:
            record.update(
                outcome="CONNECT_ERROR",
                errno=exc.errno,
                error=errno.errorcode.get(exc.errno, "UNKNOWN"),
            )
            return record
        peer = _PEER.unpack(
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER.size)
        )
        record["server_peer"] = {"pid": peer[0], "uid": peer[1], "gid": peer[2]}
        try:
            connection.sendall(_FRAME.pack(len(raw)) + raw)
            connection.shutdown(socket.SHUT_WR)
            header = _read_exact(connection, _FRAME.size)
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
        if len(header) != _FRAME.size:
            raise ProbeError("response frame header was truncated")
        response = _read_exact(connection, _FRAME.unpack(header)[0])
        if connection.recv(1) or len(response) != _FRAME.unpack(header)[0]:
            raise ProbeError("response frame was invalid")
        document = json.loads(response)
        if canonical_json(document) != response:
            raise ProbeError("response frame was not canonical")
        record.update(outcome="RESPONSE", response=document)
        return record
    finally:
        record["elapsed_ns"] = time.monotonic_ns() - started
        connection.close()


def _run_as(
    uid: int,
    gid: int,
    groups: list[int],
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
) -> dict[str, Any]:
    group_option = (
        ["--clear-groups"] if not groups else [f"--groups={','.join(map(str, groups))}"]
    )
    result = _run(
        [
            "setpriv",
            f"--reuid={uid}",
            f"--regid={gid}",
            *group_option,
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(__file__).resolve()),
            *arguments,
        ],
        input_bytes=input_bytes,
    )
    return json.loads(result.stdout)


def _write_check() -> dict[str, Any]:
    checks = {
        "control_write": (_CONTROL / "policy.json", os.O_WRONLY),
        "credential_source_read": (
            Path("/etc/aragorn/runtime-action-observation.json"),
            os.O_RDONLY,
        ),
        "protected_create": (
            _PROTECTED / "sensor-must-not-create.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        ),
        "staging_create": (
            _STAGING / "sensor-must-not-stage.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        ),
    }
    results = {}
    for name, (path, flags) in checks.items():
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            results[name] = {
                "blocked": True,
                "errno": exc.errno,
                "error": errno.errorcode.get(exc.errno, "UNKNOWN"),
            }
        else:
            os.close(descriptor)
            results[name] = {"blocked": False, "errno": None, "error": None}
    return {"process": _identity(), "checks": results}


def _broker_config() -> RuntimeActionBrokerConfig:
    broker = _user("aragorn-broker")
    runtime = _user("aragorn-runtime")
    sensor = _user("aragorn-sensor")
    runtime_gid = _group("aragorn-runtime").gr_gid
    sensor_gid = _group("aragorn-sensor").gr_gid
    return RuntimeActionBrokerConfig(
        socket_path=_BACKEND,
        instance_lock_path=_CONTROL / "broker.instance.lock",
        lock_path=_CONTROL / "broker.lock",
        control_root=_CONTROL,
        protected_root=_PROTECTED,
        staging_root=_STAGING,
        policy_path=_CONTROL / "policy.json",
        revocations_path=_CONTROL / "revocations.json",
        health_path=_CONTROL / "health.json",
        observation_path=_CONTROL / "observation.json",
        state_path=_CONTROL / "state.json",
        expected_broker_uid=broker.pw_uid,
        expected_peer_uid=sensor.pw_uid,
        expected_peer_gid=sensor_gid,
        expected_runtime_digest=_RUNTIME_DIGEST,
        expected_runtime_uid=runtime.pw_uid,
        expected_runtime_gid=runtime_gid,
    )


def _publish_unhealthy() -> dict[str, Any]:
    current = json.loads((_CONTROL / "health.json").read_bytes())
    now = int(time.time())
    document = {
        "schema": "aragorn/runtime-mediator-health/v1",
        "runtime_digest": _RUNTIME_DIGEST,
        "sensor_digest": _SENSOR_DIGEST,
        "epoch": current["epoch"] + 1,
        "status": "unhealthy",
        "observed_at_unix": now,
        "expires_at_unix": now + 15,
    }
    config = _broker_config()
    publish_runtime_control_document(config.health_path, document, config)
    return {"process": _identity(), "published": document}


def _trace(
    process: subprocess.Popen[bytes],
    path: Path,
    service_pid: int,
    expected_kinds: list[str],
) -> dict[str, Any]:
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    raw = path.read_text()
    peers = _trace_peers(raw, service_pid, expected_kinds)
    return {
        "raw": raw,
        "raw_digest": "sha256:" + hashlib.sha256(raw.encode()).hexdigest(),
        "peer_credentials": peers,
    }


def _trace_peers(
    raw: str, service_pid: int, expected_kinds: list[str]
) -> list[dict[str, int]]:
    lines = raw.splitlines()
    peers = []
    kinds = []
    for index, line in enumerate(lines):
        match = _PEER_TRACE.fullmatch(line)
        if match is None:
            continue
        previous = lines[index - 1] if index else ""
        accept = _ACCEPT_TRACE.fullmatch(previous)
        connect = _CONNECT_TRACE.fullmatch(previous)
        precursor = accept or connect
        _expect(
            precursor is not None
            and int(match["service"]) == int(precursor["service"]) == service_pid
            and match["fd"] == precursor["fd"]
            and (connect is None or connect["path"] == str(_BACKEND)),
            "SO_PEERCRED trace was not paired with a successful channel syscall",
        )
        kinds.append("accept" if accept is not None else "connect")
        peers.append(
            {name: int(match[name]) for name in ("pid", "uid", "gid")}
        )
    _expect(
        raw.count("SO_PEERCRED") == len(peers) and kinds == expected_kinds,
        "SO_PEERCRED trace direction changed",
    )
    return peers


def _start_trace(pid: int, path: Path) -> subprocess.Popen[bytes]:
    process = subprocess.Popen(
        [
            "strace",
            "-f",
            "-s",
            "256",
            "-e",
            "trace=accept4,connect,getsockopt",
            "-o",
            str(path),
            "-p",
            str(pid),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if path.exists() and process.poll() is None:
            time.sleep(0.05)
            return process
        if process.poll() is not None:
            break
        time.sleep(0.01)
    stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
    raise ProbeError(f"strace did not attach to pid {pid}: {stderr.strip()}")


def _write_control(path: Path, document: object, uid: int, gid: int) -> None:
    raw = canonical_json(document)
    path.write_bytes(raw)
    os.chown(path, uid, gid)
    os.chmod(path, 0o400)


def _request(
    action: dict[str, str],
    policy: dict[str, Any],
    *,
    suffix: str,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "schema": "aragorn/runtime-action-request/v1",
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "runtime_digest": _RUNTIME_DIGEST,
        "session_id": "session-p3-3b",
        "run_id": "run-p3-3b",
        "tool_call_id": f"call-{suffix}",
        "active_skill_digest": _SKILL_DIGEST,
        **action,
        "policy_digest": canonical_digest(policy),
        "policy_version": policy["version"],
        "issued_at_unix": now,
        "expires_at_unix": now + 5,
    }


def _envelope(
    action: dict[str, str],
    policy: dict[str, Any],
    *,
    suffix: str,
    target: str,
    payload: bytes,
) -> dict[str, Any]:
    return {
        "schema": "aragorn/runtime-action-broker-request/v1",
        "request": _request(action, policy, suffix=suffix),
        "effect": {
            "schema": "aragorn/runtime-create-file/v1",
            "operation": "create",
            "target_name": target,
            "payload_base64": base64.b64encode(payload).decode("ascii"),
        },
    }


def _wait_path(path: Path) -> None:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise ProbeError(f"timed out waiting for {path}")


def _collect() -> dict[str, Any]:
    if sys.platform != "linux" or os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise ProbeError("the collector requires root in the fixed systemd container")

    harness = _harness()
    broker = _user("aragorn-broker")
    runtime = _user("aragorn-runtime")
    sensor = _user("aragorn-sensor")
    runtime_gid = _group("aragorn-runtime").gr_gid
    sensor_gid = _group("aragorn-sensor").gr_gid
    if len({broker.pw_uid, runtime.pw_uid, sensor.pw_uid}) != 3:
        raise ProbeError("service UIDs overlap")

    _systemctl("stop", _SENSOR_UNIT, _BROKER_UNIT, check=False)
    for directory in (_PROTECTED, _STAGING):
        for child in directory.iterdir():
            child.unlink()
    for name in ("health", "observation", "policy", "revocations", "state"):
        (_CONTROL / f"{name}.json").unlink(missing_ok=True)
    _run(["systemd-tmpfiles", "--create", "/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"])

    payloads = {
        "allow": ("allowed.txt", b"Aragorn P3.3b allowed create\n"),
        "unhealthy": ("unhealthy.txt", b"Aragorn P3.3b unhealthy block\n"),
        "sensor_down": ("sensor-down.txt", b"Aragorn P3.3b sensor-down block\n"),
    }
    protected_fd = os.open(_PROTECTED, os.O_RDONLY | os.O_DIRECTORY)
    try:
        actions = {
            name: _action_digests(protected_fd, target, payload)
            for name, (target, payload) in payloads.items()
        }
    finally:
        os.close(protected_fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "p3-3b-systemd-composition",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": _SENSOR_DIGEST,
        "revocation_source_digest": _REVOCATION_SOURCE,
        "allow": sorted(
            (
                {
                    "runtime_digest": _RUNTIME_DIGEST,
                    "active_skill_digest": _SKILL_DIGEST,
                    **actions[name],
                }
                for name in ("allow", "unhealthy", "sensor_down")
            ),
            key=canonical_json,
        ),
    }
    initial_request = _request(actions["allow"], policy, suffix="initial")
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
            "active": {"schema": "aragorn/runtime-active-context/v1", **attribution},
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
    _write_control(
        etc / "runtime-action-runtime.json",
        {
            "schema": "aragorn/runtime-action-runtime-binding/v1",
            "runtime_digest": _RUNTIME_DIGEST,
        },
        0,
        0,
    )
    _write_control(
        etc / "runtime-action-observation.json",
        {
            "schema": "aragorn/runtime-observation-binding/v1",
            "runtime_digest": _RUNTIME_DIGEST,
            "active_skill_digest": _SKILL_DIGEST,
            "sensor_digest": _SENSOR_DIGEST,
        },
        0,
        0,
    )

    verification = _run(
        [
            "systemd-analyze",
            "verify",
            "/usr/lib/systemd/system/aragorn-runtime-action-broker.service",
            "/usr/lib/systemd/system/aragorn-runtime-observation-publisher.service",
        ]
    )
    _systemctl("daemon-reload")
    _systemctl("start", _SENSOR_UNIT)
    _wait_path(_FRONTEND)
    _wait_path(_BACKEND)

    broker_unit = _unit(_BROKER_UNIT)
    sensor_unit = _unit(_SENSOR_UNIT)
    broker_pid = int(broker_unit["MainPID"])
    sensor_pid = int(sensor_unit["MainPID"])
    broker_process = _process(broker_pid)
    sensor_process = _process(sensor_pid)
    deployment_directories = {
        "root": _metadata(_ROOT),
        "control": _metadata(_CONTROL),
        "protected": _metadata(_PROTECTED),
        "staging": _metadata(_STAGING),
        "runtime": _metadata(_FRONTEND.parent),
    }
    deployment_sockets = {
        "backend": _metadata(_BACKEND),
        "frontend": _metadata(_FRONTEND),
    }
    deployment_mounts = {
        "broker": {
            "root": _mount(broker_pid, "/"),
            "action_root": _mount(broker_pid, str(_ROOT)),
            "credentials": _mount(
                broker_pid,
                f"/run/credentials/{_BROKER_UNIT}",
            ),
        },
        "sensor": {
            "root": _mount(sensor_pid, "/"),
            "runtime": _mount(sensor_pid, str(_FRONTEND.parent)),
            "staging": _mount(sensor_pid, str(_STAGING)),
            "credentials": _mount(
                sensor_pid,
                f"/run/credentials/{_SENSOR_UNIT}",
            ),
        },
    }
    baseline = _control_snapshot()
    before_targets = sorted(item.name for item in _PROTECTED.iterdir())

    trace_root = Path("/tmp/aragorn-p3-3b-trace")
    trace_root.mkdir(mode=0o700, exist_ok=True)
    sensor_trace_path = trace_root / "sensor.trace"
    broker_trace_path = trace_root / "broker.trace"
    sensor_trace_path.unlink(missing_ok=True)
    broker_trace_path.unlink(missing_ok=True)
    sensor_tracer = _start_trace(sensor_pid, sensor_trace_path)
    broker_tracer = _start_trace(broker_pid, broker_trace_path)

    attacker_uid = max(broker.pw_uid, runtime.pw_uid, sensor.pw_uid) + 1000
    sample = _envelope(
        actions["allow"],
        policy,
        suffix="negative",
        target=payloads["allow"][0],
        payload=payloads["allow"][1],
    )
    raw_sample = canonical_json(sample)
    direct_backend = _run_as(
        runtime.pw_uid,
        runtime_gid,
        [],
        ["client", str(_BACKEND)],
        input_bytes=raw_sample,
    )
    wrong_backend = _run_as(
        attacker_uid,
        sensor_gid,
        [runtime_gid],
        ["client", str(_BACKEND)],
        input_bytes=raw_sample,
    )
    wrong_frontend = _run_as(
        attacker_uid,
        runtime_gid,
        [],
        ["client", str(_FRONTEND)],
        input_bytes=raw_sample,
    )
    after_peer_denials = _control_snapshot()

    allowed_envelope = _envelope(
        actions["allow"],
        policy,
        suffix="allow",
        target=payloads["allow"][0],
        payload=payloads["allow"][1],
    )
    allow = _run_as(
        runtime.pw_uid,
        runtime_gid,
        [],
        ["client", str(_FRONTEND)],
        input_bytes=canonical_json(allowed_envelope),
    )
    allowed_target = _file(_PROTECTED / payloads["allow"][0])
    after_allow = {
        name: _document(_CONTROL / f"{name}.json")
        for name in ("health", "observation", "policy", "revocations", "state")
    }
    after_allow_protected = sorted(item.name for item in _PROTECTED.iterdir())
    after_allow_staging = sorted(item.name for item in _STAGING.iterdir())

    unhealthy_publication = _run_as(
        broker.pw_uid,
        runtime_gid,
        [sensor_gid],
        ["publish-unhealthy"],
    )
    published_unhealthy = _document(_CONTROL / "health.json")
    unhealthy_envelope = _envelope(
        actions["unhealthy"],
        policy,
        suffix="unhealthy",
        target=payloads["unhealthy"][0],
        payload=payloads["unhealthy"][1],
    )
    unhealthy = _run_as(
        runtime.pw_uid,
        runtime_gid,
        [],
        ["client", str(_FRONTEND)],
        input_bytes=canonical_json(unhealthy_envelope),
    )
    after_unhealthy = {
        name: _document(_CONTROL / f"{name}.json")
        for name in ("health", "observation", "policy", "revocations", "state")
    }
    after_unhealthy_protected = sorted(item.name for item in _PROTECTED.iterdir())
    after_unhealthy_staging = sorted(item.name for item in _STAGING.iterdir())

    sensor_trace = _trace(
        sensor_tracer,
        sensor_trace_path,
        sensor_pid,
        ["accept", "accept", "connect", "accept", "connect"],
    )
    broker_trace = _trace(
        broker_tracer,
        broker_trace_path,
        broker_pid,
        ["accept", "accept", "accept"],
    )

    namespace_write_check = _run(
        [
            "nsenter",
            "--target",
            str(sensor_pid),
            "--mount",
            "--",
            "setpriv",
            f"--reuid={sensor.pw_uid}",
            f"--regid={sensor_gid}",
            f"--groups={runtime_gid}",
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(__file__).resolve()),
            "write-check",
        ]
    )
    namespace_write_check_document = json.loads(namespace_write_check.stdout)

    before_sensor_stop = _control_snapshot()
    _systemctl("stop", _SENSOR_UNIT)
    sensor_down_envelope = _envelope(
        actions["sensor_down"],
        policy,
        suffix="sensor-down",
        target=payloads["sensor_down"][0],
        payload=payloads["sensor_down"][1],
    )
    sensor_down = _run_as(
        runtime.pw_uid,
        runtime_gid,
        [],
        ["client", str(_FRONTEND)],
        input_bytes=canonical_json(sensor_down_envelope),
    )
    after_sensor_stop = _control_snapshot()
    after_sensor_stop_protected = sorted(item.name for item in _PROTECTED.iterdir())
    after_sensor_stop_staging = sorted(item.name for item in _STAGING.iterdir())
    stopped_units = {"broker": _unit(_BROKER_UNIT), "sensor": _unit(_SENSOR_UNIT)}

    _expect(baseline == after_peer_denials, "peer denials changed control state")
    _expect(
        direct_backend.get("outcome") == "CONNECT_ERROR"
        and direct_backend.get("errno") == errno.EACCES,
        "runtime reached the backend socket",
    )
    _expect(
        wrong_backend.get("outcome") == "PEER_CLOSED"
        and wrong_backend.get("server_peer")
        == {"pid": broker_pid, "uid": broker.pw_uid, "gid": runtime_gid},
        "broker did not close the wrong UID",
    )
    _expect(
        wrong_frontend.get("outcome") == "PEER_CLOSED"
        and wrong_frontend.get("server_peer")
        == {"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid},
        "sensor did not close the wrong UID",
    )
    allow_response = allow.get("response", {})
    _expect(
        allow.get("outcome") == "RESPONSE"
        and allow.get("server_peer")
        == {"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid}
        and allow_response.get("verdict") == "ALLOW"
        and allow_response.get("effect_status") == "CREATED"
        and allow_response.get("reason_codes") == []
        and allow_response.get("request_digest")
        == canonical_digest(allowed_envelope["request"]),
        "allowed create did not complete through the sensor",
    )
    _expect(
        allowed_target["path"]
        == "/var/lib/aragorn-runtime-action/protected/allowed.txt"
        and allowed_target["digest"] == actions["allow"]["payload_digest"]
        and allowed_target["stat"]["device"]
        == deployment_directories["protected"]["device"]
        and allowed_target["stat"]["inode"] > 0
        and allowed_target["stat"]["uid"] == broker.pw_uid
        and allowed_target["stat"]["gid"] == runtime_gid
        and allowed_target["stat"]["mode"] == "0400"
        and allowed_target["stat"]["nlink"] == 1,
        "allowed target metadata changed",
    )
    allow_state = after_allow["state"]["document"]
    _expect(
        after_allow["health"]["document"]["status"] == "healthy"
        and after_allow["health"]["document"]["epoch"] == 2
        and after_allow["observation"]["document"]["sequence"] == 2
        and len(allow_state["consumed"]) == 1
        and allow_state["effect_journal"] is None
        and after_allow_protected == ["allowed.txt"]
        and after_allow_staging == [],
        "allowed control transition changed",
    )
    unhealthy_response = unhealthy.get("response", {})
    unhealthy_state = after_unhealthy["state"]["document"]
    _expect(
        unhealthy_publication["published"]["status"] == "unhealthy"
        and unhealthy_publication["published"]["epoch"] == 3
        and unhealthy.get("outcome") == "RESPONSE"
        and unhealthy_response.get("verdict") == "BLOCK"
        and unhealthy_response.get("effect_status") == "NOT_PERFORMED"
        and unhealthy_response.get("reason_codes") == ["MEDIATOR_UNHEALTHY"]
        and not (_PROTECTED / payloads["unhealthy"][0]).exists()
        and after_unhealthy["health"]["document"]["status"] == "unhealthy"
        and after_unhealthy["health"]["document"]["epoch"] == 4
        and after_unhealthy["observation"]["document"]["sequence"] == 3
        and len(unhealthy_state["consumed"]) == 2
        and unhealthy_state["effect_journal"] is None
        and after_unhealthy_protected == ["allowed.txt"]
        and after_unhealthy_staging == [],
        "unhealthy state did not block before effect",
    )
    _expect(
        before_sensor_stop == after_sensor_stop
        and sensor_down.get("outcome") == "CONNECT_ERROR"
        and sensor_down.get("errno") == errno.ENOENT
        and not _FRONTEND.exists()
        and not (_PROTECTED / payloads["sensor_down"][0]).exists()
        and after_sensor_stop_protected == ["allowed.txt"]
        and after_sensor_stop_staging == []
        and stopped_units["broker"]["ActiveState"] == "active"
        and stopped_units["sensor"]["ActiveState"] == "inactive",
        "sensor unavailability did not fail closed",
    )
    _expect(
        namespace_write_check_document["process"]["euid"] == sensor.pw_uid
        and namespace_write_check_document["process"]["egid"] == sensor_gid
        and namespace_write_check_document["process"]["groups"] == [runtime_gid]
        and namespace_write_check_document["checks"]
        == {
            "control_write": {
                "blocked": True,
                "errno": errno.EACCES,
                "error": "EACCES",
            },
            "credential_source_read": {
                "blocked": True,
                "errno": errno.EACCES,
                "error": "EACCES",
            },
            "protected_create": {
                "blocked": True,
                "errno": errno.EROFS,
                "error": "EROFS",
            },
            "staging_create": {
                "blocked": True,
                "errno": errno.EACCES,
                "error": "EACCES",
            },
        },
        "sensor namespace retained a forbidden path",
    )
    _expect(
        broker_process["uids"] == [broker.pw_uid] * 4
        and broker_process["gids"] == [runtime_gid] * 4
        and broker_process["groups"] == sorted([runtime_gid, sensor_gid])
        and sensor_process["uids"] == [sensor.pw_uid] * 4
        and sensor_process["gids"] == [sensor_gid] * 4
        and sensor_process["groups"] == sorted([runtime_gid, sensor_gid])
        and broker_process["capabilities_effective"] == "0000000000000000"
        and sensor_process["capabilities_effective"] == "0000000000000000"
        and broker_process["no_new_privileges"] == 1
        and sensor_process["no_new_privileges"] == 1,
        "service process identity or privilege state changed",
    )
    expected_units = {
        "broker": {
            "unit": _BROKER_UNIT,
            "record": broker_unit,
            "process": broker_process,
            "source": Path(
                "/src/packaging/systemd/aragorn-runtime-action-broker.service"
            ),
            "credential": (
                'a(ss) 1 "runtime-binding" '
                '"/etc/aragorn/runtime-action-runtime.json"'
            ),
            "command": [
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                "/usr/libexec/aragorn/aragorn-runtime-action-service.py",
                f"/run/credentials/{_BROKER_UNIT}/runtime-binding",
            ],
        },
        "sensor": {
            "unit": _SENSOR_UNIT,
            "record": sensor_unit,
            "process": sensor_process,
            "source": Path(
                "/src/packaging/systemd/"
                "aragorn-runtime-observation-publisher.service"
            ),
            "credential": (
                'a(ss) 1 "observation-binding" '
                '"/etc/aragorn/runtime-action-observation.json"'
            ),
            "command": [
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                "/usr/libexec/aragorn/aragorn-runtime-observation-service.py",
                f"/run/credentials/{_SENSOR_UNIT}/observation-binding",
            ],
        },
    }
    for value in expected_units.values():
        unit = value["record"]
        process = value["process"]
        command = value["command"]
        argv = " ".join(command)
        _expect(
            process["cmdline"] == command
            and unit["FragmentPath"] == f"/lib/systemd/system/{value['unit']}"
            and unit["FragmentResolvedPath"]
            == f"/usr/lib/systemd/system/{value['unit']}"
            and unit["FragmentDigest"] == _file(value["source"])["digest"]
            and unit["DropInPaths"] == ""
            and unit["LoadCredential"] == value["credential"]
            and unit["ExecStart"].startswith(
                "{ path=/usr/bin/python3.12 ; argv[]="
                f"{argv} ; ignore_errors=no ; start_time=["
            )
            and unit["ExecStart"].endswith(
                "] ; stop_time=[n/a] ; "
                f"pid={process['pid']} ; code=(null) ; status=0/0 }}"
            )
            and unit["ExecStartEx"].startswith(
                "{ path=/usr/bin/python3.12 ; argv[]="
                f"{argv} ; flags= ; start_time=["
            )
            and unit["ExecStartEx"].endswith(
                "] ; stop_time=[n/a] ; "
                f"pid={process['pid']} ; code=(null) ; status=0/0 }}"
            ),
            "loaded systemd execution graph changed",
        )
    _expect(
        "ro" in deployment_mounts["sensor"]["root"]["mount_options"]
        and deployment_mounts["sensor"]["staging"]["root"]
        == "/systemd/inaccessible/dir"
        and "ro" in deployment_mounts["sensor"]["staging"]["mount_options"]
        and "rw" in deployment_mounts["broker"]["action_root"]["mount_options"]
        and "ro" in deployment_mounts["broker"]["credentials"]["mount_options"]
        and "ro" in deployment_mounts["sensor"]["credentials"]["mount_options"],
        "systemd mount boundary changed",
    )
    _expect(
        broker_trace["peer_credentials"]
        == [
            {
                "pid": wrong_backend["client"]["pid"],
                "uid": attacker_uid,
                "gid": sensor_gid,
            },
            {"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid},
            {"pid": sensor_pid, "uid": sensor.pw_uid, "gid": sensor_gid},
        ]
        and sensor_trace["peer_credentials"]
        == [
            {
                "pid": wrong_frontend["client"]["pid"],
                "uid": attacker_uid,
                "gid": runtime_gid,
            },
            {
                "pid": allow["client"]["pid"],
                "uid": runtime.pw_uid,
                "gid": runtime_gid,
            },
            {"pid": broker_pid, "uid": broker.pw_uid, "gid": runtime_gid},
            {
                "pid": unhealthy["client"]["pid"],
                "uid": runtime.pw_uid,
                "gid": runtime_gid,
            },
            {"pid": broker_pid, "uid": broker.pw_uid, "gid": runtime_gid},
        ],
        "SO_PEERCRED trace did not bind the three process relationships",
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

    evidence = {
        "schema": "aragorn/runtime-action-systemd-composition-evidence/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_3B_OBSERVED",
            "bounded_systemd_profile_observed": True,
            "pinned_openclaw_composition_observed": False,
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
            "strace": _run(["strace", "--version"]).stdout.decode().splitlines()[0],
            "container_id": platform.node(),
            "base_image": _BASE_IMAGE,
            "capture_identity": _identity(),
            "pid1_mount_namespace": os.readlink("/proc/1/ns/mnt"),
            "pid1_network_namespace": os.readlink("/proc/1/ns/net"),
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
            "dockerfile": _file(
                Path("/src/benchmark/runtime-action-systemd/Dockerfile")
            ),
            "dockerignore": _file(Path("/src/.dockerignore")),
            "installer": _file(
                Path("/src/packaging/install-runtime-action-host.sh")
            ),
            "recipe": _file(
                Path("/src/scripts/capture_runtime_action_systemd.sh")
            ),
        },
        "identities": {
            "broker": {"uid": broker.pw_uid, "passwd_gid": broker.pw_gid},
            "runtime": {"uid": runtime.pw_uid, "gid": runtime_gid},
            "sensor": {"uid": sensor.pw_uid, "gid": sensor_gid},
            "attacker_uid": attacker_uid,
        },
        "deployment": {
            "units": {"broker": broker_unit, "sensor": sensor_unit},
            "processes": {"broker": broker_process, "sensor": sensor_process},
            "directories": deployment_directories,
            "sockets": deployment_sockets,
            "mounts": deployment_mounts,
            "sensor_namespace_write_check": namespace_write_check_document,
            "targets_before": before_targets,
        },
        "peer_trace": {"broker": broker_trace, "sensor": sensor_trace},
        "inputs": {
            "initial_controls": controls,
            "policy": policy,
            "actions": actions,
            "envelopes": {
                "negative": sample,
                "allow": allowed_envelope,
                "unhealthy": unhealthy_envelope,
                "sensor_down": sensor_down_envelope,
            },
        },
        "scenarios": {
            "runtime_direct_backend": {
                "status": "PASS",
                "client": direct_backend,
                "control_before": baseline,
                "control_after": after_peer_denials,
            },
            "wrong_backend_uid": {
                "status": "PASS",
                "client": wrong_backend,
                "control_before": baseline,
                "control_after": after_peer_denials,
            },
            "wrong_frontend_uid": {
                "status": "PASS",
                "client": wrong_frontend,
                "control_before": baseline,
                "control_after": after_peer_denials,
            },
            "allowed_create": {
                "status": "PASS",
                "client": allow,
                "target": allowed_target,
                "protected_entries": after_allow_protected,
                "staging_entries": after_allow_staging,
                "control_after": after_allow,
            },
            "unhealthy_block": {
                "status": "PASS",
                "publication": unhealthy_publication,
                "published_health": published_unhealthy,
                "client": unhealthy,
                "target_exists": (_PROTECTED / payloads["unhealthy"][0]).exists(),
                "protected_entries": after_unhealthy_protected,
                "staging_entries": after_unhealthy_staging,
                "control_after": after_unhealthy,
            },
            "sensor_unavailable": {
                "status": "PASS",
                "client": sensor_down,
                "target_exists": (_PROTECTED / payloads["sensor_down"][0]).exists(),
                "frontend_exists": _FRONTEND.exists(),
                "protected_entries": after_sensor_stop_protected,
                "staging_entries": after_sensor_stop_staging,
                "control_before": before_sensor_stop,
                "control_after": after_sensor_stop,
                "units": stopped_units,
            },
        },
    }
    _systemctl("stop", _BROKER_UNIT, check=False)
    return evidence


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    output_path: Path | None = None
    if arguments and arguments[0] == "client" and len(arguments) == 2:
        result = _client(Path(arguments[1]))
    elif arguments == ["write-check"]:
        result = _write_check()
    elif arguments == ["publish-unhealthy"]:
        result = _publish_unhealthy()
    elif len(arguments) == 2 and arguments[0] == "--output":
        output_path = Path(arguments[1])
        result = _collect()
    elif not arguments:
        result = _collect()
    else:
        print("usage: runtime_action_systemd_probe.py", file=sys.stderr)
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
