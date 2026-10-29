#!/usr/bin/env python3
"""Capture one live coordinator acquisition followed by one P3.7c action."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_worker_activation_expiry_systemd_probe as p37c

import aragorn

p36b = p37c.p37b.prior
_release_package = str(p36b._PACKAGE / "src" / "aragorn")
if _release_package not in aragorn.__path__:
    aragorn.__path__.append(_release_package)

from aragorn.cas import CAS
from aragorn.github_quarantine_receipt import (
    derive_github_quarantine_closure,
    verify_github_quarantine_receipt,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_active_skill_lineage import (
    ACTIVE_RUNTIME_AUTHORITY,
    ACTIVE_RUNTIME_RECORD,
    ACTIVE_RUNTIME_SCHEMA,
    parse_active_runtime_record,
)

lineage = p36b.lineage
openclaw = p37c.openclaw

_HARNESS = Path("/run/aragorn-harness.json")
_OUTPUT = Path("/evidence/runtime-acquisition-action-systemd.json")
_ACQUISITION_MARKER = Path("/run/aragorn-p38b-acquisition-complete")
_DISCONNECTED_MARKER = Path("/run/aragorn-p38b-network-disconnected")
_COORDINATOR = Path("/usr/libexec/aragorn/aragorn-protected-install-coordinator.py")
_COORDINATOR_STATE = Path("/var/lib/aragorn-protected/coordinator-active.json")
_COORDINATOR_PATH_UNIT = "aragorn-protected-install-coordinator.path"
_COORDINATOR_UNIT = "aragorn-protected-install-coordinator.service"
_INSTALL_UNIT = p36b._SERVICE
_PYTHON = p36b._PYTHON
_QUARANTINE_ROOT = Path("/var/lib/aragorn-quarantine")
_PROTECTED_PARENT = p36b._PROTECTED_PARENT
_PROTECTED_ROOT = p36b._PROTECTED_ROOT
_TARGET = p36b._TARGET
_SOURCE_REQUEST = {
    "schema": "aragorn/github-gateway-request/v1",
    "owner": "anthropics",
    "repository": "skills",
    "commit": "2235be7c60b551f5de82ade908fd3816455afcda",
    "skill_path": "template",
}
_QUARANTINE_NAMESPACE = _QUARANTINE_ROOT / canonical_digest(_SOURCE_REQUEST)[7:]
_PACKAGE_GATEWAY = p36b._PACKAGE / "src" / "aragorn" / "github_gateway.py"
_RELEASE_IDENTITY = p36b._RELEASE
_COLLECTOR_FILES = {
    "capture_recipe": Path(
        "/src/scripts/capture_runtime_acquisition_action_systemd.sh"
    ),
    "dockerfile": Path("/src/benchmark/runtime-acquisition-action-systemd/Dockerfile"),
    "probe": Path(__file__).resolve(),
}
_INSTALLED_FILES = {
    Path("/src/src/aragorn/protected_install_coordinator.py"): (
        p36b._PACKAGE / "src" / "aragorn" / "protected_install_coordinator.py"
    ),
    Path("/src/packaging/libexec/aragorn-protected-install-coordinator.py"): (
        Path("/usr/libexec/aragorn/aragorn-protected-install-coordinator.py")
    ),
    Path("/src/packaging/systemd/aragorn-protected-install-coordinator.service"): Path(
        "/usr/lib/systemd/system/aragorn-protected-install-coordinator.service"
    ),
    Path("/src/packaging/systemd/aragorn-protected-install-coordinator.path"): (
        Path("/usr/lib/systemd/system/aragorn-protected-install-coordinator.path")
    ),
    Path(
        "/src/benchmark/runtime-acquisition-action-systemd/"
        "aragorn-protected-install-coordinator-python312.conf"
    ): Path(
        "/etc/systemd/system/aragorn-protected-install-coordinator.service.d/"
        "python312.conf"
    ),
    Path("/src/packaging/systemd/aragorn-gateway.tmpfiles"): Path(
        "/usr/lib/tmpfiles.d/aragorn-gateway.conf"
    ),
    Path(r"/src/packaging/systemd/var-lib-aragorn\x2dgateway.mount"): Path(
        r"/usr/lib/systemd/system/var-lib-aragorn\x2dgateway.mount"
    ),
}
_AUTHORITY = (
    "BOUNDED_LIVE_COORDINATOR_ACQUISITION_TO_RUNTIME_ACTION_OBSERVATION_ONLY_"
    "NOT_VERIFIED_RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "ADAPTED_PYTHON_3_12_CURRENT_RELEASE_NOT_RETAINED_PHASE1_RELEASE_IDENTITY",
    "ONE_LIVE_PUBLIC_GITHUB_COMMIT_AND_SINGLE_FILE_SKILL_ONLY",
    "ONE_EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_ACTION_ONLY",
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "SYSTEMD_252_CGROUP_AND_DOCKER_DNS_ADAPTERS_ARE_FIXTURE_ONLY",
    "NETWORK_DISCONNECTION_IS_WRAPPER_CONTROLLED_AND_PROBE_REVERIFIED",
    "SKILL_BYTES_ARE_BOUND_TO_THE_ACTION_WITHOUT_SEMANTIC_CAUSATION_AUTHORITY",
    "P3_7C_RUNTIME_FLOW_IS_REUSED_WITHOUT_PROMOTING_ITS_PARENT_QUALIFICATION",
    "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
]
_COMMAND_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TZ": "UTC",
}
_MAX_JOURNAL_BYTES = 4 * 1024 * 1024
_MARKER_WAIT_SECONDS = 120.0
_STAGE = "BOOTSTRAP"
_acquisition: dict[str, Any] | None = None


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise openclaw.ProbeError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _raw_bytes(record: dict[str, Any]) -> bytes:
    return base64.b64decode(record["base64"], validate=True)


def _harness() -> dict[str, Any]:
    retained = p37c._stable_document_snapshot(_HARNESS)
    document = retained["document"]
    _expect(
        isinstance(document, dict)
        and document.get("schema")
        == "aragorn/runtime-acquisition-action-systemd-harness/v1"
        and document.get("capture_disposition")
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and document.get("profile_label") == "p3.8b"
        and document.get("platform") == "linux"
        and re.fullmatch(r"[0-9a-f]{40}", document.get("source_commit", "")) is not None
        and re.fullmatch(r"[0-9a-f]{64}", document.get("container_id", "")) is not None
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document.get("image_id", ""))
        is not None,
        "outer P3.8b harness identity changed",
    )
    container_cgroup = _bounded_file(Path("/proc/1/cgroup"))
    _expect(
        _raw_bytes(container_cgroup)
        == f"0::/docker/{document['container_id']}/init.scope\n".encode("ascii"),
        "outer P3.8b container cgroup changed",
    )
    return {**retained, "container_cgroup": container_cgroup}


def _path_record(path: Path) -> dict[str, Any]:
    value = os.lstat(path)
    kind = (
        "directory"
        if stat.S_ISDIR(value.st_mode)
        else "file"
        if stat.S_ISREG(value.st_mode)
        else "symlink"
        if stat.S_ISLNK(value.st_mode)
        else "other"
    )
    result: dict[str, Any] = {
        "path": str(path),
        "type": kind,
        "device": value.st_dev,
        "inode": value.st_ino,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": f"{stat.S_IMODE(value.st_mode):04o}",
        "nlink": value.st_nlink,
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
    }
    if kind == "symlink":
        result["target"] = os.readlink(path)
    return result


def _command(argv: list[str], *, timeout: int, maximum: int) -> dict[str, Any]:
    started_at = _iso_now()
    started_ns = time.monotonic_ns()
    result = subprocess.run(
        argv,
        check=False,
        capture_output=True,
        timeout=timeout,
        cwd="/",
        env=_COMMAND_ENV,
    )
    completed_ns = time.monotonic_ns()
    _expect(
        len(result.stdout) <= maximum and len(result.stderr) <= maximum,
        f"bounded command output exceeded: {argv}",
    )
    return {
        "argv": argv,
        "caller": {"uid": os.getuid(), "gid": os.getgid()},
        "started_at": started_at,
        "completed_at": _iso_now(),
        "started_monotonic_ns": started_ns,
        "completed_monotonic_ns": completed_ns,
        "elapsed_ns": completed_ns - started_ns,
        "exit_code": result.returncode if result.returncode >= 0 else None,
        "signal": -result.returncode if result.returncode < 0 else None,
        "stdout": p37c._raw_record(result.stdout),
        "stderr": p37c._raw_record(result.stderr),
    }


def _canonical_command_document(command: dict[str, Any]) -> dict[str, Any]:
    raw = _raw_bytes(command["stdout"])
    stderr = _raw_bytes(command["stderr"])
    _expect(
        command["exit_code"] == 0
        and command["signal"] is None
        and stderr == b""
        and raw.endswith(b"\n")
        and raw.count(b"\n") == 1,
        "live coordinator submission failed: "
        + stderr.decode("utf-8", errors="replace")[-4000:],
    )
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise openclaw.ProbeError("live coordinator result is invalid JSON") from exc
    _expect(
        isinstance(document, dict) and canonical_json(document) + b"\n" == raw,
        "live coordinator result is not one canonical document",
    )
    return document


def _marker_snapshot(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        raw = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    _expect(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == 0
        and before.st_gid == 0
        and before.st_nlink == 1
        and stat.S_IMODE(before.st_mode) == 0o600
        and before.st_size <= 4096
        and p37c._stat_identity(before) == p37c._stat_identity(after)
        and raw == canonical_json(expected) + b"\n",
        f"marker identity or payload changed: {path}",
    )
    return {
        "document": expected,
        "file": {
            "path": str(path),
            **p37c._raw_record(raw),
            "stat": _path_record(path),
        },
    }


def _publish_acquisition_marker() -> dict[str, Any]:
    document = {
        "schema": "aragorn/p38b-acquisition-complete-marker/v1",
        "status": "ACQUISITION_COMPLETE",
    }
    raw = canonical_json(document) + b"\n"
    descriptor = os.open(
        _ACQUISITION_MARKER,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            _expect(written > 0, "acquisition marker publication made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return _marker_snapshot(_ACQUISITION_MARKER, document)


def _wait_for_disconnected_marker() -> dict[str, Any]:
    expected = {
        "disconnected": True,
        "schema": "aragorn/p38b-network-disconnected-marker/v1",
    }
    deadline = time.monotonic() + _MARKER_WAIT_SECONDS
    while True:
        try:
            return _marker_snapshot(_DISCONNECTED_MARKER, expected)
        except (OSError, openclaw.ProbeError):
            pass
        if time.monotonic() >= deadline:
            raise openclaw.ProbeError(
                "wrapper did not acknowledge network disconnection"
            )
        time.sleep(0.1)


def _bounded_file(path: Path, maximum: int = 256 * 1024) -> dict[str, Any]:
    raw = path.read_bytes()
    _expect(len(raw) <= maximum, f"bounded file exceeded: {path}")
    return {"path": str(path), **p37c._raw_record(raw), "stat": _path_record(path)}


def _protected_artifact(path: Path, mode: str) -> dict[str, Any]:
    record = p37c._file(path)
    metadata = record["stat"]
    _expect(
        metadata["type"] == "file"
        and metadata["uid"] == 0
        and metadata["gid"] == 0
        and metadata["mode"] == mode
        and metadata["nlink"] == 1,
        f"P3.8b artifact custody changed: {path}",
    )
    return record


def _artifacts() -> dict[str, Any]:
    collector = {
        name: _protected_artifact(path, "0555" if name != "dockerfile" else "0444")
        for name, path in _COLLECTOR_FILES.items()
    }
    adapter = _protected_artifact(
        Path(
            "/src/benchmark/runtime-acquisition-action-systemd/adapt-github-gateway.py"
        ),
        "0444",
    )
    preimage = _protected_artifact(
        Path(
            "/src/benchmark/runtime-acquisition-action-systemd/"
            "github-gateway-preimage.py"
        ),
        "0444",
    )
    installed_gateway = _protected_artifact(_PACKAGE_GATEWAY, "0444")
    _expect(
        preimage["digest"]
        == "sha256:21e3a74cb0927d1a160b089797cc169e1d1bfc8c68b7a2b5005904ee7aabe07c"
        and adapter["digest"]
        == "sha256:e13b2408655e1b1c2235bc7f8e511062547440ee73119a82bffd1f70f168fc30"
        and installed_gateway["digest"]
        == "sha256:b31305c4555607a19a54a3ef08a61a243fd60ab1b5cacb38b1b04569ec3cac56",
        "P3.8b gateway adaptation identity changed",
    )

    target_modes = {
        "/usr/libexec/aragorn/aragorn-protected-install-coordinator.py": "0555",
        "/usr/lib/tmpfiles.d/aragorn-gateway.conf": "0644",
    }
    installed = []
    for source_path, installed_path in sorted(
        _INSTALLED_FILES.items(), key=lambda item: str(item[0])
    ):
        source = _protected_artifact(source_path, "0444")
        target = _protected_artifact(
            installed_path, target_modes.get(str(installed_path), "0444")
        )
        _expect(
            (source["digest"], source["bytes"]) == (target["digest"], target["bytes"]),
            f"P3.8b source/install mismatch: {installed_path}",
        )
        installed.append({"source": source, "installed": target})

    release = p37c._stable_document_snapshot(_RELEASE_IDENTITY)
    expected_release = {
        "broker": {
            "digest": (
                "sha256:ea09f919760f73d5d3e3b1a0dca635eabc1db0bef4ba6ac19ec15d81278f2c70"
            ),
            "path": (
                "benchmark/admission/openclaw-v2026.7.1/"
                "protected-install-broker-recursive-v3.py"
            ),
        },
        "launcher": {
            "digest": (
                "sha256:e27b2ed1be6e24d758b148e9d6f9740d4e1c5cd74e87462d2fb2d9686dc5810b"
            ),
            "path": "/usr/libexec/aragorn/aragorn-protected-install-launcher.py",
        },
        "package": {
            "root": "/opt/aragorn-broker-p36b",
            "tree_digest": (
                "sha256:c4c2aec999a3731d0193c59114d52bfced1dca89163738a3400776f2bc42463d"
            ),
        },
        "python": {
            "digest": (
                "sha256:7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57"
            ),
            "path": "/usr/local/bin/python3.12",
        },
        "schema": "aragorn/protected-broker-launch-identity/v1",
    }
    _expect(
        release["document"] == expected_release
        and release["digest"]
        == "sha256:08ce966f9523c211ddeea9d48f386c73491d69f685c6a83d09f42d5887144cda"
        and release["file"]["stat"]["uid"] == 0
        and release["file"]["stat"]["gid"] == 0
        and release["file"]["stat"]["mode"] == "0400"
        and release["file"]["stat"]["nlink"] == 1,
        "P3.8b release identity changed",
    )
    return {
        "collector": collector,
        "gateway_adaptation": {
            "preimage": preimage,
            "adapter": adapter,
            "installed": installed_gateway,
        },
        "installed": installed,
        "release_identity": release,
    }


def _network_snapshot() -> dict[str, Any]:
    interfaces = []
    for path in sorted(Path("/sys/class/net").iterdir(), key=lambda item: item.name):
        interfaces.append(
            {
                "name": path.name,
                "address": (path / "address").read_text(encoding="ascii").strip(),
                "ifindex": int((path / "ifindex").read_text(encoding="ascii")),
                "operstate": (path / "operstate").read_text(encoding="ascii").strip(),
            }
        )
    return {
        "interfaces": interfaces,
        "ipv4_routes": _bounded_file(Path("/proc/net/route")),
        "ipv6_routes": _bounded_file(Path("/proc/net/ipv6_route")),
        "resolv_conf": _bounded_file(Path("/etc/resolv.conf")),
    }


def _require_loopback_only(snapshot: dict[str, Any]) -> None:
    _expect(
        [item["name"] for item in snapshot["interfaces"]] == ["lo"],
        "container retained a non-loopback interface after disconnection",
    )
    ipv4 = _raw_bytes(snapshot["ipv4_routes"])
    ipv6 = _raw_bytes(snapshot["ipv6_routes"])
    try:
        ipv4_lines = ipv4.decode("ascii").splitlines()
        ipv6_lines = ipv6.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise openclaw.ProbeError("kernel route tables are not ASCII") from exc
    _expect(
        bool(ipv4_lines)
        and ipv4_lines[0].split()[:2] == ["Iface", "Destination"]
        and all(line.split()[0] == "lo" for line in ipv4_lines[1:] if line.split())
        and all(line.split()[-1] == "lo" for line in ipv6_lines if line.split()),
        "container retained a non-loopback route after disconnection",
    )


def _require_docker_resolver(snapshot: dict[str, Any]) -> None:
    try:
        lines = _raw_bytes(snapshot["resolv_conf"]).decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise openclaw.ProbeError("Docker resolver configuration is not ASCII") from exc
    nameservers = [
        fields
        for line in lines
        if (fields := line.split()) and fields[0] == "nameserver"
    ]
    _expect(
        nameservers == [["nameserver", "127.0.0.11"]],
        "P3.8b requires the sole Docker embedded DNS resolver",
    )


def _failed_public_connect() -> dict[str, Any]:
    started_at = _iso_now()
    started_ns = time.monotonic_ns()
    error: BaseException | None = None
    connection: socket.socket | None = None
    try:
        connection = socket.create_connection(("github.com", 443), timeout=2.0)
    except (OSError, TimeoutError) as exc:
        error = exc
    finally:
        if connection is not None:
            connection.close()
    completed_ns = time.monotonic_ns()
    _expect(error is not None, "public GitHub connection succeeded after disconnection")
    return {
        "host": "github.com",
        "port": 443,
        "started_at": started_at,
        "completed_at": _iso_now(),
        "started_monotonic_ns": started_ns,
        "completed_monotonic_ns": completed_ns,
        "elapsed_ns": completed_ns - started_ns,
        "connected": False,
        "error": {"type": type(error).__name__, "message": str(error)},
    }


def _journal(unit: str, started_at: str, completed_at: str) -> dict[str, Any]:
    def journal_time(value: str) -> str:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
        return f"@{int(parsed.timestamp())}.{parsed.microsecond:06d}"

    command = _command(
        [
            "journalctl",
            "--all",
            "--no-pager",
            "--output=json",
            "--unit",
            unit,
            "--since",
            journal_time(started_at),
            "--until",
            journal_time(completed_at),
        ],
        timeout=30,
        maximum=_MAX_JOURNAL_BYTES,
    )
    _expect(command["exit_code"] == 0, f"journal collection failed: {unit}")
    raw = _raw_bytes(command["stdout"])
    entries = []
    for line in raw.splitlines():
        try:
            entry = json.loads(line)
        except (UnicodeDecodeError, ValueError) as exc:
            raise openclaw.ProbeError(f"journal entry is invalid: {unit}") from exc
        _expect(isinstance(entry, dict), f"journal entry is not an object: {unit}")
        entries.append(entry)
    return {"unit": unit, "entry_count": len(entries), "command": command}


def _cas_snapshot(cas: CAS, closure: dict[str, int]) -> dict[str, Any]:
    blobs = []
    for digest, size in sorted(closure.items()):
        cas.verify(digest, max_bytes=size)
        value = digest[7:]
        path = cas.root / "blobs" / "sha256" / value[:2] / value[2:]
        record = _path_record(path)
        _expect(
            record["type"] == "file"
            and record["size"] == size
            and record["mode"] == "0444",
            f"CAS blob identity changed: {digest}",
        )
        blobs.append({"digest": digest, "bytes": size, "file": record})
    return {
        "root": _path_record(cas.root),
        "closure": closure,
        "closure_digest": canonical_digest(
            [
                {"digest": digest, "bytes": size}
                for digest, size in sorted(closure.items())
            ]
        ),
        "blobs": blobs,
    }


def _validate_result(document: dict[str, Any]) -> None:
    _expect(
        set(document)
        == {
            "schema",
            "assurance",
            "operation",
            "source_request",
            "manifest_digest",
            "quarantine_receipt_digest",
            "gateway_profile_digest",
            "context_id",
            "service_request_digest",
            "installer_work_eligible",
            "runtime_conformance_qualified",
            "quarantine_authority",
            "status",
        }
        and document["schema"] == "aragorn/protected-install-coordinator-result/v1"
        and document["assurance"]
        == "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        and document["operation"] == "install"
        and document["source_request"] == _SOURCE_REQUEST
        and document["status"] == "COMPLETED_NOT_INSTALLER_AUTHORITY"
        and document["installer_work_eligible"] is False
        and document["runtime_conformance_qualified"] is False
        and document["quarantine_authority"]
        == "QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY"
        and all(
            re.fullmatch(r"sha256:[0-9a-f]{64}", document[field]) is not None
            for field in (
                "manifest_digest",
                "quarantine_receipt_digest",
                "gateway_profile_digest",
                "context_id",
                "service_request_digest",
            )
        ),
        "live coordinator success result changed",
    )


def _prepare_live_producer(runtime_gid: int) -> dict[str, Any]:
    global _acquisition
    _set_stage("LIVE_COORDINATOR_ACQUISITION")
    _expect(
        not os.path.lexists(_ACQUISITION_MARKER)
        and not os.path.lexists(_DISCONNECTED_MARKER)
        and not os.path.lexists(_COORDINATOR_STATE)
        and not os.path.lexists(_QUARANTINE_NAMESPACE),
        "P3.8b fresh acquisition namespace is occupied",
    )
    _PROTECTED_PARENT.mkdir(mode=0o750)
    os.chown(_PROTECTED_PARENT, 0, runtime_gid)
    _PROTECTED_ROOT.mkdir(mode=0o750)
    os.chown(_PROTECTED_ROOT, 0, runtime_gid)
    p37c._systemctl("daemon-reload")
    p37c._systemctl("reset-failed", _COORDINATOR_UNIT, _INSTALL_UNIT, check=False)
    path_start = p37c._command(["systemctl", "start", _COORDINATOR_PATH_UNIT])
    _expect(path_start["exit_code"] == 0, "coordinator path unit did not start")
    acquisition_started_at = _iso_now()
    network_before = _network_snapshot()
    _require_docker_resolver(network_before)
    command = _command(
        [
            str(_PYTHON),
            "-I",
            "-S",
            "-B",
            str(_COORDINATOR),
            "submit",
            "install",
            _SOURCE_REQUEST["owner"],
            _SOURCE_REQUEST["repository"],
            _SOURCE_REQUEST["commit"],
            _SOURCE_REQUEST["skill_path"],
        ],
        timeout=13 * 60,
        maximum=128 * 1024,
    )
    result = _canonical_command_document(command)
    _validate_result(result)
    acquisition_completed_at = _iso_now()
    state = p37c._stable_document_snapshot(_COORDINATOR_STATE)
    state_document = state["document"]
    active = state_document.get("expected_active")
    _expect(
        isinstance(active, dict)
        and state_document.get("schema")
        == "aragorn/protected-install-coordinator-state/v3"
        and state_document.get("assurance") == result["assurance"]
        and state_document.get("service_request_digest")
        == result["service_request_digest"]
        and active.get("source_request") == _SOURCE_REQUEST
        and all(
            active.get(field) == result[field]
            for field in (
                "context_id",
                "manifest_digest",
                "quarantine_receipt_digest",
                "gateway_profile_digest",
            )
        )
        and isinstance(active.get("recursive"), dict),
        "coordinator active state differs from its live result",
    )
    cas = CAS(_QUARANTINE_NAMESPACE, read_only=True)
    root_manifest_digest = active["recursive"]["root_manifest_digest"]
    quarantine_receipt = verify_github_quarantine_receipt(
        cas,
        result["quarantine_receipt_digest"],
        expected_manifest_digest=root_manifest_digest,
        expected_gateway_profile_digest=result["gateway_profile_digest"],
    )
    closure = derive_github_quarantine_closure(
        cas,
        result["quarantine_receipt_digest"],
        expected_manifest_digest=root_manifest_digest,
        expected_gateway_profile_digest=result["gateway_profile_digest"],
    )
    cas_before = _cas_snapshot(cas, closure)
    receipt, install_journal_identity = p36b._service_receipt()
    transaction = receipt["transaction"]
    _expect(
        quarantine_receipt["request"] == _SOURCE_REQUEST
        and receipt["source"]["request"] == _SOURCE_REQUEST
        and receipt["source"]["quarantine_receipt_digest"]
        == result["quarantine_receipt_digest"]
        and receipt["source"]["gateway_profile_digest"]
        == result["gateway_profile_digest"]
        and receipt["source"]["manifest_digest"] == result["manifest_digest"]
        and transaction["operation"] == "install"
        and transaction["context_id"] == result["context_id"]
        and transaction["manifest_digest"] == result["manifest_digest"]
        and transaction["tree_digest"] == state_document["tree_digest"]
        and transaction["version_path"] == state_document["version_path"]
        and transaction["destination"]["target_name"] == _TARGET,
        "live CAS/service transaction joins changed",
    )
    record_path = _PROTECTED_ROOT / ACTIVE_RUNTIME_RECORD
    record_raw, record_document = p36b._canonical_file(record_path)
    _expect(
        record_document
        == {
            "schema": ACTIVE_RUNTIME_SCHEMA,
            "authority": ACTIVE_RUNTIME_AUTHORITY,
            "transaction": transaction,
        }
        and parse_active_runtime_record(record_raw)["transaction"] == transaction,
        "live active record differs from its transaction",
    )
    claim_path = (
        _PROTECTED_ROOT
        / ".aragorn-install-claims"
        / f"{transaction['context_id'][7:]}.json"
    )
    claim_raw, claim_document = p36b._canonical_file(claim_path)
    _expect(claim_document == transaction, "live claim differs from its transaction")
    version_path = _PROTECTED_ROOT / transaction["version_path"]
    skill_path = version_path / "SKILL.md"
    skill_raw = skill_path.read_bytes()
    skill_name = next(
        (
            match.group(1)
            for line in skill_raw.decode("utf-8").splitlines()
            if (match := re.fullmatch(r"name: ([a-z0-9][a-z0-9-]*)", line))
        ),
        None,
    )
    tree_entry = {
        "path": "SKILL.md",
        "size": len(skill_raw),
        "digest": _digest(skill_raw),
        "executable": False,
    }
    source_skill_raw = cas.read(tree_entry["digest"], max_bytes=len(skill_raw))
    _expect(
        skill_name == "template-skill"
        and source_skill_raw == skill_raw
        and closure.get(tree_entry["digest"]) == len(skill_raw)
        and canonical_digest([tree_entry]) == transaction["tree_digest"]
        and receipt["active"]
        == {
            "link_target": transaction["version_path"],
            "tree_digest": transaction["tree_digest"],
        },
        "live installed skill differs from its transaction",
    )
    journals = {
        _COORDINATOR_UNIT: _journal(
            _COORDINATOR_UNIT, acquisition_started_at, acquisition_completed_at
        ),
        _INSTALL_UNIT: _journal(
            _INSTALL_UNIT, acquisition_started_at, acquisition_completed_at
        ),
        "aragorn-gateway-*.service": _journal(
            "aragorn-gateway-*.service",
            acquisition_started_at,
            acquisition_completed_at,
        ),
    }
    _expect(
        journals[_COORDINATOR_UNIT]["entry_count"] > 0
        and journals[_INSTALL_UNIT]["entry_count"] > 0
        and journals["aragorn-gateway-*.service"]["entry_count"] > 0,
        "live coordinator/install journals are empty",
    )
    producer = {
        "request": {
            "source_request": _SOURCE_REQUEST,
            "coordinator_result": result,
        },
        "receipt": receipt,
        "journal": install_journal_identity,
        "transaction": transaction,
        "record": {
            **lineage._record_snapshot(record_path),
            "raw_digest": _digest(record_raw),
        },
        "claim": {
            **lineage._record_snapshot(claim_path),
            "raw_digest": _digest(claim_raw),
        },
        "tree_entry": tree_entry,
        "skill_name": skill_name,
        "paths": {
            "root": _PROTECTED_ROOT,
            "record": record_path,
            "active_link": _PROTECTED_ROOT / _TARGET,
            "versions": _PROTECTED_ROOT / ".aragorn-versions",
            "target_versions": _PROTECTED_ROOT / ".aragorn-versions" / _TARGET,
            "version": version_path,
            "skill": skill_path,
            "claim": claim_path,
        },
        "service": {
            "unit": lineage._unit(_INSTALL_UNIT),
            "coordinator_path_start": path_start,
        },
        "release": lineage._record_snapshot(p36b._RELEASE),
        "revocations": lineage._record_snapshot(p36b._REVOCATIONS),
    }
    _acquisition = {
        "timing": {
            "started_at": acquisition_started_at,
            "completed_at": acquisition_completed_at,
        },
        "source_request": _SOURCE_REQUEST,
        "coordinator": {
            "command": command,
            "result": result,
            "state": state,
            "path_unit_start": path_start,
        },
        "quarantine": {
            "namespace": str(_QUARANTINE_NAMESPACE),
            "receipt_digest": result["quarantine_receipt_digest"],
            "receipt": quarantine_receipt,
            "cas_before_runtime": cas_before,
            "source_skill": p37c._raw_record(source_skill_raw),
        },
        "protected": {
            "service_receipt": receipt,
            "service_journal_identity": install_journal_identity,
            "transaction": transaction,
            "record": producer["record"],
            "claim": producer["claim"],
            "active_link": _path_record(_PROTECTED_ROOT / _TARGET),
            "version": _path_record(version_path),
            "skill": _bounded_file(skill_path),
            "tree_entry": tree_entry,
        },
        "journals": journals,
        "network": {"before_acquisition": network_before},
    }
    _set_stage("NETWORK_DISCONNECTION")
    _acquisition["network"]["acquisition_complete_marker"] = (
        _publish_acquisition_marker()
    )
    _acquisition["network"]["disconnected_marker"] = _wait_for_disconnected_marker()
    disconnected = _network_snapshot()
    _require_loopback_only(disconnected)
    _acquisition["network"]["after_disconnect"] = disconnected
    _acquisition["network"]["public_connect"] = _failed_public_connect()
    _acquisition["network"]["disconnected_before_runtime"] = True
    return producer


def _collect() -> dict[str, Any]:
    global _acquisition
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text(encoding="ascii").strip() != "systemd"
    ):
        raise openclaw.ProbeError(
            "collector requires root in the fixed P3.8b systemd container"
        )
    _set_stage("HARNESS")
    harness = _harness()
    artifacts = _artifacts()
    _acquisition = None
    _set_stage("P3_7C_RUNTIME")
    try:
        with mock.patch.object(p36b, "_prepare_producer", _prepare_live_producer):
            action = p37c._collect_live(harness)
        _expect(_acquisition is not None, "live acquisition was not retained")
        cas = CAS(_QUARANTINE_NAMESPACE, read_only=True)
        closure = _acquisition["quarantine"]["cas_before_runtime"]["closure"]
        cas_after = _cas_snapshot(cas, closure)
        final_network = _network_snapshot()
        _require_loopback_only(final_network)
        _acquisition["quarantine"]["cas_after_runtime"] = cas_after
        _acquisition["network"]["after_runtime"] = final_network
        transaction = _acquisition["protected"]["transaction"]
        action_transaction = action["inputs"]["producer"]["transaction"]
        action_record = action["inputs"]["producer"]["record"]
        coherent = action["cases"]["coherent_consumed"]
        checks = {
            "fresh_source_request_exact": _acquisition["source_request"]
            == _SOURCE_REQUEST,
            "coordinator_state_result_exact": all(
                _acquisition["coordinator"]["state"]["document"]["expected_active"][
                    field
                ]
                == _acquisition["coordinator"]["result"][field]
                for field in (
                    "context_id",
                    "manifest_digest",
                    "quarantine_receipt_digest",
                    "gateway_profile_digest",
                )
            ),
            "live_quarantine_source_exact": _acquisition["quarantine"]["receipt"][
                "request"
            ]
            == _SOURCE_REQUEST,
            "cas_unchanged_through_runtime": cas_after
            == _acquisition["quarantine"]["cas_before_runtime"],
            "transaction_reused_by_runtime": action_transaction == transaction,
            "active_record_reused_by_runtime": action_record
            == _acquisition["protected"]["record"],
            "skill_reused_by_runtime": action["inputs"]["producer"]["skill"]["digest"]
            == _acquisition["protected"]["skill"]["digest"],
            "source_blob_installed_exact": _acquisition["quarantine"]["source_skill"][
                "digest"
            ]
            == _acquisition["protected"]["skill"]["digest"]
            and _raw_bytes(_acquisition["quarantine"]["source_skill"])
            == _raw_bytes(_acquisition["protected"]["skill"]),
            "network_disconnected_before_runtime": _acquisition["network"][
                "disconnected_before_runtime"
            ]
            is True,
            "network_remained_disconnected": [
                item["name"] for item in final_network["interfaces"]
            ]
            == ["lo"],
            "one_coherent_action_completed": coherent["status"] == "OBSERVED"
            and all(coherent["checks"].values()),
        }
        _expect(all(checks.values()), "P3.8b acquisition/action binding changed")
        return {
            "schema": "aragorn/runtime-acquisition-action-systemd-observation/v1",
            "authority": _AUTHORITY,
            "recorded_at": _iso_now(),
            "harness": harness,
            "artifacts": artifacts,
            "acquisition": _acquisition,
            "action": action,
            "bindings": {
                "checks": checks,
                "source_request": _SOURCE_REQUEST,
                "context_id": transaction["context_id"],
                "manifest_digest": transaction["manifest_digest"],
                "tree_digest": transaction["tree_digest"],
                "transaction_digest": canonical_digest(transaction),
                "skill_digest": _acquisition["protected"]["skill"]["digest"],
                "tree_entry": _acquisition["protected"]["tree_entry"],
            },
            "decision": {
                "status": "P3_8B_OBSERVED_NOT_VERIFIED",
                "live_same_custody_install_to_action_observed": True,
                "retained_evidence_eligible": False,
                "same_phase1_release_identity": False,
                "semantic_skill_causation_established": False,
                "run_01_eligible": False,
                "run_02_eligible": False,
                "phase3_exit_eligible": False,
                "edr_claim_eligible": False,
                "installer_authority_eligible": False,
                "public_release_eligible": False,
            },
            "limitations": _LIMITATIONS,
        }
    finally:
        p37c.p37b._stop_stack()
        p37c._systemctl("stop", _COORDINATOR_PATH_UNIT, check=False)
        p37c._systemctl("stop", _COORDINATOR_UNIT, _INSTALL_UNIT, check=False)


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": "aragorn/runtime-acquisition-action-systemd-observation/v1",
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "decision": {
            "status": "P3_8B_NOT_OBSERVED",
            "live_same_custody_install_to_action_observed": False,
            "retained_evidence_eligible": False,
            "same_phase1_release_identity": False,
            "semantic_skill_causation_established": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "installer_authority_eligible": False,
            "public_release_eligible": False,
        },
        "limitations": _LIMITATIONS,
        "failure": {
            "code": "LIVE_CAPTURE_FAILED_CLOSED",
            "stage": _STAGE,
            "type": type(exc).__name__,
            "message": str(exc),
        },
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print(
            "usage: runtime_acquisition_action_systemd_probe.py",
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
