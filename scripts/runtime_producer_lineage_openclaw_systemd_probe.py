#!/usr/bin/env python3
"""Compose one retained protected-install service result with the P3.6a route."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pwd
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_active_lineage_openclaw_systemd_probe as lineage

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_active_skill_lineage import (
    ACTIVE_RUNTIME_AUTHORITY,
    ACTIVE_RUNTIME_RECORD,
    ACTIVE_RUNTIME_SCHEMA,
    parse_active_runtime_record,
)

_HARNESS = Path("/run/aragorn-harness.json")
_P36A_EVIDENCE = Path(
    "/src/benchmark/evidence/"
    "runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json"
)
_P36A_RAW_DIGEST = (
    "sha256:b70ca54d1efdb4b9e93ed2d3895819a2f248c132cf29d811b24635fe79517362"
)
_P36A_DIGEST = (
    "sha256:5c48201f3273dc4597e0e387f2873d6cf93940a645d6a528344c4aa9e2f7e1bd"
)
_PACKAGE = Path("/opt/aragorn-broker-p36b")
_BROKER_RELATIVE = Path(
    "benchmark/admission/openclaw-v2026.7.1/"
    "protected-install-broker-recursive-v3.py"
)
_BROKER = _PACKAGE / _BROKER_RELATIVE
_PYTHON = Path("/usr/local/bin/python3.12")
_REQUEST_TEMPLATE = Path("/var/lib/aragorn-p36b/request-template.json")
_REQUEST = Path("/run/aragorn-protected-install/request.json")
_CAS_NAMESPACE = Path(
    "/var/lib/aragorn-quarantine/"
    "918090c29df9d1dfc1f79e0534cb67d961403b4c89567c565ad4de52a042f0a1"
)
_RELEASE = Path("/etc/aragorn/protected-broker-release.json")
_REVOCATIONS = Path("/etc/aragorn/protected-install-revocations.json")
_SERVICE = "aragorn-protected-install.service"
_SERVICE_OBJECT = (
    "/org/freedesktop/systemd1/unit/"
    "aragorn_2dprotected_2dinstall_2eservice"
)
_PROTECTED_PARENT = Path("/var/lib/aragorn-protected")
_PROTECTED_ROOT = _PROTECTED_PARENT / "skills"
_PARKED_RECORD = _PROTECTED_PARENT / ".p36b-producer-active-runtime.json"
_TARGET = "aragorn-admitted"
_PRODUCER_AUTHORITY = (
    "RETAINED_CAS_PROTECTED_INSTALL_SERVICE_TRANSACTION_ONLY_"
    "NOT_ACQUISITION_OR_INSTALLER_AUTHORITY"
)
_AUTHORITY = (
    "BOUNDED_RETAINED_CAS_PROTECTED_INSTALL_TO_OPENCLAW_RUNTIME_COMPOSITION_"
    "ONLY_NOT_RUN_EDR_OR_INSTALLER_AUTHORITY"
)
_PRODUCER_ARTIFACTS = {
    "/src/benchmark/admission/openclaw-v2026.7.1/"
    "protected-install-broker-recursive-v3.py": (
        "/opt/aragorn-broker-p36b/benchmark/admission/openclaw-v2026.7.1/"
        "protected-install-broker-recursive-v3.py"
    ),
    "/src/src/aragorn/github_quarantine_receipt.py": (
        "/opt/aragorn-broker-p36b/src/aragorn/github_quarantine_receipt.py"
    ),
    "/src/src/aragorn/protected_install.py": (
        "/opt/aragorn-broker-p36b/src/aragorn/protected_install.py"
    ),
    "/src/packaging/libexec/aragorn-protected-install-launcher.py": (
        "/usr/libexec/aragorn/aragorn-protected-install-launcher.py"
    ),
    "/src/packaging/systemd/aragorn-protected-install.service": (
        "/usr/lib/systemd/system/aragorn-protected-install.service"
    ),
    "/src/benchmark/runtime-producer-lineage-openclaw-systemd/"
    "aragorn-protected-install-python312.conf": (
        "/etc/systemd/system/aragorn-protected-install.service.d/"
        "python312.conf"
    ),
}
_LIMITATIONS = [
    "ONE_RETAINED_SINGLE_FILE_CAS_INSTALL_AND_ONE_OPENCLAW_CREATE_ONLY",
    "RETAINED_PHASE1_CAS_NOT_LIVE_ACQUISITION_OR_COORDINATOR_COMPOSITION",
    "HARNESS_PINNED_CURRENT_MODULES_AND_PYTHON_3_12_NOT_RETAINED_PHASE1_RELEASE_IDENTITY",
    "EVALUATOR_REBOUND_CAS_CUSTODY_RECEIPT_NOT_ACQUISITION_ATTESTATION",
    "P3_6A_DIGEST_IS_CALLER_PIN_NOT_RUNTIME_CONFORMANCE_AUTHORITY",
    "STALE_ACTIVE_RECORD_IS_EVALUATOR_INJECTED",
    "ACTIVE_RECORD_AUTHORITY_IS_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
    "CLIENT_REPORTS_INDETERMINATE_AFTER_FRONTEND_WRITE_WHILE_BACKEND_TRACE_PROVES_NO_SUBMISSION",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "SKILL_PROMPT_PROJECTION_EVIDENCE_ONLY_NOT_SEMANTIC_CAUSATION",
    "PROCESS_PROFILE_SNAPSHOTS_NOT_CONTINUOUS_EXEC_OR_WRITER_ATTESTATION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "NO_MULTI_FILE_SKILL_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "NO_HOSTILE_ROOT_HOST_OR_FORCED_POWER_LOSS_QUALIFICATION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]

_producer: dict[str, Any] | None = None


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise lineage.openclaw.ProbeError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_file(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    document = json.loads(raw)
    _expect(canonical_json(document) == raw, f"non-canonical JSON: {path}")
    return raw, document


def _parent_evidence() -> dict[str, Any]:
    raw = _P36A_EVIDENCE.read_bytes()
    document = json.loads(raw)
    _expect(
        _digest(raw) == _P36A_RAW_DIGEST
        and canonical_digest(document) == _P36A_DIGEST
        and document.get("decision", {}).get("status")
        == "P3_6A_LIVE_PROTECTED_LINEAGE_OBSERVED",
        "retained P3.6a evidence changed",
    )
    return {
        "repository_path": (
            "benchmark/evidence/"
            "runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json"
        ),
        "captured_path": str(_P36A_EVIDENCE),
        "file_digest": _digest(raw),
        "canonical_digest": canonical_digest(document),
        "bytes": len(raw),
        "schema": document["schema"],
        "authority": document["authority"],
        "decision_status": document["decision"]["status"],
    }


def _producer_pins() -> dict[str, str]:
    analyzer = pwd.getpwnam("aragorn-analyze")
    program = r'''
import importlib.util
import json
import sys
from pathlib import Path

broker_path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("aragorn_p36b_broker", broker_path)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load protected broker")
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)
implementation = broker.candidate_implementation_digest()
executable = Path(sys.executable).resolve(strict=True)
executable_digest = broker._digest_bytes(executable.read_bytes())
script = broker._github_analyzer_script(
    implementation,
    expected_uid=int(sys.argv[2]),
    expected_gid=int(sys.argv[3]),
)
configuration = {
    "name": broker._GITHUB_SCANNER,
    "version": broker._GITHUB_ANALYZER_VERSION,
    "argv": [str(executable), "-B", "-c", script],
    "operator_argv0": str(executable),
    "executable_digest": executable_digest,
}
policy = {
    "schema": "aragorn/policy/v2",
    "id": "openclaw-live-github-broker-evidence",
    "version": 1,
    "required_analyzers": [broker._GITHUB_SCANNER],
    "hard_deny_reason_codes": [],
    "review_severities": ["critical", "high", "medium"],
    "allowed_artifact_graph_profiles": [
        "recursive-github-markdown/v1",
        "recursive-github-markdown/v2",
        "recursive-github-markdown/v3",
    ],
}
document = {
    "producer": broker._digest_bytes(broker_path.read_bytes()),
    "analyzer_implementation": implementation,
    "analyzer_executable": executable_digest,
    "analyzer_configuration": broker._digest_bytes(
        broker.canonical_json(configuration)
    ),
    "policy": broker.canonical_digest(policy),
    "analyzer_verifier": broker._module_digest(broker.analyzer_receipt_module),
    "artifact_graph_verifier": implementation,
}
sys.stdout.buffer.write(broker.canonical_json(document))
'''
    result = subprocess.run(
        [
            str(_PYTHON),
            "-I",
            "-S",
            "-B",
            "-c",
            program,
            str(_BROKER),
            str(analyzer.pw_uid),
            str(analyzer.pw_gid),
        ],
        check=True,
        capture_output=True,
        env={
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "TZ": "UTC",
        },
    )
    document = json.loads(result.stdout)
    _expect(canonical_json(document) == result.stdout, "producer pins are not canonical")
    return document


def _rebind_quarantine_receipt(request: dict[str, Any]) -> dict[str, Any]:
    program = r'''
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])

from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
import aragorn.github_quarantine_receipt as receipt

cas = CAS(Path(sys.argv[2]))
transported_digest = sys.argv[3]
manifest_digest = sys.argv[4]
gateway_profile_digest = sys.argv[5]
transported = receipt.verify_transported_github_quarantine_receipt(
    cas,
    transported_digest,
    expected_manifest_digest=manifest_digest,
    expected_gateway_profile_digest=gateway_profile_digest,
)
root = os.lstat(cas.root)
receipt_id = hashlib.sha256(
    canonical_json(
        {
            "schema": "aragorn/p36b-transported-cas-receipt-id/v1",
            "transported_receipt_digest": transported_digest,
            "root_device": root.st_dev,
            "root_inode": root.st_ino,
        }
    )
).hexdigest()
original_token_hex = receipt.secrets.token_hex
receipt.secrets.token_hex = lambda count: receipt_id if count == 32 else original_token_hex(count)
try:
    live_digest = receipt.retain_github_quarantine_receipt(
        cas,
        request=transported["request"],
        manifest_digest=transported["manifest_digest"],
        source_proof_digest=transported["source_proof_digest"],
        handoff_manifest_digest=transported["handoff_manifest_digest"],
        containment_profile=transported["containment_profile"],
        gateway_package_tree_digest=transported["gateway"]["package_tree_digest"],
        python_executable_digest=transported["gateway"]["python_executable_digest"],
    )
finally:
    receipt.secrets.token_hex = original_token_hex
live = receipt.verify_github_quarantine_receipt(
    cas,
    live_digest,
    expected_manifest_digest=manifest_digest,
    expected_gateway_profile_digest=gateway_profile_digest,
)
result = {
    "live": {"digest": live_digest, "document": live},
    "transported": {"digest": transported_digest, "document": transported},
}
sys.stdout.buffer.write(canonical_json(result))
'''
    result = subprocess.run(
        [
            str(_PYTHON),
            "-I",
            "-S",
            "-B",
            "-c",
            program,
            str(_PACKAGE / "src"),
            str(_CAS_NAMESPACE),
            request["quarantine_receipt_digest"],
            request["recursive"]["root_manifest_digest"],
            request["gateway_profile_digest"],
        ],
        check=False,
        capture_output=True,
        env={
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "TZ": "UTC",
        },
    )
    _expect(
        result.returncode == 0,
        "quarantine receipt rebinding failed: "
        + result.stderr.decode(errors="replace")[-4000:],
    )
    document = json.loads(result.stdout)
    _expect(
        canonical_json(document) == result.stdout,
        "rebound quarantine receipt result is not canonical",
    )
    request["quarantine_receipt_digest"] = document["live"]["digest"]
    return document


def _write_request() -> dict[str, Any]:
    _raw, request = _canonical_file(_REQUEST_TEMPLATE)
    quarantine_receipt = _rebind_quarantine_receipt(request)
    pins = _producer_pins()
    request.update(
        {
            "expires_at_unix": int(time.time()) + 900,
            "context_id": canonical_digest(
                {
                    "schema": "aragorn/p36b-retained-cas-context-id/v1",
                    "source_request": request["source_request"],
                    "runtime_digest": lineage.openclaw._RUNTIME_DIGEST,
                    "runtime_conformance_digest": _P36A_DIGEST,
                }
            ),
            "target_runtime_digest": lineage.openclaw._RUNTIME_DIGEST,
            "runtime_conformance_digest": _P36A_DIGEST,
            "expected_producer_implementation_digest": pins["producer"],
            "expected_analyzer_implementation_digest": pins[
                "analyzer_implementation"
            ],
            "expected_analyzer_executable_digest": pins["analyzer_executable"],
            "expected_analyzer_configuration_digest": pins[
                "analyzer_configuration"
            ],
            "expected_policy_digest": pins["policy"],
            "expected_analyzer_verifier_digest": pins["analyzer_verifier"],
            "expected_artifact_graph_verifier_digest": pins[
                "artifact_graph_verifier"
            ],
        }
    )
    _REQUEST.parent.mkdir(mode=0o700, parents=True)
    lineage.openclaw._write_document(_REQUEST, request, 0, 0, 0o400)
    return {
        "document": request,
        "digest": canonical_digest(request),
        "pins": pins,
        "quarantine_receipt": quarantine_receipt,
    }


def _service_receipt() -> tuple[dict[str, Any], dict[str, Any]]:
    journal = lineage._run(
        [
            "journalctl",
            "--all",
            "--no-pager",
            "--output=json",
            "--unit",
            _SERVICE,
        ]
    ).stdout.decode()
    candidates = []
    for raw_line in journal.splitlines():
        entry = json.loads(raw_line)
        message = entry.get("MESSAGE")
        if not isinstance(message, str):
            continue
        try:
            document = json.loads(message)
        except ValueError:
            continue
        if document.get("schema") == (
            "aragorn/openclaw-github-protected-install-broker-evidence/v1"
        ):
            candidates.append((entry, message.encode(), document))
    _expect(
        len(candidates) == 1,
        f"protected-install service receipt count is {len(candidates)}: "
        + journal[-4000:],
    )
    entry, raw, document = candidates[0]
    procfs_boot_id = (
        Path("/proc/sys/kernel/random/boot_id")
        .read_text(encoding="ascii")
        .strip()
        .replace("-", "")
    )
    expected_command = " ".join(
        (
            str(_PYTHON),
            "-I -S -B",
            str(_BROKER),
            "--github-live",
            "--service-request",
            "/run/credentials/aragorn-protected-install.service/install-request",
            "--analyzer-user aragorn-analyze",
            "--analyzer-group aragorn-analyze",
            "--cas-root /var/lib/aragorn-quarantine",
            "--protected-root /var/lib/aragorn-protected/skills",
            "--expected-broker-uid 0",
            "--revocation-file /etc/aragorn/protected-install-revocations.json",
        )
    )
    _expect(
        canonical_json(document) == raw
        and document.get("slice_status") == "PASS"
        and document.get("decision", {}).get("installer_work_eligible") is False,
        "protected-install service did not emit one canonical PASS receipt",
    )
    _expect(
        entry.get("_SYSTEMD_UNIT") == _SERVICE
        and entry.get("SYSLOG_IDENTIFIER") == "aragorn-protected-install"
        and entry.get("_EXE") == str(_PYTHON)
        and entry.get("_UID") == entry.get("_GID") == "0"
        and entry.get("_CMDLINE") == expected_command
        and re.fullmatch(r"[0-9]+", entry.get("_PID", ""))
        and int(entry["_PID"]) > 1
        and re.fullmatch(
            r"[0-9a-f]{32}", entry.get("_SYSTEMD_INVOCATION_ID", "")
        )
        and re.fullmatch(r"[0-9a-f]{32}", entry.get("_BOOT_ID", ""))
        and entry["_BOOT_ID"] == procfs_boot_id
        and re.fullmatch(r"[0-9]+", entry.get("__REALTIME_TIMESTAMP", "")),
        "protected-install journal process identity changed",
    )
    return document, {
        "message_digest": _digest(raw),
        "message_bytes": len(raw),
        "systemd_unit": entry["_SYSTEMD_UNIT"],
        "syslog_identifier": entry["SYSLOG_IDENTIFIER"],
        "invocation_id": entry.get("_SYSTEMD_INVOCATION_ID"),
        "boot_id": entry.get("_BOOT_ID"),
        "procfs_boot_id": procfs_boot_id,
        "realtime_timestamp": entry.get("__REALTIME_TIMESTAMP"),
        "executable": entry["_EXE"],
        "uid": int(entry["_UID"]),
        "gid": int(entry["_GID"]),
        "pid": int(entry["_PID"]),
        "command_line": entry["_CMDLINE"],
    }


def _prepare_producer(runtime_gid: int) -> dict[str, Any]:
    _PROTECTED_PARENT.mkdir(mode=0o750)
    os.chown(_PROTECTED_PARENT, 0, runtime_gid)
    _PROTECTED_ROOT.mkdir(mode=0o750)
    os.chown(_PROTECTED_ROOT, 0, runtime_gid)
    request = _write_request()
    verification = lineage._run(
        [
            "systemd-analyze",
            "verify",
            "/usr/lib/systemd/system/aragorn-protected-install.service",
        ]
    )
    lineage._systemctl("daemon-reload")
    lineage._systemctl("reset-failed", _SERVICE, check=False)
    try:
        lineage._systemctl("start", _SERVICE)
    except Exception as exc:
        journal = lineage._run(
            ["journalctl", "--no-pager", "--output=cat", "--unit", _SERVICE],
            check=False,
        ).stdout.decode(errors="replace")
        raise lineage.openclaw.ProbeError(
            f"protected-install service failed: {exc};{journal[-4000:]}"
        ) from exc
    receipt, journal = _service_receipt()
    record_raw, record = _canonical_file(_PROTECTED_ROOT / ACTIVE_RUNTIME_RECORD)
    transaction = receipt["transaction"]
    _expect(
        record
        == {
            "schema": ACTIVE_RUNTIME_SCHEMA,
            "authority": ACTIVE_RUNTIME_AUTHORITY,
            "transaction": transaction,
        }
        and parse_active_runtime_record(record_raw)["transaction"] == transaction,
        "producer active-runtime record differs from its receipt",
    )
    claim = (
        _PROTECTED_ROOT
        / ".aragorn-install-claims"
        / f"{transaction['context_id'][7:]}.json"
    )
    claim_raw, claim_document = _canonical_file(claim)
    _expect(claim_document == transaction, "producer claim differs from transaction")
    version = _PROTECTED_ROOT / transaction["version_path"]
    skill = version / "SKILL.md"
    skill_raw = skill.read_bytes()
    name = next(
        (
            match.group(1)
            for line in skill_raw.decode("utf-8").splitlines()
            if (match := re.fullmatch(r"name: ([a-z0-9][a-z0-9-]*)", line))
        ),
        None,
    )
    _expect(name is not None, "producer skill name is not canonical")
    tree_entry = {
        "path": "SKILL.md",
        "size": len(skill_raw),
        "digest": _digest(skill_raw),
        "executable": False,
    }
    _expect(
        canonical_digest([tree_entry]) == transaction["tree_digest"]
        and receipt["active"]["tree_digest"] == transaction["tree_digest"],
        "producer installed tree differs from its transaction",
    )
    unit = lineage._unit(_SERVICE)
    credentials = (
        lineage._run(
            [
                "busctl",
                "get-property",
                "org.freedesktop.systemd1",
                _SERVICE_OBJECT,
                "org.freedesktop.systemd1.Service",
                "LoadCredential",
            ]
        )
        .stdout.decode()
        .strip()
    )
    return {
        "request": request,
        "receipt": receipt,
        "journal": journal,
        "transaction": transaction,
        "record": {
            **lineage._record_snapshot(_PROTECTED_ROOT / ACTIVE_RUNTIME_RECORD),
            "raw_digest": _digest(record_raw),
        },
        "claim": {
            **lineage._record_snapshot(claim),
            "raw_digest": _digest(claim_raw),
        },
        "tree_entry": tree_entry,
        "skill_name": name,
        "paths": {
            "root": _PROTECTED_ROOT,
            "record": _PROTECTED_ROOT / ACTIVE_RUNTIME_RECORD,
            "active_link": _PROTECTED_ROOT / _TARGET,
            "versions": _PROTECTED_ROOT / ".aragorn-versions",
            "target_versions": _PROTECTED_ROOT / ".aragorn-versions" / _TARGET,
            "version": version,
            "skill": skill,
            "claim": claim,
        },
        "service": {
            "unit": unit,
            "load_credential": credentials,
            "systemd_verify": {
                "exit_code": verification.returncode,
                "stdout": verification.stdout.decode(),
                "stderr": verification.stderr.decode(),
            },
        },
        "release": lineage._record_snapshot(_RELEASE),
        "revocations": lineage._record_snapshot(_REVOCATIONS),
    }


def _assemble_producer_fixture(
    runtime_gid: int,
    source_manifest: dict[str, Any],
    install_context: dict[str, Any],
    *,
    stale_tree_digest: str,
) -> dict[str, Any]:
    del runtime_gid, source_manifest
    assert _producer is not None
    transaction = _producer["transaction"]
    paths = _producer["paths"]
    _expect(
        transaction["destination"] == install_context["destination"],
        "producer destination changed before runtime composition",
    )
    record_raw = paths["record"].read_bytes()
    original = os.lstat(paths["record"])
    _PARKED_RECORD.unlink(missing_ok=True)
    root_fd = os.open(_PROTECTED_ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX)
        os.rename(paths["record"], _PARKED_RECORD)
        stale_transaction = {**transaction, "tree_digest": stale_tree_digest}
        stale_record = {
            "schema": ACTIVE_RUNTIME_SCHEMA,
            "authority": ACTIVE_RUNTIME_AUTHORITY,
            "transaction": stale_transaction,
        }
        lineage._write_active_record(root_fd, stale_record)
        fcntl.flock(root_fd, fcntl.LOCK_UN)
    finally:
        os.close(root_fd)
    _producer["_original_record_raw"] = record_raw
    _producer["original_record"] = {
        "digest": _digest(record_raw),
        "device": original.st_dev,
        "inode": original.st_ino,
    }
    return {
        "record_document": {
            "schema": ACTIVE_RUNTIME_SCHEMA,
            "authority": ACTIVE_RUNTIME_AUTHORITY,
            "transaction": transaction,
        },
        "stale_record_document": stale_record,
        "transaction": transaction,
        "tree_entry": _producer["tree_entry"],
        "paths": {
            key: value
            for key, value in paths.items()
            if key != "claim"
        },
    }


def _restore_producer_record(fixture: dict[str, Any]) -> None:
    assert _producer is not None
    original = _producer["original_record"]
    original_raw = _producer["_original_record_raw"]
    root_fd = os.open(_PROTECTED_ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX)
        os.unlink(ACTIVE_RUNTIME_RECORD, dir_fd=root_fd)
        os.rename(_PARKED_RECORD, _PROTECTED_ROOT / ACTIVE_RUNTIME_RECORD)
        os.fsync(root_fd)
        fcntl.flock(root_fd, fcntl.LOCK_UN)
    finally:
        os.close(root_fd)
    restored = os.lstat(fixture["paths"]["record"])
    _expect(
        fixture["paths"]["record"].read_bytes() == original_raw
        and restored.st_dev == original["device"]
        and restored.st_ino == original["inode"],
        "original producer record was not restored by identity",
    )
    _producer["restored_record"] = lineage._record_snapshot(
        fixture["paths"]["record"]
    )


def _existing_protected_mkdir(
    original: Any,
    self: Path,
    mode: int = 0o777,
    parents: bool = False,
    exist_ok: bool = False,
) -> None:
    if self in {_PROTECTED_PARENT, _PROTECTED_ROOT} and self.is_dir():
        return
    original(self, mode=mode, parents=parents, exist_ok=exist_ok)


def _artifacts(parent: dict[str, Any]) -> dict[str, Any]:
    installed = []
    for source_path, installed_path in _PRODUCER_ARTIFACTS.items():
        source = lineage._file(Path(source_path))
        target = lineage._file(Path(installed_path))
        _expect(
            (source["digest"], source["bytes"])
            == (target["digest"], target["bytes"]),
            f"producer source/install mismatch: {source_path}",
        )
        installed.append({"source": source, "installed": target})
    return {
        "installed": parent["installed"],
        "parent_collector": parent["collector"],
        "collector": {
            "probe": lineage._file(Path(__file__).resolve()),
            "recipe": lineage._file(
                Path(
                    "/src/scripts/"
                    "capture_runtime_producer_lineage_openclaw_systemd.sh"
                )
            ),
            "dockerfile": lineage._file(
                Path(
                    "/src/benchmark/"
                    "runtime-producer-lineage-openclaw-systemd/Dockerfile"
                )
            ),
            "python_drop_in": lineage._file(
                Path(
                    "/src/benchmark/runtime-producer-lineage-openclaw-systemd/"
                    "aragorn-protected-install-python312.conf"
                )
            ),
        },
        "producer_installed": installed,
        "retained_archive": lineage._file(
            Path(
                "/src/benchmark/evidence/"
                "phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz"
            )
        ),
    }


def _collect_live(harness: dict[str, Any]) -> dict[str, Any]:
    global _producer
    runtime_gid = lineage._group("aragorn-runtime").gr_gid
    _producer = _prepare_producer(runtime_gid)
    skill = _producer["paths"]["skill"]
    skill_raw = skill.read_bytes()
    openclaw = lineage.openclaw
    original_mkdir = Path.mkdir
    patches = (
        mock.patch.object(lineage, "_parent_evidence", _parent_evidence),
        mock.patch.object(lineage, "_TARGET_NAME", _TARGET),
        mock.patch.object(lineage, "_FIXTURE_AUTHORITY", _PRODUCER_AUTHORITY),
        mock.patch.object(lineage, "_assemble_fixture", _assemble_producer_fixture),
        mock.patch.object(lineage, "_publish_coherent_record", _restore_producer_record),
        mock.patch.object(
            Path,
            "mkdir",
            lambda self, mode=0o777, parents=False, exist_ok=False: (
                _existing_protected_mkdir(
                    original_mkdir, self, mode, parents, exist_ok
                )
            ),
        ),
        mock.patch.object(openclaw, "_SKILL", skill),
        mock.patch.object(openclaw, "_SKILL_BYTES", skill_raw),
        mock.patch.object(openclaw, "_SKILL_DIGEST", _digest(skill_raw)),
        mock.patch.object(openclaw, "_SKILL_NAME", _producer["skill_name"]),
    )
    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9]:
        result = lineage._collect_live(harness)
    result.update(
        {
            "schema": (
                "aragorn/runtime-producer-lineage-openclaw-systemd-evidence/v1"
            ),
            "authority": _AUTHORITY,
            "recorded_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "limitations": _LIMITATIONS,
            "decision": {
                "status": "P3_6B_PROTECTED_INSTALL_TO_RUNTIME_OBSERVED",
                "protected_install_service_transaction_observed": True,
                "producer_active_record_exact_match_observed": True,
                "producer_to_runtime_allow_created_observed": True,
                "mismatched_active_record_broker_not_submitted_observed": True,
                "semantic_causation_eligible": False,
                "run_01_eligible": False,
                "run_02_eligible": False,
                "phase3_exit_eligible": False,
                "edr_claim_eligible": False,
                "installer_authority_eligible": False,
                "public_release_eligible": False,
            },
            "producer": {
                **{
                    key: value
                    for key, value in _producer.items()
                    if key != "paths" and not key.startswith("_")
                },
                "paths": {key: str(value) for key, value in _producer["paths"].items()},
            },
        }
    )
    result["artifacts"] = _artifacts(result["artifacts"])
    result["active_install"]["authority"] = _PRODUCER_AUTHORITY
    result["active_install"]["construction"] = _PRODUCER_AUTHORITY
    return result


def _collect() -> dict[str, Any]:
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or Path("/proc/1/comm").read_text().strip() != "systemd"
    ):
        raise lineage.openclaw.ProbeError(
            "collector requires root in the fixed systemd container"
        )
    harness = lineage._document(_HARNESS)
    lineage._reset()
    try:
        return _collect_live(harness)
    finally:
        lineage._stop_units()
        lineage._systemctl("stop", _SERVICE, check=False)


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": "aragorn/runtime-producer-lineage-openclaw-systemd-evidence/v1",
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "limitations": _LIMITATIONS,
        "decision": {
            "status": "P3_6B_PROTECTED_INSTALL_TO_RUNTIME_NOT_OBSERVED",
            "protected_install_service_transaction_observed": False,
            "producer_active_record_exact_match_observed": False,
            "producer_to_runtime_allow_created_observed": False,
            "mismatched_active_record_broker_not_submitted_observed": False,
            "semantic_causation_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "phase3_exit_eligible": False,
            "edr_claim_eligible": False,
            "installer_authority_eligible": False,
            "public_release_eligible": False,
        },
        "failure": {"type": type(exc).__name__, "message": str(exc)},
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) == 2 and arguments[0] == "--output":
        output = Path(arguments[1])
    elif not arguments:
        output = None
    else:
        print(
            "usage: runtime_producer_lineage_openclaw_systemd_probe.py "
            "[--output ABSENT_PATH]",
            file=sys.stderr,
        )
        return 64
    try:
        result = _collect()
        status = 0
    except Exception as exc:  # noqa: BLE001 - retain exact failed capture
        result = _failure(exc)
        status = 2
    lineage._publish(output, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
