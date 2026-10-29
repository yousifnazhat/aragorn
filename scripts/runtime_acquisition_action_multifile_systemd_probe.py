#!/usr/bin/env python3
"""Capture one exact two-file acquisition followed by one P3.7c action."""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_acquisition_action_systemd_probe as p38b

p37c = p38b.p37c
p36b = p38b.p36b
lineage = p38b.lineage
openclaw = p38b.openclaw

_HARNESS = Path("/run/aragorn-harness.json")
_OUTPUT = Path("/evidence/runtime-acquisition-action-multifile-systemd.json")
_ACQUISITION_MARKER = Path("/run/aragorn-p38c-acquisition-complete")
_DISCONNECTED_MARKER = Path("/run/aragorn-p38c-network-disconnected")
_SOURCE_REQUEST = {
    "schema": "aragorn/github-gateway-request/v1",
    "owner": "obra",
    "repository": "superpowers",
    "commit": "f57638a74759376871509ccf080e606f62052f1b",
    "skill_path": "skills/requesting-code-review",
}
_QUARANTINE_NAMESPACE = (
    p38b._QUARANTINE_ROOT / p38b.canonical_digest(_SOURCE_REQUEST)[7:]
)
_EXPECTED_TREE_DIGEST = (
    "sha256:c3e6b4db9b149d219cd714ecabd94806c41c5a4811fdac9299f339e0bfca5d34"
)
_EXPECTED_ENTRIES = [
    {
        "path": "SKILL.md",
        "size": 2712,
        "digest": (
            "sha256:1c9e975642c859c407bc4bbc9c06a171bf9ff88267300def1e02f46047ca5ad9"
        ),
        "executable": False,
    },
    {
        "path": "code-reviewer.md",
        "size": 3385,
        "digest": (
            "sha256:7f5328dca12cb200005ae9d4386f63a9b0acb735ece57f82db206b4a3189ccae"
        ),
        "executable": False,
    },
]
_SCHEMA = "aragorn/runtime-acquisition-action-multifile-systemd-observation/v1"
_AUTHORITY = (
    "BOUNDED_LIVE_COORDINATOR_TWO_FILE_ACQUISITION_TO_RUNTIME_ACTION_"
    "OBSERVATION_ONLY_NOT_VERIFIED_RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "ADAPTED_PYTHON_3_12_CURRENT_RELEASE_NOT_RETAINED_PHASE1_RELEASE_IDENTITY",
    "ONE_LIVE_PUBLIC_GITHUB_COMMIT_AND_EXACTLY_TWO_FILE_FLAT_SKILL_ONLY",
    "FLAT_TREE_ONLY_NESTED_SKILL_ASSETS_NOT_QUALIFIED",
    "ONE_EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_ACTION_ONLY",
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "SYSTEMD_252_CGROUP_AND_DOCKER_DNS_ADAPTERS_ARE_FIXTURE_ONLY",
    "NETWORK_DISCONNECTION_IS_WRAPPER_CONTROLLED_AND_PROBE_REVERIFIED",
    "TWO_SOURCE_FILES_ARE_BOUND_TO_THE_ACTION_WITHOUT_SEMANTIC_CAUSATION_AUTHORITY",
    "P3_7C_RUNTIME_FLOW_IS_REUSED_WITHOUT_PROMOTING_ITS_PARENT_QUALIFICATION",
    "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
]
_COLLECTOR_FILES = {
    "capture_recipe": Path(
        "/src/scripts/capture_runtime_acquisition_action_multifile_systemd.sh"
    ),
    "dockerfile": Path(
        "/src/benchmark/runtime-acquisition-action-multifile-systemd/Dockerfile"
    ),
    "probe": Path(__file__).resolve(),
}
_OVERLAY_INSTALLS = [
    (
        "acquire.py",
        Path("/src/src/aragorn/acquire.py"),
        Path("/usr/lib/aragorn/aragorn/acquire.py"),
        "0444",
        "0644",
        "sha256:56942e7c1b10c58f265615c8b7abf3f199c7f98bf016be50eb6d3a98d2bd0f8c",
    ),
    (
        "cas.py",
        Path("/src/src/aragorn/cas.py"),
        Path("/usr/lib/aragorn/aragorn/cas.py"),
        "0444",
        "0644",
        "sha256:c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859",
    ),
    (
        "runtime_active_skill_lineage.py",
        Path("/src/src/aragorn/runtime_active_skill_lineage.py"),
        Path("/usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py"),
        "0444",
        "0644",
        "sha256:7f5fc7aa979efd0a719904d14b2d8576b80af302572882de90dca464291db726",
    ),
    (
        "runtime_process_profile.py",
        Path("/src/src/aragorn/runtime_process_profile.py"),
        Path("/usr/lib/aragorn/aragorn/runtime_process_profile.py"),
        "0444",
        "0644",
        "sha256:a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68",
    ),
    (
        "activate-runtime-action-worker-host.sh",
        Path("/src/packaging/activate-runtime-action-worker-host.sh"),
        Path("/usr/libexec/aragorn/activate-runtime-action-worker-host.sh"),
        "0555",
        "0755",
        "sha256:466261b94b832da010a2f27896335731cfcaeb3a87d8c15767b80c6aceb752bb",
    ),
]
_OVERLAY_BUILD_INPUTS = [
    (
        "install-runtime-capability-host.sh",
        Path("/src/packaging/install-runtime-capability-host.sh"),
        "sha256:6a7b4ec084b4dee8d974a0acab183f850be57e0acff30b616040687b307d28d9",
    ),
    (
        "install-runtime-action-worker-host.sh",
        Path("/src/packaging/install-runtime-action-worker-host.sh"),
        "sha256:885441b628298629cc07d5c68e52b852864c6a755bc10d0e7e5de406f17b4748",
    ),
]
_PARENT_ARTIFACTS = p38b._artifacts
_PARENT_PREPARE_GATEWAY = p37c._prepare_gateway
_producer: dict[str, Any] | None = None
_projected_before: dict[str, Any] | None = None


def _expect(condition: bool, message: str) -> None:
    p38b._expect(condition, message)


def _harness() -> dict[str, Any]:
    retained = p37c._stable_document_snapshot(_HARNESS)
    document = retained["document"]
    _expect(
        isinstance(document, dict)
        and document.get("schema")
        == "aragorn/runtime-acquisition-action-multifile-systemd-harness/v1"
        and document.get("capture_disposition")
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and document.get("profile_label") == "p3.8c"
        and document.get("platform") == "linux"
        and re.fullmatch(r"[0-9a-f]{40}", document.get("source_commit", "")) is not None
        and re.fullmatch(r"[0-9a-f]{64}", document.get("container_id", "")) is not None
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document.get("image_id", ""))
        is not None,
        "outer P3.8c harness identity changed",
    )
    container_cgroup = p38b._bounded_file(Path("/proc/1/cgroup"))
    _expect(
        p38b._raw_bytes(container_cgroup)
        == f"0::/docker/{document['container_id']}/init.scope\n".encode("ascii"),
        "outer P3.8c container cgroup changed",
    )
    return {**retained, "container_cgroup": container_cgroup}


def _artifacts() -> dict[str, Any]:
    parent = _PARENT_ARTIFACTS()
    parent_collector = parent.pop("collector")
    collector = {
        name: p38b._protected_artifact(path, "0555" if name != "dockerfile" else "0444")
        for name, path in _COLLECTOR_FILES.items()
    }
    installed = []
    installed_closure = []
    for (
        name,
        source_path,
        installed_path,
        source_mode,
        installed_mode,
        digest,
    ) in _OVERLAY_INSTALLS:
        source = p38b._protected_artifact(source_path, source_mode)
        target = p38b._protected_artifact(installed_path, installed_mode)
        _expect(
            source["digest"] == target["digest"] == digest
            and source["bytes"] == target["bytes"],
            f"P3.8c overlay source/install mismatch: {installed_path}",
        )
        installed.append(
            {
                "name": name,
                "source": source,
                "installed": target,
            }
        )
        installed_closure.append(
            {
                "name": name,
                "path": str(installed_path),
                "digest": target["digest"],
                "bytes": target["bytes"],
                "mode": target["stat"]["mode"],
            }
        )
    build_inputs = {}
    for name, path, digest in _OVERLAY_BUILD_INPUTS:
        record = p38b._protected_artifact(path, "0555")
        _expect(
            record["digest"] == digest,
            f"P3.8c overlay build input changed: {path}",
        )
        build_inputs[name] = record
    return {
        **parent,
        "collector": collector,
        "parent_collector": parent_collector,
        "p3_8c_overlay": {
            "installed": installed,
            "build_inputs": build_inputs,
            "installed_closure": installed_closure,
            "installed_closure_digest": p38b.canonical_digest(installed_closure),
        },
    }


def _write_exclusive(path: Path, raw: bytes, mode: int) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            _expect(written > 0, f"exclusive write made no progress: {path}")
            remaining = remaining[written:]
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_acquisition_marker() -> dict[str, Any]:
    document = {
        "schema": "aragorn/p38c-acquisition-complete-marker/v1",
        "status": "ACQUISITION_COMPLETE",
    }
    raw = p38b.canonical_json(document) + b"\n"
    _write_exclusive(_ACQUISITION_MARKER, raw, 0o600)
    return p38b._marker_snapshot(_ACQUISITION_MARKER, document)


def _wait_for_disconnected_marker() -> dict[str, Any]:
    expected = {
        "disconnected": True,
        "schema": "aragorn/p38c-network-disconnected-marker/v1",
    }
    deadline = time.monotonic() + p38b._MARKER_WAIT_SECONDS
    while True:
        try:
            return p38b._marker_snapshot(_DISCONNECTED_MARKER, expected)
        except (OSError, openclaw.ProbeError):
            pass
        if time.monotonic() >= deadline:
            raise openclaw.ProbeError(
                "wrapper did not acknowledge network disconnection"
            )
        time.sleep(0.1)


def _flat_tree_snapshot(root: Path) -> dict[str, Any]:
    root_record = p38b._path_record(root)
    _expect(
        root_record["type"] == "directory"
        and root_record["uid"] == 0
        and root_record["gid"] == 0
        and root_record["mode"] == "0555",
        f"two-file tree root custody changed: {root}",
    )
    names = sorted(path.name for path in root.iterdir())
    _expect(
        names == [entry["path"] for entry in _EXPECTED_ENTRIES],
        f"two-file tree membership changed: {root}",
    )
    files: dict[str, dict[str, Any]] = {}
    entries: list[dict[str, Any]] = []
    for expected in _EXPECTED_ENTRIES:
        path = root / expected["path"]
        metadata = p38b._path_record(path)
        _expect(
            metadata["type"] == "file"
            and metadata["uid"] == 0
            and metadata["gid"] == 0
            and metadata["mode"] == "0444"
            and metadata["nlink"] == 1
            and metadata["size"] == expected["size"],
            f"two-file tree entry custody changed: {path}",
        )
        record = p38b._bounded_file(path, expected["size"])
        entry = {
            "path": expected["path"],
            "size": record["bytes"],
            "digest": record["digest"],
            "executable": False,
        }
        _expect(entry == expected, f"two-file tree entry changed: {path}")
        files[expected["path"]] = record
        entries.append(entry)
    tree_digest = p38b.canonical_digest(entries)
    _expect(
        tree_digest == _EXPECTED_TREE_DIGEST,
        f"two-file tree digest changed: {root}",
    )
    return {
        "root": root_record,
        "entries": entries,
        "tree_digest": tree_digest,
        "files": files,
    }


def _write_projected_companion(path: Path, raw: bytes) -> None:
    _write_exclusive(path, raw, 0o444)


def _prepare_gateway(
    gateway_uid: int,
    gateway_gid: int,
    worker_uid: int,
    skill_name: str,
    skill_raw: bytes,
) -> tuple[dict[str, Any], dict[str, str], Path, str]:
    global _projected_before
    _expect(_producer is not None, "two-file producer was not retained")
    _expect(
        skill_raw == _producer["source_files"]["SKILL.md"],
        "P3.7c received a different SKILL.md",
    )
    prepared = _PARENT_PREPARE_GATEWAY(
        gateway_uid, gateway_gid, worker_uid, skill_name, skill_raw
    )
    projected_skill = prepared[2]
    _write_projected_companion(
        projected_skill.parent / "code-reviewer.md",
        _producer["source_files"]["code-reviewer.md"],
    )
    _projected_before = _flat_tree_snapshot(projected_skill.parent)
    return prepared


def _prepare_live_producer(runtime_gid: int) -> dict[str, Any]:
    global _producer
    p38b._set_stage("LIVE_COORDINATOR_TWO_FILE_ACQUISITION")
    _expect(
        not os.path.lexists(_ACQUISITION_MARKER)
        and not os.path.lexists(_DISCONNECTED_MARKER)
        and not os.path.lexists(p38b._COORDINATOR_STATE)
        and not os.path.lexists(_QUARANTINE_NAMESPACE),
        "P3.8c fresh acquisition namespace is occupied",
    )
    p38b._PROTECTED_PARENT.mkdir(mode=0o750)
    os.chown(p38b._PROTECTED_PARENT, 0, runtime_gid)
    p38b._PROTECTED_ROOT.mkdir(mode=0o750)
    os.chown(p38b._PROTECTED_ROOT, 0, runtime_gid)
    p37c._systemctl("daemon-reload")
    p37c._systemctl(
        "reset-failed", p38b._COORDINATOR_UNIT, p38b._INSTALL_UNIT, check=False
    )
    path_start = p37c._command(["systemctl", "start", p38b._COORDINATOR_PATH_UNIT])
    _expect(path_start["exit_code"] == 0, "coordinator path unit did not start")
    acquisition_started_at = p38b._iso_now()
    network_before = p38b._network_snapshot()
    p38b._require_docker_resolver(network_before)
    command = p38b._command(
        [
            str(p38b._PYTHON),
            "-I",
            "-S",
            "-B",
            str(p38b._COORDINATOR),
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
    result = p38b._canonical_command_document(command)
    p38b._validate_result(result)
    acquisition_completed_at = p38b._iso_now()
    state = p37c._stable_document_snapshot(p38b._COORDINATOR_STATE)
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
    cas = p38b.CAS(_QUARANTINE_NAMESPACE, read_only=True)
    root_manifest_digest = active["recursive"]["root_manifest_digest"]
    quarantine_receipt = p38b.verify_github_quarantine_receipt(
        cas,
        result["quarantine_receipt_digest"],
        expected_manifest_digest=root_manifest_digest,
        expected_gateway_profile_digest=result["gateway_profile_digest"],
    )
    closure = p38b.derive_github_quarantine_closure(
        cas,
        result["quarantine_receipt_digest"],
        expected_manifest_digest=root_manifest_digest,
        expected_gateway_profile_digest=result["gateway_profile_digest"],
    )
    cas_before = p38b._cas_snapshot(cas, closure)
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
        and transaction["destination"]["target_name"] == p38b._TARGET,
        "live CAS/service transaction joins changed",
    )
    record_path = p38b._PROTECTED_ROOT / p38b.ACTIVE_RUNTIME_RECORD
    record_raw, record_document = p36b._canonical_file(record_path)
    _expect(
        record_document
        == {
            "schema": p38b.ACTIVE_RUNTIME_SCHEMA,
            "authority": p38b.ACTIVE_RUNTIME_AUTHORITY,
            "transaction": transaction,
        }
        and p38b.parse_active_runtime_record(record_raw)["transaction"] == transaction,
        "live active record differs from its transaction",
    )
    claim_path = (
        p38b._PROTECTED_ROOT
        / ".aragorn-install-claims"
        / f"{transaction['context_id'][7:]}.json"
    )
    claim_raw, claim_document = p36b._canonical_file(claim_path)
    _expect(claim_document == transaction, "live claim differs from its transaction")
    version_path = p38b._PROTECTED_ROOT / transaction["version_path"]
    protected_tree = _flat_tree_snapshot(version_path)
    skill_path = version_path / "SKILL.md"
    skill_raw = p38b._raw_bytes(protected_tree["files"]["SKILL.md"])
    skill_name = next(
        (
            match.group(1)
            for line in skill_raw.decode("utf-8").splitlines()
            if (match := re.fullmatch(r"name: ([a-z0-9][a-z0-9-]*)", line))
        ),
        None,
    )
    source_files = {
        entry["path"]: cas.read(entry["digest"], max_bytes=entry["size"])
        for entry in _EXPECTED_ENTRIES
    }
    _expect(
        skill_name == "requesting-code-review"
        and protected_tree["entries"] == _EXPECTED_ENTRIES
        and transaction["tree_digest"] == _EXPECTED_TREE_DIGEST
        and p38b.canonical_digest(_EXPECTED_ENTRIES) == transaction["tree_digest"]
        and all(
            closure.get(entry["digest"]) == entry["size"]
            and source_files[entry["path"]]
            == p38b._raw_bytes(protected_tree["files"][entry["path"]])
            for entry in _EXPECTED_ENTRIES
        )
        and receipt["active"]
        == {
            "link_target": transaction["version_path"],
            "tree_digest": transaction["tree_digest"],
        },
        "live installed two-file skill differs from its transaction",
    )
    journals = {
        p38b._COORDINATOR_UNIT: p38b._journal(
            p38b._COORDINATOR_UNIT,
            acquisition_started_at,
            acquisition_completed_at,
        ),
        p38b._INSTALL_UNIT: p38b._journal(
            p38b._INSTALL_UNIT, acquisition_started_at, acquisition_completed_at
        ),
        "aragorn-gateway-*.service": p38b._journal(
            "aragorn-gateway-*.service",
            acquisition_started_at,
            acquisition_completed_at,
        ),
    }
    _expect(
        all(value["entry_count"] > 0 for value in journals.values()),
        "live coordinator/install journals are empty",
    )
    tree_entry = _EXPECTED_ENTRIES[0]
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
            "raw_digest": p38b._digest(record_raw),
        },
        "claim": {
            **lineage._record_snapshot(claim_path),
            "raw_digest": p38b._digest(claim_raw),
        },
        "tree_entry": tree_entry,
        "tree_entries": _EXPECTED_ENTRIES,
        "source_files": source_files,
        "skill_name": skill_name,
        "paths": {
            "root": p38b._PROTECTED_ROOT,
            "record": record_path,
            "active_link": p38b._PROTECTED_ROOT / p38b._TARGET,
            "versions": p38b._PROTECTED_ROOT / ".aragorn-versions",
            "target_versions": (
                p38b._PROTECTED_ROOT / ".aragorn-versions" / p38b._TARGET
            ),
            "version": version_path,
            "skill": skill_path,
            "companion": version_path / "code-reviewer.md",
            "claim": claim_path,
        },
        "service": {
            "unit": lineage._unit(p38b._INSTALL_UNIT),
            "coordinator_path_start": path_start,
        },
        "release": lineage._record_snapshot(p36b._RELEASE),
        "revocations": lineage._record_snapshot(p36b._REVOCATIONS),
    }
    p38b._acquisition = {
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
            "source_skill": p37c._raw_record(source_files["SKILL.md"]),
            "source_files": {
                name: p37c._raw_record(raw) for name, raw in source_files.items()
            },
        },
        "protected": {
            "service_receipt": receipt,
            "service_journal_identity": install_journal_identity,
            "transaction": transaction,
            "record": producer["record"],
            "claim": producer["claim"],
            "active_link": p38b._path_record(p38b._PROTECTED_ROOT / p38b._TARGET),
            "version": p38b._path_record(version_path),
            "skill": protected_tree["files"]["SKILL.md"],
            "tree_entry": tree_entry,
            "tree_entries": _EXPECTED_ENTRIES,
            "tree": protected_tree,
        },
        "journals": journals,
        "network": {"before_acquisition": network_before},
    }
    _producer = producer
    p38b._set_stage("NETWORK_DISCONNECTION")
    p38b._acquisition["network"]["acquisition_complete_marker"] = (
        _publish_acquisition_marker()
    )
    p38b._acquisition["network"]["disconnected_marker"] = (
        _wait_for_disconnected_marker()
    )
    disconnected = p38b._network_snapshot()
    p38b._require_loopback_only(disconnected)
    p38b._acquisition["network"]["after_disconnect"] = disconnected
    p38b._acquisition["network"]["public_connect"] = p38b._failed_public_connect()
    p38b._acquisition["network"]["disconnected_before_runtime"] = True
    return producer


def _collect() -> dict[str, Any]:
    global _producer, _projected_before
    _producer = None
    _projected_before = None
    with (
        mock.patch.object(p38b, "_harness", _harness),
        mock.patch.object(p38b, "_artifacts", _artifacts),
        mock.patch.object(p38b, "_prepare_live_producer", _prepare_live_producer),
        mock.patch.object(p38b, "_SOURCE_REQUEST", _SOURCE_REQUEST),
        mock.patch.object(p38b, "_QUARANTINE_NAMESPACE", _QUARANTINE_NAMESPACE),
        mock.patch.object(p38b, "_ACQUISITION_MARKER", _ACQUISITION_MARKER),
        mock.patch.object(p38b, "_DISCONNECTED_MARKER", _DISCONNECTED_MARKER),
        mock.patch.object(
            p38b, "_publish_acquisition_marker", _publish_acquisition_marker
        ),
        mock.patch.object(
            p38b, "_wait_for_disconnected_marker", _wait_for_disconnected_marker
        ),
        mock.patch.object(p38b, "_AUTHORITY", _AUTHORITY),
        mock.patch.object(p38b, "_LIMITATIONS", _LIMITATIONS),
        mock.patch.object(p37c, "_prepare_gateway", _prepare_gateway),
    ):
        result = p38b._collect()
    _expect(
        _producer is not None
        and _projected_before is not None
        and p38b._acquisition is not None,
        "two-file acquisition/projection snapshots were not retained",
    )
    protected_after = _flat_tree_snapshot(_producer["paths"]["version"])
    projected_after = _flat_tree_snapshot(
        p37c.p37b._GATEWAY_STATE / "skills" / _producer["skill_name"]
    )
    acquisition = result["acquisition"]
    protected_before = acquisition["protected"]["tree"]
    source_files = acquisition["quarantine"]["source_files"]
    checks = {
        "bounded_two_file_tree_exact": (
            protected_before["entries"]
            == _projected_before["entries"]
            == _EXPECTED_ENTRIES
            and protected_before["tree_digest"]
            == _projected_before["tree_digest"]
            == _EXPECTED_TREE_DIGEST
            == acquisition["protected"]["transaction"]["tree_digest"]
        ),
        "source_files_installed_exact": all(
            source_files[entry["path"]]["digest"] == entry["digest"]
            and p38b._raw_bytes(source_files[entry["path"]])
            == p38b._raw_bytes(protected_before["files"][entry["path"]])
            for entry in _EXPECTED_ENTRIES
        ),
        "installed_files_projected_exact": all(
            p38b._raw_bytes(protected_before["files"][entry["path"]])
            == p38b._raw_bytes(_projected_before["files"][entry["path"]])
            for entry in _EXPECTED_ENTRIES
        ),
        "flat_tree_stable_through_action": protected_after == protected_before,
        "projection_stable_through_action": projected_after == _projected_before,
        "skill_md_remains_producer_tree_entry": (
            result["bindings"]["tree_entry"] == _EXPECTED_ENTRIES[0]
            and result["action"]["inputs"]["producer"]["skill"]["digest"]
            == _EXPECTED_ENTRIES[0]["digest"]
        ),
    }
    _expect(all(checks.values()), "P3.8c two-file acquisition/action binding changed")
    result["schema"] = _SCHEMA
    result["authority"] = _AUTHORITY
    result["limitations"] = _LIMITATIONS
    result["bindings"]["checks"].update(checks)
    result["bindings"]["tree_entries"] = _EXPECTED_ENTRIES
    result["bindings"]["protected_tree"] = {
        "before_action": protected_before,
        "after_action": protected_after,
    }
    result["bindings"]["projected_tree"] = {
        "before_action": _projected_before,
        "after_action": projected_after,
    }
    result["action"]["inputs"]["producer"].update(
        {
            "tree_entries": _EXPECTED_ENTRIES,
            "protected_tree": protected_after,
            "projected_tree": projected_after,
        }
    )
    result["decision"]["status"] = "P3_8C_OBSERVED_NOT_VERIFIED"
    result["decision"]["bounded_two_file_tree_observed"] = True
    return result


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": p38b._iso_now(),
        "decision": {
            "status": "P3_8C_NOT_OBSERVED",
            "live_same_custody_install_to_action_observed": False,
            "bounded_two_file_tree_observed": False,
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
            "stage": p38b._STAGE,
            "type": type(exc).__name__,
            "message": str(exc),
        },
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print(
            "usage: runtime_acquisition_action_multifile_systemd_probe.py",
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
