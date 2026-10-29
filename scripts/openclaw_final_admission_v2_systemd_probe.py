#!/usr/bin/env python3
"""Capture one bound, conservative V2 admission aggregation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_worker_final_combined_v2_systemd_probe as bootstrap
import runtime_action_worker_final_combined_v2_route_systemd_probe as route_probe

p37c = bootstrap.p37c

_HARNESS = Path("/run/aragorn-final-admission-v2-harness.json")
_OUTPUT = Path("/evidence/openclaw-final-admission-v2-systemd.json")
_ADMISSION = Path("/src/benchmark/admission/openclaw-v2026.7.1")
_SUITE = _ADMISSION / "final-admission-v2-suite.mjs"
_OBSERVATION_HELPER = _ADMISSION / "protected-observation-v1.mjs"
_CONFIG = _ADMISSION / "protected-final-combined-config-v2.json"
_PROFILE = _ADMISSION / "protected-final-combined-profile-v2.json"
_LOCK = _ADMISSION / "protected-final-combined-runtime-v2.lock.json"
_SKILL = Path("/opt/aragorn/runtime-profile/template-skill/SKILL.md")
_PLUGIN = Path("/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker")
_ACTIVATOR = Path("/usr/libexec/aragorn/activate-runtime-action-worker-host.sh")
_PREFLIGHT = Path("/usr/lib/aragorn/aragorn/runtime_action_worker.py")
_SOURCE_RUNTIME = Path("/runtime")
_WORK_ROOT = Path("/var/lib/aragorn-final-admission-v2")
_NODE = Path("/usr/local/bin/node")
_ENV = Path("/usr/bin/env")
_CP = Path("/usr/bin/cp")
_SCHEMA = "aragorn/openclaw-final-admission-v2-systemd-capture/v1"
_AUTHORITY = (
    "BOUND_V2_ADMISSION_RAW_OBSERVATION_AGGREGATION_ONLY_"
    "SEMANTIC_CONFORMANCE_NOT_VERIFIED_NO_INSTALLER_RUN_PHASE3_EDR_RELEASE_AUTHORITY"
)
_BOUND_EVIDENCE_SCHEMA = "aragorn/openclaw-final-admission-v2-bound-evidence/v1"
_EXPECTED_CONFIG = {
    "canonical_digest": (
        "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
    ),
    "digest": "sha256:d145feb4e935e6f86c7e2bfdeefcaec5fa4ebf8f044ffa472bd7589b03bf4fe8",
}
_EXPECTED_PROFILE = {
    "canonical_digest": (
        "sha256:a20ab2dd6572ada5fac086bc818495a6e6079f55f6fcbae397687c7b19eac59e"
    ),
    "digest": "sha256:615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc",
}
_EXPECTED_LOCK = {
    "canonical_digest": (
        "sha256:95f6088dfe227e27e136c7a1fb79688e0afa0ea3ac543137d7089d0a79f2eff9"
    ),
    "digest": "sha256:4832dc99c016bd8c0f6d97133dbb7d3681d4ad18c1c225c94f10a51d6df839c1",
}
_EXPECTED_RUNTIME = {
    "entrypoint_digest": (
        "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
    ),
    "source_commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
    "tree_digest": (
        "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154"
    ),
}
_EXPECTED_SKILL_DIGEST = (
    "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
)
_EXPECTED_OBSERVATION_HELPER_DIGEST = (
    "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b"
)
_EXPECTED_ACTIVATOR_DIGEST = (
    "sha256:52dbdae05a0a394b7314d87337b1a536ba3cf9a0b999d95432341daa068ca5cf"
)
_EXPECTED_PREFLIGHT_DIGEST = (
    "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873"
)
_EXPECTED_RUNTIME_TREE = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 45_860,
    "file_count": 45_841,
    "symlink_count": 19,
    "total_bytes": 369_443_243,
    "tree_digest": _EXPECTED_RUNTIME["tree_digest"],
}
_REQUIRED_ENV = (
    "ARAGORN_CONFIG_PATH",
    "ARAGORN_PROBE_ROOT",
    "ARAGORN_PROFILE_PATH",
    "ARAGORN_RUNTIME_LOCK_PATH",
    "ARAGORN_RUNTIME_ROOT",
    "ARAGORN_RUN_NONCE",
    "ARAGORN_SKILL_PATH",
)
_ROUTE_IDS = (
    "ADM-02/update/archive-source-force-replacement",
    "ADM-02/update/clawhub-tracked-replacement",
    "ADM-02/update/config-entry-activation",
    "ADM-02/update/core-updater-plugin-replacement",
    "ADM-02/update/curator-restore-activation",
    "ADM-02/update/plugin-enable-activation",
    "ADM-02/update/plugin-force-reinstall",
    "ADM-02/update/plugin-package-skill-replacement",
    "ADM-02/update/workshop-proposal-apply",
    "ADM-02/reload/chat-session-snapshot-consumer",
    "ADM-02/reload/config-invalidation",
    "ADM-02/reload/cron-rescan",
    "ADM-02/reload/filesystem-watch-invalidation",
    "ADM-02/reload/fresh-session-reset",
    "ADM-02/reload/manual-plugin-invalidation",
    "ADM-02/reload/missing-prompt-blob-rebuild",
    "ADM-02/reload/plugin-skill-dir-activation",
    "ADM-02/reload/remote-eligibility-invalidation",
    "ADM-02/reload/sandbox-per-run-rescan",
    "ADM-02/reload/session-snapshot-consumer",
    "ADM-02/reload/workshop-invalidation",
)
_PROPERTY_IDS = ("DET-01", "ADM-01/exact-admitted-bytes")
_CATEGORY_IDS = (
    "ADM-02/install",
    "ADM-02/update",
    "ADM-02/direct-write",
    "ADM-02/rename",
    "ADM-02/symlink",
    "ADM-02/auto-discovery",
    "ADM-02/reload",
    "ADM-02/restart",
)
_ADM03_IDS = ("ADM-03/policy-failure", "ADM-03/policy-tampering")
_MAIN_PROBES = (
    "broker-symlink-probe.mjs",
    "config-activation-probe.mjs",
    "contained-probe.mjs",
    "live-reload-probe.mjs",
    "model-activation-probe.mjs",
    "plug01-probe.mjs",
    "pre-effect-write-probe.mjs",
    "probe.mjs",
    "protected-archive-replacement-probe.mjs",
    "protected-config-activation-probe.mjs",
    "protected-cron-rescan-probe.mjs",
    "protected-curator-restore-denial-probe.mjs",
    "protected-prompt-rebuild-probe.mjs",
    "protected-route-probe.mjs",
    "protected-session-snapshot-fixed-probe.mjs",
    "protected-session-snapshot-probe.mjs",
    "restart-probe.mjs",
    "update-probe.mjs",
    "workshop-bypass-probe.mjs",
)
_ADM03_PROBES = ("adm03-probe.mjs",)
_ROUTE_SLICE_ID = "ADM-02/reload/fresh-session-reset"
_ROUTE_SLICE_PROBE = "protected-route-probe.mjs"
_ROUTE_SLICE_REASON = "BOUND_RAW_ROUTE_EXECUTION_NOT_SEMANTICALLY_VERIFIED"
_ROUTE_SLICE_ARTIFACT = "artifacts/fresh-session-reset.json"
_ELIGIBILITY_KEYS = {
    "admission_profile_eligible",
    "aggregate_admission_eligible",
    "edr_eligible",
    "installer_work_eligible",
    "phase3_exit_eligible",
    "release_eligible",
    "run_01_eligible",
    "run_02_eligible",
    "run_eligible",
}
_LIMITATIONS = [
    "ONE_BOUND_FRESH_SESSION_RESET_ROUTE_EXECUTION_ONLY",
    "ONE_ROUTE_OBSERVED_IS_NOT_SEMANTIC_PASS",
    "RAW_ROUTE_DOCUMENT_RETAINED_OPAQUELY_WITH_EXACT_BYTE_IDENTITY",
    "TWENTY_OTHER_ROUTES_REMAIN_NOT_TESTED",
    "ALL_PROPERTIES_CATEGORIES_AND_ADM_03_SCENARIOS_REMAIN_NOT_TESTED",
    "OBSERVED_STATUS_WOULD_NOT_EQUAL_PASS",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "PUBLIC_NETWORK_DENIED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
_STAGE = "BOOTSTRAP"


class CaptureError(ValueError):
    """The admission capture did not stay within its exact bound contract."""


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(document: Any) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise CaptureError(f"duplicate JSON key rejected: {key}")
        output[key] = value
    return output


def _json(raw: bytes, label: str, *, canonical_lf: bool = True) -> dict[str, Any]:
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
            parse_float=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise CaptureError(f"{label} is not strict JSON: {exc}") from exc
    _expect(isinstance(document, dict), f"{label} must be an object")
    expected = _canonical(document) + (b"\n" if canonical_lf else b"")
    _expect(raw == expected, f"{label} is not canonical JSON")
    return document


def _route_raw_document(record: Any) -> dict[str, Any]:
    value = _exact_keys(
        record,
        {
            "base64",
            "bytes",
            "canonical_digest",
            "digest",
            "raw_is_canonical_json_lf",
        },
        "aggregate route slice raw document",
    )
    try:
        raw = base64.b64decode(value["base64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise CaptureError("aggregate route slice raw base64 is invalid") from exc
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise CaptureError(f"aggregate route slice raw is not strict JSON: {exc}") from exc
    _expect(isinstance(document, dict), "aggregate route slice raw must be an object")
    canonical = _canonical(document)
    _expect(
        value["bytes"] == len(raw)
        and value["digest"] == _digest(raw)
        and value["canonical_digest"] == _digest(canonical)
        and type(value["raw_is_canonical_json_lf"]) is bool
        and value["raw_is_canonical_json_lf"] == (raw == canonical + b"\n"),
        "aggregate route slice raw identity changed",
    )
    return document


def _exact_keys(document: Any, keys: set[str], label: str) -> dict[str, Any]:
    _expect(isinstance(document, dict), f"{label} must be an object")
    _expect(set(document) == keys, f"{label} keys changed")
    return document


def _raw_record(record: Any, label: str) -> bytes:
    value = _exact_keys(record, {"base64", "bytes", "digest"}, label)
    try:
        raw = base64.b64decode(value["base64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise CaptureError(f"{label} base64 is invalid") from exc
    _expect(
        value["bytes"] == len(raw) and value["digest"] == _digest(raw),
        f"{label} identity changed",
    )
    return raw


def _file(path: Path) -> dict[str, Any]:
    return p37c._file(path)


def _harness() -> dict[str, Any]:
    retained = p37c._stable_document_snapshot(_HARNESS)
    document = _exact_keys(
        retained["document"],
        {
            "schema",
            "capture_disposition",
            "source",
            "container",
            "image_lineage",
            "runtime_volume",
        },
        "outer harness",
    )
    source = _exact_keys(
        document["source"], {"commit", "tree", "verification"}, "source"
    )
    verification = _exact_keys(
        source["verification"],
        {"command", "exit_code", "commit_object", "stdout", "stderr"},
        "source verification",
    )
    commit_raw = _raw_record(verification["commit_object"], "commit object")
    stdout = _raw_record(verification["stdout"], "verification stdout")
    stderr = _raw_record(verification["stderr"], "verification stderr")
    commit_identity = hashlib.sha1(
        f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
    ).hexdigest()
    container = _exact_keys(
        document["container"],
        {
            "id",
            "image_id",
            "image_reference",
            "platform",
            "profile_label",
            "host_profile",
        },
        "container",
    )
    host_profile = _exact_keys(
        container["host_profile"],
        {
            "binds",
            "cgroupns_mode",
            "ipc_mode",
            "network_mode",
            "privileged",
            "readonly_rootfs",
            "runtime",
            "security_opt",
            "tmpfs",
            "userns_mode",
        },
        "container host profile",
    )
    lineage = _exact_keys(
        document["image_lineage"],
        {"v1", "v2", "admission", "v2_added_layers", "admission_added_layers"},
        "image lineage",
    )
    v1 = _exact_keys(lineage["v1"], {"id", "layers"}, "V1 image")
    v2 = _exact_keys(lineage["v2"], {"id", "layers"}, "V2 image")
    admission = _exact_keys(lineage["admission"], {"id", "layers"}, "admission image")
    volume = _exact_keys(
        document["runtime_volume"], {"identity", "mount"}, "runtime volume"
    )
    expected_host_profile = {
        "binds": sorted(
            [
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                (
                    "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1:"
                    "/runtime:ro"
                ),
            ]
        ),
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
        document["schema"] == "aragorn/openclaw-final-admission-v2-systemd-harness/v1"
        and document["capture_disposition"]
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is not None
        and re.fullmatch(r"[0-9a-f]{40}", source["tree"]) is not None
        and commit_identity == source["commit"]
        and commit_raw.startswith(f"tree {source['tree']}\n".encode("ascii"))
        and b"\ngpgsig " in commit_raw
        and verification["command"]
        == ["git", "verify-commit", "--raw", source["commit"]]
        and verification["exit_code"] == 0
        and not stdout
        and bool(stderr)
        and re.fullmatch(r"[0-9a-f]{64}", container["id"]) is not None
        and re.fullmatch(r"sha256:[0-9a-f]{64}", container["image_id"]) is not None
        and container["image_id"] == admission["id"]
        and container["image_reference"]
        == "aragorn-openclaw-final-admission-v2-systemd"
        and container["platform"] == "linux"
        and container["profile_label"] == "openclaw-final-admission-v2"
        and host_profile == expected_host_profile
        and v1["id"]
        == "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
        and v2["layers"][: len(v1["layers"])] == v1["layers"]
        and admission["layers"][: len(v2["layers"])] == v2["layers"]
        and lineage["v2_added_layers"] == v2["layers"][len(v1["layers"]) :]
        and lineage["admission_added_layers"]
        == admission["layers"][len(v2["layers"]) :]
        and bool(lineage["v2_added_layers"])
        and bool(lineage["admission_added_layers"])
        and volume["identity"]["name"]
        == "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
        and volume["mount"]
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1",
            "type": "volume",
        },
        "outer harness binding changed",
    )
    return retained


def _source_bindings() -> tuple[dict[str, Any], dict[str, Any]]:
    config, config_file = bootstrap._canonical_source(_CONFIG)
    profile = bootstrap._profile_snapshot()
    lock, lock_file = bootstrap._canonical_source(_LOCK)
    skill = bootstrap._skill_snapshot()
    suite = _file(_SUITE)
    observation_helper = _file(_OBSERVATION_HELPER)
    activator = _file(_ACTIVATOR)
    preflight = _file(_PREFLIGHT)
    plugin_lock = lock["deployment_bindings"]["aragorn_plugin"]
    plugin_files = []
    for record in plugin_lock["files"]:
        path = Path(record["path"])
        observed = _file(path)
        _expect(path.parent == _PLUGIN, "plugin path escaped the exact plugin root")
        _expect(observed["digest"] == record["digest"], f"plugin changed: {path.name}")
        plugin_files.append({"digest": record["digest"], "path": record["path"]})
    expected = {
        "configuration": _EXPECTED_CONFIG,
        "plugin": {
            "files": plugin_files,
            "id": plugin_lock["id"],
            "source_commit": plugin_lock["source"]["commit"],
            "source_tree": plugin_lock["source"]["tree"],
        },
        "profile": _EXPECTED_PROFILE,
        "runtime": _EXPECTED_RUNTIME,
        "runtime_lock": _EXPECTED_LOCK,
        "skill": {"digest": _EXPECTED_SKILL_DIGEST},
        "suite": {
            "digest": suite["digest"],
            "observation_helper_digest": observation_helper["digest"],
        },
    }
    _expect(
        config_file["source"]["digest"] == _EXPECTED_CONFIG["digest"]
        and config_file["canonical_digest"] == _EXPECTED_CONFIG["canonical_digest"]
        and profile["file"]["source"]["digest"] == _EXPECTED_PROFILE["digest"]
        and profile["file"]["canonical_digest"] == _EXPECTED_PROFILE["canonical_digest"]
        and lock_file["source"]["digest"] == _EXPECTED_LOCK["digest"]
        and lock_file["canonical_digest"] == _EXPECTED_LOCK["canonical_digest"]
        and skill["file"]["digest"] == _EXPECTED_SKILL_DIGEST
        and skill["file"]["bytes"] == 140
        and observation_helper["digest"] == _EXPECTED_OBSERVATION_HELPER_DIGEST
        and activator["digest"] == _EXPECTED_ACTIVATOR_DIGEST
        and preflight["digest"] == _EXPECTED_PREFLIGHT_DIGEST
        and tuple(route["id"] for route in profile["document"]["routes"]) == _ROUTE_IDS
        and all(
            route["outcome"] == "NOT_TESTED" for route in profile["document"]["routes"]
        )
        and lock["installed_runtime"]["runtime_tree"] == _EXPECTED_RUNTIME_TREE
        and lock["installed_runtime"]["openclaw_digest"]
        == _EXPECTED_RUNTIME["entrypoint_digest"]
        and lock["source"]["commit"] == _EXPECTED_RUNTIME["source_commit"]
        and config["skills"]["activation"]["sources"][0]["sha256"]
        == _EXPECTED_SKILL_DIGEST.removeprefix("sha256:"),
        "V2 source bindings changed",
    )
    artifacts = {
        "activator": activator,
        "capture": _file(
            Path("/src/scripts/capture_openclaw_final_admission_v2_systemd.sh")
        ),
        "configuration": config_file,
        "preflight": preflight,
        "probe": _file(Path(__file__).resolve()),
        "profile": profile["file"],
        "runtime_lock": lock_file,
        "skill": skill,
        "suite": suite,
        "observation_helper": observation_helper,
    }
    return expected, artifacts


def _decision(
    document: Any, status: str, label: str, counts: dict[str, int] | None = None
) -> None:
    expected_keys = {*_ELIGIBILITY_KEYS, "status"}
    if counts is not None:
        expected_keys.add("outcome_counts")
    value = _exact_keys(document, expected_keys, f"{label} decision")
    _expect(value["status"] == status, f"{label} status changed")
    _expect(
        all(value[key] is False for key in _ELIGIBILITY_KEYS),
        f"{label} promoted eligibility",
    )
    if counts is not None:
        _expect(value["outcome_counts"] == counts, f"{label} counts changed")


def _probe_inventory(value: Any, names: tuple[str, ...], label: str) -> None:
    _expect(isinstance(value, list) and len(value) == len(names), f"{label} changed")
    for index, (record, name) in enumerate(zip(value, names, strict=True)):
        item = _exact_keys(record, {"digest", "name"}, f"{label}[{index}]")
        _expect(item["name"] == name, f"{label}[{index}] name changed")
        _expect(
            item["digest"] == _file(_ADMISSION / name)["digest"],
            f"{label}[{index}] digest changed",
        )


def _manifest(document: dict[str, Any], nonce: str, bindings: dict[str, Any]) -> None:
    _exact_keys(
        document,
        {
            "assurance",
            "bindings",
            "contract",
            "decision",
            "limitations",
            "mode",
            "run_nonce",
            "schema",
        },
        "manifest",
    )
    contract = _exact_keys(
        document["contract"],
        {"adm03", "bound_evidence_schema", "environment", "main", "row_statuses"},
        "manifest contract",
    )
    main = _exact_keys(
        contract["main"],
        {
            "allowed_probe_modules",
            "category_ids",
            "filename",
            "property_ids",
            "route_ids",
            "schema",
        },
        "manifest main contract",
    )
    adm03 = _exact_keys(
        contract["adm03"],
        {"allowed_probe_modules", "filename", "scenario_ids", "schema"},
        "manifest ADM-03 contract",
    )
    _probe_inventory(
        main["allowed_probe_modules"], _MAIN_PROBES, "main probe inventory"
    )
    _probe_inventory(
        adm03["allowed_probe_modules"], _ADM03_PROBES, "ADM-03 probe inventory"
    )
    _expect(
        document["schema"] == "aragorn/openclaw-final-admission-v2-manifest/v1"
        and document["assurance"]
        == "BOUND_INPUT_CONTRACT_ONLY_NOT_CONFORMANCE_AUTHORITY"
        and document["mode"] == "manifest"
        and document["run_nonce"] == nonce
        and document["bindings"] == bindings
        and contract["bound_evidence_schema"] == _BOUND_EVIDENCE_SCHEMA
        and contract["environment"] == list(_REQUIRED_ENV)
        and contract["row_statuses"] == ["FAIL", "NOT_TESTED", "OBSERVED"]
        and main["filename"] == "main-input.json"
        and main["schema"] == "aragorn/openclaw-final-admission-v2-main-input/v1"
        and main["property_ids"] == list(_PROPERTY_IDS)
        and main["category_ids"] == list(_CATEGORY_IDS)
        and main["route_ids"] == list(_ROUTE_IDS)
        and adm03["filename"] == "adm03-input.json"
        and adm03["schema"] == "aragorn/openclaw-final-admission-v2-adm03-input/v1"
        and adm03["scenario_ids"] == list(_ADM03_IDS),
        "manifest contract changed",
    )
    _decision(document["decision"], "NOT_TESTED", "manifest")


def _row(identifier: str) -> dict[str, Any]:
    return {
        "evidence_refs": [],
        "id": identifier,
        "reason_codes": ["SEMANTIC_EVIDENCE_NOT_PRODUCED"],
        "status": "NOT_TESTED",
    }


def _rows(identifiers: tuple[str, ...]) -> list[dict[str, Any]]:
    return [_row(identifier) for identifier in identifiers]


def _observed_route_row(identifier: str, evidence_digest: str) -> dict[str, Any]:
    _expect(identifier == _ROUTE_SLICE_ID, "aggregate route slice identity changed")
    _expect(
        re.fullmatch(r"sha256:[0-9a-f]{64}", evidence_digest) is not None,
        "aggregate route slice evidence digest is invalid",
    )
    return {
        "evidence_refs": [evidence_digest],
        "id": identifier,
        "reason_codes": [_ROUTE_SLICE_REASON],
        "status": "OBSERVED",
    }


def _write_input(path: Path, document: dict[str, Any]) -> dict[str, Any]:
    raw = _canonical(document) + b"\n"
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400
    )
    try:
        written = os.write(descriptor, raw)
        _expect(written == len(raw), "input write was short")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = path.stat(follow_symlinks=False)
    _expect(
        stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o400
        and metadata.st_nlink == 1
        and path.read_bytes() == raw,
        "input file identity changed",
    )
    return {"bytes": len(raw), "digest": _digest(raw), "path": path.name}


def _main_input(
    nonce: str, bindings: dict[str, Any], artifact: dict[str, Any]
) -> dict[str, Any]:
    record = _exact_keys(artifact, {"digest", "path", "schema"}, "route artifact")
    _expect(
        record["path"] == _ROUTE_SLICE_ARTIFACT
        and record["schema"] == _BOUND_EVIDENCE_SCHEMA
        and re.fullmatch(r"sha256:[0-9a-f]{64}", record["digest"]) is not None,
        "route artifact contract changed",
    )
    routes = _rows(_ROUTE_IDS)
    route_index = _ROUTE_IDS.index(_ROUTE_SLICE_ID)
    routes[route_index] = _observed_route_row(
        _ROUTE_SLICE_ID, record["digest"]
    )
    return {
        "artifacts": [record],
        "bindings": bindings,
        "formal_categories": _rows(_CATEGORY_IDS),
        "mode": "main",
        "properties": _rows(_PROPERTY_IDS),
        "routes": routes,
        "run_nonce": nonce,
        "schema": "aragorn/openclaw-final-admission-v2-main-input/v1",
    }


def _reject_promoted_eligibility(value: Any, label: str = "route observation") -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_promoted_eligibility(item, f"{label}[{index}]")
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        if key.endswith("_eligible"):
            _expect(item is False, f"{label}.{key} promoted eligibility")
        _reject_promoted_eligibility(item, f"{label}.{key}")


def _route_slice_observation() -> dict[str, Any]:
    with mock.patch.object(bootstrap, "_harness", _harness):
        observation = route_probe._collect(_ROUTE_SLICE_ID)
    document = _exact_keys(
        observation,
        {
            "authority",
            "composition",
            "decision",
            "limitations",
            "recorded_at",
            "route_id",
            "route_observation",
            "schema",
            "source_artifacts",
        },
        "aggregate route slice observation",
    )
    decision = _exact_keys(
        document["decision"],
        {
            *_ELIGIBILITY_KEYS,
            "route_fail_count",
            "route_not_tested_count",
            "route_observation_status",
            "route_pass_count",
            "status",
        },
        "aggregate route slice decision",
    )
    composition = _exact_keys(
        document["composition"],
        {
            "action",
            "authority",
            "bindings",
            "decision",
            "limitations",
            "profile",
            "recorded_at",
            "schema",
        },
        "aggregate route slice composition",
    )
    composition_decision = _exact_keys(
        composition["decision"],
        {
            *_ELIGIBILITY_KEYS,
            "p3_7c_activation_action_observed",
            "route_fail_count",
            "route_not_tested_count",
            "route_pass_count",
            "status",
        },
        "aggregate route slice composition decision",
    )
    route = _exact_keys(
        document["route_observation"],
        {
            "bundle",
            "document",
            "execution",
            "gateway_pid_binding",
            "raw",
            "route",
            "stack_before",
        },
        "aggregate route slice native observation",
    )
    native_route = _exact_keys(
        route["route"],
        {
            "action_id",
            "id",
            "reason_codes",
            "status",
        },
        "aggregate route slice native route",
    )
    native_document = _route_raw_document(route["raw"])
    _reject_promoted_eligibility(document)
    _expect(
        document["schema"]
        == "aragorn/runtime-action-worker-final-combined-v2-route-systemd-observation/v1"
        and document["authority"] == route_probe._AUTHORITY
        and document["route_id"] == _ROUTE_SLICE_ID
        and decision["status"]
        == "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED"
        and decision["route_observation_status"] == "OBSERVED"
        and decision["route_pass_count"] == 0
        and decision["route_fail_count"] == 0
        and decision["route_not_tested_count"] == 21
        and all(decision[key] is False for key in _ELIGIBILITY_KEYS)
        and composition["schema"] == bootstrap._SCHEMA
        and composition["authority"] == bootstrap._AUTHORITY
        and composition_decision["status"]
        == "FINAL_COMBINED_V2_ACTION_OBSERVED_PROFILE_NOT_TESTED"
        and composition_decision["p3_7c_activation_action_observed"] is True
        and composition_decision["route_pass_count"] == 0
        and composition_decision["route_fail_count"] == 0
        and composition_decision["route_not_tested_count"] == 21
        and all(composition_decision[key] is False for key in _ELIGIBILITY_KEYS)
        and native_route["id"] == _ROUTE_SLICE_ID
        and native_route["action_id"] == "fresh-session-reset"
        and native_route["reason_codes"] == []
        and native_route["status"] == "OBSERVED",
        "aggregate route slice did not remain one raw non-promoting observation",
    )
    _expect(
        route["document"] == native_document,
        "aggregate route slice parsed document differs from raw bytes",
    )
    return document


def _route_slice_probe_digest(observation: dict[str, Any]) -> str:
    source_artifacts = _exact_keys(
        observation["source_artifacts"],
        {"collector", "materializer", "probe_bundle", "v1_route_injector"},
        "aggregate route slice source artifacts",
    )
    bundle = source_artifacts["probe_bundle"]
    _expect(isinstance(bundle, list), "aggregate route slice probe bundle changed")
    matches = [
        item
        for item in bundle
        if isinstance(item, dict) and item.get("name") == _ROUTE_SLICE_PROBE
    ]
    _expect(len(matches) == 1, "aggregate route slice probe identity is ambiguous")
    match = _exact_keys(
        matches[0], {"bytes", "digest", "name"}, "aggregate route slice probe"
    )
    installed = _file(_ADMISSION / _ROUTE_SLICE_PROBE)
    _expect(
        match["bytes"] == installed["bytes"]
        and match["digest"] == installed["digest"],
        "aggregate route slice probe alias differs from the executed probe",
    )
    return installed["digest"]


def _bound_route_artifact_document(
    nonce: str,
    bindings: dict[str, Any],
    observation: dict[str, Any],
    probe_digest: str,
) -> dict[str, Any]:
    _expect(
        re.fullmatch(r"[0-9a-f]{64}", nonce) is not None,
        "bound route artifact nonce changed",
    )
    _expect(
        re.fullmatch(r"sha256:[0-9a-f]{64}", probe_digest) is not None,
        "bound route artifact probe digest changed",
    )
    return {
        "bindings": bindings,
        "mode": "main",
        "observation": observation,
        "probe_digest": probe_digest,
        "probe_module": _ROUTE_SLICE_PROBE,
        "run_nonce": nonce,
        "schema": _BOUND_EVIDENCE_SCHEMA,
    }


def _retained_route_slice_observation(document: dict[str, Any]) -> dict[str, Any]:
    raw = _canonical(document) + b"\n"
    return {
        "decision": {
            "semantic_pass_verified": False,
            "status": "OBSERVED_NOT_PASS",
            **{key: False for key in sorted(_ELIGIBILITY_KEYS)},
        },
        "limitations": [
            "RAW_ROUTE_EXECUTION_ONLY",
            "OBSERVED_IS_NOT_PASS",
            "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "route_capture": {
            "base64": base64.b64encode(raw).decode("ascii"),
            "bytes": len(raw),
            "digest": _digest(raw),
        },
        "route_capture_authority": document["authority"],
        "route_capture_schema": document["schema"],
        "route_capture_status": "OBSERVED",
        "route_id": _ROUTE_SLICE_ID,
        "schema": "aragorn/openclaw-final-admission-v2-route-slice-observation/v1",
    }


def _write_route_slice_artifact(
    root: Path,
    nonce: str,
    bindings: dict[str, Any],
    observation: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    _expect(root.parent.parent == _WORK_ROOT, "route artifact root escaped main stack")
    directory = root / "artifacts"
    directory.mkdir(mode=0o700)
    metadata = directory.stat(follow_symlinks=False)
    _expect(
        stat.S_ISDIR(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and not directory.is_symlink(),
        "route artifact directory metadata changed",
    )
    probe_digest = _route_slice_probe_digest(observation)
    retained_observation = _retained_route_slice_observation(observation)
    document = _bound_route_artifact_document(
        nonce, bindings, retained_observation, probe_digest
    )
    source = _write_input(directory / "fresh-session-reset.json", document)
    descriptor = {
        "digest": source["digest"],
        "path": _ROUTE_SLICE_ARTIFACT,
        "schema": _BOUND_EVIDENCE_SCHEMA,
    }
    normalized = {
        "digest": source["digest"],
        "observation": retained_observation,
        "path": _ROUTE_SLICE_ARTIFACT,
        "probe_digest": probe_digest,
        "probe_module": _ROUTE_SLICE_PROBE,
        "schema": _BOUND_EVIDENCE_SCHEMA,
    }
    return descriptor, normalized


def _adm03_input(nonce: str, bindings: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifacts": [],
        "bindings": bindings,
        "mode": "adm03",
        "run_nonce": nonce,
        "scenarios": _rows(_ADM03_IDS),
        "schema": "aragorn/openclaw-final-admission-v2-adm03-input/v1",
    }


def _copy_runtime(label: str, nonce: str) -> tuple[Path, Path, dict[str, Any]]:
    stack = _WORK_ROOT / f"{label}-{nonce}"
    runtime = stack / "runtime"
    probes = stack / "probes"
    _expect(
        not stack.exists() and not stack.is_symlink(), f"{label} stack already exists"
    )
    runtime.mkdir(parents=True, mode=0o700)
    probes.mkdir(mode=0o700)
    command = [str(_CP), "-a", "--reflink=auto", f"{_SOURCE_RUNTIME}/.", str(runtime)]
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=300,
    )
    _expect(
        result.returncode == 0 and not result.stdout and not result.stderr,
        f"{label} runtime copy failed",
    )
    entrypoint = runtime / "lib/node_modules/openclaw/openclaw.mjs"
    _expect(
        entrypoint.is_file()
        and not entrypoint.is_symlink()
        and _file(entrypoint)["digest"] == _EXPECTED_RUNTIME["entrypoint_digest"],
        f"{label} mutable runtime entrypoint changed",
    )
    return (
        stack,
        probes,
        {
            "command": command,
            "source": str(_SOURCE_RUNTIME),
            "destination": str(runtime),
            "entrypoint_digest": _EXPECTED_RUNTIME["entrypoint_digest"],
        },
    )


def _suite_environment(nonce: str, runtime: Path, probes: Path) -> dict[str, str]:
    return {
        "ARAGORN_CONFIG_PATH": str(_CONFIG),
        "ARAGORN_PROBE_ROOT": str(probes),
        "ARAGORN_PROFILE_PATH": str(_PROFILE),
        "ARAGORN_RUNTIME_LOCK_PATH": str(_LOCK),
        "ARAGORN_RUNTIME_ROOT": str(runtime),
        "ARAGORN_RUN_NONCE": nonce,
        "ARAGORN_SKILL_PATH": str(_SKILL),
    }


def _run_suite(mode: str, nonce: str, runtime: Path, probes: Path) -> dict[str, Any]:
    environment = _suite_environment(nonce, runtime, probes)
    _expect(tuple(environment) == _REQUIRED_ENV, "suite environment order changed")
    command = [
        str(_ENV),
        "-i",
        *(f"{key}={value}" for key, value in environment.items()),
        str(_NODE),
        str(_SUITE),
        mode,
    ]
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=300,
    )
    _expect(len(result.stdout) <= 8 * 1024 * 1024, f"{mode} stdout exceeded 8 MiB")
    _expect(len(result.stderr) <= 64 * 1024, f"{mode} stderr exceeded 64 KiB")
    _expect(
        result.returncode == 0 and result.stderr == b"", f"{mode} suite failed closed"
    )
    return _json(result.stdout, f"{mode} suite output")


def _validate_rows(value: Any, expected: list[dict[str, Any]], label: str) -> None:
    _expect(value == expected, f"{label} rows changed or gained unbound evidence")


def _runtime_verification(value: Any, runtime: Path, label: str) -> None:
    document = _exact_keys(value, {"root", "tree"}, f"{label} runtime verification")
    _expect(
        document == {"root": str(runtime), "tree": _EXPECTED_RUNTIME_TREE},
        f"{label} runtime verification changed",
    )


def _main_output(
    document: dict[str, Any],
    source: dict[str, Any],
    nonce: str,
    bindings: dict[str, Any],
    runtime: Path,
    expected_evidence: list[dict[str, Any]],
) -> None:
    _exact_keys(
        document,
        {
            "assurance",
            "bindings",
            "decision",
            "evidence",
            "formal_categories",
            "input",
            "limitations",
            "mode",
            "properties",
            "routes",
            "run_nonce",
            "runtime_verification",
            "schema",
        },
        "main observation",
    )
    _expect(
        document["schema"] == "aragorn/openclaw-final-admission-v2-main-observation/v1"
        and document["assurance"]
        == "BOUND_RAW_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        and document["mode"] == "main"
        and document["run_nonce"] == nonce
        and document["bindings"] == bindings
        and document["evidence"] == expected_evidence
        and document["input"]
        == {
            "digest": source["digest"],
            "path": "main-input.json",
            "schema": source["schema"],
        },
        "main observation binding changed",
    )
    _validate_rows(document["properties"], source["properties"], "main properties")
    _validate_rows(
        document["formal_categories"],
        source["formal_categories"],
        "main formal categories",
    )
    _validate_rows(document["routes"], source["routes"], "main routes")
    _runtime_verification(document["runtime_verification"], runtime, "main")
    _decision(
        document["decision"],
        "NOT_TESTED",
        "main",
        {"FAIL": 0, "NOT_TESTED": 30, "OBSERVED": 1},
    )


def _adm03_output(
    document: dict[str, Any],
    source: dict[str, Any],
    nonce: str,
    bindings: dict[str, Any],
    runtime: Path,
) -> None:
    _exact_keys(
        document,
        {
            "assurance",
            "bindings",
            "decision",
            "evidence",
            "input",
            "limitations",
            "mode",
            "run_nonce",
            "runtime_verification",
            "scenarios",
            "schema",
        },
        "ADM-03 observation",
    )
    _expect(
        document["schema"] == "aragorn/openclaw-final-admission-v2-adm03-observation/v1"
        and document["assurance"]
        == "ISOLATED_BOUND_RAW_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        and document["mode"] == "adm03"
        and document["run_nonce"] == nonce
        and document["bindings"] == bindings
        and document["evidence"] == []
        and document["input"]
        == {
            "digest": source["digest"],
            "path": "adm03-input.json",
            "schema": source["schema"],
        },
        "ADM-03 observation binding changed",
    )
    _validate_rows(document["scenarios"], source["scenarios"], "ADM-03 scenarios")
    _runtime_verification(document["runtime_verification"], runtime, "ADM-03")
    _decision(
        document["decision"],
        "NOT_TESTED",
        "ADM-03",
        {"FAIL": 0, "NOT_TESTED": 2, "OBSERVED": 0},
    )


def _remove_stack(path: Path) -> None:
    _expect(path.parent == _WORK_ROOT, "refusing to remove an unexpected stack")
    shutil.rmtree(path)
    _expect(
        not path.exists() and not path.is_symlink(),
        "mutable stack remained after removal",
    )


def _decision_document(
    status: str, *, route_observed_count: int = 0
) -> dict[str, Any]:
    _expect(
        type(route_observed_count) is int and route_observed_count in {0, 1},
        "aggregate route observation count changed",
    )
    return {
        "status": status,
        "semantic_pass_verified": False,
        "property_not_tested_count": 2,
        "formal_category_not_tested_count": 8,
        "route_observed_count": route_observed_count,
        "route_fail_count": 0,
        "route_not_tested_count": 21 - route_observed_count,
        "adm03_not_tested_count": 2,
        **{key: False for key in sorted(_ELIGIBILITY_KEYS)},
    }


def _collect() -> dict[str, Any]:
    _set_stage("HARNESS")
    harness = _harness()
    _set_stage("SOURCE_BINDINGS")
    bindings, artifacts = _source_bindings()
    nonce = secrets.token_hex(32)
    _expect(
        re.fullmatch(r"[0-9a-f]{64}", nonce) is not None, "run nonce generation failed"
    )
    _expect(
        not _WORK_ROOT.exists() and not _WORK_ROOT.is_symlink(),
        "work root is not fresh",
    )

    main_stack: Path | None = None
    adm03_stack: Path | None = None
    main_removed_before_adm03 = False
    try:
        _set_stage("MAIN_STACK")
        main_stack, main_probes, main_copy = _copy_runtime("main", nonce)
        main_runtime = main_stack / "runtime"
        _set_stage("MANIFEST")
        manifest = _run_suite("manifest", nonce, main_runtime, main_probes)
        _manifest(manifest, nonce, bindings)
        _set_stage("AGGREGATE_ROUTE_SLICE")
        route_observation = _route_slice_observation()
        route_artifact, normalized_route_evidence = _write_route_slice_artifact(
            main_probes, nonce, bindings, route_observation
        )
        main_input = _main_input(nonce, bindings, route_artifact)
        main_input_file = _write_input(main_probes / "main-input.json", main_input)
        main_input["digest"] = main_input_file["digest"]
        _set_stage("MAIN_AGGREGATION")
        main = _run_suite("main", nonce, main_runtime, main_probes)
        _main_output(
            main,
            main_input,
            nonce,
            bindings,
            main_runtime,
            [normalized_route_evidence],
        )
        _remove_stack(main_stack)
        main_stack = None
        main_removed_before_adm03 = True

        _set_stage("ADM03_STACK")
        adm03_stack, adm03_probes, adm03_copy = _copy_runtime("adm03", nonce)
        adm03_runtime = adm03_stack / "runtime"
        adm03_input = _adm03_input(nonce, bindings)
        adm03_input_file = _write_input(adm03_probes / "adm03-input.json", adm03_input)
        adm03_input["digest"] = adm03_input_file["digest"]
        _set_stage("ADM03_AGGREGATION")
        adm03 = _run_suite("adm03", nonce, adm03_runtime, adm03_probes)
        _adm03_output(adm03, adm03_input, nonce, bindings, adm03_runtime)
        _remove_stack(adm03_stack)
        adm03_stack = None
        _expect(
            main_removed_before_adm03, "ADM-03 was not isolated from the main stack"
        )
        _expect(
            not any(_WORK_ROOT.iterdir()), "work root is not empty after stack removal"
        )
        _WORK_ROOT.rmdir()
    finally:
        for stack in (main_stack, adm03_stack):
            if stack is not None and stack.exists():
                _remove_stack(stack)
        if _WORK_ROOT.exists() and not any(_WORK_ROOT.iterdir()):
            _WORK_ROOT.rmdir()

    _set_stage("ASSEMBLY")
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "run_nonce": nonce,
        "harness": harness,
        "source_artifacts": artifacts,
        "bindings": bindings,
        "manifest": manifest,
        "main": main,
        "adm03": adm03,
        "execution": {
            "sequence": [
                "manifest",
                "execute-fresh-session-reset-route-probe",
                "main",
                "destroy-main-stack",
                "create-isolated-adm03-stack",
                "adm03",
                "destroy-adm03-stack",
            ],
            "main_runtime_copy": main_copy,
            "adm03_runtime_copy": adm03_copy,
            "route_slice": {
                "artifact": route_artifact,
                "route_id": _ROUTE_SLICE_ID,
                "status": "OBSERVED",
            },
            "main_removed_before_adm03": main_removed_before_adm03,
            "mutable_stacks_removed": True,
            "network": "none",
            "suite_process_environment": "env-i-seven-exact-ARAGORN-variables",
        },
        "decision": _decision_document("NOT_TESTED", route_observed_count=1),
        "limitations": _LIMITATIONS,
    }


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "decision": _decision_document("FAIL_CLOSED"),
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
        print("usage: openclaw_final_admission_v2_systemd_probe.py", file=sys.stderr)
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
