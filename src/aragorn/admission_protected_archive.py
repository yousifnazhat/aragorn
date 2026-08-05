"""Exact-profile qualification for one protected OpenClaw archive route."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import admission_runtime_profile as shared
from .admission_evidence import AdmissionEvidenceError, _read_exact, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_PROFILE = "openclaw-2026.7.1-protected-consumer"
_ROUTE = "ADM-02/update/archive-source-force-replacement"
_EVIDENCE_SCHEMA = (
    "aragorn/openclaw-protected-archive-replacement-observation/v1"
)
_EVIDENCE_DIGEST = (
    "sha256:6f8e33c781fdf83434c47913bb92e898bf4e10f4490055a67ecb115b1fa8b373"
)
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:11a3b4759d891b4db3f6c36be7e46d2f87622b5d2343217e7e89d72c5fd0674b"
)
_PROBE_DIGEST = (
    "sha256:90bf211226365ede1cf781fa3faa45217b1ed72fd636cc48824c4b39e5ac7c22"
)
_CONFIG_DIGEST = (
    "sha256:ec2b2022ed27f62840583d31264826c88514a04e7e7cc94d78820b021d6288b6"
)
_CONFIG_CANONICAL_DIGEST = (
    "sha256:6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a"
)
_PROFILE_DIGEST = (
    "sha256:be2f1cec6f70fbc18be19e04556c2b52331cec61405950512e3fcd48ff26c906"
)
_TARGET_DIGEST = (
    "sha256:1a13f195721f8fa75974bd4918a25b30e8406ff6d423cd0e3306c391b8fee07a"
)
_SOURCE_DIGEST = (
    "sha256:d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1"
)
_TARGET_TREE_DIGEST = (
    "sha256:c3e201e18e2fa35a56d4cae3a0ed481072f4ed77db18e6d568b266068cbe96c3"
)
_SOURCE_TREE_DIGEST = (
    "sha256:10997bc6dcb3cc92e0cbe93578339f7fdcf46afde725722a4cc1d7dccfcf7dcf"
)
_RUNTIME_TREE = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 45_856,
    "file_count": 45_837,
    "symlink_count": 19,
    "total_bytes": 369_317_461,
    "tree_digest": (
        "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c"
    ),
}
_SHARED_IMPLEMENTATION_DIGEST = (
    "sha256:adf90754909150fba60b99b1b890e0815c2b5d081ea32dd5b5a698b1f0dfb50b"
)
_OPENCLAW_DIGEST = (
    "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
)
_TARGET = "/profile/workspace/skills/requesting-code-review"
_SOURCE = "/sources/replacement"
_TARGET_BYTES = (
    b"---\n"
    b"name: requesting-code-review\n"
    b"description: Inert protected archive replacement target v1.\n"
    b"---\n\n"
    b"This fixture performs no actions.\n"
)
_SOURCE_BYTES = (
    b"---\n"
    b"name: requesting-code-review\n"
    b"description: Inert protected archive replacement source v2.\n"
    b"---\n\n"
    b"This replacement fixture performs no actions.\n"
)
_LIMITATIONS = [
    "EXACT_PINNED_PROFILE_AND_SINGLE_CAPTURE_ONLY",
    "ARCHIVE_UPLOAD_DISABLED_AND_DIRECTORY_FORCE_DENIED",
    "ARCHIVE_BYTES_NOT_INGESTED_BECAUSE_UPLOADS_ARE_DISABLED",
    "NATIVE_ROUTE_DENIAL_NOT_BROKER_MEDIATED",
    "DOCKER_CONTROL_PLANE_NOT_INDEPENDENTLY_ATTESTED",
    "OTHER_ADMISSION_ROUTES_NOT_QUALIFIED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "PHASE3_RUN_AND_EDR_AUTHORITY_NOT_ESTABLISHED",
]
_ROOT_MOUNTS = {
    "extensions": (
        "/profile/state/extensions",
        "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
        [],
    ),
    "managed_skills": (
        "/profile/state/skills",
        "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
        [],
    ),
    "personal_agents": (
        "/profile/home/.agents/skills",
        "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
        [],
    ),
    "plugin_skills": (
        "/profile/state/plugin-skills",
        "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
        [],
    ),
    "project_agents": (
        "/profile/workspace/.agents/skills",
        "/docker/volumes/aragorn-openclaw-p3-archive-guard-v1/_data",
        [],
    ),
    "workspace_skills": (
        "/profile/workspace/skills",
        "/docker/volumes/aragorn-openclaw-p3-archive-target-v1/_data",
        ["requesting-code-review"],
    ),
}
_EXPECTED_DISCOVERY = {
    "always": False,
    "baseDir": _TARGET,
    "blockedByAgentFilter": False,
    "blockedByAllowlist": False,
    "bundled": False,
    "commandVisible": True,
    "configChecks": [],
    "description": "Inert protected archive replacement target v1.",
    "disabled": False,
    "eligible": True,
    "filePath": f"{_TARGET}/SKILL.md",
    "install": [],
    "missing": {"anyBins": [], "bins": [], "config": [], "env": [], "os": []},
    "modelVisible": True,
    "name": "requesting-code-review",
    "platformIncompatible": False,
    "requirements": {
        "anyBins": [],
        "bins": [],
        "config": [],
        "env": [],
        "os": [],
    },
    "skillKey": "requesting-code-review",
    "source": "openclaw-workspace",
    "userInvocable": True,
}


def verify_openclaw_protected_archive_replacement(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Qualify one exact existing-target denial without aggregate authority."""

    try:
        shared_digest = "sha256:" + hashlib.sha256(
            Path(shared.__file__).read_bytes()
        ).hexdigest()
        if shared_digest != _SHARED_IMPLEMENTATION_DIGEST:
            raise AdmissionEvidenceError("shared route verifier changed")
        shared.validate_openclaw_protected_consumer_profile(
            route_profile,
            route_inventory=route_inventory,
            runtime_candidates=runtime_candidates,
        )
        if canonical_digest(source_receipt) != _RECEIPT_CANONICAL_DIGEST:
            raise AdmissionEvidenceError("archive retention receipt changed")

        evidence = _read_exact(
            evidence_cas,
            _EVIDENCE_DIGEST,
            _EVIDENCE_SCHEMA,
        )
        profile_raw = canonical_json(dict(route_profile)) + b"\n"
        if (
            "sha256:" + hashlib.sha256(profile_raw).hexdigest()
            != _PROFILE_DIGEST
        ):
            raise AdmissionEvidenceError("protected-consumer profile changed")
        _read_source_bytes(
            evidence_cas,
            _PROFILE_DIGEST,
            profile_raw,
            "protected-consumer profile",
        )
        probe_raw = _read_source_bytes(
            evidence_cas,
            _PROBE_DIGEST,
            None,
            "archive replacement probe",
        )
        config_raw = _read_source_bytes(
            evidence_cas,
            _CONFIG_DIGEST,
            None,
            "protected configuration",
        )
        target_raw = _read_source_bytes(
            evidence_cas,
            _TARGET_DIGEST,
            _TARGET_BYTES,
            "existing target fixture",
        )
        source_raw = _read_source_bytes(
            evidence_cas,
            _SOURCE_DIGEST,
            _SOURCE_BYTES,
            "replacement source fixture",
        )
        _verify_source_closure(
            source_receipt,
            evidence,
            probe_raw=probe_raw,
            config_raw=config_raw,
            target_raw=target_raw,
            source_raw=source_raw,
        )
        _verify_boundary(evidence["protected_boundary"])
        _verify_action(evidence, source_receipt)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid protected archive replacement evidence: {exc}"
        ) from exc

    return {
        "assurance": (
            "SEMANTICALLY_VERIFIED_EXACT_PROFILE_EXISTING_TARGET_DENIAL"
        ),
        "bindings": {
            "configuration_digest": _CONFIG_DIGEST,
            "existing_target_digest": _TARGET_DIGEST,
            "profile_digest": _PROFILE_DIGEST,
            "replacement_source_digest": _SOURCE_DIGEST,
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "shared_verifier_implementation_digest": shared_digest,
            "source_evidence_digest": _EVIDENCE_DIGEST,
            "source_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "verifier_implementation_digest": (
                "sha256:"
                + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            ),
        },
        "decision": {
            "admission_profile_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "status": "ROUTE_PASS",
        },
        "limitations": list(_LIMITATIONS),
        "profile": _PROFILE,
        "route": {
            "id": _ROUTE,
            "observed_outcome": "DENIED_PRE_EFFECT_EXISTING_TARGET_PRESERVED",
            "status": "PASS",
        },
        "runtime": dict(route_profile["runtime"]),
        "schema": "aragorn/admission-protected-archive-route-qualification/v1",
        "source_recorded_at": evidence["recorded_at"],
    }


def _read_source_bytes(
    cas: CAS,
    digest: str,
    expected: bytes | None,
    label: str,
) -> bytes:
    max_bytes = len(expected) if expected is not None else 256 * 1024
    try:
        raw = cas.read(digest, max_bytes=max_bytes)
    except CASError as exc:
        raise AdmissionEvidenceError(f"{label} is not retained") from exc
    if expected is not None and raw != expected:
        raise AdmissionEvidenceError(f"{label} bytes changed")
    return raw


def _verify_source_closure(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    probe_raw: bytes,
    config_raw: bytes,
    target_raw: bytes,
    source_raw: bytes,
) -> None:
    inputs = receipt["inputs"]
    if (
        receipt["schema"]
        != "aragorn/phase3-openclaw-protected-archive-replacement-retention/v1"
        or receipt["assurance"]
        != "OPERATOR_RETAINED_RAW_OBSERVATION_NOT_CONFORMANCE_AUTHORITY"
        or receipt["status"] != "RAW_OBSERVATION_ONLY"
        or receipt["admission_profile_eligible"] is not False
        or receipt["installer_work_eligible"] is not False
        or receipt["phase3_exit_eligible"] is not False
        or receipt["results"]
        != {"fail": [], "not_tested": [], "observed": [_ROUTE], "pass": []}
        or receipt["evidence"]["digest"] != _EVIDENCE_DIGEST
        or receipt["evidence"]["bytes"] != 35_963
        or receipt["evidence"]["recorded_at"] != evidence["recorded_at"]
        or receipt["evidence"]["run_nonce"] != evidence["run_nonce"]
        or inputs["probe"]["digest"] != _PROBE_DIGEST
        or inputs["probe"]["bytes"] != len(probe_raw)
        or inputs["configuration"]["digest"] != _CONFIG_DIGEST
        or inputs["configuration"]["bytes"] != len(config_raw)
        or inputs["configuration"]["canonical_digest"]
        != _CONFIG_CANONICAL_DIGEST
        or inputs["existing_target"]["digest"] != _TARGET_DIGEST
        or inputs["existing_target"]["bytes"] != len(target_raw)
        or inputs["replacement_source"]["digest"] != _SOURCE_DIGEST
        or inputs["replacement_source"]["bytes"] != len(source_raw)
        or receipt["runtime"]["runtime_tree"] != _RUNTIME_TREE
    ):
        raise AdmissionEvidenceError("archive source closure changed")

    config = shared.load_runtime_profile(config_raw)
    if (
        canonical_json(config) + b"\n" != config_raw
        or canonical_digest(config) != _CONFIG_CANONICAL_DIGEST
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["implementation_digest"] != _PROBE_DIGEST
        or evidence["runtime_binding"]
        != {
            "commit": "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": _OPENCLAW_DIGEST,
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
    ):
        raise AdmissionEvidenceError("archive source identity changed")


def _verify_boundary(boundary: Mapping[str, Any]) -> None:
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"]
        != {"gid": 1000, "groups": [982, 1000], "uid": 1000}
        or set(boundary["roots"]) != set(_ROOT_MOUNTS)
        or set(boundary["inputs"]) != {"probe", "source"}
    ):
        raise AdmissionEvidenceError("archive protected boundary changed")

    for name, (target, source, entries) in _ROOT_MOUNTS.items():
        _verify_ro_mount(
            boundary["roots"][name],
            target=target,
            source=source,
            uid=0,
            gid=982,
            mode="750",
            entries=entries,
        )
    _verify_ro_mount(
        boundary["inputs"]["probe"],
        target="/probe",
        source="/docker/volumes/aragorn-openclaw-p3-archive-probe-v2/_data",
        uid=0,
        gid=982,
        mode="750",
        entries=["probe.mjs"],
    )
    _verify_ro_mount(
        boundary["inputs"]["source"],
        target="/sources",
        source="/docker/volumes/aragorn-openclaw-p3-archive-source-v1/_data",
        uid=0,
        gid=982,
        mode="750",
        entries=["replacement"],
    )
    _verify_ro_mount(
        boundary["configuration"]["mount"],
        target="/profile/config",
        source="/docker/volumes/aragorn-openclaw-p3-archive-config-v1/_data",
        uid=0,
        gid=982,
        mode="750",
        entries=["openclaw.json"],
    )
    _verify_ro_mount(
        boundary["runtime"],
        target="/runtime",
        source="/docker/volumes/aragorn-openclaw-2026-7-1-runtime/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=["bin", "lib"],
    )
    config = boundary["configuration"]
    if (
        config["ready"] is not True
        or config["canonical_digest"] != _CONFIG_CANONICAL_DIGEST
        or config["file"]["path"] != "/profile/config/openclaw.json"
        or config["file"]["type"] != "file"
        or config["file"]["uid"] != 0
        or config["file"]["gid"] != 982
        or config["file"]["mode"] != "440"
        or config["file"]["nlink"] != 1
        or config["file"]["size"] != 316
        or config["file"]["digest"] != _CONFIG_DIGEST
        or config["file"]["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("archive protected configuration changed")


def _verify_ro_mount(
    mount: Mapping[str, Any],
    *,
    target: str,
    source: str,
    uid: int,
    gid: int,
    mode: str,
    entries: list[str],
) -> None:
    records = mount["records"]
    entry = mount["entry"]
    if (
        mount["path"] != target
        or mount["explicit"] is not True
        or mount["read_only"] is not True
        or mount["ready"] is not True
        or mount["error"] is not None
        or len(records) != 1
        or records[0]["mount_point"] != target
        or records[0]["root"] != source
        or records[0]["filesystem"] != "ext4"
        or records[0]["source"] != "/dev/vdb1"
        or "ro" not in records[0]["mount_options"]
        or "rw" in records[0]["mount_options"]
        or entry["path"] != target
        or entry["exists"] is not True
        or entry["type"] != "directory"
        or entry["uid"] != uid
        or entry["gid"] != gid
        or entry["mode"] != mode
        or entry["entries"] != entries
        or entry["entry_count"] != len(entries)
        or entry["entries_truncated"] is not False
    ):
        raise AdmissionEvidenceError(f"archive read-only mount changed: {target}")


def _verify_fixture_tree(
    tree: Mapping[str, Any],
    *,
    root_path: str,
    digest: str,
    size: int,
    tree_digest: str,
) -> None:
    root = tree["root"]
    if (
        tree["ready"] is not True
        or tree["tree_digest"] != tree_digest
        or len(tree["entries"]) != 1
        or root["path"] != root_path
        or root["exists"] is not True
        or root["type"] != "directory"
        or root["uid"] != 0
        or root["gid"] != 982
        or root["mode"] != "750"
        or root["entries"] != ["SKILL.md"]
        or root["entry_count"] != 1
        or root["entries_truncated"] is not False
    ):
        raise AdmissionEvidenceError(f"archive fixture root changed: {root_path}")
    skill = tree["entries"][0]
    if (
        skill["path"] != "SKILL.md"
        or skill["exists"] is not True
        or skill["type"] != "file"
        or skill["uid"] != 0
        or skill["gid"] != 982
        or skill["mode"] != "440"
        or skill["nlink"] != 1
        or skill["size"] != size
        or skill["digest"] != digest
        or skill["digest_error"] is not None
    ):
        raise AdmissionEvidenceError(f"archive fixture file changed: {root_path}")


def _verify_action(
    evidence: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> None:
    if evidence["route"] != {
        "action_id": "archive-source-force-replacement",
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }:
        raise AdmissionEvidenceError("archive route selection changed")
    action = evidence["action"]
    prerequisites = action["prerequisites"]
    observations = action["observations"]
    if (
        action["id"] != "archive-source-force-replacement"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or prerequisites["ready"] is not True
        or prerequisites["reason_codes"] != []
        or prerequisites["runtime_tree"] != _RUNTIME_TREE
        or observations["runtime_tree_after"] != _RUNTIME_TREE
        or observations["boundary_after"] != evidence["protected_boundary"]
    ):
        raise AdmissionEvidenceError("archive action prerequisites changed")

    _verify_fixture_tree(
        prerequisites["source"],
        root_path=_SOURCE,
        digest=_SOURCE_DIGEST,
        size=len(_SOURCE_BYTES),
        tree_digest=_SOURCE_TREE_DIGEST,
    )
    _verify_fixture_tree(
        prerequisites["target_before"],
        root_path=_TARGET,
        digest=_TARGET_DIGEST,
        size=len(_TARGET_BYTES),
        tree_digest=_TARGET_TREE_DIGEST,
    )
    if (
        observations["source_after"] != prerequisites["source"]
        or observations["target_after"] != prerequisites["target_before"]
        or observations["staging_before"] != []
        or observations["staging_after"] != []
    ):
        raise AdmissionEvidenceError("archive source or protected target changed")

    gateway = prerequisites["gateway_process"]
    if (
        observations["gateway_after"] != gateway
        or gateway["cmdline"] != ["openclaw-gateway"]
        or gateway["hostname"] != receipt["containment"]["container_id"][:12]
        or gateway["pid"] != receipt["containment"]["gateway_pid"] == 1
        or gateway["start_time_ticks"]
        != receipt["containment"]["gateway_start_time_ticks"]
    ):
        raise AdmissionEvidenceError("archive gateway identity changed")
    openclaw = prerequisites["openclaw"]
    if (
        openclaw["path"] != "/runtime/lib/node_modules/openclaw/openclaw.mjs"
        or openclaw["exists"] is not True
        or openclaw["type"] != "file"
        or openclaw["uid"] != 0
        or openclaw["mode"] != "755"
        or openclaw["digest"] != _OPENCLAW_DIGEST
        or openclaw["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("archive OpenClaw launcher changed")

    positive = prerequisites["positive_control"]
    install_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "skills",
        "install",
        _SOURCE,
        "--as",
        "requesting-code-review",
        "--force",
        "--agent",
        "main",
    ]
    if (
        positive["ready"] is not True
        or positive["configuration_digest"]
        != "sha256:22845270bfefeed5724a079549b606f11e192c6818f7ab8e37acf30ba0f14e3d"
        or positive["target_before"]
        != {
            "exists": False,
            "path": "/profile/control/workspace/skills/requesting-code-review",
        }
        or positive["install"]["argv"] != install_argv
        or not shared._command_succeeded_clean(positive["install"])
        or not shared._command_output_is_exact(positive["install"])
        or positive["install"]["stdout_excerpt"]
        != (
            "Installing to /profile/control/workspace/skills/"
            "requesting-code-review…\n"
            "Installed requesting-code-review from path -> /profile/control/"
            "workspace/skills/requesting-code-review\n"
        )
        or not any(
            entry.get("path") == "SKILL.md"
            and entry.get("digest") == _SOURCE_DIGEST
            and entry.get("size") == len(_SOURCE_BYTES)
            for entry in positive["target_after"]["entries"]
        )
    ):
        raise AdmissionEvidenceError("archive replacement positive control changed")

    before = prerequisites["discovery"]
    after = observations["discovery_after"]
    _verify_discovery(before)
    _verify_discovery(after)
    if (
        before["response"] != after["response"]
        or before["command"]["stdout_digest"]
        != after["command"]["stdout_digest"]
    ):
        raise AdmissionEvidenceError("archive discovery state changed")

    upload_error = {
        "code": "UNAVAILABLE",
        "message": (
            "Uploaded skill archive installs are disabled by "
            "skills.install.allowUploadedArchives"
        ),
        "retryable": False,
        "type": "gateway_request_error",
    }
    upload_begin = observations["upload_begin"]
    upload_install = observations["upload_install"]
    for label, result in (
        ("begin", upload_begin),
        ("install", upload_install),
    ):
        command = result["command"]
        if (
            result["response"]
            != {"parsed": True, "value": {"error": upload_error, "ok": False}}
            or command["exit_code"] != 1
            or command["error"] is not None
            or command["signal"] is not None
            or not shared._command_output_is_exact(command)
            or json.loads(command["stdout_excerpt"])
            != result["response"]["value"]
        ):
            raise AdmissionEvidenceError(f"archive upload {label} denial changed")

    source_install = observations["source_install"]
    protected = source_install["command"]
    if (
        protected["argv"] != install_argv
        or protected["exit_code"] != 1
        or protected["error"] is not None
        or protected["signal"] is not None
        or source_install["response"] != {"parsed": False, "value": None}
        or protected["stdout_excerpt"]
        != "Installing to /profile/workspace/skills/requesting-code-review…\n"
        or re.fullmatch(
            r"failed to install skill: Error: EROFS: read-only file system, "
            r"mkdtemp '/profile/workspace/skills/\.openclaw-install-stage-"
            r"[A-Za-z0-9]{6}'\n",
            protected["stderr_excerpt"],
        )
        is None
        or not _command_bytes_match(protected)
    ):
        raise AdmissionEvidenceError("archive protected force denial changed")

    version = prerequisites["version"]
    system = prerequisites["system_info"]
    system_value = system["response"]["value"]
    if (
        version["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "--version",
        ]
        or not shared._command_succeeded_clean(version)
        or not shared._command_output_is_exact(version)
        or version["stdout_excerpt"] != "OpenClaw 2026.7.1 (2d2ddc4)\n"
        or system["response"]["parsed"] is not True
        or system_value["pid"] != gateway["pid"]
        or system_value["hostname"] != gateway["hostname"]
        or system_value["platform"] != "linux"
        or system_value["arch"] != "arm64"
        or system_value["nodeVersion"] != "v24.16.0"
        or system_value["port"] != 18789
        or not shared._command_succeeded_clean(system["command"])
        or not shared._command_output_is_exact(system["command"])
    ):
        raise AdmissionEvidenceError("archive runtime preflight changed")

    status_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "skills",
        "info",
        "requesting-code-review",
        "--agent",
        "main",
        "--json",
    ]
    begin_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "skills.upload.begin",
        "--json",
        "--timeout",
        "5000",
        "--params",
        "{}",
    ]
    install_upload_argv = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        "skills.install",
        "--json",
        "--timeout",
        "5000",
        "--params",
        (
            '{"agentId":"main","force":true,"sha256":"'
            + "a" * 64
            + '","slug":"requesting-code-review","source":"upload",'
            '"uploadId":"'
            + "a" * 32
            + '"}'
        ),
    ]
    commands = action["commands"]
    expected_commands = [
        version,
        system["command"],
        positive["install"],
        before["command"],
        upload_begin["command"],
        upload_install["command"],
        protected,
        after["command"],
    ]
    if (
        commands != expected_commands
        or before["command"]["argv"] != status_argv
        or after["command"]["argv"] != status_argv
        or upload_begin["command"]["argv"] != begin_argv
        or upload_install["command"]["argv"] != install_upload_argv
        or any(
            _time(current["completed_at"]) > _time(next_["started_at"])
            for current, next_ in zip(commands, commands[1:])
        )
        or _time(commands[-1]["completed_at"]) > _time(evidence["recorded_at"])
    ):
        raise AdmissionEvidenceError("archive command causality changed")


def _verify_discovery(discovery: Mapping[str, Any]) -> None:
    command = discovery["command"]
    if (
        discovery["response"] != {"parsed": True, "value": _EXPECTED_DISCOVERY}
        or not shared._command_succeeded_clean(command)
        or not shared._command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != _EXPECTED_DISCOVERY
    ):
        raise AdmissionEvidenceError("archive exact discovery changed")


def _command_bytes_match(command: Mapping[str, Any]) -> bool:
    stdout = command["stdout_excerpt"].encode()
    stderr = command["stderr_excerpt"].encode()
    return (
        command["stdout_bytes"] == len(stdout)
        and command["stdout_digest"]
        == "sha256:" + hashlib.sha256(stdout).hexdigest()
        and command["stderr_bytes"] == len(stderr)
        and command["stderr_digest"]
        == "sha256:" + hashlib.sha256(stderr).hexdigest()
    )
