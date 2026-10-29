"""Compose the exact restore-authority archive route qualification."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_archive as archive
from . import admission_protected_curator_restore as curator
from . import admission_protected_restore_authority_config as config
from . import admission_routes
from . import admission_runtime_profile as runtime_profile
from .admission_evidence import AdmissionEvidenceError, _time
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/update/archive-source-force-replacement"
_PASS_ROUTES = {_ROUTE, config._CONFIG_ROUTE, curator._ROUTE}
_EVIDENCE = {
    "bytes": 36_134,
    "canonical_bytes": 36_145,
    "canonical_digest": (
        "sha256:aa0b7fbc30fbe0c53a810e798131dc846b9e51465f837395f4d63d4a5e7fb71b"
    ),
    "digest": (
        "sha256:bef6a0b5f06db8eccf9f33c39509e4af8a5d6e35ee88364b28aa2baf07268a36"
    ),
    "path": "benchmark/evidence/openclaw-v2026.7.1-protected-restore-authority-archive-replacement-2026-08-13.json",
    "schema": "aragorn/openclaw-protected-archive-replacement-observation/v1",
}
_RECEIPT_CANONICAL_DIGEST = (
    "sha256:44bc58a722f2e6cfb15bff46cd1ba6e17a4806ed2810b0a663a53bf97afbbbd2"
)
_CONFIG_QUALIFICATION_DIGEST = (
    "sha256:b063d0fbf137d928a924241699ba53903c6fccd1a31ec808895acdc2e57905ea"
)
_CONFIG_IMPLEMENTATION_DIGEST = (
    "sha256:46fa508bda1c9f9356718643fdde4a9427295fc4ca60855a758c711bf27b353f"
)
_RUNTIME_CANDIDATES_DIGEST = (
    "sha256:948dbed03bef5e48a63b11867132c216e06dcc932d07b7701fa11dd4e6e99ab3"
)
_ARCHIVE_HELPER_DIGEST = (
    "sha256:638a06723ea7f500f159f6e784034c755b08e921a3a25ba6ec3e3bf7ce38527f"
)
_SOURCES = {
    "profile": (curator._SOURCES["profile"][0], 3_932),
    "runtime_lock": (curator._SOURCES["runtime_lock"][0], 4_596),
    "configuration": (curator._SOURCES["configuration"][0], 359),
    "probe": (
        "sha256:4b152c299a53f9b23254d73101a8785b823011f78bfd34ba0d3cd98aa83d9c7f",
        22_549,
    ),
    "target": (archive._TARGET_DIGEST, len(archive._TARGET_BYTES)),
    "replacement": (archive._SOURCE_DIGEST, len(archive._SOURCE_BYTES)),
}
_MATERIALIZER = (
    "sha256:591627cde2cc412c785a490d2ad0cb48059dd40b7ec94617ac81de0d9eba34bf",
    17_971,
)
_TARGET = "/profile/workspace/skills/requesting-code-review"
_SOURCE = "/sources/replacement"
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_VERSION_STDOUT = "OpenClaw 2026.7.1 (805a4b1)\n"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_LIMITATIONS = [
    "THREE_EXACT_PRIVATE_PATCHED_RUNTIME_ROUTE_PASSES_ONLY",
    "SEPARATE_CAPTURE_COMPOSITION_ONLY",
    "ARCHIVE_UPLOAD_DISABLED_AND_ARCHIVE_BYTES_NOT_INGESTED",
    "PRIVATE_PATCHED_RUNTIME_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "SOURCE_TO_BINARY_REPRODUCIBILITY_NOT_INDEPENDENTLY_ATTESTED",
    "EIGHTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_ADMISSION_OR_INSTALLER_AUTHORITY",
    "RUN_01_RUN_02_PHASE3_EDR_AND_RELEASE_NOT_ESTABLISHED",
]


def verify_openclaw_protected_restore_authority_archive_replacement(
    source_receipt: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    route_profile: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    route_inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    config_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Add only the exact archive replacement PASS to frozen 2-route coverage."""

    try:
        receipt = _snapshot(source_receipt)
        profile = _snapshot(route_profile)
        lock = _snapshot(runtime_lock)
        inventory = _snapshot(route_inventory)
        candidates = _snapshot(runtime_candidates)
        parent = _snapshot(config_qualification)
        if canonical_digest(candidates) != _RUNTIME_CANDIDATES_DIGEST:
            raise AdmissionEvidenceError("runtime candidates changed")
        admission_routes.validate_openclaw_2026_7_1_route_inventory(
            inventory, candidates
        )
        if (
            _digest(Path(archive.__file__).read_bytes()) != _ARCHIVE_HELPER_DIGEST
            or _digest(Path(config.__file__).read_bytes())
            != _CONFIG_IMPLEMENTATION_DIGEST
        ):
            raise AdmissionEvidenceError("archive or parent verifier changed")
        curator._verify_profile(profile, lock, inventory)
        sources = _read_sources(evidence_cas, profile, lock)
        evidence = _read_evidence(evidence_cas)
        _verify_parent(parent, profile)
        _verify_receipt(receipt, evidence, profile, lock, sources)
        _verify_evidence(evidence, receipt, profile, lock, sources["configuration"])
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid restore-authority archive evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] in _PASS_ROUTES else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    return {
        "assurance": "SEMANTICALLY_VERIFIED_PRIVATE_RESTORE_AUTHORITY_THREE_ROUTE_COVERAGE_ONLY",
        "bindings": {
            "archive_evidence_canonical_digest": _EVIDENCE["canonical_digest"],
            "archive_evidence_digest": _EVIDENCE["digest"],
            "archive_receipt_canonical_digest": _RECEIPT_CANONICAL_DIGEST,
            "config_qualification_canonical_digest": _CONFIG_QUALIFICATION_DIGEST,
            "configuration_digest": _SOURCES["configuration"][0],
            "materialized_probe_digest": _SOURCES["probe"][0],
            "materializer_digest": _MATERIALIZER[0],
            "profile_digest": _SOURCES["profile"][0],
            "replacement_source_digest": _SOURCES["replacement"][0],
            "runtime_lock_digest": _SOURCES["runtime_lock"][0],
            "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"][
                "tree_digest"
            ],
            "target_digest": _SOURCES["target"][0],
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "admission_profile_eligible": False,
            "aggregate_admission_eligible": False,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "run_eligible": False,
            "status": "PARTIAL_ROUTE_COVERAGE",
        },
        "limitations": list(_LIMITATIONS),
        "profile": {
            "counts": {"fail": 0, "not_tested": 18, "pass": 3},
            "name": profile["name"],
            "routes": routes,
        },
        "runtime": dict(profile["runtime"]),
        "schema": "aragorn/admission-protected-restore-authority-archive-route-coverage/v1",
        "source_recorded_at": max(
            parent["source_recorded_at"], evidence["recorded_at"]
        ),
    }


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(canonical_json(value))


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read_blob(cas: CAS, digest: str, size: int, label: str) -> bytes:
    raw = cas.read(digest, max_bytes=size)
    if len(raw) != size or _digest(raw) != digest:
        raise AdmissionEvidenceError(f"{label} identity changed")
    return raw


def _read_sources(
    cas: CAS, profile: Mapping[str, Any], lock: Mapping[str, Any]
) -> dict[str, bytes]:
    values = {
        name: _read_blob(cas, digest, size, name)
        for name, (digest, size) in _SOURCES.items()
    }
    if (
        values["profile"] != canonical_json(profile) + b"\n"
        or values["runtime_lock"] != canonical_json(lock) + b"\n"
        or values["target"] != archive._TARGET_BYTES
        or values["replacement"] != archive._SOURCE_BYTES
    ):
        raise AdmissionEvidenceError("archive retained source bytes changed")
    configuration = runtime_profile.load_runtime_profile(values["configuration"])
    if (
        canonical_json(configuration) + b"\n" != values["configuration"]
        or canonical_digest(configuration) != curator._CONFIG_CANONICAL_DIGEST
        or configuration["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError("archive restore-authority config changed")
    return values


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AdmissionEvidenceError(f"duplicate archive capture key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AdmissionEvidenceError(f"invalid archive capture constant: {value}")


def _read_evidence(cas: CAS) -> dict[str, Any]:
    raw = _read_blob(cas, _EVIDENCE["digest"], _EVIDENCE["bytes"], "evidence")
    try:
        document = json.loads(
            raw.decode(),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(f"invalid archive capture JSON: {exc}") from exc
    canonical = canonical_json(document)
    if (
        not isinstance(document, dict)
        or canonical_digest(document) != _EVIDENCE["canonical_digest"]
        or len(canonical) != _EVIDENCE["canonical_bytes"]
        or canonical + b"\n" == raw
    ):
        raise AdmissionEvidenceError("archive capture parsed identity changed")
    return document


def _verify_parent(parent: Mapping[str, Any], profile: Mapping[str, Any]) -> None:
    expected_routes = [
        {
            "id": item["id"],
            "status": "PASS" if item["id"] in config._PASS_ROUTES else "NOT_TESTED",
        }
        for item in profile["routes"]
    ]
    if (
        canonical_digest(parent) != _CONFIG_QUALIFICATION_DIGEST
        or parent["schema"]
        != "aragorn/admission-protected-restore-authority-config-route-coverage/v1"
        or parent["runtime"] != profile["runtime"]
        or parent["profile"]
        != {
            "counts": {"fail": 0, "not_tested": 19, "pass": 2},
            "name": profile["name"],
            "routes": expected_routes,
        }
        or parent["bindings"]["verifier_implementation_digest"]
        != _CONFIG_IMPLEMENTATION_DIGEST
        or any(
            value is not False
            for key, value in parent["decision"].items()
            if key != "status"
        )
    ):
        raise AdmissionEvidenceError("config parent qualification changed")


def _verify_receipt(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    sources: Mapping[str, bytes],
) -> None:
    false_fields = (
        "admission_profile_eligible",
        "aggregate_admission_eligible",
        "edr_eligible",
        "installer_work_eligible",
        "phase3_exit_eligible",
        "release_eligible",
        "run_01_eligible",
        "run_02_eligible",
        "run_eligible",
    )
    not_tested = [item["id"] for item in profile["routes"] if item["id"] != _ROUTE]
    expected_evidence = {
        "bytes": _EVIDENCE["bytes"],
        "canonical_bytes": _EVIDENCE["canonical_bytes"],
        "canonical_digest": _EVIDENCE["canonical_digest"],
        "canonical_lf": False,
        "path": _EVIDENCE["path"],
        "raw_sha256": _EVIDENCE["digest"].removeprefix("sha256:"),
        "recorded_at": evidence["recorded_at"],
        "run_nonce": evidence["run_nonce"],
        "schema": _EVIDENCE["schema"],
    }
    inputs = receipt["inputs"]
    if (
        canonical_digest(receipt) != _RECEIPT_CANONICAL_DIGEST
        or receipt["schema"]
        != "aragorn/phase3-openclaw-protected-restore-authority-archive-replacement-retention/v1"
        or receipt["status"] != "OBSERVED"
        or any(receipt[name] is not False for name in false_fields)
        or receipt["evidence"] != expected_evidence
        or receipt["observed_at"] != evidence["recorded_at"]
        or receipt["results"]
        != {
            "fail": [],
            "not_tested": not_tested,
            "not_tested_count": 20,
            "observed": [_ROUTE],
            "pass": [],
        }
        or inputs["profile"]["digest"] != _SOURCES["profile"][0]
        or inputs["profile"]["bytes"] != len(sources["profile"])
        or inputs["runtime_lock"]["digest"] != _SOURCES["runtime_lock"][0]
        or inputs["runtime_lock"]["bytes"] != len(sources["runtime_lock"])
        or inputs["configuration"]["digest"] != _SOURCES["configuration"][0]
        or inputs["configuration"]["bytes"] != len(sources["configuration"])
        or inputs["probe"]["digest"] != _SOURCES["probe"][0]
        or inputs["probe"]["bytes"] != len(sources["probe"])
        or inputs["protected_target"]["digest"] != _SOURCES["target"][0]
        or inputs["protected_target"]["bytes"] != len(sources["target"])
        or inputs["replacement_source"]["digest"] != _SOURCES["replacement"][0]
        or inputs["replacement_source"]["bytes"] != len(sources["replacement"])
        or receipt["implementation"]["materializer"]
        != {
            "bytes": _MATERIALIZER[1],
            "digest": _MATERIALIZER[0],
            "path": "scripts/materialize_fixed_admission_probes.py",
            "source": "git archive b82ead2e66dc1c86ea82691625321032de21ea29",
        }
        or receipt["runtime"]["commit"] != profile["runtime"]["commit"]
        or receipt["runtime"]["runtime_tree"]
        != lock["installed_runtime"]["runtime_tree"]
    ):
        raise AdmissionEvidenceError("archive retention receipt changed")
    _verify_containment(receipt, evidence)


def _verify_containment(
    receipt: Mapping[str, Any], evidence: Mapping[str, Any]
) -> None:
    containment = receipt["containment"]
    container = containment["container"]
    controls = containment["controls"]
    expected_mounts = [
        ("/profile/config", "aragorn-openclaw-restore-authority-config-3eec2a5811e2"),
        ("/profile/home/.agents/skills", "aragorn-openclaw-p3-archive-guard-v1"),
        ("/profile/state/extensions", "aragorn-openclaw-p3-archive-guard-v1"),
        ("/profile/state/plugin-skills", "aragorn-openclaw-p3-archive-guard-v1"),
        ("/profile/state/skills", "aragorn-openclaw-p3-archive-guard-v1"),
        ("/profile/workspace/.agents/skills", "aragorn-openclaw-p3-archive-guard-v1"),
        ("/profile/workspace/skills", "aragorn-openclaw-p3-archive-target-v1"),
        ("/probe", "aragorn-openclaw-restore-authority-archive-probe-b82ead2"),
        ("/runtime", "aragorn-openclaw-2026-7-1-session-snapshot-restore-authority-v1"),
        ("/sources", "aragorn-openclaw-p3-archive-source-v1"),
    ]
    mounts = [
        {"destination": destination, "read_only": True, "volume": volume}
        for destination, volume in expected_mounts
    ]
    if (
        containment["command"]
        != [
            _OPENCLAW,
            "gateway",
            "run",
            "--allow-unconfigured",
            "--auth",
            "token",
            "--bind",
            "loopback",
            "--port",
            "18789",
            "--tailscale",
            "off",
            "--ws-log",
            "full",
        ]
        or containment["mounts"] != mounts
        or controls["cap_add"] != []
        or controls["cap_drop"] != ["ALL"]
        or controls["network"] != "none"
        or controls["no_new_privileges"] is not True
        or controls["privileged"] is not False
        or controls["read_only_rootfs"] is not True
        or controls["runtime_user"] != "1000:1000"
        or controls["group_add"] != [982]
        or controls["pids_limit"] != 128
        or controls["memory_bytes"] != 1_073_741_824
        or controls["memory_swap_bytes"] != 1_073_741_824
        or controls["cpu_limit"] != 1_000_000_000
        or controls["restart_policy"] != "no"
        or controls["gateway_token_present"] is not True
        or container["id"]
        != "3a097ae41da61f73f430ffcab4c45e20d95cea299cb72f85a7706dcf55c257e3"
        or container["name"]
        != "aragorn-openclaw-restore-authority-archive-final-b82ead2"
        or container["state"]
        != {
            "dead": False,
            "exit_code": 0,
            "oom_killed": False,
            "restart_count": 0,
            "restarting": False,
            "status": "exited",
        }
        or container["labels"]["io.aragorn.probe-sha256"]
        != _SOURCES["probe"][0].removeprefix("sha256:")
        or container["labels"]["io.aragorn.source-commit"]
        != "b82ead2e66dc1c86ea82691625321032de21ea29"
        or _time(container["started_at"])
        > _time(evidence["action"]["commands"][0]["started_at"])
        or _time(evidence["recorded_at"]) > _time(container["finished_at"])
    ):
        raise AdmissionEvidenceError("archive containment changed")


def _verify_evidence(
    evidence: Mapping[str, Any],
    receipt: Mapping[str, Any],
    profile: Mapping[str, Any],
    lock: Mapping[str, Any],
    config_raw: bytes,
) -> None:
    # Exact envelope first; semantic checks below do not normalize old identities.
    if canonical_digest(evidence) != _EVIDENCE["canonical_digest"]:
        raise AdmissionEvidenceError("archive observation envelope changed")
    expected_runtime = {
        "commit": profile["runtime"]["commit"],
        "node_path": _NODE,
        "openclaw_digest": lock["installed_runtime"]["openclaw_digest"],
        "openclaw_path": _OPENCLAW,
        "runtime_tree_digest": lock["installed_runtime"]["runtime_tree"]["tree_digest"],
        "version": profile["runtime"]["version"],
    }
    if (
        set(evidence)
        != {
            "action",
            "assurance",
            "implementation_digest",
            "protected_boundary",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or evidence["schema"] != _EVIDENCE["schema"]
        or evidence["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or evidence["implementation_digest"] != _SOURCES["probe"][0]
        or evidence["runtime_binding"] != expected_runtime
        or re.fullmatch(r"[0-9a-f]{32}", evidence["run_nonce"]) is None
        or evidence["route"]
        != {
            "action_id": "archive-source-force-replacement",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
    ):
        raise AdmissionEvidenceError("archive observation identity changed")

    action = evidence["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        action["id"] != "archive-source-force-replacement"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["ready"] is not True
        or before["reason_codes"] != []
        or before["runtime_tree"] != lock["installed_runtime"]["runtime_tree"]
        or after["runtime_tree_after"] != before["runtime_tree"]
        or after["boundary_after"] != evidence["protected_boundary"]
        or after["source_after"] != before["source"]
        or after["target_after"] != before["target_before"]
        or after["gateway_after"] != before["gateway_process"]
        or after["staging_before"] != []
        or after["staging_after"] != []
        or after["discovery_after"]["response"] != before["discovery"]["response"]
    ):
        raise AdmissionEvidenceError("archive observed state changed")

    configuration = runtime_profile.load_runtime_profile(config_raw)
    _verify_boundary(evidence["protected_boundary"], configuration)
    archive._verify_fixture_tree(
        before["source"],
        root_path=_SOURCE,
        digest=_SOURCES["replacement"][0],
        size=_SOURCES["replacement"][1],
        tree_digest=archive._SOURCE_TREE_DIGEST,
    )
    archive._verify_fixture_tree(
        before["target_before"],
        root_path=_TARGET,
        digest=_SOURCES["target"][0],
        size=_SOURCES["target"][1],
        tree_digest=archive._TARGET_TREE_DIGEST,
    )
    _verify_runtime(before, after, receipt, lock)
    _verify_commands(action, evidence["recorded_at"])


def _verify_boundary(
    boundary: Mapping[str, Any], configuration: Mapping[str, Any]
) -> None:
    if (
        boundary["ready"] is not True
        or boundary["effective_identity"]
        != {"gid": 1000, "groups": [982, 1000], "uid": 1000}
        or set(boundary["roots"]) != set(curator._ROOT_SOURCES)
        or set(boundary["inputs"]) != {"probe", "source"}
    ):
        raise AdmissionEvidenceError("archive protected boundary changed")
    for name, source in curator._ROOT_SOURCES.items():
        archive._verify_ro_mount(
            boundary["roots"][name],
            target=runtime_profile._PROTECTED_ROOTS[name][0],
            source=source,
            uid=0,
            gid=982,
            mode="750",
            entries=[curator._TARGET] if name == "workspace_skills" else [],
        )
    for value, target, source, gid, mode, entries in (
        (
            boundary["configuration"]["mount"],
            "/profile/config",
            "/docker/volumes/aragorn-openclaw-restore-authority-config-3eec2a5811e2/_data",
            982,
            "750",
            ["openclaw.json"],
        ),
        (
            boundary["inputs"]["probe"],
            "/probe",
            "/docker/volumes/aragorn-openclaw-restore-authority-archive-probe-b82ead2/_data",
            0,
            "755",
            ["protected-archive-replacement-probe.mjs"],
        ),
        (
            boundary["inputs"]["source"],
            "/sources",
            "/docker/volumes/aragorn-openclaw-p3-archive-source-v1/_data",
            982,
            "750",
            ["replacement"],
        ),
        (
            boundary["runtime"],
            "/runtime",
            "/docker/volumes/aragorn-openclaw-2026-7-1-session-snapshot-restore-authority-v1/_data",
            0,
            "755",
            ["bin", "lib"],
        ),
    ):
        archive._verify_ro_mount(
            value,
            target=target,
            source=source,
            uid=0,
            gid=gid,
            mode=mode,
            entries=entries,
        )
    file = boundary["configuration"]["file"]
    if (
        boundary["configuration"]["ready"] is not True
        or boundary["configuration"]["canonical_digest"]
        != curator._CONFIG_CANONICAL_DIGEST
        or file["path"] != "/profile/config/openclaw.json"
        or file["exists"] is not True
        or file["type"] != "file"
        or file["uid"] != 0
        or file["gid"] != 982
        or file["mode"] != "440"
        or file["nlink"] != 1
        or file["size"] != _SOURCES["configuration"][1]
        or file["digest"] != _SOURCES["configuration"][0]
        or file["digest_error"] is not None
        or configuration["skills"]["workshop"]["restoreAuthority"] != "external"
    ):
        raise AdmissionEvidenceError("archive boundary config changed")


def _verify_runtime(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    receipt: Mapping[str, Any],
    lock: Mapping[str, Any],
) -> None:
    gateway = before["gateway_process"]
    openclaw = before["openclaw"]
    container = receipt["containment"]["container"]
    if (
        gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "hostname": container["id"][:12],
            "pid": 1,
            "start_time_ticks": "3484666",
        }
        or after["gateway_after"] != gateway
        or openclaw["path"] != _OPENCLAW
        or openclaw["exists"] is not True
        or openclaw["type"] != "file"
        or openclaw["uid"] != 0
        or openclaw["gid"] != 0
        or openclaw["mode"] != "755"
        or openclaw["nlink"] != 1
        or openclaw["size"] != 23_463
        or openclaw["digest"] != lock["installed_runtime"]["openclaw_digest"]
        or openclaw["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("archive runtime identity changed")


def _verify_commands(action: Mapping[str, Any], recorded_at: str) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    commands = action["commands"]
    expected = [
        before["version"],
        before["system_info"]["command"],
        before["positive_control"]["install"],
        before["discovery"]["command"],
        after["upload_begin"]["command"],
        after["upload_install"]["command"],
        after["source_install"]["command"],
        after["discovery_after"]["command"],
    ]
    if (
        commands != expected
        or len(commands) != 8
        or any(not curator._command_output_exact(command) for command in commands)
        or any(
            command["error"] is not None or command["signal"] is not None
            for command in commands
        )
        or any(
            type(command["pid"]) is not int or command["pid"] <= 0
            for command in commands
        )
        or len({command["pid"] for command in commands}) != 8
        or any(
            _time(command["started_at"]) >= _time(command["completed_at"])
            for command in commands
        )
        or any(
            _time(left["completed_at"]) > _time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or _time(commands[-1]["completed_at"]) > _time(recorded_at)
        or commands[0]["argv"] != [_NODE, _OPENCLAW, "--version"]
        or commands[0]["stdout_excerpt"] != _VERSION_STDOUT
        or any(
            not runtime_profile._command_succeeded_clean(commands[index])
            for index in (0, 1, 2, 3, 7)
        )
    ):
        raise AdmissionEvidenceError("archive command projection changed")
    _verify_system(before["system_info"], before["gateway_process"])
    _verify_positive(before["positive_control"])
    _verify_discovery(before["discovery"])
    _verify_discovery(after["discovery_after"])
    _verify_upload_denials(after)
    _verify_protected_denial(after["source_install"])


def _install_argv() -> list[str]:
    return [
        _NODE,
        _OPENCLAW,
        "skills",
        "install",
        _SOURCE,
        "--as",
        curator._TARGET,
        "--force",
        "--agent",
        "main",
    ]


def _verify_system(system: Mapping[str, Any], gateway: Mapping[str, Any]) -> None:
    value = system["response"]["value"]
    if (
        system["response"]["parsed"] is not True
        or json.loads(system["command"]["stdout_excerpt"]) != value
        or system["command"]["argv"]
        != [
            _NODE,
            _OPENCLAW,
            "gateway",
            "call",
            "system.info",
            "--json",
            "--timeout",
            "5000",
        ]
        or value["pid"] != gateway["pid"]
        or value["hostname"] != gateway["hostname"]
        or value["platform"] != "linux"
        or value["arch"] != "arm64"
        or value["nodeVersion"] != "v24.16.0"
        or value["port"] != 18_789
        or value["diskPath"] != "/profile/state"
        or value["diskTotalBytes"] != 33_554_432
    ):
        raise AdmissionEvidenceError("archive system identity changed")


def _verify_positive(positive: Mapping[str, Any]) -> None:
    target = positive["target_after"]
    if (
        positive["ready"] is not True
        or positive["configuration_digest"]
        != "sha256:22845270bfefeed5724a079549b606f11e192c6818f7ab8e37acf30ba0f14e3d"
        or positive["target_before"]
        != {
            "exists": False,
            "path": "/profile/control/workspace/skills/requesting-code-review",
        }
        or positive["install"]["argv"] != _install_argv()
        or positive["install"]["stdout_excerpt"]
        != (
            "Installing to /profile/control/workspace/skills/requesting-code-review…\n"
            "Installed requesting-code-review from path -> /profile/control/"
            "workspace/skills/requesting-code-review\n"
        )
        or target["ready"] is not True
        or target["root"]["path"]
        != "/profile/control/workspace/skills/requesting-code-review"
        or target["tree_digest"]
        != "sha256:6a265c7f954664087c03e6e90a785fdcac39991cf3338091c1bd35f7c78f4f44"
        or not any(
            item.get("path") == "SKILL.md"
            and item.get("digest") == _SOURCES["replacement"][0]
            and item.get("size") == _SOURCES["replacement"][1]
            for item in target["entries"]
        )
    ):
        raise AdmissionEvidenceError("archive positive control changed")


def _verify_discovery(discovery: Mapping[str, Any]) -> None:
    command = discovery["command"]
    if (
        discovery["response"] != {"parsed": True, "value": archive._EXPECTED_DISCOVERY}
        or json.loads(command["stdout_excerpt"]) != archive._EXPECTED_DISCOVERY
        or command["argv"]
        != [
            _NODE,
            _OPENCLAW,
            "skills",
            "info",
            curator._TARGET,
            "--agent",
            "main",
            "--json",
        ]
    ):
        raise AdmissionEvidenceError("archive discovery changed")


def _verify_upload_denials(after: Mapping[str, Any]) -> None:
    error = {
        "code": "UNAVAILABLE",
        "message": (
            "Uploaded skill archive installs are disabled by "
            "skills.install.allowUploadedArchives"
        ),
        "retryable": False,
        "type": "gateway_request_error",
    }
    begin_argv = [
        _NODE,
        _OPENCLAW,
        "gateway",
        "call",
        "skills.upload.begin",
        "--json",
        "--timeout",
        "5000",
        "--params",
        "{}",
    ]
    install_argv = [
        _NODE,
        _OPENCLAW,
        "gateway",
        "call",
        "skills.install",
        "--json",
        "--timeout",
        "5000",
        "--params",
        '{"agentId":"main","force":true,"sha256":"'
        + "a" * 64
        + '","slug":"requesting-code-review","source":"upload","uploadId":"'
        + "a" * 32
        + '"}',
    ]
    for result, argv in (
        (after["upload_begin"], begin_argv),
        (after["upload_install"], install_argv),
    ):
        command = result["command"]
        if (
            result["response"]
            != {"parsed": True, "value": {"error": error, "ok": False}}
            or command["argv"] != argv
            or command["exit_code"] != 1
            or command["stderr_bytes"] != 0
            or command["stderr_digest"] != _EMPTY_DIGEST
            or json.loads(command["stdout_excerpt"]) != result["response"]["value"]
        ):
            raise AdmissionEvidenceError("archive upload denial changed")


def _verify_protected_denial(result: Mapping[str, Any]) -> None:
    command = result["command"]
    if (
        result["response"] != {"parsed": False, "value": None}
        or command["argv"] != _install_argv()
        or command["exit_code"] != 1
        or command["stdout_excerpt"]
        != "Installing to /profile/workspace/skills/requesting-code-review…\n"
        or re.fullmatch(
            r"failed to install skill: Error: EROFS: read-only file system, "
            r"mkdtemp '/profile/workspace/skills/\.openclaw-install-stage-"
            r"[A-Za-z0-9]{6}'\n",
            command["stderr_excerpt"],
        )
        is None
    ):
        raise AdmissionEvidenceError("archive protected force denial changed")
