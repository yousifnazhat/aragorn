#!/usr/bin/env python3
"""Run one protected route while the exact final systemd stack is active."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, "/src/scripts")

import runtime_action_worker_final_combined_systemd_probe as combined

p37c = combined.p37c
openclaw = combined.openclaw

_OUTPUT = Path("/evidence/runtime-action-worker-final-route-systemd.json")
_ROUTE_HARNESS = Path("/run/aragorn-route-harness.json")
_PROBE_ROOT = Path("/route-input/probe")
_GATEWAY_CREDENTIAL = Path(
    "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
)
_MAX_OUTPUT = 4 * 1024 * 1024
_MAX_STDERR = 128 * 1024
_SCHEMA = "aragorn/runtime-action-worker-final-route-systemd-observation/v1"
_AUTHORITY = (
    "BOUNDED_FINAL_PROFILE_RAW_ROUTE_OBSERVATION_ONLY_"
    "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_ELIGIBILITY_KEYS = combined._ELIGIBILITY_KEYS
_ORIGINAL_COHERENT_CASE = p37c._coherent_case
_ORIGINAL_PREPARE_GATEWAY = combined._prepare_gateway
_ORIGINAL_COMBINED_HARNESS = combined._harness
_STAGE = "BOOTSTRAP"
_SELECTED_ROUTE = ""
_ROUTE_OBSERVATION: dict[str, Any] | None = None
_FINAL_HARNESS: dict[str, Any] | None = None

_ROUTES = {
    "ADM-02/reload/cron-rescan": {
        "files": (
            "protected-cron-rescan-probe.mjs",
            "protected-observation-v1.mjs",
        ),
        "probe": "protected-cron-rescan-probe.mjs",
        "schema": "aragorn/openclaw-protected-cron-rescan-observation/v1",
    },
    "ADM-02/reload/fresh-session-reset": {
        "files": ("protected-route-probe.mjs",),
        "probe": "protected-route-probe.mjs",
        "schema": "aragorn/openclaw-protected-route-action-observations/v1",
    },
    "ADM-02/reload/missing-prompt-blob-rebuild": {
        "files": (
            "protected-observation-v1.mjs",
            "protected-prompt-rebuild-probe.mjs",
        ),
        "probe": "protected-prompt-rebuild-probe.mjs",
        "schema": "aragorn/openclaw-protected-prompt-rebuild-observation/v1",
    },
    "ADM-02/reload/session-snapshot-consumer": {
        "files": (
            "protected-observation-v1.mjs",
            "protected-session-snapshot-fixed-probe.mjs",
        ),
        "probe": "protected-session-snapshot-fixed-probe.mjs",
        "schema": ("aragorn/openclaw-protected-session-snapshot-fixed-observation/v1"),
    },
}


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    combined._expect(condition, message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_document(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    document = json.loads(
        raw,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        parse_float=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )
    _expect(
        isinstance(document, dict) and raw == p37c.canonical_json(document),
        f"document is not canonical JSON: {path}",
    )
    return document, raw


def _route_harness() -> dict[str, Any]:
    document, raw = _canonical_document(_ROUTE_HARNESS)
    final_harness = _final_harness()
    specification = _ROUTES[_SELECTED_ROUTE]
    _expect(
        set(document)
        == {
            "schema",
            "capture_disposition",
            "route_source_commit",
            "route_source_commit_verification",
            "image_source_commit",
            "route_id",
            "child_image_id",
            "composition_harness_digest",
            "baseline_composition",
            "probe_bundle",
            "collector",
        }
        and document.get("schema")
        == "aragorn/runtime-action-worker-final-route-systemd-harness/v1"
        and document.get("capture_disposition")
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and document.get("route_id") == _SELECTED_ROUTE
        and document.get("image_source_commit")
        == final_harness["document"].get("source_commit")
        == "c59154968b2cd637d88a5a17d5b1100873df7563"
        and document.get("route_source_commit") != document.get("image_source_commit")
        and document.get("child_image_id")
        == final_harness["document"]["image_id"]
        == "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
        and document.get("composition_harness_digest") == final_harness["digest"]
        and final_harness["document"].get("host_config", {}).get("network_mode")
        == "none"
        and final_harness["document"].get("host_config", {}).get("privileged") is True
        and f"{combined._RUNTIME_VOLUME}:/runtime:ro"
        in final_harness["document"].get("host_config", {}).get("binds", [])
        and any(
            value.endswith(":/route-input:ro")
            for value in final_harness["document"]
            .get("host_config", {})
            .get("binds", [])
        )
        and document.get("baseline_composition")
        == {
            "bytes": 347400,
            "digest": (
                "sha256:281c2de033ed033cc8df71a2e45a4e058005eb4764dd926d8b5422280ed8a029"
            ),
            "path": (
                "benchmark/evidence/runtime-action-worker-final-combined-"
                "systemd-composition-p3-final-2026-08-13.json"
            ),
        }
        and tuple(item["name"] for item in document.get("probe_bundle", []))
        == specification["files"],
        "final route harness changed",
    )
    route_source_commit = document["route_source_commit"]
    verification = document["route_source_commit_verification"]
    commit_raw = p37c._raw_bytes(verification.get("commit_object", {}))
    commit_identity = hashlib.sha1(
        f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
    ).hexdigest()
    _expect(
        len(route_source_commit) == 40
        and all(value in "0123456789abcdef" for value in route_source_commit)
        and set(verification)
        == {"command", "exit_code", "commit_object", "stdout", "stderr"}
        and verification.get("command")
        == ["git", "verify-commit", "--raw", route_source_commit]
        and verification.get("exit_code") == 0
        and commit_identity == route_source_commit
        and commit_raw.startswith(b"tree ")
        and b"\ngpgsig " in commit_raw
        and p37c._raw_bytes(verification["stdout"]) == b""
        and p37c._raw_bytes(verification["stderr"]) == p37c._SOURCE_SIGNATURE,
        "route source commit signature changed",
    )
    for key, path in (
        (
            "capture_recipe",
            "/route-input/scripts/capture_runtime_action_worker_final_route_systemd.sh",
        ),
        ("materializer", "/route-input/scripts/materialize_fixed_admission_probes.py"),
        ("probe", str(Path(__file__).resolve())),
    ):
        expected = document["collector"][key]
        actual = combined.p37c._file(Path(path))
        _expect(
            expected
            == {
                "source_path": expected["source_path"],
                "runtime_path": str(Path(path)),
                "bytes": actual["bytes"],
                "digest": actual["digest"],
            },
            f"route collector changed: {key}",
        )
    return {
        "document": document,
        "bytes": len(raw),
        "digest": _digest(raw),
        "final_combined": final_harness,
    }


def _final_harness() -> dict[str, Any]:
    global _FINAL_HARNESS
    if _FINAL_HARNESS is None:
        _FINAL_HARNESS = p37c._stable_document_snapshot(combined._HARNESS)
    document = _FINAL_HARNESS["document"]
    binds = document.get("host_config", {}).get("binds", [])
    route_mounts = [value for value in binds if value.endswith(":/route-input:ro")]
    _expect(len(route_mounts) == 1, "route-aware final harness mount changed")
    normalized = json.loads(p37c.canonical_json(document))
    normalized["host_config"]["binds"].remove(route_mounts[0])
    descriptor, name = tempfile.mkstemp(
        prefix="aragorn-final-base-harness-", dir="/run"
    )
    path = Path(name)
    try:
        remaining = memoryview(p37c.canonical_json(normalized))
        while remaining:
            written = os.write(descriptor, remaining)
            _expect(written > 0, "normalized harness write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        with mock.patch.object(combined, "_HARNESS", path):
            base = _ORIGINAL_COMBINED_HARNESS()
    finally:
        path.unlink(missing_ok=True)
    _expect(base["document"] == normalized, "normalized final harness changed")
    return _FINAL_HARNESS


def _prepare_gateway(*args: Any, **kwargs: Any) -> Any:
    prepared = _ORIGINAL_PREPARE_GATEWAY(*args, **kwargs)
    gateway_uid, gateway_gid = args[:2]
    _expect((gateway_uid, gateway_gid) == (992, 992), "gateway identity changed")
    for path in (
        combined.p37c.p37b._GATEWAY_STATE / "extensions",
        combined.p37c.p37b._GATEWAY_STATE / "skills",
        combined.p37c.p37b._GATEWAY_STATE / "plugin-skills",
        combined.p37c.p37b._GATEWAY_HOME / ".agents" / "skills",
        combined.p37c.p37b._GATEWAY_WORKSPACE / ".agents" / "skills",
        combined.p37c.p37b._GATEWAY_WORKSPACE / "skills",
    ):
        combined.p37c.p37b._mkdir(path, gateway_uid, gateway_gid, 0o700)
    return prepared


def _probe_bundle(harness: dict[str, Any]) -> list[dict[str, Any]]:
    expected = harness["document"]["probe_bundle"]
    actual_names = tuple(sorted(path.name for path in _PROBE_ROOT.iterdir()))
    specification = _ROUTES[_SELECTED_ROUTE]
    _expect(
        actual_names == tuple(sorted(specification["files"])),
        "probe bundle inventory changed",
    )
    actual = []
    for name in specification["files"]:
        path = _PROBE_ROOT / name
        item = combined.p37c._file(path)
        _expect(
            item["stat"]["uid"] == 0
            and item["stat"]["gid"] == 0
            and item["stat"]["mode"] == "0444"
            and item["stat"]["nlink"] == 1,
            f"probe metadata changed: {name}",
        )
        actual.append(
            {
                "name": name,
                "bytes": item["bytes"],
                "digest": item["digest"],
            }
        )
    _expect(actual == expected, "probe bundle bytes changed after materialization")
    return actual


def _selected_result(document: dict[str, Any]) -> dict[str, Any]:
    if "route" in document:
        route = document["route"]
    else:
        routes = document.get("routes")
        _expect(
            document.get("selected_route_ids") == [_SELECTED_ROUTE]
            and isinstance(routes, list)
            and len(routes) == 1,
            "selected generic route result changed",
        )
        route = routes[0]
    _expect(
        isinstance(route, dict)
        and route.get("id") == _SELECTED_ROUTE
        and route.get("status") in {"OBSERVED", "NOT_TESTED"}
        and isinstance(route.get("reason_codes"), list),
        "selected route result changed",
    )
    return route


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        _expect(key not in document, f"duplicate route output key: {key}")
        document[key] = value
    return document


def _run_route(
    tokens: dict[str, str], harness: dict[str, Any], gateway_pid: int
) -> dict[str, Any]:
    specification = _ROUTES[_SELECTED_ROUTE]
    probe = _PROBE_ROOT / specification["probe"]
    command = [
        "nsenter",
        "--target",
        str(gateway_pid),
        "--mount",
        "--",
        "setpriv",
        "--reuid=992",
        "--regid=992",
        "--groups=992",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        "/usr/local/bin/node",
        str(probe),
    ]
    if probe.name == "protected-route-probe.mjs":
        command += ["--route-id", _SELECTED_ROUTE]
    started_at = _iso_now()
    process = subprocess.run(
        command,
        cwd=str(combined.p37c.p37b._GATEWAY_WORKSPACE),
        env={
            "HOME": str(combined.p37c.p37b._GATEWAY_HOME),
            "ARAGORN_GATEWAY_PID": str(gateway_pid),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "OPENCLAW_CONFIG_PATH": str(_GATEWAY_CREDENTIAL),
            "OPENCLAW_STATE_DIR": str(combined.p37c.p37b._GATEWAY_STATE),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TZ": "UTC",
            **tokens,
        },
        check=False,
        capture_output=True,
        timeout=120,
    )
    completed_at = _iso_now()
    _expect(
        process.returncode == 0
        and len(process.stdout) <= _MAX_OUTPUT
        and len(process.stderr) <= _MAX_STDERR,
        "route probe did not exit cleanly within output bounds",
    )
    token_values = [value.encode("ascii") for value in tokens.values()]
    _expect(
        all(
            token not in process.stdout and token not in process.stderr
            for token in token_values
        ),
        "route probe retained a token",
    )
    document = json.loads(
        process.stdout,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        object_pairs_hook=_unique_pairs,
    )
    canonical = p37c.canonical_json(document)
    _expect(
        isinstance(document, dict)
        and process.stdout.endswith(b"\n")
        and b"\n" not in process.stdout[:-1]
        and b"\r" not in process.stdout
        and document.get("schema") == specification["schema"],
        "route probe output changed",
    )
    route = _selected_result(document)
    return {
        "route": route,
        "document": document,
        "raw": {
            **p37c._raw_record(process.stdout),
            "canonical_digest": _digest(canonical),
            "raw_is_canonical_json_lf": process.stdout == canonical + b"\n",
        },
        "execution": {
            "argv": command,
            "started_at": started_at,
            "completed_at": completed_at,
            "exit_code": process.returncode,
            "effective_identity": {"uid": 992, "gid": 992, "groups": [992]},
            "environment_names": sorted(
                {
                    "ARAGORN_GATEWAY_PID",
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "NO_COLOR",
                    "NO_PROXY",
                    "OPENCLAW_CONFIG_PATH",
                    "OPENCLAW_GATEWAY_TOKEN",
                    "OPENCLAW_STATE_DIR",
                    "ARAGORN_MOCK_PROVIDER_TOKEN",
                    "PATH",
                    "TZ",
                }
            ),
            "stderr": {
                "bytes": len(process.stderr),
                "digest": _digest(process.stderr),
                "excerpt": process.stderr.decode("utf-8", errors="replace")[:2048],
            },
        },
        "bundle": _probe_bundle(harness),
    }


def _coherent_case(**kwargs: Any) -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _set_stage("FINAL_ROUTE")
    harness = _route_harness()
    gateway_pid = kwargs["stack"]["pids"][p37c._GATEWAY_UNIT]
    route = _run_route(kwargs["tokens"], harness, gateway_pid)
    _ROUTE_OBSERVATION = {
        **route,
        "stack_before": kwargs["stack"],
        "gateway_pid_binding": {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{gateway_pid}/ns/mnt",
            "pid": gateway_pid,
            "unit": p37c._GATEWAY_UNIT,
        },
        "profile_paths": {
            "config": str(_GATEWAY_CREDENTIAL),
            "home": str(combined.p37c.p37b._GATEWAY_HOME),
            "state": str(combined.p37c.p37b._GATEWAY_STATE),
            "workspace": str(combined.p37c.p37b._GATEWAY_WORKSPACE),
        },
    }
    _set_stage("P3_7C_COHERENT_ACTION")
    return _ORIGINAL_COHERENT_CASE(**kwargs)


def _collect(route_id: str) -> dict[str, Any]:
    global _SELECTED_ROUTE, _ROUTE_OBSERVATION, _FINAL_HARNESS
    _SELECTED_ROUTE = route_id
    _ROUTE_OBSERVATION = None
    _FINAL_HARNESS = None
    if os.environ.get("OPENCLAW_TEST_FAST") is not None:
        raise openclaw.ProbeError("OPENCLAW_TEST_FAST must be absent")
    _set_stage("FINAL_COMPOSITION")
    with (
        mock.patch.object(combined, "_harness", _final_harness),
        mock.patch.object(combined, "_prepare_gateway", _prepare_gateway),
        mock.patch.object(p37c, "_coherent_case", _coherent_case),
    ):
        composition = combined._collect()
    _expect(_ROUTE_OBSERVATION is not None, "selected route did not execute")
    route_status = _ROUTE_OBSERVATION["route"]["status"]
    decision = composition["decision"]
    _expect(
        decision["status"] == "FINAL_COMBINED_ACTION_OBSERVED_PROFILE_NOT_TESTED"
        and {key for key in decision if key.endswith("_eligible")} == _ELIGIBILITY_KEYS
        and all(decision[key] is False for key in _ELIGIBILITY_KEYS),
        "final composition claim ceiling changed",
    )
    _set_stage("OBSERVATION_ASSEMBLY")
    result = {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "route_id": route_id,
        "route_observation": _ROUTE_OBSERVATION,
        "composition": composition,
        "harness": _route_harness(),
        "decision": {
            "status": (
                "FINAL_ROUTE_OBSERVED_PROFILE_NOT_QUALIFIED"
                if route_status == "OBSERVED"
                else "FINAL_ROUTE_NOT_TESTED_PROFILE_NOT_QUALIFIED"
            ),
            "route_observation_status": route_status,
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in sorted(_ELIGIBILITY_KEYS)},
        },
        "limitations": [
            "RAW_ROUTE_OBSERVATION_IS_NOT_INDEPENDENT_CONFORMANCE_AUTHORITY",
            "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "NO_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        ],
    }
    tokens = composition["inputs"].get("gateway_environment_bytes_retained")
    _expect(tokens is False, "composition retained gateway environment bytes")
    return result


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "route_id": _SELECTED_ROUTE,
        "decision": {
            "status": "FINAL_ROUTE_CAPTURE_FAILED_CLOSED",
            "route_observation_status": "NOT_TESTED",
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in sorted(_ELIGIBILITY_KEYS)},
        },
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
    if len(arguments) != 1 or arguments[0] not in _ROUTES:
        print(
            "usage: runtime_action_worker_final_route_systemd_probe.py ROUTE_ID",
            file=sys.stderr,
        )
        return 64
    global _SELECTED_ROUTE
    _SELECTED_ROUTE = arguments[0]
    try:
        result = _collect(_SELECTED_ROUTE)
        status = 0
    except Exception as exc:  # noqa: BLE001 - failed captures self-describe
        result = _failure(exc)
        status = 2
    p37c._publish(_OUTPUT, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
