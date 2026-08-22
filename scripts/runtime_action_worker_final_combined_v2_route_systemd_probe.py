#!/usr/bin/env python3
"""Observe one fresh-session route in the exact final combined V2 stack."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_worker_final_combined_v2_systemd_probe as combined
import runtime_action_worker_final_route_systemd_probe as v1_route

_ROUTE = "ADM-02/reload/fresh-session-reset"
_PROBE_ROOT = Path("/route-input/probe")
_PROBE = _PROBE_ROOT / "protected-route-probe.mjs"
_EXPECTED_PROBE = {
    "bytes": 44_825,
    "digest": "sha256:ac23d68064c1a904649c6c1064f8c7729768fe516eef1e6d7c2bdc6b4e12d299",
}
_OUTPUT = Path("/evidence/runtime-action-worker-final-combined-v2-route-systemd.json")
_SCHEMA = "aragorn/runtime-action-worker-final-combined-v2-route-systemd-observation/v1"
_AUTHORITY = (
    "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_"
    "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_ORIGINAL_PREPARE_GATEWAY = combined._prepare_gateway
_ORIGINAL_COHERENT_CASE = combined.p37c._coherent_case
_ROUTE_OBSERVATION: dict[str, Any] | None = None
_STAGE = "BOOTSTRAP"


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    combined._expect(condition, message)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _probe_record() -> dict[str, Any]:
    record = combined.p37c._file(_PROBE)
    metadata = record["stat"]
    _expect(
        metadata["uid"] == 0
        and metadata["gid"] == 0
        and metadata["mode"] == "0444"
        and metadata["nlink"] == 1,
        "materialized route probe metadata changed",
    )
    _expect(
        {key: record[key] for key in _EXPECTED_PROBE} == _EXPECTED_PROBE,
        "materialized V2 route probe identity changed",
    )
    return {
        "name": _PROBE.name,
        "bytes": record["bytes"],
        "digest": record["digest"],
    }


def _prepare_gateway(
    gateway_uid: int,
    gateway_gid: int,
    worker_uid: int,
    skill_name: str,
    skill_raw: bytes,
) -> tuple[dict[str, Any], dict[str, str], Path, str]:
    prepared = _ORIGINAL_PREPARE_GATEWAY(
        gateway_uid, gateway_gid, worker_uid, skill_name, skill_raw
    )
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


def _run_route(tokens: dict[str, str], gateway_pid: int) -> dict[str, Any]:
    harness = {"document": {"probe_bundle": [_probe_record()]}}
    with (
        mock.patch.object(v1_route, "_PROBE_ROOT", _PROBE_ROOT),
        mock.patch.object(v1_route, "_SELECTED_ROUTE", _ROUTE),
    ):
        return v1_route._run_route(tokens, harness, gateway_pid)


def _coherent_case(**kwargs: Any) -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _set_stage("P3_7C_COHERENT_ACTION")
    coherent = _ORIGINAL_COHERENT_CASE(**kwargs)
    _set_stage("ADM_02_FRESH_SESSION_RESET")
    gateway_pid = kwargs["stack"]["pids"][combined.p37c._GATEWAY_UNIT]
    _ROUTE_OBSERVATION = {
        **_run_route(kwargs["tokens"], gateway_pid),
        "gateway_pid_binding": {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{gateway_pid}/ns/mnt",
            "pid": gateway_pid,
            "unit": combined.p37c._GATEWAY_UNIT,
        },
        "stack_before": kwargs["stack"],
    }
    return coherent


def _decision(status: str) -> dict[str, Any]:
    _expect(status in {"NOT_TESTED", "OBSERVED"}, "route status changed")
    return {
        "status": (
            "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED"
            if status == "OBSERVED"
            else "FINAL_COMBINED_V2_ROUTE_NOT_TESTED_PROFILE_NOT_TESTED"
        ),
        "route_observation_status": status,
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in sorted(combined._ELIGIBILITY_KEYS)},
    }


def _collect() -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _ROUTE_OBSERVATION = None
    if os.environ.get("OPENCLAW_TEST_FAST") is not None:
        raise combined.openclaw.ProbeError("OPENCLAW_TEST_FAST must be absent")
    _set_stage("FINAL_COMBINED_V2")
    with (
        mock.patch.object(combined, "_prepare_gateway", _prepare_gateway),
        mock.patch.object(combined.p37c, "_coherent_case", _coherent_case),
    ):
        composition = combined._collect()
    _expect(_ROUTE_OBSERVATION is not None, "fresh-session route did not execute")
    status = _ROUTE_OBSERVATION["route"]["status"]
    _expect(
        composition["decision"]["route_pass_count"] == 0
        and composition["decision"]["route_fail_count"] == 0
        and composition["decision"]["route_not_tested_count"] == 21
        and all(
            composition["decision"][key] is False for key in combined._ELIGIBILITY_KEYS
        ),
        "V2 composition claim ceiling changed",
    )
    _set_stage("OBSERVATION_ASSEMBLY")
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "route_id": _ROUTE,
        "route_observation": _ROUTE_OBSERVATION,
        "composition": composition,
        "source_artifacts": {
            "collector": combined.p37c._file(Path(__file__).resolve()),
            "materializer": combined.p37c._file(
                Path("/src/scripts/materialize_fixed_admission_probes.py")
            ),
            "probe": _probe_record(),
            "v1_route_injector": combined.p37c._file(
                Path("/src/scripts/runtime_action_worker_final_route_systemd_probe.py")
            ),
        },
        "decision": _decision(status),
        "limitations": [
            "OBSERVED_IS_NOT_PASS",
            "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
    }


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "route_id": _ROUTE,
        "decision": _decision("NOT_TESTED"),
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
    if arguments:
        print(
            "usage: runtime_action_worker_final_combined_v2_route_systemd_probe.py",
            file=sys.stderr,
        )
        return 64
    try:
        result = _collect()
        status = 0
    except Exception as exc:  # noqa: BLE001 - failed captures self-describe
        result = _failure(exc)
        status = 2
    combined.p37c._publish(_OUTPUT, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
