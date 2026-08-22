#!/usr/bin/env python3
"""Observe one protected route in the exact final combined V2 stack."""

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

_ROUTES = {
    **v1_route._ROUTES,
    "ADM-02/update/config-entry-activation": {
        "files": ("protected-config-activation-probe.mjs",),
        "probe": "protected-config-activation-probe.mjs",
        "schema": "aragorn/openclaw-protected-config-activation-observation/v1",
    },
}
_ROUTE_ROOTS = {
    route_id: Path("/route-input") / route_id.rsplit("/", 1)[1]
    for route_id in _ROUTES
}
_EXPECTED_PROBES = {
    "protected-config-activation-probe.mjs": {
        "bytes": 24_010,
        "digest": (
            "sha256:67b5293379997566faa0aaee192212f479b77f6708c02017bdd235ff12790b98"
        ),
    },
    "protected-cron-rescan-probe.mjs": {
        "bytes": 35_318,
        "digest": "sha256:94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0",
    },
    "protected-observation-v1.mjs": {
        "bytes": 16_324,
        "digest": "sha256:13baaac69f323603f2029eb1dc675f7438d51e0b9440befe775758a38c09a321",
    },
    "protected-prompt-rebuild-probe.mjs": {
        "bytes": 16_464,
        "digest": "sha256:9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7",
    },
    "protected-route-probe.mjs": {
        "bytes": 44_825,
        "digest": "sha256:ac23d68064c1a904649c6c1064f8c7729768fe516eef1e6d7c2bdc6b4e12d299",
    },
    "protected-session-snapshot-fixed-probe.mjs": {
        "bytes": 42_266,
        "digest": "sha256:9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11",
    },
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
_SELECTED_ROUTE = "ADM-02/reload/fresh-session-reset"
_STAGE = "BOOTSTRAP"


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    combined._expect(condition, message)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _probe_bundle(route_id: str) -> list[dict[str, Any]]:
    specification = _ROUTES[route_id]
    root = _ROUTE_ROOTS[route_id]
    _expect(
        tuple(sorted(path.name for path in root.iterdir()))
        == tuple(sorted(specification["files"])),
        "materialized V2 route bundle inventory changed",
    )
    bundle = []
    for name in specification["files"]:
        record = combined.p37c._file(root / name)
        metadata = record["stat"]
        _expect(
            metadata["uid"] == 0
            and metadata["gid"] == 0
            and metadata["mode"] == "0444"
            and metadata["nlink"] == 1,
            f"materialized route probe metadata changed: {name}",
        )
        _expect(
            {key: record[key] for key in ("bytes", "digest")} == _EXPECTED_PROBES[name],
            f"materialized V2 route probe identity changed: {name}",
        )
        bundle.append(
            {"name": name, "bytes": record["bytes"], "digest": record["digest"]}
        )
    return bundle


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


def _run_route(
    route_id: str, tokens: dict[str, str], gateway_pid: int
) -> dict[str, Any]:
    harness = {"document": {"probe_bundle": _probe_bundle(route_id)}}
    with (
        mock.patch.object(v1_route, "_ROUTES", _ROUTES),
        mock.patch.object(v1_route, "_PROBE_ROOT", _ROUTE_ROOTS[route_id]),
        mock.patch.object(v1_route, "_SELECTED_ROUTE", route_id),
    ):
        return v1_route._run_route(tokens, harness, gateway_pid)


def _coherent_case(**kwargs: Any) -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _set_stage("P3_7C_COHERENT_ACTION")
    coherent = _ORIGINAL_COHERENT_CASE(**kwargs)
    _set_stage("ADM_02_" + _SELECTED_ROUTE.rsplit("/", 1)[1].upper().replace("-", "_"))
    gateway_pid = kwargs["stack"]["pids"][combined.p37c._GATEWAY_UNIT]
    _ROUTE_OBSERVATION = {
        **_run_route(_SELECTED_ROUTE, kwargs["tokens"], gateway_pid),
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


def _collect(route_id: str) -> dict[str, Any]:
    global _ROUTE_OBSERVATION, _SELECTED_ROUTE
    _SELECTED_ROUTE = route_id
    _ROUTE_OBSERVATION = None
    if os.environ.get("OPENCLAW_TEST_FAST") is not None:
        raise combined.openclaw.ProbeError("OPENCLAW_TEST_FAST must be absent")
    _set_stage("FINAL_COMBINED_V2")
    with (
        mock.patch.object(combined, "_prepare_gateway", _prepare_gateway),
        mock.patch.object(combined.p37c, "_coherent_case", _coherent_case),
    ):
        composition = combined._collect()
    _expect(_ROUTE_OBSERVATION is not None, "selected route did not execute")
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
        "route_id": route_id,
        "route_observation": _ROUTE_OBSERVATION,
        "composition": composition,
        "source_artifacts": {
            "collector": combined.p37c._file(Path(__file__).resolve()),
            "materializer": combined.p37c._file(
                Path("/src/scripts/materialize_fixed_admission_probes.py")
            ),
            "probe_bundle": _probe_bundle(route_id),
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
        "route_id": _SELECTED_ROUTE,
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
    if len(arguments) != 1 or arguments[0] not in _ROUTES:
        print(
            "usage: runtime_action_worker_final_combined_v2_route_systemd_probe.py ROUTE_ID",
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
    combined.p37c._publish(_OUTPUT, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
