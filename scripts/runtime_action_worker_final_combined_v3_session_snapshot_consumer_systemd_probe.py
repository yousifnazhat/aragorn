#!/usr/bin/env python3
"""Observe one native session-snapshot-consumer attempt under the exact V3 stack."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_worker_final_combined_v2_route_systemd_probe as v2_route
import runtime_action_worker_final_combined_v3_fresh_session_reset_systemd_probe as fresh

v3_base = fresh.v3_base
combined = fresh.combined
p37c = fresh.p37c

_HARNESS = Path("/run/aragorn-harness.json")
_OUTPUT = Path(
    "/evidence/runtime-action-worker-final-combined-v3-session-snapshot-consumer-systemd.json"
)
_ADMISSION = Path("/src/benchmark/admission/openclaw-v2026.7.1")
_SOURCE_PROBE = _ADMISSION / "protected-session-snapshot-fixed-probe.mjs"
_SOURCE_HELPER = _ADMISSION / "protected-observation-v1.mjs"
_FIXED_MATERIALIZER = Path("/src/scripts/materialize_fixed_admission_probes.py")
_REBOUND_MATERIALIZER = Path(
    "/src/scripts/materialize_openclaw_final_v3_rebound_probes.py"
)
_ROUTE = "ADM-02/reload/session-snapshot-consumer"
_ROUTE_ROOT = Path("/route-input/session-snapshot-consumer")
_ROUTE_PROBE = _ROUTE_ROOT / "protected-session-snapshot-fixed-probe.mjs"
_ROUTE_HELPER = _ROUTE_ROOT / "protected-observation-v1.mjs"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_FIXED_MATERIALIZER_DIGEST = (
    "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec"
)
_REBOUND_MATERIALIZER_DIGEST = (
    "sha256:8321a6c423b03c283d175185de6886ca12aaa08c244f81b67be3a73a47279a1c"
)
_ROUTES = {
    _ROUTE: {
        "files": (
            "protected-session-snapshot-fixed-probe.mjs",
            "protected-observation-v1.mjs",
        ),
        "probe": "protected-session-snapshot-fixed-probe.mjs",
        "schema": "aragorn/openclaw-protected-session-snapshot-fixed-observation/v1",
    }
}
_ROUTE_ROOTS = {_ROUTE: _ROUTE_ROOT}
_EXPECTED_BUNDLE = {
    "protected-session-snapshot-fixed-probe.mjs": {
        "bytes": 42_266,
        "digest": (
            "sha256:9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11"
        ),
    },
    "protected-observation-v1.mjs": {
        "bytes": 16_324,
        "digest": (
            "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f"
        ),
    },
}
_SOURCE_IDENTITIES = {
    _SOURCE_PROBE: (
        41_345,
        "sha256:1efe13c3beb3ac2ff6fc1293aa64875c95424f1576a10b12943f0b875af223e2",
        "0444",
    ),
    _SOURCE_HELPER: (
        13_609,
        "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b",
        "0444",
    ),
    _FIXED_MATERIALIZER: (87_912, _FIXED_MATERIALIZER_DIGEST, "0555"),
    _REBOUND_MATERIALIZER: (7_691, _REBOUND_MATERIALIZER_DIGEST, "0555"),
    _ROUTE_PROBE: (
        42_266,
        "sha256:9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11",
        "0444",
    ),
    _ROUTE_HELPER: (
        16_324,
        "sha256:672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        "0444",
    ),
}
_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-session-snapshot-consumer-systemd-observation/v1"
)
_HARNESS_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-session-snapshot-consumer-systemd-harness/v1"
)
_AUTHORITY = (
    "BOUND_FINAL_COMBINED_V3_RAW_SESSION_SNAPSHOT_CONSUMER_OBSERVATION_ONLY_"
    "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
    "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "ONLY_SESSION_SNAPSHOT_CONSUMER_ATTEMPT_OBSERVED",
    "NO_SESSION_SNAPSHOT_CONSUMER_CONFORMANCE_OR_PROTECTED_PROMPT_REFRESH_CLAIM",
    "INSTALL_POLICY_PRESENT_AND_CUSTODY_BOUND_BUT_PLUGIN_ONLY_AND_NOT_CAUSAL",
    "NO_GLOBAL_NO_WRITE_CLAIM_CONTROL_PLANE_BUDGET_OR_LOGGING_MAY_CHANGE",
    "SESSION_SNAPSHOT_CONSUMER_ROUTE_SEMANTICS_REQUIRE_INDEPENDENT_VERIFICATION",
    "NO_SESSION_STATE_EQUIVALENCE_CLEANUP_ROLLBACK_OR_CAUSALITY_CLAIM",
    "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
_ELIGIBILITY_KEYS = fresh._ELIGIBILITY_KEYS
_STAGE = "BOOTSTRAP"
_ROUTE_OBSERVATION: dict[str, Any] | None = None


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    combined._expect(condition, message)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _route_input_volume_name(
    document: dict[str, Any], source_commit: str
) -> str | None:
    return combined._ephemeral_input_volume_name(
        document,
        source_commit,
        stem="route_input",
        destination="/route-input",
        name_pattern=(
            r"aragorn-phase3-final-combined-v3-session-snapshot-consumer-"
            r"route-input-([1-9][0-9]*)"
        ),
        role="final-combined-v3-session-snapshot-consumer-route-input",
    )


def _harness() -> dict[str, Any]:
    retained = p37c._stable_document_snapshot(_HARNESS)
    document = retained["document"]
    _expect(
        document.get("schema") == _HARNESS_SCHEMA
        and document.get("image_reference")
        == "aragorn-phase3-final-combined-v3-session-snapshot-consumer-systemd"
        and document.get("profile_label")
        == "phase3-final-combined-v3-session-snapshot-consumer",
        "outer V3 session-snapshot-consumer harness identity changed",
    )
    normalized = json.loads(p37c.canonical_json(document))
    normalized["schema"] = (
        "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
    )
    normalized["image_reference"] = "aragorn-phase3-final-combined-v2-systemd"
    normalized["profile_label"] = "phase3-final-combined-v2"
    descriptor, name = tempfile.mkstemp(
        prefix="aragorn-v3-session-snapshot-consumer-harness-", dir="/run"
    )
    path = Path(name)
    try:
        remaining = memoryview(p37c.canonical_json(normalized))
        while remaining:
            written = os.write(descriptor, remaining)
            _expect(written > 0, "normalized V3 harness write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        with (
            mock.patch.object(combined, "_HARNESS", path),
            mock.patch.object(combined, "_PARENT_IMAGE", _PARENT_IMAGE),
            mock.patch.object(
                combined, "_route_input_volume_name", _route_input_volume_name
            ),
        ):
            base = fresh._ORIGINAL_HARNESS()
    finally:
        path.unlink(missing_ok=True)
    _expect(base["document"] == normalized, "normalized V3 harness changed")
    return retained


def _probe_bundle() -> list[dict[str, Any]]:
    with (
        mock.patch.object(v2_route, "_ROUTES", _ROUTES),
        mock.patch.object(v2_route, "_ROUTE_ROOTS", _ROUTE_ROOTS),
        mock.patch.object(v2_route, "_EXPECTED_PROBES", _EXPECTED_BUNDLE),
    ):
        return v2_route._probe_bundle(_ROUTE)


def _artifacts() -> dict[str, Any]:
    with (
        mock.patch.object(v3_base, "_FORCE_PROBE_SOURCE", _ROUTE_PROBE),
        mock.patch.object(v3_base, "_FORCE_ROUTE", _ROUTE),
        mock.patch.object(v3_base, "_ROUTE_ROOT", _ROUTE_ROOT),
        mock.patch.object(v3_base, "_ROUTES", _ROUTES),
    ):
        artifacts = v3_base._artifacts()

    records = {path: p37c._file(path) for path in _SOURCE_IDENTITIES}
    for path, (
        expected_bytes,
        expected_digest,
        expected_mode,
    ) in _SOURCE_IDENTITIES.items():
        record = records[path]
        _expect(
            record["bytes"] == expected_bytes
            and record["digest"] == expected_digest
            and fresh._custody(record)
            == {
                "gid": 0,
                "mode": expected_mode,
                "nlink": 1,
                "type": "file",
                "uid": 0,
            },
            f"V3 session-snapshot-consumer source/runtime custody changed: {path}",
        )

    common = artifacts.pop("final_combined_v3_plugin_force_reinstall")
    common.pop("force_probe")
    common["session_snapshot_consumer_probe"] = {
        "checked_in_probe": records[_SOURCE_PROBE],
        "checked_in_observation_helper": records[_SOURCE_HELPER],
        "fixed_materializer": records[_FIXED_MATERIALIZER],
        "rebound_materializer": records[_REBOUND_MATERIALIZER],
        "runtime_probe": records[_ROUTE_PROBE],
        "runtime_observation_helper": records[_ROUTE_HELPER],
        "probe_bundle": _probe_bundle(),
    }
    common["collector"] = {
        "capture_recipe": p37c._file(
            Path(
                "/src/scripts/capture_runtime_action_worker_final_combined_"
                "v3_session_snapshot_consumer_systemd.sh"
            )
        ),
        "dockerfile": p37c._file(
            Path(
                "/src/benchmark/runtime-action-worker-final-combined-v3-"
                "session-snapshot-consumer-systemd/Dockerfile"
            )
        ),
        "probe": p37c._file(Path(__file__).resolve()),
        "inherited_v3_stack_helper": p37c._file(Path(fresh.__file__).resolve()),
        "inherited_v3_contract_base": p37c._file(Path(v3_base.__file__).resolve()),
        "inherited_v2_route_injector": p37c._file(Path(v2_route.__file__).resolve()),
    }
    artifacts["final_combined_v3_session_snapshot_consumer"] = common
    return artifacts


def _run_route(tokens: dict[str, str], gateway_pid: int) -> dict[str, Any]:
    with (
        mock.patch.object(v2_route, "_ROUTES", _ROUTES),
        mock.patch.object(v2_route, "_ROUTE_ROOTS", _ROUTE_ROOTS),
        mock.patch.object(v2_route, "_EXPECTED_PROBES", _EXPECTED_BUNDLE),
        mock.patch.object(v2_route, "_SELECTED_ROUTE", _ROUTE),
    ):
        return v2_route._run_route(_ROUTE, tokens, gateway_pid)


def _coherent_case(**kwargs: Any) -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _set_stage("P3_7C_COHERENT_ACTION")
    coherent = fresh._ORIGINAL_COHERENT_CASE(**kwargs)
    _set_stage("ADM_02_SESSION_SNAPSHOT_CONSUMER_ACTIVATION")
    gateway_pid = kwargs["stack"]["pids"][p37c._GATEWAY_UNIT]
    _ROUTE_OBSERVATION = {
        **_run_route(kwargs["tokens"], gateway_pid),
        "gateway_pid_binding": {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{gateway_pid}/ns/mnt",
            "pid": gateway_pid,
            "unit": p37c._GATEWAY_UNIT,
        },
        "stack_before": kwargs["stack"],
    }
    return coherent


def _decision(status: str) -> dict[str, Any]:
    _expect(
        status in {"NOT_TESTED", "OBSERVED"},
        "V3 session-snapshot-consumer status changed",
    )
    return {
        "status": (
            "FINAL_COMBINED_V3_SESSION_SNAPSHOT_CONSUMER_OBSERVED_PROFILE_NOT_TESTED"
            if status == "OBSERVED"
            else "FINAL_COMBINED_V3_SESSION_SNAPSHOT_CONSUMER_NOT_TESTED_PROFILE_NOT_TESTED"
        ),
        "route_observation_status": status,
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in sorted(_ELIGIBILITY_KEYS)},
    }


def _collect() -> dict[str, Any]:
    global _ROUTE_OBSERVATION
    _ROUTE_OBSERVATION = None
    if os.environ.get("OPENCLAW_TEST_FAST") is not None:
        raise combined.openclaw.ProbeError("OPENCLAW_TEST_FAST must be absent")
    _set_stage("FINAL_COMBINED_V3")
    with (
        mock.patch.object(combined, "_HARNESS", _HARNESS),
        mock.patch.object(combined, "_CONFIG", v3_base._CONFIG),
        mock.patch.object(combined, "_PROFILE", v3_base._PROFILE),
        mock.patch.object(combined, "_LOCK", v3_base._LOCK),
        mock.patch.object(combined, "_PARENT_IMAGE", _PARENT_IMAGE),
        mock.patch.object(combined, "_CONFIG_DIGEST", v3_base._CONFIG_DIGEST),
        mock.patch.object(combined, "_PROFILE_DIGEST", v3_base._PROFILE_DIGEST),
        mock.patch.object(combined, "_LOCK_DIGEST", v3_base._LOCK_DIGEST),
        mock.patch.object(combined, "_ACTIVATOR_DIGEST", v3_base._ACTIVATOR_DIGEST),
        mock.patch.object(combined, "_SCHEMA", _SCHEMA),
        mock.patch.object(combined, "_AUTHORITY", _AUTHORITY),
        mock.patch.object(combined, "_LIMITATIONS", _LIMITATIONS),
        mock.patch.object(combined, "_harness", _harness),
        mock.patch.object(combined, "_profile_snapshot", v3_base._profile_snapshot),
        mock.patch.object(combined, "_artifacts", _artifacts),
        mock.patch.object(combined, "_prepare_gateway", fresh._prepare_gateway),
        mock.patch.object(
            combined, "_observation_decision", fresh._observation_decision
        ),
        mock.patch.object(combined, "_set_stage", _set_stage),
        mock.patch.object(p37c, "_INSTALLED", v3_base._v3_installed()),
        mock.patch.object(p37c, "_coherent_case", _coherent_case),
    ):
        composition = combined._collect()
    _expect(
        _ROUTE_OBSERVATION is not None,
        "V3 session-snapshot-consumer route did not execute",
    )
    status = _ROUTE_OBSERVATION["route"]["status"]
    decision = composition["decision"]
    _expect(
        decision["status"] == "FINAL_COMBINED_V3_ACTION_OBSERVED_PROFILE_NOT_TESTED"
        and decision["route_pass_count"] == 0
        and decision["route_fail_count"] == 0
        and decision["route_not_tested_count"] == 21
        and all(decision[key] is False for key in _ELIGIBILITY_KEYS),
        "V3 session-snapshot-consumer composition claim ceiling changed",
    )
    _set_stage("OBSERVATION_ASSEMBLY")
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": _iso_now(),
        "route_id": _ROUTE,
        "route_observation": _ROUTE_OBSERVATION,
        "composition": composition,
        "harness": _harness(),
        "source_artifacts": {
            "collector": p37c._file(Path(__file__).resolve()),
            "checked_in_probe": p37c._file(_SOURCE_PROBE),
            "checked_in_observation_helper": p37c._file(_SOURCE_HELPER),
            "fixed_materializer": p37c._file(_FIXED_MATERIALIZER),
            "rebound_materializer": p37c._file(_REBOUND_MATERIALIZER),
            "probe_bundle": _probe_bundle(),
            "inherited_v3_stack_helper": p37c._file(Path(fresh.__file__).resolve()),
            "inherited_v3_contract_base": p37c._file(Path(v3_base.__file__).resolve()),
            "inherited_v2_route_injector": p37c._file(
                Path(v2_route.__file__).resolve()
            ),
        },
        "decision": _decision(status),
        "limitations": _LIMITATIONS,
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
            "usage: runtime_action_worker_final_combined_v3_"
            "session_snapshot_consumer_systemd_probe.py",
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
