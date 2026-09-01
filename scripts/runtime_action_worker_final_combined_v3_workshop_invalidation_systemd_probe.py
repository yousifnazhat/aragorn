#!/usr/bin/env python3
"""Observe one dedicated workshop-invalidation attempt under V3."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd_probe as proposal

combined = proposal.combined
p37c = proposal.p37c

_INHERITED_HARNESS = proposal._harness
_INHERITED_ARTIFACTS = proposal._artifacts
_INHERITED_HARNESS_SCHEMA = proposal._HARNESS_SCHEMA
_HARNESS = Path("/run/aragorn-harness.json")
_OUTPUT = Path(
    "/evidence/runtime-action-worker-final-combined-v3-workshop-invalidation-systemd.json"
)
_ROUTE = "ADM-02/reload/workshop-invalidation"
_ROUTE_ROOT = Path("/route-input/workshop-invalidation")
_ROUTE_PROBE = _ROUTE_ROOT / "protected-workshop-invalidation-v3-probe.mjs"
_ROUTE_PROPOSAL = _ROUTE_ROOT / "PROPOSAL.md"
_SOURCE_PROBE = (
    Path("/src/benchmark/admission/openclaw-v2026.7.1")
    / "protected-workshop-invalidation-v3-probe.mjs"
)
_MATERIALIZER = Path(
    "/src/scripts/materialize_openclaw_final_v3_workshop_invalidation_probe.py"
)
_PROBE_DIGEST = (
    "sha256:d987ab8e17caa527786486f8440d194bec6e8b441386fd0f85100e3d33459334"
)
_PROPOSAL_DIGEST = proposal._PROPOSAL_DIGEST
_ROUTES = {
    _ROUTE: {
        "files": ("PROPOSAL.md", "protected-workshop-invalidation-v3-probe.mjs"),
        "fixtures": ("PROPOSAL.md",),
        "probe": "protected-workshop-invalidation-v3-probe.mjs",
        "schema": (
            "aragorn/openclaw-protected-workshop-invalidation-observation/v1"
        ),
    }
}
_EXPECTED_BUNDLE = {
    "PROPOSAL.md": {"bytes": 84, "digest": _PROPOSAL_DIGEST, "role": "fixture"},
    "protected-workshop-invalidation-v3-probe.mjs": {
        "bytes": 48_609,
        "digest": _PROBE_DIGEST,
        "role": "probe",
    },
}
_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-"
    "workshop-invalidation-systemd-observation/v1"
)
_HARNESS_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-"
    "workshop-invalidation-systemd-harness/v1"
)
_AUTHORITY = (
    "BOUND_FINAL_COMBINED_V3_RAW_WORKSHOP_INVALIDATION_OBSERVATION_ONLY_"
    "NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_CAPTURE_ATTEMPT_ONLY",
    "DEDICATED_WORKSHOP_INVALIDATION_ROUTE_AND_ACTION_ID_ONLY",
    "PROPOSAL_APPLY_IS_PREREQUISITE_TO_INVALIDATION_OBSERVATION",
    "BLACK_BOX_NEXT_TURN_DERIVATION_NO_DIRECT_INVALIDATION_FUNCTION_TRACE",
    "NO_MODEL_PROVIDER_REQUEST_SUCCESS_OR_DELIVERY_CLAIM",
    "NO_CLEANUP_ROLLBACK_QUARANTINE_OR_GENERAL_ROUTE_CLAIM",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def _route_input_volume_name(
    document: dict[str, Any], source_commit: str
) -> str | None:
    return combined._ephemeral_input_volume_name(
        document,
        source_commit,
        stem="route_input",
        destination="/route-input",
        name_pattern=(
            r"aragorn-phase3-final-combined-v3-workshop-invalidation-"
            r"route-input-([1-9][0-9]*)"
        ),
        role="final-combined-v3-workshop-invalidation-route-input",
    )


def _harness() -> dict[str, Any]:
    retained = p37c._stable_document_snapshot(_HARNESS)
    document = retained["document"]
    proposal.combined._expect(
        document.get("schema") == _HARNESS_SCHEMA
        and document.get("image_reference")
        == "aragorn-phase3-final-combined-v3-workshop-invalidation-systemd"
        and document.get("profile_label")
        == "phase3-final-combined-v3-workshop-invalidation",
        "outer V3 workshop-invalidation harness identity changed",
    )
    normalized = proposal.json.loads(p37c.canonical_json(document))
    normalized["schema"] = proposal._HARNESS_SCHEMA
    normalized["image_reference"] = (
        "aragorn-phase3-final-combined-v3-workshop-proposal-apply-systemd"
    )
    normalized["profile_label"] = (
        "phase3-final-combined-v3-workshop-proposal-apply"
    )
    descriptor, name = tempfile.mkstemp(
        prefix="aragorn-v3-workshop-invalidation-harness-", dir="/run"
    )
    path = Path(name)
    try:
        remaining = memoryview(p37c.canonical_json(normalized))
        while remaining:
            written = os.write(descriptor, remaining)
            proposal.combined._expect(
                written > 0, "normalized invalidation harness write made no progress"
            )
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        with (
            mock.patch.object(proposal, "_HARNESS", path),
            mock.patch.object(
                proposal, "_HARNESS_SCHEMA", _INHERITED_HARNESS_SCHEMA
            ),
            mock.patch.object(
                proposal, "_route_input_volume_name", _route_input_volume_name
            ),
        ):
            base = _INHERITED_HARNESS()
    finally:
        path.unlink(missing_ok=True)
    proposal.combined._expect(
        base["document"] == normalized,
        "normalized V3 workshop-invalidation harness changed",
    )
    return retained


def _artifacts() -> dict[str, Any]:
    # Verify the complete inherited proposal harness against its original
    # immutable transformed sources, then bind the route-specific derivative.
    with (
        mock.patch.object(proposal, "_ROUTE_PROBE", proposal._TRANSFORMED_PROBE),
        mock.patch.object(proposal, "_ROUTE_PROPOSAL", proposal._V2_PROPOSAL),
    ):
        inherited = _INHERITED_ARTIFACTS()
    source = p37c._file(_SOURCE_PROBE)
    runtime = p37c._file(_ROUTE_PROBE)
    proposal_source = p37c._file(_ROUTE_PROPOSAL)
    materializer = p37c._file(_MATERIALIZER)
    collector = p37c._file(Path(__file__).resolve())
    capture_recipe = p37c._file(
        Path(
            "/src/scripts/capture_runtime_action_worker_final_combined_v3_"
            "workshop_invalidation_systemd.sh"
        )
    )
    dockerfile = p37c._file(
        Path(
            "/src/benchmark/runtime-action-worker-final-combined-v3-"
            "workshop-invalidation-systemd/Dockerfile"
        )
    )
    proposal.combined._expect(
        source["bytes"] == runtime["bytes"] == 48_609
        and source["digest"] == runtime["digest"] == _PROBE_DIGEST
        and proposal_source["bytes"] == 84
        and proposal_source["digest"] == _PROPOSAL_DIGEST
        and proposal._custody(source)
        == proposal._custody(runtime)
        == proposal._custody(proposal_source)
        == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0}
        and proposal._custody(materializer)
        == proposal._custody(collector)
        == proposal._custody(capture_recipe)
        == {"gid": 0, "mode": "0555", "nlink": 1, "type": "file", "uid": 0}
        and proposal._custody(dockerfile)
        == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0},
        "V3 workshop-invalidation derivative custody changed",
    )
    return {
        **inherited,
        "final_combined_v3_workshop_invalidation": {
            "collector": {
                "capture_recipe": capture_recipe,
                "dockerfile": dockerfile,
                "probe": collector,
            },
            "inherited_workshop_proposal_apply": inherited[
                "final_combined_v3_workshop_proposal_apply"
            ],
            "materializer": materializer,
            "proposal_fixture": proposal_source,
            "probe": {"materialized_source": source, "runtime": runtime},
        },
    }


def _decision(status: str) -> dict[str, Any]:
    proposal.combined._expect(
        status in {"NOT_TESTED", "OBSERVED"},
        "V3 workshop-invalidation route status changed",
    )
    return {
        "status": (
            "FINAL_COMBINED_V3_WORKSHOP_INVALIDATION_OBSERVED_PROFILE_NOT_TESTED"
            if status == "OBSERVED"
            else (
                "FINAL_COMBINED_V3_WORKSHOP_INVALIDATION_"
                "NOT_TESTED_PROFILE_NOT_TESTED"
            )
        ),
        "route_observation_status": status,
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in sorted(proposal._ELIGIBILITY_KEYS)},
    }


def _collect() -> dict[str, Any]:
    with (
        mock.patch.object(proposal, "_HARNESS", _HARNESS),
        mock.patch.object(proposal, "_OUTPUT", _OUTPUT),
        mock.patch.object(proposal, "_ROUTE", _ROUTE),
        mock.patch.object(proposal, "_ROUTE_ROOT", _ROUTE_ROOT),
        mock.patch.object(proposal, "_ROUTE_PROBE", _ROUTE_PROBE),
        mock.patch.object(proposal, "_ROUTE_PROPOSAL", _ROUTE_PROPOSAL),
        mock.patch.object(proposal, "_ROUTES", _ROUTES),
        mock.patch.object(proposal, "_EXPECTED_BUNDLE", _EXPECTED_BUNDLE),
        mock.patch.object(proposal, "_SCHEMA", _SCHEMA),
        mock.patch.object(proposal, "_HARNESS_SCHEMA", _HARNESS_SCHEMA),
        mock.patch.object(proposal, "_AUTHORITY", _AUTHORITY),
        mock.patch.object(proposal, "_LIMITATIONS", _LIMITATIONS),
        mock.patch.object(proposal, "_harness", _harness),
        mock.patch.object(proposal, "_artifacts", _artifacts),
        mock.patch.object(proposal, "_decision", _decision),
        mock.patch.object(
            proposal, "_route_input_volume_name", _route_input_volume_name
        ),
    ):
        result = proposal._collect()
    inherited_collector = result["source_artifacts"]["collector"]
    result["source_artifacts"].update(
        {
            "collector": p37c._file(Path(__file__).resolve()),
            "dedicated_materializer": p37c._file(_MATERIALIZER),
            "inherited_workshop_proposal_collector": inherited_collector,
            "transformed_probe": p37c._file(_SOURCE_PROBE),
        }
    )
    proposal.combined._expect(
        result["route_id"] == _ROUTE
        and result["route_observation"]["document"]["schema"]
        == _ROUTES[_ROUTE]["schema"]
        and result["route_observation"]["document"]["selected_route_ids"]
        == [_ROUTE]
        and result["route_observation"]["document"]["routes"]
        == [
            {
                "action_id": "workshop-invalidation",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ],
        "V3 workshop-invalidation dedicated route identity changed",
    )
    return result


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": proposal._iso_now(),
        "route_id": _ROUTE,
        "decision": _decision("NOT_TESTED"),
        "failure": {
            "code": "LIVE_CAPTURE_FAILED_CLOSED",
            "stage": proposal._STAGE,
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
            "workshop_invalidation_systemd_probe.py",
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
