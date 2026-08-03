"""Strict standalone contract for the Phase 2 two-scenario matrix."""

from __future__ import annotations

import re
from typing import Any

CATALOG_SCHEMA = "aragorn/phase2-matrix-catalog/v2"
COVERAGE_LOCK_SCHEMA = "aragorn/benchmark-phase2-coverage-lock/v2"
CATALOG_ASSURANCE = "operator_authored_inert_plumbing_not_independent_efficacy"
COVERAGE_LOCK_ASSURANCE = (
    "operator_asserted_pre_outcome_scenario_binding_not_independent_or_timestamped"
)
PUBLIC_FIXTURE_COMMIT = "94dba7fa420b0a202e92f574da97ddedf9a0e86c"
SCENARIO_PROFILE = "two-scenario-path-surface/v1"
SCENARIO_ENVIRONMENT_VARIABLE = "ARAGORN_SCENARIO"
RUN_SCHEDULE = ("primary", "alternate", "primary", "alternate", "primary")

_SOURCE = {
    "owner": "yousifnazhat",
    "repository": "agent-skill-inert-fixture",
    "commit": PUBLIC_FIXTURE_COMMIT,
    "case_root": "cases",
}
_CANDIDATE_CONFIG = {
    "evaluation_split": "held_out",
    "runs_per_case": 5,
    "verdict_profile": "undeclared-observed-review/v1",
    "gvisor_receipt_schema": "aragorn/gvisor-acquired-artifact-receipt/v5",
    "normalization_profile": "successful-openat-execve-attributed/v1",
    "execution_profile": "bounded-single-script/v2",
    "entrypoint_path": "run.sh",
}
_GVISOR_FIELDS = {
    "receipt_schema",
    "normalization_profile",
    "execution_profile",
    "lock_digest",
    "verifier_implementation_digest",
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")


class Phase2ScenarioContractError(ValueError):
    """A varied-scenario document does not match the fixed v2 contract."""


def scenario_for_run(run_id: object) -> str:
    """Return the caller-pinned scenario for one one-based benchmark run."""

    if type(run_id) is not int or not 1 <= run_id <= len(RUN_SCHEDULE):
        raise Phase2ScenarioContractError(
            "scenario run_id must be an integer from 1 to 5"
        )
    return RUN_SCHEDULE[run_id - 1]


def validate_phase2_scenario_catalog(document: object) -> tuple[str, ...]:
    """Validate the scenario-specific surface of one v2 matrix catalog."""

    value = _document(
        document,
        expected_schema=CATALOG_SCHEMA,
        expected_assurance=CATALOG_ASSURANCE,
        expected_fields={
            "schema",
            "assurance",
            "source",
            "candidate",
            "scenario_matrix",
            "cases",
        },
        label="Phase 2 scenario catalog",
    )
    if value["source"] != _SOURCE:
        raise Phase2ScenarioContractError(
            "Phase 2 scenario catalog source pin changed"
        )
    candidate = _object(
        value["candidate"],
        {"name", "version", "config"},
        "Phase 2 scenario catalog candidate",
    )
    version = candidate["version"]
    if (
        candidate["name"] != "aragorn"
        or not isinstance(version, str)
        or not version
        or version != version.strip()
        or "\r" in version
        or "\n" in version
        or len(version) > 256
        or candidate["config"] != _CANDIDATE_CONFIG
    ):
        raise Phase2ScenarioContractError(
            "Phase 2 scenario catalog candidate profile changed"
        )
    _scenario_matrix(value["scenario_matrix"])
    _case_ids(value["cases"], "Phase 2 scenario catalog")
    return RUN_SCHEDULE


def validate_phase2_scenario_coverage_lock(document: object) -> tuple[str, ...]:
    """Validate the scenario-specific surface of one v2 coverage lock."""

    value = _document(
        document,
        expected_schema=COVERAGE_LOCK_SCHEMA,
        expected_assurance=COVERAGE_LOCK_ASSURANCE,
        expected_fields={
            "schema",
            "assurance",
            "suite_digest",
            "evaluation_split",
            "runs_per_case",
            "candidate_system",
            "verdict_profile",
            "gvisor",
            "scenario_matrix",
            "cases",
        },
        label="Phase 2 scenario coverage lock",
    )
    if (
        value["evaluation_split"] != "held_out"
        or value["runs_per_case"] != 5
        or value["verdict_profile"] != "undeclared-observed-review/v1"
        or not _is_digest(value["suite_digest"])
    ):
        raise Phase2ScenarioContractError(
            "Phase 2 scenario coverage profile changed"
        )
    gvisor = _object(
        value["gvisor"], _GVISOR_FIELDS, "Phase 2 scenario coverage gVisor"
    )
    if (
        gvisor["receipt_schema"] != "aragorn/gvisor-acquired-artifact-receipt/v5"
        or gvisor["normalization_profile"]
        != "successful-openat-execve-attributed/v1"
        or gvisor["execution_profile"] != "bounded-single-script/v2"
        or any(
            not _is_digest(gvisor[field])
            for field in ("lock_digest", "verifier_implementation_digest")
        )
    ):
        raise Phase2ScenarioContractError(
            "Phase 2 scenario coverage gVisor profile changed"
        )
    _scenario_matrix(value["scenario_matrix"])
    _case_ids(value["cases"], "Phase 2 scenario coverage lock")
    return RUN_SCHEDULE


def _document(
    value: object,
    *,
    expected_schema: str,
    expected_assurance: str,
    expected_fields: set[str],
    label: str,
) -> dict[str, Any]:
    document = _object(value, expected_fields, label)
    if (
        document["schema"] != expected_schema
        or document["assurance"] != expected_assurance
    ):
        raise Phase2ScenarioContractError(f"{label} authority is unsupported")
    return document


def _scenario_matrix(value: object) -> None:
    if value != {
        "profile": SCENARIO_PROFILE,
        "environment_variable": SCENARIO_ENVIRONMENT_VARIABLE,
        "run_schedule": list(RUN_SCHEDULE),
    }:
        raise Phase2ScenarioContractError("Phase 2 scenario matrix changed")


def _case_ids(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) != 20:
        raise Phase2ScenarioContractError(f"{label} must contain exactly 20 cases")
    case_ids: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise Phase2ScenarioContractError(f"{label}.cases[{index}] is invalid")
        case_id = item.get("case_id")
        if not isinstance(case_id, str) or _IDENTIFIER.fullmatch(case_id) is None:
            raise Phase2ScenarioContractError(
                f"{label}.cases[{index}].case_id is invalid"
            )
        case_ids.append(case_id)
    if case_ids != sorted(set(case_ids)):
        raise Phase2ScenarioContractError(
            f"{label} case IDs must be unique and sorted"
        )
    return tuple(case_ids)


def _object(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise Phase2ScenarioContractError(f"{label} fields changed")
    return value


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None
