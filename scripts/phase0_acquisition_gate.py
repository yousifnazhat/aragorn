"""Freeze and evaluate the paired Phase 0 acquisition/reference stratum."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from fractions import Fraction
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aragorn.benchmark import (
    BenchmarkError,
    _PHASE0_BENIGN_BURDEN_CEILING,
    _PHASE0_MINIMUM_ATTACK_FLAG_DELTA,
    _canonical_json_bytes,
    _decode_json,
    _decode_json_lines,
    _digest,
    _digest_json,
    _exact_keys,
    _identifier,
    _load_phase0_expansion,
    _read_phase0_cas_json,
    _phase0_comparison_points,
    _phase0_fraction_report,
    _phase0_point_report,
    _read_bounded,
    _system_key,
    _validate_phase0_accounting,
    _validate_phase0_expected_references,
    _validate_phase0_expansion_source,
    _validate_system,
    evaluate_files,
    evaluate_phase0_files,
    load_suite_for_run,
)
from aragorn.cas import CAS, CASError
from aragorn.phase0_candidate import (
    CandidateError,
    build_candidate_policy,
    candidate_policy_digest,
    candidate_system_identity,
)

ORACLE_SCHEMA = "aragorn/benchmark-phase0-acquisition-oracle/v1"
LOCK_SCHEMA = "aragorn/benchmark-phase0-acquisition-oracle-lock/v1"
REPORT_SCHEMA = "aragorn/benchmark-phase0-acquisition-gate-report/v1"
LOCK_ASSURANCE = (
    "operator_asserted_pre_outcome_binding_not_independent_or_timestamped"
)
REPORT_ASSURANCE = "paired_evidence_metrics_only"
EXPANSION_PROFILE = "phase0-exact-github-blob-expansion/v1"
_BUDGET_NAMES = {
    "api_requests",
    "api_bytes",
    "retained_bytes",
    "expanded_objects",
    "expansion_depth",
    "references",
}
_CASE_COUNT = 448
_CLASS_COUNTS = {"adversarial": 112, "benign": 336}
_RUNS_PER_CASE = 1


class AcquisitionGateError(ValueError):
    """The paired acquisition/reference contract is invalid."""


def _json_file(path: str | Path, label: str, *, canonical: bool) -> object:
    raw = _read_bounded(Path(path))
    document = _decode_json(raw, label)
    if canonical and _canonical_json_bytes(document) != raw:
        raise AcquisitionGateError(f"{label} must use canonical JSON")
    return document


def _policy(path: str | Path) -> dict[str, Any]:
    document = build_candidate_policy(
        _json_file(path, "candidate policy", canonical=False)
    )
    return {
        "document": document,
        "digest": candidate_policy_digest(document),
        "candidate": candidate_system_identity(document),
        "comparators": list(document["required_comparators"]),
    }


def _suite(path: str | Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aragorn-acquisition-suite-") as temporary:
        return load_suite_for_run(
            path,
            CAS(Path(temporary) / "cas"),
            required_purpose="evidence_smoke",
        )


def _count(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = (1 << 63) - 1,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise AcquisitionGateError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _budgets(value: object, label: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise AcquisitionGateError(f"{label} must be a JSON object")
    _exact_keys(value, _BUDGET_NAMES, label)
    return {
        name: _count(
            value[name],
            f"{label}.{name}",
            minimum=0 if name in {"expanded_objects", "expansion_depth"} else 1,
        )
        for name in sorted(_BUDGET_NAMES)
    }


def _oracle(value: object, policy: dict[str, Any]) -> dict[str, Any]:
    label = "acquisition oracle"
    if not isinstance(value, dict):
        raise AcquisitionGateError(f"{label} must be a JSON object")
    _exact_keys(
        value,
        {
            "schema",
            "root_suite_digest",
            "expanded_suite_digest",
            "split",
            "runs_per_case",
            "candidate_system",
            "comparators",
            "expansion_profile",
            "budgets",
            "cases",
        },
        label,
    )
    if value["schema"] != ORACLE_SCHEMA:
        raise AcquisitionGateError("unsupported acquisition oracle schema")
    if value["split"] != "held_out":
        raise AcquisitionGateError("acquisition oracle split must be held_out")
    if value["expansion_profile"] != EXPANSION_PROFILE:
        raise AcquisitionGateError("unsupported acquisition expansion profile")
    candidate = _validate_system(value["candidate_system"], f"{label}.candidate_system")
    if candidate != policy["candidate"]:
        raise AcquisitionGateError("acquisition oracle candidate policy changed")
    raw_comparators = value["comparators"]
    if not isinstance(raw_comparators, list):
        raise AcquisitionGateError("acquisition oracle comparators must be an array")
    comparators = [
        _validate_system(item, f"{label}.comparators[{index}]")
        for index, item in enumerate(raw_comparators)
    ]
    if comparators != policy["comparators"]:
        raise AcquisitionGateError("acquisition oracle comparator policies changed")
    raw_cases = value["cases"]
    if not isinstance(raw_cases, list) or len(raw_cases) != _CASE_COUNT:
        raise AcquisitionGateError(
            f"acquisition oracle must contain exactly {_CASE_COUNT} cases"
        )
    cases: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_cases):
        case_label = f"{label}.cases[{index}]"
        if not isinstance(raw, dict):
            raise AcquisitionGateError(f"{case_label} must be a JSON object")
        _exact_keys(
            raw,
            {
                "case_id",
                "class",
                "family",
                "lineage",
                "root_tree_digest",
                "expanded_tree_digest",
                "source",
                "expected_references",
            },
            case_label,
        )
        case_id = _identifier(raw["case_id"], f"{case_label}.case_id")
        if case_id in cases:
            raise AcquisitionGateError(f"duplicate acquisition oracle case: {case_id}")
        case_class = raw["class"]
        if case_class not in {"benign", "adversarial"}:
            raise AcquisitionGateError(f"{case_label}.class is unsupported")
        family = _identifier(raw["family"], f"{case_label}.family")
        if (case_class == "benign") != (family == "benign"):
            raise AcquisitionGateError(f"{case_label} class and family disagree")
        references = _validate_phase0_expected_references(
            raw["expected_references"], f"{case_label}.expected_references"
        )
        if not references:
            raise AcquisitionGateError(
                f"{case_label}.expected_references must not be empty"
            )
        root_tree_digest = _digest(
            raw["root_tree_digest"], f"{case_label}.root_tree_digest"
        )
        expanded_tree_digest = _digest(
            raw["expanded_tree_digest"], f"{case_label}.expanded_tree_digest"
        )
        if root_tree_digest == expanded_tree_digest:
            raise AcquisitionGateError(
                f"{case_label} root and expanded trees must differ"
            )
        cases[case_id] = {
            "case_id": case_id,
            "class": case_class,
            "family": family,
            "lineage": _identifier(raw["lineage"], f"{case_label}.lineage"),
            "root_tree_digest": root_tree_digest,
            "expanded_tree_digest": expanded_tree_digest,
            "source": _validate_phase0_expansion_source(
                raw["source"], f"{case_label}.source"
            ),
            "expected_references": references,
        }
    class_counts = {
        name: sum(item["class"] == name for item in cases.values())
        for name in _CLASS_COUNTS
    }
    if class_counts != _CLASS_COUNTS:
        raise AcquisitionGateError(
            "acquisition oracle class accounting must be 336 benign and "
            "112 adversarial cases"
        )
    if len({item["lineage"] for item in cases.values()}) != _CASE_COUNT:
        raise AcquisitionGateError("acquisition oracle lineages must be unique")
    for field in ("root_tree_digest", "expanded_tree_digest"):
        if len({item[field] for item in cases.values()}) != _CASE_COUNT:
            raise AcquisitionGateError(
                f"acquisition oracle {field} values must be unique"
            )
    if (
        len({_digest_json(item["source"]) for item in cases.values()})
        != _CASE_COUNT
    ):
        raise AcquisitionGateError(
            "acquisition oracle GitHub source identities must be unique"
        )
    return {
        "schema": ORACLE_SCHEMA,
        "root_suite_digest": _digest(
            value["root_suite_digest"], f"{label}.root_suite_digest"
        ),
        "expanded_suite_digest": _digest(
            value["expanded_suite_digest"], f"{label}.expanded_suite_digest"
        ),
        "split": "held_out",
        "runs_per_case": _count(
            value["runs_per_case"],
            f"{label}.runs_per_case",
            minimum=_RUNS_PER_CASE,
            maximum=_RUNS_PER_CASE,
        ),
        "candidate_system": candidate,
        "comparators": comparators,
        "expansion_profile": EXPANSION_PROFILE,
        "budgets": _budgets(value["budgets"], f"{label}.budgets"),
        "cases": [cases[case_id] for case_id in sorted(cases)],
    }


def _sorted_systems(suite: dict[str, Any]) -> list[dict[str, str]]:
    return sorted(suite["systems"].values(), key=_system_key)


def _pair_suites(
    oracle: dict[str, Any],
    root: dict[str, Any],
    expanded: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    if root["digest"] != oracle["root_suite_digest"]:
        raise AcquisitionGateError("root suite digest does not match the oracle")
    if expanded["digest"] != oracle["expanded_suite_digest"]:
        raise AcquisitionGateError("expanded suite digest does not match the oracle")
    if root["runs_per_case"] != oracle["runs_per_case"] or expanded[
        "runs_per_case"
    ] != oracle["runs_per_case"]:
        raise AcquisitionGateError("acquisition suite run accounting changed")
    if _sorted_systems(root) != sorted(policy["comparators"], key=_system_key):
        raise AcquisitionGateError("root arm must contain only the frozen comparators")
    if _sorted_systems(expanded) != sorted(
        [policy["candidate"], *policy["comparators"]], key=_system_key
    ):
        raise AcquisitionGateError(
            "expanded arm must contain the frozen candidate and comparators"
        )
    oracle_cases = {item["case_id"]: item for item in oracle["cases"]}
    if set(root["cases"]) != set(oracle_cases) or set(expanded["cases"]) != set(
        oracle_cases
    ):
        raise AcquisitionGateError("acquisition arm case pairing is incomplete")
    for case_id, expected in oracle_cases.items():
        root_case = root["cases"][case_id]
        expanded_case = expanded["cases"][case_id]
        if root_case["split"] != "held_out" or expanded_case["split"] != "held_out":
            raise AcquisitionGateError("acquisition arm cases must be held_out")
        for field in ("class", "family", "lineage"):
            if (
                root_case[field] != expanded_case[field]
                or root_case[field] != expected[field]
            ):
                raise AcquisitionGateError(
                    f"acquisition case {case_id} changed {field} between arms"
                )
        if root_case["source"] != expanded_case["source"]:
            raise AcquisitionGateError(
                f"acquisition case {case_id} changed source provenance between arms"
            )
        expected_source_reference = (
            "phase0-github-source:" + _digest_json(expected["source"])
        )
        if root_case["source"].get("reference") != expected_source_reference:
            raise AcquisitionGateError(
                f"acquisition case {case_id} suite source is not bound "
                "to the oracle GitHub source"
            )
        if root_case["tree_digest"] != expected["root_tree_digest"]:
            raise AcquisitionGateError(
                f"acquisition case {case_id} root tree changed"
            )
        if expanded_case["tree_digest"] != expected["expanded_tree_digest"]:
            raise AcquisitionGateError(
                f"acquisition case {case_id} expanded tree changed"
            )


def build_lock(
    oracle: object,
    root_suite: dict[str, Any],
    expanded_suite: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    canonical_oracle = _oracle(oracle, policy)
    _pair_suites(canonical_oracle, root_suite, expanded_suite, policy)
    class_counts = {
        name: sum(item["class"] == name for item in canonical_oracle["cases"])
        for name in ("adversarial", "benign")
    }
    family_counts: dict[str, int] = {}
    for item in canonical_oracle["cases"]:
        family = item["family"]
        family_counts[family] = family_counts.get(family, 0) + 1
    return {
        "schema": LOCK_SCHEMA,
        "assurance": LOCK_ASSURANCE,
        "oracle_digest": _digest_json(canonical_oracle),
        "candidate_policy_digest": policy["digest"],
        "root_suite_digest": root_suite["digest"],
        "expanded_suite_digest": expanded_suite["digest"],
        "split": "held_out",
        "case_count": len(canonical_oracle["cases"]),
        "class_counts": class_counts,
        "family_counts": {
            family: family_counts[family] for family in sorted(family_counts)
        },
        "lineage_count": len(
            {item["lineage"] for item in canonical_oracle["cases"]}
        ),
        "runs_per_case": canonical_oracle["runs_per_case"],
        "candidate_system": policy["candidate"],
        "comparators": policy["comparators"],
        "expansion_profile": EXPANSION_PROFILE,
        "budgets": canonical_oracle["budgets"],
    }


def freeze_files(
    oracle_path: str | Path,
    root_suite_path: str | Path,
    expanded_suite_path: str | Path,
    *,
    candidate_policy_path: str | Path,
) -> dict[str, Any]:
    policy = _policy(candidate_policy_path)
    oracle = _json_file(oracle_path, "acquisition oracle", canonical=True)
    return build_lock(
        oracle,
        _suite(root_suite_path),
        _suite(expanded_suite_path),
        policy,
    )


def _fraction(value: object, label: str) -> Fraction:
    if not isinstance(value, dict):
        raise AcquisitionGateError(f"{label} must be a fraction report")
    _exact_keys(value, {"numerator", "denominator", "rate"}, label)
    numerator = _count(value["numerator"], f"{label}.numerator")
    denominator = _count(value["denominator"], f"{label}.denominator", minimum=1)
    result = Fraction(numerator, denominator)
    if value["rate"] != round(float(result), 6):
        raise AcquisitionGateError(f"{label}.rate is inconsistent")
    return result


def _comparison(
    root_report: dict[str, Any],
    expanded_report: dict[str, Any],
    *,
    candidate_system: dict[str, str],
) -> dict[str, Any]:
    (
        _root_candidate,
        comparator_points,
        frontier,
        selected,
        held_out_missing,
    ) = _phase0_comparison_points(
        root_report,
        candidate=candidate_system,
        evaluation_split="held_out",
    )
    candidate = expanded_report["comparison"]["candidate"]
    if candidate is None:
        raise AcquisitionGateError("expanded arm omitted the Aragorn candidate")
    candidate_burden = _fraction(
        candidate["benign_intervention"], "expanded candidate benign intervention"
    )
    candidate_attack = _fraction(
        candidate["adversarial_flag"], "expanded candidate adversarial flag"
    )
    if candidate["system"] != candidate_system:
        raise AcquisitionGateError("expanded candidate identity changed")
    if candidate["burden_compliant"] != (
        candidate_burden <= _PHASE0_BENIGN_BURDEN_CEILING
    ):
        raise AcquisitionGateError("expanded candidate burden accounting changed")
    reasons = []
    delta: Fraction | None = None
    accounting = expanded_report["accounting"]
    if held_out_missing:
        reasons.append("NO_HELD_OUT_SPLIT")
    if accounting["expected_references"] == 0:
        reasons.append("NO_EXPECTED_SOURCE_REFERENCES")
    if accounting["incomplete_cases"]:
        reasons.append("HELD_OUT_EXPANSION_INCOMPLETE")
    if candidate_burden > _PHASE0_BENIGN_BURDEN_CEILING:
        reasons.append("CANDIDATE_BURDEN_CEILING_EXCEEDED")
    if selected is None:
        reasons.append("NO_BURDEN_COMPLIANT_COMPARATOR")
    else:
        delta = candidate_attack - selected["attack"]
        if delta < _PHASE0_MINIMUM_ATTACK_FLAG_DELTA:
            reasons.append("ATTACK_FLAG_DELTA_BELOW_10PP")
    return {
        "benign_burden_ceiling": _phase0_fraction_report(
            _PHASE0_BENIGN_BURDEN_CEILING
        ),
        "minimum_attack_flag_delta": _phase0_fraction_report(
            _PHASE0_MINIMUM_ATTACK_FLAG_DELTA
        ),
        "candidate": candidate,
        "comparators": [
            _phase0_point_report(point)
            for point in sorted(
                comparator_points, key=lambda item: _system_key(item["system"])
            )
        ],
        "pareto_frontier": [
            _phase0_point_report(point)
            for point in sorted(frontier, key=lambda item: _system_key(item["system"]))
        ],
        "selected_comparator": (
            _phase0_point_report(selected) if selected is not None else None
        ),
        "attack_flag_delta": (
            _phase0_fraction_report(delta) if delta is not None else None
        ),
        "evaluable": not any(
            reason
            in {
                "NO_HELD_OUT_SPLIT",
                "NO_EXPECTED_SOURCE_REFERENCES",
                "NO_BURDEN_COMPLIANT_COMPARATOR",
            }
            for reason in reasons
        ),
        "passed": not reasons,
        "reason_codes": sorted(reasons),
    }


def evaluate_pair(
    *,
    oracle: object,
    lock: object,
    root_suite: dict[str, Any],
    expanded_suite: dict[str, Any],
    policy: dict[str, Any],
    accounting: object,
    expansion_records: dict[str, dict[str, Any]],
    root_report: dict[str, Any],
    expanded_report: dict[str, Any],
) -> dict[str, Any]:
    canonical_oracle = _oracle(oracle, policy)
    expected_lock = build_lock(
        canonical_oracle, root_suite, expanded_suite, policy
    )
    if lock != expected_lock:
        raise AcquisitionGateError(
            "acquisition oracle lock does not match the frozen inputs"
        )
    candidate, plans, canonical_accounting = _validate_phase0_accounting(
        accounting,
        suite_digest=expanded_suite["digest"],
        cases=expanded_suite["cases"],
        systems=expanded_suite["systems"],
    )
    if candidate != policy["candidate"]:
        raise AcquisitionGateError("acquisition accounting candidate changed")
    oracle_cases = {item["case_id"]: item for item in canonical_oracle["cases"]}
    if set(expansion_records) != set(oracle_cases):
        raise AcquisitionGateError("acquisition expansion pairing is incomplete")
    for case_id, expected in oracle_cases.items():
        if plans[case_id]["expected_references"] != expected["expected_references"]:
            raise AcquisitionGateError(
                f"acquisition case {case_id} oracle references changed"
            )
        record = expansion_records[case_id]
        if record["source"] != expected["source"]:
            raise AcquisitionGateError(
                f"acquisition case {case_id} source changed"
            )
        if record["root_tree_digest"] != expected["root_tree_digest"]:
            raise AcquisitionGateError(
                f"acquisition case {case_id} root expansion tree changed"
            )
        if (
            record["closure"]["status"] == "complete"
            and record["comparator_subject_tree_digest"]
            != expected["expanded_tree_digest"]
        ):
            raise AcquisitionGateError(
                f"acquisition case {case_id} expanded subject tree changed"
            )
        if record["closure"]["status"] != "complete":
            raise AcquisitionGateError(
                f"acquisition case {case_id} expansion is incomplete"
            )
        if not any(
            reference.get("status") == "expanded"
            and all(
                reference.get(field) == expected_reference[field]
                for field in (
                    "source_commit",
                    "source_repository_path",
                    "source_blob_digest",
                    "byte_offset",
                    "literal_size",
                    "literal_digest",
                    "target_commit",
                    "target_repository_path",
                )
            )
            and record["_target_digests"].get(
                (
                    expected_reference["target_commit"],
                    expected_reference["target_repository_path"],
                )
            )
            == expected_reference["target_digest"]
            and any(
                item.get("commit") == expected_reference["target_commit"]
                and item.get("repository_path")
                == expected_reference["target_repository_path"]
                and item.get("digest") == expected_reference["target_digest"]
                for item in record["objects"]
            )
            for expected_reference in expected["expected_references"]
            for reference in record["references"]
        ):
            raise AcquisitionGateError(
                f"acquisition case {case_id} has no retained expected expansion"
            )
        limits = {
            name: record["accounting"]["budgets"][name]["limit"]
            for name in _BUDGET_NAMES
        }
        if limits != canonical_oracle["budgets"]:
            raise AcquisitionGateError(
                f"acquisition case {case_id} resource budgets changed"
            )
    if root_report["suite_digest"] != root_suite["digest"]:
        raise AcquisitionGateError("root report suite binding changed")
    if expanded_report["suite_digest"] != expanded_suite["digest"]:
        raise AcquisitionGateError("expanded report suite binding changed")
    if expanded_report["accounting_digest"] != _digest_json(canonical_accounting):
        raise AcquisitionGateError("expanded accounting digest changed")
    comparison = _comparison(
        root_report,
        expanded_report,
        candidate_system=policy["candidate"],
    )
    return {
        "schema": REPORT_SCHEMA,
        "assurance": REPORT_ASSURANCE,
        "oracle_lock_digest": _digest_json(expected_lock),
        "oracle_digest": expected_lock["oracle_digest"],
        "candidate_policy_digest": policy["digest"],
        "root_arm": {
            "suite_digest": root_report["suite_digest"],
            "outcomes_digest": root_report["outcomes_digest"],
            "benchmark_report_digest": _digest_json(root_report),
        },
        "expanded_arm": {
            "suite_digest": expanded_report["suite_digest"],
            "outcomes_digest": expanded_report["outcomes_digest"],
            "benchmark_report_digest": expanded_report["benchmark_report_digest"],
            "accounting_digest": expanded_report["accounting_digest"],
        },
        "evaluation_split": "held_out",
        "accounting": expanded_report["accounting"],
        "comparison": comparison,
    }


def _require_authenticated_arm_evidence(
    outcome_path: str | Path,
    cas: CAS,
    *,
    candidate_system: dict[str, str],
    expanded: bool,
) -> None:
    outcomes = _decode_json_lines(_read_bounded(Path(outcome_path)))
    for index, raw in enumerate(outcomes):
        label = (
            f"{'expanded' if expanded else 'root'} acquisition "
            f"outcomes[{index}]"
        )
        if not isinstance(raw, dict):
            raise AcquisitionGateError(f"{label} must be a JSON object")
        system = _validate_system(raw.get("system"), f"{label}.system")
        evidence_digest = _digest(
            raw.get("evidence_digest"), f"{label}.evidence_digest"
        )
        evidence = _read_phase0_cas_json(
            cas,
            evidence_digest,
            f"{label}.evidence",
        )
        if not isinstance(evidence, dict):
            raise AcquisitionGateError(f"{label}.evidence must be a JSON object")
        schema = evidence.get("schema")
        if expanded and system == candidate_system:
            if schema not in {
                "aragorn/benchmark-candidate-evidence/v1",
                "aragorn/benchmark-candidate-evidence/v2",
            }:
                raise AcquisitionGateError(
                    f"{label} requires authenticated candidate-composition evidence"
                )
        elif schema != "aragorn/benchmark-authenticated-worker-evidence/v1":
            raise AcquisitionGateError(
                f"{label} requires authenticated worker evidence"
            )


def evaluate_pair_files(
    oracle_path: str | Path,
    lock_path: str | Path,
    root_suite_path: str | Path,
    root_outcomes_path: str | Path,
    expanded_suite_path: str | Path,
    expanded_outcomes_path: str | Path,
    accounting_path: str | Path,
    *,
    evidence_state: str | Path,
    candidate_policy_path: str | Path,
    root_acceptance_ledger: str | Path,
    expanded_acceptance_ledger: str | Path,
) -> dict[str, Any]:
    policy = _policy(candidate_policy_path)
    oracle = _json_file(oracle_path, "acquisition oracle", canonical=True)
    lock = _json_file(lock_path, "acquisition oracle lock", canonical=True)
    root_suite = _suite(root_suite_path)
    expanded_suite = _suite(expanded_suite_path)
    canonical_oracle = _oracle(oracle, policy)
    _pair_suites(canonical_oracle, root_suite, expanded_suite, policy)
    expected_lock = build_lock(
        canonical_oracle, root_suite, expanded_suite, policy
    )
    if lock != expected_lock:
        raise AcquisitionGateError(
            "acquisition oracle lock does not match the frozen inputs"
        )
    accounting = _json_file(
        accounting_path, "Phase 0 acquisition accounting", canonical=False
    )
    root_report = evaluate_files(
        root_suite_path,
        root_outcomes_path,
        evidence_state=evidence_state,
        acceptance_ledger=root_acceptance_ledger,
    )
    expanded_report = evaluate_phase0_files(
        expanded_suite_path,
        expanded_outcomes_path,
        accounting_path,
        evidence_state=evidence_state,
        acceptance_ledger=expanded_acceptance_ledger,
    )
    _, plans, _ = _validate_phase0_accounting(
        accounting,
        suite_digest=expanded_suite["digest"],
        cases=expanded_suite["cases"],
        systems=expanded_suite["systems"],
    )
    cas = CAS(Path(evidence_state).expanduser().resolve(strict=True), read_only=True)
    _require_authenticated_arm_evidence(
        root_outcomes_path,
        cas,
        candidate_system=policy["candidate"],
        expanded=False,
    )
    _require_authenticated_arm_evidence(
        expanded_outcomes_path,
        cas,
        candidate_system=policy["candidate"],
        expanded=True,
    )
    records = {
        case_id: _load_phase0_expansion(
            cas,
            plan["expansion_digest"],
            expected_tree_digest=expanded_suite["cases"][case_id]["tree_digest"],
            label=f"Phase 0 acquisition case {case_id}",
        )
        for case_id, plan in plans.items()
    }
    return evaluate_pair(
        oracle=canonical_oracle,
        lock=lock,
        root_suite=root_suite,
        expanded_suite=expanded_suite,
        policy=policy,
        accounting=accounting,
        expansion_records=records,
        root_report=root_report,
        expanded_report=expanded_report,
    )


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise AcquisitionGateError(message)


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="python scripts/phase0_acquisition_gate.py",
        description="Freeze or evaluate the paired Phase 0 acquisition stratum.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze")
    freeze.add_argument("oracle", type=Path)
    freeze.add_argument("root_suite", type=Path)
    freeze.add_argument("expanded_suite", type=Path)
    freeze.add_argument("--candidate-policy", type=Path, required=True)
    freeze.set_defaults(action=_freeze_command)
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("oracle", type=Path)
    evaluate.add_argument("lock", type=Path)
    evaluate.add_argument("root_suite", type=Path)
    evaluate.add_argument("root_outcomes", type=Path)
    evaluate.add_argument("expanded_suite", type=Path)
    evaluate.add_argument("expanded_outcomes", type=Path)
    evaluate.add_argument("accounting", type=Path)
    evaluate.add_argument("--state", type=Path, required=True)
    evaluate.add_argument("--candidate-policy", type=Path, required=True)
    evaluate.add_argument("--root-acceptance-ledger", type=Path, required=True)
    evaluate.add_argument("--expanded-acceptance-ledger", type=Path, required=True)
    evaluate.set_defaults(action=_evaluate_command)
    return parser


def _freeze_command(arguments: argparse.Namespace) -> dict[str, Any]:
    return freeze_files(
        arguments.oracle,
        arguments.root_suite,
        arguments.expanded_suite,
        candidate_policy_path=arguments.candidate_policy,
    )


def _evaluate_command(arguments: argparse.Namespace) -> dict[str, Any]:
    return evaluate_pair_files(
        arguments.oracle,
        arguments.lock,
        arguments.root_suite,
        arguments.root_outcomes,
        arguments.expanded_suite,
        arguments.expanded_outcomes,
        arguments.accounting,
        evidence_state=arguments.state,
        candidate_policy_path=arguments.candidate_policy,
        root_acceptance_ledger=arguments.root_acceptance_ledger,
        expanded_acceptance_ledger=arguments.expanded_acceptance_ledger,
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        result = arguments.action(arguments)
    except (
        AcquisitionGateError,
        BenchmarkError,
        CandidateError,
        CASError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": "aragorn/error/v1",
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 4
    sys.stdout.buffer.write(_canonical_json_bytes(result))
    return 0 if result.get("comparison", {}).get("passed", True) else 2


if __name__ == "__main__":
    raise SystemExit(main())
