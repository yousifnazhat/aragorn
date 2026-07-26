"""Validate Aragorn schemas and checked-in contract examples."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

try:
    from jsonschema import FormatChecker
    from jsonschema.validators import validator_for
    from referencing import Registry, Resource
except ImportError as exc:  # pragma: no cover - developer setup error
    raise SystemExit(
        "jsonschema is required; run with: uv run --python 3.12 --with jsonschema "
        "python scripts/validate_schemas.py"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from freeze_hidden_suite import validate_freeze_receipt_bindings
from prepare_hidden_suite import (
    _V2_GATE,
    _V3_GATE,
    validate_retained_preparation_receipt,
)

from aragorn.acquire import ingest_local
from aragorn.artifact_closure import resolve_source_graph
from aragorn.benchmark import evaluate_files
from aragorn.benchmark_handoff_v2 import build_handoff_manifest
from aragorn.benchmark_protocol_v2 import (
    build_worker_request_v2,
    canonical_request_digest_v2,
    portable_policy_digest,
    validate_worker_result_v2,
    verify_request_result_binding_v2,
)
from aragorn.benchmark_worker_measurement import (
    build_worker_measurement,
    build_worker_trust_store,
    validate_worker_trust_store,
    verify_worker_measurement,
)
from aragorn.cas import CAS
from aragorn.corpus_audit import audit_suite
from aragorn.label_blind_prepare import validate_private_dispatch_v2
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase0_candidate import build_candidate_policy
from aragorn.standards_gate import validate_standards_gate


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _outcome(evidence: dict[str, object], evidence_digest: str) -> dict[str, object]:
    return {
        "schema": "aragorn/benchmark-outcome/v1",
        **{
            field: evidence[field]
            for field in (
                "suite_digest",
                "case_id",
                "tree_digest",
                "run_id",
                "system",
            )
        },
        "evidence_digest": evidence_digest,
        "verdict": evidence["verdict"],
        "reason_codes": evidence["reason_codes"],
    }


def _compose_historical_candidate(
    graph: dict[str, object],
    components: list[dict[str, object]],
) -> tuple[str, list[str]]:
    by_name = {item["system"]["name"]: item for item in components}
    errors = set()
    if graph["closure"]["status"] != "complete":
        errors.add("SOURCE_REFERENCE_GRAPH_INCOMPLETE")
    for name, component in by_name.items():
        if component["verdict"] == "ERROR":
            errors.add(
                "COMPARATOR_ERROR_"
                + re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")
            )
    if errors:
        return "ERROR", sorted(errors)
    denied = [item for item in components if item["verdict"] == "DENY"]
    if denied:
        reasons = sorted(
            {
                reason
                for item in denied
                for reason in item["reason_codes"]
                if reason != "NVIDIA_ANALYSIS_INCOMPLETE"
            }
        )
        return "DENY", reasons or ["COMPARATOR_DENY"]
    reviews = set()
    if by_name["cisco-skill-scanner"]["verdict"] == "REVIEW":
        reviews.update(by_name["cisco-skill-scanner"]["reason_codes"])
    if by_name["skillspector"]["verdict"] == "REVIEW":
        reviews.update(
            reason
            for reason in by_name["skillspector"]["reason_codes"]
            if reason != "NVIDIA_ANALYSIS_INCOMPLETE"
        )
    return ("REVIEW", sorted(reviews)) if reviews else ("ALLOW", [])


def validate_candidate_composition_smoke_receipt(
    receipt: dict[str, object],
    *,
    candidate_policy: dict[str, object],
    portable_identities: list[dict[str, object]],
    baseline_lock: dict[str, object],
) -> None:
    preparation = receipt["preparation"]
    composition = receipt["composition"]
    acceptances = receipt["acceptances"]
    lineage = receipt["lineage"]
    replay = receipt["replay"]
    expected_policy_digest = canonical_digest(candidate_policy)
    if preparation["candidate_policy_digest"] != expected_policy_digest:
        raise AssertionError("composition smoke receipt candidate policy drift")

    candidate_system = {
        **candidate_policy["candidate"],
        "config_digest": expected_policy_digest,
    }
    expected_systems = [candidate_system, *portable_identities]
    if (
        receipt["source"]["candidate_implementation_digest"]
        != candidate_system["implementation_digest"]
    ):
        raise AssertionError("composition smoke receipt candidate source drift")
    if composition["systems"] != expected_systems:
        raise AssertionError("composition smoke receipt system identity drift")
    suite = preparation["suite"]
    if canonical_digest(suite) != preparation["suite_digest"]:
        raise AssertionError("composition smoke receipt suite digest drift")
    if suite["systems"] != expected_systems:
        raise AssertionError("composition smoke receipt suite system drift")
    if suite["runs_per_case"] != preparation["runs_per_case"]:
        raise AssertionError("composition smoke receipt suite run-count drift")
    if len(suite["cases"]) != preparation["case_count"]:
        raise AssertionError("composition smoke receipt suite case-count drift")

    raw_baseline_digest = (
        "sha256:"
        + hashlib.sha256(
            (ROOT / "benchmark" / "baselines.lock.json").read_bytes()
        ).hexdigest()
    )
    if receipt["runtime"]["baseline_lock_digest"] != raw_baseline_digest:
        raise AssertionError("composition smoke receipt baseline lock drift")
    baselines = {item["name"]: item for item in baseline_lock["baselines"]}
    expected_analyzers = []
    for identity in portable_identities:
        baseline = baselines[identity["name"]]
        expected_analyzers.append(
            {
                "name": identity["name"],
                "version": identity["version"],
                "implementation_digest": identity["implementation_digest"],
                "portable_policy_digest": identity["config_digest"],
                "oci_index_digest": baseline["image"]["index_digest"],
                "oci_platform_manifest_digest": baseline["image"][
                    "platform_manifest_digest"
                ],
                "image_config_digest": baseline["image"]["config_digest"],
            }
        )
    for observed, expected in zip(
        receipt["runtime"]["analyzers"], expected_analyzers, strict=True
    ):
        if {key: observed[key] for key in expected} != expected:
            raise AssertionError("composition smoke receipt analyzer identity drift")
    analyzers_by_name = {item["name"]: item for item in receipt["runtime"]["analyzers"]}

    expected_comparator_cells = {
        (case_id, system)
        for case_id in ("benign-basic", "delegated-agent-propagation")
        for system in ("cisco-skill-scanner", "skillspector")
    }
    observed_comparator_cells = {
        (item["case_id"], item["system"]) for item in acceptances
    }
    if observed_comparator_cells != expected_comparator_cells:
        raise AssertionError("composition smoke receipt comparator matrix drift")
    if len(acceptances) != preparation["comparator_job_count"]:
        raise AssertionError("composition smoke receipt comparator job-count drift")
    suite_cases = {item["id"]: item for item in suite["cases"]}
    trust_store = receipt["trust_store"]
    validate_worker_trust_store(trust_store)
    trust_store_digest = canonical_digest(trust_store)
    receipt_fields = (
        "schema",
        "assurance",
        "issuance_digest",
        "trust_store_digest",
        "envelope_digest",
        "key_id",
        "trust_domain",
        "worker_id",
        "job_id",
        "verifier_challenge",
        "request_digest",
        "result_digest",
        "handoff_manifest_digest",
    )
    worker_results_by_cell = {}
    acceptances_by_cell = {}
    for acceptance in acceptances:
        retained_receipt = {field: acceptance[field] for field in receipt_fields}
        if (
            canonical_digest(retained_receipt)
            != acceptance["acceptance_receipt_digest"]
        ):
            raise AssertionError("composition smoke receipt acceptance digest drift")
        issuance = {
            "schema": "aragorn/benchmark-worker-measurement-issuance/v1",
            "trust_domain": acceptance["trust_domain"],
            "worker_id": acceptance["worker_id"],
            "job_id": acceptance["job_id"],
            "request_digest": acceptance["request_digest"],
            "verifier_challenge": acceptance["verifier_challenge"],
        }
        if canonical_digest(issuance) != acceptance["issuance_digest"]:
            raise AssertionError("composition smoke receipt issuance digest drift")
        verified = verify_worker_measurement(
            canonical_json(acceptance["measurement_envelope"]),
            trust_store,
            expected_worker_id=acceptance["worker_id"],
            expected_job_id=acceptance["job_id"],
            expected_request_digest=acceptance["request_digest"],
            expected_challenge=acceptance["verifier_challenge"],
        )
        statement = verified.statement
        if (
            verified.envelope_digest != acceptance["envelope_digest"]
            or verified.trust_store_digest != acceptance["trust_store_digest"]
            or verified.trust_store_digest != trust_store_digest
            or statement["key_id"] != acceptance["key_id"]
            or statement["trust_domain"] != acceptance["trust_domain"]
            or statement["result_digest"] != acceptance["result_digest"]
            or statement["handoff_manifest_digest"]
            != acceptance["handoff_manifest_digest"]
        ):
            raise AssertionError("composition smoke receipt signed measurement drift")
        case = suite_cases[acceptance["case_id"]]
        if (
            acceptance["fixture_class"] != case["class"]
            or acceptance["tree_digest"] != case["tree_digest"]
        ):
            raise AssertionError("composition smoke receipt acceptance case drift")
        result = acceptance["worker_result"]
        if canonical_digest(result) != acceptance["result_digest"]:
            raise AssertionError("composition smoke receipt worker result drift")
        analyzer = analyzers_by_name[acceptance["system"]]
        for result_field, acceptance_field in (
            ("job_id", "job_id"),
            ("verifier_challenge", "verifier_challenge"),
            ("request_digest", "request_digest"),
            ("tree_digest", "tree_digest"),
        ):
            if result[result_field] != acceptance[acceptance_field]:
                raise AssertionError(
                    f"composition smoke receipt worker {result_field} drift"
                )
        if (
            result["system"]["name"] != acceptance["system"]
            or result["system"]["version"] != analyzer["version"]
            or result["system"]["implementation_digest"]
            != analyzer["implementation_digest"]
            or result["portable_policy_digest"] != analyzer["portable_policy_digest"]
            or result["effective_config_digest"] != analyzer["effective_config_digest"]
            or result["oci_index_digest"] != analyzer["oci_index_digest"]
            or result["oci_platform_manifest_digest"]
            != analyzer["oci_platform_manifest_digest"]
            or result["image_config_digest"] != analyzer["image_config_digest"]
            or result["baseline_lock_digest"]
            != receipt["runtime"]["baseline_lock_digest"]
            or result["docker_executable_digest"]
            != receipt["runtime"]["docker_executable_digest"]
        ):
            raise AssertionError("composition smoke receipt worker identity drift")
        cell = (
            acceptance["case_id"],
            acceptance["run_id"],
            acceptance["system"],
        )
        if cell in acceptances_by_cell:
            raise AssertionError("composition smoke receipt duplicate acceptance cell")
        acceptances_by_cell[cell] = acceptance
        worker_results_by_cell[cell] = result
    for field in (
        "acceptance_receipt_digest",
        "issuance_digest",
        "envelope_digest",
        "job_id",
        "verifier_challenge",
        "request_digest",
        "result_digest",
        "handoff_manifest_digest",
    ):
        if len({item[field] for item in acceptances}) != len(acceptances):
            raise AssertionError(
                f"composition smoke receipt duplicate acceptance {field}"
            )
    for field in ("trust_store_digest", "key_id"):
        if len({item[field] for item in acceptances}) != 1:
            raise AssertionError(
                f"composition smoke receipt inconsistent acceptance {field}"
            )
    if set(replay["replayed_job_ids"]) != {item["job_id"] for item in acceptances}:
        raise AssertionError("composition smoke receipt replay job drift")
    if set(replay["acceptance_receipt_digests"]) != {
        item["acceptance_receipt_digest"] for item in acceptances
    }:
        raise AssertionError("composition smoke receipt replay receipt drift")

    outcomes = composition["outcomes"]
    outcomes_by_cell = {}
    for outcome in outcomes:
        cell = (
            outcome["case_id"],
            outcome["run_id"],
            outcome["system"]["name"],
        )
        if cell in outcomes_by_cell:
            raise AssertionError("composition smoke receipt duplicate outcome cell")
        outcomes_by_cell[cell] = outcome
    expected_outcome_cells = {
        (case["id"], run_id, system["name"])
        for case in suite["cases"]
        for run_id in range(1, suite["runs_per_case"] + 1)
        for system in expected_systems
    }
    if set(outcomes_by_cell) != expected_outcome_cells:
        raise AssertionError("composition smoke receipt outcome matrix drift")

    dispatch = lineage["dispatch"]
    try:
        validate_private_dispatch_v2(dispatch)
    except ValueError as exc:
        raise AssertionError(
            f"composition smoke receipt dispatch invalid: {exc}"
        ) from exc
    if (
        canonical_digest(dispatch) != preparation["dispatch_digest"]
        or dispatch["suite_digest"] != preparation["suite_digest"]
        or dispatch["candidate_policy_digest"] != preparation["candidate_policy_digest"]
        or dispatch["candidate_system"] != candidate_system
        or dispatch["runs_per_case"] != suite["runs_per_case"]
    ):
        raise AssertionError("composition smoke receipt dispatch root drift")
    expected_identities = {
        "schema": "aragorn/benchmark-system-identities/v1",
        "systems": sorted(portable_identities, key=lambda item: item["name"]),
    }
    if canonical_digest(expected_identities) != preparation["worker_identities_digest"]:
        raise AssertionError("composition smoke receipt worker identities digest drift")
    expected_worklist = {
        "schema": "aragorn/benchmark-worker-worklist/v1",
        "jobs": [
            {
                "job_id": job["job_id"],
                "request_digest": job["request_digest"],
            }
            for job in dispatch["jobs"]
        ],
    }
    if canonical_digest(expected_worklist) != preparation["worklist_digest"]:
        raise AssertionError("composition smoke receipt worklist digest drift")
    dispatch_cases = {item["case_id"]: item for item in dispatch["cases"]}
    if set(dispatch_cases) != set(suite_cases):
        raise AssertionError("composition smoke receipt dispatch case drift")
    for case_id, case in suite_cases.items():
        if dispatch_cases[case_id]["tree_digest"] != case["tree_digest"]:
            raise AssertionError("composition smoke receipt dispatch tree drift")

    comparator_systems = {
        item["name"]: item for item in expected_systems if item["name"] != "aragorn"
    }
    dispatch_jobs = {}
    for job in dispatch["jobs"]:
        cell = (job["case_id"], job["run_id"], job["system"]["name"])
        if cell in dispatch_jobs:
            raise AssertionError("composition smoke receipt duplicate dispatch cell")
        if (
            job["suite_digest"] != preparation["suite_digest"]
            or comparator_systems.get(job["system"]["name"]) != job["system"]
        ):
            raise AssertionError("composition smoke receipt dispatch job drift")
        dispatch_jobs[cell] = job
    if set(dispatch_jobs) != set(acceptances_by_cell):
        raise AssertionError("composition smoke receipt dispatch matrix drift")
    for cell, acceptance in acceptances_by_cell.items():
        job = dispatch_jobs[cell]
        if (
            job["job_id"] != acceptance["job_id"]
            or job["request_digest"] != acceptance["request_digest"]
            or job["tree_digest"] != acceptance["tree_digest"]
            or job["private_manifest_digest"]
            != dispatch_cases[cell[0]]["private_manifest_digest"]
        ):
            raise AssertionError("composition smoke receipt dispatch acceptance drift")

    retained_graphs = {}
    for retained in lineage["source_graphs"]:
        graph = retained["graph"]
        digest = retained["source_graph_digest"]
        if canonical_digest(graph) != digest or digest in retained_graphs:
            raise AssertionError("composition smoke receipt source graph drift")
        retained_graphs[digest] = graph

    graphs_by_case = {}
    with TemporaryDirectory(prefix="aragorn-composition-replay-") as temporary:
        cas = CAS(temporary)
        for case_id, case in suite_cases.items():
            expected_path = f"oci-fixtures/{case_id}"
            if case["path"] != expected_path:
                raise AssertionError("composition smoke receipt fixture path drift")
            manifest = ingest_local(ROOT / "benchmark" / expected_path, cas)
            manifest["source"]["path"] = "/aragorn/opaque-benchmark-fixture"
            manifest_digest = canonical_digest(manifest)
            dispatch_case = dispatch_cases[case_id]
            if (
                manifest_digest != dispatch_case["private_manifest_digest"]
                or manifest["tree_digest"] != dispatch_case["tree_digest"]
            ):
                raise AssertionError("composition smoke receipt source manifest drift")
            graph = resolve_source_graph(
                manifest,
                cas,
                root_manifest_digest=manifest_digest,
            )
            graph_digest = canonical_digest(graph)
            if retained_graphs.get(graph_digest) != graph:
                raise AssertionError(
                    "composition smoke receipt source graph does not re-derive"
                )
            graphs_by_case[case_id] = (graph_digest, graph)
    if len(graphs_by_case) != len(retained_graphs):
        raise AssertionError("composition smoke receipt extra source graph")

    component_by_cell = {}
    derived_outcomes = []
    for retained in lineage["component_evidence"]:
        evidence = retained["evidence"]
        evidence_digest = retained["evidence_digest"]
        if canonical_digest(evidence) != evidence_digest:
            raise AssertionError("composition smoke receipt component digest drift")
        cell = (
            evidence["case_id"],
            evidence["run_id"],
            evidence["system"]["name"],
        )
        if cell in component_by_cell or cell not in dispatch_jobs:
            raise AssertionError("composition smoke receipt component cell drift")
        job = dispatch_jobs[cell]
        acceptance = acceptances_by_cell[cell]
        result = worker_results_by_cell[cell]
        expected_evidence = {
            "schema": "aragorn/benchmark-authenticated-worker-evidence/v1",
            "suite_digest": preparation["suite_digest"],
            "case_id": job["case_id"],
            "tree_digest": job["tree_digest"],
            "run_id": job["run_id"],
            "system": job["system"],
            "verdict": result["verdict"],
            "reason_codes": result["reason_codes"],
            "private_manifest_digest": job["private_manifest_digest"],
            "dispatch_digest": preparation["dispatch_digest"],
            "acceptance_receipt_digest": acceptance["acceptance_receipt_digest"],
            "issuance_digest": acceptance["issuance_digest"],
        }
        if evidence != expected_evidence:
            raise AssertionError("composition smoke receipt component evidence drift")
        component_by_cell[cell] = (evidence_digest, evidence)
        derived_outcomes.append(_outcome(evidence, evidence_digest))
    if set(component_by_cell) != set(dispatch_jobs):
        raise AssertionError("composition smoke receipt component matrix drift")

    candidate_cells = {}
    for retained in lineage["candidate_evidence"]:
        evidence = retained["evidence"]
        evidence_digest = retained["evidence_digest"]
        if canonical_digest(evidence) != evidence_digest:
            raise AssertionError("composition smoke receipt candidate digest drift")
        cell = (evidence["case_id"], evidence["run_id"])
        if cell in candidate_cells or evidence["case_id"] not in graphs_by_case:
            raise AssertionError("composition smoke receipt candidate cell drift")
        components = sorted(
            (
                component_by_cell[
                    (evidence["case_id"], evidence["run_id"], system_name)
                ]
                for system_name in comparator_systems
            ),
            key=lambda item: item[1]["system"]["name"],
        )
        graph_digest, graph = graphs_by_case[evidence["case_id"]]
        verdict, reason_codes = _compose_historical_candidate(
            graph,
            [item[1] for item in components],
        )
        dispatch_case = dispatch_cases[evidence["case_id"]]
        expected_evidence = {
            "schema": "aragorn/benchmark-candidate-evidence/v1",
            "suite_digest": preparation["suite_digest"],
            "case_id": evidence["case_id"],
            "tree_digest": dispatch_case["tree_digest"],
            "run_id": evidence["run_id"],
            "system": candidate_system,
            "verdict": verdict,
            "reason_codes": reason_codes,
            "private_manifest_digest": dispatch_case["private_manifest_digest"],
            "source_graph_digest": graph_digest,
            "dispatch_digest": preparation["dispatch_digest"],
            "policy_digest": preparation["candidate_policy_digest"],
            "component_evidence_digests": sorted(item[0] for item in components),
        }
        if evidence != expected_evidence:
            raise AssertionError("composition smoke receipt candidate evidence drift")
        candidate_cells[cell] = evidence
        derived_outcomes.append(_outcome(evidence, evidence_digest))
    expected_candidate_cells = {
        (case["id"], run_id)
        for case in suite["cases"]
        for run_id in range(1, suite["runs_per_case"] + 1)
    }
    if set(candidate_cells) != expected_candidate_cells:
        raise AssertionError("composition smoke receipt candidate matrix drift")

    derived_outcomes.sort(
        key=lambda item: (
            item["system"]["name"],
            item["system"]["version"],
            item["system"]["implementation_digest"],
            item["system"]["config_digest"],
            item["case_id"],
            item["run_id"],
        )
    )
    if outcomes != derived_outcomes:
        raise AssertionError("composition smoke receipt outcomes do not re-derive")
    candidate_count = sum(item["system"]["name"] == "aragorn" for item in outcomes)
    comparator_count = len(outcomes) - candidate_count
    comparator_outcome_error_count = sum(
        item["system"]["name"] != "aragorn" and item["verdict"] == "ERROR"
        for item in outcomes
    )
    worker_ok_count = sum(
        item["execution"]["status"] == "ok" for item in worker_results_by_cell.values()
    )
    if (
        composition["runs_per_case"] != suite["runs_per_case"]
        or composition["case_count"] != len(suite["cases"])
        or composition["candidate_outcome_count"] != candidate_count
        or composition["comparator_outcome_count"] != comparator_count
        or composition["outcome_count"] != len(outcomes)
        or composition["system_count"]
        != len({item["system"]["name"] for item in outcomes})
        or composition["comparator_execution_ok_count"] != worker_ok_count
        or composition["comparator_execution_error_count"]
        != len(worker_results_by_cell) - worker_ok_count
        or comparator_outcome_error_count
        != composition["comparator_execution_error_count"]
    ):
        raise AssertionError("composition smoke receipt derived counter drift")
    if canonical_digest(outcomes) != composition["outcomes_digest"]:
        raise AssertionError("composition smoke receipt outcomes digest drift")
    composed = {
        "assurance": composition["assurance"],
        "dispatch_digest": preparation["dispatch_digest"],
        "outcomes": outcomes,
        "outcomes_digest": composition["outcomes_digest"],
        "policy_digest": preparation["candidate_policy_digest"],
        "schema": composition["schema"],
        "suite_digest": preparation["suite_digest"],
    }
    if canonical_digest(composed) != composition["candidate_composition_digest"]:
        raise AssertionError("composition smoke receipt composition digest drift")


def _rehash_composition_smoke_receipt(receipt: dict[str, object]) -> None:
    """Rehash attacker-controlled lineage to test external trust anchors."""

    preparation = receipt["preparation"]
    lineage = receipt["lineage"]
    composition = receipt["composition"]
    dispatch_digest = canonical_digest(lineage["dispatch"])
    preparation["dispatch_digest"] = dispatch_digest

    component_digests = {}
    for retained in lineage["component_evidence"]:
        evidence = retained["evidence"]
        evidence["dispatch_digest"] = dispatch_digest
        evidence_digest = canonical_digest(evidence)
        retained["evidence_digest"] = evidence_digest
        component_digests[
            (evidence["case_id"], evidence["run_id"], evidence["system"]["name"])
        ] = evidence_digest

    graph_digests = {}
    for retained in lineage["source_graphs"]:
        graph = retained["graph"]
        graph_digest = canonical_digest(graph)
        retained["source_graph_digest"] = graph_digest
        graph_digests[(graph["root_manifest_digest"], graph["tree_digest"])] = (
            graph_digest
        )

    for retained in lineage["candidate_evidence"]:
        evidence = retained["evidence"]
        evidence["dispatch_digest"] = dispatch_digest
        evidence["component_evidence_digests"] = sorted(
            digest
            for (case_id, run_id, _), digest in component_digests.items()
            if (case_id, run_id) == (evidence["case_id"], evidence["run_id"])
        )
        evidence["source_graph_digest"] = graph_digests[
            (evidence["private_manifest_digest"], evidence["tree_digest"])
        ]
        retained["evidence_digest"] = canonical_digest(evidence)

    retained_evidence = [
        *lineage["component_evidence"],
        *lineage["candidate_evidence"],
    ]
    outcomes = [
        _outcome(item["evidence"], item["evidence_digest"])
        for item in retained_evidence
    ]
    outcomes.sort(
        key=lambda item: (
            item["system"]["name"],
            item["system"]["version"],
            item["system"]["implementation_digest"],
            item["system"]["config_digest"],
            item["case_id"],
            item["run_id"],
        )
    )
    composition["outcomes"] = outcomes
    composition["outcomes_digest"] = canonical_digest(outcomes)
    composition["candidate_composition_digest"] = canonical_digest(
        {
            "assurance": composition["assurance"],
            "dispatch_digest": dispatch_digest,
            "outcomes": outcomes,
            "outcomes_digest": composition["outcomes_digest"],
            "policy_digest": preparation["candidate_policy_digest"],
            "schema": composition["schema"],
            "suite_digest": preparation["suite_digest"],
        }
    )


def validate_composition_smoke_mutation_resistance(
    receipt: dict[str, object],
    *,
    candidate_policy: dict[str, object],
    portable_identities: list[dict[str, object]],
    baseline_lock: dict[str, object],
) -> None:
    mutations = []

    changed = deepcopy(receipt)
    changed["preparation"]["worker_identities_digest"] = "sha256:" + "3" * 64
    mutations.append(("worker identities digest", changed))

    changed = deepcopy(receipt)
    changed["preparation"]["worklist_digest"] = "sha256:" + "4" * 64
    mutations.append(("worklist digest", changed))

    changed = deepcopy(receipt)
    changed["lineage"]["dispatch"]["jobs"][0]["request_digest"] = "sha256:" + "0" * 64
    _rehash_composition_smoke_receipt(changed)
    mutations.append(("rehashed dispatch request", changed))

    changed = deepcopy(receipt)
    case_id = changed["lineage"]["dispatch"]["cases"][0]["case_id"]
    old_manifest = changed["lineage"]["dispatch"]["cases"][0]["private_manifest_digest"]
    new_manifest = "sha256:" + "1" * 64
    changed["lineage"]["dispatch"]["cases"][0]["private_manifest_digest"] = new_manifest
    for job in changed["lineage"]["dispatch"]["jobs"]:
        if job["case_id"] == case_id:
            job["private_manifest_digest"] = new_manifest
    for retained in changed["lineage"]["component_evidence"]:
        if retained["evidence"]["case_id"] == case_id:
            retained["evidence"]["private_manifest_digest"] = new_manifest
    for retained in changed["lineage"]["candidate_evidence"]:
        if retained["evidence"]["case_id"] == case_id:
            retained["evidence"]["private_manifest_digest"] = new_manifest
    for retained in changed["lineage"]["source_graphs"]:
        if retained["graph"]["root_manifest_digest"] == old_manifest:
            retained["graph"]["root_manifest_digest"] = new_manifest
    _rehash_composition_smoke_receipt(changed)
    mutations.append(("rehashed private manifest", changed))

    changed = deepcopy(receipt)
    evidence = changed["lineage"]["candidate_evidence"][0]["evidence"]
    evidence["verdict"] = "ERROR"
    evidence["reason_codes"] = ["FORGED_CANDIDATE_RESULT"]
    _rehash_composition_smoke_receipt(changed)
    mutations.append(("rehashed candidate decision", changed))

    changed = deepcopy(receipt)
    retained = changed["lineage"]["candidate_evidence"][0]
    retained["evidence_digest"] = "sha256:" + "2" * 64
    for outcome in changed["composition"]["outcomes"]:
        if (
            outcome["case_id"] == retained["evidence"]["case_id"]
            and outcome["system"]["name"] == "aragorn"
        ):
            outcome["evidence_digest"] = retained["evidence_digest"]
    changed["composition"]["outcomes_digest"] = canonical_digest(
        changed["composition"]["outcomes"]
    )
    changed["composition"]["candidate_composition_digest"] = canonical_digest(
        {
            "assurance": changed["composition"]["assurance"],
            "dispatch_digest": changed["preparation"]["dispatch_digest"],
            "outcomes": changed["composition"]["outcomes"],
            "outcomes_digest": changed["composition"]["outcomes_digest"],
            "policy_digest": changed["preparation"]["candidate_policy_digest"],
            "schema": changed["composition"]["schema"],
            "suite_digest": changed["preparation"]["suite_digest"],
        }
    )
    mutations.append(("detached candidate evidence digest", changed))

    for label, changed in mutations:
        try:
            validate_candidate_composition_smoke_receipt(
                changed,
                candidate_policy=candidate_policy,
                portable_identities=portable_identities,
                baseline_lock=baseline_lock,
            )
        except (AssertionError, ValueError):
            continue
        raise AssertionError(f"composition smoke accepted {label} mutation")


def main() -> int:
    schemas = {
        path.name: load(path) for path in sorted((ROOT / "schema").glob("*.json"))
    }
    registry = Registry().with_resources(
        (
            schema["$id"],
            Resource.from_contents(schema),
        )
        for schema in schemas.values()
        if isinstance(schema, dict) and "$id" in schema
    )
    validators = {}
    for name, schema in schemas.items():
        validator_class = validator_for(schema)
        validator_class.check_schema(schema)
        validators[name] = validator_class(
            schema,
            format_checker=FormatChecker(),
            registry=registry,
        )

    baseline_lock = load(ROOT / "benchmark" / "baselines.lock.json")
    validators["baseline-lock-v1.schema.json"].validate(baseline_lock)
    phase0_corpus_lock_path = ROOT / "benchmark" / "phase0-corpus.lock.json"
    phase0_corpus_lock_raw = phase0_corpus_lock_path.read_bytes()
    phase0_corpus_lock = json.loads(phase0_corpus_lock_raw)
    validators["benchmark-corpus-provenance-lock-v1.schema.json"].validate(
        phase0_corpus_lock
    )
    phase0_corpus_lock_v3_path = ROOT / "benchmark" / "phase0-corpus-v3.lock.json"
    phase0_corpus_lock_v3_raw = phase0_corpus_lock_v3_path.read_bytes()
    phase0_corpus_lock_v3 = json.loads(phase0_corpus_lock_v3_raw)
    validators["benchmark-corpus-provenance-lock-v2.schema.json"].validate(
        phase0_corpus_lock_v3
    )
    phase0_corpus_lock_v4 = load(
        ROOT / "benchmark" / "phase0-corpus-v4.lock.json"
    )
    validators["benchmark-corpus-provenance-lock-v2.schema.json"].validate(
        phase0_corpus_lock_v4
    )
    validators["benchmark-phase0-acquisition-corpus-lock-v1.schema.json"].validate(
        load(ROOT / "benchmark" / "phase0-acquisition-corpus.lock.json")
    )
    standards_gate = load(ROOT / "benchmark" / "phase0-standards-gate.json")
    validators["phase0-standards-gate-v1.schema.json"].validate(standards_gate)
    validate_standards_gate(standards_gate, repository_root=ROOT)
    validators["benchmark-suite-v1.schema.json"].validate(
        load(ROOT / "benchmark" / "suite.json")
    )
    validators["benchmark-suite-v1.schema.json"].validate(
        load(ROOT / "benchmark" / "oci-suite.json")
    )
    validators["benchmark-suite-v1.schema.json"].validate(
        load(ROOT / "benchmark" / "phase0-oci-pilot-v1.json")
    )
    phase0_candidate_policy = load(ROOT / "benchmark" / "phase0-candidate-policy.json")
    validators["benchmark-candidate-policy-v1.schema.json"].validate(
        phase0_candidate_policy
    )
    phase0_candidate_policy_v2 = load(
        ROOT / "benchmark" / "phase0-candidate-policy-v2.json"
    )
    validators["benchmark-candidate-policy-v2.schema.json"].validate(
        phase0_candidate_policy_v2
    )
    phase0_candidate_policy_v3 = load(
        ROOT / "benchmark" / "phase0-candidate-policy-v3.json"
    )
    validators["benchmark-candidate-policy-v3.schema.json"].validate(
        phase0_candidate_policy_v3
    )
    phase0_candidate_policy_v4 = load(
        ROOT / "benchmark" / "phase0-candidate-policy-v4.json"
    )
    validators["benchmark-candidate-policy-v3.schema.json"].validate(
        phase0_candidate_policy_v4
    )
    if (
        build_candidate_policy(phase0_candidate_policy_v4)
        != phase0_candidate_policy_v4
    ):
        raise AssertionError("checked v4 candidate policy is not canonical")
    portable_identities = []
    for filename in (
        "phase0-cisco-portable-policy.json",
        "phase0-skillspector-portable-policy.json",
    ):
        portable_policy = load(ROOT / "benchmark" / filename)
        validators["benchmark-portable-policy-v1.schema.json"].validate(portable_policy)
        portable_identities.append(
            {
                **portable_policy["system"],
                "config_digest": portable_policy_digest(portable_policy),
            }
        )
    if portable_identities != phase0_candidate_policy["required_comparators"]:
        raise AssertionError(
            "checked portable-policy identities do not match candidate policy"
        )
    portable_identities_v2 = []
    for filename in (
        "phase0-cisco-portable-policy-v2.json",
        "phase0-skillspector-portable-policy-v2.json",
    ):
        portable_policy = load(ROOT / "benchmark" / filename)
        validators["benchmark-portable-policy-v1.schema.json"].validate(portable_policy)
        portable_identities_v2.append(
            {
                **portable_policy["system"],
                "config_digest": portable_policy_digest(portable_policy),
            }
        )
    if portable_identities_v2 != phase0_candidate_policy_v2["required_comparators"]:
        raise AssertionError(
            "checked portable-policy identities do not match v2 candidate policy"
        )
    if portable_identities_v2 != phase0_candidate_policy_v3["required_comparators"]:
        raise AssertionError(
            "checked portable-policy identities do not match v3 candidate policy"
        )
    validators["benchmark-e2e-smoke-receipt-v1.schema.json"].validate(
        load(
            ROOT
            / "benchmark"
            / "receipts"
            / "phase0-local-label-free-smoke-2026-07-22.json"
        )
    )
    validators["benchmark-isolated-smoke-receipt-v1.schema.json"].validate(
        load(
            ROOT
            / "benchmark"
            / "receipts"
            / "phase0-isolated-protocol-v2-smoke-2026-07-23.json"
        )
    )
    composition_smoke_receipt = load(
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-public-candidate-composition-smoke-2026-07-24.json"
    )
    validators["benchmark-candidate-composition-smoke-receipt-v1.schema.json"].validate(
        composition_smoke_receipt
    )
    validators["benchmark-suite-v1.schema.json"].validate(
        composition_smoke_receipt["preparation"]["suite"]
    )
    validators["benchmark-worker-trust-store-v1.schema.json"].validate(
        composition_smoke_receipt["trust_store"]
    )
    lineage = composition_smoke_receipt["lineage"]
    validators["benchmark-private-dispatch-v2.schema.json"].validate(
        lineage["dispatch"]
    )
    for retained in lineage["component_evidence"]:
        validators["benchmark-authenticated-worker-evidence-v1.schema.json"].validate(
            retained["evidence"]
        )
    for retained in lineage["candidate_evidence"]:
        validators["benchmark-candidate-evidence-v1.schema.json"].validate(
            retained["evidence"]
        )
    for retained in lineage["source_graphs"]:
        validators["source-artifact-graph-v1.schema.json"].validate(retained["graph"])
    for acceptance in composition_smoke_receipt["acceptances"]:
        validators["benchmark-worker-result-v2.schema.json"].validate(
            acceptance["worker_result"]
        )
        validate_worker_result_v2(acceptance["worker_result"])
    for outcome in composition_smoke_receipt["composition"]["outcomes"]:
        validators["benchmark-outcome-v1.schema.json"].validate(outcome)
    validate_candidate_composition_smoke_receipt(
        composition_smoke_receipt,
        candidate_policy=phase0_candidate_policy,
        portable_identities=portable_identities,
        baseline_lock=baseline_lock,
    )
    validate_composition_smoke_mutation_resistance(
        composition_smoke_receipt,
        candidate_policy=phase0_candidate_policy,
        portable_identities=portable_identities,
        baseline_lock=baseline_lock,
    )
    validators["corpus-audit-v1.schema.json"].validate(
        audit_suite(ROOT / "benchmark" / "phase0-oci-pilot-v1.json")
    )
    outcome_validator = validators["benchmark-outcome-v1.schema.json"]
    for line in (
        (ROOT / "benchmark" / "outcomes.jsonl").read_text(encoding="utf-8").splitlines()
    ):
        outcome_validator.validate(json.loads(line))
    report = evaluate_files(
        ROOT / "benchmark" / "suite.json",
        ROOT / "benchmark" / "outcomes.jsonl",
    )
    validators["benchmark-report-v1.schema.json"].validate(report)
    digest = "sha256:" + "0" * 64
    second_digest = "sha256:" + "1" * 64
    third_digest = "sha256:" + "2" * 64
    validators["benchmark-phase0-gate-report-v2.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-phase0-gate-report/v2",
            "assurance": "comparative_metrics_only",
            "suite_id": "schema-test",
            "purpose": "evidence_smoke",
            "suite_digest": digest,
            "outcomes_digest": second_digest,
            "benchmark_report_digest": third_digest,
            "corpus_lock_digest": digest,
            "public_manifest_digest": second_digest,
            "hidden_suite_lock_digest": third_digest,
            "candidate_policy_digest": digest,
            "label_ledger_digest": second_digest,
            "evaluation_split": "hidden",
            "comparison": {
                "benign_burden_ceiling": {
                    "numerator": 1,
                    "denominator": 20,
                    "rate": 0.05,
                },
                "minimum_attack_flag_delta": {
                    "numerator": 1,
                    "denominator": 10,
                    "rate": 0.1,
                },
                "candidate": None,
                "comparators": [],
                "pareto_frontier": [],
                "selected_comparator": None,
                "attack_flag_delta": None,
                "evaluable": False,
                "passed": False,
                "reason_codes": ["NO_HIDDEN_SPLIT"],
            },
        }
    )
    acquisition_candidate = {
        **phase0_candidate_policy_v3["candidate"],
        "config_digest": canonical_digest(phase0_candidate_policy_v3),
    }
    acquisition_budgets = {
        "api_requests": 20_050,
        "api_bytes": 402_653_184,
        "retained_bytes": 134_217_728,
        "expanded_objects": 256,
        "expansion_depth": 1,
        "references": 10_000,
    }
    acquisition_cases = []
    acquisition_definitions = [
        (
            f"acquisition-adversarial-{index:03d}",
            "adversarial",
            f"acquisition-path-{index % 8:02d}",
        )
        for index in range(112)
    ]
    acquisition_definitions.extend(
        (f"acquisition-benign-{index:03d}", "benign", "benign")
        for index in range(336)
    )
    for index, (case_id, case_class, family) in enumerate(
        acquisition_definitions
    ):
        literal = f"payloads/{case_id}.txt"
        acquisition_cases.append(
            {
                "case_id": case_id,
                "class": case_class,
                "family": family,
                "lineage": f"{case_id}-lineage",
                "root_tree_digest": (
                    "sha256:"
                    + hashlib.sha256(f"{case_id}:root".encode()).hexdigest()
                ),
                "expanded_tree_digest": (
                    "sha256:"
                    + hashlib.sha256(f"{case_id}:expanded".encode()).hexdigest()
                ),
                "source": {
                    "host": "github.com",
                    "owner": "example",
                    "repository": "project",
                    "commit": hashlib.sha1(
                        f"{case_id}:commit".encode()
                    ).hexdigest(),
                    "commit_tree": hashlib.sha1(
                        f"{case_id}:tree".encode()
                    ).hexdigest(),
                    "skill_path": f"skills/{case_id}",
                    "api_version": "2026-03-10",
                },
                "expected_references": [
                    {
                        "source_commit": hashlib.sha1(
                            f"{case_id}:commit".encode()
                        ).hexdigest(),
                        "source_repository_path": (
                            f"skills/{case_id}/SKILL.md"
                        ),
                        "source_blob_digest": (
                            "sha256:"
                            + hashlib.sha256(
                                f"{case_id}:source".encode()
                            ).hexdigest()
                        ),
                        "byte_offset": 0,
                        "literal_size": len(literal.encode()),
                        "literal_digest": (
                            "sha256:"
                            + hashlib.sha256(literal.encode()).hexdigest()
                        ),
                        "target_commit": hashlib.sha1(
                            f"{case_id}:commit".encode()
                        ).hexdigest(),
                        "target_repository_path": literal,
                        "target_digest": (
                            "sha256:"
                            + hashlib.sha256(
                                f"{case_id}:target".encode()
                            ).hexdigest()
                        ),
                    }
                ],
            }
        )
    acquisition_oracle = {
        "schema": "aragorn/benchmark-phase0-acquisition-oracle/v1",
        "root_suite_digest": digest,
        "expanded_suite_digest": second_digest,
        "split": "held_out",
        "runs_per_case": 1,
        "candidate_system": acquisition_candidate,
        "comparators": phase0_candidate_policy_v3["required_comparators"],
        "expansion_profile": (
            "phase0-exact-github-blob-expansion-terminal-depth-1/v1"
        ),
        "expansion_assurance": (
            "evaluation_only_github_api_membership_asserted_blob_identity_"
            "reverified_depth_1_targets_terminal_not_reference_scanned"
        ),
        "budgets": acquisition_budgets,
        "cases": acquisition_cases,
    }
    validators["benchmark-phase0-acquisition-oracle-v1.schema.json"].validate(
        acquisition_oracle
    )
    acquisition_lock = {
        "schema": "aragorn/benchmark-phase0-acquisition-oracle-lock/v1",
        "assurance": (
            "operator_asserted_pre_outcome_binding_not_independent_or_timestamped"
        ),
        "oracle_digest": canonical_digest(acquisition_oracle),
        "candidate_policy_digest": canonical_digest(phase0_candidate_policy_v3),
        "root_suite_digest": digest,
        "expanded_suite_digest": second_digest,
        "split": "held_out",
        "case_count": 448,
        "class_counts": {"adversarial": 112, "benign": 336},
        "family_counts": {
            "acquisition-path-00": 14,
            "acquisition-path-01": 14,
            "acquisition-path-02": 14,
            "acquisition-path-03": 14,
            "acquisition-path-04": 14,
            "acquisition-path-05": 14,
            "acquisition-path-06": 14,
            "acquisition-path-07": 14,
            "benign": 336,
        },
        "lineage_count": 448,
        "runs_per_case": 1,
        "candidate_system": acquisition_candidate,
        "comparators": phase0_candidate_policy_v3["required_comparators"],
        "expansion_profile": (
            "phase0-exact-github-blob-expansion-terminal-depth-1/v1"
        ),
        "expansion_assurance": (
            "evaluation_only_github_api_membership_asserted_blob_identity_"
            "reverified_depth_1_targets_terminal_not_reference_scanned"
        ),
        "budgets": acquisition_budgets,
    }
    validators[
        "benchmark-phase0-acquisition-oracle-lock-v1.schema.json"
    ].validate(acquisition_lock)
    validators["benchmark-phase0-accounting-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-phase0-accounting/v1",
            "suite_digest": second_digest,
            "candidate_system": acquisition_candidate,
            "expansion_profile": acquisition_oracle["expansion_profile"],
            "expansion_assurance": acquisition_oracle["expansion_assurance"],
            "cases": [],
        }
    )
    zero_fraction = {"numerator": 0, "denominator": 10, "rate": 0.0}
    candidate_point = {
        "system": acquisition_candidate,
        "benign_intervention": zero_fraction,
        "adversarial_flag": {"numerator": 8, "denominator": 10, "rate": 0.8},
        "burden_compliant": True,
    }
    comparator_point = {
        "system": phase0_candidate_policy_v3["required_comparators"][1],
        "benign_intervention": zero_fraction,
        "adversarial_flag": {"numerator": 6, "denominator": 10, "rate": 0.6},
        "burden_compliant": True,
    }
    acquisition_accounting = {
        "cases": 448,
        "complete_expansions": 448,
        "incomplete_expansions": 0,
        "expansion_success_rate": 1.0,
        "incomplete_cases": 0,
        "expected_references": 448,
        "captured_references": 448,
        "missed_references": 0,
        "wrong_target_references": 0,
        "unresolved_expected_references": 0,
        "source_reference_capture_rate": 1.0,
        "profile_artifact_references": 448,
        "unresolved_references": 0,
        "non_artifact_references": 0,
        "unresolved_cases": 0,
        "unresolved_reference_rate": 0.0,
        "opaque_carriers": 0,
        "published_expanded_objects": 448,
        "attempted_expanded_objects": 448,
        "budgets": {
            name: {
                "limit": limit,
                "used": 0,
                "utilization_rate": 0.0,
            }
            for name, limit in acquisition_budgets.items()
        },
        "reason_counts": [],
    }
    validators[
        "benchmark-phase0-acquisition-gate-report-v1.schema.json"
    ].validate(
        {
            "schema": "aragorn/benchmark-phase0-acquisition-gate-report/v1",
            "assurance": "paired_evidence_metrics_only",
            "oracle_lock_digest": canonical_digest(acquisition_lock),
            "oracle_digest": canonical_digest(acquisition_oracle),
            "candidate_policy_digest": canonical_digest(
                phase0_candidate_policy_v3
            ),
            "root_arm": {
                "suite_digest": digest,
                "outcomes_digest": second_digest,
                "benchmark_report_digest": third_digest,
            },
            "expanded_arm": {
                "suite_digest": second_digest,
                "outcomes_digest": third_digest,
                "benchmark_report_digest": digest,
                "accounting_digest": second_digest,
            },
            "evaluation_split": "held_out",
            "accounting": acquisition_accounting,
            "comparison": {
                "benign_burden_ceiling": {
                    "numerator": 1,
                    "denominator": 20,
                    "rate": 0.05,
                },
                "minimum_attack_flag_delta": {
                    "numerator": 1,
                    "denominator": 10,
                    "rate": 0.1,
                },
                "candidate": candidate_point,
                "comparators": [comparator_point],
                "pareto_frontier": [comparator_point],
                "selected_comparator": comparator_point,
                "attack_flag_delta": {
                    "numerator": 1,
                    "denominator": 5,
                    "rate": 0.2,
                },
                "evaluable": True,
                "passed": True,
                "reason_codes": [],
            },
        }
    )
    validators[
        "benchmark-phase0-acquisition-gate-report-v1.schema.json"
    ].validate(
        load(
            ROOT
            / "benchmark"
            / "phase0-acquisition-gate-report-v1.example.json"
        )
    )
    hidden_lock_path = ROOT / "benchmark" / "phase0-hidden-suite.lock.json"
    hidden_lock_raw = hidden_lock_path.read_bytes()
    hidden_lock = json.loads(hidden_lock_raw)
    hidden_receipt_path = (
        ROOT / "benchmark" / "receipts" / "phase0-hidden-suite-freeze-2026-07-24.json"
    )
    hidden_receipt_raw = hidden_receipt_path.read_bytes()
    hidden_receipt = json.loads(hidden_receipt_raw)
    validators["benchmark-phase0-hidden-suite-lock-v1.schema.json"].validate(
        hidden_lock
    )
    validators["benchmark-phase0-hidden-suite-freeze-receipt-v1.schema.json"].validate(
        hidden_receipt
    )
    validate_freeze_receipt_bindings(
        hidden_receipt,
        hidden_receipt_raw,
        hidden_lock,
        hidden_lock_raw,
        phase0_corpus_lock,
        phase0_corpus_lock_raw,
    )
    hidden_preparation_path = (
        ROOT / "benchmark" / "receipts" / "phase0-hidden-preparation-2026-07-24.json"
    )
    if hidden_preparation_path.exists():
        hidden_preparation_raw = hidden_preparation_path.read_bytes()
        hidden_preparation = json.loads(hidden_preparation_raw)
        validators[
            "benchmark-phase0-hidden-preparation-receipt-v1.schema.json"
        ].validate(hidden_preparation)
        validate_retained_preparation_receipt(
            hidden_preparation,
            hidden_preparation_raw,
            hidden_lock,
            hidden_receipt,
        )
    calibration_lock_path = (
        ROOT / "benchmark" / "phase0-hidden-suite-calibration-v2.lock.json"
    )
    calibration_lock_raw = calibration_lock_path.read_bytes()
    calibration_lock = json.loads(calibration_lock_raw)
    calibration_receipt_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-suite-calibration-v2-freeze-2026-07-25.json"
    )
    calibration_receipt_raw = calibration_receipt_path.read_bytes()
    calibration_receipt = json.loads(calibration_receipt_raw)
    validators["benchmark-phase0-hidden-suite-lock-v1.schema.json"].validate(
        calibration_lock
    )
    validators["benchmark-phase0-hidden-suite-freeze-receipt-v2.schema.json"].validate(
        calibration_receipt
    )
    validate_freeze_receipt_bindings(
        calibration_receipt,
        calibration_receipt_raw,
        calibration_lock,
        calibration_lock_raw,
        phase0_corpus_lock,
        phase0_corpus_lock_raw,
    )
    calibration_preparation_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-calibration-v2-preparation-2026-07-25.json"
    )
    if calibration_preparation_path.exists():
        calibration_preparation_raw = calibration_preparation_path.read_bytes()
        calibration_preparation = json.loads(calibration_preparation_raw)
        validators[
            "benchmark-phase0-hidden-preparation-receipt-v2.schema.json"
        ].validate(calibration_preparation)
        validate_retained_preparation_receipt(
            calibration_preparation,
            calibration_preparation_raw,
            calibration_lock,
            calibration_receipt,
            _V2_GATE,
        )
    hidden_v3_lock_path = ROOT / "benchmark" / "phase0-hidden-suite-v3.lock.json"
    hidden_v3_lock_raw = hidden_v3_lock_path.read_bytes()
    hidden_v3_lock = json.loads(hidden_v3_lock_raw)
    hidden_v3_receipt_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-suite-v3-freeze-2026-07-26.json"
    )
    hidden_v3_receipt_raw = hidden_v3_receipt_path.read_bytes()
    hidden_v3_receipt = json.loads(hidden_v3_receipt_raw)
    validators["benchmark-phase0-hidden-suite-lock-v1.schema.json"].validate(
        hidden_v3_lock
    )
    validators["benchmark-phase0-hidden-suite-freeze-receipt-v3.schema.json"].validate(
        hidden_v3_receipt
    )
    validate_freeze_receipt_bindings(
        hidden_v3_receipt,
        hidden_v3_receipt_raw,
        hidden_v3_lock,
        hidden_v3_lock_raw,
        phase0_corpus_lock_v3,
        phase0_corpus_lock_v3_raw,
    )
    hidden_v3_preparation_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v3-preparation-2026-07-26.json"
    )
    if hidden_v3_preparation_path.exists():
        hidden_v3_preparation_raw = hidden_v3_preparation_path.read_bytes()
        hidden_v3_preparation = json.loads(hidden_v3_preparation_raw)
        validators[
            "benchmark-phase0-hidden-preparation-receipt-v3.schema.json"
        ].validate(hidden_v3_preparation)
        validate_retained_preparation_receipt(
            hidden_v3_preparation,
            hidden_v3_preparation_raw,
            hidden_v3_lock,
            hidden_v3_receipt,
            _V3_GATE,
        )
    hidden_v3_result_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v3-result-2026-07-26.json"
    )
    if hidden_v3_result_path.exists():
        if not hidden_v3_preparation_path.exists():
            raise AssertionError(
                "hidden v3 result requires its retained preparation receipt"
            )
        hidden_v3_result_raw = hidden_v3_result_path.read_bytes()
        hidden_v3_result = json.loads(hidden_v3_result_raw)
        validators[
            "benchmark-phase0-hidden-result-receipt-v1.schema.json"
        ].validate(hidden_v3_result)
        if hidden_v3_result_raw != canonical_json(hidden_v3_result):
            raise AssertionError("hidden v3 result receipt is not canonical JSON")
        worker_run = hidden_v3_result["worker_run_receipt"]
        gate_report = hidden_v3_result["gate_report"]
        source = hidden_v3_result["source"]
        worker_run_digest = (
            "sha256:" + hashlib.sha256(canonical_json(worker_run)).hexdigest()
        )
        gate_report_file_digest = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(gate_report, sort_keys=True).encode("ascii") + b"\n"
            ).hexdigest()
        )
        preparation_digest = (
            "sha256:" + hashlib.sha256(hidden_v3_preparation_raw).hexdigest()
        )
        hidden_v3_lock_digest = (
            "sha256:" + hashlib.sha256(hidden_v3_lock_raw).hexdigest()
        )
        if source["worker_run_receipt_digest"] != worker_run_digest:
            raise AssertionError("hidden v3 worker receipt digest drift")
        if source["gate_report_file_digest"] != gate_report_file_digest:
            raise AssertionError("hidden v3 gate report file digest drift")
        if source["evaluator_commit"] != worker_run["source"]["runner_commit"]:
            raise AssertionError("hidden v3 evaluator commit drift")
        if worker_run["source"]["preparation_receipt_digest"] != preparation_digest:
            raise AssertionError("hidden v3 preparation receipt digest drift")
        if worker_run["state"]["binding_digest"] != _V3_GATE.state_binding_digest:
            raise AssertionError("hidden v3 run state binding drift")
        if worker_run["composition"]["outcomes_digest"] != gate_report[
            "outcomes_digest"
        ]:
            raise AssertionError("hidden v3 outcome digest drift")
        expected_gate_bindings = {
            "corpus_lock_digest": hidden_v3_lock["corpus_lock_digest"],
            "public_manifest_digest": hidden_v3_lock["public_manifest_digest"],
            "hidden_suite_lock_digest": hidden_v3_lock_digest,
            "candidate_policy_digest": hidden_v3_lock["candidate_policy_digest"],
            "label_ledger_digest": hidden_v3_lock["label_ledger_digest"],
            "suite_digest": hidden_v3_lock["suite_digest"],
        }
        for field, expected in expected_gate_bindings.items():
            if gate_report[field] != expected:
                raise AssertionError(f"hidden v3 gate report {field} drift")
        comparison = gate_report["comparison"]
        if (
            comparison["evaluable"]
            or comparison["passed"]
            or comparison["attack_flag_delta"] is not None
            or comparison["selected_comparator"] is not None
            or comparison["reason_codes"]
            != [
                "CANDIDATE_BURDEN_CEILING_EXCEEDED",
                "NO_BURDEN_COMPLIANT_COMPARATOR",
            ]
        ):
            raise AssertionError(
                "hidden v3 result is not the retained non-evaluable comparison"
            )
    calibration_result_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-calibration-v2-result-2026-07-25.json"
    )
    if calibration_result_path.exists():
        if not calibration_preparation_path.exists():
            raise AssertionError(
                "calibration result requires its retained preparation receipt"
            )
        calibration_result_raw = calibration_result_path.read_bytes()
        calibration_result = json.loads(calibration_result_raw)
        validators[
            "benchmark-phase0-hidden-calibration-result-receipt-v1.schema.json"
        ].validate(calibration_result)
        if calibration_result_raw != canonical_json(calibration_result):
            raise AssertionError("calibration result receipt is not canonical JSON")
        worker_run = calibration_result["worker_run_receipt"]
        gate_report = calibration_result["gate_report"]
        source = calibration_result["source"]
        worker_run_digest = (
            "sha256:" + hashlib.sha256(canonical_json(worker_run)).hexdigest()
        )
        gate_report_file_digest = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(gate_report, sort_keys=True).encode("ascii") + b"\n"
            ).hexdigest()
        )
        preparation_digest = (
            "sha256:" + hashlib.sha256(calibration_preparation_raw).hexdigest()
        )
        calibration_lock_digest = (
            "sha256:" + hashlib.sha256(calibration_lock_raw).hexdigest()
        )
        if source["worker_run_receipt_digest"] != worker_run_digest:
            raise AssertionError("calibration worker receipt digest drift")
        if source["gate_report_file_digest"] != gate_report_file_digest:
            raise AssertionError("calibration gate report file digest drift")
        if source["evaluator_commit"] != worker_run["source"]["runner_commit"]:
            raise AssertionError("calibration evaluator commit drift")
        if (
            worker_run["source"]["preparation_receipt_digest"]
            != preparation_digest
        ):
            raise AssertionError("calibration preparation receipt digest drift")
        if worker_run["state"]["binding_digest"] != _V2_GATE.state_binding_digest:
            raise AssertionError("calibration run state binding drift")
        if (
            worker_run["limitations"]["evaluation_status"]
            != calibration_result["evaluation_status"]
        ):
            raise AssertionError("calibration run status drift")
        if (
            worker_run["composition"]["outcomes_digest"]
            != gate_report["outcomes_digest"]
        ):
            raise AssertionError("calibration outcome digest drift")
        expected_gate_bindings = {
            "corpus_lock_digest": calibration_lock["corpus_lock_digest"],
            "public_manifest_digest": calibration_lock["public_manifest_digest"],
            "hidden_suite_lock_digest": calibration_lock_digest,
            "candidate_policy_digest": calibration_lock[
                "candidate_policy_digest"
            ],
            "label_ledger_digest": calibration_lock["label_ledger_digest"],
            "suite_digest": calibration_lock["suite_digest"],
        }
        for field, expected in expected_gate_bindings.items():
            if gate_report[field] != expected:
                raise AssertionError(f"calibration gate report {field} drift")
        if gate_report["comparison"]["passed"]:
            raise AssertionError("retained calibration result unexpectedly passed")
    validators["benchmark-phase0-hidden-worker-run-receipt-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v1",
            "assurance": (
                "authenticated_complete_worker_batch_not_independent_or_hardware_attested"
            ),
            "source": {
                "runner_commit": "1" * 40,
                "preparation_receipt_digest": digest,
            },
            "state": {
                "layout": "phase0-hidden-run-state/v1",
                "binding_digest": digest,
            },
            "batch": {
                "accepted_count": 896,
                "acceptance_set_digest": digest,
                "result_set_digest": digest,
            },
            "composition": {
                "composition_digest": digest,
                "outcomes_digest": digest,
                "outcomes_file_digest": digest,
                "outcome_count": 1_344,
            },
            "limitations": {
                "authorship": (
                    "technical_codex_authorship_not_independent_human_identity"
                ),
                "custody": (
                    "software_signatures_operator_uid_trusted_not_same_uid_or_hardware_attested"
                ),
                "worker_attestation": (
                    "software_key_possession_not_vm_or_hardware_attestation"
                ),
            },
        }
    )
    validators["benchmark-phase0-hidden-worker-run-receipt-v2.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v2",
            "assurance": (
                "authenticated_complete_worker_batch_not_independent_or_hardware_attested"
            ),
            "source": {
                "runner_commit": "1" * 40,
                "preparation_receipt_digest": digest,
            },
            "state": {
                "layout": "phase0-hidden-run-state/v1",
                "binding_digest": _V2_GATE.state_binding_digest,
            },
            "batch": {
                "accepted_count": 896,
                "acceptance_set_digest": digest,
                "result_set_digest": digest,
            },
            "composition": {
                "composition_digest": digest,
                "outcomes_digest": digest,
                "outcomes_file_digest": digest,
                "outcome_count": 1_344,
            },
            "limitations": {
                "authorship": (
                    "technical_codex_authorship_not_independent_human_identity"
                ),
                "custody": (
                    "software_signatures_operator_uid_trusted_not_same_uid_or_hardware_attested"
                ),
                "worker_attestation": (
                    "software_key_possession_not_vm_or_hardware_attestation"
                ),
                "evaluation_status": (
                    "calibration_rerun_on_previously_evaluated_corpus_not_fresh_holdout"
                ),
            },
        }
    )
    validators["benchmark-phase0-hidden-worker-run-receipt-v3.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v3",
            "assurance": (
                "authenticated_complete_worker_batch_not_independent_or_hardware_attested"
            ),
            "source": {
                "runner_commit": "1" * 40,
                "preparation_receipt_digest": digest,
            },
            "state": {
                "layout": "phase0-hidden-run-state/v1",
                "binding_digest": _V3_GATE.state_binding_digest,
            },
            "batch": {
                "accepted_count": 896,
                "acceptance_set_digest": digest,
                "result_set_digest": digest,
            },
            "composition": {
                "composition_digest": digest,
                "outcomes_digest": digest,
                "outcomes_file_digest": digest,
                "outcome_count": 1_344,
            },
            "limitations": {
                "authorship": (
                    "technical_codex_authorship_not_independent_human_identity"
                ),
                "custody": (
                    "software_signatures_operator_uid_trusted_not_same_uid_or_hardware_attested"
                ),
                "worker_attestation": (
                    "software_key_possession_not_vm_or_hardware_attestation"
                ),
            },
        }
    )
    comparator_system = {
        "name": "cisco-skill-scanner",
        "version": "2.0.12",
        "implementation_digest": digest,
        "config_digest": second_digest,
    }
    candidate_policy = {
        "schema": "aragorn/benchmark-candidate-policy/v1",
        "assurance": "comparative_candidate_only_not_admission",
        "algorithm": "source-graph-fail-closed-vendor-union/v1",
        "candidate": {
            "name": "aragorn",
            "version": "0.1.0-phase0",
            "implementation_digest": third_digest,
        },
        "required_comparators": [
            comparator_system,
            {
                "name": "skillspector",
                "version": "2.4.3",
                "implementation_digest": second_digest,
                "config_digest": third_digest,
            },
        ],
    }
    candidate_system = {
        **candidate_policy["candidate"],
        "config_digest": digest,
    }
    validators["benchmark-candidate-policy-v1.schema.json"].validate(candidate_policy)
    private_dispatch_v2 = {
        "schema": "aragorn/benchmark-private-dispatch/v2",
        "suite_digest": digest,
        "candidate_system": candidate_system,
        "candidate_policy_digest": digest,
        "runs_per_case": 1,
        "cases": [
            {
                "case_id": "schema-test",
                "tree_digest": digest,
                "private_manifest_digest": digest,
            }
        ],
        "jobs": [
            {
                "job_id": "0" * 32,
                "request_digest": digest,
                "suite_digest": digest,
                "case_id": "schema-test",
                "run_id": 1,
                "system": comparator_system,
                "tree_digest": digest,
                "private_manifest_digest": digest,
            }
        ],
    }
    validators["benchmark-private-dispatch-v2.schema.json"].validate(
        private_dispatch_v2
    )
    validators["benchmark-prepare-result-v2.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-prepare-result/v2",
            "suite_digest": digest,
            "dispatch_digest": digest,
            "candidate_policy_digest": digest,
            "worker_identities_digest": digest,
            "worklist_digest": digest,
            "job_count": 1,
        }
    )
    authenticated_worker_evidence = {
        "schema": "aragorn/benchmark-authenticated-worker-evidence/v1",
        "suite_digest": digest,
        "case_id": "schema-test",
        "tree_digest": digest,
        "run_id": 1,
        "system": comparator_system,
        "verdict": "ALLOW",
        "reason_codes": [],
        "private_manifest_digest": digest,
        "dispatch_digest": digest,
        "acceptance_receipt_digest": digest,
        "issuance_digest": digest,
    }
    validators["benchmark-authenticated-worker-evidence-v1.schema.json"].validate(
        authenticated_worker_evidence
    )
    candidate_evidence = {
        "schema": "aragorn/benchmark-candidate-evidence/v1",
        "suite_digest": digest,
        "case_id": "schema-test",
        "tree_digest": digest,
        "run_id": 1,
        "system": candidate_system,
        "verdict": "ALLOW",
        "reason_codes": [],
        "private_manifest_digest": digest,
        "source_graph_digest": digest,
        "dispatch_digest": digest,
        "policy_digest": digest,
        "component_evidence_digests": [digest, second_digest],
    }
    validators["benchmark-candidate-evidence-v1.schema.json"].validate(
        candidate_evidence
    )
    validators["benchmark-candidate-evidence-v2.schema.json"].validate(
        {
            **candidate_evidence,
            "schema": "aragorn/benchmark-candidate-evidence/v2",
            "first_party_observation_digests": [],
        }
    )
    validators["benchmark-candidate-composition-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-candidate-composition/v1",
            "assurance": (
                "derived_from_authenticated_comparator_evidence_not_hardware_attested"
            ),
            "suite_digest": digest,
            "dispatch_digest": digest,
            "policy_digest": digest,
            "outcomes_digest": digest,
            "outcomes": [
                {
                    "schema": "aragorn/benchmark-outcome/v1",
                    "suite_digest": digest,
                    "case_id": "schema-test",
                    "tree_digest": digest,
                    "run_id": 1,
                    "system": candidate_system,
                    "evidence_digest": third_digest,
                    "verdict": "ALLOW",
                    "reason_codes": [],
                }
            ],
        }
    )
    validators["benchmark-prepare-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-prepare-result/v1",
            "suite_digest": digest,
            "dispatch_digest": digest,
            "worker_identities_digest": digest,
            "worklist_digest": digest,
            "job_count": 1,
        }
    )
    validators["benchmark-collection-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-collection-result/v1",
            "assurance": "unsigned_label_free_protocol_not_isolated_or_attested",
            "suite_digest": digest,
            "dispatch_digest": digest,
            "ledger_id": digest,
            "collection_digest": digest,
            "outcomes_digest": digest,
            "report_digest": digest,
            "job_count": 1,
        }
    )
    baseline = baseline_lock["baselines"][0]
    files = [
        {
            "path": "SKILL.md",
            "size": 0,
            "digest": digest,
            "executable": False,
        }
    ]
    subject = {
        "schema": "aragorn/benchmark-subject-manifest/v1",
        "tree_digest": canonical_digest(files),
        "files": files,
    }
    portable_policy = {
        "schema": "aragorn/benchmark-portable-policy/v1",
        "system": {
            "name": baseline["name"],
            "version": baseline["version"],
            "implementation_digest": baseline["image"]["platform_manifest_digest"],
        },
        "baseline": {
            "lock_digest": canonical_digest(baseline_lock),
            "entry_digest": canonical_digest(baseline),
        },
        "image": {
            key: baseline["image"][key]
            for key in (
                "index_digest",
                "platform_manifest_digest",
                "config_digest",
                "build_provenance_manifest_digest",
                "os",
                "architecture",
                "size_bytes",
            )
        },
        "entrypoint": ["/opt/venv/bin/skill-scanner"],
        "arguments": [
            ("/workspace" if argument == "{workspace}" else argument)
            for argument in baseline["profile"]["arguments"]
        ],
        "environment": {},
        "runtime_profile": baseline["runtime_profile"],
        "limits": {
            "timeout_seconds": 120.0,
            "output_bytes": 1024 * 1024,
        },
        "normalization": "cisco-ai-skill-scanner-2.0.12/v1",
    }
    validators["benchmark-portable-policy-v1.schema.json"].validate(portable_policy)
    request_v2 = build_worker_request_v2(
        subject,
        portable_policy,
        verifier_challenge="a" * 64,
        token_hex=lambda _size: "b" * 32,
    )
    validators["benchmark-worker-request-v2.schema.json"].validate(request_v2)
    request_v2_digest = canonical_request_digest_v2(request_v2)
    result_v2 = {
        "schema": "aragorn/benchmark-worker-result/v2",
        "job_id": request_v2["job_id"],
        "verifier_challenge": request_v2["verifier_challenge"],
        "request_digest": request_v2_digest,
        "portable_policy_digest": portable_policy_digest(portable_policy),
        "subject_manifest_digest": request_v2["subject"]["manifest_digest"],
        "tree_digest": request_v2["subject"]["tree_digest"],
        "verified_subject_digest": request_v2["subject"]["tree_digest"],
        "system": request_v2["system"],
        "baseline_lock_digest": request_v2["baseline"]["lock_digest"],
        "baseline_entry_digest": request_v2["baseline"]["entry_digest"],
        "effective_config_digest": digest,
        "docker_executable_digest": digest,
        "oci_index_digest": portable_policy["image"]["index_digest"],
        "oci_platform_manifest_digest": portable_policy["image"][
            "platform_manifest_digest"
        ],
        "build_provenance_manifest_digest": portable_policy["image"][
            "build_provenance_manifest_digest"
        ],
        "index_inspect_digest": digest,
        "platform_inspect_digest": digest,
        "image_config_digest": portable_policy["image"]["config_digest"],
        "runner_receipts": {
            phase: {
                "context_inspect_digest": digest,
                "daemon_version_digest": digest,
                "daemon_info_digest": digest,
            }
            for phase in ("pre", "post")
        },
        "prestart_container_inspect_digest": digest,
        "postrun_container_inspect_digest": digest,
        "stdout_digest": digest,
        "stderr_digest": digest,
        "observation_digests": [],
        "execution": {
            "status": "ok",
            "error_code": None,
            "returncode": 0,
            "container_id": "c" * 64,
        },
        "normalization": portable_policy["normalization"],
        "verdict": "ALLOW",
        "reason_codes": [],
    }
    validate_worker_result_v2(result_v2)
    verify_request_result_binding_v2(
        request_v2,
        portable_policy,
        result_v2,
        expected_request_digest=request_v2_digest,
        expected_challenge=request_v2["verifier_challenge"],
    )
    result_v2_validator = validators["benchmark-worker-result-v2.schema.json"]
    result_v2_validator.validate(result_v2)
    invalid_result_v2 = deepcopy(result_v2)
    invalid_result_v2["normalization"] = "nvidia-skillspector-2.4.3/v1"
    if result_v2_validator.is_valid(invalid_result_v2):
        raise AssertionError(
            "worker result v2 schema accepted cross-system normalization"
        )
    invalid_result_v2 = deepcopy(result_v2)
    invalid_result_v2["execution"] = {
        "status": "error",
        "error_code": "TIMEOUT",
        "returncode": -1,
        "container_id": "c" * 64,
    }
    invalid_result_v2["verdict"] = "DENY"
    invalid_result_v2["reason_codes"] = ["ANALYZER_TIMEOUT"]
    if result_v2_validator.is_valid(invalid_result_v2):
        raise AssertionError(
            "worker result v2 schema accepted an unbound error verdict"
        )
    invalid_result_v2 = deepcopy(result_v2)
    invalid_result_v2["observation_digests"] = [digest, digest]
    if result_v2_validator.is_valid(invalid_result_v2):
        raise AssertionError("worker result v2 schema accepted duplicate observations")
    public_key = bytes(range(32))
    key_id = "sha256:" + hashlib.sha256(public_key).hexdigest()
    trust_store = build_worker_trust_store(
        trust_domain="phase0.example",
        keys=[
            {
                "key_id": key_id,
                "algorithm": "Ed25519",
                "public_key": public_key.hex(),
                "worker_id": "isolated-worker-01",
                "scopes": ["aragorn/benchmark-worker-output/v2"],
                "status": "active",
            }
        ],
    )
    validators["benchmark-worker-trust-store-v1.schema.json"].validate(trust_store)
    measurement = build_worker_measurement(
        trust_domain=trust_store["trust_domain"],
        worker_id=trust_store["keys"][0]["worker_id"],
        key_id=key_id,
        job_id=request_v2["job_id"],
        verifier_challenge=request_v2["verifier_challenge"],
        request_digest=request_v2_digest,
        result_digest=digest,
        handoff_manifest_digest=digest,
    )
    validators["benchmark-worker-measurement-v1.schema.json"].validate(measurement)
    issuance = {
        "schema": "aragorn/benchmark-worker-measurement-issuance/v1",
        "trust_domain": measurement["trust_domain"],
        "worker_id": measurement["worker_id"],
        "job_id": measurement["job_id"],
        "request_digest": measurement["request_digest"],
        "verifier_challenge": measurement["verifier_challenge"],
    }
    validators["benchmark-worker-measurement-issuance-v1.schema.json"].validate(
        issuance
    )
    validators["benchmark-worker-output-acceptance-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-worker-output-acceptance/v1",
            "assurance": "software_key_signature_not_hardware_attested",
            "issuance_digest": canonical_digest(issuance),
            "trust_store_digest": canonical_digest(trust_store),
            "envelope_digest": digest,
            "key_id": key_id,
            "trust_domain": measurement["trust_domain"],
            "worker_id": measurement["worker_id"],
            "job_id": measurement["job_id"],
            "verifier_challenge": measurement["verifier_challenge"],
            "request_digest": measurement["request_digest"],
            "result_digest": measurement["result_digest"],
            "handoff_manifest_digest": measurement["handoff_manifest_digest"],
        }
    )
    validators["benchmark-worker-supervisor-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-worker-supervisor-result/v1",
            "assurance": "software_key_signature_not_hardware_attested",
            "request_digest": request_v2_digest,
            "result_digest": digest,
            "handoff_manifest_digest": digest,
            "envelope_digest": digest,
        }
    )
    validators["benchmark-cas-handoff-v1.schema.json"].validate(
        build_handoff_manifest(
            kind="worker_input",
            root_digest=digest,
            blobs={digest: 0},
        )
    )

    expansion_accounting = {
        "references": {
            "total_edges": 0,
            "artifact_references": 0,
            "resolved_in_root": 0,
            "expanded": 0,
            "deduplicated": 0,
            "non_artifact": 0,
            "unresolved": 0,
            "opaque_carriers": 0,
            "scan_complete": True,
            "occurrences_complete": True,
            "occurrences_omitted": 0,
        },
        "budgets": {
            "api_requests": {"limit": 20_050, "used": 2},
            "api_bytes": {"limit": 402_653_184, "used": 1024},
            "retained_bytes": {"limit": 134_217_728, "used": 0},
            "expanded_objects": {"limit": 256, "used": 0},
            "expansion_depth": {"limit": 4, "used": 0},
            "references": {"limit": 10_000, "used": 0},
        },
    }
    expansion = {
        "schema": "aragorn/github-expansion/v1",
        "profile": "phase0-exact-github-blob-expansion/v1",
        "assurance": (
            "evaluation_only_github_api_membership_asserted_blob_identity_reverified"
        ),
        "source": {
            "host": "github.com",
            "owner": "example",
            "repository": "project",
            "commit": "0" * 40,
            "commit_tree": "1" * 40,
            "skill_path": "skills/demo",
            "api_version": "2026-03-10",
        },
        "root_manifest_digest": digest,
        "root_tree_digest": digest,
        "comparator_subject_manifest_digest": digest,
        "comparator_subject_tree_digest": digest,
        "references": [],
        "objects": [],
        "accounting": expansion_accounting,
        "closure": {
            "scope": "phase0_exact_github_blob_expansion",
            "status": "complete",
            "unresolved": [],
        },
    }
    validators["github-expansion-v1.schema.json"].validate(expansion)
    terminal_expansion = deepcopy(expansion)
    terminal_expansion["profile"] = (
        "phase0-exact-github-blob-expansion-terminal-depth-1/v1"
    )
    terminal_expansion["assurance"] = (
        "evaluation_only_github_api_membership_asserted_blob_identity_reverified_"
        "depth_1_targets_terminal_not_reference_scanned"
    )
    terminal_expansion["accounting"]["budgets"]["expansion_depth"]["limit"] = 1
    terminal_expansion["closure"]["scope"] = (
        "phase0_exact_github_blob_expansion_terminal_depth_1"
    )
    validators["github-expansion-v1.schema.json"].validate(terminal_expansion)
    expansion_result = {
        "schema": "aragorn/github-expansion-result/v1",
        "expansion_digest": digest,
        "root_manifest_digest": digest,
        "root_tree_digest": digest,
        "comparator_subject_manifest_digest": digest,
        "comparator_subject_tree_digest": digest,
        "expanded_object_count": 0,
        "accounting": expansion_accounting,
        "closure": expansion["closure"],
    }
    validators["github-expansion-result-v1.schema.json"].validate(expansion_result)
    incomplete_expansion = deepcopy(expansion)
    incomplete_expansion["comparator_subject_manifest_digest"] = None
    incomplete_expansion["comparator_subject_tree_digest"] = None
    incomplete_expansion["closure"] = {
        "scope": "phase0_exact_github_blob_expansion",
        "status": "incomplete",
        "unresolved": [
            {
                "reason_code": "MUTABLE_GITHUB_REFERENCE",
                "subject": "skills/demo/SKILL.md",
            }
        ],
    }
    validators["github-expansion-v1.schema.json"].validate(incomplete_expansion)
    source_graph = {
        "schema": "aragorn/source-artifact-graph/v1",
        "profile": "phase0-literal-source-refs/v1",
        "assurance": "evaluation_only_literal_reference_profile",
        "source_assurance": "local_manifest_reverified",
        "root_manifest_digest": digest,
        "tree_digest": digest,
        "nodes": [
            {
                "path": "SKILL.md",
                "size": 0,
                "digest": digest,
                "executable": False,
                "scan_status": "scanned",
                "opaque_reason": None,
            }
        ],
        "edges": [],
        "closure": {
            "scope": "source_reference_graph",
            "profile": "phase0-literal-source-refs/v1",
            "status": "complete",
            "unresolved": [],
        },
    }
    validators["source-artifact-graph-v1.schema.json"].validate(source_graph)
    validators["resolve-artifacts-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/resolve-artifacts-result/v1",
            "assurance": "evaluation_only_literal_reference_profile",
            "root_manifest_digest": digest,
            "graph_digest": digest,
            "closure": source_graph["closure"],
        }
    )
    graph_validator = validators["source-artifact-graph-v1.schema.json"]
    opaque_complete = deepcopy(source_graph)
    opaque_complete["nodes"][0]["scan_status"] = "opaque"
    opaque_complete["nodes"][0]["opaque_reason"] = "NON_UTF8_CARRIER"
    if graph_validator.is_valid(opaque_complete):
        raise AssertionError("complete source graph accepted an opaque node")
    unresolved_complete = deepcopy(source_graph)
    unresolved_complete["edges"] = [
        {
            "source_path": "SKILL.md",
            "source_blob_digest": digest,
            "byte_offset": 0,
            "literal_digest": digest,
            "reference_kind": "external",
            "status": "unresolved",
            "literal": "https://example.test/payload",
            "target": None,
            "reason_code": "EXTERNAL_REFERENCE_UNSUPPORTED",
        }
    ]
    if graph_validator.is_valid(unresolved_complete):
        raise AssertionError("complete source graph accepted an unresolved edge")
    resolved_dynamic = deepcopy(source_graph)
    resolved_dynamic["edges"] = [
        {
            "source_path": "SKILL.md",
            "source_blob_digest": digest,
            "byte_offset": 0,
            "literal_digest": digest,
            "reference_kind": "dynamic_command",
            "status": "resolved",
            "literal": None,
            "target": {"path": "SKILL.md", "digest": digest},
            "reason_code": None,
        }
    ]
    if graph_validator.is_valid(resolved_dynamic):
        raise AssertionError("source graph accepted a resolved dynamic command")
    decision = {
        "schema": "aragorn/decision/v1",
        "verdict": "ERROR",
        "manifest_digest": digest,
        "tree_digest": digest,
        "artifact_digests": [],
        "policy": {"id": "schema-test", "version": 1, "digest": digest},
        "analyzers": [],
        "reason_codes": ["SCHEMA_TEST"],
    }
    validators["inspect-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/inspect-result/v1",
            "decision_digest": digest,
            "decision": decision,
        }
    )
    print(f"validated {len(schemas)} schemas and checked-in contract examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
