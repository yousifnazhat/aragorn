"""Validate Aragorn schemas and checked-in contract examples."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from copy import deepcopy
from io import BytesIO
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
from materialize_fixed_admission_probes import (
    transformed_restore_authority_probe,
)
from prepare_hidden_suite import (
    _V2_GATE,
    _V3_GATE,
    _V4_GATE,
    _V5_GATE,
    _V6_GATE,
    _V7_GATE,
    validate_retained_preparation_receipt,
)

from aragorn.acquire import ingest_local
from aragorn.admission_conformance import (
    MANDATORY_ADMISSION_SCENARIOS,
)
from aragorn.admission_evidence import (
    verify_openclaw_config_activation_slice_evidence,
    verify_openclaw_deterministic_replay_evidence,
    verify_openclaw_live_reload_cron_slice_evidence,
    verify_openclaw_live_reload_slice_evidence,
    verify_openclaw_model_activation_evidence,
    verify_openclaw_restart_evidence,
    verify_openclaw_update_reload_coverage,
    verify_openclaw_update_slice_evidence,
)
from aragorn.admission_evidence_broker import (
    verify_openclaw_broker_symlink_evidence,
)
from aragorn.admission_evidence_plug01 import (
    verify_openclaw_update_reload_coverage_v2,
)
from aragorn.admission_evidence_workshop import (
    verify_openclaw_update_reload_coverage_v3,
)
from aragorn.admission_gate import validate_retained_admission_conformance
from aragorn.admission_protected_archive import (
    verify_openclaw_protected_archive_replacement,
)
from aragorn.admission_protected_config import (
    verify_openclaw_protected_config_activation,
)
from aragorn.admission_protected_cron import (
    verify_openclaw_protected_cron_rescan,
)
from aragorn.admission_protected_curator_restore import (
    verify_openclaw_protected_curator_restore_denial,
)
from aragorn.admission_protected_final_combined_v2_archive_replacement import (
    verify_openclaw_final_combined_v2_archive_replacement,
)
from aragorn.admission_protected_final_combined_v2_catalog_fixed_fresh_session_reset import (
    verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset,
)
from aragorn.admission_protected_final_combined_v2_config_activation import (
    verify_openclaw_final_combined_v2_config_activation,
)
from aragorn.admission_protected_final_combined_v2_cron_rescan import (
    verify_openclaw_final_combined_v2_cron_rescan,
)
from aragorn.admission_protected_final_combined_v2_cron_rescan_catalog_fixed import (
    verify_openclaw_final_combined_v2_cron_rescan_catalog_fixed,
)
from aragorn.admission_protected_final_combined_v2_fresh_session_reset import (
    verify_openclaw_final_combined_v2_fresh_session_reset,
)
from aragorn.admission_protected_final_combined_v2_prompt_rebuild import (
    verify_openclaw_final_combined_v2_prompt_rebuild,
)
from aragorn.admission_protected_final_combined_v2_session_snapshot_consumer import (
    verify_openclaw_final_combined_v2_session_snapshot_consumer,
)
from aragorn.admission_protected_final_fresh_session_reset import (
    verify_openclaw_final_fresh_session_reset,
)
from aragorn.admission_protected_profile import (
    compose_openclaw_protected_profile_coverage,
    compose_openclaw_protected_profile_coverage_v2,
    compose_openclaw_protected_profile_coverage_v3,
)
from aragorn.admission_protected_prompt import (
    verify_openclaw_protected_prompt_rebuild,
)
from aragorn.admission_protected_restore_authority_archive import (
    verify_openclaw_protected_restore_authority_archive_replacement,
)
from aragorn.admission_protected_restore_authority_chat import (
    verify_openclaw_protected_restore_authority_chat,
)
from aragorn.admission_protected_restore_authority_config import (
    verify_openclaw_protected_restore_authority_config_activation,
)
from aragorn.admission_protected_restore_authority_cron import (
    verify_openclaw_protected_restore_authority_cron_rescan,
)
from aragorn.admission_protected_restore_authority_fresh_session import (
    verify_openclaw_protected_restore_authority_fresh_session_reset,
)
from aragorn.admission_protected_restore_authority_prompt import (
    verify_openclaw_protected_restore_authority_prompt_rebuild,
)
from aragorn.admission_protected_restore_authority_session_consumer import (
    verify_openclaw_protected_restore_authority_session_snapshot_consumer,
)
from aragorn.admission_protected_restore_authority_workshop import (
    verify_openclaw_protected_restore_authority_workshop_proposal_apply,
)
from aragorn.admission_protected_session_snapshot import (
    verify_openclaw_protected_session_snapshot,
)
from aragorn.admission_protected_session_snapshot_fixed import (
    verify_openclaw_protected_session_snapshot_fixed,
)
from aragorn.admission_protected_session_snapshot_fixed_chat import (
    verify_openclaw_protected_session_snapshot_fixed_chat,
)
from aragorn.admission_protected_session_snapshot_fixed_fresh_session import (
    verify_openclaw_protected_session_snapshot_fixed_fresh_session,
)
from aragorn.admission_protected_session_snapshot_fixed_routes import (
    verify_openclaw_protected_session_snapshot_fixed_routes,
)
from aragorn.admission_routes import validate_openclaw_2026_7_1_route_inventory
from aragorn.admission_runtime_profile import (
    load_runtime_profile,
    verify_openclaw_protected_workshop_route,
)
from aragorn.artifact_closure import resolve_source_graph
from aragorn.behavior_capability_diff import derive_behavior_capability_diff
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
from aragorn.detonation_observation import (
    SOURCE_SCHEMA,
    retain_detonation_capability_diff,
    retain_detonation_observation,
)
from aragorn.github_gateway_live_evidence import (
    verify_github_gateway_live_evidence,
)
from aragorn.gvisor_runtime import (
    ARTIFACT_ATTRIBUTED_NORMALIZATION_PROFILE,
    ARTIFACT_ATTRIBUTION_AUTHORITY,
    ARTIFACT_ATTRIBUTION_SCHEMA,
    ARTIFACT_AUTHORITY_V4,
    ARTIFACT_AUTHORITY_V5,
    ARTIFACT_EXECUTION_PROFILE_V2,
    ARTIFACT_SCHEMA_V4,
    ARTIFACT_SCHEMA_V5,
)
from aragorn.label_blind_prepare import validate_private_dispatch_v2
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_acquisition_action_binding import (
    runtime_acquisition_action_binding_qualification,
)
from aragorn.runtime_acquisition_action_multifile_systemd_evidence import (
    runtime_acquisition_action_multifile_systemd_qualification,
)
from aragorn.runtime_acquisition_action_nested_systemd_evidence import (
    runtime_acquisition_action_nested_systemd_qualification,
)
from aragorn.runtime_acquisition_action_systemd_evidence import (
    runtime_acquisition_action_systemd_qualification,
)
from aragorn.runtime_action_worker_activation_expiry_systemd_evidence import (
    runtime_action_worker_activation_expiry_systemd_qualification,
)
from aragorn.runtime_action_worker_openclaw_systemd_evidence import (
    runtime_action_worker_openclaw_systemd_qualification,
)
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

    digest = "sha256:" + "0" * 64
    behavior_capability_diff = derive_behavior_capability_diff(
        subject_digest=digest,
        declared_capabilities=["file-read"],
        observed_capabilities=["file-read", "network-connect"],
    )
    validators["behavior-capability-diff-v1.schema.json"].validate(
        behavior_capability_diff
    )
    with TemporaryDirectory() as temporary:
        cas = CAS(Path(temporary) / "detonation-observation-cas")
        source_event = canonical_json(
            {
                "schema": SOURCE_SCHEMA,
                "operation": "file-open-read",
                "detail": "schema validation source event",
            }
        )
        validators["detonation-source-event-v1.schema.json"].validate(
            json.loads(source_event)
        )
        observation_digest = retain_detonation_observation(
            cas,
            source_event,
            subject_digest=digest,
            input_manifest_digest=digest,
            input_tree_digest=digest,
            run_request_digest=digest,
            normalizer_implementation_digest=digest,
        )
        validators["detonation-observation-v1.schema.json"].validate(
            json.loads(cas.read(observation_digest))
        )
        source_event_digest = "sha256:" + hashlib.sha256(source_event).hexdigest()
        diff_receipt_digest = retain_detonation_capability_diff(
            cas,
            {observation_digest: source_event_digest},
            subject_digest=digest,
            input_manifest_digest=digest,
            input_tree_digest=digest,
            run_request_digest=digest,
            normalizer_implementation_digest=digest,
            declared_capabilities=["file-read"],
        )
        validators["detonation-capability-diff-receipt-v1.schema.json"].validate(
            json.loads(cas.read(diff_receipt_digest))
        )
    validators["gvisor-runtime-smoke-receipt-v1.schema.json"].validate(
        load(
            ROOT
            / "benchmark"
            / "receipts"
            / "phase2-gvisor-runtime-smoke-b86096ddeed564a5938ae9dc1819c7a8-2026-08-02.json"
        )
    )
    validators["gvisor-detonation-canary-receipt-v1.schema.json"].validate(
        load(
            ROOT
            / "benchmark"
            / "receipts"
            / (
                "phase2-gvisor-detonation-canary-"
                "7838a22fbd2de49b6f833443ca60f45e-2026-08-02.json"
            )
        )
    )
    for run_id in (
        "4147e7ee2b15c6ada9832112122225f4",
        "a34474048ae9cdd792c2d2c37c9cb4c0",
    ):
        validators["gvisor-acquired-artifact-receipt-v1.schema.json"].validate(
            load(
                ROOT
                / "benchmark"
                / "receipts"
                / f"phase2-gvisor-acquired-artifact-{run_id}-2026-08-02.json"
            )
        )
    validators["gvisor-acquired-artifact-receipt-v2.schema.json"].validate(
        load(
            ROOT
            / "benchmark"
            / "receipts"
            / (
                "phase2-gvisor-acquired-artifact-v2-"
                "e55ef93d8538c50c94dee1c25899faf0-2026-08-02.json"
            )
        )
    )
    validators["gvisor-acquired-artifact-receipt-v3.schema.json"].validate(
        load(
            ROOT
            / "benchmark"
            / "receipts"
            / (
                "phase2-gvisor-acquired-artifact-v3-"
                "0b6ec3ea4b469e9f0ad26728a8711ecf-2026-08-02.json"
            )
        )
    )
    attributed_receipt = deepcopy(
        load(
            ROOT
            / "benchmark"
            / "receipts"
            / (
                "phase2-gvisor-acquired-artifact-v3-"
                "0b6ec3ea4b469e9f0ad26728a8711ecf-2026-08-02.json"
            )
        )
    )
    attributed_receipt.update(
        {
            "schema": ARTIFACT_SCHEMA_V4,
            "authority": ARTIFACT_AUTHORITY_V4,
            "normalization_profile": ARTIFACT_ATTRIBUTED_NORMALIZATION_PROFILE,
            "attribution_manifest_digest": digest,
        }
    )
    attributed_receipt["entrypoint"]["executable"] = False
    validators["gvisor-acquired-artifact-receipt-v4.schema.json"].validate(
        attributed_receipt
    )
    scenario_receipt = deepcopy(attributed_receipt)
    scenario_receipt.update(
        {
            "schema": ARTIFACT_SCHEMA_V5,
            "authority": ARTIFACT_AUTHORITY_V5,
            "execution_profile": ARTIFACT_EXECUTION_PROFILE_V2,
            "scenario_id": "primary",
        }
    )
    validators["gvisor-acquired-artifact-receipt-v5.schema.json"].validate(
        scenario_receipt
    )
    validators[
        "gvisor-artifact-actor-attribution-manifest-v1.schema.json"
    ].validate(
        {
            "schema": ARTIFACT_ATTRIBUTION_SCHEMA,
            "authority": ARTIFACT_ATTRIBUTION_AUTHORITY,
            "normalization_profile": ARTIFACT_ATTRIBUTED_NORMALIZATION_PROFILE,
            "entrypoint": {
                "path": attributed_receipt["entrypoint"]["path"],
                "container_path": attributed_receipt["entrypoint"]["container_path"],
                "digest": attributed_receipt["entrypoint"]["digest"],
            },
            "boundary": {
                "tgid": 1,
                "tid": 1,
                "entered_record": 10,
                "exited_record": 11,
            },
            "events": [
                {
                    "sequence": sequence,
                    "scope": scope,
                    "tgid": 1,
                    "tid": 1,
                    "process": process,
                    "syscall": syscall,
                    "entered_record": entered,
                    "exited_record": exited,
                    "result": result,
                    "operation": operation,
                    "detail": detail,
                }
                for sequence, (
                    scope,
                    process,
                    syscall,
                    entered,
                    exited,
                    result,
                    operation,
                    detail,
                ) in enumerate(
                    (
                        (
                            "harness",
                            "sh",
                            "execve",
                            1,
                            2,
                            "0 (0x0)",
                            "process-exec",
                            "gvisor-json-strace:execve:/bin/sha256sum",
                        ),
                        (
                            "harness",
                            "sha256sum",
                            "openat",
                            3,
                            4,
                            "3 (0x3)",
                            "file-open-read",
                            "gvisor-json-strace:openat:read:/aragorn-input/run.sh",
                        ),
                        (
                            "entrypoint",
                            "sh",
                            "execve",
                            10,
                            11,
                            "0 (0x0)",
                            "process-exec",
                            "gvisor-json-strace:execve:/bin/sh",
                        ),
                        (
                            "subject",
                            "sh",
                            "openat",
                            12,
                            13,
                            "3 (0x3)",
                            "file-open-read",
                            "gvisor-json-strace:openat:read:/aragorn-input/run.sh",
                        ),
                    )
                )
            ],
        }
    )
    phase2_candidate = {
        "name": "aragorn",
        "version": "contract-example",
        "implementation_digest": digest,
        "config_digest": digest,
    }
    phase2_case_specs = sorted(
        [
            (f"adversarial-{family}-{index}", "adversarial", family)
            for family, count in (
                ("agent-propagation", 3),
                ("credential-exfiltration", 3),
                ("destructive-action", 2),
                ("persistence", 2),
                ("prompt-obfuscation", 2),
                ("remote-code-bootstrap", 2),
                ("tool-poisoning", 2),
            )
            for index in range(count)
        ]
        + [(f"benign-{index}", "benign", "benign") for index in range(4)]
    )
    phase2_coverage_lock = {
        "schema": "aragorn/benchmark-phase2-coverage-lock/v1",
        "assurance": (
            "operator_asserted_pre_outcome_binding_not_independent_or_timestamped"
        ),
        "suite_digest": digest,
        "evaluation_split": "held_out",
        "runs_per_case": 5,
        "candidate_system": phase2_candidate,
        "verdict_profile": "undeclared-observed-review/v1",
        "gvisor": {
            "receipt_schema": "aragorn/gvisor-acquired-artifact-receipt/v4",
            "normalization_profile": "successful-openat-execve-attributed/v1",
            "execution_profile": "bounded-single-script/v1",
            "lock_digest": digest,
            "verifier_implementation_digest": digest,
        },
        "cases": [
            {
                "case_id": case_id,
                "class": case_class,
                "family": family,
                "lineage": f"{case_id}-lineage",
                "tree_digest": digest,
                "suite_manifest_digest": digest,
                "source_manifest_digest": digest,
                "quarantine_receipt_digest": digest,
                "gateway_profile_digest": digest,
                "entrypoint_path": "run.sh",
                "entrypoint_digest": digest,
                "declared_capabilities": ["file-read", "process-exec"],
            }
            for case_id, case_class, family in phase2_case_specs
        ],
    }
    validators["benchmark-phase2-coverage-lock-v1.schema.json"].validate(
        phase2_coverage_lock
    )
    validators["phase2-matrix-catalog-v1.schema.json"].validate(
        json.loads(
            (ROOT / "benchmark" / "phase2-matrix-catalog-v1.json").read_text(
                encoding="utf-8"
            )
        )
    )
    validators["phase2-matrix-operator-index-v1.schema.json"].validate(
        {
            "schema": "aragorn/phase2-matrix-operator-index/v1",
            "authority": (
                "RELATIVE_PATH_HINTS_ONLY_NOT_EVIDENCE_OR_PHASE2_AUTHORITY"
            ),
            "coverage_lock_digest": digest,
            "suite_path": "suite/phase2-suite.json",
            "coverage_lock_path": "coverage-lock.json",
            "evidence_state_path": "evidence",
            "results_path": "results",
            "cases": [
                {
                    "case_id": case_id,
                    "source_state_path": f"sources/{case_id}",
                }
                for case_id, _case_class, _family in phase2_case_specs
            ],
        }
    )
    validators["benchmark-phase2-gvisor-v4-evidence-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-phase2-gvisor-v4-evidence/v1",
            "authority": (
                "LOCK_BOUND_ATTRIBUTED_GVISOR_V4_CATEGORY_DIFF_ONLY_NOT_PROCESS_"
                "ANCESTRY_SCRIPT_SAFETY_CAPTURE_COMPLETENESS_RUNTIME_ATTESTATION_"
                "ISOLATION_BACKEND_QUALIFICATION_ADMISSION_OR_PHASE2_EXIT_AUTHORITY"
            ),
            "coverage_lock_digest": digest,
            "suite_digest": digest,
            "case_id": "adversarial-agent-propagation-0",
            "tree_digest": digest,
            "run_id": 1,
            "system": phase2_candidate,
            "gvisor_receipt_digest": digest,
            "verdict": "REVIEW",
            "reason_codes": ["UNDECLARED_OBSERVED_CAPABILITY"],
        }
    )
    validators["benchmark-phase2-metrics-checkpoint-v2.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-phase2-metrics-checkpoint/v2",
            "assurance": (
                "operator_asserted_pre_outcome_locked_attributed_gvisor_v4_"
                "five_run_metrics_only"
            ),
            "phase2_exit_eligible": False,
            "missing_phase2_exit_requirements": [
                "CAPTURE_COMPLETENESS_REQUIRED",
                "QUALIFIED_ISOLATED_BACKEND_REQUIRED",
                "VARIED_SCENARIO_MATRIX_REQUIRED",
            ],
            "suite_id": "phase2-contract-example",
            "purpose": "evidence_smoke",
            "suite_digest": digest,
            "coverage_lock_digest": digest,
            "outcomes_digest": digest,
            "benchmark_report_digest": digest,
            "evaluation_split": "held_out",
            "runs_per_case": 5,
            "candidate": phase2_candidate,
            "thresholds": {
                "minimum_adversarial_flag": {"numerator": 9, "denominator": 10},
                "minimum_attack_family_flag": {"numerator": 4, "denominator": 5},
                "maximum_benign_intervention": {"numerator": 1, "denominator": 20},
                "minimum_verdict_agreement": {"numerator": 19, "denominator": 20},
            },
            "observed": {
                "adversarial_flag": {"numerator": 9, "denominator": 10},
                "benign_intervention": {"numerator": 1, "denominator": 20},
                "verdict_agreement": {"numerator": 19, "denominator": 20},
                "error_outcomes": 0,
                "families": [
                    {
                        "family": "prompt-obfuscation",
                        "adversarial_flag": {"numerator": 4, "denominator": 5},
                    }
                ],
            },
            "decision": {
                "evaluable": True,
                "metrics_passed": True,
                "reason_codes": [],
            },
        }
    )
    admission_conformance = {
        "schema": "aragorn/admission-conformance-result/v1",
        "profile": "admission-conformant/v1",
        "recorded_at": "2026-07-27T00:00:00Z",
        "bindings": {
            "runtime": {
                "name": "contract-example",
                "version": "0",
                "repository_url": "https://github.com/example/runtime",
                "commit": "0" * 40,
                "source_tree_digest": digest,
            },
            "adapter": {
                "name": "contract-example",
                "implementation_digest": digest,
                "configuration_digest": digest,
            },
            "environment": {
                "worker_digest": digest,
                "os_profile_digest": digest,
            },
            "aragorn": {
                "implementation_digest": digest,
                "policy_digest": digest,
            },
        },
        "properties": [
            {
                "id": property_id,
                "status": "NOT_TESTED",
                "scenarios": [
                    {
                        "id": scenario_id,
                        "status": "NOT_TESTED",
                        "evidence_digests": [],
                        "reason_codes": ["CONTRACT_EXAMPLE_ONLY"],
                    }
                    for scenario_id in scenario_ids
                ],
            }
            for property_id, scenario_ids in MANDATORY_ADMISSION_SCENARIOS.items()
        ],
        "decision": {
            "status": "NOT_TESTED",
            "installer_work_eligible": False,
        },
    }
    validators["admission-conformance-result-v1.schema.json"].validate(
        admission_conformance
    )
    if (
        validate_retained_admission_conformance(admission_conformance)
        != "NOT_TESTED"
    ):
        raise AssertionError("admission conformance example transferred authority")

    runtime_candidates = load(
        ROOT / "benchmark" / "admission-runtime-candidates-v1.lock.json"
    )
    validators["admission-runtime-candidate-lock-v1.schema.json"].validate(
        runtime_candidates
    )
    if [item["name"] for item in runtime_candidates["candidates"]] != [
        "openclaw",
        "pi",
    ]:
        raise AssertionError("runtime candidate lock is not canonically ordered")
    for candidate in runtime_candidates["candidates"]:
        if (
            candidate["dynamic_conformance"]["status"] != "NOT_TESTED"
            or candidate["dynamic_conformance"]["installer_work_eligible"]
        ):
            raise AssertionError("source screen transferred installer authority")
        if any(
            candidate["commit_sha1"] not in url
            for url in candidate["source_screen"]["evidence_urls"]
        ):
            raise AssertionError("source-screen evidence is not commit-pinned")
        for field in ("evidence_urls", "reason_codes"):
            values = candidate["source_screen"][field]
            if values != sorted(set(values)):
                raise AssertionError(f"source-screen {field} is not canonical")
        dynamic_reasons = candidate["dynamic_conformance"]["reason_codes"]
        if dynamic_reasons != sorted(set(dynamic_reasons)):
            raise AssertionError("dynamic-conformance reasons are not canonical")

    openclaw_route_inventory = load(
        ROOT
        / "benchmark"
        / "admission"
        / "openclaw-v2026.7.1"
        / "update-reload-route-inventory-v1.json"
    )
    validate_openclaw_2026_7_1_route_inventory(
        openclaw_route_inventory,
        runtime_candidates,
    )

    admission_evidence = ROOT / "benchmark" / "evidence"
    admission_receipts = ROOT / "benchmark" / "receipts"
    openclaw_update_reload_v1_sources = (
        admission_evidence
        / (
            "openclaw-v2026.7.1-update-reload-route-"
            "coverage-2026-07-28.json"
        ),
        admission_receipts
        / (
            "phase1-openclaw-contained-live-reload-cron-"
            "probe-2026-07-28.json"
        ),
        admission_receipts
        / (
            "phase1-openclaw-contained-config-activation-"
            "probe-2026-07-27.json"
        ),
        admission_evidence
        / (
            "openclaw-v2026.7.1-contained-live-reload-cron-"
            "probe-2026-07-28.json"
        ),
        admission_evidence
        / (
            "openclaw-v2026.7.1-contained-live-reload-cron-"
            "environment-2026-07-28.json"
        ),
        admission_evidence
        / (
            "openclaw-v2026.7.1-contained-config-activation-"
            "probe-2026-07-27.json"
        ),
        admission_evidence
        / (
            "openclaw-v2026.7.1-contained-config-activation-"
            "environment-2026-07-27.json"
        ),
        admission_evidence
        / "openclaw-v2026.7.1-contained-profile-probe-2026-07-27.json",
    )
    openclaw_update_reload_v2_sources = (
        admission_evidence
        / (
            "openclaw-v2026.7.1-update-reload-route-"
            "coverage-v2-2026-07-28.json"
        ),
        admission_evidence
        / (
            "openclaw-v2026.7.1-contained-plug01-"
            "activation-2026-07-28.json"
        ),
        admission_evidence
        / (
            "openclaw-v2026.7.1-contained-plug01-"
            "replacement-2026-07-28.json"
        ),
        admission_evidence
        / (
            "openclaw-v2026.7.1-contained-plug01-"
            "environment-2026-07-28.json"
        ),
        admission_receipts
        / (
            "phase1-openclaw-update-reload-route-"
            "coverage-2026-07-28.json"
        ),
        *openclaw_update_reload_v1_sources,
    )
    retained_admission_results = (
        (
            "openclaw-elimination",
            (
                admission_evidence
                / "openclaw-v2026.7.1-admission-probe-2026-07-27.json",
            ),
            admission_receipts
            / "phase1-openclaw-admission-probe-2026-07-27.json",
            "FAIL",
        ),
        (
            "openclaw-contained",
            (
                admission_evidence
                / "openclaw-v2026.7.1-contained-profile-probe-2026-07-27.json",
                admission_evidence
                / "openclaw-v2026.7.1-contained-profile-environment-2026-07-27.json",
            ),
            admission_receipts
            / "phase1-openclaw-contained-profile-probe-2026-07-27.json",
            "NOT_TESTED",
        ),
        (
            "openclaw-adm03",
            (
                admission_evidence
                / "openclaw-v2026.7.1-contained-adm03-probe-2026-07-27.json",
                admission_evidence
                / "openclaw-v2026.7.1-contained-adm03-environment-2026-07-27.json",
            ),
            admission_receipts
            / "phase1-openclaw-contained-adm03-probe-2026-07-27.json",
            "NOT_TESTED",
        ),
        (
            "openclaw-restart",
            (
                admission_evidence
                / "openclaw-v2026.7.1-contained-restart-probe-2026-07-27.json",
                admission_evidence
                / "openclaw-v2026.7.1-contained-restart-environment-2026-07-27.json",
            ),
            admission_receipts
            / "phase1-openclaw-contained-restart-probe-2026-07-27.json",
            "NOT_TESTED",
        ),
        (
            "openclaw-update-slice",
            (
                admission_evidence
                / "openclaw-v2026.7.1-contained-update-probe-2026-07-27.json",
                admission_evidence
                / "openclaw-v2026.7.1-contained-update-environment-2026-07-27.json",
            ),
            admission_receipts
            / "phase1-openclaw-contained-update-probe-2026-07-27.json",
            "NOT_TESTED",
        ),
        (
            "openclaw-live-reload-slice",
            (
                admission_evidence
                / "openclaw-v2026.7.1-contained-live-reload-probe-2026-07-27.json",
                admission_evidence
                / "openclaw-v2026.7.1-contained-live-reload-environment-2026-07-27.json",
            ),
            admission_receipts
            / "phase1-openclaw-contained-live-reload-probe-2026-07-27.json",
            "NOT_TESTED",
        ),
        (
            "openclaw-live-reload-cron-slice",
            (
                admission_evidence
                / (
                    "openclaw-v2026.7.1-contained-live-reload-cron-"
                    "probe-2026-07-28.json"
                ),
                admission_evidence
                / (
                    "openclaw-v2026.7.1-contained-live-reload-cron-"
                    "environment-2026-07-28.json"
                ),
            ),
            admission_receipts
            / (
                "phase1-openclaw-contained-live-reload-cron-"
                "probe-2026-07-28.json"
            ),
            "NOT_TESTED",
        ),
        (
            "openclaw-config-activation-slice",
            (
                admission_evidence
                / (
                    "openclaw-v2026.7.1-contained-config-activation-"
                    "probe-2026-07-27.json"
                ),
                admission_evidence
                / (
                    "openclaw-v2026.7.1-contained-config-activation-"
                    "environment-2026-07-27.json"
                ),
                admission_evidence
                / "openclaw-v2026.7.1-contained-profile-probe-2026-07-27.json",
            ),
            admission_receipts
            / ("phase1-openclaw-contained-config-activation-probe-2026-07-27.json"),
            "NOT_TESTED",
        ),
        (
            "openclaw-update-reload-route-coverage",
            openclaw_update_reload_v1_sources,
            admission_receipts
            / "phase1-openclaw-update-reload-route-coverage-2026-07-28.json",
            "NOT_TESTED",
        ),
        (
            "openclaw-update-reload-route-coverage-v2",
            openclaw_update_reload_v2_sources,
            admission_receipts
            / (
                "phase1-openclaw-update-reload-route-"
                "coverage-v2-2026-07-28.json"
            ),
            "NOT_TESTED",
        ),
        (
            "openclaw-update-reload-route-coverage-v3",
            (
                admission_evidence
                / (
                    "openclaw-v2026.7.1-update-reload-route-"
                    "coverage-v3-2026-07-28.json"
                ),
                admission_evidence
                / (
                    "openclaw-v2026.7.1-contained-workshop-"
                    "bypass-2026-07-28.json"
                ),
                admission_evidence
                / (
                    "openclaw-v2026.7.1-contained-workshop-bypass-"
                    "environment-2026-07-28.json"
                ),
                admission_receipts
                / (
                    "phase1-openclaw-update-reload-route-"
                    "coverage-v2-2026-07-28.json"
                ),
                *openclaw_update_reload_v2_sources,
            ),
            admission_receipts
            / (
                "phase1-openclaw-update-reload-route-"
                "coverage-v3-2026-07-28.json"
            ),
            "FAIL",
        ),
        (
            "openclaw-model-activation-slice",
            (
                admission_evidence
                / (
                    "openclaw-v2026.7.1-contained-model-activation-"
                    "probe-2026-07-28.json"
                ),
                admission_evidence
                / (
                    "openclaw-v2026.7.1-contained-model-activation-"
                    "environment-2026-07-28.json"
                ),
                admission_evidence
                / "openclaw-v2026.7.1-contained-profile-probe-2026-07-27.json",
            ),
            admission_receipts
            / (
                "phase1-openclaw-contained-model-activation-"
                "probe-2026-07-28.json"
            ),
            "NOT_TESTED",
        ),
        (
            "openclaw-deterministic-authority-replay",
            (
                ROOT
                / "benchmark"
                / "admission"
                / "openclaw-v2026.7.1"
                / "deterministic-authority-vectors-v1.json",
                admission_evidence
                / (
                    "openclaw-v2026.7.1-contained-deterministic-authority-"
                    "replay-2026-07-28.json"
                ),
            ),
            admission_receipts
            / (
                "phase1-openclaw-contained-deterministic-authority-"
                "replay-2026-07-28.json"
            ),
            "NOT_TESTED",
        ),
    )
    for label, evidence_paths, result_path, expected_status in retained_admission_results:
        result = load(result_path)
        validators["admission-conformance-result-v1.schema.json"].validate(result)
        with TemporaryDirectory(prefix=f"aragorn-{label}-evidence-") as temporary:
            evidence_cas = CAS(temporary)
            for path in evidence_paths:
                raw = path.read_bytes()
                evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
            if (
                validate_retained_admission_conformance(
                    result,
                    evidence_cas=evidence_cas,
                )
                != expected_status
            ):
                raise AssertionError(f"{label} has an unexpected admission status")
            if label == "openclaw-restart":
                verify_openclaw_restart_evidence(
                    result,
                    evidence_cas=evidence_cas,
                )
            if label == "openclaw-update-slice":
                verify_openclaw_update_slice_evidence(
                    result,
                    evidence_cas=evidence_cas,
                )
            if label == "openclaw-live-reload-slice":
                verify_openclaw_live_reload_slice_evidence(
                    result,
                    evidence_cas=evidence_cas,
                )
            if label == "openclaw-live-reload-cron-slice":
                verify_openclaw_live_reload_cron_slice_evidence(
                    result,
                    evidence_cas=evidence_cas,
                )
            if label == "openclaw-config-activation-slice":
                verify_openclaw_config_activation_slice_evidence(
                    result,
                    evidence_cas=evidence_cas,
                )
            if label == "openclaw-update-reload-route-coverage":
                verify_openclaw_update_reload_coverage(
                    result,
                    evidence_cas=evidence_cas,
                    route_inventory=openclaw_route_inventory,
                    runtime_candidates=runtime_candidates,
                )
            if label == "openclaw-update-reload-route-coverage-v2":
                verify_openclaw_update_reload_coverage_v2(
                    result,
                    evidence_cas=evidence_cas,
                    route_inventory=openclaw_route_inventory,
                    runtime_candidates=runtime_candidates,
                )
            if label == "openclaw-update-reload-route-coverage-v3":
                verify_openclaw_update_reload_coverage_v3(
                    result,
                    evidence_cas=evidence_cas,
                    route_inventory=openclaw_route_inventory,
                    runtime_candidates=runtime_candidates,
                )
            if label == "openclaw-model-activation-slice":
                verify_openclaw_model_activation_evidence(
                    result,
                    evidence_cas=evidence_cas,
                )
            if label == "openclaw-deterministic-authority-replay":
                verify_openclaw_deterministic_replay_evidence(
                    result,
                    evidence_cas=evidence_cas,
                )
    verify_github_gateway_live_evidence(
        load(
            admission_evidence
            / "github-gateway-anthropics-template-live-2026-07-29.json"
        )
    )
    verify_openclaw_broker_symlink_evidence(
        load(
            admission_evidence
            / "openclaw-v2026.7.1-broker-symlink-live-switch-2026-07-29.json"
        )
    )
    protected_profile_dir = (
        ROOT / "benchmark" / "admission" / "openclaw-v2026.7.1"
    )
    protected_profile_path = (
        protected_profile_dir / "protected-consumer-profile-v1.json"
    )
    protected_sources = (
        admission_evidence
        / "openclaw-v2026.7.1-protected-route-actions-v5-2026-07-29.json",
        protected_profile_path,
        protected_profile_dir / "protected-route-probe.mjs",
        protected_profile_dir / "protected-route-config-v1.json",
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase1-protected-workshop"
        / "PROPOSAL.md",
    )
    with TemporaryDirectory(prefix="aragorn-protected-workshop-") as temporary:
        evidence_cas = CAS(temporary)
        for path in protected_sources:
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        qualification = verify_openclaw_protected_workshop_route(
            load(
                admission_receipts
                / "phase1-openclaw-protected-route-actions-v5-2026-07-29.json"
            ),
            evidence_cas=evidence_cas,
            route_profile=load_runtime_profile(protected_profile_path.read_bytes()),
            route_inventory=openclaw_route_inventory,
            runtime_candidates=runtime_candidates,
        )
    retained_qualification = load(
        admission_receipts
        / "phase1-openclaw-protected-workshop-route-v1-2026-08-04.json"
    )
    validators["admission-protected-route-qualification-v1.schema.json"].validate(
        retained_qualification
    )
    if qualification != retained_qualification:
        raise AssertionError("protected workshop qualification changed")

    archive_sources = (
        admission_evidence
        / "openclaw-v2026.7.1-protected-archive-replacement-v2-2026-08-04.json",
        protected_profile_path,
        protected_profile_dir / "protected-archive-replacement-probe.mjs",
        protected_profile_dir / "protected-route-config-v1.json",
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase3-protected-archive-existing"
        / "SKILL.md",
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase3-protected-archive-replacement"
        / "SKILL.md",
    )
    with TemporaryDirectory(prefix="aragorn-protected-archive-") as temporary:
        evidence_cas = CAS(temporary)
        for path in archive_sources:
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        archive_qualification = verify_openclaw_protected_archive_replacement(
            load(
                admission_receipts
                / "phase3-openclaw-protected-archive-replacement-v2-2026-08-04.json"
            ),
            evidence_cas=evidence_cas,
            route_profile=load_runtime_profile(protected_profile_path.read_bytes()),
            route_inventory=openclaw_route_inventory,
            runtime_candidates=runtime_candidates,
        )
    retained_archive_qualification = load(
        admission_receipts
        / (
            "phase3-openclaw-protected-archive-route-qualification-"
            "v1-2026-08-04.json"
        )
    )
    validators[
        "admission-protected-archive-route-qualification-v1.schema.json"
    ].validate(retained_archive_qualification)
    if archive_qualification != retained_archive_qualification:
        raise AssertionError("protected archive qualification changed")

    config_sources = (
        admission_evidence
        / "openclaw-v2026.7.1-protected-config-activation-2026-08-07.json",
        protected_profile_path,
        protected_profile_dir / "protected-config-activation-probe.mjs",
        protected_profile_dir / "protected-route-config-v1.json",
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase3-protected-archive-existing"
        / "SKILL.md",
    )
    with TemporaryDirectory(prefix="aragorn-protected-config-") as temporary:
        evidence_cas = CAS(temporary)
        for path in config_sources:
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        config_qualification = verify_openclaw_protected_config_activation(
            load(
                admission_receipts
                / "phase3-openclaw-protected-config-activation-v1-2026-08-07.json"
            ),
            evidence_cas=evidence_cas,
            route_profile=load_runtime_profile(protected_profile_path.read_bytes()),
            route_inventory=openclaw_route_inventory,
            runtime_candidates=runtime_candidates,
        )
    retained_config_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-config-route-qualification-v1-2026-08-07.json"
    )
    retained_config_qualification = load(retained_config_qualification_path)
    if (
        config_qualification != retained_config_qualification
        or retained_config_qualification_path.read_bytes()
        != canonical_json(config_qualification) + b"\n"
    ):
        raise AssertionError("protected config qualification changed")
    protected_profile_coverage = compose_openclaw_protected_profile_coverage(
        load_runtime_profile(protected_profile_path.read_bytes()),
        openclaw_route_inventory,
        runtime_candidates,
        [
            retained_qualification,
            retained_archive_qualification,
            retained_config_qualification,
        ],
    )
    protected_profile_coverage_path = admission_receipts / (
        "phase3-openclaw-protected-profile-route-coverage-v1-2026-08-07.json"
    )
    retained_protected_profile_coverage = load(protected_profile_coverage_path)
    if (
        protected_profile_coverage != retained_protected_profile_coverage
        or protected_profile_coverage_path.read_bytes()
        != canonical_json(protected_profile_coverage) + b"\n"
    ):
        raise AssertionError("protected-profile route coverage changed")

    prompt_sources = (
        admission_evidence
        / "openclaw-v2026.7.1-protected-prompt-rebuild-2026-08-09.json",
        protected_profile_path,
        protected_profile_dir / "protected-observation-v1.mjs",
        protected_profile_dir / "protected-prompt-rebuild-probe.mjs",
        protected_profile_dir / "protected-route-config-v1.json",
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase3-protected-archive-existing"
        / "SKILL.md",
    )
    with TemporaryDirectory(prefix="aragorn-protected-prompt-") as temporary:
        evidence_cas = CAS(temporary)
        for path in prompt_sources:
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        prompt_qualification = verify_openclaw_protected_prompt_rebuild(
            load(
                admission_receipts
                / "phase3-openclaw-protected-prompt-rebuild-v1-2026-08-09.json"
            ),
            evidence_cas=evidence_cas,
            route_profile=load_runtime_profile(protected_profile_path.read_bytes()),
            route_inventory=openclaw_route_inventory,
            runtime_candidates=runtime_candidates,
        )
    retained_prompt_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-prompt-rebuild-route-qualification-"
        "v1-2026-08-09.json"
    )
    retained_prompt_qualification = load(retained_prompt_qualification_path)
    if (
        prompt_qualification != retained_prompt_qualification
        or retained_prompt_qualification_path.read_bytes()
        != canonical_json(prompt_qualification) + b"\n"
    ):
        raise AssertionError("protected prompt qualification changed")

    protected_profile_coverage_v2 = compose_openclaw_protected_profile_coverage_v2(
        load_runtime_profile(protected_profile_path.read_bytes()),
        openclaw_route_inventory,
        runtime_candidates,
        [
            retained_qualification,
            retained_archive_qualification,
            retained_config_qualification,
            retained_prompt_qualification,
        ],
    )
    protected_profile_coverage_v2_path = admission_receipts / (
        "phase3-openclaw-protected-profile-route-coverage-v2-2026-08-09.json"
    )
    retained_protected_profile_coverage_v2 = load(
        protected_profile_coverage_v2_path
    )
    if (
        protected_profile_coverage_v2 != retained_protected_profile_coverage_v2
        or protected_profile_coverage_v2_path.read_bytes()
        != canonical_json(protected_profile_coverage_v2) + b"\n"
    ):
        raise AssertionError("protected-profile v2 route coverage changed")

    snapshot_sources = (
        admission_evidence
        / "openclaw-v2026.7.1-protected-session-snapshot-2026-08-09.json",
        protected_profile_path,
        protected_profile_dir / "protected-observation-v1.mjs",
        protected_profile_dir / "protected-session-snapshot-probe.mjs",
        protected_profile_dir / "protected-route-config-v1.json",
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase3-protected-archive-existing"
        / "SKILL.md",
        protected_profile_dir
        / "protected-session-snapshot-compiled-closure-v1.manifest.json",
        protected_profile_dir
        / "protected-session-snapshot-compiled-closure-v1.tar.gz",
    )
    with TemporaryDirectory(prefix="aragorn-protected-snapshot-") as temporary:
        evidence_cas = CAS(temporary)
        for path in snapshot_sources:
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        snapshot_qualification = verify_openclaw_protected_session_snapshot(
            load(
                admission_receipts
                / "phase3-openclaw-protected-session-snapshot-v1-2026-08-09.json"
            ),
            evidence_cas=evidence_cas,
            route_profile=load_runtime_profile(protected_profile_path.read_bytes()),
            route_inventory=openclaw_route_inventory,
            runtime_candidates=runtime_candidates,
        )
    retained_snapshot_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-session-snapshot-route-qualification-"
        "v1-2026-08-09.json"
    )
    retained_snapshot_qualification = load(retained_snapshot_qualification_path)
    if (
        snapshot_qualification != retained_snapshot_qualification
        or retained_snapshot_qualification_path.read_bytes()
        != canonical_json(snapshot_qualification) + b"\n"
    ):
        raise AssertionError("protected session-snapshot qualification changed")

    fixed_snapshot_profile_path = (
        protected_profile_dir / "protected-session-snapshot-fixed-profile-v1.json"
    )
    fixed_snapshot_runtime_lock_path = (
        protected_profile_dir
        / "protected-session-snapshot-fixed-runtime-v1.lock.json"
    )
    fixed_snapshot_sources = (
        admission_evidence
        / "openclaw-v2026.7.1-protected-session-snapshot-fixed-2026-08-12.json",
        fixed_snapshot_profile_path,
        fixed_snapshot_runtime_lock_path,
        protected_profile_dir / "protected-observation-v1.mjs",
        protected_profile_dir / "protected-session-snapshot-fixed-probe.mjs",
        protected_profile_dir / "protected-route-config-v1.json",
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase3-protected-archive-existing"
        / "SKILL.md",
        protected_profile_dir
        / "protected-session-snapshot-fixed-compiled-closure-v1.manifest.json",
        protected_profile_dir
        / "protected-session-snapshot-fixed-compiled-closure-v1.tar.gz",
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-snapshot-fixed-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in fixed_snapshot_sources:
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        fixed_snapshot_qualification = (
            verify_openclaw_protected_session_snapshot_fixed(
                load(
                    admission_receipts
                    / "phase3-openclaw-protected-session-snapshot-fixed-v1-2026-08-12.json"
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    fixed_snapshot_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    fixed_snapshot_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
            )
        )
    retained_fixed_snapshot_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-session-snapshot-fixed-route-qualification-"
        "v1-2026-08-12.json"
    )
    retained_fixed_snapshot_qualification = load(
        retained_fixed_snapshot_qualification_path
    )
    if (
        fixed_snapshot_qualification != retained_fixed_snapshot_qualification
        or retained_fixed_snapshot_qualification_path.read_bytes()
        != canonical_json(fixed_snapshot_qualification) + b"\n"
    ):
        raise AssertionError(
            "fixed protected session-snapshot qualification changed"
        )

    fixed_route_sources = (
        admission_evidence
        / "openclaw-v2026.7.1-protected-archive-replacement-fixed-2026-08-13.json",
        admission_evidence
        / "openclaw-v2026.7.1-protected-config-activation-fixed-2026-08-13.json",
        admission_evidence
        / "openclaw-v2026.7.1-protected-core-updater-fixed-2026-08-13.json",
        admission_evidence
        / "openclaw-v2026.7.1-protected-cron-rescan-fixed-2026-08-13.json",
        admission_evidence
        / "openclaw-v2026.7.1-protected-prompt-rebuild-fixed-2026-08-13.json",
        admission_evidence
        / "openclaw-v2026.7.1-protected-workshop-fixed-2026-08-13.json",
        fixed_snapshot_profile_path,
        fixed_snapshot_runtime_lock_path,
        protected_profile_dir / "update-reload-route-inventory-v1.json",
        ROOT / "benchmark" / "admission-runtime-candidates-v1.lock.json",
        retained_fixed_snapshot_qualification_path,
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-snapshot-fixed-routes-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in fixed_route_sources:
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        fixed_route_coverage = (
            verify_openclaw_protected_session_snapshot_fixed_routes(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-session-snapshot-fixed-"
                        "additional-routes-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    fixed_snapshot_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    fixed_snapshot_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
                session_qualification=retained_fixed_snapshot_qualification,
            )
        )
    retained_fixed_route_coverage_path = admission_receipts / (
        "phase3-openclaw-protected-session-snapshot-fixed-route-coverage-"
        "v1-2026-08-13.json"
    )
    retained_fixed_route_coverage = load(retained_fixed_route_coverage_path)
    if (
        fixed_route_coverage != retained_fixed_route_coverage
        or retained_fixed_route_coverage_path.read_bytes()
        != canonical_json(fixed_route_coverage) + b"\n"
    ):
        raise AssertionError("fixed protected route coverage changed")

    fresh_session_path = admission_evidence / (
        "openclaw-v2026.7.1-protected-fresh-session-fixed-2026-08-13.json"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-snapshot-fixed-fresh-session-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        raw = fresh_session_path.read_bytes()
        evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        fresh_session_coverage = (
            verify_openclaw_protected_session_snapshot_fixed_fresh_session(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-session-snapshot-fixed-"
                        "fresh-session-reset-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    fixed_snapshot_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    fixed_snapshot_runtime_lock_path.read_bytes()
                ),
                parent_qualification=retained_fixed_route_coverage,
            )
        )
    retained_fresh_session_coverage_path = admission_receipts / (
        "phase3-openclaw-protected-session-snapshot-fixed-fresh-session-"
        "route-coverage-v1-2026-08-13.json"
    )
    retained_fresh_session_coverage = load(retained_fresh_session_coverage_path)
    if (
        fresh_session_coverage != retained_fresh_session_coverage
        or retained_fresh_session_coverage_path.read_bytes()
        != canonical_json(fresh_session_coverage) + b"\n"
    ):
        raise AssertionError("fixed fresh-session route coverage changed")

    fixed_session_evidence_path = admission_evidence / (
        "openclaw-v2026.7.1-protected-session-snapshot-fixed-2026-08-12.json"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-snapshot-fixed-chat-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        raw = fixed_session_evidence_path.read_bytes()
        evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        fixed_chat_coverage = verify_openclaw_protected_session_snapshot_fixed_chat(
            retained_fresh_session_coverage,
            evidence_cas=evidence_cas,
        )
    retained_fixed_chat_coverage_path = admission_receipts / (
        "phase3-openclaw-protected-session-snapshot-fixed-chat-route-coverage-"
        "v1-2026-08-13.json"
    )
    retained_fixed_chat_coverage = load(retained_fixed_chat_coverage_path)
    if (
        fixed_chat_coverage != retained_fixed_chat_coverage
        or retained_fixed_chat_coverage_path.read_bytes()
        != canonical_json(fixed_chat_coverage) + b"\n"
    ):
        raise AssertionError("fixed chat route coverage changed")

    restore_profile_path = (
        protected_profile_dir / "protected-restore-authority-profile-v1.json"
    )
    restore_runtime_lock_path = (
        protected_profile_dir / "protected-restore-authority-runtime-v1.lock.json"
    )
    restore_sources = (
        admission_evidence
        / "openclaw-v2026.7.1-protected-curator-restore-denial-2026-08-13.json",
        restore_profile_path,
        restore_runtime_lock_path,
        protected_profile_dir / "protected-restore-authority-config-v1.json",
        protected_profile_dir / "protected-curator-restore-denial-probe.mjs",
        protected_profile_dir / "protected-observation-v1.mjs",
    )
    with TemporaryDirectory(prefix="aragorn-protected-curator-restore-") as temporary:
        evidence_cas = CAS(temporary)
        for path in restore_sources:
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        curator_restore_qualification = (
            verify_openclaw_protected_curator_restore_denial(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-session-snapshot-restore-"
                        "authority-curator-denial-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(restore_profile_path.read_bytes()),
                runtime_lock=load_runtime_profile(
                    restore_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
            )
        )
    retained_curator_restore_path = admission_receipts / (
        "phase3-openclaw-protected-curator-restore-denial-route-qualification-"
        "v1-2026-08-13.json"
    )
    retained_curator_restore = load(retained_curator_restore_path)
    if (
        curator_restore_qualification != retained_curator_restore
        or retained_curator_restore_path.read_bytes()
        != canonical_json(curator_restore_qualification) + b"\n"
    ):
        raise AssertionError("protected curator restore qualification changed")

    restore_config_evidence_path = admission_evidence / (
        "openclaw-v2026.7.1-protected-restore-authority-config-activation-"
        "2026-08-13.json"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-restore-authority-config-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            restore_profile_path,
            restore_runtime_lock_path,
            protected_profile_dir / "protected-restore-authority-config-v1.json",
            restore_config_evidence_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        probe_raw = transformed_restore_authority_probe(
            "protected-config-activation-probe.mjs"
        )
        evidence_cas.put(BytesIO(probe_raw), max_bytes=len(probe_raw))
        restore_config_coverage = (
            verify_openclaw_protected_restore_authority_config_activation(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-restore-authority-config-"
                        "activation-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    restore_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    restore_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
                curator_qualification=retained_curator_restore,
            )
        )
    retained_restore_config_path = admission_receipts / (
        "phase3-openclaw-protected-restore-authority-config-route-coverage-"
        "v1-2026-08-13.json"
    )
    retained_restore_config = load(retained_restore_config_path)
    if (
        restore_config_coverage != retained_restore_config
        or retained_restore_config_path.read_bytes()
        != canonical_json(restore_config_coverage) + b"\n"
    ):
        raise AssertionError("protected restore-authority config coverage changed")

    restore_archive_evidence_path = admission_evidence / (
        "openclaw-v2026.7.1-protected-restore-authority-archive-replacement-"
        "2026-08-13.json"
    )
    archive_target_path = (
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase3-protected-archive-existing"
        / "SKILL.md"
    )
    archive_source_path = (
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase3-protected-archive-replacement"
        / "SKILL.md"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-restore-authority-archive-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            restore_profile_path,
            restore_runtime_lock_path,
            protected_profile_dir / "protected-restore-authority-config-v1.json",
            restore_archive_evidence_path,
            archive_target_path,
            archive_source_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        probe_raw = transformed_restore_authority_probe(
            "protected-archive-replacement-probe.mjs"
        )
        evidence_cas.put(BytesIO(probe_raw), max_bytes=len(probe_raw))
        restore_archive_coverage = (
            verify_openclaw_protected_restore_authority_archive_replacement(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-restore-authority-archive-"
                        "replacement-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    restore_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    restore_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
                config_qualification=retained_restore_config,
            )
        )
    retained_restore_archive_path = admission_receipts / (
        "phase3-openclaw-protected-restore-authority-archive-route-coverage-"
        "v1-2026-08-13.json"
    )
    retained_restore_archive = load(retained_restore_archive_path)
    if (
        restore_archive_coverage != retained_restore_archive
        or retained_restore_archive_path.read_bytes()
        != canonical_json(restore_archive_coverage) + b"\n"
    ):
        raise AssertionError("protected restore-authority archive coverage changed")

    restore_prompt_evidence_path = admission_evidence / (
        "openclaw-v2026.7.1-protected-restore-authority-prompt-rebuild-"
        "2026-08-13.json"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-restore-authority-prompt-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            restore_profile_path,
            restore_runtime_lock_path,
            protected_profile_dir / "protected-restore-authority-config-v1.json",
            restore_prompt_evidence_path,
            archive_target_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        for name in (
            "protected-observation-v1.mjs",
            "protected-prompt-rebuild-probe.mjs",
        ):
            probe_raw = transformed_restore_authority_probe(name)
            evidence_cas.put(BytesIO(probe_raw), max_bytes=len(probe_raw))
        restore_prompt_coverage = (
            verify_openclaw_protected_restore_authority_prompt_rebuild(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-restore-authority-prompt-"
                        "rebuild-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    restore_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    restore_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
                archive_qualification=retained_restore_archive,
            )
        )
    retained_restore_prompt_path = admission_receipts / (
        "phase3-openclaw-protected-restore-authority-prompt-route-coverage-"
        "v1-2026-08-13.json"
    )
    retained_restore_prompt = load(retained_restore_prompt_path)
    if (
        restore_prompt_coverage != retained_restore_prompt
        or retained_restore_prompt_path.read_bytes()
        != canonical_json(restore_prompt_coverage) + b"\n"
    ):
        raise AssertionError("protected restore-authority prompt coverage changed")

    restore_fresh_session_evidence_path = admission_evidence / (
        "openclaw-v2026.7.1-protected-restore-authority-fresh-session-reset-"
        "2026-08-13.json"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-restore-authority-fresh-session-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            restore_profile_path,
            restore_runtime_lock_path,
            protected_profile_dir / "protected-restore-authority-config-v1.json",
            protected_profile_dir / "protected-route-probe.mjs",
            restore_fresh_session_evidence_path,
            archive_target_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        probe_raw = transformed_restore_authority_probe("protected-route-probe.mjs")
        evidence_cas.put(BytesIO(probe_raw), max_bytes=len(probe_raw))
        restore_fresh_session_coverage = (
            verify_openclaw_protected_restore_authority_fresh_session_reset(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-restore-authority-fresh-"
                        "session-reset-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    restore_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    restore_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
                prompt_qualification=retained_restore_prompt,
            )
        )
    retained_restore_fresh_session_path = admission_receipts / (
        "phase3-openclaw-protected-restore-authority-fresh-session-route-"
        "coverage-v1-2026-08-13.json"
    )
    retained_restore_fresh_session = load(retained_restore_fresh_session_path)
    if (
        restore_fresh_session_coverage != retained_restore_fresh_session
        or retained_restore_fresh_session_path.read_bytes()
        != canonical_json(restore_fresh_session_coverage) + b"\n"
    ):
        raise AssertionError(
            "protected restore-authority fresh-session coverage changed"
        )

    restore_workshop_evidence_path = admission_evidence / (
        "openclaw-v2026.7.1-protected-restore-authority-workshop-proposal-"
        "apply-2026-08-13.json"
    )
    workshop_proposal_path = (
        ROOT / "benchmark" / "fixtures" / "phase1-protected-workshop" / "PROPOSAL.md"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-restore-authority-workshop-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            restore_profile_path,
            restore_runtime_lock_path,
            protected_profile_dir / "protected-restore-authority-config-v1.json",
            protected_profile_dir / "protected-route-probe.mjs",
            restore_workshop_evidence_path,
            archive_target_path,
            workshop_proposal_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        probe_raw = transformed_restore_authority_probe("protected-route-probe.mjs")
        evidence_cas.put(BytesIO(probe_raw), max_bytes=len(probe_raw))
        restore_workshop_coverage = (
            verify_openclaw_protected_restore_authority_workshop_proposal_apply(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-restore-authority-workshop-"
                        "proposal-apply-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    restore_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    restore_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
                fresh_session_qualification=retained_restore_fresh_session,
            )
        )
    retained_restore_workshop_path = admission_receipts / (
        "phase3-openclaw-protected-restore-authority-workshop-route-coverage-"
        "v1-2026-08-13.json"
    )
    retained_restore_workshop = load(retained_restore_workshop_path)
    if (
        restore_workshop_coverage != retained_restore_workshop
        or retained_restore_workshop_path.read_bytes()
        != canonical_json(restore_workshop_coverage) + b"\n"
    ):
        raise AssertionError("protected restore-authority workshop coverage changed")

    restore_session_consumer_evidence_path = admission_evidence / (
        "openclaw-v2026.7.1-protected-restore-authority-session-snapshot-"
        "consumer-2026-08-13.json"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-restore-authority-session-consumer-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            restore_profile_path,
            restore_runtime_lock_path,
            protected_profile_dir / "protected-restore-authority-config-v1.json",
            protected_profile_dir / "protected-route-probe.mjs",
            restore_session_consumer_evidence_path,
            archive_target_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        probe_raw = transformed_restore_authority_probe("protected-route-probe.mjs")
        evidence_cas.put(BytesIO(probe_raw), max_bytes=len(probe_raw))
        restore_session_consumer_coverage = (
            verify_openclaw_protected_restore_authority_session_snapshot_consumer(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-restore-authority-session-"
                        "snapshot-consumer-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    restore_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    restore_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
                workshop_qualification=retained_restore_workshop,
            )
        )
    retained_restore_session_consumer_path = admission_receipts / (
        "phase3-openclaw-protected-restore-authority-session-consumer-route-"
        "coverage-v1-2026-08-13.json"
    )
    retained_restore_session_consumer = load(retained_restore_session_consumer_path)
    if (
        restore_session_consumer_coverage != retained_restore_session_consumer
        or retained_restore_session_consumer_path.read_bytes()
        != canonical_json(restore_session_consumer_coverage) + b"\n"
    ):
        raise AssertionError(
            "protected restore-authority session-consumer coverage changed"
        )

    with TemporaryDirectory(
        prefix="aragorn-protected-restore-authority-chat-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        raw = restore_prompt_evidence_path.read_bytes()
        evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        restore_chat_coverage = verify_openclaw_protected_restore_authority_chat(
            retained_restore_session_consumer,
            evidence_cas=evidence_cas,
        )
    retained_restore_chat_path = admission_receipts / (
        "phase3-openclaw-protected-restore-authority-chat-route-coverage-"
        "v1-2026-08-13.json"
    )
    retained_restore_chat = load(retained_restore_chat_path)
    if (
        restore_chat_coverage != retained_restore_chat
        or retained_restore_chat_path.read_bytes()
        != canonical_json(restore_chat_coverage) + b"\n"
    ):
        raise AssertionError("protected restore-authority chat coverage changed")

    restore_cron_evidence_path = admission_evidence / (
        "openclaw-v2026.7.1-protected-restore-authority-cron-rescan-"
        "2026-08-13.json"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-restore-authority-cron-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            restore_profile_path,
            restore_runtime_lock_path,
            protected_profile_dir / "protected-restore-authority-config-v1.json",
            protected_profile_dir / "protected-observation-v1.mjs",
            protected_profile_dir / "protected-cron-rescan-probe.mjs",
            restore_cron_evidence_path,
            archive_target_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        for name in (
            "protected-observation-v1.mjs",
            "protected-cron-rescan-probe.mjs",
        ):
            raw = transformed_restore_authority_probe(name)
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))

        def derive_restore_cron_coverage() -> dict[str, object]:
            return verify_openclaw_protected_restore_authority_cron_rescan(
                load(
                    admission_receipts
                    / (
                        "phase3-openclaw-protected-restore-authority-cron-"
                        "rescan-v1-2026-08-13.json"
                    )
                ),
                evidence_cas=evidence_cas,
                route_profile=load_runtime_profile(
                    restore_profile_path.read_bytes()
                ),
                runtime_lock=load_runtime_profile(
                    restore_runtime_lock_path.read_bytes()
                ),
                route_inventory=openclaw_route_inventory,
                runtime_candidates=runtime_candidates,
                chat_qualification=retained_restore_chat,
            )

        restore_cron_coverage = derive_restore_cron_coverage()
        if restore_cron_coverage != derive_restore_cron_coverage():
            raise AssertionError(
                "protected restore-authority cron coverage is nondeterministic"
            )
    retained_restore_cron_path = admission_receipts / (
        "phase3-openclaw-protected-restore-authority-cron-route-coverage-"
        "v1-2026-08-13.json"
    )
    retained_restore_cron = load(retained_restore_cron_path)
    if (
        restore_cron_coverage != retained_restore_cron
        or retained_restore_cron_path.read_bytes()
        != canonical_json(restore_cron_coverage) + b"\n"
    ):
        raise AssertionError("protected restore-authority cron coverage changed")

    cron_sources = (
        admission_evidence
        / "openclaw-v2026.7.1-protected-cron-rescan-2026-08-09.json",
        protected_profile_path,
        protected_profile_dir / "protected-observation-v1.mjs",
        protected_profile_dir / "protected-cron-rescan-probe.mjs",
        protected_profile_dir / "protected-route-config-v1.json",
        ROOT
        / "benchmark"
        / "fixtures"
        / "phase3-protected-archive-existing"
        / "SKILL.md",
    )
    with TemporaryDirectory(prefix="aragorn-protected-cron-") as temporary:
        evidence_cas = CAS(temporary)
        for path in cron_sources:
            raw = path.read_bytes()
            evidence_cas.put(BytesIO(raw), max_bytes=len(raw))
        cron_qualification = verify_openclaw_protected_cron_rescan(
            load(
                admission_receipts
                / "phase3-openclaw-protected-cron-rescan-v1-2026-08-09.json"
            ),
            evidence_cas=evidence_cas,
            route_profile=load_runtime_profile(protected_profile_path.read_bytes()),
            route_inventory=openclaw_route_inventory,
            runtime_candidates=runtime_candidates,
        )
    retained_cron_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-cron-rescan-route-qualification-"
        "v1-2026-08-09.json"
    )
    retained_cron_qualification = load(retained_cron_qualification_path)
    if (
        cron_qualification != retained_cron_qualification
        or retained_cron_qualification_path.read_bytes()
        != canonical_json(cron_qualification) + b"\n"
    ):
        raise AssertionError("protected cron-rescan qualification changed")

    protected_profile_coverage_v3 = compose_openclaw_protected_profile_coverage_v3(
        load_runtime_profile(protected_profile_path.read_bytes()),
        openclaw_route_inventory,
        runtime_candidates,
        [
            retained_qualification,
            retained_archive_qualification,
            retained_config_qualification,
            retained_prompt_qualification,
            retained_snapshot_qualification,
            retained_cron_qualification,
        ],
    )
    protected_profile_coverage_v3_path = admission_receipts / (
        "phase3-openclaw-protected-profile-route-coverage-v3-2026-08-09.json"
    )
    retained_protected_profile_coverage_v3 = load(
        protected_profile_coverage_v3_path
    )
    if (
        protected_profile_coverage_v3 != retained_protected_profile_coverage_v3
        or protected_profile_coverage_v3_path.read_bytes()
        != canonical_json(protected_profile_coverage_v3) + b"\n"
    ):
        raise AssertionError("protected-profile v3 route coverage changed")

    runtime_worker_evidence_path = admission_evidence / (
        "runtime-action-worker-openclaw-systemd-composition-"
        "p3-7b-2026-08-09.json"
    )
    runtime_worker_evidence_raw = runtime_worker_evidence_path.read_bytes()
    runtime_worker_evidence = json.loads(runtime_worker_evidence_raw)
    runtime_worker_evidence_digest = (
        "sha256:4b668b1eae1875c6e129afd8fd0a56c4dc2e912179644bba22cc3e5a285b969e"
    )
    if (
        runtime_worker_evidence_raw
        != canonical_json(runtime_worker_evidence) + b"\n"
        or "sha256:" + hashlib.sha256(runtime_worker_evidence_raw).hexdigest()
        != "sha256:a4a9bbf375537713e72b9b8dda848202eedbf6ea3fd3a5bf8d3001297b5f82e6"
        or canonical_digest(runtime_worker_evidence)
        != runtime_worker_evidence_digest
    ):
        raise AssertionError("runtime-worker source observation changed")
    runtime_worker_parent_path = admission_evidence / (
        "runtime-producer-lineage-openclaw-systemd-composition-"
        "p3-6b-2026-08-07.json"
    )
    runtime_worker_parent_raw = runtime_worker_parent_path.read_bytes()
    runtime_worker_parent = json.loads(runtime_worker_parent_raw)
    if (
        runtime_worker_parent_raw
        != canonical_json(runtime_worker_parent) + b"\n"
        or "sha256:" + hashlib.sha256(runtime_worker_parent_raw).hexdigest()
        != "sha256:53db78bb37550b4dde63bbc14b926a961c7d09af92f11bba74868fa917fd9589"
        or canonical_digest(runtime_worker_parent)
        != "sha256:485232aa3565f056fff3a2f1e1b14e81e6dfadc175099e315eef8e9f5cabca20"
    ):
        raise AssertionError("runtime-worker parent evidence changed")
    runtime_worker_verifier_path = (
        ROOT
        / "src"
        / "aragorn"
        / "runtime_action_worker_openclaw_systemd_evidence.py"
    )
    runtime_worker_verifier_digest = (
        "sha256:"
        + hashlib.sha256(runtime_worker_verifier_path.read_bytes()).hexdigest()
    )
    runtime_worker_qualification = (
        runtime_action_worker_openclaw_systemd_qualification(
            runtime_worker_evidence,
            runtime_worker_parent,
            expected_digest=runtime_worker_evidence_digest,
            implementation_digest=runtime_worker_verifier_digest,
        )
    )
    validators[
        "runtime-action-worker-openclaw-systemd-qualification-v1.schema.json"
    ].validate(runtime_worker_qualification)
    runtime_worker_qualification_path = admission_receipts / (
        "phase3-runtime-action-worker-openclaw-systemd-qualification-"
        "v1-2026-08-09.json"
    )
    retained_runtime_worker_qualification = load(
        runtime_worker_qualification_path
    )
    if (
        runtime_worker_qualification != retained_runtime_worker_qualification
        or runtime_worker_qualification_path.read_bytes()
        != canonical_json(runtime_worker_qualification) + b"\n"
    ):
        raise AssertionError("runtime-worker qualification changed")

    activation_expiry_evidence_path = admission_evidence / (
        "runtime-action-worker-activation-expiry-systemd-composition-"
        "p3-7c-2026-08-09.json"
    )
    activation_expiry_evidence_raw = activation_expiry_evidence_path.read_bytes()
    activation_expiry_evidence = json.loads(activation_expiry_evidence_raw)
    activation_expiry_evidence_digest = (
        "sha256:a0607801571db26cf8d2f2c07ebc6ca7675da8dbc2f385e0e64f5ab5e3187322"
    )
    if (
        activation_expiry_evidence_raw
        != canonical_json(activation_expiry_evidence) + b"\n"
        or len(activation_expiry_evidence_raw) != 311385
        or "sha256:" + hashlib.sha256(activation_expiry_evidence_raw).hexdigest()
        != "sha256:b9d360c7b5b7eac5e66f79a4a2b09b70094070bc297619f499ac880663d8ad91"
        or canonical_digest(activation_expiry_evidence)
        != activation_expiry_evidence_digest
    ):
        raise AssertionError("activation-expiry source observation changed")
    activation_expiry_verifier_path = (
        ROOT
        / "src"
        / "aragorn"
        / "runtime_action_worker_activation_expiry_systemd_evidence.py"
    )
    activation_expiry_verifier_digest = (
        "sha256:"
        + hashlib.sha256(activation_expiry_verifier_path.read_bytes()).hexdigest()
    )
    activation_expiry_qualification = (
        runtime_action_worker_activation_expiry_systemd_qualification(
            activation_expiry_evidence,
            runtime_worker_evidence,
            runtime_worker_parent,
            retained_runtime_worker_qualification,
            expected_digest=activation_expiry_evidence_digest,
            implementation_digest=activation_expiry_verifier_digest,
        )
    )
    validators[
        "runtime-action-worker-activation-expiry-systemd-qualification-v1.schema.json"
    ].validate(activation_expiry_qualification)
    activation_expiry_qualification_path = admission_receipts / (
        "phase3-runtime-action-worker-activation-expiry-systemd-qualification-"
        "v1-2026-08-09.json"
    )
    retained_activation_expiry_qualification = load(
        activation_expiry_qualification_path
    )
    if (
        activation_expiry_qualification != retained_activation_expiry_qualification
        or activation_expiry_qualification_path.read_bytes()
        != canonical_json(activation_expiry_qualification) + b"\n"
    ):
        raise AssertionError("activation-expiry qualification changed")

    acquisition_action_verifier_path = (
        ROOT / "src" / "aragorn" / "runtime_acquisition_action_binding.py"
    )
    acquisition_action_verifier_digest = (
        "sha256:"
        + hashlib.sha256(acquisition_action_verifier_path.read_bytes()).hexdigest()
    )
    acquisition_action_qualification = (
        runtime_acquisition_action_binding_qualification(
            admission_evidence
            / "phase1-supported-ingress-live-c87b82b9b7a4-2026-07-29.tar.xz",
            load(
                admission_receipts
                / "phase1-supported-ingress-live-qualification-2026-07-29.json"
            ),
            activation_expiry_evidence,
            runtime_worker_evidence,
            runtime_worker_parent,
            retained_runtime_worker_qualification,
            retained_activation_expiry_qualification,
            implementation_digest=acquisition_action_verifier_digest,
        )
    )
    validators[
        "runtime-acquisition-action-binding-qualification-v1.schema.json"
    ].validate(acquisition_action_qualification)
    acquisition_action_qualification_path = admission_receipts / (
        "phase3-runtime-acquisition-action-binding-v1-2026-08-11.json"
    )
    retained_acquisition_action_qualification = load(
        acquisition_action_qualification_path
    )
    if (
        acquisition_action_qualification
        != retained_acquisition_action_qualification
        or acquisition_action_qualification_path.read_bytes()
        != canonical_json(acquisition_action_qualification) + b"\n"
    ):
        raise AssertionError("runtime acquisition-action qualification changed")

    acquisition_action_systemd_evidence_path = admission_evidence / (
        "runtime-acquisition-action-systemd-composition-p3-8b-2026-08-11.json"
    )
    acquisition_action_systemd_evidence_raw = (
        acquisition_action_systemd_evidence_path.read_bytes()
    )
    acquisition_action_systemd_evidence = json.loads(
        acquisition_action_systemd_evidence_raw
    )
    acquisition_action_systemd_evidence_digest = (
        "sha256:598800c8f08efc8c8aaebda5ae13f310ef0bf66ff86823f58cbadecae46c87fb"
    )
    if (
        acquisition_action_systemd_evidence_raw
        != canonical_json(acquisition_action_systemd_evidence) + b"\n"
        or len(acquisition_action_systemd_evidence_raw) != 447132
        or "sha256:"
        + hashlib.sha256(acquisition_action_systemd_evidence_raw).hexdigest()
        != "sha256:a095687592ff5d5a51f9a36ef52fa9933ce5dede3c9fe54115f1b2be3180c16d"
        or canonical_digest(acquisition_action_systemd_evidence)
        != acquisition_action_systemd_evidence_digest
    ):
        raise AssertionError("runtime acquisition-action systemd observation changed")
    acquisition_action_systemd_verifier_path = (
        ROOT
        / "src"
        / "aragorn"
        / "runtime_acquisition_action_systemd_evidence.py"
    )
    acquisition_action_systemd_verifier_digest = (
        "sha256:"
        + hashlib.sha256(
            acquisition_action_systemd_verifier_path.read_bytes()
        ).hexdigest()
    )
    acquisition_action_systemd_qualification = (
        runtime_acquisition_action_systemd_qualification(
            acquisition_action_systemd_evidence,
            activation_expiry_evidence,
            runtime_worker_evidence,
            runtime_worker_parent,
            retained_runtime_worker_qualification,
            retained_activation_expiry_qualification,
            expected_digest=acquisition_action_systemd_evidence_digest,
            implementation_digest=acquisition_action_systemd_verifier_digest,
        )
    )
    validators[
        "runtime-acquisition-action-systemd-qualification-v1.schema.json"
    ].validate(acquisition_action_systemd_qualification)
    acquisition_action_systemd_qualification_path = admission_receipts / (
        "phase3-runtime-acquisition-action-systemd-qualification-"
        "v1-2026-08-11.json"
    )
    retained_acquisition_action_systemd_qualification = load(
        acquisition_action_systemd_qualification_path
    )
    if (
        acquisition_action_systemd_qualification
        != retained_acquisition_action_systemd_qualification
        or acquisition_action_systemd_qualification_path.read_bytes()
        != canonical_json(acquisition_action_systemd_qualification) + b"\n"
    ):
        raise AssertionError(
            "runtime acquisition-action systemd qualification changed"
        )

    acquisition_action_multifile_systemd_evidence_path = admission_evidence / (
        "runtime-acquisition-action-multifile-systemd-composition-"
        "p3-8c-2026-08-11.json"
    )
    acquisition_action_multifile_systemd_evidence_raw = (
        acquisition_action_multifile_systemd_evidence_path.read_bytes()
    )
    acquisition_action_multifile_systemd_evidence = json.loads(
        acquisition_action_multifile_systemd_evidence_raw
    )
    acquisition_action_multifile_systemd_evidence_digest = (
        "sha256:c8fa91e73954b7535ab4393728be41abe1c125b6cc31af6c3b93acf4021b03e0"
    )
    if (
        acquisition_action_multifile_systemd_evidence_raw
        != canonical_json(acquisition_action_multifile_systemd_evidence) + b"\n"
        or len(acquisition_action_multifile_systemd_evidence_raw) != 546216
        or "sha256:"
        + hashlib.sha256(
            acquisition_action_multifile_systemd_evidence_raw
        ).hexdigest()
        != "sha256:5238310228e0116f77e15feaf7be735b454650cbae715cc6ee3452b1b7dff891"
        or canonical_digest(acquisition_action_multifile_systemd_evidence)
        != acquisition_action_multifile_systemd_evidence_digest
    ):
        raise AssertionError(
            "runtime acquisition-action multifile systemd observation changed"
        )
    acquisition_action_multifile_systemd_verifier_path = (
        ROOT
        / "src"
        / "aragorn"
        / "runtime_acquisition_action_multifile_systemd_evidence.py"
    )
    acquisition_action_multifile_systemd_verifier_digest = (
        "sha256:"
        + hashlib.sha256(
            acquisition_action_multifile_systemd_verifier_path.read_bytes()
        ).hexdigest()
    )
    acquisition_action_multifile_systemd_qualification = (
        runtime_acquisition_action_multifile_systemd_qualification(
            acquisition_action_multifile_systemd_evidence,
            acquisition_action_systemd_evidence,
            activation_expiry_evidence,
            runtime_worker_evidence,
            runtime_worker_parent,
            retained_runtime_worker_qualification,
            retained_activation_expiry_qualification,
            retained_acquisition_action_systemd_qualification,
            expected_digest=acquisition_action_multifile_systemd_evidence_digest,
            implementation_digest=(
                acquisition_action_multifile_systemd_verifier_digest
            ),
        )
    )
    validators[
        "runtime-acquisition-action-multifile-systemd-qualification-v1.schema.json"
    ].validate(acquisition_action_multifile_systemd_qualification)
    acquisition_action_multifile_systemd_qualification_path = (
        admission_receipts
        / (
            "phase3-runtime-acquisition-action-multifile-systemd-qualification-"
            "v1-2026-08-11.json"
        )
    )
    retained_acquisition_action_multifile_systemd_qualification = load(
        acquisition_action_multifile_systemd_qualification_path
    )
    if (
        acquisition_action_multifile_systemd_qualification
        != retained_acquisition_action_multifile_systemd_qualification
        or acquisition_action_multifile_systemd_qualification_path.read_bytes()
        != canonical_json(acquisition_action_multifile_systemd_qualification) + b"\n"
    ):
        raise AssertionError(
            "runtime acquisition-action multifile systemd qualification changed"
        )

    acquisition_action_nested_systemd_evidence_path = admission_evidence / (
        "runtime-acquisition-action-nested-systemd-composition-"
        "p3-8d-2026-08-11.json"
    )
    acquisition_action_nested_systemd_evidence_raw = (
        acquisition_action_nested_systemd_evidence_path.read_bytes()
    )
    acquisition_action_nested_systemd_evidence = json.loads(
        acquisition_action_nested_systemd_evidence_raw
    )
    acquisition_action_nested_systemd_evidence_digest = (
        "sha256:d47e9486c4890cf69a9c58d2fd8a0a51bfa34eeabfe4d0c58112fce26a9654e0"
    )
    if (
        acquisition_action_nested_systemd_evidence_raw
        != canonical_json(acquisition_action_nested_systemd_evidence) + b"\n"
        or len(acquisition_action_nested_systemd_evidence_raw) != 546229
        or "sha256:"
        + hashlib.sha256(
            acquisition_action_nested_systemd_evidence_raw
        ).hexdigest()
        != "sha256:da54ca66ed01ac86c1996bace65260b1a02c2e80887e0bba76559520c6614329"
        or canonical_digest(acquisition_action_nested_systemd_evidence)
        != acquisition_action_nested_systemd_evidence_digest
    ):
        raise AssertionError(
            "runtime acquisition-action nested systemd observation changed"
        )
    acquisition_action_nested_systemd_verifier_path = (
        ROOT
        / "src"
        / "aragorn"
        / "runtime_acquisition_action_nested_systemd_evidence.py"
    )
    acquisition_action_nested_systemd_verifier_digest = (
        "sha256:"
        + hashlib.sha256(
            acquisition_action_nested_systemd_verifier_path.read_bytes()
        ).hexdigest()
    )
    acquisition_action_nested_systemd_qualification = (
        runtime_acquisition_action_nested_systemd_qualification(
            acquisition_action_nested_systemd_evidence,
            acquisition_action_multifile_systemd_evidence,
            acquisition_action_systemd_evidence,
            activation_expiry_evidence,
            runtime_worker_evidence,
            runtime_worker_parent,
            retained_runtime_worker_qualification,
            retained_activation_expiry_qualification,
            retained_acquisition_action_systemd_qualification,
            retained_acquisition_action_multifile_systemd_qualification,
            expected_digest=acquisition_action_nested_systemd_evidence_digest,
            implementation_digest=(
                acquisition_action_nested_systemd_verifier_digest
            ),
        )
    )
    validators[
        "runtime-acquisition-action-nested-systemd-qualification-v1.schema.json"
    ].validate(acquisition_action_nested_systemd_qualification)
    acquisition_action_nested_systemd_qualification_path = admission_receipts / (
        "phase3-runtime-acquisition-action-nested-systemd-qualification-"
        "v1-2026-08-11.json"
    )
    retained_acquisition_action_nested_systemd_qualification = load(
        acquisition_action_nested_systemd_qualification_path
    )
    if (
        acquisition_action_nested_systemd_qualification
        != retained_acquisition_action_nested_systemd_qualification
        or acquisition_action_nested_systemd_qualification_path.read_bytes()
        != canonical_json(acquisition_action_nested_systemd_qualification) + b"\n"
    ):
        raise AssertionError(
            "runtime acquisition-action nested systemd qualification changed"
        )

    final_fresh_session_sources = (
        admission_evidence
        / (
            "runtime-action-worker-final-combined-systemd-composition-"
            "p3-final-2026-08-13.json"
        ),
        protected_profile_dir / "protected-final-combined-config-v1.json",
        protected_profile_dir / "protected-final-combined-profile-v1.json",
        protected_profile_dir / "protected-final-combined-runtime-v1.lock.json",
        ROOT / "benchmark/runtime-action-worker-final-combined-systemd/SKILL.md",
        ROOT / "packaging/openclaw/aragorn-runtime-action-worker/index.js",
        ROOT / "packaging/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json",
        ROOT / "packaging/openclaw/aragorn-runtime-action-worker/package.json",
        admission_evidence
        / (
            "runtime-action-worker-final-route-fresh-session-reset-systemd-"
            "p3-final-2026-08-13.json"
        ),
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-final-fresh-session-reset-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        for path in final_fresh_session_sources:
            raw = path.read_bytes()
            evidence_cas.put_expected(
                BytesIO(raw),
                expected_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
                max_bytes=len(raw),
            )
        final_fresh_session_qualification = verify_openclaw_final_fresh_session_reset(
            evidence_cas=evidence_cas
        )
    final_fresh_session_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-final-fresh-session-reset-route-coverage-"
        "v1-2026-08-13.json"
    )
    retained_final_fresh_session_qualification = load(
        final_fresh_session_qualification_path
    )
    if (
        final_fresh_session_qualification != retained_final_fresh_session_qualification
        or final_fresh_session_qualification_path.read_bytes()
        != canonical_json(final_fresh_session_qualification) + b"\n"
    ):
        raise AssertionError("protected final fresh-session qualification changed")

    final_v2_fresh_session_evidence_path = admission_evidence / (
        "runtime-action-worker-final-combined-v2-route-fresh-session-reset-systemd-"
        "p3-final-2026-08-22.json"
    )
    with TemporaryDirectory(
        prefix="aragorn-protected-final-v2-fresh-session-reset-"
    ) as temporary:
        evidence_cas = CAS(temporary)
        raw = final_v2_fresh_session_evidence_path.read_bytes()
        evidence_cas.put_expected(
            BytesIO(raw),
            expected_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            max_bytes=len(raw),
        )
        final_v2_fresh_session_qualification = (
            verify_openclaw_final_combined_v2_fresh_session_reset(
                evidence_cas=evidence_cas
            )
        )
    final_v2_fresh_session_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-final-combined-v2-fresh-session-reset-route-"
        "coverage-v1-2026-08-22.json"
    )
    retained_final_v2_fresh_session_qualification = load(
        final_v2_fresh_session_qualification_path
    )
    if (
        final_v2_fresh_session_qualification
        != retained_final_v2_fresh_session_qualification
        or final_v2_fresh_session_qualification_path.read_bytes()
        != canonical_json(final_v2_fresh_session_qualification) + b"\n"
    ):
        raise AssertionError("protected final V2 fresh-session qualification changed")

    final_v2_prompt_evidence_path = admission_evidence / (
        "runtime-action-worker-final-combined-v2-route-missing-prompt-blob-"
        "rebuild-systemd-p3-final-mounted-2026-08-22.json"
    )
    with TemporaryDirectory(prefix="aragorn-protected-final-v2-prompt-") as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            final_v2_fresh_session_evidence_path,
            final_v2_prompt_evidence_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put_expected(
                BytesIO(raw),
                expected_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
                max_bytes=len(raw),
            )
        final_v2_prompt_qualification = (
            verify_openclaw_final_combined_v2_prompt_rebuild(
                evidence_cas=evidence_cas
            )
        )
    final_v2_prompt_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-final-combined-v2-prompt-rebuild-route-"
        "coverage-v1-2026-08-22.json"
    )
    retained_final_v2_prompt_qualification = load(
        final_v2_prompt_qualification_path
    )
    if (
        final_v2_prompt_qualification != retained_final_v2_prompt_qualification
        or final_v2_prompt_qualification_path.read_bytes()
        != canonical_json(final_v2_prompt_qualification) + b"\n"
    ):
        raise AssertionError("protected final V2 prompt qualification changed")

    final_v2_cron_evidence_path = admission_evidence / (
        "runtime-action-worker-final-combined-v2-route-cron-rescan-systemd-p3-"
        "final-store-bound-2026-08-22.json"
    )
    with TemporaryDirectory(prefix="aragorn-protected-final-v2-cron-") as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            final_v2_fresh_session_evidence_path,
            final_v2_prompt_evidence_path,
            final_v2_cron_evidence_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put_expected(
                BytesIO(raw),
                expected_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
                max_bytes=len(raw),
            )
        final_v2_cron_qualification = (
            verify_openclaw_final_combined_v2_cron_rescan(
                evidence_cas=evidence_cas
            )
        )
    final_v2_cron_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-final-combined-v2-cron-rescan-route-coverage-"
        "v1-2026-08-22.json"
    )
    retained_final_v2_cron_qualification = load(
        final_v2_cron_qualification_path
    )
    if (
        final_v2_cron_qualification != retained_final_v2_cron_qualification
        or final_v2_cron_qualification_path.read_bytes()
        != canonical_json(final_v2_cron_qualification) + b"\n"
    ):
        raise AssertionError("protected final V2 cron qualification changed")

    final_v2_session_evidence_path = admission_evidence / (
        "runtime-action-worker-final-combined-v2-route-session-snapshot-consumer-"
        "systemd-p3-final-2026-08-22.json"
    )
    final_v2_session_manifest_path = ROOT / (
        "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-v2-"
        "session-snapshot-compiled-closure-v1.manifest.json"
    )
    final_v2_session_archive_path = ROOT / (
        "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-v2-"
        "session-snapshot-compiled-closure-v1.tar.gz"
    )
    final_v2_session_acquisition_path = admission_receipts / (
        "phase3-openclaw-protected-final-combined-v2-session-snapshot-closure-"
        "acquisition-v1-2026-08-22.json"
    )
    with TemporaryDirectory(prefix="aragorn-protected-final-v2-session-") as temporary:
        evidence_cas = CAS(temporary)
        for path in (
            final_v2_fresh_session_evidence_path,
            final_v2_prompt_evidence_path,
            final_v2_cron_evidence_path,
            final_v2_session_evidence_path,
            final_v2_session_manifest_path,
            final_v2_session_archive_path,
            final_v2_session_acquisition_path,
        ):
            raw = path.read_bytes()
            evidence_cas.put_expected(
                BytesIO(raw),
                expected_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
                max_bytes=len(raw),
            )
        final_v2_session_qualification = (
            verify_openclaw_final_combined_v2_session_snapshot_consumer(
                evidence_cas=evidence_cas
            )
        )
    final_v2_session_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-final-combined-v2-session-snapshot-consumer-"
        "route-coverage-v1-2026-08-22.json"
    )
    retained_final_v2_session_qualification = load(
        final_v2_session_qualification_path
    )
    if (
        final_v2_session_qualification != retained_final_v2_session_qualification
        or final_v2_session_qualification_path.read_bytes()
        != canonical_json(final_v2_session_qualification) + b"\n"
    ):
        raise AssertionError("protected final V2 session qualification changed")

    final_v2_archive_evidence_path = admission_evidence / (
        "runtime-action-worker-final-combined-v2-route-archive-source-force-"
        "replacement-systemd-p3-final-source-fixed-2026-08-22.json"
    )
    with TemporaryDirectory(prefix="aragorn-protected-final-v2-archive-") as temporary:
        evidence_cas = CAS(temporary)
        raw = final_v2_archive_evidence_path.read_bytes()
        evidence_cas.put_expected(
            BytesIO(raw),
            expected_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            max_bytes=len(raw),
        )
        final_v2_archive_qualification = (
            verify_openclaw_final_combined_v2_archive_replacement(
                evidence_cas=evidence_cas
            )
        )
    final_v2_archive_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-final-combined-v2-archive-source-force-"
        "replacement-route-coverage-v1-2026-08-22.json"
    )
    retained_final_v2_archive_qualification = load(
        final_v2_archive_qualification_path
    )
    if (
        final_v2_archive_qualification != retained_final_v2_archive_qualification
        or final_v2_archive_qualification_path.read_bytes()
        != canonical_json(final_v2_archive_qualification) + b"\n"
    ):
        raise AssertionError("protected final V2 archive qualification changed")

    final_v2_catalog_fresh_evidence_path = admission_evidence / (
        "runtime-action-worker-final-combined-v2-route-fresh-session-reset-"
        "systemd-p3-final-catalog-fixed-2026-08-22.json"
    )
    with TemporaryDirectory(prefix="aragorn-protected-final-v2-catalog-fresh-") as temporary:
        evidence_cas = CAS(temporary)
        raw = final_v2_catalog_fresh_evidence_path.read_bytes()
        evidence_cas.put_expected(
            BytesIO(raw),
            expected_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            max_bytes=len(raw),
        )
        final_v2_catalog_fresh_qualification = (
            verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset(
                evidence_cas=evidence_cas
            )
        )
    final_v2_catalog_fresh_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-final-combined-v2-catalog-fixed-fresh-"
        "session-reset-route-coverage-v1-2026-08-22.json"
    )
    retained_final_v2_catalog_fresh_qualification = load(
        final_v2_catalog_fresh_qualification_path
    )
    if (
        final_v2_catalog_fresh_qualification
        != retained_final_v2_catalog_fresh_qualification
        or final_v2_catalog_fresh_qualification_path.read_bytes()
        != canonical_json(final_v2_catalog_fresh_qualification) + b"\n"
    ):
        raise AssertionError(
            "protected final V2 catalog-fixed fresh-session qualification changed"
        )

    final_v2_catalog_cron_evidence_path = admission_evidence / (
        "runtime-action-worker-final-combined-v2-route-cron-rescan-systemd-"
        "p3-final-catalog-fixed-2026-08-22.json"
    )
    with TemporaryDirectory(prefix="aragorn-protected-final-v2-catalog-cron-") as temporary:
        evidence_cas = CAS(temporary)
        raw = final_v2_catalog_cron_evidence_path.read_bytes()
        evidence_cas.put_expected(
            BytesIO(raw),
            expected_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            max_bytes=len(raw),
        )
        final_v2_catalog_cron_qualification = (
            verify_openclaw_final_combined_v2_cron_rescan_catalog_fixed(
                evidence_cas=evidence_cas
            )
        )
    final_v2_catalog_cron_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-final-combined-v2-cron-rescan-catalog-"
        "fixed-route-coverage-v1-2026-08-22.json"
    )
    retained_final_v2_catalog_cron_qualification = load(
        final_v2_catalog_cron_qualification_path
    )
    if (
        final_v2_catalog_cron_qualification
        != retained_final_v2_catalog_cron_qualification
        or final_v2_catalog_cron_qualification_path.read_bytes()
        != canonical_json(final_v2_catalog_cron_qualification) + b"\n"
    ):
        raise AssertionError(
            "protected final V2 catalog-fixed cron qualification changed"
        )

    final_v2_config_evidence_path = admission_evidence / (
        "runtime-action-worker-final-combined-v2-route-config-entry-activation-"
        "systemd-p3-final-catalog-fixed-2026-08-22.json"
    )
    with TemporaryDirectory(prefix="aragorn-protected-final-v2-config-") as temporary:
        evidence_cas = CAS(temporary)
        raw = final_v2_config_evidence_path.read_bytes()
        evidence_cas.put_expected(
            BytesIO(raw),
            expected_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            max_bytes=len(raw),
        )
        final_v2_config_qualification = (
            verify_openclaw_final_combined_v2_config_activation(
                evidence_cas=evidence_cas
            )
        )
    final_v2_config_qualification_path = admission_receipts / (
        "phase3-openclaw-protected-final-combined-v2-config-entry-activation-"
        "route-coverage-v1-2026-08-22.json"
    )
    retained_final_v2_config_qualification = load(
        final_v2_config_qualification_path
    )
    if (
        final_v2_config_qualification != retained_final_v2_config_qualification
        or final_v2_config_qualification_path.read_bytes()
        != canonical_json(final_v2_config_qualification) + b"\n"
    ):
        raise AssertionError("protected final V2 config qualification changed")

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
    phase0_corpus_lock_v4_path = ROOT / "benchmark" / "phase0-corpus-v4.lock.json"
    phase0_corpus_lock_v4_raw = phase0_corpus_lock_v4_path.read_bytes()
    phase0_corpus_lock_v4 = json.loads(phase0_corpus_lock_v4_raw)
    validators["benchmark-corpus-provenance-lock-v2.schema.json"].validate(
        phase0_corpus_lock_v4
    )
    phase0_corpus_lock_v5_path = ROOT / "benchmark" / "phase0-corpus-v5.lock.json"
    phase0_corpus_lock_v5_raw = phase0_corpus_lock_v5_path.read_bytes()
    phase0_corpus_lock_v5 = json.loads(phase0_corpus_lock_v5_raw)
    validators["benchmark-corpus-provenance-lock-v2.schema.json"].validate(
        phase0_corpus_lock_v5
    )
    phase0_corpus_lock_v6_path = ROOT / "benchmark" / "phase0-corpus-v6.lock.json"
    phase0_corpus_lock_v6_raw = phase0_corpus_lock_v6_path.read_bytes()
    phase0_corpus_lock_v6 = json.loads(phase0_corpus_lock_v6_raw)
    validators["benchmark-corpus-provenance-lock-v2.schema.json"].validate(
        phase0_corpus_lock_v6
    )
    if (
        hashlib.sha256(phase0_corpus_lock_v6_raw).hexdigest()
        != "12bda81360181b5c81a9483d861c681efd40083913d3e4c6c4d835814d6c192d"
    ):
        raise AssertionError("checked v6 corpus lock does not match external bytes")
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
    phase0_candidate_policy_v5 = load(
        ROOT / "benchmark" / "phase0-candidate-policy-v5.json"
    )
    validators["benchmark-candidate-policy-v3.schema.json"].validate(
        phase0_candidate_policy_v5
    )
    phase0_candidate_policy_v6 = load(
        ROOT / "benchmark" / "phase0-candidate-policy-v6.json"
    )
    validators["benchmark-candidate-policy-v3.schema.json"].validate(
        phase0_candidate_policy_v6
    )
    phase0_candidate_policy_v7 = load(
        ROOT / "benchmark" / "phase0-candidate-policy-v7.json"
    )
    validators["benchmark-candidate-policy-v3.schema.json"].validate(
        phase0_candidate_policy_v7
    )
    # Phase 0 evidence is historical. Pin its retained identities instead of
    # rebinding it to later Phase 1 source files in this checkout.
    if (
        canonical_digest(phase0_candidate_policy_v7)
        != "sha256:8ac99b957e113fa5d02b759b5e5d12201164f1d04bc6f0bb20cd131efbdf8c98"
        or phase0_candidate_policy_v7["candidate"]["implementation_digest"]
        != "sha256:f42095ad5f4f66e372aceff560bd80b3abdf5e6998f8853014a45e77ebed1895"
    ):
        raise AssertionError("checked v7 candidate policy identity drift")
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
    retained_acquisition_lock_raw = (
        ROOT / "benchmark" / "phase0-acquisition-oracle.lock.json"
    ).read_bytes()
    retained_acquisition_lock = json.loads(retained_acquisition_lock_raw)
    validators[
        "benchmark-phase0-acquisition-oracle-lock-v1.schema.json"
    ].validate(retained_acquisition_lock)
    if (
        retained_acquisition_lock_raw != canonical_json(retained_acquisition_lock)
        or hashlib.sha256(retained_acquisition_lock_raw).hexdigest()
        != "4d9f2fa21b62d928e39993a8ec6b1b7d219b1ce83711784121ca0477526bfbd4"
        or retained_acquisition_lock["candidate_policy_digest"]
        != canonical_digest(phase0_candidate_policy_v6)
        or retained_acquisition_lock["oracle_digest"]
        != "sha256:1ae52836d485b7b9e2bd0eedb1bd926655c20877c5581302a6d44df22067fbe1"
        or retained_acquisition_lock["root_suite_digest"]
        != "sha256:03bcfb7b92b6465fb7d9c1bf9d07f5067aa4afe0b3130ce2a3dcfc66a341f2e7"
        or retained_acquisition_lock["expanded_suite_digest"]
        != "sha256:d9037d0f3acf2a2448f216f4fa58b9f35730da86b832e27cafd0d7be85e87deb"
    ):
        raise AssertionError("retained acquisition oracle lock drift")
    retained_acquisition_v7_lock_raw = (
        ROOT / "benchmark" / "phase0-acquisition-oracle-v7.lock.json"
    ).read_bytes()
    retained_acquisition_v7_lock = json.loads(retained_acquisition_v7_lock_raw)
    validators[
        "benchmark-phase0-acquisition-oracle-lock-v1.schema.json"
    ].validate(retained_acquisition_v7_lock)
    if (
        retained_acquisition_v7_lock_raw
        != canonical_json(retained_acquisition_v7_lock)
        or hashlib.sha256(retained_acquisition_v7_lock_raw).hexdigest()
        != "bd181e7cdcf60fbefec6c6e3ba61554245e0dfad30eed3be9b35d49b5525aaef"
        or retained_acquisition_v7_lock["candidate_policy_digest"]
        != canonical_digest(phase0_candidate_policy_v7)
        or retained_acquisition_v7_lock["oracle_digest"]
        != "sha256:4198475552403f0ea0e7e22c83b3df8414a3d071df5f04dbe205407a0f67007a"
        or retained_acquisition_v7_lock["root_suite_digest"]
        != "sha256:03bcfb7b92b6465fb7d9c1bf9d07f5067aa4afe0b3130ce2a3dcfc66a341f2e7"
        or retained_acquisition_v7_lock["expanded_suite_digest"]
        != "sha256:c6e018cf4a6df22b2126100c125684273edcb28ecf71ae0034330c8c58993a22"
    ):
        raise AssertionError("retained acquisition v7 oracle lock drift")
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
    acquisition_v7_result_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-acquisition-v7-regression-result-2026-07-27.json"
    )
    acquisition_v7_result_raw = acquisition_v7_result_path.read_bytes()
    acquisition_v7_result = json.loads(acquisition_v7_result_raw)
    validators[
        "benchmark-phase0-acquisition-regression-result-receipt-v1.schema.json"
    ].validate(acquisition_v7_result)
    if acquisition_v7_result_raw != canonical_json(acquisition_v7_result):
        raise AssertionError("acquisition v7 result receipt is not canonical JSON")
    acquisition_worker_run = acquisition_v7_result["worker_run_receipt"]
    acquisition_gate_report = acquisition_v7_result["gate_report"]
    acquisition_source = acquisition_v7_result["source"]
    validators[
        "benchmark-phase0-acquisition-gate-report-v1.schema.json"
    ].validate(acquisition_gate_report)
    if (
        acquisition_source["worker_run_receipt_digest"]
        != canonical_digest(acquisition_worker_run)
        or acquisition_source["gate_report_file_digest"]
        != canonical_digest(acquisition_gate_report)
    ):
        raise AssertionError("acquisition v7 embedded evidence digest drift")
    expected_acquisition_source = {
        "candidate_implementation_digest": (
            "sha256:f42095ad5f4f66e372aceff560bd80b3abdf5e6998f8853014a45e77ebed1895"
        ),
        "plan_digest": (
            "sha256:c739e7f06eff2703ad8e165fcaa0ebd9de7b0bba9bc161b446fc60285acc0906"
        ),
        "plan_file_digest": (
            "sha256:c739e7f06eff2703ad8e165fcaa0ebd9de7b0bba9bc161b446fc60285acc0906"
        ),
        "runner_commit": "a5f8c2fbca699c2aafc50f2e32cb619ca131cda9",
        "runner_digest": (
            "sha256:06edee39b4c1215dbecae4221ff35ad67f7f49060987bf39b3226d76fb86e66f"
        ),
    }
    if (
        acquisition_source["evaluator_commit"]
        != acquisition_worker_run["source"]["runner_commit"]
        or acquisition_worker_run["source"] != expected_acquisition_source
        or acquisition_worker_run["totals"]
        != {"accepted_count": 1792, "outcome_count": 2240}
        or {
            arm: (
                acquisition_worker_run["arms"][arm]["accepted_count"],
                acquisition_worker_run["arms"][arm]["outcome_count"],
            )
            for arm in ("root", "expanded")
        }
        != {"root": (896, 896), "expanded": (896, 1344)}
    ):
        raise AssertionError("acquisition v7 worker receipt drift")
    expected_acquisition_gate_bindings = {
        "oracle_lock_digest": canonical_digest(retained_acquisition_v7_lock),
        "oracle_digest": retained_acquisition_v7_lock["oracle_digest"],
        "candidate_policy_digest": retained_acquisition_v7_lock[
            "candidate_policy_digest"
        ],
    }
    for field, expected in expected_acquisition_gate_bindings.items():
        if acquisition_gate_report[field] != expected:
            raise AssertionError(f"acquisition v7 gate report {field} drift")
    for arm in ("root", "expanded"):
        if (
            acquisition_gate_report[f"{arm}_arm"]["suite_digest"]
            != retained_acquisition_v7_lock[f"{arm}_suite_digest"]
            or acquisition_gate_report[f"{arm}_arm"]["outcomes_digest"]
            != acquisition_worker_run["arms"][arm]["outcomes_digest"]
        ):
            raise AssertionError(f"acquisition v7 {arm} arm drift")
    acquisition_accounting = acquisition_gate_report["accounting"]
    if {
        field: acquisition_accounting[field]
        for field in (
            "cases",
            "complete_expansions",
            "incomplete_expansions",
            "expected_references",
            "captured_references",
            "missed_references",
            "wrong_target_references",
            "unresolved_expected_references",
        )
    } != {
        "cases": 448,
        "complete_expansions": 448,
        "incomplete_expansions": 0,
        "expected_references": 448,
        "captured_references": 448,
        "missed_references": 0,
        "wrong_target_references": 0,
        "unresolved_expected_references": 0,
    }:
        raise AssertionError("acquisition v7 reference accounting drift")
    acquisition_comparison = acquisition_gate_report["comparison"]
    expected_acquisition_candidate = {
        **phase0_candidate_policy_v7["candidate"],
        "config_digest": canonical_digest(phase0_candidate_policy_v7),
    }
    if (
        acquisition_v7_result["evaluation_status"]
        != (
            "regression_rerun_on_previously_evaluated_acquisition_corpus_"
            "not_fresh_holdout"
        )
        or acquisition_v7_result["phase0_exit_eligible"]
        or acquisition_comparison["candidate"]["system"]
        != expected_acquisition_candidate
        or not acquisition_comparison["evaluable"]
        or not acquisition_comparison["passed"]
        or acquisition_comparison["reason_codes"]
        or acquisition_comparison["attack_flag_delta"]
        != {"numerator": 1, "denominator": 8, "rate": 0.125}
        or acquisition_comparison["candidate"]["benign_intervention"]
        != {"numerator": 0, "denominator": 1, "rate": 0.0}
    ):
        raise AssertionError("acquisition v7 result is not retained as regression")
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
    hidden_v4_lock_path = ROOT / "benchmark" / "phase0-hidden-suite-v4.lock.json"
    hidden_v4_lock_raw = hidden_v4_lock_path.read_bytes()
    hidden_v4_lock = json.loads(hidden_v4_lock_raw)
    hidden_v4_receipt_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-suite-v4-freeze-2026-07-26.json"
    )
    hidden_v4_receipt_raw = hidden_v4_receipt_path.read_bytes()
    hidden_v4_receipt = json.loads(hidden_v4_receipt_raw)
    validators["benchmark-phase0-hidden-suite-lock-v1.schema.json"].validate(
        hidden_v4_lock
    )
    validators["benchmark-phase0-hidden-suite-freeze-receipt-v4.schema.json"].validate(
        hidden_v4_receipt
    )
    validate_freeze_receipt_bindings(
        hidden_v4_receipt,
        hidden_v4_receipt_raw,
        hidden_v4_lock,
        hidden_v4_lock_raw,
        phase0_corpus_lock_v4,
        phase0_corpus_lock_v4_raw,
    )
    hidden_v4_preparation_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v4-preparation-2026-07-26.json"
    )
    if hidden_v4_preparation_path.exists():
        hidden_v4_preparation_raw = hidden_v4_preparation_path.read_bytes()
        hidden_v4_preparation = json.loads(hidden_v4_preparation_raw)
        validators[
            "benchmark-phase0-hidden-preparation-receipt-v4.schema.json"
        ].validate(hidden_v4_preparation)
        validate_retained_preparation_receipt(
            hidden_v4_preparation,
            hidden_v4_preparation_raw,
            hidden_v4_lock,
            hidden_v4_receipt,
            _V4_GATE,
        )
    hidden_v5_lock_path = ROOT / "benchmark" / "phase0-hidden-suite-v5.lock.json"
    hidden_v5_lock_raw = hidden_v5_lock_path.read_bytes()
    hidden_v5_lock = json.loads(hidden_v5_lock_raw)
    hidden_v5_receipt_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-suite-v5-freeze-2026-07-26.json"
    )
    hidden_v5_receipt_raw = hidden_v5_receipt_path.read_bytes()
    hidden_v5_receipt = json.loads(hidden_v5_receipt_raw)
    validators["benchmark-phase0-hidden-suite-lock-v1.schema.json"].validate(
        hidden_v5_lock
    )
    validators["benchmark-phase0-hidden-suite-freeze-receipt-v5.schema.json"].validate(
        hidden_v5_receipt
    )
    if (
        "sha256:" + hashlib.sha256(hidden_v5_lock_raw).hexdigest()
        != _V5_GATE.lock_digest
        or "sha256:" + hashlib.sha256(hidden_v5_receipt_raw).hexdigest()
        != _V5_GATE.freeze_receipt_digest
        or hidden_v5_lock["corpus_lock_digest"]
        != "sha256:" + hashlib.sha256(phase0_corpus_lock_v5_raw).hexdigest()
        or hidden_v5_lock["suite_digest"] != _V5_GATE.suite_digest
        or hidden_v5_lock["candidate_policy_digest"]
        != _V5_GATE.candidate_policy_digest
        or hidden_v5_receipt["pre_outcome"]["state_binding_digest"]
        != _V5_GATE.state_binding_digest
    ):
        raise AssertionError("hidden v5 frozen gate binding drift")
    hidden_v5_preparation_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v5-preparation-2026-07-26.json"
    )
    if hidden_v5_preparation_path.exists():
        hidden_v5_preparation_raw = hidden_v5_preparation_path.read_bytes()
        hidden_v5_preparation = json.loads(hidden_v5_preparation_raw)
        validators[
            "benchmark-phase0-hidden-preparation-receipt-v5.schema.json"
        ].validate(hidden_v5_preparation)
        validate_retained_preparation_receipt(
            hidden_v5_preparation,
            hidden_v5_preparation_raw,
            hidden_v5_lock,
            hidden_v5_receipt,
            _V5_GATE,
        )
    hidden_v6_lock_path = ROOT / "benchmark" / "phase0-hidden-suite-v6.lock.json"
    hidden_v6_lock_raw = hidden_v6_lock_path.read_bytes()
    hidden_v6_lock = json.loads(hidden_v6_lock_raw)
    hidden_v6_receipt_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-suite-v6-freeze-2026-07-26.json"
    )
    hidden_v6_receipt_raw = hidden_v6_receipt_path.read_bytes()
    hidden_v6_receipt = json.loads(hidden_v6_receipt_raw)
    validators["benchmark-phase0-hidden-suite-lock-v1.schema.json"].validate(
        hidden_v6_lock
    )
    validators["benchmark-phase0-hidden-suite-freeze-receipt-v6.schema.json"].validate(
        hidden_v6_receipt
    )
    if (
        "sha256:" + hashlib.sha256(hidden_v6_lock_raw).hexdigest()
        != _V6_GATE.lock_digest
        or "sha256:" + hashlib.sha256(hidden_v6_receipt_raw).hexdigest()
        != _V6_GATE.freeze_receipt_digest
        or hidden_v6_lock["corpus_lock_digest"]
        != "sha256:" + hashlib.sha256(phase0_corpus_lock_v6_raw).hexdigest()
        or hidden_v6_lock["suite_digest"] != _V6_GATE.suite_digest
        or hidden_v6_lock["candidate_policy_digest"]
        != _V6_GATE.candidate_policy_digest
        or hidden_v6_receipt["pre_outcome"]["state_binding_digest"]
        != _V6_GATE.state_binding_digest
    ):
        raise AssertionError("hidden v6 frozen gate binding drift")
    hidden_v6_preparation_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v6-preparation-2026-07-26.json"
    )
    if hidden_v6_preparation_path.exists():
        hidden_v6_preparation_raw = hidden_v6_preparation_path.read_bytes()
        hidden_v6_preparation = json.loads(hidden_v6_preparation_raw)
        validators[
            "benchmark-phase0-hidden-preparation-receipt-v5.schema.json"
        ].validate(hidden_v6_preparation)
        validate_retained_preparation_receipt(
            hidden_v6_preparation,
            hidden_v6_preparation_raw,
            hidden_v6_lock,
            hidden_v6_receipt,
            _V6_GATE,
        )
    hidden_v7_lock_path = ROOT / "benchmark" / "phase0-hidden-suite-v7.lock.json"
    hidden_v7_lock_raw = hidden_v7_lock_path.read_bytes()
    hidden_v7_lock = json.loads(hidden_v7_lock_raw)
    hidden_v7_receipt_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-suite-v7-freeze-2026-07-27.json"
    )
    hidden_v7_receipt_raw = hidden_v7_receipt_path.read_bytes()
    hidden_v7_receipt = json.loads(hidden_v7_receipt_raw)
    validators["benchmark-phase0-hidden-suite-lock-v1.schema.json"].validate(
        hidden_v7_lock
    )
    validators["benchmark-phase0-hidden-v7-freeze-profile-v1.schema.json"].validate(
        hidden_v7_receipt
    )
    validate_freeze_receipt_bindings(
        hidden_v7_receipt,
        hidden_v7_receipt_raw,
        hidden_v7_lock,
        hidden_v7_lock_raw,
        phase0_corpus_lock_v6,
        phase0_corpus_lock_v6_raw,
    )
    if (
        "sha256:" + hashlib.sha256(hidden_v7_lock_raw).hexdigest()
        != _V7_GATE.lock_digest
        or "sha256:" + hashlib.sha256(hidden_v7_receipt_raw).hexdigest()
        != _V7_GATE.freeze_receipt_digest
        or hidden_v7_lock["suite_digest"] != _V7_GATE.suite_digest
        or hidden_v7_lock["candidate_policy_digest"]
        != _V7_GATE.candidate_policy_digest
        or hidden_v7_receipt["pre_outcome"]["state_binding_digest"]
        != _V7_GATE.state_binding_digest
    ):
        raise AssertionError("hidden v7 frozen gate binding drift")
    hidden_v7_preparation_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v7-preparation-2026-07-27.json"
    )
    hidden_v7_preparation_raw = hidden_v7_preparation_path.read_bytes()
    hidden_v7_preparation = json.loads(hidden_v7_preparation_raw)
    validators[
        "benchmark-phase0-hidden-v7-preparation-profile-v1.schema.json"
    ].validate(hidden_v7_preparation)
    validate_retained_preparation_receipt(
        hidden_v7_preparation,
        hidden_v7_preparation_raw,
        hidden_v7_lock,
        hidden_v7_receipt,
        _V7_GATE,
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
    hidden_v4_calibration_result_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v4-calibration-result-2026-07-26.json"
    )
    if hidden_v4_calibration_result_path.exists():
        if not hidden_v4_preparation_path.exists():
            raise AssertionError(
                "hidden v4 calibration result requires its retained "
                "preparation receipt"
            )
        hidden_v4_calibration_result_raw = (
            hidden_v4_calibration_result_path.read_bytes()
        )
        hidden_v4_calibration_result = json.loads(
            hidden_v4_calibration_result_raw
        )
        validators[
            "benchmark-phase0-hidden-calibration-result-receipt-v2.schema.json"
        ].validate(hidden_v4_calibration_result)
        if hidden_v4_calibration_result_raw != canonical_json(
            hidden_v4_calibration_result
        ):
            raise AssertionError(
                "hidden v4 calibration result receipt is not canonical JSON"
            )
        worker_run = hidden_v4_calibration_result["worker_run_receipt"]
        gate_report = hidden_v4_calibration_result["gate_report"]
        source = hidden_v4_calibration_result["source"]
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
            "sha256:" + hashlib.sha256(hidden_v4_preparation_raw).hexdigest()
        )
        hidden_v4_lock_digest = (
            "sha256:" + hashlib.sha256(hidden_v4_lock_raw).hexdigest()
        )
        if source["worker_run_receipt_digest"] != worker_run_digest:
            raise AssertionError("hidden v4 calibration worker receipt digest drift")
        if source["gate_report_file_digest"] != gate_report_file_digest:
            raise AssertionError(
                "hidden v4 calibration gate report file digest drift"
            )
        if source["evaluator_commit"] != worker_run["source"]["runner_commit"]:
            raise AssertionError("hidden v4 calibration evaluator commit drift")
        if (
            worker_run["source"]["preparation_receipt_digest"]
            != preparation_digest
        ):
            raise AssertionError(
                "hidden v4 calibration preparation receipt digest drift"
            )
        if worker_run["state"]["binding_digest"] != _V4_GATE.state_binding_digest:
            raise AssertionError("hidden v4 calibration run state binding drift")
        if (
            hidden_v4_calibration_result["evaluation_status"]
            != "calibration_rerun_on_previously_evaluated_corpus_not_fresh_holdout"
            or hidden_v4_calibration_result["phase0_exit_eligible"]
        ):
            raise AssertionError("hidden v4 result is not retained as calibration")
        if (
            worker_run["composition"]["outcomes_digest"]
            != gate_report["outcomes_digest"]
        ):
            raise AssertionError("hidden v4 calibration outcome digest drift")
        expected_gate_bindings = {
            "corpus_lock_digest": hidden_v4_lock["corpus_lock_digest"],
            "public_manifest_digest": hidden_v4_lock["public_manifest_digest"],
            "hidden_suite_lock_digest": hidden_v4_lock_digest,
            "candidate_policy_digest": hidden_v4_lock[
                "candidate_policy_digest"
            ],
            "label_ledger_digest": hidden_v4_lock["label_ledger_digest"],
            "suite_digest": hidden_v4_lock["suite_digest"],
        }
        for field, expected in expected_gate_bindings.items():
            if gate_report[field] != expected:
                raise AssertionError(
                    f"hidden v4 calibration gate report {field} drift"
                )
        if gate_report["comparison"]["passed"]:
            raise AssertionError(
                "retained hidden v4 calibration result unexpectedly passed"
            )
    hidden_v5_result_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v5-result-2026-07-26.json"
    )
    if hidden_v5_result_path.exists():
        if not hidden_v5_preparation_path.exists():
            raise AssertionError(
                "hidden v5 result requires its retained preparation receipt"
            )
        hidden_v5_result_raw = hidden_v5_result_path.read_bytes()
        hidden_v5_result = json.loads(hidden_v5_result_raw)
        validators[
            "benchmark-phase0-hidden-result-receipt-v2.schema.json"
        ].validate(hidden_v5_result)
        if hidden_v5_result_raw != canonical_json(hidden_v5_result):
            raise AssertionError("hidden v5 result receipt is not canonical JSON")
        worker_run = hidden_v5_result["worker_run_receipt"]
        gate_report = hidden_v5_result["gate_report"]
        source = hidden_v5_result["source"]
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
            "sha256:" + hashlib.sha256(hidden_v5_preparation_raw).hexdigest()
        )
        hidden_v5_lock_digest = (
            "sha256:" + hashlib.sha256(hidden_v5_lock_raw).hexdigest()
        )
        if source["worker_run_receipt_digest"] != worker_run_digest:
            raise AssertionError("hidden v5 worker receipt digest drift")
        if source["gate_report_file_digest"] != gate_report_file_digest:
            raise AssertionError("hidden v5 gate report file digest drift")
        if (
            source["evaluator_commit"]
            != worker_run["source"]["runner_commit"]
            or source["evaluator_commit"]
            != "b9cc81a8f18630fb62993f3d94de5b18a246624e"
        ):
            raise AssertionError("hidden v5 evaluator commit drift")
        if worker_run["source"]["preparation_receipt_digest"] != preparation_digest:
            raise AssertionError("hidden v5 preparation receipt digest drift")
        if worker_run["state"]["binding_digest"] != _V5_GATE.state_binding_digest:
            raise AssertionError("hidden v5 run state binding drift")
        if (
            worker_run["composition"]["outcomes_digest"]
            != gate_report["outcomes_digest"]
        ):
            raise AssertionError("hidden v5 outcome digest drift")
        expected_gate_bindings = {
            "corpus_lock_digest": hidden_v5_lock["corpus_lock_digest"],
            "public_manifest_digest": hidden_v5_lock["public_manifest_digest"],
            "hidden_suite_lock_digest": hidden_v5_lock_digest,
            "candidate_policy_digest": hidden_v5_lock[
                "candidate_policy_digest"
            ],
            "label_ledger_digest": hidden_v5_lock["label_ledger_digest"],
            "suite_digest": hidden_v5_lock["suite_digest"],
        }
        for field, expected in expected_gate_bindings.items():
            if gate_report[field] != expected:
                raise AssertionError(f"hidden v5 gate report {field} drift")
        comparison = gate_report["comparison"]
        if (
            hidden_v5_result["evaluation_status"]
            != "calibration_diagnostic_only_due_to_worker_visible_label_proxy_leakage"
            or hidden_v5_result["phase0_exit_eligible"]
            or hidden_v5_result["limitations"]
            != {
                "worker_visibility": (
                    "worker_visible_label_proxy_leakage_"
                    "invalidates_clean_hidden_assurance"
                ),
                "evaluation_use": (
                    "calibration_and_diagnostic_only_despite_"
                    "chronological_freshness"
                ),
            }
            or not comparison["evaluable"]
            or comparison["passed"]
            or comparison["reason_codes"]
            != ["ATTACK_FLAG_DELTA_BELOW_10PP"]
        ):
            raise AssertionError(
                "hidden v5 result is not retained as failed diagnostic evidence"
            )
    hidden_v6_result_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v6-result-2026-07-26.json"
    )
    if hidden_v6_result_path.exists():
        if not hidden_v6_preparation_path.exists():
            raise AssertionError(
                "hidden v6 result requires its retained preparation receipt"
            )
        hidden_v6_result_raw = hidden_v6_result_path.read_bytes()
        hidden_v6_result = json.loads(hidden_v6_result_raw)
        validators[
            "benchmark-phase0-hidden-result-receipt-v3.schema.json"
        ].validate(hidden_v6_result)
        if hidden_v6_result_raw != canonical_json(hidden_v6_result):
            raise AssertionError("hidden v6 result receipt is not canonical JSON")
        worker_run = hidden_v6_result["worker_run_receipt"]
        gate_report = hidden_v6_result["gate_report"]
        source = hidden_v6_result["source"]
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
            "sha256:" + hashlib.sha256(hidden_v6_preparation_raw).hexdigest()
        )
        hidden_v6_lock_digest = (
            "sha256:" + hashlib.sha256(hidden_v6_lock_raw).hexdigest()
        )
        if source["worker_run_receipt_digest"] != worker_run_digest:
            raise AssertionError("hidden v6 worker receipt digest drift")
        if source["gate_report_file_digest"] != gate_report_file_digest:
            raise AssertionError("hidden v6 gate report file digest drift")
        if (
            source["evaluator_commit"]
            != worker_run["source"]["runner_commit"]
            or source["evaluator_commit"]
            != "5a4f11802d0a412307be4b834d72801b11b03eb8"
        ):
            raise AssertionError("hidden v6 evaluator commit drift")
        if worker_run["source"]["preparation_receipt_digest"] != preparation_digest:
            raise AssertionError("hidden v6 preparation receipt digest drift")
        if worker_run["state"]["binding_digest"] != _V6_GATE.state_binding_digest:
            raise AssertionError("hidden v6 run state binding drift")
        if worker_run["composition"]["outcomes_digest"] != gate_report[
            "outcomes_digest"
        ]:
            raise AssertionError("hidden v6 outcome digest drift")
        expected_gate_bindings = {
            "corpus_lock_digest": hidden_v6_lock["corpus_lock_digest"],
            "public_manifest_digest": hidden_v6_lock["public_manifest_digest"],
            "hidden_suite_lock_digest": hidden_v6_lock_digest,
            "candidate_policy_digest": hidden_v6_lock["candidate_policy_digest"],
            "label_ledger_digest": hidden_v6_lock["label_ledger_digest"],
            "suite_digest": hidden_v6_lock["suite_digest"],
        }
        for field, expected in expected_gate_bindings.items():
            if gate_report[field] != expected:
                raise AssertionError(f"hidden v6 gate report {field} drift")
        comparison = gate_report["comparison"]
        if (
            not hidden_v6_result["phase0_exit_eligible"]
            or not comparison["evaluable"]
            or not comparison["passed"]
            or comparison["reason_codes"]
            or comparison["attack_flag_delta"]
            != {"numerator": 33, "denominator": 112, "rate": 0.294643}
            or comparison["candidate"]["benign_intervention"]
            != {"numerator": 1, "denominator": 24, "rate": 0.041667}
        ):
            raise AssertionError("hidden v6 result is not the retained passing gate")
    hidden_v7_result_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-hidden-v7-calibration-result-2026-07-27.json"
    )
    hidden_v7_result_raw = hidden_v7_result_path.read_bytes()
    hidden_v7_result = json.loads(hidden_v7_result_raw)
    validators[
        "benchmark-phase0-hidden-calibration-result-receipt-v3.schema.json"
    ].validate(hidden_v7_result)
    if hidden_v7_result_raw != canonical_json(hidden_v7_result):
        raise AssertionError("hidden v7 result receipt is not canonical JSON")
    worker_run = hidden_v7_result["worker_run_receipt"]
    gate_report = hidden_v7_result["gate_report"]
    source = hidden_v7_result["source"]
    validators[
        "benchmark-phase0-hidden-v7-worker-run-profile-v1.schema.json"
    ].validate(worker_run)
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
        "sha256:" + hashlib.sha256(hidden_v7_preparation_raw).hexdigest()
    )
    hidden_v7_lock_digest = (
        "sha256:" + hashlib.sha256(hidden_v7_lock_raw).hexdigest()
    )
    if source["worker_run_receipt_digest"] != worker_run_digest:
        raise AssertionError("hidden v7 worker receipt digest drift")
    if source["gate_report_file_digest"] != gate_report_file_digest:
        raise AssertionError("hidden v7 gate report file digest drift")
    if (
        source["evaluator_commit"] != worker_run["source"]["runner_commit"]
        or source["evaluator_commit"]
        != "a91affe50b26a9bc25839f7c98e3f47f05e16c58"
    ):
        raise AssertionError("hidden v7 evaluator commit drift")
    if worker_run["source"]["preparation_receipt_digest"] != preparation_digest:
        raise AssertionError("hidden v7 preparation receipt digest drift")
    if worker_run["state"]["binding_digest"] != _V7_GATE.state_binding_digest:
        raise AssertionError("hidden v7 run state binding drift")
    if worker_run["composition"]["outcomes_digest"] != gate_report[
        "outcomes_digest"
    ]:
        raise AssertionError("hidden v7 outcome digest drift")
    expected_gate_bindings = {
        "corpus_lock_digest": hidden_v7_lock["corpus_lock_digest"],
        "public_manifest_digest": hidden_v7_lock["public_manifest_digest"],
        "hidden_suite_lock_digest": hidden_v7_lock_digest,
        "candidate_policy_digest": hidden_v7_lock["candidate_policy_digest"],
        "label_ledger_digest": hidden_v7_lock["label_ledger_digest"],
        "suite_digest": hidden_v7_lock["suite_digest"],
    }
    for field, expected in expected_gate_bindings.items():
        if gate_report[field] != expected:
            raise AssertionError(f"hidden v7 gate report {field} drift")
    comparison = gate_report["comparison"]
    if (
        hidden_v7_result["evaluation_status"]
        != "calibration_rerun_on_previously_evaluated_corpus_not_fresh_holdout"
        or hidden_v7_result["phase0_exit_eligible"]
        or not comparison["evaluable"]
        or not comparison["passed"]
        or comparison["reason_codes"]
        or comparison["attack_flag_delta"]
        != {"numerator": 33, "denominator": 112, "rate": 0.294643}
        or comparison["candidate"]["benign_intervention"]
        != {"numerator": 1, "denominator": 24, "rate": 0.041667}
    ):
        raise AssertionError("hidden v7 result is not retained as passing calibration")
    phase0_milestone_path = (
        ROOT
        / "benchmark"
        / "receipts"
        / "phase0-validation-milestone-2026-07-27.json"
    )
    phase0_milestone_raw = phase0_milestone_path.read_bytes()
    phase0_milestone = json.loads(phase0_milestone_raw)
    validators[
        "benchmark-phase0-validation-milestone-receipt-v1.schema.json"
    ].validate(phase0_milestone)
    if phase0_milestone_raw != canonical_json(phase0_milestone):
        raise AssertionError("phase0 validation milestone is not canonical JSON")
    milestone_criteria = phase0_milestone["criteria"]
    milestone_components = {
        "fresh_hidden_efficacy": (
            hidden_v6_result_path,
            hidden_v6_result_raw,
            hidden_v6_result,
        ),
        "final_candidate_maintenance": (
            hidden_v7_result_path,
            hidden_v7_result_raw,
            hidden_v7_result,
        ),
        "bounded_acquisition_integration": (
            acquisition_v7_result_path,
            acquisition_v7_result_raw,
            acquisition_v7_result,
        ),
    }
    for criterion, (path, raw, document) in milestone_components.items():
        retained = milestone_criteria[criterion]
        if (
            retained["receipt_path"] != str(path.relative_to(ROOT))
            or retained["file_digest"]
            != "sha256:" + hashlib.sha256(raw).hexdigest()
            or retained["phase0_exit_eligible"]
            != document["phase0_exit_eligible"]
        ):
            raise AssertionError(f"phase0 milestone {criterion} binding drift")
    standards_gate_path = ROOT / "benchmark" / "phase0-standards-gate.json"
    standards_gate_raw = standards_gate_path.read_bytes()
    retained_standards = milestone_criteria["standards_coverage"]
    if (
        retained_standards["document_path"]
        != str(standards_gate_path.relative_to(ROOT))
        or retained_standards["file_digest"]
        != "sha256:" + hashlib.sha256(standards_gate_raw).hexdigest()
        or retained_standards["summary"] != standards_gate["gate"]["summary"]
        or standards_gate["gate"]["result"] != "pass"
    ):
        raise AssertionError("phase0 milestone standards binding drift")
    milestone_decision = phase0_milestone["decision"]
    milestone_v6_candidate = hidden_v6_result["gate_report"]["comparison"][
        "candidate"
    ]["system"]
    milestone_v7_candidate = hidden_v7_result["gate_report"]["comparison"][
        "candidate"
    ]["system"]
    milestone_acquisition_candidate = acquisition_v7_result["gate_report"][
        "comparison"
    ]["candidate"]["system"]
    expected_milestone_v6_candidate = {
        **phase0_candidate_policy_v6["candidate"],
        "config_digest": canonical_digest(phase0_candidate_policy_v6),
    }
    expected_milestone_v7_candidate = {
        **phase0_candidate_policy_v7["candidate"],
        "config_digest": canonical_digest(phase0_candidate_policy_v7),
    }
    if (
        phase0_milestone["component_digest_kind"] != "raw_sha256"
        or phase0_milestone["scope"] != "phase_evidence_validation_only"
        or milestone_decision["status"]
        != "qualified_phase0_validation_complete"
        or milestone_decision["result"] != "pass"
        or not milestone_decision["phase0_validation_milestone_complete"]
        or not milestone_decision["phase1_entry_eligible"]
        or milestone_decision["fresh_final_candidate_claim"]
        or milestone_decision["fresh_acquisition_generalization_claim"]
        or milestone_decision["admission_eligible"]
        or milestone_decision["public_release_eligible"]
        or milestone_criteria["fresh_hidden_efficacy"]["status"]
        != "satisfied_by_v6"
        or milestone_criteria["final_candidate_maintenance"]["status"]
        != "satisfied_by_v7_calibration"
        or milestone_criteria["bounded_acquisition_integration"]["status"]
        != "satisfied_by_v7_regression"
        or milestone_criteria["fresh_acquisition_generalization"]["status"]
        != "not_claimed"
        or milestone_criteria["standards_coverage"]["status"] != "satisfied"
        or not milestone_criteria["fresh_hidden_efficacy"][
            "criterion_satisfied"
        ]
        or not milestone_criteria["final_candidate_maintenance"][
            "criterion_satisfied"
        ]
        or not milestone_criteria["bounded_acquisition_integration"][
            "criterion_satisfied"
        ]
        or milestone_criteria["fresh_acquisition_generalization"][
            "criterion_satisfied"
        ]
        or not milestone_criteria["standards_coverage"]["criterion_satisfied"]
        or not hidden_v6_result["phase0_exit_eligible"]
        or hidden_v7_result["phase0_exit_eligible"]
        or acquisition_v7_result["phase0_exit_eligible"]
        or hidden_v6_result["evaluation_status"] != "fresh_clean_holdout_passed"
        or hidden_v7_result["evaluation_status"]
        != "calibration_rerun_on_previously_evaluated_corpus_not_fresh_holdout"
        or hidden_v6_result["gate_report"]["corpus_lock_digest"]
        != hidden_v7_result["gate_report"]["corpus_lock_digest"]
        or milestone_v6_candidate != expected_milestone_v6_candidate
        or milestone_v7_candidate != expected_milestone_v7_candidate
        or milestone_acquisition_candidate != expected_milestone_v7_candidate
        or milestone_v6_candidate == milestone_v7_candidate
        or milestone_criteria["fresh_hidden_efficacy"]["evidence_role"]
        != "sole_fresh_hidden_efficacy_evidence"
        or milestone_criteria["final_candidate_maintenance"]["evidence_role"]
        != "maintenance_only_not_fresh_exit_evidence"
        or milestone_criteria["bounded_acquisition_integration"]["evidence_role"]
        != (
            "authenticated_terminal_depth_1_integration_regression_"
            "not_fresh_generalization_or_standalone_exit_evidence"
        )
        or acquisition_v7_result["assurance"]
        != (
            "aggregate_authenticated_acquisition_regression_evidence_only_"
            "not_fresh_holdout_or_standalone_phase0_exit_evidence"
        )
        or standards_gate["gate"]["required_packs"]
        != ["owasp-agentic-skills", "mitre-atlas", "nist-ai-rmf-genai"]
    ):
        raise AssertionError("phase0 validation milestone transfers evidence scope")
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
    validators["benchmark-phase0-hidden-worker-run-receipt-v4.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v4",
            "assurance": (
                "authenticated_complete_worker_batch_not_independent_or_hardware_attested"
            ),
            "source": {
                "runner_commit": "1" * 40,
                "preparation_receipt_digest": digest,
            },
            "state": {
                "layout": "phase0-hidden-run-state/v1",
                "binding_digest": _V4_GATE.state_binding_digest,
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
    validators["benchmark-phase0-hidden-worker-run-receipt-v5.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v5",
            "assurance": (
                "authenticated_complete_worker_batch_not_independent_or_hardware_attested"
            ),
            "source": {
                "runner_commit": "1" * 40,
                "preparation_receipt_digest": digest,
            },
            "state": {
                "layout": "phase0-hidden-run-state/v1",
                "binding_digest": _V5_GATE.state_binding_digest,
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
    validators["benchmark-cas-handoff-v1.schema.json"].validate(
        build_handoff_manifest(
            kind="runtime_evidence",
            root_digest="sha256:" + "0" * 64,
            blobs={f"sha256:{index:064x}": 0 for index in range(69)},
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
    terminal_graph = deepcopy(source_graph)
    terminal_graph["profile"] = (
        "phase0-exact-github-blob-expansion-terminal-depth-1/v1"
    )
    terminal_graph["assurance"] = (
        "evaluation_only_github_api_membership_asserted_blob_identity_reverified_"
        "depth_1_targets_terminal_not_reference_scanned"
    )
    terminal_graph["source_assurance"] = (
        "github_api_membership_asserted_blob_identity_reverified"
    )
    terminal_graph["nodes"][0]["scan_status"] = "terminal"
    terminal_graph["closure"]["profile"] = terminal_graph["profile"]
    validators["source-artifact-graph-v1.schema.json"].validate(terminal_graph)
    generic_terminal_graph = deepcopy(source_graph)
    generic_terminal_graph["nodes"][0]["scan_status"] = "terminal"
    if validators["source-artifact-graph-v1.schema.json"].is_valid(
        generic_terminal_graph
    ):
        raise AssertionError("generic source graph accepted a terminal node")
    mismatched_terminal_graph = deepcopy(terminal_graph)
    mismatched_terminal_graph["closure"]["profile"] = source_graph["profile"]
    if validators["source-artifact-graph-v1.schema.json"].is_valid(
        mismatched_terminal_graph
    ):
        raise AssertionError("terminal source graph accepted a generic closure")
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
    decision_v2 = {
        **decision,
        "schema": "aragorn/decision/v2",
        "authority": "EVIDENCE_SUMMARY_ONLY_NOT_INSTALLER_AUTHORITY",
        "analyzers": [
            {
                "name": "schema-test",
                "version": "1",
                "config_digest": digest,
                "executable_digest": digest,
                "status": "ok",
                "run_receipt_digest": digest,
                "observation_digests": [],
                "stdout_digest": digest,
                "stderr_digest": digest,
                "returncode": 0,
            }
        ],
    }
    validators["inspect-result-v2.schema.json"].validate(
        {
            "schema": "aragorn/inspect-result/v2",
            "decision_digest": digest,
            "decision": decision_v2,
        }
    )
    validators["decision-v3.schema.json"].validate(
        {
            **decision_v2,
            "schema": "aragorn/decision/v3",
            "artifact_graph_digest": digest,
            "artifact_digests": [digest],
        }
    )
    validators["analyzer-run-receipt-v1.schema.json"].validate(
        {
            "schema": "aragorn/analyzer-run-receipt/v1",
            "authority": "EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY",
            "verifier": {
                "name": "aragorn/analyzer-run-verifier/v1",
                "implementation_digest": digest,
            },
            "request_digest": digest,
            "stdout_digest": digest,
            "stderr_digest": digest,
            "observation_digests": [],
            "execution": {
                "status": "ok",
                "error_code": None,
                "error_message": None,
                "returncode": 0,
            },
        }
    )
    print(f"validated {len(schemas)} schemas and checked-in contract examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
