from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

import aragorn.benchmark_authenticated_handoff_v2 as authenticated_handoff
from aragorn import benchmark
from aragorn.benchmark import BenchmarkError, _verify_candidate_batch_bindings
from aragorn.phase0_candidate import (
    candidate_implementation_digest,
    candidate_policy_digest,
    candidate_system_identity,
)

_ROOT = Path(__file__).parents[1]


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _bindings() -> list[dict]:
    policy = json.loads(
        (_ROOT / "benchmark" / "phase0-candidate-policy.json").read_bytes()
    )
    policy["candidate"]["implementation_digest"] = candidate_implementation_digest()
    policy_digest = candidate_policy_digest(policy)
    candidate_system = candidate_system_identity(policy)
    suite_digest = _digest("1")
    tree_digest = _digest("2")
    manifest_digest = _digest("3")
    dispatch_digest = _digest("4")
    jobs = [
        {
            "job_id": character * 32,
            "request_digest": _digest(character),
            "suite_digest": suite_digest,
            "case_id": "case",
            "run_id": 1,
            "system": system,
            "tree_digest": tree_digest,
            "private_manifest_digest": manifest_digest,
        }
        for character, system in zip(
            ("a", "b"),
            policy["required_comparators"],
            strict=True,
        )
    ]
    dispatch = {
        "schema": "aragorn/benchmark-private-dispatch/v2",
        "suite_digest": suite_digest,
        "candidate_system": candidate_system,
        "candidate_policy_digest": policy_digest,
        "jobs": jobs,
    }
    components = []
    for character, job in zip(("5", "6"), jobs, strict=True):
        envelope = {
            "schema": "aragorn/benchmark-authenticated-worker-evidence/v1",
            "suite_digest": suite_digest,
            "case_id": "case",
            "tree_digest": tree_digest,
            "run_id": 1,
            "system": job["system"],
            "verdict": "ALLOW",
            "reason_codes": [],
            "private_manifest_digest": manifest_digest,
            "dispatch_digest": dispatch_digest,
            "acceptance_receipt_digest": _digest("7"),
            "issuance_digest": _digest("8"),
        }
        components.append(
            {
                "evidence_kind": "authenticated_worker",
                "evidence_digest": _digest(character),
                "envelope": envelope,
                "dispatch_digest": dispatch_digest,
                "dispatch": dispatch,
                "policy_digest": policy_digest,
                "job": job,
            }
        )
    graph = {
        "schema": "aragorn/source-artifact-graph/v1",
        "profile": "phase0-literal-source-refs/v1",
        "assurance": "evaluation_only_literal_reference_profile",
        "source_assurance": "local_manifest_reverified",
        "root_manifest_digest": manifest_digest,
        "tree_digest": tree_digest,
        "nodes": [],
        "edges": [],
        "closure": {
            "scope": "source_reference_graph",
            "profile": "phase0-literal-source-refs/v1",
            "status": "complete",
            "unresolved": [],
        },
    }
    candidate_envelope = {
        "schema": "aragorn/benchmark-candidate-evidence/v1",
        "suite_digest": suite_digest,
        "case_id": "case",
        "tree_digest": tree_digest,
        "run_id": 1,
        "system": candidate_system,
        "verdict": "ALLOW",
        "reason_codes": [],
        "private_manifest_digest": manifest_digest,
        "source_graph_digest": _digest("9"),
        "dispatch_digest": dispatch_digest,
        "policy_digest": policy_digest,
        "component_evidence_digests": sorted(
            item["evidence_digest"] for item in components
        ),
    }
    return [
        *components,
        {
            "evidence_kind": "candidate",
            "evidence_digest": _digest("c"),
            "envelope": candidate_envelope,
            "dispatch_digest": dispatch_digest,
            "dispatch": dispatch,
            "policy_digest": policy_digest,
            "policy": policy,
            "candidate_system": candidate_system,
            "source_graph": graph,
        },
    ]


class BenchmarkCandidateEvidenceTests(unittest.TestCase):
    def test_exact_cell_closure_and_component_tampering(self) -> None:
        bindings = _bindings()
        _verify_candidate_batch_bindings(
            bindings,
            expected_count=3,
            suite_digest=_digest("1"),
        )

        changed = deepcopy(bindings)
        changed[2]["envelope"]["component_evidence_digests"][0] = _digest("d")
        with self.assertRaisesRegex(BenchmarkError, "exact comparator evidence"):
            _verify_candidate_batch_bindings(
                changed,
                expected_count=3,
                suite_digest=_digest("1"),
            )

    def test_cas_records_are_not_an_authentication_root(self) -> None:
        bindings = _bindings()
        component = bindings[0]
        outcome = {
            "evidence_digest": component["evidence_digest"],
            **{
                field: component["envelope"][field]
                for field in (
                    "suite_digest",
                    "case_id",
                    "tree_digest",
                    "run_id",
                    "system",
                    "verdict",
                    "reason_codes",
                )
            },
        }
        issuance = {"verifier_challenge": "f" * 64}
        receipt = {
            "verifier_challenge": "f" * 64,
            "result_digest": _digest("e"),
        }
        request = {
            "job_id": component["job"]["job_id"],
            "verifier_challenge": "f" * 64,
            "subject": {
                "manifest_digest": benchmark._digest_json({}),
                "tree_digest": outcome["tree_digest"],
            },
            "portable_policy_digest": outcome["system"]["config_digest"],
            "system": {
                field: outcome["system"][field]
                for field in ("name", "version", "implementation_digest")
            },
        }
        with (
            mock.patch.object(
                benchmark,
                "_verify_composed_evidence_common",
                return_value=component["envelope"]["private_manifest_digest"],
            ),
            mock.patch.object(
                benchmark,
                "_load_candidate_dispatch",
                return_value=(
                    component["dispatch_digest"],
                    component["dispatch"],
                ),
            ),
            mock.patch.object(
                benchmark,
                "_read_canonical_document",
                side_effect=(request, issuance, receipt),
            ),
            mock.patch.object(benchmark, "validate_worker_request_v2"),
            mock.patch.object(
                benchmark,
                "canonical_request_digest_v2",
                return_value=component["job"]["request_digest"],
            ),
            mock.patch.object(benchmark, "sanitize_subject_manifest", return_value={}),
        ):
            with self.assertRaisesRegex(BenchmarkError, "protected acceptance ledger"):
                benchmark._verify_authenticated_worker_evidence(
                    object(),
                    outcome,
                    expected_manifest={},
                    label="outcome",
                    envelope=component["envelope"],
                    acceptance_ledger=None,
                )

            with (
                mock.patch.object(
                    benchmark,
                    "_read_canonical_document",
                    side_effect=(request, issuance, receipt),
                ),
                mock.patch.object(
                    authenticated_handoff,
                    "load_verified_worker_output_acceptance",
                    return_value={
                        "issuance": {"verifier_challenge": "0" * 64},
                        "receipt": receipt,
                    },
                ),
                self.assertRaisesRegex(BenchmarkError, "not a member"),
            ):
                benchmark._verify_authenticated_worker_evidence(
                    object(),
                    outcome,
                    expected_manifest={},
                    label="outcome",
                    envelope=component["envelope"],
                    acceptance_ledger=Path("/trusted-ledger"),
                )


if __name__ == "__main__":
    unittest.main()
