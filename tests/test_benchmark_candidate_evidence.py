from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

import aragorn.benchmark_authenticated_handoff_v2 as authenticated_handoff
from aragorn import benchmark
from aragorn.analyze import Observation
from aragorn.benchmark import BenchmarkError, _verify_candidate_batch_bindings
from aragorn.phase0_candidate import (
    candidate_policy_digest,
    candidate_system_identity,
)

_ROOT = Path(__file__).parents[1]
_V2_IMPLEMENTATION_DIGEST = (
    "sha256:150bbcd3690737c7acc77e6bf0737240"
    "c631e07c3a86a27c90bd1928a2661dca"
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _bindings(
    policy_name: str = "phase0-candidate-policy-v2.json",
) -> list[dict]:
    policy = json.loads(
        (_ROOT / "benchmark" / policy_name).read_bytes()
    )
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
        "schema": "aragorn/benchmark-candidate-evidence/v2",
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
        "first_party_observation_digests": [],
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
            "first_party_observations": (),
        },
    ]


def _verify_candidate(
    candidate: dict,
    envelope: dict,
    *,
    first_party_observations: tuple[Observation, ...] = (),
) -> dict:
    envelope = deepcopy(envelope)
    envelope["source_graph_digest"] = benchmark._digest_json(
        candidate["source_graph"]
    )
    outcome = {
        "evidence_digest": candidate["evidence_digest"],
        **{
            field: envelope[field]
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
    observation_bytes = {
        benchmark._digest_bytes(observation.document_json.encode("ascii")): (
            observation.document_json.encode("ascii")
        )
        for observation in first_party_observations
    }
    cas = mock.Mock()
    cas.read.side_effect = lambda digest, **_kwargs: observation_bytes[digest]
    with (
        mock.patch.object(
            benchmark,
            "_verify_composed_evidence_common",
            return_value=envelope["private_manifest_digest"],
        ),
        mock.patch.object(
            benchmark,
            "_load_candidate_dispatch",
            return_value=(
                candidate["dispatch_digest"],
                candidate["dispatch"],
            ),
        ),
        mock.patch.object(
            benchmark,
            "_read_canonical_document",
            side_effect=(
                candidate["policy"],
                candidate["source_graph"],
            ),
        ),
        mock.patch.object(
            benchmark,
            "resolve_source_graph",
            return_value=candidate["source_graph"],
        ),
        mock.patch(
            "aragorn.phase0_candidate.detect_first_party_observations",
            return_value=first_party_observations,
        ),
    ):
        return benchmark._verify_candidate_evidence(
            cas,
            outcome,
            expected_manifest={},
            label="outcome",
            envelope=envelope,
        )


class BenchmarkCandidateEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        historical_identity = mock.patch(
            "aragorn.phase0_candidate.candidate_implementation_digest",
            return_value=_V2_IMPLEMENTATION_DIGEST,
        )
        historical_identity.start()
        self.addCleanup(historical_identity.stop)

    def _verify_candidate(
        self,
        envelope: dict,
    ) -> dict:
        candidate = _bindings()[2]
        return _verify_candidate(candidate, envelope)

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

    def test_v2_policy_rejects_downgraded_or_malformed_detector_evidence(
        self,
    ) -> None:
        envelope = deepcopy(_bindings()[2]["envelope"])
        downgraded = deepcopy(envelope)
        downgraded["schema"] = "aragorn/benchmark-candidate-evidence/v1"
        downgraded.pop("first_party_observation_digests")
        with self.assertRaisesRegex(BenchmarkError, "does not match candidate policy"):
            self._verify_candidate(downgraded)

        malformed = deepcopy(envelope)
        malformed["first_party_observation_digests"] = [{}]
        with self.assertRaisesRegex(BenchmarkError, "lowercase SHA-256 digest"):
            self._verify_candidate(malformed)

        oversized = deepcopy(envelope)
        oversized["first_party_observation_digests"] = [
            _digest(character) for character in "abcde"
        ]
        with self.assertRaisesRegex(BenchmarkError, "is invalid"):
            self._verify_candidate(oversized)


class BenchmarkCandidateEvidenceV3Tests(unittest.TestCase):
    def test_v3_policy_accepts_v2_evidence_and_rederives_composed_review(
        self,
    ) -> None:
        bindings = _bindings("phase0-candidate-policy-v5.json")
        candidate = bindings[2]
        observation = Observation(
            schema="aragorn/observation/v1",
            subject_digest=candidate["envelope"]["tree_digest"],
            reason_code="ARAGORN_PROMPT_OVERRIDE",
            severity="high",
            document_json="{}",
        )
        envelope = deepcopy(candidate["envelope"])
        envelope["verdict"] = "REVIEW"
        envelope["reason_codes"] = ["ARAGORN_PROMPT_OVERRIDE"]
        envelope["first_party_observation_digests"] = [
            benchmark._digest_bytes(observation.document_json.encode("ascii"))
        ]
        bindings[2] = _verify_candidate(
            candidate,
            envelope,
            first_party_observations=(observation,),
        )

        _verify_candidate_batch_bindings(
            bindings,
            expected_count=3,
            suite_digest=_digest("1"),
        )


if __name__ == "__main__":
    unittest.main()
