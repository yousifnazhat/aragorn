from __future__ import annotations

import json
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.phase0_candidate import (
    CandidateError,
    build_candidate_policy,
    candidate_implementation_digest,
    candidate_policy_digest,
    candidate_system_identity,
    compose_candidate_decision,
)

_DIGEST = "sha256:" + "0" * 64
_ROOT = Path(__file__).parents[1]


def _policy() -> dict:
    policy = json.loads(
        (_ROOT / "benchmark" / "phase0-candidate-policy.json").read_bytes()
    )
    policy["candidate"]["implementation_digest"] = candidate_implementation_digest()
    return policy


def _source_graph(status: str = "complete") -> dict:
    return {
        "schema": "aragorn/source-artifact-graph/v1",
        "profile": "phase0-literal-source-refs/v1",
        "assurance": "evaluation_only_literal_reference_profile",
        "source_assurance": "local_manifest_reverified",
        "root_manifest_digest": _DIGEST,
        "tree_digest": _DIGEST,
        "nodes": [],
        "edges": [],
        "closure": {
            "scope": "source_reference_graph",
            "profile": "phase0-literal-source-refs/v1",
            "status": status,
            "unresolved": [] if status == "complete" else ["test"],
        },
    }


def _components(
    policy: dict,
    *,
    cisco: tuple[str, list[str]] = ("ALLOW", []),
    nvidia: tuple[str, list[str]] = ("ALLOW", []),
) -> list[dict]:
    decisions = {
        "cisco-skill-scanner": cisco,
        "skillspector": nvidia,
    }
    return [
        {
            "schema": "aragorn/benchmark-authenticated-worker-evidence/v1",
            "suite_digest": _DIGEST,
            "case_id": "case",
            "tree_digest": _DIGEST,
            "run_id": 1,
            "system": dict(system),
            "verdict": decisions[system["name"]][0],
            "reason_codes": decisions[system["name"]][1],
            "private_manifest_digest": _DIGEST,
            "dispatch_digest": _DIGEST,
            "acceptance_receipt_digest": _DIGEST,
            "issuance_digest": _DIGEST,
        }
        for system in policy["required_comparators"]
    ]


class Phase0CandidateTests(unittest.TestCase):
    def test_checked_policy_matches_the_exact_composer(self) -> None:
        policy = json.loads(
            (_ROOT / "benchmark" / "phase0-candidate-policy.json").read_bytes()
        )
        self.assertEqual(build_candidate_policy(policy), policy)
        self.assertEqual(
            candidate_system_identity(policy)["config_digest"],
            candidate_policy_digest(policy),
        )

    def test_frozen_decision_table(self) -> None:
        policy = _policy()
        cases = (
            ("allow", "complete", {}, ("ALLOW", [])),
            (
                "nvidia incomplete only",
                "complete",
                {"nvidia": ("REVIEW", ["NVIDIA_ANALYSIS_INCOMPLETE"])},
                ("ALLOW", []),
            ),
            (
                "cisco review",
                "complete",
                {"cisco": ("REVIEW", ["PROMPT_INJECTION"])},
                ("REVIEW", ["PROMPT_INJECTION"]),
            ),
            (
                "nvidia actionable review",
                "complete",
                {
                    "nvidia": (
                        "REVIEW",
                        ["NVIDIA_ANALYSIS_INCOMPLETE", "TOOL_POISONING"],
                    )
                },
                ("REVIEW", ["TOOL_POISONING"]),
            ),
            (
                "deny",
                "complete",
                {"cisco": ("DENY", ["MALICIOUS_INSTRUCTION"])},
                ("DENY", ["MALICIOUS_INSTRUCTION"]),
            ),
            (
                "comparator error",
                "complete",
                {"nvidia": ("ERROR", ["NVIDIA_CRASH"])},
                ("ERROR", ["COMPARATOR_ERROR_SKILLSPECTOR"]),
            ),
            (
                "source graph incomplete",
                "incomplete",
                {},
                ("ERROR", ["SOURCE_REFERENCE_GRAPH_INCOMPLETE"]),
            ),
        )
        for name, status, overrides, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(
                    compose_candidate_decision(
                        policy,
                        _source_graph(status),
                        _components(policy, **overrides),
                    ),
                    expected,
                )

    def test_policy_and_component_identity_drift_fail_closed(self) -> None:
        policy = _policy()
        self.assertEqual(
            candidate_system_identity(policy)["config_digest"],
            candidate_policy_digest(policy),
        )

        changed_implementation = deepcopy(policy)
        changed_implementation["candidate"]["implementation_digest"] = _DIGEST
        with self.assertRaisesRegex(
            CandidateError,
            "implementation digest does not match",
        ):
            build_candidate_policy(changed_implementation)

        changed_component = _components(policy)
        changed_component[0]["system"]["version"] = "2.0.13"
        with self.assertRaisesRegex(
            CandidateError,
            "frozen comparator identities",
        ):
            compose_candidate_decision(
                policy,
                _source_graph(),
                changed_component,
            )

        changed_comparator = deepcopy(policy)
        changed_comparator["required_comparators"][0]["version"] = "2.0.13"
        with self.assertRaisesRegex(
            CandidateError,
            "comparator identities are unsupported",
        ):
            build_candidate_policy(changed_comparator)


if __name__ == "__main__":
    unittest.main()
