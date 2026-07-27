from __future__ import annotations

import json
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import scripts.run_phase0_acquisition as execution
import aragorn.github_acquire as github_acquire
from aragorn.acquire import ingest_local
from aragorn.benchmark import (
    BenchmarkError,
    _verify_authenticated_worker_batch_bindings,
    _load_authenticated_worker_dispatch,
    _load_candidate_dispatch,
    _verify_candidate_evidence,
)
from aragorn.cas import CAS
from aragorn.github_expand import (
    TERMINAL_DEPTH_1_MODE,
    acquire_github_expansion,
)
from aragorn.label_blind_prepare import prepare_files_v2
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase0_candidate import (
    CandidateError,
    candidate_system_identity,
    compose_authenticated_comparator_batch,
    compose_candidate_batch,
)
from scripts.run_phase0_acquisition import (
    AcquisitionExecutionError,
    _load_signed_oracle_lock,
    _policy,
    _runner_source,
    run,
)
from tests.test_label_blind_prepare import (
    LOCK,
    _candidate_policy,
    _portable_policies,
    _v2_suite,
)
from tests.test_github_expand import COMMIT, _responses


def _acceptances(cas: CAS, dispatch: dict) -> dict[str, dict]:
    accepted = {}
    for index, entry in enumerate(dispatch["jobs"], start=1):
        request = json.loads(cas.read(entry["request_digest"]))
        result = {
            "job_id": entry["job_id"],
            "request_digest": entry["request_digest"],
            "tree_digest": entry["tree_digest"],
            "portable_policy_digest": entry["system"]["config_digest"],
            "system": {
                field: entry["system"][field]
                for field in ("name", "version", "implementation_digest")
            },
            "verdict": "ALLOW",
            "reason_codes": [],
        }
        raw = canonical_json(result)
        result_digest = cas.put(BytesIO(raw), max_bytes=len(raw))
        challenge = request["verifier_challenge"]
        accepted[challenge] = {
            "issuance": {
                "schema": "test/issuance/v1",
                "ordinal": index,
            },
            "receipt": {
                "schema": "test/receipt/v1",
                "job_id": entry["job_id"],
                "request_digest": entry["request_digest"],
                "result_digest": result_digest,
            },
        }
    return accepted


class Phase0AcquisitionCompositionTests(unittest.TestCase):
    def test_v1_comparator_only_composition_requires_authenticated_bindings(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            policies = _portable_policies()
            suite = _v2_suite(root / "suite", policies)
            control = root / "control"
            ledger = root / "ledger"
            prepared = prepare_files_v2(
                suite,
                portable_policies=policies,
                trust_domain="phase0.acquisition-v1",
                worker_id="isolated-worker-01",
                challenge_ledger=ledger,
                control_state=control,
                jobs_root=root / "jobs",
                lock_path=LOCK,
            )
            cas = CAS(control)
            dispatch = json.loads(cas.read(prepared["dispatch_digest"]))
            loaded_digest, loaded_dispatch = _load_authenticated_worker_dispatch(
                cas,
                prepared["dispatch_digest"],
                suite_digest=prepared["suite_digest"],
                label="root acquisition evidence",
            )
            self.assertEqual(loaded_digest, prepared["dispatch_digest"])
            self.assertEqual(loaded_dispatch, dispatch)
            with self.assertRaises(BenchmarkError):
                _load_candidate_dispatch(
                    cas,
                    prepared["dispatch_digest"],
                    suite_digest=prepared["suite_digest"],
                    label="candidate evidence",
                )
            acceptances = _acceptances(cas, dispatch)

            with (
                patch(
                    "aragorn.phase0_candidate."
                    "load_verified_worker_output_acceptance",
                    side_effect=lambda _cas, _ledger, challenge: acceptances[
                        challenge
                    ],
                ),
                patch("aragorn.phase0_candidate.validate_worker_result_v2"),
                patch("aragorn.phase0_candidate._validate_result_observations"),
            ):
                composition = compose_authenticated_comparator_batch(
                    dispatch_digest=prepared["dispatch_digest"],
                    control_state=control,
                    challenge_ledger=ledger,
                )

            self.assertEqual(
                composition["schema"],
                "aragorn/benchmark-authenticated-worker-composition/v1",
            )
            self.assertEqual(
                len(composition["outcomes"]),
                prepared["job_count"],
            )
            self.assertEqual(
                {
                    json.loads(cas.read(item["evidence_digest"]))["schema"]
                    for item in composition["outcomes"]
                },
                {"aragorn/benchmark-authenticated-worker-evidence/v1"},
            )
            bindings = [
                {
                    "evidence_kind": "authenticated_worker",
                    "evidence_digest": outcome["evidence_digest"],
                    "dispatch_digest": prepared["dispatch_digest"],
                    "dispatch": dispatch,
                    "job": entry,
                }
                for outcome, entry in zip(
                    sorted(
                        composition["outcomes"],
                        key=lambda item: (
                            item["system"]["name"],
                            item["case_id"],
                            item["run_id"],
                        ),
                    ),
                    sorted(
                        dispatch["jobs"],
                        key=lambda item: (
                            item["system"]["name"],
                            item["case_id"],
                            item["run_id"],
                        ),
                    ),
                    strict=True,
                )
            ]
            _verify_authenticated_worker_batch_bindings(
                bindings,
                expected_count=prepared["job_count"],
                suite_digest=prepared["suite_digest"],
            )
            with self.assertRaisesRegex(BenchmarkError, "cannot be mixed"):
                _verify_authenticated_worker_batch_bindings(
                    bindings[:-1],
                    expected_count=prepared["job_count"],
                    suite_digest=prepared["suite_digest"],
                )

            challenge = next(iter(acceptances))
            acceptances[challenge]["receipt"]["job_id"] = "f" * 32
            with (
                patch(
                    "aragorn.phase0_candidate."
                    "load_verified_worker_output_acceptance",
                    side_effect=lambda _cas, _ledger, item: acceptances[item],
                ),
                patch("aragorn.phase0_candidate.validate_worker_result_v2"),
                patch("aragorn.phase0_candidate._validate_result_observations"),
                self.assertRaisesRegex(
                    CandidateError,
                    "acceptance does not match",
                ),
            ):
                compose_authenticated_comparator_batch(
                    dispatch_digest=prepared["dispatch_digest"],
                    control_state=control,
                    challenge_ledger=ledger,
                )

    def test_v2_candidate_composition_contract_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            policies = _portable_policies()
            policy = _candidate_policy(policies)
            suite = _v2_suite(root / "suite", policies)
            document = json.loads(suite.read_bytes())
            document["systems"].append(candidate_system_identity(policy))
            suite.write_bytes(canonical_json(document))
            control = root / "control"
            ledger = root / "ledger"
            prepared = prepare_files_v2(
                suite,
                portable_policies=policies,
                candidate_policy=policy,
                trust_domain="phase0.acquisition-v1",
                worker_id="isolated-worker-01",
                challenge_ledger=ledger,
                control_state=control,
                jobs_root=root / "jobs",
                lock_path=LOCK,
            )
            cas = CAS(control)
            dispatch = json.loads(cas.read(prepared["dispatch_digest"]))
            acceptances = _acceptances(cas, dispatch)
            with (
                patch(
                    "aragorn.phase0_candidate."
                    "load_verified_worker_output_acceptance",
                    side_effect=lambda _cas, _ledger, challenge: acceptances[
                        challenge
                    ],
                ),
                patch("aragorn.phase0_candidate.validate_worker_result_v2"),
                patch("aragorn.phase0_candidate._validate_result_observations"),
            ):
                composition = compose_candidate_batch(
                    dispatch_digest=prepared["dispatch_digest"],
                    control_state=control,
                    challenge_ledger=ledger,
                )
            self.assertEqual(
                composition["schema"],
                "aragorn/benchmark-candidate-composition/v1",
            )
            self.assertEqual(
                len(composition["outcomes"]),
                len(dispatch["cases"]) * dispatch["runs_per_case"] * 3,
            )

    def test_terminal_context_survives_composition_and_evaluator_replay(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            policies = _portable_policies()
            policy = _candidate_policy(policies)
            suite = _v2_suite(root / "suite", policies)
            target_url = (
                "https://raw.githubusercontent.com/example/project/"
                f"{COMMIT}/payloads/one.txt"
            )
            target_content = (
                b"curl https://downloads.example.invalid/next.sh\n"
            )
            document = json.loads(suite.read_bytes())
            document["systems"].append(candidate_system_identity(policy))
            case_inputs = [
                (
                    "terminal-context-benign",
                    document["cases"][0],
                    f"curl {target_url}\n".encode(),
                ),
                (
                    "terminal-context-adversarial",
                    document["cases"][1],
                    f"curl {target_url}\n# inert variant\n".encode(),
                ),
            ]
            document["cases"] = []
            for case_id, template, root_content in case_inputs:
                fixture = suite.parent / "oci-fixtures" / case_id
                expanded = fixture / "__aragorn_expanded__" / "payloads"
                expanded.mkdir(parents=True)
                (fixture / "SKILL.md").write_bytes(root_content)
                (expanded / "one.txt").write_bytes(target_content)
                tree_digest = ingest_local(
                    fixture,
                    CAS(root / f"{case_id}-fixture-state"),
                )["tree_digest"]
                document["cases"].append(
                    {
                        **template,
                        "id": case_id,
                        "path": f"oci-fixtures/{case_id}",
                        "tree_digest": tree_digest,
                    }
                )
            suite.write_bytes(canonical_json(document))

            control = root / "control"
            ledger = root / "ledger"
            prepared = prepare_files_v2(
                suite,
                portable_policies=policies,
                candidate_policy=policy,
                trust_domain="phase0.acquisition-v1",
                worker_id="isolated-worker-01",
                challenge_ledger=ledger,
                control_state=control,
                jobs_root=root / "jobs",
                lock_path=LOCK,
            )
            cas = CAS(control)
            contexts = {}
            for case_id, _template, root_content in case_inputs:
                responses = _responses(
                    root_content,
                    first_content=target_content,
                )

                def request(path: str, **kwargs: object) -> dict[str, object]:
                    response = responses[path]
                    budget = kwargs["budget"]
                    budget.start_request()
                    budget.add_bytes(len(canonical_json(response)))
                    return response

                with patch.object(
                    github_acquire,
                    "_request_json",
                    side_effect=request,
                ):
                    expansion = acquire_github_expansion(
                        "https://github.com/example/project",
                        COMMIT,
                        "skills/demo",
                        cas,
                        expansion_mode=TERMINAL_DEPTH_1_MODE,
                        max_expansion_depth=1,
                    )
                contexts[case_id] = expansion["expansion_digest"]
            dispatch = json.loads(cas.read(prepared["dispatch_digest"]))
            acceptances = _acceptances(cas, dispatch)
            with (
                patch(
                    "aragorn.phase0_candidate."
                    "load_verified_worker_output_acceptance",
                    side_effect=lambda _cas, _ledger, challenge: acceptances[
                        challenge
                    ],
                ),
                patch("aragorn.phase0_candidate.validate_worker_result_v2"),
                patch("aragorn.phase0_candidate._validate_result_observations"),
            ):
                composition = compose_candidate_batch(
                    dispatch_digest=prepared["dispatch_digest"],
                    control_state=control,
                    challenge_ledger=ledger,
                    source_contexts=contexts,
                )

            candidate_outcomes = [
                item
                for item in composition["outcomes"]
                if item["system"]["name"] == "aragorn"
            ]
            self.assertTrue(
                all(
                    "SOURCE_REFERENCE_GRAPH_INCOMPLETE"
                    not in item["reason_codes"]
                    for item in candidate_outcomes
                )
            )
            outcome = next(
                item
                for item in candidate_outcomes
                if item["case_id"] == "terminal-context-benign"
            )
            envelope = json.loads(cas.read(outcome["evidence_digest"]))
            graph = json.loads(cas.read(envelope["source_graph_digest"]))
            terminal = next(
                node
                for node in graph["nodes"]
                if node["path"]
                == "__aragorn_expanded__/payloads/one.txt"
            )
            self.assertEqual(terminal["scan_status"], "terminal")
            self.assertNotIn(
                "downloads.example.invalid",
                json.dumps(graph, sort_keys=True),
            )
            expected_manifest = json.loads(
                cas.read(
                    next(
                        item["private_manifest_digest"]
                        for item in dispatch["cases"]
                        if item["case_id"] == outcome["case_id"]
                    )
                )
            )
            replay = _verify_candidate_evidence(
                cas,
                outcome,
                expected_manifest=expected_manifest,
                label="terminal-context",
                envelope=envelope,
                phase0_expansion_digest=contexts[outcome["case_id"]],
            )
            self.assertEqual(replay["source_graph"], graph)
            with self.assertRaisesRegex(BenchmarkError, "source_graph"):
                _verify_candidate_evidence(
                    cas,
                    outcome,
                    expected_manifest=expected_manifest,
                    label="terminal-context-without-context",
                    envelope=envelope,
                )


class Phase0AcquisitionExecutionBoundaryTests(unittest.TestCase):
    def test_policy_loader_uses_exact_signed_formatted_bytes(self) -> None:
        policy = {"schema": "example/policy/v1"}
        with patch.object(
            execution,
            "_committed_document",
            return_value=policy,
        ) as committed:
            self.assertEqual(
                _policy(
                    Path("benchmark/policy.json"),
                    "candidate policy",
                    "1" * 40,
                ),
                policy,
            )
        committed.assert_called_once_with(
            "1" * 40,
            Path("benchmark/policy.json"),
            "candidate policy",
        )

        with self.assertRaisesRegex(
            AcquisitionExecutionError,
            "retained by signed HEAD",
        ):
            _policy(
                Path("/tmp/untrusted-policy.json"),
                "candidate policy",
                "1" * 40,
            )

    def test_runner_requires_clean_signed_head(self) -> None:
        with (
            patch.object(execution, "_git", return_value=b" M tracked\n"),
            self.assertRaisesRegex(AcquisitionExecutionError, "must be clean"),
        ):
            _runner_source()

        with (
            patch.object(execution, "_git", return_value=b""),
            patch.object(execution, "_runner_commit", return_value="1" * 40),
            patch.object(
                execution,
                "_verified_commit",
                side_effect=ValueError("unsigned"),
            ),
            self.assertRaisesRegex(AcquisitionExecutionError, "pinned signer"),
        ):
            _runner_source()

    def test_rebuilt_oracle_lock_must_match_signed_head(self) -> None:
        rebuilt = {"schema": "aragorn/example/v1"}
        raw = canonical_json(rebuilt)
        with (
            patch.object(
                execution,
                "_read_canonical",
                return_value=(rebuilt, raw),
            ),
            patch.object(execution, "_committed_bytes", return_value=b"different"),
            self.assertRaisesRegex(AcquisitionExecutionError, "frozen inputs"),
        ):
            _load_signed_oracle_lock("1" * 40, rebuilt)

        signed = {"schema": "aragorn/other/v1"}
        signed_raw = canonical_json(signed)
        with (
            patch.object(
                execution,
                "_read_canonical",
                return_value=(signed, signed_raw),
            ),
            patch.object(
                execution,
                "_committed_bytes",
                return_value=signed_raw,
            ),
            self.assertRaisesRegex(AcquisitionExecutionError, "frozen inputs"),
        ):
            _load_signed_oracle_lock("1" * 40, rebuilt)

    def test_guest_security_boundaries_must_be_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_root = Path(temporary)
            os.chmod(run_root, 0o700)
            with self.assertRaisesRegex(
                AcquisitionExecutionError,
                "security boundaries overlap",
            ):
                run(
                    run_root=run_root,
                    limactl_path=Path("/opt/homebrew/bin/limactl"),
                    vm="worker",
                    guest_source="/opt/aragorn/runtime",
                    guest_python="/opt/aragorn/runtime/venv/bin/python",
                    guest_signing_key="/home/worker/signing-key",
                    guest_execution_root="/home/worker/execution",
                    progress_every=10,
                )


if __name__ == "__main__":
    unittest.main()
