from __future__ import annotations

import copy
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn.acquire import inventory_local
from aragorn.behavior_capability_diff import derive_behavior_capability_diff
from aragorn.benchmark import (
    BenchmarkError,
    _digest_json,
    _validate_phase2_coverage_lock,
    _verify_phase2_gvisor_batch_bindings,
    _verify_phase2_gvisor_v4_evidence,
    evaluate,
    main,
)
from aragorn.cas import CAS

_EMPTY_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
ROOT = Path(__file__).parents[1]


class Phase2MetricsCheckpointTests(unittest.TestCase):
    def test_exact_attack_family_and_agreement_thresholds_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = self._harness(
                Path(temporary), benign=2, families=("family-a", "family-b")
            )
            self._verdict(outcomes, "attack-0", 5, "ALLOW")
            report = self._evaluate(suite, outcomes, root, state)

        self.assertTrue(report["decision"]["metrics_passed"])
        self.assertEqual(
            report["schema"], "aragorn/benchmark-phase2-metrics-checkpoint/v1"
        )
        self.assertEqual(
            report["assurance"],
            "declared_unfrozen_held_out_five_run_metrics_only",
        )
        self.assertFalse(report["phase2_exit_eligible"])
        self.assertEqual(
            report["missing_phase2_exit_requirements"],
            [
                "ATTRIBUTED_DETONATION_EVIDENCE_REQUIRED",
                "CAPTURE_COMPLETENESS_REQUIRED",
                "FROZEN_COVERAGE_AND_CANDIDATE_LOCK_REQUIRED",
                "QUALIFIED_ISOLATED_BACKEND_REQUIRED",
                "VARIED_SCENARIO_MATRIX_REQUIRED",
            ],
        )
        self.assertEqual(
            report["observed"]["adversarial_flag"],
            {"numerator": 9, "denominator": 10},
        )
        self.assertEqual(
            report["observed"]["families"][0]["adversarial_flag"],
            {"numerator": 4, "denominator": 5},
        )
        self.assertEqual(
            report["observed"]["verdict_agreement"],
            {"numerator": 19, "denominator": 20},
        )

    def test_exact_benign_intervention_threshold_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = self._harness(
                Path(temporary), benign=4, families=("family-a",)
            )
            self._verdict(outcomes, "benign-0", 5, "REVIEW")
            report = self._evaluate(suite, outcomes, root, state)

        self.assertTrue(report["decision"]["metrics_passed"])
        self.assertEqual(
            report["observed"]["benign_intervention"],
            {"numerator": 1, "denominator": 20},
        )

    def test_threshold_and_error_failures_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            suite, outcomes, root, state = self._harness(
                base, benign=2, families=("family-a", "family-b")
            )
            weak = copy.deepcopy(outcomes)
            self._verdict(weak, "attack-0", 4, "ALLOW")
            self._verdict(weak, "attack-0", 5, "ALLOW")
            weak_report = self._evaluate(suite, weak, root, state)
            self.assertEqual(
                weak_report["decision"]["reason_codes"],
                [
                    "ADVERSARIAL_FLAG_RATE_BELOW_90_PERCENT",
                    "ATTACK_FAMILY_FLAG_RATE_BELOW_80_PERCENT",
                    "VERDICT_AGREEMENT_BELOW_95_PERCENT",
                ],
            )

            unstable = copy.deepcopy(outcomes)
            self._verdict(unstable, "attack-0", 5, "ALLOW")
            self._verdict(unstable, "attack-1", 5, "DENY")
            unstable_report = self._evaluate(suite, unstable, root, state)
            self.assertEqual(
                unstable_report["decision"]["reason_codes"],
                ["VERDICT_AGREEMENT_BELOW_95_PERCENT"],
            )

        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = self._harness(
                Path(temporary), benign=4, families=("family-a",)
            )
            burden = copy.deepcopy(outcomes)
            self._verdict(burden, "benign-0", 4, "REVIEW")
            self._verdict(burden, "benign-0", 5, "REVIEW")
            burden_report = self._evaluate(suite, burden, root, state)
            self.assertIn(
                "BENIGN_INTERVENTION_RATE_ABOVE_5_PERCENT",
                burden_report["decision"]["reason_codes"],
            )

            errored = copy.deepcopy(outcomes)
            self._verdict(errored, "benign-0", 5, "ERROR")
            error_report = self._evaluate(suite, errored, root, state)
            self.assertEqual(
                error_report["decision"]["reason_codes"],
                ["ERROR_OUTCOMES_PRESENT", "VERDICT_AGREEMENT_NOT_EVALUABLE"],
            )
            self.assertFalse(error_report["decision"]["evaluable"])
            self.assertIsNone(error_report["observed"]["verdict_agreement"])

    def test_checkpoint_contract_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            suite, outcomes, root, state = self._harness(
                base, benign=1, families=("family-a",)
            )
            no_held_out = copy.deepcopy(suite)
            for case in no_held_out["cases"]:
                case["split"] = "development"
            self._rebind(no_held_out, outcomes)
            report = self._evaluate(no_held_out, outcomes, root, state)
            self.assertEqual(report["decision"]["reason_codes"], ["NO_HELD_OUT_SPLIT"])
            self.assertFalse(report["decision"]["metrics_passed"])

            for purpose, runs, message in (
                ("contract_smoke", 5, "requires evidence_smoke"),
                ("evidence_smoke", 4, "requires exactly five runs"),
            ):
                with self.subTest(purpose=purpose, runs=runs):
                    changed = copy.deepcopy(suite)
                    changed["purpose"] = purpose
                    changed["runs_per_case"] = runs
                    with self.assertRaisesRegex(BenchmarkError, message):
                        self._evaluate(changed, (), root, state)

            no_candidate = copy.deepcopy(suite)
            no_candidate["systems"][0]["name"] = "other"
            no_candidate_outcomes = self._outcomes(no_candidate)
            with self.assertRaisesRegex(BenchmarkError, "exactly one Aragorn"):
                self._evaluate(no_candidate, no_candidate_outcomes, root, state)

            two_candidates = copy.deepcopy(suite)
            second = copy.deepcopy(two_candidates["systems"][0])
            second["implementation_digest"] = "sha256:" + "2" * 64
            two_candidates["systems"].append(second)
            with self.assertRaisesRegex(BenchmarkError, "exactly one Aragorn"):
                self._evaluate(
                    two_candidates,
                    self._outcomes(two_candidates),
                    root,
                    state,
                )

    def test_cli_returns_metric_pass_and_failure_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = self._harness(
                Path(temporary), benign=2, families=("family-a", "family-b")
            )
            suite_path = root / "suite.json"
            outcomes_path = root / "outcomes.jsonl"
            suite_path.write_text(json.dumps(suite), encoding="utf-8")
            outcomes_path.write_text(
                "".join(json.dumps(outcome) + "\n" for outcome in outcomes),
                encoding="utf-8",
            )
            argv = (
                str(suite_path),
                str(outcomes_path),
                "--state",
                str(state),
                "--phase2-metrics-checkpoint",
            )
            with (
                patch("aragorn.benchmark._verify_evidence", return_value=None),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(main(argv), 0)

            self._verdict(outcomes, "attack-0", 4, "ALLOW")
            self._verdict(outcomes, "attack-0", 5, "ALLOW")
            outcomes_path.write_text(
                "".join(json.dumps(outcome) + "\n" for outcome in outcomes),
                encoding="utf-8",
            )
            with (
                patch("aragorn.benchmark._verify_evidence", return_value=None),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(main(argv), 2)

    def test_cli_requires_phase2_lock_inputs_as_a_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = self._harness(
                Path(temporary), benign=2, families=("family-a", "family-b")
            )
            suite_path = root / "suite.json"
            outcomes_path = root / "outcomes.jsonl"
            lock_path = root / "coverage-lock.json"
            suite_path.write_text(json.dumps(suite), encoding="utf-8")
            outcomes_path.write_text(
                "".join(json.dumps(outcome) + "\n" for outcome in outcomes),
                encoding="utf-8",
            )
            lock_path.write_text("{}", encoding="ascii")
            base = (
                str(suite_path),
                str(outcomes_path),
                "--state",
                str(state),
                "--phase2-metrics-checkpoint",
            )
            variants = (
                (*base, "--phase2-coverage-lock", str(lock_path)),
                (
                    *base,
                    "--expected-phase2-coverage-lock-digest",
                    _EMPTY_DIGEST,
                ),
                (
                    *base[:-1],
                    "--phase2-coverage-lock",
                    str(lock_path),
                    "--expected-phase2-coverage-lock-digest",
                    _EMPTY_DIGEST,
                ),
            )
            for argv in variants:
                with (
                    self.subTest(argv=argv),
                    redirect_stderr(StringIO()),
                    redirect_stdout(StringIO()),
                ):
                    self.assertEqual(main(argv), 4)

    @classmethod
    def _harness(
        cls,
        base: Path,
        *,
        benign: int,
        families: tuple[str, ...],
    ) -> tuple[dict[str, object], list[dict[str, object]], Path, Path]:
        root = base / "suite"
        root.mkdir()
        state = base / "state"
        CAS(state)
        system = {
            "name": "aragorn",
            "version": "1",
            "implementation_digest": "sha256:" + "1" * 64,
            "config_digest": _EMPTY_DIGEST,
        }
        cases = [
            cls._case(root, f"benign-{index}", "benign", "benign")
            for index in range(benign)
        ]
        cases.extend(
            cls._case(root, f"attack-{index}", "adversarial", family)
            for index, family in enumerate(families)
        )
        suite = {
            "schema": "aragorn/benchmark-suite/v1",
            "id": "phase2-test",
            "purpose": "evidence_smoke",
            "runs_per_case": 5,
            "systems": [system],
            "cases": cases,
        }
        return suite, cls._outcomes(suite), root, state

    @staticmethod
    def _case(
        root: Path, case_id: str, case_class: str, family: str
    ) -> dict[str, object]:
        fixture = root / case_id
        fixture.mkdir()
        (fixture / "SKILL.md").write_text(case_id + "\n", encoding="utf-8")
        return {
            "schema": "aragorn/benchmark-case/v1",
            "id": case_id,
            "class": case_class,
            "family": family,
            "lineage": case_id,
            "split": "held_out",
            "path": case_id,
            "tree_digest": inventory_local(fixture)["tree_digest"],
            "inert": True,
            "source": {
                "kind": "synthetic",
                "reference": "unit-test",
                "license": "CC0-1.0",
            },
        }

    @classmethod
    def _outcomes(cls, suite: dict[str, object]) -> list[dict[str, object]]:
        digest = cls._suite_digest(suite)
        return [
            {
                "schema": "aragorn/benchmark-outcome/v1",
                "suite_digest": digest,
                "case_id": case["id"],
                "tree_digest": case["tree_digest"],
                "run_id": run_id,
                "system": copy.deepcopy(system),
                "evidence_digest": _digest_json(
                    {"case": case["id"], "run": run_id, "system": system}
                ),
                "verdict": "ALLOW" if case["class"] == "benign" else "REVIEW",
                "reason_codes": []
                if case["class"] == "benign"
                else ["SYNTHETIC_MARKER"],
            }
            for system in suite["systems"]
            for case in suite["cases"]
            for run_id in range(1, suite["runs_per_case"] + 1)
        ]

    @staticmethod
    def _suite_digest(suite: dict[str, object]) -> str:
        return _digest_json(
            {
                **suite,
                "systems": sorted(
                    suite["systems"],
                    key=lambda system: tuple(system.values()),
                ),
                "cases": sorted(suite["cases"], key=lambda case: case["id"]),
            }
        )

    @classmethod
    def _rebind(
        cls, suite: dict[str, object], outcomes: list[dict[str, object]]
    ) -> None:
        digest = cls._suite_digest(suite)
        for outcome in outcomes:
            outcome["suite_digest"] = digest

    @staticmethod
    def _verdict(
        outcomes: list[dict[str, object]], case_id: str, run_id: int, verdict: str
    ) -> None:
        outcome = next(
            item
            for item in outcomes
            if item["case_id"] == case_id and item["run_id"] == run_id
        )
        outcome["verdict"] = verdict
        outcome["reason_codes"] = [] if verdict == "ALLOW" else [f"SYNTHETIC_{verdict}"]

    @staticmethod
    def _evaluate(
        suite: dict[str, object],
        outcomes: object,
        root: Path,
        state: Path,
    ) -> dict[str, object]:
        with patch("aragorn.benchmark._verify_evidence", return_value=None):
            return evaluate(
                suite,
                outcomes,
                root,
                evidence_state=state,
                phase2_metrics_checkpoint=True,
            )


class Phase2LockedCheckpointTests(unittest.TestCase):
    _FAMILIES = (
        "agent-propagation",
        "credential-exfiltration",
        "destructive-action",
        "persistence",
        "prompt-obfuscation",
        "remote-code-bootstrap",
        "tool-poisoning",
    )

    def test_locked_checkpoint_routes_exact_coverage_and_emits_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state, lock_path, lock_digest = self._locked_harness(
                Path(temporary)
            )
            with (
                patch(
                    "aragorn.benchmark._verify_phase2_gvisor_v4_evidence",
                    side_effect=self._fake_phase2_binding,
                ) as locked_verifier,
                patch("aragorn.benchmark._verify_evidence") as generic_verifier,
            ):
                report = evaluate(
                    suite,
                    outcomes,
                    root,
                    evidence_state=state,
                    phase2_metrics_checkpoint=True,
                    phase2_coverage_lock=lock_path,
                    expected_phase2_coverage_lock_digest=lock_digest,
                )

        self.assertEqual(locked_verifier.call_count, 100)
        generic_verifier.assert_not_called()
        self.assertEqual(
            report["schema"], "aragorn/benchmark-phase2-metrics-checkpoint/v2"
        )
        self.assertEqual(
            report["assurance"],
            "operator_asserted_pre_outcome_locked_attributed_gvisor_v4_five_run_metrics_only",
        )
        self.assertEqual(report["coverage_lock_digest"], lock_digest)
        self.assertFalse(report["phase2_exit_eligible"])
        self.assertEqual(
            report["missing_phase2_exit_requirements"],
            [
                "CAPTURE_COMPLETENESS_REQUIRED",
                "QUALIFIED_ISOLATED_BACKEND_REQUIRED",
                "VARIED_SCENARIO_MATRIX_REQUIRED",
            ],
        )
        self.assertTrue(report["decision"]["metrics_passed"])

    def test_remote_v3_keeps_the_v3_checkpoint_deficits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state, lock_path, lock_digest = self._locked_harness(
                Path(temporary), remote=True
            )
            with patch(
                "aragorn.benchmark._verify_phase2_gvisor_v4_evidence",
                side_effect=self._fake_phase2_binding,
            ) as locked_verifier:
                report = evaluate(
                    suite,
                    outcomes,
                    root,
                    evidence_state=state,
                    phase2_metrics_checkpoint=True,
                    phase2_coverage_lock=lock_path,
                    expected_phase2_coverage_lock_digest=lock_digest,
                )

        self.assertEqual(locked_verifier.call_count, 100)
        self.assertTrue(
            all(
                call.kwargs["remote_trace"]
                == {
                    "receipt_schema": (
                        "aragorn/gvisor-remote-trace-capture-receipt/v2"
                    ),
                    "profile": "gvisor-remote-default-pod-init-seqpacket/v1",
                }
                for call in locked_verifier.call_args_list
            )
        )
        self.assertEqual(
            report["schema"], "aragorn/benchmark-phase2-metrics-checkpoint/v3"
        )
        self.assertFalse(report["phase2_exit_eligible"])
        self.assertEqual(
            report["missing_phase2_exit_requirements"],
            ["CAPTURE_COMPLETENESS_REQUIRED", "QUALIFIED_ISOLATED_BACKEND_REQUIRED"],
        )

    def test_lock_digest_and_manifest_substitution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, _outcomes, root, _state, lock_path, lock_digest = (
                self._locked_harness(Path(temporary))
            )
            cases = {case["id"]: case for case in suite["cases"]}
            systems = {self._system_key(system): system for system in suite["systems"]}
            manifests = self._suite_manifests(suite, root)
            binding = _validate_phase2_coverage_lock(
                lock_path,
                expected_digest=lock_digest,
                suite_digest=Phase2MetricsCheckpointTests._suite_digest(suite),
                runs_per_case=5,
                cases=cases,
                systems=systems,
                manifests=manifests,
            )
            self.assertEqual(len(binding["cases"]), 20)

            with self.assertRaisesRegex(BenchmarkError, "caller-held expected digest"):
                _validate_phase2_coverage_lock(
                    lock_path,
                    expected_digest="sha256:" + "f" * 64,
                    suite_digest=Phase2MetricsCheckpointTests._suite_digest(suite),
                    runs_per_case=5,
                    cases=cases,
                    systems=systems,
                    manifests=manifests,
                )

            substituted = json.loads(lock_path.read_text(encoding="ascii"))
            substituted["cases"][0]["suite_manifest_digest"] = _EMPTY_DIGEST
            substituted_digest = self._write_document(lock_path, substituted)
            with self.assertRaisesRegex(BenchmarkError, "changed from the suite"):
                _validate_phase2_coverage_lock(
                    lock_path,
                    expected_digest=substituted_digest,
                    suite_digest=Phase2MetricsCheckpointTests._suite_digest(suite),
                    runs_per_case=5,
                    cases=cases,
                    systems=systems,
                    manifests=manifests,
                )

    def test_api_requires_lock_inputs_as_a_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root, state = Phase2MetricsCheckpointTests._harness(
                Path(temporary), benign=2, families=("family-a", "family-b")
            )
            lock_path = Path(temporary) / "unused-lock.json"
            lock_path.write_text("{}", encoding="ascii")
            variants = (
                {
                    "phase2_coverage_lock": lock_path,
                },
                {
                    "expected_phase2_coverage_lock_digest": _EMPTY_DIGEST,
                },
            )
            for arguments in variants:
                with (
                    self.subTest(arguments=arguments),
                    self.assertRaisesRegex(BenchmarkError, "paired inputs"),
                ):
                    evaluate(
                        suite,
                        outcomes,
                        root,
                        evidence_state=state,
                        phase2_metrics_checkpoint=True,
                        **arguments,
                    )

    def test_dedicated_path_rejects_a_generic_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas, outcome, pins, receipt, lock_digest = self._one_cell_evidence(
                Path(temporary)
            )
            envelope = json.loads(cas.read(outcome["evidence_digest"]))
            envelope["schema"] = "aragorn/benchmark-evidence/v1"
            outcome["evidence_digest"] = self._put_document(cas, envelope)
            with self.assertRaisesRegex(BenchmarkError, "not dedicated"):
                _verify_phase2_gvisor_v4_evidence(
                    cas,
                    outcome,
                    coverage_lock_digest=lock_digest,
                    pins=pins,
                    label="outcomes[0]",
                )
            self.assertEqual(
                receipt["schema"], "aragorn/gvisor-acquired-artifact-receipt/v4"
            )

    def test_dedicated_path_rejects_unknown_attribution_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas, outcome, pins, receipt, lock_digest = self._one_cell_evidence(
                Path(temporary), unknown_scope=True
            )
            with (
                patch(
                    "aragorn.gvisor_runtime.verify_gvisor_acquired_artifact",
                    return_value=receipt,
                ) as verifier,
                self.assertRaisesRegex(BenchmarkError, "unknown attribution scope"),
            ):
                _verify_phase2_gvisor_v4_evidence(
                    cas,
                    outcome,
                    coverage_lock_digest=lock_digest,
                    pins=pins,
                    label="outcomes[0]",
                )
            verifier.assert_called_once_with(cas, outcome["_receipt_digest"], **pins)

    def test_verdict_is_rederived_from_the_verified_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas, outcome, pins, receipt, lock_digest = self._one_cell_evidence(
                Path(temporary), undeclared=True, claimed_verdict="ALLOW"
            )
            with (
                patch(
                    "aragorn.gvisor_runtime.verify_gvisor_acquired_artifact",
                    return_value=receipt,
                ),
                self.assertRaisesRegex(
                    BenchmarkError, "re-derive from the verified diff"
                ),
            ):
                _verify_phase2_gvisor_v4_evidence(
                    cas,
                    outcome,
                    coverage_lock_digest=lock_digest,
                    pins=pins,
                    label="outcomes[0]",
                )

    def test_remote_evidence_cross_binds_workload_run_and_canary_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            (
                cas,
                outcome,
                pins,
                receipt,
                remote_receipt,
                remote_trace,
                canary_remote,
                lock_digest,
            ) = self._one_cell_remote_evidence(Path(temporary))
            with (
                patch(
                    "aragorn.gvisor_runtime.verify_gvisor_acquired_artifact",
                    return_value=receipt,
                ),
                patch(
                    "aragorn.gvisor_remote_trace_capture."
                    "verify_gvisor_remote_trace_capture",
                    return_value=remote_receipt,
                ) as remote_verifier,
            ):
                binding = _verify_phase2_gvisor_v4_evidence(
                    cas,
                    outcome,
                    coverage_lock_digest=lock_digest,
                    pins=pins,
                    label="outcomes[0]",
                    remote_trace=remote_trace,
                )

            self.assertEqual(
                binding["remote_trace_receipt_digest"],
                outcome["_remote_receipt_digest"],
            )
            self.assertEqual(
                binding["remote_trace_container_id"], remote_receipt["container_id"]
            )
            remote_verifier.assert_called_once_with(
                cas,
                outcome["_remote_receipt_digest"],
                expected_runtime_lock_digest=remote_receipt["runtime_lock_digest"],
                expected_session_config_digest=canary_remote["session_config_digest"],
                expected_monitor_implementation_digest=canary_remote[
                    "monitor_implementation_digest"
                ],
                expected_workload_receipt_digest=outcome["_receipt_digest"],
            )

    def test_remote_evidence_identity_drift_fails_closed(self) -> None:
        mutations = {
            "schema": "aragorn/gvisor-remote-trace-capture-receipt/v1",
            "profile": "changed/v1",
            "run_id": "2" * 32,
            "sandbox_id": "d" * 64,
            "container_id": "d" * 64,
            "runtime_lock_digest": _EMPTY_DIGEST,
            "workload_receipt_digest": _EMPTY_DIGEST,
        }
        for field, value in mutations.items():
            with tempfile.TemporaryDirectory() as temporary, self.subTest(field=field):
                (
                    cas,
                    outcome,
                    pins,
                    receipt,
                    remote_receipt,
                    remote_trace,
                    _canary_remote,
                    lock_digest,
                ) = self._one_cell_remote_evidence(Path(temporary))
                changed = copy.deepcopy(remote_receipt)
                changed[field] = value
                with (
                    patch(
                        "aragorn.gvisor_runtime.verify_gvisor_acquired_artifact",
                        return_value=receipt,
                    ),
                    patch(
                        "aragorn.gvisor_remote_trace_capture."
                        "verify_gvisor_remote_trace_capture",
                        return_value=changed,
                    ),
                    self.assertRaisesRegex(BenchmarkError, "remote trace binding"),
                ):
                    _verify_phase2_gvisor_v4_evidence(
                        cas,
                        outcome,
                        coverage_lock_digest=lock_digest,
                        pins=pins,
                        label="outcomes[0]",
                        remote_trace=remote_trace,
                    )

    def test_batch_requires_matrix_closure_and_unique_run_evidence(self) -> None:
        phase2_binding = {"cases": {"case-a": {}, "case-b": {}}}
        bindings = [
            self._fake_binding(case_id, run_id)
            for case_id in phase2_binding["cases"]
            for run_id in range(1, 6)
        ]
        _verify_phase2_gvisor_batch_bindings(
            bindings,
            phase2_binding=phase2_binding,
            runs_per_case=5,
        )
        with self.assertRaisesRegex(BenchmarkError, "does not close"):
            _verify_phase2_gvisor_batch_bindings(
                bindings[:-1],
                phase2_binding=phase2_binding,
                runs_per_case=5,
            )
        for field in (
            "evidence_digest",
            "gvisor_receipt_digest",
            "gvisor_run_id",
            "run_request_digest",
            "capability_diff_receipt_digest",
        ):
            repeated = copy.deepcopy(bindings)
            repeated[1][field] = repeated[0][field]
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(BenchmarkError, f"repeats {field}"),
            ):
                _verify_phase2_gvisor_batch_bindings(
                    repeated,
                    phase2_binding=phase2_binding,
                    runs_per_case=5,
                )

        remote_binding = {
            "cases": phase2_binding["cases"],
            "remote_trace": {
                "receipt_schema": "aragorn/gvisor-remote-trace-capture-receipt/v2",
                "profile": "gvisor-remote-default-pod-init-seqpacket/v1",
            },
        }
        remote_bindings = [
            self._fake_binding(case_id, run_id, remote=True)
            for case_id in remote_binding["cases"]
            for run_id in range(1, 6)
        ]
        _verify_phase2_gvisor_batch_bindings(
            remote_bindings,
            phase2_binding=remote_binding,
            runs_per_case=5,
        )
        for field in ("remote_trace_receipt_digest", "remote_trace_container_id"):
            repeated = copy.deepcopy(remote_bindings)
            repeated[1][field] = repeated[0][field]
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(BenchmarkError, f"repeats {field}"),
            ):
                _verify_phase2_gvisor_batch_bindings(
                    repeated,
                    phase2_binding=remote_binding,
                    runs_per_case=5,
                )

    def test_nonexecutable_shell_carrier_is_accepted_but_executable_is_not(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root = self._shell_suite(Path(temporary), executable=False)
            report = evaluate(suite, outcomes, root)
            self.assertEqual(report["schema"], "aragorn/benchmark-report/v1")
        with tempfile.TemporaryDirectory() as temporary:
            suite, outcomes, root = self._shell_suite(Path(temporary), executable=True)
            with self.assertRaisesRegex(BenchmarkError, "executable fixture files"):
                evaluate(suite, outcomes, root)

    @classmethod
    def _locked_harness(
        cls, base: Path, *, remote: bool = False
    ) -> tuple[dict, list[dict], Path, Path, Path, str]:
        root = base / "suite"
        root.mkdir()
        state = base / "state"
        CAS(state)
        system = {
            "name": "aragorn",
            "version": "1",
            "implementation_digest": "sha256:" + "1" * 64,
            "config_digest": _EMPTY_DIGEST,
        }
        cases = [
            cls._locked_case(root, f"benign-{index}", "benign", "benign")
            for index in range(4)
        ]
        for family_index, family in enumerate(cls._FAMILIES):
            count = 3 if family_index < 2 else 2
            cases.extend(
                cls._locked_case(
                    root,
                    f"attack-{family}-{index}",
                    "adversarial",
                    family,
                )
                for index in range(count)
            )
        suite = {
            "schema": "aragorn/benchmark-suite/v1",
            "id": "phase2-locked-test",
            "purpose": "evidence_smoke",
            "runs_per_case": 5,
            "systems": [system],
            "cases": cases,
        }
        outcomes = Phase2MetricsCheckpointTests._outcomes(suite)
        manifests = cls._suite_manifests(suite, root)
        lock = cls._coverage_lock(suite, manifests, remote=remote)
        lock_path = base / "phase2-coverage-lock.json"
        lock_digest = cls._write_document(lock_path, lock)
        return suite, outcomes, root, state, lock_path, lock_digest

    @staticmethod
    def _locked_case(
        root: Path, case_id: str, case_class: str, family: str
    ) -> dict[str, object]:
        fixture = root / case_id
        fixture.mkdir()
        (fixture / "SKILL.md").write_text(case_id + "\n", encoding="utf-8")
        (fixture / "run.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        return {
            "schema": "aragorn/benchmark-case/v1",
            "id": case_id,
            "class": case_class,
            "family": family,
            "lineage": case_id,
            "split": "held_out",
            "path": case_id,
            "tree_digest": inventory_local(fixture)["tree_digest"],
            "inert": True,
            "source": {
                "kind": "synthetic",
                "reference": "unit-test",
                "license": "CC0-1.0",
            },
        }

    @staticmethod
    def _suite_manifests(suite: dict, root: Path) -> dict[str, dict]:
        manifests = {}
        for case in suite["cases"]:
            manifest = inventory_local(root / case["path"])
            manifest["source"] = {
                "kind": "local",
                "path": "/aragorn/opaque-benchmark-fixture",
            }
            manifests[case["id"]] = manifest
        return manifests

    @classmethod
    def _coverage_lock(
        cls, suite: dict, manifests: dict[str, dict], *, remote: bool = False
    ) -> dict:
        gvisor_lock = "sha256:" + "a" * 64
        verifier = "sha256:" + "b" * 64
        cases = []
        for case in sorted(suite["cases"], key=lambda item: item["id"]):
            manifest = manifests[case["id"]]
            entrypoint = next(
                item for item in manifest["files"] if item["path"] == "run.sh"
            )
            cases.append(
                {
                    "case_id": case["id"],
                    "class": case["class"],
                    "family": case["family"],
                    "lineage": case["lineage"],
                    "tree_digest": case["tree_digest"],
                    "suite_manifest_digest": _digest_json(manifest),
                    "source_manifest_digest": _digest_json(
                        {"source-manifest": case["id"]}
                    ),
                    "quarantine_receipt_digest": _digest_json(
                        {"quarantine": case["id"]}
                    ),
                    "gateway_profile_digest": _digest_json({"gateway": case["id"]}),
                    "entrypoint_path": "run.sh",
                    "entrypoint_digest": entrypoint["digest"],
                    "declared_capabilities": ["file-read", "process-exec"],
                }
            )
        lock = {
            "schema": "aragorn/benchmark-phase2-coverage-lock/v1",
            "assurance": (
                "operator_asserted_pre_outcome_binding_not_independent_or_timestamped"
            ),
            "suite_digest": Phase2MetricsCheckpointTests._suite_digest(suite),
            "evaluation_split": "held_out",
            "runs_per_case": 5,
            "candidate_system": copy.deepcopy(suite["systems"][0]),
            "verdict_profile": "undeclared-observed-review/v1",
            "gvisor": {
                "receipt_schema": "aragorn/gvisor-acquired-artifact-receipt/v4",
                "normalization_profile": "successful-openat-execve-attributed/v1",
                "execution_profile": "bounded-single-script/v1",
                "lock_digest": gvisor_lock,
                "verifier_implementation_digest": verifier,
            },
            "cases": cases,
        }
        if remote:
            lock.update(
                {
                    "schema": "aragorn/benchmark-phase2-coverage-lock/v3",
                    "assurance": (
                        "operator_asserted_pre_outcome_scenario_remote_trace_"
                        "binding_not_independent_or_timestamped"
                    ),
                    "scenario_matrix": {
                        "profile": "two-scenario-path-surface/v1",
                        "environment_variable": "ARAGORN_SCENARIO",
                        "run_schedule": [
                            "primary",
                            "alternate",
                            "primary",
                            "alternate",
                            "primary",
                        ],
                    },
                }
            )
            lock["gvisor"].update(
                {
                    "receipt_schema": "aragorn/gvisor-acquired-artifact-receipt/v5",
                    "execution_profile": "bounded-single-script/v2",
                    "remote_trace_receipt_schema": (
                        "aragorn/gvisor-remote-trace-capture-receipt/v2"
                    ),
                    "remote_trace_profile": (
                        "gvisor-remote-default-pod-init-seqpacket/v1"
                    ),
                }
            )
        return lock

    @staticmethod
    def _fake_phase2_binding(_cas: CAS, outcome: dict, **kwargs: object) -> dict:
        return Phase2LockedCheckpointTests._fake_binding(
            outcome["case_id"],
            outcome["run_id"],
            outcome["evidence_digest"],
            remote=kwargs.get("remote_trace") is not None,
        )

    @staticmethod
    def _fake_binding(
        case_id: str,
        run_id: int,
        evidence_digest: str | None = None,
        *,
        remote: bool = False,
    ) -> dict:
        def digest(field: str) -> str:
            return _digest_json({"field": field, "case": case_id, "run": run_id})

        binding = {
            "case_id": case_id,
            "run_id": run_id,
            "evidence_digest": evidence_digest or digest("evidence"),
            "gvisor_receipt_digest": digest("receipt"),
            "gvisor_run_id": digest("gvisor-run").split(":", 1)[1][:32],
            "run_request_digest": digest("run-request"),
            "capability_diff_receipt_digest": digest("diff-receipt"),
            "capability_diff_digest": _EMPTY_DIGEST,
            "attribution_manifest_digest": _EMPTY_DIGEST,
        }
        if remote:
            binding.update(
                {
                    "remote_trace_receipt_digest": digest("remote-receipt"),
                    "remote_trace_container_id": digest("container").split(":", 1)[1],
                    "scenario_id": ("primary" if run_id in {1, 3, 5} else "alternate"),
                }
            )
        return binding

    @classmethod
    def _one_cell_evidence(
        cls,
        base: Path,
        *,
        unknown_scope: bool = False,
        undeclared: bool = False,
        claimed_verdict: str | None = None,
    ) -> tuple[CAS, dict, dict, dict, str]:
        cas = CAS(base / "cas")
        system = {
            "name": "aragorn",
            "version": "1",
            "implementation_digest": "sha256:" + "1" * 64,
            "config_digest": _EMPTY_DIGEST,
        }
        tree_digest = _digest_json({"tree": "case-a"})
        lock_digest = _digest_json({"coverage-lock": "one"})
        pins = {
            "expected_quarantine_receipt_digest": _digest_json(
                {"quarantine": "case-a"}
            ),
            "expected_manifest_digest": _digest_json({"manifest": "case-a"}),
            "expected_tree_digest": tree_digest,
            "expected_gateway_profile_digest": _digest_json({"gateway": "case-a"}),
            "expected_entrypoint_digest": _digest_json({"entrypoint": "case-a"}),
            "expected_lock_digest": _digest_json({"gvisor-lock": "one"}),
            "expected_verifier_implementation_digest": _digest_json(
                {"verifier": "one"}
            ),
            "expected_normalization_profile": (
                "successful-openat-execve-attributed/v1"
            ),
            "expected_execution_profile": "bounded-single-script/v1",
            "expected_entrypoint_path": "run.sh",
            "expected_declared_capabilities": ["file-read", "process-exec"],
        }
        observed = ["file-read", "process-exec"]
        if undeclared:
            observed.append("file-write")
        capability_diff = derive_behavior_capability_diff(
            subject_digest=tree_digest,
            declared_capabilities=pins["expected_declared_capabilities"],
            observed_capabilities=observed,
        )
        capability_diff_digest = cls._put_document(cas, capability_diff)
        run_request_digest = _digest_json({"run-request": "one"})
        diff_receipt = {
            "schema": "aragorn/detonation-capability-diff-receipt/v1",
            "authority": (
                "SELECTED_OBSERVATION_SET_DIFF_ONLY_NOT_EXECUTION_COMPLETENESS_"
                "ISOLATION_OR_ADMISSION_AUTHORITY"
            ),
            "subject_digest": tree_digest,
            "input_manifest_digest": pins["expected_manifest_digest"],
            "input_tree_digest": tree_digest,
            "run_request_digest": run_request_digest,
            "normalizer_implementation_digest": pins[
                "expected_verifier_implementation_digest"
            ],
            "declared_capabilities": pins["expected_declared_capabilities"],
            "observation_bindings": [],
            "capability_diff_digest": capability_diff_digest,
        }
        diff_receipt_digest = cls._put_document(cas, diff_receipt)
        events = [
            cls._attribution_event(0, "harness", "openat", "file-open-read"),
            cls._attribution_event(1, "harness", "openat", "file-open-read"),
            cls._attribution_event(2, "entrypoint", "execve", "process-exec"),
            cls._attribution_event(3, "subject", "openat", "file-open-read"),
        ]
        if unknown_scope:
            events[0]["scope"] = "unknown"
        attribution = {
            "schema": "aragorn/gvisor-artifact-actor-attribution-manifest/v1",
            "authority": (
                "ORDERED_ENTRYPOINT_EPOCH_CLASSIFICATION_ONLY_NOT_PROCESS_ANCESTRY_"
                "CAPTURE_COMPLETENESS_OR_BEHAVIOR_AUTHORITY"
            ),
            "normalization_profile": "successful-openat-execve-attributed/v1",
            "entrypoint": {
                "path": "run.sh",
                "container_path": "/aragorn-input/run.sh",
                "digest": pins["expected_entrypoint_digest"],
            },
            "boundary": {
                "tgid": 1,
                "tid": 1,
                "entered_record": 4,
                "exited_record": 5,
            },
            "events": events,
        }
        attribution_digest = cls._put_document(cas, attribution)
        receipt = {
            "schema": "aragorn/gvisor-acquired-artifact-receipt/v4",
            "run_id": "1" * 32,
            "normalization_profile": pins["expected_normalization_profile"],
            "execution_profile": pins["expected_execution_profile"],
            "subject_digest": tree_digest,
            "input_manifest_digest": pins["expected_manifest_digest"],
            "input_tree_digest": tree_digest,
            "quarantine_receipt_digest": pins["expected_quarantine_receipt_digest"],
            "gateway_profile_digest": pins["expected_gateway_profile_digest"],
            "lock_digest": pins["expected_lock_digest"],
            "implementation_digest": pins["expected_verifier_implementation_digest"],
            "entrypoint": {
                "path": pins["expected_entrypoint_path"],
                "digest": pins["expected_entrypoint_digest"],
                "executable": False,
            },
            "run_request_digest": run_request_digest,
            "capability_diff_receipt_digest": diff_receipt_digest,
            "attribution_manifest_digest": attribution_digest,
        }
        receipt_digest = cls._put_document(cas, receipt)
        expected_verdict = "REVIEW" if undeclared else "ALLOW"
        verdict = claimed_verdict or expected_verdict
        reasons = ["UNDECLARED_OBSERVED_CAPABILITY"] if verdict == "REVIEW" else []
        outcome = {
            "schema": "aragorn/benchmark-outcome/v1",
            "suite_digest": _digest_json({"suite": "one"}),
            "case_id": "case-a",
            "tree_digest": tree_digest,
            "run_id": 1,
            "system": system,
            "evidence_digest": "",
            "verdict": verdict,
            "reason_codes": reasons,
            "_receipt_digest": receipt_digest,
        }
        envelope = {
            "schema": "aragorn/benchmark-phase2-gvisor-v4-evidence/v1",
            "authority": (
                "LOCK_BOUND_ATTRIBUTED_GVISOR_V4_CATEGORY_DIFF_ONLY_NOT_PROCESS_"
                "ANCESTRY_SCRIPT_SAFETY_CAPTURE_COMPLETENESS_RUNTIME_ATTESTATION_"
                "ISOLATION_BACKEND_QUALIFICATION_ADMISSION_OR_PHASE2_EXIT_AUTHORITY"
            ),
            "coverage_lock_digest": lock_digest,
            "suite_digest": outcome["suite_digest"],
            "case_id": outcome["case_id"],
            "tree_digest": tree_digest,
            "run_id": 1,
            "system": system,
            "gvisor_receipt_digest": receipt_digest,
            "verdict": verdict,
            "reason_codes": reasons,
        }
        outcome["evidence_digest"] = cls._put_document(cas, envelope)
        return cas, outcome, pins, receipt, lock_digest

    @classmethod
    def _one_cell_remote_evidence(
        cls, base: Path
    ) -> tuple[CAS, dict, dict, dict, dict, dict, dict, str]:
        cas, outcome, pins, receipt, lock_digest = cls._one_cell_evidence(base)
        canary_raw = (
            ROOT / "benchmark" / "gvisor-detonation-canary-v2.lock.json"
        ).read_bytes()
        canary_lock = json.loads(canary_raw)
        canary_digest = cas.put(BytesIO(canary_raw), max_bytes=64 * 1024)
        pins.update(
            {
                "expected_lock_digest": canary_digest,
                "expected_execution_profile": "bounded-single-script/v2",
                "expected_scenario_id": "primary",
            }
        )
        container_id = "c" * 64
        run_request = {
            "schema": "aragorn/gvisor-acquired-artifact-run-request/v5",
            "run_id": receipt["run_id"],
            "container_id": container_id,
            "runtime_lock_digest": canary_lock["runtime_lock_digest"],
        }
        run_request_digest = cls._put_document(cas, run_request)
        diff_receipt = json.loads(cas.read(receipt["capability_diff_receipt_digest"]))
        diff_receipt["run_request_digest"] = run_request_digest
        receipt.update(
            {
                "schema": "aragorn/gvisor-acquired-artifact-receipt/v5",
                "scenario_id": "primary",
                "execution_profile": "bounded-single-script/v2",
                "lock_digest": canary_digest,
                "run_request_digest": run_request_digest,
                "capability_diff_receipt_digest": cls._put_document(cas, diff_receipt),
            }
        )
        workload_receipt_digest = cls._put_document(cas, receipt)
        remote_receipt = {
            "schema": "aragorn/gvisor-remote-trace-capture-receipt/v2",
            "profile": "gvisor-remote-default-pod-init-seqpacket/v1",
            "run_id": receipt["run_id"],
            "sandbox_id": container_id,
            "container_id": container_id,
            "runtime_lock_digest": canary_lock["runtime_lock_digest"],
            "workload_receipt_digest": workload_receipt_digest,
        }
        remote_receipt_digest = cls._put_document(cas, remote_receipt)
        envelope = json.loads(cas.read(outcome["evidence_digest"]))
        envelope.update(
            {
                "schema": "aragorn/benchmark-phase2-gvisor-v5-remote-evidence/v3",
                "authority": (
                    "LOCK_BOUND_TWO_SCENARIO_ATTRIBUTED_GVISOR_V5_CATEGORY_DIFF_"
                    "AND_GVISOR_REMOTE_TRACE_V2_RAW_WIRE_CLOSURE_ONLY_NOT_PROCESS_"
                    "ANCESTRY_SCRIPT_SAFETY_CAPTURE_COMPLETENESS_RUNTIME_"
                    "ATTESTATION_ISOLATION_BACKEND_QUALIFICATION_ADMISSION_OR_"
                    "PHASE2_EXIT_AUTHORITY"
                ),
                "scenario_id": "primary",
                "gvisor_receipt_digest": workload_receipt_digest,
                "remote_trace_receipt_digest": remote_receipt_digest,
            }
        )
        outcome["evidence_digest"] = cls._put_document(cas, envelope)
        outcome["_receipt_digest"] = workload_receipt_digest
        outcome["_remote_receipt_digest"] = remote_receipt_digest
        remote_trace = {
            "receipt_schema": "aragorn/gvisor-remote-trace-capture-receipt/v2",
            "profile": "gvisor-remote-default-pod-init-seqpacket/v1",
        }
        return (
            cas,
            outcome,
            pins,
            receipt,
            remote_receipt,
            remote_trace,
            canary_lock["remote_trace"],
            lock_digest,
        )

    @staticmethod
    def _attribution_event(
        sequence: int, scope: str, syscall: str, operation: str
    ) -> dict:
        return {
            "sequence": sequence,
            "scope": scope,
            "tgid": 1,
            "tid": 1,
            "process": "sh",
            "syscall": syscall,
            "entered_record": sequence * 2,
            "exited_record": sequence * 2 + 1,
            "result": "0",
            "operation": operation,
            "detail": f"unit-test:{sequence}",
        }

    @staticmethod
    def _put_document(cas: CAS, document: dict) -> str:
        raw = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return cas.put(BytesIO(raw), max_bytes=2 * 1024 * 1024)

    @staticmethod
    def _write_document(path: Path, document: dict) -> str:
        raw = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        path.write_bytes(raw)
        return _digest_json(document)

    @staticmethod
    def _system_key(system: dict) -> tuple[str, str, str, str]:
        return (
            system["name"],
            system["version"],
            system["implementation_digest"],
            system["config_digest"],
        )

    @classmethod
    def _shell_suite(
        cls, base: Path, *, executable: bool
    ) -> tuple[dict, list[dict], Path]:
        root = base / "suite"
        root.mkdir()
        cases = []
        for case_id, case_class, family in (
            ("benign", "benign", "benign"),
            ("attack", "adversarial", "family-a"),
        ):
            fixture = root / case_id
            fixture.mkdir()
            (fixture / "SKILL.md").write_text(case_id + "\n", encoding="utf-8")
            script = fixture / "run.sh"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            if executable and case_id == "attack":
                script.chmod(0o755)
            cases.append(
                {
                    "schema": "aragorn/benchmark-case/v1",
                    "id": case_id,
                    "class": case_class,
                    "family": family,
                    "lineage": case_id,
                    "split": "held_out",
                    "path": case_id,
                    "tree_digest": inventory_local(fixture)["tree_digest"],
                    "inert": True,
                    "source": {
                        "kind": "synthetic",
                        "reference": "unit-test",
                        "license": "CC0-1.0",
                    },
                }
            )
        system = {
            "name": "aragorn",
            "version": "1",
            "implementation_digest": "sha256:" + "1" * 64,
            "config_digest": _EMPTY_DIGEST,
        }
        suite = {
            "schema": "aragorn/benchmark-suite/v1",
            "id": "shell-carrier-test",
            "purpose": "contract_smoke",
            "runs_per_case": 1,
            "systems": [system],
            "cases": cases,
        }
        return suite, Phase2MetricsCheckpointTests._outcomes(suite), root


if __name__ == "__main__":
    unittest.main()
