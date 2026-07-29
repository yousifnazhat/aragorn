from __future__ import annotations

import json
import os
import sys
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import aragorn.decision_receipt as decision_receipt_module
from aragorn.acquire import ingest_local
from aragorn.admission_artifact_graph import retain_admission_artifact_graph
from aragorn.admission_decision import (
    AdmissionDecisionError,
    evaluate_admission,
    parse_policy,
)
from aragorn.analyze import run_analyzer
from aragorn.analyzer_receipt import retain_analyzer_run
from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.decision_receipt import (
    DecisionReceiptError,
    retain_decision_v3,
    verify_decision_v3,
)
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.protected_install_context import (
    ProtectedInstallContextError,
    verify_protected_install_context,
)

VERIFIER_DIGEST = "sha256:" + "1" * 64


def _put(cas: CAS, document: object) -> str:
    raw = canonical_json(document)
    return cas.put(BytesIO(raw), max_bytes=len(raw))


class DecisionV3Tests(unittest.TestCase):
    def test_analysis_input_pair_reaches_analyzer_replay(self) -> None:
        digest = "sha256:" + "2" * 64
        run_digest = "sha256:" + "3" * 64
        input_manifest_digest = "sha256:" + "4" * 64
        input_tree_digest = "sha256:" + "5" * 64
        graph = {
            "profile": "test-profile/v1",
            "tree_digest": digest,
            "artifacts": [],
            "closure": {"status": "complete"},
            "analysis_manifest_digest": input_manifest_digest,
            "analysis_tree_digest": input_tree_digest,
        }
        analyzer_result = mock.Mock()
        analyzer_result.name = "test-scanner"
        evaluated = mock.Mock(verdict="ALLOW", reason_codes=())

        with (
            TemporaryDirectory() as temporary,
            mock.patch.object(
                decision_receipt_module,
                "verify_admission_artifact_graph",
                return_value=graph,
            ) as verify_graph,
            mock.patch.object(
                decision_receipt_module,
                "_load_policy",
                return_value=({"id": "test", "version": 1}, object()),
            ),
            mock.patch.object(
                decision_receipt_module,
                "verify_analyzer_run",
                return_value=analyzer_result,
            ) as verify_run,
            mock.patch.object(
                decision_receipt_module,
                "summarize_analyzer_run",
                return_value={"run_receipt_digest": run_digest},
            ),
            mock.patch.object(
                decision_receipt_module,
                "evaluate_policy",
                return_value=evaluated,
            ),
            mock.patch.object(
                decision_receipt_module,
                "policy_artifact_graph_profiles",
                return_value={"test-profile/v1"},
            ),
        ):
            cas = CAS(Path(temporary) / "state")
            arguments = {
                "manifest_digest": digest,
                "artifact_graph_digest": digest,
                "policy_digest": digest,
                "analyzer_records": [{"run_receipt_digest": run_digest}],
                "expected_run_receipt_digests": [run_digest],
                "analyzer_verifier_digest": digest,
                "artifact_graph_verifier_digest": digest,
                "expected_quarantine_receipt_digest": None,
                "expected_gateway_profile_digest": None,
            }
            decision_receipt_module._derive_decision_v3(cas, **arguments)
            verify_run.assert_called_once_with(
                cas,
                run_digest,
                expected_subject_digest=digest,
                expected_verifier_digest=digest,
                expected_input_manifest_digest=input_manifest_digest,
                expected_input_tree_digest=input_tree_digest,
            )

            verify_graph.return_value = {
                key: value
                for key, value in graph.items()
                if key not in {"analysis_manifest_digest", "analysis_tree_digest"}
            }
            verify_run.reset_mock()
            decision_receipt_module._derive_decision_v3(cas, **arguments)
            verify_run.assert_called_once_with(
                cas,
                run_digest,
                expected_subject_digest=digest,
                expected_verifier_digest=digest,
            )

            for missing in ("analysis_manifest_digest", "analysis_tree_digest"):
                with self.subTest(missing=missing):
                    verify_graph.return_value = {
                        key: value for key, value in graph.items() if key != missing
                    }
                    verify_run.reset_mock()
                    with self.assertRaisesRegex(
                        DecisionReceiptError,
                        "analysis input digests must be supplied together",
                    ):
                        decision_receipt_module._derive_decision_v3(cas, **arguments)
                    verify_run.assert_not_called()

    def test_release_asset_pins_reach_decision_replay(self) -> None:
        digest = "sha256:" + "2" * 64
        release_digest = "sha256:" + "3" * 64
        decision = {
            "schema": "aragorn/decision/v3",
            "authority": "EVIDENCE_SUMMARY_ONLY_NOT_INSTALLER_AUTHORITY",
            "verdict": "ERROR",
            "manifest_digest": digest,
            "artifact_graph_digest": digest,
            "tree_digest": digest,
            "artifact_digests": [],
            "policy": {"id": "test", "version": 1, "digest": digest},
            "analyzers": [],
            "reason_codes": ["ARTIFACT_CLOSURE_INCOMPLETE"],
        }
        with TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            with mock.patch(
                "aragorn.decision_receipt._derive_decision_v3",
                return_value=decision,
            ) as derive:
                decision_digest = retain_decision_v3(
                    cas,
                    manifest_digest=digest,
                    artifact_graph_digest=digest,
                    policy_digest=digest,
                    analyzer_run_receipt_digests=[],
                    analyzer_verifier_digest=digest,
                    artifact_graph_verifier_digest=digest,
                    expected_release_asset_result_digests=[release_digest],
                )
                self.assertEqual(
                    derive.call_args.kwargs["expected_release_asset_result_digests"],
                    (release_digest,),
                )

            with mock.patch(
                "aragorn.decision_receipt._derive_decision_v3",
                return_value=decision,
            ) as derive:
                self.assertEqual(
                    verify_decision_v3(
                        CAS(Path(temporary) / "state", read_only=True),
                        decision_digest,
                        expected_manifest_digest=digest,
                        expected_artifact_graph_digest=digest,
                        expected_policy_digest=digest,
                        expected_analyzer_run_receipt_digests=[],
                        expected_analyzer_verifier_digest=digest,
                        expected_artifact_graph_verifier_digest=digest,
                        expected_release_asset_result_digests=[release_digest],
                    ),
                    decision,
                )
                self.assertEqual(
                    derive.call_args.kwargs["expected_release_asset_result_digests"],
                    (release_digest,),
                )

            with self.assertRaisesRegex(
                DecisionReceiptError,
                "release asset result digests must be unique",
            ):
                retain_decision_v3(
                    cas,
                    manifest_digest=digest,
                    artifact_graph_digest=digest,
                    policy_digest=digest,
                    analyzer_run_receipt_digests=[],
                    analyzer_verifier_digest=digest,
                    artifact_graph_verifier_digest=digest,
                    expected_release_asset_result_digests=[
                        release_digest,
                        release_digest,
                    ],
                )

    def test_policy_v2_requires_a_canonical_graph_profile_allowlist(self) -> None:
        policy = {
            "schema": "aragorn/policy/v2",
            "id": "test",
            "version": 1,
            "required_analyzers": ["test-scanner"],
            "hard_deny_reason_codes": [],
            "review_severities": ["critical", "high", "medium"],
            "allowed_artifact_graph_profiles": ["self-contained-local-markdown/v1"],
        }
        validated, _parsed = parse_policy(policy)
        self.assertEqual(validated, policy)

        vectors = json.loads(
            (
                Path(__file__).parents[1]
                / "benchmark"
                / "admission"
                / "openclaw-v2026.7.1"
                / "deterministic-authority-vectors-v1.json"
            ).read_bytes()
        )
        direct_request = deepcopy(vectors["vectors"][0]["request"])
        direct_request["policy"] = policy
        with self.assertRaisesRegex(
            AdmissionDecisionError,
            "graph-bound decision input",
        ):
            evaluate_admission(direct_request)

        for profiles in (
            ["z-profile/v1", "a-profile/v1"],
            ["a-profile/v1", "a-profile/v1"],
            ["not-a-versioned-profile"],
        ):
            with (
                self.subTest(profiles=profiles),
                self.assertRaisesRegex(
                    AdmissionDecisionError,
                    "artifact graph profile",
                ),
            ):
                parse_policy(
                    {
                        **policy,
                        "allowed_artifact_graph_profiles": profiles,
                    }
                )

    def test_graph_bound_decision_replays_and_rejects_drift(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text("# safe\n", encoding="utf-8")
            cas = CAS(root / "state")
            manifest = ingest_local(source, cas)
            manifest_digest = _put(cas, manifest)
            graph_digest = retain_admission_artifact_graph(
                cas,
                manifest_digest,
                verifier_implementation_digest=VERIFIER_DIGEST,
            )
            policy_digest = _put(
                cas,
                {
                    "schema": "aragorn/policy/v1",
                    "id": "test",
                    "version": 1,
                    "required_analyzers": ["test-scanner"],
                    "hard_deny_reason_codes": [],
                    "review_severities": ["critical", "high", "medium"],
                },
            )

            executable = Path(sys.executable).resolve(strict=True)
            with executable.open("rb") as stream:
                executable_digest = cas.put(
                    stream,
                    max_bytes=128 * 1024 * 1024,
                )
            script = "import json,sys;json.load(sys.stdin)"
            configuration = {
                "name": "test-scanner",
                "version": "1",
                "argv": [str(executable), "-c", script],
                "operator_argv0": str(executable),
                "executable_digest": executable_digest,
            }
            configuration_raw = canonical_json(configuration)
            config_digest = cas.put(
                BytesIO(configuration_raw),
                max_bytes=len(configuration_raw),
            )
            result = run_analyzer(
                (str(executable), "-c", script),
                workspace=source,
                name="test-scanner",
                version="1",
                config_digest=config_digest,
                executable_digest=executable_digest,
                subject_digest=manifest["tree_digest"],
                configuration_bytes=configuration_raw,
                timeout_seconds=2,
                output_limit_bytes=4096,
            )
            run_receipt_digest = retain_analyzer_run(
                cas,
                result,
                verifier_implementation_digest=VERIFIER_DIGEST,
            )
            decision_digest = retain_decision_v3(
                cas,
                manifest_digest=manifest_digest,
                artifact_graph_digest=graph_digest,
                policy_digest=policy_digest,
                analyzer_run_receipt_digests=[run_receipt_digest],
                analyzer_verifier_digest=VERIFIER_DIGEST,
                artifact_graph_verifier_digest=VERIFIER_DIGEST,
            )
            decision = verify_decision_v3(
                CAS(root / "state", read_only=True),
                decision_digest,
                expected_manifest_digest=manifest_digest,
                expected_artifact_graph_digest=graph_digest,
                expected_policy_digest=policy_digest,
                expected_analyzer_run_receipt_digests=[run_receipt_digest],
                expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                expected_artifact_graph_verifier_digest=VERIFIER_DIGEST,
            )

            self.assertEqual(decision["verdict"], "ALLOW")
            self.assertEqual(decision["artifact_graph_digest"], graph_digest)
            self.assertEqual(decision["reason_codes"], [])

            policy_v2 = {
                "schema": "aragorn/policy/v2",
                "id": "test",
                "version": 2,
                "required_analyzers": ["test-scanner"],
                "hard_deny_reason_codes": [],
                "review_severities": ["critical", "high", "medium"],
                "allowed_artifact_graph_profiles": ["self-contained-local-markdown/v1"],
            }
            policy_v2_digest = _put(cas, policy_v2)
            decision_v2_digest = retain_decision_v3(
                cas,
                manifest_digest=manifest_digest,
                artifact_graph_digest=graph_digest,
                policy_digest=policy_v2_digest,
                analyzer_run_receipt_digests=[run_receipt_digest],
                analyzer_verifier_digest=VERIFIER_DIGEST,
                artifact_graph_verifier_digest=VERIFIER_DIGEST,
            )
            decision_v2 = verify_decision_v3(
                CAS(root / "state", read_only=True),
                decision_v2_digest,
                expected_manifest_digest=manifest_digest,
                expected_artifact_graph_digest=graph_digest,
                expected_policy_digest=policy_v2_digest,
                expected_analyzer_run_receipt_digests=[run_receipt_digest],
                expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                expected_artifact_graph_verifier_digest=VERIFIER_DIGEST,
            )
            self.assertEqual(decision_v2["verdict"], "ALLOW")
            self.assertEqual(decision_v2["reason_codes"], [])

            disallowed_policy_digest = _put(
                cas,
                {
                    **policy_v2,
                    "allowed_artifact_graph_profiles": ["other-profile/v1"],
                },
            )
            disallowed_decision_digest = retain_decision_v3(
                cas,
                manifest_digest=manifest_digest,
                artifact_graph_digest=graph_digest,
                policy_digest=disallowed_policy_digest,
                analyzer_run_receipt_digests=[run_receipt_digest],
                analyzer_verifier_digest=VERIFIER_DIGEST,
                artifact_graph_verifier_digest=VERIFIER_DIGEST,
            )
            disallowed_decision = verify_decision_v3(
                CAS(root / "state", read_only=True),
                disallowed_decision_digest,
                expected_manifest_digest=manifest_digest,
                expected_artifact_graph_digest=graph_digest,
                expected_policy_digest=disallowed_policy_digest,
                expected_analyzer_run_receipt_digests=[run_receipt_digest],
                expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                expected_artifact_graph_verifier_digest=VERIFIER_DIGEST,
            )
            self.assertEqual(disallowed_decision["verdict"], "ERROR")
            self.assertEqual(
                disallowed_decision["reason_codes"],
                ["ARTIFACT_GRAPH_PROFILE_NOT_ALLOWED"],
            )

            protected_root = root / "protected"
            protected_root.mkdir(mode=0o700)
            root_fd = os.open(protected_root, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, root_fd)
            root_state = os.fstat(root_fd)
            runtime_digest = "sha256:" + "2" * 64
            context_id = "sha256:" + "3" * 64
            conformance_digest = "sha256:" + "4" * 64
            context = {
                "schema": "aragorn/protected-install-context/v1",
                "authority": "BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY",
                "context_id": context_id,
                "status": "active",
                "expires_at_unix": 101,
                "decision_digest": decision_digest,
                "manifest_digest": manifest_digest,
                "artifact_graph_digest": graph_digest,
                "policy_digest": policy_digest,
                "analyzer_run_receipt_digests": [run_receipt_digest],
                "analyzer_verifier_digest": VERIFIER_DIGEST,
                "artifact_graph_verifier_digest": VERIFIER_DIGEST,
                "target_runtime_digest": runtime_digest,
                "runtime_conformance_digest": conformance_digest,
                "destination": {
                    "root_device": root_state.st_dev,
                    "root_inode": root_state.st_ino,
                    "target_name": "admitted-skill",
                },
            }

            def verify_context(
                candidate: dict[str, object] = context,
                *,
                expected_digest: str | None = None,
                expected_target: str = "admitted-skill",
                expected_conformance: str = conformance_digest,
                measured_runtime: str = runtime_digest,
                revoked: tuple[str, ...] = (),
            ) -> object:
                return verify_protected_install_context(
                    CAS(root / "state", read_only=True),
                    candidate,
                    root_fd,
                    now_unix=100,
                    expected_context_digest=(
                        expected_digest or canonical_digest(candidate)
                    ),
                    expected_target_name=expected_target,
                    expected_runtime_conformance_digest=expected_conformance,
                    measured_target_runtime_digest=measured_runtime,
                    revoked_context_ids=revoked,
                )

            verified_context = verify_context()
            self.assertEqual(verified_context.manifest_digest, manifest_digest)
            self.assertEqual(verified_context.target_name, "admitted-skill")
            self.assertFalse((protected_root / "admitted-skill").exists())

            for mutation, message in (
                ({"status": "revoked"}, "revoked"),
                ({"expires_at_unix": 100}, "expired"),
                (
                    {
                        "target_runtime_digest": "sha256:" + "5" * 64,
                    },
                    "runtime identity changed",
                ),
                (
                    {
                        "destination": {
                            **context["destination"],
                            "root_inode": root_state.st_ino + 1,
                        }
                    },
                    "destination changed",
                ),
            ):
                changed_context = deepcopy(context)
                changed_context.update(mutation)
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex(
                        ProtectedInstallContextError,
                        message,
                    ),
                ):
                    verify_context(changed_context)

            with self.assertRaisesRegex(
                ProtectedInstallContextError,
                "context digest is untrusted",
            ):
                verify_context(
                    {**context, "context_id": "sha256:" + "6" * 64},
                    expected_digest=canonical_digest(context),
                )
            with self.assertRaisesRegex(
                ProtectedInstallContextError,
                "target changed",
            ):
                verify_context(expected_target="different-target")
            with self.assertRaisesRegex(
                ProtectedInstallContextError,
                "runtime conformance identity changed",
            ):
                verify_context(
                    expected_conformance="sha256:" + "6" * 64,
                )
            with self.assertRaisesRegex(
                ProtectedInstallContextError,
                "context is revoked",
            ):
                verify_context(revoked=(context_id,))

            with self.assertRaisesRegex(
                DecisionReceiptError,
                "receipt selection is untrusted",
            ):
                verify_decision_v3(
                    CAS(root / "state", read_only=True),
                    decision_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_artifact_graph_digest=graph_digest,
                    expected_policy_digest=policy_digest,
                    expected_analyzer_run_receipt_digests=[],
                    expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                    expected_artifact_graph_verifier_digest=VERIFIER_DIGEST,
                )

            other_graph = deepcopy(decision)
            other_graph["artifact_graph_digest"] = "sha256:" + "0" * 64
            with self.assertRaisesRegex(
                DecisionReceiptError,
                "another artifact graph",
            ):
                verify_decision_v3(
                    CAS(root / "state", read_only=True),
                    _put(cas, other_graph),
                    expected_manifest_digest=manifest_digest,
                    expected_artifact_graph_digest=graph_digest,
                    expected_policy_digest=policy_digest,
                    expected_analyzer_run_receipt_digests=[run_receipt_digest],
                    expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                    expected_artifact_graph_verifier_digest=VERIFIER_DIGEST,
                )

            changed = deepcopy(decision)
            changed["verdict"] = "ERROR"
            changed_digest = _put(cas, changed)
            with self.assertRaisesRegex(
                DecisionReceiptError,
                "does not match replayed evidence",
            ):
                verify_decision_v3(
                    CAS(root / "state", read_only=True),
                    changed_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_artifact_graph_digest=graph_digest,
                    expected_policy_digest=policy_digest,
                    expected_analyzer_run_receipt_digests=[run_receipt_digest],
                    expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                    expected_artifact_graph_verifier_digest=VERIFIER_DIGEST,
                )

            with self.assertRaisesRegex(
                DecisionReceiptError,
                "verifier identity is untrusted",
            ):
                verify_decision_v3(
                    CAS(root / "state", read_only=True),
                    decision_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_artifact_graph_digest=graph_digest,
                    expected_policy_digest=policy_digest,
                    expected_analyzer_run_receipt_digests=[run_receipt_digest],
                    expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                    expected_artifact_graph_verifier_digest="sha256:" + "0" * 64,
                )

            unsafe_source = root / "unsafe-skill"
            unsafe_source.mkdir()
            (unsafe_source / "SKILL.md").write_text(
                "pip install attacker-package\n",
                encoding="utf-8",
            )
            unsafe_manifest = ingest_local(unsafe_source, cas)
            unsafe_manifest_digest = _put(cas, unsafe_manifest)
            unsafe_graph_digest = retain_admission_artifact_graph(
                cas,
                unsafe_manifest_digest,
                verifier_implementation_digest=VERIFIER_DIGEST,
            )
            unsafe_decision_digest = retain_decision_v3(
                cas,
                manifest_digest=unsafe_manifest_digest,
                artifact_graph_digest=unsafe_graph_digest,
                policy_digest=policy_digest,
                analyzer_run_receipt_digests=[],
                analyzer_verifier_digest=VERIFIER_DIGEST,
                artifact_graph_verifier_digest=VERIFIER_DIGEST,
            )
            unsafe_decision = verify_decision_v3(
                CAS(root / "state", read_only=True),
                unsafe_decision_digest,
                expected_manifest_digest=unsafe_manifest_digest,
                expected_artifact_graph_digest=unsafe_graph_digest,
                expected_policy_digest=policy_digest,
                expected_analyzer_run_receipt_digests=[],
                expected_analyzer_verifier_digest=VERIFIER_DIGEST,
                expected_artifact_graph_verifier_digest=VERIFIER_DIGEST,
            )
            self.assertEqual(unsafe_decision["verdict"], "ERROR")
            self.assertIn(
                "ARTIFACT_CLOSURE_INCOMPLETE",
                unsafe_decision["reason_codes"],
            )
            unsafe_context = deepcopy(context)
            unsafe_context.update(
                {
                    "decision_digest": unsafe_decision_digest,
                    "manifest_digest": unsafe_manifest_digest,
                    "artifact_graph_digest": unsafe_graph_digest,
                    "analyzer_run_receipt_digests": [],
                }
            )
            with self.assertRaisesRegex(
                ProtectedInstallContextError,
                "decision is not ALLOW",
            ):
                verify_context(unsafe_context)


if __name__ == "__main__":
    unittest.main()
