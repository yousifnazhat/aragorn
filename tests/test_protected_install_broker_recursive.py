from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase0_candidate import candidate_implementation_digest

_ROOT = Path(__file__).resolve().parents[1]
_PRODUCER = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "protected-install-broker-recursive-v3.py"
)


def _load_producer():
    spec = importlib.util.spec_from_file_location(
        "aragorn_protected_install_broker_recursive_test",
        _PRODUCER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load recursive protected install broker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _source(commit_character: str) -> dict[str, str]:
    return {
        "schema": "aragorn/github-gateway-request/v1",
        "owner": "example",
        "repository": "skills",
        "commit": commit_character * 40,
        "skill_path": "demo",
    }


def _recursive(*, release_digests: list[str]) -> dict[str, object]:
    return {
        "root_manifest_digest": _digest("a"),
        "expansion_digest": _digest("b"),
        "expansion_proof_digest": _digest("c"),
        "release_asset_result_digests": release_digests,
    }


def _service_request(
    schema: str,
    recursive: dict[str, object],
    *,
    expected_recursive: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema": schema,
        "expires_at_unix": 200,
        "operation": "update",
        "expected_active": {
            "context_id": _digest("1"),
            "manifest_digest": _digest("2"),
            "source_request": _source("1"),
            "quarantine_receipt_digest": _digest("3"),
            "gateway_profile_digest": _digest("4"),
            "recursive": (
                recursive if expected_recursive is None else expected_recursive
            ),
        },
        "expected_manifest_diff_digest": _digest("5"),
        "target_runtime_digest": _digest("6"),
        "runtime_conformance_digest": _digest("7"),
        "manifest_digest": _digest("8"),
        "quarantine_receipt_digest": _digest("9"),
        "gateway_profile_digest": _digest("a"),
        "context_id": _digest("b"),
        "source_request": _source("2"),
        "recursive": recursive,
        "expected_producer_implementation_digest": _digest("c"),
        "expected_analyzer_implementation_digest": _digest("d"),
        "expected_analyzer_executable_digest": _digest("e"),
        "expected_analyzer_configuration_digest": _digest("f"),
        "expected_policy_digest": _digest("0"),
        "expected_analyzer_verifier_digest": _digest("1"),
        "expected_artifact_graph_verifier_digest": _digest("2"),
    }


def _live_args(producer, release_digests: list[str]) -> tuple[argparse.Namespace, dict]:
    executable = Path(sys.executable).resolve(strict=True)
    executable_digest = "sha256:" + hashlib.sha256(
        executable.read_bytes()
    ).hexdigest()
    analyzer_implementation_digest = candidate_implementation_digest()
    configuration = {
        "name": producer._GITHUB_SCANNER,
        "version": producer._GITHUB_ANALYZER_VERSION,
        "argv": [
            str(executable),
            "-B",
            "-c",
            producer._github_analyzer_script(analyzer_implementation_digest),
        ],
        "operator_argv0": str(executable),
        "executable_digest": executable_digest,
    }
    policy = {
        "schema": "aragorn/policy/v2",
        "id": "openclaw-live-github-broker-evidence",
        "version": 1,
        "required_analyzers": [producer._GITHUB_SCANNER],
        "hard_deny_reason_codes": [],
        "review_severities": ["critical", "high", "medium"],
        "allowed_artifact_graph_profiles": [
            "recursive-github-markdown/v1",
            "recursive-github-markdown/v2",
            "recursive-github-markdown/v3",
        ],
    }
    request = _source("2")
    return argparse.Namespace(
        recursive=_recursive(release_digests=release_digests),
        manifest_digest=_digest("8"),
        quarantine_receipt_digest=_digest("9"),
        gateway_profile_digest=_digest("a"),
        context_id=_digest("b"),
        expected_producer_implementation_digest=(
            "sha256:" + hashlib.sha256(_PRODUCER.read_bytes()).hexdigest()
        ),
        expected_analyzer_implementation_digest=analyzer_implementation_digest,
        expected_analyzer_executable_digest=executable_digest,
        expected_analyzer_configuration_digest=canonical_digest(configuration),
        expected_policy_digest=canonical_digest(policy),
        expected_analyzer_verifier_digest=_digest("e"),
        expected_artifact_graph_verifier_digest=_digest("f"),
        expected_owner=request["owner"],
        expected_repository=request["repository"],
        expected_commit=request["commit"],
        expected_skill_path=request["skill_path"],
        expected_broker_uid=os.geteuid(),
        revocation_file="/unused",
        operation="install",
        expected_active=None,
        expected_manifest_diff_digest=None,
        now_unix=100,
        expires_at_unix=200,
        target_runtime_digest=_digest("6"),
        runtime_conformance_digest=_digest("7"),
    ), {
        "request": request,
        "source_closure_digest": _digest("1"),
        "source_proof_digest": _digest("3"),
        "containment_profile": "test",
        "gateway": {},
        "protected_cas": {},
    }


class RecursiveProtectedInstallBrokerTests(unittest.TestCase):
    def test_service_request_v3_accepts_exact_recursive_state_and_rejects_types(
        self,
    ) -> None:
        producer = _load_producer()
        recursive = _recursive(release_digests=[_digest("d")])
        request = _service_request(
            "aragorn/protected-install-broker-request/v3",
            recursive,
        )
        with TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "request.json"
            path.write_bytes(canonical_json(request))
            path.chmod(0o400)
            loaded, authority = producer._load_service_request(
                str(path),
                os.geteuid(),
            )
            self.assertEqual(loaded, request)
            self.assertEqual(
                authority["request_schema"],
                "aragorn/protected-install-broker-request/v3",
            )

            request["recursive"] = _recursive(release_digests=[_digest("d"), 1])
            path.chmod(0o600)
            path.write_bytes(canonical_json(request))
            path.chmod(0o400)
            with self.assertRaisesRegex(
                producer.BrokerConformanceError,
                "release asset result digests are invalid",
            ):
                producer._load_service_request(str(path), os.geteuid())

    def test_service_request_v4_requires_nullable_pin_digest_and_accepts_v3_predecessor(
        self,
    ) -> None:
        producer = _load_producer()
        previous_recursive = _recursive(release_digests=[_digest("d")])
        current_recursive = {
            **_recursive(release_digests=[_digest("e")]),
            "release_pin_set_digest": None,
        }
        request = _service_request(
            "aragorn/protected-install-broker-request/v4",
            current_recursive,
            expected_recursive=previous_recursive,
        )
        with TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "request.json"
            path.write_bytes(canonical_json(request))
            path.chmod(0o400)
            loaded, authority = producer._load_service_request(
                str(path),
                os.geteuid(),
            )
            self.assertEqual(loaded, request)
            self.assertEqual(
                authority["request_schema"],
                "aragorn/protected-install-broker-request/v4",
            )

            request["recursive"] = {
                **current_recursive,
                "release_pin_set_digest": _digest("f"),
            }
            path.chmod(0o600)
            path.write_bytes(canonical_json(request))
            path.chmod(0o400)
            loaded, _authority = producer._load_service_request(
                str(path),
                os.geteuid(),
            )
            self.assertEqual(loaded, request)

            missing_digest = dict(current_recursive)
            missing_digest.pop("release_pin_set_digest")
            request["recursive"] = missing_digest
            path.chmod(0o600)
            path.write_bytes(canonical_json(request))
            path.chmod(0o400)
            with self.assertRaisesRegex(
                producer.BrokerConformanceError,
                "service recursive source is invalid",
            ):
                producer._load_service_request(str(path), os.geteuid())

            request["recursive"] = {
                **current_recursive,
                "release_pin_set_digest": "invalid",
            }
            path.chmod(0o600)
            path.write_bytes(canonical_json(request))
            path.chmod(0o400)
            with self.assertRaisesRegex(
                producer.BrokerConformanceError,
                "release pin set digest is invalid",
            ):
                producer._load_service_request(str(path), os.geteuid())

    def test_v4_update_verifies_predecessor_pin_set_before_diff(self) -> None:
        producer = _load_producer()
        pin_set_digest = _digest("0")
        previous_recursive = {
            **_recursive(release_digests=[_digest("d")]),
            "release_pin_set_digest": pin_set_digest,
        }
        previous_request = _source("1")
        expected_active = {
            "context_id": _digest("1"),
            "manifest_digest": _digest("2"),
            "source_request": previous_request,
            "quarantine_receipt_digest": _digest("3"),
            "gateway_profile_digest": _digest("4"),
            "recursive": previous_recursive,
        }
        args = SimpleNamespace(
            operation="update",
            expected_active=expected_active,
            expected_manifest_diff_digest=_digest("5"),
            manifest_digest=_digest("8"),
        )
        previous_receipt = {
            "request": previous_request,
            "source_proof_digest": _digest("6"),
            "source_closure_digest": _digest("7"),
        }
        order: list[str] = []
        with TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "current")
            previous_root = Path(temporary) / "previous"
            CAS(previous_root)
            previous_cas = CAS(previous_root, read_only=True)
            with (
                mock.patch.object(
                    producer,
                    "verify_github_quarantine_receipt",
                    return_value=previous_receipt,
                ),
                mock.patch.object(
                    producer,
                    "verify_retained_release_pin_set",
                    side_effect=lambda *_args, **_kwargs: (
                        order.append("pin-set") or {}
                    ),
                ) as verify_pin_set,
                mock.patch.object(
                    producer,
                    "diff_verified_manifests_between",
                    side_effect=lambda *_args, **_kwargs: (
                        order.append("manifest-diff") or {"status": "changed"}
                    ),
                ),
                mock.patch.object(
                    producer,
                    "_retain_document",
                    return_value=args.expected_manifest_diff_digest,
                ),
            ):
                producer._prepare_github_transition(
                    args,
                    cas,
                    previous_cas,
                )

        self.assertEqual(order, ["pin-set", "manifest-diff"])
        self.assertIs(verify_pin_set.call_args.args[0], previous_cas)
        self.assertEqual(verify_pin_set.call_args.args[1], pin_set_digest)
        self.assertEqual(
            verify_pin_set.call_args.kwargs["expected_recursive"],
            previous_recursive,
        )

    def test_recursive_v4_incomplete_replays_error_before_analyzer_or_publish(
        self,
    ) -> None:
        producer = _load_producer()
        release_digest = _digest("d")
        pin_set_digest = _digest("0")
        args, receipt = _live_args(producer, [release_digest])
        args.recursive["release_pin_set_digest"] = pin_set_digest
        order: list[str] = []
        graph = {
            "profile": "recursive-github-markdown/v2",
            "tree_digest": _digest("2"),
            "source_proof_digest": _digest("3"),
            "artifacts": [],
            "closure": {
                "scope": "artifact_graph",
                "profile": "recursive-github-markdown/v2",
                "status": "incomplete",
                "unresolved": ["GITHUB_RELEASE_ASSET_NOT_ANALYZED"],
            },
        }
        with TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            protected = Path(temporary) / "protected"
            protected.mkdir()
            root_state = protected.stat()
            with (
                mock.patch.object(
                    producer,
                    "_load_revocation_snapshot",
                    return_value=((), {}),
                ),
                mock.patch.object(
                    producer,
                    "verify_github_quarantine_receipt",
                    return_value=receipt,
                ),
                mock.patch.object(
                    producer,
                    "verify_retained_release_pin_set",
                    side_effect=lambda *_args, **_kwargs: (
                        order.append("pin-set") or {}
                    ),
                ) as verify_pin_set,
                mock.patch.object(
                    producer,
                    "_prepare_github_transition",
                    return_value=(
                        None,
                        {
                            "operation": "install",
                            "expected_active": None,
                            "manifest_diff": None,
                        },
                    ),
                ),
                mock.patch.object(
                    producer.recursive_graph_v4_module,
                    "retain_recursive_github_artifact_graph",
                    side_effect=lambda *_args, **_kwargs: (
                        order.append("artifact-graph") or _digest("4")
                    ),
                ) as retain_graph,
                mock.patch.object(
                    producer.recursive_graph_v6_module,
                    "release_assets_require_v6",
                    return_value=False,
                ),
                mock.patch.object(
                    producer,
                    "verify_admission_artifact_graph",
                    return_value=graph,
                ) as verify_graph,
                mock.patch.object(
                    producer,
                    "retain_decision_v3",
                    return_value=_digest("5"),
                ) as retain_decision,
                mock.patch.object(
                    producer,
                    "verify_decision_v3",
                    return_value={"verdict": "ERROR"},
                ) as verify_decision,
                mock.patch.object(producer, "run_analyzer") as analyzer,
                mock.patch.object(producer, "_publish") as publish,
            ):
                result = producer._run_github_live(
                    args,
                    cas=cas,
                    previous_cas=None,
                    protected_root=protected,
                    root_state=root_state,
                    analyzer_verifier_digest=_digest("e"),
                    graph_verifier_digest=_digest("f"),
                )

        self.assertEqual(result["slice_status"], "ERROR")
        self.assertEqual(result["decision"]["verdict"], "ERROR")
        self.assertEqual(result["analyzer"]["run_receipt_digests"], [])
        self.assertIn(
            "ARTIFACT_CLOSURE_LIMITED_TO_RECURSIVE_GITHUB_MARKDOWN_V2_"
            "WITH_UNANALYZED_RELEASE_ASSETS",
            result["limitations"],
        )
        analyzer.assert_not_called()
        publish.assert_not_called()
        self.assertEqual(order[:2], ["pin-set", "artifact-graph"])
        verified_cas = verify_pin_set.call_args.args[0]
        self.assertTrue(verified_cas.read_only)
        self.assertEqual(verified_cas.root, cas.root)
        self.assertEqual(verify_pin_set.call_args.args[1], pin_set_digest)
        self.assertEqual(
            verify_pin_set.call_args.kwargs,
            {
                "expected_request": receipt["request"],
                "expected_manifest_digest": args.manifest_digest,
                "expected_source_proof_digest": receipt[
                    "source_proof_digest"
                ],
                "expected_recursive": args.recursive,
            },
        )
        self.assertEqual(
            retain_graph.call_args.kwargs["release_asset_result_digests"],
            (release_digest,),
        )
        self.assertEqual(
            verify_graph.call_args.kwargs[
                "expected_release_asset_result_digests"
            ],
            (release_digest,),
        )
        self.assertEqual(
            retain_decision.call_args.kwargs[
                "expected_release_asset_result_digests"
            ],
            (release_digest,),
        )
        self.assertEqual(
            verify_decision.call_args.kwargs[
                "expected_release_asset_result_digests"
            ],
            (release_digest,),
        )

    def test_recursive_v3_complete_reaches_allow_and_publication(self) -> None:
        producer = _load_producer()
        args, receipt = _live_args(producer, [])
        graph = {
            "profile": "recursive-github-markdown/v1",
            "tree_digest": _digest("2"),
            "source_proof_digest": _digest("3"),
            "artifacts": [{"digest": _digest("4")}],
            "closure": {
                "scope": "artifact_graph",
                "profile": "recursive-github-markdown/v1",
                "status": "complete",
                "unresolved": [],
            },
        }
        manifest = {
            "tree_digest": graph["tree_digest"],
            "files": [{"path": "SKILL.md"}],
        }

        with TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            protected = Path(temporary) / "protected"
            protected.mkdir()
            root_state = protected.stat()

            def publish_result(*_args, **_kwargs):
                version_path = ".aragorn-versions/aragorn-admitted/v1"
                (protected / version_path).mkdir(parents=True)
                (protected / ".aragorn-install-claims").mkdir()
                (protected / producer._TARGET).symlink_to(version_path)
                return {
                    "version_path": version_path,
                    "tree_digest": graph["tree_digest"],
                }

            with (
                mock.patch.object(
                    producer,
                    "_load_revocation_snapshot",
                    return_value=((), {}),
                ),
                mock.patch.object(
                    producer,
                    "verify_github_quarantine_receipt",
                    return_value=receipt,
                ),
                mock.patch.object(
                    producer,
                    "_prepare_github_transition",
                    return_value=(
                        None,
                        {
                            "operation": "install",
                            "expected_active": None,
                            "manifest_diff": None,
                        },
                    ),
                ),
                mock.patch.object(
                    producer.recursive_graph_v3_module,
                    "retain_recursive_github_artifact_graph",
                    return_value=_digest("5"),
                ) as retain_v3,
                mock.patch.object(
                    producer.recursive_graph_v4_module,
                    "retain_recursive_github_artifact_graph",
                ) as retain_v4,
                mock.patch.object(
                    producer,
                    "verify_admission_artifact_graph",
                    return_value=graph,
                ),
                mock.patch.object(
                    producer,
                    "load_verified_retained_manifest",
                    return_value=manifest,
                ),
                mock.patch.object(producer, "_materialize_verified_manifest"),
                mock.patch.object(producer, "_freeze_materialized_source_tree"),
                mock.patch.object(
                    producer,
                    "verify_materialized_source_tree",
                    return_value=graph["tree_digest"],
                ),
                mock.patch.object(
                    producer,
                    "run_analyzer",
                    return_value=SimpleNamespace(ok=True, error_code=None),
                ),
                mock.patch.object(
                    producer,
                    "retain_analyzer_run",
                    return_value=_digest("6"),
                ),
                mock.patch.object(
                    producer,
                    "retain_decision_v3",
                    return_value=_digest("7"),
                ) as retain_decision,
                mock.patch.object(
                    producer,
                    "verify_decision_v3",
                    return_value={"verdict": "ALLOW"},
                ) as verify_decision,
                mock.patch.object(
                    producer,
                    "_publish",
                    side_effect=publish_result,
                ) as publish,
            ):
                result = producer._run_github_live(
                    args,
                    cas=cas,
                    previous_cas=None,
                    protected_root=protected,
                    root_state=root_state,
                    analyzer_verifier_digest=_digest("e"),
                    graph_verifier_digest=_digest("f"),
                )

        self.assertEqual(result["slice_status"], "PASS")
        self.assertEqual(result["decision"]["verdict"], "ALLOW")
        self.assertIn(
            "ARTIFACT_CLOSURE_LIMITED_TO_RECURSIVE_GITHUB_MARKDOWN_V1",
            result["limitations"],
        )
        retain_v3.assert_called_once()
        retain_v4.assert_not_called()
        publish.assert_called_once()
        self.assertEqual(
            publish.call_args.args[2]["schema"],
            "aragorn/protected-install-context/v2",
        )
        self.assertEqual(
            retain_decision.call_args.kwargs[
                "expected_release_asset_result_digests"
            ],
            (),
        )
        self.assertEqual(
            verify_decision.call_args.kwargs[
                "expected_release_asset_result_digests"
            ],
            (),
        )

    def test_recursive_v6_runtime_consumer_gap_fails_before_analyzer(
        self,
    ) -> None:
        producer = _load_producer()
        release_digest = _digest("d")
        args, receipt = _live_args(producer, [release_digest])
        install_tree_digest = _digest("2")
        analysis_manifest_digest = _digest("1")
        analysis_tree_digest = _digest("5")
        graph = {
            "profile": "recursive-github-markdown/v3",
            "tree_digest": install_tree_digest,
            "source_proof_digest": _digest("3"),
            "artifacts": [{"digest": _digest("4")}],
            "analysis_manifest_digest": analysis_manifest_digest,
            "analysis_tree_digest": analysis_tree_digest,
            "closure": {
                "scope": "artifact_graph",
                "profile": "recursive-github-markdown/v3",
                "status": "incomplete",
                "unresolved": [
                    "GITHUB_RELEASE_ASSET_RUNTIME_CONSUMER_UNPROVEN"
                ],
            },
        }
        with TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            protected = Path(temporary) / "protected"
            protected.mkdir()
            root_state = protected.stat()

            with (
                mock.patch.object(
                    producer,
                    "_load_revocation_snapshot",
                    return_value=((), {}),
                ),
                mock.patch.object(
                    producer,
                    "verify_github_quarantine_receipt",
                    return_value=receipt,
                ),
                mock.patch.object(
                    producer,
                    "_prepare_github_transition",
                    return_value=(
                        None,
                        {
                            "operation": "install",
                            "expected_active": None,
                            "manifest_diff": None,
                        },
                    ),
                ),
                mock.patch.object(
                    producer.recursive_graph_v6_module,
                    "retain_recursive_github_artifact_graph",
                    return_value=_digest("6"),
                ) as retain_v6,
                mock.patch.object(
                    producer.recursive_graph_v6_module,
                    "release_assets_require_v6",
                    return_value=True,
                ),
                mock.patch.object(
                    producer,
                    "verify_admission_artifact_graph",
                    return_value=graph,
                ),
                mock.patch.object(
                    producer,
                    "_materialize_verified_manifest",
                ) as materialize,
                mock.patch.object(producer, "run_analyzer") as analyzer,
                mock.patch.object(
                    producer,
                    "retain_decision_v3",
                    return_value=_digest("8"),
                ),
                mock.patch.object(
                    producer,
                    "verify_decision_v3",
                    return_value={"verdict": "ERROR"},
                ),
                mock.patch.object(
                    producer,
                    "_publish",
                ) as publish,
            ):
                result = producer._run_github_live(
                    args,
                    cas=cas,
                    previous_cas=None,
                    protected_root=protected,
                    root_state=root_state,
                    analyzer_verifier_digest=_digest("e"),
                    graph_verifier_digest=_digest("f"),
                )

        self.assertEqual(result["slice_status"], "ERROR")
        self.assertIn(
            "ARTIFACT_CLOSURE_LIMITED_TO_RECURSIVE_GITHUB_MARKDOWN_V3_"
            "WITH_SEPARATE_ANALYSIS_INPUT",
            result["limitations"],
        )
        retain_v6.assert_called_once()
        materialize.assert_not_called()
        analyzer.assert_not_called()
        publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
