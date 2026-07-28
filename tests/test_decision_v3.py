from __future__ import annotations

from copy import deepcopy
from io import BytesIO
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

from aragorn.acquire import ingest_local
from aragorn.admission_artifact_graph import retain_admission_artifact_graph
from aragorn.analyze import run_analyzer
from aragorn.analyzer_receipt import retain_analyzer_run
from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.decision_receipt import (
    DecisionReceiptError,
    retain_decision_v3,
    verify_decision_v3,
)


VERIFIER_DIGEST = "sha256:" + "1" * 64


def _put(cas: CAS, document: object) -> str:
    raw = canonical_json(document)
    return cas.put(BytesIO(raw), max_bytes=len(raw))


class DecisionV3Tests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
