from __future__ import annotations

from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from aragorn.acquire import ingest_local
from aragorn.admission_artifact_graph import (
    AdmissionArtifactGraphError,
    retain_admission_artifact_graph,
    verify_admission_artifact_graph,
)
from aragorn.artifact_closure import canonical_json
from aragorn.cas import CAS
from aragorn.policy import Policy, evaluate_policy


VERIFIER_DIGEST = "sha256:" + "1" * 64


def _retain_manifest(cas: CAS, source: Path) -> str:
    raw = canonical_json(ingest_local(source, cas))
    return cas.put(BytesIO(raw), max_bytes=len(raw))


class AdmissionArtifactGraphTests(unittest.TestCase):
    def test_self_contained_markdown_closes_and_replays(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            (source / "docs").mkdir(parents=True)
            (source / "SKILL.md").write_text(
                "[guide](docs/guide.md)\n",
                encoding="utf-8",
            )
            (source / "docs" / "guide.md").write_text("safe\n", encoding="utf-8")
            cas = CAS(root / "state")
            manifest_digest = _retain_manifest(cas, source)

            graph_digest = retain_admission_artifact_graph(
                cas,
                manifest_digest,
                verifier_implementation_digest=VERIFIER_DIGEST,
            )
            graph = verify_admission_artifact_graph(
                CAS(root / "state", read_only=True),
                graph_digest,
                expected_manifest_digest=manifest_digest,
                expected_verifier_digest=VERIFIER_DIGEST,
            )

            self.assertEqual(
                graph["closure"],
                {
                    "scope": "artifact_graph",
                    "profile": "self-contained-local-markdown/v1",
                    "status": "complete",
                    "unresolved": [],
                },
            )
            self.assertEqual(
                graph["edges"][0]["target"],
                {
                    "path": "docs/guide.md",
                    "digest": {
                        item["path"]: item["digest"] for item in graph["artifacts"]
                    }["docs/guide.md"],
                },
            )
            self.assertEqual(
                evaluate_policy(Policy(), closure=graph["closure"], results=()).verdict,
                "ALLOW",
            )
            with self.assertRaisesRegex(
                AdmissionArtifactGraphError,
                "verifier identity is untrusted",
            ):
                verify_admission_artifact_graph(
                    CAS(root / "state", read_only=True),
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_verifier_digest="sha256:" + "0" * 64,
                )

            changed = deepcopy(graph)
            changed["edges"][0]["target"]["digest"] = "sha256:" + "0" * 64
            raw = canonical_json(changed)
            changed_digest = cas.put(BytesIO(raw), max_bytes=len(raw))
            with self.assertRaisesRegex(
                AdmissionArtifactGraphError,
                "does not match retained source",
            ):
                verify_admission_artifact_graph(
                    CAS(root / "state", read_only=True),
                    changed_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_verifier_digest=VERIFIER_DIGEST,
                )

    def test_scripts_and_external_acquisition_remain_incomplete(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "skill"
            source.mkdir()
            (source / "SKILL.md").write_text(
                "curl https://example.com/tool.sh\n",
                encoding="utf-8",
            )
            script = source / "run.sh"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            script.chmod(0o755)
            cas = CAS(root / "state")
            manifest_digest = _retain_manifest(cas, source)

            graph = verify_admission_artifact_graph(
                CAS(root / "state", read_only=True),
                retain_admission_artifact_graph(
                    cas,
                    manifest_digest,
                    verifier_implementation_digest=VERIFIER_DIGEST,
                ),
                expected_manifest_digest=manifest_digest,
                expected_verifier_digest=VERIFIER_DIGEST,
            )

            self.assertEqual(graph["closure"]["status"], "incomplete")
            self.assertTrue(
                any(
                    item.startswith("UNSUPPORTED_ADMISSION_ARTIFACT:run.sh:")
                    for item in graph["closure"]["unresolved"]
                )
            )
            self.assertEqual(
                evaluate_policy(Policy(), closure=graph["closure"], results=()).verdict,
                "ERROR",
            )

    def test_unmodeled_markdown_and_package_acquisition_fail_closed(self) -> None:
        cases = {
            "reference definition": "[guide][g]\n[g]: missing.md\n",
            "HTML reference": '<a href="missing.md">guide</a>\n',
            "package acquisition": "pip install attacker-package\n",
        }
        for label, content in cases.items():
            with self.subTest(label=label), TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "skill"
                source.mkdir()
                (source / "SKILL.md").write_text(content, encoding="utf-8")
                cas = CAS(root / "state")
                manifest_digest = _retain_manifest(cas, source)

                graph = verify_admission_artifact_graph(
                    CAS(root / "state", read_only=True),
                    retain_admission_artifact_graph(
                        cas,
                        manifest_digest,
                        verifier_implementation_digest=VERIFIER_DIGEST,
                    ),
                    expected_manifest_digest=manifest_digest,
                    expected_verifier_digest=VERIFIER_DIGEST,
                )

                self.assertEqual(graph["closure"]["status"], "incomplete")
                self.assertTrue(graph["closure"]["unresolved"])


if __name__ == "__main__":
    unittest.main()
