"""Single-use offline B95 local Markdown closure; no policy, installation or model authority."""
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
from unittest import TestCase

from aragorn import admission_artifact_graph as graph
from aragorn.cas import CAS


ROOT = Path(__file__).resolve().parents[1]
SUPPORT = Path.home() / "Library/Application Support"
ORIGINAL = SUPPORT / "Aragorn-B95-Offline/candidate-cas"
OUT = SUPPORT / "Aragorn-B97-Offline"
MANIFEST = "sha256:e6de9001bdd41e7908d0b9097798d1ab8ae13037c4ad1a7dbceb4cea985ad77f"
VERIFIER = "sha256:05c70d81f1fac7c32ef455397079f9b73d80dfe4dc24d7427ce587f21001af85"


class PublicPilotAdmissionClosure(TestCase):
    def test_retain_and_replay_original_markdown_closure_once(self):
        # Check inputs and ownership before creating even the successor directory.
        for directory in (SUPPORT, ORIGINAL.parent, ORIGINAL):
            self.assertEqual(directory.resolve(strict=True), directory)
            self.assertTrue(directory.is_dir())
            self.assertEqual(directory.stat().st_uid, os.geteuid())
            self.assertFalse(directory.stat().st_mode & 0o022)
        self.assertFalse(os.path.lexists(OUT), "existing or partial B97 attempt; do not adopt or retry")
        module = ROOT / "src/aragorn/admission_artifact_graph.py"
        self.assertEqual(Path(graph.__file__).resolve(strict=True), module)
        self.assertEqual("sha256:" + sha256(module.read_bytes()).hexdigest(), VERIFIER)
        review = json.loads((ROOT / "benchmark/pi-core-pilot-v1/review.json").read_bytes())
        self.assertEqual(review["status"], "PROPOSED_INPUTS_ONLY")
        original = CAS(ORIGINAL, read_only=True)
        raw_manifest = original.read(MANIFEST, max_bytes=4096)
        skill = original.read(review["skill_digest"], max_bytes=47)
        self.assertEqual(len(skill), 47)
        files = [{"path": "SKILL.md", "digest": review["skill_digest"], "executable": False, "size": len(skill)}]
        # The B95 source identity belongs to the original checkout, not the current test worktree.
        source_path = Path.home() / "Documents/Commits/aragorn/benchmark/pi-core-pilot-v1/candidate"
        self.assertEqual(json.loads(raw_manifest), {
            "schema": "aragorn/manifest/v1", "source": {"kind": "local", "path": str(source_path)},
            "files": files, "tree_digest": review["tree_digest"], "closure": {"scope": "source_tree", "status": "complete"},
        })

        OUT.mkdir(mode=0o700)  # Exclusive. A failure after this point leaves the partial store intact.
        destination = OUT / "admission-cas"
        successor = CAS(destination)
        for pin, raw in ((MANIFEST, raw_manifest), (review["skill_digest"], skill)):
            self.assertEqual(successor.put_expected(BytesIO(raw), expected_digest=pin, max_bytes=len(raw)), pin)
        graph_pin = graph.retain_admission_artifact_graph(successor, MANIFEST, verifier_implementation_digest=VERIFIER)
        result = graph.verify_admission_artifact_graph(CAS(destination, read_only=True), graph_pin,
                                                      expected_manifest_digest=MANIFEST, expected_verifier_digest=VERIFIER)
        self.assertEqual(result["schema"], "aragorn/admission-artifact-graph/v1")
        self.assertEqual(result["authority"], "CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY")
        self.assertEqual((result["root_manifest_digest"], result["tree_digest"]), (MANIFEST, review["tree_digest"]))
        self.assertEqual((result["artifacts"], result["edges"]), (files, []))
        self.assertEqual(result["profile"], "self-contained-local-markdown/v1")
        self.assertEqual(result["closure"], {
            "scope": "artifact_graph", "profile": result["profile"], "status": "complete", "unresolved": [],
        })
        print(json.dumps({"admission_artifact_graph_digest": graph_pin}, sort_keys=True))
