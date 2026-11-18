"""Inert custody and packaging limits; no compiler, candidate or target execution."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from scripts import build_pi_core_worker_bundle as builder
from scripts import prepare_pi_core_restricted_runtime as stage


class RestrictedRuntimeChecks(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (self.root / stage.BASE).mkdir(parents=True, mode=0o700)

    def test_prior_reproduction_preserved_without_compiler_or_gate_access(self):
        copy = self.root / stage.COPY
        copy.mkdir()
        witness = copy / "entrypoint.js"
        witness.write_bytes(b"prior")
        with mock.patch.object(builder, "build") as emit, mock.patch.object(stage, "gate_input") as gate:
            with self.assertRaisesRegex(ValueError, "prior reproduction"):
                stage.reproduce(root=self.root)
        gate.assert_not_called()
        emit.assert_not_called()
        self.assertEqual(witness.read_bytes(), b"prior")
        self.assertFalse((self.root / stage.REVIEW / "outcome.json").exists())

    def test_rejected_original_retains_refusal_and_never_emits(self):
        original = self.root / stage.ORIGINAL
        original.mkdir(parents=True)
        for name in ("entrypoint.js", "meta.json", "receipt.json"):
            (original / name).write_bytes(b"substituted")
        with mock.patch.object(stage, "gate_input", return_value=(b"", {})), mock.patch.object(builder, "build") as emit:
            with self.assertRaisesRegex(ValueError, "bundle product differs"):
                stage.reproduce(root=self.root)
        emit.assert_not_called()
        self.assertEqual(json.loads((self.root / stage.REVIEW / "refusal.json").read_bytes())["phase"], "original")

    def test_existing_evidence_directory_blocks_attempt_even_without_emission(self):
        (self.root / stage.REVIEW).mkdir()
        with mock.patch.object(builder, "build") as emit, self.assertRaises(FileExistsError):
            stage.reproduce(root=self.root)
        emit.assert_not_called()

    def test_forged_local_pass_does_not_replace_reviewed_outcome_pin(self):
        checkpoint = self.root / stage.CHECKPOINT
        checkpoint.parent.mkdir(parents=True)
        checkpoint.write_text(json.dumps({"schema":"aragorn/pi-core-worker-reproduction-checkpoint/v1",
                                          "outcome_sha256":"0" * 64}))
        evidence = self.root / stage.REVIEW
        evidence.mkdir()
        (evidence / "outcome.json").write_bytes(b'{"status":"REPRODUCED_RESTRICTED_NOT_DEPLOYED"}\n')
        with self.assertRaisesRegex(ValueError, "unapproved reproduction outcome"):
            stage.reviewed_copy(self.root, {})

    def test_predecessor_checkpoint_substitution_is_not_a_node_pin(self):
        checkpoint = self.root / stage.V3_CHECKPOINT
        checkpoint.parent.mkdir(parents=True)
        checkpoint.write_bytes(b'{"receipt_local_path":"elsewhere"}')
        with self.assertRaisesRegex(ValueError, "unapproved v3 checkpoint"):
            stage.predecessor(self.root)

    def test_assembly_retains_blocker_without_dispatch_or_reproduction(self):
        with mock.patch.object(stage, "gate_input", side_effect=ValueError("gate pin differs")), \
                mock.patch.object(builder, "build") as emit:
            with self.assertRaisesRegex(ValueError, "gate pin differs"):
                stage.assemble(root=self.root)
        emit.assert_not_called()
        folder = self.root / stage.ASSEMBLY
        self.assertEqual({p.name for p in folder.iterdir()}, {"refusal.json"})
        with self.assertRaises(FileExistsError):
            stage.assemble(root=self.root)

    def test_linked_ancestor_or_hardlinked_evidence_refused(self):
        real = self.root / "real"
        real.mkdir()
        (real / "file").write_bytes(b"held")
        alias = self.root / "link"
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "linked input or ancestor"):
            stage.read(alias / "file")
        (self.root / "other").hardlink_to(real / "file")
        with self.assertRaisesRegex(ValueError, "multiply linked"):
            stage.read(real / "file")

    def test_exact_mode_bytes_and_directory_inventory_without_extra_runtime_members(self):
        deployment = self.root / "tiny"
        sources = {"node/bin/node":b"node", "observer/source-gate":b"gate",
                   "pi-core/entrypoint.js":b"js", "pi-core/package.json":b"{}"}
        expected = [{"path":n, "size":len(b), "digest":"sha256:" + hashlib.sha256(b).hexdigest(),
                     "executable":not n.startswith("pi-core/")} for n,b in sorted(sources.items())]
        try:
            manifest = stage.materialize(deployment, sources, expected)
            self.assertEqual(manifest["files"], expected)
            for row in expected:
                self.assertEqual(stat.S_IMODE((deployment / row["path"]).stat().st_mode),
                                 0o555 if row["executable"] else 0o444)
        finally:
            if deployment.exists():
                for path in [deployment, *deployment.rglob("*")]:
                    if path.is_dir():
                        path.chmod(0o700)

    def test_changed_member_or_extra_input_cannot_complete_assembly(self):
        row = {"path":"entry", "size":1, "digest":"sha256:" + hashlib.sha256(b"x").hexdigest(), "executable":False}
        with self.assertRaisesRegex(ValueError, "file set differs"):
            stage.materialize(self.root / "extra", {"entry":b"x", "other":b""}, [row])
        with self.assertRaisesRegex(ValueError, "unapproved runtime member"):
            stage.materialize(self.root / "changed", {"entry":b"y"}, [row])
        self.assertFalse((self.root / "changed/entry").exists())
