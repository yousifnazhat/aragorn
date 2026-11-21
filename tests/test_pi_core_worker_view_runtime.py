"""Successor assembly refusal cases; no compilation, deployment or target execution."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from aragorn import pi_core_restricted_profile as predecessor
from aragorn.pi_core_confined_launch import _runtime_inventory, _source_gate_artifact
from scripts import prepare_pi_core_worker_view_runtime as stage


class WorkerViewRuntimeContract(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="b83-candidate-"))).resolve()
        (self.root / "packaging/pi-core").mkdir(parents=True)
        self.base = self.root / ".aragorn/pi-core-build"
        self.base.mkdir(parents=True,mode=0o700)
        self.b36 = Path("packaging/pi-core/restricted-runtime-artifact-v1.json")
        self.b82 = Path("packaging/pi-core/worker-view-gate-artifact-v3.json")

    def test_wrong_b36_checkpoint_cannot_supply_predecessor(self):
        (self.root / self.b36).write_bytes(b'{"output":"different"}\n')
        with self.assertRaises((ValueError, RuntimeError)):
            stage._b36(self.root)

    def test_wrong_b82_checkpoint_refuses_before_large_predecessor_read(self):
        (self.root / self.b82).write_bytes(b'{"schema":"substitution","runtime_executed":false}\n')
        with mock.patch.object(stage,"_b36",side_effect=AssertionError("unnecessary historical read")), \
                self.assertRaises((ValueError, RuntimeError)):
            stage.prepare_inputs(self.root)

    def test_exact_b82_checkpoint_refuses_wrong_gate_bytes_or_a_b36_receipt(self):
        package = self.root / self.b82.parent
        (self.root / self.b82).write_bytes((stage.ROOT / self.b82).read_bytes())
        source = "source-gate-view-v3.c"
        (package / source).write_bytes((stage.ROOT / self.b82.parent / source).read_bytes())
        gate_dir = self.base / "gate-batch-82"
        gate_dir.mkdir()
        (gate_dir / "source-gate").write_bytes(b"not the approved ELF")
        receipt = gate_dir / "build-receipt.json"
        receipt.write_bytes((stage.ROOT / ".aragorn/pi-core-build/gate-batch-82/build-receipt.json").read_bytes())
        with self.assertRaisesRegex(RuntimeError,"source, compiler or ELF differs"):
            stage._b82(self.root)
        receipt.write_bytes((stage.ROOT / "tests/fixtures/pi_core_b36_gate_receipt.json").read_bytes())
        with self.assertRaisesRegex(RuntimeError,"receipt pin differs"):
            stage._b82(self.root)

    def test_existing_output_is_not_adopted_retried_or_modified(self):
        dest = self.base / "worker-view-runtime-b83"
        dest.mkdir(mode=0o700)
        failed = dest / "refusal.json"
        failed.write_bytes(b"prior evidence")
        with mock.patch.object(stage,"prepare_inputs",side_effect=AssertionError("read past output guard")), \
                self.assertRaises((FileExistsError,ValueError,RuntimeError)):
            stage.assemble(root=self.root)
        self.assertEqual({p.name for p in dest.iterdir()},{"refusal.json"})
        self.assertEqual(failed.read_bytes(),b"prior evidence")

    def test_b36_receipt_cannot_approve_even_one_new_gate_row(self):
        raw = (stage.ROOT / "tests/fixtures/pi_core_b36_gate_receipt.json").read_bytes()
        gate = json.loads(raw) | {"receipt_digest":"sha256:"+hashlib.sha256(raw).hexdigest()}
        old = predecessor.runtime_receipt(gate)
        docs = json.loads((stage.ROOT / self.b82).read_bytes())
        manifest = {"files":[r | {"size":4232,"digest":"sha256:"+docs["files"]["source-gate"]}
                             if r["path"] == "observer/source-gate" else r for r in predecessor.expected_files()]}
        for read in (lambda: _source_gate_artifact(manifest,old),
                     lambda: _runtime_inventory(manifest,old,predecessor.digest(old))):
            with self.assertRaises(ValueError):
                read()

    def test_current_launcher_cannot_accept_candidate_receipt_or_relabel_it(self):
        # No B83 runtime admission exists. The retained bundle still identifies
        # this as restricted even when the receipt's declared version is forged.
        original = {"files":predecessor.expected_files()}
        for schema in ("aragorn/pi-core-worker-view-runtime-candidate/v1",predecessor.RUNTIME_SCHEMA,
                       "aragorn/pi-core-linux-build/v1"):
            candidate = dict(schema=schema,status="STAGED_CANDIDATE_ONLY",runtime_executed=False)
            for read in (lambda: _source_gate_artifact(original,candidate),
                         lambda: _runtime_inventory(original,candidate,predecessor.digest(candidate))):
                with self.subTest(schema=schema),self.assertRaises(ValueError):
                    read()
