"""One fresh developer-side B83 assembly; read files as bytes, never execute them."""
import hashlib
import json
import os
import stat
import unittest

from aragorn import pi_core_restricted_profile as predecessor
from aragorn.pi_core_confined_launch import _runtime_inventory, _source_gate_artifact
from scripts import prepare_pi_core_worker_view_runtime as stage


class WorkerViewRuntimeAssembly(unittest.TestCase):
    def test_stage_once_and_independently_read_back_only_the_gate_successor(self):
        root = stage.ROOT
        work = root / ".aragorn/pi-core-build/worker-view-runtime-b83"
        self.assertFalse(os.path.lexists(work), "retain any prior result; cannot build again")
        # No compiler, preparatory run, guest process or launcher invocation.
        result = stage.assemble(root=root)
        self.assertEqual({p.name for p in work.iterdir()}, {"deployment","manifest.json","candidate-receipt.json"})
        manifest_raw = (work / "manifest.json").read_bytes()
        manifest = json.loads(manifest_raw)
        self.assertEqual(manifest_raw, predecessor.canonical(manifest)+b"\n")
        receipt_raw = (work / "candidate-receipt.json").read_bytes()
        self.assertEqual(receipt_raw, predecessor.canonical(result)+b"\n")
        self.assertEqual(result["schema"],"aragorn/pi-core-worker-view-runtime-candidate/v1")
        self.assertEqual(result["status"],"STAGED_CANDIDATE_ONLY")
        for field in ("installed","target_executed","launch_authorized","phase3_exit_eligible"):
            self.assertIs(result[field],False,field)
        self.assertEqual(result["manifest_sha256"],hashlib.sha256(manifest_raw).hexdigest())
        raw36 = (root / "packaging/pi-core/restricted-runtime-artifact-v1.json").read_bytes()
        raw82 = (root / "packaging/pi-core/worker-view-gate-artifact-v3.json").read_bytes()
        b36, b82 = json.loads(raw36), json.loads(raw82)
        self.assertEqual(result["replaced_member"],"observer/source-gate")
        self.assertEqual(result["predecessor_checkpoint_sha256"],hashlib.sha256(raw36).hexdigest())
        self.assertEqual(result["predecessor_receipt_digest"],b36["canonical_receipt_digest"])
        self.assertEqual(result["predecessor_runtime_digest"],b36["runtime_digest"])
        self.assertEqual(result["gate_checkpoint_sha256"],hashlib.sha256(raw82).hexdigest())
        self.assertEqual(result["gate_receipt_digest"],"sha256:"+b82["files"]["build-receipt.json"])
        self.assertEqual(result["gate_elf_sha256"],b82["files"]["source-gate"])
        original = predecessor.expected_files()
        expected = [r | {"digest":"sha256:"+b82["files"]["source-gate"],"size":4232} if
                    r["path"] == "observer/source-gate" else r for r in original]
        self.assertEqual(manifest["files"],expected)
        self.assertEqual([r["path"] for r,s in zip(original,expected) if r != s], ["observer/source-gate"])
        tree_pin = predecessor.digest([dict(path=r["path"],kind="file",bytes=r["size"],sha256=r["digest"][7:])
                                      for r in expected])
        self.assertEqual(result["candidate_tree_digest"],tree_pin)
        self.assertNotEqual(tree_pin,predecessor.RUNTIME_DIGEST)
        deployment = work / "deployment"
        dirs = {".","node","node/bin","observer","pi-core"}
        files = {r["path"]:r for r in expected}
        found = set()
        for path in [deployment,*deployment.rglob("*")]:
            name, info = path.relative_to(deployment).as_posix(), path.lstat()
            found.add(name)
            if name in dirs:
                self.assertTrue(stat.S_ISDIR(info.st_mode),name)
                self.assertEqual(stat.S_IMODE(info.st_mode),0o555,name)
            else:
                row = files[name]
                self.assertTrue(stat.S_ISREG(info.st_mode),name)
                self.assertEqual((info.st_nlink,info.st_size,stat.S_IMODE(info.st_mode)),
                                 (1,row["size"],0o555 if row["executable"] else 0o444),name)
                with path.open("rb") as f:
                    digest = hashlib.file_digest(f,"sha256").hexdigest()
                self.assertEqual("sha256:"+digest,row["digest"],name)
        self.assertEqual(found,dirs | set(files))
        # These are read-only receipt parsers, not calls to launch a worker.
        with self.assertRaises(ValueError):
            _runtime_inventory(manifest,result,predecessor.digest(result))
        with self.assertRaises(ValueError):
            _source_gate_artifact(manifest,result)
