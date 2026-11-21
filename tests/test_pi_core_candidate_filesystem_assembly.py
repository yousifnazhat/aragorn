"""One exclusive offline emission; compare both archives by member without extracting anything."""
from hashlib import file_digest
import json
import tarfile
import unittest

from scripts import prepare_pi_core_candidate_filesystem as successor
from scripts import prepare_pi_core_worker_filesystem as predecessor


def inventory(path):
    rows = {}
    with tarfile.open(path, mode="r:") as stream:
        for item in stream:
            if item.name in rows or not (item.isdir() or item.isreg()):
                raise ValueError("unexpected archive member")
            digest = None
            if item.isreg():
                with stream.extractfile(item) as member:
                    digest = file_digest(member, "sha256").hexdigest()
            rows[item.name] = (item.type, item.mode, item.uid, item.gid, item.mtime, item.size, digest)
    return rows


class CandidateWorkerArchive(unittest.TestCase):
    def test_only_fixed_gate_changed_and_state_seed_not_emitted(self):
        result = successor.prepare()
        old = inventory(predecessor.OUT / "worker-view.tar")
        new = inventory(successor.OUT / "worker-view.tar")
        gate = "opt/aragorn/pi-runtime/observer/source-gate"
        self.assertEqual(old.keys(), new.keys())
        self.assertEqual(len(old), 35)
        self.assertEqual([p for p in old if old[p] != new[p]], [gate])
        self.assertEqual(old[gate][:5], new[gate][:5])
        self.assertEqual(old[gate][-1], "7bbb6d6ad10732747f8145abc51b9732598bb0e926acd82f14196469ec316620")
        self.assertEqual(new[gate][-2:], (4232, "ffc723e70a72421226b554d7e0407680f9e2a41262ddd7c1456bacd923073d78"))
        self.assertEqual(set(p.name for p in successor.OUT.iterdir()), {"worker-view.tar", "outcome.json"})
        self.assertEqual(json.loads((successor.OUT / "outcome.json").read_bytes()), result)
        self.assertEqual(result["predecessor_archive_sha256"], "95ca2d28a2f5b5cf85b01f1f5772066188fe05dd63e3723327c0adc0144d058e")
        for key in ("installed_view_observed", "target_executed", "launch_authorized", "phase3_exit_eligible"):
            self.assertIs(result[key], False)
