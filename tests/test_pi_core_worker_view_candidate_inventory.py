"""B86: read retained document bytes; never assemble, install or execute a worker."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_worker_view as view


BASE = Path(".aragorn/pi-core-build/worker-view-runtime-b83")
CAT = Path("packaging/pi-core")
CP = CAT / "worker-view-runtime-checkpoint-v1.json"
OS = CAT / "os-artifact-v1.json"
B37 = CAT / "restricted-inventory-checkpoint-v1.json"
PLAN = Path(".aragorn/pi-core-build/restricted-inventory-b37/worker-source-plan.json")
MANIFEST = BASE / "manifest.json"
RECEIPT = BASE / "candidate-receipt.json"
PREFIX = "/opt/aragorn/pi-runtime/"
GATE = PREFIX + "observer/source-gate"


def pin(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class WorkerViewCandidateInventory(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        # Only original, small checkpoint documents. In particular this root has
        # neither B36 nor B83 deployment trees, gate binary, guest or private packet.
        os_record = json.loads((view.ROOT / OS).read_bytes())
        for rel in (CP, MANIFEST, RECEIPT, B37, PLAN, OS, Path(os_record["receipt_local_path"]),
                    CAT / "restricted-worker-inventory-v1.json", CAT / "worker-view-gate-artifact-v3.json",
                    CAT / "restricted-runtime-artifact-v1.json"):
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes((view.ROOT / rel).read_bytes())

    def raw(self, rel):
        return (self.root / rel).read_bytes()

    def read(self, rel):
        return json.loads(self.raw(rel))

    def inventory(self):
        return view.candidate_content_inventory(root=self.root)

    def snapshot(self):
        return {p.relative_to(self.root): (p.stat().st_ino, p.stat().st_mtime_ns, pin(p.read_bytes()))
                for p in self.root.rglob("*") if p.is_file()}

    def test_exact_four_runtime_members_and_eight_node_loaders_without_touching_inputs(self):
        original = self.snapshot()
        got = self.inventory()
        self.assertEqual(original, self.snapshot())
        self.assertEqual(set(got), {"schema", "candidate_receipt_digest", "candidate_manifest_digest",
                                    "candidate_tree_digest", "predecessor_plan_digest", "gate_receipt_digest",
                                    "runtime_files", "node_loaders", "installed_view_observed", "target_executed",
                                    "launch_authorized", "phase3_exit_eligible"})
        self.assertEqual(got["schema"], "aragorn/pi-core-worker-view-content-candidate/v1")
        cp, rc, mf = (self.read(path) for path in (CP, RECEIPT, MANIFEST))
        self.assertEqual(got["candidate_receipt_digest"], "sha256:" + cp["files"]["candidate-receipt.json"])
        self.assertEqual(got["candidate_manifest_digest"], "sha256:" + cp["files"]["manifest.json"])
        self.assertEqual(got["candidate_tree_digest"], cp["candidate_tree_digest"])
        self.assertEqual(got["gate_receipt_digest"], rc["gate_receipt_digest"])
        plan = self.read(PLAN)
        self.assertEqual(got["predecessor_plan_digest"], pin(self.raw(PLAN)))
        self.assertEqual(got["predecessor_plan_digest"], self.read(B37)["source_plan_digest"])
        self.assertEqual(got["runtime_files"], [
            dict(path=PREFIX + r["path"], size=r["size"], digest=r["digest"],
                 mode=0o555 if r["executable"] else 0o444) for r in mf["files"]])
        members = {r["path"]:r["digest"] for r in got["runtime_files"]}
        self.assertEqual(set(members), {GATE, PREFIX + "node/bin/node", *(r["path"] for r in plan["sources"])})
        self.assertEqual(members[GATE], "sha256:ffc723e70a72421226b554d7e0407680f9e2a41262ddd7c1456bacd923073d78")
        self.assertNotEqual(members[GATE], plan["pins"]["gate_digest"])
        os_rows = {"/" + r["path"]: r for r in self.read(OS)["protected_tree"]["files"]}
        self.assertEqual(len(plan["loader_files"]), 8)
        self.assertEqual(got["node_loaders"], [
            dict(path=r["path"], digest=r["digest"], size=os_rows[r["path"]]["size"],
                 mode=0o555 if os_rows[r["path"]]["executable"] else 0o444) for r in plan["loader_files"]])
        for field in ("installed_view_observed", "target_executed", "launch_authorized", "phase3_exit_eligible"):
            self.assertIs(got[field], False, field)

    def test_changed_candidate_receipt_manifest_or_predecessor_plan_bytes_are_not_accepted(self):
        for rel in (RECEIPT, MANIFEST, PLAN):
            path = self.root / rel
            original = path.read_bytes()
            with self.subTest(rel=rel):
                # Preserve the semantic JSON and every other input; even a
                # plausible re-encoding is not the retained document.
                path.write_bytes(original + b" ")
                reason = "retained worker plan bytes differ" if rel == PLAN else "retained document differs"
                with self.assertRaisesRegex(ValueError, reason):
                    self.inventory()
                path.write_bytes(original)

    def test_identical_bytes_at_an_aliased_receipt_path_are_refused(self):
        path = self.root / RECEIPT
        other = path.with_name("foreign-receipt.json")
        path.rename(other)
        path.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "linked"):
            self.inventory()

    def test_resealed_candidate_relabelled_as_installed_or_launchable_remains_refused(self):
        path = self.root / RECEIPT
        cp = self.read(CP)
        receipt = self.read(RECEIPT)
        for field in ("installed", "launch_authorized", "target_executed", "phase3_exit_eligible"):
            with self.subTest(field=field):
                path.write_bytes(view.fixed.canonical({**receipt, field: True}) + b"\n")
                cp["files"]["candidate-receipt.json"] = pin(path.read_bytes())[7:]
                (self.root / CP).write_bytes(view.fixed.canonical(cp) + b"\n")
                with self.assertRaisesRegex(ValueError, "retained document differs: worker-view-runtime-checkpoint"):
                    self.inventory()

    def test_verified_rows_cannot_change_namespace_or_carry_forward_the_old_gate(self):
        # Exercise the new semantic boundary separately from the raw digest
        # refusals above. Every original document is still checked by the
        # actual pinned reader before the isolated mutation is presented.
        document = view.worker._document
        for change in ("escape", "replace-source", "duplicate", "gate-mode", "old-gate"):
            def mutated(path, sha):
                doc = document(path, sha)
                if path != self.root / MANIFEST:
                    return doc
                rows = {r["path"]: r for r in doc["files"]}
                gate = rows["observer/source-gate"]
                if change == "escape":
                    gate["path"] = "../source-gate"
                elif change == "replace-source":
                    rows["pi-core/entrypoint.js"]["digest"] = gate["digest"]
                elif change == "duplicate":
                    gate["path"] = "node/bin/node"
                elif change == "gate-mode":
                    gate["executable"] = False
                else:
                    gate["digest"] = self.read(PLAN)["pins"]["gate_digest"]
                return doc
            with self.subTest(change=change), patch.object(view.worker, "_document", side_effect=mutated):
                with self.assertRaisesRegex(ValueError, "candidate file set, modes, sizes or tree differ"):
                    self.inventory()
