"""Offline input-boundary tests only. Kernel identities and observed loads are not modeled."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts import prepare_pi_core_restricted_worker_inventory as worker
from tests.test_pi_core_os_root import elf


class StagingInputs(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.member = self.root / "member"
        self.member.write_bytes(b"123")
        self.member.chmod(0o444)
        self.rows = [dict(path="member", size=3, digest=worker.elf.pin(b"123"), executable=False)]

    def test_unlisted_or_multiply_linked_member_never_returns_candidate_bytes(self):
        alias = self.root / "alias"
        alias.touch()
        with self.assertRaisesRegex(ValueError, "file set"):
            worker._staged_bytes(self.root, [], self.rows)
        alias.unlink()
        with tempfile.TemporaryDirectory() as other:
            os.link(self.member, Path(other) / "hardlink")
            with self.assertRaisesRegex(ValueError, "metadata"):
                worker._staged_bytes(self.root, [], self.rows)

    def test_leaf_pin_mode_or_symlink_substitution_fails(self):
        bad = [dict(self.rows[0], digest=worker.elf.pin(b"321"))]
        with self.assertRaisesRegex(ValueError, "digest"):
            worker._staged_bytes(self.root, [], bad)
        self.member.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "metadata"):
            worker._staged_bytes(self.root, [], self.rows)
        self.member.unlink()
        self.member.symlink_to(self.root)
        with self.assertRaisesRegex(ValueError, "linked"):
            worker._staged_bytes(self.root, [], self.rows)

    def test_extent_must_match_the_reviewed_directory_layout(self):
        (self.root / "extra-dir").mkdir()
        with self.assertRaisesRegex(ValueError, "file set"):
            worker._staged_bytes(self.root, [], self.rows)
        self.assertEqual(worker._staged_bytes(self.root, ["extra-dir"], self.rows), {"member": b"123"})

    def test_substituted_receipt_not_trusted_after_json_reencoding(self):
        self.member.chmod(0o600)
        self.member.write_bytes(b'{"active": true}')
        with self.assertRaisesRegex(ValueError, "document differs"):
            worker._document(self.member, worker.retained.sha(b'{"active":true}'))


class SourcePlan(unittest.TestCase):
    def test_consumable_plan_and_rehashed_runtime_or_role_substitutions(self):
        reviewed = json.loads((worker.ROOT / worker.PLAN).read_bytes())
        pins = reviewed["pins"]
        path = "/opt/aragorn/src/aragorn/"
        host = [{"path": path + "pi_core_source_observer.py", "digest": pins["producer_digest"]},
                {"path": path + "pi_core_node_source_observer.py", "digest": pins["node_observer_digest"]}]
        loader = reviewed["loader_files"]
        self.assertEqual(worker._plan(host, loader, reviewed), worker.fixed.canonical(reviewed))
        for change in ("worker", "loader", "required", "observer", "version"):
            bad = deepcopy(reviewed)
            if change == "worker":
                bad["sources"][0]["digest"] = pins["node_digest"]
            elif change == "loader":
                bad["loader_files"].pop()
            elif change == "required":
                bad["required_sources"].clear()
            elif change == "observer":
                bad["pins"]["producer_digest"] = pins["node_observer_digest"]
            else:
                bad["schema"] = "aragorn/pi-core-source-plan/v1"
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "reviewed worker inventory"):
                worker._plan(host, loader, bad)
        for bad_host in (host[:1], host + host[:1]):
            with self.assertRaisesRegex(ValueError, "host observer pin"):
                worker._plan(bad_host, loader, reviewed)

    def test_static_node_edges_exclude_env_only_dependencies_and_disallow_receipt_forgery(self):
        interp = "/lib/ld-linux-aarch64.so.1"
        lib = "lib/aarch64-linux-gnu/"
        a, b, other = "liba.so", "libb.so", "env-only.so"
        node = elf(interpreter=interp, needed=(a,))
        data = {interp[1:]: elf(), lib+a: elf(soname=a, needed=(b,)), lib+b: elf(soname=b),
                lib+other: elf(soname=other), "usr/bin/env": elf(interpreter=interp, needed=(other,))}
        edges = []
        def edge(owner, kind, name, path):
            edges.append(dict(requester=owner, kind=kind, requested=name, path=path, digest=worker.elf.pin(data[path])))
        for owner, dep in (("@compiled-node", a), ("usr/bin/env", other)):
            edge(owner, "interpreter", interp, interp[1:])
            edge(owner, "needed", dep, lib+dep)
        edge(lib+a, "needed", b, lib+b)
        receipt = dict(protected_tree={"files": [dict(path=name, executable=True) for name in data]},
                       elf_dependencies=edges)
        self.assertEqual([r["path"] for r in worker._node_loaders(node, data, receipt)],
                         sorted((interp, "/"+lib+a, "/"+lib+b)))
        with self.assertRaisesRegex(ValueError, "dependency graph"):
            worker._node_loaders(node, data, dict(receipt, elf_dependencies=edges[:-1]))
        with self.assertRaisesRegex(ValueError, "ELF"):
            worker._node_loaders(b"not an ELF", data, receipt)
