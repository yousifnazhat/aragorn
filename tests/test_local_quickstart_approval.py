"""Only the reviewed local inventory may supply quickstart worker bytes."""
from contextlib import ExitStack
import importlib
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/local-quickstart"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(EXAMPLE))
from aragorn.acquire import inventory_local
from aragorn.cas import CAS


class TestLocalQuickstartApproval(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.temp = Path(temp.name)
        self.cap = self.temp / "capability"
        self.cap.mkdir()
        self.worker = self.cap / "worker.py"
        self.original = b"# approved source\n"
        self.worker.write_bytes(self.original)
        self.cas = CAS(self.temp / "cas")
        self.pin = inventory_local(self.cap)["tree_digest"]

    def test_inventory_and_execution_share_the_existing_tree_identity(self):
        api = importlib.import_module("local_approval")
        manifest = api.inventory_worker(self.cap, self.cas)
        self.assertEqual(manifest["tree_digest"], self.pin)
        self.assertEqual(api.approved_worker(self.cap, self.cas, self.pin), self.original)

    def test_path_replaced_after_ingest_cannot_substitute_execution_bytes(self):
        api = importlib.import_module("local_approval")
        read = self.cas.read

        def replace_then_read(digest, **kwargs):
            self.worker.write_bytes(b"# replacement after inventory\n")
            return read(digest, **kwargs)

        with patch.object(self.cas, "read", side_effect=replace_then_read) as reading:
            self.assertEqual(api.approved_worker(self.cap, self.cas, self.pin), self.original)
            self.assertTrue(reading.called)
        self.assertNotEqual(self.worker.read_bytes(), self.original)

    def test_extra_files_and_symlinks_are_not_reviewable_as_one_worker(self):
        api = importlib.import_module("local_approval")
        extra = self.cap / "other.py"
        extra.write_bytes(b"# not part of this profile\n")
        with self.assertRaises(ValueError):
            api.inventory_worker(self.cap, self.cas)
        extra.unlink()
        self.worker.unlink()
        self.worker.symlink_to(self.temp / "outside.py")
        with self.assertRaises(ValueError):
            api.inventory_worker(self.cap, self.cas)

    def test_changed_approved_tree_is_refused_before_worker_launch(self):
        coordinator = importlib.import_module("coordinator")
        self.worker.write_bytes(b"# changed before launch\n")
        fixture = self.temp / "fixture"
        fixture.mkdir()
        with ExitStack() as stack:
            for name, value in (("ROOT", fixture), ("OUTPUT", fixture / "out"),
                                ("STAGING", fixture / "staging"), ("CAPABILITY_DIR", self.cap)):
                stack.enter_context(patch.object(coordinator, name, value, create=True))
            # Substitute only the coordinator's host guards; CAS still measures
            # its actual owner's UID, and operates on a real temporary directory.
            guest_os = SimpleNamespace(**vars(os))
            guest_os.geteuid = lambda: 0
            guest_os.path = SimpleNamespace(**vars(os.path))
            guest_os.path.ismount = lambda path: path == fixture
            stack.enter_context(patch.object(coordinator, "os", guest_os))
            stack.enter_context(patch.object(sys, "platform", "linux"))
            stack.enter_context(patch.object(sys, "argv", ["coordinator.py", "--approve-tree", self.pin]))
            launch = stack.enter_context(patch.object(coordinator, "exercise",
                                                      side_effect=AssertionError("worker was launched")))
            with self.assertRaisesRegex(ValueError, "(?i)approv"):
                coordinator.main()
            launch.assert_not_called()
