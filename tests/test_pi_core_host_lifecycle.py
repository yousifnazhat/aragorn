"""B46 connected, local no-store preview only. Preserve real artifacts, including failures."""
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from scripts import prepare_pi_core_host_lifecycle as life
from scripts.build_pi_core_linux import BuildError


BASE = "1fd46c7928c74dd3afa5839752782a6743425ea4"
SIGNER = "SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"


def private_roots(base):
    roots = tuple(base / n for n in ("fixture", "ledger", "exports"))
    for r in roots:
        r.mkdir(mode=0o700)
    return roots


class HostLifecycle(unittest.TestCase):
    def test_actual_signed_preview_under_watchdog_export_and_separate_readback(self):
        # Keep the original and the export outside Documents/checkout metadata management.
        parent = Path.home() / "Library/Application Support/Aragorn-B46-Offline"
        parent.mkdir(mode=0o700, exist_ok=True)
        life.binding.identity(parent, True)
        base = Path(tempfile.mkdtemp(prefix="preview-", dir=parent))
        fixture, ledger, exports = private_roots(base)
        uid = str(uuid.uuid4())
        # Make the evidence path available even when a later step refuses.
        print("B46 retained:", base, uid, flush=True)
        result = life.preview(fixture, ledger, exports, uid, BASE, SIGNER)
        self.assertEqual(result["status"], "exported_no_boot_preview")
        self.assertFalse(result["phase3_exit_eligible"] or result["boot_observed"])
        self.assertEqual((fixture / uid / "binding.json").read_bytes(), (ledger / uid / "runner.stdout").read_bytes())
        self.assertEqual((fixture / uid / "serial.raw").read_bytes(), b"")
        self.assertTrue(life.read_export(exports, uid, result["export_sha256"]))
        print(json.dumps(result, sort_keys=True), flush=True)

    def test_managed_evidence_directories_refused_without_writes(self):
        for path in (life.build.WORK, Path.home() / "Documents", Path.home() / "Library/CloudStorage" / "fixture"):
            with self.subTest(path=path), self.assertRaisesRegex(BuildError, "local evidence storage"):
                life.require_local_custody(path)

    def test_shared_nested_and_preexisting_paths_refused_before_spawn(self):
        with tempfile.TemporaryDirectory() as temp:
            roots = private_roots(Path(temp).resolve())
            uid = str(uuid.uuid4())
            parent, ledger, exports = roots
            sub = parent / "sub"
            sub.mkdir(mode=0o700)
            for r in ((parent, ledger, parent), (sub, parent, exports)):
                with self.assertRaisesRegex(BuildError, "overlapping"):
                    life.layout(*r, uid)
            (ledger / uid).symlink_to(ledger / "missing")
            with self.assertRaisesRegex(BuildError, "reserved"):
                life.layout(*roots, uid)

    def test_bad_signature_stops_before_reservation(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(life, "supervise") as launch:
            roots = private_roots(Path(temp).resolve())
            with self.assertRaisesRegex(BuildError, "signer mismatch"):
                life.preview(*roots, str(uuid.uuid4()), BASE, "SHA256:" + "A" * 43)
            launch.assert_not_called()
            self.assertTrue(all(not list(r.iterdir()) for r in roots))
