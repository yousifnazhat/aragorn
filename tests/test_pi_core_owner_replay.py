"""Whole B48 file-to-result path with inert wire fixtures only, never a fresh capture."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from scripts import replay_pi_core_owner_evidence as replay
from scripts.build_pi_core_linux import BuildError, canonical, sha256
from scripts.prepare_pi_core_vm_owner import PIN
from test_pi_core_owner_records import owner_fixture
from test_pi_core_owner_watchdog_records import watchdog_files


COMMIT = "83e72f9c0fdf409856959bf406686462006725f2"
SIGNER = "SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"


class Replay(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.uid = str(uuid.uuid4())
        self.fixture, self.ledger, self.dest = [self.root / s for s in ("fixture","ledger","archive")]
        for p in (self.fixture, self.ledger, self.dest, self.fixture / self.uid, self.ledger / self.uid):
            p.mkdir(mode=0o700)

    def populate(self):
        pin = json.loads(PIN.read_bytes())
        target = {"runner_sha256":pin["runner_sha256"], "runner_cdhash":pin["cdhash"], "disk_sha256":pin["disk_sha256"],
                  "store_sha256_before":"7"*64,"policy_sha256_before":"8"*64}
        for k, p in (("fixture_identity",self.fixture),("attempt_identity",self.fixture / self.uid),
                     ("disk_identity",self.root / "inert.disk"),("store_identity",self.root / "inert.store")):
            if not p.exists():
                p.touch(mode=0o400)
            target[k] = {"dev":p.stat().st_dev, "ino":p.stat().st_ino}
        records, _ = owner_fixture(self.uid, target)
        # Independently specified fixture times, not a production replay output used as its own oracle.
        watch = watchdog_files(self.uid, {"attempt_start_ns":1000,"recorder_armed_ns":1003,
                                          "start_issued_ns":1006,"record_end_ns":1012})
        for root, files in ((self.fixture,records),(self.ledger,watch)):
            for name, data in files.items():
                path = root / self.uid / name
                path.write_bytes(data)
                path.chmod(0o400)
        facts = {k:target[k] for k in replay.BINDINGS if k in target}
        facts.update(schema="aragorn/b48-independent-target-bindings/v1", release_commit=COMMIT, attempt_uuid=self.uid)
        return pin, facts

    def test_full_original_byte_export_replay_and_release_contradiction(self):
        _, facts = self.populate()
        p = self.root / "independent-facts"
        p.write_bytes(canonical(facts))
        p.chmod(0o400)
        args = [str(self.dest), self.uid, COMMIT, SIGNER, "--bindings", str(p), sha256(p.read_bytes())]
        with redirect_stdout(StringIO()) as out:
            code = replay.main(["export", str(self.ledger), "--fixture", str(self.fixture), *args])
        result = json.loads(out.getvalue())
        self.assertEqual((code, result["disposition"]), (2, "transcript-conflicts-with-held-release"))
        self.assertEqual(result["watchdog"]["disposition"], "consistent-supervised-transcript")
        self.assertEqual(result["recorded_timestamps"]["start_issued_ns"], 1006)
        self.assertFalse(result["boot_verified"] or result["cleanup_authorized"] or result["phase3_exit_eligible"])
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(replay.main(["replay", result["manifest_sha256"], "--host-loss", *args]), 2)
        lost = json.loads(out.getvalue())
        self.assertEqual(lost["disposition"], "unresolved-host-loss")
        self.assertFalse(lost["restoration_verified"] or lost["retry_authorized"])
        with self.assertRaisesRegex(BuildError, "bindings digest mismatch"):
            replay.load_bindings(p, "0"*64)

    def test_external_bindings_indispensable_and_not_interchangeable(self):
        pin, facts = self.populate()
        digest = replay.export_owner_archive(self.fixture, self.ledger, self.dest, self.uid)
        doc, files = replay.read_owner_archive(self.dest, self.uid, digest)
        for other in (None, facts | {"attempt_uuid":str(uuid.uuid4())}, facts | {"release_commit":"a"*40},
                      facts | {"fixture_identity":{"dev":0,"ino":1}}, facts | {"policy_sha256_before":"4"*64}):
            with self.subTest(other=other):
                r = replay.assess(doc, files, commit=COMMIT, pin=pin, bindings=other)
                self.assertEqual(r["disposition"], "indeterminate")
                self.assertFalse(r["boot_verified"] or r["cleanup_authorized"])

    def test_reserved_only_and_partial_raw_are_preserved_on_host_loss(self):
        p = self.fixture / self.uid / "serial.raw"
        p.write_bytes(b"partial\0\xff")
        p.chmod(0o600)
        reservation = watchdog_files(self.uid)["watchdog.json.started"]
        q = self.ledger / self.uid / "watchdog.json.started"
        q.write_bytes(reservation)
        q.chmod(0o400)
        digest = replay.export_owner_archive(self.fixture, self.ledger, self.dest, self.uid)
        doc, files = replay.read_owner_archive(self.dest, self.uid, digest)
        self.assertEqual(files, {"serial.raw":p.read_bytes(), "watchdog.json.started":reservation})
        r = replay.assess(doc, files, commit=COMMIT, pin=json.loads(PIN.read_bytes()), host_loss=True)
        self.assertEqual((r["transcript"],r["disposition"]), ("indeterminate","unresolved-host-loss"))
        self.assertFalse(r["retry_authorized"] or r["cleanup_authorized"])
