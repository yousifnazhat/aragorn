"""B111 host packaging checks; use the single staged result, never run its code."""
import json
from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_b109_payload as previous
from scripts import prepare_pi_core_b111_payload as subject
from scripts.build_pi_core_linux import BuildError, canonical, sha256


PROFILE = "/etc/aragorn/coordinator-host.json"
WRAPPER = "/opt/aragorn/bin/coordinator.py"
# Independently read Git blob SHA-256s, not rows from the successor's catalog.
DONOR = "2aba715e7bd90f0309891686c791b2b438785f58"
CODE = {
    WRAPPER: "9b9772bbe638078e4a3439de39020338290d29dfdec1c5104c29516554fb95e0",
    "/opt/aragorn/src/aragorn/pi_core_pilot_output_custody.py": "234d277d268d5c7e92645988bfb952cf086bdf719f2716a5b9349cbe38a27306",
    "/opt/aragorn/src/aragorn/pi_core_pilot_retention_entry.py": "9ae907a0d5158c57618ae6f00daa9186037f76400a3e10da8aba055126e8be1e",
}
B109_PAYLOAD = "f84e61381e72d7630964e07d5b4a6ee97006e7642a1666eaba4fbce7e1563232"
WORKER_ROWS = "26c5d0d1b43ef688845db21fcd3e9c9ce600078389ba2f2c469dc9ba4fa0ace9"


class B111HostSuccessorTests(TestCase):
    def test_exact_host_only_delta_and_retained_service_worker(self):
        payload, changed, outcome = subject.readback()
        old = json.loads(previous.b105.image.read(previous.OUT / "payload.json", B109_PAYLOAD, 2 << 20))
        before, after = (previous.b105.split._index(v["entries"]) for v in (old, payload))
        expected = CODE.keys() | {PROFILE}
        self.assertEqual(changed.keys(), expected)
        self.assertEqual({p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}, expected)
        self.assertEqual(after.keys() - before.keys(), CODE.keys() - {WRAPPER})
        self.assertFalse(before.keys() - after.keys())
        self.assertEqual({k: v for k, v in old.items() if k != "entries"},
                         {k: v for k, v in payload.items() if k != "entries"})
        host = json.loads(changed[PROFILE])
        prior = json.loads(previous.b105.image.read(previous.OUT / "root" / PROFILE[1:], before[PROFILE]["sha256"], 2 << 20))
        old_files, files = ({r["path"]: r for r in profile["files"]} for profile in (prior, host))
        self.assertEqual({k: v for k, v in host.items() if k != "files"},
                         {k: v for k, v in prior.items() if k != "files"})
        self.assertEqual({p for p in old_files.keys() | files.keys() if old_files.get(p) != files.get(p)}, CODE.keys())
        for path, raw in changed.items():
            with self.subTest(path=path):
                mode = 0o400 if path == PROFILE else 0o444
                self.assertEqual(after[path], dict(path=path, type="file", uid=0, gid=0, mode=mode, size=len(raw),
                                                  sha256=sha256(raw)))
                if path in CODE:
                    self.assertEqual(sha256(raw), CODE[path])
                    self.assertEqual(files[path], dict(path=path, digest="sha256:" + CODE[path], size=len(raw)))
        worker = [row for p, row in sorted(after.items()) if any(Path(p).is_relative_to(r)
                  for r in ("/var/lib/aragorn/pi-os", "/var/lib/aragorn/pi-runtime"))]
        self.assertEqual((len(worker), sha256(canonical(worker))), (37, WORKER_ROWS))
        b109 = json.loads(previous.b105.image.read(previous.OUT / "outcome.json", previous.OUTCOME_PIN, 16384))
        for key in ("service_runtime", "manifest_sha256", "binding_sha256", "layout_receipt_sha256", "service_files"):
            self.assertEqual(outcome[key], b109[key])
        self.assertEqual(outcome["source_evidence"]["source_revision"], DONOR)
        self.assertEqual((outcome["b109_payload_sha256"], outcome["payload_sha256"]), (B109_PAYLOAD, sha256(canonical(payload))))
        for flag in ("image_assembled", "installed_identity_verified", "activation_performed", "phase3_exit_eligible"):
            self.assertIs(outcome[flag], False)

    def test_substituted_b109_payload_cannot_publish_a_successor(self):
        with TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            copyfile(previous.OUT / "outcome.json", base / "outcome.json")
            (base / "payload.json").write_bytes(b"{}")
            out = base / "new"
            with patch.object(subject, "BASE", base), patch.object(subject, "OUT", out):
                with self.assertRaisesRegex(BuildError, "payload input digest differs"):
                    subject.prepare()
            self.assertFalse(out.exists())

    def test_altered_host_profile_cannot_be_read_as_reviewed_bytes(self):
        with TemporaryDirectory() as temp:
            out = Path(temp).resolve()
            for name in ("payload.json", "outcome.json"):
                copyfile(subject.OUT / name, out / name)
            for path in CODE.keys() | {PROFILE}:
                source = subject.OUT / "root" / path[1:]
                target = out / "root" / path[1:]
                target.parent.mkdir(parents=True, exist_ok=True)
                data = source.read_bytes()
                target.write_bytes(b"x" + data[1:] if path == PROFILE else data)
                target.chmod(source.stat().st_mode & 0o777)
            with patch.object(subject, "OUT", out), self.assertRaisesRegex(BuildError, "staged host bytes differ"):
                subject.readback()

    def test_occupied_successor_refuses_before_reading_the_predecessor(self):
        with TemporaryDirectory() as temp:
            out = Path(temp).resolve()
            marker = out / "retained"
            marker.write_bytes(b"keep")
            with patch.object(subject, "BASE", out / "no-such-predecessor"), patch.object(subject, "OUT", out):
                with self.assertRaisesRegex(BuildError, "output already present"):
                    subject.prepare()
            self.assertEqual(list(out.iterdir()), [marker])
            self.assertEqual(marker.read_bytes(), b"keep")
