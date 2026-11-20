"""Offline B53 package checks. No archive is extracted and no target is executed."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_worker_filesystem as fs
from scripts.build_pi_core_linux import BuildError
from scripts import prepare_pi_core_worker_view as projection


ROOT = Path(__file__).resolve().parents[1]
REJECT = (BuildError, ValueError)
DIRS = {"code": 0o555}
FILES = {"code/entry": (b"abc", 0o444)}


class WorkerFilesystem(unittest.TestCase):
    def test_substituted_retained_source_plan_refused_before_os_or_runtime_acquisition(self):
        with patch.object(projection.worker, "_document", return_value={"source_plan_digest": "sha256:" + "0" * 64}) as document, \
                patch.object(projection.retained, "read", return_value=b"{}") as read, self.assertRaisesRegex(ValueError, "plan bytes differ"):
            projection.worker_members()
        document.assert_called_once_with(ROOT / projection.CHECKPOINT, projection.CHECKPOINT_SHA256)
        read.assert_called_once_with(ROOT / projection.PLAN, 65536)

    def test_untrusted_names_collisions_and_writable_code_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n, (name, mode) in enumerate((("/bad", 0o444), ("../bad", 0o444), ("code//bad", 0o444),
                                              ("code/./bad", 0o444), ("code", 0o444), ("code/write", 0o644))):
                with self.subTest(name=name), self.assertRaises(REJECT):
                    fs.write_archive(Path(tmp).resolve() / f"bad{n}.tar", DIRS, {name: (b"x", mode)})

    def test_archive_is_exclusive_and_readback_detects_original_byte_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "view.tar"
            fs.write_archive(path, DIRS, FILES)
            before = path.read_bytes()
            self.assertEqual(fs.verify_archive(path, DIRS, FILES), hashlib.sha256(before).hexdigest())
            with self.assertRaises((FileExistsError, *REJECT)):
                fs.write_archive(path, DIRS, {"code/entry": (b"abd", 0o444)})
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaises(REJECT):
                fs.verify_archive(path, DIRS, {"code/entry": (b"abd", 0o444)})
            appended = path.with_name("trailing.tar")
            appended.write_bytes(before + before)
            with self.assertRaises(REJECT):
                fs.verify_archive(appended, DIRS, FILES)

    def test_readback_rejects_duplicate_special_or_changed_member_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            original = root / "good.tar"
            fs.write_archive(original, DIRS, FILES)
            for mutation in ("duplicate", "symlink", "device", "owner", "writable"):
                other = root / (mutation + ".tar")
                with tarfile.open(original, "r:") as src, tarfile.open(other, "x:", format=tarfile.USTAR_FORMAT) as dst:
                    for member in src:
                        if member.name != "code/entry":
                            dst.addfile(member)
                            continue
                        if mutation == "duplicate":
                            dst.addfile(member, io.BytesIO(b"abc"))
                        elif mutation in ("symlink", "device"):
                            member.type = tarfile.SYMTYPE if mutation == "symlink" else tarfile.CHRTYPE
                            member.linkname = "../outside" if mutation == "symlink" else ""
                            member.size = 0
                        elif mutation == "owner":
                            member.uid = 1
                        else:
                            member.mode = 0o644
                        dst.addfile(member, io.BytesIO(b"abc") if member.isfile() else None)
                with self.subTest(mutation=mutation), self.assertRaises(REJECT):
                    fs.verify_archive(other, DIRS, FILES)

    def test_retained_worker_and_service_state_are_separate_offline_artifacts(self):
        fs.prepare()
        output = fs.OUT
        self.assertFalse(output.is_relative_to(ROOT) or output.is_relative_to(Path.home() / "Documents"))
        outcome = json.loads((output / "outcome.json").read_bytes())
        plan_bytes = (output / "worker-source-plan.json").read_bytes()
        checkpoint = json.loads((ROOT / "packaging/pi-core/restricted-inventory-checkpoint-v1.json").read_bytes())
        self.assertEqual("sha256:" + hashlib.sha256(plan_bytes).hexdigest(), checkpoint["source_plan_digest"])
        plan = json.loads(plan_bytes)
        media_bytes = (ROOT / "packaging/pi-core/immutable-host-b44/media-output.json").read_bytes()
        self.assertEqual((outcome["disk_sha256"], outcome["media_pins_sha256"]),
                         (json.loads(media_bytes)["disk_sha256"], hashlib.sha256(media_bytes).hexdigest()))
        self.assertEqual((outcome["source_plan_sha256"], outcome["runtime_digest"]),
                         (hashlib.sha256(plan_bytes).hexdigest(), checkpoint["runtime_digest"]))
        self.assertEqual(set(outcome["archives"]), {"worker-view.tar", "writable-state.tar"})
        for name, expected_hash in outcome["archives"].items():
            path = output / name
            self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            with path.open("rb") as stream:
                self.assertEqual(hashlib.file_digest(stream, "sha256").hexdigest(), expected_hash)
        state = outcome["state"]
        self.assertEqual(set(state["required_absent"]), {"/var/lib/aragorn-runtime-action", "/var/lib/aragorn-runtime-provider"})
        self.assertEqual(state["worker_binds"], [])
        for key in ("mounted", "authorized"):
            self.assertIs(state[key], False)
        for key in ("installed_view_observed", "target_executed", "phase3_exit_eligible"):
            self.assertIs(outcome[key], False)
        runtime = "opt/aragorn/pi-runtime/"
        with tarfile.open(output / "worker-view.tar", "r:") as archive:
            members = archive.getmembers()
            self.assertEqual(len(members), len({m.name for m in members}))
            self.assertTrue(all(m.isfile() or m.isdir() for m in members))
            self.assertTrue(all((m.uid, m.gid, m.mtime, m.mode & 0o222) == (0, 0, 0, 0) for m in members))
            for name in ("run/aragorn-pi-bootstrap", "var/lib/aragorn/admitted", "tmp", "var/tmp"):
                self.assertTrue(archive.getmember(name).isdir())
                self.assertFalse(any(m.name.startswith(name + "/") for m in members))
            for row in plan["loader_files"] + plan["sources"] + [
                    {"path": "/" + runtime + "node/bin/node", "digest": plan["pins"]["node_digest"]},
                    {"path": "/" + runtime + "observer/source-gate", "digest": plan["pins"]["gate_digest"]}]:
                member = archive.getmember(row["path"][1:])
                with archive.extractfile(member) as stream:
                    self.assertEqual("sha256:" + hashlib.file_digest(stream, "sha256").hexdigest(), row["digest"])
            for leaf in ("var/lib/aragorn-runtime-action", "var/lib/aragorn-runtime-provider"):
                self.assertFalse(any(m.name == leaf or m.name.startswith(leaf + "/") for m in members))
        with tarfile.open(output / "writable-state.tar", "r:") as archive:
            members = archive.getmembers()
            self.assertEqual([(m.name, m.mode, m.uid, m.gid, m.isdir()) for m in members],
                             [("var", 0o755, 0, 0, True), ("var/lib", 0o755, 0, 0, True)])
        print(json.dumps(outcome, sort_keys=True), flush=True)
