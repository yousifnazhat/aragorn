"""New cumulative-delta and one-shot publication boundaries; no guest or real output."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_b62_host_successor as batch
from scripts.build_pi_core_linux import BuildError


def file(path, data):
    return dict(path=path, type="file", mode=0o444, uid=0, gid=0, size=len(data), sha256=batch.sha256(data))


DIR = dict(path="/root", type="dir", mode=0o755, uid=0, gid=0)


class ProtectedHostPayload(unittest.TestCase):
    def test_changes_relative_to_base_not_predecessor_preserve_carried_bytes_and_one_final_supervisor(self):
        old = file("/root/supervisor", b"old")
        middle = file("/root/supervisor", b"middle")
        final = file("/root/supervisor", b"final")
        carry, added = file("/root/carry", b"retained"), file("/root/entry", b"new")
        base = dict(entries=[DIR, old])
        intermediate = dict(entries=[DIR, carry, middle])
        target = dict(entries=[DIR, carry, added, final])
        self.assertEqual(batch._delta(base, target), target)
        self.assertEqual(batch._delta(intermediate, target)["entries"], [DIR, added, final])
        self.assertEqual(intermediate["entries"][-1], middle)

    def test_removal_duplicate_mode_change_new_directory_and_path_escape_refuse(self):
        row = file("/root/file", b"one")
        base = {"entries": [DIR, row]}
        for contents in ([DIR], [DIR, row, row], [DIR, dict(row, uid=1)],
                         [dict(DIR, mode=0o777), row], [DIR, row, dict(DIR, path="/new")],
                         [DIR, row, file("//etc/file", b"x")], [DIR, row, file("/root/../bad", b"x")]):
            with self.subTest(contents=contents), self.assertRaises(BuildError):
                batch._delta(base, dict(entries=contents))

    def test_changed_host_rows_need_the_independent_source_inventory_pin(self):
        with self.assertRaisesRegex(BuildError, "unreviewed"):
            batch.project({}, [])

    def test_publish_readback_is_exclusive_and_does_not_adopt_partial_or_linked_output(self):
        with TemporaryDirectory() as temp:
            private = Path(temp).resolve()
            out = private / "out"
            base = dict(entries=[DIR])
            row = file("/root/entry", b"kept")
            delta = batch._delta(base, dict(entries=[DIR, row]))
            with patch.object(batch, "OUT", out):
                batch._publish(delta, {row["path"]: b"kept"}, {"notes.json": b"{}"}, {})
                before = (out / "changed-files/root/entry").read_bytes()
                with self.assertRaises(FileExistsError):
                    batch._publish(delta, {row["path"]: b"not kept"}, {}, {})
                self.assertEqual((out / "changed-files/root/entry").read_bytes(), before)
            link = private / "link"
            link.symlink_to(out, target_is_directory=True)
            with patch.object(batch, "OUT", link), self.assertRaisesRegex(BuildError, "already present"):
                batch.prepare()

