"""B86 package-boundary refusals on small inputs; no real media is created."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_candidate_filesystem as package


class CandidateFilesystemInputs(unittest.TestCase):
    def test_wrong_predecessor_is_refused_before_archive_parsing(self):
        raw = b"not a nominated archive"
        with patch.object(package, "B53_ARCHIVE_BYTES", len(raw)), patch.object(package.tarfile, "open") as parser:
            with self.assertRaisesRegex(ValueError, "different B53 worker archive"):
                package._original_members(raw)
            parser.assert_not_called()

    def test_existing_output_is_never_adopted_or_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d).resolve() / "existing"
            path.mkdir(mode=0o700)
            marker = path / "partial"
            marker.write_bytes(b"original partial")
            with patch.object(package, "OUT", path), patch.object(package, "candidate_members") as inputs:
                with self.assertRaises(FileExistsError):
                    package.prepare()
                inputs.assert_not_called()
            self.assertEqual(marker.read_bytes(), b"original partial")

    def test_gate_substitution_loader_mode_and_extra_member_refuse_without_mutating_predecessor(self):
        inv = package.candidate_content_inventory()
        old, gate = b"fixed old", b"c" * 4232
        files = {"usr/bin/env": (b"env", 0o555)}
        inv = deepcopy(inv)
        for row in inv["runtime_files"] + inv["node_loaders"]:
            name = row["path"][1:]
            data = gate if name == package.MEMBER else name.encode()
            row.update(size=len(data), digest="sha256:" + package.retained.sha(data))
            files[name] = (old if name == package.MEMBER else data, row["mode"])
        with patch.object(package.fixed, "GATE_BYTES", len(old)), patch.object(package.fixed, "GATE_SHA256", package.retained.sha(old)):
            for issue in ("substituted gate", "writable loader", "unexpected file"):
                original = dict(files)
                proposed = gate
                if issue == "substituted gate":
                    proposed = b"x" * len(gate)
                elif issue == "writable loader":
                    name = inv["node_loaders"][0]["path"][1:]
                    original[name] = (original[name][0], 0o755)
                else:
                    original["etc/unapproved"] = (b"extra", 0o444)
                before = dict(original)
                with self.subTest(issue=issue), self.assertRaisesRegex(ValueError, "content or mode|unchecked worker member"):
                    package.replace_gate({}, original, proposed, inv)
                self.assertEqual(original, before)
