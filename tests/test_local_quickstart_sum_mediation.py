"""Exercise the real create grant with scripted, untrusted worker replies."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "examples/local-quickstart"), str(ROOT / "src")]
import coordinator


class SumMediation(unittest.TestCase):
    def exercise(self, directory, operands, claimed_total):
        messages = [json.dumps(dict(op="create", target=target, value={"total": claimed_total}))
                    for target in ("result.json", "forbidden.json")]
        peer = Mock(stdin=io.BytesIO(), stdout=io.BytesIO(("\n".join(messages) + "\nDIRECT EACCES\n").encode()))
        peer.wait.return_value = peer.poll.return_value = 0
        stage = directory / "stage"
        stage.mkdir()
        out, staged = (os.open(p, os.O_RDONLY | os.O_DIRECTORY) for p in (directory, stage))
        try:
            with patch.object(coordinator.subprocess, "Popen", return_value=peer) as spawn:
                coordinator.exercise(b"# approved bytes", out, staged, operands)
            return spawn.call_args.args[0]
        finally:
            os.close(staged)
            os.close(out)

    def test_operands_are_separate_from_code_and_grant_has_only_one_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            argv = self.exercise(root, (-2147483648, -2147483648), -4294967296)
            self.assertEqual(argv[argv.index("-c")+1:], [b"# approved bytes", "-2147483648", "-2147483648"])
            self.assertEqual((root / "result.json").read_bytes(), b'{"total":-4294967296}')
            self.assertFalse(os.path.lexists(root / "forbidden.json"))

    def test_worker_cannot_choose_the_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError):
                self.exercise(root, (8, 13), 3)
            self.assertFalse(os.path.lexists(root / "result.json"))

    def test_without_operands_the_approved_code_gets_no_extra_arguments(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            argv = self.exercise(root, None, 3)
            self.assertEqual(argv[argv.index("-c")+1:], [b"# approved bytes"])
            self.assertEqual((root / "result.json").read_bytes(), b'{"total":3}')
