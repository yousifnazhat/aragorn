"""Check the bundled worker's first request without starting a process or creating a file."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, mock_open, patch


SOURCE = Path(__file__).resolve().parents[1] / "examples/local-quickstart/capability/worker.py"
spec = importlib.util.spec_from_file_location("sum_worker_fixture", SOURCE)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class RequestSent(Exception):
    pass


class SumWorkerTests(unittest.TestCase):
    def first_request(self, operands):
        output = io.StringIO()
        stdin = Mock()
        stdin.readline.side_effect = RequestSent
        with (
            patch.object(worker.sys, "argv", ["-c", *operands]),
            patch.object(worker.sys, "stdin", stdin),
            patch.object(worker.os, "geteuid", return_value=65534),
            patch.object(worker.os, "getegid", return_value=65534),
            patch.object(worker.os, "getgroups", return_value=[]),
            patch("builtins.open", mock_open(read_data="CapEff:\t00000000\n")),
            redirect_stdout(output),
        ):
            try:
                worker.main()
            except RequestSent:
                return json.loads(output.getvalue())
        self.fail("worker stopped without a request or an explicit refusal")

    def test_request_uses_wide_sum_and_retains_no_argument_default(self):
        for operands, expected in (([], 3), (["8", "13"], 21),
                                   (["-2147483648"] * 2, -4294967296),
                                   (["2147483647"] * 2, 4294967294)):
            with self.subTest(operands=operands):
                self.assertEqual(self.first_request(operands),
                                 {"op": "create", "target": "result.json", "value": {"total": expected}})

    def test_invalid_wire_operands_refused_before_request(self):
        for operands in (["1"], ["0", "0", "0"], ["-2147483649", "0"], ["2147483648", "0"],
                         ["1+2", "0"], ["００", "1"], ["03", "4"], ["-0", "1"]):
            with self.subTest(operands=operands), self.assertRaises(SystemExit):
                self.first_request(operands)
