"""Load the actual pinned service definitions; never call or activate a service."""

import importlib
import json
from pathlib import Path
import unittest
from unittest import mock

from tests import test_pi_core_service_source as fixture


class ServiceSourceIntegrationTests(fixture.PiServiceSourceTests):
    def test_actual_service_entry_imports_through_the_verified_loader(self):
        root = Path(__file__).resolve().parents[1]
        record = json.loads((root / "packaging/pi-core/service-assembly-inputs-v3.json").read_bytes())
        self.sources = {name: (root / "src" / name).read_bytes()
                        for name in record["expected_source_inventory"]}
        self.assertEqual({name: fixture.digest(raw) for name, raw in self.sources.items()},
                         record["expected_source_inventory"])
        with mock.patch("subprocess.Popen", side_effect=AssertionError("no process")), \
             mock.patch("subprocess.run", side_effect=AssertionError("no process")), \
             mock.patch("socket.socket", side_effect=AssertionError("no socket")), \
             mock.patch("os.system", side_effect=AssertionError("no command")):
            self.install()
            entry = importlib.import_module("aragorn.pi_core_service_entry")
            self.assertTrue(callable(entry.main))
            rows = self.loader.snapshot()
            names = {row["module"] for row in rows}
            self.assertTrue({"aragorn", "aragorn.pi_core_service_entry", "aragorn.pi_core_request_service",
                "aragorn.pi_core_provider_service", "aragorn.pi_core_request_sensor"} <= names)
            self.assertEqual(len(rows), len(names))
            for row in rows:
                self.assertEqual(row["digest"], record["expected_source_inventory"][row["path"][len(fixture._PREFIX):]])


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([ServiceSourceIntegrationTests(
        "test_actual_service_entry_imports_through_the_verified_loader")])


if __name__ == "__main__":
    unittest.main()
