from __future__ import annotations

import json
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn.admission_routes import (
    OPENCLAW_2026_7_1_PHASE1_BLOCKING_ROUTE_IDS,
    AdmissionRouteInventoryError,
    build_openclaw_2026_7_1_route_probe_scaffold,
    validate_openclaw_2026_7_1_route_probe_scaffold,
)
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_INVENTORY = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "update-reload-route-inventory-v1.json"
)
_CANDIDATES = _ROOT / "benchmark" / "admission-runtime-candidates-v1.lock.json"
_COVERAGE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "openclaw-v2026.7.1-update-reload-route-coverage-v3-2026-07-28.json"
)


class AdmissionRouteProbeScaffoldTests(unittest.TestCase):
    def test_selector_is_inventory_driven_and_cannot_claim_execution(self) -> None:
        inventory = json.loads(_INVENTORY.read_bytes())
        candidates = json.loads(_CANDIDATES.read_bytes())
        coverage = json.loads(_COVERAGE.read_bytes())
        scaffold = build_openclaw_2026_7_1_route_probe_scaffold(
            inventory,
            candidates,
        )

        expected_ids = [
            route["id"] for route in coverage["routes"] if route["status"] != "PASS"
        ]
        self.assertEqual(
            list(OPENCLAW_2026_7_1_PHASE1_BLOCKING_ROUTE_IDS),
            expected_ids,
        )
        self.assertEqual(
            [route["id"] for route in scaffold["routes"]],
            expected_ids,
        )
        self.assertTrue(
            all(
                route["status"] == "NOT_TESTED"
                and route["evidence_digests"] == []
                and route["reason_codes"] == ["ROUTE_EXECUTION_NOT_RECORDED"]
                for route in scaffold["routes"]
            )
        )
        self.assertEqual(
            scaffold["decision"],
            {
                "installer_work_eligible": False,
                "runtime_executed": False,
                "status": "NOT_TESTED",
            },
        )
        validate_openclaw_2026_7_1_route_probe_scaffold(
            scaffold,
            inventory,
            candidates,
        )

        forged = deepcopy(scaffold)
        forged["routes"][0]["status"] = "PASS"
        forged["decision"]["runtime_executed"] = True
        with self.assertRaises(AdmissionRouteInventoryError):
            validate_openclaw_2026_7_1_route_probe_scaffold(
                forged,
                inventory,
                candidates,
            )

        selected_id = expected_ids[0]
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "aragorn.admission_routes",
                "--inventory",
                str(_INVENTORY),
                "--runtime-candidates",
                str(_CANDIDATES),
                "--route-id",
                selected_id,
            ],
            capture_output=True,
            check=False,
            cwd=_ROOT,
            timeout=5,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        selected = json.loads(completed.stdout)
        self.assertEqual(completed.stdout, canonical_json(selected) + b"\n")
        self.assertEqual([route["id"] for route in selected["routes"]], [selected_id])
        validate_openclaw_2026_7_1_route_probe_scaffold(
            selected,
            inventory,
            candidates,
            route_ids=[selected_id],
        )

        with self.assertRaises(AdmissionRouteInventoryError):
            build_openclaw_2026_7_1_route_probe_scaffold(
                inventory,
                candidates,
                route_ids=["ADM-02/update/config-entry-activation"],
            )


if __name__ == "__main__":
    unittest.main()
