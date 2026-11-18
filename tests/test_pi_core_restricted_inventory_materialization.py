"""Prepare retained intent once; never open a worker/observer view or run a target."""
import json
from pathlib import Path
import unittest

from aragorn import pi_core_source_inventory_prepare as installed
from aragorn.oci_worker_protocol import canonical_json
from scripts import prepare_pi_core_restricted_runtime as storage
from scripts import prepare_pi_core_restricted_worker_inventory as worker


class RetainedInventoryPreparation(unittest.TestCase):
    def test_release_bound_host_rows_and_exact_consumer_bytes(self):
        root = Path(__file__).resolve().parents[1]
        work = storage.fresh(root, storage.BASE / "restricted-inventory-b37")
        try:
            rows, raw = worker.prepare_worker_inventory(root=root)
            host = canonical_json(rows)
            host_pin = "sha256:" + storage.sha(host)
            plan_pin = "sha256:" + storage.sha(raw)
            checkpoint = json.loads(storage.read(root / "packaging/pi-core/restricted-inventory-checkpoint-v1.json"))
            self.assertEqual(checkpoint["schema"], "aragorn/pi-core-restricted-inventory-checkpoint/v1")
            self.assertEqual(checkpoint["runtime_digest"], worker.fixed.RUNTIME_DIGEST)
            self.assertEqual(checkpoint["host_file_rows_digest"], host_pin)
            self.assertEqual(checkpoint["source_plan_digest"], plan_pin)
            plan = installed._plan(raw, checkpoint["source_plan_digest"])
            self.assertEqual(len(rows), checkpoint["host_files"])
            host_pins = {r["path"]: r["digest"] for r in rows}
            self.assertEqual(checkpoint["wrapper_digest"], host_pins["/opt/aragorn/bin/coordinator.py"])
            for name, key in (("pi_core_source_observer", "producer_digest"),
                              ("pi_core_node_source_observer", "node_observer_digest")):
                self.assertEqual(plan["pins"][key], host_pins["/opt/aragorn/src/aragorn/" + name + ".py"])
            self.assertEqual(len(plan["loader_files"]), checkpoint["worker_loader_paths"])
            self.assertEqual(plan["required_sources"], ["/opt/aragorn/pi-runtime/pi-core/entrypoint.js"])
            # The installed reader requires canonical JSON without a trailing newline.
            for name, data in (("host-source-files.json", host), ("worker-source-plan.json", raw)):
                storage.write(work / name, data)
                self.assertEqual(storage.read(work / name), data)
            outcome = {"schema": "aragorn/pi-core-retained-inventory-preparation/v1",
                       "status": "SOURCE_PINS_AND_WORKER_INTENT_PREPARED_NOT_INSTALLED",
                       "host_file_rows_digest": host_pin, "source_plan_digest": plan_pin,
                       "runtime_digest": worker.fixed.RUNTIME_DIGEST, "host_profile_approved": False,
                       "installed_view_observed": False, "target_executed": False,
                       "phase3_exit_eligible": False}
            storage.record(work / "outcome.json", outcome)
            print(json.dumps(outcome, sort_keys=True), flush=True)
        except Exception as error:
            storage.record(work / "refusal.json", {"reason": str(error)[:4096], "target_executed": False})
            raise
