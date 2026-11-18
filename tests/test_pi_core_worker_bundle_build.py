"""The only real bundle-build stage: one original and one independent reproduction.

Outputs, partial directories and pipeline logs are retained, including on refusal.
This stage must not be discovered by a broad suite or used as a runtime test.
"""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts import build_pi_core_worker_bundle as builder
from scripts import verify_pi_core_worker_bundle as verifier


ROOT = Path(__file__).resolve().parents[1]


def retain(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")


class WorkerBundleBuildChecks(unittest.TestCase):
    def test_fresh_build_and_independent_reproduction_without_worker_execution(self):
        base = ROOT / ".aragorn/pi-core-build"
        self.assertEqual(base.resolve(strict=True), base, "linked bundle evidence directory")
        run = Path(tempfile.mkdtemp(prefix="d2-worker-bundle-", dir=base))
        first, second = run / "original", run / "reproduction"
        print(json.dumps({"worker_bundle_evidence": str(run)}), flush=True)
        reports = []
        try:
            for destination in (first, second):
                phase = destination.name + "-build"
                receipt = builder.build(destination, root=ROOT)
                phase = destination.name + "-inspection"
                self.assertEqual(json.loads(verifier._read(destination / "receipt.json")), receipt)
                # Refusal propagates immediately: do not reproduce a known-rejected original.
                inspection = verifier.verify_one(destination, root=ROOT)
                self.assertEqual(inspection["status"], "INSPECTED_NOT_DEPLOYED")
                self.assertIs(inspection["target_executed"], False)
                self.assertIs(inspection["phase3_exit_eligible"], False)
                retain(run / (phase + ".json"), inspection)
                reports.append(inspection)
            phase = "compare-and-recheck-original"
            self.assertFalse(first.samefile(second))
            self.assertEqual(reports[0], reports[1], "independent inspection results differ")
            pins = {name: record["sha256"] for name, record in reports[0]["outputs"].items()}
            pins["receipt.json"] = reports[0]["build_receipt_sha256"]
            self.assertEqual(set(pins), {"entrypoint.js", "meta.json", "receipt.json"})
            self.assertFalse(first.is_symlink())
            self.assertEqual({p.name for p in first.iterdir()}, set(pins))
            for name, pin in pins.items():
                path = first / name
                self.assertEqual(path.lstat().st_nlink, 1)
                self.assertEqual(hashlib.sha256(verifier._read(path)).hexdigest(), pin, name)
            retain(run / "verification.json", {**reports[0], "status": "REPRODUCED_NOT_DEPLOYED",
                                               "invocation_independence_attested_by_bytes": False})
        except Exception as refusal:
            retain(run / "inspection-refusal.json", {"phase": phase, "reason": str(refusal)[:32768],
                                                      "target_executed": False, "phase3_exit_eligible": False})
            raise
        print(json.dumps({"verified_bundle_evidence": str(run / "verification.json"),
                          "worker_sha256": pins["entrypoint.js"]}), flush=True)
