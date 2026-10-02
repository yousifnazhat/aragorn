"""First acceptance of the new opt-in staging/rendering path, never activation."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from aragorn import runtime_broker_decision_measurement as measurement
from scripts import materialize_runtime_broker_decision_measurement as renderer
from scripts import stage_runtime_broker_decision_measurement_profile as stage


class BrokerDecisionMeasurementProfileTests(unittest.TestCase):
    def test_new_profile_stages_pinned_boundaries_without_changing_predecessor(self):
        sources_before = {
            name: (renderer._ROOT / name).read_bytes()
            for name in (renderer._CORE, renderer._GRANT, renderer._SERVICE)
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "measured-profile"
            report = stage.stage_runtime_broker_decision_measurement_profile(output)
            self.assertEqual(report["schema"], stage._SCHEMA)
            self.assertEqual(len(report["files"]), 73)
            self.assertEqual(set(report["binding_source_pins"]), measurement._SOURCES)
            for key in (
                "decision_measurement_deployed",
                "measurement_binding_provisioned",
                "measurement_collected",
                "phase3_qualification",
                "run_qualification",
            ):
                self.assertIs(report[key], False)
            rendered = {}
            for name in renderer._INPUTS:
                destination, _ = renderer.predecessor._destination(name)
                raw = (output / destination).read_bytes()
                self.assertEqual(
                    (len(raw), renderer.base.overlay._digest(raw)),
                    renderer._OUTPUTS[name],
                )
                rendered[name] = raw
            for name in (
                renderer._CORE,
                renderer._GRANT,
                renderer._SERVICE,
                renderer._HELPER,
            ):
                destination, _ = renderer.predecessor._destination(name)
                compile((output / destination).read_bytes(), destination, "exec")
            for name in (renderer._BASE_ACTIVATOR, renderer._ACTIVATOR):
                destination, _ = renderer.predecessor._destination(name)
                checked = subprocess.run(
                    ["/bin/sh", "-n", str(output / destination)],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(checked.returncode, 0, checked.stderr.decode())
            core = rendered[renderer._CORE].decode("ascii")
            self.assertIn("authorize_link=measured_authorize_link,", core)
            wrapper = core.split("        def measured_authorize_link()", 1)[1].split(
                "        def record_pending(", 1
            )[0]
            self.assertLess(
                wrapper.index("allowed = authorize_link()"),
                wrapper.index("_measurement.final_decision("),
            )
            self.assertLess(
                wrapper.index("_measurement.final_decision("),
                wrapper.index("return allowed"),
            )
            grant = (
                rendered[renderer._GRANT]
                .decode("ascii")
                .split("def mediate_granted_profiled_runtime_create(", 1)[1]
                .split("def recover_runtime_capability_grant(", 1)[0]
            )
            self.assertLess(
                grant.index("_issued_submission("), grant.index("_measurement.begin(")
            )
            self.assertLess(
                grant.index("_measurement.begin("), grant.index("_claim_grant(")
            )
            self.assertLess(
                grant.index("_consume_grant("), grant.index("_measurement.retain(")
            )
            self.assertIn("finally:\n        _measurement.close(measurement)", grant)
            unit = rendered[renderer._UNIT].decode("ascii")
            self.assertIn("ProcSubset=pid\n", unit)
            self.assertNotIn("ProcSubset=all", unit)
            self.assertIn(
                "BindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/aragorn-broker-boot-id\n",
                unit,
            )
            self.assertIn(
                "LoadCredential=decision-measurement-binding:/etc/aragorn/runtime-broker-decision-measurement.json\n",
                unit,
            )
            self.assertIn(" %d/decision-measurement-binding\n", unit)
        self.assertEqual(
            sources_before,
            {name: (renderer._ROOT / name).read_bytes() for name in sources_before},
        )


if __name__ == "__main__":
    unittest.main()
