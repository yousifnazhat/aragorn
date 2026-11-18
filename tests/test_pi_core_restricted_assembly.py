"""Consume the independently approved reproduction; never invoke a builder or a target."""
import json
import unittest

from scripts import prepare_pi_core_restricted_runtime as stage


class RestrictedAssemblyCheck(unittest.TestCase):
    def test_assemble_original_gate_node_and_module_metadata_only(self):
        outcome = stage.assemble()
        self.assertEqual(outcome["status"], "ASSEMBLED_NOT_DEPLOYED_OR_OS_QUALIFIED")
        self.assertEqual(outcome["source_worker"], str(stage.ORIGINAL / "entrypoint.js"))
        self.assertIs(outcome["installed"], False)
        self.assertEqual(stage.audit._json(stage.read(stage.ROOT / stage.ASSEMBLY / "outcome.json")), outcome)
        print(json.dumps(outcome, sort_keys=True), flush=True)
