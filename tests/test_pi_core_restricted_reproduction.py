"""One independently emitted worker after passing retained-original and gate readback."""
import json
import unittest

from scripts import prepare_pi_core_restricted_runtime as stage


class RestrictedReproductionCheck(unittest.TestCase):
    def test_replay_original_then_emit_one_independent_copy(self):
        result, pin = stage.reproduce()
        self.assertEqual(result["status"], "REPRODUCED_RESTRICTED_NOT_DEPLOYED")
        self.assertFalse(result["target_executed"])
        self.assertEqual(stage.sha(stage.read(stage.ROOT / stage.REVIEW / "outcome.json")), pin)
        print(json.dumps({"reproduction_outcome":str(stage.REVIEW / "outcome.json"),
                          "outcome_sha256":pin, "outputs":result["products"]}), flush=True)
