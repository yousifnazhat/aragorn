"""One local offline payload materialization from reviewed inputs; no guest execution."""
import json
import unittest

from scripts import prepare_pi_core_b62_host_successor as batch


class ProtectedHostMaterialization(unittest.TestCase):
    def test_materialize_exact_cumulative_payload_once(self):
        result = batch.prepare()
        self.assertEqual((result["host_files"], result["changed_payload_files"]), (804, 15))
        self.assertFalse(any(result[k] for k in ("image_assembled", "installed_identity_verified",
                                                 "phase3_exit_eligible")))
        print(json.dumps(result, sort_keys=True), flush=True)
