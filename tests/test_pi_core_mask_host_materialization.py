"""One offline changed-payload preparation; no guest binaries, services or resources."""
import json
import unittest
from scripts import prepare_pi_core_mask_host_successor as batch


class MaskHostMaterialization(unittest.TestCase):
    def test_prepare_reviewed_successor_sources_and_worker_plan_without_rebuilding_media(self):
        result = batch.prepare()
        self.assertEqual((result["host_files"], result["changed_payload_files"]), (802, 12))
        self.assertFalse(any(result[k] for k in ("image_assembled", "installed_identity_verified",
                                                "phase3_exit_eligible")))
        print(json.dumps(result, sort_keys=True), flush=True)
