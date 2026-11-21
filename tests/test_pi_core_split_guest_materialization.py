"""One explicit offline materialization. No VM, mount, state volume or guest process."""
import json
import unittest

from scripts import prepare_pi_core_split_guest_payload as batch


class SplitGuestMaterialization(unittest.TestCase):
    def test_materialize_committed_full_payload_without_guest_operations(self):
        result = batch.prepare()
        self.assertFalse(any(result[k] for k in ("image_assembled", "installed_identity_verified", "phase3_exit_eligible")))
        self.assertEqual(result["payload_sha256"], json.loads(batch.REVIEW.read_bytes())["payload_sha256"])
        print(json.dumps(result, sort_keys=True), flush=True)
