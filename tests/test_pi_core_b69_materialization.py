"""One absent-only B69 staging run. Does not build boot media, mount or execute guest code."""
import json
import unittest

from scripts import prepare_pi_core_b69_payload as batch


class ManagedPayloadPreparation(unittest.TestCase):
    def test_publish_verified_joint_host_and_service_inputs_once(self):
        result = batch.prepare()
        section = result["service_runtime"]
        self.assertEqual(section, dict(deployment_path=batch.prior.DEPLOY,
            receipt_digest="sha256:" + result["layout_receipt_sha256"],
            manifest=dict(path=batch._M, digest="sha256:" + result["manifest_sha256"]),
            runtime_binding=dict(path=batch._B, digest="sha256:" + result["binding_sha256"])))
        self.assertFalse(any(result[k] for k in ("image_assembled", "installed_identity_verified",
                                                 "activation_performed", "phase3_exit_eligible")))
        print(json.dumps(result, sort_keys=True), flush=True)
