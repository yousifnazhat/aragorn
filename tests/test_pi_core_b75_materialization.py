"""Run B75 absent-only, after independent review; this is not boot or activation."""
import json
import unittest

from scripts import prepare_pi_core_b75_payload as batch


class ManagedPayloadPreparation(unittest.TestCase):
    def test_publish_signed_b74_sources_in_one_retained_guest_layout(self):
        result = batch.prepare()
        self.assertEqual(
            result["service_runtime"],
            dict(deployment_path="/var/lib/aragorn/pi-service-runtime",
                 receipt_digest="sha256:" + result["layout_receipt_sha256"],
                 manifest=dict(path="/etc/aragorn/service-runtime-inputs/manifest.json",
                               digest="sha256:" + result["manifest_sha256"]),
                 runtime_binding=dict(path="/etc/aragorn/service-runtime-inputs/runtime-binding.json",
                                      digest="sha256:" + result["binding_sha256"])))
        self.assertEqual((result["b69_outcome_sha256"], result["b69_payload_sha256"]),
                         (batch.SPEC.base_outcome, batch.SPEC.base_payload))
        self.assertEqual(result["source_evidence"]["source_revision"], batch.SPEC.revision)
        self.assertFalse(any(result[k] for k in ("image_assembled", "installed_identity_verified",
                                                 "activation_performed", "phase3_exit_eligible")))
        print(json.dumps(result, sort_keys=True), flush=True)
