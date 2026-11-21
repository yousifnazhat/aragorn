"""Exclusive physical preparation; no target code is executed and no real configuration is issued."""
import json
import unittest

from scripts import prepare_pi_core_service_successor as batch


class ServicePreparation(unittest.TestCase):
    def test_emit_full_image_inputs_and_consumer_section_once(self):
        result = batch.prepare()
        self.assertEqual((result["entries"], result["service_files"], result["carried_service_files"]), (1760, 791, 685))
        self.assertFalse(any(result[k] for k in ("installed_identity_verified", "activation_performed",
                                                 "image_assembled", "phase3_exit_eligible")))
        section = result["service_runtime"]
        self.assertEqual(set(section), {"deployment_path","receipt_digest","manifest","runtime_binding"})
        self.assertEqual(section["receipt_digest"], "sha256:" + result["layout_receipt_sha256"])
        for key, pin in (("manifest","manifest_sha256"), ("runtime_binding","binding_sha256")):
            self.assertEqual(section[key]["digest"], "sha256:" + result[pin])
        print(json.dumps(result, sort_keys=True), flush=True)
