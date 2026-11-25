"""Inert B110 originals; the named guest plan path is never opened."""
import json
from pathlib import Path
from unittest import TestCase

from aragorn import pi_core_pilot_retention_entry as release
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import verify_pi_core_b109_retained_output as verifier
from tests import test_pi_core_b109_retained_output as private, test_pi_core_coordinator_entry as coordinator


REVIEW = Path(__file__).resolve().parents[1] / "packaging/pi-core/managed-payload-b111.json"


class PlannedOutput(TestCase):
    def replay(self, field=None):
        def plan_for(action, descriptor, deployment):
            plan, _ = coordinator.prepared(True)
            pins = json.loads(REVIEW.read_bytes())
            plan["host_profile_digest"] = "sha256:" + pins["host_profile_sha256"]
            plan["deployment"]["digest"] = deployment
            plan["context"]["digest"] = action.activation["install_context_digest"]
            plan["pilot_output"] = dict(path_descriptor=descriptor,
                reader_source_digest="sha256:" + release._B109["pi_core_pilot_output_observer"])
            runtime = plan["service_runtime"]
            runtime["manifest"]["digest"], runtime["runtime_binding"]["digest"], runtime["receipt_digest"] = release._SERVICE
            if field == "context":
                plan["context"]["digest"] = canonical_digest("other install")
            elif field == "host":
                plan["host_profile_digest"] = release.sink.B109_HOST_PROFILE_DIGEST
            elif field == "path":
                plan["pilot_output"]["path_descriptor"] = descriptor | {"root_inode": descriptor["root_inode"] + 1}
            return action.put(canonical_json(plan))

        donor = private.B109RetainedOutput
        self.addCleanup(donor.doClassCleanups)
        alias = "sha256:" + json.loads(REVIEW.read_bytes())["host_profile_sha256"] if field == "release" else None
        donor.setUpClass(plan_for=plan_for, release_pin=alias)
        return verifier.verify_retained_output(**donor.args, b111_plan_path="/never-opened/approved.json")

    def test_actual_replay_binds_reviewed_plan_to_original_observation(self):
        report = self.replay()
        self.assertTrue(report["recorded_b111_plan_matched"])
        self.assertEqual(report["schema"], "aragorn/pi-core-b111-planned-output-finding/v1")
        for name in ("installed_identity_verified", "release_authority_verified", "effect_verified", "phase3_qualified"):
            self.assertFalse(report[name])

    def test_receipt_for_a_different_install_context_refuses(self):
        with self.assertRaisesRegex(ValueError, "INSTALL_CONTEXT"):
            self.replay("context")

    def test_predecessor_host_profile_refuses_even_when_receipt_agrees(self):
        with self.assertRaisesRegex((ValueError, RuntimeError), "PLAN_BINDING"):
            self.replay("host")

    def test_matching_receipt_cannot_substitute_another_output_directory(self):
        with self.assertRaisesRegex(ValueError, "PLAN_OUTPUT"):
            self.replay("path")

    def test_host_identity_cannot_also_be_the_nominated_release(self):
        with self.assertRaisesRegex(ValueError, "RELEASE_ALIAS"):
            self.replay("release")
