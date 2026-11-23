"""Check the retained offline inputs without preparing or starting a deployment."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from scripts import verify_pi_core_b105_evidence_inputs as subject


class B105EvidenceInputs(TestCase):
    def test_retained_inputs_are_pinned_without_nominating_a_pilot(self):
        evidence = subject.verify_evidence_inputs()
        self.assertEqual(evidence["schema"], "aragorn/pi-core-b105-evidence-inputs/v1")
        self.assertEqual(evidence["authority"], "OFFLINE_INPUT_PINS_ONLY_NOT_DEPLOYMENT_OR_PILOT_AUTHORITY")
        self.assertEqual(set(evidence["protected_inventories"]), {
            "coordinator-host.json", "manifest.json", "runtime-binding.json", "service-runtime-receipt.json",
        })
        for field in ("deployment_digest", "action_nomination_pin", "context_pin", "owner_pin", "plan_pin",
                      "policy_manifest_digest", "pilot_approval"):
            self.assertIsNone(evidence["held_nominations"][field])
        self.assertIs(evidence["activation_authorized"], False)
        self.assertIs(evidence["phase3_exit_eligible"], False)

    def test_foreign_payload_bytes_are_not_accepted_as_the_successor(self):
        with TemporaryDirectory(dir=Path.home().resolve()) as directory:
            payload = Path(directory)
            for name in ("payload.json", "outcome.json"):
                (payload / name).write_bytes(b"{}\n")
            with self.assertRaisesRegex((ValueError, RuntimeError), "digest differs"):
                subject.verify_evidence_inputs(payload_dir=payload)
