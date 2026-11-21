"""Offline consistency checks on inert spent-lease, measured-action and DONE records."""
from unittest import TestCase, TestSuite
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_action_evidence as evidence
from tests import test_pi_core_pilot_action_replay as pilot


class SpentLeaseReplayTests(TestCase):
    def check_mismatch(self, field, reason):
        fixture = pilot.PilotActionReplay()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        make_receipt = evidence.NativeActionEvidenceTests.set_receipt
        other = canonical_digest("a different action in the inert fixture")

        def mismatched_receipt(source, outcome):
            # Change the donor's in-memory records before its normal encoding,
            # readback and indexing. No production parser/verifier is mocked.
            claim = source.claim
            lease, profile = claim["lease"], claim["profile_claim"]
            pending = profile["profile_pending"]
            if field == "envelope_digest":
                pending[field] = profile[field] = other
            elif field in ("path_digest", "payload_digest"):
                pending["measured_action"][field] = lease[field] = other
                profile["measured_action_digest"] = canonical_digest(pending["measured_action"])
            elif field == "policy_version":
                lease[field] = source.grant[field] + 1
            elif field == "expires_at_unix":
                lease[field] += 1
            elif field == "issued_at_unix":
                lease[field] = source.envelope["request"][field] - 1
            else:
                self.assertEqual(field, "sensor_digest")
                lease[field] = other
            profile["lease_digest"] = claim["lease_digest"] = canonical_digest(lease)
            make_receipt(source, outcome)

        with patch.object(evidence.NativeActionEvidenceTests, "set_receipt", mismatched_receipt):
            fixture.original()
        nomination = fixture.nomination()
        with self.assertRaisesRegex(ValueError, reason):
            fixture.replay(nomination)

    def test_spent_claim_must_name_the_terminal_envelope(self):
        self.check_mismatch("envelope_digest", "ACTION_TERMINAL_CLAIM")

    def test_measured_action_must_match_the_terminal_request(self):
        for field in ("path_digest", "payload_digest"):
            with self.subTest(field=field):
                self.check_mismatch(field, "ACTION_TERMINAL_MEASURED_REQUEST")

    def test_spent_lease_must_match_the_grant(self):
        for field in ("sensor_digest", "policy_version"):
            with self.subTest(field=field):
                self.check_mismatch(field, "ACTION_TERMINAL_LEASE_GRANT")

    def test_lease_window_must_fit_the_original_request_and_grant(self):
        for field in ("issued_at_unix", "expires_at_unix"):
            with self.subTest(field=field):
                self.check_mismatch(field, "ACTION_TERMINAL_LEASE_WINDOW")


def load_tests(loader, tests, pattern):
    return TestSuite((loader.loadTestsFromTestCase(SpentLeaseReplayTests),
                      pilot.PilotActionReplay("test_terminal_create_and_effective_block_stay_recorded_not_physical")))
