"""One operator-scheduled full B112 disk readback; never boot or call the builder."""
import json
import unittest

from scripts import verify_pi_core_b112_media as subject


class TestB112OfflineReadback(unittest.TestCase):
    def test_candidate_disk_matches_complete_b111_over_b41_inventory(self):
        result = subject.verify()
        self.assertEqual((result['inventory_sha256'], result['inventory_entries']), (subject.LOGICAL, subject.ROWS))
        self.assertIs(result['phase3_exit_eligible'], False)
        self.assertIs(result['boot_observed'], False)
        self.assertIs(result['secure_boot_enrollment'], False)
        print(json.dumps(result, sort_keys=True))  # small finding retained by the reviewed stage
