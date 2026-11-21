"""Private file fixtures only: join original-format replies, protected plan, and independent archive."""
from contextlib import redirect_stderr
from io import StringIO
import unittest
from uuid import UUID

from scripts.verify_pi_core_joined_sensor_state import main
import test_pi_core_sensor_state_evidence as archives


def prepare(*, plan_id="filesystem_uuid", observed_id="filesystem_uuid"):
    def select(section, view, volume):
        if plan_id is not None:
            section["filesystem_uuid"] = volume[plan_id]
        if observed_id is not None:
            raw = (bytes([16]) + UUID(volume[observed_id]).bytes).hex()
            view.update(schema="aragorn/pi-core-sensor-state-view/v2",
                        filesystem_uuid_observation={"before": raw, "after": raw})
    return select


class SensorFilesystemUUIDReplay(unittest.TestCase):
    def fixture(self, select=None):
        archive = archives._JoinedSensorFixture()
        self.addCleanup(archive.doCleanups)
        archive.setUp(prepare_observation=select)
        return archive

    def test_plan_archive_and_both_observations_match_without_promoting_physical_identity(self):
        report = self.fixture(prepare()).check(require_filesystem_uuid=True)
        self.assertIs(report["state_filesystem_uuid_matched"], True)
        for name in ("physical_asset_verified", "external_freshness_verified", "sensor_health_verified",
                     "phase3_exit_eligible"):
            self.assertIs(report[name], False)

    def test_original_view_replays_but_does_not_report_a_measured_filesystem_uuid(self):
        self.assertIs(self.fixture().check()["state_filesystem_uuid_matched"], False)

    def test_cli_can_require_measured_uuid_and_refuse_historical_archive(self):
        params = self.fixture().replay_args()
        params["archive"] = params["archive"].root
        flags = [s for name, value in params.items() for s in ("--" + name.replace("_", "-"), str(value))]
        with redirect_stderr(StringIO()) as errors:
            self.assertEqual(main([*flags, "--require-filesystem-uuid"]), 2)
        self.assertIn("filesystem UUID observation required", errors.getvalue())

    def test_declared_plan_cannot_downgrade_and_undeclared_observation_cannot_upgrade(self):
        for args in (dict(observed_id=None), dict(plan_id=None)):
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, "plan and sensor view version"):
                self.fixture(prepare(**args)).check()

    def test_local_plan_and_raw_agreement_do_not_replace_independent_filesystem_pin(self):
        # Both other records agree on the same nonzero UUID but for a different
        # identity category. The external volume record is independently pinned.
        with self.assertRaisesRegex(ValueError, "filesystem UUID differs from independent admission"):
            self.fixture(prepare(plan_id="encryption_uuid", observed_id="encryption_uuid")).check()

    def test_plan_and_archive_agreement_do_not_replace_the_original_raw_replies(self):
        with self.assertRaises(ValueError):
            self.fixture(prepare(observed_id="encryption_uuid")).check()
