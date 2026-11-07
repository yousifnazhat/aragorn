"""Only the repaired inert producer-to-replay handoff; 58 prior passes retained."""

import unittest
from tests import test_pi_core_source_observation_verify as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([cases.PiSourceObservationReplayTests(
        "test_inert_producer_capture_round_trips_through_cas_and_independent_replay"
    )])

