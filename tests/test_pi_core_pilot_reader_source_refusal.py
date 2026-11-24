"""Target the changed source-custody fixture without replaying native handoffs."""
from unittest import TestSuite

from tests import test_pi_core_pilot_output_caller as caller


def load_tests(loader, tests, pattern):
    return TestSuite([caller.PilotCallerTests(
        "test_mismatched_or_unconsumed_source_never_acquires_credentials_or_starts")])
