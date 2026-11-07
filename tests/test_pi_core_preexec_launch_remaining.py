"""Only the two initial fixture-exception errors; 52 passes remain retained."""

import unittest

from tests import test_pi_core_preexec_launch as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(cases.SourceProfileTests(name) for name in (
        "test_missing_extra_or_bad_inventory_pins_are_refused",
        "test_profile_and_pin_are_required_together",
    ))
