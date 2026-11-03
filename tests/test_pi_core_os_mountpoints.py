"""Only the changed OS mountpoint case; retain the other 23 original passes."""

import unittest
import test_pi_core_os_root as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([cases.PiCoreOSRootTests(
        "test_preparation_emits_regular_aliases_bound_inventory_and_licenses")])
