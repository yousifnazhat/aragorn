"""One existing argv assertion affected by the newly explicit device masks."""

import unittest
import test_pi_core_confined_launch as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([cases.ConfinedPlanTests(
        "test_plan_argv_is_fixed_confined_and_not_an_execution_claim")])
