"""Only the corrected exception assertion; retain the other 25 prior passes."""

import unittest

from tests import test_pi_core_provider_start as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([cases.ProviderStartContractTests(
        "test_enabled_route_pin_is_exact_digest_not_truthy_opt_in")])
