"""Only the two corrected first-run assertions; retain the other13 successes."""

import unittest

import test_runtime_phase3_http_ready_profile as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(
        [
            cases.HttpReadyActivationGuardTests(
                "test_nonce_binding_and_noncanonical_input_each_refuse"
            ),
            cases.HttpReadyProfileTests(
                "test_both_activators_check_readiness_before_mutation_and_pin_current_sources"
            ),
        ]
    )
