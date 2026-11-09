"""Only one corrected fixture and 17 unreached checks; retain 21 prior passes."""

import unittest

from tests import test_pi_core_native_provider as cases


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(cases.NativeProviderOwnershipTests(name) for name in (
        "test_fixed_endpoint_is_absent_only_and_root_owned",
        "test_remote_hold_retains_namespace_and_never_retries_cleanup",
        "test_verified_cleanup_removes_only_owned_endpoint",
    ))
    suite.addTests(loader.loadTestsFromTestCase(cases.NativeProviderStartTests))
    return suite
