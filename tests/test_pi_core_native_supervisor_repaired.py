"""Only the missing-Linux-constant fixture case; retain the other 55 passes."""

import unittest
import test_pi_core_native_supervisor as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([cases.NativeProtectedResourceTests(
        "test_socket_is_exclusive_descriptor_relative_and_exact_mode")])
