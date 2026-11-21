"""Only the B81 replay paths affected by sharing the host/source custody check."""
import unittest

import test_pi_core_owned_socket_replay as b81


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(b81.OwnedSocketReplay(name) for name in (
        "test_verified_originals_report_only_manager_membership",
        "test_replaced_host_source_registration_refuses",
    ))
