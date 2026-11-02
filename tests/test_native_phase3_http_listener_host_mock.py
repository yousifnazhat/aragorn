"""Only the three macOS mock-boundary repairs; five unchanged checks retained."""

import unittest
from test_native_phase3_http_broker_ready_capture import BrokerReadyCaptureTests


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(BrokerReadyCaptureTests(name) for name in (
        "test_body_failure_and_partial_observation_survive_cleanup_failure",
        "test_existing_claim_refuses_before_any_child_or_socket",
        "test_success_is_not_published_until_context_and_handles_close",
    ))
