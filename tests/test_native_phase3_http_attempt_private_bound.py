"""Rerun only the staged-semantic join affected by original-source pin repair."""

import unittest

from test_native_phase3_http_attempt_private_dependencies import (
    HttpAttemptPrivateDependencyTests,
)


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([
        HttpAttemptPrivateDependencyTests(
            "test_staged_semantics_and_late_imports_leave_frozen_globals_unchanged"
        )
    ])
