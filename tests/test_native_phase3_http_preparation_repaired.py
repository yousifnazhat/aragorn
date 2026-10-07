"""Only preparation paths affected by the HTTP directory/import repair.

The exact-renderer check passed under the retained first-run fingerprint and is
intentionally excluded. Negative cases now establish a valid baseline first.
"""

import unittest

from tests import test_native_phase3_http_preparation as cases


def load_tests(loader, tests, pattern):
    names = loader.getTestCaseNames(cases.HttpPreparationTests)
    selected = [
        name
        for name in names
        if name != "test_renderer_is_exact_pinned_and_does_not_modify_predecessors"
    ]
    if len(selected) != 14:
        raise ValueError("HTTP preparation repair test inventory changed")
    return unittest.TestSuite(cases.HttpPreparationTests(name) for name in selected)
