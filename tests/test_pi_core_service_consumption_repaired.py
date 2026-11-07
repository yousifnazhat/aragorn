"""Only the corrected legacy-image refusal assertion; other 41 checks retained.

The first stage's error was a mock-only assertion on a plain fixture function.
No implementation changed. Its other successful cases are not rescheduled.
"""

import unittest
from tests import test_pi_core_service_consumption as previous


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([previous.LifecycleSourceTests(
        "test_legacy_image_refuses_before_any_service_start")])


if __name__ == "__main__":
    unittest.main()
