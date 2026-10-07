"""Only the corrected canonical HTTP binding size assertion is selected.

The complete 21-source binding need not exceed the predecessor's size limit;
the actual contract is nonempty canonical bytes bounded by 8192 bytes.
"""

import unittest

from tests import test_native_phase3_http_preparation as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(
        [
            cases.HttpPreparationTests(
                "test_http_measurement_input_binding_closes_over_twenty_one_sources"
            )
        ]
    )
