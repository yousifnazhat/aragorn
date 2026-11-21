"""Two install comparisons affected by the new exact wrapper pin."""
import unittest

import test_pi_core_installed_bundle_readback as original


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(original.InstalledReadback(name) for name in (
        "test_actual_wrapper_stdout_and_approved_bytes_give_only_a_reported_materialization_match",
        "test_resealed_v2_report_and_matching_source_rows_cannot_upgrade_a_real_v1_wrapper_or_old_installer",
    ))
