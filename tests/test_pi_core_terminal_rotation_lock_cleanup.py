"""Select only callback/role-lock behavior affected by the final review fix."""

import unittest

from tests.test_pi_core_terminal_rotation import TerminalRotationTests
from tests.test_pi_core_terminal_rotation_readback import TerminalRotationReadbackTests


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(TerminalRotationTests(name) for name in (
        "test_uncertain_retirement_and_lock_cleanup_keep_both_failures",
        "test_uncertain_consumption_and_lock_cleanup_keep_both_failures",
        "test_foreign_claim_bytes_refuse_before_any_archive",
        "test_effective_block_recovers_without_rewriting_allow_policy",
    ))
    suite.addTest(TerminalRotationReadbackTests("test_new_grant_readback_after_consumed_preserves_both_raw_archives"))
    return suite
