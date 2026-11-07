"""Only new/affected eventfd birth joins after the initial 60 replay passes."""

import unittest

from tests import test_pi_core_node_source_replay as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(cases.NodeReplayTests(name) for name in (
        "test_distinct_eventfd_births_can_share_anon_inode_identity",
        "test_aliased_eventfd_identity_cannot_supply_an_unrecorded_birth",
        "test_created_eventfd_has_independent_syscall_and_identity_join",
        "test_eventfd_input_cannot_invent_creation_origin",
        "test_eventfd_creation_cannot_substitute_output_descriptor",
    ))
