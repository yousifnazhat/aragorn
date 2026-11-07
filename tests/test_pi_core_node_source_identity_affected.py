"""Only new/affected open-description identity cases after the initial pass."""

import unittest

from tests import test_pi_core_node_source_observer as cases


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(cases.NodeAcquisitionTests(name) for name in (
        "test_internal_anon_inode_alias_uses_exact_held_description",
        "test_same_anon_inode_without_description_match_is_refused",
        "test_kcmp_uses_two_held_fds_in_same_tracer_process",
        "test_kcmp_requires_stopped_tasks_and_retained_descriptors",
        "test_kcmp_failure_is_not_a_metadata_fallback",
        "test_internal_created_pipe_objects_remain_held",
        "test_unknown_pipe_input_refused",
        "test_ambiguous_temporary_close_retains_custody_and_disables_retry",
        "test_successful_temporary_close_drops_record_only_after_close",
        "test_successful_source_read_completes_required_delivery",
    ))
