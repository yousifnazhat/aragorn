"""Only 20 cases blocked by the corrected macOS temporary-group fixture.

The 14 unchanged successful preflight/manifest cases are retained, not rerun.
"""

import unittest
import test_pi_core_os_provision as cases


def load_tests(loader, tests, pattern):
    selected = (
        "test_exact_closures_are_installed_and_receipt_is_canonical",
        "test_existing_destination_is_never_overwritten",
        "test_existing_destination_symlink_is_never_followed",
        "test_modes_are_protected_roots_and_immutable_descendants",
        "test_overlapping_source_and_destination_refuse",
        "test_partial_destination_cannot_be_automatically_retried",
        "test_receipt_creation_failure_preserves_completed_trees",
        "test_runtime_byte_mutation_rejects_compiled_receipt",
        "test_runtime_execution_bits_are_reduced_to_node_only",
        "test_runtime_extra_empty_directory_is_unbound_and_rejected",
        "test_runtime_node_must_start_executable",
        "test_source_ancestor_symlink_is_rejected",
        "test_source_changed_os_bytes_are_rejected",
        "test_source_extra_os_file_is_rejected",
        "test_source_fifo_is_rejected_without_opening",
        "test_source_hardlink_is_rejected",
        "test_source_missing_os_file_is_rejected",
        "test_source_symlink_is_rejected",
        "test_write_failure_retains_partial_tree_without_receipt",
        "test_wrong_compiled_pin_refuses_before_creation",
    )
    return unittest.TestSuite(cases.PiOsProvisionTests(name) for name in selected)
