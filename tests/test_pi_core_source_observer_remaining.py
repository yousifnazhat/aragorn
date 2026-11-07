"""Only the 31 failed or unrun observer cases after Linux-status fixture repair.

The first fingerprint retains 23 passing cases; no production source changed.
The coordinator checkpoint records both runs. Never load the entire prior suite.
"""

import unittest
from tests import test_pi_core_source_observer as cases


_CASES = (
    "SourceAcquisitionTests.test_challenge_acquires_fresh_interrupt_wait",
    "SourceAcquisitionTests.test_challenge_cannot_reuse_any_historical_nonce",
    "SourceAcquisitionTests.test_equal_but_replaced_plan_is_refused",
    "SourceAcquisitionTests.test_health_guard_joins_real_local_custody_and_acquisition",
    "SourceAcquisitionTests.test_health_guard_missing_coverage_never_challenges",
    "SourceAcquisitionTests.test_health_guard_rejects_unowned_activation_bytes",
    "SourceAcquisitionTests.test_initial_stop_is_acquired_not_assumed",
    "SourceAcquisitionTests.test_initial_wrong_stop_refused",
    "SourceAcquisitionTests.test_io_uring_is_refused",
    "SourceAcquisitionTests.test_missing_exec_exit_refuses_next_entry",
    "SourceAcquisitionTests.test_noninventory_descriptor_refused",
    "SourceAcquisitionTests.test_original_pidfd_substitution_is_refused",
    "SourceAcquisitionTests.test_owned_cleanup_does_not_close_live_tracee_handles",
    "SourceAcquisitionTests.test_partial_ranges_must_cover_all_bytes",
    "SourceAcquisitionTests.test_pread_completes_exact_source_range",
    "SourceAcquisitionTests.test_preexec_other_syscall_refused",
    "SourceAcquisitionTests.test_read_offset_race_refused",
    "SourceAcquisitionTests.test_read_result_beyond_requested_count_refused",
    "SourceAcquisitionTests.test_read_uses_held_open_description_offset",
    "SourceAcquisitionTests.test_thread_inventory_expansion_refused",
    "SourceAcquisitionTests.test_unclassified_aio_is_refused",
    "SourceAcquisitionTests.test_unexpected_exec_without_entry_refused",
    "SourceAcquisitionTests.test_withdrawn_bundle_lease_refuses_before_kernel_access",
    "SourceAcquisitionTests.test_withdrawn_launch_lease_refuses_before_kernel_access",
    "SourcePrimitiveTests.test_closed_or_foreign_owner_custody_refused",
    "SourcePrimitiveTests.test_fifo_leaf_is_nonblocking_and_closed_without_read",
    "SourcePrimitiveTests.test_hash_changed_identity_is_refused",
    "SourcePrimitiveTests.test_hash_uses_pread_without_shared_offset_changes",
    "SourcePrimitiveTests.test_kernel_entry_and_exit_abi_sizes_are_exact",
    "SourcePrimitiveTests.test_kernel_wrong_architecture_refused",
    "SourcePrimitiveTests.test_metadata_refuses_writable_or_nonroot_or_hardlinked_sources",
)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for name in _CASES:
        owner, method = name.split(".")
        suite.addTest(getattr(cases, owner)(method))
    return suite

