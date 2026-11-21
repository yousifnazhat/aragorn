"""Only the managed composition cases affected by the serial-measurement rule."""
import unittest

import test_pi_core_phase3_qualification as managed


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(managed.PiCorePhase3QualificationTests(name) for name in (
        "test_complete_synthetic_contract_composes_without_claiming_other_profiles",
        "test_baseline_first_is_enforced_on_actual_sample_intervals",
        "test_strict_500ms_boundary_reuses_numeric_rejection",
        "test_strict_ten_percent_overhead_boundary_reuses_numeric_rejection",
        "test_two_attempts_cannot_overlap_by_one_nanosecond",
        "test_task_cannot_overlap_the_last_attempt_by_one_nanosecond",
        "test_individually_baseline_first_pairs_cannot_overlap_each_other",
        "test_touching_attempt_and_pair_boundaries_are_serialized",
        "test_original_receipts_refuse_reverse_schedule_even_when_intervals_are_disjoint",
        "test_outer_chronology_uses_shared_checked_pin_after_caller_map_mutation",
    ))
