"""Only the managed measurement receipt integration and affected expectations; no broad suite."""
import unittest

from tests import test_pi_core_phase3_qualification as managed


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(managed.PiCorePhase3QualificationTests(name) for name in (
        'test_complete_synthetic_contract_composes_without_claiming_other_profiles',
        'test_touching_attempt_and_pair_boundaries_are_serialized',
        'test_original_receipts_refuse_reverse_schedule_even_when_intervals_are_disjoint',
        'test_outer_chronology_uses_shared_checked_pin_after_caller_map_mutation',
        'test_missing_original_receipt_collection_refuses_before_any_receipt_callback',
        'test_unapproved_collection_authority_refuses_before_receipt_callbacks',
        'test_even_resealed_passing_aggregate_must_equal_the_original_receipt_measurements',
        'test_failed_prerequisite_skips_receipt_reads_and_yields_no_receipt_finding',
        'test_independently_selected_receipt_verifier_and_source_pins_are_not_exchangeable',
        'test_resealed_receipt_collection_for_another_schedule_or_collector_refuses',
    ))
