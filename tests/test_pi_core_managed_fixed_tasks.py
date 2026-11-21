"""Only the managed fixed-output receipt gate and directly affected integrations."""
import unittest

from tests import test_pi_core_phase3_qualification as managed


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(managed.PiCorePhase3QualificationTests(name) for name in (
        'test_complete_synthetic_contract_composes_without_claiming_other_profiles',
        'test_same_input_cannot_substitute_sha_for_the_scheduled_line_count',
        'test_resealed_wrong_sum_refuses_despite_generic_completion_and_unchanged_metrics',
        'test_copy_metadata_or_wrong_readback_result_cannot_stand_in_for_fixed_output',
        'test_missing_or_substituted_fixed_output_verifier_source_refuses',
        'test_even_resealed_passing_aggregate_must_equal_the_original_receipt_measurements',
    ))
