"""Only the B76 public measurement/cleanup contract. No historical dispatch suite."""
import unittest

import test_pi_core_bundle_install_dispatch as dispatch


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(dispatch.BundleInstallDispatchTests("test_" + name) for name in (
        "fixed_route_returns_only_metadata_and_existing_transaction_digest",
        "success_requires_owned_input_and_destination_cleanup",
        "success_requires_attempt_transaction_context_and_no_recovery",
        "publisher_failure_retains_recovery_digest_without_raw_record",
        "post_install_host_custody_failure_does_not_erase_publication_digest",
        "wrapper_close_failure_cannot_become_success",
        "successful_looking_exception_cannot_publish_the_tree",
        "old_or_invalid_measurement_preserves_publication_but_cannot_be_certified",
        "matching_noncanonical_or_zero_pins_are_not_observed_trees",
        "changed_matching_observation_and_transaction_after_guard_cannot_be_emitted",
        "original_deadline_reached_during_final_close_withholds_measurement",
        "measured_digest_requires_custody_and_the_invoked_plan_and_host",
        "missing_entry_record_preserves_unknown_attempt",
        "uncertain_descriptor_metadata_remains_private_and_bound",
        "prepublication_refusal_does_not_claim_installation",
    ))
