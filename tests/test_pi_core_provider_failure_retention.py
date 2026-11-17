"""Exact producer-to-native failure joins and root source gate; inert owners only."""

import copy
import unittest
from unittest import mock

from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_native_provider as native
from tests import test_pi_core_coordinator_entry as root


class ProviderFailureRetentionTests(native.ProviderFixture):
    def record(self):
        return {"schema": "aragorn/pi-core-provider-mediation-observation/v1",
            "authority": "PROVIDER_DATA_GATE_OBSERVATION_NOT_EGRESS_OR_RUN_AUTHORITY",
            "status": "INDETERMINATE", "submission_attempted": True,
            "activation_digest": canonical_digest(self.pd._activation),
            "request_digest": canonical_digest(self.pd._expected),
            "cleanup": "OWNED_HANDLES_CLOSED", "client_delivery": "NOT_ATTEMPTED",
            "retained_evidence": {"status": "CLOSED", "index_status": "DURABLE_PREFIX"},
            "phase3_eligible": False}

    def fail(self, error, record):
        error.pi_provider_mediation_observation = record
        self.mediate.side_effect = error
        with self.assertRaises(type(error)) as caught:
            self.pd.serve_once(114)
        self.assertIs(caught.exception, error)
        self.mediate.assert_called_once()
        self.provider_worker.close.assert_called_once()
        return self.pd.observation

    def test_cancellation_retains_same_attempt_before_owned_stream_close(self):
        self.begin()
        record = self.record()
        observed = self.fail(KeyboardInterrupt(), record)
        self.assertEqual(observed["provider_result"], record)
        self.assertEqual(observed["cleanup"], "CLEANUP_HOLD")
        self.assertEqual(observed["status"], "PROVIDER_INDETERMINATE")

    def test_stream_cleanup_replacement_does_not_erase_mediator_record(self):
        self.begin()
        interrupted = KeyboardInterrupt()
        interrupted.pi_provider_mediation_observation = self.record()
        self.mediate.side_effect = interrupted
        replaced = OSError("inert accepted close failure")
        self.provider_worker.close.side_effect = replaced
        with self.assertRaises(OSError) as caught:
            self.pd.serve_once(114)
        self.assertIs(caught.exception, replaced)
        self.assertIs(replaced.__context__, interrupted)
        self.assertEqual(self.pd.observation["provider_result"], interrupted.pi_provider_mediation_observation)
        self.provider_worker.close.assert_called_once()

    def test_private_record_detaches_before_cleanup_mutates_original(self):
        self.begin()
        record = self.record()
        self.provider_worker.close.side_effect = lambda: record["retained_evidence"].update(status="tampered")
        observed = self.fail(OSError("inert mediator failure"), record)
        self.assertEqual(observed["provider_result"]["retained_evidence"]["status"], "CLOSED")

    def test_foreign_activation_is_not_adopted(self):
        self.begin()
        record = self.record()
        record["activation_digest"] = "sha256:" + "f" * 64
        self.assertIsNone(self.fail(OSError("foreign record"), record)["provider_result"])

    def test_foreign_request_is_not_adopted(self):
        self.begin()
        record = self.record()
        record["request_digest"] = "sha256:" + "e" * 64
        self.assertIsNone(self.fail(OSError("foreign request"), record)["provider_result"])

    def test_submitted_record_cannot_omit_its_actual_request_digest(self):
        self.begin()
        record = self.record()
        record["request_digest"] = None
        self.assertIsNone(self.fail(OSError("missing submitted request"), record)["provider_result"])

    def test_attempted_submit_cannot_be_labeled_not_submitted(self):
        self.begin()
        record = self.record()
        record["status"] = "NOT_SUBMITTED"
        self.assertIsNone(self.fail(OSError("invalid status"), record)["provider_result"])

    def test_pre_request_failure_keeps_unsubmitted_unknown_request(self):
        self.begin()
        record = self.record()
        record.update(status="NOT_SUBMITTED", submission_attempted=False, request_digest=None)
        self.assertEqual(self.fail(KeyboardInterrupt(), record)["provider_result"], record)

    def test_oversized_record_never_replaces_original_error(self):
        self.begin()
        record = self.record()
        record["retained_evidence"] = {"oversized": "x" * (4 * 1024 * 1024)}
        self.assertIsNone(self.fail(KeyboardInterrupt(), record)["provider_result"])


class ProviderPublisherSourceTests(root.CoordinatorEntryTests):
    def setUp(self):
        super().setUp()
        self.plan, self.documents = root.prepared(True)

    def test_actual_consumed_publisher_row_is_retained_before_call(self):
        result = self.invoke()
        self.assertEqual(result["source_before"], self.custody.return_value[1])
        self.call.assert_called_once()
        self.assertIn("aragorn.pi_core_provider_observation",
            [row["module"] for row in result["source_before"]])

    def test_missing_pinned_publisher_refuses_before_credential_or_activation(self):
        self.source.source_digests.clear()
        self.refuse()
        self.credential_hold.assert_not_called()
        self.approval_hold.assert_not_called()

    def test_missing_consumed_publisher_refuses(self):
        self.custody.return_value[1].pop()
        self.refuse()
        self.credential_hold.assert_not_called()

    def test_changed_consumed_publisher_digest_refuses(self):
        self.custody.return_value[1][-1]["digest"] = root.pin("a")
        self.refuse()

    def test_duplicate_consumed_row_refuses(self):
        rows = self.custody.return_value[1]
        rows.append(copy.deepcopy(rows[-1]))
        self.refuse()


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(ProviderFailureRetentionTests)
    for name in ProviderPublisherSourceTests.__dict__:
        if name.startswith("test_"):
            suite.addTest(ProviderPublisherSourceTests(name))
    for name in ("test_one_native_request_reuses_exact_mediator_and_held_channels",
                 "test_ambiguous_mediator_exception_preserves_hold_no_retry"):
        suite.addTest(native.NativeProviderDispatchTests(name))
    for name in ("test_unavailable_calls_once_with_derived_inputs_and_readonly_cas",
                 "test_protected_uses_only_existing_metadata_credential_and_approval_holders"):
        suite.addTest(root.CoordinatorEntryTests(name))
    return suite
