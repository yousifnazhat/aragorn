"""Real request publisher/decision with inert source acquisition, storage and I/O."""

import copy
import json
import unittest
from unittest import mock

from aragorn import pi_core_provider_mediation as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_provider_egress as fixtures
from tests import test_pi_core_provider_mediation as legacy
from tests import test_pi_core_source_health_enforcement as health_fixtures


class EvidenceCompositionTests(fixtures.ProviderEgressTests):
    def records(self, kind):
        return [value for label, value in self.store.records if label == kind]

    def fail_storage(self, kind, *, phase=None):
        def fail(label, value):
            if label == kind and (phase is None or value.get("phase") == phase):
                self.store.status = "CLEANUP_HOLD"
                raise OSError("inert retained-evidence failure")
        self.store.before_retain = fail

    def test_actual_publication_replaces_inactive_anchor_without_refreshing_global_health(self):
        before = copy.deepcopy(self.f.storage["health.json"])
        observed = self.run_request()
        self.assertEqual(observed["status"], "COMPLETED")
        self.assertEqual(self.f.storage["health.json"], before)
        current = self.f.storage["observation.json"]
        self.assertEqual(current["sequence"], 2)
        self.assertEqual(current["active"]["tool_call_id"], canonical_digest(self.f.request))
        self.assertEqual(current["measured_action"]["payload_digest"], self.f.approval["payload_digest"])
        self.assertEqual([call.args[1] for call in self.publish.call_args_list], ["observation.json"])
        self.assertLess(self.f.events.index("retain:SOURCE_HEALTH"), self.f.events.index("publish:observation.json"))

    def test_raw_inputs_decisions_and_authenticated_packets_are_retained_with_no_public_content(self):
        observed = self.run_request()
        self.assertEqual(observed["status"], "COMPLETED")
        self.assertEqual(self.records("REQUEST"), [self.f.request])
        self.assertEqual(self.records("ACTIVATION"), [self.f.activation])
        self.assertEqual(self.records("APPROVAL"), [self.f.approval])
        self.assertEqual(len(self.records("DECISION")), 4)
        self.assertEqual(len(self.records("SOURCE_HEALTH")), 3)
        self.assertEqual(len(self.records("SOURCE_BOUNDARY")), 6)
        self.assertEqual(self.records("SERVICE_REQUEST"), [self.sent[0]])
        self.assertEqual(self.records("SERVICE_PERMIT"), self.sent[1:])
        self.assertEqual(self.records("SERVICE_RESULT")[0]["result"], self.f.service_result)
        self.assertEqual(self.records("PROVIDER_RESULT"), [self.f.service_result])
        self.assertEqual(len(self.store.records), 41)
        raw = canonical_json(observed)
        for text in (b"approved public instructions", b"untrusted completion", b"Bearer", b"api.openai.com"):
            self.assertNotIn(text, raw)
        self.assertFalse(observed["phase3_eligible"])

    def test_same_captured_source_cannot_be_replayed_for_a_later_permission(self):
        self.f.source_health.side_effect = lambda *a, **kw: copy.deepcopy(self.capture)
        observed = self.run_request()
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(observed["egress_checks"], 0)

    def test_final_permission_clock_checks_are_retained_separately_from_storage_boundary(self):
        observed = self.run_request()
        self.assertEqual(observed["status"], "COMPLETED")
        boundaries = self.records("SOURCE_BOUNDARY")
        self.assertEqual([value["phase"] for value in boundaries],
            ["PRE_POLICY", "POLICY_PUBLICATION", "CONNECT", "CONNECT_PERMIT_CHECK", "SEND", "SEND_PERMIT_CHECK"])
        pins = {canonical_digest(value) for value in self.records("SOURCE_HEALTH")}
        self.assertTrue(all(row["source_digest"] in pins for row in boundaries))
        self.assertTrue(all(row["clock"]["clock_id"] == "CLOCK_BOOTTIME" for row in boundaries))

    def test_missing_evidence_store_refuses_before_publication_claim_or_submission(self):
        self.hold_evidence.side_effect = FileNotFoundError("inert absent owned store")
        observed = self.run_request()
        self.assertEqual(observed["status"], "NOT_SUBMITTED")
        self.assertIsNone(observed["retained_evidence"])
        self.publish.assert_not_called()
        self.f.claim.assert_not_called()
        self.assertEqual(self.sent, [])
        self.f.release.assert_called_once()

    def test_evidence_failure_before_decision_refuses_without_auto_retry(self):
        self.fail_storage("SOURCE_HEALTH")
        observed = self.run_request()
        self.assertEqual(observed["status"], "NOT_SUBMITTED")
        self.assertEqual(observed["cleanup"], "CLEANUP_HOLD")
        self.assertEqual(observed["retained_evidence"]["status"], "CLEANUP_HOLD")
        self.publish.assert_not_called()
        self.f.claim.assert_not_called()
        self.assertEqual(self.store.close_count, 1)
        self.f.release.assert_called_once()

    def test_stale_source_retention_cannot_get_a_new_convenient_challenge(self):
        def age(kind, value):
            if kind == "SOURCE_HEALTH":
                self.tick.return_value = self.capture["events"][-1]["boottime_ns"] + 200_000_001
        self.store.before_retain = age
        observed = self.run_request()
        self.assertEqual(observed["status"], "NOT_SUBMITTED")
        self.assertEqual(len(self.records("SOURCE_HEALTH")), 1)
        self.publish.assert_not_called()
        self.f.claim.assert_not_called()

    def test_missing_global_health_remains_a_refusal_despite_valid_source_capture(self):
        self.f.storage["health.json"]["status"] = "unknown"
        before = copy.deepcopy(self.f.storage["health.json"])
        observed = self.run_request()
        self.assertEqual(observed["status"], "NOT_SUBMITTED")
        self.assertEqual(self.f.storage["health.json"], before)
        self.assertEqual(len(self.records("SOURCE_HEALTH")), 1)
        self.f.claim.assert_not_called()
        self.assertEqual(self.sent, [])

    def test_control_snapshot_change_during_retention_refuses_before_claim(self):
        original = self.f.load.side_effect
        def changed(fd, path, config, label):
            value = original(fd, path, config, label)
            if label == "provider retained decision input" and path == config.health_path:
                value["epoch"] += 1
            return value
        self.f.load.side_effect = changed
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.f.claim.assert_not_called()
        self.assertEqual(self.sent, [])

    def test_service_request_retention_failure_does_not_claim_submission(self):
        self.fail_storage("SERVICE_REQUEST")
        observed = self.run_request()
        self.assertEqual(observed["status"], "NOT_SUBMITTED")
        self.assertFalse(observed["submission_attempted"])
        self.assertTrue(self.f.claims)
        self.assertEqual(self.sent, [])

    def test_permit_retention_failure_after_submission_is_indeterminate(self):
        self.fail_storage("SERVICE_PERMIT", phase="CONNECT")
        observed = self.run_request()
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.assertTrue(observed["submission_attempted"])
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(observed["egress_checks"], 0)

    def test_post_permission_boundary_failure_preserves_actual_successful_check_count(self):
        self.fail_storage("SOURCE_BOUNDARY", phase="CONNECT_PERMIT_CHECK")
        observed = self.run_request()
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.assertEqual(observed["egress_checks"], 1)
        self.assertEqual(len(self.sent), 2)

    def test_result_retention_failure_never_becomes_completed(self):
        self.fail_storage("PROVIDER_RESULT")
        observed = self.run_request()
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.assertEqual(observed["egress_checks"], 2)
        self.assertEqual(len(self.records("SERVICE_RESULT")), 1)
        self.assertIsNone(json.loads(self.f.worker_send.call_args.args[1])["completion"])

    def test_evidence_close_failure_still_releases_other_owned_resources_once(self):
        self.store.close_failure = OSError("inert evidence close")
        observed = self.run_request()
        self.assertEqual(observed["cleanup"], "CLEANUP_HOLD")
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.assertEqual(self.store.close_count, 1)
        self.f.release.assert_called_once()
        self.assertIn("lineage_close", self.f.events)
        self.assertIn(("fd_close", 71), self.f.events)

    def test_cancelled_provider_retains_evidence_before_reraising_same_exception(self):
        error = KeyboardInterrupt()
        self.before_receive = lambda index: (_ for _ in ()).throw(error)
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_request()
        self.assertIs(caught.exception, error)
        observed = error.pi_provider_mediation_observation
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.assertEqual(observed["client_delivery"], "NOT_ATTEMPTED")
        self.assertTrue(observed["submission_attempted"])
        self.assertEqual(observed["retained_evidence"]["status"], "CLOSED")
        self.assertEqual(self.store.close_count, 1)
        self.assertEqual(len(self.records("FAILURE")), 1)

    def test_client_delivery_cancellation_retains_completed_provider_receipt_without_retry(self):
        error = KeyboardInterrupt()
        self.f.worker_send.side_effect = error
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_request()
        self.assertIs(caught.exception, error)
        observed = error.pi_provider_mediation_observation
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.assertEqual(observed["failure_stage"], "CLIENT_DELIVERY")
        self.assertEqual(observed["client_delivery"], "UNCONFIRMED")
        self.assertEqual(len(self.records("SERVICE_RESULT")), 1)
        self.f.worker_send.assert_called_once()
        self.assertEqual(self.store.close_count, 1)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(EvidenceCompositionTests(name) for name in
        EvidenceCompositionTests.__dict__ if name.startswith("test_"))
    for name in ("test_root_binds_exact_wire_and_checks_twice_under_one_claim",
                 "test_fresh_health_change_after_connect_refuses_send_permission",
                 "test_observation_expiring_during_preparation_is_not_cached_allow",
                 "test_permission_cannot_outlive_shortest_verified_snapshot",
                 "test_authenticated_terminal_may_precede_service_exit_without_fabricated_liveness",
                 "test_cleanup_hold_cannot_be_success"):
        suite.addTest(fixtures.ProviderEgressTests(name))
    for name in ("test_real_policy_allow_consumes_before_handoff_and_closes_before_worker_completion",
                 "test_returned_observation_contains_no_prompt_response_route_secret_or_exception"):
        suite.addTest(legacy.ProviderMediationTests(name))
    suite.addTest(health_fixtures.ProviderSourceHealthTests(
        "test_same_activation_and_tightened_budget_are_used_for_each_check"))
    return suite
