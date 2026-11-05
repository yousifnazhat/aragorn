"""New root/service-v2 checks and selected affected v1 checks; no live I/O."""

import copy
import json
import unittest
from unittest import mock

from aragorn import pi_core_provider_mediation as subject
from aragorn import pi_core_openai_transport as transport
from aragorn import pi_core_provider_service as service
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_provider_mediation as fixtures


class ProviderEgressTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ProviderMediationTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        f = self.f
        route = {**fixtures.route(), "provider": "openai", "api": "openai-responses",
                 "endpoint": {"scheme": "https", "host": "api.openai.com", "port": 443, "path": "/v1"}}
        f.request["route_digest"] = canonical_digest(route)
        f.request["payload"]["model"].update(provider="openai", api="openai-responses", baseUrl="https://api.openai.com/v1")
        f.approval.update(route=route, payload_digest=canonical_digest(f.request["payload"]))
        action = f.approval["request"]
        action.update(path_digest=canonical_digest(route), payload_digest=f.approval["payload_digest"],
                      tool_call_id=canonical_digest(f.request))
        f.storage["policy.json"]["allow"][0].update(path_digest=action["path_digest"], payload_digest=action["payload_digest"])
        action["policy_digest"] = canonical_digest(f.storage["policy.json"])
        f.activation["policy_digest"] = action["policy_digest"]
        f.approval["activation_digest"] = canonical_digest(f.activation)
        for key in ("active", "measured_action"):
            for field in f.storage["observation.json"][key]:
                if field != "schema":
                    f.storage["observation.json"][key][field] = action[field]
        f.service_result = fixtures.result(f.request)
        self.profile = {"schema": "aragorn/pi-core-openai-profile/v1", "service_uid": f.peer[1],
                        "service_gid": f.peer[2], "address": "8.8.8.8", "ca_digest": "sha256:" + "c" * 64}
        # Numeric public fixture value is never resolved, connected or used as a real provider.
        self.read_profile = f.stack.enter_context(mock.patch.object(transport, "read_profile", side_effect=lambda: copy.deepcopy(self.profile)))
        claim = {"schema": "aragorn/pi-core-provider-activation-claim/v1",
                 "authority": "PERSISTENT_PROVIDER_BUDGET_CONSUMPTION_NOT_EGRESS_AUTHORITY",
                 "activation_digest": canonical_digest(f.activation), "request_digest": canonical_digest(f.request),
                 "approval_digest": canonical_digest(f.approval), "status": "SPENT"}
        self.claim_read = f.stack.enter_context(mock.patch.object(subject.broker, "_read_owned_bytes_at", return_value=canonical_json(claim)))
        self.sent, self.responses = [], 0
        self.before_receive = lambda index: None
        self.mutate_reply = lambda index, value: value

        def send(connection, packet, deadline, **kwargs):
            self.assertTrue(f.claims)
            self.assertEqual(len(f.storage["state.json"]["consumed"]), 1)
            self.sent.append(copy.deepcopy(packet))
            if packet["kind"] == "REQUEST":
                f.packet = copy.deepcopy(packet)

        def receive(*args, **kwargs):
            index = self.responses
            self.responses += 1
            self.before_receive(index)
            fields = {key: f.packet[key] for key in
                      ("schema", "authority", "nonce", "deadline_ns", "request_digest", "wire_digest")}
            if index < 2:
                value = {**fields, "kind": "CHECK", "phase": ("CONNECT", "SEND")[index], "sequence": index + 1}
            else:
                value = {**fields, "kind": "RESULT", "result": copy.deepcopy(f.service_result),
                         "cleanup": "OWNED_TRANSPORT_CLOSED", "connect_attempted": True, "send_attempted": True}
            return self.mutate_reply(index, value), ()

        f.send.side_effect, f.receive.side_effect = send, receive

    def run_request(self):
        return self.f.run_request(provider_service=True)

    def test_root_binds_exact_wire_and_checks_twice_under_one_claim(self):
        observed = self.run_request()
        self.assertEqual(observed["status"], "COMPLETED")
        self.assertEqual([value["kind"] for value in self.sent], ["REQUEST", "CURRENT", "CURRENT"])
        self.assertEqual([value["phase"] for value in self.sent[1:]], ["CONNECT", "SEND"])
        self.assertEqual(observed["egress_checks"], 2)
        self.assertIsNotNone(observed["provider_service_receipt_digest"])
        self.assertTrue(observed["provider_transport_implemented"])
        self.assertFalse(observed["phase3_eligible"])
        self.f.claim.assert_called_once()
        self.assertEqual(self.sent[0]["wire_digest"], canonical_digest(self.sent[0]["wire"]))
        self.assertEqual(self.sent[0]["wire"]["path"], "/v1/responses")

    def test_fresh_health_change_after_connect_refuses_send_permission(self):
        def changed(index):
            if index == 1:
                self.f.storage["health.json"]["status"] = "unknown"
        self.before_receive = changed
        observed = self.run_request()
        self.assertEqual(observed["status"], "INDETERMINATE")
        self.assertEqual(observed["egress_checks"], 1)
        self.assertEqual(len(self.sent), 2)
        self.assertTrue(self.f.claims)

    def test_revocation_after_connect_refuses_send_permission(self):
        def changed(index):
            if index == 1:
                self.f.storage["revocations.json"]["skill_digests"] = [self.f.activation["active_skill_digest"]]
        self.before_receive = changed
        self.assertEqual(self.run_request()["egress_checks"], 1)
        self.assertEqual(len(self.sent), 2)

    def test_observation_expiring_during_preparation_is_not_cached_allow(self):
        self.f.storage["observation.json"]["expires_at_unix"] = 101
        def changed(index):
            if index == 1:
                self.f.wall.return_value = 101
        self.before_receive = changed
        self.assertEqual(self.run_request()["status"], "INDETERMINATE")
        self.assertEqual(len(self.sent), 2)

    def test_snapshot_digest_change_during_expiry_read_refuses(self):
        original = self.f.load.side_effect
        def changed(fd, path, config, label):
            value = original(fd, path, config, label)
            if label == "provider egress snapshot" and path == config.health_path:
                value["epoch"] += 1
            return value
        self.f.load.side_effect = changed
        self.assertEqual(self.run_request()["egress_checks"], 0)
        self.assertEqual(len(self.sent), 1)

    def test_permission_cannot_outlive_shortest_verified_snapshot(self):
        self.f.storage["health.json"]["expires_at_unix"] = 101
        self.f.wall.return_value = 100.95
        observed = self.run_request()
        self.assertEqual(observed["status"], "COMPLETED")
        for reply in self.sent[1:]:
            self.assertLessEqual(reply["permit_expires_monotonic_ns"], 100_050_000_000)

    def test_permission_is_at_most_100ms_and_never_refreshes_original_deadline(self):
        self.assertEqual(self.run_request()["status"], "COMPLETED")
        for reply in self.sent[1:]:
            self.assertEqual(reply["permit_expires_monotonic_ns"], 100_100_000_000)
            self.assertEqual(reply["deadline_ns"], 103_000_000_000)

    def test_profile_substitution_after_handoff_refuses_before_connect_permission(self):
        self.before_receive = lambda index: self.profile.update(address="1.1.1.1")
        self.assertEqual(self.run_request()["egress_checks"], 0)
        self.assertEqual(len(self.sent), 1)

    def test_service_role_mismatch_refuses_before_claim_or_handoff(self):
        self.profile["service_uid"] += 1
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.f.claim.assert_not_called()
        self.assertEqual(self.sent, [])

    def test_permanent_claim_substitution_refuses_permission_without_recreating(self):
        self.claim_read.return_value = b"{}"
        self.assertEqual(self.run_request()["egress_checks"], 0)
        self.f.claim.assert_called_once()
        self.assertEqual(len(self.sent), 1)

    def test_out_of_order_or_duplicate_phase_refuses_without_permission(self):
        def changed(index, value):
            if index == 0:
                value.update(sequence=2, phase="SEND")
            return value
        self.mutate_reply = changed
        self.assertEqual(self.run_request()["egress_checks"], 0)
        self.assertEqual(len(self.sent), 1)

    def test_completed_without_both_checks_is_not_accepted(self):
        def changed(index, value):
            return {key: value[key] for key in ("schema", "authority", "nonce", "deadline_ns", "request_digest", "wire_digest")} | {
                "kind": "RESULT", "result": copy.deepcopy(self.f.service_result),
                "cleanup": "OWNED_TRANSPORT_CLOSED", "connect_attempted": True, "send_attempted": True}
        self.mutate_reply = changed
        self.assertEqual(self.run_request()["status"], "INDETERMINATE")
        self.assertEqual(len(self.sent), 1)

    def test_explicit_preconnect_refusal_can_complete_custody_without_network_permission(self):
        self.f.service_result.update(status="NOT_SUBMITTED", completion=None)
        def changed(index, value):
            return {key: value[key] for key in ("schema", "authority", "nonce", "deadline_ns", "request_digest", "wire_digest")} | {
                "kind": "RESULT", "result": copy.deepcopy(self.f.service_result),
                "cleanup": "OWNED_TRANSPORT_CLOSED", "connect_attempted": False, "send_attempted": False}
        self.mutate_reply = changed
        self.assertEqual(self.run_request()["status"], "NOT_SUBMITTED")
        self.assertEqual(len(self.sent), 1)
        self.assertTrue(self.f.claims)

    def test_authenticated_terminal_may_precede_service_exit_without_fabricated_liveness(self):
        def exited(index):
            if index == 2:
                self.f.peer_live.side_effect = RuntimeError("one-shot service exited")
        self.before_receive = exited
        self.assertEqual(self.run_request()["status"], "COMPLETED")

    def test_cleanup_hold_cannot_be_success(self):
        def changed(index, value):
            if index == 2:
                value["cleanup"] = "CLEANUP_HOLD"
            return value
        self.mutate_reply = changed
        self.assertEqual(self.run_request()["status"], "INDETERMINATE")
        response = json.loads(self.f.worker_send.call_args.args[1])
        self.assertIsNone(response["completion"])

    def test_unknown_service_mode_refuses_before_identity(self):
        with self.assertRaises(RuntimeError):
            self.f.run_request(provider_service=1)
        self.f.read.assert_not_called()


def load_tests(loader, tests, pattern):
    # Only affected default-mode dispatch/cleanup behavior, not the whole old stage.
    for name in (
        "test_real_policy_allow_consumes_before_handoff_and_closes_before_worker_completion",
        "test_service_send_failure_is_indeterminate_and_never_retried",
        "test_explicit_service_not_submitted_is_not_relabelled_completed",
        "test_cleanup_failure_still_attempts_all_owned_handles_and_prevents_completed",
    ):
        tests.addTest(fixtures.ProviderMediationTests(name))
    return tests
