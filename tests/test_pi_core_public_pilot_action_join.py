"""B27 and B93 producer records for the B95 inputs, entirely in inert developer fixtures."""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import verify_pi_core_pilot_provider_records as provider, verify_pi_core_retained_action as cli
from tests import test_pi_core_pilot_action_replay as pilot, test_pi_core_provider_egress as egress


INPUTS = Path(__file__).resolve().parents[1] / "benchmark/pi-core-pilot-v1"
CALL = "call-b99-inert-1"


def _public_records(action):
    review = json.loads((INPUTS / "review.json").read_bytes())
    skill = (INPUTS / "candidate/SKILL.md").read_bytes()
    task = (INPUTS / "task.txt").read_bytes()
    values = egress.acquired.provider_inputs()
    request = values["request"]
    request["payload"]["messages"][0]["content"] = skill.decode("utf-8")
    request["payload"]["messages"][1]["content"] = [{"type":"text", "text":task.decode("utf-8")}]
    # Same inert route/model selected by the existing B27 egress harness before
    # acquisition; B27 will independently recompute and use the policy digest.
    route = {**egress.fixtures.route(), "provider":"openai", "api":"openai-responses",
             "endpoint":{"scheme":"https", "host":"api.openai.com", "port":443, "path":"/v1"}}
    request["payload"]["model"].update(provider="openai", api="openai-responses", baseUrl="https://api.openai.com/v1")
    policy = values["storage"]["policy.json"]
    policy["version"] = pilot.actions.fixtures._grant()["policy_version"]
    policy["allow"][0].update(runtime_digest=action.sources["expected_bindings"]["runtime_digest"],
        active_skill_digest=review["skill_digest"], path_digest=canonical_digest(route),
        payload_digest=canonical_digest(request["payload"]))
    policy_pin = canonical_digest(policy)
    action.original(public_pilot_call_id=CALL, public_pilot_policy_digest=policy_pin)
    public_bytes = cli._public_pilot_inputs(action.activation, action.request)
    action.assertEqual(public_bytes, (skill, task))
    context = dict(action.records)["REQUEST_CONTEXT"]
    values.update(activation=deepcopy(action.activation), grant=deepcopy(context["grant"]),
                  measured=deepcopy(context["measurement"]), lineage=deepcopy(context["lineage"]),
                  source_capture=deepcopy(action.node.record), boundary_boottime_ns=action.node.arguments["boundary_boottime_ns"])
    values["config"] = replace(values["config"], expected_runtime_digest=action.activation["runtime_digest"],
                               expected_runtime_uid=action.activation["uid"], expected_runtime_gid=action.activation["gid"])
    values["storage"]["health.json"]["runtime_digest"] = action.activation["runtime_digest"]
    request["activation_id"] = action.activation["activation_id"]
    values["approval"]["data_class"] = review["data_class"]
    values["approval"]["request"].update({k:action.activation[k] for k in
        ("runtime_digest", "active_skill_digest", "session_id", "run_id")}, policy_version=policy["version"])

    f = egress.ProviderEgressTests()
    try:
        with patch.object(egress.acquired, "provider_inputs", return_value=values):
            f.setUp()
        action.assertEqual(f.f.activation, action.activation)
        action.assertEqual(canonical_digest(f.f.storage["policy.json"]), policy_pin)
        result = f.f.service_result
        result["completion"].update(stop_reason="toolUse", content=[{
            "type":"toolCall", "id":CALL, "name":"aragorn_runtime_create",
            "arguments":{"target_name":review["target_name"], "content":canonical_json({"total":sum(review["inputs"])}).decode("ascii")},
        }])
        observed = f.run_request()
        action.assertEqual(observed["status"], "COMPLETED")
        records, references = deepcopy(f.store.records), deepcopy(f.store.references)
        packet = deepcopy(f.sent[0])
    finally:
        f.doCleanups()  # Restore the donor's OS-denial mocks before using the temporary CAS.

    action.assertEqual(len(records), 41)
    action.assertEqual(len(records), len(references))
    activation_pin = canonical_digest(action.activation)
    header = dict(schema="aragorn/pi-core-provider-evidence-index/v1",
                  authority="DURABLE_REFERENCE_PREFIX_ONLY_NOT_COMPLETED_CAPTURE", sequence=0, kind="HEADER",
                  activation_id=action.activation["activation_id"], activation_digest=activation_pin)
    raw = canonical_json(header) + b"\n"
    for seq, ((kind, doc), ref) in enumerate(zip(records, references), 1):
        original = canonical_json(doc)
        action.assertEqual(ref, dict(kind=kind, digest=action.put(original), bytes=len(original)))
        raw += canonical_json(dict(schema="aragorn/pi-core-provider-evidence-reference/v1", sequence=seq,
                              previous_prefix_digest="sha256:" + sha256(raw).hexdigest(), **ref)) + b"\n"
    nomination = dict(schema="aragorn/pi-core-pilot-provider-nomination/v1", index_digest=action.put(raw),
        activation_digest=activation_pin, request_digest=canonical_digest(request), route_digest=canonical_digest(route),
        profile_digest=canonical_digest(packet["profile"]), nonce=packet["nonce"], deadline_ns=packet["deadline_ns"])
    return action.put(canonical_json(nomination)), nomination, public_bytes


class PublicPilotActionJoin(TestCase):
    @classmethod
    def setUpClass(cls):
        # One producer capture in memory for this class, reused read-only across its cases.
        cls.action = pilot.PilotActionReplay()
        cls.addClassCleanup(cls.action.doCleanups)
        cls.action.setUp()
        cls.provider_pin, cls.nomination, cls.public = _public_records(cls.action)
        cls.action_pin = cls.action.put(canonical_json(cls.action.nomination()))

    def test_b27_tool_and_b93_worker_match_b95_without_claiming_network_or_effect(self):
        a = self.action
        report = cli.replay(a.readonly, self.action_pin, provider_archive=a.readonly,
                            provider_nomination_digest=self.provider_pin)
        self.assertIs(report["recorded_tool_call_matches_worker_request"], True)
        self.assertIs(report["recorded_public_pilot_inputs_matched"], True)
        self.assertEqual(report["provider_index_digest"], self.nomination["index_digest"])
        for key in ("provider_peer_authentication_verified", "provider_delivery_verified", "effect_verified",
                    "timing_verified", "sensor_health_verified", "phase3_qualified"):
            self.assertIs(report[key], False)

    def test_wrong_original_task_or_worker_tool_call_refuses(self):
        a = self.action
        skill, task = self.public
        for worker, text, why in ((a.request, task.rstrip(b"\n"), "PILOT_PROVIDER_INPUTS"),
                (a.request | {"tool_call_digest":canonical_digest("another inert tool call")}, task, "PILOT_PROVIDER_WORKER_TOOL")):
            with self.subTest(reason=why), self.assertRaisesRegex(ValueError, why):
                provider.compare_provider_records(a.readonly, self.provider_pin, activation=a.activation,
                                                  worker_request=worker, skill_bytes=skill, task_bytes=text)

    def test_independent_service_nonce_cannot_be_substituted(self):
        a = self.action
        other = a.put(canonical_json(self.nomination | {"nonce":"7"*32}))
        with self.assertRaisesRegex(ValueError, "PILOT_PROVIDER_PACKET"):
            cli.replay(a.readonly, self.action_pin, provider_archive=a.readonly, provider_nomination_digest=other)

    def test_provider_journal_prefix_does_not_establish_a_final_proposal(self):
        a = self.action
        original = a.readonly.read(self.nomination["index_digest"])
        prefix = original[:original.rstrip(b"\n").rindex(b"\n") + 1]
        nomination = a.put(canonical_json(self.nomination | {"index_digest": a.put(prefix)}))
        with self.assertRaisesRegex(ValueError, "PILOT_PROVIDER_INDEX_TRUNCATED"):
            provider.compare_provider_records(a.readonly, nomination, activation=a.activation,
                worker_request=a.request, skill_bytes=self.public[0], task_bytes=self.public[1])

    def test_wrong_target_or_same_length_wrong_answer_is_not_the_public_pilot(self):
        a = self.action
        for change in ({"target_name": "other.json"}, {"payload_base64": "eyJ0b3RhbCI6NH0="}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "PILOT_ACTION_OUTPUT_REQUEST"):
                cli._public_pilot_inputs(a.activation, a.request | change)

    def test_generic_action_replay_is_not_a_public_pilot_result(self):
        a = pilot.PilotActionReplay()
        self.addCleanup(a.doCleanups)
        a.setUp()
        a.original()
        pin = a.put(canonical_json(a.nomination()))
        self.assertNotIn("recorded_public_pilot_inputs_matched", cli.replay(a.readonly, pin))
        with self.assertRaisesRegex(ValueError, "PILOT_ACTION_SOURCE"):
            cli.replay(a.readonly, pin, provider_archive=self.action.readonly, provider_nomination_digest=self.provider_pin)
