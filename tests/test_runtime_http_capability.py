"""New HTTP grant/profile integration checks; transport and custody I/O are inert."""

from __future__ import annotations

import copy
import hashlib
import sys
import types
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from aragorn import native_phase3_http_canary_contract as canary
from aragorn import runtime_action_broker as broker
from aragorn import runtime_http_action as http
from aragorn import runtime_http_broker as mediation
from aragorn import runtime_http_capability as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from scripts import materialize_runtime_http_capability as renderer
from scripts import stage_runtime_phase3_ingress_profile as predecessor

ROOT = Path(__file__).resolve().parents[1]


def digest(character):
    return "sha256:" + character * 64


def fixture():
    binding = {
        "schema": http.BINDING_SCHEMA,
        "fixture": {
            "container_id": "a" * 64,
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "netns_device": 4,
            "netns_inode": 9,
        },
        "expected_broker_uid": 996,
        "expected_broker_gid": 997,
    }
    request = {
        "schema": "aragorn/runtime-action-request/v1",
        "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
        "runtime_digest": digest("4"),
        "session_id": "session-1",
        "run_id": "run-1",
        "tool_call_id": "call-1",
        "active_skill_digest": digest("5"),
        **http.action_digests("p3-lab-a001", binding),
        "policy_digest": digest("a"),
        "policy_version": 3,
        "issued_at_unix": 100,
        "expires_at_unix": 105,
    }
    envelope = {
        "schema": mediation.ENVELOPE_SCHEMA,
        "request": request,
        "effect": http.effect_for_attempt("p3-lab-a001"),
    }
    measured = {
        "schema": "aragorn/measured-runtime-action/v1",
        **{
            key: request[key]
            for key in (
                "runtime_digest",
                "session_id",
                "run_id",
                "tool_call_id",
                "active_skill_digest",
                "operation_digest",
                "path_digest",
                "payload_digest",
            )
        },
    }
    attribution = {
        "schema": "aragorn/runtime-process-profile-attribution/v1",
        "authority": "KERNEL_PROCESS_PROFILE_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
        "profile_digest": digest("3"),
        "runtime_digest": digest("4"),
        "executable_digest": digest("b"),
        "active_skill_digest": digest("5"),
        "skill_path": "/profile/skills/demo/SKILL.md",
        "cgroup": "/aragorn.slice/worker.service",
        "pid": 11,
        "uid": 997,
        "gid": 997,
        "start_time_ticks": 14,
        "mount_namespace": {"device": 15, "inode": 16},
    }
    submission = {
        "schema": subject.PROFILED_SCHEMA,
        "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
        "sensor_digest": digest("6"),
        "envelope_digest": canonical_digest(envelope),
        "request_digest": canonical_digest(request),
        "runtime_peer": {"pid": 11, "uid": 997, "gid": 997},
        "measured_action": measured,
        "envelope": envelope,
        "runtime_attribution": attribution,
    }
    grant = {
        "schema": "aragorn/runtime-capability-grant/v1",
        "authority": "ROOT_RUNTIME_CAPABILITY_GRANT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
        "grant_id": "1" * 64,
        "source_manifest_digest": digest("1"),
        "install_context_digest": digest("2"),
        "runtime_profile_digest": digest("3"),
        "runtime_digest": digest("4"),
        "active_skill_digest": digest("5"),
        "sensor_digest": digest("6"),
        "policy_digest": digest("a"),
        "policy_version": 3,
        "operation_digest": request["operation_digest"],
        "issued_at_unix": 90,
        "expires_at_unix": 110,
        "max_actions": 1,
    }
    return binding, submission, grant


def result_for(binding, submission, *, blocked=False, replay=False):
    request = submission["envelope"]["request"]
    effect = submission["envelope"]["effect"]
    reasons = (
        ["BROKER_REPLAY_BLOCKED"] if replay else ["POLICY_DENIED"] if blocked else []
    )
    decision = (
        None
        if replay
        else {
            "schema": "aragorn/runtime-action-decision/v1",
            "authority": "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": canonical_digest(request),
            "verdict": "BLOCK" if blocked else "ALLOW",
            "reason_codes": reasons,
        }
    )
    transport = (
        None
        if blocked or replay
        else {
            "schema": http.RESULT_SCHEMA,
            "authority": http.RESULT_AUTHORITY,
            "attempt_id": effect["attempt_id"],
            "fixture_binding_digest": canonical_digest(binding),
            "effect_digest": canonical_digest(effect),
            "action_digests": http.action_digests(effect["attempt_id"], binding),
            "connect_attempted": True,
            "sent_bytes": len(canary.canary_request(effect["attempt_id"])),
            "response_bytes": len(canary.RESPONSE_BYTES),
            "response_digest": canary.digest(canary.RESPONSE_BYTES),
            "status": "SENT",
            "error_code": None,
            "identity": {
                "fixture": binding["fixture"],
                "pid": 21,
                "start_time_ticks": 22,
                "uid": binding["expected_broker_uid"],
                "gid": binding["expected_broker_gid"],
            },
            **dict.fromkeys(canary.FALSE_FLAGS, False),
        }
    )
    return mediation._result(
        request,
        effect,
        digest("c"),
        decision,
        reasons,
        transport,
        payload_decision=None if reasons else decision,
    )


class HttpCapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inherited, replacements = predecessor._verified_payloads()
        cls.original = {
            name: raw for name, _mode, raw in (inherited | replacements).values()
        }
        cls.rendered = renderer.render(cls.original)

    def setUp(self):
        self.binding, self.submission, self.grant = fixture()
        self.modules = {}
        for source, raw in self.rendered.items():
            key = Path(source).stem
            name = "aragorn._http_capability_test_" + key
            module = types.ModuleType(name)
            module.__package__ = "aragorn"
            module.__file__ = str(ROOT / source)
            self.enterContext(patch.dict(sys.modules, {name: module}))
            # Only the exact pinned and reversibly rendered local source is run.
            exec(compile(raw, source + ":http-successor", "exec"), module.__dict__)  # noqa: S102
            self.modules[key] = module
        self.grants = self.modules["runtime_capability_grant"]
        self.v2 = self.modules["runtime_action_broker_v2"]
        self.v3 = self.modules["runtime_action_broker_v3"]
        self.v4 = self.modules["runtime_action_broker_v4"]
        self.v5 = self.modules["runtime_action_broker_v5"]
        self.journal = self.modules["runtime_endpoint_journal"]
        # Resolve rendered siblings exactly as a separately staged package does;
        # never replace or mutate the imported frozen predecessor modules.
        self.v4._profiled_submission = self.v2._profiled_submission
        self.v4._validate_profile_claim = self.v3._claim
        self.v4._validate_profile_result = self.v3._lease_result
        self.v4.mediate_profiled_runtime_create = (
            self.v2.mediate_profiled_runtime_create
        )
        self.v5._issued_submission = self.v4._issued_submission
        self.v5.mediate_granted_profiled_runtime_create = (
            self.v4.mediate_granted_profiled_runtime_create
        )
        self.profile_config = types.SimpleNamespace(
            expected_runtime_profile_digest=digest("3"), broker=object()
        )
        self.config = types.SimpleNamespace(
            broker=self.profile_config, capability_grant=canonical_json(self.grant)
        )
        self.enterContext(
            patch.object(self.grants.secrets, "token_hex", return_value="d" * 64)
        )
        self.issued = self.grants.issue_profiled_runtime_capability(
            self.submission, canonical_json(self.grant), 102
        )
        self.enterContext(patch.object(self.v4.time, "time", return_value=102))
        self.enterContext(
            patch.object(self.v4, "_validate_config", return_value=self.grant)
        )
        self.enterContext(patch.object(self.v2, "_validate_config"))
        self.enterContext(
            patch.object(self.v4._measurement, "begin", return_value=object())
        )
        self.enterContext(patch.object(self.v4._measurement, "retain"))
        self.enterContext(patch.object(self.v4._measurement, "close"))
        self.result = result_for(self.binding, self.submission)
        self.transport = self.enterContext(
            patch.object(mediation, "mediate_observed_http", return_value=self.result)
        )
        self.create = self.enterContext(
            patch.object(
                self.v2,
                "mediate_observed_runtime_create",
                side_effect=AssertionError("create route selected"),
            )
        )
        self.socket = self.enterContext(
            patch.object(
                http.socket, "socket", side_effect=AssertionError("live socket")
            )
        )
        self.addCleanup(self.socket.assert_not_called)
        self.state = {
            "schema": "aragorn/runtime-capability-grant-state/v1",
            "authority": "BROKER_DURABLE_GRANT_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "grant_digest": canonical_digest(self.grant),
            "status": "AVAILABLE",
            "claim": None,
            "result": None,
        }
        self.pending = self.receipt = None
        self.enterContext(
            patch.object(
                self.v4,
                "_with_profile_lock",
                side_effect=lambda _config, _deadline, callback: callback(17),
            )
        )
        self.enterContext(
            patch.object(
                self.v4, "_load_state", side_effect=lambda *_: copy.deepcopy(self.state)
            )
        )
        self.enterContext(
            patch.object(self.v4, "_publish_state", side_effect=self.publish_state)
        )
        self.enterContext(
            patch.object(
                self.v4, "_require_no_pending_at", side_effect=self.require_no_pending
            )
        )
        self.enterContext(
            patch.object(
                self.v4,
                "_require_no_profile_receipt_at",
                side_effect=self.require_no_receipt,
            )
        )
        self.enterContext(
            patch.object(
                self.v4,
                "_discard_stale_profile_receipt",
                side_effect=self.discard_receipt,
            )
        )
        self.enterContext(
            patch.object(
                self.v4,
                "_load_profile_receipt",
                side_effect=lambda *_: copy.deepcopy(self.receipt),
            )
        )
        self.enterContext(
            patch.object(
                self.v2, "_create_profile_pending", side_effect=self.create_pending
            )
        )
        self.enterContext(
            patch.object(
                self.v2, "_persist_profile_receipt", side_effect=self.persist_receipt
            )
        )
        self.enterContext(
            patch.object(
                self.v2, "_discard_profile_pending", side_effect=self.discard_pending
            )
        )

    def publish_state(self, _fd, _config, state):
        self.v4._state(state, canonical_digest(self.grant))
        self.state = copy.deepcopy(state)

    def require_no_pending(self, *_):
        if self.pending is not None:
            raise broker.RuntimeActionBrokerError("pending remains")

    def require_no_receipt(self, *_):
        if self.receipt is not None:
            raise broker.RuntimeActionBrokerError("receipt remains")

    def discard_receipt(self, *_):
        self.receipt = None

    def create_pending(self, _config, pending, _deadline):
        self.require_no_pending()
        self.pending = copy.deepcopy(pending)

    def persist_receipt(self, _config, receipt, _deadline):
        self.receipt = copy.deepcopy(receipt)

    def discard_pending(self, _config, pending, _deadline):
        self.assertEqual(self.pending, pending)
        self.pending = None

    def redeem(self):
        return self.v4.mediate_granted_profiled_runtime_create(
            self.issued, self.config, deadline_monotonic=999
        )

    def claim(self):
        observed = subject.observed_from_profile(self.submission)
        return subject.build_grant_claim(
            self.grant,
            self.issued["lease"],
            observed,
            self.submission["runtime_attribution"],
            canonical_digest(self.submission),
            102,
        )

    def test_exact_source_pins_and_new_types(self):
        self.assertEqual(set(self.rendered), set(renderer.INPUTS))
        for name, pin in renderer.INPUTS.items():
            self.assertEqual(
                (
                    len(self.original[name]),
                    hashlib.sha256(self.original[name]).hexdigest(),
                ),
                pin,
            )
            self.assertNotEqual(self.original[name], self.rendered[name])
            compile(self.rendered[name], name, "exec")

    def test_renderer_refuses_mutation_missing_and_double_render(self):
        for original in (
            {},
            {**self.original, renderer._V4: self.original[renderer._V4] + b"\n"},
            {**self.original, **self.rendered},
        ):
            with (
                self.subTest(keys=len(original)),
                self.assertRaises(renderer.HttpCapabilityRenderError),
            ):
                renderer.render(original)

    def test_issuance_preserves_http_types_and_detaches(self):
        issued = self.issued
        self.assertEqual(
            issued["profiled_submission"]["schema"], subject.PROFILED_SCHEMA
        )
        self.assertEqual(
            issued["lease"]["operation_digest"], self.grant["operation_digest"]
        )
        self.assertEqual(issued["lease"]["max_actions"], 1)
        self.submission["runtime_peer"]["pid"] = 999
        self.assertEqual(issued["profiled_submission"]["runtime_peer"]["pid"], 11)

    def test_issuance_refuses_unbound_grant_and_http_create_mix(self):
        cases = [
            (self.submission, {**self.grant, "operation_digest": digest("e")}),
            (
                {
                    **self.submission,
                    "schema": "aragorn/runtime-observed-create-submission/v2",
                },
                self.grant,
            ),
        ]
        for submission, grant in cases:
            with (
                self.subTest(grant=grant["operation_digest"]),
                self.assertRaises(broker.RuntimeActionBrokerError),
            ):
                self.grants.issue_profiled_runtime_capability(
                    submission, canonical_json(grant), 102
                )

    def test_profile_validation_retains_measured_peer_and_digest_checks(self):
        for field, changed in (("pid", 12), ("profile_digest", digest("f"))):
            value = copy.deepcopy(self.submission)
            value["runtime_attribution"][field] = changed
            with (
                self.subTest(field=field),
                self.assertRaises(broker.RuntimeActionBrokerError),
            ):
                self.v2._profiled_submission(value, self.profile_config)

    def test_claim_is_http_specific_without_create_target(self):
        claim = self.claim()["profile_claim"]
        self.assertEqual(claim["schema"], subject.CLAIM_SCHEMA)
        self.assertNotIn("target_name", claim)
        self.assertEqual(claim["attempt_id"], "p3-lab-a001")
        self.assertEqual(self.v3._claim(claim, claim["lease_digest"]), claim)

    def test_claim_rejects_effect_and_attempt_rebinding(self):
        for field, value in (
            ("attempt_id", "p3-lab-a002"),
            ("effect_digest", digest("f")),
            ("target_name", "fake"),
        ):
            claim = self.claim()["profile_claim"]
            claim[field] = value
            with (
                self.subTest(field=field),
                self.assertRaises(broker.RuntimeActionBrokerError),
            ):
                subject.validate_claim(claim, claim["lease_digest"])

    def test_claim_rejects_non_http_measured_operation(self):
        claim = self.claim()["profile_claim"]
        claim["profile_pending"]["measured_action"]["operation_digest"] = digest("f")
        claim["measured_action_digest"] = canonical_digest(
            claim["profile_pending"]["measured_action"]
        )
        with self.assertRaises(broker.RuntimeActionBrokerError):
            subject.validate_claim(claim, claim["lease_digest"])

    def test_http_chain_consumes_once_and_retains_sent_receipt(self):
        self.assertEqual(self.redeem(), self.result)
        self.assertEqual(self.state["status"], "CONSUMED")
        self.assertIsNone(self.pending)
        self.assertEqual(self.receipt["broker_result"], self.result)
        self.assertEqual(
            self.state["result"]["profile_result"]["schema"],
            subject.LEASE_RESULT_SCHEMA,
        )
        self.create.assert_not_called()
        self.transport.assert_called_once()
        observed = self.transport.call_args.args[0]
        self.assertEqual(observed["schema"], mediation.SUBMISSION_SCHEMA)

    def test_consumed_grant_never_retries_http(self):
        self.redeem()
        with self.assertRaisesRegex(broker.RuntimeActionBrokerError, "consumed"):
            self.redeem()
        self.transport.assert_called_once()
        self.assertEqual(self.state["status"], "CONSUMED")

    def test_indeterminate_transport_retains_claim_and_pending(self):
        self.transport.side_effect = broker.RuntimeActionEffectIndeterminate(
            "unknown send"
        )
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.redeem()
        self.assertEqual(self.state["status"], "CLAIMED")
        self.assertIsNotNone(self.pending)
        self.assertIsNone(self.receipt)

    def test_known_pre_effect_refusal_abandons_without_reset(self):
        self.transport.side_effect = broker.RuntimeActionBrokerError("no connect")
        with self.assertRaises(broker.RuntimeActionBrokerError):
            self.redeem()
        self.assertEqual(self.state["status"], "ABANDONED")
        self.assertIsNone(self.pending)

    def test_sent_receipt_failure_is_indeterminate_and_claimed(self):
        self.v2._persist_profile_receipt.side_effect = broker.RuntimeActionBrokerError(
            "retention failure"
        )
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.redeem()
        self.assertEqual(self.state["status"], "CLAIMED")
        self.assertIsNotNone(self.pending)

    def test_sent_pending_cleanup_failure_retains_claim(self):
        self.v2._discard_profile_pending.side_effect = broker.RuntimeActionBrokerError(
            "cleanup failure"
        )
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.redeem()
        self.assertEqual(self.state["status"], "CLAIMED")
        self.assertIsNotNone(self.receipt)

    def test_interruption_never_abandons_or_retries(self):
        self.transport.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.redeem()
        self.assertEqual(self.state["status"], "CLAIMED")
        self.assertIsNotNone(self.pending)

    def test_sent_consumption_publication_failure_keeps_claimed_state(self):
        def publish(_fd, _config, state):
            if state["status"] == "CONSUMED":
                raise broker.RuntimeActionBrokerError("consumed publication failure")
            self.publish_state(_fd, _config, state)

        self.v4._publish_state.side_effect = publish
        with self.assertRaises(broker.RuntimeActionEffectIndeterminate):
            self.redeem()
        self.assertEqual(self.state["status"], "CLAIMED")
        self.assertIsNone(self.pending)
        self.assertIsNotNone(self.receipt)

    def test_all_http_broker_response_failures_are_indeterminate(self):
        for module, depth, mediator_name in (
            (self.v2, 1, "mediate_profiled_runtime_create"),
            (self.v4, 2, "mediate_granted_profiled_runtime_create"),
            (self.v5, 3, "mediate_lineage_granted_profiled_runtime_create"),
        ):
            config = types.SimpleNamespace(expected_peer_uid=997, expected_peer_gid=997)
            for _ in range(depth):
                config = types.SimpleNamespace(broker=config)
            handler = getattr(
                module._handle_connection, "__wrapped__", module._handle_connection
            )
            with (
                self.subTest(module=module.__name__),
                patch.object(module, "_peer_credentials", return_value=(20, 997, 997)),
                patch.object(module, "_read_frame", return_value={}),
                patch.object(module, mediator_name, return_value=self.result),
                patch.object(
                    module,
                    "_send_frame",
                    side_effect=broker.RuntimeActionBrokerError("response failure"),
                ),
                self.assertRaises(broker.RuntimeActionEffectIndeterminate),
            ):
                handler(object(), config, timeout_seconds=0.5)

    def test_block_and_replay_receipts_remain_effect_free(self):
        for replay in (False, True):
            result = result_for(
                self.binding, self.submission, blocked=True, replay=replay
            )
            claim = self.claim()["profile_claim"]
            self.assertEqual(subject.validate_broker_result(result, claim), result)
            self.assertEqual(result["effect_status"], "NOT_PERFORMED")

    def test_http_policy_block_consumes_capability(self):
        self.transport.return_value = result_for(
            self.binding, self.submission, blocked=True
        )
        self.assertEqual(self.redeem()["effect_status"], "NOT_PERFORMED")
        self.assertEqual(self.state["status"], "CONSUMED")

    def test_sent_requires_both_decisions_and_transport(self):
        for field, value in (
            ("payload_decision", None),
            ("transport", None),
            ("effect_status", "CREATED"),
            ("phase3_eligible", True),
        ):
            result = {**self.result, field: value}
            with (
                self.subTest(field=field),
                self.assertRaises(broker.RuntimeActionBrokerError),
            ):
                subject.validate_broker_result(result, self.claim()["profile_claim"])

    def test_transport_binding_and_send_count_must_match(self):
        for field, value in (
            ("sent_bytes", 0),
            ("fixture_binding_digest", digest("e")),
            ("status", "INDETERMINATE"),
        ):
            result = copy.deepcopy(self.result)
            result["transport"][field] = value
            with (
                self.subTest(field=field),
                self.assertRaises(broker.RuntimeActionBrokerError),
            ):
                subject.validate_broker_result(result, self.claim()["profile_claim"])

    def test_result_receipt_cannot_relabel_http_as_create(self):
        self.redeem()
        record = self.state["result"]["profile_result"]
        claim = self.state["claim"]["profile_claim"]
        self.assertEqual(self.v3._lease_result(record, claim), record)
        for changes in (
            {"schema": "aragorn/runtime-capability-lease-result/v1"},
            {"effect_status": "CREATED"},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(broker.RuntimeActionBrokerError),
            ):
                self.v3._lease_result({**record, **changes}, claim)

    def test_v5_holds_lineage_before_redemption_and_sent_cleanup_is_indeterminate(self):
        @contextmanager
        def hold(*_args, **_kwargs):
            self.assertEqual(self.state["status"], "AVAILABLE")
            yield {"unit-test-lineage": True}
            self.assertEqual(self.state["status"], "CONSUMED")
            raise RuntimeActionObservationPublisherError("held lineage cleanup failure")

        wrapped = {
            "schema": self.v5.LINEAGE_ISSUANCE_SCHEMA,
            "authority": self.v5.LINEAGE_ISSUANCE_AUTHORITY,
            "lineage": {"unit-test-lineage": True},
            "issuance": self.issued,
        }
        config = types.SimpleNamespace(
            broker=self.config, protected_install_root=Path("/unit-test")
        )
        with (
            patch.object(self.v5, "_validate_config", return_value=self.grant),
            patch.object(
                self.v5, "hold_runtime_active_skill_lineage", side_effect=hold
            ),
            self.assertRaises(broker.RuntimeActionEffectIndeterminate),
        ):
            self.v5.mediate_lineage_granted_profiled_runtime_create(wrapped, config)
        self.assertEqual(self.state["status"], "CONSUMED")
        self.transport.assert_called_once()

    def test_v5_changed_lineage_refuses_before_grant_claim(self):
        @contextmanager
        def hold(*_args, **_kwargs):
            yield {"different": True}

        wrapped = {
            "schema": self.v5.LINEAGE_ISSUANCE_SCHEMA,
            "authority": self.v5.LINEAGE_ISSUANCE_AUTHORITY,
            "lineage": {"expected": True},
            "issuance": self.issued,
        }
        config = types.SimpleNamespace(
            broker=self.config, protected_install_root=Path("/unit-test")
        )
        with (
            patch.object(self.v5, "_validate_config", return_value=self.grant),
            patch.object(
                self.v5, "hold_runtime_active_skill_lineage", side_effect=hold
            ),
            self.assertRaises(broker.RuntimeActionBrokerError),
        ):
            self.v5.mediate_lineage_granted_profiled_runtime_create(wrapped, config)
        self.assertEqual(self.state["status"], "AVAILABLE")
        self.transport.assert_not_called()


if __name__ == "__main__":
    unittest.main()
