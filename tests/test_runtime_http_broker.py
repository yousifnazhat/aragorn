"""HTTP policy/replay mediation in disposable file fixtures; no network I/O."""

import copy
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_http_broker as subject
from aragorn import runtime_http_action as http
from aragorn import native_phase3_http_canary_contract as canary
from aragorn.oci_worker_protocol import canonical_digest
from test_runtime_action_broker import _Fixture, _write_control, _observed_submission


class HttpBrokerTests(unittest.TestCase):
    def setUp(self):
        # The production custody check rejects writable /tmp ancestry. Keep the
        # disposable files beneath this already-owned workspace instead; do not
        # mock or weaken that check merely to exercise the mediation boundary.
        temporary = tempfile.TemporaryDirectory(
            prefix="http-broker-unit-",
            dir=Path(__file__).resolve().parents[1] / ".aragorn",
        )
        self.addCleanup(temporary.cleanup)
        self.fixture = _Fixture(Path(temporary.name).resolve())
        f = self.fixture
        self.binding = {
            "schema": http.BINDING_SCHEMA,
            "fixture": {
                "container_id": "a" * 64,
                "boot_id": "12345678-1234-1234-1234-123456789abc",
                "netns_device": 4,
                "netns_inode": 9,
            },
            "expected_broker_uid": os.geteuid(),
            "expected_broker_gid": os.getegid(),
        }
        self.effect = http.effect_for_attempt("p3-lab-a001")
        self.digests = http.action_digests("p3-lab-a001", self.binding)
        f.policy["allow"][0].update(self.digests)
        f.request.update(self.digests)
        f.request["policy_digest"] = canonical_digest(f.policy)
        _write_control(f.paths["policy"], f.policy)
        f.config = replace(
            f.config,
            expected_runtime_uid=os.geteuid() + 2,
            expected_runtime_gid=os.getegid() + 2,
        )
        f.envelope = {
            "schema": subject.ENVELOPE_SCHEMA,
            "request": f.request,
            "effect": self.effect,
        }
        self.submission = _observed_submission(f, f.config)
        self.submission["schema"] = subject.SUBMISSION_SCHEMA
        self.sequence = []
        self.enterContext(
            patch.object(http, "load_fixture_binding", return_value=self.binding)
        )
        self.final = self.enterContext(
            patch.object(
                subject.measurement,
                "final_decision",
                side_effect=lambda *args: self.sequence.append("decision"),
            )
        )
        self.send = self.enterContext(
            patch.object(http, "execute_http_effect", side_effect=self.transport)
        )
        self.socket = self.enterContext(
            patch.object(
                http.socket, "socket", side_effect=AssertionError("live socket")
            )
        )
        self.addCleanup(self.socket.assert_not_called)

    def transport(
        self, effect, *, fixture_binding, deadline_monotonic, authorize_effect=None
    ):
        if not authorize_effect():
            record = self.transport_record(effect, fixture_binding)
            record.update(
                connect_attempted=False,
                status="NOT_PERFORMED",
                sent_bytes=0,
                response_bytes=0,
                response_digest=canary.digest(b""),
                error_code="HTTP_AUTHORIZATION_REFUSED",
            )
            raise http.RuntimeHttpActionError(
                "HTTP_AUTHORIZATION_REFUSED",
                record,
            )
        self.assertEqual(self.sequence, ["decision"])
        self.assertEqual(len(self.fixture.load_state()["consumed"]), 1)
        self.sequence.append("transport")
        if not authorize_effect():
            raise http.RuntimeHttpActionIndeterminate(
                "HTTP_AUTHORIZATION_REFUSED",
                {"connect_attempted": True, "sent_bytes": 0},
            )
        return self.transport_record(effect, fixture_binding)

    def transport_record(self, effect, fixture_binding):
        return {
            "schema": http.RESULT_SCHEMA,
            "authority": http.RESULT_AUTHORITY,
            "attempt_id": effect["attempt_id"],
            "fixture_binding_digest": canonical_digest(fixture_binding),
            "effect_digest": canonical_digest(effect),
            "action_digests": self.digests,
            "connect_attempted": True,
            "sent_bytes": len(canary.canary_request(effect["attempt_id"])),
            "response_bytes": len(canary.RESPONSE_BYTES),
            "response_digest": canary.digest(canary.RESPONSE_BYTES),
            "status": "SENT",
            "error_code": None,
            "identity": {
                "fixture": fixture_binding["fixture"],
                "pid": 42,
                "start_time_ticks": 123,
                "uid": fixture_binding["expected_broker_uid"],
                "gid": fixture_binding["expected_broker_gid"],
            },
            **dict.fromkeys(canary.FALSE_FLAGS, False),
        }

    def run_action(self, **kwargs):
        return subject.mediate_observed_http(
            self.submission,
            self.fixture.config,
            clock=kwargs.pop("clock", lambda: 100),
            **kwargs,
        )

    def test_allow_consumes_before_final_decision_and_transport(self):
        result = self.run_action()
        self.assertEqual(result["verdict"], "ALLOW")
        self.assertEqual(result["effect_status"], "SENT")
        self.assertEqual(self.sequence, ["decision", "transport"])
        self.final.assert_called_once()
        self.assertTrue(self.final.call_args.args[3])
        self.assertFalse(result["phase3_eligible"])
        self.assertEqual(list(self.fixture.protected.iterdir()), [])

    def test_replay_blocks_without_second_transport_or_claim(self):
        self.run_action()
        result = self.run_action()
        self.assertEqual(result["reason_codes"], ["BROKER_REPLAY_BLOCKED"])
        self.assertIsNone(result["transport"])
        self.send.assert_called_once()
        self.assertEqual(len(self.fixture.load_state()["consumed"]), 1)

    def test_deny_policy_health_and_revocation_never_open_transport(self):
        f = self.fixture
        for control in ("policy", "health", "revocations"):
            with self.subTest(control=control):
                originals = {
                    name: copy.deepcopy(getattr(f, name))
                    for name in (
                        "policy",
                        "health",
                        "revocations",
                        "state",
                        "observation",
                    )
                }
                if control == "policy":
                    f.policy["allow"] = []
                    f.request["policy_digest"] = canonical_digest(f.policy)
                    self.submission["request_digest"] = canonical_digest(f.request)
                    self.submission["envelope_digest"] = canonical_digest(f.envelope)
                elif control == "health":
                    f.health["status"] = "unhealthy"
                else:
                    f.revocations["skill_digests"] = [f.request["active_skill_digest"]]
                _write_control(f.paths[control], getattr(f, control))
                result = self.run_action()
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertEqual(result["effect_status"], "NOT_PERFORMED")
                self.send.assert_not_called()
                for name, original in originals.items():
                    setattr(f, name, original)
                    _write_control(f.paths[name], original)
                f.request["policy_digest"] = canonical_digest(f.policy)
                self.submission["request_digest"] = canonical_digest(f.request)
                self.submission["envelope_digest"] = canonical_digest(f.envelope)

    def test_final_revocation_change_blocks_after_claim(self):
        original = subject.broker._evaluate_snapshot
        calls = 0

        def evaluate(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                f = self.fixture
                f.revocations["generation"] += 1
                f.revocations["skill_digests"] = [f.request["active_skill_digest"]]
                _write_control(f.paths["revocations"], f.revocations)
            return original(*args, **kwargs)

        with patch.object(subject.broker, "_evaluate_snapshot", side_effect=evaluate):
            result = self.run_action()
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(len(self.fixture.load_state()["consumed"]), 1)
        self.send.assert_called_once()
        self.assertNotIn("transport", self.sequence)

    def test_unknown_transport_failure_retains_consumed_state(self):
        self.send.side_effect = OSError("unknown post-send failure")
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
            self.run_action()
        self.assertEqual(len(self.fixture.load_state()["consumed"]), 1)
        self.assertEqual(self.run_action()["verdict"], "BLOCK")
        self.send.assert_called_once()

    def test_partial_transport_observation_is_preserved(self):
        observation = {"connect_attempted": True, "sent_bytes": None}
        self.send.side_effect = http.RuntimeHttpActionIndeterminate(
            "HTTP_TRANSPORT_FAILED", observation
        )
        with self.assertRaises(
            subject.broker.RuntimeActionEffectIndeterminate
        ) as caught:
            self.run_action()
        self.assertEqual(caught.exception.http_action_observation, observation)
        self.assertEqual(len(self.fixture.load_state()["consumed"]), 1)

    def test_preconnect_refusal_is_not_allow_and_claim_remains(self):
        self.send.side_effect = http.RuntimeHttpActionError("HTTP_NAMESPACE_CHANGED")
        with self.assertRaises(subject.broker.RuntimeActionBrokerError) as caught:
            self.run_action()
        self.assertNotIsInstance(
            caught.exception, subject.broker.RuntimeActionEffectIndeterminate
        )
        self.assertEqual(len(self.fixture.load_state()["consumed"]), 1)

    def test_interrupt_preserves_exception_and_claim(self):
        failure = KeyboardInterrupt()
        failure.http_action_observation = {"sent_bytes": None}
        self.send.side_effect = failure
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_action()
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(self.fixture.load_state()["consumed"]), 1)

    def test_cleanup_failure_after_send_is_indeterminate(self):
        original = subject.broker._release_lock_and_close

        def close(*args):
            original(*args)
            return OSError("cleanup failed")

        with patch.object(subject.broker, "_release_lock_and_close", side_effect=close):
            with self.assertRaises(
                subject.broker.RuntimeActionEffectIndeterminate
            ) as caught:
                self.run_action()
        self.assertEqual(caught.exception.http_action_observation["status"], "SENT")

    def test_clock_rollback_blocks_transport(self):
        values = iter([100, 99])
        result = self.run_action(clock=lambda: next(values))
        self.assertEqual(result["reason_codes"], ["BROKER_CLOCK_ROLLBACK"])
        self.send.assert_called_once()
        self.assertNotIn("transport", self.sequence)

    def test_final_clock_rollover_rechecks_once(self):
        values = iter([100, 100, 101, 101, 101, 101, 101])
        self.assertEqual(
            self.run_action(clock=lambda: next(values))["verdict"], "ALLOW"
        )

    def test_deadline_refused_before_any_claim_or_transport(self):
        for deadline in (True, float("nan"), float("inf"), 99, 101):
            with (
                self.subTest(deadline=deadline),
                patch.object(subject.time, "monotonic", return_value=100),
            ):
                with self.assertRaises(subject.broker.RuntimeActionBrokerError):
                    self.run_action(deadline_monotonic=deadline)
        self.send.assert_not_called()
        self.assertEqual(self.fixture.load_state()["consumed"], [])

    def test_bad_digest_and_destination_override_refused_without_claim(self):
        for mutate in (
            lambda s: s.update(request_digest="sha256:" + "f" * 64),
            lambda s: s["envelope"]["effect"].update(url="https://example.com"),
            lambda s: s.update(schema="aragorn/runtime-observed-create-submission/v1"),
        ):
            value = copy.deepcopy(self.submission)
            mutate(value)
            with self.assertRaises(subject.broker.RuntimeActionBrokerError):
                subject.mediate_observed_http(value, self.fixture.config)
        self.send.assert_not_called()
        self.assertEqual(self.fixture.load_state()["consumed"], [])

    def test_measurement_failure_prevents_transport(self):
        self.final.side_effect = subject.broker.RuntimeActionBrokerError(
            "measurement refused"
        )
        with self.assertRaises(subject.broker.RuntimeActionBrokerError):
            self.run_action()
        self.send.assert_called_once()
        self.assertNotIn("transport", self.sequence)
        self.assertEqual(len(self.fixture.load_state()["consumed"]), 1)

    def test_malformed_successful_transport_result_stays_indeterminate(self):
        self.send.side_effect = None
        self.send.return_value = {"status": "SENT"}
        with self.assertRaises(subject.broker.RuntimeActionEffectIndeterminate):
            self.run_action()
        self.assertEqual(len(self.fixture.load_state()["consumed"]), 1)

    def test_final_claim_change_blocks_transport(self):
        original = subject.broker._evaluate_snapshot

        def evaluate(*args, **kwargs):
            state, observed, decision, reasons = original(*args, **kwargs)
            if "minimum_state" in kwargs:
                state["consumed"] = []
            return state, observed, decision, reasons

        with patch.object(subject.broker, "_evaluate_snapshot", side_effect=evaluate):
            result = self.run_action()
        self.assertEqual(result["reason_codes"], ["BROKER_CLAIM_STATE_CHANGED"])
        self.send.assert_called_once()
        self.assertNotIn("transport", self.sequence)

    def test_expired_health_is_not_renewed_by_http_activity(self):
        f = self.fixture
        f.health["observed_at_unix"] = 90
        f.health["expires_at_unix"] = 99
        _write_control(f.paths["health"], f.health)
        before = f.paths["health"].read_bytes()
        result = self.run_action()
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(f.paths["health"].read_bytes(), before)
        self.send.assert_not_called()

    def test_expiry_during_transport_guards_prevents_connection(self):
        now = 100
        normal = self.transport

        def guarded(*args, **kwargs):
            nonlocal now
            now = 104
            return normal(*args, **kwargs)

        self.send.side_effect = guarded
        self.assertEqual(self.run_action(clock=lambda: now)["verdict"], "BLOCK")
        self.assertNotIn("transport", self.sequence)

    def test_partial_failure_and_cleanup_preserve_observation(self):
        partial = {"connect_attempted": True, "sent_bytes": None}
        self.send.side_effect = http.RuntimeHttpActionIndeterminate(
            "HTTP_TRANSPORT_FAILED", partial
        )
        original = subject.broker._release_lock_and_close

        def close(*args):
            original(*args)
            return OSError("cleanup")

        with patch.object(subject.broker, "_release_lock_and_close", side_effect=close):
            with self.assertRaises(
                subject.broker.RuntimeActionEffectIndeterminate
            ) as caught:
                self.run_action()
        self.assertEqual(caught.exception.http_action_observation, partial)

    def test_interrupt_and_cleanup_preserve_original_interrupt(self):
        interrupted = KeyboardInterrupt()
        interrupted.http_action_observation = {
            "connect_attempted": True,
            "sent_bytes": None,
        }
        self.send.side_effect = interrupted
        original = subject.broker._release_lock_and_close

        def close(*args):
            original(*args)
            return OSError("cleanup")

        with patch.object(subject.broker, "_release_lock_and_close", side_effect=close):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.run_action()
        self.assertIs(caught.exception, interrupted)

    def test_publisher_rejects_forged_measured_action(self):
        self.submission["measured_action"]["payload_digest"] = "sha256:" + "f" * 64
        with self.assertRaises(subject.broker.RuntimeActionBrokerError):
            self.run_action()
        self.send.assert_not_called()
        self.assertEqual(self.fixture.load_state()["consumed"], [])
