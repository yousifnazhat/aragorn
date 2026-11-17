"""Retained native failure observations; every operational edge stays inert."""

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_native_request as request
from aragorn import pi_core_native_supervisor as subject
from aragorn.oci_worker_protocol import WorkerProtocolError
from tests import test_pi_core_native_supervisor as native_fixtures
from tests import test_pi_core_native_provider_wiring as provider_fixtures
from tests import test_pi_core_identity_supervisor as identity_fixtures


def fixture(test, kind):
    result = kind(methodName="runTest")
    result.setUp()
    test.addCleanup(result.doCleanups)
    return result


class NativeFailureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, native_fixtures.NativeOrchestrationTests)
        for target in ("os.open", "os.close", "os.unlink", "socket.socketpair"):
            self.enterContext(mock.patch(target, side_effect=AssertionError("no native operations")))
        self.exit_error = None
        self.exit_action = None
        @contextmanager
        def held(*args, **kwargs):
            self.f.events.append("lease_enter")
            try:
                yield self.f.plan
            finally:
                self.f.events.append("lease_exit")
                if self.exit_action is not None:
                    self.exit_action()
                if self.exit_error is not None:
                    raise self.exit_error
        self.f.hold.side_effect = held

    def escaped(self, error):
        with self.assertRaises(type(error)) as caught:
            self.f.run_worker()
        self.assertIs(caught.exception, error)
        result = error.pi_native_supervisor_observation
        self.assertEqual(result["schema"], "aragorn/pi-core-native-supervisor-result/v1")
        self.assertEqual(result["authority"],
            "BOOTSTRAP_AND_OWNED_CLEANUP_ONLY_NOT_EFFECT_RUN_OR_PHASE3_QUALIFICATION")
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["failure_evidence"]["launch_scope_cleanup"], "UNVERIFIED_ON_EXCEPTION")
        return result

    def observer(self, *, capture=None, health=None):
        class Observer:
            pass
        self.capture = self.enterContext(mock.patch.object(Observer, "observation", create=True,
            new_callable=mock.PropertyMock, return_value={"source": "retained"} if capture is None else capture))
        self.health = self.enterContext(mock.patch.object(Observer, "health_observation", create=True,
            new_callable=mock.PropertyMock, return_value={"progress": 1} if health is None else health))
        original_cleanup = self.f.cleanup.side_effect
        def cleanup(owned, *args):
            result = original_cleanup(owned, *args)
            owned.source_observer = Observer()
            owned.source_observer_closed = True
            return result
        self.f.cleanup.side_effect = cleanup

    def test_completed_terminal_is_retained_when_launch_scope_exit_fails(self):
        error = self.exit_error = OSError("inert held descriptor refusal")
        result = self.escaped(error)
        self.assertEqual(result["bootstrap"], {"status": "PROVIDER_UNAVAILABLE"})
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(result["pid"], 1234)
        self.assertEqual(result["failure_evidence"]["stage"], "LAUNCH_SCOPE_EXIT")
        self.assertTrue(result["failure_evidence"]["worker_started"])
        self.f.hold.assert_called_once()
        self.f.command.assert_called_once_with(self.f.plan.systemd_run_argv, 115)
        self.f.cleanup.assert_called_once_with(self.f.owned, 120.0, 5.0)
        self.f.close.assert_called_once_with(self.f.owned)
        self.assertEqual(self.f.events, ["lease_enter", "cleanup", "lease_exit"])

    def test_refused_terminal_and_actual_failure_remain_after_scope_exit_error(self):
        self.f.command.return_value = (1, b"")
        error = self.exit_error = OSError("inert held exit")
        result = self.escaped(error)
        self.assertIsNone(result["bootstrap"])
        self.assertIn("one-shot transient service start failed", result["failure"])
        self.assertTrue(result["failure_evidence"]["worker_start_attempted"])
        self.assertFalse(result["failure_evidence"]["worker_started"])
        self.assertEqual(result["failure_evidence"]["stage"], "LAUNCH_SCOPE_EXIT")
        self.f.command.assert_called_once()

    def test_terminal_snapshot_precedes_held_scope_mutation(self):
        raw = {"result": {"value": 6}}
        self.f.exchange.side_effect = None
        self.f.exchange.return_value = raw
        self.exit_action = lambda: raw["result"].update(value=99)
        error = self.exit_error = OSError("inert exit")
        result = self.escaped(error)
        self.assertEqual(result["bootstrap"], {"result": {"value": 6}})
        self.assertEqual(raw["result"]["value"], 99)

    def test_clean_scope_returns_detached_terminal_without_failure_metadata(self):
        raw = {"result": {"value": 6}}
        self.f.exchange.side_effect = None
        self.f.exchange.return_value = raw
        self.exit_action = lambda: raw["result"].update(value=99)
        result = self.f.run_worker()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertEqual(result["bootstrap"], {"result": {"value": 6}})
        self.assertNotIn("failure_evidence", result)
        self.assertEqual(self.f.events[-1], "lease_exit")

    def test_acquisition_failure_keeps_every_unacquired_owner_unknown(self):
        error = OSError("inert admission acquisition refusal")
        self.f.hold.side_effect = error
        result = self.escaped(error)
        for field in ("unit", "pid", "bootstrap", "cleanup", "request_channel", "provider_channel",
                      "identity_registration", "source_observation"):
            self.assertIsNone(result[field])
        self.assertIsNone(result["failure_evidence"]["worker_start_attempted"])
        self.assertEqual(result["failure_evidence"]["last_stage"], "LAUNCH_SCOPE_ACQUIRE")
        self.f.prepare.assert_not_called()
        self.f.cleanup.assert_not_called()
        self.f.close.assert_not_called()

    def test_body_cancellation_retains_cleanup_without_fabricating_terminal_output(self):
        error = KeyboardInterrupt()
        self.f.exchange.side_effect = error
        result = self.escaped(error)
        self.assertIsNone(result["bootstrap"])
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(result["failure_evidence"]["stage"], "INCOMPLETE_NATIVE_SCOPE")
        self.assertEqual(result["failure_evidence"]["last_stage"], "HANDLE_CLEANUP")
        self.f.cleanup.assert_called_once()
        self.f.close.assert_called_once()
        self.f.exchange.assert_called_once()

    def test_prestart_cancellation_does_not_claim_a_start_attempt(self):
        error = KeyboardInterrupt()
        self.f.prepare.side_effect = error
        result = self.escaped(error)
        self.assertFalse(result["failure_evidence"]["worker_start_attempted"])
        self.assertFalse(result["failure_evidence"]["worker_started"])
        self.assertIsNone(result["pid"])
        self.f.command.assert_not_called()
        self.f.cleanup.assert_called_once()

    def test_worker_cleanup_exception_does_not_resume_skipped_handle_cleanup(self):
        error = OSError("inert worker cleanup failure")
        self.f.cleanup.side_effect = error
        result = self.escaped(error)
        self.assertIsNone(result["cleanup"])
        self.assertEqual(result["bootstrap"], {"status": "PROVIDER_UNAVAILABLE"})
        self.assertEqual(result["failure_evidence"]["last_stage"], "WORKER_CLEANUP")
        self.f.cleanup.assert_called_once()
        self.f.close.assert_not_called()

    def test_handle_cleanup_cancellation_preserves_worker_cleanup_without_second_close(self):
        error = KeyboardInterrupt()
        self.f.close.side_effect = error
        result = self.escaped(error)
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(result["failure_evidence"]["last_stage"], "HANDLE_CLEANUP")
        self.f.close.assert_called_once()
        self.f.cleanup.assert_called_once()

    def test_cleanup_replacement_preserves_same_escaped_error_and_cancellation_context(self):
        interrupted = KeyboardInterrupt()
        self.f.exchange.side_effect = interrupted
        error = OSError("inert replacement cleanup failure")
        self.f.cleanup.side_effect = error
        result = self.escaped(error)
        self.assertIs(error.__context__, interrupted)
        self.assertIsNone(result["cleanup"])
        self.assertIsNone(result["bootstrap"])
        self.f.close.assert_not_called()

    def test_scope_exit_replacement_cannot_claim_a_completed_terminal(self):
        interrupted = KeyboardInterrupt()
        self.f.exchange.side_effect = interrupted
        error = self.exit_error = OSError("inert held-plan replacement")
        result = self.escaped(error)
        self.assertIs(error.__context__, interrupted)
        self.assertIsNone(result["bootstrap"])
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(result["failure_evidence"]["stage"], "INCOMPLETE_NATIVE_SCOPE")

    def test_failed_source_capture_read_keeps_other_records_and_is_never_repeated(self):
        self.observer()
        error = OSError("inert capture snapshot refusal")
        self.capture.side_effect = error
        result = self.escaped(error)
        self.assertEqual(result["bootstrap"], {"status": "PROVIDER_UNAVAILABLE"})
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertIsNone(result["source_observation"]["capture"])
        self.assertIsNone(result["source_observation"]["latest_health_capture"])
        self.assertEqual(result["failure_evidence"]["last_stage"], "TERMINAL_SNAPSHOT")
        self.capture.assert_called_once_with()
        self.health.assert_not_called()

    def test_failed_health_snapshot_preserves_prior_source_capture(self):
        self.observer()
        error = OSError("inert health snapshot refusal")
        self.health.side_effect = error
        result = self.escaped(error)
        self.assertEqual(result["source_observation"]["capture"], {"source": "retained"})
        self.assertIsNone(result["source_observation"]["latest_health_capture"])
        self.capture.assert_called_once_with()
        self.health.assert_called_once_with()
        self.f.cleanup.assert_called_once()
        self.f.close.assert_called_once()

    def test_noncanonical_terminal_field_does_not_erase_other_owner_records(self):
        self.f.exchange.side_effect = None
        self.f.exchange.return_value = {"noncanonical": float("nan")}
        with self.assertRaises(WorkerProtocolError) as caught:
            self.f.run_worker()
        result = caught.exception.pi_native_supervisor_observation
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertIsNone(result["bootstrap"])
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(result["failure_evidence"]["uncertainty"], ["bootstrap"])

    def test_malformed_held_plan_metadata_cannot_replace_original_validation_failure(self):
        good_plan = self.f.plan
        self.f.plan = object()
        channels = object.__new__(request.PiNativeRequestChannels)
        with self.assertRaisesRegex(subject.PiNativeSupervisorError, "held Pi START") as caught:
            subject.run_native_pi_worker(object(), {}, profile=good_plan.profile, grant={},
                protected_root=Path("/var/lib/aragorn/admitted"), runtime_conformance_digest="sha256:" + "a" * 64,
                deployment={}, revoked_context_ids=(), now_unix=1, deadline=120.0,
                config=SimpleNamespace(native_request=True), request_channels=channels)
        result = caught.exception.pi_native_supervisor_observation
        self.assertIsNone(result["unit"])
        self.assertIsNone(result["cleanup"])
        self.assertEqual(result["failure_evidence"]["uncertainty"], ["native_metadata"])
        self.f.prepare.assert_not_called()
        self.f.cleanup.assert_not_called()

    def test_original_error_survives_report_assembly_failure(self):
        error = self.exit_error = OSError("inert held cleanup failure")
        with mock.patch.object(subject, "_retain_native_failure", side_effect=KeyboardInterrupt()):
            with self.assertRaises(OSError) as caught:
                self.f.run_worker()
        self.assertIs(caught.exception, error)
        self.f.cleanup.assert_called_once()
        self.f.close.assert_called_once()

    def test_existing_error_survives_field_snapshot_failure(self):
        error = self.exit_error = OSError("original cleanup failure")
        canonical = subject.canonical_json
        def serialize(value):
            if value == {"status": "PROVIDER_UNAVAILABLE"}:
                raise KeyboardInterrupt("inert secondary snapshot failure")
            return canonical(value)
        with mock.patch.object(subject, "canonical_json", side_effect=serialize):
            result = self.escaped(error)
        self.assertIsNone(result["bootstrap"])
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(result["failure_evidence"]["uncertainty"], ["bootstrap"])

    def test_oversized_field_keeps_other_evidence_and_does_not_become_success(self):
        self.f.exchange.side_effect = None
        self.f.exchange.return_value = {"oversized": "x" * (4 * 1024 * 1024)}
        error = self.exit_error = OSError("inert held cleanup failure")
        result = self.escaped(error)
        self.assertIsNone(result["bootstrap"])
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(result["failure_evidence"]["uncertainty"], ["bootstrap"])

    def test_preexisting_exception_record_is_replaced_by_this_invocation_only(self):
        error = KeyboardInterrupt()
        error.pi_native_supervisor_observation = {"status": "BOOTSTRAP_COMPLETE", "bootstrap": {"forged": True}}
        self.f.exchange.side_effect = error
        result = self.escaped(error)
        self.assertIsNone(result["bootstrap"])
        self.assertNotIn("forged", repr(result))

    def test_exception_attachment_refusal_preserves_original_object(self):
        class SealedError(OSError):
            def __setattr__(self, key, value):
                if key == "pi_native_supervisor_observation":
                    raise TypeError("inert attachment refusal")
                super().__setattr__(key, value)
        error = self.exit_error = SealedError("original scope error")
        with self.assertRaises(SealedError) as caught:
            self.f.run_worker()
        self.assertIs(caught.exception, error)
        self.assertFalse(hasattr(error, "pi_native_supervisor_observation"))
        self.f.cleanup.assert_called_once()
        self.f.close.assert_called_once()


class NativeOwnerEvidenceTests(unittest.TestCase):
    def test_provider_and_request_terminal_records_survive_held_plan_failure(self):
        f = fixture(self, provider_fixtures.ProviderNativeCallerTests)
        error = OSError("inert held-plan failure")
        @contextmanager
        def held(*args, **kwargs):
            yield f.f.plan
            raise error
        f.f.hold.side_effect = held
        with self.assertRaises(OSError) as caught:
            f.run_worker()
        self.assertIs(caught.exception, error)
        result = error.pi_native_supervisor_observation
        self.assertEqual(result["request_channel"], f.r.observation)
        self.assertEqual(result["provider_channel"], f.p.observation)
        self.assertEqual(result["source_observation"]["capture"], {})
        self.assertEqual(result["source_observation"]["latest_health_capture"], {})
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(f.f.events.count("request_close"), 1)
        self.assertEqual(f.f.events.count("provider_close"), 1)
        f.f.cleanup.assert_called_once()
        f.f.close.assert_called_once()
        f.hold_provider.assert_called_once()

    def test_revoked_identity_evidence_is_retained_without_repeating_revocation(self):
        f = fixture(self, identity_fixtures.IdentitySupervisorTests)
        error = OSError("inert plan descriptor failure")
        @contextmanager
        def held(*args, **kwargs):
            yield f.plan
            raise error
        f.hold.side_effect = held
        with self.assertRaises(OSError) as caught:
            f.run_worker()
        self.assertIs(caught.exception, error)
        result = error.pi_native_supervisor_observation
        self.assertEqual(result["identity_registration"]["status"], "REVOKED")
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(f.events.count("revoke_attempt"), 1)
        f.handoff.assert_called_once()
        f.relay.close.assert_not_called()
        f.cleanup.assert_called_once()


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(NativeFailureEvidenceTests)
    suite.addTests(loader.loadTestsFromTestCase(NativeOwnerEvidenceTests))
    for name in (
        "test_one_start_trusted_pid_exchange_and_cleanup_inside_admission",
        "test_start_failure_is_attempted_once_and_never_bootstraps",
        "test_start_timeout_retains_uncertain_state_for_cleanup_hold",
        "test_callback_failure_prevents_bootstrap_success",
        "test_cleanup_hold_overrides_successful_bootstrap",
        "test_handle_close_failure_cannot_report_clean_completion",
    ):
        suite.addTest(native_fixtures.NativeOrchestrationTests(name))
    for name in (
        "test_native_caller_opens_both_then_closes_before_release_and_unit_cleanup",
        "test_provider_cleanup_hold_is_not_promoted_by_bootstrap",
    ):
        suite.addTest(provider_fixtures.ProviderNativeCallerTests(name))
    return suite
