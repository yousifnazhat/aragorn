"""Inert lifecycle wiring. No worker, guest, ptrace, listener or data collection."""
from contextlib import ExitStack, nullcontext
from pathlib import Path
import queue
import threading
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn import pi_core_native_supervisor as native
from aragorn import pi_core_node_source_observer as node
from aragorn import pi_core_stopped_mask_capture as capture_module


def custody():
    # Native capture and its custody validator are replaced at the kernel
    # boundary; this object must not supply a callback or open a store.
    return capture_module.StoppedMaskCapture(Path("/evidence/objects"), Path("/evidence/receipts"), "a"*32,
        *("sha256:" + c*64 for c in "123"), "253:7", ("259:0",), "ext4")


class OwnerHook(TestCase):
    def owner(self, error=None, health=False, arm_error=None):
        held = custody()
        with ExitStack() as st:
            st.enter_context(mock.patch.object(node, "validate_node_profile", return_value={}))
            s = node._NodeSession(object(), {}, 10.0, 15.0)
            s._mask_capture = held
            s.observer.close_after_exit = mock.Mock()
            s._budget, s._drain = mock.Mock(), mock.Mock(return_value=False)
            s._pump, s._resume = mock.Mock(), mock.Mock()
            s._barrier = mock.Mock()
            st.enter_context(mock.patch.object(node.base, "_tick", return_value=1))
            st.enter_context(mock.patch.object(node.time, "sleep"))
            transitions = []
            def arm(session):
                self.assertIs(s, session)
                transitions.append(("arm", threading.get_native_id()))
                if arm_error:
                    raise arm_error
            def retain(session, value, *, deadline):
                self.assertIs(session, s)
                self.assertIs(held, value)
                self.assertEqual(deadline, 10.0)
                self.assertFalse(s.ready.is_set())
                transitions.append(("capture", threading.get_native_id()))
                if error:
                    raise error
                return {"reference": "inert"}
            st.enter_context(mock.patch.object(node, "_arm", side_effect=arm))
            st.enter_context(mock.patch.object(capture_module, "capture_stopped_masks", side_effect=retain))
            health_result = []
            script = [None, *(["health"] if health else []), "stop", "close"]
            def command(*args, **kwargs):
                self.assertTrue(s.ready.is_set())
                op = script.pop(0)
                if op is None:
                    raise queue.Empty()
                return op, None, 15.0, threading.Event(), health_result if op == "health" else []
            s.commands = mock.Mock(get=command, get_nowait=command)
            s._main()
            expected = [("arm", s.observer._thread)]
            if not arm_error:
                expected.append(("capture", s.observer._thread))
            self.assertEqual(transitions, expected)
            self.assertEqual(script, [])
            self.assertTrue(s.closed.is_set())
            s._pump.assert_not_called()
            s._resume.assert_not_called()
            s._barrier.assert_not_called()
            s.observer.close_after_exit.assert_called_once()
            return s, health_result

    def test_capture_precedes_ready_and_only_exit_drain_follows(self):
        session, _ = self.owner()
        self.assertIsNone(session.failure)
        self.assertEqual(session._mask_receipt, {"reference": "inert"})
        session._drain.assert_called_once_with(15.0)

    def test_capture_timeout_stays_parked_for_cleanup_no_retry(self):
        failure = TimeoutError("inert deadline")
        session, _ = self.owner(failure)
        self.assertIs(session.failure, failure)
        self.assertIsNone(session._mask_receipt)

    def test_failed_gate_custody_never_enters_capture_or_resume(self):
        failure = ValueError("inert gate generation changed")
        session, _ = self.owner(arm_error=failure)
        self.assertIs(session.failure, failure)
        self.assertIsNone(session._mask_receipt)

    def test_health_cannot_turn_parked_capture_into_a_pump(self):
        session, health = self.owner(health=True)
        self.assertIsNotNone(session.failure)
        self.assertIsInstance(health[0], node.base.PiSourceObserverError)


class CaptureSupervisor(TestCase):
    def setUp(self):
        st = self.st = ExitStack()
        self.addCleanup(st.close)
        self.custody = custody()
        object.__setattr__(self.custody, "store", Path("/evidence/objects"))
        object.__setattr__(self.custody, "receipt_directory", Path("/evidence/receipts"))
        prof = {"schema": node.restricted.PROFILE_SCHEMA}
        self.config = object.__new__(native.PiConfinedLaunchConfig)
        for name, value in dict(native_request=True, source_observation=prof, provider_route_digest=None,
                                worker_uid=101, worker_gid=102, root_directory=Path("/fixture/worker"),
                                runtime_directory=Path("/fixture/runtime"),
                                activation_directory=Path("/fixture/activation")).items():
            object.__setattr__(self.config, name, value)
        self.plan = native.PiConfinedLaunchPlan(SimpleNamespace(deployment_digest="deployment"), None, 101, 102,
            "inert.service", ("inert",),
            Path("/never/open"), b"never sent", 15.0, "", "", None,
            source_observation=prof, source_observation_digest=native.canonical_digest(prof))
        def replace(module, name, **options):
            return st.enter_context(mock.patch.object(module, name, **options))
        replace(native.time, "monotonic", return_value=1.0)
        self.prep = replace(native, "_prerequisites")
        self.preflight = replace(capture_module.StoppedMaskCapture, "preflight")
        self.receipt = {"ref": "inert", "mask_consistent": True}
        replace(native, "hold_confined_pi_launch_plan", return_value=nullcontext(self.plan))
        replace(native, "_start", return_value=self.plan.start_bytes)
        replace(native, "_unit_state", return_value={})
        replace(native, "_absent", return_value=True)
        self.resources = replace(native, "_prepare_resources")
        self.start = replace(native, "_command", return_value=(0, b""))
        def capture_unit(owned, deadline):
            owned.pid, owned.start_ticks, owned.invocation = 71, 10, "held"
        replace(native, "_capture_unit", side_effect=capture_unit)
        self.arm = replace(node, "_start_stopped_mask_observer")
        self.cleanup = replace(native, "_cleanup", return_value={"status": "VERIFIED_OWNED_CLEANUP"})
        self.close = replace(native, "_close_handles")
        self.exchange = replace(native, "exchange_prepared_pi_bootstrap")
        self.register = replace(native, "hold_pi_identity_handoff")

    def run_capture(self):
        return native.run_native_pi_stopped_mask_capture(None, {}, profile=None, grant={}, protected_root=Path("/fixture/admitted"),
            runtime_conformance_digest="", deployment={}, revoked_context_ids=(), now_unix=0, deadline=20.0,
            config=self.config, capture=self.custody)

    def stub_observer(self, owned, profile, **options):
        self.assertEqual(options, dict(capture=self.custody, operation_deadline=15.0, cleanup_deadline=20.0))
        obs = node.base.PiSourceObserver(node.base._SEAL)
        obs._owned = owned
        obs._node_session = mock.Mock(_mask_capture=self.custody, _mask_receipt=self.receipt)
        return obs

    def was_cleanup_only(self):
        self.start.assert_called_once_with(self.plan.systemd_run_argv, 15.0)
        self.preflight.assert_called_once_with(deployment_digest="deployment",
            profile_digest=self.plan.source_observation_digest, deadline=15.0)
        self.cleanup.assert_called_once_with(self.arm.call_args.args[0], 20.0, 5.0)
        self.close.assert_called_once_with(self.arm.call_args.args[0])
        self.exchange.assert_not_called()
        self.register.assert_not_called()

    def test_capture_does_not_exchange_or_publish_and_cleanup_remains_owned(self):
        self.arm.side_effect = self.stub_observer
        result = self.run_capture()
        self.assertEqual((result["status"], result["retention"]), ("CAPTURE_RETAINED_ONLY", self.receipt))
        self.was_cleanup_only()

    def test_inconsistent_capture_retained_without_positive_claim(self):
        self.receipt["mask_consistent"] = False
        self.arm.side_effect = self.stub_observer
        result = self.run_capture()
        self.assertEqual((result["status"], result["retention"]), ("CAPTURE_RETAINED_INCONSISTENT", self.receipt))
        self.was_cleanup_only()

    def test_nonboolean_mask_finding_refused_even_when_truthy(self):
        self.receipt["mask_consistent"] = 1
        self.arm.side_effect = self.stub_observer
        result = self.run_capture()
        self.assertEqual((result["status"], result["retention"]), ("REFUSED", self.receipt))
        self.was_cleanup_only()

    def test_uncertain_cleanup_blocks_even_after_retention(self):
        self.arm.side_effect = self.stub_observer
        self.cleanup.return_value = {"status": "CLEANUP_HOLD"}
        result = self.run_capture()
        self.assertEqual((result["status"], result["retention"]), ("CLEANUP_HOLD", self.receipt))
        self.was_cleanup_only()

    def test_cleanup_exception_retains_receipt_attempts_handle_close_without_retry(self):
        self.arm.side_effect = self.stub_observer
        self.cleanup.side_effect = RuntimeError("inert close assertion")
        with self.assertRaises(RuntimeError) as raised:
            self.run_capture()
        result = raised.exception.pi_stopped_mask_observation
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["retention"], self.receipt)
        self.was_cleanup_only()

    def test_preflight_refusal_precedes_resources_and_start(self):
        self.preflight.side_effect = ValueError("inert deployment differs")
        with self.assertRaises(ValueError):
            self.run_capture()
        self.resources.assert_not_called()
        self.start.assert_not_called()

    def test_overlap_in_either_direction_rejected_for_either_destination(self):
        for field in ("store", "receipt_directory"):
            original = getattr(self.custody, field)
            for path in (Path("/fixture/worker"), Path("/fixture/runtime/x"),
                         Path("/fixture/admitted/x"), Path("/fixture/activation/x"),
                         native._BOOTSTRAP / "x", Path("/fixture"), native._BOOTSTRAP.parent):
                with self.subTest(field=field, path=path):
                    object.__setattr__(self.custody, field, path)
                    with self.assertRaisesRegex(native.PiNativeSupervisorError, "overlaps"):
                        self.run_capture()
                    self.preflight.assert_not_called()
                    self.resources.assert_not_called()
                    self.start.assert_not_called()
            object.__setattr__(self.custody, field, original)

    def test_arm_timeout_preserves_observer_for_one_owned_cleanup(self):
        def timed_out(*args, **kwargs):
            raise node.base.PiSourceObserverError("NODE_ARM_TIMEOUT", self.stub_observer(*args, **kwargs))
        self.arm.side_effect = timed_out
        result = self.run_capture()
        self.assertEqual((result["status"], result["retention"]), ("REFUSED", None))
        self.assertIsNotNone(self.cleanup.call_args.args[0].source_observer)
        self.was_cleanup_only()

    def test_capture_requires_concrete_custody_before_prerequisites(self):
        self.custody = lambda: None
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_capture()
        self.prep.assert_not_called()
        self.start.assert_not_called()

    def test_provider_enabled_configuration_rejected_before_start(self):
        object.__setattr__(self.config, "provider_route_digest", "sha256:" + "a" * 64)
        with self.assertRaises(native.PiNativeSupervisorError):
            self.run_capture()
        self.prep.assert_not_called()
        self.start.assert_not_called()
