"""New identity-registration/native callback checks, with all native edges inert."""

import json
import os
import socket
import subprocess
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import pi_core_confined_launch as confined
from aragorn import pi_core_native_supervisor as native
from aragorn.pi_core_identity_handoff import PiIdentityHandoffError
from aragorn.oci_worker_protocol import canonical_json
from aragorn.runtime_process_profile import RuntimeProcessProfile


def plan():
    unit = "aragorn-pi-" + "a" * 32 + ".service"
    profile = RuntimeProcessProfile("sha256:" + "a" * 64, "sha256:" + "b" * 64,
        "/system.slice/" + unit, Path("/var/lib/aragorn/admitted/version/SKILL.md"),
        "sha256:" + "c" * 64)
    prepared = SimpleNamespace(activation_id="a" * 32, system_prompt="inert",
        skill_path=profile.skill_path, _lease=SimpleNamespace(active=True),
        expires_at_monotonic_ns=120_000_000_000)
    return confined.PiConfinedLaunchPlan(prepared, profile, 1101, 1102, unit,
        ("/usr/bin/systemd-run", "--unit=" + unit),
        Path("/var/lib/aragorn/pi-activations") / ("a" * 32 + ".json"),
        canonical_json({"schema": "aragorn/pi-core-bootstrap-start/v1"}),
        115.0, "sha256:" + "d" * 64, profile.runtime_digest, confined._PlanLease())


def absent(unit):
    return {"Id": unit, "LoadState": "not-found", "ActiveState": "inactive",
            "SubState": "dead", "MainPID": "0", "ControlPID": "0", "InvocationID": ""}


class InertTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(native.time, "monotonic", return_value=100.0))
        self.stack.enter_context(mock.patch.object(native.time, "monotonic_ns", return_value=100_000_000_000))
        self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
        for owner, name in ((subprocess, "run"), (subprocess, "Popen"), (socket, "socket"),
                            (socket, "create_connection"), (os, "system"), (os, "open"),
                            (os, "close"), (os, "unlink")):
            self.stack.enter_context(mock.patch.object(owner, name,
                side_effect=AssertionError("native operation forbidden in focused identity checks")))
        for name in ("fork", "posix_spawn", "posix_spawnp", "pidfd_open"):
            self.stack.enter_context(mock.patch.object(os, name, create=True,
                side_effect=AssertionError("native process/PIDFD operation forbidden")))
        for name in ("_read_virtual_file", "_process_start_time", "_process_cgroup", "_cgroup_processes",
                     "require_live_pidfd", "measure_runtime_process_profile", "open_peer_pidfd"):
            self.stack.enter_context(mock.patch.object(native.process, name,
                side_effect=AssertionError("live kernel read forbidden")))


class IdentitySupervisorTests(InertTests):
    def setUp(self):
        super().setUp()
        self.plan = plan()
        self.events = []
        self.document = {"fixture": "root-authenticated-activation"}
        self.relay = mock.Mock()
        self.peer = (400, 1301, 1302)
        self.worker = mock.Mock()
        self.listener = mock.Mock()
        self.listener.accept.return_value = (self.worker, "")
        self.registration_failure = None
        self.revocation_failure = None

        @contextmanager
        def held(*args, **kwargs):
            self.events.append("lease_enter")
            yield self.plan
            self.events.append("lease_exit")

        self.prereq = self.stack.enter_context(mock.patch.object(native, "_prerequisites"))
        self.hold = self.stack.enter_context(mock.patch.object(native, "hold_confined_pi_launch_plan", side_effect=held))
        self.state = self.stack.enter_context(mock.patch.object(native, "_unit_state", side_effect=[
            absent(self.plan.unit_name), absent(self.plan.unit_name), *[{"fixture": "same-generation"}] * 20]))

        def prepare(owned):
            self.owned = owned
            owned.listener = self.listener

        self.stack.enter_context(mock.patch.object(native, "_prepare_resources", side_effect=prepare))
        self.command = self.stack.enter_context(mock.patch.object(native, "_command", return_value=(0, b"")))

        def capture(owned, deadline):
            owned.pid, owned.pidfd = 1234, 73
            owned.invocation, owned.start_ticks = "1" * 32, 5

        self.stack.enter_context(mock.patch.object(native, "_capture_unit", side_effect=capture))
        self.same = self.stack.enter_context(mock.patch.object(native, "_same_generation"))
        self.custody = self.stack.enter_context(mock.patch.object(native, "_resource_ownership"))
        self.measured = self.stack.enter_context(mock.patch.object(native.pi_identity, "_measured"))
        self.read_activation = self.stack.enter_context(mock.patch.object(native, "read_activation", return_value=self.document))
        self.capture_activation = self.stack.enter_context(mock.patch.object(native, "_capture_activation",
            side_effect=lambda *_: self.events.append("capture_activation")))

        @contextmanager
        def handoff(connection, document, pidfd, *, expected_relay_peer, deadline, guard):
            self.assertIs(connection, self.relay)
            self.assertEqual(document, self.document)
            self.assertEqual((pidfd, expected_relay_peer, deadline), (73, self.peer, 115.0))
            guard()
            if self.registration_failure:
                raise self.registration_failure
            state = {"authority": native.IDENTITY_AUTHORITY, "status": "REGISTERED"}
            self.events.append("registered")
            try:
                yield state
            finally:
                self.events.append("revoke_attempt")
                guard()
                if self.revocation_failure:
                    raise self.revocation_failure
                state["status"] = "REVOKED"
                self.events.append("revoked")

        self.handoff = self.stack.enter_context(mock.patch.object(native, "hold_pi_identity_handoff", side_effect=handoff))

        def exchange(value, connection, *, expected_pid, on_activation, **options):
            self.assertIs(value, self.plan)
            self.assertIs(connection, self.worker)
            self.assertEqual(expected_pid, 1234)
            on_activation(self.document)
            self.events.extend(["START", "RESULT"])
            if "on_before_release" in options:
                options["on_before_release"]()
            self.events.append("RELEASE")
            return {"status": "PROVIDER_UNAVAILABLE"}

        self.exchange = self.stack.enter_context(mock.patch.object(native, "exchange_prepared_pi_bootstrap", side_effect=exchange))

        def cleanup(owned, deadline, budget):
            self.events.append("cleanup")
            self.assertNotIn("lease_exit", self.events)
            self.assertEqual((deadline, budget), (120.0, 5.0))
            return {"status": "VERIFIED_OWNED_CLEANUP"}

        self.cleanup = self.stack.enter_context(mock.patch.object(native, "_cleanup", side_effect=cleanup))
        self.close = self.stack.enter_context(mock.patch.object(native, "_close_handles"))

    def run_worker(self, *, identity=True, **options):
        arguments = {"deadline": 120.0}
        if identity:
            arguments.update(identity_relay_connection=self.relay, expected_identity_relay_peer=self.peer)
        arguments.update(options)
        return native.run_native_pi_worker(object(), {}, profile=self.plan.profile, grant={},
            protected_root=Path("/var/lib/aragorn/admitted"), runtime_conformance_digest="sha256:" + "a" * 64,
            deployment={}, revoked_context_ids=(), now_unix=1, config=mock.sentinel.config, **arguments)

    def test_no_channel_keeps_existing_bootstrap_and_explicit_not_requested(self):
        result = self.run_worker(identity=False)
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertEqual(result["identity_registration"]["status"], "NOT_REQUESTED")
        self.assertNotIn("on_before_release", self.exchange.call_args.kwargs)
        self.handoff.assert_not_called()
        self.assertEqual(self.events, ["lease_enter", "capture_activation", "START", "RESULT", "RELEASE", "cleanup", "lease_exit"])

    def test_registration_precedes_start_and_revocation_precedes_release(self):
        result = self.run_worker()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertEqual(result["identity_registration"]["status"], "REVOKED")
        self.assertEqual(self.events, ["lease_enter", "capture_activation", "registered", "START", "RESULT",
            "revoke_attempt", "revoked", "RELEASE", "cleanup", "lease_exit"])
        self.handoff.assert_called_once()
        self.assertEqual(self.events.count("revoke_attempt"), 1)
        self.relay.close.assert_not_called()

    def test_guard_remeasures_actual_accepted_peer_profile_and_original_deadline(self):
        self.run_worker()
        self.assertEqual(self.measured.call_args_list, [mock.call(self.worker, 73, self.plan.profile, self.document, 115.0)] * 2)
        self.assertEqual(self.custody.call_count, 2)
        self.assertEqual(self.read_activation.call_args_list, [mock.call(self.plan.activation_path)] * 2)
        self.assertTrue(all(call.args[2] == 115.0 and call.kwargs["live"] for call in self.same.call_args_list))
        self.assertEqual(self.hold.call_args.kwargs["deadline"], 115.0)

    def test_changed_worker_measurement_refuses_before_start_and_cleans_up(self):
        self.measured.side_effect = RuntimeError("mount namespace or executable changed")
        result = self.run_worker()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["identity_registration"]["status"], "HOLD_UNCONFIRMED")
        self.assertNotIn("START", self.events)
        self.assertNotIn("RELEASE", self.events)
        self.cleanup.assert_called_once()

    def test_changed_activation_refuses_registration(self):
        self.read_activation.return_value = {"fixture": "replacement"}
        result = self.run_worker()
        self.assertNotEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertNotIn("START", self.events)
        self.cleanup.assert_called_once()

    def test_unknown_registration_offer_remains_hold_even_after_native_cleanup(self):
        error = PiIdentityHandoffError("lost registration ack")
        error.publication = {"status": "HOLD_UNCONFIRMED", "nonce": "b" * 32}
        self.registration_failure = error
        result = self.run_worker()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(result["identity_registration"]["nonce"], "b" * 32)
        self.assertNotIn("START", self.events)
        self.assertNotIn("revoke_attempt", self.events)

    def test_preoffer_refusal_is_not_promoted_to_registered(self):
        error = PiIdentityHandoffError("refused before offer")
        error.publication = {"status": "REFUSED"}
        self.registration_failure = error
        result = self.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["identity_registration"]["status"], "REFUSED")
        self.assertNotIn("START", self.events)

    def test_failed_revoke_prevents_release_and_is_attempted_only_once(self):
        error = PiIdentityHandoffError("lost revocation ack")
        error.publication = {"status": "HOLD_UNCONFIRMED"}
        self.revocation_failure = error
        result = self.run_worker()
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertIsNone(result["bootstrap"])
        self.assertNotIn("RELEASE", self.events)
        self.assertEqual(self.events.count("revoke_attempt"), 1)
        self.cleanup.assert_called_once()
        self.relay.close.assert_not_called()

    def test_failed_bootstrap_still_revokes_before_native_cleanup(self):
        def failed(value, connection, *, on_activation, **options):
            on_activation(self.document)
            raise RuntimeError("bootstrap result refused")
        self.exchange.side_effect = failed
        result = self.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["identity_registration"]["status"], "REVOKED")
        self.assertLess(self.events.index("revoked"), self.events.index("cleanup"))
        self.assertEqual(self.events.count("revoke_attempt"), 1)

    def test_bootstrap_observation_does_not_hide_failed_final_revoke(self):
        def missing_hook(value, connection, *, on_activation, **options):
            on_activation(self.document)
            return {"status": "PROVIDER_UNAVAILABLE"}
        self.exchange.side_effect = missing_hook
        self.revocation_failure = RuntimeError("revocation uncertain")
        result = self.run_worker()
        self.assertIsNotNone(result["bootstrap"])
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["identity_registration"]["status"], "HOLD_UNCONFIRMED")

    def test_channel_and_peer_must_be_supplied_together_before_prerequisites(self):
        for fields in ({"identity_relay_connection": self.relay}, {"expected_identity_relay_peer": self.peer}):
            with self.subTest(fields=list(fields)), self.assertRaises(native.PiNativeSupervisorError):
                self.run_worker(identity=False, **fields)
        self.prereq.assert_not_called()

    def test_root_malformed_and_nonpositive_relay_peer_refuse_before_prerequisites(self):
        for peer in ((400, 0, 0), (400, 1301, 0), (0, 1301, 1302), (True, 1301, 1302),
                     (2**31, 1301, 1302), [400, 1301, 1302], (400, 1301)):
            with self.subTest(peer=peer), self.assertRaises(native.PiNativeSupervisorError):
                self.run_worker(expected_identity_relay_peer=peer)
        self.prereq.assert_not_called()

    def test_capture_failure_cannot_publish_identity(self):
        self.capture_activation.side_effect = RuntimeError("activation custody failed")
        result = self.run_worker()
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["identity_registration"]["status"], "PENDING")
        self.handoff.assert_not_called()
        self.cleanup.assert_called_once()


class PrereleaseCallbackTests(InertTests):
    def setUp(self):
        super().setUp()
        self.plan = plan()
        self.connection = mock.Mock()
        self.events = []
        self.document = {"fixture": "activation"}
        self.result = {"schema": "aragorn/pi-core-bootstrap-result/v1", "activation_id": "a" * 32,
            "status": "PROVIDER_UNAVAILABLE", "authority": confined._RESULT_AUTHORITY}
        hello = {"schema": "aragorn/pi-core-bootstrap-hello/v1", "worker_nonce": "b" * 32}
        self.read = self.stack.enter_context(mock.patch.object(confined, "_read_bootstrap", side_effect=[hello, self.result]))
        self.bind = self.stack.enter_context(mock.patch.object(confined, "bind_pi_worker_activation", return_value=self.document))
        self.send = self.stack.enter_context(mock.patch.object(confined, "_send_frame",
            side_effect=lambda connection, raw, deadline: self.events.append(json.loads(raw)["schema"])))

    def exchange(self, callback):
        return confined.exchange_prepared_pi_bootstrap(self.plan, self.connection, expected_pid=1234,
            on_activation=lambda document: self.events.append("activation"), on_before_release=callback)

    def test_callback_runs_after_valid_result_and_before_release(self):
        def revoke():
            self.assertEqual(self.read.call_count, 2)
            self.events.append("revoke")
        result = self.exchange(revoke)
        self.assertTrue(result["release_sent"])
        self.assertEqual(self.events, ["activation", "aragorn/pi-core-bootstrap-start/v1", "revoke", "aragorn/pi-core-bootstrap-release/v1"])

    def test_failed_callback_prevents_release(self):
        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            self.exchange(mock.Mock(side_effect=RuntimeError("revocation uncertain")))
        self.send.assert_called_once()
        self.assertNotIn("aragorn/pi-core-bootstrap-release/v1", self.events)

    def test_noncallable_callback_refuses_before_plan_consumption_or_binding(self):
        with self.assertRaisesRegex(confined.PiConfinedLaunchError, "prerelease"):
            self.exchange(1)
        self.assertFalse(self.plan._lease.exchange_attempted)
        self.read.assert_not_called()
        self.bind.assert_not_called()
        self.send.assert_not_called()

    def test_invalid_result_does_not_trigger_callback_or_release(self):
        self.result["status"] = "READY"
        revoke = mock.Mock()
        with self.assertRaises(confined.PiConfinedLaunchError):
            self.exchange(revoke)
        revoke.assert_not_called()
        self.send.assert_called_once()


if __name__ == "__main__":
    unittest.main()
