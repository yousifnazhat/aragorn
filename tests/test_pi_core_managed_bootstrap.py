"""Only new composition/path checks and selected affected wrapper fixtures."""

from contextlib import contextmanager
import copy
from dataclasses import replace
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest import mock

from aragorn import pi_core_managed_bootstrap as subject
from aragorn import pi_core_service_entry as entry
from aragorn import runtime_process_profile as process
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.runtime_action_worker import RuntimeActionWorkerBinding
from tests import test_pi_core_confined_launch as launch_fixtures
from tests import test_pi_core_service_entry as entry_fixtures
from tests import test_pi_core_service_channels as channel_fixtures
from tests import test_runtime_capability_grant as grant_fixtures


class RuntimeHold:
    def __init__(self):
        self.guard = mock.Mock()


class ConfigurationHold(RuntimeHold):
    pass


class PublicHold(RuntimeHold):
    pass


class ManagedBootstrapTests(unittest.TestCase):
    def setUp(self):
        for target in ("subprocess.run", "subprocess.Popen", "socket.socket", "socket.socketpair",
                       "socket.create_connection", "os.open", "os.system"):
            self.enterContext(mock.patch(target, side_effect=AssertionError("no live operation")))
        self.enterContext(mock.patch.object(subject.runtime, "PiServiceRuntime", RuntimeHold))
        self.enterContext(mock.patch.object(subject.configuration, "PiServiceConfiguration", ConfigurationHold))
        self.enterContext(mock.patch.object(subject.configuration, "PiProviderInputs", PublicHold))
        self.runtime, self.configuration, self.public = RuntimeHold(), ConfigurationHold(), PublicHold()
        self.config = replace(launch_fixtures.configuration(), native_request=True)
        document = {"schema": process.PROFILE_SCHEMA, "authority": process.PROFILE_AUTHORITY,
            "runtime_digest": grant_fixtures._digest("4"), "executable_digest": grant_fixtures._digest("b"),
            "cgroup": "/system.slice/aragorn-pi-" + "a" * 32 + ".service",
            "skill_path": "/var/lib/aragorn/admitted/.aragorn-versions/example/version/SKILL.md"}
        self.profile = process.runtime_process_profile(document)
        self.grant = grant_fixtures._grant(runtime_profile_digest=self.profile.digest)
        self.binding = RuntimeActionWorkerBinding(*(self.grant[key] for key in
            ("runtime_digest", "active_skill_digest", "policy_digest", "policy_version")))
        self.configuration.configurations = {
            "action": {"capability_grant": copy.deepcopy(self.grant)},
            "sensor": {"capability_grant": copy.deepcopy(self.grant),
                       "observation_binding": {"runtime_profile": document}}}
        self.configuration.identities = {"worker": {"uid": self.config.worker_uid, "gid": self.config.worker_gid}}
        self.events = []
        self.channels = mock.Mock(request_channels=object())
        self.services = mock.Mock(operation_deadline=120.0, channels=self.channels)
        self.services.guard.side_effect = lambda **kw: self.events.append("guard")
        self.services.observation = {"cleanup": {"status": "VERIFIED_OWNED_CLEANUP"}}
        self.worker_result = {"status": "BOOTSTRAP_COMPLETE", "cleanup": {"status": "VERIFIED_OWNED_CLEANUP"},
                              "request_channel": {"status": "NO_REQUEST"}}
        self.cleanup_error = None
        @contextmanager
        def hold(**kw):
            self.events.append("services-started")
            try:
                yield self.services
            finally:
                self.events.append("services-cleanup")
                if self.cleanup_error:
                    raise self.cleanup_error
        self.hold = self.enterContext(mock.patch.object(subject.lifecycle, "hold_native_pi_services", side_effect=hold))
        def worker(*args, **kw):
            self.events.append("worker-cleanup-returned")
            return copy.deepcopy(self.worker_result)
        self.worker = self.enterContext(mock.patch.object(subject.native, "run_native_pi_worker", side_effect=worker))
        self.args = dict(profile=self.profile, grant=self.grant, protected_root=Path("/var/lib/aragorn/admitted"),
            runtime_conformance_digest=grant_fixtures._digest("c"), deployment={}, revoked_context_ids=set(),
            now_unix=100, deadline=125.0, config=self.config, service_runtime=self.runtime,
            service_configuration=self.configuration, provider_inputs=self.public, binding=self.binding)

    def run_bootstrap(self, **changes):
        return subject.run_native_pi_service_bootstrap(object(), {}, **(self.args | changes))

    def test_existing_worker_receives_exact_owned_channels_inside_service_lifetime(self):
        result = self.run_bootstrap()
        self.assertEqual(self.events, ["services-started", "guard", "worker-cleanup-returned", "services-cleanup"])
        self.assertIs(self.worker.call_args.kwargs["request_channels"], self.channels.request_channels)
        self.assertIs(self.hold.call_args.kwargs["deployment"], self.runtime)
        self.assertIs(self.hold.call_args.kwargs["configuration"], self.configuration)
        self.assertIs(self.hold.call_args.kwargs["provider_inputs"], self.public)
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertFalse(result["provider_available"])
        self.assertFalse(result["useful_task_verified"])
        self.assertFalse(result["phase3_exit_eligible"])

    def test_deadlines_reserve_worker_cleanup_inside_service_cleanup_budget(self):
        self.run_bootstrap()
        self.assertEqual(self.hold.call_args.kwargs["deadline"], 125)
        self.assertEqual(self.worker.call_args.kwargs["deadline"], 120)
        self.assertEqual(self.worker.call_args.kwargs["cleanup_timeout_seconds"], 5)
        self.services.guard.assert_called_once_with(deadline=120)
        for held in (self.runtime, self.configuration, self.public):
            held.guard.assert_called_once_with(deadline=125)

    def test_unavailable_legacy_mode_refuses_before_service_start(self):
        with self.assertRaises(subject.PiManagedBootstrapError):
            self.run_bootstrap(config=replace(self.config, native_request=False))
        self.hold.assert_not_called()

    def test_serialized_or_unheld_config_runtime_public_inputs_refuse(self):
        for name in ("service_runtime", "service_configuration", "provider_inputs"):
            with self.subTest(name=name), self.assertRaises(subject.PiManagedBootstrapError):
                self.run_bootstrap(**{name: {}})
        self.hold.assert_not_called()

    def test_changed_held_inputs_stop_before_any_service_start(self):
        for held in (self.runtime, self.configuration, self.public):
            held.guard.side_effect = RuntimeError("inert changed custody")
            with self.assertRaisesRegex(RuntimeError, "changed custody"):
                self.run_bootstrap()
            held.guard.side_effect = None
        self.hold.assert_not_called()

    def test_worker_identity_mismatch_refuses(self):
        with self.assertRaises(subject.PiManagedBootstrapError):
            self.run_bootstrap(config=replace(self.config, worker_uid=999))
        self.hold.assert_not_called()

    def test_different_or_stale_grant_refuses(self):
        for grant in (self.grant | {"grant_id": "2" * 64}, self.grant | {"expires_at_unix": 99}):
            with self.subTest(grant=grant), self.assertRaises(Exception):
                self.run_bootstrap(grant=grant)
        self.hold.assert_not_called()

    def test_worker_sensor_profile_mismatch_refuses(self):
        with self.assertRaises(subject.PiManagedBootstrapError):
            self.run_bootstrap(profile=replace(self.profile, cgroup="/system.slice/other.service"))
        self.hold.assert_not_called()

    def test_worker_binding_fields_must_match_same_grant(self):
        for name in ("runtime_digest", "active_skill_digest", "policy_digest", "policy_version"):
            value = 4 if name == "policy_version" else grant_fixtures._digest("f")
            with self.subTest(name=name), self.assertRaises(subject.PiManagedBootstrapError):
                self.run_bootstrap(binding=replace(self.binding, **{name: value}))
        self.hold.assert_not_called()

    def test_invalid_profile_or_binding_types_refuse(self):
        for name in ("profile", "binding"):
            with self.subTest(name=name), self.assertRaises(subject.PiManagedBootstrapError):
                self.run_bootstrap(**{name: {}})
        self.hold.assert_not_called()

    def test_failed_service_guard_prevents_worker_and_still_cleans_services(self):
        self.services.guard.side_effect = RuntimeError("inert guard refusal")
        with self.assertRaises(RuntimeError):
            self.run_bootstrap()
        self.worker.assert_not_called()
        self.assertEqual(self.events[-1], "services-cleanup")

    def test_worker_exception_never_retries_and_cleans_services(self):
        self.worker.side_effect = RuntimeError("inert worker refusal")
        with self.assertRaises(RuntimeError):
            self.run_bootstrap()
        self.worker.assert_called_once()
        self.assertEqual(self.events[-1], "services-cleanup")

    def test_worker_cleanup_hold_is_not_promoted_by_clean_services(self):
        for status, cleanup in (("CLEANUP_HOLD", {"status": "CLEANUP_HOLD"}),
                                ("BOOTSTRAP_COMPLETE", {"status": "CLEANUP_HOLD"}),
                                ("BOOTSTRAP_COMPLETE", {})):
            with self.subTest(status=status, cleanup=cleanup):
                self.worker_result.update(status=status, cleanup=cleanup)
                self.assertEqual(self.run_bootstrap()["status"], "CLEANUP_HOLD")

    def test_service_cleanup_hold_is_not_promoted_by_clean_worker(self):
        self.services.observation = {"cleanup": {"status": "CLEANUP_HOLD"}}
        self.assertEqual(self.run_bootstrap()["status"], "CLEANUP_HOLD")

    def test_service_cleanup_exception_is_propagated_without_retry(self):
        self.cleanup_error = RuntimeError("inert cleanup hold")
        with self.assertRaisesRegex(RuntimeError, "cleanup hold"):
            self.run_bootstrap()
        self.hold.assert_called_once()
        self.worker.assert_called_once()

    def test_refused_worker_cannot_become_success(self):
        self.worker_result["status"] = "REFUSED"
        self.assertEqual(self.run_bootstrap()["status"], "REFUSED")


class InstalledVersionPathTests(unittest.TestCase):
    def setUp(self):
        self.f = entry_fixtures.PiServiceEntryTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.configure("sensor")

    def test_actual_protected_installer_version_path_is_accepted(self):
        self.assertTrue(self.f.value["observation_binding"]["runtime_profile"]["skill_path"].startswith(
            "/var/lib/aragorn/admitted/.aragorn-versions/"))
        self.assertEqual(entry.validate_configuration(self.f.value, "sensor"), self.f.value)

    def test_legacy_wrong_directory_and_similar_prefixes_are_refused(self):
        for directory in ("versions", ".aragorn-versions-other", "", "../elsewhere"):
            value = copy.deepcopy(self.f.value)
            profile = value["observation_binding"]["runtime_profile"]
            profile["skill_path"] = "/var/lib/aragorn/admitted/" + directory + "/example/version/SKILL.md"
            value["capability_grant"]["runtime_profile_digest"] = canonical_digest(profile)
            with self.subTest(directory=directory), self.assertRaises(Exception):
                entry.validate_configuration(value, "sensor")

    def test_correct_path_does_not_override_profile_grant_join(self):
        self.f.value["capability_grant"]["runtime_profile_digest"] = grant_fixtures._digest("f")
        with self.assertRaises(Exception):
            entry.validate_configuration(self.f.value, "sensor")


class LifecycleChannelWiringTests(unittest.TestCase):
    def setUp(self):
        self.f = channel_fixtures.PiServiceChannelTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        class Owner:
            def __init__(self):
                self._attach_channels = mock.Mock()
                self.guard_inputs_and_units = mock.Mock()
        self.enterContext(mock.patch.object(subject.lifecycle, "PiServiceLifecycle", Owner))
        self.owner = Owner()

    def test_exact_lifecycle_is_bound_before_initial_guard_and_rechecked(self):
        with self.f.hold(lifecycle_custody=self.owner) as held:
            self.owner._attach_channels.assert_called_once_with(held)
            self.owner.guard_inputs_and_units.assert_called_once_with(held, deadline=105)
            held.guard(deadline=104)
            self.owner.guard_inputs_and_units.assert_called_with(held, deadline=104)

    def test_serialized_lifecycle_cannot_opt_in_or_acquire_pidfds(self):
        with self.assertRaises(channel_fixtures.subject.PiServiceChannelsError):
            with self.f.hold(lifecycle_custody={}): pass
        self.assertEqual(self.f.opened, [])

    def test_owner_attachment_refusal_precedes_acquisition(self):
        self.owner._attach_channels.side_effect = RuntimeError("inert owner mismatch")
        with self.assertRaisesRegex(RuntimeError, "owner mismatch"):
            with self.f.hold(lifecycle_custody=self.owner): pass
        self.assertEqual(self.f.opened, [])

    def test_initial_owner_failure_closes_only_new_peer_descriptors(self):
        self.owner.guard_inputs_and_units.side_effect = RuntimeError("inert configuration changed")
        with self.assertRaisesRegex(RuntimeError, "configuration changed"):
            with self.f.hold(lifecycle_custody=self.owner): pass
        self.assertEqual(self.f.closed, [501, 502, 503])

    def test_later_owner_failure_stops_before_peer_remeasurement(self):
        with self.f.hold(lifecycle_custody=self.owner) as held:
            before = self.f.executable.call_count
            self.owner.guard_inputs_and_units.side_effect = RuntimeError("inert unit replaced")
            with self.assertRaisesRegex(RuntimeError, "unit replaced"):
                held.guard(deadline=104)
            self.assertEqual(self.f.executable.call_count, before)

    def test_replaced_lifecycle_reference_is_rejected(self):
        with self.f.hold(lifecycle_custody=self.owner) as held:
            held._lifecycle = {}
            with self.assertRaises(channel_fixtures.subject.PiServiceChannelsError):
                held.guard()


def load_tests(loader, tests, pattern):
    selected = unittest.TestSuite()
    selected.addTests(loader.loadTestsFromTestCase(ManagedBootstrapTests))
    selected.addTests(loader.loadTestsFromTestCase(InstalledVersionPathTests))
    selected.addTests(loader.loadTestsFromTestCase(LifecycleChannelWiringTests))
    for name in ("test_sensor_dispatches_real_adoption_wrapper_with_direct_stream",
                 "test_observation_profile_must_match_grant_and_admitted_path",
                 "test_runtime_binding_must_match_real_grant"):
        selected.addTest(entry_fixtures.PiServiceEntryTests(name))
    for name in ("test_real_peer_authentication_builds_existing_request_channels_without_readiness_io",
                 "test_tighter_guard_budget_reaches_deployment_and_every_peer_check",
                 "test_retirement_accepts_authenticated_terminal_after_provider_exit"):
        selected.addTest(channel_fixtures.PiServiceChannelTests(name))
    return selected


if __name__ == "__main__":
    unittest.main()
