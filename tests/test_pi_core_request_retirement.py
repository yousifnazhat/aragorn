"""Atomic action/sensor retirement over inert existing lifecycle observations.

Only new methods and explicitly named affected provider/channel checks run.
There is no service, socket, process, provider request or filesystem activity.
These checks do not establish live terminal receipts or Phase 3 qualification.
"""

import unittest
from unittest import mock

from aragorn import pi_core_service_lifecycle as subject
from tests import test_pi_core_service_retirement as fixtures
from tests import test_pi_core_service_channels as channel_fixtures


class PiRequestRetirementTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PiServiceRetirementTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.lease, self.owner = self.fixture.lease, self.fixture.owner

    def refuse(self, operation):
        with self.assertRaises((subject.PiServiceLifecycleError,
                                subject.channels.PiServiceChannelsError, RuntimeError)):
            operation()

    def retire(self):
        self.lease.retire_requests(deadline=110.0)

    def test_pair_starts_unretired_and_observation_is_detached(self):
        self.assertIs(self.lease.requests_retired, False)
        record = self.lease.observation
        self.assertIs(record["requests_retired"], False)
        record["requests_retired"] = True
        self.assertIs(self.lease.requests_retired, False)
        with self.assertRaises(AttributeError):
            self.lease.requests_retired = True

    def test_atomic_pair_transition_follows_all_full_live_checks(self):
        flags = []
        original = self.fixture.readback.side_effect

        def readback(service, state, deadline):
            flags.append((service.role, self.lease.requests_retired))
            return original(service, state, deadline)

        self.fixture.readback.side_effect = readback
        self.retire()
        self.assertEqual(flags, [(role, False) for role in subject.ROLES])
        self.assertIs(self.lease.requests_retired, True)
        self.assertIs(self.lease.provider_retired, False)
        self.assertEqual({call.args[1][0] for call in self.fixture.live.call_args_list},
                         {item.pid for item in self.owner.services.values()})

    def test_preterminal_action_exit_refuses_without_pair_retirement(self):
        self.fixture.exit("action")
        self.refuse(self.retire)
        self.assertFalse(self.lease.requests_retired)

    def test_preterminal_sensor_exit_refuses_without_pair_retirement(self):
        self.fixture.exit("sensor")
        self.refuse(self.retire)
        self.assertFalse(self.lease.requests_retired)

    def test_no_request_exit_remains_a_failure_without_retirement(self):
        self.fixture.exit("action", collected=True)
        self.fixture.exit("sensor", collected=True)
        self.refuse(self.lease.guard)
        self.assertFalse(self.lease.requests_retired)

    def test_provider_exit_has_no_new_preterminal_waiver(self):
        self.fixture.exit("provider")
        self.refuse(self.retire)
        self.assertFalse(self.lease.requests_retired)
        self.assertFalse(self.lease.provider_retired)

    def test_existing_provider_retirement_and_request_pair_compose(self):
        self.fixture.exit("provider", collected=True)
        self.lease.retire_provider(deadline=110.0)
        self.retire()
        self.fixture.exit("action")
        self.fixture.exit("sensor", collected=True)
        self.lease.guard(deadline=110.0)
        self.assertTrue(self.lease.provider_retired)
        self.assertTrue(self.lease.requests_retired)

    def test_provider_can_retire_after_request_pair_without_reopening_it(self):
        self.retire()
        self.fixture.exit("action")
        self.fixture.exit("sensor")
        self.fixture.exit("provider")
        self.lease.retire_provider(deadline=110.0)
        self.lease.guard(deadline=110.0)
        self.assertTrue(self.lease.requests_retired)

    def test_failed_retirement_check_cannot_be_retried(self):
        self.fixture.config.guard.side_effect = RuntimeError("changed configuration")
        self.refuse(self.retire)
        self.fixture.config.guard.side_effect = None
        self.fixture.config.guard.reset_mock()
        self.refuse(self.retire)
        self.fixture.config.guard.assert_not_called()
        self.assertFalse(self.lease.requests_retired)

    def test_successful_retirement_is_irreversible_and_one_shot(self):
        self.retire()
        self.refuse(self.retire)
        self.assertTrue(self.lease.requests_retired)

    def test_reentrant_retirement_cannot_partially_retire_a_role(self):
        observed = []

        def guard(**options):
            observed.append(self.lease.requests_retired)
            self.refuse(self.retire)
            self.assertFalse(self.lease.requests_retired)

        self.fixture.config.guard.side_effect = guard
        self.retire()
        self.assertEqual(observed, [False])
        self.assertTrue(self.lease.requests_retired)

    def test_request_retirement_requires_exact_attached_lifecycle(self):
        self.lease._lifecycle = None
        self.refuse(self.retire)
        self.assertFalse(self.lease.requests_retired)
        self.assertEqual(self.lease._pidfds, [901, 902, 903])

    def test_request_retirement_refuses_foreign_captured_lifecycle(self):
        self.owner._channels = object()
        self.refuse(self.retire)
        self.assertFalse(self.lease.requests_retired)

    def test_unsealed_or_inactive_lease_cannot_retire_requests(self):
        uninitialized = object.__new__(subject.channels.PiServiceChannels)
        self.refuse(uninitialized.retire_requests)
        self.lease._active = False
        self.refuse(self.retire)
        self.assertFalse(self.lease.requests_retired)

    def test_retired_pair_cannot_drop_its_captured_lifecycle(self):
        self.retire()
        self.lease._lifecycle = None
        self.refuse(self.lease.guard)

    def test_terminal_flag_without_one_shot_transition_refuses(self):
        self.lease._requests_retired = True
        self.refuse(self.lease.guard)
        self.refuse(lambda: self.owner.guard_inputs_and_units(self.lease, deadline=110.0))

    def test_remaining_live_request_roles_keep_captured_generation_checks(self):
        self.retire()
        self.fixture.readback.reset_mock()
        self.lease.guard(deadline=110.0)
        self.assertEqual([call.args[0].role for call in self.fixture.readback.call_args_list],
                         list(subject.ROLES))
        self.fixture.states["sensor"]["InvocationID"] = "f" * 32
        self.refuse(self.lease.guard)

    def test_one_retired_role_may_exit_while_other_waits_for_ack(self):
        self.retire()
        self.fixture.exit("sensor")
        self.lease.guard(deadline=110.0)
        self.fixture.exit("action")
        self.lease.guard(deadline=110.0)
        self.assertFalse(self.owner.services["action"].terminal)
        self.assertFalse(self.owner.services["sensor"].terminal)

    def test_both_collected_units_require_the_original_empty_cgroups(self):
        self.retire()
        for role in ("action", "sensor"):
            self.fixture.exit(role, collected=True)
        self.lease.guard(deadline=110.0)
        self.assertTrue(self.lease.requests_retired)

    def test_exited_generation_checks_reject_changed_invocation_pid_or_start(self):
        self.retire()
        for role in ("action", "sensor"):
            self.fixture.exit(role)
            for field, replacement in (("InvocationID", "f" * 32),
                                       ("ExecMainPID", "9999"),
                                       ("ExecMainStartTimestampMonotonic", "9999")):
                with self.subTest(role=role, field=field):
                    original = self.fixture.states[role][field]
                    self.fixture.states[role][field] = replacement
                    self.refuse(self.lease.guard)
                    self.fixture.states[role][field] = original

    def test_cleared_terminal_invocations_keep_original_exec_identity(self):
        self.retire()
        for role in ("action", "sensor"):
            self.fixture.exit(role)
            self.fixture.states[role]["InvocationID"] = ""
        self.lease.guard(deadline=110.0)

    def test_collected_name_replacement_is_not_the_retired_generation(self):
        self.retire()
        self.fixture.exit("action", collected=True)
        self.lease.guard(deadline=110.0)
        self.fixture.states["action"].update(LoadState="loaded", ActiveState="active",
            SubState="running", MainPID="9999", InvocationID="f" * 32)
        self.refuse(self.lease.guard)

    def test_retired_residual_request_process_is_not_cleanup(self):
        self.retire()
        self.fixture.exit("sensor")
        path = self.owner.services["sensor"].plan.profile.cgroup
        self.fixture.members[path] = (9999,)
        self.refuse(self.lease.guard)
        self.assertFalse(self.owner.services["sensor"].terminal)

    def test_retired_cgroup_name_substitution_refuses_after_collection(self):
        self.retire()
        self.fixture.exit("action", collected=True)

        def ownership(service, **options):
            if service.role == "action":
                raise subject.native.PiNativeSupervisorError("captured cgroup changed")
            return False

        self.fixture.cgroup.side_effect = ownership
        self.refuse(self.lease.guard)

    def test_collected_unit_with_a_control_process_is_not_absent(self):
        self.retire()
        self.fixture.exit("sensor", collected=True)
        self.fixture.states["sensor"]["ControlPID"] = "9999"
        self.refuse(self.lease.guard)

    def test_retired_channel_keeps_actual_kernel_peer_and_descriptor(self):
        self.retire()
        self.fixture.exit("sensor")
        connection = self.fixture.connections["sensor"]
        peer, descriptor = connection.peer, connection.descriptor
        connection.peer = (9999, peer[1], peer[2])
        self.refuse(self.lease.guard)
        connection.peer = peer
        connection.descriptor = descriptor + 100
        self.refuse(self.lease.guard)

    def test_retired_expected_process_and_captured_connection_must_match(self):
        self.retire()
        self.fixture.exit("action")
        self.lease._expected["action"]["start_ticks"] += 1
        self.refuse(self.lease.guard)
        self.lease._expected["action"]["start_ticks"] -= 1
        self.owner.services["action"].connection = fixtures.Connection(99, (401, 1201, 1301))
        self.refuse(self.lease.guard)

    def test_retired_unit_configuration_and_held_input_changes_refuse(self):
        self.retire()
        self.fixture.exit("action")
        original = self.fixture.readback.side_effect
        self.fixture.readback.side_effect = lambda service, state, deadline: (
            "changed" if service.role == "action" else service.immutable_digest)
        self.refuse(self.lease.guard)
        self.fixture.readback.side_effect = original
        self.fixture.public.guard.side_effect = RuntimeError("protected inputs changed")
        self.refuse(self.lease.guard)

    def test_tightened_budget_reaches_live_and_terminal_reads_without_extension(self):
        self.retire()
        self.assertTrue(all(call.args[1] == 110.0 for call in self.fixture.state.call_args_list))
        self.fixture.state.reset_mock()
        self.fixture.exit("action")
        self.fixture.exit("sensor")
        self.lease.guard(deadline=105.0)
        self.assertTrue(all(call.args[1] == 105.0 for call in self.fixture.state.call_args_list))
        self.assertEqual(self.lease.deadline, 120.0)
        self.assertEqual(self.owner.operation_deadline, 120.0)

    def test_extended_retirement_never_sets_terminal_state(self):
        self.refuse(lambda: self.lease.retire_requests(deadline=120.1))
        self.assertFalse(self.lease.requests_retired)

    def test_expired_retirement_refuses_before_captured_unit_reads(self):
        self.fixture.clock.return_value = 121.0
        self.refuse(self.retire)
        self.fixture.state.assert_not_called()
        self.assertFalse(self.lease.requests_retired)

    def test_budget_expiring_during_full_check_cannot_retire_pair(self):
        original = self.fixture.readback.side_effect

        def readback(service, state, deadline):
            observed = original(service, state, deadline)
            if service.role == "sensor":
                self.fixture.clock.return_value = 111.0
            return observed

        self.fixture.readback.side_effect = readback
        self.refuse(self.retire)
        self.assertFalse(self.lease.requests_retired)

    def test_terminal_state_does_not_claim_effect_exit_or_handle_cleanup(self):
        self.retire()
        self.assertEqual(self.lease._pidfds, [901, 902, 903])
        record = self.lease.observation
        self.assertEqual(record["cleanup"], "HELD")
        self.assertFalse(record["phase3_exit_eligible"])
        self.assertFalse(record["service_ready"])
        self.assertFalse(record["loaded_code_verified"])
        self.assertFalse(record["unit_lifetime_verified"])
        self.assertEqual(self.owner.observation["cleanup"]["status"], "PENDING")

    def test_retired_close_failure_keeps_hold_and_does_not_retry_handles(self):
        self.retire()
        calls = []

        def close(descriptor):
            calls.append(descriptor)
            self.assertFalse(self.lease.observation["active"])
            if descriptor == 902:
                raise OSError("owned handle close uncertain")

        with mock.patch.object(subject.channels.os, "close", side_effect=close):
            self.refuse(self.lease._close)
            self.refuse(self.lease._close)
        self.assertEqual(calls, [901, 902, 903])
        self.assertEqual(self.lease.observation["cleanup"], "CLEANUP_HOLD")
        self.assertTrue(self.lease.requests_retired)
        self.refuse(self.retire)


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(PiRequestRetirementTests)
    # These exact existing cases exercise the changed shared terminal helper
    # and channel guard. Do not discover either historical test module.
    for name in (
        "test_authenticated_retirement_accepts_exact_loaded_exit",
        "test_authenticated_retirement_accepts_collected_unit_only_with_empty_cgroup",
        "test_retirement_before_exit_keeps_full_live_provider_checks",
        "test_action_exit_after_retirement_still_refuses",
        "test_sensor_exit_after_retirement_still_refuses",
        "test_foreign_provider_invocation_refuses",
        "test_residual_cgroup_process_refuses",
        "test_no_lifecycle_channel_retirement_remains_supported",
    ):
        suite.addTest(fixtures.PiServiceRetirementTests(name))
    for name in (
        "test_retirement_accepts_authenticated_terminal_after_provider_exit",
        "test_retirement_cannot_waive_sensor_or_action_liveness",
    ):
        suite.addTest(channel_fixtures.PiServiceChannelTests(name))
    return suite


if __name__ == "__main__":
    unittest.main()
