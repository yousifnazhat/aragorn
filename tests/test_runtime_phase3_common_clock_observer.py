"""Inert owned-fixture clock wrapper tests; no clock or service observations run."""

from contextlib import ExitStack
from copy import deepcopy
import unittest
from unittest.mock import patch

from aragorn import native_phase3_clock_domain as clock
from scripts import runtime_phase3_common_process_observer as subject
from tests import test_runtime_phase3_common_process_observer as fixtures


class CommonClockObserverTests(unittest.TestCase):
    def fixture(self):
        return fixtures.Fixture(self)

    def observation(self, fixture):
        namespace = {"device": 4, "inode": 100}
        roles = {
            role: {
                key: fixture.processes[role][key]
                for key in ("pid", "start_time_ticks", "uid", "gid")
            }
            | {"time_namespace": dict(namespace)}
            for role in ("worker", "broker")
        }
        return {
            "schema": "aragorn/native-phase3-clock-domain/v1",
            "authority": "LOCAL_ROOT_PROCESS_TIME_NAMESPACE_READBACK_NOT_REQUEST_EVENTS_OR_ATTESTATION",
            "clock_id": "CLOCK_BOOTTIME",
            "boot_id": fixtures.BOOT,
            "read_started_boottime_ns": 100,
            "read_finished_boottime_ns": 101,
            "processes": {
                "collector": {
                    "pid": 99,
                    "start_time_ticks": 900,
                    "uid": 0,
                    "gid": 0,
                    "time_namespace": dict(namespace),
                },
                **roles,
            },
            "limitations": list(clock.LIMITATIONS),
            **dict.fromkeys(subject._FALSE, False),
        }

    def observe(self):
        return subject.observe_common_clock_domain(
            expected_container_id=fixtures.CONTAINER
        )

    def test_derives_fixed_targets_and_returns_exact_clock_record(self):
        fixture = self.fixture()
        observation = self.observation(fixture)
        commands, roles = (
            deepcopy(subject.prior._COMMANDS),
            deepcopy(subject.prior._ROLES),
        )
        with (
            fixture.patched(),
            patch.object(
                clock, "observe_native_common_clock_domain", return_value=observation
            ) as read,
        ):
            result = self.observe()
        self.assertIs(result, observation)
        read.assert_called_once_with(
            **{
                "expected_" + role: {
                    key: fixture.processes[role][key]
                    for key in ("pid", "start_time_ticks", "uid", "gid")
                }
                for role in ("worker", "broker")
            }
        )
        self.assertEqual(fixture.commands, ["worker", "sensor", "broker"] * 4)
        self.assertEqual(len(fixture.descriptors), 8)
        self.assertEqual(subject.prior._COMMANDS, commands)
        self.assertEqual(subject.prior._ROLES, roles)
        self.assertTrue(all(result[key] is False for key in subject._FALSE))
        fixture.assert_closed()

    def test_environment_refusal_precedes_clock_reader(self):
        for mode in ("platform", "uid", "gid", "container", "fixture"):
            with self.subTest(mode=mode):
                fixture = self.fixture()
                with (
                    fixture.patched(),
                    patch.object(clock, "observe_native_common_clock_domain") as read,
                    ExitStack() as patches,
                ):
                    if mode == "platform":
                        patches.enter_context(
                            patch.object(subject.sys, "platform", "darwin")
                        )
                    elif mode in ("uid", "gid"):
                        patches.enter_context(
                            patch.object(subject.os, "gete" + mode, return_value=1000)
                        )
                    elif mode == "fixture":
                        patches.enter_context(
                            patch.object(
                                subject.response,
                                "_process_cgroup",
                                return_value="/init.scope",
                            )
                        )
                    with self.assertRaises(subject.CommonProcessObservationError):
                        subject.observe_common_clock_domain(
                            expected_container_id="invalid"
                            if mode == "container"
                            else fixtures.CONTAINER
                        )
                read.assert_not_called()
                self.assertEqual(fixture.commands, [])
                fixture.assert_closed()

    def test_every_role_epoch_remains_bound_across_clock_read(self):
        for role in ("gateway", "worker", "sensor", "broker"):
            with self.subTest(role=role):
                fixture = self.fixture()
                observation = self.observation(fixture)

                def changed(**_expected):
                    fixture.processes[role]["start_time_ticks"] += 1
                    return observation

                with (
                    fixture.patched(),
                    patch.object(
                        clock, "observe_native_common_clock_domain", side_effect=changed
                    ) as read,
                    self.assertRaises(subject.CommonProcessObservationError),
                ):
                    self.observe()
                read.assert_called_once()
                self.assertEqual(len(fixture.descriptors), 8)
                fixture.assert_closed()

    def test_clock_target_and_boot_mismatches_are_not_relabelled(self):
        for mode in (
            "worker-pid",
            "broker-uid",
            "integer-type",
            "boot",
            "boot-shape",
            "missing",
        ):
            with self.subTest(mode=mode):
                fixture = self.fixture()
                observation = self.observation(fixture)
                if mode == "worker-pid":
                    observation["processes"]["worker"]["pid"] += 1
                elif mode == "broker-uid":
                    observation["processes"]["broker"]["uid"] += 1
                elif mode == "integer-type":
                    observation["processes"]["broker"]["uid"] = float(fixtures.IDS[0])
                elif mode == "boot":
                    observation["boot_id"] = fixtures.BOOT[:-1] + "2"
                elif mode == "boot-shape":
                    observation["boot_id"] = fixtures.BOOT.replace("-", "")
                else:
                    del observation["processes"]["worker"]["start_time_ticks"]
                with (
                    fixture.patched(),
                    patch.object(
                        clock,
                        "observe_native_common_clock_domain",
                        return_value=observation,
                    ) as read,
                    self.assertRaises(subject.CommonProcessObservationError),
                ):
                    self.observe()
                read.assert_called_once()
                fixture.assert_closed()

    def test_fixture_boot_accounts_and_unit_drift_refuse_return(self):
        for mode in ("boot", "accounts", "fixture", "unit"):
            with self.subTest(mode=mode):
                fixture = self.fixture()
                observation = self.observation(fixture)
                with fixture.patched(), ExitStack() as patches:

                    def changed(**_expected):
                        if mode == "boot":
                            fixture.mutate_virtual = lambda path, raw, count: (
                                raw.replace(b"0001", b"0002")
                                if path.endswith("boot_id")
                                else raw
                            )
                        elif mode == "accounts":
                            patches.enter_context(
                                patch.object(
                                    subject.response,
                                    "_identities",
                                    return_value=tuple(reversed(fixtures.IDS)),
                                )
                            )
                        elif mode == "fixture":
                            patches.enter_context(
                                patch.object(
                                    subject.response,
                                    "_process_cgroup",
                                    return_value="/init.scope",
                                )
                            )
                        else:
                            fixture.states["broker"]["InvocationID"] = "f" * 32
                        return observation

                    read = patches.enter_context(
                        patch.object(
                            clock,
                            "observe_native_common_clock_domain",
                            side_effect=changed,
                        )
                    )
                    with self.assertRaises(subject.CommonProcessObservationError):
                        self.observe()
                    read.assert_called_once()
                fixture.assert_closed()

    def test_reader_failure_or_interruption_is_not_retried(self):
        for error in (
            ValueError("inert clock refusal"),
            KeyboardInterrupt("inert cancellation"),
        ):
            with self.subTest(error=type(error).__name__):
                fixture = self.fixture()
                with (
                    fixture.patched(),
                    patch.object(
                        clock, "observe_native_common_clock_domain", side_effect=error
                    ) as read,
                    self.assertRaises(
                        KeyboardInterrupt
                        if isinstance(error, KeyboardInterrupt)
                        else subject.CommonProcessObservationError
                    ),
                ):
                    self.observe()
                read.assert_called_once()
                self.assertEqual(len(fixture.descriptors), 4)
                fixture.assert_closed()

    def test_post_clock_pidfd_cleanup_failure_prevents_return(self):
        fixture = self.fixture()
        observation = self.observation(fixture)

        def changed(**_expected):
            fixture.fail_close = True
            return observation

        with (
            fixture.patched(),
            patch.object(
                clock, "observe_native_common_clock_domain", side_effect=changed
            ) as read,
            self.assertRaises(subject.CommonProcessObservationError),
        ):
            self.observe()
        read.assert_called_once()
        self.assertEqual(len(fixture.descriptors), 8)
        fixture.assert_closed()


if __name__ == "__main__":
    unittest.main()
