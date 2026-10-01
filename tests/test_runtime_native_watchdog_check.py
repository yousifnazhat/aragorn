"""Focused inert checks for the owned timer-expiry acceptance helper."""

import unittest
from copy import deepcopy
from unittest.mock import patch

from scripts import runtime_native_watchdog_check as subject
from tests.test_runtime_native_health_systemd_check import (
    BEFORE,
    BOOT,
    CONTAINER,
    SETUP,
    _captured,
    _row,
)


def _expiry():
    document = {
        "schema": "aragorn/runtime-mediator-health/v1",
        "runtime_digest": SETUP["runtime_digest"],
        "sensor_digest": SETUP["policy"]["sensor_digest"],
        "epoch": 4,
        "status": "healthy",
        "observed_at_unix": 100,
        "expires_at_unix": 115,
    }
    result = _captured(document, unhealthy=True)["response"]["result"]["response"]
    result["schema"] = "aragorn/runtime-health-watchdog-result/v1"
    result.pop("health_snapshot_digest")
    result["status"] = "SUSPENDED_EXPIRED_HEALTH_FIXED_RUNTIME_PROFILE"
    result["accepted_health"].update(expired=True, observed_at_unix=100)
    for item in result["after"]:
        item["unit"]["SubState"] = "dead"
    row = _row(unit=subject._SERVICE)
    row["__REALTIME_TIMESTAMP"] = "115000000"
    captured = {
        "journal": row,
        "invocation_id": row["_SYSTEMD_INVOCATION_ID"],
        "result": {"response": result},
    }
    return document, captured


class NativeWatchdogFixtureTests(unittest.TestCase):
    def test_timestamps_use_typed_microseconds_not_systemctl_duration_display(self):
        raw = f"Id={subject._TIMER}\nLastTriggerUSecMonotonic=2.5s\n".encode()
        with patch.object(
            subject.response, "_command", side_effect=[raw, b"t 2500000\n"]
        ):
            result = subject._show(subject._TIMER, ("Id", "LastTriggerUSecMonotonic"))
        self.assertEqual(result["LastTriggerUSecMonotonic"], "2500000")
        with (
            patch.object(
                subject.response, "_command", side_effect=[raw, b"s 2500000\n"]
            ),
            self.assertRaises(subject.WatchdogFixtureError),
        ):
            subject._show(subject._TIMER, ("Id", "LastTriggerUSecMonotonic"))

    def test_guard_is_first_and_selectors_are_fixed(self):
        with (
            patch.object(
                subject.health, "_guard", side_effect=RuntimeError("fixture")
            ) as guard,
            patch.object(subject, "_contract") as contract,
        ):
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                subject.run_after_native(CONTAINER, {}, None)
            guard.assert_called_once_with(CONTAINER)
            contract.assert_not_called()
        with patch.object(subject.response, "_command") as command:
            for callback, args in (
                (subject._show, ("other.service", ("Id",))),
                (subject._journal, ("bad cursor", BOOT)),
            ):
                with self.assertRaises(subject.WatchdogFixtureError):
                    callback(*args)
            command.assert_not_called()

    def test_expiry_join_binds_authority_identity_time_and_masks(self):
        document, captured = _expiry()
        with patch.object(
            subject.retained,
            "_retained_response",
            side_effect=lambda value: (value["response"], {"checked": True}),
        ):
            self.assertEqual(
                subject._join(captured, document, SETUP, BEFORE)["retention"],
                {"checked": True},
            )
            mutations = (
                lambda c: c["result"]["response"]["accepted_health"].update(
                    expired=False
                ),
                lambda c: c["result"]["response"]["accepted_health"].update(epoch=3),
                lambda c: c["result"]["response"]["accepted_health"].update(
                    status="unhealthy"
                ),
                lambda c: c["result"]["response"]["before"][0]["process"].update(
                    pid=999
                ),
                lambda c: c["result"]["response"]["after"][0]["cgroup"].update(
                    status="POPULATED"
                ),
                lambda c: c["result"]["response"]["future_start_barrier"].update(
                    directory_fsynced=False
                ),
                lambda c: c["journal"].update(__REALTIME_TIMESTAMP="114999999"),
            )
            for mutate in mutations:
                changed = deepcopy(captured)
                mutate(changed)
                with (
                    self.subTest(mutation=mutate),
                    self.assertRaises(subject.WatchdogFixtureError),
                ):
                    subject._join(changed, document, SETUP, BEFORE)

    def test_timer_completion_requires_actual_successful_invocation(self):
        state = {
            "ActiveState": "inactive",
            "SubState": "dead",
            "MainPID": "0",
            "ControlPID": "0",
            "ExecMainStatus": "0",
            "Result": "success",
            "ExecMainStartTimestampMonotonic": "100",
            "ExecMainExitTimestampMonotonic": "200",
        }
        self.assertTrue(subject._complete(state))
        for key, value in (
            ("ExecMainStartTimestampMonotonic", "0"),
            ("ExecMainExitTimestampMonotonic", "99"),
            ("ExecMainStatus", "126"),
            ("ActiveState", "active"),
            ("ControlPID", "1"),
        ):
            with self.subTest(key=key):
                self.assertFalse(subject._complete({**state, key: value}))

    def test_journal_retains_only_exact_service_boot_and_new_result(self):
        row = _row(unit=subject._SERVICE)
        raw = subject.health.canonical_json(row) + b"\n"
        with patch.object(subject.response, "_command", return_value=raw):
            rows = subject._journal("s=old", BOOT)
            self.assertEqual(rows[0]["journal"], row)
            self.assertEqual(subject._journal("s=new", BOOT), [])
        row["_SYSTEMD_UNIT"] = subject.health._DISPATCH
        with (
            patch.object(
                subject.response,
                "_command",
                return_value=subject.health.canonical_json(row) + b"\n",
            ),
            self.assertRaises(subject.WatchdogFixtureError),
        ):
            subject._journal("s=old", BOOT)


if __name__ == "__main__":
    unittest.main()
