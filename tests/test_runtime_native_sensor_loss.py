"""Focused inert checks for the bounded native sensor process-exit helper."""

import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from scripts import capture_runtime_native_sensor_loss_check as host
from scripts import runtime_native_sensor_loss_check as subject

CONTAINER = "a" * 64


def _states():
    before = {
        "units": {},
        "broker_process": {"pid": 42, "start_time_ticks": 7},
        "watchdog": {"inactive": True},
        "endpoint_paths_present": {"worker": True, "sensor": True},
    }
    for unit in subject._UNITS:
        before["units"][unit] = {
            "unit": {
                "ActiveState": "active",
                "SubState": "running",
                "MainPID": "42",
                "ControlPID": "0",
                "NRestarts": "0",
                "InvocationID": "b" * 32,
                "Restart": "no",
                "Result": "success",
                "ExecMainCode": "0",
                "ExecMainStatus": "0",
            },
            "cgroup": {"members": [42], "present": True},
        }
    after = deepcopy(before)
    for unit in (subject._GATEWAY, subject._WORKER, subject._SENSOR):
        failed = unit == subject._SENSOR
        after["units"][unit]["unit"].update(
            ActiveState="failed" if failed else "inactive",
            SubState="failed" if failed else "dead",
            MainPID="0",
            Result="signal" if failed else "success",
            ExecMainCode="2" if failed else "0",
            ExecMainStatus="9" if failed else "0",
        )
        after["units"][unit]["cgroup"] = {"members": [], "present": False}
    after["endpoint_paths_present"] = {"worker": False, "sensor": False}
    return before, after


class NativeSensorLossTests(unittest.TestCase):
    def test_terminal_accepts_only_bounded_fail_stop(self):
        before, after = _states()
        self.assertTrue(subject._terminal(before, after))
        mutations = (
            lambda x: x["units"][subject._SENSOR]["unit"].update(NRestarts="1"),
            lambda x: x["units"][subject._SENSOR]["unit"].update(InvocationID="c" * 32),
            lambda x: x["units"][subject._SENSOR]["unit"].update(Result="exit-code"),
            lambda x: x["units"][subject._WORKER]["cgroup"].update(members=[99]),
            lambda x: x["units"][subject._GATEWAY]["unit"].update(ControlPID="3"),
            lambda x: x["broker_process"].update(start_time_ticks=8),
            lambda x: x["endpoint_paths_present"].update(sensor=True),
            lambda x: x["watchdog"].update(inactive=False),
        )
        for mutate in mutations:
            changed = deepcopy(after)
            mutate(changed)
            with self.subTest(mutation=mutate):
                self.assertFalse(subject._terminal(before, changed))

    def test_cgroup_path_uses_exact_owned_container(self):
        native = SimpleNamespace(
            prior=SimpleNamespace(_read_virtual_file=MagicMock(return_value=b"42\n"))
        )
        result = subject._members(native, CONTAINER, subject._SENSOR)
        self.assertEqual(
            result["path"],
            f"/sys/fs/cgroup/docker/{CONTAINER}/system.slice/{subject._SENSOR}/cgroup.procs",
        )
        self.assertEqual(result["members"], [42])
        with self.assertRaises(subject.SensorLossError):
            subject._members(native, "../outside", subject._SENSOR)

    def test_pidfd_identity_rechecked_before_signal_and_fd_closed(self):
        group = f"/docker/{CONTAINER}/system.slice/{subject._SENSOR}"
        before, _ = _states()
        state = before["units"][subject._SENSOR]["unit"]
        state["ControlGroup"] = group
        process = {"pid": 42, "cgroup": group, "start_time_ticks": 7}
        processes = {"sensor": {"process": process, "unit": state}}
        native = SimpleNamespace(
            response=SimpleNamespace(
                _process_start_time=MagicMock(return_value=7),
                _process_cgroup=MagicMock(return_value=group),
            )
        )
        for changed in (False, True):
            with (
                self.subTest(changed_identity=changed),
                patch.object(
                    subject.os, "pidfd_open", create=True, return_value=100
                ) as opened,
                patch.object(subject.signal, "pidfd_send_signal", create=True) as sent,
                patch.object(subject.os, "close") as close,
                patch.object(
                    subject,
                    "_show",
                    return_value={**state, "InvocationID": "c" * 32}
                    if changed
                    else state,
                ),
                patch.object(subject, "_members", return_value={"members": [42]}),
                patch.object(subject, "_watchdog", return_value=before["watchdog"]),
            ):
                if changed:
                    with self.assertRaises(subject.SensorLossError):
                        subject._signal_sensor(native, CONTAINER, processes, before)
                    sent.assert_not_called()
                else:
                    subject._signal_sensor(native, CONTAINER, processes, before)
                    sent.assert_called_once_with(100, subject.signal.SIGKILL, None, 0)
                opened.assert_called_once_with(42, 0)
                close.assert_called_once_with(100)

    def test_proof_ceiling_is_always_false(self):
        self.assertIn("run02_eligible", subject._FALSE_FLAGS)
        self.assertIn("full_sensor_health_coverage", subject._FALSE_FLAGS)
        self.assertIn("general_socket_reachability_verified", subject._FALSE_FLAGS)

    def test_missing_pidfd_is_refused_without_fallback(self):
        with (
            patch.object(subject, "os", SimpleNamespace()),
            self.assertRaisesRegex(
                subject.SensorLossError, "numeric PID fallback forbidden"
            ),
        ):
            subject._signal_sensor(None, CONTAINER, {}, {})

    def test_guard_precedes_fixture_or_signal_work(self):
        native = MagicMock()
        native.setup_prior._require_fixture.side_effect = subject.SensorLossError(
            "guard"
        )
        with (
            patch.object(subject, "_native", return_value=native),
            patch.object(subject, "_signal_sensor") as signal,
        ):
            with self.assertRaisesRegex(subject.SensorLossError, "guard"):
                subject._run(CONTAINER)
            native._prepare.assert_not_called()
            signal.assert_not_called()

    def test_original_refusal_survives_cleanup_failure(self):
        native = MagicMock()
        native.setup_prior._ALL_UNITS = subject._UNITS
        native.prior._stop_fixture.side_effect = RuntimeError("cleanup")
        fake_cgroup = SimpleNamespace(observe=lambda _: {"status": "UNAVAILABLE"})
        with (
            patch.object(subject, "_native", return_value=native),
            patch.dict(
                subject.sys.modules,
                {
                    "runtime_native_cgroup_prerequisite": fake_cgroup,
                    "runtime_action_worker_openclaw_systemd_probe": SimpleNamespace(),
                },
            ),
            self.assertRaisesRegex(
                subject.SensorLossError, "native cgroup prerequisite unavailable"
            ),
        ):
            subject._run(CONTAINER)
        native.prior._stop_fixture.assert_called_once_with()
        native.response._command.assert_not_called()

    def test_host_retains_only_bounded_refusals(self):
        prefix = b"native sensor loss fixture refused: "
        result = SimpleNamespace(
            returncode=126, stdout=b"", stderr=prefix + b"idle stack is incomplete\n"
        )
        with patch.object(host.subprocess, "run", return_value=result):
            refused = host._invoke_guest(["exec", CONTAINER], CONTAINER)
            self.assertEqual(refused["status"], "REFUSED")
            self.assertTrue(all(refused[key] is False for key in subject._FALSE_FLAGS))
            result.stderr = prefix + b"arbitrary external text or credentials\n"
            with self.assertRaises(RuntimeError):
                host._invoke_guest(["exec", CONTAINER], CONTAINER)


if __name__ == "__main__":
    unittest.main()
