from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_health_watchdog as watchdog
from aragorn import runtime_response_service as response
from aragorn.oci_worker_protocol import canonical_digest
from tests.test_runtime_action_broker import _Fixture, _write_control
from tests.test_runtime_response_service import _accepted_health, _environment


@contextmanager
def _pending_environment(root):
    directory = root / "response"
    directory.mkdir(mode=0o700)
    path = directory / "health-watchdog-pending.json"

    @contextmanager
    def opened():
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    def retained(result):
        if not path.is_file():
            raise AssertionError("pending response must exist through retention")
        return {"schema": "aragorn/retained-runtime-response/v1", "response": result}

    with (
        patch.object(watchdog, "_PENDING", path),
        patch.object(watchdog, "_pending_directory", side_effect=opened),
        patch.object(response, "_retain_result", side_effect=retained),
    ):
        yield path


class RuntimeHealthWatchdogTests(unittest.TestCase):
    def test_fresh_health_expiry_boundary_unhealthy_and_no_control_mutation(self):
        for now, unhealthy, expected in (
            (104, False, "ACCEPTED_HEALTHY_FIXED_RUNTIME_PROFILE"),
            (105, False, "SUSPENDED_EXPIRED_HEALTH_FIXED_RUNTIME_PROFILE"),
            (500, False, "SUSPENDED_EXPIRED_HEALTH_FIXED_RUNTIME_PROFILE"),
            (100, True, "SUSPENDED_UNHEALTHY_FIXED_RUNTIME_PROFILE"),
        ):
            with (
                self.subTest(now=now, unhealthy=unhealthy),
                tempfile.TemporaryDirectory() as tmp,
            ):
                fixture = _Fixture(Path(tmp).resolve())
                health = _accepted_health(fixture, unhealthy=unhealthy)
                before = {key: path.read_bytes() for key, path in fixture.paths.items()}
                with (
                    _pending_environment(Path(tmp)) as pending,
                    _environment(fixture) as (_, events, stop),
                    patch.object(response, "_inactive_profile", return_value=None),
                    patch.object(
                        response, "_mask_future_starts", return_value={}
                    ) as mask,
                    patch.object(watchdog.time, "time", return_value=now),
                ):
                    result = watchdog._run()
                    result = result.get("response", result)
                    self.assertFalse(pending.exists())
                    self.assertEqual(result["status"], expected)
                    self.assertEqual(
                        result["accepted_health"]["snapshot_digest"],
                        canonical_digest(health),
                    )
                    self.assertEqual(result["accepted_health"]["epoch"], 5)
                    if expected.startswith("SUSPENDED_"):
                        stop.assert_called_once_with()
                        mask.assert_called_once_with()
                        self.assertEqual(
                            events, ["activation-lock", "stop", "activation-unlock"]
                        )
                    else:
                        stop.assert_not_called()
                        mask.assert_not_called()
                        self.assertEqual(result["before"], result["after"])
                    # A subsequent timer tick on the stopped profile must not stop/mask again.
                    with patch.object(
                        response,
                        "_inactive_profile",
                        return_value={"status": "NO_ACTIVE_RUNTIME_PROFILE"},
                    ):
                        self.assertEqual(
                            watchdog._run()["status"], "NO_ACTIVE_RUNTIME_PROFILE"
                        )
                    self.assertLessEqual(stop.call_count, 1)
                    self.assertLessEqual(mask.call_count, 1)
                self.assertEqual(
                    {key: path.read_bytes() for key, path in fixture.paths.items()},
                    before,
                )

    def test_unaccepted_unbound_future_or_unsafe_health_never_stops(self):
        for mutation in (
            {"epoch": 4},
            {"epoch": 6},
            {"epoch": True},
            {"sensor_digest": "sha256:" + "9" * 64},
            {"runtime_digest": "sha256:" + "9" * 64},
            {"observed_at_unix": 106, "expires_at_unix": 110},
            {"observed_at_unix": 1, "expires_at_unix": 105},
            {"status": "unknown"},
            {"extra": True},
            "policy",
            "mode",
            "missing",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                fixture = _Fixture(Path(tmp).resolve())
                health = _accepted_health(fixture, unhealthy=False)
                if isinstance(mutation, dict):
                    _write_control(fixture.paths["health"], {**health, **mutation})
                elif mutation == "policy":
                    _write_control(
                        fixture.paths["policy"], {**fixture.policy, "version": 2}
                    )
                elif mutation == "mode":
                    fixture.paths["health"].chmod(0o600)
                else:
                    fixture.paths["health"].unlink()
                with (
                    _pending_environment(Path(tmp)),
                    _environment(fixture) as (_, _, stop),
                    patch.object(response, "_inactive_profile", return_value=None),
                    patch.object(watchdog.time, "time", return_value=105),
                    self.assertRaises((RuntimeError, ValueError, OSError)),
                ):
                    watchdog._run()
                stop.assert_not_called()

    def test_rechecks_authority_and_reports_partial_stop_as_indeterminate(self):
        for failure in ("authority", "mask", "cgroup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                fixture = _Fixture(Path(tmp).resolve())
                _accepted_health(fixture, unhealthy=False)
                with (
                    _pending_environment(Path(tmp)),
                    _environment(fixture) as (_, _, stop),
                    patch.object(response, "_inactive_profile", return_value=None),
                    patch.object(watchdog.time, "time", return_value=105),
                ):
                    accepted = watchdog._locked_health
                    if failure == "authority":
                        calls = 0

                        def changed(*args, accepted=accepted):
                            nonlocal calls
                            calls += 1
                            result = accepted(*args)
                            return result if calls == 1 else {**result, "epoch": 6}

                        context = patch.object(
                            watchdog, "_locked_health", side_effect=changed
                        )
                        expected = response.RuntimeResponseError
                    else:
                        target = (
                            "_mask_future_starts"
                            if failure == "mask"
                            else "_cgroup_empty"
                        )
                        context = patch.object(
                            response,
                            target,
                            side_effect=response.RuntimeResponseError("unconfirmed"),
                        )
                        expected = response.RuntimeResponseIndeterminate
                    with context, self.assertRaises(expected):
                        watchdog._run()
                    self.assertEqual(
                        stop.call_count, 0 if failure == "authority" else 1
                    )

    def test_failed_response_remains_indeterminate_on_next_timer_tick(self):
        for failure in ("stop", "mask", "retention"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                fixture = _Fixture(Path(tmp).resolve())
                health = _accepted_health(fixture, unhealthy=False)
                with (
                    _pending_environment(Path(tmp)) as pending,
                    _environment(fixture) as (_, _, stop),
                    patch.object(
                        response, "_inactive_profile", return_value=None
                    ) as inactive,
                    patch.object(response, "_mask_future_starts", return_value={}),
                    patch.object(watchdog.time, "time", return_value=105),
                    redirect_stderr(StringIO()),
                ):
                    target = {
                        "stop": "_stop_units",
                        "mask": "_mask_future_starts",
                        "retention": "_retain_result",
                    }[failure]
                    with patch.object(
                        response, target, side_effect=RuntimeError("partial response")
                    ):
                        self.assertEqual(watchdog.main([]), 125)
                    self.assertEqual(inactive.call_count, 1)
                    self.assertTrue(pending.is_file())
                    self.assertEqual(pending.stat().st_mode & 0o777, 0o400)
                    document = json.loads(pending.read_bytes())
                    self.assertEqual(document["status"], "RESPONSE_PENDING")
                    self.assertEqual(
                        document["accepted_health"]["snapshot_digest"],
                        canonical_digest(health),
                    )
                    inactive.return_value = {"status": "NO_ACTIVE_RUNTIME_PROFILE"}
                    self.assertEqual(watchdog.main([]), 125)
                    self.assertEqual(inactive.call_count, 1)
                    self.assertTrue(pending.exists())
                    self.assertLessEqual(stop.call_count, 1)

    def test_cli_rejects_arguments_and_emits_only_retained_suspension(self):
        with redirect_stderr(StringIO()), redirect_stdout(StringIO()) as output:
            self.assertEqual(watchdog.main(["--arbitrary-target"]), 64)
            for result in (
                {"status": "NO_ACTIVE_RUNTIME_PROFILE"},
                {"status": "ACCEPTED_HEALTHY_FIXED_RUNTIME_PROFILE"},
                {"schema": "aragorn/retained-runtime-response/v1"},
            ):
                with (
                    patch.object(watchdog, "_run", return_value=result),
                    patch.object(response, "_retain_result") as retain,
                ):
                    self.assertEqual(watchdog.main([]), 0)
                    retain.assert_not_called()
            with patch.object(
                watchdog,
                "_run",
                side_effect=response.RuntimeResponseIndeterminate("retention"),
            ):
                self.assertEqual(watchdog.main([]), 125)
            self.assertEqual(
                output.getvalue().strip(),
                '{"schema":"aragorn/retained-runtime-response/v1"}',
            )


if __name__ == "__main__":
    unittest.main()
