from __future__ import annotations

import fcntl
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aragorn import runtime_response_service as service
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_broker import publish_runtime_control_document
from aragorn.runtime_action_worker import RuntimeActionWorkerBinding
from tests.test_runtime_action_broker import _SKILL, _Fixture, _write_control

_ROOT = Path(__file__).resolve().parents[1]
_OTHER = "sha256:" + "9" * 64


def _accepted(fixture: _Fixture) -> dict[str, object]:
    document = {**fixture.revocations, "generation": 4, "skill_digests": [_SKILL]}
    publish_runtime_control_document(
        fixture.paths["revocations"], document, fixture.config, clock=lambda: 100
    )
    return document


def _accepted_health(fixture: _Fixture, *, unhealthy: bool = True) -> dict[str, object]:
    document = {
        **fixture.health,
        "epoch": 5,
        "status": "unhealthy" if unhealthy else "healthy",
    }
    publish_runtime_control_document(
        fixture.paths["health"], document, fixture.config, clock=lambda: 100
    )
    return document


@contextmanager
def _environment(fixture: _Fixture):
    identities = (
        os.geteuid(),
        os.geteuid() + 1,
        os.getegid() + 1,
        os.geteuid() + 2,
        os.getegid() + 2,
        os.geteuid() + 3,
        os.getegid() + 3,
    )
    binding = RuntimeActionWorkerBinding(
        runtime_digest=fixture.config.expected_runtime_digest,
        active_skill_digest=_SKILL,
        policy_digest=canonical_digest(fixture.policy),
        policy_version=fixture.policy["version"],
    )
    events: list[str] = []
    stopped = False

    @contextmanager
    def guard():
        events.append("activation-lock")
        try:
            yield
        finally:
            events.append("activation-unlock")

    def unit_state(unit):
        return {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "inactive" if stopped else "active",
            "SubState": "dead" if stopped else "running",
            "MainPID": "0" if stopped else "123",
            "ControlPID": "0",
            "ControlGroup": "" if stopped else f"/system.slice/{unit}",
            "InvocationID": "a" * 32,
            "KillMode": "control-group",
            "Restart": "no",
            "SendSIGKILL": "yes",
            "Delegate": "no",
            "User": "aragorn-agent-gateway" if "gateway" in unit else "aragorn-runtime",
            "Group": "aragorn-agent-gateway"
            if "gateway" in unit
            else "aragorn-runtime",
        }

    def stop_units():
        nonlocal stopped
        events.append("stop")
        with fixture.lock_path.open("rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise AssertionError("broker lock not held through native stop")
        stopped = True

    with ExitStack() as stack:
        for name, value in (
            ("_identities", identities),
            ("_read_bindings", binding),
            ("_broker_config", fixture.config),
            (
                "_process_identity",
                {
                    "pid": 123,
                    "start_time_ticks": 456,
                    "cgroup_device": 7,
                    "cgroup_inode": 8,
                },
            ),
            ("_cgroup_empty", {"status": "EMPTY", "device": 7, "inode": 8}),
        ):
            stack.enter_context(patch.object(service, name, return_value=value))
        stack.enter_context(patch.object(service.sys, "platform", "linux"))
        stack.enter_context(patch.object(service.os, "geteuid", return_value=0))
        stack.enter_context(patch.object(service.time, "time", return_value=100))
        stack.enter_context(
            patch.object(service, "_activation_guard", side_effect=guard)
        )
        stack.enter_context(
            patch.object(service, "_unit_state", side_effect=unit_state)
        )
        stop = stack.enter_context(
            patch.object(service, "_stop_units", side_effect=stop_units)
        )
        yield binding, events, stop


class RuntimeResponseServiceTests(unittest.TestCase):
    def test_health_dispatch_is_exact_fixed_profile_and_always_retains(self) -> None:
        result = {"status": "SUSPENDED_UNHEALTHY_FIXED_RUNTIME_PROFILE"}
        with (
            patch.object(service, "_respond", return_value=result) as respond,
            patch.object(service, "_retain_result", return_value=result) as retain,
            redirect_stdout(StringIO()) as output,
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["--health-dispatch"]), 0)
            respond.assert_called_once_with(
                prevent_starts=True, health=True, health_dispatch=True
            )
            retain.assert_called_once_with(result)
            self.assertEqual(json.loads(output.getvalue()), result)
            for arguments in (
                ["--health-dispatch", _SKILL],
                ["--health-dispatch", _SKILL, _OTHER],
                ["--health-dispatch", "--health"],
                ["--health-dispatch", "--dispatch"],
                ["--dispatch", "--health-dispatch"],
                ["--retain-evidence", "--health-dispatch"],
                ["--prevent-starts", "--health-dispatch"],
            ):
                self.assertEqual(service.main(arguments), 64)
            respond.assert_called_once()
        for failure, code in (
            (service.RuntimeResponseError("stale health"), 126),
            (service.RuntimeResponseIndeterminate("partial effect"), 125),
        ):
            with (
                patch.object(service, "_respond", side_effect=failure),
                patch.object(service, "_retain_result") as retain,
                redirect_stdout(StringIO()) as output,
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(service.main(["--health-dispatch"]), code)
                self.assertEqual(output.getvalue(), "")
                retain.assert_not_called()
        with (
            patch.object(service, "_respond", return_value=result),
            patch.object(
                service, "_retain_result", side_effect=service.CASError("disk")
            ),
            redirect_stdout(StringIO()) as output,
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["--health-dispatch"]), 125)
            self.assertEqual(output.getvalue(), "")

    def test_health_dispatch_rejects_other_modes_or_targets_before_authority(
        self,
    ) -> None:
        for arguments, options in (
            ((), {"health": False, "health_dispatch": True}),
            ((), {"health": True, "health_dispatch": 1}),
            ((), {"health": True, "health_dispatch": "true"}),
            ((), {"health": 1, "health_dispatch": True}),
            ((_SKILL, _OTHER), {"health": True, "health_dispatch": True}),
            ((), {"health": True, "health_dispatch": True, "prevent_starts": False}),
        ):
            with (
                self.subTest(arguments=arguments, options=options),
                patch.object(service, "_activation_guard") as guard,
                self.assertRaises(service.RuntimeResponseError),
            ):
                service._respond(*arguments, **{"prevent_starts": True, **options})
            guard.assert_not_called()

    def test_dispatch_kinds_refuse_shared_activation_lock_contention(self) -> None:
        real_fstat, real_lstat = os.fstat, os.lstat

        def root_metadata(metadata):
            return SimpleNamespace(
                **{
                    name: getattr(metadata, name)
                    for name in dir(metadata)
                    if name.startswith("st_") and name != "st_uid"
                },
                st_uid=0,
            )

        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "activation.lock"
            lock_path.touch(mode=0o600)
            with (
                lock_path.open("rb") as lock,
                patch.object(service, "_ACTIVATION_LOCK", lock_path),
                patch.object(service.sys, "platform", "linux"),
                patch.object(service.os, "geteuid", return_value=0),
                patch.object(service.broker, "_require_protected_ancestry"),
                patch.object(
                    service.os,
                    "fstat",
                    side_effect=lambda fd: root_metadata(real_fstat(fd)),
                ),
                patch.object(
                    service.os,
                    "lstat",
                    side_effect=lambda path: root_metadata(real_lstat(path)),
                ),
                patch.object(service, "_inactive_profile") as inactive,
                patch.object(service, "_read_bindings") as binding,
                patch.object(service, "_stop_units") as stop,
                patch.object(service, "_retain_result") as retain,
            ):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                for mode in ("--dispatch", "--health-dispatch"):
                    with (
                        self.subTest(mode=mode),
                        redirect_stdout(StringIO()) as output,
                        redirect_stderr(StringIO()) as error,
                    ):
                        self.assertEqual(service.main([mode]), 126)
                        self.assertEqual(output.getvalue(), "")
                        self.assertIn("REFUSED", error.getvalue())
                inactive.assert_not_called()
                binding.assert_not_called()
                stop.assert_not_called()
                retain.assert_not_called()

    def test_health_mode_is_explicit_fixed_profile_and_always_retains(self) -> None:
        result = {"status": "SUSPENDED_UNHEALTHY_FIXED_RUNTIME_PROFILE"}
        with (
            patch.object(service, "_respond", return_value=result) as respond,
            patch.object(
                service, "_retain_result", return_value={"response": result}
            ) as retain,
            redirect_stdout(StringIO()) as output,
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["--health"]), 0)
            respond.assert_called_once_with(prevent_starts=True, health=True)
            retain.assert_called_once_with(result)
            self.assertEqual(json.loads(output.getvalue()), {"response": result})
            for arguments in (
                ["--health", _SKILL],
                ["--health", _SKILL, _OTHER],
                ["--health", "--dispatch"],
                ["--retain-evidence", "--health"],
                ["--prevent-starts", "--health"],
            ):
                self.assertEqual(service.main(arguments), 64)
            respond.assert_called_once()
        for failure, code in (
            (service.RuntimeResponseError("unaccepted health"), 126),
            (service.RuntimeResponseIndeterminate("partial stop"), 125),
        ):
            with (
                patch.object(service, "_respond", side_effect=failure),
                patch.object(service, "_retain_result") as retain,
                redirect_stdout(StringIO()) as output,
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(service.main(["--health"]), code)
                self.assertEqual(output.getvalue(), "")
                retain.assert_not_called()
        with (
            patch.object(service, "_respond", return_value=result),
            patch.object(
                service, "_retain_result", side_effect=service.CASError("disk")
            ),
            redirect_stdout(StringIO()) as output,
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["--health"]), 125)
            self.assertEqual(output.getvalue(), "")

    def test_accepted_unhealthy_suspends_under_locks_and_healthy_does_not(self) -> None:
        for unhealthy, health_dispatch in (
            (False, False),
            (False, True),
            (True, False),
            (True, True),
        ):
            with (
                self.subTest(unhealthy=unhealthy, dispatch=health_dispatch),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = _Fixture(Path(temporary).resolve())
                document = _accepted_health(fixture, unhealthy=unhealthy)
                before = {
                    name: path.read_bytes() for name, path in fixture.paths.items()
                }
                with (
                    _environment(fixture) as (_binding, events, stop),
                    patch.object(service, "_inactive_profile", return_value=None),
                    patch.object(service, "_locked_revocations") as revoked,
                    patch.object(
                        service, "_mask_future_starts", return_value={}
                    ) as mask,
                ):
                    result = service._respond(
                        prevent_starts=True,
                        health=True,
                        health_dispatch=health_dispatch,
                    )
                    self.assertEqual(
                        result["health_snapshot_digest"], canonical_digest(document)
                    )
                    self.assertEqual(result["accepted_health"]["epoch"], 5)
                    self.assertEqual(
                        result["accepted_health"]["minimum_mediator_health_epoch"], 5
                    )
                    self.assertEqual(result["expected_skill_digest"], _SKILL)
                    self.assertNotIn("accepted_revocation", result)
                    self.assertNotIn("revocation_snapshot_digest", result)
                    revoked.assert_not_called()
                    self.assertEqual(service._read_bindings.call_count, 2)
                    self.assertTrue(
                        all(
                            call.kwargs == {"dispatch": health_dispatch}
                            for call in service._read_bindings.call_args_list
                        )
                    )
                    limitations = (
                        service._HEALTH_DISPATCH_LIMITATIONS
                        if health_dispatch
                        else service._HEALTH_LIMITATIONS
                    )
                    for limitation in limitations:
                        self.assertIn(limitation, result["limitations"])
                    if health_dispatch:
                        self.assertNotIn(
                            service._HEALTH_LIMITATIONS[0], result["limitations"]
                        )
                    if unhealthy:
                        stop.assert_called_once_with()
                        mask.assert_called_once_with()
                        self.assertEqual(
                            result["status"],
                            "SUSPENDED_UNHEALTHY_FIXED_RUNTIME_PROFILE",
                        )
                        self.assertEqual(
                            events, ["activation-lock", "stop", "activation-unlock"]
                        )
                    else:
                        stop.assert_not_called()
                        mask.assert_not_called()
                        self.assertEqual(
                            result["status"], "ACCEPTED_HEALTHY_FIXED_RUNTIME_PROFILE"
                        )
                        self.assertEqual(result["before"], result["after"])
                self.assertEqual(
                    {name: path.read_bytes() for name, path in fixture.paths.items()},
                    before,
                )

    def test_health_requires_accepted_fresh_bound_snapshot_and_policy(self) -> None:
        for mutation in (
            {"epoch": 4},
            {"epoch": 6},
            {"epoch": True},
            {"runtime_digest": _OTHER},
            {"sensor_digest": _OTHER},
            {"observed_at_unix": 80, "expires_at_unix": 90},
            {"observed_at_unix": 101, "expires_at_unix": 110},
            {"status": "unknown"},
            {"extra": "field"},
            "malformed",
            "missing",
            "policy",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = _Fixture(Path(temporary).resolve())
                document = _accepted_health(fixture)
                if isinstance(mutation, dict):
                    _write_control(fixture.paths["health"], {**document, **mutation})
                elif mutation == "malformed":
                    fixture.paths["health"].chmod(0o600)
                    fixture.paths["health"].write_bytes(b"{")
                    fixture.paths["health"].chmod(0o400)
                elif mutation == "missing":
                    fixture.paths["health"].unlink()
                elif mutation == "policy":
                    _write_control(
                        fixture.paths["policy"], {**fixture.policy, "version": 2}
                    )
                with (
                    _environment(fixture) as (_binding, _events, stop),
                    patch.object(service, "_inactive_profile", return_value=None),
                ):
                    for health_dispatch in (False, True):
                        with (
                            self.subTest(dispatch=health_dispatch),
                            self.assertRaises((RuntimeError, ValueError, OSError)),
                        ):
                            service._respond(
                                prevent_starts=True,
                                health=True,
                                health_dispatch=health_dispatch,
                            )
                stop.assert_not_called()

    def test_health_rechecks_control_time_and_running_identity_before_stop(
        self,
    ) -> None:
        for change in ("time", "snapshot", "binding", "process"):
            with (
                self.subTest(change=change),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = _Fixture(Path(temporary).resolve())
                document = _accepted_health(fixture)
                with (
                    _environment(fixture) as (binding, _events, stop),
                    patch.object(service, "_inactive_profile", return_value=None),
                    ExitStack() as patches,
                ):
                    if change == "time":
                        patches.enter_context(
                            patch.object(service.time, "time", side_effect=[100, 106])
                        )
                    elif change == "snapshot":
                        original = service._locked_health

                        def replace_after_read(
                            *args, original=original, fixture=fixture, document=document
                        ):
                            result = original(*args)
                            _write_control(
                                fixture.paths["health"],
                                {**document, "status": "healthy"},
                            )
                            return result

                        patches.enter_context(
                            patch.object(
                                service,
                                "_locked_health",
                                side_effect=replace_after_read,
                            )
                        )
                    elif change == "binding":
                        wrong = RuntimeActionWorkerBinding(
                            binding.runtime_digest,
                            _OTHER,
                            binding.policy_digest,
                            binding.policy_version,
                        )
                        patches.enter_context(
                            patch.object(
                                service, "_read_bindings", side_effect=[binding, wrong]
                            )
                        )
                    else:
                        patches.enter_context(
                            patch.object(
                                service,
                                "_process_identity",
                                side_effect=[{"pid": 123}, {"pid": 456}, {"pid": 789}],
                            )
                        )
                    with self.assertRaises(service.RuntimeResponseError):
                        service._respond(prevent_starts=True, health=True)
                    stop.assert_not_called()

    def test_health_partial_effects_are_indeterminate(self) -> None:
        for failure in ("stop", "population", "mask"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = _Fixture(Path(temporary).resolve())
                _accepted_health(fixture)
                name = {
                    "stop": "_stop_units",
                    "population": "_cgroup_empty",
                    "mask": "_mask_future_starts",
                }[failure]
                with (
                    _environment(fixture),
                    patch.object(service, "_inactive_profile", return_value=None),
                    patch.object(service, name, side_effect=OSError("partial effect")),
                    self.assertRaises(service.RuntimeResponseIndeterminate),
                ):
                    service._respond(prevent_starts=True, health=True)

    def test_dispatch_has_no_target_arguments_and_always_retains(self) -> None:
        result = {"status": "NO_REVOCATION_FOR_ACTIVE_PROFILE"}
        with (
            patch.object(service, "_respond", return_value=result) as respond,
            patch.object(
                service, "_retain_result", return_value={"response": result}
            ) as retain,
            redirect_stdout(StringIO()) as output,
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["--dispatch"]), 0)
            respond.assert_called_once_with(prevent_starts=True)
            retain.assert_called_once_with(result)
            self.assertEqual(json.loads(output.getvalue()), {"response": result})
            for arguments in (
                ["--dispatch", _SKILL],
                ["--dispatch", _SKILL, _OTHER],
                ["--retain-evidence", "--dispatch"],
                ["--prevent-starts", "--dispatch"],
            ):
                self.assertEqual(service.main(arguments), 64)
            respond.assert_called_once()
        for failure, exit_code in (
            (service.RuntimeResponseError("stale snapshot"), 126),
            (service.RuntimeResponseIndeterminate("stop attempted"), 125),
        ):
            with (
                patch.object(service, "_respond", side_effect=failure),
                patch.object(service, "_retain_result") as retain,
                redirect_stderr(StringIO()),
                redirect_stdout(StringIO()) as output,
            ):
                self.assertEqual(service.main(["--dispatch"]), exit_code)
                self.assertEqual(output.getvalue(), "")
                retain.assert_not_called()
        with (
            patch.object(service, "_respond", return_value=result),
            patch.object(
                service, "_retain_result", side_effect=service.CASError("disk")
            ),
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(service.main(["--dispatch"]), 125)

    def test_dispatch_selects_current_snapshot_under_existing_locks(self) -> None:
        for revoked in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(Path(temporary).resolve())
                document = {
                    **fixture.revocations,
                    "generation": 4,
                    "skill_digests": [_SKILL] if revoked else [],
                }
                publish_runtime_control_document(
                    fixture.paths["revocations"],
                    document,
                    fixture.config,
                    clock=lambda: 100,
                )
                with (
                    _environment(fixture) as (_binding, events, stop),
                    patch.object(service, "_inactive_profile", return_value=None),
                    patch.object(
                        service, "_mask_future_starts", return_value={}
                    ) as mask,
                ):
                    result = service._respond(prevent_starts=True)
                    self.assertEqual(result["expected_skill_digest"], _SKILL)
                    self.assertEqual(
                        result["revocation_snapshot_digest"], canonical_digest(document)
                    )
                    self.assertEqual(result["accepted_revocation"]["generation"], 4)
                    self.assertIs(
                        result["accepted_revocation"]["revokes_active_skill"], revoked
                    )
                    if revoked:
                        stop.assert_called_once()
                        mask.assert_called_once()
                        self.assertEqual(
                            events, ["activation-lock", "stop", "activation-unlock"]
                        )
                        self.assertEqual(
                            result["status"],
                            "TERMINATED_AND_REVOKED_FIXED_RUNTIME_PROFILE",
                        )
                    else:
                        stop.assert_not_called()
                        mask.assert_not_called()
                        self.assertEqual(
                            events, ["activation-lock", "activation-unlock"]
                        )
                        self.assertEqual(
                            result["status"], "NO_REVOCATION_FOR_ACTIVE_PROFILE"
                        )
                        self.assertEqual(result["before"], result["after"])
                        self.assertNotIn("future_start_barrier", result)

    def test_dispatch_noop_still_requires_fresh_accepted_bound_snapshot(self) -> None:
        for mutation in (
            {"generation": 3},
            {"generation": 5},
            {"source_digest": _OTHER},
            {"observed_at_unix": 80, "expires_at_unix": 90},
        ):
            with tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(Path(temporary).resolve())
                document = {**_accepted(fixture), "skill_digests": [], **mutation}
                _write_control(fixture.paths["revocations"], document)
                with (
                    _environment(fixture) as (_binding, _events, stop),
                    patch.object(service, "_inactive_profile", return_value=None),
                    self.assertRaises(service.RuntimeResponseError),
                ):
                    service._respond(prevent_starts=True)
                stop.assert_not_called()

    def test_inactive_dispatch_requires_two_empty_stable_fixed_units(self) -> None:
        for case in (
            "loaded",
            "masked",
            "missing",
            "pid",
            "substate",
            "cgroup",
            "populated",
            "changed",
            "partial",
        ):
            states = [
                {
                    "Id": unit,
                    "LoadState": "masked" if case == "masked" else "loaded",
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "MainPID": "0",
                    "ControlPID": "0",
                    "ControlGroup": "",
                }
                for unit in service._UNITS
            ]
            changes = {
                "missing": {"LoadState": "not-found"},
                "pid": {"ControlPID": "42"},
                "substate": {"SubState": "failed"},
                "cgroup": {"ControlGroup": "/other"},
                "partial": {
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "42",
                },
            }
            states[0].update(changes.get(case, {}))
            repeated = [dict(item) for item in states]
            if case == "changed":
                repeated[0]["MainPID"] = "42"
            with (
                self.subTest(case=case),
                patch.object(service, "_show_unit", side_effect=states + repeated),
                patch.object(
                    service,
                    "_service_cgroup",
                    side_effect=lambda unit: f"/system.slice/{unit}",
                ),
                patch.object(
                    service,
                    "_cgroup_empty",
                    return_value={"status": "ABSENT"},
                    side_effect=service.RuntimeResponseError("populated")
                    if case == "populated"
                    else None,
                ),
                patch.object(service, "_read_bindings") as bindings,
            ):
                if case == "partial":
                    self.assertIsNone(service._inactive_profile())
                elif case in {"loaded", "masked"}:
                    result = service._inactive_profile()
                    self.assertEqual(result["status"], "NO_ACTIVE_RUNTIME_PROFILE")
                    self.assertNotIn("accepted_revocation", result)
                    self.assertNotIn("future_start_barrier", result)
                else:
                    with self.assertRaises(service.RuntimeResponseError):
                        service._inactive_profile()
                bindings.assert_not_called()

    def test_retention_is_opt_in_and_failure_after_response_is_indeterminate(
        self,
    ) -> None:
        result = {"status": "TERMINATED_FIXED_RUNTIME_PROFILE"}
        for options in (
            ["--retain-evidence"],
            ["--prevent-starts", "--retain-evidence"],
            ["--retain-evidence", "--prevent-starts"],
        ):
            with (
                patch.object(service, "_run", return_value=result) as run,
                patch.object(
                    service, "_retain_result", return_value={"response": result}
                ) as retain,
                redirect_stdout(StringIO()) as output,
            ):
                self.assertEqual(service.main([*options, _SKILL, _OTHER]), 0)
                self.assertEqual(json.loads(output.getvalue()), {"response": result})
                retain.assert_called_once_with(result)
                self.assertEqual(
                    run.call_args.kwargs,
                    {"prevent_starts": True} if "--prevent-starts" in options else {},
                )
        for failure in (
            service.CASError("disk failure"),
            OSError("fsync failure"),
            RuntimeError("readback changed"),
        ):
            with (
                patch.object(service, "_run", return_value=result),
                patch.object(service, "_retain_result", side_effect=failure),
                redirect_stdout(StringIO()) as output,
                redirect_stderr(StringIO()) as errors,
            ):
                self.assertEqual(
                    service.main(["--retain-evidence", _SKILL, _OTHER]), 125
                )
                self.assertEqual(output.getvalue(), "")
                self.assertIn("INDETERMINATE", errors.getvalue())
        with patch.object(service, "_run") as run, redirect_stderr(StringIO()):
            for options in (["--retain-evidence", "--retain-evidence"], ["--unknown"]):
                self.assertEqual(service.main([*options, _SKILL, _OTHER]), 64)
            run.assert_not_called()

    def test_retention_requires_custody_exact_readback_and_complete_sync(self) -> None:
        result = {"status": "TERMINATED_FIXED_RUNTIME_PROFILE"}
        raw, digest = canonical_json(result), canonical_digest(result)
        root = service._EVIDENCE_ROOT
        blob = root / "blobs" / "sha256" / digest[7:9] / digest[9:]
        for failure in (None, "mode", "digest", "readback", "custody", "fsync", "root"):
            metadata = SimpleNamespace(
                st_dev=1,
                st_ino=2,
                st_uid=0,
                st_gid=0,
                st_mode=stat.S_IFDIR | (0o755 if failure == "mode" else 0o700),
            )
            with (
                self.subTest(failure=failure),
                patch.object(service.sys, "platform", "linux"),
                patch.object(service.os, "geteuid", return_value=0),
                patch.object(
                    service.broker, "_open_protected_directory", return_value=9
                ) as opened,
                patch.object(service.os, "fstat", return_value=metadata),
                patch.object(
                    service.os,
                    "lstat",
                    return_value=SimpleNamespace(**{**vars(metadata), "st_ino": 3})
                    if failure == "root"
                    else metadata,
                ),
                patch.object(service.os, "open", return_value=10) as descriptors,
                patch.object(service.os, "close") as close,
                patch.object(
                    service.os,
                    "fsync",
                    side_effect=OSError("fsync failed") if failure == "fsync" else None,
                ) as sync,
                patch.object(service, "CAS") as cas,
                patch.object(
                    service,
                    "_read_regular",
                    return_value=b"changed" if failure == "custody" else raw,
                ) as read,
            ):
                cas.return_value.put_expected.return_value = (
                    _OTHER if failure == "digest" else digest
                )
                cas.return_value.read.return_value = (
                    b"changed" if failure == "readback" else raw
                )
                if failure:
                    with self.assertRaises((service.RuntimeResponseError, OSError)):
                        service._retain_result(result)
                else:
                    retained = service._retain_result(result)
                    self.assertEqual(retained["response"], result)
                    self.assertEqual(retained["evidence"]["digest"], digest)
                    self.assertTrue(
                        retained["evidence"]["blob_and_directory_chain_fsynced"]
                    )
                    self.assertEqual(sync.call_count, 6)
                    self.assertEqual(
                        [call.args[0] for call in descriptors.call_args_list],
                        [
                            blob,
                            blob.parent,
                            blob.parent.parent,
                            root / "blobs",
                            root,
                            root.parent,
                        ],
                    )
                    read.assert_called_once_with(blob, 0, {0o444})
                opened.assert_called_once_with(root, 0, "response evidence")
                self.assertEqual(close.call_args.args, (9,))

    def test_future_start_masks_follow_confirmed_stop_under_both_locks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            snapshot = canonical_digest(_accepted(fixture))
            with _environment(fixture) as (_binding, events, _stop):
                barrier = {"status": "PERSISTENT_FIXED_PROFILE_STARTS_MASKED"}

                def mask():
                    self.assertEqual(service._cgroup_empty.call_count, 2)
                    self.assertEqual(events, ["activation-lock", "stop"])
                    with (
                        fixture.lock_path.open("rb") as lock,
                        self.assertRaises(BlockingIOError),
                    ):
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    events.append("mask")
                    return barrier

                with patch.object(service, "_mask_future_starts", side_effect=mask):
                    result = service._run(_SKILL, snapshot, prevent_starts=True)
                self.assertEqual(
                    events, ["activation-lock", "stop", "mask", "activation-unlock"]
                )
                self.assertEqual(result["future_start_barrier"], barrier)
                self.assertEqual(
                    result["status"], "TERMINATED_AND_REVOKED_FIXED_RUNTIME_PROFILE"
                )
                self.assertIn(
                    "FIXED_PROFILE_MASKS_NOT_GENERAL_INSTALLED_DIGEST_QUARANTINE",
                    result["limitations"],
                )
        with (
            patch.object(service, "_run", return_value={}) as run,
            redirect_stdout(StringIO()),
        ):
            self.assertEqual(service.main(["--prevent-starts", _SKILL, _OTHER]), 0)
            run.assert_called_once_with(_SKILL, _OTHER, prevent_starts=True)

    def test_mask_failure_after_stop_never_reports_success_or_rolls_back(self) -> None:
        for failure in (OSError("mask failure"), KeyboardInterrupt()):
            with (
                self.subTest(failure=type(failure)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = _Fixture(Path(temporary).resolve())
                snapshot = canonical_digest(_accepted(fixture))
                with (
                    _environment(fixture) as (_binding, events, stop),
                    patch.object(service, "_mask_future_starts", side_effect=failure),
                    self.assertRaises(service.RuntimeResponseIndeterminate),
                ):
                    service._run(_SKILL, snapshot, prevent_starts=True)
                stop.assert_called_once_with()
                self.assertEqual(
                    events, ["activation-lock", "stop", "activation-unlock"]
                )

    def test_persistent_masks_require_exact_paths_durability_and_systemd_state(
        self,
    ) -> None:
        cases = ("good", "existing", "bad-target", "bad-owner", "not-masked", "fsync")
        real_stat, real_lstat, real_fstat = os.stat, os.lstat, os.fstat

        def root_metadata(metadata, *, uid=0):
            return SimpleNamespace(
                **{
                    name: getattr(metadata, name)
                    for name in ("st_mode", "st_dev", "st_ino", "st_nlink")
                },
                st_uid=uid,
                st_gid=0,
            )

        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary).resolve()
                events = []
                if case == "existing":
                    (directory / service._UNITS[0]).write_bytes(b"existing authority")

                def command(
                    argv, *, timeout, events=events, directory=directory, case=case
                ):
                    if "mask" in argv:
                        self.assertEqual(timeout, 5)
                        self.assertEqual(
                            argv,
                            [
                                "/usr/bin/systemctl",
                                "--system",
                                "--no-pager",
                                "--no-ask-password",
                                "--quiet",
                                "--no-reload",
                                "mask",
                                *service._UNITS,
                            ],
                        )
                        events.append("mask")
                        for unit in service._UNITS:
                            (directory / unit).symlink_to(
                                "/bad-target" if case == "bad-target" else "/dev/null"
                            )
                        return b""
                    if "daemon-reload" in argv:
                        self.assertEqual(events, ["mask", "fsync"])
                        events.append("reload")
                        return b""
                    self.assertIn("show", argv)
                    self.assertEqual(events, ["mask", "fsync", "reload"])
                    return (
                        f"Id={argv[-1]}\nLoadState=masked\n"
                        f"UnitFileState={'enabled' if case == 'not-masked' else 'masked'}\n"
                        "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\n"
                    ).encode("ascii")

                def fsync(descriptor, events=events, case=case):
                    self.assertTrue(stat.S_ISDIR(real_fstat(descriptor).st_mode))
                    events.append("fsync")
                    if case == "fsync":
                        raise OSError("durability was not confirmed")

                with (
                    patch.object(service, "_MASK_ROOT", directory),
                    patch.object(service.broker, "_require_protected_ancestry"),
                    patch.object(service, "_command", side_effect=command),
                    patch.object(service.os, "fsync", side_effect=fsync),
                    patch.object(
                        service.os,
                        "fstat",
                        side_effect=lambda fd: root_metadata(real_fstat(fd)),
                    ),
                    patch.object(
                        service.os,
                        "lstat",
                        side_effect=lambda path: root_metadata(real_lstat(path)),
                    ),
                    patch.object(
                        service.os,
                        "stat",
                        side_effect=lambda *args, case=case, **kwargs: root_metadata(
                            real_stat(*args, **kwargs),
                            uid=7 if case == "bad-owner" else 0,
                        ),
                    ),
                ):
                    if case == "good":
                        result = service._mask_future_starts()
                        self.assertTrue(result["directory_fsynced"])
                        self.assertFalse(result["automatic_unmask_supported"])
                        self.assertEqual(
                            [mask["path"] for mask in result["masks"]],
                            [str(directory / unit) for unit in service._UNITS],
                        )
                    else:
                        with self.assertRaises((service.RuntimeResponseError, OSError)):
                            service._mask_future_starts()
                if case == "existing":
                    self.assertEqual(events, [])
                    self.assertEqual(
                        (directory / service._UNITS[0]).read_bytes(),
                        b"existing authority",
                    )
                else:
                    self.assertTrue(
                        all((directory / unit).is_symlink() for unit in service._UNITS)
                    )

    def test_accepted_snapshot_is_locked_through_fixed_unit_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            document = _accepted(fixture)
            before = {name: path.read_bytes() for name, path in fixture.paths.items()}
            with _environment(fixture) as (_binding, events, stop):
                result = service._run(_SKILL, canonical_digest(document))
                stop.assert_called_once_with()
                self.assertEqual(
                    events, ["activation-lock", "stop", "activation-unlock"]
                )
            self.assertEqual(
                {name: path.read_bytes() for name, path in fixture.paths.items()},
                before,
            )
            self.assertIsInstance(result, dict)
            self.assertEqual(result["expected_skill_digest"], _SKILL)
            self.assertEqual(
                result["revocation_snapshot_digest"], canonical_digest(document)
            )
            self.assertEqual(result["status"], "TERMINATED_FIXED_RUNTIME_PROFILE")
            self.assertNotIn("future_start_barrier", result)
            self.assertEqual(
                result["authority"],
                "LOCAL_ROOT_RESPONSE_RESULT_NOT_RUN_OR_PHASE3_CONFORMANCE",
            )
            self.assertEqual(result["accepted_revocation"]["generation"], 4)
            self.assertEqual(
                [entry["unit"]["Id"] for entry in result["after"]], list(service._UNITS)
            )

    def test_unbound_unaccepted_stale_or_unrevoked_snapshots_never_stop(self) -> None:
        mutations = (
            {"generation": 3},
            {"generation": 5},
            {"observed_at_unix": 80, "expires_at_unix": 90},
            {"observed_at_unix": 101, "expires_at_unix": 110},
            {"skill_digests": []},
            {"source_digest": _OTHER},
        )
        for changes in mutations:
            with (
                self.subTest(changes=changes),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = _Fixture(Path(temporary).resolve())
                document = {**_accepted(fixture), **changes}
                _write_control(fixture.paths["revocations"], document)
                with _environment(fixture) as (_binding, _events, stop):
                    with self.assertRaises((service.RuntimeResponseError, ValueError)):
                        service._run(_SKILL, canonical_digest(document))
                    stop.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            _accepted(fixture)
            with _environment(fixture) as (_binding, _events, stop):
                with self.assertRaises(service.RuntimeResponseError):
                    service._run(_SKILL, _OTHER)
                stop.assert_not_called()

    def test_preflight_identity_or_worker_binding_mismatch_never_stops(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary).resolve())
            snapshot = canonical_digest(_accepted(fixture))
            with _environment(fixture) as (binding, _events, stop):
                for name in ("_read_bindings", "_process_identity", "_unit_state"):
                    with (
                        self.subTest(name=name),
                        patch.object(
                            service,
                            name,
                            side_effect=service.RuntimeResponseError("unsafe"),
                        ),
                        self.assertRaises(service.RuntimeResponseError),
                    ):
                        service._run(_SKILL, snapshot)
                    stop.assert_not_called()
                wrong = RuntimeActionWorkerBinding(
                    runtime_digest=binding.runtime_digest,
                    active_skill_digest=_OTHER,
                    policy_digest=binding.policy_digest,
                    policy_version=binding.policy_version,
                )
                with (
                    patch.object(service, "_read_bindings", return_value=wrong),
                    self.assertRaises(service.RuntimeResponseError),
                ):
                    service._run(_SKILL, snapshot)
                stop.assert_not_called()
                for name, values in (
                    ("_read_bindings", [binding, wrong]),
                    ("_process_identity", [{"pid": 123}, {"pid": 456}, {"pid": 789}]),
                ):
                    with (
                        self.subTest(drift=name),
                        patch.object(service, name, side_effect=values),
                        self.assertRaises(service.RuntimeResponseError),
                    ):
                        service._run(_SKILL, snapshot)
                    stop.assert_not_called()
                with (
                    patch.object(service.time, "time", side_effect=[100, 106]),
                    self.assertRaises(service.RuntimeResponseError),
                ):
                    service._run(_SKILL, snapshot)
                stop.assert_not_called()

    def test_stop_failure_timeout_and_interrupt_are_indeterminate(self) -> None:
        failures = (
            OSError("native stop failed"),
            subprocess.TimeoutExpired("systemctl", 20),
            KeyboardInterrupt(),
        )
        for failure in failures:
            with (
                self.subTest(failure=type(failure)),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = _Fixture(Path(temporary).resolve())
                snapshot = canonical_digest(_accepted(fixture))
                with (
                    _environment(fixture),
                    patch.object(service, "_stop_units", side_effect=failure),
                    self.assertRaises(service.RuntimeResponseIndeterminate),
                ):
                    service._run(_SKILL, snapshot)

    def test_post_stop_population_or_confirmation_failure_is_not_success(self) -> None:
        for failure in ("populated", "replaced", "still-active"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = _Fixture(Path(temporary).resolve())
                snapshot = canonical_digest(_accepted(fixture))
                with (
                    _environment(fixture) as (_binding, _events, stop),
                    ExitStack() as stack,
                ):
                    if failure == "populated":
                        stack.enter_context(
                            patch.object(
                                service,
                                "_cgroup_empty",
                                side_effect=service.RuntimeResponseError(
                                    "descendants remain"
                                ),
                            )
                        )
                    elif failure == "replaced":
                        stack.enter_context(
                            patch.object(
                                service,
                                "_cgroup_empty",
                                return_value={
                                    "status": "EMPTY",
                                    "device": 7,
                                    "inode": 999,
                                },
                            )
                        )
                    else:
                        original = service._unit_state

                        def still_active(unit, original=original):
                            return {**original(unit), "ActiveState": "active"}

                        stack.enter_context(
                            patch.object(
                                service, "_unit_state", side_effect=still_active
                            )
                        )
                    with self.assertRaises(service.RuntimeResponseIndeterminate):
                        service._run(_SKILL, snapshot)
                    stop.assert_called_once_with()

    def test_usage_platform_root_and_digest_gates_never_stop(self) -> None:
        for arguments in ([], [_SKILL], [_SKILL, _OTHER, "extra"]):
            with self.subTest(arguments=arguments), redirect_stderr(StringIO()):
                self.assertEqual(service.main(arguments), 64)
        cases = (
            ("darwin", 0, [_SKILL, _OTHER]),
            ("linux", 501, [_SKILL, _OTHER]),
            ("linux", 0, ["--all", _OTHER]),
            ("linux", 0, [_SKILL, "not-a-digest"]),
        )
        for platform, uid, arguments in cases:
            with (
                self.subTest(platform=platform, uid=uid, arguments=arguments),
                patch.object(service.sys, "platform", platform),
                patch.object(service.os, "geteuid", return_value=uid),
                patch.object(service, "_stop_units") as stop,
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(service.main(arguments), 126)
                stop.assert_not_called()

    def test_provisioned_and_live_binding_must_join_exactly(self) -> None:
        binding = {
            "schema": service.worker._BINDING_SCHEMA,
            "runtime_digest": "sha256:" + "1" * 64,
            "active_skill_digest": _SKILL,
            "policy_digest": "sha256:" + "3" * 64,
            "policy_version": 1,
        }
        for live_uid, dispatch in ((0, False), (1001, False), (0, True), (1001, True)):
            live_path = (
                service._DISPATCH_WORKER_BINDING
                if dispatch
                else service._LIVE_WORKER_BINDING
            )

            def metadata(path, live_uid=live_uid):
                live = path in {
                    service._LIVE_WORKER_BINDING,
                    service._LIVE_WORKER_BINDING.parent,
                    service._DISPATCH_WORKER_BINDING,
                    service._DISPATCH_WORKER_BINDING.parent,
                }
                return SimpleNamespace(
                    st_uid=live_uid if live else 0,
                    st_gid=live_uid if live else 0,
                    st_mode=stat.S_IFDIR | 0o500,
                )

            with (
                self.subTest(live_uid=live_uid, dispatch=dispatch),
                patch.object(service.broker, "_require_protected_ancestry") as ancestry,
                patch.object(service.os, "lstat", side_effect=metadata),
                patch.object(
                    service.os,
                    "statvfs",
                    return_value=SimpleNamespace(f_flag=os.ST_RDONLY),
                ),
                patch.object(
                    service, "_read_regular", return_value=canonical_json(binding)
                ) as read,
            ):
                result = service._read_bindings(1001, dispatch=dispatch)
                self.assertEqual(result.active_skill_digest, _SKILL)
                self.assertEqual(
                    [call.args for call in ancestry.call_args_list],
                    [
                        (service._WORKER_BINDING.parent, 0),
                        (live_path.parent.parent, 0),
                    ],
                )
                self.assertEqual(
                    [call.args[1] for call in read.call_args_list], [0, live_uid]
                )
                self.assertEqual(read.call_args.args[0], live_path)
        with (
            patch.object(service.broker, "_require_protected_ancestry"),
            patch.object(
                service.os, "lstat", side_effect=lambda path: metadata(path, 1001)
            ),
            patch.object(service.os, "statvfs", return_value=SimpleNamespace(f_flag=0)),
            patch.object(
                service, "_read_regular", return_value=canonical_json(binding)
            ),
        ):
            for dispatch in (False, True):
                with self.assertRaises(service.RuntimeResponseError):
                    service._read_bindings(1001, dispatch=dispatch)
        for field, value in (
            ("active_skill_digest", _OTHER),
            ("runtime_digest", _OTHER),
            ("policy_digest", _OTHER),
            ("policy_version", 2),
        ):
            with (
                self.subTest(field=field),
                patch.object(service.broker, "_require_protected_ancestry"),
                patch.object(
                    service.os,
                    "lstat",
                    return_value=SimpleNamespace(
                        st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o500
                    ),
                ),
                patch.object(
                    service,
                    "_read_regular",
                    side_effect=[
                        canonical_json(binding),
                        canonical_json({**binding, field: value}),
                    ],
                ),
                self.assertRaisesRegex(service.RuntimeResponseError, "bindings differ"),
            ):
                service._read_bindings(1001)

    def test_service_cgroup_derives_only_fixed_native_or_docker_systemd_roots(
        self,
    ) -> None:
        unit = service._UNITS[0]
        docker = "/docker/" + "a" * 64
        for init_scope, expected in (
            ("/init.scope", f"/system.slice/{unit}"),
            (f"{docker}/init.scope", f"{docker}/system.slice/{unit}"),
        ):
            with patch.object(
                service, "_process_cgroup", return_value=init_scope
            ) as read:
                self.assertEqual(service._service_cgroup(unit), expected)
                read.assert_called_once_with(1)
        for unsafe in (
            "/",
            "/user.slice/init.scope",
            "/docker/short/init.scope",
            "/docker/" + "A" * 64 + "/init.scope",
            docker,
            docker + "/../init.scope",
            docker + "/system.slice/init.scope",
        ):
            with (
                self.subTest(cgroup=unsafe),
                patch.object(service, "_process_cgroup", return_value=unsafe),
                self.assertRaises(service.RuntimeResponseError),
            ):
                service._service_cgroup(unit)
        with (
            patch.object(service, "_process_cgroup") as read,
            self.assertRaises(service.RuntimeResponseError),
        ):
            service._service_cgroup("unrelated.service")
        read.assert_not_called()

    @patch.object(service, "_process_cgroup", return_value="/init.scope")
    def test_native_cgroup_confirmation_includes_descendants(self, _cgroup) -> None:
        unit = service._UNITS[0]
        cgroup = f"/system.slice/{unit}"
        before = {"ControlGroup": cgroup}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(service, "_CGROUP_ROOT", root):
                self.assertEqual(
                    service._cgroup_empty(unit, before)["status"], "ABSENT"
                )
                directory = root / cgroup.removeprefix("/")
                directory.mkdir(parents=True)
                events = directory / "cgroup.events"
                events.write_bytes(b"populated 0\nfrozen 0\n")
                with patch.object(
                    service.os,
                    "fstat",
                    return_value=SimpleNamespace(st_uid=0, st_dev=7, st_ino=8),
                ):
                    self.assertEqual(
                        service._cgroup_empty(unit, before),
                        {
                            "path": cgroup,
                            "status": "EMPTY",
                            "events": {"populated": "0", "frozen": "0"},
                            "device": 7,
                            "inode": 8,
                        },
                    )
                    for raw in (
                        b"populated 1\n",
                        b"populated 0\npopulated 0\n",
                        b"frozen 0\n",
                    ):
                        events.write_bytes(raw)
                        with (
                            self.subTest(raw=raw),
                            self.assertRaises(service.RuntimeResponseError),
                        ):
                            service._cgroup_empty(unit, before)
        with patch.object(service, "_command", return_value=b"") as command:
            service._stop_units()
        command.assert_called_once_with(
            [
                "/usr/bin/systemctl",
                "--system",
                "--no-pager",
                "--no-ask-password",
                "stop",
                *service._UNITS,
            ],
            timeout=15,
        )
        state = {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": "123",
            "ControlPID": "0",
            "ControlGroup": cgroup,
            "User": "aragorn-agent-gateway",
            "Group": "aragorn-agent-gateway",
            "KillMode": "control-group",
            "Delegate": "no",
            "Restart": "no",
            "SendSIGKILL": "yes",
            "InvocationID": "a" * 32,
        }
        raw = "".join(f"{key}={value}\n" for key, value in state.items()).encode()
        with patch.object(service, "_command", return_value=raw):
            self.assertEqual(service._unit_state(unit), state)
        for bad in (
            raw.replace(b"KillMode=control-group", b"KillMode=process"),
            raw.replace(b"SendSIGKILL=yes", b"SendSIGKILL=no"),
            raw.replace(b"Restart=no", b"Restart=always"),
            raw.replace(b"Restart=no", b"Restart=on-failure"),
            raw + b"Id=another.service\n",
        ):
            with (
                self.subTest(properties=bad),
                patch.object(service, "_command", return_value=bad),
                self.assertRaises(service.RuntimeResponseError),
            ):
                service._unit_state(unit)
        worker = {
            **state,
            "Id": service._UNITS[1],
            "User": "aragorn-runtime",
            "Group": "aragorn-runtime",
            "Restart": "on-failure",
        }
        with patch.object(
            service,
            "_command",
            return_value="".join(
                f"{key}={value}\n" for key, value in worker.items()
            ).encode(),
        ):
            self.assertEqual(service._unit_state(service._UNITS[1]), worker)

    def test_authority_files_refuse_fifo_symlink_hardlink_and_unsafe_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "regular"
            regular.write_bytes(b"safe")
            regular.chmod(0o400)
            self.assertEqual(
                service._read_regular(regular, os.geteuid(), {0o400}), b"safe"
            )
            fifo = root / "fifo"
            os.mkfifo(fifo, 0o400)
            symlink = root / "symlink"
            symlink.symlink_to(regular)
            for path in (fifo, symlink):
                with (
                    self.subTest(path=path),
                    self.assertRaises((OSError, service.RuntimeResponseError)),
                ):
                    service._read_regular(path, os.geteuid(), {0o400})
            hardlink = root / "hardlink"
            os.link(regular, hardlink)
            with self.assertRaises(service.RuntimeResponseError):
                service._read_regular(regular, os.geteuid(), {0o400})
            hardlink.unlink()
            regular.chmod(0o600)
            with self.assertRaises(service.RuntimeResponseError):
                service._read_regular(regular, os.geteuid(), {0o400})

    def test_installer_stages_exact_inert_files_and_isolated_launcher(self) -> None:
        installer = _ROOT / "packaging/install-runtime-response-host.sh"
        for forbidden in ("/etc/", "systemctl", "systemd-sysusers", "systemd-tmpfiles"):
            self.assertNotIn(forbidden, installer.read_text())
        subprocess.run(["sh", "-n", str(installer)], check=True, capture_output=True)
        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary)
            subprocess.run(
                ["sh", str(installer)],
                check=True,
                cwd=_ROOT,
                env={**os.environ, "DESTDIR": temporary},
                capture_output=True,
                timeout=30,
            )
            launcher = (
                staged / "usr/libexec/aragorn/aragorn-runtime-response-service.py"
            )
            expected = {
                staged
                / "usr/lib/systemd/system/aragorn-runtime-revocation-response.service": (
                    _ROOT
                    / "packaging/systemd/aragorn-runtime-revocation-response.service",
                    0o644,
                ),
                staged / "usr/share/aragorn/systemd/50-runtime-response.conf": (
                    _ROOT / "packaging/systemd/50-runtime-response.conf",
                    0o644,
                ),
                staged / "usr/lib/aragorn/aragorn/runtime_response_service.py": (
                    _ROOT / "src/aragorn/runtime_response_service.py",
                    0o644,
                ),
                launcher: (
                    _ROOT / "packaging/libexec/aragorn-runtime-response-service.py",
                    0o755,
                ),
            }
            for relative, directory, mode in (
                (
                    "src/aragorn/runtime_health_service.py",
                    "usr/lib/aragorn/aragorn",
                    0o644,
                ),
                (
                    "packaging/libexec/aragorn-runtime-health-service.py",
                    "usr/libexec/aragorn",
                    0o755,
                ),
                (
                    "packaging/systemd/aragorn-runtime-health-publisher.service",
                    "usr/lib/systemd/system",
                    0o644,
                ),
                (
                    "packaging/systemd/aragorn-runtime-health-response.service",
                    "usr/lib/systemd/system",
                    0o644,
                ),
                (
                    "packaging/systemd/50-runtime-health-response.conf",
                    "usr/share/aragorn/systemd",
                    0o644,
                ),
            ):
                source = _ROOT / relative
                expected[staged / directory / source.name] = (source, mode)
            for installed, (source, mode) in expected.items():
                self.assertEqual(installed.read_bytes(), source.read_bytes())
                self.assertEqual(stat.S_IMODE(installed.stat().st_mode), mode)
            self.assertEqual(
                stat.S_IMODE(
                    (staged / "var/lib/aragorn-runtime-response").stat().st_mode
                ),
                0o700,
            )
            self.assertEqual(
                list((staged / "var/lib/aragorn-runtime-response").iterdir()), []
            )
            for untouched in ("etc", "run", "opt"):
                self.assertFalse((staged / untouched).exists())
            for name in ("response", "health"):
                launcher = (
                    staged / f"usr/libexec/aragorn/aragorn-runtime-{name}-service.py"
                )
                result = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(launcher)],
                    check=False,
                    cwd=staged,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertIn(f"usage: aragorn-runtime-{name}", result.stderr)
                self.assertEqual(result.stdout, "")

        unit = (
            _ROOT / "packaging/systemd/aragorn-runtime-revocation-response.service"
        ).read_text()
        for required in (
            "Before=aragorn-runtime-revocation-publisher.service\n",
            "RefuseManualStart=yes\n",
            "User=root\n",
            "Group=root\n",
            "Type=oneshot\n",
            "RemainAfterExit=no\n",
            "CapabilityBoundingSet=CAP_DAC_OVERRIDE\n",
            "ProtectProc=default\n",
            "ProtectSystem=strict\n",
            "ProtectControlGroups=yes\n",
            "BindPaths=-/run/credentials/aragorn-runtime-action-worker.service:/run/aragorn-runtime-response-worker-credential\n",
            "ExecStart=/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-response-service.py --dispatch\n",
        ):
            self.assertIn(required, unit)
        for forbidden in (
            "[Install]",
            "After=aragorn-runtime-revocation-publisher",
            "Restart=",
            "ExecStartPost=",
            "BindReadOnlyPaths=",
        ):
            self.assertNotIn(forbidden, unit)
        self.assertEqual(
            (_ROOT / "packaging/systemd/50-runtime-response.conf").read_text(),
            "[Unit]\nOnSuccess=aragorn-runtime-revocation-response.service\nOnSuccessJobMode=fail\n",
        )

    def test_health_units_preserve_fixed_hardening_and_opt_in_hook(self) -> None:
        directory = _ROOT / "packaging/systemd"
        for kind in ("publisher", "response"):
            original = (
                directory / f"aragorn-runtime-revocation-{kind}.service"
            ).read_text()
            health = (directory / f"aragorn-runtime-health-{kind}.service").read_text()
            expected = original.replace("revocations", "health").replace(
                "revocation", "health"
            )
            if kind == "response":
                expected = expected.replace("--dispatch", "--health-dispatch")

            def directives(value):
                return [
                    line
                    for line in value.splitlines()
                    if line and not line.startswith("#")
                ]

            self.assertEqual(directives(health), directives(expected))
            for forbidden in (
                "[Install]",
                "OnSuccess=",
                "ExecStartPost=",
                "Restart=",
                "BindReadOnlyPaths=",
            ):
                self.assertNotIn(forbidden, health)
        self.assertEqual(
            (directory / "50-runtime-health-response.conf").read_text(),
            "[Unit]\nOnSuccess=aragorn-runtime-health-response.service\nOnSuccessJobMode=fail\n",
        )
        self.assertIn(
            "contention needs root retry",
            (directory / "aragorn-runtime-health-response.service").read_text(),
        )


if __name__ == "__main__":
    unittest.main()
