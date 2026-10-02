"""One idle native sensor process exit; never full sensor-health qualification."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import signal
import sys
import time
from pathlib import Path

_SCHEMA = "aragorn/runtime-native-sensor-loss-observation/v1"
_AUTHORITY = (
    "OWNED_IDLE_SENSOR_PROCESS_EXIT_ONLY_NOT_FULL_SENSOR_HEALTH_OR_RUN_QUALIFICATION"
)
_GATEWAY = "aragorn-agent-gateway.service"
_WORKER = "aragorn-runtime-action-worker.service"
_SENSOR = "aragorn-runtime-lineage-capability-observation-publisher.service"
_BROKER = "aragorn-runtime-lineage-capability-action-broker.service"
_TIMER = "aragorn-runtime-health-watchdog.timer"
_WATCHDOG = "aragorn-runtime-health-watchdog.service"
_UNITS = (_GATEWAY, _WORKER, _SENSOR, _BROKER)
_PROPERTIES = (
    "Id",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "InvocationID",
    "NRestarts",
    "Restart",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
)
_FALSE_FLAGS = (
    "phase3_eligible",
    "run_conformance_eligible",
    "run02_eligible",
    "production_activation_eligible",
    "full_sensor_health_coverage",
    "hung_sensor_coverage",
    "stale_sensor_coverage",
    "inflight_action_coverage",
    "general_socket_reachability_verified",
)
_REFUSAL_REASONS = frozenset(
    {
        "unexpected unit selector",
        "sensor exit observation exceeded its deadline",
        "malformed unit state",
        "incomplete unit state",
        "watchdog timer has triggered",
        "watchdog was activated or is not inactive",
        "invalid owned cgroup selector",
        "invalid owned cgroup membership",
        "unit escaped owned cgroup",
        "broker process disappeared",
        "pidfd signaling is unavailable; numeric PID fallback forbidden",
        "sensor is outside verified fixture",
        "sensor identity changed after pidfd open",
        "watchdog state changed before signal",
        "native cgroup prerequisite unavailable",
        "fresh native fixture is denied",
        "idle native receipts changed",
        "idle stack is incomplete",
        "broker changed after native identity verification",
        "sensor exit did not fail-stop the owned stack",
        "sensor exit terminal state did not remain stable",
        "native identity or protected state changed",
        "native fixed unit identity changed",
    }
)


class SensorLossError(RuntimeError):
    """Fixed local assertions; no external diagnostic text."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise SensorLossError(message)


def _native():
    sys.path[:0] = [
        "/usr/lib/aragorn",
        str(Path(__file__).resolve().parent),
        "/src/scripts",
    ]
    spec = importlib.util.spec_from_file_location(
        "native_sensor_loss_bootstrap",
        "/opt/aragorn/runtime-native-receipt-systemd-check.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _timeout(deadline: float | None) -> float:
    remaining = 3 if deadline is None else min(3, deadline - time.monotonic())
    _expect(remaining > 0, "sensor exit observation exceeded its deadline")
    return remaining


def _show(
    native, unit: str, properties: tuple[str, ...] = _PROPERTIES, *, deadline=None
) -> dict:
    _expect(unit in (*_UNITS, _TIMER, _WATCHDOG), "unexpected unit selector")
    raw = native.response._command(
        [
            "/usr/bin/systemctl",
            "show",
            "--all",
            "--property=" + ",".join(properties),
            unit,
        ],
        timeout=_timeout(deadline),
    )
    pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
    _expect(all(len(pair) == 2 for pair in pairs), "malformed unit state")
    state = dict(pairs)
    _expect(
        len(pairs) == len(properties)
        and set(state) == set(properties)
        and state["Id"] == unit,
        "incomplete unit state",
    )
    return state


def _watchdog(native, *, deadline=None) -> dict:
    states = {
        _TIMER: _show(
            native, _TIMER, ("Id", "ActiveState", "SubState"), deadline=deadline
        ),
        _WATCHDOG: _show(
            native,
            _WATCHDOG,
            ("Id", "ActiveState", "SubState", "MainPID", "InvocationID"),
            deadline=deadline,
        ),
    }
    # systemctl formats time properties as durations; compare the typed value.
    triggered = native.response._command(
        [
            "/usr/bin/busctl",
            "get-property",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/aragorn_2druntime_2dhealth_2dwatchdog_2etimer",
            "org.freedesktop.systemd1.Timer",
            "LastTriggerUSecMonotonic",
        ],
        timeout=_timeout(deadline),
    )
    _expect(triggered == b"t 0\n", "watchdog timer has triggered")
    states[_TIMER]["LastTriggerUSecMonotonic"] = "0"
    _expect(
        all(
            value["ActiveState"] == "inactive" and value["SubState"] == "dead"
            for value in states.values()
        )
        and states[_TIMER]["LastTriggerUSecMonotonic"] == "0"
        and states[_WATCHDOG]["MainPID"] == "0"
        and states[_WATCHDOG]["InvocationID"] in ("", "0" * 32),
        "watchdog was activated or is not inactive",
    )
    return states


def _members(native, container: str, unit: str) -> dict:
    _expect(
        re.fullmatch(r"[0-9a-f]{64}", container) is not None and unit in _UNITS,
        "invalid owned cgroup selector",
    )
    path = Path(f"/sys/fs/cgroup/docker/{container}/system.slice/{unit}/cgroup.procs")
    try:
        raw = native.prior._read_virtual_file(path, 65536)
    except FileNotFoundError:
        return {"path": str(path), "present": False, "members": []}
    members = raw.decode("ascii").split()
    _expect(
        all(re.fullmatch(r"[1-9][0-9]*", item) for item in members)
        and len(set(members)) == len(members),
        "invalid owned cgroup membership",
    )
    return {
        "path": str(path),
        "present": True,
        "members": sorted(int(item) for item in members),
    }


def _snapshot(native, p37b, container: str, *, deadline=None) -> dict:
    units = {}
    for unit in _UNITS:
        state = _show(native, unit, deadline=deadline)
        expected = f"/docker/{container}/system.slice/{unit}"
        _expect(state["ControlGroup"] in ("", expected), "unit escaped owned cgroup")
        units[unit] = {"unit": state, "cgroup": _members(native, container, unit)}
    broker = units[_BROKER]["unit"]
    _expect(
        re.fullmatch(r"[1-9][0-9]*", broker["MainPID"]) is not None,
        "broker process disappeared",
    )
    pid = int(broker["MainPID"])
    return {
        "units": units,
        "broker_process": {
            "pid": pid,
            "start_time_ticks": native.response._process_start_time(pid),
            "cgroup": native.response._process_cgroup(pid),
        },
        "endpoint_paths_present": {
            str(path): os.path.lexists(path)
            for path in (p37b._WORKER_SOCKET, p37b._SENSOR_SOCKET)
        },
        "watchdog": _watchdog(native, deadline=deadline),
    }


def _stopped(record: dict, *, failed: bool = False) -> bool:
    unit = record["unit"]
    return (
        unit["ActiveState"] == ("failed" if failed else "inactive")
        and unit["SubState"] == ("failed" if failed else "dead")
        and unit["MainPID"] == unit["ControlPID"] == "0"
        and not record["cgroup"]["members"]
    )


def _terminal(before: dict, after: dict) -> bool:
    sensor_before, sensor_after = (
        state["units"][_SENSOR]["unit"] for state in (before, after)
    )
    return (
        all(_stopped(after["units"][unit]) for unit in (_GATEWAY, _WORKER))
        and _stopped(after["units"][_SENSOR], failed=True)
        and sensor_after["NRestarts"] == sensor_before["NRestarts"]
        and sensor_after["InvocationID"] == sensor_before["InvocationID"]
        and sensor_after["Restart"] == "no"
        and sensor_after["Result"] == "signal"
        and sensor_after["ExecMainCode"] == "2"
        and sensor_after["ExecMainStatus"] == str(signal.SIGKILL)
        and after["units"][_BROKER] == before["units"][_BROKER]
        and after["broker_process"] == before["broker_process"]
        and after["watchdog"] == before["watchdog"]
        and set(after["endpoint_paths_present"])
        == set(before["endpoint_paths_present"])
        and len(after["endpoint_paths_present"]) == 2
        and not any(after["endpoint_paths_present"].values())
    )


def _signal_sensor(native, container: str, processes: dict, before: dict) -> dict:
    _expect(
        hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
        "pidfd signaling is unavailable; numeric PID fallback forbidden",
    )
    verified = processes["sensor"]
    pid = verified["process"]["pid"]
    expected_group = f"/docker/{container}/system.slice/{_SENSOR}"
    _expect(
        verified["process"]["cgroup"] == expected_group
        and before["units"][_SENSOR]["unit"]["MainPID"] == str(pid),
        "sensor is outside verified fixture",
    )
    descriptor = os.pidfd_open(pid, 0)
    try:
        state = _show(native, _SENSOR)
        members = _members(native, container, _SENSOR)
        _expect(
            state == before["units"][_SENSOR]["unit"]
            and state["InvocationID"] == verified["unit"]["InvocationID"]
            and state["ActiveState"] == "active"
            and state["SubState"] == "running"
            and state["ControlPID"] == "0"
            and state["Restart"] == "no"
            and state["ControlGroup"] == expected_group
            and pid in members["members"]
            and native.response._process_start_time(pid)
            == verified["process"]["start_time_ticks"]
            and native.response._process_cgroup(pid) == expected_group,
            "sensor identity changed after pidfd open",
        )
        _expect(
            _watchdog(native) == before["watchdog"],
            "watchdog state changed before signal",
        )
        started = time.monotonic_ns()
        signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
        return {
            "method": "pidfd_send_signal",
            "signal": "SIGKILL",
            "pid": pid,
            "started_monotonic_ns": started,
            "identity_rechecked_after_open": True,
        }
    finally:
        os.close(descriptor)


def _run(container: str) -> dict:
    native = _native()
    native.setup_prior._require_fixture(container)
    import runtime_action_worker_openclaw_systemd_probe as p37b
    import runtime_native_cgroup_prerequisite as cgroup

    _expect(
        native.setup_prior._ALL_UNITS == _UNITS, "native fixed unit identity changed"
    )
    sources = native._sources(health=True, startup_reserve=True)
    terminal = None
    failure = None
    try:
        prerequisites = cgroup.observe(container)
        _expect(
            prerequisites["status"] == "READY", "native cgroup prerequisite unavailable"
        )
        _watchdog(native)
        setup = (
            native._prepare()
        )  # Fresh provisioning/startup only; no read/create driver.
        budget = native._checked_startup_budget(container, cgroup)
        processes, boot = native.prior._processes(container), native.prior._boot()
        installed = native.setup_prior._installed(setup["skill_digest"])
        _expect(installed["denial"] is None, "fresh native fixture is denied")
        effects = p37b._snapshot_effects()
        receipts = native._snapshot(setup["provisioning"]["genesis_digest"], 0)
        _expect(receipts == setup["empty_store"], "idle native receipts changed")
        before = _snapshot(native, p37b, container)
        _expect(
            all(
                value["unit"]["ActiveState"] == "active"
                and value["unit"]["SubState"] == "running"
                and int(value["unit"]["MainPID"]) in value["cgroup"]["members"]
                for value in before["units"].values()
            )
            and all(before["endpoint_paths_present"].values()),
            "idle stack is incomplete",
        )
        _expect(
            before["broker_process"]
            == {
                key: processes["broker"]["process"][key]
                for key in ("pid", "start_time_ticks", "cgroup")
            },
            "broker changed after native identity verification",
        )
        action = _signal_sensor(native, container, processes, before)
        deadline = action["started_monotonic_ns"] / 1_000_000_000 + 20
        while True:
            after = _snapshot(native, p37b, container, deadline=deadline)
            _expect(
                time.monotonic() < deadline,
                "sensor exit observation exceeded its deadline",
            )
            if _terminal(before, after):
                break
            _expect(
                time.monotonic() < deadline,
                "sensor exit did not fail-stop the owned stack",
            )
            time.sleep(0.05)
        first_terminal_ns = time.monotonic_ns()
        stable_until = time.monotonic() + 2
        while time.monotonic() < stable_until:
            time.sleep(0.05)
            after = _snapshot(native, p37b, container)
            _expect(
                _terminal(before, after),
                "sensor exit terminal state did not remain stable",
            )
        terminal = after
        _expect(
            native._snapshot(setup["provisioning"]["genesis_digest"], 0) == receipts
            and p37b._snapshot_effects() == effects
            and native.prior._boot() == boot
            and native._sources(health=True, startup_reserve=True) == sources
            and native.setup_prior._installed(setup["skill_digest"]) == installed,
            "native identity or protected state changed",
        )
        observation = {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "status": "OBSERVED",
            "fixture_container": container,
            "setup": setup,
            "installed_sources": sources,
            "cgroup_prerequisites": prerequisites,
            "startup_task_budget": budget,
            "processes_before": processes,
            "boot_id": boot,
            "before": before,
            "signal": action,
            "first_terminal_monotonic_ns": first_terminal_ns,
            "stable_terminal_monotonic_ns": time.monotonic_ns(),
            "terminal_before_cleanup": terminal,
            "empty_receipt_store_after": receipts,
            "protected_effects_unchanged": True,
            "endpoint_authority": "FIXED_WORKER_AND_SENSOR_PATH_ABSENCE_ONLY",
            **dict.fromkeys(_FALSE_FLAGS, False),
        }
    except BaseException as exc:
        failure = exc
        raise
    finally:
        # Terminal evidence is retained above before this narrow state cleanup.
        try:
            try:
                if terminal is not None:
                    native.response._command(
                        ["/usr/bin/systemctl", "stop", _SENSOR], timeout=3
                    )
                    native.response._command(
                        ["/usr/bin/systemctl", "reset-failed", _SENSOR], timeout=3
                    )
            finally:
                cleanup = native.prior._stop_fixture()
        except BaseException:
            if failure is None:
                raise
            # Keep the first refusal; the host still removes this owned container.
    observation["fixture_stack_cleanup"] = cleanup
    observation["cleanup_sensor_reset_failed_after_terminal_evidence"] = True
    return observation


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1 or re.fullmatch(r"[0-9a-f]{64}", arguments[0]) is None:
        print(
            "usage: runtime_native_sensor_loss_check OWNED_CONTAINER_ID",
            file=sys.stderr,
        )
        return 64
    try:
        result = _run(arguments[0])
        print(
            json.dumps(
                result,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - retain only controlled text or an exception type
        detail = str(exc) if type(exc) is SensorLossError else type(exc).__name__
        print("native sensor loss fixture refused: " + detail, file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
