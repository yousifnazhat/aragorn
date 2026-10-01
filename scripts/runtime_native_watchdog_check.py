"""One accepted-health expiry through the timer in a fresh owned fixture only."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path[:0] = [
    "/usr/lib/aragorn",
    str(Path(__file__).resolve().parent),
    "/src/scripts",
]

import runtime_native_health_systemd_check as health

from aragorn import runtime_health_watchdog as watchdog

response, retained = health.response, health.retained
_SERVICE = "aragorn-runtime-health-watchdog.service"
_TIMER = "aragorn-runtime-health-watchdog.timer"
_UNITS = (_TIMER, _SERVICE)
_TTL_SECONDS = 15
_DEADLINE_SECONDS = 30


class WatchdogFixtureError(RuntimeError):
    """Fixed fixture assertions only, never arbitrary external exception text."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise WatchdogFixtureError(message)


def _show(unit: str, properties: tuple[str, ...]) -> dict[str, str]:
    _expect(unit in _UNITS, "unsupported watchdog unit selector")
    raw = response._command(
        [
            "/usr/bin/systemctl",
            "show",
            "--all",
            "--property=" + ",".join(properties),
            unit,
        ],
        timeout=3,
    )
    pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
    _expect(all(len(pair) == 2 for pair in pairs), "malformed watchdog unit state")
    state = dict(pairs)
    _expect(
        len(pairs) == len(properties)
        and set(state) == set(properties)
        and state["Id"] == unit,
        "incomplete watchdog unit state",
    )
    # systemctl may format *USec properties as durations; use typed D-Bus values
    # for comparisons with the journal's integer microsecond timestamps.
    for name in set(properties) & {
        "LastTriggerUSecMonotonic",
        "ExecMainStartTimestampMonotonic",
        "ExecMainExitTimestampMonotonic",
    }:
        interface = "Timer" if unit == _TIMER else "Service"
        object_path = "/org/freedesktop/systemd1/unit/" + unit.replace(
            "-", "_2d"
        ).replace(".", "_2e")
        value = (
            response._command(
                [
                    "/usr/bin/busctl",
                    "get-property",
                    "org.freedesktop.systemd1",
                    object_path,
                    "org.freedesktop.systemd1." + interface,
                    name,
                ],
                timeout=3,
            )
            .decode("ascii")
            .strip()
        )
        match = re.fullmatch(r"t ([0-9]{1,20})", value)
        _expect(
            match is not None and int(match[1]) < 2**64,
            "watchdog monotonic timestamp is not a typed uint64",
        )
        state[name] = match[1]
    return state


def _states() -> dict:
    return {
        _TIMER: _show(
            _TIMER,
            ("Id", "ActiveState", "SubState", "LastTriggerUSecMonotonic"),
        ),
        _SERVICE: _show(
            _SERVICE,
            (
                *health._STATE,
                "ExecMainStartTimestampMonotonic",
                "ExecMainExitTimestampMonotonic",
            ),
        ),
    }


def _contract() -> dict:
    common = ("Id", "LoadState", "FragmentPath", "DropInPaths")
    timer = _show(
        _TIMER,
        (*common, "Unit", "AccuracyUSec", "RandomizedDelayUSec", "UnitFileState"),
    )
    service = _show(
        _SERVICE,
        (
            *common,
            "RefuseManualStart",
            "Type",
            "User",
            "Group",
            "ExecStart",
            "TasksMax",
            "PrivateNetwork",
            "ProtectSystem",
            "StartLimitIntervalUSec",
        ),
    )
    for unit, state in ((_TIMER, timer), (_SERVICE, service)):
        _expect(
            state["LoadState"] == "loaded"
            and state["DropInPaths"] == ""
            and state["FragmentPath"]
            in {"/lib/systemd/system/" + unit, "/usr/lib/systemd/system/" + unit}
            and Path(state["FragmentPath"]).resolve(strict=True)
            == Path("/usr/lib/systemd/system/" + unit),
            "watchdog unit source or drop-in changed",
        )
    _expect(
        timer["Unit"] == _SERVICE
        and timer["AccuracyUSec"] == "100ms"
        and timer["RandomizedDelayUSec"] == "0"
        and timer["UnitFileState"] == "disabled"
        and all(
            service[key] == value
            for key, value in {
                "RefuseManualStart": "yes",
                "Type": "oneshot",
                "User": "root",
                "Group": "root",
                "TasksMax": "8",
                "PrivateNetwork": "yes",
                "ProtectSystem": "strict",
                "StartLimitIntervalUSec": "0",
            }.items()
        )
        and service["ExecStart"].startswith(
            "{ path=/usr/bin/python3.12 ; argv[]=/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-health-watchdog.py ; ignore_errors=no ; "
        )
        and service["ExecStart"].count("argv[]=")
        == service["ExecStart"].count("path=")
        == 1,
        "effective watchdog contract changed",
    )
    return {"timer": timer, "service": service}


def _journal(cursor: str, boot: str) -> list[dict]:
    _expect(
        re.fullmatch(r"[A-Za-z0-9;=_-]{1,1024}", cursor) is not None
        and re.fullmatch(r"[0-9a-f]{32}", boot) is not None,
        "unbounded watchdog journal selector",
    )
    raw = response._command(
        [
            "/usr/bin/journalctl",
            "--quiet",
            "--all",
            "--no-pager",
            "--output=json",
            "--output-fields=" + ",".join(sorted(health._JOURNAL_FIELDS)),
            "--cursor=" + cursor,
            "--lines=3",
            "_SYSTEMD_UNIT=" + _SERVICE,
            "_BOOT_ID=" + boot,
        ],
        timeout=5,
    )
    _expect(
        len(raw) <= 131072
        and (not raw or raw.endswith(b"\n"))
        and len(raw.splitlines()) <= 2,
        "watchdog journal is ambiguous or oversized",
    )
    rows, seen = [], set()
    for line in raw.splitlines():
        row = json.loads(line, object_pairs_hook=health._object)
        _expect(
            type(row) is dict
            and set(row) == health._JOURNAL_FIELDS
            and all(type(value) is str for value in row.values())
            and row["_SYSTEMD_UNIT"] == _SERVICE
            and row["_BOOT_ID"] == boot
            and row["__CURSOR"] not in seen
            and re.fullmatch(r"[A-Za-z0-9;=_-]{1,1024}", row["__CURSOR"]) is not None
            and re.fullmatch(r"[0-9a-f]{32}", row["_SYSTEMD_INVOCATION_ID"]) is not None
            and all(
                re.fullmatch(r"[0-9]{1,20}", row[key]) is not None
                and 0 < int(row[key]) < 2**64
                for key in ("__MONOTONIC_TIMESTAMP", "__REALTIME_TIMESTAMP")
            ),
            "watchdog journal invocation is unbound",
        )
        document = response.broker._parse_canonical_document(
            row["MESSAGE"].encode("ascii"), "watchdog journal result"
        )
        seen.add(row["__CURSOR"])
        if row["__CURSOR"] != cursor:
            rows.append(
                {
                    "journal": row,
                    "invocation_id": row["_SYSTEMD_INVOCATION_ID"],
                    "result": document,
                }
            )
    _expect(len(rows) <= 1, "watchdog has multiple new results")
    return rows


def _complete(state: dict) -> bool:
    return (
        state["ActiveState"] == "inactive"
        and state["SubState"] == "dead"
        and state["MainPID"] == state["ControlPID"] == state["ExecMainStatus"] == "0"
        and state["Result"] == "success"
        and int(state["ExecMainExitTimestampMonotonic"])
        >= int(state["ExecMainStartTimestampMonotonic"])
        > 0
    )


def _join(captured: dict, document: dict, setup: dict, before: list[dict]) -> dict:
    result, evidence = retained._retained_response(captured["result"])
    expected_health = {
        "snapshot_digest": health.canonical_digest(document),
        "status": "healthy",
        "expired": True,
        "epoch": document["epoch"],
        "minimum_mediator_health_epoch": document["epoch"],
        "policy_digest": health.canonical_digest(setup["policy"]),
        "worker_runtime_digest": setup["runtime_digest"],
        "sensor_digest": document["sensor_digest"],
        "observed_at_unix": document["observed_at_unix"],
        "expires_at_unix": document["expires_at_unix"],
    }
    _expect(
        result["schema"] == "aragorn/runtime-health-watchdog-result/v1"
        and result["authority"]
        == "LOCAL_ROOT_RESPONSE_RESULT_NOT_RUN_OR_PHASE3_CONFORMANCE"
        and result["expected_skill_digest"] == setup["skill_digest"]
        and result["status"] == "SUSPENDED_EXPIRED_HEALTH_FIXED_RUNTIME_PROFILE"
        and result["accepted_health"] == expected_health
        and result["before"] == before
        and int(captured["journal"]["__REALTIME_TIMESTAMP"])
        >= document["expires_at_unix"] * 1_000_000,
        "watchdog expiry authority or process identity is unbound",
    )
    barrier = result["future_start_barrier"]
    _expect(
        barrier["status"] == "PERSISTENT_FIXED_PROFILE_STARTS_MASKED"
        and barrier["directory_fsynced"] is True
        and barrier["automatic_unmask_supported"] is False
        and len(barrier["masks"]) == 2
        and [item["unit"]["Id"] for item in result["after"]] == list(response._UNITS)
        and all(
            item["unit"]["ActiveState"] == "inactive"
            and item["unit"]["SubState"] == "dead"
            and item["unit"]["MainPID"] == item["unit"]["ControlPID"] == "0"
            and item["cgroup"]["status"] in {"EMPTY", "ABSENT"}
            for item in result["after"]
        ),
        "watchdog did not stop and persistently mask the fixed profile",
    )
    return {**captured, "retention": evidence}


def run_after_native(container: str, observation: dict, native: Any) -> dict:
    health._guard(container)
    import runtime_action_worker_openclaw_systemd_probe as p37b

    _expect(
        observation["fixture_container"] == container
        and observation["status"] == "OBSERVED"
        and observation["phase3_eligible"] is False
        and observation["run_conformance_eligible"] is False,
        "watchdog predecessor observation is unbound",
    )
    setup = observation["setup"]
    _expect(
        native.prior._processes(container) == observation["processes"]
        and native.prior._boot() == observation["boot_id"],
        "watchdog predecessor processes changed",
    )
    contract, fresh = _contract(), _states()
    _expect(
        all(
            item["ActiveState"] == "inactive" and item["SubState"] == "dead"
            for item in fresh.values()
        )
        and fresh[_TIMER]["LastTriggerUSecMonotonic"] == "0"
        and fresh[_SERVICE]["ExecMainStartTimestampMonotonic"] == "0",
        "watchdog fixture is not fresh",
    )
    before = retained._running(response._identities())
    effects, state = health._effect_snapshot(p37b, observation), health._controls(setup)
    floor = state["minimum_mediator_health_epoch"]
    _expect(
        type(floor) is int and 0 < floor < 2**53 - 1,
        "watchdog accepted floor is invalid",
    )
    hook = health._install_hook()
    processes = native.prior._processes(container)
    health._check_hook_processes(observation["processes"], processes)
    now, cursor = int(time.time()), native.prior._cursor()
    document = {
        "schema": "aragorn/runtime-mediator-health/v1",
        "runtime_digest": setup["runtime_digest"],
        "sensor_digest": setup["policy"]["sensor_digest"],
        "epoch": floor + 1,
        "status": "healthy",
        "observed_at_unix": now,
        "expires_at_unix": now + _TTL_SECONDS,
    }
    publication = health._join(
        health._publish(p37b, document, cursor, observation["boot_id"]),
        document,
        setup,
        before,
        unhealthy=False,
    )
    _expect(
        health._controls(setup)
        == {**state, "minimum_mediator_health_epoch": floor + 1},
        "healthy watchdog publication changed broker effects",
    )
    cursor, deadline = native.prior._cursor(), time.monotonic() + _DEADLINE_SECONDS
    response._command(["/usr/bin/systemctl", "start", _TIMER], timeout=5)
    healthy = None
    while True:
        states = _states()
        _expect(
            all(item["ActiveState"] != "failed" for item in states.values()),
            "watchdog timer or service failed",
        )
        _expect(
            states[_TIMER]["ActiveState"] == "active",
            "watchdog timer stopped before expiry",
        )
        if healthy is None and _complete(states[_SERVICE]):
            _expect(
                time.time() < document["expires_at_unix"]
                and int(states[_TIMER]["LastTriggerUSecMonotonic"]) > 0
                and native.prior._processes(container) == processes
                and retained._running(response._identities()) == before,
                "healthy timer invocation was not a no-op",
            )
            healthy = states
        rows = _journal(cursor, observation["boot_id"])
        if (
            rows
            and _complete(states[_SERVICE])
            and int(states[_SERVICE]["ExecMainExitTimestampMonotonic"])
            >= int(rows[0]["journal"]["__MONOTONIC_TIMESTAMP"])
        ):
            _expect(healthy is not None, "no healthy timer invocation preceded expiry")
            expiry = _join(rows[0], document, setup, before)
            break
        _expect(
            time.monotonic() < deadline,
            "watchdog expiry did not complete within fixed deadline",
        )
        time.sleep(0.1)
    cleanup = stop_extra_units()
    _expect(
        watchdog._PENDING
        == Path("/var/lib/aragorn-runtime-response/health-watchdog-pending.json")
        and not os.path.lexists(watchdog._PENDING),
        "watchdog indeterminate response latch remains",
    )
    start = retained._start_refused()
    receipts = native._snapshot(setup["provisioning"]["genesis_digest"], 4)
    final_state = response.broker._state(
        response.broker._parse_canonical_document(
            response._read_regular(
                p37b.lineage._CONTROL / "state.json", response._identities()[0], {0o400}
            ),
            "final watchdog fixture state",
        )
    )
    _expect(
        receipts == observation["receipt_store_after_create"]
        and health._effect_snapshot(p37b, observation) == effects
        and final_state == {**state, "minimum_mediator_health_epoch": floor + 1}
        and native.prior._boot() == observation["boot_id"],
        "watchdog changed retained native evidence or effects",
    )
    return {
        "schema": "aragorn/native-watchdog-systemd-observation/v1",
        "status": "OBSERVED",
        "fixture_container": container,
        "authority": "OWNED_ACCEPTED_HEALTH_EXPIRY_RESPONSE_ONLY_NOT_SENSOR_HEARTBEAT_OR_RUN_QUALIFICATION",
        "contract": contract,
        "fresh_units": fresh,
        "hook": hook,
        "processes_after_hook": processes,
        "accepted_floor_before": floor,
        "healthy_publication": publication,
        "healthy_timer_completion": healthy,
        "watchdog_response": expiry,
        "timer_cleanup": cleanup,
        "indeterminate_latch_absent": True,
        "persistent_start_refusal": start,
        "native_receipts_retained": receipts["state_digest"],
        "native_target_and_broker_receipt_unchanged": True,
        "phase3_eligible": False,
        "run_conformance_eligible": False,
        "sensor_loss_detection": False,
        "durable_dispatch_queue": False,
        "production_activation_eligible": False,
    }


def stop_extra_units() -> dict:
    health._guard()
    response._command(["/usr/bin/systemctl", "stop", _TIMER, _SERVICE], timeout=15)
    states = _states()
    _expect(
        all(
            item["ActiveState"] == "inactive" and item["SubState"] == "dead"
            for item in states.values()
        )
        and states[_SERVICE]["MainPID"] == states[_SERVICE]["ControlPID"] == "0",
        "watchdog fixture cleanup is unconfirmed",
    )
    return states
