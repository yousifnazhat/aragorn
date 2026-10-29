"""Suspend the fixed runtime when its accepted health expires or is unhealthy."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import time
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import runtime_action_broker as broker
from . import runtime_response_service as response
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_decision import _health, qualify_runtime_health_epoch

_PENDING = Path("/var/lib/aragorn-runtime-response/health-watchdog-pending.json")
_LIMITATIONS = [
    "ACCEPTED_HEALTH_WALL_CLOCK_EXPIRY_NOT_SENSOR_HEARTBEAT_OR_HANG_DETECTION",
    "MISSING_MALFORMED_OR_UNBOUND_HEALTH_REFUSED_NOT_EXPIRY_AUTHORITY",
    "PERIODIC_LOCAL_TRIGGER_NOT_DURABLE_QUEUE_OR_BOUNDED_RESPONSE_LATENCY",
    "FIXED_PROFILE_MASKS_REQUIRE_INDEPENDENT_ROOT_REMOVAL",
    "PENDING_RESPONSE_REQUIRES_ROOT_REPAIR_AFTER_INTERRUPTION_OR_FAILURE",
    "NO_RUN_PHASE3_EDR_OR_RELEASE_CONFORMANCE_AUTHORITY",
]


@contextmanager
def _pending_directory():
    descriptor = broker._open_protected_directory(
        _PENDING.parent, 0, "watchdog evidence"
    )
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise response.RuntimeResponseError(
                "watchdog evidence must be root:root 0700"
            )
        yield descriptor
    finally:
        os.close(descriptor)


def _check_pending(descriptor: int) -> None:
    try:
        os.stat(_PENDING.name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise response.RuntimeResponseIndeterminate(
        "watchdog pending response requires root repair"
    )


def _create_pending(descriptor: int, result: dict[str, Any]) -> tuple[int, ...]:
    raw = canonical_json({**result, "status": "RESPONSE_PENDING"})
    fd = os.open(
        _PENDING.name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o400,
        dir_fd=descriptor,
    )
    # Leave even an incomplete latch in place if writing or syncing fails.
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
        identity = broker._file_identity(os.fstat(stream.fileno()))
    os.fsync(descriptor)
    return identity


def _clear_pending(descriptor: int, identity: tuple[int, ...]) -> None:
    if (
        broker._file_identity(
            os.stat(_PENDING.name, dir_fd=descriptor, follow_symlinks=False)
        )
        != identity
    ):
        raise response.RuntimeResponseIndeterminate("watchdog pending response changed")
    os.unlink(_PENDING.name, dir_fd=descriptor)
    os.fsync(descriptor)


def _locked_health(control_fd: int, config: Any, binding: Any) -> dict[str, Any]:
    def read(path):
        return broker._parse_canonical_document(
            response._read_regular(
                path, config.expected_broker_uid, {0o400}, dir_fd=control_fd
            ),
            "watchdog health authority",
        )

    policy = read(config.policy_path)
    state = broker._state(read(config.state_path))
    health = _health(read(config.health_path))
    now = int(time.time())
    # Check the complete existing authority contract at the last valid second.
    # Only expiry is relaxed; a future observation still cannot qualify.
    epoch = qualify_runtime_health_epoch(
        policy,
        health,
        expected_runtime_digest=binding.runtime_digest,
        now_unix=min(now, health["expires_at_unix"] - 1),
        minimum_mediator_health_epoch=state["minimum_mediator_health_epoch"],
    )
    if (
        epoch is None
        or epoch != state["minimum_mediator_health_epoch"]
        or canonical_digest(policy) != binding.policy_digest
        or policy["version"] != binding.policy_version
    ):
        raise response.RuntimeResponseError("watchdog health is unaccepted or unbound")
    return {
        "snapshot_digest": canonical_digest(health),
        "status": health["status"],
        "expired": now >= health["expires_at_unix"],
        "epoch": epoch,
        "minimum_mediator_health_epoch": state["minimum_mediator_health_epoch"],
        "policy_digest": canonical_digest(policy),
        "worker_runtime_digest": binding.runtime_digest,
        "sensor_digest": health["sensor_digest"],
        "observed_at_unix": health["observed_at_unix"],
        "expires_at_unix": health["expires_at_unix"],
    }


def _run() -> dict[str, Any]:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise response.RuntimeResponseError("root Linux execution is required")
    stop_attempted = False
    try:
        with response._activation_guard(), _pending_directory() as pending_fd:
            _check_pending(pending_fd)
            inactive = response._inactive_profile()
            if inactive is not None:
                return inactive
            identities = response._identities()
            owners = ((identities[3], identities[4]), (identities[1], identities[2]))
            before = [response._unit_state(unit) for unit in response._UNITS]
            processes = [
                response._process_identity(unit, state, uid, gid)
                for unit, state, (uid, gid) in zip(
                    response._UNITS, before, owners, strict=True
                )
            ]
            binding = response._read_bindings(identities[1], dispatch=True)
            config = response._broker_config(identities, binding)
            with response._broker_guard(config) as control_fd:
                accepted = _locked_health(control_fd, config, binding)
                if response._read_bindings(identities[1], dispatch=True) != binding:
                    raise response.RuntimeResponseError(
                        "watchdog worker binding changed"
                    )
                for unit, state, process, (uid, gid) in zip(
                    response._UNITS, before, processes, owners, strict=True
                ):
                    current = response._unit_state(unit)
                    if (
                        current != state
                        or response._process_identity(unit, current, uid, gid)
                        != process
                    ):
                        raise response.RuntimeResponseError(
                            "watchdog runtime identity changed"
                        )
                if _locked_health(control_fd, config, binding) != accepted:
                    raise response.RuntimeResponseError(
                        "watchdog health changed before response"
                    )
                observed = [
                    {"unit": state, "process": process}
                    for state, process in zip(before, processes, strict=True)
                ]
                result = {
                    "schema": "aragorn/runtime-health-watchdog-result/v1",
                    "authority": "LOCAL_ROOT_RESPONSE_RESULT_NOT_RUN_OR_PHASE3_CONFORMANCE",
                    "expected_skill_digest": binding.active_skill_digest,
                    "accepted_health": accepted,
                    "before": observed,
                    "limitations": list(_LIMITATIONS),
                }
                if not accepted["expired"] and accepted["status"] == "healthy":
                    return {
                        **result,
                        "status": "ACCEPTED_HEALTHY_FIXED_RUNTIME_PROFILE",
                        "after": observed,
                    }
                # ponytail: fixed profile stop; per-capability responses need bound units.
                pending_identity = _create_pending(pending_fd, result)
                stop_attempted = True
                response._stop_units()
                after = []
                for unit, state, process in zip(
                    response._UNITS, before, processes, strict=True
                ):
                    current = response._unit_state(unit)
                    if (
                        current["ActiveState"] != "inactive"
                        or current["SubState"] != "dead"
                        or current["MainPID"] != "0"
                        or current["ControlPID"] != "0"
                        or current["ControlGroup"] not in {"", state["ControlGroup"]}
                    ):
                        raise response.RuntimeResponseError(
                            "watchdog termination unconfirmed"
                        )
                    empty = response._cgroup_empty(unit, state)
                    if empty["status"] == "EMPTY" and (
                        empty["device"] != process["cgroup_device"]
                        or empty["inode"] != process["cgroup_inode"]
                    ):
                        raise response.RuntimeResponseError(
                            "watchdog cgroup identity changed"
                        )
                    after.append({"unit": current, "cgroup": empty})
                result = {
                    **result,
                    "status": "SUSPENDED_EXPIRED_HEALTH_FIXED_RUNTIME_PROFILE"
                    if accepted["expired"]
                    else "SUSPENDED_UNHEALTHY_FIXED_RUNTIME_PROFILE",
                    "after": after,
                    "future_start_barrier": response._mask_future_starts(),
                }
                retained = response._retain_result(result)
                _clear_pending(pending_fd, pending_identity)
                return retained
    except BaseException as exc:
        if stop_attempted:
            raise response.RuntimeResponseIndeterminate(
                "watchdog response pending; termination, masks or retention unconfirmed"
            ) from exc
        raise


def main(argv: Sequence[str] | None = None) -> int:
    if list(sys.argv[1:] if argv is None else argv):
        print("usage: aragorn-runtime-health-watchdog", file=sys.stderr)
        return 64
    completed = False
    try:
        result = _run()
        completed = True
        # A one-second timer must not append healthy/idle CAS evidence indefinitely.
        if result.get("schema") == "aragorn/retained-runtime-response/v1":
            print(canonical_json(result).decode("ascii"))
        return 0
    except response.RuntimeResponseIndeterminate:
        print("aragorn health watchdog: INDETERMINATE response", file=sys.stderr)
        return 125
    except KeyboardInterrupt:
        return 125 if completed else 130
    except (
        response.CASError,
        OSError,
        ValueError,
        TypeError,
        RuntimeError,
        KeyError,
        subprocess.SubprocessError,
    ):
        print(
            "aragorn health watchdog: INDETERMINATE retention"
            if completed
            else "aragorn health watchdog: REFUSED authority or response",
            file=sys.stderr,
        )
        return 125 if completed else 126


if __name__ == "__main__":
    raise SystemExit(main())
