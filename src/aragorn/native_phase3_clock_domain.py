"""External Linux clock-domain observations, not request-event timestamps.

The root collector reads exactly itself and the caller-pinned worker and broker.
It retains independently observed active time namespaces; equality between roles
is deliberately an independent consumer decision. No services, files, namespace
transitions, clock offsets, or caller-selected observation paths are modified.
"""

from __future__ import annotations

import os
import re
import stat
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path

from . import runtime_process_profile as process

SCHEMA = "aragorn/native-phase3-clock-domain/v1"
AUTHORITY = (
    "LOCAL_ROOT_PROCESS_TIME_NAMESPACE_READBACK_NOT_REQUEST_EVENTS_OR_ATTESTATION"
)
FALSE_FLAGS = (
    "common_deployment_fully_verified",
    "route_qualified",
    "phase3_eligible",
    "live_deployment_attested",
    "metrics_eligible",
    "application_acknowledged",
)
LIMITATIONS = (
    "EXTERNAL_ROOT_OBSERVER_NOT_IN_PROCESS_REQUEST_OR_DECISION_TIMESTAMPS",
    "POINT_IN_TIME_READ_BRACKETS_NOT_CONTINUOUS_PROCESS_OR_NAMESPACE_IMMUTABILITY",
    "ACTIVE_TIME_NAMESPACE_IDENTITIES_ONLY_NO_OFFSET_TRANSLATION",
    "LOCAL_ROOT_PROC_READBACK_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
)
_PROCESS_FIELDS = {"pid", "start_time_ticks", "uid", "gid"}


class NativeClockDomainError(ValueError):
    """The fixed external process/clock read could not be safely established."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeClockDomainError(message)


def _integer(value: object, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < 2**63


def _expected(value: dict) -> dict:
    _require(
        type(value) is dict
        and set(value) == _PROCESS_FIELDS
        and all(_integer(item, 1) for item in value.values()),
        "invalid caller-held worker or broker identity",
    )
    return dict(value)


def _stamp() -> int:
    value = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    _require(_integer(value), "invalid CLOCK_BOOTTIME reading")
    return value


def _boot() -> str:
    raw = process._read_virtual_file(Path("/proc/sys/kernel/random/boot_id"), 64)
    _require(
        re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", raw)
        is not None,
        "invalid actual kernel boot identity",
    )
    return raw[:-1].decode("ascii")


def _snapshot(pid: int) -> dict:
    started = process._process_start_time(pid)
    raw = process._read_virtual_file(Path(f"/proc/{pid}/status"), 16384)
    accounts = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition(":")
        if key not in {"Uid", "Gid"}:
            continue
        parts = value.split()
        _require(
            separator == ":"
            and key not in accounts
            and len(parts) == 4
            and all(
                re.fullmatch(r"(?:0|[1-9][0-9]*)", part) is not None for part in parts
            ),
            "malformed process account vector",
        )
        values = [int(part) for part in parts]
        _require(
            all(_integer(item) for item in values) and len(set(values)) == 1,
            "process account vector is not one fixed identity",
        )
        accounts[key] = values[0]
    _require(
        set(accounts) == {"Uid", "Gid"} and _integer(started, 1),
        "incomplete process identity",
    )
    _require(
        process._process_start_time(pid) == started, "process epoch changed while read"
    )
    return {
        "pid": pid,
        "start_time_ticks": started,
        "uid": accounts["Uid"],
        "gid": accounts["Gid"],
    }


def _live_pidfd(descriptor: int, pid: int) -> None:
    process.require_live_pidfd(descriptor)
    raw = process._read_virtual_file(Path(f"/proc/self/fdinfo/{descriptor}"), 4096)
    _require(
        [
            line.partition(":")[2].strip()
            for line in raw.decode("ascii").splitlines()
            if line.startswith("Pid:")
        ]
        == [str(pid)],
        "held PIDFD differs from the expected process",
    )


def _namespace(pid: int, descriptor: int) -> dict:
    path = f"/proc/{pid}/ns/time"
    held, named = os.fstat(descriptor), os.stat(path)
    _require(
        stat.S_ISREG(held.st_mode)
        and stat.S_ISREG(named.st_mode)
        and _integer(held.st_dev)
        and _integer(held.st_ino, 1)
        and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
        and os.readlink(path) == f"time:[{held.st_ino}]",
        "held active time namespace differs from proc readback",
    )
    return {"device": held.st_dev, "inode": held.st_ino}


def observe_native_common_clock_domain(
    *, expected_worker: dict, expected_broker: dict
) -> dict:
    """Read the collector/worker/broker epochs and active namespaces once.

    All PIDFDs and namespace FDs stay held across the before/after readbacks.
    The two collector clock reads bracket external observation work, not worker
    ingress, broker finalization, or any application acknowledgement.
    """
    try:
        _require(
            sys.platform == "linux"
            and os.geteuid() == os.getegid() == 0
            and threading.get_native_id() == os.getpid()
            and hasattr(os, "pidfd_open")
            and hasattr(time, "CLOCK_BOOTTIME"),
            "Linux root main-thread PIDFD/CLOCK_BOOTTIME observation is required",
        )
        expected = {
            "worker": _expected(expected_worker),
            "broker": _expected(expected_broker),
        }
        pid = os.getpid()
        _require(
            _integer(pid, 1)
            and len({pid, expected["worker"]["pid"], expected["broker"]["pid"]}) == 3,
            "collector, worker and broker must be distinct processes",
        )
        boot = _boot()
        collector = _snapshot(pid)
        _require(
            collector["uid"] == os.geteuid() == 0
            and collector["gid"] == os.getegid() == 0,
            "collector account identity changed",
        )
        expected = {"collector": collector, **expected}
        records, descriptors = {}, {}
        with ExitStack() as held:
            for role, record in expected.items():
                process_fd = os.pidfd_open(record["pid"], 0)
                held.callback(os.close, process_fd)
                _live_pidfd(process_fd, record["pid"])
                # This one fixed proc namespace magic link must be followed in
                # order to hold the nsfs object; arbitrary paths are not accepted.
                namespace_fd = os.open(
                    f"/proc/{record['pid']}/ns/time", os.O_RDONLY | os.O_CLOEXEC
                )
                held.callback(os.close, namespace_fd)
                _require(
                    _snapshot(record["pid"]) == record,
                    "caller process epoch or accounts changed",
                )
                records[role] = {
                    **record,
                    "time_namespace": _namespace(record["pid"], namespace_fd),
                }
                descriptors[role] = process_fd, namespace_fd
            started = _stamp()
            for role, record in records.items():
                process_fd, namespace_fd = descriptors[role]
                _live_pidfd(process_fd, record["pid"])
                _require(
                    _snapshot(record["pid"]) == expected[role]
                    and _namespace(record["pid"], namespace_fd)
                    == record["time_namespace"],
                    "process epoch, accounts or active time namespace changed",
                )
            _require(
                _boot() == boot
                and os.getpid() == pid
                and os.geteuid() == collector["uid"]
                and os.getegid() == collector["gid"]
                and threading.get_native_id() == pid,
                "collector or boot identity changed",
            )
            finished = _stamp()
            _require(
                started < finished, "CLOCK_BOOTTIME observation bracket did not advance"
            )
            # Both clock samples must have collector-domain identity readbacks
            # around them. This still does not prove continuous immutability.
            for role, record in records.items():
                _live_pidfd(descriptors[role][0], record["pid"])
            _require(
                _snapshot(pid) == collector
                and _namespace(pid, descriptors["collector"][1])
                == records["collector"]["time_namespace"]
                and _boot() == boot
                and os.getpid() == pid
                and os.geteuid() == os.getegid() == 0
                and threading.get_native_id() == pid,
                "collector clock domain changed after final sample",
            )
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "clock_id": "CLOCK_BOOTTIME",
            "boot_id": boot,
            "read_started_boottime_ns": started,
            "read_finished_boottime_ns": finished,
            "processes": records,
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(FALSE_FLAGS, False),
        }
    except NativeClockDomainError:
        raise
    except Exception as exc:
        raise NativeClockDomainError(
            "native common clock-domain observation refused"
        ) from exc
