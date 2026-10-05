"""Independent, read-only process observations for the fixed common profile.

This does not call the common live identity reader or project its observations.
The frozen native/journal helpers supply account, gateway, boot and kernel reads.
The endpoint loop is explicit here because its broker command has a third
credential; neither frozen command inventories nor their globals are modified.
"""

from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
import re
import sys

if __package__:
    from scripts import runtime_native_receipt_systemd_check as native
else:
    sys.path[:0] = ["/usr/lib/aragorn", str(Path(__file__).resolve().parent)]
    import runtime_native_receipt_systemd_check as native

from aragorn import runtime_process_profile as process

prior = native.prior
response = native.response
SCHEMA = "aragorn/phase3-common-process-observation/v1"
AUTHORITY = "INDEPENDENT_LOCAL_PROCESS_READBACK_NOT_DEPLOYMENT_OR_APPLICATION_ACK"
LIMITATIONS = (
    "POINT_IN_TIME_PIDFD_HELD_PROCESS_READS_NOT_CONTINUOUS_IMMUTABILITY",
    "NO_PROTECTED_BYTES_LOADED_CREDENTIAL_OR_PYTHON_PROVENANCE_MEASURED",
    "LOCAL_ROOT_OBSERVER_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
)
_FALSE = (
    "common_deployment_fully_verified",
    "route_qualified",
    "phase3_eligible",
    "live_deployment_attested",
    "metrics_eligible",
    "application_acknowledged",
)
_BROKER_COMMAND = (
    "aragorn-runtime-action-service-v5.py",
    ("runtime-binding", "capability-grant", "decision-measurement-binding"),
)


class CommonProcessObservationError(ValueError):
    """A fixed readback refused, without publishing native diagnostic text."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CommonProcessObservationError(message)


def _argv(role: str) -> list[str]:
    unit = prior._ROLES[role]
    shim, credentials = _BROKER_COMMAND if role == "broker" else prior._COMMANDS[role]
    return [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        "/usr/libexec/aragorn/" + shim,
        *(f"/run/credentials/{unit}/{name}" for name in credentials),
    ]


def _endpoint(role: str, container: str, identities: tuple) -> dict:
    broker, worker, worker_gid, _, _, sensor, sensor_gid = identities
    expected = {
        "worker": (worker, worker_gid, "aragorn-runtime", "aragorn-runtime"),
        "sensor": (sensor, sensor_gid, "aragorn-sensor", "aragorn-sensor"),
        "broker": (broker, worker_gid, "aragorn-broker", "aragorn-runtime"),
    }
    unit, argv = prior._ROLES[role], _argv(role)
    raw = response._command(
        [
            "/usr/bin/systemctl",
            "show",
            "--property=" + ",".join(prior._PROPERTIES),
            unit,
        ],
        timeout=3,
    )
    pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
    _require(all(len(pair) == 2 for pair in pairs), "malformed endpoint unit readback")
    state = dict(pairs)
    _require(
        len(pairs) == len(prior._PROPERTIES) and set(state) == set(prior._PROPERTIES),
        "endpoint unit property inventory changed",
    )
    uid, gid, user, group = expected[role]
    cgroup = f"/docker/{container}/system.slice/{unit}"
    _require(
        re.fullmatch(r"[1-9][0-9]*", state["MainPID"]) is not None,
        "endpoint has no active PID",
    )
    pid = int(state["MainPID"])
    _require(
        state["Id"] == unit
        and state["ActiveState"] == "active"
        and state["SubState"] == "running"
        and state["ControlPID"] == "0"
        and state["ControlGroup"] == cgroup
        and state["User"] == user
        and state["Group"] == group
        and state["StandardOutput"] == "journal"
        and state["DropInPaths"] == ""
        and Path(state["FragmentPath"]).resolve(strict=True)
        == Path("/usr/lib/systemd/system") / unit
        and re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"]) is not None
        and state["InvocationID"] != "0" * 32
        and state["ExecStart"].startswith(
            "{ path=/usr/bin/python3.12 ; argv[]="
            + " ".join(argv)
            + " ; ignore_errors=no ; "
        )
        and state["ExecStart"].count("argv[]=") == 1,
        "endpoint unit or common credential arguments changed",
    )
    started = response._process_start_time(pid)
    pairs = [
        line.split(":", 1)
        for line in prior._read_virtual_file(Path(f"/proc/{pid}/status"), 8192)
        .decode("ascii")
        .splitlines()
        if ":" in line
    ]
    fields = dict(pairs)
    _require(len(fields) == len(pairs), "duplicate process status fields")
    uids = [int(value) for value in fields["Uid"].split()]
    gids = [int(value) for value in fields["Gid"].split()]
    command = prior._read_virtual_file(Path(f"/proc/{pid}/cmdline"), 4096)
    executable = os.readlink(f"/proc/{pid}/exe")
    _require(
        uids == [uid, uid, uid, worker if role == "sensor" else uid]
        and gids == [gid, gid, gid, worker_gid if role == "sensor" else gid]
        and command == b"\0".join(item.encode("ascii") for item in argv) + b"\0"
        and executable == str(Path("/usr/bin/python3.12").resolve(strict=True))
        and response._process_cgroup(pid) == cgroup
        and response._process_start_time(pid) == started
        and re.fullmatch(r"socket:\[[1-9][0-9]*\]", os.readlink(f"/proc/{pid}/fd/1"))
        is not None,
        "endpoint kernel identity changed",
    )
    return {
        "unit": state,
        "process": {
            "pid": pid,
            "uid": uid,
            "gid": gid,
            "uids": uids,
            "gids": gids,
            "start_time_ticks": started,
            "cgroup": cgroup,
            "executable": executable,
            "command": " ".join(argv),
        },
    }


def _processes(container: str, identities: tuple) -> dict:
    gateway, gateway_gid = identities[3:5]
    unit = native.setup_prior._GATEWAY
    state = response._unit_state(unit)
    identity = response._process_identity(unit, state, gateway, gateway_gid)
    _require(
        identity["cgroup"] == f"/docker/{container}/system.slice/{unit}"
        and state["InvocationID"] != "0" * 32,
        "gateway is outside the owned process epoch",
    )
    result = {"gateway": {"unit": state, "process": identity}}
    for role in prior._ROLES:
        result[role] = _endpoint(role, container, identities)
    _require(
        len({record["process"]["pid"] for record in result.values()}) == 4,
        "common fixture PIDs overlap",
    )
    return result


def _pidfd(record: dict) -> int:
    fd = os.pidfd_open(record["pid"], 0)
    try:
        info = prior._read_virtual_file(Path(f"/proc/self/fdinfo/{fd}"), 16384).decode(
            "ascii"
        )
        _require(
            [
                line.partition(":")[2].strip()
                for line in info.splitlines()
                if line.startswith("Pid:")
            ]
            == [str(record["pid"])],
            "PIDFD does not pin the independently observed process",
        )
        process.require_live_pidfd(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def observe_common_processes(*, expected_container_id: str) -> dict:
    """Perform bounded real reads, retaining the original second-observer shape."""
    try:
        return _observe(expected_container_id)
    except CommonProcessObservationError:
        raise
    except Exception as exc:
        raise CommonProcessObservationError(
            "common process observation refused"
        ) from exc


def _observe(container: str) -> dict:
    _require(
        sys.platform == "linux"
        and os.geteuid() == os.getegid() == 0
        and hasattr(os, "pidfd_open"),
        "Linux root and PIDFD support required",
    )
    _require(
        type(container) is str and re.fullmatch(r"[0-9a-f]{64}", container) is not None,
        "invalid owned fixture identity",
    )
    init = f"/docker/{container}/init.scope"
    _require(response._process_cgroup(1) == init, "observer is outside owned fixture")
    boot, identities = prior._boot(), response._identities()
    records = _processes(container, identities)
    with ExitStack() as stack:
        descriptors = []
        for entry in records.values():
            fd = _pidfd(entry["process"])
            stack.callback(os.close, fd)
            descriptors.append(fd)
        # This second bounded read is an identity recheck, never a case retry.
        _require(
            _processes(container, identities) == records,
            "process identity changed across PIDFD acquisition",
        )
        for fd in descriptors:
            process.require_live_pidfd(fd)
        _require(
            prior._boot() == boot
            and response._identities() == identities
            and response._process_cgroup(1) == init,
            "observer boot, accounts or fixture changed",
        )
        result = {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "container_id": container,
            "boot_id": boot,
            "processes": records,
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(_FALSE, False),
        }
    return result
