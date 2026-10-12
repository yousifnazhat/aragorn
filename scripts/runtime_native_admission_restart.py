"""Finite nonroot restart acquisition callable; coordinator owns launch and retention.

No CLI/provider fallback is exposed. The protected launcher supplies independently
held bindings and the lifecycle callable after source/config/environment custody.
"""
from __future__ import annotations

from contextlib import ExitStack
import os
from pathlib import Path
import re
import select
import selectors
import signal
import subprocess
import sys
import time

if __package__:
    from scripts import runtime_native_admission_direct_write as readers
else:
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_admission_direct_write as readers

import aragorn
from aragorn import native_phase3_admission_restart as contract
from aragorn import oci_worker_protocol
from aragorn.oci_worker_protocol import canonical_json
ROOT = "/var/lib/aragorn-agent-gateway"


def _guard(bindings):
    contract.validate_bindings(bindings)
    contract.require(sys.platform == "linux" and os.getresuid() == (992,) * 3
                     and os.getresgid() == (992,) * 3 and os.getgroups() == [992],
                     "FIXED_NONROOT_IDENTITY_REQUIRED")
    contract.require(str(Path(__file__)) == contract.PROBE
                     and str(Path(contract.__file__)) == contract.VERIFIER
                     and str(Path(readers.__file__)) == contract.shared.PROBE
                     and str(Path(contract.shared.__file__)) == contract.shared.VERIFIER
                     and str(Path(oci_worker_protocol.__file__)) == contract.SOURCE_PATHS[4]
                     and str(Path(aragorn.__file__)) == contract.SOURCE_PATHS[5],
                     "SOURCE_LOCATION_REFUSED")
    for who in ("self", str(bindings["gateway"]["pid"])):
        status = readers._status(who)
        contract.require(all(status.get(k, "").strip() == "0000000000000000"
                             for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
                         and status.get("NoNewPrivs", "").strip() == "1", "PRIVILEGE_DROP_REQUIRED")
    cgroup = readers._read_proc("/proc/self/cgroup").decode("ascii")
    contract.require(re.fullmatch(r"0::/docker/" + bindings["container"] + r"(?:/[^\n]*)?\n", cgroup),
                     "OWNED_CONTAINER_REFUSED")
    token = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
    contract.require(re.fullmatch(r"[0-9a-f]{64}", token), "FIXTURE_TOKEN_REQUIRED")
    return token


def _gateway(bindings):
    pid = bindings["gateway"]["pid"]
    value = readers._gateway(bindings["container"], pid)
    contract.require(value == bindings["gateway"], "GATEWAY_IDENTITY_CHANGED")
    for name, expected in bindings["namespaces"].items():
        contract.require(os.stat(f"/proc/{pid}/ns/{name}").st_ino == expected
                         == os.stat(f"/proc/self/ns/{name}").st_ino, "NAMESPACE_CHANGED")
    environment = readers._read_proc(f"/proc/{pid}/environ").split(b"\x00")
    for key, expected in ((b"OPENCLAW_NO_RESPAWN", b"1"), (b"TZ", b"UTC")):
        contract.require([p for p in environment if p.startswith(key + b"=")]
                         == [key + b"=" + expected], "GATEWAY_ENVIRONMENT_CHANGED")
    return value


def _sources(bindings):
    with ExitStack() as held:
        result = {path: readers._file(path, held) for path in contract.SOURCE_PATHS}
    for path, expected in bindings["source_pins"].items():
        contract.shared._file(result[path], expected)
        identity = result[path]["identity"]
        contract.require(identity[3:6] == [0, 0, 1] and identity[2] & 0o7777 == 0o444,
                         "SOURCE_CUSTODY_CHANGED")
    return result


def _boundary(bindings):
    with ExitStack() as held:
        result = {"gateway": _gateway(bindings),
                  "roots": {path: readers._tree(path, held) for path in contract.shared.ROOTS},
                  "admitted": readers._file(contract.shared.ADMITTED, held),
                  "entry": readers._file(contract.shared.ENTRY, held),
                  "config": readers._file(contract.shared.CONFIG, held),
                  "sources": _sources(bindings)}
    contract.validate_boundary(result, bindings)
    return result


def _child_start(pid):
    raw = readers._read_proc(f"/proc/{pid}/stat").decode("ascii")
    end = raw.rfind(")")
    fields = raw[end + 2:].split()
    contract.require(end > 0 and len(fields) >= 20, "CHILD_IDENTITY_REFUSED")
    return contract.integer(int(fields[19]), 1)


def _clock():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    after = time.monotonic_ns()
    return {"monotonic_before_ns": before, "realtime_ns": realtime, "monotonic_after_ns": after}


def _command(argv, token):
    """One unreaped session leader; bounded streams, then group kill and finite reap."""
    contract.require(type(argv) is tuple and argv in (*contract.CATALOGS, contract.ARGV, contract.DENIAL_ARGV),
                     "FIXED_COMMAND_REQUIRED")
    contract.require(type(token) is str and re.fullmatch(r"[0-9a-f]{64}", token), "FIXTURE_TOKEN_REQUIRED")
    contract.require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "CHILD_CUSTODY_REQUIRED")
    env = {"HOME": ROOT + "/home", "OPENCLAW_STATE_DIR": ROOT + "/state",
           "OPENCLAW_CONFIG_PATH": contract.shared.CONFIG, "OPENCLAW_NO_RESPAWN": "1",
           "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
           "NO_COLOR": "1", "TZ": "UTC", "NO_PROXY": "127.0.0.1,localhost"}
    if argv != contract.DENIAL_ARGV:
        env["OPENCLAW_GATEWAY_TOKEN"] = token
    streams = {"stdout": b"", "stderr": b""}
    start_clock = _clock()
    row = {"argv": list(argv), "pid": None, "start_time_ticks": None,
           "started_realtime_ns": start_clock["realtime_ns"],
           "started_monotonic_ns": start_clock["monotonic_before_ns"],
           "start_clock": start_clock, "completion_clock": None,
           "completed_realtime_ns": None, "completed_monotonic_ns": None,
           "exit_code": None, "stdout_base64": "", "stderr_base64": "",
           "group_cleanup": False, "leader_reaped": False, "cleanup_failures": []}
    deadline = row["started_monotonic_ns"] + 15000000000
    process, failure, owned = None, None, True
    try:
        process = subprocess.Popen(list(argv), cwd=ROOT + "/workspace", env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        row["pid"] = process.pid
        row["start_time_ticks"] = _child_start(process.pid)
        with selectors.DefaultSelector() as selector:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic_ns()
                contract.require(remaining > 0, "COMMAND_DEADLINE_EXCEEDED")
                for key, _ in selector.select(min(remaining / 1e9, 0.25)):
                    capacity = contract.shared.MAX_COMMAND - len(streams[key.data])
                    try:
                        chunk = os.read(key.fileobj.fileno(), min(65536, capacity + 1))
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        streams[key.data] += chunk[:capacity]
                        contract.require(len(chunk) <= capacity, "COMMAND_OUTPUT_EXCEEDED")
            try:
                while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    remaining = deadline - time.monotonic_ns()
                    contract.require(remaining > 0, "COMMAND_DEADLINE_EXCEEDED")
                    time.sleep(min(remaining / 1e9, 0.01))
            except ChildProcessError:
                owned = False
                raise
            row["completion_clock"] = _clock()
            row["completed_realtime_ns"] = row["completion_clock"]["realtime_ns"]
            row["completed_monotonic_ns"] = row["completion_clock"]["monotonic_after_ns"]
            contract.require(row["completed_monotonic_ns"] <= deadline, "COMMAND_DEADLINE_EXCEEDED")
    except BaseException as error:
        failure = error
    finally:
        if process is not None:
            try:
                contract.require(owned, "CHILD_CUSTODY_LOST")
                try:
                    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except ChildProcessError:
                    owned = False
                    raise
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                row["group_cleanup"] = True
            except BaseException as error:
                row["cleanup_failures"].append("PROCESS_GROUP_CLEANUP_REFUSED")
                failure = failure or error
            try:
                contract.require(owned, "CHILD_CUSTODY_LOST")
                row["exit_code"] = process.wait(timeout=5)
                row["leader_reaped"] = True
            except BaseException as error:
                row["cleanup_failures"].append("LEADER_REAP_REFUSED")
                failure = failure or error
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except BaseException as error:
                    row["cleanup_failures"].append("PIPE_CLOSE_REFUSED")
                    failure = failure or error
    for channel, raw in streams.items():
        row[channel + "_base64"] = contract.encode(raw)
    if failure is not None:
        failure._native_restart_command = row
        raise failure
    return row


def run_restart_probe(*, expected_bindings, read_native_restart_lifecycle):
    """Acquire once. Return private retained evidence; launcher owns durable custody."""
    # Freeze caller values before using callbacks; never derive expected pins from observations.
    bindings = contract.parse(canonical_json(expected_bindings))
    result = {"schema": contract.SCHEMA, "status": "REFUSED", "bindings": bindings,
              "before": None, "dispatch_boundary": None, "after": None,
              "commands_before": [], "commands_after": [], "restart": None,
              "lifecycle": [], "markers": [], "refusal": None, "partial": [],
              "cleanup_failures": [], "limitations": list(contract.LIMITATIONS),
              **dict.fromkeys(contract.shared.FALSE_FLAGS, False)}
    pidfd, interruption, previous_handler = None, None, None
    phase, snapshots = "PREREQUISITES", []

    def fail(error):
        nonlocal interruption
        result["status"] = "REFUSED"
        if result["refusal"] is None:
            result["refusal"] = {"phase": phase, "reason": (
                str(error) if type(error) is contract.NativeRestartError else "FIXED_RESTART_LEAF_REFUSED")}
        if not isinstance(error, Exception) and interruption is None:
            interruption = error

    def terminate(signum, frame):
        raise KeyboardInterrupt("RESTART_LEAF_TERMINATED")

    try:
        token = _guard(bindings)
        contract.require(callable(read_native_restart_lifecycle), "PROTECTED_READER_REQUIRED")
        previous_handler = signal.signal(signal.SIGTERM, terminate)
        pidfd = os.pidfd_open(bindings["gateway"]["pid"], 0)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)

        def alive():
            contract.require(not poller.poll(0), "GATEWAY_EXITED")
            _gateway(bindings)

        def boundary():
            alive()
            value = _boundary(bindings)
            alive()
            return value

        def execute(argv, target):
            alive()
            contract.require(_sources(bindings) == result["before"]["sources"], "SOURCE_CHANGED")
            try:
                row = _command(argv, token)
            except BaseException as error:
                partial = getattr(error, "_native_restart_command", None)
                if partial is not None:
                    result["partial"].append({"kind": "command", "record": partial})
                raise
            if target == "restart":
                result["restart"] = row
            else:
                result[target].append(row)
            contract.command(row, argv, bindings["gateway"]["pid"])
            alive()
            return row

        def lifecycle(name, deadline=None):
            alive()
            start = time.monotonic_ns()
            deadline = deadline if deadline is not None else start + 3000000000
            contract.require(start < deadline, "LIFECYCLE_DEADLINE_EXCEEDED")
            old = snapshots[-1] if snapshots else None
            try:
                raw = read_native_restart_lifecycle(
                    phase=name, previous_snapshot_digest=contract.digest(old[2]) if old else None,
                    after_cursor=old[0]["cursor"] if old else None,
                    deadline_monotonic_ns=deadline)
            except BaseException as error:
                partial = getattr(error, "partial_bytes", None)
                if type(partial) is bytes:
                    result["partial"].append({"kind": "lifecycle", "phase": name,
                                              "raw_base64": contract.encode(partial[:contract.MAX_ENVELOPE]),
                                              "truncated": len(partial) > contract.MAX_ENVELOPE})
                if isinstance(error, Exception):
                    raise contract.NativeRestartError("LIFECYCLE_PROVIDER_FAILED") from error
                raise
            end = time.monotonic_ns()
            contract.require(type(raw) is bytes, "LIFECYCLE_BYTES_REQUIRED")
            if len(raw) > contract.MAX_ENVELOPE:
                result["partial"].append({"kind": "lifecycle", "phase": name,
                                          "raw_base64": contract.encode(raw[:contract.MAX_ENVELOPE]),
                                          "truncated": True})
                raise contract.NativeRestartError("SNAPSHOT_BOUND")
            result["lifecycle"].append({"raw_base64": contract.encode(raw),
                "call_started_ns": start, "call_completed_ns": end, "deadline_ns": deadline})
            contract.require(start <= end <= deadline, "LIFECYCLE_DEADLINE_EXCEEDED")
            value = contract.snapshot(raw, phase=name, bindings=bindings, previous=old)
            acquisition = value[0]["acquisition"]
            contract.require(start <= acquisition["started_ns"] <= acquisition["completed_ns"] <= end,
                             "LIFECYCLE_ACQUISITION_OUTSIDE_CALL")
            snapshots.append(value)
            alive()

        phase = "INITIAL"
        result["before"] = boundary()
        lifecycle("INITIAL")
        contract.initial_readiness(snapshots[0][1], snapshots[0][1])
        phase = "PRECHECKS"
        for argv in (*contract.CATALOGS, contract.DENIAL_ARGV):
            execute(argv, "commands_before")
        contract.catalogs(result["commands_before"], bindings["gateway"]["pid"])
        phase = "BOUNDARY"
        lifecycle("BOUNDARY")
        contract.initial_readiness(snapshots[0][1], snapshots[1][1])
        result["dispatch_boundary"] = boundary()
        contract.require(result["dispatch_boundary"] == result["before"], "PROTECTED_STATE_CHANGED")
        phase = "RESTART"
        restart = execute(contract.ARGV, "restart")
        phase = "AFTER"
        lifecycle("AFTER", restart["started_monotonic_ns"] + 20000000000)
        result["markers"] = contract.markers(*(s[1] for s in snapshots))
        phase = "POSTCHECKS"
        for argv in (*contract.CATALOGS, contract.DENIAL_ARGV):
            execute(argv, "commands_after")
        result["after"] = boundary()
        phase = "REPLAY"
        result["status"] = "OBSERVED"
        raw = canonical_json(result)
        contract.verify_native_admission_restart(raw, expected_raw_digest=contract.digest(raw),
                                                expected_bindings=bindings)
        alive()
    except BaseException as error:
        fail(error)
    finally:
        if pidfd is not None and result["before"] is not None and result["after"] is None:
            try:
                result["after"] = boundary()
            except BaseException as error:
                result["cleanup_failures"].append("FINAL_BOUNDARY_UNAVAILABLE")
                fail(error)
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as error:
                result["cleanup_failures"].append("GATEWAY_PIDFD_CLOSE_REFUSED")
                fail(error)
        if previous_handler is not None:
            try:
                signal.signal(signal.SIGTERM, previous_handler)
            except BaseException as error:
                result["cleanup_failures"].append("SIGNAL_RESTORE_REFUSED")
                fail(error)
    if interruption is not None:
        interruption._native_restart_leaf = result
        raise interruption
    return result
