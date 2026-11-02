"""Fixed nonroot upload-denial leaf; no staging, activation or fixture cleanup."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import re
import select
import selectors
import signal
import stat
import subprocess
import sys
import time

if __package__:
    from scripts import runtime_native_admission_direct_write as readers
else:
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_admission_direct_write as readers

from aragorn import native_phase3_admission_install as contract
from aragorn.oci_worker_protocol import canonical_json

PROBE = "/opt/aragorn/runtime_native_admission_install.py"
VERIFIER = "/usr/lib/aragorn/aragorn/native_phase3_admission_install.py"
SCHEMA = "aragorn/native-admission-install-leaf/v1"
CATALOGS = tuple(
    ("/usr/local/bin/node", contract.shared.ENTRY, *args)
    for _, args in contract.shared.COMMANDS
)
ROOT = "/var/lib/aragorn-agent-gateway"


def _guard(arguments):
    contract.require(
        sys.platform == "linux"
        and os.getresuid() == (992, 992, 992)
        and os.getresgid() == (992, 992, 992) and os.getgroups() == [992],
        "FIXED_NONROOT_IDENTITY_REQUIRED",
    )
    container, pid = arguments["expected_container"], arguments["expected_gateway_pid"]
    contract.require(type(container) is str
                     and re.fullmatch(r"[0-9a-f]{64}", container) is not None
                     and type(pid) is int and pid > 1, "OWNED_CALLER_REFUSED")
    for key, value in arguments.items():
        if key.endswith("digest"):
            contract.shared.pin(value)
    contract.require(
        str(Path(__file__)) == PROBE and str(Path(contract.__file__)) == VERIFIER
        and str(Path(readers.__file__)) == contract.shared.PROBE
        and str(Path(contract.shared.__file__)) == contract.shared.VERIFIER,
        "SOURCE_LOCATION_REFUSED",
    )
    own = readers._status("self")
    contract.require(
        all(own.get(key, "").strip() == "0000000000000000"
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        and own.get("NoNewPrivs", "").strip() == "1", "PRIVILEGE_DROP_REQUIRED",
    )
    contract.require(re.fullmatch(
        r"0::/docker/" + container + r"(?:/[^\n]*)?\n",
        readers._read_proc("/proc/self/cgroup").decode("ascii"),
    ) is not None, "OWNED_CONTAINER_REFUSED")
    token = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
    contract.require(re.fullmatch(r"[0-9a-f]{64}", token) is not None,
                     "FIXTURE_TOKEN_REQUIRED")
    return token


def _sources(pins):
    with ExitStack() as held:
        result = {}
        for path, pin in pins.items():
            row = readers._file(path, held)
            contract.shared._file(row, pin)
            metadata = row["identity"]
            contract.require(metadata[3:6] == [0, 0, 1]
                             and stat.S_IMODE(metadata[2]) == 0o444,
                             "SOURCE_CUSTODY_REFUSED")
            result[path] = row
        return result


def _command(argv, token):
    """Own one session leader until group cleanup; retain only bounded metadata on failure."""
    contract.require(type(argv) is list and tuple(argv) in (*CATALOGS, contract.ARGV),
                     "FIXED_COMMAND_REQUIRED")
    contract.require(type(token) is str
                     and re.fullmatch(r"[0-9a-f]{64}", token) is not None,
                     "FIXTURE_TOKEN_REQUIRED")
    contract.require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
                     "CHILD_CUSTODY_REQUIRED")
    env = {
        "HOME": ROOT + "/home", "OPENCLAW_STATE_DIR": ROOT + "/state",
        "OPENCLAW_CONFIG_PATH": contract.shared.CONFIG, "OPENCLAW_GATEWAY_TOKEN": token,
        "OPENCLAW_NO_RESPAWN": "1", "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C", "LC_ALL": "C", "NO_COLOR": "1", "TZ": "UTC",
        "NO_PROXY": "127.0.0.1,localhost",
    }
    streams = {"stdout": b"", "stderr": b""}
    metadata = {"argv": argv, "launched": False, "exit_code": None,
                "group_cleanup": False, "leader_reaped": False, "cleanup_failures": []}
    process, failure, owned = None, None, True
    try:
        process = subprocess.Popen(
            argv, cwd=ROOT + "/workspace", env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        metadata["launched"] = True
        deadline = time.monotonic() + 15
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                contract.require(remaining > 0, "COMMAND_DEADLINE_EXCEEDED")
                for key, _ in selector.select(min(remaining, 0.25)):
                    # One excess byte detects overflow without retaining an unbounded chunk.
                    chunk = os.read(key.fileobj.fileno(), min(
                        65536, contract.shared.MAX_COMMAND + 1 - len(streams[key.data]),
                    ))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        streams[key.data] += chunk
                        contract.require(len(streams[key.data]) <= contract.shared.MAX_COMMAND,
                                         "COMMAND_OUTPUT_EXCEEDED")
            # WNOWAIT keeps this owned PID reserved until its group is killed below.
            try:
                while os.waitid(os.P_PID, process.pid,
                                os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                    remaining = deadline - time.monotonic()
                    contract.require(remaining > 0, "COMMAND_DEADLINE_EXCEEDED")
                    time.sleep(min(remaining, 0.01))
            except ChildProcessError:
                owned = False
                raise
    except BaseException as error:
        failure = error
    finally:
        if process is not None:
            try:
                contract.require(owned, "CHILD_CUSTODY_LOST")
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                metadata["group_cleanup"] = True
            except BaseException as error:
                metadata["cleanup_failures"].append("PROCESS_GROUP_CLEANUP_REFUSED")
                if failure is None or not isinstance(error, Exception):
                    failure = error
            try:
                contract.require(owned, "CHILD_CUSTODY_LOST")
                metadata["exit_code"] = process.wait(timeout=5)
                metadata["leader_reaped"] = True
            except BaseException as error:
                metadata["cleanup_failures"].append("LEADER_REAP_REFUSED")
                if failure is None or not isinstance(error, Exception):
                    failure = error
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except BaseException as error:
                    metadata["cleanup_failures"].append("PIPE_CLOSE_REFUSED")
                    if failure is None or not isinstance(error, Exception):
                        failure = error
    for channel, raw in streams.items():
        metadata[channel + "_bytes"] = len(raw)
        metadata[channel + "_digest"] = contract.shared.digest(raw)
    if failure is None:
        expected_code = 1 if tuple(argv) == contract.ARGV else 0
        if (metadata["exit_code"] != expected_code or not streams["stdout"]
                or streams["stderr"] or token.encode() in streams["stdout"]):
            failure = contract.NativeInstallError("COMMAND_RESULT_REFUSED")
    if failure is not None:
        failure._native_install_command = metadata
        raise failure
    completed = subprocess.CompletedProcess(argv, metadata["exit_code"],
                                            streams["stdout"], streams["stderr"])
    completed._native_install_command = metadata
    return completed


def run_install_probe(*, expected_container, expected_gateway_pid,
                      expected_admitted_digest, expected_probe_digest,
                      expected_verifier_digest, expected_shared_probe_digest,
                      expected_shared_verifier_digest):
    arguments = dict(
        expected_container=expected_container, expected_gateway_pid=expected_gateway_pid,
        expected_admitted_digest=expected_admitted_digest,
        expected_probe_digest=expected_probe_digest, expected_verifier_digest=expected_verifier_digest,
        expected_shared_probe_digest=expected_shared_probe_digest,
        expected_shared_verifier_digest=expected_shared_verifier_digest,
    )
    bindings = {key: value for key, value in arguments.items()
                if key not in ("expected_probe_digest", "expected_verifier_digest")}
    pins = {PROBE: expected_probe_digest, VERIFIER: expected_verifier_digest,
            contract.shared.PROBE: expected_shared_probe_digest,
            contract.shared.VERIFIER: expected_shared_verifier_digest}
    result = {
        "schema": SCHEMA, "status": "REFUSED", "refusal": None,
        "observation": None, "source_pins": pins, "sources_before": None,
        "sources_after": None, "gateway": None, "command_failures": [],
        "cleanup_failures": [], **dict.fromkeys(contract.shared.FALSE_FLAGS, False),
    }
    phase, interruption, pidfd = "PREREQUISITES", None, None

    def refuse(error):
        nonlocal interruption
        result["status"] = "REFUSED"
        if result["refusal"] is None:
            result["refusal"] = {"phase": phase, "reason": "FIXED_INSTALL_LEAF_REFUSED"}
        if not isinstance(error, Exception) and interruption is None:
            interruption = error

    try:
        token = _guard(arguments)
        pidfd = os.pidfd_open(expected_gateway_pid, 0)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        result["sources_before"] = _sources(pins)
        result["gateway"] = readers._gateway(expected_container, expected_gateway_pid)

        def alive():
            contract.require(not poller.poll(0), "GATEWAY_EXITED")
            contract.require(readers._gateway(expected_container, expected_gateway_pid)
                             == result["gateway"], "GATEWAY_IDENTITY_CHANGED")

        def boundary():
            alive()
            value = readers._boundary(expected_container, expected_gateway_pid)
            contract.shared.validate_boundary(
                value, container=expected_container, gateway_pid=expected_gateway_pid,
                admitted_pin=expected_admitted_digest,
                source_pins={path: pins[path] for path in
                             (contract.shared.PROBE, contract.shared.VERIFIER)},
            )
            contract.require(value["gateway"] == result["gateway"], "GATEWAY_IDENTITY_CHANGED")
            alive()
            return value

        def command(argv):
            alive()
            contract.require(_sources(pins) == result["sources_before"], "SOURCES_CHANGED")
            value = None
            try:
                value = _command(argv, token)
                alive()
            except BaseException as error:
                metadata = getattr(error, "_native_install_command", None) or getattr(
                    value, "_native_install_command", None,
                )
                if metadata is not None:
                    result["command_failures"].append(metadata)
                raise
            return value

        phase = "RECORDING"
        try:
            result["observation"] = contract.record_native_admission_install(
                read_boundary=boundary, run_command=command, **bindings,
            )
        except BaseException as error:
            result["observation"] = getattr(error, "_native_install_observation", None)
            refuse(error)
        finally:
            phase = "POSTCONDITIONS"
            try:
                result["sources_after"] = _sources(pins)
                contract.require(result["sources_after"] == result["sources_before"],
                                 "SOURCES_CHANGED")
                alive()
            except BaseException as error:
                refuse(error)
        if result["refusal"] is None:
            phase = "REPLAY"
            raw = canonical_json(result["observation"])
            contract.verify_native_admission_install(
                raw, expected_raw_digest=contract.shared.digest(raw), **bindings,
            )
            contract.require(not result["command_failures"], "COMMAND_FAILURE_RETAINED")
            result["status"] = "OBSERVED"
    except BaseException as error:
        refuse(error)
    finally:
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as error:
                result["cleanup_failures"].append("GATEWAY_PIDFD_CLOSE_REFUSED")
                phase = "CLEANUP"
                refuse(error)
    if interruption is not None:
        interruption._native_install_leaf = result
        raise interruption
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--container", required=True)
    parser.add_argument("--gateway-pid", type=int, required=True)
    for name in ("admitted", "probe", "verifier", "shared-probe", "shared-verifier"):
        parser.add_argument("--" + name + "-digest", required=True)
    args = parser.parse_args(argv)

    def terminate(signum, frame):
        raise KeyboardInterrupt("INSTALL_LEAF_TERMINATED")

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        interrupted = False
        try:
            result = run_install_probe(**{"expected_" + key: value for key, value in vars(args).items()})
        except BaseException as error:
            result = getattr(error, "_native_install_leaf", None)
            if result is None:
                raise
            interrupted = True
        raw = canonical_json(result)
        contract.require(len(raw) <= 4 * 1024 * 1024, "OUTPUT_BOUND_EXCEEDED")
        sys.stdout.buffer.write(raw + b"\n")
        return 130 if interrupted else (0 if result["status"] == "OBSERVED" else 126)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
