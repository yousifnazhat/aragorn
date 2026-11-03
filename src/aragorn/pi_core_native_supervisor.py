"""One-shot root supervisor for the provider-unavailable Pi bootstrap.

The entrypoint is operational code, not an argv renderer: it exclusively binds
the bootstrap socket, creates one transient service, authenticates its actual
post-exec peer, and verifies owned cleanup. It is never invoked by import.
Neither successful bootstrap nor cleanup qualifies effects, RUN, or Phase 3.
Uncertain ownership preserves on-disk resources and reports CLEANUP_HOLD.
"""

from __future__ import annotations

import hashlib
import math
import os
import platform
import re
import select
import shlex
import socket
import stat
import subprocess
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path

from . import runtime_active_skill_lineage as lineage
from . import runtime_process_profile as process
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_confined_launch import (
    PiConfinedLaunchConfig, PiConfinedLaunchPlan, exchange_prepared_pi_bootstrap,
    hold_confined_pi_launch_plan,
)
from .pi_core_worker_identity import read_activation
from .runtime_action_broker import _directory_identity, _file_identity, _read_owned_bytes_at

_RUN = Path("/run")
_BOOTSTRAP = _RUN / "aragorn-pi-bootstrap"
_SOCKET = _BOOTSTRAP / "bootstrap.sock"
_BINARY = ("/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/busctl")
_UNIT = re.compile(r"aragorn-pi-[a-f0-9]{32}\.service\Z")
_INVOCATION = re.compile(r"[a-f0-9]{32}\Z")
_MAX_COMMAND_OUTPUT = 64 * 1024
_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"}
_STATIC = {
    "Type": "exec", "Transient": "yes", "Restart": "no", "KillMode": "control-group",
    "SendSIGKILL": "yes", "Delegate": "no", "NoNewPrivileges": "yes",
    "CapabilityBoundingSet": "", "AmbientCapabilities": "", "SupplementaryGroups": "",
    "UMask": "0077", "PrivateDevices": "yes", "PrivateIPC": "yes", "PrivateMounts": "yes",
    "PrivateNetwork": "yes", "PrivateTmp": "yes", "ProtectSystem": "strict",
    "ProtectHome": "yes", "ProtectControlGroups": "yes", "ProtectKernelModules": "yes",
    "ProtectKernelTunables": "yes", "ProtectKernelLogs": "yes", "ProtectClock": "yes",
    "ProtectHostname": "yes", "ProtectProc": "invisible", "ProcSubset": "pid",
    "RestrictAddressFamilies": "AF_UNIX", "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
    "SystemCallArchitectures": "native", "RestrictNamespaces": "yes", "TasksMax": "64",
    "MemoryMax": str(1024**3), "Environment": "", "PassEnvironment": "",
    "DropInPaths": "", "ControlPID": "0", "RootImage": "",
    "StandardInput": "null", "StandardOutput": "null", "StandardError": "null",
    "BindLogSockets": "no", "LogNamespace": "",
}
_STATE = tuple(sorted({*_STATIC, "Id", "LoadState", "ActiveState", "SubState", "MainPID",
    "ExecMainPID", "ExecMainStartTimestampMonotonic", "ControlGroup", "InvocationID",
    "User", "Group", "RootDirectory", "WorkingDirectory", "FragmentPath", "InaccessiblePaths"}))


class PiNativeSupervisorError(RuntimeError):
    """A required kernel, systemd, or protected-resource invariant failed."""


def _require(value: bool, message: str) -> None:
    if not value:
        raise PiNativeSupervisorError(message)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    _require(remaining > 0, "native Pi deadline exhausted")
    return remaining


def _command(argv: tuple[str, ...], deadline: float) -> tuple[int, bytes]:
    """Only fixed systemd tools, no shell, no stdin or inherited credentials."""
    _require(argv[0] in _BINARY, "unapproved native command")
    completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=_ENV, close_fds=True, check=False,
        timeout=min(3.0, _remaining(deadline)))
    _require(len(completed.stdout) <= _MAX_COMMAND_OUTPUT and
             len(completed.stderr) <= _MAX_COMMAND_OUTPUT, "native command output exceeds bound")
    return completed.returncode, completed.stdout


def _prerequisites(deadline: float) -> None:
    _require(os.geteuid() == 0 and platform.system() == "Linux" and
             platform.machine() in {"aarch64", "arm64"}, "native Pi requires root on Linux arm64")
    _require(hasattr(os, "pidfd_open") and hasattr(select, "poll") and hasattr(socket, "SO_PEERCRED"),
             "native Pi requires PIDFD and Linux peer credentials")
    _remaining(deadline)
    _require(process._read_virtual_file(Path("/proc/1/comm"), 64) == b"systemd\n",
             "native Pi requires the controlled systemd environment")
    controllers = process._read_virtual_file(Path("/sys/fs/cgroup/cgroup.controllers"), 4096)
    _require(b"pids" in controllers.split() and b"memory" in controllers.split(),
             "native Pi requires unified memory and process controllers")
    for name in _BINARY:
        path = Path(name)
        descriptor = lineage._open_protected_root(path.parent, 0)
        try:
            value = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
            _require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1 and
                     not stat.S_IMODE(value.st_mode) & 0o6022 and value.st_mode & stat.S_IXUSR,
                     "native systemd binary is not root-owned and protected")
        finally:
            os.close(descriptor)
    _manager_version(deadline)
    _client_version(deadline)


def _client_version(deadline: float) -> int:
    """The protected systemd-run property parser must also support v257."""
    code, raw = _command(("/usr/bin/systemd-run", "--version"), deadline)
    _require(code == 0, "protected systemd-run version is unavailable")
    try:
        first = raw.decode("ascii").splitlines()[0]
    except (UnicodeError, IndexError) as exc:
        raise PiNativeSupervisorError("protected systemd-run version is malformed") from exc
    matched = re.fullmatch(r"systemd ([1-9][0-9]{2,3})(?:[ .+~()\-][A-Za-z0-9 .+~()\-]*)?", first)
    _require(matched is not None and int(matched.group(1)) >= 257,
             "native Pi requires systemd-run 257+ property support")
    return int(matched.group(1))


def _manager_version(deadline: float) -> int:
    """BindLogSockets is a v257+ manager feature, not a client version claim."""
    code, raw = _command(("/usr/bin/busctl", "get-property", "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "Version"), deadline)
    _require(code == 0, "trusted systemd manager version is unavailable")
    try:
        fields = shlex.split(raw.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise PiNativeSupervisorError("trusted manager version is malformed") from exc
    _require(len(fields) == 2 and fields[0] == "s", "trusted manager version type is invalid")
    matched = re.fullmatch(r"([1-9][0-9]{2,3})(?:[ .+~()\-][A-Za-z0-9 .+~()\-]*)?", fields[1])
    _require(matched is not None and int(matched.group(1)) >= 257,
             "native Pi requires systemd manager 257+ with explicit BindLogSockets=no")
    return int(matched.group(1))


def _unit_state(unit: str, deadline: float) -> dict[str, str]:
    _require(_UNIT.fullmatch(unit) is not None, "invalid exact native unit")
    code, raw = _command(("/usr/bin/systemctl", "show", "--all",
                          "--property=" + ",".join(_STATE), unit), deadline)
    try:
        pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
    except UnicodeError as exc:
        raise PiNativeSupervisorError("unit readback is not ASCII") from exc
    _require(all(len(pair) == 2 for pair in pairs), "unit readback is malformed")
    state = dict(pairs)
    _require(len(pairs) == len(_STATE) and set(state) == set(_STATE) and state["Id"] == unit,
             "unit readback is incomplete or duplicated")
    _require(code == 0 or (code in {1, 4} and _absent(state)), "unit readback failed")
    return state


def _absent(state: Mapping) -> bool:
    return (state.get("LoadState") == "not-found" and state.get("ActiveState") == "inactive" and
            state.get("SubState") == "dead" and state.get("MainPID") == "0" and
            state.get("ControlPID") == "0" and state.get("InvocationID") in {"", "0" * 32})


def _property(unit: str, name: str, deadline: float) -> list[str]:
    allowed = {"BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "EnvironmentFiles", "ExecCondition", "ExecStart", "ExecStartPre",
               "ExecStartPost", "ExecStop", "ExecStopPost", "LoadCredential", "LoadCredentialEncrypted",
               "SetCredential", "SetCredentialEncrypted", "RuntimeMaxUSec", "TimeoutStopUSec"}
    _require(_UNIT.fullmatch(unit) is not None and name in allowed, "invalid compound unit selector")
    path = "/org/freedesktop/systemd1/unit/" + unit.replace("-", "_2d").replace(".", "_2e")
    code, raw = _command(("/usr/bin/busctl", "get-property", "org.freedesktop.systemd1", path,
                         "org.freedesktop.systemd1.Service", name), deadline)
    _require(code == 0, "compound unit property is unavailable")
    try:
        return shlex.split(raw.decode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise PiNativeSupervisorError("compound unit property is malformed") from exc


def _readback(plan: PiConfinedLaunchPlan, state: Mapping, deadline: float) -> str:
    """Check exact immutable launch configuration; return its retained digest."""
    properties = {}
    for argument in plan.systemd_run_argv:
        if argument.startswith("--property="):
            name, value = argument[11:].split("=", 1)
            properties.setdefault(name, []).append(value)
    expected = {**_STATIC, "User": str(plan.worker_uid), "Group": str(plan.worker_gid),
                "RootDirectory": properties["RootDirectory"][0],
                "WorkingDirectory": properties["WorkingDirectory"][0],
                "FragmentPath": "/run/systemd/transient/" + plan.unit_name,
                "InaccessiblePaths": properties["InaccessiblePaths"][0]}
    _require(all(state.get(name) == value for name, value in expected.items()),
             "immutable systemd launch properties differ")
    observed = {"scalar": expected}
    for name, expected_value in (("RuntimeMaxUSec", "30000000"), ("TimeoutStopUSec", "5000000")):
        value = _property(plan.unit_name, name, deadline)
        _require(value == ["t", expected_value], "unit lifetime or stop bound differs")
        observed[name] = value
    empty = {"BindPaths": "a(ssbt)", "EnvironmentFiles": "a(sb)", "LoadCredential": "a(ss)",
        "LoadCredentialEncrypted": "a(ss)", "SetCredential": "a(say)", "SetCredentialEncrypted": "a(say)",
        **{name: "a(sasbttttuii)" for name in ("ExecCondition", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost")}}
    for name, signature in empty.items():
        value = _property(plan.unit_name, name, deadline)
        _require(value == [signature, "0"], "unexpected privileged unit hook or mount: " + name)
        observed[name] = value
    binds = _property(plan.unit_name, "BindReadOnlyPaths", deadline)
    expected_binds = ["a(ssbt)", str(len(properties["BindReadOnlyPaths"]))]
    for item in properties["BindReadOnlyPaths"]:
        source, destination = item.split(":")
        expected_binds.extend((source, destination, "false", "16384"))
    _require(binds == expected_binds, "readonly runtime/bundle/bootstrap mounts differ")
    observed["BindReadOnlyPaths"] = binds
    temporary = _property(plan.unit_name, "TemporaryFileSystem", deadline)
    _require(temporary == ["a(ss)", "1", "/var/lib/aragorn/admitted", "ro"],
             "immutable bundle mount parent differs")
    observed["TemporaryFileSystem"] = temporary
    argv = plan.systemd_run_argv[plan.systemd_run_argv.index("--") + 1:]
    command = _property(plan.unit_name, "ExecStart", deadline)
    prefix = ["a(sasbttttuii)", "1", argv[0], str(len(argv)), *argv, "false"]
    suffix = command[len(prefix):]
    _require(command[:len(prefix)] == prefix and len(suffix) == 7 and
             all(re.fullmatch(r"-?[0-9]+", value) is not None for value in suffix),
             "compiled entrypoint ExecStart differs")
    observed["ExecStart"] = prefix  # timestamps/status are not immutable configuration
    return canonical_digest(observed)


@dataclass
class _Owned:
    plan: PiConfinedLaunchPlan
    run_fd: int = -1
    directory_fd: int = -1
    directory_identity: tuple = ()
    directory_created: bool = False
    listener: socket.socket | None = None
    connection: socket.socket | None = None
    socket_identity: tuple = ()
    activation_fd: int = -1
    activation_directory_identity: tuple = ()
    activation_identity: tuple = ()
    activation_raw: bytes | None = None
    start_attempted: bool = False
    started: bool = False
    pid: int = 0
    pidfd: int = -1
    start_ticks: int = 0
    invocation: str = ""
    unit_started_at: str = ""
    immutable_digest: str = ""
    exit_observed: bool = False
    unit_absence_observed: bool = False
    cgroup_parent_fd: int = -1
    cgroup_fd: int = -1
    cgroup_parent_identity: tuple = ()
    cgroup_identity: tuple = ()


def _missing(parent: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
        return False
    except FileNotFoundError:
        return True


def _prepare_resources(owned: _Owned) -> None:
    owned.activation_fd = lineage._open_protected_root(owned.plan.activation_path.parent, 0)
    owned.activation_directory_identity = _directory_identity(os.fstat(owned.activation_fd))
    _require(_missing(owned.activation_fd, owned.plan.activation_path.name), "activation already exists")
    owned.run_fd = lineage._open_protected_root(_RUN, 0)
    try:
        os.mkdir(_BOOTSTRAP.name, mode=0o755, dir_fd=owned.run_fd)
        owned.directory_created = True
    except FileExistsError:
        pass
    if owned.directory_created:
        # Set only our newly created directory's mode; never repair an unsafe
        # preexisting namespace. mkdir mode is otherwise reduced by caller umask.
        owned.directory_fd = os.open(_BOOTSTRAP.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=owned.run_fd)
        value = os.fstat(owned.directory_fd)
        _require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0, "new bootstrap directory ownership differs")
        os.fchmod(owned.directory_fd, 0o755)
    else:
        owned.directory_fd = lineage._open_directory_at(owned.run_fd, _BOOTSTRAP.name, 0, 0o755,
                                                        "Pi bootstrap directory")
    owned.directory_identity = _directory_identity(os.fstat(owned.directory_fd))
    _require(os.listdir(owned.directory_fd) == [], "bootstrap directory contains existing resources")
    owned.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    # Descriptor-relative pathname avoids following a substituted parent name.
    owned.listener.bind(f"/proc/self/fd/{owned.directory_fd}/bootstrap.sock")
    before = os.stat("bootstrap.sock", dir_fd=owned.directory_fd, follow_symlinks=False)
    _require(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1,
             "new bootstrap endpoint is not an owned socket")
    os.chown("bootstrap.sock", 0, owned.plan.worker_gid, dir_fd=owned.directory_fd, follow_symlinks=False)
    os.chmod("bootstrap.sock", 0o660, dir_fd=owned.directory_fd, follow_symlinks=False)
    after = os.stat("bootstrap.sock", dir_fd=owned.directory_fd, follow_symlinks=False)
    _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and
             after.st_gid == owned.plan.worker_gid and stat.S_IMODE(after.st_mode) == 0o660,
             "bootstrap endpoint metadata changed")
    owned.socket_identity = _file_identity(after)
    owned.listener.listen(1)


def _pidfd(pid: int) -> int:
    descriptor = os.pidfd_open(pid, 0)
    try:
        info = process._read_virtual_file(Path(f"/proc/self/fdinfo/{descriptor}"), 16384).decode("ascii")
        _require([line.partition(":")[2].strip() for line in info.splitlines() if line.startswith("Pid:")]
                 == [str(pid)], "independent PIDFD does not identify systemd MainPID")
        process.require_live_pidfd(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _exited(descriptor: int) -> bool:
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLERR | select.POLLHUP)
    events = poller.poll(0)
    _require(all(fd == descriptor and not event & select.POLLNVAL for fd, event in events),
             "retained PIDFD became invalid")
    _require(not events or any(event & select.POLLIN for _fd, event in events),
             "retained PIDFD has uncertain poll state")
    return any(event & select.POLLIN for _fd, event in events)


def _capture_unit(owned: _Owned, deadline: float) -> None:
    while True:
        state = _unit_state(owned.plan.unit_name, deadline)
        _require(state["LoadState"] == "loaded" and state["ActiveState"] in {"active", "activating"},
                 "new Pi unit failed before owned process capture")
        if state["ActiveState"] == "active" and state["SubState"] == "running":
            break
        time.sleep(min(0.02, _remaining(deadline)))
    _require(re.fullmatch(r"[1-9][0-9]*", state["MainPID"]) is not None and
             _INVOCATION.fullmatch(state["InvocationID"]) is not None and
             state["InvocationID"] != "0" * 32 and state["ControlGroup"] == owned.plan.profile.cgroup,
             "new unit does not expose a dedicated process generation")
    owned.pid = int(state["MainPID"])
    owned.pidfd = _pidfd(owned.pid)
    owned.start_ticks = process._process_start_time(owned.pid)
    owned.invocation = state["InvocationID"]
    owned.unit_started_at = state["ExecMainStartTimestampMonotonic"]
    _require(owned.unit_started_at.isdigit() and int(owned.unit_started_at) > 0 and
             state["ExecMainPID"] == str(owned.pid) and
             process._process_cgroup(owned.pid) == owned.plan.profile.cgroup and
             process._cgroup_processes(owned.plan.profile.cgroup) == (owned.pid,),
             "new process is not the singleton unit child")
    cgroup = Path("/sys/fs/cgroup") / owned.plan.profile.cgroup.lstrip("/")
    owned.cgroup_parent_fd = lineage._open_protected_root(cgroup.parent, 0)
    owned.cgroup_parent_identity = _directory_identity(os.fstat(owned.cgroup_parent_fd))
    owned.cgroup_fd = os.open(cgroup.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=owned.cgroup_parent_fd)
    owned.cgroup_identity = _directory_identity(os.fstat(owned.cgroup_fd))
    _cgroup_owned(owned)
    owned.immutable_digest = _readback(owned.plan, state, deadline)
    _same_generation(owned, _unit_state(owned.plan.unit_name, deadline), deadline, live=True)


def _same_generation(owned: _Owned, state: Mapping, deadline: float, *, live: bool) -> None:
    _require(owned.invocation and state["LoadState"] == "loaded" and
             state["InvocationID"] == owned.invocation and
             state["ExecMainStartTimestampMonotonic"] == owned.unit_started_at and
             state["ExecMainPID"] == str(owned.pid) and
             state["ControlGroup"] == owned.plan.profile.cgroup and
             state["MainPID"] in {str(owned.pid), "0"}, "owned Pi unit generation changed")
    _cgroup_owned(owned, allow_absent=not live)
    _require(_readback(owned.plan, state, deadline) == owned.immutable_digest,
             "owned Pi launch configuration changed")
    if live:
        _require(state["MainPID"] == str(owned.pid) and not _exited(owned.pidfd), "owned Pi child exited")
        _require(process._process_start_time(owned.pid) == owned.start_ticks and
                 process._process_cgroup(owned.pid) == owned.plan.profile.cgroup and
                 process._cgroup_processes(owned.plan.profile.cgroup) == (owned.pid,),
                 "owned Pi kernel child identity changed")


def _cgroup_owned(owned: _Owned, *, allow_absent: bool = False) -> bool:
    """Return whether the exact retained cgroup name is absent, never replaced."""
    _require(owned.cgroup_parent_fd >= 0 and owned.cgroup_fd >= 0,
             "owned cgroup descriptors are unavailable")
    path = Path("/sys/fs/cgroup") / owned.plan.profile.cgroup.lstrip("/")
    _require(_directory_identity(os.fstat(owned.cgroup_parent_fd)) == owned.cgroup_parent_identity ==
             _directory_identity(path.parent.lstat()), "owned cgroup parent changed")
    retained = os.fstat(owned.cgroup_fd)
    _require(_directory_identity(retained) == owned.cgroup_identity,
             "retained cgroup descriptor identity changed")
    try:
        named = os.stat(path.name, dir_fd=owned.cgroup_parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        _require(allow_absent and retained.st_nlink == 0, "cgroup disappearance lacks retained removal proof")
        return True
    _require(_directory_identity(named) == owned.cgroup_identity, "owned cgroup name replaced")
    return False


def _cgroup_empty(owned: _Owned) -> bool:
    if _cgroup_owned(owned, allow_absent=True):
        return True
    # This existing helper also refuses delegated descendant cgroups.
    _require(process._cgroup_processes(owned.plan.profile.cgroup) == (), "owned cgroup retains processes")
    _cgroup_owned(owned, allow_absent=True)
    return True


def _capture_activation(owned: _Owned, document: Mapping) -> None:
    _require(read_activation(owned.plan.activation_path) == document,
             "published activation differs from authenticated binding")
    raw = _read_owned_bytes_at(owned.activation_fd, owned.plan.activation_path.name,
        max_bytes=64 * 1024, expected_uid=0, exact_mode=0o444, label="owned Pi activation")
    _require(raw == canonical_json(document), "published activation bytes differ")
    metadata = os.stat(owned.plan.activation_path.name, dir_fd=owned.activation_fd, follow_symlinks=False)
    _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1 and
             stat.S_IMODE(metadata.st_mode) == 0o444, "published activation metadata differs")
    owned.activation_raw = raw
    owned.activation_identity = _file_identity(metadata)


def _resource_ownership(owned: _Owned) -> None:
    if owned.activation_fd >= 0:
        _require(_directory_identity(os.fstat(owned.activation_fd)) == owned.activation_directory_identity ==
                 _directory_identity(owned.plan.activation_path.parent.lstat()), "activation directory replaced")
        if owned.activation_raw is None:
            _require(_missing(owned.activation_fd, owned.plan.activation_path.name),
                     "unrecorded or partial activation requires preservation")
        else:
            before = os.stat(owned.plan.activation_path.name, dir_fd=owned.activation_fd, follow_symlinks=False)
            raw = _read_owned_bytes_at(owned.activation_fd, owned.plan.activation_path.name,
                max_bytes=64 * 1024, expected_uid=0, exact_mode=0o444, label="owned Pi activation")
            after = os.stat(owned.plan.activation_path.name, dir_fd=owned.activation_fd, follow_symlinks=False)
            _require(_file_identity(before) == owned.activation_identity == _file_identity(after) and
                     raw == owned.activation_raw, "owned activation changed")
    if owned.directory_fd >= 0:
        _require(_directory_identity(os.fstat(owned.directory_fd)) == owned.directory_identity ==
                 _directory_identity(os.stat(_BOOTSTRAP.name, dir_fd=owned.run_fd, follow_symlinks=False)),
                 "bootstrap directory replaced")
        expected = ["bootstrap.sock"] if owned.socket_identity else []
        _require(sorted(os.listdir(owned.directory_fd)) == expected, "bootstrap namespace contains unowned residue")
        if owned.socket_identity:
            actual = os.stat("bootstrap.sock", dir_fd=owned.directory_fd, follow_symlinks=False)
            _require(_file_identity(actual) == owned.socket_identity, "owned bootstrap socket replaced")


def _cleanup(owned: _Owned, original_deadline: float, maximum_seconds: float = 5.0) -> dict:
    # A cap may shorten, never restart or extend, the caller's original budget.
    deadline = min(original_deadline, time.monotonic() + maximum_seconds)
    result = {"status": "CLEANUP_HOLD", "unit_absent": False, "process_exit_observed": False,
              "cgroup_empty_or_absent": False, "activation_withdrawn": False,
              "socket_removed": False, "directory_removed": False}
    try:
        _remaining(deadline)
        _resource_ownership(owned)
        if owned.start_attempted:
            _require(owned.started and owned.pidfd >= 0 and owned.invocation and owned.immutable_digest and
                     owned.cgroup_fd >= 0 and owned.cgroup_parent_fd >= 0,
                     "start outcome or unit custody is uncertain")
            state = _unit_state(owned.plan.unit_name, deadline)
            if not _absent(state):
                dead = _exited(owned.pidfd)
                terminal = dead and state["ActiveState"] in {"inactive", "failed"} and state["MainPID"] == "0"
                if terminal and state["InvocationID"] == "":
                    _require(state["ExecMainPID"] == str(owned.pid) and
                             state["ExecMainStartTimestampMonotonic"] == owned.unit_started_at and
                             _readback(owned.plan, state, deadline) == owned.immutable_digest,
                             "terminated Pi unit lost its owned generation")
                else:
                    _same_generation(owned, state, deadline, live=not dead)
                if not terminal:
                    # Exactly one owned stop; no restart, reset-failed, kill-all, or retry.
                    code, _ = _command(("/usr/bin/systemctl", "stop", "--no-block", owned.plan.unit_name), deadline)
                    _require(code == 0, "owned unit stop was not accepted")
            while True:
                owned.exit_observed = _exited(owned.pidfd)
                state = _unit_state(owned.plan.unit_name, deadline)
                if _absent(state) and owned.exit_observed:
                    break
                if not _absent(state):
                    _require(state["InvocationID"] in {owned.invocation, ""} and
                             state["MainPID"] in {str(owned.pid), "0"} and
                             state["ExecMainPID"] == str(owned.pid) and
                             state["ExecMainStartTimestampMonotonic"] == owned.unit_started_at,
                             "unit generation replaced during stop")
                time.sleep(min(0.02, _remaining(deadline)))
            result.update(unit_absent=True, process_exit_observed=True)
            result["cgroup_empty_or_absent"] = _cgroup_empty(owned)
        else:
            result["unit_absent"] = owned.unit_absence_observed
        _resource_ownership(owned)
        if owned.activation_raw is not None:
            _remaining(deadline)
            os.unlink(owned.plan.activation_path.name, dir_fd=owned.activation_fd)
            os.fsync(owned.activation_fd)
            _require(_missing(owned.activation_fd, owned.plan.activation_path.name), "activation remains after withdrawal")
            result["activation_withdrawn"] = True
        if owned.listener is not None:
            owned.listener.close()
            owned.listener = None
        if owned.socket_identity:
            _remaining(deadline)
            os.unlink("bootstrap.sock", dir_fd=owned.directory_fd)
            os.fsync(owned.directory_fd)
            _require(_missing(owned.directory_fd, "bootstrap.sock"), "bootstrap socket remains")
            result["socket_removed"] = True
        if owned.directory_created:
            _remaining(deadline)
            _require(owned.directory_fd >= 0 and os.listdir(owned.directory_fd) == [] and
                     _directory_identity(os.stat(_BOOTSTRAP.name, dir_fd=owned.run_fd, follow_symlinks=False))
                     == owned.directory_identity, "owned bootstrap directory changed before removal")
            os.rmdir(_BOOTSTRAP.name, dir_fd=owned.run_fd)
            os.fsync(owned.run_fd)
            _require(_missing(owned.run_fd, _BOOTSTRAP.name), "bootstrap directory remains")
            result["directory_removed"] = True
        _remaining(deadline)
        result["status"] = "VERIFIED_OWNED_CLEANUP"
    except Exception as exc:
        result["reason"] = f"{type(exc).__name__}: {str(exc)[:512]}"
    return result


def _close_handles(owned: _Owned) -> None:
    failures = []
    for connection in (owned.connection, owned.listener):
        if connection is not None:
            try:
                connection.close()
            except Exception as exc:
                failures.append(exc)
    for descriptor in (owned.pidfd, owned.cgroup_fd, owned.cgroup_parent_fd, owned.activation_fd,
                       owned.directory_fd, owned.run_fd):
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except Exception as exc:
                failures.append(exc)
    if failures:
        raise PiNativeSupervisorError(f"{len(failures)} owned handles could not be closed") from failures[0]


def run_native_pi_worker(
    cas: CAS, context: Mapping, *, profile: process.RuntimeProcessProfile, grant: Mapping,
    protected_root: Path, runtime_conformance_digest: str, deployment: Mapping,
    revoked_context_ids: Collection[str], now_unix: int, deadline: float,
    config: PiConfinedLaunchConfig, cleanup_timeout_seconds: float = 5.0,
) -> dict:
    """Run one bootstrap and owned cleanup within the original <=30s deadline.

    There are no automatic effect/start/stop retries. The separate cleanup
    reserve never extends admission or bootstrap authority. The held admission
    and launch plan remain open until cleanup has been attempted and recorded.
    """
    now = time.monotonic()
    _require(type(deadline) in (int, float) and math.isfinite(deadline) and now < deadline <= now + 30,
             "original native Pi deadline is invalid")
    _require(type(cleanup_timeout_seconds) in (int, float) and math.isfinite(cleanup_timeout_seconds) and
             0 < cleanup_timeout_seconds <= 5, "native cleanup deadline must be bounded to five seconds")
    operation_deadline = deadline - cleanup_timeout_seconds
    _require(operation_deadline > now, "original deadline cannot reserve the cleanup budget")
    _prerequisites(operation_deadline)
    with hold_confined_pi_launch_plan(cas, context, profile=profile, grant=grant,
            protected_root=protected_root, runtime_conformance_digest=runtime_conformance_digest,
            deployment=deployment, revoked_context_ids=revoked_context_ids, now_unix=now_unix,
            deadline=operation_deadline, config=config) as plan:
        owned = _Owned(plan)
        observation = None
        failure = None
        cleanup = None
        try:
            owned.unit_absence_observed = _absent(_unit_state(plan.unit_name, operation_deadline))
            _require(owned.unit_absence_observed, "fresh Pi unit already exists")
            _prepare_resources(owned)
            owned.unit_absence_observed = _absent(_unit_state(plan.unit_name, operation_deadline))
            _require(owned.unit_absence_observed, "Pi unit appeared before exclusive start")
            owned.start_attempted = True
            code, _ = _command(plan.systemd_run_argv, operation_deadline)
            _require(code == 0, "one-shot transient service start failed")
            owned.started = True
            _capture_unit(owned, operation_deadline)
            assert owned.listener is not None
            owned.listener.settimeout(_remaining(operation_deadline))
            owned.connection, _address = owned.listener.accept()
            _same_generation(owned, _unit_state(plan.unit_name, operation_deadline), operation_deadline, live=True)
            observation = exchange_prepared_pi_bootstrap(plan, owned.connection,
                expected_pid=owned.pid, on_activation=lambda document: _capture_activation(owned, document))
        except Exception as exc:
            failure = f"{type(exc).__name__}: {str(exc)[:512]}"
        finally:
            cleanup = _cleanup(owned, deadline, cleanup_timeout_seconds)
            try:
                _close_handles(owned)
            except Exception as exc:
                cleanup.update(status="CLEANUP_HOLD", reason="owned handle close failed: " + str(exc)[:256])
        return {
            "schema": "aragorn/pi-core-native-supervisor-result/v1",
            "authority": "BOOTSTRAP_AND_OWNED_CLEANUP_ONLY_NOT_EFFECT_RUN_OR_PHASE3_QUALIFICATION",
            "status": "CLEANUP_HOLD" if cleanup["status"] == "CLEANUP_HOLD" else
                      "BOOTSTRAP_COMPLETE" if observation is not None else "REFUSED",
            "unit": plan.unit_name, "invocation_id": owned.invocation or None,
            "pid": owned.pid or None, "start_time_ticks": owned.start_ticks or None,
            "immutable_launch_digest": owned.immutable_digest or None,
            "activation_digest": ("sha256:" + hashlib.sha256(owned.activation_raw).hexdigest())
                                  if owned.activation_raw is not None else None,
            "bootstrap": observation, "failure": failure, "cleanup": cleanup,
        }
