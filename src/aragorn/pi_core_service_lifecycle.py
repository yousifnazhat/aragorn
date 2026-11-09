"""One owned service bootstrap in a controlled Linux VM.

This operational context is never called on import. It starts exactly three
fixed wrappers, accepts their post-exec channels, then stops only captured unit
generations. It does not dispatch a provider request, initialize/rotate a grant,
perform root-side grant recovery, enable Pi START or qualify
loaded Python/effects/Phase 3. Read-only readiness is a pre-start snapshot; the
action handler retains its independent role-local recovery and effect guards.
Trusted root and the system manager are the TCB; empty manager-environment checks
cannot make adversarial root changes atomic with process creation.
The default remains credential-free and network-unavailable. An exact held
credential optionally prepares only the provider service for a separately
approved request; unit-property readback is not kernel egress qualification.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
import fcntl
import ipaddress
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import stat
import time
from types import SimpleNamespace

from . import pi_core_identity_handoff as transport
from . import pi_core_native_supervisor as native
from . import pi_core_service_channels as channels
from . import pi_core_service_configuration as configuration
from . import pi_core_service_entry as entry
from . import pi_core_service_provision as provision
from . import runtime_action_broker as broker
from . import runtime_action_broker_v4 as grants
from . import runtime_active_skill_lineage as lineage
from . import runtime_capability_grant as capability
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json

ROLES = ("action", "sensor", "provider")
_UNITS = {role: "aragorn-pi-" + role + ".service" for role in ROLES}
_ROOT = Path("/run/aragorn-pi-services")
_ACTION = Path("/run/aragorn-pi-action")
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")
_SEAL = object()
_SOURCE_LOADER = provision.SOURCE_ROOT + "/pi_core_service_source.py"
# At most 512 source files plus their package directories remain held by the loader.
_MAX_SERVICE_FDS = 64 + 2 * 512
_CAPS = "cap_setgid cap_setuid cap_setpcap"
_BASE = {**native._STATIC, "ProtectProc": "default", "TasksMax": "1", "MemoryMax": str(256 * 1024**2),
    "PAMName": "", "ReadWritePaths": "", "WorkingDirectory": "/", "RootImage": "",
    "Environment": "", "PassEnvironment": "", "CollectMode": "inactive-or-failed", "KillSignal": "2"}
_STATE = tuple(sorted({*native._STATE, *_BASE, "ExecMainCode", "ExecMainStatus"}))
_EMPTY = {"EnvironmentFiles": "a(sb)", "LoadCredential": "a(ss)", "LoadCredentialEncrypted": "a(ss)",
    "SetCredential": "a(say)", "SetCredentialEncrypted": "a(say)", "TemporaryFileSystem": "a(ss)",
    **{name: "a(sasbttttuii)" for name in ("ExecCondition", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost")}}
_PROVIDER_EMPTY = {"ImportCredential": "as", "ImportCredentialEx": "a(ss)"}
_CREDENTIAL_SOURCE = re.compile(r"/proc/[1-9][0-9]*/fd/(?:0|[1-9][0-9]*)\Z")


class PiServiceLifecycleError(RuntimeError):
    """Refusal or ownership ambiguity; no retry or unscoped cleanup authority."""


def _require(value, message):
    if not value:
        raise PiServiceLifecycleError(message)


def _remaining(deadline):
    return native._remaining(deadline)


def _safe_path(value):
    _require(isinstance(value, Path) and value.is_absolute() and value != Path("/") and
             ".." not in value.parts and _SAFE_PATH.fullmatch(str(value)), "unsafe service mount path")
    return str(value)


def _manager_environment(deadline):
    code, raw = native._command(("/usr/bin/busctl", "get-property", "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "Environment"), deadline)
    _require(code == 0 and shlex.split(raw.decode("ascii")) == ["as", "0"],
             "manager exported environment is not empty")


def _state(role, deadline):
    _require(role in ROLES, "unknown fixed service role")
    code, raw = native._command(("/usr/bin/systemctl", "show", "--all",
        "--property=" + ",".join(_STATE), _UNITS[role]), deadline)
    pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
    _require(all(len(pair) == 2 for pair in pairs), "service state malformed")
    value = dict(pairs)
    _require(len(pairs) == len(_STATE) and set(value) == set(_STATE) and value["Id"] == _UNITS[role] and
             (code == 0 or (code in (1, 4) and native._absent(value))), "service state incomplete or unavailable")
    return value


def _property(role, name, deadline):
    _require(role in ROLES and name in {*_EMPTY, "BindPaths", "BindReadOnlyPaths", "ExecStart",
                                       "RuntimeMaxUSec", "TimeoutStopUSec", *_PROVIDER_EMPTY,
                                       "IPAddressAllow", "IPAddressDeny"}, "unknown fixed service property")
    unit = _UNITS[role]
    path = "/org/freedesktop/systemd1/unit/" + unit.replace("-", "_2d").replace(".", "_2e")
    code, raw = native._command(("/usr/bin/busctl", "get-property", "org.freedesktop.systemd1", path,
        "org.freedesktop.systemd1.Service", name), deadline)
    _require(code == 0, "service property unavailable")
    return shlex.split(raw.decode("ascii"))


def _guard_credential(credential, provider_inputs, deadline):
    from .pi_core_provider_credential import PiProviderCredential
    _require(type(credential) is PiProviderCredential and credential.provider_inputs is provider_inputs and
             deadline <= credential.deadline, "provider credential custody or public-input join differs")
    credential.guard(deadline=deadline)  # Descriptor metadata only; never read/hash the key here.
    source = credential.source
    _require(type(source) is str and _CREDENTIAL_SOURCE.fullmatch(source), "provider credential source is not held procfd")
    return source


def _credential_directory_absent(deadline):
    """Observe the exact manager-owned credential path; never adopt/delete it."""
    fds = []
    try:
        _remaining(deadline)
        run = lineage._open_protected_root(Path("/run"), 0)
        fds.append(run)
        run_identity = broker._directory_identity(os.fstat(run))
        try:
            before = os.stat("credentials", dir_fd=run, follow_symlinks=False)
        except FileNotFoundError:
            _require(native._missing(run, "credentials"), "manager credential parent appeared")
        else:
            _require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0 and
                     not stat.S_IMODE(before.st_mode) & 0o7022, "manager credential parent is not protected")
            parent = os.open("credentials", _DIR, dir_fd=run)
            fds.append(parent)
            identity = broker._directory_identity(before)
            _require(broker._directory_identity(os.fstat(parent)) == identity,
                     "manager credential parent changed during open")
            _require(native._missing(parent, _UNITS["provider"]), "manager provider credential directory is not absent")
            _require(broker._directory_identity(os.stat("credentials", dir_fd=run, follow_symlinks=False)) ==
                     identity == broker._directory_identity(os.fstat(parent)), "manager credential parent changed")
        _require(broker._directory_identity(os.lstat("/run")) == run_identity ==
                 broker._directory_identity(os.fstat(run)), "manager credential ancestry changed")
        _remaining(deadline)
    finally:
        transport._close_installed(list(reversed(fds)))


def _provider_manager_prerequisites(deadline):
    """Known API prerequisites before exposing a credential to the manager.

    This version floor covers ImportCredentialEx, not kernel BPF enforcement.
    Exact per-unit properties still require the subsequent generation readback.
    """
    code, raw = native._command(("/usr/bin/busctl", "get-property", "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "Version"), deadline)
    tokens = shlex.split(raw.decode("ascii"))
    _require(code == 0 and len(tokens) == 2 and tokens[0] == "s", "provider manager version unavailable")
    version = re.fullmatch(r"([1-9][0-9]{2,3})(?:[-.+~ ][A-Za-z0-9().+~_ -]{1,100})?", tokens[1])
    _require(version is not None and int(version.group(1)) >= 257, "provider requires systemd 257 or newer")
    _credential_directory_absent(deadline)


def _credential_generation(service, deadline):
    if service.provider_credential is not None:
        _require(service.role == "provider" and _guard_credential(service.provider_credential,
            service.provider_inputs, deadline) == service.credential_source, "provider credential generation changed")


def _ip_rules(value):
    """Parse bounded systemd Service a(iayu), with Linux family numbers.

    Array order is not authority. Exact normalized rows reject extra hosts,
    duplicate rules, broad prefixes, wrong families and malformed byte arrays.
    """
    _require(type(value) is list and len(value) >= 2 and value[0] == "a(iayu)" and
             value[1] in {"1", "2"}, "provider IP property shape differs")
    rows, offset = [], 2
    for _ in range(int(value[1])):
        _require(offset + 2 <= len(value) and value[offset] in {"2", "10"}, "provider IP family differs")
        family = int(value[offset])
        size = 4 if family == 2 else 16
        _require(value[offset + 1] == str(size) and offset + size + 3 <= len(value), "provider IP byte count differs")
        octets = value[offset + 2:offset + 2 + size]
        prefix = value[offset + 2 + size]
        _require(all(type(item) is str and re.fullmatch(r"0|[1-9][0-9]{0,2}", item) and int(item) <= 255
                     for item in octets) and type(prefix) is str and
                 re.fullmatch(r"0|[1-9][0-9]{0,2}", prefix) and int(prefix) <= size * 8,
                 "provider IP bytes or prefix invalid")
        rows.append((family, tuple(map(int, octets)), int(prefix)))
        offset += size + 3
    _require(offset == len(value) and len(set(rows)) == len(rows), "provider IP rules duplicated or trailing")
    return tuple(sorted(rows))


def _read_at(parent, name, uid, deadline, *, maximum=128 * 1024, mode=0o400):
    """Bounded nonblocking read; no legacy migration or hardlink reconciliation."""
    descriptor = os.open(name, _FILE, dir_fd=parent)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1 and
                 stat.S_IMODE(before.st_mode) == mode and 0 <= before.st_size <= maximum, "unsafe readiness file")
        raw = bytearray()
        while True:
            _remaining(deadline)
            chunk = os.read(descriptor, min(8192, maximum + 1 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
            _require(len(raw) <= before.st_size, "readiness file grew")
        _require(len(raw) == before.st_size and broker._file_identity(before) == broker._file_identity(os.fstat(descriptor)) ==
                 broker._file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), "readiness file changed")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _readiness(configs, deadline):
    """Read-only AVAILABLE/journal freshness check before any service start."""
    selected = configs["action"]
    uid, gid = (selected["identities"]["action"][name] for name in ("uid", "gid"))
    grant = capability.parse_runtime_capability_grant(canonical_json(selected["capability_grant"]), int(time.time()))
    digest = canonical_digest(grant)
    descriptors, lock_fd, locked = [], -1, False
    try:
        for leaf, mode in (("control", 0o710), ("protected", 0o710), ("staging", 0o700)):
            path = entry.EFFECT_ROOT / leaf
            fd = broker._open_protected_directory(path, uid, "service " + leaf)
            descriptors.append(fd)
            info = os.fstat(fd)
            _require(info.st_gid == gid and stat.S_IMODE(info.st_mode) == mode, "broker role root mode/group differs")
        _require(len({broker._directory_identity(os.fstat(fd))[:2] for fd in descriptors}) == 3 and
                 os.fstat(descriptors[1]).st_dev == os.fstat(descriptors[2]).st_dev, "broker roots alias or cross filesystems")
        control = descriptors[0]
        lock_fd = os.open("broker.lock", os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=control)
        metadata = os.fstat(lock_fd)
        _require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid and metadata.st_nlink == 1 and
                 stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size == 0, "preexisting broker lock unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        _remaining(deadline)
        stored = broker._parse_canonical_document(_read_at(control, "state.json", uid, deadline), "service broker state")
        state = broker._state(stored)
        _require(state == stored and state["effect_journal"] is None, "broker journal or migration hold")
        available = grants._state(broker._parse_canonical_document(
            _read_at(control, "capability-grant-state.json", uid, deadline), "service grant state"), digest)
        _require(available["status"] == "AVAILABLE", "service grant is not explicitly prepared AVAILABLE")
        for name in ("profile-pending.json", "profile-receipt.json",
                     grants._archive_name("state", digest), grants._archive_name("profile-receipt", digest)):
            _require(native._missing(control, name), "pending, receipt or archived terminal authority exists")
        _require(broker._file_identity(os.fstat(lock_fd)) == broker._file_identity(metadata) ==
                 broker._file_identity(os.stat("broker.lock", dir_fd=control, follow_symlinks=False)), "broker lock changed")
        for fd, leaf in zip(descriptors, ("control", "protected", "staging")):
            _require(broker._directory_identity(os.fstat(fd)) ==
                     broker._directory_identity(os.lstat(entry.EFFECT_ROOT / leaf)), "broker root changed")
        _remaining(deadline)
        return {"grant_digest": digest, "state_digest": canonical_digest(available), "read_only": True}
    finally:
        failure = None
        if locked:
            try: fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except BaseException as exc: failure = exc
        try: transport._close_installed(([lock_fd] if lock_fd >= 0 else []) + list(reversed(descriptors)))
        except BaseException as exc: failure = failure or exc
        if failure is not None: raise PiServiceLifecycleError("readiness handle cleanup uncertain") from failure


@dataclass
class _Service:
    role: str
    uid: int
    gid: int
    root: Path
    argv: tuple = ()
    scalar: dict = field(default_factory=dict)
    binds: dict = field(default_factory=dict)
    provider_credential: object = None
    provider_inputs: object = None
    credential_source: str = ""
    ip_rules: dict = field(default_factory=dict)
    started: bool = False
    start_attempted: bool = False
    pid: int = 0
    pidfd: int = -1
    start_ticks: int = 0
    invocation: str = ""
    unit_started_at: str = ""
    immutable_digest: str = ""
    cgroup_parent_fd: int = -1
    cgroup_fd: int = -1
    cgroup_parent_identity: tuple = ()
    cgroup_identity: tuple = ()
    listener: object = None
    connection: object = None
    socket_identity: tuple = ()
    stop_attempted: bool = False
    terminal: bool = False

    @property
    def plan(self):
        # The frozen cgroup-ownership leaves use only this exact cgroup path.
        return SimpleNamespace(profile=SimpleNamespace(cgroup="/system.slice/" + _UNITS[self.role]))


def _plan(service, held):
    role = service.role
    _safe_path(held.deployment.root)
    _safe_path(held.configuration.root)
    _safe_path(held.provider_inputs.root)
    scalar = {**_BASE, "User": str(service.uid), "Group": str(service.gid), "RootDirectory": str(service.root),
        "FragmentPath": "/run/systemd/transient/" + _UNITS[role], "InaccessiblePaths": "-/dev/shm -/dev/hugepages -/dev/pts"}
    if role == "sensor":
        scalar.update(CapabilityBoundingSet=_CAPS, AmbientCapabilities=_CAPS,
                      SupplementaryGroups=str(held.identities["action"]["gid"]))
    ro = [(held.deployment.root / "usr", "/usr"), (held.deployment.root / "lib", "/lib"),
          (held.deployment.root / "opt/aragorn", "/opt/aragorn"),
          (held.configuration.root / configuration.PATHS[role], "/" + configuration.PATHS[role]),
          (_ROOT / role, str(_ROOT / role))]
    rw = []
    if role in ("action", "sensor"):
        ro.append((entry.ADMITTED_ROOT, str(entry.ADMITTED_ROOT)))
        (rw if role == "action" else ro).extend(((entry.EFFECT_ROOT, str(entry.EFFECT_ROOT)), (_ACTION, str(_ACTION))))
    if role == "provider":
        ro.extend((held.provider_inputs.root / path, "/" + path) for path in
                  ("etc/aragorn/pi-provider-profile.json", "etc/aragorn/pi-provider-ca.pem"))
        if held.provider_credential is not None:
            service.provider_credential, service.provider_inputs = held.provider_credential, held.provider_inputs
            service.credential_source = _guard_credential(held.provider_credential, held.provider_inputs, held.operation_deadline)
            address = ipaddress.ip_address(held.provider_inputs.profile["address"])
            family = 2 if address.version == 4 else 10  # Linux ABI, including when planned on macOS.
            scalar.update(PrivateNetwork="no", RestrictAddressFamilies="AF_UNIX " +
                          ("AF_INET" if address.version == 4 else "AF_INET6"))
            service.ip_rules = {"IPAddressAllow": ((family, tuple(address.packed), address.max_prefixlen),),
                "IPAddressDeny": ((2, (0,) * 4, 0), (10, (0,) * 16, 0))}
    scalar["ReadWritePaths"] = " ".join(target for _source, target in rw)
    service.scalar = scalar
    service.binds = {"BindReadOnlyPaths": ro, "BindPaths": rw}
    executable = tuple(held.deployment.binding["wrappers"][role]["argv"]) + (str(os.getpid()), str(held.deadline_ns))
    properties = {key: value for key, value in scalar.items() if key not in
                  {"Transient", "FragmentPath", "DropInPaths", "ControlPID"}}
    properties.update(Type="exec", RuntimeMaxSec="30", TimeoutStopSec="5")
    if service.provider_credential is not None:
        properties.update(LoadCredential="openai-api-key:" + service.credential_source,
            IPAddressDeny="any", IPAddressAllow=str(address) + "/" + str(address.max_prefixlen))
    args = ["/usr/bin/systemd-run", "--quiet", "--no-block", "--collect", "--unit=" + _UNITS[role]]
    args.extend("--property=" + key + "=" + value for key, value in properties.items())
    for name, entries in service.binds.items():
        args.extend("--property=" + name + "=" + _safe_path(source) + ":" + target for source, target in entries)
    service.argv = (*args, "--", *executable)


def _readback(service, state, deadline):
    _require(all(state.get(key) == value for key, value in service.scalar.items()), "service immutable properties differ")
    observed = {"scalar": service.scalar}
    for name, signature in _EMPTY.items():
        value = _property(service.role, name, deadline)
        expected = ([signature, "1", "openai-api-key", service.credential_source]
                    if name == "LoadCredential" and service.provider_credential is not None else [signature, "0"])
        _require(value == expected, "service contains unexpected hook/environment/credential")
        observed[name] = value
    if service.provider_credential is not None:
        for name, signature in _PROVIDER_EMPTY.items():
            value = _property(service.role, name, deadline)
            _require(value == [signature, "0"], "provider contains additional imported credentials")
            observed[name] = value
        for name, expected in service.ip_rules.items():
            value = _ip_rules(_property(service.role, name, deadline))
            _require(value == expected, "provider IP rules differ from exact approved address")
            observed[name] = value
    for name, expected in (("RuntimeMaxUSec", "30000000"), ("TimeoutStopUSec", "5000000")):
        value = _property(service.role, name, deadline)
        _require(value == ["t", expected], "service lifetime bound differs")
        observed[name] = value
    for name, entries in service.binds.items():
        expected = ["a(ssbt)", str(len(entries))]
        for source, target in entries:
            expected.extend((str(source), target, "false", "16384" if name == "BindReadOnlyPaths" else "0"))
        _require(_property(service.role, name, deadline) == expected, "service mounts differ")
        observed[name] = expected
    argv = service.argv[service.argv.index("--") + 1:]
    prefix = ["a(sasbttttuii)", "1", argv[0], str(len(argv)), *argv, "false"]
    command = _property(service.role, "ExecStart", deadline)
    _require(command[:len(prefix)] == prefix and len(command[len(prefix):]) == 7 and
             all(re.fullmatch(r"-?[0-9]+", value) for value in command[len(prefix):]), "fixed wrapper invocation differs")
    observed["ExecStart"] = prefix
    _manager_environment(deadline)
    return canonical_digest(observed)


def _generation(service, deadline, *, live=True, credential_authority=True):
    if credential_authority: _credential_generation(service, deadline)
    state = _state(service.role, deadline)
    terminal_identity = (not live and native._exited(service.pidfd) and state["MainPID"] == "0" and
                         state["ActiveState"] in {"inactive", "failed"} and state["InvocationID"] == "")
    _require(service.invocation and state["LoadState"] == "loaded" and
             (state["InvocationID"] == service.invocation or terminal_identity) and
             state["ExecMainStartTimestampMonotonic"] == service.unit_started_at and state["ExecMainPID"] == str(service.pid) and
             state["ControlGroup"] == service.plan.profile.cgroup and state["MainPID"] in {str(service.pid), "0"},
             "service generation changed")
    native._cgroup_owned(service, allow_absent=not live)
    _require(_readback(service, state, deadline) == service.immutable_digest, "service launch configuration changed")
    if live:
        _require(state["MainPID"] == str(service.pid) and not native._exited(service.pidfd) and
                 process._process_start_time(service.pid) == service.start_ticks and
                 process._process_cgroup(service.pid) == service.plan.profile.cgroup and
                 process._cgroup_processes(service.plan.profile.cgroup) == (service.pid,), "service child identity changed")
    _remaining(deadline)
    if credential_authority: _credential_generation(service, deadline)


def _retired_provider_generation(service, deadline):
    """Validate captured provider custody after authenticated terminal receipt.

    Retirement is not process-exit proof. A still-running provider retains full
    generation checks; a dead provider must have no residual/replacement cgroup.
    systemd may already have collected this exact one-shot transient unit.
    """
    _credential_generation(service, deadline)
    _require(service.role == "provider" and service.started and service.pidfd >= 0 and
             service.invocation and service.immutable_digest, "provider capture is incomplete")
    if not native._exited(service.pidfd):
        _generation(service, deadline)
        return
    state = _state(service.role, deadline)
    if not native._absent(state):
        _require(state["ActiveState"] in {"inactive", "failed"} and
                 state["MainPID"] == state["ControlPID"] == "0",
                 "retired provider unit is not terminal")
        _generation(service, deadline, live=False)
    native._cgroup_empty(service)  # Retained descriptors reject a reused name.
    _remaining(deadline)


def _capture(service, deadline):
    while True:
        state = _state(service.role, deadline)
        _require(state["LoadState"] == "loaded" and state["ActiveState"] in {"activating", "active"}, "service failed before capture")
        if state["ActiveState"] == "active" and state["SubState"] == "running": break
        time.sleep(min(0.02, _remaining(deadline)))
    _require(re.fullmatch(r"[1-9][0-9]*", state["MainPID"]) and native._INVOCATION.fullmatch(state["InvocationID"]) and
             state["InvocationID"] != "0" * 32 and state["ControlGroup"] == service.plan.profile.cgroup, "service has no exact process generation")
    service.pid = int(state["MainPID"])
    service.pidfd = native._pidfd(service.pid)
    service.start_ticks = process._process_start_time(service.pid)
    service.invocation = state["InvocationID"]
    service.unit_started_at = state["ExecMainStartTimestampMonotonic"]
    _require(service.unit_started_at.isdigit() and int(service.unit_started_at) > 0, "service start timestamp missing")
    path = Path("/sys/fs/cgroup") / service.plan.profile.cgroup.lstrip("/")
    service.cgroup_parent_fd = lineage._open_protected_root(path.parent, 0)
    service.cgroup_parent_identity = broker._directory_identity(os.fstat(service.cgroup_parent_fd))
    service.cgroup_fd = os.open(path.name, _DIR, dir_fd=service.cgroup_parent_fd)
    service.cgroup_identity = broker._directory_identity(os.fstat(service.cgroup_fd))
    service.immutable_digest = _readback(service, state, deadline)
    _generation(service, deadline)


def _listener_ready(service, directory_fd, directory_identity, deadline):
    """Passive same-process LISTEN evidence; never consume the only accept.

    Adapts the frozen HTTP-ready verifier's fd-link/kernel-inode/LISTEN join.
    The wrapper binds a literal procfd path, whose directory FD must independently
    resolve to the exact retained action directory. A pathname alone is not ready.
    """
    while True:
        _generation(service, deadline)
        try: metadata = os.stat("sensor.sock", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError: metadata = None
        raw = process._read_virtual_file(Path(f"/proc/{service.pid}/net/unix"), 49152)
        names = os.listdir(f"/proc/{service.pid}/fd")
        _require(len(names) <= _MAX_SERVICE_FDS and all(name.isdigit() for name in names), "action fd inventory exceeds bound")
        links = {}
        for name in names:
            _remaining(deadline)
            try: links[name] = os.readlink(f"/proc/{service.pid}/fd/{name}")
            except FileNotFoundError: continue
        matches = []
        for line in raw.decode("ascii").splitlines()[1:]:
            row = line.split()
            if len(row) != 8 or row[3:6] != ["00010000", "0001", "01"]: continue
            match = re.fullmatch(r"/proc/self/fd/([0-9]+)/sensor\.sock", row[7])
            if match is None or not row[6].isdigit() or int(row[6]) <= 0 or "socket:[" + row[6] + "]" not in links.values(): continue
            _require(broker._directory_identity(os.stat(f"/proc/{service.pid}/fd/{match[1]}")) == directory_identity,
                     "action listener procfd directory differs")
            matches.append(row[6])
        _require(len(matches) <= 1, "multiple action listeners")
        if metadata is not None and matches:
            _require(stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == service.uid and metadata.st_gid == service.gid and
                     stat.S_IMODE(metadata.st_mode) == 0o660 and metadata.st_nlink == 1, "action socket metadata differs")
            _generation(service, deadline)
            _require(broker._file_identity(metadata) == broker._file_identity(os.stat("sensor.sock", dir_fd=directory_fd,
                follow_symlinks=False)), "action listener changed during passive observation")
            return broker._file_identity(metadata)
        time.sleep(min(0.02, _remaining(deadline)))


def _consumed_sources(records, source_digests, role):
    """Validate a startup subset, never pretend every installed module ran."""
    _require(type(records) is list and 0 < len(records) <= 512, "invalid consumed-source inventory")
    modules, paths = set(), set()
    for row in records:
        _require(type(row) is dict and set(row) == {"module", "path", "digest"} and
                 all(type(row[key]) is str for key in row), "invalid consumed-source record")
        name, path, digest = row["module"], row["path"], row["digest"]
        _require(re.fullmatch(r"aragorn(?:\.[A-Za-z_][A-Za-z0-9_]*)*", name) is not None and
                 name not in modules and path not in paths, "duplicate or invalid consumed module")
        relative = name.replace(".", "/")
        _require(path in {provision.IMPORT_ROOT + "/" + relative + suffix
                          for suffix in (".py", "/__init__.py")} and
                 path in source_digests and digest == source_digests[path],
                 "consumed source differs from the held service image")
        modules.add(name)
        paths.add(path)
    _require({"aragorn", "aragorn.pi_core_service_entry", provision.ROLES[role]["module"]} <= modules,
             "service startup lacks its package, entrypoint or role handler")
    return records


class PiServiceLifecycle:
    def __init__(self, seal, deployment, config, provider_inputs, binding, deadline, cleanup_seconds,
                 provider_credential=None):
        _require(seal is _SEAL, "service lifecycle requires protected factory")
        self.deployment, self.configuration, self.provider_inputs = deployment, config, provider_inputs
        self.provider_credential = provider_credential
        self.binding, self.deadline = binding, deadline
        self.operation_deadline = deadline - cleanup_seconds
        # Wrappers retain the original reserve for their finally blocks. Root
        # channels, request authority and the worker use operation_deadline;
        # this original lifetime budget grants no later request authority.
        self.deadline_ns = math.floor(deadline * 1_000_000_000)
        self.identities = config.identities
        self.services = {role: _Service(role, self.identities[role]["uid"], self.identities[role]["gid"],
                                       _ROOT / "roots" / role) for role in ROLES}
        self._seal, self._active, self._closed = seal, False, False
        self._channels, self._stack = None, ExitStack()
        self._fds, self._identities, self._created, self._files = {}, {}, [], []
        self._action_socket = ()
        self._observation = {"schema": "aragorn/pi-core-service-lifecycle/v1", "status": "PREPARING",
            "provider_mode": "UNAVAILABLE_NO_EGRESS_NO_CREDENTIAL", "provider_dispatched": False,
            "credential_read": False, "loaded_code_verified": False, "phase3_exit_eligible": False,
            "cleanup": {"status": "PENDING"}}
        self._observation["trusted_source_startup"] = {}
        if provider_credential is not None:
            self._observation.update(provider_mode="CONTROLLED_CREDENTIAL_FIXED_ADDRESS",
                provider_dispatched=None, credential_read=None,
                credential_custody="METADATA_ONLY_NO_SECRET_READ",
                provider_request_observation="NOT_OBSERVED_BY_LIFECYCLE", egress_filter_kernel_verified=False)

    @property
    def channels(self):
        _require(self._active and not self._closed and self._channels is not None, "service scope is not active")
        return self._channels

    @property
    def observation(self):
        import json
        return json.loads(canonical_json(self._observation))

    def _inputs(self, deadline):
        for value in (self.deployment, self.configuration, self.provider_inputs):
            _require(deadline <= value.deadline, "service inputs extend held deadline")
            value.guard(deadline=deadline)
        if self.provider_credential is not None:
            _guard_credential(self.provider_credential, self.provider_inputs, deadline)

    def _mkdir(self, path, uid=0, gid=0, mode=0o755):
        parent = self._fds[path.parent]
        os.mkdir(path.name, 0o700, dir_fd=parent)  # Absent-only, including fixed top-level names.
        self._created.append(path)
        fd = os.open(path.name, _DIR, dir_fd=parent)
        self._fds[path] = fd
        before = os.fstat(fd)
        _require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0, "new lifecycle directory ownership differs")
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        self._identities[path] = broker._directory_identity(os.fstat(fd))
        _require(self._identities[path] == broker._directory_identity(os.stat(path.name, dir_fd=parent,
            follow_symlinks=False)), "new lifecycle directory changed")
        os.fsync(parent)

    def _ownership(self, deadline):
        for path, identity in self._identities.items():
            _remaining(deadline)
            _require(broker._directory_identity(os.fstat(self._fds[path])) == identity ==
                     broker._directory_identity(os.lstat(path)), "lifecycle directory generation changed")
        for service in self.services.values():
            if service.socket_identity:
                _require(broker._file_identity(os.stat("supervisor.sock", dir_fd=self._fds[_ROOT / service.role],
                    follow_symlinks=False)) == service.socket_identity, "owned supervisor endpoint changed")

    def _prepare(self):
        self._fds[Path("/run")] = lineage._open_protected_root(Path("/run"), 0)
        self._identities[Path("/run")] = broker._directory_identity(os.fstat(self._fds[Path("/run")]))
        self._mkdir(_ROOT)
        self._mkdir(_ACTION, self.identities["action"]["uid"], self.identities["action"]["gid"], 0o750)
        self._mkdir(_ROOT / "roots")
        tree = ("dev", "proc", "sys", "tmp", "var", "var/tmp", "var/lib", "var/lib/aragorn-runtime-action",
                "var/lib/aragorn", "var/lib/aragorn/admitted", "etc", "etc/aragorn", "run", "run/aragorn-pi-services",
                "run/aragorn-pi-action", "usr", "lib", "opt", "opt/aragorn")
        for role, service in self.services.items():
            self._mkdir(_ROOT / role)
            self._mkdir(service.root)
            for relative in (*tree, "run/aragorn-pi-services/" + role): self._mkdir(service.root / relative)
            if role == "provider" and self.provider_credential is not None:
                # systemd supplies its private read-only credential mount here;
                # never bind the original key or copy its bytes into this root.
                self._mkdir(service.root / "run/credentials")
                self._mkdir(service.root / "run/credentials" / _UNITS[role])
            # Fixed regular placeholders prevent systemd from modifying the
            # private skeleton to create file mountpoints after custody capture.
            leaves = [configuration.PATHS[role]]
            if role == "provider": leaves += ["etc/aragorn/pi-provider-profile.json", "etc/aragorn/pi-provider-ca.pem"]
            for relative in leaves:
                path = service.root / relative
                fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o444, dir_fd=self._fds[path.parent])
                try:
                    os.fchmod(fd, 0o444)
                    self._files.append((path, broker._file_identity(os.fstat(fd))))
                finally: os.close(fd)
            fd = self._fds[_ROOT / role]
            service.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            service.listener.bind(f"/proc/self/fd/{fd}/supervisor.sock")
            before = os.stat("supervisor.sock", dir_fd=fd, follow_symlinks=False)
            _require(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1, "new supervisor endpoint unsafe")
            os.chown("supervisor.sock", 0, service.gid, dir_fd=fd, follow_symlinks=False)
            os.chmod("supervisor.sock", 0o660, dir_fd=fd, follow_symlinks=False)
            after = os.stat("supervisor.sock", dir_fd=fd, follow_symlinks=False)
            _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and after.st_uid == 0 and
                     after.st_gid == service.gid and stat.S_IMODE(after.st_mode) == 0o660, "supervisor endpoint changed")
            service.socket_identity = broker._file_identity(after)
            service.listener.listen(1)
            _plan(service, self)
        self._ownership(self.operation_deadline)

    def _start(self, role):
        service = self.services[role]
        self._inputs(self.operation_deadline)
        self._ownership(self.operation_deadline)
        _require(native._absent(_state(role, self.operation_deadline)), "fixed service appeared before start")
        _manager_environment(self.operation_deadline)
        if role == "provider" and self.provider_credential is not None:
            _credential_directory_absent(self.operation_deadline)
        service.start_attempted = True
        code, _ = native._command(service.argv, self.operation_deadline)
        _require(code == 0, "one service start failed or is uncertain")
        service.started = True
        _capture(service, self.operation_deadline)
        if self.provider_credential is not None:
            self._inputs(self.operation_deadline)
        service.listener.settimeout(_remaining(self.operation_deadline))
        service.connection, _ = service.listener.accept()
        service.connection.set_inheritable(False)
        _require(broker._peer_credentials(service.connection) == (service.pid, service.uid, service.gid),
                 "post-exec channel does not belong to captured service")
        _generation(service, self.operation_deadline)
        self._source_startup(service)

    def _source_startup(self, service):
        """Join the trusted loader report to this already-captured generation."""
        deadline, connection = self.operation_deadline, service.connection
        role = service.role
        _require(role not in self._observation["trusted_source_startup"], "source startup already attempted")
        startup = {"status": "INCOMPLETE"}
        self._observation["trusted_source_startup"][role] = startup
        peer = (service.pid, service.uid, service.gid)
        peer_fd = transport.guard_channel(connection, peer, deadline)
        try:
            pins = channels._deployment_pins(self.deployment, deadline)
            inventory = self.deployment.binding["source_digests"]
            base = {"schema": entry.SOURCE_STARTUP_SCHEMA, "role": role,
                "nonce": secrets.token_hex(32), "runtime_closure_digest": pins["runtime_closure_digest"],
                "binding_digest": pins["binding_digest"], "source_inventory_digest": canonical_digest(inventory)}
            challenge = {**base, "kind": "CHALLENGE"}
            startup.update(challenge=challenge,
                process={"pid": service.pid, "uid": service.uid, "gid": service.gid,
                    "start_ticks": service.start_ticks, "cgroup": service.plan.profile.cgroup,
                    "invocation_id": service.invocation, "unit_properties_digest": service.immutable_digest,
                    "python_digest": pins["python_digest"]})
            transport.send_authenticated_packet(connection, challenge, deadline, max_bytes=entry.SOURCE_PACKET_LIMIT)
            receipt, _ = transport.receive_authenticated_packet(connection, peer, deadline,
                expected_rights=0, max_bytes=entry.SOURCE_PACKET_LIMIT)
            # Retain bounded authenticated failure evidence, without logging packet contents.
            _require(len(canonical_json(receipt)) <= entry.SOURCE_PACKET_LIMIT, "source receipt exceeds retention bound")
            startup.update(receipt=receipt, receipt_digest=canonical_digest(receipt))
            _require(type(receipt) is dict and set(receipt) == set(base) | {"kind", "sources", "sources_digest"} and
                     all(receipt[key] == value for key, value in base.items()) and receipt["kind"] == "CONSUMED",
                     "service consumed-source startup binding differs")
            records = _consumed_sources(receipt["sources"], inventory, role)
            _require(receipt["sources_digest"] == canonical_digest(records), "consumed-source digest differs")
            self._inputs(deadline)
            _generation(service, deadline)
            transport.require_peer_live(connection, peer, peer_fd, deadline)
            transport.send_authenticated_packet(connection, {**base, "kind": "ACCEPTED",
                "sources_digest": receipt["sources_digest"]}, deadline, max_bytes=entry.SOURCE_PACKET_LIMIT)
            startup.update(status="AUTHENTICATED_TRUSTED_SOURCE_STARTUP",
                authority="TRUSTED_ARAGORN_STARTUP_IMPORTS_NOT_WORKER_STDLIB_OR_LATER_CODE")
        finally:
            transport._close_installed([peer_fd])

    def _bounded(self, deadline):
        _require(type(self) is PiServiceLifecycle and getattr(self, "_seal", None) is _SEAL and
                 getattr(self, "_active", False) and not getattr(self, "_closed", True),
                 "service lifecycle custody is not active")
        bounded = self.operation_deadline if deadline is None else deadline
        transport.validate_deadline(bounded)
        _require(bounded <= self.operation_deadline, "service lifecycle deadline extended")
        return bounded

    def _attach_channels(self, lease):
        self._bounded(self.operation_deadline)
        _require(type(lease) is channels.PiServiceChannels and getattr(lease, "_seal", None) is channels._SEAL and
                 getattr(lease, "_active", False) and self._channels is None and
                 lease._lifecycle is self and lease._deployment is self.deployment and
                 lease._binding is self.binding and lease._deadline == self.operation_deadline,
                 "service channels do not belong to this captured lifecycle")
        expected = {role: {"pid": item.pid, "uid": item.uid, "gid": item.gid, "start_ticks": item.start_ticks,
            "cgroup": item.plan.profile.cgroup, "executable_digest": self.deployment.observation["python_digest"]}
            for role, item in self.services.items()}
        _require(all(item.started and item.pidfd >= 0 and item.invocation and item.immutable_digest and
                     item.connection is not None for item in self.services.values()) and
                 len(lease._connections) == 3 and all(connection is item.connection
                    for connection, item in zip(lease._connections, self.services.values())) and
                 lease._expected == expected, "service channels differ from captured processes")
        self._channels = lease

    def guard_inputs_and_units(self, lease, *, deadline, allow_provider_exit=False):
        bounded = self._bounded(deadline)
        _require(self._channels is lease and type(lease) is channels.PiServiceChannels and
                 lease._lifecycle is self, "service lifecycle/channel join differs")
        _require(type(allow_provider_exit) is bool and
                 (not allow_provider_exit or
                  (getattr(lease, "_provider_retiring", False) is True and
                   lease.provider_retired is False)),
                 "provider exit exception is not the held retirement transition")
        # The caller channel guard separately hashes the runtime image. Recheck
        # public/configuration custody and exact units here without recursion.
        for value in (self.configuration, self.provider_inputs):
            _require(bounded <= value.deadline, "service inputs extend held deadline")
            value.guard(deadline=bounded)
        if self.provider_credential is not None:
            _guard_credential(self.provider_credential, self.provider_inputs, bounded)
        self._ownership(bounded)
        retired = getattr(lease, "provider_retired", False)
        _require(type(retired) is bool, "provider retirement state differs")
        for service in self.services.values():
            if service.role == "provider" and (retired or allow_provider_exit):
                _require(lease._expected["provider"] == {
                    "pid": service.pid, "uid": service.uid, "gid": service.gid,
                    "start_ticks": service.start_ticks, "cgroup": service.plan.profile.cgroup,
                    "executable_digest": self.deployment.observation["python_digest"]} and
                    lease.provider_connection is service.connection,
                    "retired provider differs from captured channel generation")
                _retired_provider_generation(service, bounded)
            else:
                _generation(service, bounded)
        _remaining(bounded)

    def guard(self, *, deadline=None):
        self.channels.guard(deadline=self._bounded(deadline))

    def _stop(self, service):
        if not service.start_attempted: return
        _require(service.started and service.pidfd >= 0 and service.invocation and service.immutable_digest and
                 service.cgroup_fd >= 0 and service.cgroup_parent_fd >= 0, "uncertain start cannot authorize stop")
        state = _state(service.role, self.deadline)
        if not native._absent(state):
            dead = native._exited(service.pidfd)
            # Revoked request authority must not prevent exact owned teardown.
            _generation(service, self.deadline, live=not dead, credential_authority=False)
            _require(not service.stop_attempted, "service stop is already attempted")
            service.stop_attempted = True
            code, _ = native._command(("/usr/bin/systemctl", "stop", "--no-block", _UNITS[service.role]), self.deadline)
            _require(code == 0, "owned service stop was not accepted")
        while True:
            dead, state = native._exited(service.pidfd), _state(service.role, self.deadline)
            if dead and native._absent(state): break
            _generation(service, self.deadline, live=not dead, credential_authority=False)
            time.sleep(min(0.02, _remaining(self.deadline)))
        native._cgroup_empty(service)
        service.terminal = True

    def close(self):
        if self._closed:
            _require(self._observation["cleanup"]["status"] == "VERIFIED_OWNED_CLEANUP",
                     "service cleanup already failed; no retry")
            return
        self._closed, self._active = True, False
        failures = []
        try: self._stack.close()  # Withdraw borrowed-channel authority first.
        except BaseException as exc: failures.append(exc)
        for service in reversed(tuple(self.services.values())):
            try: self._stop(service)
            except BaseException as exc: failures.append(exc)
        try:
            _require(not failures, "service exit/custody cleanup hold")
            if self.provider_credential is not None and self.services["provider"].start_attempted:
                _require(self.services["provider"].terminal, "provider credential cleanup requires owned process exit")
                _credential_directory_absent(self.deadline)
                self._observation["provider_credential_cleanup"] = "MANAGER_DIRECTORY_ABSENT"
            self._ownership(self.deadline)
            if _ACTION in self._created:
                _require(_ACTION in self._fds and native._missing(self._fds[_ACTION], "sensor.sock"),
                         "child-owned action listener cleanup unverified; preserve endpoint")
            for service in self.services.values():
                if service.listener is not None:
                    value, service.listener = service.listener, None
                    value.close()
                if service.socket_identity:
                    os.unlink("supervisor.sock", dir_fd=self._fds[_ROOT / service.role])
                    service.socket_identity = ()
            for path, identity in reversed(self._files):
                _remaining(self.deadline)
                _require(broker._file_identity(os.stat(path.name, dir_fd=self._fds[path.parent], follow_symlinks=False)) == identity,
                         "root placeholder changed")
                os.unlink(path.name, dir_fd=self._fds[path.parent])
            for path in reversed(self._created):
                _remaining(self.deadline)
                _require(os.listdir(self._fds[path]) == [] and broker._directory_identity(os.lstat(path)) == self._identities[path],
                         "owned service directory is not empty or replaced")
                os.rmdir(path.name, dir_fd=self._fds[path.parent])
            self._observation["cleanup"] = {"status": "VERIFIED_OWNED_CLEANUP"}
        except BaseException as exc:
            failures.append(exc)
        finally:
            for service in self.services.values():
                for name in ("connection", "listener"):
                    value = getattr(service, name)
                    setattr(service, name, None)
                    if value is not None:
                        try: value.close()
                        except BaseException as exc: failures.append(exc)
                for name in ("pidfd", "cgroup_fd", "cgroup_parent_fd"):
                    value = getattr(service, name)
                    setattr(service, name, -1)
                    if value >= 0:
                        try: os.close(value)
                        except BaseException as exc: failures.append(exc)
            pending, self._fds = list(reversed(list(self._fds.values()))), {}
            try: transport._close_installed(pending)
            except BaseException as exc: failures.append(exc)
        self._observation.update(status="CLOSED" if not failures else "CLEANUP_HOLD",
            units={role: {"pid": item.pid or None, "invocation_id": item.invocation or None,
                          "process_exit_and_cgroup_cleanup": item.terminal} for role, item in self.services.items()})
        if failures:
            self._observation["cleanup"] = {"status": "CLEANUP_HOLD"}
            error = PiServiceLifecycleError("service lifecycle cleanup is uncertain; preserve resources")
            error.pi_service_lifecycle_observation = self.observation
            raise error from failures[0]


@contextmanager
def hold_native_pi_services(*, deployment, configuration: configuration.PiServiceConfiguration,
                            provider_inputs, binding, deadline, cleanup_timeout_seconds=5.0,
                            provider_credential=None):
    transport.validate_deadline(deadline)
    _require(type(cleanup_timeout_seconds) in (int, float) and math.isfinite(cleanup_timeout_seconds) and
             0 < cleanup_timeout_seconds <= 5 and time.monotonic() < deadline - cleanup_timeout_seconds,
             "service cleanup reserve invalid")
    # Parameter name intentionally mirrors caller API; use actual type modules
    # through imports without accepting arbitrary guard callbacks or wire dicts.
    from .pi_core_service_configuration import PiServiceConfiguration, PiProviderInputs
    _require(type(deployment) is provision.PiServiceRuntime and type(configuration) is PiServiceConfiguration and
             type(provider_inputs) is PiProviderInputs, "exact held service/runtime/public-input custody required")
    channels._binding(binding)
    held = PiServiceLifecycle(_SEAL, deployment, configuration, provider_inputs, binding, deadline, cleanup_timeout_seconds,
                             provider_credential=provider_credential)
    failure = None
    try:
        native._prerequisites(held.operation_deadline)
        held._inputs(held.operation_deadline)
        _require(deployment.binding["schema"] == provision.BINDING_SCHEMA_V2, "fixed service wrapper image required")
        source_pins = deployment.binding.get("source_digests", {})
        _require(type(source_pins) is dict and _SOURCE_LOADER in source_pins,
                 "verified-source wrapper successor required before service startup")
        profile = provider_inputs.profile
        _require((profile["service_uid"], profile["service_gid"]) ==
                 (held.identities["provider"]["uid"], held.identities["provider"]["gid"]), "provider role/profile differs")
        grant = configuration.configurations["action"]["capability_grant"]
        _require((binding.runtime_digest, binding.active_skill_digest, binding.policy_digest, binding.policy_version) ==
                 (grant["runtime_digest"], grant["active_skill_digest"], grant["policy_digest"], grant["policy_version"]),
                 "worker/grant service binding differs")
        _require(all(native._absent(_state(role, held.operation_deadline)) for role in ROLES), "fixed service already exists")
        _manager_environment(held.operation_deadline)
        if provider_credential is not None:
            _provider_manager_prerequisites(held.operation_deadline)
        held._observation["grant_readiness"] = _readiness(configuration.configurations, held.operation_deadline)
        held._prepare()
        held._start("action")
        held._action_socket = _listener_ready(held.services["action"], held._fds[_ACTION], held._identities[_ACTION], held.operation_deadline)
        held._start("sensor")
        held._start("provider")
        expected = {role: {"pid": value.pid, "uid": value.uid, "gid": value.gid, "start_ticks": value.start_ticks,
            "cgroup": value.plan.profile.cgroup, "executable_digest": deployment.observation["python_digest"]}
            for role, value in held.services.items()}
        held._active = True
        lease = held._stack.enter_context(channels.hold_pi_service_channels(
            {role: value.connection for role, value in held.services.items()}, expected, binding,
            deployment=deployment, deadline=held.operation_deadline, lifecycle_custody=held))
        _require(held._channels is lease, "channel factory did not join captured lifecycle")
        held.guard()
        held._observation["status"] = ("AUTHENTICATED_SERVICES_PROVIDER_PREPARED" if provider_credential is not None
                                       else "AUTHENTICATED_SERVICES_PROVIDER_UNAVAILABLE")
        yield held
        held.guard()  # A dead service during NO_REQUEST is not a successful bootstrap.
    except BaseException as exc:
        failure = exc
        raise
    finally:
        try: held.close()
        finally:
            if failure is not None: failure.pi_service_lifecycle_observation = held.observation
