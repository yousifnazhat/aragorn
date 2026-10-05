"""Read the fixed native Linux stack's current bytes and kernel identities.

This read-only measurement is deliberately not a seven-dimension deployment
attestation. It neither imports capture scripts nor starts/stops services. The
outer owned-fixture adapter must still measure the whole runtime tree, Docker
image/volume, complete installed profile, adapter source and signed source tree.
Loaded credentials are read through PIDFD-pinned process roots, not inferred
from the source files in the observer's namespace. Credential bytes are never
returned. This strict reader has not itself established live fixture coverage.
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import selectors
import stat
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from . import runtime_action_broker as broker
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-phase3-live-identity/v1"
AUTHORITY = "LOCAL_KERNEL_AND_PROTECTED_BYTES_NOT_HOST_ATTESTATION_OR_QUALIFICATION"
_UNITS = {
    "gateway": "aragorn-agent-gateway.service",
    "worker": "aragorn-runtime-action-worker.service",
    "sensor": "aragorn-runtime-lineage-capability-observation-publisher.service",
    "broker": "aragorn-runtime-lineage-capability-action-broker.service",
}
_ACCOUNTS = {
    "gateway": ("aragorn-agent-gateway", "aragorn-agent-gateway"),
    "worker": ("aragorn-runtime", "aragorn-runtime"),
    "sensor": ("aragorn-sensor", "aragorn-sensor"),
    "broker": ("aragorn-broker", "aragorn-runtime"),
}
_SHIMS = {
    "worker": "aragorn-runtime-action-worker-service.py",
    "sensor": "aragorn-runtime-observation-service-v4.py",
    "broker": "aragorn-runtime-action-service-v5.py",
}
_CONFIG = "/etc/aragorn/agent-gateway/openclaw.json"
_WORKER = "/etc/aragorn/runtime-action-worker.json"
_RUNTIME = "/etc/aragorn/runtime-action-runtime.json"
_OBSERVATION = "/etc/aragorn/runtime-action-observation.json"
_GRANT = "/etc/aragorn/runtime-capability-grant.json"
_GENESIS = "/etc/aragorn/runtime-native-tool-genesis.json"
_POLICY = "/var/lib/aragorn-runtime-action/control/policy.json"
_ENTRY = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_WORKER_CODE = "/usr/lib/aragorn/aragorn/runtime_action_worker.py"
_PYTHON = "/usr/local/bin/python3.12"
_CREDENTIALS = {
    "gateway": {"openclaw-config": _CONFIG, "native-tool-genesis": _GENESIS},
    "worker": {
        "worker-binding": _WORKER,
        "openclaw-config": _CONFIG,
        "native-tool-genesis": _GENESIS,
    },
    "sensor": {"observation-binding": _OBSERVATION, "capability-grant": _GRANT},
    "broker": {"runtime-binding": _RUNTIME, "capability-grant": _GRANT},
}
_CODE = (
    _ENTRY,
    _WORKER_CODE,
    *("/usr/libexec/aragorn/" + name for name in _SHIMS.values()),
    *("/usr/lib/systemd/system/" + name for name in _UNITS.values()),
)
FILE_PATHS = (
    *_CODE,
    _CONFIG,
    _WORKER,
    _RUNTIME,
    _OBSERVATION,
    _GRANT,
    _GENESIS,
    _POLICY,
    _PYTHON,
    "/usr/local/bin/node",
)
_PROPERTIES = (
    "Id",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "InvocationID",
    "ActiveState",
    "SubState",
    "User",
    "Group",
    "ExecStart",
    "FragmentPath",
    "DropInPaths",
)
_LIMIT = 2 * 1024 * 1024
_EXECUTABLE_LIMIT = 256 * 1024 * 1024
LIMITATIONS = (
    "POINT_IN_TIME_BEFORE_AFTER_READS_NOT_CONTINUOUS_IMMUTABILITY",
    "RUNTIME_ENTRYPOINT_BYTES_NOT_WHOLE_RUNTIME_TREE_OR_DOCKER_IMAGE",
    "GATEWAY_PROCESS_TITLE_AND_UNIT_LAUNCHER_NOT_LOADED_SCRIPT_PROVENANCE",
    "LOADED_CREDENTIAL_BYTES_NOT_PROOF_OF_APPLICATION_USE_OR_POLICY_SEMANTICS",
    "FIXED_WORKER_AND_UNIT_BYTES_NOT_FULL_IMPORTED_CODE_OR_70_FILE_PROFILE",
    "NO_ADAPTER_SOURCE_OR_SIGNED_ARAGORN_SOURCE_MEASUREMENT",
    "LOCAL_ROOT_OBSERVER_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_ROUTE_RUN_SENSOR_HEALTH_OR_PHASE3_QUALIFICATION",
)
UNRESOLVED_DIMENSIONS = {
    "runtime_commit_or_image": [
        "whole_runtime_tree",
        "image",
        "runtime_volume",
        "build_record",
    ],
    "adapter": ["capture_adapter_source_identity"],
    "configuration": ["application_use_of_measured_loaded_configuration"],
    "worker": ["complete_imported_worker_code_closure"],
    "os_profile": ["complete_installed_70_file_profile", "image_and_kernel_provenance"],
    "policy": ["independent_policy_semantics"],
    "aragorn_version": ["signed_source_commit_and_source_inventory"],
}


class NativeLiveIdentityError(ValueError):
    """Current native identity could not be measured under the fixed contract."""


def _require(value: bool, message: str) -> None:
    if not value:
        raise NativeLiveIdentityError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "invalid caller-held file digest",
    )
    return value


def _pairs(items):
    result = dict(items)
    _require(len(result) == len(items), "duplicate protected document key")
    return result


def _document(raw: bytes) -> dict:
    value = json.loads(raw, object_pairs_hook=_pairs)
    _require(
        type(value) is dict
        and raw in (canonical_json(value), canonical_json(value) + b"\n"),
        "protected document is not canonical",
    )
    return value


def _read_at(
    root_fd: int,
    path: str,
    *,
    owner: int,
    modes: set[int],
    limit: int = _LIMIT,
    credential_owner: int | None = None,
    credential_gid: int | None = None,
    owner_gid: int = 0,
    require_read_only: bool = False,
) -> tuple[bytes, dict]:
    """Hold each no-follow ancestor until named identities are rechecked."""
    value = Path(path)
    _require(
        value.is_absolute() and str(value) == path and ".." not in value.parts,
        "invalid fixed measurement path",
    )
    _require(
        type(require_read_only) is bool
        and (
            not require_read_only
            or (
                path == _ENTRY
                and owner == owner_gid == 1000
                and modes == {0o755}
                and credential_owner is None
                and credential_gid is None
            )
        ),
        "read-only ownership exception is only for the fixed runtime entrypoint",
    )
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with ExitStack() as stack:
        parent = root_fd
        ancestors = []
        for index, part in enumerate(value.parts[1:-1], start=1):
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
            stack.callback(os.close, child)
            after = os.fstat(child)
            allowed = {0, owner} if credential_owner is None else {0}
            if credential_owner is not None and index == len(value.parts) - 2:
                allowed.add(credential_owner)
            _require(
                stat.S_ISDIR(after.st_mode)
                and after.st_uid in allowed
                and not stat.S_IMODE(after.st_mode) & 0o022
                and broker._directory_identity(before)
                == broker._directory_identity(after),
                "protected ancestor changed or is writable",
            )
            if require_read_only:
                # These are only /runtime and its fixed descendants. Retained
                # native build ownership is 1000:1000; root-owned descendants
                # are also protected, but no other or mixed owner pair is valid.
                _require(
                    (after.st_uid, after.st_gid) in {(0, 0), (1000, 1000)}
                    and bool(os.fstatvfs(child).f_flag & os.ST_RDONLY),
                    "fixed runtime ancestor is not protected and read-only",
                )
            if credential_owner is not None and after.st_uid == credential_owner:
                _require(
                    bool(os.fstatvfs(child).f_flag & os.ST_RDONLY),
                    "service-owned credential directory is writable",
                )
            ancestors.append((parent, part, child, broker._directory_identity(after)))
            parent = child
        fd = os.open(value.name, flags, dir_fd=parent)
        stack.callback(os.close, fd)
        before = os.fstat(fd)
        allowed = {owner} if credential_owner is None else {0, credential_owner}
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid in allowed
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) in modes
            and 0 < before.st_size <= limit
            and not stat.S_IMODE(before.st_mode) & 0o022,
            "protected file metadata is unsafe",
        )
        if credential_owner is not None:
            _require(
                type(credential_gid) is int
                and credential_gid > 0
                and before.st_gid in {0, credential_gid}
                and (before.st_uid != 0 or before.st_gid == 0)
                and (
                    before.st_uid != credential_owner
                    or (
                        stat.S_IMODE(before.st_mode) == 0o400
                        and bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
                    )
                ),
                "loaded credential custody is unsafe",
            )
        else:
            _require(before.st_gid == owner_gid, "protected file group is unsafe")
        if require_read_only:
            _require(
                bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY),
                "fixed runtime entrypoint is not read-only",
            )
        raw = bytearray()
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - len(raw))):
            raw.extend(chunk)
            _require(len(raw) <= limit, "protected file exceeds byte bound")
        identity = broker._file_identity(before)
        _require(
            len(raw) == before.st_size
            and identity
            == broker._file_identity(os.fstat(fd))
            == broker._file_identity(
                os.stat(value.name, dir_fd=parent, follow_symlinks=False)
            ),
            "protected file changed while measured",
        )
        if require_read_only:
            _require(
                bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY),
                "fixed runtime entrypoint became writable while measured",
            )
        for directory, name, child, previous in ancestors:
            _require(
                previous
                == broker._directory_identity(os.fstat(child))
                == broker._directory_identity(
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                ),
                "protected ancestor changed while measured",
            )
            if require_read_only:
                _require(
                    bool(os.fstatvfs(child).f_flag & os.ST_RDONLY),
                    "fixed runtime ancestor became writable while measured",
                )
        return bytes(raw), {
            "bytes": len(raw),
            "digest": _digest(raw),
            "identity": list(identity),
        }


def _show(unit: str) -> dict[str, str]:
    child = subprocess.Popen(
        [
            "/usr/bin/systemctl",
            "--system",
            "--no-pager",
            "show",
            "--property=" + ",".join(_PROPERTIES),
            unit,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        deadline = time.monotonic() + 3
        with selectors.DefaultSelector() as selector:
            for name in buffers:
                stream = getattr(child, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                _require(remaining > 0, "fixed unit readback timed out")
                for key, _ in selector.select(remaining):
                    limit = 16384 if key.data == "stdout" else 4096
                    chunk = os.read(
                        key.fileobj.fileno(),
                        min(4096, limit + 1 - len(buffers[key.data])),
                    )
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        buffers[key.data].extend(chunk)
                        _require(
                            len(buffers[key.data]) <= limit,
                            "fixed unit output exceeds byte bound",
                        )
        _require(
            child.wait(timeout=max(0.001, deadline - time.monotonic())) == 0
            and not buffers["stderr"],
            "fixed unit readback failed",
        )
    finally:
        # Terminate only this reader's own systemctl child, never a service PID.
        if child.poll() is None:
            child.kill()
        child.stdout.close()
        child.stderr.close()
        child.wait(timeout=1)
    pairs = [
        line.split("=", 1)
        for line in bytes(buffers["stdout"]).decode("ascii").splitlines()
    ]
    _require(
        all(len(pair) == 2 for pair in pairs) and len(pairs) == len(_PROPERTIES),
        "fixed unit readback has malformed fields",
    )
    value = dict(pairs)
    _require(set(value) == set(_PROPERTIES), "fixed unit readback inventory changed")
    return value


def _python_link(root: int, *, uid: int = 0, gid: int = 0) -> dict:
    """The native fixture has this one fixed launcher link, not arbitrary aliases."""
    with ExitStack() as stack:
        parent, ancestors = root, []
        for name in ("usr", "bin"):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            stack.callback(os.close, fd)
            metadata = broker.require_owned_directory(
                fd,
                expected_uid=uid,
                require_owner_write=False,
                label="fixed Python launcher",
            )
            _require(
                metadata.st_gid == gid
                and broker._directory_identity(metadata)
                == broker._directory_identity(before),
                "fixed Python launcher ancestry changed",
            )
            ancestors.append((parent, name, fd, broker._directory_identity(metadata)))
            parent = fd
        before = os.stat("python3.12", dir_fd=parent, follow_symlinks=False)
        _require(
            stat.S_ISLNK(before.st_mode)
            and before.st_uid == uid
            and before.st_gid == gid
            and before.st_nlink == 1
            and os.readlink("python3.12", dir_fd=parent) == _PYTHON,
            "fixed Python launcher link changed",
        )
        identity = broker._file_identity(before)
        _require(
            identity
            == broker._file_identity(
                os.stat("python3.12", dir_fd=parent, follow_symlinks=False)
            ),
            "fixed Python launcher changed while read",
        )
        for directory, name, fd, prior in ancestors:
            _require(
                prior
                == broker._directory_identity(os.fstat(fd))
                == broker._directory_identity(
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                ),
                "fixed Python launcher ancestry changed while read",
            )
        return {
            "path": "/usr/bin/python3.12",
            "target": _PYTHON,
            "identity": list(identity),
        }


@contextmanager
def _systemd_library_alias(root: int, *, uid: int = 0, gid: int = 0):
    """Hold only the fixed merged-/usr target; never resolve arbitrary aliases."""

    def link_identity():
        before = os.stat("lib", dir_fd=root, follow_symlinks=False)
        _require(
            stat.S_ISLNK(before.st_mode)
            and before.st_uid == uid
            and before.st_gid == gid
            and before.st_nlink == 1
            and os.readlink("lib", dir_fd=root) == "usr/lib",
            "fixed systemd library alias changed",
        )
        identity = broker._file_identity(before)
        _require(
            identity
            == broker._file_identity(
                os.stat("lib", dir_fd=root, follow_symlinks=False)
            ),
            "fixed systemd library alias changed while read",
        )
        return identity

    with ExitStack() as stack:
        metadata = broker.require_owned_directory(
            root, expected_uid=uid, require_owner_write=False, label="alias root"
        )
        _require(metadata.st_gid == gid, "fixed systemd alias root group changed")
        root_identity = broker._directory_identity(metadata)
        identity = link_identity()
        parent, ancestors, provenance = root, [], []
        for name in ("usr", "lib", "systemd", "system"):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            stack.callback(os.close, fd)
            metadata = broker.require_owned_directory(
                fd, expected_uid=uid, require_owner_write=False, label="alias target"
            )
            prior = broker._directory_identity(metadata)
            _require(
                metadata.st_gid == gid and prior == broker._directory_identity(before),
                "fixed systemd alias target ancestry changed",
            )
            ancestors.append((parent, name, fd, prior))
            provenance.append(list(prior))
            parent = fd
        _require(link_identity() == identity, "fixed systemd library alias changed")
        yield {
            "path": "/lib",
            "target": "usr/lib",
            "canonical_unit_directory": "/usr/lib/systemd/system",
            "identity": list(identity),
            "target_ancestry_identities": provenance,
        }
        _require(
            link_identity() == identity
            and broker._directory_identity(os.fstat(root)) == root_identity,
            "fixed systemd library alias custody changed during measurement",
        )
        for directory, name, fd, prior in ancestors:
            _require(
                prior
                == broker._directory_identity(os.fstat(fd))
                == broker._directory_identity(
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                ),
                "fixed systemd alias target ancestry changed during measurement",
            )


def _executable_path(role: str) -> str:
    return "/usr/local/bin/node" if role == "gateway" else _PYTHON


def _argv(role: str) -> list[str]:
    if role == "gateway":
        return [
            "/usr/local/bin/node",
            _ENTRY,
            "gateway",
            "run",
            "--auth",
            "token",
            "--bind",
            "loopback",
            "--port",
            "18789",
            "--tailscale",
            "off",
        ]
    names = {
        "worker": ("worker-binding",),
        "sensor": ("observation-binding", "capability-grant"),
        "broker": ("runtime-binding", "capability-grant"),
    }[role]
    return [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        "/usr/libexec/aragorn/" + _SHIMS[role],
        *(f"/run/credentials/{_UNITS[role]}/{name}" for name in names),
    ]


def _accounts() -> dict[str, tuple[int, int]]:
    values = {}
    for role, (user, group) in _ACCOUNTS.items():
        account, gid = pwd.getpwnam(user), grp.getgrnam(group).gr_gid
        _require(
            account.pw_uid > 0
            and gid > 0
            and (role == "broker" or account.pw_gid == gid),
            "fixed service account changed",
        )
        values[role] = (account.pw_uid, gid)
    _require(
        len({uid for uid, _ in values.values()}) == 4, "service users are not distinct"
    )
    return values


def _groups(role: str, accounts: dict) -> list[int]:
    if role in {"sensor", "broker"}:
        return sorted({accounts["worker"][1], accounts["sensor"][1]})
    if role == "worker":
        return sorted({accounts["worker"][1], accounts["gateway"][1]})
    return [accounts[role][1]]


def _process(
    role: str, container: str, accounts: dict, fragment_alias_guard=None
) -> dict:
    unit, argv = _UNITS[role], _argv(role)
    # The frozen gateway consumers observe Node's rewritten process title.
    # ExecStart remains separately constrained to the full launcher command.
    kernel_argv = ["openclaw-gateway"] if role == "gateway" else argv
    state = _show(unit)
    uid, gid = accounts[role]
    cgroup = f"/docker/{container}/system.slice/{unit}"
    _require(
        re.fullmatch(r"[1-9][0-9]*", state["MainPID"]) is not None,
        "fixed service has no active PID",
    )
    pid = int(state["MainPID"])
    _require(
        state["Id"] == unit
        and state["ActiveState"] == "active"
        and state["SubState"] == "running"
        and state["ControlPID"] == "0"
        and state["ControlGroup"] == cgroup
        and state["User"] == _ACCOUNTS[role][0]
        and state["Group"] == _ACCOUNTS[role][1]
        and re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"]) is not None
        and state["InvocationID"] != "0" * 32
        and state["DropInPaths"] == ""
        and (
            state["FragmentPath"] == "/usr/lib/systemd/system/" + unit
            or (
                state["FragmentPath"] == "/lib/systemd/system/" + unit
                and fragment_alias_guard is not None
            )
        )
        and state["ExecStart"].startswith(
            "{ path="
            + argv[0]
            + " ; argv[]="
            + " ".join(argv)
            + " ; ignore_errors=no ; "
        )
        and state["ExecStart"].count("argv[]=") == 1,
        "fixed unit identity differs from native contract",
    )
    if state["FragmentPath"] == "/lib/systemd/system/" + unit:
        fragment_alias_guard()
    started = process._process_start_time(pid)
    raw = process._read_virtual_file(Path(f"/proc/{pid}/status"), 16384)
    fields = _pairs(
        [line.split(":", 1) for line in raw.decode("ascii").splitlines() if ":" in line]
    )
    uids, gids = (
        [int(item) for item in fields["Uid"].split()],
        [int(item) for item in fields["Gid"].split()],
    )
    groups = [int(item) for item in fields["Groups"].split()]
    expected_groups = _groups(role, accounts)
    fsuid, fsgid = accounts["worker"] if role == "sensor" else (uid, gid)
    command = process._read_virtual_file(Path(f"/proc/{pid}/cmdline"), 8192)
    _require(
        uids == [uid, uid, uid, fsuid]
        and gids == [gid, gid, gid, fsgid]
        and sorted(groups) == expected_groups
        and command.endswith(b"\0")
        and command.rstrip(b"\0").split(b"\0")
        == [item.encode("ascii") for item in kernel_argv]
        and os.readlink(f"/proc/{pid}/exe") == _executable_path(role)
        and process._process_cgroup(pid) == cgroup
        and pid in process._cgroup_processes(cgroup)
        and process._process_start_time(pid) == started,
        "kernel process identity differs from fixed unit",
    )
    group = os.lstat("/sys/fs/cgroup" + cgroup)
    root = os.stat(f"/proc/{pid}/root")
    _require(
        stat.S_ISDIR(group.st_mode)
        and group.st_uid == 0
        and stat.S_ISDIR(root.st_mode)
        and root.st_uid == 0,
        "process root or cgroup custody is unsafe",
    )
    return {
        "unit": state,
        "pid": pid,
        "start_time_ticks": started,
        "uids": uids,
        "gids": gids,
        "groups": sorted(groups),
        "cgroup": cgroup,
        "cgroup_identity": [group.st_dev, group.st_ino],
        "root_identity": [root.st_dev, root.st_ino],
        "mount_namespace": process._mount_namespace(pid),
        "argv": kernel_argv,
    }


def _open_pidfd(record: dict) -> int:
    fd = os.pidfd_open(record["pid"], 0)
    try:
        info = process._read_virtual_file(
            Path(f"/proc/self/fdinfo/{fd}"), 16384
        ).decode("ascii")
        _require(
            [
                line.partition(":")[2].strip()
                for line in info.splitlines()
                if line.startswith("Pid:")
            ]
            == [str(record["pid"])],
            "pidfd does not pin measured process",
        )
        process.require_live_pidfd(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _boot() -> str:
    raw = process._read_virtual_file(Path("/proc/sys/kernel/random/boot_id"), 64)
    _require(
        re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", raw)
        is not None,
        "kernel boot identity is malformed",
    )
    return raw.decode("ascii").strip()


def _joins(raw: dict[str, bytes]) -> dict:
    config, worker, runtime, observation, policy = (
        _document(raw[name])
        for name in (_CONFIG, _WORKER, _RUNTIME, _OBSERVATION, _POLICY)
    )
    _require(
        worker["schema"] == "aragorn/runtime-action-worker-binding/v1"
        and runtime["schema"] == "aragorn/runtime-action-runtime-binding/v2"
        and observation["schema"] == "aragorn/runtime-observation-binding/v2"
        and policy["schema"] == "aragorn/runtime-action-policy/v1"
        and _pin(worker["runtime_digest"])
        == _pin(runtime["runtime_digest"])
        == _pin(observation["runtime_profile"]["runtime_digest"])
        and _pin(runtime["runtime_profile_digest"])
        == _digest(canonical_json(observation["runtime_profile"]))
        and _pin(worker["policy_digest"]) == _digest(canonical_json(policy))
        and type(worker["policy_version"]) is int
        and worker["policy_version"] == policy["version"],
        "measured native binding documents disagree",
    )
    return {
        "configuration_digest": _digest(canonical_json(config)),
        "worker_binding_digest": _digest(canonical_json(worker)),
        "policy_digest": _digest(canonical_json(policy)),
        "declared_runtime_digest_not_whole_tree_measurement": worker["runtime_digest"],
    }


def read_native_live_identity(
    *, expected_container_id: str, expected_file_digests: dict[str, str]
) -> dict[str, Any]:
    """Measure only the exact caller-owned running native fixture; never mutate it.

    Caller-held digest keys must equal ``FILE_PATHS``. They are expectations,
    never substituted for actual readback. No report or offline CAS is accepted.
    """
    try:
        _require(
            sys.platform == "linux" and os.geteuid() == 0 and hasattr(os, "pidfd_open"),
            "native identity requires Linux root and PIDFD support",
        )
        _require(
            type(expected_container_id) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected_container_id) is not None,
            "invalid owned container identity",
        )
        _require(
            type(expected_file_digests) is dict
            and set(expected_file_digests) == set(FILE_PATHS),
            "caller-held fixed file inventory changed",
        )
        pins = {path: _pin(value) for path, value in expected_file_digests.items()}
        init_group = "/docker/" + expected_container_id + "/init.scope"
        _require(
            process._process_cgroup(1) == init_group,
            "observer is outside owned fixture",
        )
        boot, accounts = _boot(), _accounts()
        with ExitStack() as stack:
            root = os.open(
                "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            stack.callback(os.close, root)
            broker.require_owned_directory(
                root, expected_uid=0, require_owner_write=False, label="observer root"
            )
            launcher = _python_link(root)
            fragment_alias = None

            def guard_fragment_alias():
                nonlocal fragment_alias
                if fragment_alias is None:
                    fragment_alias = stack.enter_context(_systemd_library_alias(root))

            processes = {
                role: _process(
                    role, expected_container_id, accounts, guard_fragment_alias
                )
                for role in _UNITS
            }
            _require(
                len({record["pid"] for record in processes.values()}) == 4,
                "native process PIDs overlap",
            )
            pidfds = {}
            for role, record in processes.items():
                fd = _open_pidfd(record)
                stack.callback(os.close, fd)
                pidfds[role] = fd
            _require(
                processes
                == {
                    role: _process(
                        role, expected_container_id, accounts, guard_fragment_alias
                    )
                    for role in _UNITS
                },
                "native identity changed after PIDFD open",
            )
            raw, files = {}, {}
            for path in FILE_PATHS:
                owner = (
                    1000
                    if path == _ENTRY
                    else accounts["broker"][0]
                    if path == _POLICY
                    else 0
                )
                modes = (
                    {0o755}
                    if path == _ENTRY
                    else {0o644, 0o755}
                    if path in _CODE or path in (_PYTHON, "/usr/local/bin/node")
                    else {0o400}
                )
                limit = (
                    _EXECUTABLE_LIMIT
                    if path in (_PYTHON, "/usr/local/bin/node")
                    else _LIMIT
                )
                raw[path], files[path] = _read_at(
                    root,
                    path,
                    owner=owner,
                    modes=modes,
                    limit=limit,
                    owner_gid=1000
                    if path == _ENTRY
                    else accounts["broker"][1]
                    if path == _POLICY
                    else 0,
                    require_read_only=path == _ENTRY,
                )
                _require(
                    files[path]["digest"] == pins[path],
                    "protected bytes differ from caller-held pin",
                )
            credentials, view_reads = {}, []
            for role, record in processes.items():
                fd = os.open(
                    f"/proc/{record['pid']}/root",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                stack.callback(os.close, fd)
                broker.require_owned_directory(
                    fd, expected_uid=0, require_owner_write=False, label="process root"
                )
                measured = {}
                for name, source in _CREDENTIALS[role].items():
                    path = f"/run/credentials/{_UNITS[role]}/{name}"
                    content, metadata = _read_at(
                        fd,
                        path,
                        owner=0,
                        modes={0o400, 0o440},
                        credential_owner=accounts[role][0],
                        credential_gid=accounts[role][1],
                    )
                    _require(
                        content == raw[source],
                        "loaded credential differs from protected source",
                    )
                    measured[name] = metadata
                    view_reads.append(
                        (
                            fd,
                            path,
                            {
                                "owner": 0,
                                "modes": {0o400, 0o440},
                                "credential_owner": accounts[role][0],
                                "credential_gid": accounts[role][1],
                            },
                            content,
                            metadata,
                        )
                    )
                # Prove the running view has the same selected worker/runtime bytes.
                target = (
                    _ENTRY
                    if role == "gateway"
                    else _WORKER_CODE
                    if role == "worker"
                    else "/usr/libexec/aragorn/" + _SHIMS[role]
                )
                code_arguments = (
                    {
                        "owner": 1000,
                        "owner_gid": 1000,
                        "modes": {0o755},
                        "require_read_only": True,
                    }
                    if target == _ENTRY
                    else {"owner": 0, "modes": {0o644, 0o755}}
                )
                content, metadata = _read_at(fd, target, **code_arguments)
                _require(
                    content == raw[target],
                    "running process code view differs from observer",
                )
                measured["code_view"] = metadata
                view_reads.append(
                    (
                        fd,
                        target,
                        code_arguments,
                        content,
                        metadata,
                    )
                )
                _require(
                    process._executable_digest(record["pid"])
                    == pins[_executable_path(role)],
                    "running executable differs from caller-held pin",
                )
                credentials[role] = measured
            joins = _joins(raw)
            for path in FILE_PATHS:
                owner = (
                    1000
                    if path == _ENTRY
                    else accounts["broker"][0]
                    if path == _POLICY
                    else 0
                )
                modes = {stat.S_IMODE(files[path]["identity"][2])}
                # Re-read source bytes; a pathname digest alone is not a stability claim.
                content, metadata = _read_at(
                    root,
                    path,
                    owner=owner,
                    modes=modes,
                    limit=_EXECUTABLE_LIMIT
                    if path in (_PYTHON, "/usr/local/bin/node")
                    else _LIMIT,
                    owner_gid=1000
                    if path == _ENTRY
                    else accounts["broker"][1]
                    if path == _POLICY
                    else 0,
                    require_read_only=path == _ENTRY,
                )
                _require(
                    content == raw[path] and metadata == files[path],
                    "protected source changed during measurement",
                )
            for fd, path, arguments, content, metadata in view_reads:
                _require(
                    _read_at(fd, path, **arguments) == (content, metadata),
                    "loaded process view changed during measurement",
                )
            for role, fd in pidfds.items():
                process.require_live_pidfd(fd)
                _require(
                    _process(
                        role, expected_container_id, accounts, guard_fragment_alias
                    )
                    == processes[role],
                    "native process changed during byte measurement",
                )
            _require(
                _python_link(root) == launcher
                and _boot() == boot
                and process._process_cgroup(1) == init_group
                and _accounts() == accounts,
                "observer boot, cgroup or account identity changed",
            )
            return {
                "schema": SCHEMA,
                "authority": AUTHORITY,
                "status": "LOCAL_NATIVE_IDENTITY_MEASURED",
                "container_id": expected_container_id,
                "boot_id": boot,
                "files": files,
                "fixed_python_launcher": launcher,
                **(
                    {"fixed_systemd_library_alias": fragment_alias}
                    if fragment_alias is not None
                    else {}
                ),
                "processes": processes,
                "loaded_process_views": credentials,
                "measured_joins": joins,
                "unresolved_dimensions": {
                    name: list(parts) for name, parts in UNRESOLVED_DIMENSIONS.items()
                },
                "limitations": list(LIMITATIONS),
                "common_deployment_fully_verified": False,
                "route_qualified": False,
                "phase3_eligible": False,
                "live_deployment_attested": False,
            }
    except NativeLiveIdentityError:
        raise
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        subprocess.SubprocessError,
        broker.RuntimeActionBrokerError,
        process.RuntimeActionObservationPublisherError,
    ) as exc:
        raise NativeLiveIdentityError(
            "fixed native live identity read refused"
        ) from exc


def compare_native_live_identity(before: dict, after: dict) -> dict:
    """Compare two caller-retained measurements, not independently attest them."""
    _require(
        type(before) is dict
        and type(after) is dict
        and before == after
        and before.get("schema") == SCHEMA
        and before.get("authority") == AUTHORITY
        and before.get("status") == "LOCAL_NATIVE_IDENTITY_MEASURED"
        and before.get("limitations") == list(LIMITATIONS)
        and before.get("unresolved_dimensions") == UNRESOLVED_DIMENSIONS
        and all(
            before.get(name) is False
            for name in (
                "common_deployment_fully_verified",
                "route_qualified",
                "phase3_eligible",
                "live_deployment_attested",
            )
        ),
        "before/after native measurement changed or proof ceiling is missing",
    )
    return {
        "status": "CALLER_MEASUREMENTS_EQUAL",
        "authority": "COMPARISON_ONLY_NOT_INDEPENDENT_LIVE_READBACK",
        "snapshot_digest": _digest(canonical_json(before)),
        "phase3_eligible": False,
        "route_qualified": False,
        "common_deployment_fully_verified": False,
    }
