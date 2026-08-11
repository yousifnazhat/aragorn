"""Linux process-profile measurement for a single active agent skill."""

from __future__ import annotations

import hashlib
import os
import re
import select
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .oci_worker_protocol import canonical_digest
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    _file_identity,
    _read_owned_bytes_at,
    require_owned_directory,
)
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)

PROFILE_SCHEMA = "aragorn/runtime-single-skill-process-profile/v1"
PROFILE_AUTHORITY = "ROOT_PROFILE_PIN_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
ATTRIBUTION_SCHEMA = "aragorn/runtime-process-profile-attribution/v1"
ATTRIBUTION_AUTHORITY = "KERNEL_PROCESS_PROFILE_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PROFILE_FIELDS = {
    "schema",
    "authority",
    "runtime_digest",
    "executable_digest",
    "cgroup",
    "skill_path",
}
_MAX_PROFILE_SKILL_BYTES = 1024 * 1024
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_MAX_PROC_BYTES = 16 * 1024
_SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)


@dataclass(frozen=True, slots=True)
class RuntimeProcessProfile:
    runtime_digest: str
    executable_digest: str
    cgroup: str
    skill_path: Path
    digest: str


def runtime_process_profile(document: object) -> RuntimeProcessProfile:
    """Validate a root-provisioned, digest-free single-skill profile."""

    if not isinstance(document, dict) or set(document) != _PROFILE_FIELDS:
        raise RuntimeActionObservationPublisherError(
            "runtime process profile is invalid"
        )
    runtime_digest = document["runtime_digest"]
    executable_digest = document["executable_digest"]
    skill_path = document["skill_path"]
    if (
        document["schema"] != PROFILE_SCHEMA
        or document["authority"] != PROFILE_AUTHORITY
        or not isinstance(runtime_digest, str)
        or _DIGEST.fullmatch(runtime_digest) is None
        or not isinstance(executable_digest, str)
        or _DIGEST.fullmatch(executable_digest) is None
        or not isinstance(skill_path, str)
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime process profile is invalid"
        )
    path = Path(skill_path)
    if (
        not path.is_absolute()
        or path.name != "SKILL.md"
        or any(component in {"", ".", ".."} for component in path.parts[1:])
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime profile skill path is invalid"
        )
    return RuntimeProcessProfile(
        runtime_digest=runtime_digest,
        executable_digest=executable_digest,
        cgroup=_cgroup_path(document["cgroup"]),
        skill_path=path,
        digest=canonical_digest(document),
    )


def open_peer_pidfd(connection: socket.socket, expected_pid: int) -> int:
    """Pin the kernel-authenticated socket peer against PID reuse."""

    descriptor = -1
    try:
        descriptor = connection.getsockopt(socket.SOL_SOCKET, _SO_PEERPIDFD)
        if (
            isinstance(descriptor, bool)
            or not isinstance(descriptor, int)
            or descriptor < 0
        ):
            raise RuntimeActionObservationPublisherError(
                "runtime peer pidfd is invalid"
            )
        fdinfo = _read_virtual_file(
            Path(f"/proc/self/fdinfo/{descriptor}"),
            _MAX_PROC_BYTES,
        ).decode("ascii")
        pids = [
            line.partition(":")[2].strip()
            for line in fdinfo.splitlines()
            if line.startswith("Pid:")
        ]
        if pids != [str(expected_pid)]:
            raise RuntimeActionObservationPublisherError(
                "runtime peer pidfd does not match socket credentials"
            )
        require_live_pidfd(descriptor)
        return descriptor
    except BaseException as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if isinstance(exc, RuntimeActionObservationPublisherError):
            raise
        if isinstance(exc, (OSError, UnicodeError, ValueError)):
            raise RuntimeActionObservationPublisherError(
                "runtime peer pidfd is unavailable"
            ) from exc
        raise


def measure_runtime_process_profile(
    pid: int,
    pidfd: int,
    profile: RuntimeProcessProfile,
    *,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, Any]:
    """Derive profile attribution from live kernel state and skill bytes."""

    try:
        require_live_pidfd(pidfd)
        start_time = _process_start_time(pid)
        cgroup = _process_cgroup(pid)
        if cgroup != profile.cgroup:
            raise RuntimeActionObservationPublisherError(
                "runtime process cgroup does not match"
            )
        if _cgroup_processes(cgroup) != (pid,):
            raise RuntimeActionObservationPublisherError(
                "runtime process cgroup is not single-capability"
            )
        _require_process_status(pid, expected_uid, expected_gid)
        mount_namespace = _mount_namespace(pid)
        executable_digest = _executable_digest(pid)
        if executable_digest != profile.executable_digest:
            raise RuntimeActionObservationPublisherError(
                "runtime process executable does not match"
            )
        skill_digest = _profile_skill_digest(pid, profile.skill_path)
        if (
            _process_start_time(pid) != start_time
            or _mount_namespace(pid) != mount_namespace
            or _cgroup_processes(cgroup) != (pid,)
        ):
            raise RuntimeActionObservationPublisherError(
                "runtime process identity changed while measured"
            )
        require_live_pidfd(pidfd)
    except RuntimeActionObservationPublisherError:
        raise
    except (OSError, RuntimeActionBrokerError, UnicodeError, ValueError) as exc:
        raise RuntimeActionObservationPublisherError(
            "runtime process profile cannot be measured"
        ) from exc
    return {
        "schema": ATTRIBUTION_SCHEMA,
        "authority": ATTRIBUTION_AUTHORITY,
        "profile_digest": profile.digest,
        "runtime_digest": profile.runtime_digest,
        "executable_digest": executable_digest,
        "active_skill_digest": skill_digest,
        "skill_path": str(profile.skill_path),
        "cgroup": cgroup,
        "pid": pid,
        "uid": expected_uid,
        "gid": expected_gid,
        "start_time_ticks": start_time,
        "mount_namespace": mount_namespace,
    }


def require_live_pidfd(descriptor: int) -> None:
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLERR | select.POLLHUP)
    if poller.poll(0):
        raise RuntimeActionObservationPublisherError(
            "runtime peer exited while observed"
        )


def _process_start_time(pid: int) -> int:
    raw = _read_virtual_file(Path(f"/proc/{pid}/stat"), _MAX_PROC_BYTES)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeActionObservationPublisherError(
            "runtime process stat is invalid"
        ) from exc
    marker = text.rfind(") ")
    fields = text[marker + 2 :].split() if marker >= 0 else []
    if (
        not text.startswith(f"{pid} (")
        or len(fields) < 20
        or not fields[19].isdigit()
        or int(fields[19]) <= 0
    ):
        raise RuntimeActionObservationPublisherError("runtime process stat is invalid")
    return int(fields[19])


def _process_cgroup(pid: int) -> str:
    raw = _read_virtual_file(Path(f"/proc/{pid}/cgroup"), _MAX_PROC_BYTES)
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeActionObservationPublisherError(
            "runtime process cgroup is invalid"
        ) from exc
    if len(lines) != 1 or not lines[0].startswith("0::"):
        raise RuntimeActionObservationPublisherError(
            "runtime process cgroup is not unified"
        )
    return _cgroup_path(lines[0][3:])


def _cgroup_processes(cgroup: str) -> tuple[int, ...]:
    path = Path("/sys/fs/cgroup").joinpath(*_cgroup_path(cgroup).lstrip("/").split("/"))
    with os.scandir(path) as entries:
        if any(entry.is_dir(follow_symlinks=False) for entry in entries):
            raise RuntimeActionObservationPublisherError(
                "runtime cgroup has delegated descendants"
            )
    raw = _read_virtual_file(path / "cgroup.procs", _MAX_PROC_BYTES)
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeActionObservationPublisherError(
            "runtime cgroup process inventory is invalid"
        ) from exc
    if not lines or any(not line.isdigit() or int(line) <= 0 for line in lines):
        raise RuntimeActionObservationPublisherError(
            "runtime cgroup process inventory is invalid"
        )
    return tuple(sorted(map(int, lines)))


def _require_process_status(pid: int, expected_uid: int, expected_gid: int) -> None:
    raw = _read_virtual_file(Path(f"/proc/{pid}/status"), _MAX_PROC_BYTES)
    try:
        values = {
            name: remainder.split()
            for line in raw.decode("ascii").splitlines()
            for name, separator, remainder in (line.partition(":"),)
            if separator
            and name
            in {
                "Uid",
                "Gid",
                "CapInh",
                "CapPrm",
                "CapEff",
                "CapBnd",
                "CapAmb",
                "NoNewPrivs",
            }
        }
        capabilities = [
            values.get(name, ["invalid"])
            for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        ]
        valid_capabilities = all(
            len(capability) == 1
            and capability[0]
            and all(
                character in "0123456789abcdefABCDEF"
                for character in capability[0]
            )
            and int(capability[0], 16) == 0
            for capability in capabilities
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeActionObservationPublisherError(
            "runtime process status is invalid"
        ) from exc
    if (
        values.get("Uid") != [str(expected_uid)] * 4
        or values.get("Gid") != [str(expected_gid)] * 4
        or values.get("NoNewPrivs") != ["1"]
        or not valid_capabilities
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime process security profile does not match"
        )


def _mount_namespace(pid: int) -> dict[str, int]:
    metadata = os.stat(f"/proc/{pid}/ns/mnt")
    if metadata.st_dev < 0 or metadata.st_ino <= 0:
        raise RuntimeActionObservationPublisherError(
            "runtime mount namespace is invalid"
        )
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def _executable_digest(pid: int) -> str:
    descriptor = os.open(
        f"/proc/{pid}/exe",
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or before.st_size > _MAX_EXECUTABLE_BYTES
            or mode & 0o111 == 0
            or mode & 0o7022
        ):
            raise RuntimeActionObservationPublisherError(
                "runtime process executable metadata is unsafe"
            )
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(
            descriptor,
            min(1024 * 1024, _MAX_EXECUTABLE_BYTES + 1 - total),
        ):
            total += len(chunk)
            if total > _MAX_EXECUTABLE_BYTES:
                raise RuntimeActionObservationPublisherError(
                    "runtime process executable exceeds its byte limit"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if total != after.st_size or _file_identity(before) != _file_identity(after):
        raise RuntimeActionObservationPublisherError(
            "runtime process executable changed while measured"
        )
    return "sha256:" + digest.hexdigest()


def _profile_skill_digest(pid: int, path: Path) -> str:
    descriptor = -1
    try:
        descriptor = _open_peer_directory(pid, path.parent)
        raw = _read_owned_bytes_at(
            descriptor,
            "SKILL.md",
            max_bytes=_MAX_PROFILE_SKILL_BYTES,
            expected_uid=0,
            exact_mode=0o444,
            label="runtime profile skill",
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw:
        raise RuntimeActionObservationPublisherError("runtime profile skill is empty")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _open_peer_directory(pid: int, path: Path) -> int:
    if not path.is_absolute() or any(
        component in {"", ".", ".."} for component in path.parts[1:]
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime profile skill path is invalid"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(
        f"/proc/{pid}/root",
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        require_owned_directory(
            descriptor,
            expected_uid=0,
            require_owner_write=False,
            label="runtime peer root",
        )
        for component in path.parts[1:]:
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(component, flags, dir_fd=descriptor)
            try:
                after = require_owned_directory(
                    child,
                    expected_uid=0,
                    require_owner_write=False,
                    label="runtime skill profile",
                )
                if (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_uid,
                    before.st_gid,
                ) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_uid,
                    after.st_gid,
                ):
                    raise RuntimeActionObservationPublisherError(
                        "runtime skill profile identity changed"
                    )
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_virtual_file(path: Path, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        raw = bytearray()
        while chunk := os.read(descriptor, min(8192, maximum + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > maximum:
                raise RuntimeActionObservationPublisherError(
                    f"{path} exceeds its byte limit"
                )
        return bytes(raw)
    finally:
        os.close(descriptor)


def _cgroup_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 < len(value) <= 1024
        or not value.startswith("/")
        or any(component in {"", ".", ".."} for component in value[1:].split("/"))
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise RuntimeActionObservationPublisherError(
            "runtime process cgroup path is invalid"
        )
    return value
