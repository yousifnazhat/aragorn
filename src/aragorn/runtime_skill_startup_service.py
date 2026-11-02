"""Fixed-credential entrypoint for a future mandatory worker pre-start check.

This module installs nothing and starts no process or service. A successful
invocation verifies a point-in-time byte snapshot, not subsequent process
consumption or an atomic check-to-start transition. The fixed successor unit
and its authenticated activation/deployment profile remain separate inputs.
"""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import runtime_action_worker as worker
from . import runtime_skill_startup as startup
from .runtime_action_broker import _file_identity, _parse_canonical_document

_CREDENTIAL_DIRECTORY = Path("/run/credentials/aragorn-runtime-action-worker.service")
_CREDENTIAL_NAMES = frozenset({"worker-binding", "openclaw-config"})
_EXPECTED_ROOT_UID = 0
_MAX_BINDING_BYTES = 4096


class RuntimeSkillStartupServiceError(RuntimeError):
    """Credential custody or the fixed startup check could not be verified."""


@dataclass(frozen=True, slots=True)
class _Held:
    parent_fd: int | None
    name: str
    fd: int
    before: os.stat_result
    ancestor: bool = False


def _custody(metadata: os.stat_result) -> tuple[int, ...]:
    # Unrelated entries may change in /run while this check is running.
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _recheck(entries: list[_Held], directory_fd: int) -> None:
    if os.environ.get("CREDENTIALS_DIRECTORY") != str(_CREDENTIAL_DIRECTORY):
        raise RuntimeSkillStartupServiceError("credential directory binding changed")
    for entry in entries:
        named = os.stat(entry.name, dir_fd=entry.parent_fd, follow_symlinks=False)
        identity = _custody if entry.ancestor else _file_identity
        if identity(entry.before) != identity(os.fstat(entry.fd)) or (
            identity(entry.before) != identity(named)
        ):
            raise RuntimeSkillStartupServiceError("credential custody changed")
    if not os.fstatvfs(directory_fd).f_flag & os.ST_RDONLY:
        raise RuntimeSkillStartupServiceError("credential mount is not read-only")
    # A file bind mount must not hide a writable credential beneath the directory.
    for entry in entries:
        if not entry.ancestor and not os.fstatvfs(entry.fd).f_flag & os.ST_RDONLY:
            raise RuntimeSkillStartupServiceError("credential mount is not read-only")
    if set(os.listdir(directory_fd)) != _CREDENTIAL_NAMES:
        raise RuntimeSkillStartupServiceError("credential namespace is invalid")


def _open_directory(worker_uid: int, entries: list[_Held]) -> int:
    if os.environ.get("CREDENTIALS_DIRECTORY") != str(_CREDENTIAL_DIRECTORY):
        raise RuntimeSkillStartupServiceError("fixed credential directory is required")
    parts = _CREDENTIAL_DIRECTORY.parts
    if (
        not _CREDENTIAL_DIRECTORY.is_absolute()
        or len(parts) < 2
        or any(part in {".", ".."} for part in parts)
    ):
        raise RuntimeSkillStartupServiceError("fixed credential directory is invalid")
    parent_fd = None
    for index, name in enumerate(parts):
        final = index == len(parts) - 1
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        # Linux O_PATH retains ancestry without requiring directory-list access.
        access = os.O_RDONLY if final else getattr(os, "O_PATH", os.O_RDONLY)
        fd = os.open(
            name,
            access | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        entries.append(_Held(parent_fd, name, fd, before, ancestor=not final))
        metadata = os.fstat(fd)
        owners = (
            {0, _EXPECTED_ROOT_UID, worker_uid} if final else {0, _EXPECTED_ROOT_UID}
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in owners
            or stat.S_IMODE(metadata.st_mode) & 0o7022
            or _file_identity(before) != _file_identity(metadata)
        ):
            raise RuntimeSkillStartupServiceError("credential directory is unsafe")
        parent_fd = fd
    assert parent_fd is not None
    _recheck(entries, parent_fd)
    return parent_fd


def _read_credential(
    directory_fd: int,
    name: str,
    worker_uid: int,
    entries: list[_Held],
    max_bytes: int,
) -> bytes:
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    entries.append(_Held(directory_fd, name, fd, before))
    metadata = os.fstat(fd)
    mode = stat.S_IMODE(metadata.st_mode)
    safe_owner = (metadata.st_uid == worker_uid and mode == 0o400) or (
        metadata.st_uid == 0 and metadata.st_gid == 0 and mode in {0o400, 0o440}
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not safe_owner
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= max_bytes
    ):
        raise RuntimeSkillStartupServiceError("credential metadata is unsafe")
    _recheck(entries, directory_fd)
    raw = bytearray()
    while len(raw) <= max_bytes:
        chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) != metadata.st_size or len(raw) > max_bytes:
        raise RuntimeSkillStartupServiceError("credential size changed")
    _recheck(entries, directory_fd)
    return bytes(raw)


def _binding(raw: bytes) -> worker.RuntimeActionWorkerBinding:
    document = _parse_canonical_document(raw, "worker binding")
    if (
        set(document) != worker._BINDING_FIELDS
        or document["schema"] != worker._BINDING_SCHEMA
    ):
        raise RuntimeSkillStartupServiceError("worker binding schema is invalid")
    binding = worker.RuntimeActionWorkerBinding(
        runtime_digest=document["runtime_digest"],
        active_skill_digest=document["active_skill_digest"],
        policy_digest=document["policy_digest"],
        policy_version=document["policy_version"],
    )
    startup._binding_document(binding)
    return binding


def _run() -> dict[str, Any]:
    if sys.platform != "linux":
        raise RuntimeSkillStartupServiceError("Linux execution is required")
    worker_uid = worker._service_identities()[0]
    if type(worker_uid) is not int or worker_uid <= 0:
        raise RuntimeSkillStartupServiceError(
            "unprivileged worker identity is required"
        )
    entries: list[_Held] = []
    try:
        directory_fd = _open_directory(worker_uid, entries)
        binding = _binding(
            _read_credential(
                directory_fd, "worker-binding", worker_uid, entries, _MAX_BINDING_BYTES
            )
        )
        config = _parse_canonical_document(
            _read_credential(
                directory_fd,
                "openclaw-config",
                worker_uid,
                entries,
                startup._MAX_CONFIG_BYTES,
            ),
            "gateway configuration",
        )
        _recheck(entries, directory_fd)
        result = startup._verify_runtime_skill_startup(binding, config)
        _recheck(entries, directory_fd)
        return result
    finally:
        close_error = None
        for entry in reversed(entries):
            try:
                os.close(entry.fd)
            except OSError as exc:
                close_error = close_error or exc
        if close_error is not None:
            raise RuntimeSkillStartupServiceError(
                "credential cleanup failed"
            ) from close_error


def main(argv: Sequence[str] | None = None) -> int:
    """Run only the fixed pre-start check; never accept caller-selected paths."""
    if list(sys.argv[1:] if argv is None else argv):
        print("usage: aragorn-runtime-skill-startup", file=sys.stderr)
        return 64
    try:
        _run()
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 - one fail-closed service exit
        # Do not echo credentials, parser input, or successful snapshots to logs.
        print("aragorn runtime skill startup: verification failed", file=sys.stderr)
        return 126
    return 0
