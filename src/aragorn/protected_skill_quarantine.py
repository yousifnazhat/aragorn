"""Persistent installed-skill digest denial records under the installer lock."""

from __future__ import annotations

import os
import re
import stat
from typing import Any

from .oci_worker_protocol import canonical_json
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    _exact,
    _file_identity,
    _parse_canonical_document,
    _uint,
    create_exclusive_file_at,
    require_owned_directory,
    write_all,
)

_PREFIX = ".aragorn-quarantined-skill-"
_SCHEMA = "aragorn/protected-skill-digest-denial/v1"
_AUTHORITY = "ROOT_RECORDED_DIGEST_DENIAL_ONLY_NOT_QUARANTINE_OR_PHASE3_QUALIFICATION"
_FIELDS = {"schema", "authority", "skill_digest", "revocation_snapshot_digest"}
_MAX_BYTES = 1024


class ProtectedSkillQuarantineError(ValueError):
    """A digest is denied or its protected denial state cannot be verified."""


def _digest(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ProtectedSkillQuarantineError("skill denial digest is not canonical")
    return value


def _name(skill_digest: str) -> str:
    return _PREFIX + _digest(skill_digest)[7:] + ".json"


def _root(root_fd: int, expected_uid: int, *, write: bool = False) -> None:
    if type(root_fd) is not int or root_fd < 0:
        raise ProtectedSkillQuarantineError("invalid protected install root fd")
    _uint(expected_uid, "protected install owner")
    require_owned_directory(
        root_fd,
        expected_uid=expected_uid,
        require_owner_write=write,
        label="skill denial root",
    )
    if write and os.geteuid() != expected_uid:
        raise ProtectedSkillQuarantineError("skill denial publisher is not root owner")


def _read(
    root_fd: int, skill_digest: str, expected_uid: int, *, sync: bool = False
) -> dict[str, Any] | None:
    name = _name(skill_digest)
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o444
            or not 0 < before.st_size <= _MAX_BYTES
        ):
            raise ProtectedSkillQuarantineError(
                "skill denial record metadata is unsafe"
            )
        raw = os.read(fd, _MAX_BYTES + 1)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            len(raw) != before.st_size
            or _file_identity(before) != _file_identity(after)
            or _file_identity(after) != _file_identity(named)
        ):
            raise ProtectedSkillQuarantineError(
                "skill denial record changed during read"
            )
        record = _exact(
            _parse_canonical_document(raw, "skill denial record"),
            _FIELDS,
            "skill denial record",
        )
        if (
            record["schema"] != _SCHEMA
            or record["authority"] != _AUTHORITY
            or record["skill_digest"] != skill_digest
        ):
            raise ProtectedSkillQuarantineError(
                "skill denial record identity is unbound"
            )
        _digest(record["revocation_snapshot_digest"])
        if sync:
            os.fsync(fd)
            os.fsync(root_fd)
        return record
    finally:
        os.close(fd)


def read_quarantine_at(
    root_fd: int, skill_digest: str, *, expected_uid: int
) -> dict[str, Any] | None:
    """Read under the caller-held install root SH/EX lock; absence means unbanned."""
    try:
        _root(root_fd, expected_uid)
        return _read(root_fd, skill_digest, expected_uid)
    except (OSError, RuntimeActionBrokerError, TypeError, ValueError) as exc:
        raise ProtectedSkillQuarantineError(
            f"cannot verify skill denial: {exc}"
        ) from exc


def require_not_quarantined_at(
    root_fd: int, skill_digest: str, *, expected_uid: int
) -> None:
    if read_quarantine_at(root_fd, skill_digest, expected_uid=expected_uid) is not None:
        raise ProtectedSkillQuarantineError("installed skill digest is quarantined")


def publish_quarantine_at(
    root_fd: int,
    skill_digest: str,
    revocation_snapshot_digest: str,
    *,
    expected_uid: int,
) -> dict[str, Any]:
    """Publish under caller-held root EX after accepted-revocation/lineage checks.

    This private state primitive is not a response or publication authority. The
    first record is permanent; there is no unquarantine or snapshot replacement.
    Any exception may follow publication: never infer rollback from failure.
    """
    temporary: str | None = None
    fd = -1
    try:
        _root(root_fd, expected_uid, write=True)
        name = _name(skill_digest)
        _digest(revocation_snapshot_digest)
        existing = _read(root_fd, skill_digest, expected_uid, sync=True)
        if existing is not None:
            return existing
        record = {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "skill_digest": skill_digest,
            "revocation_snapshot_digest": revocation_snapshot_digest,
        }
        raw = canonical_json(record)
        temporary, fd = create_exclusive_file_at(
            root_fd, prefix=".aragorn-skill-denial-staging-", mode=0o600
        )
        write_all(fd, raw)
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        staged = os.fstat(fd)
        named = os.stat(temporary, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(staged.st_mode)
            or staged.st_uid != expected_uid
            or staged.st_nlink != 1
            or stat.S_IMODE(staged.st_mode) != 0o444
            or staged.st_size != len(raw)
            or _file_identity(staged) != _file_identity(named)
        ):
            raise ProtectedSkillQuarantineError("skill denial staging changed")
        os.link(
            temporary,
            name,
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=root_fd)
        temporary = None
        retained = _read(root_fd, skill_digest, expected_uid, sync=True)
        if retained != record:
            raise ProtectedSkillQuarantineError("skill denial readback changed")
        return retained
    except (OSError, RuntimeActionBrokerError, TypeError, ValueError) as exc:
        raise ProtectedSkillQuarantineError(
            f"skill denial publication failed: {exc}"
        ) from exc
    finally:
        try:
            if fd >= 0:
                os.close(fd)
        finally:
            if temporary is not None:
                os.unlink(temporary, dir_fd=root_fd)
