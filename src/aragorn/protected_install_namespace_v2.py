"""Read-only producer namespace adaptation for validated digest-denial records."""

from __future__ import annotations

import fcntl
import os
import re
from pathlib import Path

from .protected_skill_quarantine import read_quarantine_at
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    _file_identity,
    require_owned_directory,
)

_PREFIX = ".aragorn-quarantined-skill-"
_RECORD_NAME = re.compile(r"\.aragorn-quarantined-skill-([0-9a-f]{64})\.json")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class ProtectedInstallNamespaceError(ValueError):
    """The producer namespace or its protected denial records are unverifiable."""


def protected_root_entries(path: Path, expected_uid: int) -> list[str]:
    """Return sorted non-record entries after checking every denial record.

    Acquire an independent, nonblocking root SH lock for this inventory only.
    Callers must not hold install-root EX on another open-file description.
    The two supported producer entrypoints call this outside their transactions.
    Unknown entries remain visible to their existing exact-namespace checks.
    This read-only helper grants no publication or installation authority.
    """

    root_fd = -1
    locked = False
    try:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path.resolve(strict=True) != path
            or type(expected_uid) is not int
            or expected_uid < 0
        ):
            raise ProtectedInstallNamespaceError("protected root identity is invalid")
        named_before = path.lstat()
        root_fd = os.open(path, _DIRECTORY_FLAGS)
        before = require_owned_directory(
            root_fd,
            expected_uid=expected_uid,
            require_owner_write=True,
            label="producer protected root",
        )
        if _file_identity(before) != _file_identity(named_before):
            raise ProtectedInstallNamespaceError("protected root binding changed")
        fcntl.flock(root_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        locked = True
        locked_state = os.fstat(root_fd)
        if _file_identity(locked_state) != _file_identity(before):
            raise ProtectedInstallNamespaceError("protected root changed before lock")

        names = sorted(os.listdir(root_fd))
        entries = []
        for name in names:
            if not name.startswith(_PREFIX):
                entries.append(name)
                continue
            match = _RECORD_NAME.fullmatch(name)
            if match is None:
                raise ProtectedInstallNamespaceError("skill denial filename is invalid")
            record = read_quarantine_at(
                root_fd, "sha256:" + match[1], expected_uid=expected_uid
            )
            if record is None:
                raise ProtectedInstallNamespaceError("listed skill denial disappeared")

        if (
            sorted(os.listdir(root_fd)) != names
            or _file_identity(os.fstat(root_fd)) != _file_identity(locked_state)
            or _file_identity(path.lstat()) != _file_identity(locked_state)
            or path.resolve(strict=True) != path
        ):
            raise ProtectedInstallNamespaceError(
                "protected root changed during inventory"
            )
        return entries
    except (OSError, RuntimeActionBrokerError, TypeError, ValueError) as exc:
        raise ProtectedInstallNamespaceError(
            f"cannot verify producer namespace: {exc}"
        ) from exc
    finally:
        try:
            if locked:
                fcntl.flock(root_fd, fcntl.LOCK_UN)
        finally:
            if root_fd >= 0:
                os.close(root_fd)
