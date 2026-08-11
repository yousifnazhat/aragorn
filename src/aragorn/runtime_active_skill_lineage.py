"""Live binding from one runtime profile to the protected active skill."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .acquire import inventory_open_directory
from .oci_worker_protocol import canonical_digest
from .runtime_action_broker import (
    RuntimeActionBrokerError,
    _exact,
    _file_identity,
    _parse_canonical_document,
    _read_owned_bytes_at,
    _release_lock_and_close,
    _require_digest,
    _uint,
    require_owned_directory,
)
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)

ACTIVE_RUNTIME_RECORD = ".aragorn-active-runtime.json"
ACTIVE_RUNTIME_SCHEMA = "aragorn/protected-active-runtime/v1"
ACTIVE_RUNTIME_AUTHORITY = (
    "BROKER_ACTIVE_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
)
VERIFIED_LINEAGE_SCHEMA = "aragorn/verified-runtime-active-skill-lineage/v1"
VERIFIED_LINEAGE_AUTHORITY = (
    "SENSOR_LIVE_PROTECTED_TRANSACTION_BINDING_ONLY_NOT_INSTALLER_OR_"
    "SEMANTIC_CAUSATION_AUTHORITY"
)
DEFAULT_PROTECTED_INSTALL_ROOT = Path("/var/lib/aragorn-protected/skills")

_MAX_RECORD_BYTES = 4 * 1024
_MAX_SKILL_BYTES = 1024 * 1024
_MAX_SKILL_FILES = 64
_TARGET = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_RECORD_FIELDS = {"schema", "authority", "transaction"}
_TRANSACTION_FIELDS = {
    "schema",
    "authority",
    "context_digest",
    "context_id",
    "operation",
    "expected_active",
    "manifest_digest",
    "tree_digest",
    "destination",
    "version_path",
}
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def parse_active_runtime_record(raw: bytes) -> dict[str, Any]:
    """Validate one canonical record published by the protected installer."""

    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_RECORD_BYTES:
        raise RuntimeActionBrokerError("protected active-runtime record is invalid")
    record = _exact(
        _parse_canonical_document(raw, "protected active-runtime record"),
        _RECORD_FIELDS,
        "protected active-runtime record",
    )
    if (
        record["schema"] != ACTIVE_RUNTIME_SCHEMA
        or record["authority"] != ACTIVE_RUNTIME_AUTHORITY
    ):
        raise RuntimeActionBrokerError(
            "protected active-runtime record identity is invalid"
        )
    record["transaction"] = _transaction(record["transaction"])
    return record


def verify_runtime_active_skill_lineage(
    pid: int,
    attribution: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    protected_root: Path = DEFAULT_PROTECTED_INSTALL_ROOT,
    expected_install_uid: int = 0,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Remeasure one live active record and release its shared install lock."""

    with hold_runtime_active_skill_lineage(
        pid,
        attribution,
        grant,
        protected_root=protected_root,
        expected_install_uid=expected_install_uid,
        deadline=deadline,
    ) as lineage:
        return lineage


@contextmanager
def hold_runtime_active_skill_lineage(
    pid: int,
    attribution: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    protected_root: Path = DEFAULT_PROTECTED_INSTALL_ROOT,
    expected_install_uid: int = 0,
    deadline: float | None = None,
) -> Iterator[dict[str, Any]]:
    """Hold the installer's root lock while a verified action completes."""

    descriptors: list[int] = []
    root_fd = -1
    locked = False
    try:
        result, descriptors = _open_verified_lineage(
            pid,
            attribution,
            grant,
            protected_root=protected_root,
            expected_install_uid=expected_install_uid,
            deadline=deadline,
        )
        root_fd = descriptors[-1]
        locked = True
    except RuntimeActionObservationPublisherError:
        raise
    except (OSError, RuntimeActionBrokerError, TypeError, ValueError) as exc:
        raise RuntimeActionObservationPublisherError(
            f"runtime active-skill lineage cannot be verified: {exc}"
        ) from exc
    try:
        yield result
    finally:
        cleanup_error = _release_lock_and_close(
            root_fd,
            locked,
            *descriptors[:-1],
        )
        if cleanup_error is not None:
            raise RuntimeActionObservationPublisherError(
                "runtime active-skill lineage cleanup failed"
            ) from cleanup_error


def _open_verified_lineage(
    pid: int,
    attribution: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    protected_root: Path,
    expected_install_uid: int,
    deadline: float | None,
) -> tuple[dict[str, Any], list[int]]:
    descriptors: list[int] = []
    locked = False
    try:
        if (
            isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
            or attribution.get("pid") != pid
            or isinstance(expected_install_uid, bool)
            or not isinstance(expected_install_uid, int)
            or expected_install_uid < 0
        ):
            raise RuntimeActionBrokerError("runtime lineage identity is invalid")
        if (
            not isinstance(protected_root, Path)
            or not protected_root.is_absolute()
            or protected_root == Path(protected_root.anchor)
        ):
            raise RuntimeActionBrokerError("protected install root is invalid")
        active_skill_digest = _require_digest(
            attribution.get("active_skill_digest"),
            "runtime attribution active skill",
        )
        if active_skill_digest != _require_digest(
            grant.get("active_skill_digest"),
            "runtime grant active skill",
        ):
            raise RuntimeActionBrokerError("runtime active-skill grant is unbound")

        root_fd = _open_protected_root(protected_root, expected_install_uid)
        descriptors.append(root_fd)
        root_before = os.fstat(root_fd)
        _acquire_shared_lock(root_fd, deadline)
        locked = True
        root_state = require_owned_directory(
            root_fd,
            expected_uid=expected_install_uid,
            require_owner_write=True,
            label="runtime protected-install root",
        )
        if _file_identity(root_before) != _file_identity(root_state):
            raise RuntimeActionBrokerError(
                "runtime protected-install root changed before lock"
            )

        record_raw = _read_owned_bytes_at(
            root_fd,
            ACTIVE_RUNTIME_RECORD,
            max_bytes=_MAX_RECORD_BYTES,
            expected_uid=expected_install_uid,
            exact_mode=0o444,
            label="protected active-runtime record",
        )
        record = parse_active_runtime_record(record_raw)
        transaction = record["transaction"]
        destination = transaction["destination"]
        if (
            destination["root_device"] != root_state.st_dev
            or destination["root_inode"] != root_state.st_ino
            or transaction["context_digest"]
            != _require_digest(
                grant.get("install_context_digest"),
                "runtime grant install context",
            )
            or transaction["manifest_digest"]
            != _require_digest(
                grant.get("source_manifest_digest"),
                "runtime grant source manifest",
            )
        ):
            raise RuntimeActionBrokerError(
                "runtime protected-install transaction is unbound"
            )

        target_name = destination["target_name"]
        version_names = _version_names(transaction, target_name)
        active_before = _active_link(
            root_fd,
            target_name,
            transaction["version_path"],
            expected_install_uid,
        )
        versions_fd = _open_directory_at(
            root_fd,
            ".aragorn-versions",
            expected_install_uid,
            0o755,
            "protected install versions",
        )
        descriptors.insert(0, versions_fd)
        target_fd = _open_directory_at(
            versions_fd,
            target_name,
            expected_install_uid,
            0o755,
            "protected install target versions",
        )
        descriptors.insert(0, target_fd)
        version_fd = _open_directory_at(
            target_fd,
            version_names,
            expected_install_uid,
            0o555,
            "protected immutable skill version",
        )
        descriptors.insert(0, version_fd)
        # ponytail: flat, bounded skill trees; increase depth only after a
        # nested runtime profile is qualified.
        observed_tree, _ = inventory_open_directory(
            version_fd,
            max_depth=0,
            max_files=_MAX_SKILL_FILES,
            max_file_size=_MAX_SKILL_BYTES,
            max_total_bytes=_MAX_SKILL_BYTES,
        )
        for entry in observed_tree["files"]:
            metadata = os.stat(
                entry["path"],
                dir_fd=version_fd,
                follow_symlinks=False,
            )
            expected_mode = 0o555 if entry["executable"] else 0o444
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != expected_install_uid
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != expected_mode
                or metadata.st_size != entry["size"]
            ):
                raise RuntimeActionBrokerError(
                    "runtime active-skill tree metadata is unsafe"
                )

        skill_before = os.stat("SKILL.md", dir_fd=version_fd, follow_symlinks=False)
        skill_raw = _read_owned_bytes_at(
            version_fd,
            "SKILL.md",
            max_bytes=_MAX_SKILL_BYTES,
            expected_uid=expected_install_uid,
            exact_mode=0o444,
            label="runtime protected-install skill",
        )
        skill_after = os.stat("SKILL.md", dir_fd=version_fd, follow_symlinks=False)
        if not skill_raw or _file_identity(skill_before) != _file_identity(skill_after):
            raise RuntimeActionBrokerError(
                "runtime protected-install skill changed while measured"
            )
        observed_digest = "sha256:" + hashlib.sha256(skill_raw).hexdigest()
        observed_skill = {
            "path": "SKILL.md",
            "size": len(skill_raw),
            "digest": observed_digest,
            "executable": False,
        }
        if (
            observed_digest != active_skill_digest
            or observed_skill not in observed_tree["files"]
            or observed_tree["tree_digest"] != transaction["tree_digest"]
        ):
            raise RuntimeActionBrokerError(
                "runtime active-skill installed bytes are unbound"
            )

        version_state = os.fstat(version_fd)
        active_after = _active_link(
            root_fd,
            target_name,
            transaction["version_path"],
            expected_install_uid,
        )
        if _file_identity(active_before) != _file_identity(
            active_after
        ) or _file_identity(root_state) != _file_identity(os.fstat(root_fd)):
            raise RuntimeActionBrokerError(
                "runtime active-skill lineage changed while measured"
            )
        return (
            {
                "schema": VERIFIED_LINEAGE_SCHEMA,
                "authority": VERIFIED_LINEAGE_AUTHORITY,
                "active_record_digest": canonical_digest(record),
                "context_digest": transaction["context_digest"],
                "manifest_digest": transaction["manifest_digest"],
                "tree_digest": transaction["tree_digest"],
                "version_path": transaction["version_path"],
                "target_name": target_name,
                "root_device": root_state.st_dev,
                "root_inode": root_state.st_ino,
                "active_link_device": active_after.st_dev,
                "active_link_inode": active_after.st_ino,
                "version_device": version_state.st_dev,
                "version_inode": version_state.st_ino,
                "skill_device": skill_after.st_dev,
                "skill_inode": skill_after.st_ino,
                "runtime_skill_path": attribution.get("skill_path"),
                "active_skill_digest": active_skill_digest,
            },
            descriptors,
        )
    except BaseException:
        root_fd = descriptors[-1] if descriptors else -1
        cleanup_error = _release_lock_and_close(
            root_fd,
            locked,
            *descriptors[:-1],
        )
        if cleanup_error is not None:
            raise RuntimeActionObservationPublisherError(
                "runtime active-skill lineage cleanup failed"
            ) from cleanup_error
        raise


def _transaction(value: object) -> dict[str, Any]:
    transaction = _exact(value, _TRANSACTION_FIELDS, "protected install transaction")
    expected_active = transaction.get("expected_active")
    if (
        transaction["schema"] != "aragorn/protected-install-transaction/v1"
        or transaction["authority"]
        != "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        or transaction["operation"] not in {"install", "update", "rollback"}
        or (transaction["operation"] == "install") != (expected_active is None)
    ):
        raise RuntimeActionBrokerError("protected install transaction is invalid")
    for field in ("context_digest", "context_id", "manifest_digest", "tree_digest"):
        _require_digest(transaction[field], f"protected install transaction {field}")
    if expected_active is not None:
        active = _exact(
            expected_active,
            {"context_id", "manifest_digest"},
            "protected install predecessor",
        )
        _require_digest(active["context_id"], "protected install predecessor context")
        _require_digest(
            active["manifest_digest"], "protected install predecessor manifest"
        )
    destination = _exact(
        transaction["destination"],
        {"root_device", "root_inode", "target_name"},
        "protected install destination",
    )
    _uint(destination["root_device"], "protected install root device")
    if _uint(destination["root_inode"], "protected install root inode") == 0:
        raise RuntimeActionBrokerError("protected install root inode is invalid")
    if (
        not isinstance(destination["target_name"], str)
        or _TARGET.fullmatch(destination["target_name"]) is None
        or not isinstance(transaction["version_path"], str)
    ):
        raise RuntimeActionBrokerError("protected install path is invalid")
    return transaction


def _version_names(transaction: Mapping[str, Any], target_name: str) -> str:
    version_name = (
        f"{transaction['context_id'][7:]}-{transaction['manifest_digest'][7:]}"
    )
    expected = f".aragorn-versions/{target_name}/{version_name}"
    if transaction["version_path"] != expected:
        raise RuntimeActionBrokerError("protected install version path is invalid")
    return version_name


def _open_protected_root(path: Path, expected_uid: int) -> int:
    if path.resolve(strict=True) != path:
        raise RuntimeActionBrokerError("protected install root path is not canonical")
    _require_safe_ancestry(path.parent, expected_uid)
    before = os.lstat(path)
    descriptor = os.open(path, _DIRECTORY_FLAGS)
    try:
        after = require_owned_directory(
            descriptor,
            expected_uid=expected_uid,
            require_owner_write=True,
            label="runtime protected-install root",
        )
        if _file_identity(before) != _file_identity(after):
            raise RuntimeActionBrokerError("protected install root identity changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_directory_at(
    parent_fd: int,
    name: str,
    expected_uid: int,
    exact_mode: int,
    label: str,
) -> int:
    descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    try:
        metadata = require_owned_directory(
            descriptor,
            expected_uid=expected_uid,
            require_owner_write=False,
            label=label,
        )
        if stat.S_IMODE(metadata.st_mode) != exact_mode:
            raise RuntimeActionBrokerError(f"{label} mode is unsafe")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _active_link(
    root_fd: int,
    target_name: str,
    expected_version_path: str,
    expected_uid: int,
) -> os.stat_result:
    metadata = os.stat(target_name, dir_fd=root_fd, follow_symlinks=False)
    if (
        not stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_nlink != 1
        or os.readlink(target_name, dir_fd=root_fd) != expected_version_path
    ):
        raise RuntimeActionBrokerError(
            "runtime active link does not match the protected transaction"
        )
    return metadata


def _require_safe_ancestry(path: Path, expected_uid: int) -> None:
    current = path
    while True:
        metadata = os.lstat(current)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in {0, expected_uid}
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise RuntimeActionBrokerError("protected install ancestry is unsafe")
        if current == Path(current.anchor):
            return
        current = current.parent


def _acquire_shared_lock(descriptor: int, deadline: float | None) -> None:
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if deadline is None:
                raise RuntimeActionBrokerError("protected install root is busy")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeActionBrokerError("protected install root lock timed out")
            time.sleep(min(0.01, remaining))
