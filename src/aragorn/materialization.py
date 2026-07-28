"""Descriptor-bound verification of a materialized source-tree snapshot."""

from __future__ import annotations

import os
from pathlib import PurePosixPath
import re
import stat
from typing import Any

from .acquire import InventoryError, inventory_open_directory
from .artifact_closure import ArtifactClosureError, load_verified_retained_manifest
from .cas import CAS, CASError

_MAX_STAGING_DEPTH = 8
_STAGING_NAME = re.compile(r"\.aragorn-stage-[0-9a-f]{24}\Z")
_TARGET_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")


class MaterializationVerificationError(ValueError):
    """A staged source tree does not match its retained manifest."""


def verify_materialized_source_tree(
    cas: CAS,
    manifest_digest: str,
    staging_fd: int,
) -> str:
    """Verify one descriptor-bound snapshot without authorizing activation.

    The caller must keep the tree protected and the descriptor open through a
    later descriptor-relative atomic activation.
    """

    try:
        manifest = load_verified_retained_manifest(cas, manifest_digest)
        expected_files = [
            {key: entry[key] for key in ("path", "size", "digest", "executable")}
            for entry in manifest["files"]
        ]
        expected_directories: set[str] = set()
        max_depth = 0
        for entry in expected_files:
            parts = PurePosixPath(entry["path"]).parts
            max_depth = max(max_depth, len(parts) - 1)
            expected_directories.update(
                "/".join(parts[:depth]) for depth in range(1, len(parts))
            )
        if max_depth > _MAX_STAGING_DEPTH:
            raise MaterializationVerificationError(
                "retained source tree exceeds the supported depth"
            )
        observed, observed_directories = inventory_open_directory(
            staging_fd,
            max_depth=max_depth,
        )
    except (ArtifactClosureError, CASError, InventoryError) as exc:
        raise MaterializationVerificationError(
            f"cannot verify materialized source tree: {exc}"
        ) from exc

    if (
        observed["files"] != expected_files
        or observed["tree_digest"] != manifest["tree_digest"]
        or observed_directories != tuple(sorted(expected_directories))
    ):
        raise MaterializationVerificationError(
            "materialized source tree does not match retained bytes"
        )
    return manifest["tree_digest"]


def _publish_materialized_source_tree(
    cas: CAS,
    manifest_digest: str,
    root_fd: int,
    *,
    staging_name: str,
    target_name: str,
) -> str:
    """Publish a fresh verified sibling tree through one protected root fd.

    This is not an installer-authority verifier and is intentionally not wired
    to the CLI. A dedicated broker UID must validate an installer-authoritative
    receipt first and be the only writer using this local-filesystem root. The
    directory lock serializes cooperating broker processes; it does not protect
    against a malicious process running as the broker UID. Before rename, a
    failure leaves the staging tree in place for broker-owned quarantine and
    recovery.
    """

    if os.name != "posix":
        raise MaterializationVerificationError(
            "descriptor-relative publication is unsupported on this platform"
        )
    if isinstance(root_fd, bool) or not isinstance(root_fd, int) or root_fd < 0:
        raise MaterializationVerificationError("protected root fd is invalid")
    if (
        not isinstance(staging_name, str)
        or _STAGING_NAME.fullmatch(staging_name) is None
    ):
        raise MaterializationVerificationError("staging name is invalid")
    if not isinstance(target_name, str) or _TARGET_NAME.fullmatch(target_name) is None:
        raise MaterializationVerificationError("target name is invalid")
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - non-POSIX import guard
        raise MaterializationVerificationError(
            "descriptor-relative publication locking is unsupported"
        ) from exc

    broker_root_fd = -1
    staging_fd = -1
    locked = False
    published = False
    try:
        if not {os.open, os.rename, os.stat}.issubset(os.supports_dir_fd):
            raise MaterializationVerificationError(
                "descriptor-relative publication is unsupported"
            )
        broker_root_fd = os.dup(root_fd)
        os.set_inheritable(broker_root_fd, False)
        root_state = os.fstat(broker_root_fd)
        if (
            not stat.S_ISDIR(root_state.st_mode)
            or root_state.st_nlink < 1
            or root_state.st_uid != os.geteuid()
            or stat.S_IMODE(root_state.st_mode) & 0o022
        ):
            raise MaterializationVerificationError(
                "protected root must be broker-owned and not group or other writable"
            )

        fcntl.flock(broker_root_fd, fcntl.LOCK_EX)
        locked = True
        staging_fd = os.open(
            staging_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=broker_root_fd,
        )
        staging_state = os.fstat(staging_fd)
        named_staging_state = os.stat(
            staging_name,
            dir_fd=broker_root_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(staging_state.st_mode)
            or staging_state.st_nlink < 1
            or staging_state.st_uid != os.geteuid()
            or stat.S_IMODE(staging_state.st_mode) & 0o022
            or _inode(staging_state) != _inode(named_staging_state)
        ):
            raise MaterializationVerificationError(
                "staging tree must be broker-owned, protected, and descriptor-bound"
            )

        manifest = load_verified_retained_manifest(cas, manifest_digest)
        expected_tree_digest = verify_materialized_source_tree(
            cas,
            manifest_digest,
            staging_fd,
        )
        _freeze_materialized_source_tree(staging_fd, manifest)
        if (
            verify_materialized_source_tree(cas, manifest_digest, staging_fd)
            != expected_tree_digest
        ):
            raise MaterializationVerificationError(
                "frozen source tree changed during verification"
            )

        named_staging_state = os.stat(
            staging_name,
            dir_fd=broker_root_fd,
            follow_symlinks=False,
        )
        if _inode(staging_state) != _inode(named_staging_state):
            raise MaterializationVerificationError(
                "staging tree changed before publication"
            )
        try:
            os.stat(target_name, dir_fd=broker_root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MaterializationVerificationError("activation target already exists")

        os.rename(
            staging_name,
            target_name,
            src_dir_fd=broker_root_fd,
            dst_dir_fd=broker_root_fd,
        )
        published = True
        active_state = os.stat(
            target_name,
            dir_fd=broker_root_fd,
            follow_symlinks=False,
        )
        if _inode(active_state) != _inode(staging_state):
            raise MaterializationVerificationError(
                "published source tree identity is indeterminate"
            )
        os.fchmod(staging_fd, 0o555)
        os.fsync(staging_fd)
        os.fsync(broker_root_fd)
        return expected_tree_digest
    except MaterializationVerificationError:
        raise
    except (ArtifactClosureError, CASError, OSError, TypeError, ValueError) as exc:
        state = (
            "published source tree durability is indeterminate"
            if published
            else "cannot publish materialized source tree"
        )
        raise MaterializationVerificationError(f"{state}: {exc}") from exc
    finally:
        if locked:
            fcntl.flock(broker_root_fd, fcntl.LOCK_UN)
        if staging_fd >= 0:
            os.close(staging_fd)
        if broker_root_fd >= 0:
            os.close(broker_root_fd)


def _freeze_materialized_source_tree(
    staging_fd: int,
    manifest: dict[str, Any],
) -> None:
    file_flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    )
    directories: set[str] = set()
    for entry in manifest["files"]:
        parts = PurePosixPath(entry["path"]).parts
        directories.update("/".join(parts[:depth]) for depth in range(1, len(parts)))
        descriptor = os.open(entry["path"], file_flags, dir_fd=staging_fd)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise MaterializationVerificationError(
                    "staged source entry is not a singly linked regular file"
                )
            os.fchmod(descriptor, 0o555 if entry["executable"] else 0o444)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    for directory in sorted(
        directories,
        key=lambda item: (-len(PurePosixPath(item).parts), item),
    ):
        descriptor = os.open(directory, directory_flags, dir_fd=staging_fd)
        try:
            os.fchmod(descriptor, 0o555)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    os.fsync(staging_fd)


def _inode(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino
