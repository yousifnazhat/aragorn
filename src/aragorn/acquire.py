"""Bounded inventory of an untrusted local skill directory."""

from __future__ import annotations

import hashlib
from io import BytesIO
import json
import os
import stat
from pathlib import Path
from typing import Any

from .cas import CAS


class InventoryError(ValueError):
    """The source tree cannot be inventoried safely or completely."""


def inventory_local(
    skill_root: str | os.PathLike[str],
    *,
    max_depth: int = 8,
    max_files: int = 10_000,
    max_file_size: int = 16 * 1024 * 1024,
    max_total_bytes: int = 128 * 1024 * 1024,
) -> dict[str, Any]:
    """Return a deterministic manifest for *skill_root* without following links.

    This inventories only; use :func:`ingest_local` when the reviewed bytes
    must also be written to the CAS without reopening paths.
    """

    return _inventory_local(
        skill_root,
        None,
        max_depth=max_depth,
        max_files=max_files,
        max_file_size=max_file_size,
        max_total_bytes=max_total_bytes,
    )


def ingest_local(
    skill_root: str | os.PathLike[str],
    cas: CAS,
    *,
    max_depth: int = 8,
    max_files: int = 10_000,
    max_file_size: int = 16 * 1024 * 1024,
    max_total_bytes: int = 128 * 1024 * 1024,
) -> dict[str, Any]:
    """Inventory *skill_root* and put those exact open-file bytes into *cas*."""

    return _inventory_local(
        skill_root,
        cas,
        max_depth=max_depth,
        max_files=max_files,
        max_file_size=max_file_size,
        max_total_bytes=max_total_bytes,
    )


def ingest_open_directory(
    skill_root: str | os.PathLike[str],
    directory_fd: int,
    cas: CAS,
    *,
    max_depth: int = 8,
    max_files: int = 10_000,
    max_file_size: int = 16 * 1024 * 1024,
    max_total_bytes: int = 128 * 1024 * 1024,
) -> dict[str, Any]:
    """Ingest from an already-open source directory capability."""

    return _inventory_local(
        skill_root,
        cas,
        supplied_directory_fd=directory_fd,
        max_depth=max_depth,
        max_files=max_files,
        max_file_size=max_file_size,
        max_total_bytes=max_total_bytes,
    )


def inventory_open_directory(
    directory_fd: int,
    *,
    max_depth: int = 8,
    max_files: int = 10_000,
    max_file_size: int = 16 * 1024 * 1024,
    max_total_bytes: int = 128 * 1024 * 1024,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Inventory an already-open directory and its exact directory layout."""

    directories: list[str] = []
    manifest = _inventory_local(
        "<open-directory>",
        None,
        supplied_directory_fd=directory_fd,
        max_depth=max_depth,
        max_files=max_files,
        max_file_size=max_file_size,
        max_total_bytes=max_total_bytes,
        observed_directories=directories,
    )
    return manifest, tuple(sorted(directories))


def _inventory_local(
    skill_root: str | os.PathLike[str],
    cas: CAS | None,
    *,
    max_depth: int,
    max_files: int,
    max_file_size: int,
    max_total_bytes: int,
    supplied_directory_fd: int | None = None,
    observed_directories: list[str] | None = None,
) -> dict[str, Any]:
    """Build a bounded manifest, optionally ingesting the bytes into *cas*.

    Files directly inside the root are at depth zero. ``max_files`` also
    bounds directory entries so an empty-directory tree cannot exhaust the
    inventory process. ``closure.complete`` describes only this local source
    tree; it makes no claim about artifacts referenced by its contents.
    """

    _check_limit("max_depth", max_depth, minimum=0)
    _check_limit("max_files", max_files, minimum=1)
    _check_limit("max_file_size", max_file_size, minimum=0)
    _check_limit("max_total_bytes", max_total_bytes, minimum=0)

    raw_root = os.fspath(skill_root)
    if not isinstance(raw_root, str):
        raise InventoryError("skill root must be a text path")
    if not raw_root:
        raise InventoryError("skill root must not be empty")
    if ".." in Path(raw_root).parts:
        raise InventoryError("skill root must not contain '..'")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise InventoryError("safe local inventory is unsupported on this platform")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
        file_flags |= os.O_CLOEXEC

    root = os.path.abspath(raw_root)
    if supplied_directory_fd is None:
        try:
            root_lstat = os.lstat(root)
        except OSError as exc:
            raise InventoryError(f"cannot inspect skill root: {exc}") from exc
        if stat.S_ISLNK(root_lstat.st_mode):
            raise InventoryError("skill root must not be a symlink")
        if not stat.S_ISDIR(root_lstat.st_mode):
            raise InventoryError("skill root must be a directory")
        try:
            root_fd = os.open(root, directory_flags)
        except OSError as exc:
            raise InventoryError(f"cannot open skill root safely: {exc}") from exc
    else:
        if isinstance(supplied_directory_fd, bool) or not isinstance(
            supplied_directory_fd, int
        ):
            raise InventoryError("source directory descriptor must be an integer")
        try:
            root_fd = os.dup(supplied_directory_fd)
            root_lstat = os.fstat(root_fd)
        except OSError as exc:
            raise InventoryError(f"cannot duplicate source directory: {exc}") from exc
        if not stat.S_ISDIR(root_lstat.st_mode):
            os.close(root_fd)
            raise InventoryError("source descriptor must refer to a directory")

    files: list[dict[str, object]] = []
    total_bytes = 0
    entries_seen = 0

    def walk(directory_fd: int, parts: tuple[str, ...]) -> None:
        nonlocal entries_seen, total_bytes

        try:
            directory_before = os.fstat(directory_fd)
            with os.scandir(directory_fd) as iterator:
                entries = []
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen > max_files:
                        raise InventoryError("maximum file count exceeded")
                    entries.append(entry)
                entries.sort(key=lambda entry: entry.name)
        except OSError as exc:
            raise InventoryError(f"cannot read source directory: {exc}") from exc

        for entry in entries:
            relative_parts = (*parts, entry.name)
            relative_path = "/".join(relative_parts)
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise InventoryError(f"cannot inspect {relative_path!r}: {exc}") from exc

            if stat.S_ISLNK(entry_stat.st_mode):
                raise InventoryError(f"symlink rejected: {relative_path}")
            if stat.S_ISDIR(entry_stat.st_mode):
                if observed_directories is not None:
                    observed_directories.append(relative_path)
                child_depth = len(relative_parts)
                if child_depth > max_depth:
                    raise InventoryError(f"maximum depth exceeded at {relative_path}")
                try:
                    child_fd = os.open(entry.name, directory_flags, dir_fd=directory_fd)
                except OSError as exc:
                    raise InventoryError(
                        f"cannot open directory {relative_path!r} safely: {exc}"
                    ) from exc
                try:
                    opened_stat = os.fstat(child_fd)
                    if not stat.S_ISDIR(opened_stat.st_mode) or not _same_object(
                        entry_stat, opened_stat
                    ):
                        raise InventoryError(f"directory changed during inventory: {relative_path}")
                    walk(child_fd, relative_parts)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                raise InventoryError(f"non-regular file rejected: {relative_path}")
            if entry_stat.st_nlink != 1:
                raise InventoryError(f"hardlink rejected: {relative_path}")
            if entry_stat.st_size > max_file_size:
                raise InventoryError(f"maximum file size exceeded: {relative_path}")
            if total_bytes + entry_stat.st_size > max_total_bytes:
                raise InventoryError("maximum total byte count exceeded")

            try:
                file_fd = os.open(entry.name, file_flags, dir_fd=directory_fd)
            except OSError as exc:
                raise InventoryError(f"cannot open {relative_path!r} safely: {exc}") from exc
            try:
                before = os.fstat(file_fd)
                if not stat.S_ISREG(before.st_mode) or not _same_object(entry_stat, before):
                    raise InventoryError(f"file changed during inventory: {relative_path}")
                if before.st_nlink != 1:
                    raise InventoryError(f"hardlink rejected: {relative_path}")

                digest = hashlib.sha256()
                size = 0
                # ponytail: memory is bounded by max_file_size (16 MiB by
                # default); use a streaming tee if larger files are required.
                content = bytearray() if cas is not None else None
                while chunk := os.read(file_fd, 1024 * 1024):
                    size += len(chunk)
                    if size > max_file_size:
                        raise InventoryError(f"maximum file size exceeded: {relative_path}")
                    if total_bytes + size > max_total_bytes:
                        raise InventoryError("maximum total byte count exceeded")
                    digest.update(chunk)
                    if content is not None:
                        content.extend(chunk)

                after = os.fstat(file_fd)
                if size != after.st_size or _changed_while_reading(before, after):
                    raise InventoryError(f"file changed during inventory: {relative_path}")

                file_digest = f"sha256:{digest.hexdigest()}"
                if content is not None:
                    stored_digest = cas.put(BytesIO(content), max_bytes=size)
                    if stored_digest != file_digest:
                        raise InventoryError(f"CAS digest mismatch: {relative_path}")
            finally:
                os.close(file_fd)

            total_bytes += size
            files.append(
                {
                    "path": relative_path,
                    "size": size,
                    "digest": file_digest,
                    "executable": bool(before.st_mode & 0o111),
                }
            )

        directory_after = os.fstat(directory_fd)
        if _changed_while_reading(directory_before, directory_after):
            relative_directory = "/".join(parts) or "."
            raise InventoryError(
                f"directory changed during inventory: {relative_directory}"
            )

    try:
        opened_root = os.fstat(root_fd)
        if not stat.S_ISDIR(opened_root.st_mode) or not _same_object(root_lstat, opened_root):
            raise InventoryError("skill root changed during inventory")
        walk(root_fd, ())
    finally:
        os.close(root_fd)

    files.sort(key=lambda item: str(item["path"]))
    canonical_tree = json.dumps(
        files, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    tree_digest = f"sha256:{hashlib.sha256(canonical_tree).hexdigest()}"

    return {
        "schema": "aragorn/manifest/v1",
        "source": {"kind": "local", "path": root},
        "tree_digest": tree_digest,
        "files": files,
        "closure": {"scope": "source_tree", "status": "complete"},
    }


def _check_limit(name: str, value: int, *, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise InventoryError(f"{name} must be an integer >= {minimum}")


def _same_object(first: os.stat_result, second: os.stat_result) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _changed_while_reading(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_size,
        first.st_nlink,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) != (
        second.st_dev,
        second.st_ino,
        second.st_mode,
        second.st_size,
        second.st_nlink,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )
