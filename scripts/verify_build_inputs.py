#!/usr/bin/env python3
"""Verify the exact regular-file set copied into a baseline image build."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat


_CHUNK_BYTES = 1024 * 1024
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024


class VerificationError(ValueError):
    """The build input tree is unsupported or does not match its pin."""


def tree_digest(root: Path, includes: tuple[str, ...] = ()) -> str:
    """Hash sorted relative paths, lengths, and file bytes under ``root``."""

    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise VerificationError("build input root must be a directory")

    selected: list[Path] = []
    if includes:
        for value in includes:
            if not value or value.startswith("/") or "\\" in value:
                raise VerificationError(f"invalid include path: {value!r}")
            candidate = Path(value)
            if any(part in {"", ".", ".."} for part in candidate.parts):
                raise VerificationError(f"invalid include path: {value!r}")
            selected.append(resolved.joinpath(*candidate.parts))
    else:
        selected.append(resolved)

    all_paths: set[Path] = set()
    for selected_path in selected:
        metadata = selected_path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            all_paths.update(selected_path.rglob("*"))
        else:
            all_paths.add(selected_path)

    digest = hashlib.sha256()
    total = 0
    paths = sorted(all_paths, key=lambda path: path.relative_to(resolved).as_posix())
    for path in paths:
        relative = path.relative_to(resolved).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise VerificationError(f"unsupported build input: {relative}")
        if metadata.st_size > _MAX_FILE_BYTES:
            raise VerificationError(f"build input exceeds 64 MiB: {relative}")
        total += metadata.st_size
        if total > _MAX_TOTAL_BYTES:
            raise VerificationError("build input tree exceeds 256 MiB")

        file_digest = hashlib.sha256()
        size = 0
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            while chunk := os.read(descriptor, _CHUNK_BYTES):
                size += len(chunk)
                if size > _MAX_FILE_BYTES:
                    raise VerificationError(f"build input exceeds 64 MiB: {relative}")
                file_digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if size != after.st_size or before_identity != after_identity:
            raise VerificationError(f"build input changed while reading: {relative}")

        path_bytes = relative.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(stat.S_IMODE(after.st_mode).to_bytes(4, "big"))
        digest.update(size.to_bytes(8, "big"))
        digest.update(file_digest.digest())

    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("expected", help="lowercase SHA-256 without a prefix")
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        help="relative file or directory to include; repeat as needed",
    )
    arguments = parser.parse_args()
    if len(arguments.expected) != 64 or any(
        character not in "0123456789abcdef" for character in arguments.expected
    ):
        parser.error("expected digest must be 64 lowercase hexadecimal characters")
    actual = tree_digest(arguments.root, tuple(arguments.include))
    if actual != arguments.expected:
        raise VerificationError(
            f"build input digest mismatch: expected {arguments.expected}, got {actual}"
        )
    print(actual)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
