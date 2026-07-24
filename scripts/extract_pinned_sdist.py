#!/usr/bin/env python3
"""Extract one already digest-verified source distribution with hard limits."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import tarfile


_MAX_MEMBERS = 512
_MAX_TOTAL_BYTES = 16 * 1024 * 1024


class ExtractionError(ValueError):
    """The source archive shape is unsafe or unexpected."""


def extract_sdist(archive: Path, destination: Path, expected_root: str) -> None:
    if (
        not expected_root
        or expected_root.startswith("/")
        or "\\" in expected_root
        or len(PurePosixPath(expected_root).parts) != 1
        or expected_root in {".", ".."}
    ):
        raise ExtractionError("expected root must be one relative path component")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    total = 0
    with tarfile.open(archive, mode="r:gz") as source:
        members = source.getmembers()
        if not members or len(members) > _MAX_MEMBERS:
            raise ExtractionError("source archive has an invalid member count")
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or any(part in {"", ".", ".."} for part in path.parts)
                or path.parts[0] != expected_root
            ):
                raise ExtractionError(f"source archive path escapes expected root: {member.name}")
            if not (member.isfile() or member.isdir()):
                raise ExtractionError(f"unsupported source archive member: {member.name}")
            if member.size < 0:
                raise ExtractionError(f"invalid source archive size: {member.name}")
            total += member.size
            if total > _MAX_TOTAL_BYTES:
                raise ExtractionError("source archive exceeds 16 MiB expanded")
        source.extractall(destination, members=members, filter="data")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("expected_root")
    arguments = parser.parse_args()
    extract_sdist(arguments.archive, arguments.destination, arguments.expected_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
