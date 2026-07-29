"""Full-manifest verification of archived installed source trees."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

from .artifact_closure import ArtifactClosureError, load_verified_retained_manifest
from .cas import CAS, CASError

_DIRECTORY_MODE = 0o555
_EXECUTABLE_MODE = 0o555
_READ_ONLY_MODE = 0o444


class InstalledTreeVerificationError(ValueError):
    """An archived installed tree does not match its retained manifest."""


@dataclass(frozen=True, slots=True)
class ArchivedTreeMember:
    """One root-relative archived member and its retained metadata."""

    path: str
    kind: str
    mode: int
    size: int
    content: bytes | None = None


@dataclass(frozen=True, slots=True)
class InstalledTreeInventory:
    """Counts derived from an exactly verified installed tree."""

    tree_digest: str
    file_count: int
    directory_count: int
    payload_bytes: int


def verify_installed_tree_members(
    cas: CAS,
    manifest_digest: str,
    members: Iterable[ArchivedTreeMember],
) -> InstalledTreeInventory:
    """Verify one complete installed-tree inventory against retained bytes.

    Paths are relative to the installed version directory. The version root
    itself must be present as the directory member ``.``. Directory counts
    include that root.
    """

    try:
        manifest = load_verified_retained_manifest(cas, manifest_digest)
    except (ArtifactClosureError, CASError) as exc:
        raise InstalledTreeVerificationError(
            f"cannot verify retained source manifest: {exc}"
        ) from exc

    file_paths = {entry["path"] for entry in manifest["files"]}
    directory_paths: set[str] = set()
    for entry in manifest["files"]:
        parts = PurePosixPath(entry["path"]).parts
        for depth in range(1, len(parts)):
            directory_paths.add("/".join(parts[:depth]))
    if file_paths & directory_paths:
        raise InstalledTreeVerificationError(
            "retained source manifest has a file and directory path collision"
        )

    expected: dict[str, tuple[str, int, int, str | None]] = {
        ".": ("directory", _DIRECTORY_MODE, 0, None),
        **{
            path: (
                "directory",
                _DIRECTORY_MODE,
                0,
                None,
            )
            for path in directory_paths
        },
    }
    for entry in manifest["files"]:
        expected[entry["path"]] = (
            "file",
            _EXECUTABLE_MODE if entry["executable"] else _READ_ONLY_MODE,
            entry["size"],
            entry["digest"],
        )

    observed: dict[str, ArchivedTreeMember] = {}
    try:
        iterator = iter(members)
    except TypeError as exc:
        raise InstalledTreeVerificationError(
            "installed tree members must be iterable"
        ) from exc
    for member in iterator:
        if not isinstance(member, ArchivedTreeMember):
            raise InstalledTreeVerificationError(
                "installed tree member record is invalid"
            )
        path = _canonical_member_path(member.path)
        if path is None:
            raise InstalledTreeVerificationError("installed tree member path is unsafe")
        if path in observed:
            raise InstalledTreeVerificationError(
                f"installed tree repeats a member: {path}"
            )
        if not isinstance(member.kind, str) or member.kind not in {
            "file",
            "directory",
        }:
            raise InstalledTreeVerificationError(
                f"installed tree contains a link or special file: {path}"
            )
        if (
            isinstance(member.mode, bool)
            or not isinstance(member.mode, int)
            or member.mode < 0
            or member.mode & ~0o777
        ):
            raise InstalledTreeVerificationError(
                f"installed tree member mode is invalid: {path}"
            )
        if (
            isinstance(member.size, bool)
            or not isinstance(member.size, int)
            or member.size < 0
        ):
            raise InstalledTreeVerificationError(
                f"installed tree member size is invalid: {path}"
            )
        if member.kind == "file":
            if not isinstance(member.content, bytes):
                raise InstalledTreeVerificationError(
                    f"installed tree file content is unavailable: {path}"
                )
        elif member.content is not None:
            raise InstalledTreeVerificationError(
                f"installed tree directory has content: {path}"
            )
        observed[path] = member
        if len(observed) > len(expected):
            raise InstalledTreeVerificationError(
                "installed tree has an unexpected member"
            )

    if set(observed) != set(expected):
        raise InstalledTreeVerificationError(
            "installed tree has missing or unexpected members"
        )

    payload_bytes = 0
    for path, (kind, mode, size, digest) in expected.items():
        member = observed[path]
        if member.kind != kind:
            raise InstalledTreeVerificationError(
                f"installed tree member type changed: {path}"
            )
        if member.mode != mode:
            raise InstalledTreeVerificationError(
                f"installed tree member mode changed: {path}"
            )
        if member.size != size:
            raise InstalledTreeVerificationError(
                f"installed tree member size changed: {path}"
            )
        if kind == "directory":
            continue

        content = member.content
        if content is None or len(content) != size:
            raise InstalledTreeVerificationError(
                f"installed tree file size changed: {path}"
            )
        assert digest is not None
        try:
            retained = cas.read(digest, max_bytes=size)
        except CASError as exc:
            raise InstalledTreeVerificationError(
                f"cannot verify retained installed bytes: {path}: {exc}"
            ) from exc
        if content != retained:
            raise InstalledTreeVerificationError(
                f"installed tree file content changed: {path}"
            )
        payload_bytes += len(content)

    return InstalledTreeInventory(
        tree_digest=manifest["tree_digest"],
        file_count=sum(member.kind == "file" for member in observed.values()),
        directory_count=sum(member.kind == "directory" for member in observed.values()),
        payload_bytes=payload_bytes,
    )


def _canonical_member_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    if value == ".":
        return "."
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if unicodedata.normalize("NFC", value) != value or any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for character in value
    ):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    if any(
        part != part.strip() or len(part.encode("utf-8")) > 255 for part in path.parts
    ):
        return None
    normalized = path.as_posix()
    if normalized != value or len(encoded) > 4096:
        return None
    return normalized
