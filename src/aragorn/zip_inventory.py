"""Bounded, non-executing inventory of retained ZIP-family archives."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import unicodedata
import zipfile
import zlib
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any

from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json


SCHEMA = "aragorn/zip-archive-inventory/v1"
PROFILE = "bounded-zip-members/v1"
AUTHORITY = "ARCHIVE_INVENTORY_ONLY_NOT_INSTALLER_AUTHORITY"

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_COMPONENT_BYTES = 255
MAX_PATH_DEPTH = 32
MAX_COMPRESSION_RATIO = 100
MAX_SHEBANG_BYTES = 255
MAX_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_NESTED_ARCHIVES = 0

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ZIP_MAGIC = b"PK\x03\x04"
_SUPPORTED_SUFFIXES = {
    ".pyz": "zipapp",
    ".whl": "wheel",
    ".zip": "zip",
}
_ALLOWED_METHODS = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflate",
}
_ALLOWED_COMMON_FLAGS = (1 << 3) | (1 << 11)
_ALLOWED_DEFLATE_FLAGS = (1 << 1) | (1 << 2)


class ZipInventoryError(ValueError):
    """A retained ZIP cannot be inventoried under the bounded profile."""


def retain_zip_inventory(
    cas: CAS,
    archive_digest: str,
    *,
    archive_name: str,
) -> str:
    """Extract regular members into *cas* and retain their canonical inventory."""

    if cas.read_only:
        raise ZipInventoryError("cannot retain ZIP inventory in a read-only CAS")
    try:
        document = _derive_inventory(
            cas,
            _digest(archive_digest, "archive digest"),
            _archive_name(archive_name),
            retain_members=True,
        )
        raw = canonical_json(document)
        if len(raw) > MAX_INVENTORY_BYTES:
            raise ZipInventoryError("ZIP inventory exceeds its byte limit")
        return cas.put(BytesIO(raw), max_bytes=len(raw))
    except ZipInventoryError:
        raise
    except (
        CASError,
        EOFError,
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        raise ZipInventoryError(f"cannot retain ZIP inventory: {exc}") from exc


def verify_zip_inventory(
    cas: CAS,
    inventory_digest: str,
    *,
    expected_archive_digest: str,
    expected_archive_name: str,
) -> dict[str, Any]:
    """Re-derive a retained inventory and verify every extracted member blob."""

    try:
        raw = cas.read(
            _digest(inventory_digest, "inventory digest"),
            max_bytes=MAX_INVENTORY_BYTES,
        )
        document = _canonical_document(raw)
        expected = _derive_inventory(
            cas,
            _digest(expected_archive_digest, "expected archive digest"),
            _archive_name(expected_archive_name),
            retain_members=False,
        )
        if raw != canonical_json(expected):
            raise ZipInventoryError(
                "retained ZIP inventory does not match the archive bytes"
            )
        return document
    except ZipInventoryError:
        raise
    except (
        CASError,
        EOFError,
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        raise ZipInventoryError(f"cannot verify ZIP inventory: {exc}") from exc


def _derive_inventory(
    cas: CAS,
    archive_digest: str,
    archive_name: str,
    *,
    retain_members: bool,
) -> dict[str, Any]:
    raw = cas.read(archive_digest, max_bytes=MAX_ARCHIVE_BYTES)
    payload_offset, prefix = _zip_payload(raw)
    archive_kind = _SUPPORTED_SUFFIXES.get(
        PurePosixPath(archive_name).suffix.casefold(),
        "zip",
    )

    with zipfile.ZipFile(BytesIO(raw), mode="r") as archive:
        infos = archive.infolist()
        if not 1 <= len(infos) <= MAX_ENTRIES:
            raise ZipInventoryError("ZIP entry count is outside its bounded range")
        if min(info.header_offset for info in infos) != payload_offset:
            raise ZipInventoryError("ZIP payload has an unsupported leading prefix")

        entries: list[tuple[str, bool, zipfile.ZipInfo]] = []
        kinds: dict[str, str] = {}
        folded_kinds: dict[str, str] = {}
        compressed_total = 0
        expanded_total = 0
        for info in infos:
            path, is_directory = _member_path(info)
            kind = "directory" if is_directory else "file"
            folded = path.casefold()
            if path in kinds:
                raise ZipInventoryError(f"duplicate ZIP member path: {path}")
            if folded in folded_kinds:
                raise ZipInventoryError(
                    f"case-insensitive ZIP member path collision: {path}"
                )
            kinds[path] = kind
            folded_kinds[folded] = kind
            _member_metadata(info, is_directory=is_directory)
            compressed_total += info.compress_size
            expanded_total += info.file_size
            if compressed_total > len(raw):
                raise ZipInventoryError(
                    "ZIP member compressed sizes exceed the archive size"
                )
            if expanded_total > MAX_EXPANDED_BYTES:
                raise ZipInventoryError("ZIP expanded bytes exceed their limit")
            entries.append((path, is_directory, info))

        _reject_path_prefix_conflicts(kinds)
        _reject_path_prefix_conflicts(folded_kinds)
        if not any(not is_directory for _path, is_directory, _info in entries):
            raise ZipInventoryError("ZIP archive contains no regular files")
        if expanded_total > max(1, compressed_total) * MAX_COMPRESSION_RATIO:
            raise ZipInventoryError("ZIP aggregate compression ratio exceeds its limit")

        directories: list[str] = []
        files: list[dict[str, Any]] = []
        for path, is_directory, info in sorted(entries, key=lambda item: item[0]):
            try:
                with archive.open(info, mode="r") as member:
                    content = member.read(MAX_MEMBER_BYTES + 1)
                    if member.read(1):
                        raise ZipInventoryError(f"ZIP member exceeds its size: {path}")
            except (NotImplementedError, RuntimeError) as exc:
                raise ZipInventoryError(f"cannot read ZIP member {path}: {exc}") from exc
            if len(content) != info.file_size:
                raise ZipInventoryError(f"ZIP member size changed: {path}")
            if zlib.crc32(content) & 0xFFFFFFFF != info.CRC:
                raise ZipInventoryError(f"ZIP member CRC changed: {path}")
            if is_directory:
                if content:
                    raise ZipInventoryError(f"ZIP directory contains bytes: {path}")
                directories.append(path)
                continue
            if _is_nested_archive(path, content):
                raise ZipInventoryError(
                    f"nested ZIP archives exceed the supported depth: {path}"
                )
            digest = _sha256(content)
            if retain_members:
                cas.put_expected(
                    BytesIO(content),
                    expected_digest=digest,
                    max_bytes=len(content),
                )
            else:
                retained = cas.read(digest, max_bytes=len(content))
                if retained != content:
                    raise ZipInventoryError(
                        f"retained ZIP member bytes changed: {path}"
                    )
            files.append(
                {
                    "path": path,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "digest": digest,
                    "crc32": f"{info.CRC:08x}",
                    "compression_method": _ALLOWED_METHODS[info.compress_type],
                }
            )

    return {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "profile": PROFILE,
        "archive": {
            "name": archive_name,
            "kind": archive_kind,
            "digest": archive_digest,
            "size": len(raw),
            "payload_offset": payload_offset,
            "prefix": prefix,
        },
        "limits": {
            "max_archive_bytes": MAX_ARCHIVE_BYTES,
            "max_entries": MAX_ENTRIES,
            "max_member_bytes": MAX_MEMBER_BYTES,
            "max_expanded_bytes": MAX_EXPANDED_BYTES,
            "max_path_bytes": MAX_PATH_BYTES,
            "max_component_bytes": MAX_COMPONENT_BYTES,
            "max_path_depth": MAX_PATH_DEPTH,
            "max_compression_ratio": MAX_COMPRESSION_RATIO,
            "max_nested_archives": MAX_NESTED_ARCHIVES,
            "allowed_compression_methods": sorted(_ALLOWED_METHODS),
        },
        "totals": {
            "entries": len(entries),
            "directories": len(directories),
            "files": len(files),
            "compressed_bytes": compressed_total,
            "expanded_bytes": expanded_total,
        },
        "directories": directories,
        "files": files,
        "closure": {"scope": "zip_archive_members", "status": "complete"},
    }


def _zip_payload(raw: bytes) -> tuple[int, str]:
    if raw.startswith(_ZIP_MAGIC):
        return 0, "none"
    if not raw.startswith(b"#!"):
        raise ZipInventoryError("ZIP local-header magic is missing")
    newline = raw.find(b"\n", 0, MAX_SHEBANG_BYTES + 1)
    if newline < 0:
        raise ZipInventoryError("ZIP app shebang exceeds its byte limit")
    shebang = raw[: newline + 1]
    body = shebang[:-1].removesuffix(b"\r")
    if (
        not body.startswith(b"#!")
        or any(byte != 0x09 and not 0x20 <= byte <= 0x7E for byte in body)
        or raw[newline + 1 : newline + 5] != _ZIP_MAGIC
    ):
        raise ZipInventoryError("ZIP app shebang or local-header magic is invalid")
    return newline + 1, "python_shebang"


def _member_path(info: zipfile.ZipInfo) -> tuple[str, bool]:
    name = info.filename
    if (
        not isinstance(name, str)
        or info.orig_filename != name
        or not name
        or "\\" in name
        or name.startswith("/")
        or "//" in name
        or unicodedata.normalize("NFC", name) != name
        or any(unicodedata.category(character).startswith("C") for character in name)
    ):
        raise ZipInventoryError("ZIP member path is not canonical")
    is_directory = info.is_dir()
    path = name[:-1] if is_directory else name
    if not path or path.endswith("/") or path.startswith("./"):
        raise ZipInventoryError("ZIP member path is not canonical")
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ZipInventoryError("ZIP member path is not UTF-8") from exc
    parts = path.split("/")
    if (
        len(path_bytes) > MAX_PATH_BYTES
        or len(parts) > MAX_PATH_DEPTH
        or any(
            not component
            or component in {".", ".."}
            or len(component.encode("utf-8")) > MAX_COMPONENT_BYTES
            for component in parts
        )
        or (len(parts[0]) >= 2 and parts[0][0].isalpha() and parts[0][1] == ":")
    ):
        raise ZipInventoryError(f"ZIP member path exceeds its bounds: {path}")
    return path, is_directory


def _member_metadata(info: zipfile.ZipInfo, *, is_directory: bool) -> None:
    if (
        isinstance(info.file_size, bool)
        or not 0 <= info.file_size <= MAX_MEMBER_BYTES
        or isinstance(info.compress_size, bool)
        or info.compress_size < 0
        or not 0 <= info.CRC <= 0xFFFFFFFF
        or info.header_offset < 0
        or getattr(info, "volume", 0) != 0
    ):
        raise ZipInventoryError(f"ZIP member metadata is invalid: {info.filename}")
    if info.flag_bits & 1:
        raise ZipInventoryError(f"encrypted ZIP member is unsupported: {info.filename}")
    allowed_flags = _ALLOWED_COMMON_FLAGS
    if info.compress_type == zipfile.ZIP_DEFLATED:
        allowed_flags |= _ALLOWED_DEFLATE_FLAGS
    if info.flag_bits & ~allowed_flags:
        raise ZipInventoryError(f"ZIP member flags are unsupported: {info.filename}")
    if info.compress_type not in _ALLOWED_METHODS:
        raise ZipInventoryError(
            f"ZIP compression method is unsupported: {info.filename}"
        )
    if (
        info.file_size > 0
        and (
            info.compress_size == 0
            or info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
        )
    ):
        raise ZipInventoryError(
            f"ZIP member compression ratio exceeds its limit: {info.filename}"
        )
    mode_type = (
        stat.S_IFMT((info.external_attr >> 16) & 0xFFFF)
        if info.create_system == 3
        else 0
    )
    if is_directory:
        if info.file_size != 0 or mode_type not in {0, stat.S_IFDIR}:
            raise ZipInventoryError(f"ZIP directory metadata is invalid: {info.filename}")
    elif mode_type not in {0, stat.S_IFREG}:
        raise ZipInventoryError(
            f"ZIP links and special members are unsupported: {info.filename}"
        )


def _reject_path_prefix_conflicts(kinds: dict[str, str]) -> None:
    for path in kinds:
        parts = path.split("/")
        for end in range(1, len(parts)):
            if kinds.get("/".join(parts[:end])) == "file":
                raise ZipInventoryError(
                    f"ZIP file path is also a directory prefix: {path}"
                )


def _is_nested_archive(path: str, content: bytes) -> bool:
    if PurePosixPath(path).suffix.casefold() in _SUPPORTED_SUFFIXES:
        return True
    try:
        _zip_payload(content)
    except ZipInventoryError:
        return False
    return True


def _archive_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "/" in value
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise ZipInventoryError("archive name is invalid")
    try:
        if len(value.encode("utf-8")) > MAX_COMPONENT_BYTES:
            raise ZipInventoryError("archive name exceeds its byte limit")
    except UnicodeEncodeError as exc:
        raise ZipInventoryError("archive name is not UTF-8") from exc
    return value


def _canonical_document(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ZipInventoryError(f"ZIP inventory JSON is invalid: {exc}") from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise ZipInventoryError("ZIP inventory must be a canonical JSON object")
    return document


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ZipInventoryError(f"{label} is invalid")
    return value


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
