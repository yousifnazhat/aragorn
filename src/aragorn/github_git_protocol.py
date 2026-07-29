"""Strict, transport-independent Git protocol parsing for GitHub acquisition."""

from __future__ import annotations

import hashlib
import re
import struct
import unicodedata
import zlib
from dataclasses import dataclass

_OID = re.compile(r"[0-9a-f]{40}\Z")
_CAPABILITY_KEY = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_FETCH_FEATURE = re.compile(r"[a-z0-9][a-z0-9-]*(?:=[!-~]+)?\Z")
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
_MAX_ADVERTISEMENT_BYTES = 256 * 1024
_MAX_CAPABILITY_LINE_BYTES = 4096
_MAX_FETCH_WIRE_OVERHEAD = 1024 * 1024
_MAX_PKT_LINE_BYTES = 65_520
_MAX_PKT_DATA_BYTES = _MAX_PKT_LINE_BYTES - 4
_MAX_PKT_LINES = 16_384
_MAX_TREE_BYTES = 8 * 1024 * 1024
_MAX_TREE_ENTRIES = 100_000
_PACK_HEADER_BYTES = 12
_PACK_CHECKSUM_BYTES = 20
_PACK_TYPE_CODES = {"commit": 1, "tree": 2}
_FLUSH = "flush"
_DELIMITER = "delimiter"
_RESPONSE_END = "response_end"
_DATA = "data"


class GitProtocolError(ValueError):
    """Git protocol bytes were unsupported, ambiguous, or internally invalid."""


@dataclass(frozen=True)
class GitCapabilities:
    """Validated protocol-v2 capabilities needed to build one fetch request."""

    lines: frozenset[str]
    fetch_features: frozenset[str]
    object_format: str


@dataclass(frozen=True)
class _Packet:
    kind: str
    data: bytes = b""


def parse_capabilities(raw: bytes) -> GitCapabilities:
    """Parse one bounded smart-HTTP protocol-v2 capability advertisement."""

    if type(raw) is not bytes:
        raise GitProtocolError("Git capability advertisement must be bytes")
    if not raw or len(raw) > _MAX_ADVERTISEMENT_BYTES:
        raise GitProtocolError("Git capability advertisement exceeds its byte limit")

    packets = _parse_pkt_lines(raw, "Git capability advertisement")
    index = 0
    if (
        len(packets) >= 2
        and packets[0] == _Packet(_DATA, b"# service=git-upload-pack\n")
        and packets[1].kind == _FLUSH
    ):
        index = 2
    elif (
        packets
        and packets[0].kind == _DATA
        and packets[0].data.startswith(b"# service=")
    ):
        raise GitProtocolError("Git capability advertisement has the wrong service")

    if index >= len(packets) or packets[index] != _Packet(_DATA, b"version 2\n"):
        raise GitProtocolError("Git server did not advertise protocol version 2")
    index += 1

    lines: list[str] = []
    values_by_key: dict[str, str | None] = {}
    while index < len(packets) and packets[index].kind == _DATA:
        data = packets[index].data
        index += 1
        if (
            not data.endswith(b"\n")
            or len(data) > _MAX_CAPABILITY_LINE_BYTES
            or b"\x00" in data
        ):
            raise GitProtocolError("Git capability line is not canonical")
        try:
            line = data[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise GitProtocolError("Git capability line is not ASCII") from exc
        key, separator, value = line.partition("=")
        if _CAPABILITY_KEY.fullmatch(key) is None or not line:
            raise GitProtocolError("Git capability name is invalid")
        if key in values_by_key:
            raise GitProtocolError(f"Git capability is duplicated: {key}")
        if separator and not value:
            raise GitProtocolError(f"Git capability value is empty: {key}")
        if any(ord(character) < 32 or ord(character) > 126 for character in line):
            raise GitProtocolError("Git capability line contains control bytes")
        values_by_key[key] = value if separator else None
        lines.append(line)

    if (
        index >= len(packets)
        or packets[index].kind != _FLUSH
        or index != len(packets) - 1
    ):
        raise GitProtocolError("Git capability advertisement is not flush-terminated")

    object_format = values_by_key.get("object-format")
    if object_format != "sha1":
        raise GitProtocolError("Git object format is not exactly sha1")
    fetch_value = values_by_key.get("fetch")
    if not isinstance(fetch_value, str):
        raise GitProtocolError("Git server did not advertise the fetch command")
    fetch_features = fetch_value.split(" ")
    if (
        not fetch_features
        or any(
            not feature or _FETCH_FEATURE.fullmatch(feature) is None
            for feature in fetch_features
        )
        or len(fetch_features) != len(set(fetch_features))
    ):
        raise GitProtocolError("Git fetch capability features are not canonical")

    return GitCapabilities(
        lines=frozenset(lines),
        fetch_features=frozenset(fetch_features),
        object_format=object_format,
    )


def build_fetch_request(
    oid: str,
    expected_type: str,
    capabilities: GitCapabilities,
) -> bytes:
    """Build a protocol-v2 request that can yield only one commit or tree."""

    oid = _validate_oid(oid, "requested Git object")
    type_code = _expected_type_code(expected_type)
    if not isinstance(capabilities, GitCapabilities):
        raise GitProtocolError("Git capabilities are invalid")
    if capabilities.object_format != "sha1":
        raise GitProtocolError("Git object format is not exactly sha1")
    if "filter" not in capabilities.fetch_features:
        raise GitProtocolError("Git server does not support object filtering")
    if type_code == _PACK_TYPE_CODES["commit"] and (
        "shallow" not in capabilities.fetch_features
    ):
        raise GitProtocolError("Git server does not support shallow fetches")

    request = [
        _encode_pkt_line(b"command=fetch\n"),
        _encode_pkt_line(b"object-format=sha1\n"),
        b"0001",
        _encode_pkt_line(f"want {oid}\n".encode("ascii")),
    ]
    if type_code == _PACK_TYPE_CODES["commit"]:
        request.append(_encode_pkt_line(b"deepen 1\n"))
    request.extend(
        (
            _encode_pkt_line(b"filter tree:0\n"),
            _encode_pkt_line(b"no-progress\n"),
            _encode_pkt_line(b"done\n"),
            b"0000",
        )
    )
    return b"".join(request)


def decode_fetch_response(
    raw: bytes,
    oid: str,
    expected_type: str,
    max_object_bytes: int,
) -> bytes:
    """Extract and verify one independently hashed object from a v2 response."""

    if type(raw) is not bytes:
        raise GitProtocolError("Git fetch response must be bytes")
    oid = _validate_oid(oid, "requested Git object")
    type_code = _expected_type_code(expected_type)
    if (
        isinstance(max_object_bytes, bool)
        or not isinstance(max_object_bytes, int)
        or max_object_bytes < 0
    ):
        raise GitProtocolError("maximum Git object bytes must be nonnegative")
    if len(raw) > max_object_bytes + _MAX_FETCH_WIRE_OVERHEAD:
        raise GitProtocolError("Git fetch response exceeds its byte limit")

    packets = _parse_pkt_lines(raw, "Git fetch response")
    index = 0
    if packets[0].kind == _DATA and packets[0].data.startswith(b"ERR "):
        raise GitProtocolError("Git fetch reported a remote protocol error")

    if _packet_is(packets, index, b"acknowledgments\n"):
        index += 1
        if not _packet_is(packets, index, b"NAK\n"):
            raise GitProtocolError("Git fetch acknowledgments are unexpected")
        index += 1
        index = _consume_delimiter(packets, index, "acknowledgments")

    if _packet_is(packets, index, b"shallow-info\n"):
        if type_code != _PACK_TYPE_CODES["commit"]:
            raise GitProtocolError("Git tree fetch returned shallow information")
        index += 1
        expected_line = f"shallow {oid}".encode("ascii")
        if not _packet_is(packets, index, expected_line):
            raise GitProtocolError("Git shallow boundary does not match the commit")
        index += 1
        if index < len(packets) and packets[index].kind == _DATA:
            raise GitProtocolError("Git fetch returned extra shallow boundaries")
        index = _consume_delimiter(packets, index, "shallow information")

    if not _packet_is(packets, index, b"packfile\n"):
        raise GitProtocolError("Git fetch response has no packfile section")
    index += 1

    pack_parts: list[bytes] = []
    pack_bytes = 0
    while index < len(packets) and packets[index].kind == _DATA:
        data = packets[index].data
        index += 1
        if len(data) < 2:
            raise GitProtocolError("Git packfile sideband packet is empty")
        channel = data[0]
        if channel == 2:
            raise GitProtocolError("Git fetch returned unexpected progress output")
        if channel == 3:
            raise GitProtocolError("Git fetch reported a remote failure")
        if channel != 1:
            raise GitProtocolError("Git fetch returned an invalid sideband channel")
        part = data[1:]
        pack_bytes += len(part)
        if pack_bytes > max_object_bytes + _MAX_FETCH_WIRE_OVERHEAD:
            raise GitProtocolError("Git packfile exceeds its byte limit")
        pack_parts.append(part)

    if not pack_parts:
        raise GitProtocolError("Git fetch response contains no packfile bytes")
    if (
        index >= len(packets)
        or packets[index].kind not in {_FLUSH, _RESPONSE_END}
        or index != len(packets) - 1
    ):
        raise GitProtocolError("Git fetch response is not canonically terminated")

    return _decode_one_object_pack(
        b"".join(pack_parts),
        oid,
        expected_type,
        type_code,
        max_object_bytes,
    )


def parse_commit_tree(payload: bytes) -> str:
    """Return the exact root-tree OID from an independently verified commit."""

    if type(payload) is not bytes:
        raise GitProtocolError("Git commit payload must be bytes")
    prefix = b"tree "
    line_bytes = len(prefix) + 40 + 1
    if (
        len(payload) < line_bytes
        or not payload.startswith(prefix)
        or payload[line_bytes - 1 : line_bytes] != b"\n"
    ):
        raise GitProtocolError("Git commit has no canonical root-tree header")
    raw_oid = payload[len(prefix) : line_bytes - 1]
    try:
        oid = raw_oid.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GitProtocolError("Git commit root-tree identity is not ASCII") from exc
    return _validate_oid(oid, "Git commit root tree")


def parse_tree(payload: bytes) -> tuple[dict[str, str], ...]:
    """Parse a canonical raw Git tree into safe acquisition entries."""

    if type(payload) is not bytes:
        raise GitProtocolError("Git tree payload must be bytes")
    if len(payload) > _MAX_TREE_BYTES:
        raise GitProtocolError("Git tree payload exceeds its byte limit")

    entries: list[dict[str, str]] = []
    folded_names: set[str] = set()
    previous_sort_key: bytes | None = None
    cursor = 0
    while cursor < len(payload):
        if len(entries) >= _MAX_TREE_ENTRIES:
            raise GitProtocolError("Git tree contains too many entries")
        mode_end = payload.find(b" ", cursor, min(len(payload), cursor + 8))
        if mode_end < 0:
            raise GitProtocolError("Git tree entry has no canonical mode")
        raw_mode = payload[cursor:mode_end]
        if raw_mode == b"40000":
            mode = "040000"
            kind = "tree"
            sort_suffix = b"/"
        elif raw_mode in {b"100644", b"100755"}:
            mode = raw_mode.decode("ascii")
            kind = "blob"
            sort_suffix = b"\x00"
        elif raw_mode == b"120000":
            raise GitProtocolError("Git tree symlink entry is unsupported")
        elif raw_mode == b"160000":
            raise GitProtocolError("Git tree submodule entry is unsupported")
        else:
            raise GitProtocolError("Git tree entry mode is unsupported")

        name_start = mode_end + 1
        name_end = payload.find(b"\x00", name_start)
        if name_end < 0:
            raise GitProtocolError("Git tree entry has no name terminator")
        raw_name = payload[name_start:name_end]
        oid_start = name_end + 1
        oid_end = oid_start + 20
        if oid_end > len(payload):
            raise GitProtocolError("Git tree entry identity is truncated")
        raw_oid = payload[oid_start:oid_end]
        if raw_oid == b"\x00" * 20:
            raise GitProtocolError("Git tree entry has a null identity")

        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GitProtocolError("Git tree entry name is not UTF-8") from exc
        if not _safe_component(name):
            raise GitProtocolError("Git tree contains an unsafe path component")
        collision_key = name.casefold()
        if collision_key in folded_names:
            raise GitProtocolError(
                "Git tree contains duplicate or case-folding-colliding names"
            )
        folded_names.add(collision_key)

        sort_key = raw_name + sort_suffix
        if previous_sort_key is not None and sort_key <= previous_sort_key:
            raise GitProtocolError("Git tree entries are not in canonical Git order")
        previous_sort_key = sort_key
        entries.append(
            {
                "path": name,
                "mode": mode,
                "type": kind,
                "sha": raw_oid.hex(),
            }
        )
        cursor = oid_end

    return tuple(entries)


def _parse_pkt_lines(raw: bytes, subject: str) -> tuple[_Packet, ...]:
    packets: list[_Packet] = []
    cursor = 0
    while cursor < len(raw):
        if len(packets) >= _MAX_PKT_LINES:
            raise GitProtocolError(f"{subject} contains too many packets")
        if len(raw) - cursor < 4:
            raise GitProtocolError(f"{subject} has a truncated packet prefix")
        prefix = raw[cursor : cursor + 4]
        cursor += 4
        if any(byte not in _HEX_DIGITS for byte in prefix):
            raise GitProtocolError(f"{subject} has a non-hexadecimal packet prefix")
        length = int(prefix, 16)
        if length == 0:
            packets.append(_Packet(_FLUSH))
            continue
        if length == 1:
            packets.append(_Packet(_DELIMITER))
            continue
        if length == 2:
            packets.append(_Packet(_RESPONSE_END))
            continue
        if length < 4 or length > _MAX_PKT_LINE_BYTES:
            raise GitProtocolError(f"{subject} has an invalid packet length")
        data_length = length - 4
        if data_length > len(raw) - cursor:
            raise GitProtocolError(f"{subject} has a truncated packet payload")
        packets.append(_Packet(_DATA, raw[cursor : cursor + data_length]))
        cursor += data_length
    if not packets:
        raise GitProtocolError(f"{subject} contains no packets")
    return tuple(packets)


def _encode_pkt_line(data: bytes) -> bytes:
    if type(data) is not bytes or len(data) > _MAX_PKT_DATA_BYTES:
        raise GitProtocolError("Git packet data exceeds its byte limit")
    return f"{len(data) + 4:04x}".encode("ascii") + data


def _packet_is(packets: tuple[_Packet, ...], index: int, data: bytes) -> bool:
    return index < len(packets) and packets[index] == _Packet(_DATA, data)


def _consume_delimiter(
    packets: tuple[_Packet, ...],
    index: int,
    subject: str,
) -> int:
    if index >= len(packets) or packets[index].kind != _DELIMITER:
        raise GitProtocolError(f"Git fetch {subject} is not delimiter-terminated")
    return index + 1


def _decode_one_object_pack(
    pack: bytes,
    oid: str,
    expected_type: str,
    expected_type_code: int,
    max_object_bytes: int,
) -> bytes:
    if len(pack) < _PACK_HEADER_BYTES + 1 + _PACK_CHECKSUM_BYTES:
        raise GitProtocolError("Git packfile is truncated")
    body = pack[:-_PACK_CHECKSUM_BYTES]
    checksum = pack[-_PACK_CHECKSUM_BYTES:]
    if _sha1(body).digest() != checksum:
        raise GitProtocolError("Git packfile checksum verification failed")
    if body[:4] != b"PACK":
        raise GitProtocolError("Git packfile signature is invalid")
    version, object_count = struct.unpack(">II", body[4:_PACK_HEADER_BYTES])
    if version != 2:
        raise GitProtocolError("Git packfile version is not exactly 2")
    if object_count != 1:
        raise GitProtocolError("Git packfile must contain exactly one object")

    cursor = _PACK_HEADER_BYTES
    first = body[cursor]
    cursor += 1
    type_code = (first >> 4) & 0x07
    declared_size = first & 0x0F
    shift = 4
    continuing = bool(first & 0x80)
    header_bytes = bytearray((first,))
    while continuing:
        if cursor >= len(body) or len(header_bytes) >= 10:
            raise GitProtocolError("Git pack object header is invalid")
        current = body[cursor]
        cursor += 1
        header_bytes.append(current)
        declared_size |= (current & 0x7F) << shift
        shift += 7
        continuing = bool(current & 0x80)
        if declared_size > max_object_bytes:
            raise GitProtocolError("Git object exceeds its declared byte limit")
    if bytes(header_bytes) != _encode_pack_object_header(type_code, declared_size):
        raise GitProtocolError("Git pack object header is not canonical")
    if type_code != expected_type_code:
        if type_code in {6, 7}:
            raise GitProtocolError("Git pack delta objects are unsupported")
        raise GitProtocolError(f"Git pack object is not the requested {expected_type}")
    if declared_size > max_object_bytes:
        raise GitProtocolError("Git object exceeds its declared byte limit")

    compressed = body[cursor:]
    if not compressed:
        raise GitProtocolError("Git pack object has no compressed payload")
    inflater = zlib.decompressobj()
    try:
        payload = inflater.decompress(compressed, declared_size + 1)
    except zlib.error as exc:
        raise GitProtocolError("Git pack object compression is invalid") from exc
    if (
        len(payload) != declared_size
        or not inflater.eof
        or inflater.unconsumed_tail
        or inflater.unused_data
    ):
        raise GitProtocolError("Git pack object size or compressed boundary is invalid")

    object_header = (
        expected_type.encode("ascii")
        + b" "
        + str(len(payload)).encode("ascii")
        + b"\x00"
    )
    if _sha1(object_header + payload).hexdigest() != oid:
        raise GitProtocolError("Git object bytes fail SHA-1 identity verification")
    return payload


def _encode_pack_object_header(type_code: int, size: int) -> bytes:
    first = (type_code << 4) | (size & 0x0F)
    size >>= 4
    result = bytearray()
    if size:
        first |= 0x80
    result.append(first)
    while size:
        current = size & 0x7F
        size >>= 7
        if size:
            current |= 0x80
        result.append(current)
    return bytes(result)


def _validate_oid(value: object, subject: str) -> str:
    if type(value) is not str or _OID.fullmatch(value) is None or value == "0" * 40:
        raise GitProtocolError(f"{subject} has a noncanonical SHA-1 identity")
    return value


def _expected_type_code(expected_type: object) -> int:
    if type(expected_type) is not str or expected_type not in _PACK_TYPE_CODES:
        raise GitProtocolError("expected Git object type must be commit or tree")
    return _PACK_TYPE_CODES[expected_type]


def _safe_component(value: str) -> bool:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        value not in {"", ".", ".."}
        and value == value.strip()
        and unicodedata.normalize("NFC", value) == value
        and len(encoded) <= 255
        and "/" not in value
        and "\\" not in value
        and all(
            ord(character) >= 32
            and ord(character) != 127
            and unicodedata.category(character) not in {"Cc", "Cf", "Cs", "Zl", "Zp"}
            for character in value
        )
    )


def _sha1(value: bytes) -> object:
    return hashlib.sha1(value, usedforsecurity=False)
