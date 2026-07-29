from __future__ import annotations

import hashlib
import struct
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from aragorn.github_git_protocol import (
    GitCapabilities,
    GitProtocolError,
    build_fetch_request,
    decode_fetch_response,
    parse_capabilities,
    parse_commit_tree,
    parse_tree,
)

COMMIT = "ab" * 20
ROOT_TREE = "cd" * 20


def pkt(data: bytes) -> bytes:
    return f"{len(data) + 4:04x}".encode("ascii") + data


def advertisement(
    *lines: bytes,
    service: bool = True,
) -> bytes:
    prelude = pkt(b"# service=git-upload-pack\n") + b"0000" if service else b""
    return (
        prelude + pkt(b"version 2\n") + b"".join(pkt(line) for line in lines) + b"0000"
    )


def standard_advertisement(
    *, fetch: bytes = b"fetch=shallow wait-for-done filter\n"
) -> bytes:
    return advertisement(
        b"agent=git/github\n",
        fetch,
        b"object-format=sha1\n",
    )


def git_oid(kind: str, payload: bytes) -> str:
    header = kind.encode("ascii") + b" " + str(len(payload)).encode("ascii") + b"\0"
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def pack_object_header(type_code: int, size: int) -> bytes:
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


def one_object_pack(
    payload: bytes,
    *,
    type_code: int,
    version: int = 2,
    count: int = 1,
    declared_size: int | None = None,
    object_header: bytes | None = None,
    compressed_suffix: bytes = b"",
) -> bytes:
    size = len(payload) if declared_size is None else declared_size
    header = (
        pack_object_header(type_code, size) if object_header is None else object_header
    )
    body = (
        b"PACK"
        + struct.pack(">II", version, count)
        + header
        + zlib.compress(payload)
        + compressed_suffix
    )
    return body + hashlib.sha1(body, usedforsecurity=False).digest()


def fetch_response(
    pack: bytes,
    *,
    oid: str | None = None,
    acknowledge: bool = False,
    channel: int = 1,
    terminator: bytes = b"0000",
) -> bytes:
    sections = bytearray()
    if acknowledge:
        sections.extend(pkt(b"acknowledgments\n"))
        sections.extend(pkt(b"NAK\n"))
        sections.extend(b"0001")
    if oid is not None:
        sections.extend(pkt(b"shallow-info\n"))
        sections.extend(pkt(f"shallow {oid}".encode("ascii")))
        sections.extend(b"0001")
    sections.extend(pkt(b"packfile\n"))
    split = max(1, len(pack) // 3)
    for offset in range(0, len(pack), split):
        sections.extend(pkt(bytes((channel,)) + pack[offset : offset + split]))
    sections.extend(terminator)
    return bytes(sections)


def tree_entry(mode: bytes, name: bytes, oid_byte: int) -> bytes:
    return mode + b" " + name + b"\0" + bytes((oid_byte,)) * 20


class CapabilityTests(unittest.TestCase):
    def test_parses_smart_http_prelude_and_v2_capabilities(self) -> None:
        capabilities = parse_capabilities(standard_advertisement())

        self.assertEqual(capabilities.object_format, "sha1")
        self.assertEqual(
            capabilities.fetch_features,
            frozenset({"shallow", "wait-for-done", "filter"}),
        )
        self.assertEqual(
            capabilities.lines,
            frozenset(
                {
                    "agent=git/github",
                    "fetch=shallow wait-for-done filter",
                    "object-format=sha1",
                }
            ),
        )

    def test_accepts_direct_v2_advertisement_without_http_prelude(self) -> None:
        capabilities = parse_capabilities(
            advertisement(
                b"fetch=shallow filter\n",
                b"object-format=sha1\n",
                service=False,
            )
        )

        self.assertEqual(capabilities.object_format, "sha1")

    def test_rejects_wrong_service_version_or_required_capability(self) -> None:
        cases = (
            pkt(b"# service=git-receive-pack\n")
            + b"0000"
            + pkt(b"version 2\n")
            + pkt(b"fetch=shallow filter\n")
            + pkt(b"object-format=sha1\n")
            + b"0000",
            pkt(b"version 1\n")
            + pkt(b"fetch=shallow filter\n")
            + pkt(b"object-format=sha1\n")
            + b"0000",
            advertisement(b"object-format=sha1\n"),
            advertisement(b"fetch=shallow filter\n"),
            advertisement(
                b"fetch=shallow filter\n",
                b"object-format=sha256\n",
            ),
        )
        for raw in cases:
            with self.subTest(raw=raw[:48]), self.assertRaises(GitProtocolError):
                parse_capabilities(raw)

    def test_rejects_duplicate_or_noncanonical_capability_lines(self) -> None:
        cases = (
            advertisement(
                b"fetch=shallow filter\n",
                b"fetch=filter\n",
                b"object-format=sha1\n",
            ),
            advertisement(
                b"fetch=shallow  filter\n",
                b"object-format=sha1\n",
            ),
            advertisement(
                b"fetch=shallow filter\r\n",
                b"object-format=sha1\n",
            ),
            advertisement(
                b"fetch=shallow filter\n",
                b"object-format=\n",
            ),
            advertisement(
                b"Fetch=shallow filter\n",
                b"object-format=sha1\n",
            ),
        )
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(GitProtocolError):
                parse_capabilities(raw)

    def test_rejects_malformed_packet_lines_and_trailing_packets(self) -> None:
        cases = (
            b"",
            b"zzzz",
            b"0003",
            b"ffff",
            b"0008abc",
            standard_advertisement() + pkt(b"extra\n"),
        )
        for raw in cases:
            with self.subTest(raw=raw[:48]), self.assertRaises(GitProtocolError):
                parse_capabilities(raw)

    def test_rejects_excessive_packet_count(self) -> None:
        with self.assertRaisesRegex(GitProtocolError, "too many packets"):
            parse_capabilities(b"0000" * 16_385)


class FetchRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.capabilities = parse_capabilities(standard_advertisement())

    def test_builds_exact_filtered_shallow_commit_request(self) -> None:
        expected = b"".join(
            (
                pkt(b"command=fetch\n"),
                pkt(b"object-format=sha1\n"),
                b"0001",
                pkt(f"want {COMMIT}\n".encode("ascii")),
                pkt(b"deepen 1\n"),
                pkt(b"filter tree:0\n"),
                pkt(b"no-progress\n"),
                pkt(b"done\n"),
                b"0000",
            )
        )

        self.assertEqual(
            build_fetch_request(COMMIT, "commit", self.capabilities),
            expected,
        )

    def test_tree_request_does_not_ask_for_shallow_history(self) -> None:
        request = build_fetch_request(ROOT_TREE, "tree", self.capabilities)

        self.assertNotIn(b"deepen", request)
        self.assertIn(pkt(b"filter tree:0\n"), request)

    def test_rejects_bad_identity_type_and_missing_server_features(self) -> None:
        no_filter = GitCapabilities(
            lines=frozenset(),
            fetch_features=frozenset({"shallow"}),
            object_format="sha1",
        )
        no_shallow = GitCapabilities(
            lines=frozenset(),
            fetch_features=frozenset({"filter"}),
            object_format="sha1",
        )
        cases = (
            ("0" * 40, "commit", self.capabilities),
            (COMMIT.upper(), "commit", self.capabilities),
            (COMMIT, "blob", self.capabilities),
            (COMMIT, "commit", no_filter),
            (COMMIT, "commit", no_shallow),
            (COMMIT, "commit", object()),
        )
        for oid, kind, capabilities in cases:
            with (
                self.subTest(
                    oid=oid,
                    kind=kind,
                    capabilities=capabilities,
                ),
                self.assertRaises(GitProtocolError),
            ):
                build_fetch_request(oid, kind, capabilities)  # type: ignore[arg-type]


class FetchResponseTests(unittest.TestCase):
    def test_decodes_and_rehashes_one_commit_from_strict_sideband(self) -> None:
        payload = (
            f"tree {ROOT_TREE}\n".encode("ascii")
            + f"parent {'33' * 20}\n".encode("ascii")
            + b"author A <a@example.test> 1 +0000\n"
            + b"committer A <a@example.test> 1 +0000\n"
            + b"gpgsig -----BEGIN PGP SIGNATURE-----\n"
            + b" continuation line\n"
            + b" -----END PGP SIGNATURE-----\n"
            + b"\nmessage bytes\x00remain opaque\n"
        )
        oid = git_oid("commit", payload)
        pack = one_object_pack(payload, type_code=1)
        response = fetch_response(pack, oid=oid, acknowledge=True)

        decoded = decode_fetch_response(
            response,
            oid,
            "commit",
            max_object_bytes=len(payload),
        )

        self.assertEqual(decoded, payload)
        self.assertEqual(parse_commit_tree(decoded), ROOT_TREE)

    def test_decodes_empty_tree_and_accepts_response_end(self) -> None:
        payload = b""
        oid = git_oid("tree", payload)
        pack = one_object_pack(payload, type_code=2)
        response = fetch_response(pack, terminator=b"0002")

        self.assertEqual(
            decode_fetch_response(response, oid, "tree", max_object_bytes=0),
            b"",
        )

    def test_rejects_progress_fatal_and_unknown_sideband_channels(self) -> None:
        payload = f"tree {ROOT_TREE}\n".encode("ascii")
        oid = git_oid("commit", payload)
        pack = one_object_pack(payload, type_code=1)
        for channel in (0, 2, 3, 4):
            with self.subTest(channel=channel), self.assertRaises(GitProtocolError):
                decode_fetch_response(
                    fetch_response(pack, oid=oid, channel=channel),
                    oid,
                    "commit",
                    len(payload),
                )

    def test_rejects_bad_section_order_boundaries_and_shallow_identity(self) -> None:
        payload = f"tree {ROOT_TREE}\n".encode("ascii")
        oid = git_oid("commit", payload)
        pack = one_object_pack(payload, type_code=1)
        wrong_shallow = fetch_response(pack, oid="44" * 20)
        missing_pack_header = pkt(b"\x01" + pack) + b"0000"
        extra_section = fetch_response(pack) + b"0000"
        no_delimiter = (
            pkt(b"shallow-info\n")
            + pkt(f"shallow {oid}".encode("ascii"))
            + pkt(b"packfile\n")
            + pkt(b"\x01" + pack)
            + b"0000"
        )
        for response in (
            wrong_shallow,
            missing_pack_header,
            extra_section,
            no_delimiter,
        ):
            with (
                self.subTest(response=response[:48]),
                self.assertRaises(GitProtocolError),
            ):
                decode_fetch_response(
                    response,
                    oid,
                    "commit",
                    len(payload),
                )

    def test_rejects_remote_error_packet_without_reflecting_its_bytes(self) -> None:
        response = pkt(b"ERR upload-pack: not our ref secret-value")

        with self.assertRaisesRegex(
            GitProtocolError,
            r"^Git fetch reported a remote protocol error$",
        ):
            decode_fetch_response(
                response,
                COMMIT,
                "commit",
                max_object_bytes=1024,
            )

    def test_rejects_pack_checksum_version_and_object_count(self) -> None:
        payload = f"tree {ROOT_TREE}\n".encode("ascii")
        oid = git_oid("commit", payload)
        valid = one_object_pack(payload, type_code=1)
        corrupt_checksum = valid[:-1] + bytes((valid[-1] ^ 1,))
        cases = (
            corrupt_checksum,
            one_object_pack(payload, type_code=1, version=3),
            one_object_pack(payload, type_code=1, count=0),
            one_object_pack(payload, type_code=1, count=2),
            valid[:-5],
        )
        for pack in cases:
            with self.subTest(pack=pack[:16]), self.assertRaises(GitProtocolError):
                decode_fetch_response(
                    fetch_response(pack, oid=oid),
                    oid,
                    "commit",
                    len(payload),
                )

    def test_rejects_wrong_delta_or_noncanonical_object_header(self) -> None:
        payload = f"tree {ROOT_TREE}\n".encode("ascii")
        oid = git_oid("commit", payload)
        canonical = pack_object_header(1, len(payload))
        noncanonical = bytes((canonical[0] | 0x80, 0))
        cases = (
            one_object_pack(payload, type_code=2),
            one_object_pack(payload, type_code=6),
            one_object_pack(
                payload,
                type_code=1,
                object_header=noncanonical,
            ),
        )
        for pack in cases:
            with self.subTest(pack=pack[:16]), self.assertRaises(GitProtocolError):
                decode_fetch_response(
                    fetch_response(pack),
                    oid,
                    "commit",
                    len(payload),
                )

    def test_rejects_size_compression_boundary_oid_and_limit_mismatches(self) -> None:
        payload = f"tree {ROOT_TREE}\n".encode("ascii")
        oid = git_oid("commit", payload)
        cases = (
            (
                one_object_pack(
                    payload,
                    type_code=1,
                    declared_size=len(payload) + 1,
                ),
                oid,
                len(payload) + 1,
            ),
            (
                one_object_pack(
                    payload,
                    type_code=1,
                    compressed_suffix=b"garbage",
                ),
                oid,
                len(payload),
            ),
            (
                one_object_pack(payload, type_code=1),
                "55" * 20,
                len(payload),
            ),
            (
                one_object_pack(payload, type_code=1),
                oid,
                len(payload) - 1,
            ),
        )
        for pack, requested_oid, limit in cases:
            with (
                self.subTest(
                    requested_oid=requested_oid,
                    limit=limit,
                ),
                self.assertRaises(GitProtocolError),
            ):
                decode_fetch_response(
                    fetch_response(pack),
                    requested_oid,
                    "commit",
                    limit,
                )


class CommitParserTests(unittest.TestCase):
    def test_only_requires_the_exact_first_tree_header(self) -> None:
        payload = (
            f"tree {ROOT_TREE}\n".encode("ascii")
            + b"gpgsig opaque\n continuation\n\nraw message\x00"
        )

        self.assertEqual(parse_commit_tree(payload), ROOT_TREE)

    def test_rejects_noncanonical_root_tree_header(self) -> None:
        cases = (
            b"",
            f"Tree {ROOT_TREE}\n".encode("ascii"),
            f"tree {ROOT_TREE.upper()}\n".encode("ascii"),
            f"tree {'0' * 40}\n".encode("ascii"),
            f"tree {ROOT_TREE}\r\n".encode("ascii"),
            f"tree {ROOT_TREE}".encode("ascii"),
            "not bytes",
        )
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(GitProtocolError):
                parse_commit_tree(payload)  # type: ignore[arg-type]


class TreeParserTests(unittest.TestCase):
    def test_parses_known_canonical_tree_fixture(self) -> None:
        payload = tree_entry(b"100644", b"foo.c", 0x11) + tree_entry(
            b"40000", b"foo", 0x22
        )

        self.assertEqual(
            git_oid("tree", payload),
            "cd91612c03ba4858c9c33e5925679699c0ee5b1f",
        )
        self.assertEqual(
            parse_tree(payload),
            (
                {
                    "path": "foo.c",
                    "mode": "100644",
                    "type": "blob",
                    "sha": "11" * 20,
                },
                {
                    "path": "foo",
                    "mode": "040000",
                    "type": "tree",
                    "sha": "22" * 20,
                },
            ),
        )

    def test_parses_empty_tree(self) -> None:
        self.assertEqual(
            git_oid("tree", b""),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        )
        self.assertEqual(parse_tree(b""), ())

    def test_enforces_directory_as_slash_git_order(self) -> None:
        valid = tree_entry(b"100644", b"foo.bar", 0x11) + tree_entry(
            b"40000", b"foo", 0x22
        )
        invalid = tree_entry(b"40000", b"foo", 0x22) + tree_entry(
            b"100644", b"foo.bar", 0x11
        )

        self.assertEqual(
            [entry["path"] for entry in parse_tree(valid)], ["foo.bar", "foo"]
        )
        with self.assertRaises(GitProtocolError):
            parse_tree(invalid)

    def test_rejects_unsafe_colliding_and_non_utf8_names(self) -> None:
        cases = (
            tree_entry(b"100644", b".", 0x11),
            tree_entry(b"100644", b"a/b", 0x11),
            tree_entry(b"100644", b"trailing ", 0x11),
            tree_entry(b"100644", b"\xff", 0x11),
            tree_entry(b"100644", "e\u0301".encode(), 0x11),
            tree_entry(b"100644", b"A", 0x11) + tree_entry(b"100644", b"a", 0x22),
        )
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(GitProtocolError):
                parse_tree(payload)

    def test_rejects_unsupported_modes_null_ids_and_bad_boundaries(self) -> None:
        null_oid = b"100644 safe\0" + b"\0" * 20
        cases = (
            tree_entry(b"040000", b"directory", 0x11),
            tree_entry(b"100664", b"file", 0x11),
            tree_entry(b"120000", b"link", 0x11),
            tree_entry(b"160000", b"submodule", 0x11),
            null_oid,
            b"100644-no-space",
            b"100644 no-null",
            b"100644 short\0" + b"\x11" * 19,
        )
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(GitProtocolError):
                parse_tree(payload)

    def test_rejects_noncanonical_entry_order(self) -> None:
        payload = tree_entry(b"40000", b"foo", 0x22) + tree_entry(
            b"100644", b"foo.c", 0x11
        )

        with self.assertRaises(GitProtocolError):
            parse_tree(payload)

    def test_caller_can_reduce_the_tree_entry_budget(self) -> None:
        payload = tree_entry(b"100644", b"a", 0x11) + tree_entry(
            b"100644", b"b", 0x22
        )
        with self.assertRaisesRegex(GitProtocolError, "too many entries"):
            parse_tree(payload, max_entries=1)
        for invalid in (0, True, 100_001):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                GitProtocolError,
                "entry limit",
            ):
                parse_tree(b"", max_entries=invalid)


if __name__ == "__main__":
    unittest.main()
