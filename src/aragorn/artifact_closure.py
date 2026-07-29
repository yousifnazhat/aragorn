"""Evaluation-only resolution of literal references in retained source trees."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from array import array
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from .cas import CAS, CASError

PROFILE = "phase0-literal-source-refs/v1"
ASSURANCE = "evaluation_only_literal_reference_profile"
MAX_GRAPH_BYTES = 128 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_TEXT_BYTES = 1024 * 1024
_MAX_EDGES = 10_000
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_GITHUB_OWNER = re.compile(r"[a-z0-9][a-z0-9-]{0,38}\Z")
_GITHUB_REPOSITORY = re.compile(r"[a-z0-9_.-]{1,100}\Z")
_GITHUB_PATH = re.compile(r"[A-Za-z0-9._/-]{1,4096}\Z")
_CHARACTER_REFERENCE = re.compile(
    r"&(?:#[0-9]{1,7}|#x[0-9a-f]{1,6}|[a-z][a-z0-9]{1,31});",
    re.IGNORECASE,
)
_AUTOLINK = re.compile(
    r"<([a-z][a-z0-9+.-]{1,31}:[^<>\s\r\n]{1,4096})>",
    re.IGNORECASE,
)
_URI = re.compile(
    r"[a-z][a-z0-9+.-]{1,31}://[^\s<>\"'`]{1,4096}",
    re.IGNORECASE,
)
_ACQUISITION_COMMAND = re.compile(
    r"(?<![a-z0-9_./-])(?:sudo[ \t]+|run[ \t]+)?"
    r"(?:(?:/[a-z0-9._-]+)*/)?"
    r"(?:curl|wget|invoke-webrequest|invoke-restmethod|"
    r"iwr|irm|git[ \t]+clone|"
    r"(?:python(?:[0-9]+(?:\.[0-9]+)?)?[ \t]+-m[ \t]+)?"
    r"pip(?:[0-9]+(?:\.[0-9]+)?)?[ \t]+install|"
    r"uv[ \t]+(?:add|pip[ \t]+install|tool[ \t]+install)|"
    r"poetry[ \t]+add|"
    r"(?:npm|pnpm|yarn|bun)[ \t]+(?:add|ci|i|install)|"
    r"(?:npx|pnpx|yarn[ \t]+dlx|bunx)|"
    r"(?:gem|cargo|nuget)[ \t]+install|"
    r"go[ \t]+(?:get|install)|composer[ \t]+require|"
    r"(?:apt|apt-get|dnf|yum|zypper|brew)[ \t]+install|"
    r"apk[ \t]+add)\b",
    re.IGNORECASE,
)
_GIT_ACQUISITION = re.compile(
    r"(?<![a-z0-9_./-])(?:(?:/[a-z0-9._-]+)*/)?git\b"
    r"[^\r\n]{0,512}\b(?:clone|submodule[ \t]+add)\b",
    re.IGNORECASE,
)
_INTERPRETER_DEPENDENCY = re.compile(
    r"^[ \t]*(?:(?:[-*+$>]|sudo|env)[ \t]+)?"
    r"(?:(?:/[a-z0-9._-]+)*/)?"
    r"(?:(?:ba|da|k|z)?sh|python(?:[0-9]+(?:\.[0-9]+)?)?|"
    r"node|perl|ruby|pwsh)"
    r"[ \t]+(?P<quote>[\"']?)(?P<path>(?!-)[a-z0-9._~/\\/-]{1,4096})"
    r"(?P=quote)(?=$|[ \t])",
    re.IGNORECASE,
)
_AMBIGUOUS_INTERPRETER_COMMAND = re.compile(
    r"^[ \t]*(?:[-*+$>][ \t]+)?(?:sudo[ \t]+)?"
    r"(?:"
    r"(?:(?:/[a-z0-9._-]+)*/)?env[ \t]+"
    r"(?:[a-z_][a-z0-9_]*=[^\s\"'`]+[ \t]+)+"
    r"(?:(?:/[a-z0-9._-]+)*/)?"
    r"(?:(?:ba|da|k|z)?sh|python(?:[0-9]+(?:\.[0-9]+)?)?|"
    r"node|perl|ruby|pwsh)(?=$|[ \t])"
    r"|"
    r"(?:(?:/[a-z0-9._-]+)*/)?"
    r"(?:(?:ba|da|k|z)?sh|python(?:[0-9]+(?:\.[0-9]+)?)?|"
    r"node|perl|ruby|pwsh)[ \t]+-"
    r")",
    re.IGNORECASE,
)
_OPTION_WRAPPED_INTERPRETER_COMMAND = re.compile(
    r"^[ \t]*(?:[-*+$>][ \t]+)?"
    r"(?:(?:/[a-z0-9._-]+)*/)?(?:env|sudo)[ \t]+-[^\s\"'`]+[ \t]+"
    r"[^\r\n]{0,128}\b"
    r"(?:(?:/[a-z0-9._-]+)*/)?"
    r"(?:(?:ba|da|k|z)?sh|python(?:[0-9]+(?:\.[0-9]+)?)?|"
    r"node|perl|ruby|pwsh)(?=$|[ \t])",
    re.IGNORECASE,
)
_DIRECT_EXECUTABLE_DEPENDENCY = re.compile(
    r"^[ \t]*(?:[-*+$>][ \t]+)?"
    r"(?:(?:sudo|env|command|exec)[ \t]+)?"
    r"(?P<quote>[\"']?)(?P<path>\.{1,2}/[a-z0-9._~/-]{1,4096})"
    r"(?P=quote)(?=$|[ \t])",
    re.IGNORECASE,
)
_SINGLE_LITERAL_FETCH = re.compile(
    r"^(?:curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm)"
    r"[ \t]+(?P<quote>[\"']?)(?P<url>https?://[^\s\"'`]+)"
    r"(?P=quote)[ \t]*$",
    re.IGNORECASE,
)
_UNSUPPORTED_MARKDOWN_REFERENCE = re.compile(
    r"(?:\[[^\]\r\n]{0,4096}\]\[[^\]\r\n]{0,4096}\]|"
    r"^[ \t]{0,3}\[[^\]\r\n]{0,4096}\]:[ \t]*\S|"
    r"<[/]?[a-z][a-z0-9-]*(?=[ \t/>]|$))",
    re.IGNORECASE,
)
_SHELL_JOIN = r"(?:\\\r?\n|''|\"\")*"


def _shell_word(word: str) -> str:
    return _SHELL_JOIN.join(rf"(?:\\?{re.escape(character)})" for character in word)


_OBFUSCATED_FETCH = re.compile(
    r"(?<![a-z0-9_./-])"
    r"(?:(?:/[a-z0-9._-]+)*/)?"
    r"(?=(?:[^ \t]|\\\r?\n){0,128}(?:\\|''|\"\"))"
    rf"(?:{
        '|'.join(
            _shell_word(word)
            for word in (
                'curl',
                'wget',
                'invoke-webrequest',
                'invoke-restmethod',
                'iwr',
                'irm',
            )
        )
    }"
    rf"|{_shell_word('git')}[ \t]+{_shell_word('clone')})\b",
    re.IGNORECASE,
)
_DOWNLOAD_SUFFIXES = (
    ".7z",
    ".appimage",
    ".bin",
    ".deb",
    ".dmg",
    ".exe",
    ".gz",
    ".msi",
    ".pkg",
    ".ps1",
    ".rpm",
    ".sh",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".whl",
    ".zip",
)
_SCRIPT_DEPENDENCY_SUFFIXES = (
    ".bash",
    ".cjs",
    ".js",
    ".mjs",
    ".pl",
    ".ps1",
    ".py",
    ".rb",
    ".sh",
)
_TEXT_SUFFIXES = frozenset(
    {
        "",
        ".bash",
        ".cfg",
        ".ini",
        ".js",
        ".json",
        ".lua",
        ".md",
        ".markdown",
        ".ps1",
        ".py",
        ".sh",
        ".toml",
        ".ts",
        ".txt",
        ".yaml",
        ".yml",
        ".zsh",
    }
)
MAX_SCANNED_TEXT_BYTES = _MAX_TEXT_BYTES
TEXT_CARRIER_SUFFIXES = _TEXT_SUFFIXES
_LOCAL_FILE_KEYS = {"path", "size", "digest", "executable"}
_GITHUB_FILE_KEYS = {
    "path",
    "size",
    "digest",
    "git_blob_sha1",
    "executable",
}


class ArtifactClosureError(ValueError):
    """A retained manifest cannot be resolved under the Phase 0 profile."""


class ReferenceBudgetExceeded(ArtifactClosureError):
    """The retained-text scanner found more references than it can retain."""

    def __init__(self, message: str, *, references_seen: int) -> None:
        super().__init__(message)
        self.references_seen = references_seen


def load_retained_manifest(cas: CAS, digest: str) -> dict[str, Any]:
    """Read one canonical source manifest from the CAS."""

    raw = cas.read(_digest(digest, "manifest digest"), max_bytes=_MAX_MANIFEST_BYTES)
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ArtifactClosureError(f"invalid retained manifest JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ArtifactClosureError("retained manifest must be a JSON object")
    if canonical_json(document) != raw:
        raise ArtifactClosureError("retained manifest must use canonical JSON")
    return document


def load_verified_retained_manifest(cas: CAS, digest: str) -> dict[str, Any]:
    """Read and verify one canonical source manifest and every retained blob."""

    manifest, _ = _validate_manifest(load_retained_manifest(cas, digest), cas)
    return manifest


def is_git_lfs_pointer(content: bytes) -> bool:
    """Return whether bytes are a canonical Git LFS v1 pointer."""

    return content.startswith(
        (
            b"version https://git-lfs.github.com/spec/v1\n",
            b"version https://git-lfs.github.com/spec/v1\r\n",
        )
    )


def resolve_source_graph(
    manifest: object,
    cas: CAS,
    *,
    root_manifest_digest: str | None = None,
) -> dict[str, Any]:
    """Resolve bounded literal references without executing source content.

    ``complete`` below is scoped only to :data:`PROFILE`; the returned closure
    is deliberately not an ``artifact_graph`` accepted by admission policy.
    """

    normalized, files = _validate_manifest(manifest, cas)
    actual_manifest_digest = _sha256(canonical_json(normalized))
    if root_manifest_digest is not None and (
        _digest(root_manifest_digest, "root manifest digest") != actual_manifest_digest
    ):
        raise ArtifactClosureError("root manifest digest does not match content")

    source = normalized["source"]
    source_by_path = {entry["path"]: entry for entry in files}
    nodes: list[dict[str, Any]] = []
    edges: dict[tuple[Any, ...], dict[str, Any]] = {}

    def add_edge(
        *,
        source_entry: dict[str, Any],
        byte_offset: int,
        literal: str,
        reference_kind: str,
        status: str,
        reason_code: str | None,
        target: dict[str, str] | None = None,
    ) -> None:
        if len(edges) >= _MAX_EDGES:
            raise ReferenceBudgetExceeded(
                "literal reference count exceeds 10000",
                references_seen=len(edges),
            )
        edge = _reference_edge(
            source_entry=source_entry,
            byte_offset=byte_offset,
            literal=literal,
            reference_kind=reference_kind,
            status=status,
            reason_code=reason_code,
            target=target,
        )
        edges[_reference_edge_key(edge)] = edge

    for entry in files:
        suffix = PurePosixPath(entry["path"]).suffix.casefold()
        if suffix not in _TEXT_SUFFIXES or entry["size"] > _MAX_TEXT_BYTES:
            nodes.append(_node(entry, "opaque", "UNSUPPORTED_OR_OVERSIZED_CARRIER"))
            continue
        content = cas.read(entry["digest"], max_bytes=entry["size"])
        if len(content) != entry["size"]:
            raise ArtifactClosureError(
                f"retained source blob size changed: {entry['path']}"
            )
        if b"\0" in content:
            nodes.append(_node(entry, "opaque", "NUL_CONTAINING_CARRIER"))
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            nodes.append(_node(entry, "opaque", "NON_UTF8_CARRIER"))
            continue
        nodes.append(_node(entry, "scanned", None))
        _scan_retained_text_into(
            text,
            source_entry=entry,
            source=source,
            source_by_path=source_by_path,
            add_edge=add_edge,
        )

    ordered_edges = sorted(
        edges.values(),
        key=lambda item: (
            item["source_path"],
            item["byte_offset"],
            item["literal_digest"],
            item["reference_kind"],
            item["status"],
        ),
    )
    unresolved_items = {
        (
            f"{edge['reason_code']}:{edge['source_path']}:"
            f"{edge['byte_offset']}:{edge['literal_digest']}"
        )
        for edge in ordered_edges
        if edge["status"] == "unresolved"
    }
    unresolved_items.update(
        (
            f"{node['opaque_reason']}:{node['path']}:{node['digest']}"
            for node in nodes
            if node["scan_status"] == "opaque"
        )
    )
    unresolved = sorted(unresolved_items)
    closure = {
        "scope": "source_reference_graph",
        "profile": PROFILE,
        "status": "incomplete" if unresolved else "complete",
        "unresolved": unresolved,
    }
    return {
        "schema": "aragorn/source-artifact-graph/v1",
        "profile": PROFILE,
        "assurance": ASSURANCE,
        "source_assurance": (
            "local_manifest_reverified"
            if source["kind"] == "local"
            else "github_api_membership_asserted_blob_identity_reverified"
        ),
        "root_manifest_digest": actual_manifest_digest,
        "tree_digest": normalized["tree_digest"],
        "nodes": sorted(nodes, key=lambda item: item["path"]),
        "edges": ordered_edges,
        "closure": closure,
    }


def canonical_json(document: object) -> bytes:
    """Return deterministic ASCII JSON for graph identities."""

    try:
        return json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ArtifactClosureError(f"document is not canonical JSON: {exc}") from exc


def scan_retained_text_references(
    text: str,
    *,
    source_entry: dict[str, Any],
    source: dict[str, Any],
    source_by_path: dict[str, dict[str, Any]],
    redact_dynamic_literals: bool = True,
    include_literal_size: bool = False,
) -> tuple[dict[str, Any], ...]:
    """Return deterministic reference edges using the v1 retained-text parser."""

    edges: dict[tuple[Any, ...], dict[str, Any]] = {}

    def add_edge(
        *,
        source_entry: dict[str, Any],
        byte_offset: int,
        literal: str,
        reference_kind: str,
        status: str,
        reason_code: str | None,
        target: dict[str, str] | None = None,
    ) -> None:
        if len(edges) >= _MAX_EDGES:
            raise ArtifactClosureError("literal reference count exceeds 10000")
        edge = _reference_edge(
            source_entry=source_entry,
            byte_offset=byte_offset,
            literal=literal,
            reference_kind=reference_kind,
            status=status,
            reason_code=reason_code,
            target=target,
            redact_dynamic_literals=redact_dynamic_literals,
            include_literal_size=include_literal_size,
        )
        edges[_reference_edge_key(edge)] = edge

    try:
        _scan_retained_text_into(
            text,
            source_entry=source_entry,
            source=source,
            source_by_path=source_by_path,
            add_edge=add_edge,
        )
    except ReferenceBudgetExceeded:
        raise
    except ArtifactClosureError as exc:
        if str(exc) in {
            "literal reference count exceeds 10000",
            "Markdown reference count exceeds 10000",
        }:
            raise ReferenceBudgetExceeded(
                str(exc),
                references_seen=max(len(edges), _MAX_EDGES),
            ) from exc
        raise
    return tuple(
        sorted(
            edges.values(),
            key=lambda item: (
                item["source_path"],
                item["byte_offset"],
                item["literal_digest"],
                item["reference_kind"],
                item["status"],
            ),
        )
    )


def parse_immutable_github_reference(literal: object) -> dict[str, str] | None:
    """Parse one canonical exact-commit GitHub blob reference, if supported."""

    if not isinstance(literal, str) or not literal or "%" in literal:
        return None
    try:
        if len(literal.encode("utf-8")) > 4096:
            return None
        parsed = urlsplit(literal)
        port = parsed.port
    except (UnicodeEncodeError, ValueError):
        return None
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or not literal.isascii()
    ):
        return None
    return _immutable_github_target(parsed)


def is_direct_raw_github_reference(literal: str) -> bool:
    """Return whether a supported reference denotes raw GitHub blob bytes."""

    return parse_immutable_github_reference(
        literal
    ) is not None and _is_direct_raw_github(literal)


def exact_raw_github_fetch_target(command: object) -> dict[str, str] | None:
    """Return the target of one exact supported raw-byte fetch command."""

    if not isinstance(command, str):
        return None
    match = _SINGLE_LITERAL_FETCH.fullmatch(command)
    if match is None:
        return None
    literal = match.group("url")
    if not is_direct_raw_github_reference(literal):
        return None
    return parse_immutable_github_reference(literal)


def canonical_local_reference_target(
    literal: object,
    *,
    source_path: object,
) -> str | None:
    """Return the canonical target of one supported relative reference."""

    if (
        not isinstance(literal, str)
        or not isinstance(source_path, str)
        or "%" in literal
        or "\\" in literal
    ):
        return None
    try:
        parsed = urlsplit(literal)
    except ValueError:
        return None
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    return _resolve_local_path(source_path, unquote(parsed.path))


def _is_script_dependency_candidate(
    literal: str,
    *,
    source_path: str,
    source_by_path: dict[str, dict[str, Any]],
) -> bool:
    folded = literal.casefold()
    if (
        "/" in literal
        or "\\" in literal
        or literal.startswith((".", "~"))
        or folded.endswith(_SCRIPT_DEPENDENCY_SUFFIXES)
    ):
        return True
    target = canonical_local_reference_target(literal, source_path=source_path)
    return target is not None and target in source_by_path


def _scan_retained_text_into(
    text: str,
    *,
    source_entry: dict[str, Any],
    source: dict[str, Any],
    source_by_path: dict[str, dict[str, Any]],
    add_edge: Any,
) -> None:
    _scan_text(
        text,
        source_entry=source_entry,
        source=source,
        source_by_path=source_by_path,
        add_edge=add_edge,
    )
    if source_entry["path"] == ".gitmodules":
        add_edge(
            source_entry=source_entry,
            byte_offset=0,
            literal=text,
            reference_kind="git_submodule",
            status="unresolved",
            reason_code="GIT_SUBMODULE_UNSUPPORTED",
        )
    if text.startswith("version https://git-lfs.github.com/spec/v1"):
        add_edge(
            source_entry=source_entry,
            byte_offset=0,
            literal=text.splitlines()[0],
            reference_kind="git_lfs",
            status="unresolved",
            reason_code="GIT_LFS_OBJECT_UNRESOLVED",
        )


def _reference_edge(
    *,
    source_entry: dict[str, Any],
    byte_offset: int,
    literal: str,
    reference_kind: str,
    status: str,
    reason_code: str | None,
    target: dict[str, str] | None,
    redact_dynamic_literals: bool = True,
    include_literal_size: bool = False,
) -> dict[str, Any]:
    edge = {
        "source_path": source_entry["path"],
        "source_blob_digest": source_entry["digest"],
        "byte_offset": byte_offset,
        "literal_digest": _sha256(literal.encode("utf-8")),
        "reference_kind": reference_kind,
        "status": status,
        "literal": (
            None
            if reference_kind == "dynamic_command" and redact_dynamic_literals
            else _safe_literal(literal)
        ),
        "target": target,
        "reason_code": reason_code,
    }
    if include_literal_size:
        edge["literal_size"] = len(literal.encode("utf-8"))
    return edge


def _reference_edge_key(edge: dict[str, Any]) -> tuple[Any, ...]:
    target = edge["target"]
    return (
        edge["source_path"],
        edge["byte_offset"],
        edge["literal_digest"],
        edge["reference_kind"],
        edge["status"],
        json.dumps(target, sort_keys=True) if target is not None else "",
        edge["reason_code"] or "",
    )


def _scan_text(
    text: str,
    *,
    source_entry: dict[str, Any],
    source: dict[str, Any],
    source_by_path: dict[str, dict[str, Any]],
    add_edge: Any,
) -> None:
    _scan_obfuscated_fetches(
        text,
        source_entry=source_entry,
        add_edge=add_edge,
    )
    byte_cursor = 0
    for raw_line in text.splitlines(keepends=True):
        raw_content = raw_line.rstrip("\r\n")
        line, source_offsets, source_characters = _normalize_line_with_offsets(
            raw_content
        )
        stripped = line.lstrip()
        acquisition_command = (
            _ACQUISITION_COMMAND.search(stripped) is not None
            or _GIT_ACQUISITION.search(stripped) is not None
        )
        matches: list[tuple[int, str]] = []
        claimed_spans: list[tuple[int, int]] = []
        inert_references: set[tuple[int, str]] = set()
        markdown_matches, unsupported_markdown = _markdown_references(line)
        unsupported_markdown.extend(
            match.start() for match in _UNSUPPORTED_MARKDOWN_REFERENCE.finditer(line)
        )
        for start, literal in markdown_matches:
            matches.append((start, literal))
            claimed_spans.append((start, start + len(literal)))
            inert_references.add((start, literal))
        for match in _AUTOLINK.finditer(line):
            captured = match.group(1)
            leading = len(captured) - len(captured.lstrip())
            literal = captured.strip()
            start = match.start(1) + leading
            matches.append((start, literal))
            claimed_spans.append((start, start + len(literal)))
            inert_references.add((start, literal))
        for match in _URI.finditer(line):
            if any(start <= match.start() < end for start, end in claimed_spans):
                continue
            matches.append((match.start(), match.group(0)))
        interpreter_dependency = _INTERPRETER_DEPENDENCY.match(line)
        if interpreter_dependency is not None and _is_script_dependency_candidate(
            interpreter_dependency.group("path"),
            source_path=source_entry["path"],
            source_by_path=source_by_path,
        ):
            matches.append(
                (
                    interpreter_dependency.start("path"),
                    interpreter_dependency.group("path"),
                )
            )
        direct_executable = _DIRECT_EXECUTABLE_DEPENDENCY.match(line)
        if direct_executable is not None:
            direct_path = direct_executable.group("path")
            prefix_length = 2 if direct_path.startswith("./") else 0
            matches.append(
                (
                    direct_executable.start("path") + prefix_length,
                    direct_path[prefix_length:],
                )
            )
        interpreter_requires_dynamic = (
            _AMBIGUOUS_INTERPRETER_COMMAND.match(line) is not None
            or _OPTION_WRAPPED_INTERPRETER_COMMAND.match(line) is not None
        )

        for delimiter_offset in sorted(set(unsupported_markdown)):
            raw_start = source_characters[delimiter_offset]
            raw_end = source_characters[delimiter_offset + 1] + 1
            add_edge(
                source_entry=source_entry,
                byte_offset=byte_cursor + source_offsets[delimiter_offset],
                literal=raw_content[raw_start:raw_end],
                reference_kind="malformed",
                status="unresolved",
                reason_code="REFERENCE_SYNTAX_UNSUPPORTED",
            )

        seen_literals: set[tuple[int, str]] = set()
        supported_immutable = False
        for character_offset, literal in sorted(matches):
            if not literal or (character_offset, literal) in seen_literals:
                continue
            seen_literals.add((character_offset, literal))
            byte_offset = byte_cursor + source_offsets[character_offset]
            raw_start = source_characters[character_offset]
            raw_end = source_characters[character_offset + len(literal) - 1] + 1
            raw_literal = raw_content[raw_start:raw_end]
            if raw_literal != literal:
                edge_literal = raw_literal
                classification = _unresolved(
                    "normalized",
                    "NORMALIZED_REFERENCE_UNSUPPORTED",
                )
            else:
                edge_literal = literal
                classification = _classify_reference(
                    literal,
                    source_path=source_entry["path"],
                    source=source,
                    source_by_path=source_by_path,
                )
            immutable = parse_immutable_github_reference(literal)
            exact_fetch_target = exact_raw_github_fetch_target(stripped)
            if (
                immutable is not None
                and (character_offset, literal) not in inert_references
                and exact_fetch_target != immutable
            ):
                classification = _unresolved(
                    "github_immutable",
                    (
                        "FETCH_ENDPOINT_BYTES_UNMODELED"
                        if acquisition_command and not _is_direct_raw_github(literal)
                        else "BARE_IMMUTABLE_REFERENCE_CONTEXT_UNSUPPORTED"
                    ),
                )
            if classification is None:
                continue
            if (
                classification["reason_code"] == "GITHUB_METADATA_REFERENCE"
                and (character_offset, literal) not in inert_references
            ):
                classification = _unresolved(
                    "external",
                    "EXTERNAL_REFERENCE_UNSUPPORTED",
                )
            if (
                acquisition_command
                and literal.casefold().startswith(("http://", "https://"))
                and classification["status"] == "non_artifact"
            ):
                classification = _unresolved(
                    "external",
                    "EXTERNAL_REFERENCE_UNSUPPORTED",
                )
            if (
                acquisition_command
                and classification["reference_kind"] == "github_immutable"
                and classification["status"] == "resolved"
                and not _is_direct_raw_github(literal)
            ):
                classification = _unresolved(
                    "github_immutable",
                    "FETCH_ENDPOINT_BYTES_UNMODELED",
                )
            if (
                classification["reference_kind"] == "github_immutable"
                and classification["status"] == "resolved"
            ):
                supported_immutable = True
            add_edge(
                source_entry=source_entry,
                byte_offset=byte_offset,
                literal=edge_literal,
                **classification,
            )

        fetch_requires_dynamic = acquisition_command and (
            not supported_immutable
            or _SINGLE_LITERAL_FETCH.fullmatch(stripped) is None
            or line != raw_content
        )
        if fetch_requires_dynamic or interpreter_requires_dynamic:
            raw_stripped = raw_content.lstrip()
            command_offset = len(raw_content) - len(raw_stripped)
            add_edge(
                source_entry=source_entry,
                byte_offset=(
                    byte_cursor + len(raw_content[:command_offset].encode("utf-8"))
                ),
                literal=raw_stripped,
                reference_kind="dynamic_command",
                status="unresolved",
                reason_code="DYNAMIC_OR_MUTABLE_ACQUISITION",
            )
        byte_cursor += len(raw_line.encode("utf-8"))


def _markdown_references(line: str) -> tuple[list[tuple[int, str]], list[int]]:
    """Extract bounded destinations while honoring balanced parentheses."""

    matches: list[tuple[int, str]] = []
    unsupported: list[int] = []
    delimiter = line.find("](")
    candidates = 0
    while delimiter >= 0:
        candidates += 1
        if candidates > _MAX_EDGES:
            raise ArtifactClosureError("Markdown reference count exceeds 10000")
        label_start = line.rfind("[", max(0, delimiter - 4097), delimiter)
        if (
            label_start < 0
            or delimiter - label_start - 1 > 4096
            or "]" in line[label_start + 1 : delimiter]
        ):
            unsupported.append(delimiter)
            delimiter = line.find("](", delimiter + 2)
            continue

        destination_start = delimiter + 2
        depth = 0
        destination_end: int | None = None
        limit = min(len(line), destination_start + 4097)
        cursor = destination_start
        while cursor < limit:
            character = line[cursor]
            if character == "(":
                depth += 1
                if depth > 32:
                    break
            elif character == ")":
                if depth == 0:
                    destination_end = cursor
                    break
                depth -= 1
            cursor += 1
        if destination_end is None:
            unsupported.append(delimiter)
        else:
            captured = line[destination_start:destination_end]
            leading = len(captured) - len(captured.lstrip())
            literal = captured.strip()
            if not literal or not _supported_markdown_destination(literal):
                unsupported.append(delimiter)
            else:
                matches.append((destination_start + leading, literal))
        delimiter = line.find("](", delimiter + 2)
    return matches, unsupported


def _supported_markdown_destination(literal: str) -> bool:
    return (
        not literal.startswith("<")
        and not literal.endswith(">")
        and not any(character.isspace() for character in literal)
        and _CHARACTER_REFERENCE.search(literal) is None
    )


def _scan_obfuscated_fetches(
    text: str,
    *,
    source_entry: dict[str, Any],
    add_edge: Any,
) -> None:
    """Record sink spellings that the strict literal command grammar rejects."""

    character_cursor = 0
    byte_cursor = 0
    for match in _OBFUSCATED_FETCH.finditer(text):
        byte_cursor += len(text[character_cursor : match.start()].encode("utf-8"))
        raw_literal = match.group(0)
        add_edge(
            source_entry=source_entry,
            byte_offset=byte_cursor,
            literal=raw_literal,
            reference_kind="dynamic_command",
            status="unresolved",
            reason_code="DYNAMIC_OR_MUTABLE_ACQUISITION",
        )
        character_cursor = match.start()


def _is_direct_raw_github(literal: str) -> bool:
    try:
        parsed = urlsplit(literal)
    except ValueError:
        return False
    return (parsed.hostname or "").casefold() == "raw.githubusercontent.com"


def _classify_reference(
    literal: str,
    *,
    source_path: str,
    source: dict[str, Any],
    source_by_path: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    if len(literal.encode("utf-8")) > 4096 or any(
        unicodedata.category(character).startswith("C") for character in literal
    ):
        return _unresolved("malformed", "REFERENCE_LITERAL_UNSUPPORTED")
    if literal.startswith("#"):
        return _non_artifact("DOCUMENT_FRAGMENT")
    if "%" in literal:
        return _unresolved("encoded", "PERCENT_ENCODED_REFERENCE_UNSUPPORTED")
    try:
        parsed = urlsplit(literal)
        port = parsed.port
    except ValueError:
        return _unresolved("malformed", "REFERENCE_LITERAL_UNSUPPORTED")

    if parsed.scheme in {"http", "https"}:
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            or parsed.query
            or parsed.fragment
        ):
            return _unresolved("external", "EXTERNAL_REFERENCE_UNSUPPORTED")
        if not literal.isascii():
            return _unresolved("external", "REFERENCE_LITERAL_UNSUPPORTED")
        immutable = parse_immutable_github_reference(literal)
        if immutable is not None:
            target = _resolve_retained_github_target(
                immutable,
                source=source,
                source_by_path=source_by_path,
            )
            if target is not None:
                return {
                    "reference_kind": "github_immutable",
                    "status": "resolved",
                    "reason_code": None,
                    "target": target,
                }
            return _unresolved(
                "github_immutable", "IMMUTABLE_GITHUB_OBJECT_NOT_RETAINED"
            )
        path = parsed.path.casefold()
        path_parts = [part for part in parsed.path.split("/") if part]
        if (
            parsed.hostname in {"github.com", "www.github.com"}
            and len(path_parts) >= 4
            and path_parts[2] in {"blob", "raw", "tree"}
        ):
            return _unresolved("github_mutable", "MUTABLE_GITHUB_REFERENCE")
        if "/releases/" in path or "/archive/" in path or _download_path(path):
            return _unresolved("external_artifact", "RELEASE_OR_ARCHIVE_UNRESOLVED")
        if parsed.hostname in {"github.com", "www.github.com"} and (
            path.count("/") <= 2
            or "/issues" in path
            or "/pull/" in path
            or "/commit/" in path
        ):
            return _non_artifact("GITHUB_METADATA_REFERENCE")
        return _unresolved("external", "EXTERNAL_REFERENCE_UNSUPPORTED")

    if parsed.scheme or parsed.netloc:
        return _unresolved("external", "EXTERNAL_REFERENCE_UNSUPPORTED")
    if parsed.query or parsed.fragment or "\\" in literal:
        return _unresolved("local", "LOCAL_REFERENCE_NOT_CANONICAL")

    target_path = _resolve_local_path(source_path, unquote(parsed.path))
    if target_path is None:
        return _unresolved("local", "LOCAL_REFERENCE_NOT_CANONICAL")
    target_entry = source_by_path.get(target_path)
    if target_entry is None:
        return _unresolved("local", "LOCAL_ARTIFACT_NOT_RETAINED")
    return {
        "reference_kind": "local",
        "status": "resolved",
        "reason_code": None,
        "target": {
            "path": target_entry["path"],
            "digest": target_entry["digest"],
        },
    }


def _immutable_github_target(parsed: Any) -> dict[str, str] | None:
    host = (parsed.hostname or "").casefold()
    if (
        not parsed.path.startswith("/")
        or parsed.path.endswith("/")
        or "//" in parsed.path
        or "\\" in parsed.path
        or _GITHUB_PATH.fullmatch(parsed.path) is None
    ):
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if host in {"github.com", "www.github.com"}:
        if len(parts) < 5 or parts[2] not in {"blob", "raw"}:
            return None
        owner, repository, _mode, commit, *path_parts = parts
    elif host == "raw.githubusercontent.com":
        if len(parts) < 4:
            return None
        owner, repository, commit, *path_parts = parts
    else:
        return None
    if (
        _GIT_SHA1.fullmatch(commit) is None
        or _GITHUB_OWNER.fullmatch(owner.casefold()) is None
        or _GITHUB_REPOSITORY.fullmatch(repository.casefold()) is None
        or not owner
        or not repository
        or owner.endswith("-")
        or repository in {".", ".."}
        or repository.casefold().endswith(".git")
        or not path_parts
    ):
        return None
    path = _canonical_relative_path("/".join(path_parts))
    if path is None:
        return None
    return {
        "owner": owner.casefold(),
        "repository": repository.casefold(),
        "commit": commit,
        "path": path,
    }


def _resolve_retained_github_target(
    target: dict[str, str],
    *,
    source: dict[str, Any],
    source_by_path: dict[str, dict[str, Any]],
) -> dict[str, str] | None:
    if source.get("kind") != "github_commit":
        return None
    if (
        str(source.get("owner", "")).casefold() != target["owner"]
        or str(source.get("repository", "")).casefold() != target["repository"]
        or source.get("commit") != target["commit"]
    ):
        return None
    skill_path = source.get("skill_path")
    if not isinstance(skill_path, str):
        return None
    repository_path = PurePosixPath(target["path"])
    if skill_path == ".":
        local_path = repository_path.as_posix()
    else:
        try:
            local_path = repository_path.relative_to(
                PurePosixPath(skill_path)
            ).as_posix()
        except ValueError:
            return None
    entry = source_by_path.get(local_path)
    if entry is None:
        return None
    return {"path": entry["path"], "digest": entry["digest"]}


def _validate_manifest(
    manifest: object, cas: CAS
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(manifest, dict):
        raise ArtifactClosureError("source manifest must be a JSON object")
    schema = manifest.get("schema")
    if schema not in {"aragorn/manifest/v1", "aragorn/github-manifest/v1"}:
        raise ArtifactClosureError("source manifest schema is unsupported")
    if set(manifest) != {"schema", "source", "tree_digest", "files", "closure"}:
        raise ArtifactClosureError("source manifest has missing or unknown fields")
    closure = manifest["closure"]
    if closure != {"scope": "source_tree", "status": "complete"}:
        raise ArtifactClosureError("source manifest is not a complete source tree")
    source = manifest["source"]
    if not isinstance(source, dict):
        raise ArtifactClosureError("source manifest source must be an object")
    _validate_source(source, schema)
    files_value = manifest["files"]
    if not isinstance(files_value, list) or not 1 <= len(files_value) <= 10_000:
        raise ArtifactClosureError("source manifest files must be a bounded array")

    expected_keys = (
        _LOCAL_FILE_KEYS if schema == "aragorn/manifest/v1" else _GITHUB_FILE_KEYS
    )
    files: list[dict[str, Any]] = []
    paths: set[str] = set()
    folded_paths: set[str] = set()
    total_bytes = 0
    for index, value in enumerate(files_value):
        label = f"source manifest files[{index}]"
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise ArtifactClosureError(f"{label} has missing or unknown fields")
        path = _canonical_relative_path(value["path"])
        if path is None:
            raise ArtifactClosureError(f"{label}.path is not canonical")
        if path in paths or path.casefold() in folded_paths:
            raise ArtifactClosureError("source manifest repeats a file path")
        paths.add(path)
        folded_paths.add(path.casefold())
        size = value["size"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= 16 * 1024 * 1024
        ):
            raise ArtifactClosureError(f"{label}.size is outside the bounded range")
        total_bytes += size
        if total_bytes > 128 * 1024 * 1024:
            raise ArtifactClosureError("source manifest exceeds the total byte limit")
        digest = _digest(value["digest"], f"{label}.digest")
        executable = value["executable"]
        if not isinstance(executable, bool):
            raise ArtifactClosureError(f"{label}.executable must be a boolean")
        if schema == "aragorn/github-manifest/v1" and (
            not isinstance(value["git_blob_sha1"], str)
            or _GIT_SHA1.fullmatch(value["git_blob_sha1"]) is None
        ):
            raise ArtifactClosureError(f"{label}.git_blob_sha1 is invalid")
        try:
            content = cas.read(digest, max_bytes=size)
        except CASError as exc:
            raise ArtifactClosureError(
                f"cannot verify retained source blob {path}: {exc}"
            ) from exc
        if len(content) != size:
            raise ArtifactClosureError(f"retained source blob size changed: {path}")
        if schema == "aragorn/github-manifest/v1":
            git_object = f"blob {size}\0".encode("ascii") + content
            if hashlib.sha1(git_object).hexdigest() != value["git_blob_sha1"]:
                raise ArtifactClosureError(
                    f"retained source Git blob identity changed: {path}"
                )
            if is_git_lfs_pointer(content):
                raise ArtifactClosureError(
                    f"retained source Git LFS pointer rejected: {path}"
                )
        normalized = {
            "path": path,
            "size": size,
            "digest": digest,
            "executable": executable,
        }
        files.append({**value, **normalized})
    if [entry["path"] for entry in files] != sorted(paths):
        raise ArtifactClosureError("source manifest files must be sorted by path")

    tree_files = [
        {
            "path": entry["path"],
            "size": entry["size"],
            "digest": entry["digest"],
            "executable": entry["executable"],
        }
        for entry in files
    ]
    tree_digest = _sha256(canonical_json(tree_files))
    if _digest(manifest["tree_digest"], "source manifest tree_digest") != tree_digest:
        raise ArtifactClosureError("source manifest tree digest does not match files")
    return dict(manifest), files


def _validate_source(source: dict[str, Any], schema: object) -> None:
    if schema == "aragorn/manifest/v1":
        if set(source) != {"kind", "path"} or source.get("kind") != "local":
            raise ArtifactClosureError("local source identity is malformed")
        path = source.get("path")
        if not isinstance(path, str) or not path:
            raise ArtifactClosureError("local source path is malformed")
        return
    expected = {
        "kind",
        "host",
        "owner",
        "repository",
        "commit",
        "repository_hash_algorithm",
        "commit_tree",
        "skill_path",
        "skill_tree",
        "api_version",
    }
    if set(source) != expected:
        raise ArtifactClosureError("GitHub source identity is malformed")
    owner = source.get("owner")
    repository = source.get("repository")
    skill_path = source.get("skill_path")
    if (
        source.get("kind") != "github_commit"
        or source.get("host") != "github.com"
        or source.get("repository_hash_algorithm") != "sha1"
        or source.get("api_version") != "2026-03-10"
        or not isinstance(owner, str)
        or _GITHUB_OWNER.fullmatch(owner) is None
        or owner.endswith("-")
        or not isinstance(repository, str)
        or _GITHUB_REPOSITORY.fullmatch(repository) is None
        or repository in {".", ".."}
        or repository.endswith(".git")
        or not isinstance(source.get("commit"), str)
        or _GIT_SHA1.fullmatch(source["commit"]) is None
        or not isinstance(source.get("commit_tree"), str)
        or _GIT_SHA1.fullmatch(source["commit_tree"]) is None
        or not isinstance(source.get("skill_tree"), str)
        or _GIT_SHA1.fullmatch(source["skill_tree"]) is None
        or not isinstance(skill_path, str)
        or (skill_path != "." and _canonical_relative_path(skill_path) != skill_path)
    ):
        raise ArtifactClosureError("GitHub source identity is malformed")


def _resolve_local_path(source_path: str, value: str) -> str | None:
    if _canonical_relative_path(value) != value:
        return None
    candidate = PurePosixPath(source_path).parent / PurePosixPath(value)
    return _canonical_relative_path(candidate.as_posix())


def _canonical_relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
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


def _download_path(path: str) -> bool:
    return path.endswith(_DOWNLOAD_SUFFIXES)


def _safe_literal(value: str) -> str | None:
    if len(value.encode("utf-8")) > 4096 or any(
        unicodedata.category(character).startswith("C") for character in value
    ):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    return value


def _normalize_line_with_offsets(
    value: str,
) -> tuple[str, array[int], array[int]]:
    """NFKC-normalize one line while retaining raw source byte offsets."""

    normalized: list[str] = []
    source_offsets = array("I")
    source_characters = array("I")
    byte_offset = 0
    for character_index, character in enumerate(value):
        replacement = unicodedata.normalize("NFKC", character)
        normalized.extend(replacement)
        source_offsets.extend([byte_offset] * len(replacement))
        source_characters.extend([character_index] * len(replacement))
        byte_offset += len(character.encode("utf-8"))
    return "".join(normalized), source_offsets, source_characters


def _node(
    entry: dict[str, Any], scan_status: str, opaque_reason: str | None
) -> dict[str, Any]:
    return {
        "path": entry["path"],
        "size": entry["size"],
        "digest": entry["digest"],
        "executable": entry["executable"],
        "scan_status": scan_status,
        "opaque_reason": opaque_reason,
    }


def _unresolved(reference_kind: str, reason_code: str) -> dict[str, Any]:
    return {
        "reference_kind": reference_kind,
        "status": "unresolved",
        "reason_code": reason_code,
        "target": None,
    }


def _non_artifact(reason_code: str) -> dict[str, Any]:
    return {
        "reference_kind": "non_artifact",
        "status": "non_artifact",
        "reason_code": reason_code,
        "target": None,
    }


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ArtifactClosureError(f"{label} must be a lowercase sha256 digest")
    return value


def _sha256(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactClosureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ArtifactClosureError(f"non-finite JSON value: {value}")
