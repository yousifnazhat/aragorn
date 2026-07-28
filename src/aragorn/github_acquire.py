"""Evaluation-only acquisition of one public GitHub skill at an immutable commit."""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import ipaddress
from io import BytesIO
import json
import math
import os
import re
import socket
import ssl
import time
from typing import Any
import unicodedata
from urllib.parse import urlsplit

from .cas import CAS


API_HOST = "api.github.com"
API_VERSION = "2026-03-10"
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_MAX_METADATA_BYTES = 8 * 1024 * 1024
_MAX_API_REQUESTS = 20_050
_MAX_API_BYTES = 384 * 1024 * 1024
_MAX_ACQUISITION_SECONDS = 600.0
_MAX_BEARER_TOKEN_BYTES = 1024
_MAX_PINNED_ENDPOINTS = 16
_HTTPS_PORT = 443

_Endpoint = tuple[int, int, int, tuple[Any, ...]]


class GitHubAcquisitionError(ValueError):
    """A GitHub source could not be resolved completely and safely."""


class GitHubBudgetExceeded(GitHubAcquisitionError):
    """A shared acquisition resource budget was exhausted."""


class _BearerToken:
    """Validated credential whose diagnostic forms are always redacted."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def authorization_header(self) -> str:
        return f"Bearer {self._value}"

    def redact(self, value: object) -> str:
        return str(value).replace(self._value, "<redacted>")

    def __repr__(self) -> str:
        return "_BearerToken(<redacted>)"

    __str__ = __repr__


class _PinnedEndpoints:
    """Resolve the fixed API host once and retain only public addresses."""

    def __init__(self) -> None:
        self._value: tuple[_Endpoint, ...] | None = None

    def get(self) -> tuple[_Endpoint, ...]:
        if self._value is None:
            self._value = _resolve_public_api_endpoints()
        return self._value


class GitHubAcquisitionSession:
    """One immutable-repository acquisition session with shared request state."""

    def __init__(
        self,
        repository_url: str,
        commit: str,
        *,
        max_api_requests: int = _MAX_API_REQUESTS,
        max_api_bytes: int = _MAX_API_BYTES,
        timeout_seconds: float = 120.0,
        bearer_token: str | None = None,
    ) -> None:
        owner, repository = _parse_repository_url(repository_url)
        if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
            raise GitHubAcquisitionError(
                "commit must contain exactly 40 lowercase hexadecimal characters"
            )
        authorization = _validate_bearer_token(bearer_token)
        _check_limit("max_api_requests", max_api_requests, 1)
        _check_limit("max_api_bytes", max_api_bytes, 1)
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= _MAX_ACQUISITION_SECONDS
        ):
            raise GitHubAcquisitionError(
                f"timeout_seconds must be between 0 and {_MAX_ACQUISITION_SECONDS:g}"
            )

        self.owner = owner
        self.repository = repository
        self.commit = commit
        self.prefix = f"/repos/{owner}/{repository}"
        self._authorization = authorization
        self._budget = _RequestBudget(max_api_requests, max_api_bytes)
        self._deadline = time.monotonic() + float(timeout_seconds)
        self._endpoints = _PinnedEndpoints()
        self._tree_cache: dict[str, tuple[dict[str, Any], ...]] = {}

        algorithm = self._request(
            f"{self.prefix}/hash-algorithm",
            max_bytes=_MAX_METADATA_BYTES,
        )
        if (
            set(algorithm) != {"hash_algorithm"}
            or algorithm["hash_algorithm"] != "sha1"
        ):
            raise GitHubAcquisitionError("repository object format is not exactly sha1")

        self._load_commit(commit)

    def for_commit(self, commit: str) -> GitHubAcquisitionSession:
        """Open another exact commit in this repository under the same limits."""

        if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
            raise GitHubAcquisitionError(
                "commit must contain exactly 40 lowercase hexadecimal characters"
            )
        if commit == self.commit:
            return self
        session = GitHubAcquisitionSession.__new__(GitHubAcquisitionSession)
        session.owner = self.owner
        session.repository = self.repository
        session.prefix = self.prefix
        session._authorization = self._authorization
        session._budget = self._budget
        session._deadline = self._deadline
        session._endpoints = self._endpoints
        session._tree_cache = {}
        session._load_commit(commit)
        return session

    def _load_commit(self, commit: str) -> None:
        self.commit = commit
        commit_document = self._request(
            f"{self.prefix}/git/commits/{commit}",
            max_bytes=_MAX_METADATA_BYTES,
        )
        if commit_document.get("sha") != commit:
            raise GitHubAcquisitionError("GitHub returned a different commit identity")
        commit_tree = commit_document.get("tree")
        if not isinstance(commit_tree, dict):
            raise GitHubAcquisitionError("commit response has no tree")
        self.root_tree_sha = _object_sha(commit_tree.get("sha"), "commit tree")

    def read_tree(self, tree_sha: str) -> tuple[dict[str, Any], ...]:
        """Read and validate one non-recursive Git tree, with session caching."""

        tree_sha = _object_sha(tree_sha, "tree")
        cached = self._tree_cache.get(tree_sha)
        if cached is not None:
            return cached
        document = self._request(
            f"{self.prefix}/git/trees/{tree_sha}",
            max_bytes=_MAX_METADATA_BYTES,
        )
        if document.get("sha") != tree_sha:
            raise GitHubAcquisitionError("GitHub returned a different tree identity")
        if document.get("truncated") is not False:
            raise GitHubAcquisitionError(
                "GitHub tree response is truncated or ambiguous"
            )
        raw_entries = document.get("tree")
        if not isinstance(raw_entries, list):
            raise GitHubAcquisitionError("GitHub tree response has no entry array")
        entries: list[dict[str, Any]] = []
        names: set[str] = set()
        for raw_entry in raw_entries:
            entry = _validate_tree_entry(raw_entry)
            name = entry["path"]
            collision_key = name.casefold()
            if collision_key in names:
                raise GitHubAcquisitionError(
                    f"duplicate or colliding Git tree entry after case folding: {name}"
                )
            names.add(collision_key)
            entries.append(entry)
        entries.sort(key=lambda item: item["path"])
        result = tuple(entries)
        self._tree_cache[tree_sha] = result
        return result

    def resolve_tree(self, path: str) -> tuple[str, tuple[str, ...]]:
        """Resolve one canonical repository-relative directory to its tree."""

        parts = _parse_skill_path(path)
        tree_sha = self.root_tree_sha
        for component in parts:
            selected = self._select_entry(tree_sha, component, path)
            if selected["type"] != "tree" or selected["mode"] != "040000":
                raise GitHubAcquisitionError(f"skill path is not a directory: {path}")
            tree_sha = selected["sha"]
        return tree_sha, parts

    def read_repository_blob(
        self,
        path: str,
        *,
        max_file_size: int = 16 * 1024 * 1024,
    ) -> dict[str, Any]:
        """Resolve and verify one exact blob at *path* in the pinned commit."""

        _check_limit("max_file_size", max_file_size, 0)
        parts = _parse_repository_path(path)
        tree_sha = self.root_tree_sha
        for index, component in enumerate(parts):
            selected = self._select_entry(tree_sha, component, path)
            final = index == len(parts) - 1
            if not final:
                if selected["type"] != "tree" or selected["mode"] != "040000":
                    raise GitHubAcquisitionError(
                        f"repository path crosses a non-directory: {path}"
                    )
                tree_sha = selected["sha"]
                continue
            if selected["type"] != "blob" or selected["mode"] not in {
                "100644",
                "100755",
            }:
                raise GitHubAcquisitionError(
                    f"repository path is not a supported blob: {path}"
                )
            if selected["size"] > max_file_size:
                raise GitHubAcquisitionError(f"maximum file size exceeded: {path}")
            content = _read_blob(
                self.prefix,
                selected["sha"],
                selected["size"],
                budget=self._budget,
                deadline=self._deadline,
                authorization=self._authorization,
                endpoints=self._endpoints,
            )
            if _is_lfs_pointer(content):
                raise GitHubAcquisitionError(f"Git LFS pointer rejected: {path}")
            return {
                "path": path,
                "size": selected["size"],
                "git_blob_sha1": selected["sha"],
                "executable": selected["mode"] == "100755",
                "content": content,
            }
        raise AssertionError("repository path parser returned no components")

    def budget_snapshot(self) -> dict[str, dict[str, int]]:
        """Return deterministic request accounting for a completed session."""

        return {
            "api_requests": {
                "limit": self._budget.max_requests,
                "used": self._budget.requests,
            },
            "api_bytes": {
                "limit": self._budget.max_bytes,
                "used": self._budget.bytes,
            },
        }

    def check_deadline(self) -> None:
        """Fail if the shared monotonic deadline is exhausted."""

        _remaining_seconds(self._deadline)

    def _select_entry(
        self, tree_sha: str, component: str, requested_path: str
    ) -> dict[str, Any]:
        matches = [
            entry for entry in self.read_tree(tree_sha) if entry["path"] == component
        ]
        if len(matches) != 1:
            raise GitHubAcquisitionError(
                f"repository path does not exist: {requested_path}"
            )
        return matches[0]

    def _request(self, path: str, *, max_bytes: int) -> dict[str, Any]:
        return _request_before_deadline(
            path,
            max_bytes=max_bytes,
            budget=self._budget,
            deadline=self._deadline,
            authorization=self._authorization,
            endpoints=self._endpoints,
        )


def acquire_github_commit(
    repository_url: str,
    commit: str,
    skill_path: str,
    cas: CAS,
    *,
    max_depth: int = 8,
    max_files: int = 10_000,
    max_file_size: int = 16 * 1024 * 1024,
    max_total_bytes: int = 128 * 1024 * 1024,
    max_api_requests: int = _MAX_API_REQUESTS,
    max_api_bytes: int = _MAX_API_BYTES,
    timeout_seconds: float = 120.0,
    bearer_token: str | None = None,
) -> dict[str, Any]:
    """Acquire exact file bytes from one public GitHub SHA-1 commit.

    This narrow Phase 0 resolver never runs Git, checks out a repository, follows
    redirects, reads ambient credentials, or claims external-artifact closure.
    An explicit bearer token is confined to the fixed GitHub API transport.
    """

    owner, repository = _parse_repository_url(repository_url)
    if not isinstance(commit, str) or _COMMIT.fullmatch(commit) is None:
        raise GitHubAcquisitionError(
            "commit must contain exactly 40 lowercase hexadecimal characters"
        )
    skill_parts = _parse_skill_path(skill_path)
    _check_limit("max_depth", max_depth, 0)
    _check_limit("max_files", max_files, 1)
    _check_limit("max_file_size", max_file_size, 0)
    _check_limit("max_total_bytes", max_total_bytes, 0)
    _check_limit("max_api_requests", max_api_requests, 1)
    _check_limit("max_api_bytes", max_api_bytes, 1)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= _MAX_ACQUISITION_SECONDS
    ):
        raise GitHubAcquisitionError(
            f"timeout_seconds must be between 0 and {_MAX_ACQUISITION_SECONDS:g}"
        )

    session = GitHubAcquisitionSession(
        repository_url,
        commit,
        max_api_requests=max_api_requests,
        max_api_bytes=max_api_bytes,
        timeout_seconds=timeout_seconds,
        bearer_token=bearer_token,
    )
    root_tree_sha = session.root_tree_sha
    skill_tree_sha, _ = session.resolve_tree(skill_path)

    pending_files: list[dict[str, Any]] = []
    entries_seen = 0
    total_bytes = 0

    def walk(tree_sha: str, parts: tuple[str, ...]) -> None:
        nonlocal entries_seen, total_bytes
        for entry in session.read_tree(tree_sha):
            entries_seen += 1
            if entries_seen > max_files:
                raise GitHubAcquisitionError("maximum file count exceeded")
            relative_parts = (*parts, entry["path"])
            relative_path = "/".join(relative_parts)
            if entry["type"] == "tree":
                if len(relative_parts) > max_depth:
                    raise GitHubAcquisitionError(
                        f"maximum depth exceeded at {relative_path}"
                    )
                walk(entry["sha"], relative_parts)
                continue
            size = entry["size"]
            if size > max_file_size:
                raise GitHubAcquisitionError(
                    f"maximum file size exceeded: {relative_path}"
                )
            total_bytes += size
            if total_bytes > max_total_bytes:
                raise GitHubAcquisitionError("maximum total byte count exceeded")
            pending_files.append(
                {
                    "path": relative_path,
                    "size": size,
                    "git_blob_sha1": entry["sha"],
                    "executable": entry["mode"] == "100755",
                }
            )

    walk(skill_tree_sha, ())

    staged_files: list[dict[str, Any]] = []
    for pending in pending_files:
        repository_path = (
            pending["path"]
            if not skill_parts
            else "/".join((*skill_parts, pending["path"]))
        )
        staged = session.read_repository_blob(
            repository_path,
            max_file_size=max_file_size,
        )
        if (
            staged["size"] != pending["size"]
            or staged["git_blob_sha1"] != pending["git_blob_sha1"]
            or staged["executable"] != pending["executable"]
        ):
            raise GitHubAcquisitionError(
                f"Git tree membership changed during acquisition: {pending['path']}"
            )
        staged_files.append({**pending, "content": staged["content"]})

    session.check_deadline()
    files: list[dict[str, Any]] = []
    for staged in staged_files:
        content = staged["content"]
        digest = cas.put(BytesIO(content), max_bytes=staged["size"])
        files.append(
            {
                "path": staged["path"],
                "size": staged["size"],
                "digest": digest,
                "git_blob_sha1": staged["git_blob_sha1"],
                "executable": staged["executable"],
            }
        )

    files.sort(key=lambda item: item["path"])
    # Match local-manifest identity: Git provenance is evidence, not tree content.
    tree_files = [
        {
            "path": entry["path"],
            "size": entry["size"],
            "digest": entry["digest"],
            "executable": entry["executable"],
        }
        for entry in files
    ]
    canonical_tree = json.dumps(
        tree_files, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return {
        "schema": "aragorn/github-manifest/v1",
        "source": {
            "kind": "github_commit",
            "host": "github.com",
            "owner": owner,
            "repository": repository,
            "commit": commit,
            "repository_hash_algorithm": "sha1",
            "commit_tree": root_tree_sha,
            "skill_path": "." if not skill_parts else "/".join(skill_parts),
            "skill_tree": skill_tree_sha,
            "api_version": API_VERSION,
        },
        "tree_digest": f"sha256:{hashlib.sha256(canonical_tree).hexdigest()}",
        "files": files,
        "closure": {"scope": "source_tree", "status": "complete"},
    }


def _validate_bearer_token(value: object) -> _BearerToken | None:
    if value is None:
        return None
    if type(value) is not str:
        raise GitHubAcquisitionError(
            "bearer_token must be a string of 1 to 1024 visible ASCII characters"
        )
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        encoded = b""
    if (
        not 1 <= len(encoded) <= _MAX_BEARER_TOKEN_BYTES
        or any(byte < 0x21 or byte > 0x7E for byte in encoded)
    ):
        raise GitHubAcquisitionError(
            "bearer_token must be a string of 1 to 1024 visible ASCII characters"
        )
    return _BearerToken(value)


def _parse_repository_url(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise GitHubAcquisitionError("repository must be a canonical HTTPS URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise GitHubAcquisitionError("repository URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GitHubAcquisitionError(
            "repository must be exactly https://github.com/OWNER/REPOSITORY"
        )
    parts = parsed.path.split("/")
    if len(parts) != 3 or parts[0] or not parts[1] or not parts[2]:
        raise GitHubAcquisitionError(
            "repository must be exactly https://github.com/OWNER/REPOSITORY"
        )
    owner, repository = parts[1:]
    if _OWNER.fullmatch(owner) is None or owner.endswith("-"):
        raise GitHubAcquisitionError("GitHub owner is not canonical")
    if (
        _REPOSITORY.fullmatch(repository) is None
        or repository in {".", ".."}
        or repository.lower().endswith(".git")
    ):
        raise GitHubAcquisitionError("GitHub repository name is not canonical")
    return owner.lower(), repository.lower()


def _parse_skill_path(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise GitHubAcquisitionError("skill path must be a canonical relative path")
    if value == ".":
        return ()
    try:
        parts = _parse_repository_path(value)
    except GitHubAcquisitionError as exc:
        raise GitHubAcquisitionError(
            "skill path must be a canonical relative path"
        ) from exc
    if len(parts) > 32:
        raise GitHubAcquisitionError("skill path must be a canonical relative path")
    return parts


def _parse_repository_path(value: object) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise GitHubAcquisitionError(
            "repository path must be a canonical relative path"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise GitHubAcquisitionError(
            "repository path must be a canonical relative path"
        ) from exc
    if (
        not value
        or value != value.strip()
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or len(encoded) > 4096
    ):
        raise GitHubAcquisitionError(
            "repository path must be a canonical relative path"
        )
    parts = tuple(value.split("/"))
    if len(parts) > 128 or any(not _safe_component(part) for part in parts):
        raise GitHubAcquisitionError(
            "repository path must be a canonical relative path"
        )
    return parts


def _safe_component(value: object) -> bool:
    if not isinstance(value, str):
        return False
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


def _validate_tree_entry(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubAcquisitionError("GitHub tree entry is not an object")
    path = value.get("path")
    mode = value.get("mode")
    kind = value.get("type")
    sha = _object_sha(value.get("sha"), "tree entry")
    if not _safe_component(path):
        raise GitHubAcquisitionError("GitHub tree contains an unsafe path component")
    if mode == "120000":
        raise GitHubAcquisitionError(f"symlink rejected: {path}")
    if mode == "160000" or kind == "commit":
        raise GitHubAcquisitionError(f"submodule rejected: {path}")
    if kind == "tree" and mode == "040000":
        return {"path": path, "mode": mode, "type": kind, "sha": sha}
    if kind == "blob" and mode in {"100644", "100755"}:
        size = value.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise GitHubAcquisitionError(f"blob size is invalid: {path}")
        return {
            "path": path,
            "mode": mode,
            "type": kind,
            "sha": sha,
            "size": size,
        }
    raise GitHubAcquisitionError(f"unsupported Git object type or mode: {path}")


def _read_blob(
    prefix: str,
    sha: str,
    expected_size: int,
    *,
    budget: _RequestBudget,
    deadline: float,
    authorization: _BearerToken | None,
    endpoints: _PinnedEndpoints,
) -> bytes:
    document = _request_before_deadline(
        f"{prefix}/git/blobs/{sha}",
        max_bytes=max(65_536, expected_size * 2 + 65_536),
        budget=budget,
        deadline=deadline,
        authorization=authorization,
        endpoints=endpoints,
    )
    if document.get("sha") != sha:
        raise GitHubAcquisitionError("GitHub returned a different blob identity")
    reported_size = document.get("size")
    if (
        isinstance(reported_size, bool)
        or not isinstance(reported_size, int)
        or reported_size != expected_size
        or document.get("encoding") != "base64"
    ):
        raise GitHubAcquisitionError("GitHub blob metadata does not match the tree")
    encoded = document.get("content")
    if not isinstance(encoded, str) or "\r" in encoded:
        raise GitHubAcquisitionError("GitHub blob content is not canonical base64")
    try:
        content = base64.b64decode(encoded.replace("\n", ""), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GitHubAcquisitionError("GitHub blob content is not valid base64") from exc
    if len(content) != expected_size:
        raise GitHubAcquisitionError("GitHub blob byte size does not match the tree")
    git_object = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    if hashlib.sha1(git_object).hexdigest() != sha:
        raise GitHubAcquisitionError("GitHub blob bytes fail Git SHA-1 verification")
    return content


def _is_lfs_pointer(content: bytes) -> bool:
    return content.startswith(
        (
            b"version https://git-lfs.github.com/spec/v1\n",
            b"version https://git-lfs.github.com/spec/v1\r\n",
        )
    )


def _object_sha(value: object, subject: str) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise GitHubAcquisitionError(f"{subject} has a noncanonical SHA-1 identity")
    return value


def _server_tls_context() -> ssl.SSLContext:
    """Build one server-auth context from OpenSSL's compiled trust paths only."""

    paths = ssl.get_default_verify_paths()
    overrides = sorted(
        name
        for name in (paths.openssl_cafile_env, paths.openssl_capath_env)
        if name and name in os.environ
    )
    if overrides:
        raise GitHubAcquisitionError(
            "ambient TLS trust overrides are unsupported: " + ", ".join(overrides)
        )
    cafile = (
        paths.openssl_cafile
        if paths.openssl_cafile and os.path.isfile(paths.openssl_cafile)
        else None
    )
    capath = (
        paths.openssl_capath
        if paths.openssl_capath and os.path.isdir(paths.openssl_capath)
        else None
    )
    if cafile is None and capath is None:
        raise GitHubAcquisitionError("no compiled TLS trust store is available")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_verify_locations(cafile=cafile, capath=capath)
    except (OSError, ssl.SSLError) as exc:
        raise GitHubAcquisitionError(
            f"cannot load the compiled TLS trust store: {exc}"
        ) from exc
    return context


def _resolve_public_api_endpoints() -> tuple[_Endpoint, ...]:
    try:
        records = socket.getaddrinfo(
            API_HOST,
            _HTTPS_PORT,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise GitHubAcquisitionError(
            f"cannot resolve the fixed GitHub API host: {exc}"
        ) from exc

    endpoints: list[_Endpoint] = []
    seen: set[tuple[int, str, int, int, int]] = set()
    for family, socket_type, protocol, _canonical_name, socket_address in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        if socket_type != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP:
            continue
        try:
            address = ipaddress.ip_address(socket_address[0].partition("%")[0])
        except ValueError as exc:
            raise GitHubAcquisitionError(
                "fixed GitHub API host resolved to an invalid address"
            ) from exc
        if (
            not address.is_global
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or address.is_loopback
            or address.is_link_local
            or getattr(address, "is_site_local", False)
        ):
            raise GitHubAcquisitionError(
                "fixed GitHub API host resolved to a non-global or non-unicast address"
            )
        port = socket_address[1]
        flow = socket_address[2] if family == socket.AF_INET6 else 0
        scope = socket_address[3] if family == socket.AF_INET6 else 0
        identity = (family, address.compressed, port, flow, scope)
        if port != _HTTPS_PORT or identity in seen:
            continue
        if len(endpoints) >= _MAX_PINNED_ENDPOINTS:
            raise GitHubAcquisitionError(
                "fixed GitHub API host returned too many addresses"
            )
        seen.add(identity)
        endpoints.append((family, socket_type, protocol, socket_address))
    if not endpoints:
        raise GitHubAcquisitionError(
            "fixed GitHub API host has no usable public address"
        )
    return tuple(endpoints)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        endpoints: tuple[_Endpoint, ...],
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(API_HOST, timeout=timeout, context=context)
        self._endpoints = endpoints

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise OSError("proxy tunnels are unsupported")
        deadline = time.monotonic() + float(self.timeout)
        last_error: OSError | None = None
        for family, socket_type, protocol, socket_address in self._endpoints:
            raw_socket: socket.socket | None = None
            try:
                raw_socket = socket.socket(family, socket_type, protocol)
                raw_socket.settimeout(_remaining_connect_seconds(deadline))
                raw_socket.connect(socket_address)
                raw_socket.settimeout(_remaining_connect_seconds(deadline))
                self.sock = self._context.wrap_socket(
                    raw_socket,
                    server_hostname=API_HOST,
                )
                return
            except OSError as exc:
                last_error = exc
                if raw_socket is not None:
                    raw_socket.close()
        raise OSError("cannot connect to a pinned GitHub API address") from last_error


def _remaining_connect_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OSError("pinned GitHub API connection deadline exceeded")
    return remaining


def _request_json(
    path: str,
    *,
    max_bytes: int,
    timeout_seconds: float,
    budget: _RequestBudget,
    authorization: _BearerToken | None = None,
    endpoints: _PinnedEndpoints | None = None,
) -> dict[str, Any]:
    """GET one bounded GitHub API object without ambient auth or proxies."""

    if not path.startswith("/repos/") or any(character in path for character in "\r\n"):
        raise GitHubAcquisitionError("invalid GitHub API path")
    if authorization is not None and not isinstance(authorization, _BearerToken):
        raise GitHubAcquisitionError("invalid internal GitHub authorization")
    budget.start_request()
    context = _server_tls_context()
    connection = (
        http.client.HTTPSConnection(
            API_HOST,
            timeout=timeout_seconds,
            context=context,
        )
        if endpoints is None
        else _PinnedHTTPSConnection(
            endpoints.get(),
            timeout=timeout_seconds,
            context=context,
        )
    )
    connection.set_debuglevel(0)
    try:
        headers = {
            "Accept": "application/vnd.github+json",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "User-Agent": "aragorn-evaluation-resolver/0",
            "X-GitHub-Api-Version": API_VERSION,
        }
        if authorization is not None:
            headers["Authorization"] = authorization.authorization_header()
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise GitHubAcquisitionError(
                f"GitHub API request failed with status {response.status}"
            )
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise GitHubAcquisitionError("compressed GitHub responses are unsupported")
        content_type = response.getheader("Content-Type", "")
        media_type = content_type.partition(";")[0].strip().lower()
        if media_type not in {"application/json", "application/vnd.github+json"}:
            raise GitHubAcquisitionError("GitHub response is not JSON")
        content_length = response.getheader("Content-Length")
        declared_length: int | None = None
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                if authorization is not None:
                    raise GitHubAcquisitionError(
                        "GitHub response has an invalid Content-Length"
                    ) from None
                raise GitHubAcquisitionError(
                    "GitHub response has an invalid Content-Length"
                ) from exc
            if declared_length < 0 or declared_length > max_bytes:
                raise GitHubAcquisitionError("GitHub response exceeds its byte limit")
            if declared_length > budget.remaining_bytes:
                raise GitHubBudgetExceeded("maximum GitHub API byte limit exceeded")
        read_limit = min(max_bytes, budget.remaining_bytes)
        raw = response.read(read_limit + 1)
        if len(raw) > max_bytes:
            raise GitHubAcquisitionError("GitHub response exceeds its byte limit")
        if declared_length is not None and len(raw) != declared_length:
            raise GitHubAcquisitionError(
                "GitHub response length does not match Content-Length"
            )
        budget.add_bytes(len(raw))
    except GitHubAcquisitionError:
        raise
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        if authorization is None:
            raise GitHubAcquisitionError(
                f"GitHub API request failed: {exc}"
            ) from exc
        raise GitHubAcquisitionError(
            f"GitHub API request failed: {authorization.redact(exc)}"
        ) from None
    finally:
        connection.close()
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_parse_json_float,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        if authorization is None:
            raise GitHubAcquisitionError(
                f"GitHub returned invalid JSON: {exc}"
            ) from exc
        raise GitHubAcquisitionError(
            f"GitHub returned invalid JSON: {authorization.redact(exc)}"
        ) from None
    if not isinstance(document, dict):
        raise GitHubAcquisitionError("GitHub response must be a JSON object")
    return document


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _check_limit(name: str, value: int, minimum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GitHubAcquisitionError(f"{name} must be an integer >= {minimum}")


def _request_before_deadline(
    path: str,
    *,
    max_bytes: int,
    budget: _RequestBudget,
    deadline: float,
    authorization: _BearerToken | None,
    endpoints: _PinnedEndpoints,
) -> dict[str, Any]:
    document = _request_json(
        path,
        max_bytes=max_bytes,
        timeout_seconds=_remaining_seconds(deadline),
        budget=budget,
        authorization=authorization,
        endpoints=endpoints,
    )
    _remaining_seconds(deadline)
    return document


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise GitHubBudgetExceeded("GitHub acquisition deadline exceeded")
    return remaining


def _parse_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


class _RequestBudget:
    def __init__(self, max_requests: int, max_bytes: int) -> None:
        self.max_requests = max_requests
        self.max_bytes = max_bytes
        self.requests = 0
        self.bytes = 0

    @property
    def remaining_bytes(self) -> int:
        return self.max_bytes - self.bytes

    def start_request(self) -> None:
        if self.requests >= self.max_requests:
            raise GitHubBudgetExceeded("maximum GitHub API request count exceeded")
        self.requests += 1

    def add_bytes(self, count: int) -> None:
        if count > self.remaining_bytes:
            raise GitHubBudgetExceeded("maximum GitHub API byte limit exceeded")
        self.bytes += count
