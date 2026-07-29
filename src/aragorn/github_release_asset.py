"""Bounded, credential-free acquisition of one public GitHub release asset."""

from __future__ import annotations

import http.client
import re
import ssl
import time
from collections.abc import Mapping
from io import BytesIO
from typing import Any
from urllib.parse import urlsplit

from .cas import CAS, CASError
from .github_acquire import (
    _MAX_ACQUISITION_SECONDS,
    _MAX_METADATA_BYTES,
    _OWNER,
    _REPOSITORY,
    API_HOST,
    API_VERSION,
    RELEASE_ASSET_HOST,
    GitHubAcquisitionError,
    _PinnedEndpoints,
    _PinnedHTTPSConnection,
    _read_response_before_deadline,
    _remaining_seconds,
    _request_before_deadline,
    _RequestBudget,
    _server_tls_context,
)

SCHEMA = "aragorn/github-release-asset/v1"
_MAX_ASSET_BYTES = 16 * 1024 * 1024
_MAX_REDIRECT_BYTES = 16 * 1024
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class GitHubReleaseAssetError(GitHubAcquisitionError):
    """A GitHub release asset could not be acquired completely and safely."""


def verify_github_release_asset_result(
    result: Mapping[str, Any],
    *,
    evidence_cas: CAS,
    expected_url: str,
    expected_release_id: int,
    expected_asset_id: int,
    expected_digest: str,
    expected_github_digest: str | None,
    expected_content_type: str,
    expected_redirected: bool,
) -> dict[str, Any]:
    """Re-hash one retained release asset against caller-held source pins."""

    owner, repository, tag, name = _parse_url(expected_url)
    if (
        not evidence_cas.read_only
        or isinstance(expected_release_id, bool)
        or not isinstance(expected_release_id, int)
        or expected_release_id <= 0
        or isinstance(expected_asset_id, bool)
        or not isinstance(expected_asset_id, int)
        or expected_asset_id <= 0
        or not isinstance(expected_digest, str)
        or _DIGEST.fullmatch(expected_digest) is None
        or (
            expected_github_digest is not None
            and (
                not isinstance(expected_github_digest, str)
                or _DIGEST.fullmatch(expected_github_digest) is None
                or expected_github_digest != expected_digest
            )
        )
        or not isinstance(expected_content_type, str)
        or not expected_content_type
        or len(expected_content_type) > 255
        or any(
            ord(character) < 0x20 or ord(character) > 0x7E
            for character in expected_content_type
        )
        or type(expected_redirected) is not bool
        or not isinstance(result, Mapping)
        or set(result) != {"schema", "source", "asset", "transport", "closure"}
        or result.get("schema") != SCHEMA
    ):
        raise GitHubReleaseAssetError(
            "retained GitHub release asset verification inputs are invalid"
        )
    source = result["source"]
    asset = result["asset"]
    transport = result["transport"]
    closure = result["closure"]
    if (
        not isinstance(source, Mapping)
        or set(source) != {"kind", "host", "owner", "repository", "tag", "url"}
        or source
        != {
            "kind": "github_release_asset",
            "host": "github.com",
            "owner": owner,
            "repository": repository,
            "tag": tag,
            "url": expected_url,
        }
        or not isinstance(asset, Mapping)
        or set(asset)
        != {
            "release_id",
            "asset_id",
            "name",
            "size",
            "digest",
            "github_digest",
            "content_type",
        }
        or asset.get("release_id") != expected_release_id
        or asset.get("asset_id") != expected_asset_id
        or asset.get("name") != name
        or asset.get("digest") != expected_digest
        or asset.get("github_digest") != expected_github_digest
        or asset.get("content_type") != expected_content_type
        or isinstance(asset.get("size"), bool)
        or not isinstance(asset.get("size"), int)
        or not 0 <= asset["size"] <= _MAX_ASSET_BYTES
        or not isinstance(asset.get("content_type"), str)
        or not asset["content_type"]
        or len(asset["content_type"]) > 255
        or any(
            ord(character) < 0x20 or ord(character) > 0x7E
            for character in asset["content_type"]
        )
        or not isinstance(transport, Mapping)
        or set(transport) != {"api_version", "redirected", "final_host"}
        or transport
        != {
            "api_version": API_VERSION,
            "redirected": expected_redirected,
            "final_host": (RELEASE_ASSET_HOST if expected_redirected else API_HOST),
        }
        or closure != {"scope": "release_asset", "status": "complete"}
    ):
        raise GitHubReleaseAssetError(
            "retained GitHub release asset result does not match its pins"
        )
    try:
        content = evidence_cas.read(expected_digest, max_bytes=asset["size"])
    except CASError as exc:
        raise GitHubReleaseAssetError(
            f"cannot re-read retained GitHub release asset: {exc}"
        ) from exc
    if len(content) != asset["size"]:
        raise GitHubReleaseAssetError(
            "retained GitHub release asset size does not match"
        )
    return dict(result)


def acquire_github_release_asset(
    url: str,
    cas: CAS,
    *,
    timeout_seconds: float = 60.0,
    _pinned_api_addresses: list[str] | tuple[str, ...] | None = None,
    _pinned_asset_addresses: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Retain one exact public release asset without executing or extracting it."""

    owner, repository, tag, name = _parse_url(url)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= _MAX_ACQUISITION_SECONDS
    ):
        raise GitHubReleaseAssetError(
            f"timeout_seconds must be between 0 and {_MAX_ACQUISITION_SECONDS:g}"
        )

    budget = _RequestBudget(3, _MAX_METADATA_BYTES + _MAX_ASSET_BYTES)
    deadline = time.monotonic() + float(timeout_seconds)
    api_endpoints = _PinnedEndpoints(_pinned_api_addresses, host=API_HOST)
    asset_endpoints = _PinnedEndpoints(
        _pinned_asset_addresses,
        host=RELEASE_ASSET_HOST,
    )
    release = _request_before_deadline(
        f"/repos/{owner}/{repository}/releases/tags/{tag}",
        max_bytes=_MAX_METADATA_BYTES,
        budget=budget,
        deadline=deadline,
        authorization=None,
        endpoints=api_endpoints,
    )
    asset = _select_asset(release, url, owner, repository, tag, name)
    content, redirected, final_host = _download(
        f"/repos/{owner}/{repository}/releases/assets/{asset['id']}",
        expected_size=asset["size"],
        budget=budget,
        deadline=deadline,
        api_endpoints=api_endpoints,
        asset_endpoints=asset_endpoints,
    )
    expected_digest = asset["digest"]
    if expected_digest is None:
        digest = cas.put(BytesIO(content), max_bytes=len(content))
    else:
        digest = cas.put_expected(
            BytesIO(content),
            expected_digest=expected_digest,
            max_bytes=len(content),
        )
    _remaining_seconds(deadline)
    return {
        "schema": SCHEMA,
        "source": {
            "kind": "github_release_asset",
            "host": "github.com",
            "owner": owner,
            "repository": repository,
            "tag": tag,
            "url": url,
        },
        "asset": {
            "release_id": release["id"],
            "asset_id": asset["id"],
            "name": name,
            "size": len(content),
            "digest": digest,
            "github_digest": expected_digest,
            "content_type": asset["content_type"],
        },
        "transport": {
            "api_version": API_VERSION,
            "redirected": redirected,
            "final_host": final_host,
        },
        "closure": {"scope": "release_asset", "status": "complete"},
    }


def _parse_url(value: object) -> tuple[str, str, str, str]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise GitHubReleaseAssetError(
            "release asset must be a canonical public GitHub URL"
        )
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise GitHubReleaseAssetError("release asset URL is invalid") from exc
    parts = parsed.path.split("/")
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or len(parts) != 7
        or parts[0]
        or parts[3:5] != ["releases", "download"]
    ):
        raise GitHubReleaseAssetError(
            "release asset must be exactly "
            "https://github.com/OWNER/REPOSITORY/releases/download/TAG/ASSET"
        )
    owner, repository, tag, name = parts[1], parts[2], parts[5], parts[6]
    if (
        _OWNER.fullmatch(owner) is None
        or owner.endswith("-")
        or owner != owner.lower()
        or _REPOSITORY.fullmatch(repository) is None
        or repository in {".", ".."}
        or repository.lower().endswith(".git")
        or repository != repository.lower()
        or _COMPONENT.fullmatch(tag) is None
        or _COMPONENT.fullmatch(name) is None
    ):
        raise GitHubReleaseAssetError("release asset URL is not canonical")
    return owner, repository, tag, name


def _select_asset(
    release: dict[str, Any],
    url: str,
    owner: str,
    repository: str,
    tag: str,
    name: str,
) -> dict[str, Any]:
    release_id = release.get("id")
    assets = release.get("assets")
    if (
        isinstance(release_id, bool)
        or not isinstance(release_id, int)
        or release_id <= 0
        or release.get("tag_name") != tag
        or release.get("draft") is not False
        or not isinstance(assets, list)
        or len(assets) > 1_000
    ):
        raise GitHubReleaseAssetError("GitHub release metadata is invalid")
    matches = [
        item for item in assets if isinstance(item, dict) and item.get("name") == name
    ]
    if len(matches) != 1:
        raise GitHubReleaseAssetError(
            "GitHub release metadata does not identify one matching asset"
        )
    asset = matches[0]
    asset_id = asset.get("id")
    size = asset.get("size")
    digest = asset.get("digest")
    content_type = asset.get("content_type")
    expected_api_url = (
        f"https://api.github.com/repos/{owner}/{repository}/releases/assets/{asset_id}"
    )
    if (
        isinstance(asset_id, bool)
        or not isinstance(asset_id, int)
        or asset_id <= 0
        or isinstance(size, bool)
        or not isinstance(size, int)
        or not 0 <= size <= _MAX_ASSET_BYTES
        or asset.get("state") != "uploaded"
        or asset.get("url") != expected_api_url
        or asset.get("browser_download_url") != url
        or (
            digest is not None
            and (not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None)
        )
        or not isinstance(content_type, str)
        or not content_type
        or len(content_type) > 255
        or any(
            ord(character) < 0x20 or ord(character) > 0x7E for character in content_type
        )
    ):
        raise GitHubReleaseAssetError("GitHub release asset metadata is invalid")
    return asset


def _download(
    path: str,
    *,
    expected_size: int,
    budget: _RequestBudget,
    deadline: float,
    api_endpoints: _PinnedEndpoints,
    asset_endpoints: _PinnedEndpoints,
) -> tuple[bytes, bool, str]:
    first = _request_asset(
        API_HOST,
        path,
        expected_size=expected_size,
        budget=budget,
        deadline=deadline,
        endpoints=api_endpoints,
        allow_redirect=True,
    )
    if isinstance(first, bytes):
        return first, False, API_HOST
    redirect_path = _redirect_path(first)
    second = _request_asset(
        RELEASE_ASSET_HOST,
        redirect_path,
        expected_size=expected_size,
        budget=budget,
        deadline=deadline,
        endpoints=asset_endpoints,
        allow_redirect=False,
    )
    if not isinstance(second, bytes):
        raise GitHubReleaseAssetError("GitHub release asset redirected more than once")
    return second, True, RELEASE_ASSET_HOST


def _request_asset(
    host: str,
    path: str,
    *,
    expected_size: int,
    budget: _RequestBudget,
    deadline: float,
    endpoints: _PinnedEndpoints,
    allow_redirect: bool,
) -> bytes | str:
    if (
        host not in {API_HOST, RELEASE_ASSET_HOST}
        or endpoints.host != host
        or not path.startswith("/")
        or len(path) > _MAX_REDIRECT_BYTES
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in path)
    ):
        raise GitHubReleaseAssetError("invalid GitHub release asset request")
    budget.start_request()
    connection = _PinnedHTTPSConnection(
        endpoints.get(deadline=deadline),
        host=host,
        timeout=_remaining_seconds(deadline),
        context=_server_tls_context(),
    )
    connection.set_debuglevel(0)
    try:
        headers = {
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "User-Agent": "aragorn-acquisition-gateway/0",
        }
        if host == API_HOST:
            headers["X-GitHub-Api-Version"] = API_VERSION
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        response_headers = response.getheaders()
        if not isinstance(response_headers, list) or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(part, str) for part in item)
            for item in response_headers
        ):
            raise GitHubReleaseAssetError(
                "GitHub release asset response headers are invalid"
            )
        critical_headers = {
            "content-encoding",
            "content-length",
            "content-type",
            "location",
            "transfer-encoding",
        }
        observed_headers = [
            name.lower()
            for name, _value in response_headers
            if name.lower() in critical_headers
        ]
        if (
            len(observed_headers) != len(set(observed_headers))
            or "transfer-encoding" in observed_headers
        ):
            raise GitHubReleaseAssetError(
                "GitHub release asset response framing is ambiguous"
            )
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise GitHubReleaseAssetError(
                "compressed GitHub release assets are unsupported"
            )
        if response.status == 302 and allow_redirect:
            if response.getheader("Content-Length") != "0":
                raise GitHubReleaseAssetError(
                    "GitHub release asset redirect contains a body"
                )
            location = response.getheader("Location")
            if not isinstance(location, str):
                raise GitHubReleaseAssetError(
                    "GitHub release asset redirect omits its location"
                )
            return location
        if response.status != 200:
            raise GitHubReleaseAssetError(
                f"GitHub release asset request failed with status {response.status}"
            )
        media_type = response.getheader("Content-Type", "").partition(";")[0]
        if media_type.strip().lower() != "application/octet-stream":
            raise GitHubReleaseAssetError(
                "GitHub release asset response is not an octet stream"
            )
        content_length = response.getheader("Content-Length")
        try:
            declared_length = int(content_length)
        except (TypeError, ValueError):
            raise GitHubReleaseAssetError(
                "GitHub release asset has an invalid Content-Length"
            ) from None
        if declared_length != expected_size or declared_length > budget.remaining_bytes:
            raise GitHubReleaseAssetError(
                "GitHub release asset size differs from its metadata"
            )
        raw = _read_response_before_deadline(
            response,
            connection,
            max_bytes=expected_size,
            deadline=deadline,
        )
        if len(raw) != expected_size:
            raise GitHubReleaseAssetError(
                "GitHub release asset byte size differs from its metadata"
            )
        budget.add_bytes(len(raw))
        _remaining_seconds(deadline)
        return raw
    except GitHubReleaseAssetError:
        raise
    except (
        OSError,
        UnicodeError,
        ValueError,
        http.client.HTTPException,
        ssl.SSLError,
    ):
        raise GitHubReleaseAssetError("GitHub release asset transport failed") from None
    finally:
        connection.close()


def _redirect_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_REDIRECT_BYTES
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise GitHubReleaseAssetError("GitHub release asset redirect is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise GitHubReleaseAssetError(
            "GitHub release asset redirect is invalid"
        ) from None
    if (
        parsed.scheme != "https"
        or parsed.netloc != RELEASE_ASSET_HOST
        or parsed.hostname != RELEASE_ASSET_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or not parsed.path.startswith("/")
        or not parsed.query
        or parsed.fragment
    ):
        raise GitHubReleaseAssetError(
            "GitHub release asset redirect target is unsupported"
        )
    return f"{parsed.path}?{parsed.query}"
