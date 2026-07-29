from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
import zipfile
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from aragorn import github_acquire
from aragorn.cas import CAS, CASError
from aragorn.github_acquire import API_HOST, RELEASE_ASSET_HOST
from aragorn.github_release_asset import (
    GitHubReleaseAssetError,
    acquire_github_release_asset,
    verify_github_release_asset_result,
)
from aragorn.oci_worker_protocol import canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_URL = "https://github.com/astral-sh/uv/releases/download/0.12.0/sha256.sum"
_CONTENT = b"fixture checksum\n"
_DIGEST = "sha256:" + hashlib.sha256(_CONTENT).hexdigest()
_API_ADDRESS = ["1.1.1.1"]
_ASSET_ADDRESS = ["8.8.8.8"]


def _metadata(*, digest: str | None = _DIGEST) -> dict:
    return {
        "id": 361308705,
        "tag_name": "0.12.0",
        "draft": False,
        "assets": [
            {
                "id": 493071343,
                "name": "sha256.sum",
                "size": len(_CONTENT),
                "digest": digest,
                "state": "uploaded",
                "content_type": "text/plain",
                "url": (
                    "https://api.github.com/repos/astral-sh/uv/"
                    "releases/assets/493071343"
                ),
                "browser_download_url": _URL,
            }
        ],
    }


def _response(
    raw: bytes = _CONTENT,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    response = MagicMock()
    response.status = status
    actual = {
        "Content-Encoding": "identity",
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(raw)),
        **(headers or {}),
    }
    response.getheader.side_effect = lambda name, default=None: actual.get(
        name,
        default,
    )
    response.getheaders.return_value = list(actual.items())
    response.read.side_effect = lambda limit: raw[:limit]
    response.read1.side_effect = BytesIO(raw).read
    return response


def _connection(response: MagicMock) -> MagicMock:
    connection = MagicMock()
    connection.getresponse.return_value = response
    return connection


def _zip_bytes(*, shebang: bool = False) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr("package/main.py", b"print('retained')\n")
        archive.writestr("README.md", b"bounded release archive\n")
    raw = output.getvalue()
    return b"#!/usr/bin/env python3\n" + raw if shebang else raw


class GitHubReleaseAssetTests(unittest.TestCase):
    def _acquire(
        self,
        responses: tuple[MagicMock, ...],
        *,
        metadata: dict | None = None,
    ) -> tuple[dict, CAS, tuple[MagicMock, ...]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        cas = CAS(Path(temporary.name) / "cas")
        connections = tuple(_connection(response) for response in responses)
        with (
            patch(
                "aragorn.github_release_asset._request_before_deadline",
                return_value=_metadata() if metadata is None else metadata,
            ) as release_request,
            patch(
                "aragorn.github_release_asset._PinnedHTTPSConnection",
                side_effect=connections,
            ),
            patch(
                "aragorn.github_release_asset._server_tls_context",
                return_value=MagicMock(),
            ),
        ):
            result = acquire_github_release_asset(
                _URL,
                cas,
                _pinned_api_addresses=_API_ADDRESS,
                _pinned_asset_addresses=_ASSET_ADDRESS,
            )
        self.assertEqual(
            release_request.call_args.args[0],
            "/repos/astral-sh/uv/releases/tags/0.12.0",
        )
        return result, cas, connections

    def _acquire_named(self, name: str, content: bytes) -> tuple[dict, CAS, str, str]:
        url = (
            "https://github.com/astral-sh/uv/releases/download/"
            f"0.12.0/{name}"
        )
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        metadata = {
            "id": 361308705,
            "tag_name": "0.12.0",
            "draft": False,
            "assets": [
                {
                    "id": 493071343,
                    "name": name,
                    "size": len(content),
                    "digest": digest,
                    "state": "uploaded",
                    "content_type": "application/octet-stream",
                    "url": (
                        "https://api.github.com/repos/astral-sh/uv/"
                        "releases/assets/493071343"
                    ),
                    "browser_download_url": url,
                }
            ],
        }
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        cas = CAS(Path(temporary.name) / "cas")
        connection = _connection(_response(content))
        with (
            patch(
                "aragorn.github_release_asset._request_before_deadline",
                return_value=metadata,
            ),
            patch(
                "aragorn.github_release_asset._PinnedHTTPSConnection",
                return_value=connection,
            ),
            patch(
                "aragorn.github_release_asset._server_tls_context",
                return_value=MagicMock(),
            ),
        ):
            result = acquire_github_release_asset(
                url,
                cas,
                _pinned_api_addresses=_API_ADDRESS,
                _pinned_asset_addresses=_ASSET_ADDRESS,
            )
        return result, cas, url, digest

    def test_direct_stream_is_digest_bound_and_retained(self) -> None:
        result, cas, connections = self._acquire((_response(),))

        self.assertEqual(
            result,
            {
                "schema": "aragorn/github-release-asset/v1",
                "source": {
                    "kind": "github_release_asset",
                    "host": "github.com",
                    "owner": "astral-sh",
                    "repository": "uv",
                    "tag": "0.12.0",
                    "url": _URL,
                },
                "asset": {
                    "release_id": 361308705,
                    "asset_id": 493071343,
                    "name": "sha256.sum",
                    "size": len(_CONTENT),
                    "digest": _DIGEST,
                    "github_digest": _DIGEST,
                    "content_type": "text/plain",
                },
                "transport": {
                    "api_version": "2026-03-10",
                    "redirected": False,
                    "final_host": API_HOST,
                },
                "closure": {"scope": "release_asset", "status": "complete"},
            },
        )
        self.assertEqual(cas.read(_DIGEST), _CONTENT)
        self.assertEqual(len(connections), 1)
        request = connections[0].request.call_args
        self.assertEqual(
            request.args[:2], ("GET", "/repos/astral-sh/uv/releases/assets/493071343")
        )
        self.assertNotIn("Authorization", request.kwargs["headers"])
        self.assertNotIn("Proxy-Authorization", request.kwargs["headers"])

    def test_zip_family_and_magic_only_assets_bind_v2_inventory(self) -> None:
        for name, shebang, expected_kind in (
            ("bundle.zip", False, "zip"),
            ("bundle.whl", False, "wheel"),
            ("bundle.pyz", True, "zipapp"),
            ("bundle.bin", False, "zip"),
        ):
            with self.subTest(name=name):
                result, cas, url, digest = self._acquire_named(
                    name,
                    _zip_bytes(shebang=shebang),
                )
                self.assertEqual(result["schema"], "aragorn/github-release-asset/v2")
                self.assertIsInstance(result["inventory_digest"], str)
                replay = verify_github_release_asset_result(
                    result,
                    evidence_cas=CAS(cas.root, read_only=True),
                    expected_url=url,
                    expected_release_id=361308705,
                    expected_asset_id=493071343,
                    expected_digest=digest,
                    expected_github_digest=digest,
                    expected_content_type="application/octet-stream",
                    expected_redirected=False,
                )
                inventory = json.loads(cas.read(result["inventory_digest"]))
                self.assertEqual(inventory["archive"]["kind"], expected_kind)
                self.assertEqual(inventory["totals"]["files"], 2)
                self.assertEqual(replay, result)

    def test_zip_intent_cannot_downgrade_or_bind_incomplete_inventory(self) -> None:
        for name, content in (
            ("malformed.zip", b"not a ZIP"),
            ("malformed.pyz", b"#!/usr/bin/env python3\nnot a ZIP"),
            ("sfx.bin", b"MZ-bounded-prefix" + _zip_bytes()),
        ):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    GitHubReleaseAssetError,
                    "cannot inventory",
                ),
            ):
                self._acquire_named(name, content)

        result, cas, url, digest = self._acquire_named(
            "bundle.pyz",
            _zip_bytes(shebang=True),
        )
        downgraded = deepcopy(result)
        downgraded["schema"] = "aragorn/github-release-asset/v1"
        downgraded.pop("inventory_digest")
        self.assertEqual(
            verify_github_release_asset_result(
                downgraded,
                evidence_cas=CAS(cas.root, read_only=True),
                expected_url=url,
                expected_release_id=361308705,
                expected_asset_id=493071343,
                expected_digest=digest,
                expected_github_digest=digest,
                expected_content_type="application/octet-stream",
                expected_redirected=False,
            ),
            downgraded,
        )
        with self.assertRaisesRegex(GitHubReleaseAssetError, "require a v2"):
            verify_github_release_asset_result(
                downgraded,
                evidence_cas=CAS(cas.root, read_only=True),
                expected_url=url,
                expected_release_id=361308705,
                expected_asset_id=493071343,
                expected_digest=digest,
                expected_github_digest=digest,
                expected_content_type="application/octet-stream",
                expected_redirected=False,
                require_zip_inventory=True,
            )

        inventory_raw = cas.read(result["inventory_digest"])
        archive_raw = cas.read(digest)
        with tempfile.TemporaryDirectory() as temporary:
            incomplete = CAS(Path(temporary) / "cas")
            incomplete.put_expected(
                BytesIO(archive_raw),
                expected_digest=digest,
                max_bytes=len(archive_raw),
            )
            incomplete.put_expected(
                BytesIO(inventory_raw),
                expected_digest=result["inventory_digest"],
                max_bytes=len(inventory_raw),
            )
            with self.assertRaisesRegex(
                GitHubReleaseAssetError,
                "cannot verify retained.*inventory",
            ):
                verify_github_release_asset_result(
                    result,
                    evidence_cas=CAS(incomplete.root, read_only=True),
                    expected_url=url,
                    expected_release_id=361308705,
                    expected_asset_id=493071343,
                    expected_digest=digest,
                    expected_github_digest=digest,
                    expected_content_type="application/octet-stream",
                    expected_redirected=False,
                )

    def test_one_pinned_release_host_redirect_is_supported_without_retention(
        self,
    ) -> None:
        location = (
            f"https://{RELEASE_ASSET_HOST}/asset/path"
            "?token=ephemeral-secret&response-content-type=application%2Foctet-stream"
        )
        redirect = _response(
            b"",
            status=302,
            headers={"Location": location, "Content-Length": "0"},
        )
        result, cas, connections = self._acquire((redirect, _response()))

        self.assertTrue(result["transport"]["redirected"])
        self.assertEqual(result["transport"]["final_host"], RELEASE_ASSET_HOST)
        self.assertNotIn("ephemeral-secret", json.dumps(result))
        self.assertEqual(cas.read(_DIGEST), _CONTENT)
        self.assertEqual(len(connections), 2)
        final_request = connections[1].request.call_args
        self.assertEqual(final_request.args[0], "GET")
        self.assertIn("token=ephemeral-secret", final_request.args[1])
        self.assertNotIn("Authorization", final_request.kwargs["headers"])

    def test_invalid_urls_fail_before_metadata_or_network(self) -> None:
        values = (
            "http://github.com/astral-sh/uv/releases/download/0.12.0/sha256.sum",
            "https://github.com/ASTRAL-SH/uv/releases/download/0.12.0/sha256.sum",
            "https://github.com/astral-sh/uv/releases/latest/sha256.sum",
            "https://github.com/astral-sh/uv/releases/download/0.12.0/a/b",
            _URL + "?token=secret",
            _URL + "#fragment",
            "https://user@github.com/astral-sh/uv/releases/download/0.12.0/sha256.sum",
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("aragorn.github_release_asset._request_before_deadline") as request,
            patch("aragorn.github_release_asset._PinnedHTTPSConnection") as connection,
        ):
            for value in values:
                with (
                    self.subTest(value=value),
                    self.assertRaises(GitHubReleaseAssetError),
                ):
                    acquire_github_release_asset(
                        value,
                        CAS(
                            Path(temporary) / hashlib.sha256(value.encode()).hexdigest()
                        ),
                    )
        request.assert_not_called()
        connection.assert_not_called()

    def test_metadata_identity_and_digest_mismatches_fail_closed(self) -> None:
        variants = []
        for mutate in (
            lambda value: value.__setitem__("tag_name", "latest"),
            lambda value: value.__setitem__("draft", True),
            lambda value: value["assets"].append(deepcopy(value["assets"][0])),
            lambda value: value["assets"][0].__setitem__("state", "starter"),
            lambda value: value["assets"][0].__setitem__("size", 17 * 1024 * 1024),
            lambda value: value["assets"][0].__setitem__(
                "browser_download_url",
                "https://github.com/other/repo/releases/download/v1/file",
            ),
            lambda value: value["assets"][0].__setitem__(
                "url",
                "https://api.github.com/repos/other/repo/releases/assets/493071343",
            ),
            lambda value: value["assets"][0].__setitem__(
                "digest",
                "sha256:not-a-digest",
            ),
        ):
            value = _metadata()
            mutate(value)
            variants.append(value)

        for value in variants:
            with self.subTest(value=value), self.assertRaises(GitHubReleaseAssetError):
                self._acquire((_response(),), metadata=value)

        wrong = _metadata(digest="sha256:" + "0" * 64)
        with self.assertRaises(CASError):
            self._acquire((_response(),), metadata=wrong)

    def test_remaining_aggregate_cap_rejects_before_download_or_store(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            with (
                patch(
                    "aragorn.github_release_asset._request_before_deadline",
                    return_value=_metadata(),
                ) as release_request,
                patch("aragorn.github_release_asset._download") as download,
                self.assertRaisesRegex(
                    GitHubReleaseAssetError,
                    "remaining byte limit",
                ),
            ):
                acquire_github_release_asset(
                    _URL,
                    cas,
                    max_asset_bytes=len(_CONTENT) - 1,
                    _pinned_api_addresses=_API_ADDRESS,
                    _pinned_asset_addresses=_ASSET_ADDRESS,
                )

            release_request.assert_called_once()
            download.assert_not_called()
            with self.assertRaises(CASError):
                cas.verify(_DIGEST)

    def test_redirect_and_response_ambiguity_are_rejected(self) -> None:
        locations = (
            "http://release-assets.githubusercontent.com/path?token=x",
            "https://example.com/path?token=x",
            "https://user@release-assets.githubusercontent.com/path?token=x",
            "https://release-assets.githubusercontent.com:444/path?token=x",
            "https://release-assets.githubusercontent.com/path",
            "https://release-assets.githubusercontent.com/path?token=x#fragment",
        )
        for location in locations:
            redirect = _response(
                b"",
                status=302,
                headers={"Location": location, "Content-Length": "0"},
            )
            with (
                self.subTest(location=location),
                self.assertRaises(GitHubReleaseAssetError),
            ):
                self._acquire((redirect,))

        marker = "ephemeral-secret"
        for location in (
            f"https://{RELEASE_ASSET_HOST}/pa\tth?token={marker}",
            f"https://{RELEASE_ASSET_HOST}/páth?token={marker}",
        ):
            redirect = _response(
                b"",
                status=302,
                headers={"Location": location, "Content-Length": "0"},
            )
            with (
                self.subTest(location=location),
                self.assertRaises(GitHubReleaseAssetError) as raised,
            ):
                self._acquire((redirect,))
            self.assertNotIn(marker, str(raised.exception))
            self.assertNotIn(marker, repr(raised.exception))

        response_cases = (
            _response(headers={"Content-Encoding": "gzip"}),
            _response(headers={"Transfer-Encoding": "chunked"}),
            _response(headers={"Content-Type": "application/json"}),
            _response(headers={"Content-Length": str(len(_CONTENT) + 1)}),
            _response(_CONTENT[:-1]),
            _response(
                _CONTENT + b"UNACCOUNTED",
                headers={"Content-Length": str(len(_CONTENT))},
            ),
            _response(status=404),
        )
        duplicate_length = _response()
        duplicate_length.getheaders.return_value.append(
            ("Content-Length", str(len(_CONTENT)))
        )
        response_cases += (duplicate_length,)
        for response in response_cases:
            with (
                self.subTest(status=response.status),
                self.assertRaises(GitHubReleaseAssetError),
            ):
                self._acquire((response,))

        redirect = _response(
            b"",
            status=302,
            headers={
                "Location": f"https://{RELEASE_ASSET_HOST}/one?token=x",
                "Content-Length": "0",
            },
        )
        again = _response(
            b"",
            status=302,
            headers={
                "Location": f"https://{RELEASE_ASSET_HOST}/two?token=x",
                "Content-Length": "0",
            },
        )
        with self.assertRaises(GitHubReleaseAssetError):
            self._acquire((redirect, again))

    def test_release_transport_requires_pins_and_enforces_deadlines(self) -> None:
        with (
            patch.object(github_acquire.http.client, "HTTPSConnection") as connection,
            self.assertRaises(github_acquire.GitHubAcquisitionError),
        ):
            github_acquire._request_bytes(
                RELEASE_ASSET_HOST,
                "/asset?token=secret",
                method="GET",
                headers={},
                media_types={"application/octet-stream"},
                max_bytes=1,
                timeout_seconds=1.0,
                budget=github_acquire._RequestBudget(1, 1),
            )
        connection.assert_not_called()

        unblock = threading.Event()
        endpoints = github_acquire._PinnedEndpoints(host=RELEASE_ASSET_HOST)

        def blocked_resolution(_host: str) -> tuple:
            unblock.wait()
            return ()

        try:
            with (
                patch.object(
                    github_acquire,
                    "_resolve_public_host_endpoints",
                    side_effect=blocked_resolution,
                ),
                self.assertRaisesRegex(
                    github_acquire.GitHubAcquisitionError,
                    "resolution deadline",
                ),
            ):
                endpoints.get(deadline=time.monotonic() + 0.01)
        finally:
            unblock.set()

        response = _response(b"ab")
        connection = _connection(response)
        with (
            patch.object(
                github_acquire.time,
                "monotonic",
                side_effect=(0.0, 2.0),
            ),
            self.assertRaises(OSError),
        ):
            github_acquire._read_response_before_deadline(
                response,
                connection,
                max_bytes=2,
                deadline=1.0,
            )
        response.read1.assert_called_once()

    def test_missing_github_digest_still_uses_observed_cas_identity(self) -> None:
        result, cas, _connections = self._acquire(
            (_response(),),
            metadata=_metadata(digest=None),
        )

        self.assertIsNone(result["asset"]["github_digest"])
        self.assertEqual(result["asset"]["digest"], _DIGEST)
        self.assertEqual(cas.read(_DIGEST), _CONTENT)

    def test_checked_in_live_retention_replays_and_rejects_forgery(self) -> None:
        evidence = (
            _ROOT
            / "benchmark"
            / "evidence"
            / "phase1-github-release-asset-astral-sh-uv-0.12.0-sha256.sum"
        ).read_bytes()
        receipt_path = (
            _ROOT
            / "benchmark"
            / "receipts"
            / "phase1-github-release-asset-live-retention-2026-07-29.json"
        )
        result = json.loads(receipt_path.read_bytes())
        with tempfile.TemporaryDirectory() as temporary:
            writable = CAS(Path(temporary) / "cas")
            writable.put_expected(
                BytesIO(evidence),
                expected_digest=result["asset"]["digest"],
                max_bytes=len(evidence),
            )
            replay = verify_github_release_asset_result(
                result,
                evidence_cas=CAS(writable.root, read_only=True),
                expected_url=_URL,
                expected_release_id=361308705,
                expected_asset_id=493071343,
                expected_digest=(
                    "sha256:"
                    "625cade2a341d2dceaf8197e51c7271728060b729f64670562d0a74df303ef73"
                ),
                expected_github_digest=(
                    "sha256:"
                    "625cade2a341d2dceaf8197e51c7271728060b729f64670562d0a74df303ef73"
                ),
                expected_content_type="application/octet-stream",
                expected_redirected=True,
            )
            forged = deepcopy(result)
            forged["asset"]["asset_id"] += 1
            with self.assertRaises(GitHubReleaseAssetError):
                verify_github_release_asset_result(
                    forged,
                    evidence_cas=CAS(writable.root, read_only=True),
                    expected_url=_URL,
                    expected_release_id=361308705,
                    expected_asset_id=493071343,
                    expected_digest=result["asset"]["digest"],
                    expected_github_digest=result["asset"]["github_digest"],
                    expected_content_type=result["asset"]["content_type"],
                    expected_redirected=result["transport"]["redirected"],
                )
            omitted_metadata_digest = deepcopy(result)
            omitted_metadata_digest["asset"]["github_digest"] = None
            with self.assertRaises(GitHubReleaseAssetError):
                verify_github_release_asset_result(
                    omitted_metadata_digest,
                    evidence_cas=CAS(writable.root, read_only=True),
                    expected_url=_URL,
                    expected_release_id=361308705,
                    expected_asset_id=493071343,
                    expected_digest=result["asset"]["digest"],
                    expected_github_digest=result["asset"]["github_digest"],
                    expected_content_type=result["asset"]["content_type"],
                    expected_redirected=result["transport"]["redirected"],
                )
            with self.assertRaises(GitHubReleaseAssetError):
                verify_github_release_asset_result(
                    result,
                    evidence_cas=writable,
                    expected_url=_URL,
                    expected_release_id=361308705,
                    expected_asset_id=493071343,
                    expected_digest=result["asset"]["digest"],
                    expected_github_digest=result["asset"]["github_digest"],
                    expected_content_type=result["asset"]["content_type"],
                    expected_redirected=result["transport"]["redirected"],
                )
            with self.assertRaises(GitHubReleaseAssetError):
                verify_github_release_asset_result(
                    result,
                    evidence_cas=CAS(writable.root, read_only=True),
                    expected_url=_URL,
                    expected_release_id=361308705,
                    expected_asset_id=493071343,
                    expected_digest=result["asset"]["digest"],
                    expected_github_digest="sha256:" + "0" * 64,
                    expected_content_type=result["asset"]["content_type"],
                    expected_redirected=result["transport"]["redirected"],
                )

            for key, value in (
                ("content_type", "application/forged"),
                ("transport", False),
            ):
                forged = deepcopy(result)
                if key == "content_type":
                    forged["asset"][key] = value
                else:
                    forged[key]["redirected"] = value
                    forged[key]["final_host"] = API_HOST
                with (
                    self.subTest(key=key),
                    self.assertRaises(GitHubReleaseAssetError),
                ):
                    verify_github_release_asset_result(
                        forged,
                        evidence_cas=CAS(writable.root, read_only=True),
                        expected_url=_URL,
                        expected_release_id=361308705,
                        expected_asset_id=493071343,
                        expected_digest=result["asset"]["digest"],
                        expected_github_digest=result["asset"]["github_digest"],
                        expected_content_type=result["asset"]["content_type"],
                        expected_redirected=result["transport"]["redirected"],
                    )

        self.assertEqual(replay, result)
        self.assertEqual(
            receipt_path.read_bytes(),
            canonical_json(result) + b"\n",
        )


if __name__ == "__main__":
    unittest.main()
