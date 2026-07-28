from __future__ import annotations

import base64
from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch


import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from aragorn.cas import CAS
from aragorn.cli import main
import aragorn.github_acquire as github_acquire
from aragorn.github_acquire import (
    API_HOST,
    API_VERSION,
    GitHubAcquisitionError,
    acquire_github_commit,
)


COMMIT = "a" * 40
ROOT_TREE = "b" * 40
SKILLS_TREE = "c" * 40
SKILL_TREE = "d" * 40
SCRIPTS_TREE = "e" * 40


def git_blob_sha(content: bytes) -> str:
    git_object = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    return hashlib.sha1(git_object).hexdigest()


def blob_document(content: bytes) -> dict[str, object]:
    return {
        "sha": git_blob_sha(content),
        "size": len(content),
        "encoding": "base64",
        "content": base64.encodebytes(content).decode("ascii"),
    }


def valid_responses(
    *,
    skill_content: bytes = b"# safe\n",
    script_content: bytes = b"#!/bin/sh\n",
) -> dict[str, dict[str, object]]:
    skill_blob = git_blob_sha(skill_content)
    script_blob = git_blob_sha(script_content)
    prefix = "/repos/example/project"
    return {
        f"{prefix}/hash-algorithm": {"hash_algorithm": "sha1"},
        f"{prefix}/git/commits/{COMMIT}": {
            "sha": COMMIT,
            "tree": {"sha": ROOT_TREE},
        },
        f"{prefix}/git/trees/{ROOT_TREE}": {
            "sha": ROOT_TREE,
            "truncated": False,
            "tree": [
                {
                    "path": "skills",
                    "mode": "040000",
                    "type": "tree",
                    "sha": SKILLS_TREE,
                }
            ],
        },
        f"{prefix}/git/trees/{SKILLS_TREE}": {
            "sha": SKILLS_TREE,
            "truncated": False,
            "tree": [
                {
                    "path": "demo",
                    "mode": "040000",
                    "type": "tree",
                    "sha": SKILL_TREE,
                }
            ],
        },
        f"{prefix}/git/trees/{SKILL_TREE}": {
            "sha": SKILL_TREE,
            "truncated": False,
            "tree": [
                {
                    "path": "scripts",
                    "mode": "040000",
                    "type": "tree",
                    "sha": SCRIPTS_TREE,
                },
                {
                    "path": "SKILL.md",
                    "mode": "100644",
                    "type": "blob",
                    "sha": skill_blob,
                    "size": len(skill_content),
                },
            ],
        },
        f"{prefix}/git/trees/{SCRIPTS_TREE}": {
            "sha": SCRIPTS_TREE,
            "truncated": False,
            "tree": [
                {
                    "path": "run.sh",
                    "mode": "100755",
                    "type": "blob",
                    "sha": script_blob,
                    "size": len(script_content),
                }
            ],
        },
        f"{prefix}/git/blobs/{skill_blob}": blob_document(skill_content),
        f"{prefix}/git/blobs/{script_blob}": blob_document(script_content),
    }


class GitHubAcquisitionTests(unittest.TestCase):
    def acquire(
        self,
        responses: dict[str, dict[str, object]],
        *,
        skill_path: str = "skills/demo",
        **limits: object,
    ) -> tuple[dict[str, object], CAS, list[str], tempfile.TemporaryDirectory[str]]:
        temporary = tempfile.TemporaryDirectory()
        cas = CAS(Path(temporary.name) / "state")
        calls: list[str] = []

        def request(path: str, **_kwargs: object) -> dict[str, object]:
            calls.append(path)
            if path not in responses:
                raise AssertionError(f"unexpected request: {path}")
            return responses[path]

        try:
            with patch.object(github_acquire, "_request_json", side_effect=request):
                manifest = acquire_github_commit(
                    "https://github.com/Example/Project",
                    COMMIT,
                    skill_path,
                    cas,
                    **limits,
                )
        except BaseException:
            temporary.cleanup()
            raise
        return manifest, cas, calls, temporary

    def test_exact_bytes_are_sha256_bound_and_manifest_is_deterministic(self) -> None:
        expected = {
            "SKILL.md": b"# safe\n",
            "scripts/run.sh": b"#!/bin/sh\n",
        }
        first, cas, calls, temporary = self.acquire(valid_responses())
        self.addCleanup(temporary.cleanup)
        second, _cas, second_calls, temporary2 = self.acquire(valid_responses())
        self.addCleanup(temporary2.cleanup)

        self.assertEqual(first, second)
        self.assertEqual(first["schema"], "aragorn/github-manifest/v1")
        self.assertEqual(
            first["source"],
            {
                "kind": "github_commit",
                "host": "github.com",
                "owner": "example",
                "repository": "project",
                "commit": COMMIT,
                "repository_hash_algorithm": "sha1",
                "commit_tree": ROOT_TREE,
                "skill_path": "skills/demo",
                "skill_tree": SKILL_TREE,
                "api_version": API_VERSION,
            },
        )
        self.assertEqual(
            first["closure"], {"scope": "source_tree", "status": "complete"}
        )
        self.assertEqual(
            expected,
            {
                entry["path"]: cas.read(entry["digest"])
                for entry in first["files"]
            },
        )
        self.assertEqual(
            [entry["executable"] for entry in first["files"]], [False, True]
        )
        self.assertFalse(any("?recursive" in path for path in calls + second_calls))

    def test_bearer_token_is_redacted_and_never_retained(self) -> None:
        token = "github_pat_private-evaluation-token"
        responses = valid_responses()
        observed_authorization_reprs: list[str] = []

        def request(path: str, **kwargs: object) -> dict[str, object]:
            observed_authorization_reprs.append(repr(kwargs["authorization"]))
            return responses[path]

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            cas = CAS(state)
            with patch.object(
                github_acquire,
                "_request_json",
                side_effect=request,
            ):
                manifest = acquire_github_commit(
                    "https://github.com/example/project",
                    COMMIT,
                    "skills/demo",
                    cas,
                    bearer_token=token,
                )
            retained = b"".join(
                path.read_bytes() for path in state.rglob("*") if path.is_file()
            )

        self.assertTrue(observed_authorization_reprs)
        self.assertTrue(
            all(
                value == "_BearerToken(<redacted>)"
                for value in observed_authorization_reprs
            )
        )
        self.assertNotIn(token, json.dumps(manifest, sort_keys=True))
        self.assertNotIn(token.encode("ascii"), retained)

    def test_invalid_bearer_tokens_fail_before_network_without_echo(self) -> None:
        invalid = (
            b"private-token",
            "",
            "private token",
            "private\ttoken",
            "private\ntoken",
            "private\x00token",
            "private\u00a0token",
            "private-\N{LATIN SMALL LETTER E WITH ACUTE}-token",
            "p" * 1025,
        )
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            for value in invalid:
                with self.subTest(value=repr(value)):
                    with patch.object(github_acquire, "_request_json") as request:
                        with self.assertRaises(GitHubAcquisitionError) as raised:
                            acquire_github_commit(
                                "https://github.com/example/project",
                                COMMIT,
                                "skills/demo",
                                cas,
                                bearer_token=value,
                            )
                    request.assert_not_called()
                    rendered = repr(raised.exception)
                    if isinstance(value, str) and len(value) > 8:
                        self.assertNotIn(value, rendered)
                    if isinstance(value, bytes):
                        self.assertNotIn(value.decode("ascii"), rendered)

    def test_repository_hash_algorithm_and_commit_are_exact(self) -> None:
        cases = (
            (
                "/repos/example/project/hash-algorithm",
                {"hash_algorithm": "sha256"},
                "object format",
            ),
            (
                f"/repos/example/project/git/commits/{COMMIT}",
                {"sha": "f" * 40, "tree": {"sha": ROOT_TREE}},
                "different commit",
            ),
        )
        for path, replacement, message in cases:
            with self.subTest(path=path):
                responses = valid_responses()
                responses[path] = replacement
                with self.assertRaisesRegex(GitHubAcquisitionError, message):
                    self.acquire(responses)

    def test_unsafe_source_inputs_are_rejected_before_network_or_state(self) -> None:
        invalid_repositories = (
            "http://github.com/example/project",
            "https://user@github.com/example/project",
            "https://github.com:443/example/project",
            "https://evil.example/example/project",
            "https://github.com/example/project.git",
            "https://github.com/example/PROJECT.GIT",
            "https://github.com/example/project/",
            "https://github.com/example/project?token=secret",
        )
        invalid_commits = ("A" * 40, "a" * 39, "../" + "a" * 40)
        invalid_paths = (
            "",
            "/skills/demo",
            "../demo",
            "skills\\demo",
            "skills//demo",
            "\ud800",
            "skills/e\u0301",
        )
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            for repository in invalid_repositories:
                with self.subTest(repository=repository):
                    with self.assertRaises(GitHubAcquisitionError):
                        acquire_github_commit(repository, COMMIT, "skills/demo", CAS(state))
            for commit in invalid_commits:
                with self.subTest(commit=commit):
                    with self.assertRaises(GitHubAcquisitionError):
                        acquire_github_commit(
                            "https://github.com/example/project",
                            commit,
                            "skills/demo",
                            CAS(state),
                        )
            for skill_path in invalid_paths:
                with self.subTest(skill_path=skill_path):
                    with self.assertRaises(GitHubAcquisitionError):
                        acquire_github_commit(
                            "https://github.com/example/project",
                            COMMIT,
                            skill_path,
                            CAS(state),
                        )

    def test_links_submodules_special_modes_and_unsafe_names_are_rejected(self) -> None:
        cases = (
            (
                {
                    "path": "link",
                    "mode": "120000",
                    "type": "blob",
                    "sha": "f" * 40,
                    "size": 6,
                },
                "symlink",
            ),
            (
                {
                    "path": "vendor",
                    "mode": "160000",
                    "type": "commit",
                    "sha": "f" * 40,
                },
                "submodule",
            ),
            (
                {
                    "path": "device",
                    "mode": "100600",
                    "type": "blob",
                    "sha": "f" * 40,
                    "size": 0,
                },
                "unsupported",
            ),
            (
                {
                    "path": "../escape",
                    "mode": "100644",
                    "type": "blob",
                    "sha": "f" * 40,
                    "size": 0,
                },
                "unsafe path",
            ),
        )
        tree_path = f"/repos/example/project/git/trees/{SKILL_TREE}"
        for entry, message in cases:
            with self.subTest(entry=entry):
                responses = valid_responses()
                responses[tree_path] = {
                    "sha": SKILL_TREE,
                    "truncated": False,
                    "tree": [entry],
                }
                with self.assertRaisesRegex(GitHubAcquisitionError, message):
                    self.acquire(responses)

    def test_truncated_and_duplicate_trees_are_rejected(self) -> None:
        tree_path = f"/repos/example/project/git/trees/{SKILL_TREE}"
        responses = valid_responses()
        responses[tree_path]["truncated"] = True
        with self.assertRaisesRegex(GitHubAcquisitionError, "truncated"):
            self.acquire(responses)

        responses = valid_responses()
        entry = responses[tree_path]["tree"][1]
        responses[tree_path]["tree"] = [entry, dict(entry)]
        with self.assertRaisesRegex(GitHubAcquisitionError, "duplicate"):
            self.acquire(responses)

    def test_portability_collisions_and_unsafe_unicode_names_are_rejected(self) -> None:
        tree_path = f"/repos/example/project/git/trees/{SKILL_TREE}"
        blob_sha = git_blob_sha(b"x")
        entry = {
            "mode": "100644",
            "type": "blob",
            "sha": blob_sha,
            "size": 1,
        }
        responses = valid_responses()
        responses[tree_path] = {
            "sha": SKILL_TREE,
            "truncated": False,
            "tree": [
                {"path": "README", **entry},
                {"path": "readme", **entry},
            ],
        }
        with self.assertRaisesRegex(GitHubAcquisitionError, "case folding"):
            self.acquire(responses)

        responses = valid_responses()
        responses[tree_path] = {
            "sha": SKILL_TREE,
            "truncated": False,
            "tree": [{"path": "e\u0301.txt", **entry}],
        }
        with self.assertRaisesRegex(GitHubAcquisitionError, "unsafe path"):
            self.acquire(responses)

        responses = valid_responses()
        responses[tree_path] = {
            "sha": SKILL_TREE,
            "truncated": False,
            "tree": [{"path": "safe\u202etxt", **entry}],
        }
        with self.assertRaisesRegex(GitHubAcquisitionError, "unsafe path"):
            self.acquire(responses)

    def test_lfs_pointer_and_blob_identity_mismatches_are_rejected(self) -> None:
        lfs = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + b"0" * 64 + b"\nsize 1\n"
        )
        with self.assertRaisesRegex(GitHubAcquisitionError, "LFS pointer"):
            self.acquire(valid_responses(skill_content=lfs))

        responses = valid_responses()
        blob_path = next(path for path in responses if "/git/blobs/" in path)
        responses[blob_path]["content"] = base64.b64encode(b"tampered").decode("ascii")
        with self.assertRaisesRegex(GitHubAcquisitionError, "byte size|SHA-1"):
            self.acquire(responses)

    def test_late_blob_failure_publishes_no_source_blob_to_cas(self) -> None:
        lfs = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + b"0" * 64 + b"\nsize 1\n"
        )
        responses = valid_responses(script_content=lfs)
        published: list[bytes] = []

        class RecordingCAS:
            def put(self, source: object, *, max_bytes: int) -> str:
                content = source.read(max_bytes + 1)
                published.append(content)
                return "sha256:" + hashlib.sha256(content).hexdigest()

        with patch.object(
            github_acquire,
            "_request_json",
            side_effect=lambda path, **_kwargs: responses[path],
        ):
            with self.assertRaisesRegex(GitHubAcquisitionError, "LFS pointer"):
                acquire_github_commit(
                    "https://github.com/example/project",
                    COMMIT,
                    "skills/demo",
                    RecordingCAS(),
                )

        self.assertEqual(published, [])

    def test_file_count_depth_file_size_and_total_size_are_bounded(self) -> None:
        cases = (
            ({"max_files": 2}, "file count"),
            ({"max_depth": 0}, "depth"),
            ({"max_file_size": 5}, "file size"),
            ({"max_total_bytes": 10}, "total byte"),
        )
        for limits, message in cases:
            with self.subTest(limits=limits):
                with self.assertRaisesRegex(GitHubAcquisitionError, message):
                    self.acquire(valid_responses(), **limits)

    def test_one_monotonic_deadline_is_shared_by_all_requests(self) -> None:
        responses = valid_responses()
        request_timeouts: list[float] = []

        def request(path: str, **kwargs: object) -> dict[str, object]:
            request_timeouts.append(float(kwargs["timeout_seconds"]))
            return responses[path]

        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            with patch.object(
                github_acquire.time,
                "monotonic",
                side_effect=(0.0, 0.0, 0.6, 0.6, 1.1),
            ):
                with patch.object(
                    github_acquire, "_request_json", side_effect=request
                ):
                    with self.assertRaisesRegex(
                        GitHubAcquisitionError, "deadline exceeded"
                    ):
                        acquire_github_commit(
                            "https://github.com/example/project",
                            COMMIT,
                            "skills/demo",
                            cas,
                            timeout_seconds=1.0,
                        )

        self.assertEqual(len(request_timeouts), 2)
        self.assertAlmostEqual(request_timeouts[0], 1.0)
        self.assertAlmostEqual(request_timeouts[1], 0.4)

    def test_acquisition_deadline_configuration_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            for value in (0, 600.1, float("inf"), float("nan"), True):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(
                        GitHubAcquisitionError, "timeout_seconds"
                    ):
                        acquire_github_commit(
                            "https://github.com/example/project",
                            COMMIT,
                            "skills/demo",
                            cas,
                            timeout_seconds=value,
                        )

    def test_cli_retains_the_github_manifest_in_cas(self) -> None:
        manifest = {
            "schema": "aragorn/github-manifest/v1",
            "source": {},
            "tree_digest": "sha256:" + "1" * 64,
            "files": [],
            "closure": {"scope": "source_tree", "status": "complete"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            stdout = StringIO()
            with patch("aragorn.cli.acquire_github_commit", return_value=manifest):
                with redirect_stdout(stdout):
                    status = main(
                        (
                            "acquire-github",
                            "https://github.com/example/project",
                            COMMIT,
                            "skills/demo",
                            "--state",
                            str(state),
                        )
                    )
            result = json.loads(stdout.getvalue())
            retained = json.loads(CAS(state).read(result["manifest_digest"]))

        self.assertEqual(status, 0)
        self.assertEqual(retained, manifest)
        self.assertEqual(result["closure"]["scope"], "source_tree")


class GitHubTransportTests(unittest.TestCase):
    def response(
        self,
        raw: bytes = b'{"hash_algorithm":"sha1"}',
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> MagicMock:
        response = MagicMock()
        response.status = status
        actual_headers = {
            "Content-Encoding": "identity",
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(raw)),
            **(headers or {}),
        }
        response.getheader.side_effect = (
            lambda name, default=None: actual_headers.get(name, default)
        )
        response.read.side_effect = lambda limit: raw[:limit]
        return response

    def test_transport_uses_fixed_host_headers_and_no_ambient_credentials_or_proxy(
        self,
    ) -> None:
        connection = MagicMock()
        connection.getresponse.return_value = self.response()
        environment = {
            "GH_TOKEN": "secret",
            "GITHUB_TOKEN": "secret",
            "HTTPS_PROXY": "https://proxy.invalid",
            "ALL_PROXY": "socks5://proxy.invalid",
            "NETRC": "/tmp/credentials",
            "SSLKEYLOGFILE": "/tmp/tls.keys",
        }
        with patch.dict(os.environ, environment, clear=True):
            with patch.object(
                github_acquire.http.client,
                "HTTPSConnection",
                return_value=connection,
            ) as constructor:
                result = github_acquire._request_json(
                    "/repos/example/project/hash-algorithm",
                    max_bytes=1024,
                    timeout_seconds=1.0,
                    budget=github_acquire._RequestBudget(1, 1024),
                )

        self.assertEqual(result, {"hash_algorithm": "sha1"})
        self.assertEqual(constructor.call_args.args, (API_HOST,))
        self.assertEqual(constructor.call_args.kwargs["timeout"], 1.0)
        context = constructor.call_args.kwargs["context"]
        self.assertIsNone(context.keylog_filename)
        _method, _path = connection.request.call_args.args
        headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(headers["Accept"], "application/vnd.github+json")
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["X-GitHub-Api-Version"], "2026-03-10")
        self.assertIn("User-Agent", headers)
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Proxy-Authorization", headers)
        connection.set_debuglevel.assert_called_once_with(0)
        connection.close.assert_called_once()

    def test_dns_is_public_only_and_resolved_once_per_session(self) -> None:
        public = (
            github_acquire.socket.AF_INET,
            github_acquire.socket.SOCK_STREAM,
            github_acquire.socket.IPPROTO_TCP,
            "",
            ("140.82.112.6", 443),
        )
        private = (
            github_acquire.socket.AF_INET,
            github_acquire.socket.SOCK_STREAM,
            github_acquire.socket.IPPROTO_TCP,
            "",
            ("127.0.0.1", 443),
        )
        multicast = (
            github_acquire.socket.AF_INET,
            github_acquire.socket.SOCK_STREAM,
            github_acquire.socket.IPPROTO_TCP,
            "",
            ("224.0.0.1", 443),
        )
        for unsafe in (private, multicast):
            with self.subTest(address=unsafe[4][0]), patch.object(
                github_acquire.socket,
                "getaddrinfo",
                return_value=[public, unsafe],
            ):
                with self.assertRaisesRegex(
                    GitHubAcquisitionError,
                    "non-global or non-unicast",
                ):
                    github_acquire._resolve_public_api_endpoints()

        endpoints = github_acquire._PinnedEndpoints()
        with patch.object(
            github_acquire.socket,
            "getaddrinfo",
            return_value=[public, public],
        ) as resolve:
            self.assertEqual(
                endpoints.get(),
                (
                    (
                        github_acquire.socket.AF_INET,
                        github_acquire.socket.SOCK_STREAM,
                        github_acquire.socket.IPPROTO_TCP,
                        ("140.82.112.6", 443),
                    ),
                ),
            )
            self.assertIs(endpoints.get(), endpoints.get())
        resolve.assert_called_once()

        too_many = [
            (*public[:4], (f"8.8.8.{index}", 443))
            for index in range(1, github_acquire._MAX_PINNED_ENDPOINTS + 2)
        ]
        with patch.object(
            github_acquire.socket,
            "getaddrinfo",
            return_value=too_many,
        ):
            with self.assertRaisesRegex(
                GitHubAcquisitionError,
                "too many addresses",
            ):
                github_acquire._resolve_public_api_endpoints()

    def test_exact_pinned_addresses_are_normalized_without_dns(self) -> None:
        responses = valid_responses()
        observed: list[tuple[github_acquire._Endpoint, ...]] = []

        def request(path: str, **kwargs: object) -> dict[str, object]:
            endpoints = kwargs["endpoints"]
            assert isinstance(endpoints, github_acquire._PinnedEndpoints)
            observed.append(endpoints.get())
            return responses[path]

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            github_acquire.socket,
            "getaddrinfo",
        ) as resolve, patch.object(
            github_acquire,
            "_request_json",
            side_effect=request,
        ):
            acquire_github_commit(
                "https://github.com/example/project",
                COMMIT,
                "skills/demo",
                CAS(Path(temporary) / "state"),
                _pinned_addresses=[
                    "2606:4700:4700::1111",
                    "8.8.8.8",
                    "1.1.1.1",
                    "8.8.8.8",
                ],
            )

        expected = (
            (
                github_acquire.socket.AF_INET,
                github_acquire.socket.SOCK_STREAM,
                github_acquire.socket.IPPROTO_TCP,
                ("1.1.1.1", 443),
            ),
            (
                github_acquire.socket.AF_INET,
                github_acquire.socket.SOCK_STREAM,
                github_acquire.socket.IPPROTO_TCP,
                ("8.8.8.8", 443),
            ),
            (
                github_acquire.socket.AF_INET6,
                github_acquire.socket.SOCK_STREAM,
                github_acquire.socket.IPPROTO_TCP,
                ("2606:4700:4700::1111", 443, 0, 0),
            ),
        )
        self.assertTrue(observed)
        self.assertTrue(all(item == expected for item in observed))
        resolve.assert_not_called()

    def test_exact_pinned_addresses_fail_closed_before_network(self) -> None:
        cases = (
            ((), "between 1 and 16"),
            (("8.8.8.8",) * 17, "between 1 and 16"),
            ((1,), "canonical IPv4 or IPv6"),
            (("8.8.8.8 ",), "canonical IPv4 or IPv6"),
            (("2001:4860:4860:0:0:0:0:8888",), "canonical IPv4 or IPv6"),
            (("127.0.0.1",), "global unicast"),
            (("::ffff:8.8.8.8",), "global unicast"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, (addresses, message) in enumerate(cases):
                with self.subTest(addresses=addresses), patch.object(
                    github_acquire,
                    "_request_json",
                ) as request:
                    with self.assertRaisesRegex(GitHubAcquisitionError, message):
                        acquire_github_commit(
                            "https://github.com/example/project",
                            COMMIT,
                            "skills/demo",
                            CAS(Path(temporary) / f"state-{index}"),
                            _pinned_addresses=addresses,
                        )
                    request.assert_not_called()

    def test_pinned_connection_uses_numeric_peer_and_github_sni(self) -> None:
        first_endpoint = (
            github_acquire.socket.AF_INET,
            github_acquire.socket.SOCK_STREAM,
            github_acquire.socket.IPPROTO_TCP,
            ("140.82.112.6", 443),
        )
        second_endpoint = (*first_endpoint[:3], ("140.82.112.7", 443))
        first_socket = MagicMock()
        first_socket.connect.side_effect = OSError("unreachable")
        second_socket = MagicMock()
        tls_socket = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value = tls_socket
        with patch.object(
            github_acquire.socket,
            "socket",
            side_effect=(first_socket, second_socket),
        ) as constructor, patch.object(
            github_acquire.time,
            "monotonic",
            side_effect=(10.0, 10.0, 10.4, 10.5),
        ):
            connection = github_acquire._PinnedHTTPSConnection(
                (first_endpoint, second_endpoint),
                timeout=1.0,
                context=context,
            )
            connection.connect()

        self.assertEqual(
            [item.args for item in constructor.call_args_list],
            [first_endpoint[:3], second_endpoint[:3]],
        )
        self.assertAlmostEqual(first_socket.settimeout.call_args.args[0], 1.0)
        self.assertEqual(
            len(second_socket.settimeout.call_args_list),
            2,
        )
        self.assertAlmostEqual(
            second_socket.settimeout.call_args_list[0].args[0],
            0.6,
        )
        self.assertAlmostEqual(
            second_socket.settimeout.call_args_list[1].args[0],
            0.5,
        )
        first_socket.connect.assert_called_once_with(first_endpoint[3])
        first_socket.close.assert_called_once()
        second_socket.connect.assert_called_once_with(second_endpoint[3])
        context.wrap_socket.assert_called_once_with(
            second_socket,
            server_hostname=API_HOST,
        )
        self.assertIs(connection.sock, tls_socket)

    def test_explicit_bearer_token_is_sent_only_to_the_fixed_transport(self) -> None:
        token = "github_pat_private-transport-token"
        authorization = github_acquire._validate_bearer_token(token)
        connection = MagicMock()
        connection.getresponse.return_value = self.response()
        with patch.object(
            github_acquire.http.client,
            "HTTPSConnection",
            return_value=connection,
        ) as constructor:
            result = github_acquire._request_json(
                "/repos/example/project/hash-algorithm",
                max_bytes=1024,
                timeout_seconds=1.0,
                budget=github_acquire._RequestBudget(1, 1024),
                authorization=authorization,
            )

        self.assertEqual(result, {"hash_algorithm": "sha1"})
        self.assertEqual(constructor.call_args.args, (API_HOST,))
        self.assertEqual(
            connection.request.call_args.args,
            ("GET", "/repos/example/project/hash-algorithm"),
        )
        headers = connection.request.call_args.kwargs["headers"]
        self.assertEqual(headers["Authorization"], f"Bearer {token}")
        self.assertNotIn("Proxy-Authorization", headers)
        self.assertNotIn(token, repr(authorization))

    def test_authenticated_transport_redacts_token_from_failures(self) -> None:
        token = "github_pat_private-error-token"
        authorization = github_acquire._validate_bearer_token(token)
        connection = MagicMock()
        connection.request.side_effect = OSError(f"transport echoed {token}")
        with patch.object(
            github_acquire.http.client,
            "HTTPSConnection",
            return_value=connection,
        ):
            with self.assertRaises(GitHubAcquisitionError) as raised:
                github_acquire._request_json(
                    "/repos/example/project/hash-algorithm",
                    max_bytes=1024,
                    timeout_seconds=1.0,
                    budget=github_acquire._RequestBudget(1, 1024),
                    authorization=authorization,
                )

        self.assertNotIn(token, str(raised.exception))
        self.assertNotIn(token, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_authenticated_response_errors_do_not_chain_token_text(self) -> None:
        token = "github_pat_private-response-token"
        authorization = github_acquire._validate_bearer_token(token)
        connection = MagicMock()
        connection.getresponse.return_value = self.response(
            headers={"Content-Length": token}
        )
        with patch.object(
            github_acquire.http.client,
            "HTTPSConnection",
            return_value=connection,
        ):
            with self.assertRaises(GitHubAcquisitionError) as raised:
                github_acquire._request_json(
                    "/repos/example/project/hash-algorithm",
                    max_bytes=1024,
                    timeout_seconds=1.0,
                    budget=github_acquire._RequestBudget(1, 1024),
                    authorization=authorization,
                )

        self.assertNotIn(token, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_transport_rejects_unvalidated_authorization_before_network(self) -> None:
        token = "github_pat_unvalidated-token"
        with patch.object(
            github_acquire.http.client,
            "HTTPSConnection",
        ) as constructor:
            with self.assertRaises(GitHubAcquisitionError) as raised:
                github_acquire._request_json(
                    "/repos/example/project/hash-algorithm",
                    max_bytes=1024,
                    timeout_seconds=1.0,
                    budget=github_acquire._RequestBudget(1, 1024),
                    authorization=token,
                )

        constructor.assert_not_called()
        self.assertNotIn(token, repr(raised.exception))

    def test_transport_rejects_ambient_ca_overrides_before_network(self) -> None:
        for variable in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            with self.subTest(variable=variable):
                with patch.dict(os.environ, {variable: ""}, clear=True):
                    with patch.object(
                        github_acquire.http.client,
                        "HTTPSConnection",
                    ) as constructor:
                        with self.assertRaisesRegex(
                            GitHubAcquisitionError,
                            f"ambient TLS trust overrides.*{variable}",
                        ):
                            github_acquire._request_json(
                                "/repos/example/project/hash-algorithm",
                                max_bytes=1024,
                                timeout_seconds=1.0,
                                budget=github_acquire._RequestBudget(1, 1024),
                            )
                constructor.assert_not_called()

    def test_tls_context_uses_only_compiled_ca_paths(self) -> None:
        paths = SimpleNamespace(
            openssl_cafile_env="SSL_CERT_FILE",
            openssl_cafile="/compiled/cert.pem",
            openssl_capath_env="SSL_CERT_DIR",
            openssl_capath="/compiled/certs",
        )
        context = MagicMock()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(
                github_acquire.ssl,
                "get_default_verify_paths",
                return_value=paths,
            ),
            patch.object(github_acquire.os.path, "isfile", return_value=True),
            patch.object(github_acquire.os.path, "isdir", return_value=True),
            patch.object(
                github_acquire.ssl,
                "SSLContext",
                return_value=context,
            ),
        ):
            result = github_acquire._server_tls_context()

        self.assertIs(result, context)
        self.assertEqual(
            context.minimum_version,
            github_acquire.ssl.TLSVersion.TLSv1_2,
        )
        context.load_verify_locations.assert_called_once_with(
            cafile="/compiled/cert.pem",
            capath="/compiled/certs",
        )
        context.load_default_certs.assert_not_called()

    def test_transport_rejects_redirects_compression_oversize_and_duplicate_json(
        self,
    ) -> None:
        cases = (
            (self.response(status=302), "status 302"),
            (
                self.response(headers={"Content-Encoding": "gzip"}),
                "compressed",
            ),
            (
                self.response(b"{}" * 20, headers={"Content-Length": "40"}),
                "byte limit",
            ),
            (
                self.response(
                    b"{}",
                    headers={"Content-Type": "application/json-malicious"},
                ),
                "not JSON",
            ),
            (
                self.response(b"{}", headers={"Content-Length": "3"}),
                "does not match",
            ),
            (self.response(b'{"a":1,"a":2}'), "duplicate JSON key"),
            (self.response(b'{"value":1e999}'), "non-finite JSON number"),
        )
        for response, message in cases:
            with self.subTest(message=message):
                connection = MagicMock()
                connection.getresponse.return_value = response
                with patch.object(
                    github_acquire.http.client,
                    "HTTPSConnection",
                    return_value=connection,
                ):
                    with self.assertRaisesRegex(GitHubAcquisitionError, message):
                        github_acquire._request_json(
                            "/repos/example/project/hash-algorithm",
                            max_bytes=16,
                            timeout_seconds=1.0,
                            budget=github_acquire._RequestBudget(1, 16),
                        )

    def test_transport_enforces_shared_request_and_raw_byte_budgets(self) -> None:
        connection = MagicMock()
        connection.getresponse.return_value = self.response(b'{"ok":true}')
        with patch.object(
            github_acquire.http.client,
            "HTTPSConnection",
            return_value=connection,
        ):
            request_budget = github_acquire._RequestBudget(1, 1024)
            github_acquire._request_json(
                "/repos/example/project/hash-algorithm",
                max_bytes=1024,
                timeout_seconds=1.0,
                budget=request_budget,
            )
            with self.assertRaisesRegex(GitHubAcquisitionError, "request count"):
                github_acquire._request_json(
                    "/repos/example/project/hash-algorithm",
                    max_bytes=1024,
                    timeout_seconds=1.0,
                    budget=request_budget,
                )

            byte_budget = github_acquire._RequestBudget(2, 15)
            github_acquire._request_json(
                "/repos/example/project/hash-algorithm",
                max_bytes=1024,
                timeout_seconds=1.0,
                budget=byte_budget,
            )
            with self.assertRaisesRegex(GitHubAcquisitionError, "byte limit"):
                github_acquire._request_json(
                    "/repos/example/project/hash-algorithm",
                    max_bytes=1024,
                    timeout_seconds=1.0,
                    budget=byte_budget,
                )


if __name__ == "__main__":
    unittest.main()
