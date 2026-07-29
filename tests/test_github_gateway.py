from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext
from io import BytesIO
from pathlib import Path
from unittest import mock

from aragorn import github_gateway
from aragorn.artifact_closure import canonical_json, load_verified_retained_manifest
from aragorn.cas import CAS
from aragorn.github_gateway import (
    GatewayQuarantineReceipt,
    GitHubGatewayError,
    build_gateway_request,
    quarantine_through_gateway,
    run_worker,
)
from aragorn.github_source_proof import retain_github_source_proof
from aragorn.oci_runtime import _ProcessResult, _run_bounded


def _git_oid(object_type: str, payload: bytes) -> str:
    header = f"{object_type} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _tree_entry(mode: bytes, name: bytes, oid: str) -> bytes:
    return mode + b" " + name + b"\0" + bytes.fromhex(oid)


_CONTENT = b"# inert skill\n"
_BLOB_OID = _git_oid("blob", _CONTENT)
_SKILL_TREE_PAYLOAD = _tree_entry(b"100644", b"SKILL.md", _BLOB_OID)
_SKILL_TREE_OID = _git_oid("tree", _SKILL_TREE_PAYLOAD)
_ROOT_TREE_PAYLOAD = _tree_entry(b"40000", b"demo", _SKILL_TREE_OID)
_ROOT_TREE_OID = _git_oid("tree", _ROOT_TREE_PAYLOAD)
_COMMIT_PAYLOAD = (
    f"tree {_ROOT_TREE_OID}\n".encode("ascii")
    + b"author Fixture <fixture@example.test> 1 +0000\n"
    + b"committer Fixture <fixture@example.test> 1 +0000\n\nfixture\n"
)
COMMIT = _git_oid("commit", _COMMIT_PAYLOAD)
_PYTHON_DIGEST = "sha256:" + "a" * 64
_PACKAGE_DIGEST = "sha256:" + "b" * 64
_ACCEPTANCE_MEASUREMENTS = {
    "containment_profile": github_gateway.LINUX_CONTAINMENT_PROFILE,
    "python_executable_digest": _PYTHON_DIGEST,
    "gateway_package_tree_digest": _PACKAGE_DIGEST,
}
_GATEWAY_PROFILE_DIGEST = github_gateway.github_gateway_profile_digest(
    **_ACCEPTANCE_MEASUREMENTS,
)


class GitHubGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.request = build_gateway_request(
            "example",
            "skills",
            COMMIT,
            "demo",
        )

    def test_quarantine_receipt_keeps_legacy_constructor_shape(self) -> None:
        receipt = GatewayQuarantineReceipt(
            "authority",
            "assurance",
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
            "sha256:" + "3" * 64,
            1,
            "sha256:" + "4" * 64,
            Path("/quarantine"),
        )
        self.assertIsNone(receipt.source_proof_digest)
        self.assertIsNone(receipt.quarantine_receipt_digest)
        self.assertIsNone(receipt.gateway_profile_digest)

    def test_worker_is_credential_free_and_broker_reverifies_exact_closure(
        self,
    ) -> None:
        gateway = self.root / "gateway"
        gateway.mkdir(mode=0o700)
        job = gateway / "job"
        with mock.patch.object(
            github_gateway,
            "acquire_github_commit",
            side_effect=self._fake_acquire,
        ) as acquire:
            result = run_worker(
                self.request,
                job,
                pinned_api_addresses=("1.1.1.1",),
                pinned_git_addresses=("8.8.8.8",),
            )

        acquire.assert_called_once()
        positional, keywords = acquire.call_args
        self.assertEqual(
            positional[:3],
            ("https://github.com/example/skills", COMMIT, "demo"),
        )
        self.assertIsInstance(positional[3], CAS)
        self.assertEqual(
            keywords,
            {
                **github_gateway._FIXED_LIMITS,
                "bearer_token": None,
                "_pinned_addresses": ("1.1.1.1",),
                "_pinned_git_addresses": ("8.8.8.8",),
                "_retain_source_proof": True,
            },
        )
        self.assertEqual(
            result["request_digest"],
            github_gateway._digest(canonical_json(self.request)),
        )

        broker = self.root / "broker"
        broker.mkdir(mode=0o700)
        quarantine = broker / "quarantine"
        with mock.patch(
            "aragorn.github_quarantine_receipt.sys.platform",
            "linux",
        ):
            accepted = github_gateway._accept_gateway_output(
                self.request,
                result,
                job_root=job,
                quarantine_state=quarantine,
                worker_uid=os.geteuid(),
                **_ACCEPTANCE_MEASUREMENTS,
            )
        self.assertIsInstance(accepted, GatewayQuarantineReceipt)
        self.assertEqual(
            accepted.authority,
            github_gateway.QUARANTINE_AUTHORITY,
        )
        self.assertEqual(
            accepted.source_assurance,
            github_gateway.SOURCE_ASSURANCE,
        )
        self.assertEqual(accepted.file_count, 1)
        self.assertEqual(accepted.manifest_digest, result["manifest_digest"])
        self.assertEqual(
            accepted.source_proof_digest,
            result["source_proof_digest"],
        )
        self.assertIsNotNone(accepted.quarantine_receipt_digest)
        self.assertEqual(
            accepted.gateway_profile_digest,
            _GATEWAY_PROFILE_DIGEST,
        )
        with mock.patch(
            "aragorn.github_quarantine_receipt.sys.platform",
            "linux",
        ):
            retained_receipt = github_gateway.verify_github_quarantine_receipt(
                CAS(quarantine, read_only=True),
                accepted.quarantine_receipt_digest,
                expected_manifest_digest=accepted.manifest_digest,
                expected_gateway_profile_digest=_GATEWAY_PROFILE_DIGEST,
            )
            with self.assertRaisesRegex(
                ValueError,
                "gateway profile identity is untrusted",
            ):
                github_gateway.verify_github_quarantine_receipt(
                    CAS(quarantine, read_only=True),
                    accepted.quarantine_receipt_digest,
                    expected_manifest_digest=accepted.manifest_digest,
                    expected_gateway_profile_digest="sha256:" + "0" * 64,
                )
        quarantine_state = os.lstat(quarantine)
        self.assertEqual(
            retained_receipt["containment_profile"],
            github_gateway.LINUX_CONTAINMENT_PROFILE,
        )
        self.assertEqual(
            retained_receipt["gateway"],
            {
                "package_tree_digest": _PACKAGE_DIGEST,
                "python_executable_digest": _PYTHON_DIGEST,
            },
        )
        self.assertEqual(
            retained_receipt["gateway_profile_digest"],
            _GATEWAY_PROFILE_DIGEST,
        )
        CAS(quarantine, read_only=True).verify(
            retained_receipt["handoff_manifest_digest"],
        )
        self.assertEqual(
            retained_receipt["protected_cas"]["root_device"],
            quarantine_state.st_dev,
        )
        self.assertEqual(
            retained_receipt["protected_cas"]["root_inode"],
            quarantine_state.st_ino,
        )
        manifest = load_verified_retained_manifest(
            CAS(quarantine, read_only=True),
            accepted.manifest_digest,
        )
        self.assertEqual(manifest["source"]["commit"], COMMIT)
        self.assertEqual(manifest["files"][0]["path"], "SKILL.md")

    def test_wire_request_rejects_credentials_ambiguity_and_noncanonical_bytes(
        self,
    ) -> None:
        raw = canonical_json(self.request) + b"\n"
        self.assertEqual(github_gateway._decode_request_line(raw), self.request)

        credential_field = {**self.request, "token": "secret"}
        cases = (
            canonical_json(credential_field) + b"\n",
            canonical_json({**self.request, "owner": "user@example"}) + b"\n",
            canonical_json({**self.request, "repository": "UPPER"}) + b"\n",
            (
                b'{"schema":"aragorn/github-gateway-request/v1",'
                b'"schema":"aragorn/github-gateway-request/v1"}\n'
            ),
            b"{\n" + canonical_json(self.request)[1:] + b"\n",
            b"x" * github_gateway._MAX_WIRE_BYTES + b"\n",
        )
        for candidate in cases:
            with (
                self.subTest(candidate=candidate[:40]),
                self.assertRaises(GitHubGatewayError),
            ):
                github_gateway._decode_request_line(candidate)

    def test_broker_rejects_replayed_source_even_with_forged_request_binding(
        self,
    ) -> None:
        other = build_gateway_request("other", "skills", COMMIT, "demo")
        job = self.root / "replayed-job"

        def acquire_other(*args: object, **kwargs: object) -> dict:
            return self._fake_acquire(*args, source_request=other, **kwargs)

        with mock.patch.object(
            github_gateway,
            "acquire_github_commit",
            side_effect=acquire_other,
        ):
            result = run_worker(
                other,
                job,
                pinned_api_addresses=("1.1.1.1",),
                pinned_git_addresses=("8.8.8.8",),
            )
        forged = {
            **result,
            "request_digest": github_gateway._digest(canonical_json(self.request)),
        }

        quarantine = self.root / "replay-quarantine"
        with self.assertRaisesRegex(GitHubGatewayError, "source does not match"):
            github_gateway._accept_gateway_output(
                self.request,
                forged,
                job_root=job,
                quarantine_state=quarantine,
                worker_uid=os.geteuid(),
                **_ACCEPTANCE_MEASUREMENTS,
            )
        self.assertFalse(quarantine.exists())
        self.assertEqual(list(self.root.glob(".replay-quarantine.import-*")), [])

    def test_broker_rejects_handoff_missing_raw_source_proof(self) -> None:
        job = self.root / "missing-proof-job"
        with mock.patch.object(
            github_gateway,
            "acquire_github_commit",
            side_effect=self._fake_acquire,
        ):
            result = run_worker(
                self.request,
                job,
                pinned_api_addresses=("1.1.1.1",),
                pinned_git_addresses=("8.8.8.8",),
            )
        proof_path = (
            job
            / "bundle"
            / "blobs"
            / result["source_proof_digest"].removeprefix("sha256:")
        )
        proof_path.unlink()

        quarantine = self.root / "missing-proof-quarantine"
        with self.assertRaisesRegex(
            GitHubGatewayError,
            "gateway quarantine verification failed",
        ):
            github_gateway._accept_gateway_output(
                self.request,
                result,
                job_root=job,
                quarantine_state=quarantine,
                worker_uid=os.geteuid(),
                **_ACCEPTANCE_MEASUREMENTS,
            )
        self.assertFalse(quarantine.exists())

    def test_worker_cleanup_failure_prevents_quarantine_publication(self) -> None:
        job = self.root / "cleanup-job"
        with mock.patch.object(
            github_gateway,
            "acquire_github_commit",
            side_effect=self._fake_acquire,
        ):
            result = run_worker(
                self.request,
                job,
                pinned_api_addresses=("1.1.1.1",),
                pinned_git_addresses=("8.8.8.8",),
            )

        quarantine = self.root / "cleanup-quarantine"
        with (
            mock.patch.object(
                github_gateway,
                "_remove_worker_job",
                side_effect=GitHubGatewayError("cleanup failed"),
            ),
            self.assertRaisesRegex(GitHubGatewayError, "cleanup failed"),
        ):
            github_gateway._accept_gateway_output(
                self.request,
                result,
                job_root=job,
                quarantine_state=quarantine,
                worker_uid=os.geteuid(),
                **_ACCEPTANCE_MEASUREMENTS,
            )
        self.assertFalse(quarantine.exists())
        self.assertEqual(list(self.root.glob(".cleanup-quarantine.import-*")), [])

    def test_supervisor_requests_kernel_uid_drop_and_sanitized_launch(self) -> None:
        result = {
            "schema": github_gateway.RESULT_SCHEMA,
            "request_digest": "sha256:" + "1" * 64,
            "manifest_digest": "sha256:" + "2" * 64,
            "source_proof_digest": "sha256:" + "3" * 64,
            "handoff_manifest_digest": "sha256:" + "4" * 64,
        }
        process = _ProcessResult(
            canonical_json(result) + b"\n",
            b"",
            0,
        )
        resolver_process = _ProcessResult(
            canonical_json(
                {
                    "schema": github_gateway.ADDRESS_RESULT_SCHEMA,
                    "hosts": {
                        github_gateway.API_HOST: [
                            "1.1.1.1",
                            "2606:4700:4700::1111",
                        ],
                        github_gateway.GIT_HOST: ["8.8.8.8"],
                    },
                }
            )
            + b"\n",
            b"",
            0,
        )
        accepted = GatewayQuarantineReceipt(
            authority=github_gateway.QUARANTINE_AUTHORITY,
            source_assurance=github_gateway.SOURCE_ASSURANCE,
            request_digest=result["request_digest"],
            manifest_digest=result["manifest_digest"],
            source_proof_digest=result["source_proof_digest"],
            tree_digest="sha256:" + "5" * 64,
            file_count=1,
            handoff_manifest_digest=result["handoff_manifest_digest"],
            quarantine_state=Path("/broker/quarantine"),
        )

        with (
            mock.patch.object(github_gateway, "_broker_euid", return_value=0),
            mock.patch.object(
                github_gateway,
                "_prepare_paths",
                return_value=(Path("/gateway"), Path("/broker/quarantine")),
            ),
            mock.patch.object(
                github_gateway,
                "_trusted_python_executable",
                return_value=Path("/usr/bin/python3"),
            ),
            mock.patch.object(
                github_gateway,
                "_trusted_package_root",
                return_value=Path("/opt/aragorn-gateway"),
            ),
            mock.patch.object(
                github_gateway,
                "_gateway_runtime_measurements",
                return_value=(_PYTHON_DIGEST, _PACKAGE_DIGEST),
            ),
            mock.patch.object(
                github_gateway,
                "_require_gateway_runtime_unchanged",
            ),
            mock.patch.object(
                github_gateway,
                "_exclusive_uid_lease",
                return_value=nullcontext(),
            ) as lease,
            mock.patch.object(github_gateway, "_require_gateway_entries"),
            mock.patch.object(github_gateway, "_require_idle_uid") as idle_uid,
            mock.patch.object(
                github_gateway.secrets,
                "token_hex",
                return_value="f" * 32,
            ),
            mock.patch.object(
                github_gateway,
                "_run_bounded",
                side_effect=(
                    resolver_process,
                    process,
                    resolver_process,
                    _ProcessResult(b"", b"", -9, timed_out=True),
                ),
            ) as launch,
            mock.patch.object(
                github_gateway,
                "_run_gateway_process",
                wraps=github_gateway._run_gateway_process,
            ) as gateway_launch,
            mock.patch.object(
                github_gateway,
                "_accept_gateway_output",
                return_value=accepted,
            ) as accept,
            mock.patch.object(github_gateway, "_remove_worker_job"),
        ):
            observed = quarantine_through_gateway(
                self.request,
                gateway_root="/gateway",
                quarantine_state="/broker/quarantine",
                worker_uid=501,
                worker_gid=20,
                python_executable="/usr/bin/python3",
                package_root="/opt/aragorn-gateway",
            )
            with self.assertRaisesRegex(
                GitHubGatewayError,
                "process-group wall-clock",
            ):
                quarantine_through_gateway(
                    self.request,
                    gateway_root="/gateway",
                    quarantine_state="/broker/quarantine",
                    worker_uid=501,
                    worker_gid=20,
                    python_executable="/usr/bin/python3",
                    package_root="/opt/aragorn-gateway",
                )

        self.assertEqual(observed, accepted)
        arguments, options = launch.call_args
        self.assertEqual(
            launch.call_args_list[0].args[0],
            (
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                github_gateway._ISOLATED_ENTRYPOINT,
                "501",
                "20",
                "/opt/aragorn-gateway",
                "resolve",
            ),
        )
        self.assertEqual(
            arguments[0],
            (
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                github_gateway._ISOLATED_ENTRYPOINT,
                "501",
                "20",
                "/opt/aragorn-gateway",
                "worker",
                "--job-root",
                "/gateway/job-" + "f" * 32,
                "--api-endpoint",
                "1.1.1.1",
                "--api-endpoint",
                "2606:4700:4700::1111",
                "--git-endpoint",
                "8.8.8.8",
            ),
        )
        self.assertEqual(
            gateway_launch.call_args_list[1].kwargs["allowed_addresses"],
            ("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"),
        )
        self.assertEqual(options["user"], 501)
        self.assertEqual(options["group"], 20)
        self.assertEqual(options["extra_groups"], ())
        self.assertEqual(options["umask"], 0o077)
        self.assertEqual(options["cwd"], os.path.sep)
        self.assertEqual(
            set(options["env"]),
            {"HOME", "LANG", "LC_ALL", "PATH", "PYTHONDONTWRITEBYTECODE", "TZ"},
        )
        self.assertEqual(launch.call_count, 4)
        self.assertEqual(
            lease.call_args_list,
            [
                mock.call(github_gateway._UID_LEASE_ROOT, 501),
                mock.call(github_gateway._UID_LEASE_ROOT, 501),
            ],
        )
        self.assertNotIn("SSL_CERT_FILE", options["env"])
        self.assertNotIn("HTTPS_PROXY", options["env"])
        self.assertEqual(
            idle_uid.call_args_list,
            [
                mock.call(501, "before launch"),
                mock.call(501, "after resolver shutdown"),
                mock.call(501, "after worker shutdown"),
                mock.call(501, "before launch"),
                mock.call(501, "after resolver shutdown"),
                mock.call(501, "after worker shutdown"),
            ],
        )
        accept.assert_called_once()

    def test_recursive_worker_alone_receives_release_asset_network_pins(
        self,
    ) -> None:
        resolver_process = _ProcessResult(
            canonical_json(
                {
                    "schema": github_gateway.ADDRESS_RESULT_SCHEMA,
                    "hosts": {
                        github_gateway.API_HOST: ["1.1.1.1"],
                        github_gateway.GIT_HOST: ["8.8.8.8"],
                        github_gateway.RELEASE_ASSET_HOST: ["9.9.9.9"],
                    },
                }
            )
            + b"\n",
            b"",
            0,
        )
        worker_process = _ProcessResult(b"{}\n", b"", 0)
        accepted = object()
        broker_pins = {
            (
                "https://github.com/example/skills/releases/"
                "download/v1/checksums.txt"
            ): {
                "release_id": 1,
                "asset_id": 2,
                "digest": "sha256:" + "4" * 64,
                "github_digest": "sha256:" + "4" * 64,
                "content_type": "application/octet-stream",
                "redirected": True,
            }
        }
        with (
            mock.patch.object(github_gateway, "_broker_euid", return_value=0),
            mock.patch.object(
                github_gateway,
                "_prepare_paths",
                return_value=(Path("/gateway"), Path("/broker/quarantine")),
            ),
            mock.patch.object(
                github_gateway,
                "_trusted_python_executable",
                return_value=Path("/usr/bin/python3"),
            ),
            mock.patch.object(
                github_gateway,
                "_trusted_package_root",
                return_value=Path("/opt/aragorn-gateway"),
            ),
            mock.patch.object(
                github_gateway,
                "_gateway_runtime_measurements",
                return_value=(_PYTHON_DIGEST, _PACKAGE_DIGEST),
            ),
            mock.patch.object(github_gateway, "_require_gateway_runtime_unchanged"),
            mock.patch.object(
                github_gateway,
                "_exclusive_uid_lease",
                return_value=nullcontext(),
            ),
            mock.patch.object(github_gateway, "_require_gateway_entries"),
            mock.patch.object(github_gateway, "_require_idle_uid"),
            mock.patch.object(
                github_gateway.secrets,
                "token_hex",
                return_value="e" * 32,
            ),
            mock.patch.object(
                github_gateway,
                "_run_gateway_process",
                side_effect=(resolver_process, worker_process),
            ) as launch,
            mock.patch.object(github_gateway, "_remove_worker_job"),
            mock.patch(
                "aragorn.github_recursive_gateway.require_recursive_success_result",
                return_value={"schema": "recursive-result"},
            ),
            mock.patch(
                "aragorn.github_recursive_gateway.accept_recursive_gateway_output",
                return_value=accepted,
            ) as accept,
        ):
            observed = github_gateway._quarantine_through_gateway(
                self.request,
                gateway_root="/gateway",
                quarantine_state="/broker/quarantine",
                worker_uid=501,
                worker_gid=20,
                process_timeout_seconds=130.0,
                python_executable="/usr/bin/python3",
                package_root="/opt/aragorn-gateway",
                recursive=True,
                broker_release_asset_pins=broker_pins,
            )

        self.assertIs(observed, accepted)
        resolver_command = launch.call_args_list[0].args[0]
        self.assertEqual(
            resolver_command[-2:],
            ("resolve", "--include-release-asset"),
        )
        worker_command = launch.call_args_list[1].args[0]
        self.assertEqual(
            worker_command[-9:],
            (
                "recursive-worker",
                "--job-root",
                "/gateway/job-" + "e" * 32,
                "--api-endpoint",
                "1.1.1.1",
                "--git-endpoint",
                "8.8.8.8",
                "--release-asset-endpoint",
                "9.9.9.9",
            ),
        )
        self.assertEqual(
            launch.call_args_list[1].kwargs["allowed_addresses"],
            ("1.1.1.1", "8.8.8.8", "9.9.9.9"),
        )
        self.assertEqual(
            accept.call_args.kwargs["release_asset_pins"],
            broker_pins,
        )
        self.assertNotIn(
            broker_pins[
                (
                    "https://github.com/example/skills/releases/"
                    "download/v1/checksums.txt"
                )
            ]["digest"],
            worker_command,
        )
        self.assertNotIn(
            "--release-asset-endpoint",
            github_gateway._gateway_command(
                Path("/usr/bin/python3"),
                Path("/opt/aragorn-gateway"),
                501,
                20,
                "worker",
                "--job-root",
                "/gateway/job",
                "--api-endpoint",
                "1.1.1.1",
                "--git-endpoint",
                "8.8.8.8",
            ),
        )

    def test_release_asset_resolution_and_flag_are_recursive_only(self) -> None:
        addresses = {
            github_gateway.API_HOST: ("1.1.1.1",),
            github_gateway.GIT_HOST: ("8.8.8.8",),
            github_gateway.RELEASE_ASSET_HOST: ("9.9.9.9",),
        }
        with (
            mock.patch.object(github_gateway, "_require_worker_process_limit"),
            mock.patch.object(
                github_gateway,
                "_resolve_public_host_addresses",
                side_effect=lambda host: addresses[host],
            ) as resolve,
        ):
            ordinary = github_gateway._resolver_command(
                mock.Mock(include_release_asset=False)
            )
            recursive = github_gateway._resolver_command(
                mock.Mock(include_release_asset=True)
            )

        self.assertEqual(
            set(ordinary["hosts"]),
            {github_gateway.API_HOST, github_gateway.GIT_HOST},
        )
        self.assertEqual(
            set(recursive["hosts"]),
            {
                github_gateway.API_HOST,
                github_gateway.GIT_HOST,
                github_gateway.RELEASE_ASSET_HOST,
            },
        )
        self.assertEqual(resolve.call_count, 5)

        recursive_args = github_gateway._parser().parse_args(
            (
                "recursive-worker",
                "--job-root",
                "/gateway/job",
                "--api-endpoint",
                "1.1.1.1",
                "--git-endpoint",
                "8.8.8.8",
                "--release-asset-endpoint",
                "9.9.9.9",
            )
        )
        self.assertEqual(recursive_args.release_asset_endpoint, ["9.9.9.9"])
        with self.assertRaises(GitHubGatewayError):
            github_gateway._parser().parse_args(
                (
                    "worker",
                    "--job-root",
                    "/gateway/job",
                    "--api-endpoint",
                    "1.1.1.1",
                    "--git-endpoint",
                    "8.8.8.8",
                    "--release-asset-endpoint",
                    "9.9.9.9",
                )
            )

    def test_broker_rejects_untrusted_resolver_output(self) -> None:
        valid_hosts = {
            github_gateway.API_HOST: ["1.1.1.1"],
            github_gateway.GIT_HOST: ["8.8.8.8"],
        }
        cases = (
            {
                github_gateway.API_HOST: ["1.1.1.1"],
            },
            {
                github_gateway.API_HOST: ["1.1.1.1", "1.1.1.1"],
                github_gateway.GIT_HOST: ["8.8.8.8"],
            },
            {
                github_gateway.API_HOST: [
                    "2606:4700:4700::1111",
                    "1.1.1.1",
                ],
                github_gateway.GIT_HOST: ["8.8.8.8"],
            },
            {
                github_gateway.API_HOST: ["1.1.1.1"],
                github_gateway.GIT_HOST: ["2001:0db8::1"],
            },
        )
        for hosts in cases:
            raw = (
                canonical_json(
                    {
                        "schema": github_gateway.ADDRESS_RESULT_SCHEMA,
                        "hosts": hosts,
                    }
                )
                + b"\n"
            )
            with (
                self.subTest(hosts=hosts),
                self.assertRaises(GitHubGatewayError),
            ):
                github_gateway._decode_address_result_line(raw)

        noncanonical_key_order = (
            b'{"hosts":{"github.com":["8.8.8.8"],'
            b'"api.github.com":["1.1.1.1"]},'
            b'"schema":"aragorn/github-gateway-address-result/v2"}\n'
        )
        duplicate = (
            b'{"hosts":{"api.github.com":["1.1.1.1"],'
            b'"api.github.com":["8.8.8.8"],"github.com":["8.8.8.8"]},'
            b'"schema":"aragorn/github-gateway-address-result/v2"}\n'
        )
        for raw in (noncanonical_key_order, duplicate):
            with self.assertRaises(GitHubGatewayError):
                github_gateway._decode_address_result_line(raw)

        self.assertEqual(
            github_gateway._decode_address_result_line(
                canonical_json(
                    {
                        "schema": github_gateway.ADDRESS_RESULT_SCHEMA,
                        "hosts": valid_hosts,
                    }
                )
                + b"\n"
            ),
            {
                github_gateway.API_HOST: ("1.1.1.1",),
                github_gateway.GIT_HOST: ("8.8.8.8",),
            },
        )
        recursive_hosts = {
            **valid_hosts,
            github_gateway.RELEASE_ASSET_HOST: ["9.9.9.9"],
        }
        recursive_raw = (
            canonical_json(
                {
                    "schema": github_gateway.ADDRESS_RESULT_SCHEMA,
                    "hosts": recursive_hosts,
                }
            )
            + b"\n"
        )
        with self.assertRaises(GitHubGatewayError):
            github_gateway._decode_address_result_line(recursive_raw)
        self.assertEqual(
            github_gateway._decode_address_result_line(
                recursive_raw,
                recursive=True,
            ),
            {
                github_gateway.API_HOST: ("1.1.1.1",),
                github_gateway.GIT_HOST: ("8.8.8.8",),
                github_gateway.RELEASE_ASSET_HOST: ("9.9.9.9",),
            },
        )

    def test_isolated_entrypoint_imports_without_cwd_or_pythonpath(self) -> None:
        package_root = Path(github_gateway.__file__).resolve().parents[1]
        completed = self._run_isolated(
            github_gateway._gateway_command(
                Path(sys.executable),
                package_root,
                os.getuid(),
                os.getgid(),
                "--help",
            )
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(b"GitHub acquisition worker", completed.stdout)

        worker = self._run_isolated(
            github_gateway._gateway_command(
                Path(sys.executable),
                package_root,
                os.getuid(),
                os.getgid(),
                "worker",
                "--job-root",
                os.fspath(self.root / "unused-job"),
                "--api-endpoint",
                "1.1.1.1",
                "--git-endpoint",
                "8.8.8.8",
            )
        )
        self.assertEqual(worker.returncode, 4)
        self.assertIn(b"bounded canonical JSON line", worker.stderr)
        self.assertNotIn(b"process limit is not enforced", worker.stderr)

        unconfined = self._run_isolated(
            (
                sys.executable,
                "-I",
                "-S",
                "-c",
                (
                    "import sys;"
                    "sys.path.insert(0,sys.argv.pop(1));"
                    "from aragorn.github_gateway import main;"
                    "raise SystemExit(main())"
                ),
                os.fspath(package_root),
                "worker",
                "--job-root",
                os.fspath(self.root / "unused-job"),
                "--api-endpoint",
                "1.1.1.1",
                "--git-endpoint",
                "8.8.8.8",
            )
        )
        self.assertEqual(unconfined.returncode, 4)
        self.assertIn(b"process limit is not enforced", unconfined.stderr)

    def test_gateway_rejects_privileged_interpreter_and_identity_mismatch(
        self,
    ) -> None:
        executable = self.root / "python"
        executable.write_bytes(b"placeholder")
        executable.chmod(0o4755)
        with (
            mock.patch.object(
                github_gateway,
                "_broker_euid",
                return_value=os.geteuid(),
            ),
            mock.patch.object(github_gateway, "_require_protected_ancestors"),
            self.assertRaisesRegex(GitHubGatewayError, "privilege bits"),
        ):
            github_gateway._trusted_python_executable(executable)

        executable.chmod(0o755)
        with (
            mock.patch.object(
                github_gateway,
                "_broker_euid",
                return_value=os.geteuid(),
            ),
            mock.patch.object(github_gateway, "_require_protected_ancestors"),
            mock.patch.object(github_gateway.sys, "platform", "linux"),
            mock.patch.object(
                github_gateway.os,
                "getxattr",
                return_value=b"capability",
                create=True,
            ),
            self.assertRaisesRegex(GitHubGatewayError, "file capabilities"),
        ):
            github_gateway._trusted_python_executable(executable)

        with (
            mock.patch.object(github_gateway.sys, "platform", "linux"),
            mock.patch.object(github_gateway.os, "getxattr", None, create=True),
            self.assertRaisesRegex(GitHubGatewayError, "cannot verify"),
        ):
            github_gateway._reject_file_capabilities(executable)

        package_root = Path(github_gateway.__file__).resolve().parents[1]
        mismatch = self._run_isolated(
            github_gateway._gateway_command(
                Path(sys.executable),
                package_root,
                os.getuid() + 1,
                os.getgid(),
                "--help",
            )
        )
        self.assertEqual(mismatch.returncode, 70)

    def test_worker_uid_lease_and_process_census_fail_closed(self) -> None:
        self.assertEqual(
            github_gateway._parse_uid_census(
                b"  3   501\n  1     0\n  4    -2\n  2   501\n",
                501,
            ),
            (2, 3),
        )
        for raw in (
            b"",
            b"2 501\n",
            b"1 0\n1 501\n",
            b"1 root\n",
            b"\xff\n",
        ):
            with (
                self.subTest(raw=raw),
                self.assertRaises(GitHubGatewayError),
            ):
                github_gateway._parse_uid_census(raw, 501)

        with (
            mock.patch.object(
                github_gateway,
                "_broker_euid",
                return_value=os.geteuid(),
            ),
            github_gateway._exclusive_uid_lease(self.root, 501),
            self.assertRaisesRegex(GitHubGatewayError, "already leased"),
            github_gateway._exclusive_uid_lease(self.root, 501),
        ):
            pass

        with (
            mock.patch.object(
                github_gateway,
                "_uid_processes",
                return_value=(123,),
            ),
            self.assertRaisesRegex(GitHubGatewayError, "123"),
        ):
            github_gateway._require_idle_uid(501, "before launch")

    def test_gateway_root_rejects_unexpected_worker_entries(self) -> None:
        (self.root / "sibling").write_bytes(b"persistence")
        with self.assertRaisesRegex(
            GitHubGatewayError,
            "unexpected entries after worker shutdown",
        ):
            github_gateway._require_gateway_entries(
                self.root,
                ("expected-job",),
                worker_uid=os.geteuid(),
                stage="after worker shutdown",
            )

    def test_process_census_rejects_executable_identity_change(self) -> None:
        process = _ProcessResult(b"1 0\n", b"", 0)
        with (
            mock.patch.object(
                github_gateway,
                "_trusted_process_census_executable",
                return_value=(Path("/bin/ps"), ("sha256:" + "1" * 64, (1, 2, 3, 4))),
            ),
            mock.patch.object(
                github_gateway,
                "_run_bounded",
                return_value=process,
            ),
            mock.patch.object(
                github_gateway,
                "_hash_regular_file",
                return_value=("sha256:" + "2" * 64, (1, 2, 3, 4), 0o100755),
            ),
            self.assertRaisesRegex(GitHubGatewayError, "changed during use"),
        ):
            github_gateway._uid_processes(501)

    def test_supervisor_refuses_same_privilege_and_failed_processes(self) -> None:
        with (
            mock.patch.object(
                github_gateway,
                "_broker_euid",
                return_value=os.geteuid(),
            ),
            self.assertRaisesRegex(GitHubGatewayError, "privileged POSIX broker"),
        ):
            quarantine_through_gateway(
                self.request,
                gateway_root=self.root,
                quarantine_state=self.root / "unused",
                worker_uid=os.geteuid(),
                worker_gid=os.getegid(),
            )

        with self.assertRaisesRegex(GitHubGatewayError, "process-group wall-clock"):
            github_gateway._require_success_result(
                _ProcessResult(b"", b"", -9, timed_out=True)
            )
        with self.assertRaisesRegex(GitHubGatewayError, "output byte limit"):
            github_gateway._require_success_result(
                _ProcessResult(b"", b"", -9, output_exceeded=True)
            )

    def test_failed_gateway_surfaces_only_canonical_structured_error(self) -> None:
        structured = (
            canonical_json(
                {
                    "schema": "aragorn/error/v1",
                    "error": "GitHubExpansionError",
                    "message": "external artifact is unsupported",
                }
            )
            + b"\n"
        )
        with self.assertRaisesRegex(
            GitHubGatewayError,
            ("status 4: GitHubExpansionError: external artifact is unsupported"),
        ):
            github_gateway._require_success_output(_ProcessResult(b"", structured, 4))

        secret = "SHOULD_NOT_BE_SURFACED"
        malformed = (
            canonical_json(
                {
                    "schema": "aragorn/error/v1",
                    "error": "GitHubExpansionError",
                    "message": secret,
                    "unexpected": True,
                }
            )
            + b"\n"
        )
        oversized = (
            canonical_json(
                {
                    "schema": "aragorn/error/v1",
                    "error": "GitHubExpansionError",
                    "message": secret * 256,
                }
            )
            + b"\n"
        )
        for stderr in (b"", malformed, oversized):
            with (
                self.subTest(stderr=bool(stderr)),
                self.assertRaisesRegex(
                    GitHubGatewayError,
                    r"gateway exited unsuccessfully with status 4$",
                ) as raised,
            ):
                github_gateway._require_success_output(_ProcessResult(b"", stderr, 4))
            self.assertNotIn(secret, str(raised.exception))

    def test_shared_runner_bounds_process_group_deadline_and_output(self) -> None:
        timeout = _run_bounded(
            (sys.executable, "-I", "-c", "import time; time.sleep(60)"),
            timeout=0.05,
            stdout_limit=128,
            stderr_limit=128,
            shared_limit=256,
            env={"PATH": os.defpath},
            stdin_bytes=b"{}\n",
        )
        self.assertTrue(timeout.timed_out)

        overflow = _run_bounded(
            (
                sys.executable,
                "-I",
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 65536)",
            ),
            timeout=5.0,
            stdout_limit=128,
            stderr_limit=128,
            shared_limit=256,
            env={"PATH": os.defpath},
        )
        self.assertTrue(overflow.output_exceeded)
        self.assertLessEqual(len(overflow.stdout) + len(overflow.stderr), 256)

        descendant = _run_bounded(
            (
                sys.executable,
                "-I",
                "-c",
                (
                    "import subprocess,sys;"
                    "child=subprocess.Popen("
                    "[sys.executable,'-I','-c','import time;time.sleep(60)']);"
                    "print(child.pid,flush=True)"
                ),
            ),
            timeout=5.0,
            stdout_limit=128,
            stderr_limit=128,
            shared_limit=256,
            env={"PATH": os.defpath},
        )
        self.assertEqual(descendant.returncode, 0)
        self.assertIsNone(descendant.io_error)
        child_pid = int(descendant.stdout)
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            pass
        else:
            try:
                os.kill(child_pid, 9)
            except ProcessLookupError:
                pass
            self.fail("same-process-group descendant survived command completion")

    @staticmethod
    def _run_isolated(
        command: tuple[str, ...],
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            command,
            cwd=os.path.sep,
            env={
                "HOME": os.path.sep,
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.defpath,
                "PYTHONDONTWRITEBYTECODE": "1",
                "TZ": "UTC",
            },
            input=b"",
            capture_output=True,
            check=False,
            timeout=5.0,
        )

    def _fake_acquire(
        self,
        repository_url: str,
        commit: str,
        skill_path: str,
        cas: CAS,
        *,
        source_request: dict[str, str] | None = None,
        **kwargs: object,
    ) -> dict | tuple[dict, str]:
        request = self.request if source_request is None else source_request
        content = _CONTENT
        digest = cas.put(BytesIO(content), max_bytes=len(content))
        git_blob = _BLOB_OID
        files = [
            {
                "path": "SKILL.md",
                "size": len(content),
                "digest": digest,
                "git_blob_sha1": git_blob,
                "executable": False,
            }
        ]
        tree_files = [
            {
                "path": entry["path"],
                "size": entry["size"],
                "digest": entry["digest"],
                "executable": entry["executable"],
            }
            for entry in files
        ]
        manifest = {
            "schema": "aragorn/github-manifest/v1",
            "source": {
                "kind": "github_commit",
                "host": "github.com",
                "owner": request["owner"],
                "repository": request["repository"],
                "commit": request["commit"],
                "repository_hash_algorithm": "sha1",
                "commit_tree": _ROOT_TREE_OID,
                "skill_path": request["skill_path"],
                "skill_tree": _SKILL_TREE_OID,
                "api_version": "2026-03-10",
            },
            "tree_digest": github_gateway._digest(canonical_json(tree_files)),
            "files": files,
            "closure": {"scope": "source_tree", "status": "complete"},
        }
        if kwargs.get("_retain_source_proof") is not True:
            return manifest
        proof_digest = retain_github_source_proof(
            cas,
            manifest,
            {
                ("commit", COMMIT): _COMMIT_PAYLOAD,
                ("tree", _ROOT_TREE_OID): _ROOT_TREE_PAYLOAD,
                ("tree", _SKILL_TREE_OID): _SKILL_TREE_PAYLOAD,
            },
        )
        return manifest, proof_digest


if __name__ == "__main__":
    unittest.main()
