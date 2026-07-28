from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
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
from aragorn.oci_runtime import _ProcessResult, _run_bounded

COMMIT = "a" * 40


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

    def test_worker_is_credential_free_and_broker_reverifies_exact_closure(
        self,
    ) -> None:
        job = self.root / "job"
        with mock.patch.object(
            github_gateway,
            "acquire_github_commit",
            side_effect=self._fake_acquire,
        ) as acquire:
            result = run_worker(self.request, job)

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
            },
        )
        self.assertEqual(
            result["request_digest"],
            github_gateway._digest(canonical_json(self.request)),
        )

        quarantine = self.root / "broker-quarantine"
        accepted = github_gateway._accept_gateway_output(
            self.request,
            result,
            job_root=job,
            quarantine_state=quarantine,
            worker_uid=os.geteuid(),
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
            result = run_worker(other, job)
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
            )
        self.assertFalse(quarantine.exists())
        self.assertEqual(list(self.root.glob(".replay-quarantine.import-*")), [])

    def test_supervisor_requests_kernel_uid_drop_and_sanitized_launch(self) -> None:
        result = {
            "schema": github_gateway.RESULT_SCHEMA,
            "request_digest": "sha256:" + "1" * 64,
            "manifest_digest": "sha256:" + "2" * 64,
            "handoff_manifest_digest": "sha256:" + "3" * 64,
        }
        process = _ProcessResult(
            canonical_json(result) + b"\n",
            b"",
            0,
        )
        accepted = GatewayQuarantineReceipt(
            authority=github_gateway.QUARANTINE_AUTHORITY,
            source_assurance=github_gateway.SOURCE_ASSURANCE,
            request_digest=result["request_digest"],
            manifest_digest=result["manifest_digest"],
            tree_digest="sha256:" + "4" * 64,
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
                github_gateway.secrets,
                "token_hex",
                return_value="f" * 32,
            ),
            mock.patch.object(
                github_gateway,
                "_run_bounded",
                return_value=process,
            ) as launch,
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

        self.assertEqual(observed, accepted)
        arguments, options = launch.call_args
        self.assertEqual(
            arguments[0],
            (
                "/usr/bin/python3",
                "-I",
                "-c",
                github_gateway._ISOLATED_ENTRYPOINT,
                "/opt/aragorn-gateway",
                "worker",
                "--job-root",
                "/gateway/job-" + "f" * 32,
            ),
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
        self.assertNotIn("SSL_CERT_FILE", options["env"])
        self.assertNotIn("HTTPS_PROXY", options["env"])
        accept.assert_called_once()

    def test_isolated_entrypoint_imports_without_cwd_or_pythonpath(self) -> None:
        package_root = Path(github_gateway.__file__).resolve().parents[1]
        completed = subprocess.run(
            github_gateway._gateway_command(
                Path(sys.executable),
                package_root,
                "--help",
            ),
            cwd=os.path.sep,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.defpath,
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5.0,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(b"GitHub acquisition worker", completed.stdout)

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

    def _fake_acquire(
        self,
        repository_url: str,
        commit: str,
        skill_path: str,
        cas: CAS,
        *,
        source_request: dict[str, str] | None = None,
        **kwargs: object,
    ) -> dict:
        request = self.request if source_request is None else source_request
        content = b"# inert skill\n"
        digest = cas.put(BytesIO(content), max_bytes=len(content))
        git_blob = hashlib.sha1(
            f"blob {len(content)}\0".encode("ascii") + content
        ).hexdigest()
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
        return {
            "schema": "aragorn/github-manifest/v1",
            "source": {
                "kind": "github_commit",
                "host": "github.com",
                "owner": request["owner"],
                "repository": request["repository"],
                "commit": request["commit"],
                "repository_hash_algorithm": "sha1",
                "commit_tree": "b" * 40,
                "skill_path": request["skill_path"],
                "skill_tree": "c" * 40,
                "api_version": "2026-03-10",
            },
            "tree_digest": github_gateway._digest(canonical_json(tree_files)),
            "files": files,
            "closure": {"scope": "source_tree", "status": "complete"},
        }


if __name__ == "__main__":
    unittest.main()
