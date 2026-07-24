from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from io import BytesIO, StringIO
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from aragorn.cas import CAS, CASError
from aragorn import oci_benchmark_runner as benchmark_runner
from aragorn import oci_runtime as runtime
from aragorn import oci_worker as worker
from aragorn.oci_worker_protocol import (
    build_worker_request,
    canonical_digest,
    canonical_json,
    validate_worker_result,
    verify_request_result_binding,
)
from tests import test_oci_benchmark_runner as runner_support


CISCO_IMPLEMENTATION = (
    "sha256:7fadcfbe836eef9490feba0fadd2ada564c11eb541077e3efee5f61edbd2e65c"
)


def _local_prepared(root: Path) -> benchmark_runner._PreparedBaseline:
    base = runner_support.prepared_cisco()
    docker_path = root / "docker"
    docker_bytes = b"#!/bin/sh\nexit 0\n"
    docker_path.write_bytes(docker_bytes)
    docker_path.chmod(0o700)
    metadata = docker_path.stat()
    docker = runtime.DockerExecutable(
        path=docker_path.resolve(strict=True),
        digest=runtime._sha256(docker_bytes),
        identity=(
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        ),
    )
    effective = json.loads(base.effective_config_json)
    effective["docker_executable_digest"] = docker.digest
    effective_json = canonical_json(effective)
    return benchmark_runner._PreparedBaseline(
        baseline=base.baseline,
        raw_lock=base.raw_lock,
        selected_json=base.selected_json,
        docker=docker,
        verification=base.verification,
        effective_config_json=effective_json,
        runner_identity_json=base.runner_identity_json,
        system={
            **base.system,
            "implementation_digest": CISCO_IMPLEMENTATION,
            "config_digest": runtime._sha256(effective_json),
        },
    )


def _write_input(
    root: Path,
    prepared: benchmark_runner._PreparedBaseline,
    *,
    content: bytes = b"# inert skill\n",
    declared_size: int | None = None,
    store_blob: bool = True,
    mutate_request=None,
) -> tuple[Path, Path, Path, str, dict, dict, bytes]:
    input_path = root / "held-out-case-secret" / "input"
    input_cas = CAS(input_path)
    content_digest = runtime._sha256(content)
    if store_blob:
        actual = input_cas.put(BytesIO(content), max_bytes=len(content))
        assert actual == content_digest
    files = [
        {
            "path": "SKILL.md",
            "size": len(content) if declared_size is None else declared_size,
            "digest": content_digest,
            "executable": False,
        }
    ]
    manifest = {
        "schema": "aragorn/benchmark-subject-manifest/v1",
        "tree_digest": canonical_digest(files),
        "files": files,
    }
    raw_manifest = canonical_json(manifest)
    manifest_digest = input_cas.put(
        BytesIO(raw_manifest),
        max_bytes=len(raw_manifest),
    )
    assert manifest_digest == canonical_digest(manifest)
    tokens = iter(("a" * 32, "b" * 64))
    request = build_worker_request(
        manifest,
        prepared.system,
        baseline_lock_digest=runtime._sha256(prepared.raw_lock),
        baseline_entry_digest=runtime._sha256(prepared.selected_json),
        timeout_seconds=120.0,
        output_limit_bytes=1024 * 1024,
        token_hex=lambda _size: next(tokens),
    )
    if mutate_request is not None:
        mutate_request(request)
    raw_request = canonical_json(request)
    request_digest = runtime._sha256(raw_request)
    request_path = input_path.parent / "request.json"
    request_path.write_bytes(raw_request)
    request_path.chmod(0o400)
    lock_path = root / "baselines.lock.json"
    lock_path.write_bytes(prepared.raw_lock)
    return (
        request_path,
        input_path,
        lock_path,
        request_digest,
        request,
        manifest,
        content,
    )


def _successful_execution(
    prepared: benchmark_runner._PreparedBaseline,
    tree_digest: str,
) -> runtime.OCIExecutionResult:
    return replace(
        runner_support.execution_result(
            prepared,
            runner_support.cisco_report(),
        ),
        verified_subject_digest=tree_digest,
    )


def _retained_error(
    prepared: benchmark_runner._PreparedBaseline,
    tree_digest: str,
    error_code: str,
) -> runtime.OCIExecutionError:
    success = _successful_execution(prepared, tree_digest)
    return runtime.OCIExecutionError(
        error_code=error_code,
        message=error_code.lower(),
        baseline_name=success.baseline_name,
        docker_path=success.docker_path,
        docker_digest=success.docker_digest,
        image_reference=success.image_reference,
        container_id=success.container_id,
        raw_lock=success.raw_lock,
        selected_baseline_json=success.selected_baseline_json,
        effective_config_json=success.effective_config_json,
        raw_index_inspect=success.raw_index_inspect,
        raw_platform_inspect=success.raw_platform_inspect,
        raw_oci_index_json=success.raw_oci_index_json,
        raw_oci_platform_manifest_json=success.raw_oci_platform_manifest_json,
        raw_build_provenance_manifest_json=(
            success.raw_build_provenance_manifest_json
        ),
        raw_config_json=success.raw_config_json,
        raw_prestart_container_inspect=success.raw_prestart_container_inspect,
        raw_postrun_container_inspect=success.raw_postrun_container_inspect,
        raw_stdout=b"",
        raw_stderr=b"",
        returncode=137,
        verified_subject_digest=tree_digest,
        raw_pre_context_inspect=success.raw_pre_context_inspect,
        raw_pre_daemon_version=success.raw_pre_daemon_version,
        raw_pre_daemon_info=success.raw_pre_daemon_info,
        raw_post_context_inspect=success.raw_post_context_inspect,
        raw_post_daemon_version=success.raw_post_daemon_version,
        raw_post_daemon_info=success.raw_post_daemon_info,
        runner_identity_json=success.runner_identity_json,
    )


def _replace_read_only(path: Path, content: bytes) -> None:
    path.chmod(0o600)
    path.write_bytes(content)
    path.chmod(0o400)


class WorkerExecutionTests(unittest.TestCase):
    def test_one_job_retains_complete_label_free_output_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared = _local_prepared(root)
            (
                request_path,
                input_path,
                lock_path,
                request_digest,
                request,
                manifest,
                content,
            ) = _write_input(root, prepared)
            output_path = root / "held-out-case-secret" / "output"
            workspace_root = root / "workspace-root"
            workspace_root.mkdir(mode=0o700)
            execution = _successful_execution(
                prepared,
                manifest["tree_digest"],
            )

            def launch(
                baseline_name: str,
                **kwargs: object,
            ) -> runtime.OCIExecutionResult:
                workspace = Path(kwargs["workspace"])
                self.assertFalse(output_path.exists())
                self.assertEqual(baseline_name, "cisco-skill-scanner")
                self.assertNotIn("held-out", str(workspace))
                self.assertNotIn("case-secret", str(workspace))
                self.assertTrue(workspace.parent.name.startswith(
                    ".aragorn-oci-workspace-"
                ))
                self.assertTrue(workspace.parent.parent.name.startswith(
                    ".aragorn-worker-"
                ))
                self.assertEqual(
                    workspace.parent.parent.parent,
                    workspace_root.resolve(strict=True),
                )
                self.assertEqual((workspace / "SKILL.md").read_bytes(), content)
                self.assertEqual(
                    stat.S_IMODE((workspace / "SKILL.md").stat().st_mode),
                    0o444,
                )
                self.assertEqual(
                    kwargs["expected_tree_digest"],
                    manifest["tree_digest"],
                )
                self.assertEqual(
                    kwargs["expected_effective_config_json"],
                    prepared.effective_config_json,
                )
                return execution

            with (
                patch.object(
                    worker,
                    "resolve_docker",
                    return_value=prepared.docker,
                ),
                patch.object(
                    worker,
                    "_preflight",
                    return_value=(prepared,),
                ),
                patch.object(
                    worker,
                    "run_baseline",
                    side_effect=launch,
                ) as run_baseline,
            ):
                result = worker.run(
                    request_path,
                    request_digest=request_digest,
                    input_state=input_path,
                    output_state=output_path,
                    lock_path=lock_path,
                    docker_executable=prepared.docker.path,
                    workspace_root=workspace_root,
                )

            self.assertEqual(run_baseline.call_count, 1)
            self.assertTrue(output_path.is_dir())
            validate_worker_result(result)
            verify_request_result_binding(request, result)
            self.assertEqual(result["verdict"], "ALLOW")
            self.assertEqual(result["reason_codes"], [])

            output_cas = CAS(output_path, read_only=True)
            self.assertEqual(
                output_cas.read(request_digest),
                canonical_json(request),
            )
            self.assertEqual(
                output_cas.read(request["subject"]["manifest_digest"]),
                canonical_json(manifest),
            )
            self.assertEqual(
                output_cas.read(manifest["files"][0]["digest"]),
                content,
            )
            self.assertEqual(
                output_cas.read(prepared.docker.digest),
                prepared.docker.path.read_bytes(),
            )
            output_cas.verify(canonical_digest(result))

            serialized = canonical_json(
                {"request": request, "manifest": manifest, "result": result}
            ).decode("ascii")
            for label in (
                '"suite"',
                '"case_id"',
                '"class"',
                '"family"',
                '"lineage"',
                '"split"',
            ):
                self.assertNotIn(label, serialized)

    def test_request_identity_drift_prevents_launch(self) -> None:
        mutations = {
            "system": lambda request: request["system"].__setitem__(
                "config_digest",
                "sha256:" + "f" * 64,
            ),
            "lock": lambda request: request["baseline"].__setitem__(
                "lock_digest",
                "sha256:" + "e" * 64,
            ),
            "entry": lambda request: request["baseline"].__setitem__(
                "entry_digest",
                "sha256:" + "d" * 64,
            ),
        }
        for index, (label, mutation) in enumerate(mutations.items()):
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                prepared = _local_prepared(root)
                request_path, input_path, lock_path, request_digest, *_ = _write_input(
                    root,
                    prepared,
                    mutate_request=mutation,
                )
                with (
                    patch.object(
                        worker,
                        "resolve_docker",
                        return_value=prepared.docker,
                    ),
                    patch.object(
                        worker,
                        "_preflight",
                        return_value=(prepared,),
                    ),
                    patch.object(worker, "run_baseline") as launch,
                ):
                    output_path = root / f"output-{index}"
                    with self.assertRaises(worker.WorkerError):
                        worker.run(
                            request_path,
                            request_digest=request_digest,
                            input_state=input_path,
                            output_state=output_path,
                            lock_path=lock_path,
                            docker_executable=prepared.docker.path,
                        )
                launch.assert_not_called()
                self.assertFalse(output_path.exists())

    def test_missing_wrong_sized_and_corrupt_subjects_fail_before_preflight(
        self,
    ) -> None:
        variants = (
            {"store_blob": False},
            {"declared_size": 64},
            {"corrupt": True},
        )
        for index, variant in enumerate(variants):
            with (
                self.subTest(variant=variant),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                prepared = _local_prepared(root)
                content = b"# inert skill\n"
                (
                    request_path,
                    input_path,
                    lock_path,
                    request_digest,
                    _request,
                    manifest,
                    _content,
                ) = (
                    _write_input(
                        root,
                        prepared,
                        content=content,
                        declared_size=variant.get("declared_size"),
                        store_blob=variant.get("store_blob", True),
                    )
                )
                if variant.get("corrupt"):
                    digest = manifest["files"][0]["digest"].removeprefix(
                        "sha256:"
                    )
                    blob = (
                        input_path
                        / "blobs"
                        / "sha256"
                        / digest[:2]
                        / digest[2:]
                    )
                    blob.chmod(0o600)
                    blob.write_bytes(b"! corrupt !!!\n")
                    blob.chmod(0o444)

                with (
                    patch.object(
                        worker,
                        "resolve_docker",
                        return_value=prepared.docker,
                    ),
                    patch.object(worker, "_preflight") as preflight,
                    patch.object(worker, "run_baseline") as launch,
                ):
                    output_path = root / f"output-{index}"
                    with self.assertRaises((CASError, worker.WorkerError)):
                        worker.run(
                            request_path,
                            request_digest=request_digest,
                            input_state=input_path,
                            output_state=output_path,
                            lock_path=lock_path,
                            docker_executable=prepared.docker.path,
                        )
                preflight.assert_not_called()
                launch.assert_not_called()
                self.assertFalse(output_path.exists())

    def test_timeout_and_output_limit_are_label_free_worker_results(self) -> None:
        for index, error_code in enumerate(
            ("TIMEOUT", "OUTPUT_LIMIT_EXCEEDED")
        ):
            with (
                self.subTest(error_code=error_code),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                prepared = _local_prepared(root)
                (
                    request_path,
                    input_path,
                    lock_path,
                    request_digest,
                    request,
                    manifest,
                    _content,
                ) = _write_input(root, prepared)
                execution = _retained_error(
                    prepared,
                    manifest["tree_digest"],
                    error_code,
                )
                with (
                    patch.object(
                        worker,
                        "resolve_docker",
                        return_value=prepared.docker,
                    ),
                    patch.object(
                        worker,
                        "_preflight",
                        return_value=(prepared,),
                    ),
                    patch.object(
                        worker,
                        "run_baseline",
                        return_value=execution,
                    ),
                ):
                    result = worker.run(
                        request_path,
                        request_digest=request_digest,
                        input_state=input_path,
                        output_state=root / f"output-{index}",
                        lock_path=lock_path,
                        docker_executable=prepared.docker.path,
                    )

                verify_request_result_binding(request, result)
                self.assertEqual(
                    result["execution"]["error_code"],
                    error_code,
                )
                self.assertEqual(result["verdict"], "ERROR")
                self.assertEqual(
                    result["reason_codes"],
                    [f"ANALYZER_{error_code}"],
                )
                self.assertEqual(result["observation_digests"], [])

    def test_extra_output_blob_rejects_publication_and_removes_staging(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared = _local_prepared(root)
            (
                request_path,
                input_path,
                lock_path,
                request_digest,
                _request,
                manifest,
                _content,
            ) = _write_input(root, prepared)
            output_path = input_path.parent / "output"
            execution = _successful_execution(
                prepared,
                manifest["tree_digest"],
            )

            def retain(cas: CAS, **kwargs: object) -> dict:
                retained = benchmark_runner._retain_execution_evidence(
                    cas,
                    **kwargs,
                )
                unexpected = b"unexpected output closure blob"
                cas.put(BytesIO(unexpected), max_bytes=len(unexpected))
                return retained

            with (
                patch.object(
                    worker,
                    "resolve_docker",
                    return_value=prepared.docker,
                ),
                patch.object(
                    worker,
                    "_preflight",
                    return_value=(prepared,),
                ),
                patch.object(
                    worker,
                    "run_baseline",
                    return_value=execution,
                ),
                patch.object(
                    worker,
                    "_retain_execution_evidence",
                    side_effect=retain,
                ),
                self.assertRaisesRegex(worker.WorkerError, "exact result closure"),
            ):
                worker.run(
                    request_path,
                    request_digest=request_digest,
                    input_state=input_path,
                    output_state=output_path,
                    lock_path=lock_path,
                    docker_executable=prepared.docker.path,
                )

            self.assertFalse(output_path.exists())
            self.assertEqual(
                list(input_path.parent.glob(".aragorn-worker-output-*")),
                [],
            )

    def test_request_decoder_rejects_duplicates_nonfinite_and_noncanonical(
        self,
    ) -> None:
        for label in ("duplicate", "nonfinite", "noncanonical"):
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                prepared = _local_prepared(root)
                (
                    request_path,
                    input_path,
                    lock_path,
                    _request_digest,
                    request,
                    _manifest,
                    _content,
                ) = _write_input(root, prepared)
                canonical = canonical_json(request)
                if label == "duplicate":
                    raw = (
                        b'{"schema":"aragorn/benchmark-worker-request/v1",'
                        + canonical[1:]
                    )
                elif label == "nonfinite":
                    raw = canonical.replace(
                        b'"timeout_seconds":120.0',
                        b'"timeout_seconds":NaN',
                    )
                else:
                    raw = json.dumps(
                        request,
                        indent=2,
                        sort_keys=True,
                    ).encode("ascii")
                _replace_read_only(request_path, raw)
                with (
                    patch.object(worker, "resolve_docker") as docker,
                    patch.object(worker, "_preflight") as preflight,
                    self.assertRaises(worker.WorkerError),
                ):
                    worker.run(
                        request_path,
                        request_digest=runtime._sha256(raw),
                        input_state=input_path,
                        output_state=input_path.parent / "output",
                        lock_path=lock_path,
                        docker_executable=prepared.docker.path,
                    )
                docker.assert_not_called()
                preflight.assert_not_called()
                self.assertFalse((input_path.parent / "output").exists())

    def test_manifest_decoder_rejects_duplicates_nonfinite_and_noncanonical(
        self,
    ) -> None:
        for label in ("duplicate", "nonfinite", "noncanonical"):
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                prepared = _local_prepared(root)
                (
                    request_path,
                    input_path,
                    lock_path,
                    _request_digest,
                    request,
                    manifest,
                    _content,
                ) = _write_input(root, prepared)
                canonical = canonical_json(manifest)
                if label == "duplicate":
                    raw_manifest = (
                        b'{"schema":"aragorn/benchmark-subject-manifest/v1",'
                        + canonical[1:]
                    )
                elif label == "nonfinite":
                    size = str(manifest["files"][0]["size"]).encode("ascii")
                    raw_manifest = canonical.replace(
                        b'"size":' + size,
                        b'"size":NaN',
                    )
                else:
                    raw_manifest = json.dumps(
                        manifest,
                        indent=2,
                        sort_keys=True,
                    ).encode("ascii")
                input_cas = CAS(input_path)
                manifest_digest = input_cas.put(
                    BytesIO(raw_manifest),
                    max_bytes=len(raw_manifest),
                )
                request["subject"]["manifest_digest"] = manifest_digest
                raw_request = canonical_json(request)
                request_digest = runtime._sha256(raw_request)
                _replace_read_only(request_path, raw_request)

                with (
                    patch.object(worker, "resolve_docker") as docker,
                    patch.object(worker, "_preflight") as preflight,
                    self.assertRaises(worker.WorkerError),
                ):
                    worker.run(
                        request_path,
                        request_digest=request_digest,
                        input_state=input_path,
                        output_state=input_path.parent / "output",
                        lock_path=lock_path,
                        docker_executable=prepared.docker.path,
                    )
                docker.assert_not_called()
                preflight.assert_not_called()
                self.assertFalse((input_path.parent / "output").exists())

    def test_request_must_be_read_only_and_outside_the_subject_cas(self) -> None:
        variants = ("writable", "symlink", "inside-cas")
        for label in variants:
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                prepared = _local_prepared(root)
                (
                    request_path,
                    input_path,
                    lock_path,
                    request_digest,
                    _request,
                    _manifest,
                    _content,
                ) = _write_input(root, prepared)
                if label == "writable":
                    request_path.chmod(0o600)
                elif label == "symlink":
                    link = root / "request-link.json"
                    link.symlink_to(request_path)
                    request_path = link
                else:
                    inside = input_path / "request.json"
                    inside.write_bytes(request_path.read_bytes())
                    inside.chmod(0o400)
                    request_path = inside

                with (
                    patch.object(worker, "resolve_docker") as docker,
                    self.assertRaises(worker.WorkerError),
                ):
                    worker.run(
                        request_path,
                        request_digest=request_digest,
                        input_state=input_path,
                        output_state=input_path.parent / "output",
                        lock_path=lock_path,
                        docker_executable=prepared.docker.path,
                    )
                docker.assert_not_called()
                self.assertFalse((input_path.parent / "output").exists())


class WorkerCLITests(unittest.TestCase):
    def test_run_buffers_stdout_and_rejects_label_arguments(self) -> None:
        request_digest = "sha256:" + "1" * 64
        output = StringIO()
        errors = StringIO()
        with (
            patch.object(
                worker,
                "run",
                side_effect=worker.WorkerError("late worker failure"),
            ),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            status = worker.main(
                [
                    "run",
                    "request.json",
                    "--request-digest",
                    request_digest,
                    "--input-state",
                    "input",
                    "--output-state",
                    "output",
                ]
            )

        self.assertEqual(status, 4)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(
            json.loads(errors.getvalue())["message"],
            "late worker failure",
        )

        output = StringIO()
        errors = StringIO()
        with (
            patch.object(worker, "run") as run,
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            status = worker.main(
                [
                    "run",
                    "request.json",
                    "--request-digest",
                    request_digest,
                    "--input-state",
                    "input",
                    "--output-state",
                    "output",
                    "--case-id",
                    "secret-case",
                ]
            )
        self.assertEqual(status, 4)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("unrecognized arguments", errors.getvalue())
        run.assert_not_called()

    def test_identity_prints_only_the_derived_system_document(self) -> None:
        systems = (
            {
                "name": "cisco-skill-scanner",
                "version": "2.0.12",
                "implementation_digest": "sha256:" + "2" * 64,
                "config_digest": "sha256:" + "3" * 64,
            },
        )
        output = StringIO()
        errors = StringIO()
        with (
            patch.object(worker, "identity", return_value=systems),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            status = worker.main(["identity"])

        self.assertEqual(status, 0)
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(
            json.loads(output.getvalue()),
            {
                "schema": "aragorn/benchmark-system-identities/v1",
                "systems": list(systems),
            },
        )


if __name__ == "__main__":
    unittest.main()
