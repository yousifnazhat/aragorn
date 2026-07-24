from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import oci_benchmark_runner as benchmark_runner
from aragorn import oci_runtime as runtime
from aragorn import oci_worker_v2 as worker
from aragorn.benchmark_protocol_v2 import canonical_result_digest_v2
from aragorn.benchmark_semantic_closure_v2 import (
    derive_worker_input_cas_closure,
    verify_worker_output_evidence_cas_v2,
)
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from tests import test_benchmark_semantic_closure_v2 as semantic_support


class WorkerV2ExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            dir=Path(__file__).parents[1].resolve()
        )
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)

        self.semantic_fixture = (
            semantic_support.BenchmarkSemanticClosureV2Tests(
                "test_deep_v2_verifier_rechecks_oci_receipts_and_vendor_evidence"
            )
        )
        self.semantic_fixture.setUp()
        self.addCleanup(self.semantic_fixture.doCleanups)
        (
            _seed_result_digest,
            self.request_digest,
            self.expected_result,
        ) = self.semantic_fixture._deep_output()
        self.seed = self.semantic_fixture.source
        self.challenge = self.expected_result["verifier_challenge"]

        self.prepared, self.execution = self._runtime_fixture()
        self.lock_path = self.root / "baselines.lock.json"
        self.lock_path.write_bytes(self.prepared.raw_lock)
        self.lock_path.chmod(0o400)
        self.workspace_root = self.root / "workspace"
        self.workspace_root.mkdir(mode=0o700)

    def test_executes_and_deeply_verifies_exact_v2_output_closure(self) -> None:
        input_path = self._copy_input_closure("input")
        output_path = self.root / "output"
        manifest = json.loads(
            self.seed.read(self.expected_result["subject_manifest_digest"])
        )

        def launch(
            baseline_name: str,
            **kwargs: object,
        ) -> runtime.OCIExecutionResult:
            workspace = Path(kwargs["workspace"])
            self.assertEqual(baseline_name, self.prepared.baseline["name"])
            self.assertEqual(
                kwargs["expected_tree_digest"],
                self.expected_result["tree_digest"],
            )
            self.assertEqual(
                kwargs["expected_effective_config_json"],
                self.prepared.effective_config_json,
            )
            for entry in manifest["files"]:
                self.assertEqual(
                    (workspace / entry["path"]).read_bytes(),
                    self.seed.read(entry["digest"], max_bytes=entry["size"]),
                )
            return self.execution

        with (
            patch.object(
                worker,
                "resolve_docker",
                return_value=self.prepared.docker,
            ),
            patch.object(
                worker,
                "_preflight",
                return_value=(self.prepared,),
            ),
            patch.object(
                worker,
                "run_baseline",
                side_effect=launch,
            ) as run_baseline,
        ):
            result = worker.run(
                request_digest=self.request_digest,
                expected_challenge=self.challenge,
                input_state=input_path,
                output_state=output_path,
                lock_path=self.lock_path,
                docker_executable=self.prepared.docker.path,
                workspace_root=self.workspace_root,
            )

        self.assertEqual(run_baseline.call_count, 1)
        self.assertEqual(result, self.expected_result)
        result_digest = canonical_result_digest_v2(result)
        output_cas = CAS(output_path, read_only=True)
        closure = verify_worker_output_evidence_cas_v2(
            output_cas,
            result_digest,
            expected_request_digest=self.request_digest,
            expected_challenge=self.challenge,
        )
        self.assertIn(result_digest, closure)
        for digest, size in closure.items():
            output_cas.verify(digest, max_bytes=size)

    def test_effective_policy_drift_is_rejected_before_launch(self) -> None:
        input_path = self._copy_input_closure("policy-drift-input")
        output_path = self.root / "policy-drift-output"
        effective = json.loads(self.prepared.effective_config_json)
        effective["runtime_profile"]["cpus"] = 1
        drifted = replace(
            self.prepared,
            effective_config_json=canonical_json(effective),
        )

        with (
            patch.object(
                worker,
                "resolve_docker",
                return_value=self.prepared.docker,
            ),
            patch.object(worker, "_preflight", return_value=(drifted,)),
            patch.object(worker, "run_baseline") as run_baseline,
            self.assertRaisesRegex(
                worker.WorkerError,
                "effective policy is invalid before launch",
            ),
        ):
            worker.run(
                request_digest=self.request_digest,
                expected_challenge=self.challenge,
                input_state=input_path,
                output_state=output_path,
                lock_path=self.lock_path,
                docker_executable=self.prepared.docker.path,
                workspace_root=self.workspace_root,
            )

        run_baseline.assert_not_called()
        self.assertFalse(output_path.exists())

    def test_wrong_challenge_and_extra_input_fail_before_preflight(self) -> None:
        cases = (
            (
                "wrong-challenge",
                self._copy_input_closure("wrong-challenge-input"),
                "c" * 64,
            ),
            (
                "extra-input",
                self._copy_input_closure(
                    "extra-input-cas",
                    extra=b"not reachable from the request",
                ),
                self.challenge,
            ),
        )

        for label, input_path, challenge in cases:
            with self.subTest(label=label):
                output_path = self.root / f"{label}-output"
                with (
                    patch.object(worker, "_preflight") as preflight,
                    patch.object(worker, "resolve_docker") as resolve_docker,
                    self.assertRaisesRegex(
                        worker.WorkerError,
                        "input (closure|CAS) is not|input closure is invalid",
                    ),
                ):
                    worker.run(
                        request_digest=self.request_digest,
                        expected_challenge=challenge,
                        input_state=input_path,
                        output_state=output_path,
                        lock_path=self.lock_path,
                        docker_executable=self.prepared.docker.path,
                        workspace_root=self.workspace_root,
                    )

                preflight.assert_not_called()
                resolve_docker.assert_not_called()
                self.assertFalse(output_path.exists())

    def _copy_input_closure(
        self,
        name: str,
        *,
        extra: bytes | None = None,
    ) -> Path:
        closure = derive_worker_input_cas_closure(
            self.seed,
            self.request_digest,
            expected_challenge=self.challenge,
        )
        path = self.root / name
        destination = CAS(path)
        for digest, size in closure.items():
            content = self.seed.read(digest, max_bytes=size)
            self.assertEqual(
                destination.put_expected(
                    BytesIO(content),
                    expected_digest=digest,
                    max_bytes=size,
                ),
                digest,
            )
        if extra is not None:
            destination.put(BytesIO(extra), max_bytes=len(extra))
        return path

    def _runtime_fixture(
        self,
    ) -> tuple[
        benchmark_runner._PreparedBaseline,
        runtime.OCIExecutionResult,
    ]:
        result = self.expected_result
        raw_lock = self.seed.read(result["baseline_lock_digest"])
        selected_json = self.seed.read(result["baseline_entry_digest"])
        baseline = json.loads(selected_json)
        effective_json = self.seed.read(result["effective_config_digest"])
        effective = json.loads(effective_json)

        docker_path = self.root / "docker"
        docker_bytes = self.seed.read(result["docker_executable_digest"])
        docker_path.write_bytes(docker_bytes)
        docker_path.chmod(0o700)
        metadata = docker_path.stat()
        docker = runtime.DockerExecutable(
            path=docker_path.resolve(strict=True),
            digest=result["docker_executable_digest"],
            identity=(
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            ),
        )

        raw_config = self.seed.read(result["image_config_digest"])
        image_config = json.loads(raw_config)
        verification = runtime.ImageVerification(
            name=baseline["name"],
            image_reference=effective["image"]["reference"],
            raw_index_inspect=self.seed.read(result["index_inspect_digest"]),
            raw_platform_inspect=self.seed.read(
                result["platform_inspect_digest"]
            ),
            raw_oci_index_json=self.seed.read(result["oci_index_digest"]),
            raw_oci_platform_manifest_json=self.seed.read(
                result["oci_platform_manifest_digest"]
            ),
            raw_build_provenance_manifest_json=self.seed.read(
                result["build_provenance_manifest_digest"]
            ),
            raw_config_json=raw_config,
            image_entrypoint=tuple(effective["entrypoint"]),
            image_environment=tuple(image_config["config"]["Env"]),
        )
        runner_identity_json = canonical_json(effective["runner_identity"])
        prepared = benchmark_runner._PreparedBaseline(
            baseline=baseline,
            raw_lock=raw_lock,
            selected_json=selected_json,
            docker=docker,
            verification=verification,
            effective_config_json=effective_json,
            runner_identity_json=runner_identity_json,
            system={
                **result["system"],
                "config_digest": result["effective_config_digest"],
            },
        )
        execution = runtime.OCIExecutionResult(
            baseline_name=baseline["name"],
            version=baseline["version"],
            docker_path=os.fspath(docker.path),
            docker_digest=docker.digest,
            image_reference=verification.image_reference,
            index_digest=baseline["image"]["index_digest"],
            platform_manifest_digest=baseline["image"][
                "platform_manifest_digest"
            ],
            config_digest=baseline["image"]["config_digest"],
            container_id=result["execution"]["container_id"],
            raw_lock=raw_lock,
            selected_baseline_json=selected_json,
            effective_config_json=effective_json,
            raw_index_inspect=verification.raw_index_inspect,
            raw_platform_inspect=verification.raw_platform_inspect,
            raw_oci_index_json=verification.raw_oci_index_json,
            raw_oci_platform_manifest_json=(
                verification.raw_oci_platform_manifest_json
            ),
            raw_build_provenance_manifest_json=(
                verification.raw_build_provenance_manifest_json
            ),
            raw_config_json=verification.raw_config_json,
            raw_prestart_container_inspect=self.seed.read(
                result["prestart_container_inspect_digest"]
            ),
            raw_postrun_container_inspect=self.seed.read(
                result["postrun_container_inspect_digest"]
            ),
            raw_stdout=self.seed.read(result["stdout_digest"]),
            raw_stderr=self.seed.read(result["stderr_digest"]),
            returncode=result["execution"]["returncode"],
            verified_subject_digest=result["verified_subject_digest"],
            raw_pre_context_inspect=self.seed.read(
                result["runner_receipts"]["pre"]["context_inspect_digest"]
            ),
            raw_pre_daemon_version=self.seed.read(
                result["runner_receipts"]["pre"]["daemon_version_digest"]
            ),
            raw_pre_daemon_info=self.seed.read(
                result["runner_receipts"]["pre"]["daemon_info_digest"]
            ),
            raw_post_context_inspect=self.seed.read(
                result["runner_receipts"]["post"]["context_inspect_digest"]
            ),
            raw_post_daemon_version=self.seed.read(
                result["runner_receipts"]["post"]["daemon_version_digest"]
            ),
            raw_post_daemon_info=self.seed.read(
                result["runner_receipts"]["post"]["daemon_info_digest"]
            ),
            runner_identity_json=runner_identity_json,
        )
        return prepared, execution


if __name__ == "__main__":
    unittest.main()
