from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


import sys


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from tests import (  # noqa: E402
    test_benchmark_oci_evidence as evidence_support,
)
from tests import test_docker_identity as identity_support  # noqa: E402

from aragorn.cas import CAS  # noqa: E402
from aragorn import oci_benchmark_runner as runner  # noqa: E402
from aragorn import oci_runtime as runtime  # noqa: E402


SUBJECT = "sha256:" + "a" * 64
SUITE = "sha256:" + "b" * 64
CONTAINER_ID = "c" * 64
POLICY = "7e571f3db6d7aa3d0c8a40e9ae8f8f6a0f0a721fe518e59f71943a11b418c91f"


def canonical(document: object) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def cisco_report() -> bytes:
    return canonical(
        {
            "skill_name": "example",
            "skill_path": "/workspace",
            "is_safe": True,
            "max_severity": "SAFE",
            "findings_count": 0,
            "findings": [],
            "scan_duration_seconds": 0,
            "duration_ms": 0,
            "analyzers_used": [
                "static_analyzer",
                "bytecode",
                "pipeline",
                "behavioral_analyzer",
            ],
            "timestamp": "2026-07-22T12:00:00+00:00",
            "scan_metadata": {
                "policy_name": "strict",
                "policy_version": "1.0",
                "policy_preset_base": "strict",
                "policy_fingerprint_sha256": POLICY,
            },
        }
    )


class OCIIdentityTests(unittest.TestCase):
    def test_identity_verifies_both_images_without_launching_a_case(self) -> None:
        raw_lock, baselines = runtime.load_baseline_lock()
        docker = runtime.DockerExecutable(
            path=Path("/usr/bin/docker"),
            digest="sha256:" + "d" * 64,
            identity=(1, 2, 3, 4),
        )
        identity = identity_support.normalize()

        def capture_pre(
            _docker: runtime.DockerExecutable,
            _control: Path,
            evidence: runtime._RunnerReceiptBuffer,
        ):
            evidence.raw_context = identity.raw_context
            evidence.raw_version = identity.raw_version
            evidence.raw_info = identity.raw_info
            environment = {
                "DOCKER_CONFIG": "/private/config",
                "DOCKER_HOST": identity.endpoint,
                "LC_ALL": "C",
            }
            return {"DOCKER_CONFIG": "/original"}, environment, identity

        def capture_post(
            _docker: runtime.DockerExecutable,
            *,
            evidence: runtime._RunnerReceiptBuffer,
            **_kwargs: object,
        ):
            evidence.raw_context = identity.raw_context
            evidence.raw_version = identity.raw_version
            evidence.raw_info = identity.raw_info
            return identity

        def verification(
            _docker: Path,
            baseline: dict,
            *,
            env: dict[str, str],
        ) -> runtime.ImageVerification:
            self.assertEqual(env["LC_ALL"], "C")
            entrypoint = {
                "cisco-skill-scanner": ("/opt/venv/bin/skill-scanner",),
                "skillspector": (
                    "/opt/venv/bin/python",
                    "-P",
                    "-m",
                    "skillspector.cli",
                ),
            }[baseline["name"]]
            return runtime.ImageVerification(
                name=baseline["name"],
                image_reference=(
                    baseline["image"]["local_tag"].rsplit(":", 1)[0]
                    + "@"
                    + baseline["image"]["index_digest"]
                ),
                raw_index_inspect=b"[]",
                raw_platform_inspect=b"[]",
                raw_oci_index_json=b"{}",
                raw_oci_platform_manifest_json=b"{}",
                raw_build_provenance_manifest_json=b"{}",
                raw_config_json=b"{}",
                image_entrypoint=entrypoint,
                image_environment=("PATH=/usr/bin",),
            )

        with (
            patch.object(
                runner,
                "load_baseline_lock",
                return_value=(raw_lock, baselines),
            ),
            patch.object(runner, "resolve_docker", return_value=docker),
            patch.object(
                runner, "verify_image", side_effect=verification
            ) as verify,
            patch.object(
                runner,
                "_capture_pre_runner_identity",
                side_effect=capture_pre,
            ),
            patch.object(
                runner,
                "_capture_post_runner_identity",
                side_effect=capture_post,
            ),
            patch.object(runner, "_verify_docker_unchanged"),
            patch.object(runner, "run_baseline") as launch,
        ):
            prepared = runner._preflight(
                lock_path=runtime.LOCK,
                docker_executable="docker",
                timeout_seconds=120,
                output_limit_bytes=1024,
            )
            systems = tuple(item.system for item in prepared)

        self.assertEqual(
            [system["name"] for system in systems],
            ["cisco-skill-scanner", "skillspector"],
        )
        self.assertEqual(verify.call_count, 2)
        launch.assert_not_called()
        self.assertTrue(
            all(system["config_digest"].startswith("sha256:") for system in systems)
        )
        effective = json.loads(prepared[0].effective_config_json)
        self.assertEqual(
            effective["schema"],
            "aragorn/benchmark-oci-system-config/v2",
        )
        self.assertEqual(effective["runner_identity"], json.loads(identity.document_json))

    def test_suite_identity_mismatch_prevents_every_launch(self) -> None:
        prepared = prepared_cisco()
        unexpected = {
            **prepared.system,
            "config_digest": "sha256:" + "f" * 64,
        }
        loaded = {
            "systems": {runner._system_key(unexpected): unexpected},
            "cases": {},
            "manifests": {},
            "runs_per_case": 1,
            "digest": SUITE,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite_root = root / "suite"
            suite_root.mkdir()
            suite = suite_root / "suite.json"
            suite.write_text("{}")
            with (
                patch.object(
                    runner, "load_suite_for_run", return_value=loaded
                ),
                patch.object(runner, "_preflight", return_value=(prepared,)),
                patch.object(runner, "run_baseline") as launch,
            ):
                with self.assertRaisesRegex(runner.RunnerError, "do not match suite"):
                    runner.run_files(suite, state=root / "state")
        launch.assert_not_called()


class OCIRetentionTests(unittest.TestCase):
    def test_oci_workspace_contains_only_cas_subject_with_nonroot_read_modes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cas = CAS(root / "state")
            content = b"subject"
            content_digest = cas.put(
                BytesIO(content), max_bytes=len(content)
            )
            manifest = {
                "files": [
                    {
                        "path": "nested/SKILL.md",
                        "digest": content_digest,
                    }
                ]
            }
            with runner._oci_workspace(
                cas,
                manifest,
                parent=root,
                forbidden_roots=(root / "suite", root / "state"),
            ) as workspace:
                temporary_workspace = workspace.parent
                file = workspace / "nested" / "SKILL.md"
                self.assertEqual(file.read_bytes(), content)
                self.assertEqual(stat.S_IMODE(workspace.stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o444)
                self.assertEqual(
                    sorted(path.relative_to(workspace).as_posix() for path in workspace.rglob("*")),
                    ["nested", "nested/SKILL.md"],
                )
            self.assertFalse(temporary_workspace.exists())

    def test_valid_vendor_report_retains_v3_and_unchanged_v1_outcome(self) -> None:
        prepared = prepared_cisco()
        result = execution_result(prepared, cisco_report())
        loaded = {
            "digest": SUITE,
            "cases": {"case": {"tree_digest": SUBJECT}},
        }
        manifest = {"schema": "manifest", "tree_digest": SUBJECT}
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            manifest_digest = cas.put(
                BytesIO(canonical(manifest)), max_bytes=len(canonical(manifest))
            )
            outcome = runner._retain_run(
                cas,
                loaded,
                "case",
                1,
                prepared.system,
                prepared,
                result,
                manifest_digest=manifest_digest,
            )
            envelope = json.loads(cas.read(outcome["evidence_digest"]))

            self.assertEqual(outcome["schema"], "aragorn/benchmark-outcome/v1")
            self.assertEqual(outcome["verdict"], "ALLOW")
            self.assertEqual(envelope["schema"], "aragorn/benchmark-evidence/v3")
            self.assertEqual(cas.read(envelope["stdout_digest"]), cisco_report())
            self.assertEqual(len(envelope["observation_digests"]), 1)
            self.assertEqual(envelope["verified_subject_digest"], SUBJECT)
            self.assertEqual(
                envelope["oci_index_digest"],
                prepared.baseline["image"]["index_digest"],
            )
            self.assertEqual(
                envelope["oci_platform_manifest_digest"],
                prepared.baseline["image"]["platform_manifest_digest"],
            )
            self.assertEqual(
                envelope["build_provenance_manifest_digest"],
                prepared.baseline["image"][
                    "build_provenance_manifest_digest"
                ],
            )
            for phase, prefix in (("pre", "raw_pre"), ("post", "raw_post")):
                receipt = envelope["runner_receipts"][phase]
                self.assertEqual(
                    cas.read(receipt["context_inspect_digest"]),
                    getattr(result, f"{prefix}_context_inspect"),
                )
                self.assertEqual(
                    cas.read(receipt["daemon_version_digest"]),
                    getattr(result, f"{prefix}_daemon_version"),
                )
                self.assertEqual(
                    cas.read(receipt["daemon_info_digest"]),
                    getattr(result, f"{prefix}_daemon_info"),
                )

    def test_infrastructure_failure_is_never_an_outcome(self) -> None:
        prepared = prepared_cisco()
        result = runtime.OCIExecutionError(
            error_code="CLEANUP_FAILED",
            message="container remains",
            baseline_name=prepared.baseline["name"],
            docker_path=str(prepared.docker.path),
            docker_digest=prepared.docker.digest,
            image_reference=prepared.verification.image_reference,
            raw_lock=prepared.raw_lock,
            selected_baseline_json=prepared.selected_json,
            effective_config_json=prepared.effective_config_json,
            runner_identity_json=prepared.runner_identity_json,
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(runner.RunnerError, "infrastructure"):
                runner._retain_run(
                    CAS(Path(temporary) / "state"),
                    {
                        "digest": SUITE,
                        "cases": {"case": {"tree_digest": SUBJECT}},
                    },
                    "case",
                    1,
                    prepared.system,
                    prepared,
                    result,
                    manifest_digest="sha256:" + "e" * 64,
                )

    def test_bounded_runtime_errors_round_trip_as_verified_error_evidence(
        self,
    ) -> None:
        cases = (
            ("TIMEOUT", b"", b""),
            ("OUTPUT_LIMIT_EXCEEDED", b"x" * 32, b""),
        )
        for error_code, stdout, stderr in cases:
            with (
                self.subTest(error_code=error_code),
                tempfile.TemporaryDirectory() as temporary,
            ):
                cas = CAS(Path(temporary) / "state")
                prepared, manifest, manifest_digest, result = retained_error_fixture(
                    cas,
                    error_code=error_code,
                    stdout=stdout,
                    stderr=stderr,
                )
                loaded = {
                    "digest": SUITE,
                    "cases": {"case": {"tree_digest": SUBJECT}},
                }
                outcome = runner._retain_run(
                    cas,
                    loaded,
                    "case",
                    1,
                    prepared.system,
                    prepared,
                    result,
                    manifest_digest=manifest_digest,
                )
                envelope = json.loads(cas.read(outcome["evidence_digest"]))
                postrun = json.loads(
                    cas.read(envelope["postrun_container_inspect_digest"])
                )

                self.assertEqual(
                    postrun[0]["State"],
                    {
                        "Status": "exited",
                        "Running": False,
                        "Dead": False,
                        "OOMKilled": False,
                        "ExitCode": 137,
                    },
                )
                self.assertEqual(envelope["execution"]["returncode"], 137)
                self.assertEqual(envelope["verified_subject_digest"], SUBJECT)
                self.assertEqual(envelope["observation_digests"], [])
                self.assertEqual(outcome["verdict"], "ERROR")
                self.assertEqual(
                    outcome["reason_codes"],
                    [f"ANALYZER_{error_code}"],
                )
                for field, raw in (
                    ("oci_index_digest", result.raw_oci_index_json),
                    (
                        "oci_platform_manifest_digest",
                        result.raw_oci_platform_manifest_json,
                    ),
                    (
                        "build_provenance_manifest_digest",
                        result.raw_build_provenance_manifest_json,
                    ),
                ):
                    self.assertEqual(cas.read(envelope[field]), raw)

                runner._verify_evidence(
                    cas,
                    outcome,
                    expected_manifest=manifest,
                    label=f"{error_code}:case:run-1",
                )

                if error_code == "TIMEOUT":
                    postrun[0]["State"]["Status"] = "running"
                    envelope["postrun_container_inspect_digest"] = cas.put(
                        BytesIO(canonical(postrun)),
                        max_bytes=len(canonical(postrun)),
                    )
                    outcome["evidence_digest"] = cas.put(
                        BytesIO(canonical(envelope)),
                        max_bytes=len(canonical(envelope)),
                    )
                    with self.assertRaisesRegex(
                        runner.BenchmarkError,
                        "State is inconsistent",
                    ):
                        runner._verify_evidence(
                            cas,
                            outcome,
                            expected_manifest=manifest,
                            label="tampered:case:run-1",
                        )

    def test_cli_failure_has_json_error_and_no_partial_stdout(self) -> None:
        output = StringIO()
        errors = StringIO()
        with (
            patch.object(
                runner,
                "run_files",
                side_effect=runner.RunnerError("late matrix failure"),
            ),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            status = runner.main(["run", "suite.json", "--state", "state"])

        self.assertEqual(status, 4)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(
            json.loads(errors.getvalue())["message"],
            "late matrix failure",
        )


def prepared_cisco() -> runner._PreparedBaseline:
    raw_config = b'{"config":"synthetic"}'
    config_digest = digest(raw_config)
    raw_platform_manifest = b'{"platform":"synthetic"}'
    raw_provenance_manifest = b'{"provenance":"synthetic"}'
    raw_oci_index = b'{"index":"synthetic"}'
    baseline = {
        "name": "cisco-skill-scanner",
        "version": "2.0.12",
        "image": {
            "index_digest": digest(raw_oci_index),
            "platform_manifest_digest": digest(raw_platform_manifest),
            "config_digest": config_digest,
            "build_provenance_manifest_digest": digest(
                raw_provenance_manifest
            ),
        },
    }
    raw_lock = canonical({"baselines": [baseline]})
    selected = canonical(baseline)
    docker = runtime.DockerExecutable(
        path=Path("/synthetic/docker"),
        digest="sha256:" + "3" * 64,
        identity=(1, 2, 3, 4),
    )
    verification = runtime.ImageVerification(
        name=baseline["name"],
        image_reference=(
            "aragorn/cisco-skill-scanner@" + baseline["image"]["index_digest"]
        ),
        raw_index_inspect=b"[]",
        raw_platform_inspect=b"[]",
        raw_oci_index_json=raw_oci_index,
        raw_oci_platform_manifest_json=raw_platform_manifest,
        raw_build_provenance_manifest_json=raw_provenance_manifest,
        raw_config_json=raw_config,
        image_entrypoint=("/opt/venv/bin/skill-scanner",),
        image_environment=("PATH=/usr/bin",),
    )
    identity = identity_support.normalize()
    effective = canonical(
        {
            "normalization": "cisco-ai-skill-scanner-2.0.12/v1",
            "runner_identity": json.loads(identity.document_json),
        }
    )
    system = {
        "name": baseline["name"],
        "version": baseline["version"],
        "implementation_digest": baseline["image"]["platform_manifest_digest"],
        "config_digest": digest(effective),
    }
    return runner._PreparedBaseline(
        baseline=baseline,
        raw_lock=raw_lock,
        selected_json=selected,
        docker=docker,
        verification=verification,
        effective_config_json=effective,
        runner_identity_json=identity.document_json,
        system=system,
    )


def execution_result(
    prepared: runner._PreparedBaseline, stdout: bytes
) -> runtime.OCIExecutionResult:
    image = prepared.baseline["image"]
    identity = identity_support.normalize()
    return runtime.OCIExecutionResult(
        baseline_name=prepared.baseline["name"],
        version=prepared.baseline["version"],
        docker_path=str(prepared.docker.path),
        docker_digest=prepared.docker.digest,
        image_reference=prepared.verification.image_reference,
        index_digest=image["index_digest"],
        platform_manifest_digest=image["platform_manifest_digest"],
        config_digest=image["config_digest"],
        container_id=CONTAINER_ID,
        raw_lock=prepared.raw_lock,
        selected_baseline_json=prepared.selected_json,
        effective_config_json=prepared.effective_config_json,
        raw_index_inspect=b"[]",
        raw_platform_inspect=b"[]",
        raw_oci_index_json=prepared.verification.raw_oci_index_json,
        raw_oci_platform_manifest_json=(
            prepared.verification.raw_oci_platform_manifest_json
        ),
        raw_build_provenance_manifest_json=(
            prepared.verification.raw_build_provenance_manifest_json
        ),
        raw_config_json=prepared.verification.raw_config_json,
        raw_prestart_container_inspect=b"[]",
        raw_postrun_container_inspect=b"[]",
        raw_stdout=stdout,
        raw_stderr=b"",
        returncode=0,
        verified_subject_digest=SUBJECT,
        raw_pre_context_inspect=identity.raw_context,
        raw_pre_daemon_version=identity.raw_version,
        raw_pre_daemon_info=identity.raw_info,
        raw_post_context_inspect=identity.raw_context,
        raw_post_daemon_version=identity.raw_version,
        raw_post_daemon_info=identity.raw_info,
        runner_identity_json=prepared.runner_identity_json,
    )


def retained_error_fixture(
    cas: CAS,
    *,
    error_code: str,
    stdout: bytes,
    stderr: bytes,
) -> tuple[
    runner._PreparedBaseline,
    dict,
    str,
    runtime.OCIExecutionError,
]:
    seed_outcome, manifest = evidence_support.OciEvidenceTests._evidence(
        cas,
        cisco_report(),
        evidence_version=3,
    )
    seed = json.loads(cas.read(seed_outcome["evidence_digest"]))
    raw_lock = cas.read(seed["baseline_lock_digest"])
    selected_json = cas.read(seed["baseline_entry_digest"])
    selected = json.loads(selected_json)
    effective = json.loads(cas.read(seed["effective_config_digest"]))
    effective["limits"]["output_bytes"] = 32
    effective_json = canonical(effective)
    system = {
        **seed_outcome["system"],
        "config_digest": digest(effective_json),
    }
    verification = runtime.ImageVerification(
        name=selected["name"],
        image_reference=effective["image"]["reference"],
        raw_index_inspect=cas.read(seed["index_inspect_digest"]),
        raw_platform_inspect=cas.read(seed["platform_inspect_digest"]),
        raw_oci_index_json=cas.read(seed["oci_index_digest"]),
        raw_oci_platform_manifest_json=cas.read(
            seed["oci_platform_manifest_digest"]
        ),
        raw_build_provenance_manifest_json=cas.read(
            seed["build_provenance_manifest_digest"]
        ),
        raw_config_json=cas.read(seed["image_config_digest"]),
        image_entrypoint=tuple(effective["entrypoint"]),
        image_environment=tuple(
            f"{name}={value}" for name, value in effective["environment"].items()
        ),
    )
    prepared = runner._PreparedBaseline(
        baseline=selected,
        raw_lock=raw_lock,
        selected_json=selected_json,
        docker=runtime.DockerExecutable(
            path=Path("/synthetic/docker"),
            digest=effective["docker_executable_digest"],
            identity=(1, 2, 3, 4),
        ),
        verification=verification,
        effective_config_json=effective_json,
        runner_identity_json=canonical(effective["runner_identity"]),
        system=system,
    )
    postrun = json.loads(cas.read(seed["postrun_container_inspect_digest"]))
    postrun[0]["State"]["ExitCode"] = 137
    error = runtime.OCIExecutionError(
        error_code=error_code,
        message=error_code.lower(),
        baseline_name=selected["name"],
        docker_path=str(prepared.docker.path),
        docker_digest=prepared.docker.digest,
        image_reference=verification.image_reference,
        container_id=CONTAINER_ID,
        raw_lock=raw_lock,
        selected_baseline_json=selected_json,
        effective_config_json=effective_json,
        raw_index_inspect=verification.raw_index_inspect,
        raw_platform_inspect=verification.raw_platform_inspect,
        raw_oci_index_json=verification.raw_oci_index_json,
        raw_oci_platform_manifest_json=verification.raw_oci_platform_manifest_json,
        raw_build_provenance_manifest_json=(
            verification.raw_build_provenance_manifest_json
        ),
        raw_config_json=verification.raw_config_json,
        raw_prestart_container_inspect=cas.read(
            seed["prestart_container_inspect_digest"]
        ),
        raw_postrun_container_inspect=canonical(postrun),
        raw_stdout=stdout,
        raw_stderr=stderr,
        returncode=137,
        verified_subject_digest=SUBJECT,
        raw_pre_context_inspect=cas.read(
            seed["runner_receipts"]["pre"]["context_inspect_digest"]
        ),
        raw_pre_daemon_version=cas.read(
            seed["runner_receipts"]["pre"]["daemon_version_digest"]
        ),
        raw_pre_daemon_info=cas.read(
            seed["runner_receipts"]["pre"]["daemon_info_digest"]
        ),
        raw_post_context_inspect=cas.read(
            seed["runner_receipts"]["post"]["context_inspect_digest"]
        ),
        raw_post_daemon_version=cas.read(
            seed["runner_receipts"]["post"]["daemon_version_digest"]
        ),
        raw_post_daemon_info=cas.read(
            seed["runner_receipts"]["post"]["daemon_info_digest"]
        ),
        runner_identity_json=prepared.runner_identity_json,
    )
    return prepared, manifest, seed["manifest_digest"], error


if __name__ == "__main__":
    unittest.main()
