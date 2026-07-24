from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from tests import test_docker_identity as identity_support  # noqa: E402

from aragorn import oci_runtime as runtime  # noqa: E402


CONTAINER_ID = "c" * 64
DOCKER_DIGEST = "sha256:" + "d" * 64


class StrictLockTests(unittest.TestCase):
    def test_lock_is_exactly_the_two_pending_pins(self) -> None:
        _raw, baselines = runtime.load_baseline_lock()

        self.assertEqual(
            {item["name"] for item in baselines},
            {"cisco-skill-scanner", "skillspector"},
        )
        self.assertEqual(
            {item["attestation_status"] for item in baselines},
            {"oci_closure_candidate_runner_attestation_pending"},
        )

    def test_partial_duplicate_forged_and_wrong_version_locks_fail(self) -> None:
        raw, baselines = runtime.load_baseline_lock()
        original = json.loads(raw)
        variants = []
        partial = copy.deepcopy(original)
        partial["baselines"].pop()
        variants.append(partial)
        duplicate = copy.deepcopy(original)
        duplicate["baselines"][1] = copy.deepcopy(duplicate["baselines"][0])
        variants.append(duplicate)
        forged = copy.deepcopy(original)
        forged["baselines"][0]["attestation_status"] = "attested"
        variants.append(forged)
        wrong_version = copy.deepcopy(original)
        wrong_version["baselines"][0]["version"] = "2.0.13"
        variants.append(wrong_version)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            for document in variants:
                with self.subTest(document=document):
                    path.write_text(json.dumps(document))
                    with self.assertRaises(runtime.VerificationError):
                        runtime.load_baseline_lock(path)

            path.write_text('{"schema":"x","schema":"y"}')
            with self.assertRaises(runtime.VerificationError):
                runtime.load_baseline_lock(path)

        self.assertEqual(len(baselines), 2)

    def test_resolved_docker_is_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "docker"
            executable.write_bytes(b"fake-docker")
            executable.chmod(0o700)

            resolved = runtime.resolve_docker(executable)

        self.assertEqual(
            resolved.digest,
            "sha256:" + hashlib.sha256(b"fake-docker").hexdigest(),
        )


class OCIRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_lock, baselines = runtime.load_baseline_lock()
        self.baseline = next(
            item for item in baselines if item["name"] == "cisco-skill-scanner"
        )
        self.docker = runtime.DockerExecutable(
            path=Path("/usr/bin/docker"),
            digest=DOCKER_DIGEST,
            identity=(1, 2, 3, 4),
        )
        self.verification = runtime.ImageVerification(
            name=self.baseline["name"],
            image_reference=(
                "aragorn/cisco-skill-scanner@"
                + self.baseline["image"]["index_digest"]
            ),
            raw_index_inspect=b'[{"index":true}]',
            raw_platform_inspect=b'[{"platform":true}]',
            raw_oci_index_json=b'{"schemaVersion":2,"manifests":[]}',
            raw_oci_platform_manifest_json=b'{"schemaVersion":2,"layers":[]}',
            raw_build_provenance_manifest_json=b'{"schemaVersion":2,"layers":[]}',
            raw_config_json=b'{"config":true}',
            image_entrypoint=("/opt/venv/bin/skill-scanner",),
            image_environment=("PATH=/usr/bin",),
        )
        self.raw_context = identity_support.encoded(identity_support.context())
        self.raw_version = identity_support.encoded(identity_support.version())
        self.raw_info = identity_support.encoded(identity_support.info())
        self.runner_identity = runtime.normalize_docker_identity(
            self.raw_context,
            self.raw_version,
            self.raw_info,
        )

    def _container(self, workspace: Path, *, phase: str) -> dict:
        policy = self.baseline["runtime_profile"]
        tmpfs = policy["tmpfs"]
        options = ",".join(
            [
                *tmpfs["options"][:-1],
                f"size={tmpfs['size_bytes']}",
                tmpfs["options"][-1],
            ]
        )
        return {
            "Id": CONTAINER_ID,
            "Image": self.baseline["image"]["index_digest"],
            "ImageManifestDescriptor": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": self.baseline["image"]["platform_manifest_digest"],
                "size": 100,
                "platform": {"architecture": "arm64", "os": "linux"},
            },
            "Path": "/opt/venv/bin/skill-scanner",
            "Args": [
                "scan",
                "/workspace",
                "--use-behavioral",
                "--policy",
                "strict",
                "--format",
                "json",
                "--compact",
            ],
            "Config": {
                "Image": self.verification.image_reference,
                "Entrypoint": list(self.verification.image_entrypoint),
                "Cmd": [
                    "scan",
                    "/workspace",
                    "--use-behavioral",
                    "--policy",
                    "strict",
                    "--format",
                    "json",
                    "--compact",
                ],
                "User": policy["user"],
                "WorkingDir": policy["workdir"],
                "Env": ["PATH=/usr/bin"],
                "ExposedPorts": None,
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges=true"],
                "Privileged": False,
                "PublishAllPorts": False,
                "PortBindings": {},
                "PidsLimit": policy["pids_limit"],
                "Memory": policy["memory_bytes"],
                "MemorySwap": policy["memory_swap_bytes"],
                "NanoCpus": 2_000_000_000,
                "Ulimits": [
                    {
                        "Name": "nofile",
                        "Hard": policy["nofile_hard"],
                        "Soft": policy["nofile_soft"],
                    }
                ],
                "Tmpfs": {"/tmp": options},
                "Mounts": [
                    {
                        "Type": "bind",
                        "Source": str(workspace),
                        "Target": "/workspace",
                        "ReadOnly": True,
                    }
                ],
            },
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(workspace),
                    "Destination": "/workspace",
                    "Mode": "ro",
                    "RW": False,
                }
            ],
            "NetworkSettings": {"Networks": {}, "Ports": {}},
            "State": (
                {
                    "Status": "created",
                    "Running": False,
                    "Dead": False,
                    "OOMKilled": False,
                    "ExitCode": 0,
                }
                if phase == "prestart"
                else {
                    "Status": "exited",
                    "Running": False,
                    "Dead": False,
                    "OOMKilled": False,
                    "ExitCode": 1,
                }
            ),
        }

    def _run(
        self,
        workspace: Path,
        *,
        prestart_container: dict | None = None,
        postrun_container: dict | None = None,
        start: runtime._ProcessResult | None = None,
        expected_tree_digest: str | None = None,
        create: runtime._ProcessResult | None = None,
        cleanup: runtime._ProcessResult | None = None,
        remaining_container_ids: bytes = b"",
        post_identity_error: Exception | None = None,
        expected_effective_config_json: bytes | None = None,
    ) -> tuple[
        runtime.OCIExecutionResult | runtime.OCIExecutionError,
        list[tuple[str, ...]],
    ]:
        calls: list[tuple[str, ...]] = []
        prestart = prestart_container or self._container(
            workspace, phase="prestart"
        )
        postrun = postrun_container or self._container(
            workspace, phase="postrun"
        )
        start_result = start or runtime._ProcessResult(b"report", b"warning", 1)
        create_result = create or runtime._ProcessResult(
            (CONTAINER_ID + "\n").encode(), b"", 0
        )
        cleanup_result = cleanup or runtime._ProcessResult(
            CONTAINER_ID.encode(), b"", 0
        )
        subject_digest = (
            expected_tree_digest
            if expected_tree_digest is not None
            else runtime.inventory_local(workspace)["tree_digest"]
        )
        inspect_count = 0

        def fake_run(argv: tuple[str, ...] | list[str], **_kwargs: object):
            nonlocal inspect_count
            command = tuple(argv)
            calls.append(command)
            environment = _kwargs["env"]
            assert isinstance(environment, dict)
            self.assertEqual(
                environment["DOCKER_HOST"],
                self.runner_identity.endpoint,
            )
            self.assertNotIn("DOCKER_CONTEXT", environment)
            if command[1] == "create":
                return create_result
            if command[1:3] == ("container", "inspect"):
                inspected = prestart if inspect_count == 0 else postrun
                inspect_count += 1
                return runtime._ProcessResult(
                    json.dumps([inspected]).encode(), b"", 0
                )
            if command[1] == "start":
                return start_result
            if command[1:3] == ("rm", "-f"):
                return cleanup_result
            if command[1] == "ps":
                return runtime._ProcessResult(remaining_container_ids, b"", 0)
            raise AssertionError(command)

        def capture_pre(
            _docker: runtime.DockerExecutable,
            control: Path,
            evidence: runtime._RunnerReceiptBuffer,
        ):
            evidence.raw_context = self.raw_context
            evidence.raw_version = self.raw_version
            evidence.raw_info = self.raw_info
            return (
                {"DOCKER_CONFIG": "/original"},
                {
                    "DOCKER_CONFIG": str(control / "docker-config"),
                    "DOCKER_HOST": self.runner_identity.endpoint,
                },
                self.runner_identity,
            )

        def capture_post(
            _docker: runtime.DockerExecutable,
            *,
            evidence: runtime._RunnerReceiptBuffer,
            **_kwargs: object,
        ):
            evidence.raw_context = self.raw_context
            evidence.raw_version = self.raw_version
            evidence.raw_info = self.raw_info
            if post_identity_error is not None:
                raise post_identity_error
            return self.runner_identity

        def verify_image(
            _docker: Path,
            _baseline: dict,
            *,
            env: dict[str, str],
        ):
            self.assertEqual(
                env["DOCKER_HOST"],
                self.runner_identity.endpoint,
            )
            calls.append((str(self.docker.path), "verify-image"))
            return self.verification

        with (
            patch.object(
                runtime,
                "load_baseline_lock",
                return_value=(self.raw_lock, (self.baseline,)),
            ),
            patch.object(runtime, "resolve_docker", return_value=self.docker),
            patch.object(runtime, "verify_image", side_effect=verify_image),
            patch.object(
                runtime,
                "_capture_pre_runner_identity",
                side_effect=capture_pre,
            ),
            patch.object(
                runtime,
                "_capture_post_runner_identity",
                side_effect=capture_post,
            ),
            patch.object(runtime, "_run_bounded", side_effect=fake_run),
            patch.object(runtime, "_verify_docker_unchanged"),
        ):
            result = runtime.run_baseline(
                self.baseline["name"],
                workspace=workspace,
                output_limit_bytes=32,
                expected_tree_digest=subject_digest,
                expected_effective_config_json=expected_effective_config_json,
            )
        return result, calls

    def test_create_uses_digest_never_tag_and_exact_sole_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            result, calls = self._run(workspace)

        self.assertIsInstance(result, runtime.OCIExecutionResult)
        create = next(item for item in calls if item[1] == "create")
        self.assertIn(self.verification.image_reference, create)
        self.assertNotIn(self.baseline["image"]["local_tag"], create)
        mount_indexes = [index for index, item in enumerate(create) if item == "--mount"]
        self.assertEqual(len(mount_indexes), 1)
        self.assertEqual(
            create[mount_indexes[0] + 1],
            f"type=bind,source={workspace},destination=/workspace,readonly",
        )
        self.assertTrue(any(item[1:3] == ("rm", "-f") for item in calls))
        self.assertEqual(result.raw_pre_context_inspect, self.raw_context)
        self.assertEqual(result.raw_post_daemon_info, self.raw_info)
        self.assertEqual(
            result.runner_identity_json,
            self.runner_identity.document_json,
        )

    def test_pre_capture_uses_existing_config_then_private_pinned_environment(
        self,
    ) -> None:
        calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def fake_run(argv: list[str], **kwargs: object):
            command = tuple(argv)
            environment = kwargs["env"]
            assert isinstance(environment, dict)
            calls.append((command, environment))
            if command[1:3] == ("context", "inspect"):
                raw = self.raw_context
            elif command[1] == "version":
                raw = self.raw_version
            elif command[1] == "info":
                raw = self.raw_info
            else:
                raise AssertionError(command)
            return runtime._ProcessResult(raw, b"", 0)

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(
                os.environ,
                {
                    "DOCKER_CONFIG": "/trusted/current-config",
                    "DOCKER_CONTEXT": "ambient-context",
                    "DOCKER_HOST": "tcp://attacker:2375",
                    "DOCKER_TLS_VERIFY": "0",
                },
                clear=False,
            ),
            patch.object(runtime, "_run_bounded", side_effect=fake_run),
            patch.object(runtime, "_verify_docker_unchanged"),
        ):
            control = Path(temporary)
            evidence = runtime._RunnerReceiptBuffer()
            discovery, execution, receipt = (
                runtime._capture_pre_runner_identity(
                    self.docker,
                    control,
                    evidence,
                )
            )
            private_config = Path(execution["DOCKER_CONFIG"])
            self.assertEqual(private_config.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(private_config.iterdir()), [])

        self.assertEqual(discovery["DOCKER_CONFIG"], "/trusted/current-config")
        self.assertNotIn("DOCKER_HOST", discovery)
        self.assertEqual(execution["DOCKER_HOST"], receipt.endpoint)
        self.assertNotIn("DOCKER_CONTEXT", execution)
        self.assertNotIn("DOCKER_TLS_VERIFY", execution)
        self.assertEqual(calls[0][1], discovery)
        self.assertEqual(calls[1][1], execution)
        self.assertEqual(calls[2][1], execution)
        self.assertEqual(
            calls[0][0][1:],
            (
                "context",
                "inspect",
                "--format",
                runtime.DOCKER_CONTEXT_TEMPLATE,
            ),
        )

    def test_pre_identity_failure_prevents_image_access_and_create(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            with (
                patch.object(
                    runtime,
                    "load_baseline_lock",
                    return_value=(self.raw_lock, (self.baseline,)),
                ),
                patch.object(
                    runtime, "resolve_docker", return_value=self.docker
                ),
                patch.object(
                    runtime,
                    "_capture_pre_runner_identity",
                    side_effect=runtime.DockerIdentityError("bad context"),
                ),
                patch.object(runtime, "verify_image") as verify_image,
                patch.object(runtime, "_run_bounded") as command,
            ):
                result = runtime.run_baseline(
                    self.baseline["name"],
                    workspace=workspace,
                    expected_tree_digest=runtime.inventory_local(workspace)[
                        "tree_digest"
                    ],
                )

        self.assertIsInstance(result, runtime.OCIExecutionError)
        self.assertEqual(result.error_code, "RUNNER_IDENTITY_FAILED")
        verify_image.assert_not_called()
        command.assert_not_called()

    def test_preflight_config_mismatch_prevents_create(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run(
                Path(temporary).resolve(),
                expected_effective_config_json=b"{}",
            )

        self.assertIsInstance(result, runtime.OCIExecutionError)
        self.assertEqual(result.error_code, "RUNNER_IDENTITY_CHANGED")
        self.assertFalse(any(item[1] == "verify-image" for item in calls))
        self.assertFalse(any(item[1] == "create" for item in calls))

    def test_post_identity_drift_fails_after_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run(
                Path(temporary).resolve(),
                post_identity_error=runtime.DockerIdentityError(
                    "Docker runner identity changed"
                ),
            )

        self.assertIsInstance(result, runtime.OCIExecutionError)
        self.assertEqual(result.error_code, "RUNNER_IDENTITY_CHANGED")
        self.assertTrue(any(item[1:3] == ("rm", "-f") for item in calls))
        self.assertEqual(result.raw_post_context_inspect, self.raw_context)

    def test_cleanup_failure_has_priority_over_runner_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, _calls = self._run(
                Path(temporary).resolve(),
                remaining_container_ids=(CONTAINER_ID + "\n").encode(),
                post_identity_error=runtime.DockerIdentityError(
                    "Docker runner identity changed"
                ),
            )

        self.assertIsInstance(result, runtime.OCIExecutionError)
        self.assertEqual(result.error_code, "CLEANUP_FAILED")

    def test_expected_tree_digest_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(TypeError):
                runtime.run_baseline(
                    self.baseline["name"],
                    workspace=Path(temporary),
                )

    def test_workspace_digest_mismatch_prevents_create_and_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run(
                Path(temporary).resolve(),
                expected_tree_digest="sha256:" + "0" * 64,
            )

        self.assertIsInstance(result, runtime.OCIExecutionError)
        self.assertEqual(result.error_code, "CREATE_FAILED")
        self.assertFalse(any(item[1] in {"create", "start"} for item in calls))

    def test_malformed_create_identity_cannot_hide_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result, calls = self._run(
                Path(temporary).resolve(),
                create=runtime._ProcessResult(b"not-a-container-id\n", b"", 0),
                cleanup=runtime._ProcessResult(b"", b"remove failed", 1),
                remaining_container_ids=(CONTAINER_ID + "\n").encode(),
            )

        self.assertIsInstance(result, runtime.OCIExecutionError)
        self.assertEqual(result.error_code, "CLEANUP_FAILED")
        self.assertIn("still exists", result.message)
        self.assertTrue(any(item[1:3] == ("rm", "-f") for item in calls))
        self.assertTrue(any(item[1] == "ps" for item in calls))

    def test_changed_workspace_digest_after_run_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            expected = runtime.inventory_local(workspace)["tree_digest"]
            changed = "sha256:" + "0" * 64
            if changed == expected:
                changed = "sha256:" + "1" * 64

            with patch.object(
                runtime,
                "inventory_local",
                side_effect=(
                    {"tree_digest": expected},
                    {"tree_digest": changed},
                ),
            ):
                result, calls = self._run(
                    workspace,
                    expected_tree_digest=expected,
                )

        self.assertIsInstance(result, runtime.OCIExecutionError)
        self.assertEqual(result.error_code, "POST_EXECUTION_INSPECT_FAILED")
        self.assertIn("workspace tree digest changed", result.message)
        self.assertTrue(any(item[1] == "start" for item in calls))
        self.assertTrue(any(item[1:3] == ("rm", "-f") for item in calls))

    def test_non_created_prestart_state_prevents_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            container = self._container(workspace, phase="prestart")
            container["State"]["Status"] = "exited"

            result, calls = self._run(
                workspace,
                prestart_container=container,
            )

        self.assertIsInstance(result, runtime.OCIExecutionError)
        self.assertEqual(result.error_code, "CONTAINER_POLICY_MISMATCH")
        self.assertFalse(any(item[1] == "start" for item in calls))
        self.assertTrue(any(item[1:3] == ("rm", "-f") for item in calls))

    def test_added_capabilities_and_devices_prevent_start(self) -> None:
        forbidden = (
            ("CapAdd", ["SYS_ADMIN"]),
            ("Devices", [{"PathOnHost": "/dev/kvm"}]),
            ("DeviceRequests", [{"Capabilities": [["gpu"]]}]),
        )
        for field, value in forbidden:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary).resolve()
                container = self._container(workspace, phase="prestart")
                container["HostConfig"][field] = value

                result, calls = self._run(
                    workspace,
                    prestart_container=container,
                )

                self.assertIsInstance(result, runtime.OCIExecutionError)
                self.assertEqual(
                    result.error_code,
                    "CONTAINER_POLICY_MISMATCH",
                )
                self.assertFalse(any(item[1] == "start" for item in calls))
                self.assertTrue(
                    any(item[1:3] == ("rm", "-f") for item in calls)
                )

    def test_inspect_mismatch_prevents_start_and_still_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve()
            container = self._container(workspace, phase="prestart")
            container["HostConfig"]["NetworkMode"] = "bridge"

            result, calls = self._run(
                workspace, prestart_container=container
            )

        self.assertIsInstance(result, runtime.OCIExecutionError)
        self.assertEqual(result.error_code, "CONTAINER_POLICY_MISMATCH")
        self.assertFalse(any(item[1] == "start" for item in calls))
        self.assertTrue(any(item[1:3] == ("rm", "-f") for item in calls))

    def test_output_limit_and_timeout_are_typed_and_cleaned_up(self) -> None:
        cases = (
            (
                runtime._ProcessResult(
                    b"x" * 32, b"", -9, output_exceeded=True
                ),
                "OUTPUT_LIMIT_EXCEEDED",
            ),
            (
                runtime._ProcessResult(b"", b"", -9, timed_out=True),
                "TIMEOUT",
            ),
        )
        for start, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temporary:
                result, calls = self._run(Path(temporary).resolve(), start=start)
                self.assertIsInstance(result, runtime.OCIExecutionError)
                self.assertEqual(result.error_code, code)
                self.assertTrue(result.raw_postrun_container_inspect)
                self.assertEqual(result.returncode, 1)
                self.assertTrue(any(item[1:3] == ("rm", "-f") for item in calls))

    def test_bounded_error_stops_running_container_before_final_inspect(self) -> None:
        running = {"State": {"Running": True}}
        exited = {"State": {"Running": False, "ExitCode": 137}}
        with (
            patch.object(
                runtime,
                "_inspect_container",
                side_effect=((running, b"running"), (exited, b"exited")),
            ),
            patch.object(
                runtime,
                "_run_bounded",
                return_value=runtime._ProcessResult(CONTAINER_ID.encode(), b"", 0),
            ) as command,
        ):
            container, raw = runtime._stop_and_inspect_container(
                self.docker.path,
                CONTAINER_ID,
                {},
            )

        self.assertEqual(container, exited)
        self.assertEqual(raw, b"exited")
        self.assertEqual(
            command.call_args.args[0],
            [
                str(self.docker.path),
                "kill",
                "--signal",
                "KILL",
                CONTAINER_ID,
            ],
        )


if __name__ == "__main__":
    unittest.main()
