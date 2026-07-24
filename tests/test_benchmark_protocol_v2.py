from __future__ import annotations

from copy import deepcopy
import unittest

from aragorn.benchmark_protocol_v2 import (
    build_portable_policy,
    build_worker_request_v2,
    canonical_request_digest_v2,
    canonical_result_digest_v2,
    portable_policy_digest,
    validate_portable_policy,
    validate_worker_request_v2,
    validate_worker_result_v2,
    verify_effective_config_binding_v2,
    verify_effective_config_policy_v2,
    verify_request_bindings_v2,
    verify_request_challenge_v2,
    verify_request_policy_v2,
    verify_request_result_binding_v2,
    verify_request_subject_v2,
)
from aragorn.oci_worker_protocol import (
    WorkerProtocolError,
    build_worker_request,
    canonical_digest,
    sanitize_subject_manifest,
    validate_worker_request,
    validate_worker_result,
)


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def subject_manifest() -> dict:
    files = [
        {
            "path": "SKILL.md",
            "size": 12,
            "digest": digest("1"),
            "executable": False,
        },
        {
            "path": "notes/readme.txt",
            "size": 7,
            "digest": digest("2"),
            "executable": False,
        },
    ]
    return sanitize_subject_manifest(
        {
            "schema": "aragorn/manifest/v1",
            "tree_digest": canonical_digest(files),
            "files": files,
        }
    )


def portable_policy() -> dict:
    return {
        "schema": "aragorn/benchmark-portable-policy/v1",
        "system": {
            "name": "cisco-skill-scanner",
            "version": "2.0.12",
            "implementation_digest": (
                "sha256:"
                "7fadcfbe836eef9490feba0fadd2ada564c11eb541077e3efee5f61edbd2e65c"
            ),
        },
        "baseline": {
            "lock_digest": digest("3"),
            "entry_digest": digest("4"),
        },
        "image": {
            "index_digest": digest("5"),
            "platform_manifest_digest": (
                "sha256:"
                "7fadcfbe836eef9490feba0fadd2ada564c11eb541077e3efee5f61edbd2e65c"
            ),
            "config_digest": digest("6"),
            "build_provenance_manifest_digest": digest("7"),
            "os": "linux",
            "architecture": "arm64",
            "size_bytes": 138_894_369,
        },
        "entrypoint": ["/opt/venv/bin/skill-scanner"],
        "arguments": [
            "scan",
            "/workspace",
            "--use-behavioral",
            "--policy",
            "strict",
            "--format",
            "json",
            "--compact",
        ],
        "environment": {"PATH": "/usr/bin"},
        "runtime_profile": {
            "engine": "docker",
            "pull": "never",
            "network": "none",
            "read_only_rootfs": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "user": "65532:65532",
            "workdir": "/opt/aragorn-control",
            "pids_limit": 256,
            "memory_bytes": 2_147_483_648,
            "memory_swap_bytes": 2_147_483_648,
            "cpus": 2,
            "nofile_soft": 1024,
            "nofile_hard": 1024,
            "tmpfs": {
                "destination": "/tmp",
                "size_bytes": 536_870_912,
                "options": [
                    "rw",
                    "noexec",
                    "nosuid",
                    "nodev",
                    "mode=1777",
                ],
            },
            "workspace": {
                "destination": "/workspace",
                "read_only": True,
            },
        },
        "limits": {
            "timeout_seconds": 120.0,
            "output_bytes": 1024 * 1024,
        },
        "normalization": "cisco-ai-skill-scanner-2.0.12/v1",
    }


def worker_request() -> tuple[dict, dict, dict]:
    subject = subject_manifest()
    policy = portable_policy()
    tokens = iter(("a" * 32, "b" * 64))
    request = build_worker_request_v2(
        subject,
        policy,
        token_hex=lambda _size: next(tokens),
    )
    return request, subject, policy


def worker_result(request: dict, policy: dict) -> dict:
    return {
        "schema": "aragorn/benchmark-worker-result/v2",
        "job_id": request["job_id"],
        "verifier_challenge": request["verifier_challenge"],
        "request_digest": canonical_request_digest_v2(request),
        "portable_policy_digest": portable_policy_digest(policy),
        "subject_manifest_digest": request["subject"]["manifest_digest"],
        "tree_digest": request["subject"]["tree_digest"],
        "verified_subject_digest": request["subject"]["tree_digest"],
        "system": deepcopy(request["system"]),
        "baseline_lock_digest": request["baseline"]["lock_digest"],
        "baseline_entry_digest": request["baseline"]["entry_digest"],
        "effective_config_digest": digest("8"),
        "docker_executable_digest": digest("9"),
        "oci_index_digest": policy["image"]["index_digest"],
        "oci_platform_manifest_digest": policy["image"]["platform_manifest_digest"],
        "build_provenance_manifest_digest": policy["image"][
            "build_provenance_manifest_digest"
        ],
        "index_inspect_digest": digest("a"),
        "platform_inspect_digest": digest("b"),
        "image_config_digest": policy["image"]["config_digest"],
        "runner_receipts": {
            "pre": {
                "context_inspect_digest": digest("c"),
                "daemon_version_digest": digest("d"),
                "daemon_info_digest": digest("e"),
            },
            "post": {
                "context_inspect_digest": digest("c"),
                "daemon_version_digest": digest("d"),
                "daemon_info_digest": digest("e"),
            },
        },
        "prestart_container_inspect_digest": digest("f"),
        "postrun_container_inspect_digest": digest("0"),
        "stdout_digest": digest("1"),
        "stderr_digest": digest("2"),
        "observation_digests": [],
        "execution": {
            "status": "ok",
            "error_code": None,
            "returncode": 0,
            "container_id": "3" * 64,
        },
        "normalization": policy["normalization"],
        "verdict": "ALLOW",
        "reason_codes": [],
    }


def runner_identity() -> dict:
    return {
        "assurance": "docker_daemon_self_report_not_attested",
        "context": {
            "name": "phase0",
            "endpoint": "unix:///tmp/docker.sock",
            "skip_tls_verify": False,
            "tls_material_count": 0,
        },
        "engine": {
            "platform_name": "Docker Engine",
            "version": "25.0.0",
            "api_version": "1.44",
            "minimum_api_version": "1.24",
            "git_commit": "abc123",
            "go_version": "go1.22",
            "os": "linux",
            "architecture": "arm64",
            "kernel_version": "6.8.0",
            "build_time": "2026-07-23T00:00:00Z",
            "components": [
                {
                    "name": "Engine",
                    "version": "25.0.0",
                    "git_commit": "abc123",
                },
                {
                    "name": "containerd",
                    "version": "1.7.0",
                    "git_commit": "def456",
                },
                {
                    "name": "runc",
                    "version": "1.2.0",
                    "git_commit": "789abc",
                },
            ],
        },
        "worker_claim": {
            "daemon_id": "daemon-1",
            "daemon_name": "phase0",
            "server_version": "25.0.0",
            "operating_system": "Linux",
            "os": "linux",
            "architecture": "arm64",
            "kernel_version": "6.8.0",
            "security_options": ["name=seccomp,profile=default"],
            "cgroup_version": "2",
            "default_runtime": "runc",
            "storage_driver": "overlay2",
        },
    }


def effective_config(policy: dict, result: dict) -> dict:
    return {
        "schema": "aragorn/benchmark-oci-system-config/v2",
        "name": policy["system"]["name"],
        "version": policy["system"]["version"],
        "baseline_lock_digest": policy["baseline"]["lock_digest"],
        "baseline_entry_digest": policy["baseline"]["entry_digest"],
        "docker_executable_digest": result["docker_executable_digest"],
        "runner_identity": runner_identity(),
        "image": {
            "reference": (
                f"aragorn/cisco-skill-scanner@{policy['image']['index_digest']}"
            ),
            **{
                field: policy["image"][field]
                for field in (
                    "index_digest",
                    "platform_manifest_digest",
                    "config_digest",
                    "os",
                    "architecture",
                    "size_bytes",
                )
            },
        },
        "entrypoint": deepcopy(policy["entrypoint"]),
        "arguments": deepcopy(policy["arguments"]),
        "environment": deepcopy(policy["environment"]),
        "runtime_profile": deepcopy(policy["runtime_profile"]),
        "limits": deepcopy(policy["limits"]),
        "normalization": policy["normalization"],
    }


class PortablePolicyTests(unittest.TestCase):
    def test_digest_is_deterministic_and_builder_returns_an_independent_copy(
        self,
    ) -> None:
        original = portable_policy()
        reordered = {key: deepcopy(original[key]) for key in reversed(tuple(original))}
        reordered["environment"] = {
            key: reordered["environment"][key]
            for key in reversed(tuple(reordered["environment"]))
        }

        built = build_portable_policy(original)

        self.assertEqual(
            portable_policy_digest(original),
            portable_policy_digest(reordered),
        )
        self.assertEqual(portable_policy_digest(built), canonical_digest(built))
        original["runtime_profile"]["network"] = "bridge"
        self.assertEqual(built["runtime_profile"]["network"], "none")
        validate_portable_policy(built)

    def test_policy_weakening_and_host_specific_fields_fail_closed(self) -> None:
        mutations: list[tuple[str, dict]] = []

        for field, value in (
            ("network", "bridge"),
            ("read_only_rootfs", False),
            ("cap_drop", []),
            ("no_new_privileges", False),
        ):
            changed = deepcopy(portable_policy())
            changed["runtime_profile"][field] = value
            mutations.append((field, changed))

        writable_workspace = deepcopy(portable_policy())
        writable_workspace["runtime_profile"]["workspace"]["read_only"] = False
        mutations.append(("writable workspace", writable_workspace))

        host_argument = deepcopy(portable_policy())
        host_argument["arguments"][1] = "/Users/operator/private-fixture"
        mutations.append(("host path", host_argument))

        docker_endpoint = deepcopy(portable_policy())
        docker_endpoint["environment"]["DOCKER_HOST"] = "unix:///var/run/docker.sock"
        mutations.append(("Docker endpoint", docker_endpoint))

        for field in (
            "docker_executable_digest",
            "runner_identity",
            "runtime_identity",
            "host_workspace_path",
            "signature",
            "attestation",
            "class",
            "family",
        ):
            changed = deepcopy(portable_policy())
            changed[field] = "forbidden"
            mutations.append((field, changed))

        image_reference = deepcopy(portable_policy())
        image_reference["image"]["reference"] = "local/private:latest"
        mutations.append(("image reference", image_reference))

        workspace_source = deepcopy(portable_policy())
        workspace_source["runtime_profile"]["workspace"]["source"] = "/tmp/private"
        mutations.append(("workspace source", workspace_source))

        for label, mutation in mutations:
            with self.subTest(label=label):
                with self.assertRaises(WorkerProtocolError):
                    validate_portable_policy(mutation)

    def test_policy_rejects_unpinned_system_and_cross_system_image(self) -> None:
        unpinned = deepcopy(portable_policy())
        unpinned["system"]["version"] = "2.0.13"
        with self.assertRaisesRegex(WorkerProtocolError, "pinned worker version"):
            validate_portable_policy(unpinned)

        mismatched_image = deepcopy(portable_policy())
        mismatched_image["image"]["platform_manifest_digest"] = digest("9")
        with self.assertRaisesRegex(WorkerProtocolError, "pinned system"):
            validate_portable_policy(mismatched_image)


class WorkerRequestV2Tests(unittest.TestCase):
    def test_builder_binds_policy_subject_baseline_limits_and_fresh_challenge(
        self,
    ) -> None:
        calls: list[int] = []
        tokens = iter(("a" * 32, "b" * 64))

        def token_hex(size: int) -> str:
            calls.append(size)
            return next(tokens)

        subject = subject_manifest()
        policy = portable_policy()
        request = build_worker_request_v2(
            subject,
            policy,
            token_hex=token_hex,
        )

        self.assertEqual(calls, [16, 32])
        self.assertEqual(request["job_id"], "a" * 32)
        self.assertEqual(request["verifier_challenge"], "b" * 64)
        self.assertEqual(
            request["portable_policy_digest"],
            portable_policy_digest(policy),
        )
        self.assertEqual(request["system"], policy["system"])
        self.assertEqual(request["baseline"], policy["baseline"])
        self.assertEqual(request["limits"], policy["limits"])
        self.assertEqual(
            canonical_request_digest_v2(request),
            canonical_digest(request),
        )
        verify_request_bindings_v2(
            request,
            subject,
            policy,
            expected_challenge="b" * 64,
        )

    def test_malformed_and_stale_verifier_challenges_fail_closed(self) -> None:
        request, subject, policy = worker_request()

        malformed = deepcopy(request)
        malformed["verifier_challenge"] = "not-a-256-bit-challenge"
        with self.assertRaisesRegex(WorkerProtocolError, "verifier_challenge"):
            validate_worker_request_v2(malformed)

        with self.assertRaisesRegex(WorkerProtocolError, "stale"):
            verify_request_challenge_v2(request, "c" * 64)

        with self.assertRaisesRegex(WorkerProtocolError, "canonical lowercase hex"):
            verify_request_challenge_v2(request, "malformed")

        with self.assertRaisesRegex(WorkerProtocolError, "verifier_challenge"):
            build_worker_request_v2(
                subject,
                policy,
                verifier_challenge="short",
                token_hex=lambda _size: "a" * 32,
            )

    def test_subject_and_policy_drift_are_rejected(self) -> None:
        request, subject, policy = worker_request()
        verify_request_subject_v2(request, subject)
        verify_request_policy_v2(request, policy)

        changed_subject = deepcopy(subject)
        changed_subject["files"][0]["size"] += 1
        changed_subject["tree_digest"] = canonical_digest(changed_subject["files"])
        with self.assertRaisesRegex(WorkerProtocolError, "manifest digest"):
            verify_request_subject_v2(request, changed_subject)

        changed_tree_binding = deepcopy(request)
        changed_tree_binding["subject"]["tree_digest"] = digest("f")
        with self.assertRaisesRegex(WorkerProtocolError, "tree digest"):
            verify_request_subject_v2(changed_tree_binding, subject)

        changed_policy = deepcopy(policy)
        changed_policy["runtime_profile"]["cpus"] = 1
        with self.assertRaisesRegex(WorkerProtocolError, "policy binding"):
            verify_request_policy_v2(request, changed_policy)

        changed_baseline = deepcopy(policy)
        changed_baseline["baseline"]["entry_digest"] = digest("e")
        changed_request = deepcopy(request)
        changed_request["portable_policy_digest"] = portable_policy_digest(
            changed_baseline
        )
        with self.assertRaisesRegex(WorkerProtocolError, "baseline"):
            verify_request_policy_v2(changed_request, changed_baseline)

        changed_limits = deepcopy(policy)
        changed_limits["limits"]["output_bytes"] //= 2
        changed_request = deepcopy(request)
        changed_request["portable_policy_digest"] = portable_policy_digest(
            changed_limits
        )
        with self.assertRaisesRegex(WorkerProtocolError, "limits"):
            verify_request_policy_v2(changed_request, changed_limits)

    def test_labels_signatures_attestation_and_runtime_identity_are_rejected(
        self,
    ) -> None:
        request, _subject, _policy = worker_request()
        forbidden = (
            "suite_digest",
            "case_id",
            "class",
            "family",
            "lineage",
            "split",
            "run_id",
            "purpose",
            "source",
            "expected_verdict",
            "signature",
            "attested",
            "attestation",
            "worker_assurance",
            "runner_identity",
            "runtime_identity",
            "docker_executable_digest",
            "docker_endpoint",
            "host_workspace_path",
        )
        for field in forbidden:
            mutation = deepcopy(request)
            mutation[field] = "forbidden"
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    WorkerProtocolError,
                    "missing or unknown fields",
                ):
                    validate_worker_request_v2(mutation)

    def test_v1_and_v2_requests_cannot_be_substituted(self) -> None:
        request_v2, subject, policy = worker_request()
        request_v1 = build_worker_request(
            subject,
            {
                **policy["system"],
                "config_digest": digest("d"),
            },
            baseline_lock_digest=policy["baseline"]["lock_digest"],
            baseline_entry_digest=policy["baseline"]["entry_digest"],
            timeout_seconds=policy["limits"]["timeout_seconds"],
            output_limit_bytes=policy["limits"]["output_bytes"],
            token_hex=lambda size: "a" * (size * 2),
        )

        with self.assertRaises(WorkerProtocolError):
            validate_worker_request_v2(request_v1)
        with self.assertRaises(WorkerProtocolError):
            validate_worker_request(request_v2)

        schema_only_substitution = deepcopy(request_v2)
        schema_only_substitution["schema"] = "aragorn/benchmark-worker-request/v1"
        with self.assertRaisesRegex(WorkerProtocolError, "schema is unsupported"):
            validate_worker_request_v2(schema_only_substitution)


class WorkerResultV2Tests(unittest.TestCase):
    def test_valid_result_binds_to_issued_request_policy_and_challenge(self) -> None:
        request, _subject, policy = worker_request()
        result = worker_result(request, policy)
        request_digest = canonical_request_digest_v2(request)

        validate_worker_result_v2(result)
        self.assertEqual(canonical_result_digest_v2(result), canonical_digest(result))
        verify_request_result_binding_v2(
            request,
            policy,
            result,
            expected_request_digest=request_digest,
            expected_challenge=request["verifier_challenge"],
        )

    def test_effective_config_binds_policy_projection_and_docker_bytes(self) -> None:
        request, _subject, policy = worker_request()
        result = worker_result(request, policy)
        config = effective_config(policy, result)
        result["effective_config_digest"] = canonical_digest(config)

        verify_effective_config_policy_v2(
            policy,
            config,
            expected_config_digest=result["effective_config_digest"],
            expected_docker_digest=result["docker_executable_digest"],
        )
        verify_effective_config_binding_v2(policy, result, config)

        docker_drift = deepcopy(config)
        docker_drift["docker_executable_digest"] = digest("f")
        changed_result = deepcopy(result)
        changed_result["effective_config_digest"] = canonical_digest(docker_drift)
        with self.assertRaisesRegex(WorkerProtocolError, "docker_executable"):
            verify_effective_config_binding_v2(
                policy,
                changed_result,
                docker_drift,
            )

        wrong_digest = deepcopy(result)
        wrong_digest["effective_config_digest"] = digest("f")
        with self.assertRaisesRegex(WorkerProtocolError, "digest"):
            verify_effective_config_binding_v2(policy, wrong_digest, config)

    def test_effective_config_policy_and_runner_drift_fail_closed(self) -> None:
        request, _subject, policy = worker_request()
        result = worker_result(request, policy)
        config = effective_config(policy, result)
        mutations: list[tuple[str, dict]] = []

        changed = deepcopy(config)
        changed["runtime_profile"]["cpus"] = 1
        mutations.append(("runtime profile", changed))

        changed = deepcopy(config)
        changed["image"]["size_bytes"] += 1
        mutations.append(("image", changed))

        changed = deepcopy(config)
        changed["arguments"].append("--extra")
        mutations.append(("arguments", changed))

        changed = deepcopy(config)
        changed["environment"]["EXTRA"] = "1"
        mutations.append(("environment", changed))

        changed = deepcopy(config)
        changed["limits"]["output_bytes"] //= 2
        mutations.append(("limits", changed))

        for field, mutation in mutations:
            changed_result = deepcopy(result)
            changed_result["effective_config_digest"] = canonical_digest(mutation)
            with self.subTest(field=field):
                with self.assertRaisesRegex(WorkerProtocolError, "binding"):
                    verify_effective_config_binding_v2(
                        policy,
                        changed_result,
                        mutation,
                    )

        runner_drift = deepcopy(config)
        runner_drift["runner_identity"]["context"]["skip_tls_verify"] = True
        changed_result = deepcopy(result)
        changed_result["effective_config_digest"] = canonical_digest(runner_drift)
        with self.assertRaisesRegex(WorkerProtocolError, "TLS"):
            verify_effective_config_binding_v2(
                policy,
                changed_result,
                runner_drift,
            )

        mutable_reference = deepcopy(config)
        mutable_reference["image"]["reference"] = (
            f"aragorn/cisco-skill-scanner:latest@{policy['image']['index_digest']}"
        )
        changed_result = deepcopy(result)
        changed_result["effective_config_digest"] = canonical_digest(mutable_reference)
        with self.assertRaisesRegex(WorkerProtocolError, "digest-only"):
            verify_effective_config_binding_v2(
                policy,
                changed_result,
                mutable_reference,
            )

    def test_result_surface_is_exact_unsigned_and_version_separated(self) -> None:
        request, _subject, policy = worker_request()
        result = worker_result(request, policy)

        missing = deepcopy(result)
        del missing["stderr_digest"]
        with self.assertRaisesRegex(WorkerProtocolError, "missing or unknown"):
            validate_worker_result_v2(missing)

        for field in (
            "nonce",
            "signature",
            "attestation",
            "worker_assurance",
            "labels",
            "runner_identity",
            "runtime_identity",
        ):
            mutation = deepcopy(result)
            mutation[field] = "forbidden"
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    WorkerProtocolError,
                    "missing or unknown",
                ):
                    validate_worker_result_v2(mutation)

        retagged = deepcopy(result)
        retagged["schema"] = "aragorn/benchmark-worker-result/v1"
        with self.assertRaisesRegex(WorkerProtocolError, "schema is unsupported"):
            validate_worker_result_v2(retagged)
        with self.assertRaises(WorkerProtocolError):
            validate_worker_result(result)

    def test_internal_subject_platform_and_normalization_invariants(self) -> None:
        request, _subject, policy = worker_request()
        result = worker_result(request, policy)

        mutations = []
        changed = deepcopy(result)
        changed["verified_subject_digest"] = digest("f")
        mutations.append(("verified subject", changed))

        changed = deepcopy(result)
        changed["oci_platform_manifest_digest"] = digest("f")
        mutations.append(("platform manifest", changed))

        changed = deepcopy(result)
        changed["normalization"] = "nvidia-skillspector-2.4.3/v1"
        mutations.append(("normalization", changed))

        changed = deepcopy(result)
        changed["observation_digests"] = [digest("a"), digest("a")]
        mutations.append(("duplicate observations", changed))

        for label, mutation in mutations:
            with self.subTest(label=label):
                with self.assertRaises(WorkerProtocolError):
                    validate_worker_result_v2(mutation)

        normalizer_order = deepcopy(result)
        normalizer_order["observation_digests"] = [digest("b"), digest("a")]
        validate_worker_result_v2(normalizer_order)

    def test_every_result_binding_fails_closed_on_drift(self) -> None:
        request, _subject, policy = worker_request()
        request_digest = canonical_request_digest_v2(request)
        result = worker_result(request, policy)
        mutations: list[tuple[str, dict]] = []

        for field, value in (
            ("job_id", "c" * 32),
            ("verifier_challenge", "c" * 64),
            ("request_digest", digest("c")),
            ("portable_policy_digest", digest("c")),
            ("subject_manifest_digest", digest("c")),
            ("baseline_lock_digest", digest("c")),
            ("baseline_entry_digest", digest("c")),
            ("oci_index_digest", digest("c")),
            ("build_provenance_manifest_digest", digest("c")),
            ("image_config_digest", digest("c")),
        ):
            changed = deepcopy(result)
            changed[field] = value
            mutations.append((field, changed))

        changed = deepcopy(result)
        changed["tree_digest"] = digest("c")
        changed["verified_subject_digest"] = digest("c")
        mutations.append(("tree_digest", changed))

        for field, mutation in mutations:
            with self.subTest(field=field):
                with self.assertRaisesRegex(WorkerProtocolError, "binding"):
                    verify_request_result_binding_v2(
                        request,
                        policy,
                        mutation,
                        expected_request_digest=request_digest,
                        expected_challenge=request["verifier_challenge"],
                    )

    def test_cross_system_result_cannot_change_system_platform_or_normalization(
        self,
    ) -> None:
        request, _subject, policy = worker_request()
        result = worker_result(request, policy)
        result["system"] = {
            "name": "skillspector",
            "version": "2.4.3+git.a54947c",
            "implementation_digest": (
                "sha256:"
                "e731be01105243f94437a4b9bd449bd46bbcb5cb306f44b4845121d109a4a95e"
            ),
        }
        result["oci_platform_manifest_digest"] = result["system"][
            "implementation_digest"
        ]
        result["normalization"] = "nvidia-skillspector-2.4.3/v1"

        validate_worker_result_v2(result)
        with self.assertRaisesRegex(WorkerProtocolError, "system"):
            verify_request_result_binding_v2(
                request,
                policy,
                result,
                expected_request_digest=canonical_request_digest_v2(request),
                expected_challenge=request["verifier_challenge"],
            )

    def test_coordinated_request_rewrites_fail_external_identity_checks(self) -> None:
        request, _subject, policy = worker_request()
        issued_request_digest = canonical_request_digest_v2(request)
        result = worker_result(request, policy)

        replayed_request = deepcopy(request)
        replayed_request["verifier_challenge"] = "c" * 64
        replayed_result = deepcopy(result)
        replayed_result["verifier_challenge"] = "c" * 64
        replayed_result["request_digest"] = canonical_request_digest_v2(
            replayed_request
        )
        with self.assertRaisesRegex(WorkerProtocolError, "stale"):
            verify_request_result_binding_v2(
                replayed_request,
                policy,
                replayed_result,
                expected_request_digest=issued_request_digest,
                expected_challenge=request["verifier_challenge"],
            )

        substituted_policy = deepcopy(policy)
        substituted_policy["runtime_profile"]["cpus"] = 1
        substituted_request = deepcopy(request)
        substituted_request["portable_policy_digest"] = portable_policy_digest(
            substituted_policy
        )
        substituted_result = deepcopy(result)
        substituted_result["portable_policy_digest"] = portable_policy_digest(
            substituted_policy
        )
        substituted_result["request_digest"] = canonical_request_digest_v2(
            substituted_request
        )
        with self.assertRaisesRegex(WorkerProtocolError, "verifier-issued"):
            verify_request_result_binding_v2(
                substituted_request,
                substituted_policy,
                substituted_result,
                expected_request_digest=issued_request_digest,
                expected_challenge=request["verifier_challenge"],
            )

    def test_execution_verdict_and_reason_invariants_fail_closed(self) -> None:
        request, _subject, policy = worker_request()
        result = worker_result(request, policy)
        mutations: list[tuple[str, dict]] = []

        invalid_exit = deepcopy(result)
        invalid_exit["execution"]["returncode"] = 2
        mutations.append(("invalid successful exit", invalid_exit))

        timeout_success = deepcopy(result)
        timeout_success["execution"] = {
            "status": "error",
            "error_code": "TIMEOUT",
            "returncode": 0,
            "container_id": "3" * 64,
        }
        timeout_success["verdict"] = "ERROR"
        timeout_success["reason_codes"] = ["ANALYZER_TIMEOUT"]
        mutations.append(("timeout with successful exit", timeout_success))

        wrong_error_verdict = deepcopy(result)
        wrong_error_verdict["execution"] = {
            "status": "error",
            "error_code": "TIMEOUT",
            "returncode": -1,
            "container_id": "3" * 64,
        }
        wrong_error_verdict["verdict"] = "DENY"
        wrong_error_verdict["reason_codes"] = ["ANALYZER_TIMEOUT"]
        mutations.append(("wrong error verdict", wrong_error_verdict))

        error_observation = deepcopy(wrong_error_verdict)
        error_observation["verdict"] = "ERROR"
        error_observation["observation_digests"] = [digest("a")]
        mutations.append(("error with observation", error_observation))

        success_error = deepcopy(result)
        success_error["verdict"] = "ERROR"
        success_error["reason_codes"] = ["ANALYZER_TIMEOUT"]
        mutations.append(("successful ERROR", success_error))

        allow_reason = deepcopy(result)
        allow_reason["reason_codes"] = ["SUSPICIOUS_PROMPT"]
        mutations.append(("ALLOW with reason", allow_reason))

        review_without_reason = deepcopy(result)
        review_without_reason["verdict"] = "REVIEW"
        mutations.append(("REVIEW without reason", review_without_reason))

        duplicate_reasons = deepcopy(result)
        duplicate_reasons["verdict"] = "REVIEW"
        duplicate_reasons["reason_codes"] = [
            "SUSPICIOUS_PROMPT",
            "SUSPICIOUS_PROMPT",
        ]
        mutations.append(("duplicate reasons", duplicate_reasons))

        for label, mutation in mutations:
            with self.subTest(label=label):
                with self.assertRaises(WorkerProtocolError):
                    validate_worker_result_v2(mutation)

        valid_timeout = deepcopy(result)
        valid_timeout["execution"] = {
            "status": "error",
            "error_code": "TIMEOUT",
            "returncode": -1,
            "container_id": "3" * 64,
        }
        valid_timeout["verdict"] = "ERROR"
        valid_timeout["reason_codes"] = ["ANALYZER_TIMEOUT"]
        validate_worker_result_v2(valid_timeout)


if __name__ == "__main__":
    unittest.main()
