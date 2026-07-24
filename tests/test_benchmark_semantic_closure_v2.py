from __future__ import annotations

from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import aragorn.benchmark_protocol_v2 as benchmark_protocol_v2
import aragorn.benchmark_handoff_v2 as benchmark_handoff_v2
from tests import test_benchmark_oci_evidence as evidence_support
from aragorn.benchmark_handoff_v2 import (
    HandoffError,
    build_handoff_manifest,
    build_worker_input_handoff_manifest,
    build_worker_output_handoff_manifest,
    export_declared_byte_transport,
    export_handoff,
    handoff_manifest_digest,
    import_handoff,
)
from aragorn.benchmark_protocol_v2 import build_worker_request_v2
from aragorn.benchmark_semantic_closure_v2 import (
    SemanticClosureError,
    derive_worker_input_cas_closure,
    derive_worker_output_cas_closure,
    verify_worker_output_evidence_cas_v2,
)
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import (
    canonical_digest,
    canonical_json,
    sanitize_subject_manifest,
)


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _portable_policy() -> dict:
    implementation = (
        "sha256:7fadcfbe836eef9490feba0fadd2ada564c11eb541077e3efee5f61edbd2e65c"
    )
    return {
        "schema": "aragorn/benchmark-portable-policy/v1",
        "system": {
            "name": "cisco-skill-scanner",
            "version": "2.0.12",
            "implementation_digest": implementation,
        },
        "baseline": {
            "lock_digest": _digest("3"),
            "entry_digest": _digest("4"),
        },
        "image": {
            "index_digest": _digest("5"),
            "platform_manifest_digest": implementation,
            "config_digest": _digest("6"),
            "build_provenance_manifest_digest": _digest("7"),
            "os": "linux",
            "architecture": "arm64",
            "size_bytes": 138_894_369,
        },
        "entrypoint": ["/opt/venv/bin/skill-scanner"],
        "arguments": ["scan", "/workspace"],
        "environment": {},
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
                "options": ["rw", "noexec", "nosuid", "nodev", "mode=1777"],
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


def _runner_identity() -> dict:
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


class BenchmarkSemanticClosureV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.source = CAS(self.root / "source")

    def test_derives_and_transports_exact_worker_input_semantics(self) -> None:
        request_digest, expected = self._input_closure()

        derived = derive_worker_input_cas_closure(
            self.source,
            request_digest,
            expected_challenge="b" * 64,
        )
        manifest = build_worker_input_handoff_manifest(
            self.source,
            request_digest,
            expected_verifier_challenge="b" * 64,
        )

        self.assertEqual(derived, expected)
        self.assertEqual(
            {item["digest"]: item["size"] for item in manifest["blobs"]},
            expected,
        )
        bundle = self.root / "bundle"
        manifest_digest = export_handoff(
            self.source,
            manifest,
            bundle,
            expected_verifier_challenge="b" * 64,
        )
        destination = CAS(self.root / "destination")
        imported = import_handoff(
            bundle,
            destination,
            expected_manifest_digest=manifest_digest,
            expected_kind="worker_input",
            expected_root_digest=request_digest,
            expected_verifier_challenge="b" * 64,
        )

        self.assertEqual(imported, manifest)
        for digest, size in expected.items():
            destination.verify(digest, max_bytes=size)

    def test_deep_v2_verifier_rechecks_oci_receipts_and_vendor_evidence(self) -> None:
        result_digest, request_digest, result = self._deep_output()

        verified = verify_worker_output_evidence_cas_v2(
            self.source,
            result_digest,
            expected_request_digest=request_digest,
            expected_challenge="b" * 64,
        )
        self.assertIn(result_digest, verified)

        forged = dict(result)
        forged_receipts = {
            phase: dict(receipt)
            for phase, receipt in result["runner_receipts"].items()
        }
        forged_receipts["post"]["daemon_info_digest"] = self._put(
            self.source, b"{}"
        )
        forged["runner_receipts"] = forged_receipts
        forged_digest = self._put(self.source, canonical_json(forged))
        with self.assertRaisesRegex(SemanticClosureError, "OCI evidence"):
            verify_worker_output_evidence_cas_v2(
                self.source,
                forged_digest,
                expected_request_digest=request_digest,
                expected_challenge="b" * 64,
            )

    def test_export_rejects_missing_extra_and_wrong_worker_input_root(self) -> None:
        request_digest, exact = self._input_closure()
        arbitrary_digest = self._put(self.source, b"not semantically reachable")
        cases = {}

        missing = dict(exact)
        missing.pop(next(digest for digest in exact if digest != request_digest))
        cases["missing"] = build_handoff_manifest(
            kind="worker_input",
            root_digest=request_digest,
            blobs=missing,
        )

        extra = {**exact, arbitrary_digest: len(b"not semantically reachable")}
        cases["extra"] = build_handoff_manifest(
            kind="worker_input",
            root_digest=request_digest,
            blobs=extra,
        )

        wrong_root = next(digest for digest in exact if digest != request_digest)
        cases["wrong-root"] = build_handoff_manifest(
            kind="worker_input",
            root_digest=wrong_root,
            blobs=exact,
        )

        for label, manifest in cases.items():
            destination = self.root / f"rejected-{label}"
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    HandoffError,
                    "worker-input .*semantic closure",
                ),
            ):
                export_handoff(
                    self.source,
                    manifest,
                    destination,
                    expected_verifier_challenge="b" * 64,
                )
            self.assertFalse(destination.exists())

    def test_import_rejects_authenticated_semantic_extra_before_cas_publish(
        self,
    ) -> None:
        request_digest, exact = self._input_closure()
        extra_content = b"authenticated but unreachable"
        extra_digest = self._put(self.source, extra_content)
        blobs = {**exact, extra_digest: len(extra_content)}

        transport_manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=request_digest,
            blobs=blobs,
        )
        bundle = self.root / "invalid-input-bundle"
        export_declared_byte_transport(self.source, transport_manifest, bundle)

        invalid_input = build_handoff_manifest(
            kind="worker_input",
            root_digest=request_digest,
            blobs=blobs,
        )
        manifest_path = bundle / "manifest.json"
        manifest_path.chmod(0o644)
        manifest_path.write_bytes(canonical_json(invalid_input))
        manifest_path.chmod(0o444)
        destination = CAS(self.root / "destination-invalid-input")

        with self.assertRaisesRegex(HandoffError, "exact semantic closure"):
            import_handoff(
                bundle,
                destination,
                expected_manifest_digest=handoff_manifest_digest(invalid_input),
                expected_kind="worker_input",
                expected_root_digest=request_digest,
                expected_verifier_challenge="b" * 64,
            )

        for digest in blobs:
            with self.assertRaises(CASError):
                destination.verify(digest)
        self.assertEqual(
            list(destination.root.glob(".aragorn-handoff-import-*")),
            [],
        )

    def test_expected_challenge_is_external_required_and_fresh(self) -> None:
        request_digest, expected = self._input_closure()
        manifest = build_worker_input_handoff_manifest(
            self.source,
            request_digest,
            expected_verifier_challenge="b" * 64,
        )

        with self.assertRaisesRegex(HandoffError, "requires an expected"):
            export_handoff(self.source, manifest, self.root / "missing-challenge")
        with self.assertRaisesRegex(HandoffError, "stale"):
            export_handoff(
                self.source,
                manifest,
                self.root / "stale-challenge",
                expected_verifier_challenge="c" * 64,
            )

        bundle = self.root / "challenge-bundle"
        manifest_digest = export_handoff(
            self.source,
            manifest,
            bundle,
            expected_verifier_challenge="b" * 64,
        )
        destination = CAS(self.root / "challenge-destination")
        with self.assertRaisesRegex(HandoffError, "requires an expected"):
            import_handoff(
                bundle,
                destination,
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_input",
                expected_root_digest=request_digest,
            )
        with self.assertRaisesRegex(HandoffError, "stale"):
            import_handoff(
                bundle,
                destination,
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_input",
                expected_root_digest=request_digest,
                expected_verifier_challenge="c" * 64,
            )
        for digest in expected:
            with self.assertRaises(CASError):
                destination.verify(digest)

    def test_omitted_blob_cannot_be_satisfied_from_destination_cas(self) -> None:
        request_digest, exact = self._input_closure()
        omitted_digest = next(digest for digest in exact if digest != request_digest)
        declared = {
            digest: size for digest, size in exact.items() if digest != omitted_digest
        }
        transport_manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=request_digest,
            blobs=declared,
        )
        bundle = self.root / "omitted-bundle"
        export_declared_byte_transport(self.source, transport_manifest, bundle)
        invalid_input = build_handoff_manifest(
            kind="worker_input",
            root_digest=request_digest,
            blobs=declared,
        )
        manifest_path = bundle / "manifest.json"
        manifest_path.chmod(0o644)
        manifest_path.write_bytes(canonical_json(invalid_input))
        manifest_path.chmod(0o444)

        destination = CAS(self.root / "preseeded-destination")
        omitted_content = self.source.read(
            omitted_digest,
            max_bytes=exact[omitted_digest],
        )
        self._put_exact(destination, omitted_content, omitted_digest)
        with self.assertRaisesRegex(HandoffError, "cannot read"):
            import_handoff(
                bundle,
                destination,
                expected_manifest_digest=handoff_manifest_digest(invalid_input),
                expected_kind="worker_input",
                expected_root_digest=request_digest,
                expected_verifier_challenge="b" * 64,
            )

        destination.verify(omitted_digest, max_bytes=exact[omitted_digest])
        for digest in declared:
            with self.assertRaises(CASError):
                destination.verify(digest)

    def test_noncanonical_root_and_missing_reachable_blob_fail_closed(self) -> None:
        request_digest, exact = self._input_closure()
        raw_request = self.source.read(request_digest)
        noncanonical = raw_request.replace(b'{"baseline"', b'{ "baseline"', 1)
        noncanonical_digest = self._put(self.source, noncanonical)
        with self.assertRaisesRegex(SemanticClosureError, "canonical JSON"):
            derive_worker_input_cas_closure(
                self.source,
                noncanonical_digest,
                expected_challenge="b" * 64,
            )

        missing_digest = next(
            digest
            for digest in exact
            if digest not in {request_digest, noncanonical_digest}
        )
        missing_cas = CAS(self.root / "missing")
        for digest, size in exact.items():
            if digest == missing_digest:
                continue
            self._put_exact(
                missing_cas,
                self.source.read(digest, max_bytes=size),
                digest,
            )
        with self.assertRaisesRegex(SemanticClosureError, "cannot read worker-input"):
            derive_worker_input_cas_closure(
                missing_cas,
                request_digest,
                expected_challenge="b" * 64,
            )

    def test_derives_exact_worker_output_with_full_input_and_typed_evidence(
        self,
    ) -> None:
        result_digest, request_digest, expected, result = self._output_closure()

        derived = derive_worker_output_cas_closure(
            self.source,
            result_digest,
            expected_request_digest=request_digest,
            expected_challenge="b" * 64,
        )

        self.assertEqual(derived, expected)
        self.assertIn(result_digest, derived)
        self.assertIn(request_digest, derived)
        self.assertIn(result["docker_executable_digest"], derived)
        self.assertNotIn(result["tree_digest"], derived)
        self.assertNotIn(result["verified_subject_digest"], derived)

    def test_builds_exports_and_imports_semantic_worker_output(self) -> None:
        result_digest, request_digest, expected, _result = self._output_closure()
        manifest = build_worker_output_handoff_manifest(
            self.source,
            result_digest,
            expected_request_digest=request_digest,
            expected_verifier_challenge="b" * 64,
        )
        self.assertEqual(
            {item["digest"]: item["size"] for item in manifest["blobs"]},
            expected,
        )

        bundle = self.root / "output-bundle"
        manifest_digest = export_handoff(
            self.source,
            manifest,
            bundle,
            expected_request_digest=request_digest,
            expected_verifier_challenge="b" * 64,
        )
        destination = CAS(self.root / "output-destination")
        imported = import_handoff(
            bundle,
            destination,
            expected_manifest_digest=manifest_digest,
            expected_kind="worker_output",
            expected_root_digest=result_digest,
            expected_request_digest=request_digest,
            expected_verifier_challenge="b" * 64,
        )

        self.assertEqual(imported, manifest)
        for digest, size in expected.items():
            destination.verify(digest, max_bytes=size)

    def test_semantic_output_requires_both_external_request_and_challenge(
        self,
    ) -> None:
        result_digest, request_digest, _expected, _result = self._output_closure()
        manifest = build_worker_output_handoff_manifest(
            self.source,
            result_digest,
            expected_request_digest=request_digest,
            expected_verifier_challenge="b" * 64,
        )
        with self.assertRaisesRegex(HandoffError, "requires an expected"):
            export_handoff(
                self.source,
                manifest,
                self.root / "output-missing-both",
            )
        with self.assertRaisesRegex(HandoffError, "requires an expected"):
            export_handoff(
                self.source,
                manifest,
                self.root / "output-missing-request",
                expected_verifier_challenge="b" * 64,
            )
        with self.assertRaisesRegex(HandoffError, "requires an expected"):
            export_handoff(
                self.source,
                manifest,
                self.root / "output-missing-challenge",
                expected_request_digest=request_digest,
            )

        bundle = self.root / "output-required-bundle"
        manifest_digest = export_handoff(
            self.source,
            manifest,
            bundle,
            expected_request_digest=request_digest,
            expected_verifier_challenge="b" * 64,
        )
        destination = CAS(self.root / "output-required-destination")
        with self.assertRaisesRegex(HandoffError, "requires an expected"):
            import_handoff(
                bundle,
                destination,
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_output",
                expected_root_digest=result_digest,
            )
        for digest in _expected:
            with self.assertRaises(CASError):
                destination.verify(digest)

    def test_output_omission_cannot_be_satisfied_by_preseeded_destination(
        self,
    ) -> None:
        result_digest, request_digest, exact, result = self._output_closure()
        omitted_digest = result["docker_executable_digest"]
        declared = {
            digest: size for digest, size in exact.items() if digest != omitted_digest
        }
        incomplete = build_handoff_manifest(
            kind="worker_output",
            root_digest=result_digest,
            blobs=declared,
        )
        bundle = self.root / "output-omitted-bundle"
        manifest_digest = export_declared_byte_transport(
            self.source,
            incomplete,
            bundle,
        )

        destination = CAS(self.root / "output-preseeded-destination")
        omitted_content = self.source.read(
            omitted_digest,
            max_bytes=exact[omitted_digest],
        )
        self._put_exact(destination, omitted_content, omitted_digest)
        with self.assertRaisesRegex(HandoffError, "cannot read"):
            import_handoff(
                bundle,
                destination,
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_output",
                expected_root_digest=result_digest,
                expected_request_digest=request_digest,
                expected_verifier_challenge="b" * 64,
            )

        destination.verify(omitted_digest, max_bytes=exact[omitted_digest])
        for digest in declared:
            with self.assertRaises(CASError):
                destination.verify(digest)

    def test_output_export_rejects_authenticated_but_unreachable_extra(self) -> None:
        result_digest, request_digest, exact, _result = self._output_closure()
        extra_content = b"authenticated but unreachable output"
        extra_digest = self._put(self.source, extra_content)
        manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=result_digest,
            blobs={**exact, extra_digest: len(extra_content)},
        )
        destination = self.root / "output-extra-rejected"

        with self.assertRaisesRegex(HandoffError, "exact semantic closure"):
            export_handoff(
                self.source,
                manifest,
                destination,
                expected_request_digest=request_digest,
                expected_verifier_challenge="b" * 64,
            )
        self.assertFalse(destination.exists())

    def test_staged_output_mutation_after_semantics_cannot_publish_root(
        self,
    ) -> None:
        result_digest, request_digest, exact, _result = self._output_closure()
        manifest = build_worker_output_handoff_manifest(
            self.source,
            result_digest,
            expected_request_digest=request_digest,
            expected_verifier_challenge="b" * 64,
        )
        bundle = self.root / "output-post-semantics-mutation"
        manifest_digest = export_handoff(
            self.source,
            manifest,
            bundle,
            expected_request_digest=request_digest,
            expected_verifier_challenge="b" * 64,
        )
        destination = CAS(self.root / "output-post-semantics-destination")
        original_verify = benchmark_handoff_v2._verify_semantic_manifest_from_staging
        first_nonroot = next(
            item for item in manifest["blobs"] if item["digest"] != result_digest
        )

        def verify_then_mutate(
            staging_fd,
            staged_manifest,
            *,
            expected_request_digest,
            expected_verifier_challenge,
        ):
            original_verify(
                staging_fd,
                staged_manifest,
                expected_request_digest=expected_request_digest,
                expected_verifier_challenge=expected_verifier_challenge,
            )
            name = first_nonroot["digest"].removeprefix("sha256:")
            original = benchmark_handoff_v2._read_named_file(
                staging_fd,
                name,
                max_bytes=first_nonroot["size"],
                label="staged mutation target",
            )
            replacement = (
                b"\0" if not original else bytes((original[0] ^ 1,)) + original[1:]
            )
            os.chmod(
                name,
                0o600,
                dir_fd=staging_fd,
                follow_symlinks=False,
            )
            descriptor = os.open(name, os.O_WRONLY, dir_fd=staging_fd)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(replacement)

        with mock.patch.object(
            benchmark_handoff_v2,
            "_verify_semantic_manifest_from_staging",
            side_effect=verify_then_mutate,
        ):
            with self.assertRaisesRegex(
                HandoffError,
                "digest does not match expected",
            ):
                import_handoff(
                    bundle,
                    destination,
                    expected_manifest_digest=manifest_digest,
                    expected_kind="worker_output",
                    expected_root_digest=result_digest,
                    expected_request_digest=request_digest,
                    expected_verifier_challenge="b" * 64,
                )

        for digest in exact:
            with self.assertRaises(CASError):
                destination.verify(digest)
        self.assertEqual(
            list(destination.root.glob(".aragorn-handoff-import-*")),
            [],
        )

    def test_output_rejects_external_request_drift_and_missing_evidence(self) -> None:
        result_digest, request_digest, expected, result = self._output_closure()

        with self.assertRaisesRegex(
            SemanticClosureError,
            "verifier-issued request",
        ):
            derive_worker_output_cas_closure(
                self.source,
                result_digest,
                expected_request_digest=result["subject_manifest_digest"],
                expected_challenge="b" * 64,
            )

        omitted = result["docker_executable_digest"]
        missing = CAS(self.root / "missing-output")
        for digest, size in expected.items():
            if digest == omitted:
                continue
            self._put_exact(
                missing,
                self.source.read(digest, max_bytes=size),
                digest,
            )
        with self.assertRaisesRegex(
            SemanticClosureError,
            "cannot read worker-output",
        ):
            derive_worker_output_cas_closure(
                missing,
                result_digest,
                expected_request_digest=request_digest,
                expected_challenge="b" * 64,
            )

    def test_output_rejects_effective_policy_and_docker_binding_drift(self) -> None:
        result_digest, request_digest, _expected, result = self._output_closure()
        del result_digest
        effective = json.loads(
            self.source.read(result["effective_config_digest"]).decode("ascii")
        )

        policy_drift = json.loads(canonical_json(effective))
        policy_drift["runtime_profile"]["cpus"] = 1
        policy_drift_digest = self._put(self.source, canonical_json(policy_drift))
        changed_result = json.loads(canonical_json(result))
        changed_result["effective_config_digest"] = policy_drift_digest
        changed_result_digest = self._put(
            self.source,
            canonical_json(changed_result),
        )
        with self.assertRaisesRegex(SemanticClosureError, "policy binding"):
            derive_worker_output_cas_closure(
                self.source,
                changed_result_digest,
                expected_request_digest=request_digest,
                expected_challenge="b" * 64,
            )

        docker_drift = json.loads(canonical_json(effective))
        replacement_docker = self._put(self.source, b"another docker executable")
        docker_drift["docker_executable_digest"] = replacement_docker
        docker_drift_digest = self._put(self.source, canonical_json(docker_drift))
        changed_result = json.loads(canonical_json(result))
        changed_result["effective_config_digest"] = docker_drift_digest
        changed_result_digest = self._put(
            self.source,
            canonical_json(changed_result),
        )
        with self.assertRaisesRegex(
            SemanticClosureError,
            "docker_executable_digest",
        ):
            derive_worker_output_cas_closure(
                self.source,
                changed_result_digest,
                expected_request_digest=request_digest,
                expected_challenge="b" * 64,
            )

    def _input_closure(self) -> tuple[str, dict[str, int]]:
        files = (
            ("SKILL.md", b"# inert fixture\n"),
            ("notes/readme.txt", b"notes\n"),
        )
        entries = []
        expected = {}
        for path, content in files:
            digest = self._put(self.source, content)
            entries.append(
                {
                    "path": path,
                    "size": len(content),
                    "digest": digest,
                    "executable": False,
                }
            )
            expected[digest] = len(content)
        manifest = sanitize_subject_manifest(
            {
                "schema": "aragorn/manifest/v1",
                "tree_digest": canonical_digest(entries),
                "files": entries,
            }
        )
        raw_manifest = canonical_json(manifest)
        manifest_digest = self._put(self.source, raw_manifest)
        expected[manifest_digest] = len(raw_manifest)

        policy = _portable_policy()
        raw_policy = canonical_json(policy)
        policy_digest = self._put(self.source, raw_policy)
        expected[policy_digest] = len(raw_policy)

        tokens = iter(("a" * 32, "b" * 64))
        request = build_worker_request_v2(
            manifest,
            policy,
            token_hex=lambda _size: next(tokens),
        )
        raw_request = canonical_json(request)
        request_digest = self._put(self.source, raw_request)
        expected[request_digest] = len(raw_request)
        return request_digest, dict(sorted(expected.items()))

    def _output_closure(self) -> tuple[str, str, dict[str, int], dict]:
        expected: dict[str, int] = {}

        def put(content: bytes) -> str:
            digest = self._put(self.source, content)
            expected[digest] = len(content)
            return digest

        platform_digest = put(b"pinned platform manifest")
        identity_patch = mock.patch.dict(
            benchmark_protocol_v2._SYSTEM_IDENTITIES["cisco-skill-scanner"],
            {"implementation_digest": platform_digest},
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)

        files = (
            ("SKILL.md", b"# inert fixture\n"),
            ("notes/readme.txt", b"notes\n"),
        )
        entries = []
        for path, content in files:
            digest = put(content)
            entries.append(
                {
                    "path": path,
                    "size": len(content),
                    "digest": digest,
                    "executable": False,
                }
            )
        manifest = sanitize_subject_manifest(
            {
                "schema": "aragorn/manifest/v1",
                "tree_digest": canonical_digest(entries),
                "files": entries,
            }
        )
        manifest_digest = put(canonical_json(manifest))

        baseline_lock_digest = put(
            canonical_json(
                {
                    "schema": "aragorn/test-baseline-lock/v1",
                    "selected": "cisco-skill-scanner",
                }
            )
        )
        baseline_entry_digest = put(
            canonical_json(
                {
                    "schema": "aragorn/test-baseline-entry/v1",
                    "name": "cisco-skill-scanner",
                }
            )
        )
        index_digest = put(b"pinned OCI index")
        config_digest = put(b"pinned image config")
        provenance_digest = put(b"pinned build provenance")
        policy = _portable_policy()
        policy["system"]["implementation_digest"] = platform_digest
        policy["baseline"] = {
            "lock_digest": baseline_lock_digest,
            "entry_digest": baseline_entry_digest,
        }
        policy["image"].update(
            {
                "index_digest": index_digest,
                "platform_manifest_digest": platform_digest,
                "config_digest": config_digest,
                "build_provenance_manifest_digest": provenance_digest,
            }
        )
        policy_digest = put(canonical_json(policy))

        request = build_worker_request_v2(
            manifest,
            policy,
            verifier_challenge="b" * 64,
            token_hex=lambda _size: "a" * 32,
        )
        request_digest = put(canonical_json(request))
        self.assertEqual(request["subject"]["manifest_digest"], manifest_digest)
        self.assertEqual(request["portable_policy_digest"], policy_digest)

        docker_digest = put(b"measured docker executable")
        effective = {
            "schema": "aragorn/benchmark-oci-system-config/v2",
            "name": policy["system"]["name"],
            "version": policy["system"]["version"],
            "baseline_lock_digest": baseline_lock_digest,
            "baseline_entry_digest": baseline_entry_digest,
            "docker_executable_digest": docker_digest,
            "runner_identity": _runner_identity(),
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
            "entrypoint": policy["entrypoint"],
            "arguments": policy["arguments"],
            "environment": policy["environment"],
            "runtime_profile": policy["runtime_profile"],
            "limits": policy["limits"],
            "normalization": policy["normalization"],
        }
        effective_digest = put(canonical_json(effective))

        evidence = {
            name: put(name.encode("ascii"))
            for name in (
                "index inspect",
                "platform inspect",
                "prestart inspect",
                "postrun inspect",
                "runner context",
                "runner version",
                "runner info",
            )
        }
        stdout_digest = put(b"")
        result = {
            "schema": "aragorn/benchmark-worker-result/v2",
            "job_id": request["job_id"],
            "verifier_challenge": request["verifier_challenge"],
            "request_digest": request_digest,
            "portable_policy_digest": policy_digest,
            "subject_manifest_digest": manifest_digest,
            "tree_digest": manifest["tree_digest"],
            "verified_subject_digest": manifest["tree_digest"],
            "system": request["system"],
            "baseline_lock_digest": baseline_lock_digest,
            "baseline_entry_digest": baseline_entry_digest,
            "effective_config_digest": effective_digest,
            "docker_executable_digest": docker_digest,
            "oci_index_digest": index_digest,
            "oci_platform_manifest_digest": platform_digest,
            "build_provenance_manifest_digest": provenance_digest,
            "index_inspect_digest": evidence["index inspect"],
            "platform_inspect_digest": evidence["platform inspect"],
            "image_config_digest": config_digest,
            "runner_receipts": {
                phase: {
                    "context_inspect_digest": evidence["runner context"],
                    "daemon_version_digest": evidence["runner version"],
                    "daemon_info_digest": evidence["runner info"],
                }
                for phase in ("pre", "post")
            },
            "prestart_container_inspect_digest": evidence["prestart inspect"],
            "postrun_container_inspect_digest": evidence["postrun inspect"],
            "stdout_digest": stdout_digest,
            "stderr_digest": stdout_digest,
            "observation_digests": [],
            "execution": {
                "status": "ok",
                "error_code": None,
                "returncode": 0,
                "container_id": "c" * 64,
            },
            "normalization": policy["normalization"],
            "verdict": "ALLOW",
            "reason_codes": [],
        }
        result_digest = put(canonical_json(result))
        return result_digest, request_digest, dict(sorted(expected.items())), result

    def _deep_output(self) -> tuple[str, str, dict]:
        content = b"# inert worker subject\n"
        content_digest = self._put(self.source, content)
        files = [
            {
                "path": "SKILL.md",
                "size": len(content),
                "digest": content_digest,
                "executable": False,
            }
        ]
        tree_digest = canonical_digest(files)
        with mock.patch.object(evidence_support, "SUBJECT", tree_digest):
            outcome, _private_manifest = evidence_support.OciEvidenceTests._evidence(
                self.source,
                evidence_support.cisco_report(),
                evidence_version=3,
            )
        nested = json.loads(self.source.read(outcome["evidence_digest"]))
        effective = json.loads(self.source.read(nested["effective_config_digest"]))
        lock = json.loads(self.source.read(nested["baseline_lock_digest"]))
        selected = next(
            item
            for item in lock["baselines"]
            if item["name"] == nested["system"]["name"]
        )
        identity_patch = mock.patch.dict(
            benchmark_protocol_v2._SYSTEM_IDENTITIES[nested["system"]["name"]],
            {"implementation_digest": nested["oci_platform_manifest_digest"]},
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)

        subject = {
            "schema": "aragorn/benchmark-subject-manifest/v1",
            "tree_digest": tree_digest,
            "files": files,
        }
        subject_digest = self._put(self.source, canonical_json(subject))
        policy = {
            "schema": "aragorn/benchmark-portable-policy/v1",
            "system": {
                key: nested["system"][key]
                for key in ("name", "version", "implementation_digest")
            },
            "baseline": {
                "lock_digest": nested["baseline_lock_digest"],
                "entry_digest": nested["baseline_entry_digest"],
            },
            "image": {
                key: selected["image"][key]
                for key in (
                    "index_digest",
                    "platform_manifest_digest",
                    "config_digest",
                    "build_provenance_manifest_digest",
                    "os",
                    "architecture",
                    "size_bytes",
                )
            },
            "entrypoint": effective["entrypoint"],
            "arguments": effective["arguments"],
            "environment": effective["environment"],
            "runtime_profile": effective["runtime_profile"],
            "limits": effective["limits"],
            "normalization": effective["normalization"],
        }
        policy_digest = self._put(self.source, canonical_json(policy))
        request = build_worker_request_v2(
            subject,
            policy,
            verifier_challenge="b" * 64,
            token_hex=lambda _size: "a" * 32,
        )
        request_digest = self._put(self.source, canonical_json(request))
        result = {
            "schema": "aragorn/benchmark-worker-result/v2",
            "job_id": request["job_id"],
            "verifier_challenge": request["verifier_challenge"],
            "request_digest": request_digest,
            "portable_policy_digest": policy_digest,
            "subject_manifest_digest": subject_digest,
            "tree_digest": tree_digest,
            "verified_subject_digest": tree_digest,
            "system": request["system"],
            "baseline_lock_digest": nested["baseline_lock_digest"],
            "baseline_entry_digest": nested["baseline_entry_digest"],
            "effective_config_digest": nested["effective_config_digest"],
            "docker_executable_digest": effective["docker_executable_digest"],
            "oci_index_digest": nested["oci_index_digest"],
            "oci_platform_manifest_digest": nested["oci_platform_manifest_digest"],
            "build_provenance_manifest_digest": nested[
                "build_provenance_manifest_digest"
            ],
            "index_inspect_digest": nested["index_inspect_digest"],
            "platform_inspect_digest": nested["platform_inspect_digest"],
            "image_config_digest": nested["image_config_digest"],
            "runner_receipts": nested["runner_receipts"],
            "prestart_container_inspect_digest": nested[
                "prestart_container_inspect_digest"
            ],
            "postrun_container_inspect_digest": nested[
                "postrun_container_inspect_digest"
            ],
            "stdout_digest": nested["stdout_digest"],
            "stderr_digest": nested["stderr_digest"],
            "observation_digests": nested["observation_digests"],
            "execution": nested["execution"],
            "normalization": nested["normalization"],
            "verdict": nested["verdict"],
            "reason_codes": nested["reason_codes"],
        }
        return self._put(self.source, canonical_json(result)), request_digest, result

    @staticmethod
    def _put(cas: CAS, content: bytes) -> str:
        return cas.put(BytesIO(content), max_bytes=len(content))

    def _put_exact(self, cas: CAS, content: bytes, expected_digest: str) -> None:
        self.assertEqual(self._put(cas, content), expected_digest)


if __name__ == "__main__":
    unittest.main()
