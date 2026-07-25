from __future__ import annotations

import copy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from aragorn.analyze import Observation  # noqa: E402
from aragorn.benchmark import (  # noqa: E402
    BenchmarkError,
    _normalize_runner_receipt,
    _select_oci_baseline,
    _validate_oci_runtime_profile,
    _verify_evidence,
    _verify_oci_metadata_graph,
    normalize_vendor_observations,
)
from aragorn.cas import CAS  # noqa: E402
from aragorn.vendor_reports import normalize_cisco_report  # noqa: E402


ROOT = Path(__file__).parents[1]
SUBJECT = "sha256:" + "a" * 64
SUITE = "sha256:" + "b" * 64
POLICY = "7e571f3db6d7aa3d0c8a40e9ae8f8f6a0f0a721fe518e59f71943a11b418c91f"
CONTAINER_ID = "c" * 64


def canonical(document: object) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def put(cas: CAS, content: bytes) -> str:
    return cas.put(BytesIO(content), max_bytes=len(content))


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


def runner_receipt_documents(
    *,
    version_architecture: str = "aarch64",
    info_architecture: str = "arm64",
) -> tuple[dict, dict, dict]:
    context = {
        "Name": "desktop-linux",
        "DockerEndpoint": {
            "Host": "unix:///Users/test/.docker/run/docker.sock",
            "SkipTLSVerify": False,
            "TLSMaterialCount": 0,
        },
    }
    version = {
        "PlatformName": "Docker Engine - Community",
        "Version": "29.5.2",
        "APIVersion": "1.54",
        "MinAPIVersion": "1.40",
        "GitCommit": "568f755",
        "GoVersion": "go1.26.3",
        "Os": "linux",
        "Arch": version_architecture,
        "KernelVersion": "6.8.0-test",
        "BuildTime": "2026-05-20T14:39:25.000000000+00:00",
        "Components": [
            {
                "Name": "runc",
                "Version": "1.3.5",
                "Details": {"GitCommit": "runc-commit"},
            },
            {
                "Name": "Engine",
                "Version": "29.5.2",
                "Details": {"GitCommit": "568f755", "ApiVersion": "1.54"},
            },
            {
                "Name": "containerd",
                "Version": "v2.2.4",
                "Details": {"GitCommit": "containerd-commit"},
            },
        ],
    }
    info = {
        "ID": "daemon-id",
        "Name": "docker-desktop",
        "ServerVersion": "29.5.2",
        "OperatingSystem": "Docker Desktop",
        "OSType": "linux",
        "Architecture": info_architecture,
        "KernelVersion": "6.8.0-test",
        "SecurityOptions": [
            "name=seccomp,profile=builtin",
            "name=apparmor",
        ],
        "CgroupVersion": "2",
        "DefaultRuntime": "runc",
        "Driver": "overlayfs",
    }
    return context, version, info


def normalized_runner_identity(*, architecture: str = "arm64") -> dict:
    return {
        "assurance": "docker_daemon_self_report_not_attested",
        "context": {
            "name": "desktop-linux",
            "endpoint": "unix:///Users/test/.docker/run/docker.sock",
            "skip_tls_verify": False,
            "tls_material_count": 0,
        },
        "engine": {
            "platform_name": "Docker Engine - Community",
            "version": "29.5.2",
            "api_version": "1.54",
            "minimum_api_version": "1.40",
            "git_commit": "568f755",
            "go_version": "go1.26.3",
            "os": "linux",
            "architecture": architecture,
            "kernel_version": "6.8.0-test",
            "build_time": "2026-05-20T14:39:25.000000000+00:00",
            "components": [
                {
                    "name": "Engine",
                    "version": "29.5.2",
                    "git_commit": "568f755",
                },
                {
                    "name": "containerd",
                    "version": "v2.2.4",
                    "git_commit": "containerd-commit",
                },
                {
                    "name": "runc",
                    "version": "1.3.5",
                    "git_commit": "runc-commit",
                },
            ],
        },
        "worker_claim": {
            "daemon_id": "daemon-id",
            "daemon_name": "docker-desktop",
            "server_version": "29.5.2",
            "operating_system": "Docker Desktop",
            "os": "linux",
            "architecture": architecture,
            "kernel_version": "6.8.0-test",
            "security_options": [
                "name=apparmor",
                "name=seccomp,profile=builtin",
            ],
            "cgroup_version": "2",
            "default_runtime": "runc",
            "storage_driver": "overlayfs",
        },
    }


class RunnerIdentityReceiptTests(unittest.TestCase):
    def test_optional_component_without_git_commit_is_independently_bound(
        self,
    ) -> None:
        context, version, info = runner_receipt_documents()
        version["Components"].append(
            {
                "Name": "rootlesskit",
                "Version": "3.0.2",
                "Details": {
                    "ApiVersion": "1.1.2",
                    "NetworkDriver": "gvisor-tap-vsock",
                    "PortDriver": "builtin",
                    "StateDir": "/run/user/501/dockerd-rootless",
                },
            }
        )
        identity = _normalize_runner_receipt(
            context,
            version,
            info,
            "rootless worker",
        )
        component = next(
            item
            for item in identity["engine"]["components"]
            if item["name"] == "rootlesskit"
        )
        self.assertRegex(
            component["git_commit"],
            r"^unreported-details-sha256:[0-9a-f]{64}$",
        )

        changed = copy.deepcopy(version)
        changed["Components"][-1]["Details"]["NetworkDriver"] = "slirp4netns"
        self.assertNotEqual(
            identity,
            _normalize_runner_receipt(
                context,
                changed,
                info,
                "changed rootless worker",
            ),
        )


class OciEvidenceTests(unittest.TestCase):
    def test_v3_verifies_runner_receipts_and_normalizes_arch_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            outcome, manifest = self._evidence(
                cas,
                cisco_report(),
                evidence_version=3,
            )

            _verify_evidence(
                cas,
                outcome,
                expected_manifest=manifest,
                label="outcomes[0]",
            )

    def test_v3_rejects_forged_effective_runner_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            outcome, manifest = self._evidence(
                cas,
                cisco_report(),
                evidence_version=3,
            )
            envelope = json.loads(cas.read(outcome["evidence_digest"]))
            effective = json.loads(cas.read(envelope["effective_config_digest"]))
            effective["runner_identity"]["worker_claim"]["daemon_id"] = "forged"
            effective_digest = put(cas, canonical(effective))
            envelope["effective_config_digest"] = effective_digest
            envelope["system"]["config_digest"] = effective_digest
            outcome["system"]["config_digest"] = effective_digest
            outcome["evidence_digest"] = put(cas, canonical(envelope))

            with self.assertRaisesRegex(BenchmarkError, "runner identity is unbound"):
                _verify_evidence(
                    cas,
                    outcome,
                    expected_manifest=manifest,
                    label="outcomes[0]",
                )

    def test_v3_rejects_missing_or_swapped_receipt(self) -> None:
        for mutation in ("missing", "swapped"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                cas = CAS(Path(temporary) / "state")
                outcome, manifest = self._evidence(
                    cas,
                    cisco_report(),
                    evidence_version=3,
                )
                envelope = json.loads(cas.read(outcome["evidence_digest"]))
                if mutation == "missing":
                    del envelope["runner_receipts"]["post"]
                else:
                    receipt = envelope["runner_receipts"]["post"]
                    (
                        receipt["context_inspect_digest"],
                        receipt["daemon_version_digest"],
                    ) = (
                        receipt["daemon_version_digest"],
                        receipt["context_inspect_digest"],
                    )
                outcome["evidence_digest"] = put(cas, canonical(envelope))

                with self.assertRaisesRegex(
                    BenchmarkError, "missing or unknown fields"
                ):
                    _verify_evidence(
                        cas,
                        outcome,
                        expected_manifest=manifest,
                        label="outcomes[0]",
                    )

    def test_v3_runner_receipts_reject_duplicate_and_nonfinite_json(self) -> None:
        raw_context = canonical(runner_receipt_documents()[0])
        invalid_receipts = {
            "duplicate": raw_context.replace(
                b'"Name":"desktop-linux"',
                b'"Name":"desktop-linux","Name":"forged"',
                1,
            ),
            "exponent_overflow": raw_context.replace(
                b'"TLSMaterialCount":0',
                b'"TLSMaterialCount":1e999',
                1,
            ),
        }
        for case, invalid_context in invalid_receipts.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                cas = CAS(Path(temporary) / "state")
                outcome, manifest = self._evidence(
                    cas,
                    cisco_report(),
                    evidence_version=3,
                )
                envelope = json.loads(cas.read(outcome["evidence_digest"]))
                envelope["runner_receipts"]["pre"]["context_inspect_digest"] = put(
                    cas,
                    invalid_context,
                )
                outcome["evidence_digest"] = put(cas, canonical(envelope))

                with self.assertRaisesRegex(
                    BenchmarkError, "duplicate JSON key|non-finite number"
                ):
                    _verify_evidence(
                        cas,
                        outcome,
                        expected_manifest=manifest,
                        label="outcomes[0]",
                    )

    def test_v3_rejects_pre_post_runner_drift(self) -> None:
        cases = {
            "endpoint": [
                (
                    "context_inspect_digest",
                    ("DockerEndpoint", "Host"),
                    "unix:///Users/test/.docker/run/other.sock",
                )
            ],
            "daemon": [
                ("daemon_info_digest", ("ID",), "other-daemon"),
            ],
            "engine": [
                ("daemon_version_digest", ("GitCommit",), "other-engine"),
                (
                    "daemon_version_digest",
                    ("Components", 1, "Details", "GitCommit"),
                    "other-engine",
                ),
            ],
            "kernel": [
                (
                    "daemon_version_digest",
                    ("KernelVersion",),
                    "6.8.1-test",
                ),
                ("daemon_info_digest", ("KernelVersion",), "6.8.1-test"),
            ],
            "security": [
                (
                    "daemon_info_digest",
                    ("SecurityOptions",),
                    [
                        "name=apparmor",
                        "name=cgroupns",
                        "name=seccomp,profile=builtin",
                    ],
                )
            ],
        }
        for drift, changes in cases.items():
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as temporary:
                cas = CAS(Path(temporary) / "state")
                outcome, manifest = self._evidence(
                    cas,
                    cisco_report(),
                    evidence_version=3,
                )
                envelope = json.loads(cas.read(outcome["evidence_digest"]))
                receipt = envelope["runner_receipts"]["post"]
                for field in {change[0] for change in changes}:
                    document = json.loads(cas.read(receipt[field]))
                    for _, path, replacement in (
                        change for change in changes if change[0] == field
                    ):
                        target = document
                        for component in path[:-1]:
                            target = target[component]
                        target[path[-1]] = replacement
                    receipt[field] = put(cas, canonical(document))
                outcome["evidence_digest"] = put(cas, canonical(envelope))

                with self.assertRaisesRegex(
                    BenchmarkError, "runner identity changed"
                ):
                    _verify_evidence(
                        cas,
                        outcome,
                        expected_manifest=manifest,
                        label="outcomes[0]",
                    )

    def test_v2_reconstructs_allow_and_binds_all_retained_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            outcome, manifest = self._evidence(cas, cisco_report())

            _verify_evidence(
                cas,
                outcome,
                expected_manifest=manifest,
                label="outcomes[0]",
            )

            envelope = json.loads(cas.read(outcome["evidence_digest"]))
            platform = json.loads(cas.read(envelope["platform_inspect_digest"]))
            platform[0]["Id"] = "sha256:" + "d" * 64
            envelope["platform_inspect_digest"] = put(cas, canonical(platform))
            outcome["evidence_digest"] = put(cas, canonical(envelope))
            with self.assertRaisesRegex(BenchmarkError, "locked image"):
                _verify_evidence(
                    cas,
                    outcome,
                    expected_manifest=manifest,
                    label="outcomes[0]",
                )

    def test_raw_oci_graph_rejects_unbound_provenance_annotation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            outcome, _manifest = self._evidence(cas, cisco_report())
            envelope = json.loads(cas.read(outcome["evidence_digest"]))
            lock = json.loads(cas.read(envelope["baseline_lock_digest"]))
            selected = next(
                item
                for item in lock["baselines"]
                if item["name"] == "cisco-skill-scanner"
            )
            provenance = json.loads(
                cas.read(envelope["build_provenance_manifest_digest"])
            )
            provenance["layers"][0]["annotations"][
                "in-toto.io/predicate-type"
            ] = "https://slsa.dev/provenance/v0"

            with self.assertRaisesRegex(BenchmarkError, "statement is unsupported"):
                _verify_oci_metadata_graph(
                    cas.read(envelope["oci_index_digest"]),
                    cas.read(envelope["oci_platform_manifest_digest"]),
                    canonical(provenance),
                    cas.read(envelope["image_config_digest"]),
                    selected=selected,
                    label="outcomes[0].evidence",
                )

    def test_verified_subject_must_match_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            outcome, manifest = self._evidence(cas, cisco_report())
            envelope = json.loads(cas.read(outcome["evidence_digest"]))
            envelope["verified_subject_digest"] = "sha256:" + "f" * 64
            outcome["evidence_digest"] = put(cas, canonical(envelope))

            with self.assertRaisesRegex(BenchmarkError, "verified subject"):
                _verify_evidence(
                    cas,
                    outcome,
                    expected_manifest=manifest,
                    label="outcomes[0]",
                )

    def test_malformed_vendor_report_is_a_reverifiable_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            outcome, manifest = self._evidence(
                cas,
                b"{",
                status="error",
                error_code="MALFORMED_VENDOR_REPORT",
                verdict="ERROR",
                reason_codes=["ANALYZER_MALFORMED_VENDOR_REPORT"],
            )

            _verify_evidence(
                cas,
                outcome,
                expected_manifest=manifest,
                label="outcomes[0]",
            )

    def test_raw_lock_duplicate_keys_fail_before_selected_entry_use(self) -> None:
        raw_lock = (ROOT / "benchmark" / "baselines.lock.json").read_bytes()
        duplicate = raw_lock.replace(
            b'"schema": "aragorn/baseline-lock/v1",',
            (
                b'"schema": "aragorn/baseline-lock/v1",'
                b'"schema": "aragorn/baseline-lock/v1",'
            ),
            1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            outcome, manifest = self._evidence(
                cas,
                cisco_report(),
                raw_lock=duplicate,
            )

            with self.assertRaisesRegex(BenchmarkError, "duplicate JSON key"):
                _verify_evidence(
                    cas,
                    outcome,
                    expected_manifest=manifest,
                    label="outcomes[0]",
                )

    def test_vendor_outcome_policy_ignores_non_actionable_information(self) -> None:
        completion = Observation(
            schema="aragorn/observation/v1",
            subject_digest=SUBJECT,
            reason_code="CISCO_SCAN_COMPLETED",
            severity="info",
            document_json="{}",
        )
        finding = Observation(
            schema="aragorn/observation/v1",
            subject_digest=SUBJECT,
            reason_code="CISCO_VENDOR_FINDING",
            severity="high",
            document_json="{}",
        )
        information = Observation(
            schema="aragorn/observation/v1",
            subject_digest=SUBJECT,
            reason_code="CISCO_MANIFEST_MISSING_LICENSE",
            severity="info",
            document_json="{}",
        )

        self.assertEqual(
            normalize_vendor_observations(
                "cisco-skill-scanner", (completion, information)
            ),
            ("REVIEW", ("CISCO_MANIFEST_MISSING_LICENSE",)),
        )
        self.assertEqual(
            normalize_vendor_observations(
                "cisco-skill-scanner",
                (completion, information),
                normalization="cisco-ai-skill-scanner-2.0.12/v2",
            ),
            ("ALLOW", ()),
        )
        self.assertEqual(
            normalize_vendor_observations(
                "cisco-skill-scanner",
                (completion, information, finding),
                normalization="cisco-ai-skill-scanner-2.0.12/v2",
            ),
            ("DENY", ("CISCO_VENDOR_FINDING",)),
        )

    def test_independent_verifier_requires_full_lock_and_exact_runtime(self) -> None:
        lock = json.loads((ROOT / "benchmark" / "baselines.lock.json").read_bytes())
        cisco = next(
            item for item in lock["baselines"] if item["name"] == "cisco-skill-scanner"
        )
        system = {
            "name": cisco["name"],
            "version": cisco["version"],
            "implementation_digest": cisco["image"]["platform_manifest_digest"],
            "config_digest": "sha256:" + "f" * 64,
        }
        partial = copy.deepcopy(lock)
        partial["baselines"] = [cisco]
        with self.assertRaisesRegex(BenchmarkError, "exactly the pinned"):
            _select_oci_baseline(partial, system, "evidence")

        weakened = copy.deepcopy(cisco["runtime_profile"])
        weakened["pids_limit"] += 1
        with self.assertRaisesRegex(BenchmarkError, "pinned isolation"):
            _validate_oci_runtime_profile(weakened, "runtime")

    @staticmethod
    def _evidence(
        cas: CAS,
        stdout: bytes,
        *,
        raw_lock: bytes | None = None,
        evidence_version: int = 2,
        status: str = "ok",
        error_code: str | None = None,
        verdict: str = "ALLOW",
        reason_codes: list[str] | None = None,
    ) -> tuple[dict, dict]:
        if evidence_version not in {2, 3}:
            raise AssertionError("unsupported synthetic evidence version")
        reason_codes = reason_codes or []
        parsed_lock = json.loads(
            (ROOT / "benchmark" / "baselines.lock.json").read_bytes()
        )
        selected = next(
            item
            for item in parsed_lock["baselines"]
            if item["name"] == "cisco-skill-scanner"
        )
        labels = {
            "dev.aragorn.baseline.build-input-sha256": selected["build"][
                "build_input_sha256"
            ],
            "dev.aragorn.baseline.lock-sha256": selected["build"][
                "dependency_lock_sha256"
            ],
            "dev.aragorn.closure-status": "candidate-not-runner-attested",
            "org.opencontainers.image.revision": selected["commit"],
            "org.opencontainers.image.source": selected["repository"],
            "org.opencontainers.image.version": "2.0.12",
        }
        raw_image_config = canonical(
            {
                "architecture": selected["image"]["architecture"],
                "os": selected["image"]["os"],
                "config": {
                    "User": "65532:65532",
                    "Env": ["PATH=/opt/venv/bin:/usr/bin:/bin"],
                    "Entrypoint": ["/opt/venv/bin/skill-scanner"],
                    "WorkingDir": "/opt/aragorn-control",
                    "Labels": labels,
                },
            }
        )
        retained_config_digest = put(cas, raw_image_config)
        raw_platform_manifest = canonical(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": retained_config_digest,
                    "size": len(raw_image_config),
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": "sha256:" + "6" * 64,
                        "size": 1,
                    }
                ],
            }
        )
        platform_manifest_digest = digest(raw_platform_manifest)
        raw_provenance_manifest = canonical(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:" + "7" * 64,
                    "size": 1,
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.in-toto+json",
                        "digest": "sha256:" + "8" * 64,
                        "size": 1,
                        "annotations": {
                            "in-toto.io/predicate-type": (
                                "https://slsa.dev/provenance/v1"
                            )
                        },
                    }
                ],
            }
        )
        provenance_manifest_digest = digest(raw_provenance_manifest)
        raw_oci_index = canonical(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": platform_manifest_digest,
                        "size": len(raw_platform_manifest),
                        "platform": {
                            "architecture": selected["image"]["architecture"],
                            "os": selected["image"]["os"],
                        },
                    },
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": provenance_manifest_digest,
                        "size": len(raw_provenance_manifest),
                        "annotations": {
                            "vnd.docker.reference.digest": (
                                platform_manifest_digest
                            ),
                            "vnd.docker.reference.type": "attestation-manifest",
                        },
                        "platform": {
                            "architecture": "unknown",
                            "os": "unknown",
                        },
                    },
                ],
            }
        )
        index_digest = digest(raw_oci_index)
        if raw_lock is None:
            parsed_lock = copy.deepcopy(parsed_lock)
            selected = next(
                item
                for item in parsed_lock["baselines"]
                if item["name"] == "cisco-skill-scanner"
            )
            selected["image"]["config_digest"] = retained_config_digest
            selected["image"]["platform_manifest_digest"] = (
                platform_manifest_digest
            )
            selected["image"]["build_provenance_manifest_digest"] = (
                provenance_manifest_digest
            )
            selected["image"]["index_digest"] = index_digest
            locked_bytes = canonical(parsed_lock)
        else:
            locked_bytes = raw_lock
        lock_digest = put(cas, locked_bytes)
        entry_digest = put(cas, canonical(selected))
        docker_digest = put(cas, b"synthetic-docker")
        image = selected["image"]
        local_tag = image["local_tag"]
        repository = local_tag.rsplit(":", 1)[0]
        reference = f"{repository}@{image['index_digest']}"
        environment = {"PATH": "/opt/venv/bin:/usr/bin:/bin"}
        effective = {
            "schema": (
                "aragorn/benchmark-oci-system-config/v2"
                if evidence_version == 3
                else "aragorn/benchmark-oci-system-config/v1"
            ),
            "name": selected["name"],
            "version": selected["version"],
            "baseline_lock_digest": lock_digest,
            "baseline_entry_digest": entry_digest,
            "docker_executable_digest": docker_digest,
            "image": {
                "reference": reference,
                "index_digest": image["index_digest"],
                "platform_manifest_digest": image["platform_manifest_digest"],
                "config_digest": image["config_digest"],
                "os": image["os"],
                "architecture": image["architecture"],
                "size_bytes": image["size_bytes"],
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
            "environment": environment,
            "runtime_profile": selected["runtime_profile"],
            "limits": {"timeout_seconds": 120, "output_bytes": 8 * 1024 * 1024},
            "normalization": "cisco-ai-skill-scanner-2.0.12/v1",
        }
        if evidence_version == 3:
            effective["runner_identity"] = normalized_runner_identity()
        effective_digest = put(cas, canonical(effective))
        system = {
            "name": selected["name"],
            "version": selected["version"],
            "implementation_digest": image["platform_manifest_digest"],
            "config_digest": effective_digest,
        }
        image_config = {
            "User": "65532:65532",
            "Env": ["PATH=/opt/venv/bin:/usr/bin:/bin"],
            "Entrypoint": ["/opt/venv/bin/skill-scanner"],
            "WorkingDir": "/opt/aragorn-control",
            "Labels": labels,
        }
        common = {
            "RepoTags": [local_tag],
            "RepoDigests": [reference],
            "Architecture": image["architecture"],
            "Os": image["os"],
            "Size": image["size_bytes"],
            "Config": image_config,
        }
        index_inspect = [
            {
                **common,
                "Id": image["index_digest"],
                "Descriptor": {
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "digest": image["index_digest"],
                },
            }
        ]
        platform_inspect = [
            {
                **common,
                "Id": image["platform_manifest_digest"],
                "Descriptor": {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": image["platform_manifest_digest"],
                    "platform": {
                        "architecture": image["architecture"],
                        "os": image["os"],
                    },
                },
            }
        ]
        runtime = selected["runtime_profile"]
        container_inspect = [
            {
                "Id": CONTAINER_ID,
                "Image": image["index_digest"],
                "ImageManifestDescriptor": {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": image["platform_manifest_digest"],
                    "platform": {
                        "architecture": image["architecture"],
                        "os": image["os"],
                    },
                },
                "Path": "/opt/venv/bin/skill-scanner",
                "Args": effective["arguments"],
                "Config": {
                    "Image": reference,
                    "User": runtime["user"],
                    "WorkingDir": runtime["workdir"],
                    "Entrypoint": effective["entrypoint"],
                    "Cmd": effective["arguments"],
                    "Env": ["PATH=/opt/venv/bin:/usr/bin:/bin"],
                },
                "HostConfig": {
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "CapAdd": None,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges=true"],
                    "PidsLimit": runtime["pids_limit"],
                    "Memory": runtime["memory_bytes"],
                    "MemorySwap": runtime["memory_swap_bytes"],
                    "NanoCpus": 2_000_000_000,
                    "Privileged": False,
                    "PublishAllPorts": False,
                    "Devices": [],
                    "DeviceRequests": [],
                    "Ulimits": [
                        {
                            "Name": "nofile",
                            "Soft": runtime["nofile_soft"],
                            "Hard": runtime["nofile_hard"],
                        }
                    ],
                    "Tmpfs": {
                        "/tmp": (
                            "rw,noexec,nosuid,nodev,mode=1777,"
                            f"size={runtime['tmpfs']['size_bytes']}"
                        )
                    },
                    "Mounts": [
                        {
                            "Type": "bind",
                            "Source": "/host/case",
                            "Target": "/workspace",
                            "ReadOnly": True,
                        }
                    ],
                },
                "Mounts": [
                    {
                        "Type": "bind",
                        "Source": "/host/case",
                        "Destination": "/workspace",
                        "Mode": "ro",
                        "RW": False,
                    }
                ],
                "NetworkSettings": {"Networks": {"none": {}}},
                "State": {
                    "Status": "created",
                    "Running": False,
                    "Dead": False,
                    "OOMKilled": False,
                    "ExitCode": 0,
                },
            }
        ]
        postrun_inspect = copy.deepcopy(container_inspect)
        postrun_inspect[0]["State"]["Status"] = "exited"
        manifest = {"schema": "synthetic-manifest/v1", "tree_digest": SUBJECT}
        manifest_digest = put(cas, canonical(manifest))
        stdout_digest = put(cas, stdout)
        stderr_digest = put(cas, b"")
        observations = (
            normalize_cisco_report(stdout, subject_digest=SUBJECT, returncode=0)
            if status == "ok"
            else ()
        )
        observation_digests = [
            put(cas, observation.document_json.encode("ascii"))
            for observation in observations
        ]
        envelope = {
            "schema": f"aragorn/benchmark-evidence/v{evidence_version}",
            "suite_digest": SUITE,
            "case_id": "case",
            "tree_digest": SUBJECT,
            "verified_subject_digest": SUBJECT,
            "run_id": 1,
            "system": system,
            "manifest_digest": manifest_digest,
            "baseline_lock_digest": lock_digest,
            "baseline_entry_digest": entry_digest,
            "effective_config_digest": effective_digest,
            "oci_index_digest": put(cas, raw_oci_index),
            "oci_platform_manifest_digest": put(
                cas, raw_platform_manifest
            ),
            "build_provenance_manifest_digest": put(
                cas, raw_provenance_manifest
            ),
            "index_inspect_digest": put(cas, canonical(index_inspect)),
            "platform_inspect_digest": put(cas, canonical(platform_inspect)),
            "image_config_digest": image["config_digest"],
            "prestart_container_inspect_digest": put(
                cas, canonical(container_inspect)
            ),
            "postrun_container_inspect_digest": put(
                cas, canonical(postrun_inspect)
            ),
            "stdout_digest": stdout_digest,
            "stderr_digest": stderr_digest,
            "observation_digests": observation_digests,
            "execution": {
                "status": status,
                "error_code": error_code,
                "returncode": 0,
                "container_id": CONTAINER_ID,
            },
            "normalization": effective["normalization"],
            "verdict": verdict,
            "reason_codes": reason_codes,
        }
        if evidence_version == 3:
            raw_context, raw_version, raw_info = runner_receipt_documents()
            receipt = {
                "context_inspect_digest": put(cas, canonical(raw_context)),
                "daemon_version_digest": put(cas, canonical(raw_version)),
                "daemon_info_digest": put(cas, canonical(raw_info)),
            }
            envelope["runner_receipts"] = {
                "pre": receipt,
                "post": receipt.copy(),
            }
        outcome = {
            "schema": "aragorn/benchmark-outcome/v1",
            "suite_digest": SUITE,
            "case_id": "case",
            "tree_digest": SUBJECT,
            "run_id": 1,
            "system": system,
            "evidence_digest": put(cas, canonical(envelope)),
            "verdict": verdict,
            "reason_codes": reason_codes,
        }
        return outcome, manifest


if __name__ == "__main__":
    unittest.main()
