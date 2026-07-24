from __future__ import annotations

from copy import deepcopy
import unittest

from aragorn.oci_worker_protocol import (
    WorkerProtocolError,
    build_worker_request,
    canonical_digest,
    canonical_request_digest,
    sanitize_subject_manifest,
    subject_manifest_digest,
    validate_subject_manifest,
    validate_worker_request,
    validate_worker_result,
    verify_request_result_binding,
    verify_request_subject,
)


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def source_manifest() -> dict:
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
    return {
        "schema": "aragorn/manifest/v1",
        "source": {
            "kind": "local",
            "path": "/private/corpus/held_out/adversarial/injection-family",
        },
        "tree_digest": canonical_digest(files),
        "files": files,
        "closure": {"scope": "source_tree", "status": "complete"},
        "class": "adversarial",
        "family": "injection-family",
        "lineage": "lineage-secret",
        "split": "held_out",
    }


def system() -> dict:
    return {
        "name": "cisco-skill-scanner",
        "version": "2.0.12",
        "implementation_digest": (
            "sha256:7fadcfbe836eef9490feba0fadd2ada564c11eb541077e3efee5f61edbd2e65c"
        ),
        "config_digest": digest("4"),
    }


def request_and_subject() -> tuple[dict, dict]:
    subject = sanitize_subject_manifest(source_manifest())
    tokens = iter(("a" * 32, "b" * 64))
    request = build_worker_request(
        subject,
        system(),
        baseline_lock_digest=digest("5"),
        baseline_entry_digest=digest("6"),
        timeout_seconds=120.0,
        output_limit_bytes=1024 * 1024,
        token_hex=lambda _size: next(tokens),
    )
    return request, subject


def worker_result(request: dict) -> dict:
    receipt = {
        "context_inspect_digest": digest("7"),
        "daemon_version_digest": digest("8"),
        "daemon_info_digest": digest("9"),
    }
    return {
        "schema": "aragorn/benchmark-worker-result/v1",
        "job_id": request["job_id"],
        "nonce": request["nonce"],
        "request_digest": canonical_request_digest(request),
        "subject_manifest_digest": request["subject"]["manifest_digest"],
        "tree_digest": request["subject"]["tree_digest"],
        "verified_subject_digest": request["subject"]["tree_digest"],
        "system": dict(request["system"]),
        "baseline_lock_digest": request["baseline"]["lock_digest"],
        "baseline_entry_digest": request["baseline"]["entry_digest"],
        "effective_config_digest": request["system"]["config_digest"],
        "oci_index_digest": digest("a"),
        "oci_platform_manifest_digest": digest("b"),
        "build_provenance_manifest_digest": digest("c"),
        "index_inspect_digest": digest("d"),
        "platform_inspect_digest": digest("e"),
        "image_config_digest": digest("f"),
        "runner_receipts": {
            "pre": dict(receipt),
            "post": dict(receipt),
        },
        "prestart_container_inspect_digest": digest("0"),
        "postrun_container_inspect_digest": digest("1"),
        "stdout_digest": digest("2"),
        "stderr_digest": digest("3"),
        "observation_digests": [],
        "execution": {
            "status": "ok",
            "error_code": None,
            "returncode": 0,
            "container_id": "4" * 64,
        },
        "normalization": "cisco-ai-skill-scanner-2.0.12/v1",
        "verdict": "ALLOW",
        "reason_codes": [],
    }


class SubjectManifestTests(unittest.TestCase):
    def test_sanitizer_retains_only_label_free_execution_identity(self) -> None:
        subject = sanitize_subject_manifest(source_manifest())

        self.assertEqual(
            set(subject),
            {"schema", "tree_digest", "files"},
        )
        self.assertEqual(
            subject["schema"],
            "aragorn/benchmark-subject-manifest/v1",
        )
        serialized = str(subject)
        for secret in (
            "source",
            "held_out",
            "adversarial",
            "injection-family",
            "lineage-secret",
        ):
            self.assertNotIn(secret, serialized)
        validate_subject_manifest(subject)

    def test_tree_digest_is_independently_derived_from_sorted_files(self) -> None:
        manifest = source_manifest()
        manifest["tree_digest"] = digest("f")
        with self.assertRaisesRegex(WorkerProtocolError, "tree digest"):
            sanitize_subject_manifest(manifest)

        subject = sanitize_subject_manifest(source_manifest())
        subject["files"][0]["size"] += 1
        with self.assertRaisesRegex(WorkerProtocolError, "tree digest"):
            validate_subject_manifest(subject)

    def test_duplicate_unsorted_executable_and_unsafe_paths_fail_closed(self) -> None:
        subject = sanitize_subject_manifest(source_manifest())
        mutations = []

        duplicate = deepcopy(subject)
        duplicate["files"].append(dict(duplicate["files"][0]))
        duplicate["tree_digest"] = canonical_digest(duplicate["files"])
        mutations.append(duplicate)

        unsorted = deepcopy(subject)
        unsorted["files"].reverse()
        unsorted["tree_digest"] = canonical_digest(unsorted["files"])
        mutations.append(unsorted)

        executable = deepcopy(subject)
        executable["files"][0]["executable"] = True
        executable["tree_digest"] = canonical_digest(executable["files"])
        mutations.append(executable)

        unsafe = deepcopy(subject)
        unsafe["files"][0]["path"] = "../SKILL.md"
        unsafe["tree_digest"] = canonical_digest(unsafe["files"])
        mutations.append(unsafe)

        for mutation in mutations:
            with self.subTest(mutation=mutation["files"]):
                with self.assertRaises(WorkerProtocolError):
                    validate_subject_manifest(mutation)

    def test_ambiguous_and_control_bearing_paths_fail_closed(self) -> None:
        subject = sanitize_subject_manifest(source_manifest())
        mutations = []

        collision = deepcopy(subject)
        collision["files"][1]["path"] = "skill.MD"
        collision["tree_digest"] = canonical_digest(collision["files"])
        mutations.append(collision)

        for path in ("notes/line\nbreak.txt", "notes/zero\u200bwidth.txt", "e\u0301.txt"):
            changed = deepcopy(subject)
            changed["files"][1]["path"] = path
            changed["tree_digest"] = canonical_digest(changed["files"])
            mutations.append(changed)

        for mutation in mutations:
            with self.subTest(path=mutation["files"][1]["path"]):
                with self.assertRaises(WorkerProtocolError):
                    validate_subject_manifest(mutation)


class WorkerRequestTests(unittest.TestCase):
    def test_builder_uses_injected_fresh_random_values_and_canonical_digest(self) -> None:
        subject = sanitize_subject_manifest(source_manifest())
        calls = []
        tokens = iter(("a" * 32, "b" * 64))

        def token_hex(size: int) -> str:
            calls.append(size)
            return next(tokens)

        request = build_worker_request(
            subject,
            system(),
            baseline_lock_digest=digest("5"),
            baseline_entry_digest=digest("6"),
            timeout_seconds=120,
            output_limit_bytes=4096,
            token_hex=token_hex,
        )

        self.assertEqual(calls, [16, 32])
        self.assertEqual(request["job_id"], "a" * 32)
        self.assertEqual(request["nonce"], "b" * 64)
        self.assertEqual(
            request["subject"]["manifest_digest"],
            subject_manifest_digest(subject),
        )
        self.assertEqual(
            canonical_request_digest(request),
            canonical_digest(request),
        )
        validate_worker_request(request)

    def test_request_rejects_labels_and_trust_claims(self) -> None:
        request, _subject = request_and_subject()
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
        )
        for field in forbidden:
            mutation = deepcopy(request)
            mutation[field] = "forbidden"
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    WorkerProtocolError, "missing or unknown fields"
                ):
                    validate_worker_request(mutation)

    def test_request_subject_binding_rejects_manifest_and_tree_drift(self) -> None:
        request, subject = request_and_subject()
        verify_request_subject(request, subject)

        changed_manifest = deepcopy(subject)
        changed_manifest["files"][0]["size"] += 1
        changed_manifest["tree_digest"] = canonical_digest(changed_manifest["files"])
        with self.assertRaisesRegex(WorkerProtocolError, "manifest digest"):
            verify_request_subject(request, changed_manifest)

        changed_request = deepcopy(request)
        changed_request["subject"]["tree_digest"] = digest("f")
        with self.assertRaisesRegex(WorkerProtocolError, "tree digest"):
            verify_request_subject(changed_request, subject)

    def test_malformed_injected_randomness_is_rejected(self) -> None:
        subject = sanitize_subject_manifest(source_manifest())
        with self.assertRaisesRegex(WorkerProtocolError, "job_id"):
            build_worker_request(
                subject,
                system(),
                baseline_lock_digest=digest("5"),
                baseline_entry_digest=digest("6"),
                timeout_seconds=120,
                output_limit_bytes=4096,
                token_hex=lambda _size: "not-random",
            )

    def test_system_identity_cannot_encode_label_metadata(self) -> None:
        request, _subject = request_and_subject()
        mutations = (
            ("name", "held_out"),
            ("version", "held_out-adversarial"),
            ("implementation_digest", digest("f")),
        )
        for field, value in mutations:
            changed = deepcopy(request)
            changed["system"][field] = value
            with self.subTest(field=field), self.assertRaises(WorkerProtocolError):
                validate_worker_request(changed)


class WorkerResultTests(unittest.TestCase):
    def test_valid_unsigned_result_is_bound_to_request(self) -> None:
        request, _subject = request_and_subject()
        result = worker_result(request)

        validate_worker_result(result)
        verify_request_result_binding(request, result)

    def test_result_rejects_labels_dummy_signatures_and_attestation_claims(self) -> None:
        request, _subject = request_and_subject()
        result = worker_result(request)
        forbidden = (
            "suite_digest",
            "case_id",
            "class",
            "family",
            "lineage",
            "split",
            "run_id",
            "purpose",
            "expected_verdict",
            "signature",
            "attested",
            "attestation",
            "worker_assurance",
        )
        for field in forbidden:
            mutation = deepcopy(result)
            mutation[field] = True
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    WorkerProtocolError, "missing or unknown fields"
                ):
                    validate_worker_result(mutation)

    def test_nonce_request_and_subject_mutations_are_rejected(self) -> None:
        request, _subject = request_and_subject()
        result = worker_result(request)
        mutations = {
            "nonce": ("nonce", "c" * 64),
            "request_digest": ("request_digest", digest("d")),
            "subject_manifest_digest": ("subject_manifest_digest", digest("e")),
            "tree_digest": ("tree_digest", digest("f")),
            "verified_subject_digest": ("verified_subject_digest", digest("0")),
        }
        for label, (field, value) in mutations.items():
            mutation = deepcopy(result)
            mutation[field] = value
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    WorkerProtocolError, "changed request binding"
                ):
                    verify_request_result_binding(request, mutation)

        changed_request = deepcopy(request)
        changed_request["nonce"] = "d" * 64
        with self.assertRaisesRegex(
            WorkerProtocolError, "changed request binding"
        ):
            verify_request_result_binding(changed_request, result)

    def test_config_and_baseline_drift_are_rejected(self) -> None:
        request, _subject = request_and_subject()
        result = worker_result(request)

        internally_unbound = deepcopy(result)
        internally_unbound["effective_config_digest"] = digest("e")
        with self.assertRaisesRegex(
            WorkerProtocolError, "effective configuration"
        ):
            validate_worker_result(internally_unbound)

        changed_system = deepcopy(result)
        changed_system["system"]["config_digest"] = digest("e")
        changed_system["effective_config_digest"] = digest("e")
        with self.assertRaisesRegex(
            WorkerProtocolError, "changed request binding"
        ):
            verify_request_result_binding(request, changed_system)

        for field in ("baseline_lock_digest", "baseline_entry_digest"):
            mutation = deepcopy(result)
            mutation[field] = digest("e")
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    WorkerProtocolError, "changed request binding"
                ):
                    verify_request_result_binding(request, mutation)

    def test_normalizer_must_match_the_selected_system(self) -> None:
        request, _subject = request_and_subject()
        result = worker_result(request)
        result["normalization"] = "nvidia-skillspector-2.4.3/v1"

        with self.assertRaisesRegex(WorkerProtocolError, "selected system"):
            validate_worker_result(result)

    def test_execution_errors_are_typed_and_cannot_carry_clean_evidence(self) -> None:
        request, _subject = request_and_subject()
        result = worker_result(request)
        result["execution"] = {
            "status": "error",
            "error_code": "TIMEOUT",
            "returncode": 137,
            "container_id": "4" * 64,
        }
        result["verdict"] = "ERROR"
        result["reason_codes"] = ["ANALYZER_TIMEOUT"]
        validate_worker_result(result)

        result["reason_codes"] = ["ANALYZER_OUTPUT_LIMIT_EXCEEDED"]
        with self.assertRaisesRegex(WorkerProtocolError, "derive its verdict"):
            validate_worker_result(result)

        result = worker_result(request)
        result["execution"]["status"] = []
        with self.assertRaisesRegex(WorkerProtocolError, "status is unsupported"):
            validate_worker_result(result)

    def test_execution_status_and_vendor_exit_cannot_contradict(self) -> None:
        request, _subject = request_and_subject()

        result = worker_result(request)
        result["execution"]["returncode"] = 137
        with self.assertRaisesRegex(WorkerProtocolError, "invalid vendor exit"):
            validate_worker_result(result)

        result = worker_result(request)
        result["execution"].update(
            {"status": "error", "error_code": "TIMEOUT", "returncode": 0}
        )
        result["verdict"] = "ERROR"
        result["reason_codes"] = ["ANALYZER_TIMEOUT"]
        with self.assertRaisesRegex(WorkerProtocolError, "successful container exit"):
            validate_worker_result(result)

        result = worker_result(request)
        result["execution"].update(
            {
                "status": "error",
                "error_code": "MALFORMED_VENDOR_REPORT",
                "returncode": 9,
            }
        )
        result["verdict"] = "ERROR"
        result["reason_codes"] = ["ANALYZER_MALFORMED_VENDOR_REPORT"]
        with self.assertRaisesRegex(WorkerProtocolError, "invalid vendor exit"):
            validate_worker_result(result)

        result = worker_result(request)
        result["execution"].update(
            {
                "status": "error",
                "error_code": "NONZERO_OR_INVALID_VENDOR_EXIT",
                "returncode": 0,
            }
        )
        result["verdict"] = "ERROR"
        result["reason_codes"] = ["ANALYZER_NONZERO_OR_INVALID_VENDOR_EXIT"]
        with self.assertRaisesRegex(WorkerProtocolError, "inconsistent"):
            validate_worker_result(result)

    def test_reason_codes_must_be_sorted_unique_and_match_allow(self) -> None:
        request, _subject = request_and_subject()
        result = worker_result(request)
        result["verdict"] = "REVIEW"
        result["reason_codes"] = ["Z_REASON", "A_REASON"]
        with self.assertRaisesRegex(WorkerProtocolError, "sorted and unique"):
            validate_worker_result(result)

        result["verdict"] = "ALLOW"
        result["reason_codes"] = ["A_REASON"]
        with self.assertRaisesRegex(WorkerProtocolError, "ALLOW"):
            validate_worker_result(result)


if __name__ == "__main__":
    unittest.main()
