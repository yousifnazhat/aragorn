"""Exact semantic CAS closure for protocol-v2 benchmark worker handoffs."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

from .benchmark import BenchmarkError, _verify_oci_evidence_v2
from .benchmark_protocol_v2 import (
    canonical_request_digest_v2,
    canonical_result_digest_v2,
    portable_policy_digest,
    validate_portable_policy,
    validate_worker_request_v2,
    validate_worker_result_v2,
    verify_effective_config_binding_v2,
    verify_request_challenge_v2,
    verify_request_policy_v2,
    verify_request_result_binding_v2,
    verify_request_subject_v2,
)
from .cas import CAS, CASError
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_json,
    subject_manifest_digest,
    validate_subject_manifest,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_REQUEST_BYTES = 64 * 1024
_MAX_RESULT_BYTES = 8 * 1024 * 1024
_MAX_PORTABLE_POLICY_BYTES = 8 * 1024 * 1024
_MAX_SUBJECT_MANIFEST_BYTES = 128 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_MAX_RUNNER_RECEIPT_BYTES = 1024 * 1024
_MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_MAX_OUTPUT_BLOBS = 25_000
_MAX_OUTPUT_TOTAL_BYTES = 512 * 1024 * 1024

BlobReader = Callable[[str, int], bytes]


class SemanticClosureError(ValueError):
    """A protocol-v2 root does not select one exact transferable closure."""


def derive_worker_input_cas_closure(
    cas: CAS,
    request_digest: str,
    *,
    expected_challenge: str,
) -> dict[str, int]:
    """Derive an exact worker-input closure from a verified CAS."""

    def read_blob(digest: str, maximum: int) -> bytes:
        try:
            return cas.read(digest, max_bytes=maximum)
        except CASError as exc:
            raise SemanticClosureError(
                f"cannot read worker-input blob {digest}: {exc}"
            ) from exc

    return derive_worker_input_closure(
        read_blob,
        request_digest,
        expected_challenge=expected_challenge,
    )


def derive_worker_input_closure(
    read_blob: BlobReader,
    request_digest: str,
    *,
    expected_challenge: str,
) -> dict[str, int]:
    """Derive request, policy, subject-manifest, and subject-file reachability."""

    root_digest = _digest(request_digest, "worker-input request digest")
    closure: dict[str, int] = {}
    try:
        raw_request = _read_verified_blob(
            read_blob,
            root_digest,
            _MAX_REQUEST_BYTES,
            "worker request v2",
        )
        request = _decode_canonical_object(raw_request, "worker request v2")
        validate_worker_request_v2(request)
        verify_request_challenge_v2(request, expected_challenge)
        if canonical_request_digest_v2(request) != root_digest:
            raise SemanticClosureError(
                "worker-input root is not the canonical request digest"
            )
        _retain(closure, root_digest, len(raw_request))

        manifest_digest = request["subject"]["manifest_digest"]
        raw_manifest = _read_verified_blob(
            read_blob,
            manifest_digest,
            _MAX_SUBJECT_MANIFEST_BYTES,
            "worker subject manifest",
        )
        manifest = _decode_canonical_object(
            raw_manifest,
            "worker subject manifest",
        )
        validate_subject_manifest(manifest)
        if subject_manifest_digest(manifest) != manifest_digest:
            raise SemanticClosureError(
                "worker subject manifest digest does not match its content"
            )
        verify_request_subject_v2(request, manifest)
        _retain(closure, manifest_digest, len(raw_manifest))

        policy_digest = request["portable_policy_digest"]
        raw_policy = _read_verified_blob(
            read_blob,
            policy_digest,
            _MAX_PORTABLE_POLICY_BYTES,
            "portable policy",
        )
        policy = _decode_canonical_object(raw_policy, "portable policy")
        validate_portable_policy(policy)
        if portable_policy_digest(policy) != policy_digest:
            raise SemanticClosureError(
                "portable policy digest does not match its content"
            )
        verify_request_policy_v2(request, policy)
        _retain(closure, policy_digest, len(raw_policy))

        for entry in manifest["files"]:
            content = _read_verified_blob(
                read_blob,
                entry["digest"],
                entry["size"],
                f"subject file {entry['path']}",
            )
            if len(content) != entry["size"]:
                raise SemanticClosureError(
                    f"subject file size does not match: {entry['path']}"
                )
            _retain(closure, entry["digest"], len(content))
    except SemanticClosureError:
        raise
    except (WorkerProtocolError, KeyError, TypeError, ValueError) as exc:
        raise SemanticClosureError(
            f"invalid worker-input semantic closure: {exc}"
        ) from exc
    return dict(sorted(closure.items()))


def derive_worker_output_cas_closure(
    cas: CAS,
    result_digest: str,
    *,
    expected_request_digest: str,
    expected_challenge: str,
) -> dict[str, int]:
    """Derive an exact worker-output closure from a verified CAS."""

    def read_blob(digest: str, maximum: int) -> bytes:
        try:
            return cas.read(digest, max_bytes=maximum)
        except CASError as exc:
            raise SemanticClosureError(
                f"cannot read worker-output blob {digest}: {exc}"
            ) from exc

    return derive_worker_output_closure(
        read_blob,
        result_digest,
        expected_request_digest=expected_request_digest,
        expected_challenge=expected_challenge,
    )


def verify_worker_output_evidence_cas_v2(
    cas: CAS,
    result_digest: str,
    *,
    expected_request_digest: str,
    expected_challenge: str,
) -> dict[str, int]:
    """Accept a v2 worker result only after re-verifying its OCI evidence.

    The worker result deliberately has no private suite labels.  This adapter
    constructs only fixed local labels for the legacy OCI evidence verifier;
    the verifier's security-relevant inputs remain the result, request, and
    sanitized subject already bound to the verifier-held request and challenge.
    """

    closure = derive_worker_output_cas_closure(
        cas,
        result_digest,
        expected_request_digest=expected_request_digest,
        expected_challenge=expected_challenge,
    )
    root_digest = _digest(result_digest, "worker-output result digest")

    def read_blob(digest: str, maximum: int) -> bytes:
        try:
            return cas.read(digest, max_bytes=maximum)
        except CASError as exc:
            raise SemanticClosureError(
                f"cannot read worker-output blob {digest}: {exc}"
            ) from exc

    try:
        result = _decode_canonical_object(
            _read_verified_blob(
                read_blob,
                root_digest,
                _MAX_RESULT_BYTES,
                "worker result v2",
            ),
            "worker result v2",
        )
        subject = _decode_canonical_object(
            _read_verified_blob(
                read_blob,
                result["subject_manifest_digest"],
                _MAX_SUBJECT_MANIFEST_BYTES,
                "worker subject manifest",
            ),
            "worker subject manifest",
        )
        evidence_system = {
            **result["system"],
            "config_digest": result["effective_config_digest"],
        }
        # These values are intentionally fixed and never supplied by the worker.
        # They only satisfy the legacy envelope shape; no suite labels are
        # introduced into, or inferred from, the worker result.
        envelope = {
            "schema": "aragorn/benchmark-evidence/v3",
            "suite_digest": _digest_bytes(b"aragorn/worker-v2-evidence/v1"),
            "case_id": "worker-v2",
            "tree_digest": result["tree_digest"],
            "verified_subject_digest": result["verified_subject_digest"],
            "run_id": 1,
            "system": evidence_system,
            "manifest_digest": result["subject_manifest_digest"],
            "baseline_lock_digest": result["baseline_lock_digest"],
            "baseline_entry_digest": result["baseline_entry_digest"],
            "effective_config_digest": result["effective_config_digest"],
            "oci_index_digest": result["oci_index_digest"],
            "oci_platform_manifest_digest": result[
                "oci_platform_manifest_digest"
            ],
            "build_provenance_manifest_digest": result[
                "build_provenance_manifest_digest"
            ],
            "index_inspect_digest": result["index_inspect_digest"],
            "platform_inspect_digest": result["platform_inspect_digest"],
            "image_config_digest": result["image_config_digest"],
            "runner_receipts": result["runner_receipts"],
            "prestart_container_inspect_digest": result[
                "prestart_container_inspect_digest"
            ],
            "postrun_container_inspect_digest": result[
                "postrun_container_inspect_digest"
            ],
            "stdout_digest": result["stdout_digest"],
            "stderr_digest": result["stderr_digest"],
            "observation_digests": result["observation_digests"],
            "execution": result["execution"],
            "normalization": result["normalization"],
            "verdict": result["verdict"],
            "reason_codes": result["reason_codes"],
        }
        outcome = {
            "suite_digest": envelope["suite_digest"],
            "case_id": envelope["case_id"],
            "tree_digest": result["tree_digest"],
            "run_id": 1,
            "system": evidence_system,
            "verdict": result["verdict"],
            "reason_codes": result["reason_codes"],
        }
        _verify_oci_evidence_v2(
            cas,
            outcome,
            expected_manifest=subject,
            label="worker-output-v2",
            envelope=envelope,
        )
    except (BenchmarkError, KeyError, TypeError, ValueError) as exc:
        raise SemanticClosureError(
            f"invalid worker-output OCI evidence: {exc}"
        ) from exc
    return closure


def derive_worker_output_closure(
    read_blob: BlobReader,
    result_digest: str,
    *,
    expected_request_digest: str,
    expected_challenge: str,
) -> dict[str, int]:
    """Derive result, full input, and every explicitly retained evidence edge."""

    root_digest = _digest(result_digest, "worker-output result digest")
    issued_request_digest = _digest(
        expected_request_digest,
        "expected worker request v2 digest",
    )
    closure: dict[str, int] = {}
    total_bytes = 0

    def retain_blob(digest: str, maximum: int, label: str) -> bytes:
        nonlocal total_bytes
        content = _read_verified_blob(read_blob, digest, maximum, label)
        total_bytes += _retain(closure, digest, len(content))
        if len(closure) > _MAX_OUTPUT_BLOBS:
            raise SemanticClosureError("worker-output closure has too many blobs")
        if total_bytes > _MAX_OUTPUT_TOTAL_BYTES:
            raise SemanticClosureError(
                "worker-output closure exceeds its total byte limit"
            )
        return content

    try:
        raw_result = retain_blob(
            root_digest,
            _MAX_RESULT_BYTES,
            "worker result v2",
        )
        result = _decode_canonical_object(raw_result, "worker result v2")
        validate_worker_result_v2(result)
        if canonical_result_digest_v2(result) != root_digest:
            raise SemanticClosureError(
                "worker-output root is not the canonical result digest"
            )
        if result["request_digest"] != issued_request_digest:
            raise SemanticClosureError(
                "worker result v2 does not select the verifier-issued request"
            )

        input_closure = derive_worker_input_closure(
            read_blob,
            issued_request_digest,
            expected_challenge=expected_challenge,
        )
        for digest, size in input_closure.items():
            total_bytes += _retain(closure, digest, size)
        if len(closure) > _MAX_OUTPUT_BLOBS:
            raise SemanticClosureError("worker-output closure has too many blobs")
        if total_bytes > _MAX_OUTPUT_TOTAL_BYTES:
            raise SemanticClosureError(
                "worker-output closure exceeds its total byte limit"
            )

        raw_request = _read_verified_blob(
            read_blob,
            issued_request_digest,
            _MAX_REQUEST_BYTES,
            "worker request v2",
        )
        request = _decode_canonical_object(raw_request, "worker request v2")
        raw_policy = _read_verified_blob(
            read_blob,
            request["portable_policy_digest"],
            _MAX_PORTABLE_POLICY_BYTES,
            "portable policy",
        )
        policy = _decode_canonical_object(raw_policy, "portable policy")
        verify_request_result_binding_v2(
            request,
            policy,
            result,
            expected_request_digest=issued_request_digest,
            expected_challenge=expected_challenge,
        )

        for field in ("baseline_lock_digest", "baseline_entry_digest"):
            retain_blob(
                result[field],
                _MAX_EVIDENCE_BYTES,
                f"worker result v2 {field}",
            )

        raw_effective_config = retain_blob(
            result["effective_config_digest"],
            _MAX_EVIDENCE_BYTES,
            "effective config v2",
        )
        effective_config = _decode_canonical_object(
            raw_effective_config,
            "effective config v2",
        )
        verify_effective_config_binding_v2(policy, result, effective_config)
        retain_blob(
            result["docker_executable_digest"],
            _MAX_EXECUTABLE_BYTES,
            "Docker executable",
        )

        for field in (
            "oci_index_digest",
            "oci_platform_manifest_digest",
            "build_provenance_manifest_digest",
            "index_inspect_digest",
            "platform_inspect_digest",
            "image_config_digest",
            "prestart_container_inspect_digest",
            "postrun_container_inspect_digest",
        ):
            retain_blob(
                result[field],
                _MAX_EVIDENCE_BYTES,
                f"worker result v2 {field}",
            )

        for phase in ("pre", "post"):
            for field in (
                "context_inspect_digest",
                "daemon_version_digest",
                "daemon_info_digest",
            ):
                retain_blob(
                    result["runner_receipts"][phase][field],
                    _MAX_RUNNER_RECEIPT_BYTES,
                    f"worker result v2 runner_receipts.{phase}.{field}",
                )

        output_limit = policy["limits"]["output_bytes"]
        stdout = retain_blob(
            result["stdout_digest"],
            output_limit,
            "worker result v2 stdout",
        )
        stderr = retain_blob(
            result["stderr_digest"],
            output_limit,
            "worker result v2 stderr",
        )
        output_bytes = len(stdout) + len(stderr)
        if output_bytes > output_limit:
            raise SemanticClosureError(
                "worker result v2 stdout and stderr exceed the output limit"
            )
        if (
            result["execution"]["error_code"] == "OUTPUT_LIMIT_EXCEEDED"
            and output_bytes != output_limit
        ):
            raise SemanticClosureError(
                "worker result v2 output-limit error is inconsistent"
            )

        for index, digest in enumerate(result["observation_digests"]):
            retain_blob(
                digest,
                _MAX_EVIDENCE_BYTES,
                f"worker result v2 observation_digests[{index}]",
            )
    except SemanticClosureError:
        raise
    except (WorkerProtocolError, KeyError, TypeError, ValueError) as exc:
        raise SemanticClosureError(
            f"invalid worker-output semantic closure: {exc}"
        ) from exc
    return dict(sorted(closure.items()))


def _read_verified_blob(
    read_blob: BlobReader,
    digest: str,
    maximum: int,
    label: str,
) -> bytes:
    digest = _digest(digest, f"{label} digest")
    try:
        content = read_blob(digest, maximum)
    except SemanticClosureError:
        raise
    except Exception as exc:
        raise SemanticClosureError(f"cannot read {label}: {exc}") from exc
    if not isinstance(content, bytes):
        raise SemanticClosureError(f"{label} reader did not return bytes")
    if len(content) > maximum:
        raise SemanticClosureError(f"{label} exceeds its byte limit")
    actual = "sha256:" + hashlib.sha256(content).hexdigest()
    if actual != digest:
        raise SemanticClosureError(f"{label} digest does not match")
    return content


def _decode_canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SemanticClosureError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SemanticClosureError(f"{label} must be a JSON object")
    if canonical_json(document) != raw:
        raise SemanticClosureError(f"{label} must be canonical JSON")
    return document


def _retain(closure: dict[str, int], digest: str, size: int) -> int:
    previous = closure.get(digest)
    if previous is not None and previous != size:
        raise SemanticClosureError(
            f"semantic closure digest has conflicting sizes: {digest}"
        )
    if previous is not None:
        return 0
    closure[digest] = size
    return size


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise SemanticClosureError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _digest_bytes(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SemanticClosureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise SemanticClosureError(f"non-finite JSON value: {value}")
