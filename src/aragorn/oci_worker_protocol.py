"""Label-free contracts for one bounded OCI benchmark worker job."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import secrets
from typing import Any
import unicodedata


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_MAX_FILES = 10_000
_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 128 * 1024 * 1024
_MAX_PATH_LENGTH = 4096
_MAX_OBSERVATIONS = 10_000
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_TIMEOUT_SECONDS = 3600.0
_ERROR_CODES = frozenset(
    {
        "MALFORMED_VENDOR_REPORT",
        "NONZERO_OR_INVALID_VENDOR_EXIT",
        "OUTPUT_LIMIT_EXCEEDED",
        "TIMEOUT",
    }
)
_NORMALIZATIONS = frozenset(
    {
        "cisco-ai-skill-scanner-2.0.12/v1",
        "nvidia-skillspector-2.4.3/v1",
    }
)
_SYSTEM_NORMALIZATION = {
    "cisco-skill-scanner": "cisco-ai-skill-scanner-2.0.12/v1",
    "skillspector": "nvidia-skillspector-2.4.3/v1",
}
_SYSTEM_IDENTITY = {
    "cisco-skill-scanner": {
        "version": "2.0.12",
        "implementation_digest": (
            "sha256:7fadcfbe836eef9490feba0fadd2ada564c11eb541077e3efee5f61edbd2e65c"
        ),
    },
    "skillspector": {
        "version": "2.4.3+git.a54947c",
        "implementation_digest": (
            "sha256:e731be01105243f94437a4b9bd449bd46bbcb5cb306f44b4845121d109a4a95e"
        ),
    },
}
_VERDICTS = frozenset({"ALLOW", "REVIEW", "DENY", "ERROR"})
_SUBJECT_KEYS = {"schema", "tree_digest", "files"}
_REQUEST_KEYS = {
    "schema",
    "job_id",
    "nonce",
    "subject",
    "system",
    "baseline",
    "limits",
}
_RESULT_KEYS = {
    "schema",
    "job_id",
    "nonce",
    "request_digest",
    "subject_manifest_digest",
    "tree_digest",
    "verified_subject_digest",
    "system",
    "baseline_lock_digest",
    "baseline_entry_digest",
    "effective_config_digest",
    "oci_index_digest",
    "oci_platform_manifest_digest",
    "build_provenance_manifest_digest",
    "index_inspect_digest",
    "platform_inspect_digest",
    "image_config_digest",
    "runner_receipts",
    "prestart_container_inspect_digest",
    "postrun_container_inspect_digest",
    "stdout_digest",
    "stderr_digest",
    "observation_digests",
    "execution",
    "normalization",
    "verdict",
    "reason_codes",
}
_RESULT_DIGEST_FIELDS = (
    "request_digest",
    "subject_manifest_digest",
    "tree_digest",
    "verified_subject_digest",
    "baseline_lock_digest",
    "baseline_entry_digest",
    "effective_config_digest",
    "oci_index_digest",
    "oci_platform_manifest_digest",
    "build_provenance_manifest_digest",
    "index_inspect_digest",
    "platform_inspect_digest",
    "image_config_digest",
    "prestart_container_inspect_digest",
    "postrun_container_inspect_digest",
    "stdout_digest",
    "stderr_digest",
)


class WorkerProtocolError(ValueError):
    """A worker protocol document is malformed or is not bound to its request."""


def canonical_json(document: object) -> bytes:
    """Return the protocol's canonical JSON representation."""

    try:
        return json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise WorkerProtocolError(f"document is not canonical JSON: {exc}") from exc


def canonical_digest(document: object) -> str:
    """Return the SHA-256 identity of canonical JSON bytes."""

    return _digest_bytes(canonical_json(document))


def sanitize_subject_manifest(source_manifest: object) -> dict[str, Any]:
    """Copy only execution-essential file identity from a private manifest."""

    if not isinstance(source_manifest, dict):
        raise WorkerProtocolError("source manifest must be a JSON object")
    if "tree_digest" not in source_manifest or "files" not in source_manifest:
        raise WorkerProtocolError("source manifest omits tree_digest or files")
    manifest = {
        "schema": "aragorn/benchmark-subject-manifest/v1",
        "tree_digest": source_manifest["tree_digest"],
        "files": source_manifest["files"],
    }
    validate_subject_manifest(manifest)
    return {
        "schema": manifest["schema"],
        "tree_digest": manifest["tree_digest"],
        "files": [dict(entry) for entry in manifest["files"]],
    }


def validate_subject_manifest(document: object) -> None:
    """Validate a label-free subject and independently derive its tree digest."""

    subject = _exact_object(document, _SUBJECT_KEYS, "subject manifest")
    if subject["schema"] != "aragorn/benchmark-subject-manifest/v1":
        raise WorkerProtocolError("subject manifest schema is unsupported")
    tree_digest = _digest(subject["tree_digest"], "subject manifest tree_digest")
    files = _validate_files(subject["files"])
    if tree_digest != canonical_digest(files):
        raise WorkerProtocolError("subject manifest tree digest does not match files")


def subject_manifest_digest(document: object) -> str:
    """Return the canonical identity of a validated label-free manifest."""

    validate_subject_manifest(document)
    return canonical_digest(document)


def build_worker_request(
    subject_manifest: object,
    system: object,
    *,
    baseline_lock_digest: str,
    baseline_entry_digest: str,
    timeout_seconds: float,
    output_limit_bytes: int,
    token_hex: Callable[[int], str] | None = None,
) -> dict[str, Any]:
    """Build one fresh request without accepting benchmark label metadata."""

    validate_subject_manifest(subject_manifest)
    _validate_system(system, "worker request system")
    generator = secrets.token_hex if token_hex is None else token_hex
    try:
        job_id = generator(16)
        nonce = generator(32)
    except Exception as exc:
        raise WorkerProtocolError(f"cannot generate worker request identity: {exc}") from exc
    request = {
        "schema": "aragorn/benchmark-worker-request/v1",
        "job_id": job_id,
        "nonce": nonce,
        "subject": {
            "manifest_digest": subject_manifest_digest(subject_manifest),
            "tree_digest": subject_manifest["tree_digest"],
        },
        "system": dict(system),
        "baseline": {
            "lock_digest": baseline_lock_digest,
            "entry_digest": baseline_entry_digest,
        },
        "limits": {
            "timeout_seconds": timeout_seconds,
            "output_bytes": output_limit_bytes,
        },
    }
    validate_worker_request(request)
    return request


def validate_worker_request(document: object) -> None:
    """Validate the exact label-blind request surface."""

    request = _exact_object(document, _REQUEST_KEYS, "worker request")
    if request["schema"] != "aragorn/benchmark-worker-request/v1":
        raise WorkerProtocolError("worker request schema is unsupported")
    _hex(request["job_id"], _JOB_ID, "worker request job_id")
    _hex(request["nonce"], _NONCE, "worker request nonce")

    subject = _exact_object(
        request["subject"],
        {"manifest_digest", "tree_digest"},
        "worker request subject",
    )
    _digest(subject["manifest_digest"], "worker request subject manifest_digest")
    _digest(subject["tree_digest"], "worker request subject tree_digest")
    _validate_system(request["system"], "worker request system")

    baseline = _exact_object(
        request["baseline"],
        {"lock_digest", "entry_digest"},
        "worker request baseline",
    )
    _digest(baseline["lock_digest"], "worker request baseline lock_digest")
    _digest(baseline["entry_digest"], "worker request baseline entry_digest")
    _validate_limits(request["limits"], "worker request limits")


def canonical_request_digest(document: object) -> str:
    """Return the canonical digest of an exact worker request."""

    validate_worker_request(document)
    return canonical_digest(document)


def verify_request_subject(request: object, subject_manifest: object) -> None:
    """Verify that the request selects exactly this sanitized subject."""

    validate_worker_request(request)
    validate_subject_manifest(subject_manifest)
    if request["subject"]["manifest_digest"] != subject_manifest_digest(
        subject_manifest
    ):
        raise WorkerProtocolError("worker request subject manifest digest changed")
    if request["subject"]["tree_digest"] != subject_manifest["tree_digest"]:
        raise WorkerProtocolError("worker request subject tree digest changed")


def validate_worker_result(document: object) -> None:
    """Validate an unsigned label-free worker result and its internal invariants."""

    result = _exact_object(document, _RESULT_KEYS, "worker result")
    if result["schema"] != "aragorn/benchmark-worker-result/v1":
        raise WorkerProtocolError("worker result schema is unsupported")
    _hex(result["job_id"], _JOB_ID, "worker result job_id")
    _hex(result["nonce"], _NONCE, "worker result nonce")
    for field in _RESULT_DIGEST_FIELDS:
        _digest(result[field], f"worker result {field}")

    system = _validate_system(result["system"], "worker result system")
    if result["effective_config_digest"] != system["config_digest"]:
        raise WorkerProtocolError(
            "worker result effective configuration is not bound to the system"
        )
    _validate_runner_receipts(result["runner_receipts"])

    observations = result["observation_digests"]
    if not isinstance(observations, list) or len(observations) > _MAX_OBSERVATIONS:
        raise WorkerProtocolError(
            "worker result observation_digests must be a bounded array"
        )
    for index, digest in enumerate(observations):
        _digest(digest, f"worker result observation_digests[{index}]")

    execution = _validate_execution(result["execution"], system["name"])
    normalization = result["normalization"]
    if not isinstance(normalization, str) or normalization not in _NORMALIZATIONS:
        raise WorkerProtocolError("worker result normalization is unsupported")
    if _SYSTEM_NORMALIZATION.get(system["name"]) != normalization:
        raise WorkerProtocolError(
            "worker result normalization does not match the selected system"
        )
    verdict = result["verdict"]
    if not isinstance(verdict, str) or verdict not in _VERDICTS:
        raise WorkerProtocolError("worker result verdict is unsupported")
    reasons = result["reason_codes"]
    if not isinstance(reasons, list) or len(reasons) > _MAX_OBSERVATIONS:
        raise WorkerProtocolError(
            "worker result reason_codes must be a bounded array"
        )
    normalized_reasons = [
        _reason_code(value, f"worker result reason_codes[{index}]")
        for index, value in enumerate(reasons)
    ]
    if normalized_reasons != sorted(set(normalized_reasons)):
        raise WorkerProtocolError(
            "worker result reason_codes must be sorted and unique"
        )
    if verdict == "ALLOW" and normalized_reasons:
        raise WorkerProtocolError("worker result ALLOW must not contain reason codes")
    if verdict != "ALLOW" and not normalized_reasons:
        raise WorkerProtocolError("worker result non-ALLOW requires a reason code")
    if execution["status"] == "error":
        expected_reason = f"ANALYZER_{execution['error_code']}"
        if verdict != "ERROR" or normalized_reasons != [expected_reason]:
            raise WorkerProtocolError(
                "worker result execution error does not derive its verdict"
            )
        if observations:
            raise WorkerProtocolError(
                "worker result execution error must not contain observations"
            )
    elif verdict == "ERROR":
        raise WorkerProtocolError(
            "worker result successful execution cannot declare ERROR"
        )


def verify_request_result_binding(request: object, result: object) -> None:
    """Verify that an unsigned result is bound to exactly one issued request."""

    validate_worker_request(request)
    validate_worker_result(result)
    expected_request_digest = canonical_request_digest(request)
    comparisons = {
        "job_id": (result["job_id"], request["job_id"]),
        "nonce": (result["nonce"], request["nonce"]),
        "request_digest": (result["request_digest"], expected_request_digest),
        "subject_manifest_digest": (
            result["subject_manifest_digest"],
            request["subject"]["manifest_digest"],
        ),
        "tree_digest": (result["tree_digest"], request["subject"]["tree_digest"]),
        "verified_subject_digest": (
            result["verified_subject_digest"],
            request["subject"]["tree_digest"],
        ),
        "system": (result["system"], request["system"]),
        "baseline_lock_digest": (
            result["baseline_lock_digest"],
            request["baseline"]["lock_digest"],
        ),
        "baseline_entry_digest": (
            result["baseline_entry_digest"],
            request["baseline"]["entry_digest"],
        ),
        "effective_config_digest": (
            result["effective_config_digest"],
            request["system"]["config_digest"],
        ),
    }
    for field, (actual, expected) in comparisons.items():
        if actual != expected:
            raise WorkerProtocolError(f"worker result changed request binding: {field}")


def _validate_files(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_FILES:
        raise WorkerProtocolError("subject manifest files must be a bounded array")
    files: list[dict[str, Any]] = []
    paths: set[str] = set()
    folded_paths: set[str] = set()
    total_bytes = 0
    for index, raw_entry in enumerate(value):
        label = f"subject manifest files[{index}]"
        entry = _exact_object(
            raw_entry,
            {"path", "size", "digest", "executable"},
            label,
        )
        path = _relative_path(entry["path"], f"{label}.path")
        if path in paths:
            raise WorkerProtocolError(f"duplicate subject manifest path: {path}")
        paths.add(path)
        folded = path.casefold()
        if folded in folded_paths:
            raise WorkerProtocolError(
                f"case-insensitive subject manifest path collision: {path}"
            )
        folded_paths.add(folded)
        size = entry["size"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= _MAX_FILE_BYTES
        ):
            raise WorkerProtocolError(f"{label}.size is outside the bounded range")
        total_bytes += size
        if total_bytes > _MAX_TOTAL_BYTES:
            raise WorkerProtocolError("subject manifest exceeds total byte limit")
        digest = _digest(entry["digest"], f"{label}.digest")
        if entry["executable"] is not False:
            raise WorkerProtocolError(f"{label}.executable must be false")
        files.append(
            {
                "path": path,
                "size": size,
                "digest": digest,
                "executable": False,
            }
        )
    if [entry["path"] for entry in files] != sorted(paths):
        raise WorkerProtocolError("subject manifest files must be sorted by path")
    return files


def _validate_system(value: object, label: str) -> dict[str, str]:
    system = _exact_object(
        value,
        {"name", "version", "implementation_digest", "config_digest"},
        label,
    )
    name = system["name"]
    if not isinstance(name, str) or _IDENTIFIER.fullmatch(name) is None:
        raise WorkerProtocolError(f"{label}.name is not a canonical identifier")
    pinned_identity = _SYSTEM_IDENTITY.get(name)
    if pinned_identity is None:
        raise WorkerProtocolError(f"{label}.name is not a pinned worker system")
    version = system["version"]
    if (
        not isinstance(version, str)
        or not version
        or version != version.strip()
        or "\r" in version
        or "\n" in version
        or len(version) > 256
        or any(
            unicodedata.category(character).startswith("C")
            for character in version
        )
    ):
        raise WorkerProtocolError(f"{label}.version is not canonical")
    if version != pinned_identity["version"]:
        raise WorkerProtocolError(f"{label}.version is not the pinned worker version")
    implementation_digest = _digest(
        system["implementation_digest"], f"{label}.implementation_digest"
    )
    if implementation_digest != pinned_identity["implementation_digest"]:
        raise WorkerProtocolError(
            f"{label}.implementation_digest is not the pinned worker image"
        )
    return {
        "name": name,
        "version": version,
        "implementation_digest": implementation_digest,
        "config_digest": _digest(system["config_digest"], f"{label}.config_digest"),
    }


def _validate_limits(value: object, label: str) -> None:
    limits = _exact_object(value, {"timeout_seconds", "output_bytes"}, label)
    timeout = limits["timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= _MAX_TIMEOUT_SECONDS
    ):
        raise WorkerProtocolError(f"{label}.timeout_seconds is outside the bounded range")
    output = limits["output_bytes"]
    if (
        isinstance(output, bool)
        or not isinstance(output, int)
        or not 1 <= output <= _MAX_OUTPUT_BYTES
    ):
        raise WorkerProtocolError(f"{label}.output_bytes is outside the bounded range")


def _validate_runner_receipts(value: object) -> None:
    receipts = _exact_object(value, {"pre", "post"}, "worker result runner_receipts")
    for phase in ("pre", "post"):
        receipt = _exact_object(
            receipts[phase],
            {
                "context_inspect_digest",
                "daemon_version_digest",
                "daemon_info_digest",
            },
            f"worker result runner_receipts.{phase}",
        )
        for field in (
            "context_inspect_digest",
            "daemon_version_digest",
            "daemon_info_digest",
        ):
            _digest(
                receipt[field],
                f"worker result runner_receipts.{phase}.{field}",
            )


def _validate_execution(value: object, system_name: str) -> dict[str, Any]:
    execution = _exact_object(
        value,
        {"status", "error_code", "returncode", "container_id"},
        "worker result execution",
    )
    status = execution["status"]
    if not isinstance(status, str) or status not in {"ok", "error"}:
        raise WorkerProtocolError("worker result execution status is unsupported")
    error_code = execution["error_code"]
    if status == "ok" and error_code is not None:
        raise WorkerProtocolError(
            "worker result successful execution has an error code"
        )
    if status == "error" and (
        not isinstance(error_code, str) or error_code not in _ERROR_CODES
    ):
        raise WorkerProtocolError(
            "worker result failed execution has an unsupported error code"
        )
    returncode = execution["returncode"]
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise WorkerProtocolError("worker result execution returncode is invalid")
    valid_vendor_exit = (
        system_name == "cisco-skill-scanner" and returncode == 0
    ) or (system_name == "skillspector" and returncode in {0, 1})
    if status == "ok" and not valid_vendor_exit:
        raise WorkerProtocolError(
            "worker result successful execution has an invalid vendor exit"
        )
    if status == "error":
        if error_code == "TIMEOUT" and returncode == 0:
            raise WorkerProtocolError(
                "worker result timeout has a successful container exit"
            )
        if error_code == "MALFORMED_VENDOR_REPORT" and not valid_vendor_exit:
            raise WorkerProtocolError(
                "worker result malformed report has an invalid vendor exit"
            )
        if error_code == "NONZERO_OR_INVALID_VENDOR_EXIT" and valid_vendor_exit:
            raise WorkerProtocolError(
                "worker result invalid vendor exit is inconsistent"
            )
    container_id = execution["container_id"]
    _hex(container_id, _CONTAINER_ID, "worker result execution container_id")
    return {
        "status": status,
        "error_code": error_code,
        "returncode": returncode,
        "container_id": container_id,
    }


def _exact_object(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WorkerProtocolError(f"{label} must be a JSON object")
    if set(value) != expected:
        raise WorkerProtocolError(f"{label} has missing or unknown fields")
    return value


def _relative_path(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_PATH_LENGTH
        or "\\" in value
        or "\0" in value
        or unicodedata.normalize("NFC", value) != value
        or any(
            unicodedata.category(character).startswith("C") for character in value
        )
    ):
        raise WorkerProtocolError(f"{label} is not a bounded relative POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise WorkerProtocolError(f"{label} escapes the subject workspace")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise WorkerProtocolError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise WorkerProtocolError(f"{label} is not canonical lowercase hex")
    return value


def _reason_code(value: object, label: str) -> str:
    if not isinstance(value, str) or _REASON_CODE.fullmatch(value) is None:
        raise WorkerProtocolError(f"{label} is not a canonical reason code")
    return value


def _digest_bytes(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"
