"""Portable, label-free contracts for protocol-v2 benchmark requests."""

from __future__ import annotations

import json
import math
import posixpath
import re
import secrets
import unicodedata
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    canonical_json,
    subject_manifest_digest,
    validate_subject_manifest,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
_CHALLENGE = re.compile(r"[0-9a-f]{64}\Z")
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_MAX_TEXT_LENGTH = 4096
_MAX_ENVIRONMENT_VALUE_LENGTH = 16 * 1024
_MAX_TIMEOUT_SECONDS = 3600.0
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_IMAGE_BYTES = 16 * 1024 * 1024 * 1024 * 1024
_MAX_RESOURCE_VALUE = 1024 * 1024 * 1024 * 1024 * 1024
_MAX_CPUS = 1024.0
_MAX_ENVIRONMENT = 256
_MAX_ENTRYPOINT = 32
_MAX_ARGUMENTS = 128
_MAX_OBSERVATIONS = 10_000
_ERROR_CODES = frozenset(
    {
        "MALFORMED_VENDOR_REPORT",
        "NONZERO_OR_INVALID_VENDOR_EXIT",
        "OUTPUT_LIMIT_EXCEEDED",
        "TIMEOUT",
    }
)
_VERDICTS = frozenset({"ALLOW", "REVIEW", "DENY", "ERROR"})

_POLICY_KEYS = {
    "schema",
    "system",
    "baseline",
    "image",
    "entrypoint",
    "arguments",
    "environment",
    "runtime_profile",
    "limits",
    "normalization",
}
_REQUEST_KEYS = {
    "schema",
    "job_id",
    "verifier_challenge",
    "subject",
    "portable_policy_digest",
    "system",
    "baseline",
    "limits",
}
_RESULT_KEYS = {
    "schema",
    "job_id",
    "verifier_challenge",
    "request_digest",
    "portable_policy_digest",
    "subject_manifest_digest",
    "tree_digest",
    "verified_subject_digest",
    "system",
    "baseline_lock_digest",
    "baseline_entry_digest",
    "effective_config_digest",
    "docker_executable_digest",
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
    "portable_policy_digest",
    "subject_manifest_digest",
    "tree_digest",
    "verified_subject_digest",
    "baseline_lock_digest",
    "baseline_entry_digest",
    "effective_config_digest",
    "docker_executable_digest",
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
_SYSTEM_IDENTITIES = {
    "cisco-skill-scanner": {
        "version": "2.0.12",
        "implementation_digest": (
            "sha256:7fadcfbe836eef9490feba0fadd2ada564c11eb541077e3efee5f61edbd2e65c"
        ),
        "normalizations": (
            "cisco-ai-skill-scanner-2.0.12/v1",
            "cisco-ai-skill-scanner-2.0.12/v2",
        ),
    },
    "skillspector": {
        "version": "2.4.3+git.a54947c",
        "implementation_digest": (
            "sha256:e731be01105243f94437a4b9bd449bd46bbcb5cb306f44b4845121d109a4a95e"
        ),
        "normalizations": (
            "nvidia-skillspector-2.4.3/v1",
            "nvidia-skillspector-2.4.3/v2",
        ),
    },
}
_FORBIDDEN_ENVIRONMENT_NAMES = {
    "attestation",
    "attested",
    "case_id",
    "class",
    "docker_config",
    "docker_context",
    "docker_host",
    "expected_verdict",
    "family",
    "host_path",
    "label",
    "labels",
    "lineage",
    "purpose",
    "run_id",
    "runner_identity",
    "runtime_identity",
    "signature",
    "source",
    "split",
    "suite_digest",
    "worker_assurance",
    "workspace_source",
}
_FORBIDDEN_PORTABLE_TEXT = (
    "unix://",
    "npipe://",
    "docker://",
    "/var/run/docker.sock",
    "/run/docker.sock",
)


def build_portable_policy(document: object) -> dict[str, Any]:
    """Return an independent canonical copy of one explicit portable policy."""

    validate_portable_policy(document)
    copied = json.loads(canonical_json(document))
    if not isinstance(copied, dict):  # pragma: no cover - guarded by validation
        raise WorkerProtocolError("portable policy must be a JSON object")
    return copied


def validate_portable_policy(document: object) -> None:
    """Validate an exact host-independent requested execution policy."""

    policy = _exact_object(document, _POLICY_KEYS, "portable policy")
    if policy["schema"] != "aragorn/benchmark-portable-policy/v1":
        raise WorkerProtocolError("portable policy schema is unsupported")

    system = _validate_system(policy["system"], "portable policy system")
    _validate_baseline(policy["baseline"], "portable policy baseline")
    image = _validate_image(policy["image"])
    if image["platform_manifest_digest"] != system["implementation_digest"]:
        raise WorkerProtocolError(
            "portable policy image does not match the pinned system implementation"
        )

    _validate_string_array(
        policy["entrypoint"],
        "portable policy entrypoint",
        maximum=_MAX_ENTRYPOINT,
    )
    arguments = _validate_string_array(
        policy["arguments"],
        "portable policy arguments",
        maximum=_MAX_ARGUMENTS,
    )
    if arguments.count("/workspace") != 1:
        raise WorkerProtocolError(
            "portable policy arguments must select /workspace exactly once"
        )
    _validate_environment(policy["environment"])
    _validate_runtime_profile(policy["runtime_profile"])
    _validate_limits(policy["limits"], "portable policy limits")

    normalization = policy["normalization"]
    if normalization not in system["normalizations"]:
        raise WorkerProtocolError(
            "portable policy normalization does not match the selected system"
        )


def portable_policy_digest(document: object) -> str:
    """Return the canonical digest of an exact portable requested policy."""

    validate_portable_policy(document)
    return canonical_digest(document)


def build_worker_request_v2(
    subject_manifest: object,
    portable_policy: object,
    *,
    verifier_challenge: str | None = None,
    token_hex: Callable[[int], str] | None = None,
) -> dict[str, Any]:
    """Build a fresh v2 request bound to an explicit portable policy."""

    validate_subject_manifest(subject_manifest)
    policy = build_portable_policy(portable_policy)
    generator = secrets.token_hex if token_hex is None else token_hex
    try:
        job_id = generator(16)
        challenge = generator(32) if verifier_challenge is None else verifier_challenge
    except Exception as exc:
        raise WorkerProtocolError(
            f"cannot generate worker request identity: {exc}"
        ) from exc

    request = {
        "schema": "aragorn/benchmark-worker-request/v2",
        "job_id": job_id,
        "verifier_challenge": challenge,
        "subject": {
            "manifest_digest": subject_manifest_digest(subject_manifest),
            "tree_digest": subject_manifest["tree_digest"],
        },
        "portable_policy_digest": portable_policy_digest(policy),
        "system": dict(policy["system"]),
        "baseline": dict(policy["baseline"]),
        "limits": dict(policy["limits"]),
    }
    validate_worker_request_v2(request)
    verify_request_policy_v2(request, policy)
    return request


def validate_worker_request_v2(document: object) -> None:
    """Validate only the exact label-free protocol-v2 request surface."""

    request = _exact_object(document, _REQUEST_KEYS, "worker request v2")
    if request["schema"] != "aragorn/benchmark-worker-request/v2":
        raise WorkerProtocolError("worker request v2 schema is unsupported")
    _hex(request["job_id"], _JOB_ID, "worker request v2 job_id")
    _hex(
        request["verifier_challenge"],
        _CHALLENGE,
        "worker request v2 verifier_challenge",
    )

    subject = _exact_object(
        request["subject"],
        {"manifest_digest", "tree_digest"},
        "worker request v2 subject",
    )
    _digest(subject["manifest_digest"], "worker request v2 subject manifest_digest")
    _digest(subject["tree_digest"], "worker request v2 subject tree_digest")
    _digest(
        request["portable_policy_digest"],
        "worker request v2 portable_policy_digest",
    )
    _validate_system(request["system"], "worker request v2 system")
    _validate_baseline(request["baseline"], "worker request v2 baseline")
    _validate_limits(request["limits"], "worker request v2 limits")


def canonical_request_digest_v2(document: object) -> str:
    """Return the canonical digest of an exact protocol-v2 worker request."""

    validate_worker_request_v2(document)
    return canonical_digest(document)


def verify_request_challenge_v2(
    request: object,
    expected_challenge: object,
) -> None:
    """Require the request to contain the verifier's exact fresh challenge."""

    validate_worker_request_v2(request)
    expected = _hex(
        expected_challenge,
        _CHALLENGE,
        "expected verifier challenge",
    )
    if request["verifier_challenge"] != expected:
        raise WorkerProtocolError("worker request verifier challenge is stale")


def verify_request_subject_v2(
    request: object,
    subject_manifest: object,
) -> None:
    """Verify that a v2 request selects exactly this sanitized subject."""

    validate_worker_request_v2(request)
    validate_subject_manifest(subject_manifest)
    if request["subject"]["manifest_digest"] != subject_manifest_digest(
        subject_manifest
    ):
        raise WorkerProtocolError("worker request v2 subject manifest digest changed")
    if request["subject"]["tree_digest"] != subject_manifest["tree_digest"]:
        raise WorkerProtocolError("worker request v2 subject tree digest changed")


def verify_request_policy_v2(
    request: object,
    portable_policy: object,
) -> None:
    """Verify the policy digest and every duplicated security-critical binding."""

    validate_worker_request_v2(request)
    validate_portable_policy(portable_policy)
    comparisons = {
        "portable_policy_digest": (
            request["portable_policy_digest"],
            portable_policy_digest(portable_policy),
        ),
        "system": (request["system"], portable_policy["system"]),
        "baseline": (request["baseline"], portable_policy["baseline"]),
        "limits": (request["limits"], portable_policy["limits"]),
    }
    for field, (actual, expected) in comparisons.items():
        if actual != expected:
            raise WorkerProtocolError(
                f"worker request v2 changed portable policy binding: {field}"
            )


def verify_request_bindings_v2(
    request: object,
    subject_manifest: object,
    portable_policy: object,
    *,
    expected_challenge: object,
) -> None:
    """Verify all externally supplied protocol-v2 request bindings."""

    verify_request_challenge_v2(request, expected_challenge)
    verify_request_subject_v2(request, subject_manifest)
    verify_request_policy_v2(request, portable_policy)


def validate_worker_result_v2(document: object) -> None:
    """Validate an unsigned result and its protocol-v2 internal invariants."""

    result = _exact_object(document, _RESULT_KEYS, "worker result v2")
    if result["schema"] != "aragorn/benchmark-worker-result/v2":
        raise WorkerProtocolError("worker result v2 schema is unsupported")
    _hex(result["job_id"], _JOB_ID, "worker result v2 job_id")
    _hex(
        result["verifier_challenge"],
        _CHALLENGE,
        "worker result v2 verifier_challenge",
    )
    for field in _RESULT_DIGEST_FIELDS:
        _digest(result[field], f"worker result v2 {field}")

    system = _validate_system(result["system"], "worker result v2 system")
    if result["verified_subject_digest"] != result["tree_digest"]:
        raise WorkerProtocolError(
            "worker result v2 verified subject does not match its tree digest"
        )
    if result["oci_platform_manifest_digest"] != system["implementation_digest"]:
        raise WorkerProtocolError(
            "worker result v2 platform manifest does not match the selected system"
        )
    _validate_runner_receipts(result["runner_receipts"])

    observations = result["observation_digests"]
    if not isinstance(observations, list) or len(observations) > _MAX_OBSERVATIONS:
        raise WorkerProtocolError(
            "worker result v2 observation_digests must be a bounded array"
        )
    normalized_observations = [
        _digest(value, f"worker result v2 observation_digests[{index}]")
        for index, value in enumerate(observations)
    ]
    if len(normalized_observations) != len(set(normalized_observations)):
        raise WorkerProtocolError(
            "worker result v2 observation_digests must be unique"
        )

    execution = _validate_execution(result["execution"], system["name"])
    normalization = result["normalization"]
    if normalization not in system["normalizations"]:
        raise WorkerProtocolError(
            "worker result v2 normalization does not match the selected system"
        )
    verdict = result["verdict"]
    if not isinstance(verdict, str) or verdict not in _VERDICTS:
        raise WorkerProtocolError("worker result v2 verdict is unsupported")
    reasons = result["reason_codes"]
    if not isinstance(reasons, list) or len(reasons) > _MAX_OBSERVATIONS:
        raise WorkerProtocolError(
            "worker result v2 reason_codes must be a bounded array"
        )
    normalized_reasons = [
        _reason_code(value, f"worker result v2 reason_codes[{index}]")
        for index, value in enumerate(reasons)
    ]
    if normalized_reasons != sorted(set(normalized_reasons)):
        raise WorkerProtocolError(
            "worker result v2 reason_codes must be sorted and unique"
        )
    if verdict == "ALLOW" and normalized_reasons:
        raise WorkerProtocolError(
            "worker result v2 ALLOW must not contain reason codes"
        )
    if verdict != "ALLOW" and not normalized_reasons:
        raise WorkerProtocolError("worker result v2 non-ALLOW requires a reason code")
    if execution["status"] == "error":
        expected_reason = f"ANALYZER_{execution['error_code']}"
        if verdict != "ERROR" or normalized_reasons != [expected_reason]:
            raise WorkerProtocolError(
                "worker result v2 execution error does not derive its verdict"
            )
        if normalized_observations:
            raise WorkerProtocolError(
                "worker result v2 execution error must not contain observations"
            )
    elif verdict == "ERROR":
        raise WorkerProtocolError(
            "worker result v2 successful execution cannot declare ERROR"
        )


def canonical_result_digest_v2(document: object) -> str:
    """Return the canonical digest of an exact protocol-v2 worker result."""

    validate_worker_result_v2(document)
    return canonical_digest(document)


def verify_request_result_binding_v2(
    request: object,
    portable_policy: object,
    result: object,
    *,
    expected_request_digest: object,
    expected_challenge: object,
) -> None:
    """Bind an unsigned result to one verifier-issued request and challenge."""

    verify_request_challenge_v2(request, expected_challenge)
    verify_request_policy_v2(request, portable_policy)
    validate_worker_result_v2(result)
    issued_request_digest = _digest(
        expected_request_digest,
        "expected worker request v2 digest",
    )
    actual_request_digest = canonical_request_digest_v2(request)
    if actual_request_digest != issued_request_digest:
        raise WorkerProtocolError(
            "worker request v2 does not match the verifier-issued request digest"
        )
    comparisons = {
        "job_id": (result["job_id"], request["job_id"]),
        "verifier_challenge": (
            result["verifier_challenge"],
            request["verifier_challenge"],
        ),
        "request_digest": (
            result["request_digest"],
            issued_request_digest,
        ),
        "portable_policy_digest": (
            result["portable_policy_digest"],
            portable_policy_digest(portable_policy),
        ),
        "subject_manifest_digest": (
            result["subject_manifest_digest"],
            request["subject"]["manifest_digest"],
        ),
        "tree_digest": (
            result["tree_digest"],
            request["subject"]["tree_digest"],
        ),
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
        "oci_index_digest": (
            result["oci_index_digest"],
            portable_policy["image"]["index_digest"],
        ),
        "oci_platform_manifest_digest": (
            result["oci_platform_manifest_digest"],
            portable_policy["image"]["platform_manifest_digest"],
        ),
        "build_provenance_manifest_digest": (
            result["build_provenance_manifest_digest"],
            portable_policy["image"]["build_provenance_manifest_digest"],
        ),
        "image_config_digest": (
            result["image_config_digest"],
            portable_policy["image"]["config_digest"],
        ),
        "normalization": (
            result["normalization"],
            portable_policy["normalization"],
        ),
    }
    for field, (actual, expected) in comparisons.items():
        if actual != expected:
            raise WorkerProtocolError(
                f"worker result v2 changed request binding: {field}"
            )


def verify_effective_config_policy_v2(
    portable_policy: object,
    effective_config: object,
    *,
    expected_config_digest: object,
    expected_docker_digest: object,
) -> None:
    """Reject host-effective configuration drift before analyzer execution."""

    validate_portable_policy(portable_policy)
    config_digest = _digest(
        expected_config_digest,
        "expected effective config v2 digest",
    )
    expected_docker = _digest(
        expected_docker_digest,
        "expected effective config v2 Docker digest",
    )
    config = _exact_object(
        effective_config,
        {
            "schema",
            "name",
            "version",
            "baseline_lock_digest",
            "baseline_entry_digest",
            "docker_executable_digest",
            "runner_identity",
            "image",
            "entrypoint",
            "arguments",
            "environment",
            "runtime_profile",
            "limits",
            "normalization",
        },
        "effective config v2",
    )
    if config["schema"] != "aragorn/benchmark-oci-system-config/v2":
        raise WorkerProtocolError("effective config v2 schema is unsupported")
    if canonical_digest(config) != config_digest:
        raise WorkerProtocolError(
            "effective config v2 digest does not match the expected bytes"
        )

    _validate_runner_identity(config["runner_identity"])
    docker_digest = _digest(
        config["docker_executable_digest"],
        "effective config v2 docker_executable_digest",
    )
    image = _exact_object(
        config["image"],
        {
            "reference",
            "index_digest",
            "platform_manifest_digest",
            "config_digest",
            "os",
            "architecture",
            "size_bytes",
        },
        "effective config v2 image",
    )
    reference = _canonical_text(
        image["reference"],
        "effective config v2 image.reference",
        maximum=1024,
    )
    for field in ("index_digest", "platform_manifest_digest", "config_digest"):
        _digest(image[field], f"effective config v2 image.{field}")
    if image["os"] != "linux":
        raise WorkerProtocolError("effective config v2 image.os is unsupported")
    if image["architecture"] not in {"arm64", "amd64"}:
        raise WorkerProtocolError(
            "effective config v2 image.architecture is unsupported"
        )
    _positive_int(
        image["size_bytes"],
        "effective config v2 image.size_bytes",
        maximum=_MAX_IMAGE_BYTES,
    )
    expected_reference_suffix = f"@{portable_policy['image']['index_digest']}"
    repository = reference[: -len(expected_reference_suffix)]
    if (
        reference.count("@") != 1
        or not reference.endswith(expected_reference_suffix)
        or not repository
        or repository.rfind(":") > repository.rfind("/")
    ):
        raise WorkerProtocolError(
            "effective config v2 image.reference is not the policy-bound "
            "digest-only image"
        )

    _validate_string_array(
        config["entrypoint"],
        "effective config v2 entrypoint",
        maximum=_MAX_ENTRYPOINT,
    )
    _validate_string_array(
        config["arguments"],
        "effective config v2 arguments",
        maximum=_MAX_ARGUMENTS,
    )
    _validate_environment(config["environment"])
    _validate_runtime_profile(config["runtime_profile"])
    _validate_limits(config["limits"], "effective config v2 limits")
    policy_environment = portable_policy["environment"]
    if any(
        config["environment"].get(name) != value
        for name, value in policy_environment.items()
    ):
        raise WorkerProtocolError(
            "effective config v2 changed portable policy binding: environment"
        )
    comparisons = {
        "name": (config["name"], portable_policy["system"]["name"]),
        "version": (config["version"], portable_policy["system"]["version"]),
        "baseline_lock_digest": (
            config["baseline_lock_digest"],
            portable_policy["baseline"]["lock_digest"],
        ),
        "baseline_entry_digest": (
            config["baseline_entry_digest"],
            portable_policy["baseline"]["entry_digest"],
        ),
        "docker_executable_digest": (
            docker_digest,
            expected_docker,
        ),
        "image": (
            {
                field: image[field]
                for field in (
                    "index_digest",
                    "platform_manifest_digest",
                    "config_digest",
                    "os",
                    "architecture",
                    "size_bytes",
                )
            },
            {
                field: portable_policy["image"][field]
                for field in (
                    "index_digest",
                    "platform_manifest_digest",
                    "config_digest",
                    "os",
                    "architecture",
                    "size_bytes",
                )
            },
        ),
        "entrypoint": (config["entrypoint"], portable_policy["entrypoint"]),
        "arguments": (config["arguments"], portable_policy["arguments"]),
        "runtime_profile": (
            config["runtime_profile"],
            portable_policy["runtime_profile"],
        ),
        "limits": (config["limits"], portable_policy["limits"]),
        "normalization": (
            config["normalization"],
            portable_policy["normalization"],
        ),
    }
    for field, (actual, expected) in comparisons.items():
        if actual != expected:
            raise WorkerProtocolError(
                f"effective config v2 changed portable policy binding: {field}"
            )


def verify_effective_environment_v2(
    image_environment: object,
    policy_environment: object,
    effective_environment: object,
) -> None:
    """Require the exact image environment plus portable policy overrides."""

    _validate_environment(image_environment)
    _validate_environment(policy_environment)
    _validate_environment(effective_environment)
    expected = {**image_environment, **policy_environment}
    if effective_environment != expected:
        raise WorkerProtocolError(
            "effective config v2 environment is not the exact image and "
            "portable policy merge"
        )


def verify_effective_config_binding_v2(
    portable_policy: object,
    result: object,
    effective_config: object,
) -> None:
    """Bind retained host-effective configuration to policy and result bytes."""

    validate_worker_result_v2(result)
    verify_effective_config_policy_v2(
        portable_policy,
        effective_config,
        expected_config_digest=result["effective_config_digest"],
        expected_docker_digest=result["docker_executable_digest"],
    )


def _validate_system(value: object, label: str) -> dict[str, Any]:
    system = _exact_object(
        value,
        {"name", "version", "implementation_digest"},
        label,
    )
    name = system["name"]
    if not isinstance(name, str) or _IDENTIFIER.fullmatch(name) is None:
        raise WorkerProtocolError(f"{label}.name is not a canonical identifier")
    expected = _SYSTEM_IDENTITIES.get(name)
    if expected is None:
        raise WorkerProtocolError(f"{label}.name is not a pinned worker system")
    version = _canonical_text(
        system["version"],
        f"{label}.version",
        maximum=256,
    )
    if version != expected["version"]:
        raise WorkerProtocolError(f"{label}.version is not the pinned worker version")
    implementation_digest = _digest(
        system["implementation_digest"],
        f"{label}.implementation_digest",
    )
    if implementation_digest != expected["implementation_digest"]:
        raise WorkerProtocolError(
            f"{label}.implementation_digest is not the pinned implementation"
        )
    return {
        "name": name,
        "version": version,
        "implementation_digest": implementation_digest,
        "normalizations": expected["normalizations"],
    }


def _validate_baseline(value: object, label: str) -> None:
    baseline = _exact_object(
        value,
        {"lock_digest", "entry_digest"},
        label,
    )
    _digest(baseline["lock_digest"], f"{label}.lock_digest")
    _digest(baseline["entry_digest"], f"{label}.entry_digest")


def _validate_image(value: object) -> dict[str, Any]:
    image = _exact_object(
        value,
        {
            "index_digest",
            "platform_manifest_digest",
            "config_digest",
            "build_provenance_manifest_digest",
            "os",
            "architecture",
            "size_bytes",
        },
        "portable policy image",
    )
    for field in (
        "index_digest",
        "platform_manifest_digest",
        "config_digest",
        "build_provenance_manifest_digest",
    ):
        _digest(image[field], f"portable policy image.{field}")
    if image["os"] != "linux":
        raise WorkerProtocolError("portable policy image.os is unsupported")
    if image["architecture"] not in {"arm64", "amd64"}:
        raise WorkerProtocolError("portable policy image.architecture is unsupported")
    _positive_int(
        image["size_bytes"],
        "portable policy image.size_bytes",
        maximum=_MAX_IMAGE_BYTES,
    )
    return image


def _validate_string_array(
    value: object,
    label: str,
    *,
    maximum: int,
) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise WorkerProtocolError(f"{label} must be a bounded non-empty array")
    return [
        _portable_text(item, f"{label}[{index}]") for index, item in enumerate(value)
    ]


def _validate_environment(value: object) -> None:
    if not isinstance(value, dict) or len(value) > _MAX_ENVIRONMENT:
        raise WorkerProtocolError(
            "portable policy environment must be a bounded object"
        )
    for raw_name, raw_value in value.items():
        if (
            not isinstance(raw_name, str)
            or _ENVIRONMENT_NAME.fullmatch(raw_name) is None
        ):
            raise WorkerProtocolError(
                "portable policy environment name is not canonical"
            )
        if raw_name.casefold() in _FORBIDDEN_ENVIRONMENT_NAMES:
            raise WorkerProtocolError(
                "portable policy environment contains forbidden metadata "
                "or runtime identity"
            )
        _portable_text(
            raw_value,
            f"portable policy environment.{raw_name}",
            maximum=_MAX_ENVIRONMENT_VALUE_LENGTH,
            allow_empty=True,
        )


def _validate_runtime_profile(value: object) -> None:
    runtime = _exact_object(
        value,
        {
            "engine",
            "pull",
            "network",
            "read_only_rootfs",
            "cap_drop",
            "no_new_privileges",
            "user",
            "workdir",
            "pids_limit",
            "memory_bytes",
            "memory_swap_bytes",
            "cpus",
            "nofile_soft",
            "nofile_hard",
            "tmpfs",
            "workspace",
        },
        "portable policy runtime_profile",
    )
    expected = {
        "engine": "docker",
        "pull": "never",
        "network": "none",
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "user": "65532:65532",
        "workdir": "/opt/aragorn-control",
    }
    for field, required in expected.items():
        if runtime[field] != required:
            raise WorkerProtocolError(
                f"portable policy runtime_profile.{field} weakens "
                "the required isolation policy"
            )

    for field in (
        "pids_limit",
        "memory_bytes",
        "memory_swap_bytes",
        "nofile_soft",
        "nofile_hard",
    ):
        _positive_int(
            runtime[field],
            f"portable policy runtime_profile.{field}",
            maximum=_MAX_RESOURCE_VALUE,
        )
    if runtime["memory_swap_bytes"] < runtime["memory_bytes"]:
        raise WorkerProtocolError(
            "portable policy runtime_profile.memory_swap_bytes is below memory_bytes"
        )
    if runtime["nofile_hard"] < runtime["nofile_soft"]:
        raise WorkerProtocolError(
            "portable policy runtime_profile.nofile_hard is below nofile_soft"
        )
    cpus = runtime["cpus"]
    if (
        isinstance(cpus, bool)
        or not isinstance(cpus, (int, float))
        or not math.isfinite(cpus)
        or not 0 < cpus <= _MAX_CPUS
    ):
        raise WorkerProtocolError(
            "portable policy runtime_profile.cpus is outside the bounded range"
        )

    tmpfs = _exact_object(
        runtime["tmpfs"],
        {"destination", "size_bytes", "options"},
        "portable policy runtime_profile.tmpfs",
    )
    if tmpfs["destination"] != "/tmp":
        raise WorkerProtocolError(
            "portable policy runtime_profile.tmpfs.destination is unsupported"
        )
    _positive_int(
        tmpfs["size_bytes"],
        "portable policy runtime_profile.tmpfs.size_bytes",
        maximum=_MAX_RESOURCE_VALUE,
    )
    if tmpfs["options"] != ["rw", "noexec", "nosuid", "nodev", "mode=1777"]:
        raise WorkerProtocolError(
            "portable policy runtime_profile.tmpfs.options weakens "
            "the required isolation policy"
        )

    workspace = _exact_object(
        runtime["workspace"],
        {"destination", "read_only"},
        "portable policy runtime_profile.workspace",
    )
    if workspace != {"destination": "/workspace", "read_only": True}:
        raise WorkerProtocolError(
            "portable policy runtime_profile.workspace weakens "
            "the required isolation policy"
        )


def _validate_limits(value: object, label: str) -> None:
    limits = _exact_object(value, {"timeout_seconds", "output_bytes"}, label)
    timeout = limits["timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= _MAX_TIMEOUT_SECONDS
    ):
        raise WorkerProtocolError(
            f"{label}.timeout_seconds is outside the bounded range"
        )
    _positive_int(
        limits["output_bytes"],
        f"{label}.output_bytes",
        maximum=_MAX_OUTPUT_BYTES,
    )


def _validate_runner_receipts(value: object) -> None:
    receipts = _exact_object(
        value,
        {"pre", "post"},
        "worker result v2 runner_receipts",
    )
    for phase in ("pre", "post"):
        receipt = _exact_object(
            receipts[phase],
            {
                "context_inspect_digest",
                "daemon_version_digest",
                "daemon_info_digest",
            },
            f"worker result v2 runner_receipts.{phase}",
        )
        for field in (
            "context_inspect_digest",
            "daemon_version_digest",
            "daemon_info_digest",
        ):
            _digest(
                receipt[field],
                f"worker result v2 runner_receipts.{phase}.{field}",
            )


def _validate_execution(value: object, system_name: str) -> dict[str, Any]:
    execution = _exact_object(
        value,
        {"status", "error_code", "returncode", "container_id"},
        "worker result v2 execution",
    )
    status = execution["status"]
    if not isinstance(status, str) or status not in {"ok", "error"}:
        raise WorkerProtocolError("worker result v2 execution status is unsupported")
    error_code = execution["error_code"]
    if status == "ok" and error_code is not None:
        raise WorkerProtocolError(
            "worker result v2 successful execution has an error code"
        )
    if status == "error" and (
        not isinstance(error_code, str) or error_code not in _ERROR_CODES
    ):
        raise WorkerProtocolError(
            "worker result v2 failed execution has an unsupported error code"
        )
    returncode = execution["returncode"]
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise WorkerProtocolError("worker result v2 execution returncode is invalid")
    valid_vendor_exit = (system_name == "cisco-skill-scanner" and returncode == 0) or (
        system_name == "skillspector" and returncode in {0, 1}
    )
    if status == "ok" and not valid_vendor_exit:
        raise WorkerProtocolError(
            "worker result v2 successful execution has an invalid vendor exit"
        )
    if status == "error":
        if error_code == "TIMEOUT" and returncode == 0:
            raise WorkerProtocolError(
                "worker result v2 timeout has a successful container exit"
            )
        if error_code == "MALFORMED_VENDOR_REPORT" and not valid_vendor_exit:
            raise WorkerProtocolError(
                "worker result v2 malformed report has an invalid vendor exit"
            )
        if error_code == "NONZERO_OR_INVALID_VENDOR_EXIT" and valid_vendor_exit:
            raise WorkerProtocolError(
                "worker result v2 invalid vendor exit is inconsistent"
            )
    container_id = _hex(
        execution["container_id"],
        _CONTAINER_ID,
        "worker result v2 execution container_id",
    )
    return {
        "status": status,
        "error_code": error_code,
        "returncode": returncode,
        "container_id": container_id,
    }


def _validate_runner_identity(value: object) -> None:
    label = "effective config v2 runner_identity"
    identity = _exact_object(
        value,
        {"assurance", "context", "engine", "worker_claim"},
        label,
    )
    if identity["assurance"] != "docker_daemon_self_report_not_attested":
        raise WorkerProtocolError(f"{label}.assurance is unsupported")

    context = _exact_object(
        identity["context"],
        {"name", "endpoint", "skip_tls_verify", "tls_material_count"},
        f"{label}.context",
    )
    _canonical_text(context["name"], f"{label}.context.name", maximum=4096)
    _canonical_unix_endpoint(context["endpoint"], f"{label}.context.endpoint")
    if context["skip_tls_verify"] is not False:
        raise WorkerProtocolError(f"{label}.context skips TLS verification")
    if (
        isinstance(context["tls_material_count"], bool)
        or not isinstance(context["tls_material_count"], int)
        or context["tls_material_count"] != 0
    ):
        raise WorkerProtocolError(f"{label}.context has TLS material")

    engine = _exact_object(
        identity["engine"],
        {
            "platform_name",
            "version",
            "api_version",
            "minimum_api_version",
            "git_commit",
            "go_version",
            "os",
            "architecture",
            "kernel_version",
            "build_time",
            "components",
        },
        f"{label}.engine",
    )
    for field in (
        "platform_name",
        "version",
        "api_version",
        "minimum_api_version",
        "git_commit",
        "go_version",
        "kernel_version",
        "build_time",
    ):
        _canonical_text(engine[field], f"{label}.engine.{field}", maximum=4096)
    if engine["os"] != "linux":
        raise WorkerProtocolError(f"{label}.engine.os is unsupported")
    if engine["architecture"] not in {"arm64", "amd64"}:
        raise WorkerProtocolError(f"{label}.engine.architecture is unsupported")
    components = engine["components"]
    if not isinstance(components, list) or not 3 <= len(components) <= 32:
        raise WorkerProtocolError(f"{label}.engine.components is invalid")
    names: list[str] = []
    folded_names: set[str] = set()
    normalized_components: list[dict[str, Any]] = []
    for index, value in enumerate(components):
        component_label = f"{label}.engine.components[{index}]"
        component = _exact_object(
            value,
            {"name", "version", "git_commit"},
            component_label,
        )
        name = _canonical_text(
            component["name"],
            f"{component_label}.name",
            maximum=4096,
        )
        folded = name.casefold()
        if folded in folded_names:
            raise WorkerProtocolError(f"{label}.engine.components is not canonical")
        folded_names.add(folded)
        names.append(name)
        _canonical_text(
            component["version"],
            f"{component_label}.version",
            maximum=4096,
        )
        _canonical_text(
            component["git_commit"],
            f"{component_label}.git_commit",
            maximum=4096,
        )
        normalized_components.append(component)
    if names != sorted(names) or not {"Engine", "containerd", "runc"}.issubset(names):
        raise WorkerProtocolError(f"{label}.engine.components is not canonical")
    engine_component = next(
        component
        for component in normalized_components
        if component["name"] == "Engine"
    )
    if (
        engine_component["version"] != engine["version"]
        or engine_component["git_commit"] != engine["git_commit"]
    ):
        raise WorkerProtocolError(f"{label}.engine Engine component is inconsistent")

    worker = _exact_object(
        identity["worker_claim"],
        {
            "daemon_id",
            "daemon_name",
            "server_version",
            "operating_system",
            "os",
            "architecture",
            "kernel_version",
            "security_options",
            "cgroup_version",
            "default_runtime",
            "storage_driver",
        },
        f"{label}.worker_claim",
    )
    for field in (
        "daemon_id",
        "daemon_name",
        "server_version",
        "operating_system",
        "kernel_version",
        "cgroup_version",
        "default_runtime",
        "storage_driver",
    ):
        _canonical_text(
            worker[field],
            f"{label}.worker_claim.{field}",
            maximum=4096,
        )
    if worker["os"] != "linux":
        raise WorkerProtocolError(f"{label}.worker_claim.os is unsupported")
    if worker["architecture"] not in {"arm64", "amd64"}:
        raise WorkerProtocolError(f"{label}.worker_claim.architecture is unsupported")
    security_options = worker["security_options"]
    if not isinstance(security_options, list) or len(security_options) > 64:
        raise WorkerProtocolError(f"{label}.worker_claim.security_options is invalid")
    for index, option in enumerate(security_options):
        _canonical_text(
            option,
            f"{label}.worker_claim.security_options[{index}]",
            maximum=4096,
        )
    if security_options != sorted(set(security_options)):
        raise WorkerProtocolError(
            f"{label}.worker_claim.security_options is not canonical"
        )
    if (
        worker["server_version"] != engine["version"]
        or worker["os"] != engine["os"]
        or worker["architecture"] != engine["architecture"]
        or worker["kernel_version"] != engine["kernel_version"]
    ):
        raise WorkerProtocolError(f"{label} daemon version and info are inconsistent")


def _canonical_unix_endpoint(value: object, label: str) -> str:
    endpoint = _canonical_text(value, label, maximum=4096)
    if "%" in endpoint or "\\" in endpoint:
        raise WorkerProtocolError(f"{label} must be a canonical absolute Unix endpoint")
    try:
        parsed = urlsplit(endpoint)
    except ValueError as exc:
        raise WorkerProtocolError(
            f"{label} must be a canonical absolute Unix endpoint"
        ) from exc
    path = parsed.path
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not path.startswith("/")
        or path == "/"
        or "//" in path
        or posixpath.normpath(path) != path
        or any(part in {".", ".."} for part in path.split("/"))
        or endpoint != f"unix://{path}"
    ):
        raise WorkerProtocolError(f"{label} must be a canonical absolute Unix endpoint")
    return endpoint


def _portable_text(
    value: object,
    label: str,
    *,
    maximum: int = _MAX_TEXT_LENGTH,
    allow_empty: bool = False,
) -> str:
    text = _canonical_text(
        value,
        label,
        maximum=maximum,
        allow_empty=allow_empty,
    )
    folded = text.casefold()
    if any(marker in folded for marker in _FORBIDDEN_PORTABLE_TEXT):
        raise WorkerProtocolError(f"{label} contains a Docker endpoint or host path")
    if re.search(r"(?:^|[=,:])(?:/Users/|[A-Za-z]:[\\/]|\\\\)", text):
        raise WorkerProtocolError(f"{label} contains an absolute host path")
    return text


def _canonical_text(
    value: object,
    label: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or len(value) > maximum
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise WorkerProtocolError(f"{label} is not bounded canonical text")
    return value


def _positive_int(value: object, label: str, *, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise WorkerProtocolError(f"{label} is outside the bounded range")
    return value


def _exact_object(
    value: object,
    expected: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WorkerProtocolError(f"{label} must be a JSON object")
    if set(value) != expected:
        raise WorkerProtocolError(f"{label} has missing or unknown fields")
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
