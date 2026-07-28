"""Retain and replay one analyzer subprocess result from exact CAS bytes."""

from __future__ import annotations

import hashlib
from io import BytesIO
import json
import math
import os
import re
from typing import Any

from .analyze import (
    MAX_ANALYZER_OUTPUT_BYTES,
    AnalyzerResult,
    Observation,
    _decode_analyzer_configuration,
    _parse_observations,
    _reject_duplicate_json_keys,
    _reject_json_constant,
)
from .cas import CAS, CASError
from .oci_worker_protocol import WorkerProtocolError, canonical_json


ANALYZER_RUN_VERIFIER = "aragorn/analyzer-run-verifier/v1"
_AUTHORITY = "EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_MAX_REQUEST_BYTES = 1024 * 1024
_MAX_RECEIPT_BYTES = 1024 * 1024
_MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_MAX_OBSERVATIONS = 10_000


class AnalyzerReceiptError(ValueError):
    """A retained analyzer run is malformed, incomplete, or inconsistent."""


def retain_analyzer_run(
    cas: CAS,
    result: AnalyzerResult,
    *,
    verifier_implementation_digest: str,
) -> str:
    """Retain one result and return its evidence-only receipt digest."""

    request = _request(result.raw_request)
    _result_matches_request(result, request)
    _validated_configuration(result.raw_configuration, request)
    verifier_digest = _digest(
        verifier_implementation_digest,
        "verifier implementation digest",
    )
    observations = _verified_observations(result, request["subject_digest"])
    try:
        cas.verify(
            request["analyzer"]["executable_digest"],
            max_bytes=_MAX_EXECUTABLE_BYTES,
        )
        cas.put_expected(
            BytesIO(result.raw_configuration),
            expected_digest=request["analyzer"]["config_digest"],
            max_bytes=_MAX_REQUEST_BYTES,
        )
        request_digest = _put(cas, result.raw_request, _MAX_REQUEST_BYTES)
        stdout_digest = _put(cas, result.raw_stdout, request["limits"]["output_bytes"])
        stderr_digest = _put(cas, result.raw_stderr, request["limits"]["output_bytes"])
        observation_digests = [
            _put(
                cas,
                observation.document_json.encode("ascii"),
                MAX_ANALYZER_OUTPUT_BYTES,
            )
            for observation in observations
        ]
        receipt = {
            "schema": "aragorn/analyzer-run-receipt/v1",
            "authority": _AUTHORITY,
            "verifier": {
                "name": ANALYZER_RUN_VERIFIER,
                "implementation_digest": verifier_digest,
            },
            "request_digest": request_digest,
            "stdout_digest": stdout_digest,
            "stderr_digest": stderr_digest,
            "observation_digests": observation_digests,
            "execution": {
                "status": result.status,
                "error_code": result.error_code,
                "error_message": result.error_message,
                "returncode": result.returncode,
            },
        }
        return _put(cas, canonical_json(receipt), _MAX_RECEIPT_BYTES)
    except (CASError, WorkerProtocolError) as exc:
        raise AnalyzerReceiptError(f"cannot retain analyzer run: {exc}") from exc


def verify_analyzer_run(
    cas: CAS,
    receipt_digest: str,
    *,
    expected_subject_digest: str | None = None,
    expected_verifier_digest: str,
) -> AnalyzerResult:
    """Replay internally consistent evidence without authenticating its producer.

    Installer authority additionally requires a broker-owned CAS and protected
    expected identities; a successful result from this function is not enough.
    """

    try:
        receipt = _canonical_document(
            cas.read(
                _digest(receipt_digest, "receipt digest"),
                max_bytes=_MAX_RECEIPT_BYTES,
            ),
            "analyzer receipt",
        )
        _exact_keys(
            receipt,
            {
                "schema",
                "authority",
                "verifier",
                "request_digest",
                "stdout_digest",
                "stderr_digest",
                "observation_digests",
                "execution",
            },
            "analyzer receipt",
        )
        if receipt["schema"] != "aragorn/analyzer-run-receipt/v1":
            raise AnalyzerReceiptError("analyzer receipt schema is unsupported")
        if receipt["authority"] != _AUTHORITY:
            raise AnalyzerReceiptError("analyzer receipt overstates its authority")
        verifier = receipt["verifier"]
        _exact_keys(
            verifier,
            {"name", "implementation_digest"},
            "analyzer receipt verifier",
        )
        if verifier["name"] != ANALYZER_RUN_VERIFIER:
            raise AnalyzerReceiptError("analyzer receipt verifier is unsupported")
        if _digest(
            verifier["implementation_digest"],
            "analyzer receipt verifier implementation digest",
        ) != _digest(expected_verifier_digest, "expected verifier digest"):
            raise AnalyzerReceiptError(
                "analyzer receipt verifier identity is untrusted"
            )

        request_raw = cas.read(
            _digest(receipt["request_digest"], "request digest"),
            max_bytes=_MAX_REQUEST_BYTES,
        )
        request = _request(request_raw)
        subject_digest = request["subject_digest"]
        if expected_subject_digest is not None and subject_digest != _digest(
            expected_subject_digest, "expected subject digest"
        ):
            raise AnalyzerReceiptError("analyzer request is bound to another subject")
        cas.verify(
            request["analyzer"]["executable_digest"],
            max_bytes=_MAX_EXECUTABLE_BYTES,
        )
        configuration_raw = cas.read(
            request["analyzer"]["config_digest"],
            max_bytes=_MAX_REQUEST_BYTES,
        )
        _validated_configuration(configuration_raw, request)

        limit = request["limits"]["output_bytes"]
        stdout = cas.read(
            _digest(receipt["stdout_digest"], "stdout digest"), max_bytes=limit
        )
        stderr = cas.read(
            _digest(receipt["stderr_digest"], "stderr digest"), max_bytes=limit
        )
        if len(stdout) + len(stderr) > limit:
            raise AnalyzerReceiptError("analyzer streams exceed the request limit")

        execution = receipt["execution"]
        _exact_keys(
            execution,
            {"status", "error_code", "error_message", "returncode"},
            "analyzer receipt execution",
        )
        status = execution["status"]
        error_code = execution["error_code"]
        error_message = execution["error_message"]
        returncode = execution["returncode"]
        observation_digests = _digest_list(receipt["observation_digests"])
        observations, parse_error = _parse_observations(stdout, subject_digest)
        if status == "ok":
            if (
                error_code is not None
                or error_message is not None
                or returncode != 0
                or parse_error is not None
            ):
                raise AnalyzerReceiptError(
                    "successful analyzer execution is inconsistent"
                )
            expected_bytes = [
                observation.document_json.encode("ascii")
                for observation in observations
            ]
            if observation_digests != [_raw_digest(raw) for raw in expected_bytes]:
                raise AnalyzerReceiptError("analyzer observations do not match stdout")
            for digest, raw in zip(observation_digests, expected_bytes, strict=True):
                if cas.read(digest, max_bytes=MAX_ANALYZER_OUTPUT_BYTES) != raw:
                    raise AnalyzerReceiptError(
                        "retained canonical observation bytes do not match stdout"
                    )
        elif status == "error":
            if (
                not isinstance(error_code, str)
                or _ERROR_CODE.fullmatch(error_code) is None
                or not isinstance(error_message, str)
                or not error_message
                or len(error_message) > 4096
                or observation_digests
                or (
                    returncode is not None
                    and (
                        isinstance(returncode, bool) or not isinstance(returncode, int)
                    )
                )
            ):
                raise AnalyzerReceiptError("failed analyzer execution is malformed")
            observations = ()
        else:
            raise AnalyzerReceiptError("analyzer execution status is unsupported")

        analyzer = request["analyzer"]
        return AnalyzerResult(
            name=analyzer["name"],
            version=analyzer["version"],
            config_digest=analyzer["config_digest"],
            executable_digest=analyzer["executable_digest"],
            status=status,
            observations=observations,
            error_code=error_code,
            error_message=error_message,
            raw_configuration=configuration_raw,
            raw_request=request_raw,
            raw_stdout=stdout,
            raw_stderr=stderr,
            stderr=stderr.decode("utf-8", errors="replace"),
            returncode=returncode,
        )
    except CASError as exc:
        raise AnalyzerReceiptError(
            f"cannot verify retained analyzer run: {exc}"
        ) from exc


def summarize_analyzer_run(
    result: AnalyzerResult,
    *,
    run_receipt_digest: str,
) -> dict[str, Any]:
    """Return the exact decision/v2 summary for one retained run."""

    record: dict[str, Any] = {
        "name": result.name,
        "version": result.version,
        "config_digest": result.config_digest,
        "executable_digest": result.executable_digest,
        "status": result.status,
        "run_receipt_digest": _digest(run_receipt_digest, "run receipt digest"),
        "observation_digests": [
            _raw_digest(observation.document_json.encode("ascii"))
            for observation in result.observations
        ],
        "stdout_digest": _raw_digest(result.raw_stdout),
        "stderr_digest": _raw_digest(result.raw_stderr),
    }
    if result.error_code is not None:
        record["error_code"] = result.error_code
    if result.returncode is not None:
        record["returncode"] = result.returncode
    return record


def _request(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_REQUEST_BYTES:
        raise AnalyzerReceiptError("analyzer request bytes are missing or oversized")
    if not raw.endswith(b"\n"):
        raise AnalyzerReceiptError("analyzer request is not canonical JSON Lines")
    request = _canonical_document(raw[:-1], "analyzer request")
    _exact_keys(
        request,
        {"schema", "workspace", "subject_digest", "analyzer", "limits"},
        "analyzer request",
    )
    if request["schema"] != "aragorn/analyzer-request/v1":
        raise AnalyzerReceiptError("analyzer request schema is unsupported")
    workspace = request["workspace"]
    if (
        not isinstance(workspace, str)
        or not workspace
        or "\0" in workspace
        or not os.path.isabs(workspace)
    ):
        raise AnalyzerReceiptError("analyzer request workspace is invalid")
    _digest(request["subject_digest"], "analyzer request subject digest")

    analyzer = request["analyzer"]
    _exact_keys(
        analyzer,
        {"name", "version", "config_digest", "executable_digest"},
        "analyzer request identity",
    )
    for field in ("name", "version"):
        value = analyzer[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise AnalyzerReceiptError(f"analyzer request {field} is invalid")
    _digest(analyzer["config_digest"], "analyzer request config digest")
    _digest(analyzer["executable_digest"], "analyzer request executable digest")

    limits = request["limits"]
    _exact_keys(limits, {"timeout_seconds", "output_bytes"}, "analyzer request limits")
    timeout = limits["timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise AnalyzerReceiptError("analyzer request timeout is invalid")
    output_bytes = limits["output_bytes"]
    if (
        isinstance(output_bytes, bool)
        or not isinstance(output_bytes, int)
        or not 1 <= output_bytes <= MAX_ANALYZER_OUTPUT_BYTES
    ):
        raise AnalyzerReceiptError("analyzer request output limit is invalid")
    return request


def _result_matches_request(result: AnalyzerResult, request: dict[str, Any]) -> None:
    analyzer = request["analyzer"]
    if (
        result.name,
        result.version,
        result.config_digest,
        result.executable_digest,
    ) != (
        analyzer["name"],
        analyzer["version"],
        analyzer["config_digest"],
        analyzer["executable_digest"],
    ):
        raise AnalyzerReceiptError(
            "analyzer result identity does not match its request"
        )
    if not isinstance(result.raw_stdout, bytes) or not isinstance(
        result.raw_stderr, bytes
    ):
        raise AnalyzerReceiptError("analyzer streams must be bytes")
    if (
        len(result.raw_stdout) + len(result.raw_stderr)
        > request["limits"]["output_bytes"]
    ):
        raise AnalyzerReceiptError("analyzer streams exceed the request limit")


def _verified_observations(
    result: AnalyzerResult, subject_digest: str
) -> tuple[Observation, ...]:
    observations, parse_error = _parse_observations(result.raw_stdout, subject_digest)
    if result.status == "ok":
        if (
            result.error_code is not None
            or result.returncode != 0
            or parse_error is not None
            or result.observations != observations
        ):
            raise AnalyzerReceiptError("successful analyzer result is inconsistent")
        return observations
    if (
        result.status != "error"
        or not isinstance(result.error_code, str)
        or _ERROR_CODE.fullmatch(result.error_code) is None
        or not isinstance(result.error_message, str)
        or not result.error_message
        or len(result.error_message) > 4096
        or result.observations
        or (
            result.returncode is not None
            and (
                isinstance(result.returncode, bool)
                or not isinstance(result.returncode, int)
            )
        )
    ):
        raise AnalyzerReceiptError("failed analyzer result is malformed")
    return ()


def _validated_configuration(raw: bytes, request: dict[str, Any]) -> dict[str, Any]:
    analyzer = request["analyzer"]
    try:
        configuration = _decode_analyzer_configuration(raw)
    except ValueError as exc:
        raise AnalyzerReceiptError(f"analyzer configuration is invalid: {exc}") from exc
    if {
        key: configuration[key] for key in ("name", "version", "executable_digest")
    } != {key: analyzer[key] for key in ("name", "version", "executable_digest")}:
        raise AnalyzerReceiptError(
            "analyzer configuration does not match the requested identity"
        )
    return configuration


def _canonical_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(document, dict) or canonical_json(document) != raw:
            raise AnalyzerReceiptError(f"{label} is not a canonical JSON object")
        return document
    except AnalyzerReceiptError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError, WorkerProtocolError) as exc:
        raise AnalyzerReceiptError(f"{label} is invalid: {exc}") from exc


def _exact_keys(document: object, expected: set[str], label: str) -> None:
    if not isinstance(document, dict) or set(document) != expected:
        raise AnalyzerReceiptError(f"{label} fields are invalid")


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AnalyzerReceiptError(f"{label} is invalid")
    return value


def _digest_list(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_OBSERVATIONS:
        raise AnalyzerReceiptError("analyzer observation digest list is invalid")
    return [_digest(item, "observation digest") for item in value]


def _put(cas: CAS, raw: bytes, max_bytes: int) -> str:
    if len(raw) > max_bytes:
        raise AnalyzerReceiptError("analyzer evidence exceeds its byte limit")
    return cas.put(BytesIO(raw), max_bytes=len(raw))


def _raw_digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"
