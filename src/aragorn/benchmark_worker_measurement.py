"""Signed protocol-v2 worker measurements and verifier-owned trust policy."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable

from .oci_worker_protocol import canonical_digest, canonical_json


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
_CHALLENGE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_HEX_PUBLIC_KEY = re.compile(r"[0-9a-f]{64}\Z")
_PAYLOAD_TYPE = "application/vnd.aragorn.benchmark-worker-measurement.v1+json"
_SCOPE = "aragorn/benchmark-worker-output/v2"
_ALGORITHM = "Ed25519"
_MAX_DOCUMENT_BYTES = 256 * 1024
_MAX_KEYS = 1024
_STATEMENT_KEYS = {
    "schema",
    "scope",
    "algorithm",
    "trust_domain",
    "worker_id",
    "key_id",
    "job_id",
    "verifier_challenge",
    "request_digest",
    "result_digest",
    "handoff_manifest_digest",
}
_ENVELOPE_KEYS = {"payloadType", "payload", "signatures"}
_SIGNATURE_KEYS = {"keyid", "sig"}
_TRUST_STORE_KEYS = {"schema", "trust_domain", "keys"}
_TRUST_KEY_KEYS = {
    "key_id",
    "algorithm",
    "public_key",
    "worker_id",
    "scopes",
    "status",
}


class WorkerMeasurementError(ValueError):
    """A signed worker measurement or its trust policy is invalid."""


@dataclass(frozen=True)
class VerifiedWorkerMeasurement:
    """Control-plane identities established by one trusted signature."""

    statement: dict[str, str]
    envelope_digest: str
    trust_store_digest: str


def generate_worker_signing_key(
    path: str | os.PathLike[str],
    *,
    worker_id: str,
) -> dict[str, Any]:
    """Create one exclusive private Ed25519 seed and return its public trust record."""

    _identifier(worker_id, "worker signing key worker_id")
    target = _protected_file_target(path, "worker signing key")
    private_key_type, encoding, private_format, public_format, no_encryption = (
        _cryptography_types()
    )
    private_key = private_key_type.generate()
    seed = private_key.private_bytes(
        encoding.Raw,
        private_format.Raw,
        no_encryption(),
    )
    descriptor = -1
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(seed)
            stream.flush()
            os.fchmod(stream.fileno(), 0o600)
            os.fsync(stream.fileno())
        _fsync_directory(target.parent)
    except OSError as exc:
        raise WorkerMeasurementError(
            f"cannot create worker signing key: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    public_key = private_key.public_key().public_bytes(
        encoding.Raw,
        public_format.Raw,
    )
    return _trust_key_record(public_key, worker_id=worker_id)


def build_worker_trust_store(
    *,
    trust_domain: str,
    keys: list[object],
) -> dict[str, Any]:
    """Build one canonical verifier-owned worker trust store."""

    document = {
        "schema": "aragorn/benchmark-worker-trust-store/v1",
        "trust_domain": trust_domain,
        "keys": keys,
    }
    validate_worker_trust_store(document)
    copied = _canonical_copy(document, "worker trust store")
    return copied


def validate_worker_trust_store(document: object) -> None:
    """Validate active/revoked Ed25519 worker keys without trusting the bundle."""

    store = _exact_object(document, _TRUST_STORE_KEYS, "worker trust store")
    if store["schema"] != "aragorn/benchmark-worker-trust-store/v1":
        raise WorkerMeasurementError("worker trust store schema is unsupported")
    _identifier(store["trust_domain"], "worker trust store trust_domain")
    keys = store["keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= _MAX_KEYS:
        raise WorkerMeasurementError(
            "worker trust store keys must be a bounded non-empty array"
        )
    key_ids: list[str] = []
    for index, raw_key in enumerate(keys):
        label = f"worker trust store keys[{index}]"
        key = _exact_object(raw_key, _TRUST_KEY_KEYS, label)
        if key["algorithm"] != _ALGORITHM:
            raise WorkerMeasurementError(f"{label}.algorithm is unsupported")
        public_key = _public_key(key["public_key"], f"{label}.public_key")
        expected_key_id = _key_id(public_key)
        if key["key_id"] != expected_key_id:
            raise WorkerMeasurementError(
                f"{label}.key_id does not match its public key"
            )
        _identifier(key["worker_id"], f"{label}.worker_id")
        scopes = key["scopes"]
        if (
            not isinstance(scopes, list)
            or not scopes
            or scopes != sorted(set(scopes))
            or any(scope != _SCOPE for scope in scopes)
        ):
            raise WorkerMeasurementError(
                f"{label}.scopes must be sorted, unique, and supported"
            )
        if key["status"] not in {"active", "revoked"}:
            raise WorkerMeasurementError(f"{label}.status is unsupported")
        key_ids.append(expected_key_id)
    if key_ids != sorted(key_ids) or len(key_ids) != len(set(key_ids)):
        raise WorkerMeasurementError(
            "worker trust store keys must be sorted and unique by key_id"
        )


def write_worker_trust_store(
    path: str | os.PathLike[str],
    document: object,
) -> str:
    """Publish a canonical trust store once into protected control state."""

    store = _canonical_copy(document, "worker trust store")
    validate_worker_trust_store(store)
    raw = canonical_json(store)
    target = _protected_file_target(path, "worker trust store")
    descriptor = -1
    try:
        descriptor = os.open(
            target,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o400,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        _fsync_directory(target.parent)
    except OSError as exc:
        raise WorkerMeasurementError(
            f"cannot publish worker trust store: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return canonical_digest(store)


def load_worker_trust_store(
    path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Load a stable, protected trust store that is never bundle-supplied."""

    raw = _read_protected_file(
        path,
        maximum=_MAX_DOCUMENT_BYTES,
        label="worker trust store",
    )
    store = _decode_canonical_object(raw, "worker trust store")
    validate_worker_trust_store(store)
    return store


def build_worker_measurement(
    *,
    trust_domain: str,
    worker_id: str,
    key_id: str,
    job_id: str,
    verifier_challenge: str,
    request_digest: str,
    result_digest: str,
    handoff_manifest_digest: str,
) -> dict[str, str]:
    """Build the only statement a protocol-v2 worker key may sign."""

    statement = {
        "schema": "aragorn/benchmark-worker-measurement/v1",
        "scope": _SCOPE,
        "algorithm": _ALGORITHM,
        "trust_domain": trust_domain,
        "worker_id": worker_id,
        "key_id": key_id,
        "job_id": job_id,
        "verifier_challenge": verifier_challenge,
        "request_digest": request_digest,
        "result_digest": result_digest,
        "handoff_manifest_digest": handoff_manifest_digest,
    }
    validate_worker_measurement(statement)
    return _canonical_copy(statement, "worker measurement")


def validate_worker_measurement(document: object) -> None:
    """Validate one exact signed-statement payload."""

    statement = _exact_object(document, _STATEMENT_KEYS, "worker measurement")
    if statement["schema"] != "aragorn/benchmark-worker-measurement/v1":
        raise WorkerMeasurementError("worker measurement schema is unsupported")
    if statement["scope"] != _SCOPE:
        raise WorkerMeasurementError("worker measurement scope is unsupported")
    if statement["algorithm"] != _ALGORITHM:
        raise WorkerMeasurementError("worker measurement algorithm is unsupported")
    _identifier(statement["trust_domain"], "worker measurement trust_domain")
    _identifier(statement["worker_id"], "worker measurement worker_id")
    _digest(statement["key_id"], "worker measurement key_id")
    _hex(statement["job_id"], _JOB_ID, "worker measurement job_id")
    _hex(
        statement["verifier_challenge"],
        _CHALLENGE,
        "worker measurement verifier_challenge",
    )
    for field in (
        "request_digest",
        "result_digest",
        "handoff_manifest_digest",
    ):
        _digest(statement[field], f"worker measurement {field}")


def sign_worker_measurement(
    statement: object,
    private_key_path: str | os.PathLike[str],
) -> bytes:
    """Return a canonical single-signature DSSE envelope."""

    frozen = _canonical_copy(statement, "worker measurement")
    validate_worker_measurement(frozen)
    seed = _read_private_seed(private_key_path)
    private_key_type, encoding, _private_format, public_format, _no_encryption = (
        _cryptography_types()
    )
    private_key = private_key_type.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding.Raw,
        public_format.Raw,
    )
    if frozen["key_id"] != _key_id(public_key):
        raise WorkerMeasurementError(
            "worker measurement key_id does not match the private key"
        )
    payload = canonical_json(frozen)
    signature = private_key.sign(_dsse_pae(_PAYLOAD_TYPE, payload))
    envelope = {
        "payloadType": _PAYLOAD_TYPE,
        "payload": _base64(payload),
        "signatures": [
            {
                "keyid": frozen["key_id"],
                "sig": _base64(signature),
            }
        ],
    }
    return canonical_json(envelope)


def verify_worker_measurement(
    envelope_bytes: bytes,
    trust_store: object,
    *,
    expected_worker_id: str,
    expected_job_id: str,
    expected_request_digest: str,
    expected_challenge: str,
) -> VerifiedWorkerMeasurement:
    """Verify DSSE, trust policy, and verifier-held request identities."""

    store = _canonical_copy(trust_store, "worker trust store")
    validate_worker_trust_store(store)
    _identifier(expected_worker_id, "expected worker_id")
    _hex(expected_job_id, _JOB_ID, "expected job_id")
    _digest(expected_request_digest, "expected request digest")
    _hex(expected_challenge, _CHALLENGE, "expected verifier challenge")

    envelope = _decode_canonical_object(
        envelope_bytes,
        "worker measurement envelope",
    )
    envelope = _exact_object(
        envelope,
        _ENVELOPE_KEYS,
        "worker measurement envelope",
    )
    if envelope["payloadType"] != _PAYLOAD_TYPE:
        raise WorkerMeasurementError(
            "worker measurement envelope payloadType is unsupported"
        )
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise WorkerMeasurementError(
            "worker measurement envelope requires exactly one signature"
        )
    signature = _exact_object(
        signatures[0],
        _SIGNATURE_KEYS,
        "worker measurement envelope signature",
    )
    payload = _decode_base64(
        envelope["payload"],
        "worker measurement envelope payload",
        maximum=_MAX_DOCUMENT_BYTES,
    )
    signature_bytes = _decode_base64(
        signature["sig"],
        "worker measurement envelope signature",
        expected=64,
    )
    statement = _decode_canonical_object(payload, "worker measurement")
    validate_worker_measurement(statement)
    if signature["keyid"] != statement["key_id"]:
        raise WorkerMeasurementError(
            "worker measurement signature keyid does not match its statement"
        )

    if statement["trust_domain"] != store["trust_domain"]:
        raise WorkerMeasurementError(
            "worker measurement does not match the trusted domain"
        )
    expected = {
        "worker_id": expected_worker_id,
        "job_id": expected_job_id,
        "request_digest": expected_request_digest,
        "verifier_challenge": expected_challenge,
    }
    for field, value in expected.items():
        if statement[field] != value:
            raise WorkerMeasurementError(
                f"worker measurement does not match the expected {field}"
            )

    key = next(
        (
            item
            for item in store["keys"]
            if item["key_id"] == statement["key_id"]
        ),
        None,
    )
    if key is None:
        raise WorkerMeasurementError("worker measurement key is not trusted")
    if key["status"] != "active":
        raise WorkerMeasurementError("worker measurement key is revoked")
    if key["worker_id"] != expected_worker_id:
        raise WorkerMeasurementError(
            "worker measurement key is not trusted for the expected worker"
        )
    if statement["scope"] not in key["scopes"]:
        raise WorkerMeasurementError(
            "worker measurement key is not trusted for this scope"
        )

    _private_key_type, _encoding, _private_format, _public_format, _no_encryption = (
        _cryptography_types()
    )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        Ed25519PublicKey.from_public_bytes(
            _public_key(key["public_key"], "trusted worker public key")
        ).verify(
            signature_bytes,
            _dsse_pae(_PAYLOAD_TYPE, payload),
        )
    except InvalidSignature as exc:
        raise WorkerMeasurementError(
            "worker measurement signature is invalid"
        ) from exc
    except ValueError as exc:
        raise WorkerMeasurementError(
            "trusted worker public key is invalid"
        ) from exc

    return VerifiedWorkerMeasurement(
        statement=dict(statement),
        envelope_digest=_bytes_digest(envelope_bytes),
        trust_store_digest=canonical_digest(store),
    )


def _trust_key_record(public_key: bytes, *, worker_id: str) -> dict[str, Any]:
    return {
        "key_id": _key_id(public_key),
        "algorithm": _ALGORITHM,
        "public_key": public_key.hex(),
        "worker_id": worker_id,
        "scopes": [_SCOPE],
        "status": "active",
    }


def _protected_file_target(
    path: str | os.PathLike[str],
    label: str,
) -> Path:
    target = Path(path)
    if not target.is_absolute():
        raise WorkerMeasurementError(f"{label} path must be absolute")
    try:
        parent = target.parent
        parent_stat = parent.lstat()
    except OSError as exc:
        raise WorkerMeasurementError(
            f"cannot inspect {label} parent: {exc}"
        ) from exc
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
    ):
        raise WorkerMeasurementError(
            f"{label} parent must be a private owned directory"
        )
    return target


def _read_private_seed(path: str | os.PathLike[str]) -> bytes:
    seed = _read_protected_file(
        path,
        maximum=32,
        label="worker signing key",
    )
    if len(seed) != 32:
        raise WorkerMeasurementError(
            "worker signing key must be a stable 32-byte Ed25519 seed"
        )
    return seed


def _read_protected_file(
    path: str | os.PathLike[str],
    *,
    maximum: int,
    label: str,
) -> bytes:
    target = _protected_file_target(path, label)
    descriptor = -1
    try:
        descriptor = os.open(
            target,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_nlink != 1
        ):
            raise WorkerMeasurementError(
                f"{label} must be a private owned single-link file"
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(content) > maximum
            or metadata.st_dev != after.st_dev
            or metadata.st_ino != after.st_ino
            or metadata.st_size != after.st_size
            or metadata.st_mtime_ns != after.st_mtime_ns
        ):
            raise WorkerMeasurementError(
                f"{label} must be a stable bounded file"
            )
        return content
    except WorkerMeasurementError:
        raise
    except OSError as exc:
        raise WorkerMeasurementError(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _cryptography_types() -> tuple[Any, Any, Any, Any, Callable[[], Any]]:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
    except ImportError as exc:
        raise WorkerMeasurementError(
            "signed worker measurements require the locked cryptography dependency"
        ) from exc
    return (
        Ed25519PrivateKey,
        Encoding,
        PrivateFormat,
        PublicFormat,
        NoEncryption,
    )


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("ascii")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _base64(content: bytes) -> str:
    return base64.b64encode(content).decode("ascii")


def _decode_base64(
    value: object,
    label: str,
    *,
    maximum: int | None = None,
    expected: int | None = None,
) -> bytes:
    if not isinstance(value, str) or len(value) > (_MAX_DOCUMENT_BYTES * 2):
        raise WorkerMeasurementError(f"{label} is not bounded canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise WorkerMeasurementError(f"{label} is not valid base64") from exc
    if _base64(decoded) != value:
        raise WorkerMeasurementError(f"{label} is not canonical base64")
    if maximum is not None and len(decoded) > maximum:
        raise WorkerMeasurementError(f"{label} exceeds its byte limit")
    if expected is not None and len(decoded) != expected:
        raise WorkerMeasurementError(f"{label} has the wrong byte length")
    return decoded


def _decode_canonical_object(raw: object, label: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > _MAX_DOCUMENT_BYTES:
        raise WorkerMeasurementError(f"{label} must be bounded bytes")
    try:
        document = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_number,
            parse_int=_reject_number,
            parse_constant=_reject_number,
        )
    except WorkerMeasurementError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise WorkerMeasurementError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise WorkerMeasurementError(f"{label} must be a JSON object")
    if canonical_json(document) != raw:
        raise WorkerMeasurementError(f"{label} must be canonical JSON")
    return document


def _canonical_copy(document: object, label: str) -> dict[str, Any]:
    try:
        raw = canonical_json(document)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise WorkerMeasurementError(f"{label} cannot be copied canonically") from exc
    copied = json.loads(raw)
    if not isinstance(copied, dict):
        raise WorkerMeasurementError(f"{label} must be a JSON object")
    return copied


def _exact_object(
    value: object,
    keys: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WorkerMeasurementError(f"{label} must be a JSON object")
    if set(value) != keys:
        raise WorkerMeasurementError(f"{label} fields are invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise WorkerMeasurementError(f"{label} is invalid")
    return value


def _hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise WorkerMeasurementError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise WorkerMeasurementError(f"{label} is invalid")
    return value


def _public_key(value: object, label: str) -> bytes:
    if not isinstance(value, str) or _HEX_PUBLIC_KEY.fullmatch(value) is None:
        raise WorkerMeasurementError(f"{label} is invalid")
    return bytes.fromhex(value)


def _key_id(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise WorkerMeasurementError("worker public key must be 32 bytes")
    return _bytes_digest(public_key)


def _bytes_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _fsync_directory(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.fsync(descriptor)
    except OSError as exc:
        raise WorkerMeasurementError(
            f"cannot synchronize worker signing key directory: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise WorkerMeasurementError(
                f"worker measurement JSON repeats key {key!r}"
            )
        document[key] = value
    return document


def _reject_number(value: str) -> Any:
    raise WorkerMeasurementError(
        f"worker measurement JSON number is not permitted: {value}"
    )
