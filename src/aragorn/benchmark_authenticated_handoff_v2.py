"""Replay-safe acceptance of signed protocol-v2 worker-output handoffs."""

from __future__ import annotations

from io import BytesIO
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from typing import Any

from .benchmark_handoff_v2 import HandoffError, import_handoff
from .benchmark_protocol_v2 import validate_worker_result_v2
from .benchmark_semantic_closure_v2 import (
    SemanticClosureError,
    verify_worker_output_evidence_cas_v2,
)
from .benchmark_worker_measurement import (
    WorkerMeasurementError,
    load_worker_trust_store,
    validate_worker_trust_store,
    verify_worker_measurement,
)
from .cas import CAS, CASError
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    canonical_json,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
_CHALLENGE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_RECORD_FILE = re.compile(r"[0-9a-f]{64}\.json\Z")
_MAX_RECORD_BYTES = 256 * 1024
_MAX_RECORDS = 200_000
_ISSUANCE_KEYS = {
    "schema",
    "trust_domain",
    "worker_id",
    "job_id",
    "request_digest",
    "verifier_challenge",
}
_RECEIPT_KEYS = {
    "schema",
    "assurance",
    "issuance_digest",
    "trust_store_digest",
    "envelope_digest",
    "key_id",
    "trust_domain",
    "worker_id",
    "job_id",
    "verifier_challenge",
    "request_digest",
    "result_digest",
    "handoff_manifest_digest",
}
_LEDGER_ENTRIES = {".lock", ".staging", "issuances", "receipts"}


class AuthenticatedHandoffError(ValueError):
    """A signed worker handoff could not be accepted into protected state."""


def issue_worker_measurement_challenge(
    ledger_root: str | os.PathLike[str],
    *,
    trust_domain: str,
    worker_id: str,
    job_id: str,
    request_digest: str,
    verifier_challenge: str | None = None,
) -> dict[str, str]:
    """Issue and durably retain one verifier-owned challenge binding."""

    challenge = (
        secrets.token_hex(32)
        if verifier_challenge is None
        else verifier_challenge
    )
    issuance = {
        "schema": "aragorn/benchmark-worker-measurement-issuance/v1",
        "trust_domain": trust_domain,
        "worker_id": worker_id,
        "job_id": job_id,
        "request_digest": request_digest,
        "verifier_challenge": challenge,
    }
    _validate_issuance(issuance)
    root = _prepare_ledger(ledger_root)
    raw = canonical_json(issuance)
    with _ledger_lock(root):
        receipt_path = root / "receipts" / f"{challenge}.json"
        if os.path.lexists(receipt_path):
            raise AuthenticatedHandoffError(
                "worker measurement challenge is already consumed"
            )
        destination = root / "issuances" / f"{challenge}.json"
        if os.path.lexists(destination):
            existing = _load_record(destination, "worker measurement issuance")
            _validate_issuance(existing)
            if existing == issuance:
                return issuance
            raise AuthenticatedHandoffError(
                "worker measurement challenge is already bound differently"
            )
        _publish_record(
            root,
            raw,
            destination_directory="issuances",
            filename=f"{challenge}.json",
        )
    return issuance


def collect_signed_worker_output(
    bundle: str | os.PathLike[str],
    destination_cas: CAS,
    envelope_bytes: bytes,
    *,
    trust_store_path: str | os.PathLike[str],
    ledger_root: str | os.PathLike[str],
    verifier_challenge: str,
) -> dict[str, str]:
    """Accept one authenticated output and atomically consume its challenge.

    The global verifier ledger lock intentionally remains held through import
    and deep evidence verification. Phase 0 favors one unambiguous acceptance
    boundary over concurrent throughput.
    """

    _hex(verifier_challenge, _CHALLENGE, "verifier challenge")
    if not isinstance(envelope_bytes, bytes) or len(envelope_bytes) > _MAX_RECORD_BYTES:
        raise AuthenticatedHandoffError(
            "worker measurement envelope must be bounded bytes"
        )
    root = _prepare_ledger(ledger_root)
    bundle_path = Path(bundle)
    trust_path = Path(trust_store_path)
    _require_separate_security_boundaries(
        root,
        trust_path,
        bundle_path,
        destination_cas.root,
    )

    with _ledger_lock(root):
        issuance_path = root / "issuances" / f"{verifier_challenge}.json"
        if not os.path.lexists(issuance_path):
            raise AuthenticatedHandoffError(
                "worker measurement challenge was not issued"
            )
        issuance = _load_record(
            issuance_path,
            "worker measurement issuance",
        )
        _validate_issuance(issuance)
        if issuance["verifier_challenge"] != verifier_challenge:
            raise AuthenticatedHandoffError(
                "worker measurement issuance filename is unbound"
            )
        issuance_digest = canonical_digest(issuance)

        receipt_path = root / "receipts" / f"{verifier_challenge}.json"
        if os.path.lexists(receipt_path):
            receipt = _load_record(
                receipt_path,
                "worker output acceptance receipt",
            )
            _validate_receipt(receipt)
            if (
                receipt["issuance_digest"] == issuance_digest
                and receipt["envelope_digest"] == _bytes_digest(envelope_bytes)
            ):
                return _verify_replay_receipt(
                    receipt,
                    issuance,
                    envelope_bytes,
                    destination_cas,
                )
            raise AuthenticatedHandoffError(
                "worker measurement challenge was consumed by another binding"
            )

        try:
            trust_store = load_worker_trust_store(trust_path)
            if trust_store["trust_domain"] != issuance["trust_domain"]:
                raise AuthenticatedHandoffError(
                    "worker trust store does not match the issued trust domain"
                )
            verified = verify_worker_measurement(
                envelope_bytes,
                trust_store,
                expected_worker_id=issuance["worker_id"],
                expected_job_id=issuance["job_id"],
                expected_request_digest=issuance["request_digest"],
                expected_challenge=issuance["verifier_challenge"],
            )
            statement = verified.statement
            with tempfile.TemporaryDirectory(
                prefix=".aragorn-authenticated-worker-output-",
                dir=destination_cas.root.parent,
            ) as temporary:
                quarantine = CAS(temporary)
                import_handoff(
                    bundle_path,
                    quarantine,
                    expected_manifest_digest=statement[
                        "handoff_manifest_digest"
                    ],
                    expected_kind="worker_output",
                    expected_root_digest=statement["result_digest"],
                    expected_request_digest=issuance["request_digest"],
                    expected_verifier_challenge=issuance[
                        "verifier_challenge"
                    ],
                )
                closure = verify_worker_output_evidence_cas_v2(
                    quarantine,
                    statement["result_digest"],
                    expected_request_digest=issuance["request_digest"],
                    expected_challenge=issuance["verifier_challenge"],
                )
                _require_signed_job_matches_result(
                    quarantine,
                    statement,
                )
                _promote_verified_acceptance_evidence(
                    quarantine,
                    destination_cas,
                    closure,
                    envelope_bytes=envelope_bytes,
                    envelope_digest=verified.envelope_digest,
                    trust_store_bytes=canonical_json(trust_store),
                    trust_store_digest=verified.trust_store_digest,
                    result_digest=statement["result_digest"],
                )
        except AuthenticatedHandoffError:
            raise
        except (
            CASError,
            HandoffError,
            OSError,
            SemanticClosureError,
            WorkerMeasurementError,
        ) as exc:
            raise AuthenticatedHandoffError(
                f"signed worker output was not accepted: {exc}"
            ) from exc

        receipt = _build_receipt(issuance, verified)
        _validate_receipt(receipt)
        _publish_record(
            root,
            canonical_json(receipt),
            destination_directory="receipts",
            filename=f"{verifier_challenge}.json",
        )
        return receipt


def _build_receipt(
    issuance: dict[str, str],
    verified: Any,
) -> dict[str, str]:
    statement = verified.statement
    return {
        "schema": "aragorn/benchmark-worker-output-acceptance/v1",
        "assurance": "software_key_signature_not_hardware_attested",
        "issuance_digest": canonical_digest(issuance),
        "trust_store_digest": verified.trust_store_digest,
        "envelope_digest": verified.envelope_digest,
        "key_id": statement["key_id"],
        "trust_domain": statement["trust_domain"],
        "worker_id": statement["worker_id"],
        "job_id": statement["job_id"],
        "verifier_challenge": statement["verifier_challenge"],
        "request_digest": statement["request_digest"],
        "result_digest": statement["result_digest"],
        "handoff_manifest_digest": statement["handoff_manifest_digest"],
    }


def _verify_replay_receipt(
    receipt: dict[str, str],
    issuance: dict[str, str],
    envelope_bytes: bytes,
    destination_cas: CAS,
) -> dict[str, str]:
    try:
        retained_envelope = destination_cas.read(
            receipt["envelope_digest"],
            max_bytes=_MAX_RECORD_BYTES,
        )
        if retained_envelope != envelope_bytes:
            raise AuthenticatedHandoffError(
                "retained worker measurement envelope changed"
            )
        retained_trust_store = destination_cas.read(
            receipt["trust_store_digest"],
            max_bytes=_MAX_RECORD_BYTES,
        )
        trust_store = _decode_canonical_object(
            retained_trust_store,
            "retained worker trust store",
        )
        validate_worker_trust_store(trust_store)
        verified = verify_worker_measurement(
            retained_envelope,
            trust_store,
            expected_worker_id=issuance["worker_id"],
            expected_job_id=issuance["job_id"],
            expected_request_digest=issuance["request_digest"],
            expected_challenge=issuance["verifier_challenge"],
        )
        expected_receipt = _build_receipt(issuance, verified)
        if receipt != expected_receipt:
            raise AuthenticatedHandoffError(
                "worker output acceptance receipt does not re-derive"
            )
        verify_worker_output_evidence_cas_v2(
            destination_cas,
            receipt["result_digest"],
            expected_request_digest=issuance["request_digest"],
            expected_challenge=issuance["verifier_challenge"],
        )
        _require_signed_job_matches_result(
            destination_cas,
            verified.statement,
        )
        return receipt
    except AuthenticatedHandoffError:
        raise
    except (
        CASError,
        SemanticClosureError,
        WorkerMeasurementError,
    ) as exc:
        raise AuthenticatedHandoffError(
            f"worker output acceptance receipt cannot be replayed: {exc}"
        ) from exc


def _require_signed_job_matches_result(
    cas: CAS,
    statement: dict[str, str],
) -> None:
    result_job_id = _worker_result_job_id(
        cas,
        statement["result_digest"],
    )
    if result_job_id != statement["job_id"]:
        raise AuthenticatedHandoffError(
            "signed worker job_id does not match the imported result"
        )


def _promote_verified_acceptance_evidence(
    quarantine: CAS,
    destination: CAS,
    closure: dict[str, int],
    *,
    envelope_bytes: bytes,
    envelope_digest: str,
    trust_store_bytes: bytes,
    trust_store_digest: str,
    result_digest: str,
) -> None:
    evidence = {
        envelope_digest: envelope_bytes,
        trust_store_digest: trust_store_bytes,
    }
    for digest, content in sorted(evidence.items()):
        _put_exact(destination, content, digest)
    for digest, size in sorted(closure.items()):
        if digest == result_digest:
            continue
        _put_exact(
            destination,
            quarantine.read(digest, max_bytes=size),
            digest,
        )
    result_size = closure.get(result_digest)
    if result_size is None:
        raise AuthenticatedHandoffError(
            "verified worker output closure omits its result root"
        )
    _put_exact(
        destination,
        quarantine.read(result_digest, max_bytes=result_size),
        result_digest,
    )


def _put_exact(cas: CAS, content: bytes, expected_digest: str) -> None:
    actual = cas.put(BytesIO(content), max_bytes=len(content))
    if actual != expected_digest:
        raise AuthenticatedHandoffError(
            "verified acceptance evidence changed during promotion"
        )


def _validate_issuance(document: object) -> None:
    issuance = _exact_object(
        document,
        _ISSUANCE_KEYS,
        "worker measurement issuance",
    )
    if issuance["schema"] != "aragorn/benchmark-worker-measurement-issuance/v1":
        raise AuthenticatedHandoffError(
            "worker measurement issuance schema is unsupported"
        )
    _identifier(issuance["trust_domain"], "worker measurement trust_domain")
    _identifier(issuance["worker_id"], "worker measurement worker_id")
    _hex(issuance["job_id"], _JOB_ID, "worker measurement job_id")
    _digest(issuance["request_digest"], "worker measurement request_digest")
    _hex(
        issuance["verifier_challenge"],
        _CHALLENGE,
        "worker measurement verifier_challenge",
    )


def _validate_receipt(document: object) -> None:
    receipt = _exact_object(
        document,
        _RECEIPT_KEYS,
        "worker output acceptance receipt",
    )
    if receipt["schema"] != "aragorn/benchmark-worker-output-acceptance/v1":
        raise AuthenticatedHandoffError(
            "worker output acceptance receipt schema is unsupported"
        )
    if receipt["assurance"] != "software_key_signature_not_hardware_attested":
        raise AuthenticatedHandoffError(
            "worker output acceptance receipt assurance is unsupported"
        )
    for field in (
        "issuance_digest",
        "trust_store_digest",
        "envelope_digest",
        "key_id",
        "request_digest",
        "result_digest",
        "handoff_manifest_digest",
    ):
        _digest(receipt[field], f"worker output acceptance {field}")
    _identifier(receipt["trust_domain"], "worker output acceptance trust_domain")
    _identifier(receipt["worker_id"], "worker output acceptance worker_id")
    _hex(receipt["job_id"], _JOB_ID, "worker output acceptance job_id")
    _hex(
        receipt["verifier_challenge"],
        _CHALLENGE,
        "worker output acceptance verifier_challenge",
    )


def _prepare_ledger(path: str | os.PathLike[str]) -> Path:
    root = Path(path)
    if not root.is_absolute():
        raise AuthenticatedHandoffError(
            "worker measurement ledger path must be absolute"
        )
    parent = root.parent
    _require_private_directory(parent, "worker measurement ledger parent")
    if not os.path.lexists(root):
        try:
            os.mkdir(root, 0o700)
            _fsync_directory(parent, "worker measurement ledger parent")
        except OSError as exc:
            raise AuthenticatedHandoffError(
                f"cannot create worker measurement ledger: {exc}"
            ) from exc
    _require_private_directory(root, "worker measurement ledger")
    for name in (".staging", "issuances", "receipts"):
        child = root / name
        if not os.path.lexists(child):
            try:
                os.mkdir(child, 0o700)
                _fsync_directory(root, "worker measurement ledger")
            except OSError as exc:
                raise AuthenticatedHandoffError(
                    f"cannot create worker measurement ledger {name}: {exc}"
                ) from exc
        _require_private_directory(
            child,
            f"worker measurement ledger {name}",
        )
    lock = root / ".lock"
    if not os.path.lexists(lock):
        descriptor = -1
        try:
            descriptor = os.open(
                lock,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            _fsync_directory(root, "worker measurement ledger")
        except FileExistsError:
            pass
        except OSError as exc:
            raise AuthenticatedHandoffError(
                f"cannot create worker measurement ledger lock: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    metadata = _lstat(lock, "worker measurement ledger lock")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_nlink != 1
    ):
        raise AuthenticatedHandoffError(
            "worker measurement ledger lock must be private and regular"
        )
    entries = _directory_names(root, "worker measurement ledger")
    if entries != _LEDGER_ENTRIES:
        raise AuthenticatedHandoffError(
            "worker measurement ledger has unknown entries"
        )
    for name in ("issuances", "receipts"):
        records = _directory_names(
            root / name,
            f"worker measurement ledger {name}",
        )
        if len(records) > _MAX_RECORDS or any(
            _RECORD_FILE.fullmatch(record) is None for record in records
        ):
            raise AuthenticatedHandoffError(
                f"worker measurement ledger {name} is invalid or over limit"
            )
    return root


class _ledger_lock:
    def __init__(self, root: Path) -> None:
        self._root = root
        self._path = root / ".lock"
        self._descriptor = -1

    def __enter__(self) -> None:
        try:
            self._descriptor = os.open(
                self._path,
                os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            )
            fcntl.flock(self._descriptor, fcntl.LOCK_EX)
            if _directory_names(
                self._root / ".staging",
                "worker measurement ledger staging",
            ):
                raise AuthenticatedHandoffError(
                    "worker measurement ledger has abandoned staging files"
                )
        except AuthenticatedHandoffError:
            if self._descriptor >= 0:
                try:
                    fcntl.flock(self._descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(self._descriptor)
                    self._descriptor = -1
            raise
        except OSError as exc:
            if self._descriptor >= 0:
                os.close(self._descriptor)
                self._descriptor = -1
            raise AuthenticatedHandoffError(
                f"cannot lock worker measurement ledger: {exc}"
            ) from exc

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._descriptor >= 0:
            try:
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._descriptor)
                self._descriptor = -1


def _publish_record(
    root: Path,
    content: bytes,
    *,
    destination_directory: str,
    filename: str,
) -> None:
    if (
        destination_directory not in {"issuances", "receipts"}
        or _RECORD_FILE.fullmatch(filename) is None
        or len(content) > _MAX_RECORD_BYTES
    ):
        raise AuthenticatedHandoffError(
            "worker measurement ledger record publication is invalid"
        )
    staging = root / ".staging"
    stage = staging / f"{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            stage,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o400,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        destination = root / destination_directory
        destination_fd = os.open(
            destination,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.link(
                stage,
                filename,
                dst_dir_fd=destination_fd,
                follow_symlinks=False,
            )
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
    except FileExistsError as exc:
        raise AuthenticatedHandoffError(
            "worker measurement ledger record already exists"
        ) from exc
    except OSError as exc:
        raise AuthenticatedHandoffError(
            f"cannot publish worker measurement ledger record: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(stage)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise AuthenticatedHandoffError(
                f"cannot remove staged worker measurement record: {exc}"
            ) from exc


def _load_record(path: Path, label: str) -> dict[str, Any]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_nlink != 1
        ):
            raise AuthenticatedHandoffError(
                f"{label} must be a protected immutable ledger record"
            )
        chunks: list[bytes] = []
        remaining = _MAX_RECORD_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) > _MAX_RECORD_BYTES
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise AuthenticatedHandoffError(f"{label} changed while read")
    except AuthenticatedHandoffError:
        raise
    except OSError as exc:
        raise AuthenticatedHandoffError(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return _decode_canonical_object(raw, label)


def _decode_canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except AuthenticatedHandoffError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AuthenticatedHandoffError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise AuthenticatedHandoffError(f"{label} must be a JSON object")
    if canonical_json(document) != raw:
        raise AuthenticatedHandoffError(f"{label} must be canonical JSON")
    return document


def _worker_result_job_id(cas: CAS, digest: str) -> str:
    try:
        raw = cas.read(digest, max_bytes=8 * 1024 * 1024)
        result = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_number,
        )
        validate_worker_result_v2(result)
        if canonical_json(result) != raw:
            raise AuthenticatedHandoffError(
                "imported worker result must be canonical JSON"
            )
        return result["job_id"]
    except AuthenticatedHandoffError:
        raise
    except (
        CASError,
        KeyError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        WorkerProtocolError,
    ) as exc:
        raise AuthenticatedHandoffError(
            f"cannot bind signed job to imported worker result: {exc}"
        ) from exc


def _require_separate_security_boundaries(
    ledger: Path,
    trust_store: Path,
    bundle: Path,
    destination_cas: Path,
) -> None:
    try:
        bundle_resolved = bundle.resolve(strict=True)
        ledger_resolved = ledger.resolve(strict=True)
        trust_resolved = trust_store.resolve(strict=True)
        destination_resolved = destination_cas.resolve(strict=True)
    except OSError as exc:
        raise AuthenticatedHandoffError(
            f"cannot resolve signed handoff paths: {exc}"
        ) from exc
    if (
        ledger_resolved == bundle_resolved
        or ledger_resolved.is_relative_to(bundle_resolved)
        or bundle_resolved.is_relative_to(ledger_resolved)
        or trust_resolved == bundle_resolved
        or trust_resolved.is_relative_to(bundle_resolved)
        or destination_resolved == ledger_resolved
        or destination_resolved.is_relative_to(ledger_resolved)
        or ledger_resolved.is_relative_to(destination_resolved)
        or destination_resolved == trust_resolved
        or trust_resolved.is_relative_to(destination_resolved)
        or destination_resolved == bundle_resolved
        or destination_resolved.is_relative_to(bundle_resolved)
        or bundle_resolved.is_relative_to(destination_resolved)
    ):
        raise AuthenticatedHandoffError(
            "worker bundle, verifier state, and destination CAS boundaries overlap"
        )


def _require_private_directory(path: Path, label: str) -> None:
    metadata = _lstat(path, label)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise AuthenticatedHandoffError(
            f"{label} must be a private owned directory"
        )


def _directory_names(path: Path, label: str) -> set[str]:
    try:
        with os.scandir(path) as entries:
            return {entry.name for entry in entries}
    except OSError as exc:
        raise AuthenticatedHandoffError(f"cannot inspect {label}: {exc}") from exc


def _fsync_directory(path: Path, label: str) -> None:
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
        raise AuthenticatedHandoffError(f"cannot synchronize {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise AuthenticatedHandoffError(f"cannot inspect {label}: {exc}") from exc


def _exact_object(
    value: object,
    keys: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AuthenticatedHandoffError(f"{label} fields are invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise AuthenticatedHandoffError(f"{label} is invalid")
    return value


def _hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AuthenticatedHandoffError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AuthenticatedHandoffError(f"{label} is invalid")
    return value


def _bytes_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise AuthenticatedHandoffError(
                f"worker measurement ledger JSON repeats key {key!r}"
            )
        document[key] = value
    return document


def _reject_number(value: str) -> Any:
    raise AuthenticatedHandoffError(
        f"non-finite worker measurement ledger number: {value}"
    )
