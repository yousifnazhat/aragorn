"""Internal Phase 1 coordinator evidence; never installer authority."""

from __future__ import annotations

import fcntl
import grp
import hashlib
import importlib.util
import inspect
import json
import os
import pwd
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import aragorn.analyzer_receipt as analyzer_receipt_module
import aragorn.github_recursive_artifact_graph_v6 as recursive_artifact_graph_v6

from .artifact_closure import load_verified_retained_manifest
from .cas import CAS
from .github_gateway import (
    QUARANTINE_AUTHORITY,
    build_gateway_request,
)
from .github_quarantine_receipt import verify_github_quarantine_receipt
from .github_recursive_gateway import (
    GitHubRecursiveGatewayError,
    quarantine_recursive_through_gateway,
    verify_retained_release_pin_set,
)
from .manifest_diff import diff_verified_manifests_between
from .oci_worker_protocol import canonical_digest, canonical_json
from .phase0_candidate import candidate_implementation_digest

INTENT_SCHEMA = "aragorn/protected-install-intent/v1"
PRODUCTION_SUBMISSION_SCHEMA = "aragorn/protected-install-submission/v1"
REQUEST_SCHEMA = "aragorn/protected-install-broker-request/v4"
STATE_SCHEMA_V1 = "aragorn/protected-install-coordinator-state/v1"
STATE_SCHEMA_V2 = "aragorn/protected-install-coordinator-state/v2"
STATE_SCHEMA = "aragorn/protected-install-coordinator-state/v3"
RESULT_SCHEMA = "aragorn/protected-install-coordinator-result/v1"
SUBMISSION_RESULT_SCHEMA = "aragorn/protected-install-submission-result/v1"
ASSURANCE = "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"

_INTENT_FIELDS = {
    "schema",
    "operation",
    "owner",
    "repository",
    "commit",
    "skill_path",
}
_EXPECTED_ACTIVE_V1_FIELDS = {
    "context_id",
    "manifest_digest",
    "source_request",
    "quarantine_receipt_digest",
    "gateway_profile_digest",
}
_EXPECTED_ACTIVE_FIELDS = _EXPECTED_ACTIVE_V1_FIELDS | {"recursive"}
_RECURSIVE_V3_FIELDS = {
    "root_manifest_digest",
    "expansion_digest",
    "expansion_proof_digest",
    "release_asset_result_digests",
}
_RECURSIVE_FIELDS = _RECURSIVE_V3_FIELDS | {"release_pin_set_digest"}
_STATE_FIELDS = {
    "schema",
    "assurance",
    "expected_active",
    "tree_digest",
    "version_path",
    "service_request_digest",
}
_IDENTITY_FIELDS = {"schema", "broker", "launcher", "package", "python"}
_RELEASE_SCHEMA = "aragorn/protected-broker-launch-identity/v1"
_TARGET = "aragorn-admitted"
_ANALYZER_USER = "aragorn-analyze"
_ANALYZER_GROUP = "aragorn-analyze"
_FETCH_USER = "aragorn-fetch"
_FETCH_GROUP = "aragorn-fetch"
_SERVICE_UNIT = "aragorn-protected-install.service"
_SYSTEMCTL = Path("/usr/bin/systemctl")
_INTENT_PATH = Path("/run/aragorn-protected-install/intent.json")
_SUBMISSION_LOCK_PATH = Path("/run/aragorn-protected-install/submission.lock")
_PRODUCTION_PATH_UNIT = "aragorn-protected-install-coordinator.path"
_NESTED_COORDINATION_MAX_SECONDS = 630
_PRODUCTION_SERVICE_TIMEOUT_SECONDS = 12 * 60
_SUBMISSION_TIMEOUT_SECONDS = 13 * 60
_MAX_INTENT_BYTES = 8 * 1024
_MAX_DOCUMENT_BYTES = 64 * 1024
_REQUEST_TTL_SECONDS = 15 * 60

if not (
    _NESTED_COORDINATION_MAX_SECONDS
    < _PRODUCTION_SERVICE_TIMEOUT_SECONDS
    < _SUBMISSION_TIMEOUT_SECONDS
):
    raise RuntimeError("protected install timeout margins are invalid")

# These are release-owned Phase 1 pins, not a claim that the current runtime
# conformance ledger passes. The coordinator removes caller control over them.
_TARGET_RUNTIME_DIGEST = (
    "sha256:475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c"
)
_RUNTIME_CONFORMANCE_DIGEST = (
    "sha256:a56a63860f62a48b51a2b37687f471cecdf1ad83619893a655200df79a290428"
)


class ProtectedInstallCoordinatorError(ValueError):
    """A protected transition could not be coordinated safely."""


class _ProtectedFileTooLarge(ProtectedInstallCoordinatorError):
    def __init__(
        self,
        message: str,
        token: tuple[tuple[int, ...], str],
    ) -> None:
        super().__init__(message)
        self.token = token


def coordinate_intent(
    intent_path: Path,
    *,
    release_identity_path: Path = Path(
        "/etc/aragorn/protected-broker-release.json"
    ),
    gateway_root: Path = Path("/var/lib/aragorn-gateway"),
    quarantine_root: Path = Path("/var/lib/aragorn-quarantine"),
    protected_root: Path = Path("/var/lib/aragorn-protected/skills"),
    request_path: Path = Path("/run/aragorn-protected-install/request.json"),
    state_path: Path = Path(
        "/var/lib/aragorn-protected/coordinator-active.json"
    ),
    release_asset_pins_path: Path | None = Path(
        "/etc/aragorn/github-release-asset-pins.json"
    ),
    expected_uid: int = 0,
    now_unix: int | None = None,
    expected_intent_digest: str | None = None,
) -> dict[str, Any]:
    """Acquire, bind, publish, and invoke one internal install/update intent."""

    if os.geteuid() != expected_uid:
        raise ProtectedInstallCoordinatorError(
            "coordinator effective UID is not its fixed broker UID"
        )
    intent = _load_intent(intent_path, expected_uid)
    if (
        expected_intent_digest is not None
        and canonical_digest(intent)
        != _require_digest(expected_intent_digest, "expected intent digest")
    ):
        raise ProtectedInstallCoordinatorError(
            "coordinator intent changed after submission"
        )
    source_request = build_gateway_request(
        intent["owner"],
        intent["repository"],
        intent["commit"],
        intent["skill_path"],
    )
    pins, release = _derive_release_pins(
        release_identity_path,
        expected_uid,
    )
    protected = _protected_directory(
        protected_root,
        expected_uid,
        "protected skill root",
    )
    quarantine_base = _protected_directory(
        quarantine_root,
        expected_uid,
        "quarantine root",
    )
    operation = intent["operation"]
    previous = _prepare_predecessor(
        operation,
        source_request,
        protected,
        quarantine_base,
        state_path,
        expected_uid,
    )
    quarantine = quarantine_base / canonical_digest(source_request)[7:]
    if os.path.lexists(quarantine):
        raise ProtectedInstallCoordinatorError(
            "source quarantine namespace is not fresh"
        )

    worker_uid, worker_gid = _service_identity(_FETCH_USER, _FETCH_GROUP)
    release_asset_pins = _load_release_asset_pins(
        release_asset_pins_path,
        expected_uid,
    )
    automatic_release_pin_preflight = release_asset_pins is None
    receipt = quarantine_recursive_through_gateway(
        source_request,
        gateway_root=gateway_root,
        quarantine_state=quarantine,
        worker_uid=worker_uid,
        worker_gid=worker_gid,
        python_executable=release["python_path"],
        package_root=release["package_root"] / "src",
        release_asset_pins=release_asset_pins,
    )
    replay = _verify_recursive_gateway_receipt(
        receipt,
        source_request,
        quarantine,
        require_release_pin_set=automatic_release_pin_preflight,
    )
    recursive = replay["recursive"]
    pins["expected_artifact_graph_verifier_digest"] = (
        _recursive_artifact_graph_verifier_digest(
            CAS(quarantine, read_only=True),
            recursive["release_asset_result_digests"],
        )
    )
    transition = _transition_fields(
        operation,
        previous,
        quarantine,
        receipt.manifest_digest,
    )
    clock = int(time.time()) if now_unix is None else now_unix
    if isinstance(clock, bool) or not isinstance(clock, int) or clock < 0:
        raise ProtectedInstallCoordinatorError(
            "coordinator clock is invalid"
        )
    context_id = "sha256:" + hashlib.sha256(
        secrets.token_bytes(32)
    ).hexdigest()
    request = {
        "schema": REQUEST_SCHEMA,
        "expires_at_unix": clock + _REQUEST_TTL_SECONDS,
        "operation": operation,
        "expected_active": transition["expected_active"],
        "expected_manifest_diff_digest": transition[
            "expected_manifest_diff_digest"
        ],
        "target_runtime_digest": _TARGET_RUNTIME_DIGEST,
        "runtime_conformance_digest": _RUNTIME_CONFORMANCE_DIGEST,
        "manifest_digest": receipt.manifest_digest,
        "quarantine_receipt_digest": receipt.quarantine_receipt_digest,
        "gateway_profile_digest": receipt.gateway_profile_digest,
        "context_id": context_id,
        "source_request": source_request,
        "recursive": recursive,
        **pins,
    }
    raw_request = canonical_json(request)
    request_digest = _digest(raw_request)
    _atomic_publish(request_path, raw_request, expected_uid)
    try:
        _start_fixed_service()
        transaction = _verify_active_transaction(
            protected,
            context_id=context_id,
            manifest_digest=receipt.manifest_digest,
            tree_digest=replay["tree_digest"],
            operation=operation,
            expected_active=transition["context_expected_active"],
            expected_uid=expected_uid,
        )
        _verify_recursive_gateway_receipt(
            receipt,
            source_request,
            quarantine,
            require_release_pin_set=automatic_release_pin_preflight,
        )
        active = {
            "context_id": context_id,
            "manifest_digest": receipt.manifest_digest,
            "source_request": source_request,
            "quarantine_receipt_digest": receipt.quarantine_receipt_digest,
            "gateway_profile_digest": receipt.gateway_profile_digest,
            "recursive": recursive,
        }
        state = {
            "schema": STATE_SCHEMA,
            "assurance": ASSURANCE,
            "expected_active": active,
            "tree_digest": replay["tree_digest"],
            "version_path": transaction["version_path"],
            "service_request_digest": request_digest,
        }
        _atomic_publish(state_path, canonical_json(state), expected_uid)
    finally:
        _remove_request(request_path)

    return {
        "schema": RESULT_SCHEMA,
        "assurance": ASSURANCE,
        "operation": operation,
        "source_request": source_request,
        "manifest_digest": receipt.manifest_digest,
        "quarantine_receipt_digest": receipt.quarantine_receipt_digest,
        "gateway_profile_digest": receipt.gateway_profile_digest,
        "context_id": context_id,
        "service_request_digest": request_digest,
        "installer_work_eligible": False,
        "runtime_conformance_qualified": False,
        "quarantine_authority": replay["receipt"]["authority"],
    }


def submit_intent(
    operation: str,
    owner: str,
    repository: str,
    commit: str,
    skill_path: str,
    *,
    intent_path: Path = _INTENT_PATH,
    lock_path: Path = _SUBMISSION_LOCK_PATH,
    expected_uid: int = 0,
    timeout_seconds: float = _SUBMISSION_TIMEOUT_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Submit one release-owned install/update intent and await its result."""

    if os.geteuid() != expected_uid:
        raise ProtectedInstallCoordinatorError(
            "protected install submission requires its fixed root UID"
        )
    if operation not in {"install", "update"}:
        raise ProtectedInstallCoordinatorError(
            "protected install operation must be install or update"
        )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= _SUBMISSION_TIMEOUT_SECONDS
    ):
        raise ProtectedInstallCoordinatorError(
            "protected install submission timeout is invalid"
        )
    intent = _build_intent(
        operation,
        owner,
        repository,
        commit,
        skill_path,
    )
    submission_id = _new_submission_id()
    submission = {
        "schema": PRODUCTION_SUBMISSION_SCHEMA,
        "submission_id": submission_id,
        "intent": intent,
    }
    raw_submission = canonical_json(submission)
    submission_digest = _digest(raw_submission)
    intent_digest = canonical_digest(intent)
    result_path = _submission_result_path(intent_path.parent, submission_id)
    lock_descriptor = _open_submission_lock(lock_path, expected_uid)
    intent_token = None
    published = False
    try:
        _require_production_path()
        if os.path.lexists(intent_path) or os.path.lexists(result_path):
            raise ProtectedInstallCoordinatorError(
                "protected install submission namespace is occupied"
            )
        intent_token = _atomic_publish(
            intent_path,
            raw_submission,
            expected_uid,
            replace=False,
        )
        published = True
        return _wait_for_submission_result(
            result_path,
            submission_id,
            submission_digest,
            intent_digest,
            expected_uid=expected_uid,
            deadline=monotonic() + timeout_seconds,
            monotonic=monotonic,
            sleep=sleep,
        )
    finally:
        if intent_token is not None:
            _unlink_matching(intent_path, intent_token, expected_uid)
        if published:
            _unlink_current_file(result_path, expected_uid)
        os.close(lock_descriptor)


def _open_submission_lock(path: Path, expected_uid: int) -> int:
    parent = _protected_directory(
        path.parent,
        expected_uid,
        "protected install submission directory",
    )
    if parent / path.name != path:
        raise ProtectedInstallCoordinatorError(
            "protected install submission lock path is not canonical"
        )
    descriptor = os.open(
        path,
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ProtectedInstallCoordinatorError(
                "protected install submission lock is unsafe"
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProtectedInstallCoordinatorError(
                "another protected install submission is active"
            ) from exc
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _require_production_path() -> None:
    _require_root_executable(_SYSTEMCTL)
    try:
        result = subprocess.run(
            (
                str(_SYSTEMCTL),
                "--no-ask-password",
                "is-active",
                "--quiet",
                _PRODUCTION_PATH_UNIT,
            ),
            check=False,
            cwd="/",
            env={
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProtectedInstallCoordinatorError(
            f"cannot inspect protected install ingress: {exc}"
        ) from exc
    if result.returncode != 0:
        raise ProtectedInstallCoordinatorError(
            "protected install ingress path is not active"
        )


def _wait_for_submission_result(
    path: Path,
    submission_id: str,
    submission_digest: str,
    intent_digest: str,
    *,
    expected_uid: int,
    deadline: float,
    monotonic: Callable[[], float],
    sleep: Callable[[float], None],
) -> dict[str, Any]:
    while not os.path.lexists(path):
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ProtectedInstallCoordinatorError(
                "protected install submission timed out"
            )
        sleep(min(0.1, remaining))
    token = None
    try:
        try:
            raw, token = _read_protected_bytes(
                path,
                max_bytes=_MAX_DOCUMENT_BYTES,
                expected_uid=expected_uid,
                exact_mode=0o400,
                label="protected install submission result",
            )
        except _ProtectedFileTooLarge as exc:
            token = exc.token
            raise
        document = _parse_canonical_document(
            raw,
            "protected install submission result",
        )
        if (
            set(document)
            != {
                "schema",
                "submission_id",
                "submission_digest",
                "intent_digest",
                "coordinator_result",
            }
            or document.get("schema") != SUBMISSION_RESULT_SCHEMA
            or document.get("submission_id") != submission_id
            or document.get("submission_digest") != submission_digest
            or document.get("intent_digest") != intent_digest
        ):
            raise ProtectedInstallCoordinatorError(
                "protected install submission result is not correlated"
            )
        return _validate_coordinator_result(document["coordinator_result"])
    finally:
        if token is not None:
            _unlink_matching(path, token, expected_uid)


def _build_intent(
    operation: str,
    owner: str,
    repository: str,
    commit: str,
    skill_path: str,
) -> dict[str, str]:
    source_request = build_gateway_request(
        owner,
        repository,
        commit,
        skill_path,
    )
    source_request.pop("schema")
    return {
        "schema": INTENT_SCHEMA,
        "operation": operation,
        **source_request,
    }


def _submission_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProtectedInstallCoordinatorError(
            "protected install submission ID is invalid"
        )
    return value


def _new_submission_id() -> str:
    return _submission_id(secrets.token_hex(32))


def _submission_result_path(parent: Path, submission_id: str) -> Path:
    return parent / f"submission-result-{_submission_id(submission_id)}.json"


def _derived_intent_path(parent: Path, submission_id: str) -> Path:
    return parent / f".coordinator-intent-{_submission_id(submission_id)}.json"


def _validate_production_submission(
    document: dict[str, Any],
) -> tuple[str, dict[str, str]]:
    if (
        set(document) != {"schema", "submission_id", "intent"}
        or document.get("schema") != PRODUCTION_SUBMISSION_SCHEMA
    ):
        raise ProtectedInstallCoordinatorError(
            "protected install submission is invalid"
        )
    return (
        _submission_id(document["submission_id"]),
        _validate_intent(document["intent"]),
    )


def _validate_coordinator_result(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtectedInstallCoordinatorError(
            "protected install submission result is invalid"
        )
    common = (
        value.get("schema") == RESULT_SCHEMA
        and value.get("assurance") == ASSURANCE
        and value.get("installer_work_eligible") is False
        and value.get("runtime_conformance_qualified") is False
    )
    if value.get("status") == "ERROR":
        error = value.get("error")
        if (
            not common
            or set(value)
            != {
                "schema",
                "assurance",
                "status",
                "error",
                "installer_work_eligible",
                "runtime_conformance_qualified",
            }
            or not isinstance(error, dict)
            or set(error) != {"type", "message"}
            or not isinstance(error.get("type"), str)
            or not error["type"]
            or not isinstance(error.get("message"), str)
            or not error["message"]
        ):
            raise ProtectedInstallCoordinatorError(
                "protected install submission error result is invalid"
            )
        return value
    success_fields = {
        "schema",
        "assurance",
        "operation",
        "source_request",
        "manifest_digest",
        "quarantine_receipt_digest",
        "gateway_profile_digest",
        "context_id",
        "service_request_digest",
        "installer_work_eligible",
        "runtime_conformance_qualified",
        "quarantine_authority",
        "status",
    }
    source = value.get("source_request")
    try:
        if not isinstance(source, dict):
            raise ProtectedInstallCoordinatorError(
                "submission result source request is invalid"
            )
        expected_source = build_gateway_request(
            source.get("owner"),
            source.get("repository"),
            source.get("commit"),
            source.get("skill_path"),
        )
        for field in (
            "manifest_digest",
            "quarantine_receipt_digest",
            "gateway_profile_digest",
            "context_id",
            "service_request_digest",
        ):
            _require_digest(value.get(field), f"submission result {field}")
    except (ProtectedInstallCoordinatorError, ValueError) as exc:
        raise ProtectedInstallCoordinatorError(
            "protected install submission success result is invalid"
        ) from exc
    if (
        not common
        or set(value) != success_fields
        or value.get("status") != "COMPLETED_NOT_INSTALLER_AUTHORITY"
        or value.get("operation") not in {"install", "update"}
        or source != expected_source
        or value.get("quarantine_authority") != QUARANTINE_AUTHORITY
    ):
        raise ProtectedInstallCoordinatorError(
            "protected install submission success result is invalid"
        )
    return value


def _load_intent(path: Path, expected_uid: int) -> dict[str, str]:
    document, token = _read_canonical_document_snapshot(
        path,
        max_bytes=_MAX_INTENT_BYTES,
        expected_uid=expected_uid,
        exact_mode=0o400,
        label="coordinator intent",
    )
    intent = _validate_intent(document)
    if not _unlink_matching(path, token, expected_uid):
        raise ProtectedInstallCoordinatorError(
            "coordinator intent changed before consumption"
        )
    return intent


def _validate_intent(document: object) -> dict[str, str]:
    if (
        not isinstance(document, dict)
        or set(document) != _INTENT_FIELDS
        or document.get("schema") != INTENT_SCHEMA
        or document.get("operation") not in {"install", "update"}
    ):
        raise ProtectedInstallCoordinatorError(
            "coordinator intent must be one exact high-level request"
        )
    expected = {
        "schema": INTENT_SCHEMA,
        "operation": document["operation"],
        **build_gateway_request(
            document.get("owner"),
            document.get("repository"),
            document.get("commit"),
            document.get("skill_path"),
        ),
    }
    expected.pop("schema", None)
    expected["schema"] = INTENT_SCHEMA
    if document != expected:
        raise ProtectedInstallCoordinatorError(
            "coordinator intent is not canonical"
        )
    return document


def _derive_release_pins(
    identity_path: Path,
    expected_uid: int,
) -> tuple[dict[str, str], dict[str, Any]]:
    identity = _read_canonical_document(
        identity_path,
        max_bytes=16 * 1024,
        expected_uid=expected_uid,
        label="broker release identity",
    )
    if (
        set(identity) != _IDENTITY_FIELDS
        or identity.get("schema") != _RELEASE_SCHEMA
    ):
        raise ProtectedInstallCoordinatorError(
            "broker release identity is unsupported"
        )
    broker = _exact_mapping(identity["broker"], {"digest", "path"}, "broker")
    package = _exact_mapping(
        identity["package"],
        {"root", "tree_digest"},
        "package",
    )
    python = _exact_mapping(identity["python"], {"digest", "path"}, "Python")
    _exact_mapping(identity["launcher"], {"digest", "path"}, "launcher")
    package_root = _protected_directory(
        _absolute_real_path(package["root"], "package root"),
        expected_uid,
        "release package root",
    )
    _require_digest(package["tree_digest"], "package tree digest")
    broker_relative = Path(_string(broker["path"], "broker path"))
    if (
        broker_relative.is_absolute()
        or "\\" in str(broker_relative)
        or any(part in {"", ".", ".."} for part in broker_relative.parts)
    ):
        raise ProtectedInstallCoordinatorError(
            "release broker path is invalid"
        )
    broker_path = (package_root / broker_relative).resolve(strict=True)
    try:
        broker_path.relative_to(package_root)
    except ValueError as exc:
        raise ProtectedInstallCoordinatorError(
            "release broker escapes its package"
        ) from exc
    producer_digest = _hash_protected_file(
        broker_path,
        expected_uid,
        64 * 1024 * 1024,
    )
    if producer_digest != _require_digest(
        broker["digest"],
        "broker digest",
    ):
        raise ProtectedInstallCoordinatorError(
            "release broker digest does not match"
        )
    python_path = _absolute_real_path(python["path"], "Python path")
    if Path(sys.executable).resolve(strict=True) != python_path:
        raise ProtectedInstallCoordinatorError(
            "coordinator is not running under release Python"
        )
    python_digest = _hash_protected_file(
        python_path,
        expected_uid,
        256 * 1024 * 1024,
    )
    if python_digest != _require_digest(
        python["digest"],
        "Python digest",
    ):
        raise ProtectedInstallCoordinatorError(
            "release Python digest does not match"
        )

    producer = _load_release_broker(broker_path, producer_digest)
    analyzer_implementation_digest = candidate_implementation_digest()
    analyzer_script = _release_analyzer_script(
        producer,
        analyzer_implementation_digest,
    )
    scanner = _string(
        getattr(producer, "_GITHUB_SCANNER", None),
        "release analyzer name",
    )
    version = _string(
        getattr(producer, "_GITHUB_ANALYZER_VERSION", None),
        "release analyzer version",
    )
    configuration = {
        "name": scanner,
        "version": version,
        "argv": [str(python_path), "-B", "-c", analyzer_script],
        "operator_argv0": str(python_path),
        "executable_digest": python_digest,
    }
    policy = {
        "schema": "aragorn/policy/v2",
        "id": "openclaw-live-github-broker-evidence",
        "version": 1,
        "required_analyzers": [scanner],
        "hard_deny_reason_codes": [],
        "review_severities": ["critical", "high", "medium"],
        "allowed_artifact_graph_profiles": [
            "recursive-github-markdown/v1",
            "recursive-github-markdown/v2",
            "recursive-github-markdown/v3",
        ],
    }
    return (
        {
            "expected_producer_implementation_digest": producer_digest,
            "expected_analyzer_implementation_digest": (
                analyzer_implementation_digest
            ),
            "expected_analyzer_executable_digest": python_digest,
            "expected_analyzer_configuration_digest": canonical_digest(
                configuration
            ),
            "expected_policy_digest": canonical_digest(policy),
            "expected_analyzer_verifier_digest": _module_digest(
                analyzer_receipt_module
            ),
            "expected_artifact_graph_verifier_digest": (
                analyzer_implementation_digest
            ),
        },
        {
            "package_root": package_root,
            "python_path": python_path,
        },
    )


def _load_release_asset_pins(
    path: Path | None,
    expected_uid: int,
) -> dict[str, Any] | None:
    if path is None:
        return None
    if not path.is_absolute():
        raise ProtectedInstallCoordinatorError(
            "release asset pins path must be absolute"
        )
    parent = _protected_directory(
        path.parent,
        expected_uid,
        "release asset pins directory",
    )
    if parent / path.name != path:
        raise ProtectedInstallCoordinatorError(
            "release asset pins path is not canonical"
        )
    try:
        os.lstat(path)
    except FileNotFoundError:
        return None
    return _read_canonical_document(
        path,
        max_bytes=_MAX_DOCUMENT_BYTES,
        expected_uid=expected_uid,
        exact_mode=0o400,
        label="release asset pins",
    )


def _recursive_identity(receipt: Any) -> dict[str, Any]:
    try:
        release_digests = sorted(
            _require_digest(
                item,
                "recursive acquisition release asset result digest",
            )
            for item in receipt.release_asset_result_digests
        )
    except (TypeError, ProtectedInstallCoordinatorError) as exc:
        raise ProtectedInstallCoordinatorError(
            "recursive release asset result digests are invalid"
        ) from exc
    return _verify_recursive_identity(
        {
            "root_manifest_digest": receipt.root_manifest_digest,
            "expansion_digest": receipt.expansion_digest,
            "expansion_proof_digest": receipt.expansion_proof_digest,
            "release_asset_result_digests": release_digests,
            "release_pin_set_digest": receipt.release_pin_set_digest,
        },
        "recursive acquisition",
        require_release_pin_set_field=True,
    )


def _recursive_artifact_graph_verifier_digest(
    cas: CAS,
    release_asset_result_digests: list[str],
) -> str:
    if release_asset_result_digests:
        recursive_artifact_graph_v6.release_assets_require_v6(
            cas,
            release_asset_result_digests,
        )
    return candidate_implementation_digest()


def _verify_recursive_identity(
    value: object,
    label: str,
    *,
    require_release_pin_set_field: bool,
) -> dict[str, Any]:
    expected_fields = (
        _RECURSIVE_FIELDS
        if require_release_pin_set_field
        else _RECURSIVE_V3_FIELDS
    )
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise ProtectedInstallCoordinatorError(f"{label} is invalid")
    proof = value["expansion_proof_digest"]
    if proof is not None:
        proof = _require_digest(proof, f"{label} expansion proof digest")
    release_digests = value["release_asset_result_digests"]
    if (
        not isinstance(release_digests, list)
        or len(release_digests) > 16
        or any(not isinstance(item, str) for item in release_digests)
        or len(set(release_digests)) != len(release_digests)
    ):
        raise ProtectedInstallCoordinatorError(f"{label} is invalid")
    ordered_release_digests = sorted(
        _require_digest(item, f"{label} release asset result digest")
        for item in release_digests
    )
    if release_digests != ordered_release_digests:
        raise ProtectedInstallCoordinatorError(f"{label} is not canonical")
    verified = {
        "root_manifest_digest": _require_digest(
            value["root_manifest_digest"],
            f"{label} root manifest digest",
        ),
        "expansion_digest": _require_digest(
            value["expansion_digest"],
            f"{label} expansion digest",
        ),
        "expansion_proof_digest": proof,
        "release_asset_result_digests": ordered_release_digests,
    }
    if require_release_pin_set_field:
        pin_set_digest = value["release_pin_set_digest"]
        verified["release_pin_set_digest"] = (
            None
            if pin_set_digest is None
            else _require_digest(
                pin_set_digest,
                f"{label} release pin-set digest",
            )
        )
    return verified


def _prepare_predecessor(
    operation: str,
    source_request: dict[str, str],
    protected_root: Path,
    quarantine_root: Path,
    state_path: Path,
    expected_uid: int,
) -> dict[str, Any] | None:
    active_path = protected_root / _TARGET
    if operation == "install":
        if state_path.exists() or os.path.lexists(active_path):
            raise ProtectedInstallCoordinatorError(
                "install requires no coordinator-managed active skill"
            )
        return None
    if not state_path.exists():
        raise ProtectedInstallCoordinatorError(
            "update requires coordinator-managed predecessor state"
        )
    state = _read_canonical_document(
        state_path,
        max_bytes=_MAX_DOCUMENT_BYTES,
        expected_uid=expected_uid,
        exact_mode=0o400,
        label="coordinator active state",
    )
    schema = state.get("schema")
    if (
        set(state) != _STATE_FIELDS
        or schema not in {STATE_SCHEMA_V1, STATE_SCHEMA_V2, STATE_SCHEMA}
        or state.get("assurance") != ASSURANCE
    ):
        raise ProtectedInstallCoordinatorError(
            "coordinator active state is invalid"
        )
    active = _exact_mapping(
        state["expected_active"],
        (
            _EXPECTED_ACTIVE_V1_FIELDS
            if schema == STATE_SCHEMA_V1
            else _EXPECTED_ACTIVE_FIELDS
        ),
        "coordinator expected active",
    )
    active_source = build_gateway_request(
        active.get("source_request", {}).get("owner"),
        active.get("source_request", {}).get("repository"),
        active.get("source_request", {}).get("commit"),
        active.get("source_request", {}).get("skill_path"),
    )
    if active_source != active["source_request"]:
        raise ProtectedInstallCoordinatorError(
            "coordinator predecessor source is not canonical"
        )
    for field in (
        "context_id",
        "manifest_digest",
        "quarantine_receipt_digest",
        "gateway_profile_digest",
    ):
        _require_digest(active[field], f"coordinator predecessor {field}")
    recursive = None
    if schema in {STATE_SCHEMA_V2, STATE_SCHEMA}:
        recursive = _verify_recursive_identity(
            active["recursive"],
            "coordinator predecessor recursive identity",
            require_release_pin_set_field=(schema == STATE_SCHEMA),
        )
    _require_digest(state["tree_digest"], "coordinator predecessor tree digest")
    _require_digest(
        state["service_request_digest"],
        "coordinator predecessor service request digest",
    )
    for field in ("owner", "repository", "skill_path"):
        if source_request[field] != active_source[field]:
            raise ProtectedInstallCoordinatorError(
                "update changes the coordinator source lineage"
            )
    if source_request["commit"] == active_source["commit"]:
        raise ProtectedInstallCoordinatorError(
            "update must select a new exact commit"
        )
    _verify_state_transaction(
        protected_root,
        state,
        expected_uid,
    )
    previous_cas = quarantine_root / canonical_digest(active_source)[7:]
    receipt = verify_github_quarantine_receipt(
        CAS(previous_cas, read_only=True),
        active["quarantine_receipt_digest"],
        expected_manifest_digest=(
            active["manifest_digest"]
            if recursive is None
            else recursive["root_manifest_digest"]
        ),
        expected_gateway_profile_digest=active["gateway_profile_digest"],
    )
    if receipt["request"] != active_source:
        raise ProtectedInstallCoordinatorError(
            "coordinator predecessor quarantine source changed"
        )
    if (
        recursive is not None
        and recursive.get("release_pin_set_digest") is not None
    ):
        try:
            verify_retained_release_pin_set(
                CAS(previous_cas, read_only=True),
                recursive["release_pin_set_digest"],
                expected_request=active_source,
                expected_manifest_digest=active["manifest_digest"],
                expected_source_proof_digest=receipt["source_proof_digest"],
                expected_recursive=recursive,
            )
        except GitHubRecursiveGatewayError as exc:
            raise ProtectedInstallCoordinatorError(
                f"coordinator predecessor release pin set is invalid: {exc}"
            ) from exc
    return state


def _transition_fields(
    operation: str,
    previous: dict[str, Any] | None,
    current_cas_path: Path,
    current_manifest_digest: str,
) -> dict[str, Any]:
    if operation == "install":
        return {
            "expected_active": None,
            "context_expected_active": None,
            "expected_manifest_diff_digest": None,
        }
    if previous is None:
        raise ProtectedInstallCoordinatorError(
            "update predecessor state is absent"
        )
    expected_active = previous["expected_active"]
    previous_cas = current_cas_path.parent / canonical_digest(
        expected_active["source_request"]
    )[7:]
    manifest_diff = diff_verified_manifests_between(
        CAS(previous_cas, read_only=True),
        expected_active["manifest_digest"],
        CAS(current_cas_path, read_only=True),
        current_manifest_digest,
    )
    context_expected_active = {
        "context_id": expected_active["context_id"],
        "manifest_digest": expected_active["manifest_digest"],
    }
    return {
        "expected_active": expected_active,
        "context_expected_active": context_expected_active,
        "expected_manifest_diff_digest": canonical_digest(manifest_diff),
    }


def _verify_recursive_gateway_receipt(
    receipt: Any,
    source_request: dict[str, str],
    quarantine_path: Path,
    *,
    require_release_pin_set: bool,
) -> dict[str, Any]:
    recursive = _recursive_identity(receipt)
    if (
        receipt.request_digest != canonical_digest(source_request)
        or receipt.quarantine_state != quarantine_path
        or receipt.quarantine_receipt_digest is None
        or receipt.gateway_profile_digest is None
    ):
        raise ProtectedInstallCoordinatorError(
            "gateway returned an unsupported quarantine result"
        )
    replay = verify_github_quarantine_receipt(
        CAS(quarantine_path, read_only=True),
        receipt.quarantine_receipt_digest,
        expected_manifest_digest=receipt.root_manifest_digest,
        expected_gateway_profile_digest=receipt.gateway_profile_digest,
    )
    manifest = load_verified_retained_manifest(
        CAS(quarantine_path, read_only=True),
        receipt.manifest_digest,
    )
    if (
        replay["request"] != source_request
        or replay["manifest_digest"] != receipt.root_manifest_digest
        or replay["source_proof_digest"] != receipt.source_proof_digest
        or replay["authority"] != QUARANTINE_AUTHORITY
    ):
        raise ProtectedInstallCoordinatorError(
            "gateway quarantine replay does not match its intent"
        )
    pin_set_digest = recursive["release_pin_set_digest"]
    if require_release_pin_set != (pin_set_digest is not None):
        raise ProtectedInstallCoordinatorError(
            "gateway release pin-set mode changed"
        )
    if pin_set_digest is not None:
        try:
            verify_retained_release_pin_set(
                CAS(quarantine_path, read_only=True),
                pin_set_digest,
                expected_request=source_request,
                expected_manifest_digest=receipt.manifest_digest,
                expected_source_proof_digest=receipt.source_proof_digest,
                expected_recursive=recursive,
            )
        except GitHubRecursiveGatewayError as exc:
            raise ProtectedInstallCoordinatorError(
                f"gateway release pin set is invalid: {exc}"
            ) from exc
    return {
        "receipt": replay,
        "recursive": recursive,
        "tree_digest": manifest["tree_digest"],
    }


def _verify_state_transaction(
    protected_root: Path,
    state: dict[str, Any],
    expected_uid: int,
) -> None:
    active = state["expected_active"]
    transaction = _load_claim(
        protected_root,
        active["context_id"],
        expected_uid,
    )
    if (
        transaction["context_id"] != active["context_id"]
        or transaction["manifest_digest"] != active["manifest_digest"]
        or transaction["tree_digest"] != state["tree_digest"]
        or transaction["version_path"] != state["version_path"]
        or transaction["operation"] not in {"install", "update"}
    ):
        raise ProtectedInstallCoordinatorError(
            "coordinator predecessor transaction changed"
        )
    _verify_active_link(protected_root, transaction["version_path"])


def _verify_active_transaction(
    protected_root: Path,
    *,
    context_id: str,
    manifest_digest: str,
    tree_digest: str,
    operation: str,
    expected_active: dict[str, str] | None,
    expected_uid: int,
) -> dict[str, Any]:
    transaction = _load_claim(protected_root, context_id, expected_uid)
    if (
        transaction["authority"]
        != "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        or transaction["operation"] != operation
        or transaction["expected_active"] != expected_active
        or transaction["manifest_digest"] != manifest_digest
        or transaction["tree_digest"] != tree_digest
        or transaction["destination"].get("target_name") != _TARGET
    ):
        raise ProtectedInstallCoordinatorError(
            "protected service published another transaction"
        )
    _verify_active_link(protected_root, transaction["version_path"])
    return transaction


def _load_claim(
    protected_root: Path,
    context_id: str,
    expected_uid: int,
) -> dict[str, Any]:
    context_id = _require_digest(context_id, "claim context id")
    path = (
        protected_root
        / ".aragorn-install-claims"
        / f"{context_id[7:]}.json"
    )
    document = _read_canonical_document(
        path,
        max_bytes=_MAX_DOCUMENT_BYTES,
        expected_uid=expected_uid,
        exact_mode=0o400,
        label="protected install claim",
    )
    expected_fields = {
        "schema",
        "authority",
        "context_id",
        "context_digest",
        "operation",
        "expected_active",
        "manifest_digest",
        "tree_digest",
        "destination",
        "version_path",
    }
    if (
        set(document) != expected_fields
        or document.get("schema") != "aragorn/protected-install-transaction/v1"
        or document.get("context_id") != context_id
    ):
        raise ProtectedInstallCoordinatorError(
            "protected install claim is invalid"
        )
    _require_digest(document["context_digest"], "claim context digest")
    manifest_digest = _require_digest(
        document.get("manifest_digest"),
        "claim manifest digest",
    )
    expected_version = (
        f".aragorn-versions/{_TARGET}/{context_id[7:]}-"
        f"{manifest_digest[7:]}"
    )
    if document.get("version_path") != expected_version:
        raise ProtectedInstallCoordinatorError(
            "protected install claim version path is invalid"
        )
    return document


def _verify_active_link(protected_root: Path, version_path: object) -> None:
    if not isinstance(version_path, str):
        raise ProtectedInstallCoordinatorError(
            "protected version path is invalid"
        )
    active = protected_root / _TARGET
    metadata = os.lstat(active)
    if (
        not stat.S_ISLNK(metadata.st_mode)
        or os.readlink(active) != version_path
    ):
        raise ProtectedInstallCoordinatorError(
            "protected active link does not match coordinator state"
        )
    version = protected_root / version_path
    try:
        version.relative_to(protected_root)
        version_state = os.lstat(version)
    except (OSError, ValueError) as exc:
        raise ProtectedInstallCoordinatorError(
            "protected version path is unavailable"
        ) from exc
    if not stat.S_ISDIR(version_state.st_mode):
        raise ProtectedInstallCoordinatorError(
            "protected version is not a directory"
        )


def _start_fixed_service() -> None:
    _require_root_executable(_SYSTEMCTL)
    try:
        result = subprocess.run(
            (
                str(_SYSTEMCTL),
                "--no-ask-password",
                "--wait",
                "start",
                _SERVICE_UNIT,
            ),
            check=False,
            cwd="/",
            env={
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=360,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProtectedInstallCoordinatorError(
            f"cannot invoke protected install service: {exc}"
        ) from exc
    if result.returncode != 0:
        message = result.stderr[:4096].decode("utf-8", "replace").strip()
        raise ProtectedInstallCoordinatorError(
            f"protected install service failed: {message or result.returncode}"
        )


def _atomic_publish(
    path: Path,
    raw: bytes,
    expected_uid: int,
    *,
    replace: bool = True,
) -> tuple[tuple[int, ...], str]:
    if len(raw) > _MAX_DOCUMENT_BYTES:
        raise ProtectedInstallCoordinatorError(
            "coordinator document exceeds 64 KiB"
        )
    parent = _protected_directory(
        path.parent,
        expected_uid,
        "coordinator publication directory",
    )
    if path.parent.resolve(strict=True) / path.name != path:
        raise ProtectedInstallCoordinatorError(
            "coordinator publication path is not canonical"
        )
    temporary = parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise OSError("short coordinator document write")
                written += count
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                metadata.st_uid != expected_uid
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_size != len(raw)
            ):
                raise ProtectedInstallCoordinatorError(
                    "coordinator publication metadata is unsafe"
                )
        finally:
            os.close(descriptor)
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        _fsync_directory(parent)
        retained, token = _read_protected_bytes(
            path,
            max_bytes=_MAX_DOCUMENT_BYTES,
            expected_uid=expected_uid,
            exact_mode=0o400,
            label="coordinator publication",
        )
        if retained != raw:
            raise ProtectedInstallCoordinatorError(
                "coordinator publication bytes changed"
            )
        return token
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        if not replace:
            _unlink_current_file(
                path,
                expected_uid,
                expected_digest=_digest(raw),
            )
        raise


def _remove_request(path: Path) -> None:
    try:
        path.unlink()
        _fsync_directory(path.parent)
    except FileNotFoundError:
        return


def _read_canonical_document(
    path: Path,
    *,
    max_bytes: int,
    expected_uid: int,
    label: str,
    exact_mode: int | None = None,
) -> dict[str, Any]:
    document, _token = _read_canonical_document_snapshot(
        path,
        max_bytes=max_bytes,
        expected_uid=expected_uid,
        label=label,
        exact_mode=exact_mode,
    )
    return document


def _read_canonical_document_snapshot(
    path: Path,
    *,
    max_bytes: int,
    expected_uid: int,
    label: str,
    exact_mode: int | None = None,
) -> tuple[dict[str, Any], tuple[tuple[int, ...], str]]:
    raw, token = _read_protected_bytes(
        path,
        max_bytes=max_bytes,
        expected_uid=expected_uid,
        label=label,
        exact_mode=exact_mode,
    )
    return _parse_canonical_document(raw, label), token


def _read_protected_bytes(
    path: Path,
    *,
    max_bytes: int,
    expected_uid: int,
    label: str,
    exact_mode: int | None = None,
) -> tuple[bytes, tuple[tuple[int, ...], str]]:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProtectedInstallCoordinatorError(
            f"cannot resolve {label}: {exc}"
        ) from exc
    if not path.is_absolute() or path != resolved:
        raise ProtectedInstallCoordinatorError(
            f"{label} path must be absolute and canonical"
        )
    _require_protected_ancestry(path.parent, expected_uid)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or mode & 0o022
            or (exact_mode is not None and mode != exact_mode)
        ):
            raise ProtectedInstallCoordinatorError(
                f"{label} metadata is unsafe"
            )
        raw = bytearray()
        content_digest = hashlib.sha256()
        size = 0
        oversized = before.st_size > max_bytes
        while chunk := os.read(descriptor, 8192):
            content_digest.update(chunk)
            size += len(chunk)
            if not oversized and size <= max_bytes:
                raw.extend(chunk)
            else:
                oversized = True
                raw.clear()
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        _file_identity(before) != _file_identity(after)
        or size != after.st_size
    ):
        raise ProtectedInstallCoordinatorError(
            f"{label} changed while read"
        )
    token = (
        _file_identity(after),
        "sha256:" + content_digest.hexdigest(),
    )
    if oversized:
        raise _ProtectedFileTooLarge(
            f"{label} exceeds its byte limit",
            token,
        )
    return bytes(raw), token


def _parse_canonical_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except ProtectedInstallCoordinatorError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtectedInstallCoordinatorError(f"{label} is invalid: {exc}") from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise ProtectedInstallCoordinatorError(
            f"{label} must be canonical JSON"
        )
    return document


def _unlink_matching(
    path: Path,
    token: tuple[tuple[int, ...], str],
    expected_uid: int,
) -> bool:
    try:
        _raw, current = _read_protected_bytes(
            path,
            max_bytes=_MAX_DOCUMENT_BYTES,
            expected_uid=expected_uid,
            exact_mode=0o400,
            label="coordinator cleanup target",
        )
    except _ProtectedFileTooLarge as exc:
        current = exc.token
    except ProtectedInstallCoordinatorError:
        return False
    if current != token:
        return False
    parent = _protected_directory(
        path.parent,
        expected_uid,
        "coordinator cleanup directory",
    )
    descriptor = os.open(
        parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        if _file_identity(metadata) != token[0]:
            return False
        os.unlink(path.name, dir_fd=descriptor)
        os.fsync(descriptor)
    except FileNotFoundError:
        return False
    finally:
        os.close(descriptor)
    return True


def _unlink_current_file(
    path: Path,
    expected_uid: int,
    *,
    expected_digest: str | None = None,
) -> bool:
    try:
        _raw, token = _read_protected_bytes(
            path,
            max_bytes=_MAX_DOCUMENT_BYTES,
            expected_uid=expected_uid,
            exact_mode=0o400,
            label="coordinator cleanup target",
        )
    except _ProtectedFileTooLarge as exc:
        token = exc.token
    except ProtectedInstallCoordinatorError:
        return False
    if expected_digest is not None and token[1] != expected_digest:
        return False
    return _unlink_matching(path, token, expected_uid)


def _protected_directory(
    path: Path,
    expected_uid: int,
    label: str,
) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = os.lstat(resolved)
    except (OSError, RuntimeError) as exc:
        raise ProtectedInstallCoordinatorError(
            f"cannot resolve {label}: {exc}"
        ) from exc
    if (
        path != resolved
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ProtectedInstallCoordinatorError(
            f"{label} is not broker-protected"
        )
    _require_protected_ancestry(resolved.parent, expected_uid)
    return resolved


def _require_protected_ancestry(path: Path, expected_uid: int) -> None:
    current = path
    while True:
        metadata = os.lstat(current)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid not in {0, expected_uid}
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ProtectedInstallCoordinatorError(
                "coordinator protected ancestry is unsafe"
            )
        if current == Path(current.anchor):
            return
        current = current.parent


def _hash_protected_file(
    path: Path,
    expected_uid: int,
    max_bytes: int,
) -> str:
    _require_protected_ancestry(path.parent, expected_uid)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > max_bytes
        ):
            raise ProtectedInstallCoordinatorError(
                "release file metadata is unsafe"
            )
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise ProtectedInstallCoordinatorError(
                    "release file exceeds its byte limit"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if size != after.st_size or _file_identity(before) != _file_identity(after):
        raise ProtectedInstallCoordinatorError(
            "release file changed while read"
        )
    return "sha256:" + digest.hexdigest()


def _load_release_broker(path: Path, digest: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"_aragorn_protected_broker_{digest[7:23]}",
        path,
    )
    if spec is None or spec.loader is None:
        raise ProtectedInstallCoordinatorError(
            "cannot load release broker"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _release_analyzer_script(
    producer: ModuleType,
    analyzer_implementation_digest: str,
) -> str:
    builder = getattr(producer, "_github_analyzer_script", None)
    if not callable(builder):
        raise ProtectedInstallCoordinatorError(
            "release broker omits its analyzer configuration"
        )
    parameters = inspect.signature(builder).parameters
    if {"expected_uid", "expected_gid"}.issubset(parameters):
        analyzer_uid, analyzer_gid = _service_identity(
            _ANALYZER_USER,
            _ANALYZER_GROUP,
        )
        script = builder(
            analyzer_implementation_digest,
            expected_uid=analyzer_uid,
            expected_gid=analyzer_gid,
        )
    elif {"expected_user", "expected_group"}.issubset(parameters):
        script = builder(
            analyzer_implementation_digest,
            expected_user=_ANALYZER_USER,
            expected_group=_ANALYZER_GROUP,
        )
    else:
        raise ProtectedInstallCoordinatorError(
            "release broker analyzer identity binding is unsupported"
        )
    return _string(script, "release analyzer script")


def _service_identity(user: str, group: str) -> tuple[int, int]:
    try:
        user_record = pwd.getpwnam(user)
        group_record = grp.getgrnam(group)
    except KeyError as exc:
        raise ProtectedInstallCoordinatorError(
            "fixed gateway identity is not provisioned"
        ) from exc
    if (
        user_record.pw_name != user
        or group_record.gr_name != group
        or user_record.pw_uid <= 0
        or group_record.gr_gid <= 0
        or user_record.pw_gid != group_record.gr_gid
        or user_record.pw_dir != "/nonexistent"
        or user_record.pw_shell != "/usr/sbin/nologin"
    ):
        raise ProtectedInstallCoordinatorError(
            "fixed gateway identity is invalid"
        )
    return user_record.pw_uid, group_record.gr_gid


def _require_root_executable(path: Path) -> None:
    resolved = path.resolve(strict=True)
    metadata = os.lstat(resolved)
    if (
        path != resolved
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise ProtectedInstallCoordinatorError(
            "systemctl executable is not trusted"
        )
    _require_protected_ancestry(path.parent, 0)


def _absolute_real_path(value: object, label: str) -> Path:
    supplied = Path(_string(value, label))
    try:
        resolved = supplied.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProtectedInstallCoordinatorError(
            f"cannot resolve {label}: {exc}"
        ) from exc
    if not supplied.is_absolute() or supplied != resolved:
        raise ProtectedInstallCoordinatorError(
            f"{label} must be an absolute real path"
        )
    return resolved


def _exact_mapping(
    value: object,
    fields: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtectedInstallCoordinatorError(
            f"release {label} identity is invalid"
        )
    return value


def _module_digest(module: ModuleType) -> str:
    path = Path(_string(module.__file__, "module path")).resolve(strict=True)
    return _digest(path.read_bytes())


def _require_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ProtectedInstallCoordinatorError(f"{label} is invalid")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtectedInstallCoordinatorError(f"{label} is invalid")
    return value


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ProtectedInstallCoordinatorError(
                f"duplicate JSON key: {key}"
            )
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise ProtectedInstallCoordinatorError(
        f"non-finite JSON number: {value}"
    )


def _run_coordinator(
    *,
    intent_path: Path = _INTENT_PATH,
    expected_uid: int = 0,
) -> int:
    try:
        result = coordinate_intent(
            intent_path,
            expected_uid=expected_uid,
        )
    except Exception as exc:  # noqa: BLE001 - one fail-closed service result
        result = _coordinator_error(exc)
        status = 4
    else:
        result["status"] = "COMPLETED_NOT_INSTALLER_AUTHORITY"
        status = 0
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return status


def _run_submitted(
    *,
    submission_path: Path = _INTENT_PATH,
    expected_uid: int = 0,
) -> int:
    submission_token = None
    derived_token = None
    derived_path = None
    result_path = None
    submission_id = None
    submission_digest = None
    intent_digest = None
    try:
        try:
            raw, submission_token = _read_protected_bytes(
                submission_path,
                max_bytes=_MAX_INTENT_BYTES,
                expected_uid=expected_uid,
                exact_mode=0o400,
                label="protected install submission",
            )
        except _ProtectedFileTooLarge as exc:
            submission_token = exc.token
            raise
        submission_digest = _digest(raw)
        document = _parse_canonical_document(
            raw,
            "protected install submission",
        )
        submission_id, intent = _validate_production_submission(document)
        intent_digest = canonical_digest(intent)
        result_path = _submission_result_path(
            submission_path.parent,
            submission_id,
        )
        derived_path = _derived_intent_path(
            submission_path.parent,
            submission_id,
        )
        if os.path.lexists(result_path) or os.path.lexists(derived_path):
            raise ProtectedInstallCoordinatorError(
                "protected install submission namespace is occupied"
            )
        if not _unlink_matching(
            submission_path,
            submission_token,
            expected_uid,
        ):
            raise ProtectedInstallCoordinatorError(
                "protected install submission changed before consumption"
            )
        submission_token = None
        derived_token = _atomic_publish(
            derived_path,
            canonical_json(intent),
            expected_uid,
            replace=False,
        )
        result = coordinate_intent(
            derived_path,
            expected_uid=expected_uid,
            expected_intent_digest=intent_digest,
        )
    except Exception as exc:  # noqa: BLE001 - one fail-closed service result
        result = _coordinator_error(exc)
        status = 4
    else:
        result["status"] = "COMPLETED_NOT_INSTALLER_AUTHORITY"
        status = 0
    finally:
        if submission_token is not None:
            _unlink_matching(
                submission_path,
                submission_token,
                expected_uid,
            )
        if derived_token is not None and derived_path is not None:
            _unlink_matching(derived_path, derived_token, expected_uid)
    if (
        result_path is not None
        and submission_id is not None
        and submission_digest is not None
        and intent_digest is not None
    ):
        try:
            _atomic_publish(
                result_path,
                canonical_json(
                    {
                        "schema": SUBMISSION_RESULT_SCHEMA,
                        "submission_id": submission_id,
                        "submission_digest": submission_digest,
                        "intent_digest": intent_digest,
                        "coordinator_result": result,
                    }
                ),
                expected_uid,
                replace=False,
            )
        except Exception as exc:  # noqa: BLE001 - publication must fail closed
            result = _coordinator_error(exc)
            status = 4
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return status


def _coordinator_error(exc: Exception) -> dict[str, Any]:
    message = str(exc) or "protected install coordination failed"
    return {
        "schema": RESULT_SCHEMA,
        "assurance": ASSURANCE,
        "status": "ERROR",
        "error": {"type": type(exc).__name__, "message": message},
        "installer_work_eligible": False,
        "runtime_conformance_qualified": False,
    }


def _submission_error(exc: Exception) -> int:
    sys.stderr.buffer.write(canonical_json(_coordinator_error(exc)) + b"\n")
    return 4


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if not arguments:
        return _run_coordinator()
    if arguments == ("run-submitted",):
        return _run_submitted()
    if len(arguments) == 6 and arguments[0] == "submit":
        try:
            result = submit_intent(*arguments[1:])
        except Exception as exc:  # noqa: BLE001 - one fail-closed CLI result
            return _submission_error(exc)
        sys.stdout.buffer.write(canonical_json(result) + b"\n")
        return (
            0
            if result.get("status") == "COMPLETED_NOT_INSTALLER_AUTHORITY"
            else 4
        )
    print(
        "usage: aragorn-protected-install-coordinator "
        "[run-submitted | submit INSTALL_OR_UPDATE OWNER REPOSITORY "
        "40_HEX_COMMIT SKILL_PATH]",
        file=sys.stderr,
    )
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
