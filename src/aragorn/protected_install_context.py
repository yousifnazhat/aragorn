"""Broker-protected bindings for a future exact-digest install transaction."""

from __future__ import annotations

import os
import stat
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any

from .cas import CAS
from .decision_receipt import DecisionReceiptError, verify_decision_v3
from .materialization import _TARGET_NAME
from .oci_worker_protocol import canonical_digest

_AUTHORITY = "BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY"
_DIGEST_PREFIX = "sha256:"
_MAX_ANALYZERS = 16
_GITHUB_TRUST_FIELDS = {
    "quarantine_receipt_digest",
    "gateway_profile_digest",
}
_COMMON_FIELDS = {
    "schema",
    "authority",
    "context_id",
    "status",
    "expires_at_unix",
    "decision_digest",
    "manifest_digest",
    "artifact_graph_digest",
    "policy_digest",
    "analyzer_run_receipt_digests",
    "analyzer_verifier_digest",
    "artifact_graph_verifier_digest",
    "target_runtime_digest",
    "runtime_conformance_digest",
    "destination",
}


class ProtectedInstallContextError(ValueError):
    """A protected install context is malformed, stale, or inconsistently bound."""


@dataclass(frozen=True)
class VerifiedInstallContext:
    """Values independently verified for later consumption by a broker."""

    context_digest: str
    context_id: str
    decision_digest: str
    manifest_digest: str
    target_runtime_digest: str
    runtime_conformance_digest: str
    root_device: int
    root_inode: int
    target_name: str
    expires_at_unix: int


@dataclass(frozen=True)
class VerifiedInstallContextV2(VerifiedInstallContext):
    """A v2 context that also binds the requested state transition."""

    operation: str
    expected_active_context_id: str | None
    expected_active_manifest_digest: str | None


def verify_protected_install_context(
    cas: CAS,
    context: Mapping[str, Any],
    root_fd: int,
    *,
    now_unix: int,
    expected_context_digest: str,
    expected_target_name: str,
    expected_runtime_conformance_digest: str,
    measured_target_runtime_digest: str,
    revoked_context_ids: Collection[str],
) -> VerifiedInstallContext:
    """Verify protected transaction inputs without authorizing publication."""

    try:
        document = _context_document(context, _COMMON_FIELDS)
        return _verify_context_bindings(
            cas,
            document,
            root_fd,
            schema="aragorn/protected-install-context/v1",
            now_unix=now_unix,
            expected_context_digest=expected_context_digest,
            expected_target_name=expected_target_name,
            expected_runtime_conformance_digest=(expected_runtime_conformance_digest),
            measured_target_runtime_digest=measured_target_runtime_digest,
            revoked_context_ids=revoked_context_ids,
        )
    except ProtectedInstallContextError:
        raise
    except (DecisionReceiptError, OSError, TypeError, ValueError) as exc:
        raise ProtectedInstallContextError(
            f"cannot verify protected install context: {exc}"
        ) from exc


def verify_protected_install_context_v2(
    cas: CAS,
    context: Mapping[str, Any],
    root_fd: int,
    *,
    now_unix: int,
    expected_context_digest: str,
    expected_target_name: str,
    expected_runtime_conformance_digest: str,
    measured_target_runtime_digest: str,
    revoked_context_ids: Collection[str],
) -> VerifiedInstallContextV2:
    """Verify a transition-bound v2 context without authorizing publication."""

    try:
        document = _context_document(
            context,
            _COMMON_FIELDS | {"operation", "expected_active"},
        )
        operation = document["operation"]
        if operation not in {"install", "update", "rollback"}:
            raise ProtectedInstallContextError("protected install operation is invalid")
        expected_active = document["expected_active"]
        if operation == "install":
            if expected_active is not None:
                raise ProtectedInstallContextError(
                    "fresh install must not bind an active predecessor"
                )
            expected_active_context_id = None
            expected_active_manifest_digest = None
        else:
            active = _exact_object(
                expected_active,
                {"context_id", "manifest_digest"},
                "protected install expected active state",
            )
            expected_active_context_id = _digest(
                active["context_id"],
                "expected active protected install context id",
            )
            expected_active_manifest_digest = _digest(
                active["manifest_digest"],
                "expected active protected install manifest digest",
            )

        verified = _verify_context_bindings(
            cas,
            document,
            root_fd,
            schema="aragorn/protected-install-context/v2",
            now_unix=now_unix,
            expected_context_digest=expected_context_digest,
            expected_target_name=expected_target_name,
            expected_runtime_conformance_digest=(expected_runtime_conformance_digest),
            measured_target_runtime_digest=measured_target_runtime_digest,
            revoked_context_ids=revoked_context_ids,
        )
        if verified.context_id == expected_active_context_id:
            raise ProtectedInstallContextError(
                "new protected install context repeats the active context"
            )
        return VerifiedInstallContextV2(
            context_digest=verified.context_digest,
            context_id=verified.context_id,
            decision_digest=verified.decision_digest,
            manifest_digest=verified.manifest_digest,
            target_runtime_digest=verified.target_runtime_digest,
            runtime_conformance_digest=verified.runtime_conformance_digest,
            root_device=verified.root_device,
            root_inode=verified.root_inode,
            target_name=verified.target_name,
            expires_at_unix=verified.expires_at_unix,
            operation=operation,
            expected_active_context_id=expected_active_context_id,
            expected_active_manifest_digest=expected_active_manifest_digest,
        )
    except ProtectedInstallContextError:
        raise
    except (DecisionReceiptError, OSError, TypeError, ValueError) as exc:
        raise ProtectedInstallContextError(
            f"cannot verify protected install context: {exc}"
        ) from exc


def _verify_context_bindings(
    cas: CAS,
    document: Mapping[str, Any],
    root_fd: int,
    *,
    schema: str,
    now_unix: int,
    expected_context_digest: str,
    expected_target_name: str,
    expected_runtime_conformance_digest: str,
    measured_target_runtime_digest: str,
    revoked_context_ids: Collection[str],
) -> VerifiedInstallContext:
    context_digest = _digest(
        expected_context_digest,
        "expected protected install context digest",
    )
    if canonical_digest(document) != context_digest:
        raise ProtectedInstallContextError(
            "protected install context digest is untrusted"
        )
    if document["schema"] != schema:
        raise ProtectedInstallContextError(
            "protected install context schema is unsupported"
        )
    if document["authority"] != _AUTHORITY:
        raise ProtectedInstallContextError(
            "protected install context overstates its authority"
        )
    context_id = _digest(
        document["context_id"],
        "protected install context id",
    )
    if isinstance(revoked_context_ids, (str, bytes)) or not isinstance(
        revoked_context_ids,
        Collection,
    ):
        raise ProtectedInstallContextError("protected revocation state is invalid")
    revoked = {
        _digest(item, "revoked protected install context id")
        for item in revoked_context_ids
    }
    if context_id in revoked:
        raise ProtectedInstallContextError("protected install context is revoked")
    if document["status"] not in {"active", "revoked"}:
        raise ProtectedInstallContextError(
            "protected install context status is invalid"
        )
    if document["status"] == "revoked":
        raise ProtectedInstallContextError("protected install context is revoked")
    now = _non_negative_integer(now_unix, "trusted current time")
    expires = _non_negative_integer(
        document["expires_at_unix"],
        "protected install context expiry",
    )
    if now >= expires:
        raise ProtectedInstallContextError("protected install context is expired")

    target_runtime_digest = _digest(
        document["target_runtime_digest"],
        "protected target runtime digest",
    )
    if (
        _digest(
            measured_target_runtime_digest,
            "measured target runtime digest",
        )
        != target_runtime_digest
    ):
        raise ProtectedInstallContextError("measured target runtime identity changed")
    runtime_conformance_digest = _digest(
        document["runtime_conformance_digest"],
        "runtime conformance digest",
    )
    if (
        _digest(
            expected_runtime_conformance_digest,
            "expected runtime conformance digest",
        )
        != runtime_conformance_digest
    ):
        raise ProtectedInstallContextError("runtime conformance identity changed")

    destination = _exact_object(
        document["destination"],
        {"root_device", "root_inode", "target_name"},
        "protected install destination",
    )
    target_name = destination["target_name"]
    if not isinstance(target_name, str) or _TARGET_NAME.fullmatch(target_name) is None:
        raise ProtectedInstallContextError("protected install target name is invalid")
    if (
        not isinstance(expected_target_name, str)
        or _TARGET_NAME.fullmatch(expected_target_name) is None
        or target_name != expected_target_name
    ):
        raise ProtectedInstallContextError("protected install target changed")
    root_state = _protected_root_state(root_fd)
    root_device = _non_negative_integer(
        destination["root_device"],
        "protected install root device",
    )
    root_inode = _positive_integer(
        destination["root_inode"],
        "protected install root inode",
    )
    if root_device != root_state.st_dev or root_inode != root_state.st_ino:
        raise ProtectedInstallContextError("protected install destination changed")

    run_receipt_digests = document["analyzer_run_receipt_digests"]
    if (
        not isinstance(run_receipt_digests, list)
        or len(run_receipt_digests) > _MAX_ANALYZERS
    ):
        raise ProtectedInstallContextError(
            "analyzer run receipt digest list is invalid"
        )
    for digest in run_receipt_digests:
        _digest(digest, "analyzer run receipt digest")
    if len(run_receipt_digests) != len(set(run_receipt_digests)):
        raise ProtectedInstallContextError(
            "analyzer run receipt digests must be unique"
        )

    decision_digest = _digest(document["decision_digest"], "decision digest")
    receipt_digest, gateway_profile_digest = _context_github_trust_digests(document)
    decision = verify_decision_v3(
        cas,
        decision_digest,
        expected_manifest_digest=_digest(
            document["manifest_digest"],
            "expected manifest digest",
        ),
        expected_artifact_graph_digest=_digest(
            document["artifact_graph_digest"],
            "expected artifact graph digest",
        ),
        expected_policy_digest=_digest(
            document["policy_digest"],
            "expected policy digest",
        ),
        expected_analyzer_run_receipt_digests=run_receipt_digests,
        expected_analyzer_verifier_digest=_digest(
            document["analyzer_verifier_digest"],
            "expected analyzer verifier digest",
        ),
        expected_artifact_graph_verifier_digest=_digest(
            document["artifact_graph_verifier_digest"],
            "expected artifact graph verifier digest",
        ),
        expected_quarantine_receipt_digest=receipt_digest,
        expected_gateway_profile_digest=gateway_profile_digest,
    )
    if decision["verdict"] != "ALLOW":
        raise ProtectedInstallContextError("protected install decision is not ALLOW")
    return VerifiedInstallContext(
        context_digest=context_digest,
        context_id=context_id,
        decision_digest=decision_digest,
        manifest_digest=decision["manifest_digest"],
        target_runtime_digest=target_runtime_digest,
        runtime_conformance_digest=runtime_conformance_digest,
        root_device=root_device,
        root_inode=root_inode,
        target_name=target_name,
        expires_at_unix=expires,
    )


def _protected_root_state(root_fd: int) -> os.stat_result:
    if isinstance(root_fd, bool) or not isinstance(root_fd, int) or root_fd < 0:
        raise ProtectedInstallContextError("protected root fd is invalid")
    state = os.fstat(root_fd)
    if not stat.S_ISDIR(state.st_mode) or state.st_nlink < 1:
        raise ProtectedInstallContextError(
            "protected install root is not a live directory"
        )
    return state


def _exact_object(
    value: object,
    keys: set[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ProtectedInstallContextError(f"{label} fields are invalid")
    return value


def _context_document(
    value: object,
    required_keys: set[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtectedInstallContextError(
            "protected install context fields are invalid"
        )
    keys = set(value)
    if keys != required_keys and keys != required_keys | _GITHUB_TRUST_FIELDS:
        raise ProtectedInstallContextError(
            "protected install context fields are invalid"
        )
    return value


def _context_github_trust_digests(
    document: Mapping[str, Any],
) -> tuple[str | None, str | None]:
    receipt = document.get("quarantine_receipt_digest")
    gateway_profile = document.get("gateway_profile_digest")
    if receipt is None and gateway_profile is None:
        return None, None
    if receipt is None or gateway_profile is None:
        raise ProtectedInstallContextError(
            "protected GitHub trust identities must be supplied together"
        )
    return (
        _digest(receipt, "protected quarantine receipt digest"),
        _digest(gateway_profile, "protected gateway profile digest"),
    )


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_DIGEST_PREFIX)
        or len(value) != 71
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ProtectedInstallContextError(f"{label} is invalid")
    return value


def _non_negative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtectedInstallContextError(f"{label} is invalid")
    return value


def _positive_integer(value: object, label: str) -> int:
    integer = _non_negative_integer(value, label)
    if integer == 0:
        raise ProtectedInstallContextError(f"{label} is invalid")
    return integer
