"""Additive digest-denial prerequisite around the frozen install transaction.

This private wrapper is not wired into a deployed installer and does not grant
quarantine, startup enforcement, or Phase 3 qualification authority.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Collection, Mapping
from typing import Any

from . import protected_install as legacy
from .cas import CAS
from .protected_install import ProtectedInstallTransactionError
from .protected_skill_quarantine import require_not_quarantined_at


def _publish_protected_install_transaction(
    cas: CAS,
    context: Mapping[str, Any],
    root_fd: int,
    *,
    now_unix: int,
    claim_now_unix: int,
    expected_context_digest: str,
    expected_target_name: str,
    expected_runtime_conformance_digest: str,
    measured_target_runtime_digest: str,
    revoked_context_ids: Collection[str],
    expected_active_cas: CAS | None = None,
    claim_state_provider: Callable[[], tuple[int, Collection[str]]] | None = None,
) -> dict[str, Any]:
    """Reject recorded candidate skill bytes before staging and before claim.

    The root lock is acquired through a duplicate of the caller's descriptor.
    The frozen publisher receives that same open-file description, so its own
    lock acquisition cannot deadlock on the wrapper's lock. It retains its
    existing claim, cleanup, recovery, predecessor, and return-value semantics.

    A generic manifest without a root SKILL.md retains the private primitive's
    existing contract. Supported skill ingresses must require SKILL.md before
    calling this primitive. No marker is removed and no installed evidence is
    mutated by the denial checks.
    """

    broker_root_fd = -1
    locked = False
    try:
        try:
            if os.name != "posix":
                raise ProtectedInstallTransactionError(
                    "protected install transactions are unsupported on this platform"
                )
            if isinstance(root_fd, bool) or not isinstance(root_fd, int) or root_fd < 0:
                raise ProtectedInstallTransactionError(
                    "protected install root fd is invalid"
                )
            if (
                isinstance(claim_now_unix, bool)
                or not isinstance(claim_now_unix, int)
                or isinstance(now_unix, bool)
                or not isinstance(now_unix, int)
                or claim_now_unix < now_unix
            ):
                raise ProtectedInstallTransactionError(
                    "protected install claim time is invalid"
                )
            try:
                import fcntl
            except ImportError as exc:  # pragma: no cover - non-POSIX guard
                raise ProtectedInstallTransactionError(
                    "protected install transaction locking is unsupported"
                ) from exc

            broker_root_fd = os.dup(root_fd)
            os.set_inheritable(broker_root_fd, False)
            before = legacy._require_broker_directory(
                broker_root_fd,
                "protected install root",
                require_owner_write=True,
            )
            fcntl.flock(broker_root_fd, fcntl.LOCK_EX)
            locked = True
            after = legacy._require_broker_directory(
                broker_root_fd,
                "protected install root",
                require_owner_write=True,
            )
            if legacy._inode(before) != legacy._inode(after):
                raise ProtectedInstallTransactionError(
                    "protected install root identity changed"
                )
            verified = legacy.verify_protected_install_context_v2(
                cas,
                context,
                broker_root_fd,
                now_unix=now_unix,
                expected_context_digest=expected_context_digest,
                expected_target_name=expected_target_name,
                expected_runtime_conformance_digest=expected_runtime_conformance_digest,
                measured_target_runtime_digest=measured_target_runtime_digest,
                revoked_context_ids=revoked_context_ids,
            )
            manifest = legacy.load_verified_retained_manifest(
                cas, verified.manifest_digest
            )
            skill_digest = next(
                (
                    entry["digest"]
                    for entry in manifest["files"]
                    if entry["path"] == "SKILL.md"
                ),
                None,
            )
            if skill_digest is not None:
                require_not_quarantined_at(
                    broker_root_fd, skill_digest, expected_uid=os.geteuid()
                )
        except Exception as exc:
            raise ProtectedInstallTransactionError(
                "protected install transaction failed before consuming its "
                f"context: {exc}"
            ) from exc

        def fresh_claim_state() -> tuple[int, Collection[str]]:
            # Preserve the supplied provider's ordering and exact returned state.
            state = (
                (claim_now_unix, revoked_context_ids)
                if claim_state_provider is None
                else claim_state_provider()
            )
            require_not_quarantined_at(
                broker_root_fd, skill_digest, expected_uid=os.geteuid()
            )
            return state

        # Do not wrap delegated exceptions: post-claim recovery is authoritative.
        return legacy._publish_protected_install_transaction(
            cas,
            context,
            broker_root_fd,
            now_unix=now_unix,
            claim_now_unix=claim_now_unix,
            expected_context_digest=expected_context_digest,
            expected_target_name=expected_target_name,
            expected_runtime_conformance_digest=expected_runtime_conformance_digest,
            measured_target_runtime_digest=measured_target_runtime_digest,
            revoked_context_ids=revoked_context_ids,
            expected_active_cas=expected_active_cas,
            claim_state_provider=(
                fresh_claim_state if skill_digest is not None else claim_state_provider
            ),
        )
    finally:
        if locked:
            fcntl.flock(broker_root_fd, fcntl.LOCK_UN)
        if broker_root_fd >= 0:
            os.close(broker_root_fd)
