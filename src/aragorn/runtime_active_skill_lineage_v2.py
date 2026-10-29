"""Additive digest-denial prerequisite retaining the frozen lineage lock.

This module is not wired into a deployed runtime or startup gate. A successful
check has only the existing lineage authority; it is not Phase 3 qualification.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import runtime_active_skill_lineage as legacy
from .protected_skill_quarantine import require_not_quarantined_at
from .runtime_action_broker import RuntimeActionBrokerError
from .runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)


def verify_runtime_active_skill_lineage(
    pid: int,
    attribution: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    protected_root: Path = legacy.DEFAULT_PROTECTED_INSTALL_ROOT,
    expected_install_uid: int = 0,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Verify live lineage plus candidate denial state, then release the lock."""

    with hold_runtime_active_skill_lineage(
        pid,
        attribution,
        grant,
        protected_root=protected_root,
        expected_install_uid=expected_install_uid,
        deadline=deadline,
    ) as lineage:
        return lineage


@contextmanager
def hold_runtime_active_skill_lineage(
    pid: int,
    attribution: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    protected_root: Path = legacy.DEFAULT_PROTECTED_INSTALL_ROOT,
    expected_install_uid: int = 0,
    deadline: float | None = None,
) -> Iterator[dict[str, Any]]:
    """Deny recorded active bytes while holding the original SH through yield."""

    with legacy.hold_runtime_active_skill_lineage(
        pid,
        attribution,
        grant,
        protected_root=protected_root,
        expected_install_uid=expected_install_uid,
        deadline=deadline,
    ) as lineage:
        root_fd = -1
        try:
            try:
                root_fd = legacy._open_protected_root(
                    protected_root, expected_install_uid
                )
                state = os.fstat(root_fd)
                if (state.st_dev, state.st_ino) != (
                    lineage["root_device"],
                    lineage["root_inode"],
                ):
                    raise RuntimeActionBrokerError(
                        "protected install root identity changed"
                    )
                require_not_quarantined_at(
                    root_fd,
                    lineage["active_skill_digest"],
                    expected_uid=expected_install_uid,
                )
            except (OSError, RuntimeActionBrokerError, TypeError, ValueError) as exc:
                raise RuntimeActionObservationPublisherError(
                    f"runtime active-skill lineage cannot be verified: {exc}"
                ) from exc
            yield lineage
        finally:
            if root_fd >= 0:
                try:
                    os.close(root_fd)
                except OSError as exc:
                    raise RuntimeActionObservationPublisherError(
                        "runtime active-skill lineage cleanup failed"
                    ) from exc
