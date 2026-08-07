"""Live protected-install gate around the source-frozen capability issuer."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .runtime_action_broker import RuntimeActionBrokerError
from .runtime_active_skill_lineage import (
    DEFAULT_PROTECTED_INSTALL_ROOT,
    hold_runtime_active_skill_lineage,
)
from .runtime_capability_grant import (
    _canonical_profiled_submission,
    _profile_attribution,
    issue_profiled_runtime_capability,
    parse_runtime_capability_grant,
)
from .runtime_process_profile import require_live_pidfd

LINEAGE_ISSUANCE_SCHEMA = "aragorn/lineage-profiled-runtime-capability-issuance/v1"
LINEAGE_ISSUANCE_AUTHORITY = (
    "SENSOR_LIVE_LINEAGE_ISSUANCE_ONLY_NOT_INSTALLER_OR_EFFECT_AUTHORITY"
)


@contextmanager
def hold_profiled_runtime_capability_issuance(
    submission: object,
    grant_raw: bytes,
    now_unix: int,
    *,
    pidfd: int,
    lineage_snapshot: object,
    protected_install_root: Path = DEFAULT_PROTECTED_INSTALL_ROOT,
    deadline: float | None = None,
) -> Iterator[dict[str, Any]]:
    """Keep active install lineage stable through one broker response."""

    grant = parse_runtime_capability_grant(grant_raw, now_unix)
    profiled = _canonical_profiled_submission(submission)
    attribution = _profile_attribution(profiled)
    with hold_runtime_active_skill_lineage(
        attribution["pid"],
        attribution,
        grant,
        protected_root=protected_install_root,
        deadline=deadline,
    ) as live_lineage:
        if live_lineage != lineage_snapshot:
            raise RuntimeActionBrokerError(
                "runtime active-skill lineage changed before capability issuance"
            )
        require_live_pidfd(pidfd)
        yield {
            "schema": LINEAGE_ISSUANCE_SCHEMA,
            "authority": LINEAGE_ISSUANCE_AUTHORITY,
            "lineage": live_lineage,
            "issuance": issue_profiled_runtime_capability(
                profiled,
                grant_raw,
                now_unix,
            ),
        }
