"""Uninstalled exact-digest entrypoint for the private quarantine response.

This source installs nothing and has no automatic dispatch. Successor producers,
runtime overrides and mandatory startup enforcement require a separately bound
deployment before claiming digest quarantine or future-start enforcement.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from . import runtime_quarantine_response as response
from .oci_worker_protocol import canonical_json
from .runtime_skill_startup import _digest


def _diagnostic(status: int, message: str) -> int:
    """Keep the response status even when diagnostics cannot be delivered."""
    try:
        if sys.stderr is not None:
            print(message, file=sys.stderr, flush=True)
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 - diagnostic boundary
        # Interpreter shutdown must not retry a failed diagnostic stream.
        sys.stderr = None
    return status


def main(argv: Sequence[str] | None = None) -> int:
    """Accept two canonical digests; never select paths, units or processes."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        return _diagnostic(
            64,
            "usage: aragorn-runtime-quarantine-service EXPECTED_SKILL_DIGEST "
            "EXPECTED_REVOCATION_SNAPSHOT_DIGEST",
        )
    completed = False
    try:
        _digest(arguments[0], "requested skill")
        _digest(arguments[1], "requested revocation snapshot")
        result = response._quarantine_fixed_runtime_profile(*arguments)
        # The core has already retained evidence and released all held locks.
        completed = True
        try:
            print(canonical_json(result).decode("ascii"), flush=True)
        except (Exception, KeyboardInterrupt):
            # Do not reflush a failed stream at interpreter shutdown: that can
            # replace the required indeterminate exit 125 with Python's 120.
            sys.stdout = None
            raise
        return 0
    except response.RuntimeQuarantineIndeterminate:
        return _diagnostic(
            125,
            "aragorn runtime quarantine: INDETERMINATE: denial or response "
            "effects may persist",
        )
    except KeyboardInterrupt:
        if completed:
            return _diagnostic(
                125,
                "aragorn runtime quarantine: INDETERMINATE: retained response "
                "delivery interrupted",
            )
        return 130
    except Exception:  # noqa: BLE001 - one fail-closed service boundary
        if completed:
            return _diagnostic(
                125,
                "aragorn runtime quarantine: INDETERMINATE: retained response "
                "delivery failed",
            )
        return _diagnostic(126, "aragorn runtime quarantine: REFUSED")
