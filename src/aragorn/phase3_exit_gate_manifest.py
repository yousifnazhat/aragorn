"""Strictly parse the fixed Phase 3 V1 exit-gate manifest envelope."""

from __future__ import annotations

import json
from typing import Any

from .oci_worker_protocol import canonical_json

_MAX_MANIFEST_BYTES = 64 * 1024


class Phase3ExitGateManifestError(ValueError):
    """The manifest bytes are not unique canonical integer-only JSON."""


def load_phase3_exit_gate_manifest_bytes(raw: bytes) -> dict[str, Any]:
    """Return the manifest object after strict lexical and canonical checks."""

    if type(raw) is not bytes or not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise Phase3ExitGateManifestError(
            "Phase 3 exit-gate manifest must be bounded non-empty bytes"
        )
    if b"\x00" in raw:
        raise Phase3ExitGateManifestError("Phase 3 exit-gate manifest contains NUL")
    try:
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_noninteger_number,
            parse_float=_reject_noninteger_number,
        )
    except Phase3ExitGateManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise Phase3ExitGateManifestError(
            "Phase 3 exit-gate manifest is not strict JSON"
        ) from exc
    if type(document) is not dict:
        raise Phase3ExitGateManifestError(
            "Phase 3 exit-gate manifest must be an object"
        )
    if canonical_json(document) + b"\n" != raw:
        raise Phase3ExitGateManifestError(
            "Phase 3 exit-gate manifest is not canonical JSON plus LF"
        )
    return document


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise Phase3ExitGateManifestError(
                f"Phase 3 exit-gate manifest repeats JSON key: {key}"
            )
        output[key] = value
    return output


def _reject_noninteger_number(value: str) -> Any:
    raise Phase3ExitGateManifestError(
        f"Phase 3 exit-gate manifest contains non-integer number: {value}"
    )
