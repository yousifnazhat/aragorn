#!/usr/bin/env python3
"""Materialize the dedicated V3 workshop-invalidation subfixture bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
from pathlib import Path
from typing import Any


class WorkshopInvalidationMaterializationError(ValueError):
    """The pinned proposal-derived invalidation bundle changed."""


_ROOT = Path(__file__).resolve().parents[1]
_V2_MATERIALIZER = _ROOT / "scripts/materialize_fixed_admission_probes.py"
_V2_MATERIALIZER_BYTES = 87_912
_V2_MATERIALIZER_DIGEST = (
    "sha256:0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec"
)
_CASE_ID = "ADM-02/reload/workshop-invalidation"
_PROBE = "protected-workshop-invalidation-v3-probe.mjs"
_PROPOSAL = "PROPOSAL.md"
_PROPOSAL_BYTES = 84
_PROPOSAL_DIGEST = (
    "sha256:a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a"
)
_PROBE_BYTES = 48_609
_PROBE_DIGEST = (
    "sha256:d987ab8e17caa527786486f8440d194bec6e8b441386fd0f85100e3d33459334"
)
_SCHEMA = "aragorn/openclaw-final-v3-workshop-invalidation-bundle/v1"
_AUTHORITY = (
    "PINNED_PROPOSAL_DERIVED_WORKSHOP_INVALIDATION_PROBE_ONLY_"
    "NOT_EXECUTION_QUALIFICATION_OR_ADMISSION_AUTHORITY"
)
_V3_REPLACEMENTS = (
    (
        b"sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
        b"sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c",
        2,
    ),
    (
        b"configuration.file?.size === 1880",
        b"configuration.file?.size === 2159",
        1,
    ),
)
_ROUTE_IDS_OLD = b"""const ROUTE_IDS = Object.freeze([
  "ADM-02/update/archive-source-force-replacement",
  "ADM-02/update/clawhub-tracked-replacement",
  "ADM-02/update/core-updater-plugin-replacement",
  "ADM-02/update/curator-restore-activation",
  "ADM-02/update/plugin-package-skill-replacement",
  "ADM-02/update/workshop-proposal-apply",
  "ADM-02/reload/fresh-session-reset",
  "ADM-02/reload/manual-plugin-invalidation",
  "ADM-02/reload/remote-eligibility-invalidation",
  "ADM-02/reload/sandbox-per-run-rescan",
  "ADM-02/reload/session-snapshot-consumer",
  "ADM-02/reload/workshop-invalidation",
]);"""
_ROUTE_IDS_NEW = b"""const ROUTE_IDS = Object.freeze([
  "ADM-02/reload/workshop-invalidation",
]);"""
_ROUTE_DISPATCH_OLD = b"""const ACTION_BY_ROUTE = Object.freeze({
  "ADM-02/update/archive-source-force-replacement":
    "archive-source-force-replacement",
  "ADM-02/update/core-updater-plugin-replacement":
    "core-updater-plugin-replacement",
  "ADM-02/update/workshop-proposal-apply": "workshop-protected-apply",
  "ADM-02/reload/fresh-session-reset": "fresh-session-reset",
  "ADM-02/reload/session-snapshot-consumer": "session-snapshot-consumer",
});
const PROFILE_BLOCKED_ROUTES = Object.freeze({
  "ADM-02/reload/workshop-invalidation":
    "WORKSHOP_INVALIDATION_NOT_REACHED_AFTER_PROTECTED_APPLY_DENIAL",
});
const ADAPTER_BY_ROUTE = Object.freeze({
  "ADM-02/update/clawhub-tracked-replacement":
    "/route-adapters/clawhub-tracked-replacement.mjs",
  "ADM-02/update/curator-restore-activation":
    "/route-adapters/curator-restore-activation.mjs",
  "ADM-02/update/plugin-package-skill-replacement":
    "/route-adapters/plugin-package-skill-replacement.mjs",
  "ADM-02/reload/manual-plugin-invalidation":
    "/route-adapters/manual-plugin-invalidation.mjs",
  "ADM-02/reload/remote-eligibility-invalidation":
    "/route-adapters/remote-eligibility-invalidation.mjs",
  "ADM-02/reload/sandbox-per-run-rescan":
    "/route-adapters/sandbox-per-run-rescan.mjs",
});"""
_ROUTE_DISPATCH_NEW = b"""const ACTION_BY_ROUTE = Object.freeze({
  "ADM-02/reload/workshop-invalidation": "workshop-invalidation",
});
const PROFILE_BLOCKED_ROUTES = Object.freeze({});
const ADAPTER_BY_ROUTE = Object.freeze({});"""
_ROUTE_REPLACEMENTS = (
    (
        b'/route-input/workshop-proposal-apply/PROPOSAL.md',
        b'/route-input/workshop-invalidation/PROPOSAL.md',
        1,
    ),
    (_ROUTE_IDS_OLD, _ROUTE_IDS_NEW, 1),
    (_ROUTE_DISPATCH_OLD, _ROUTE_DISPATCH_NEW, 1),
    (b'"workshop-protected-apply"', b'"workshop-invalidation"', 2),
    (
        b'aragorn/openclaw-protected-route-action-observations/v1',
        b'aragorn/openclaw-protected-workshop-invalidation-observation/v1',
        1,
    ),
)


def materialize_openclaw_final_v3_workshop_invalidation(
    output: Path,
) -> dict[str, Any]:
    """Write one exact read-only invalidation probe and inert proposal fixture."""

    if not isinstance(output, Path) or output.exists() or output.is_symlink():
        raise WorkshopInvalidationMaterializationError("output must be a new Path")
    namespace = _verified_v2_materializer()
    transform = namespace.get("transformed_final_combined_v2_probe")
    if not callable(transform):
        raise WorkshopInvalidationMaterializationError(
            "fixed V2 materializer entry changed"
        )
    try:
        probe = transform("protected-route-probe.mjs", workshop=True)
        proposal = transform(_PROPOSAL, workshop=True)
    except (OSError, TypeError, ValueError) as exc:
        raise WorkshopInvalidationMaterializationError(
            f"proposal harness materialization failed: {exc}"
        ) from exc
    if type(probe) is not bytes or type(proposal) is not bytes:
        raise WorkshopInvalidationMaterializationError(
            "proposal materializer returned non-bytes"
        )
    probe = _replace_exact(probe, _V3_REPLACEMENTS + _ROUTE_REPLACEMENTS)
    if (
        len(probe) != _PROBE_BYTES
        or _digest(probe) != _PROBE_DIGEST
        or len(proposal) != _PROPOSAL_BYTES
        or _digest(proposal) != _PROPOSAL_DIGEST
    ):
        raise WorkshopInvalidationMaterializationError(
            "materialized bundle bytes changed: "
            f"probe={len(probe)}/{_digest(probe)} "
            f"proposal={len(proposal)}/{_digest(proposal)}"
        )
    output.mkdir(mode=0o755)
    files = []
    for name, raw, digest, role in (
        (_PROPOSAL, proposal, _PROPOSAL_DIGEST, "fixture"),
        (_PROBE, probe, _PROBE_DIGEST, "probe"),
    ):
        path = output / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o444)
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise WorkshopInvalidationMaterializationError(
                        "bundle write made no progress"
                    )
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o444, follow_symlinks=False)
        files.append(
            {"bytes": len(raw), "digest": digest, "name": name, "role": role}
        )
    os.chmod(output, 0o555, follow_symlinks=False)
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "case_id": _CASE_ID,
        "files": files,
        "source_relationship": {
            "base": "final-combined-v2-workshop-proposal-apply",
            "configuration_rebound": "protected-final-combined-v3",
            "route_semantics": "dedicated-route-input-only",
        },
    }


def _verified_v2_materializer() -> dict[str, Any]:
    raw = _V2_MATERIALIZER.read_bytes()
    if len(raw) != _V2_MATERIALIZER_BYTES or _digest(raw) != _V2_MATERIALIZER_DIGEST:
        raise WorkshopInvalidationMaterializationError(
            "fixed V2 materializer bytes changed"
        )
    return runpy.run_path(str(_V2_MATERIALIZER))


def _replace_exact(
    raw: bytes, replacements: tuple[tuple[bytes, bytes, int], ...]
) -> bytes:
    for old, new, expected in replacements:
        if raw.count(old) != expected:
            raise WorkshopInvalidationMaterializationError(
                "proposal-derived route replacement shape changed"
            )
        raw = raw.replace(old, new)
        if raw.count(old) != 0:
            raise WorkshopInvalidationMaterializationError(
                "stale proposal-derived route bytes remain"
            )
    return raw


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = materialize_openclaw_final_v3_workshop_invalidation(args.output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
