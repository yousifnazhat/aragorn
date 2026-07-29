"""Evidence-only regular-file diffs between verified retained manifests."""

from __future__ import annotations

from typing import Any

from .artifact_closure import ArtifactClosureError, load_verified_retained_manifest
from .cas import CAS, CASError

_AUTHORITY = "UPDATE_DIFF_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"


class ManifestDiffError(ValueError):
    """A retained manifest pair cannot produce a trustworthy update diff."""


def diff_verified_manifests(
    cas: CAS,
    old_manifest_digest: str,
    new_manifest_digest: str,
) -> dict[str, Any]:
    """Diff regular-file content and executable bits without granting authority."""

    return diff_verified_manifests_between(
        cas,
        old_manifest_digest,
        cas,
        new_manifest_digest,
    )


def diff_verified_manifests_between(
    old_cas: CAS,
    old_manifest_digest: str,
    new_cas: CAS,
    new_manifest_digest: str,
) -> dict[str, Any]:
    """Diff manifests retained under distinct, verified custody roots."""

    try:
        old_manifest = load_verified_retained_manifest(
            old_cas,
            old_manifest_digest,
        )
        new_manifest = load_verified_retained_manifest(
            new_cas,
            new_manifest_digest,
        )
    except (ArtifactClosureError, CASError, TypeError, ValueError) as exc:
        raise ManifestDiffError(f"cannot verify update manifests: {exc}") from exc

    old_files = {
        entry["path"]: _file_identity(entry) for entry in old_manifest["files"]
    }
    new_files = {
        entry["path"]: _file_identity(entry) for entry in new_manifest["files"]
    }
    old_paths = set(old_files)
    new_paths = set(new_files)
    return {
        "schema": "aragorn/manifest-update-diff/v1",
        "authority": _AUTHORITY,
        "old": {
            "manifest_digest": old_manifest_digest,
            "tree_digest": old_manifest["tree_digest"],
        },
        "new": {
            "manifest_digest": new_manifest_digest,
            "tree_digest": new_manifest["tree_digest"],
        },
        "added_paths": sorted(new_paths - old_paths),
        "removed_paths": sorted(old_paths - new_paths),
        "changed_paths": sorted(
            path for path in old_paths & new_paths if old_files[path] != new_files[path]
        ),
    }


def _file_identity(entry: dict[str, Any]) -> tuple[int, str, bool]:
    return entry["size"], entry["digest"], entry["executable"]
