"""Descriptor-bound verification of a materialized source-tree snapshot."""

from __future__ import annotations

from pathlib import PurePosixPath

from .acquire import InventoryError, inventory_open_directory
from .artifact_closure import ArtifactClosureError, load_verified_retained_manifest
from .cas import CAS, CASError

_MAX_STAGING_DEPTH = 8


class MaterializationVerificationError(ValueError):
    """A staged source tree does not match its retained manifest."""


def verify_materialized_source_tree(
    cas: CAS,
    manifest_digest: str,
    staging_fd: int,
) -> str:
    """Verify one descriptor-bound snapshot without authorizing activation.

    The caller must keep the tree protected and the descriptor open through a
    later descriptor-relative atomic activation.
    """

    try:
        manifest = load_verified_retained_manifest(cas, manifest_digest)
        expected_files = [
            {key: entry[key] for key in ("path", "size", "digest", "executable")}
            for entry in manifest["files"]
        ]
        expected_directories: set[str] = set()
        max_depth = 0
        for entry in expected_files:
            parts = PurePosixPath(entry["path"]).parts
            max_depth = max(max_depth, len(parts) - 1)
            expected_directories.update(
                "/".join(parts[:depth]) for depth in range(1, len(parts))
            )
        if max_depth > _MAX_STAGING_DEPTH:
            raise MaterializationVerificationError(
                "retained source tree exceeds the supported depth"
            )
        observed, observed_directories = inventory_open_directory(
            staging_fd,
            max_depth=max_depth,
        )
    except (ArtifactClosureError, CASError, InventoryError) as exc:
        raise MaterializationVerificationError(
            f"cannot verify materialized source tree: {exc}"
        ) from exc

    if (
        observed["files"] != expected_files
        or observed["tree_digest"] != manifest["tree_digest"]
        or observed_directories != tuple(sorted(expected_directories))
    ):
        raise MaterializationVerificationError(
            "materialized source tree does not match retained bytes"
        )
    return manifest["tree_digest"]
