"""Narrow admission closure for self-contained local Markdown skills."""

from __future__ import annotations

from io import BytesIO
import json
from pathlib import PurePosixPath
import re
from typing import Any

from .artifact_closure import (
    MAX_GRAPH_BYTES,
    MAX_SCANNED_TEXT_BYTES,
    ArtifactClosureError,
    ReferenceBudgetExceeded,
    canonical_json,
    load_verified_retained_manifest,
    scan_retained_text_references,
)
from .cas import CAS, CASError


PROFILE = "self-contained-local-markdown/v1"
VERIFIER = "aragorn/admission-artifact-graph-verifier"
VERIFIER_VERSION = "1"
_AUTHORITY = "CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
_MAX_EDGES = 10_000
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class AdmissionArtifactGraphError(ValueError):
    """An admission artifact graph is malformed or inconsistent."""


def retain_admission_artifact_graph(
    cas: CAS,
    manifest_digest: str,
    *,
    verifier_implementation_digest: str,
) -> str:
    """Derive and retain the narrow artifact-closure record."""

    try:
        verifier_digest = _digest(
            verifier_implementation_digest,
            "verifier implementation digest",
        )
        return _put(
            cas,
            canonical_json(_derive(cas, manifest_digest, verifier_digest)),
        )
    except (ArtifactClosureError, CASError) as exc:
        raise AdmissionArtifactGraphError(
            f"cannot retain admission artifact graph: {exc}"
        ) from exc


def verify_admission_artifact_graph(
    cas: CAS,
    graph_digest: str,
    *,
    expected_manifest_digest: str,
    expected_verifier_digest: str,
) -> dict[str, Any]:
    """Re-derive closure evidence without granting installer authority."""

    try:
        manifest_digest = _digest(
            expected_manifest_digest,
            "expected manifest digest",
        )
        raw = cas.read(
            _digest(graph_digest, "admission artifact graph digest"),
            max_bytes=MAX_GRAPH_BYTES,
        )
        graph = _canonical_document(raw)
        verifier_digest = _digest(
            expected_verifier_digest,
            "expected verifier digest",
        )
        if graph.get("verifier") != {
            "name": VERIFIER,
            "version": VERIFIER_VERSION,
            "implementation_digest": verifier_digest,
        }:
            raise AdmissionArtifactGraphError(
                "admission artifact graph verifier identity is untrusted"
            )
        if raw != canonical_json(_derive(cas, manifest_digest, verifier_digest)):
            raise AdmissionArtifactGraphError(
                "admission artifact graph does not match retained source"
            )
        return graph
    except AdmissionArtifactGraphError:
        raise
    except (ArtifactClosureError, CASError) as exc:
        raise AdmissionArtifactGraphError(
            f"cannot verify admission artifact graph: {exc}"
        ) from exc


def _derive(
    cas: CAS,
    manifest_digest: str,
    verifier_digest: str,
) -> dict[str, Any]:
    manifest_digest = _digest(manifest_digest, "manifest digest")
    manifest = load_verified_retained_manifest(cas, manifest_digest)
    local_source = manifest["schema"] == "aragorn/manifest/v1"
    unresolved: set[str] = set()
    if not local_source:
        unresolved.add(f"UNSUPPORTED_ADMISSION_SOURCE:{manifest_digest}")
    source_by_path = {entry["path"]: entry for entry in manifest["files"]}
    edges: list[dict[str, Any]] = []
    for entry in manifest["files"]:
        path = entry["path"]
        digest = entry["digest"]
        if PurePosixPath(path).suffix.casefold() != ".md" or entry["executable"]:
            unresolved.add(f"UNSUPPORTED_ADMISSION_ARTIFACT:{path}:{digest}")
            continue
        if not local_source:
            continue
        if entry["size"] > MAX_SCANNED_TEXT_BYTES:
            unresolved.add(f"OVERSIZED_ADMISSION_MARKDOWN:{path}:{digest}")
            continue
        content = cas.read(digest, max_bytes=entry["size"])
        if b"\0" in content:
            unresolved.add(f"NUL_CONTAINING_ADMISSION_MARKDOWN:{path}:{digest}")
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            unresolved.add(f"NON_UTF8_ADMISSION_MARKDOWN:{path}:{digest}")
            continue
        try:
            file_edges = scan_retained_text_references(
                text,
                source_entry=entry,
                source=manifest["source"],
                source_by_path=source_by_path,
            )
        except ReferenceBudgetExceeded:
            unresolved.add(f"ADMISSION_REFERENCE_BUDGET_EXCEEDED:{path}:{digest}")
            continue
        if len(edges) + len(file_edges) > _MAX_EDGES:
            unresolved.add(f"ADMISSION_REFERENCE_BUDGET_EXCEEDED:{path}:{digest}")
            continue
        edges.extend(file_edges)
    ordered_edges = sorted(
        edges,
        key=lambda edge: (
            edge["source_path"],
            edge["byte_offset"],
            edge["literal_digest"],
            edge["reference_kind"],
            edge["status"],
        ),
    )
    unresolved.update(
        (
            f"{edge['reason_code']}:{edge['source_path']}:"
            f"{edge['byte_offset']}:{edge['literal_digest']}"
        )
        for edge in ordered_edges
        if edge["status"] == "unresolved"
    )
    ordered_unresolved = sorted(unresolved)
    return {
        "schema": "aragorn/admission-artifact-graph/v1",
        "authority": _AUTHORITY,
        "verifier": {
            "name": VERIFIER,
            "version": VERIFIER_VERSION,
            "implementation_digest": verifier_digest,
        },
        "profile": PROFILE,
        "root_manifest_digest": manifest_digest,
        "tree_digest": manifest["tree_digest"],
        "artifacts": [
            {key: entry[key] for key in ("path", "size", "digest", "executable")}
            for entry in manifest["files"]
        ],
        "edges": ordered_edges,
        "closure": {
            "scope": "artifact_graph",
            "profile": PROFILE,
            "status": "incomplete" if ordered_unresolved else "complete",
            "unresolved": ordered_unresolved,
        },
    }


def _canonical_document(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except AdmissionArtifactGraphError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise AdmissionArtifactGraphError(
            f"admission artifact graph is invalid: {exc}"
        ) from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise AdmissionArtifactGraphError(
            "admission artifact graph is not canonical JSON"
        )
    return document


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AdmissionArtifactGraphError(f"{label} is invalid")
    return value


def _put(cas: CAS, raw: bytes) -> str:
    if len(raw) > MAX_GRAPH_BYTES:
        raise AdmissionArtifactGraphError(
            "admission artifact graph evidence exceeds its byte limit"
        )
    return cas.put(BytesIO(raw), max_bytes=len(raw))


def _reject_duplicate_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise AdmissionArtifactGraphError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise AdmissionArtifactGraphError(f"non-finite JSON number: {value}")
