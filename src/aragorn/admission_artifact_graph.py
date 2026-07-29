"""Versioned admission closure for local and proof-bound GitHub Markdown."""

from __future__ import annotations

import json
import re
from io import BytesIO
from pathlib import PurePosixPath
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
from .github_quarantine_receipt import (
    LINUX_CONTAINMENT_PROFILE,
    GitHubQuarantineReceiptError,
    verify_github_quarantine_receipt,
)

PROFILE = "self-contained-local-markdown/v1"
GITHUB_PROFILE = "self-contained-github-markdown/v1"
VERIFIER = "aragorn/admission-artifact-graph-verifier"
VERIFIER_VERSION = "1"
GITHUB_VERIFIER_VERSION = "2"
_AUTHORITY = "CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
_REQUIRED_BROKER_UID = 0
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
    expected_quarantine_receipt_digest: str | None = None,
    expected_gateway_profile_digest: str | None = None,
    expected_release_asset_result_digests: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Re-derive closure evidence without granting installer authority."""

    try:
        manifest_digest = _digest(
            expected_manifest_digest,
            "expected manifest digest",
        )
        verifier_digest = _digest(
            expected_verifier_digest,
            "expected verifier digest",
        )
        raw = cas.read(
            _digest(graph_digest, "admission artifact graph digest"),
            max_bytes=MAX_GRAPH_BYTES,
        )
        graph = _canonical_document(raw)
        if graph.get("schema") in {
            "aragorn/admission-artifact-graph/v3",
            "aragorn/admission-artifact-graph/v4",
            "aragorn/admission-artifact-graph/v5",
        }:
            if (
                expected_quarantine_receipt_digest is None
                or expected_gateway_profile_digest is None
            ):
                raise AdmissionArtifactGraphError(
                    "recursive GitHub admission replay requires caller-held "
                    "quarantine receipt and gateway profile digests"
                )
            receipt_digest = _digest(
                expected_quarantine_receipt_digest,
                "expected quarantine receipt digest",
            )
            gateway_profile_digest = _digest(
                expected_gateway_profile_digest,
                "expected gateway profile digest",
            )
            if graph["schema"] == "aragorn/admission-artifact-graph/v5":
                from .github_recursive_artifact_graph_v5 import (
                    verify_recursive_github_artifact_graph,
                )

                return verify_recursive_github_artifact_graph(
                    cas,
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile_digest,
                    expected_verifier_digest=verifier_digest,
                    expected_release_asset_result_digests=(
                        expected_release_asset_result_digests
                    ),
                )
            if graph["schema"] == "aragorn/admission-artifact-graph/v4":
                from .github_recursive_artifact_graph_v4 import (
                    verify_recursive_github_artifact_graph,
                )

                return verify_recursive_github_artifact_graph(
                    cas,
                    graph_digest,
                    expected_manifest_digest=manifest_digest,
                    expected_quarantine_receipt_digest=receipt_digest,
                    expected_gateway_profile_digest=gateway_profile_digest,
                    expected_verifier_digest=verifier_digest,
                    expected_release_asset_result_digests=(
                        expected_release_asset_result_digests
                    ),
                )
            if expected_release_asset_result_digests:
                raise AdmissionArtifactGraphError(
                    "v3 recursive admission replay does not accept release assets"
                )
            from .github_recursive_artifact_graph import (
                verify_recursive_github_artifact_graph,
            )

            return verify_recursive_github_artifact_graph(
                cas,
                graph_digest,
                expected_manifest_digest=manifest_digest,
                expected_quarantine_receipt_digest=receipt_digest,
                expected_gateway_profile_digest=gateway_profile_digest,
                expected_verifier_digest=verifier_digest,
            )
        if expected_release_asset_result_digests:
            raise AdmissionArtifactGraphError(
                "non-recursive admission replay does not accept release assets"
            )
        if graph.get("schema") == "aragorn/admission-artifact-graph/v2":
            if (
                expected_quarantine_receipt_digest is None
                or expected_gateway_profile_digest is None
            ):
                raise AdmissionArtifactGraphError(
                    "GitHub admission replay requires caller-held quarantine "
                    "receipt and gateway profile digests"
                )
            return verify_github_admission_artifact_graph_v2(
                cas,
                graph_digest,
                expected_manifest_digest=manifest_digest,
                expected_quarantine_receipt_digest=_digest(
                    expected_quarantine_receipt_digest,
                    "expected quarantine receipt digest",
                ),
                expected_gateway_profile_digest=_digest(
                    expected_gateway_profile_digest,
                    "expected gateway profile digest",
                ),
                expected_verifier_digest=verifier_digest,
            )
        if graph.get("schema") != "aragorn/admission-artifact-graph/v1":
            raise AdmissionArtifactGraphError(
                "admission artifact graph schema is unsupported"
            )
        if (
            expected_quarantine_receipt_digest is not None
            or expected_gateway_profile_digest is not None
        ):
            raise AdmissionArtifactGraphError(
                "local admission replay does not accept GitHub trust identities"
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


def retain_github_admission_artifact_graph_v2(
    cas: CAS,
    manifest_digest: str,
    *,
    expected_quarantine_receipt_digest: str,
    expected_gateway_profile_digest: str,
    verifier_implementation_digest: str,
) -> str:
    """Derive proof-bound GitHub Markdown closure without authorizing it."""

    try:
        verifier_digest = _digest(
            verifier_implementation_digest,
            "verifier implementation digest",
        )
        receipt_digest = _digest(
            expected_quarantine_receipt_digest,
            "expected quarantine receipt digest",
        )
        gateway_profile_digest = _digest(
            expected_gateway_profile_digest,
            "expected gateway profile digest",
        )
        return _put(
            cas,
            canonical_json(
                _derive_github_v2(
                    cas,
                    manifest_digest,
                    receipt_digest,
                    gateway_profile_digest,
                    verifier_digest,
                )
            ),
        )
    except AdmissionArtifactGraphError:
        raise
    except (
        ArtifactClosureError,
        CASError,
        GitHubQuarantineReceiptError,
    ) as exc:
        raise AdmissionArtifactGraphError(
            f"cannot retain GitHub admission artifact graph: {exc}"
        ) from exc


def verify_github_admission_artifact_graph_v2(
    cas: CAS,
    graph_digest: str,
    *,
    expected_manifest_digest: str,
    expected_quarantine_receipt_digest: str,
    expected_gateway_profile_digest: str,
    expected_verifier_digest: str,
) -> dict[str, Any]:
    """Replay caller-selected receipt, proof, and GitHub Markdown closure."""

    try:
        manifest_digest = _digest(
            expected_manifest_digest,
            "expected manifest digest",
        )
        receipt_digest = _digest(
            expected_quarantine_receipt_digest,
            "expected quarantine receipt digest",
        )
        gateway_profile_digest = _digest(
            expected_gateway_profile_digest,
            "expected gateway profile digest",
        )
        verifier_digest = _digest(
            expected_verifier_digest,
            "expected verifier digest",
        )
        raw = cas.read(
            _digest(graph_digest, "admission artifact graph digest"),
            max_bytes=MAX_GRAPH_BYTES,
        )
        graph = _canonical_document(raw)
        if graph.get("verifier") != {
            "name": VERIFIER,
            "version": GITHUB_VERIFIER_VERSION,
            "implementation_digest": verifier_digest,
        }:
            raise AdmissionArtifactGraphError(
                "GitHub admission artifact graph verifier identity is untrusted"
            )
        if graph.get("quarantine_receipt_digest") != receipt_digest:
            raise AdmissionArtifactGraphError(
                "GitHub admission artifact graph is bound to another quarantine receipt"
            )
        if graph.get("gateway_profile_digest") != gateway_profile_digest:
            raise AdmissionArtifactGraphError(
                "GitHub admission artifact graph is bound to another gateway profile"
            )
        if raw != canonical_json(
            _derive_github_v2(
                cas,
                manifest_digest,
                receipt_digest,
                gateway_profile_digest,
                verifier_digest,
            )
        ):
            raise AdmissionArtifactGraphError(
                "GitHub admission artifact graph does not match retained source"
            )
        return graph
    except AdmissionArtifactGraphError:
        raise
    except (
        ArtifactClosureError,
        CASError,
        GitHubQuarantineReceiptError,
    ) as exc:
        raise AdmissionArtifactGraphError(
            f"cannot verify GitHub admission artifact graph: {exc}"
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
    ordered_edges, ordered_unresolved = _scan_admission_markdown(
        cas,
        manifest,
        scan_references=local_source,
        unresolved=unresolved,
    )
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


def _derive_github_v2(
    cas: CAS,
    manifest_digest: str,
    receipt_digest: str,
    gateway_profile_digest: str,
    verifier_digest: str,
) -> dict[str, Any]:
    manifest_digest = _digest(manifest_digest, "manifest digest")
    receipt = verify_github_quarantine_receipt(
        cas,
        receipt_digest,
        expected_manifest_digest=manifest_digest,
        expected_gateway_profile_digest=gateway_profile_digest,
    )
    if receipt["containment_profile"] != LINUX_CONTAINMENT_PROFILE:
        raise AdmissionArtifactGraphError(
            "GitHub admission requires the Linux restricted-egress containment profile"
        )
    if receipt["protected_cas"]["owner_uid"] != _REQUIRED_BROKER_UID:
        raise AdmissionArtifactGraphError(
            "GitHub admission requires root-owned quarantine custody"
        )
    source_proof_digest = _digest(
        receipt["source_proof_digest"],
        "receipt source proof digest",
    )
    manifest = load_verified_retained_manifest(cas, manifest_digest)
    if manifest["schema"] != "aragorn/github-manifest/v1":
        raise AdmissionArtifactGraphError(
            "GitHub admission graph requires a GitHub manifest"
        )
    ordered_edges, ordered_unresolved = _scan_admission_markdown(
        cas,
        manifest,
        scan_references=True,
        unresolved=set(),
    )
    return {
        "schema": "aragorn/admission-artifact-graph/v2",
        "authority": _AUTHORITY,
        "verifier": {
            "name": VERIFIER,
            "version": GITHUB_VERIFIER_VERSION,
            "implementation_digest": verifier_digest,
        },
        "profile": GITHUB_PROFILE,
        "root_manifest_digest": manifest_digest,
        "source_proof_digest": source_proof_digest,
        "quarantine_receipt_digest": receipt_digest,
        "gateway_profile_digest": gateway_profile_digest,
        "tree_digest": manifest["tree_digest"],
        "artifacts": [
            {key: entry[key] for key in ("path", "size", "digest", "executable")}
            for entry in manifest["files"]
        ],
        "edges": ordered_edges,
        "closure": {
            "scope": "artifact_graph",
            "profile": GITHUB_PROFILE,
            "status": "incomplete" if ordered_unresolved else "complete",
            "unresolved": ordered_unresolved,
        },
    }


def _scan_admission_markdown(
    cas: CAS,
    manifest: dict[str, Any],
    *,
    scan_references: bool,
    unresolved: set[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    source_by_path = {entry["path"]: entry for entry in manifest["files"]}
    edges: list[dict[str, Any]] = []
    for entry in manifest["files"]:
        path = entry["path"]
        digest = entry["digest"]
        if PurePosixPath(path).suffix.casefold() != ".md" or entry["executable"]:
            unresolved.add(f"UNSUPPORTED_ADMISSION_ARTIFACT:{path}:{digest}")
            continue
        if not scan_references:
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
    return ordered_edges, sorted(unresolved)


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
