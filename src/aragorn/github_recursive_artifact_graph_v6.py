"""V6 recursive admission closure with release runtime-candidate bytes."""

from __future__ import annotations

import hashlib
from io import BytesIO
from typing import Any

from . import github_recursive_artifact_graph_v4 as legacy
from .artifact_closure import (
    MAX_GRAPH_BYTES,
    canonical_json,
    load_verified_retained_manifest,
)
from .cas import CAS, CASError
from .github_release_asset import ZIP_SCHEMA as RELEASE_ASSET_ZIP_SCHEMA
from .github_release_asset import (
    GitHubReleaseAssetError,
    verify_github_release_asset_result,
)
from .zip_inventory import ZipInventoryError, verify_zip_inventory

SCHEMA = "aragorn/admission-artifact-graph/v6"
PROFILE = "recursive-github-markdown/v3"
VERIFIER_VERSION = "6"
_MAX_COMBINED_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_MATERIALIZED_DEPTH = 8
_RELEASE_PREFIX = "__aragorn_release_assets__"
_RUNTIME_BINDING_REASON = "GITHUB_RELEASE_ASSET_RUNTIME_BINDING_UNPROVEN"
_RUNTIME_CONSUMER_REASON = "GITHUB_RELEASE_ASSET_RUNTIME_CONSUMER_UNPROVEN"

GitHubRecursiveArtifactGraphError = legacy.GitHubRecursiveArtifactGraphError
discover_recursive_github_release_asset_urls = (
    legacy.discover_recursive_github_release_asset_urls
)
retain_expanded_github_manifest = legacy.retain_expanded_github_manifest


def release_assets_require_v6(cas: CAS, value: object) -> bool:
    """Return whether a strictly verified result set contains an inventory."""

    return any(
        item["result_schema"] == RELEASE_ASSET_ZIP_SCHEMA
        for item in _load_release_assets(cas, value).values()
    )


def retain_vendored_release_manifest(
    cas: CAS,
    source_manifest_digest: str,
    release_asset_result_digests: object,
) -> str:
    """Retain source plus exact GitHub-digest-backed inventory archives."""

    source_digest = legacy._digest(
        source_manifest_digest,
        "source manifest digest",
    )
    source_manifest = load_verified_retained_manifest(cas, source_digest)
    release_assets = _load_release_assets(
        cas,
        release_asset_result_digests,
    )
    vendored = _vendored_manifest(
        cas,
        source_manifest,
        release_assets,
        retain=True,
    )
    return source_digest if vendored is None else vendored[0]


def retain_recursive_github_artifact_graph(
    cas: CAS,
    manifest_digest: str,
    *,
    root_manifest_digest: str,
    expansion_digest: str,
    expansion_proof_digest: str | None,
    expected_quarantine_receipt_digest: str,
    expected_gateway_profile_digest: str,
    verifier_implementation_digest: str,
    release_asset_result_digests: tuple[str, ...] = (),
) -> str:
    """Retain v6 only when an inventory-backed release is present."""

    release_assets = _load_release_assets(cas, release_asset_result_digests)
    if not any(
        item["result_schema"] == RELEASE_ASSET_ZIP_SCHEMA
        for item in release_assets.values()
    ):
        return legacy.retain_recursive_github_artifact_graph(
            cas,
            manifest_digest,
            root_manifest_digest=root_manifest_digest,
            expansion_digest=expansion_digest,
            expansion_proof_digest=expansion_proof_digest,
            expected_quarantine_receipt_digest=(
                expected_quarantine_receipt_digest
            ),
            expected_gateway_profile_digest=expected_gateway_profile_digest,
            verifier_implementation_digest=verifier_implementation_digest,
            release_asset_result_digests=release_asset_result_digests,
        )
    document = _derive(
        cas,
        manifest_digest=legacy._digest(manifest_digest, "manifest digest"),
        root_manifest_digest=legacy._digest(
            root_manifest_digest,
            "root manifest digest",
        ),
        expansion_digest=legacy._digest(expansion_digest, "expansion digest"),
        expansion_proof_digest=legacy._optional_digest(
            expansion_proof_digest,
            "expansion proof digest",
        ),
        receipt_digest=legacy._digest(
            expected_quarantine_receipt_digest,
            "quarantine receipt digest",
        ),
        gateway_profile_digest=legacy._digest(
            expected_gateway_profile_digest,
            "gateway profile digest",
        ),
        verifier_digest=legacy._digest(
            verifier_implementation_digest,
            "verifier implementation digest",
        ),
        release_asset_result_digests=release_asset_result_digests,
        release_assets=release_assets,
        retain_derived_manifests=True,
    )
    raw = canonical_json(document)
    if len(raw) > MAX_GRAPH_BYTES:
        raise GitHubRecursiveArtifactGraphError(
            "recursive artifact graph exceeds its byte limit"
        )
    return cas.put(BytesIO(raw), max_bytes=len(raw))


def verify_recursive_github_artifact_graph(
    cas: CAS,
    graph_digest: str,
    *,
    expected_manifest_digest: str,
    expected_quarantine_receipt_digest: str,
    expected_gateway_profile_digest: str,
    expected_verifier_digest: str,
    expected_release_asset_result_digests: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Re-derive v6, delegating strictly verified all-v1 inputs to v4."""

    try:
        release_assets = _load_release_assets(
            cas,
            expected_release_asset_result_digests,
        )
        if not any(
            item["result_schema"] == RELEASE_ASSET_ZIP_SCHEMA
            for item in release_assets.values()
        ):
            return legacy.verify_recursive_github_artifact_graph(
                cas,
                graph_digest,
                expected_manifest_digest=expected_manifest_digest,
                expected_quarantine_receipt_digest=(
                    expected_quarantine_receipt_digest
                ),
                expected_gateway_profile_digest=expected_gateway_profile_digest,
                expected_verifier_digest=expected_verifier_digest,
                expected_release_asset_result_digests=(
                    expected_release_asset_result_digests
                ),
            )
        raw = cas.read(
            legacy._digest(graph_digest, "artifact graph digest"),
            max_bytes=MAX_GRAPH_BYTES,
        )
        graph = legacy._canonical_document(raw, "recursive artifact graph")
        if graph.get("schema") != SCHEMA:
            raise GitHubRecursiveArtifactGraphError(
                "recursive artifact graph schema is unsupported"
            )
        expected = _derive(
            cas,
            manifest_digest=legacy._digest(
                expected_manifest_digest,
                "expected manifest digest",
            ),
            root_manifest_digest=legacy._digest(
                graph.get("root_github_manifest_digest"),
                "root GitHub manifest digest",
            ),
            expansion_digest=legacy._digest(
                graph.get("expansion_digest"),
                "expansion digest",
            ),
            expansion_proof_digest=legacy._optional_digest(
                graph.get("expansion_proof_digest"),
                "expansion proof digest",
            ),
            receipt_digest=legacy._digest(
                expected_quarantine_receipt_digest,
                "expected quarantine receipt digest",
            ),
            gateway_profile_digest=legacy._digest(
                expected_gateway_profile_digest,
                "expected gateway profile digest",
            ),
            verifier_digest=legacy._digest(
                expected_verifier_digest,
                "expected verifier digest",
            ),
            release_asset_result_digests=(
                expected_release_asset_result_digests
            ),
            release_assets=release_assets,
            retain_derived_manifests=False,
        )
        if raw != canonical_json(expected):
            raise GitHubRecursiveArtifactGraphError(
                "recursive artifact graph does not match retained source"
            )
        return graph
    except GitHubRecursiveArtifactGraphError:
        raise
    except (
        CASError,
        GitHubReleaseAssetError,
        ZipInventoryError,
        TypeError,
        ValueError,
    ) as exc:
        raise GitHubRecursiveArtifactGraphError(
            f"cannot verify recursive GitHub artifact graph: {exc}"
        ) from exc


def _derive(
    cas: CAS,
    *,
    manifest_digest: str,
    root_manifest_digest: str,
    expansion_digest: str,
    expansion_proof_digest: str | None,
    receipt_digest: str,
    gateway_profile_digest: str,
    verifier_digest: str,
    release_asset_result_digests: tuple[str, ...],
    release_assets: dict[str, dict[str, Any]],
    retain_derived_manifests: bool,
) -> dict[str, Any]:
    graph = legacy._derive(
        cas,
        manifest_digest=manifest_digest,
        root_manifest_digest=root_manifest_digest,
        expansion_digest=expansion_digest,
        expansion_proof_digest=expansion_proof_digest,
        receipt_digest=receipt_digest,
        gateway_profile_digest=gateway_profile_digest,
        verifier_digest=verifier_digest,
        release_asset_result_digests=release_asset_result_digests,
    )
    source_manifest = load_verified_retained_manifest(
        cas,
        manifest_digest,
    )
    vendored = _vendored_manifest(
        cas,
        source_manifest,
        release_assets,
        retain=retain_derived_manifests,
    )
    candidate_manifest_digest = manifest_digest if vendored is None else vendored[0]
    candidate_manifest = load_verified_retained_manifest(
        cas,
        candidate_manifest_digest,
    )

    unresolved = set(graph["closure"]["unresolved"])
    for edge in graph["edges"]:
        release_asset = release_assets.get(edge.get("literal"))
        if release_asset is None:
            continue
        target = dict(edge["target"])
        target["inventory_digest"] = release_asset["inventory_digest"]
        target["runtime_path"] = (
            _vendored_path(release_asset)
            if release_asset["runtime_vendored"]
            else None
        )
        edge["target"] = target
        if target["github_digest"] is None:
            unresolved.discard(_edge_reason(edge))
            edge["reason_code"] = "GITHUB_RELEASE_ASSET_DIGEST_UNAVAILABLE"
            unresolved.add(_edge_reason(edge))
            continue
        if release_asset["runtime_vendored"]:
            unresolved.discard(_edge_reason(edge))
            edge["status"] = "unresolved"
            edge["reason_code"] = _RUNTIME_CONSUMER_REASON
            unresolved.add(_edge_reason(edge))
            continue
        if release_asset["analysis_captured"]:
            unresolved.discard(_edge_reason(edge))
            edge["status"] = "unresolved"
            edge["reason_code"] = _RUNTIME_BINDING_REASON
            unresolved.add(_edge_reason(edge))

    analysis_manifest_digest, analysis_tree_digest = _analysis_manifest(
        cas,
        source_manifest,
        release_assets,
        retain=retain_derived_manifests,
    )
    graph.update(
        {
            "schema": SCHEMA,
            "verifier": {
                "name": legacy.VERIFIER,
                "version": VERIFIER_VERSION,
                "implementation_digest": verifier_digest,
            },
            "profile": PROFILE,
            "runtime_candidate_manifest_digest": candidate_manifest_digest,
            "runtime_candidate_tree_digest": candidate_manifest["tree_digest"],
            "runtime_candidate_artifacts": candidate_manifest["files"],
            "analysis_manifest_digest": analysis_manifest_digest,
            "analysis_tree_digest": analysis_tree_digest,
        }
    )
    graph["coverage"]["unresolved_required"] = len(unresolved)
    if not unresolved:
        raise GitHubRecursiveArtifactGraphError(
            "v6 release closure unexpectedly has no unresolved consumer"
        )
    graph["closure"] = {
        "scope": "artifact_graph",
        "profile": PROFILE,
        "status": "incomplete",
        "unresolved": sorted(unresolved),
    }
    return graph


def _edge_reason(edge: dict[str, Any]) -> str:
    return (
        f"{edge['reason_code']}:{edge['source_path']}:{edge['byte_offset']}:"
        f"{edge['literal_digest']}"
    )


def _load_release_assets(
    cas: CAS,
    value: object,
) -> dict[str, dict[str, Any]]:
    if (
        not isinstance(value, (list, tuple))
        or len(value) > legacy._MAX_RELEASE_ASSETS
    ):
        raise GitHubRecursiveArtifactGraphError(
            "release asset result digest list is invalid"
        )
    digests = [
        legacy._digest(item, "release asset result digest") for item in value
    ]
    if len(digests) != len(set(digests)):
        raise GitHubRecursiveArtifactGraphError(
            "release asset result digest list contains duplicates"
        )
    evidence_cas = CAS(cas.root, read_only=True)
    targets: dict[str, dict[str, Any]] = {}
    for result_digest in sorted(digests):
        result = legacy._canonical_document(
            cas.read(
                result_digest,
                max_bytes=legacy._MAX_RELEASE_ASSET_RESULT_BYTES,
            ),
            "GitHub release asset result",
        )
        source = result.get("source")
        asset = result.get("asset")
        transport = result.get("transport")
        if not all(isinstance(item, dict) for item in (source, asset, transport)):
            raise GitHubRecursiveArtifactGraphError(
                "GitHub release asset result is invalid"
            )
        try:
            verified = verify_github_release_asset_result(
                result,
                evidence_cas=evidence_cas,
                expected_url=source.get("url"),
                expected_release_id=asset.get("release_id"),
                expected_asset_id=asset.get("asset_id"),
                expected_digest=asset.get("digest"),
                expected_github_digest=asset.get("github_digest"),
                expected_content_type=asset.get("content_type"),
                expected_redirected=transport.get("redirected"),
                require_zip_inventory=True,
            )
        except GitHubReleaseAssetError as exc:
            raise GitHubRecursiveArtifactGraphError(
                f"cannot verify retained GitHub release asset result: {exc}"
            ) from exc
        url = verified["source"]["url"]
        if url in targets:
            raise GitHubRecursiveArtifactGraphError(
                "release asset results repeat a canonical URL"
            )
        inventory_digest = verified.get("inventory_digest")
        inventory = (
            verify_zip_inventory(
                evidence_cas,
                inventory_digest,
                expected_archive_digest=verified["asset"]["digest"],
                expected_archive_name=verified["asset"]["name"],
            )
            if inventory_digest is not None
            else None
        )
        is_archive = (
            inventory is not None
            or verified["asset"]["name"]
            .casefold()
            .endswith(legacy._ARCHIVE_SUFFIXES)
        )
        targets[url] = {
            "result_schema": verified["schema"],
            "name": verified["asset"]["name"],
            "size": verified["asset"]["size"],
            "inventory_digest": inventory_digest,
            "inventory": inventory,
            "runtime_vendored": (
                verified["asset"]["github_digest"] is not None
                and inventory is not None
                and is_archive
            ),
            "analysis_captured": (
                verified["asset"]["github_digest"] is not None
                and (inventory is not None or not is_archive)
            ),
            "target": {
                "release_id": verified["asset"]["release_id"],
                "asset_id": verified["asset"]["asset_id"],
                "digest": verified["asset"]["digest"],
            },
        }
    return targets


def _vendored_path(release_asset: dict[str, Any]) -> str:
    target = release_asset["target"]
    return (
        f"{_RELEASE_PREFIX}/{target['release_id']}/{target['asset_id']}/"
        f"raw/{release_asset['name']}"
    )


def _vendored_manifest(
    cas: CAS,
    source_manifest: dict[str, Any],
    release_assets: dict[str, dict[str, Any]],
    *,
    retain: bool,
) -> tuple[str, str] | None:
    eligible = [
        release_assets[url]
        for url in sorted(release_assets)
        if release_assets[url]["runtime_vendored"]
    ]
    if not eligible:
        return None
    files = _manifest_files(source_manifest)
    identities: set[tuple[int, int]] = set()
    for release_asset in eligible:
        _add_identity(identities, release_asset)
        files.append(
            {
                "path": _vendored_path(release_asset),
                "size": release_asset["size"],
                "digest": release_asset["target"]["digest"],
                "executable": False,
            }
        )
    return _retain_combined_manifest(
        cas,
        source_manifest,
        files,
        purpose="runtime",
        retain=retain,
    )


def _analysis_manifest(
    cas: CAS,
    source_manifest: dict[str, Any],
    release_assets: dict[str, dict[str, Any]],
    *,
    retain: bool,
) -> tuple[str, str]:
    files = _manifest_files(source_manifest)
    identities: set[tuple[int, int]] = set()
    for url in sorted(release_assets):
        release_asset = release_assets[url]
        if not release_asset["analysis_captured"]:
            continue
        _add_identity(identities, release_asset)
        target = release_asset["target"]
        prefix = (
            f"{_RELEASE_PREFIX}/"
            f"{target['release_id']}/{target['asset_id']}"
        )
        inventory = release_asset["inventory"]
        if inventory is None:
            files.append(
                {
                    "path": f"{prefix}/raw/{release_asset['name']}",
                    "size": release_asset["size"],
                    "digest": target["digest"],
                    "executable": False,
                }
            )
        else:
            for member in inventory["files"]:
                files.append(
                    {
                        "path": f"{prefix}/members/{member['path']}",
                        "size": member["size"],
                        "digest": member["digest"],
                        "executable": False,
                    }
                )

    return _retain_combined_manifest(
        cas,
        source_manifest,
        files,
        purpose="analysis",
        retain=retain,
    )


def _manifest_files(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    files = [
        {key: entry[key] for key in ("path", "size", "digest", "executable")}
        for entry in manifest["files"]
    ]
    reserved = _RELEASE_PREFIX.casefold()
    if any(
        entry["path"].casefold() == reserved
        or entry["path"].casefold().startswith(f"{reserved}/")
        for entry in files
    ):
        raise GitHubRecursiveArtifactGraphError(
            "source manifest occupies the reserved release namespace"
        )
    return files


def _add_identity(
    identities: set[tuple[int, int]],
    release_asset: dict[str, Any],
) -> None:
    target = release_asset["target"]
    identity = (target["release_id"], target["asset_id"])
    if identity in identities:
        raise GitHubRecursiveArtifactGraphError(
            "vendored release assets repeat a GitHub identity"
        )
    identities.add(identity)


def _retain_combined_manifest(
    cas: CAS,
    source_manifest: dict[str, Any],
    files: list[dict[str, Any]],
    *,
    purpose: str,
    retain: bool,
) -> tuple[str, str]:
    files.sort(key=lambda item: item["path"])
    _validate_combined_analysis_files(files)
    tree_digest = "sha256:" + hashlib.sha256(canonical_json(files)).hexdigest()
    document = {
        "schema": "aragorn/manifest/v1",
        "source": {
            "kind": "local",
            "path": (
                f"/aragorn/{purpose}/github-release-assets/"
                f"{source_manifest['tree_digest'].removeprefix('sha256:')}"
            ),
        },
        "tree_digest": tree_digest,
        "files": files,
        "closure": {"scope": "source_tree", "status": "complete"},
    }
    raw = canonical_json(document)
    if len(raw) > _MAX_COMBINED_MANIFEST_BYTES:
        raise GitHubRecursiveArtifactGraphError(
            f"combined {purpose} manifest exceeds its byte limit"
        )
    manifest_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if retain:
        cas.put_expected(
            BytesIO(raw),
            expected_digest=manifest_digest,
            max_bytes=len(raw),
        )
    if load_verified_retained_manifest(cas, manifest_digest) != document:
        raise GitHubRecursiveArtifactGraphError(
            f"combined {purpose} manifest changed during validation"
        )
    return manifest_digest, tree_digest


def _validate_combined_analysis_files(files: list[dict[str, Any]]) -> None:
    if not 1 <= len(files) <= 10_000:
        raise GitHubRecursiveArtifactGraphError(
            "combined analysis manifest file count exceeds its bound"
        )
    folded_paths: set[str] = set()
    total_bytes = 0
    for entry in files:
        folded = entry["path"].casefold()
        if len(folded.split("/")) - 1 > _MAX_MATERIALIZED_DEPTH:
            raise GitHubRecursiveArtifactGraphError(
                "combined manifest exceeds the materialization depth"
            )
        if folded in folded_paths:
            raise GitHubRecursiveArtifactGraphError(
                "combined analysis manifest repeats a path"
            )
        folded_paths.add(folded)
        size = entry["size"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= 16 * 1024 * 1024
        ):
            raise GitHubRecursiveArtifactGraphError(
                "combined analysis manifest file size exceeds its bound"
            )
        total_bytes += size
        if total_bytes > 128 * 1024 * 1024:
            raise GitHubRecursiveArtifactGraphError(
                "combined analysis manifest total bytes exceed their bound"
            )
    for folded in folded_paths:
        parts = folded.split("/")
        if any(
            "/".join(parts[:depth]) in folded_paths
            for depth in range(1, len(parts))
        ):
            raise GitHubRecursiveArtifactGraphError(
                "combined analysis manifest contains a path-prefix collision"
            )
