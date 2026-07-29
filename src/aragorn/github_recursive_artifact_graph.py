"""Proof-bound recursive admission closure for GitHub Agent Skills."""

from __future__ import annotations

import hashlib
import json
import re
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any

from .artifact_closure import (
    MAX_GRAPH_BYTES,
    MAX_SCANNED_TEXT_BYTES,
    ReferenceBudgetExceeded,
    canonical_json,
    exact_raw_github_fetch_target,
    load_verified_retained_manifest,
    parse_immutable_github_reference,
    scan_retained_text_references,
)
from .cas import CAS, CASError
from .github_expansion_proof import (
    GitHubExpansionProofError,
    verify_github_expansion_proof,
)
from .github_quarantine_receipt import (
    LINUX_CONTAINMENT_PROFILE,
    GitHubQuarantineReceiptError,
    verify_github_quarantine_receipt,
)

PROFILE = "recursive-github-markdown/v1"
VERIFIER = "aragorn/admission-artifact-graph-verifier"
VERIFIER_VERSION = "3"
SCHEMA = "aragorn/admission-artifact-graph/v3"
_AUTHORITY = "CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
_REQUIRED_BROKER_UID = 0
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_EXPANSION_BYTES = 16 * 1024 * 1024
_MAX_EDGES = 10_000
_MATERIALIZED_PREFIX = "__aragorn_expanded__"


class GitHubRecursiveArtifactGraphError(ValueError):
    """Recursive GitHub admission evidence is malformed or incomplete."""


def retain_expanded_github_manifest(
    cas: CAS,
    expansion_digest: str,
) -> str:
    """Retain the exact installable root-plus-expanded byte manifest."""

    expansion_digest = _digest(expansion_digest, "expansion digest")
    expansion = _load_expansion(cas, expansion_digest)
    manifest = _derive_expanded_manifest(cas, expansion)
    raw = canonical_json(manifest)
    return cas.put(BytesIO(raw), max_bytes=len(raw))


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
) -> str:
    """Retain recursive closure bound to gateway custody and Git proofs."""

    document = _derive(
        cas,
        manifest_digest=_digest(manifest_digest, "manifest digest"),
        root_manifest_digest=_digest(
            root_manifest_digest,
            "root manifest digest",
        ),
        expansion_digest=_digest(expansion_digest, "expansion digest"),
        expansion_proof_digest=_optional_digest(
            expansion_proof_digest,
            "expansion proof digest",
        ),
        receipt_digest=_digest(
            expected_quarantine_receipt_digest,
            "quarantine receipt digest",
        ),
        gateway_profile_digest=_digest(
            expected_gateway_profile_digest,
            "gateway profile digest",
        ),
        verifier_digest=_digest(
            verifier_implementation_digest,
            "verifier implementation digest",
        ),
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
) -> dict[str, Any]:
    """Re-derive recursive closure without trusting the worker's graph."""

    try:
        raw = cas.read(
            _digest(graph_digest, "artifact graph digest"),
            max_bytes=MAX_GRAPH_BYTES,
        )
        graph = _canonical_document(raw, "recursive artifact graph")
        if graph.get("schema") != SCHEMA:
            raise GitHubRecursiveArtifactGraphError(
                "recursive artifact graph schema is unsupported"
            )
        expected = _derive(
            cas,
            manifest_digest=_digest(
                expected_manifest_digest,
                "expected manifest digest",
            ),
            root_manifest_digest=_digest(
                graph.get("root_github_manifest_digest"),
                "root GitHub manifest digest",
            ),
            expansion_digest=_digest(
                graph.get("expansion_digest"),
                "expansion digest",
            ),
            expansion_proof_digest=_optional_digest(
                graph.get("expansion_proof_digest"),
                "expansion proof digest",
            ),
            receipt_digest=_digest(
                expected_quarantine_receipt_digest,
                "expected quarantine receipt digest",
            ),
            gateway_profile_digest=_digest(
                expected_gateway_profile_digest,
                "expected gateway profile digest",
            ),
            verifier_digest=_digest(
                expected_verifier_digest,
                "expected verifier digest",
            ),
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
        GitHubExpansionProofError,
        GitHubQuarantineReceiptError,
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
) -> dict[str, Any]:
    receipt = verify_github_quarantine_receipt(
        cas,
        receipt_digest,
        expected_manifest_digest=root_manifest_digest,
        expected_gateway_profile_digest=gateway_profile_digest,
    )
    if (
        receipt["containment_profile"] != LINUX_CONTAINMENT_PROFILE
        or receipt["protected_cas"]["owner_uid"] != _REQUIRED_BROKER_UID
    ):
        raise GitHubRecursiveArtifactGraphError(
            "recursive GitHub admission requires root-owned Linux gateway custody"
        )
    expansion = _load_expansion(cas, expansion_digest)
    if expansion.get("root_manifest_digest") != root_manifest_digest:
        raise GitHubRecursiveArtifactGraphError(
            "expansion is bound to another root manifest"
        )
    expected_manifest = _derive_expanded_manifest(cas, expansion)
    retained_manifest = load_verified_retained_manifest(cas, manifest_digest)
    if retained_manifest != expected_manifest:
        raise GitHubRecursiveArtifactGraphError(
            "installable manifest does not match recursive expansion bytes"
        )

    closure = expansion.get("closure")
    complete = (
        isinstance(closure, dict)
        and closure.get("status") == "complete"
        and closure.get("unresolved") == []
    )
    has_expanded_objects = bool(expansion.get("objects"))
    if complete or has_expanded_objects:
        if expansion_proof_digest is None:
            raise GitHubRecursiveArtifactGraphError(
                "retained expansion objects require offline Git membership proof"
            )
        verify_github_expansion_proof(
            cas,
            expansion_proof_digest,
            expected_expansion_digest=expansion_digest,
            expected_root_manifest_digest=root_manifest_digest,
        )
    elif expansion_proof_digest is not None:
        raise GitHubRecursiveArtifactGraphError(
            "empty incomplete expansion cannot claim membership proof"
        )

    edges, scan_unresolved, static_total, static_captured = _scan_recursive(
        cas,
        expansion,
    )
    unresolved = set(scan_unresolved)
    if not complete:
        for reason in _expansion_unresolved(closure):
            unresolved.add(
                f"EXPANSION_{reason['reason_code']}:{reason['subject']}"
            )
    ordered_unresolved = sorted(unresolved)
    return {
        "schema": SCHEMA,
        "authority": _AUTHORITY,
        "verifier": {
            "name": VERIFIER,
            "version": VERIFIER_VERSION,
            "implementation_digest": verifier_digest,
        },
        "profile": PROFILE,
        "root_manifest_digest": manifest_digest,
        "root_github_manifest_digest": root_manifest_digest,
        "source_proof_digest": receipt["source_proof_digest"],
        "quarantine_receipt_digest": receipt_digest,
        "gateway_profile_digest": gateway_profile_digest,
        "expansion_digest": expansion_digest,
        "expansion_proof_digest": expansion_proof_digest,
        "tree_digest": retained_manifest["tree_digest"],
        "artifacts": retained_manifest["files"],
        "edges": edges,
        "coverage": {
            "statically_resolvable": {
                "captured": static_captured,
                "total": static_total,
            },
            "unresolved_required": len(ordered_unresolved),
        },
        "closure": {
            "scope": "artifact_graph",
            "profile": PROFILE,
            "status": "incomplete" if ordered_unresolved else "complete",
            "unresolved": ordered_unresolved,
        },
    }


def _derive_expanded_manifest(
    cas: CAS,
    expansion: dict[str, Any],
) -> dict[str, Any]:
    root_digest = _digest(
        expansion.get("root_manifest_digest"),
        "expansion root manifest digest",
    )
    root = load_verified_retained_manifest(cas, root_digest)
    if root.get("schema") != "aragorn/github-manifest/v1":
        raise GitHubRecursiveArtifactGraphError(
            "recursive expansion requires a GitHub root manifest"
        )
    source = root["source"]
    expansion_source = expansion.get("source")
    if not isinstance(expansion_source, dict) or any(
        expansion_source.get(field) != source.get(field)
        for field in (
            "host",
            "owner",
            "repository",
            "commit",
            "commit_tree",
            "skill_path",
            "api_version",
        )
    ):
        raise GitHubRecursiveArtifactGraphError(
            "expansion source does not match its GitHub root"
        )
    files = [
        {
            key: entry[key]
            for key in ("path", "size", "digest", "executable")
        }
        for entry in root["files"]
    ]
    objects = expansion.get("objects")
    if not isinstance(objects, list) or len(objects) > 256:
        raise GitHubRecursiveArtifactGraphError(
            "expansion object count exceeds its bound"
        )
    for item in objects:
        if not isinstance(item, dict):
            raise GitHubRecursiveArtifactGraphError("expansion object is invalid")
        path = _materialized_path(item, source["commit"])
        files.append(
            {
                "path": path,
                "size": item.get("size"),
                "digest": item.get("digest"),
                "executable": item.get("executable"),
            }
        )
    files.sort(key=lambda item: item["path"])
    if len(files) != len({item["path"].casefold() for item in files}):
        raise GitHubRecursiveArtifactGraphError(
            "expanded install manifest repeats a path"
        )
    tree_digest = "sha256:" + hashlib.sha256(canonical_json(files)).hexdigest()
    manifest = {
        "schema": "aragorn/manifest/v1",
        "source": {
            "kind": "local",
            "path": (
                f"/aragorn/github/{source['owner']}/{source['repository']}/"
                f"{source['commit']}/{source['skill_path']}"
            ),
        },
        "tree_digest": tree_digest,
        "files": files,
        "closure": {"scope": "source_tree", "status": "complete"},
    }
    # Reuse the production manifest validator for all byte, path, and size bounds.
    raw = canonical_json(manifest)
    temporary_digest = cas.put(BytesIO(raw), max_bytes=len(raw))
    validated = load_verified_retained_manifest(cas, temporary_digest)
    if validated != manifest:
        raise GitHubRecursiveArtifactGraphError(
            "expanded install manifest changed during validation"
        )
    return manifest


def _scan_recursive(
    cas: CAS,
    expansion: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], int, int]:
    root = load_verified_retained_manifest(
        cas,
        expansion["root_manifest_digest"],
    )
    source = root["source"]
    artifacts: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in root["files"]:
        repository_path = _repository_path(source["skill_path"], entry["path"])
        artifacts[(source["commit"], repository_path)] = {
            **entry,
            "installed_path": entry["path"],
            "repository_path": repository_path,
            "commit": source["commit"],
        }
    for item in expansion["objects"]:
        identity = (item["commit"], item["repository_path"])
        artifacts[identity] = {
            key: item[key]
            for key in ("size", "digest", "executable")
        } | {
            "installed_path": _materialized_path(item, source["commit"]),
            "repository_path": item["repository_path"],
            "commit": item["commit"],
        }

    edges: list[dict[str, Any]] = []
    unresolved: set[str] = set()
    static_total = 0
    static_captured = 0
    for identity in sorted(artifacts):
        artifact = artifacts[identity]
        installed_path = artifact["installed_path"]
        suffix = PurePosixPath(installed_path).suffix.casefold()
        if suffix != ".md" or artifact["executable"]:
            unresolved.add(
                f"UNSUPPORTED_ADMISSION_ARTIFACT:{installed_path}:"
                f"{artifact['digest']}"
            )
            continue
        if artifact["size"] > MAX_SCANNED_TEXT_BYTES:
            unresolved.add(
                f"OVERSIZED_ADMISSION_MARKDOWN:{installed_path}:"
                f"{artifact['digest']}"
            )
            continue
        content = cas.read(artifact["digest"], max_bytes=artifact["size"])
        if b"\0" in content:
            unresolved.add(
                f"NUL_CONTAINING_ADMISSION_MARKDOWN:{installed_path}:"
                f"{artifact['digest']}"
            )
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            unresolved.add(
                f"NON_UTF8_ADMISSION_MARKDOWN:{installed_path}:"
                f"{artifact['digest']}"
            )
            continue
        same_commit = {
            value["repository_path"]: {
                "path": value["repository_path"],
                "size": value["size"],
                "digest": value["digest"],
                "executable": value["executable"],
            }
            for key, value in artifacts.items()
            if key[0] == identity[0]
        }
        scan_source = {
            **source,
            "commit": identity[0],
            "skill_path": ".",
        }
        scan_entry = {
            "path": artifact["repository_path"],
            "size": artifact["size"],
            "digest": artifact["digest"],
            "executable": artifact["executable"],
        }
        try:
            scanned = scan_retained_text_references(
                text,
                source_entry=scan_entry,
                source=scan_source,
                source_by_path=same_commit,
            )
        except ReferenceBudgetExceeded:
            unresolved.add(
                f"ADMISSION_REFERENCE_BUDGET_EXCEEDED:{installed_path}:"
                f"{artifact['digest']}"
            )
            continue
        if len(edges) + len(scanned) > _MAX_EDGES:
            unresolved.add(
                f"ADMISSION_REFERENCE_BUDGET_EXCEEDED:{installed_path}:"
                f"{artifact['digest']}"
            )
            continue
        immutable_targets = {
            (target["commit"], target["path"])
            for edge in scanned
            if edge["reference_kind"] == "github_immutable"
            for target in [parse_immutable_github_reference(edge["literal"])]
            if target is not None
            and target["owner"] == source["owner"]
            and target["repository"] == source["repository"]
        }
        for edge in scanned:
            if edge["reference_kind"] == "dynamic_command":
                target = exact_raw_github_fetch_target(edge["literal"])
                if (
                    target is not None
                    and (target["commit"], target["path"]) in immutable_targets
                    and target["owner"] == source["owner"]
                    and target["repository"] == source["repository"]
                ):
                    continue
            transformed = dict(edge)
            transformed["source_path"] = installed_path
            if edge["status"] == "resolved" and edge["target"] is not None:
                target_path = edge["target"]["path"]
                target = artifacts.get((identity[0], target_path))
                if target is not None:
                    transformed["target"] = {
                        "path": target["installed_path"],
                        "digest": target["digest"],
                    }
            elif edge["reference_kind"] == "github_immutable":
                target_value = parse_immutable_github_reference(edge["literal"])
                if (
                    target_value is not None
                    and target_value["owner"] == source["owner"]
                    and target_value["repository"] == source["repository"]
                ):
                    target = artifacts.get(
                        (target_value["commit"], target_value["path"])
                    )
                    if target is not None:
                        transformed.update(
                            {
                                "status": "resolved",
                                "reason_code": None,
                                "target": {
                                    "path": target["installed_path"],
                                    "digest": target["digest"],
                                },
                            }
                        )
            if transformed["reference_kind"] in {"local", "github_immutable"}:
                static_total += 1
                static_captured += transformed["status"] == "resolved"
            if transformed["status"] == "unresolved":
                unresolved.add(
                    f"{transformed['reason_code']}:{installed_path}:"
                    f"{transformed['byte_offset']}:"
                    f"{transformed['literal_digest']}"
                )
            edges.append(transformed)
    edges.sort(
        key=lambda edge: (
            edge["source_path"],
            edge["byte_offset"],
            edge["literal_digest"],
            edge["reference_kind"],
            edge["status"],
        )
    )
    return edges, sorted(unresolved), static_total, static_captured


def _materialized_path(item: dict[str, Any], root_commit: str) -> str:
    commit = item.get("commit")
    repository_path = item.get("repository_path")
    expected = (
        f"{_MATERIALIZED_PREFIX}/"
        f"{'' if commit == root_commit else f'{commit}/'}"
        f"{repository_path}"
    )
    if item.get("materialized_path") != expected:
        raise GitHubRecursiveArtifactGraphError(
            "expansion materialized path is invalid"
        )
    return expected


def _repository_path(skill_path: str, relative_path: str) -> str:
    return relative_path if skill_path == "." else f"{skill_path}/{relative_path}"


def _expansion_unresolved(value: object) -> list[dict[str, str]]:
    if not isinstance(value, dict) or value.get("status") != "incomplete":
        raise GitHubRecursiveArtifactGraphError(
            "expansion closure status is invalid"
        )
    reasons = value.get("unresolved")
    if not isinstance(reasons, list) or not reasons:
        raise GitHubRecursiveArtifactGraphError(
            "incomplete expansion omits unresolved reasons"
        )
    result = []
    for reason in reasons:
        if (
            not isinstance(reason, dict)
            or set(reason) != {"reason_code", "subject"}
            or not all(isinstance(item, str) and item for item in reason.values())
        ):
            raise GitHubRecursiveArtifactGraphError(
                "expansion unresolved reason is invalid"
            )
        result.append(reason)
    return result


def _load_expansion(cas: CAS, digest: str) -> dict[str, Any]:
    raw = cas.read(digest, max_bytes=_MAX_EXPANSION_BYTES)
    expansion = _canonical_document(raw, "GitHub expansion")
    if (
        expansion.get("schema") != "aragorn/github-expansion/v1"
        or expansion.get("profile") != "phase0-exact-github-blob-expansion/v1"
    ):
        raise GitHubRecursiveArtifactGraphError(
            "GitHub expansion profile is unsupported for admission"
        )
    return expansion


def _canonical_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GitHubRecursiveArtifactGraphError(
            f"{label} is invalid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise GitHubRecursiveArtifactGraphError(
            f"{label} must use canonical JSON"
        )
    return document


def _optional_digest(value: object, label: str) -> str | None:
    return None if value is None else _digest(value, label)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise GitHubRecursiveArtifactGraphError(f"{label} is invalid")
    return value


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GitHubRecursiveArtifactGraphError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_nonfinite(value: str) -> None:
    raise GitHubRecursiveArtifactGraphError(f"non-finite JSON number: {value}")
