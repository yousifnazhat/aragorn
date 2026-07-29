"""Offline Git membership proof for recursively expanded GitHub blobs."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from io import BytesIO
from typing import Any

from .artifact_closure import canonical_json, load_verified_retained_manifest
from .cas import CAS, CASError
from .github_git_protocol import GitProtocolError, parse_commit_tree, parse_tree

SCHEMA = "aragorn/github-expansion-proof/v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OID = re.compile(r"[0-9a-f]{40}\Z")
_MAX_RECORD_BYTES = 16 * 1024 * 1024
_MAX_OBJECT_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_OBJECT_BYTES = 32 * 1024 * 1024
_MAX_OBJECTS = 20_000
_MAX_TARGETS = 256
_MAX_TREE_ENTRIES = 10_000
_PROOF_KEYS = {
    "schema",
    "expansion_digest",
    "root_manifest_digest",
    "targets",
    "objects",
}
_TARGET_KEYS = {
    "commit",
    "commit_tree",
    "repository_path",
    "size",
    "digest",
    "git_blob_sha1",
    "executable",
}
_OBJECT_KEYS = {"type", "oid", "size", "digest"}
_TYPE_ORDER = {"commit": 0, "tree": 1}

_ObjectKey = tuple[str, str]


class GitHubExpansionProofError(ValueError):
    """A recursive GitHub expansion proof is invalid or incomplete."""


def retain_github_expansion_proof(
    cas: CAS,
    expansion_digest: str,
    root_manifest_digest: str,
    raw_objects: Mapping[_ObjectKey, bytes],
) -> str:
    """Retain only the raw Git objects needed to prove expanded blobs."""

    try:
        expansion_digest = _digest(expansion_digest, "expansion digest")
        root_manifest_digest = _digest(
            root_manifest_digest,
            "root manifest digest",
        )
        expansion = _load_expansion(cas, expansion_digest)
        targets = _expected_targets(
            cas,
            expansion,
            root_manifest_digest=root_manifest_digest,
        )
        payloads = _snapshot_raw_objects(raw_objects)
        used = _verify_targets(cas, targets, payloads)
        records = []
        for object_type, oid in sorted(
            used,
            key=lambda item: (_TYPE_ORDER[item[0]], item[1]),
        ):
            payload = payloads[(object_type, oid)]
            digest = _sha256(payload)
            cas.put_expected(
                BytesIO(payload),
                expected_digest=digest,
                max_bytes=len(payload),
            )
            records.append(
                {
                    "type": object_type,
                    "oid": oid,
                    "size": len(payload),
                    "digest": digest,
                }
            )
        proof = {
            "schema": SCHEMA,
            "expansion_digest": expansion_digest,
            "root_manifest_digest": root_manifest_digest,
            "targets": targets,
            "objects": records,
        }
        raw = canonical_json(proof)
        if len(raw) > _MAX_RECORD_BYTES:
            raise GitHubExpansionProofError("expansion proof exceeds 16 MiB")
        return cas.put(BytesIO(raw), max_bytes=len(raw))
    except GitHubExpansionProofError:
        raise
    except (CASError, GitProtocolError, TypeError, ValueError) as exc:
        raise GitHubExpansionProofError(
            f"cannot retain GitHub expansion proof: {exc}"
        ) from exc


def verify_github_expansion_proof(
    cas: CAS,
    proof_digest: str,
    *,
    expected_expansion_digest: str,
    expected_root_manifest_digest: str,
) -> dict[str, Any]:
    """Replay one expansion proof and every referenced Git object."""

    try:
        proof_digest = _digest(proof_digest, "expansion proof digest")
        expansion_digest = _digest(
            expected_expansion_digest,
            "expected expansion digest",
        )
        root_manifest_digest = _digest(
            expected_root_manifest_digest,
            "expected root manifest digest",
        )
        raw = cas.read(proof_digest, max_bytes=_MAX_RECORD_BYTES)
        proof = _canonical_document(raw, "expansion proof")
        if set(proof) != _PROOF_KEYS or proof.get("schema") != SCHEMA:
            raise GitHubExpansionProofError(
                "expansion proof has missing, unknown, or unsupported fields"
            )
        if (
            proof.get("expansion_digest") != expansion_digest
            or proof.get("root_manifest_digest") != root_manifest_digest
        ):
            raise GitHubExpansionProofError(
                "expansion proof is bound to different source evidence"
            )

        expansion = _load_expansion(cas, expansion_digest)
        targets = _expected_targets(
            cas,
            expansion,
            root_manifest_digest=root_manifest_digest,
        )
        if proof.get("targets") != targets:
            raise GitHubExpansionProofError(
                "expansion proof targets do not match the expansion"
            )
        payloads = _load_proof_objects(cas, proof.get("objects"))
        used = _verify_targets(cas, targets, payloads)
        if used != set(payloads):
            raise GitHubExpansionProofError(
                "expansion proof contains unused Git objects"
            )
        return proof
    except GitHubExpansionProofError:
        raise
    except (CASError, GitProtocolError, TypeError, ValueError) as exc:
        raise GitHubExpansionProofError(
            f"cannot verify GitHub expansion proof: {exc}"
        ) from exc


def expansion_proof_closure(
    cas: CAS,
    proof_digest: str,
    *,
    expected_expansion_digest: str,
    expected_root_manifest_digest: str,
) -> dict[str, int]:
    """Return the exact proof-record and raw-object CAS closure."""

    proof = verify_github_expansion_proof(
        cas,
        proof_digest,
        expected_expansion_digest=expected_expansion_digest,
        expected_root_manifest_digest=expected_root_manifest_digest,
    )
    raw = cas.read(proof_digest, max_bytes=_MAX_RECORD_BYTES)
    closure = {proof_digest: len(raw)}
    for item in proof["objects"]:
        previous = closure.setdefault(item["digest"], item["size"])
        if previous != item["size"]:
            raise GitHubExpansionProofError(
                "expansion proof repeats a digest with another size"
            )
    return closure


def _expected_targets(
    cas: CAS,
    expansion: dict[str, Any],
    *,
    root_manifest_digest: str,
) -> list[dict[str, Any]]:
    if expansion.get("schema") != "aragorn/github-expansion/v1":
        raise GitHubExpansionProofError("GitHub expansion schema is unsupported")
    if expansion.get("root_manifest_digest") != root_manifest_digest:
        raise GitHubExpansionProofError(
            "GitHub expansion is bound to another root manifest"
        )
    if expansion.get("closure", {}).get("status") not in {
        "complete",
        "incomplete",
    }:
        raise GitHubExpansionProofError(
            "GitHub expansion closure status is unsupported"
        )
    root = load_verified_retained_manifest(cas, root_manifest_digest)
    source = root["source"]
    expansion_source = expansion.get("source")
    if (
        root.get("schema") != "aragorn/github-manifest/v1"
        or not isinstance(expansion_source, dict)
        or any(
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
        )
    ):
        raise GitHubExpansionProofError(
            "GitHub expansion source does not match its root manifest"
        )
    raw_targets = expansion.get("objects")
    if not isinstance(raw_targets, list) or len(raw_targets) > _MAX_TARGETS:
        raise GitHubExpansionProofError(
            "GitHub expansion target count exceeds its bound"
        )
    targets = []
    identities: set[tuple[str, str]] = set()
    for item in raw_targets:
        if not isinstance(item, dict):
            raise GitHubExpansionProofError("GitHub expansion target is invalid")
        target = {key: item.get(key) for key in _TARGET_KEYS}
        _validate_target(target)
        identity = (target["commit"], target["repository_path"])
        if identity in identities:
            raise GitHubExpansionProofError(
                "GitHub expansion repeats a target identity"
            )
        identities.add(identity)
        targets.append(target)
    targets.sort(key=lambda item: (item["commit"], item["repository_path"]))
    return targets


def _validate_target(target: dict[str, Any]) -> None:
    for field in ("commit", "commit_tree", "git_blob_sha1"):
        value = target[field]
        if not isinstance(value, str) or _OID.fullmatch(value) is None:
            raise GitHubExpansionProofError(
                f"GitHub expansion target {field} is invalid"
            )
    path = target["repository_path"]
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or path.endswith("/")
        or "\\" in path
        or len(path.encode("utf-8")) > 4096
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise GitHubExpansionProofError(
            "GitHub expansion target repository_path is invalid"
        )
    size = target["size"]
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 16 << 20:
        raise GitHubExpansionProofError("GitHub expansion target size is invalid")
    _digest(target["digest"], "GitHub expansion target digest")
    if not isinstance(target["executable"], bool):
        raise GitHubExpansionProofError(
            "GitHub expansion target executable flag is invalid"
        )


def _verify_targets(
    cas: CAS,
    targets: list[dict[str, Any]],
    payloads: Mapping[_ObjectKey, bytes],
) -> set[_ObjectKey]:
    used: set[_ObjectKey] = set()
    parsed_trees: dict[str, tuple[dict[str, str], ...]] = {}
    parsed_entries = 0

    def tree_entries(oid: str) -> tuple[dict[str, str], ...]:
        nonlocal parsed_entries
        payload = _required_payload(payloads, ("tree", oid))
        used.add(("tree", oid))
        if oid not in parsed_trees:
            remaining = _MAX_TREE_ENTRIES - parsed_entries
            if remaining <= 0:
                raise GitHubExpansionProofError(
                    "expansion proof tree-entry budget is exhausted"
                )
            parsed_trees[oid] = parse_tree(payload, max_entries=remaining)
            parsed_entries += len(parsed_trees[oid])
        return parsed_trees[oid]

    for target in targets:
        commit = target["commit"]
        commit_payload = _required_payload(payloads, ("commit", commit))
        used.add(("commit", commit))
        root_tree = parse_commit_tree(commit_payload)
        if root_tree != target["commit_tree"]:
            raise GitHubExpansionProofError(
                "expanded target commit tree does not match its proof"
            )
        tree = root_tree
        selected: dict[str, str] | None = None
        parts = target["repository_path"].split("/")
        for index, component in enumerate(parts):
            selected = next(
                (
                    entry
                    for entry in tree_entries(tree)
                    if entry["path"] == component
                ),
                None,
            )
            if selected is None:
                raise GitHubExpansionProofError(
                    "expanded target path is absent from its Git tree"
                )
            if index < len(parts) - 1:
                if selected["type"] != "tree" or selected["mode"] != "040000":
                    raise GitHubExpansionProofError(
                        "expanded target path crosses a non-directory"
                    )
                tree = selected["sha"]
        if selected is None or selected["type"] != "blob":
            raise GitHubExpansionProofError(
                "expanded target is not a Git blob"
            )
        expected_mode = "100755" if target["executable"] else "100644"
        if (
            selected["mode"] != expected_mode
            or selected["sha"] != target["git_blob_sha1"]
        ):
            raise GitHubExpansionProofError(
                "expanded target mode or blob identity changed"
            )
        content = cas.read(target["digest"], max_bytes=target["size"])
        if (
            len(content) != target["size"]
            or _git_oid("blob", content) != target["git_blob_sha1"]
        ):
            raise GitHubExpansionProofError(
                "expanded target CAS bytes do not match its Git blob"
            )
    return used


def _snapshot_raw_objects(
    raw_objects: Mapping[_ObjectKey, bytes],
) -> dict[_ObjectKey, bytes]:
    if not isinstance(raw_objects, Mapping):
        raise GitHubExpansionProofError("raw expansion proof objects are invalid")
    try:
        items = list(raw_objects.items())
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise GitHubExpansionProofError(
            "raw expansion proof objects cannot be read"
        ) from exc
    if len(items) > _MAX_OBJECTS:
        raise GitHubExpansionProofError(
            "raw expansion proof object count exceeds its bound"
        )
    payloads: dict[_ObjectKey, bytes] = {}
    total = 0
    for key, payload in items:
        _validate_object_key(key)
        if not isinstance(payload, bytes) or len(payload) > _MAX_OBJECT_BYTES:
            raise GitHubExpansionProofError(
                "raw expansion proof object exceeds its byte limit"
            )
        total += len(payload)
        if total > _MAX_TOTAL_OBJECT_BYTES:
            raise GitHubExpansionProofError(
                "raw expansion proof objects exceed 32 MiB"
            )
        _verify_git_identity(key, payload)
        payloads[key] = payload
    return payloads


def _load_proof_objects(
    cas: CAS,
    value: object,
) -> dict[_ObjectKey, bytes]:
    if not isinstance(value, list) or len(value) > _MAX_OBJECTS:
        raise GitHubExpansionProofError(
            "expansion proof object list exceeds its bound"
        )
    payloads: dict[_ObjectKey, bytes] = {}
    total = 0
    normalized = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _OBJECT_KEYS:
            raise GitHubExpansionProofError("expansion proof object is invalid")
        key = (item.get("type"), item.get("oid"))
        _validate_object_key(key)
        size = item.get("size")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= _MAX_OBJECT_BYTES
        ):
            raise GitHubExpansionProofError(
                "expansion proof object size is invalid"
            )
        digest = _digest(item.get("digest"), "expansion proof object digest")
        if key in payloads:
            raise GitHubExpansionProofError(
                "expansion proof repeats a Git object"
            )
        total += size
        if total > _MAX_TOTAL_OBJECT_BYTES:
            raise GitHubExpansionProofError(
                "expansion proof objects exceed 32 MiB"
            )
        payload = cas.read(digest, max_bytes=size)
        if len(payload) != size:
            raise GitHubExpansionProofError(
                "expansion proof object size changed"
            )
        _verify_git_identity(key, payload)
        payloads[key] = payload
        normalized.append(item)
    if normalized != sorted(
        normalized,
        key=lambda item: (_TYPE_ORDER[item["type"]], item["oid"]),
    ):
        raise GitHubExpansionProofError(
            "expansion proof objects are not canonically ordered"
        )
    return payloads


def _validate_object_key(key: object) -> None:
    if (
        not isinstance(key, tuple)
        or len(key) != 2
        or key[0] not in _TYPE_ORDER
        or not isinstance(key[1], str)
        or _OID.fullmatch(key[1]) is None
    ):
        raise GitHubExpansionProofError("expansion proof Git object key is invalid")


def _required_payload(
    payloads: Mapping[_ObjectKey, bytes],
    key: _ObjectKey,
) -> bytes:
    try:
        return payloads[key]
    except KeyError as exc:
        raise GitHubExpansionProofError(
            f"expansion proof is missing required {key[0]} object {key[1]}"
        ) from exc


def _load_expansion(cas: CAS, digest: str) -> dict[str, Any]:
    raw = cas.read(digest, max_bytes=_MAX_RECORD_BYTES)
    return _canonical_document(raw, "GitHub expansion")


def _canonical_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GitHubExpansionProofError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise GitHubExpansionProofError(f"{label} must use canonical JSON")
    return document


def _verify_git_identity(key: _ObjectKey, payload: bytes) -> None:
    if _git_oid(key[0], payload) != key[1]:
        raise GitHubExpansionProofError(
            f"raw Git {key[0]} bytes do not match OID {key[1]}"
        )


def _git_oid(object_type: str, payload: bytes) -> str:
    header = f"{object_type} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise GitHubExpansionProofError(f"{label} is invalid")
    return value


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GitHubExpansionProofError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_nonfinite(value: str) -> None:
    raise GitHubExpansionProofError(f"non-finite JSON number: {value}")
