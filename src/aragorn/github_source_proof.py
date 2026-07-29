"""Durable, offline verification of GitHub commit and tree source proof."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from io import BytesIO
from typing import Any

from .artifact_closure import (
    ArtifactClosureError,
    canonical_json,
    load_verified_retained_manifest,
)
from .cas import CAS, CASError
from .github_git_protocol import GitProtocolError, parse_commit_tree, parse_tree

_SCHEMA = "aragorn/github-source-proof/v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OID = re.compile(r"[0-9a-f]{40}\Z")
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_PROOF_BYTES = 8 * 1024 * 1024
_MAX_OBJECT_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_OBJECT_BYTES = 16 * 1024 * 1024
_MAX_OBJECTS = 10_034
_MAX_TREE_WALKS = 10_001
_MAX_TREE_ENTRIES = 10_000
_MAX_TRAVERSED_TREE_ENTRIES = 10_000
_MAX_FILES = 10_000
_MAX_SKILL_TREE_DEPTH = 8
_MAX_REPOSITORY_PATH_BYTES = 4096
_PROOF_KEYS = {"schema", "manifest_digest", "source", "objects"}
_OBJECT_KEYS = {"type", "oid", "size", "digest"}
_TYPE_ORDER = {"commit": 0, "tree": 1}

_ObjectKey = tuple[str, str]


def retain_github_source_proof(
    cas: CAS,
    manifest: object,
    raw_objects: Mapping[_ObjectKey, bytes],
) -> str:
    """Validate and retain the raw Git objects proving one GitHub manifest."""

    try:
        manifest_raw = canonical_json(manifest)
        if len(manifest_raw) > _MAX_MANIFEST_BYTES:
            raise ArtifactClosureError("GitHub source manifest exceeds 64 MiB")
        manifest_digest = cas.put(
            BytesIO(manifest_raw),
            max_bytes=len(manifest_raw),
        )
        verified_manifest = load_verified_retained_manifest(cas, manifest_digest)
        if verified_manifest.get("schema") != "aragorn/github-manifest/v1":
            raise ArtifactClosureError(
                "GitHub source proof requires a github-manifest/v1"
            )

        payloads = _snapshot_raw_objects(raw_objects)
        _verify_topology(verified_manifest, payloads)
        records = []
        for (object_type, oid), payload in payloads.items():
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
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
        records.sort(key=_record_sort_key)
        proof = {
            "schema": _SCHEMA,
            "manifest_digest": manifest_digest,
            "source": verified_manifest["source"],
            "objects": records,
        }
        raw = canonical_json(proof)
        if len(raw) > _MAX_PROOF_BYTES:
            raise ArtifactClosureError("GitHub source proof exceeds 8 MiB")
        return cas.put(BytesIO(raw), max_bytes=len(raw))
    except ArtifactClosureError:
        raise
    except (CASError, GitProtocolError, TypeError, ValueError) as exc:
        raise ArtifactClosureError(f"cannot retain GitHub source proof: {exc}") from exc


def verify_github_source_proof(
    cas: CAS,
    proof_digest: str,
    expected_manifest_digest: str,
) -> dict[str, Any]:
    """Reload and verify a source-proof record and every raw Git payload."""

    try:
        expected = _digest(expected_manifest_digest, "expected manifest digest")
        raw = cas.read(
            _digest(proof_digest, "GitHub source-proof digest"),
            max_bytes=_MAX_PROOF_BYTES,
        )
        proof = _canonical_document(raw)
        if set(proof) != _PROOF_KEYS or proof.get("schema") != _SCHEMA:
            raise ArtifactClosureError(
                "GitHub source proof has missing, unknown, or unsupported fields"
            )
        if proof.get("manifest_digest") != expected:
            raise ArtifactClosureError(
                "GitHub source proof does not bind the expected manifest"
            )

        manifest = load_verified_retained_manifest(cas, expected)
        if manifest.get("schema") != "aragorn/github-manifest/v1":
            raise ArtifactClosureError(
                "GitHub source proof requires a github-manifest/v1"
            )
        if proof.get("source") != manifest["source"]:
            raise ArtifactClosureError(
                "GitHub source proof does not bind the manifest source"
            )

        records = _validate_records(proof.get("objects"))
        payloads: dict[_ObjectKey, bytes] = {}
        total_bytes = 0
        for record in records:
            size = record["size"]
            total_bytes += size
            if total_bytes > _MAX_TOTAL_OBJECT_BYTES:
                raise ArtifactClosureError("GitHub source-proof objects exceed 16 MiB")
            payload = cas.read(record["digest"], max_bytes=size)
            if len(payload) != size:
                raise ArtifactClosureError("GitHub source-proof object size changed")
            key = (record["type"], record["oid"])
            _verify_git_identity(key, payload)
            payloads[key] = payload

        _verify_topology(manifest, payloads)
        return proof
    except ArtifactClosureError:
        raise
    except (CASError, GitProtocolError, TypeError, ValueError) as exc:
        raise ArtifactClosureError(f"cannot verify GitHub source proof: {exc}") from exc


def _snapshot_raw_objects(
    raw_objects: Mapping[_ObjectKey, bytes],
) -> dict[_ObjectKey, bytes]:
    if not isinstance(raw_objects, Mapping):
        raise ArtifactClosureError("raw Git source-proof objects must be a mapping")
    try:
        items = list(raw_objects.items())
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise ArtifactClosureError(
            "raw Git source-proof objects cannot be read"
        ) from exc
    if not 2 <= len(items) <= _MAX_OBJECTS:
        raise ArtifactClosureError(
            "raw Git source-proof object count is outside the bounded range"
        )

    payloads: dict[_ObjectKey, bytes] = {}
    total_bytes = 0
    for key, payload in items:
        if (
            type(key) is not tuple
            or len(key) != 2
            or key[0] not in _TYPE_ORDER
            or type(key[1]) is not str
            or _OID.fullmatch(key[1]) is None
            or key[1] == "0" * 40
        ):
            raise ArtifactClosureError("raw Git source-proof object key is invalid")
        if type(payload) is not bytes or len(payload) > _MAX_OBJECT_BYTES:
            raise ArtifactClosureError(
                "raw Git source-proof object exceeds its byte limit"
            )
        if key in payloads:
            raise ArtifactClosureError("raw Git source-proof object is duplicated")
        total_bytes += len(payload)
        if total_bytes > _MAX_TOTAL_OBJECT_BYTES:
            raise ArtifactClosureError("raw Git source-proof objects exceed 16 MiB")
        _verify_git_identity(key, payload)
        payloads[key] = payload
    return payloads


def _validate_records(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 2 <= len(value) <= _MAX_OBJECTS:
        raise ArtifactClosureError(
            "GitHub source-proof object list is outside the bounded range"
        )
    records: list[dict[str, Any]] = []
    keys: set[_ObjectKey] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != _OBJECT_KEYS:
            raise ArtifactClosureError(
                "GitHub source-proof object has missing or unknown fields"
            )
        object_type = item["type"]
        oid = item["oid"]
        size = item["size"]
        if object_type not in _TYPE_ORDER:
            raise ArtifactClosureError("GitHub source-proof object type is invalid")
        if type(oid) is not str or _OID.fullmatch(oid) is None or oid == "0" * 40:
            raise ArtifactClosureError("GitHub source-proof object OID is invalid")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= _MAX_OBJECT_BYTES
        ):
            raise ArtifactClosureError("GitHub source-proof object size is invalid")
        digest = _digest(item["digest"], "GitHub source-proof object digest")
        key = (object_type, oid)
        if key in keys:
            raise ArtifactClosureError("GitHub source-proof object is duplicated")
        keys.add(key)
        records.append(
            {
                "type": object_type,
                "oid": oid,
                "size": size,
                "digest": digest,
            }
        )
    if records != sorted(records, key=_record_sort_key):
        raise ArtifactClosureError(
            "GitHub source-proof objects are not canonically ordered"
        )
    return records


def _verify_topology(
    manifest: dict[str, Any],
    payloads: Mapping[_ObjectKey, bytes],
) -> None:
    source = manifest["source"]
    commit_oid = source["commit"]
    commit_payload = _required_payload(payloads, ("commit", commit_oid))
    used: set[_ObjectKey] = {("commit", commit_oid)}
    root_tree = _parse_commit(commit_payload)
    if root_tree != source["commit_tree"]:
        raise ArtifactClosureError(
            "GitHub source-proof commit root tree does not match the manifest"
        )

    parsed_trees: dict[str, tuple[dict[str, str], ...]] = {}
    entries_seen = 0

    def tree_entries(oid: str) -> tuple[dict[str, str], ...]:
        nonlocal entries_seen
        key = ("tree", oid)
        payload = _required_payload(payloads, key)
        used.add(key)
        if oid not in parsed_trees:
            try:
                remaining = _MAX_TREE_ENTRIES - entries_seen
                if remaining <= 0:
                    raise GitProtocolError(
                        "shared Git tree entry budget is exhausted"
                    )
                parsed_trees[oid] = parse_tree(
                    payload,
                    max_entries=remaining,
                )
            except GitProtocolError as exc:
                raise ArtifactClosureError(
                    f"invalid raw Git tree object {oid}: {exc}"
                ) from exc
            entries_seen += len(parsed_trees[oid])
        return parsed_trees[oid]

    skill_tree = root_tree
    skill_path = source["skill_path"]
    if skill_path != ".":
        for component in skill_path.split("/"):
            entry = next(
                (
                    candidate
                    for candidate in tree_entries(skill_tree)
                    if candidate["path"] == component
                ),
                None,
            )
            if entry is None or entry["type"] != "tree":
                raise ArtifactClosureError(
                    "GitHub source-proof skill_path is absent or not a tree"
                )
            skill_tree = entry["sha"]
    if skill_tree != source["skill_tree"]:
        raise ArtifactClosureError(
            "GitHub source-proof skill tree does not match the manifest"
        )

    files: list[dict[str, str]] = []
    stack: list[tuple[str, str, int]] = [(skill_tree, "", 0)]
    tree_walks = 0
    traversed_entries = 0
    while stack:
        oid, prefix, depth = stack.pop()
        tree_walks += 1
        if tree_walks > _MAX_TREE_WALKS:
            raise ArtifactClosureError(
                "GitHub source-proof tree traversal exceeds its walk limit"
            )
        entries = tree_entries(oid)
        traversed_entries += len(entries)
        if traversed_entries > _MAX_TRAVERSED_TREE_ENTRIES:
            raise ArtifactClosureError(
                "GitHub source-proof subtree traversal exceeds 10000 entries"
            )
        for entry in reversed(entries):
            path = entry["path"] if not prefix else f"{prefix}/{entry['path']}"
            if len(path.encode("utf-8")) > 4096:
                raise ArtifactClosureError(
                    "GitHub source-proof path exceeds 4096 UTF-8 bytes"
                )
            if entry["type"] == "tree":
                next_depth = depth + 1
                if next_depth > _MAX_SKILL_TREE_DEPTH:
                    raise ArtifactClosureError(
                        "GitHub source-proof skill tree exceeds depth 8"
                    )
                stack.append((entry["sha"], path, next_depth))
            else:
                repository_path = (
                    path if skill_path == "." else f"{skill_path}/{path}"
                )
                if (
                    len(repository_path.encode("utf-8"))
                    > _MAX_REPOSITORY_PATH_BYTES
                ):
                    raise ArtifactClosureError(
                        "GitHub source-proof repository path exceeds "
                        "4096 UTF-8 bytes"
                    )
                files.append(
                    {
                        "path": path,
                        "mode": entry["mode"],
                        "git_blob_sha1": entry["sha"],
                    }
                )
                if len(files) > _MAX_FILES:
                    raise ArtifactClosureError(
                        "GitHub source-proof file count exceeds 10000"
                    )

    expected_files = [
        {
            "path": entry["path"],
            "mode": "100755" if entry["executable"] else "100644",
            "git_blob_sha1": entry["git_blob_sha1"],
        }
        for entry in manifest["files"]
    ]
    if sorted(files, key=lambda item: item["path"]) != expected_files:
        raise ArtifactClosureError(
            "GitHub source-proof file membership, mode, or blob identity "
            "does not match the manifest"
        )

    object_keys = set(payloads)
    missing = used - object_keys
    if missing:
        raise ArtifactClosureError("GitHub source proof is missing required objects")
    extra = object_keys - used
    if extra:
        raise ArtifactClosureError("GitHub source proof contains extra objects")


def _required_payload(
    payloads: Mapping[_ObjectKey, bytes],
    key: _ObjectKey,
) -> bytes:
    try:
        return payloads[key]
    except KeyError as exc:
        raise ArtifactClosureError(
            f"GitHub source proof is missing required {key[0]} object {key[1]}"
        ) from exc


def _parse_commit(payload: bytes) -> str:
    try:
        return parse_commit_tree(payload)
    except GitProtocolError as exc:
        raise ArtifactClosureError(f"invalid raw Git commit object: {exc}") from exc


def _verify_git_identity(key: _ObjectKey, payload: bytes) -> None:
    object_type, oid = key
    header = (
        object_type.encode("ascii") + b" " + str(len(payload)).encode("ascii") + b"\0"
    )
    if hashlib.sha1(header + payload, usedforsecurity=False).hexdigest() != oid:
        raise ArtifactClosureError(
            f"raw Git {object_type} object bytes do not match OID {oid}"
        )


def _canonical_document(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ArtifactClosureError(f"invalid GitHub source-proof JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactClosureError("GitHub source proof must be a JSON object")
    if canonical_json(value) != raw:
        raise ArtifactClosureError("GitHub source proof must use canonical JSON")
    return value


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _digest(value: object, subject: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ArtifactClosureError(f"{subject} is not a canonical SHA-256 digest")
    return value


def _record_sort_key(record: Mapping[str, Any]) -> tuple[int, str]:
    return (_TYPE_ORDER[record["type"]], record["oid"])
