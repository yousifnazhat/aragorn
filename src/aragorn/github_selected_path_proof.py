"""Offline proof for an exact set of selected GitHub commit paths."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from io import BytesIO
from typing import Any

from .artifact_closure import (
    ArtifactClosureError,
    _canonical_relative_path,
    canonical_json,
)
from .cas import CAS, CASError
from .github_git_protocol import GitProtocolError, parse_tree
from .github_source_proof import (
    _canonical_document,
    _digest,
    _parse_commit,
    _required_payload,
    _verify_git_identity,
)

_SCHEMA = "aragorn/github-selected-path-proof/v1"
_OID = re.compile(r"[0-9a-f]{40}\Z")
_OWNER = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?\Z")
_REPOSITORY = re.compile(r"[a-z0-9_.-]{1,100}\Z")
_MAX_PROOF_BYTES = 8 * 1024 * 1024
_MAX_OBJECT_BYTES = 8 * 1024 * 1024
_MAX_TARGETS = 256
_MAX_OBJECTS = 10_512
_MAX_BLOB_BYTES = 128 * 1024 * 1024
_MAX_METADATA_BYTES = 16 * 1024 * 1024
_MAX_BLOB_SIZE = 16 * 1024 * 1024
_MAX_TREE_ENTRIES = 10_000
_PROOF_KEYS = {"schema", "repository", "targets", "objects"}
_REPOSITORY_KEYS = {
    "host",
    "owner",
    "repository",
    "repository_hash_algorithm",
}
_TARGET_KEYS = {
    "commit",
    "repository_path",
    "git_blob_sha1",
    "size",
    "digest",
    "executable",
}
_OBJECT_KEYS = {"type", "oid", "size", "digest"}
_TYPE_ORDER = {"commit": 0, "tree": 1, "blob": 2}

_ObjectKey = tuple[str, str]


def retain_github_selected_path_proof(
    cas: CAS,
    repository: object,
    targets: object,
    raw_objects: Mapping[_ObjectKey, bytes],
) -> str:
    """Retain exact Git object paths and selected blob bytes for offline replay."""

    try:
        canonical_repository = _validate_repository(repository)
        canonical_targets = _validate_targets(targets, require_sorted=False)
        payloads = _snapshot_objects(raw_objects)
        _verify_topology(canonical_targets, payloads)
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
            "repository": canonical_repository,
            "targets": canonical_targets,
            "objects": records,
        }
        raw = canonical_json(proof)
        if len(raw) > _MAX_PROOF_BYTES:
            raise ArtifactClosureError("GitHub selected-path proof exceeds 8 MiB")
        return cas.put(BytesIO(raw), max_bytes=len(raw))
    except ArtifactClosureError:
        raise
    except (CASError, GitProtocolError, TypeError, ValueError) as exc:
        raise ArtifactClosureError(
            f"cannot retain GitHub selected-path proof: {exc}"
        ) from exc


def verify_github_selected_path_proof(
    cas: CAS,
    proof_digest: str,
    *,
    expected_repository: object,
    expected_targets: object,
) -> dict[str, Any]:
    """Replay a selected-path proof against caller-authorized exact targets."""

    try:
        raw = cas.read(
            _digest(proof_digest, "GitHub selected-path proof digest"),
            max_bytes=_MAX_PROOF_BYTES,
        )
        proof = _canonical_document(raw)
        if set(proof) != _PROOF_KEYS or proof.get("schema") != _SCHEMA:
            raise ArtifactClosureError(
                "GitHub selected-path proof has missing, unknown, or unsupported fields"
            )

        repository = _validate_repository(proof.get("repository"))
        authorized_repository = _validate_repository(expected_repository)
        if repository != authorized_repository:
            raise ArtifactClosureError(
                "GitHub selected-path proof repository is not caller-authorized"
            )
        targets = _validate_targets(proof.get("targets"), require_sorted=True)
        authorized_targets = _validate_targets(
            expected_targets,
            require_sorted=False,
        )
        if targets != authorized_targets:
            raise ArtifactClosureError(
                "GitHub selected-path proof targets are not caller-authorized"
            )

        records = _validate_records(proof.get("objects"))
        payloads: dict[_ObjectKey, bytes] = {}
        metadata_bytes = 0
        blob_bytes = 0
        for record in records:
            size = record["size"]
            if record["type"] == "blob":
                blob_bytes += size
                if blob_bytes > _MAX_BLOB_BYTES:
                    raise ArtifactClosureError(
                        "GitHub selected-path blob objects exceed 128 MiB"
                    )
            else:
                metadata_bytes += size
                if metadata_bytes > _MAX_METADATA_BYTES:
                    raise ArtifactClosureError(
                        "GitHub selected-path metadata objects exceed 16 MiB"
                    )
            payload = cas.read(record["digest"], max_bytes=size)
            if len(payload) != size:
                raise ArtifactClosureError(
                    "GitHub selected-path proof object size changed"
                )
            key = (record["type"], record["oid"])
            _verify_git_identity(key, payload)
            payloads[key] = payload

        _verify_topology(targets, payloads)
        return proof
    except ArtifactClosureError:
        raise
    except (CASError, GitProtocolError, TypeError, ValueError) as exc:
        raise ArtifactClosureError(
            f"cannot verify GitHub selected-path proof: {exc}"
        ) from exc


def _snapshot_objects(
    raw_objects: Mapping[_ObjectKey, bytes],
) -> dict[_ObjectKey, bytes]:
    if not isinstance(raw_objects, Mapping):
        raise ArtifactClosureError(
            "raw Git selected-path proof objects must be a mapping"
        )
    try:
        items = list(raw_objects.items())
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise ArtifactClosureError(
            "raw Git selected-path proof objects cannot be read"
        ) from exc
    if not 3 <= len(items) <= _MAX_OBJECTS:
        raise ArtifactClosureError(
            "raw Git selected-path proof object count is outside the bounded range"
        )

    payloads: dict[_ObjectKey, bytes] = {}
    metadata_bytes = 0
    blob_bytes = 0
    for key, payload in items:
        if (
            type(key) is not tuple
            or len(key) != 2
            or key[0] not in _TYPE_ORDER
            or type(key[1]) is not str
            or _OID.fullmatch(key[1]) is None
            or key[1] == "0" * 40
        ):
            raise ArtifactClosureError(
                "raw Git selected-path proof object key is invalid"
            )
        maximum = _MAX_BLOB_SIZE if key[0] == "blob" else _MAX_OBJECT_BYTES
        if type(payload) is not bytes or len(payload) > maximum:
            raise ArtifactClosureError(
                "raw Git selected-path proof object exceeds its byte limit"
            )
        if key in payloads:
            raise ArtifactClosureError(
                "raw Git selected-path proof object is duplicated"
            )
        if key[0] == "blob":
            blob_bytes += len(payload)
            if blob_bytes > _MAX_BLOB_BYTES:
                raise ArtifactClosureError(
                    "raw Git selected-path blob objects exceed 128 MiB"
                )
        else:
            metadata_bytes += len(payload)
            if metadata_bytes > _MAX_METADATA_BYTES:
                raise ArtifactClosureError(
                    "raw Git selected-path metadata objects exceed 16 MiB"
                )
        _verify_git_identity(key, payload)
        payloads[key] = payload
    return payloads


def _validate_records(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 3 <= len(value) <= _MAX_OBJECTS:
        raise ArtifactClosureError(
            "GitHub selected-path proof object list is outside the bounded range"
        )
    records: list[dict[str, Any]] = []
    keys: set[_ObjectKey] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != _OBJECT_KEYS:
            raise ArtifactClosureError(
                "GitHub selected-path proof object has missing or unknown fields"
            )
        object_type = item["type"]
        oid = item["oid"]
        size = item["size"]
        if object_type not in _TYPE_ORDER:
            raise ArtifactClosureError(
                "GitHub selected-path proof object type is invalid"
            )
        maximum = _MAX_BLOB_SIZE if object_type == "blob" else _MAX_OBJECT_BYTES
        if type(oid) is not str or _OID.fullmatch(oid) is None or oid == "0" * 40:
            raise ArtifactClosureError(
                "GitHub selected-path proof object OID is invalid"
            )
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= maximum
        ):
            raise ArtifactClosureError(
                "GitHub selected-path proof object size is invalid"
            )
        digest = _digest(
            item["digest"],
            "GitHub selected-path proof object digest",
        )
        key = (object_type, oid)
        if key in keys:
            raise ArtifactClosureError(
                "GitHub selected-path proof object is duplicated"
            )
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
            "GitHub selected-path proof objects are not canonically ordered"
        )
    return records


def _validate_repository(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _REPOSITORY_KEYS:
        raise ArtifactClosureError("GitHub selected-path proof repository is malformed")
    host = value["host"]
    owner = value["owner"]
    repository = value["repository"]
    algorithm = value["repository_hash_algorithm"]
    if (
        host != "github.com"
        or type(owner) is not str
        or _OWNER.fullmatch(owner) is None
        or owner.endswith("-")
        or type(repository) is not str
        or _REPOSITORY.fullmatch(repository) is None
        or repository in {".", ".."}
        or repository.endswith(".git")
        or algorithm != "sha1"
    ):
        raise ArtifactClosureError("GitHub selected-path proof repository is malformed")
    return {
        "host": "github.com",
        "owner": owner,
        "repository": repository,
        "repository_hash_algorithm": "sha1",
    }


def _validate_targets(
    value: object,
    *,
    require_sorted: bool,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_TARGETS:
        raise ArtifactClosureError(
            "GitHub selected-path proof target list is outside the bounded range"
        )
    targets: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != _TARGET_KEYS:
            raise ArtifactClosureError(
                "GitHub selected-path proof target has missing or unknown fields"
            )
        commit = item["commit"]
        path = item["repository_path"]
        blob_oid = item["git_blob_sha1"]
        size = item["size"]
        executable = item["executable"]
        if (
            type(commit) is not str
            or _OID.fullmatch(commit) is None
            or commit == "0" * 40
            or _canonical_relative_path(path) != path
            or len(path.split("/")) > 128
            or type(blob_oid) is not str
            or _OID.fullmatch(blob_oid) is None
            or blob_oid == "0" * 40
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= _MAX_BLOB_SIZE
            or type(executable) is not bool
        ):
            raise ArtifactClosureError("GitHub selected-path proof target is malformed")
        identity = (commit, path)
        if identity in identities:
            raise ArtifactClosureError(
                "GitHub selected-path proof repeats a commit and path"
            )
        identities.add(identity)
        targets.append(
            {
                "commit": commit,
                "repository_path": path,
                "git_blob_sha1": blob_oid,
                "size": size,
                "digest": _digest(
                    item["digest"],
                    "GitHub selected-path proof target digest",
                ),
                "executable": executable,
            }
        )
    ordered = sorted(
        targets,
        key=lambda target: (target["commit"], target["repository_path"]),
    )
    if require_sorted and targets != ordered:
        raise ArtifactClosureError(
            "GitHub selected-path proof targets are not canonically ordered"
        )
    return ordered


def _verify_topology(
    targets: list[dict[str, Any]],
    payloads: Mapping[_ObjectKey, bytes],
) -> None:
    used: set[_ObjectKey] = set()
    parsed_trees: dict[str, tuple[dict[str, str], ...]] = {}
    entries_seen = 0

    def tree_entries(oid: str) -> tuple[dict[str, str], ...]:
        nonlocal entries_seen
        key = ("tree", oid)
        payload = _required_payload(payloads, key)
        used.add(key)
        if oid not in parsed_trees:
            remaining = _MAX_TREE_ENTRIES - entries_seen
            if remaining <= 0:
                raise ArtifactClosureError(
                    "GitHub selected-path tree entry budget is exhausted"
                )
            try:
                parsed_trees[oid] = parse_tree(payload, max_entries=remaining)
            except GitProtocolError as exc:
                raise ArtifactClosureError(
                    f"invalid raw Git tree object {oid}: {exc}"
                ) from exc
            entries_seen += len(parsed_trees[oid])
        return parsed_trees[oid]

    commit_trees: dict[str, str] = {}
    for target in targets:
        commit_oid = target["commit"]
        commit_key = ("commit", commit_oid)
        commit_payload = _required_payload(payloads, commit_key)
        used.add(commit_key)
        root_tree = commit_trees.get(commit_oid)
        if root_tree is None:
            root_tree = _parse_commit(commit_payload)
            commit_trees[commit_oid] = root_tree

        tree_oid = root_tree
        components = target["repository_path"].split("/")
        for index, component in enumerate(components):
            entry = next(
                (
                    candidate
                    for candidate in tree_entries(tree_oid)
                    if candidate["path"] == component
                ),
                None,
            )
            if entry is None:
                raise ArtifactClosureError(
                    "GitHub selected-path target is absent from its commit"
                )
            final = index == len(components) - 1
            if not final:
                if entry["type"] != "tree" or entry["mode"] != "040000":
                    raise ArtifactClosureError(
                        "GitHub selected-path target crosses a non-directory"
                    )
                tree_oid = entry["sha"]
                continue
            expected_mode = "100755" if target["executable"] else "100644"
            if (
                entry["type"] != "blob"
                or entry["mode"] != expected_mode
                or entry["sha"] != target["git_blob_sha1"]
            ):
                raise ArtifactClosureError(
                    "GitHub selected-path target blob identity or mode changed"
                )

        blob_key = ("blob", target["git_blob_sha1"])
        blob = _required_payload(payloads, blob_key)
        used.add(blob_key)
        if (
            len(blob) != target["size"]
            or "sha256:" + hashlib.sha256(blob).hexdigest() != target["digest"]
        ):
            raise ArtifactClosureError("GitHub selected-path target bytes changed")

    object_keys = set(payloads)
    missing = used - object_keys
    if missing:
        raise ArtifactClosureError(
            "GitHub selected-path proof is missing required objects"
        )
    extra = object_keys - used
    if extra:
        raise ArtifactClosureError("GitHub selected-path proof contains extra objects")


def _record_sort_key(record: Mapping[str, Any]) -> tuple[int, str]:
    return (_TYPE_ORDER[record["type"]], record["oid"])
