"""Bounded Phase 0 expansion of exact GitHub blob references."""

from __future__ import annotations

from collections import deque
import hashlib
from io import BytesIO
import json
from pathlib import PurePosixPath
from typing import Any

from .artifact_closure import (
    MAX_SCANNED_TEXT_BYTES,
    ReferenceBudgetExceeded,
    TEXT_CARRIER_SUFFIXES,
    canonical_local_reference_target,
    canonical_json,
    exact_raw_github_fetch_target,
    load_retained_manifest,
    parse_immutable_github_reference,
    scan_retained_text_references,
    _validate_manifest,
)
from .cas import CAS, CASError
from .github_acquire import (
    API_VERSION,
    GitHubAcquisitionError,
    GitHubAcquisitionSession,
    GitHubBudgetExceeded,
)
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    sanitize_subject_manifest,
    validate_subject_manifest,
)


PROFILE = "phase0-exact-github-blob-expansion/v1"
ASSURANCE = "evaluation_only_github_api_membership_asserted_blob_identity_reverified"
TERMINAL_DEPTH_1_MODE = "terminal_depth_1"
TERMINAL_DEPTH_1_PROFILE = (
    "phase0-exact-github-blob-expansion-terminal-depth-1/v1"
)
TERMINAL_DEPTH_1_ASSURANCE = (
    "evaluation_only_github_api_membership_asserted_blob_identity_reverified_"
    "depth_1_targets_terminal_not_reference_scanned"
)
MATERIALIZED_PREFIX = "__aragorn_expanded__"
MAX_RECORD_BYTES = 16 * 1024 * 1024

_DEFAULT_MAX_API_REQUESTS = 20_050
_DEFAULT_MAX_API_BYTES = 384 * 1024 * 1024
_DEFAULT_MAX_RETAINED_BYTES = 128 * 1024 * 1024
_DEFAULT_MAX_EXPANDED_OBJECTS = 256
_DEFAULT_MAX_EXPANSION_DEPTH = 4
_DEFAULT_MAX_REFERENCES = 10_000
_DEFAULT_MAX_SOURCE_DEPTH = 8
_DEFAULT_MAX_SOURCE_ENTRIES = 10_000
_DEFAULT_MAX_FILE_SIZE = 16 * 1024 * 1024
_MAX_SUBJECT_FILES = 10_000
_MAX_SUBJECT_PATH_LENGTH = 4096


class GitHubExpansionError(ValueError):
    """An exact GitHub expansion could not be completed under its bounds."""


class _IncompleteExpansion(Exception):
    def __init__(
        self,
        reason_code: str,
        subject: str,
        *,
        references_seen: int = 0,
    ) -> None:
        super().__init__(f"{reason_code}:{subject}")
        self.reason_code = reason_code
        self.subject = subject
        self.references_seen = references_seen


def acquire_github_expansion(
    repository_url: str,
    commit: str,
    skill_path: str,
    cas: CAS,
    *,
    max_api_requests: int = _DEFAULT_MAX_API_REQUESTS,
    max_api_bytes: int = _DEFAULT_MAX_API_BYTES,
    max_retained_bytes: int = _DEFAULT_MAX_RETAINED_BYTES,
    max_expanded_objects: int = _DEFAULT_MAX_EXPANDED_OBJECTS,
    max_expansion_depth: int = _DEFAULT_MAX_EXPANSION_DEPTH,
    max_references: int = _DEFAULT_MAX_REFERENCES,
    max_source_depth: int = _DEFAULT_MAX_SOURCE_DEPTH,
    max_source_entries: int = _DEFAULT_MAX_SOURCE_ENTRIES,
    max_file_size: int = _DEFAULT_MAX_FILE_SIZE,
    timeout_seconds: float = 120.0,
    bearer_token: str | None = None,
    expansion_mode: str | None = None,
) -> dict[str, Any]:
    """Acquire a skill and retain supported exact-commit blob references.

    The function stages and verifies every byte before publishing any manifest or
    result record to the caller. The default recursively closes supported
    references. ``terminal_depth_1`` retains verified first-hop targets without
    scanning their contents for additional references.
    """

    _bounded_integer(
        "max_api_requests",
        max_api_requests,
        minimum=1,
        maximum=_DEFAULT_MAX_API_REQUESTS,
    )
    _bounded_integer(
        "max_api_bytes",
        max_api_bytes,
        minimum=1,
        maximum=_DEFAULT_MAX_API_BYTES,
    )
    _bounded_integer(
        "max_retained_bytes",
        max_retained_bytes,
        minimum=1,
        maximum=_DEFAULT_MAX_RETAINED_BYTES,
    )
    _bounded_integer(
        "max_expanded_objects",
        max_expanded_objects,
        minimum=0,
        maximum=_DEFAULT_MAX_EXPANDED_OBJECTS,
    )
    _bounded_integer(
        "max_expansion_depth",
        max_expansion_depth,
        minimum=0,
        maximum=_DEFAULT_MAX_EXPANSION_DEPTH,
    )
    _bounded_integer(
        "max_references",
        max_references,
        minimum=1,
        maximum=_DEFAULT_MAX_REFERENCES,
    )
    _bounded_integer("max_source_depth", max_source_depth, minimum=0, maximum=32)
    _bounded_integer(
        "max_source_entries",
        max_source_entries,
        minimum=1,
        maximum=_DEFAULT_MAX_SOURCE_ENTRIES,
    )
    _bounded_integer(
        "max_file_size",
        max_file_size,
        minimum=0,
        maximum=_DEFAULT_MAX_FILE_SIZE,
    )
    if expansion_mode not in (None, TERMINAL_DEPTH_1_MODE):
        raise GitHubExpansionError("unsupported GitHub expansion mode")
    if (
        expansion_mode == TERMINAL_DEPTH_1_MODE
        and max_expansion_depth != 1
    ):
        raise GitHubExpansionError(
            "terminal-depth-1 expansion requires max_expansion_depth=1"
        )
    terminal_depth_1 = expansion_mode == TERMINAL_DEPTH_1_MODE
    profile = TERMINAL_DEPTH_1_PROFILE if terminal_depth_1 else PROFILE
    assurance = TERMINAL_DEPTH_1_ASSURANCE if terminal_depth_1 else ASSURANCE
    closure_scope = (
        "phase0_exact_github_blob_expansion_terminal_depth_1"
        if terminal_depth_1
        else "phase0_exact_github_blob_expansion"
    )

    try:
        session = GitHubAcquisitionSession(
            repository_url,
            commit,
            max_api_requests=max_api_requests,
            max_api_bytes=max_api_bytes,
            timeout_seconds=timeout_seconds,
            bearer_token=bearer_token,
        )
        root_manifest, root_content, retained_bytes = _stage_root(
            session,
            skill_path,
            max_source_depth=max_source_depth,
            max_source_entries=max_source_entries,
            max_file_size=max_file_size,
            max_retained_bytes=max_retained_bytes,
        )
    except GitHubAcquisitionError as exc:
        raise GitHubExpansionError(str(exc)) from exc

    root_manifest_digest = _digest_document(root_manifest)
    root_source = root_manifest["source"]
    root_repository_entries = {
        (
            root_source["commit"],
            _repository_path(root_source["skill_path"], entry["path"]),
        ): {
            **entry,
            "path": _repository_path(root_source["skill_path"], entry["path"]),
        }
        for entry in root_manifest["files"]
    }
    all_content: dict[str, bytes] = dict(root_content)
    expanded: dict[tuple[str, str], dict[str, Any]] = {}
    queued_depth: dict[tuple[str, str], int] = {}
    references_by_target: dict[tuple[str, str], list[dict[str, Any]]] = {}
    reference_occurrences: list[dict[str, Any]] = []
    deferred_local_references: list[dict[str, Any]] = []
    pending: deque[tuple[str, str]] = deque()
    sessions = {root_source["commit"]: session}
    reference_totals = {
        "total_edges": 0,
        "artifact_references": 0,
        "resolved_in_root": 0,
        "expanded": 0,
        "deduplicated": 0,
        "non_artifact": 0,
        "unresolved": 0,
        "opaque_carriers": 0,
        "scan_complete": True,
        "occurrences_complete": True,
        "occurrences_omitted": 0,
    }
    maximum_depth_used = 0
    incomplete_reasons: list[dict[str, str]] = []
    stop_scanning = False

    def session_for_commit(target_commit: str) -> GitHubAcquisitionSession:
        cached = sessions.get(target_commit)
        if cached is None:
            cached = session.for_commit(target_commit)
            sessions[target_commit] = cached
        return cached

    def add_incomplete(reason_code: str, subject: str) -> None:
        reason = {"reason_code": reason_code, "subject": subject}
        if reason not in incomplete_reasons:
            incomplete_reasons.append(reason)

    def mark_scan_incomplete(*, stop: bool) -> None:
        nonlocal stop_scanning
        reference_totals["scan_complete"] = False
        reference_totals["occurrences_complete"] = False
        reference_totals["occurrences_omitted"] = None
        stop_scanning = stop_scanning or stop

    def register_edges(
        edges: tuple[dict[str, Any], ...],
        *,
        source_repository_path: str,
        source_commit: str,
        target_base_path: str,
        next_depth: int,
    ) -> None:
        nonlocal maximum_depth_used
        immutable_targets: dict[tuple[str, str], dict[str, str]] = {}
        for edge in edges:
            if edge["reference_kind"] != "github_immutable":
                continue
            target = parse_immutable_github_reference(edge["literal"])
            if target is None:
                raise GitHubExpansionError(
                    "supported GitHub edge has no canonical immutable target"
                )
            immutable_targets[(target["commit"], target["path"])] = target

        suppressed_dynamic: set[tuple[str, int, str]] = set()
        for edge in edges:
            if (
                edge["reference_kind"] != "dynamic_command"
                or edge["status"] != "unresolved"
            ):
                continue
            fetch_target = exact_raw_github_fetch_target(edge["literal"])
            if (
                fetch_target is not None
                and (fetch_target["commit"], fetch_target["path"])
                in immutable_targets
                and _same_repository(fetch_target, root_source)
            ):
                suppressed_dynamic.add(
                    (
                        edge["source_path"],
                        edge["byte_offset"],
                        edge["literal_digest"],
                    )
                )

        reference_totals["total_edges"] += len(edges) - len(suppressed_dynamic)
        if reference_totals["total_edges"] > max_references:
            add_incomplete("REFERENCE_BUDGET_EXCEEDED", source_repository_path)
            mark_scan_incomplete(stop=True)
            return

        for edge in edges:
            status = edge["status"]
            if status == "non_artifact":
                reference_totals["non_artifact"] += 1
                continue
            if (
                edge["reference_kind"] == "dynamic_command"
                and (
                    edge["source_path"],
                    edge["byte_offset"],
                    edge["literal_digest"],
                )
                in suppressed_dynamic
            ):
                continue
            if status == "resolved":
                reference_totals["artifact_references"] += 1
                if edge["reference_kind"] == "github_immutable":
                    target = parse_immutable_github_reference(edge["literal"])
                    if target is None:
                        raise GitHubExpansionError(
                            "resolved GitHub edge has no canonical immutable target"
                        )
                    target_commit = target["commit"]
                    target_path = target["path"]
                else:
                    target_commit = source_commit
                    target_path = _repository_path(
                        target_base_path, edge["target"]["path"]
                    )
                target_identity = (target_commit, target_path)
                if target_identity in root_repository_entries:
                    occurrence_status = "root_resolved"
                elif target_identity in expanded:
                    occurrence_status = "expanded"
                    reference = {
                        "source_repository_path": source_repository_path,
                        "source_commit": source_commit,
                        "source_blob_digest": edge["source_blob_digest"],
                        "byte_offset": edge["byte_offset"],
                        "literal_size": edge["literal_size"],
                        "literal_digest": edge["literal_digest"],
                    }
                    target_references = references_by_target.setdefault(
                        target_identity,
                        [],
                    )
                    if reference not in target_references:
                        target_references.append(reference)
                        reference_totals["deduplicated"] += 1
                else:
                    raise GitHubExpansionError(
                        "resolved reference target is absent from retained closure"
                    )
                reference_occurrences.append(
                    _occurrence(
                        edge,
                        source_repository_path=source_repository_path,
                        source_commit=source_commit,
                        target_commit=target_commit,
                        target_repository_path=target_path,
                        status=occurrence_status,
                        reason_code=None,
                    )
                )
                continue
            if (
                edge["reference_kind"] != "github_immutable"
                or edge["reason_code"] != "IMMUTABLE_GITHUB_OBJECT_NOT_RETAINED"
            ):
                if (
                    edge["reference_kind"] == "local"
                    and edge["reason_code"] == "LOCAL_ARTIFACT_NOT_RETAINED"
                ):
                    target = canonical_local_reference_target(
                        edge["literal"],
                        source_path=edge["source_path"],
                    )
                    if target is None:
                        raise GitHubExpansionError(
                            "deferred local reference has no canonical target"
                        )
                    deferred_local_references.append(
                        {
                            "edge": edge,
                            "source_repository_path": source_repository_path,
                            "source_commit": source_commit,
                            "target_commit": source_commit,
                            "target_repository_path": _repository_path(
                                target_base_path, target
                            ),
                        }
                    )
                    continue
                reference_totals["unresolved"] += 1
                reason_code = edge["reason_code"] or "UNSUPPORTED_SOURCE_REFERENCE"
                reference_occurrences.append(
                    _occurrence(
                        edge,
                        source_repository_path=source_repository_path,
                        source_commit=source_commit,
                        target_commit=None,
                        target_repository_path=None,
                        status="unresolved",
                        reason_code=reason_code,
                    )
                )
                add_incomplete(reason_code, source_repository_path)
                continue

            target = parse_immutable_github_reference(edge["literal"])
            if target is None:
                raise GitHubExpansionError(
                    "immutable GitHub edge has no canonical target"
                )
            if not _same_repository(target, root_source):
                reference_totals["unresolved"] += 1
                reference_occurrences.append(
                    _occurrence(
                        edge,
                        source_repository_path=source_repository_path,
                        source_commit=source_commit,
                        target_commit=target["commit"],
                        target_repository_path=target["path"],
                        status="unresolved",
                        reason_code="CROSS_SOURCE_GITHUB_REFERENCE",
                    )
                )
                add_incomplete("CROSS_SOURCE_GITHUB_REFERENCE", source_repository_path)
                continue
            target_commit = target["commit"]
            target_path = target["path"]
            target_identity = (target_commit, target_path)
            reference_totals["artifact_references"] += 1
            if target_identity in root_repository_entries:
                reference_totals["resolved_in_root"] += 1
                reference_occurrences.append(
                    _occurrence(
                        edge,
                        source_repository_path=source_repository_path,
                        source_commit=source_commit,
                        target_commit=target_commit,
                        target_repository_path=target_path,
                        status="root_resolved",
                        reason_code=None,
                    )
                )
                continue

            if next_depth > max_expansion_depth:
                reference_totals["unresolved"] += 1
                reference_occurrences.append(
                    _occurrence(
                        edge,
                        source_repository_path=source_repository_path,
                        source_commit=source_commit,
                        target_commit=target_commit,
                        target_repository_path=target_path,
                        status="unresolved",
                        reason_code="EXPANSION_DEPTH_BUDGET_EXCEEDED",
                    )
                )
                add_incomplete("EXPANSION_DEPTH_BUDGET_EXCEEDED", target_path)
                continue
            reference = {
                "source_repository_path": source_repository_path,
                "source_commit": source_commit,
                "source_blob_digest": edge["source_blob_digest"],
                "byte_offset": edge["byte_offset"],
                "literal_size": edge["literal_size"],
                "literal_digest": edge["literal_digest"],
            }
            target_references = references_by_target.setdefault(target_identity, [])
            reference_is_new = reference not in target_references
            if reference_is_new:
                target_references.append(reference)
            reference_totals["expanded"] += 1
            if target_identity in expanded or target_identity in queued_depth:
                if reference_is_new:
                    reference_totals["deduplicated"] += 1
                reference_occurrences.append(
                    _occurrence(
                        edge,
                        source_repository_path=source_repository_path,
                        source_commit=source_commit,
                        target_commit=target_commit,
                        target_repository_path=target_path,
                        status="expanded",
                        reason_code=None,
                    )
                )
                continue
            if len(expanded) + len(queued_depth) >= max_expanded_objects:
                reference_totals["expanded"] -= 1
                reference_totals["unresolved"] += 1
                reference_occurrences.append(
                    _occurrence(
                        edge,
                        source_repository_path=source_repository_path,
                        source_commit=source_commit,
                        target_commit=target_commit,
                        target_repository_path=target_path,
                        status="unresolved",
                        reason_code="EXPANDED_OBJECT_BUDGET_EXCEEDED",
                    )
                )
                add_incomplete("EXPANDED_OBJECT_BUDGET_EXCEEDED", target_path)
                continue
            if (
                len(root_manifest["files"]) + len(expanded) + len(queued_depth)
                >= _MAX_SUBJECT_FILES
            ):
                reference_totals["expanded"] -= 1
                reference_totals["unresolved"] += 1
                reference_occurrences.append(
                    _occurrence(
                        edge,
                        source_repository_path=source_repository_path,
                        source_commit=source_commit,
                        target_commit=target_commit,
                        target_repository_path=target_path,
                        status="unresolved",
                        reason_code="COMPARATOR_SUBJECT_FILE_BUDGET_EXCEEDED",
                    )
                )
                add_incomplete(
                    "COMPARATOR_SUBJECT_FILE_BUDGET_EXCEEDED",
                    target_path,
                )
                continue
            materialized_path = _materialized_path(
                root_source["commit"],
                target_commit,
                target_path,
            )
            if len(materialized_path) > _MAX_SUBJECT_PATH_LENGTH:
                reference_totals["expanded"] -= 1
                reference_totals["unresolved"] += 1
                reference_occurrences.append(
                    _occurrence(
                        edge,
                        source_repository_path=source_repository_path,
                        source_commit=source_commit,
                        target_commit=target_commit,
                        target_repository_path=target_path,
                        status="unresolved",
                        reason_code="COMPARATOR_SUBJECT_PATH_BUDGET_EXCEEDED",
                    )
                )
                add_incomplete(
                    "COMPARATOR_SUBJECT_PATH_BUDGET_EXCEEDED",
                    target_path,
                )
                continue
            queued_depth[target_identity] = next_depth
            pending.append(target_identity)
            maximum_depth_used = max(maximum_depth_used, next_depth)
            reference_occurrences.append(
                _occurrence(
                    edge,
                    source_repository_path=source_repository_path,
                    source_commit=source_commit,
                    target_commit=target_commit,
                    target_repository_path=target_path,
                    status="expanded",
                    reason_code=None,
                )
            )

    root_by_path = {entry["path"]: entry for entry in root_manifest["files"]}
    repository_source = {
        **root_source,
        "skill_path": ".",
        "skill_tree": root_source["commit_tree"],
    }
    for entry in root_manifest["files"]:
        content = root_content[entry["digest"]]
        try:
            edges = _scan_entry(
                content,
                source_entry=entry,
                source=root_source,
                source_by_path=root_by_path,
            )
        except _IncompleteExpansion as exc:
            reference_totals["total_edges"] += exc.references_seen
            if exc.reason_code in {
                "OPAQUE_SOURCE_CARRIER",
                "NUL_CONTAINING_SOURCE_CARRIER",
                "NON_UTF8_SOURCE_CARRIER",
            }:
                reference_totals["opaque_carriers"] += 1
            add_incomplete(exc.reason_code, exc.subject)
            mark_scan_incomplete(stop=exc.reason_code == "REFERENCE_BUDGET_EXCEEDED")
            if stop_scanning:
                break
            continue
        register_edges(
            edges,
            source_repository_path=_repository_path(
                root_source["skill_path"], entry["path"]
            ),
            source_commit=root_source["commit"],
            target_base_path=root_source["skill_path"],
            next_depth=1,
        )
        if stop_scanning:
            break

    if not incomplete_reasons:
        while pending:
            depth = queued_depth[pending[0]]
            layer: list[tuple[str, str]] = []
            while pending and queued_depth[pending[0]] == depth:
                target_identity = pending.popleft()
                queued_depth.pop(target_identity)
                layer.append(target_identity)
            layer.sort()

            for target_commit, repository_path in layer:
                remaining_bytes = max_retained_bytes - retained_bytes
                try:
                    target_session = session_for_commit(target_commit)
                    staged = target_session.read_repository_blob(
                        repository_path,
                        max_file_size=min(max_file_size, remaining_bytes),
                    )
                except GitHubBudgetExceeded:
                    add_incomplete("ACQUISITION_BUDGET_EXCEEDED", repository_path)
                    break
                except GitHubAcquisitionError as exc:
                    expected_reason = _expected_blob_failure(
                        exc, remaining_bytes, max_file_size
                    )
                    if expected_reason is None:
                        raise GitHubExpansionError(str(exc)) from exc
                    add_incomplete(expected_reason, repository_path)
                    break
                content = staged.pop("content")
                digest = _digest_bytes(content)
                retained_bytes += staged["size"]
                if retained_bytes > max_retained_bytes:
                    add_incomplete("RETAINED_BYTE_BUDGET_EXCEEDED", repository_path)
                    break
                entry = {
                    **staged,
                    "commit": target_commit,
                    "commit_tree": target_session.root_tree_sha,
                    "digest": digest,
                }
                expanded[(target_commit, repository_path)] = {
                    **entry,
                    "depth": depth,
                    "materialized_path": _materialized_path(
                        root_source["commit"],
                        target_commit,
                        repository_path,
                    ),
                }
                all_content.setdefault(digest, content)

            if incomplete_reasons:
                break
            if terminal_depth_1:
                continue
            for target_commit, repository_path in layer:
                target_identity = (target_commit, repository_path)
                repository_entries = {
                    path: {
                        "path": path,
                        "size": value["size"],
                        "digest": value["digest"],
                        "git_blob_sha1": value["git_blob_sha1"],
                        "executable": value["executable"],
                    }
                    for (entry_commit, path), value in {
                        **root_repository_entries,
                        **expanded,
                    }.items()
                    if entry_commit == target_commit
                }
                target_source = {
                    **repository_source,
                    "commit": target_commit,
                    "commit_tree": sessions[target_commit].root_tree_sha,
                }
                content = all_content[expanded[target_identity]["digest"]]
                try:
                    edges = _scan_entry(
                        content,
                        source_entry=repository_entries[repository_path],
                        source=target_source,
                        source_by_path=repository_entries,
                    )
                except _IncompleteExpansion as exc:
                    reference_totals["total_edges"] += exc.references_seen
                    if exc.reason_code in {
                        "OPAQUE_SOURCE_CARRIER",
                        "NUL_CONTAINING_SOURCE_CARRIER",
                        "NON_UTF8_SOURCE_CARRIER",
                    }:
                        reference_totals["opaque_carriers"] += 1
                    add_incomplete(exc.reason_code, exc.subject)
                    mark_scan_incomplete(
                        stop=exc.reason_code == "REFERENCE_BUDGET_EXCEEDED"
                    )
                    if stop_scanning:
                        break
                    continue
                register_edges(
                    edges,
                    source_repository_path=repository_path,
                    source_commit=target_commit,
                    target_base_path=".",
                    next_depth=depth + 1,
                )
                if stop_scanning:
                    break

            if incomplete_reasons:
                break

        if not incomplete_reasons:
            try:
                session.check_deadline()
            except GitHubBudgetExceeded:
                add_incomplete(
                    "ACQUISITION_DEADLINE_EXCEEDED",
                    root_source["skill_path"],
                )

    for deferred in deferred_local_references:
        target_commit = deferred["target_commit"]
        target_path = deferred["target_repository_path"]
        target_identity = (target_commit, target_path)
        if target_identity in root_repository_entries:
            status = "root_resolved"
            reason_code = None
        elif target_identity in expanded:
            status = "expanded"
            reason_code = None
            reference = {
                "source_repository_path": deferred["source_repository_path"],
                "source_commit": deferred["source_commit"],
                "source_blob_digest": deferred["edge"]["source_blob_digest"],
                "byte_offset": deferred["edge"]["byte_offset"],
                "literal_size": deferred["edge"]["literal_size"],
                "literal_digest": deferred["edge"]["literal_digest"],
            }
            target_references = references_by_target.setdefault(target_identity, [])
            if reference not in target_references:
                target_references.append(reference)
                reference_totals["deduplicated"] += 1
        else:
            status = "unresolved"
            reason_code = "LOCAL_ARTIFACT_NOT_RETAINED"
            add_incomplete(
                reason_code,
                deferred["source_repository_path"],
            )
        reference_occurrences.append(
            _occurrence(
                deferred["edge"],
                source_repository_path=deferred["source_repository_path"],
                source_commit=deferred["source_commit"],
                target_commit=target_commit,
                target_repository_path=target_path,
                status=status,
                reason_code=reason_code,
            )
        )

    complete = not incomplete_reasons
    comparator_manifest: dict[str, Any] | None = None
    comparator_manifest_digest: str | None = None
    comparator_tree_digest: str | None = None
    objects: list[dict[str, Any]] = []
    if complete:
        comparator_manifest = _comparator_subject(root_manifest, expanded)
        try:
            validate_subject_manifest(comparator_manifest)
        except WorkerProtocolError as exc:
            raise GitHubExpansionError(
                f"expanded comparator subject is invalid: {exc}"
            ) from exc
        comparator_manifest_digest = canonical_digest(comparator_manifest)
        comparator_tree_digest = comparator_manifest["tree_digest"]
        for target_identity in sorted(expanded):
            target_commit, repository_path = target_identity
            item = expanded[target_identity]
            objects.append(
                {
                    "commit": target_commit,
                    "commit_tree": item["commit_tree"],
                    "repository_path": repository_path,
                    "materialized_path": item["materialized_path"],
                    "depth": item["depth"],
                    "size": item["size"],
                    "digest": item["digest"],
                    "git_blob_sha1": item["git_blob_sha1"],
                    "executable": item["executable"],
                    "references": sorted(
                        references_by_target[target_identity],
                        key=lambda reference: (
                            reference["source_commit"],
                            reference["source_repository_path"],
                            reference["byte_offset"],
                            reference["literal_size"],
                            reference["literal_digest"],
                        ),
                    ),
                }
            )
    else:
        failure_code = incomplete_reasons[0]["reason_code"]
        for occurrence in reference_occurrences:
            if occurrence["status"] == "expanded":
                occurrence["status"] = "unresolved"
                occurrence["reason_code"] = failure_code

    reference_occurrences.sort(
        key=lambda occurrence: (
            occurrence["source_commit"],
            occurrence["source_repository_path"],
            occurrence["byte_offset"],
            occurrence["literal_size"],
            occurrence["literal_digest"],
            occurrence["target_commit"] or "",
            occurrence["target_repository_path"] or "",
            occurrence["status"],
        )
    )
    reference_totals["artifact_references"] = len(reference_occurrences)
    reference_totals["resolved_in_root"] = sum(
        item["status"] == "root_resolved" for item in reference_occurrences
    )
    reference_totals["expanded"] = sum(
        item["status"] == "expanded" for item in reference_occurrences
    )
    reference_totals["unresolved"] = sum(
        item["status"] == "unresolved" for item in reference_occurrences
    )

    accounting = {
        "references": reference_totals,
        "budgets": {
            **session.budget_snapshot(),
            "retained_bytes": {
                "limit": max_retained_bytes,
                "used": retained_bytes,
            },
            "expanded_objects": {
                "limit": max_expanded_objects,
                "used": len(expanded),
            },
            "expansion_depth": {
                "limit": max_expansion_depth,
                "used": maximum_depth_used,
            },
            "references": {
                "limit": max_references,
                "used": min(reference_totals["total_edges"], max_references),
            },
        },
    }
    closure = {
        "scope": closure_scope,
        "status": "complete" if complete else "incomplete",
        "unresolved": sorted(
            incomplete_reasons,
            key=lambda item: (item["reason_code"], item["subject"]),
        ),
    }
    expansion = {
        "schema": "aragorn/github-expansion/v1",
        "profile": profile,
        "assurance": assurance,
        "source": {
            "host": "github.com",
            "owner": root_source["owner"],
            "repository": root_source["repository"],
            "commit": root_source["commit"],
            "commit_tree": root_source["commit_tree"],
            "skill_path": root_source["skill_path"],
            "api_version": API_VERSION,
        },
        "root_manifest_digest": root_manifest_digest,
        "root_tree_digest": root_manifest["tree_digest"],
        "comparator_subject_manifest_digest": comparator_manifest_digest,
        "comparator_subject_tree_digest": comparator_tree_digest,
        "references": reference_occurrences,
        "objects": objects,
        "accounting": accounting,
        "closure": closure,
    }

    root_record = _record_bytes(root_manifest, "root manifest")
    record_failure: tuple[str, str] | None = None
    comparator_record: bytes | None = None
    if comparator_manifest is not None:
        try:
            comparator_record = _record_bytes(
                comparator_manifest,
                "comparator subject manifest",
            )
        except GitHubExpansionError:
            record_failure = (
                "COMPARATOR_SUBJECT_RECORD_BUDGET_EXCEEDED",
                "comparator-subject-manifest",
            )
    if record_failure is None:
        try:
            expansion_record = _record_bytes(expansion, "GitHub expansion")
        except GitHubExpansionError:
            record_failure = (
                "EXPANSION_RECORD_BUDGET_EXCEEDED",
                "github-expansion",
            )
    if record_failure is not None:
        add_incomplete(*record_failure)
        complete = False
        comparator_manifest = None
        comparator_manifest_digest = None
        comparator_tree_digest = None
        comparator_record = None
        objects = []
        compact_reference_totals = {
            **reference_totals,
            "occurrences_complete": False,
            "occurrences_omitted": (
                len(reference_occurrences)
                if reference_totals["scan_complete"]
                else None
            ),
        }
        accounting = {
            **accounting,
            "references": compact_reference_totals,
        }
        closure = {
            "scope": closure_scope,
            "status": "incomplete",
            "unresolved": sorted(
                incomplete_reasons,
                key=lambda item: (item["reason_code"], item["subject"]),
            ),
        }
        expansion.update(
            {
                "comparator_subject_manifest_digest": None,
                "comparator_subject_tree_digest": None,
                "references": [],
                "objects": [],
                "accounting": accounting,
                "closure": closure,
            }
        )
        expansion_record = _record_bytes(
            expansion,
            "compact incomplete GitHub expansion",
        )

    # No CAS object is published before recursive scanning reaches a complete or
    # explicitly incomplete, bounded versioned outcome.
    published_content = all_content if complete else root_content
    for digest in sorted(published_content):
        actual = cas.put(
            BytesIO(published_content[digest]),
            max_bytes=len(published_content[digest]),
        )
        if actual != digest:
            raise GitHubExpansionError("retained content digest changed during publish")
    actual_root_digest = _put_record(cas, root_record)
    if actual_root_digest != root_manifest_digest:
        raise GitHubExpansionError("root manifest digest changed during publish")
    if comparator_record is not None:
        actual_subject_digest = _put_record(cas, comparator_record)
        if actual_subject_digest != comparator_manifest_digest:
            raise GitHubExpansionError(
                "comparator manifest digest changed during publish"
            )
    expansion_digest = _put_record(cas, expansion_record)

    return {
        "schema": "aragorn/github-expansion-result/v1",
        "expansion_digest": expansion_digest,
        "root_manifest_digest": root_manifest_digest,
        "root_tree_digest": root_manifest["tree_digest"],
        "comparator_subject_manifest_digest": comparator_manifest_digest,
        "comparator_subject_tree_digest": comparator_tree_digest,
        "expanded_object_count": len(objects),
        "accounting": accounting,
        "closure": closure,
    }


def resolve_terminal_source_graph(
    manifest: object,
    cas: CAS,
    expansion: object,
    *,
    root_manifest_digest: str,
) -> dict[str, Any]:
    """Derive a source graph from a verified terminal-depth-1 expansion."""

    if not isinstance(expansion, dict):
        raise GitHubExpansionError("terminal expansion must be a JSON object")
    if (
        expansion.get("profile") != TERMINAL_DEPTH_1_PROFILE
        or expansion.get("assurance") != TERMINAL_DEPTH_1_ASSURANCE
        or expansion.get("closure")
        != {
            "scope": "phase0_exact_github_blob_expansion_terminal_depth_1",
            "status": "complete",
            "unresolved": [],
        }
    ):
        raise GitHubExpansionError("terminal expansion is not complete")

    try:
        normalized_manifest, expanded_files = _validate_manifest(manifest, cas)
    except (ValueError, CASError) as exc:
        raise GitHubExpansionError(
            f"expanded source manifest is invalid: {exc}"
        ) from exc
    if normalized_manifest["schema"] != "aragorn/manifest/v1":
        raise GitHubExpansionError(
            "expanded source manifest must be a re-ingested local tree"
        )
    if _digest_document(normalized_manifest) != root_manifest_digest:
        raise GitHubExpansionError(
            "expanded source manifest digest does not match candidate evidence"
        )

    comparator_digest = expansion.get("comparator_subject_manifest_digest")
    comparator_tree = expansion.get("comparator_subject_tree_digest")
    if not isinstance(comparator_digest, str) or not isinstance(
        comparator_tree, str
    ):
        raise GitHubExpansionError(
            "terminal expansion omits its comparator subject"
        )
    try:
        comparator_raw = cas.read(comparator_digest, max_bytes=MAX_RECORD_BYTES)
        comparator = json.loads(comparator_raw)
    except (CASError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubExpansionError(
            f"terminal comparator subject is unavailable or invalid: {exc}"
        ) from exc
    if canonical_json(comparator) != comparator_raw:
        raise GitHubExpansionError(
            "terminal comparator subject must use canonical JSON"
        )
    try:
        validate_subject_manifest(comparator)
        expanded_subject = sanitize_subject_manifest(normalized_manifest)
    except WorkerProtocolError as exc:
        raise GitHubExpansionError(
            f"terminal comparator subject is invalid: {exc}"
        ) from exc
    if (
        canonical_digest(comparator) != comparator_digest
        or comparator.get("tree_digest") != comparator_tree
        or expanded_subject != comparator
    ):
        raise GitHubExpansionError(
            "expanded source manifest does not exactly match retained "
            "comparator subject"
        )

    root_digest = expansion.get("root_manifest_digest")
    if not isinstance(root_digest, str):
        raise GitHubExpansionError("terminal expansion omits its root manifest")
    try:
        root_manifest = load_retained_manifest(cas, root_digest)
        normalized_root, root_files = _validate_manifest(root_manifest, cas)
    except (ValueError, CASError) as exc:
        raise GitHubExpansionError(
            f"terminal root manifest is invalid: {exc}"
        ) from exc
    if (
        normalized_root["schema"] != "aragorn/github-manifest/v1"
        or _digest_document(normalized_root) != root_digest
        or normalized_root["tree_digest"] != expansion.get("root_tree_digest")
    ):
        raise GitHubExpansionError(
            "terminal expansion root manifest binding changed"
        )
    source = normalized_root["source"]
    expansion_source = expansion.get("source")
    source_fields = (
        "host",
        "owner",
        "repository",
        "commit",
        "commit_tree",
        "skill_path",
        "api_version",
    )
    if not isinstance(expansion_source, dict) or any(
        source.get(field) != expansion_source.get(field)
        for field in source_fields
    ):
        raise GitHubExpansionError(
            "terminal expansion source does not match its root manifest"
        )

    objects = expansion.get("objects")
    references = expansion.get("references")
    if not isinstance(objects, list) or not isinstance(references, list):
        raise GitHubExpansionError(
            "terminal expansion objects and references must be arrays"
        )
    expanded_by_path = {entry["path"]: entry for entry in expanded_files}
    expected_subject_files = [
        {
            "path": entry["path"],
            "size": entry["size"],
            "digest": entry["digest"],
            "executable": False,
        }
        for entry in root_files
    ]
    targets: dict[tuple[str, str], dict[str, Any]] = {
        (
            source["commit"],
            _repository_path(source["skill_path"], entry["path"]),
        ): {
            "path": entry["path"],
            "digest": entry["digest"],
            "status": "root_resolved",
        }
        for entry in root_files
    }
    object_reference_keys: dict[
        tuple[str, str], set[tuple[str, str, str, int, int, str]]
    ] = {}
    for item in objects:
        if not isinstance(item, dict) or item.get("depth") != 1:
            raise GitHubExpansionError(
                "terminal expansion contains a non-terminal object"
            )
        identity = (item.get("commit"), item.get("repository_path"))
        materialized_path = item.get("materialized_path")
        if (
            not all(isinstance(value, str) for value in identity)
            or not isinstance(materialized_path, str)
            or materialized_path
            != _materialized_path(
                source["commit"],
                identity[0],
                identity[1],
            )
            or identity in targets
        ):
            raise GitHubExpansionError(
                "terminal expansion object identity or materialized path changed"
            )
        retained = expanded_by_path.get(materialized_path)
        expected = {
            "path": materialized_path,
            "size": item.get("size"),
            "digest": item.get("digest"),
            "executable": False,
        }
        if retained != expected:
            raise GitHubExpansionError(
                "terminal expansion object does not match re-ingested bytes"
            )
        expected_subject_files.append(expected)
        targets[identity] = {
            "path": materialized_path,
            "digest": item["digest"],
            "status": "expanded",
        }
        raw_object_references = item.get("references")
        if not isinstance(raw_object_references, list):
            raise GitHubExpansionError(
                "terminal expansion object references must be an array"
            )
        object_reference_keys[identity] = {
            _terminal_reference_key(reference)
            for reference in raw_object_references
            if isinstance(reference, dict)
        }
        if len(object_reference_keys[identity]) != len(raw_object_references):
            raise GitHubExpansionError(
                "terminal expansion object references are not unique"
            )
    expected_subject_files.sort(key=lambda entry: entry["path"])
    if comparator["files"] != expected_subject_files:
        raise GitHubExpansionError(
            "retained comparator subject does not match root and terminal objects"
        )

    references_by_key: dict[
        tuple[str, str, str, int, int, str], dict[str, Any]
    ] = {}
    expected_object_references: dict[
        tuple[str, str], set[tuple[str, str, str, int, int, str]]
    ] = {identity: set() for identity in object_reference_keys}
    for reference in references:
        if not isinstance(reference, dict):
            raise GitHubExpansionError(
                "terminal expansion reference must be an object"
            )
        key = _terminal_reference_key(reference)
        if (
            key in references_by_key
            or reference.get("source_commit") != source["commit"]
            or reference.get("status") not in {"root_resolved", "expanded"}
            or reference.get("reason_code") is not None
        ):
            raise GitHubExpansionError(
                "terminal expansion reference identity or status changed"
            )
        target_identity = (
            reference.get("target_commit"),
            reference.get("target_repository_path"),
        )
        target = targets.get(target_identity)
        if target is None or target["status"] != reference["status"]:
            raise GitHubExpansionError(
                "terminal expansion reference target is not retained"
            )
        references_by_key[key] = reference
        if reference["status"] == "expanded":
            expected_object_references[target_identity].add(key)
    if expected_object_references != object_reference_keys:
        raise GitHubExpansionError(
            "terminal expansion object occurrence binding changed"
        )

    root_by_path = {entry["path"]: entry for entry in root_files}
    graph_edges: list[dict[str, Any]] = []
    consumed: set[tuple[str, str, str, int, int, str]] = set()
    for entry in root_files:
        try:
            content = cas.read(entry["digest"], max_bytes=entry["size"])
            scanned = _scan_entry(
                content,
                source_entry=entry,
                source=source,
                source_by_path=root_by_path,
            )
        except (CASError, _IncompleteExpansion) as exc:
            raise GitHubExpansionError(
                f"terminal root source graph is incomplete: {exc}"
            ) from exc

        immutable_targets = {
            (target["commit"], target["path"])
            for edge in scanned
            if edge["reference_kind"] == "github_immutable"
            for target in [parse_immutable_github_reference(edge["literal"])]
            if target is not None
        }
        suppressed_dynamic = {
            (
                edge["source_path"],
                edge["byte_offset"],
                edge["literal_digest"],
            )
            for edge in scanned
            if edge["reference_kind"] == "dynamic_command"
            and edge["status"] == "unresolved"
            for target in [exact_raw_github_fetch_target(edge["literal"])]
            if target is not None
            and (target["commit"], target["path"]) in immutable_targets
            and _same_repository(target, source)
        }
        for edge in scanned:
            if (
                edge["reference_kind"] == "dynamic_command"
                and (
                    edge["source_path"],
                    edge["byte_offset"],
                    edge["literal_digest"],
                )
                in suppressed_dynamic
            ):
                continue
            graph_edge = {
                key: value for key, value in edge.items() if key != "literal_size"
            }
            if edge["status"] == "non_artifact":
                graph_edges.append(graph_edge)
                continue
            source_repository_path = _repository_path(
                source["skill_path"], edge["source_path"]
            )
            key = (
                source["commit"],
                source_repository_path,
                edge["source_blob_digest"],
                edge["byte_offset"],
                edge["literal_size"],
                edge["literal_digest"],
            )
            reference = references_by_key.get(key)
            if reference is None:
                raise GitHubExpansionError(
                    "root source edge has no exact terminal expansion occurrence"
                )
            target_commit, target_path = _terminal_edge_target(
                edge,
                source=source,
            )
            if (
                target_commit != reference["target_commit"]
                or target_path != reference["target_repository_path"]
            ):
                raise GitHubExpansionError(
                    "terminal expansion occurrence target changed"
                )
            target = targets[(target_commit, target_path)]
            graph_edge.update(
                {
                    "status": "resolved",
                    "target": {
                        "path": target["path"],
                        "digest": target["digest"],
                    },
                    "reason_code": None,
                }
            )
            graph_edges.append(graph_edge)
            consumed.add(key)
    if consumed != set(references_by_key):
        raise GitHubExpansionError(
            "terminal expansion contains an unproved root occurrence"
        )

    nodes = [
        {
            "path": expanded_by_path[entry["path"]]["path"],
            "size": expanded_by_path[entry["path"]]["size"],
            "digest": expanded_by_path[entry["path"]]["digest"],
            "executable": expanded_by_path[entry["path"]]["executable"],
            "scan_status": "scanned",
            "opaque_reason": None,
        }
        for entry in root_files
    ]
    nodes.extend(
        {
            "path": item["materialized_path"],
            "size": item["size"],
            "digest": item["digest"],
            "executable": False,
            "scan_status": "terminal",
            "opaque_reason": None,
        }
        for item in objects
    )
    graph_edges.sort(
        key=lambda item: (
            item["source_path"],
            item["byte_offset"],
            item["literal_digest"],
            item["reference_kind"],
            item["status"],
        )
    )
    return {
        "schema": "aragorn/source-artifact-graph/v1",
        "profile": TERMINAL_DEPTH_1_PROFILE,
        "assurance": TERMINAL_DEPTH_1_ASSURANCE,
        "source_assurance": (
            "github_api_membership_asserted_blob_identity_reverified"
        ),
        "root_manifest_digest": root_manifest_digest,
        "tree_digest": normalized_manifest["tree_digest"],
        "nodes": sorted(nodes, key=lambda item: item["path"]),
        "edges": graph_edges,
        "closure": {
            "scope": "source_reference_graph",
            "profile": TERMINAL_DEPTH_1_PROFILE,
            "status": "complete",
            "unresolved": [],
        },
    }


def _terminal_reference_key(
    reference: dict[str, Any],
) -> tuple[str, str, str, int, int, str]:
    try:
        return (
            reference["source_commit"],
            reference["source_repository_path"],
            reference["source_blob_digest"],
            reference["byte_offset"],
            reference["literal_size"],
            reference["literal_digest"],
        )
    except (KeyError, TypeError) as exc:
        raise GitHubExpansionError(
            "terminal expansion reference identity is incomplete"
        ) from exc


def _terminal_edge_target(
    edge: dict[str, Any],
    *,
    source: dict[str, Any],
) -> tuple[str, str]:
    literal = edge["literal"]
    if edge["reference_kind"] == "github_immutable":
        target = parse_immutable_github_reference(literal)
        if target is None or not _same_repository(target, source):
            raise GitHubExpansionError(
                "terminal GitHub edge has no exact same-repository target"
            )
        return target["commit"], target["path"]
    if edge["reference_kind"] == "local":
        target_path = canonical_local_reference_target(
            literal,
            source_path=edge["source_path"],
        )
        if target_path is None:
            raise GitHubExpansionError(
                "terminal local edge has no canonical target"
            )
        return (
            source["commit"],
            _repository_path(source["skill_path"], target_path),
        )
    raise GitHubExpansionError(
        "terminal expansion retained an unsupported artifact edge"
    )


def _stage_root(
    session: GitHubAcquisitionSession,
    skill_path: str,
    *,
    max_source_depth: int,
    max_source_entries: int,
    max_file_size: int,
    max_retained_bytes: int,
) -> tuple[dict[str, Any], dict[str, bytes], int]:
    skill_tree_sha, skill_parts = session.resolve_tree(skill_path)
    pending_files: list[dict[str, Any]] = []
    entries_seen = 0
    retained_bytes = 0

    def walk(tree_sha: str, parts: tuple[str, ...]) -> None:
        nonlocal entries_seen, retained_bytes
        for entry in session.read_tree(tree_sha):
            entries_seen += 1
            if entries_seen > max_source_entries:
                raise GitHubAcquisitionError("maximum source entry count exceeded")
            relative_parts = (*parts, entry["path"])
            relative_path = "/".join(relative_parts)
            if entry["type"] == "tree":
                if len(relative_parts) > max_source_depth:
                    raise GitHubAcquisitionError(
                        f"maximum source depth exceeded at {relative_path}"
                    )
                walk(entry["sha"], relative_parts)
                continue
            if entry["size"] > max_file_size:
                raise GitHubAcquisitionError(
                    f"maximum file size exceeded: {relative_path}"
                )
            retained_bytes += entry["size"]
            if retained_bytes > max_retained_bytes:
                raise GitHubAcquisitionError("maximum retained byte count exceeded")
            pending_files.append(
                {
                    "path": relative_path,
                    "size": entry["size"],
                    "git_blob_sha1": entry["sha"],
                    "executable": entry["mode"] == "100755",
                }
            )

    walk(skill_tree_sha, ())
    if not pending_files:
        raise GitHubAcquisitionError("skill root contains no supported files")

    content_by_digest: dict[str, bytes] = {}
    files = []
    for pending in pending_files:
        repository_path = (
            pending["path"]
            if not skill_parts
            else "/".join((*skill_parts, pending["path"]))
        )
        staged = session.read_repository_blob(
            repository_path,
            max_file_size=max_file_size,
        )
        content = staged.pop("content")
        if (
            staged["size"] != pending["size"]
            or staged["git_blob_sha1"] != pending["git_blob_sha1"]
            or staged["executable"] != pending["executable"]
        ):
            raise GitHubAcquisitionError(
                f"Git tree membership changed during acquisition: {pending['path']}"
            )
        digest = _digest_bytes(content)
        content_by_digest.setdefault(digest, content)
        files.append({**pending, "digest": digest})

    files.sort(key=lambda item: item["path"])
    reserved_prefix = MATERIALIZED_PREFIX.casefold()
    if any(
        entry["path"].casefold() == reserved_prefix
        or entry["path"].casefold().startswith(f"{reserved_prefix}/")
        for entry in files
    ):
        raise GitHubAcquisitionError(
            f"skill root uses reserved comparator path: {MATERIALIZED_PREFIX}"
        )
    tree_files = [
        {
            "path": entry["path"],
            "size": entry["size"],
            "digest": entry["digest"],
            "executable": entry["executable"],
        }
        for entry in files
    ]
    manifest = {
        "schema": "aragorn/github-manifest/v1",
        "source": {
            "kind": "github_commit",
            "host": "github.com",
            "owner": session.owner,
            "repository": session.repository,
            "commit": session.commit,
            "repository_hash_algorithm": "sha1",
            "commit_tree": session.root_tree_sha,
            "skill_path": "." if not skill_parts else "/".join(skill_parts),
            "skill_tree": skill_tree_sha,
            "api_version": API_VERSION,
        },
        "tree_digest": _digest_bytes(canonical_json(tree_files)),
        "files": files,
        "closure": {"scope": "source_tree", "status": "complete"},
    }
    return manifest, content_by_digest, retained_bytes


def _scan_entry(
    content: bytes,
    *,
    source_entry: dict[str, Any],
    source: dict[str, Any],
    source_by_path: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    suffix = PurePosixPath(source_entry["path"]).suffix.casefold()
    if suffix not in TEXT_CARRIER_SUFFIXES or len(content) > MAX_SCANNED_TEXT_BYTES:
        raise _IncompleteExpansion("OPAQUE_SOURCE_CARRIER", source_entry["path"])
    if b"\0" in content:
        raise _IncompleteExpansion(
            "NUL_CONTAINING_SOURCE_CARRIER", source_entry["path"]
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _IncompleteExpansion(
            "NON_UTF8_SOURCE_CARRIER", source_entry["path"]
        ) from exc
    try:
        edges = scan_retained_text_references(
            text,
            source_entry=source_entry,
            source=source,
            source_by_path=source_by_path,
            redact_dynamic_literals=False,
            include_literal_size=True,
        )
    except ReferenceBudgetExceeded as exc:
        raise _IncompleteExpansion(
            "REFERENCE_BUDGET_EXCEEDED",
            source_entry["path"],
            references_seen=exc.references_seen,
        ) from exc
    return tuple(
        {
            **edge,
            "reason_code": "IMMUTABLE_GITHUB_OBJECT_NOT_RETAINED",
        }
        if _standalone_raw_github_reference(content, edge)
        else edge
        for edge in edges
    )


def _standalone_raw_github_reference(
    content: bytes,
    edge: dict[str, Any],
) -> bool:
    literal = edge["literal"]
    if (
        edge["reference_kind"] != "github_immutable"
        or edge["status"] != "unresolved"
        or edge["reason_code"] != "BARE_IMMUTABLE_REFERENCE_CONTEXT_UNSUPPORTED"
        or not isinstance(literal, str)
        or not literal.startswith("https://raw.githubusercontent.com/")
        or parse_immutable_github_reference(literal) is None
    ):
        return False
    start = edge["byte_offset"]
    end = start + edge["literal_size"]
    if not 0 <= start < end <= len(content):
        return False
    try:
        literal_bytes = literal.encode("ascii")
    except UnicodeEncodeError:
        return False
    if content[start:end] != literal_bytes:
        return False
    line_start = content.rfind(b"\n", 0, start) + 1
    line_end = content.find(b"\n", end)
    if line_end < 0:
        line_end = len(content)
    return (
        not content[line_start:start].strip(b" \t")
        and not content[end:line_end].strip(b" \t\r")
    )


def _comparator_subject(
    root_manifest: dict[str, Any],
    expanded: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    files = [
        {
            "path": entry["path"],
            "size": entry["size"],
            "digest": entry["digest"],
            "executable": False,
        }
        for entry in root_manifest["files"]
    ]
    files.extend(
        {
            "path": item["materialized_path"],
            "size": item["size"],
            "digest": item["digest"],
            "executable": False,
        }
        for item in expanded.values()
    )
    files.sort(key=lambda entry: entry["path"])
    if len(files) > _MAX_SUBJECT_FILES:
        raise GitHubExpansionError(
            "expanded comparator subject exceeds file count limit"
        )
    return {
        "schema": "aragorn/benchmark-subject-manifest/v1",
        "tree_digest": canonical_digest(files),
        "files": files,
    }


def _same_repository(target: dict[str, str], source: dict[str, Any]) -> bool:
    return (
        target["owner"] == source["owner"]
        and target["repository"] == source["repository"]
    )


def _materialized_path(
    root_commit: str,
    target_commit: str,
    repository_path: str,
) -> str:
    commit_prefix = "" if target_commit == root_commit else f"{target_commit}/"
    return f"{MATERIALIZED_PREFIX}/{commit_prefix}{repository_path}"


def _repository_path(skill_path: str, relative_path: str) -> str:
    return relative_path if skill_path == "." else f"{skill_path}/{relative_path}"


def _occurrence(
    edge: dict[str, Any],
    *,
    source_repository_path: str,
    source_commit: str,
    target_commit: str | None,
    target_repository_path: str | None,
    status: str,
    reason_code: str | None,
) -> dict[str, Any]:
    return {
        "source_repository_path": source_repository_path,
        "source_commit": source_commit,
        "source_blob_digest": edge["source_blob_digest"],
        "byte_offset": edge["byte_offset"],
        "literal_size": edge["literal_size"],
        "literal_digest": edge["literal_digest"],
        "target_commit": target_commit,
        "target_repository_path": target_repository_path,
        "status": status,
        "reason_code": reason_code,
    }


def _expected_blob_failure(
    error: GitHubAcquisitionError,
    remaining_bytes: int,
    max_file_size: int,
) -> str | None:
    message = str(error)
    if "Git LFS pointer rejected" in message:
        return "GIT_LFS_OBJECT_UNRESOLVED"
    if "repository path does not exist" in message:
        return "IMMUTABLE_GITHUB_OBJECT_NOT_FOUND"
    if "repository path crosses a non-directory" in message:
        return "IMMUTABLE_GITHUB_OBJECT_NOT_A_BLOB"
    if "repository path is not a supported blob" in message:
        return "IMMUTABLE_GITHUB_OBJECT_NOT_A_BLOB"
    if "symlink rejected" in message:
        return "GIT_SYMLINK_UNSUPPORTED"
    if "submodule rejected" in message:
        return "GIT_SUBMODULE_UNSUPPORTED"
    if "unsupported Git object type or mode" in message:
        return "GIT_OBJECT_MODE_UNSUPPORTED"
    if "GitHub tree contains an unsafe path component" in message:
        return "GIT_TREE_PATH_UNSUPPORTED"
    if "duplicate or colliding Git tree entry" in message:
        return "GIT_TREE_AMBIGUOUS"
    if "GitHub tree response is truncated or ambiguous" in message:
        return "GIT_TREE_TRUNCATED_OR_AMBIGUOUS"
    if "blob size is invalid" in message:
        return "GIT_TREE_BLOB_SIZE_INVALID"
    if "maximum file size exceeded" in message:
        return (
            "RETAINED_BYTE_BUDGET_EXCEEDED"
            if remaining_bytes < max_file_size
            else "FILE_SIZE_BUDGET_EXCEEDED"
        )
    return None


def _bounded_integer(
    name: str,
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise GitHubExpansionError(
            f"{name} must be an integer between {minimum} and {maximum}"
        )
    return value


def _digest_bytes(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _digest_document(document: object) -> str:
    return _digest_bytes(canonical_json(document))


def _record_bytes(document: dict[str, Any], record_name: str) -> bytes:
    raw = canonical_json(document)
    if len(raw) > MAX_RECORD_BYTES:
        raise GitHubExpansionError(f"{record_name} exceeds its byte limit")
    return raw


def _put_record(cas: CAS, raw: bytes) -> str:
    return cas.put(BytesIO(raw), max_bytes=len(raw))
