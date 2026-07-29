"""Offline semantic replay for one retained Phase 1 install/update capture."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tarfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from . import (
    admission_artifact_graph,
    analyzer_receipt,
    decision_receipt,
    github_gateway_live_evidence,
    github_quarantine_receipt,
)
from .artifact_closure import canonical_json, load_verified_retained_manifest
from .cas import CAS
from .github_gateway import build_gateway_request
from .manifest_diff import diff_verified_manifests_between
from .oci_worker_protocol import canonical_digest
from .protected_install import _transaction_record, _version_path
from .protected_install_context import VerifiedInstallContextV2

AUTHORITY = "OFF_HOST_REPLAY_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
ARCHIVE_DIGEST = (
    "sha256:738a57537a9c1ad24736f0cb5a3ce9507debb830f632ec4e7606d09ee6302aec"
)
INSTALL_EVIDENCE_DIGEST = (
    "sha256:71bfaa2318576443841ee7b6de097ba0df07c19ad1be22d42bed39c058fb0d04"
)
UPDATE_EVIDENCE_DIGEST = (
    "sha256:42e0cf87abb76f4a3c65c7f97c2c5d89a9c277ee5a0772da86300da292473a9c"
)
CONSUMED_EVIDENCE_DIGEST = (
    "sha256:94faa277bb26b623899c75e927ad488b189b95b5b29cbcaec3fa9b6001d75a3d"
)
STALE_EVIDENCE_DIGEST = (
    "sha256:e7d1a12400fbe2cdb8337018c6db26ad129ea8b876a4dbd432b50ca723e9356a"
)
CAPTURE_EVIDENCE_DIGEST = (
    "sha256:85f043ce3b49711251129d877996f0e6e7d31c09da56b46af50704d98d4867dd"
)

_OLD_CAS = "c15bc915a9a1d4e0ba78f10075063386744f642144333353f77bbfae477e9d8f"
_NEW_CAS = "cbffabd3a2d20ec65f967d04159e686dd81327259314aa1b8a7e701949c12d27"
_CAS_PREFIX = "var/lib/aragorn-quarantine/"
_EVIDENCE_PREFIX = "var/lib/aragorn-broker-evidence/"
_OLD_REQUEST = _EVIDENCE_PREFIX + "protected-install-request-v1-before-update-20260729.json"
_UPDATE_REQUEST = (
    _EVIDENCE_PREFIX
    + "protected-install-request-v2-positive-8924988-20260729.json"
)
_STALE_REQUEST = (
    _EVIDENCE_PREFIX
    + "protected-install-request-v2-stale-8924988-20260729.json"
)
_RUNTIME_REQUEST = "run/aragorn-protected-install/request.json"
_ARCHIVED_UPDATE = (
    _EVIDENCE_PREFIX + "phase1-protected-update-positive-8924988-20260729.json"
)
_ARCHIVED_CONSUMED = (
    _EVIDENCE_PREFIX + "phase1-protected-update-consumed-8924988-20260729.json"
)
_ARCHIVED_STALE = (
    _EVIDENCE_PREFIX + "phase1-protected-update-stale-8924988-20260729.json"
)
_ARCHIVED_CAPTURE = (
    _EVIDENCE_PREFIX + "phase1-protected-update-capture-8924988-20260729.json"
)
_PREFLIGHT = (
    _EVIDENCE_PREFIX + "protected-service-update-preflight-8924988-20260729.json"
)
_REVOCATIONS = "etc/aragorn/protected-install-revocations.json"
_RELEASE = "etc/aragorn/protected-broker-release.json"
_LAUNCHER = "usr/libexec/aragorn/aragorn-protected-install-launcher.py"
_PROTECTED = "var/lib/aragorn-protected/skills"

_MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 1024 * 1024
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 20 * 1024 * 1024
_MAX_MEMBERS = 128
_EXPECTED_MEMBERS = 104
_EXPECTED_FILES = 56
_EXPECTED_PAYLOAD_BYTES = 15_086_594
_REQUEST_DIGEST_FIELDS = {
    "target_runtime_digest",
    "runtime_conformance_digest",
    "manifest_digest",
    "quarantine_receipt_digest",
    "gateway_profile_digest",
    "context_id",
    "expected_producer_implementation_digest",
    "expected_analyzer_implementation_digest",
    "expected_analyzer_executable_digest",
    "expected_analyzer_configuration_digest",
    "expected_policy_digest",
    "expected_analyzer_verifier_digest",
    "expected_artifact_graph_verifier_digest",
}
_REQUEST_V1_FIELDS = {
    "schema",
    "expires_at_unix",
    "source_request",
    *_REQUEST_DIGEST_FIELDS,
}
_REQUEST_V2_FIELDS = _REQUEST_V1_FIELDS | {
    "operation",
    "expected_active",
    "expected_manifest_diff_digest",
}


class ProtectedInstallTransitionReplayError(ValueError):
    """The retained capture is malformed, incomplete, or inconsistent."""


@dataclass(frozen=True)
class _File:
    raw: bytes
    mode: int


@dataclass
class _Archive:
    cases: dict[str, CAS]
    inventories: dict[str, dict[str, int]]
    files: dict[str, _File]
    directories: dict[str, int]


@dataclass
class _Phase:
    cas: CAS
    request: dict[str, Any]
    evidence: dict[str, Any]
    manifest: dict[str, Any]
    graph: dict[str, Any]
    context: dict[str, Any]
    transaction: dict[str, Any]
    closure: set[str]


def verify_protected_install_transition_replay(
    archive_path: str | os.PathLike[str],
    install_evidence_path: str | os.PathLike[str],
    update_evidence_path: str | os.PathLike[str],
    consumed_evidence_path: str | os.PathLike[str],
    stale_evidence_path: str | os.PathLike[str],
    capture_evidence_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Replay retained content semantics without re-attesting Linux custody."""

    try:
        archive_raw = _pinned_bytes(
            archive_path, ARCHIVE_DIGEST, "transition archive", _MAX_ARCHIVE_BYTES
        )
        install, _ = _pinned_document(
            install_evidence_path, INSTALL_EVIDENCE_DIGEST, "install evidence"
        )
        update, update_raw = _pinned_document(
            update_evidence_path, UPDATE_EVIDENCE_DIGEST, "update evidence"
        )
        consumed, consumed_raw = _pinned_document(
            consumed_evidence_path,
            CONSUMED_EVIDENCE_DIGEST,
            "consumed-context evidence",
        )
        stale, stale_raw = _pinned_document(
            stale_evidence_path, STALE_EVIDENCE_DIGEST, "stale evidence"
        )
        capture, capture_raw = _pinned_document(
            capture_evidence_path, CAPTURE_EVIDENCE_DIGEST, "capture evidence"
        )
        _evidence_boundaries(install, update, consumed, stale, capture)

        with TemporaryDirectory(prefix="aragorn-transition-replay-") as temporary:
            retained = _load_archive(archive_raw, Path(temporary))
            for path, expected, label in (
                (_ARCHIVED_UPDATE, update_raw, "update"),
                (_ARCHIVED_CONSUMED, consumed_raw, "consumed-context"),
                (_ARCHIVED_STALE, stale_raw, "stale"),
                (_ARCHIVED_CAPTURE, capture_raw, "capture"),
            ):
                if retained.files[path].raw != expected:
                    raise ProtectedInstallTransitionReplayError(
                        f"archived {label} evidence differs from its pinned copy"
                    )

            old_request = _request(retained.files[_OLD_REQUEST], version=1)
            update_request = _request(retained.files[_UPDATE_REQUEST], version=2)
            stale_request = _request(retained.files[_STALE_REQUEST], version=2)
            if retained.files[_RUNTIME_REQUEST].raw != retained.files[_STALE_REQUEST].raw:
                raise ProtectedInstallTransitionReplayError(
                    "runtime request is not the retained stale-predecessor request"
                )
            _lineage(old_request, update_request, stale_request)
            _request_authority(
                install["request_authority"], retained.files[_OLD_REQUEST], old_request
            )
            _request_authority(
                update["request_authority"], retained.files[_UPDATE_REQUEST], update_request
            )
            _request_authority(
                consumed["request_authority"],
                retained.files[_UPDATE_REQUEST],
                update_request,
            )
            _request_authority(
                stale["request_authority"], retained.files[_STALE_REQUEST], stale_request
            )

            revocations = _canonical_document(
                retained.files[_REVOCATIONS].raw, "revocation snapshot"
            )
            if revocations != {
                "schema": "aragorn/protected-install-revocations/v1",
                "context_ids": [],
            }:
                raise ProtectedInstallTransitionReplayError(
                    "retained revocation snapshot changed"
                )
            revocation_digest = _sha256(retained.files[_REVOCATIONS].raw)
            old = _phase(
                retained.cases[_OLD_CAS],
                old_request,
                install,
                operation="install",
                revocation_digest=revocation_digest,
            )
            new = _phase(
                retained.cases[_NEW_CAS],
                update_request,
                update,
                operation="update",
                revocation_digest=revocation_digest,
                previous=old,
            )
            if old.closure != set(retained.inventories[_OLD_CAS]):
                raise ProtectedInstallTransitionReplayError(
                    "install CAS is not its exact semantic closure"
                )
            if not new.closure.issubset(retained.inventories[_NEW_CAS]):
                raise ProtectedInstallTransitionReplayError(
                    "update CAS omits positive semantic closure bytes"
                )
            negative = _negative_chains(
                retained.cases[_NEW_CAS],
                retained.inventories[_NEW_CAS],
                new,
                update_request,
                stale_request,
                consumed,
                stale,
            )
            if new.closure | set(negative["digests"]) != set(
                retained.inventories[_NEW_CAS]
            ):
                raise ProtectedInstallTransitionReplayError(
                    "update CAS contains unexplained blobs"
                )
            installed = _installed_bytes(retained, old, new, capture)
            _capture_bindings(
                retained,
                capture,
                old,
                new,
                consumed,
                stale,
                retained.files[_UPDATE_REQUEST],
                retained.files[_STALE_REQUEST],
            )

            return {
                "authority": AUTHORITY,
                "archive_digest": ARCHIVE_DIGEST,
                "evidence_digests": {
                    "install": INSTALL_EVIDENCE_DIGEST,
                    "update": UPDATE_EVIDENCE_DIGEST,
                    "consumed_context": CONSUMED_EVIDENCE_DIGEST,
                    "stale_predecessor": STALE_EVIDENCE_DIGEST,
                    "capture": CAPTURE_EVIDENCE_DIGEST,
                },
                "install": {
                    "cas_namespace": _OLD_CAS,
                    "blob_count": len(retained.inventories[_OLD_CAS]),
                    "blob_bytes": sum(retained.inventories[_OLD_CAS].values()),
                    "closure": "exact",
                    "context_id": old.context["context_id"],
                    "manifest_digest": old.context["manifest_digest"],
                },
                "update": {
                    "cas_namespace": _NEW_CAS,
                    "blob_count": len(retained.inventories[_NEW_CAS]),
                    "blob_bytes": sum(retained.inventories[_NEW_CAS].values()),
                    "positive_closure_blob_count": len(new.closure),
                    "closure": "exact_positive_plus_two_negative_chains",
                    "context_id": new.context["context_id"],
                    "manifest_digest": new.context["manifest_digest"],
                },
                "negative_extra_chains": negative,
                "installed": installed,
                "custody_replay": (
                    "HISTORICAL_VALUES_BOUND_BUT_DEVICE_INODE_CUSTODY_NOT_REATTESTED"
                ),
                "phase1_exit_eligible": False,
            }
    except ProtectedInstallTransitionReplayError:
        raise
    except Exception as exc:
        raise ProtectedInstallTransitionReplayError(
            f"cannot replay retained protected-install transition: {exc}"
        ) from exc


def _load_archive(raw: bytes, temporary: Path) -> _Archive:
    cases = {
        _OLD_CAS: CAS(temporary / _OLD_CAS),
        _NEW_CAS: CAS(temporary / _NEW_CAS),
    }
    inventories = {_OLD_CAS: {}, _NEW_CAS: {}}
    files: dict[str, _File] = {}
    directories: dict[str, int] = {}
    seen: set[str] = set()
    members = regular_files = payload_bytes = 0
    try:
        with tarfile.open(fileobj=BytesIO(raw), mode="r|gz") as archive:
            for member in archive:
                members += 1
                if members > _MAX_MEMBERS:
                    raise ProtectedInstallTransitionReplayError(
                        "transition archive has too many members"
                    )
                name = _safe_name(member)
                if name in seen:
                    raise ProtectedInstallTransitionReplayError(
                        f"transition archive repeats {name}"
                    )
                seen.add(name)
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.mode & ~0o777
                    or member.linkname
                ):
                    raise ProtectedInstallTransitionReplayError(
                        "transition archive ownership or mode is invalid"
                    )
                if member.isdir():
                    if member.size:
                        raise ProtectedInstallTransitionReplayError(
                            "transition archive directory has content"
                        )
                    directories[name] = member.mode
                    continue
                if not member.isfile():
                    raise ProtectedInstallTransitionReplayError(
                        "transition archive contains a link or special file"
                    )
                if not 0 <= member.size <= _MAX_MEMBER_BYTES:
                    raise ProtectedInstallTransitionReplayError(
                        "transition archive member exceeds its byte limit"
                    )
                regular_files += 1
                payload_bytes += member.size
                if payload_bytes > _MAX_PAYLOAD_BYTES:
                    raise ProtectedInstallTransitionReplayError(
                        "transition archive exceeds its total byte limit"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise ProtectedInstallTransitionReplayError(
                        "transition archive regular member is unreadable"
                    )
                identity = _cas_identity(name)
                if identity is not None:
                    namespace, digest = identity
                    if member.mode != 0o444 or digest in inventories[namespace]:
                        raise ProtectedInstallTransitionReplayError(
                            "transition archive CAS entry is duplicated or writable"
                        )
                    cases[namespace].put_expected(
                        stream,
                        expected_digest=digest,
                        max_bytes=member.size,
                    )
                    inventories[namespace][digest] = member.size
                else:
                    content = stream.read(member.size + 1)
                    if len(content) != member.size:
                        raise ProtectedInstallTransitionReplayError(
                            "transition archive member size changed"
                        )
                    files[name] = _File(content, member.mode)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ProtectedInstallTransitionReplayError(
            f"transition archive is invalid: {exc}"
        ) from exc
    if (members, regular_files, payload_bytes) != (
        _EXPECTED_MEMBERS,
        _EXPECTED_FILES,
        _EXPECTED_PAYLOAD_BYTES,
    ):
        raise ProtectedInstallTransitionReplayError(
            "transition archive inventory changed"
        )
    required = {
        _OLD_REQUEST,
        _UPDATE_REQUEST,
        _STALE_REQUEST,
        _RUNTIME_REQUEST,
        _ARCHIVED_UPDATE,
        _ARCHIVED_CONSUMED,
        _ARCHIVED_STALE,
        _ARCHIVED_CAPTURE,
        _PREFLIGHT,
        _REVOCATIONS,
        _RELEASE,
        _LAUNCHER,
    }
    if not required.issubset(files):
        raise ProtectedInstallTransitionReplayError(
            "transition archive omits required evidence"
        )
    return _Archive(cases, inventories, files, directories)


def _safe_name(member: tarfile.TarInfo) -> str:
    name = member.name
    if (
        not name
        or len(name) > 512
        or name.startswith("/")
        or "\\" in name
        or "\x00" in name
        or "//" in name
        or member.pax_headers
        or getattr(member, "sparse", None)
    ):
        raise ProtectedInstallTransitionReplayError(
            "transition archive member metadata is unsafe"
        )
    normalized = name[:-1] if member.isdir() and name.endswith("/") else name
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or path.as_posix() != normalized
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ProtectedInstallTransitionReplayError(
            "transition archive member path is non-canonical"
        )
    return normalized


def _cas_identity(name: str) -> tuple[str, str] | None:
    if not name.startswith(_CAS_PREFIX):
        return None
    parts = name.removeprefix(_CAS_PREFIX).split("/")
    if (
        len(parts) != 5
        or parts[0] not in {_OLD_CAS, _NEW_CAS}
        or parts[1:3] != ["blobs", "sha256"]
        or len(parts[3]) != 2
        or len(parts[4]) != 62
        or any(
            character not in "0123456789abcdef"
            for character in parts[0] + parts[3] + parts[4]
        )
    ):
        raise ProtectedInstallTransitionReplayError(
            "transition archive CAS path is invalid"
        )
    return parts[0], "sha256:" + parts[3] + parts[4]


def _phase(
    cas: CAS,
    request: dict[str, Any],
    evidence: dict[str, Any],
    *,
    operation: str,
    revocation_digest: str,
    previous: _Phase | None = None,
) -> _Phase:
    if (
        evidence["slice_status"] != "PASS"
        or evidence["mode"] != "github-live"
        or evidence["producer_implementation_digest"]
        != request["expected_producer_implementation_digest"]
    ):
        raise ProtectedInstallTransitionReplayError(
            f"{operation} producer/status binding changed"
        )
    manifest, graph, closure = _source(cas, request, evidence)
    closure |= _evidence_decision(cas, request, evidence, graph)

    expected_active = None
    if operation == "update":
        if previous is None:
            raise ProtectedInstallTransitionReplayError("update predecessor is absent")
        expected_active = {
            "context_id": previous.context["context_id"],
            "manifest_digest": previous.context["manifest_digest"],
        }
        manifest_diff = diff_verified_manifests_between(
            previous.cas,
            previous.context["manifest_digest"],
            cas,
            request["manifest_digest"],
        )
        diff_digest = canonical_digest(manifest_diff)
        if (
            diff_digest != request["expected_manifest_diff_digest"]
            or github_gateway_live_evidence._canonical_cas_document(
                cas, diff_digest, "manifest diff"
            )
            != manifest_diff
        ):
            raise ProtectedInstallTransitionReplayError(
                "update manifest diff does not replay across the two CAS roots"
            )
        transition = {
            "operation": "update",
            "expected_active": expected_active,
            "previous_source": {
                "request": previous.evidence["source"]["request"],
                "manifest_digest": previous.context["manifest_digest"],
                "quarantine_receipt_digest": previous.evidence["source"][
                    "quarantine_receipt_digest"
                ],
                "gateway_profile_digest": previous.evidence["source"][
                    "gateway_profile_digest"
                ],
                "source_closure_digest": previous.evidence["source"][
                    "source_closure_digest"
                ],
            },
            "manifest_diff": {"digest": diff_digest, "document": manifest_diff},
        }
        if evidence["transition"] != transition:
            raise ProtectedInstallTransitionReplayError(
                "update transition does not bind the retained predecessor"
            )
        closure.add(diff_digest)

    context = {
        "schema": "aragorn/protected-install-context/v2",
        "authority": "BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY",
        "context_id": request["context_id"],
        "status": "active",
        "expires_at_unix": request["expires_at_unix"],
        "operation": operation,
        "expected_active": expected_active,
        "decision_digest": evidence["decision"]["digest"],
        "manifest_digest": request["manifest_digest"],
        "artifact_graph_digest": evidence["source"]["artifact_graph_digest"],
        "policy_digest": request["expected_policy_digest"],
        "analyzer_run_receipt_digests": [
            evidence["analyzer"]["run_receipt_digest"]
        ],
        "analyzer_verifier_digest": request["expected_analyzer_verifier_digest"],
        "artifact_graph_verifier_digest": request[
            "expected_artifact_graph_verifier_digest"
        ],
        "quarantine_receipt_digest": request["quarantine_receipt_digest"],
        "gateway_profile_digest": request["gateway_profile_digest"],
        "target_runtime_digest": request["target_runtime_digest"],
        "runtime_conformance_digest": request["runtime_conformance_digest"],
        "destination": evidence["context"]["destination"],
    }
    context_digest = canonical_digest(context)
    summary = {
        "context_id": context["context_id"],
        "digest": context_digest,
        "target_runtime_digest": context["target_runtime_digest"],
        "runtime_conformance_digest": context["runtime_conformance_digest"],
        "destination": context["destination"],
    }
    if operation == "update":
        summary.update({"operation": "update", "expected_active": expected_active})
    if evidence["context"] != summary:
        raise ProtectedInstallTransitionReplayError(
            f"{operation} context does not replay"
        )
    _claim(evidence["claim"], request, context["context_id"], revocation_digest)

    destination = context["destination"]
    verified = VerifiedInstallContextV2(
        context_digest=context_digest,
        context_id=context["context_id"],
        decision_digest=context["decision_digest"],
        manifest_digest=context["manifest_digest"],
        target_runtime_digest=context["target_runtime_digest"],
        runtime_conformance_digest=context["runtime_conformance_digest"],
        root_device=_integer(destination["root_device"], 0, "root device"),
        root_inode=_integer(destination["root_inode"], 1, "root inode"),
        target_name=destination["target_name"],
        expires_at_unix=request["expires_at_unix"],
        operation=operation,
        expected_active_context_id=(
            None if expected_active is None else expected_active["context_id"]
        ),
        expected_active_manifest_digest=(
            None if expected_active is None else expected_active["manifest_digest"]
        ),
    )
    version_path = _version_path(
        destination["target_name"], context["context_id"], context["manifest_digest"]
    )
    transaction = _transaction_record(
        verified,
        tree_digest=graph["tree_digest"],
        version_path=version_path,
    )
    if evidence["transaction"] != transaction or evidence["active"] != {
        "link_target": version_path,
        "tree_digest": graph["tree_digest"],
    }:
        raise ProtectedInstallTransitionReplayError(
            f"{operation} transaction or active state does not replay"
        )
    return _Phase(
        cas, request, evidence, manifest, graph, context, transaction, closure
    )


def _source(
    cas: CAS,
    request: dict[str, Any],
    evidence: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], set[str]]:
    source = evidence["source"]
    manifest_digest = request["manifest_digest"]
    receipt_digest = request["quarantine_receipt_digest"]
    manifest = load_verified_retained_manifest(cas, manifest_digest)
    receipt = github_gateway_live_evidence._canonical_cas_document(
        cas, receipt_digest, "quarantine receipt"
    )
    github_gateway_live_evidence._verify_receipt(
        cas,
        receipt,
        request=request["source_request"],
        manifest=manifest,
        manifest_digest=manifest_digest,
        receipt_digest=receipt_digest,
        profile_digest=request["gateway_profile_digest"],
    )
    source_inventory = github_quarantine_receipt._github_source_closure(
        cas,
        manifest_digest=manifest_digest,
        source_proof_digest=receipt["source_proof_digest"],
    )
    closure_digest = github_quarantine_receipt.github_source_closure_digest(
        cas,
        manifest_digest=manifest_digest,
        source_proof_digest=receipt["source_proof_digest"],
        handoff_manifest_digest=receipt["handoff_manifest_digest"],
    )
    handoff_raw = cas.read(
        receipt["handoff_manifest_digest"], max_bytes=8 * 1024 * 1024
    )
    source_inventory[receipt["handoff_manifest_digest"]] = len(handoff_raw)
    graph = _graph(
        cas,
        source["artifact_graph_digest"],
        manifest,
        receipt,
        request,
    )
    expected = {
        "request": request["source_request"],
        "manifest_digest": manifest_digest,
        "tree_digest": manifest["tree_digest"],
        "source_proof_digest": receipt["source_proof_digest"],
        "source_closure_digest": closure_digest,
        "quarantine_receipt_digest": receipt_digest,
        "gateway_profile_digest": request["gateway_profile_digest"],
        "containment_profile": receipt["containment_profile"],
        "gateway": receipt["gateway"],
        "quarantine_protected_cas": receipt["protected_cas"],
        "artifact_graph_digest": source["artifact_graph_digest"],
        "artifact_graph_profile": graph["profile"],
        "artifact_graph_verifier_implementation_digest": request[
            "expected_artifact_graph_verifier_digest"
        ],
        "artifact_count": len(graph["artifacts"]),
        "closure": graph["closure"],
    }
    if source != expected:
        raise ProtectedInstallTransitionReplayError(
            "source evidence does not match its archived closure"
        )
    return (
        manifest,
        graph,
        set(source_inventory) | {receipt_digest, source["artifact_graph_digest"]},
    )


def _graph(
    cas: CAS,
    digest: str,
    manifest: dict[str, Any],
    receipt: dict[str, Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    graph = github_gateway_live_evidence._canonical_cas_document(
        cas, digest, "artifact graph"
    )
    edges, unresolved = admission_artifact_graph._scan_admission_markdown(
        cas, manifest, scan_references=True, unresolved=set()
    )
    expected = {
        "schema": "aragorn/admission-artifact-graph/v2",
        "authority": "CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY",
        "verifier": {
            "name": admission_artifact_graph.VERIFIER,
            "version": admission_artifact_graph.GITHUB_VERIFIER_VERSION,
            "implementation_digest": request[
                "expected_artifact_graph_verifier_digest"
            ],
        },
        "profile": admission_artifact_graph.GITHUB_PROFILE,
        "root_manifest_digest": request["manifest_digest"],
        "source_proof_digest": receipt["source_proof_digest"],
        "quarantine_receipt_digest": request["quarantine_receipt_digest"],
        "gateway_profile_digest": request["gateway_profile_digest"],
        "tree_digest": manifest["tree_digest"],
        "artifacts": [
            {key: entry[key] for key in ("path", "size", "digest", "executable")}
            for entry in manifest["files"]
        ],
        "edges": edges,
        "closure": {
            "scope": "artifact_graph",
            "profile": admission_artifact_graph.GITHUB_PROFILE,
            "status": "incomplete" if unresolved else "complete",
            "unresolved": unresolved,
        },
    }
    if graph != expected or canonical_digest(graph) != digest:
        raise ProtectedInstallTransitionReplayError(
            "artifact graph does not replay without live custody"
        )
    if graph["closure"]["status"] != "complete":
        raise ProtectedInstallTransitionReplayError(
            "artifact graph closure is incomplete"
        )
    return graph


def _evidence_decision(
    cas: CAS,
    request: dict[str, Any],
    evidence: dict[str, Any],
    graph: dict[str, Any],
) -> set[str]:
    analyzer = evidence["analyzer"]
    if analyzer != {
        "name": analyzer["name"],
        "version": analyzer["version"],
        "implementation_digest": request["expected_analyzer_implementation_digest"],
        "configuration_digest": request[
            "expected_analyzer_configuration_digest"
        ],
        "executable_digest": request["expected_analyzer_executable_digest"],
        "run_receipt_digest": analyzer["run_receipt_digest"],
        "verifier_implementation_digest": request[
            "expected_analyzer_verifier_digest"
        ],
    }:
        raise ProtectedInstallTransitionReplayError(
            "analyzer evidence is not request-bound"
        )
    decision, closure, result, _analyzer_request = _decision(
        cas,
        evidence["decision"]["digest"],
        graph,
        request["expected_policy_digest"],
        analyzer["run_receipt_digest"],
        request["expected_analyzer_verifier_digest"],
    )
    if (
        not result.ok
        or result.name != analyzer["name"]
        or result.version != analyzer["version"]
        or result.config_digest != analyzer["configuration_digest"]
        or result.executable_digest != analyzer["executable_digest"]
    ):
        raise ProtectedInstallTransitionReplayError(
            "analyzer evidence does not replay"
        )
    configuration = _canonical_document(
        result.raw_configuration, "analyzer configuration"
    )
    argv = configuration.get("argv")
    binding = (
        "expected=" + repr(request["expected_analyzer_implementation_digest"]) + "\n"
    )
    if (
        not isinstance(argv, list)
        or len(argv) != 4
        or not isinstance(argv[3], str)
        or binding not in argv[3]
    ):
        raise ProtectedInstallTransitionReplayError(
            "analyzer implementation binding is absent"
        )
    if evidence["decision"] != {
        "digest": evidence["decision"]["digest"],
        "verdict": decision["verdict"],
        "policy_digest": request["expected_policy_digest"],
        "installer_work_eligible": False,
    } or decision["verdict"] != "ALLOW":
        raise ProtectedInstallTransitionReplayError(
            "decision evidence does not replay to ALLOW"
        )
    return closure


def _decision(
    cas: CAS,
    decision_digest: str,
    graph: dict[str, Any],
    policy_digest: str,
    run_receipt_digest: str,
    verifier_digest: str,
) -> tuple[dict[str, Any], set[str], Any, dict[str, Any]]:
    decision = github_gateway_live_evidence._canonical_cas_document(
        cas, decision_digest, "decision"
    )
    validated_policy, policy = decision_receipt._load_policy(cas, policy_digest)
    results, analyzer_records = decision_receipt._replay_analyzers(
        cas,
        decision["analyzers"],
        tree_digest=graph["tree_digest"],
        verifier_digest=verifier_digest,
        expected_run_receipt_digests=[run_receipt_digest],
    )
    evaluated = decision_receipt.evaluate_policy(
        policy, closure=graph["closure"], results=results
    )
    if graph["profile"] in decision_receipt.policy_artifact_graph_profiles(
        validated_policy
    ):
        verdict = evaluated.verdict
        reason_codes = list(evaluated.reason_codes)
    else:
        verdict = "ERROR"
        reason_codes = ["ARTIFACT_GRAPH_PROFILE_NOT_ALLOWED"]
    expected = {
        "schema": "aragorn/decision/v3",
        "authority": "EVIDENCE_SUMMARY_ONLY_NOT_INSTALLER_AUTHORITY",
        "verdict": verdict,
        "manifest_digest": graph["root_manifest_digest"],
        "artifact_graph_digest": canonical_digest(graph),
        "tree_digest": graph["tree_digest"],
        "artifact_digests": sorted(
            artifact["digest"] for artifact in graph["artifacts"]
        ),
        "policy": {
            "id": validated_policy["id"],
            "version": validated_policy["version"],
            "digest": policy_digest,
        },
        "analyzers": analyzer_records,
        "reason_codes": reason_codes,
    }
    if decision != expected or canonical_digest(decision) != decision_digest:
        raise ProtectedInstallTransitionReplayError(
            "decision differs from replayed graph, analyzer, or policy"
        )
    receipt = github_gateway_live_evidence._canonical_cas_document(
        cas, run_receipt_digest, "analyzer receipt"
    )
    analyzer_request = analyzer_receipt._request(results[0].raw_request)
    closure = {
        decision_digest,
        policy_digest,
        run_receipt_digest,
        receipt["request_digest"],
        receipt["stdout_digest"],
        receipt["stderr_digest"],
        analyzer_request["analyzer"]["config_digest"],
        analyzer_request["analyzer"]["executable_digest"],
        *receipt["observation_digests"],
    }
    return decision, closure, results[0], analyzer_request


def _negative_chains(
    cas: CAS,
    inventory: dict[str, int],
    positive: _Phase,
    positive_request: dict[str, Any],
    stale_request: dict[str, Any],
    consumed: dict[str, Any],
    stale: dict[str, Any],
) -> dict[str, Any]:
    if consumed["error"] != {
        "type": "ProtectedInstallTransactionError",
        "message": (
            "protected install transaction failed before consuming its context: "
            "protected install context is consumed"
        ),
    } or stale["error"] != {
        "type": "ProtectedInstallTransactionError",
        "message": (
            "protected install transaction failed before consuming its context: "
            "protected install active link does not match the expected state"
        ),
    }:
        raise ProtectedInstallTransitionReplayError(
            "negative transaction errors are not distinct and exact"
        )
    extras = set(inventory) - positive.closure
    documents = {
        digest: _document(
            cas.read(digest, max_bytes=8 * 1024 * 1024),
            "negative CAS blob",
        )
        for digest in extras
    }
    groups: dict[str, set[str]] = {}
    for digest, document in documents.items():
        groups.setdefault(document.get("schema", ""), set()).add(digest)
    if (
        len(extras) != 6
        or set(groups)
        != {
            "aragorn/decision/v3",
            "aragorn/analyzer-run-receipt/v1",
            "aragorn/analyzer-request/v1",
        }
        or any(len(group) != 2 for group in groups.values())
    ):
        raise ProtectedInstallTransitionReplayError(
            "negative attempts do not leave two exact analyzer-decision chains"
        )
    positive_receipt = github_gateway_live_evidence._canonical_cas_document(
        cas,
        positive.evidence["analyzer"]["run_receipt_digest"],
        "positive analyzer receipt",
    )
    positive_analyzer_request = analyzer_receipt._request(
        cas.read(positive_receipt["request_digest"], max_bytes=1024 * 1024)
    )
    explained: set[str] = set()
    workspaces = {positive_analyzer_request["workspace"]}
    chains: list[dict[str, str]] = []
    for decision_digest in sorted(groups["aragorn/decision/v3"]):
        analyzer_records = documents[decision_digest].get("analyzers")
        if not isinstance(analyzer_records, list) or len(analyzer_records) != 1:
            raise ProtectedInstallTransitionReplayError(
                "negative decision analyzer selection changed"
            )
        receipt_digest = analyzer_records[0].get("run_receipt_digest")
        if receipt_digest not in groups["aragorn/analyzer-run-receipt/v1"]:
            raise ProtectedInstallTransitionReplayError(
                "negative decision does not select an extra receipt"
            )
        request_digest = documents[receipt_digest].get("request_digest")
        if request_digest not in groups["aragorn/analyzer-request/v1"]:
            raise ProtectedInstallTransitionReplayError(
                "negative receipt does not select an extra request"
            )
        decision, closure, result, analyzer_request = _decision(
            cas,
            decision_digest,
            positive.graph,
            positive_request["expected_policy_digest"],
            receipt_digest,
            positive_request["expected_analyzer_verifier_digest"],
        )
        workspace = analyzer_request.get("workspace")
        if (
            decision["verdict"] != "ALLOW"
            or not result.ok
            or result.config_digest
            != positive_request["expected_analyzer_configuration_digest"]
            or result.executable_digest
            != positive_request["expected_analyzer_executable_digest"]
            or not isinstance(workspace, str)
            or workspace in workspaces
            or {
                key: value for key, value in analyzer_request.items() if key != "workspace"
            }
            != {
                key: value
                for key, value in positive_analyzer_request.items()
                if key != "workspace"
            }
            or closure - positive.closure
            != {decision_digest, receipt_digest, request_digest}
        ):
            raise ProtectedInstallTransitionReplayError(
                "negative analyzer-decision chain is inconsistent"
            )
        workspaces.add(workspace)
        explained.update({decision_digest, receipt_digest, request_digest})
        chains.append(
            {
                "analyzer_request_digest": request_digest,
                "analyzer_run_receipt_digest": receipt_digest,
                "decision_digest": decision_digest,
            }
        )
    if explained != extras:
        raise ProtectedInstallTransitionReplayError(
            "negative chains do not explain the exact extra CAS inventory"
        )
    return {
        "digests": sorted(extras),
        "blob_count": 6,
        "chain_count": 2,
        "chains": chains,
        "negative_requests": {
            "consumed_context": canonical_digest(positive_request),
            "stale_predecessor": canonical_digest(stale_request),
        },
        "explanation": (
            "TWO_ALTERNATE_ANALYZER_AND_ALLOW_DECISION_CHAINS_RETAINED_"
            "BEFORE_DISTINCT_TRANSACTION_REJECTIONS"
        ),
        "temporal_binding": (
            "COLLECTIVE_STRUCTURAL_CAPTURE_EVIDENCE_NOT_PER_CHAIN_"
            "INDEPENDENT_CLOCK_ATTESTATION"
        ),
    }


def _installed_bytes(
    retained: _Archive,
    old: _Phase,
    new: _Phase,
    capture: dict[str, Any],
) -> dict[str, Any]:
    expected_claims: set[str] = set()
    expected_skills: set[str] = set()
    captured_claims = {item["name"]: item for item in capture["active"]["claims"]}
    result: dict[str, Any] = {}
    for label, phase in (("install", old), ("update", new)):
        context_hex = phase.context["context_id"][7:]
        claim_name = f"{context_hex}.json"
        claim_path = f"{_PROTECTED}/.aragorn-install-claims/{claim_name}"
        version_dir = f"{_PROTECTED}/{phase.transaction['version_path']}"
        skill_path = version_dir + "/SKILL.md"
        expected_claims.add(claim_path)
        expected_skills.add(skill_path)
        claim = retained.files[claim_path]
        skill = retained.files[skill_path]
        manifest_skill = next(
            entry for entry in phase.manifest["files"] if entry["path"] == "SKILL.md"
        )
        if (
            claim.mode != 0o400
            or claim.raw != canonical_json(phase.transaction)
            or retained.directories.get(version_dir) != 0o555
            or skill.mode != 0o444
            or _sha256(skill.raw) != manifest_skill["digest"]
            or skill.raw
            != phase.cas.read(
                manifest_skill["digest"], max_bytes=manifest_skill["size"]
            )
        ):
            raise ProtectedInstallTransitionReplayError(
                f"{label} installed bytes or claim changed"
            )
        if captured_claims.get(claim_name) != {
            "name": claim_name,
            "digest": _sha256(claim.raw),
            "document": phase.transaction,
        }:
            raise ProtectedInstallTransitionReplayError(
                f"{label} capture claim differs from retained bytes"
            )
        result[label] = {
            "skill_digest": manifest_skill["digest"],
            "skill_bytes": manifest_skill["size"],
            "version_path": phase.transaction["version_path"],
            "claim_digest": _sha256(claim.raw),
        }
    actual_claims = {
        path
        for path in retained.files
        if path.startswith(f"{_PROTECTED}/.aragorn-install-claims/")
    }
    actual_skills = {
        path
        for path in retained.files
        if path.startswith(f"{_PROTECTED}/.aragorn-versions/")
        and path.endswith("/SKILL.md")
    }
    if actual_claims != expected_claims or actual_skills != expected_skills:
        raise ProtectedInstallTransitionReplayError(
            "protected archive has an unexpected claim or version"
        )
    active = capture["active"]
    if (
        active["link_target"] != new.transaction["version_path"]
        or active["skill_digest"] != result["update"]["skill_digest"]
        or active["skill_bytes"] != result["update"]["skill_bytes"]
        or active["skill_mode"] != 0o444
    ):
        raise ProtectedInstallTransitionReplayError(
            "captured active target differs from retained update bytes"
        )
    return result


def _capture_bindings(
    retained: _Archive,
    capture: dict[str, Any],
    old: _Phase,
    new: _Phase,
    consumed: dict[str, Any],
    stale: dict[str, Any],
    update_request: _File,
    stale_request: _File,
) -> None:
    for label, namespace in (("previous", _OLD_CAS), ("current", _NEW_CAS)):
        custody = capture["custody"][label]
        if (
            custody["path"] != f"/var/lib/aragorn-quarantine/{namespace}"
            or custody["blob_count"] != len(retained.inventories[namespace])
            or custody["blob_bytes"] != sum(retained.inventories[namespace].values())
            or custody["owner_uid"] != 0
            or custody["mode"] != 0o700
            or _integer(custody["device"], 1, "historical CAS device") <= 0
            or _integer(custody["inode"], 1, "historical CAS inode") <= 0
        ):
            raise ProtectedInstallTransitionReplayError(
                f"captured {label} CAS inventory changed"
            )
    for key, path, item in (
        ("positive_request", _UPDATE_REQUEST, update_request),
        ("stale_request", _STALE_REQUEST, stale_request),
    ):
        if capture["custody"][key] != {
            "path": "/" + path,
            "digest": _sha256(item.raw),
            "bytes": len(item.raw),
        }:
            raise ProtectedInstallTransitionReplayError(
                f"captured {key} bytes changed"
            )
    positive = capture["positive"]
    if (
        positive["evidence_digest"] != UPDATE_EVIDENCE_DIGEST
        or positive["request_digest"] != _sha256(update_request.raw)
        or positive["slice_status"] != "PASS"
        or positive["transaction"] != new.transaction
        or positive["transition"] != new.evidence["transition"]
    ):
        raise ProtectedInstallTransitionReplayError(
            "capture positive summary changed"
        )
    negatives = capture["negative"]
    expected_negatives = (
        (
            "consumed_context_replay",
            consumed,
            CONSUMED_EVIDENCE_DIGEST,
            _sha256(update_request.raw),
        ),
        (
            "stale_predecessor",
            stale,
            STALE_EVIDENCE_DIGEST,
            _sha256(stale_request.raw),
        ),
    )
    for key, evidence, digest, request_digest in expected_negatives:
        summary = negatives[key]
        if (
            summary["evidence_digest"] != digest
            or summary["request_digest"] != request_digest
            or summary["slice_status"] != "ERROR"
            or summary["error"] != evidence["error"]
            or summary["snapshot_before"] != capture["active"]["snapshot_digest"]
            or summary["snapshot_after"] != capture["active"]["snapshot_digest"]
        ):
            raise ProtectedInstallTransitionReplayError(
                f"capture {key} did not preserve the protected snapshot"
            )
    preflight_raw = retained.files[_PREFLIGHT].raw
    preflight = _document(preflight_raw, "update preflight")
    old_skill = next(
        entry for entry in old.manifest["files"] if entry["path"] == "SKILL.md"
    )
    if (
        capture["preflight"]["document"] != preflight
        or capture["preflight"]["evidence_digest"] != _sha256(preflight_raw)
        or preflight["protected"]["active_link"] != old.transaction["version_path"]
        or preflight["protected"]["skill_digest"] != old_skill["digest"]
        or preflight["protected"]["skill_bytes"] != old_skill["size"]
        or preflight["protected"]["skill_mode"] != 0o444
    ):
        raise ProtectedInstallTransitionReplayError(
            "preflight predecessor bytes changed"
        )
    release_raw = retained.files[_RELEASE].raw
    release = _document(release_raw, "release identity")
    implementation = capture["implementation"]
    if (
        implementation["release_identity_digest"] != _sha256(release_raw)
        or release["broker"]["digest"] != implementation["broker_digest"]
        or release["launcher"]["digest"] != implementation["launcher_digest"]
        or release["package"]["tree_digest"] != implementation["package_tree_digest"]
        or release["package"]["root"] != implementation["package_path"]
        or release["python"]["digest"] != implementation["python_executable_digest"]
        or _sha256(retained.files[_LAUNCHER].raw)
        != implementation["launcher_digest"]
        or implementation["broker_digest"]
        != new.request["expected_producer_implementation_digest"]
        or implementation["python_executable_digest"]
        != new.request["expected_analyzer_executable_digest"]
        or capture["phase1_exit_eligible"] is not False
        or old.context["destination"] != new.context["destination"]
        or capture["active"]["root"] != "/var/lib/aragorn-protected/skills"
    ):
        raise ProtectedInstallTransitionReplayError(
            "capture implementation, destination, or assurance binding changed"
        )


def _claim(
    claim: dict[str, Any],
    request: dict[str, Any],
    context_id: str,
    revocation_digest: str,
) -> None:
    initial = claim["initial_revocation_snapshot"]
    fresh = claim["fresh"]
    snapshots = (initial, fresh["revocation_snapshot"])
    for snapshot in snapshots:
        if (
            snapshot["schema"] != "aragorn/protected-install-revocations/v1"
            or snapshot["path"] != "/etc/aragorn/protected-install-revocations.json"
            or snapshot["digest"] != revocation_digest
            or snapshot["context_ids"] != []
            or snapshot["owner_uid"] != 0
            or snapshot["mode"] != 0o400
            or _integer(snapshot["device"], 1, "revocation device") <= 0
            or _integer(snapshot["inode"], 1, "revocation inode") <= 0
        ):
            raise ProtectedInstallTransitionReplayError(
                "historical revocation snapshot changed"
            )
    claim_now = _integer(fresh["claim_now_unix"], 0, "claim time")
    if claim_now >= request["expires_at_unix"] or context_id in initial["context_ids"]:
        raise ProtectedInstallTransitionReplayError(
            "claim expiry or revocation binding changed"
        )


def _lineage(
    old: dict[str, Any],
    update: dict[str, Any],
    stale: dict[str, Any],
) -> None:
    expected_active = {
        "context_id": old["context_id"],
        "manifest_digest": old["manifest_digest"],
        "source_request": old["source_request"],
        "quarantine_receipt_digest": old["quarantine_receipt_digest"],
        "gateway_profile_digest": old["gateway_profile_digest"],
    }
    if (
        update["operation"] != "update"
        or update["expected_active"] != expected_active
        or update["manifest_digest"] == old["manifest_digest"]
        or update["source_request"] == old["source_request"]
        or any(
            update["source_request"][field] != old["source_request"][field]
            for field in ("owner", "repository", "skill_path")
        )
        or {
            key: value for key, value in update.items() if key != "context_id"
        }
        != {key: value for key, value in stale.items() if key != "context_id"}
        or update["context_id"] == stale["context_id"]
        or canonical_digest(stale)
        != "sha256:61cb84b4b76912d716bc8cdfd526776009787fbe4d617ff1de63859f1cc98cb5"
        or canonical_digest(old["source_request"])[7:] != _OLD_CAS
        or canonical_digest(update["source_request"])[7:] != _NEW_CAS
    ):
        raise ProtectedInstallTransitionReplayError(
            "install/update/stale request lineage changed"
        )


def _request(value: _File, *, version: int) -> dict[str, Any]:
    request = _canonical_document(value.raw, "service request")
    schema = f"aragorn/protected-install-broker-request/v{version}"
    fields = _REQUEST_V1_FIELDS if version == 1 else _REQUEST_V2_FIELDS
    if request.get("schema") != schema or set(request) != fields or value.mode != 0o400:
        raise ProtectedInstallTransitionReplayError(
            "service request schema, fields, or archive mode changed"
        )
    for field in _REQUEST_DIGEST_FIELDS:
        _digest(request[field], field)
    _integer(request["expires_at_unix"], 0, "request expiry")
    source = request["source_request"]
    if source != build_gateway_request(
        source.get("owner"),
        source.get("repository"),
        source.get("commit"),
        source.get("skill_path"),
    ):
        raise ProtectedInstallTransitionReplayError(
            "service source request is not canonical"
        )
    if version == 2:
        _digest(request["expected_manifest_diff_digest"], "manifest diff")
        if request["operation"] != "update" or not isinstance(
            request["expected_active"], dict
        ):
            raise ProtectedInstallTransitionReplayError(
                "v2 request is not an update"
            )
    return request


def _request_authority(
    authority: dict[str, Any],
    request_file: _File,
    request: dict[str, Any],
) -> None:
    credential = authority["credential"]
    if (
        authority["authority"] != "PROTECTED_CANONICAL_REQUEST_CREDENTIAL"
        or authority["request_digest"] != _sha256(request_file.raw)
        or authority["request_schema"] != request["schema"]
        or credential["path"]
        != "/run/credentials/aragorn-protected-install.service/install-request"
        or credential["uid"] != 0
        or credential["gid"] != 0
        or credential["links"] != 1
        or credential["mode"] != 0o400
        or credential["size"] != len(request_file.raw)
        or _integer(credential["device"], 1, "credential device") <= 0
        or _integer(credential["inode"], 1, "credential inode") <= 0
    ):
        raise ProtectedInstallTransitionReplayError(
            "request credential evidence changed"
        )


def _evidence_boundaries(
    install: dict[str, Any],
    update: dict[str, Any],
    consumed: dict[str, Any],
    stale: dict[str, Any],
    capture: dict[str, Any],
) -> None:
    schema = "aragorn/openclaw-github-protected-install-broker-evidence/v1"
    assurance = (
        "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_"
        "NOT_INSTALLER_AUTHORITY"
    )
    if any(
        item.get("schema") != schema or item.get("assurance") != assurance
        for item in (install, update, consumed, stale)
    ) or (
        capture.get("schema")
        != "aragorn/phase1-protected-service-update-live-capture/v1"
        or capture.get("assurance")
        != "OPERATOR_CAPTURE_OF_LIVE_V2_UPDATE_NOT_PHASE1_EXIT_AUTHORITY"
    ):
        raise ProtectedInstallTransitionReplayError(
            "retained evidence schema or authority changed"
        )


def _pinned_document(
    path: str | os.PathLike[str],
    digest: str,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    raw = _pinned_bytes(path, digest, label, _MAX_EVIDENCE_BYTES)
    return _document(raw, label), raw


def _pinned_bytes(
    path: str | os.PathLike[str],
    digest: str,
    label: str,
    max_bytes: int,
) -> bytes:
    target = Path(path)
    descriptor = os.open(
        target,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= max_bytes:
            raise ProtectedInstallTransitionReplayError(
                f"{label} is not a bounded regular file"
            )
        raw = bytearray()
        while chunk := os.read(
            descriptor, min(1024 * 1024, max_bytes + 1 - len(raw))
        ):
            raw.extend(chunk)
            if len(raw) > max_bytes:
                raise ProtectedInstallTransitionReplayError(
                    f"{label} exceeds its byte limit"
                )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(raw) != after.st_size
        or _sha256(bytes(raw)) != digest
    ):
        raise ProtectedInstallTransitionReplayError(
            f"{label} digest is not the retained identity"
        )
    return bytes(raw)


def _canonical_document(raw: bytes, label: str) -> dict[str, Any]:
    return decision_receipt._canonical_document(raw, label)[0]


def _document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except ProtectedInstallTransitionReplayError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtectedInstallTransitionReplayError(
            f"{label} JSON is invalid"
        ) from exc
    if not isinstance(document, dict):
        raise ProtectedInstallTransitionReplayError(f"{label} is not a JSON object")
    return document


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ProtectedInstallTransitionReplayError(f"{label} is invalid")
    return value


def _integer(value: object, minimum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProtectedInstallTransitionReplayError(f"{label} is invalid")
    return value


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ProtectedInstallTransitionReplayError(
                f"duplicate JSON key: {key}"
            )
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise ProtectedInstallTransitionReplayError(f"non-finite JSON number: {value}")
