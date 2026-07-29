"""Generic replay of one normalized protected install/update archive."""

from __future__ import annotations

import os
import tarfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from .cas import CAS, CASError
from .github_gateway import QUARANTINE_AUTHORITY, build_gateway_request
from .installed_tree_replay import (
    ArchivedTreeMember,
    InstalledTreeInventory,
    verify_installed_tree_members,
)
from .manifest_diff import diff_verified_manifests_between
from .oci_worker_protocol import canonical_digest
from .protected_install_transition_replay import (
    _REQUEST_DIGEST_FIELDS,
    _REQUEST_V2_FIELDS,
    _canonical_document,
    _digest,
    _File,
    _Phase,
    _phase,
    _pinned_bytes,
    _request_authority,
    _safe_name,
    _sha256,
)

AUTHORITY = "OFF_HOST_PROTECTED_TRANSITION_REPLAY_NOT_INSTALLER_AUTHORITY"
CAPTURE_SCHEMA = "aragorn/protected-transition-live-capture/v1"
CAPTURE_AUTHORITY = "OPERATOR_CAPTURE_ONLY_NOT_INSTALLER_AUTHORITY"

_MODES = {
    "capture.json": 0o444,
    "requests/install.json": 0o400,
    "requests/update.json": 0o400,
    "evidence/install-broker.json": 0o444,
    "evidence/update-broker.json": 0o444,
    "evidence/install-coordinator.json": 0o444,
    "evidence/update-coordinator.json": 0o444,
    "protected/claims/install.json": 0o400,
    "protected/claims/update.json": 0o400,
    "protected/coordinator-state.json": 0o400,
    "config/revocations.json": 0o400,
    "config/release.json": 0o400,
}
_ROOTS = {
    "install": "protected/versions/install",
    "update": "protected/versions/update",
}
_PHASE_FIELDS = {
    "source_request",
    "context_id",
    "manifest_digest",
    "tree_digest",
    "version_path",
    "members",
}
_MEMBER_FIELDS = {
    "request_digest",
    "broker_evidence_digest",
    "coordinator_evidence_digest",
    "claim_digest",
}
_RUNTIME_FIELDS = {
    "release_digest",
    "producer_implementation_digest",
    "analyzer_implementation_digest",
    "analyzer_executable_digest",
    "analyzer_configuration_digest",
    "policy_digest",
    "analyzer_verifier_digest",
    "artifact_graph_verifier_digest",
    "target_runtime_digest",
    "runtime_conformance_digest",
    "launcher_digest",
    "package_tree_digest",
}
_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 512 * 1024 * 1024
_MAX_MEMBERS = 25_000


class ProtectedTransitionLiveArchiveError(ValueError):
    """The live transition archive is unsafe or inconsistent."""


@dataclass(slots=True)
class _Archive:
    cases: dict[str, CAS]
    blobs: dict[str, dict[str, int]]
    files: dict[str, _File]
    directories: dict[str, int]
    members: int
    payload_bytes: int


def verify_protected_transition_live_archive(
    path: str | os.PathLike[str],
    *,
    expected_archive_digest: str,
) -> dict[str, Any]:
    """Replay retained semantics without re-attesting live Linux custody."""

    try:
        raw = _pinned_bytes(
            path,
            expected_archive_digest,
            "protected transition archive",
            _MAX_ARCHIVE_BYTES,
        )
        if (
            len(raw) < 10
            or raw[:3] != b"\x1f\x8b\x08"
            or raw[3] != 0
            or raw[4:8] != b"\0\0\0\0"
        ):
            raise ProtectedTransitionLiveArchiveError(
                "archive gzip header is not normalized"
            )
        with TemporaryDirectory(prefix="aragorn-transition-live-") as temporary:
            archive = _load(raw, Path(temporary))
            docs = {
                name: _canonical_document(archive.files[name].raw, name)
                for name in _MODES
            }
            capture = _capture(docs["capture.json"])
            requests = {
                label: _request(
                    archive.files[f"requests/{label}.json"],
                    label,
                )
                for label in ("install", "update")
            }
            _lineage(requests)
            evidence = {
                label: _broker_boundary(
                    docs[f"evidence/{label}-broker.json"],
                    label,
                )
                for label in ("install", "update")
            }
            for label in ("install", "update"):
                _request_authority(
                    evidence[label]["request_authority"],
                    archive.files[f"requests/{label}.json"],
                    requests[label],
                )
            revocations = docs["config/revocations.json"]
            if revocations != {
                "schema": "aragorn/protected-install-revocations/v1",
                "context_ids": [],
            }:
                raise ProtectedTransitionLiveArchiveError("revocation snapshot changed")
            revocation_digest = _sha256(archive.files["config/revocations.json"].raw)
            phases = {
                "install": _phase(
                    archive.cases["install"],
                    requests["install"],
                    evidence["install"],
                    operation="install",
                    revocation_digest=revocation_digest,
                )
            }
            phases["update"] = _phase(
                archive.cases["update"],
                requests["update"],
                evidence["update"],
                operation="update",
                revocation_digest=revocation_digest,
                previous=phases["install"],
            )
            for label in ("install", "update"):
                if phases[label].closure != set(archive.blobs[label]):
                    raise ProtectedTransitionLiveArchiveError(
                        f"{label} CAS is not its exact semantic closure"
                    )

            manifest_diff = _diff(phases, requests["update"])
            installed = {
                label: _installed(archive, phases[label], label)
                for label in ("install", "update")
            }
            runtime = _bindings(
                archive,
                docs,
                capture,
                requests,
                phases,
                installed,
            )

            return {
                "schema": "aragorn/protected-transition-live-archive-replay/v1",
                "authority": AUTHORITY,
                "archive_digest": expected_archive_digest,
                "archive": {
                    "members": archive.members,
                    "regular_files": len(archive.files)
                    + sum(map(len, archive.blobs.values())),
                    "directories": len(archive.directories),
                    "payload_bytes": archive.payload_bytes,
                },
                "install": _result(archive, phases["install"], installed["install"]),
                "update": _result(archive, phases["update"], installed["update"]),
                "transition": {
                    "manifest_diff_digest": canonical_digest(manifest_diff),
                    "added_paths": manifest_diff["added_paths"],
                    "removed_paths": manifest_diff["removed_paths"],
                    "changed_paths": manifest_diff["changed_paths"],
                    "byte_changing": True,
                    "active_context_id": phases["update"].context["context_id"],
                    "active_version_path": phases["update"].transaction["version_path"],
                    "tree_mismatches": 0,
                },
                "runtime_provenance": runtime,
                "custody_replay": (
                    "HISTORICAL_ARCHIVE_VALUES_BOUND_BUT_LIVE_CUSTODY_NOT_REATTESTED"
                ),
                "phase1_exit_eligible": False,
            }
    except ProtectedTransitionLiveArchiveError:
        raise
    except Exception as exc:
        raise ProtectedTransitionLiveArchiveError(
            f"cannot verify protected transition archive: {exc}"
        ) from exc


def _load(raw: bytes, root: Path) -> _Archive:
    writable = {label: CAS(root / label) for label in ("install", "update")}
    blobs: dict[str, dict[str, int]] = {"install": {}, "update": {}}
    files: dict[str, _File] = {}
    directories: dict[str, int] = {}
    seen: set[str] = set()
    previous = ""
    members = payload_bytes = 0
    try:
        with tarfile.open(fileobj=BytesIO(raw), mode="r|gz") as tar:
            for member in tar:
                members += 1
                if members > _MAX_MEMBERS:
                    raise ProtectedTransitionLiveArchiveError(
                        "archive member limit exceeded"
                    )
                name = _safe_name(member)
                if name in seen or name <= previous:
                    raise ProtectedTransitionLiveArchiveError(
                        "archive members are repeated or not name-sorted"
                    )
                seen.add(name)
                previous = name
                if (
                    member.uid
                    or member.gid
                    or member.uname
                    or member.gname
                    or member.mtime
                    or member.pax_headers
                    or getattr(member, "sparse", None)
                    or member.linkname
                    or member.devmajor
                    or member.devminor
                    or member.mode & ~0o777
                ):
                    raise ProtectedTransitionLiveArchiveError(
                        f"archive metadata is not normalized: {name}"
                    )
                if member.isdir():
                    if member.size:
                        raise ProtectedTransitionLiveArchiveError(
                            f"archive directory has content: {name}"
                        )
                    directories[name] = member.mode
                    continue
                if not member.isfile() or not 0 <= member.size <= _MAX_MEMBER_BYTES:
                    raise ProtectedTransitionLiveArchiveError(
                        f"archive member is unsafe or oversized: {name}"
                    )
                payload_bytes += member.size
                if payload_bytes > _MAX_PAYLOAD_BYTES:
                    raise ProtectedTransitionLiveArchiveError(
                        "archive payload limit exceeded"
                    )
                stream = tar.extractfile(member)
                if stream is None:
                    raise ProtectedTransitionLiveArchiveError(
                        f"archive member is unreadable: {name}"
                    )
                identity = _cas_identity(name)
                if identity:
                    label, digest = identity
                    if member.mode != 0o444 or digest in blobs[label]:
                        raise ProtectedTransitionLiveArchiveError(
                            f"CAS member is duplicated or writable: {name}"
                        )
                    writable[label].put_expected(
                        stream,
                        expected_digest=digest,
                        max_bytes=member.size,
                    )
                    blobs[label][digest] = member.size
                    continue
                if name not in _MODES and not _tree_relative(name):
                    raise ProtectedTransitionLiveArchiveError(
                        f"archive has an unexpected file: {name}"
                    )
                if name in _MODES and member.mode != _MODES[name]:
                    raise ProtectedTransitionLiveArchiveError(
                        f"archive named-file mode changed: {name}"
                    )
                content = stream.read(member.size + 1)
                if len(content) != member.size:
                    raise ProtectedTransitionLiveArchiveError(
                        f"archive member size changed: {name}"
                    )
                files[name] = _File(content, member.mode)
    except ProtectedTransitionLiveArchiveError:
        raise
    except (CASError, EOFError, OSError, tarfile.TarError) as exc:
        raise ProtectedTransitionLiveArchiveError(
            f"archive cannot be read safely: {exc}"
        ) from exc

    if set(_MODES) - set(files) or any(not blobs[label] for label in blobs):
        raise ProtectedTransitionLiveArchiveError(
            "archive omits required named files or CAS bytes"
        )
    regular = set(files)
    regular.update(
        _cas_path(label, digest) for label in blobs for digest in blobs[label]
    )
    expected_dirs = {
        "/".join(PurePosixPath(path).parts[:depth])
        for path in regular
        for depth in range(1, len(PurePosixPath(path).parts))
    }
    if set(directories) != expected_dirs or set(files) & expected_dirs:
        raise ProtectedTransitionLiveArchiveError("archive directory inventory changed")
    for name, mode in directories.items():
        tree = any(
            name == tree_root or name.startswith(tree_root + "/")
            for tree_root in _ROOTS.values()
        )
        if mode != (0o555 if tree else 0o700):
            raise ProtectedTransitionLiveArchiveError(
                f"archive directory mode changed: {name}"
            )
    return _Archive(
        {label: CAS(writable[label].root, read_only=True) for label in writable},
        blobs,
        files,
        directories,
        members,
        payload_bytes,
    )


def _request(item: _File, label: str) -> dict[str, Any]:
    request = _canonical_document(item.raw, f"{label} request")
    if (
        item.mode != 0o400
        or set(request) != _REQUEST_V2_FIELDS
        or request.get("schema") != "aragorn/protected-install-broker-request/v2"
        or request.get("operation") != label
        or isinstance(request.get("expires_at_unix"), bool)
        or not isinstance(request.get("expires_at_unix"), int)
        or request["expires_at_unix"] < 0
    ):
        raise ProtectedTransitionLiveArchiveError(
            f"{label} request schema, fields, or mode changed"
        )
    for field in _REQUEST_DIGEST_FIELDS:
        _digest(request[field], field)
    source = request["source_request"]
    if not isinstance(source, dict) or source != build_gateway_request(
        source.get("owner"),
        source.get("repository"),
        source.get("commit"),
        source.get("skill_path"),
    ):
        raise ProtectedTransitionLiveArchiveError(
            f"{label} source request is not canonical"
        )
    if label == "install":
        if (
            request["expected_active"] is not None
            or request["expected_manifest_diff_digest"] is not None
        ):
            raise ProtectedTransitionLiveArchiveError(
                "install request names an unexpected predecessor"
            )
    elif not _keys(
        request["expected_active"],
        {
            "context_id",
            "manifest_digest",
            "source_request",
            "quarantine_receipt_digest",
            "gateway_profile_digest",
        },
    ):
        raise ProtectedTransitionLiveArchiveError("update predecessor is malformed")
    else:
        _digest(request["expected_manifest_diff_digest"], "manifest diff")
    return request


def _lineage(requests: dict[str, dict[str, Any]]) -> None:
    old, new = requests["install"], requests["update"]
    expected = {
        "context_id": old["context_id"],
        "manifest_digest": old["manifest_digest"],
        "source_request": old["source_request"],
        "quarantine_receipt_digest": old["quarantine_receipt_digest"],
        "gateway_profile_digest": old["gateway_profile_digest"],
    }
    if (
        new["expected_active"] != expected
        or old["context_id"] == new["context_id"]
        or old["manifest_digest"] == new["manifest_digest"]
        or old["source_request"]["commit"] == new["source_request"]["commit"]
        or any(
            old["source_request"][field] != new["source_request"][field]
            for field in ("owner", "repository", "skill_path")
        )
    ):
        raise ProtectedTransitionLiveArchiveError(
            "install/update request lineage changed"
        )


def _broker_boundary(
    evidence: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    context = evidence.get("context")
    analyzer = evidence.get("analyzer")
    execution_identity = (
        analyzer.get("execution_identity") if isinstance(analyzer, dict) else None
    )
    if (
        evidence.get("schema")
        != "aragorn/openclaw-github-protected-install-broker-evidence/v1"
        or evidence.get("assurance")
        != (
            "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_"
            "NOT_INSTALLER_AUTHORITY"
        )
        or evidence.get("slice_status") != "PASS"
        or evidence.get("mode") != "github-live"
        or not isinstance(evidence.get("request_authority"), dict)
        or evidence.get("decision", {}).get("verdict") != "ALLOW"
        or evidence["decision"].get("installer_work_eligible") is not False
        or not _keys(
            execution_identity,
            {"uid", "user", "gid", "group", "supplementary_groups"},
        )
        or execution_identity["user"] != "aragorn-analyze"
        or execution_identity["group"] != "aragorn-analyze"
        or execution_identity["supplementary_groups"] != []
        or isinstance(execution_identity["uid"], bool)
        or not isinstance(execution_identity["uid"], int)
        or execution_identity["uid"] < 1
        or isinstance(execution_identity["gid"], bool)
        or not isinstance(execution_identity["gid"], int)
        or execution_identity["gid"] < 1
        or not isinstance(context, dict)
        or (
            label == "install"
            and (
                evidence.get("transition")
                != {
                    "operation": "install",
                    "expected_active": None,
                    "manifest_diff": None,
                }
                or context.get("operation") != "install"
                or context.get("expected_active") is not None
            )
        )
    ):
        raise ProtectedTransitionLiveArchiveError(
            f"{label} broker evidence is not ALLOW/PASS"
        )
    compatible = {
        **evidence,
        "analyzer": {
            key: value for key, value in analyzer.items() if key != "execution_identity"
        },
    }
    if label == "install":
        return {
            **compatible,
            "context": {
                key: value
                for key, value in context.items()
                if key not in {"operation", "expected_active"}
            },
        }
    return compatible


def _diff(
    phases: dict[str, _Phase],
    update_request: dict[str, Any],
) -> dict[str, Any]:
    old, new = phases["install"], phases["update"]
    diff = diff_verified_manifests_between(
        old.cas,
        old.context["manifest_digest"],
        new.cas,
        new.context["manifest_digest"],
    )
    digest = update_request["expected_manifest_diff_digest"]
    try:
        retained = _canonical_document(
            new.cas.read(digest, max_bytes=1024 * 1024),
            "manifest diff",
        )
    except CASError as exc:
        raise ProtectedTransitionLiveArchiveError(
            f"manifest diff is unavailable: {exc}"
        ) from exc
    if (
        canonical_digest(diff) != digest
        or retained != diff
        or not _byte_change(old.manifest, new.manifest)
    ):
        raise ProtectedTransitionLiveArchiveError(
            "manifest diff is empty or not byte-changing"
        )
    return diff


def _byte_change(old: dict[str, Any], new: dict[str, Any]) -> bool:
    before = {item["path"]: item for item in old["files"]}
    after = {item["path"]: item for item in new["files"]}
    for path in set(before) | set(after):
        left, right = before.get(path), after.get(path)
        if left is None:
            if right["size"]:
                return True
        elif right is None:
            if left["size"]:
                return True
        elif (left["size"], left["digest"]) != (right["size"], right["digest"]):
            return True
    return False


def _installed(
    archive: _Archive,
    phase: _Phase,
    label: str,
) -> InstalledTreeInventory:
    root = _ROOTS[label]
    members = [ArchivedTreeMember(".", "directory", archive.directories[root], 0)]
    members.extend(
        ArchivedTreeMember(
            name.removeprefix(root + "/"),
            "directory",
            mode,
            0,
        )
        for name, mode in archive.directories.items()
        if name.startswith(root + "/")
    )
    members.extend(
        ArchivedTreeMember(
            name.removeprefix(root + "/"),
            "file",
            item.mode,
            len(item.raw),
            item.raw,
        )
        for name, item in archive.files.items()
        if name.startswith(root + "/")
    )
    result = verify_installed_tree_members(
        phase.cas,
        phase.context["manifest_digest"],
        members,
    )
    if result.tree_digest != phase.manifest["tree_digest"]:
        raise ProtectedTransitionLiveArchiveError(
            f"{label} installed tree digest changed"
        )
    return result


def _capture(document: dict[str, Any]) -> dict[str, Any]:
    if (
        not _keys(
            document,
            {
                "schema",
                "authority",
                "phases",
                "active",
                "control_members",
                "runtime_provenance",
            },
        )
        or document["schema"] != CAPTURE_SCHEMA
        or document["authority"] != CAPTURE_AUTHORITY
        or not _keys(document["phases"], {"install", "update"})
        or any(
            not _keys(document["phases"][label], _PHASE_FIELDS)
            or not _keys(document["phases"][label]["members"], _MEMBER_FIELDS)
            for label in ("install", "update")
        )
        or not _keys(
            document["active"],
            {"context_id", "manifest_digest", "tree_digest", "link_target"},
        )
        or not _keys(
            document["control_members"],
            {"coordinator_state_digest", "revocations_digest"},
        )
        or not _keys(document["runtime_provenance"], _RUNTIME_FIELDS)
    ):
        raise ProtectedTransitionLiveArchiveError("capture schema or fields changed")
    return document


def _bindings(
    archive: _Archive,
    docs: dict[str, dict[str, Any]],
    capture: dict[str, Any],
    requests: dict[str, dict[str, Any]],
    phases: dict[str, _Phase],
    installed: dict[str, InstalledTreeInventory],
) -> dict[str, str]:
    member_paths = {
        "request_digest": "requests/{label}.json",
        "broker_evidence_digest": "evidence/{label}-broker.json",
        "coordinator_evidence_digest": "evidence/{label}-coordinator.json",
        "claim_digest": "protected/claims/{label}.json",
    }
    for label in ("install", "update"):
        phase, request = phases[label], requests[label]
        if docs[f"protected/claims/{label}.json"] != phase.transaction:
            raise ProtectedTransitionLiveArchiveError(
                f"{label} protected claim changed"
            )
        coordinator = {
            "schema": "aragorn/protected-install-coordinator-result/v1",
            "assurance": ("TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"),
            "operation": label,
            "source_request": request["source_request"],
            "manifest_digest": request["manifest_digest"],
            "quarantine_receipt_digest": request["quarantine_receipt_digest"],
            "gateway_profile_digest": request["gateway_profile_digest"],
            "context_id": request["context_id"],
            "service_request_digest": _sha256(
                archive.files[f"requests/{label}.json"].raw
            ),
            "installer_work_eligible": False,
            "runtime_conformance_qualified": False,
            "quarantine_authority": QUARANTINE_AUTHORITY,
            "status": "COMPLETED_NOT_INSTALLER_AUTHORITY",
        }
        captured_phase = {
            "source_request": request["source_request"],
            "context_id": phase.context["context_id"],
            "manifest_digest": phase.context["manifest_digest"],
            "tree_digest": phase.manifest["tree_digest"],
            "version_path": phase.transaction["version_path"],
            "members": {
                field: _sha256(archive.files[path.format(label=label)].raw)
                for field, path in member_paths.items()
            },
        }
        if (
            docs[f"evidence/{label}-coordinator.json"] != coordinator
            or capture["phases"][label] != captured_phase
            or installed[label].tree_digest != captured_phase["tree_digest"]
        ):
            raise ProtectedTransitionLiveArchiveError(
                f"{label} coordinator, capture, or installed binding changed"
            )

    update, update_request = phases["update"], requests["update"]
    state = {
        "schema": "aragorn/protected-install-coordinator-state/v1",
        "assurance": "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "expected_active": {
            "context_id": update.context["context_id"],
            "manifest_digest": update.context["manifest_digest"],
            "source_request": update_request["source_request"],
            "quarantine_receipt_digest": update_request["quarantine_receipt_digest"],
            "gateway_profile_digest": update_request["gateway_profile_digest"],
        },
        "tree_digest": update.manifest["tree_digest"],
        "version_path": update.transaction["version_path"],
        "service_request_digest": _sha256(archive.files["requests/update.json"].raw),
    }
    active = {
        "context_id": update.context["context_id"],
        "manifest_digest": update.context["manifest_digest"],
        "tree_digest": update.manifest["tree_digest"],
        "link_target": update.transaction["version_path"],
    }
    controls = {
        "coordinator_state_digest": _sha256(
            archive.files["protected/coordinator-state.json"].raw
        ),
        "revocations_digest": _sha256(archive.files["config/revocations.json"].raw),
    }
    runtime = _runtime(docs["config/release.json"], archive, requests)
    if (
        docs["protected/coordinator-state.json"] != state
        or capture["active"] != active
        or capture["control_members"] != controls
        or capture["runtime_provenance"] != runtime
    ):
        raise ProtectedTransitionLiveArchiveError(
            "final active state or runtime provenance changed"
        )
    return runtime


def _runtime(
    release: dict[str, Any],
    archive: _Archive,
    requests: dict[str, dict[str, Any]],
) -> dict[str, str]:
    if (
        not _keys(release, {"schema", "broker", "launcher", "package", "python"})
        or release["schema"] != "aragorn/protected-broker-launch-identity/v1"
        or not _keys(release["broker"], {"digest", "path"})
        or not _keys(release["launcher"], {"digest", "path"})
        or not _keys(release["package"], {"root", "tree_digest"})
        or not _keys(release["python"], {"digest", "path"})
    ):
        raise ProtectedTransitionLiveArchiveError("release identity changed")
    fields = {
        "producer_implementation_digest": "expected_producer_implementation_digest",
        "analyzer_implementation_digest": "expected_analyzer_implementation_digest",
        "analyzer_executable_digest": "expected_analyzer_executable_digest",
        "analyzer_configuration_digest": "expected_analyzer_configuration_digest",
        "policy_digest": "expected_policy_digest",
        "analyzer_verifier_digest": "expected_analyzer_verifier_digest",
        "artifact_graph_verifier_digest": ("expected_artifact_graph_verifier_digest"),
        "target_runtime_digest": "target_runtime_digest",
        "runtime_conformance_digest": "runtime_conformance_digest",
    }
    old, new = requests["install"], requests["update"]
    if any(old[field] != new[field] for field in fields.values()):
        raise ProtectedTransitionLiveArchiveError(
            "runtime provenance differs between phases"
        )
    result = {
        "release_digest": _sha256(archive.files["config/release.json"].raw),
        **{name: old[field] for name, field in fields.items()},
        "launcher_digest": release["launcher"]["digest"],
        "package_tree_digest": release["package"]["tree_digest"],
    }
    for name, value in result.items():
        _digest(value, name)
    if (
        release["broker"]["digest"] != result["producer_implementation_digest"]
        or release["python"]["digest"] != result["analyzer_executable_digest"]
    ):
        raise ProtectedTransitionLiveArchiveError(
            "release identity does not bind requested runtime"
        )
    return result


def _result(
    archive: _Archive,
    phase: _Phase,
    installed: InstalledTreeInventory,
) -> dict[str, Any]:
    label = phase.request["operation"]
    return {
        "source_request": phase.request["source_request"],
        "context_id": phase.context["context_id"],
        "manifest_digest": phase.context["manifest_digest"],
        "tree_digest": phase.manifest["tree_digest"],
        "version_path": phase.transaction["version_path"],
        "slice_status": "PASS",
        "verdict": "ALLOW",
        "cas_blob_count": len(archive.blobs[label]),
        "cas_payload_bytes": sum(archive.blobs[label].values()),
        "installed_file_count": installed.file_count,
        "installed_directory_count": installed.directory_count,
        "installed_payload_bytes": installed.payload_bytes,
    }


def _cas_identity(path: str) -> tuple[str, str] | None:
    if not path.startswith("cas/"):
        return None
    parts = path.split("/")
    if (
        len(parts) != 6
        or parts[1] not in {"install", "update"}
        or parts[2:4] != ["blobs", "sha256"]
        or len(parts[4]) != 2
        or len(parts[5]) != 62
        or any(character not in "0123456789abcdef" for character in parts[4] + parts[5])
    ):
        raise ProtectedTransitionLiveArchiveError("archive CAS path is invalid")
    return parts[1], "sha256:" + parts[4] + parts[5]


def _cas_path(label: str, digest: str) -> str:
    value = digest[7:]
    return f"cas/{label}/blobs/sha256/{value[:2]}/{value[2:]}"


def _tree_relative(path: str) -> str | None:
    for root in _ROOTS.values():
        if path.startswith(root + "/"):
            return path.removeprefix(root + "/")
    return None


def _keys(value: object, fields: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == fields
