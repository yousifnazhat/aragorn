"""Broker-authored custody receipt for one verified GitHub quarantine."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import sys
from io import BytesIO
from typing import Any

from .artifact_closure import (
    ArtifactClosureError,
    canonical_json,
    load_verified_retained_manifest,
)
from .benchmark_handoff_v2 import build_handoff_manifest
from .cas import CAS, CASError
from .github_source_proof import verify_github_source_proof

SCHEMA = "aragorn/github-quarantine-receipt/v1"
AUTHORITY = "QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY"
SOURCE_ASSURANCE = (
    "git_smart_http_v2_commit_tree_proof_and_api_blob_identity_reverified"
)
LINUX_CONTAINMENT_PROFILE = "linux-systemd-restricted-egress/v1"
DARWIN_CONTAINMENT_PROFILE = "darwin-distinct-principal/v1"
_CONTAINMENT_PROFILES = {
    LINUX_CONTAINMENT_PROFILE,
    DARWIN_CONTAINMENT_PROFILE,
}
_REQUEST_SCHEMA = "aragorn/github-gateway-request/v1"
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_PROOF_BYTES = 8 * 1024 * 1024
_MAX_HANDOFF_MANIFEST_BYTES = 8 * 1024 * 1024
_DIGEST_LENGTH = len("sha256:") + 64
_GATEWAY_PROFILE_SCHEMA = "aragorn/github-gateway-profile/v1"


class GitHubQuarantineReceiptError(ValueError):
    """A retained broker quarantine receipt is malformed or inconsistent."""


def retain_github_quarantine_receipt(
    cas: CAS,
    *,
    request: object,
    manifest_digest: str,
    source_proof_digest: str,
    handoff_manifest_digest: str,
    containment_profile: str,
    gateway_package_tree_digest: str,
    python_executable_digest: str,
) -> str:
    """Retain a receipt only after replaying the imported source closure."""

    try:
        manifest_digest = _digest(manifest_digest, "manifest digest")
        source_proof_digest = _digest(
            source_proof_digest,
            "source proof digest",
        )
        handoff_manifest_digest = _digest(
            handoff_manifest_digest,
            "handoff manifest digest",
        )
        gateway_package_tree_digest = _digest(
            gateway_package_tree_digest,
            "gateway package tree digest",
        )
        python_executable_digest = _digest(
            python_executable_digest,
            "Python executable digest",
        )
        containment_profile = _containment_profile(containment_profile)
        _require_host_containment_profile(containment_profile)
        gateway_profile_digest = github_gateway_profile_digest(
            containment_profile=containment_profile,
            gateway_package_tree_digest=gateway_package_tree_digest,
            python_executable_digest=python_executable_digest,
        )
        manifest = load_verified_retained_manifest(cas, manifest_digest)
        if manifest["schema"] != "aragorn/github-manifest/v1":
            raise GitHubQuarantineReceiptError(
                "quarantine receipt requires a GitHub manifest"
            )
        frozen_request = _request_for_manifest(request, manifest)
        closure_digest = github_source_closure_digest(
            cas,
            manifest_digest=manifest_digest,
            source_proof_digest=source_proof_digest,
            handoff_manifest_digest=handoff_manifest_digest,
        )
        root_state = _protected_cas_state(cas)
        document = {
            "schema": SCHEMA,
            "receipt_id": secrets.token_hex(32),
            "authority": AUTHORITY,
            "source_assurance": SOURCE_ASSURANCE,
            "request": frozen_request,
            "request_digest": _sha256(canonical_json(frozen_request)),
            "manifest_digest": manifest_digest,
            "source_proof_digest": source_proof_digest,
            "handoff_manifest_digest": handoff_manifest_digest,
            "source_closure_digest": closure_digest,
            "tree_digest": manifest["tree_digest"],
            "file_count": len(manifest["files"]),
            "containment_profile": containment_profile,
            "gateway_profile_digest": gateway_profile_digest,
            "protected_cas": {
                "root_device": root_state.st_dev,
                "root_inode": root_state.st_ino,
                "owner_uid": root_state.st_uid,
                "mode": stat.S_IMODE(root_state.st_mode),
            },
            "gateway": {
                "package_tree_digest": gateway_package_tree_digest,
                "python_executable_digest": python_executable_digest,
            },
        }
        raw = canonical_json(document)
        receipt_digest = cas.put(BytesIO(raw), max_bytes=_MAX_RECEIPT_BYTES)
        verify_github_quarantine_receipt(
            cas,
            receipt_digest,
            expected_manifest_digest=manifest_digest,
            expected_gateway_profile_digest=gateway_profile_digest,
        )
        return receipt_digest
    except GitHubQuarantineReceiptError:
        raise
    except (ArtifactClosureError, CASError, OSError, TypeError, ValueError) as exc:
        raise GitHubQuarantineReceiptError(
            f"cannot retain GitHub quarantine receipt: {exc}"
        ) from exc


def verify_github_quarantine_receipt(
    cas: CAS,
    expected_receipt_digest: str,
    *,
    expected_manifest_digest: str,
    expected_gateway_profile_digest: str,
) -> dict[str, Any]:
    """Replay one caller-selected receipt against its live protected CAS."""

    try:
        receipt_digest = _digest(
            expected_receipt_digest,
            "expected quarantine receipt digest",
        )
        manifest_digest = _digest(
            expected_manifest_digest,
            "expected manifest digest",
        )
        gateway_profile_digest = _digest(
            expected_gateway_profile_digest,
            "expected gateway profile digest",
        )
        raw = cas.read(receipt_digest, max_bytes=_MAX_RECEIPT_BYTES)
        document = _canonical_document(raw)
        _exact_keys(
            document,
            {
                "schema",
                "receipt_id",
                "authority",
                "source_assurance",
                "request",
                "request_digest",
                "manifest_digest",
                "source_proof_digest",
                "handoff_manifest_digest",
                "source_closure_digest",
                "tree_digest",
                "file_count",
                "containment_profile",
                "gateway_profile_digest",
                "protected_cas",
                "gateway",
            },
            "quarantine receipt",
        )
        if document["schema"] != SCHEMA:
            raise GitHubQuarantineReceiptError(
                "quarantine receipt schema is unsupported"
            )
        _receipt_id(document["receipt_id"])
        if document["authority"] != AUTHORITY:
            raise GitHubQuarantineReceiptError(
                "quarantine receipt overstates its authority"
            )
        if document["source_assurance"] != SOURCE_ASSURANCE:
            raise GitHubQuarantineReceiptError(
                "quarantine receipt source assurance is unsupported"
            )
        if document["manifest_digest"] != manifest_digest:
            raise GitHubQuarantineReceiptError(
                "quarantine receipt is bound to another manifest"
            )
        source_proof_digest = _digest(
            document["source_proof_digest"],
            "quarantine source proof digest",
        )
        for field, label in (
            ("request_digest", "quarantine request digest"),
            ("handoff_manifest_digest", "quarantine handoff manifest digest"),
            ("source_closure_digest", "quarantine source closure digest"),
            ("tree_digest", "quarantine tree digest"),
            ("gateway_profile_digest", "quarantine gateway profile digest"),
        ):
            _digest(document[field], label)
        containment_profile = _containment_profile(document["containment_profile"])
        _require_host_containment_profile(containment_profile)

        manifest = load_verified_retained_manifest(cas, manifest_digest)
        if manifest["schema"] != "aragorn/github-manifest/v1":
            raise GitHubQuarantineReceiptError(
                "quarantine receipt requires a GitHub manifest"
            )
        request = _request_for_manifest(document["request"], manifest)
        if document["request_digest"] != _sha256(canonical_json(request)):
            raise GitHubQuarantineReceiptError(
                "quarantine receipt request digest does not match its request"
            )
        if document["tree_digest"] != manifest["tree_digest"]:
            raise GitHubQuarantineReceiptError(
                "quarantine receipt tree digest does not match its manifest"
            )
        file_count = document["file_count"]
        if (
            isinstance(file_count, bool)
            or not isinstance(file_count, int)
            or file_count != len(manifest["files"])
        ):
            raise GitHubQuarantineReceiptError(
                "quarantine receipt file count does not match its manifest"
            )
        expected_closure_digest = github_source_closure_digest(
            cas,
            manifest_digest=manifest_digest,
            source_proof_digest=source_proof_digest,
            handoff_manifest_digest=document["handoff_manifest_digest"],
        )
        if document["source_closure_digest"] != expected_closure_digest:
            raise GitHubQuarantineReceiptError(
                "quarantine receipt source closure digest does not match"
            )

        protected_cas = _exact_object(
            document["protected_cas"],
            {"root_device", "root_inode", "owner_uid", "mode"},
            "quarantine protected CAS",
        )
        root_state = _protected_cas_state(cas)
        expected_custody = {
            "root_device": root_state.st_dev,
            "root_inode": root_state.st_ino,
            "owner_uid": root_state.st_uid,
            "mode": stat.S_IMODE(root_state.st_mode),
        }
        if protected_cas != expected_custody:
            raise GitHubQuarantineReceiptError(
                "quarantine receipt protected CAS custody changed"
            )

        gateway = _exact_object(
            document["gateway"],
            {"package_tree_digest", "python_executable_digest"},
            "quarantine gateway measurement",
        )
        _digest(
            gateway["package_tree_digest"],
            "quarantine gateway package tree digest",
        )
        _digest(
            gateway["python_executable_digest"],
            "quarantine Python executable digest",
        )
        derived_gateway_profile_digest = github_gateway_profile_digest(
            containment_profile=containment_profile,
            gateway_package_tree_digest=gateway["package_tree_digest"],
            python_executable_digest=gateway["python_executable_digest"],
        )
        if document["gateway_profile_digest"] != derived_gateway_profile_digest:
            raise GitHubQuarantineReceiptError(
                "quarantine gateway profile does not match its measurements"
            )
        if document["gateway_profile_digest"] != gateway_profile_digest:
            raise GitHubQuarantineReceiptError(
                "quarantine gateway profile identity is untrusted"
            )
        # The profile value is deliberately returned for the admission layer to
        # authorize. Receipt replay itself records both supported acquisition
        # environments without granting either admission authority.
        document["containment_profile"] = containment_profile
        return document
    except GitHubQuarantineReceiptError:
        raise
    except (ArtifactClosureError, CASError, OSError, TypeError, ValueError) as exc:
        raise GitHubQuarantineReceiptError(
            f"cannot verify GitHub quarantine receipt: {exc}"
        ) from exc


def github_source_closure_digest(
    cas: CAS,
    *,
    manifest_digest: str,
    source_proof_digest: str,
    handoff_manifest_digest: str,
) -> str:
    """Digest the exact handoff/manifest/blob/proof/raw-object closure."""

    manifest_digest = _digest(manifest_digest, "manifest digest")
    source_proof_digest = _digest(source_proof_digest, "source proof digest")
    handoff_manifest_digest = _digest(
        handoff_manifest_digest,
        "handoff manifest digest",
    )
    closure = _github_source_closure(
        cas,
        manifest_digest=manifest_digest,
        source_proof_digest=source_proof_digest,
    )
    expected_handoff = build_handoff_manifest(
        kind="github_source",
        root_digest=manifest_digest,
        blobs=closure,
    )
    raw_handoff = cas.read(
        handoff_manifest_digest,
        max_bytes=_MAX_HANDOFF_MANIFEST_BYTES,
    )
    if raw_handoff != canonical_json(expected_handoff):
        raise GitHubQuarantineReceiptError(
            "retained handoff manifest does not match the verified source closure"
        )
    _add_closure_entry(
        closure,
        handoff_manifest_digest,
        len(raw_handoff),
        "handoff manifest",
    )
    records = [
        {"digest": digest, "size": size} for digest, size in sorted(closure.items())
    ]
    return _sha256(canonical_json(records))


def github_gateway_profile_digest(
    *,
    containment_profile: str,
    gateway_package_tree_digest: str,
    python_executable_digest: str,
) -> str:
    """Bind the exact gateway code measurements to one containment profile."""

    profile = {
        "schema": _GATEWAY_PROFILE_SCHEMA,
        "containment_profile": _containment_profile(containment_profile),
        "gateway": {
            "package_tree_digest": _digest(
                gateway_package_tree_digest,
                "gateway package tree digest",
            ),
            "python_executable_digest": _digest(
                python_executable_digest,
                "Python executable digest",
            ),
        },
    }
    return _sha256(canonical_json(profile))


def _github_source_closure(
    cas: CAS,
    *,
    manifest_digest: str,
    source_proof_digest: str,
) -> dict[str, int]:
    manifest = load_verified_retained_manifest(cas, manifest_digest)
    if manifest["schema"] != "aragorn/github-manifest/v1":
        raise GitHubQuarantineReceiptError("source closure requires a GitHub manifest")
    raw_manifest = cas.read(manifest_digest, max_bytes=_MAX_MANIFEST_BYTES)
    if canonical_json(manifest) != raw_manifest:
        raise GitHubQuarantineReceiptError(
            "verified GitHub manifest bytes are not canonical"
        )
    closure = {manifest_digest: len(raw_manifest)}
    for entry in manifest["files"]:
        _add_closure_entry(
            closure,
            entry["digest"],
            entry["size"],
            "source manifest",
        )
    proof = verify_github_source_proof(
        cas,
        source_proof_digest,
        manifest_digest,
    )
    raw_proof = cas.read(source_proof_digest, max_bytes=_MAX_PROOF_BYTES)
    if canonical_json(proof) != raw_proof:
        raise GitHubQuarantineReceiptError(
            "verified GitHub source proof bytes are not canonical"
        )
    _add_closure_entry(
        closure,
        source_proof_digest,
        len(raw_proof),
        "source proof",
    )
    for entry in proof["objects"]:
        _add_closure_entry(
            closure,
            entry["digest"],
            entry["size"],
            "source proof",
        )
    return closure


def _add_closure_entry(
    closure: dict[str, int],
    digest: object,
    size: object,
    label: str,
) -> None:
    digest = _digest(digest, f"{label} blob digest")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise GitHubQuarantineReceiptError(f"{label} blob size is invalid")
    previous = closure.setdefault(digest, size)
    if previous != size:
        raise GitHubQuarantineReceiptError(
            f"{label} repeats a digest with another size"
        )


def _request_for_manifest(
    request: object,
    manifest: dict[str, Any],
) -> dict[str, str]:
    source = manifest["source"]
    expected = {
        "schema": _REQUEST_SCHEMA,
        "owner": source["owner"],
        "repository": source["repository"],
        "commit": source["commit"],
        "skill_path": source["skill_path"],
    }
    if not isinstance(request, dict) or request != expected:
        raise GitHubQuarantineReceiptError(
            "quarantine request does not match the verified GitHub manifest"
        )
    return expected


def _protected_cas_state(cas: CAS) -> os.stat_result:
    root = cas.root
    metadata = os.lstat(root)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_uid != os.geteuid()
    ):
        raise GitHubQuarantineReceiptError(
            "quarantine CAS root is not protected by the current broker"
        )
    return metadata


def _containment_profile(value: object) -> str:
    if not isinstance(value, str) or value not in _CONTAINMENT_PROFILES:
        raise GitHubQuarantineReceiptError(
            "quarantine containment profile is unsupported"
        )
    return value


def _require_host_containment_profile(profile: str) -> None:
    expected_platform = {
        LINUX_CONTAINMENT_PROFILE: "linux",
        DARWIN_CONTAINMENT_PROFILE: "darwin",
    }[profile]
    if sys.platform != expected_platform:
        raise GitHubQuarantineReceiptError(
            "quarantine containment profile does not match the current host"
        )


def _canonical_document(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except GitHubQuarantineReceiptError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise GitHubQuarantineReceiptError(
            f"quarantine receipt is invalid: {exc}"
        ) from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise GitHubQuarantineReceiptError("quarantine receipt is not canonical JSON")
    return document


def _exact_object(
    value: object,
    keys: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubQuarantineReceiptError(f"{label} must be an object")
    _exact_keys(value, keys, label)
    return value


def _exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise GitHubQuarantineReceiptError(f"{label} has missing or unknown fields")


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _DIGEST_LENGTH
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise GitHubQuarantineReceiptError(f"{label} is invalid")
    return value


def _receipt_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise GitHubQuarantineReceiptError("quarantine receipt id is invalid")
    return value


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GitHubQuarantineReceiptError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise GitHubQuarantineReceiptError(f"non-finite JSON number: {value}")
