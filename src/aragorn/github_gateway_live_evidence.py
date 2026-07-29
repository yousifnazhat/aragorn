"""Offline replay for the retained Phase 1 live GitHub gateway evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from io import BytesIO
from tempfile import TemporaryDirectory
from typing import Any

from . import admission_artifact_graph, github_quarantine_receipt
from .artifact_closure import (
    ArtifactClosureError,
    canonical_json,
    load_verified_retained_manifest,
)
from .cas import CAS, CASError
from .github_source_proof import verify_github_source_proof

SCHEMA = "aragorn/github-gateway-live-evidence/v1"
AUTHORITY = "QUARANTINE_AND_CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
LIVE_EVIDENCE_DIGEST = (
    "sha256:ca8a5f940c5a5cb0ff261c3adb71e131f05cdee852dff2b37a84d43de5c5be8a"
)
_MAX_BLOB_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 32 * 1024 * 1024


class GitHubGatewayLiveEvidenceError(ValueError):
    """The retained live gateway evidence is malformed or inconsistent."""


def verify_github_gateway_live_evidence(document: object) -> dict[str, Any]:
    """Replay archived source semantics without claiming live Linux custody."""

    try:
        evidence = _exact_object(
            document,
            {"schema", "authority", "environment", "assurance", "positive", "negative"},
            "live gateway evidence",
        )
        if evidence["schema"] != SCHEMA or evidence["authority"] != AUTHORITY:
            raise GitHubGatewayLiveEvidenceError(
                "live gateway evidence overstates or changes its authority"
            )
        if _sha256(canonical_json(evidence)) != LIVE_EVIDENCE_DIGEST:
            raise GitHubGatewayLiveEvidenceError(
                "live gateway evidence digest is not the retained identity"
            )
        _verify_boundary(evidence)
        _verify_negative(evidence["negative"])
        _verify_positive(evidence["positive"])
        return evidence
    except GitHubGatewayLiveEvidenceError:
        raise
    except (
        ArtifactClosureError,
        AttributeError,
        CASError,
        github_quarantine_receipt.GitHubQuarantineReceiptError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise GitHubGatewayLiveEvidenceError(
            f"cannot verify retained live gateway evidence: {exc}"
        ) from exc


def _verify_boundary(evidence: dict[str, Any]) -> None:
    if evidence["environment"] != {
        "capture": "OPERATOR_AND_READ_ONLY_VM_INSPECTION",
        "host": "aragorn-phase1-gateway-20260728a",
        "platform": "linux",
        "quarantine_path": (
            "/var/lib/aragorn-quarantine/phase1-skill-anthropics-b29e7cf"
        ),
        "recorded_on": "2026-07-29",
    }:
        raise GitHubGatewayLiveEvidenceError("live gateway environment changed")
    if evidence["assurance"] != {
        "custody_replay": (
            "LIVE_LINUX_DEVICE_INODE_AND_ROOT_CUSTODY_NOT_REPLAYABLE_ON_MACOS"
        ),
        "limitations": [
            "NO_INSTALLER_AUTHORITY",
            "NO_CROSS_HOST_CUSTODY_REPLAY",
            "NEGATIVE_CLEANUP_COUNTERS_NOT_RETAINED_AS_MACHINE_ATTESTATION",
        ],
        "negative_observation": "OPERATOR_OBSERVED_NON_AUTHORITATIVE",
        "positive_replay": "SOURCE_CLOSURE_AND_GRAPH_SEMANTICS_REPLAYED_OFFLINE",
    }:
        raise GitHubGatewayLiveEvidenceError("live gateway assurance boundary changed")


def _verify_negative(value: object) -> None:
    negative = _exact_object(
        value,
        {"request", "result", "cleanup"},
        "negative gateway observation",
    )
    if negative["request"] != {
        "commit": "a" * 40,
        "owner": "openai",
        "repository": "skills",
        "schema": "aragorn/github-gateway-request/v1",
        "skill_path": (
            "skills/.curated/figma-code-connect-components/references"
        ),
    }:
        raise GitHubGatewayLiveEvidenceError("negative gateway request changed")
    if negative["result"] != {
        "error": "gateway exited unsuccessfully with status 4",
        "error_type": "GitHubGatewayError",
        "quarantine_target": (
            "/var/lib/aragorn-quarantine/phase1-invalid-openai-all-a"
        ),
        "quarantine_target_absent": True,
        "status": "ERROR",
    }:
        raise GitHubGatewayLiveEvidenceError("negative gateway result changed")
    if negative["cleanup"] != {
        "cgroup_directories": 0,
        "gateway_root_entries": 0,
        "systemd_transient_units": 0,
        "uid_999_processes": 0,
        "uid_lease_flock_available": True,
    }:
        raise GitHubGatewayLiveEvidenceError("negative cleanup observation changed")


def _verify_positive(value: object) -> None:
    positive = _exact_object(
        value,
        {"request", "result", "cas_blobs"},
        "positive gateway evidence",
    )
    request = positive["request"]
    if request != {
        "commit": "b29e7cf65e5cb78a5ac33d582270551bc74a14eb",
        "owner": "anthropics",
        "repository": "skills",
        "schema": "aragorn/github-gateway-request/v1",
        "skill_path": "template",
    }:
        raise GitHubGatewayLiveEvidenceError("positive gateway request changed")
    result = _exact_object(
        positive["result"],
        {
            "artifact_graph_digest",
            "gateway_profile_digest",
            "manifest_digest",
            "quarantine_receipt_digest",
        },
        "positive gateway result",
    )
    blobs = positive["cas_blobs"]
    if not isinstance(blobs, list) or len(blobs) != 9:
        raise GitHubGatewayLiveEvidenceError(
            "positive gateway CAS inventory must contain nine blobs"
        )

    total = 0
    inventory: dict[str, int] = {}
    with TemporaryDirectory() as temporary:
        cas = CAS(temporary)
        for item in blobs:
            blob = _exact_object(
                item,
                {"digest", "size", "base64"},
                "positive gateway CAS blob",
            )
            digest = _digest(blob["digest"], "positive gateway CAS blob digest")
            size = blob["size"]
            if (
                isinstance(size, bool)
                or not isinstance(size, int)
                or not 0 <= size <= _MAX_BLOB_BYTES
            ):
                raise GitHubGatewayLiveEvidenceError(
                    "positive gateway CAS blob size is invalid"
                )
            if digest in inventory:
                raise GitHubGatewayLiveEvidenceError(
                    "positive gateway CAS blob is duplicated"
                )
            try:
                raw = base64.b64decode(blob["base64"], validate=True)
            except (binascii.Error, TypeError, ValueError) as exc:
                raise GitHubGatewayLiveEvidenceError(
                    "positive gateway CAS blob base64 is invalid"
                ) from exc
            if len(raw) != size:
                raise GitHubGatewayLiveEvidenceError(
                    "positive gateway CAS blob size changed"
                )
            total += size
            if total > _MAX_TOTAL_BYTES:
                raise GitHubGatewayLiveEvidenceError(
                    "positive gateway CAS inventory exceeds its byte limit"
                )
            cas.put_expected(
                BytesIO(raw),
                expected_digest=digest,
                max_bytes=size,
            )
            inventory[digest] = size
        if [item["digest"] for item in blobs] != sorted(inventory):
            raise GitHubGatewayLiveEvidenceError(
                "positive gateway CAS inventory is not canonically ordered"
            )
        _replay_positive(cas, request=request, result=result, inventory=inventory)


def _replay_positive(
    cas: CAS,
    *,
    request: dict[str, Any],
    result: dict[str, Any],
    inventory: dict[str, int],
) -> None:
    manifest_digest = _digest(
        result["manifest_digest"],
        "positive manifest digest",
    )
    receipt_digest = _digest(
        result["quarantine_receipt_digest"],
        "positive quarantine receipt digest",
    )
    graph_digest = _digest(
        result["artifact_graph_digest"],
        "positive artifact graph digest",
    )
    profile_digest = _digest(
        result["gateway_profile_digest"],
        "positive gateway profile digest",
    )
    manifest = load_verified_retained_manifest(cas, manifest_digest)
    if manifest["source"] != {
        "api_version": "2026-03-10",
        "commit": request["commit"],
        "commit_tree": "a87780349fa9dc5c65c9a11dcc7151ec297f21a1",
        "host": "github.com",
        "kind": "github_commit",
        "owner": request["owner"],
        "repository": request["repository"],
        "repository_hash_algorithm": "sha1",
        "skill_path": request["skill_path"],
        "skill_tree": "a38aa7fa73fd2835b9ce77a60274f7dc62d015a6",
    }:
        raise GitHubGatewayLiveEvidenceError("positive manifest source changed")

    receipt = _canonical_cas_document(cas, receipt_digest, "quarantine receipt")
    proof_digest = _digest(
        receipt.get("source_proof_digest"),
        "positive source proof digest",
    )
    verify_github_source_proof(cas, proof_digest, manifest_digest)
    handoff_digest = _digest(
        receipt.get("handoff_manifest_digest"),
        "positive handoff manifest digest",
    )
    handoff = _canonical_cas_document(cas, handoff_digest, "handoff manifest")
    closure_inventory = {
        item["digest"]: item["size"] for item in handoff.get("blobs", ())
    }
    expected_inventory = {
        **closure_inventory,
        handoff_digest: inventory[handoff_digest],
        receipt_digest: inventory[receipt_digest],
        graph_digest: inventory[graph_digest],
    }
    if inventory != expected_inventory:
        raise GitHubGatewayLiveEvidenceError(
            "positive gateway CAS inventory is not the exact retained closure"
        )

    _verify_receipt(
        cas,
        receipt,
        request=request,
        manifest=manifest,
        manifest_digest=manifest_digest,
        receipt_digest=receipt_digest,
        profile_digest=profile_digest,
    )
    _verify_graph(
        cas,
        graph_digest=graph_digest,
        manifest=manifest,
        manifest_digest=manifest_digest,
        receipt_digest=receipt_digest,
        source_proof_digest=proof_digest,
        profile_digest=profile_digest,
    )


def _verify_receipt(
    cas: CAS,
    receipt: dict[str, Any],
    *,
    request: dict[str, Any],
    manifest: dict[str, Any],
    manifest_digest: str,
    receipt_digest: str,
    profile_digest: str,
) -> None:
    if set(receipt) != {
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
    }:
        raise GitHubGatewayLiveEvidenceError("positive quarantine receipt shape changed")
    if (
        receipt["schema"] != github_quarantine_receipt.SCHEMA
        or receipt["authority"] != github_quarantine_receipt.AUTHORITY
        or receipt["source_assurance"] != github_quarantine_receipt.SOURCE_ASSURANCE
        or receipt["request"] != request
        or receipt["request_digest"] != _sha256(canonical_json(request))
        or receipt["manifest_digest"] != manifest_digest
        or receipt["tree_digest"] != manifest["tree_digest"]
        or receipt["file_count"] != len(manifest["files"])
        or receipt["containment_profile"]
        != github_quarantine_receipt.LINUX_CONTAINMENT_PROFILE
        or receipt["gateway_profile_digest"] != profile_digest
    ):
        raise GitHubGatewayLiveEvidenceError(
            "positive quarantine receipt binding changed"
        )
    if _sha256(canonical_json(receipt)) != receipt_digest:
        raise GitHubGatewayLiveEvidenceError(
            "positive quarantine receipt digest changed"
        )
    if receipt[
        "source_closure_digest"
    ] != github_quarantine_receipt.github_source_closure_digest(
        cas,
        manifest_digest=manifest_digest,
        source_proof_digest=receipt["source_proof_digest"],
        handoff_manifest_digest=receipt["handoff_manifest_digest"],
    ):
        raise GitHubGatewayLiveEvidenceError(
            "positive quarantine source closure changed"
        )
    gateway = receipt["gateway"]
    if profile_digest != github_quarantine_receipt.github_gateway_profile_digest(
        containment_profile=github_quarantine_receipt.LINUX_CONTAINMENT_PROFILE,
        gateway_package_tree_digest=gateway["package_tree_digest"],
        python_executable_digest=gateway["python_executable_digest"],
    ):
        raise GitHubGatewayLiveEvidenceError(
            "positive quarantine gateway profile changed"
        )
    custody = receipt["protected_cas"]
    if (
        not isinstance(custody, dict)
        or set(custody) != {"root_device", "root_inode", "owner_uid", "mode"}
        or custody["owner_uid"] != 0
        or custody["mode"] != 0o700
        or not all(
            isinstance(custody[field], int)
            and not isinstance(custody[field], bool)
            and custody[field] > 0
            for field in ("root_device", "root_inode")
        )
    ):
        raise GitHubGatewayLiveEvidenceError(
            "positive quarantine observed custody changed"
        )


def _verify_graph(
    cas: CAS,
    *,
    graph_digest: str,
    manifest: dict[str, Any],
    manifest_digest: str,
    receipt_digest: str,
    source_proof_digest: str,
    profile_digest: str,
) -> None:
    graph = _canonical_cas_document(cas, graph_digest, "artifact graph")
    edges, unresolved = admission_artifact_graph._scan_admission_markdown(
        cas,
        manifest,
        scan_references=True,
        unresolved=set(),
    )
    expected = {
        "schema": "aragorn/admission-artifact-graph/v2",
        "authority": "CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY",
        "verifier": {
            "name": admission_artifact_graph.VERIFIER,
            "version": admission_artifact_graph.GITHUB_VERIFIER_VERSION,
            "implementation_digest": graph.get("verifier", {}).get(
                "implementation_digest"
            ),
        },
        "profile": admission_artifact_graph.GITHUB_PROFILE,
        "root_manifest_digest": manifest_digest,
        "source_proof_digest": source_proof_digest,
        "quarantine_receipt_digest": receipt_digest,
        "gateway_profile_digest": profile_digest,
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
    if (
        graph != expected
        or graph["verifier"]["implementation_digest"]
        != _canonical_cas_document(
            cas,
            receipt_digest,
            "quarantine receipt",
        )["gateway"]["package_tree_digest"]
        or _sha256(canonical_json(graph)) != graph_digest
    ):
        raise GitHubGatewayLiveEvidenceError(
            "positive admission artifact graph changed"
        )


def _canonical_cas_document(cas: CAS, digest: str, label: str) -> dict[str, Any]:
    raw = cas.read(digest, max_bytes=_MAX_BLOB_BYTES)
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GitHubGatewayLiveEvidenceError(f"{label} JSON is invalid") from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise GitHubGatewayLiveEvidenceError(f"{label} is not canonical JSON")
    return document


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise GitHubGatewayLiveEvidenceError(
            f"{label} has missing or unknown fields"
        )
    return value


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise GitHubGatewayLiveEvidenceError(f"{label} is invalid")
    return value


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise GitHubGatewayLiveEvidenceError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise GitHubGatewayLiveEvidenceError(f"non-finite JSON number: {value}")
