"""Strict offline replay for normalized recursive GitHub evidence archives."""

from __future__ import annotations

import hashlib
import json
import tarfile
from collections import Counter
from io import BytesIO
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from . import (
    decision_receipt,
    github_gateway_live_evidence,
    github_recursive_artifact_graph,
)
from .admission_decision import policy_artifact_graph_profiles
from .artifact_closure import canonical_json, load_verified_retained_manifest
from .benchmark_handoff_v2 import validate_handoff_manifest
from .cas import CAS
from .github_expansion_proof import verify_github_expansion_proof
from .github_gateway import build_gateway_request
from .github_source_proof import verify_github_source_proof
from .oci_worker_protocol import canonical_digest
from .policy import evaluate_policy

AUTHORITY = "OFFLINE_RECURSIVE_GITHUB_REPLAY_ONLY_NOT_INSTALLER_AUTHORITY"
CAPTURE_AUTHORITY = "QUARANTINE_AND_CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_MEMBERS = 1024
_V1_KEYS = {
    "schema",
    "authority",
    "assurance",
    "capture",
    "cas_blobs",
    "metrics",
    "provenance",
    "request",
    "result",
}
_V2_KEYS = _V1_KEYS | {"decision"}
_RESULT_KEYS = {
    "closure_status",
    "expansion_digest",
    "expansion_proof_digest",
    "gateway_profile_digest",
    "graph_digest",
    "handoff_manifest_digest",
    "manifest_digest",
    "quarantine_receipt_digest",
    "request_digest",
    "root_handoff_manifest_digest",
    "root_manifest_digest",
    "source_proof_digest",
}
_METRIC_KEYS = {
    "cas_blob_count",
    "cas_payload_bytes",
    "edge_count",
    "expanded_artifact_count",
    "root_file_count",
    "static_captured",
    "static_percentage",
    "static_total",
    "unresolved_reason_counts",
    "unresolved_required",
}
_DECISION_KEYS = {
    "decision_digest",
    "verdict",
    "reason_codes",
    "policy_digest",
    "analyzer_run_receipt_digests",
    "analyzer_verifier_digest",
    "artifact_graph_verifier_digest",
}


class GitHubRecursiveLiveArchiveError(ValueError):
    """A retained recursive GitHub archive is malformed or inconsistent."""


def verify_github_recursive_live_archive(
    archive_path: str | Path,
    *,
    expected_archive_digest: str,
    inventory_path: str | Path,
    expected_inventory_digest: str,
    expected_request: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Replay one digest-pinned archive without re-attesting live custody."""

    try:
        archive_raw = _pinned_raw(
            archive_path,
            expected_archive_digest,
            _MAX_ARCHIVE_BYTES,
            "archive",
        )
        inventory_raw = _pinned_raw(
            inventory_path,
            expected_inventory_digest,
            _MAX_MEMBER_BYTES,
            "inventory",
        )
        inventory = _pretty_document(inventory_raw, "inventory")
        capture_raw, blobs, archive_facts, member_inventory = _load_archive(archive_raw)
        _verify_inventory(
            inventory,
            archive_path=Path(archive_path),
            archive_digest=expected_archive_digest,
            archive_size=len(archive_raw),
            archive_facts=archive_facts,
            members=member_inventory,
        )
        capture = _canonical_document(capture_raw, "capture")
        schema = capture.get("schema")
        expected_keys = {
            "aragorn/github-recursive-live-evidence/v1": _V1_KEYS,
            "aragorn/github-recursive-live-evidence/v2": _V2_KEYS,
        }.get(schema)
        if (
            expected_keys is None
            or set(capture) != expected_keys
            or capture["authority"] != CAPTURE_AUTHORITY
        ):
            raise GitHubRecursiveLiveArchiveError(
                "capture schema, fields, or authority are unsupported"
            )
        _verify_capture_boundary(capture)
        request = build_gateway_request(
            capture["request"].get("owner"),
            capture["request"].get("repository"),
            capture["request"].get("commit"),
            capture["request"].get("skill_path"),
        )
        if capture["request"] != request or (
            expected_request is not None and request != expected_request
        ):
            raise GitHubRecursiveLiveArchiveError("capture request changed")
        actual_blobs = [
            {"digest": digest, "size": len(content)}
            for digest, content in sorted(blobs.items())
        ]
        if capture["cas_blobs"] != actual_blobs:
            raise GitHubRecursiveLiveArchiveError(
                "capture CAS inventory does not match the archive"
            )

        with TemporaryDirectory(prefix="aragorn-recursive-archive-") as temporary:
            cas = CAS(Path(temporary))
            for digest, content in blobs.items():
                cas.put_expected(
                    BytesIO(content),
                    expected_digest=digest,
                    max_bytes=len(content),
                )
            result = _result(capture["result"])
            if canonical_digest(request) != result["request_digest"]:
                raise GitHubRecursiveLiveArchiveError(
                    "recursive request digest changed"
                )
            root_manifest = load_verified_retained_manifest(
                cas,
                result["root_manifest_digest"],
            )
            receipt = _verify_receipt(cas, capture, request, root_manifest, result)
            graph = _verify_graph(cas, capture, receipt, result)
            decision = (
                _verify_decision(cas, capture["decision"], graph, result)
                if schema.endswith("/v2")
                else None
            )
            _verify_handoff(
                cas,
                blobs,
                result,
                decision_record=(
                    capture["decision"] if schema.endswith("/v2") else None
                ),
            )
            _verify_cas_inventory(cas, blobs)

        coverage = graph["coverage"]["statically_resolvable"]
        unresolved = graph["closure"]["unresolved"]
        _verify_metrics(
            capture["metrics"],
            graph=graph,
            root_manifest=root_manifest,
            coverage=coverage,
            unresolved=unresolved,
            blobs=blobs,
        )
        return {
            "schema": "aragorn/github-recursive-live-archive-replay/v1",
            "authority": AUTHORITY,
            "archive_digest": expected_archive_digest,
            "inventory_digest": expected_inventory_digest,
            "archive": archive_facts,
            "request": request,
            "manifest_digest": result["manifest_digest"],
            "graph_digest": result["graph_digest"],
            "tree_digest": graph["tree_digest"],
            "closure_status": graph["closure"]["status"],
            "static_captured": coverage["captured"],
            "static_total": coverage["total"],
            "unresolved": unresolved,
            "allow_possible": graph["closure"]["status"] == "complete",
            "outcome": None if decision is None else decision["verdict"],
            "decision_digest": (
                None if decision is None else capture["decision"]["decision_digest"]
            ),
        }
    except GitHubRecursiveLiveArchiveError:
        raise
    except Exception as exc:
        raise GitHubRecursiveLiveArchiveError(
            f"cannot verify recursive GitHub archive: {exc}"
        ) from exc


def _verify_capture_boundary(capture: dict[str, Any]) -> None:
    if capture["assurance"] != {
        "archive_replay": (
            "SOURCE_PROOF_RECEIPT_HANDOFF_EXPANSION_AND_GRAPH_REPLAYED_OFFLINE"
        ),
        "custody_replay": "LIVE_LINUX_CUSTODY_RECORDED_NOT_REATTESTED",
        "decision": "INCOMPLETE_CLOSURE_NOT_ALLOW",
        "skill_handling": "INERT_CAS_BYTES_ONLY_NOT_INSTALLED_OR_EXECUTED",
    }:
        raise GitHubRecursiveLiveArchiveError("capture assurance changed")
    environment = capture["capture"]
    if (
        not isinstance(environment, dict)
        or set(environment) != {"host", "platform", "quarantine_path", "recorded_on"}
        or environment["platform"] != "linux"
        or environment["recorded_on"] != "2026-07-29"
    ):
        raise GitHubRecursiveLiveArchiveError("capture environment changed")
    provenance = capture["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != {
        "aragorn_commit",
        "aragorn_tree",
        "commit_signature",
        "gateway_runtime",
        "graph_verifier",
    }:
        raise GitHubRecursiveLiveArchiveError("capture provenance fields changed")
    graph_verifier = provenance["graph_verifier"]
    if (
        not isinstance(graph_verifier, dict)
        or set(graph_verifier) != {"implementation_digest", "path"}
        or graph_verifier["path"] != "src/aragorn/github_recursive_artifact_graph.py"
    ):
        raise GitHubRecursiveLiveArchiveError(
            "capture graph verifier provenance changed"
        )
    expected = _require_digest(
        graph_verifier["implementation_digest"],
        "graph verifier implementation digest",
    )
    implementation = Path(github_recursive_artifact_graph.__file__).read_bytes()
    if _digest(implementation) != expected:
        raise GitHubRecursiveLiveArchiveError(
            "local graph verifier differs from captured implementation"
        )
    signature = provenance["commit_signature"]
    if (
        not isinstance(signature, dict)
        or set(signature) != {"fingerprint", "signer", "status"}
        or signature["status"] != "GOOD_SSH_SIGNATURE"
    ):
        raise GitHubRecursiveLiveArchiveError(
            "capture commit signature provenance changed"
        )
    runtime = provenance["gateway_runtime"]
    if not isinstance(runtime, dict) or set(runtime) != {
        "package_archive_raw_sha256",
        "package_file_count",
        "package_protected_source_tree_sha256",
        "package_tree_digest",
        "python_executable_digest",
    }:
        raise GitHubRecursiveLiveArchiveError(
            "capture gateway runtime provenance changed"
        )
    for field in runtime:
        if field != "package_file_count":
            _require_digest(runtime[field], f"gateway runtime {field}")
    if (
        isinstance(runtime["package_file_count"], bool)
        or not isinstance(runtime["package_file_count"], int)
        or runtime["package_file_count"] < 1
    ):
        raise GitHubRecursiveLiveArchiveError("capture package file count is invalid")


def _result(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _RESULT_KEYS:
        raise GitHubRecursiveLiveArchiveError("recursive result fields changed")
    for field in _RESULT_KEYS - {"closure_status", "expansion_proof_digest"}:
        _require_digest(value[field], f"recursive result {field}")
    proof = value["expansion_proof_digest"]
    if proof is not None:
        _require_digest(proof, "recursive result expansion proof digest")
    if value["closure_status"] not in {"complete", "incomplete"}:
        raise GitHubRecursiveLiveArchiveError(
            "recursive result closure status is invalid"
        )
    return value


def _verify_receipt(
    cas: CAS,
    capture: dict[str, Any],
    request: dict[str, str],
    root_manifest: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    receipt = _cas_document(
        cas,
        result["quarantine_receipt_digest"],
        "quarantine receipt",
    )
    github_gateway_live_evidence._verify_receipt(
        cas,
        receipt,
        request=request,
        manifest=root_manifest,
        manifest_digest=result["root_manifest_digest"],
        receipt_digest=result["quarantine_receipt_digest"],
        profile_digest=result["gateway_profile_digest"],
    )
    if (
        receipt["source_proof_digest"] != result["source_proof_digest"]
        or receipt["handoff_manifest_digest"] != result["root_handoff_manifest_digest"]
        or receipt["gateway"]
        != {
            "package_tree_digest": capture["provenance"]["gateway_runtime"][
                "package_tree_digest"
            ],
            "python_executable_digest": capture["provenance"]["gateway_runtime"][
                "python_executable_digest"
            ],
        }
    ):
        raise GitHubRecursiveLiveArchiveError("quarantine receipt provenance changed")
    verify_github_source_proof(
        cas,
        result["source_proof_digest"],
        result["root_manifest_digest"],
    )
    return receipt


def _verify_handoff(
    cas: CAS,
    blobs: dict[str, bytes],
    result: dict[str, Any],
    *,
    decision_record: dict[str, Any] | None,
) -> None:
    digest = result["handoff_manifest_digest"]
    handoff = _cas_document(cas, digest, "recursive handoff")
    validate_handoff_manifest(handoff)
    if handoff["root_digest"] != result["manifest_digest"]:
        raise GitHubRecursiveLiveArchiveError("recursive handoff root changed")
    declared = {item["digest"]: item["size"] for item in handoff["blobs"]}
    for blob_digest, size in declared.items():
        cas.verify(blob_digest, max_bytes=size)
    expected = {
        **declared,
        digest: len(blobs[digest]),
        result["quarantine_receipt_digest"]: len(
            blobs[result["quarantine_receipt_digest"]]
        ),
        result["graph_digest"]: len(blobs[result["graph_digest"]]),
        **(
            {}
            if decision_record is None
            else _decision_blob_closure(cas, decision_record)
        ),
    }
    actual = {blob_digest: len(content) for blob_digest, content in blobs.items()}
    if expected != actual:
        raise GitHubRecursiveLiveArchiveError(
            "recursive handoff is not the exact retained CAS closure"
        )


def _decision_blob_closure(
    cas: CAS,
    record: dict[str, Any],
) -> dict[str, int]:
    """Return the exact replay inputs referenced by one verified decision."""

    digests = {
        record["decision_digest"],
        record["policy_digest"],
        *record["analyzer_run_receipt_digests"],
    }
    for run_digest in record["analyzer_run_receipt_digests"]:
        receipt = _cas_document(cas, run_digest, "analyzer run receipt")
        request_digest = receipt["request_digest"]
        digests.update(
            {
                request_digest,
                receipt["stdout_digest"],
                receipt["stderr_digest"],
                *receipt["observation_digests"],
            }
        )
        request = _json_document(
            cas.read(request_digest, max_bytes=_MAX_MEMBER_BYTES),
            "analyzer request",
        )
        analyzer = request["analyzer"]
        digests.update(
            {
                analyzer["config_digest"],
                analyzer["executable_digest"],
            }
        )
    return {
        digest: len(cas.read(digest, max_bytes=_MAX_MEMBER_BYTES)) for digest in digests
    }


def _verify_graph(
    cas: CAS,
    capture: dict[str, Any],
    receipt: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    expansion = github_recursive_artifact_graph._load_expansion(
        cas,
        result["expansion_digest"],
    )
    if expansion.get("root_manifest_digest") != result["root_manifest_digest"]:
        raise GitHubRecursiveLiveArchiveError(
            "recursive expansion root manifest changed"
        )
    expected_manifest = github_recursive_artifact_graph._derive_expanded_manifest(
        cas,
        expansion,
    )
    retained_manifest = load_verified_retained_manifest(
        cas,
        result["manifest_digest"],
    )
    if retained_manifest != expected_manifest:
        raise GitHubRecursiveLiveArchiveError("expanded installable manifest changed")
    closure = expansion.get("closure")
    complete = (
        isinstance(closure, dict)
        and closure.get("status") == "complete"
        and closure.get("unresolved") == []
    )
    has_objects = bool(expansion.get("objects"))
    proof_digest = result["expansion_proof_digest"]
    if complete or has_objects:
        if proof_digest is None:
            raise GitHubRecursiveLiveArchiveError(
                "retained expansion objects omit membership proof"
            )
        verify_github_expansion_proof(
            cas,
            proof_digest,
            expected_expansion_digest=result["expansion_digest"],
            expected_root_manifest_digest=result["root_manifest_digest"],
        )
    elif proof_digest is not None:
        raise GitHubRecursiveLiveArchiveError(
            "empty incomplete expansion claims membership proof"
        )
    edges, scan_unresolved, static_total, static_captured = (
        github_recursive_artifact_graph._scan_recursive(cas, expansion)
    )
    unresolved = set(scan_unresolved)
    if not complete:
        for reason in github_recursive_artifact_graph._expansion_unresolved(closure):
            unresolved.add(f"EXPANSION_{reason['reason_code']}:{reason['subject']}")
    ordered_unresolved = sorted(unresolved)
    verifier_digest = _require_digest(
        capture["provenance"]["graph_verifier"]["implementation_digest"],
        "captured graph verifier digest",
    )
    expected = {
        "schema": github_recursive_artifact_graph.SCHEMA,
        "authority": github_recursive_artifact_graph._AUTHORITY,
        "verifier": {
            "name": github_recursive_artifact_graph.VERIFIER,
            "version": github_recursive_artifact_graph.VERIFIER_VERSION,
            "implementation_digest": verifier_digest,
        },
        "profile": github_recursive_artifact_graph.PROFILE,
        "root_manifest_digest": result["manifest_digest"],
        "root_github_manifest_digest": result["root_manifest_digest"],
        "source_proof_digest": receipt["source_proof_digest"],
        "quarantine_receipt_digest": result["quarantine_receipt_digest"],
        "gateway_profile_digest": result["gateway_profile_digest"],
        "expansion_digest": result["expansion_digest"],
        "expansion_proof_digest": proof_digest,
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
            "profile": github_recursive_artifact_graph.PROFILE,
            "status": "incomplete" if ordered_unresolved else "complete",
            "unresolved": ordered_unresolved,
        },
    }
    graph = _cas_document(cas, result["graph_digest"], "recursive artifact graph")
    if graph != expected or canonical_digest(graph) != result["graph_digest"]:
        raise GitHubRecursiveLiveArchiveError(
            "recursive artifact graph does not replay"
        )
    return graph


def _verify_decision(
    cas: CAS,
    record: object,
    graph: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != _DECISION_KEYS:
        raise GitHubRecursiveLiveArchiveError("decision fields are invalid")
    for field in (
        "decision_digest",
        "policy_digest",
        "analyzer_verifier_digest",
        "artifact_graph_verifier_digest",
    ):
        _require_digest(record[field], f"decision {field}")
    run_receipts = record["analyzer_run_receipt_digests"]
    if (
        not isinstance(run_receipts, list)
        or len(run_receipts) > 16
        or len(run_receipts) != len(set(run_receipts))
    ):
        raise GitHubRecursiveLiveArchiveError(
            "decision analyzer receipt selection is invalid"
        )
    for digest in run_receipts:
        _require_digest(digest, "decision analyzer run receipt digest")
    decision = _cas_document(cas, record["decision_digest"], "decision")
    validated_policy, policy = decision_receipt._load_policy(
        cas,
        record["policy_digest"],
    )
    results, analyzer_records = decision_receipt._replay_analyzers(
        cas,
        decision.get("analyzers"),
        tree_digest=graph["tree_digest"],
        verifier_digest=record["analyzer_verifier_digest"],
        expected_run_receipt_digests=run_receipts,
    )
    evaluated = evaluate_policy(
        policy,
        closure=graph["closure"],
        results=results,
    )
    if graph["profile"] not in policy_artifact_graph_profiles(validated_policy):
        verdict = "ERROR"
        reason_codes = ["ARTIFACT_GRAPH_PROFILE_NOT_ALLOWED"]
    else:
        verdict = evaluated.verdict
        reason_codes = list(evaluated.reason_codes)
    expected = {
        "schema": "aragorn/decision/v3",
        "authority": "EVIDENCE_SUMMARY_ONLY_NOT_INSTALLER_AUTHORITY",
        "verdict": verdict,
        "manifest_digest": result["manifest_digest"],
        "artifact_graph_digest": result["graph_digest"],
        "tree_digest": graph["tree_digest"],
        "artifact_digests": sorted(
            artifact["digest"] for artifact in graph["artifacts"]
        ),
        "policy": {
            "id": validated_policy["id"],
            "version": validated_policy["version"],
            "digest": record["policy_digest"],
        },
        "analyzers": analyzer_records,
        "reason_codes": reason_codes,
    }
    if (
        decision != expected
        or canonical_digest(decision) != record["decision_digest"]
        or record["artifact_graph_verifier_digest"]
        != graph["verifier"]["implementation_digest"]
        or record["verdict"] != verdict
        or record["reason_codes"] != reason_codes
    ):
        raise GitHubRecursiveLiveArchiveError("decision summary does not replay")
    return decision


def _verify_metrics(
    metrics: object,
    *,
    graph: dict[str, Any],
    root_manifest: dict[str, Any],
    coverage: dict[str, int],
    unresolved: list[str],
    blobs: dict[str, bytes],
) -> None:
    reasons = dict(
        sorted(Counter(item.split(":", 1)[0] for item in unresolved).items())
    )
    percentage = (
        None
        if coverage["total"] == 0
        else 100.0 * coverage["captured"] / coverage["total"]
    )
    expected = {
        "cas_blob_count": len(blobs),
        "cas_payload_bytes": sum(len(content) for content in blobs.values()),
        "edge_count": len(graph["edges"]),
        "expanded_artifact_count": len(graph["artifacts"]),
        "root_file_count": len(root_manifest["files"]),
        "static_captured": coverage["captured"],
        "static_percentage": percentage,
        "static_total": coverage["total"],
        "unresolved_reason_counts": reasons,
        "unresolved_required": len(unresolved),
    }
    if not isinstance(metrics, dict) or set(metrics) != _METRIC_KEYS:
        raise GitHubRecursiveLiveArchiveError("capture metric fields changed")
    if metrics != expected:
        raise GitHubRecursiveLiveArchiveError(
            "capture metrics do not match replayed facts"
        )


def _verify_cas_inventory(cas: CAS, blobs: dict[str, bytes]) -> None:
    observed: dict[str, int] = {}
    root = cas.root / "blobs" / "sha256"
    for path in root.glob("*/*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        digest = f"sha256:{relative.parts[0]}{relative.parts[1]}"
        cas.verify(digest)
        observed[digest] = path.stat().st_size
    expected = {digest: len(content) for digest, content in blobs.items()}
    if observed != expected:
        raise GitHubRecursiveLiveArchiveError(
            "offline replay changed the exact CAS inventory"
        )


def _pinned_raw(
    path: str | Path,
    expected_digest: str,
    maximum: int,
    label: str,
) -> bytes:
    candidate = Path(path)
    if candidate.stat().st_size > maximum:
        raise GitHubRecursiveLiveArchiveError(f"{label} exceeds size limit")
    raw = candidate.read_bytes()
    if _digest(raw) != _require_digest(expected_digest, f"expected {label} digest"):
        raise GitHubRecursiveLiveArchiveError(f"{label} digest changed")
    return raw


def _load_archive(
    raw: bytes,
) -> tuple[bytes, dict[str, bytes], dict[str, int], list[dict[str, Any]]]:
    if (
        len(raw) < 10
        or raw[:3] != b"\x1f\x8b\x08"
        or raw[3] != 0
        or int.from_bytes(raw[4:8], "little") != 0
    ):
        raise GitHubRecursiveLiveArchiveError("archive gzip metadata is not normalized")
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    members_seen: list[dict[str, Any]] = []
    with tarfile.open(fileobj=BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= _MAX_MEMBERS:
            raise GitHubRecursiveLiveArchiveError("archive member count is invalid")
        for member in members:
            name = _member_name(member)
            if (
                member.uid != 0
                or member.gid != 0
                or member.uname
                or member.gname
                or member.mtime != 0
                or member.pax_headers
                or member.devmajor
                or member.devminor
            ):
                raise GitHubRecursiveLiveArchiveError(
                    f"archive metadata changed: {name}"
                )
            if name in files or name in directories:
                raise GitHubRecursiveLiveArchiveError(
                    f"archive repeats a member: {name}"
                )
            if member.isdir():
                if member.mode != 0o555 or member.size:
                    raise GitHubRecursiveLiveArchiveError(
                        f"archive directory metadata changed: {name}"
                    )
                directories.add(name)
                members_seen.append(
                    {"kind": "directory", "mode": 0o555, "path": name, "size": 0}
                )
                continue
            if not member.isfile() or member.mode != 0o444:
                raise GitHubRecursiveLiveArchiveError(
                    f"archive member type or mode is unsafe: {name}"
                )
            if member.size > _MAX_MEMBER_BYTES:
                raise GitHubRecursiveLiveArchiveError(
                    f"archive member exceeds size limit: {name}"
                )
            stream = archive.extractfile(member)
            content = b"" if stream is None else stream.read(member.size + 1)
            if len(content) != member.size:
                raise GitHubRecursiveLiveArchiveError(
                    f"archive member size changed: {name}"
                )
            files[name] = content
            members_seen.append(
                {
                    "kind": "file",
                    "mode": 0o444,
                    "path": name,
                    "sha256": _digest(content),
                    "size": len(content),
                }
            )
    if members_seen != sorted(members_seen, key=lambda item: item["path"]):
        raise GitHubRecursiveLiveArchiveError(
            "archive members are not canonically ordered"
        )
    roots = {PurePosixPath(name).parts[0] for name in set(files) | directories}
    if len(roots) != 1:
        raise GitHubRecursiveLiveArchiveError("archive must contain one evidence root")
    root = roots.pop()
    capture_path = f"{root}/capture.json"
    blob_prefix = f"{root}/cas/blobs/sha256/"
    if capture_path not in files:
        raise GitHubRecursiveLiveArchiveError("archive omits capture.json")
    blobs: dict[str, bytes] = {}
    for name, content in files.items():
        if name == capture_path:
            continue
        relative = name.removeprefix(blob_prefix)
        parts = relative.split("/")
        if (
            not name.startswith(blob_prefix)
            or len(parts) != 2
            or len(parts[0]) != 2
            or len(parts[1]) != 62
        ):
            raise GitHubRecursiveLiveArchiveError(
                f"archive has an unexpected file: {name}"
            )
        digest = f"sha256:{parts[0]}{parts[1]}"
        if _digest(content) != digest or digest in blobs:
            raise GitHubRecursiveLiveArchiveError(
                f"archive CAS blob identity changed: {name}"
            )
        blobs[digest] = content
    expected_directories = {
        root,
        f"{root}/cas",
        f"{root}/cas/blobs",
        f"{root}/cas/blobs/sha256",
        *(f"{root}/cas/blobs/sha256/{digest[7:9]}" for digest in blobs),
    }
    if directories != expected_directories or not blobs:
        raise GitHubRecursiveLiveArchiveError("archive directory inventory changed")
    facts = {
        "members": len(files) + len(directories),
        "regular_files": len(files),
        "directories": len(directories),
        "cas_blob_count": len(blobs),
        "cas_payload_bytes": sum(len(content) for content in blobs.values()),
    }
    return files[capture_path], blobs, facts, members_seen


def _verify_inventory(
    inventory: dict[str, Any],
    *,
    archive_path: Path,
    archive_digest: str,
    archive_size: int,
    archive_facts: dict[str, int],
    members: list[dict[str, Any]],
) -> None:
    if set(inventory) != {
        "schema",
        "archive",
        "normalization",
        "summary",
        "members",
    } or inventory["schema"] != ("aragorn/deterministic-evidence-archive-inventory/v1"):
        raise GitHubRecursiveLiveArchiveError("inventory schema or fields changed")
    if inventory["archive"] != {
        "bytes": archive_size,
        "format": "ustar+gzip",
        "name": archive_path.name,
        "raw_sha256": archive_digest,
    }:
        raise GitHubRecursiveLiveArchiveError("inventory archive identity changed")
    if inventory["normalization"] != {
        "gid": 0,
        "gname": "",
        "gzip_filename": "",
        "gzip_mtime": 0,
        "member_mtime": 0,
        "uid": 0,
        "uname": "",
    }:
        raise GitHubRecursiveLiveArchiveError(
            "inventory normalization metadata changed"
        )
    expected_summary = {
        "cas_blob_count": archive_facts["cas_blob_count"],
        "cas_payload_bytes": archive_facts["cas_payload_bytes"],
        "directory_count": archive_facts["directories"],
        "member_count": archive_facts["members"],
        "regular_file_count": archive_facts["regular_files"],
        "regular_payload_bytes": sum(
            member["size"] for member in members if member["kind"] == "file"
        ),
    }
    if inventory["summary"] != expected_summary or inventory["members"] != members:
        raise GitHubRecursiveLiveArchiveError(
            "inventory does not match normalized archive members"
        )


def _member_name(member: tarfile.TarInfo) -> str:
    name = (
        member.name[:-1]
        if member.isdir() and member.name.endswith("/")
        else member.name
    )
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or path.as_posix() != name
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in name
        or "\0" in name
    ):
        raise GitHubRecursiveLiveArchiveError("archive member path is unsafe")
    return name


def _pretty_document(raw: bytes, label: str) -> dict[str, Any]:
    document = _json_document(raw, label)
    expected = (
        json.dumps(
            document,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode()
    if raw != expected:
        raise GitHubRecursiveLiveArchiveError(
            f"{label} must use normalized pretty JSON"
        )
    return document


def _canonical_document(raw: bytes, label: str) -> dict[str, Any]:
    document = _json_document(raw, label)
    if canonical_json(document) != raw:
        raise GitHubRecursiveLiveArchiveError(f"{label} must use canonical JSON")
    return document


def _json_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise GitHubRecursiveLiveArchiveError(
            f"{label} is invalid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise GitHubRecursiveLiveArchiveError(f"{label} must be a JSON object")
    return document


def _cas_document(cas: CAS, digest: str, label: str) -> dict[str, Any]:
    return _canonical_document(
        cas.read(digest, max_bytes=_MAX_MEMBER_BYTES),
        label,
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _require_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise GitHubRecursiveLiveArchiveError(f"{label} is invalid")
    return value


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
