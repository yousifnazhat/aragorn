"""Credential-free worker export for recursive GitHub acquisition."""

from __future__ import annotations

import hashlib
import os
import secrets
import sys
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

from .artifact_closure import canonical_json, load_verified_retained_manifest
from .benchmark_handoff_v2 import (
    build_handoff_manifest,
    export_declared_byte_transport,
    import_declared_byte_transport,
)
from .cas import CAS
from .github_expand import acquire_github_expansion
from .github_expansion_proof import expansion_proof_closure
from .github_gateway import (
    _FIXED_LIMITS,
    _decode_canonical_line,
    _freeze_request,
    _fsync_directory,
    _quarantine_through_gateway,
    _remove_broker_staging,
    _remove_worker_job,
    _repository_url,
    _require_gateway_entries,
    _require_private_directory,
    _require_requested_source,
    _require_success_output,
    _source_closure,
)
from .github_quarantine_receipt import (
    github_gateway_profile_digest,
    retain_github_quarantine_receipt,
    verify_github_quarantine_receipt,
)
from .github_recursive_artifact_graph import retain_expanded_github_manifest

RESULT_SCHEMA = "aragorn/github-recursive-gateway-result/v1"
_MAX_RECORD_BYTES = 16 * 1024 * 1024


class GitHubRecursiveGatewayError(ValueError):
    """The recursive credential-free gateway failed closed."""


@dataclass(frozen=True, slots=True)
class RecursiveGatewayQuarantineReceipt:
    """Protected recursive bytes plus the root gateway custody identity."""

    request_digest: str
    manifest_digest: str
    root_manifest_digest: str
    source_proof_digest: str
    quarantine_receipt_digest: str
    gateway_profile_digest: str
    expansion_digest: str
    expansion_proof_digest: str | None
    handoff_manifest_digest: str
    closure_status: str
    quarantine_state: Path


def quarantine_recursive_through_gateway(
    request: object,
    *,
    gateway_root: str | os.PathLike[str],
    quarantine_state: str | os.PathLike[str],
    worker_uid: int,
    worker_gid: int,
    process_timeout_seconds: float = 130.0,
    python_executable: str | os.PathLike[str] = sys.executable,
    package_root: str | os.PathLike[str] | None = None,
) -> RecursiveGatewayQuarantineReceipt:
    """Run recursive acquisition under the existing gateway supervisor."""

    from . import github_gateway

    return _quarantine_through_gateway(
        request,
        gateway_root=gateway_root,
        quarantine_state=quarantine_state,
        worker_uid=worker_uid,
        worker_gid=worker_gid,
        process_timeout_seconds=process_timeout_seconds,
        python_executable=python_executable,
        package_root=(
            Path(github_gateway.__file__).resolve().parents[1]
            if package_root is None
            else package_root
        ),
        recursive=True,
    )


def run_recursive_worker(
    request: object,
    job_root: str | Path,
    *,
    pinned_api_addresses: list[str] | tuple[str, ...],
    pinned_git_addresses: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    """Acquire, prove, and export one recursive same-repository closure."""

    frozen = _freeze_request(request)
    root = Path(job_root)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    source_cas = CAS(root / "state")
    result = acquire_github_expansion(
        _repository_url(frozen),
        frozen["commit"],
        frozen["skill_path"],
        source_cas,
        max_api_requests=_FIXED_LIMITS["max_api_requests"],
        max_api_bytes=_FIXED_LIMITS["max_api_bytes"],
        max_retained_bytes=_FIXED_LIMITS["max_total_bytes"],
        max_expanded_objects=256,
        max_expansion_depth=4,
        max_references=10_000,
        max_source_depth=_FIXED_LIMITS["max_depth"],
        max_source_entries=_FIXED_LIMITS["max_files"],
        max_file_size=_FIXED_LIMITS["max_file_size"],
        timeout_seconds=_FIXED_LIMITS["timeout_seconds"],
        bearer_token=None,
        _pinned_addresses=pinned_api_addresses,
        _pinned_git_addresses=pinned_git_addresses,
        _retain_source_proof=True,
        _retain_expansion_proof=True,
        _retain_partial_objects=True,
    )
    root_manifest_digest = result["root_manifest_digest"]
    source_proof_digest = result.get("source_proof_digest")
    if not isinstance(source_proof_digest, str):
        raise GitHubRecursiveGatewayError(
            "recursive acquisition omitted its root source proof"
        )
    root_manifest = load_verified_retained_manifest(
        source_cas,
        root_manifest_digest,
    )
    source_closure = _source_closure(
        source_cas,
        root_manifest_digest,
        root_manifest,
        source_proof_digest,
    )
    root_handoff = build_handoff_manifest(
        kind="github_source",
        root_digest=root_manifest_digest,
        blobs=source_closure,
    )
    root_handoff_raw = canonical_json(root_handoff)
    root_handoff_digest = source_cas.put(
        BytesIO(root_handoff_raw),
        max_bytes=len(root_handoff_raw),
    )

    expansion_digest = result["expansion_digest"]
    expansion_raw = source_cas.read(
        expansion_digest,
        max_bytes=_MAX_RECORD_BYTES,
    )
    manifest_digest = retain_expanded_github_manifest(
        source_cas,
        expansion_digest,
    )
    manifest = load_verified_retained_manifest(source_cas, manifest_digest)
    manifest_raw = source_cas.read(manifest_digest, max_bytes=_MAX_RECORD_BYTES)
    closure = {
        **source_closure,
        root_handoff_digest: len(root_handoff_raw),
        expansion_digest: len(expansion_raw),
        manifest_digest: len(manifest_raw),
    }
    for entry in manifest["files"]:
        previous = closure.setdefault(entry["digest"], entry["size"])
        if previous != entry["size"]:
            raise GitHubRecursiveGatewayError(
                "recursive manifest repeats a digest with another size"
            )
    expansion_proof_digest = result.get("expansion_proof_digest")
    complete = result["closure"]["status"] == "complete"
    if complete and not isinstance(expansion_proof_digest, str):
        raise GitHubRecursiveGatewayError(
            "complete recursive acquisition omitted membership proof"
        )
    if isinstance(expansion_proof_digest, str):
        closure.update(
            expansion_proof_closure(
                source_cas,
                expansion_proof_digest,
                expected_expansion_digest=expansion_digest,
                expected_root_manifest_digest=root_manifest_digest,
            )
        )
    transport = build_handoff_manifest(
        kind="github_source",
        root_digest=manifest_digest,
        blobs=closure,
    )
    transport_digest = export_declared_byte_transport(
        source_cas,
        transport,
        root / "bundle",
    )
    recursive_result = {
        "schema": RESULT_SCHEMA,
        "request_digest": _sha256(canonical_json(frozen)),
        "manifest_digest": manifest_digest,
        "root_manifest_digest": root_manifest_digest,
        "source_proof_digest": source_proof_digest,
        "root_handoff_manifest_digest": root_handoff_digest,
        "expansion_digest": expansion_digest,
        "expansion_proof_digest": expansion_proof_digest,
        "handoff_manifest_digest": transport_digest,
        "closure_status": result["closure"]["status"],
    }
    validate_recursive_result(recursive_result)
    return recursive_result


def validate_recursive_result(value: object) -> None:
    keys = {
        "schema",
        "request_digest",
        "manifest_digest",
        "root_manifest_digest",
        "source_proof_digest",
        "root_handoff_manifest_digest",
        "expansion_digest",
        "expansion_proof_digest",
        "handoff_manifest_digest",
        "closure_status",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise GitHubRecursiveGatewayError(
            "recursive gateway result has missing or unknown fields"
        )
    if value["schema"] != RESULT_SCHEMA:
        raise GitHubRecursiveGatewayError(
            "recursive gateway result schema is unsupported"
        )
    for field in keys - {"schema", "expansion_proof_digest", "closure_status"}:
        _digest(value[field], f"recursive gateway result {field}")
    if value["closure_status"] not in {"complete", "incomplete"}:
        raise GitHubRecursiveGatewayError(
            "recursive gateway closure status is invalid"
        )
    proof = value["expansion_proof_digest"]
    if value["closure_status"] == "complete" and not isinstance(proof, str):
        raise GitHubRecursiveGatewayError(
            "recursive gateway proof does not match closure status"
        )
    if proof is not None:
        _digest(proof, "recursive gateway result expansion_proof_digest")


def require_recursive_success_result(process: object) -> dict[str, Any]:
    """Decode one bounded successful recursive worker result."""

    raw = _require_success_output(process)
    document = _decode_canonical_line(raw, "recursive gateway result")
    validate_recursive_result(document)
    return document


def accept_recursive_gateway_output(
    request: dict[str, str],
    result: dict[str, Any],
    *,
    job_root: Path,
    quarantine_state: Path,
    worker_uid: int,
    containment_profile: str,
    python_executable_digest: str,
    gateway_package_tree_digest: str,
) -> RecursiveGatewayQuarantineReceipt:
    """Import and independently replay the recursive gateway handoff."""

    validate_recursive_result(result)
    expected_request_digest = _sha256(canonical_json(request))
    if result["request_digest"] != expected_request_digest:
        raise GitHubRecursiveGatewayError(
            "recursive gateway result is bound to another request"
        )
    _require_private_directory(job_root, expected_uid=worker_uid, label="gateway job")
    bundle = job_root / "bundle"
    _require_private_directory(bundle, expected_uid=worker_uid, label="gateway bundle")
    staging = quarantine_state.parent / (
        f".{quarantine_state.name}.import-{secrets.token_hex(16)}"
    )
    if os.path.lexists(staging):
        raise GitHubRecursiveGatewayError(
            "broker quarantine staging path already exists"
        )
    published = False
    try:
        destination = CAS(staging)
        handoff = import_declared_byte_transport(
            bundle,
            destination,
            expected_manifest_digest=result["handoff_manifest_digest"],
            expected_kind="github_source",
            expected_root_digest=result["manifest_digest"],
        )
        root_manifest = load_verified_retained_manifest(
            destination,
            result["root_manifest_digest"],
        )
        _require_requested_source(root_manifest, request)
        source_closure = _source_closure(
            destination,
            result["root_manifest_digest"],
            root_manifest,
            result["source_proof_digest"],
        )
        root_handoff = build_handoff_manifest(
            kind="github_source",
            root_digest=result["root_manifest_digest"],
            blobs=source_closure,
        )
        root_handoff_raw = destination.read(
            result["root_handoff_manifest_digest"],
            max_bytes=_MAX_RECORD_BYTES,
        )
        if root_handoff_raw != canonical_json(root_handoff):
            raise GitHubRecursiveGatewayError(
                "recursive handoff root source subset changed"
            )
        expansion_raw = destination.read(
            result["expansion_digest"],
            max_bytes=_MAX_RECORD_BYTES,
        )
        if (
            retain_expanded_github_manifest(
                destination,
                result["expansion_digest"],
            )
            != result["manifest_digest"]
        ):
            raise GitHubRecursiveGatewayError(
                "recursive handoff install manifest changed"
            )
        manifest = load_verified_retained_manifest(
            destination,
            result["manifest_digest"],
        )
        manifest_raw = destination.read(
            result["manifest_digest"],
            max_bytes=_MAX_RECORD_BYTES,
        )
        expected_closure = {
            **source_closure,
            result["root_handoff_manifest_digest"]: len(root_handoff_raw),
            result["expansion_digest"]: len(expansion_raw),
            result["manifest_digest"]: len(manifest_raw),
        }
        for entry in manifest["files"]:
            previous = expected_closure.setdefault(entry["digest"], entry["size"])
            if previous != entry["size"]:
                raise GitHubRecursiveGatewayError(
                    "recursive manifest repeats a digest with another size"
                )
        proof_digest = result["expansion_proof_digest"]
        if proof_digest is not None:
            expected_closure.update(
                expansion_proof_closure(
                    destination,
                    proof_digest,
                    expected_expansion_digest=result["expansion_digest"],
                    expected_root_manifest_digest=result["root_manifest_digest"],
                )
            )
        actual_closure = {
            entry["digest"]: entry["size"] for entry in handoff["blobs"]
        }
        if actual_closure != expected_closure:
            raise GitHubRecursiveGatewayError(
                "recursive handoff contains bytes outside its verified closure"
            )
        handoff_raw = canonical_json(handoff)
        destination.put_expected(
            BytesIO(handoff_raw),
            expected_digest=result["handoff_manifest_digest"],
            max_bytes=len(handoff_raw),
        )
        _remove_worker_job(job_root, expected_uid=worker_uid)
        _require_gateway_entries(
            job_root.parent,
            (),
            worker_uid=worker_uid,
            stage="before recursive quarantine publication",
        )
        gateway_profile_digest = github_gateway_profile_digest(
            containment_profile=containment_profile,
            gateway_package_tree_digest=gateway_package_tree_digest,
            python_executable_digest=python_executable_digest,
        )
        receipt_digest = retain_github_quarantine_receipt(
            destination,
            request=request,
            manifest_digest=result["root_manifest_digest"],
            source_proof_digest=result["source_proof_digest"],
            handoff_manifest_digest=result["root_handoff_manifest_digest"],
            containment_profile=containment_profile,
            gateway_package_tree_digest=gateway_package_tree_digest,
            python_executable_digest=python_executable_digest,
        )
        receipt = RecursiveGatewayQuarantineReceipt(
            request_digest=expected_request_digest,
            manifest_digest=result["manifest_digest"],
            root_manifest_digest=result["root_manifest_digest"],
            source_proof_digest=result["source_proof_digest"],
            quarantine_receipt_digest=receipt_digest,
            gateway_profile_digest=gateway_profile_digest,
            expansion_digest=result["expansion_digest"],
            expansion_proof_digest=proof_digest,
            handoff_manifest_digest=result["handoff_manifest_digest"],
            closure_status=result["closure_status"],
            quarantine_state=quarantine_state,
        )
        if os.path.lexists(quarantine_state):
            raise GitHubRecursiveGatewayError(
                "broker quarantine is no longer a fresh path"
            )
        os.rename(staging, quarantine_state)
        try:
            _fsync_directory(quarantine_state.parent)
            verify_github_quarantine_receipt(
                CAS(quarantine_state, read_only=True),
                receipt_digest,
                expected_manifest_digest=result["root_manifest_digest"],
                expected_gateway_profile_digest=gateway_profile_digest,
            )
        except (OSError, ValueError):
            _remove_broker_staging(quarantine_state)
            raise
        published = True
        return receipt
    except GitHubRecursiveGatewayError:
        raise
    except (OSError, ValueError) as exc:
        raise GitHubRecursiveGatewayError(
            f"cannot publish recursive broker quarantine: {exc}"
        ) from exc
    finally:
        if not published:
            _remove_broker_staging(staging)


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise GitHubRecursiveGatewayError(f"{label} is invalid")
    return value


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
