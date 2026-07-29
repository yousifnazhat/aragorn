"""Credential-free worker export for recursive GitHub acquisition."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import time
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
from .cas import CAS, CASError
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
from .github_recursive_artifact_graph import (
    retain_expanded_github_manifest,
)
from .github_recursive_artifact_graph_v4 import (
    discover_recursive_github_release_asset_urls,
)
from .github_release_asset import (
    acquire_github_release_asset,
    parse_github_release_asset_url,
    verify_github_release_asset_result,
)

RESULT_SCHEMA_V1 = "aragorn/github-recursive-gateway-result/v1"
RESULT_SCHEMA = "aragorn/github-recursive-gateway-result/v2"
_MAX_RECORD_BYTES = 16 * 1024 * 1024
_MAX_RELEASE_ASSETS = 16
_MAX_RELEASE_ASSET_BYTES = 64 * 1024 * 1024
_RELEASE_ASSET_PIN_FIELDS = {
    "release_id",
    "asset_id",
    "digest",
    "github_digest",
    "content_type",
    "redirected",
}


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
    release_asset_result_digests: tuple[str, ...]
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
    release_asset_pins: object | None = None,
) -> RecursiveGatewayQuarantineReceipt:
    """Run recursive acquisition with optional broker-held release pins.

    Automatic pin derivation is intentionally unsupported. A release-bearing
    result cannot enter broker quarantine unless the caller supplied exact pins
    before the worker was launched. Pins are keyed by canonical URL and contain
    ``release_id``, ``asset_id``, ``digest``, ``github_digest``,
    ``content_type``, and ``redirected``.
    """

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
        broker_release_asset_pins=release_asset_pins,
    )


def run_recursive_worker(
    request: object,
    job_root: str | Path,
    *,
    pinned_api_addresses: list[str] | tuple[str, ...],
    pinned_git_addresses: list[str] | tuple[str, ...],
    pinned_release_asset_addresses: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """Acquire, prove, and export one recursive same-repository closure."""

    frozen = _freeze_request(request)
    deadline = time.monotonic() + float(_FIXED_LIMITS["timeout_seconds"])
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
        timeout_seconds=_remaining_recursive_seconds(deadline),
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
    release_asset_entries: list[dict[str, str]] = []
    release_asset_bytes = 0
    release_asset_urls = discover_recursive_github_release_asset_urls(
        source_cas,
        expansion_digest,
    )
    if len(release_asset_urls) > _MAX_RELEASE_ASSETS:
        raise GitHubRecursiveGatewayError(
            "recursive release asset count exceeds its bound"
        )
    for url in release_asset_urls:
        remaining_asset_bytes = _MAX_RELEASE_ASSET_BYTES - release_asset_bytes
        acquired_asset = acquire_github_release_asset(
            url,
            source_cas,
            timeout_seconds=_remaining_recursive_seconds(deadline),
            max_asset_bytes=min(_MAX_RECORD_BYTES, remaining_asset_bytes),
            _pinned_api_addresses=pinned_api_addresses,
            _pinned_asset_addresses=pinned_release_asset_addresses,
        )
        asset_size = acquired_asset["asset"]["size"]
        release_asset_bytes += asset_size
        if release_asset_bytes > _MAX_RELEASE_ASSET_BYTES:
            raise GitHubRecursiveGatewayError(
                "recursive release asset bytes exceed their bound"
            )
        result_raw = canonical_json(acquired_asset)
        result_digest = source_cas.put(
            BytesIO(result_raw),
            max_bytes=len(result_raw),
        )
        release_asset_entries.append({"url": url, "result_digest": result_digest})
        for digest, size in (
            (result_digest, len(result_raw)),
            (acquired_asset["asset"]["digest"], asset_size),
        ):
            previous = closure.setdefault(digest, size)
            if previous != size:
                raise GitHubRecursiveGatewayError(
                    "recursive release closure repeats a digest with another size"
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
    recursive_result: dict[str, Any] = {
        "schema": RESULT_SCHEMA if release_asset_entries else RESULT_SCHEMA_V1,
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
    if release_asset_entries:
        recursive_result["release_assets"] = release_asset_entries
    validate_recursive_result(recursive_result)
    return recursive_result


def validate_recursive_result(value: object) -> None:
    base_keys = {
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
    if not isinstance(value, dict):
        raise GitHubRecursiveGatewayError(
            "recursive gateway result has missing or unknown fields"
        )
    schema = value.get("schema")
    expected_keys = (
        base_keys
        if schema == RESULT_SCHEMA_V1
        else base_keys | {"release_assets"}
        if schema == RESULT_SCHEMA
        else None
    )
    if expected_keys is None:
        raise GitHubRecursiveGatewayError(
            "recursive gateway result schema is unsupported"
        )
    if set(value) != expected_keys:
        raise GitHubRecursiveGatewayError(
            "recursive gateway result has missing or unknown fields"
        )
    for field in base_keys - {"schema", "expansion_proof_digest", "closure_status"}:
        _digest(value[field], f"recursive gateway result {field}")
    if value["closure_status"] not in {"complete", "incomplete"}:
        raise GitHubRecursiveGatewayError("recursive gateway closure status is invalid")
    proof = value["expansion_proof_digest"]
    if value["closure_status"] == "complete" and not isinstance(proof, str):
        raise GitHubRecursiveGatewayError(
            "recursive gateway proof does not match closure status"
        )
    if proof is not None:
        _digest(proof, "recursive gateway result expansion_proof_digest")
    _release_asset_entries(value)


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
    release_asset_pins: object | None = None,
) -> RecursiveGatewayQuarantineReceipt:
    """Import and independently replay the recursive gateway handoff."""

    validate_recursive_result(result)
    frozen_release_asset_pins = _freeze_release_asset_pins(release_asset_pins)
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
        release_asset_entries = _release_asset_entries(result)
        discovered_release_assets = (
            discover_recursive_github_release_asset_urls(
                destination,
                result["expansion_digest"],
            )
            if result["schema"] == RESULT_SCHEMA
            else ()
        )
        release_asset_closure = _verify_release_assets(
            destination,
            release_asset_entries,
            discovered_release_assets,
            release_asset_pins=frozen_release_asset_pins,
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
        for digest, size in release_asset_closure.items():
            previous = expected_closure.setdefault(digest, size)
            if previous != size:
                raise GitHubRecursiveGatewayError(
                    "recursive release closure repeats a digest with another size"
                )
        actual_closure = {entry["digest"]: entry["size"] for entry in handoff["blobs"]}
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
            release_asset_result_digests=tuple(
                entry["result_digest"] for entry in release_asset_entries
            ),
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


def _release_asset_entries(
    result: dict[str, Any],
) -> tuple[dict[str, str], ...]:
    if result.get("schema") == RESULT_SCHEMA_V1:
        return ()
    value = result.get("release_assets")
    if not isinstance(value, list) or not value or len(value) > _MAX_RELEASE_ASSETS:
        raise GitHubRecursiveGatewayError(
            "recursive gateway release assets are invalid"
        )
    entries: list[dict[str, str]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"url", "result_digest"}
            or not isinstance(item.get("url"), str)
        ):
            raise GitHubRecursiveGatewayError(
                "recursive gateway release asset entry is invalid"
            )
        try:
            parse_github_release_asset_url(item["url"])
        except ValueError:
            raise GitHubRecursiveGatewayError(
                "recursive gateway release asset URL is invalid"
            ) from None
        entries.append(
            {
                "url": item["url"],
                "result_digest": _digest(
                    item.get("result_digest"),
                    "recursive release asset result digest",
                ),
            }
        )
    urls = [entry["url"] for entry in entries]
    digests = [entry["result_digest"] for entry in entries]
    if urls != sorted(set(urls)) or len(digests) != len(set(digests)):
        raise GitHubRecursiveGatewayError(
            "recursive gateway release assets are not unique and ordered"
        )
    return tuple(entries)


def _verify_release_assets(
    cas: CAS,
    entries: tuple[dict[str, str], ...],
    discovered_urls: tuple[str, ...],
    *,
    release_asset_pins: object | None = None,
) -> dict[str, int]:
    if tuple(entry["url"] for entry in entries) != discovered_urls:
        raise GitHubRecursiveGatewayError(
            "recursive gateway release assets do not match retained source"
        )
    pins = _freeze_release_asset_pins(release_asset_pins)
    if set(pins) != set(discovered_urls):
        raise GitHubRecursiveGatewayError(
            "recursive gateway release assets lack exact broker-held pins"
        )
    closure: dict[str, int] = {}
    retained_bytes = 0
    evidence_cas = CAS(cas.root, read_only=True)
    for entry in entries:
        try:
            raw = cas.read(entry["result_digest"], max_bytes=_MAX_RECORD_BYTES)
            document = json.loads(raw)
            if (
                not isinstance(document, dict)
                or canonical_json(document) != raw
                or not isinstance(document.get("asset"), dict)
                or not isinstance(document.get("transport"), dict)
            ):
                raise ValueError("release asset result is not canonical")
            pin = pins[entry["url"]]
            verified = verify_github_release_asset_result(
                document,
                evidence_cas=evidence_cas,
                expected_url=entry["url"],
                expected_release_id=pin["release_id"],
                expected_asset_id=pin["asset_id"],
                expected_digest=pin["digest"],
                expected_github_digest=pin["github_digest"],
                expected_content_type=pin["content_type"],
                expected_redirected=pin["redirected"],
            )
        except (
            CASError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            TypeError,
            ValueError,
        ) as exc:
            raise GitHubRecursiveGatewayError(
                "recursive gateway release asset verification failed"
            ) from exc
        asset_size = verified["asset"]["size"]
        retained_bytes += asset_size
        if retained_bytes > _MAX_RELEASE_ASSET_BYTES:
            raise GitHubRecursiveGatewayError(
                "recursive release asset bytes exceed their bound"
            )
        for digest, size in (
            (entry["result_digest"], len(raw)),
            (verified["asset"]["digest"], asset_size),
        ):
            previous = closure.setdefault(digest, size)
            if previous != size:
                raise GitHubRecursiveGatewayError(
                    "recursive release closure repeats a digest with another size"
                )
    return closure


def _freeze_release_asset_pins(value: object | None) -> dict[str, dict[str, Any]]:
    """Freeze caller-held release identities before untrusted worker execution."""

    try:
        frozen = json.loads(canonical_json({} if value is None else value))
    except (TypeError, ValueError, RecursionError) as exc:
        raise GitHubRecursiveGatewayError(
            "broker-held release asset pins are invalid"
        ) from exc
    if not isinstance(frozen, dict) or len(frozen) > _MAX_RELEASE_ASSETS:
        raise GitHubRecursiveGatewayError("broker-held release asset pins are invalid")
    pins: dict[str, dict[str, Any]] = {}
    for url, pin in frozen.items():
        if not isinstance(url, str) or not isinstance(pin, dict):
            raise GitHubRecursiveGatewayError(
                "broker-held release asset pin is invalid"
            )
        try:
            parse_github_release_asset_url(url)
        except ValueError:
            raise GitHubRecursiveGatewayError(
                "broker-held release asset pin URL is invalid"
            ) from None
        if set(pin) != _RELEASE_ASSET_PIN_FIELDS:
            raise GitHubRecursiveGatewayError(
                "broker-held release asset pin is invalid"
            )
        release_id = pin.get("release_id")
        asset_id = pin.get("asset_id")
        digest = _digest(pin.get("digest"), "broker-held release asset digest")
        github_digest = pin.get("github_digest")
        content_type = pin.get("content_type")
        redirected = pin.get("redirected")
        if (
            isinstance(release_id, bool)
            or not isinstance(release_id, int)
            or release_id <= 0
            or isinstance(asset_id, bool)
            or not isinstance(asset_id, int)
            or asset_id <= 0
            or (
                github_digest is not None
                and (
                    _digest(
                        github_digest,
                        "broker-held GitHub release asset digest",
                    )
                    != digest
                )
            )
            or not isinstance(content_type, str)
            or not content_type
            or len(content_type) > 255
            or any(
                ord(character) < 0x20 or ord(character) > 0x7E
                for character in content_type
            )
            or type(redirected) is not bool
        ):
            raise GitHubRecursiveGatewayError(
                "broker-held release asset pin is invalid"
            )
        pins[url] = {
            "release_id": release_id,
            "asset_id": asset_id,
            "digest": digest,
            "github_digest": github_digest,
            "content_type": content_type,
            "redirected": redirected,
        }
    return pins


def _remaining_recursive_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise GitHubRecursiveGatewayError(
            "recursive gateway acquisition deadline exceeded"
        )
    return remaining


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
