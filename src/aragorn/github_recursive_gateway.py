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
    HandoffError,
    build_handoff_manifest,
    export_declared_byte_transport,
    import_declared_byte_transport,
    validate_handoff_manifest,
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
from .github_release_asset import SCHEMA as RELEASE_ASSET_SCHEMA
from .github_release_asset import ZIP_SCHEMA as RELEASE_ASSET_ZIP_SCHEMA
from .github_release_asset import (
    acquire_github_release_asset,
    parse_github_release_asset_url,
    resolve_github_release_asset_pin,
    verify_github_release_asset_result,
)
from .zip_inventory import (
    MAX_ENTRIES,
    MAX_EXPANDED_BYTES,
    MAX_INVENTORY_BYTES,
    ZipInventoryError,
    verify_zip_inventory,
)

RESULT_SCHEMA_V1 = "aragorn/github-recursive-gateway-result/v1"
RESULT_SCHEMA = "aragorn/github-recursive-gateway-result/v2"
PIN_PREFLIGHT_SCHEMA = "aragorn/github-recursive-release-pin-preflight/v1"
PIN_SET_SCHEMA = "aragorn/github-release-asset-pin-set/v1"
PIN_PREFLIGHT_AUTHORITY = "PIN_EVIDENCE_ONLY_NOT_ADMISSION_AUTHORITY"
PIN_PREFLIGHT_ASSURANCE = "GITHUB_API_DIGEST_PREFLIGHT_NOT_PUBLISHER_SIGNATURE"
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
    release_pin_set_digest: str | None = None


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
    """Run recursive acquisition with broker-held or independently preflighted pins.

    ``None`` selects an evidence-only preflight worker before the distinct byte
    worker. An explicit mapping, including ``{}``, keeps the single-worker path.
    Pins are keyed by canonical URL and contain ``release_id``, ``asset_id``,
    ``digest``, ``github_digest``, ``content_type``, and ``redirected``.
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

    return _run_recursive_worker(
        request,
        job_root,
        pinned_api_addresses=pinned_api_addresses,
        pinned_git_addresses=pinned_git_addresses,
        pinned_release_asset_addresses=pinned_release_asset_addresses,
        pin_preflight=False,
    )


def run_recursive_pin_preflight_worker(
    request: object,
    job_root: str | Path,
    *,
    pinned_api_addresses: list[str] | tuple[str, ...],
    pinned_git_addresses: list[str] | tuple[str, ...],
    pinned_release_asset_addresses: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """Resolve release pins while exporting only recursive source proof."""

    return _run_recursive_worker(
        request,
        job_root,
        pinned_api_addresses=pinned_api_addresses,
        pinned_git_addresses=pinned_git_addresses,
        pinned_release_asset_addresses=pinned_release_asset_addresses,
        pin_preflight=True,
    )


def _run_recursive_worker(
    request: object,
    job_root: str | Path,
    *,
    pinned_api_addresses: list[str] | tuple[str, ...],
    pinned_git_addresses: list[str] | tuple[str, ...],
    pinned_release_asset_addresses: list[str] | tuple[str, ...],
    pin_preflight: bool,
) -> dict[str, Any]:
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
    release_asset_pins: dict[str, dict[str, Any]] = {}
    release_asset_bytes = 0
    release_archive_expanded_bytes = 0
    release_archive_entries = 0
    release_archive_member_digests: set[str] = set()
    release_asset_urls = discover_recursive_github_release_asset_urls(
        source_cas,
        expansion_digest,
    )
    if len(release_asset_urls) > _MAX_RELEASE_ASSETS or release_asset_urls != tuple(
        sorted(set(release_asset_urls))
    ):
        raise GitHubRecursiveGatewayError(
            "recursive release asset URLs are not bounded, unique, and ordered"
        )
    for url in release_asset_urls:
        if pin_preflight:
            release_asset_pins[url] = resolve_github_release_asset_pin(
                url,
                timeout_seconds=_remaining_recursive_seconds(deadline),
                max_asset_bytes=_MAX_RECORD_BYTES,
                _pinned_api_addresses=pinned_api_addresses,
                _pinned_asset_addresses=pinned_release_asset_addresses,
            )
            continue
        remaining_asset_bytes = _MAX_RELEASE_ASSET_BYTES - release_asset_bytes
        acquired_asset = acquire_github_release_asset(
            url,
            source_cas,
            timeout_seconds=_remaining_recursive_seconds(deadline),
            max_asset_bytes=min(_MAX_RECORD_BYTES, remaining_asset_bytes),
            _pinned_api_addresses=pinned_api_addresses,
            _pinned_asset_addresses=pinned_release_asset_addresses,
            _max_zip_expanded_bytes=(
                MAX_EXPANDED_BYTES - release_archive_expanded_bytes
            ),
            _max_zip_entries=MAX_ENTRIES - release_archive_entries,
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
        release_archive_expanded_bytes, release_archive_entries = (
            _extend_release_asset_inventory_closure(
                closure,
                source_cas,
                acquired_asset,
                expanded_bytes=release_archive_expanded_bytes,
                entry_count=release_archive_entries,
                member_digests=release_archive_member_digests,
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
    recursive_result: dict[str, Any] = {
        "schema": (
            PIN_PREFLIGHT_SCHEMA
            if pin_preflight
            else RESULT_SCHEMA
            if release_asset_entries
            else RESULT_SCHEMA_V1
        ),
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
    if pin_preflight:
        recursive_result.update(
            {
                "authority": PIN_PREFLIGHT_AUTHORITY,
                "assurance": PIN_PREFLIGHT_ASSURANCE,
                "release_asset_pins": release_asset_pins,
            }
        )
        validate_recursive_pin_preflight_result(recursive_result)
    else:
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


def validate_recursive_pin_preflight_result(value: object) -> None:
    """Validate one source-bound, evidence-only automatic pin proposal."""

    expected = {
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
        "authority",
        "assurance",
        "release_asset_pins",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema") != PIN_PREFLIGHT_SCHEMA
        or value.get("authority") != PIN_PREFLIGHT_AUTHORITY
        or value.get("assurance") != PIN_PREFLIGHT_ASSURANCE
    ):
        raise GitHubRecursiveGatewayError(
            "recursive release-pin preflight result is invalid"
        )
    source_result = {
        key: item
        for key, item in value.items()
        if key not in {"authority", "assurance", "release_asset_pins"}
    }
    source_result["schema"] = RESULT_SCHEMA_V1
    validate_recursive_result(source_result)
    raw_pins = value["release_asset_pins"]
    pins = _freeze_release_asset_pins(raw_pins)
    if (
        not isinstance(raw_pins, dict)
        or list(raw_pins) != sorted(raw_pins)
        or raw_pins != pins
        or any(pin["github_digest"] != pin["digest"] for pin in pins.values())
    ):
        raise GitHubRecursiveGatewayError(
            "recursive release-pin preflight pins are invalid"
        )


def _validate_release_pin_set(value: object) -> dict[str, Any]:
    expected = {
        "schema",
        "authority",
        "assurance",
        "request_digest",
        "manifest_digest",
        "root_manifest_digest",
        "source_proof_digest",
        "expansion_digest",
        "expansion_proof_digest",
        "handoff_manifest_digest",
        "release_asset_pins",
        "closure",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema") != PIN_SET_SCHEMA
        or value.get("authority") != PIN_PREFLIGHT_AUTHORITY
        or value.get("assurance") != PIN_PREFLIGHT_ASSURANCE
        or value.get("closure")
        != {"scope": "github_release_asset_pins", "status": "complete"}
    ):
        raise GitHubRecursiveGatewayError(
            "recursive release pin set is invalid"
        )
    for field in (
        "request_digest",
        "manifest_digest",
        "root_manifest_digest",
        "source_proof_digest",
        "expansion_digest",
        "handoff_manifest_digest",
    ):
        _digest(value[field], f"recursive release pin set {field}")
    expansion_proof_digest = value["expansion_proof_digest"]
    if expansion_proof_digest is not None:
        _digest(
            expansion_proof_digest,
            "recursive release pin set expansion_proof_digest",
        )
    pins = _freeze_release_asset_pins(value["release_asset_pins"])
    if (
        value["release_asset_pins"] != pins
        or list(value["release_asset_pins"]) != sorted(value["release_asset_pins"])
        or any(pin["github_digest"] != pin["digest"] for pin in pins.values())
    ):
        raise GitHubRecursiveGatewayError(
            "recursive release pin set pins are invalid"
        )
    frozen = dict(value)
    frozen["release_asset_pins"] = pins
    return frozen


def verify_retained_release_pin_set(
    cas: CAS,
    pin_set_digest: str,
    *,
    expected_request: dict[str, str],
    expected_manifest_digest: str,
    expected_source_proof_digest: str,
    expected_recursive: dict[str, Any],
) -> dict[str, Any]:
    """Replay one retained independent pin set against its exact CAS closure."""

    try:
        if not cas.read_only:
            raise GitHubRecursiveGatewayError(
                "release pin-set replay requires a read-only CAS"
            )
        digest = _digest(pin_set_digest, "release pin-set digest")
        raw = cas.read(digest, max_bytes=_MAX_RECORD_BYTES)
        document = json.loads(raw)
        if canonical_json(document) != raw:
            raise GitHubRecursiveGatewayError(
                "retained recursive release pin set is not canonical"
            )
        pin_set = _validate_release_pin_set(document)
        recursive_fields = {
            "root_manifest_digest",
            "expansion_digest",
            "expansion_proof_digest",
            "release_asset_result_digests",
            "release_pin_set_digest",
        }
        if (
            not isinstance(expected_recursive, dict)
            or set(expected_recursive) != recursive_fields
            or expected_recursive["release_pin_set_digest"] != digest
        ):
            raise GitHubRecursiveGatewayError(
                "recursive release pin-set identity is invalid"
            )
        request_digest = _sha256(canonical_json(expected_request))
        manifest_digest = _digest(
            expected_manifest_digest,
            "expected release pin-set manifest digest",
        )
        source_proof_digest = _digest(
            expected_source_proof_digest,
            "expected release pin-set source proof digest",
        )
        root_manifest_digest = _digest(
            expected_recursive["root_manifest_digest"],
            "expected release pin-set root manifest digest",
        )
        expansion_digest = _digest(
            expected_recursive["expansion_digest"],
            "expected release pin-set expansion digest",
        )
        expansion_proof_digest = expected_recursive["expansion_proof_digest"]
        if expansion_proof_digest is not None:
            expansion_proof_digest = _digest(
                expansion_proof_digest,
                "expected release pin-set expansion proof digest",
            )
        if (
            pin_set["request_digest"] != request_digest
            or pin_set["manifest_digest"] != manifest_digest
            or pin_set["root_manifest_digest"] != root_manifest_digest
            or pin_set["source_proof_digest"] != source_proof_digest
            or pin_set["expansion_digest"] != expansion_digest
            or pin_set["expansion_proof_digest"] != expansion_proof_digest
        ):
            raise GitHubRecursiveGatewayError(
                "retained recursive release pin set changed its source identity"
            )

        handoff_raw = cas.read(
            pin_set["handoff_manifest_digest"],
            max_bytes=_MAX_RECORD_BYTES,
        )
        handoff = json.loads(handoff_raw)
        if canonical_json(handoff) != handoff_raw:
            raise GitHubRecursiveGatewayError(
                "retained release pin-set handoff is not canonical"
            )
        validate_handoff_manifest(handoff)
        if (
            handoff["kind"] != "github_source"
            or handoff["root_digest"] != manifest_digest
        ):
            raise GitHubRecursiveGatewayError(
                "retained release pin-set handoff changed"
            )
        for blob in handoff["blobs"]:
            cas.verify(blob["digest"], max_bytes=blob["size"])

        release_digests = expected_recursive["release_asset_result_digests"]
        if (
            not isinstance(release_digests, list)
            or len(release_digests) > _MAX_RELEASE_ASSETS
            or release_digests != sorted(set(release_digests))
        ):
            raise GitHubRecursiveGatewayError(
                "recursive release pin-set result digests are invalid"
            )
        entries: list[dict[str, str]] = []
        for result_digest in release_digests:
            result_digest = _digest(
                result_digest,
                "recursive release pin-set result digest",
            )
            result_raw = cas.read(result_digest, max_bytes=_MAX_RECORD_BYTES)
            result = json.loads(result_raw)
            source = result.get("source") if isinstance(result, dict) else None
            url = source.get("url") if isinstance(source, dict) else None
            if (
                canonical_json(result) != result_raw
                or not isinstance(url, str)
            ):
                raise GitHubRecursiveGatewayError(
                    "retained release pin-set result is invalid"
                )
            entries.append({"url": url, "result_digest": result_digest})
        entries.sort(key=lambda entry: entry["url"])
        if len({entry["url"] for entry in entries}) != len(entries):
            raise GitHubRecursiveGatewayError(
                "retained release pin-set results repeat a URL"
            )
        discovered_urls = discover_recursive_github_release_asset_urls(
            cas,
            expansion_digest,
        )
        _verify_release_assets(
            cas,
            tuple(entries),
            discovered_urls,
            release_asset_pins=pin_set["release_asset_pins"],
        )
        return pin_set
    except GitHubRecursiveGatewayError:
        raise
    except (
        CASError,
        HandoffError,
        OSError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        raise GitHubRecursiveGatewayError(
            f"cannot verify retained recursive release pin set: {exc}"
        ) from exc


def _require_release_pin_set_matches(
    pin_set: dict[str, Any],
    *,
    request_digest: str,
    result: dict[str, Any],
    release_asset_pins: dict[str, dict[str, Any]],
) -> None:
    source_fields = (
        "manifest_digest",
        "root_manifest_digest",
        "source_proof_digest",
        "expansion_digest",
        "expansion_proof_digest",
    )
    if (
        pin_set["request_digest"] != request_digest
        or any(pin_set[field] != result[field] for field in source_fields)
        or pin_set["release_asset_pins"] != release_asset_pins
    ):
        raise GitHubRecursiveGatewayError(
            "recursive byte worker source identity changed after release-pin preflight"
        )


def require_recursive_success_result(process: object) -> dict[str, Any]:
    """Decode one bounded successful recursive worker result."""

    raw = _require_success_output(process)
    document = _decode_canonical_line(raw, "recursive gateway result")
    validate_recursive_result(document)
    return document


def require_recursive_pin_preflight_success_result(
    process: object,
) -> dict[str, Any]:
    """Decode one bounded successful recursive pin-preflight result."""

    raw = _require_success_output(process)
    document = _decode_canonical_line(raw, "recursive release-pin preflight result")
    validate_recursive_pin_preflight_result(document)
    return document


def verify_recursive_pin_preflight_output(
    request: dict[str, str],
    result: dict[str, Any],
    *,
    job_root: Path,
    broker_state: Path,
    worker_uid: int,
) -> tuple[str, dict[str, Any]]:
    """Replay pins into a fresh CAS without removing the job or publishing."""

    validate_recursive_pin_preflight_result(result)
    expected_request_digest = _sha256(canonical_json(request))
    if result["request_digest"] != expected_request_digest:
        raise GitHubRecursiveGatewayError(
            "recursive release-pin preflight is bound to another request"
        )
    _require_private_directory(job_root, expected_uid=worker_uid, label="gateway job")
    bundle = job_root / "bundle"
    _require_private_directory(bundle, expected_uid=worker_uid, label="gateway bundle")
    parent = _require_private_directory(
        broker_state.parent,
        expected_uid=os.geteuid(),
        label="release-pin preflight parent",
    )
    if (
        not broker_state.is_absolute()
        or parent / broker_state.name != broker_state
        or os.path.lexists(broker_state)
    ):
        raise GitHubRecursiveGatewayError(
            "release-pin preflight broker CAS is not a fresh canonical path"
        )
    retained = False
    try:
        destination = CAS(broker_state)
        handoff, expected_closure, _proof_digest = _import_and_replay_recursive_source(
            request,
            result,
            bundle,
            destination,
        )
        _retain_exact_recursive_handoff(
            destination,
            result,
            handoff,
            expected_closure,
        )
        pins = _freeze_release_asset_pins(result["release_asset_pins"])
        discovered_urls = discover_recursive_github_release_asset_urls(
            destination,
            result["expansion_digest"],
        )
        if tuple(pins) != discovered_urls:
            raise GitHubRecursiveGatewayError(
                "recursive release-pin preflight URLs changed during replay"
            )
        pin_set = {
            "schema": PIN_SET_SCHEMA,
            "authority": PIN_PREFLIGHT_AUTHORITY,
            "assurance": PIN_PREFLIGHT_ASSURANCE,
            "request_digest": expected_request_digest,
            "manifest_digest": result["manifest_digest"],
            "root_manifest_digest": result["root_manifest_digest"],
            "source_proof_digest": result["source_proof_digest"],
            "expansion_digest": result["expansion_digest"],
            "expansion_proof_digest": result["expansion_proof_digest"],
            "handoff_manifest_digest": result["handoff_manifest_digest"],
            "release_asset_pins": pins,
            "closure": {
                "scope": "github_release_asset_pins",
                "status": "complete",
            },
        }
        pin_set_raw = canonical_json(pin_set)
        pin_set_digest = destination.put(
            BytesIO(pin_set_raw),
            max_bytes=len(pin_set_raw),
        )
        retained = True
        return pin_set_digest, pin_set
    except GitHubRecursiveGatewayError:
        raise
    except (CASError, OSError, ValueError) as exc:
        raise GitHubRecursiveGatewayError(
            f"cannot verify recursive release-pin preflight: {exc}"
        ) from exc
    finally:
        if not retained:
            _remove_broker_staging(broker_state)


def _import_and_replay_recursive_source(
    request: dict[str, str],
    result: dict[str, Any],
    bundle: Path,
    destination: CAS,
) -> tuple[dict[str, Any], dict[str, int], str | None]:
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
    expansion = json.loads(expansion_raw)
    if (
        canonical_json(expansion) != expansion_raw
        or not isinstance(expansion, dict)
        or not isinstance(expansion.get("closure"), dict)
        or expansion["closure"].get("status") != result["closure_status"]
    ):
        raise GitHubRecursiveGatewayError(
            "recursive handoff closure status changed"
        )
    if (
        retain_expanded_github_manifest(
            destination,
            result["expansion_digest"],
        )
        != result["manifest_digest"]
    ):
        raise GitHubRecursiveGatewayError("recursive handoff install manifest changed")
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
    return handoff, expected_closure, proof_digest


def _retain_exact_recursive_handoff(
    destination: CAS,
    result: dict[str, Any],
    handoff: dict[str, Any],
    expected_closure: dict[str, int],
) -> None:
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
    release_pin_set_digest: str | None = None,
    release_pin_set: object | None = None,
    broker_staging_state: Path | None = None,
) -> RecursiveGatewayQuarantineReceipt:
    """Import and independently replay the recursive gateway handoff."""

    validate_recursive_result(result)
    frozen_release_asset_pins = _freeze_release_asset_pins(release_asset_pins)
    expected_request_digest = _sha256(canonical_json(request))
    if result["request_digest"] != expected_request_digest:
        raise GitHubRecursiveGatewayError(
            "recursive gateway result is bound to another request"
        )
    preflight_values = (
        release_pin_set_digest,
        release_pin_set,
        broker_staging_state,
    )
    using_preflight = any(value is not None for value in preflight_values)
    if using_preflight != all(value is not None for value in preflight_values):
        raise GitHubRecursiveGatewayError(
            "recursive release-pin preflight inputs are incomplete"
        )
    frozen_pin_set: dict[str, Any] | None = None
    frozen_pin_set_digest: str | None = None
    if using_preflight:
        frozen_pin_set = _validate_release_pin_set(release_pin_set)
        frozen_pin_set_digest = _digest(
            release_pin_set_digest,
            "release pin-set digest",
        )
        _require_release_pin_set_matches(
            frozen_pin_set,
            request_digest=expected_request_digest,
            result=result,
            release_asset_pins=frozen_release_asset_pins,
        )
    _require_private_directory(job_root, expected_uid=worker_uid, label="gateway job")
    bundle = job_root / "bundle"
    _require_private_directory(bundle, expected_uid=worker_uid, label="gateway bundle")
    staging = (
        broker_staging_state
        if using_preflight
        else quarantine_state.parent
        / f".{quarantine_state.name}.import-{secrets.token_hex(16)}"
    )
    if not isinstance(staging, Path):
        raise GitHubRecursiveGatewayError(
            "recursive release-pin preflight staging path is invalid"
        )
    if using_preflight:
        parent = _require_private_directory(
            staging.parent,
            expected_uid=os.geteuid(),
            label="release-pin preflight parent",
        )
        prefix = f".{quarantine_state.name}.pin-preflight-"
        suffix = staging.name.removeprefix(prefix)
        if (
            not staging.is_absolute()
            or parent != quarantine_state.parent
            or parent / staging.name != staging
            or not staging.name.startswith(prefix)
            or len(suffix) != 32
            or any(character not in "0123456789abcdef" for character in suffix)
        ):
            raise GitHubRecursiveGatewayError(
                "recursive release-pin preflight staging path is invalid"
            )
        _require_private_directory(
            staging,
            expected_uid=os.geteuid(),
            label="release-pin preflight state",
        )
    elif os.path.lexists(staging):
        raise GitHubRecursiveGatewayError(
            "broker quarantine staging path already exists"
        )
    published = False
    try:
        destination = CAS(staging)
        if frozen_pin_set is not None and (
            destination.read(
                frozen_pin_set_digest,
                max_bytes=_MAX_RECORD_BYTES,
            )
            != canonical_json(frozen_pin_set)
        ):
            raise GitHubRecursiveGatewayError(
                "retained recursive release pin set changed"
            )
        handoff, expected_closure, proof_digest = _import_and_replay_recursive_source(
            request,
            result,
            bundle,
            destination,
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
        for digest, size in release_asset_closure.items():
            previous = expected_closure.setdefault(digest, size)
            if previous != size:
                raise GitHubRecursiveGatewayError(
                    "recursive release closure repeats a digest with another size"
                )
        _retain_exact_recursive_handoff(
            destination,
            result,
            handoff,
            expected_closure,
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
            release_pin_set_digest=frozen_pin_set_digest,
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
        except (CASError, OSError, ValueError):
            _remove_broker_staging(quarantine_state)
            raise
        published = True
        return receipt
    except GitHubRecursiveGatewayError:
        raise
    except (CASError, OSError, ValueError) as exc:
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
    release_archive_expanded_bytes = 0
    release_archive_entries = 0
    release_archive_member_digests: set[str] = set()
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
                require_zip_inventory=True,
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
        release_archive_expanded_bytes, release_archive_entries = (
            _extend_release_asset_inventory_closure(
                closure,
                cas,
                verified,
                expanded_bytes=release_archive_expanded_bytes,
                entry_count=release_archive_entries,
                member_digests=release_archive_member_digests,
            )
        )
    return closure


def _extend_release_asset_inventory_closure(
    closure: dict[str, int],
    cas: CAS,
    result: dict[str, Any],
    *,
    expanded_bytes: int,
    entry_count: int,
    member_digests: set[str],
) -> tuple[int, int]:
    schema = result.get("schema")
    if schema == RELEASE_ASSET_SCHEMA:
        return expanded_bytes, entry_count
    if schema != RELEASE_ASSET_ZIP_SCHEMA:
        raise GitHubRecursiveGatewayError(
            "recursive release asset result schema is unsupported"
        )
    asset = result.get("asset")
    inventory_digest = result.get("inventory_digest")
    if (
        not isinstance(asset, dict)
        or not isinstance(asset.get("name"), str)
        or not isinstance(asset.get("digest"), str)
        or not isinstance(inventory_digest, str)
    ):
        raise GitHubRecursiveGatewayError(
            "recursive release asset inventory binding is invalid"
        )
    try:
        evidence_cas = CAS(cas.root, read_only=True)
        inventory = verify_zip_inventory(
            evidence_cas,
            inventory_digest,
            expected_archive_digest=asset["digest"],
            expected_archive_name=asset["name"],
        )
        inventory_raw = cas.read(
            inventory_digest,
            max_bytes=MAX_INVENTORY_BYTES,
        )
    except (CASError, ZipInventoryError) as exc:
        raise GitHubRecursiveGatewayError(
            "recursive release asset inventory verification failed"
        ) from exc
    expanded_bytes += inventory["totals"]["expanded_bytes"]
    entry_count += inventory["totals"]["entries"]
    member_digests.update(entry["digest"] for entry in inventory["files"])
    if expanded_bytes > MAX_EXPANDED_BYTES:
        raise GitHubRecursiveGatewayError(
            "recursive release ZIP expanded bytes exceed their aggregate bound"
        )
    if entry_count > MAX_ENTRIES:
        raise GitHubRecursiveGatewayError(
            "recursive release ZIP entries exceed their aggregate bound"
        )
    if len(member_digests) > MAX_ENTRIES:
        raise GitHubRecursiveGatewayError(
            "recursive release ZIP member blobs exceed their aggregate bound"
        )
    inventory_closure = {inventory_digest: len(inventory_raw)}
    for entry in inventory["files"]:
        digest = entry["digest"]
        size = entry["size"]
        previous = inventory_closure.setdefault(digest, size)
        if previous != size:
            raise GitHubRecursiveGatewayError(
                "recursive release inventory repeats a digest with another size"
            )
    for digest, size in inventory_closure.items():
        previous = closure.setdefault(digest, size)
        if previous != size:
            raise GitHubRecursiveGatewayError(
                "recursive release closure repeats a digest with another size"
            )
    return expanded_bytes, entry_count


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
