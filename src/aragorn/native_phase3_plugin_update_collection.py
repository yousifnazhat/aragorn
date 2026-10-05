"""Retain and replay the one bounded native plugin-update observation offline.

This is not a live capture callback or a campaign executor. Preparation projects
reported identities without writing; collection requires a separately supplied
deployment envelope, retains exact bytes, invokes the existing independent
binding consumer through a read-only CAS, and publishes the manifest last.
Partial failures may leave immutable blobs, including a completion-shaped
manifest if post-publication readback fails, but never a returned success receipt.
Independent replay must still resolve and verify every child. Nothing repairs,
deletes, retries, activates or qualifies a deployment.
"""

from __future__ import annotations

import hashlib
import json
import re
from io import BytesIO
from typing import Any

from . import native_phase3_plugin_update_binding as binding
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json
from .phase3_deployment import (
    BINDING_DIMENSIONS,
    build_phase3_deployment_identity,
    retain_phase3_deployment_identity,
)

SCHEMA = "aragorn/native-phase3-plugin-update-collection/v1"
AUTHORITY = "OFFLINE_RETAINED_REPORT_COLLECTION_NOT_FRESH_CAMPAIGN_OR_QUALIFICATION"
LIMITATIONS = (
    *binding.LIMITATIONS,
    "LOCAL_CAS_RETENTION_NOT_EXTERNAL_ATTESTATION_OR_DURABLE_DELIVERY",
    "PREPARATION_PROJECTS_CAPTURE_IDENTITIES_NOT_A_LIVE_DEPLOYMENT_MEASUREMENT",
)
_CAPTURE_LIMIT = 2 * 1024 * 1024
_ARTIFACT_LIMIT = 1024 * 1024
_DEPLOYMENT_LIMIT = 4096
_RESULT_LIMIT = 64 * 1024
_COLLECTION_LIMIT = 64 * 1024
_FALSE_FLAGS = (
    "route_qualified",
    "phase3_eligible",
    "run_conformance_eligible",
    "production_activation_eligible",
    "fresh_campaign_execution",
    "common_deployment_fully_verified",
    "signature_verified",
    "live_deployment_attested",
    "independent_policy_semantics_verified",
)


class NativePluginUpdateCollectionError(ValueError):
    """Retention or replay could not establish the exact bounded report binding."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativePluginUpdateCollectionError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "invalid caller-held content digest",
    )
    return value


def _pairs(items):
    result = dict(items)
    _require(len(result) == len(items), "duplicate collection key")
    return result


def _constant(_):
    raise NativePluginUpdateCollectionError("non-finite collection value")


def _parse(raw: bytes, limit: int) -> dict:
    _require(
        type(raw) is bytes and 0 < len(raw) <= limit, "unbounded retained document"
    )
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    _require(
        type(value) is dict and canonical_json(value) == raw,
        "noncanonical retained document",
    )
    return value


def _reference(raw: bytes) -> dict:
    return {"digest": _digest(raw), "bytes": len(raw)}


def _read_reference(store: CAS, value: object, limit: int) -> bytes:
    _require(
        type(value) is dict
        and set(value) == {"digest", "bytes"}
        and type(value["bytes"]) is int
        and 0 < value["bytes"] <= limit,
        "invalid retained blob reference",
    )
    raw = store.read(_pin(value["digest"]), max_bytes=limit)
    _require(_reference(raw) == value, "retained bytes disagree with manifest")
    return raw


def _retain(store: CAS, raw: bytes, limit: int) -> str:
    _require(type(raw) is bytes and 0 < len(raw) <= limit, "unbounded collection input")
    digest = _digest(raw)
    _require(
        store.put_expected(BytesIO(raw), expected_digest=digest, max_bytes=limit)
        == digest
        and store.read(digest, max_bytes=limit) == raw,
        "content-addressed retention or readback failed",
    )
    return digest


def prepare_native_plugin_update_collection(
    capture_raw: bytes,
    *,
    expected_capture_digest: str,
    expected_source_digest: str,
    expected_source_commit: str,
) -> dict[str, Any]:
    """Validate/project the retained report without CAS writes or live operations.

    ``deployment_raw`` is a proposal derived from the pinned report. An operator
    may approve it for collection or compare it with an already-held deployment
    envelope; it must never be relabeled as measured current deployment state.
    """
    try:
        artifacts = binding.native_plugin_update_identity_artifacts(
            capture_raw,
            expected_capture_digest=expected_capture_digest,
            expected_source_digest=expected_source_digest,
            expected_source_commit=expected_source_commit,
        )
        deployment = build_phase3_deployment_identity(
            {name: _digest(raw) for name, raw in artifacts.items()}
        )
        deployment_raw = canonical_json(deployment)
        # The independent consumer already validated canonical capture/source pins.
        source_raw = canonical_json(json.loads(capture_raw)["source"])
        _require(
            _digest(source_raw) == _pin(expected_source_digest),
            "source projection changed",
        )
        return {
            "schema": "aragorn/native-phase3-plugin-update-preparation/v1",
            "authority": "REPORT_IDENTITY_PROJECTION_ONLY_NOT_LIVE_MEASUREMENT_OR_QUALIFICATION",
            "capture": _reference(capture_raw),
            "source": _reference(source_raw),
            "source_commit": expected_source_commit,
            "source_raw": source_raw,
            "identity_artifacts": artifacts,
            "deployment_raw": deployment_raw,
            "deployment_digest": _digest(deployment_raw),
            **dict.fromkeys(_FALSE_FLAGS, False),
        }
    except NativePluginUpdateCollectionError:
        raise
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        raise NativePluginUpdateCollectionError(
            "plugin-update preparation refused"
        ) from exc


def _context(
    capture_pin: str, source_pin: str, source_commit: str, deployment_pin: str
) -> dict:
    return {
        "route_id": binding.ROUTE,
        "branch": binding.BRANCH,
        "capture_digest": _pin(capture_pin),
        "source_record_digest": _pin(source_pin),
        "source_commit": source_commit,
        "deployment_identity_digest": _pin(deployment_pin),
    }


def _replay(
    collection_raw: bytes,
    *,
    expected_collection_digest: str,
    expected_capture_digest: str,
    expected_source_digest: str,
    expected_source_commit: str,
    expected_deployment_digest: str,
    evidence_cas: CAS,
) -> dict[str, Any]:
    _require(
        type(evidence_cas) is CAS and evidence_cas.read_only is True,
        "replay requires a read-only CAS",
    )
    _require(
        _digest(collection_raw) == _pin(expected_collection_digest),
        "collection differs from caller-held digest",
    )
    value = _parse(collection_raw, _COLLECTION_LIMIT)
    _require(
        set(value)
        == {
            "schema",
            "authority",
            "status",
            "context",
            "capture",
            "source",
            "deployment",
            "identity_artifacts",
            "verification",
            "limitations",
            *_FALSE_FLAGS,
        },
        "collection field inventory changed",
    )
    _require(
        value["schema"] == SCHEMA
        and value["authority"] == AUTHORITY
        and value["status"] == "BOUNDED_OBSERVATION_RETAINED"
        and value["limitations"] == list(LIMITATIONS)
        and all(value[key] is False for key in _FALSE_FLAGS),
        "collection authority or proof ceiling changed",
    )
    expected_context = _context(
        expected_capture_digest,
        expected_source_digest,
        expected_source_commit,
        expected_deployment_digest,
    )
    _require(
        value["context"] == expected_context,
        "collection context differs from caller-held pins",
    )
    capture_raw = _read_reference(evidence_cas, value["capture"], _CAPTURE_LIMIT)
    source_raw = _read_reference(evidence_cas, value["source"], _ARTIFACT_LIMIT)
    deployment_raw = _read_reference(
        evidence_cas, value["deployment"], _DEPLOYMENT_LIMIT
    )
    verification_raw = _read_reference(
        evidence_cas, value["verification"], _RESULT_LIMIT
    )
    _require(
        value["capture"]["digest"] == expected_capture_digest
        and value["source"]["digest"] == expected_source_digest
        and value["deployment"]["digest"] == expected_deployment_digest,
        "manifest blob pins disagree with context",
    )
    source = _parse(source_raw, _ARTIFACT_LIMIT)
    _require(
        source["commit"] == expected_source_commit
        and canonical_json(json.loads(capture_raw)["source"]) == source_raw,
        "retained source does not match capture",
    )
    deployment = _parse(deployment_raw, _DEPLOYMENT_LIMIT)
    _require(
        type(value["identity_artifacts"]) is dict
        and set(value["identity_artifacts"]) == set(BINDING_DIMENSIONS),
        "identity artifact inventory changed",
    )
    reads = {
        value["capture"]["digest"]: (capture_raw, _CAPTURE_LIMIT),
        value["source"]["digest"]: (source_raw, _ARTIFACT_LIMIT),
        value["deployment"]["digest"]: (deployment_raw, _DEPLOYMENT_LIMIT),
        value["verification"]["digest"]: (verification_raw, _RESULT_LIMIT),
    }
    for name, reference in value["identity_artifacts"].items():
        raw = _read_reference(evidence_cas, reference, _ARTIFACT_LIMIT)
        _require(
            reference["digest"] == deployment["bindings"][name],
            "manifest identity disagrees with deployment",
        )
        reads[reference["digest"]] = (raw, _ARTIFACT_LIMIT)
    # Never accept a retained verifier verdict as semantic authority.
    verified = binding.verify_native_plugin_update_binding(
        capture_raw,
        expected_capture_digest=expected_capture_digest,
        expected_source_digest=expected_source_digest,
        expected_source_commit=expected_source_commit,
        deployment_raw=deployment_raw,
        expected_deployment_digest=expected_deployment_digest,
        evidence_cas=evidence_cas,
    )
    _require(
        canonical_json(verified) == verification_raw,
        "retained verification differs from independent replay",
    )
    for digest, (raw, limit) in reads.items():
        _require(
            evidence_cas.read(digest, max_bytes=limit) == raw,
            "retained evidence changed during replay",
        )
    return {
        "collection_digest": expected_collection_digest,
        "collection": value,
        "verification": verified,
    }


def replay_native_plugin_update_collection(
    *,
    expected_collection_digest: str,
    expected_capture_digest: str,
    expected_source_digest: str,
    expected_source_commit: str,
    expected_deployment_digest: str,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Resolve a caller-pinned manifest and independently recompute its result."""
    try:
        _require(
            type(evidence_cas) is CAS and evidence_cas.read_only is True,
            "replay requires a read-only CAS",
        )
        raw = evidence_cas.read(
            _pin(expected_collection_digest), max_bytes=_COLLECTION_LIMIT
        )
        result = _replay(
            raw,
            expected_collection_digest=expected_collection_digest,
            expected_capture_digest=expected_capture_digest,
            expected_source_digest=expected_source_digest,
            expected_source_commit=expected_source_commit,
            expected_deployment_digest=expected_deployment_digest,
            evidence_cas=evidence_cas,
        )
        _require(
            evidence_cas.read(expected_collection_digest, max_bytes=_COLLECTION_LIMIT)
            == raw,
            "collection changed during replay",
        )
        return result
    except NativePluginUpdateCollectionError:
        raise
    except (CASError, KeyError, OSError, TypeError, ValueError, IndexError) as exc:
        raise NativePluginUpdateCollectionError(
            "plugin-update collection replay refused"
        ) from exc


def collect_native_plugin_update_observation(
    capture_raw: bytes,
    *,
    expected_capture_digest: str,
    expected_source_digest: str,
    expected_source_commit: str,
    deployment_raw: bytes,
    expected_deployment_digest: str,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Retain exact supplied evidence and publish a bounded collection last.

    The operator must supply/approve the exact reported deployment envelope.
    No receipt is returned on partial failure; existing CAS blobs are preserved.
    A post-publication failure can leave a manifest that must not be accepted
    without independent replay of all referenced evidence.
    Successful identical calls deduplicate naturally without re-executing a case.
    """
    try:
        _require(
            type(evidence_cas) is CAS and evidence_cas.read_only is False,
            "collection requires a writable CAS",
        )
        prepared = prepare_native_plugin_update_collection(
            capture_raw,
            expected_capture_digest=expected_capture_digest,
            expected_source_digest=expected_source_digest,
            expected_source_commit=expected_source_commit,
        )
        _require(
            type(deployment_raw) is bytes
            and deployment_raw == prepared["deployment_raw"]
            and _pin(expected_deployment_digest) == prepared["deployment_digest"],
            "caller deployment differs from pinned report projection",
        )
        for raw in prepared["identity_artifacts"].values():
            _retain(evidence_cas, raw, _ARTIFACT_LIMIT)
        _retain(evidence_cas, capture_raw, _CAPTURE_LIMIT)
        _retain(evidence_cas, prepared["source_raw"], _ARTIFACT_LIMIT)
        retained_deployment = retain_phase3_deployment_identity(
            json.loads(deployment_raw), evidence_cas=evidence_cas
        )
        _require(
            retained_deployment == expected_deployment_digest,
            "deployment retention changed identity",
        )
        readonly = CAS(evidence_cas.root, read_only=True)
        _require(
            readonly.read(expected_capture_digest, max_bytes=_CAPTURE_LIMIT)
            == capture_raw
            and readonly.read(expected_deployment_digest, max_bytes=_DEPLOYMENT_LIMIT)
            == deployment_raw,
            "retained capture/deployment readback changed",
        )
        verification = binding.verify_native_plugin_update_binding(
            readonly.read(expected_capture_digest, max_bytes=_CAPTURE_LIMIT),
            expected_capture_digest=expected_capture_digest,
            expected_source_digest=expected_source_digest,
            expected_source_commit=expected_source_commit,
            deployment_raw=readonly.read(
                expected_deployment_digest, max_bytes=_DEPLOYMENT_LIMIT
            ),
            expected_deployment_digest=expected_deployment_digest,
            evidence_cas=readonly,
        )
        verification_raw = canonical_json(verification)
        _retain(evidence_cas, verification_raw, _RESULT_LIMIT)
        manifest = {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": "BOUNDED_OBSERVATION_RETAINED",
            "context": _context(
                expected_capture_digest,
                expected_source_digest,
                expected_source_commit,
                expected_deployment_digest,
            ),
            "capture": prepared["capture"],
            "source": prepared["source"],
            "deployment": _reference(deployment_raw),
            "identity_artifacts": {
                name: _reference(raw)
                for name, raw in prepared["identity_artifacts"].items()
            },
            "verification": _reference(verification_raw),
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(_FALSE_FLAGS, False),
        }
        manifest_raw = canonical_json(manifest)
        manifest_digest = _digest(manifest_raw)
        # Resolve/replay all children before publishing any completion manifest.
        _replay(
            manifest_raw,
            expected_collection_digest=manifest_digest,
            expected_capture_digest=expected_capture_digest,
            expected_source_digest=expected_source_digest,
            expected_source_commit=expected_source_commit,
            expected_deployment_digest=expected_deployment_digest,
            evidence_cas=readonly,
        )
        _retain(evidence_cas, manifest_raw, _COLLECTION_LIMIT)
        return replay_native_plugin_update_collection(
            expected_collection_digest=manifest_digest,
            expected_capture_digest=expected_capture_digest,
            expected_source_digest=expected_source_digest,
            expected_source_commit=expected_source_commit,
            expected_deployment_digest=expected_deployment_digest,
            evidence_cas=readonly,
        )
    except NativePluginUpdateCollectionError:
        raise
    except (CASError, KeyError, OSError, TypeError, ValueError, IndexError) as exc:
        raise NativePluginUpdateCollectionError(
            "plugin-update collection refused; partial immutable blobs may remain"
        ) from exc
