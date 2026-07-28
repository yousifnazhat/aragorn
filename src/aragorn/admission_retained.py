"""Retained-input binding for policy-only admission decisions."""

from __future__ import annotations

import json
from typing import Any

from .admission_decision import AdmissionDecisionError, evaluate_admission
from .artifact_closure import ArtifactClosureError, load_verified_retained_manifest
from .cas import CAS, CASError
from .oci_worker_protocol import WorkerProtocolError, canonical_json


_MAX_DOCUMENT_BYTES = 8 * 1024 * 1024


def evaluate_retained_admission(
    document: object,
    *,
    cas: CAS,
    source_manifest_digest: str,
) -> dict[str, Any]:
    """Bind a policy-only decision to retained source and evidence bytes.

    Opaque evidence is only re-hashed here, not semantically replayed, so the
    returned decision intentionally remains ineligible for installation.
    """

    try:
        request_raw = canonical_json(document)
    except (RecursionError, WorkerProtocolError) as exc:
        raise AdmissionDecisionError(
            f"retained admission input is not canonical JSON: {exc}"
        ) from exc
    if len(request_raw) > _MAX_DOCUMENT_BYTES:
        raise AdmissionDecisionError("retained admission input exceeds 8 MiB")
    try:
        request = json.loads(request_raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionDecisionError(
            f"retained admission input cannot be decoded: {exc}"
        ) from exc
    decision = evaluate_admission(request)
    try:
        retained = load_verified_retained_manifest(cas, source_manifest_digest)
        admission_manifest = request["manifest"]
        retained_files = [
            {key: entry[key] for key in ("path", "size", "digest", "executable")}
            for entry in retained["files"]
        ]
        if (
            admission_manifest["tree_digest"] != retained["tree_digest"]
            or admission_manifest["files"] != retained_files
        ):
            raise AdmissionDecisionError(
                "admission manifest does not match retained source bytes"
            )
        if retained["schema"] != "aragorn/manifest/v1" or retained["source"] != {
            "kind": "local",
            "path": admission_manifest["source"]["path"],
        }:
            raise AdmissionDecisionError(
                "admission manifest does not match retained source identity"
            )

        evidence = request["evidence"]
        evidence_digests = {
            evidence["source_receipt_digest"],
            *evidence["source_evidence_digests"],
        }
        for digest in sorted(evidence_digests):
            cas.verify(digest, max_bytes=_MAX_DOCUMENT_BYTES)
    except (ArtifactClosureError, CASError) as exc:
        raise AdmissionDecisionError(
            f"cannot verify retained admission inputs: {exc}"
        ) from exc
    return decision
