"""One content-addressed deployment identity shared by Phase 3 collectors.

These seven identities bind evidence together; they do not attest a live machine
or qualify any behavior. A trusted runtime adapter must measure the deployment
before and after collection. Each binding addresses an identity artifact (for
example an image/source identity or a configuration manifest), not a path that
may silently change between admission and RUN collection.
"""

from __future__ import annotations

import hashlib
import json
import re
from io import BytesIO
from typing import Any

from .cas import CAS
from .oci_worker_protocol import canonical_json

SCHEMA = "aragorn/phase3-deployment-identity/v1"
BINDING_DIMENSIONS = (
    "runtime_commit_or_image",
    "adapter",
    "configuration",
    "worker",
    "os_profile",
    "policy",
    "aragorn_version",
)
_MAX_IDENTITY_BYTES = 4096
_MAX_ARTIFACT_BYTES = 1024 * 1024


class Phase3DeploymentError(ValueError):
    """An incomplete, changed, or unresolved deployment cannot bind a campaign."""


def _require_digest(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise Phase3DeploymentError("deployment binding must be a SHA-256 digest")
    return value


def build_phase3_deployment_identity(bindings: object) -> dict[str, Any]:
    """Build an exact seven-dimension identity, without asserting qualification."""
    if type(bindings) is not dict or set(bindings) != set(BINDING_DIMENSIONS):
        raise Phase3DeploymentError("deployment requires exactly seven bindings")
    return {
        "schema": SCHEMA,
        "bindings": {key: _require_digest(bindings[key]) for key in BINDING_DIMENSIONS},
    }


def validate_phase3_deployment_identity(value: object) -> dict[str, Any]:
    """Validate and detach the caller's identity; no boolean claims are accepted."""
    if (
        type(value) is not dict
        or set(value) != {"schema", "bindings"}
        or value["schema"] != SCHEMA
    ):
        raise Phase3DeploymentError("deployment identity envelope is invalid")
    return build_phase3_deployment_identity(value["bindings"])


def resolve_phase3_deployment_identity(
    raw: bytes, *, expected_digest: str, evidence_cas: CAS
) -> dict[str, Any]:
    """Resolve all identity artifacts, refusing dangling or mixed-deployment data."""
    _require_digest(expected_digest)
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_IDENTITY_BYTES:
        raise Phase3DeploymentError("deployment identity bytes are not bounded")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest:
        raise Phase3DeploymentError("deployment identity differs from the frozen pin")
    try:
        value = validate_phase3_deployment_identity(json.loads(raw))
        if canonical_json(value) != raw:
            raise Phase3DeploymentError("deployment identity is not canonical JSON")
        for name, digest in value["bindings"].items():
            artifact = evidence_cas.read(digest, max_bytes=_MAX_ARTIFACT_BYTES)
            if not artifact:
                raise Phase3DeploymentError(f"deployment artifact is empty: {name}")
    except Phase3DeploymentError:
        raise
    except Exception as exc:
        raise Phase3DeploymentError("deployment identity cannot be resolved") from exc
    return value


def retain_phase3_deployment_identity(value: object, *, evidence_cas: CAS) -> str:
    """Retain an identity only after every referenced artifact has been resolved."""
    raw = canonical_json(validate_phase3_deployment_identity(value))
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    resolve_phase3_deployment_identity(
        raw, expected_digest=digest, evidence_cas=evidence_cas
    )
    return evidence_cas.put_expected(
        BytesIO(raw), expected_digest=digest, max_bytes=_MAX_IDENTITY_BYTES
    )
