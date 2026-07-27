"""Retained-evidence pre-gate for admission-runtime conformance."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .admission_conformance import (
    AdmissionConformanceError,
    validate_admission_conformance,
)
from .cas import CAS, CASError


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024


def validate_retained_admission_conformance(
    document: Mapping[str, Any],
    *,
    evidence_cas: CAS | None = None,
) -> str:
    """Validate aggregation and evidence retention without granting PASS."""

    evidence_digests: set[str] = set()
    properties = document.get("properties")
    if isinstance(properties, list):
        for item in properties:
            if not isinstance(item, Mapping):
                continue
            scenarios = item.get("scenarios")
            if not isinstance(scenarios, list):
                continue
            for scenario in scenarios:
                if not isinstance(scenario, Mapping):
                    continue
                evidence = scenario.get("evidence_digests")
                if not isinstance(evidence, list):
                    continue
                for digest in evidence:
                    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                        raise AdmissionConformanceError(
                            "evidence digest is not a canonical SHA-256 identity"
                        )
                    evidence_digests.add(digest)

    status = validate_admission_conformance(document)
    if evidence_digests and evidence_cas is None:
        raise AdmissionConformanceError("retained evidence CAS is required")
    for digest in sorted(evidence_digests):
        try:
            evidence_cas.verify(digest, max_bytes=_MAX_EVIDENCE_BYTES)
        except CASError as exc:
            raise AdmissionConformanceError(
                f"cannot verify retained evidence {digest}: {exc}"
            ) from exc

    if status == "PASS":
        raise AdmissionConformanceError(
            "positive evidence semantics are not verified; "
            "installer authority remains disabled"
        )
    return status
