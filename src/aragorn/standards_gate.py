"""Semantic validation for the Phase 0 standards evidence gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


EXPECTED_GATE_DIGEST = (
    "sha256:082d1aa31789f44ee9ab5e1a378c7eba797d2623f16737e77029fdeaafc70ac7"
)
EXPECTED_PACKS = frozenset(
    {
        "mitre-atlas",
        "nist-ai-rmf-genai",
        "owasp-agentic-skills",
    }
)
EXPECTED_SOURCES = {
    "mitre-atlas": frozenset({"mitre-atlas-2026.06"}),
    "nist-ai-rmf-genai": frozenset({"nist-ai-100-1", "nist-ai-600-1"}),
    "owasp-agentic-skills": frozenset(
        {
            "owasp-agentic-applications-top-10-2026",
            "owasp-agentic-skills-top-10",
        }
    ),
}
EXPECTED_ITEMS = {
    "mitre-atlas": frozenset(
        {
            "AML.T0010.005",
            "AML.T0011.002",
            "AML.T0051.001",
            "AML.T0053",
            "AML.T0068",
            "AML.T0086",
            "AML.T0098",
            "AML.T0104",
            "AML.T0110",
        }
    ),
    "nist-ai-rmf-genai": frozenset(
        {
            "GV-1.3-002",
            "GV-6.1-009",
            "MG-1.3-001",
            "MP-5.1-006",
            "MS-2.3-002",
            "MS-2.7-001",
            "MS-2.7-007",
        }
    ),
    "owasp-agentic-skills": frozenset(
        {
            "AST01",
            "AST02",
            "AST03",
            "AST04",
            "AST05",
            "AST06",
            "AST07",
            "AST08",
            "AST09",
            "AST10",
        }
    ),
}


class StandardsGateError(ValueError):
    """The standards gate is internally inconsistent or references missing evidence."""


def _canonical_digest(document: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def validate_standards_gate(
    document: Mapping[str, Any],
    *,
    repository_root: Path,
) -> dict[str, int]:
    """Verify pack identity, accounting, and repository-local evidence references."""

    if document.get("schema") != "aragorn/phase0-standards-gate/v1":
        raise StandardsGateError("unsupported standards gate schema")

    packs = document.get("packs")
    if not isinstance(packs, list):
        raise StandardsGateError("standards gate packs must be an array")

    pack_ids = [pack.get("pack_id") for pack in packs if isinstance(pack, Mapping)]
    if len(pack_ids) != len(packs) or len(set(pack_ids)) != len(pack_ids):
        raise StandardsGateError("standards gate pack IDs must be present and unique")
    if set(pack_ids) != EXPECTED_PACKS:
        raise StandardsGateError(
            "standards gate must contain exactly the OWASP, MITRE, and NIST packs"
        )

    declared_required = document.get("gate", {}).get("required_packs")
    if not isinstance(declared_required, list) or set(declared_required) != EXPECTED_PACKS:
        raise StandardsGateError("standards gate required_packs does not match its packs")

    root = repository_root.resolve()
    source_ids: set[str] = set()
    item_ids: set[str] = set()
    evidence_mapped = 0
    roadmap_mapped = 0

    for pack in packs:
        pack_id = pack["pack_id"]
        pack_source_ids = [source["source_id"] for source in pack["sources"]]
        if (
            len(set(pack_source_ids)) != len(pack_source_ids)
            or set(pack_source_ids) != EXPECTED_SOURCES[pack_id]
        ):
            raise StandardsGateError(
                f"standards source inventory does not match frozen pack: {pack_id}"
            )

        pack_item_ids = [item["id"] for item in pack["items"]]
        if (
            len(set(pack_item_ids)) != len(pack_item_ids)
            or set(pack_item_ids) != EXPECTED_ITEMS[pack_id]
        ):
            raise StandardsGateError(
                f"standards item inventory does not match frozen pack: {pack_id}"
            )

        for source in pack["sources"]:
            source_id = source["source_id"]
            if source_id in source_ids:
                raise StandardsGateError(f"duplicate standards source ID: {source_id}")
            source_ids.add(source_id)

        for item in pack["items"]:
            item_id = item["id"]
            if item_id in item_ids:
                raise StandardsGateError(f"duplicate standards item ID: {item_id}")
            item_ids.add(item_id)

            disposition = item["disposition"]
            if disposition == "evidence_mapped":
                evidence_mapped += 1
            elif disposition == "roadmap_mapped":
                roadmap_mapped += 1
            else:  # The JSON Schema should reject this first; retain fail-closed semantics.
                raise StandardsGateError(
                    f"unresolved standards item disposition for {item_id}"
                )

            for reference in item["evidence_refs"]:
                candidate = (root / reference).resolve()
                try:
                    candidate.relative_to(root)
                except ValueError as exc:
                    raise StandardsGateError(
                        f"standards evidence escapes repository root: {reference}"
                    ) from exc
                if not candidate.is_file():
                    raise StandardsGateError(
                        f"standards evidence does not resolve to a file: {reference}"
                    )

    summary = {
        "pack_count": len(packs),
        "item_count": len(item_ids),
        "evidence_mapped": evidence_mapped,
        "roadmap_mapped": roadmap_mapped,
        "unresolved": 0,
    }
    if document["gate"]["summary"] != summary:
        raise StandardsGateError("standards gate summary does not match derived counts")
    if document["gate"]["result"] != "pass":
        raise StandardsGateError("fully resolved standards gate must report pass")
    if _canonical_digest(document) != EXPECTED_GATE_DIGEST:
        raise StandardsGateError(
            "standards gate content does not match its frozen v1 identity"
        )
    return summary
