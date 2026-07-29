"""Fail-closed validation for static admission route inventories."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .oci_worker_protocol import canonical_digest, canonical_json

_OPENCLAW_2026_7_1_INVENTORY_DIGEST = (
    "sha256:c175cd145a0c18d80921edbeb2452e34182188f97ee4e3b8d26176e7e38f5b41"
)
_SOURCE_ANCHOR = re.compile(r"^.+#L([1-9][0-9]*)-L([1-9][0-9]*)$")
_MAX_CONTROL_BYTES = 1024 * 1024
_SCAFFOLD_SCHEMA = "aragorn/openclaw-route-probe-scaffold/v1"
_SCAFFOLD_ASSURANCE = "SELECTOR_ONLY_NO_RUNTIME_EXECUTION_OR_CONFORMANCE_AUTHORITY"
_NOT_TESTED_REASON = "ROUTE_EXECUTION_NOT_RECORDED"

OPENCLAW_2026_7_1_PHASE1_BLOCKING_ROUTE_IDS = (
    "ADM-02/update/archive-source-force-replacement",
    "ADM-02/update/clawhub-tracked-replacement",
    "ADM-02/update/core-updater-plugin-replacement",
    "ADM-02/update/curator-restore-activation",
    "ADM-02/update/plugin-package-skill-replacement",
    "ADM-02/update/workshop-proposal-apply",
    "ADM-02/reload/fresh-session-reset",
    "ADM-02/reload/manual-plugin-invalidation",
    "ADM-02/reload/remote-eligibility-invalidation",
    "ADM-02/reload/sandbox-per-run-rescan",
    "ADM-02/reload/session-snapshot-consumer",
    "ADM-02/reload/workshop-invalidation",
)


class AdmissionRouteInventoryError(ValueError):
    """A route inventory is malformed, unbound, or transfers authority."""


def validate_openclaw_2026_7_1_route_inventory(
    inventory: object,
    runtime_candidates: object,
) -> None:
    """Validate the reviewed exact inventory without accepting conformance."""

    if not isinstance(inventory, Mapping) or set(inventory) != {
        "schema",
        "assurance",
        "runtime",
        "routes",
        "decision",
    }:
        raise AdmissionRouteInventoryError("admission route inventory shape drift")
    if inventory["schema"] != "aragorn/admission-route-inventory/v1":
        raise AdmissionRouteInventoryError("admission route inventory schema drift")
    if inventory["assurance"] != "static_source_inventory_only_not_runtime_conformance":
        raise AdmissionRouteInventoryError("admission route inventory assurance drift")
    if canonical_digest(inventory) != _OPENCLAW_2026_7_1_INVENTORY_DIGEST:
        raise AdmissionRouteInventoryError(
            "OpenClaw route inventory exact binding drift"
        )
    if not isinstance(runtime_candidates, Mapping):
        raise AdmissionRouteInventoryError("runtime candidate lock must be an object")
    candidates = runtime_candidates.get("candidates")
    if not isinstance(candidates, list):
        raise AdmissionRouteInventoryError(
            "runtime candidate lock candidates must be a list"
        )
    openclaw = [
        item
        for item in candidates
        if isinstance(item, Mapping) and item.get("name") == "openclaw"
    ]
    if len(openclaw) != 1:
        raise AdmissionRouteInventoryError(
            "OpenClaw runtime candidate identity is ambiguous"
        )
    candidate = openclaw[0]
    if inventory["runtime"] != {
        field: candidate[field]
        for field in ("name", "version", "commit_sha1", "tree_sha1")
    }:
        raise AdmissionRouteInventoryError(
            "admission route inventory runtime binding drift"
        )
    if inventory["decision"] != {
        "runtime_executed": False,
        "status": "NOT_TESTED",
        "installer_work_eligible": False,
    }:
        raise AdmissionRouteInventoryError(
            "admission route inventory transferred authority"
        )

    source_prefix = (
        f"https://github.com/openclaw/openclaw/blob/{candidate['commit_sha1']}/src/"
    )
    for route in inventory["routes"]:
        for path in route["paths"]:
            for url in path["source_urls"]:
                match = _SOURCE_ANCHOR.fullmatch(url)
                if (
                    not url.startswith(source_prefix)
                    or match is None
                    or int(match[2]) < int(match[1])
                ):
                    raise AdmissionRouteInventoryError(
                        "OpenClaw route inventory contains an invalid source anchor"
                    )


def build_openclaw_2026_7_1_route_probe_scaffold(
    inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    *,
    route_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Select pending routes without claiming that any runtime was executed."""

    validate_openclaw_2026_7_1_route_inventory(inventory, runtime_candidates)
    requested = tuple(
        OPENCLAW_2026_7_1_PHASE1_BLOCKING_ROUTE_IDS if route_ids is None else route_ids
    )
    allowed = set(OPENCLAW_2026_7_1_PHASE1_BLOCKING_ROUTE_IDS)
    if (
        not requested
        or len(set(requested)) != len(requested)
        or any(
            not isinstance(route_id, str) or route_id not in allowed
            for route_id in requested
        )
    ):
        raise AdmissionRouteInventoryError(
            "route selectors must be unique current Phase 1 blockers"
        )

    selected = set(requested)
    routes = [
        {
            "evidence_digests": [],
            "id": route_id,
            "reason_codes": [_NOT_TESTED_REASON],
            "source_urls": list(path["source_urls"]),
            "status": "NOT_TESTED",
        }
        for route in inventory["routes"]
        for path in route["paths"]
        if (route_id := f"{route['id']}/{path['id']}") in selected
    ]
    if {route["id"] for route in routes} != selected:
        raise AdmissionRouteInventoryError(
            "route selector is absent from the authoritative inventory"
        )
    return {
        "assurance": _SCAFFOLD_ASSURANCE,
        "decision": {
            "installer_work_eligible": False,
            "runtime_executed": False,
            "status": "NOT_TESTED",
        },
        "route_inventory_canonical_digest": _OPENCLAW_2026_7_1_INVENTORY_DIGEST,
        "routes": routes,
        "runtime": dict(inventory["runtime"]),
        "schema": _SCAFFOLD_SCHEMA,
    }


def validate_openclaw_2026_7_1_route_probe_scaffold(
    document: object,
    inventory: Mapping[str, Any],
    runtime_candidates: Mapping[str, Any],
    *,
    route_ids: Sequence[str] | None = None,
) -> None:
    """Reject selector drift and every attempted result or authority promotion."""

    expected = build_openclaw_2026_7_1_route_probe_scaffold(
        inventory,
        runtime_candidates,
        route_ids=route_ids,
    )
    if not isinstance(document, Mapping) or document != expected:
        raise AdmissionRouteInventoryError(
            "OpenClaw route probe scaffold changed or claimed execution"
        )


def _load_control_document(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        if len(raw) > _MAX_CONTROL_BYTES:
            raise AdmissionRouteInventoryError("route control document is oversized")
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdmissionRouteInventoryError(
            f"cannot load route control document: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise AdmissionRouteInventoryError("route control document must be an object")
    return document


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise AdmissionRouteInventoryError(f"duplicate route control key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise AdmissionRouteInventoryError(f"invalid route control constant: {value}")


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit a non-authoritative OpenClaw route-probe scaffold."
    )
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--runtime-candidates", required=True, type=Path)
    parser.add_argument(
        "--route-id",
        action="append",
        help="Select one current Phase 1 blocking route; repeat as needed.",
    )
    arguments = parser.parse_args(argv)
    try:
        scaffold = build_openclaw_2026_7_1_route_probe_scaffold(
            _load_control_document(arguments.inventory),
            _load_control_document(arguments.runtime_candidates),
            route_ids=arguments.route_id,
        )
    except AdmissionRouteInventoryError as exc:
        parser.error(str(exc))
    sys.stdout.buffer.write(canonical_json(scaffold) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
