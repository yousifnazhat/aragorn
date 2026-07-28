"""Fail-closed validation for static admission route inventories."""

from __future__ import annotations

import re
from collections.abc import Mapping

from .oci_worker_protocol import canonical_digest

_OPENCLAW_2026_7_1_INVENTORY_DIGEST = (
    "sha256:c175cd145a0c18d80921edbeb2452e34182188f97ee4e3b8d26176e7e38f5b41"
)
_SOURCE_ANCHOR = re.compile(r"^.+#L([1-9][0-9]*)-L([1-9][0-9]*)$")


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
