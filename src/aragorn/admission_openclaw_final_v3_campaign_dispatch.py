"""Describe fixed V3 campaign invocations without executing probes."""

from __future__ import annotations

import re
from collections import Counter
from copy import deepcopy
from pathlib import PurePosixPath
from typing import Any


class CampaignDispatchError(ValueError):
    """A campaign case was not an exact member of the fixed registry."""


CURRENT_V3 = "CURRENT_V3"
V3_CAPTURE_REQUIRED = "V3_CAPTURE_REQUIRED"
V3_REBIND_REQUIRED = "V3_REBIND_REQUIRED"
V3_PORT_REQUIRED = "V3_PORT_REQUIRED"
MISSING_ADAPTER = "MISSING_ADAPTER"

_IMPLEMENTATION_STATES = (
    CURRENT_V3,
    V3_CAPTURE_REQUIRED,
    V3_REBIND_REQUIRED,
    V3_PORT_REQUIRED,
    MISSING_ADAPTER,
)
_NODE = "/usr/local/bin/node"
_PYTHON = "/usr/local/bin/python3.12"
_INTERPRETERS = {_NODE, _PYTHON}
_REGISTRY_SCHEMA = "aragorn/openclaw-final-admission-v3-campaign-registry/v1"
_DISPATCH_SCHEMA = "aragorn/openclaw-final-admission-v3-campaign-dispatch/v1"
_READINESS_SCHEMA = "aragorn/openclaw-final-admission-v3-campaign-dispatch-readiness/v1"
_AUTHORITY = (
    "V3_CAMPAIGN_CASE_INVENTORY_AND_PINNED_MATERIALIZED_BUNDLE_DESCRIPTORS_ONLY_"
    "NATIVE_EXECUTION_DISABLED_"
    "NO_QUALIFICATION_AUTHORITY"
)
_LIMITATIONS = [
    "PROVISIONAL_STAGING_PATHS_NOT_EXECUTABLE_BYTE_PINS",
    "TWO_MATERIALIZED_V3_BUNDLES_REQUIRE_FRESH_SUBFIXTURE_CAPTURE",
    "WORKSHOP_INVALIDATION_HAS_ROUTE_ONLY_QUALIFICATION_NOT_CAMPAIGN_EVIDENCE",
    "NO_NATIVE_INTERPRETER_RUNTIME_OR_IMAGE_DIGEST_EXECUTION_BINDINGS",
    "LEGACY_MULTI_SCENARIO_PROBES_REQUIRE_V3_PER_CASE_PORTS",
    "MISSING_ROUTE_ADAPTERS_ARE_NOT_EXECUTED_BY_THE_CURRENT_ROUTE_PROBE",
]
_DET01_MATERIALIZER = {
    "bytes": 6_960,
    "digest": "sha256:42af9e1c895a2e63de4c5803b5fb0dfc9aedcef2b164e4d8bd53b4cbf1660081",
    "path": "/src/scripts/materialize_openclaw_final_v3_det01.py",
}
_CORE_UPDATER_MATERIALIZER = {
    "bytes": 8_295,
    "digest": "sha256:0f7d04c91765ce85039a3f55ad4a2320d26556af2c4e1683d2eb8b858afe9ada",
    "path": (
        "/src/scripts/"
        "materialize_openclaw_final_v3_core_updater_plugin_replacement.py"
    ),
}
_MATERIALIZER_BY_CASE = {
    "DET-01": _DET01_MATERIALIZER,
    "ADM-02/update/core-updater-plugin-replacement": _CORE_UPDATER_MATERIALIZER,
}
_ROUTE_SCHEMA = "aragorn/openclaw-protected-route-action-observations/v1"
_CONTAINED_SCHEMA = "aragorn/openclaw-contained-profile-probe-evidence/v1"


def _bundle_item(name: str, role: str) -> tuple[str, str]:
    return name, role


def _case_materializer(
    case_id: str, root: str, implementation_state: str
) -> dict[str, Any] | None:
    if implementation_state != V3_CAPTURE_REQUIRED:
        return None
    source = _MATERIALIZER_BY_CASE[case_id]
    return {
        "argv": [_PYTHON, source["path"], root],
        "source": dict(source),
    }


def _descriptor(
    ordinal: int,
    case_id: str,
    implementation_state: str,
    interpreter: str,
    probe: str,
    expected_schema: str,
    *,
    arguments: tuple[str, ...] = (),
    bundle: tuple[tuple[str, str], ...] | None = None,
) -> dict[str, Any]:
    slug = case_id.lower().replace("/", "-")
    root = f"/campaign/cases/{ordinal:02d}-{slug}"
    items = bundle if bundle is not None else (_bundle_item(probe, "probe"),)
    return {
        "argv": [interpreter, f"{root}/{probe}", *arguments],
        "bundle": [{"path": f"{root}/{name}", "role": role} for name, role in items],
        "case_id": case_id,
        "expected_schema": expected_schema,
        "implementation_state": implementation_state,
        "interpreter": interpreter,
        "materializer": _case_materializer(case_id, root, implementation_state),
        "native_execution_enabled": False,
        "ordinal": ordinal,
    }


_CASES = (
    _descriptor(
        0,
        "DET-01",
        V3_CAPTURE_REQUIRED,
        _PYTHON,
        "run_admission_authority_replay.py",
        "aragorn/admission-authority-replay-evidence/v1",
        bundle=(
            _bundle_item("run_admission_authority_replay.py", "probe"),
            _bundle_item("deterministic-authority-vectors-v1.json", "vector"),
            _bundle_item("aragorn/__init__.py", "probe-dependency"),
            _bundle_item("aragorn/admission_decision.py", "probe-dependency"),
            _bundle_item("aragorn/analyze.py", "probe-dependency"),
            _bundle_item("aragorn/oci_worker_protocol.py", "probe-dependency"),
            _bundle_item("aragorn/policy.py", "probe-dependency"),
        ),
    ),
    _descriptor(
        1,
        "ADM-01/exact-admitted-bytes",
        V3_PORT_REQUIRED,
        _NODE,
        "model-activation-probe.mjs",
        "aragorn/openclaw-contained-model-activation-probe-evidence/v1",
    ),
    *(
        _descriptor(
            ordinal,
            case_id,
            V3_PORT_REQUIRED,
            _NODE,
            "contained-probe.mjs",
            _CONTAINED_SCHEMA,
            bundle=(
                _bundle_item("contained-probe.mjs", "probe"),
                _bundle_item("probe.mjs", "probe-dependency"),
            ),
        )
        for ordinal, case_id in enumerate(
            (
                "ADM-02/install",
                "ADM-02/direct-write",
                "ADM-02/rename",
                "ADM-02/symlink",
                "ADM-02/auto-discovery",
                "ADM-02/restart",
            ),
            start=2,
        )
    ),
    _descriptor(
        8,
        "ADM-02/update/archive-source-force-replacement",
        CURRENT_V3,
        _NODE,
        "protected-archive-replacement-probe.mjs",
        "aragorn/openclaw-protected-archive-replacement-observation/v1",
    ),
    _descriptor(
        9,
        "ADM-02/update/clawhub-tracked-replacement",
        MISSING_ADAPTER,
        _NODE,
        "protected-route-probe.mjs",
        _ROUTE_SCHEMA,
        arguments=(
            "--route-id",
            "ADM-02/update/clawhub-tracked-replacement",
        ),
        bundle=(
            _bundle_item("protected-route-probe.mjs", "probe"),
            _bundle_item("clawhub-tracked-replacement.mjs", "adapter"),
        ),
    ),
    _descriptor(
        10,
        "ADM-02/update/config-entry-activation",
        CURRENT_V3,
        _NODE,
        "protected-config-activation-v3-probe.mjs",
        "aragorn/openclaw-protected-config-activation-observation/v1",
    ),
    _descriptor(
        11,
        "ADM-02/update/core-updater-plugin-replacement",
        V3_CAPTURE_REQUIRED,
        _NODE,
        "protected-core-updater-plugin-replacement-v3-probe.mjs",
        (
            "aragorn/openclaw-protected-core-updater-plugin-"
            "replacement-observation/v1"
        ),
        arguments=(
            "--route-id",
            "ADM-02/update/core-updater-plugin-replacement",
        ),
        bundle=(
            _bundle_item(
                "protected-core-updater-plugin-replacement-v3-probe.mjs",
                "probe",
            ),
            _bundle_item("protected-route-action-probe.mjs", "probe-dependency"),
            _bundle_item(
                "core-updater-plugin-replacement-audit-listener.mjs",
                "probe-dependency",
            ),
            _bundle_item("candidate-source/index.js", "fixture"),
            _bundle_item("candidate-source/openclaw.plugin.json", "fixture"),
            _bundle_item("candidate-source/package.json", "fixture"),
        ),
    ),
    _descriptor(
        12,
        "ADM-02/update/curator-restore-activation",
        CURRENT_V3,
        _NODE,
        "protected-curator-restore-denial-probe.mjs",
        "aragorn/openclaw-protected-curator-restore-denial-observation/v1",
        bundle=(
            _bundle_item("protected-curator-restore-denial-probe.mjs", "probe"),
            _bundle_item("protected-observation-v1.mjs", "probe-dependency"),
        ),
    ),
    _descriptor(
        13,
        "ADM-02/update/plugin-enable-activation",
        CURRENT_V3,
        _NODE,
        "protected-plugin-enable-v3-probe.mjs",
        "aragorn/openclaw-protected-plugin-enable-observation/v1",
    ),
    _descriptor(
        14,
        "ADM-02/update/plugin-force-reinstall",
        CURRENT_V3,
        _PYTHON,
        "protected-plugin-force-reinstall-v3-probe.py",
        "aragorn/openclaw-protected-plugin-force-reinstall-v3-observation/v1",
        bundle=(
            _bundle_item("protected-plugin-force-reinstall-v3-probe.py", "probe"),
            _bundle_item("baseline-source/index.js", "fixture"),
            _bundle_item("baseline-source/openclaw.plugin.json", "fixture"),
            _bundle_item("baseline-source/package.json", "fixture"),
            _bundle_item("candidate-source/index.js", "fixture"),
            _bundle_item("candidate-source/openclaw.plugin.json", "fixture"),
            _bundle_item("candidate-source/package.json", "fixture"),
        ),
    ),
    _descriptor(
        15,
        "ADM-02/update/plugin-package-skill-replacement",
        MISSING_ADAPTER,
        _NODE,
        "protected-route-probe.mjs",
        _ROUTE_SCHEMA,
        arguments=(
            "--route-id",
            "ADM-02/update/plugin-package-skill-replacement",
        ),
        bundle=(
            _bundle_item("protected-route-probe.mjs", "probe"),
            _bundle_item("plugin-package-skill-replacement.mjs", "adapter"),
        ),
    ),
    _descriptor(
        16,
        "ADM-02/update/workshop-proposal-apply",
        CURRENT_V3,
        _NODE,
        "protected-route-probe.mjs",
        _ROUTE_SCHEMA,
        arguments=(
            "--route-id",
            "ADM-02/update/workshop-proposal-apply",
        ),
        bundle=(
            _bundle_item("protected-route-probe.mjs", "probe"),
            _bundle_item("PROPOSAL.md", "fixture"),
        ),
    ),
    _descriptor(
        17,
        "ADM-02/reload/chat-session-snapshot-consumer",
        CURRENT_V3,
        _NODE,
        "protected-chat-session-snapshot-consumer-v3-probe.mjs",
        "aragorn/openclaw-protected-chat-session-snapshot-consumer-observation/v1",
        bundle=(
            _bundle_item(
                "protected-chat-session-snapshot-consumer-v3-probe.mjs", "probe"
            ),
            _bundle_item("protected-observation-v1.mjs", "probe-dependency"),
        ),
    ),
    _descriptor(
        18,
        "ADM-02/reload/config-invalidation",
        V3_PORT_REQUIRED,
        _NODE,
        "config-activation-probe.mjs",
        "aragorn/openclaw-contained-config-activation-probe-evidence/v1",
    ),
    _descriptor(
        19,
        "ADM-02/reload/cron-rescan",
        CURRENT_V3,
        _NODE,
        "protected-cron-rescan-probe.mjs",
        "aragorn/openclaw-protected-cron-rescan-observation/v1",
        bundle=(
            _bundle_item("protected-cron-rescan-probe.mjs", "probe"),
            _bundle_item("protected-observation-v1.mjs", "probe-dependency"),
        ),
    ),
    _descriptor(
        20,
        "ADM-02/reload/filesystem-watch-invalidation",
        V3_PORT_REQUIRED,
        _NODE,
        "live-reload-probe.mjs",
        "aragorn/openclaw-contained-live-reload-probe-evidence/v1",
    ),
    _descriptor(
        21,
        "ADM-02/reload/fresh-session-reset",
        CURRENT_V3,
        _NODE,
        "protected-route-probe.mjs",
        _ROUTE_SCHEMA,
        arguments=("--route-id", "ADM-02/reload/fresh-session-reset"),
    ),
    _descriptor(
        22,
        "ADM-02/reload/manual-plugin-invalidation",
        MISSING_ADAPTER,
        _NODE,
        "protected-route-probe.mjs",
        _ROUTE_SCHEMA,
        arguments=("--route-id", "ADM-02/reload/manual-plugin-invalidation"),
        bundle=(
            _bundle_item("protected-route-probe.mjs", "probe"),
            _bundle_item("manual-plugin-invalidation.mjs", "adapter"),
        ),
    ),
    _descriptor(
        23,
        "ADM-02/reload/missing-prompt-blob-rebuild",
        CURRENT_V3,
        _NODE,
        "protected-prompt-rebuild-probe.mjs",
        "aragorn/openclaw-protected-prompt-rebuild-observation/v1",
        bundle=(
            _bundle_item("protected-prompt-rebuild-probe.mjs", "probe"),
            _bundle_item("protected-observation-v1.mjs", "probe-dependency"),
        ),
    ),
    _descriptor(
        24,
        "ADM-02/reload/plugin-skill-dir-activation",
        V3_PORT_REQUIRED,
        _NODE,
        "plug01-probe.mjs",
        "aragorn/openclaw-contained-plug01-activation-evidence/v1",
        arguments=("activate",),
    ),
    _descriptor(
        25,
        "ADM-02/reload/remote-eligibility-invalidation",
        MISSING_ADAPTER,
        _NODE,
        "protected-route-probe.mjs",
        _ROUTE_SCHEMA,
        arguments=(
            "--route-id",
            "ADM-02/reload/remote-eligibility-invalidation",
        ),
        bundle=(
            _bundle_item("protected-route-probe.mjs", "probe"),
            _bundle_item("remote-eligibility-invalidation.mjs", "adapter"),
        ),
    ),
    _descriptor(
        26,
        "ADM-02/reload/sandbox-per-run-rescan",
        MISSING_ADAPTER,
        _NODE,
        "protected-route-probe.mjs",
        _ROUTE_SCHEMA,
        arguments=("--route-id", "ADM-02/reload/sandbox-per-run-rescan"),
        bundle=(
            _bundle_item("protected-route-probe.mjs", "probe"),
            _bundle_item("sandbox-per-run-rescan.mjs", "adapter"),
        ),
    ),
    _descriptor(
        27,
        "ADM-02/reload/session-snapshot-consumer",
        CURRENT_V3,
        _NODE,
        "protected-session-snapshot-fixed-probe.mjs",
        "aragorn/openclaw-protected-session-snapshot-fixed-observation/v1",
        bundle=(
            _bundle_item("protected-session-snapshot-fixed-probe.mjs", "probe"),
            _bundle_item("protected-observation-v1.mjs", "probe-dependency"),
        ),
    ),
    _descriptor(
        28,
        "ADM-02/reload/workshop-invalidation",
        CURRENT_V3,
        _NODE,
        "protected-workshop-invalidation-v3-probe.mjs",
        "aragorn/openclaw-protected-workshop-invalidation-observation/v1",
        arguments=("--route-id", "ADM-02/reload/workshop-invalidation"),
        bundle=(
            _bundle_item("protected-workshop-invalidation-v3-probe.mjs", "probe"),
            _bundle_item("PROPOSAL.md", "fixture"),
        ),
    ),
    *(
        _descriptor(
            ordinal,
            case_id,
            V3_PORT_REQUIRED,
            _NODE,
            "adm03-probe.mjs",
            "aragorn/openclaw-contained-adm03-probe-evidence/v1",
            bundle=(
                _bundle_item("adm03-probe.mjs", "probe"),
                _bundle_item("contained-probe.mjs", "probe-dependency"),
                _bundle_item("probe.mjs", "probe-dependency"),
            ),
        )
        for ordinal, case_id in enumerate(
            ("ADM-03/policy-failure", "ADM-03/policy-tampering"),
            start=29,
        )
    ),
)
_BY_CASE_ID = {case["case_id"]: case for case in _CASES}


def openclaw_final_v3_campaign_case_ids() -> tuple[str, ...]:
    """Return the immutable canonical case order."""

    return tuple(case["case_id"] for case in _CASES)


def openclaw_final_v3_campaign_registry() -> dict[str, Any]:
    """Return a detached copy of the case inventory and provisional paths."""

    return {
        "schema": _REGISTRY_SCHEMA,
        "authority": _AUTHORITY,
        "cases": deepcopy(list(_CASES)),
        "limitations": list(_LIMITATIONS),
        "native_execution_enabled": False,
    }


def dispatch_openclaw_final_v3_campaign_case(case_id: object) -> dict[str, Any]:
    """Resolve one exact case ID to a descriptor; never execute its argv."""

    if type(case_id) is not str or case_id not in _BY_CASE_ID:
        raise CampaignDispatchError("campaign case id is not an exact registry member")
    return {
        "schema": _DISPATCH_SCHEMA,
        "authority": _AUTHORITY,
        "descriptor": deepcopy(_BY_CASE_ID[case_id]),
        "limitations": list(_LIMITATIONS),
        "native_execution_enabled": False,
    }


def openclaw_final_v3_campaign_readiness() -> dict[str, Any]:
    """Summarize implementation inventory without making a qualification claim."""

    counts = Counter(case["implementation_state"] for case in _CASES)
    remaining = [
        case["case_id"] for case in _CASES if case["implementation_state"] != CURRENT_V3
    ]
    return {
        "schema": _READINESS_SCHEMA,
        "authority": _AUTHORITY,
        "case_count": len(_CASES),
        "current_v3_case_ids": [
            case["case_id"]
            for case in _CASES
            if case["implementation_state"] == CURRENT_V3
        ],
        "case_inventory_complete": True,
        "capture_required_case_ids": [
            case["case_id"]
            for case in _CASES
            if case["implementation_state"] == V3_CAPTURE_REQUIRED
        ],
        "execution_descriptors_complete": False,
        "implementation_counts": {
            state: counts.get(state, 0) for state in _IMPLEMENTATION_STATES
        },
        "missing_adapter_case_ids": [
            case["case_id"]
            for case in _CASES
            if case["implementation_state"] == MISSING_ADAPTER
        ],
        "limitations": list(_LIMITATIONS),
        "native_execution_enabled": False,
        "ordered_case_ids": list(openclaw_final_v3_campaign_case_ids()),
        "remaining_implementation_case_ids": remaining,
        "remaining_implementation_count": len(remaining),
        "state": "CASE_INVENTORY_COMPLETE_NATIVE_EXECUTION_DISABLED",
    }


def _validate_registry() -> None:
    if len(_CASES) != 31 or len(_BY_CASE_ID) != len(_CASES):
        raise RuntimeError("fixed V3 campaign registry cardinality changed")
    capture_cases = {
        case["case_id"]
        for case in _CASES
        if case["implementation_state"] == V3_CAPTURE_REQUIRED
    }
    if capture_cases != set(_MATERIALIZER_BY_CASE):
        raise RuntimeError("fixed V3 campaign materializer registry changed")
    for ordinal, case in enumerate(_CASES):
        if set(case) != {
            "argv",
            "bundle",
            "case_id",
            "expected_schema",
            "implementation_state",
            "interpreter",
            "materializer",
            "native_execution_enabled",
            "ordinal",
        }:
            raise RuntimeError("fixed V3 campaign descriptor shape changed")
        if (
            case["ordinal"] != ordinal
            or case["implementation_state"] not in _IMPLEMENTATION_STATES
            or case["interpreter"] not in _INTERPRETERS
            or case["native_execution_enabled"] is not False
            or case["argv"][0] != case["interpreter"]
            or not re.fullmatch(r"aragorn/[a-z0-9-]+/v1", case["expected_schema"])
        ):
            raise RuntimeError("fixed V3 campaign descriptor binding changed")
        bundle_paths = [item["path"] for item in case["bundle"]]
        if (
            not bundle_paths
            or case["argv"][1] not in bundle_paths
            or len(bundle_paths) != len(set(bundle_paths))
        ):
            raise RuntimeError("fixed V3 campaign bundle binding changed")
        expected_materializer = _case_materializer(
            case["case_id"],
            str(PurePosixPath(case["argv"][1]).parent),
            case["implementation_state"],
        )
        if case["materializer"] != expected_materializer:
            raise RuntimeError("fixed V3 campaign materializer binding changed")
        for item in case["bundle"]:
            path = PurePosixPath(item["path"])
            if (
                set(item) != {"path", "role"}
                or not path.is_absolute()
                or path.parts[:3] != ("/", "campaign", "cases")
                or ".." in path.parts
                or item["role"]
                not in {"adapter", "fixture", "probe", "probe-dependency", "vector"}
            ):
                raise RuntimeError("fixed V3 campaign bundle item changed")


_validate_registry()
