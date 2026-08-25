"""Compose six exact current-contract V2 route qualifications."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_archive_replacement as archive
from . import (
    admission_protected_final_combined_v2_catalog_fixed_fresh_session_reset as fresh,
)
from . import admission_protected_final_combined_v2_config_activation as config
from . import (
    admission_protected_final_combined_v2_cron_rescan_catalog_fixed as cron,
)
from . import (
    admission_protected_final_combined_v2_prompt_rebuild_catalog_fixed as prompt,
)
from . import (
    admission_protected_final_combined_v2_session_snapshot_consumer_catalog_fixed as session,
)
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS
from .oci_worker_protocol import canonical_digest

_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_ELIGIBILITY_KEYS = config.base.legacy.parent._ELIGIBILITY_KEYS
_SHARED_BINDINGS = ("configuration", "profile", "runtime_lock", "skill", "runtime")
_VERIFIER_PATH = "src/aragorn/admission_protected_final_combined_v2_route_coverage.py"
_EXPECTED_SHARED_BINDINGS = {
    "configuration": {
        "bytes": 1_881,
        "canonical_bytes": 1_880,
        "canonical_digest": (
            "sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
        ),
        "digest": (
            "sha256:d145feb4e935e6f86c7e2bfdeefcaec5fa4ebf8f044ffa472bd7589b03bf4fe8"
        ),
    },
    "profile": {
        "bytes": 4_951,
        "canonical_bytes": 4_950,
        "canonical_digest": (
            "sha256:a20ab2dd6572ada5fac086bc818495a6e6079f55f6fcbae397687c7b19eac59e"
        ),
        "digest": (
            "sha256:615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc"
        ),
    },
    "runtime_lock": {
        "bytes": 6_742,
        "canonical_bytes": 6_741,
        "canonical_digest": (
            "sha256:95f6088dfe227e27e136c7a1fb79688e0afa0ea3ac543137d7089d0a79f2eff9"
        ),
        "digest": (
            "sha256:4832dc99c016bd8c0f6d97133dbb7d3681d4ad18c1c225c94f10a51d6df839c1"
        ),
    },
    "skill": {
        "bytes": 140,
        "digest": (
            "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
        ),
    },
    "runtime": {
        "entrypoint_digest": (
            "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
        ),
        "runtime_digest": (
            "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154"
        ),
        "runtime_volume": "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1",
        "version_output": "OpenClaw 2026.7.1 (7fa98d8)",
    },
}
_EXPECTED_RUNTIME = {
    "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
    "name": "openclaw-protected-final-combined-v2",
    "source_parent_commit": "805a4b152b0cee271ee78ad5608c15a4f8d1624b",
    "source_tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
    "upstream_base_commit": "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
    "version": "2026.7.1",
}
_ROUTES = (
    "ADM-02/update/archive-source-force-replacement",
    "ADM-02/update/clawhub-tracked-replacement",
    "ADM-02/update/config-entry-activation",
    "ADM-02/update/core-updater-plugin-replacement",
    "ADM-02/update/curator-restore-activation",
    "ADM-02/update/plugin-enable-activation",
    "ADM-02/update/plugin-force-reinstall",
    "ADM-02/update/plugin-package-skill-replacement",
    "ADM-02/update/workshop-proposal-apply",
    "ADM-02/reload/chat-session-snapshot-consumer",
    "ADM-02/reload/config-invalidation",
    "ADM-02/reload/cron-rescan",
    "ADM-02/reload/filesystem-watch-invalidation",
    "ADM-02/reload/fresh-session-reset",
    "ADM-02/reload/manual-plugin-invalidation",
    "ADM-02/reload/missing-prompt-blob-rebuild",
    "ADM-02/reload/plugin-skill-dir-activation",
    "ADM-02/reload/remote-eligibility-invalidation",
    "ADM-02/reload/sandbox-per-run-rescan",
    "ADM-02/reload/session-snapshot-consumer",
    "ADM-02/reload/workshop-invalidation",
)
_EXPECTED_PASS_ROUTES = frozenset(
    {
        config._ROUTE,
        fresh._ROUTE,
        cron._ROUTE,
        prompt._ROUTE,
        session._ROUTE,
        archive._ROUTE,
    }
)
_CHILDREN = (
    {
        "name": "config_entry_activation",
        "module": config,
        "verifier": "verify_openclaw_final_combined_v2_config_activation",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_config_activation.py"
        ),
        "verifier_digest": (
            "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6"
        ),
        "result_digest": (
            "sha256:488e8fb5dd5e1664f690af4f5740ab05f8ffcccb70ea1f988f75d5a899a11351"
        ),
        "route": config._ROUTE,
        "image": config._IMAGE,
    },
    {
        "name": "catalog_fixed_fresh_session_reset",
        "module": fresh,
        "verifier": (
            "verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset"
        ),
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_catalog_fixed_"
            "fresh_session_reset.py"
        ),
        "verifier_digest": (
            "sha256:dfea26baa270b7b1aecfa1e40838618d9ab4aa7f6e1d5ef006e5dfee1533b1dd"
        ),
        "result_digest": (
            "sha256:006e169cb8f45ba5d364b9402b3a44b58e45df19390859939d6884ead89708c5"
        ),
        "route": fresh._ROUTE,
        "image": fresh._IMAGE,
    },
    {
        "name": "catalog_fixed_cron_rescan",
        "module": cron,
        "verifier": "verify_openclaw_final_combined_v2_cron_rescan_catalog_fixed",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_cron_rescan_"
            "catalog_fixed.py"
        ),
        "verifier_digest": (
            "sha256:685e8e17d15f107f66a8864ee0d19ae2fce995d98049c2e6d1eb4331b850d3b5"
        ),
        "result_digest": (
            "sha256:1f00f61957d12325b329dea4ca9cdb8f3f8aa3012380f430b1b358300868799b"
        ),
        "route": cron._ROUTE,
        "image": cron._IMAGE,
    },
    {
        "name": "catalog_fixed_prompt_rebuild",
        "module": prompt,
        "verifier": "verify_openclaw_final_combined_v2_prompt_rebuild_catalog_fixed",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_prompt_rebuild_"
            "catalog_fixed.py"
        ),
        "verifier_digest": (
            "sha256:df9623c4ff226b070f7cfed903a79d86a4eef0ad757114e61847709485b3ac2e"
        ),
        "result_digest": (
            "sha256:54f0132b56b31a1e3f3f07e58b9e0794fc32c2cbd44c35e718e1e7c8c5919869"
        ),
        "route": prompt._ROUTE,
        "image": prompt._IMAGE,
    },
    {
        "name": "catalog_fixed_session_snapshot_consumer",
        "module": session,
        "verifier": (
            "verify_openclaw_final_combined_v2_session_snapshot_consumer_catalog_fixed"
        ),
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_session_snapshot_"
            "consumer_catalog_fixed.py"
        ),
        "verifier_digest": (
            "sha256:9f8c14d6c109bf0b2d686c354af64b0d65dd70ac5a34f405051f37bfa55dfcfa"
        ),
        "result_digest": (
            "sha256:a8b82efd6195ece5f00d2770c6778378305017318017d4d2419fd524f77d3315"
        ),
        "route": session._ROUTE,
        "image": session._IMAGE,
    },
    {
        "name": "archive_post_write_activation_prevention",
        "module": archive,
        "verifier": "verify_openclaw_final_combined_v2_archive_replacement",
        "verifier_path": (
            "src/aragorn/admission_protected_final_combined_v2_archive_replacement.py"
        ),
        "verifier_digest": (
            "sha256:c31d209c5ea7af4181396bcdeb8a4e54d965ed793ba4fc4be489cd69e460602e"
        ),
        "result_digest": (
            "sha256:b1ca41a414eb51c47620e4eee26f739f99e7ff19e924c3a0798af55fa8f42d58"
        ),
        "route": archive._ROUTE,
        "image": archive._IMAGE,
    },
)
_EXPECTED_CHILD_SEQUENCE = (
    (
        "config_entry_activation",
        config._ROUTE,
        "src/aragorn/admission_protected_final_combined_v2_config_activation.py",
    ),
    (
        "catalog_fixed_fresh_session_reset",
        fresh._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_catalog_fixed_"
            "fresh_session_reset.py"
        ),
    ),
    (
        "catalog_fixed_cron_rescan",
        cron._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_cron_rescan_"
            "catalog_fixed.py"
        ),
    ),
    (
        "catalog_fixed_prompt_rebuild",
        prompt._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_prompt_rebuild_"
            "catalog_fixed.py"
        ),
    ),
    (
        "catalog_fixed_session_snapshot_consumer",
        session._ROUTE,
        (
            "src/aragorn/admission_protected_final_combined_v2_session_snapshot_"
            "consumer_catalog_fixed.py"
        ),
    ),
    (
        "archive_post_write_activation_prevention",
        archive._ROUTE,
        "src/aragorn/admission_protected_final_combined_v2_archive_replacement.py",
    ),
)


def compose_openclaw_final_combined_v2_route_coverage(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Reverify and compose six separate exact child captures without authority."""

    children: list[dict[str, Any]] = []
    names: set[str] = set()
    pass_routes: set[str] = set()
    shared: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None

    try:
        child_sequence = tuple(
            (child["name"], child["route"], child["verifier_path"])
            for child in _CHILDREN
        )
        if child_sequence != _EXPECTED_CHILD_SEQUENCE:
            raise AdmissionEvidenceError("exact ordered V2 child inventory changed")
        for child in _CHILDREN:
            name = child["name"]
            route = child["route"]
            module = child["module"]
            if name in names or route in pass_routes:
                raise AdmissionEvidenceError("duplicate V2 child qualification")
            names.add(name)
            pass_routes.add(route)

            module_path = Path(module.__file__).resolve()
            if (
                not module_path.as_posix().endswith(child["verifier_path"])
                or _digest(module_path.read_bytes()) != child["verifier_digest"]
            ):
                raise AdmissionEvidenceError(f"{name} verifier implementation drifted")

            result = getattr(module, child["verifier"])(evidence_cas=evidence_cas)
            if canonical_digest(result) != child["result_digest"]:
                raise AdmissionEvidenceError(f"{name} canonical result drifted")
            _verify_child(result, child)

            child_shared = {key: result["bindings"][key] for key in _SHARED_BINDINGS}
            if shared is None:
                shared = child_shared
                runtime = result["runtime"]
            elif child_shared != shared or result["runtime"] != runtime:
                raise AdmissionEvidenceError(
                    "V2 child shared contract binding mismatch"
                )

            children.append(
                {
                    "image": result["bindings"]["image"],
                    "name": name,
                    "result_canonical_digest": child["result_digest"],
                    "route": route,
                    "source_recorded_at": result["source_recorded_at"],
                    "verifier": {
                        "digest": child["verifier_digest"],
                        "path": child["verifier_path"],
                    },
                }
            )
    except AdmissionEvidenceError:
        raise
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(f"invalid V2 child qualification: {exc}") from exc

    if pass_routes != _EXPECTED_PASS_ROUTES or len(children) != 6:
        raise AdmissionEvidenceError("exact six V2 child routes are required")
    if shared is None or runtime is None:
        raise AdmissionEvidenceError("V2 child contract bindings are missing")
    implementation_digest = _digest(Path(__file__).resolve().read_bytes())

    qualification_digests = {
        child["route"]: child["result_canonical_digest"] for child in children
    }
    routes = [
        {
            "id": route,
            "qualification_digest": qualification_digests.get(route),
            "status": "PASS" if route in pass_routes else "NOT_TESTED",
        }
        for route in _ROUTES
    ]
    return {
        "schema": ("aragorn/admission-protected-final-combined-v2-route-coverage/v1"),
        "assurance": (
            "SIX_EXACT_INDEPENDENTLY_REVERIFIED_SEPARATE_CAPTURE_ROUTE_PASSES_ONLY"
        ),
        "bindings": {
            **{key: dict(shared[key]) for key in _SHARED_BINDINGS},
            "child_qualifications": children,
            "verifier_implementation_digest": implementation_digest,
            "verifier_source_path": _VERIFIER_PATH,
        },
        "capture_model": {
            "aggregate_execution_observed": False,
            "kind": "SIX_SEPARATE_EXACT_CHILD_CAPTURES",
            "same_image_required": False,
        },
        "decision": {
            "status": "PARTIAL_SEPARATE_CAPTURE_V2_ROUTE_COVERAGE",
            **{key: False for key in _ELIGIBILITY_KEYS},
        },
        "limitations": [
            "SIX_EXACT_SEPARATE_CAPTURE_ROUTE_PASSES_COMPOSED",
            "FIFTEEN_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "SEPARATE_CAPTURES_DO_NOT_ESTABLISH_AGGREGATE_ADMISSION",
            "SESSION_SNAPSHOT_COMPILED_CLOSURE_ACQUISITION_PRE_ROUTE_ONLY",
            "NO_POST_ROUTE_SESSION_CLOSURE_PROVENANCE_OR_CONTINUOUS_IMMUTABILITY_CLAIM",
            "SESSION_SNAPSHOT_DETERMINISTIC_COMPILED_REPLAY_NOT_NATIVE_AGENT_EXECUTION",
            "SESSION_SNAPSHOT_NATIVE_MODEL_ATTEMPTS_ENDED_IN_EXPECTED_NETWORK_ERROR",
            "SESSION_SNAPSHOT_NATIVE_PROVIDER_REQUEST_BODY_AND_SYSTEM_PROMPT_REPORT_NOT_OBSERVED",
            "SESSION_SNAPSHOT_FOURTEEN_SELECTED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "SESSION_SNAPSHOT_COMPILED_CLOSURE_REUSED_FROM_PRIOR_DIFFERENT_IMAGE_CAPTURE",
            "SESSION_SNAPSHOT_LOCAL_DOCKER_VOLUME_NOT_INDEPENDENTLY_ATTESTED",
            "SESSION_SNAPSHOT_ORIGINAL_PROVIDER_REQUEST_AND_SESSION_STORE_RAW_BYTES_NOT_RETAINED",
            "ARCHIVE_DIRECTORY_INSTALL_LEFT_EXCLUDED_WORKSPACE_SKILL_RESIDUE",
            "ARCHIVE_POST_WRITE_CATALOG_REJECTION_MAY_DENY_SKILL_DISCOVERY_AVAILABILITY",
            "NO_PRE_EFFECT_OR_NO_MUTATION_CLAIM_FOR_ARCHIVE_ROUTE",
            "SEPARATE_EXACT_CHILD_IMAGE_IDS_RETAINED_NOT_UNIFIED",
            "NO_AGGREGATE_ADMISSION_EDR_PHASE3_RELEASE_OR_INSTALLER_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 6, "NOT_TESTED": 15},
            "name": _PROFILE,
            "route_inventory_canonical_digest": canonical_digest(list(_ROUTES)),
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [
                route for route in _ROUTES if route in pass_routes
            ],
            "transitions_dynamically_exercised_in_one_aggregate_execution": False,
        },
        "runtime": dict(runtime),
    }


def _verify_child(result: Mapping[str, Any], child: Mapping[str, Any]) -> None:
    route = child["route"]
    expected_routes = [
        {"id": route_id, "status": "PASS" if route_id == route else "NOT_TESTED"}
        for route_id in _ROUTES
    ]
    expected_decision = {
        "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
        **{key: False for key in _ELIGIBILITY_KEYS},
    }
    counts = result["profile"]["counts"]
    decision = result["decision"]
    shared = {key: result["bindings"][key] for key in _SHARED_BINDINGS}
    if (
        set(counts) != {"PASS", "NOT_TESTED"}
        or type(counts["PASS"]) is not int
        or type(counts["NOT_TESTED"]) is not int
        or result["profile"]
        != {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": expected_routes,
        }
        or set(decision) != set(expected_decision)
        or decision["status"] != expected_decision["status"]
        or any(decision[key] is not False for key in _ELIGIBILITY_KEYS)
        or shared != _EXPECTED_SHARED_BINDINGS
        or result["runtime"] != _EXPECTED_RUNTIME
        or result["bindings"]["image"] != child["image"]
        or result["bindings"]["verifier_implementation_digest"]
        != child["verifier_digest"]
        or result["route_semantics"]["dynamically_exercised_routes"] != [route]
        or result["route_semantics"]["transitions_dynamically_exercised"] is not True
    ):
        raise AdmissionEvidenceError(
            f"{child['name']} route, decision, or runtime binding changed"
        )


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
