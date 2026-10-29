"""Verify and qualify one dedicated V3 workshop-invalidation subfixture."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import runpy
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from . import admission_protected_final_combined_v3_workshop_proposal_apply as parent
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

_ROUTE = "ADM-02/reload/workshop-invalidation"
_ACTION = "workshop-invalidation"
_SCHEMA = "aragorn/openclaw-protected-workshop-invalidation-observation/v1"
_PROBE_DIGEST = (
    "sha256:d987ab8e17caa527786486f8440d194bec6e8b441386fd0f85100e3d33459334"
)
_PROPOSAL_DIGEST = (
    "sha256:a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a"
)
_ELIGIBILITY_KEYS = (
    "admission_profile_eligible",
    "aggregate_admission_eligible",
    "edr_eligible",
    "installer_work_eligible",
    "phase3_exit_eligible",
    "release_eligible",
    "run_01_eligible",
    "run_02_eligible",
    "run_eligible",
)
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
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
    _ROUTE,
)
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = (
    "aragorn-phase3-final-combined-v3-workshop-invalidation-route-input-18227"
)
_IMAGE = "sha256:865b39ac8631240fe6c493fe300d5a1bedfa339f38db94c4d54ff417fa782e29"
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()
_EVIDENCE = {
    "bytes": 581_618,
    "canonical_bytes": 581_617,
    "canonical_digest": (
        "sha256:dcd4b1f701a069f08dcd2ffc905ee0b8501fa02e8b989e3cc52cf6c0d89887de"
    ),
    "digest": "sha256:35c48bd6552d15682b8c500f540212d1e1deab8533edbfcc0c2188476ffff3c6",
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
        "workshop-invalidation-systemd-p3-final-2026-09-01.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 48_092,
    "canonical_digest": (
        "sha256:60d6fd35efc250fe06a59388f0c6122c389c71d31524aa83fa79cdd124a99572"
    ),
    "digest": "sha256:c245f6810bca0cacae417fdbe1b0a298763689cbe940f52c6dc4b141ab0c3d44",
}
_SOURCE = {
    "commit": "276d5f3a6a33f4cf5ddfccaa800486d73682358a",
    "parent": "06ac7ec5e119e5f52b04b6a5f605ac52642cd3ad",
    "tree": "076f827c359622dba6401831280e3baa608f84aa",
}
_RETENTION = {
    "commit": "63b36792758ed9e7d0c0adfbb0b50fd44ccf77f7",
    "parent": _SOURCE["commit"],
    "tree": "663ae8cecde4ea61360125d46dcf8da0d58d6159",
}
_RETENTION_BLOB = "717da066704aae7e7e6a96cdd96c09049776d0e9"
_VERIFIER_BASE = {
    "blob": "b65996bee83f182270fee8425d798a468044e592",
    "bytes": 84_088,
    "digest": "sha256:6e43aef6ca014100e5c192d414c3616528c2004195e20cb90fc9cd22f2c5cad8",
    "path": (
        "src/aragorn/"
        "admission_protected_final_combined_v3_workshop_proposal_apply.py"
    ),
}
_COMPONENT_DIGESTS = {
    "composition": "sha256:1da4431d1604c967f02bb6432b178a72c201a2816551585728cd8d670211f570",
    "decision": "sha256:afe6fa23eced0be345c3982bad9dd8f090ff92f80c10acc62c9b274ab835eac0",
    "harness": "sha256:f1a0d148c475698ae9d345b80738915eac6f04ff95b8a030dcff4a7e2a4dca4a",
    "limitations": "sha256:fdc8a565e5665138f9185b50aef9c5ad7ea2112cf57b9abe7b3343bd07ca4760",
    "route_observation": (
        "sha256:7dbfffd3bd205a0eceb78fd429a221ed50a527eb3c66697ac10beae7b37375bd"
    ),
    "source_artifacts": (
        "sha256:1bcd26c07d9245991e47daa86682ba7d6268ef215dd2941335a3c49a2a1a05bb"
    ),
}
_CAPTURE_SOURCES = {
    "capture_recipe": (
        "100755",
        "6554b1eb4a55a7c15fae19f2ef4abbd943d13621",
        2_818,
        "sha256:0aab169f990453a1de2a3529ae63e598ae7ca355201dee1357a66f6bdddc6495",
        "scripts/capture_runtime_action_worker_final_combined_v3_workshop_invalidation_systemd.sh",
    ),
    "inherited_capture_recipe": (
        "100755",
        "d668f6dc0490115dc2d945241ae3902c88a5d442",
        26_603,
        "sha256:a4f03cf2788f097d556be2b6ef93d758d6b12622a292a530784599d20b00ae96",
        "scripts/capture_runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd.sh",
    ),
    "dockerfile": (
        "100644",
        "10c89038d0886ee4ad51d885a2d2ca715d17152d",
        5_269,
        "sha256:ab4f3098b94f167af4e637253d1c11a93a986af8942f0f1a70eb17d0d9cf5fea",
        "benchmark/runtime-action-worker-final-combined-v3-workshop-invalidation-systemd/Dockerfile",
    ),
}
_SOURCE_ARTIFACTS = {
    "checked_in_probe": dict(parent._SOURCE_ARTIFACTS["checked_in_probe"]),
    "checked_in_proposal": dict(parent._SOURCE_ARTIFACTS["checked_in_proposal"]),
    "collector": {
        "bytes": 12_743,
        "digest": "sha256:57126ab37e697ee693281dbf517f19333ce62b12bc8ab627f97cb307ee53d771",
        "mode": "0555",
        "path": (
            "scripts/runtime_action_worker_final_combined_v3_"
            "workshop_invalidation_systemd_probe.py"
        ),
    },
    "dedicated_materializer": {
        "bytes": 8_612,
        "digest": "sha256:d60da66234d68f180e19e61f74f16a8ce9422221015f726fa9b839549edd06fc",
        "mode": "0555",
        "path": "scripts/materialize_openclaw_final_v3_workshop_invalidation_probe.py",
    },
    "inherited_combined_base": dict(
        parent._SOURCE_ARTIFACTS["inherited_combined_base"]
    ),
    "inherited_route_injector": dict(
        parent._SOURCE_ARTIFACTS["inherited_route_injector"]
    ),
    "inherited_v3_contract_base": dict(
        parent._SOURCE_ARTIFACTS["inherited_v3_contract_base"]
    ),
    "inherited_workshop_proposal_collector": dict(
        parent._SOURCE_ARTIFACTS["collector"]
    ),
    "materializer": dict(parent._SOURCE_ARTIFACTS["materializer"]),
}
_DOCUMENT_KEYS = {
    "actions",
    "assurance",
    "implementation_digest",
    "protected_boundary",
    "recorded_at",
    "routes",
    "run_nonce",
    "runtime_binding",
    "schema",
    "selected_route_ids",
}
_ACTION_KEYS = {
    "commands",
    "execution_error",
    "id",
    "observations",
    "prerequisites",
    "reason_codes",
    "status",
}
_OBSERVATION_KEYS = {
    "catalog_after_apply",
    "catalog_after_apply_excludes_workshop",
    "catalog_after_apply_matches_initial",
    "catalog_before",
    "final_catalog",
    "final_catalog_matches_initial",
    "final_same_session_catalog_exact",
    "final_snapshot",
    "final_snapshot_check",
    "final_snapshot_observed_at",
    "final_snapshot_transition",
    "immediate_post_apply_same_session",
    "immediate_post_apply_snapshot",
    "immediate_post_apply_snapshot_check",
    "immediate_post_apply_snapshot_observed_at",
    "immediate_post_apply_store_unchanged",
    "initial_snapshot",
    "initial_snapshot_check",
    "initial_snapshot_observed_at",
    "initial_turn",
    "native_apply_result",
    "native_proposal_result",
    "next_same_session_turn",
    "proposal_result",
    "target_after_apply",
    "target_after_apply_observed_at",
    "target_after_proposal",
    "target_after_proposal_observed_at",
    "target_final",
}


def qualify_openclaw_final_v3_workshop_invalidation_subfixture(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one exact dedicated route PASS without campaign authority."""

    try:
        _verify_dependencies()
        retained = _verify_signed_capture_sources()
        contract = parent.v3_contract.contract
        raw = contract._read_blob(
            evidence_cas, _EVIDENCE, "V3 workshop-invalidation subfixture"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 workshop-invalidation CAS differs from signed retention"
            )
        evidence = contract._load_canonical_json(
            raw, _EVIDENCE, "V3 workshop-invalidation subfixture"
        )
        semantic, profile = _verify_dedicated_evidence(evidence)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid dedicated V3 workshop-invalidation evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED",
        }
        for route in profile["routes"]
    ]
    artifacts = evidence["source_artifacts"]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v3-workshop-"
            "invalidation-dedicated-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SIGNED_DEDICATED_PRIVATE_CURRENT_V3_WORKSHOP_"
            "INVALIDATION_ROUTE_ONLY"
        ),
        "bindings": {
            "capture_protocol": {
                name: {"bytes": item[2], "digest": item[3], "path": item[4]}
                for name, item in _CAPTURE_SOURCES.items()
            },
            "image": _IMAGE,
            "parent_image": _PARENT_IMAGE,
            "semantic_compatibility_canonical_digest": canonical_digest(semantic),
            "source_artifacts": {
                name: {
                    "bytes": artifacts[name]["bytes"],
                    "digest": artifacts[name]["digest"],
                    "path": artifacts[name]["path"].removeprefix("/src/"),
                }
                for name in sorted(_SOURCE_ARTIFACTS)
            },
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
            "workshop_invalidation_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": parent.v3_contract.contract._SIGNATURE[
                        "key"
                    ],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(
                        parent.v3_contract.contract._SIGNATURE
                    ),
                },
            },
        },
        "capture": {
            "cleanup_protocol_verified": True,
            "dedicated_route_container": True,
            "dedicated_route_volume": True,
            "independent_from_regression_oracle": True,
            "independent_host_destruction_attestation": False,
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE",
            **{key: False for key in _ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_WORKSHOP_INVALIDATION_PASS_ONLY",
            "TWENTY_OTHER_V3_PROFILE_ROUTES_NOT_TESTED",
            "DEDICATED_ROUTE_CAPTURE_NOT_FINAL_CAMPAIGN_SUBFIXTURE_EVIDENCE",
            "PINNED_CAPTURE_RECIPE_CLEANUP_NOT_INDEPENDENT_HOST_ATTESTATION",
            "PROPOSAL_APPLY_IS_PREREQUISITE_TO_INVALIDATION_OBSERVATION",
            "BLACK_BOX_NEXT_TURN_DERIVATION_NO_DIRECT_INVALIDATION_FUNCTION_TRACE",
            "NO_MODEL_PROVIDER_REQUEST_SUCCESS_OR_DELIVERY_CLAIM",
            "NO_CLEANUP_ROLLBACK_QUARANTINE_OR_GENERAL_ROUTE_CLAIM",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 1, "NOT_TESTED": len(routes) - 1},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "native_independent_route_execution": True,
            "pass_basis": (
                "SIGNED_DEDICATED_CURRENT_V3_POST_APPLY_NEXT_SAME_SESSION_"
                "PROTECTED_SNAPSHOT_AND_STORE_TRANSITION"
            ),
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(evidence["route_observation"]["document"]["runtime_binding"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _probe_bundle() -> list[dict[str, Any]]:
    return [
        {
            "bytes": 84,
            "digest": _PROPOSAL_DIGEST,
            "name": "PROPOSAL.md",
            "role": "fixture",
        },
        {
            "bytes": 48_609,
            "digest": _PROBE_DIGEST,
            "name": "protected-workshop-invalidation-v3-probe.mjs",
            "role": "probe",
        },
    ]


def _verify_dependencies() -> None:
    root = Path(__file__).resolve(strict=True).parents[2]
    path = Path(parent.__file__).resolve(strict=True)
    expected = (root / _VERIFIER_BASE["path"]).resolve(strict=True)
    git = parent.v3_contract.config.base.legacy._git
    raw = _read_signed_blob(
        git,
        commit=_SOURCE["commit"],
        mode="100644",
        blob=_VERIFIER_BASE["blob"],
        bytes_=_VERIFIER_BASE["bytes"],
        digest=_VERIFIER_BASE["digest"],
        path=_VERIFIER_BASE["path"],
    )
    if (
        path != expected
        or path.read_bytes() != raw
        or tuple(parent.v3_contract.contract._ROUTES) != _ROUTES
        or tuple(parent.v3_contract.contract._ELIGIBILITY_KEYS) != _ELIGIBILITY_KEYS
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation verifier dependency changed"
        )
    parent._verify_dependencies()


def _verify_signed_capture_sources() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = parent.v3_contract.config.base.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation qualification repository changed"
        )
    parent.v3_contract.config.base._verify_commit(_SOURCE)
    parent.v3_contract.config.base._verify_commit(_RETENTION)
    retained = _read_signed_blob(
        git,
        commit=_RETENTION["commit"],
        mode="100644",
        blob=_RETENTION_BLOB,
        bytes_=_EVIDENCE["bytes"],
        digest=_EVIDENCE["digest"],
        path=_EVIDENCE["path"],
    )
    for mode, blob, bytes_, digest, path in _CAPTURE_SOURCES.values():
        _read_signed_blob(
            git,
            commit=_SOURCE["commit"],
            mode=mode,
            blob=blob,
            bytes_=bytes_,
            digest=digest,
            path=path,
        )
    return retained


def _read_signed_blob(
    git: Any,
    *,
    commit: str,
    mode: str,
    blob: str,
    bytes_: int,
    digest: str,
    path: str,
) -> bytes:
    entry = git(["ls-tree", "-z", "--full-name", commit, "--", path])
    expected = f"{mode} blob {blob}\t{path}".encode() + b"\0"
    raw = git(["cat-file", "blob", blob], maximum=bytes_ + 1)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        entry != expected
        or oid != blob
        or len(raw) != bytes_
        or _digest(raw) != digest
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation signed source blob changed"
        )
    return raw


def _verify_dedicated_evidence(
    evidence: Mapping[str, Any],
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    if type(evidence) is not dict:
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation dedicated evidence must be an object"
        )
    parent._verify_scalar_types(evidence)
    parent.v3_contract.config._verify_no_positive_eligibility(evidence)
    keys = {
        "authority",
        "composition",
        "decision",
        "harness",
        "limitations",
        "recorded_at",
        "route_id",
        "route_observation",
        "schema",
        "source_artifacts",
    }
    if (
        set(evidence) != keys
        or evidence["schema"]
        != (
            "aragorn/runtime-action-worker-final-combined-v3-workshop-"
            "invalidation-systemd-observation/v1"
        )
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V3_RAW_WORKSHOP_INVALIDATION_OBSERVATION_"
            "ONLY_NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY"
        )
        or evidence["route_id"] != _ROUTE
        or evidence["recorded_at"] != "2026-09-01T17:23:39.482951Z"
        or any(
            canonical_digest(evidence[name]) != digest
            for name, digest in _COMPONENT_DIGESTS.items()
        )
        or evidence["decision"]
        != {
            "admission_profile_eligible": False,
            "aggregate_admission_eligible": False,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            "route_observation_status": "OBSERVED",
            "route_pass_count": 0,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "run_eligible": False,
            "status": (
                "FINAL_COMBINED_V3_WORKSHOP_INVALIDATION_OBSERVED_PROFILE_"
                "NOT_TESTED"
            ),
        }
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation dedicated envelope changed"
        )
    profile, config = _verify_composition(
        evidence["composition"], evidence["source_artifacts"], evidence["harness"]
    )
    _verify_harness(evidence["harness"])
    document = _verify_route_observation(
        evidence["route_observation"],
        evidence,
        boundaries=evidence["composition"]["action"]["boundaries"],
        config=config,
    )
    signed = _verify_source_artifacts(evidence["source_artifacts"])
    _verify_materialization(
        evidence["source_artifacts"],
        evidence["composition"]["action"]["artifacts"][
            "final_combined_v3_workshop_invalidation"
        ],
        signed,
    )
    semantic = verify_openclaw_final_v3_workshop_invalidation_semantic_compatibility(
        document
    )
    return semantic, profile


def _verify_composition(
    composition: Mapping[str, Any],
    source_artifacts: Mapping[str, Any],
    harness: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    action = composition["action"]
    artifacts = action["artifacts"]
    inherited = artifacts["final_combined_v3_workshop_proposal_apply"]
    dedicated = artifacts["final_combined_v3_workshop_invalidation"]
    profile = inherited["profile"]["document"]
    if (
        set(composition)
        != {
            "action",
            "authority",
            "bindings",
            "decision",
            "limitations",
            "profile",
            "recorded_at",
            "schema",
        }
        or composition["schema"]
        != (
            "aragorn/runtime-action-worker-final-combined-v3-workshop-"
            "invalidation-systemd-observation/v1"
        )
        or composition["authority"]
        != (
            "BOUND_FINAL_COMBINED_V3_RAW_WORKSHOP_INVALIDATION_OBSERVATION_"
            "ONLY_NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY"
        )
        or composition["recorded_at"] != "2026-09-01T17:23:39.482914Z"
        or composition["decision"]
        != {
            "admission_profile_eligible": False,
            "aggregate_admission_eligible": False,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "p3_7c_activation_action_observed": True,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            "route_pass_count": 0,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "run_eligible": False,
            "status": "FINAL_COMBINED_V3_ACTION_OBSERVED_PROFILE_NOT_TESTED",
        }
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": parent.v3_contract.config._RUNTIME_TREE["tree_digest"],
            "runtime_volume": _RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": parent.v3_contract.config._SOURCES["skill"]["digest"],
        }
        or set(artifacts)
        != {
            "collector",
            "final_combined_v3_workshop_invalidation",
            "final_combined_v3_workshop_proposal_apply",
            "installed",
            "installed_closure_digest",
            "obsolete_shims_absent",
            "plugin",
            "worker_installer",
        }
        or composition["profile"]["before"] != composition["profile"]["after"]
        or composition["profile"]["before"]["document"] != profile
        or composition["profile"]["before"]["outcomes"]
        != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]] != list(_ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile["runtime"]
        != {
            **parent.v3_contract.contract._OPENCLAW,
            "name": "openclaw-protected-final-combined-v3",
        }
        or action["inputs"]["gateway_config"] != inherited["config"]["document"]
        or action["harness"] != harness
        or action["identities"]
        != {
            "broker": {"gid": 997, "uid": 995},
            "gateway": {"gid": 992, "uid": 992},
            "sensor": {"gid": 996, "uid": 996},
            "worker": {"gid": 997, "uid": 997},
        }
        or action["secret_checks"]
        != {
            "forbidden_driver_fields": [],
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
            "provider_and_gateway_token_values_retained": False,
        }
        or action["runtime"]
        != {
            "entrypoint": parent._OPENCLAW,
            "entrypoint_digest": parent.v3_contract.contract._RUNTIME[
                "entrypoint_digest"
            ],
            "expected_version": parent.v3_contract.contract._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": parent.v3_contract.config._RUNTIME_TREE,
            "version_output": parent.v3_contract.contract._RUNTIME["version_output"],
        }
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation dedicated composition changed"
        )
    parent.v3_contract.parent._verify_contract_artifacts(inherited)
    _verify_dedicated_artifact(dedicated, source_artifacts, inherited)
    return profile, action["inputs"]["gateway_config"]


def _verify_dedicated_artifact(
    artifact: Mapping[str, Any],
    source_artifacts: Mapping[str, Any],
    inherited: Mapping[str, Any],
) -> None:
    if (
        set(artifact)
        != {
            "collector",
            "inherited_workshop_proposal_apply",
            "materializer",
            "probe",
            "proposal_fixture",
        }
        or artifact["inherited_workshop_proposal_apply"] != inherited
        or artifact["materializer"] != source_artifacts["dedicated_materializer"]
        or artifact["probe"]["materialized_source"]
        != source_artifacts["transformed_probe"]
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation dedicated artifact changed"
        )
    file_record = parent.v3_contract.enable_route._verify_file_record
    collector = artifact["collector"]
    if set(collector) != {"capture_recipe", "dockerfile", "probe"}:
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation collector artifact changed"
        )
    for name, mode in (("capture_recipe", "0555"), ("dockerfile", "0444")):
        expected = _CAPTURE_SOURCES[name]
        file_record(
            collector[name],
            path=f"/src/{expected[4]}",
            bytes_=expected[2],
            digest=expected[3],
            mode=mode,
            label=f"workshop invalidation {name}",
        )
    expected_collector = _SOURCE_ARTIFACTS["collector"]
    file_record(
        collector["probe"],
        path=f"/src/{expected_collector['path']}",
        bytes_=expected_collector["bytes"],
        digest=expected_collector["digest"],
        mode="0555",
        label="workshop invalidation collector probe",
    )
    for record, path, bytes_, digest, label in (
        (
            artifact["probe"]["runtime"],
            (
                "/route-input/workshop-invalidation/"
                "protected-workshop-invalidation-v3-probe.mjs"
            ),
            48_609,
            _PROBE_DIGEST,
            "runtime probe",
        ),
        (
            artifact["proposal_fixture"],
            "/route-input/workshop-invalidation/PROPOSAL.md",
            84,
            _PROPOSAL_DIGEST,
            "runtime proposal",
        ),
    ):
        file_record(
            record,
            path=path,
            bytes_=bytes_,
            digest=digest,
            mode="0444",
            label=f"workshop invalidation {label}",
        )


def _verify_harness(envelope: Mapping[str, Any]) -> None:
    contract = parent.v3_contract.contract
    document = envelope["document"]
    file = envelope["file"]
    raw = base64.b64decode(file["base64"], validate=True)
    parsed = json.loads(
        raw.decode(),
        object_pairs_hook=contract._reject_duplicates,
        parse_constant=contract._reject_constant,
    )
    lineage = document["image_lineage"]
    container_id = document["container_id"]
    route_labels = document["route_input_volume_identity"]["labels"]
    verification = document["source_commit_verification"]
    commit_file = verification["commit_object"]
    commit_raw = base64.b64decode(commit_file["base64"], validate=True)
    git = parent.v3_contract.config.base.legacy._git
    if (
        set(envelope) != {"digest", "document", "file"}
        or parsed != document
        or raw != canonical_json(document)
        or envelope["digest"] != _digest(raw)
        or file["digest"] != _digest(raw)
        or file["bytes"] != len(raw)
        or file["path"] != "/run/aragorn-harness.json"
        or file["stat"]["uid"] != 0
        or file["stat"]["gid"] != 0
        or file["stat"]["mode"] != "0600"
        or file["stat"]["nlink"] != 1
        or file["stat"]["size"] != len(raw)
        or file["stat"]["type"] != "file"
        or document["schema"]
        != (
            "aragorn/runtime-action-worker-final-combined-v3-workshop-"
            "invalidation-systemd-harness/v1"
        )
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["platform"] != "linux"
        or document["openclaw_runtime_volume"] != _RUNTIME_VOLUME
        or document["openclaw_runtime_mount"]["source"] != _RUNTIME_VOLUME
        or document["openclaw_runtime_mount"]["rw"] is not False
        or document["route_input_mount"]["source"] != _ROUTE_VOLUME
        or document["route_input_mount"]["rw"] is not False
        or document["route_input_volume_identity"]["name"] != _ROUTE_VOLUME
        or route_labels
        != {
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:18227",
            "dev.aragorn.role": (
                "final-combined-v3-workshop-invalidation-route-input"
            ),
            "dev.aragorn.source-commit": _SOURCE["commit"],
        }
        or document["host_config"]["network_mode"] != "none"
        or f"{_RUNTIME_VOLUME}:/runtime:ro" not in document["host_config"]["binds"]
        or f"{_ROUTE_VOLUME}:/route-input:ro" not in document["host_config"]["binds"]
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or verification["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or verification["exit_code"] != 0
        or commit_file["bytes"] != len(commit_raw)
        or commit_file["digest"] != _digest(commit_raw)
        or commit_raw
        != git(["cat-file", "commit", _SOURCE["commit"]], maximum=len(commit_raw) + 1)
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation dedicated harness changed"
        )


def _verify_route_observation(
    observation: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    boundaries: Mapping[str, Any],
    config: Mapping[str, Any],
) -> Mapping[str, Any]:
    contract = parent.v3_contract.contract
    raw_record = observation["raw"]
    raw = base64.b64decode(raw_record["base64"], validate=True)
    document = json.loads(
        raw.decode(),
        object_pairs_hook=contract._reject_duplicates,
        parse_constant=contract._reject_constant,
    )
    canonical = canonical_json(document)
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    pid = binding["pid"]
    container_id = evidence["harness"]["document"]["container_id"]
    units = {
        "aragorn-agent-gateway.service",
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    stack = observation["stack_before"]
    gateway_unit = "aragorn-agent-gateway.service"
    process = stack["processes"][gateway_unit]
    prerequisite_gateway = document["actions"][0]["prerequisites"][
        "gateway_process"
    ]
    if (
        set(observation)
        != {
            "bundle",
            "document",
            "execution",
            "gateway_pid_binding",
            "raw",
            "route",
            "stack_before",
        }
        or observation["bundle"] != _probe_bundle()
        or raw_record["bytes"] != _ROUTE_RAW["bytes"]
        or raw_record["digest"] != _ROUTE_RAW["digest"]
        or raw_record["canonical_digest"] != _ROUTE_RAW["canonical_digest"]
        or raw_record["raw_is_canonical_json_lf"] is not False
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or document != observation["document"]
        or observation["route"]
        != {
            "action_id": _ACTION,
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or type(pid) is not int
        or pid <= 0
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
            "unit": "aragorn-agent-gateway.service",
        }
        or set(execution)
        != {
            "argv",
            "completed_at",
            "effective_identity",
            "environment_names",
            "exit_code",
            "started_at",
            "stderr",
        }
        or execution["argv"]
        != [
            "nsenter",
            "--target",
            str(pid),
            "--mount",
            "--",
            "setpriv",
            "--reuid=992",
            "--regid=992",
            "--groups=992",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "/usr/local/bin/node",
            (
                "/route-input/workshop-invalidation/"
                "protected-workshop-invalidation-v3-probe.mjs"
            ),
            "--route-id",
            _ROUTE,
        ]
        or execution["effective_identity"]
        != {"gid": 992, "groups": [992], "uid": 992}
        or execution["environment_names"]
        != [
            "ARAGORN_GATEWAY_PID",
            "ARAGORN_MOCK_PROVIDER_TOKEN",
            "HOME",
            "LANG",
            "LC_ALL",
            "NO_COLOR",
            "NO_PROXY",
            "OPENCLAW_CONFIG_PATH",
            "OPENCLAW_GATEWAY_TOKEN",
            "OPENCLAW_STATE_DIR",
            "PATH",
            "TZ",
        ]
        or execution["exit_code"] != 0
        or execution["stderr"]
        != {"bytes": 0, "digest": _EMPTY_DIGEST, "excerpt": ""}
        or set(stack["units"]) != units
        or set(stack["pids"]) != units
        or set(stack["processes"]) != units
        or stack["pids"][gateway_unit] != pid
        or stack["gateway_listener"]["pid"] != pid
        or process["pid"] != pid
        or process["cmdline"] != ["openclaw-gateway"]
        or process["uids"] != [992, 992, 992, 992]
        or process["gids"] != [992, 992, 992, 992]
        or process["groups"] != [992]
        or process["capabilities_effective"] != "0000000000000000"
        or process["no_new_privileges"] != 1
        or prerequisite_gateway["hostname"] != container_id[:12]
        or prerequisite_gateway["pid"] != pid
        or prerequisite_gateway["cmdline"] != process["cmdline"]
        or prerequisite_gateway["start_time_ticks"] != process["start_time_ticks"]
        or any(
            boundaries[name] != stack[name]
            for name in (
                "enablement",
                "gateway_listener",
                "processes",
                "service_state",
                "sockets",
                "units",
            )
        )
        or any(
            stack["units"][name]["ControlGroup"]
            != f"/docker/{container_id}/system.slice/{name}"
            for name in units
        )
        or any(
            stack["units"][name]["ActiveState"] != "active"
            or stack["units"][name]["SubState"] != "running"
            or stack["units"][name]["Result"] != "success"
            or stack["units"][name]["ExecMainStatus"] != "0"
            for name in units
        )
        or not (
            parent.contract.base.legacy._parse_time(execution["started_at"])
            <= parent.contract.base.legacy._parse_time(document["recorded_at"])
            <= parent.contract.base.legacy._parse_time(execution["completed_at"])
            <= parent.contract.base.legacy._parse_time(evidence["recorded_at"])
        )
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation dedicated execution changed"
        )
    parent.contract.base.legacy._verify_stack_boundary(
        stack,
        trusted=boundaries,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    parent.contract.base.legacy._verify_gateway_listener(
        stack["gateway_listener"], stack["processes"]
    )
    _verify_document(document, config=config)
    return document


def _verify_source_artifacts(artifacts: Mapping[str, Any]) -> dict[str, bytes]:
    if set(artifacts) != {
        *_SOURCE_ARTIFACTS,
        "materialized_v2_probe",
        "materialized_v2_proposal",
        "probe_bundle",
        "transformed_probe",
    }:
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation source artifact inventory changed"
        )
    git = parent.v3_contract.config.base.legacy._git
    signed: dict[str, bytes] = {}
    for name, expected in _SOURCE_ARTIFACTS.items():
        record = artifacts[name]
        path = record["path"]
        stat = record["stat"]
        if (
            set(record) != {"bytes", "digest", "path", "stat"}
            or path != f"/src/{expected['path']}"
            or record["bytes"] != expected["bytes"]
            or record["digest"] != expected["digest"]
            or stat["uid"] != 0
            or stat["gid"] != 0
            or stat["mode"] != expected["mode"]
            or stat["nlink"] != 1
            or stat["size"] != record["bytes"]
            or stat["type"] != "file"
        ):
            raise AdmissionEvidenceError(
                "V3 workshop-invalidation source artifact changed"
            )
        repository_path = path.removeprefix("/src/")
        entry = git(
            ["ls-tree", "-z", "--full-name", _SOURCE["commit"], "--", repository_path]
        )
        prefix, separator, suffix = entry.partition(b"\t")
        parts = prefix.split()
        git_mode = (
            b"100644"
            if name in {"checked_in_probe", "checked_in_proposal", "materializer"}
            else b"100755"
        )
        if (
            separator != b"\t"
            or suffix != repository_path.encode() + b"\0"
            or len(parts) != 3
            or parts[0] != git_mode
            or parts[1] != b"blob"
        ):
            raise AdmissionEvidenceError(
                "V3 workshop-invalidation signed source artifact changed"
            )
        raw = git(
            ["cat-file", "blob", parts[2].decode()],
            maximum=record["bytes"] + 1,
        )
        if len(raw) != record["bytes"] or _digest(raw) != record["digest"]:
            raise AdmissionEvidenceError(
                "V3 workshop-invalidation signed source artifact bytes changed"
            )
        signed[name] = raw

    file_record = parent.v3_contract.enable_route._verify_file_record
    for name in ("materialized_v2_probe", "materialized_v2_proposal"):
        expected = parent._SOURCE_ARTIFACTS[name]
        file_record(
            artifacts[name],
            path=f"/src/{expected['path']}",
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode="0444",
            label=f"workshop invalidation {name}",
        )
    file_record(
        artifacts["transformed_probe"],
        path=(
            "/src/benchmark/admission/openclaw-v2026.7.1/"
            "protected-workshop-invalidation-v3-probe.mjs"
        ),
        bytes_=48_609,
        digest=_PROBE_DIGEST,
        mode="0444",
        label="workshop invalidation transformed probe",
    )
    bundle = artifacts["probe_bundle"]
    if bundle != _probe_bundle():
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation generated bundle changed"
        )
    return signed


def _verify_materialization(
    artifacts: Mapping[str, Any],
    dedicated: Mapping[str, Any],
    signed: Mapping[str, bytes],
) -> None:
    parent._verify_materialization()
    root = Path(__file__).resolve(strict=True).parents[2]
    path = (root / _SOURCE_ARTIFACTS["dedicated_materializer"]["path"]).resolve(
        strict=True
    )
    if path.read_bytes() != signed["dedicated_materializer"]:
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation materializer checkout changed"
        )
    namespace = runpy.run_path(str(path))
    materialize = namespace.get(
        "materialize_openclaw_final_v3_workshop_invalidation"
    )
    if not callable(materialize):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation materializer entry changed"
        )
    with TemporaryDirectory(prefix="aragorn-workshop-invalidation-verify-") as temporary:
        output = Path(temporary) / "bundle"
        manifest = materialize(output)
        if (
            manifest
            != {
                "schema": "aragorn/openclaw-final-v3-workshop-invalidation-bundle/v1",
                "authority": (
                    "PINNED_PROPOSAL_DERIVED_WORKSHOP_INVALIDATION_PROBE_ONLY_"
                    "NOT_EXECUTION_QUALIFICATION_OR_ADMISSION_AUTHORITY"
                ),
                "case_id": _ROUTE,
                "files": _probe_bundle(),
                "source_relationship": {
                    "base": "final-combined-v2-workshop-proposal-apply",
                    "configuration_rebound": "protected-final-combined-v3",
                    "route_semantics": "dedicated-route-input-only",
                },
            }
            or output.stat().st_mode & 0o777 != 0o555
        ):
            raise AdmissionEvidenceError(
                "V3 workshop-invalidation materializer result changed"
            )
        for item in _probe_bundle():
            generated = output / item["name"]
            raw = generated.read_bytes()
            if (
                generated.is_symlink()
                or not generated.is_file()
                or generated.stat().st_mode & 0o777 != 0o444
                or len(raw) != item["bytes"]
                or _digest(raw) != item["digest"]
            ):
                raise AdmissionEvidenceError(
                    "V3 workshop-invalidation generated bytes changed"
                )
    if (
        artifacts["transformed_probe"]["digest"]
        != dedicated["probe"]["runtime"]["digest"]
        or artifacts["materialized_v2_proposal"]["digest"]
        != dedicated["proposal_fixture"]["digest"]
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation runtime materialization custody changed"
        )


def verify_openclaw_final_v3_workshop_invalidation_semantic_compatibility(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify exact document predicates without claiming route execution."""

    try:
        _verify_document(document)
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 workshop-invalidation subfixture: {exc}"
        ) from exc
    return {
        "schema": (
            "aragorn/openclaw-final-v3-workshop-invalidation-"
            "semantic-compatibility/v1"
        ),
        "assurance": (
            "WORKSHOP_INVALIDATION_SEMANTIC_COMPATIBILITY_ONLY_NOT_EXECUTION_"
            "CAPTURE_FRESHNESS_INDEPENDENCE_PASS_OR_CAMPAIGN_AUTHORITY"
        ),
        "bindings": {
            "target_case_id": _ROUTE,
            "expected_probe_digest": _PROBE_DIGEST,
            "input_document_canonical_digest": canonical_digest(document),
        },
        "decision": {
            "status": (
                "WORKSHOP_INVALIDATION_SEMANTIC_COMPATIBILITY_VERIFIED_"
                "NOT_OBSERVED_OR_QUALIFIED"
            ),
            **{key: False for key in _ELIGIBILITY_KEYS},
        },
        "limitations": [
            "NO_DEDICATED_CAPTURE_OBSERVATION_BOUND",
            "CAPTURE_FRESHNESS_NOT_VERIFIED",
            "CAPTURE_DESTRUCTION_NOT_VERIFIED",
            "CAPTURE_INDEPENDENCE_NOT_VERIFIED",
            "PROPOSAL_APPLY_IS_PREREQUISITE_TO_INVALIDATION_OBSERVATION",
            "BLACK_BOX_NEXT_TURN_DERIVATION_NO_DIRECT_INVALIDATION_FUNCTION_TRACE",
            "NO_MODEL_PROVIDER_REQUEST_SUCCESS_OR_DELIVERY_CLAIM",
            "NO_CLEANUP_ROLLBACK_QUARANTINE_OR_GENERAL_ROUTE_CLAIM",
            "NOT_COMPOSED_WITH_OTHER_FRESH_CAMPAIGN_SUBFIXTURES",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "route_semantics": {
            "expected_action_id": _ACTION,
            "semantic_target_route": _ROUTE,
            "native_independent_route_execution_verified": False,
            "pass_authority": False,
            "shared_capture_independence_verified": False,
            "transition_predicates_verified": True,
        },
    }


def _verify_document(
    document: Mapping[str, Any], *, config: Mapping[str, Any] | None = None
) -> None:
    if type(document) is not dict:
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation document must be an object"
        )
    parent._verify_scalar_types(document)
    route = {
        "action_id": _ACTION,
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }
    runtime = parent.v3_contract.contract
    if (
        set(document) != _DOCUMENT_KEYS
        or document["schema"] != _SCHEMA
        or document["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE_DIGEST
        or document["selected_route_ids"] != [_ROUTE]
        or document["routes"] != [route]
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["runtime_binding"]
        != {
            "commit": runtime._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": runtime._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "version": "2026.7.1",
        }
        or document["protected_boundary"].get("ready") is not True
        or len(document["actions"]) != 1
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation document identity changed"
        )
    action = document["actions"][0]
    prerequisites = action["prerequisites"]
    draft = prerequisites["draft"]
    draft_file = draft["observation"]
    if (
        set(action) != _ACTION_KEYS
        or action["id"] != _ACTION
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or set(prerequisites)
        != {
            "commands",
            "draft",
            "gateway_process",
            "ready",
            "reason_codes",
            "runtime_files",
            "system_info",
            "target_before",
        }
        or prerequisites["ready"] is not True
        or prerequisites["reason_codes"] != []
        or len(prerequisites["commands"]) != 2
        or prerequisites["commands"][1] != prerequisites["system_info"]["command"]
        or prerequisites["system_info"]["response"]["parsed"] is not True
        or not parent.contract._command_succeeded_clean(
            prerequisites["system_info"]["command"]
        )
        or not parent.contract._command_output_is_exact(
            prerequisites["system_info"]["command"]
        )
        or json.loads(prerequisites["system_info"]["command"]["stdout_excerpt"])
        != prerequisites["system_info"]["response"]["value"]
        or prerequisites["system_info"]["response"]["value"]["pid"]
        != prerequisites["gateway_process"]["pid"]
        or prerequisites["system_info"]["response"]["value"]["hostname"]
        != prerequisites["gateway_process"]["hostname"]
        or prerequisites["system_info"]["response"]["value"]["machineName"]
        != prerequisites["gateway_process"]["hostname"]
        or prerequisites["gateway_process"]
        != {
            "cmdline": ["openclaw-gateway"],
            "hostname": prerequisites["gateway_process"]["hostname"],
            "pid": prerequisites["gateway_process"]["pid"],
            "start_time_ticks": prerequisites["gateway_process"]["start_time_ticks"],
        }
        or re.fullmatch(
            r"[0-9a-f]{12}", prerequisites["gateway_process"]["hostname"]
        )
        is None
        or type(prerequisites["gateway_process"]["pid"]) is not int
        or prerequisites["gateway_process"]["pid"] <= 0
        or re.fullmatch(
            r"[1-9][0-9]*", prerequisites["gateway_process"]["start_time_ticks"]
        )
        is None
        or draft["expected_digest"] != _PROPOSAL_DIGEST
        or draft_file.get("path")
        != "/route-input/workshop-invalidation/PROPOSAL.md"
        or draft_file.get("exists") is not True
        or draft_file.get("type") != "file"
        or draft_file.get("uid") != 0
        or draft_file.get("gid") != 0
        or draft_file.get("mode") != "444"
        or draft_file.get("nlink") != 1
        or draft_file.get("size") != 84
        or draft_file.get("digest") != _PROPOSAL_DIGEST
        or set(action["observations"]) != _OBSERVATION_KEYS
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation action prerequisites changed"
        )
    try:
        parent._verify_boundary(
            document["protected_boundary"],
            config
            if config is not None
            else {
                "security": {"installPolicy": parent.v3_contract.parent._POLICY},
                "skills": {
                    "activation": {"authority": "external"},
                    "workshop": {"restoreAuthority": "external"},
                },
            },
        )
        parent.contract._verify_version(prerequisites["commands"][0])
        parent._verify_runtime_files(prerequisites["runtime_files"])
    except AdmissionEvidenceError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid V3 workshop-invalidation prerequisite: {exc}"
        ) from exc
    _verify_transition(action, document["run_nonce"], document["recorded_at"])


def _verify_transition(
    action: Mapping[str, Any], nonce: str, recorded_at: str
) -> None:
    after = action["observations"]
    initial = after["initial_snapshot"]
    immediate = after["immediate_post_apply_snapshot"]
    final = after["final_snapshot"]
    initial_entry = initial["entry"]
    final_entry = final["entry"]
    initial_store = initial["file"]
    final_store = final["file"]
    next_turn = after["next_same_session_turn"]
    commands = action["commands"]
    proposed = after["native_proposal_result"]
    applied = after["native_apply_result"]
    pending_record = proposed["response"]["value"]["record"]
    applied_record = applied["response"]["value"]["record"]
    applied_at = applied_record["appliedAt"]
    parse = parent.contract.base.legacy._parse_time
    applied_ms = parent.contract.base.legacy._epoch_ms(applied_at)
    proposal_argv = proposed["command"]["argv"]
    if (
        proposed["response"].get("parsed") is not True
        or applied["response"].get("parsed") is not True
        or pending_record.get("status") != "pending"
        or applied_record.get("status") != "applied"
        or pending_record.get("id") != applied_record.get("id")
        or after["proposal_result"]
        != {"parsed": True, "proposal_id": applied_record.get("id")}
        or applied_record.get("appliedAt") != applied_record.get("updatedAt")
        or proposal_argv[-2:]
        != ["/route-input/workshop-invalidation/PROPOSAL.md", "--json"]
        or initial != immediate
        or after["target_final"] != after["target_after_apply"]
        or initial_entry["session_id"] != final_entry["session_id"]
        or initial_entry["skill_names"] != final_entry["skill_names"]
        or initial_entry["prompt"] != final_entry["prompt"]
        or type(initial_entry["snapshot_version"]) is not int
        or type(final_entry["snapshot_version"]) is not int
        or initial_entry["snapshot_version"] >= final_entry["snapshot_version"]
        or final_entry["snapshot_version"] != applied_ms
        or type(initial_entry["updated_at"]) is not int
        or type(final_entry["updated_at"]) is not int
        or initial_entry["updated_at"] >= final_entry["updated_at"]
        or initial_store["path"] != final_store["path"]
        or initial_store["device"] != final_store["device"]
        or initial_store["digest"] == final_store["digest"]
        or initial_store["inode"] == final_store["inode"]
        or after["catalog_before"]["response"]["value"]
        == after["catalog_after_apply"]["response"]["value"]
        or after["catalog_after_apply"]["response"]["value"]
        != after["final_catalog"]["response"]["value"]
        or commands
        != [
            after["catalog_before"]["command"],
            *after["initial_turn"]["commands"],
            proposed["command"],
            applied["command"],
            after["catalog_after_apply"]["command"],
            *next_turn["commands"],
            after["final_catalog"]["command"],
        ]
        or not (
            parse(applied["command"]["started_at"])
            <= parse(applied_at)
            <= parse(applied["command"]["completed_at"])
            <= parse(after["target_after_apply_observed_at"])
            <= parse(after["catalog_after_apply"]["command"]["started_at"])
            < parse(next_turn["send"]["command"]["started_at"])
            <= parse(next_turn["wait"]["command"]["completed_at"])
            <= parse(after["final_snapshot_observed_at"])
            <= parse(after["final_catalog"]["command"]["started_at"])
            <= parse(recorded_at)
        )
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation post-apply transition changed"
        )
    proposal_id = applied_record["id"]
    expected_proposal_argv = [
        parent._NODE,
        parent._OPENCLAW,
        "skills",
        "workshop",
        "--agent",
        "main",
        "propose-create",
        "--name",
        parent._WORKSHOP,
        "--description",
        "Inert Aragorn protected workshop fixture",
        "--proposal",
        "/route-input/workshop-invalidation/PROPOSAL.md",
        "--json",
    ]
    parent._verify_command(proposed["command"], expected_proposal_argv)
    parent._verify_command(
        applied["command"],
        parent._gateway_argv(
            "skills.proposals.apply",
            params={"agentId": "main", "proposalId": proposal_id},
        ),
    )
    if (
        parent._load_strict_json_stdout(proposed["command"])
        != proposed["response"]["value"]
        or parent._load_strict_json_stdout(applied["command"])
        != applied["response"]["value"]
        or set(proposed["response"]["value"]) != {"content", "record"}
        or set(applied["response"]["value"]) != {"record", "targetSkillFile"}
        or applied["response"]["value"]["targetSkillFile"]
        != parent._WORKSHOP_FILE
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation proposal response changed"
        )
    _verify_proposal_join(
        proposed["response"]["value"], applied["response"]["value"]
    )
    if (
        after["target_after_proposal"] != parent._absent_target()
        or after["target_final"] != after["target_after_apply"]
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation target transition changed"
        )
    parent._verify_residue(after["target_after_apply"])
    # Reuse the existing exact catalog and same-session-turn validators. Their
    # raw records are authority; the probe's summary booleans are intentionally
    # excluded from the qualification predicate.
    parent._verify_catalog(after["catalog_before"], initial=True)
    parent._verify_catalog(after["catalog_after_apply"], initial=False)
    parent._verify_catalog(after["final_catalog"], initial=False)
    parent._verify_turn(
        after["initial_turn"],
        nonce=nonce,
        label="initial-snapshot",
        message="Inert protected workshop initial snapshot observation.",
        snapshot=initial,
    )
    parent._verify_turn(
        next_turn,
        nonce=nonce,
        label="next-same-session",
        message="Inert protected workshop next same-session observation.",
        snapshot=final,
    )


def _verify_proposal_join(
    proposed: Mapping[str, Any], applied: Mapping[str, Any]
) -> None:
    pending = proposed["record"]
    final = applied["record"]
    immutable = {
        "createdAt",
        "createdBy",
        "description",
        "draftFile",
        "draftHash",
        "id",
        "kind",
        "proposedVersion",
        "schema",
        "target",
        "title",
    }
    _verify_proposal_record(pending, applied=False)
    _verify_proposal_record(final, applied=True)
    content = proposed["content"]
    if (
        type(content) is not str
        or parent._digest(content.encode())
        != f"sha256:{pending['draftHash']}"
        or {key: pending[key] for key in immutable}
        != {key: final[key] for key in immutable}
        or pending["status"] != "pending"
        or final["status"] != "applied"
        or final["appliedAt"] != final["updatedAt"]
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation proposal/apply join changed"
        )


def _verify_proposal_record(value: Mapping[str, Any], *, applied: bool) -> None:
    keys = {
        "createdAt",
        "createdBy",
        "description",
        "draftFile",
        "draftHash",
        "id",
        "kind",
        "proposedVersion",
        "scan",
        "schema",
        "status",
        "target",
        "title",
        "updatedAt",
    }
    if applied:
        keys.add("appliedAt")
    scan = value["scan"]
    if (
        set(value) != keys
        or value["schema"] != "openclaw.skill-workshop.proposal.v1"
        or type(value["id"]) is not str
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", value["id"]) is None
        or value["kind"] != "create"
        or value["title"] != f"Create {parent._WORKSHOP}"
        or value["description"] != "Inert Aragorn protected workshop fixture"
        or value["createdBy"] != "cli"
        or value["proposedVersion"] != "v1"
        or value["draftFile"] != "PROPOSAL.md"
        or re.fullmatch(r"[0-9a-f]{64}", value["draftHash"]) is None
        or value["target"]
        != {
            "skillName": parent._WORKSHOP,
            "skillKey": parent._WORKSHOP,
            "skillDir": parent._WORKSHOP_ROOT,
            "skillFile": parent._WORKSHOP_FILE,
            "source": "openclaw-workspace",
        }
        or set(scan) != {"critical", "findings", "info", "scannedAt", "state", "warn"}
        or scan["state"] != "clean"
        or scan["critical"] != 0
        or scan["warn"] != 0
        or scan["info"] != 0
        or scan["findings"] != []
    ):
        raise AdmissionEvidenceError(
            "V3 workshop-invalidation proposal record changed"
        )
