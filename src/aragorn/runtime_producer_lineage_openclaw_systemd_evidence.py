"""Verify the bounded P3.6b protected-producer/runtime composition artifact."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import timezone
from typing import Any

from . import runtime_active_lineage_openclaw_systemd_evidence as _p36a
from .admission_evidence import AdmissionEvidenceError, _time
from .github_quarantine_receipt import AUTHORITY as _QUARANTINE_AUTHORITY
from .github_quarantine_receipt import SCHEMA as _QUARANTINE_SCHEMA
from .github_quarantine_receipt import SOURCE_ASSURANCE
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import RuntimeActionBrokerError
from .runtime_action_systemd_evidence import _contains_float
from .runtime_process_profile_openclaw_systemd_evidence import _RUNTIME_DIGEST
from .runtime_process_profile_systemd_evidence import _digest, _file, _positive
from .runtime_revocation_openclaw_systemd_evidence import _expect, _retained

_SCHEMA = "aragorn/runtime-producer-lineage-openclaw-systemd-evidence/v1"
_AUTHORITY = (
    "BOUNDED_RETAINED_CAS_PROTECTED_INSTALL_TO_OPENCLAW_RUNTIME_COMPOSITION_"
    "ONLY_NOT_RUN_EDR_OR_INSTALLER_AUTHORITY"
)
_RAW_DIGEST = "53db78bb37550b4dde63bbc14b926a961c7d09af92f11bba74868fa917fd9589"
_EVIDENCE_DIGEST = (
    "sha256:485232aa3565f056fff3a2f1e1b14e81e6dfadc175099e315eef8e9f5cabca20"
)
_P36A_IMAGE = "sha256:5059135af5a9b0799be878814abe293f921fd55ea680bc2298330aff56198972"
_P36B_IMAGE = "sha256:e0992ea8995a7ce1f537d6372cb78febab8761edbcbfc06e07b6c096c65ca16f"
_P36A_RAW_DIGEST = (
    "sha256:b70ca54d1efdb4b9e93ed2d3895819a2f248c132cf29d811b24635fe79517362"
)
_P36A_DIGEST = (
    "sha256:5c48201f3273dc4597e0e387f2873d6cf93940a645d6a528344c4aa9e2f7e1bd"
)
_P36A_ARTIFACTS_DIGEST = (
    "sha256:5c6a31dc2020299c757e5fb769bd1eb113ff2eba461960b4267dadf1e5694250"
)
_IMAGE_LINEAGE_DIGEST = (
    "sha256:0b2eea0cc1a7d27ebed7099ef963be4f76903cd8ecaff1dc2bdcd68d5b4211d2"
)
_ARTIFACTS_DIGEST = (
    "sha256:7e2dafad82e15e7bbf20ae8b30eb81771bbd5c3b675e3b30f5e3814b4d8bcbbb"
)
_TARGET_NAME = "aragorn-admitted"
_INSTALL_ROOT = "/var/lib/aragorn-protected/skills"
_PRODUCER_AUTHORITY = (
    "RETAINED_CAS_PROTECTED_INSTALL_SERVICE_TRANSACTION_ONLY_"
    "NOT_ACQUISITION_OR_INSTALLER_AUTHORITY"
)
_SOURCE_REQUEST = {
    "schema": "aragorn/github-gateway-request/v1",
    "owner": "anthropics",
    "repository": "skills",
    "commit": "00756142ab04c82a447693cf373c4e0c554d1005",
    "skill_path": "template",
}
_RECURSIVE = {
    "root_manifest_digest": (
        "sha256:9153af66b0f2e0a5d8700e22e6161fac770eacd6f44c86de21d9aaae8658b1a6"
    ),
    "expansion_digest": (
        "sha256:bc7c5d36c6b0aa6da28bbfe686128f6b0cb8efcf10223a39df6b64e727359df6"
    ),
    "expansion_proof_digest": (
        "sha256:de1bc5ae9e734a6a5dc4fc164c5d5539c7610e58c77d8894c9dcaba3b6e71bf0"
    ),
    "release_asset_result_digests": [],
    "release_pin_set_digest": (
        "sha256:75e967bf318535c6acd224ee5bb2f8c911b1d9b1b787c8ade8d69a7462efe262"
    ),
}
_MANIFEST_DIGEST = (
    "sha256:9b15b6b43f0afe9cfe02ede35b8c50e32e8394c17b9aad792964805f08589470"
)
_TREE_DIGEST = "sha256:d409d3747207c4ac4b50002c256557c43262457e988de92189b9f8324beb5b7b"
_SKILL_DIGEST = "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
_SOURCE_PROOF_DIGEST = (
    "sha256:dc3dbb98c5b9983f1dc938a522a5ab2b2f9ff7a6d6d54daccdc4bc75ed6d9a39"
)
_SOURCE_CLOSURE_DIGEST = (
    "sha256:238228c526500d486f941f9aa060959af2e8a76bd8375c14ef0df7af49b8fb90"
)
_GATEWAY_PROFILE_DIGEST = (
    "sha256:bf7fcd7f0876a8531ed0a2ec63c473926d8f803a58c2e6aa611a10cc29b23ead"
)
_GATEWAY = {
    "package_tree_digest": (
        "sha256:d150a52369c47017b05032dad2ae0a840d77251ec266c2f90c6a832c5137b285"
    ),
    "python_executable_digest": (
        "sha256:d7dc1ef6da10929a8bb44e1e3f1d666b83fa746f92db9c50f889e4c747c6dc26"
    ),
}
_TRANSPORTED_RECEIPT_DIGEST = (
    "sha256:d7f8d0491086a29560f8d1f5d5f2768637663f22f22232166c3e3bdc81349900"
)
_LIVE_RECEIPT_DIGEST = (
    "sha256:dc47d0c71309e024feaa5590374681ba1610b0e670626b4847ccd62879507b16"
)
_CONTEXT_DIGEST = (
    "sha256:e8f195f9747ddea66cfaebea53c804f5e011bf6592c927eb721ee1077b836a78"
)
_DECISION_DIGEST = (
    "sha256:61045dead4823bcb1227ecd7cfd98701170bdbdd4b1736eed10246d7e1cb6c82"
)
_GRAPH_DIGEST = "sha256:c96442a1d0c48a6949cbcc88ee4b67fa775a7fc556862d54e98c405d8beaafc3"
_ANALYZER_RUN_DIGEST = (
    "sha256:dbb50ea6bc80a5ef95f3f188a014afbbcb68fc9672608df10c6932713fe2a2ac"
)
_BROKER_DIGEST = "sha256:ea09f919760f73d5d3e3b1a0dca635eabc1db0bef4ba6ac19ec15d81278f2c70"
_ANALYZER_IMPLEMENTATION = (
    "sha256:2d4004ae39adc2077121748ae5d88044561313b3a5c424312200780ba096709f"
)
_PYTHON_DIGEST = "sha256:7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57"
_ANALYZER_CONFIGURATION = (
    "sha256:d3f8261c703a2f17a4febee7e489c19bfb14d6f4e07a6770232aa9348ea4cbea"
)
_ANALYZER_VERIFIER = (
    "sha256:6d4a54c3206e9ab5cc767131f35de7587f7f6d05707a69d9f52028fda5821e45"
)
_POLICY_DIGEST = "sha256:aa90f135d9634ce22428ffd17a780044b11ae13755b7c16ea427ae8aa684232f"
_LAUNCHER_DIGEST = (
    "sha256:e27b2ed1be6e24d758b148e9d6f9740d4e1c5cd74e87462d2fb2d9686dc5810b"
)
_SERVICE_DIGEST = "sha256:7087601d0602d2ab64a7386b2c6a5da91c3cf6755b473a99b600ae78f5e95228"
_DROP_IN_DIGEST = "sha256:1c94aafb0211f72e2da694b055d8aa41e51d82dedf513ab71ee350e21313a74a"
_PACKAGE_TREE_DIGEST = (
    "sha256:d7373dd2ced9aee9ae4762f1170dddf4178f4d9aacb4b9d4a8ed90370d3bc3b0"
)
_LIMITATIONS = [
    "ONE_RETAINED_SINGLE_FILE_CAS_INSTALL_AND_ONE_OPENCLAW_CREATE_ONLY",
    "RETAINED_PHASE1_CAS_NOT_LIVE_ACQUISITION_OR_COORDINATOR_COMPOSITION",
    "HARNESS_PINNED_CURRENT_MODULES_AND_PYTHON_3_12_NOT_RETAINED_PHASE1_RELEASE_IDENTITY",
    "EVALUATOR_REBOUND_CAS_CUSTODY_RECEIPT_NOT_ACQUISITION_ATTESTATION",
    "P3_6A_DIGEST_IS_CALLER_PIN_NOT_RUNTIME_CONFORMANCE_AUTHORITY",
    "STALE_ACTIVE_RECORD_IS_EVALUATOR_INJECTED",
    "ACTIVE_RECORD_AUTHORITY_IS_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
    "CLIENT_REPORTS_INDETERMINATE_AFTER_FRONTEND_WRITE_WHILE_BACKEND_TRACE_PROVES_NO_SUBMISSION",
    "EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_DETERMINES_TOOL_CALL",
    "SKILL_PROMPT_PROJECTION_EVIDENCE_ONLY_NOT_SEMANTIC_CAUSATION",
    "PROCESS_PROFILE_SNAPSHOTS_NOT_CONTINUOUS_EXEC_OR_WRITER_ATTESTATION",
    "OUTER_PRIVILEGED_DOCKER_HARNESS_AND_CONTROL_PLANE_NOT_ATTESTED",
    "NO_MULTI_FILE_SKILL_DIRECT_WRITE_RENAME_SYMLINK_PROCESS_OR_NETWORK_ACTION_COVERAGE",
    "NO_HOSTILE_ROOT_HOST_OR_FORCED_POWER_LOSS_QUALIFICATION",
    "RUN_01_NOT_ESTABLISHED",
    "RUN_02_NOT_ESTABLISHED",
    "PHASE_3_EXIT_NOT_ESTABLISHED",
    "EDR_CLAIM_NOT_ESTABLISHED",
    "INSTALLER_AUTHORITY_NOT_ESTABLISHED",
    "PUBLIC_RELEASE_NOT_AUTHORIZED",
]
_DECISION = {
    "status": "P3_6B_PROTECTED_INSTALL_TO_RUNTIME_OBSERVED",
    "protected_install_service_transaction_observed": True,
    "producer_active_record_exact_match_observed": True,
    "producer_to_runtime_allow_created_observed": True,
    "mismatched_active_record_broker_not_submitted_observed": True,
    "semantic_causation_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "phase3_exit_eligible": False,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "public_release_eligible": False,
}
_TOP_LEVEL = {
    "schema",
    "authority",
    "recorded_at",
    "limitations",
    "decision",
    "parent_evidence",
    "harness",
    "artifacts",
    "runtime",
    "profile",
    "identities",
    "grant",
    "active_install",
    "deployment",
    "cases",
    "timing",
    "producer",
}
_COLLECTORS = {
    "probe": ("/src/scripts/runtime_producer_lineage_openclaw_systemd_probe.py", "0555"),
    "recipe": ("/src/scripts/capture_runtime_producer_lineage_openclaw_systemd.sh", "0555"),
    "dockerfile": (
        "/src/benchmark/runtime-producer-lineage-openclaw-systemd/Dockerfile",
        "0444",
    ),
    "python_drop_in": (
        (
            "/src/benchmark/runtime-producer-lineage-openclaw-systemd/"
            "aragorn-protected-install-python312.conf"
        ),
        "0444",
    ),
}
_PRODUCER_ARTIFACTS = {
    "/src/benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py": (
        (
            "/opt/aragorn-broker-p36b/benchmark/admission/openclaw-v2026.7.1/"
            "protected-install-broker-recursive-v3.py"
        ),
        "0444",
    ),
    "/src/src/aragorn/github_quarantine_receipt.py": (
        "/opt/aragorn-broker-p36b/src/aragorn/github_quarantine_receipt.py",
        "0444",
    ),
    "/src/src/aragorn/protected_install.py": (
        "/opt/aragorn-broker-p36b/src/aragorn/protected_install.py",
        "0444",
    ),
    "/src/packaging/libexec/aragorn-protected-install-launcher.py": (
        "/usr/libexec/aragorn/aragorn-protected-install-launcher.py",
        "0555",
    ),
    "/src/packaging/systemd/aragorn-protected-install.service": (
        "/usr/lib/systemd/system/aragorn-protected-install.service",
        "0444",
    ),
    _COLLECTORS["python_drop_in"][0]: (
        "/etc/systemd/system/aragorn-protected-install.service.d/python312.conf",
        "0444",
    ),
}
_PIN_FIELDS = {
    "producer": "expected_producer_implementation_digest",
    "analyzer_implementation": "expected_analyzer_implementation_digest",
    "analyzer_executable": "expected_analyzer_executable_digest",
    "analyzer_configuration": "expected_analyzer_configuration_digest",
    "policy": "expected_policy_digest",
    "analyzer_verifier": "expected_analyzer_verifier_digest",
    "artifact_graph_verifier": "expected_artifact_graph_verifier_digest",
}
_PINS = {
    "producer": _BROKER_DIGEST,
    "analyzer_implementation": _ANALYZER_IMPLEMENTATION,
    "analyzer_executable": _PYTHON_DIGEST,
    "analyzer_configuration": _ANALYZER_CONFIGURATION,
    "policy": _POLICY_DIGEST,
    "analyzer_verifier": _ANALYZER_VERIFIER,
    "artifact_graph_verifier": _ANALYZER_IMPLEMENTATION,
}
_RECEIPT_LIMITATIONS = [
    "PHASE0_FIRST_PARTY_ANALYZER_NOT_PRODUCTION_ANALYSIS",
    "PYTHON_STDLIB_AND_DYNAMIC_RUNTIME_CLOSURE_NOT_PINNED",
    "CALLER_SUPPLIED_RUNTIME_DIGESTS_NOT_SEMANTICALLY_VERIFIED",
    "HOST_SYSTEM_CLOCK_AND_REVOCATION_INPUT_NOT_EXTERNALLY_ATTESTED",
    "CALLER_SUPPLIED_CONTEXT_ID_NOT_EXTERNALLY_ATTESTED",
    "SELF_DERIVED_CONTEXT_DIGEST_NOT_INDEPENDENT_AUTHORIZATION",
    "ARTIFACT_CLOSURE_LIMITED_TO_RECURSIVE_GITHUB_MARKDOWN_V1",
    "PRODUCER_RECEIPT_NOT_OPENCLAW_ROUTE_OR_ADM02_CONFORMANCE_EVIDENCE",
    "PROTECTED_TRANSACTION_EXECUTION_NOT_INSTALLER_AUTHORITY",
    "NO_INSTALLER_AUTHORITY",
]
_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def verify_runtime_producer_lineage_openclaw_systemd_evidence(
    document: Mapping[str, Any], *, expected_digest: str | None = None
) -> None:
    """Replay P3.6b without promoting acquisition, RUN, EDR, or release claims."""

    try:
        _expect(
            _digest(expected_digest), "an explicit retained evidence digest is required"
        )
        _expect(set(document) == _TOP_LEVEL, "top-level fields changed")
        _expect(
            canonical_digest(document) == expected_digest, "retained evidence changed"
        )
        _expect(not _contains_float(document), "floating-point evidence is invalid")
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["authority"] == _AUTHORITY, "authority changed")
        _expect(document["limitations"] == _LIMITATIONS, "limitations changed")
        _expect(document["decision"] == _DECISION, "claim ceiling changed")
        recorded_at = _time(document["recorded_at"])
        _verify_parent(document["parent_evidence"])
        harness = _verify_harness(document["harness"])
        _verify_artifacts(document["artifacts"])
        producer = _verify_producer(document, recorded_at)
        _p36a._verify_composition(
            document,
            harness,
            fixture_authority=_PRODUCER_AUTHORITY,
            target_name=_TARGET_NAME,
            skill_path=producer["skill_path"],
            skill_digest=producer["skill_digest"],
        )
        _verify_runtime_binding(document, producer)
    except AdmissionEvidenceError:
        raise
    except (
        IndexError,
        KeyError,
        RecursionError,
        RuntimeActionBrokerError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime producer-lineage OpenClaw evidence: {exc}"
        ) from exc


def _verify_parent(value: Mapping[str, Any]) -> None:
    _expect(
        value
        == {
            "repository_path": (
                "benchmark/evidence/"
                "runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json"
            ),
            "captured_path": (
                "/src/benchmark/evidence/"
                "runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json"
            ),
            "file_digest": _P36A_RAW_DIGEST,
            "canonical_digest": _P36A_DIGEST,
            "bytes": 499823,
            "schema": "aragorn/runtime-active-lineage-openclaw-systemd-evidence/v1",
            "authority": _p36a._AUTHORITY,
            "decision_status": "P3_6A_LIVE_PROTECTED_LINEAGE_OBSERVED",
        },
        "P3.6a parent evidence pin changed",
    )


def _verify_harness(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _retained(value)
    harness = value["document"]
    _expect(
        set(harness)
        == {
            "schema",
            "container_id",
            "image_id",
            "image_reference",
            "run_image_reference",
            "parent_image_id",
            "image_lineage",
            "platform",
            "profile_label",
            "openclaw_runtime_volume",
            "openclaw_runtime_volume_identity",
            "openclaw_runtime_mount",
            "host_config",
        }
        and harness["schema"]
        == "aragorn/runtime-producer-lineage-openclaw-systemd-harness/v1"
        and _HEX64.fullmatch(harness["container_id"])
        and harness["image_id"] == harness["run_image_reference"] == _P36B_IMAGE
        and harness["image_reference"]
        == "aragorn-p36b-runtime-producer-lineage-openclaw-systemd"
        and harness["parent_image_id"] == _P36A_IMAGE
        and harness["platform"] == "linux"
        and harness["profile_label"] == "p3.6b",
        "P3.6b harness identity changed",
    )
    _expect(
        harness["openclaw_runtime_volume"] == "aragorn-openclaw-2026-7-1-runtime"
        and harness["openclaw_runtime_volume_identity"]
        == {
            "driver": "local",
            "labels": None,
            "name": "aragorn-openclaw-2026-7-1-runtime",
            "options": None,
            "scope": "local",
        }
        and harness["openclaw_runtime_mount"]
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": "aragorn-openclaw-2026-7-1-runtime",
            "type": "volume",
        }
        and harness["host_config"]
        == {
            "binds": [
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "aragorn-openclaw-2026-7-1-runtime:/runtime:ro",
            ],
            "cgroupns_mode": "host",
            "ipc_mode": "private",
            "network_mode": "none",
            "privileged": True,
            "readonly_rootfs": False,
            "runtime": "runc",
            "security_opt": ["label=disable"],
            "tmpfs": {
                "/run": "rw,nosuid,nodev,noexec,mode=755",
                "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
            },
            "userns_mode": "",
        },
        "pinned P3.6b outer harness changed",
    )
    lineage = harness["image_lineage"]
    parent, child = lineage["parent"], lineage["child"]
    _expect(
        canonical_digest(lineage) == _IMAGE_LINEAGE_DIGEST
        and set(lineage) == {"parent", "child", "added_layers"}
        and set(parent) == set(child) == {"id", "rootfs_type", "layers"}
        and parent["id"] == _P36A_IMAGE
        and child["id"] == _P36B_IMAGE
        and parent["rootfs_type"] == child["rootfs_type"] == "layers"
        and all(_digest(layer) for layer in parent["layers"] + child["layers"])
        and child["layers"][: len(parent["layers"])] == parent["layers"]
        and lineage["added_layers"] == child["layers"][len(parent["layers"]) :]
        and bool(lineage["added_layers"]),
        "P3.6a parent/P3.6b child lineage changed",
    )
    return harness


def _verify_artifacts(value: Mapping[str, Any]) -> None:
    _expect(
        set(value)
        == {
            "installed",
            "parent_collector",
            "collector",
            "producer_installed",
            "retained_archive",
        }
        and canonical_digest(value) == _ARTIFACTS_DIGEST,
        "P3.6b artifact closure changed",
    )
    parent = {"installed": value["installed"], "collector": value["parent_collector"]}
    _expect(
        canonical_digest(parent) == _P36A_ARTIFACTS_DIGEST,
        "P3.6a inherited artifact closure changed",
    )
    _p36a._verify_artifacts(parent)
    collector = value["collector"]
    _expect(set(collector) == set(_COLLECTORS), "collector closure changed")
    for name, (path, mode) in _COLLECTORS.items():
        _file(collector[name], path=path, uid=0, gid=0, mode=mode)
    installed = value["producer_installed"]
    _expect(
        isinstance(installed, list) and len(installed) == len(_PRODUCER_ARTIFACTS),
        "producer artifact count changed",
    )
    by_source = {item["source"]["path"]: item for item in installed}
    _expect(
        len(by_source) == len(installed) and set(by_source) == set(_PRODUCER_ARTIFACTS),
        "producer source paths changed",
    )
    for source_path, (installed_path, installed_mode) in _PRODUCER_ARTIFACTS.items():
        item = by_source[source_path]
        _expect(set(item) == {"source", "installed"}, "producer artifact fields changed")
        source, target = item["source"], item["installed"]
        _file(source, path=source_path, uid=0, gid=0, mode="0444")
        _file(target, path=installed_path, uid=0, gid=0, mode=installed_mode)
        _expect(
            (source["digest"], source["bytes"])
            == (target["digest"], target["bytes"]),
            f"producer source/install binding changed: {installed_path}",
        )
    archive = value["retained_archive"]
    _file(
        archive,
        path=(
            "/src/benchmark/evidence/"
            "phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz"
        ),
        uid=0,
        gid=0,
        mode="0644",
    )
    _expect(
        archive["digest"]
        == "sha256:08bb32c12e159fede3618bcdeecff5e56c8630e9681d70fe7922f4654cb1b6d8"
        and archive["bytes"] == 11705756,
        "retained Phase1 archive changed",
    )


def _verify_producer(
    document: Mapping[str, Any], recorded_at: Any
) -> dict[str, Any]:
    value = document["producer"]
    _expect(
        set(value)
        == {
            "request",
            "receipt",
            "journal",
            "transaction",
            "record",
            "claim",
            "tree_entry",
            "skill_name",
            "paths",
            "service",
            "release",
            "revocations",
            "original_record",
            "restored_record",
        },
        "producer closure changed",
    )
    request, live_receipt = _verify_request(value["request"])
    release = _verify_bound_file(
        value["release"], "/etc/aragorn/protected-broker-release.json", "0400"
    )
    _verify_release(release)
    revocations = _verify_bound_file(
        value["revocations"], "/etc/aragorn/protected-install-revocations.json", "0400"
    )
    _expect(
        revocations == {
            "schema": "aragorn/protected-install-revocations/v1",
            "context_ids": [],
        },
        "producer revocation input changed",
    )
    transaction = _verify_transaction_and_records(value, request)
    receipt = _verify_receipt(
        value["receipt"], request, live_receipt, transaction, value["revocations"]
    )
    _verify_journal(value["journal"], receipt, request, release, recorded_at)
    _verify_service(value["service"], value["journal"])
    _expect(
        release["broker"]["digest"]
        == request["expected_producer_implementation_digest"]
        == receipt["producer_implementation_digest"]
        and release["python"]["digest"]
        == request["expected_analyzer_executable_digest"]
        == receipt["analyzer"]["executable_digest"],
        "producer release/request/receipt identity changed",
    )
    return {
        "transaction": transaction,
        "skill_path": value["paths"]["skill"],
        "skill_digest": value["tree_entry"]["digest"],
    }


def _verify_request(value: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    _expect(
        set(value) == {"document", "digest", "pins", "quarantine_receipt"},
        "producer request fields changed",
    )
    request = value["document"]
    _expect(
        value["digest"] == canonical_digest(request)
        and set(request)
        == {
            "schema",
            "context_id",
            "expected_active",
            "expected_analyzer_configuration_digest",
            "expected_analyzer_executable_digest",
            "expected_analyzer_implementation_digest",
            "expected_analyzer_verifier_digest",
            "expected_artifact_graph_verifier_digest",
            "expected_manifest_diff_digest",
            "expected_policy_digest",
            "expected_producer_implementation_digest",
            "expires_at_unix",
            "gateway_profile_digest",
            "manifest_digest",
            "operation",
            "quarantine_receipt_digest",
            "recursive",
            "runtime_conformance_digest",
            "source_request",
            "target_runtime_digest",
        },
        "producer request record changed",
    )
    context_id = canonical_digest(
        {
            "schema": "aragorn/p36b-retained-cas-context-id/v1",
            "source_request": _SOURCE_REQUEST,
            "runtime_digest": _RUNTIME_DIGEST,
            "runtime_conformance_digest": _P36A_DIGEST,
        }
    )
    _expect(
        request["schema"] == "aragorn/protected-install-broker-request/v4"
        and request["context_id"] == context_id
        and request["expected_active"] is None
        and request["expected_manifest_diff_digest"] is None
        and request["manifest_digest"] == _MANIFEST_DIGEST
        and request["operation"] == "install"
        and request["recursive"] == _RECURSIVE
        and request["runtime_conformance_digest"] == _P36A_DIGEST
        and request["source_request"] == _SOURCE_REQUEST
        and request["target_runtime_digest"] == _RUNTIME_DIGEST
        and request["gateway_profile_digest"] == _GATEWAY_PROFILE_DIGEST
        and _positive(request["expires_at_unix"]),
        "producer request binding changed",
    )
    _expect(value["pins"] == _PINS, "producer request pin set changed")
    _expect(
        all(request[field] == value["pins"][name] for name, field in _PIN_FIELDS.items()),
        "producer request pins are not bound",
    )
    live = _verify_quarantine_receipts(value["quarantine_receipt"])
    _expect(
        request["quarantine_receipt_digest"] == live["digest"],
        "rebound quarantine receipt is not the service input",
    )
    return request, live["document"]


def _verify_quarantine_receipts(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _expect(set(value) == {"transported", "live"}, "quarantine receipt epochs changed")
    for item in value.values():
        _retained(item)
        receipt = item["document"]
        _expect(
            set(receipt)
            == {
                "schema",
                "receipt_id",
                "authority",
                "source_assurance",
                "request",
                "request_digest",
                "manifest_digest",
                "source_proof_digest",
                "handoff_manifest_digest",
                "source_closure_digest",
                "tree_digest",
                "file_count",
                "containment_profile",
                "gateway_profile_digest",
                "protected_cas",
                "gateway",
            }
            and receipt["schema"] == _QUARANTINE_SCHEMA
            and _HEX64.fullmatch(receipt["receipt_id"])
            and receipt["authority"] == _QUARANTINE_AUTHORITY
            and receipt["source_assurance"] == SOURCE_ASSURANCE
            and receipt["request"] == _SOURCE_REQUEST
            and receipt["request_digest"] == canonical_digest(_SOURCE_REQUEST)
            and receipt["manifest_digest"] == _RECURSIVE["root_manifest_digest"]
            and receipt["source_proof_digest"] == _SOURCE_PROOF_DIGEST
            and _digest(receipt["handoff_manifest_digest"])
            and receipt["source_closure_digest"] == _SOURCE_CLOSURE_DIGEST
            and receipt["tree_digest"] == _TREE_DIGEST
            and receipt["file_count"] == 1
            and receipt["containment_profile"]
            == "linux-systemd-restricted-egress/v1"
            and receipt["gateway_profile_digest"] == _GATEWAY_PROFILE_DIGEST
            and receipt["gateway"] == _GATEWAY,
            "quarantine receipt source closure changed",
        )
        custody = receipt["protected_cas"]
        _expect(
            set(custody) == {"root_device", "root_inode", "owner_uid", "mode"}
            and _positive(custody["root_device"])
            and _positive(custody["root_inode"])
            and custody["owner_uid"] == 0
            and custody["mode"] == 0o700,
            "quarantine custody record changed",
        )
    transported, live = value["transported"], value["live"]
    _expect(
        transported["digest"] == _TRANSPORTED_RECEIPT_DIGEST
        and live["digest"] == _LIVE_RECEIPT_DIGEST
        and live["digest"] != transported["digest"],
        "transported/live quarantine receipt identity changed",
    )
    excluded = {"receipt_id", "protected_cas"}
    _expect(
        {key: val for key, val in live["document"].items() if key not in excluded}
        == {
            key: val
            for key, val in transported["document"].items()
            if key not in excluded
        }
        and live["document"]["receipt_id"]
        != transported["document"]["receipt_id"]
        and live["document"]["protected_cas"]
        != transported["document"]["protected_cas"],
        "transported receipt changed beyond live custody rebinding",
    )
    return live


def _verify_transaction_and_records(
    value: Mapping[str, Any], request: Mapping[str, Any]
) -> dict[str, Any]:
    transaction = value["transaction"]
    version_name = f"{request['context_id'][7:]}-{_MANIFEST_DIGEST[7:]}"
    version_path = f".aragorn-versions/{_TARGET_NAME}/{version_name}"
    _expect(
        transaction
        == {
            "schema": "aragorn/protected-install-transaction/v1",
            "authority": "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
            "context_digest": _CONTEXT_DIGEST,
            "context_id": request["context_id"],
            "operation": "install",
            "expected_active": None,
            "manifest_digest": _MANIFEST_DIGEST,
            "tree_digest": _TREE_DIGEST,
            "destination": {
                "root_device": transaction["destination"]["root_device"],
                "root_inode": transaction["destination"]["root_inode"],
                "target_name": _TARGET_NAME,
            },
            "version_path": version_path,
        }
        and _positive(transaction["destination"]["root_device"])
        and _positive(transaction["destination"]["root_inode"]),
        "producer transaction changed",
    )
    record = value["record"]
    _expect(set(record) == {"digest", "document", "file", "raw_digest"}, "producer record fields changed")
    retained_record = {key: val for key, val in record.items() if key != "raw_digest"}
    parsed = _p36a._record(retained_record, stale=False)
    restored = value["restored_record"]
    _p36a._record(restored, stale=False)
    _expect(
        record["raw_digest"] == record["digest"]
        and parsed["transaction"] == transaction
        and restored == retained_record
        and value["original_record"]
        == {
            "digest": record["digest"],
            "device": record["file"]["stat"]["device"],
            "inode": record["file"]["stat"]["inode"],
        },
        "producer active record was not restored exactly",
    )
    context = request["context_id"][7:]
    claim_path = f"{_INSTALL_ROOT}/.aragorn-install-claims/{context}.json"
    claim = value["claim"]
    _expect(
        set(claim) == {"digest", "document", "file", "raw_digest"},
        "producer claim fields changed",
    )
    _verify_bound_file(
        {key: val for key, val in claim.items() if key != "raw_digest"},
        claim_path,
        "0400",
    )
    _expect(
        claim["document"] == transaction
        and claim["raw_digest"] == claim["digest"],
        "producer claim is not the protected transaction",
    )
    paths = {
        "root": _INSTALL_ROOT,
        "record": f"{_INSTALL_ROOT}/.aragorn-active-runtime.json",
        "active_link": f"{_INSTALL_ROOT}/{_TARGET_NAME}",
        "versions": f"{_INSTALL_ROOT}/.aragorn-versions",
        "target_versions": f"{_INSTALL_ROOT}/.aragorn-versions/{_TARGET_NAME}",
        "version": f"{_INSTALL_ROOT}/{version_path}",
        "skill": f"{_INSTALL_ROOT}/{version_path}/SKILL.md",
        "claim": claim_path,
    }
    tree_entry = {
        "path": "SKILL.md",
        "size": 140,
        "digest": _SKILL_DIGEST,
        "executable": False,
    }
    _expect(
        value["paths"] == paths
        and value["tree_entry"] == tree_entry
        and canonical_digest([tree_entry]) == _TREE_DIGEST
        and value["skill_name"] == "template-skill",
        "producer immutable tree or paths changed",
    )
    return transaction


def _verify_receipt(
    value: Mapping[str, Any],
    request: Mapping[str, Any],
    live_receipt: Mapping[str, Any],
    transaction: Mapping[str, Any],
    revocations: Mapping[str, Any],
) -> Mapping[str, Any]:
    _expect(
        set(value)
        == {
            "schema",
            "assurance",
            "mode",
            "slice_status",
            "producer_implementation_digest",
            "request_authority",
            "source",
            "analyzer",
            "decision",
            "context",
            "claim",
            "limitations",
            "transition",
            "transaction",
            "active",
            "verified_sequence",
        }
        and value["schema"]
        == "aragorn/openclaw-github-protected-install-broker-evidence/v1"
        and value["assurance"]
        == "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
        and value["mode"] == "github-live"
        and value["slice_status"] == "PASS"
        and value["producer_implementation_digest"] == _BROKER_DIGEST
        and value["limitations"] == _RECEIPT_LIMITATIONS
        and value["transition"]
        == {"expected_active": None, "manifest_diff": None, "operation": "install"}
        and value["transaction"] == transaction
        and value["active"]
        == {"link_target": transaction["version_path"], "tree_digest": _TREE_DIGEST}
        and value["verified_sequence"]
        == [
            "quarantine-custody",
            "recursive-github-markdown/v1-closure",
            "exact-source-materialization",
            "digest-bound-first-party-analyzer-run",
            "decision-v3-replay",
            "protected-install-context-v2",
            "protected-install-transaction",
            "active-tree-reverification",
        ],
        "producer service receipt changed",
    )
    source = value["source"]
    _expect(
        source
        == {
            "request": _SOURCE_REQUEST,
            "manifest_digest": _MANIFEST_DIGEST,
            "tree_digest": _TREE_DIGEST,
            "source_proof_digest": _SOURCE_PROOF_DIGEST,
            "source_closure_digest": _SOURCE_CLOSURE_DIGEST,
            "quarantine_receipt_digest": request["quarantine_receipt_digest"],
            "gateway_profile_digest": _GATEWAY_PROFILE_DIGEST,
            "containment_profile": "linux-systemd-restricted-egress/v1",
            "gateway": _GATEWAY,
            "quarantine_protected_cas": live_receipt["protected_cas"],
            "artifact_graph_digest": _GRAPH_DIGEST,
            "artifact_graph_profile": "recursive-github-markdown/v1",
            "artifact_graph_verifier_implementation_digest": _ANALYZER_IMPLEMENTATION,
            "artifact_count": 1,
            "closure": {
                "profile": "recursive-github-markdown/v1",
                "scope": "artifact_graph",
                "status": "complete",
                "unresolved": [],
            },
            "recursive": _RECURSIVE,
        },
        "producer source receipt changed",
    )
    _expect(
        value["analyzer"]
        == {
            "name": "aragorn-agent-skill-threats",
            "version": "0.1.0-phase0-v7",
            "implementation_digest": _ANALYZER_IMPLEMENTATION,
            "executable_digest": _PYTHON_DIGEST,
            "configuration_digest": _ANALYZER_CONFIGURATION,
            "verifier_implementation_digest": _ANALYZER_VERIFIER,
            "execution_identity": {
                "uid": 993,
                "gid": 993,
                "user": "aragorn-analyze",
                "group": "aragorn-analyze",
                "supplementary_groups": [],
            },
            "run_receipt_digest": _ANALYZER_RUN_DIGEST,
        }
        and value["decision"]
        == {
            "digest": _DECISION_DIGEST,
            "installer_work_eligible": False,
            "policy_digest": _POLICY_DIGEST,
            "verdict": "ALLOW",
        },
        "producer analyzer or decision changed",
    )
    context = value["context"]
    _expect(
        context
        == {
            "context_id": request["context_id"],
            "destination": transaction["destination"],
            "digest": _CONTEXT_DIGEST,
            "expected_active": None,
            "operation": "install",
            "runtime_conformance_digest": _P36A_DIGEST,
            "target_runtime_digest": _RUNTIME_DIGEST,
        },
        "producer protected context changed",
    )
    authority = value["request_authority"]
    credential = authority["credential"]
    _expect(
        set(authority) == {"authority", "credential", "request_digest", "request_schema"}
        and authority["authority"] == "PROTECTED_CANONICAL_REQUEST_CREDENTIAL"
        and authority["request_digest"] == canonical_digest(request)
        and authority["request_schema"] == request["schema"]
        and set(credential)
        == {
            "ctime_ns",
            "device",
            "gid",
            "inode",
            "links",
            "mode",
            "mtime_ns",
            "path",
            "size",
            "uid",
        }
        and credential["path"]
        == "/run/credentials/aragorn-protected-install.service/install-request"
        and credential["uid"] == credential["gid"] == 0
        and credential["links"] == 1
        and credential["mode"] == 0o400
        and credential["size"] == len(canonical_json(request))
        and _positive(credential["device"])
        and _positive(credential["inode"])
        and _positive(credential["ctime_ns"])
        and credential["mtime_ns"] == credential["ctime_ns"]
        and request["expires_at_unix"]
        == credential["ctime_ns"] // 1_000_000_000 + 900,
        "producer request credential changed",
    )
    revocation_file = revocations["file"]
    snapshot = {
        "schema": "aragorn/protected-install-revocations/v1",
        "context_ids": [],
        "path": revocation_file["path"],
        "digest": revocations["digest"],
        "device": revocation_file["stat"]["device"],
        "inode": revocation_file["stat"]["inode"],
        "owner_uid": 0,
        "mode": 0o400,
    }
    claim_now = value["claim"]["fresh"]["claim_now_unix"]
    credential_second = credential["ctime_ns"] // 1_000_000_000
    _expect(
        value["claim"]
        == {
            "initial_revocation_snapshot": snapshot,
            "fresh": {
                "claim_now_unix": claim_now,
                "revocation_snapshot": snapshot,
            },
        }
        and credential_second <= claim_now <= credential_second + 5
        and claim_now < request["expires_at_unix"],
        "producer freshness or revocation claim changed",
    )
    return value


def _verify_journal(
    value: Mapping[str, Any],
    receipt: Mapping[str, Any],
    request: Mapping[str, Any],
    release: Mapping[str, Any],
    recorded_at: Any,
) -> None:
    _expect(
        set(value)
        == {
            "message_digest",
            "message_bytes",
            "invocation_id",
            "boot_id",
            "procfs_boot_id",
            "realtime_timestamp",
            "systemd_unit",
            "syslog_identifier",
            "executable",
            "uid",
            "gid",
            "pid",
            "command_line",
        }
        and value["message_digest"] == canonical_digest(receipt)
        and value["message_bytes"] == len(canonical_json(receipt))
        and _HEX32.fullmatch(value["invocation_id"])
        and _HEX32.fullmatch(value["boot_id"])
        and value["procfs_boot_id"] == value["boot_id"]
        and isinstance(value["realtime_timestamp"], str)
        and value["realtime_timestamp"].isdigit()
        and value["systemd_unit"] == "aragorn-protected-install.service"
        and value["syslog_identifier"] == "aragorn-protected-install"
        and value["executable"] == release["python"]["path"]
        and value["uid"] == value["gid"] == 0
        and _positive(value["pid"])
        and value["command_line"]
        == " ".join(
            (
                release["python"]["path"],
                "-I -S -B",
                f"{release['package']['root']}/{release['broker']['path']}",
                (
                    "--github-live --service-request /run/credentials/"
                    "aragorn-protected-install.service/install-request"
                ),
                "--analyzer-user aragorn-analyze --analyzer-group aragorn-analyze",
                "--cas-root /var/lib/aragorn-quarantine",
                "--protected-root /var/lib/aragorn-protected/skills",
                "--expected-broker-uid 0",
                "--revocation-file /etc/aragorn/protected-install-revocations.json",
            )
        ),
        "producer journal record changed",
    )
    timestamp = int(value["realtime_timestamp"]) / 1_000_000
    credential_second = (
        receipt["request_authority"]["credential"]["ctime_ns"] // 1_000_000_000
    )
    _expect(
        credential_second <= timestamp <= credential_second + 5
        and timestamp < request["expires_at_unix"]
        and 0 <= recorded_at.astimezone(timezone.utc).timestamp() - timestamp <= 60,
        "producer journal ordering changed",
    )


def _verify_service(
    value: Mapping[str, Any], journal: Mapping[str, Any]
) -> None:
    _expect(
        set(value) == {"unit", "load_credential", "systemd_verify"}
        and value["load_credential"]
        == 'a(ss) 1 "install-request" "/run/aragorn-protected-install/request.json"'
        and value["systemd_verify"] == {"exit_code": 0, "stdout": "", "stderr": ""},
        "producer service binding changed",
    )
    unit = value["unit"]
    _expect(
        set(unit)
        == {
            "ActiveState",
            "AmbientCapabilities",
            "CapabilityBoundingSet",
            "ControlGroup",
            "DropInPaths",
            "ExecMainStatus",
            "ExecStart",
            "FragmentDigest",
            "FragmentPath",
            "FragmentResolvedPath",
            "Group",
            "InvocationID",
            "MainPID",
            "NoNewPrivileges",
            "Result",
            "SubState",
            "SupplementaryGroups",
            "User",
        }
        and unit["ActiveState"] == "inactive"
        and unit["SubState"] == "dead"
        and unit["Result"] == "success"
        and unit["ExecMainStatus"] == "0"
        and unit["MainPID"] == "0"
        and unit["InvocationID"] == ""
        and unit["ControlGroup"] == ""
        and unit["User"] == unit["Group"] == "root"
        and unit["SupplementaryGroups"] == ""
        and unit["AmbientCapabilities"]
        == unit["CapabilityBoundingSet"]
        == "cap_setgid cap_setuid"
        and unit["NoNewPrivileges"] == "yes"
        and unit["FragmentPath"]
        == "/lib/systemd/system/aragorn-protected-install.service"
        and unit["FragmentResolvedPath"]
        == "/usr/lib/systemd/system/aragorn-protected-install.service"
        and journal["systemd_unit"] == unit["FragmentResolvedPath"].rsplit("/", 1)[-1]
        and unit["FragmentDigest"] == _SERVICE_DIGEST
        and unit["DropInPaths"]
        == "/etc/systemd/system/aragorn-protected-install.service.d/python312.conf"
        and unit["ExecStart"]
        == (
            "{ path=/usr/local/bin/python3.12 ; argv[]=/usr/local/bin/python3.12 "
            "-I -S -B /usr/libexec/aragorn/aragorn-protected-install-launcher.py -- "
            "--github-live --service-request /run/credentials/"
            "aragorn-protected-install.service/install-request --analyzer-user "
            "aragorn-analyze --analyzer-group aragorn-analyze --cas-root "
            "/var/lib/aragorn-quarantine --protected-root "
            "/var/lib/aragorn-protected/skills --expected-broker-uid 0 "
            "--revocation-file /etc/aragorn/protected-install-revocations.json ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; "
            "code=(null) ; status=0/0 }"
        ),
        "producer systemd unit changed",
    )


def _verify_release(value: Mapping[str, Any]) -> None:
    _expect(
        value
        == {
            "schema": "aragorn/protected-broker-launch-identity/v1",
            "broker": {
                "digest": _BROKER_DIGEST,
                "path": (
                    "benchmark/admission/openclaw-v2026.7.1/"
                    "protected-install-broker-recursive-v3.py"
                ),
            },
            "launcher": {
                "digest": _LAUNCHER_DIGEST,
                "path": "/usr/libexec/aragorn/aragorn-protected-install-launcher.py",
            },
            "package": {
                "root": "/opt/aragorn-broker-p36b",
                "tree_digest": _PACKAGE_TREE_DIGEST,
            },
            "python": {
                "digest": _PYTHON_DIGEST,
                "path": "/usr/local/bin/python3.12",
            },
        },
        "producer release identity changed",
    )


def _verify_bound_file(
    value: Mapping[str, Any], path: str, mode: str
) -> Mapping[str, Any]:
    _expect(set(value) == {"digest", "document", "file"}, f"bound file fields changed: {path}")
    _file(value["file"], path=path, uid=0, gid=0, mode=mode)
    _expect(
        value["digest"] == canonical_digest(value["document"])
        and value["file"]["digest"] == value["digest"]
        and value["file"]["bytes"] == len(canonical_json(value["document"])),
        f"bound file changed: {path}",
    )
    return value["document"]


def _verify_runtime_binding(
    document: Mapping[str, Any], producer: Mapping[str, Any]
) -> None:
    active = document["active_install"]
    value = document["producer"]
    profile_skill = document["profile"]["skill"]
    active_skill = active["coherent_snapshot"]["before"]["skill"]
    _expect(
        producer["transaction"]
        == value["receipt"]["transaction"]
        == active["transaction"]
        and active["record"] == value["restored_record"]
        and {key: val for key, val in value["paths"].items() if key != "claim"}
        == active["paths"]
        and value["tree_entry"] == active["tree_entry"]
        and profile_skill["path"] == producer["skill_path"]
        and profile_skill["digest"] == producer["skill_digest"]
        and active_skill == {"path": profile_skill["path"], **profile_skill["stat"]},
        "producer output is not the exact runtime-consumed immutable skill",
    )
