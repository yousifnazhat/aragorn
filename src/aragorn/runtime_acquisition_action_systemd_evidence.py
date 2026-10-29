"""Verify the bounded P3.8b live acquisition-to-action observation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import runtime_action_broker as broker
from . import runtime_action_broker_v4 as broker_v4
from . import runtime_action_decision as action_decision
from . import runtime_action_worker_activation_expiry_systemd_evidence as p37c
from . import runtime_producer_lineage_openclaw_systemd_evidence as p36b
from .admission_evidence import AdmissionEvidenceError, _time
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import RuntimeActionBrokerError
from .runtime_active_skill_lineage import parse_active_runtime_record
from .runtime_capability_grant import parse_runtime_capability_grant

_SCHEMA = "aragorn/runtime-acquisition-action-systemd-observation/v1"
_AUTHORITY = (
    "BOUNDED_LIVE_COORDINATOR_ACQUISITION_TO_RUNTIME_ACTION_OBSERVATION_ONLY_"
    "NOT_VERIFIED_RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
)
_RETAINED_PATH = (
    "benchmark/evidence/runtime-acquisition-action-systemd-composition-"
    "p3-8b-2026-08-11.json"
)
_EVIDENCE_BYTES = 447_132
_EVIDENCE_RAW_DIGEST = (
    "sha256:a095687592ff5d5a51f9a36ef52fa9933ce5dede3c9fe54115f1b2be3180c16d"
)
_EVIDENCE_DIGEST = (
    "sha256:598800c8f08efc8c8aaebda5ae13f310ef0bf66ff86823f58cbadecae46c87fb"
)
_RECORDED_AT = "2026-08-11T06:48:23.307028Z"
_SOURCE_COMMIT = "cc96e7965e183639681d1ed23239db6158b821de"
_PARENT_IMAGE = p37c._CHILD_IMAGE
_CHILD_IMAGE = "sha256:d9c0da9a13a72d1c4d28749421840da13d79a93f748fb9de472a78962f1707d9"
_HARNESS_DIGEST = (
    "sha256:a984e20e65670445f773c142cb3c9b7f50ca5b03f7d5200901e38cd96e623e3f"
)
_IMAGE_LINEAGE_DIGEST = (
    "sha256:bd9645fe769aa6997f099ca51032ae4e0d85eede9d24cde746b4a31723d4b040"
)
_ACTION_DIGEST = (
    "sha256:9ececb9b6882c2d5052dabb8b7ca75d072175948d5c03bbe5fb1e93b94058ad0"
)
_ACTION_CASE_DIGESTS = {
    "coherent_consumed": (
        "sha256:2723cbe1f5546657cc091ad33775e345e0b004c568c64868f653602a9b4c1e91"
    ),
    "expired_fail_stop": (
        "sha256:19592f7ae370314c616cffe6747a7632f7f03926d2d10198863a4ba67ec8359a"
    ),
    "full_activation": (
        "sha256:20f06f8fc9250b97638e82701889ee1a92207062dc1c1b0496c8010416bba0db"
    ),
    "terminal_archive_rotation": (
        "sha256:08156ae60b10631c3fa9fc1e45a06093c2d86d02801e8c335e870d83116c3ff2"
    ),
}
_COLLECTOR_DIGEST = (
    "sha256:80ab3c73d7a7f2c982e32cb6773bc59c6b1b70f19d590017a4d94616ac9f07b2"
)
_ADAPTATION_DIGEST = (
    "sha256:654abea2fe55a49f31ac2f69a56c5c632f09e77a8459f4bdb716b4f231447af5"
)
_PAIR_IDENTITY_DIGEST = (
    "sha256:4bf7e2379611d30a1851a337c7b9f6afd5cdc1c39afe051f11186263f35c4750"
)
_SOURCE_IDENTITY_DIGEST = (
    "sha256:7c2b4f88376dfe5c5a328f6b81db01457f5ef4ce99b07dd695a310eaf793c448"
)
_INSTALLED_IDENTITY_DIGEST = (
    "sha256:c193e8d5d56fb858257ba866f8abc150949b2898d67759746eb1ce0d64fe1f0d"
)
_SOURCE_INSTALL_PATHS = [
    (
        (
            "/src/benchmark/runtime-acquisition-action-systemd/"
            "aragorn-protected-install-coordinator-python312.conf"
        ),
        (
            "/etc/systemd/system/aragorn-protected-install-coordinator.service.d/"
            "python312.conf"
        ),
    ),
    (
        "/src/packaging/libexec/aragorn-protected-install-coordinator.py",
        "/usr/libexec/aragorn/aragorn-protected-install-coordinator.py",
    ),
    (
        "/src/packaging/systemd/aragorn-gateway.tmpfiles",
        "/usr/lib/tmpfiles.d/aragorn-gateway.conf",
    ),
    (
        "/src/packaging/systemd/aragorn-protected-install-coordinator.path",
        "/usr/lib/systemd/system/aragorn-protected-install-coordinator.path",
    ),
    (
        "/src/packaging/systemd/aragorn-protected-install-coordinator.service",
        "/usr/lib/systemd/system/aragorn-protected-install-coordinator.service",
    ),
    (
        "/src/packaging/systemd/var-lib-aragorn\\x2dgateway.mount",
        "/usr/lib/systemd/system/var-lib-aragorn\\x2dgateway.mount",
    ),
    (
        "/src/src/aragorn/protected_install_coordinator.py",
        "/opt/aragorn-broker-p36b/src/aragorn/protected_install_coordinator.py",
    ),
]
_P37C_RECEIPT_PATH = (
    "benchmark/receipts/phase3-runtime-action-worker-activation-expiry-systemd-"
    "qualification-v1-2026-08-09.json"
)
_P37C_RECEIPT_BYTES = 6_655
_P37C_RECEIPT_RAW_DIGEST = (
    "sha256:e01fdcf8e18ecd02ddbbaece02a7b4abe14dd2635396d1ffa7bb9a8f9ed61eb7"
)
_P37C_RECEIPT_DIGEST = (
    "sha256:62d04b3615832f2da7713d5ac7eb2ae14e859454d810f421b79b54d427876fa1"
)
_P37C_VERIFIER_DIGEST = (
    "sha256:46e527ed0977ea5e2778cd775527515732002acf3051a580b786c8f90bcfda97"
)
_SOURCE_REQUEST = {
    "commit": "2235be7c60b551f5de82ade908fd3816455afcda",
    "owner": "anthropics",
    "repository": "skills",
    "schema": "aragorn/github-gateway-request/v1",
    "skill_path": "template",
}
_ANALYZER_IMPLEMENTATION = (
    "sha256:190f4aad373350e17db38de05433cba685864a4a8fc4ef09d1dca77f12fe6350"
)
_ANALYZER_CONFIGURATION = (
    "sha256:21e168d5992a9a5c43b087b68810e661807f1b0db03bd9b9b6c729e054aebe1a"
)
_ANALYZER_RUN_DIGEST = (
    "sha256:7642912456958c161bbdbc2582aa112a2053aea27e9dd607cf44c4a95a1e77df"
)
_INSTALL_DECISION_DIGEST = (
    "sha256:33c00ca9088f8e8012a331390e687c349e7dc14e55f71713c0671c089a709e55"
)
_RUNTIME_CONFORMANCE_DIGEST = (
    "sha256:a56a63860f62a48b51a2b37687f471cecdf1ad83619893a655200df79a290428"
)
_ARTIFACT_GRAPH_DIGEST = (
    "sha256:21beb2e07336cc8e2d1c5ac37d76b553c2b82cb7be70b93f7e85220c26b3093c"
)
_SOURCE_PROOF_DIGEST = (
    "sha256:78bcbe8dbcee265bfeb09b08ade12cf3c91a275ba7892a5f3f4b06af7384e8a3"
)
_SOURCE_CLOSURE_DIGEST = (
    "sha256:f6ee5cf31682f2d34b6398faf05e53360f084ade92adf6f0944e18016d9bd5bc"
)
_ROOT_MANIFEST_DIGEST = (
    "sha256:99c08a9f18b3c4d0b7a07f058f93e69df6c1e4176ffe0f209a085ba317d6c82d"
)
_HANDOFF_MANIFEST_DIGEST = (
    "sha256:a2d3e43f1afd5b84ff34ee21c373444bf64fc447dcc6b03e88e3d425e61aa165"
)
_REVOCATION_DIGEST = (
    "sha256:cdfd19a4856fbe5e5caa1ba03db79d0d9917fc27330744df96507b27d1b73d0e"
)
_RECURSIVE = {
    "expansion_digest": (
        "sha256:ec45ceb57fe1368020849c8aef31bec8ff16c2a57f6728383d1eacca85c5538a"
    ),
    "expansion_proof_digest": (
        "sha256:6402b1ac407b4e11b21d592c6f1be9a5a463ba60aaf2d6f78409f769d2f227b8"
    ),
    "release_asset_result_digests": [],
    "release_pin_set_digest": (
        "sha256:b04ffc44562f0998091639459ae46386ba135b0545cbd55c31ac5a2e573fbe23"
    ),
    "root_manifest_digest": _ROOT_MANIFEST_DIGEST,
}
_CAS_CLOSURE = {
    _SOURCE_PROOF_DIGEST: 974,
    "sha256:7c67870c68c170dc2db7442f5fb3102f0df35ee02394ca3fca889258af9cac02": 1477,
    "sha256:8f37c542cc7b7e41affb55bf9cabe44ada98064e7526b1db8840026d9dde477e": 265,
    _ROOT_MANIFEST_DIGEST: 731,
    "sha256:9bb6da9b6aca8716f753940f26c762e3e38b8a79284f6524a5392ce0f3913010": 36,
    _HANDOFF_MANIFEST_DIGEST: 761,
    "sha256:de58950e6df623902264c93ddad66fe3e84d9725c91362dfb30937d7c46acc64": 1074,
    "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa": 140,
}
_TOP_LEVEL = {
    "acquisition",
    "action",
    "artifacts",
    "authority",
    "bindings",
    "decision",
    "harness",
    "limitations",
    "recorded_at",
    "schema",
}
_LIMITATIONS = [
    "ADAPTED_PYTHON_3_12_CURRENT_RELEASE_NOT_RETAINED_PHASE1_RELEASE_IDENTITY",
    "ONE_LIVE_PUBLIC_GITHUB_COMMIT_AND_SINGLE_FILE_SKILL_ONLY",
    "ONE_EVALUATOR_CONTROLLED_LOOPBACK_PROVIDER_ACTION_ONLY",
    "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "SYSTEMD_252_CGROUP_AND_DOCKER_DNS_ADAPTERS_ARE_FIXTURE_ONLY",
    "NETWORK_DISCONNECTION_IS_WRAPPER_CONTROLLED_AND_PROBE_REVERIFIED",
    "SKILL_BYTES_ARE_BOUND_TO_THE_ACTION_WITHOUT_SEMANTIC_CAUSATION_AUTHORITY",
    "P3_7C_RUNTIME_FLOW_IS_REUSED_WITHOUT_PROMOTING_ITS_PARENT_QUALIFICATION",
    "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
]
_DECISION = {
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "live_same_custody_install_to_action_observed": True,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "retained_evidence_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "same_phase1_release_identity": False,
    "semantic_skill_causation_established": False,
    "status": "P3_8B_OBSERVED_NOT_VERIFIED",
}
_QUALIFICATION_LIMITATIONS = [
    *_LIMITATIONS[:-1],
    "QUARANTINE_CAS_METADATA_AND_SKILL_BYTES_RETAINED_NOT_FULL_NON_SKILL_BLOB_REPLAY",
    "PROVIDER_AND_OPENCLAW_SESSION_RAW_BYTES_NOT_RETAINED",
    "TRACE_PROVES_ONE_ROUTE_CONNECT_WITHOUT_RETRY_NOT_APPLICATION_SEND_COUNT",
    "PYTHON_STDLIB_AND_DYNAMIC_VERIFIER_DEPENDENCY_CLOSURE_NOT_PINNED",
    _LIMITATIONS[-1],
]
_QUALIFICATION_DECISION = {
    "aggregate_gate_eligible": False,
    "bounded_live_acquisition_action_evidence_eligible": True,
    "edr_claim_eligible": False,
    "installer_authority_eligible": False,
    "live_same_custody_install_to_action_verified": True,
    "network_disconnected_before_runtime_verified": True,
    "one_coherent_allow_created_consumed_action_verified": True,
    "parent_p3_7c_unchanged": True,
    "phase3_exit_eligible": False,
    "public_release_eligible": False,
    "qualified_pair_retained_evidence_eligible": True,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "same_phase1_release_identity": False,
    "semantic_skill_causation_established": False,
    "source_observation_unchanged": True,
    "source_observation_verified": True,
    "status": "P3_8B_BOUNDED_PASS",
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def verify_runtime_acquisition_action_systemd_evidence(
    document: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
    p37b_observation: Mapping[str, Any],
    p36b_observation: Mapping[str, Any],
    p37b_receipt: Mapping[str, Any],
    p37c_receipt: Mapping[str, Any],
    *,
    expected_digest: str | None,
) -> None:
    """Replay the exact P3.8b observation without promoting broader authority."""

    try:
        _expect(expected_digest == _EVIDENCE_DIGEST, "retained digest pin changed")
        _expect(not p37c.parent_verifier._contains_float(document), "float is invalid")
        document = _snapshot(document)
        p37c_observation = _snapshot(p37c_observation)
        p37b_observation = _snapshot(p37b_observation)
        p36b_observation = _snapshot(p36b_observation)
        p37b_receipt = _snapshot(p37b_receipt)
        p37c_receipt = _snapshot(p37c_receipt)
        encoded = canonical_json(document)
        _expect(set(document) == _TOP_LEVEL, "top-level fields changed")
        _expect(canonical_digest(document) == _EVIDENCE_DIGEST, "evidence changed")
        _expect(
            _raw_digest(encoded + b"\n") == _EVIDENCE_RAW_DIGEST
            and len(encoded) + 1 == _EVIDENCE_BYTES,
            "raw evidence identity changed",
        )
        _expect(document["schema"] == _SCHEMA, "schema changed")
        _expect(document["authority"] == _AUTHORITY, "authority changed")
        _expect(document["recorded_at"] == _RECORDED_AT, "recorded time changed")
        _expect(document["limitations"] == _LIMITATIONS, "source ceiling changed")
        _expect(
            canonical_json(document["decision"]) == canonical_json(_DECISION),
            "source decision changed",
        )

        expected_parent = (
            p37c.runtime_action_worker_activation_expiry_systemd_qualification(
                p37c_observation,
                p37b_observation,
                p36b_observation,
                p37b_receipt,
                expected_digest=p37c._EVIDENCE_DIGEST,
                implementation_digest=_P37C_VERIFIER_DIGEST,
            )
        )
        _require_receipt(
            p37c_receipt,
            expected_parent,
            digest=_P37C_RECEIPT_DIGEST,
            raw_digest=_P37C_RECEIPT_RAW_DIGEST,
            size=_P37C_RECEIPT_BYTES,
        )
        _verify_record_closure(document)
        _verify_artifacts(document["artifacts"])
        _verify_harness(document["harness"])
        acquisition = _verify_acquisition(document["acquisition"])
        action_context = _verify_action(
            document["action"],
            document["harness"],
            p37c_observation,
            acquisition,
        )
        _verify_bindings(document["bindings"], acquisition, action_context)
        _verify_network_order(document, acquisition, action_context)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        IndexError,
        KeyError,
        RuntimeActionBrokerError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime acquisition action systemd evidence: {exc}"
        ) from exc


def runtime_acquisition_action_systemd_qualification(
    document: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
    p37b_observation: Mapping[str, Any],
    p36b_observation: Mapping[str, Any],
    p37b_receipt: Mapping[str, Any],
    p37c_receipt: Mapping[str, Any],
    *,
    expected_digest: str | None,
    implementation_digest: str | None = None,
) -> dict[str, Any]:
    """Return the deterministic bounded P3.8b qualification."""

    try:
        (
            document,
            p37c_observation,
            p37b_observation,
            p36b_observation,
            p37b_receipt,
            p37c_receipt,
        ) = (
            _snapshot(value)
            for value in (
                document,
                p37c_observation,
                p37b_observation,
                p36b_observation,
                p37b_receipt,
                p37c_receipt,
            )
        )
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise AdmissionEvidenceError(
            f"invalid runtime acquisition action systemd evidence: {exc}"
        ) from exc
    verify_runtime_acquisition_action_systemd_evidence(
        document,
        p37c_observation,
        p37b_observation,
        p36b_observation,
        p37b_receipt,
        p37c_receipt,
        expected_digest=expected_digest,
    )
    verifier_digest = _raw_digest(Path(__file__).read_bytes())
    _expect(
        implementation_digest is not None and implementation_digest == verifier_digest,
        "verifier implementation pin changed",
    )
    harness = document["harness"]
    acquisition = document["acquisition"]
    action = document["action"]
    coherent = action["cases"]["coherent_consumed"]
    transaction = acquisition["protected"]["transaction"]
    return {
        "assurance": (
            "SEMANTICALLY_REPLAY_VERIFIED_PINNED_LIVE_ACQUISITION_TO_ONE_"
            "COHERENT_RUNTIME_ACTION"
        ),
        "bindings": {
            "source_observation": {
                "authority": _AUTHORITY,
                "bytes": _EVIDENCE_BYTES,
                "canonical_digest": _EVIDENCE_DIGEST,
                "path": _RETAINED_PATH,
                "raw_digest": _EVIDENCE_RAW_DIGEST,
                "schema": _SCHEMA,
            },
            "parent_qualification": {
                "observation": {
                    "bytes": p37c._EVIDENCE_BYTES,
                    "canonical_digest": p37c._EVIDENCE_DIGEST,
                    "path": p37c._RETAINED_PATH,
                    "raw_digest": p37c._EVIDENCE_RAW_DIGEST,
                },
                "receipt": {
                    "bytes": _P37C_RECEIPT_BYTES,
                    "canonical_digest": _P37C_RECEIPT_DIGEST,
                    "path": _P37C_RECEIPT_PATH,
                    "raw_digest": _P37C_RECEIPT_RAW_DIGEST,
                },
            },
            "harness": {
                "child_image_id": harness["document"]["image_id"],
                "container_cgroup_digest": harness["container_cgroup"]["digest"],
                "container_id": harness["document"]["container_id"],
                "harness_digest": harness["digest"],
                "image_lineage_digest": canonical_digest(
                    harness["document"]["image_lineage"]
                ),
                "parent_image_id": harness["document"]["parent_image_id"],
                "source_commit": harness["document"]["source_commit"],
            },
            "implementation": {
                "adapter_digest": document["artifacts"]["gateway_adaptation"][
                    "adapter"
                ]["digest"],
                "capture_recipe_digest": document["artifacts"]["collector"][
                    "capture_recipe"
                ]["digest"],
                "dockerfile_digest": document["artifacts"]["collector"]["dockerfile"][
                    "digest"
                ],
                "gateway_postimage_digest": document["artifacts"]["gateway_adaptation"][
                    "installed"
                ]["digest"],
                "gateway_preimage_digest": document["artifacts"]["gateway_adaptation"][
                    "preimage"
                ]["digest"],
                "installed_identity_digest": _INSTALLED_IDENTITY_DIGEST,
                "p37c_verifier_digest": _P37C_VERIFIER_DIGEST,
                "package_tree_digest": document["artifacts"]["release_identity"][
                    "document"
                ]["package"]["tree_digest"],
                "probe_digest": document["artifacts"]["collector"]["probe"]["digest"],
                "release_identity_digest": document["artifacts"]["release_identity"][
                    "digest"
                ],
                "source_identity_digest": _SOURCE_IDENTITY_DIGEST,
                "source_install_pair_identity_digest": _PAIR_IDENTITY_DIGEST,
                "verifier_implementation_digest": verifier_digest,
            },
            "acquisition": {
                "cas_closure_digest": acquisition["quarantine"]["cas_before_runtime"][
                    "closure_digest"
                ],
                "context_id": transaction["context_id"],
                "gateway_profile_digest": acquisition["coordinator"]["result"][
                    "gateway_profile_digest"
                ],
                "manifest_digest": transaction["manifest_digest"],
                "quarantine_receipt_digest": acquisition["quarantine"][
                    "receipt_digest"
                ],
                "source_request": dict(acquisition["source_request"]),
                "tree_digest": transaction["tree_digest"],
            },
            "custody": {
                "active_record_digest": acquisition["protected"]["record"]["digest"],
                "claim_digest": acquisition["protected"]["claim"]["digest"],
                "skill_digest": acquisition["protected"]["skill"]["digest"],
                "transaction_digest": canonical_digest(transaction),
            },
            "network": {
                "acquisition_complete_marker_digest": acquisition["network"][
                    "acquisition_complete_marker"
                ]["file"]["digest"],
                "disconnected_before_runtime": True,
                "disconnected_marker_digest": acquisition["network"][
                    "disconnected_marker"
                ]["file"]["digest"],
                "public_connect_succeeded": False,
                "runtime_interfaces": ["lo"],
            },
            "runtime_action": {
                "action_digest": _ACTION_DIGEST,
                "consumed_state_digest": coherent["grant_state"]["digest"],
                "fresh_grant_digest": action["inputs"]["fresh_grant"]["digest"],
                "profile_digest": action["profiles"]["worker"]["digest"],
                "profile_receipt_digest": coherent["receipt"]["digest"],
                "target_digest": coherent["target"]["digest"],
            },
        },
        "cases": {
            "live_acquisition": {
                "file_count": acquisition["quarantine"]["receipt"]["file_count"],
                "source": "anthropics/skills@2235be7c60b551f5de82ade908fd3816455afcda:template",
                "status": "PASS",
                "verdict": "COMPLETED_NOT_INSTALLER_AUTHORITY",
            },
            "same_custody_binding": {
                "skill_digest": acquisition["protected"]["skill"]["digest"],
                "status": "PASS",
                "transaction_digest": canonical_digest(transaction),
                "tree_digest": transaction["tree_digest"],
            },
            "network_cutover": {
                "disconnected_before_runtime": True,
                "public_connect_succeeded": False,
                "runtime_interfaces": ["lo"],
                "status": "PASS",
            },
            "coherent_action": {
                "driver_status": "COMPLETED",
                "effect_status": "CREATED",
                "grant_state": "CONSUMED",
                "status": "PASS",
                "verdict": "ALLOW",
            },
        },
        "decision": dict(_QUALIFICATION_DECISION),
        "limitations": list(_QUALIFICATION_LIMITATIONS),
        "schema": "aragorn/runtime-acquisition-action-systemd-qualification/v1",
        "source_recorded_at": document["recorded_at"],
    }


def _verify_record_closure(document: Mapping[str, Any]) -> None:
    records: dict[str, list[Mapping[str, Any]]] = {
        name: []
        for name in ("documents", "files", "raw", "commands", "sockets", "clocks")
    }

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            if "digest" in value and isinstance(value.get("document"), Mapping):
                records["documents"].append(value)
            if {"bytes", "digest", "path", "stat"}.issubset(value):
                records["files"].append(value)
            if set(value) == {"base64", "bytes", "digest"}:
                records["raw"].append(value)
            if {
                "argv",
                "caller",
                "completed_at",
                "completed_monotonic_ns",
                "elapsed_ns",
                "exit_code",
                "signal",
                "started_at",
                "started_monotonic_ns",
                "stderr",
                "stdout",
            }.issubset(value):
                records["commands"].append(value)
            if set(value) == {"metadata", "path", "present", "unix"}:
                records["sockets"].append(value)
            if set(value) == {
                "boot_id",
                "boottime_ns",
                "clocksource",
                "monotonic_ns",
                "proc_uptime",
                "realtime_ns",
                "recorded_at",
                "timedatectl",
            }:
                records["clocks"].append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    _expect(
        {name: len(values) for name, values in records.items()}
        == {
            "documents": 36,
            "files": 168,
            "raw": 134,
            "commands": 53,
            "sockets": 31,
            "clocks": 8,
        },
        "retained record closure changed",
    )
    for value in records["documents"]:
        _expect(
            value["digest"] == canonical_digest(value["document"]), "document changed"
        )
    for value in records["files"]:
        if "path" in value["stat"]:
            _verify_bounded_file(value)
        else:
            p37c._verify_file(value)
    for value in records["raw"]:
        p37c._verify_raw(value)
    for value in records["commands"]:
        p37c._verify_command(value)
        _expect(
            value["started_monotonic_ns"] >= 0,
            "command monotonic time changed",
        )
    socket_owners = {
        "/run/aragorn-runtime-action-worker/worker.sock": (997, 992),
        "/run/aragorn-runtime-observation/sensor.sock": (996, 997),
        "/var/lib/aragorn-runtime-action/control/broker.sock": (995, 996),
    }
    _expect(
        {
            (path, present): sum(
                value["path"] == path and value["present"] is present
                for value in records["sockets"]
            )
            for path in socket_owners
            for present in (False, True)
        }
        == {
            ("/run/aragorn-runtime-action-worker/worker.sock", False): 4,
            ("/run/aragorn-runtime-action-worker/worker.sock", True): 6,
            ("/run/aragorn-runtime-observation/sensor.sock", False): 4,
            ("/run/aragorn-runtime-observation/sensor.sock", True): 6,
            ("/var/lib/aragorn-runtime-action/control/broker.sock", False): 5,
            ("/var/lib/aragorn-runtime-action/control/broker.sock", True): 6,
        },
        "socket inventory changed",
    )
    for value in records["sockets"]:
        _expect(
            value["path"] in socket_owners and value["unix"] == [],
            "socket path changed",
        )
        p37c._verify_socket_record(value, value["path"])
        if value["present"]:
            _expect(
                (value["metadata"]["uid"], value["metadata"]["gid"])
                == socket_owners[value["path"]],
                "socket owner changed",
            )
    for value in records["clocks"]:
        p37c._verify_clock(value)


def _verify_bounded_file(value: Mapping[str, Any]) -> bytes:
    _expect(
        set(value) == {"base64", "bytes", "digest", "path", "stat"},
        "bounded file fields changed",
    )
    stat_value = value["stat"]
    _expect(
        set(stat_value)
        == {
            "ctime_ns",
            "device",
            "gid",
            "inode",
            "mode",
            "mtime_ns",
            "nlink",
            "path",
            "size",
            "type",
            "uid",
        }
        and stat_value["path"] == value["path"]
        and stat_value["type"] == "file"
        and re.fullmatch(r"[0-7]{4}", stat_value["mode"]) is not None
        and all(
            isinstance(stat_value[field], int)
            and not isinstance(stat_value[field], bool)
            and stat_value[field] >= 0
            for field in ("ctime_ns", "device", "gid", "mtime_ns", "size", "uid")
        )
        and all(
            isinstance(stat_value[field], int)
            and not isinstance(stat_value[field], bool)
            and stat_value[field] > 0
            for field in ("inode", "nlink")
        ),
        "bounded file metadata changed",
    )
    raw = p37c._verify_raw(
        {field: value[field] for field in ("base64", "bytes", "digest")}
    )
    expected_size = 0 if value["path"].startswith("/proc/") else len(raw)
    _expect(stat_value["size"] == expected_size, "bounded file size changed")
    return raw


def _verify_artifacts(value: Mapping[str, Any]) -> None:
    _expect(
        set(value)
        == {"collector", "gateway_adaptation", "installed", "release_identity"},
        "artifact fields changed",
    )
    collector = value["collector"]
    _expect(
        set(collector) == {"capture_recipe", "dockerfile", "probe"}
        and canonical_digest(collector) == _COLLECTOR_DIGEST,
        "collector closure changed",
    )
    for name, record in collector.items():
        p37c._verify_file(record)
        _expect(
            record["path"]
            == {
                "capture_recipe": "/src/scripts/capture_runtime_acquisition_action_systemd.sh",
                "dockerfile": "/src/benchmark/runtime-acquisition-action-systemd/Dockerfile",
                "probe": "/src/scripts/runtime_acquisition_action_systemd_probe.py",
            }[name]
            and record["stat"]["uid"] == record["stat"]["gid"] == 0
            and record["stat"]["nlink"] == 1
            and record["stat"]["mode"] == ("0444" if name == "dockerfile" else "0555"),
            "collector custody changed",
        )
    adaptation = value["gateway_adaptation"]
    _expect(
        set(adaptation) == {"adapter", "installed", "preimage"}
        and canonical_digest(adaptation) == _ADAPTATION_DIGEST,
        "gateway adaptation changed",
    )
    expected_gateway = {
        "adapter": "sha256:e13b2408655e1b1c2235bc7f8e511062547440ee73119a82bffd1f70f168fc30",
        "installed": "sha256:b31305c4555607a19a54a3ef08a61a243fd60ab1b5cacb38b1b04569ec3cac56",
        "preimage": "sha256:21e3a74cb0927d1a160b089797cc169e1d1bfc8c68b7a2b5005904ee7aabe07c",
    }
    for name, record in adaptation.items():
        p37c._verify_file(record)
        _expect(
            record["digest"] == expected_gateway[name]
            and record["path"]
            == {
                "adapter": (
                    "/src/benchmark/runtime-acquisition-action-systemd/"
                    "adapt-github-gateway.py"
                ),
                "installed": ("/opt/aragorn-broker-p36b/src/aragorn/github_gateway.py"),
                "preimage": (
                    "/src/benchmark/runtime-acquisition-action-systemd/"
                    "github-gateway-preimage.py"
                ),
            }[name]
            and record["stat"]["uid"] == record["stat"]["gid"] == 0
            and record["stat"]["mode"] == "0444"
            and record["stat"]["nlink"] == 1,
            "gateway adaptation custody changed",
        )
    installed = value["installed"]
    _expect(
        isinstance(installed, list) and len(installed) == 7,
        "installed inventory changed",
    )
    _expect(
        [(pair["source"]["path"], pair["installed"]["path"]) for pair in installed]
        == _SOURCE_INSTALL_PATHS,
        "installed path inventory changed",
    )
    pair_identity = []
    source_identity = []
    installed_identity = []
    artifact_records = [*collector.values(), *adaptation.values()]
    for pair in installed:
        _expect(set(pair) == {"installed", "source"}, "installed pair changed")
        source, target = pair["source"], pair["installed"]
        p37c._verify_file(source)
        p37c._verify_file(target)
        expected_mode = {
            "/usr/libexec/aragorn/aragorn-protected-install-coordinator.py": "0555",
            "/usr/lib/tmpfiles.d/aragorn-gateway.conf": "0644",
        }.get(target["path"], "0444")
        _expect(
            (source["digest"], source["bytes"]) == (target["digest"], target["bytes"])
            and source["stat"]["uid"] == source["stat"]["gid"] == 0
            and source["stat"]["mode"] == "0444"
            and source["stat"]["nlink"] == 1
            and target["stat"]["uid"] == target["stat"]["gid"] == 0
            and target["stat"]["mode"] == expected_mode
            and target["stat"]["nlink"] == 1,
            "source/install binding changed",
        )
        pair_identity.append(
            {
                "bytes": target["bytes"],
                "digest": target["digest"],
                "installed": target["path"],
                "mode": target["stat"]["mode"],
                "source": source["path"],
            }
        )
        source_identity.append(
            {
                "bytes": source["bytes"],
                "digest": source["digest"],
                "mode": source["stat"]["mode"],
                "path": source["path"],
            }
        )
        installed_identity.append(
            {
                "bytes": target["bytes"],
                "digest": target["digest"],
                "mode": target["stat"]["mode"],
                "path": target["path"],
            }
        )
        artifact_records.extend((source, target))
    _expect(
        canonical_digest(pair_identity) == _PAIR_IDENTITY_DIGEST
        and canonical_digest(source_identity) == _SOURCE_IDENTITY_DIGEST
        and canonical_digest(installed_identity) == _INSTALLED_IDENTITY_DIGEST,
        "installed implementation closure changed",
    )
    _expect(
        len({record["path"] for record in artifact_records})
        == len(artifact_records)
        == len(
            {
                (record["stat"]["device"], record["stat"]["inode"])
                for record in artifact_records
            }
        ),
        "artifact identity closure changed",
    )
    release = value["release_identity"]
    p37c._verify_document_snapshot(release)
    expected_release = {
        "broker": {
            "digest": p36b._BROKER_DIGEST,
            "path": (
                "benchmark/admission/openclaw-v2026.7.1/"
                "protected-install-broker-recursive-v3.py"
            ),
        },
        "launcher": {
            "digest": (
                "sha256:e27b2ed1be6e24d758b148e9d6f9740d4e1c5cd74e87462d2fb2d9686dc5810b"
            ),
            "path": "/usr/libexec/aragorn/aragorn-protected-install-launcher.py",
        },
        "package": {
            "root": "/opt/aragorn-broker-p36b",
            "tree_digest": (
                "sha256:c4c2aec999a3731d0193c59114d52bfced1dca89163738a3400776f2bc42463d"
            ),
        },
        "python": {"digest": p36b._PYTHON_DIGEST, "path": "/usr/local/bin/python3.12"},
        "schema": "aragorn/protected-broker-launch-identity/v1",
    }
    _expect(
        release["digest"]
        == "sha256:08ce966f9523c211ddeea9d48f386c73491d69f685c6a83d09f42d5887144cda"
        and canonical_json(release["document"]) == canonical_json(expected_release)
        and release["file"]["path"] == "/etc/aragorn/protected-broker-release.json"
        and release["file"]["stat"]["uid"] == release["file"]["stat"]["gid"] == 0
        and release["file"]["stat"]["mode"] == "0400"
        and release["file"]["stat"]["nlink"] == 1,
        "release identity changed",
    )


def _verify_harness(value: Mapping[str, Any]) -> Mapping[str, Any]:
    _expect(
        set(value) == {"container_cgroup", "digest", "document", "file"},
        "harness fields changed",
    )
    stable = {field: value[field] for field in ("digest", "document", "file")}
    harness = p37c._verify_document_snapshot(stable)
    _expect(
        value["digest"] == _HARNESS_DIGEST
        and value["file"]["path"] == "/run/aragorn-harness.json"
        and value["file"]["stat"]["uid"] == value["file"]["stat"]["gid"] == 0
        and value["file"]["stat"]["mode"] == "0600"
        and value["file"]["stat"]["nlink"] == 1,
        "harness digest or custody changed",
    )
    cgroup_raw = _verify_bounded_file(value["container_cgroup"])
    _expect(
        cgroup_raw
        == f"0::/docker/{harness['container_id']}/init.scope\n".encode("ascii"),
        "container cgroup binding changed",
    )
    _expect(
        set(harness)
        == {
            "capture_disposition",
            "capture_network",
            "capture_network_attachment",
            "capture_network_inspect",
            "container_id",
            "host_config",
            "image_id",
            "image_lineage",
            "image_reference",
            "openclaw_runtime_mount",
            "openclaw_runtime_volume",
            "openclaw_runtime_volume_identity",
            "parent_image_id",
            "platform",
            "profile_label",
            "published_ports",
            "run_image_reference",
            "schema",
            "source_commit",
            "source_commit_verification",
        }
        and harness["schema"] == "aragorn/runtime-acquisition-action-systemd-harness/v1"
        and harness["capture_disposition"]
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and re.fullmatch(r"[0-9a-f]{64}", harness["container_id"]) is not None
        and harness["container_id"] != "0" * 64
        and harness["source_commit"] == _SOURCE_COMMIT
        and harness["parent_image_id"] == _PARENT_IMAGE
        and harness["image_id"] == harness["run_image_reference"] == _CHILD_IMAGE
        and harness["profile_label"] == "p3.8b"
        and harness["platform"] == "linux"
        and canonical_digest(harness["image_lineage"]) == _IMAGE_LINEAGE_DIGEST,
        "harness implementation binding changed",
    )
    lineage = harness["image_lineage"]
    _expect(
        set(lineage) == {"added_layers", "child", "parent"}
        and set(lineage["parent"]) == {"id", "layers", "rootfs_type"}
        and set(lineage["child"]) == {"id", "layers", "rootfs_type"}
        and isinstance(lineage["added_layers"], list)
        and all(isinstance(item, str) for item in lineage["added_layers"])
        and all(
            isinstance(entry["layers"], list)
            and all(isinstance(item, str) for item in entry["layers"])
            for entry in (lineage["parent"], lineage["child"])
        )
        and lineage["parent"]["id"] == _PARENT_IMAGE
        and lineage["child"]["id"] == _CHILD_IMAGE
        and lineage["parent"]["rootfs_type"]
        == lineage["child"]["rootfs_type"]
        == "layers"
        and lineage["child"]["layers"]
        == [*lineage["parent"]["layers"], *lineage["added_layers"]]
        and len(lineage["added_layers"]) == 7,
        "image lineage changed",
    )
    host = harness["host_config"]
    network = harness["capture_network"]
    attachment = harness["capture_network_attachment"]
    expected_mount = {
        "destination": "/runtime",
        "driver": "local",
        "mode": "ro",
        "rw": False,
        "source": "aragorn-openclaw-2026-7-1-runtime",
        "type": "volume",
    }
    expected_host = {
        "binds": [
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            "aragorn-openclaw-2026-7-1-runtime:/runtime:ro",
        ],
        "cgroupns_mode": "host",
        "ipc_mode": "private",
        "network_mode": network["name"],
        "port_bindings": {},
        "privileged": True,
        "publish_all_ports": False,
        "readonly_rootfs": False,
        "runtime": "runc",
        "security_opt": ["label=disable"],
        "tmpfs": {
            "/run": "rw,nosuid,nodev,noexec,mode=755",
            "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
        },
        "userns_mode": "",
    }
    _expect(
        canonical_json(host) == canonical_json(expected_host)
        and harness["image_reference"]
        == "aragorn-p38b-runtime-acquisition-action-systemd"
        and harness["published_ports"] == {}
        and harness["openclaw_runtime_volume"] == "aragorn-openclaw-2026-7-1-runtime"
        and canonical_json(harness["openclaw_runtime_mount"])
        == canonical_json(expected_mount)
        and canonical_json(harness["openclaw_runtime_volume_identity"])
        == canonical_json(
            {
                "driver": "local",
                "labels": None,
                "name": "aragorn-openclaw-2026-7-1-runtime",
                "options": None,
                "scope": "local",
            }
        )
        and set(network)
        == {
            "attachable",
            "config_from",
            "config_only",
            "driver",
            "enable_ipv4",
            "enable_ipv6",
            "id",
            "ingress",
            "internal",
            "ipam",
            "labels",
            "name",
            "options",
            "scope",
        }
        and network["driver"] == "bridge"
        and network["scope"] == "local"
        and network["config_from"] == {"Network": ""}
        and network["config_only"] is False
        and network["enable_ipv4"] is True
        and network["enable_ipv6"] is False
        and network["internal"] is False
        and network["attachable"] is False
        and network["ingress"] is False
        and network["options"] == {}
        and canonical_json(network["ipam"])
        == canonical_json(
            {
                "Config": [{"Gateway": "172.18.0.1", "Subnet": "172.18.0.0/16"}],
                "Driver": "default",
                "Options": {},
            }
        )
        and set(network["labels"])
        == {"dev.aragorn.capture-owner", "dev.aragorn.profile"}
        and network["labels"]["dev.aragorn.profile"] == "p3.8b"
        and network["labels"]["dev.aragorn.capture-owner"]
        == f"{_SOURCE_COMMIT}:{network['name'].rsplit('-', 1)[1]}"
        and re.fullmatch(r"[0-9a-f]{64}", network["id"]) is not None
        and network["id"] != "0" * 64
        and re.fullmatch(r"aragorn-p38b-acquisition-[1-9][0-9]*", network["name"])
        is not None
        and set(attachment)
        == {
            "aliases",
            "dns_names",
            "endpoint_id",
            "gateway",
            "global_ipv6_address",
            "global_ipv6_prefix_len",
            "ip_address",
            "ip_prefix_len",
            "ipv6_gateway",
            "links",
            "mac_address",
            "network_id",
        }
        and attachment["network_id"] == network["id"]
        and attachment["gateway"] == network["ipam"]["Config"][0]["Gateway"]
        and attachment["aliases"] is None
        and attachment["links"] is None
        and attachment["global_ipv6_address"] == attachment["ipv6_gateway"] == ""
        and isinstance(attachment["global_ipv6_prefix_len"], int)
        and not isinstance(attachment["global_ipv6_prefix_len"], bool)
        and attachment["global_ipv6_prefix_len"] == 0
        and re.fullmatch(r"[0-9a-f]{64}", attachment["endpoint_id"]) is not None
        and attachment["endpoint_id"] != "0" * 64
        and re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", attachment["mac_address"])
        is not None
        and attachment["mac_address"] != "00:00:00:00:00:00"
        and int(attachment["mac_address"][:2], 16) & 1 == 0
        and re.fullmatch(r"[0-9]+(?:[.][0-9]+){3}", attachment["gateway"]) is not None
        and attachment["ip_address"] == "172.18.0.2"
        and attachment["dns_names"]
        == [
            "aragorn-p38b-runtime-acquisition-action-"
            + network["name"].rsplit("-", 1)[1],
            harness["container_id"][:12],
        ]
        and isinstance(attachment["ip_prefix_len"], int)
        and not isinstance(attachment["ip_prefix_len"], bool)
        and attachment["ip_prefix_len"] == 16,
        "harness network or host profile changed",
    )
    inspect_raw = p37c._verify_raw(harness["capture_network_inspect"])
    inspected = json.loads(inspect_raw)
    _expect(
        isinstance(inspected, list)
        and len(inspected) == 1
        and set(inspected[0])
        == {
            "Attachable",
            "ConfigFrom",
            "ConfigOnly",
            "Containers",
            "Created",
            "Driver",
            "EnableIPv4",
            "EnableIPv6",
            "IPAM",
            "Id",
            "Ingress",
            "Internal",
            "Labels",
            "Name",
            "Options",
            "Scope",
            "Status",
        }
        and inspected[0]["Id"] == network["id"]
        and inspected[0]["Name"] == network["name"]
        and inspected[0]["Driver"] == network["driver"]
        and inspected[0]["Scope"] == network["scope"]
        and inspected[0]["Internal"] is network["internal"]
        and inspected[0]["Attachable"] is network["attachable"]
        and inspected[0]["Ingress"] is network["ingress"]
        and inspected[0]["EnableIPv4"] is network["enable_ipv4"]
        and inspected[0]["EnableIPv6"] is network["enable_ipv6"]
        and canonical_json(inspected[0]["IPAM"]) == canonical_json(network["ipam"])
        and canonical_json(inspected[0]["Options"])
        == canonical_json(network["options"])
        and canonical_json(inspected[0]["Labels"]) == canonical_json(network["labels"])
        and inspected[0]["ConfigOnly"] is network["config_only"]
        and canonical_json(inspected[0]["ConfigFrom"])
        == canonical_json(network["config_from"])
        and isinstance(inspected[0]["Created"], str)
        and _time(inspected[0]["Created"])
        and canonical_json(inspected[0]["Status"])
        == canonical_json(
            {
                "IPAM": {
                    "Subnets": {
                        "172.18.0.0/16": {
                            "DynamicIPsAvailable": 65_532,
                            "IPsInUse": 4,
                        }
                    }
                }
            }
        )
        and set(inspected[0].get("Containers") or {}) == {harness["container_id"]}
        and canonical_json(inspected[0]["Containers"][harness["container_id"]])
        == canonical_json(
            {
                "EndpointID": attachment["endpoint_id"],
                "IPv4Address": (
                    f"{attachment['ip_address']}/{attachment['ip_prefix_len']}"
                ),
                "IPv6Address": "",
                "MacAddress": attachment["mac_address"],
                "Name": attachment["dns_names"][0],
            }
        ),
        "captured network inspection changed",
    )
    verification = harness["source_commit_verification"]
    commit_raw = p37c._verify_raw(verification["commit_object"])
    _expect(
        set(verification)
        == {"command", "commit_object", "exit_code", "stderr", "stdout"}
        and verification["command"] == ["git", "verify-commit", "--raw", _SOURCE_COMMIT]
        and isinstance(verification["exit_code"], int)
        and not isinstance(verification["exit_code"], bool)
        and verification["exit_code"] == 0
        and hashlib.sha1(
            f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
        ).hexdigest()
        == _SOURCE_COMMIT
        and b"gpgsig " in commit_raw
        and p37c._verify_raw(verification["stdout"]) == b""
        and p37c._verify_raw(verification["stderr"])
        == (
            b'Good "git" signature for yousif.snazhat@gmail.com with ED25519 key '
            b"SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk\n"
        ),
        "source commit verification changed",
    )
    return harness


def _verify_acquisition(value: Mapping[str, Any]) -> dict[str, Any]:
    _expect(
        set(value)
        == {
            "coordinator",
            "journals",
            "network",
            "protected",
            "quarantine",
            "source_request",
            "timing",
        }
        and value["source_request"] == _SOURCE_REQUEST,
        "acquisition fields changed",
    )
    timing = value["timing"]
    _expect(
        set(timing) == {"completed_at", "started_at"}
        and _time(timing["started_at"]) <= _time(timing["completed_at"]),
        "acquisition timing changed",
    )
    acquisition_started_ns = int(
        _time(timing["started_at"]).timestamp() * 1_000_000_000
    )
    acquisition_completed_ns = int(
        _time(timing["completed_at"]).timestamp() * 1_000_000_000
    )
    coordinator = value["coordinator"]
    _expect(
        set(coordinator) == {"command", "path_unit_start", "result", "state"},
        "coordinator fields changed",
    )
    command = coordinator["command"]
    result = coordinator["result"]
    stdout = p37c._verify_raw(command["stdout"])
    path_start = coordinator["path_unit_start"]
    _expect(
        set(result)
        == {
            "assurance",
            "context_id",
            "gateway_profile_digest",
            "installer_work_eligible",
            "manifest_digest",
            "operation",
            "quarantine_authority",
            "quarantine_receipt_digest",
            "runtime_conformance_qualified",
            "schema",
            "service_request_digest",
            "source_request",
            "status",
        }
        and command["exit_code"] == 0
        and command["signal"] is None
        and json.loads(stdout) == result
        and canonical_json(result) + b"\n" == stdout
        and _time(timing["started_at"])
        <= _time(command["started_at"])
        <= _time(command["completed_at"])
        <= _time(timing["completed_at"])
        and result["source_request"] == _SOURCE_REQUEST
        and result["schema"] == "aragorn/protected-install-coordinator-result/v1"
        and result["operation"] == "install"
        and result["assurance"]
        == "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        and result["quarantine_authority"] == "QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY"
        and result["status"] == "COMPLETED_NOT_INSTALLER_AUTHORITY"
        and result["installer_work_eligible"] is False
        and result["runtime_conformance_qualified"] is False,
        "coordinator result changed",
    )
    _expect(
        command["argv"]
        == [
            "/usr/local/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/aragorn-protected-install-coordinator.py",
            "submit",
            "install",
            "anthropics",
            "skills",
            _SOURCE_REQUEST["commit"],
            "template",
        ]
        and command["signal"] is None
        and p37c._verify_raw(command["stderr"]) == b"",
        "coordinator command changed",
    )
    _expect(
        path_start["argv"]
        == ["systemctl", "start", "aragorn-protected-install-coordinator.path"]
        and path_start["exit_code"] == 0
        and path_start["signal"] is None
        and p37c._verify_raw(path_start["stdout"]) == b""
        and p37c._verify_raw(path_start["stderr"]) == b""
        and path_start["completed_monotonic_ns"] <= command["started_monotonic_ns"]
        and _time(path_start["started_at"])
        <= _time(path_start["completed_at"])
        <= _time(timing["started_at"])
        <= _time(command["started_at"]),
        "coordinator path activation changed",
    )
    state = p37c._verify_document_snapshot(coordinator["state"])
    active = state["expected_active"]
    _expect(
        set(state)
        == {
            "assurance",
            "expected_active",
            "schema",
            "service_request_digest",
            "tree_digest",
            "version_path",
        }
        and set(active)
        == {
            "context_id",
            "gateway_profile_digest",
            "manifest_digest",
            "quarantine_receipt_digest",
            "recursive",
            "source_request",
        }
        and set(active["recursive"])
        == {
            "expansion_digest",
            "expansion_proof_digest",
            "release_asset_result_digests",
            "release_pin_set_digest",
            "root_manifest_digest",
        }
        and state["schema"] == "aragorn/protected-install-coordinator-state/v3"
        and state["assurance"] == result["assurance"]
        and state["service_request_digest"] == result["service_request_digest"]
        and coordinator["state"]["file"]["path"]
        == "/var/lib/aragorn-protected/coordinator-active.json"
        and coordinator["state"]["file"]["stat"]["uid"]
        == coordinator["state"]["file"]["stat"]["gid"]
        == 0
        and coordinator["state"]["file"]["stat"]["mode"] == "0400"
        and coordinator["state"]["file"]["stat"]["nlink"] == 1
        and active["source_request"] == _SOURCE_REQUEST
        and canonical_json(active["recursive"]) == canonical_json(_RECURSIVE)
        and all(
            active[field] == result[field]
            for field in (
                "context_id",
                "gateway_profile_digest",
                "manifest_digest",
                "quarantine_receipt_digest",
            )
        ),
        "coordinator state join changed",
    )
    quarantine = value["quarantine"]
    _expect(
        set(quarantine)
        == {
            "cas_after_runtime",
            "cas_before_runtime",
            "namespace",
            "receipt",
            "receipt_digest",
            "source_skill",
        },
        "quarantine fields changed",
    )
    receipt = quarantine["receipt"]
    request_digest = canonical_digest(_SOURCE_REQUEST)
    _expect(
        set(receipt)
        == {
            "authority",
            "containment_profile",
            "file_count",
            "gateway",
            "gateway_profile_digest",
            "handoff_manifest_digest",
            "manifest_digest",
            "protected_cas",
            "receipt_id",
            "request",
            "request_digest",
            "schema",
            "source_assurance",
            "source_closure_digest",
            "source_proof_digest",
            "tree_digest",
        }
        and set(receipt["gateway"])
        == {"package_tree_digest", "python_executable_digest"}
        and set(receipt["protected_cas"])
        == {"mode", "owner_uid", "root_device", "root_inode"}
        and quarantine["receipt_digest"]
        == canonical_digest(receipt)
        == result["quarantine_receipt_digest"]
        and receipt["schema"] == "aragorn/github-quarantine-receipt/v1"
        and re.fullmatch(r"[0-9a-f]{64}", receipt["receipt_id"]) is not None
        and quarantine["namespace"]
        == f"/var/lib/aragorn-quarantine/{request_digest[7:]}"
        and receipt["request"] == _SOURCE_REQUEST
        and receipt["request_digest"] == request_digest
        and receipt["source_assurance"]
        == "git_smart_http_v2_commit_tree_proof_and_api_blob_identity_reverified"
        and receipt["containment_profile"] == "linux-systemd-restricted-egress/v1"
        and isinstance(receipt["file_count"], int)
        and not isinstance(receipt["file_count"], bool)
        and receipt["file_count"] == 1
        and receipt["tree_digest"] == state["tree_digest"]
        and receipt["manifest_digest"] == active["recursive"]["root_manifest_digest"]
        and receipt["manifest_digest"] == _ROOT_MANIFEST_DIGEST
        and receipt["handoff_manifest_digest"] == _HANDOFF_MANIFEST_DIGEST
        and receipt["source_proof_digest"] == _SOURCE_PROOF_DIGEST
        and receipt["source_closure_digest"] == _SOURCE_CLOSURE_DIGEST
        and receipt["gateway_profile_digest"] == result["gateway_profile_digest"]
        and receipt["gateway_profile_digest"]
        == "sha256:297201c776e8c510f4ca62a8c5e41d3a9d0b73125d84c963088b5a7836df5686"
        and receipt["gateway"]
        == {
            "package_tree_digest": (
                "sha256:b877b340ed6efc8f1cb61e3404d0afaf86a0e49a5410a2ce4151bc6a57b07fa5"
            ),
            "python_executable_digest": p36b._PYTHON_DIGEST,
        }
        and all(
            isinstance(receipt["protected_cas"][field], int)
            and not isinstance(receipt["protected_cas"][field], bool)
            for field in ("mode", "owner_uid", "root_device", "root_inode")
        )
        and all(
            _DIGEST.fullmatch(receipt[field]) is not None
            for field in (
                "handoff_manifest_digest",
                "source_closure_digest",
                "source_proof_digest",
            )
        )
        and receipt["authority"] == "QUARANTINE_ONLY_NOT_ADMISSION_AUTHORITY",
        "quarantine receipt join changed",
    )
    _verify_cas_snapshot(quarantine["cas_before_runtime"], quarantine["namespace"])
    _verify_cas_snapshot(quarantine["cas_after_runtime"], quarantine["namespace"])
    _expect(
        receipt["protected_cas"]
        == {
            "mode": int(quarantine["cas_before_runtime"]["root"]["mode"], 8),
            "owner_uid": quarantine["cas_before_runtime"]["root"]["uid"],
            "root_device": quarantine["cas_before_runtime"]["root"]["device"],
            "root_inode": quarantine["cas_before_runtime"]["root"]["inode"],
        }
        and quarantine["receipt_digest"] in quarantine["cas_before_runtime"]["closure"]
        and receipt["handoff_manifest_digest"]
        in quarantine["cas_before_runtime"]["closure"]
        and receipt["manifest_digest"] in quarantine["cas_before_runtime"]["closure"]
        and receipt["source_proof_digest"]
        in quarantine["cas_before_runtime"]["closure"]
        and quarantine["cas_before_runtime"] == quarantine["cas_after_runtime"],
        "CAS changed through runtime",
    )
    source_skill = p37c._verify_raw(quarantine["source_skill"])
    _expect(
        quarantine["source_skill"]["digest"]
        == "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
        and all(
            snapshot["closure"][quarantine["source_skill"]["digest"]]
            == quarantine["source_skill"]["bytes"]
            for snapshot in (
                quarantine["cas_before_runtime"],
                quarantine["cas_after_runtime"],
            )
        )
        and b"name: template-skill\n" in source_skill,
        "source skill changed",
    )
    protected = value["protected"]
    _expect(
        set(protected)
        == {
            "active_link",
            "claim",
            "record",
            "service_journal_identity",
            "service_receipt",
            "skill",
            "transaction",
            "tree_entry",
            "version",
        },
        "protected fields changed",
    )
    transaction = protected["transaction"]
    expected_version = (
        f".aragorn-versions/{transaction['destination']['target_name']}/"
        f"{transaction['context_id'][7:]}-{transaction['manifest_digest'][7:]}"
    )
    _expect(
        transaction["schema"] == "aragorn/protected-install-transaction/v1"
        and set(transaction)
        == {
            "authority",
            "context_digest",
            "context_id",
            "destination",
            "expected_active",
            "manifest_digest",
            "operation",
            "schema",
            "tree_digest",
            "version_path",
        }
        and transaction["authority"]
        == "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
        and transaction["operation"] == "install"
        and transaction["expected_active"] is None
        and set(transaction["destination"])
        == {"root_device", "root_inode", "target_name"}
        and transaction["destination"]["target_name"] == "aragorn-admitted"
        and all(
            isinstance(transaction["destination"][field], int)
            and not isinstance(transaction["destination"][field], bool)
            and transaction["destination"][field] > 0
            for field in ("root_device", "root_inode")
        )
        and transaction["context_id"] == result["context_id"]
        and transaction["manifest_digest"] == result["manifest_digest"]
        and transaction["tree_digest"] == state["tree_digest"]
        and transaction["version_path"] == state["version_path"] == expected_version,
        "protected transaction changed",
    )
    record = protected["record"]
    parsed = parse_active_runtime_record(canonical_json(record["document"]))
    _expect(
        set(record) == {"digest", "document", "file", "raw_digest"}
        and parsed == record["document"]
        and parsed["transaction"] == transaction
        and record["digest"]
        == record["raw_digest"]
        == record["file"]["digest"]
        == canonical_digest(record["document"]),
        "active record changed",
    )
    _expect(
        record["file"]["bytes"] == len(canonical_json(record["document"]))
        and record["file"]["path"]
        == "/var/lib/aragorn-protected/skills/.aragorn-active-runtime.json"
        and record["file"]["stat"]["uid"] == record["file"]["stat"]["gid"] == 0
        and record["file"]["stat"]["mode"] == "0444"
        and record["file"]["stat"]["nlink"] == 1,
        "active record custody changed",
    )
    claim = protected["claim"]
    _expect(
        set(claim) == {"digest", "document", "file", "raw_digest"}
        and claim["document"] == transaction
        and claim["digest"]
        == claim["raw_digest"]
        == claim["file"]["digest"]
        == canonical_digest(transaction),
        "install claim changed",
    )
    _expect(
        claim["file"]["bytes"] == len(canonical_json(transaction))
        and claim["file"]["path"]
        == (
            "/var/lib/aragorn-protected/skills/.aragorn-install-claims/"
            f"{transaction['context_id'][7:]}.json"
        )
        and claim["file"]["stat"]["uid"] == claim["file"]["stat"]["gid"] == 0
        and claim["file"]["stat"]["mode"] == "0400"
        and claim["file"]["stat"]["nlink"] == 1,
        "install claim custody changed",
    )
    tree_entry = protected["tree_entry"]
    skill_raw = _verify_bounded_file(protected["skill"])
    _expect(
        canonical_json(tree_entry)
        == canonical_json(
            {
                "digest": quarantine["source_skill"]["digest"],
                "executable": False,
                "path": "SKILL.md",
                "size": len(source_skill),
            }
        )
        and canonical_digest([tree_entry]) == transaction["tree_digest"]
        and skill_raw == source_skill
        and protected["skill"]["path"]
        == f"/var/lib/aragorn-protected/skills/{expected_version}/SKILL.md"
        and protected["skill"]["stat"]["uid"] == protected["skill"]["stat"]["gid"] == 0
        and protected["skill"]["stat"]["mode"] == "0444"
        and protected["skill"]["stat"]["nlink"] == 1,
        "installed skill changed",
    )
    service_receipt = protected["service_receipt"]
    _verify_service_receipt(service_receipt, transaction, result, receipt, state)
    link = protected["active_link"]
    _verify_path_record(link)
    _verify_path_record(protected["version"])
    _expect(
        link["type"] == "symlink"
        and link["path"] == "/var/lib/aragorn-protected/skills/aragorn-admitted"
        and link["target"] == transaction["version_path"]
        and link["uid"] == link["gid"] == 0
        and link["mode"] == "0777"
        and link["nlink"] == 1
        and protected["version"]["type"] == "directory"
        and protected["version"]["path"]
        == f"/var/lib/aragorn-protected/skills/{expected_version}"
        and protected["version"]["uid"] == protected["version"]["gid"] == 0
        and protected["version"]["mode"] == "0555"
        and protected["version"]["nlink"] == 2
        and link["size"] == len(link["target"].encode("utf-8"))
        and all(
            item["device"] == transaction["destination"]["root_device"]
            for item in (link, protected["version"])
        )
        and all(
            item["stat"]["device"] == transaction["destination"]["root_device"]
            for item in (record["file"], claim["file"], protected["skill"])
        ),
        "protected path binding changed",
    )
    identities = [
        (entry["stat"]["device"], entry["stat"]["inode"])
        for entry in (record["file"], claim["file"], protected["skill"])
    ]
    identities.extend(
        (entry["device"], entry["inode"]) for entry in (link, protected["version"])
    )
    cas_identities = {
        (item["file"]["device"], item["file"]["inode"])
        for item in quarantine["cas_before_runtime"]["blobs"]
    } | {
        (
            quarantine["cas_before_runtime"]["root"]["device"],
            quarantine["cas_before_runtime"]["root"]["inode"],
        )
    }
    _expect(
        len(set(identities)) == 5 and set(identities).isdisjoint(cas_identities),
        "protected files share custody identity",
    )
    journals = value["journals"]
    journal_since = f"@{_time(timing['started_at']).timestamp():.6f}"
    journal_until = f"@{_time(timing['completed_at']).timestamp():.6f}"
    _expect(
        set(journals)
        == {
            "aragorn-gateway-*.service",
            "aragorn-protected-install-coordinator.service",
            "aragorn-protected-install.service",
        }
        and all(
            set(item) == {"command", "entry_count", "unit"}
            and item["unit"] == unit
            and isinstance(item["entry_count"], int)
            and not isinstance(item["entry_count"], bool)
            and item["entry_count"] > 0
            and item["command"]["argv"][:7]
            == [
                "journalctl",
                "--all",
                "--no-pager",
                "--output=json",
                "--unit",
                unit,
                "--since",
            ]
            and item["command"]["argv"][7] == journal_since
            and item["command"]["argv"][8] == "--until"
            and item["command"]["argv"][9] == journal_until
            and len(item["command"]["argv"]) == 10
            and item["command"]["exit_code"] == 0
            and len(
                [
                    json.loads(line)
                    for line in p37c._verify_raw(item["command"]["stdout"]).splitlines()
                ]
            )
            == item["entry_count"]
            for unit, item in journals.items()
        ),
        "acquisition journal inventory changed",
    )
    _verify_service_journal(
        protected["service_journal_identity"],
        journals["aragorn-protected-install.service"],
        service_receipt,
        timing,
    )
    cas_root = quarantine["cas_before_runtime"]["root"]
    credential = service_receipt["request_authority"]["credential"]
    skill_stat = protected["skill"]["stat"]
    version = protected["version"]
    journal_ns = (
        int(protected["service_journal_identity"]["realtime_timestamp"]) * 1_000
    )
    state_stat = coordinator["state"]["file"]["stat"]
    _expect(
        all(
            acquisition_started_ns
            <= item["file"]["mtime_ns"]
            <= item["file"]["ctime_ns"]
            <= cas_root["ctime_ns"]
            for item in quarantine["cas_before_runtime"]["blobs"]
        )
        and acquisition_started_ns
        <= cas_root["mtime_ns"]
        <= cas_root["ctime_ns"]
        <= credential["mtime_ns"]
        == credential["ctime_ns"]
        <= version["mtime_ns"]
        <= skill_stat["mtime_ns"]
        <= skill_stat["ctime_ns"]
        <= version["ctime_ns"]
        <= link["mtime_ns"]
        == link["ctime_ns"]
        <= journal_ns
        <= state_stat["mtime_ns"]
        <= state_stat["ctime_ns"]
        <= acquisition_completed_ns,
        "acquisition custody timing changed",
    )
    return {
        "source_skill": source_skill,
        "transaction": transaction,
        "record": record,
        "skill": protected["skill"],
        "timing": timing,
        "network": value["network"],
        "quarantine": quarantine,
        "service_journal_boot_id": protected["service_journal_identity"]["boot_id"],
    }


def _verify_service_receipt(
    value: Mapping[str, Any],
    transaction: Mapping[str, Any],
    result: Mapping[str, Any],
    quarantine_receipt: Mapping[str, Any],
    coordinator_state: Mapping[str, Any],
) -> None:
    _expect(
        set(value)
        == {
            "active",
            "analyzer",
            "assurance",
            "claim",
            "context",
            "decision",
            "limitations",
            "mode",
            "producer_implementation_digest",
            "request_authority",
            "schema",
            "slice_status",
            "source",
            "transaction",
            "transition",
            "verified_sequence",
        }
        and value["schema"]
        == "aragorn/openclaw-github-protected-install-broker-evidence/v1"
        and value["assurance"]
        == "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
        and value["mode"] == "github-live"
        and value["slice_status"] == "PASS"
        and value["producer_implementation_digest"] == p36b._BROKER_DIGEST
        and value["limitations"] == p36b._RECEIPT_LIMITATIONS
        and canonical_json(value["transition"])
        == canonical_json(
            {"expected_active": None, "manifest_diff": None, "operation": "install"}
        )
        and value["transaction"] == transaction
        and canonical_json(value["active"])
        == canonical_json(
            {
                "link_target": transaction["version_path"],
                "tree_digest": transaction["tree_digest"],
            }
        )
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
        "service receipt authority changed",
    )
    source = value["source"]
    _expect(
        set(source)
        == {
            "artifact_count",
            "artifact_graph_digest",
            "artifact_graph_profile",
            "artifact_graph_verifier_implementation_digest",
            "closure",
            "containment_profile",
            "gateway",
            "gateway_profile_digest",
            "manifest_digest",
            "quarantine_protected_cas",
            "quarantine_receipt_digest",
            "recursive",
            "request",
            "source_closure_digest",
            "source_proof_digest",
            "tree_digest",
        }
        and source["request"] == _SOURCE_REQUEST
        and source["manifest_digest"] == result["manifest_digest"]
        and source["tree_digest"] == transaction["tree_digest"]
        and source["source_proof_digest"] == quarantine_receipt["source_proof_digest"]
        and source["source_closure_digest"]
        == quarantine_receipt["source_closure_digest"]
        and source["quarantine_receipt_digest"] == result["quarantine_receipt_digest"]
        and source["gateway_profile_digest"] == result["gateway_profile_digest"]
        and source["containment_profile"] == "linux-systemd-restricted-egress/v1"
        and source["gateway"] == quarantine_receipt["gateway"]
        and source["quarantine_protected_cas"] == quarantine_receipt["protected_cas"]
        and set(source["quarantine_protected_cas"])
        == {"mode", "owner_uid", "root_device", "root_inode"}
        and all(
            isinstance(source["quarantine_protected_cas"][field], int)
            and not isinstance(source["quarantine_protected_cas"][field], bool)
            for field in ("mode", "owner_uid", "root_device", "root_inode")
        )
        and source["quarantine_protected_cas"]["mode"] == 0o700
        and source["quarantine_protected_cas"]["owner_uid"] == 0
        and source["quarantine_protected_cas"]["root_device"] > 0
        and source["quarantine_protected_cas"]["root_inode"] > 0
        and isinstance(source["artifact_count"], int)
        and not isinstance(source["artifact_count"], bool)
        and source["artifact_count"] == quarantine_receipt["file_count"] == 1
        and source["artifact_graph_profile"] == "recursive-github-markdown/v1"
        and source["artifact_graph_verifier_implementation_digest"]
        == _ANALYZER_IMPLEMENTATION
        and source["artifact_graph_digest"] == _ARTIFACT_GRAPH_DIGEST
        and canonical_json(source["closure"])
        == canonical_json(
            {
                "profile": "recursive-github-markdown/v1",
                "scope": "artifact_graph",
                "status": "complete",
                "unresolved": [],
            }
        )
        and source["recursive"] == coordinator_state["expected_active"]["recursive"],
        "service receipt source changed",
    )
    _expect(
        canonical_json(value["analyzer"])
        == canonical_json(
            {
                "configuration_digest": _ANALYZER_CONFIGURATION,
                "executable_digest": p36b._PYTHON_DIGEST,
                "execution_identity": {
                    "gid": 993,
                    "group": "aragorn-analyze",
                    "supplementary_groups": [],
                    "uid": 993,
                    "user": "aragorn-analyze",
                },
                "implementation_digest": _ANALYZER_IMPLEMENTATION,
                "name": "aragorn-agent-skill-threats",
                "run_receipt_digest": _ANALYZER_RUN_DIGEST,
                "verifier_implementation_digest": p36b._ANALYZER_VERIFIER,
                "version": "0.1.0-phase0-v7",
            }
        )
        and canonical_json(value["decision"])
        == canonical_json(
            {
                "digest": _INSTALL_DECISION_DIGEST,
                "installer_work_eligible": False,
                "policy_digest": p36b._POLICY_DIGEST,
                "verdict": "ALLOW",
            }
        ),
        "service receipt analyzer or decision changed",
    )
    context = value["context"]
    _expect(
        set(context)
        == {
            "context_id",
            "destination",
            "digest",
            "expected_active",
            "operation",
            "runtime_conformance_digest",
            "target_runtime_digest",
        }
        and context["context_id"] == transaction["context_id"]
        and context["destination"] == transaction["destination"]
        and context["digest"] == transaction["context_digest"]
        and context["expected_active"] is None
        and context["operation"] == "install"
        and context["runtime_conformance_digest"] == _RUNTIME_CONFORMANCE_DIGEST
        and context["target_runtime_digest"] == p36b._RUNTIME_DIGEST,
        "service receipt context changed",
    )
    authority = value["request_authority"]
    credential = authority["credential"]
    _expect(
        set(authority)
        == {"authority", "credential", "request_digest", "request_schema"}
        and authority["authority"] == "PROTECTED_CANONICAL_REQUEST_CREDENTIAL"
        and authority["request_digest"] == result["service_request_digest"]
        and authority["request_schema"] == "aragorn/protected-install-broker-request/v4"
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
        and all(
            isinstance(credential[field], int)
            and not isinstance(credential[field], bool)
            for field in (
                "ctime_ns",
                "device",
                "gid",
                "inode",
                "links",
                "mode",
                "mtime_ns",
                "size",
                "uid",
            )
        )
        and credential["uid"] == credential["gid"] == 0
        and credential["links"] == 1
        and credential["mode"] == 0o400
        and credential["size"] == 2_151
        and all(
            isinstance(credential[field], int)
            and not isinstance(credential[field], bool)
            and credential[field] > 0
            for field in ("ctime_ns", "device", "inode", "mtime_ns")
        )
        and credential["mtime_ns"] == credential["ctime_ns"],
        "service request authority changed",
    )
    claim = value["claim"]
    snapshot = claim["initial_revocation_snapshot"]
    claim_now = claim["fresh"]["claim_now_unix"]
    _expect(
        set(claim) == {"fresh", "initial_revocation_snapshot"}
        and set(claim["fresh"]) == {"claim_now_unix", "revocation_snapshot"}
        and canonical_json(claim["fresh"]["revocation_snapshot"])
        == canonical_json(snapshot)
        and set(snapshot)
        == {
            "context_ids",
            "device",
            "digest",
            "inode",
            "mode",
            "owner_uid",
            "path",
            "schema",
        }
        and snapshot["schema"] == "aragorn/protected-install-revocations/v1"
        and snapshot["context_ids"] == []
        and snapshot["path"] == "/etc/aragorn/protected-install-revocations.json"
        and all(
            isinstance(snapshot[field], int) and not isinstance(snapshot[field], bool)
            for field in ("device", "inode", "mode", "owner_uid")
        )
        and snapshot["owner_uid"] == 0
        and snapshot["mode"] == 0o400
        and snapshot["digest"] == _REVOCATION_DIGEST
        and all(
            isinstance(snapshot[field], int)
            and not isinstance(snapshot[field], bool)
            and snapshot[field] > 0
            for field in ("device", "inode")
        )
        and isinstance(claim_now, int)
        and not isinstance(claim_now, bool)
        and credential["ctime_ns"] // 1_000_000_000
        <= claim_now
        <= credential["ctime_ns"] // 1_000_000_000 + 5,
        "service receipt claim changed",
    )


def _verify_service_journal(
    identity: Mapping[str, Any],
    journal: Mapping[str, Any],
    receipt: Mapping[str, Any],
    timing: Mapping[str, Any],
) -> None:
    _expect(
        set(identity)
        == {
            "boot_id",
            "command_line",
            "executable",
            "gid",
            "invocation_id",
            "message_bytes",
            "message_digest",
            "pid",
            "procfs_boot_id",
            "realtime_timestamp",
            "syslog_identifier",
            "systemd_unit",
            "uid",
        }
        and identity["message_digest"] == canonical_digest(receipt)
        and identity["message_bytes"] == len(canonical_json(receipt))
        and re.fullmatch(r"[0-9a-f]{32}", identity["invocation_id"]) is not None
        and re.fullmatch(r"[0-9a-f]{32}", identity["boot_id"]) is not None
        and identity["procfs_boot_id"] == identity["boot_id"]
        and isinstance(identity["realtime_timestamp"], str)
        and identity["realtime_timestamp"].isdigit()
        and identity["systemd_unit"] == "aragorn-protected-install.service"
        and identity["syslog_identifier"] == "aragorn-protected-install"
        and identity["executable"] == "/usr/local/bin/python3.12"
        and all(
            isinstance(identity[field], int) and not isinstance(identity[field], bool)
            for field in ("gid", "message_bytes", "pid", "uid")
        )
        and identity["uid"] == identity["gid"] == 0
        and isinstance(identity["pid"], int)
        and not isinstance(identity["pid"], bool)
        and identity["pid"] > 0
        and identity["command_line"]
        == (
            "/usr/local/bin/python3.12 -I -S -B /opt/aragorn-broker-p36b/"
            "benchmark/admission/openclaw-v2026.7.1/"
            "protected-install-broker-recursive-v3.py --github-live "
            "--service-request /run/credentials/aragorn-protected-install.service/"
            "install-request --analyzer-user aragorn-analyze --analyzer-group "
            "aragorn-analyze --cas-root /var/lib/aragorn-quarantine --protected-root "
            "/var/lib/aragorn-protected/skills --expected-broker-uid 0 "
            "--revocation-file /etc/aragorn/protected-install-revocations.json"
        ),
        "service journal identity changed",
    )
    entries = [
        json.loads(line)
        for line in p37c._verify_raw(journal["command"]["stdout"]).splitlines()
    ]
    matching = [
        entry
        for entry in entries
        if entry.get("_SYSTEMD_INVOCATION_ID") == identity["invocation_id"]
    ]
    expected_entry = {
        "MESSAGE": canonical_json(receipt).decode("utf-8"),
        "SYSLOG_IDENTIFIER": identity["syslog_identifier"],
        "_BOOT_ID": identity["boot_id"],
        "_CMDLINE": identity["command_line"],
        "_EXE": identity["executable"],
        "_GID": str(identity["gid"]),
        "_PID": str(identity["pid"]),
        "_SYSTEMD_INVOCATION_ID": identity["invocation_id"],
        "_SYSTEMD_UNIT": identity["systemd_unit"],
        "_UID": str(identity["uid"]),
        "__REALTIME_TIMESTAMP": identity["realtime_timestamp"],
    }
    timestamp = int(identity["realtime_timestamp"]) / 1_000_000
    credential_second = (
        receipt["request_authority"]["credential"]["ctime_ns"] // 1_000_000_000
    )
    _expect(
        len(matching) == 1
        and all(
            matching[0].get(key) == expected for key, expected in expected_entry.items()
        )
        and credential_second <= timestamp <= credential_second + 5
        and _time(timing["started_at"]).timestamp()
        <= timestamp
        <= _time(timing["completed_at"]).timestamp(),
        "service journal receipt binding changed",
    )


def _verify_cas_snapshot(value: Mapping[str, Any], namespace: str) -> None:
    _expect(
        set(value) == {"blobs", "closure", "closure_digest", "root"}
        and value["root"]["path"] == namespace,
        "CAS snapshot fields changed",
    )
    _verify_path_record(value["root"])
    _expect(
        value["root"]["type"] == "directory"
        and value["root"]["uid"] == value["root"]["gid"] == 0
        and value["root"]["mode"] == "0700"
        and value["root"]["nlink"] == 3,
        "CAS root custody changed",
    )
    closure = value["closure"]
    _expect(
        isinstance(closure, Mapping)
        and canonical_json(closure) == canonical_json(_CAS_CLOSURE)
        and all(
            _DIGEST.fullmatch(digest) is not None
            and isinstance(size, int)
            and not isinstance(size, bool)
            and size > 0
            for digest, size in closure.items()
        )
        and value["closure_digest"]
        == canonical_digest(
            [
                {"bytes": size, "digest": digest}
                for digest, size in sorted(closure.items())
            ]
        ),
        "CAS closure digest changed",
    )
    observed = {}
    paths = set()
    inodes = set()
    for item in value["blobs"]:
        _expect(set(item) == {"bytes", "digest", "file"}, "CAS blob fields changed")
        digest = item["digest"]
        file = item["file"]
        _verify_path_record(file)
        _expect(
            _DIGEST.fullmatch(digest) is not None
            and isinstance(item["bytes"], int)
            and not isinstance(item["bytes"], bool)
            and item["bytes"] > 0
            and item["bytes"] == closure[digest] == file["size"]
            and file["path"] == f"{namespace}/blobs/sha256/{digest[7:9]}/{digest[9:]}"
            and file["type"] == "file"
            and file["device"] == value["root"]["device"]
            and file["uid"] == file["gid"] == 0
            and file["mode"] == "0444"
            and file["nlink"] == 1,
            "CAS blob custody changed",
        )
        observed[digest] = item["bytes"]
        paths.add(file["path"])
        inodes.add((file["device"], file["inode"]))
    _expect(
        observed == closure
        and len(value["blobs"]) == len(closure) == len(paths) == len(inodes)
        and (value["root"]["device"], value["root"]["inode"]) not in inodes,
        "CAS blob closure changed",
    )


def _verify_action(
    value: Mapping[str, Any],
    harness: Mapping[str, Any],
    p37c_observation: Mapping[str, Any],
    acquisition: Mapping[str, Any],
) -> dict[str, Any]:
    _expect(
        set(value) == p37c._TOP_LEVEL
        and value["authority"] == p37c._AUTHORITY
        and canonical_json(value["decision"]) == canonical_json(p37c._DECISION)
        and value["limitations"] == p37c._LIMITATIONS
        and value["identities"] == p37c_observation["identities"]
        and value["runtime"] == p37c_observation["runtime"]
        and value["parent"] == p37c_observation["parent"]
        and value["harness"] == harness
        and canonical_digest(value) == _ACTION_DIGEST,
        "nested action identity changed",
    )
    _expect(
        set(value["cases"]) == set(p37c_observation["cases"])
        and all(
            set(case) == set(p37c_observation["cases"][name])
            and case["status"] == "OBSERVED"
            and set(case["checks"]) == set(p37c_observation["cases"][name]["checks"])
            and all(result is True for result in case["checks"].values())
            and canonical_digest(case) == _ACTION_CASE_DIGESTS[name]
            for name, case in value["cases"].items()
        ),
        "nested action case closure changed",
    )
    _expect(
        _artifact_projection(value["artifacts"])
        == _artifact_projection(p37c_observation["artifacts"]),
        "nested runtime implementation changed",
    )
    inputs = value["inputs"]
    _expect(
        set(inputs)
        == {
            "action",
            "control_sets",
            "fresh_grant",
            "gateway_config",
            "gateway_environment_bytes_retained",
            "gateway_environment_digest_retained",
            "grant_source",
            "policy",
            "policy_digest",
            "producer",
            "short_grant",
            "worker_binding",
            "worker_binding_file",
        }
        and inputs["gateway_environment_bytes_retained"] is False
        and inputs["gateway_environment_digest_retained"] is False,
        "action input fields changed",
    )
    producer = inputs["producer"]
    _expect(
        set(producer) == {"projected_skill", "record", "skill", "transaction"}
        and producer["transaction"] == acquisition["transaction"]
        and producer["record"] == acquisition["record"]
        and producer["skill"]["path"] == acquisition["skill"]["path"]
        and producer["skill"]["digest"] == acquisition["skill"]["digest"]
        and producer["skill"]["bytes"] == acquisition["skill"]["bytes"]
        and producer["skill"]["stat"]
        == {key: acquisition["skill"]["stat"][key] for key in producer["skill"]["stat"]}
        and producer["projected_skill"]["path"]
        == "/var/lib/aragorn-agent-gateway/state/skills/template-skill/SKILL.md"
        and producer["projected_skill"]["digest"] == producer["skill"]["digest"]
        and all(
            item["stat"]["type"] == "file"
            and item["stat"]["uid"] == item["stat"]["gid"] == 0
            and item["stat"]["mode"] == "0444"
            and item["stat"]["nlink"] == 1
            for item in (producer["skill"], producer["projected_skill"])
        ),
        "action producer custody changed",
    )
    action = inputs["action"]
    _expect(
        action
        == {
            "operation_digest": canonical_digest(
                {"operation": "create", "schema": "aragorn/runtime-file-operation/v1"}
            ),
            "path_digest": "sha256:5eee84fa8bfc717be58d113c27eec3bb2b6e9b4d6846ffc8837a50a36ccff061",
            "payload_digest": _raw_digest(b"Aragorn P3.7b distinct worker create\n"),
        },
        "action digest binding changed",
    )
    policy = inputs["policy"]
    _expect(
        inputs["policy_digest"] == canonical_digest(policy)
        and policy["schema"] == "aragorn/runtime-action-policy/v1"
        and policy["id"] == "p3-7c-worker-activation-expiry"
        and policy["default"] == "BLOCK"
        and policy["version"] == 1
        and policy["sensor_digest"] == "sha256:" + "3" * 64
        and policy["revocation_source_digest"] == "sha256:" + "4" * 64
        and policy["allow"]
        == [
            {
                **action,
                "active_skill_digest": producer["skill"]["digest"],
                "runtime_digest": value["runtime"]["tree"]["tree_digest"],
            }
        ],
        "action policy changed",
    )
    action_decision._policy(policy)
    _expect(
        canonical_digest(inputs["gateway_config"])
        == "sha256:65e0fe737f7d094bf89d10ae5854e934ca734c8a4ea0479a6eb3b96335a8a006",
        "gateway configuration changed",
    )
    container_id = harness["document"]["container_id"]
    p37c._verify_profiles(value["profiles"], producer, container_id)
    grants = {}
    for name in ("short_grant", "fresh_grant"):
        wrapper = inputs[name]
        _expect(
            set(wrapper)
            == (
                {"digest", "document", "source"}
                if name == "short_grant"
                else {"digest", "document"}
            ),
            f"{name} wrapper changed",
        )
        grant = parse_runtime_capability_grant(canonical_json(wrapper["document"]))
        _expect(
            wrapper["digest"] == canonical_digest(grant)
            and grant["runtime_profile_digest"] == value["profiles"]["worker"]["digest"]
            and grant["runtime_digest"] == value["runtime"]["tree"]["tree_digest"]
            and grant["active_skill_digest"] == producer["skill"]["digest"]
            and grant["policy_digest"] == inputs["policy_digest"]
            and grant["operation_digest"] == action["operation_digest"]
            and grant["source_manifest_digest"]
            == producer["transaction"]["manifest_digest"]
            and grant["install_context_digest"]
            == producer["transaction"]["context_digest"],
            f"{name} binding changed",
        )
        grants[name] = {"digest": wrapper["digest"], "document": grant}
    _expect(
        p37c._verify_document_snapshot(inputs["short_grant"]["source"])
        == grants["short_grant"]["document"]
        and p37c._verify_document_snapshot(inputs["grant_source"])
        == grants["fresh_grant"]["document"],
        "grant source binding changed",
    )
    short_source = inputs["short_grant"]["source"]
    fresh_source = inputs["grant_source"]
    _expect(
        short_source["file"]["path"]
        == fresh_source["file"]["path"]
        == "/etc/aragorn/runtime-capability-grant.json"
        and all(
            source["file"]["stat"]["uid"] == source["file"]["stat"]["gid"] == 0
            and source["file"]["stat"]["mode"] == "0400"
            and source["file"]["stat"]["nlink"] == 1
            for source in (short_source, fresh_source)
        )
        and grants["short_grant"]["digest"] != grants["fresh_grant"]["digest"]
        and grants["short_grant"]["document"]["grant_id"]
        != grants["fresh_grant"]["document"]["grant_id"],
        "grant rotation changed",
    )
    p37c._verify_control_sets(
        inputs["control_sets"], policy, action, producer["skill"]["digest"], grants
    )
    binding = inputs["worker_binding"]
    _expect(
        binding
        == {
            "active_skill_digest": producer["skill"]["digest"],
            "policy_digest": inputs["policy_digest"],
            "policy_version": policy["version"],
            "runtime_digest": value["runtime"]["tree"]["tree_digest"],
            "schema": "aragorn/runtime-action-worker-binding/v1",
        }
        and inputs["worker_binding_file"]["digest"] == canonical_digest(binding)
        and inputs["worker_binding_file"]["bytes"] == len(canonical_json(binding))
        and inputs["worker_binding_file"]["path"]
        == "/etc/aragorn/runtime-action-worker.json"
        and inputs["worker_binding_file"]["stat"]["uid"]
        == inputs["worker_binding_file"]["stat"]["gid"]
        == 0
        and inputs["worker_binding_file"]["stat"]["mode"] == "0400"
        and inputs["worker_binding_file"]["stat"]["nlink"] == 1,
        "worker binding changed",
    )
    context = {
        "action": action,
        "container_id": container_id,
        "control_sets": inputs["control_sets"],
        "fresh_grant": grants["fresh_grant"],
        "identities": value["identities"],
        "policy": policy,
        "producer": producer,
        "profiles": value["profiles"],
    }
    _verify_coherent_action(value["cases"]["coherent_consumed"], context)
    p37c._verify_secrets(value["secret_checks"], value["cases"])
    return context


def _verify_coherent_action(
    case: Mapping[str, Any], context: Mapping[str, Any]
) -> None:
    _expect(
        case["status"] == "OBSERVED"
        and all(value is True for value in case["checks"].values())
        and p37c.parent_verifier._verify_driver("coherent", case["driver"]) == 14,
        "coherent action shape changed",
    )
    receipt_document = p37c._verify_document_snapshot(case["receipt"])
    broker_state_document = p37c._verify_document_snapshot(case["broker_state"])
    grant_state_document = p37c._verify_grant_state_snapshot(
        case["grant_state"], context["fresh_grant"]["digest"]
    )
    projected = {
        **case,
        "receipt": {"digest": case["receipt"]["digest"], "document": receipt_document},
        "broker_state": {
            "digest": case["broker_state"]["digest"],
            "document": broker_state_document,
        },
    }
    legacy_context = {
        "action": context["action"],
        "control_sets": context["control_sets"],
        "grant": context["fresh_grant"],
        "policy": context["policy"],
        "producer": context["producer"],
        "profiles": context["profiles"],
    }
    p37c.parent_verifier._verify_snapshot_binding("coherent", projected, legacy_context)
    p37c.parent_verifier._verify_coherent(projected, legacy_context)
    _expect(
        broker._state(broker_state_document) == broker_state_document
        and broker_v4._state(grant_state_document, context["fresh_grant"]["digest"])[
            "status"
        ]
        == "CONSUMED"
        and case["effects"]["after"]["grant_state"]
        == {"digest": case["grant_state"]["digest"], "document": grant_state_document},
        "coherent durable state changed",
    )
    traces = case["traces"]
    _expect(
        set(traces) == {"broker", "gateway", "sensor", "worker"},
        "trace inventory changed",
    )
    p37c._verify_gateway_trace(traces["gateway"])
    for name in ("worker", "sensor", "broker"):
        p37c.parent_verifier._verify_trace(traces[name], unix_only_service=True)
    p37c._verify_service_snapshot(case["service_state_after"])
    target_raw = p37c._verify_raw(
        {field: case["target"][field] for field in ("base64", "bytes", "digest")}
    )
    attribution = receipt_document["runtime_attribution"]
    result = receipt_document["broker_result"]
    _expect(
        target_raw == b"Aragorn P3.7b distinct worker create\n"
        and case["target"]["digest"] == context["action"]["payload_digest"]
        and result["verdict"] == "ALLOW"
        and result["effect_status"] == "CREATED"
        and attribution["active_skill_digest"] == context["producer"]["skill"]["digest"]
        and attribution["skill_path"] == context["producer"]["skill"]["path"]
        and attribution["profile_digest"] == context["profiles"]["worker"]["digest"]
        and attribution["cgroup"]
        == f"/docker/{context['container_id']}/system.slice/aragorn-runtime-action-worker.service",
        "coherent action result or attribution changed",
    )


def _verify_bindings(
    value: Mapping[str, Any],
    acquisition: Mapping[str, Any],
    action: Mapping[str, Any],
) -> None:
    transaction = acquisition["transaction"]
    expected = {
        "checks": {name: True for name in value["checks"]},
        "context_id": transaction["context_id"],
        "manifest_digest": transaction["manifest_digest"],
        "skill_digest": acquisition["skill"]["digest"],
        "source_request": _SOURCE_REQUEST,
        "transaction_digest": canonical_digest(transaction),
        "tree_digest": transaction["tree_digest"],
        "tree_entry": {
            "digest": acquisition["skill"]["digest"],
            "executable": False,
            "path": "SKILL.md",
            "size": acquisition["skill"]["bytes"],
        },
    }
    _expect(
        set(value)
        == {
            "checks",
            "context_id",
            "manifest_digest",
            "skill_digest",
            "source_request",
            "transaction_digest",
            "tree_digest",
            "tree_entry",
        }
        and set(value["checks"])
        == {
            "active_record_reused_by_runtime",
            "cas_unchanged_through_runtime",
            "coordinator_state_result_exact",
            "fresh_source_request_exact",
            "live_quarantine_source_exact",
            "network_disconnected_before_runtime",
            "network_remained_disconnected",
            "one_coherent_action_completed",
            "skill_reused_by_runtime",
            "source_blob_installed_exact",
            "transaction_reused_by_runtime",
        }
        and canonical_json(value) == canonical_json(expected)
        and action["producer"]["transaction"] == transaction,
        "outer acquisition/action bindings changed",
    )


def _verify_network_order(
    document: Mapping[str, Any],
    acquisition: Mapping[str, Any],
    action: Mapping[str, Any],
) -> None:
    network = acquisition["network"]
    _expect(
        set(network)
        == {
            "acquisition_complete_marker",
            "after_disconnect",
            "after_runtime",
            "before_acquisition",
            "disconnected_before_runtime",
            "disconnected_marker",
            "public_connect",
        }
        and network["disconnected_before_runtime"] is True,
        "network transition fields changed",
    )
    _verify_marker(
        network["acquisition_complete_marker"],
        {
            "schema": "aragorn/p38b-acquisition-complete-marker/v1",
            "status": "ACQUISITION_COMPLETE",
        },
    )
    _verify_marker(
        network["disconnected_marker"],
        {"disconnected": True, "schema": "aragorn/p38b-network-disconnected-marker/v1"},
    )
    before = network["before_acquisition"]
    after_disconnect = network["after_disconnect"]
    after_runtime = network["after_runtime"]
    loopback = {
        "address": "00:00:00:00:00:00",
        "ifindex": 1,
        "name": "lo",
        "operstate": "unknown",
    }
    eth0 = before["interfaces"][0]
    attachment = document["harness"]["document"]["capture_network_attachment"]
    _expect(
        all(
            set(snapshot) == {"interfaces", "ipv4_routes", "ipv6_routes", "resolv_conf"}
            and isinstance(snapshot["interfaces"], list)
            and all(
                set(interface) == {"address", "ifindex", "name", "operstate"}
                for interface in snapshot["interfaces"]
            )
            for snapshot in (before, after_disconnect, after_runtime)
        )
        and len(before["interfaces"]) == 2
        and set(eth0) == {"address", "ifindex", "name", "operstate"}
        and eth0["name"] == "eth0"
        and eth0["operstate"] == "up"
        and eth0["address"] == attachment["mac_address"]
        and re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", eth0["address"]) is not None
        and isinstance(eth0["ifindex"], int)
        and not isinstance(eth0["ifindex"], bool)
        and eth0["ifindex"] > 1
        and canonical_json(before["interfaces"][1]) == canonical_json(loopback)
        and canonical_json(after_disconnect["interfaces"]) == canonical_json([loopback])
        and canonical_json(after_runtime["interfaces"]) == canonical_json([loopback])
        and all(
            _resolver(snapshot) == [["nameserver", "127.0.0.11"]]
            for snapshot in (before, after_disconnect, after_runtime)
        )
        and all(
            snapshot["ipv4_routes"]["stat"]["ctime_ns"]
            == snapshot["ipv6_routes"]["stat"]["ctime_ns"]
            and snapshot["ipv4_routes"]["stat"]["mtime_ns"]
            == snapshot["ipv6_routes"]["stat"]["mtime_ns"]
            and snapshot["ipv4_routes"]["stat"]["mtime_ns"]
            == snapshot["ipv4_routes"]["stat"]["ctime_ns"]
            for snapshot in (before, after_disconnect, after_runtime)
        )
        and all(
            _route_records_have_exact_custody(snapshot)
            for snapshot in (before, after_disconnect, after_runtime)
        )
        and _loopback_routes(after_disconnect)
        and _loopback_routes(after_runtime),
        "network isolation changed",
    )
    public = network["public_connect"]
    _expect(
        set(public)
        == {
            "completed_at",
            "completed_monotonic_ns",
            "connected",
            "elapsed_ns",
            "error",
            "host",
            "port",
            "started_at",
            "started_monotonic_ns",
        }
        and canonical_json(public["error"])
        == canonical_json(
            {
                "message": "[Errno -3] Temporary failure in name resolution",
                "type": "gaierror",
            }
        )
        and public["host"] == "github.com"
        and public["port"] == 443
        and public["connected"] is False
        and all(
            isinstance(public[field], int) and not isinstance(public[field], bool)
            for field in (
                "completed_monotonic_ns",
                "elapsed_ns",
                "port",
                "started_monotonic_ns",
            )
        )
        and public["elapsed_ns"] > 0
        and 0 <= public["started_monotonic_ns"] < public["completed_monotonic_ns"]
        and public["elapsed_ns"]
        == public["completed_monotonic_ns"] - public["started_monotonic_ns"]
        and _time(public["started_at"]) < _time(public["completed_at"]),
        "post-disconnect public connection changed",
    )
    complete_ns = network["acquisition_complete_marker"]["file"]["stat"]["ctime_ns"]
    disconnected_ns = network["disconnected_marker"]["file"]["stat"]["ctime_ns"]
    clocks: list[Mapping[str, Any]] = []

    def collect(value: Any) -> None:
        if isinstance(value, Mapping):
            if set(value) == {
                "boot_id",
                "boottime_ns",
                "clocksource",
                "monotonic_ns",
                "proc_uptime",
                "realtime_ns",
                "recorded_at",
                "timedatectl",
            }:
                clocks.append(value)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(document["action"])
    acquisition_completed_ns = int(
        _time(acquisition["timing"]["completed_at"]).timestamp() * 1_000_000_000
    )
    public_started_ns = int(_time(public["started_at"]).timestamp() * 1_000_000_000)
    public_completed_ns = int(_time(public["completed_at"]).timestamp() * 1_000_000_000)
    outer_recorded_ns = int(_time(document["recorded_at"]).timestamp() * 1_000_000_000)
    capture_created_ns = int(
        _time(
            json.loads(
                p37c._verify_raw(
                    document["harness"]["document"]["capture_network_inspect"]
                )
            )[0]["Created"]
        ).timestamp()
        * 1_000_000_000
    )
    path_started_ns = int(
        _time(
            document["acquisition"]["coordinator"]["path_unit_start"]["started_at"]
        ).timestamp()
        * 1_000_000_000
    )
    command = document["acquisition"]["coordinator"]["command"]
    path_start = document["acquisition"]["coordinator"]["path_unit_start"]
    _expect(
        capture_created_ns <= path_started_ns <= capture_created_ns + 60_000_000_000
        and path_started_ns
        <= before["ipv4_routes"]["stat"]["ctime_ns"]
        <= int(_time(acquisition["timing"]["started_at"]).timestamp() * 1_000_000_000)
        and acquisition_completed_ns
        <= complete_ns
        <= disconnected_ns
        <= after_disconnect["ipv4_routes"]["stat"]["ctime_ns"]
        <= public_started_ns
        <= public_completed_ns
        < min(clock["realtime_ns"] for clock in clocks)
        and command["completed_monotonic_ns"] <= public["started_monotonic_ns"]
        and public["completed_monotonic_ns"]
        < min(clock["monotonic_ns"] for clock in clocks)
        and all(
            abs(
                int(_time(record[f"{edge}_at"]).timestamp() * 1_000_000_000)
                - record[f"{edge}_monotonic_ns"]
                - (clock["realtime_ns"] - clock["monotonic_ns"])
            )
            <= 1_000_000
            for record in (path_start, command, public)
            for edge in ("started", "completed")
            for clock in clocks
        )
        and max(clock["realtime_ns"] for clock in clocks)
        <= after_runtime["ipv4_routes"]["stat"]["ctime_ns"]
        <= outer_recorded_ns
        and {clock["boot_id"].replace("-", "") for clock in clocks}
        == {acquisition["service_journal_boot_id"]}
        and _time(document["action"]["recorded_at"]) <= _time(document["recorded_at"]),
        "acquisition/disconnect/action ordering changed",
    )


def _verify_marker(value: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    expected_path = {
        "aragorn/p38b-acquisition-complete-marker/v1": (
            "/run/aragorn-p38b-acquisition-complete"
        ),
        "aragorn/p38b-network-disconnected-marker/v1": (
            "/run/aragorn-p38b-network-disconnected"
        ),
    }[expected["schema"]]
    _expect(
        set(value) == {"document", "file"}
        and canonical_json(value["document"]) == canonical_json(expected)
        and value["file"]["path"] == expected_path
        and value["file"]["stat"]["uid"] == value["file"]["stat"]["gid"] == 0
        and value["file"]["stat"]["mode"] == "0600"
        and value["file"]["stat"]["nlink"] == 1,
        "marker changed",
    )
    raw = _verify_bounded_file(value["file"])
    _expect(raw == canonical_json(expected) + b"\n", "marker bytes changed")


def _resolver(value: Mapping[str, Any]) -> list[list[str]]:
    record = value["resolv_conf"]
    raw = _verify_bounded_file(record)
    _expect(
        record["path"] == "/etc/resolv.conf"
        and record["stat"]["uid"] == record["stat"]["gid"] == 0
        and record["stat"]["mode"] == "0644"
        and record["stat"]["nlink"] == 1,
        "resolver custody changed",
    )
    return [
        fields
        for line in raw.decode("ascii").splitlines()
        if (fields := line.split()) and fields[0] == "nameserver"
    ]


def _loopback_routes(value: Mapping[str, Any]) -> bool:
    ipv4 = _verify_bounded_file(value["ipv4_routes"]).decode("ascii").splitlines()
    ipv6 = _verify_bounded_file(value["ipv6_routes"]).decode("ascii").splitlines()
    return (
        bool(ipv4)
        and ipv4[0].split()[:2] == ["Iface", "Destination"]
        and all(line.split()[0] == "lo" for line in ipv4[1:] if line.split())
        and all(line.split()[-1] == "lo" for line in ipv6 if line.split())
    )


def _route_records_have_exact_custody(value: Mapping[str, Any]) -> bool:
    records = (
        (value["ipv4_routes"], "/proc/net/route"),
        (value["ipv6_routes"], "/proc/net/ipv6_route"),
    )
    return all(
        record["path"] == path
        and record["stat"]["uid"] == record["stat"]["gid"] == 0
        and record["stat"]["mode"] == "0444"
        and record["stat"]["nlink"] == 1
        and record["stat"]["type"] == "file"
        and record["stat"]["mtime_ns"] == record["stat"]["ctime_ns"] > 0
        for record, path in records
    )


def _verify_path_record(value: Mapping[str, Any]) -> None:
    expected = {
        "ctime_ns",
        "device",
        "gid",
        "inode",
        "mode",
        "mtime_ns",
        "nlink",
        "path",
        "size",
        "type",
        "uid",
    }
    if value.get("type") == "symlink":
        expected.add("target")
    _expect(
        set(value) == expected
        and isinstance(value["path"], str)
        and value["path"].startswith("/")
        and value["type"] in {"directory", "file", "symlink"}
        and re.fullmatch(r"[0-7]{4}", value["mode"]) is not None
        and all(
            isinstance(value[field], int)
            and not isinstance(value[field], bool)
            and value[field] >= 0
            for field in ("ctime_ns", "device", "gid", "mtime_ns", "size", "uid")
        )
        and all(
            isinstance(value[field], int)
            and not isinstance(value[field], bool)
            and value[field] > 0
            for field in ("inode", "nlink")
        ),
        "path record changed",
    )


def _artifact_projection(value: Any) -> Any:
    if isinstance(value, Mapping):
        if {"bytes", "digest", "path", "stat"}.issubset(value):
            stat_value = value["stat"]
            return {
                "bytes": value["bytes"],
                "digest": value["digest"],
                "path": value["path"],
                "stat": {
                    field: stat_value[field]
                    for field in ("gid", "mode", "nlink", "size", "type", "uid")
                },
            }
        return {key: _artifact_projection(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_artifact_projection(child) for child in value]
    return value


def _require_receipt(
    observed: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    digest: str,
    raw_digest: str,
    size: int,
) -> None:
    encoded = canonical_json(observed)
    _expect(
        observed == expected
        and canonical_digest(observed) == digest
        and _raw_digest(encoded + b"\n") == raw_digest
        and len(encoded) + 1 == size,
        "P3.7c receipt identity changed",
    )


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(canonical_json(value))


def _raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _expect(condition: Any, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError(message)
